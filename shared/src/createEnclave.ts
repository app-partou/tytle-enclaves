/**
 * Enclave factory - starts a generic attested HTTPS fetch enclave.
 *
 * Each service (vies, sicae, stripe, monerium) calls startEnclave() with
 * its config (name + allowlist). The allowlist is baked into the Docker
 * image and reflected in PCR0.
 */

import { VsockListener } from '@tytle-enclaves/native';
import type { VsockStream } from '@tytle-enclaves/native';
import { readMessage, writeMessage } from './protocol.js';
import { createRequestHandler } from './requestHandler.js';
import { toErrorMessage } from './errorUtils.js';
import type { EnclaveConfig, EnclaveRequest, EnclaveResponse } from './types.js';

const VSOCK_PORT = 5000;

const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT || '4', 10);

const CONNECTION_TIMEOUT_MS = 60_000;

/**
 * Start the enclave accept loop.
 *
 * Uses acceptAsync() to accept connections on the libuv thread pool,
 * keeping the event loop free for concurrent handler I/O. Request
 * handlers run concurrently up to MAX_CONCURRENT; excess connections
 * are rejected with 503 so the parent server can retry.
 *
 * Pings (health checks) are handled without counting against the
 * concurrency limit - they read the message, detect { type: 'ping' },
 * respond immediately, and close the connection.
 *
 * readMessage/writeMessage use synchronous libc::read/write (the native
 * addon has no async read variant). They stay inside dispatched handlers
 * so they don't block the accept loop itself. Accepted connections have
 * SO_RCVTIMEO=60s set by the Rust addon, so a stuck read returns EAGAIN
 * instead of blocking indefinitely.
 */
export function startEnclave(config: EnclaveConfig): void {
  const processRequest = config.customHandler || createRequestHandler(config);

  let activeHandlers = 0;

  const main = async (): Promise<void> => {
    console.log(`[enclave:${config.name}] Starting on vsock port ${VSOCK_PORT} (max concurrent: ${MAX_CONCURRENT})`);
    console.log(`[enclave:${config.name}] Allowed hosts: ${config.hosts.map((h) => h.hostname).join(', ')}`);

    const listener = VsockListener.bind(VSOCK_PORT);
    console.log(`[enclave:${config.name}] Listening for connections...`);

    while (true) {
      let conn: VsockStream | undefined;
      try {
        conn = await listener.acceptAsync();

        const handlerConn = conn;
        conn = undefined;

        dispatchConnection(handlerConn, config.name, processRequest)
          .catch((err: unknown) => {
            console.error(`[enclave:${config.name}] Unhandled connection error: ${toErrorMessage(err)}`);
          });
      } catch (err: unknown) {
        console.error(`[enclave:${config.name}] Accept error: ${toErrorMessage(err)}`);
        if (conn) {
          try { conn.close(); } catch { /* ignore */ }
        }
        await sleep(100);
      }
    }
  };

  /**
   * Read the first message to determine if this is a ping or a request.
   * Pings are handled immediately without capacity accounting.
   * Requests check capacity, then dispatch to the full handler.
   */
  async function dispatchConnection(
    conn: VsockStream,
    name: string,
    handler: (req: EnclaveRequest) => Promise<EnclaveResponse>,
  ): Promise<void> {
    try {
      const message = await withTimeout(
        () => readMessage<EnclaveRequest | { type: string }>(conn),
        CONNECTION_TIMEOUT_MS,
        `Read timed out after ${CONNECTION_TIMEOUT_MS}ms`,
      );

      if ('type' in message && (message as { type: string }).type === 'ping') {
        await writeMessage(conn, { type: 'pong', timestamp: Date.now() });
        return;
      }

      const request = message as EnclaveRequest;

      if (activeHandlers >= MAX_CONCURRENT) {
        const busyResp: EnclaveResponse = {
          success: false, status: 503, headers: {},
          rawBody: '', error: 'Enclave at capacity',
        };
        await writeMessage(conn, busyResp);
        return;
      }

      activeHandlers++;
      try {
        await executeRequest(conn, name, handler, request);
      } finally {
        activeHandlers--;
      }
    } catch (err: unknown) {
      const msg = toErrorMessage(err);
      console.error(`[enclave:${name}] Connection error: ${msg}`);
      try {
        await writeMessage(conn, {
          success: false, status: 500, headers: {},
          rawBody: '', error: msg,
        } satisfies EnclaveResponse);
      } catch {
        // Can't send error response - connection is broken
      }
    } finally {
      try { conn.close(); } catch { /* ignore */ }
    }
  }

  async function executeRequest(
    conn: VsockStream,
    name: string,
    handler: (req: EnclaveRequest) => Promise<EnclaveResponse>,
    request: EnclaveRequest,
  ): Promise<void> {
    console.log(`[enclave:${name}] Request ${request.id}: ${request.method} ${request.url}`);

    const response = await withTimeout(
      () => handler(request),
      CONNECTION_TIMEOUT_MS,
      `Handler timed out after ${CONNECTION_TIMEOUT_MS}ms`,
    );
    await writeMessage(conn, response);

    console.log(
      `[enclave:${name}] Request ${request.id}: ${response.success ? 'OK' : 'FAILED'} (status ${response.status})`,
    );
  }

  main().catch((err: unknown) => {
    console.error(`[enclave:${config.name}] Fatal error: ${toErrorMessage(err)}`);
    process.exit(1);
  });
}

async function withTimeout<T>(
  fn: () => Promise<T>,
  timeoutMs: number,
  message: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    fn().then(
      (result) => { clearTimeout(timer); resolve(result); },
      (err) => { clearTimeout(timer); reject(err); },
    );
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
