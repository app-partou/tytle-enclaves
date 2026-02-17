/**
 * Enclave factory — starts a generic attested HTTPS fetch enclave.
 *
 * Each service (vies, sicae, stripe) calls startEnclave() with its
 * config (name + allowlist). The allowlist is baked into the Docker
 * image and reflected in PCR0.
 */

import { VsockListener } from '@tytle-enclaves/native';
import { readMessage, writeMessage } from './protocol.js';
import { createRequestHandler } from './requestHandler.js';
import type { EnclaveConfig, EnclaveRequest, EnclaveResponse } from './types.js';

const VSOCK_PORT = 5000;

/**
 * Start the enclave accept loop.
 *
 * This is the main entry point for any enclave service. It:
 * 1. Binds a vsock listener on port 5000
 * 2. Accepts connections sequentially from the parent server
 * 3. For each connection: read request → validate URL → proxy → attest → respond
 *
 * Never returns (runs until the enclave is terminated).
 */
export function startEnclave(config: EnclaveConfig): void {
  const handleRequest = config.customHandler || createRequestHandler(config);

  const main = async (): Promise<void> => {
    console.log(`[enclave:${config.name}] Starting on vsock port ${VSOCK_PORT}`);
    console.log(`[enclave:${config.name}] Allowed hosts: ${config.hosts.map((h) => h.hostname).join(', ')}`);

    const listener = VsockListener.bind(VSOCK_PORT);
    console.log(`[enclave:${config.name}] Listening for connections...`);

    // Accept and process connections sequentially.
    // accept() is a blocking libc call (napi-rs runs on main thread).
    // Awaiting handleConnection ensures the event loop is free during
    // TLS/HTTP processing. Sequential is fine: requests are short-lived (<5s),
    // the parent server queues concurrent requests at the HTTP level.
    while (true) {
      try {
        const conn = listener.accept();
        await handleConnection(conn, config.name, handleRequest);
      } catch (err: any) {
        console.error(`[enclave:${config.name}] Accept error: ${err.message}`);
        await sleep(100);
      }
    }
  };

  main().catch((err) => {
    console.error(`[enclave:${config.name}] Fatal error: ${err.message}`);
    process.exit(1);
  });
}

async function handleConnection(
  conn: any,
  name: string,
  handleRequest: (req: EnclaveRequest) => Promise<EnclaveResponse>,
): Promise<void> {
  try {
    const request = await readMessage<EnclaveRequest>(conn);
    console.log(`[enclave:${name}] Request ${request.id}: ${request.method} ${request.url}`);

    const response = await handleRequest(request);
    await writeMessage(conn, response);

    console.log(
      `[enclave:${name}] Request ${request.id}: ${response.success ? 'OK' : 'FAILED'} (status ${response.status})`,
    );
  } catch (err: any) {
    console.error(`[enclave:${name}] Connection error: ${err.message}`);
    try {
      const errorResponse: EnclaveResponse = {
        success: false,
        status: 500,
        headers: {},
        rawBody: '',
        error: err.message,
      };
      await writeMessage(conn, errorResponse);
    } catch {
      // Can't send error response — connection is broken
    }
  } finally {
    try {
      conn.close();
    } catch {
      // Ignore close errors
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
