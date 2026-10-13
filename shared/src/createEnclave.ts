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
import { ANSWER_GRACE_MS, ANSWER_WRITE_MS, RequestDeadlineError, requestBudget, type RequestBudget } from './requestBudget.js';
import type { EnclaveConfig, EnclaveRequest, EnclaveResponse } from './types.js';

const VSOCK_PORT = 5000;

const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT || '4', 10);

/**
 * The whole request (or ping) must arrive within this of the connection's arrival. The parent writes it in one go
 * right after connecting; a peer that trickles bytes is cut off here (protocol.ts ReadDeadlineError) instead of
 * holding the connection open. The bound is exact: no read waits past it (enclave review 2026-10-09, E1 F-6: each
 * blocking read could wait one more socket timeout, 20 s in all).
 */
const REQUEST_READ_DEADLINE_MS = 10_000;

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
 * readMessage/writeMessage wait in slices (vsockWait.ts): no native read or write waits longer than WAIT_SLICE_MS,
 * and the event loop runs between them, so a slow peer or a slow upstream never stops the enclave from serving its
 * other connections (enclave review 2026-10-09, E-1: a blocking read held a ping 23.5 s). The request read has a
 * deadline over the whole message (REQUEST_READ_DEADLINE_MS), and every write of a connection ends by the answer's
 * own deadline (the budget, ANSWER_GRACE_MS and ANSWER_WRITE_MS: 34 s, inside the parent's 35 s).
 *
 * A request has one time budget from the moment its connection arrived (requestBudget.ts, 30 s; the native accept
 * takes that time): the handler's reads, retries and KMS call take what is left of it, and an answer still not given
 * ANSWER_GRACE_MS after it is a 504, inside the parent's 35 s. It was a 60 s timer, longer than the parent's 30 s, that
 * never stopped the handler.
 */
export function startEnclave(config: EnclaveConfig): void {
  const processRequest = config.customHandler || createRequestHandler(config);

  let activeHandlers = 0;
  const freeSlot = (): void => {
    activeHandlers--;
  };

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
    handler: (req: EnclaveRequest, budget: RequestBudget) => Promise<EnclaveResponse>,
  ): Promise<void> {
    // From the moment the connection arrived, as the native accept took it: a connection that waited for the event
    // loop gets no fresh budget (enclave review 2026-10-09, E-1).
    const budget = requestBudget(conn.openedAtMs);
    // Every write of this connection ends by then, the answer's own deadline (E1 F-10).
    const writeBy = { deadlineMs: budget.deadlineMs + ANSWER_GRACE_MS + ANSWER_WRITE_MS };
    try {
      const message = await readMessage<EnclaveRequest | { type: string }>(conn, {
        deadlineMs: conn.openedAtMs + REQUEST_READ_DEADLINE_MS,
      });

      if ('type' in message && (message as { type: string }).type === 'ping') {
        // The enclave's own clock: the parent reports how far it drifted (audit §5.1 F1). Diagnostic only - the
        // attestation time follows the hypervisor's signed one (attestor.ts).
        await writeMessage(conn, { type: 'pong', timestamp: Date.now() }, writeBy);
        return;
      }

      const request = message as EnclaveRequest;

      if (activeHandlers >= MAX_CONCURRENT) {
        const busyResp: EnclaveResponse = {
          success: false, status: 503, headers: {},
          rawBody: '', error: 'Enclave at capacity',
        };
        await writeMessage(conn, busyResp, writeBy);
        return;
      }

      // The slot is held until the handler itself stops, not until its answer was written: a 504 ends the answer, not
      // the handler, which may still hold its upstream socket (enclave review 2026-10-09, E1 F-7). A handler that
      // throws at once rejects its run, as one that throws later does, so its slot is freed too.
      activeHandlers++;
      const handling = (async () => handler(request, budget))();
      void handling.then(freeSlot, freeSlot);
      await executeRequest(conn, name, request, handling, budget, writeBy);
    } catch (err: unknown) {
      const msg = toErrorMessage(err);
      console.error(`[enclave:${name}] Connection error: ${msg}`);
      try {
        await writeMessage(conn, {
          success: false, status: err instanceof RequestDeadlineError ? 504 : 500, headers: {},
          rawBody: '', error: msg,
        } satisfies EnclaveResponse, writeBy);
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
    request: EnclaveRequest,
    handling: Promise<EnclaveResponse>,
    budget: RequestBudget,
    writeBy: { deadlineMs: number },
  ): Promise<void> {
    console.log(`[enclave:${name}] Request ${request.id}: ${request.method} ${request.url}`);

    const response = await withTimeout(
      handling,
      budget.deadlineMs + ANSWER_GRACE_MS - Date.now(),
      () => new RequestDeadlineError('the answer'),
    );
    await writeMessage(conn, response, writeBy);

    console.log(
      `[enclave:${name}] Request ${request.id}: ${response.success ? 'OK' : 'FAILED'} (status ${response.status})`,
    );
  }

  main().catch((err: unknown) => {
    console.error(`[enclave:${config.name}] Fatal error: ${toErrorMessage(err)}`);
    process.exit(1);
  });
}

/** What `promise` gives, or `onTimeout()` when `timeoutMs` passes first. The promise's own work goes on: it is not stopped. */
async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  onTimeout: () => Error,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(onTimeout()), timeoutMs);
    promise.then(
      (result) => { clearTimeout(timer); resolve(result); },
      (err) => { clearTimeout(timer); reject(err); },
    );
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
