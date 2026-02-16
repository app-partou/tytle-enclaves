/**
 * VIES Enclave — main entry point.
 *
 * Listens for incoming vsock connections from the parent server,
 * processes requests, and returns attested responses.
 *
 * Runs inside an AWS Nitro Enclave. The Docker image containing this code
 * is converted to an EIF (Enclave Image Format), and its hash becomes PCR0.
 * Anyone can reproduce the build, compute PCR0, and verify attestations.
 */

import { VsockListener } from '@tytle-enclaves/native';
import { readMessage, writeMessage } from './protocol.js';
import { handleRequest } from './requestHandler.js';
import type { EnclaveRequest, EnclaveResponse } from './types.js';

const VSOCK_PORT = 5000;

async function main(): Promise<void> {
  console.log(`[enclave] VIES enclave starting on vsock port ${VSOCK_PORT}`);

  const listener = VsockListener.bind(VSOCK_PORT);
  console.log(`[enclave] Listening for connections...`);

  // Accept and process connections sequentially.
  // IMPORTANT: accept() is a blocking libc call (napi-rs #[napi] runs on main thread).
  // If we fire-and-forget handleConnection, the next accept() blocks the event loop
  // before async I/O (TLS handshake via VsockDuplex) can progress → deadlock.
  // Awaiting ensures the event loop is free during TLS/HTTP processing.
  // Sequential processing is fine: requests are short-lived (<5s), and the parent
  // server queues concurrent requests at the HTTP level.
  while (true) {
    try {
      const conn = listener.accept();
      await handleConnection(conn);
    } catch (err: any) {
      console.error(`[enclave] Accept error: ${err.message}`);
      // Brief pause before retrying accept
      await sleep(100);
    }
  }
}

/**
 * Handle a single vsock connection from the parent server.
 * Reads a length-prefixed request, processes it, sends a length-prefixed response.
 */
async function handleConnection(conn: any): Promise<void> {
  try {
    // Read the request
    const request = await readMessage<EnclaveRequest>(conn);
    console.log(`[enclave] Request ${request.id}: ${request.method} ${request.url}`);

    // Process the request
    const response = await handleRequest(request);

    // Send the response
    await writeMessage(conn, response);

    console.log(
      `[enclave] Request ${request.id}: ${response.success ? 'OK' : 'FAILED'} (status ${response.status})`,
    );
  } catch (err: any) {
    console.error(`[enclave] Connection error: ${err.message}`);

    // Try to send an error response
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

// Start the enclave
main().catch((err) => {
  console.error(`[enclave] Fatal error: ${err.message}`);
  process.exit(1);
});
