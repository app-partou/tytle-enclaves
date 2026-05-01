/**
 * vsock Client - connects to Nitro Enclaves via AF_VSOCK using the native addon.
 *
 * Uses VsockStream.connectAsync() for non-blocking connect with kernel-level
 * timeouts, and the shared protocol module for length-prefixed message framing.
 *
 * Build note: The parent server runs on EC2 (Amazon Linux 2023, glibc).
 * The native addon must be compiled with a glibc-based Rust toolchain,
 * NOT the musl toolchain used for enclave Docker images. See parent/Dockerfile.
 */

import { VsockStream } from '@tytle-enclaves/native';
import { readMessage, writeMessage } from '@tytle-enclaves/shared';
import type { EnclaveRequest, EnclaveResponse } from './types.js';

/**
 * Send a request to an enclave via vsock and return the response.
 *
 * @param cid - Enclave CID (e.g., 16 for VIES)
 * @param port - Enclave vsock port (e.g., 5000)
 * @param request - Request to forward
 * @param timeoutMs - Timeout in ms (default 30000)
 */
export async function sendToEnclave(
  cid: number,
  port: number,
  request: EnclaveRequest,
  timeoutMs: number = 30_000,
): Promise<EnclaveResponse> {
  const timeoutSecs = Math.max(1, Math.ceil(timeoutMs / 1000));
  const conn = await VsockStream.connectAsync(cid, port, timeoutSecs);

  try {
    return await withTimeout(
      async () => {
        await writeMessage(conn, request);
        return readMessage<EnclaveResponse>(conn);
      },
      timeoutMs,
      `Enclave request timed out after ${timeoutMs}ms (CID ${cid}, port ${port})`,
    );
  } finally {
    try { conn.close(); } catch { /* ignore */ }
  }
}

/**
 * Send a lightweight ping to an enclave and wait for pong.
 * Used by the health check to verify vsock connectivity beyond nitro-cli state.
 */
export async function pingEnclave(
  cid: number,
  port: number,
  timeoutMs: number = 2_000,
): Promise<boolean> {
  try {
    const timeoutSecs = Math.max(1, Math.ceil(timeoutMs / 1000));
    const conn = await VsockStream.connectAsync(cid, port, timeoutSecs);
    try {
      const result = await withTimeout(
        async () => {
          await writeMessage(conn, { type: 'ping' });
          const resp = await readMessage<{ type: string }>(conn);
          return resp.type === 'pong';
        },
        timeoutMs,
        'ping timeout',
      );
      return result;
    } finally {
      try { conn.close(); } catch { /* ignore */ }
    }
  } catch {
    return false;
  }
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
