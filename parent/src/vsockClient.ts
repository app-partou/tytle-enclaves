/**
 * vsock Client - connects to Nitro Enclaves via AF_VSOCK using the native addon.
 *
 * Uses vsockConnectAsync() for non-blocking connect with kernel-level
 * timeouts, and the shared protocol module for length-prefixed message framing.
 *
 * Build note: The parent server runs on EC2 (Amazon Linux 2023, glibc).
 * The native addon must be compiled with a glibc-based Rust toolchain,
 * NOT the musl toolchain used for enclave Docker images. See parent/Dockerfile.
 */

import { vsockConnectAsync } from '@tytle-enclaves/native';
import { readMessage, writeMessage } from '@tytle-enclaves/shared';
import type { EnclaveRequest, EnclaveResponse } from './types.js';

/**
 * How long the parent waits for an enclave's answer (enclave audit F6; D-P1-11 "A", LJ 2026-10-08): longer than the
 * enclave's own budget for a request (30 s from accept, plus 2 s to hand over an answer on its way; shared
 * requestBudget.ts), shorter than data-bridge's 45 s for a whole call. It was 30 s while the enclave allowed a handler
 * 60 s, so the parent gave up on answers the enclave went on to produce.
 */
export const ENCLAVE_ANSWER_BUDGET_MS = 35_000;

/**
 * Send a request to an enclave via vsock and return the response.
 *
 * @param cid - Enclave CID (e.g., 16 for VIES)
 * @param port - Enclave vsock port (e.g., 5000)
 * @param request - Request to forward
 * @param timeoutMs - Timeout in ms (default ENCLAVE_ANSWER_BUDGET_MS, 35 s)
 */
export async function sendToEnclave(
  cid: number,
  port: number,
  request: EnclaveRequest,
  timeoutMs: number = ENCLAVE_ANSWER_BUDGET_MS,
): Promise<EnclaveResponse> {
  // Reads are blocking libc calls: withTimeout's timer cannot fire while one waits, and a peer that
  // sends one byte at a time resets the socket's per-read timeout. The deadline bounds the whole answer.
  const deadlineMs = Date.now() + timeoutMs;
  const timeoutSecs = Math.max(1, Math.ceil(timeoutMs / 1000));
  const conn = await vsockConnectAsync(cid, port, timeoutSecs);

  try {
    return await withTimeout(
      async () => {
        await writeMessage(conn, request);
        return readMessage<EnclaveResponse>(conn, { deadlineMs });
      },
      timeoutMs,
      `Enclave request timed out after ${timeoutMs}ms (CID ${cid}, port ${port})`,
    );
  } finally {
    try { conn.close(); } catch { /* ignore */ }
  }
}

/** What a ping found: whether the enclave answered, and how far its clock is from this host's. */
export interface PingResult {
  responsive: boolean;
  /**
   * The enclave's clock (the pong's `timestamp`) minus this host's at the middle of the round trip, in ms;
   * null when it did not answer or its pong carries no clock. This host keeps NTP time; an enclave has no NTP
   * and drifts (audit §5.1 F1). Diagnostic: the attestation time follows the hypervisor (attestor.ts).
   */
  clockDriftMs: number | null;
}

/**
 * Send a lightweight ping to an enclave and wait for pong.
 * Used by the health check to verify vsock connectivity beyond nitro-cli state, and to read the enclave's clock.
 */
export async function pingEnclave(
  cid: number,
  port: number,
  timeoutMs: number = 2_000,
): Promise<PingResult> {
  try {
    const deadlineMs = Date.now() + timeoutMs;
    const timeoutSecs = Math.max(1, Math.ceil(timeoutMs / 1000));
    const conn = await vsockConnectAsync(cid, port, timeoutSecs);
    try {
      return await withTimeout(
        async (): Promise<PingResult> => {
          const sentAtMs = Date.now();
          await writeMessage(conn, { type: 'ping' });
          const resp = await readMessage<{ type?: unknown; timestamp?: unknown }>(conn, { deadlineMs });
          const receivedAtMs = Date.now();
          if (resp.type !== 'pong') return { responsive: false, clockDriftMs: null };
          const clock = resp.timestamp;
          return {
            responsive: true,
            clockDriftMs: typeof clock === 'number' && Number.isFinite(clock) ? Math.round(clock - (sentAtMs + receivedAtMs) / 2) : null,
          };
        },
        timeoutMs,
        'ping timeout',
      );
    } finally {
      try { conn.close(); } catch { /* ignore */ }
    }
  } catch {
    return { responsive: false, clockDriftMs: null };
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
