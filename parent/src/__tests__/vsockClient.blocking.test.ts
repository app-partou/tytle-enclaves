/**
 * One slow enclave no longer stops the parent (enclave review 2026-10-09, D7 = E2b F-1, its core).
 *
 * The parent read each enclave answer with a blocking libc call on its only thread: for the whole upstream round trip
 * of one enclave, no other request, no /health and no ping was served, and the host watchdog read the silence as a dead
 * parent. The shared framing now waits in slices (shared vsockWait.ts) and the event loop runs between them.
 *
 * MOCK BOUNDARY: the native connect only; each enclave connection blocks the thread for real as libc does
 * (shared/src/__tests__/helpers/blockingVsock.ts). The client and the framing run for real, on the real clock.
 * "(red)": fails on the release before R4 part 6.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BlockingVsock } from '../../../shared/src/__tests__/helpers/blockingVsock.js';

const { vsockConnectAsync } = vi.hoisted(() => ({ vsockConnectAsync: vi.fn() }));
vi.mock('@tytle-enclaves/native', () => ({ vsockConnectAsync }));

import { pingEnclave, sendToEnclave } from '../vsockClient.js';
import type { EnclaveRequest } from '../types.js';

function frame(message: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(message), 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

const REQUEST: EnclaveRequest = { id: 'req-1', url: 'https://ec.europa.eu/x', method: 'POST', headers: {}, body: '{}' };
const ANSWER = { success: true, status: 200, headers: {}, rawBody: 'b64' };

beforeEach(() => {
  vsockConnectAsync.mockReset();
});

describe('one slow enclave', { timeout: 20_000 }, () => {
  it('while enclave 16 takes 1.5 s to answer, a ping to enclave 17 is answered at once (red)', async () => {
    vsockConnectAsync.mockImplementation(async (cid: number, _port: number, socketTimeoutSecs: number) => (cid === 16
      ? new BlockingVsock({ sends: [{ atMs: 1_500, bytes: frame(ANSWER) }], socketTimeoutSecs })
      : new BlockingVsock({ sends: [{ atMs: 0, bytes: frame({ type: 'pong', timestamp: Date.now() }) }], socketTimeoutSecs })));

    const start = Date.now();
    const slow = sendToEnclave(16, 5000, REQUEST, 5_000);
    // The ping starts 100 ms in: a timer, which needs the event loop. Before, it started after enclave 16's answer.
    const pinged = await new Promise<{ responsive: boolean; at: number }>((resolve) => {
      setTimeout(() => {
        void pingEnclave(17, 5000, 2_000).then((r) => resolve({ responsive: r.responsive, at: Date.now() - start }));
      }, 100);
    });
    expect(pinged.responsive).toBe(true);
    expect(pinged.at).toBeLessThan(100 + 400);
    await expect(slow).resolves.toEqual(ANSWER);
  });
});
