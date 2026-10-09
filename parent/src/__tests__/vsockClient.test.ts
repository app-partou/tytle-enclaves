/**
 * The parent's vsock client with only the native connect replaced: the framing and the deadlines run for real.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

/** An enclave connection that answers with `bytes`, `perRead` at a time, moving the clock per read. */
function enclaveAnswering(bytes: Buffer, perRead: number, onRead: () => void = () => {}) {
  let offset = 0;
  return {
    written: [] as Buffer[],
    closed: false,
    read(size: number): Buffer {
      onRead();
      const n = Math.min(size, perRead, bytes.length - offset);
      const out = bytes.subarray(offset, offset + n);
      offset += n;
      return out;
    },
    write(data: Buffer): number {
      this.written.push(Buffer.from(data));
      return data.length;
    },
    close(): void {
      this.closed = true;
    },
  };
}

function frame(message: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(message), 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

const { vsockConnectAsync } = vi.hoisted(() => ({ vsockConnectAsync: vi.fn() }));
vi.mock('@tytle-enclaves/native', () => ({ vsockConnectAsync }));

import { sendToEnclave, pingEnclave } from '../vsockClient.js';

const REQUEST = { id: 'r1', url: 'https://ec.europa.eu/x', method: 'POST', headers: {} };

beforeEach(() => {
  vsockConnectAsync.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('sendToEnclave', () => {
  it('returns a prompt answer and closes the connection (lock)', async () => {
    const answer = { success: true, status: 200, headers: {}, rawBody: 'ok' };
    const conn = enclaveAnswering(frame(answer), 65536);
    vsockConnectAsync.mockResolvedValue(conn);
    await expect(sendToEnclave(16, 5000, REQUEST)).resolves.toEqual(answer);
    expect(conn.closed).toBe(true);
  });

  it('🔴 waits 35 s by default (D-P1-11): longer than the enclave\'s 30 s budget and its 2 s to hand over an answer', async () => {
    let now = 7_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const answer = { success: true, status: 200, headers: {}, rawBody: 'ok' };
    // The enclave answers 32 s after the request (its first read returns at t+32 s).
    let reads = 0;
    const conn = enclaveAnswering(frame(answer), 65536, () => { if (reads++ === 0) now += 32_000; });
    vsockConnectAsync.mockResolvedValue(conn);
    await expect(sendToEnclave(16, 5000, REQUEST)).resolves.toEqual(answer);
    expect(vsockConnectAsync).toHaveBeenCalledWith(16, 5000, 35);
  });

  it('an answer trickled past the budget is an error, not a late answer', async () => {
    let now = 7_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const answer = { success: true, status: 200, headers: {}, rawBody: 'x'.repeat(64) };
    const conn = enclaveAnswering(frame(answer), 1, () => { now += 5_000; });
    vsockConnectAsync.mockResolvedValue(conn);
    await expect(sendToEnclave(16, 5000, REQUEST, 30_000)).rejects.toMatchObject({ name: 'ReadDeadlineError' });
    expect(conn.closed).toBe(true);
  });
});

describe('pingEnclave: whether the enclave answers, and how far its clock is from this host (audit §5.1 F1)', () => {
  it('a prompt pong is responsive, with the enclave clock\'s drift from the middle of the round trip (red)', async () => {
    let now = 9_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    // Sent at 9 000 000, answered after two reads of 200 ms: the middle of the round trip is 9 000 200.
    vsockConnectAsync.mockResolvedValue(enclaveAnswering(frame({ type: 'pong', timestamp: 9_090_200 }), 65536, () => { now += 200; }));
    await expect(pingEnclave(16, 5000)).resolves.toEqual({ responsive: true, clockDriftMs: 90_000 });
  });

  it('an enclave clock behind this host is a negative drift (red)', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(9_000_000);
    vsockConnectAsync.mockResolvedValue(enclaveAnswering(frame({ type: 'pong', timestamp: 8_955_000 }), 65536));
    await expect(pingEnclave(16, 5000)).resolves.toEqual({ responsive: true, clockDriftMs: -45_000 });
  });

  it('a pong without a clock is responsive, its drift unknown (red)', async () => {
    vsockConnectAsync.mockResolvedValue(enclaveAnswering(frame({ type: 'pong' }), 65536));
    await expect(pingEnclave(16, 5000)).resolves.toEqual({ responsive: true, clockDriftMs: null });
    vsockConnectAsync.mockResolvedValue(enclaveAnswering(frame({ type: 'pong', timestamp: 'noon' }), 65536));
    await expect(pingEnclave(16, 5000)).resolves.toEqual({ responsive: true, clockDriftMs: null });
  });

  it('a pong trickled past the 2 s budget is unresponsive (red)', async () => {
    let now = 9_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    vsockConnectAsync.mockResolvedValue(enclaveAnswering(frame({ type: 'pong', timestamp: 1 }), 1, () => { now += 1_000; }));
    await expect(pingEnclave(16, 5000)).resolves.toEqual({ responsive: false, clockDriftMs: null });
  });

  it('an answer that is not a pong, or no connection, is unresponsive (red)', async () => {
    vsockConnectAsync.mockResolvedValue(enclaveAnswering(frame({ type: 'busy', timestamp: 1 }), 65536));
    await expect(pingEnclave(16, 5000)).resolves.toEqual({ responsive: false, clockDriftMs: null });
    vsockConnectAsync.mockRejectedValue(new Error('connection refused'));
    await expect(pingEnclave(16, 5000)).resolves.toEqual({ responsive: false, clockDriftMs: null });
  });
});
