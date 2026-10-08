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
    expect(vsockConnectAsync).toHaveBeenCalledWith(16, 5000, 30);
    expect(conn.closed).toBe(true);
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

describe('pingEnclave', () => {
  it('a prompt pong is healthy (lock)', async () => {
    vsockConnectAsync.mockResolvedValue(enclaveAnswering(frame({ type: 'pong', timestamp: 1 }), 65536));
    await expect(pingEnclave(16, 5000)).resolves.toBe(true);
  });

  it('a pong trickled past the 2 s budget is unhealthy', async () => {
    let now = 9_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    vsockConnectAsync.mockResolvedValue(enclaveAnswering(frame({ type: 'pong', timestamp: 1 }), 1, () => { now += 1_000; }));
    await expect(pingEnclave(16, 5000)).resolves.toBe(false);
  });
});
