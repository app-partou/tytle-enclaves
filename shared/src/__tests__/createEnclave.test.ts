/**
 * The enclave's accept loop (startEnclave) with only the vsock listener replaced: each accepted
 * connection is a scripted stream, the dispatch, the framing and the handler call run for real.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { EnclaveRequest, EnclaveResponse } from '../types.js';

/** An accepted connection that hands out `bytes` `perRead` at a time; resolves `done` when the enclave closes it. */
class ScriptedConnection {
  readonly written: Buffer[] = [];
  reads = 0;
  readonly done: Promise<void>;
  private offset = 0;
  private resolveDone!: () => void;
  constructor(
    private readonly bytes: Buffer,
    private readonly perRead: number,
    private readonly onRead: () => void = () => {},
  ) {
    this.done = new Promise((r) => { this.resolveDone = r; });
  }
  read(size: number): Buffer {
    this.reads++;
    this.onRead();
    const n = Math.min(size, this.perRead, this.bytes.length - this.offset);
    const out = this.bytes.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }
  write(data: Buffer): number {
    this.written.push(Buffer.from(data));
    return data.length;
  }
  close(): void {
    this.resolveDone();
  }
  /** The one framed message the enclave wrote back. */
  reply(): unknown {
    const all = Buffer.concat(this.written);
    const length = all.readUInt32BE(0);
    return JSON.parse(all.subarray(4, 4 + length).toString('utf-8'));
  }
}

const { pending } = vi.hoisted(() => ({ pending: [] as ScriptedConnection[] }));
vi.mock('@tytle-enclaves/native', () => ({
  VsockListener: {
    bind: () => ({
      // Hands out the scripted connections, then waits forever (the loop stays parked).
      acceptAsync: () => {
        const next = pending.shift();
        return next ? Promise.resolve(next) : new Promise(() => {});
      },
    }),
  },
}));

import { startEnclave } from '../createEnclave.js';

function frame(message: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(message), 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

const REQUEST: EnclaveRequest = { id: 'req-1', url: 'https://ec.europa.eu/x', method: 'POST', headers: {}, body: '{}' };

beforeEach(() => {
  pending.length = 0;
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('startEnclave', () => {
  it('answers a ping with a pong without calling the handler (lock)', async () => {
    const conn = new ScriptedConnection(frame({ type: 'ping' }), 65536);
    pending.push(conn);
    const handler = vi.fn();
    startEnclave({ name: 'test-ping', hosts: [], customHandler: handler });
    await conn.done;
    expect(conn.reply()).toMatchObject({ type: 'pong' });
    expect(handler).not.toHaveBeenCalled();
  });

  it('the pong carries the enclave\'s own clock, which the parent compares with its own (lock)', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_760_000_123_456);
    const conn = new ScriptedConnection(frame({ type: 'ping' }), 65536);
    pending.push(conn);
    startEnclave({ name: 'test-pong-clock', hosts: [], customHandler: vi.fn() });
    await conn.done;
    expect(conn.reply()).toEqual({ type: 'pong', timestamp: 1_760_000_123_456 });
  });

  it('hands a request to the handler and writes its answer back (lock)', async () => {
    const conn = new ScriptedConnection(frame(REQUEST), 65536);
    pending.push(conn);
    const answer: EnclaveResponse = { success: true, status: 200, headers: {}, rawBody: 'ok' };
    const handler = vi.fn(async (_request: EnclaveRequest, _budget?: unknown) => answer);
    startEnclave({ name: 'test-request', hosts: [], customHandler: handler });
    await conn.done;
    expect(handler.mock.calls[0]?.[0]).toEqual(REQUEST);
    expect(conn.reply()).toEqual(answer);
  });

  it('🔴 the handler gets the request\'s budget: 30 s from the accept (D-P1-11)', async () => {
    let now = 5_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const conn = new ScriptedConnection(frame(REQUEST), 65536, () => { now += 1_000; });
    pending.push(conn);
    const handler = vi.fn(async (_request: EnclaveRequest, _budget?: unknown): Promise<EnclaveResponse> => ({ success: true, status: 200, headers: {}, rawBody: '' }));
    startEnclave({ name: 'test-budget', hosts: [], customHandler: handler });
    await conn.done;
    // Counted from the accept, before the request was read (the read moved the clock): the read is inside it.
    expect(handler.mock.calls[0]?.[1]).toEqual({ deadlineMs: 5_000_000 + 30_000 });
  });

  it('🔴 a handler with no answer 2 s after its budget: the parent gets a 504 then, not after 60 s (D-P1-11)', async () => {
    vi.useFakeTimers({ now: 6_000_000 });
    try {
      const conn = new ScriptedConnection(frame(REQUEST), 65536);
      pending.push(conn);
      const handler = vi.fn((): Promise<EnclaveResponse> => new Promise(() => {}));
      startEnclave({ name: 'test-overrun', hosts: [], customHandler: handler });
      await vi.advanceTimersByTimeAsync(31_900);
      expect(conn.written).toEqual([]);
      await vi.advanceTimersByTimeAsync(200);
      await conn.done;
      expect(conn.reply()).toMatchObject({ success: false, status: 504 });
      expect((conn.reply() as EnclaveResponse).error).toMatch(/budget was spent before the answer/);
    } finally {
      vi.useRealTimers();
    }
  });

  it('a peer that trickles its request past 10 s is cut off: an error answer, the handler never called', async () => {
    // Each read hands out one byte and moves the clock 3 s, so the socket's per-read timeout never fires.
    let now = 5_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const conn = new ScriptedConnection(frame(REQUEST), 1, () => { now += 3_000; });
    pending.push(conn);
    const handler = vi.fn(async (): Promise<EnclaveResponse> => ({ success: true, status: 200, headers: {}, rawBody: '' }));
    startEnclave({ name: 'test-trickle', hosts: [], customHandler: handler });
    await conn.done;
    expect(handler).not.toHaveBeenCalled();
    // The deadline is 10 s: four 3-second reads reach t+12 s, and the check before the fifth stops it.
    expect(conn.reads).toBe(4);
    expect(conn.reply()).toMatchObject({ success: false, status: 500 });
    expect((conn.reply() as EnclaveResponse).error).toMatch(/^Read deadline passed/);
  });
});
