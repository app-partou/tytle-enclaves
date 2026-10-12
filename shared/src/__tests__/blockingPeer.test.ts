/**
 * A peer that takes its time cannot hold the enclave (enclave review 2026-10-09, E-1, E1 F-6, F-10).
 *
 * Every native read and write was a blocking libc call on the event loop, bounded only by the socket's timeout: an
 * upstream that went quiet kept a fetch past its own timer (an answer 49.5 s after the accept, past the 30 s budget),
 * and the whole enclave served nothing else meanwhile (a ping held 23.5 s). Now each call waits at most a slice and the
 * event loop runs between calls (vsockWait.ts).
 *
 * MOCK BOUNDARY: the native addon only (the vsock sockets): the peers here block the thread for real
 * (helpers/blockingVsock.ts), as libc does. startEnclave, the framing, httpProxy and httpParse run for real, on the real
 * clock. "(red)": fails on the release before R4 part 6.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { EnclaveRequest, EnclaveResponse } from '../types.js';
import { BlockingVsock } from './helpers/blockingVsock.js';

/** An accepted connection whose bytes are all there: it records when the enclave wrote to it, and when it closed it. */
class InstantConnection {
  readonly written: Buffer[] = [];
  wroteAt: number | null = null;
  readonly done: Promise<void>;
  private offset = 0;
  private resolveDone!: () => void;
  constructor(private readonly bytes: Buffer, readonly openedAtMs: number = Date.now()) {
    this.done = new Promise((r) => { this.resolveDone = r; });
  }
  readWithin(size: number, _timeoutMs: number): Buffer | null {
    return this.read(size);
  }
  read(size: number): Buffer {
    const out = this.bytes.subarray(this.offset, this.offset + size);
    this.offset += out.length;
    return out;
  }
  writeWithin(data: Buffer, _timeoutMs: number): number {
    return this.write(data);
  }
  write(data: Buffer): number {
    this.wroteAt ??= Date.now();
    this.written.push(Buffer.from(data));
    return data.length;
  }
  close(): void {
    this.resolveDone();
  }
  reply(): unknown {
    const all = Buffer.concat(this.written);
    return JSON.parse(all.subarray(4, 4 + all.readUInt32BE(0)).toString('utf-8'));
  }
}

const io = vi.hoisted(() => ({
  /** The accepted connections, in order: each a function that gives the connection when it arrives */
  accepts: [] as Array<() => Promise<unknown>>,
  /** The upstream peer of the next fetch, from the socket timeout the fetch asked for */
  upstream: null as null | ((socketTimeoutSecs: number) => unknown),
}));
vi.mock('@tytle-enclaves/native', () => ({
  VsockListener: {
    bind: () => ({
      acceptAsync: () => (io.accepts.shift() ?? (() => new Promise(() => {})))(),
    }),
  },
  VsockStream: {
    connect: (_cid: number, _port: number, socketTimeoutSecs: number) => {
      if (!io.upstream) throw new Error('no upstream scripted');
      return io.upstream(socketTimeoutSecs);
    },
  },
}));

import { startEnclave } from '../createEnclave.js';
import { proxyFetchPlain } from '../httpProxy.js';
import { readMessage, writeMessage } from '../protocol.js';

function frame(message: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(message), 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

const REQUEST: EnclaveRequest = { id: 'req-1', url: 'http://slow.example/', method: 'GET', headers: {} };
const OK: EnclaveResponse = { success: true, status: 200, headers: {}, rawBody: '' };

/** These tests run on the real clock, for a few seconds each. */
const REAL_TIME = { timeout: 20_000 };

beforeEach(() => {
  io.accepts.length = 0;
  io.upstream = null;
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('an upstream that goes quiet (E-1)', REAL_TIME, () => {
  it('a fetch ends at its own timeout, not one socket timeout later (red)', async () => {
    // A head and part of a body at 300 ms, then nothing, and the socket stays open. The fetch has 1.5 s; the socket's
    // timeout is ceil(1.5 s) = 2 s, which the blocking read waited out after the bytes came: 2.3 s before.
    io.upstream = (secs) => new BlockingVsock({
      sends: [{ atMs: 300, bytes: 'HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab' }],
      socketTimeoutSecs: secs,
    });
    const start = Date.now();
    const err = await proxyFetchPlain(8445, 'slow.example', 'GET', '/', {}, undefined, 1_500).catch((e: unknown) => e);
    const took = Date.now() - start;
    expect(err).toBeInstanceOf(Error);
    expect(took).toBeGreaterThanOrEqual(1_400);
    expect(took).toBeLessThan(1_900);
  });

  it('a fetch whose upstream takes none of its request ends at its own timeout (red)', async () => {
    // The upstream reads nothing. The fetch has 1.2 s; before, the write blocked for the socket's 2 s timeout.
    io.upstream = (secs) => new BlockingVsock({ takes: () => 0, socketTimeoutSecs: secs });
    const start = Date.now();
    const err = await proxyFetchPlain(8445, 'slow.example', 'POST', '/', {}, 'x'.repeat(100), 1_200).catch((e: unknown) => e);
    const took = Date.now() - start;
    expect(err).toBeInstanceOf(Error);
    expect(took).toBeGreaterThanOrEqual(1_100);
    expect(took).toBeLessThan(1_600);
  });

  it('a ping is answered while a request waits for its upstream: the enclave serves on (red)', async () => {
    // The request's upstream says nothing; its fetch has 2 s. The ping's connection arrives 300 ms in: a timer, which
    // needs the event loop, as an accepted connection does. Before, the pong came only after the fetch's read gave up.
    io.upstream = (secs) => new BlockingVsock({ socketTimeoutSecs: secs });
    const request = new InstantConnection(frame(REQUEST));
    const ping = new InstantConnection(frame({ type: 'ping' }));
    io.accepts.push(
      () => Promise.resolve(request),
      () => new Promise((resolve) => setTimeout(() => resolve(ping), 300)),
    );
    const start = Date.now();
    startEnclave({
      name: 'test-busy-upstream',
      hosts: [],
      customHandler: async (): Promise<EnclaveResponse> => {
        await proxyFetchPlain(8445, 'slow.example', 'GET', '/', {}, undefined, 2_000).catch(() => undefined);
        return OK;
      },
    });
    await ping.done;
    expect(ping.reply()).toMatchObject({ type: 'pong' });
    expect(ping.wroteAt! - start).toBeLessThan(300 + 400);
    await request.done;
  });

  it('a ping is answered while another connection is still sending its request (red)', async () => {
    // The first connection's request comes whole at 1.5 s; the ping's connection arrives 300 ms in. Before, the read of
    // the first request blocked the event loop until its bytes came.
    const slowRequest = new BlockingVsock({ sends: [{ atMs: 1_500, bytes: frame(REQUEST) }], socketTimeoutSecs: 10 });
    const ping = new InstantConnection(frame({ type: 'ping' }));
    io.accepts.push(
      () => Promise.resolve(slowRequest),
      () => new Promise((resolve) => setTimeout(() => resolve(ping), 300)),
    );
    const start = Date.now();
    const handler = vi.fn(async (): Promise<EnclaveResponse> => OK);
    startEnclave({ name: 'test-slow-request', hosts: [], customHandler: handler });
    await ping.done;
    expect(ping.wroteAt! - start).toBeLessThan(300 + 400);
    await vi.waitFor(() => expect(handler).toHaveBeenCalledTimes(1), { timeout: 5_000 });
  });
});

describe('a parent that takes its answer slowly (E1 F-10)', REAL_TIME, () => {
  it('a ping is answered while another connection takes its answer slowly (red)', async () => {
    // The first connection's peer takes 8 bytes at once and the rest after 1.5 s; the ping's connection arrives 300 ms
    // in. Before, the answer's write blocked the event loop until the peer made room.
    const slowReader = new BlockingVsock({
      sends: [{ atMs: 0, bytes: frame(REQUEST) }],
      takes: (elapsedMs) => (elapsedMs >= 1_500 ? Infinity : 8),
      socketTimeoutSecs: 10,
    });
    const ping = new InstantConnection(frame({ type: 'ping' }));
    io.accepts.push(
      () => Promise.resolve(slowReader),
      () => new Promise((resolve) => setTimeout(() => resolve(ping), 300)),
    );
    const start = Date.now();
    startEnclave({
      name: 'test-slow-reader',
      hosts: [],
      customHandler: async (): Promise<EnclaveResponse> => ({ ...OK, rawBody: 'x'.repeat(1_000) }),
    });
    await ping.done;
    expect(ping.wroteAt! - start).toBeLessThan(300 + 400);
    await vi.waitFor(() => expect(Buffer.concat(slowReader.written).length).toBeGreaterThan(1_000), { timeout: 5_000 });
  });

  it('the answer\'s write gives up 34 s after the connection arrived, inside the parent\'s 35 s (red)', async () => {
    // The clock jumps 31 s while the handler works (it took its budget); the peer then takes 8 bytes and no more. The
    // write gives up at 34 s, 3 s later. Before, a write had no deadline: each one blocked for the socket's 10 s.
    const realNow = Date.now.bind(Date);
    let jump = 0;
    vi.spyOn(Date, 'now').mockImplementation(() => realNow() + jump);
    const slowReader = new BlockingVsock({ sends: [{ atMs: 0, bytes: frame(REQUEST) }], takes: () => 8, socketTimeoutSecs: 10 });
    io.accepts.push(() => Promise.resolve(slowReader));
    const start = realNow();
    startEnclave({
      name: 'test-answer-write',
      hosts: [],
      customHandler: async (): Promise<EnclaveResponse> => {
        jump = 31_000;
        return OK;
      },
    });
    await vi.waitFor(() => expect(slowReader.closed).toBe(true), { timeout: 8_000, interval: 50 });
    const took = realNow() - start;
    expect(took).toBeGreaterThanOrEqual(2_500);
    expect(took).toBeLessThan(4_500);
    expect(Buffer.concat(slowReader.written).length).toBe(8);
  });
});

describe('the request budget starts when the connection arrived (E-1)', () => {
  it('as the native accept took the time, not when the event loop got to the connection (red)', async () => {
    // It arrived 5 s ago, while the event loop was busy: its budget runs from then.
    const conn = new InstantConnection(frame(REQUEST), Date.now() - 5_000);
    io.accepts.push(() => Promise.resolve(conn));
    const handler = vi.fn(async (_request: EnclaveRequest, _budget?: unknown): Promise<EnclaveResponse> => OK);
    startEnclave({ name: 'test-arrival', hosts: [], customHandler: handler });
    await conn.done;
    expect(handler.mock.calls[0]?.[1]).toEqual({ deadlineMs: conn.openedAtMs + 30_000 });
  });

  it('so does the request read\'s 10 s: a connection that arrived 11 s ago is refused, its handler never called (red)', async () => {
    const conn = new InstantConnection(frame(REQUEST), Date.now() - 11_000);
    io.accepts.push(() => Promise.resolve(conn));
    const handler = vi.fn(async (): Promise<EnclaveResponse> => OK);
    startEnclave({ name: 'test-late-read', hosts: [], customHandler: handler });
    await conn.done;
    expect(handler).not.toHaveBeenCalled();
    expect(conn.reply()).toMatchObject({ success: false, status: 500 });
    expect((conn.reply() as EnclaveResponse).error).toMatch(/^Read deadline passed/);
  });
});

describe('the deadlines of a message (E1 F-6, F-10)', REAL_TIME, () => {
  it('a peer that trickles its message is cut off at the read deadline, not when its next byte comes (red)', async () => {
    // One byte every 900 ms; the deadline is 1 s. Before, the read under way at 900 ms waited for the byte at 1.8 s.
    const bytes = frame({ type: 'ping' });
    const peer = new BlockingVsock({
      sends: [...bytes].map((byte, i) => ({ atMs: i * 900, bytes: Buffer.from([byte]) })),
      socketTimeoutSecs: 10,
    });
    const start = Date.now();
    const err = await readMessage(peer, { deadlineMs: start + 1_000 }).catch((e: unknown) => e);
    const took = Date.now() - start;
    expect(err).toMatchObject({ name: 'ReadDeadlineError', receivedBytes: 2 });
    expect(took).toBeLessThan(1_000 + 300);
  });

  it('a peer that drains slowly cannot hold a write past its deadline (red)', async () => {
    // It takes 8 bytes at once and 8 more every 900 ms (everything after 2.5 s); the deadline is 1 s. Before, a write
    // had no deadline: it went on until the peer took everything.
    const peer = new BlockingVsock({
      takes: (elapsedMs) => (elapsedMs >= 2_500 ? Infinity : 8 * (1 + Math.floor(elapsedMs / 900))),
      socketTimeoutSecs: 10,
    });
    const start = Date.now();
    const err = await writeMessage(peer, { rawBody: 'x'.repeat(200) }, { deadlineMs: start + 1_000 }).catch((e: unknown) => e);
    const took = Date.now() - start;
    expect(err).toMatchObject({ name: 'WriteDeadlineError', code: 'WRITE_DEADLINE', writtenBytes: 16 });
    expect(took).toBeLessThan(1_000 + 300);
  });

  it('a peer that keeps up gets the whole message, in order (lock)', async () => {
    const message = { rawBody: 'é'.repeat(100_000) };
    const peer = new BlockingVsock({ socketTimeoutSecs: 10 });
    await writeMessage(peer, message, { deadlineMs: Date.now() + 5_000 });
    const back = new BlockingVsock({ sends: [{ atMs: 0, bytes: Buffer.concat(peer.written) }], socketTimeoutSecs: 10 });
    await expect(readMessage(back, { deadlineMs: Date.now() + 5_000 })).resolves.toEqual(message);
  });
});
