/**
 * A vsock peer that takes its time - for real. A read or a write here blocks the thread (Atomics.wait) as the native
 * call does, until the peer's bytes (or room for ours) are due or the call's time runs out: timers, accepted
 * connections and everything else on the event loop wait meanwhile, exactly as in an enclave or the parent (enclave
 * review 2026-10-09, E-1: every fake before returned at once, so no test could see a frozen event loop).
 *
 * Both native APIs are here, so one test runs against the release before R4 part 6 and the one after it:
 *   - read(size) / write(data): the blocking libc calls of the release before, bounded only by the socket's timeout
 *     (SO_RCVTIMEO / SO_SNDTIMEO, whole seconds), after which they fail with EAGAIN as libc does;
 *   - readWithin(size, timeoutMs) / writeWithin(data, timeoutMs): the calls that wait at most `timeoutMs`
 *     (null / 0 when nothing came or nothing was taken by then).
 *
 * Times are real (Date.now()); a plan gives each event in ms after the stream was made.
 */

const sleeper = new Int32Array(new SharedArrayBuffer(4));

/** Block the thread for `ms`, as a blocking system call does: nothing else on the event loop runs meanwhile. */
export function blockFor(ms: number): void {
  if (ms > 0) Atomics.wait(sleeper, 0, 0, ms);
}

export interface PeerPlan {
  /** What the peer sends, each part at its time (ms after the stream was made) */
  sends?: Array<{ atMs: number; bytes: Buffer | string }>;
  /** When the peer closes its end (ms after); never when absent */
  closesAtMs?: number;
  /** How many of our bytes the peer has taken by `elapsedMs` (a total); everything at once when absent */
  takes?: (elapsedMs: number) => number;
  /** The socket's timeout (SO_RCVTIMEO / SO_SNDTIMEO) in whole seconds: what bounds the release before's calls */
  socketTimeoutSecs: number;
}

const EAGAIN = 'Resource temporarily unavailable (os error 11)';

export class BlockingVsock {
  readonly written: Buffer[] = [];
  /** When the stream was made (the native accept or connect returned) */
  readonly openedAtMs: number;
  closed = false;
  private readonly sends: Array<{ atMs: number; bytes: Buffer }>;
  private arrived: Buffer = Buffer.alloc(0);
  private takenBytes = 0;

  constructor(private readonly plan: PeerPlan, openedAtMs: number = Date.now()) {
    this.openedAtMs = openedAtMs;
    this.sends = (plan.sends ?? [])
      .map((s) => ({ atMs: s.atMs, bytes: typeof s.bytes === 'string' ? Buffer.from(s.bytes, 'utf-8') : s.bytes }))
      .sort((a, b) => a.atMs - b.atMs);
  }

  // --- the release after R4 part 6 -------------------------------------------------------------------------------

  readWithin(size: number, timeoutMs: number): Buffer | null {
    return this.bytesBy(size, Date.now() + timeoutMs) ?? null;
  }

  writeWithin(data: Buffer, timeoutMs: number): number {
    return this.roomBy(data, Date.now() + timeoutMs) ?? 0;
  }

  // --- the release before ----------------------------------------------------------------------------------------

  read(size: number): Buffer {
    const bytes = this.bytesBy(size, Date.now() + this.plan.socketTimeoutSecs * 1000);
    if (bytes === undefined) throw new Error(`read() failed: ${EAGAIN}`);
    return bytes;
  }

  write(data: Buffer): number {
    const n = this.roomBy(data, Date.now() + this.plan.socketTimeoutSecs * 1000);
    if (n === undefined) throw new Error(`write() failed: ${EAGAIN}`);
    return n;
  }

  close(): void {
    this.closed = true;
  }

  // ---------------------------------------------------------------------------------------------------------------

  /** Up to `size` bytes (empty at the end of the stream), blocking until they are due or `untilMs`; undefined then. */
  private bytesBy(size: number, untilMs: number): Buffer | undefined {
    for (;;) {
      if (this.closed) return Buffer.alloc(0);
      const elapsed = Date.now() - this.openedAtMs;
      while (this.sends.length > 0 && this.sends[0].atMs <= elapsed) {
        this.arrived = Buffer.concat([this.arrived, this.sends.shift()!.bytes]);
      }
      if (this.arrived.length > 0) {
        const out = Buffer.from(this.arrived.subarray(0, size));
        this.arrived = this.arrived.subarray(out.length);
        return out;
      }
      if (this.plan.closesAtMs !== undefined && elapsed >= this.plan.closesAtMs) return Buffer.alloc(0);
      const now = Date.now();
      if (now >= untilMs) return undefined;
      const nextAt = Math.min(
        this.sends.length > 0 ? this.openedAtMs + this.sends[0].atMs : Infinity,
        this.plan.closesAtMs !== undefined ? this.openedAtMs + this.plan.closesAtMs : Infinity,
      );
      blockFor(Math.min(untilMs, nextAt) - now);
    }
  }

  /** How many of `data`'s bytes the peer takes, blocking until it has room or `untilMs`; undefined then. */
  private roomBy(data: Buffer, untilMs: number): number | undefined {
    for (;;) {
      if (this.closed) throw new Error('Stream already closed');
      const taken = this.plan.takes ? this.plan.takes(Date.now() - this.openedAtMs) : Infinity;
      const room = taken - this.takenBytes;
      if (room > 0) {
        const n = Math.min(room, data.length);
        this.written.push(Buffer.from(data.subarray(0, n)));
        this.takenBytes += n;
        return n;
      }
      const now = Date.now();
      if (now >= untilMs) return undefined;
      // The peer frees room as time goes on: look again every 10 ms, blocked meanwhile
      blockFor(Math.min(untilMs - now, 10));
    }
  }
}
