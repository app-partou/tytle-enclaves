/**
 * Every wait for a vsock peer, in short slices (enclave review 2026-10-09, E-1).
 *
 * A read or write on a vsock is a native call on the event loop. It used to block until the peer answered or the
 * socket's own timeout ran out, so the enclave served nothing else meanwhile (measured: a ping held 23.5 s), and no
 * timer could stop a read that already waited (an answer came 49.5 s after the accept, past the 30 s budget). The
 * native calls now wait at most the time they are given (native/src/vsock.rs: readWithin, writeWithin), and every
 * caller gives them WAIT_SLICE_MS at a time and lets the event loop run before the next call: timers fire, other
 * connections are served, and a deadline is checked before each call and bounds the last one.
 */

/** The longest one native read or write waits for its peer before the event loop runs again. */
export const WAIT_SLICE_MS = 50;

/** A stream whose reads and writes wait at most the time they are given (the native VsockStream). */
export interface SlicedStream {
  /** Up to `size` bytes, an empty buffer at the end of the stream, or null when nothing came within `timeoutMs` */
  readWithin(size: number, timeoutMs: number): Buffer | null;
  /** The number of bytes written (maybe fewer than `data`), or 0 when the peer took nothing within `timeoutMs` */
  writeWithin(data: Buffer, timeoutMs: number): number;
}

/** The most bytes one native read or write moves (a 64 KiB slice of a message or a body). */
export const MAX_IO_CHUNK = 65536;

/** The next turn of the event loop: whatever waits for it (a timer, an accepted connection, an answer) runs first. */
export function nextTurn(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

/** Whether `deadlineMs` has passed: a caller stops before its next native call. No deadline never passes. */
export function deadlinePassed(deadlineMs: number | undefined): boolean {
  return deadlineMs !== undefined && Date.now() > deadlineMs;
}

/**
 * The time the next native call may wait: WAIT_SLICE_MS, or what is left before `deadlineMs` when that is less (0 at
 * the deadline itself: one last look, without waiting). With no deadline, always WAIT_SLICE_MS.
 */
export function sliceBefore(deadlineMs: number | undefined): number {
  if (deadlineMs === undefined) return WAIT_SLICE_MS;
  return Math.max(0, Math.min(WAIT_SLICE_MS, deadlineMs - Date.now()));
}
