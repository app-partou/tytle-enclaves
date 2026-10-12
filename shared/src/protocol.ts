/**
 * Length-prefixed message framing for vsock communication.
 *
 * Format: [4-byte big-endian length][JSON payload]
 *
 * Generic over MessageStream so the same framing works with both
 * VsockStream (native addon, inside enclaves and in the parent) and test streams.
 *
 * Every read and write waits in slices (vsockWait.ts, enclave review 2026-10-09, E-1): the event loop runs between
 * them, and a deadline over the whole message is checked before each one and bounds the last.
 */

import { MAX_IO_CHUNK, deadlinePassed, nextTurn, sliceBefore, type SlicedStream } from './vsockWait.js';

const HEADER_SIZE = 4;
const MAX_MESSAGE_SIZE = 16 * 1024 * 1024; // 16MB max

/**
 * The whole message did not arrive before its deadline: a peer that sends one byte at a time cannot hold a
 * connection open. The deadline is exact: no read waits past it (E1 F-6: each blocking read could wait one more
 * socket timeout past it).
 */
export class ReadDeadlineError extends Error {
  readonly code = 'READ_DEADLINE' as const;
  constructor(readonly expectedBytes: number, readonly receivedBytes: number) {
    super(`Read deadline passed: expected ${expectedBytes} bytes, got ${receivedBytes}`);
    this.name = 'ReadDeadlineError';
  }
}

/**
 * The whole message could not be written before its deadline: a peer that drains a little at a time cannot hold the
 * writer (E1 F-10: a write had no deadline, and each one could block for the socket's timeout).
 */
export class WriteDeadlineError extends Error {
  readonly code = 'WRITE_DEADLINE' as const;
  constructor(readonly expectedBytes: number, readonly writtenBytes: number) {
    super(`Write deadline passed: wrote ${writtenBytes} of ${expectedBytes} bytes`);
    this.name = 'WriteDeadlineError';
  }
}

export interface ReadOptions {
  /** Epoch ms after which the read gives up (ReadDeadlineError); no read waits past it. */
  deadlineMs?: number;
}

export interface WriteOptions {
  /** Epoch ms after which the write gives up (WriteDeadlineError); no write waits past it. */
  deadlineMs?: number;
}

/**
 * Minimal stream interface for the protocol layer: reads and writes that wait at most the time they are given.
 * VsockStream from the native addon implements this shape natively.
 */
export type MessageStream = SlicedStream;

/** Write a JSON message with length prefix, giving up once `options.deadlineMs` has passed. */
export async function writeMessage(stream: MessageStream, data: unknown, options: WriteOptions = {}): Promise<void> {
  const json = JSON.stringify(data);
  const payload = Buffer.from(json, 'utf-8');

  if (payload.length > MAX_MESSAGE_SIZE) {
    throw new Error(`Message too large: ${payload.length} bytes (max ${MAX_MESSAGE_SIZE})`);
  }

  const header = Buffer.alloc(HEADER_SIZE);
  header.writeUInt32BE(payload.length, 0);

  const frame = Buffer.concat([header, payload]);

  let offset = 0;
  while (offset < frame.length) {
    if (deadlinePassed(options.deadlineMs)) throw new WriteDeadlineError(frame.length, offset);
    offset += stream.writeWithin(Buffer.from(frame.subarray(offset, offset + MAX_IO_CHUNK)), sliceBefore(options.deadlineMs));
    if (offset < frame.length) await nextTurn();
  }
}

/** Read a length-prefixed JSON message. Returns parsed object. */
export async function readMessage<T = unknown>(stream: MessageStream, options: ReadOptions = {}): Promise<T> {
  const header = await readExact(stream, HEADER_SIZE, options.deadlineMs);
  const length = header.readUInt32BE(0);

  if (length === 0) {
    throw new Error('Empty message received');
  }
  if (length > MAX_MESSAGE_SIZE) {
    throw new Error(`Message too large: ${length} bytes (max ${MAX_MESSAGE_SIZE})`);
  }

  const payload = await readExact(stream, length, options.deadlineMs);
  const json = payload.toString('utf-8');

  return JSON.parse(json) as T;
}

/** Read exactly `size` bytes from the stream, giving up once `deadlineMs` has passed. */
async function readExact(stream: MessageStream, size: number, deadlineMs?: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let remaining = size;

  while (remaining > 0) {
    if (deadlinePassed(deadlineMs)) throw new ReadDeadlineError(size, size - remaining);
    const chunk = stream.readWithin(Math.min(remaining, MAX_IO_CHUNK), sliceBefore(deadlineMs));

    if (chunk !== null) {
      if (chunk.length === 0) {
        throw new Error(`Connection closed: expected ${size} bytes, got ${size - remaining}`);
      }
      chunks.push(Buffer.from(chunk));
      remaining -= chunk.length;
    }
    // Between two reads the event loop runs, whether bytes came or not: a peer that sends a byte now and then
    // must not keep the loop for itself.
    if (remaining > 0) await nextTurn();
  }

  return Buffer.concat(chunks);
}
