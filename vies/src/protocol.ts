/**
 * Length-prefixed message framing for vsock communication.
 *
 * Format: [4-byte big-endian length][JSON payload]
 *
 * This is necessary because vsock is a stream protocol — there are no
 * message boundaries. Without framing, a large response could arrive
 * in multiple chunks and be misinterpreted.
 */

import type { VsockStream } from '@tytle-enclaves/native';

const HEADER_SIZE = 4;
const MAX_MESSAGE_SIZE = 16 * 1024 * 1024; // 16MB max

/** Write a JSON message with length prefix. */
export async function writeMessage(stream: VsockStream, data: unknown): Promise<void> {
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
    const chunk = Buffer.from(frame.subarray(offset));
    const written = stream.write(chunk);
    offset += written;
  }
}

/** Read a length-prefixed JSON message. Returns parsed object. */
export async function readMessage<T = unknown>(stream: VsockStream): Promise<T> {
  // Read 4-byte header
  const header = await readExact(stream, HEADER_SIZE);
  const length = header.readUInt32BE(0);

  if (length === 0) {
    throw new Error('Empty message received');
  }
  if (length > MAX_MESSAGE_SIZE) {
    throw new Error(`Message too large: ${length} bytes (max ${MAX_MESSAGE_SIZE})`);
  }

  // Read payload
  const payload = await readExact(stream, length);
  const json = payload.toString('utf-8');

  return JSON.parse(json) as T;
}

/** Read exactly `size` bytes from the stream. */
async function readExact(stream: VsockStream, size: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let remaining = size;

  while (remaining > 0) {
    const readSize = Math.min(remaining, 65536);
    const chunk = stream.read(readSize);

    if (chunk.length === 0) {
      throw new Error(`Connection closed: expected ${size} bytes, got ${size - remaining}`);
    }

    chunks.push(Buffer.from(chunk));
    remaining -= chunk.length;
  }

  return Buffer.concat(chunks);
}
