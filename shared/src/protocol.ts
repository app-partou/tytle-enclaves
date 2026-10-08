/**
 * Length-prefixed message framing for vsock communication.
 *
 * Format: [4-byte big-endian length][JSON payload]
 *
 * Generic over MessageStream so the same framing works with both
 * VsockStream (native addon, inside enclaves) and any other stream
 * implementation (parent server, test mocks).
 */

const HEADER_SIZE = 4;
const MAX_MESSAGE_SIZE = 16 * 1024 * 1024; // 16MB max

/**
 * The whole message did not arrive before its deadline. Each read is a blocking libc::read with a
 * socket timeout (native/src/vsock.rs), which a peer can reset forever by sending one byte at a
 * time; the deadline bounds the whole message, so such a peer cannot hold a connection open.
 */
export class ReadDeadlineError extends Error {
  readonly code = 'READ_DEADLINE' as const;
  constructor(readonly expectedBytes: number, readonly receivedBytes: number) {
    super(`Read deadline passed: expected ${expectedBytes} bytes, got ${receivedBytes}`);
    this.name = 'ReadDeadlineError';
  }
}

export interface ReadOptions {
  /** Epoch ms after which the read gives up (ReadDeadlineError). Checked before every read call. */
  deadlineMs?: number;
}

/**
 * Minimal stream interface for the protocol layer.
 * VsockStream from the native addon implements this shape natively.
 */
export interface MessageStream {
  read(size: number): Buffer;
  write(data: Buffer): number;
}

/** Write a JSON message with length prefix. */
export async function writeMessage(stream: MessageStream, data: unknown): Promise<void> {
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
    if (deadlineMs !== undefined && Date.now() > deadlineMs) {
      throw new ReadDeadlineError(size, size - remaining);
    }
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
