/**
 * The vsock framing: [4-byte big-endian length][JSON]. readMessage runs for real over a scripted
 * stream; the clock is the only other thing replaced.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { readMessage, writeMessage, type MessageStream } from '../protocol.js';

/** A stream that hands out the given bytes `perRead` at a time and moves the clock `msPerRead` per read. */
function trickle(bytes: Buffer, perRead: number, clock?: { now: number; msPerRead: number }): MessageStream & { reads: number } {
  let offset = 0;
  const stream = {
    reads: 0,
    read(size: number): Buffer {
      stream.reads++;
      if (clock) clock.now += clock.msPerRead;
      const n = Math.min(size, perRead, bytes.length - offset);
      const out = bytes.subarray(offset, offset + n);
      offset += n;
      return out;
    },
    write(data: Buffer): number {
      return data.length;
    },
  };
  return stream;
}

function frame(message: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(message), 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('readMessage (locks)', () => {
  it('reads a complete frame', async () => {
    await expect(readMessage(trickle(frame({ a: 1 }), 65536))).resolves.toEqual({ a: 1 });
  });

  it('reads a frame that arrives a byte at a time when no deadline is given', async () => {
    await expect(readMessage(trickle(frame({ type: 'ping' }), 1))).resolves.toEqual({ type: 'ping' });
  });

  it('refuses a length over 16 MiB before reading the payload', async () => {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(16 * 1024 * 1024 + 1, 0);
    const stream = trickle(header, 65536);
    await expect(readMessage(stream)).rejects.toThrow('Message too large');
    expect(stream.reads).toBe(1);
  });

  it('refuses an empty message', async () => {
    await expect(readMessage(trickle(Buffer.alloc(4), 65536))).rejects.toThrow('Empty message received');
  });

  it('a stream that closes mid-frame is an error naming the bytes it got', async () => {
    await expect(readMessage(trickle(frame({ a: 1 }).subarray(0, 6), 65536))).rejects.toThrow('expected 7 bytes, got 2');
  });

  it('writeMessage frames what readMessage reads', async () => {
    const written: Buffer[] = [];
    await writeMessage({ read: () => Buffer.alloc(0), write: (d: Buffer) => { written.push(Buffer.from(d)); return d.length; } }, { b: 'é' });
    await expect(readMessage(trickle(Buffer.concat(written), 3))).resolves.toEqual({ b: 'é' });
  });
});

describe('readMessage with a deadline', () => {
  it('a peer that trickles a byte per read past the deadline gets ReadDeadlineError naming the bytes it sent', async () => {
    const clock = { now: 1_000_000, msPerRead: 3_000 };
    vi.spyOn(Date, 'now').mockImplementation(() => clock.now);
    const message = { id: 'x'.repeat(40) };
    const stream = trickle(frame(message), 1, clock);

    const err = await readMessage(stream, { deadlineMs: clock.now + 10_000 }).catch((e: unknown) => e);
    // The 4 header bytes arrive by t+12s (one per read, 3 s apart); the check before the first payload
    // read sees t+12s > t+10s and stops, with none of the payload's bytes read.
    expect(err).toMatchObject({
      name: 'ReadDeadlineError',
      code: 'READ_DEADLINE',
      expectedBytes: JSON.stringify(message).length,
      receivedBytes: 0,
    });
    expect(stream.reads).toBe(4);
  });

  it('a peer that stalls inside the 4-byte length header is cut off there', async () => {
    const clock = { now: 2_000_000, msPerRead: 5_000 };
    vi.spyOn(Date, 'now').mockImplementation(() => clock.now);
    const stream = trickle(frame({ a: 1 }), 1, clock);

    const err = await readMessage(stream, { deadlineMs: clock.now + 10_000 }).catch((e: unknown) => e);
    // Header bytes 1-3 arrive at t+5s, t+10s, t+15s; the check before the 4th (t+15s > t+10s) stops it.
    expect(err).toMatchObject({ name: 'ReadDeadlineError', expectedBytes: 4, receivedBytes: 3 });
  });

  it('a frame that arrives before its deadline is read', async () => {
    const clock = { now: 1_000_000, msPerRead: 1 };
    vi.spyOn(Date, 'now').mockImplementation(() => clock.now);
    await expect(readMessage(trickle(frame({ ok: true }), 2, clock), { deadlineMs: clock.now + 10_000 })).resolves.toEqual({ ok: true });
  });
});
