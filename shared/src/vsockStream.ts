/**
 * VsockDuplex — wraps a native VsockStream as a Node.js Duplex.
 *
 * This is needed because `tls.connect({ socket })` requires a Duplex stream.
 * The native VsockStream is a raw fd with read/write methods; this adapter
 * makes it compatible with Node.js streams.
 *
 * Used for TLS-over-vsock: the vsock carries encrypted traffic to vsock-proxy,
 * which tunnels it to the remote server. TLS is negotiated end-to-end between
 * the enclave and the remote server — the host cannot inspect or modify it.
 *
 * Each native read and write waits at most WAIT_SLICE_MS, and the event loop runs between them (vsockWait.ts,
 * enclave review 2026-10-09, E-1). The fetch's own timer (httpProxy.ts) ends a wait that runs too long: it destroys
 * this stream, and the waiting stops.
 */

import { Duplex, type DuplexOptions } from 'node:stream';
import type { VsockStream } from '@tytle-enclaves/native';
import { MAX_IO_CHUNK, WAIT_SLICE_MS } from './vsockWait.js';

export class VsockDuplex extends Duplex {
  private readonly vsock: VsockStream;
  private reading: boolean = false;

  constructor(vsock: VsockStream, opts?: DuplexOptions) {
    super({ ...opts, allowHalfOpen: false });
    this.vsock = vsock;
  }

  _read(size: number): void {
    if (this.reading) return;
    this.reading = true;

    const poll = (): void => {
      if (this.destroyed) {
        this.reading = false;
        return;
      }
      let chunk: Buffer | null;
      try {
        chunk = this.vsock.readWithin(Math.min(size, MAX_IO_CHUNK), WAIT_SLICE_MS);
      } catch (err) {
        this.reading = false;
        this.destroy(err as Error);
        return;
      }
      if (chunk === null) {
        // Nothing yet: let the event loop run, then wait again
        setImmediate(poll);
        return;
      }
      if (chunk.length === 0) {
        // EOF
        this.reading = false;
        this.push(null);
        return;
      }
      if (this.push(Buffer.from(chunk))) {
        // Consumer wants more data — schedule another read
        setImmediate(poll);
      } else {
        this.reading = false;
      }
    };

    setImmediate(poll);
  }

  _write(chunk: Buffer, _encoding: string, callback: (error?: Error | null) => void): void {
    let offset = 0;
    const step = (): void => {
      if (this.destroyed) {
        callback(new Error('vsock stream closed before the write ended'));
        return;
      }
      try {
        offset += this.vsock.writeWithin(Buffer.from(chunk.subarray(offset, offset + MAX_IO_CHUNK)), WAIT_SLICE_MS);
      } catch (err) {
        callback(err as Error);
        return;
      }
      // No room yet, or more to write: let the event loop run, then go on
      if (offset < chunk.length) setImmediate(step);
      else callback();
    };
    step();
  }

  _destroy(err: Error | null, callback: (error: Error | null) => void): void {
    try {
      this.vsock.close();
    } catch {
      // Ignore close errors during destroy
    }
    callback(err);
  }
}
