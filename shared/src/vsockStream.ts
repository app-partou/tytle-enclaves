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
 */

import { Duplex, type DuplexOptions } from 'node:stream';
import type { VsockStream } from '@tytle-enclaves/native';

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

    // Note: vsock.read() is a blocking libc::read call. For the single-request
    // enclave pattern this is fine. For concurrent streams, consider worker_threads.
    const poll = (): void => {
      try {
        const chunk = this.vsock.read(Math.min(size, 65536));
        if (chunk.length === 0) {
          // EOF
          this.push(null);
          this.reading = false;
          return;
        }
        const more = this.push(Buffer.from(chunk));
        if (more) {
          // Consumer wants more data — schedule another read
          setImmediate(poll);
        } else {
          this.reading = false;
        }
      } catch (err) {
        this.destroy(err as Error);
      }
    };

    setImmediate(poll);
  }

  _write(chunk: Buffer, _encoding: string, callback: (error?: Error | null) => void): void {
    try {
      let offset = 0;
      while (offset < chunk.length) {
        const remaining = Buffer.from(chunk.subarray(offset));
        const written = this.vsock.write(remaining);
        if (written === 0) {
          callback(new Error('vsock write returned 0'));
          return;
        }
        offset += written;
      }
      callback();
    } catch (err) {
      callback(err as Error);
    }
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
