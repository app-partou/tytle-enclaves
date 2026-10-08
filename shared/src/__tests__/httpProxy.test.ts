/**
 * The enclave's HTTP leg, driven through its real entry points (proxyFetchPlain, proxyFetch) with only
 * the vsock socket (and, for TLS, the TLS socket) replaced: the bytes an upstream sends are scripted,
 * everything that reads them runs for real.
 *
 * A reply the enclave cannot read completely must never come back as a parsed body: the handler would
 * parse a truncated SOAP or JSON body and the enclave would sign it (audit 2026-10 §5, July D8).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'node:events';

/** A vsock socket that hands out scripted bytes, then EOF. */
class ScriptedVsock {
  readonly written: Buffer[] = [];
  closed = false;
  private readonly pending: Buffer[];
  constructor(chunks: Buffer[]) {
    this.pending = [...chunks];
  }
  read(size: number): Buffer {
    const next = this.pending.shift();
    if (!next) return Buffer.alloc(0);
    if (next.length > size) {
      this.pending.unshift(next.subarray(size));
      return next.subarray(0, size);
    }
    return next;
  }
  write(data: Buffer): number {
    this.written.push(Buffer.from(data));
    return data.length;
  }
  close(): void {
    this.closed = true;
  }
}

const { connect } = vi.hoisted(() => ({ connect: vi.fn() }));
vi.mock('@tytle-enclaves/native', () => ({ VsockStream: { connect } }));

const { tlsConnect } = vi.hoisted(() => ({ tlsConnect: vi.fn() }));
vi.mock('node:tls', () => ({ connect: tlsConnect }));

import { proxyFetch, proxyFetchPlain } from '../httpProxy.js';
import { IncompleteBodyError, MalformedResponseError, ResponseTooLargeError } from '../httpErrors.js';

function scripted(...parts: Array<string | Buffer>): ScriptedVsock {
  const sock = new ScriptedVsock(parts.map((p) => (typeof p === 'string' ? Buffer.from(p, 'utf-8') : p)));
  connect.mockReturnValue(sock);
  return sock;
}

function fetchPlain() {
  return proxyFetchPlain(8445, 'www.sicae.pt', 'GET', '/Consulta.aspx', {}, undefined, 5_000);
}

beforeEach(() => {
  connect.mockReset();
  tlsConnect.mockReset();
});

describe('proxyFetchPlain - replies it reads completely (locks)', () => {
  it('reads a body of exactly its Content-Length', async () => {
    scripted('HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 11\r\n\r\nhello world');
    const res = await fetchPlain();
    expect(res).toEqual({ status: 200, headers: { 'content-type': 'text/xml', 'content-length': '11' }, body: 'hello world' });
  });

  it('decodes a chunked body whose chunks split a multi-byte character', async () => {
    const euro = Buffer.from('€', 'utf-8'); // 3 bytes
    scripted(
      'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n',
      Buffer.concat([Buffer.from('4\r\nab'), euro.subarray(0, 2), Buffer.from('\r\n')]),
      Buffer.concat([Buffer.from('3\r\n'), euro.subarray(2), Buffer.from('cd\r\n')]),
      '0\r\n\r\n',
    );
    const res = await fetchPlain();
    expect(res.body).toBe('ab€cd');
  });

  it('reads a body delimited by the server closing the connection (no Content-Length, not chunked)', async () => {
    scripted('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>', '</html>');
    const res = await fetchPlain();
    expect(res.body).toBe('<html></html>');
  });

  it('reads a 204 with no body', async () => {
    scripted('HTTP/1.1 204 No Content\r\n\r\n');
    const res = await fetchPlain();
    expect(res).toEqual({ status: 204, headers: {}, body: '' });
  });

  it('reads chunk extensions and trailer fields', async () => {
    scripted('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;name=value\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n');
    const res = await fetchPlain();
    expect(res.body).toBe('hello');
  });

  it('sends the request with Host and Connection: close after the caller headers', async () => {
    const sock = scripted('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n');
    await proxyFetchPlain(8445, 'www.sicae.pt', 'POST', '/Consulta.aspx', { Host: 'evil', 'X-A': 'b' }, 'a=1', 5_000);
    const sent = Buffer.concat(sock.written).toString('utf-8');
    expect(sent).toBe('POST /Consulta.aspx HTTP/1.1\r\nHost: www.sicae.pt\r\nX-A: b\r\nConnection: close\r\nContent-Length: 3\r\n\r\na=1');
  });
});

describe('proxyFetchPlain - a reply cut short or out of frame is an error, never a body', () => {
  it('a body shorter than its Content-Length is IncompleteBodyError', async () => {
    scripted('HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n', 'x'.repeat(60));
    await expect(fetchPlain()).rejects.toBeInstanceOf(IncompleteBodyError);
  });

  it('a body longer than its Content-Length is MalformedResponseError', async () => {
    scripted('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nabcdef');
    await expect(fetchPlain()).rejects.toBeInstanceOf(MalformedResponseError);
  });

  it('a Content-Length that is not a decimal number is MalformedResponseError', async () => {
    scripted('HTTP/1.1 200 OK\r\nContent-Length: 1x\r\n\r\nx');
    await expect(fetchPlain()).rejects.toBeInstanceOf(MalformedResponseError);
  });

  it('two different Content-Length headers are MalformedResponseError', async () => {
    scripted('HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc');
    await expect(fetchPlain()).rejects.toBeInstanceOf(MalformedResponseError);
  });

  it('a chunked body that ends before its terminal chunk is IncompleteBodyError', async () => {
    scripted('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n');
    await expect(fetchPlain()).rejects.toBeInstanceOf(IncompleteBodyError);
  });

  it('a chunk that announces more bytes than arrive is IncompleteBodyError', async () => {
    scripted('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nonly-ten-b');
    await expect(fetchPlain()).rejects.toBeInstanceOf(IncompleteBodyError);
  });

  it('a chunked body that ends after "0\\r\\n" without its final CRLF is IncompleteBodyError', async () => {
    scripted('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n');
    await expect(fetchPlain()).rejects.toBeInstanceOf(IncompleteBodyError);
  });

  it('a chunk size that is not hexadecimal is MalformedResponseError', async () => {
    scripted('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1g\r\nx\r\n0\r\n\r\n');
    await expect(fetchPlain()).rejects.toBeInstanceOf(MalformedResponseError);
  });

  it('chunk data not followed by CRLF is MalformedResponseError', async () => {
    // Skipping the two bytes after "hi" would land on a valid terminal chunk: only the CRLF check refuses it.
    scripted('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhiXY0\r\n\r\n');
    await expect(fetchPlain()).rejects.toBeInstanceOf(MalformedResponseError);
  });

  it('a chunked body cut inside its trailer section is IncompleteBodyError', async () => {
    scripted('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-Trailer: 1\r\n');
    await expect(fetchPlain()).rejects.toBeInstanceOf(IncompleteBodyError);
  });

  it('a status code that is not three digits is MalformedResponseError', async () => {
    scripted('HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n');
    await expect(fetchPlain()).rejects.toBeInstanceOf(MalformedResponseError);
  });

  it('bytes after the end of a chunked body are MalformedResponseError', async () => {
    scripted('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\nHTTP/1.1 200 OK\r\n\r\nsmuggled');
    await expect(fetchPlain()).rejects.toBeInstanceOf(MalformedResponseError);
  });

  it('Transfer-Encoding together with Content-Length is MalformedResponseError', async () => {
    scripted('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n2\r\nhi\r\n0\r\n\r\n');
    await expect(fetchPlain()).rejects.toBeInstanceOf(MalformedResponseError);
  });

  it('a transfer coding other than chunked is MalformedResponseError (the enclave cannot decode it)', async () => {
    scripted('HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n');
    await expect(fetchPlain()).rejects.toBeInstanceOf(MalformedResponseError);
  });

  it('a reply that ends inside its header section is MalformedResponseError', async () => {
    scripted('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n');
    await expect(fetchPlain()).rejects.toBeInstanceOf(MalformedResponseError);
  });

  it('a reply over 4 MiB is ResponseTooLargeError, and the socket is closed at once', async () => {
    const mib = Buffer.alloc(1024 * 1024, 0x61);
    const sock = scripted('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n', mib, mib, mib, mib, mib, mib);
    await expect(fetchPlain()).rejects.toBeInstanceOf(ResponseTooLargeError);
    expect(sock.closed).toBe(true);
  });
});

describe('proxyFetch (TLS) - the same reading rules', () => {
  /** A TLS socket stand-in: the handshake callback fires, then the scripted bytes arrive. */
  function scriptedTls(...parts: string[]) {
    const sock = scripted(); // the vsock leg carries only TLS records, unseen here
    const tlsSocket = Object.assign(new EventEmitter(), {
      write: vi.fn(),
      destroy: vi.fn(),
    });
    tlsConnect.mockImplementation((_opts: unknown, onSecure: () => void) => {
      setImmediate(() => {
        onSecure();
        for (const p of parts) tlsSocket.emit('data', Buffer.from(p, 'utf-8'));
        tlsSocket.emit('end');
      });
      return tlsSocket;
    });
    return { sock, tlsSocket };
  }

  it('reads a complete Content-Length body (lock)', async () => {
    scriptedTls('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok');
    const res = await proxyFetch(8443, 'ec.europa.eu', 'POST', '/x', {}, 'b', 5_000);
    expect(res.body).toBe('ok');
  });

  it('a TLS reply shorter than its Content-Length is IncompleteBodyError', async () => {
    scriptedTls('HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n<valid>tr');
    await expect(proxyFetch(8443, 'ec.europa.eu', 'POST', '/x', {}, 'b', 5_000)).rejects.toBeInstanceOf(IncompleteBodyError);
  });

  it('a TLS reply over 4 MiB is ResponseTooLargeError and both sockets are closed', async () => {
    const big = 'a'.repeat(1024 * 1024);
    const { sock, tlsSocket } = scriptedTls('HTTP/1.1 200 OK\r\n\r\n', big, big, big, big, big);
    await expect(proxyFetch(8443, 'ec.europa.eu', 'POST', '/x', {}, 'b', 5_000)).rejects.toBeInstanceOf(ResponseTooLargeError);
    expect(tlsSocket.destroy).toHaveBeenCalled();
    expect(sock.closed).toBe(true);
  });
});
