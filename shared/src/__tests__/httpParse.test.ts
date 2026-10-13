/**
 * The header section of a reply, as parseHttpResponse reads it (enclave review 2026-10-09, E1 F-1).
 *
 * A repeated header kept its last value. Set-Cookie is the one header RFC 9110 §5.3 says is never combined, and a
 * site (or a load balancer before it) may send several: SICAE's session cookie was dropped whenever another cookie
 * came after it. Every Set-Cookie value is now kept, one per line (a header value never holds a line break).
 *
 * Pure: parseHttpResponse takes the reply's bytes, no socket.
 */
import { describe, it, expect } from 'vitest';
import { parseHttpResponse, ResponseCollector } from '../httpParse.js';
import { MalformedResponseError } from '../httpErrors.js';

const reply = (headLines: string[], body = 'ok'): Buffer =>
  Buffer.from([...headLines, `Content-Length: ${Buffer.byteLength(body)}`].join('\r\n') + `\r\n\r\n${body}`);

describe('repeated headers', () => {
  it('a repeated Set-Cookie keeps every value, one per line, in order (red before)', () => {
    const r = parseHttpResponse(reply([
      'HTTP/1.1 200 OK',
      'Set-Cookie: ASP.NET_SessionId=abc123; path=/; HttpOnly',
      'set-cookie: BIGipServerpool=1234567.20480.0000; path=/',
    ]));
    expect(r.headers['set-cookie']).toBe('ASP.NET_SessionId=abc123; path=/; HttpOnly\nBIGipServerpool=1234567.20480.0000; path=/');
  });

  it('one Set-Cookie is that value (lock)', () => {
    const r = parseHttpResponse(reply(['HTTP/1.1 200 OK', 'Set-Cookie: a=1; path=/']));
    expect(r.headers['set-cookie']).toBe('a=1; path=/');
  });

  it('any other repeated header keeps its last value (lock)', () => {
    const r = parseHttpResponse(reply(['HTTP/1.1 200 OK', 'X-Thing: first', 'x-thing: second']));
    expect(r.headers['x-thing']).toBe('second');
  });
});

describe('the bytes of a reply are read as they are (enclave review 2026-10-09, E1 F-13)', () => {
  const withBody = (body: Buffer): Buffer =>
    Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n`), body]);

  it('a body that is not UTF-8 is an error, never a text with U+FFFD in it: a hash of it would not be of the bytes sent (red before)', () => {
    const raw = withBody(Buffer.from([0x61, 0xff, 0x62]));
    expect(() => parseHttpResponse(raw)).toThrow(MalformedResponseError);
    expect(() => parseHttpResponse(raw)).toThrow('Malformed HTTP response (body): not UTF-8');
  });

  it('a UTF-8 body is its text, a byte-order mark kept: the text is the bytes sent (lock)', () => {
    const text = '\ufeff{"name":"Comércio"}';
    expect(parseHttpResponse(withBody(Buffer.from(text, 'utf-8'))).body).toBe(text);
  });

  it('a head byte 0x8D 0x8A does not end a header line: the head is read byte for byte, not as 7-bit ASCII (red before)', () => {
    const raw = Buffer.concat([
      Buffer.from('HTTP/1.1 200 OK\r\nX-Note: a'), Buffer.from([0x8d, 0x8a]), Buffer.from('Injected: yes\r\nContent-Length: 2\r\n\r\nok'),
    ]);
    const r = parseHttpResponse(raw);
    expect(r.headers.injected).toBeUndefined();
    expect(r.headers['x-note']).toBe('a\u008d\u008aInjected: yes');
  });
});

describe('an interim reply is not the answer (enclave review 2026-10-09, E1 F-2)', () => {
  // RFC 9110 §15.2: a client must read 1xx replies before the final one, even when it asked for none. Before, the first
  // head was the answer: `100 Continue` came back as status 100 with the real reply as its body.
  const parse = (text: string) => parseHttpResponse(Buffer.from(text));

  it('a 100 Continue before the answer is skipped: the answer is the reply after it (red before)', () => {
    expect(parse('HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'))
      .toEqual({ status: 200, headers: { 'content-length': '2' }, body: 'ok' });
  });

  it('a 103 Early Hints is skipped with its headers: they are not the answer\'s (red before)', () => {
    expect(parse('HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'))
      .toEqual({ status: 200, headers: { 'content-length': '2' }, body: 'ok' });
  });

  it('interim replies in a row are all skipped (red before)', () => {
    expect(parse('HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n'))
      .toEqual({ status: 404, headers: { 'content-length': '0' }, body: '' });
  });

  it('an interim reply and then nothing is an error, never an answer with status 100 (red before)', () => {
    expect(() => parse('HTTP/1.1 100 Continue\r\n\r\n')).toThrow(MalformedResponseError);
  });

  it('a 101 Switching Protocols is final: HTTP ends there, and no handler takes it for an answer (lock)', () => {
    expect(parse('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n').status).toBe(101);
  });
});

describe('ResponseCollector: when a reply is complete by its own framing, byte by byte (E1 F-3)', () => {
  // The collector reads the framing as the bytes come, so a fetch can end before the connection does. Each reply here
  // comes one byte at a time, the hardest split: every line end and every head end falls between two reads.
  /** How many bytes were in when complete() first said yes; null when it never did. */
  function completeAt(text: string): number | null {
    const collector = new ResponseCollector('example.org');
    const bytes = Buffer.from(text, 'utf-8');
    for (let i = 0; i < bytes.length; i++) {
      collector.push(bytes.subarray(i, i + 1));
      if (collector.complete()) return i + 1;
    }
    return null;
  }

  function collected(...pieces: Buffer[]): ResponseCollector {
    const collector = new ResponseCollector('example.org');
    for (const piece of pieces) collector.push(piece);
    return collector;
  }

  it.each([
    ['a Content-Length body', 'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello'],
    ['an empty Content-Length body', 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'],
    ['a chunked body, with an extension and a trailer', 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=y\r\nhello\r\n1\r\n!\r\n0\r\nX-Trailer: 1\r\n\r\n'],
    ['a chunked body of a CRLF', 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n\r\n\r\n0\r\n\r\n'],
    ['an answer after interim replies', 'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'],
  ])('%s: complete at its last byte, not before, and read as the whole reply is (red before)', (_label, text) => {
    expect(completeAt(text)).toBe(Buffer.byteLength(text));
    expect(collected(Buffer.from(text)).finish()).toEqual(parseHttpResponse(Buffer.from(text)));
  });

  it('a body that runs to the end of the connection is never complete before it (red before)', () => {
    expect(completeAt('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>')).toBeNull();
  });

  it.each([
    ['a status line that is not one', 'HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n', 'HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n'],
    ['both Transfer-Encoding and Content-Length', 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n2\r\nhi', 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n'],
    ['a chunk size that is not hexadecimal', 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1g\r\nx\r\n0\r\n\r\n', 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1g\r\n'],
    ['chunk data not followed by CRLF', 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhiXY0\r\n\r\n', 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhiXY'],
  ])('%s: complete as soon as no later byte could mend it, and finish() throws (red before)', (_label, text, brokenBy) => {
    expect(completeAt(text)).toBe(Buffer.byteLength(brokenBy));
    expect(() => collected(Buffer.from(brokenBy)).finish()).toThrow(MalformedResponseError);
  });

  it('keeps every byte, whatever sizes they come in (lock)', () => {
    const body = 'x'.repeat(100_000);
    const reply = Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
    expect(collected(reply).finish().body).toBe(body);
    const pieces: Buffer[] = [];
    for (let i = 0; i < reply.length; i += 7_001) pieces.push(reply.subarray(i, i + 7_001));
    expect(collected(...pieces).finish().body).toBe(body);
  });
});
