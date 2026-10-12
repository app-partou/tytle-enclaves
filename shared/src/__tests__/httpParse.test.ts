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
import { parseHttpResponse } from '../httpParse.js';
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
