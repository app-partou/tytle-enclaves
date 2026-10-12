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
