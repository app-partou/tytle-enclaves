/**
 * HTTP/1.1 response reading for the enclave's fetches - pure, no sockets.
 *
 * The enclave signs what it parses out of a reply, so a reply it cannot read COMPLETELY must be an
 * error, never a body: a host that cuts the connection short (any host can close a TCP connection,
 * even under TLS) would otherwise get a truncated SOAP or JSON body parsed and signed (audit 2026-10
 * §5, July D8). The rules:
 *   - at most MAX_RESPONSE_BYTES are read (ResponseTooLargeError);
 *   - Content-Length: the body is exactly that many bytes (fewer: IncompleteBodyError; more, a
 *     non-number or two different values: MalformedResponseError);
 *   - Transfer-Encoding: only `chunked`, each chunk complete and followed by CRLF, ended by the
 *     terminal chunk and the final CRLF, nothing after it (IncompleteBodyError when cut short,
 *     MalformedResponseError when out of frame); together with Content-Length it is refused
 *     (RFC 9112 §6.3: a smuggling signal);
 *   - neither header: the body runs to the end of the connection (every request sends
 *     `Connection: close`). Truncation is undetectable there; the handlers' rule that a parse miss
 *     is an error is the backstop.
 */

import { IncompleteBodyError, MalformedResponseError, ResponseTooLargeError } from './httpErrors.js';

/** The most bytes of one reply (head + body) the enclave reads. VIES SOAP is ~2 KB, a SICAE page ~100 KB, a Stripe list <= 1 MB. */
export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

const CRLF = Buffer.from('\r\n');
const HEAD_END = Buffer.from('\r\n\r\n');

/** Up to 8 hex digits (4 GiB): anything larger is beyond MAX_RESPONSE_BYTES by construction. */
const CHUNK_SIZE_PATTERN = /^[0-9a-fA-F]{1,8}$/;
const CONTENT_LENGTH_PATTERN = /^\d{1,10}$/;

/**
 * Collects the bytes of one reply and refuses to hold more than `limitBytes`.
 * `push` throws ResponseTooLargeError as soon as the limit is passed; the caller destroys the socket.
 */
export class ResponseCollector {
  private readonly chunks: Buffer[] = [];
  private received = 0;

  constructor(private readonly hostname: string, private readonly limitBytes: number = MAX_RESPONSE_BYTES) {}

  push(chunk: Buffer): void {
    this.received += chunk.length;
    if (this.received > this.limitBytes) {
      throw new ResponseTooLargeError(this.hostname, this.received, this.limitBytes);
    }
    this.chunks.push(chunk);
  }

  /** The reply, read under the rules above. */
  finish(): HttpResponse {
    return parseHttpResponse(Buffer.concat(this.chunks));
  }
}

/**
 * Parse one complete HTTP/1.1 response. Works on bytes so chunk sizes index the data correctly when the
 * body holds multi-byte UTF-8; the header section is ASCII, the body is decoded after de-chunking.
 * Header names are lower-cased; a repeated header keeps its last value (Content-Length and
 * Transfer-Encoding are checked across every occurrence).
 */
export function parseHttpResponse(raw: Buffer): HttpResponse {
  const headEnd = raw.indexOf(HEAD_END);
  if (headEnd === -1) {
    throw new MalformedResponseError('head', 'no header/body separator');
  }

  const lines = raw.subarray(0, headEnd).toString('ascii').split('\r\n');
  const statusMatch = lines[0].match(/^HTTP\/\d\.\d\s+(\d{3})(?:\s|$)/);
  if (!statusMatch) {
    throw new MalformedResponseError('status-line', JSON.stringify(lines[0].slice(0, 64)));
  }
  const status = parseInt(statusMatch[1], 10);

  const headers: Record<string, string> = {};
  const contentLengths: string[] = [];
  const transferCodings: string[] = [];
  for (let i = 1; i < lines.length; i++) {
    const colon = lines[i].indexOf(':');
    if (colon <= 0) continue;
    const key = lines[i].substring(0, colon).trim().toLowerCase();
    const value = lines[i].substring(colon + 1).trim();
    headers[key] = value;
    if (key === 'content-length') contentLengths.push(value);
    if (key === 'transfer-encoding') {
      transferCodings.push(...value.split(',').map((c) => c.trim().toLowerCase()).filter((c) => c !== ''));
    }
  }

  const bodyBytes = raw.subarray(headEnd + HEAD_END.length);
  return { status, headers, body: frameBody(bodyBytes, contentLengths, transferCodings).toString('utf-8') };
}

function frameBody(body: Buffer, contentLengths: string[], transferCodings: string[]): Buffer {
  if (transferCodings.length > 0) {
    if (contentLengths.length > 0) {
      throw new MalformedResponseError('framing', 'both Transfer-Encoding and Content-Length');
    }
    if (transferCodings.length !== 1 || transferCodings[0] !== 'chunked') {
      throw new MalformedResponseError('transfer-encoding', `unsupported transfer coding "${transferCodings.join(', ')}"`);
    }
    return decodeChunked(body);
  }

  if (contentLengths.length > 0) {
    if (new Set(contentLengths).size > 1) {
      throw new MalformedResponseError('content-length', `conflicting values ${contentLengths.join(' / ')}`);
    }
    const declared = contentLengths[0];
    if (!CONTENT_LENGTH_PATTERN.test(declared)) {
      throw new MalformedResponseError('content-length', `not a decimal length: "${declared.slice(0, 32)}"`);
    }
    const expected = Number(declared);
    if (body.length < expected) {
      throw new IncompleteBodyError(`Content-Length ${expected}, received ${body.length}`);
    }
    if (body.length > expected) {
      throw new MalformedResponseError('content-length', `Content-Length ${expected}, received ${body.length}`);
    }
    return body;
  }

  return body;
}

/**
 * Decode a chunked body (RFC 9112 §7.1): chunks of `size[;ext]CRLF data CRLF`, then `0[;ext]CRLF`,
 * optional trailer fields, and the final CRLF. Every chunk must be complete; nothing may follow.
 */
export function decodeChunked(raw: Buffer): Buffer {
  const parts: Buffer[] = [];
  let offset = 0;

  for (;;) {
    const sizeLineEnd = raw.indexOf(CRLF, offset);
    if (sizeLineEnd === -1) {
      throw new IncompleteBodyError('the chunked body ends inside a chunk-size line');
    }
    const sizeToken = raw.subarray(offset, sizeLineEnd).toString('ascii').split(';', 1)[0].trim();
    if (!CHUNK_SIZE_PATTERN.test(sizeToken)) {
      throw new MalformedResponseError('chunk-size', `"${sizeToken.slice(0, 32)}" is not a hexadecimal chunk size`);
    }
    const size = parseInt(sizeToken, 16);
    const dataStart = sizeLineEnd + CRLF.length;

    if (size === 0) {
      return endOfChunkedBody(raw, dataStart, parts);
    }

    const dataEnd = dataStart + size;
    if (dataEnd + CRLF.length > raw.length) {
      throw new IncompleteBodyError(`a chunk of ${size} bytes is cut short`);
    }
    if (raw[dataEnd] !== CRLF[0] || raw[dataEnd + 1] !== CRLF[1]) {
      throw new MalformedResponseError('chunk', `the ${size}-byte chunk is not followed by CRLF`);
    }
    parts.push(raw.subarray(dataStart, dataEnd));
    offset = dataEnd + CRLF.length;
  }
}

/** After the terminal chunk: trailer field lines, then an empty line that must be the last bytes. */
function endOfChunkedBody(raw: Buffer, from: number, parts: Buffer[]): Buffer {
  let lineStart = from;
  for (;;) {
    const lineEnd = raw.indexOf(CRLF, lineStart);
    if (lineEnd === -1) {
      throw new IncompleteBodyError('the chunked body ends without its final CRLF');
    }
    if (lineEnd === lineStart) {
      if (lineEnd + CRLF.length !== raw.length) {
        throw new MalformedResponseError('chunked', `${raw.length - lineEnd - CRLF.length} bytes after the end of the chunked body`);
      }
      return Buffer.concat(parts);
    }
    lineStart = lineEnd + CRLF.length;
  }
}
