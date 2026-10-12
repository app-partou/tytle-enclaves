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
 *     is an error is the backstop;
 *   - a 1xx reply other than 101 is an interim one (RFC 9110 §15.2): it is skipped, its headers
 *     with it, and the reply after it is the answer (enclave review 2026-10-09, E1 F-2);
 *   - a reply whose Content-Length or chunked body is complete is read then, not at the end of the
 *     connection, which a server may keep open (E1 F-3). Bytes after it in a later read are never
 *     read: data after a complete reply may be discarded, and is never a reply (RFC 9112 §6.3).
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

/** The collector's first buffer; it doubles as it fills, up to the limit. */
const FIRST_BUFFER_BYTES = 16 * 1024;

/**
 * How far ResponseCollector.complete() has read a reply's framing, so the next call goes on from there: each byte is
 * looked at a bounded number of times, whatever sizes the bytes come in. `from` is where a search for a line end goes
 * on.
 */
type FramingRead =
  /** A reply head starts at `start`; its end is not in yet */
  | { at: 'head'; start: number; from: number }
  /** The body ends at `end` (Content-Length) */
  | { at: 'length'; end: number }
  /** A chunk-size line starts at `start` */
  | { at: 'size-line'; start: number; from: number }
  /** A chunk's data ends at `dataEnd`, where its CRLF is due */
  | { at: 'chunk-end'; dataEnd: number }
  /** A trailer line, or the empty line that ends the chunked body, starts at `start` */
  | { at: 'trailer'; start: number; from: number }
  /** The body runs to the end of the connection: never complete before it */
  | { at: 'end-of-connection' }
  /** Complete, or broken beyond what any later byte could mend: finish() reads it now */
  | { at: 'done' };

/**
 * Collects the bytes of one reply and refuses to hold more than `limitBytes`.
 * `push` throws ResponseTooLargeError as soon as the limit is passed; the caller destroys the socket.
 */
export class ResponseCollector {
  /** The bytes so far: the first `received` bytes of `buffer` */
  private buffer = Buffer.alloc(FIRST_BUFFER_BYTES);
  private received = 0;
  private framing: FramingRead = { at: 'head', start: 0, from: 0 };

  constructor(private readonly hostname: string, private readonly limitBytes: number = MAX_RESPONSE_BYTES) {}

  push(chunk: Buffer): void {
    const total = this.received + chunk.length;
    if (total > this.limitBytes) {
      throw new ResponseTooLargeError(this.hostname, total, this.limitBytes);
    }
    if (total > this.buffer.length) {
      const grown = Buffer.alloc(Math.min(this.limitBytes, Math.max(total, this.buffer.length * 2)));
      this.buffer.copy(grown, 0, 0, this.received);
      this.buffer = grown;
    }
    chunk.copy(this.buffer, this.received);
    this.received = total;
  }

  /** The reply, read under the rules above. */
  finish(): HttpResponse {
    return parseHttpResponse(this.buffer.subarray(0, this.received));
  }

  /**
   * Whether the bytes so far are a whole reply by its own framing - its Content-Length body, or its chunked body to the
   * final CRLF - or are broken beyond what a later byte could mend: either way finish() reads it now, before the
   * connection ends (E1 F-3). Never for a body that runs to the end of the connection. The same reading as finish()'s
   * parse, step by step: it goes on from where the last call stopped.
   */
  complete(): boolean {
    const raw = this.buffer.subarray(0, this.received);
    for (;;) {
      const read = this.framing;
      switch (read.at) {
        case 'done':
          return true;
        case 'end-of-connection':
          return false;
        case 'length':
          return raw.length >= read.end;
        case 'head': {
          const headEnd = raw.indexOf(HEAD_END, read.from);
          if (headEnd === -1) {
            read.from = Math.max(read.start, raw.length - (HEAD_END.length - 1));
            return false;
          }
          this.framing = framingAfterHead(raw, read.start, headEnd);
          break;
        }
        case 'size-line': {
          const lineEnd = raw.indexOf(CRLF, read.from);
          if (lineEnd === -1) {
            read.from = Math.max(read.start, raw.length - (CRLF.length - 1));
            return false;
          }
          const size = chunkSizeOf(raw, read.start, lineEnd);
          const dataStart = lineEnd + CRLF.length;
          this.framing = size === null ? { at: 'done' }
            : size === 0 ? { at: 'trailer', start: dataStart, from: dataStart }
              : { at: 'chunk-end', dataEnd: dataStart + size };
          break;
        }
        case 'chunk-end': {
          if (raw.length < read.dataEnd + CRLF.length) return false;
          const next = read.dataEnd + CRLF.length;
          this.framing = isCrlfAt(raw, read.dataEnd) ? { at: 'size-line', start: next, from: next } : { at: 'done' };
          break;
        }
        case 'trailer': {
          const lineEnd = raw.indexOf(CRLF, read.from);
          if (lineEnd === -1) {
            read.from = Math.max(read.start, raw.length - (CRLF.length - 1));
            return false;
          }
          const next = lineEnd + CRLF.length;
          this.framing = lineEnd === read.start ? { at: 'done' } : { at: 'trailer', start: next, from: next };
          break;
        }
      }
    }
  }
}

/**
 * Where the framing read goes after the head from `start` to `headEnd`: the next head after an interim reply, else the
 * answer's body. A head that cannot be read is done: finish() throws its error.
 */
function framingAfterHead(raw: Buffer, start: number, headEnd: number): FramingRead {
  const bodyStart = headEnd + HEAD_END.length;
  let framing: BodyFraming;
  try {
    const head = readHead(raw, start, headEnd);
    if (isInterim(head.status)) return { at: 'head', start: bodyStart, from: bodyStart };
    framing = bodyFramingOf(head);
  } catch (err) {
    if (err instanceof MalformedResponseError) return { at: 'done' };
    throw err;
  }
  switch (framing.by) {
    case 'chunked':
      return { at: 'size-line', start: bodyStart, from: bodyStart };
    case 'length':
      return { at: 'length', end: bodyStart + framing.length };
    case 'end-of-connection':
      return { at: 'end-of-connection' };
  }
}

/**
 * Parse one complete HTTP/1.1 response. Works on bytes so chunk sizes index the data correctly when the
 * body holds multi-byte UTF-8; the header section is ASCII, the body is decoded after de-chunking.
 * Header names are lower-cased; a repeated header keeps its last value (Content-Length and
 * Transfer-Encoding are checked across every occurrence), except Set-Cookie: RFC 9110 §5.3 says it is never
 * combined, so every value is kept, one per line, in order (a header value never holds a line break). A site, or a
 * load balancer before it, may send several: SICAE's session cookie was dropped when another came after it
 * (enclave review 2026-10-09, E1 F-1).
 */
export function parseHttpResponse(raw: Buffer): HttpResponse {
  let start = 0;
  for (;;) {
    const headEnd = raw.indexOf(HEAD_END, start);
    if (headEnd === -1) {
      throw new MalformedResponseError('head', 'no header/body separator');
    }
    const head = readHead(raw, start, headEnd);
    // An interim reply has no body: the next head starts right after it
    if (isInterim(head.status)) {
      start = headEnd + HEAD_END.length;
      continue;
    }
    const bodyBytes = raw.subarray(headEnd + HEAD_END.length);
    return { status: head.status, headers: head.headers, body: utf8Of(frameBody(bodyBytes, bodyFramingOf(head))) };
  }
}

/** 1xx but 101: an interim reply, read and skipped (RFC 9110 §15.2). A 101 ends HTTP on the connection: it is final. */
function isInterim(status: number): boolean {
  return status >= 100 && status < 200 && status !== 101;
}

/** A reply head: its status, its headers, and the values that frame its body. */
interface Head {
  status: number;
  headers: Record<string, string>;
  contentLengths: string[];
  transferCodings: string[];
}

/** The head from `start` to `headEnd` (its CRLFCRLF). A status line that is not one is MalformedResponseError. */
function readHead(raw: Buffer, start: number, headEnd: number): Head {
  // Byte for byte (latin1): read as 7-bit ASCII, the bytes 0x8D 0x8A became CR LF and split a header line in two
  // (enclave review 2026-10-09, E1 F-13).
  const lines = raw.subarray(start, headEnd).toString('latin1').split('\r\n');
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
    headers[key] = key === 'set-cookie' && headers[key] !== undefined ? `${headers[key]}\n${value}` : value;
    if (key === 'content-length') contentLengths.push(value);
    if (key === 'transfer-encoding') {
      transferCodings.push(...value.split(',').map((c) => c.trim().toLowerCase()).filter((c) => c !== ''));
    }
  }
  return { status, headers, contentLengths, transferCodings };
}

/** Bodies are UTF-8, decoded strictly and with a byte-order mark kept: the text is exactly the bytes sent. */
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * A body's text, or MalformedResponseError when its bytes are not UTF-8. Read loosely, each invalid byte became U+FFFD,
 * and a handler hashed and signed that text as the upstream body (dataHash): a commitment to bytes nobody sent
 * (enclave review 2026-10-09, E1 F-13). Every register the enclaves read answers in UTF-8.
 */
function utf8Of(body: Buffer): string {
  try {
    return UTF8.decode(body);
  } catch {
    throw new MalformedResponseError('body', 'not UTF-8');
  }
}

/** How the body after a final head is framed. */
type BodyFraming = { by: 'chunked' } | { by: 'length'; length: number } | { by: 'end-of-connection' };

/** The framing a final head gives its body, under the rules at the top; MalformedResponseError when it cannot be read. */
function bodyFramingOf({ contentLengths, transferCodings }: Head): BodyFraming {
  if (transferCodings.length > 0) {
    if (contentLengths.length > 0) {
      throw new MalformedResponseError('framing', 'both Transfer-Encoding and Content-Length');
    }
    if (transferCodings.length !== 1 || transferCodings[0] !== 'chunked') {
      throw new MalformedResponseError('transfer-encoding', `unsupported transfer coding "${transferCodings.join(', ')}"`);
    }
    return { by: 'chunked' };
  }

  if (contentLengths.length > 0) {
    if (new Set(contentLengths).size > 1) {
      throw new MalformedResponseError('content-length', `conflicting values ${contentLengths.join(' / ')}`);
    }
    const declared = contentLengths[0];
    if (!CONTENT_LENGTH_PATTERN.test(declared)) {
      throw new MalformedResponseError('content-length', `not a decimal length: "${declared.slice(0, 32)}"`);
    }
    return { by: 'length', length: Number(declared) };
  }

  return { by: 'end-of-connection' };
}

function frameBody(body: Buffer, framing: BodyFraming): Buffer {
  switch (framing.by) {
    case 'chunked':
      return decodeChunked(body);
    case 'length':
      if (body.length < framing.length) {
        throw new IncompleteBodyError(`Content-Length ${framing.length}, received ${body.length}`);
      }
      if (body.length > framing.length) {
        throw new MalformedResponseError('content-length', `Content-Length ${framing.length}, received ${body.length}`);
      }
      return body;
    case 'end-of-connection':
      return body;
  }
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
    const size = chunkSizeOf(raw, offset, sizeLineEnd);
    if (size === null) {
      const sizeToken = chunkSizeToken(raw, offset, sizeLineEnd);
      throw new MalformedResponseError('chunk-size', `"${sizeToken.slice(0, 32)}" is not a hexadecimal chunk size`);
    }
    const dataStart = sizeLineEnd + CRLF.length;

    if (size === 0) {
      return endOfChunkedBody(raw, dataStart, parts);
    }

    const dataEnd = dataStart + size;
    if (dataEnd + CRLF.length > raw.length) {
      throw new IncompleteBodyError(`a chunk of ${size} bytes is cut short`);
    }
    if (!isCrlfAt(raw, dataEnd)) {
      throw new MalformedResponseError('chunk', `the ${size}-byte chunk is not followed by CRLF`);
    }
    parts.push(raw.subarray(dataStart, dataEnd));
    offset = dataEnd + CRLF.length;
  }
}

/** The size field of the chunk-size line from `start` to its CRLF at `lineEnd` (extensions after `;` cut off). */
function chunkSizeToken(raw: Buffer, start: number, lineEnd: number): string {
  return raw.subarray(start, lineEnd).toString('ascii').split(';', 1)[0].trim();
}

/** The size the chunk-size line from `start` to `lineEnd` gives, or null when it is not hexadecimal. */
function chunkSizeOf(raw: Buffer, start: number, lineEnd: number): number | null {
  const token = chunkSizeToken(raw, start, lineEnd);
  return CHUNK_SIZE_PATTERN.test(token) ? parseInt(token, 16) : null;
}

function isCrlfAt(raw: Buffer, at: number): boolean {
  return raw[at] === CRLF[0] && raw[at + 1] === CRLF[1];
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
