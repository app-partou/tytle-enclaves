/**
 * What POST /attest/fetch accepts (enclave audit r4_fragilities #8, P2.5).
 *
 * The parent is outside the enclaves' trust boundary: each enclave checks what it is asked on its own. This check is
 * the parent's: a caller's values reach its logs and its router only in the shape data-bridge sends them
 * (data-bridge/src/attestation/attestedFetchService.ts, executeViaEnclave). Before it, the fields were untyped and
 * `id`, `method` and `url` went into console.log raw - an id with a newline wrote a forged journald line - and a
 * 10 MB body was read in full.
 *
 * Unknown fields are dropped, never forwarded, and never a refusal: a newer caller can add one before the parent
 * knows it.
 */

import type { EnclaveRequest } from './types.js';

/** The largest JSON body the parent reads: the largest real one is a Stripe or Monerium parameter object. */
export const MAX_REQUEST_BODY = '64kb';

/** The methods data-bridge sends. Each enclave picks its own upstream method. */
export const METHODS: readonly string[] = ['GET', 'POST'];
const METHOD_SET: ReadonlySet<string> = new Set(METHODS);

/** SICAE is fetched over plain HTTP (its vector's transport tag says so); every other upstream over HTTPS. */
const URL_PROTOCOLS: ReadonlySet<string> = new Set(['https:', 'http:']);

/** data-bridge's request id: crypto.randomUUID(). */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A space or a control character: never in a URL as sent (they are percent-encoded), and a newline forges a log line. */
const URL_FORBIDDEN_RE = /[\u0000- \u007f]/;

/** RFC 9110 5.1: a field name is a token. */
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/** RFC 9110 5.5: a field value never holds CR, LF or NUL. */
const HEADER_VALUE_FORBIDDEN_RE = /[\r\n\u0000]/;

/** The request to forward, or why it is refused (the parent answers 400 with it). */
export type ParsedFetchRequest =
  | { ok: true; request: Omit<EnclaveRequest, 'id'> & { id?: string } }
  | { ok: false; error: string };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isFetchUrl(url: string): boolean {
  if (URL_FORBIDDEN_RE.test(url)) return false;
  try {
    return URL_PROTOCOLS.has(new URL(url).protocol);
  } catch {
    return false;
  }
}

function headersOf(headers: unknown): Record<string, string> | string {
  if (headers === undefined) return {};
  if (!isPlainObject(headers)) return 'headers must be an object of strings';
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!HEADER_NAME_RE.test(name)) return 'a header name is not an HTTP token';
    if (typeof value !== 'string') return 'every header value must be a string';
    if (HEADER_VALUE_FORBIDDEN_RE.test(value)) return 'a header value holds CR, LF or NUL';
    out[name] = value;
  }
  return out;
}

/** Check the JSON body of POST /attest/fetch. */
export function parseFetchRequest(body: unknown): ParsedFetchRequest {
  if (!isPlainObject(body)) return { ok: false, error: 'the request must be a JSON object' };
  const { id, url, method, headers, body: payload, challenge } = body;

  if (id !== undefined && (typeof id !== 'string' || !UUID_RE.test(id))) {
    return { ok: false, error: 'id must be a UUID' };
  }
  if (typeof url !== 'string' || !isFetchUrl(url)) {
    return { ok: false, error: 'url must be an http or https URL without spaces or control characters' };
  }
  if (typeof method !== 'string' || !METHOD_SET.has(method)) {
    return { ok: false, error: `method must be one of ${METHODS.join(', ')}` };
  }
  const forwardedHeaders = headersOf(headers);
  if (typeof forwardedHeaders === 'string') return { ok: false, error: forwardedHeaders };
  if (payload !== undefined && typeof payload !== 'string') {
    return { ok: false, error: 'body must be a string' };
  }
  // The caller's challenge (P1.3) goes to the enclave untouched; the enclave checks its format.
  if (challenge !== undefined && typeof challenge !== 'string') {
    return { ok: false, error: 'challenge must be a string' };
  }

  return {
    ok: true,
    request: {
      ...(id === undefined ? {} : { id }),
      url,
      method,
      headers: forwardedHeaders,
      ...(payload === undefined ? {} : { body: payload }),
      ...(challenge === undefined ? {} : { challenge }),
    },
  };
}
