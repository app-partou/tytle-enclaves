/**
 * Typed errors of the enclave's HTTP leg.
 *
 * Each carries a literal `code`, so callers decide by class, never by message text: the retry
 * wrapper (retryProxy.ts) never retries a response that was too large, and retries the rest once.
 * Every one of them ends a handler as an error (HTTP 502 to the parent, no attestation): a reply the
 * enclave could not read completely is never parsed, and so never signed.
 */

/** The upstream sent more than the enclave reads (MAX_RESPONSE_BYTES in httpParse.ts). */
export class ResponseTooLargeError extends Error {
  readonly code = 'RESPONSE_TOO_LARGE' as const;
  constructor(readonly hostname: string, readonly receivedBytes: number, readonly limitBytes: number) {
    super(`Response from ${hostname} exceeds ${limitBytes} bytes (received ${receivedBytes})`);
    this.name = 'ResponseTooLargeError';
  }
}

/** The connection ended before the body its own framing announced (Content-Length, chunks). */
export class IncompleteBodyError extends Error {
  readonly code = 'INCOMPLETE_BODY' as const;
  constructor(readonly detail: string) {
    super(`Incomplete HTTP response body: ${detail}`);
    this.name = 'IncompleteBodyError';
  }
}

/** The response breaks HTTP/1.1 framing in a way that cannot be read safely. */
export class MalformedResponseError extends Error {
  readonly code = 'MALFORMED_RESPONSE' as const;
  constructor(readonly part: string, readonly detail: string) {
    super(`Malformed HTTP response (${part}): ${detail}`);
    this.name = 'MalformedResponseError';
  }
}
