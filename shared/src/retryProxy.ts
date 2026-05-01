/**
 * Retry wrapper for enclave proxy calls.
 *
 * Lightweight retry inside the enclave avoids the full vsock roundtrip
 * when external APIs return transient errors. Only retries on 5xx status
 * codes or network errors - never on 4xx (client errors).
 */

import { proxyFetch, proxyFetchPlain, type HttpResponse } from './httpProxy.js';
import { toErrorMessage } from './errorUtils.js';

export interface RetryConfig {
  maxRetries?: number;
  baseDelayMs?: number;
  retryOnStatus?: (status: number) => boolean;
}

const DEFAULT_CONFIG: Required<RetryConfig> = {
  maxRetries: 1,
  baseDelayMs: 500,
  retryOnStatus: (s) => s >= 500,
};

/**
 * Wrap proxyFetch or proxyFetchPlain with retry on transient failures.
 * Adds random jitter to backoff to prevent thundering herd across
 * concurrent handlers.
 */
export async function proxyFetchWithRetry(
  vsockPort: number,
  hostname: string,
  method: string,
  path: string,
  headers: Record<string, string>,
  body?: string,
  timeoutMs?: number,
  tls: boolean = true,
  retryConfig?: RetryConfig,
): Promise<HttpResponse> {
  const cfg = { ...DEFAULT_CONFIG, ...retryConfig };
  const fetchFn = tls ? proxyFetch : proxyFetchPlain;

  let lastError: Error | undefined;
  let lastResponse: HttpResponse | undefined;

  for (let attempt = 0; attempt <= cfg.maxRetries; attempt++) {
    try {
      const response = await fetchFn(vsockPort, hostname, method, path, headers, body, timeoutMs);
      if (!cfg.retryOnStatus(response.status) || attempt === cfg.maxRetries) {
        return response;
      }
      lastResponse = response;
    } catch (err: unknown) {
      if (attempt === cfg.maxRetries) {
        if (lastResponse) return lastResponse;
        throw err;
      }
      lastError = err instanceof Error ? err : new Error(toErrorMessage(err));
    }

    const jitter = Math.random() * 0.3 + 0.85;
    const delay = cfg.baseDelayMs * Math.pow(2, attempt) * jitter;
    await new Promise((r) => setTimeout(r, delay));
  }

  if (lastResponse) return lastResponse;
  throw lastError ?? new Error('Retry exhausted');
}
