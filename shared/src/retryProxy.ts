/**
 * Retry wrapper for enclave proxy calls.
 *
 * Lightweight retry inside the enclave avoids the full vsock roundtrip
 * when external APIs return transient errors. Only retries on 5xx status
 * codes or network errors - never on 4xx (client errors), and never on a
 * reply that was too large (the same request would pull the same bytes).
 * Thrown errors are judged by class (httpErrors.ts), never by message text.
 */

import { proxyFetch, proxyFetchPlain, type HttpResponse } from './httpProxy.js';
import { ResponseTooLargeError } from './httpErrors.js';
import { toErrorMessage } from './errorUtils.js';
import { DEFAULT_FETCH_TIMEOUT_MS, timeFor, type RequestBudget } from './requestBudget.js';

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
 *
 * With the request's `budget` (requestBudget.ts), every try takes what is left of it, and no pause or try starts that
 * it cannot hold: the last answer, or the last error, stands. A first try with nothing left is RequestDeadlineError.
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
  budget?: RequestBudget,
): Promise<HttpResponse> {
  const cfg = { ...DEFAULT_CONFIG, ...retryConfig };
  const fetchFn = tls ? proxyFetch : proxyFetchPlain;

  let lastError: Error | undefined;
  let lastResponse: HttpResponse | undefined;

  for (let attempt = 0; attempt <= cfg.maxRetries; attempt++) {
    if (budget && attempt > 0 && budget.deadlineMs <= Date.now()) break;
    const tryTimeoutMs = budget ? timeFor(budget, `the read of ${hostname}`, timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS) : timeoutMs;
    try {
      const response = await fetchFn(vsockPort, hostname, method, path, headers, body, tryTimeoutMs);
      if (!cfg.retryOnStatus(response.status) || attempt === cfg.maxRetries) {
        return response;
      }
      lastResponse = response;
    } catch (err: unknown) {
      if (err instanceof ResponseTooLargeError) throw err;
      if (attempt === cfg.maxRetries) {
        if (lastResponse) return lastResponse;
        throw err;
      }
      lastError = err instanceof Error ? err : new Error(toErrorMessage(err));
    }

    const jitter = Math.random() * 0.3 + 0.85;
    const delay = cfg.baseDelayMs * Math.pow(2, attempt) * jitter;
    if (budget && Date.now() + delay >= budget.deadlineMs) break;
    await new Promise((r) => setTimeout(r, delay));
  }

  if (lastResponse) return lastResponse;
  throw lastError ?? new Error('Retry exhausted');
}
