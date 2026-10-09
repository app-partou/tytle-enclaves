/**
 * Generic request handler — validates URL against allowlist, proxies, attests.
 *
 * The allowlist is the key isolation mechanism. PCR0 proves this exact code
 * (including the allowlist) ran inside the enclave. A verifier can clone the
 * repo, see the allowlist, and confirm which hosts the enclave was allowed
 * to call.
 */

import { proxyFetch, proxyFetchPlain } from './httpProxy.js';
import { assertChallenge, attest } from './attestor.js';
import { DEFAULT_FETCH_TIMEOUT_MS, RequestDeadlineError, requestBudget, timeFor, type RequestBudget } from './requestBudget.js';
import type { EnclaveConfig, EnclaveRequest, EnclaveResponse } from './types.js';

/**
 * Create a request handler bound to a specific enclave config.
 * The returned function validates URLs against the config's allowlist. The upstream read takes what is left of the
 * request's `budget` (requestBudget.ts); spent before the read or before the attestation, the answer is 504 and no
 * document is minted.
 */
export function createRequestHandler(
  config: EnclaveConfig,
): (request: EnclaveRequest, budget?: RequestBudget) => Promise<EnclaveResponse> {
  return async (request: EnclaveRequest, budget: RequestBudget = requestBudget(Date.now())): Promise<EnclaveResponse> => {
    try {
      assertChallenge(request.challenge);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, status: 400, headers: {}, rawBody: '', error: `Invalid request: ${msg}` };
    }
    try {
      const parsedUrl = new URL(request.url);
      const hostname = parsedUrl.hostname;

      const allowed = config.hosts.find((h) => h.hostname === hostname);
      if (!allowed) {
        return {
          success: false,
          status: 403,
          headers: {},
          rawBody: '',
          error: `Host not allowed: ${hostname}. This enclave only permits: ${config.hosts.map((h) => h.hostname).join(', ')}`,
        };
      }

      const path = parsedUrl.pathname + parsedUrl.search;
      const apiEndpoint = `${hostname}${parsedUrl.pathname}`;

      const fetch = allowed.tls !== false ? proxyFetch : proxyFetchPlain;
      const response = await fetch(
        allowed.vsockProxyPort,
        hostname,
        request.method,
        path,
        request.headers,
        request.body,
        timeFor(budget, `the read of ${hostname}`, DEFAULT_FETCH_TIMEOUT_MS),
      );

      timeFor(budget, 'the attestation');
      const attestation = await attest(
        apiEndpoint,
        request.method,
        response.body,
        request.url,
        request.headers,
        { challenge: request.challenge },
      );

      return {
        success: true,
        status: response.status,
        headers: response.headers,
        rawBody: response.body,
        attestation,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[enclave:${config.name}] Request error: ${msg}`);
      return {
        success: false,
        status: err instanceof RequestDeadlineError ? 504 : 502,
        headers: {},
        rawBody: '',
        error: msg,
      };
    }
  };
}
