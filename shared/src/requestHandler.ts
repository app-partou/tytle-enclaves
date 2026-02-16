/**
 * Generic request handler — validates URL against allowlist, proxies, attests.
 *
 * The allowlist is the key isolation mechanism. PCR0 proves this exact code
 * (including the allowlist) ran inside the enclave. A verifier can clone the
 * repo, see the allowlist, and confirm which hosts the enclave was allowed
 * to call.
 */

import { proxyFetch } from './httpProxy.js';
import { attest } from './attestor.js';
import type { EnclaveConfig, EnclaveRequest, EnclaveResponse } from './types.js';

/**
 * Create a request handler bound to a specific enclave config.
 * The returned function validates URLs against the config's allowlist.
 */
export function createRequestHandler(
  config: EnclaveConfig,
): (request: EnclaveRequest) => Promise<EnclaveResponse> {
  return async (request: EnclaveRequest): Promise<EnclaveResponse> => {
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

      const response = await proxyFetch(
        allowed.vsockProxyPort,
        hostname,
        request.method,
        path,
        request.headers,
        request.body,
      );

      const attestation = await attest(
        apiEndpoint,
        request.method,
        response.body,
        request.url,
        request.headers,
      );

      return {
        success: true,
        status: response.status,
        headers: response.headers,
        rawBody: response.body,
        attestation,
      };
    } catch (err: any) {
      console.error(`[enclave:${config.name}] Request error: ${err.message}`);
      return {
        success: false,
        status: 502,
        headers: {},
        rawBody: '',
        error: err.message,
      };
    }
  };
}
