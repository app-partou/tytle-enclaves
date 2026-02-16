/**
 * Request Handler — the core of what PCR0 attests.
 *
 * This module defines the URL allowlist and orchestrates:
 * 1. URL validation against allowlist
 * 2. HTTP proxy (TLS-over-vsock)
 * 3. Response hashing
 * 4. NSM attestation
 *
 * The allowlist is the key isolation mechanism. This enclave ONLY allows
 * requests to ec.europa.eu (VIES SOAP) and api.service.hmrc.gov.uk (HMRC REST).
 * Since PCR0 proves this exact code ran, a verifier knows that Stripe calls
 * cannot go through this enclave.
 */

import { proxyFetch } from './httpProxy.js';
import { attest } from './attestor.js';
import type { EnclaveRequest, EnclaveResponse, AllowedHost } from './types.js';

/** Allowlisted hosts and their vsock-proxy ports. */
const ALLOWED_HOSTS: AllowedHost[] = [
  { hostname: 'ec.europa.eu', vsockProxyPort: 8443 },
  { hostname: 'api.service.hmrc.gov.uk', vsockProxyPort: 8444 },
];

/**
 * Handle an incoming request from the parent server.
 *
 * 1. Validate URL against allowlist
 * 2. Proxy the HTTP request through TLS-over-vsock
 * 3. Hash the response
 * 4. Create NSM attestation
 * 5. Return response + attestation
 */
export async function handleRequest(request: EnclaveRequest): Promise<EnclaveResponse> {
  try {
    // Parse and validate URL
    const parsedUrl = new URL(request.url);
    const hostname = parsedUrl.hostname;

    // Check allowlist
    const allowed = ALLOWED_HOSTS.find((h) => h.hostname === hostname);
    if (!allowed) {
      return {
        success: false,
        status: 403,
        headers: {},
        rawBody: '',
        error: `Host not allowed: ${hostname}. This enclave only permits: ${ALLOWED_HOSTS.map((h) => h.hostname).join(', ')}`,
      };
    }

    // Build request path (include query string)
    const path = parsedUrl.pathname + parsedUrl.search;
    const apiEndpoint = `${hostname}${parsedUrl.pathname}`;

    // Proxy the request through TLS-over-vsock
    const response = await proxyFetch(
      allowed.vsockProxyPort,
      hostname,
      request.method,
      path,
      request.headers,
      request.body,
    );

    // Create attestation
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
    console.error(`[requestHandler] Error processing request ${request.id}: ${err.message}`);
    return {
      success: false,
      status: 502,
      headers: {},
      rawBody: '',
      error: err.message,
    };
  }
}
