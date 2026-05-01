/**
 * Handler Factory - eliminates boilerplate across enclave handlers.
 *
 * Each handler exports a HandlerDef with parseParams + execute. The factory
 * wraps them with: JSON parsing, error handling, policy enforcement, BN254
 * encoding, attestation, and response construction.
 */

import { encodeBn254AndAttest } from './enclaveHelpers.js';
import { errorResponse } from './enclaveHelpers.js';
import { toErrorMessage } from './errorUtils.js';
import { proxyFetch, proxyFetchPlain, type HttpResponse } from './httpProxy.js';
import { proxyFetchWithRetry, type RetryConfig } from './retryProxy.js';
import { getHeadersToStrip, redactError } from './policyEngine.js';
import { stripSensitiveHeaders } from './sanitize.js';
import type { FieldDef } from './bn254Codec.js';
import type { PolicyDef } from './manifest.js';
import type { EnclaveRequest, EnclaveResponse, AllowedHost } from './types.js';
import { createLogger, type Logger } from './logger.js';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

export interface HandlerResult {
  values: Record<string, string | number | bigint | null>;
  apiEndpoint: string;
  method: string;
  url: string;
  requestHeaders: Record<string, string>;
  responseHeaders: Record<string, string>;
  bn254Headers?: Record<string, string>;
  status?: number;
  skipAttestation?: boolean;
  rawPassthrough?: { status: number; headers: Record<string, string>; rawBody: string };
}

export interface HandlerContext {
  hosts: AllowedHost[];
  log: Logger;
  fetch(host: AllowedHost, method: string, path: string, headers: Record<string, string>, body?: string, timeoutMs?: number): Promise<HttpResponse>;
  fetchWithRetry(host: AllowedHost, method: string, path: string, headers: Record<string, string>, body?: string, timeoutMs?: number, retryConfig?: RetryConfig): Promise<HttpResponse>;
}

export interface HandlerDef<TParams> {
  name: string;
  schema: FieldDef[];
  manifestHash: string;
  policies: PolicyDef[];
  requiredHosts: string[];
  parseParams: (body: unknown) => TParams;
  execute: (params: TParams, ctx: HandlerContext) => Promise<HandlerResult>;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a request handler from a HandlerDef.
 *
 * Validates required hosts at construction time (fail-fast on misconfiguration).
 * At request time, handles all boilerplate: JSON parsing, policy enforcement,
 * BN254 encoding + attestation, and response construction.
 */
export function createHandler<TParams>(
  def: HandlerDef<TParams>,
  hosts: AllowedHost[],
): (request: EnclaveRequest) => Promise<EnclaveResponse> {
  for (const required of def.requiredHosts) {
    if (!hosts.find((h) => h.hostname === required)) {
      throw new Error(`Handler "${def.name}" requires host "${required}" but it is not in the allowlist`);
    }
  }

  const headersToStrip = getHeadersToStrip(def.policies);
  const log = createLogger(def.name);

  const ctx: HandlerContext = {
    hosts,
    log,
    fetch(host, method, path, headers, body, timeoutMs) {
      const fetchFn = host.tls !== false ? proxyFetch : proxyFetchPlain;
      return fetchFn(host.vsockProxyPort, host.hostname, method, path, headers, body, timeoutMs);
    },
    fetchWithRetry(host, method, path, headers, body, timeoutMs, retryConfig) {
      return proxyFetchWithRetry(
        host.vsockProxyPort, host.hostname, method, path, headers, body,
        timeoutMs, host.tls !== false, retryConfig,
      );
    },
  };

  return async (request: EnclaveRequest): Promise<EnclaveResponse> => {
    try {
      let params: TParams;
      try {
        const body = JSON.parse(request.body || '{}');
        params = def.parseParams(body);
      } catch (err: unknown) {
        return errorResponse(400, `Invalid request: ${toErrorMessage(err)}`);
      }

      const startMs = Date.now();
      const result = await def.execute(params, ctx);
      const executeMs = Date.now() - startMs;

      if (result.rawPassthrough) {
        log.info('Passthrough response', { status: result.rawPassthrough.status, execute_ms: executeMs });

        return {
          success: true,
          status: result.rawPassthrough.status,
          headers: result.rawPassthrough.headers,
          rawBody: result.rawPassthrough.rawBody,
        };
      }

      if (result.skipAttestation) {
        log.info('Skip attestation', { status: result.status ?? 200, execute_ms: executeMs });
        return {
          success: true,
          status: result.status ?? 200,
          headers: result.responseHeaders,
          rawBody: '',
        };
      }

      const attestHeaders = headersToStrip.length > 0
        ? stripSensitiveHeaders(result.requestHeaders, headersToStrip)
        : result.requestHeaders;

      const attestStartMs = Date.now();
      const attestResult = await encodeBn254AndAttest(
        def.schema,
        result.values,
        {
          apiEndpoint: result.apiEndpoint,
          method: result.method,
          url: result.url,
          requestHeaders: { ...attestHeaders, 'x-manifest-hash': def.manifestHash },
        },
      );

      const attestMs = Date.now() - attestStartMs;
      const totalMs = Date.now() - startMs;
      log.info('Request complete', {
        status: result.status ?? 200,
        execute_ms: executeMs,
        attest_ms: attestMs,
        total_ms: totalMs,
        endpoint: result.apiEndpoint,
      });

      return {
        success: true,
        status: result.status ?? 200,
        headers: {
          ...result.responseHeaders,
          [`x-${def.name}-manifest-hash`]: def.manifestHash,
        },
        rawBody: attestResult.rawBody,
        attestation: attestResult.attestation,
        bn254: attestResult.rawBody,
        bn254Headers: result.bn254Headers,
      };
    } catch (err: unknown) {
      const safeMessage = redactError(def.policies, toErrorMessage(err));
      log.error('Handler error', { error: safeMessage });
      return errorResponse(502, safeMessage);
    }
  };
}
