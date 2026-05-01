/**
 * Standard Reusable Policies
 *
 * Pre-built policy blocks that any enclave handler can compose into its
 * manifest. Services pick the standard blocks they need and add custom
 * policies for domain-specific validation.
 *
 * Usage:
 *   import { SKIP_TRANSIENT_ERRORS, ATTEST_NOT_FOUND, STRIP_AUTH, REDACT_BEARER } from '@tytle-enclaves/shared';
 *
 *   const manifest = {
 *     policies: [
 *       SKIP_TRANSIENT_ERRORS,
 *       ATTEST_NOT_FOUND,
 *       STRIP_AUTH,
 *       REDACT_BEARER,
 *       // ...custom service-specific policies
 *     ],
 *   };
 */

import type { PolicyDef } from './manifest.js';

/**
 * Skip attestation for transient HTTP errors.
 * Rate limits, auth failures, and server errors are not definitive answers —
 * they should not be attested because the same query may succeed later.
 */
export const SKIP_TRANSIENT_ERRORS: PolicyDef = {
  id: 'skip_transient_errors',
  check: { type: 'status_skip', codes: [400, 401, 403, 429, 500, 502, 503] },
  reason: 'Transient HTTP errors are not attested (404 handled by ATTEST_NOT_FOUND)',
};

/**
 * Attest 404 responses as definitive "not found".
 * A resource that doesn't exist is a valid, attestable answer —
 * proving non-existence is as valuable as proving existence.
 */
export const ATTEST_NOT_FOUND: PolicyDef = {
  id: 'attest_not_found',
  check: { type: 'status_attest', code: 404, overrides: { state: 'not_found' } },
  reason: 'Non-existence is a definitive, attestable answer',
};

/**
 * Strip the Authorization header before computing the attestation hash.
 * External verifiers must be able to reproduce the requestHash without
 * knowing the secret API token used at request time.
 */
export const STRIP_AUTH: PolicyDef = {
  id: 'strip_auth',
  check: { type: 'header_strip', headers: ['Authorization'] },
  reason: 'Verifiers must reproduce attestation hashes without secret tokens',
};

/**
 * Redact Bearer tokens from error messages.
 * If a network error includes the Authorization header value in its message,
 * replace it to prevent credential leakage in logs.
 */
export const REDACT_BEARER: PolicyDef = {
  id: 'redact_bearer',
  check: { type: 'error_redact', pattern: 'Bearer\\s+\\S+', replacement: 'Bearer [REDACTED]' },
  reason: 'Prevent credential leakage in logs and error responses',
};
