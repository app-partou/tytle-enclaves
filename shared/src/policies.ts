/**
 * Standard Reusable Policies
 *
 * Pre-built policy blocks that any enclave handler can compose into its
 * manifest. Services pick the standard blocks they need and add custom
 * policies for domain-specific validation.
 *
 * Usage:
 *   import { SKIP_TRANSIENT_ERRORS, STRIP_AUTH, REDACT_BEARER } from '@tytle-enclaves/shared';
 *
 *   const manifest = {
 *     policies: [
 *       SKIP_TRANSIENT_ERRORS,
 *       STRIP_AUTH,
 *       REDACT_BEARER,
 *       // ...custom service-specific policies
 *     ],
 *   };
 */

import type { PolicyDef } from './manifest.js';

/**
 * Pass every upstream error on unsigned, as it was sent: every status of 400 or more but 404. An error is never a
 * signed answer: a rate limit, an auth failure or a server error says nothing definitive, and the same question may
 * succeed later. A 404 is each handler's own rule (Stripe signs only its own "no such object"; Monerium passes every
 * 404 on too). Before, the list named seven codes while the handlers passed on every error, 402, 409 and 504
 * included (enclave review 2026-10-09, E2a F-17).
 */
export const SKIP_TRANSIENT_ERRORS: PolicyDef = {
  id: 'skip_transient_errors',
  check: { type: 'status_skip', codes: [], atLeast: 400, except: [404] },
  reason: 'An upstream error (400 or more, but 404) is passed on unsigned, as it was sent: never a signed answer',
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
