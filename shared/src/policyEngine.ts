/**
 * Policy Engine - evaluates manifest PolicyDef[].
 *
 * Pure functions with no side effects. The handler factory applies getHeadersToStrip and redactError to every request.
 * shouldSkipAttestation and getAttestOverrides read what a manifest says of an upstream status; each package's tests
 * run them against the handler, so a manifest that says other than the code fails there (enclave review 2026-10-09,
 * E2a F-17).
 */

import type { PolicyDef } from './manifest.js';

/**
 * Whether a manifest says an upstream answer with this status is passed on unsigned: a status_skip policy names it, by
 * its code or by `atLeast`, and does not except it.
 */
export function shouldSkipAttestation(policies: PolicyDef[], status: number): boolean {
  for (const p of policies) {
    const check = p.check;
    if (check.type === 'status_skip') {
      const named = check.codes.includes(status) || (check.atLeast !== undefined && status >= check.atLeast);
      if (named && !(check.except ?? []).includes(status)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Get field overrides for a status-attested response (e.g., 404 -> not_found).
 * Returns the overrides record, or null if no status_attest policy matches.
 */
export function getAttestOverrides(
  policies: PolicyDef[],
  status: number,
): Record<string, string | number> | null {
  for (const p of policies) {
    const check = p.check;
    if (check.type === 'status_attest' && check.code === status) {
      return check.overrides ?? {};
    }
  }
  return null;
}

/**
 * Collect all header names that should be stripped before attestation hash.
 */
export function getHeadersToStrip(policies: PolicyDef[]): string[] {
  const headers: string[] = [];
  for (const p of policies) {
    const check = p.check;
    if (check.type === 'header_strip') {
      headers.push(...check.headers);
    }
  }
  return headers;
}

/**
 * Apply error redaction patterns from policies.
 * Prevents credential leakage in logs and error responses.
 */
export function redactError(policies: PolicyDef[], message: string): string {
  let result = message;
  for (const p of policies) {
    const check = p.check;
    if (check.type === 'error_redact') {
      result = result.replace(new RegExp(check.pattern, 'gi'), check.replacement);
    }
  }
  return result;
}
