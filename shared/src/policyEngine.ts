/**
 * Policy Engine - evaluates manifest PolicyDef[] at runtime.
 *
 * Pure functions with no side effects. The handler factory calls these
 * automatically based on each handler's manifest policies.
 */

import type { PolicyDef } from './manifest.js';

/**
 * Evaluate whether a response status should skip attestation.
 * Matches status_skip policies: transient errors that are not definitive.
 */
export function shouldSkipAttestation(policies: PolicyDef[], status: number): boolean {
  for (const p of policies) {
    const check = p.check;
    if (check.type === 'status_skip') {
      if (check.codes.includes(status) && !(check.except ?? []).includes(status)) {
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
