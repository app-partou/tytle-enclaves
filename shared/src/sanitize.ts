/**
 * Credential sanitization and header stripping for enclave handlers.
 *
 * Prevents secret tokens from leaking into logs, error responses,
 * or attestation hashes.
 */

import { toErrorMessage } from './errorUtils.js';

/**
 * Extract an error message and redact any embedded credentials.
 * Handles Bearer tokens and Stripe-style API keys (sk_*, rk_*).
 */
export function sanitizeError(err: unknown): string {
  const msg = toErrorMessage(err);
  return msg
    .replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]')
    .replace(/\b(sk_|rk_)(live|test)_[A-Za-z0-9]{10,}/g, '$1$2_[REDACTED]');
}

/**
 * Strip sensitive headers before attestation hash computation.
 * Case-insensitive: 'Authorization' matches 'authorization', 'AUTHORIZATION', etc.
 * External verifiers must reproduce hashes without secret tokens.
 */
export function stripSensitiveHeaders(
  headers: Record<string, string>,
  strip: string[] = ['Authorization'],
): Record<string, string> {
  const lowerStrip = new Set(strip.map((k) => k.toLowerCase()));
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!lowerStrip.has(key.toLowerCase())) {
      result[key] = value;
    }
  }
  return result;
}
