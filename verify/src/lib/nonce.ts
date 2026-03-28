/**
 * Nonce computation and verification.
 * Mirrors shared/src/attestor.ts:67-72.
 */

import crypto from 'node:crypto';
import type { AttestationDocument } from './types.js';

/**
 * Compute the expected nonce for an attestation.
 * nonce = SHA-256(responseHash|apiEndpoint|timestamp)
 * Pipe delimiter prevents domain collisions from field concatenation.
 */
export function computeNonce(
  responseHash: string,
  apiEndpoint: string,
  timestamp: number,
): string {
  return crypto
    .createHash('sha256')
    .update(`${responseHash}|${apiEndpoint}|${timestamp}`)
    .digest('hex');
}

/**
 * Verify that the nonce in an attestation matches the expected value.
 * Uses constant-time comparison to prevent timing side-channels.
 */
export function verifyNonce(attestation: AttestationDocument): {
  valid: boolean;
  expected: string;
  actual: string;
} {
  const expected = computeNonce(
    attestation.responseHash,
    attestation.apiEndpoint,
    attestation.timestamp,
  );

  let valid = false;
  try {
    valid = crypto.timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(attestation.nonce, 'hex'),
    );
  } catch {
    // timingSafeEqual throws if lengths differ — that's a mismatch
    valid = false;
  }

  return { valid, expected, actual: attestation.nonce };
}
