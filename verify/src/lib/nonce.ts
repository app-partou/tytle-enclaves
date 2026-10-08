/**
 * Nonce computation and verification.
 * Mirrors shared/src/attestor.ts and the main repo's nsmNonceOf (packages/attestation-core): one preimage.
 *
 * Version 1: nonce = SHA-256(responseHash|apiEndpoint|timestamp)
 * Version 2: nonce = SHA-256(responseHash|apiEndpoint|timestamp|challenge) - the caller's challenge (32 bytes as
 * 64 lowercase hex) binds the document to ONE request (enclave audit P1.3). A document says which one it signed
 * (`nonceVersion`, absent = 1) and echoes the challenge.
 */

import crypto from 'node:crypto';
import type { AttestationDocument } from './types.js';

/** A caller challenge: 32 bytes as 64 lowercase hex (the enclave's and the core's CHALLENGE_PATTERN). */
export const CHALLENGE_PATTERN = /^[0-9a-f]{64}$/;

/**
 * Compute the expected nonce for an attestation.
 * Pipe delimiter prevents domain collisions from field concatenation.
 * With a challenge it is version 2; without one, version 1.
 */
export function computeNonce(
  responseHash: string,
  apiEndpoint: string,
  timestamp: number,
  challenge?: string,
): string {
  const base = `${responseHash}|${apiEndpoint}|${timestamp}`;
  return crypto
    .createHash('sha256')
    .update(challenge === undefined ? base : `${base}|${challenge}`)
    .digest('hex');
}

/**
 * Verify that the nonce in an attestation matches the expected value for the version it says it signed.
 * Version 2 needs its challenge; version 1 must carry none. Uses constant-time comparison.
 */
export function verifyNonce(attestation: AttestationDocument): {
  valid: boolean;
  expected: string;
  actual: string;
  error?: string;
} {
  const version = attestation.nonceVersion ?? 1;
  const { challenge } = attestation;
  if (version === 2 && (typeof challenge !== 'string' || !CHALLENGE_PATTERN.test(challenge))) {
    return { valid: false, expected: '', actual: attestation.nonce, error: 'nonce version 2 needs a challenge of 64 lowercase hex' };
  }
  if (version === 1 && challenge !== undefined) {
    return { valid: false, expected: '', actual: attestation.nonce, error: 'a challenge was given but the nonce is version 1' };
  }
  const expected = computeNonce(
    attestation.responseHash,
    attestation.apiEndpoint,
    attestation.timestamp,
    version === 2 ? challenge : undefined,
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
