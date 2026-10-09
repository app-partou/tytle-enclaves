import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { computeNonce, verifyNonce } from '../lib/nonce.js';
import type { AttestationDocument } from '../lib/types.js';

describe('computeNonce', () => {
  it('computes SHA-256 of pipe-delimited fields', () => {
    const responseHash = 'abc123';
    const apiEndpoint = 'ec.europa.eu/taxation_customs/vies/services/checkVatService';
    const timestamp = 1711612200;

    const expected = crypto
      .createHash('sha256')
      .update(`${responseHash}|${apiEndpoint}|${timestamp}`)
      .digest('hex');

    expect(computeNonce(responseHash, apiEndpoint, timestamp)).toBe(expected);
  });

  it('produces different nonces for different inputs', () => {
    const a = computeNonce('hash1', 'endpoint1', 1000);
    const b = computeNonce('hash2', 'endpoint1', 1000);
    const c = computeNonce('hash1', 'endpoint2', 1000);
    const d = computeNonce('hash1', 'endpoint1', 1001);

    expect(new Set([a, b, c, d]).size).toBe(4);
  });

  it('uses pipe delimiter to prevent domain collisions', () => {
    const a = computeNonce('abc', 'def', 123);
    const b = computeNonce('ab', 'cdef', 123);
    expect(a).not.toBe(b);
  });
});

describe('verifyNonce', () => {
  it('returns valid when nonce matches (constant-time)', () => {
    const responseHash = 'abc123';
    const apiEndpoint = 'example.com/api';
    const timestamp = 1700000000;

    const nonce = computeNonce(responseHash, apiEndpoint, timestamp);

    const attestation = {
      responseHash,
      apiEndpoint,
      timestamp,
      nonce,
    } as AttestationDocument;

    const result = verifyNonce(attestation);
    expect(result.valid).toBe(true);
    expect(result.expected).toBe(result.actual);
  });

  it('returns invalid when nonce does not match', () => {
    const attestation = {
      responseHash: 'abc123',
      apiEndpoint: 'example.com/api',
      timestamp: 1700000000,
      nonce: 'aa'.repeat(32), // valid hex but wrong nonce
    } as AttestationDocument;

    const result = verifyNonce(attestation);
    expect(result.valid).toBe(false);
    expect(result.expected).not.toBe(result.actual);
  });

  it('returns invalid for non-hex nonce without throwing', () => {
    const attestation = {
      responseHash: 'abc123',
      apiEndpoint: 'example.com/api',
      timestamp: 1700000000,
      nonce: 'not-hex-at-all',
    } as AttestationDocument;

    const result = verifyNonce(attestation);
    expect(result.valid).toBe(false);
  });

  it('returns invalid for different-length nonce', () => {
    const attestation = {
      responseHash: 'abc123',
      apiEndpoint: 'example.com/api',
      timestamp: 1700000000,
      nonce: 'aabb', // too short
    } as AttestationDocument;

    const result = verifyNonce(attestation);
    expect(result.valid).toBe(false);
  });
});

// Version 2 (enclave audit P1.3): the caller's challenge is appended, so the document is bound to ONE request.
describe('nonce version 2', () => {
  const challenge = 'c0'.repeat(32);
  const base = { responseHash: 'abc123', apiEndpoint: 'example.com/api', timestamp: 1700000000 };
  const v2 = crypto.createHash('sha256').update(`abc123|example.com/api|1700000000|${challenge}`).digest('hex');

  it('appends |challenge to the version-1 preimage (red)', () => {
    expect(computeNonce(base.responseHash, base.apiEndpoint, base.timestamp, challenge)).toBe(v2);
    expect(v2).not.toBe(computeNonce(base.responseHash, base.apiEndpoint, base.timestamp));
  });

  it('a version-2 document verifies with the challenge it echoes (red)', () => {
    const result = verifyNonce({ ...base, nonce: v2, nonceVersion: 2, challenge } as AttestationDocument);
    expect(result).toEqual({ valid: true, expected: v2, actual: v2 });
  });

  it('a version-2 document without its challenge is invalid, and says why (red)', () => {
    const result = verifyNonce({ ...base, nonce: v2, nonceVersion: 2 } as AttestationDocument);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('nonce version 2 needs a challenge of 64 lowercase hex');
  });

  it('a challenge that is not 64 lowercase hex is invalid, even when the nonce was made with it (red)', () => {
    for (const bad of ['C0'.repeat(32), 'c0'.repeat(31), 'zz'.repeat(32)]) {
      const nonce = crypto.createHash('sha256').update(`abc123|example.com/api|1700000000|${bad}`).digest('hex');
      const result = verifyNonce({ ...base, nonce, nonceVersion: 2, challenge: bad } as AttestationDocument);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('nonce version 2 needs a challenge of 64 lowercase hex');
    }
  });

  it('a version-1 document that carries a challenge is invalid (red)', () => {
    const result = verifyNonce({ ...base, nonce: v2, challenge } as AttestationDocument);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('a challenge was given but the nonce is version 1');
  });

  it('a version-1 nonce does not verify as version 2 (red)', () => {
    const v1 = computeNonce(base.responseHash, base.apiEndpoint, base.timestamp);
    expect(verifyNonce({ ...base, nonce: v1, nonceVersion: 2, challenge } as AttestationDocument).valid).toBe(false);
  });
});
