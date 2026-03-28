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
