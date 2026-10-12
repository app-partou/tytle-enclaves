import { describe, it, expect } from 'vitest';
import {
  shouldSkipAttestation,
  getAttestOverrides,
  getHeadersToStrip,
  redactError,
} from '../policyEngine.js';
import {
  SKIP_TRANSIENT_ERRORS,
  STRIP_AUTH,
  REDACT_BEARER,
} from '../policies.js';
import type { PolicyDef } from '../manifest.js';

const STANDARD_POLICIES: PolicyDef[] = [
  SKIP_TRANSIENT_ERRORS,
  STRIP_AUTH,
  REDACT_BEARER,
];

describe('shouldSkipAttestation', () => {
  it('skips 500, 502, 503', () => {
    expect(shouldSkipAttestation(STANDARD_POLICIES, 500)).toBe(true);
    expect(shouldSkipAttestation(STANDARD_POLICIES, 502)).toBe(true);
    expect(shouldSkipAttestation(STANDARD_POLICIES, 503)).toBe(true);
  });

  it('skips 400, 401, 403, 429', () => {
    expect(shouldSkipAttestation(STANDARD_POLICIES, 400)).toBe(true);
    expect(shouldSkipAttestation(STANDARD_POLICIES, 401)).toBe(true);
    expect(shouldSkipAttestation(STANDARD_POLICIES, 429)).toBe(true);
  });

  it('does NOT skip 404 (definitive answer)', () => {
    expect(shouldSkipAttestation(STANDARD_POLICIES, 404)).toBe(false);
  });

  it('does NOT skip 200', () => {
    expect(shouldSkipAttestation(STANDARD_POLICIES, 200)).toBe(false);
  });

  it('does NOT skip 201, 204', () => {
    expect(shouldSkipAttestation(STANDARD_POLICIES, 201)).toBe(false);
    expect(shouldSkipAttestation(STANDARD_POLICIES, 204)).toBe(false);
  });

  it('handles empty policies', () => {
    expect(shouldSkipAttestation([], 500)).toBe(false);
  });

  it('respects except field when code IS in both codes and except', () => {
    const policy: PolicyDef = {
      id: 'test',
      check: { type: 'status_skip', codes: [500, 502, 404], except: [404] },
      reason: 'test',
    };
    expect(shouldSkipAttestation([policy], 500)).toBe(true);
    expect(shouldSkipAttestation([policy], 404)).toBe(false);
  });

  // Enclave review 2026-10-09, E2a F-17: the handlers pass on EVERY error status but 404 (Stripe) or every one
  // (Monerium), and a list of seven codes said otherwise: 402, 409, 504 were passed on with no rule naming them.
  it('a status_skip with atLeast skips every status from it, but those in except (red)', () => {
    const policy: PolicyDef = {
      id: 'test',
      check: { type: 'status_skip', codes: [], atLeast: 400, except: [404] },
      reason: 'test',
    };
    expect([399, 400, 402, 404, 409, 504, 599].map((status) => shouldSkipAttestation([policy], status)))
      .toEqual([false, true, true, false, true, true, true]);
  });

  it('SKIP_TRANSIENT_ERRORS skips every status of 400 or more but 404: 402, 409, 422 and 504 too (red)', () => {
    for (const status of [400, 401, 402, 403, 405, 409, 422, 429, 500, 501, 502, 503, 504, 599]) {
      expect(shouldSkipAttestation([SKIP_TRANSIENT_ERRORS], status), String(status)).toBe(true);
    }
    for (const status of [200, 201, 204, 301, 399, 404]) {
      expect(shouldSkipAttestation([SKIP_TRANSIENT_ERRORS], status), String(status)).toBe(false);
    }
  });
});

describe('getAttestOverrides', () => {
  it('returns overrides for 404', () => {
    const notFound: PolicyDef = { id: 'test', check: { type: 'status_attest', code: 404, overrides: { state: 'not_found' } }, reason: 'test' };
    const overrides = getAttestOverrides([...STANDARD_POLICIES, notFound], 404);
    expect(overrides).toEqual({ state: 'not_found' });
  });

  it('returns null for 200 (no status_attest policy)', () => {
    expect(getAttestOverrides(STANDARD_POLICIES, 200)).toBeNull();
  });

  it('returns null for 500 (not a status_attest code)', () => {
    expect(getAttestOverrides(STANDARD_POLICIES, 500)).toBeNull();
  });

  it('returns empty object when overrides is undefined', () => {
    const policy: PolicyDef = {
      id: 'test',
      check: { type: 'status_attest', code: 410 },
      reason: 'test',
    };
    expect(getAttestOverrides([policy], 410)).toEqual({});
  });
});

describe('getHeadersToStrip', () => {
  it('returns Authorization from standard policies', () => {
    expect(getHeadersToStrip(STANDARD_POLICIES)).toEqual(['Authorization']);
  });

  it('returns empty for no header_strip policies', () => {
    expect(getHeadersToStrip([SKIP_TRANSIENT_ERRORS])).toEqual([]);
  });

  it('collects from multiple header_strip policies', () => {
    const policies: PolicyDef[] = [
      { id: 'a', check: { type: 'header_strip', headers: ['Authorization'] }, reason: '' },
      { id: 'b', check: { type: 'header_strip', headers: ['X-Api-Key', 'Cookie'] }, reason: '' },
    ];
    expect(getHeadersToStrip(policies)).toEqual(['Authorization', 'X-Api-Key', 'Cookie']);
  });
});

describe('redactError', () => {
  it('redacts Bearer tokens', () => {
    const msg = 'TLS error: Bearer sk_live_abc123def456 was rejected';
    const result = redactError(STANDARD_POLICIES, msg);
    expect(result).toBe('TLS error: Bearer [REDACTED] was rejected');
  });

  it('leaves messages without tokens unchanged', () => {
    const msg = 'Connection refused';
    expect(redactError(STANDARD_POLICIES, msg)).toBe('Connection refused');
  });

  it('handles empty policies', () => {
    const msg = 'Bearer secret123';
    expect(redactError([], msg)).toBe('Bearer secret123');
  });

  it('is case-insensitive', () => {
    const msg = 'bearer TOKEN123';
    const result = redactError(STANDARD_POLICIES, msg);
    expect(result).toBe('Bearer [REDACTED]');
  });
});
