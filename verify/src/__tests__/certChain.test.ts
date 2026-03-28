import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { getAwsNitroRootCa, verifyCertificateChain } from '../lib/certChain.js';

describe('getAwsNitroRootCa', () => {
  it('returns a valid X509Certificate', () => {
    const rootCa = getAwsNitroRootCa();
    expect(rootCa).toBeInstanceOf(crypto.X509Certificate);
  });

  it('has the expected subject', () => {
    const rootCa = getAwsNitroRootCa();
    expect(rootCa.subject).toContain('aws.nitro-enclaves');
  });

  it('is self-signed', () => {
    const rootCa = getAwsNitroRootCa();
    expect(rootCa.issuer).toBe(rootCa.subject);
  });

  it('uses ECDSA P-384', () => {
    const rootCa = getAwsNitroRootCa();
    const key = rootCa.publicKey;
    const details = key.asymmetricKeyDetails;
    expect(details?.namedCurve).toBe('secp384r1');
  });

  it('has the expected SHA-256 fingerprint (verified at runtime)', () => {
    const rootCa = getAwsNitroRootCa();
    // This MUST match the EXPECTED_ROOT_FINGERPRINT constant in certChain.ts.
    // If it doesn't, getRootCa() would have already thrown.
    expect(rootCa.fingerprint256.replace(/:/g, '')).toBe(
      '641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B',
    );
  });

  it('is currently valid (not expired)', () => {
    const rootCa = getAwsNitroRootCa();
    const now = new Date();
    expect(new Date(rootCa.validFrom) <= now).toBe(true);
    expect(new Date(rootCa.validTo) >= now).toBe(true);
  });

  it('has CA:TRUE basic constraint', () => {
    const rootCa = getAwsNitroRootCa();
    expect(rootCa.ca).toBe(true);
  });
});

describe('verifyCertificateChain', () => {
  it('rejects invalid DER bytes', () => {
    const fakeCert = Buffer.from('not-a-certificate');
    const result = verifyCertificateChain(fakeCert, []);
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('rejects malformed DER structures', () => {
    const fakeDer = Buffer.from([0x30, 0x82, 0x00, 0x01, 0x00]);
    const result = verifyCertificateChain(fakeDer, []);
    expect(result.valid).toBe(false);
  });
});
