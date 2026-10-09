/**
 * The certificate chain of a Nitro document (enclave audit P2.1).
 *
 * AWS orders the cabundle root first, [ROOT, INTERM_1, ..., INTERM_N]; the leaf is signed by INTERM_N; every
 * certificate is judged at the signed time. Until 2026-10 the CLI walked [leaf, ROOT, INTERM_1, ...] and judged at
 * "now", and its tests used an EMPTY cabundle, so they passed while every real document failed: those cases are
 * replaced by the synthetic chains (fixtures/synthetic-chain), passed as the anchor, which is a plain argument.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';
import { getAwsNitroRootCa, verifyCertificateChain } from '../lib/certChain.js';
import { CHAINS, SIGNED_AT_SEC, type SyntheticChain } from './helpers/syntheticNsm.js';

const SIGNED_AT = new Date(SIGNED_AT_SEC * 1000);
const verifyAt = (chain: SyntheticChain, at: Date = SIGNED_AT, cabundle: Buffer[] = chain.cabundle) =>
  verifyCertificateChain(chain.leafDer, cabundle, at, new crypto.X509Certificate(chain.anchorPem));

afterEach(() => {
  vi.useRealTimers();
});

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
    // This MUST match the fingerprint pinned in trustAnchor.ts; if it did not, getAwsNitroRootCa() would have thrown.
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

describe('verifyCertificateChain: what verifies', () => {
  it('an AWS-ordered bundle [root, int] with a leaf signed by int verifies, judged at the signed time (red)', () => {
    expect(verifyAt(CHAINS.main())).toEqual({ valid: true, warnings: [] });
  });

  it("AWS's own depth (root, regional, zonal, instance) verifies (red)", () => {
    expect(verifyAt(CHAINS.awsDepth())).toEqual({ valid: true, warnings: [] });
  });

  it('a leaf signed by the root itself (a cabundle of one) verifies (red)', () => {
    expect(verifyAt(CHAINS.direct())).toEqual({ valid: true, warnings: [] });
  });

  it('validity is judged at the signed time: the 3-hour leaf verifies at signing, days after it expired (red)', () => {
    // The leaf lives 2026-10-05 11:00Z - 15:00Z; "now" is any later day.
    expect(Date.now()).toBeGreaterThan(Date.UTC(2026, 9, 5, 15, 0, 0));
    expect(verifyAt(CHAINS.main()).valid).toBe(true);
  });
});

describe('verifyCertificateChain: what fails', () => {
  it('a cabundle[0] that is not the pin fails, and the error names both fingerprints (red)', () => {
    const other = CHAINS.otherRoot();
    const pin = new crypto.X509Certificate(CHAINS.main().anchorPem);
    const result = verifyCertificateChain(other.leafDer, other.cabundle, SIGNED_AT, pin);
    expect(result.valid).toBe(false);
    expect(result.error).toBe(
      `cabundle[0] (${new crypto.X509Certificate(other.cabundle[0]).fingerprint256}) is not the AWS Nitro root (${pin.fingerprint256})`,
    );
  });

  it('by default the pin is the embedded AWS root: a chain under any other root fails (red)', () => {
    const chain = CHAINS.main();
    const result = verifyCertificateChain(chain.leafDer, chain.cabundle, SIGNED_AT);
    expect(result.valid).toBe(false);
    expect(result.error).toContain(`is not the AWS Nitro root (${getAwsNitroRootCa().fingerprint256})`);
  });

  it('an empty cabundle fails (red)', () => {
    const result = verifyAt(CHAINS.main(), SIGNED_AT, []);
    expect(result).toEqual({ valid: false, error: 'cabundle is empty: a Nitro document always carries the root first', warnings: [] });
  });

  it('the bundle in the order the old walk expected (intermediate first) fails (red)', () => {
    const chain = CHAINS.main();
    expect(verifyAt(chain, SIGNED_AT, [...chain.cabundle].reverse()).error).toMatch(/^cabundle\[0\] \(.+\) is not the AWS Nitro root/);
  });

  it('a leaf one second after it expired fails, naming the signed time (red)', () => {
    const after = new Date(Date.UTC(2026, 9, 5, 15, 0, 1));
    expect(verifyAt(CHAINS.main(), after).error).toMatch(/^Leaf certificate is not valid at the signed time 2026-10-05T15:00:01.000Z/);
  });

  it('a leaf one second before it was issued fails (red)', () => {
    const before = new Date(Date.UTC(2026, 9, 5, 10, 59, 59));
    expect(verifyAt(CHAINS.main(), before).error).toMatch(/^Leaf certificate is not valid at the signed time/);
  });

  it('an instance CA past its day fails, named before the leaf (red)', () => {
    // int-c-instance lives 2026-10-05 only; the bundle is judged before the leaf.
    const nextDay = new Date(Date.UTC(2026, 9, 6, 0, 0, 1));
    expect(verifyAt(CHAINS.awsDepth(), nextDay).error).toMatch(/^cabundle\[3\] is not valid at the signed time/);
  });

  it('a document with no valid signed time fails (red)', () => {
    expect(verifyAt(CHAINS.main(), new Date(Number.NaN)).error).toBe('The document has no valid signed time');
  });

  it('a pin that is not valid now fails (red)', () => {
    vi.useFakeTimers({ now: Date.UTC(2060, 0, 2) });   // the synthetic roots end 2060-01-01
    expect(verifyAt(CHAINS.main()).error).toMatch(/^The AWS Nitro root is not valid now/);
  });

  it('an intermediate without CA:TRUE fails (red)', () => {
    expect(verifyAt(CHAINS.intermediateNotCa()).error).toBe('cabundle[1] is not a CA certificate (basicConstraints CA:TRUE missing)');
  });

  it('an instance CA without CA:TRUE at AWS depth fails (red)', () => {
    expect(verifyAt(CHAINS.awsDepthInstanceNotCa()).error).toBe('cabundle[3] is not a CA certificate (basicConstraints CA:TRUE missing)');
  });

  it('a leaf that claims CA:TRUE fails (red)', () => {
    expect(verifyAt(CHAINS.leafIsCa()).error).toBe('Leaf certificate is a CA certificate (basicConstraints CA:TRUE)');
  });

  it('a bundle member not signed by the one before it fails (red)', () => {
    const main = CHAINS.main();
    const strange = [main.cabundle[0], CHAINS.otherRoot().cabundle[1]];
    expect(verifyAt(main, SIGNED_AT, strange).error).toBe('cabundle[1] is not signed by cabundle[0]');
  });

  it('a leaf not signed by the last bundle member fails (red)', () => {
    const main = CHAINS.main();
    const result = verifyCertificateChain(CHAINS.otherRoot().leafDer, main.cabundle, SIGNED_AT, new crypto.X509Certificate(main.anchorPem));
    expect(result.error).toBe('Leaf certificate is not signed by cabundle[1]');
  });

  it('bytes that are not a certificate fail (lock)', () => {
    const chain = CHAINS.main();
    const result = verifyAt({ ...chain, leafDer: Buffer.from('not-a-certificate') });
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/^Certificate chain verification error: /);
  });

  it('a malformed DER structure fails (lock)', () => {
    const chain = CHAINS.main();
    const result = verifyAt(chain, SIGNED_AT, [Buffer.from([0x30, 0x82, 0x00, 0x01, 0x00])]);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/^Certificate chain verification error: /);
  });
});
