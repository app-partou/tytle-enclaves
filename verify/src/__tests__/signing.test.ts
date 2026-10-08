/**
 * EIF signing (enclave audit P1.6). PCR0 says which code ran; anyone can run the public EIF in their own AWS account,
 * and their documents carry the same PCR0. Tytle signs its EIFs: a signed EIF boots with PCR8, the signing
 * certificate's, and signing changes no other PCR. The build (scripts/lib/recipe.mjs) checks the certificate before
 * it signs and computes the PCR8 the EIF must carry; the verify CLI (src/lib/signing.ts) computes it to compare. Both
 * are checked here against what nitro-cli 1.4.4 itself printed for one image, unsigned and then signed (fixtures/
 * signing). The 2026-10 plan wrote PCR8 = SHA-384(48 zero bytes || DER): that is not what nitro-cli computes.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const RECIPE_MJS = path.join(ROOT, 'scripts/lib/recipe.mjs');
const fixture = (file: string): string => path.join(ROOT, 'verify/src/__tests__/fixtures/signing', file);
const read = (file: string): string => readFileSync(fixture(file), 'utf8');

/** What nitro-cli 1.4.4 printed for ONE image: unsigned, then signed with signer.pem. */
const UNSIGNED = read('nitro-cli-1.4.4-unsigned.stdout.txt');
const SIGNED = read('nitro-cli-1.4.4-signed.stdout.txt');
const REAL_PCR8 = (JSON.parse(SIGNED) as { Measurements: { PCR8: string } }).Measurements.PCR8.toLowerCase();

/** scripts/lib/recipe.mjs, the build's half (plain JavaScript, so its shape is declared here). */
interface RecipeSigning {
  SIGNING_CERT_MIN_DAYS: number;
  pcr8Of(certPem: string): string;
  signingCheck(certPem: string, keyPem: string, now?: Date): string;
  measurementsOf(stdout: string): Record<string, string>;
  eifMeasurementsOf(service: string, digest: string, measurementsJson: string): Record<string, string>;
}
const recipe = async (): Promise<RecipeSigning> =>
  (await import(pathToFileURL(RECIPE_MJS).href)) as RecipeSigning;
/** The verify CLI's half (imported where it is used: each test fails alone where it is missing). */
const cliPcr8 = async (certPem: string): Promise<string> => (await import('../lib/signing.js')).pcr8OfCertificate(certPem);

/** recipe.mjs as the shell runs it: its exit code, what it printed, what it said on standard error. */
function command(args: string[], input = '') {
  const run = spawnSync(process.execPath, [RECIPE_MJS, ...args], { input, encoding: 'utf8' });
  return { status: run.status, stdout: run.stdout.trim(), stderr: run.stderr };
}

/** A day after signer.pem was made: every check below runs at this one instant, never on today's clock. */
const NOW = new Date('2026-10-09T00:00:00Z');
const DAY_MS = 86_400_000;

describe('the PCR8 of a signed EIF', () => {
  it("is the PCR8 nitro-cli printed for the build signed with the certificate: the build's and the CLI's (red)", async () => {
    expect(REAL_PCR8).toMatch(/^[0-9a-f]{96}$/);
    expect((await recipe()).pcr8Of(read('signer.pem'))).toBe(REAL_PCR8);
    expect(await cliPcr8(read('signer.pem'))).toBe(REAL_PCR8);
  });

  it("is SHA-384(48 zero bytes || SHA-384(DER)) - not the plan's SHA-384(48 zero bytes || DER) (lock)", () => {
    const der = new crypto.X509Certificate(read('signer.pem')).raw;
    const sha384 = (data: Buffer) => crypto.createHash('sha384').update(data).digest();
    expect(sha384(Buffer.concat([Buffer.alloc(48), sha384(der)])).toString('hex')).toBe(REAL_PCR8);
    expect(sha384(Buffer.concat([Buffer.alloc(48), der])).toString('hex')).not.toBe(REAL_PCR8);
  });

  it('another certificate gives another PCR8, the same key too (red)', async () => {
    const { pcr8Of } = await recipe();
    expect(pcr8Of(read('signer-long-lived.pem'))).not.toBe(REAL_PCR8);
    expect(await cliPcr8(read('signer-long-lived.pem'))).toBe(pcr8Of(read('signer-long-lived.pem')));
  });

  it('signing changes no other PCR: the build reads PCR0-2 alike, and PCR8 from the signed EIF only (red)', async () => {
    const { measurementsOf } = await recipe();
    const unsigned = measurementsOf(UNSIGNED);
    expect(unsigned).not.toHaveProperty('pcr8');
    expect(measurementsOf(SIGNED)).toEqual({ ...unsigned, pcr8: REAL_PCR8 });
  });

  it("an EIF's measurements file holds the build's record, and PCR8 when it is signed (red)", async () => {
    const { measurementsOf, eifMeasurementsOf } = await recipe();
    const digest = `sha256:${'b'.repeat(64)}`;
    const unsigned = measurementsOf(UNSIGNED);
    expect(eifMeasurementsOf('vies', digest, JSON.stringify(unsigned)))
      .toEqual({ enclave: 'vies', imageConfigDigest: digest, ...unsigned });
    expect(eifMeasurementsOf('vies', digest, JSON.stringify(measurementsOf(SIGNED))))
      .toEqual({ enclave: 'vies', imageConfigDigest: digest, ...unsigned, pcr8: REAL_PCR8 });
    expect(() => eifMeasurementsOf('vies', digest, JSON.stringify({ ...unsigned, pcr8: 'zz' })))
      .toThrow('not a measurements object');
  });
});

describe('the signing check, before anything is signed', () => {
  const refusal = async (cert: string, key: string, now = NOW): Promise<string> => {
    try {
      (await recipe()).signingCheck(read(cert), read(key), now);
    } catch (err) {
      return (err as Error).message;
    }
    return '(accepted)';
  };

  it("accepts an EC P-384 certificate with its own key and 60 days or more left, and returns its EIF's PCR8 (red)", async () => {
    expect((await recipe()).signingCheck(read('signer.pem'), read('signer-TESTONLY.key.pem'), NOW)).toBe(REAL_PCR8);
  });

  it('refuses a P-256 certificate (red)', async () => {
    expect(await refusal('p256.pem', 'p256-TESTONLY.key.pem')).toContain('its key is not EC P-384');
  });

  it("refuses a key that is not the certificate's (red)", async () => {
    expect(await refusal('signer.pem', 'other-TESTONLY.key.pem')).toContain('the private key is not its key');
  });

  it('refuses a certificate with fewer than 60 days left: an EIF whose certificate expired does not start (red)', async () => {
    expect(await refusal('ends-in-30-days.pem', 'signer-TESTONLY.key.pem')).toMatch(/29 days from now \(at least 60\)/);
  });

  it('refuses an expired certificate (red)', async () => {
    expect(await refusal('expired.pem', 'signer-TESTONLY.key.pem')).toContain('it ends 2025-01-01T00:00:00.000Z');
  });

  it('refuses a certificate that is not valid yet (red)', async () => {
    expect(await refusal('not-yet-valid.pem', 'signer-TESTONLY.key.pem'))
      .toContain('it is not valid before 2030-01-01T00:00:00.000Z');
  });

  it('60 days left is enough; a millisecond less is not (red)', async () => {
    const { SIGNING_CERT_MIN_DAYS } = await recipe();
    expect(SIGNING_CERT_MIN_DAYS).toBe(60);
    const end = new Date(new crypto.X509Certificate(read('signer.pem')).validTo).getTime();
    expect(await refusal('signer.pem', 'signer-TESTONLY.key.pem', new Date(end - 60 * DAY_MS))).toBe('(accepted)');
    expect(await refusal('signer.pem', 'signer-TESTONLY.key.pem', new Date(end - 60 * DAY_MS + 1)))
      .toContain('59 days from now (at least 60)');
  });

  it('names every problem at once, and the certificate (red)', async () => {
    const message = await refusal('p256.pem', 'signer-TESTONLY.key.pem');
    expect(message).toContain('CN=tytle-probe-p256-TESTONLY');
    expect(message).toContain('its key is not EC P-384; the private key is not its key');
  });
});

describe('the recipe commands the build scripts run', { timeout: 30_000 }, () => {
  it("signing-check prints the PCR8 an EIF the certificate signs carries, on today's clock (red)", async () => {
    const run = command(['signing-check', fixture('signer-long-lived.pem'), fixture('signer-TESTONLY.key.pem')]);
    expect(run).toMatchObject({ status: 0, stdout: await cliPcr8(read('signer-long-lived.pem')) });
  });

  it('signing-check fails, printing nothing, for a certificate it refuses (red)', () => {
    const run = command(['signing-check', fixture('expired.pem'), fixture('signer-TESTONLY.key.pem')]);
    expect(run.status).toBe(1);
    expect(run.stdout).toBe('');
    expect(run.stderr).toContain('recipe.mjs: the signing certificate CN=tytle-probe-expired-TESTONLY');
  });

  it("pcr8-is passes the measurements of an EIF signed with the certificate, and fails any other (red)", async () => {
    const { measurementsOf } = await recipe();
    const signed = JSON.stringify(measurementsOf(SIGNED));
    const unsigned = JSON.stringify(measurementsOf(UNSIGNED));
    expect(command(['pcr8-is', REAL_PCR8], signed)).toMatchObject({ status: 0, stdout: REAL_PCR8 });
    expect(command(['pcr8-is', 'ab'.repeat(48)], signed).status).toBe(1);
    const run = command(['pcr8-is', REAL_PCR8], unsigned);
    expect(run.status).toBe(1);
    expect(run.stderr).toContain('the EIF carries PCR8 (none: it is unsigned)');
  });

  it('measurements prints PCR8 for the signed output only (red)', () => {
    expect(JSON.parse(command(['measurements'], SIGNED).stdout)).toHaveProperty('pcr8', REAL_PCR8);
    expect(JSON.parse(command(['measurements'], UNSIGNED).stdout)).not.toHaveProperty('pcr8');
  });
});
