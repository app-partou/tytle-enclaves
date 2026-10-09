/**
 * The build scripts sign an EIF only as they should (enclave audit P1.6): scripts/build-eif.sh, through
 * scripts/lib/recipe.sh, checks the signing certificate before it builds, signs with the two files mounted read-only,
 * refuses an EIF whose PCR8 is not the certificate's or whose build is not the committed one, and writes nothing then.
 * The determinism gate never signs.
 *
 * The scripts run for real (bash, recipe.mjs, tar) on this repository; only `docker` is swapped, for
 * helpers/fakeDocker.mjs on PATH, which records each call and prints nitro-cli's real output for the vies build of
 * scripts/expected-digests.json (fixtures/signing).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const fixture = (file: string): string => path.join(ROOT, 'verify/src/__tests__/fixtures/signing', file);
const FAKE_DOCKER = path.join(ROOT, 'verify/src/__tests__/helpers/fakeDocker.mjs');

const VIES = (JSON.parse(readFileSync(path.join(ROOT, 'scripts/expected-digests.json'), 'utf8')) as
  Record<string, { imageConfigDigest: string; pcr0: string; pcr1: string; pcr2: string }>).vies;
const SIGNER = fixture('signer-long-lived.pem');
const SIGNER_KEY = fixture('signer-TESTONLY.key.pem');
/** SHA-384(48 zero bytes || SHA-384(DER)): signing.test.ts proves it is the PCR8 nitro-cli computes. */
const sha384 = (data: Buffer): Buffer => crypto.createHash('sha384').update(data).digest();
const SIGNER_PCR8 = sha384(Buffer.concat([Buffer.alloc(48), sha384(new crypto.X509Certificate(readFileSync(SIGNER)).raw)]))
  .toString('hex');

let dir: string;
let out: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'build-eif-'));
  out = path.join(dir, 'out');
  mkdirSync(path.join(dir, 'bin'));
  writeFileSync(path.join(dir, 'bin', 'docker'), `#!/bin/sh\nexec "${process.execPath}" "${FAKE_DOCKER}" "$@"\n`);
  chmodSync(path.join(dir, 'bin', 'docker'), 0o755);
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
  /** Every docker call, in order */
  calls: string[][];
}

/** Run a script of this repository with the fake docker first on PATH. */
function runScript(script: string, args: string[], env: Record<string, string> = {}): Run {
  const log = path.join(dir, 'docker.log');
  const run = spawnSync('bash', [path.join(ROOT, script), ...args], {
    encoding: 'utf8',
    env: {
      PATH: `${path.join(dir, 'bin')}:${process.env.PATH ?? ''}`,
      HOME: dir,
      TMPDIR: dir,
      FAKE_DOCKER_LOG: log,
      FAKE_DOCKER_CONFIG_DIGEST: VIES.imageConfigDigest,
      FAKE_DOCKER_MEASUREMENTS: fixture('nitro-cli-1.4.4-unsigned.stdout.txt'),
      FAKE_DOCKER_PCR8: SIGNER_PCR8,
      ...env,
    },
  });
  const calls = existsSync(log)
    ? readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line) as string[])
    : [];
  return { status: run.status, stdout: run.stdout, stderr: run.stderr, calls };
}

/** Each script runs bash and a dozen node processes: alone a second or two, much more beside the other suites. */
const SCRIPT_TIMEOUT = { timeout: 60_000 };

const runOf = (r: Run): string[] | undefined => r.calls.find((call) => call[0] === 'run');
const built = (r: Run): boolean => r.calls.some((call) => call[0] === 'buildx' && call[1] === 'build');
const signing = { EIF_SIGNING_KEY: SIGNER_KEY, EIF_SIGNING_CERT: SIGNER };

describe('the nitro-cli pair is the record\'s vies build', () => {
  // The tests below print nitro-cli's REAL output for ONE vies image (fixtures/signing). When the vies entry of
  // scripts/expected-digests.json changes, that output is another build's and the scripts refuse it as "not the
  // committed build": the fix is to measure the pair again, not to touch the record.
  it.each(['nitro-cli-1.4.4-unsigned.stdout.txt', 'nitro-cli-1.4.4-signed.stdout.txt'])('%s', (file) => {
    const m = (JSON.parse(readFileSync(fixture(file), 'utf8')) as { Measurements: Record<string, string> }).Measurements;
    expect({ pcr0: m.PCR0, pcr1: m.PCR1, pcr2: m.PCR2 },
      `${file} is not the vies build of scripts/expected-digests.json: measure the nitro-cli pair again (fixtures/signing/generate.sh)`)
      .toEqual({ pcr0: VIES.pcr0, pcr1: VIES.pcr1, pcr2: VIES.pcr2 });
  });
});

describe('scripts/build-eif.sh', SCRIPT_TIMEOUT, () => {
  it('unsigned: the committed build, its EIF and its measurements, and no signing flag (red)', () => {
    const r = runScript('scripts/build-eif.sh', ['vies', out]);
    expect(r.status, r.stderr).toBe(0);
    expect(readFileSync(path.join(out, 'vies.eif'), 'utf8')).toBe('a fake EIF\n');
    const written = JSON.parse(readFileSync(path.join(out, 'vies.measurements.json'), 'utf8')) as unknown;
    expect(written).toEqual({ enclave: 'vies', ...VIES });
    expect(JSON.parse(r.stdout)).toEqual(written);
    expect(runOf(r)?.slice(0, 6)).toEqual(['run', '--rm', '--platform', 'linux/amd64', '-v', '/var/run/docker.sock:/var/run/docker.sock']);
    expect(runOf(r)).not.toContain('--private-key');
    expect(runOf(r)?.join(' ')).not.toContain('/signing/');
  });

  it('signed: the key and certificate mounted read-only, and the PCR8 that is the certificate\'s recorded (red)', () => {
    const r = runScript('scripts/build-eif.sh', ['vies', out], signing);
    expect(r.status, r.stderr).toBe(0);
    const run = runOf(r)!;
    expect(run.join(' ')).toContain(`-v ${SIGNER_KEY}:/signing/key.pem:ro -v ${SIGNER}:/signing/cert.pem:ro`);
    expect(run.slice(-4)).toEqual(['--private-key', '/signing/key.pem', '--signing-certificate', '/signing/cert.pem']);
    expect(run).toContain('build-enclave');
    expect(JSON.parse(readFileSync(path.join(out, 'vies.measurements.json'), 'utf8')))
      .toEqual({ enclave: 'vies', ...VIES, pcr8: SIGNER_PCR8 });
    expect(existsSync(path.join(out, 'vies.eif'))).toBe(true);
  });

  it('a certificate the check refuses stops it before anything is built (red)', () => {
    const r = runScript('scripts/build-eif.sh', ['vies', out], { ...signing, EIF_SIGNING_CERT: fixture('expired.pem') });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('the signing certificate CN=tytle-probe-expired-TESTONLY');
    expect(built(r)).toBe(false);
    expect(readdirSync(out)).toEqual([]);
  });

  it('a key without its certificate stops it before anything is built (red)', () => {
    const r = runScript('scripts/build-eif.sh', ['vies', out], { EIF_SIGNING_KEY: SIGNER_KEY });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('set both EIF_SIGNING_KEY and EIF_SIGNING_CERT, or neither');
    expect(built(r)).toBe(false);
  });

  it("an EIF whose PCR8 is not the certificate's is refused, and nothing is written (red)", () => {
    const r = runScript('scripts/build-eif.sh', ['vies', out], { ...signing, FAKE_DOCKER_PCR8: 'ab'.repeat(48) });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain(`the EIF carries PCR8 ${'ab'.repeat(48)}, not the certificate's ${SIGNER_PCR8}`);
    expect(readdirSync(out)).toEqual([]);
  });

  it('a build that is not the committed one is refused, and nothing is written (red)', () => {
    const r = runScript('scripts/build-eif.sh', ['vies', out], { FAKE_DOCKER_CONFIG_DIGEST: `sha256:${'0'.repeat(64)}` });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('vies is not the committed build');
    expect(readdirSync(out)).toEqual([]);
  });

  it('takes only an enclave of this repository, and an output directory (red)', () => {
    for (const args of [['parent', out], ['../vies', out], ['vies']]) {
      const r = runScript('scripts/build-eif.sh', args);
      expect(r.status, args.join(' ')).toBe(2);
      expect(built(r)).toBe(false);
    }
  });
});

describe('scripts/lib/recipe.sh', SCRIPT_TIMEOUT, () => {
  it('recipe_measure itself refuses a certificate the check refuses, before nitro-cli runs: every caller is safe (red)', () => {
    const log = path.join(dir, 'docker.log');
    const tar = path.join(dir, 'image.tar');
    const run = spawnSync('bash', ['-c', 'source "$1" && recipe_build vies "$2" tytle-enclave-vies:t && recipe_measure "$2"',
      '_', path.join(ROOT, 'scripts/lib/recipe.sh'), tar], {
      encoding: 'utf8',
      env: {
        PATH: `${path.join(dir, 'bin')}:${process.env.PATH ?? ''}`,
        FAKE_DOCKER_LOG: log,
        FAKE_DOCKER_CONFIG_DIGEST: VIES.imageConfigDigest,
        FAKE_DOCKER_MEASUREMENTS: fixture('nitro-cli-1.4.4-unsigned.stdout.txt'),
        EIF_SIGNING_KEY: SIGNER_KEY,
        EIF_SIGNING_CERT: fixture('ends-in-30-days.pem'),
      },
    });
    expect(run.status).not.toBe(0);
    expect(run.stderr).toContain('the signing certificate CN=tytle-probe-ends-in-30-days-TESTONLY');
    const calls = readFileSync(log, 'utf8').trim().split('\n').map((line) => JSON.parse(line) as string[]);
    expect(calls.some((call) => call[0] === 'buildx' && call[1] === 'build')).toBe(true);
    expect(calls.some((call) => call[0] === 'run' || call[0] === 'load')).toBe(false);
  });
});

describe('the determinism gate', SCRIPT_TIMEOUT, () => {
  it('never signs, whatever the shell holds: it measures the unsigned build (lock)', () => {
    const r = runScript('scripts/test-determinism.sh', ['vies'], signing);
    expect(r.status, r.stderr + r.stdout).toBe(0);
    expect(r.stdout).toContain('PASS: vies');
    const run = runOf(r)!;
    expect(run).toContain('build-enclave');
    expect(run).not.toContain('--private-key');
  });
});
