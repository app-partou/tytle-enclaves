/**
 * The build scripts hold an enclave to its committed build (enclave review 2026-10-09: H6's build half, E2b F-3 and F-5).
 *
 * scripts/build-service.sh is the deploy's build (each build.sh). It built an enclave, then loaded and pushed it
 * whatever its digest, so a build that drifted from scripts/expected-digests.json became the production PCR0 with no
 * alarm. It now refuses an enclave image that is not the committed build, before Docker loads it or a registry gets it.
 *
 * scripts/rotate-pcr0.sh printed "New PCR0: (empty) ... CHANGED" for a failed build, read every SSM error as
 * "(not set)", and its --apply wrote any PCR0 to SSM: the record unchecked, the commit and the previous pin not kept.
 * It now fails on a failed build or SSM read, says whether the build is the committed one (and fails when it is not),
 * and writes nothing. The main repository's enclave reload publishes each pin, once its enclave runs, with the record
 * checked and the previous pin kept.
 *
 * The scripts run for real (bash, recipe.mjs, tar). Only `docker` and `aws` are swapped, for helpers/fakeDocker.mjs and
 * helpers/fakeAws.mjs on PATH, which record each call. "(red)": fails on the scripts before this change; "(lock)":
 * right before and after.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const helper = (file: string): string => path.join(ROOT, 'verify/src/__tests__/helpers', file);

const ENCLAVES = readdirSync(ROOT, { withFileTypes: true })
  .filter((d) => d.isDirectory() && existsSync(path.join(ROOT, d.name, 'src/enclave.ts')))
  .map((d) => d.name)
  .sort();
const RECORD = JSON.parse(readFileSync(path.join(ROOT, 'scripts/expected-digests.json'), 'utf8')) as
  Record<string, { imageConfigDigest: string; pcr0: string; pcr1: string; pcr2: string }>;
/** nitro-cli's real output for the vies build of the record (fixtures/signing; buildEif.test.ts pins the pair). */
const VIES_MEASUREMENTS = path.join(ROOT, 'verify/src/__tests__/fixtures/signing/nitro-cli-1.4.4-unsigned.stdout.txt');
const DRIFTED = `sha256:${'0'.repeat(64)}`;

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'build-scripts-'));
  mkdirSync(path.join(dir, 'bin'));
  for (const [tool, program] of [['docker', 'fakeDocker.mjs'], ['aws', 'fakeAws.mjs']]) {
    writeFileSync(path.join(dir, 'bin', tool), `#!/bin/sh\nexec "${process.execPath}" "${helper(program)}" "$@"\n`);
    chmodSync(path.join(dir, 'bin', tool), 0o755);
  }
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
  /** Every docker call, in order */
  docker: string[][];
  /** Every aws call, in order */
  aws: string[][];
}

const callsIn = (log: string): string[][] => (existsSync(log)
  ? readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line) as string[])
  : []);

/** Run a script of this repository with the fake docker and aws first on PATH. */
function runScript(script: string, args: string[], env: Record<string, string> = {}): Run {
  const dockerLog = path.join(dir, 'docker.log');
  const awsLog = path.join(dir, 'aws.log');
  const run = spawnSync('bash', [path.join(ROOT, script), ...args], {
    encoding: 'utf8',
    env: {
      PATH: `${path.join(dir, 'bin')}:${process.env.PATH ?? ''}`,
      HOME: dir,
      TMPDIR: dir,
      FAKE_DOCKER_LOG: dockerLog,
      FAKE_DOCKER_CONFIG_DIGEST: RECORD.vies.imageConfigDigest,
      FAKE_DOCKER_MEASUREMENTS: VIES_MEASUREMENTS,
      FAKE_AWS_LOG: awsLog,
      ...env,
    },
  });
  return { status: run.status, stdout: run.stdout, stderr: run.stderr, docker: callsIn(dockerLog), aws: callsIn(awsLog) };
}

const did = (calls: string[][], ...words: string[]): boolean =>
  calls.some((call) => words.every((word, i) => call[i] === word));

/** Each script runs bash and a dozen node processes: alone a second or two, much more beside the other suites. */
const SCRIPT_TIMEOUT = { timeout: 60_000 };

describe('scripts/build-service.sh: an enclave is the committed build, or nothing is loaded or pushed', SCRIPT_TIMEOUT, () => {
  it.each(ENCLAVES)('%s: an image that is not the committed build is refused before it is loaded, tagged or pushed (red)', (enclave) => {
    const r = runScript('scripts/build-service.sh', [enclave, 'release', 'registry.example/tytle'], { FAKE_DOCKER_CONFIG_DIGEST: DRIFTED });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain(`${enclave} is not the committed build`);
    expect(r.stderr).toContain(`imageConfigDigest: committed ${RECORD[enclave].imageConfigDigest}, built ${DRIFTED}`);
    expect(did(r.docker, 'buildx', 'build')).toBe(true);
    expect(did(r.docker, 'load')).toBe(false);
    expect(did(r.docker, 'tag')).toBe(false);
    expect(did(r.docker, 'push')).toBe(false);
  });

  it('an enclave with no record is never the committed build (red)', () => {
    // A new enclave's first build is refused until its record is committed (scripts/test-determinism.sh --update).
    const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts/lib/recipe.mjs'), 'check-digest', 'not-recorded', DRIFTED],
      { encoding: 'utf8' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('not-recorded is not the committed build');
    expect(r.stderr).toContain('no committed record');
  });

  it('the committed build is loaded, tagged and pushed (lock)', () => {
    const r = runScript('scripts/build-service.sh', ['vies', 'release', 'registry.example/tytle']);
    expect(r.status, r.stderr).toBe(0);
    expect(did(r.docker, 'load', '-i')).toBe(true);
    expect(did(r.docker, 'tag', 'tytle-enclave-vies:release', 'registry.example/tytle:vies')).toBe(true);
    expect(did(r.docker, 'push', 'registry.example/tytle:vies')).toBe(true);
    expect(r.stdout).toContain(`Image digest: ${RECORD.vies.imageConfigDigest}`);
  });

  it('the parent is no enclave: it has no record, and its image is loaded (lock)', () => {
    const r = runScript('scripts/build-service.sh', ['parent', 'ci'], { FAKE_DOCKER_CONFIG_DIGEST: DRIFTED });
    expect(r.status, r.stderr).toBe(0);
    expect(did(r.docker, 'load', '-i')).toBe(true);
  });
});

describe('scripts/rotate-pcr0.sh: the PCR0 of a build, the record and SSM - and nothing written', SCRIPT_TIMEOUT, () => {
  it('a failed build fails the script, prints no PCR0 and reads no SSM (red)', () => {
    const r = runScript('scripts/rotate-pcr0.sh', ['vies'], { FAKE_DOCKER_BUILD_FAILS: '1', FAKE_AWS_SSM_VALUE: RECORD.vies.pcr0 });
    expect(r.status).not.toBe(0);
    expect(r.stdout).not.toMatch(/PCR0: *\n/);
    expect(r.stdout).not.toContain('CHANGED');
    expect(r.aws).toEqual([]);
  });

  it('an SSM read that fails fails the script: an expired session is not "(not set)" (red)', () => {
    const r = runScript('scripts/rotate-pcr0.sh', ['vies'], { FAKE_AWS_FAILS: '1' });
    expect(r.status).not.toBe(0);
    expect(r.stdout).not.toContain('(not set)');
    expect(r.stderr).toContain('ExpiredTokenException');
  });

  it('an SSM answer that names neither the parameter nor its absence fails the script (red)', () => {
    const r = runScript('scripts/rotate-pcr0.sh', ['vies'], { FAKE_AWS_RAW: '{"Parameters": [], "InvalidParameters": []}' });
    expect(r.status).not.toBe(0);
    expect(r.stdout).not.toContain('(not set)');
  });

  it('a parameter SSM does not have reads as "(not set)" (lock)', () => {
    const r = runScript('scripts/rotate-pcr0.sh', ['vies']);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain('(not set) (/tytle/staging/enclave/vies/pcr0)');
  });

  it('the committed build, published: the build, the record and SSM name one PCR0 (red)', () => {
    const r = runScript('scripts/rotate-pcr0.sh', ['vies'], { FAKE_AWS_SSM_VALUE: RECORD.vies.pcr0, ENVIRONMENT: 'production' });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain(`Built PCR0: ${RECORD.vies.pcr0}`);
    expect(r.stdout).toContain(`Record:     vies: the committed build (${RECORD.vies.imageConfigDigest})`);
    expect(r.stdout).toContain(`SSM PCR0:   ${RECORD.vies.pcr0} (/tytle/production/enclave/vies/pcr0)`);
    expect(r.stdout).toContain('SSM has this build.');
    expect(did(r.aws, 'ssm', 'get-parameters', '--names', '/tytle/production/enclave/vies/pcr0')).toBe(true);
  });

  it('a build that is not the committed one is named, and the script fails (red)', () => {
    const r = runScript('scripts/rotate-pcr0.sh', ['vies'], { FAKE_DOCKER_CONFIG_DIGEST: DRIFTED, FAKE_AWS_SSM_VALUE: RECORD.vies.pcr0 });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('Record:     NOT the committed build');
    expect(r.stdout).toContain(`imageConfigDigest: committed ${RECORD.vies.imageConfigDigest}, built ${DRIFTED}`);
  });

  it('--apply writes nothing, builds nothing, and names the door that publishes pins (red)', () => {
    const r = runScript('scripts/rotate-pcr0.sh', ['vies', '--apply'], { FAKE_AWS_SSM_VALUE: 'ab'.repeat(48) });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('infra/scripts/enclave-reload.sh');
    expect(did(r.aws, 'ssm', 'put-parameter')).toBe(false);
    expect(did(r.docker, 'buildx', 'build')).toBe(false);
  });
});
