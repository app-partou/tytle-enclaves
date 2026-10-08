/**
 * The PCR0 rebuild helper is the pinned verify/Dockerfile.nitro-cli (enclave audit P2.1), built and run for the
 * recipe's platform, and its measurements are read as nitro-cli prints them (P2.2). Until 2026-10 the CLI built an
 * inline, unpinned `FROM amazonlinux:2023` + `aws-nitro-enclaves-cli` image tagged `:latest`, while VERIFICATION.md
 * promised the pinned file: an unpinned helper can measure a different PCR0 than the release did. Then it built the
 * pinned file for the HOST's platform: on an Apple Silicon Mac an arm64 nitro-cli, which looks for an arm64 image and
 * fails (E48). And it parsed each line of nitro-cli's output as JSON on its own, while nitro-cli prints ONE object over
 * several lines: no rebuild ever got its PCR0.
 *
 * The boundary swapped is the one the helper crosses, node:child_process (docker).
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

const docker = vi.hoisted(() => ({ calls: [] as Array<readonly string[]>, runOutput: '' }));
vi.mock('node:child_process', () => ({
  execFileSync: (file: string, args: readonly string[]) => {
    if (file !== 'docker') throw new Error(`not docker: ${file} (test)`);
    docker.calls.push(args);
    if (args[0] === 'image' && args[1] === 'inspect') throw new Error('No such image (test)');
    return args[0] === 'run' ? docker.runOutput : '';
  },
}));

import { HELPER_IMAGE, NITRO_CLI_DOCKERFILE, extractPcr0 } from '../lib/nitroCli.js';

const PINNED = readFileSync(new URL('../../Dockerfile.nitro-cli', import.meta.url), 'utf-8');
/** The standard output of a real nitro-cli 1.4.4 build-enclave (fixtures/README.md). */
const REAL_OUTPUT = readFileSync(new URL('./fixtures/nitro-cli-1.4.4-build-enclave.stdout.txt', import.meta.url), 'utf-8');
const REAL_PCRS = {
  pcr0: 'e6e9d38e06f431dc20dbc8056b5aae351bfe70d6c30afee0e811cfc616a83ffd2bdf5b4dc6076ef9071ad5c5df97afaf',
  pcr1: '4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493',
  pcr2: '331957c79e3e8d0327d58b66a82872729bb37125721e0033d3079181d346bd0210a8f99a1a88f62bd783a8b10222ab24',
};

afterEach(() => {
  docker.calls.length = 0;
  docker.runOutput = '';
  vi.restoreAllMocks();
});

const quietly = <T>(run: () => T): T => {
  vi.spyOn(console, 'log').mockImplementation(() => {});
  return run();
};

describe('the nitro-cli helper image', () => {
  it('is built from verify/Dockerfile.nitro-cli, byte for byte (red)', () => {
    expect(NITRO_CLI_DOCKERFILE).toBe(PINNED);
  });

  it('the file pins the base image by digest and nitro-cli by version (lock)', () => {
    expect(PINNED).toMatch(/^FROM amazonlinux:2023@sha256:[0-9a-f]{64}$/m);
    expect(PINNED).toMatch(/^\s+aws-nitro-enclaves-cli-\d+\.\d+\.\d+-\S+ \\$/m);
    expect(PINNED).toMatch(/^\s+aws-nitro-enclaves-cli-devel-\d+\.\d+\.\d+-\S+ \\$/m);
  });

  it('its tag is a hash of its platform and the file, so a changed pin never reuses a stale local image (red)', () => {
    const hash = crypto.createHash('sha256').update(`linux/amd64\n${PINNED}`).digest('hex').slice(0, 16);
    expect(HELPER_IMAGE).toBe(`tytle-verify-nitro-cli:${hash}`);
  });

  it('the file ships in the npm package (lock)', () => {
    const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf-8')) as { files: string[] };
    expect(pkg.files).toContain('Dockerfile.nitro-cli');
  });

  it('is built and run for linux/amd64 on every host: an arm64 nitro-cli cannot read an amd64 image (red)', () => {
    docker.runOutput = REAL_OUTPUT;
    try {
      quietly(() => extractPcr0('verify-vies:abc1234'));
    } catch {
      // The measurements are the next block's
    }
    const build = docker.calls.find((args) => args[0] === 'build');
    const run = docker.calls.find((args) => args[0] === 'run');
    expect(build?.slice(0, 5)).toEqual(['build', '--platform', 'linux/amd64', '-t', HELPER_IMAGE]);
    expect(run?.slice(0, 4)).toEqual(['run', '--rm', '--platform', 'linux/amd64']);
    expect(run).toContain(HELPER_IMAGE);
  });
});

describe('the measurements of a rebuild', () => {
  it("are read from nitro-cli's real output: ONE JSON object over several lines (red)", () => {
    docker.runOutput = REAL_OUTPUT;
    expect(quietly(() => extractPcr0('verify-vies:abc1234'))).toEqual(REAL_PCRS);
  });

  it('an object on one line is read too (lock)', () => {
    docker.runOutput = `${JSON.stringify({ Measurements: { PCR0: REAL_PCRS.pcr0, PCR1: REAL_PCRS.pcr1, PCR2: REAL_PCRS.pcr2 } })}\n`;
    expect(quietly(() => extractPcr0('verify-vies:abc1234'))).toEqual(REAL_PCRS);
  });

  it('an output without the three measurements is an error, never a PCR0 (lock)', () => {
    docker.runOutput = '{\n  "Measurements": {\n    "PCR0": "abc"\n  }\n}\n';
    expect(() => quietly(() => extractPcr0('verify-vies:abc1234'))).toThrow('Failed to parse PCR0');
  });
});
