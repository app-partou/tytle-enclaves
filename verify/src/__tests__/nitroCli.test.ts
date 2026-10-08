/**
 * The PCR0 rebuild helper is the pinned verify/Dockerfile.nitro-cli (enclave audit P2.1). Until 2026-10 the CLI
 * built an inline, unpinned `FROM amazonlinux:2023` + `aws-nitro-enclaves-cli` image tagged `:latest`, while
 * VERIFICATION.md promised the pinned file: an unpinned helper can measure a different PCR0 than the release did.
 */

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { HELPER_IMAGE, NITRO_CLI_DOCKERFILE } from '../lib/nitroCli.js';

const PINNED = readFileSync(new URL('../../Dockerfile.nitro-cli', import.meta.url), 'utf-8');

describe('the nitro-cli helper image', () => {
  it('is built from verify/Dockerfile.nitro-cli, byte for byte (red)', () => {
    expect(NITRO_CLI_DOCKERFILE).toBe(PINNED);
  });

  it('the file pins the base image by digest and nitro-cli by version (lock)', () => {
    expect(PINNED).toMatch(/^FROM amazonlinux:2023@sha256:[0-9a-f]{64}$/m);
    expect(PINNED).toMatch(/^\s+aws-nitro-enclaves-cli-\d+\.\d+\.\d+-\S+ \\$/m);
    expect(PINNED).toMatch(/^\s+aws-nitro-enclaves-cli-devel-\d+\.\d+\.\d+-\S+ \\$/m);
  });

  it('its tag is a hash of the file, so a changed pin never reuses a stale local image (red)', () => {
    const hash = crypto.createHash('sha256').update(PINNED).digest('hex').slice(0, 16);
    expect(HELPER_IMAGE).toBe(`tytle-verify-nitro-cli:${hash}`);
  });

  it('the file ships in the npm package (lock)', () => {
    const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf-8')) as { files: string[] };
    expect(pkg.files).toContain('Dockerfile.nitro-cli');
  });
});
