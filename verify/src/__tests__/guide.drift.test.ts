/**
 * The public "how to verify" words match the code (enclave audit P2.8 step 1). Until 2026-10 VERIFICATION.md and the
 * CLI's docblock told the public to run `npx @tytle-enclaves/verify`, a package that is not on npm.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { getAwsNitroRootCa } from '../lib/certChain.js';

const read = (relative: string) => readFileSync(new URL(relative, import.meta.url), 'utf-8');
const GUIDE = read('../../../VERIFICATION.md');
const README = read('../../../README.md');
const CLI = read('../cli.ts');
const PCR0_API = read('../lib/pcr0Api.ts');

describe('the verification guide', () => {
  it('no one is told to run the CLI from npm while it is not published (red)', () => {
    for (const text of [GUIDE, README, CLI]) expect(text).not.toMatch(/npx\s+@tytle-enclaves\/verify/);
    expect(GUIDE).toContain('node dist/cli.js');
  });

  it('names the root fingerprint the CLI pins (red)', () => {
    expect(GUIDE).toContain(getAwsNitroRootCa().fingerprint256);
  });

  it('tells how to check PCR8 as the CLI checks it: its option, and the formula as a command (red)', () => {
    expect(CLI).toContain("'--signing-cert <file>'");
    expect(GUIDE).toContain('node dist/cli.js --service vies --attestation attestation.json --signing-cert signing-cert.pem');
    // SHA-384(48 zero bytes || SHA-384(DER)): signing.test.ts proves it is the PCR8 nitro-cli computes
    expect(GUIDE).toContain(
      '{ head -c 48 /dev/zero; openssl x509 -in signing-cert.pem -outform DER | openssl dgst -sha384 -binary; }');
  });

  it("names the PCR0 route the CLI reads (lock)", () => {
    const route = /`\$\{apiBaseUrl\}(\/api\/enclave\/pcr0)`/.exec(PCR0_API)?.[1];
    expect(route).toBe('/api/enclave/pcr0');
    expect(GUIDE).toContain(`GET https://api.tytle.io${route}`);
  });
});
