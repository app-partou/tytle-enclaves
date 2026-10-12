/**
 * The public "how to verify" words match the code (enclave audit P2.8 step 1). Until 2026-10 VERIFICATION.md and the
 * CLI's docblock told the public to run `npx @tytle-enclaves/verify`, a package that is not on npm.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { BUILDER_NAME } from '../lib/buildRecipe.js';
import { getAwsNitroRootCa } from '../lib/certChain.js';

const read = (relative: string) => readFileSync(new URL(relative, import.meta.url), 'utf-8');
const GUIDE = read('../../../VERIFICATION.md');
const README = read('../../../README.md');
const SECURITY = read('../../../SECURITY.md');
const MANIFESTS = read('../../../MANIFESTS.md');
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

  // Enclave review 2026-10-09, E2b F-10: the manual build made a builder named plain "tytle-repro", so a verifier who
  // made it under an earlier BuildKit pin kept building on that BuildKit. The CLI names its builder after the pin.
  it('the manual build makes and uses the builder the CLI makes: named after the BuildKit pin (red)', () => {
    expect(GUIDE).toContain(`docker buildx create --name ${BUILDER_NAME} --driver docker-container`);
    expect(GUIDE).toContain(`--builder ${BUILDER_NAME} \\`);
    expect(GUIDE).not.toMatch(/tytle-repro(?!-[0-9a-f]{12})/);
  });

  // E2b F-8: nothing signed covers attestationId, requestHash or apiMethod, and a version-2 challenge binds the
  // document to a request only for the caller who chose it.
  it('says which fields are signed, and never that requestHash or the id is checked (red)', () => {
    expect(GUIDE).toContain('`attestationId`, `requestHash` and `apiMethod` are not signed');
    expect(GUIDE).not.toMatch(/refuses a document without `requestHash`/);
    expect(GUIDE).not.toMatch(/to one request\)/);
    expect(MANIFESTS).not.toMatch(/requestHash → includes manifest hash → proves/);
  });

  // E2b F-11: the guarantees each page states are the ones the repository holds.
  it('states no guarantee the repository does not enforce (red)', () => {
    // CI is a check on a pull request; only branch protection on main (a GitHub setting) makes a merge wait for it
    for (const text of [GUIDE, SECURITY]) expect(text).not.toMatch(/CI builds every enclave twice on each pull request and fails unless/);
    // the enclave images install vendored, checksummed packages; the parent image installs from apt, unpinned
    expect(SECURITY).not.toMatch(/^- System packages are pinned by version$/m);
  });
});
