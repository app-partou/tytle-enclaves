/**
 * The CI of this repository covers every package and every enclave (enclave audit P2.2). Until 2026-10 the repository
 * had no CI at all: no test, no determinism gate and no PCR0 ran on a pull request. A new package or enclave must be
 * in the workflow's lists (and in scripts/ci/test-package.sh), or CI would pass without it.
 */

import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const read = (rel: string): string => readFileSync(path.join(ROOT, rel), 'utf8');
const WORKFLOW = '.github/workflows/ci.yml';

const ENCLAVES = readdirSync(ROOT, { withFileTypes: true })
  .filter((d) => d.isDirectory() && existsSync(path.join(ROOT, d.name, 'src/enclave.ts')))
  .map((d) => d.name)
  .sort();
/** Every package with tests: each top-level directory with a package.json and a vitest config. */
const TESTED = readdirSync(ROOT, { withFileTypes: true })
  .filter((d) => d.isDirectory() && existsSync(path.join(ROOT, d.name, 'package.json'))
    && existsSync(path.join(ROOT, d.name, 'vitest.config.ts')))
  .map((d) => d.name)
  .sort();

/** The values of a one-line YAML list `<key>: [a, b, c]`. */
function yamlList(text: string, key: string): string[] {
  const m = new RegExp(`^\\s+${key}: \\[([^\\]]*)\\]$`, 'm').exec(text);
  return m ? m[1].split(',').map((s) => s.trim()).sort() : [];
}

describe('the CI workflow', () => {
  it('tests every package (red)', () => {
    expect(TESTED).toEqual(expect.arrayContaining(['shared', 'parent', 'verify', ...ENCLAVES]));
    expect(yamlList(read(WORKFLOW), 'package')).toEqual(TESTED);
    const accepted = /^\s+([a-z|-]+)\) ;;$/m.exec(read('scripts/ci/test-package.sh'))?.[1].split('|').sort();
    expect(accepted).toEqual(TESTED);
    for (const pkg of TESTED) {
      const manifest = JSON.parse(read(`${pkg}/package.json`)) as { scripts?: Record<string, string> };
      expect(manifest.scripts?.test, pkg).toBe('vitest run');
    }
  });

  it('runs the determinism gate, with the EIF and its PCR0, for every enclave (red)', () => {
    expect(yamlList(read(WORKFLOW), 'enclave')).toEqual(ENCLAVES);
    expect(read(WORKFLOW)).toContain('run: bash scripts/test-determinism.sh "$ENCLAVE"');
  });

  it("then signs each enclave's EIF with a throwaway certificate, as the deploy is to sign it (P1.6) (red)", () => {
    const workflow = read(WORKFLOW);
    const job = workflow.slice(workflow.indexOf('\n  determinism:'), workflow.indexOf('\n  pcr0-changes:'));
    expect(job.indexOf('run: bash scripts/ci/test-signing.sh "$ENCLAVE"'))
      .toBeGreaterThan(job.indexOf('run: bash scripts/test-determinism.sh "$ENCLAVE"'));
    const script = read('scripts/ci/test-signing.sh');
    expect(script).toContain('openssl ecparam -name secp384r1 -genkey -noout -out "$WORK/key.pem"');
    expect(script).toContain('EIF_SIGNING_KEY="$WORK/key.pem" EIF_SIGNING_CERT="$WORK/cert.pem" \\\n'
      + '  bash "$REPO_DIR/scripts/build-eif.sh" "$ENCLAVE" "$WORK/eif"');
  });

  it('builds the parent image as the deploy builds it (red)', () => {
    expect(read(WORKFLOW)).toContain('run: bash scripts/build-service.sh parent ci');
  });

  it('runs the Rust tests and clippy with warnings as errors, on the committed lock (red)', () => {
    expect(read(WORKFLOW)).toContain('run: bash scripts/ci/test-native.sh');
    const script = read('scripts/ci/test-native.sh');
    expect(script).toContain('\ncargo test --locked\n');
    expect(script).toContain('\ncargo clippy --locked --all-targets -- -D warnings\n');
  });

  it('pins every action by commit, reads with the token, and lets only the PCR0 table comment (red)', () => {
    const workflow = read(WORKFLOW);
    const uses = [...workflow.matchAll(/^\s+- uses: (\S+)/gm)].map((m) => m[1]);
    expect(uses.length).toBeGreaterThan(0);
    for (const use of uses) expect(use).toMatch(/^[\w-]+\/[\w-]+@[0-9a-f]{40}$/);
    expect(workflow).toMatch(/^permissions:\n {2}contents: read\n/m);
    expect(workflow.match(/pull-requests: write/g)).toHaveLength(1);
    expect(workflow).not.toContain('secrets.');
    expect(workflow).not.toContain('pull_request_target');
  });
});
