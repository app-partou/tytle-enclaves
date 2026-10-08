#!/usr/bin/env node
/**
 * CI: the PCR0 changes of a pull request (enclave audit P2.2; .github/workflows/ci.yml). It compares
 * scripts/expected-digests.json at the base with the one at HEAD - the determinism gate has already checked that
 * HEAD's record is what the code builds - and writes a markdown table of every enclave whose PCR0 changes.
 *
 * It fails when an enclave's PCR0 changes and the pull request changes none of that enclave's inputs: something
 * outside the list below changed an image, or the record was edited by hand.
 *
 *   node scripts/ci/pcr0-changes.mjs <base-commit> <markdown-file>
 * prints the number of enclaves whose PCR0 changes; exit 1 = a change no input explains.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const RECORD = 'scripts/expected-digests.json';

/**
 * What goes into every enclave image and its PCR0, besides the enclave's own directory: the code every image holds
 * (shared/, native/, the vendored packages of deps/), how it is built (the recipe; a root .dockerignore would filter
 * the build context) and what measures it (the nitro-cli helper: its version is in every PCR0).
 */
export const COMMON_INPUTS = [
  'shared/',
  'native/',
  'deps/',
  'scripts/build-recipe.json',
  'scripts/lib/',
  '.dockerignore',
  'verify/Dockerfile.nitro-cli',
];

export const inputsOf = (service) => [`${service}/`, ...COMMON_INPUTS];

const isInput = (file, input) => (input.endsWith('/') ? file.startsWith(input) : file === input);

/**
 * The enclaves whose PCR0 differs between two records, each with whether a changed file is one of its inputs.
 * An enclave new in the head record, or gone from it, is a change too.
 */
export function pcr0Changes(baseRecord, headRecord, changedFiles) {
  const services = [...new Set([...Object.keys(baseRecord), ...Object.keys(headRecord)])].sort();
  return services
    .map((service) => ({
      service,
      before: baseRecord[service]?.pcr0 ?? null,
      after: headRecord[service]?.pcr0 ?? null,
    }))
    .filter(({ before, after }) => before !== after)
    .map((change) => ({
      ...change,
      inputs: changedFiles.filter((file) => inputsOf(change.service).some((input) => isInput(file, input))),
    }));
}

const short = (pcr0) => (pcr0 === null ? '(none)' : `\`${pcr0.slice(0, 16)}...\``);

/** The table for the job summary and the comment. */
export function markdown(changes) {
  if (changes.length === 0) return '### PCR0\n\nNo enclave\'s PCR0 changes.\n';
  const rows = changes.map(({ service, before, after, inputs }) =>
    `| ${service} | ${short(before)} | ${short(after)} | ${inputs.length > 0 ? `${inputs.length} changed` : '**NONE - fails**'} |`);
  return [
    '### PCR0 changes',
    '',
    'Each enclave below runs new code after this pull request: its new PCR0 must be published (SSM) and allowed',
    'before its image is deployed. The full values are in `scripts/expected-digests.json`.',
    '',
    '| Enclave | PCR0 before | PCR0 after | Its inputs |',
    '|---|---|---|---|',
    ...rows,
    '',
  ].join('\n');
}

function recordAt(commit) {
  // The base must be in the checkout (fetch-depth: 0): a missing commit is an error, never "no record"
  execFileSync('git', ['cat-file', '-e', `${commit}^{commit}`], { cwd: ROOT, stdio: 'pipe' });
  let text;
  try {
    text = execFileSync('git', ['show', `${commit}:${RECORD}`], { cwd: ROOT, encoding: 'utf8', stdio: 'pipe' });
  } catch {
    return {}; // the base has no record yet: every enclave of the head is a change
  }
  return JSON.parse(text);
}

function main([base, out]) {
  if (!/^[0-9a-f]{40}$/.test(base ?? '') || !out) {
    throw new Error('usage: pcr0-changes.mjs <base-commit (40 hex)> <markdown-file>');
  }
  const changedFiles = execFileSync('git', ['diff', '--name-only', base, 'HEAD'], { cwd: ROOT, encoding: 'utf8' })
    .split('\n').filter(Boolean);
  const changes = pcr0Changes(recordAt(base), JSON.parse(readFileSync(path.join(ROOT, RECORD), 'utf8')), changedFiles);
  writeFileSync(out, markdown(changes));
  process.stdout.write(`${changes.length}\n`);
  const unexplained = changes.filter((change) => change.inputs.length === 0).map((change) => change.service);
  if (unexplained.length > 0) {
    process.stderr.write(`The PCR0 of ${unexplained.join(', ')} changes, and none of its inputs did.\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`pcr0-changes.mjs: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  }
}
