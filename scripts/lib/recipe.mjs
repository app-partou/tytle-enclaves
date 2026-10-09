#!/usr/bin/env node
/**
 * The data half of the build recipe (scripts/lib/recipe.sh is the shell half, and the only caller): it reads
 * scripts/build-recipe.json, scripts/expected-digests.json and what docker and nitro-cli print. Each command prints
 * one value or fails with exit 1 - it never guesses.
 *
 *   node recipe.mjs value <key>                 one value of scripts/build-recipe.json
 *   node recipe.mjs builder-name                the pinned BuildKit's builder: tytle-repro-<12 hex of its image>
 *   node recipe.mjs helper-tag                  the nitro-cli helper's tag, as the verify CLI computes it
 *   node recipe.mjs config-digest  < manifest   the config digest of a docker tarball's one image
 *   node recipe.mjs image-name     < manifest   the one name of a docker tarball's one image
 *   node recipe.mjs measurements   < stdout     the {pcr0, pcr1, pcr2, and pcr8 when signed} of nitro-cli build-enclave
 *   node recipe.mjs pcr0           < json       the pcr0 of a measurements object
 *   node recipe.mjs signing-check <cert> <key>  refuse a signing certificate that is not P-384, is not the key's, or
 *                                               ends within 60 days; print the PCR8 an EIF it signs carries
 *   node recipe.mjs pcr8-is <hex>  < json       fail unless the measurements carry that PCR8
 *   node recipe.mjs check  <service> <digest> < measurements    the build against scripts/expected-digests.json
 *   node recipe.mjs record <service> <digest> < measurements    the build INTO scripts/expected-digests.json
 *   node recipe.mjs eif-measurements <service> <digest> < measurements    what build-eif.sh writes next to an EIF
 *
 * The verify CLI holds the same rules in TypeScript (verify/src/lib/buildRecipe.ts, nitroCli.ts): it never runs code
 * of the repository it verifies on its host. verify's buildRecipe.drift.test.ts runs both on the same inputs.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { X509Certificate, createHash, createPrivateKey } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const RECIPE_KEYS = ['buildkitImage', 'platform', 'sourceDateEpoch', 'version'];
const SHA384_HEX = /^[0-9a-f]{96}$/;
const CONFIG_DIGEST = /^sha256:[0-9a-f]{64}$/;

const sha256 = (text) => createHash('sha256').update(text).digest('hex');

/** scripts/build-recipe.json, every key present and of its one shape. */
export function readRecipe(root = ROOT) {
  const recipe = JSON.parse(readFileSync(path.join(root, 'scripts/build-recipe.json'), 'utf8'));
  const problems = [];
  if (Object.keys(recipe).sort().join() !== RECIPE_KEYS.join()) problems.push(`its keys are ${RECIPE_KEYS.join(', ')}`);
  if (recipe.version !== 2) problems.push('version is 2 (the fixed time, the pinned BuildKit, the tarball)');
  if (recipe.platform !== 'linux/amd64') problems.push('platform is linux/amd64, what a Nitro host runs');
  if (!Number.isSafeInteger(recipe.sourceDateEpoch) || recipe.sourceDateEpoch <= 0) {
    problems.push('sourceDateEpoch is a positive whole number of seconds');
  }
  if (!/^moby\/buildkit:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$/.test(recipe.buildkitImage)) {
    problems.push('buildkitImage is moby/buildkit:v<x.y.z>@sha256:<digest>');
  }
  if (problems.length > 0) throw new Error(`scripts/build-recipe.json: ${problems.join('; ')}`);
  return recipe;
}

/** The pinned BuildKit's builder, one per image: a changed pin never builds on a builder of the old one. */
export const builderName = (recipe) => `tytle-repro-${sha256(recipe.buildkitImage).slice(0, 12)}`;

/** The nitro-cli helper's tag (the verify CLI's HELPER_IMAGE): a hash of its platform and its pinned Dockerfile. */
export const helperTag = (platform, dockerfile) =>
  `tytle-verify-nitro-cli:${sha256(`${platform}\n${dockerfile}`).slice(0, 16)}`;

/** The one image of a docker tarball's manifest.json. */
function oneImage(manifestJson) {
  const manifest = JSON.parse(manifestJson);
  if (!Array.isArray(manifest) || manifest.length !== 1) {
    throw new Error(`a docker tarball of one image, not ${Array.isArray(manifest) ? manifest.length : 'a non-list'}`);
  }
  return manifest[0];
}

/** The image's config digest: the image id on Docker's classic store, and the same on every store. */
export function configDigestOf(manifestJson) {
  const m = /^blobs\/sha256\/([0-9a-f]{64})$/.exec(String(oneImage(manifestJson).Config));
  if (!m) throw new Error('the tarball names no config blob blobs/sha256/<digest>');
  return `sha256:${m[1]}`;
}

/** The one name the recipe gave the image (its output's name=...). */
export function imageNameOf(manifestJson) {
  const tags = oneImage(manifestJson).RepoTags;
  if (!Array.isArray(tags) || tags.length !== 1) throw new Error('the tarball names its image once');
  return tags[0];
}

/**
 * The EIF measurements of nitro-cli build-enclave: after its progress lines it prints ONE JSON object over several
 * lines ({ "Measurements": { "HashAlgorithm", "PCR0", "PCR1", "PCR2" } }). Each PCR is a SHA-384, in hex.
 */
export function measurementsOf(stdout) {
  const lines = stdout.split('\n');
  const start = lines.findIndex((line) => line.startsWith('{'));
  if (start < 0) throw new Error('nitro-cli printed no measurements');
  const measured = JSON.parse(lines.slice(start).join('\n')).Measurements ?? {};
  const pcrs = { pcr0: measured.PCR0, pcr1: measured.PCR1, pcr2: measured.PCR2 };
  if (measured.PCR8 !== undefined) pcrs.pcr8 = measured.PCR8; // a signed EIF only
  for (const [name, value] of Object.entries(pcrs)) {
    if (typeof value !== 'string' || !SHA384_HEX.test(value.toLowerCase())) {
      throw new Error(`nitro-cli printed no ${name.toUpperCase()} (a SHA-384 in hex)`);
    }
    pcrs[name] = value.toLowerCase();
  }
  return pcrs;
}

/** A measurements object (what `measurements` prints), checked. */
function pcrsOf(measurementsJson) {
  const { pcr0, pcr1, pcr2 } = JSON.parse(measurementsJson);
  for (const value of [pcr0, pcr1, pcr2]) {
    if (typeof value !== 'string' || !SHA384_HEX.test(value)) throw new Error('not a measurements object');
  }
  return { pcr0, pcr1, pcr2 };
}

/**
 * How long a signing certificate must still be valid when it signs. An EIF whose certificate has expired does not start
 * (nitro-cli run-enclave fails with E36, E39 and E11), so each restart of it on the host would fail too.
 */
export const SIGNING_CERT_MIN_DAYS = 60;

/**
 * The PCR8 of an EIF signed with this certificate: the register starts at 48 zero bytes and is extended once with the
 * SHA-384 of the certificate's DER - SHA-384(0x00 * 48 || SHA-384(DER)). Not SHA-384(0x00 * 48 || DER): an extend
 * takes the digest. Checked against the PCR8 nitro-cli 1.4.4 printed for a signed build (verify's fixtures).
 */
export function pcr8Of(certPem) {
  const digest = createHash('sha384').update(new X509Certificate(certPem).raw).digest();
  return createHash('sha384').update(Buffer.concat([Buffer.alloc(48), digest])).digest('hex');
}

/** The signing certificate and its key, checked before anything is signed; returns the PCR8 the EIF will carry. */
export function signingCheck(certPem, keyPem, now = new Date()) {
  const cert = new X509Certificate(certPem);
  const problems = [];
  const { asymmetricKeyType } = cert.publicKey;
  if (asymmetricKeyType !== 'ec' || cert.publicKey.asymmetricKeyDetails?.namedCurve !== 'secp384r1') {
    problems.push('its key is not EC P-384');
  }
  let ownKey = false;
  try { ownKey = cert.checkPrivateKey(createPrivateKey(keyPem)); } catch { ownKey = false; }
  if (!ownKey) problems.push('the private key is not its key');
  const validFrom = new Date(cert.validFrom);
  const validTo = new Date(cert.validTo);
  if (validFrom > now) problems.push(`it is not valid before ${validFrom.toISOString()}`);
  const daysLeft = Math.floor((validTo.getTime() - now.getTime()) / 86_400_000);
  if (daysLeft < SIGNING_CERT_MIN_DAYS) {
    problems.push(`it ends ${validTo.toISOString()}, ${daysLeft} days from now (at least ${SIGNING_CERT_MIN_DAYS})`);
  }
  if (problems.length > 0) throw new Error(`the signing certificate ${cert.subject}: ${problems.join('; ')}`);
  return pcr8Of(certPem);
}

/** One build's record: its config digest and its measurements. */
function entryOf(digest, measurementsJson) {
  if (!CONFIG_DIGEST.test(digest)) throw new Error(`not a config digest: "${digest}"`);
  return { imageConfigDigest: digest, ...pcrsOf(measurementsJson) };
}

/** What scripts/build-eif.sh writes next to an EIF: the enclave, its build's record, and PCR8 when it is signed. */
export function eifMeasurementsOf(service, digest, measurementsJson) {
  const { pcr8 } = JSON.parse(measurementsJson);
  if (pcr8 !== undefined && (typeof pcr8 !== 'string' || !SHA384_HEX.test(pcr8))) {
    throw new Error('not a measurements object');
  }
  return { enclave: service, ...entryOf(digest, measurementsJson), ...(pcr8 === undefined ? {} : { pcr8 }) };
}

const EXPECTED = (root) => path.join(root, 'scripts/expected-digests.json');
const ENTRY_KEYS = ['imageConfigDigest', 'pcr0', 'pcr1', 'pcr2'];

/** scripts/expected-digests.json: service -> the record of its committed build, every record of the one shape. */
export function readExpected(root = ROOT) {
  const all = JSON.parse(readFileSync(EXPECTED(root), 'utf8'));
  for (const [service, entry] of Object.entries(all)) {
    const shaped = Object.keys(entry).sort().join() === ENTRY_KEYS.join()
      && CONFIG_DIGEST.test(entry.imageConfigDigest)
      && [entry.pcr0, entry.pcr1, entry.pcr2].every((value) => SHA384_HEX.test(value));
    if (!shaped) throw new Error(`scripts/expected-digests.json: the record of ${service} is not {${ENTRY_KEYS.join(', ')}}`);
  }
  return all;
}

/** What differs between the committed record and this build ([] = the same image, the same PCRs). */
export function differences(expected, built) {
  if (!expected) return ['no committed record'];
  return Object.keys(built).filter((key) => expected[key] !== built[key])
    .map((key) => `${key}: committed ${expected[key] ?? '(none)'}, built ${built[key]}`);
}

function record(root, service, entry) {
  let all = {};
  try { all = readExpected(root); } catch (err) { if (err.code !== 'ENOENT') throw err; }
  all[service] = entry;
  const sorted = Object.fromEntries(Object.keys(all).sort().map((key) => [key, all[key]]));
  writeFileSync(EXPECTED(root), `${JSON.stringify(sorted, null, 2)}\n`);
}

function main([command, ...args]) {
  const stdin = () => readFileSync(0, 'utf8');
  switch (command) {
    case 'value': {
      const recipe = readRecipe();
      if (!RECIPE_KEYS.includes(args[0])) throw new Error(`build-recipe.json has no key "${args[0]}"`);
      return String(recipe[args[0]]);
    }
    case 'builder-name': return builderName(readRecipe());
    case 'helper-tag':
      return helperTag(readRecipe().platform, readFileSync(path.join(ROOT, 'verify/Dockerfile.nitro-cli'), 'utf8'));
    case 'config-digest': return configDigestOf(stdin());
    case 'image-name': return imageNameOf(stdin());
    case 'measurements': return JSON.stringify(measurementsOf(stdin()));
    case 'pcr0': return pcrsOf(stdin()).pcr0;
    case 'signing-check': return signingCheck(readFileSync(args[0], 'utf8'), readFileSync(args[1], 'utf8'));
    case 'pcr8-is': {
      const { pcr8 } = JSON.parse(stdin());
      if (pcr8 !== args[0]) {
        throw new Error(`the EIF carries PCR8 ${pcr8 ?? '(none: it is unsigned)'}, not the certificate's ${args[0]}`);
      }
      return pcr8;
    }
    case 'check': {
      const [service, digest] = args;
      const found = differences(readExpected()[service], entryOf(digest, stdin()));
      if (found.length > 0) {
        throw new Error(`${service} is not the committed build (run scripts/test-determinism.sh --update ${service} `
          + `and commit scripts/expected-digests.json if the change is meant):\n  ${found.join('\n  ')}`);
      }
      return `${service}: the committed build (${digest})`;
    }
    case 'record': {
      const [service, digest] = args;
      record(ROOT, service, entryOf(digest, stdin()));
      return `${service}: recorded in scripts/expected-digests.json`;
    }
    case 'eif-measurements': return JSON.stringify(eifMeasurementsOf(args[0], args[1], stdin()), null, 2);
    default: throw new Error(`unknown command "${command}"`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    process.stdout.write(`${main(process.argv.slice(2))}\n`);
  } catch (err) {
    process.stderr.write(`recipe.mjs: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  }
}
