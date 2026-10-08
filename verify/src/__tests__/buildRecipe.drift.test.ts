/**
 * ONE build recipe (enclave audit P2.2). scripts/lib/recipe.sh builds every image of this repository with the values
 * of scripts/build-recipe.json - the deploy (each build.sh), the determinism gate, the PCR0 helper script and CI - and
 * the verify CLI rebuilds with the same values (src/lib/buildRecipe.ts: it never runs the script). Until 2026-10
 * seven places each ran their own `docker buildx build` with SOURCE_DATE_EPOCH = the newest commit's time: every
 * commit, a README edit too, changed every PCR0, so no digest could be committed or checked; the direct load failed on
 * Docker's containerd image store; and each host built on whatever BuildKit it had.
 */

import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { BUILD_RECIPE, BUILDER_NAME } from '../lib/buildRecipe.js';
import { HELPER_IMAGE, parseMeasurements } from '../lib/nitroCli.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const read = (rel: string): string => readFileSync(path.join(ROOT, rel), 'utf8');

const ENCLAVES = readdirSync(ROOT, { withFileTypes: true })
  .filter((d) => d.isDirectory() && existsSync(path.join(ROOT, d.name, 'src/enclave.ts')))
  .map((d) => d.name)
  .sort();

/** scripts/lib/recipe.mjs, the scripts' half (plain JavaScript, so its shape is declared here). */
interface RecipeScripts {
  readRecipe(): unknown;
  builderName(recipe: unknown): string;
  helperTag(platform: string, dockerfile: string): string;
  measurementsOf(stdout: string): unknown;
  readExpected(): Record<string, unknown>;
}
const scripts = async (): Promise<RecipeScripts> =>
  (await import(pathToFileURL(path.join(ROOT, 'scripts/lib/recipe.mjs')).href)) as RecipeScripts;

/** Every shell script of the repository, by its path from the root. */
function shellScripts(dir = ROOT): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name === 'node_modules' || entry.name === '.git') return [];
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return shellScripts(full);
    return entry.name.endsWith('.sh') ? [path.relative(ROOT, full)] : [];
  });
}

describe('one build recipe', () => {
  it('the CLI rebuilds with scripts/build-recipe.json, value for value (red)', async () => {
    expect(BUILD_RECIPE).toEqual((await scripts()).readRecipe());
  });

  it('the recipe: linux/amd64, a fixed time, a BuildKit pinned by digest (red)', async () => {
    expect((await scripts()).readRecipe()).toEqual({
      version: 2,
      platform: 'linux/amd64',
      sourceDateEpoch: expect.any(Number) as number,
      buildkitImage: expect.stringMatching(/^moby\/buildkit:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$/) as string,
    });
  });

  it('the CLI and the scripts name the same builder and measure with the same helper (red)', async () => {
    const recipe = await scripts();
    expect(BUILDER_NAME).toBe(recipe.builderName(recipe.readRecipe()));
    expect(HELPER_IMAGE).toBe(recipe.helperTag('linux/amd64', read('verify/Dockerfile.nitro-cli')));
  });

  it("the CLI and the scripts read nitro-cli's real output alike (red)", async () => {
    const output = read('verify/src/__tests__/fixtures/nitro-cli-1.4.4-build-enclave.stdout.txt');
    expect(parseMeasurements(output)).toEqual((await scripts()).measurementsOf(output));
  });

  it("the shell recipe builds and measures as the CLI does: its builder, platform, tarball and helper (red)", () => {
    const shell = read('scripts/lib/recipe.sh');
    // The builder: its own docker-container builder on the pinned image, made without --use
    expect(shell).toContain('docker buildx create --name "$name" --driver docker-container \\\n'
      + '      --driver-opt "image=$(recipe_value buildkitImage)"');
    expect(shell).not.toMatch(/buildx create[^\n]*--use/);
    // The build: the recipe's time, builder and platform, no attestations, a docker tarball with rewrite-timestamp
    expect(shell).toContain([
      'SOURCE_DATE_EPOCH="$(recipe_value sourceDateEpoch)" docker buildx build \\',
      '    --builder "$builder" \\',
      '    --platform "$(recipe_value platform)" \\',
      '    --provenance=false --sbom=false \\',
      '    --output "type=docker,dest=$out,rewrite-timestamp=true,name=$name" \\',
    ].join('\n'));
    // The helper: built and run for the recipe's platform
    expect(shell).toContain('docker build --platform "$(recipe_value platform)" -t "$tag"');
    expect(shell).toContain('docker run --rm --platform "$(recipe_value platform)"');
  });

  it('no script but scripts/lib/recipe.sh runs a docker build (red)', () => {
    const building = shellScripts().filter((file) => /\bdocker (buildx )?build\b/.test(read(file)));
    expect(building).toEqual(['scripts/lib/recipe.sh']);
  });

  it('every build.sh builds its own service through scripts/build-service.sh (red)', () => {
    for (const service of [...ENCLAVES, 'parent']) {
      expect(read(`${service}/build.sh`), service)
        .toContain(`exec bash "$(cd "$(dirname "$0")/.." && pwd)/scripts/build-service.sh" ${service} "$@"\n`);
    }
  });

  it('scripts/expected-digests.json records the committed build of every enclave (red)', async () => {
    expect(Object.keys((await scripts()).readExpected()).sort()).toEqual(ENCLAVES);
  });

  it('the guide and the README rebuild with the recipe, never with the commit time (red)', () => {
    for (const doc of ['VERIFICATION.md', 'README.md']) {
      const text = read(doc);
      expect(text, doc).not.toContain('git log -1 --pretty=%ct');
      expect(text, doc).toContain(`SOURCE_DATE_EPOCH=${BUILD_RECIPE.sourceDateEpoch}`);
      expect(text, doc).toContain(BUILD_RECIPE.buildkitImage);
      expect(text, doc).toContain('type=docker,dest=');
    }
    // The helper of step 4 is built and run for the recipe's platform
    expect(read('VERIFICATION.md')).toMatch(/docker build --platform linux\/amd64 [^\n]*Dockerfile\.nitro-cli/);
    expect(read('VERIFICATION.md')).toMatch(/docker run --rm --platform linux\/amd64/);
  });
});
