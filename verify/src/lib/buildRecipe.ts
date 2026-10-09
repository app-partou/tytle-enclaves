/**
 * The build recipe of every image of this repository (enclave audit P2.2) - the verify CLI's copy.
 *
 * scripts/lib/recipe.sh builds every image with the values of scripts/build-recipe.json: linux/amd64, a FIXED
 * SOURCE_DATE_EPOCH (so an image, and its PCR0, changes only when what goes into it changes), and a BuildKit pinned
 * by digest, run as its own docker-container builder, exporting to a docker tarball. The CLI never runs that script -
 * a verifier does not run the verified repository's code on their own host - so it holds the same values here, and
 * buildRecipe.drift.test.ts keeps both equal.
 *
 * A commit is rebuilt only when ITS scripts/build-recipe.json is this recipe. A commit before the file was built
 * another way (with its own commit time, on whatever BuildKit the host had), and a later recipe needs the CLI of its
 * time: both are refused, never rebuilt another way.
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';

export interface BuildRecipe {
  version: number;
  platform: string;
  sourceDateEpoch: number;
  buildkitImage: string;
}

export const BUILD_RECIPE: Readonly<BuildRecipe> = Object.freeze({
  version: 2,
  platform: 'linux/amd64',
  sourceDateEpoch: 1767225600, // 2026-01-01T00:00:00Z
  buildkitImage: 'moby/buildkit:v0.27.1@sha256:1e110c71d389d6d24f67b9438e2f7b8da749a6ff407b22a1631e025c95599368',
});

const sha256 = (text: string): string => createHash('sha256').update(text).digest('hex');

/** The pinned BuildKit's builder: one per image, so a changed pin never builds on a builder of the old one. */
export const BUILDER_NAME = `tytle-repro-${sha256(BUILD_RECIPE.buildkitImage).slice(0, 12)}`;

/** Throws unless the checked-out commit in repoDir builds with BUILD_RECIPE (see the file comment). */
export function assertCommitRecipe(repoDir: string, commit: string): void {
  const file = path.join(repoDir, 'scripts', 'build-recipe.json');
  if (!existsSync(file)) {
    throw new Error(
      `Commit ${commit} has no scripts/build-recipe.json: it was built before the fixed build recipe (with its own ` +
      'commit time), so this CLI cannot rebuild it. Use --skip-build for the other checks.',
    );
  }
  const found: unknown = JSON.parse(readFileSync(file, 'utf-8'));
  if (!isDeepStrictEqual(found, BUILD_RECIPE)) {
    throw new Error(
      `Commit ${commit} builds with another recipe than this CLI (${JSON.stringify(found)}): ` +
      'rebuild it with the CLI of that commit.',
    );
  }
}

/** The config digest (sha256:<hex>) of the one image of a docker tarball's manifest.json. */
export function configDigestOf(manifestJson: string): string {
  const manifest: unknown = JSON.parse(manifestJson);
  if (!Array.isArray(manifest) || manifest.length !== 1) {
    throw new Error('The build did not write a docker tarball of one image.');
  }
  const config: unknown = (manifest[0] as { Config?: unknown }).Config;
  const m = typeof config === 'string' ? /^blobs\/sha256\/([0-9a-f]{64})$/.exec(config) : null;
  if (!m) throw new Error('The docker tarball names no config blob blobs/sha256/<digest>.');
  return `sha256:${m[1]}`;
}
