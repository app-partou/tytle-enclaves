/**
 * The CLI's rebuild is the recipe's build (enclave audit P2.2; src/lib/buildRecipe.ts, scripts/lib/recipe.sh): the
 * pinned BuildKit as its own builder, linux/amd64, the fixed SOURCE_DATE_EPOCH, a docker tarball with rewrite-timestamp
 * and no attestations; then the config digest read from the tarball and the image loaded for nitro-cli. A commit built
 * another way is refused before anything is built. Until 2026-10 the CLI built with the commit's time on the host's
 * own BuildKit and loaded the image directly, which Docker's containerd image store refuses.
 *
 * The boundary swapped is node:child_process (git, docker, tar). The checked-out repository is a real directory.
 */

import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const CONFIG = 'c'.repeat(64);
const MANIFEST = JSON.stringify([{ Config: `blobs/sha256/${CONFIG}`, RepoTags: ['verify-vies:aaaaaaa'], Layers: [] }]);

interface Call { file: string; args: readonly string[]; env?: NodeJS.ProcessEnv; cwd?: string }
const host = vi.hoisted(() => ({ calls: [] as Call[] }));
vi.mock('node:child_process', () => ({
  execFileSync: (file: string, args: readonly string[], options?: { env?: NodeJS.ProcessEnv; cwd?: string }) => {
    host.calls.push({ file, args, env: options?.env, cwd: options?.cwd });
    if (file === 'docker' && args[0] === 'buildx' && args[1] === 'inspect') throw new Error('no such builder (test)');
    if (file === 'tar') return MANIFEST;
    return '';
  },
}));

import { reproduceBuild } from '../lib/docker.js';
import { BUILD_RECIPE, BUILDER_NAME } from '../lib/buildRecipe.js';
import { REPO_URL } from '../commands/verify.js';

const COMMIT = 'a'.repeat(40);
let repoDir = '';

/** A checked-out commit: vies/Dockerfile and, unless null, scripts/build-recipe.json. */
function checkout(recipe: unknown): void {
  mkdirSync(path.join(repoDir, 'vies'), { recursive: true });
  writeFileSync(path.join(repoDir, 'vies', 'Dockerfile'), 'FROM scratch\n');
  if (recipe !== null) {
    mkdirSync(path.join(repoDir, 'scripts'), { recursive: true });
    writeFileSync(path.join(repoDir, 'scripts', 'build-recipe.json'), JSON.stringify(recipe));
  }
}

const docker = (...head: string[]) =>
  host.calls.filter((c) => c.file === 'docker' && head.every((word, i) => c.args[i] === word));

beforeEach(() => {
  repoDir = mkdtempSync(path.join(tmpdir(), 'verify-recipe-'));
  vi.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
  rmSync(repoDir, { recursive: true, force: true });
  host.calls.length = 0;
  vi.restoreAllMocks();
});

describe("the CLI's rebuild", () => {
  it('builds on the pinned BuildKit for linux/amd64 at the fixed time, into a tarball, without attestations (red)', () => {
    checkout(BUILD_RECIPE);
    reproduceBuild('vies', COMMIT, REPO_URL, repoDir);

    const [build] = docker('buildx', 'build');
    expect(build.args.slice(0, 9)).toEqual([
      'buildx', 'build',
      '--builder', BUILDER_NAME,
      '--platform', 'linux/amd64',
      '--provenance=false', '--sbom=false',
      '--output',
    ]);
    expect(build.args[9]).toMatch(/^type=docker,dest=[^,]+\/image\.tar,rewrite-timestamp=true,name=verify-vies:aaaaaaa$/);
    expect(build.args.slice(10)).toEqual(['-f', 'vies/Dockerfile', '.']);
    expect(build.cwd).toBe(repoDir);
    expect(build.env?.SOURCE_DATE_EPOCH).toBe(String(BUILD_RECIPE.sourceDateEpoch));
  });

  it('makes the pinned builder when it is missing, never as the default builder (red)', () => {
    checkout(BUILD_RECIPE);
    reproduceBuild('vies', COMMIT, REPO_URL, repoDir);

    expect(docker('buildx', 'create').map((c) => c.args)).toEqual([[
      'buildx', 'create',
      '--name', BUILDER_NAME,
      '--driver', 'docker-container',
      '--driver-opt', `image=${BUILD_RECIPE.buildkitImage}`,
    ]]);
  });

  it('reads the config digest from the tarball and loads the image for nitro-cli (red)', () => {
    checkout(BUILD_RECIPE);
    const result = reproduceBuild('vies', COMMIT, REPO_URL, repoDir);

    const tarball = /dest=([^,]+),/.exec(docker('buildx', 'build')[0].args[9])?.[1];
    expect(host.calls.find((c) => c.file === 'tar')?.args).toEqual(['-xOf', tarball, 'manifest.json']);
    expect(docker('load').map((c) => c.args)).toEqual([['load', '-i', tarball]]);
    expect(result).toMatchObject({ imageTag: 'verify-vies:aaaaaaa', imageDigest: `sha256:${CONFIG}` });
  });

  it('refuses a commit without scripts/build-recipe.json before anything is built (red)', () => {
    checkout(null);
    expect(() => reproduceBuild('vies', COMMIT, REPO_URL, repoDir)).toThrow(/has no scripts\/build-recipe\.json/);
    expect(docker('buildx', 'build')).toEqual([]);
  });

  it('refuses a commit with another recipe before anything is built (red)', () => {
    checkout({ ...BUILD_RECIPE, sourceDateEpoch: BUILD_RECIPE.sourceDateEpoch + 1 });
    expect(() => reproduceBuild('vies', COMMIT, REPO_URL, repoDir)).toThrow(/another recipe/);
    expect(docker('buildx', 'build')).toEqual([]);
  });
});
