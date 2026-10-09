/**
 * Docker build orchestration for reproducible enclave builds: the build recipe of scripts/lib/recipe.sh (every
 * service's build.sh, the determinism gate, CI), with the values of ./buildRecipe.ts.
 *
 * SECURITY: All shell commands use execFileSync with argument arrays (not string interpolation)
 * to prevent command injection from user-provided or API-provided inputs.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { ServiceName } from './types.js';
import { validateCommitHash, validateRepoUrl } from './validation.js';
import { BUILD_RECIPE, BUILDER_NAME, assertCommitRecipe, configDigestOf } from './buildRecipe.js';
import * as report from './report.js';

/**
 * Check that Docker is available and responsive.
 */
export function checkDocker(): boolean {
  try {
    execFileSync('docker', ['version'], { stdio: 'pipe', timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Check that Docker buildx is available (the recipe builds on its own docker-container builder).
 */
export function checkBuildx(): boolean {
  try {
    execFileSync('docker', ['buildx', 'version'], { stdio: 'pipe', timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

export interface BuildResult {
  imageTag: string;
  /** The image's config digest (sha256:...), read from the tarball: the same on every Docker image store. */
  imageDigest: string;
  repoDir: string;
  tempDir?: string;
}

/**
 * The pinned BuildKit's builder, made on first use. It is never made the default builder: the user's own builds
 * stay on theirs.
 */
export function ensureBuilder(): void {
  try {
    execFileSync('docker', ['buildx', 'inspect', BUILDER_NAME], { stdio: 'pipe' });
    return;
  } catch {
    // Not made yet
  }
  report.info(`Creating the builder ${BUILDER_NAME} (${BUILD_RECIPE.buildkitImage})...`);
  execFileSync('docker', [
    'buildx', 'create',
    '--name', BUILDER_NAME,
    '--driver', 'docker-container',
    '--driver-opt', `image=${BUILD_RECIPE.buildkitImage}`,
  ], { stdio: 'pipe' });
}

/**
 * Reproduce the enclave Docker build from a specific commit.
 */
export function reproduceBuild(
  service: ServiceName,
  commit: string,
  repoUrl: string,
  existingRepoDir?: string,
): BuildResult {
  // Validate all inputs before touching any shell command
  const safeCommit = validateCommitHash(commit);
  const safeRepoUrl = validateRepoUrl(repoUrl);

  if (!checkBuildx()) {
    throw new Error(
      'docker buildx is required for reproducible builds but was not found. ' +
      'Install Docker Desktop or enable the buildx plugin.',
    );
  }

  let repoDir: string;
  let tempDir: string | undefined;

  if (existingRepoDir) {
    if (!existsSync(existingRepoDir)) {
      throw new Error(`Repo directory does not exist: ${existingRepoDir}`);
    }
    // Verify it's a git repo
    try {
      execFileSync('git', ['rev-parse', '--git-dir'], {
        cwd: existingRepoDir,
        stdio: 'pipe',
      });
    } catch {
      throw new Error(`Not a git repository: ${existingRepoDir}`);
    }
    repoDir = existingRepoDir;
    report.info(`Using existing repo at ${repoDir}`);
  } else {
    tempDir = mkdtempSync(path.join(tmpdir(), 'tytle-verify-'));
    repoDir = path.join(tempDir, 'tytle-enclaves');
    report.info(`Cloning ${safeRepoUrl}...`);
    execFileSync('git', ['clone', '--quiet', safeRepoUrl, repoDir], {
      stdio: 'pipe',
    });
  }

  // Checkout the specific commit
  report.info(`Checking out commit ${safeCommit}...`);
  execFileSync('git', ['checkout', '--quiet', safeCommit], {
    cwd: repoDir,
    stdio: 'pipe',
  });

  // Verify the Dockerfile exists for this service
  const dockerfile = path.join(repoDir, service, 'Dockerfile');
  if (!existsSync(dockerfile)) {
    throw new Error(
      `Dockerfile not found at ${service}/Dockerfile in commit ${safeCommit}. ` +
      `Is "${service}" a valid enclave service at this commit?`,
    );
  }

  // Only the recipe this CLI holds: a commit built another way is refused before anything is built.
  assertCommitRecipe(repoDir, safeCommit);
  ensureBuilder();

  const imageTag = `verify-${service}:${safeCommit.slice(0, 7)}`;
  const imageDir = mkdtempSync(path.join(tmpdir(), 'tytle-verify-image-'));
  const tarPath = path.join(imageDir, 'image.tar');

  try {
    if (tarPath.includes(',')) {
      throw new Error(`The temporary directory has a comma, which --output cannot take: ${tarPath}`);
    }
    report.info(
      `Building ${service} image (${BUILD_RECIPE.platform}, SOURCE_DATE_EPOCH=${BUILD_RECIPE.sourceDateEpoch}, ` +
      `${BUILD_RECIPE.buildkitImage})...`,
    );
    report.info('This may take several minutes on first build.');

    // A docker tarball, not a direct load: Docker's containerd image store (Docker Desktop's default) refuses
    // rewrite-timestamp on a load ("rewrite-timestamp conflicts with unpack").
    execFileSync('docker', [
      'buildx', 'build',
      '--builder', BUILDER_NAME,
      '--platform', BUILD_RECIPE.platform,
      '--provenance=false', '--sbom=false',
      '--output', `type=docker,dest=${tarPath},rewrite-timestamp=true,name=${imageTag}`,
      '-f', `${service}/Dockerfile`,
      '.',
    ], {
      cwd: repoDir,
      stdio: 'inherit',
      env: { ...process.env, SOURCE_DATE_EPOCH: String(BUILD_RECIPE.sourceDateEpoch) },
    });

    const imageDigest = configDigestOf(
      execFileSync('tar', ['-xOf', tarPath, 'manifest.json'], { encoding: 'utf-8' }),
    );
    // nitro-cli reads the image from Docker
    execFileSync('docker', ['load', '-i', tarPath], { stdio: 'pipe' });

    return { imageTag, imageDigest, repoDir, tempDir };
  } finally {
    rmSync(imageDir, { recursive: true, force: true });
  }
}

/**
 * Clean up a temporary repo directory.
 */
export function cleanupTempDir(tempDir: string): void {
  try {
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  } catch {
    // Best-effort cleanup
  }
}
