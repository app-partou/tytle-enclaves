/**
 * Docker build orchestration for reproducible enclave builds.
 * Mirrors the pattern from vies/build.sh, sicae/build.sh, stripe-payment/build.sh.
 *
 * SECURITY: All shell commands use execFileSync with argument arrays (not string interpolation)
 * to prevent command injection from user-provided or API-provided inputs.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { ServiceName } from './types.js';
import {
  validateCommitHash,
  validateRepoUrl,
  validateSourceDateEpoch,
} from './validation.js';
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
 * Check that Docker buildx is available (needed for --output rewrite-timestamp).
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
  imageDigest: string;
  repoDir: string;
  tempDir?: string;
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

  // Get SOURCE_DATE_EPOCH from the commit
  const sourceDate = validateSourceDateEpoch(
    execFileSync('git', ['log', '-1', '--pretty=%ct'], {
      cwd: repoDir,
      encoding: 'utf-8',
    }).trim(),
  );

  const imageTag = `verify-${service}:${safeCommit.slice(0, 7)}`;

  report.info(
    `Building ${service} image (SOURCE_DATE_EPOCH=${sourceDate})...`,
  );
  report.info('This may take several minutes on first build.');

  execFileSync('docker', [
    'buildx', 'build',
    '--output', 'type=docker,rewrite-timestamp=true',
    '--platform', 'linux/amd64',
    '-t', imageTag,
    '-f', `${service}/Dockerfile`,
    '.',
  ], {
    cwd: repoDir,
    stdio: 'inherit',
    env: { ...process.env, SOURCE_DATE_EPOCH: sourceDate },
  });

  const imageDigest = execFileSync('docker', [
    'inspect', '--format={{.Id}}', imageTag,
  ], { encoding: 'utf-8' }).trim();

  return { imageTag, imageDigest, repoDir, tempDir };
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
