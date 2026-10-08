/**
 * Portable nitro-cli wrapper — runs nitro-cli inside a Docker container.
 *
 * nitro-cli build-enclave computes EIF measurements mathematically and
 * does NOT need actual Nitro hardware. By running it in an Amazon Linux
 * container with Docker socket mounted, this works on any machine.
 *
 * The helper image is built from THIS package's Dockerfile.nitro-cli (shipped in the package `files`), which pins the
 * base image by digest and nitro-cli by version: an unpinned helper can measure a different PCR0 than the release
 * did. It is built and run for the recipe's platform (linux/amd64) on every host: on an arm64 host (an Apple Silicon
 * Mac) Docker picks the base image's arm64 variant, and that nitro-cli looks for an arm64 image and fails (E48).
 * The helper's tag is a hash of the platform and that file, so a changed pin never reuses a stale local image.
 *
 * SECURITY: All shell commands use execFileSync with argument arrays.
 */

import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { BUILD_RECIPE } from './buildRecipe.js';
import * as report from './report.js';

/** The pinned helper Dockerfile: the package root's Dockerfile.nitro-cli (from src/lib or dist/lib alike). */
export const NITRO_CLI_DOCKERFILE = readFileSync(new URL('../../Dockerfile.nitro-cli', import.meta.url), 'utf-8');

/** The helper image's tag: the first 16 hex of the SHA-256 of `<platform>\n<the pinned Dockerfile>`. */
export const HELPER_IMAGE = `tytle-verify-nitro-cli:${crypto.createHash('sha256')
  .update(`${BUILD_RECIPE.platform}\n${NITRO_CLI_DOCKERFILE}`).digest('hex').slice(0, 16)}`;

/**
 * Get the Docker socket mount path, platform-aware.
 * - Linux/macOS: /var/run/docker.sock
 * - Windows (Docker Desktop): //./pipe/docker_engine (named pipe)
 */
function getDockerSocketMount(): [string, string] {
  if (process.platform === 'win32') {
    return ['//./pipe/docker_engine', '//./pipe/docker_engine'];
  }
  return ['/var/run/docker.sock', '/var/run/docker.sock'];
}

/**
 * Build the nitro-cli helper Docker image (if not already built).
 */
export function ensureNitroCliImage(): void {
  try {
    execFileSync('docker', ['image', 'inspect', HELPER_IMAGE], { stdio: 'pipe' });
    return;
  } catch {
    // Need to build
  }

  report.info('Building nitro-cli helper container (one-time)...');

  // Write the Dockerfile to a temp directory (works with npx, global install, etc.)
  const buildDir = mkdtempSync(path.join(tmpdir(), 'nitro-cli-build-'));
  try {
    writeFileSync(path.join(buildDir, 'Dockerfile'), NITRO_CLI_DOCKERFILE);
    execFileSync('docker', ['build', '--platform', BUILD_RECIPE.platform, '-t', HELPER_IMAGE, buildDir], {
      stdio: 'inherit',
    });
  } finally {
    rmSync(buildDir, { recursive: true, force: true });
  }
}

export interface Pcr0Result {
  pcr0: string;
  pcr1: string;
  pcr2: string;
}

/**
 * The measurements nitro-cli build-enclave prints: after its progress lines, ONE JSON object over several lines
 * ({ "Measurements": { "HashAlgorithm", "PCR0", "PCR1", "PCR2" } }), each PCR a SHA-384 in hex. Until 2026-10 the CLI
 * parsed each line as JSON on its own, so it never found them.
 */
export function parseMeasurements(output: string): Pcr0Result {
  const lines = output.split('\n');
  const start = lines.findIndex((line) => line.startsWith('{'));
  if (start >= 0) {
    let measured: { PCR0?: unknown; PCR1?: unknown; PCR2?: unknown } = {};
    try {
      measured = (JSON.parse(lines.slice(start).join('\n')) as { Measurements?: typeof measured }).Measurements ?? {};
    } catch {
      // Not the measurements object: reported below
    }
    const pcrs = [measured.PCR0, measured.PCR1, measured.PCR2].map((v) => (typeof v === 'string' ? v.toLowerCase() : ''));
    if (pcrs.every((v) => /^[0-9a-f]{96}$/.test(v))) return { pcr0: pcrs[0], pcr1: pcrs[1], pcr2: pcrs[2] };
  }
  throw new Error(
    `Failed to parse PCR0 from nitro-cli output.\n` +
    `Expected JSON with Measurements.PCR0, PCR1 and PCR2 (SHA-384, hex).\n` +
    `Raw output (first 500 chars):\n${output.slice(0, 500)}`,
  );
}

/**
 * Extract PCR0 from a Docker image by building an EIF inside the nitro-cli helper container.
 *
 * @param dockerImageTag - The Docker image to convert to EIF (must already be built locally).
 *                         Expected format: "verify-{service}:{commitPrefix}" — validated by caller.
 * @returns PCR0, PCR1, PCR2 values (lowercase hex)
 */
export function extractPcr0(dockerImageTag: string): Pcr0Result {
  // Validate image tag format: only allow alphanumeric, dash, colon, dot, slash
  if (!/^[a-zA-Z0-9._\-/:]+$/.test(dockerImageTag)) {
    throw new Error(`Invalid Docker image tag: "${dockerImageTag}"`);
  }

  ensureNitroCliImage();

  report.info(`Converting ${dockerImageTag} to EIF and extracting PCR0...`);

  const [hostSocket, containerSocket] = getDockerSocketMount();

  const output = execFileSync('docker', [
    'run', '--rm',
    '--platform', BUILD_RECIPE.platform,
    '-v', `${hostSocket}:${containerSocket}`,
    HELPER_IMAGE,
    'build-enclave',
    '--docker-uri', dockerImageTag,
    // This path is INSIDE the Amazon Linux container (always Linux).
    // Forward slashes are correct regardless of host OS.
    '--output-file', '/tmp/verify.eif',
  ], { encoding: 'utf-8' });

  return parseMeasurements(output);
}
