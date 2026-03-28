/**
 * Portable nitro-cli wrapper — runs nitro-cli inside a Docker container.
 *
 * nitro-cli build-enclave computes EIF measurements mathematically and
 * does NOT need actual Nitro hardware. By running it in an Amazon Linux
 * container with Docker socket mounted, this works on any machine.
 *
 * SECURITY: All shell commands use execFileSync with argument arrays.
 */

import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import * as report from './report.js';

const HELPER_IMAGE = 'tytle-verify-nitro-cli:latest';

// Inline Dockerfile so it works regardless of how the package is installed (npx, global, local)
const NITRO_CLI_DOCKERFILE = `FROM amazonlinux:2023
RUN dnf install -y aws-nitro-enclaves-cli && dnf clean all
ENTRYPOINT ["nitro-cli"]
`;

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
    execFileSync('docker', ['build', '-t', HELPER_IMAGE, buildDir], {
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
    '-v', `${hostSocket}:${containerSocket}`,
    HELPER_IMAGE,
    'build-enclave',
    '--docker-uri', dockerImageTag,
    // This path is INSIDE the Amazon Linux container (always Linux).
    // Forward slashes are correct regardless of host OS.
    '--output-file', '/tmp/verify.eif',
  ], { encoding: 'utf-8' });

  // nitro-cli outputs JSON lines. Find the one with Measurements.
  const lines = output.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed.Measurements?.PCR0) {
        return {
          pcr0: parsed.Measurements.PCR0.toLowerCase(),
          pcr1: (parsed.Measurements.PCR1 || '').toLowerCase(),
          pcr2: (parsed.Measurements.PCR2 || '').toLowerCase(),
        };
      }
    } catch {
      // Not valid JSON line, skip
    }
  }

  throw new Error(
    `Failed to parse PCR0 from nitro-cli output.\n` +
    `Expected JSON with Measurements.PCR0.\n` +
    `Raw output (first 500 chars):\n${output.slice(0, 500)}`,
  );
}
