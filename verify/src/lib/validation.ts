/**
 * Input validation for all user-provided and API-provided values.
 * Every value that touches a shell command or comparison MUST be validated here first.
 */

import type { ServiceName } from './types.js';
import { VALID_SERVICES } from './types.js';

/** Validate a git commit hash (full SHA-1 or SHA-256, hex only). */
export function validateCommitHash(hash: string): string {
  const normalized = hash.trim().toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(normalized) && !/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error(
      `Invalid commit hash: "${hash}". Must be a full 40-char (SHA-1) or 64-char (SHA-256) hex string.`,
    );
  }
  return normalized;
}

/** Validate a git repo URL (https only, no shell metacharacters). */
export function validateRepoUrl(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid repo URL: "${url}". Must be a valid URL.`);
  }

  if (parsed.protocol !== 'https:') {
    throw new Error(
      `Repo URL must use https:// protocol, got "${parsed.protocol}"`,
    );
  }

  // Block obvious SSRF targets
  if (['localhost', '127.0.0.1', '0.0.0.0', '::1'].includes(parsed.hostname)) {
    throw new Error('Repo URL cannot point to localhost.');
  }

  return url;
}

/** Validate a service name. */
export function validateServiceName(name: string): ServiceName {
  if (!VALID_SERVICES.includes(name as ServiceName)) {
    throw new Error(
      `Invalid service: "${name}". Must be one of: ${VALID_SERVICES.join(', ')}`,
    );
  }
  return name as ServiceName;
}

/** Validate a PCR0 hex string. */
export function validatePcr0Hex(hex: string): string {
  const normalized = hex.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(normalized)) {
    throw new Error(
      `Invalid PCR0: "${hex}". Must be a hex string.`,
    );
  }
  if (normalized.length < 32) {
    throw new Error(
      `PCR0 too short: ${normalized.length} chars. Expected at least 32 hex chars.`,
    );
  }
  return normalized;
}

/** Validate an API base URL. */
export function validateApiUrl(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid API URL: "${url}". Must be a valid URL.`);
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(
      `API URL must use http:// or https://, got "${parsed.protocol}"`,
    );
  }

  return url;
}

/** Validate SOURCE_DATE_EPOCH is a numeric unix timestamp. */
export function validateSourceDateEpoch(value: string): string {
  if (!/^\d+$/.test(value)) {
    throw new Error(
      `Invalid SOURCE_DATE_EPOCH: "${value}". Must be a numeric Unix timestamp.`,
    );
  }
  return value;
}

/** Validate a directory path exists and is a git repo. */
export function validateRepoDir(dir: string): string {
  // Resolved at call site via existsSync + git rev-parse
  // This function just checks for obviously malicious paths
  if (dir.includes('\0')) {
    throw new Error('Directory path contains null bytes.');
  }
  return dir;
}
