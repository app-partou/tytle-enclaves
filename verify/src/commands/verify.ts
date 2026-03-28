/**
 * End-to-end enclave attestation verification command.
 *
 * Runs all checks sequentially and outputs a final report:
 * 1. Parse attestation document
 * 2. Verify COSE_Sign1 signature + certificate chain (establishes trusted PCR0)
 * 3. Verify nonce binding (application nonce == COSE payload nonce)
 * 4. Fetch PCR0 + commit from public API (uses trusted PCR0 for history lookup)
 * 5. Compare PCR0 against API
 * 6. Reproduce Docker build (unless --skip-build)
 * 7. Extract PCR0 from reproduced build + compare
 */

import { readFileSync, existsSync } from 'node:fs';
import crypto from 'node:crypto';
import type {
  AttestationDocument,
  CheckResult,
  ServiceName,
} from '../lib/types.js';
import { verifyCoseSignature } from '../lib/cose.js';
import { verifyNonce } from '../lib/nonce.js';
import { fetchPcr0Info } from '../lib/pcr0Api.js';
import {
  checkDocker,
  reproduceBuild,
  cleanupTempDir,
} from '../lib/docker.js';
import { extractPcr0 } from '../lib/nitroCli.js';
import * as report from '../lib/report.js';
import { printReport } from '../lib/report.js';

export interface VerifyOptions {
  service: ServiceName;
  attestation: string; // file path or "-" for stdin
  apiUrl?: string;
  commit?: string;
  repoDir?: string;
  skipBuild?: boolean;
  pcr0?: string; // manual PCR0 override
}

export async function runVerification(options: VerifyOptions): Promise<boolean> {
  const checks: CheckResult[] = [];
  let commit = options.commit || 'unknown';
  let tempDir: string | undefined;

  // Register signal handlers for cleanup
  const cleanup = () => {
    if (tempDir) cleanupTempDir(tempDir);
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  try {
    // --- Step 1: Parse attestation document ---
    report.step(1, 'Parsing attestation document');

    const attestation = readAttestation(options.attestation);
    report.info(`Attestation ID: ${attestation.attestationId}`);
    report.info(`API endpoint: ${attestation.apiEndpoint}`);
    report.info(
      `Timestamp: ${new Date(attestation.timestamp * 1000).toISOString()}`,
    );

    // --- Step 2: Verify COSE_Sign1 signature + certificate chain ---
    // This MUST happen before the API lookup so we have a trusted PCR0.
    // attestation.pcrs is self-reported; coseResult.pcrs comes from the
    // hardware-signed COSE payload and is trustworthy after signature check.
    report.step(2, 'Verifying COSE_Sign1 signature');

    let coseResult;
    try {
      coseResult = verifyCoseSignature(attestation.nsmDocument);
    } catch (err: any) {
      checks.push({
        name: 'COSE_Sign1 signature valid',
        passed: false,
        detail: `Decode error: ${err.message}`,
      });
      report.fail(`COSE_Sign1 decode error: ${err.message}`);
      printReport(options.service, commit, checks);
      return false;
    }

    checks.push({
      name: 'COSE_Sign1 signature valid',
      passed: coseResult.signatureValid,
      detail: coseResult.signatureValid ? undefined : coseResult.error,
    });

    if (coseResult.signatureValid) {
      report.pass('COSE_Sign1 signature is valid (ES384/P-384)');
    } else {
      report.fail(`COSE_Sign1 signature invalid: ${coseResult.error}`);
    }

    report.step(3, 'Verifying certificate chain');

    checks.push({
      name: 'Certificate chain roots to AWS Nitro CA',
      passed: coseResult.certChainValid,
      detail: coseResult.certChainValid ? undefined : coseResult.error,
    });

    if (coseResult.certChainValid) {
      report.pass('Certificate chain verified to AWS Nitro root CA');
    } else {
      report.fail(`Certificate chain invalid: ${coseResult.error}`);
    }

    // The trusted PCR0 from the hardware-signed COSE payload (normalized to lowercase)
    const trustedPcr0 = coseResult.pcrs.pcr0.toLowerCase();

    // --- Step 3b: Verify nonce binding ---
    // The nonce in the COSE payload (hardware-signed) must match the
    // application-level nonce. This proves the application didn't
    // swap the envelope around a different NSM document.
    report.step(4, 'Verifying nonce');

    const nonceResult = verifyNonce(attestation);

    checks.push({
      name: 'Nonce matches recomputed value',
      passed: nonceResult.valid,
      detail: nonceResult.valid
        ? undefined
        : `Expected ${nonceResult.expected}, got ${nonceResult.actual}`,
    });

    if (nonceResult.valid) {
      report.pass('Nonce matches recomputed SHA-256(responseHash|apiEndpoint|timestamp)');
    } else {
      report.fail(
        `Nonce mismatch: expected ${nonceResult.expected}, got ${nonceResult.actual}`,
      );
    }

    // Verify COSE payload nonce matches the application nonce
    if (coseResult.payloadNonce) {
      const nonceBinding = safeEqual(coseResult.payloadNonce, attestation.nonce);
      checks.push({
        name: 'COSE payload nonce matches application nonce',
        passed: nonceBinding,
        detail: nonceBinding
          ? undefined
          : `COSE payload: ${coseResult.payloadNonce.slice(0, 16)}..., App: ${attestation.nonce.slice(0, 16)}...`,
      });

      if (nonceBinding) {
        report.pass('COSE payload nonce bound to application nonce');
      } else {
        report.fail('COSE payload nonce does NOT match application nonce');
      }
    }

    // --- Step 5: Fetch PCR0 + commit from API ---
    report.step(5, 'Fetching PCR0 and commit from public API');

    let apiPcr0: string | undefined;
    let repoUrl = 'https://github.com/app-partou/tytle-enclaves';

    if (options.pcr0) {
      apiPcr0 = options.pcr0.toLowerCase();
      report.info(`Using provided PCR0: ${apiPcr0.slice(0, 16)}...`);
    } else {
      try {
        const pcr0Info = await fetchPcr0Info(options.service, options.apiUrl);
        apiPcr0 = pcr0Info.pcr0.toLowerCase();
        repoUrl = pcr0Info.repoUrl || repoUrl;
        commit = options.commit || pcr0Info.gitCommit;
        report.info(`Published PCR0: ${apiPcr0.slice(0, 16)}...`);
        report.info(`Published commit: ${commit}`);

        // If the trusted PCR0 doesn't match current, search history
        if (trustedPcr0 !== apiPcr0 && pcr0Info.history?.length) {
          const historyMatch = pcr0Info.history.find(
            (h) => h.pcr0.toLowerCase() === trustedPcr0,
          );
          if (historyMatch) {
            report.info(
              `Attestation PCR0 matches historical entry from ${historyMatch.deployedAt}`,
            );
            apiPcr0 = historyMatch.pcr0.toLowerCase();
            commit = options.commit || historyMatch.gitCommit;
          } else {
            report.warn(
              'Attestation PCR0 does not match current or any historical value',
            );
          }
        }
      } catch (err: any) {
        report.warn(`Failed to fetch from API: ${err.message}`);
        report.warn('Continuing without API comparison');
      }
    }

    // --- Step 6: Compare PCR0 against API ---
    report.step(6, 'Comparing PCR0 against published value');

    if (apiPcr0) {
      const pcr0Match = trustedPcr0 === apiPcr0;
      checks.push({
        name: 'PCR0 matches published value (API)',
        passed: pcr0Match,
        detail: pcr0Match
          ? undefined
          : `Attestation: ${trustedPcr0.slice(0, 32)}..., API: ${apiPcr0.slice(0, 32)}...`,
      });

      if (pcr0Match) {
        report.pass('PCR0 from attestation matches published value');
      } else {
        report.fail(
          `PCR0 mismatch: attestation has ${trustedPcr0.slice(0, 32)}..., API has ${apiPcr0.slice(0, 32)}...`,
        );
      }
    } else {
      checks.push({
        name: 'PCR0 matches published value (API)',
        passed: false,
        detail: 'API unreachable and no --pcr0 provided',
      });
      report.fail('Cannot compare PCR0 — API unreachable and no --pcr0 provided');
    }

    // --- Steps 7-8: Reproducible build (optional) ---
    if (!options.skipBuild) {
      report.step(7, 'Reproducing Docker build');

      if (!checkDocker()) {
        checks.push({
          name: 'Docker build reproduced deterministically',
          passed: false,
          detail: 'Docker not available — install Docker or use --skip-build',
        });
        report.fail('Docker is not available. Install Docker or use --skip-build.');
      } else if (commit === 'unknown') {
        checks.push({
          name: 'Docker build reproduced deterministically',
          passed: false,
          detail: 'No commit hash — provide --commit or ensure API is reachable',
        });
        report.fail(
          'No commit hash available. Provide --commit or ensure API is reachable.',
        );
      } else {
        try {
          const buildResult = reproduceBuild(
            options.service,
            commit,
            repoUrl,
            options.repoDir,
          );
          tempDir = buildResult.tempDir;

          checks.push({
            name: 'Docker build reproduced deterministically',
            passed: true,
            detail: `Image: ${buildResult.imageTag}`,
          });
          report.pass(`Image built: ${buildResult.imageTag}`);

          // Extract PCR0 from reproduced build and compare
          report.step(8, 'Extracting and comparing reproduced PCR0');

          try {
            const buildPcr0 = extractPcr0(buildResult.imageTag);
            const reproduced = buildPcr0.pcr0 === trustedPcr0;

            checks.push({
              name: 'PCR0 from reproduced build matches attestation',
              passed: reproduced,
              detail: reproduced
                ? undefined
                : `Built: ${buildPcr0.pcr0.slice(0, 32)}..., Attestation: ${trustedPcr0.slice(0, 32)}...`,
            });

            if (reproduced) {
              report.pass(
                'Reproduced PCR0 matches attestation — code identity confirmed',
              );
            } else {
              report.fail(
                `Reproduced PCR0 mismatch: built ${buildPcr0.pcr0.slice(0, 32)}..., attestation has ${trustedPcr0.slice(0, 32)}...`,
              );
            }
          } catch (err: any) {
            checks.push({
              name: 'PCR0 from reproduced build matches attestation',
              passed: false,
              detail: `nitro-cli failed: ${err.message}`,
            });
            report.fail(`PCR0 extraction failed: ${err.message}`);
          }
        } catch (err: any) {
          checks.push({
            name: 'Docker build reproduced deterministically',
            passed: false,
            detail: err.message,
          });
          report.fail(`Docker build failed: ${err.message}`);
        }
      }
    } else {
      checks.push({
        name: 'Reproducible build verification',
        passed: true,
        detail: 'Skipped (--skip-build)',
      });
      report.info('Skipping Docker build (--skip-build)');
    }

    // --- Final Report ---
    printReport(options.service, commit, checks);

    return checks.every((c) => c.passed);
  } finally {
    process.removeListener('SIGINT', cleanup);
    process.removeListener('SIGTERM', cleanup);
    cleanup();
  }
}

/** Constant-time hex string comparison. */
function safeEqual(a: string, b: string): boolean {
  try {
    return crypto.timingSafeEqual(
      Buffer.from(a, 'hex'),
      Buffer.from(b, 'hex'),
    );
  } catch {
    return false;
  }
}

function readAttestation(filePath: string): AttestationDocument {
  let raw: string;

  if (filePath === '-') {
    raw = readFileSync(0, 'utf-8');
  } else {
    if (!existsSync(filePath)) {
      throw new Error(`Attestation file not found: ${filePath}`);
    }
    raw = readFileSync(filePath, 'utf-8');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(
      'Attestation file is not valid JSON. Expected a JSON object with attestation fields.',
    );
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Attestation must be a JSON object, not an array or primitive.');
  }

  const doc = parsed as Record<string, unknown>;

  // Validate required fields with type checks
  const stringFields = [
    'attestationId',
    'responseHash',
    'requestHash',
    'apiEndpoint',
    'apiMethod',
    'nsmDocument',
    'nonce',
  ] as const;

  for (const field of stringFields) {
    if (typeof doc[field] !== 'string' || doc[field] === '') {
      throw new Error(
        `Attestation document missing or invalid field: ${field} (expected non-empty string)`,
      );
    }
  }

  if (typeof doc.timestamp !== 'number' || doc.timestamp <= 0) {
    throw new Error(
      'Attestation document missing or invalid field: timestamp (expected positive number)',
    );
  }

  const pcrs = doc.pcrs as Record<string, unknown> | undefined;
  if (
    !pcrs ||
    typeof pcrs !== 'object' ||
    typeof pcrs.pcr0 !== 'string' ||
    pcrs.pcr0 === ''
  ) {
    throw new Error('Attestation document missing or invalid field: pcrs.pcr0');
  }

  // Validate nsmDocument is plausible base64 with sane bounds
  const nsmDoc = doc.nsmDocument as string;
  const decodedLength = Math.floor((nsmDoc.length * 3) / 4);
  if (decodedLength < 100) {
    throw new Error(
      'Attestation field nsmDocument is too short to be a valid COSE_Sign1 document',
    );
  }
  if (decodedLength > 1_048_576) {
    throw new Error(
      'Attestation field nsmDocument exceeds 1MB — likely not a valid attestation',
    );
  }

  // Validate nonce looks like a hex string
  const nonce = doc.nonce as string;
  if (!/^[0-9a-f]+$/i.test(nonce)) {
    throw new Error(
      'Attestation field nonce is not a valid hex string',
    );
  }

  return doc as unknown as AttestationDocument;
}
