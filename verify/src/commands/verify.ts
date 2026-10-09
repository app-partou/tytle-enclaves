/**
 * End-to-end enclave attestation verification command.
 *
 * Runs all checks sequentially and outputs a final report:
 * 1. Parse attestation document
 * 2. Verify COSE_Sign1 signature + certificate chain at the signed time (establishes trusted PCR0); a debug-mode
 *    enclave (PCR0 all zeroes) fails
 * 3. Verify nonce binding (application nonce == COSE payload nonce; a payload without one fails), the nonce for
 *    the version the document says it signed, and that the document's time agrees with the signed time
 * 4. Verify the data binding: COSE user_data == bn254Hash; with --bn254, the vector's hashes
 * 5. Fetch PCR0 + commit from public API (uses trusted PCR0 for history lookup)
 * 6. Compare PCR0 against API
 * 7. The operator binding: with --signing-cert, PCR8 must be that certificate's (the EIF was signed with it); without
 *    it, PCR8 is reported (lib/signing.ts)
 * 8. Reproduce Docker build (unless --skip-build), always from the repository below
 * 9. Extract PCR0 from reproduced build + compare
 */

import { readFileSync, existsSync } from 'node:fs';
import crypto from 'node:crypto';
import type {
  AttestationDocument,
  CheckResult,
  ServiceName,
} from '../lib/types.js';
import { verifyCoseSignature } from '../lib/cose.js';
import { CHALLENGE_PATTERN, verifyNonce } from '../lib/nonce.js';
import { fetchPcr0Info } from '../lib/pcr0Api.js';
import {
  checkDocker,
  reproduceBuild,
  cleanupTempDir,
} from '../lib/docker.js';
import { extractPcr0 } from '../lib/nitroCli.js';
import * as report from '../lib/report.js';
import { printReport } from '../lib/report.js';
import { isEmptyPcr, pcr8OfCertificate } from '../lib/signing.js';
import { validateSigningCertFile } from '../lib/validation.js';

export interface VerifyOptions {
  service: ServiceName;
  attestation: string; // file path or "-" for stdin
  apiUrl?: string;
  commit?: string;
  repoDir?: string;
  skipBuild?: boolean;
  pcr0?: string; // manual PCR0 override
  /** A file holding the BN254 vector (base64) the data holder received: its hashes are recomputed. */
  bn254?: string;
  /** A file holding the EIF signing certificate (PEM) Tytle publishes: PCR8 must be its. */
  signingCert?: string;
}

/**
 * The source every reproducible build comes from. Hardcoded: the thing being verified never chooses the code it is
 * compared with - the API's `repoUrl` is reported, never used.
 */
export const REPO_URL = 'https://github.com/app-partou/tytle-enclaves';

/**
 * How far the document's own time (the enclave's, in the nonce) may be from the signed NSM time. The same bound as
 * the main repo's verifier; since the 2026-10 enclave release the enclave signs the hypervisor's time, so an honest
 * document is within a second.
 */
const MAX_TIME_DRIFT_MS = 10 * 60 * 1000;

/** SHA-256 (hex) of a BN254 vector, as the enclave puts it in user_data. */
const HEX64 = /^[0-9a-f]{64}$/i;

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

    for (const warning of coseResult.chainWarnings) report.warn(warning);

    // A debug-mode enclave's document carries all-zero PCRs, and the host can read its memory: it proves nothing,
    // whatever PCR0 is published (the same rule as the main repo's verifier).
    const releaseMode = /[1-9a-f]/.test(trustedPcr0);
    checks.push({
      name: 'Enclave ran in release mode (PCR0 not all zeroes)',
      passed: releaseMode,
      detail: releaseMode ? undefined : 'PCR0 is all zeroes: a debug-mode enclave, never trusted',
    });
    if (releaseMode) report.pass('The enclave ran in release mode');
    else report.fail('PCR0 is all zeroes: a debug-mode enclave, never trusted');

    // --- Step 4: Verify nonce binding ---
    // The nonce in the COSE payload (hardware-signed) must match the
    // application-level nonce. This proves the application didn't
    // swap the envelope around a different NSM document.
    report.step(4, 'Verifying nonce');

    const version = attestation.nonceVersion ?? 1;
    const nonceResult = verifyNonce(attestation);

    checks.push({
      name: 'Nonce matches recomputed value',
      passed: nonceResult.valid,
      detail: nonceResult.valid
        ? undefined
        : nonceResult.error ?? `Expected ${nonceResult.expected}, got ${nonceResult.actual}`,
    });

    if (nonceResult.valid) {
      report.pass(version === 2
        ? 'Nonce matches recomputed SHA-256(responseHash|apiEndpoint|timestamp|challenge)'
        : 'Nonce matches recomputed SHA-256(responseHash|apiEndpoint|timestamp)');
    } else {
      report.fail(nonceResult.error ?? `Nonce mismatch: expected ${nonceResult.expected}, got ${nonceResult.actual}`);
    }

    // The COSE payload nonce must match the application nonce. A payload without one binds the document to nothing.
    const nonceBinding = coseResult.payloadNonce !== null && safeEqual(coseResult.payloadNonce, attestation.nonce);
    checks.push({
      name: 'COSE payload nonce matches application nonce',
      passed: nonceBinding,
      detail: nonceBinding
        ? undefined
        : coseResult.payloadNonce === null
          ? 'The NSM payload carries no nonce: the document is not bound to this answer'
          : `COSE payload: ${coseResult.payloadNonce.slice(0, 16)}..., App: ${attestation.nonce.slice(0, 16)}...`,
    });
    if (nonceBinding) {
      report.pass('COSE payload nonce bound to application nonce');
    } else {
      report.fail(coseResult.payloadNonce === null
        ? 'COSE payload carries no nonce'
        : 'COSE payload nonce does NOT match application nonce');
    }

    // The document's own time (in the nonce) must agree with the signed NSM time.
    const timeAgrees = coseResult.payloadTimestampMs !== null
      && Math.abs(coseResult.payloadTimestampMs - attestation.timestamp * 1000) <= MAX_TIME_DRIFT_MS;
    checks.push({
      name: 'Attestation time agrees with the signed NSM time',
      passed: timeAgrees,
      detail: timeAgrees
        ? undefined
        : coseResult.payloadTimestampMs === null
          ? 'The NSM payload carries no valid signed time'
          : `Attestation: ${new Date(attestation.timestamp * 1000).toISOString()}, signed: ${new Date(coseResult.payloadTimestampMs).toISOString()} (at most ${MAX_TIME_DRIFT_MS / 60_000} minutes apart)`,
    });
    if (timeAgrees) report.pass('Attestation time agrees with the signed NSM time');
    else report.fail('Attestation time does not agree with the signed NSM time');

    // --- Step 5: Verify the data binding ---
    // The enclave puts the SHA-256 of its BN254 vector in user_data: what the data holder received is what was signed.
    report.step(5, 'Verifying the data binding (user_data)');

    if (attestation.bn254Hash !== undefined) {
      const bound = coseResult.payloadUserData !== null && safeEqual(coseResult.payloadUserData, attestation.bn254Hash);
      checks.push({
        name: 'COSE user_data equals bn254Hash',
        passed: bound,
        detail: bound ? undefined : `user_data: ${coseResult.payloadUserData ?? 'none'}, bn254Hash: ${attestation.bn254Hash}`,
      });
      if (bound) report.pass('COSE user_data is the bn254Hash');
      else report.fail('COSE user_data is NOT the bn254Hash');
    } else if (coseResult.payloadUserData !== null) {
      checks.push({
        name: 'COSE user_data equals bn254Hash',
        passed: false,
        detail: 'The document carries user_data, but the attestation names no bn254Hash',
      });
      report.fail('The document carries user_data, but the attestation names no bn254Hash');
    } else {
      report.info('No user_data and no bn254Hash: this answer carries no BN254 vector');
    }

    if (options.bn254) {
      // The vector as the data holder received it: base64. The enclave hashes its bytes into user_data
      // (bn254Hash), and its rawBody - the base64 STRING - into responseHash (shared/src/attestor.ts).
      const vectorB64 = readFileSync(options.bn254, 'utf-8').trim();
      const vectorHash = crypto.createHash('sha256').update(Buffer.from(vectorB64, 'base64')).digest('hex');
      const vectorResponseHash = crypto.createHash('sha256').update(vectorB64, 'utf-8').digest('hex');
      const hashOk = attestation.bn254Hash !== undefined && safeEqual(vectorHash, attestation.bn254Hash);
      const responseOk = safeEqual(vectorResponseHash, attestation.responseHash);
      checks.push({
        name: 'bn254Hash is SHA-256 of the vector (--bn254)',
        passed: hashOk,
        detail: hashOk ? undefined : `SHA-256 of the vector: ${vectorHash}, bn254Hash: ${attestation.bn254Hash ?? 'none'}`,
      });
      checks.push({
        name: 'responseHash is SHA-256 of the vector as base64 (--bn254)',
        passed: responseOk,
        detail: responseOk ? undefined : `SHA-256 of the base64: ${vectorResponseHash}, responseHash: ${attestation.responseHash}`,
      });
      if (hashOk && responseOk) report.pass('The vector given with --bn254 is the one signed');
      else report.fail('The vector given with --bn254 is NOT the one signed');
    }

    // --- Step 6: Fetch PCR0 + commit from API ---
    report.step(6, 'Fetching PCR0 and commit from public API');

    let apiPcr0: string | undefined;

    if (options.pcr0) {
      apiPcr0 = options.pcr0.toLowerCase();
      report.info(`Using provided PCR0: ${apiPcr0.slice(0, 16)}...`);
    } else {
      try {
        const pcr0Info = await fetchPcr0Info(options.service, options.apiUrl);
        apiPcr0 = pcr0Info.pcr0.toLowerCase();
        if (pcr0Info.repoUrl && pcr0Info.repoUrl !== REPO_URL) {
          report.warn(`The API names ${pcr0Info.repoUrl} as the source; the build always comes from ${REPO_URL}`);
        }
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

    // --- Step 7: Compare PCR0 against API ---
    report.step(7, 'Comparing PCR0 against published value');

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

    // --- Step 8: The operator binding (PCR8) ---
    // PCR0 says which code ran, wherever it ran. An EIF signed with a certificate boots with PCR8 = that certificate's
    // (lib/signing.ts); an unsigned one with PCR8 all zeroes. The certificate is one the person names: the document
    // never chooses what it is compared with.
    report.step(8, 'Checking the operator binding (PCR8)');

    const trustedPcr8 = coseResult.pcrs.pcr8.toLowerCase();
    const signedEif = !isEmptyPcr(trustedPcr8);
    if (options.signingCert) {
      const certificatePcr8 = pcr8OfCertificate(validateSigningCertFile(options.signingCert));
      const bound = safeEqual(trustedPcr8, certificatePcr8);
      checks.push({
        name: "PCR8 is the signing certificate's (--signing-cert)",
        passed: bound,
        detail: bound
          ? undefined
          : signedEif
            ? `PCR8: ${trustedPcr8.slice(0, 32)}..., the certificate's: ${certificatePcr8.slice(0, 32)}...`
            : 'PCR8 is zero: the EIF that ran was not signed',
      });
      if (bound) report.pass("PCR8 is the signing certificate's: the EIF that ran was signed with it");
      else if (signedEif) report.fail("PCR8 is NOT the signing certificate's: another key signed the EIF that ran");
      else report.fail('PCR8 is zero: the EIF that ran was not signed');
    } else if (signedEif) {
      report.info(`PCR8 ${trustedPcr8.slice(0, 16)}...: a signed EIF. --signing-cert <pem> checks whose key signed it`);
    } else {
      report.info('PCR8 is zero: an unsigned EIF, so the document does not say whose EIF ran');
    }

    // --- Steps 9-10: Reproducible build (optional) ---
    if (!options.skipBuild) {
      report.step(9, 'Reproducing Docker build');

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
            REPO_URL,
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
          report.step(10, 'Extracting and comparing reproduced PCR0');

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

  // Optional fields: present means well-formed.
  if (doc.bn254Hash !== undefined && (typeof doc.bn254Hash !== 'string' || !HEX64.test(doc.bn254Hash))) {
    throw new Error('Attestation field bn254Hash must be 64 hex characters');
  }
  if (doc.nonceVersion !== undefined && doc.nonceVersion !== 1 && doc.nonceVersion !== 2) {
    throw new Error('Attestation field nonceVersion must be 1 or 2');
  }
  if (doc.challenge !== undefined && (typeof doc.challenge !== 'string' || !CHALLENGE_PATTERN.test(doc.challenge))) {
    throw new Error('Attestation field challenge must be 64 lowercase hex characters');
  }

  return doc as unknown as AttestationDocument;
}
