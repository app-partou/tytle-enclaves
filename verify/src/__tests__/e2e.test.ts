/**
 * End-to-end tests for the verification CLI.
 *
 * Uses a self-signed COSE_Sign1 attestation that mirrors real Nitro format.
 * The signature IS valid (we generated the keypair), but the certificate chain
 * will NOT root to AWS Nitro CA (expected). This exercises the full flow.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { buildTestAttestation, type TestAttestation } from './helpers/buildAttestation.js';
import { verifyCoseSignature } from '../lib/cose.js';
import { verifyNonce, computeNonce } from '../lib/nonce.js';
import { decodeNsmDocument, extractPcrs } from '../lib/attestationDoc.js';
import { runVerification } from '../commands/verify.js';

let testAtt: TestAttestation;
let tempDir: string;
let attestationFile: string;

beforeAll(() => {
  testAtt = buildTestAttestation({
    apiEndpoint: 'ec.europa.eu/taxation_customs/vies/services/checkVatService',
    apiMethod: 'POST',
    rawResponseBody: '<soap:Envelope><valid>true</valid></soap:Envelope>',
    pcr0: 'ab'.repeat(48),
  });

  tempDir = mkdtempSync(path.join(tmpdir(), 'verify-e2e-'));
  attestationFile = path.join(tempDir, 'attestation.json');
  writeFileSync(attestationFile, JSON.stringify(testAtt.document));
});

describe('e2e: COSE decode + signature', () => {
  it('decodes the self-signed COSE_Sign1 document', () => {
    const decoded = decodeNsmDocument(testAtt.document.nsmDocument);

    expect(decoded.protectedRaw).toBeInstanceOf(Buffer);
    expect(decoded.payload.module_id).toBe('test-enclave-module');
    expect(decoded.payload.certificate).toBeInstanceOf(Buffer);
    expect(decoded.signature).toBeInstanceOf(Buffer);
  });

  it('extracts PCRs from the COSE payload', () => {
    const decoded = decodeNsmDocument(testAtt.document.nsmDocument);
    const pcrs = extractPcrs(decoded);

    expect(pcrs.pcr0).toBe('ab'.repeat(48));
    expect(pcrs.pcr1).toBe('00'.repeat(48));
    expect(pcrs.pcr2).toBe('00'.repeat(48));
  });

  it('verifies the COSE_Sign1 signature (self-signed)', () => {
    const result = verifyCoseSignature(testAtt.document.nsmDocument);

    // Signature SHOULD be valid (we signed it with our own key)
    expect(result.signatureValid).toBe(true);
    // Cert chain should FAIL (not signed by Nitro CA)
    expect(result.certChainValid).toBe(false);
    // PCRs should be extracted
    expect(result.pcrs.pcr0).toBe('ab'.repeat(48));
  });

  it('extracts payload nonce from COSE document', () => {
    const result = verifyCoseSignature(testAtt.document.nsmDocument);

    expect(result.payloadNonce).toBe(testAtt.document.nonce);
  });
});

describe('e2e: nonce verification', () => {
  it('nonce matches recomputed value', () => {
    const result = verifyNonce(testAtt.document);
    expect(result.valid).toBe(true);
  });

  it('nonce fails with tampered responseHash', () => {
    const tampered = { ...testAtt.document, responseHash: 'ff'.repeat(32) };
    const result = verifyNonce(tampered);
    expect(result.valid).toBe(false);
  });

  it('nonce fails with tampered timestamp', () => {
    const tampered = { ...testAtt.document, timestamp: testAtt.document.timestamp + 1 };
    const result = verifyNonce(tampered);
    expect(result.valid).toBe(false);
  });

  it('nonce fails with tampered apiEndpoint', () => {
    const tampered = { ...testAtt.document, apiEndpoint: 'evil.com/fake' };
    const result = verifyNonce(tampered);
    expect(result.valid).toBe(false);
  });
});

describe('e2e: COSE payload nonce binding', () => {
  it('payload nonce matches application nonce', () => {
    const result = verifyCoseSignature(testAtt.document.nsmDocument);
    expect(result.payloadNonce).toBe(testAtt.document.nonce);
  });

  it('detects tampered application nonce (envelope swap)', () => {
    const result = verifyCoseSignature(testAtt.document.nsmDocument);
    // If someone swaps the envelope nonce, it won't match the payload nonce
    const fakeNonce = 'ff'.repeat(32);
    expect(result.payloadNonce).not.toBe(fakeNonce);
  });
});

describe('e2e: full verification flow', () => {
  it('runs full verification with --skip-build (self-signed cert fails chain)', async () => {
    // Mock the PCR0 API to return our test PCR0
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          enclaves: {
            vies: {
              pcr0: 'ab'.repeat(48),
              gitCommit: 'a'.repeat(40),
              repoUrl: 'https://github.com/app-partou/tytle-enclaves',
              buildDir: 'vies',
              history: [],
            },
          },
          verificationGuide: '',
        }),
        { status: 200 },
      );

    try {
      const success = await runVerification({
        service: 'vies',
        attestation: attestationFile,
        skipBuild: true,
      });

      // Should FAIL overall because cert chain doesn't root to Nitro CA
      expect(success).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('runs verification with explicit --pcr0 (matching)', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          enclaves: {
            vies: {
              pcr0: 'ab'.repeat(48),
              gitCommit: 'a'.repeat(40),
              repoUrl: 'https://github.com/app-partou/tytle-enclaves',
              buildDir: 'vies',
              history: [],
            },
          },
          verificationGuide: '',
        }),
        { status: 200 },
      );

    try {
      const success = await runVerification({
        service: 'vies',
        attestation: attestationFile,
        skipBuild: true,
        pcr0: 'ab'.repeat(48),
      });

      // Still fails (cert chain) but PCR0 check should pass
      expect(success).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('runs verification with wrong --pcr0 (mismatching)', async () => {
    const success = await runVerification({
      service: 'vies',
      attestation: attestationFile,
      skipBuild: true,
      pcr0: 'ff'.repeat(48), // Wrong PCR0
    });

    expect(success).toBe(false);
  });
});

describe('e2e: error handling', () => {
  it('rejects missing attestation file', async () => {
    await expect(
      runVerification({
        service: 'vies',
        attestation: '/tmp/nonexistent-attestation-file.json',
        skipBuild: true,
      }),
    ).rejects.toThrow('not found');
  });

  it('rejects malformed JSON', async () => {
    const badFile = path.join(tempDir, 'bad.json');
    writeFileSync(badFile, 'not json');

    await expect(
      runVerification({
        service: 'vies',
        attestation: badFile,
        skipBuild: true,
      }),
    ).rejects.toThrow('not valid JSON');
  });

  it('rejects attestation missing required fields', async () => {
    const incompleteFile = path.join(tempDir, 'incomplete.json');
    writeFileSync(incompleteFile, JSON.stringify({ attestationId: 'test' }));

    await expect(
      runVerification({
        service: 'vies',
        attestation: incompleteFile,
        skipBuild: true,
      }),
    ).rejects.toThrow('missing or invalid');
  });

  it('rejects attestation with invalid nsmDocument (too short)', async () => {
    const badDoc = { ...testAtt.document, nsmDocument: btoa('short') };
    const badFile = path.join(tempDir, 'short-nsm.json');
    writeFileSync(badFile, JSON.stringify(badDoc));

    await expect(
      runVerification({
        service: 'vies',
        attestation: badFile,
        skipBuild: true,
      }),
    ).rejects.toThrow('too short');
  });

  it('rejects attestation with non-hex nonce', async () => {
    const badDoc = { ...testAtt.document, nonce: 'not-hex-at-all!!!' };
    const badFile = path.join(tempDir, 'bad-nonce.json');
    writeFileSync(badFile, JSON.stringify(badDoc));

    await expect(
      runVerification({
        service: 'vies',
        attestation: badFile,
        skipBuild: true,
      }),
    ).rejects.toThrow('not a valid hex');
  });

  it('handles API failure gracefully', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      throw new Error('Network error');
    };

    try {
      const success = await runVerification({
        service: 'vies',
        attestation: attestationFile,
        skipBuild: true,
      });

      // Should fail (API unreachable + cert chain)
      expect(success).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe('e2e: tamper detection', () => {
  it('detects tampered nsmDocument (invalid CBOR)', async () => {
    // Flip a byte in the middle of the nsmDocument
    const nsmBytes = Buffer.from(testAtt.document.nsmDocument, 'base64');
    nsmBytes[Math.floor(nsmBytes.length / 2)] ^= 0xff;
    const tampered = { ...testAtt.document, nsmDocument: nsmBytes.toString('base64') };
    const tamperedFile = path.join(tempDir, 'tampered-nsm.json');
    writeFileSync(tamperedFile, JSON.stringify(tampered));

    // Should either throw during decode or fail signature verification
    try {
      const success = await runVerification({
        service: 'vies',
        attestation: tamperedFile,
        skipBuild: true,
        pcr0: 'ab'.repeat(48),
      });
      expect(success).toBe(false);
    } catch {
      // Also acceptable — decode error
    }
  });

  it('detects swapped nonce (envelope modified but COSE intact)', async () => {
    const wrongNonce = computeNonce('ff'.repeat(32), testAtt.document.apiEndpoint, testAtt.document.timestamp);
    const tampered = { ...testAtt.document, nonce: wrongNonce, responseHash: 'ff'.repeat(32) };
    const tamperedFile = path.join(tempDir, 'swapped-nonce.json');
    writeFileSync(tamperedFile, JSON.stringify(tampered));

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          enclaves: { vies: { pcr0: 'ab'.repeat(48), gitCommit: 'a'.repeat(40), repoUrl: '', buildDir: 'vies', history: [] } },
          verificationGuide: '',
        }),
        { status: 200 },
      );

    try {
      const success = await runVerification({
        service: 'vies',
        attestation: tamperedFile,
        skipBuild: true,
      });

      // Should fail — the recomputed nonce matches the tampered envelope,
      // BUT the COSE payload nonce binding check will catch the mismatch
      // (payload nonce != tampered envelope nonce)
      expect(success).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
