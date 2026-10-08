/**
 * REAL AWS Nitro documents through the CLI, under the EMBEDDED AWS root: nothing is swapped but the network.
 *
 * - fixtures/third-party: two documents AWS produced for another project, which published them as test data (see
 *   that folder's README: source, licence, the SHA-256 of the unchanged bytes). Their signature and chain are AWS's:
 *   four CAs in AWS's order, regional, zonal and instance CAs long expired, a 3-hour leaf. Their nonce and user_data
 *   follow that project's rules, so the two Tytle bindings fail on them by construction.
 * - fixtures/real-<service>-attestation.json: Tytle's own documents, captured at gate G3, the same row files as the
 *   main repository's verifier tests. Each suite is skipped until its file exists.
 *
 * Until 2026-10 the CLI walked the cabundle backwards and judged it at "now": every one of these failed.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import cbor from 'cbor';
import { runVerification, type VerifyOptions } from '../commands/verify.js';
import { getAwsNitroRootCa } from '../lib/certChain.js';
import { verifyCoseSignature } from '../lib/cose.js';
import type { ServiceName } from '../lib/types.js';

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'verify-real-'));
  vi.stubGlobal('fetch', vi.fn(async () => {
    throw new Error('no network in tests');
  }));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  vi.unstubAllGlobals();
});

/** Run the CLI's verification with --skip-build; returns the names of the checks that failed. */
async function failedChecks(document: unknown, options: Partial<VerifyOptions> = {}): Promise<string[]> {
  const file = path.join(dir, 'attestation.json');
  writeFileSync(file, JSON.stringify(document));
  const lines: string[] = [];
  const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    lines.push(args.map(String).join(' ').replace(/\x1b\[[0-9;]*m/g, ''));
  });
  try {
    await runVerification({ service: 'vies', attestation: file, skipBuild: true, ...options });
  } finally {
    spy.mockRestore();
  }
  return lines.flatMap((line) => {
    const m = /^║  \[FAIL\] (.+?) *║$/.exec(line);
    return m ? [m[1]] : [];
  });
}

describe('real AWS documents published by another project', () => {
  interface ThirdParty { sha256: string; documentBase64: string }
  const load = (name: string) => {
    const f = JSON.parse(readFileSync(path.join(FIXTURES, 'third-party', name), 'utf8')) as ThirdParty;
    const bytes = Buffer.from(f.documentBase64, 'base64');
    const cose = cbor.decodeFirstSync(bytes) as unknown[];
    const payload = cbor.decodeFirstSync(cose[2] as Buffer, { preferMap: true }) as Map<string, unknown>;
    const signedMs = Number(payload.get('timestamp'));
    const pcr0 = Buffer.from((payload.get('pcrs') as Map<number, Buffer>).get(0)!).toString('hex');
    /** The CLI's attestation JSON for it: its own nonce and time, so the signed parts are what is tested. */
    const document = (nsmDocument: string = f.documentBase64) => ({
      attestationId: 'third-party',
      responseHash: '0'.repeat(64),
      requestHash: '0'.repeat(64),
      apiEndpoint: 'not-a-tytle-document',
      apiMethod: 'POST',
      timestamp: Math.floor(signedMs / 1000),
      nsmDocument,
      pcrs: { pcr0, pcr1: '', pcr2: '' },
      nonce: Buffer.from(payload.get('nonce') as Buffer).toString('hex'),
    });
    return { f, bytes, payload, signedMs, pcr0, document };
  };
  const NOT_TYTLE = ['Nonce matches recomputed value', 'COSE user_data equals bn254Hash'];

  const release = load('automata-attestation-2.json');
  const debug = load('automata-attestation-1.json');

  it('their bytes are the published ones (lock)', () => {
    expect(crypto.createHash('sha256').update(release.bytes).digest('hex')).toBe(release.f.sha256);
    expect(release.f.sha256).toBe('93c85b9b3d81e2c1310469ad5975a5f09a601e5a700ca7c0602ab1c416cab95f');
    expect(crypto.createHash('sha256').update(debug.bytes).digest('hex')).toBe(debug.f.sha256);
    expect(debug.f.sha256).toBe('0637674127de25b7694e9ccd1d3f6a170e47ca470c266d601f5535afc8832aa4');
  });

  it('the cabundle is in AWS order: the embedded root first, then the regional, zonal and instance CAs (lock)', () => {
    const bundle = (release.payload.get('cabundle') as Buffer[]).map((d) => new crypto.X509Certificate(d));
    expect(bundle[0].fingerprint256).toBe(getAwsNitroRootCa().fingerprint256);
    const cn = (c: crypto.X509Certificate) => c.subject.split('\n').find((l) => l.startsWith('CN='));
    expect(bundle.map(cn)).toEqual([
      'CN=aws.nitro-enclaves',
      'CN=105e7cc00dfb7671.ap-southeast-1.aws.nitro-enclaves',
      'CN=29de1c7c7cc1da1.zonal.ap-southeast-1.aws.nitro-enclaves',
      'CN=i-015531f954c54297c.ap-southeast-1.aws.nitro-enclaves',
    ]);
  });

  it('the signature and the chain verify under the embedded root, judged at the signed time 2023-09-28 (red)', () => {
    const result = verifyCoseSignature(release.f.documentBase64);
    expect(result.signatureValid).toBe(true);
    expect(result.certChainValid).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.chainWarnings).toEqual([]);
    expect(result.payloadTimestampMs).toBe(Date.parse('2023-09-28T11:08:27.117Z'));
  });

  it('through runVerification, only the Tytle bindings fail (red)', async () => {
    expect(await failedChecks(release.document(), { pcr0: release.pcr0 })).toEqual(NOT_TYTLE);
  });

  it('one flipped bit in the signature fails the signature, not the chain (red)', async () => {
    const tampered = Buffer.from(release.bytes);
    tampered[tampered.length - 1] ^= 0x01;       // the signature is the COSE array's last item
    const result = verifyCoseSignature(tampered.toString('base64'));
    expect(result.signatureValid).toBe(false);
    expect(result.certChainValid).toBe(true);
    expect(await failedChecks(release.document(tampered.toString('base64')), { pcr0: release.pcr0 }))
      .toEqual(['COSE_Sign1 signature valid', ...NOT_TYTLE]);
  });

  it('a real debug-mode document (PCR0 all zeroes): its chain verifies, and the run refuses it even when the published PCR0 is the zeroes (red)', async () => {
    expect(debug.pcr0).toBe('0'.repeat(96));
    const result = verifyCoseSignature(debug.f.documentBase64);
    expect(result.signatureValid).toBe(true);
    expect(result.certChainValid).toBe(true);
    expect(await failedChecks(debug.document(), { pcr0: debug.pcr0 }))
      .toEqual(['Enclave ran in release mode (PCR0 not all zeroes)', ...NOT_TYTLE]);
  });
});

// Tytle's own documents (gate G3): the enclave_attestations rows, served to the CLI as the public route serves them
// (ai-agent-server attestationController.ts toAttestationDocument, the full document).
interface AttestationRow {
  attestation_id: string;
  response_hash: string;
  request_hash: string;
  api_endpoint: string;
  api_method: string;
  attestation_timestamp: number;
  nsm_document: string;
  pcr0: string;
  nonce: string;
  bn254_data: string | null;
  bn254_hash: string | null;
  nonce_version?: number | null;
  challenge?: string | null;
}

const CAPTURES: Array<[string, ServiceName]> = [['vies', 'vies'], ['sicae', 'sicae'], ['stripe', 'stripe-payment']];
for (const [fixture, service] of CAPTURES) {
  const file = path.join(FIXTURES, `real-${fixture}-attestation.json`);
  describe.skipIf(!existsSync(file))(`the real ${fixture.toUpperCase()} attestation captured from staging`, () => {
    it('passes every check, with the vector the row stored given by --bn254', async () => {
      const row = JSON.parse(readFileSync(file, 'utf8')) as AttestationRow;
      const document = {
        attestationId: row.attestation_id,
        responseHash: row.response_hash,
        requestHash: row.request_hash,
        apiEndpoint: row.api_endpoint,
        apiMethod: row.api_method,
        timestamp: row.attestation_timestamp,
        nsmDocument: row.nsm_document,
        pcrs: { pcr0: row.pcr0, pcr1: '', pcr2: '' },
        nonce: row.nonce,
        ...(row.bn254_hash ? { bn254Hash: row.bn254_hash } : {}),
        ...(row.nonce_version === 2 ? { nonceVersion: 2, challenge: row.challenge ?? null } : {}),
      };
      const bn254 = row.bn254_data ? path.join(dir, 'vector.b64') : undefined;
      if (bn254 && row.bn254_data) writeFileSync(bn254, row.bn254_data);
      // --pcr0 is the row's own copy: this proves the signed PCR0 is the one stored. The release's published PCR0
      // is the rebuild's question, which these tests skip.
      expect(await failedChecks(document, { service, pcr0: row.pcr0, bn254 })).toEqual([]);
    });
  });
}
