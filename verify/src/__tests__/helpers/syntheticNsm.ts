/**
 * AWS-shaped NSM attestation documents for the CLI tests.
 *
 * A port of the Tytle main repository's packages/attestation-core/src/__tests__/helpers/syntheticNsm.ts over the
 * same committed chains (../fixtures/synthetic-chain, made once by generate.sh), so the CLI and the server-side
 * verifier are tested on documents of one shape: an untagged COSE_Sign1 [protected {1: -35}, {}, payload,
 * signature], a payload map with TEXT keys (module_id, digest, timestamp, pcrs, certificate, cabundle, public_key,
 * user_data, nonce), PCRs as 48-byte digests, the cabundle root first, signed ES384 in IEEE P1363 form over
 * ['Signature1', protected, h'', payload]. It returns the attestation JSON the CLI reads (the `document` of
 * GET /api/attestations/verify/:id) and the BN254 vector as the data holder receives it (the --bn254 file).
 *
 * Every option is a knob for ONE check; the defaults build a document that passes every check under the
 * synthetic root.
 */
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import cbor from 'cbor';
import type { AttestationDocument } from '../../lib/types.js';

const CHAIN_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'synthetic-chain');

/** The instant every synthetic leaf is valid around (11:00Z - 15:00Z), as an enclave's clock would read it. */
export const SIGNED_AT_SEC = Date.UTC(2026, 9, 5, 12, 0, 0) / 1000;

const pem = (file: string) => readFileSync(join(CHAIN_DIR, file), 'utf8');
const der = (name: string) => Buffer.from(new crypto.X509Certificate(pem(`${name}.pem`)).raw);
const key = (name: string) => crypto.createPrivateKey(pem(`${name}-TESTONLY.key.pem`));

export interface SyntheticChain {
  /** The root a test puts where the embedded AWS root is */
  anchorPem: string;
  leafDer: Buffer;
  leafKey: crypto.KeyObject;
  /** As the NSM orders it: root first */
  cabundle: Buffer[];
}

/** Every chain generate.sh made, by the shape it stands for. */
export const CHAINS = {
  /** root-a -> int-a -> leaf-a: the AWS shape */
  main: (): SyntheticChain => ({ anchorPem: pem('root-a.pem'), leafDer: der('leaf-a'), leafKey: key('leaf-a'), cabundle: [der('root-a'), der('int-a')] }),
  /** a leaf signed by the root itself: a one-member cabundle */
  direct: (): SyntheticChain => ({ anchorPem: pem('root-a.pem'), leafDer: der('leaf-a-direct'), leafKey: key('leaf-a-direct'), cabundle: [der('root-a')] }),
  /** an intermediate WITHOUT CA:TRUE (still signed by the root) that signed the leaf */
  intermediateNotCa: (): SyntheticChain => ({ anchorPem: pem('root-a.pem'), leafDer: der('leaf-a-noca'), leafKey: key('leaf-a-noca'), cabundle: [der('root-a'), der('int-a-noca')] }),
  /** a leaf that claims CA:TRUE */
  leafIsCa: (): SyntheticChain => ({ anchorPem: pem('root-a.pem'), leafDer: der('leaf-a-ca'), leafKey: key('leaf-a-ca'), cabundle: [der('root-a'), der('int-a')] }),
  /** an unrelated chain: a valid document under a root that is NOT the pin */
  otherRoot: (): SyntheticChain => ({ anchorPem: pem('root-b.pem'), leafDer: der('leaf-b'), leafKey: key('leaf-b'), cabundle: [der('root-b'), der('int-b')] }),
  /**
   * AWS's real depth: root -> regional -> zonal -> instance -> leaf, a cabundle of four. The zonal CA lives October
   * 2026 and the instance CA only 2026-10-05, the day of the signature (AWS's lower CAs are short-lived too).
   */
  awsDepth: (): SyntheticChain => ({
    anchorPem: pem('root-c.pem'), leafDer: der('leaf-c'), leafKey: key('leaf-c'),
    cabundle: [der('root-c'), der('int-c-regional'), der('int-c-zonal'), der('int-c-instance')],
  }),
  /** the same depth with an instance "CA" that is NOT a CA (still signed by the zonal CA) that signed the leaf */
  awsDepthInstanceNotCa: (): SyntheticChain => ({
    anchorPem: pem('root-c.pem'), leafDer: der('leaf-c-noca'), leafKey: key('leaf-c-noca'),
    cabundle: [der('root-c'), der('int-c-regional'), der('int-c-zonal'), der('int-c-instance-noca')],
  }),
};

export interface DocOptions {
  chain?: SyntheticChain;
  /** The attestation's own time in seconds (the enclave's; inside the nonce). */
  timestampSec?: number;
  /** The hypervisor's signed time, in ms (default: the attestation's time). `null` omits it. */
  payloadTimestampMs?: number | null;
  apiEndpoint?: string;
  alg?: number;
  pcr0?: Buffer;
  omit?: Array<'nonce' | 'user_data'>;
  signWith?: crypto.KeyObject;
  /** NSM user_data (default: the SHA-256 of the vector); `null` = the enclave encoded no BN254 vector. */
  userData?: Buffer | null;
  bn254Bytes?: Buffer;
  /** A caller challenge (64 lowercase hex): the nonce becomes version 2 (enclave audit P1.3). */
  challenge?: string;
}

export interface SyntheticAttestation {
  /** The attestation JSON the CLI reads: the public route's `document`, as an employee gets it. */
  document: AttestationDocument;
  /** The BN254 vector as the data holder receives it: base64, the --bn254 file's content. */
  bn254Base64: string;
}

/** One AWS-shaped document and the attestation JSON the public route serves for it. */
export function buildDoc(o: DocOptions = {}): SyntheticAttestation {
  const chain = o.chain ?? CHAINS.main();
  const timestamp = o.timestampSec ?? SIGNED_AT_SEC;
  const apiEndpoint = o.apiEndpoint ?? 'ec.europa.eu/taxation_customs/vies/services/checkVatService';
  const bn254Bytes = o.bn254Bytes ?? crypto.randomBytes(160);           // the VIES vector: 5 field elements
  const bn254Hash = crypto.createHash('sha256').update(bn254Bytes).digest();
  // As the enclave computes them: responseHash over the base64 vector, the nonce over resp|endpoint|ts[|challenge].
  // Built here on purpose, not with computeNonce: this helper is an independent copy of the enclave's preimage.
  const responseHash = crypto.createHash('sha256').update(bn254Bytes.toString('base64')).digest('hex');
  const preimage = `${responseHash}|${apiEndpoint}|${timestamp}` + (o.challenge === undefined ? '' : `|${o.challenge}`);
  const nonce = crypto.createHash('sha256').update(preimage).digest();

  const pcrs = new Map<number, Buffer>();
  for (let i = 0; i < 16; i++) {
    pcrs.set(i, i === 0 && o.pcr0 ? o.pcr0 : i < 3 ? crypto.randomBytes(48) : Buffer.alloc(48));
  }
  const payload = new Map<string, unknown>([
    ['module_id', 'i-0synthetic0000000-enc0123456789abcdef'],
    ['digest', 'SHA384'],
    ['timestamp', o.payloadTimestampMs === undefined ? timestamp * 1000 : o.payloadTimestampMs],
    ['pcrs', pcrs],
    ['certificate', chain.leafDer],
    ['cabundle', chain.cabundle],
    ['public_key', null],
    ['user_data', o.userData === undefined ? bn254Hash : o.userData],
    ['nonce', nonce],
  ]);
  if (o.payloadTimestampMs === null) payload.delete('timestamp');
  for (const k of o.omit ?? []) payload.delete(k);

  const protectedBytes = cbor.encodeOne(new Map([[1, o.alg ?? -35]]));
  const payloadBytes = cbor.encodeOne(payload);
  const signature = crypto.sign(
    'sha384',
    cbor.encodeCanonical(['Signature1', protectedBytes, Buffer.alloc(0), payloadBytes]),
    { key: o.signWith ?? chain.leafKey, dsaEncoding: 'ieee-p1363' },
  );
  const nsmDocument = cbor.encodeOne([protectedBytes, new Map(), payloadBytes, signature]).toString('base64');

  return {
    document: {
      attestationId: 'enc-synthetic',
      responseHash,
      requestHash: crypto.createHash('sha256').update('request').digest('hex'),
      apiEndpoint,
      apiMethod: 'POST',
      timestamp,
      nsmDocument,
      pcrs: { pcr0: pcrs.get(0)!.toString('hex'), pcr1: '', pcr2: '' },
      nonce: nonce.toString('hex'),
      bn254Hash: bn254Hash.toString('hex'),
      ...(o.challenge === undefined ? {} : { nonceVersion: 2 as const, challenge: o.challenge }),
    },
    bn254Base64: bn254Bytes.toString('base64'),
  };
}
