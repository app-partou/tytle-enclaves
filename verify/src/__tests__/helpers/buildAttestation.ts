/**
 * Test helper: build a structurally valid attestation document.
 *
 * Generates a self-signed P-384 COSE_Sign1 document that mirrors the real
 * Nitro NSM format. It will FAIL certificate chain validation (not signed
 * by AWS Nitro CA) but exercises all other verification logic:
 * - COSE_Sign1 decode
 * - Algorithm validation (ES384 / -35)
 * - Signature verification against leaf cert
 * - Nonce computation + binding
 * - PCR extraction
 */

import crypto from 'node:crypto';
import cbor from 'cbor';

// COSE algorithm ID for ES384
const COSE_ALG_ES384 = -35;

export interface TestAttestationOptions {
  apiEndpoint?: string;
  apiMethod?: string;
  rawResponseBody?: string;
  pcr0?: string;
}

export interface TestAttestation {
  /** Full attestation JSON (CLI-compatible) */
  document: {
    attestationId: string;
    responseHash: string;
    requestHash: string;
    apiEndpoint: string;
    apiMethod: string;
    timestamp: number;
    nsmDocument: string;
    pcrs: { pcr0: string; pcr1: string; pcr2: string };
    nonce: string;
  };
  /** The P-384 private key used for signing (for test assertions) */
  privateKey: crypto.KeyObject;
  /** The leaf certificate (self-signed, DER) */
  leafCertDer: Buffer;
}

/**
 * Build a complete, self-signed attestation document.
 */
export function buildTestAttestation(
  opts: TestAttestationOptions = {},
): TestAttestation {
  const apiEndpoint = opts.apiEndpoint ?? 'ec.europa.eu/taxation_customs/vies/services/checkVatService';
  const apiMethod = opts.apiMethod ?? 'POST';
  const rawResponseBody = opts.rawResponseBody ?? '<soap:Envelope>test response</soap:Envelope>';
  const pcr0Hex = opts.pcr0 ?? 'aa'.repeat(48);

  // Generate a P-384 keypair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-384',
  });

  // Create a self-signed certificate (DER)
  // Node doesn't have createCertificate, so we use a raw X.509 approach via openssl-like structure.
  // For testing, we'll create a minimal self-signed cert using the SubtleCrypto-compatible approach.
  const leafCertDer = createSelfSignedCert(publicKey, privateKey);

  const timestamp = Math.floor(Date.now() / 1000);
  const attestationId = `enc-test-${crypto.randomUUID()}`;

  const responseHash = crypto.createHash('sha256').update(rawResponseBody).digest('hex');
  const requestHash = crypto.createHash('sha256')
    .update(`https://example.com/api|${apiMethod}|{}`)
    .digest('hex');
  const nonce = crypto.createHash('sha256')
    .update(`${responseHash}|${apiEndpoint}|${timestamp}`)
    .digest('hex');

  // Build PCR buffers
  const pcr0 = Buffer.from(pcr0Hex, 'hex');
  const pcr1 = Buffer.alloc(48);
  const pcr2 = Buffer.alloc(48);

  // Build COSE_Sign1
  // Protected headers: { 1: -35 } (alg: ES384)
  const protectedHeaders = cbor.encodeOne(new Map([[1, COSE_ALG_ES384]]));

  // Payload: NSM attestation payload
  const payload = cbor.encodeOne({
    module_id: 'test-enclave-module',
    digest: 'SHA384',
    timestamp: timestamp * 1000, // NSM uses milliseconds
    pcrs: new Map<number, Buffer>([
      [0, pcr0],
      [1, pcr1],
      [2, pcr2],
    ]),
    certificate: leafCertDer,
    cabundle: [], // Empty — will fail chain validation (expected in tests)
    nonce: Buffer.from(nonce, 'hex'),
    user_data: null,
    public_key: null,
  });

  // Sign: Sig_structure = ["Signature1", protectedHeaders, b"", payload]
  const sigStructure = cbor.encodeOne([
    'Signature1',
    protectedHeaders,
    Buffer.alloc(0),
    payload,
  ]);

  const signature = crypto.sign('sha384', sigStructure, {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });

  // Encode as COSE_Sign1 (CBOR Tag 18)
  const coseSign1 = cbor.encodeOne(
    new cbor.Tagged(18, [protectedHeaders, new Map(), payload, signature]),
  );

  const nsmDocument = coseSign1.toString('base64');

  return {
    document: {
      attestationId,
      responseHash,
      requestHash,
      apiEndpoint,
      apiMethod,
      timestamp,
      nsmDocument,
      pcrs: {
        pcr0: pcr0Hex,
        pcr1: '00'.repeat(48),
        pcr2: '00'.repeat(48),
      },
      nonce,
    },
    privateKey,
    leafCertDer,
  };
}

/**
 * Create a minimal self-signed X.509 certificate in DER format.
 *
 * This is a simplified certificate for testing only. It uses Node's
 * createCertificate-like flow via raw ASN.1 building.
 *
 * For Node 20+, we use the experimental X509Certificate generation if available,
 * otherwise fall back to a raw DER construction.
 */
function createSelfSignedCert(
  publicKey: crypto.KeyObject,
  privateKey: crypto.KeyObject,
): Buffer {
  // Export public key as SPKI DER
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });

  // Build a minimal X.509v3 certificate in DER
  // This is a simplified but valid structure for testing
  const serialNumber = crypto.randomBytes(8);
  const now = new Date();
  const notBefore = formatAsn1Time(now);
  const notAfter = formatAsn1Time(new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000));

  // Subject and Issuer: CN=test-nitro-enclave
  const name = buildAsn1Name('test-nitro-enclave');

  // TBSCertificate
  const tbs = buildAsn1Sequence([
    // version [0] EXPLICIT v3
    buildAsn1Explicit(0, buildAsn1Integer(2)),
    // serialNumber
    buildAsn1Integer(serialNumber),
    // signature algorithm: ecdsaWithSHA384 (1.2.840.10045.4.3.3)
    buildAsn1Sequence([asn1Oid([1, 2, 840, 10045, 4, 3, 3])]),
    // issuer
    name,
    // validity
    buildAsn1Sequence([notBefore, notAfter]),
    // subject
    name,
    // subjectPublicKeyInfo (raw SPKI)
    spkiDer,
  ]);

  // Sign the TBS
  const tbsSignature = crypto.sign('sha384', tbs, {
    key: privateKey,
    dsaEncoding: 'der',
  });

  // Full certificate: SEQUENCE { tbs, signatureAlgorithm, signatureValue }
  const cert = buildAsn1Sequence([
    tbs,
    buildAsn1Sequence([asn1Oid([1, 2, 840, 10045, 4, 3, 3])]),
    buildAsn1BitString(tbsSignature),
  ]);

  return cert;
}

// ---- ASN.1 DER helpers ----

function buildAsn1Sequence(items: Buffer[]): Buffer {
  const content = Buffer.concat(items);
  return wrapAsn1(0x30, content);
}

function buildAsn1Integer(value: number | Buffer): Buffer {
  let bytes: Buffer;
  if (Buffer.isBuffer(value)) {
    // Ensure positive (leading zero if high bit set)
    bytes = value[0] & 0x80 ? Buffer.concat([Buffer.from([0]), value]) : value;
  } else {
    bytes = Buffer.from([value]);
  }
  return wrapAsn1(0x02, bytes);
}

function buildAsn1Explicit(tag: number, content: Buffer): Buffer {
  return wrapAsn1(0xa0 | tag, content);
}

function buildAsn1BitString(data: Buffer): Buffer {
  // BitString: first byte is number of unused bits (0)
  return wrapAsn1(0x03, Buffer.concat([Buffer.from([0]), data]));
}

function buildAsn1Name(cn: string): Buffer {
  const cnOid = asn1Oid([2, 5, 4, 3]); // id-at-commonName
  const cnValue = wrapAsn1(0x0c, Buffer.from(cn, 'utf-8')); // UTF8String
  const atv = buildAsn1Sequence([cnOid, cnValue]);
  const rdn = wrapAsn1(0x31, atv); // SET OF AttributeTypeAndValue
  return buildAsn1Sequence([rdn]);
}

function formatAsn1Time(date: Date): Buffer {
  const s = date.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z';
  return wrapAsn1(0x17, Buffer.from(s, 'ascii')); // UTCTime
}

function asn1Oid(components: number[]): Buffer {
  const bytes: number[] = [40 * components[0] + components[1]];
  for (let i = 2; i < components.length; i++) {
    let v = components[i];
    if (v < 128) {
      bytes.push(v);
    } else {
      const enc: number[] = [];
      enc.push(v & 0x7f);
      v >>= 7;
      while (v > 0) {
        enc.push((v & 0x7f) | 0x80);
        v >>= 7;
      }
      bytes.push(...enc.reverse());
    }
  }
  return wrapAsn1(0x06, Buffer.from(bytes));
}

function wrapAsn1(tag: number, content: Buffer): Buffer {
  const len = content.length;
  let header: Buffer;
  if (len < 128) {
    header = Buffer.from([tag, len]);
  } else if (len < 256) {
    header = Buffer.from([tag, 0x81, len]);
  } else if (len < 65536) {
    header = Buffer.from([tag, 0x82, (len >> 8) & 0xff, len & 0xff]);
  } else {
    header = Buffer.from([tag, 0x83, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff]);
  }
  return Buffer.concat([header, content]);
}
