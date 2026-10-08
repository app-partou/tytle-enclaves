/**
 * A CMS EnvelopedData writer for tests: what KMS returns as CiphertextForRecipient, sealed to a public key the test
 * names (the fake KMS, fakeKms.ts, seals to the key in the attestation document it is sent). DER, from RFC 5652 §6
 * (EnvelopedData, KeyTransRecipientInfo with a subjectKeyIdentifier), RFC 4055 §4.1 (RSAES-OAEP parameters) and
 * RFC 3565 (AES-CBC). OpenSSL is the independent writer the reader is tested against (fixtures/cms); this one only
 * reaches keys made at test time, and OpenSSL opened its output once (cms.test.ts says how to repeat that).
 */
import crypto from 'node:crypto';

/** One definite-length DER node. */
export function der(tag: number, ...content: Buffer[]): Buffer {
  const body = Buffer.concat(content);
  const length = body.length;
  if (length < 0x80) return Buffer.concat([Buffer.from([tag, length]), body]);
  if (length < 0x100) return Buffer.concat([Buffer.from([tag, 0x81, length]), body]);
  if (length < 0x10000) return Buffer.concat([Buffer.from([tag, 0x82, length >> 8, length & 0xff]), body]);
  throw new Error('cmsWriter: a node longer than 65535 bytes');
}

/** An arc in base 128, high bit set on every byte but the last. */
function base128(arc: number): number[] {
  const out = [arc & 0x7f];
  for (let rest = Math.floor(arc / 128); rest > 0; rest = Math.floor(rest / 128)) out.unshift((rest & 0x7f) | 0x80);
  return out;
}

export function oid(dotted: string): Buffer {
  const arcs = dotted.split('.').map(Number);
  return der(0x06, Buffer.from([...base128(arcs[0] * 40 + arcs[1]), ...arcs.slice(2).flatMap(base128)]));
}

export const seq = (...content: Buffer[]) => der(0x30, ...content);
const set = (...content: Buffer[]) => der(0x31, ...content);
const integer = (value: number) => der(0x02, Buffer.from([value]));
const octets = (bytes: Buffer) => der(0x04, bytes);
export const NULL = Buffer.from([0x05, 0x00]);
export const octetString = octets;

export const CMS_OID = {
  envelopedData: '1.2.840.113549.1.7.3',
  data: '1.2.840.113549.1.7.1',
  rsaesOaep: '1.2.840.113549.1.1.7',
  mgf1: '1.2.840.113549.1.1.8',
  pSpecified: '1.2.840.113549.1.1.9',
  sha256: '2.16.840.1.101.3.4.2.1',
  aes256Cbc: '2.16.840.1.101.3.4.1.42',
} as const;

/** What a test may change in the written structure, to see the reader refuse it (the encryption itself is unchanged). */
export interface SealOptions {
  /** The RSAES-OAEP parameters as written (default: SHA-256 and MGF1 with SHA-256). */
  oaepParams?: Buffer;
  /** The IV as written (default: the IV used). */
  writtenIv?: Buffer;
  /** Write the IV as BER does when it streams: a constructed OCTET STRING of two 8-byte chunks. */
  ivInChunks?: boolean;
  /** The encrypted content as written (default: the secret, encrypted). */
  writtenContent?: Buffer;
  /** The key RSA wraps (default: the AES-256 key the content is encrypted with). */
  wrappedKey?: Buffer;
}

/**
 * The secret, sealed to `publicKey` (an RSA key) the way KMS seals to an attestation document's key: a fresh AES-256
 * key encrypts the secret (CBC), and RSAES-OAEP with SHA-256 and MGF1(SHA-256) wraps that key.
 */
export function sealForRecipient(secret: Buffer, publicKey: crypto.KeyObject, options: SealOptions = {}): Buffer {
  const contentKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', contentKey, iv);
  const encryptedContent = Buffer.concat([cipher.update(secret), cipher.final()]);
  const encryptedKey = crypto.publicEncrypt(
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    options.wrappedKey ?? contentKey,
  );
  // The recipient's key identifier, RFC 5280 §4.2.1.2 method 1: SHA-1 of the subjectPublicKey BIT STRING's value,
  // which for RSA is the RSAPublicKey DER. An identifier only: the reader does not look at it.
  const keyId = crypto.createHash('sha1').update(publicKey.export({ type: 'pkcs1', format: 'der' })).digest();

  const sha256 = seq(oid(CMS_OID.sha256), NULL);
  const oaepParams = options.oaepParams ?? seq(der(0xa0, sha256), der(0xa1, seq(oid(CMS_OID.mgf1), sha256)));
  const recipient = seq(integer(2), der(0x80, keyId), seq(oid(CMS_OID.rsaesOaep), oaepParams), octets(encryptedKey));
  const encryptedContentInfo = seq(oid(CMS_OID.data), seq(oid(CMS_OID.aes256Cbc), options.ivInChunks ? der(0x24, octets(iv.subarray(0, 8)), octets(iv.subarray(8))) : octets(options.writtenIv ?? iv)), der(0x80, options.writtenContent ?? encryptedContent));
  const envelopedData = seq(integer(2), set(recipient), encryptedContentInfo);
  return seq(oid(CMS_OID.envelopedData), der(0xa0, envelopedData));
}
