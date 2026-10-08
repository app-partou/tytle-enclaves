/**
 * The one CMS structure the enclave opens: the EnvelopedData KMS returns as `CiphertextForRecipient` when a Decrypt
 * names this enclave as its Recipient (sealedSecret.ts; enclave audit P1.7). AWS: it "can be decrypted only by using
 * a private key from the attested environment". Its shape, as aws-nitro-enclaves-sdk-c opens it (RFC 5652 §6): ONE
 * KeyTransRecipientInfo whose content key is wrapped with RSAES-OAEP (SHA-256, MGF1 with SHA-256) to the public key
 * of the attestation document, and the secret encrypted with AES-256-CBC under that key.
 *
 * A streaming CMS encoder writes BER - indefinite lengths, the encrypted content in chunks - and a DER-only reader
 * refuses that. So this reads BER as well as DER. It accepts exactly that one pair of algorithms and refuses anything
 * else by name: it never guesses. __tests__/cms.test.ts opens what OpenSSL writes, in DER and in streamed BER.
 */

import crypto from 'node:crypto';

/** A CiphertextForRecipient this enclave cannot open, and why. Never carries a byte of the secret. */
export class CmsError extends Error {
  constructor(message: string) {
    super(`CiphertextForRecipient: ${message}`);
    this.name = 'CmsError';
  }
}

const OID = {
  envelopedData: '1.2.840.113549.1.7.3',
  data: '1.2.840.113549.1.7.1',
  rsaesOaep: '1.2.840.113549.1.1.7',
  mgf1: '1.2.840.113549.1.1.8',
  pSpecified: '1.2.840.113549.1.1.9',
  sha256: '2.16.840.1.101.3.4.2.1',
  aes256Cbc: '2.16.840.1.101.3.4.1.42',
} as const;

const TAG = {
  integer: 0x02,
  octetString: 0x04,
  null: 0x05,
  oid: 0x06,
  sequence: 0x30,
  set: 0x31,
} as const;

/** Nesting deeper than this is not a CMS answer; it is refused before it can exhaust the stack. */
const MAX_DEPTH = 32;

interface Node {
  /** The identifier octet: class, constructed bit and tag number (low-tag-number form only). */
  tag: number;
  constructed: boolean;
  /** A primitive node's content. */
  value: Buffer;
  /** A constructed node's children. */
  children: Node[];
}

/** One BER node at `pos`: definite or indefinite length. Returns the node and the offset after it. */
function readNode(buf: Buffer, pos: number, depth: number): { node: Node; next: number } {
  if (depth > MAX_DEPTH) throw new CmsError(`nested deeper than ${MAX_DEPTH}`);
  if (pos + 2 > buf.length) throw new CmsError('ends inside a header');
  const tag = buf[pos];
  if ((tag & 0x1f) === 0x1f) throw new CmsError('a high tag number (not in this structure)');
  const constructed = (tag & 0x20) !== 0;
  let offset = pos + 1;
  const first = buf[offset++];
  let length: number | null;
  if (first < 0x80) {
    length = first;
  } else if (first === 0x80) {
    if (!constructed) throw new CmsError('an indefinite length on a primitive');
    length = null;
  } else {
    const count = first & 0x7f;
    if (count > 4 || offset + count > buf.length) throw new CmsError('a length it cannot read');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + buf[offset++];
  }

  if (!constructed) {
    if (length === null || offset + length > buf.length) throw new CmsError('ends inside a value');
    return { node: { tag, constructed, value: buf.subarray(offset, offset + length), children: [] }, next: offset + length };
  }

  const children: Node[] = [];
  if (length === null) {
    // Indefinite: children until the end-of-contents octets 00 00
    for (;;) {
      if (offset + 2 > buf.length) throw new CmsError('an indefinite length without its end');
      if (buf[offset] === 0x00 && buf[offset + 1] === 0x00) return { node: { tag, constructed, value: Buffer.alloc(0), children }, next: offset + 2 };
      const { node, next } = readNode(buf, offset, depth + 1);
      children.push(node);
      offset = next;
    }
  }
  const end = offset + length;
  if (end > buf.length) throw new CmsError('ends inside a value');
  while (offset < end) {
    const { node, next } = readNode(buf, offset, depth + 1);
    if (next > end) throw new CmsError('a child runs past its parent');
    children.push(node);
    offset = next;
  }
  return { node: { tag, constructed, value: Buffer.alloc(0), children }, next: end };
}

function expectTag(node: Node | undefined, tag: number, what: string): Node {
  if (!node || node.tag !== tag) throw new CmsError(`expected ${what}`);
  return node;
}

/** An OBJECT IDENTIFIER in dotted form. */
function oidOf(node: Node | undefined, what: string): string {
  const bytes = expectTag(node, TAG.oid, `${what} (an OBJECT IDENTIFIER)`).value;
  if (bytes.length === 0) throw new CmsError(`${what}: an empty OBJECT IDENTIFIER`);
  const arcs: number[] = [];
  let value = 0;
  for (const byte of bytes) {
    value = value * 128 + (byte & 0x7f);
    if (value > Number.MAX_SAFE_INTEGER) throw new CmsError(`${what}: an OBJECT IDENTIFIER arc too large`);
    if ((byte & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  const first = Math.min(Math.floor(arcs[0] / 40), 2);
  return [first, arcs[0] - first * 40, ...arcs.slice(1)].join('.');
}

/** The bytes of an OCTET STRING (or of an IMPLICIT one with another tag): primitive, or constructed in chunks. */
function octetsOf(node: Node): Buffer {
  if (!node.constructed) return node.value;
  return Buffer.concat(node.children.map((child) => octetsAt(child, 'an OCTET STRING chunk')));
}

/** An OCTET STRING's bytes: primitive (04) or, in BER, constructed of chunks (24). */
function octetsAt(node: Node | undefined, what: string): Buffer {
  if (!node || (node.tag !== TAG.octetString && node.tag !== (TAG.octetString | 0x20))) {
    throw new CmsError(`expected ${what} (an OCTET STRING)`);
  }
  return octetsOf(node);
}

/** An AlgorithmIdentifier: its OBJECT IDENTIFIER and its parameters (undefined when absent). */
function algorithmOf(node: Node | undefined, what: string): { oid: string; params?: Node } {
  const seq = expectTag(node, TAG.sequence, `${what} (an AlgorithmIdentifier)`);
  return { oid: oidOf(seq.children[0], what), params: seq.children[1] };
}

/** A SHA-256 AlgorithmIdentifier: the OID, with NULL parameters or none. */
function isSha256(alg: { oid: string; params?: Node }): boolean {
  return alg.oid === OID.sha256 && (alg.params === undefined || (alg.params.tag === TAG.null && alg.params.value.length === 0));
}

/** RSAES-OAEP with SHA-256 and MGF1(SHA-256), and an empty label: KMS's RSAES_OAEP_SHA_256. Nothing else. */
function assertOaepSha256(params: Node | undefined): void {
  const seq = expectTag(params, TAG.sequence, 'RSAES-OAEP parameters');
  let hash = false;
  let mgf = false;
  for (const field of seq.children) {
    const inner = field.children[0];
    if (field.tag === 0xa0) {
      hash = isSha256(algorithmOf(inner, 'the OAEP hash'));
      if (!hash) throw new CmsError('the content key is wrapped with an OAEP hash other than SHA-256');
    } else if (field.tag === 0xa1) {
      const maskGen = algorithmOf(inner, 'the OAEP mask generation');
      mgf = maskGen.oid === OID.mgf1 && isSha256(algorithmOf(maskGen.params, 'the MGF1 hash'));
      if (!mgf) throw new CmsError('the content key is wrapped with a mask generation other than MGF1 with SHA-256');
    } else if (field.tag === 0xa2) {
      const source = algorithmOf(inner, 'the OAEP label source');
      const label = source.params === undefined ? Buffer.alloc(0) : octetsAt(source.params, 'the OAEP label');
      if (source.oid !== OID.pSpecified || label.length > 0) throw new CmsError('the content key is wrapped with an OAEP label');
    } else {
      throw new CmsError('an unknown field in the RSAES-OAEP parameters');
    }
  }
  // Both default to SHA-1 when absent: SHA-1 is not KMS's RSAES_OAEP_SHA_256
  if (!hash || !mgf) throw new CmsError('the content key is wrapped with the default (SHA-1) OAEP parameters');
}

/**
 * The plaintext of a CiphertextForRecipient (a CMS ContentInfo of EnvelopedData, BER or DER), opened with the
 * enclave's RSA private key.
 */
export function openEnvelopedData(cms: Buffer, privateKey: crypto.KeyObject): Buffer {
  const { node: contentInfo, next } = readNode(cms, 0, 0);
  if (next !== cms.length) throw new CmsError('bytes after the structure');
  expectTag(contentInfo, TAG.sequence, 'a ContentInfo');
  if (oidOf(contentInfo.children[0], 'the content type') !== OID.envelopedData) throw new CmsError('not an EnvelopedData');
  const envelope = expectTag(expectTag(contentInfo.children[1], 0xa0, 'the [0] content').children[0], TAG.sequence, 'an EnvelopedData');

  // version, [0] originatorInfo (optional), recipientInfos, encryptedContentInfo, [1] unprotectedAttrs (optional)
  const fields = envelope.children.filter((field) => field.tag !== 0xa0 && field.tag !== 0xa1);
  expectTag(fields[0], TAG.integer, 'the EnvelopedData version');
  const recipients = expectTag(fields[1], TAG.set, 'the RecipientInfos');
  if (recipients.children.length !== 1) throw new CmsError(`${recipients.children.length} recipients, not one`);
  const recipient = recipients.children[0];
  if (recipient.tag !== TAG.sequence) throw new CmsError('a recipient that is not a KeyTransRecipientInfo');
  // version, rid (IssuerAndSerialNumber or [0] SubjectKeyIdentifier), keyEncryptionAlgorithm, encryptedKey
  const keyAlgorithm = algorithmOf(recipient.children[2], 'the key encryption algorithm');
  if (keyAlgorithm.oid !== OID.rsaesOaep) throw new CmsError(`the content key is wrapped with ${keyAlgorithm.oid}, not RSAES-OAEP`);
  assertOaepSha256(keyAlgorithm.params);
  const encryptedKey = octetsAt(recipient.children[3], 'the encrypted key');

  const contentInfoNode = expectTag(fields[2], TAG.sequence, 'the EncryptedContentInfo');
  if (oidOf(contentInfoNode.children[0], 'the encrypted content type') !== OID.data) throw new CmsError('content that is not data');
  const contentAlgorithm = algorithmOf(contentInfoNode.children[1], 'the content encryption algorithm');
  if (contentAlgorithm.oid !== OID.aes256Cbc) {
    throw new CmsError(`the content is encrypted with ${contentAlgorithm.oid}, not AES-256-CBC`);
  }
  const iv = octetsAt(contentAlgorithm.params, 'the AES-256-CBC IV');
  if (iv.length !== 16) throw new CmsError(`an IV of ${iv.length} bytes, not 16`);
  const encryptedContent = contentInfoNode.children[2];
  if (!encryptedContent || (encryptedContent.tag !== 0x80 && encryptedContent.tag !== 0xa0)) {
    throw new CmsError('no encrypted content');
  }

  let contentKey: Buffer;
  try {
    contentKey = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      encryptedKey,
    );
  } catch {
    throw new CmsError('the content key does not open with this enclave\'s private key');
  }
  if (contentKey.length !== 32) throw new CmsError(`a content key of ${contentKey.length} bytes, not 32`);
  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', contentKey, iv);
    return Buffer.concat([decipher.update(octetsOf(encryptedContent)), decipher.final()]);
  } catch {
    throw new CmsError('the content does not decrypt under its key');
  }
}
