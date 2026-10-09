/**
 * The CMS reader (cms.ts, enclave audit P1.7) that opens KMS's CiphertextForRecipient. The independent writer is
 * OpenSSL: fixtures/cms holds what `openssl cms -encrypt` wrote (generate.sh says how), in DER and in streamed BER,
 * with KMS's pair of algorithms and with each pair the reader must refuse. The test writer (helpers/cmsWriter.ts, the
 * fake KMS's) is checked here too; OpenSSL opened its output once (2026-10-08: `openssl cms -decrypt -binary -inform
 * DER -in <file> -inkey recipient-TESTONLY.key.pem -recip recipient.pem`, after sealing to recipient.pem's key).
 * Nothing is mocked: the reader is a pure function.
 *
 * Labels: "red" = fails on the release before this one (it had no reader).
 */
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { openEnvelopedData, CmsError } from '../cms.js';
import { sealForRecipient, der, oid, seq, NULL, octetString, CMS_OID } from './helpers/cmsWriter.js';

const fixture = (name: string) => readFileSync(new URL(`./fixtures/cms/${name}`, import.meta.url));
const RECIPIENT = crypto.createPrivateKey(fixture('recipient-TESTONLY.key.pem'));
const OTHER = crypto.createPrivateKey(fixture('other-TESTONLY.key.pem'));
const RECIPIENT_PUBLIC = crypto.createPublicKey(fixture('recipient.pem'));
const SECRET = fixture('secret.txt').toString('utf-8');

function refusal(cms: Buffer, key: crypto.KeyObject = RECIPIENT): string {
  try {
    openEnvelopedData(cms, key);
  } catch (err) {
    expect(err).toBeInstanceOf(CmsError);
    return (err as Error).message;
  }
  throw new Error('opened, not refused');
}

describe('opens what OpenSSL writes with KMS\'s algorithms (red)', () => {
  it.each([
    ['DER, the recipient named by its key identifier', 'oaep256-aes256-keyid.der'],
    ['streamed BER (indefinite lengths, the content in chunks)', 'oaep256-aes256-keyid-stream.ber'],
    ['DER, the recipient named by issuer and serial', 'oaep256-aes256-issuer.der'],
  ])('%s', (_label, file) => {
    expect(openEnvelopedData(fixture(file), RECIPIENT).toString('utf-8')).toBe(SECRET);
  });

  it('the streamed sample really is BER: an indefinite length', () => {
    // 30 80: a SEQUENCE of indefinite length, which DER never writes
    expect(fixture('oaep256-aes256-keyid-stream.ber').subarray(0, 2)).toEqual(Buffer.from([0x30, 0x80]));
  });
});

describe('refuses, by name, every other algorithm OpenSSL can write (red)', () => {
  it.each([
    ['RSAES-OAEP with its default SHA-1', 'oaep-sha1-aes256.der', /default \(SHA-1\) OAEP parameters/],
    ['RSA PKCS #1 v1.5', 'pkcs1v15-aes256.der', /wrapped with 1\.2\.840\.113549\.1\.1\.1, not RSAES-OAEP/],
    ['AES-128-CBC', 'oaep256-aes128.der', /encrypted with 2\.16\.840\.1\.101\.3\.4\.1\.2, not AES-256-CBC/],
    ['two recipients', 'two-recipients.der', /2 recipients, not one/],
  ])('%s', (_label, file, reason) => {
    expect(refusal(fixture(file))).toMatch(reason);
  });

  it('refuses a key it was not sealed to', () => {
    expect(refusal(fixture('oaep256-aes256-keyid.der'), OTHER)).toMatch(/does not open with this enclave's private key/);
  });
});

describe('the test writer (the fake KMS\'s) writes what the reader opens (red)', () => {
  it('opens a secret sealed to the recipient\'s public key', () => {
    expect(openEnvelopedData(sealForRecipient(Buffer.from(SECRET), RECIPIENT_PUBLIC), RECIPIENT).toString('utf-8')).toBe(SECRET);
  });

  const sha = (name: keyof typeof CMS_OID | '1.3.14.3.2.26' | '2.16.840.1.101.3.4.2.2') =>
    seq(oid(name in CMS_OID ? CMS_OID[name as keyof typeof CMS_OID] : name), NULL);
  const mgf1 = (hash: Buffer) => seq(oid(CMS_OID.mgf1), hash);

  it.each([
    ['an OAEP hash of SHA-384', seq(der(0xa0, sha('2.16.840.1.101.3.4.2.2')), der(0xa1, mgf1(sha('sha256')))), /OAEP hash other than SHA-256/],
    ['MGF1 with SHA-1 under a SHA-256 hash', seq(der(0xa0, sha('sha256')), der(0xa1, mgf1(sha('1.3.14.3.2.26')))), /mask generation other than MGF1 with SHA-256/],
    ['the SHA-256 hash with MGF1 left at its SHA-1 default', seq(der(0xa0, sha('sha256'))), /default \(SHA-1\) OAEP parameters/],
    ['a label', seq(der(0xa0, sha('sha256')), der(0xa1, mgf1(sha('sha256'))), der(0xa2, seq(oid(CMS_OID.pSpecified), octetString(Buffer.from('label'))))), /an OAEP label/],
    ['a mask generation that is not MGF1, even over SHA-256', seq(der(0xa0, sha('sha256')), der(0xa1, seq(oid('1.2.840.113549.1.1.9'), sha('sha256')))), /mask generation other than MGF1 with SHA-256/],
    ['a field RFC 4055 does not define', seq(der(0xa0, sha('sha256')), der(0xa1, mgf1(sha('sha256'))), der(0xa3, NULL)), /an unknown field/],
  ])('refuses %s', (_label, oaepParams, reason) => {
    expect(refusal(sealForRecipient(Buffer.from(SECRET), RECIPIENT_PUBLIC, { oaepParams }))).toMatch(reason);
  });

  it('opens a label written as pSpecified with an EMPTY value (RFC 4055\'s default, written out)', () => {
    const oaepParams = seq(der(0xa0, sha('sha256')), der(0xa1, mgf1(sha('sha256'))), der(0xa2, seq(oid(CMS_OID.pSpecified), octetString(Buffer.alloc(0)))));
    expect(openEnvelopedData(sealForRecipient(Buffer.from(SECRET), RECIPIENT_PUBLIC, { oaepParams }), RECIPIENT).toString('utf-8')).toBe(SECRET);
  });

  it('opens an IV written in BER chunks (a constructed OCTET STRING)', () => {
    expect(openEnvelopedData(sealForRecipient(Buffer.from(SECRET), RECIPIENT_PUBLIC, { ivInChunks: true }), RECIPIENT).toString('utf-8')).toBe(SECRET);
  });

  it('refuses an IV that is not 16 bytes', () => {
    expect(refusal(sealForRecipient(Buffer.from(SECRET), RECIPIENT_PUBLIC, { writtenIv: Buffer.alloc(8) }))).toMatch(/an IV of 8 bytes, not 16/);
  });

  it('refuses content that does not decrypt under its key (not a whole number of AES blocks)', () => {
    expect(refusal(sealForRecipient(Buffer.from(SECRET), RECIPIENT_PUBLIC, { writtenContent: Buffer.alloc(15) }))).toMatch(/does not decrypt under its key/);
  });

  it('refuses a wrapped key that is not 32 bytes (an AES-128 key under the AES-256 name)', () => {
    expect(refusal(sealForRecipient(Buffer.from(SECRET), RECIPIENT_PUBLIC, { wrappedKey: Buffer.alloc(16, 1) }))).toMatch(/a content key of 16 bytes, not 32/);
  });
});

describe('malformed BER: a CmsError, never a crash (red)', () => {
  const der0 = fixture('oaep256-aes256-keyid.der');
  const ber0 = fixture('oaep256-aes256-keyid-stream.ber');

  it('refuses every truncation of both samples', () => {
    for (const sample of [der0, ber0]) {
      for (let length = 0; length < sample.length; length++) {
        expect(() => openEnvelopedData(sample.subarray(0, length), RECIPIENT)).toThrow(CmsError);
      }
    }
  });

  it('refuses bytes after the structure', () => {
    expect(refusal(Buffer.concat([der0, Buffer.from([0x00])]))).toMatch(/bytes after the structure/);
  });

  it.each([
    ['nesting deeper than 32', Buffer.concat([Buffer.from(Array(40).fill([0x30, 0x80]).flat()), Buffer.alloc(80)]), /nested deeper than 32/],
    ['an indefinite length on a primitive', Buffer.from([0x04, 0x80, 0x01, 0x00, 0x00]), /an indefinite length on a primitive/],
    ['a high tag number', Buffer.from([0x1f, 0x81, 0x01, 0x00]), /a high tag number/],
    ['a five-byte length', Buffer.from([0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]), /a length it cannot read/],
    ['a child that runs past its parent', Buffer.from([0x30, 0x03, 0x04, 0x05, 1, 2, 3, 4, 5]), /a child runs past its parent/],
    ['an indefinite length without its end', Buffer.from([0x30, 0x80, 0x05, 0x00]), /an indefinite length without its end/],
    ['not an EnvelopedData', seq(oid(CMS_OID.data), der(0xa0, octetString(Buffer.from('x')))), /not an EnvelopedData/],
  ])('refuses %s', (_label, bytes, reason) => {
    expect(refusal(bytes)).toMatch(reason);
  });
});
