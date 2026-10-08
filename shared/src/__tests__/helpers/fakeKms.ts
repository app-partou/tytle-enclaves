/**
 * A stand-in for KMS's Decrypt as the enclave reaches it (sealedSecret.ts, enclave audit P1.7): a fake server for
 * fakeEnclaveIo's `reply(KMS_HOST.vsockProxyPort, kms.reply)`. It answers the way the KMS API reference documents a
 * Decrypt with a Recipient: 200 with CiphertextForRecipient - the secret sealed (CMS EnvelopedData, cmsWriter.ts) to
 * the RSA public key of the attestation document the request carried - and no Plaintext. Real KMS also verifies the
 * document's signature chain and the key policy's conditions; the fake NSM's documents are unsigned, so this does
 * neither (the main repo's KMS key policy test owns the conditions). Every request is kept, parsed.
 */
import crypto from 'node:crypto';
import cbor from 'cbor';
import { sealForRecipient } from './cmsWriter.js';
import { httpReply } from './fakeEnclaveIo.js';

export interface KmsRequest {
  requestLine: string;
  /** Every header line, in order, as written (names as sent). */
  headerLines: Array<[string, string]>;
  /** The values of one header, any case. */
  header(name: string): string[];
  rawBody: string;
  body: Record<string, unknown>;
  /** The public_key of the Recipient's attestation document (SPKI DER), or null when it has none. */
  recipientPublicKey: Buffer | null;
}

export type KmsAnswer =
  /** The documented answer: the secret sealed to the document's key (and, to test a refusal, extra fields). */
  | { sealed: string | Buffer; extra?: Record<string, unknown>; sealTo?: crypto.KeyObject }
  /** Any other answer, verbatim. */
  | { status: number; body: string };

export function parseKmsRequest(raw: string): KmsRequest {
  const split = raw.indexOf('\r\n\r\n');
  if (split < 0) throw new Error('fake KMS: a request without the end of its headers');
  const [requestLine, ...lines] = raw.slice(0, split).split('\r\n');
  const headerLines = lines.map((line): [string, string] => {
    const colon = line.indexOf(':');
    return [line.slice(0, colon), line.slice(colon + 1).trim()];
  });
  const rawBody = raw.slice(split + 4);
  const body = JSON.parse(rawBody) as Record<string, unknown>;
  const recipient = body.Recipient as { AttestationDocument?: string } | undefined;
  let recipientPublicKey: Buffer | null = null;
  if (typeof recipient?.AttestationDocument === 'string') {
    const cose = cbor.decodeFirstSync(Buffer.from(recipient.AttestationDocument, 'base64')) as Buffer[];
    const payload = cbor.decodeFirstSync(cose[2]) as Map<string, unknown>;
    const key = payload instanceof Map ? payload.get('public_key') : (payload as Record<string, unknown>).public_key;
    recipientPublicKey = Buffer.isBuffer(key) ? key : null;
  }
  return {
    requestLine,
    headerLines,
    header: (name) => headerLines.filter(([n]) => n.toLowerCase() === name.toLowerCase()).map(([, v]) => v),
    rawBody,
    body,
    recipientPublicKey,
  };
}

/** A fake KMS that answers each Decrypt with the next of `answers` (the last one repeats). */
export function fakeKms(...answers: KmsAnswer[]) {
  const requests: KmsRequest[] = [];
  function reply(raw: string): string {
    const request = parseKmsRequest(raw);
    requests.push(request);
    const answer = answers[Math.min(requests.length - 1, answers.length - 1)];
    if ('status' in answer) return httpReply(answer.status, answer.body, { 'Content-Type': 'application/x-amz-json-1.1' });
    const sealTo = answer.sealTo ?? (request.recipientPublicKey
      ? crypto.createPublicKey({ key: request.recipientPublicKey, format: 'der', type: 'spki' })
      : null);
    if (!sealTo) {
      return httpReply(400, JSON.stringify({ __type: 'ValidationException', message: 'no Recipient public key' }), { 'Content-Type': 'application/x-amz-json-1.1' });
    }
    const secret = Buffer.isBuffer(answer.sealed) ? answer.sealed : Buffer.from(answer.sealed, 'utf-8');
    const body = JSON.stringify({
      KeyId: 'arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
      CiphertextForRecipient: sealForRecipient(secret, sealTo).toString('base64'),
      EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
      ...answer.extra,
    });
    return httpReply(200, body, { 'Content-Type': 'application/x-amz-json-1.1' });
  }
  return { reply, requests };
}
