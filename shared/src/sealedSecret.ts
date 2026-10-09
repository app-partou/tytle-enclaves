/**
 * Secrets sealed to an enclave (enclave audit P1.7). A provider's secret - Stripe's platform key - is encrypted once,
 * by the deploy role, with the KMS key `alias/tytle-<env>-enclave-secrets` and the encryption context
 * `{enclave: <name>}`; a caller then sends only that ciphertext. The key policy lets the host's role Decrypt only with
 * an attestation document of an enclave image it names (kms:RecipientAttestation:ImageSha384), for that enclave's
 * context alone. So the secret is never in clear on the host, in data-bridge or in a log: KMS encrypts it to an RSA
 * key that exists only in this enclave's memory, and only this code opens it.
 *
 * One Decrypt: an RSA-2048 key pair, made once per process; an attestation document whose public_key is that key
 * (attestor.ts recipientAttestation); KMS Decrypt with the document as its Recipient, signed with SigV4 (sigv4.ts) by
 * the host role's temporary credentials, which the parent sends with the request; over the host's vsock-proxy for
 * KMS, TLS end to end. The answer must be CiphertextForRecipient (opened by cms.ts), never Plaintext. An opened
 * secret stays in this process's memory for an hour; a failure is never kept.
 */

import crypto from 'node:crypto';
import { recipientAttestation } from './attestor.js';
import { openEnvelopedData } from './cms.js';
import { proxyFetch } from './httpProxy.js';
import { timeFor, type RequestBudget } from './requestBudget.js';
import { signRequest, type AwsCredentials } from './sigv4.js';
import type { AllowedHost } from './types.js';

/** The region of the enclave hosts and of their KMS key. */
export const KMS_REGION = 'eu-central-1';

/**
 * KMS, through the host's vsock-proxy on port 8000 (the port kmstool uses), TLS end to end: the proxy sees only
 * encrypted bytes. An enclave that opens sealed secrets names this host in its own allowlist (part of its PCR0);
 * one that does not cannot reach KMS.
 */
export const KMS_HOST: AllowedHost = { hostname: `kms.${KMS_REGION}.amazonaws.com`, vsockProxyPort: 8000 };

/** How long an opened secret is kept in memory before KMS is asked again. */
export const SEALED_SECRET_TTL_MS = 60 * 60 * 1000;

/** At most this many opened secrets in memory (an enclave has one or two). */
const CACHE_LIMIT = 16;

const KMS_TIMEOUT_MS = 10_000;

/** KMS's limit for a CiphertextBlob, in bytes: the most a sealed secret can be. */
export const SEALED_SECRET_MAX_BYTES = 6144;

/** The enclave names of the key policy's encryption contexts: stripe_payment, monerium_payment, ... */
const CONTEXT_PATTERN = /^[a-z][a-z_]{0,63}$/;

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** Base64 holds 3 bytes in every 4 characters: no longer text decodes to more than SEALED_SECRET_MAX_BYTES. */
const MAX_SEALED_TEXT = Math.ceil(SEALED_SECRET_MAX_BYTES / 3) * 4;

/** A sealed secret as a caller sends one: base64 (as `aws kms encrypt` prints it) of at most SEALED_SECRET_MAX_BYTES. */
export function isSealedSecretText(value: unknown): value is string {
  return typeof value === 'string' && value !== '' && value.length <= MAX_SEALED_TEXT && BASE64_PATTERN.test(value);
}

/** A sealed secret this enclave could not open, and why. Never carries a byte of the secret. */
export class SealedSecretError extends Error {
  constructor(
    readonly code: 'INVALID_SEALED_SECRET' | 'KMS_NOT_ALLOWED' | 'NO_CREDENTIALS' | 'KMS_REFUSED' | 'KMS_ANSWER' | 'KMS_PLAINTEXT',
    message: string,
  ) {
    super(`Sealed secret: ${message}`);
    this.name = 'SealedSecretError';
  }
}

let recipientKeys: crypto.KeyPairKeyObjectResult | null = null;

/** The process's RSA-2048 key pair: its public half goes into the Recipient document, its private half never leaves. */
function recipientKeyPair(): crypto.KeyPairKeyObjectResult {
  recipientKeys ??= crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return recipientKeys;
}

const opened = new Map<string, { secret: string; expiresAt: number }>();

function credentialsOf(credentials: unknown): AwsCredentials {
  if (credentials === undefined || credentials === null) {
    throw new SealedSecretError('NO_CREDENTIALS', 'the parent sent no AWS credentials with this request');
  }
  const c = credentials as Partial<Record<keyof AwsCredentials, unknown>>;
  if (typeof c.accessKeyId !== 'string' || !/^[A-Z0-9]{16,128}$/.test(c.accessKeyId)
    || typeof c.secretAccessKey !== 'string' || c.secretAccessKey === ''
    || (c.sessionToken !== undefined && (typeof c.sessionToken !== 'string' || c.sessionToken === ''))) {
    throw new SealedSecretError('NO_CREDENTIALS', 'the AWS credentials the parent sent are not an access key id, a secret and a session token');
  }
  return { accessKeyId: c.accessKeyId, secretAccessKey: c.secretAccessKey, ...(c.sessionToken ? { sessionToken: c.sessionToken } : {}) };
}

/** The plaintext of a KMS answer to a Decrypt with a Recipient: CiphertextForRecipient, opened here, or an error. */
function secretOf(status: number, body: string, privateKey: crypto.KeyObject): string {
  let answer: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(body);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('not an object');
    answer = parsed as Record<string, unknown>;
  } catch {
    throw new SealedSecretError('KMS_ANSWER', `KMS answered ${status} without a JSON object`);
  }
  if (status !== 200) {
    const type = typeof answer.__type === 'string' ? answer.__type.split('#').pop() : 'an unnamed error';
    const message = typeof answer.message === 'string' ? answer.message
      : typeof answer.Message === 'string' ? answer.Message : '';
    throw new SealedSecretError('KMS_REFUSED', `KMS refused the Decrypt (${status} ${type})${message ? `: ${message}` : ''}`);
  }
  // With a Recipient, KMS answers CiphertextForRecipient, and "the Plaintext field in the response is null or empty"
  // (KMS API reference, Decrypt, Recipient). A Plaintext with a value means the secret travelled in clear past this
  // enclave's key: refused, never used.
  if (answer.Plaintext !== undefined && answer.Plaintext !== null && answer.Plaintext !== '') {
    throw new SealedSecretError('KMS_PLAINTEXT', 'KMS answered with Plaintext, not CiphertextForRecipient');
  }
  if (typeof answer.CiphertextForRecipient !== 'string' || !BASE64_PATTERN.test(answer.CiphertextForRecipient)) {
    throw new SealedSecretError('KMS_ANSWER', 'KMS answered without CiphertextForRecipient');
  }
  const secret = openEnvelopedData(Buffer.from(answer.CiphertextForRecipient, 'base64'), privateKey).toString('utf-8');
  if (secret === '') throw new SealedSecretError('KMS_ANSWER', 'the sealed secret is empty');
  return secret;
}

/** KMS as this enclave's allowlist names it, over TLS; an enclave whose allowlist does not name KMS opens nothing. */
function kmsHostOf(allowlist: readonly AllowedHost[]): AllowedHost {
  const host = allowlist.find((h) => h.hostname === KMS_HOST.hostname);
  if (!host) throw new SealedSecretError('KMS_NOT_ALLOWED', `this enclave's allowlist does not name ${KMS_HOST.hostname}`);
  if (host.tls === false) throw new SealedSecretError('KMS_NOT_ALLOWED', `${KMS_HOST.hostname} is reached over TLS only`);
  return host;
}

/**
 * The secret `ciphertext` (base64, as `aws kms encrypt` gives it) holds, sealed for the enclave named `context`.
 * `credentials` are the host role's, from the parent (EnclaveRequest.awsCredentials); `allowlist` is the enclave's own;
 * `budget` is the request's (requestBudget.ts): the KMS call takes what is left of it.
 */
export async function unsealSecret(
  ciphertext: string, context: string, credentials: unknown, allowlist: readonly AllowedHost[], budget?: RequestBudget,
): Promise<string> {
  if (!CONTEXT_PATTERN.test(context)) throw new SealedSecretError('INVALID_SEALED_SECRET', `"${context}" is not an enclave name`);
  if (!isSealedSecretText(ciphertext)) {
    throw new SealedSecretError('INVALID_SEALED_SECRET', `a sealed secret is base64 of at most ${SEALED_SECRET_MAX_BYTES} bytes`);
  }

  const cacheKey = crypto.createHash('sha256').update(`${context}\n${ciphertext}`).digest('hex');
  const kms = kmsHostOf(allowlist);
  const kept = opened.get(cacheKey);
  if (kept && kept.expiresAt > Date.now()) return kept.secret;

  // The KMS call takes what is left of the request's budget, at most KMS_TIMEOUT_MS (requestBudget.ts); with nothing
  // left, neither the recipient document nor the call is made
  const kmsTimeoutMs = budget ? timeFor(budget, 'the KMS call', KMS_TIMEOUT_MS) : KMS_TIMEOUT_MS;
  const signer = credentialsOf(credentials);
  const { publicKey, privateKey } = recipientKeyPair();
  const document = recipientAttestation(publicKey.export({ type: 'spki', format: 'der' }));
  const body = JSON.stringify({
    CiphertextBlob: ciphertext,
    EncryptionContext: { enclave: context },
    Recipient: { AttestationDocument: document.toString('base64'), KeyEncryptionAlgorithm: 'RSAES_OAEP_SHA_256' },
  });
  const signed = signRequest(
    {
      method: 'POST',
      host: kms.hostname,
      path: '/',
      headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'TrentService.Decrypt' },
      body,
    },
    { service: 'kms', region: KMS_REGION, credentials: signer, now: new Date() },
  );
  // proxyFetch writes the Host header itself (the same value): sent twice, it would be a malformed request
  const headers = Object.fromEntries(Object.entries(signed).filter(([name]) => name !== 'host'));
  const response = await proxyFetch(kms.vsockProxyPort, kms.hostname, 'POST', '/', headers, body, kmsTimeoutMs);
  const secret = secretOf(response.status, response.body, privateKey);

  // An expired copy of this secret leaves first; then, at the limit, the oldest secret kept
  opened.delete(cacheKey);
  if (opened.size >= CACHE_LIMIT) opened.delete(opened.keys().next().value as string);
  opened.set(cacheKey, { secret, expiresAt: Date.now() + SEALED_SECRET_TTL_MS });
  return secret;
}
