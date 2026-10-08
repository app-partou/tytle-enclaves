/**
 * unsealSecret through its real path (enclave audit P1.7): the process's RSA key pair, the recipient attestation
 * (attestor.ts), the SigV4 signer, proxyFetch through the host's vsock-proxy to KMS, and the CMS reader all run for
 * real. MOCK BOUNDARY: the enclave's two boundaries (helpers/fakeEnclaveIo.ts: the vsock socket with TLS over it, and
 * the NSM device) and KMS behind them (helpers/fakeKms.ts: a fake server that seals to the attestation document's key,
 * as the KMS API reference documents a Decrypt with a Recipient).
 *
 * The module keeps its key pair and the opened secrets for the life of the process, so each test seals its own
 * ciphertext (uniqueCiphertext) and none depends on another's memory.
 *
 * Labels: "red" = fails on the release before this one (it had no sealed secrets).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';

vi.mock('@tytle-enclaves/native', async () => (await import('./helpers/fakeEnclaveIo.js')).nativeModule);
vi.mock('node:tls', async () => (await import('./helpers/fakeEnclaveIo.js')).tlsModule);

import cbor from 'cbor';
import { fakeIo } from './helpers/fakeEnclaveIo.js';
import { fakeKms } from './helpers/fakeKms.js';
import { signRequest } from '../sigv4.js';
import { CmsError } from '../cms.js';
import { unsealSecret, SealedSecretError, KMS_HOST, KMS_REGION, SEALED_SECRET_TTL_MS } from '../sealedSecret.js';
import type { AllowedHost } from '../types.js';

const KMS_PORT = 8000;
/** An enclave's allowlist that names KMS, as the Stripe enclave's does. */
const ALLOWLIST: AllowedHost[] = [{ hostname: 'api.stripe.com', vsockProxyPort: 8446 }, { hostname: 'kms.eu-central-1.amazonaws.com', vsockProxyPort: 8000 }];
const SECRET = 'sk_test_TESTONLY_sealed';
const CREDENTIALS = {
  accessKeyId: 'ASIAEXAMPLEEXAMPLE01',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  sessionToken: 'IQoJb3JpZ2luX2VjEXAMPLETOKEN//////////wEaDGV1LWNlbnRyYWwtMSJHMEUCIQ==',
};

let counter = 0;
/** A ciphertext no other test used. A KMS CiphertextBlob is opaque to the enclave: any base64 serves. */
const uniqueCiphertext = () => crypto.createHash('sha256').update(`sealed-${++counter}-${process.hrtime.bigint()}`).digest('base64');

async function refusal(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (err) {
    return err as Error;
  }
  throw new Error('opened, not refused');
}

/** A KMS that seals `secret` to the attestation document's key, scripted for `times` connections. */
function kmsSealing(secret: string, times = 1) {
  const kms = fakeKms({ sealed: secret });
  for (let i = 0; i < times; i++) fakeIo.reply(KMS_PORT, kms.reply);
  return kms;
}

beforeEach(() => {
  fakeIo.reset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('KMS through the host\'s vsock-proxy (red)', () => {
  it('is kms.eu-central-1.amazonaws.com on vsock port 8000, over TLS', () => {
    expect(KMS_REGION).toBe('eu-central-1');
    expect(KMS_HOST).toEqual({ hostname: 'kms.eu-central-1.amazonaws.com', vsockProxyPort: 8000 });
  });
});

describe('opens a secret sealed to this enclave (red)', () => {
  it('asks KMS to Decrypt with this enclave as the Recipient, and opens the answer', async () => {
    const kms = kmsSealing(SECRET);
    const ciphertext = uniqueCiphertext();
    expect(await unsealSecret(ciphertext, 'stripe_payment', CREDENTIALS, ALLOWLIST)).toBe(SECRET);

    expect(fakeIo.requests(KMS_PORT)).toHaveLength(1);
    const [request] = kms.requests;
    expect(request.requestLine).toBe('POST / HTTP/1.1');
    expect(request.header('host')).toEqual(['kms.eu-central-1.amazonaws.com']);
    expect(request.header('x-amz-target')).toEqual(['TrentService.Decrypt']);
    expect(request.header('content-type')).toEqual(['application/x-amz-json-1.1']);
    expect(request.header('x-amz-security-token')).toEqual([CREDENTIALS.sessionToken]);
    expect(request.body).toEqual({
      CiphertextBlob: ciphertext,
      EncryptionContext: { enclave: 'stripe_payment' },
      Recipient: { AttestationDocument: expect.any(String), KeyEncryptionAlgorithm: 'RSAES_OAEP_SHA_256' },
    });
  });

  it('signs exactly what it sends: the headers, and the body as written', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-08T12:00:00.250Z'));
    const kms = kmsSealing(SECRET);
    await unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, ALLOWLIST);

    const [request] = kms.requests;
    const added = new Set(['host', 'connection', 'content-length', 'authorization', 'x-amz-date', 'x-amz-security-token']);
    const own = Object.fromEntries(request.headerLines.filter(([name]) => !added.has(name.toLowerCase())));
    const expected = signRequest(
      { method: 'POST', host: KMS_HOST.hostname, path: '/', headers: own, body: request.rawBody },
      { service: 'kms', region: 'eu-central-1', credentials: CREDENTIALS, now: new Date('2026-10-08T12:00:00Z') },
    );
    expect(request.header('authorization')).toEqual([expected.authorization]);
    expect(request.header('x-amz-date')).toEqual(['20261008T120000Z']);
    // Every header the signature names is sent, once: Host included, never twice
    for (const name of /SignedHeaders=([^,]+),/.exec(expected.authorization)![1].split(';')) {
      expect(request.header(name), name).toHaveLength(1);
    }
    expect(request.header('content-length')).toEqual([String(Buffer.byteLength(request.rawBody))]);
  });

  it('asks the NSM for a document that carries ONLY its RSA-2048 public key, and sends that document', async () => {
    const kms = kmsSealing(SECRET);
    await unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, ALLOWLIST);

    expect(fakeIo.nsmAsks).toHaveLength(1);
    const [ask] = fakeIo.nsmAsks;
    expect(ask.nonce).toBeNull();
    expect(ask.userData).toBeNull();
    const key = crypto.createPublicKey({ key: ask.publicKey!, format: 'der', type: 'spki' });
    expect(key.asymmetricKeyType).toBe('rsa');
    expect(key.asymmetricKeyDetails?.modulusLength).toBe(2048);
    expect(kms.requests[0].recipientPublicKey).toEqual(ask.publicKey);
  });

  it('makes its key pair once per process: the next secret is sealed to the same key', async () => {
    kmsSealing(SECRET, 2);
    await unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, ALLOWLIST);
    await unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, ALLOWLIST);
    expect(fakeIo.nsmAsks).toHaveLength(2);
    expect(fakeIo.nsmAsks[1].publicKey).toEqual(fakeIo.nsmAsks[0].publicKey);
  });

  it.each([
    ['null', null],
    ['empty', ''],
  ])('opens an answer whose Plaintext is %s (KMS: "null or empty" beside CiphertextForRecipient)', async (_label, plaintext) => {
    const kms = fakeKms({ sealed: SECRET, extra: { Plaintext: plaintext } });
    fakeIo.reply(KMS_PORT, kms.reply);
    expect(await unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, ALLOWLIST)).toBe(SECRET);
  });

  it('accepts a sealed secret of 6144 bytes, KMS\'s limit for a CiphertextBlob', async () => {
    kmsSealing(SECRET);
    expect(await unsealSecret(crypto.randomBytes(6144).toString('base64'), 'stripe_payment', CREDENTIALS, ALLOWLIST)).toBe(SECRET);
  });
});

describe('keeps an opened secret in memory for an hour, and nothing else (red)', () => {
  it('answers the same sealed secret from memory until the hour is up, then asks KMS again', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const start = new Date('2026-10-08T12:00:00Z').getTime();
    vi.setSystemTime(start);
    const kms = kmsSealing(SECRET);
    const ciphertext = uniqueCiphertext();
    expect(await unsealSecret(ciphertext, 'stripe_payment', CREDENTIALS, ALLOWLIST)).toBe(SECRET);

    vi.setSystemTime(start + SEALED_SECRET_TTL_MS - 1);
    expect(await unsealSecret(ciphertext, 'stripe_payment', CREDENTIALS, ALLOWLIST)).toBe(SECRET); // nothing scripted: memory
    expect(kms.requests).toHaveLength(1);

    vi.setSystemTime(start + SEALED_SECRET_TTL_MS);
    fakeIo.reply(KMS_PORT, kms.reply);
    expect(await unsealSecret(ciphertext, 'stripe_payment', CREDENTIALS, ALLOWLIST)).toBe(SECRET);
    expect(kms.requests).toHaveLength(2);
    expect(SEALED_SECRET_TTL_MS).toBe(60 * 60 * 1000);
  });

  it('keeps a secret per enclave name: the same ciphertext under another name asks KMS', async () => {
    const kms = kmsSealing(SECRET, 2);
    const ciphertext = uniqueCiphertext();
    await unsealSecret(ciphertext, 'stripe_payment', CREDENTIALS, ALLOWLIST);
    await unsealSecret(ciphertext, 'monerium_payment', CREDENTIALS, ALLOWLIST);
    expect(kms.requests.map((r) => r.body.EncryptionContext)).toEqual([{ enclave: 'stripe_payment' }, { enclave: 'monerium_payment' }]);
  });

  it('keeps at most 16 secrets: the oldest leaves first', async () => {
    const kms = kmsSealing(SECRET, 17);
    const ciphertexts = Array.from({ length: 17 }, uniqueCiphertext);
    for (const ciphertext of ciphertexts) await unsealSecret(ciphertext, 'stripe_payment', CREDENTIALS, ALLOWLIST);
    expect(kms.requests).toHaveLength(17);

    await unsealSecret(ciphertexts[16], 'stripe_payment', CREDENTIALS, ALLOWLIST); // the newest: memory (nothing scripted)
    await unsealSecret(ciphertexts[1], 'stripe_payment', CREDENTIALS, ALLOWLIST); // the oldest kept: memory
    expect(kms.requests).toHaveLength(17);
    fakeIo.reply(KMS_PORT, kms.reply);
    await unsealSecret(ciphertexts[0], 'stripe_payment', CREDENTIALS, ALLOWLIST); // the first: gone, so KMS again
    expect(kms.requests).toHaveLength(18);
  });

  it('a secret opened again after its hour moves to the newest place: no fresh secret is pushed out for it', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const start = new Date('2026-10-09T12:00:00Z').getTime();
    vi.setSystemTime(start);
    const kms = kmsSealing(SECRET, 16);
    const old = Array.from({ length: 16 }, uniqueCiphertext);
    for (const ciphertext of old) await unsealSecret(ciphertext, 'stripe_payment', CREDENTIALS, ALLOWLIST);

    vi.setSystemTime(start + SEALED_SECRET_TTL_MS); // all 16 have expired
    for (let i = 0; i < 3; i++) fakeIo.reply(KMS_PORT, kms.reply);
    await unsealSecret(old[1], 'stripe_payment', CREDENTIALS, ALLOWLIST); // opened again: now the newest
    await unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, ALLOWLIST);
    await unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, ALLOWLIST);
    expect(kms.requests).toHaveLength(19);
    await unsealSecret(old[1], 'stripe_payment', CREDENTIALS, ALLOWLIST); // fresh, so still kept: memory (nothing scripted)
    expect(kms.requests).toHaveLength(19);
  });

  it('never keeps a refusal: the next ask goes to KMS again', async () => {
    const kms = fakeKms(
      { status: 400, body: JSON.stringify({ __type: 'AccessDeniedException', message: 'not authorized' }) },
      { sealed: SECRET },
    );
    fakeIo.reply(KMS_PORT, kms.reply);
    fakeIo.reply(KMS_PORT, kms.reply);
    const ciphertext = uniqueCiphertext();
    await expect(unsealSecret(ciphertext, 'stripe_payment', CREDENTIALS, ALLOWLIST)).rejects.toThrow(SealedSecretError);
    expect(await unsealSecret(ciphertext, 'stripe_payment', CREDENTIALS, ALLOWLIST)).toBe(SECRET);
    expect(kms.requests).toHaveLength(2);
  });
});

describe('KMS only through the enclave\'s own allowlist (red)', () => {
  it('an allowlist that does not name KMS: KMS_NOT_ALLOWED, before any NSM document or call', async () => {
    const err = await refusal(unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, [{ hostname: 'api.stripe.com', vsockProxyPort: 8446 }]));
    expect((err as SealedSecretError).code).toBe('KMS_NOT_ALLOWED');
    expect(err.message).toMatch(/does not name kms\.eu-central-1\.amazonaws\.com/);
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });

  it('KMS listed for plain HTTP: KMS_NOT_ALLOWED', async () => {
    const err = await refusal(unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, [{ ...KMS_HOST, tls: false }]));
    expect((err as SealedSecretError).code).toBe('KMS_NOT_ALLOWED');
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });

  it('dials the vsock port the allowlist names', async () => {
    const kms = fakeKms({ sealed: SECRET });
    fakeIo.reply(8100, kms.reply);
    expect(await unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, [{ hostname: KMS_HOST.hostname, vsockProxyPort: 8100 }])).toBe(SECRET);
    expect(fakeIo.requests(8100)).toHaveLength(1);
  });

  it('a secret already in memory is not handed to an allowlist without KMS', async () => {
    kmsSealing(SECRET);
    const ciphertext = uniqueCiphertext();
    await unsealSecret(ciphertext, 'stripe_payment', CREDENTIALS, ALLOWLIST);
    const err = await refusal(unsealSecret(ciphertext, 'stripe_payment', CREDENTIALS, [{ hostname: 'api.stripe.com', vsockProxyPort: 8446 }]));
    expect((err as SealedSecretError).code).toBe('KMS_NOT_ALLOWED');
  });
});

describe('refuses before any call: no NSM document, no KMS request (red)', () => {
  it.each([
    ['no credentials', undefined],
    ['null', null],
    ['an empty object', {}],
    ['an access key id that is not one', { ...CREDENTIALS, accessKeyId: 'asia-lowercase-0001' }],
    ['an empty secret key', { ...CREDENTIALS, secretAccessKey: '' }],
    ['a session token that is not text', { ...CREDENTIALS, sessionToken: 42 }],
    ['an empty session token', { ...CREDENTIALS, sessionToken: '' }],
  ])('credentials: %s', async (_label, credentials) => {
    const err = await refusal(unsealSecret(uniqueCiphertext(), 'stripe_payment', credentials, ALLOWLIST));
    expect(err).toBeInstanceOf(SealedSecretError);
    expect((err as SealedSecretError).code).toBe('NO_CREDENTIALS');
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });

  it.each([
    ['an enclave name in capitals', 'Stripe_payment'],
    ['an enclave name with a hyphen', 'stripe-payment'],
    ['an empty enclave name', ''],
    ['an enclave name of 65 characters', `s${'a'.repeat(64)}`],
  ])('%s', async (_label, context) => {
    const err = await refusal(unsealSecret(uniqueCiphertext(), context, CREDENTIALS, ALLOWLIST));
    expect((err as SealedSecretError).code).toBe('INVALID_SEALED_SECRET');
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });

  it.each([
    ['empty', ''],
    ['not base64', 'not base64!'],
    ['base64 without its padding', 'QUJD'.slice(0, 3)],
    ['more than 6144 bytes', crypto.randomBytes(6145).toString('base64')],
    ['not text', 42],
  ])('a ciphertext that is %s', async (_label, ciphertext) => {
    const err = await refusal(unsealSecret(ciphertext as string, 'stripe_payment', CREDENTIALS, ALLOWLIST));
    expect((err as SealedSecretError).code).toBe('INVALID_SEALED_SECRET');
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });
});

describe('refuses every answer that is not a sealed secret (red)', () => {
  const kmsAnswering = (status: number, body: string) => fakeIo.reply(KMS_PORT, fakeKms({ status, body }).reply);

  it.each([
    ['a denial', 400, { __type: 'AccessDeniedException', message: 'User: arn:aws:sts::111122223333:assumed-role/host is not authorized to perform: kms:Decrypt' }, /\(400 AccessDeniedException\): User: arn:aws:sts/],
    ['a namespaced error type', 400, { __type: 'com.amazonaws.kms#InvalidCiphertextException' }, /\(400 InvalidCiphertextException\)$/],
    ['an internal error', 500, { __type: 'KMSInternalException', Message: 'retry' }, /\(500 KMSInternalException\): retry/],
  ])('%s: KMS_REFUSED, with KMS\'s reason', async (_label, status, body, reason) => {
    kmsAnswering(status, JSON.stringify(body));
    const err = await refusal(unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, ALLOWLIST));
    expect((err as SealedSecretError).code).toBe('KMS_REFUSED');
    expect(err.message).toMatch(reason);
  });

  it('a Plaintext with a value: KMS_PLAINTEXT, even beside CiphertextForRecipient', async () => {
    fakeIo.reply(KMS_PORT, fakeKms({ sealed: SECRET, extra: { Plaintext: Buffer.from(SECRET).toString('base64') } }).reply);
    const err = await refusal(unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, ALLOWLIST));
    expect((err as SealedSecretError).code).toBe('KMS_PLAINTEXT');
  });

  it.each([
    ['no CiphertextForRecipient', JSON.stringify({ KeyId: 'k' }), /without CiphertextForRecipient/],
    ['a CiphertextForRecipient that is not base64', JSON.stringify({ CiphertextForRecipient: 'not base64!' }), /without CiphertextForRecipient/],
    ['not JSON', '<html>proxy</html>', /without a JSON object/],
    ['a JSON array', '[]', /without a JSON object/],
  ])('%s: KMS_ANSWER', async (_label, body, reason) => {
    kmsAnswering(200, body);
    const err = await refusal(unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, ALLOWLIST));
    expect((err as SealedSecretError).code).toBe('KMS_ANSWER');
    expect(err.message).toMatch(reason);
  });

  it('an empty secret: KMS_ANSWER', async () => {
    kmsSealing('');
    const err = await refusal(unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, ALLOWLIST));
    expect((err as SealedSecretError).code).toBe('KMS_ANSWER');
    expect(err.message).toMatch(/the sealed secret is empty/);
  });

  it('the NSM answers an error instead of a document: refused, and KMS is never asked', async () => {
    fakeIo.nsmAnswersNext(cbor.encode({ Error: 'InvalidArgument' }));
    const err = await refusal(unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, ALLOWLIST));
    expect(err.message).toMatch(/NSM response missing Attestation\.document/);
    expect(fakeIo.requests(KMS_PORT)).toEqual([]);
  });

  it('a secret sealed to another key: the CMS reader refuses it', async () => {
    const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey;
    fakeIo.reply(KMS_PORT, fakeKms({ sealed: SECRET, sealTo: other }).reply);
    const err = await refusal(unsealSecret(uniqueCiphertext(), 'stripe_payment', CREDENTIALS, ALLOWLIST));
    expect(err).toBeInstanceOf(CmsError);
    expect(err.message).toMatch(/does not open with this enclave's private key/);
  });
});
