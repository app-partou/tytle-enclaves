/**
 * attest() with only the NSM device replaced (helpers/fakeNsm.ts): the nonce, the CBOR request and the
 * COSE decoding run for real. The nonce preimages are the contract with the verifier (the main repo's
 * nsmNonceOf; its nonceFormula.drift.test.ts reads this repo's attestor.ts as text).
 * attest() takes its options as an object since the challenge release; the behaviour locks that hold
 * across that change run through the handler factory (handlerFactory.challenge.test.ts).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'node:crypto';
import { createFakeNsm, FAKE_PCRS } from './helpers/fakeNsm.js';

const { fake } = vi.hoisted(() => ({ fake: { current: null as ReturnType<typeof import('./helpers/fakeNsm.js').createFakeNsm> | null } }));
vi.mock('@tytle-enclaves/native', () => ({
  nsmRequest: (request: Buffer) => fake.current!.nsmRequest(request),
}));

import { attest } from '../attestor.js';

const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const CHALLENGE = 'c'.repeat(64);
const BN254_HASH = 'b'.repeat(64);

function callAttest(options?: Parameters<typeof attest>[5]) {
  return attest('ec.europa.eu/checkVatService', 'POST', 'BASE64VECTOR==', 'https://ec.europa.eu/x', { countryCode: 'PT' }, options);
}

beforeEach(() => {
  fake.current = createFakeNsm();
  vi.useRealTimers();
});

describe('attest - nonce version 1, no challenge (the preimage of every stored row)', () => {
  it('signs SHA-256(responseHash|apiEndpoint|timestamp) and asks the NSM for exactly that nonce', async () => {
    const doc = await callAttest({ userDataHex: BN254_HASH });
    const responseHash = sha256('BASE64VECTOR==');
    expect(doc.responseHash).toBe(responseHash);
    expect(doc.nonce).toBe(sha256(`${responseHash}|ec.europa.eu/checkVatService|${doc.timestamp}`));
    expect(fake.current!.asks).toHaveLength(1);
    expect(fake.current!.asks[0].nonce?.toString('hex')).toBe(doc.nonce);
    expect(doc).not.toHaveProperty('challenge');
  });

  it('puts the BN254 hash in user_data and no public key', async () => {
    await callAttest({ userDataHex: BN254_HASH });
    expect(fake.current!.asks[0].userData?.toString('hex')).toBe(BN254_HASH);
    expect(fake.current!.asks[0].publicKey).toBeNull();
  });

  it('returns the document and the PCRs read from its signed payload', async () => {
    const doc = await callAttest();
    expect(doc.pcrs).toEqual(FAKE_PCRS);
    expect(Buffer.from(doc.nsmDocument, 'base64').length).toBeGreaterThan(100);
  });
});

describe('attest - nonce version 2, the caller challenge (P1.3)', () => {
  it('says which preimage it signed: version 1 without a challenge', async () => {
    const doc = await callAttest();
    expect(doc.nonceVersion).toBe(1);
  });

  it('signs SHA-256(responseHash|apiEndpoint|timestamp|challenge), echoes the challenge, version 2', async () => {
    const doc = await callAttest({ userDataHex: BN254_HASH, challenge: CHALLENGE });
    const responseHash = sha256('BASE64VECTOR==');
    expect(doc.nonceVersion).toBe(2);
    expect(doc.challenge).toBe(CHALLENGE);
    expect(doc.nonce).toBe(sha256(`${responseHash}|ec.europa.eu/checkVatService|${doc.timestamp}|${CHALLENGE}`));
    expect(fake.current!.asks[0].nonce?.toString('hex')).toBe(doc.nonce);
    expect(fake.current!.asks[0].userData?.toString('hex')).toBe(BN254_HASH);
  });

  it.each([
    ['upper-case hex', 'C'.repeat(64)],
    ['63 characters', 'c'.repeat(63)],
    ['65 characters', 'c'.repeat(65)],
    ['not hex', 'g'.repeat(64)],
    ['empty', ''],
  ])('refuses a challenge that is %s before the NSM is asked', async (_label, challenge) => {
    await expect(callAttest({ challenge })).rejects.toMatchObject({ name: 'InvalidChallengeError', code: 'INVALID_CHALLENGE' });
    expect(fake.current!.asks).toHaveLength(0);
  });
});
