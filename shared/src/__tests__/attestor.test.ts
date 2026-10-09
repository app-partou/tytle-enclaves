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

describe('the attestation time: the hypervisor\'s signed time, never the enclave clock (P1.4, audit §5.1 F1)', () => {
  const SIGNED_MS = 1_760_000_000_000; // the fake NSM's signed time
  const RESPONSE_HASH = sha256('BASE64VECTOR==');

  /** attest() from a freshly loaded attestor: an enclave just launched. */
  async function launchedAttest() {
    vi.resetModules();
    const { attest: fresh } = await import('../attestor.js');
    return () => fresh('ec.europa.eu/checkVatService', 'POST', 'BASE64VECTOR==', 'https://ec.europa.eu/x', { countryCode: 'PT' });
  }

  it('the first attestation after a launch signs the enclave clock as it is (lock)', async () => {
    vi.useFakeTimers({ now: SIGNED_MS - 90_000 });
    const doc = await (await launchedAttest())();
    expect(doc.timestamp).toBe((SIGNED_MS - 90_000) / 1000);
    expect(doc.nonce).toBe(sha256(`${RESPONSE_HASH}|ec.europa.eu/checkVatService|${doc.timestamp}`));
  });

  it.each([
    ['90 s behind', -90_000],
    ['2 min ahead', 120_000],
  ])('an enclave clock %s: the next attestation signs the clock plus the gap its last document showed (red)', async (_label, offBy) => {
    vi.useFakeTimers({ now: SIGNED_MS + offBy });
    const attestNow = await launchedAttest();
    await attestNow();
    const second = await attestNow();
    expect(second.timestamp).toBe(SIGNED_MS / 1000);
    expect(second.nonce).toBe(sha256(`${RESPONSE_HASH}|ec.europa.eu/checkVatService|${SIGNED_MS / 1000}`));
    // The clock moves on, and the gap goes with it: the time is the clock plus the gap, not the last signed time.
    vi.advanceTimersByTime(30_000);
    expect((await attestNow()).timestamp).toBe(SIGNED_MS / 1000 + 30);
  });

  it('a signed time the NSM encodes as a bignum is read too (red)', async () => {
    fake.current = createFakeNsm(BigInt(SIGNED_MS));
    vi.useFakeTimers({ now: SIGNED_MS - 90_000 });
    const attestNow = await launchedAttest();
    await attestNow();
    expect((await attestNow()).timestamp).toBe(SIGNED_MS / 1000);
  });

  it.each([
    ['no signed time', null],
    ['a signed time of 0', 0],
    ['a signed time that is not a whole number', 1_760_000_000_000.5],
  ])('a document with %s is refused, and sets no gap (red)', async (_label, signed) => {
    fake.current = createFakeNsm(signed);
    vi.useFakeTimers({ now: SIGNED_MS - 90_000 });
    const attestNow = await launchedAttest();
    await expect(attestNow()).rejects.toThrow('NSM document has no valid signed timestamp');
    fake.current = createFakeNsm();
    expect((await attestNow()).timestamp).toBe((SIGNED_MS - 90_000) / 1000);
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
