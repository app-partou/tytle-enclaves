/**
 * The real handler factory with a minimal handler definition: the request's challenge must reach the
 * signed nonce, and a malformed one must stop the request before anything is fetched or signed.
 * Only the NSM device (helpers/fakeNsm.ts) and the upstream fetch (the def's execute, not called on refusal) are stand-ins.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'node:crypto';
import { createFakeNsm } from './helpers/fakeNsm.js';

const { fake } = vi.hoisted(() => ({ fake: { current: null as ReturnType<typeof import('./helpers/fakeNsm.js').createFakeNsm> | null } }));
vi.mock('@tytle-enclaves/native', () => ({
  nsmRequest: (request: Buffer) => fake.current!.nsmRequest(request),
}));

import { createHandler, type HandlerDef } from '../handlerFactory.js';
import type { EnclaveRequest } from '../types.js';

const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const CHALLENGE = '0123456789abcdef'.repeat(4);

const execute = vi.fn(async () => ({
  values: { countryCode: 'PT', vatNumber: '509178944', valid: 1, name: 'X', address: 'Y' },
  apiEndpoint: 'ec.europa.eu/taxation_customs/vies/services/checkVatService',
  method: 'POST',
  url: 'https://ec.europa.eu/taxation_customs/vies/services/checkVatService',
  requestHeaders: { countryCode: 'PT', vatNumber: '509178944' },
  responseHeaders: {},
}));

const def: HandlerDef<Record<string, unknown>> = {
  name: 'test',
  schema: [
    { name: 'countryCode', encoding: 'shortString' },
    { name: 'vatNumber', encoding: 'shortString' },
    { name: 'valid', encoding: 'uint', jsType: 'boolean' },
    { name: 'name', encoding: 'sha256' },
    { name: 'address', encoding: 'sha256' },
  ],
  manifestHash: 'm'.repeat(64),
  policies: [],
  requiredHosts: [],
  parseParams: (body) => body as Record<string, unknown>,
  execute,
};

const handler = createHandler(def, []);

function request(extra: Partial<EnclaveRequest> = {}): EnclaveRequest {
  return { id: 'r1', url: 'https://ec.europa.eu/x', method: 'POST', headers: {}, body: '{}', ...extra };
}

beforeEach(() => {
  fake.current = createFakeNsm();
  execute.mockClear();
});

describe('createHandler and the caller challenge', () => {
  it('without a challenge the answer carries nonce version 1 (lock: today\'s parent sends none)', async () => {
    const res = await handler(request());
    expect(res.success).toBe(true);
    const att = res.attestation!;
    expect(att.nonce).toBe(sha256(`${att.responseHash}|${att.apiEndpoint}|${att.timestamp}`));
    expect(att).not.toHaveProperty('challenge');
    // What the NSM was asked to sign: that nonce, the BN254 hash as user_data, no public key.
    const ask = fake.current!.asks[0];
    expect(ask.nonce?.toString('hex')).toBe(att.nonce);
    expect(ask.userData?.toString('hex')).toBe(att.bn254Hash);
    expect(att.bn254Hash).toBe(crypto.createHash('sha256').update(Buffer.from(res.bn254!, 'base64')).digest('hex'));
    expect(ask.publicKey).toBeNull();
  });

  it('the request\'s challenge is signed into the nonce and echoed (version 2)', async () => {
    const res = await handler(request({ challenge: CHALLENGE }));
    expect(res.success).toBe(true);
    const att = res.attestation!;
    expect(att.nonceVersion).toBe(2);
    expect(att.challenge).toBe(CHALLENGE);
    expect(att.nonce).toBe(sha256(`${att.responseHash}|${att.apiEndpoint}|${att.timestamp}|${CHALLENGE}`));
    expect(fake.current!.asks[0].nonce?.toString('hex')).toBe(att.nonce);
  });

  it.each([
    ['a number', 42],
    ['null', null],
  ])('a challenge that is %s (not text) is a 400 before anything is signed', async (_label, challenge) => {
    const res = await handler(request({ challenge: challenge as unknown as string }));
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(execute).not.toHaveBeenCalled();
    expect(fake.current!.asks).toHaveLength(0);
  });

  it('a malformed challenge is a 400 before the upstream is called or anything is signed', async () => {
    const res = await handler(request({ challenge: 'NOT-HEX' }));
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toMatch(/^Invalid request: challenge must be 32 bytes of lowercase hex/);
    expect(execute).not.toHaveBeenCalled();
    expect(fake.current!.asks).toHaveLength(0);
  });
});
