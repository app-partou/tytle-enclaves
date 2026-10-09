/**
 * The Monerium handler through the REAL handler factory (P2.4). It replaces the suite that re-implemented
 * createHandler inline (audit 2026-07 §6.4, still true in 2026-10).
 *
 * MOCK BOUNDARY: the enclave's two boundaries only - the vsock sockets to the host's proxies (and the TLS layer
 * over them) and the NSM device (shared/src/__tests__/helpers/fakeEnclaveIo.ts). createHandler, ctx.fetch, the
 * HTTP framing, the answer rules, the BN254 encoder and attest() all run for real.
 *
 * WHY (audit 2026-10 P1.4 and the caller-input row): the handler fetched any orderId it was given, signed an order
 * without checking it was the one asked, signed ANY JSON 404 as "not found", and signed a balance from a JSON-RPC
 * answer to another call. Now each of those is a 400 or an error, never signed.
 *
 * Labels: "lock" = the behaviour of the release before this one, kept; "red" = fails on that release.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';

vi.mock('@tytle-enclaves/native', async () => (await import('../../../shared/src/__tests__/helpers/fakeEnclaveIo.js')).nativeModule);
vi.mock('node:tls', async () => (await import('../../../shared/src/__tests__/helpers/fakeEnclaveIo.js')).tlsModule);

import { createHandler } from '@tytle-enclaves/shared';
import type { EnclaveResponse } from '@tytle-enclaves/shared';
import { encodeFieldElements, hashFieldElements, MONERIUM_PAYMENT_SCHEMA } from '../../../shared/src/bn254Codec.js';
import { fakeIo, httpReply } from '../../../shared/src/__tests__/helpers/fakeEnclaveIo.js';
import { moneriumPaymentHandlerDef, MONERIUM_HOSTS } from '../moneriumPaymentHandler.js';
import { HANDLER_MANIFEST, MANIFEST_HASH } from '../manifest.js';

/**
 * Monerium's order, shaped after its API reference (docs.monerium.com/api, the Order object of GET /orders/{orderId},
 * API version 2; the id and address are the reference's own examples, names and the IBAN are placeholders) - NOT
 * recorded: that needs a Monerium token. Its error body {code, status, message} is the reference's general one; no
 * 404 is documented for this call. The Gnosis answer is a JSON-RPC 2.0 eth_call result (one ABI word).
 */
const ORDER_ID = '8c0fd7b1-01da-11ed-89c1-52c47a86c354';
const ADDRESS = '0x59cFC408d310697f9D3598e1BE75B0157a072407';
function order(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    id: ORDER_ID, kind: 'issue', profile: 'a78d8ff2-e51f-11ed-9e13-cacb9390199c', address: ADDRESS, chain: 'gnosis',
    currency: 'eur', amount: '999',
    counterpart: { identifier: { standard: 'iban', iban: 'PT50000000000000000000000' }, details: { firstName: 'Example', lastName: 'Payer', country: 'PT' } },
    memo: 'Example payment', state: 'processed',
    meta: { placedAt: '2026-10-01T10:00:00.000000Z', processedAt: '2026-10-01T10:00:05.000000Z' },
    ...overrides,
  });
}
const NOT_FOUND = JSON.stringify({ code: 404, status: 'Not Found', message: 'Not Found' });
const BALANCE_WEI = 999n * 10n ** 18n;
const word = (n: bigint) => `0x${n.toString(16).padStart(64, '0')}`;
const rpc = (result: unknown, id: unknown = 1) => JSON.stringify({ jsonrpc: '2.0', id, result });

const MONERIUM_PORT = 8447;
const RPC_PORT = 8448;
const TOKEN = 'slBcjO-QTJGGMRbYTJHq8A';
const json = (status: number, body: string) => httpReply(status, body, { 'Content-Type': 'application/json' });

const handler = createHandler(moneriumPaymentHandlerDef, MONERIUM_HOSTS);

function call(body: unknown): Promise<EnclaveResponse> {
  return handler({ id: 'req-1', url: `https://api.monerium.app/orders/${ORDER_ID}`, method: 'POST', headers: {}, body: typeof body === 'string' ? body : JSON.stringify(body) });
}
const ask = (overrides: Record<string, unknown> = {}) => call({ operation: 'get_order_with_balance', accessToken: TOKEN, orderId: ORDER_ID, ...overrides });

/** The SHA-256 hex of a text: how the handler hashes the order id and the bodies it signs. */
const sha256 = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

function signed(values: Record<string, string | number | bigint | null>) {
  const vector = encodeFieldElements(MONERIUM_PAYMENT_SCHEMA, values);
  return { base64: vector.toString('base64'), hash: hashFieldElements(vector) };
}

async function expectError(result: Promise<EnclaveResponse>, error?: RegExp) {
  const res = await result;
  expect(res).toMatchObject({ success: false, status: 502 });
  if (error) expect(res.error).toMatch(error);
  expect(res.attestation).toBeUndefined();
  expect(fakeIo.nsmAsks).toHaveLength(0);
}

beforeEach(() => {
  fakeIo.reset();
  // The enclave logs one JSON line per request to stdout (shared/src/logger.ts).
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

describe('request validation (lock)', () => {
  it.each([
    ['not JSON', 'not json', /Invalid request/],
    ['no operation', { accessToken: TOKEN, orderId: ORDER_ID }, /Invalid operation/],
    ['an unsupported operation', { operation: 'get_balance', accessToken: TOKEN, orderId: ORDER_ID }, /Invalid operation/],
    ['no accessToken', { operation: 'get_order_with_balance', orderId: ORDER_ID }, /accessToken is required/],
    ['no orderId', { operation: 'get_order_with_balance', accessToken: TOKEN }, /orderId is required/],
  ])('%s is a 400, and nothing is fetched', async (_label, body, error) => {
    const res = await call(body);
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toMatch(error);
    expect(fakeIo.requests(MONERIUM_PORT).length + fakeIo.requests(RPC_PORT).length).toBe(0);
  });
});

describe('a value Monerium is never asked with is a 400 before anything is fetched (red)', () => {
  it.each([
    ['an orderId that is not a UUID', { orderId: 'test-order-id' }, /Invalid orderId: a Monerium order id is a UUID/],
    ['an orderId with a path in it', { orderId: `${ORDER_ID}/payments` }, /Invalid orderId/],
    ['an orderId that is not text', { orderId: 42 }, /Invalid orderId/],
    ['an accessToken that is not text', { accessToken: { token: TOKEN } }, /accessToken is required/],
  ])('%s', async (_label, overrides, error) => {
    const res = await ask(overrides);
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toMatch(error);
    expect(fakeIo.requests(MONERIUM_PORT).length + fakeIo.requests(RPC_PORT).length).toBe(0);
  });
});

describe('an order and its balance', () => {
  it('the vector, the two requests, and what the NSM signed (lock)', async () => {
    const orderBody = order();
    const rpcBody = rpc(word(BALANCE_WEI));
    fakeIo.reply(MONERIUM_PORT, json(200, orderBody));
    fakeIo.reply(RPC_PORT, json(200, rpcBody));
    const res = await ask();

    const dataHash = sha256(`${orderBody}\n${rpcBody}`);
    const want = signed({ orderId: ORDER_ID, state: 'processed', orderAmount: '999', currency: 'eur', balance: BALANCE_WEI, dataHash });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64, bn254: want.base64 });
    expect(res.headers).toMatchObject({
      'x-monerium-order-id': ORDER_ID, 'x-monerium-state': 'processed', 'x-monerium-order-amount': '999',
      'x-monerium-currency': 'eur', 'x-monerium-balance': BALANCE_WEI.toString(), 'x-monerium-data-hash': dataHash,
      'x-monerium-payment-manifest-hash': MANIFEST_HASH,
    });
    expect(res.bn254Headers).toEqual({ 'x-monerium-data-hash': dataHash });
    expect(fakeIo.nsmAsks.map((a) => a.userData?.toString('hex'))).toEqual([want.hash]);

    const [orderRequest] = fakeIo.requests(MONERIUM_PORT);
    expect(orderRequest).toMatch(new RegExp(`^GET /orders/${ORDER_ID} HTTP/1\\.1\\r\\n`));
    expect(orderRequest).toContain(`Authorization: Bearer ${TOKEN}\r\n`);
    expect(orderRequest).toContain('Accept: application/vnd.monerium.api-v2+json\r\n');
    const [rpcRequest] = fakeIo.requests(RPC_PORT);
    expect(rpcRequest).toMatch(/^POST \/ HTTP\/1\.1\r\n/);
    const rpcCall = JSON.parse(rpcRequest.slice(rpcRequest.indexOf('\r\n\r\n') + 4));
    expect(rpcCall).toEqual({
      jsonrpc: '2.0', method: 'eth_call', id: 1,
      params: [{ to: '0xcB444e90D8198415266c6a2724b7900fb12FC56E', data: `0x70a08231${ADDRESS.slice(2).toLowerCase().padStart(64, '0')}` }, 'latest'],
    });
  });

  it('the attested request names the order and the manifest, never the token (lock)', async () => {
    fakeIo.reply(MONERIUM_PORT, json(200, order()));
    fakeIo.reply(RPC_PORT, json(200, rpc(word(0n))));
    const res = await ask();
    const requestConfig = `https://api.monerium.app/orders/${ORDER_ID}|GET|${JSON.stringify({ Accept: 'application/vnd.monerium.api-v2+json', 'x-manifest-hash': MANIFEST_HASH })}`;
    expect(res.attestation?.requestHash).toBe(createHash('sha256').update(requestConfig).digest('hex'));
    expect(res.attestation?.apiEndpoint).toBe(`api.monerium.app/orders/${ORDER_ID}`);
    expect(JSON.stringify(res)).not.toContain(TOKEN);
  });

  it('a zero balance is signed as 0 (lock)', async () => {
    fakeIo.reply(MONERIUM_PORT, json(200, order({ state: 'pending' })));
    fakeIo.reply(RPC_PORT, json(200, rpc(word(0n))));
    const res = await ask();
    expect(res.headers).toMatchObject({ 'x-monerium-state': 'pending', 'x-monerium-balance': '0' });
  });

  it('another order than the one asked is an error, never signed (red)', async () => {
    fakeIo.reply(MONERIUM_PORT, json(200, order({ id: 'a78d8ff2-e51f-11ed-9e13-cacb9390199c' })));
    fakeIo.reply(RPC_PORT, json(200, rpc(word(BALANCE_WEI))));
    await expectError(ask(), /Monerium answered order a78d8ff2-e51f-11ed-9e13-cacb9390199c, not the one asked/);
  });

  it.each([
    ['an amount that is not text', { amount: 999 }, /no "amount" text/],
    ['a state that is not text', { state: ['processed'] }, /no "state" text/],
    ['a currency that is not text', { currency: 1 }, /no "currency" text/],
  ])('%s is an error (red)', async (_label, overrides, error) => {
    fakeIo.reply(MONERIUM_PORT, json(200, order(overrides)));
    fakeIo.reply(RPC_PORT, json(200, rpc(word(BALANCE_WEI))));
    await expectError(ask(), error);
  });

  it.each([
    ['no state', { state: undefined }],
    ['another chain', { chain: 'ethereum' }],
    ['an address that is not one', { address: '0x1234' }],
  ])('an order with %s is an error (lock)', async (_label, overrides) => {
    fakeIo.reply(MONERIUM_PORT, json(200, order(overrides)));
    fakeIo.reply(RPC_PORT, json(200, rpc(word(BALANCE_WEI))));
    await expectError(ask());
    expect(fakeIo.requests(RPC_PORT)).toEqual([]);
  });
});

describe('404', () => {
  it('Monerium\'s own error body with code 404 is signed as not_found, for the order asked (lock)', async () => {
    fakeIo.reply(MONERIUM_PORT, json(404, NOT_FOUND));
    const res = await ask();
    const want = signed({ orderId: ORDER_ID, state: 'not_found', orderAmount: null, currency: null, balance: 0, dataHash: sha256(NOT_FOUND) });
    expect(res).toMatchObject({ success: true, status: 404, rawBody: want.base64 });
    expect(fakeIo.requests(RPC_PORT)).toEqual([]);
  });

  it('a JSON 404 that is not Monerium\'s error body is an error, never signed (red)', async () => {
    fakeIo.reply(MONERIUM_PORT, json(404, JSON.stringify({ message: 'Not Found' })));
    await expectError(ask(), /Monerium answered 404 without its error body \(code 404\)/);
  });

  it('a 404 page that is not JSON (a proxy\'s) is an error (lock)', async () => {
    fakeIo.reply(MONERIUM_PORT, httpReply(404, '<html><body>Not Found</body></html>', { 'Content-Type': 'text/html' }));
    await expectError(ask());
  });
});

describe('the balance', () => {
  it.each([
    ['an HTTP error', () => json(500, '{}')],
    ['a JSON-RPC error', () => json(200, JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'execution reverted' } }))],
    ['a body that is not JSON', () => json(200, 'not json')],
    ['an empty result', () => json(200, rpc('0x'))],
  ])('%s is an error (lock)', async (_label, reply) => {
    fakeIo.reply(MONERIUM_PORT, json(200, order()));
    fakeIo.reply(RPC_PORT, reply());
    await expectError(ask());
  });

  it('an answer to another call (another JSON-RPC id) is an error (red)', async () => {
    fakeIo.reply(MONERIUM_PORT, json(200, order()));
    fakeIo.reply(RPC_PORT, json(200, rpc(word(BALANCE_WEI), 2)));
    await expectError(ask(), /Gnosis RPC answered call 2, not this one/);
  });

  it('a result that is not hex text is an error (red)', async () => {
    fakeIo.reply(MONERIUM_PORT, json(200, order()));
    fakeIo.reply(RPC_PORT, json(200, rpc(123)));
    await expectError(ask(), /balanceOf returned no uint256 result \(123\)/);
  });

  it('a result longer than one ABI word (65 hex digits) is an error that says so (red)', async () => {
    fakeIo.reply(MONERIUM_PORT, json(200, order()));
    fakeIo.reply(RPC_PORT, json(200, rpc(`0x1${'0'.repeat(64)}`)));
    await expectError(ask(), /balanceOf returned no uint256 result/);
  });
});

describe('an order body that is not a JSON object (red: it read as an order without an id)', () => {
  it('is an error that says so', async () => {
    fakeIo.reply(MONERIUM_PORT, json(200, '[]'));
    await expectError(ask(), /Monerium API returned JSON that is not an object/);
  });
});

describe('Monerium could not answer: passed on unsigned (lock)', () => {
  it.each([[429], [500], [401]])('HTTP %i is passed on as Monerium sent it, without a signature or a balance call', async (status) => {
    fakeIo.reply(MONERIUM_PORT, json(status, '{"code":0,"status":"error","message":"x"}'));
    const res = await ask();
    expect(res).toMatchObject({ success: true, status, rawBody: '{"code":0,"status":"error","message":"x"}' });
    expect(res.attestation).toBeUndefined();
    expect(fakeIo.nsmAsks).toHaveLength(0);
    expect(fakeIo.requests(RPC_PORT)).toEqual([]);
  });
});

describe('manifest (lock)', () => {
  it('declares the MONERIUM_PAYMENT_SCHEMA fields in order, and their size', () => {
    expect(HANDLER_MANIFEST.schema.fields.map((f) => [f.name, f.encoding])).toEqual(MONERIUM_PAYMENT_SCHEMA.map((f) => [f.name, f.encoding]));
    expect(HANDLER_MANIFEST.schema.outputBytes).toBe(MONERIUM_PAYMENT_SCHEMA.length * 32);
  });
});
