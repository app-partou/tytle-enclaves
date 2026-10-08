/**
 * The Stripe handler through the REAL handler factory (P2.4). It replaces the suite that re-implemented
 * createHandler inline (audit 2026-07 §6.4, still true in 2026-10).
 *
 * MOCK BOUNDARY: the enclave's two boundaries only - the vsock socket to the host's proxy (and the TLS layer
 * over it) and the NSM device (shared/src/__tests__/helpers/fakeEnclaveIo.ts). createHandler, ctx.fetch, the
 * HTTP framing, the answer rules, the BN254 encoder and attest() all run for real.
 *
 * WHY (audit 2026-10 P1.4 and the caller-input row): the handler signed ANY Stripe 404 as "not found" (a path Stripe
 * does not know, a proxy's page), a single object without checking it was the one asked, a list it could not read as
 * an empty one, and a Stripe-Account value nobody checked. And the signed answer never carried Stripe's body, so the
 * data a caller needs (the charges) could not be read as attested data at all: only its hash was signed. Now each of
 * those is an error or a 400, and the body travels beside the signed answer (upstreamBody).
 *
 * Labels: "lock" = the behaviour of the release before this one, kept; "red" = fails on that release.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';

vi.mock('@tytle-enclaves/native', async () => (await import('../../../shared/src/__tests__/helpers/fakeEnclaveIo.js')).nativeModule);
vi.mock('node:tls', async () => (await import('../../../shared/src/__tests__/helpers/fakeEnclaveIo.js')).tlsModule);

import { createHandler } from '@tytle-enclaves/shared';
import type { EnclaveResponse } from '@tytle-enclaves/shared';
import { encodeFieldElements, hashFieldElements, STRIPE_PAYMENT_SCHEMA } from '../../../shared/src/bn254Codec.js';
import { fakeIo, httpReply } from '../../../shared/src/__tests__/helpers/fakeEnclaveIo.js';
import { stripePaymentHandlerDef, STRIPE_HOSTS } from '../stripePaymentHandler.js';
import { HANDLER_MANIFEST, MANIFEST_HASH } from '../manifest.js';

/**
 * Stripe's answers, shaped after its API reference (docs.stripe.com/api: the list object, the Charge, PaymentIntent and
 * Account objects, the error object) - NOT recorded: recording needs Tytle's Stripe key (the G3 capture records real
 * answers). The rules under test read only documented fields: object, id, data, has_more and error.code.
 */
const CHARGE = { id: 'ch_3Pexample1', object: 'charge', amount: 5000, currency: 'eur', status: 'succeeded' };
const LIST_CHARGES = JSON.stringify({ object: 'list', data: [CHARGE, { ...CHARGE, id: 'ch_3Pexample2' }], has_more: true, url: '/v1/charges' });
const EMPTY_LIST = JSON.stringify({ object: 'list', data: [], has_more: false, url: '/v1/customers' });
const ONE_CHARGE = JSON.stringify(CHARGE);
const ACCOUNT = JSON.stringify({ id: 'acct_1Nv0FGQ9RKHgCVdK', object: 'account', country: 'US', charges_enabled: false });
const PAYMENT_INTENT = JSON.stringify({ id: 'pi_3Pexample1', object: 'payment_intent', amount: 5000, currency: 'eur', status: 'succeeded' });
/** Stripe's "no such object" error (code resource_missing, docs.stripe.com/error-codes); the message wording is illustrative. */
const NO_SUCH_CHARGE = JSON.stringify({ error: { code: 'resource_missing', doc_url: 'https://stripe.com/docs/error-codes/resource-missing', message: "No such charge: 'ch_missing'", param: 'id', type: 'invalid_request_error' } });
/** A 404 for a path Stripe does not know: an invalid_request_error with no code (wording illustrative). */
const UNKNOWN_PATH = JSON.stringify({ error: { message: 'Unrecognized request URL (GET: /v1/chargez).', type: 'invalid_request_error' } });

const STRIPE_PORT = 8446;
const API_KEY = 'sk_test_51Example00000000000000';
const ACCT = 'acct_1Example0Connected';
const json = (status: number, body: string, headers: Record<string, string> = {}) => httpReply(status, body, { 'Content-Type': 'application/json', ...headers });

const handler = createHandler(stripePaymentHandlerDef, STRIPE_HOSTS);

function call(body: unknown): Promise<EnclaveResponse> {
  return handler({ id: 'req-1', url: 'https://api.stripe.com/v1/charges', method: 'POST', headers: {}, body: typeof body === 'string' ? body : JSON.stringify(body) });
}

/** The SHA-256 hex of an upstream body: the value the handler signs as dataHash. */
const sha256 = (body: string) => createHash('sha256').update(body, 'utf8').digest('hex');

function signed(values: Record<string, string | number | null>) {
  const vector = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, values);
  return { base64: vector.toString('base64'), hash: hashFieldElements(vector) };
}

async function expectError(body: unknown, error: RegExp) {
  const res = await call(body);
  expect(res).toMatchObject({ success: false, status: 502 });
  expect(res.error).toMatch(error);
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
    ['no operation', { apiKey: API_KEY }, /Invalid operation/],
    ['an unsupported operation', { operation: 'delete_all', apiKey: API_KEY }, /Invalid operation/],
    ['no apiKey', { operation: 'list_charges' }, /apiKey is required/],
    ['get_charge without resourceId', { operation: 'get_charge', apiKey: API_KEY }, /get_charge requires resourceId/],
    ['get_payment_intent without resourceId', { operation: 'get_payment_intent', apiKey: API_KEY }, /get_payment_intent requires resourceId/],
    ['get_account without resourceId', { operation: 'get_account', apiKey: API_KEY }, /get_account requires resourceId/],
  ])('%s is a 400, and nothing is fetched', async (_label, body, error) => {
    const res = await call(body);
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toMatch(error);
    expect(fakeIo.requests(STRIPE_PORT)).toEqual([]);
  });
});

describe('a value Stripe is never asked with is a 400 before anything is fetched (red)', () => {
  it.each([
    ['a stripeAccount that is not an account id', { operation: 'list_charges', apiKey: API_KEY, stripeAccount: 'cus_123' }, /Invalid stripeAccount/],
    ['a stripeAccount with a line break', { operation: 'list_charges', apiKey: API_KEY, stripeAccount: `${ACCT}\r\nX-Other: 1` }, /Invalid stripeAccount/],
    ['a stripeAccount that is not text', { operation: 'list_charges', apiKey: API_KEY, stripeAccount: 42 }, /stripeAccount must be text/],
    ['an apiKey that is not text', { operation: 'list_charges', apiKey: { key: API_KEY } }, /apiKey is required/],
    ['a resourceId that is not text', { operation: 'get_charge', apiKey: API_KEY, resourceId: 42 }, /resourceId must be text/],
    ['a query value that is not text', { operation: 'list_charges', apiKey: API_KEY, queryParams: { limit: 100 } }, /queryParams\.limit must be text/],
    ['queryParams that are not an object', { operation: 'list_charges', apiKey: API_KEY, queryParams: ['limit=100'] }, /queryParams must be an object/],
  ])('%s', async (_label, body, error) => {
    const res = await call(body);
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toMatch(error);
    expect(fakeIo.requests(STRIPE_PORT)).toEqual([]);
  });
});

describe('lists', () => {
  it('a connected account\'s charges: the vector, the request Stripe got, and what the NSM signed (lock)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES, { 'Stripe-Account': ACCT }));
    const res = await call({ operation: 'list_charges', apiKey: API_KEY, stripeAccount: ACCT, queryParams: { limit: '2', 'created[gte]': '1700000000' } });

    const want = signed({ operation: 'list_charges', accountId: ACCT, objectType: 'list', dataHash: sha256(LIST_CHARGES), totalCount: 2, hasMore: 1 });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64, bn254: want.base64 });
    expect(res.headers).toMatchObject({
      'x-stripe-operation': 'list_charges', 'x-stripe-account-id': ACCT, 'x-stripe-object-type': 'list',
      'x-stripe-data-hash': sha256(LIST_CHARGES), 'x-stripe-total-count': '2', 'x-stripe-has-more': '1',
      'x-stripe-payment-manifest-hash': MANIFEST_HASH,
    });
    expect(res.bn254Headers).toEqual({ 'x-stripe-data-hash': sha256(LIST_CHARGES) });
    expect(fakeIo.nsmAsks.map((a) => a.userData?.toString('hex'))).toEqual([want.hash]);

    const [request] = fakeIo.requests(STRIPE_PORT);
    expect(request).toMatch(/^GET \/v1\/charges\?limit=2&created%5Bgte%5D=1700000000 HTTP\/1\.1\r\n/);
    expect(request).toContain(`Authorization: Bearer ${API_KEY}\r\n`);
    expect(request).toContain('Stripe-Version: 2025-12-15.clover\r\n');
    expect(request).toContain(`Stripe-Account: ${ACCT}\r\n`);
  });

  it('the attested request names the call and the manifest, never the API key (lock)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    const res = await call({ operation: 'list_charges', apiKey: API_KEY, stripeAccount: ACCT });
    const requestHeaders = { 'Content-Type': 'application/x-www-form-urlencoded', 'Stripe-Version': '2025-12-15.clover', 'Stripe-Account': ACCT, 'x-manifest-hash': MANIFEST_HASH };
    const requestConfig = `https://api.stripe.com/v1/charges|GET|${JSON.stringify(requestHeaders)}`;
    expect(res.attestation?.requestHash).toBe(createHash('sha256').update(requestConfig).digest('hex'));
    expect(res.attestation?.apiEndpoint).toBe('api.stripe.com/v1/charges');
    expect(JSON.stringify(res)).not.toContain(API_KEY);
  });

  it('an empty list on the platform\'s own account: no Stripe-Account sent, accountId null, hasMore 0 (lock)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, EMPTY_LIST));
    const res = await call({ operation: 'list_customers', apiKey: API_KEY });
    const want = signed({ operation: 'list_customers', accountId: null, objectType: 'list', dataHash: sha256(EMPTY_LIST), totalCount: 0, hasMore: 0 });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64 });
    const [request] = fakeIo.requests(STRIPE_PORT);
    expect(request).toMatch(/^GET \/v1\/customers HTTP\/1\.1\r\n/);
    expect(request).not.toContain('Stripe-Account');
  });

  it('a list without its data array is an error, never signed as an empty list (red)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, JSON.stringify({ object: 'list', has_more: false, url: '/v1/charges' })));
    await expectError({ operation: 'list_charges', apiKey: API_KEY }, /a list without its data array and has_more/);
  });

  it('a list without has_more is an error (red)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, JSON.stringify({ object: 'list', data: [], url: '/v1/charges' })));
    await expectError({ operation: 'list_charges', apiKey: API_KEY }, /a list without its data array and has_more/);
  });
});

describe('single objects', () => {
  it('get_charge: the URL-encoded id in the path, signed as a charge (lock)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, JSON.stringify({ ...CHARGE, id: 'ch_a/b' })));
    const res = await call({ operation: 'get_charge', apiKey: API_KEY, resourceId: 'ch_a/b' });
    const body = JSON.stringify({ ...CHARGE, id: 'ch_a/b' });
    const want = signed({ operation: 'get_charge', accountId: null, objectType: 'charge', dataHash: sha256(body), totalCount: 0, hasMore: 0 });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64 });
    const [request] = fakeIo.requests(STRIPE_PORT);
    expect(request).toMatch(/^GET \/v1\/charges\/ch_a%2Fb HTTP\/1\.1\r\n/);
  });

  it('get_account and get_payment_intent: their paths and object types (lock)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, ACCOUNT));
    fakeIo.reply(STRIPE_PORT, json(200, PAYMENT_INTENT, { 'Stripe-Account': ACCT }));
    const account = await call({ operation: 'get_account', apiKey: API_KEY, resourceId: 'acct_1Nv0FGQ9RKHgCVdK' });
    const intent = await call({ operation: 'get_payment_intent', apiKey: API_KEY, stripeAccount: ACCT, resourceId: 'pi_3Pexample1' });
    expect(account.headers['x-stripe-object-type']).toBe('account');
    expect(intent.headers['x-stripe-object-type']).toBe('payment_intent');
    const [first, second] = fakeIo.requests(STRIPE_PORT);
    expect(first).toMatch(/^GET \/v1\/accounts\/acct_1Nv0FGQ9RKHgCVdK HTTP\/1\.1\r\n/);
    expect(second).toMatch(/^GET \/v1\/payment_intents\/pi_3Pexample1 HTTP\/1\.1\r\n/);
  });

  it.each([
    ['get_charge', 'ch_asked', ONE_CHARGE],
    ['get_account', 'acct_asked', ACCOUNT],
    ['get_payment_intent', 'pi_asked', PAYMENT_INTENT],
  ])('%s answered with another object is an error, never signed (red)', async (operation, resourceId, body) => {
    fakeIo.reply(STRIPE_PORT, json(200, body));
    await expectError({ operation, apiKey: API_KEY, resourceId }, /not the object asked/);
  });

  it('an object of another type is an error (lock)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, PAYMENT_INTENT));
    await expectError({ operation: 'get_charge', apiKey: API_KEY, resourceId: 'pi_3Pexample1' }, /expected "charge", got "payment_intent"/);
  });
});

describe('the account the answer belongs to', () => {
  it('Stripe\'s answer names another account than the one asked: an error, never signed (red)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES, { 'Stripe-Account': 'acct_1Example0Other' }));
    await expectError({ operation: 'list_charges', apiKey: API_KEY, stripeAccount: ACCT }, /Stripe answered for account acct_1Example0Other, not the one asked/);
  });

  it('an answer that names no account keeps the one asked: Stripe refuses an account the key cannot act as (lock)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    const res = await call({ operation: 'list_charges', apiKey: API_KEY, stripeAccount: ACCT });
    expect(res.headers['x-stripe-account-id']).toBe(ACCT);
  });

  it('a request that names no account signs none, whatever the answer names (lock)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES, { 'Stripe-Account': ACCT }));
    const res = await call({ operation: 'list_charges', apiKey: API_KEY });
    const want = signed({ operation: 'list_charges', accountId: null, objectType: 'list', dataHash: sha256(LIST_CHARGES), totalCount: 2, hasMore: 1 });
    expect(res.rawBody).toBe(want.base64);
  });
});

describe('404', () => {
  it('Stripe\'s own "no such object" (resource_missing) is signed as not_found (lock)', async () => {
    fakeIo.reply(STRIPE_PORT, json(404, NO_SUCH_CHARGE, { 'Stripe-Account': ACCT }));
    const res = await call({ operation: 'get_charge', apiKey: API_KEY, stripeAccount: ACCT, resourceId: 'ch_missing' });
    const want = signed({ operation: 'get_charge', accountId: ACCT, objectType: 'not_found', dataHash: sha256(NO_SUCH_CHARGE), totalCount: 0, hasMore: 0 });
    expect(res).toMatchObject({ success: true, status: 404, rawBody: want.base64 });
    expect(res.headers['x-stripe-object-type']).toBe('not_found');
    expect(fakeIo.nsmAsks).toHaveLength(1);
  });

  it('a 404 for a path Stripe does not know (no error code) is an error, never signed (red)', async () => {
    fakeIo.reply(STRIPE_PORT, json(404, UNKNOWN_PATH));
    await expectError({ operation: 'get_charge', apiKey: API_KEY, resourceId: 'ch_missing' }, /Stripe answered 404 without its "resource_missing" code \(code: none\)/);
  });

  it('a 404 page that is not Stripe\'s JSON (a proxy\'s) is an error (red)', async () => {
    fakeIo.reply(STRIPE_PORT, httpReply(404, '<html><body>Not Found</body></html>', { 'Content-Type': 'text/html' }));
    await expectError({ operation: 'get_charge', apiKey: API_KEY, resourceId: 'ch_missing' }, /without its "resource_missing" code/);
  });

  it('a 404 for another account than the one asked is an error (red)', async () => {
    fakeIo.reply(STRIPE_PORT, json(404, NO_SUCH_CHARGE, { 'Stripe-Account': 'acct_1Example0Other' }));
    await expectError({ operation: 'get_charge', apiKey: API_KEY, stripeAccount: ACCT, resourceId: 'ch_missing' }, /not the one asked/);
  });
});

describe('the signed answer carries Stripe\'s body: its SHA-256 is the signed dataHash (red)', () => {
  it('a list', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    const res = await call({ operation: 'list_charges', apiKey: API_KEY });
    expect(res.upstreamBody).toBe(LIST_CHARGES);
    expect(sha256(res.upstreamBody ?? '')).toBe(res.bn254Headers?.['x-stripe-data-hash']);
  });

  it('a "no such object" 404', async () => {
    fakeIo.reply(STRIPE_PORT, json(404, NO_SUCH_CHARGE));
    const res = await call({ operation: 'get_charge', apiKey: API_KEY, resourceId: 'ch_missing' });
    expect(res.upstreamBody).toBe(NO_SUCH_CHARGE);
  });
});

describe('Stripe could not answer: passed on unsigned, or an error (lock)', () => {
  it.each([
    [429, '{"error":{"type":"rate_limit_error"}}'],
    [500, '{"error":{"type":"api_error"}}'],
    [401, '{"error":{"type":"invalid_request_error","message":"Invalid API Key provided"}}'],
    [403, '{"error":{"code":"account_invalid","type":"invalid_request_error"}}'],
  ])('HTTP %i is passed on as Stripe sent it, without a signature or a body beside it', async (status, body) => {
    fakeIo.reply(STRIPE_PORT, json(status, body));
    const res = await call({ operation: 'list_charges', apiKey: API_KEY, stripeAccount: ACCT });
    expect(res).toMatchObject({ success: true, status, rawBody: body });
    expect(res.attestation).toBeUndefined();
    expect(res.upstreamBody).toBeUndefined();
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });

  it('a body that is not JSON is an error', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, 'not json'));
    await expectError({ operation: 'list_charges', apiKey: API_KEY }, /Stripe API returned invalid JSON/);
  });

  it('a reply cut short (fewer bytes than its Content-Length) is an error', async () => {
    fakeIo.reply(STRIPE_PORT, `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${LIST_CHARGES.length + 10}\r\n\r\n${LIST_CHARGES}`);
    const res = await call({ operation: 'list_charges', apiKey: API_KEY });
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });
});

describe('a JSON body that is not an object (red: it read as a wrong object type)', () => {
  it('is an error that says so', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, '[]'));
    await expectError({ operation: 'list_charges', apiKey: API_KEY }, /Stripe API returned JSON that is not an object/);
  });
});

describe('manifest (lock)', () => {
  it('declares the STRIPE_PAYMENT_SCHEMA fields in order, and their size', () => {
    expect(HANDLER_MANIFEST.schema.fields.map((f) => [f.name, f.encoding])).toEqual(STRIPE_PAYMENT_SCHEMA.map((f) => [f.name, f.encoding]));
    expect(HANDLER_MANIFEST.schema.outputBytes).toBe(STRIPE_PAYMENT_SCHEMA.length * 32);
  });
});
