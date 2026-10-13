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

import { createHandler, getAttestOverrides, KMS_HOST, shouldSkipAttestation } from '@tytle-enclaves/shared';
import type { EnclaveResponse } from '@tytle-enclaves/shared';
import { encodeFieldElements, hashFieldElements, STRIPE_PAYMENT_SCHEMA } from '../../../shared/src/bn254Codec.js';
import { fakeIo, httpReply } from '../../../shared/src/__tests__/helpers/fakeEnclaveIo.js';
import { fakeKms } from '../../../shared/src/__tests__/helpers/fakeKms.js';
import { stripePaymentHandlerDef, STRIPE_HOSTS, SEALED_KEY_CONTEXT } from '../stripePaymentHandler.js';
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

/** The account a key belongs to, as Stripe's GET /v1/account answers it (docs.stripe.com/api/accounts/retrieve). */
const OWN_ACCOUNT_ID = 'acct_1Example0Platform';
const OWN_ACCOUNT = JSON.stringify({ id: OWN_ACCOUNT_ID, object: 'account', country: 'PT', charges_enabled: true });
const LIST_INVOICES = JSON.stringify({ object: 'list', data: [{ id: 'in_1Example', object: 'invoice', status: 'paid' }], has_more: false, url: '/v1/invoices' });

const STRIPE_PORT = 8446;
const API_KEY = 'sk_test_51Example00000000000000';
const ACCT = 'acct_1Example0Connected';
const json = (status: number, body: string, headers: Record<string, string> = {}) => httpReply(status, body, { 'Content-Type': 'application/json', ...headers });

const handler = createHandler(stripePaymentHandlerDef, STRIPE_HOSTS);
/** Stripe answers GET /v1/account: the key's own account, asked for an answer to sign when no Stripe-Account is named. */
const ownAccount = (body = OWN_ACCOUNT, status = 200) => fakeIo.reply(STRIPE_PORT, json(status, body));

function call(body: unknown): Promise<EnclaveResponse> {
  return handler({ id: 'req-1', url: 'https://api.stripe.com/v1/charges', method: 'POST', headers: {}, body: typeof body === 'string' ? body : JSON.stringify(body) });
}

/** The SHA-256 hex of an upstream body: the value the handler signs as dataHash. */
const sha256 = (body: string) => createHash('sha256').update(body, 'utf8').digest('hex');

function signed(values: Record<string, string | number | null>) {
  const vector = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, values);
  return { base64: vector.toString('base64'), hash: hashFieldElements(vector) };
}

/** The key mode a vector signs: its seventh field, livemode (1 = a live key, 0 = a test key). */
function signedLivemode(base64: string): number {
  const vector = Buffer.from(base64, 'base64');
  expect(vector.length, 'the vector holds seven fields').toBe(7 * 32);
  return Number(BigInt(`0x${vector.subarray(6 * 32).toString('hex')}`));
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
  it('a connected account\'s charges: the vector, the request Stripe got (its query keys in order), and what the NSM signed', async () => {
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
    expect(request).toMatch(/^GET \/v1\/charges\?created%5Bgte%5D=1700000000&limit=2 HTTP\/1\.1\r\n/);
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

  it('an empty list on the platform\'s own account: no Stripe-Account sent, accountId the key\'s own account, hasMore 0 (red: it signed a null account)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, EMPTY_LIST));
    ownAccount();
    const res = await call({ operation: 'list_customers', apiKey: API_KEY });
    const want = signed({ operation: 'list_customers', accountId: OWN_ACCOUNT_ID, objectType: 'list', dataHash: sha256(EMPTY_LIST), totalCount: 0, hasMore: 0 });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64 });
    const [request, accountRequest] = fakeIo.requests(STRIPE_PORT);
    expect(request).toMatch(/^GET \/v1\/customers HTTP\/1\.1\r\n/);
    expect(request).not.toContain('Stripe-Account');
    expect(accountRequest).toMatch(/^GET \/v1\/account HTTP\/1\.1\r\n/);
    expect(accountRequest).toContain(`Authorization: Bearer ${API_KEY}\r\n`);
    expect(accountRequest).not.toContain('Stripe-Account');
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

describe('the answer signs its question: the query is in the signed endpoint (enclave review 2026-10-09, H5; red)', () => {
  it('a list\'s query, its keys in code-unit order, is in the endpoint the nonce signs and in the request Stripe gets', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, LIST_INVOICES));
    const res = await call({
      operation: 'list_invoices', apiKey: API_KEY, stripeAccount: ACCT,
      queryParams: { status: 'paid', limit: '10', 'created[lte]': '1700000999', 'created[gte]': '1700000000' },
    });
    const query = 'created%5Bgte%5D=1700000000&created%5Blte%5D=1700000999&limit=10&status=paid';
    expect(res).toMatchObject({ success: true, status: 200 });
    expect(res.attestation?.apiEndpoint).toBe(`api.stripe.com/v1/invoices?${query}`);
    expect(fakeIo.requests(STRIPE_PORT)[0]).toMatch(new RegExp(`^GET /v1/invoices\\?${query} HTTP/1\\.1\\r\\n`));
  });

  it('two time windows are two signed questions, never the same answer', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    const a = await call({ operation: 'list_charges', apiKey: API_KEY, stripeAccount: ACCT, queryParams: { 'created[gte]': '1700000000' } });
    const b = await call({ operation: 'list_charges', apiKey: API_KEY, stripeAccount: ACCT, queryParams: { 'created[gte]': '1600000000' } });
    expect(a.attestation?.apiEndpoint).toBe('api.stripe.com/v1/charges?created%5Bgte%5D=1700000000');
    expect(b.attestation?.apiEndpoint).toBe('api.stripe.com/v1/charges?created%5Bgte%5D=1600000000');
  });
});

describe('a list is signed only as a list of the operation\'s objects (enclave review 2026-10-09, E2a F-12; red)', () => {
  it.each([
    ['list_charges', JSON.stringify({ object: 'list', data: [{ id: 'cus_1', object: 'customer' }], has_more: false }), 'charge'],
    ['list_customers', JSON.stringify({ object: 'list', data: [{ id: 'ch_1', object: 'charge' }], has_more: false }), 'customer'],
    ['list_invoices', JSON.stringify({ object: 'list', data: [{ id: 'in_1', object: 'invoice' }, 'in_2'], has_more: false }), 'invoice'],
  ])('%s with an item of another kind is an error', async (operation, body, kind) => {
    fakeIo.reply(STRIPE_PORT, json(200, body));
    await expectError({ operation, apiKey: API_KEY, stripeAccount: ACCT }, new RegExp(`an item that is not a ${kind}`));
  });
});

describe('the query keys each operation takes (enclave review 2026-10-09, E2a F-13; red: any key went to Stripe)', () => {
  it.each([
    ['expand[] on a list', { operation: 'list_charges', queryParams: { 'expand[]': 'data.customer' } }, /queryParams\.expand\[\] is not a query list_charges takes/],
    ['a filter list_charges does not take', { operation: 'list_charges', queryParams: { email: 'a@example.com' } }, /queryParams\.email is not a query list_charges takes/],
    ['an invoice status on charges', { operation: 'list_charges', queryParams: { status: 'paid' } }, /queryParams\.status is not a query list_charges takes/],
    ['any query on a single object', { operation: 'get_charge', resourceId: 'ch_1', queryParams: { limit: '1' } }, /queryParams\.limit is not a query get_charge takes/],
    ['a page larger than 100', { operation: 'list_charges', queryParams: { limit: '101' } }, /queryParams\.limit is not a valid value/],
    ['a time that is not Unix seconds', { operation: 'list_charges', queryParams: { 'created[gte]': '2026-10-01' } }, /queryParams\.created\[gte\] is not a valid value/],
    ['a cursor that is not an object id', { operation: 'list_customers', queryParams: { starting_after: 'cus_1&expand[]=x' } }, /queryParams\.starting_after is not a valid value/],
    ['an invoice status Stripe does not have', { operation: 'list_invoices', queryParams: { status: 'paid,open' } }, /queryParams\.status is not a valid value/],
  ])('%s is a 400, and nothing is fetched', async (_label, body, error) => {
    const res = await call({ apiKey: API_KEY, ...body });
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toMatch(error);
    expect(fakeIo.requests(STRIPE_PORT)).toEqual([]);
  });

  it.each([
    ['list_charges', { limit: '100', starting_after: 'ch_3Pexample1', 'created[gte]': '1700000000', 'created[lt]': '1700009999' }],
    ['list_customers', { limit: '1', ending_before: 'cus_1Example' }],
    ['list_invoices', { status: 'uncollectible', 'created[gt]': '0', 'created[lte]': '1700000000' }],
  ])('%s takes its paging, its time window and (invoices) its status (lock)', async (operation, queryParams) => {
    fakeIo.reply(STRIPE_PORT, json(200, JSON.stringify({ object: 'list', data: [], has_more: false })));
    const res = await call({ operation, apiKey: API_KEY, stripeAccount: ACCT, queryParams });
    expect(res).toMatchObject({ success: true, status: 200 });
  });
});

describe('single objects', () => {
  it('get_charge: the URL-encoded id in the path, signed as a charge, on the key\'s own account (red: a null account)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, JSON.stringify({ ...CHARGE, id: 'ch_a/b' })));
    ownAccount();
    const res = await call({ operation: 'get_charge', apiKey: API_KEY, resourceId: 'ch_a/b' });
    const body = JSON.stringify({ ...CHARGE, id: 'ch_a/b' });
    const want = signed({ operation: 'get_charge', accountId: OWN_ACCOUNT_ID, objectType: 'charge', dataHash: sha256(body), totalCount: 0, hasMore: 0 });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64 });
    const [request] = fakeIo.requests(STRIPE_PORT);
    expect(request).toMatch(/^GET \/v1\/charges\/ch_a%2Fb HTTP\/1\.1\r\n/);
  });

  it('get_account and get_payment_intent: their paths and object types; the first, with no Stripe-Account, asks the key\'s own account', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, ACCOUNT));
    ownAccount();
    fakeIo.reply(STRIPE_PORT, json(200, PAYMENT_INTENT, { 'Stripe-Account': ACCT }));
    const account = await call({ operation: 'get_account', apiKey: API_KEY, resourceId: 'acct_1Nv0FGQ9RKHgCVdK' });
    const intent = await call({ operation: 'get_payment_intent', apiKey: API_KEY, stripeAccount: ACCT, resourceId: 'pi_3Pexample1' });
    expect(account.headers['x-stripe-object-type']).toBe('account');
    expect(intent.headers['x-stripe-object-type']).toBe('payment_intent');
    const [first, accountRequest, second] = fakeIo.requests(STRIPE_PORT);
    expect(first).toMatch(/^GET \/v1\/accounts\/acct_1Nv0FGQ9RKHgCVdK HTTP\/1\.1\r\n/);
    expect(accountRequest).toMatch(/^GET \/v1\/account HTTP\/1\.1\r\n/);
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

  it('a request that names no account signs the key\'s own account, whatever the answer\'s header names (red: it signed none)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES, { 'Stripe-Account': ACCT }));
    ownAccount();
    const res = await call({ operation: 'list_charges', apiKey: API_KEY });
    const want = signed({ operation: 'list_charges', accountId: OWN_ACCOUNT_ID, objectType: 'list', dataHash: sha256(LIST_CHARGES), totalCount: 2, hasMore: 1 });
    expect(res.rawBody).toBe(want.base64);
  });

  it('another key answers: its own account is signed, so its answer never reads as this key\'s (red: both signed a null account)', async () => {
    fakeIo.reply(STRIPE_PORT, json(404, NO_SUCH_CHARGE));
    ownAccount(JSON.stringify({ id: 'acct_1Example0Another', object: 'account' }));
    const res = await call({ operation: 'get_charge', apiKey: 'sk_test_51Another0000000000000', resourceId: 'ch_missing' });
    expect(res).toMatchObject({ success: true, status: 404 });
    expect(res.headers['x-stripe-account-id']).toBe('acct_1Example0Another');
    expect(fakeIo.requests(STRIPE_PORT)[1]).toContain('Authorization: Bearer sk_test_51Another0000000000000\r\n');
  });

  it.each([
    ['an HTTP 401', 401, '{"error":{"type":"invalid_request_error","message":"Invalid API Key provided"}}'],
    ['an HTTP 500 that carries an account', 500, OWN_ACCOUNT],
    ['an object that is not an account', 200, JSON.stringify({ id: 'acct_1Example0Platform', object: 'customer' })],
    ['an account without an account id', 200, JSON.stringify({ id: 'cus_1Example', object: 'account' })],
    ['a body that is not JSON', 200, 'not json'],
  ])('the key\'s own account answered with %s: an error, never a null account (red)', async (_label, status, body) => {
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    ownAccount(body, status);
    await expectError({ operation: 'list_charges', apiKey: API_KEY }, /the key's own account/);
  });

  it('a named Stripe-Account is the account: the key\'s own one is never asked (lock)', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    await call({ operation: 'list_charges', apiKey: API_KEY, stripeAccount: ACCT });
    expect(fakeIo.requests(STRIPE_PORT)).toHaveLength(1);
  });

  it('an answer that is not signed asks no account (lock)', async () => {
    fakeIo.reply(STRIPE_PORT, json(429, '{"error":{"type":"rate_limit_error"}}'));
    const res = await call({ operation: 'list_charges', apiKey: API_KEY });
    expect(res).toMatchObject({ success: true, status: 429 });
    expect(fakeIo.requests(STRIPE_PORT)).toHaveLength(1);
  });
});

describe('the answer signs the mode of the key it asked with (enclave review 2026-10-09, E-3; red: the vector named no mode)', () => {
  const LIVE_KEY = 'sk_live_51Example00000000000000';
  /**
   * What a test key gets for a live object: Stripe's own resource_missing (docs.stripe.com/keys: "Objects in one mode
   * aren't accessible to the other"). The wording is illustrative: the handler reads only the code.
   */
  const NO_SUCH_LIVE_CHARGE = JSON.stringify({ error: { code: 'resource_missing', message: "No such charge: 'ch_3Plive1'; a similar object exists in live mode, but a test mode key was used to make this request.", param: 'id', type: 'invalid_request_error' } });

  it('a live key: livemode 1, in the vector the NSM signs and in its header', async () => {
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    const res = await call({ operation: 'list_charges', apiKey: LIVE_KEY, stripeAccount: ACCT });
    const want = signed({ operation: 'list_charges', accountId: ACCT, objectType: 'list', dataHash: sha256(LIST_CHARGES), totalCount: 2, hasMore: 1, livemode: 1 });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64 });
    expect(signedLivemode(res.rawBody)).toBe(1);
    expect(res.headers['x-stripe-livemode']).toBe('1');
    expect(fakeIo.nsmAsks.map((a) => a.userData?.toString('hex'))).toEqual([want.hash]);
  });

  it.each([
    ['a live secret key', 1, 'sk_live_51Example00000000000000'],
    ['a live restricted key', 1, 'rk_live_51Example00000000000000'],
    ['a test secret key', 0, 'sk_test_51Example00000000000000'],
    ['a test restricted key', 0, 'rk_test_51Example00000000000000'],
  ])('%s: livemode %i', async (_label, livemode, apiKey) => {
    fakeIo.reply(STRIPE_PORT, json(200, ONE_CHARGE));
    const res = await call({ operation: 'get_charge', apiKey, stripeAccount: ACCT, resourceId: CHARGE.id });
    expect(res).toMatchObject({ success: true, status: 200 });
    expect(signedLivemode(res.rawBody)).toBe(livemode);
    expect(res.headers['x-stripe-livemode']).toBe(String(livemode));
  });

  it('a test key asked about a live charge: Stripe\'s own "no such object", signed not_found with livemode 0 - the mode says a test key asked', async () => {
    fakeIo.reply(STRIPE_PORT, json(404, NO_SUCH_LIVE_CHARGE));
    const res = await call({ operation: 'get_charge', apiKey: API_KEY, stripeAccount: ACCT, resourceId: 'ch_3Plive1' });
    const want = signed({ operation: 'get_charge', accountId: ACCT, objectType: 'not_found', dataHash: sha256(NO_SUCH_LIVE_CHARGE), totalCount: 0, hasMore: 0, livemode: 0 });
    expect(res).toMatchObject({ success: true, status: 404, rawBody: want.base64 });
    expect(signedLivemode(res.rawBody)).toBe(0);
    expect(res.headers).toMatchObject({ 'x-stripe-object-type': 'not_found', 'x-stripe-livemode': '0' });
  });

  it('a live key\'s "no such object": not_found with livemode 1', async () => {
    fakeIo.reply(STRIPE_PORT, json(404, NO_SUCH_CHARGE));
    const res = await call({ operation: 'get_charge', apiKey: LIVE_KEY, stripeAccount: ACCT, resourceId: 'ch_missing' });
    expect(res).toMatchObject({ success: true, status: 404 });
    expect(signedLivemode(res.rawBody)).toBe(1);
    expect(res.headers['x-stripe-livemode']).toBe('1');
  });

  it.each([
    ['names no mode', 'sk_51Example0NoMode0000000000'],
    ['names its mode in capitals', 'sk_LIVE_51Example00000000000000'],
    ['has another word where the mode goes', 'rk_prod_51Example00000000000000'],
    ['is a publishable key', 'pk_live_51Example00000000000000'],
    ['has something before it', 'Bearer sk_live_51Example00000000000000'],
    ['carries a line break', `${API_KEY}\r\nX-Other: 1`],
  ])('a key in clear that %s is a 400 that names no byte of it, and nothing is fetched', async (_label, apiKey) => {
    const res = await call({ operation: 'list_charges', apiKey, stripeAccount: ACCT });
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toBe('Invalid request: apiKey must be a Stripe secret or restricted key that names its mode (sk_live_, sk_test_, rk_live_ or rk_test_)');
    expect(fakeIo.requests(STRIPE_PORT)).toEqual([]);
    expect(fakeIo.nsmAsks).toHaveLength(0);
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
    ownAccount();
    const res = await call({ operation: 'list_charges', apiKey: API_KEY });
    expect(res.upstreamBody).toBe(LIST_CHARGES);
    expect(sha256(res.upstreamBody ?? '')).toBe(res.bn254Headers?.['x-stripe-data-hash']);
  });

  it('a "no such object" 404', async () => {
    fakeIo.reply(STRIPE_PORT, json(404, NO_SUCH_CHARGE));
    ownAccount();
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

describe('a key sealed to this enclave (sealedApiKey, enclave audit P1.7) (red)', () => {
  /** KMS, through the host's vsock-proxy port for it (shared/src/sealedSecret.ts KMS_HOST). */
  const KMS_PORT = 8000;
  /** What a caller sends: `aws kms encrypt` output. Opaque to the enclave; the fake KMS seals the key it is told to. */
  const SEALED = Buffer.from('a KMS ciphertext blob, opaque to the enclave').toString('base64');
  const CREDENTIALS = { accessKeyId: 'ASIAEXAMPLEEXAMPLE01', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', sessionToken: 'IQoJb3JpZ2luX2VjEXAMPLETOKEN==' };
  let n = 0;
  /** A ciphertext no other test used: the enclave keeps an opened key for an hour, keyed by its ciphertext. */
  const sealedOnce = () => Buffer.from(`a KMS ciphertext blob ${++n}`).toString('base64');

  /** A request as the parent sends one for this enclave: with the host role's credentials, unless a test leaves them out. */
  function callWithCredentials(body: unknown, parentAdds: { awsCredentials?: unknown } = { awsCredentials: CREDENTIALS }): Promise<EnclaveResponse> {
    return handler({ id: 'req-1', url: 'https://api.stripe.com/v1/charges', method: 'POST', headers: {}, body: JSON.stringify(body), ...parentAdds } as Parameters<typeof handler>[0]);
  }

  /** Every line the enclave wrote to stdout and stderr during the test (its logs). */
  const logged = () => [...vi.mocked(process.stdout.write).mock.calls, ...vi.mocked(process.stderr.write).mock.calls].map((c) => String(c[0])).join('\n');

  it('names KMS in its allowlist exactly as shared does, and does not start without it', () => {
    expect(STRIPE_HOSTS).toContainEqual(KMS_HOST);
    expect(() => createHandler(stripePaymentHandlerDef, STRIPE_HOSTS.filter((h) => h.hostname !== KMS_HOST.hostname)))
      .toThrow(/requires host "kms\.eu-central-1\.amazonaws\.com"/);
  });

  it('declares each call it makes in its manifest: Stripe, the key\'s own account, and the KMS Decrypt with its signature stripped', () => {
    expect(HANDLER_MANIFEST.queries.map((q) => [q.id, q.method, q.host, q.path])).toEqual([
      ['stripe_api', 'GET', 'api.stripe.com', '/v1/{resource}/{resourceId?}'],
      ['stripe_own_account', 'GET', 'api.stripe.com', '/v1/account'],
      ['kms_decrypt', 'POST', 'kms.eu-central-1.amazonaws.com', '/'],
    ]);
    expect(HANDLER_MANIFEST.queries[1].auth).toEqual({ header: 'Authorization', scheme: 'Bearer', strippedBeforeAttestation: true });
    expect(HANDLER_MANIFEST.queries[2].auth).toEqual({ header: 'Authorization', scheme: 'AWS4-HMAC-SHA256', strippedBeforeAttestation: true });
    for (const query of HANDLER_MANIFEST.queries) expect(STRIPE_HOSTS.map((h) => h.hostname)).toContain(query.host);
  });

  it('opens the key through KMS first, then asks Stripe with it; the signed answer is the one the key in clear gets', async () => {
    const kms = fakeKms({ sealed: API_KEY });
    fakeIo.reply(KMS_PORT, kms.reply);
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    const sealed = await callWithCredentials({ operation: 'list_charges', sealedApiKey: SEALED, stripeAccount: ACCT });

    expect(kms.requests).toHaveLength(1);
    expect(kms.requests[0].body).toMatchObject({ CiphertextBlob: SEALED, EncryptionContext: { enclave: 'stripe_payment' } });
    expect(SEALED_KEY_CONTEXT).toBe('stripe_payment');
    const [request] = fakeIo.requests(STRIPE_PORT);
    expect(request).toContain(`Authorization: Bearer ${API_KEY}\r\n`);
    // Two documents, in order: the recipient document (its public key, nothing signed), then the answer's
    expect(fakeIo.nsmAsks.map((a) => [a.publicKey !== null, a.userData !== null])).toEqual([[true, false], [false, true]]);

    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    const clear = await call({ operation: 'list_charges', apiKey: API_KEY, stripeAccount: ACCT });
    expect(sealed).toMatchObject({ success: true, status: 200, rawBody: clear.rawBody, upstreamBody: LIST_CHARGES });
    expect(sealed.attestation?.requestHash).toBe(clear.attestation?.requestHash);
  });

  it('the key is in no answer and no log line', async () => {
    fakeIo.reply(KMS_PORT, fakeKms({ sealed: API_KEY }).reply);
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    ownAccount();
    const res = await callWithCredentials({ operation: 'list_charges', sealedApiKey: sealedOnce() });
    expect(res.success).toBe(true);
    expect(JSON.stringify(res)).not.toContain(API_KEY);
    expect(logged()).not.toContain(API_KEY);
    expect(logged()).not.toContain(CREDENTIALS.secretAccessKey);
  });

  it.each([
    ['a restricted key', 'rk_live_51Example00000000000000'],
    ['a live secret key', 'sk_live_51Example00000000000000'],
  ])('opens %s', async (_label, key) => {
    fakeIo.reply(KMS_PORT, fakeKms({ sealed: key }).reply);
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    ownAccount();
    expect((await callWithCredentials({ operation: 'list_charges', sealedApiKey: sealedOnce() })).success).toBe(true);
    expect(fakeIo.requests(STRIPE_PORT)[0]).toContain(`Authorization: Bearer ${key}\r\n`);
    // the key's own account is asked with the key the enclave opened
    expect(fakeIo.requests(STRIPE_PORT)[1]).toContain(`Authorization: Bearer ${key}\r\n`);
  });

  it.each([
    ['a live key', 1, 'rk_live_51Example00000000000000'],
    ['a test key', 0, API_KEY],
  ])('the mode of a sealed key is signed once it is opened: %s, livemode %i (red)', async (_label, livemode, key) => {
    fakeIo.reply(KMS_PORT, fakeKms({ sealed: key }).reply);
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    const res = await callWithCredentials({ operation: 'list_charges', sealedApiKey: sealedOnce(), stripeAccount: ACCT });
    expect(res).toMatchObject({ success: true, status: 200 });
    expect(signedLivemode(res.rawBody)).toBe(livemode);
  });

  it.each([
    ['not a Stripe key', 'pk_live_publishable_not_secret'],
    ['a key with a line break (sealed from a file that ends in one)', `${API_KEY}\n`],
    ['a key that names no mode (red: it was opened and used)', 'sk_51Example0NoMode0000000000'],
  ])('a sealed value that is %s: an error that names no byte of it, and Stripe is never asked', async (_label, value) => {
    fakeIo.reply(KMS_PORT, fakeKms({ sealed: value }).reply);
    const res = await callWithCredentials({ operation: 'list_charges', sealedApiKey: sealedOnce() });
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(res.error).toMatch(/the sealed key is not a Stripe secret or restricted key \(sk_ or rk_\)/);
    expect(res.error).not.toContain(value.trim());
    expect(fakeIo.requests(STRIPE_PORT)).toEqual([]);
  });

  it('KMS refuses: an error with KMS\'s reason, and Stripe is never asked', async () => {
    fakeIo.reply(KMS_PORT, fakeKms({ status: 400, body: JSON.stringify({ __type: 'AccessDeniedException', message: 'not authorized to perform: kms:Decrypt' }) }).reply);
    const res = await callWithCredentials({ operation: 'list_charges', sealedApiKey: sealedOnce() });
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(res.error).toMatch(/KMS refused the Decrypt \(400 AccessDeniedException\)/);
    expect(fakeIo.requests(STRIPE_PORT)).toEqual([]);
    expect(res.attestation).toBeUndefined();
  });

  it('the parent sent no AWS credentials: an error, and neither KMS nor Stripe is asked', async () => {
    const res = await callWithCredentials({ operation: 'list_charges', sealedApiKey: sealedOnce() }, {});
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(res.error).toMatch(/the parent sent no AWS credentials/);
    expect(fakeIo.requests(KMS_PORT)).toEqual([]);
    expect(fakeIo.requests(STRIPE_PORT)).toEqual([]);
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });

  it.each([
    ['both keys', { apiKey: API_KEY, sealedApiKey: SEALED }, /apiKey and sealedApiKey: send one, not both/],
    ['a sealed key that is not base64', { sealedApiKey: 'sk_live_in_clear_by_mistake!' }, /sealedApiKey must be a KMS ciphertext/],
    ['a sealed key longer than KMS allows', { sealedApiKey: Buffer.alloc(6145).toString('base64') }, /sealedApiKey must be a KMS ciphertext: base64 of at most 6144 bytes/],
    ['a sealed key that is not text', { sealedApiKey: 42 }, /sealedApiKey must be a KMS ciphertext/],
  ])('%s is a 400, and nothing is asked', async (_label, key, error) => {
    const res = await callWithCredentials({ operation: 'list_charges', ...key });
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toMatch(error);
    expect(fakeIo.requests(KMS_PORT)).toEqual([]);
    expect(fakeIo.requests(STRIPE_PORT)).toEqual([]);
  });

  it.each([
    ['null', null],
    ['empty', ''],
  ])('a sealedApiKey that is %s is no sealed key: apiKey is used as before (lock)', async (_label, empty) => {
    fakeIo.reply(STRIPE_PORT, json(200, LIST_CHARGES));
    ownAccount();
    expect((await call({ operation: 'list_charges', apiKey: API_KEY, sealedApiKey: empty })).success).toBe(true);
    expect(fakeIo.requests(KMS_PORT)).toEqual([]);
  });
});

describe('manifest (lock)', () => {
  it('declares the STRIPE_PAYMENT_SCHEMA fields in order, and their size', () => {
    expect(HANDLER_MANIFEST.schema.fields.map((f) => [f.name, f.encoding])).toEqual(STRIPE_PAYMENT_SCHEMA.map((f) => [f.name, f.encoding]));
    expect(HANDLER_MANIFEST.schema.outputBytes).toBe(STRIPE_PAYMENT_SCHEMA.length * 32);
  });
});

// Enclave review 2026-10-09, E2a F-17: the manifest said only 400, 401, 403, 429, 500, 502 and 503 pass unsigned (the
// handler passes every error but 404: 402, 409, 504 too), and that every 404 is signed with state not_found (the
// vector has no state; only Stripe's own resource_missing is signed). Found with it: a status other than 200 that is
// no error (a 201, a 302) was read as an answer and could be signed.
describe('the manifest says what the handler does (red before part 9)', () => {
  const STATUSES = [201, 301, 400, 401, 402, 403, 404, 409, 422, 429, 500, 502, 503, 504];

  // Each status, answered by Stripe with a body that is no answer: the handler passes it on unsigned exactly when a
  // status_skip policy of the manifest names it, and signs it exactly when a status_attest policy does.
  it.each(STATUSES)('Stripe answering %i', async (status) => {
    const body = JSON.stringify({ error: { type: 'api_error', message: 'no answer' } });
    fakeIo.reply(STRIPE_PORT, json(status, body));
    const res = await call({ operation: 'list_charges', apiKey: API_KEY });
    const passedOn = res.success && res.status === status && res.attestation === undefined && res.rawBody === body;
    expect(passedOn).toBe(shouldSkipAttestation(HANDLER_MANIFEST.policies, status));
    expect(res.success && res.attestation !== undefined).toBe(getAttestOverrides(HANDLER_MANIFEST.policies, status) !== null);
  });

  it.each([201, 203, 302])('a %i that carries a list is an error, never signed: only a 200 is an answer', async (status) => {
    fakeIo.reply(STRIPE_PORT, json(status, LIST_CHARGES));
    ownAccount();
    const res = await call({ operation: 'list_charges', apiKey: API_KEY });
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(res.error).toBe(`Stripe answered HTTP ${status}: only a 200 is an answer`);
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });

  /**
   * The manifests the enclave releases shipped, with their versions: a version names one manifest, so a changed manifest
   * moves its version. 718b999 = the 2026-10-09 release. The next release appends its own.
   */
  const SHIPPED: ReadonlyArray<readonly [version: string, hash: string]> = [
    ['1.1.0', '89dfb85f0a9d971738e96f6fb5e5ab1c28dd887318d72d785674a33c68a06e09'],
  ];

  it('a version names one manifest: a changed manifest moves its version', () => {
    for (const [version, hash] of SHIPPED) {
      expect(HANDLER_MANIFEST.version === version, `shipped ${version}`).toBe(MANIFEST_HASH === hash);
    }
  });
});
