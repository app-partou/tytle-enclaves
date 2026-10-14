/**
 * The VIES/HMRC handler through the REAL handler factory (P2.4), with the services' own answers where they can
 * be recorded (fixtures/README.md).
 *
 * MOCK BOUNDARY: the enclave's two boundaries only - the vsock socket to the host's proxy (and the TLS layer
 * over it) and the NSM device (shared/src/__tests__/helpers/fakeEnclaveIo.ts). createHandler, ctx.fetch, the
 * HTTP framing, the parse rules, the BN254 encoder and attest() all run for real.
 *
 * WHY (audit 2026-10 P1.4 and the caller-input row): the handler signed "not valid" for a VIES reply without
 * its <valid> answer and for ANY HMRC 404 - including the 404 HMRC's API platform answers for the version-1.0
 * API it removed on 17 February 2025 - and signed "valid" for an HMRC 200 that named no company. It also asked
 * the registers for values they refuse. Now a reply that is not the register's answer is an error (502), never
 * signed, and a value the register would refuse is a 400 before anything is fetched.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

vi.mock('@tytle-enclaves/native', async () => (await import('../../../shared/src/__tests__/helpers/fakeEnclaveIo.js')).nativeModule);
vi.mock('node:tls', async () => (await import('../../../shared/src/__tests__/helpers/fakeEnclaveIo.js')).tlsModule);

import { createHandler, getAttestOverrides, shouldSkipAttestation } from '@tytle-enclaves/shared';
import type { EnclaveResponse } from '@tytle-enclaves/shared';
import { encodeFieldElements, hashFieldElements, VIES_SCHEMA } from '../../../shared/src/bn254Codec.js';
import { fakeIo, httpReply } from '../../../shared/src/__tests__/helpers/fakeEnclaveIo.js';
import { viesHandlerDef, VIES_HOSTS } from '../viesHandler.js';
import { HANDLER_MANIFEST, MANIFEST_HASH, PASSED_ON_STATUSES } from '../manifest.js';

const recorded = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf-8');
const VIES_VALID = recorded('checkvat-valid-PT503504564.xml');
const VIES_NOT_VALID = recorded('checkvat-not-valid-PT123456789.xml');
const VIES_FAULT = recorded('checkvat-fault-invalid-input.xml');
const HMRC_V1_GONE = recorded('hmrc-v1-404-matching-resource-not-found.json');

/** HMRC's version-2.0 answers, from the API definition (they need OAuth credentials to record). */
const HMRC_NOT_REGISTERED = JSON.stringify({ code: 'NOT_FOUND', message: 'targetVrn does not match a registered company' });
const HMRC_REGISTERED = JSON.stringify({
  target: { name: 'EXAMPLE TRADING LTD', vatNumber: '123456789', address: { line1: '10 EXAMPLE STREET', line2: 'EXAMPLETOWN', postcode: 'EX1 1EX', countryCode: 'GB' } },
  processingDate: '2026-10-08T03:00:00+01:00',
});

const VIES_PORT = 8443;
const HMRC_PORT = 8444;
/** A stand-in for the OAuth token data-bridge gets from HMRC (client credentials, scope read:vat): TEST ONLY. */
const HMRC_TOKEN = 'testonly-hmrc-access-token-0001';
/** A UK lookup as data-bridge sends it: the VRN and HMRC's OAuth token (Check a UK VAT number 2.0, D-P1-9). */
const gb = (vatNumber: string) => ({ countryCode: 'GB', vatNumber, hmrcAccessToken: HMRC_TOKEN });
const xml = (body: string, status = 200) => httpReply(status, body, { 'Content-Type': 'text/xml; charset=UTF-8' });
const json = (status: number, body: string) => httpReply(status, body, { 'Content-Type': 'application/json' });

const handler = createHandler(viesHandlerDef, VIES_HOSTS);

function check(body: unknown): Promise<EnclaveResponse> {
  return handler({ id: 'req-1', url: 'https://ec.europa.eu/x', method: 'POST', headers: {}, body: typeof body === 'string' ? body : JSON.stringify(body) });
}

/** The SHA-256 hex of an upstream body: the value the handler signs as dataHash. */
const sha256 = (body: string) => createHash('sha256').update(body, 'utf8').digest('hex');

function signed(values: Record<string, string | number | null>) {
  const vector = encodeFieldElements(VIES_SCHEMA, values);
  return { base64: vector.toString('base64'), hash: hashFieldElements(vector) };
}

beforeEach(() => {
  fakeIo.reset();
  // The enclave logs one JSON line per request to stdout (shared/src/logger.ts).
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

describe('request validation (lock)', () => {
  it.each([
    ['not JSON', 'not json', 'Invalid request'],
    ['no countryCode', { vatNumber: '123456789' }, 'required'],
    ['a bad countryCode', { countryCode: 'P&T', vatNumber: '123456789' }, 'Invalid countryCode'],
  ])('%s is a 400, and nothing is fetched', async (_label, body, error) => {
    const res = await check(body);
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toContain(error);
    expect(fakeIo.requests(VIES_PORT).length + fakeIo.requests(HMRC_PORT).length).toBe(0);
  });
});

describe('VIES', () => {
  it('a valid number: valid, name, the three-line address and the body\'s hash are signed (red before the release: dataHash)', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_VALID));
    const res = await check({ countryCode: 'PT', vatNumber: '503504564' });

    const name = 'EDP COMERCIAL - COMERCIALIZAÇÃO DE ENERGIA S A';
    const address = 'AV 24 DE JULHO N 12\nLISBOA\n1249-300 LISBOA';
    const want = signed({ countryCode: 'PT', vatNumber: '503504564', valid: 1, name, address, dataHash: sha256(VIES_VALID) });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64, bn254: want.base64 });
    expect(res.headers).toMatchObject({ 'x-vies-valid': 'true', 'x-vies-name': name, 'x-vies-address': address, 'x-vies-manifest-hash': MANIFEST_HASH });
    expect(res.bn254Headers).toEqual({ 'x-vies-name': name, 'x-vies-address': address, 'x-vies-data-hash': sha256(VIES_VALID) });
    // The attested request config names the number asked and the manifest the handler ran under.
    const requestConfig = `https://ec.europa.eu/taxation_customs/vies/services/checkVatService|POST|${JSON.stringify({ countryCode: 'PT', vatNumber: '503504564', 'x-manifest-hash': MANIFEST_HASH })}`;
    expect(res.attestation?.requestHash).toBe(createHash('sha256').update(requestConfig).digest('hex'));
    expect(fakeIo.nsmAsks.map((a) => a.userData?.toString('hex'))).toEqual([want.hash]);
  });

  it('VIES\'s own "not valid" is signed as valid 0 (lock)', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_NOT_VALID));
    const res = await check({ countryCode: 'PT', vatNumber: '123456789' });
    const want = signed({ countryCode: 'PT', vatNumber: '123456789', valid: 0, name: null, address: null, dataHash: sha256(VIES_NOT_VALID) });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64 });
    expect(res.headers['x-vies-valid']).toBe('false');
  });

  it('asks VIES over its own port with the SOAP checkVat request (lock)', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_VALID));
    await check({ countryCode: 'PT', vatNumber: '503504564' });
    const [request] = fakeIo.requests(VIES_PORT);
    expect(request).toMatch(/^POST \/taxation_customs\/vies\/services\/checkVatService HTTP\/1\.1\r\n/);
    expect(request).toContain('<urn:countryCode>PT</urn:countryCode>');
    expect(request).toContain('<urn:vatNumber>503504564</urn:vatNumber>');
    expect(fakeIo.requests(HMRC_PORT)).toEqual([]);
  });

  it('a SOAP fault is an error, never signed (lock)', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_FAULT));
    const res = await check({ countryCode: 'PT', vatNumber: '503504564' });
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(res.error).toContain('INVALID_INPUT');
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });

  it('a VIES HTTP 500 is an error (lock)', async () => {
    fakeIo.reply(VIES_PORT, xml('error', 500));
    const res = await check({ countryCode: 'PT', vatNumber: '503504564' });
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });
});

describe('HMRC', () => {
  it('a registered number: valid, name and address are signed (lock)', async () => {
    fakeIo.reply(HMRC_PORT, json(200, HMRC_REGISTERED));
    const res = await check(gb('123456789'));
    const want = signed({ countryCode: 'GB', vatNumber: '123456789', valid: 1, name: 'EXAMPLE TRADING LTD', address: '10 EXAMPLE STREET, EXAMPLETOWN, EX1 1EX', dataHash: sha256(HMRC_REGISTERED) });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64 });
    expect(res.headers).toMatchObject({ 'x-vies-valid': 'true', 'x-vies-name': 'EXAMPLE TRADING LTD' });
    const [request] = fakeIo.requests(HMRC_PORT);
    expect(request).toMatch(/^GET \/organisations\/vat\/check-vat-number\/lookup\/123456789 HTTP\/1\.1\r\n/);
    expect(fakeIo.requests(VIES_PORT)).toEqual([]);
  });

  it('HMRC\'s own "not registered" (404, code NOT_FOUND) is signed as valid 0 (lock)', async () => {
    fakeIo.reply(HMRC_PORT, json(404, HMRC_NOT_REGISTERED));
    const res = await check(gb('123456789'));
    const want = signed({ countryCode: 'GB', vatNumber: '123456789', valid: 0, name: null, address: null, dataHash: sha256(HMRC_NOT_REGISTERED) });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64 });
    expect(res.headers['x-vies-valid']).toBe('false');
  });

  it('an HMRC 500 is an error (lock)', async () => {
    fakeIo.reply(HMRC_PORT, json(500, '{}'));
    const res = await check(gb('123456789'));
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });
});

// OPEN_ISSUES 9 item 2 (R5 part 2): a refusal or a rate limit of the register was a 502, so data-bridge read HMRC's rate
// limit as an outage and asked the enclave again, each try one more HMRC request on the rate limit. Passed on unsigned
// as it was sent, it is a hint for the caller's retries, never a verdict: no value is signed and no x-vies header set.
describe('a refusal or a rate limit of the register is passed on unsigned, as it was sent (red before R5)', () => {
  const THROTTLED = JSON.stringify({ code: 'MESSAGE_THROTTLED_OUT', message: 'The application has exceeded its request rate limit' });

  it.each([403, 406, 429])('HMRC answering %i', async (status) => {
    fakeIo.reply(HMRC_PORT, json(status, THROTTLED));
    const res = await check(gb('123456789'));
    expect(res).toEqual({ success: true, status, headers: { 'content-type': 'application/json' }, rawBody: THROTTLED });
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });

  it.each([401, 403, 406, 429])('VIES answering %i', async (status) => {
    fakeIo.reply(VIES_PORT, httpReply(status, '<html>slow down</html>', { 'Content-Type': 'text/html' }));
    const res = await check({ countryCode: 'PT', vatNumber: '503504564' });
    expect(res).toEqual({ success: true, status, headers: { 'content-type': 'text/html' }, rawBody: '<html>slow down</html>' });
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });

  it('the four are the manifest\'s status_skip, and nothing else is passed on', () => {
    expect(PASSED_ON_STATUSES).toEqual([401, 403, 406, 429]);
    for (const status of [200, 400, 404, 500, 502, 503]) expect(shouldSkipAttestation(HANDLER_MANIFEST.policies, status)).toBe(false);
  });
});

// D-P1-9 (LJ "A", 2026-10-12): HMRC removed version 1.0 of Check a UK VAT number on 17 February 2025, and version 2.0
// is application-restricted - an OAuth 2.0 bearer token with the read:vat scope (hmrc/vat-registered-companies-api,
// public/api/conf/2.0/application.yaml). data-bridge gets the token and passes it with each UK lookup; the enclave
// sends it to HMRC and nowhere else. Before, every UK lookup asked version 1.0 and got its 404: no verdict, ever.
describe('HMRC Check a UK VAT number 2.0: the caller\'s OAuth token goes to HMRC and nowhere else (red before D-P1-9)', () => {
  it('asks version 2.0, with the token as its Bearer credentials', async () => {
    fakeIo.reply(HMRC_PORT, json(200, HMRC_REGISTERED));
    const res = await check(gb('123456789'));
    expect(res).toMatchObject({ success: true, status: 200 });
    const [request] = fakeIo.requests(HMRC_PORT);
    expect(request).toMatch(/\r\nAccept: application\/vnd\.hmrc\.2\.0\+json\r\n/);
    expect(request).toContain(`\r\nAuthorization: Bearer ${HMRC_TOKEN}\r\n`);
  });

  it('a token of 4096 characters with "=" padding is a bearer token (RFC 6750 b64token)', async () => {
    const token = `${'a'.repeat(4094)}==`;
    fakeIo.reply(HMRC_PORT, json(200, HMRC_REGISTERED));
    const res = await check({ ...gb('123456789'), hmrcAccessToken: token });
    expect(res).toMatchObject({ success: true, status: 200 });
    expect(fakeIo.requests(HMRC_PORT)[0]).toContain(`\r\nAuthorization: Bearer ${token}\r\n`);
  });

  it('the token is in nothing the enclave answers or signs: the attested request names the number only (lock)', async () => {
    fakeIo.reply(HMRC_PORT, json(200, HMRC_REGISTERED));
    const res = await check(gb('123456789'));
    expect(JSON.stringify(res)).not.toContain(HMRC_TOKEN);
    const requestConfig = `https://api.service.hmrc.gov.uk/organisations/vat/check-vat-number/lookup/123456789|GET|${JSON.stringify({ countryCode: 'GB', vatNumber: '123456789', 'x-manifest-hash': MANIFEST_HASH })}`;
    expect(res.attestation?.requestHash).toBe(createHash('sha256').update(requestConfig).digest('hex'));
  });

  it('a UK number without a token is a 400, and nothing is fetched', async () => {
    const res = await check({ countryCode: 'GB', vatNumber: '123456789' });
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toMatch(/hmrcAccessToken is required for a UK number/);
    expect(fakeIo.requests(HMRC_PORT)).toEqual([]);
  });

  it.each([
    ['empty', ''],
    ['not text', 12345],
    ['with a space', 'testonly token'],
    ['with a line break that would add a header of its own', 'testonly\r\nX-Forged: 1'],
    ['longer than 4096 characters', 'a'.repeat(4097)],
    ['with a character no bearer token has', 'testonly"token'],
    ['with "=" before its end', 'testonly=token'],
  ])('a token %s is a 400, nothing is fetched, and the error does not repeat it', async (_label, token) => {
    const res = await check({ countryCode: 'GB', vatNumber: '123456789', hmrcAccessToken: token });
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toMatch(/hmrcAccessToken/);
    if (typeof token === 'string' && token !== '') expect(res.error).not.toContain(token);
    expect(fakeIo.requests(HMRC_PORT)).toEqual([]);
  });

  it('a token on a lookup that is not for a UK number is a 400: VIES is never asked with it', async () => {
    const res = await check({ countryCode: 'PT', vatNumber: '503504564', hmrcAccessToken: HMRC_TOKEN });
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toMatch(/hmrcAccessToken is only for a UK number/);
    expect(fakeIo.requests(VIES_PORT)).toEqual([]);
  });

  it('HMRC refusing the token (401) is passed on unsigned with HMRC\'s body, and nothing answered carries the token (red before R5)', async () => {
    const refused = JSON.stringify({ code: 'INVALID_CREDENTIALS', message: 'Invalid Authentication information provided' });
    fakeIo.reply(HMRC_PORT, json(401, refused));
    const res = await check(gb('123456789'));
    expect(res).toEqual({ success: true, status: 401, headers: { 'content-type': 'application/json' }, rawBody: refused });
    expect(fakeIo.nsmAsks).toHaveLength(0);
    expect(JSON.stringify(res)).not.toContain(HMRC_TOKEN);
  });

  it('the manifest names version 2.0 and the Bearer token, stripped before attestation', () => {
    const hmrc = HANDLER_MANIFEST.queries.find((q) => q.id === 'hmrc_rest');
    expect(hmrc?.headers).toEqual({ Accept: 'application/vnd.hmrc.2.0+json' });
    expect(hmrc?.auth).toEqual({ header: 'Authorization', scheme: 'Bearer', strippedBeforeAttestation: true });
    expect(HANDLER_MANIFEST.policies.map((p) => p.id)).toEqual(expect.arrayContaining(['strip_auth', 'redact_bearer', 'gb_needs_hmrc_token']));
  });
});

describe('a reply that is not the register\'s answer is an error, never signed (red before the release)', () => {
  async function expectError(body: unknown, error: RegExp) {
    const res = await check(body);
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(res.error).toMatch(error);
    expect(res.attestation).toBeUndefined();
    expect(fakeIo.nsmAsks).toHaveLength(0);
  }

  it('a VIES reply without <valid>', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_VALID.replace('<ns2:valid>true</ns2:valid>', '')));
    await expectError({ countryCode: 'PT', vatNumber: '503504564' }, /VIES response has no <valid>true\|false<\/valid> answer/);
  });

  it('a VIES <valid> that is neither true nor false', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_NOT_VALID.replace('<ns2:valid>false</ns2:valid>', '<ns2:valid>unknown</ns2:valid>')));
    await expectError({ countryCode: 'PT', vatNumber: '123456789' }, /no <valid>true\|false<\/valid> answer/);
  });

  it('the 404 HMRC answers for the removed version-1.0 API (MATCHING_RESOURCE_NOT_FOUND, recorded live)', async () => {
    fakeIo.reply(HMRC_PORT, json(404, HMRC_V1_GONE));
    await expectError(gb('123456789'), /HMRC returned 404 MATCHING_RESOURCE_NOT_FOUND - not a "not registered" answer/);
  });

  it('an HMRC 404 without a JSON error code (a proxy or WAF page)', async () => {
    fakeIo.reply(HMRC_PORT, httpReply(404, '<html><body>Not Found</body></html>', { 'Content-Type': 'text/html' }));
    await expectError(gb('123456789'), /HMRC returned 404 without an error code/);
  });

  it('an HMRC 200 that names no company', async () => {
    fakeIo.reply(HMRC_PORT, json(200, '{}'));
    await expectError(gb('123456789'), /HMRC response has no target/);
  });
});

describe('a value the register would refuse is a 400 before anything is fetched (red before the release)', () => {
  it.each([
    ['a UK number of 3 digits', { countryCode: 'GB', vatNumber: '123' }, /a UK VAT registration number is 9 or 12 digits/],
    ['a UK number with its GB prefix', { countryCode: 'GB', vatNumber: 'GB123456789' }, /9 or 12 digits/],
    ['a UK number of 10 digits', { countryCode: 'GB', vatNumber: '1234567890' }, /9 or 12 digits/],
    ['a VIES number with spaces', { countryCode: 'PT', vatNumber: '503 504 564' }, /VIES accepts 2 to 12 characters/],
    ['a VIES number of 13 characters', { countryCode: 'DE', vatNumber: '1234567890123' }, /VIES accepts 2 to 12 characters/],
    ['a vatNumber that is not text', { countryCode: 'PT', vatNumber: 503504564 }, /VIES accepts 2 to 12 characters/],
    ['a countryCode that is not text', { countryCode: ['PT'], vatNumber: '503504564' }, /Invalid countryCode/],
  ])('%s', async (_label, body, error) => {
    const res = await check(body);
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toMatch(error);
    expect(fakeIo.requests(VIES_PORT).length + fakeIo.requests(HMRC_PORT).length).toBe(0);
  });
});

describe('the signed name and address are the text VIES meant (red before the release)', () => {
  it('XML escapes are read back: "&amp;" is signed as "&"', async () => {
    const reply = VIES_VALID
      .replace('EDP COMERCIAL - COMERCIALIZAÇÃO DE ENERGIA S A', 'SMITH &amp; SONS &lt;PT&gt; &amp;lt;1&amp;gt;')
      .replace('AV 24 DE JULHO N 12', 'RUA D&apos;ALMEIDA &quot;12&quot;');
    fakeIo.reply(VIES_PORT, xml(reply));
    const res = await check({ countryCode: 'PT', vatNumber: '503504564' });
    const address = 'RUA D\'ALMEIDA "12"\nLISBOA\n1249-300 LISBOA';
    // "&amp;lt;" is the text "&lt;": read once, never twice.
    const name = 'SMITH & SONS <PT> &lt;1&gt;';
    const want = signed({ countryCode: 'PT', vatNumber: '503504564', valid: 1, name, address, dataHash: sha256(reply) });
    expect(res).toMatchObject({ success: true, rawBody: want.base64 });
    expect(res.headers).toMatchObject({ 'x-vies-name': name, 'x-vies-address': address });
  });
});

describe('the whole upstream body is committed: dataHash (red before the release)', () => {
  it('the vector is 6 fields, the last the SHA-256 of the body VIES sent - one byte more is another hash', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_VALID));
    fakeIo.reply(VIES_PORT, xml(`${VIES_VALID} `));
    const a = await check({ countryCode: 'PT', vatNumber: '503504564' });
    const b = await check({ countryCode: 'PT', vatNumber: '503504564' });
    expect(Buffer.from(a.rawBody, 'base64')).toHaveLength(192);
    expect(a.headers['x-vies-data-hash']).toBe(sha256(VIES_VALID));
    expect(b.headers['x-vies-data-hash']).toBe(sha256(`${VIES_VALID} `));
    // Everything but dataHash is the same answer.
    expect(Buffer.from(a.rawBody, 'base64').subarray(0, 160)).toEqual(Buffer.from(b.rawBody, 'base64').subarray(0, 160));
    expect(a.rawBody).not.toBe(b.rawBody);
  });

  it('HMRC: the body HMRC sent, the "not registered" answer too', async () => {
    fakeIo.reply(HMRC_PORT, json(404, HMRC_NOT_REGISTERED));
    const res = await check(gb('123456789'));
    expect(res.headers['x-vies-data-hash']).toBe(sha256(HMRC_NOT_REGISTERED));
  });
});

describe('the body behind dataHash goes out beside the answer, unsigned (enclave review 2026-10-09, E-4; red before)', () => {
  // dataHash committed to a body that never left the enclave and cannot be fetched again (VIES dates every answer):
  // nobody could ever open the commitment. Stripe's rule now holds for every enclave: the body goes out as
  // upstreamBody, and a reader uses it only when its SHA-256 is the signed dataHash.
  it.each([
    ['VIES, a valid number', VIES_PORT, xml(VIES_VALID), { countryCode: 'PT', vatNumber: '503504564' }, VIES_VALID],
    ['VIES, "not valid"', VIES_PORT, xml(VIES_NOT_VALID), { countryCode: 'PT', vatNumber: '123456789' }, VIES_NOT_VALID],
    ['HMRC, a registered number', HMRC_PORT, json(200, HMRC_REGISTERED), gb('123456789'), HMRC_REGISTERED],
    ['HMRC, "not registered"', HMRC_PORT, json(404, HMRC_NOT_REGISTERED), gb('123456789'), HMRC_NOT_REGISTERED],
  ])('%s: upstreamBody is the body the register sent, and its SHA-256 is the signed dataHash', async (_label, port, reply, body, sent) => {
    fakeIo.reply(port, reply);
    const res = await check(body);
    expect(res.success).toBe(true);
    expect(res.upstreamBody).toBe(sent);
    const dataHash = Buffer.from(res.rawBody, 'base64').subarray(5 * 32, 6 * 32);
    expect(dataHash).toEqual(encodeFieldElements([{ name: 'dataHash', encoding: 'sha256' }], { dataHash: sha256(sent) }));
  });

  it('an error carries no body (lock)', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_FAULT, 500));
    const res = await check({ countryCode: 'PT', vatNumber: '503504564' });
    expect(res.success).toBe(false);
    expect(res.upstreamBody).toBeUndefined();
  });
});

describe('manifest (lock)', () => {
  it('declares the VIES_SCHEMA fields in order, and their size', () => {
    expect(HANDLER_MANIFEST.schema.fields.map((f) => [f.name, f.encoding])).toEqual(VIES_SCHEMA.map((f) => [f.name, f.encoding]));
    expect(HANDLER_MANIFEST.schema.outputBytes).toBe(VIES_SCHEMA.length * 32);
  });
});

/** The answer is an error (502): nothing signed, nothing passed on. */
async function expectRefused(body: unknown, error: RegExp): Promise<void> {
  const res = await check(body);
  expect(res).toMatchObject({ success: false, status: 502 });
  expect(res.error).toMatch(error);
  expect(res.attestation).toBeUndefined();
  expect(fakeIo.nsmAsks).toHaveLength(0);
}

// Enclave review 2026-10-09, E2a F-1: VIES answers with the countryCode and vatNumber it checked. The handler signed
// the request's spelling and never read them, so a vector could name a number VIES never confirmed.
describe("VIES's own echo of the number it checked must be the number asked (red before part 9)", () => {
  it('an answer for another number is an error, never signed', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_VALID));                // VIES checked PT503504564
    await expectRefused({ countryCode: 'PT', vatNumber: '503504565' }, /^VIES answered for PT503504564, not for PT503504565$/);
  });

  it('an answer for another country is an error', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_VALID));
    await expectRefused({ countryCode: 'ES', vatNumber: '503504564' }, /^VIES answered for PT503504564, not for ES503504564$/);
  });

  it('a spelling VIES rewrites is an error: only the number VIES confirmed is ever signed', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_VALID));
    await expectRefused({ countryCode: 'PT', vatNumber: '503.504.564' }, /^VIES answered for PT503504564, not for PT503\.504\.564$/);
  });

  it.each([
    ['its countryCode', '<ns2:countryCode>PT</ns2:countryCode>'],
    ['its vatNumber', '<ns2:vatNumber>503504564</ns2:vatNumber>'],
  ])('an answer without %s is an error', async (_label, echo) => {
    fakeIo.reply(VIES_PORT, xml(VIES_VALID.replace(echo, '')));
    await expectRefused({ countryCode: 'PT', vatNumber: '503504564' }, /^VIES response does not say which number it checked$/);
  });
});

// E2a F-2: only <valid> was required, so a reply that ended early was signed valid with no name and no address.
describe('a VIES answer is read only when it is complete (red before part 9)', () => {
  it.each([
    ['inside the name', VIES_VALID.slice(0, VIES_VALID.indexOf('<ns2:name>') + '<ns2:name>EDP COMER'.length)],
    ['after the address, before the answer closes', VIES_VALID.slice(0, VIES_VALID.indexOf('</ns2:checkVatResponse>'))],
  ])('a reply cut %s is an error, never signed', async (_label, cut) => {
    fakeIo.reply(VIES_PORT, xml(cut));
    await expectRefused({ countryCode: 'PT', vatNumber: '503504564' }, /^VIES response has no complete checkVatResponse$/);
  });

  it('a field outside the answer is not read: a name before checkVatResponse is no name of it', async () => {
    const reply = VIES_NOT_VALID.replace('<env:Header/>', '<env:Header><ns2:name>FORGED</ns2:name><ns2:valid>true</ns2:valid></env:Header>');
    fakeIo.reply(VIES_PORT, xml(reply));
    const res = await check({ countryCode: 'PT', vatNumber: '123456789' });
    const want = signed({ countryCode: 'PT', vatNumber: '123456789', valid: 0, name: null, address: null, dataHash: sha256(reply) });
    expect(res).toMatchObject({ success: true, rawBody: want.base64 });
  });
});

// E2a F-3: any JSON object or array under target was signed valid, and the VRN HMRC answered for was never compared.
describe('an HMRC 200 is signed valid only for a target that names the VRN asked (red before part 9)', () => {
  const target = (t: unknown) => JSON.stringify({ target: t, processingDate: '2026-10-08T03:00:00+01:00' });

  it.each([
    ['an array', target([])],
    ['an array of the company', target([{ name: 'EXAMPLE TRADING LTD', vatNumber: '123456789' }])],
  ])('a target that is %s is an error', async (_label, body) => {
    fakeIo.reply(HMRC_PORT, json(200, body));
    await expectRefused(gb('123456789'), /^HMRC response has no target$/);
  });

  it.each([
    ['another VRN', target({ name: 'EXAMPLE TRADING LTD', vatNumber: '987654321' })],
    ['no VRN', target({ name: 'EXAMPLE TRADING LTD' })],
    ['a VRN that is not text', target({ name: 'EXAMPLE TRADING LTD', vatNumber: 123456789 })],
  ])('a target for %s is an error', async (_label, body) => {
    fakeIo.reply(HMRC_PORT, json(200, body));
    await expectRefused(gb('123456789'), /^HMRC answered for another VRN than 123456789$/);
  });

  it.each([
    ['no name', target({ vatNumber: '123456789' })],
    ['an empty name', target({ name: '', vatNumber: '123456789' })],
  ])('a target with %s is an error', async (_label, body) => {
    fakeIo.reply(HMRC_PORT, json(200, body));
    await expectRefused(gb('123456789'), /^HMRC's target has no name$/);
  });
});

// E2a F-17: the manifest's status rules described other code than the handler's (status_skip codes the handler turns
// into a 502, status_attest for every HMRC 404), and VIES kept version 1.0.0 across vector version 2.
describe('the manifest says what the handler does (red before part 9)', () => {
  const STATUSES = [201, 301, 400, 401, 402, 403, 404, 406, 409, 422, 429, 500, 502, 503, 504];

  // Each status, answered by the register with a body that is no answer: the handler passes it on unsigned exactly
  // when a status_skip policy of the manifest names it, and signs it exactly when a status_attest policy does.
  it.each([
    ...STATUSES.map((status) => ['VIES', status] as const),
    ...STATUSES.map((status) => ['HMRC', status] as const),
  ])('%s answering %i', async (register, status) => {
    if (register === 'VIES') fakeIo.reply(VIES_PORT, httpReply(status, '<html>no answer</html>', { 'Content-Type': 'text/html' }));
    else fakeIo.reply(HMRC_PORT, json(status, JSON.stringify({ code: 'SERVER_ERROR' })));
    const res = await check(register === 'VIES' ? { countryCode: 'PT', vatNumber: '503504564' } : gb('123456789'));
    expect(res.success && res.status === status && res.attestation === undefined).toBe(shouldSkipAttestation(HANDLER_MANIFEST.policies, status));
    expect(res.success && res.attestation !== undefined).toBe(getAttestOverrides(HANDLER_MANIFEST.policies, status) !== null);
  });

  /**
   * The manifests the enclave releases shipped, with their versions: a version names one manifest, so a changed manifest
   * moves its version. The first entry is the 2026-10-09 release's (718b999), the second the R4 release's. The next
   * release appends its own.
   */
  const SHIPPED: ReadonlyArray<readonly [version: string, hash: string]> = [
    ['1.0.0', 'ff9e64d530c112defa3a325c4cae3d1477d64706dd3ec28092c8a993f287ac67'],
    ['1.1.0', 'e9b6b13fb35fb9afb5992733c00ead1b2b071d3413c6649bfd28a1f97664abf2'],
  ];

  it('a version names one manifest: a changed manifest moves its version', () => {
    for (const [version, hash] of SHIPPED) {
      expect(HANDLER_MANIFEST.version === version, `shipped ${version}`).toBe(MANIFEST_HASH === hash);
    }
  });
});
