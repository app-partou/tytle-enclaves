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

import { createHandler } from '@tytle-enclaves/shared';
import type { EnclaveResponse } from '@tytle-enclaves/shared';
import { encodeFieldElements, hashFieldElements, VIES_SCHEMA } from '../../../shared/src/bn254Codec.js';
import { fakeIo, httpReply } from '../../../shared/src/__tests__/helpers/fakeEnclaveIo.js';
import { viesHandlerDef, VIES_HOSTS } from '../viesHandler.js';
import { HANDLER_MANIFEST, MANIFEST_HASH } from '../manifest.js';

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
const xml = (body: string, status = 200) => httpReply(status, body, { 'Content-Type': 'text/xml; charset=UTF-8' });
const json = (status: number, body: string) => httpReply(status, body, { 'Content-Type': 'application/json' });

const handler = createHandler(viesHandlerDef, VIES_HOSTS);

function check(body: unknown): Promise<EnclaveResponse> {
  return handler({ id: 'req-1', url: 'https://ec.europa.eu/x', method: 'POST', headers: {}, body: typeof body === 'string' ? body : JSON.stringify(body) });
}

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

describe('VIES (lock)', () => {
  it('a valid number: valid, name and the three-line address are signed', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_VALID));
    const res = await check({ countryCode: 'PT', vatNumber: '503504564' });

    const name = 'EDP COMERCIAL - COMERCIALIZAÇÃO DE ENERGIA S A';
    const address = 'AV 24 DE JULHO N 12\nLISBOA\n1249-300 LISBOA';
    const want = signed({ countryCode: 'PT', vatNumber: '503504564', valid: 1, name, address });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64, bn254: want.base64 });
    expect(res.headers).toMatchObject({ 'x-vies-valid': 'true', 'x-vies-name': name, 'x-vies-address': address, 'x-vies-manifest-hash': MANIFEST_HASH });
    expect(res.bn254Headers).toEqual({ 'x-vies-name': name, 'x-vies-address': address });
    // The attested request config names the number asked and the manifest the handler ran under.
    const requestConfig = `https://ec.europa.eu/taxation_customs/vies/services/checkVatService|POST|${JSON.stringify({ countryCode: 'PT', vatNumber: '503504564', 'x-manifest-hash': MANIFEST_HASH })}`;
    expect(res.attestation?.requestHash).toBe(createHash('sha256').update(requestConfig).digest('hex'));
    expect(fakeIo.nsmAsks.map((a) => a.userData?.toString('hex'))).toEqual([want.hash]);
  });

  it('VIES\'s own "not valid" is signed as valid 0', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_NOT_VALID));
    const res = await check({ countryCode: 'PT', vatNumber: '123456789' });
    const want = signed({ countryCode: 'PT', vatNumber: '123456789', valid: 0, name: null, address: null });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64 });
    expect(res.headers['x-vies-valid']).toBe('false');
  });

  it('asks VIES over its own port with the SOAP checkVat request', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_VALID));
    await check({ countryCode: 'PT', vatNumber: '503504564' });
    const [request] = fakeIo.requests(VIES_PORT);
    expect(request).toMatch(/^POST \/taxation_customs\/vies\/services\/checkVatService HTTP\/1\.1\r\n/);
    expect(request).toContain('<urn:countryCode>PT</urn:countryCode>');
    expect(request).toContain('<urn:vatNumber>503504564</urn:vatNumber>');
    expect(fakeIo.requests(HMRC_PORT)).toEqual([]);
  });

  it('a SOAP fault is an error, never signed', async () => {
    fakeIo.reply(VIES_PORT, xml(VIES_FAULT));
    const res = await check({ countryCode: 'PT', vatNumber: '503504564' });
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(res.error).toContain('INVALID_INPUT');
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });

  it('a VIES HTTP 500 is an error', async () => {
    fakeIo.reply(VIES_PORT, xml('error', 500));
    const res = await check({ countryCode: 'PT', vatNumber: '503504564' });
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });
});

describe('HMRC (lock)', () => {
  it('a registered number: valid, name and address are signed', async () => {
    fakeIo.reply(HMRC_PORT, json(200, HMRC_REGISTERED));
    const res = await check({ countryCode: 'GB', vatNumber: '123456789' });
    const want = signed({ countryCode: 'GB', vatNumber: '123456789', valid: 1, name: 'EXAMPLE TRADING LTD', address: '10 EXAMPLE STREET, EXAMPLETOWN, EX1 1EX' });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64 });
    expect(res.headers).toMatchObject({ 'x-vies-valid': 'true', 'x-vies-name': 'EXAMPLE TRADING LTD' });
    const [request] = fakeIo.requests(HMRC_PORT);
    expect(request).toMatch(/^GET \/organisations\/vat\/check-vat-number\/lookup\/123456789 HTTP\/1\.1\r\n/);
    expect(fakeIo.requests(VIES_PORT)).toEqual([]);
  });

  it('HMRC\'s own "not registered" (404, code NOT_FOUND) is signed as valid 0', async () => {
    fakeIo.reply(HMRC_PORT, json(404, HMRC_NOT_REGISTERED));
    const res = await check({ countryCode: 'GB', vatNumber: '123456789' });
    const want = signed({ countryCode: 'GB', vatNumber: '123456789', valid: 0, name: null, address: null });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64 });
    expect(res.headers['x-vies-valid']).toBe('false');
  });

  it('an HMRC 500 is an error', async () => {
    fakeIo.reply(HMRC_PORT, json(500, '{}'));
    const res = await check({ countryCode: 'GB', vatNumber: '123456789' });
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(fakeIo.nsmAsks).toHaveLength(0);
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
    await expectError({ countryCode: 'GB', vatNumber: '123456789' }, /HMRC returned 404 MATCHING_RESOURCE_NOT_FOUND - not a "not registered" answer/);
  });

  it('an HMRC 404 without a JSON error code (a proxy or WAF page)', async () => {
    fakeIo.reply(HMRC_PORT, httpReply(404, '<html><body>Not Found</body></html>', { 'Content-Type': 'text/html' }));
    await expectError({ countryCode: 'GB', vatNumber: '123456789' }, /HMRC returned 404 without an error code/);
  });

  it('an HMRC 200 that names no company', async () => {
    fakeIo.reply(HMRC_PORT, json(200, '{}'));
    await expectError({ countryCode: 'GB', vatNumber: '123456789' }, /HMRC response has no target/);
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
    fakeIo.reply(VIES_PORT, xml(VIES_VALID
      .replace('EDP COMERCIAL - COMERCIALIZAÇÃO DE ENERGIA S A', 'SMITH &amp; SONS &lt;PT&gt; &amp;lt;1&amp;gt;')
      .replace('AV 24 DE JULHO N 12', 'RUA D&apos;ALMEIDA &quot;12&quot;')));
    const res = await check({ countryCode: 'PT', vatNumber: '503504564' });
    const address = 'RUA D\'ALMEIDA "12"\nLISBOA\n1249-300 LISBOA';
    // "&amp;lt;" is the text "&lt;": read once, never twice.
    const name = 'SMITH & SONS <PT> &lt;1&gt;';
    const want = signed({ countryCode: 'PT', vatNumber: '503504564', valid: 1, name, address });
    expect(res).toMatchObject({ success: true, rawBody: want.base64 });
    expect(res.headers).toMatchObject({ 'x-vies-name': name, 'x-vies-address': address });
  });
});

describe('manifest (lock)', () => {
  it('declares the VIES_SCHEMA fields in order', () => {
    expect(HANDLER_MANIFEST.schema.fields.map((f) => [f.name, f.encoding])).toEqual(VIES_SCHEMA.map((f) => [f.name, f.encoding]));
  });
});
