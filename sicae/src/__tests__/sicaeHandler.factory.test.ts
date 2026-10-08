/**
 * The SICAE handler through the REAL handler factory (P2.4) and SICAE's own pages (fixtures/README.md).
 *
 * MOCK BOUNDARY: the enclave's two boundaries only - the vsock socket to the host's proxy and the NSM device
 * (shared/src/__tests__/helpers/fakeEnclaveIo.ts). createHandler, ctx.fetch, the HTTP framing, the page
 * rules, the BN254 encoder and attest() all run for real.
 *
 * WHY (audit 2026-10 P1.4): the handler read every page it could not read - and a site that refused every
 * form - as "not found", and passed that answer on unsigned. Now only SICAE's own answers are answers: a
 * results row, its "no data" row and its "NIPC not valid" refusal (both signed as not_found: nif + five nulls,
 * status 404); anything else is an error (502), never signed.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

vi.mock('@tytle-enclaves/native', async () => (await import('../../../shared/src/__tests__/helpers/fakeEnclaveIo.js')).nativeModule);
vi.mock('node:tls', async () => (await import('../../../shared/src/__tests__/helpers/fakeEnclaveIo.js')).tlsModule);

import { createHandler } from '@tytle-enclaves/shared';
import type { EnclaveResponse } from '@tytle-enclaves/shared';
import { encodeFieldElements, hashFieldElements, SICAE_SCHEMA } from '../../../shared/src/bn254Codec.js';
import { fakeIo, httpReply } from '../../../shared/src/__tests__/helpers/fakeEnclaveIo.js';
import { sicaeHandlerDef, SICAE_HOSTS } from '../sicaeHandler.js';
import { HANDLER_MANIFEST, MANIFEST_HASH } from '../manifest.js';

const page = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf-8');
const SEARCH_PAGE = page('consulta-get.html');
const FOUND = page('post-found-503504564.html');
const NO_DATA = page('post-no-data-980494796.html');
const INVALID_NIPC = page('post-invalid-nipc-123456788.html');

const PORT = 8445;
const SESSION = 'fake0session0id0for0tests';
const html = (body: string) => httpReply(200, body, { 'Content-Type': 'text/html; charset=utf-8' });

const handler = createHandler(sicaeHandlerDef, SICAE_HOSTS);

function lookup(nif: unknown): Promise<EnclaveResponse> {
  return handler({ id: 'req-1', url: 'http://www.sicae.pt/Consulta.aspx', method: 'POST', headers: {}, body: JSON.stringify({ nif }) });
}

/** SICAE's search page, then the given POST answers (one per form variant the handler may try). */
function scriptSicae(...posts: string[]): void {
  fakeIo.reply(PORT, httpReply(200, SEARCH_PAGE, {
    'Content-Type': 'text/html; charset=utf-8',
    'Set-Cookie': `ASP.NET_SessionId=${SESSION}; path=/; HttpOnly`,
  }));
  for (const post of posts) fakeIo.reply(PORT, post);
}

const posts = () => fakeIo.requests(PORT).filter((r) => r.startsWith('POST '));

/** The SHA-256 hex of a page: the value the handler signs as dataHash. */
const sha256 = (page: string) => createHash('sha256').update(page, 'utf8').digest('hex');

/** The vector the enclave must sign, and the hash it must hand the NSM as user_data. */
function signed(values: Record<string, string | null>) {
  const vector = encodeFieldElements(SICAE_SCHEMA, values);
  return { base64: vector.toString('base64'), hash: hashFieldElements(vector) };
}
/** "Not found": nif, five nulls, the hash of the page it was read from, and the transport. */
const NOT_FOUND = (nif: string, page: string) => signed({
  nif, name: null, cae1Code: null, cae1Desc: null, cae2Code: null, cae2Desc: null, dataHash: sha256(page), transport: 'http',
});

beforeEach(() => {
  fakeIo.reset();
  // The enclave logs one JSON line per request to stdout (shared/src/logger.ts).
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

describe('request validation (lock)', () => {
  it.each([
    ['not JSON', 'not json', 'Invalid request'],
    ['an empty body', '', 'Invalid NIF'],
    ['no nif', JSON.stringify({}), 'Invalid NIF'],
    ['5 digits', JSON.stringify({ nif: '12345' }), 'must be exactly 9 digits'],
    ['a letter', JSON.stringify({ nif: '12345678A' }), 'must be exactly 9 digits'],
  ])('%s is a 400, and nothing is fetched', async (_label, body, error) => {
    const res = await handler({ id: 'r', url: 'http://www.sicae.pt/Consulta.aspx', method: 'POST', headers: {}, body });
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(res.error).toContain(error);
    expect(fakeIo.requests(PORT)).toHaveLength(0);
  });
});

describe('a results row', () => {
  it('signs nif, name, primary CAE and the first secondary CAE with its description (red before the release: the description was signed as null)', async () => {
    scriptSicae(html(FOUND));
    const res = await lookup('503504564');

    const want = signed({
      nif: '503504564',
      name: 'EDP COMERCIAL-COMERCIALIZAÇÃO DE ENERGIA, S.A.',
      cae1Code: '35151',
      cae1Desc: 'Comércio de eletricidade, exceto para mobilidade elétrica',
      cae2Code: '35230',
      cae2Desc: 'Comércio de gás por condutas',
      dataHash: sha256(FOUND),
      transport: 'http',
    });
    expect(res).toMatchObject({ success: true, status: 200, rawBody: want.base64, bn254: want.base64 });
    expect(res.headers).toMatchObject({
      'x-sicae-nif': '503504564',
      'x-sicae-name': 'EDP COMERCIAL-COMERCIALIZAÇÃO DE ENERGIA, S.A.',
      'x-sicae-cae1-code': '35151',
      'x-sicae-cae2-code': '35230',
      'x-sicae-manifest-hash': MANIFEST_HASH,
    });
    expect(res.bn254Headers).toEqual({
      'x-sicae-name': 'EDP COMERCIAL-COMERCIALIZAÇÃO DE ENERGIA, S.A.',
      'x-sicae-cae1-desc': 'Comércio de eletricidade, exceto para mobilidade elétrica',
      'x-sicae-cae2-desc': 'Comércio de gás por condutas',
      'x-sicae-data-hash': sha256(FOUND),
    });
    expect(res.attestation?.bn254Hash).toBe(want.hash);
    // The attested request config names the NIF and the manifest the handler ran under.
    const requestConfig = `http://www.sicae.pt/Consulta.aspx|POST|${JSON.stringify({ nif: '503504564', 'x-manifest-hash': MANIFEST_HASH })}`;
    expect(res.attestation?.requestHash).toBe(createHash('sha256').update(requestConfig).digest('hex'));
    expect(fakeIo.nsmAsks).toHaveLength(1);
    expect(fakeIo.nsmAsks[0].userData?.toString('hex')).toBe(want.hash);
  });

  it('carries the session cookie and the NIF in the form post, after one GET (lock)', async () => {
    scriptSicae(html(FOUND));
    await lookup('503504564');

    const [get, post, ...rest] = fakeIo.requests(PORT);
    expect(get).toMatch(/^GET \/Consulta\.aspx HTTP\/1\.1\r\n/);
    expect(get).toContain('Host: www.sicae.pt\r\n');
    expect(post).toMatch(/^POST \/Consulta\.aspx HTTP\/1\.1\r\n/);
    expect(post).toContain('ctl00%24MainContent%24btnPesquisa=Pesquisar');
    expect(post).toContain(`Cookie: ASP.NET_SessionId=${SESSION}\r\n`);
    expect(post).toContain('ctl00%24MainContent%24ipNipc=503504564');
    expect(rest).toEqual([]);
  });

  it('the same page gives the same signed bytes (lock)', async () => {
    scriptSicae(html(FOUND));
    const a = await lookup('503504564');
    scriptSicae(html(FOUND));
    const b = await lookup('503504564');
    expect(a.rawBody).toBe(b.rawBody);
  });
});

describe('SICAE\'s own "not found" answers are signed (red before the release)', () => {
  it('the "no data" row is not_found: nif + five nulls, status 404, attested, after one form', async () => {
    scriptSicae(html(NO_DATA));
    const res = await lookup('980494796');

    const want = NOT_FOUND('980494796', NO_DATA);
    expect(res).toMatchObject({ success: true, status: 404, rawBody: want.base64, bn254: want.base64 });
    expect(res.headers).toMatchObject({ 'x-sicae-nif': '980494796', 'x-sicae-not-found': 'no_data', 'x-sicae-manifest-hash': MANIFEST_HASH });
    expect(res.attestation?.bn254Hash).toBe(want.hash);
    expect(fakeIo.nsmAsks.map((a) => a.userData?.toString('hex'))).toEqual([want.hash]);
    expect(posts()).toHaveLength(1);
  });

  it('the "NIPC not valid" refusal is not_found too, attested, after one form', async () => {
    scriptSicae(html(INVALID_NIPC));
    const res = await lookup('123456788');

    const want = NOT_FOUND('123456788', INVALID_NIPC);
    expect(res).toMatchObject({ success: true, status: 404, rawBody: want.base64 });
    expect(res.headers['x-sicae-not-found']).toBe('invalid_nipc');
    expect(fakeIo.nsmAsks.map((a) => a.userData?.toString('hex'))).toEqual([want.hash]);
    expect(posts()).toHaveLength(1);
  });
});

describe('a page that is not one of SICAE\'s answers is an error, never signed (red before the release)', () => {
  async function expectError(nif: string, error: RegExp) {
    const res = await lookup(nif);
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(res.error).toMatch(error);
    expect(res.attestation).toBeUndefined();
    expect(fakeIo.nsmAsks).toHaveLength(0);
  }

  it('a results grid the handler cannot read: an error after one form', async () => {
    // SICAE's real results page with the primary CAE gone from the row: no rule reads it.
    const unreadable = FOUND.replace('35151</div>', '</div>').replace('35230,</div>', '</div>').replace('35152</div>', '</div>');
    expect(unreadable).not.toBe(FOUND);
    scriptSicae(html(unreadable));
    await expectError('503504564', /SICAE page unreadable: a results grid this handler cannot read/);
    expect(posts()).toHaveLength(1);
  });

  it('a results row for another NIPC is never signed under the asked one', async () => {
    scriptSicae(html(FOUND));
    await expectError('513032525', /SICAE page unreadable: the results row is for another NIPC \(503504564\)/);
  });

  it('a grid row with another message than SICAE\'s "no data" words', async () => {
    scriptSicae(html(NO_DATA.replaceAll('Não existem dados para o critério de pesquisa indicado.', 'Não foi possível obter os dados.')));
    await expectError('980494796', /SICAE page unreadable: a results grid this handler cannot read/);
  });

  it('the "no data" row beside another row', async () => {
    const row = NO_DATA.match(/<\/tr><tr>[\s\S]*?<\/tr>/)![0];
    scriptSicae(html(NO_DATA.replace(row, row + row.slice('</tr>'.length))));
    await expectError('980494796', /SICAE page unreadable: a results grid this handler cannot read/);
  });

  it('the "NIPC not valid" label beside a second label', async () => {
    scriptSicae(html(INVALID_NIPC.replace("não é válido</span>", 'não é válido</span><span class="ClassErro">Tente mais tarde.</span>')));
    await expectError('123456788', /an error label this handler does not know: "O campo 'NIPC' não é válido \| Tente mais tarde\."/);
  });

  it('an error label with any other text', async () => {
    scriptSicae(html(INVALID_NIPC.replace("O campo 'NIPC' não é válido", 'Ocorreu um erro inesperado.')));
    await expectError('123456788', /SICAE page unreadable: an error label this handler does not know: "Ocorreu um erro inesperado\."/);
  });

  it('the "NIPC not valid" label beside a results grid', async () => {
    const both = NO_DATA.replace('<table class="gridMain"', '<span id="ctl00_MainContent_lblError" class="ClassErro">O campo \'NIPC\' não é válido</span><table class="gridMain"');
    scriptSicae(html(both));
    await expectError('980494796', /SICAE page unreadable: an error label beside a results grid: "O campo 'NIPC' não é válido"/);
  });

  it('pages with neither a grid nor an error label, for every form variant: an error after both forms', async () => {
    scriptSicae(html(SEARCH_PAGE), html(SEARCH_PAGE));
    await expectError('503504564', /SICAE processed no form variant/);
    expect(posts()).toHaveLength(2);
  });

  it('a site that refuses every form variant', async () => {
    scriptSicae(httpReply(500, 'Server Error'), httpReply(400, 'Bad Request'));
    await expectError('503504564', /SICAE refused every form variant \(HTTP 500, 400\)/);
  });

  it('one refused variant, then a page with neither marker: still an error', async () => {
    scriptSicae(httpReply(500, 'Server Error'), html(SEARCH_PAGE));
    await expectError('503504564', /SICAE processed no form variant/);
  });
});

describe('the other variant is tried only when the first was not processed (lock)', () => {
  it('a refused first variant, then the results page', async () => {
    scriptSicae(httpReply(500, 'Server Error'), html(FOUND));
    const res = await lookup('503504564');
    expect(res).toMatchObject({ success: true, status: 200 });
    expect(posts()).toHaveLength(2);
    expect(posts()[1]).toContain('ctl00%24MainContent%24consultaSimplesNIPCNIPC=503504564');
  });
});

describe('what the vector commits to besides the answer (red before the release)', () => {
  it('dataHash is the SHA-256 of the page the answer was read from - not a page a first variant brought back', async () => {
    scriptSicae(html(SEARCH_PAGE), html(FOUND));
    const res = await lookup('503504564');
    expect(res.headers['x-sicae-data-hash']).toBe(sha256(FOUND));
    expect(Buffer.from(res.rawBody, 'base64')).toHaveLength(256);
  });

  it('transport is signed as "http": www.sicae.pt is reached in plaintext', async () => {
    scriptSicae(html(FOUND));
    const res = await lookup('503504564');
    expect(res.headers['x-sicae-transport']).toBe('http');
    const transport = Buffer.from(res.rawBody, 'base64').subarray(7 * 32, 8 * 32);
    expect(transport).toEqual(encodeFieldElements([{ name: 'transport', encoding: 'shortString' }], { transport: 'http' }));
  });
});

describe('the search page itself (lock)', () => {
  it('a GET that is not 200 is an error', async () => {
    fakeIo.reply(PORT, httpReply(503, 'Service Unavailable'));
    const res = await lookup('503504564');
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(res.error).toContain('SICAE GET failed: 503');
    expect(fakeIo.nsmAsks).toHaveLength(0);
  });

  it('a search page without __VIEWSTATE is an error', async () => {
    fakeIo.reply(PORT, html('<html><body>No viewstate here</body></html>'));
    const res = await lookup('503504564');
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(res.error).toContain('__VIEWSTATE');
  });

  it('a search page without __EVENTVALIDATION is an error', async () => {
    fakeIo.reply(PORT, html('<html><body><input type="hidden" id="__VIEWSTATE" value="abc" /></body></html>'));
    const res = await lookup('503504564');
    expect(res).toMatchObject({ success: false, status: 502 });
    expect(res.error).toContain('__EVENTVALIDATION');
  });
});

describe('manifest (lock)', () => {
  it('declares the SICAE_SCHEMA fields in order, and their size', () => {
    expect(HANDLER_MANIFEST.schema.fields.map((f) => [f.name, f.encoding])).toEqual(SICAE_SCHEMA.map((f) => [f.name, f.encoding]));
    expect(HANDLER_MANIFEST.schema.outputBytes).toBe(SICAE_SCHEMA.length * 32);
  });
});
