import { describe, it, expect, vi, beforeEach } from 'vitest';

// Import real codec directly (bypasses barrel re-export that pulls in native)
import { encodeFieldElements, SICAE_SCHEMA } from '../../node_modules/@tytle-enclaves/shared/src/bn254Codec.js';

// vi.hoisted runs before vi.mock hoisting — safe to reference in factory
const { mockProxyFetchPlain, mockAttest } = vi.hoisted(() => ({
  mockProxyFetchPlain: vi.fn(),
  mockAttest: vi.fn().mockResolvedValue({
    attestationId: 'test-att-id',
    responseHash: 'deadbeef',
    mode: 'dev',
    pcrs: { pcr0: '0'.repeat(96) },
    timestamp: 1234567890,
  }),
}));

// Mock @tytle-enclaves/shared — provide real codec + mocked proxyFetchPlain/attest
vi.mock('@tytle-enclaves/shared', () => ({
  encodeFieldElements,
  SICAE_SCHEMA,
  proxyFetchPlain: mockProxyFetchPlain,
  attest: mockAttest,
}));

import { createSicaeHandler } from '../sicaeHandler.js';

interface EnclaveRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}

const handler = createSicaeHandler({
  hostname: 'www.sicae.pt',
  vsockProxyPort: 8445,
});

function makeRequest(body: string): EnclaveRequest {
  return {
    url: 'http://www.sicae.pt/Consulta.aspx',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  };
}

// =============================================================================
// Real SICAE HTML Fixtures (fetched from www.sicae.pt on 2026-02-17)
// =============================================================================

/** GET Consulta.aspx — landing page with ASP.NET form tokens */
const CONSULTA_PAGE = `<!DOCTYPE html>
<html><head><title>SICAE</title></head><body>
<form method="post" action="Consulta.aspx" id="form1">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="dDwtMTIzNDU2Nzg5MDt0PDs7bDw=" />
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="dDwtMTIzNDU2Nzg5MDt0PDs7bDw9" />
<input name="ctl00$MainContent$ipNipc" type="text" id="ctl00_MainContent_ipNipc" />
<input type="submit" name="ctl00$MainContent$btnPesquisa" value="Pesquisar" id="ctl00_MainContent_btnPesquisa" />
</form></body></html>`;

/** NIF 513032525 — SUCCESS: GREEN OPPORTUNITY LDA, primary 71120, 3 secondary CAEs */
const RESULT_513032525 = `<!DOCTYPE html>
<html><head><title>SICAE</title></head><body>
<form method="post" action="Consulta.aspx" id="form1">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="abc123" />
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="def456" />
<table class="gridMain" cellspacing="0" border="0" id="ctl00_MainContent_ConsultaDataGrid" style="border-collapse:collapse;text-align: center">
	<tr class="gridHeader">
		<td>NIPC</td><td>Denomina\u00e7\u00e3o Social/Firma</td><td>CAE Principal</td><td>CAEs Secund\u00e1rios</td><td>Mais CAE</td>
	</tr><tr>
		<td>513032525</td><td class="upperFirma"><div style="cursor: pointer;" title="GREEN OPPORTUNITY LDA">GREEN OPPORTUNITY LDA</div>
            </td><td>
                    <div style="cursor: pointer;" title="Atividades de engenharia e t\u00e9cnicas afins">
                        71120</div>
                </td><td class="centerCae">
                    <div style="cursor: pointer; float: left; padding-left:50px;" title="Com\u00e9rcio a retalho n\u00e3o especializado, por outros m\u00e9todos, sem predomin\u00e2ncia de produtos alimentares, bebidas e tabaco">
                        47126,</div>
                    <div style="cursor: pointer; float: left; padding-left:15px;" title="Compra e venda de bens imobili\u00e1rios">
                        68110,</div>
                    <div style="cursor: pointer; float: left; padding-left:15px;" title="Atividades de servi\u00e7os de intermedia\u00e7\u00e3o de atividades imobili\u00e1rias">
                        68310</div>
                </td><td>
                    <div style="cursor: pointer; float: left; padding-left:15px;" title="Ver mais CAE"><a target="_self" href='Detalhe.aspx?NIPC=513032525' > Mais CAE</a></div>
                </td>
	</tr>
</table>
</form></body></html>`;

/** NIF 980494796 — NO DATA: gridMain present but "Não existem dados..." */
const RESULT_NO_DATA = `<!DOCTYPE html>
<html><head><title>SICAE</title></head><body>
<form method="post" action="Consulta.aspx" id="form1">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="abc123" />
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="def456" />
<table class="gridMain" cellspacing="0" border="0" id="ctl00_MainContent_ConsultaDataGrid" style="border-collapse:collapse;text-align: center">
	<tr class="gridHeader">
		<td>NIPC</td><td>Denomina\u00e7\u00e3o Social/Firma</td><td>CAE Principal</td><td>CAEs Secund\u00e1rios</td>
	</tr><tr>
		<td>&nbsp;</td><td class="upperFirma"><div style="cursor: pointer;" title="N\u00e3o existem dados para o crit\u00e9rio de pesquisa indicado.">N\u00e3o existem dados para o crit\u00e9rio de pesquisa indicado.</div>
            </td><td>
                    <div style="cursor: pointer;" title="">
                        </div>
                </td><td class="centerCae">
                    <div style="cursor: pointer; float: left; padding-left:50px;" title="">
                        </div>
                    <div style="cursor: pointer; float: left; padding-left:15px;" title="">
                        </div>
                    <div style="cursor: pointer; float: left; padding-left:15px;" title="">
                        </div>
                </td>
	</tr>
</table>
</form></body></html>`;

/** NIF 308203811 — VALIDATION ERROR: ClassErro, no gridMain */
const RESULT_INVALID_NIF = `<!DOCTYPE html>
<html><head><title>SICAE</title></head><body>
<form method="post" action="Consulta.aspx" id="form1">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="abc123" />
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="def456" />
<span id="ctl00_MainContent_lblError" class="ClassErro">O campo 'NIPC' n\u00e3o \u00e9 v\u00e1lido</span>
</form></body></html>`;

// =============================================================================
// Helper — sets up standard GET + POST mock sequence
// =============================================================================

function mockSicaeFlow(resultHtml: string, cookie?: string) {
  // GET Consulta.aspx
  mockProxyFetchPlain.mockResolvedValueOnce({
    status: 200,
    headers: cookie ? { 'set-cookie': `ASP.NET_SessionId=${cookie}; path=/; HttpOnly` } : {},
    body: CONSULTA_PAGE,
  });
  // POST with NIF — the handler tries both form variants; we mock both calls
  // returning the same result (first variant produces the result, handler stops)
  mockProxyFetchPlain.mockResolvedValueOnce({
    status: 200,
    headers: {},
    body: resultHtml,
  });
  // Second variant (in case first doesn't match) — provide a fallback
  mockProxyFetchPlain.mockResolvedValueOnce({
    status: 200,
    headers: {},
    body: resultHtml,
  });
}

// =============================================================================
// Tests
// =============================================================================

beforeEach(() => {
  mockProxyFetchPlain.mockReset();
  mockAttest.mockReset().mockResolvedValue({
    attestationId: 'test-att-id',
    responseHash: 'deadbeef',
    mode: 'dev',
    pcrs: { pcr0: '0'.repeat(96) },
    timestamp: 1234567890,
  });
});

describe('request validation', () => {
  it('returns 400 for invalid JSON body', async () => {
    const result = await handler(makeRequest('not json'));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('Invalid request body');
  });

  it('returns 400 for empty body', async () => {
    const result = await handler(makeRequest(''));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
  });

  it('returns 400 for missing nif', async () => {
    const result = await handler(makeRequest(JSON.stringify({})));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('Invalid NIF');
  });

  it('returns 400 for non-9-digit NIF', async () => {
    const result = await handler(makeRequest(JSON.stringify({ nif: '12345' })));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('must be exactly 9 digits');
  });

  it('returns 400 for NIF with letters', async () => {
    const result = await handler(makeRequest(JSON.stringify({ nif: '12345678A' })));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
  });
});

describe('SICAE lookup — real HTML fixtures', () => {
  it('parses NIF 513032525 (GREEN OPPORTUNITY LDA) with primary + 3 secondary CAEs', async () => {
    mockSicaeFlow(RESULT_513032525);

    const result = await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    expect(result.success).toBe(true);
    expect(result.status).toBe(200);
    expect(result.headers['x-sicae-nif']).toBe('513032525');
    expect(result.headers['x-sicae-name']).toBe('GREEN OPPORTUNITY LDA');
    expect(result.headers['x-sicae-cae1-code']).toBe('71120');
    // Primary desc comes from fallback strategy (no title extraction)
    // or primary strategy — either way, code must be correct
    expect(result.headers['x-sicae-cae1-code']).toMatch(/^\d{5}$/);

    // First secondary CAE should be 47126
    expect(result.headers['x-sicae-cae2-code']).toBe('47126');

    // rawBody should be base64 of 192 bytes (6 fields x 32 bytes)
    const raw = Buffer.from(result.rawBody, 'base64');
    expect(raw.length).toBe(192);
  });

  it('handles "Não existem dados" response (NIF exists but no CAE data)', async () => {
    mockSicaeFlow(RESULT_NO_DATA);

    const result = await handler(makeRequest(JSON.stringify({ nif: '980494796' })));

    expect(result.success).toBe(false);
    expect(result.status).toBe(404);
    expect(result.error).toContain('No CAE found');
    expect(result.headers['x-sicae-nif']).toBe('980494796');
  });

  it('handles ClassErro validation error (invalid NIF 308203811)', async () => {
    mockSicaeFlow(RESULT_INVALID_NIF);

    const result = await handler(makeRequest(JSON.stringify({ nif: '308203811' })));

    expect(result.success).toBe(false);
    expect(result.status).toBe(404);
    expect(result.error).toContain('No CAE found');
  });
});

describe('HTTP flow', () => {
  it('passes session cookie from GET to POST', async () => {
    mockSicaeFlow(RESULT_513032525, 'sess_abc123');

    await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    // Second call is the POST — verify it includes the cookie
    const postHeaders = mockProxyFetchPlain.mock.calls[1][4] as Record<string, string>;
    expect(postHeaders['Cookie']).toBe('ASP.NET_SessionId=sess_abc123');
  });

  it('sends correct form data in POST', async () => {
    mockSicaeFlow(RESULT_513032525);

    await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    // Verify the GET call
    expect(mockProxyFetchPlain.mock.calls[0][0]).toBe(8445);
    expect(mockProxyFetchPlain.mock.calls[0][1]).toBe('www.sicae.pt');
    expect(mockProxyFetchPlain.mock.calls[0][2]).toBe('GET');
    expect(mockProxyFetchPlain.mock.calls[0][3]).toBe('/Consulta.aspx');

    // Verify the POST call
    expect(mockProxyFetchPlain.mock.calls[1][2]).toBe('POST');
    expect(mockProxyFetchPlain.mock.calls[1][3]).toBe('/Consulta.aspx');
    const formBody = mockProxyFetchPlain.mock.calls[1][5] as string;
    expect(formBody).toContain('513032525');
    expect(formBody).toContain('__VIEWSTATE');
    expect(formBody).toContain('__EVENTVALIDATION');
  });

  it('handles GET failure', async () => {
    mockProxyFetchPlain.mockResolvedValueOnce({
      status: 503,
      headers: {},
      body: 'Service Unavailable',
    });

    const result = await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    expect(result.success).toBe(false);
    expect(result.status).toBe(503);
    expect(result.error).toContain('SICAE GET failed');
  });

  it('handles missing __VIEWSTATE', async () => {
    mockProxyFetchPlain.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: '<html><body>No viewstate here</body></html>',
    });

    const result = await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('__VIEWSTATE');
  });

  it('handles missing __EVENTVALIDATION', async () => {
    mockProxyFetchPlain.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: '<html><body><input type="hidden" id="__VIEWSTATE" value="abc" /></body></html>',
    });

    const result = await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('__EVENTVALIDATION');
  });
});

describe('BN254 encoding output', () => {
  it('produces exactly 192 bytes (6 fields x 32 bytes)', async () => {
    mockSicaeFlow(RESULT_513032525);

    const result = await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    const raw = Buffer.from(result.rawBody, 'base64');
    expect(raw.length).toBe(192);
  });

  it('produces deterministic output for identical inputs', async () => {
    mockSicaeFlow(RESULT_513032525);
    const r1 = await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    mockSicaeFlow(RESULT_513032525);
    const r2 = await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    expect(r1.rawBody).toBe(r2.rawBody);
  });

  it('NIF field element at offset 0-31 encodes the NIF as shortString', async () => {
    mockSicaeFlow(RESULT_513032525);

    const result = await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    const raw = Buffer.from(result.rawBody, 'base64');
    // shortString encoding: BigInt('0x' + Buffer.from('513032525').toString('hex'))
    const nifHex = Buffer.from('513032525', 'utf8').toString('hex');
    const expected = BigInt('0x' + nifHex);
    const actual = BigInt('0x' + raw.subarray(0, 32).toString('hex'));
    expect(actual).toBe(expected);
  });

  it('no-data response does not produce BN254 output', async () => {
    mockSicaeFlow(RESULT_NO_DATA);

    const result = await handler(makeRequest(JSON.stringify({ nif: '980494796' })));

    expect(result.success).toBe(false);
    expect(result.rawBody).toBe('');
  });
});
