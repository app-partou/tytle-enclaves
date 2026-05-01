import { describe, it, expect, vi, beforeEach } from 'vitest';

// Import real codec directly (bypasses barrel re-export that pulls in native)
import { encodeFieldElements, hashFieldElements, SICAE_SCHEMA } from '../../../shared/src/bn254Codec.js';
import { stableStringify, computeManifestHash, validateManifest } from '../../../shared/src/manifest.js';
import { toErrorMessage } from '../../../shared/src/errorUtils.js';
import { getHeadersToStrip, redactError } from '../../../shared/src/policyEngine.js';
import { stripSensitiveHeaders } from '../../../shared/src/sanitize.js';
import { SKIP_TRANSIENT_ERRORS, ATTEST_NOT_FOUND, STRIP_AUTH, REDACT_BEARER } from '../../../shared/src/policies.js';

// vi.hoisted runs before vi.mock hoisting — safe to reference in factory
const { mockProxyFetch, mockAttest } = vi.hoisted(() => ({
  mockProxyFetch: vi.fn(),
  mockAttest: vi.fn().mockResolvedValue({
    attestationId: 'test-att-id',
    responseHash: 'deadbeef',
    mode: 'dev',
    pcrs: { pcr0: '0'.repeat(96) },
    timestamp: 1234567890,
  }),
}));

// Mock @tytle-enclaves/shared — provide real codec + mocked proxyFetch/attest
vi.mock('@tytle-enclaves/shared', () => {
  const errorResponse = (status: number, error: string, headers: Record<string, string> = {}) =>
    ({ success: false, status, headers, rawBody: '', error });

  const encodeBn254AndAttest = async (
    schema: unknown[], values: Record<string, unknown>,
    args: { apiEndpoint: string; method: string; url: string; requestHeaders: Record<string, string> },
  ) => {
    const encodedBytes = encodeFieldElements(schema as Parameters<typeof encodeFieldElements>[0], values);
    const rawBody = encodedBytes.toString('base64');
    const bn254Hash = hashFieldElements(encodedBytes);
    const attestation = await mockAttest(args.apiEndpoint, args.method, rawBody, args.url, args.requestHeaders, bn254Hash);
    return { rawBody, bn254Hash, attestation: { ...attestation, bn254Hash } };
  };

  // Inline createHandler that mirrors the real factory but uses mocked I/O
  const createHandler = (def: Record<string, unknown>, hosts: Array<{ hostname: string; vsockProxyPort: number; tls?: boolean }>) => {
    const hToStrip = getHeadersToStrip((def.policies || []) as Parameters<typeof getHeadersToStrip>[0]);
    const noop = () => {};
    const ctx = {
      hosts,
      log: { info: noop, warn: noop, error: noop },
      fetch: (host: { vsockProxyPort: number; hostname: string }, method: string, path: string, headers: Record<string, string>, body?: string) =>
        mockProxyFetch(host.vsockProxyPort, host.hostname, method, path, headers, body),
      fetchWithRetry: (host: { vsockProxyPort: number; hostname: string }, method: string, path: string, headers: Record<string, string>, body?: string) =>
        mockProxyFetch(host.vsockProxyPort, host.hostname, method, path, headers, body),
    };
    return async (request: { body?: string }) => {
      try {
        let params: unknown;
        try {
          const body = JSON.parse(request.body || '{}');
          params = (def.parseParams as (b: unknown) => unknown)(body);
        } catch (err: unknown) {
          return errorResponse(400, `Invalid request: ${toErrorMessage(err)}`);
        }
        const result = await (def.execute as (p: unknown, c: unknown) => Promise<Record<string, unknown>>)(params, ctx);
        if (result.rawPassthrough) return { success: true, ...(result.rawPassthrough as Record<string, unknown>) };
        if (result.skipAttestation) return { success: true, status: result.status ?? 200, headers: result.responseHeaders, rawBody: '' };
        const attestHeaders = hToStrip.length > 0
          ? stripSensitiveHeaders(result.requestHeaders as Record<string, string>, hToStrip)
          : result.requestHeaders as Record<string, string>;
        const attestResult = await encodeBn254AndAttest(
          def.schema as unknown[], result.values as Record<string, unknown>,
          {
            apiEndpoint: result.apiEndpoint as string, method: result.method as string,
            url: result.url as string,
            requestHeaders: { ...attestHeaders, 'x-manifest-hash': def.manifestHash as string },
          },
        );
        return {
          success: true, status: result.status ?? 200,
          headers: { ...(result.responseHeaders as Record<string, string>), [`x-${def.name}-manifest-hash`]: def.manifestHash },
          rawBody: attestResult.rawBody, attestation: attestResult.attestation,
          bn254: attestResult.rawBody, bn254Headers: result.bn254Headers,
        };
      } catch (err: unknown) {
        return errorResponse(502, redactError((def.policies || []) as Parameters<typeof redactError>[0], toErrorMessage(err)));
      }
    };
  };

  return {
    encodeFieldElements, hashFieldElements, SICAE_SCHEMA,
    stableStringify, computeManifestHash, validateManifest,
    toErrorMessage, getHeadersToStrip, redactError, stripSensitiveHeaders,
    SKIP_TRANSIENT_ERRORS, ATTEST_NOT_FOUND, STRIP_AUTH, REDACT_BEARER,
    proxyFetch: mockProxyFetch, proxyFetchPlain: mockProxyFetch,
    proxyFetchWithRetry: mockProxyFetch,
    attest: mockAttest, errorResponse, encodeBn254AndAttest, createHandler,
  };
});

import { sicaeHandlerDef } from '../sicaeHandler.js';
import { createHandler } from '@tytle-enclaves/shared';
import { HANDLER_MANIFEST, MANIFEST_HASH } from '../manifest.js';

const hosts = [{ hostname: 'www.sicae.pt', vsockProxyPort: 8445, tls: false as const }];

const handler = createHandler(sicaeHandlerDef as Parameters<typeof createHandler>[0], hosts);

function makeRequest(body: string) {
  return {
    id: 'test-request-id',
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
		<td>NIPC</td><td>Denominação Social/Firma</td><td>CAE Principal</td><td>CAEs Secundários</td><td>Mais CAE</td>
	</tr><tr>
		<td>513032525</td><td class="upperFirma"><div style="cursor: pointer;" title="GREEN OPPORTUNITY LDA">GREEN OPPORTUNITY LDA</div>
            </td><td>
                    <div style="cursor: pointer;" title="Atividades de engenharia e técnicas afins">
                        71120</div>
                </td><td class="centerCae">
                    <div style="cursor: pointer; float: left; padding-left:50px;" title="Comércio a retalho não especializado, por outros métodos, sem predominância de produtos alimentares, bebidas e tabaco">
                        47126,</div>
                    <div style="cursor: pointer; float: left; padding-left:15px;" title="Compra e venda de bens imobiliários">
                        68110,</div>
                    <div style="cursor: pointer; float: left; padding-left:15px;" title="Atividades de serviços de intermediação de atividades imobiliárias">
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
		<td>NIPC</td><td>Denominação Social/Firma</td><td>CAE Principal</td><td>CAEs Secundários</td>
	</tr><tr>
		<td>&nbsp;</td><td class="upperFirma"><div style="cursor: pointer;" title="Não existem dados para o critério de pesquisa indicado.">Não existem dados para o critério de pesquisa indicado.</div>
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
<span id="ctl00_MainContent_lblError" class="ClassErro">O campo 'NIPC' não é válido</span>
</form></body></html>`;

// =============================================================================
// Helper — sets up standard GET + POST mock sequence
// =============================================================================

function mockSicaeFlow(resultHtml: string, cookie?: string) {
  // GET Consulta.aspx
  mockProxyFetch.mockResolvedValueOnce({
    status: 200,
    headers: cookie ? { 'set-cookie': `ASP.NET_SessionId=${cookie}; path=/; HttpOnly` } : {},
    body: CONSULTA_PAGE,
  });
  // POST with NIF — the handler tries both form variants; we mock both calls
  // returning the same result (first variant produces the result, handler stops)
  mockProxyFetch.mockResolvedValueOnce({
    status: 200,
    headers: {},
    body: resultHtml,
  });
  // Second variant (in case first doesn't match) — provide a fallback
  mockProxyFetch.mockResolvedValueOnce({
    status: 200,
    headers: {},
    body: resultHtml,
  });
}

// =============================================================================
// Tests
// =============================================================================

beforeEach(() => {
  mockProxyFetch.mockReset();
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
    expect(result.error).toContain('Invalid request');
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

    // "Not found" is a valid, definitive answer — success: true so the provider
    // receives the 404 status via rawPassthrough instead of the enclave throwing.
    expect(result.success).toBe(true);
    expect(result.status).toBe(404);
    expect(result.headers['x-sicae-nif']).toBe('980494796');
  });

  it('handles ClassErro validation error (invalid NIF 308203811)', async () => {
    mockSicaeFlow(RESULT_INVALID_NIF);

    const result = await handler(makeRequest(JSON.stringify({ nif: '308203811' })));

    expect(result.success).toBe(true);
    expect(result.status).toBe(404);
  });
});

describe('HTTP flow', () => {
  it('passes session cookie from GET to POST', async () => {
    mockSicaeFlow(RESULT_513032525, 'sess_abc123');

    await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    // Second call is the POST — verify it includes the cookie
    const postHeaders = mockProxyFetch.mock.calls[1][4] as Record<string, string>;
    expect(postHeaders['Cookie']).toBe('ASP.NET_SessionId=sess_abc123');
  });

  it('sends correct form data in POST', async () => {
    mockSicaeFlow(RESULT_513032525);

    await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    // Verify the GET call
    expect(mockProxyFetch.mock.calls[0][0]).toBe(8445);
    expect(mockProxyFetch.mock.calls[0][1]).toBe('www.sicae.pt');
    expect(mockProxyFetch.mock.calls[0][2]).toBe('GET');
    expect(mockProxyFetch.mock.calls[0][3]).toBe('/Consulta.aspx');

    // Verify the POST call
    expect(mockProxyFetch.mock.calls[1][2]).toBe('POST');
    expect(mockProxyFetch.mock.calls[1][3]).toBe('/Consulta.aspx');
    const formBody = mockProxyFetch.mock.calls[1][5] as string;
    expect(formBody).toContain('513032525');
    expect(formBody).toContain('__VIEWSTATE');
    expect(formBody).toContain('__EVENTVALIDATION');
  });

  it('handles GET failure', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 503,
      headers: {},
      body: 'Service Unavailable',
    });

    const result = await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('SICAE GET failed');
  });

  it('handles missing __VIEWSTATE', async () => {
    mockProxyFetch.mockResolvedValueOnce({
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
    mockProxyFetch.mockResolvedValueOnce({
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

    expect(result.success).toBe(true);
    expect(result.status).toBe(404);
    expect(result.rawBody).toBe('');
  });
});

describe('BN254 attestation chain', () => {
  it('passes bn254Hash as 6th argument to attest()', async () => {
    mockSicaeFlow(RESULT_513032525);

    await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    expect(mockAttest).toHaveBeenCalledTimes(1);
    const attestArgs = mockAttest.mock.calls[0];
    // 6th argument should be BN254 hash (hex string, 64 chars)
    expect(attestArgs[5]).toMatch(/^[0-9a-f]{64}$/);
  });

  it('returns bn254 and bn254Headers in response', async () => {
    mockSicaeFlow(RESULT_513032525);

    const result = await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    expect(result.bn254).toBe(result.rawBody);
    expect(result.bn254Headers).toBeDefined();
    expect(result.bn254Headers!['x-sicae-name']).toBe('GREEN OPPORTUNITY LDA');
  });

  it('includes bn254Hash in attestation object', async () => {
    mockSicaeFlow(RESULT_513032525);

    const result = await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    expect(result.attestation).toBeDefined();
    expect((result.attestation as Record<string, unknown>).bn254Hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('bn254Hash matches SHA-256 of encoded field elements', async () => {
    mockSicaeFlow(RESULT_513032525);

    const result = await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    // Reproduce encoding using the same values the handler parsed from HTML.
    // Use the response headers as ground truth (they contain the parsed values).
    const expectedEncoded = encodeFieldElements(SICAE_SCHEMA, {
      nif: '513032525',
      name: result.headers['x-sicae-name'],
      cae1Code: result.headers['x-sicae-cae1-code'],
      cae1Desc: result.headers['x-sicae-cae1-desc'],
      cae2Code: result.headers['x-sicae-cae2-code'] || null,
      cae2Desc: result.headers['x-sicae-cae2-desc'] || null,
    });
    const expectedHash = hashFieldElements(expectedEncoded);

    expect((result.attestation as Record<string, unknown>).bn254Hash).toBe(expectedHash);
  });
});

describe('manifest hash integration', () => {
  it('includes manifest hash in success response headers', async () => {
    mockSicaeFlow(RESULT_513032525);

    const result = await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    expect(result.success).toBe(true);
    expect(result.status).toBe(200);
    expect(result.headers['x-sicae-manifest-hash']).toBe(MANIFEST_HASH);
  });

  it('includes manifest hash in attestation request headers', async () => {
    mockSicaeFlow(RESULT_513032525);

    await handler(makeRequest(JSON.stringify({ nif: '513032525' })));

    expect(mockAttest).toHaveBeenCalledTimes(1);
    const attestArgs = mockAttest.mock.calls[0];
    // 5th argument is requestHeaders passed through encodeBn254AndAttest
    const requestHeaders = attestArgs[4] as Record<string, string>;
    expect(requestHeaders['x-manifest-hash']).toBe(MANIFEST_HASH);
  });

  it('manifest schema fields match SICAE_SCHEMA', () => {
    const manifestFieldNames = HANDLER_MANIFEST.schema.fields.map((f: Record<string, unknown>) => f.name);
    const schemaFieldNames = SICAE_SCHEMA.map((f: Record<string, unknown>) => f.name);
    expect(manifestFieldNames).toEqual(schemaFieldNames);

    for (const field of HANDLER_MANIFEST.schema.fields) {
      const schemaField = SICAE_SCHEMA.find((f: Record<string, unknown>) => f.name === field.name);
      expect(schemaField).toBeDefined();
      expect(field.encoding).toBe(schemaField!.encoding);
    }
  });
});
