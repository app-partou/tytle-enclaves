import { describe, it, expect, vi, beforeEach } from 'vitest';

// Import real codec directly (bypasses barrel re-export that pulls in native)
import { encodeFieldElements, hashFieldElements, VIES_SCHEMA } from '../../../shared/src/bn254Codec.js';
import { stableStringify, computeManifestHash, validateManifest } from '../../../shared/src/manifest.js';
import { toErrorMessage } from '../../../shared/src/errorUtils.js';
import { getHeadersToStrip, redactError } from '../../../shared/src/policyEngine.js';
import { stripSensitiveHeaders } from '../../../shared/src/sanitize.js';
import { SKIP_TRANSIENT_ERRORS, ATTEST_NOT_FOUND, STRIP_AUTH, REDACT_BEARER } from '../../../shared/src/policies.js';

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
    encodeFieldElements, hashFieldElements, VIES_SCHEMA,
    stableStringify, computeManifestHash, validateManifest,
    toErrorMessage, getHeadersToStrip, redactError, stripSensitiveHeaders,
    SKIP_TRANSIENT_ERRORS, ATTEST_NOT_FOUND, STRIP_AUTH, REDACT_BEARER,
    proxyFetch: mockProxyFetch, proxyFetchPlain: mockProxyFetch,
    proxyFetchWithRetry: mockProxyFetch,
    attest: mockAttest, errorResponse, encodeBn254AndAttest, createHandler,
  };
});

import { viesHandlerDef } from '../viesHandler.js';
import { createHandler } from '@tytle-enclaves/shared';
import { HANDLER_MANIFEST, MANIFEST_HASH } from '../manifest.js';

const hosts = [
  { hostname: 'ec.europa.eu', vsockProxyPort: 8443 },
  { hostname: 'api.service.hmrc.gov.uk', vsockProxyPort: 8444 },
];

const handler = createHandler(viesHandlerDef as Parameters<typeof createHandler>[0], hosts);

function makeRequest(body: string) {
  return { id: 'test-req', url: 'https://test', method: 'POST', headers: {}, body };
}

function viesSoapValid(cc: string, vn: string, name: string, addr: string): string {
  return `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><checkVatResponse xmlns="urn:ec.europa.eu:taxud:vies:services:checkVat:types"><countryCode>${cc}</countryCode><vatNumber>${vn}</vatNumber><valid>true</valid><name>${name}</name><address>${addr}</address></checkVatResponse></soap:Body></soap:Envelope>`;
}
function viesSoapInvalid(cc: string, vn: string): string {
  return `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><checkVatResponse xmlns="urn:ec.europa.eu:taxud:vies:services:checkVat:types"><countryCode>${cc}</countryCode><vatNumber>${vn}</vatNumber><valid>false</valid><name>---</name><address>---</address></checkVatResponse></soap:Body></soap:Envelope>`;
}
function viesSoapFault(code: string): string {
  return `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Server</faultcode><faultstring>${code}</faultstring></soap:Fault></soap:Body></soap:Envelope>`;
}
function hmrcValid(vn: string, name: string): string {
  return JSON.stringify({ target: { name, vatNumber: vn, address: { line1: '10 Downing St', postcode: 'SW1A' } } });
}

beforeEach(() => {
  mockProxyFetch.mockReset();
  mockAttest.mockReset().mockResolvedValue({
    attestationId: 'test-att-id', responseHash: 'deadbeef', mode: 'dev',
    pcrs: { pcr0: '0'.repeat(96) }, timestamp: 1234567890,
  });
});

describe('request validation', () => {
  it('returns 400 for invalid JSON body', async () => {
    const r = await handler(makeRequest('not json'));
    expect(r.success).toBe(false);
    expect(r.status).toBe(400);
  });

  it('returns 400 for missing countryCode', async () => {
    const r = await handler(makeRequest(JSON.stringify({ vatNumber: '123' })));
    expect(r.success).toBe(false);
    expect(r.status).toBe(400);
    expect(r.error).toContain('required');
  });

  it('returns 400 for invalid countryCode format', async () => {
    const r = await handler(makeRequest(JSON.stringify({ countryCode: 'P&T', vatNumber: '123' })));
    expect(r.success).toBe(false);
    expect(r.status).toBe(400);
    expect(r.error).toContain('Invalid countryCode');
  });
});

describe('VIES SOAP path', () => {
  it('parses valid response and returns BN254 output', async () => {
    mockProxyFetch.mockResolvedValueOnce({ status: 200, headers: {}, body: viesSoapValid('PT', '507172230', 'TYTLE LDA', 'RUA 123') });
    const r = await handler(makeRequest(JSON.stringify({ countryCode: 'PT', vatNumber: '507172230' })));
    expect(r.success).toBe(true);
    expect(r.status).toBe(200);
    expect(r.headers['x-vies-valid']).toBe('true');
    expect(r.headers['x-vies-name']).toBe('TYTLE LDA');
    expect(Buffer.from(r.rawBody, 'base64').length).toBe(160);
  });

  it('parses invalid VAT response', async () => {
    mockProxyFetch.mockResolvedValueOnce({ status: 200, headers: {}, body: viesSoapInvalid('DE', '999') });
    const r = await handler(makeRequest(JSON.stringify({ countryCode: 'DE', vatNumber: '999' })));
    expect(r.success).toBe(true);
    expect(r.headers['x-vies-valid']).toBe('false');
  });

  it('handles SOAP fault', async () => {
    mockProxyFetch.mockResolvedValueOnce({ status: 200, headers: {}, body: viesSoapFault('MS_UNAVAILABLE') });
    const r = await handler(makeRequest(JSON.stringify({ countryCode: 'PT', vatNumber: '507172230' })));
    expect(r.success).toBe(false);
    expect(r.status).toBe(502);
    expect(r.error).toContain('MS_UNAVAILABLE');
  });

  it('handles non-200 VIES status', async () => {
    mockProxyFetch.mockResolvedValueOnce({ status: 500, headers: {}, body: 'error' });
    const r = await handler(makeRequest(JSON.stringify({ countryCode: 'PT', vatNumber: '507172230' })));
    expect(r.success).toBe(false);
    expect(r.status).toBe(502);
  });
});

describe('HMRC path (GB)', () => {
  it('routes GB to HMRC and returns valid result', async () => {
    mockProxyFetch.mockResolvedValueOnce({ status: 200, headers: {}, body: hmrcValid('123', 'British Co') });
    const r = await handler(makeRequest(JSON.stringify({ countryCode: 'GB', vatNumber: '123' })));
    expect(r.success).toBe(true);
    expect(r.headers['x-vies-valid']).toBe('true');
    expect(r.headers['x-vies-name']).toBe('British Co');
  });

  it('handles HMRC 404 (not found)', async () => {
    mockProxyFetch.mockResolvedValueOnce({ status: 404, headers: {}, body: '{}' });
    const r = await handler(makeRequest(JSON.stringify({ countryCode: 'GB', vatNumber: '000' })));
    expect(r.success).toBe(true);
    expect(r.headers['x-vies-valid']).toBe('false');
  });

  it('throws on HMRC 500', async () => {
    mockProxyFetch.mockResolvedValueOnce({ status: 500, headers: {}, body: 'err' });
    const r = await handler(makeRequest(JSON.stringify({ countryCode: 'GB', vatNumber: '123' })));
    expect(r.success).toBe(false);
    expect(r.status).toBe(502);
  });
});

describe('BN254 attestation', () => {
  it('returns bn254 and bn254Headers', async () => {
    mockProxyFetch.mockResolvedValueOnce({ status: 200, headers: {}, body: viesSoapValid('PT', '507172230', 'NAME', 'ADDR') });
    const r = await handler(makeRequest(JSON.stringify({ countryCode: 'PT', vatNumber: '507172230' })));
    expect(r.bn254).toBe(r.rawBody);
    expect(r.bn254Headers?.['x-vies-name']).toBe('NAME');
  });

  it('includes manifest hash in response headers', async () => {
    mockProxyFetch.mockResolvedValueOnce({ status: 200, headers: {}, body: viesSoapValid('IE', '123', 'CO', 'ADDR') });
    const r = await handler(makeRequest(JSON.stringify({ countryCode: 'IE', vatNumber: '123' })));
    expect(r.headers['x-vies-manifest-hash']).toBe(MANIFEST_HASH);
  });
});

describe('manifest', () => {
  it('schema fields match VIES_SCHEMA', () => {
    expect(HANDLER_MANIFEST.schema.fields.length).toBe(VIES_SCHEMA.length);
    for (let i = 0; i < VIES_SCHEMA.length; i++) {
      expect(HANDLER_MANIFEST.schema.fields[i].name).toBe(VIES_SCHEMA[i].name);
      expect(HANDLER_MANIFEST.schema.fields[i].encoding).toBe(VIES_SCHEMA[i].encoding);
    }
  });
});
