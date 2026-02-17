import { describe, it, expect, vi, beforeEach } from 'vitest';

// Import real codec directly (bypasses barrel re-export that pulls in native)
import { encodeFieldElements, VIES_SCHEMA } from '../../node_modules/@tytle-enclaves/shared/src/bn254Codec.js';

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
vi.mock('@tytle-enclaves/shared', () => ({
  encodeFieldElements,
  VIES_SCHEMA,
  proxyFetch: mockProxyFetch,
  attest: mockAttest,
}));

import { createViesHandler } from '../viesHandler.js';

interface EnclaveRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}

const handler = createViesHandler({
  viesHostname: 'ec.europa.eu',
  viesVsockPort: 8443,
  hmrcHostname: 'api.service.hmrc.gov.uk',
  hmrcVsockPort: 8444,
});

function makeRequest(body: string): EnclaveRequest {
  return {
    url: 'https://ec.europa.eu/taxation_customs/vies/services/checkVatService',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  };
}

// =============================================================================
// VIES SOAP Response Fixtures
// =============================================================================

function viesSoapValid(countryCode: string, vatNumber: string, name: string, address: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <checkVatResponse xmlns="urn:ec.europa.eu:taxud:vies:services:checkVat:types">
      <countryCode>${countryCode}</countryCode>
      <vatNumber>${vatNumber}</vatNumber>
      <requestDate>2026-02-17+01:00</requestDate>
      <valid>true</valid>
      <name>${name}</name>
      <address>${address}</address>
    </checkVatResponse>
  </soap:Body>
</soap:Envelope>`;
}

function viesSoapInvalid(countryCode: string, vatNumber: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <checkVatResponse xmlns="urn:ec.europa.eu:taxud:vies:services:checkVat:types">
      <countryCode>${countryCode}</countryCode>
      <vatNumber>${vatNumber}</vatNumber>
      <requestDate>2026-02-17+01:00</requestDate>
      <valid>false</valid>
      <name>---</name>
      <address>---</address>
    </checkVatResponse>
  </soap:Body>
</soap:Envelope>`;
}

function viesSoapFault(faultCode: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:Fault>
      <faultcode>soap:Server</faultcode>
      <faultstring>${faultCode}</faultstring>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>`;
}

// =============================================================================
// HMRC JSON Fixtures
// =============================================================================

function hmrcValid(vatNumber: string, name: string): string {
  return JSON.stringify({
    target: {
      name,
      vatNumber,
      address: {
        line1: '10 Downing Street',
        line2: null,
        postcode: 'SW1A 2AA',
      },
    },
    processingDate: '2026-02-17T12:00:00+00:00',
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
    expect(result.error).toContain('Invalid request body');
  });

  it('returns 400 for empty body', async () => {
    const result = await handler(makeRequest(''));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
  });

  it('returns 400 for missing countryCode', async () => {
    const result = await handler(makeRequest(JSON.stringify({ vatNumber: '123' })));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('required');
  });

  it('returns 400 for missing vatNumber', async () => {
    const result = await handler(makeRequest(JSON.stringify({ countryCode: 'PT' })));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('required');
  });
});

describe('VIES SOAP path (non-GB)', () => {
  it('parses valid VIES response and returns BN254 output', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: viesSoapValid('PT', '507172230', 'TYTLE LDA', 'RUA DO EXEMPLO 123'),
    });

    const result = await handler(makeRequest(JSON.stringify({
      countryCode: 'PT',
      vatNumber: '507172230',
    })));

    expect(result.success).toBe(true);
    expect(result.status).toBe(200);
    expect(result.headers['x-vies-valid']).toBe('true');
    expect(result.headers['x-vies-name']).toBe('TYTLE LDA');
    expect(result.headers['x-vies-address']).toBe('RUA DO EXEMPLO 123');
    expect(result.headers['x-vies-country-code']).toBe('PT');
    expect(result.headers['x-vies-vat-number']).toBe('507172230');

    // rawBody should be base64 of 160 bytes
    const raw = Buffer.from(result.rawBody, 'base64');
    expect(raw.length).toBe(160);

    // Verify proxyFetch was called with VIES params
    expect(mockProxyFetch).toHaveBeenCalledWith(
      8443,
      'ec.europa.eu',
      'POST',
      '/taxation_customs/vies/services/checkVatService',
      expect.objectContaining({ 'Content-Type': 'text/xml;charset=UTF-8' }),
      expect.stringContaining('checkVat'),
    );
  });

  it('parses invalid VAT response', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: viesSoapInvalid('DE', '999999999'),
    });

    const result = await handler(makeRequest(JSON.stringify({
      countryCode: 'DE',
      vatNumber: '999999999',
    })));

    expect(result.success).toBe(true);
    expect(result.headers['x-vies-valid']).toBe('false');
  });

  it('handles SOAP fault (MS_UNAVAILABLE)', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: viesSoapFault('MS_UNAVAILABLE'),
    });

    const result = await handler(makeRequest(JSON.stringify({
      countryCode: 'PT',
      vatNumber: '507172230',
    })));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('VIES SOAP error');
    expect(result.error).toContain('MS_UNAVAILABLE');
  });

  it('handles SOAP fault (INVALID_INPUT)', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: viesSoapFault('INVALID_INPUT'),
    });

    const result = await handler(makeRequest(JSON.stringify({
      countryCode: 'PT',
      vatNumber: 'abc',
    })));

    expect(result.success).toBe(false);
    expect(result.error).toContain('INVALID_INPUT');
  });

  it('handles non-200 VIES HTTP status', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 500,
      headers: {},
      body: 'Internal Server Error',
    });

    const result = await handler(makeRequest(JSON.stringify({
      countryCode: 'PT',
      vatNumber: '507172230',
    })));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
  });

  it('escapes XML special characters in input', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: viesSoapInvalid('PT', '123'),
    });

    await handler(makeRequest(JSON.stringify({
      countryCode: 'P&T',
      vatNumber: '<script>',
    })));

    const soapBody = mockProxyFetch.mock.calls[0][5] as string;
    expect(soapBody).toContain('P&amp;T');
    expect(soapBody).toContain('&lt;script&gt;');
    expect(soapBody).not.toContain('<script>');
  });

  it('handles VIES response with no name/address', async () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <checkVatResponse xmlns="urn:ec.europa.eu:taxud:vies:services:checkVat:types">
      <countryCode>PT</countryCode>
      <vatNumber>507172230</vatNumber>
      <valid>true</valid>
    </checkVatResponse>
  </soap:Body>
</soap:Envelope>`;

    mockProxyFetch.mockResolvedValueOnce({ status: 200, headers: {}, body: xml });

    const result = await handler(makeRequest(JSON.stringify({
      countryCode: 'PT',
      vatNumber: '507172230',
    })));

    expect(result.success).toBe(true);
    expect(result.headers['x-vies-name']).toBe('');
    expect(result.headers['x-vies-address']).toBe('');
  });
});

describe('HMRC path (GB)', () => {
  it('routes GB to HMRC endpoint', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: hmrcValid('123456789', 'British Company Ltd'),
    });

    const result = await handler(makeRequest(JSON.stringify({
      countryCode: 'GB',
      vatNumber: '123456789',
    })));

    expect(result.success).toBe(true);
    expect(result.headers['x-vies-valid']).toBe('true');
    expect(result.headers['x-vies-name']).toBe('British Company Ltd');
    expect(result.headers['x-vies-address']).toBe('10 Downing Street, SW1A 2AA');

    expect(mockProxyFetch).toHaveBeenCalledWith(
      8444,
      'api.service.hmrc.gov.uk',
      'GET',
      '/organisations/vat/check-vat-number/lookup/123456789',
      expect.objectContaining({ 'Accept': 'application/vnd.hmrc.1.0+json' }),
    );
  });

  it('handles HMRC 404 (VAT not found)', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 404,
      headers: {},
      body: '{"code":"NOT_FOUND"}',
    });

    const result = await handler(makeRequest(JSON.stringify({
      countryCode: 'GB',
      vatNumber: '000000000',
    })));

    expect(result.success).toBe(true);
    expect(result.headers['x-vies-valid']).toBe('false');
  });

  it('throws on HMRC 500 (service error)', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 500,
      headers: {},
      body: 'Internal Server Error',
    });

    const result = await handler(makeRequest(JSON.stringify({
      countryCode: 'GB',
      vatNumber: '123456789',
    })));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('HMRC returned unexpected status 500');
  });

  it('throws on HMRC 429 (rate limited)', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 429,
      headers: {},
      body: '{"code":"TOO_MANY_REQUESTS"}',
    });

    const result = await handler(makeRequest(JSON.stringify({
      countryCode: 'GB',
      vatNumber: '123456789',
    })));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('unexpected status 429');
  });

  it('throws on HMRC invalid JSON', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: 'not json at all',
    });

    const result = await handler(makeRequest(JSON.stringify({
      countryCode: 'GB',
      vatNumber: '123456789',
    })));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('invalid JSON');
  });

  it('URL-encodes vatNumber in HMRC path', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 404,
      headers: {},
      body: '{}',
    });

    await handler(makeRequest(JSON.stringify({
      countryCode: 'GB',
      vatNumber: '12/34',
    })));

    const path = mockProxyFetch.mock.calls[0][3] as string;
    expect(path).toContain('12%2F34');
    expect(path).not.toContain('12/34');
  });
});

describe('BN254 encoding output', () => {
  it('produces exactly 160 bytes for valid VIES response', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: viesSoapValid('PT', '507172230', 'TEST', 'ADDR'),
    });

    const result = await handler(makeRequest(JSON.stringify({
      countryCode: 'PT',
      vatNumber: '507172230',
    })));

    const raw = Buffer.from(result.rawBody, 'base64');
    expect(raw.length).toBe(160);
  });

  it('produces identical bytes for identical inputs (deterministic)', async () => {
    const soapResponse = viesSoapValid('PT', '507172230', 'TEST', 'ADDR');

    mockProxyFetch.mockResolvedValue({
      status: 200,
      headers: {},
      body: soapResponse,
    });

    const r1 = await handler(makeRequest(JSON.stringify({ countryCode: 'PT', vatNumber: '507172230' })));
    const r2 = await handler(makeRequest(JSON.stringify({ countryCode: 'PT', vatNumber: '507172230' })));

    expect(r1.rawBody).toBe(r2.rawBody);
  });
});
