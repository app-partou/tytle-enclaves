import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'node:crypto';

// Import real codec directly (bypasses barrel re-export that pulls in native)
import {
  encodeFieldElements,
  hashFieldElements,
  STRIPE_PAYMENT_SCHEMA,
} from '../../node_modules/@tytle-enclaves/shared/src/bn254Codec.js';

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
  hashFieldElements,
  STRIPE_PAYMENT_SCHEMA,
  proxyFetch: mockProxyFetch,
  attest: mockAttest,
  errorResponse: (status: number, error: string, headers: Record<string, string> = {}) =>
    ({ success: false, status, headers, rawBody: '', error }),
  encodeBn254AndAttest: async (
    schema: any, values: any, args: { apiEndpoint: string; method: string; url: string; requestHeaders: Record<string, string> },
  ) => {
    const encodedBytes = encodeFieldElements(schema, values);
    const rawBody = encodedBytes.toString('base64');
    const bn254Hash = hashFieldElements(encodedBytes);
    const attestation = await mockAttest(args.apiEndpoint, args.method, rawBody, args.url, args.requestHeaders, bn254Hash);
    return { rawBody, bn254Hash, attestation: { ...attestation, bn254Hash } };
  },
}));

import { createStripePaymentHandler } from '../stripePaymentHandler.js';

interface EnclaveRequest {
  id: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}

const handler = createStripePaymentHandler({
  hostname: 'api.stripe.com',
  vsockPort: 8446,
});

function makeRequest(body: object | string): EnclaveRequest {
  return {
    id: 'test-req-1',
    url: 'https://api.stripe.com/v1/charges',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  };
}

// =============================================================================
// Stripe API Response Fixtures
// =============================================================================

function stripeListCharges(count: number, hasMore = false): string {
  const charges = Array.from({ length: count }, (_, i) => ({
    id: `ch_${i}`,
    object: 'charge',
    amount: 1000 + i,
    currency: 'eur',
    status: 'succeeded',
  }));
  return JSON.stringify({
    object: 'list',
    data: charges,
    has_more: hasMore,
    url: '/v1/charges',
  });
}

function stripeSingleCharge(): string {
  return JSON.stringify({
    id: 'ch_abc123',
    object: 'charge',
    amount: 5000,
    currency: 'eur',
    status: 'succeeded',
  });
}

function stripeAccount(): string {
  return JSON.stringify({
    id: 'acct_123',
    object: 'account',
    business_type: 'company',
    country: 'PT',
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

  it('returns 400 for missing operation', async () => {
    const result = await handler(makeRequest({ apiKey: 'sk_test_123' }));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('Invalid operation');
  });

  it('returns 400 for unsupported operation', async () => {
    const result = await handler(makeRequest({ operation: 'delete_all', apiKey: 'sk_test_123' }));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('Invalid operation');
  });

  it('returns 400 for missing apiKey', async () => {
    const result = await handler(makeRequest({ operation: 'list_charges' }));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('apiKey is required');
  });

  it('returns 400 for get_charge without resourceId', async () => {
    const result = await handler(makeRequest({
      operation: 'get_charge',
      apiKey: 'sk_test_123',
    }));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('get_charge requires resourceId');
  });

  it('returns 400 for get_payment_intent without resourceId', async () => {
    const result = await handler(makeRequest({
      operation: 'get_payment_intent',
      apiKey: 'sk_test_123',
    }));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('get_payment_intent requires resourceId');
  });

  it('returns 400 for get_account without resourceId', async () => {
    const result = await handler(makeRequest({
      operation: 'get_account',
      apiKey: 'sk_test_123',
    }));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('get_account requires resourceId');
  });
});

describe('list operations', () => {
  it('list_charges returns BN254 output with correct headers', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: stripeListCharges(3, true),
    });

    const result = await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
      stripeAccount: 'acct_xyz',
    }));

    expect(result.success).toBe(true);
    expect(result.status).toBe(200);
    expect(result.headers['x-stripe-operation']).toBe('list_charges');
    expect(result.headers['x-stripe-account-id']).toBe('acct_xyz');
    expect(result.headers['x-stripe-object-type']).toBe('list');
    expect(result.headers['x-stripe-total-count']).toBe('3');
    expect(result.headers['x-stripe-has-more']).toBe('1');

    // rawBody should be base64 of 192 bytes (6 fields x 32)
    const raw = Buffer.from(result.rawBody, 'base64');
    expect(raw.length).toBe(192);
  });

  it('list_charges with has_more=false returns 0', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: stripeListCharges(2, false),
    });

    const result = await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
    }));

    expect(result.headers['x-stripe-has-more']).toBe('0');
    expect(result.headers['x-stripe-total-count']).toBe('2');
  });

  it('passes query params to Stripe API path', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: stripeListCharges(1),
    });

    await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
      queryParams: { limit: '10', 'created[gte]': '1700000000' },
    }));

    const path = mockProxyFetch.mock.calls[0][3] as string;
    expect(path).toContain('/v1/charges?');
    expect(path).toContain('limit=10');
    expect(path).toContain('created');
  });
});

describe('single-resource operations', () => {
  it('get_charge appends resourceId to path', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: stripeSingleCharge(),
    });

    const result = await handler(makeRequest({
      operation: 'get_charge',
      apiKey: 'sk_test_123',
      resourceId: 'ch_abc123',
    }));

    expect(result.success).toBe(true);
    expect(result.headers['x-stripe-object-type']).toBe('charge');

    const path = mockProxyFetch.mock.calls[0][3] as string;
    expect(path).toBe('/v1/charges/ch_abc123');
  });

  it('get_account appends resourceId to path', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: stripeAccount(),
    });

    await handler(makeRequest({
      operation: 'get_account',
      apiKey: 'sk_test_123',
      resourceId: 'acct_123',
    }));

    const path = mockProxyFetch.mock.calls[0][3] as string;
    expect(path).toBe('/v1/accounts/acct_123');
  });

  it('URL-encodes resourceId', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: stripeSingleCharge(),
    });

    await handler(makeRequest({
      operation: 'get_charge',
      apiKey: 'sk_test_123',
      resourceId: 'ch_a/b%c',
    }));

    const path = mockProxyFetch.mock.calls[0][3] as string;
    expect(path).toContain('ch_a%2Fb%25c');
  });
});

describe('error handling', () => {
  it('returns transient error without attestation for HTTP 429', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 429,
      headers: { 'retry-after': '2' },
      body: '{"error":{"type":"rate_limit"}}',
    });

    const result = await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
    }));

    expect(result.success).toBe(true);
    expect(result.status).toBe(429);
    expect(result.attestation).toBeUndefined();
    expect(mockAttest).not.toHaveBeenCalled();
  });

  it('returns transient error without attestation for HTTP 500', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 500,
      headers: {},
      body: 'Internal Server Error',
    });

    const result = await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
    }));

    expect(result.success).toBe(true);
    expect(result.status).toBe(500);
    expect(result.attestation).toBeUndefined();
  });

  it('returns transient error without attestation for HTTP 401', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 401,
      headers: {},
      body: '{"error":{"type":"authentication_error"}}',
    });

    const result = await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_bad',
    }));

    expect(result.success).toBe(true);
    expect(result.status).toBe(401);
    expect(result.attestation).toBeUndefined();
  });

  it('throws on invalid JSON from Stripe', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: 'not json',
    });

    const result = await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('invalid JSON');
  });

  it('throws on unexpected object type', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: JSON.stringify({ object: 'refund', id: 're_123' }),
    });

    const result = await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('Unexpected Stripe object type');
  });
});

describe('404 attestation', () => {
  it('attests 404 responses (entity not found is definitive)', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 404,
      headers: {},
      body: JSON.stringify({ object: 'charge', error: { type: 'invalid_request_error' } }),
    });

    const result = await handler(makeRequest({
      operation: 'get_charge',
      apiKey: 'sk_test_123',
      resourceId: 'ch_nonexistent',
    }));

    // 404 should be attested, not returned as a transient error
    expect(mockAttest).toHaveBeenCalled();
  });
});

describe('security: API key handling', () => {
  it('strips Authorization header before attestation', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: stripeListCharges(1),
    });

    await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_SECRET_KEY',
    }));

    // attest() should be called without Authorization header
    const attestCall = mockAttest.mock.calls[0];
    const attestHeaders = attestCall[4] as Record<string, string>;
    expect(attestHeaders).not.toHaveProperty('Authorization');
    expect(attestHeaders).toHaveProperty('Content-Type');
    expect(attestHeaders).toHaveProperty('Stripe-Version');
  });

  it('redacts Bearer token in error messages', async () => {
    mockProxyFetch.mockRejectedValueOnce(
      new Error('TLS error: Bearer sk_live_SUPERSECRET connection reset'),
    );

    const result = await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_live_SUPERSECRET',
    }));

    expect(result.success).toBe(false);
    expect(result.error).not.toContain('sk_live_SUPERSECRET');
    expect(result.error).toContain('Bearer [REDACTED]');
  });

  it('handles errors with no Bearer token (no false redaction)', async () => {
    mockProxyFetch.mockRejectedValueOnce(
      new Error('Connection timeout after 25000ms'),
    );

    const result = await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
    }));

    expect(result.error).toBe('Connection timeout after 25000ms');
  });
});

describe('BN254 encoding + attestation chain', () => {
  it('produces exactly 192 bytes (6 fields x 32)', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: stripeListCharges(5, true),
    });

    const result = await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
    }));

    const raw = Buffer.from(result.rawBody, 'base64');
    expect(raw.length).toBe(192);
  });

  it('passes bn254Hash as 6th argument to attest()', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: stripeListCharges(1),
    });

    await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
    }));

    expect(mockAttest).toHaveBeenCalledTimes(1);
    const attestArgs = mockAttest.mock.calls[0];
    // 6th argument should be the BN254 hash (hex string, 64 chars)
    expect(attestArgs[5]).toMatch(/^[0-9a-f]{64}$/);
  });

  it('returns bn254 and bn254Headers in response', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: stripeListCharges(1),
    });

    const result = await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
    }));

    expect(result.bn254).toBe(result.rawBody);
    expect(result.bn254Headers).toBeDefined();
    expect(result.bn254Headers!['x-stripe-data-hash']).toBeDefined();
  });

  it('includes bn254Hash in attestation object', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: stripeListCharges(1),
    });

    const result = await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
    }));

    expect(result.attestation).toBeDefined();
    expect((result.attestation as any).bn254Hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('bn254Hash matches SHA-256 of encoded field elements', async () => {
    const responseBody = stripeListCharges(2, true);
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: responseBody,
    });

    const result = await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
      stripeAccount: 'acct_test',
    }));

    // Reproduce the encoding independently
    const dataHash = crypto.createHash('sha256').update(responseBody, 'utf8').digest('hex');
    const expectedEncoded = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
      operation: 'list_charges',
      accountId: 'acct_test',
      objectType: 'list',
      dataHash,
      totalCount: 2,
      hasMore: 1,
    });
    const expectedHash = hashFieldElements(expectedEncoded);

    const attestArgs = mockAttest.mock.calls[0];
    expect(attestArgs[5]).toBe(expectedHash);
  });

  it('deterministic output for identical inputs', async () => {
    const body = stripeListCharges(1);
    mockProxyFetch.mockResolvedValue({ status: 200, headers: {}, body });

    const r1 = await handler(makeRequest({ operation: 'list_charges', apiKey: 'sk_test_123' }));
    const r2 = await handler(makeRequest({ operation: 'list_charges', apiKey: 'sk_test_123' }));

    expect(r1.rawBody).toBe(r2.rawBody);
  });
});

describe('Stripe-Account header', () => {
  it('includes Stripe-Account header when stripeAccount provided', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: stripeListCharges(1),
    });

    await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
      stripeAccount: 'acct_connected',
    }));

    const headers = mockProxyFetch.mock.calls[0][4] as Record<string, string>;
    expect(headers['Stripe-Account']).toBe('acct_connected');
  });

  it('omits Stripe-Account header when not provided', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: stripeListCharges(1),
    });

    await handler(makeRequest({
      operation: 'list_charges',
      apiKey: 'sk_test_123',
    }));

    const headers = mockProxyFetch.mock.calls[0][4] as Record<string, string>;
    expect(headers).not.toHaveProperty('Stripe-Account');
  });
});
