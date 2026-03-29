import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'node:crypto';

// Import real codec directly (bypasses barrel re-export that pulls in native)
import {
  encodeFieldElements,
  hashFieldElements,
  MONERIUM_PAYMENT_SCHEMA,
} from '../../node_modules/@tytle-enclaves/shared/src/bn254Codec.js';
import {
  stableStringify,
  computeManifestHash,
  validateManifest,
} from '../../node_modules/@tytle-enclaves/shared/src/manifest.js';
import {
  SKIP_TRANSIENT_ERRORS,
  ATTEST_NOT_FOUND,
  STRIP_AUTH,
  REDACT_BEARER,
} from '../../node_modules/@tytle-enclaves/shared/src/policies.js';

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

// Mock @tytle-enclaves/shared — provide real codec + policies + manifest utils + mocked proxyFetch/attest
vi.mock('@tytle-enclaves/shared', () => ({
  encodeFieldElements,
  hashFieldElements,
  MONERIUM_PAYMENT_SCHEMA,
  stableStringify,
  computeManifestHash,
  validateManifest,
  SKIP_TRANSIENT_ERRORS,
  ATTEST_NOT_FOUND,
  STRIP_AUTH,
  REDACT_BEARER,
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

import { createMoneriumPaymentHandler } from '../moneriumPaymentHandler.js';
import { HANDLER_MANIFEST, MANIFEST_HASH } from '../manifest.js';

interface EnclaveRequest {
  id: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}

const handler = createMoneriumPaymentHandler({
  moneriumHostname: 'api.monerium.app',
  moneriumVsockPort: 8447,
  rpcHostname: 'rpc.gnosischain.com',
  rpcVsockPort: 8448,
});

function makeRequest(body: object | string): EnclaveRequest {
  return {
    id: 'test-req-1',
    url: 'https://api.monerium.app/orders/test-order-id',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  };
}

// =============================================================================
// Monerium API Response Fixtures
// =============================================================================

function moneriumOrder(overrides: Record<string, any> = {}): string {
  return JSON.stringify({
    id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
    profile: 'profile_xyz',
    address: '0x1234567890abcdef1234567890abcdef12345678',
    kind: 'issue',
    chain: 'gnosis',
    amount: '100.00',
    currency: 'eur',
    counterpart: { identifier: {}, details: {} },
    memo: 'Test payment',
    meta: { placedAt: '2024-01-01T00:00:00Z', processedAt: '2024-01-01T00:01:00Z' },
    state: 'processed',
    ...overrides,
  });
}

function rpcBalanceResponse(balanceHex: string = '0x56bc75e2d63100000'): string {
  return JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    result: balanceHex,
  });
}

function rpcErrorResponse(message: string = 'execution reverted'): string {
  return JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    error: { code: -32000, message },
  });
}

/** Set up both proxyFetch calls: order then balance. */
function mockBothCalls(
  orderBody: string = moneriumOrder(),
  balanceHex: string = '0x56bc75e2d63100000',
  orderStatus: number = 200,
): void {
  mockProxyFetch
    .mockResolvedValueOnce({ status: orderStatus, headers: {}, body: orderBody })
    .mockResolvedValueOnce({ status: 200, headers: {}, body: rpcBalanceResponse(balanceHex) });
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
    const result = await handler(makeRequest({ accessToken: 'test-token', orderId: 'abc' }));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('Invalid operation');
  });

  it('returns 400 for unsupported operation', async () => {
    const result = await handler(makeRequest({ operation: 'delete_order', accessToken: 'test-token', orderId: 'abc' }));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('Invalid operation');
  });

  it('returns 400 for missing accessToken', async () => {
    const result = await handler(makeRequest({ operation: 'get_order_with_balance', orderId: 'abc' }));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('accessToken is required');
  });

  it('returns 400 for missing orderId', async () => {
    const result = await handler(makeRequest({ operation: 'get_order_with_balance', accessToken: 'test-token' }));
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('orderId is required');
  });
});

describe('order fetch', () => {
  it('returns BN254 output with correct headers on success', async () => {
    mockBothCalls();

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
    }));

    expect(result.success).toBe(true);
    expect(result.status).toBe(200);
    expect(result.headers['x-monerium-order-id']).toBe('a1b2c3d4-e5f6-7890-abcd-ef1234567890');
    expect(result.headers['x-monerium-state']).toBe('processed');
    expect(result.headers['x-monerium-order-amount']).toBe('100.00');
    expect(result.headers['x-monerium-currency']).toBe('eur');
    expect(result.headers['x-monerium-balance']).toBe('100000000000000000000');

    // rawBody should be base64 of 192 bytes (6 fields x 32)
    const raw = Buffer.from(result.rawBody, 'base64');
    expect(raw.length).toBe(192);
  });

  it('URL-encodes orderId in the path', async () => {
    mockBothCalls();

    await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'order/with%special',
    }));

    const path = mockProxyFetch.mock.calls[0][3] as string;
    expect(path).toContain('order%2Fwith%25special');
  });

  it('passes correct headers to Monerium API', async () => {
    mockBothCalls();

    await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'my-secret-token',
      orderId: 'test-id',
    }));

    const headers = mockProxyFetch.mock.calls[0][4] as Record<string, string>;
    expect(headers['Authorization']).toBe('Bearer my-secret-token');
    expect(headers['Accept']).toBe('application/vnd.monerium.api-v2+json');
  });
});

describe('chain validation', () => {
  it('returns 400 for non-gnosis chain', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: moneriumOrder({ chain: 'ethereum' }),
    });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toContain('Only gnosis chain is supported');
    // Should NOT make the RPC call
    expect(mockProxyFetch).toHaveBeenCalledTimes(1);
  });
});

describe('address validation', () => {
  it('returns 502 for invalid address format', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: moneriumOrder({ address: 'not-an-address' }),
    });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('Invalid address');
  });

  it('returns 502 for missing address', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: moneriumOrder({ address: undefined }),
    });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('Invalid address');
  });
});

describe('RPC balance call', () => {
  it('sends correct balanceOf eth_call to Gnosis RPC', async () => {
    mockBothCalls();

    await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    // Second call should be to RPC
    expect(mockProxyFetch).toHaveBeenCalledTimes(2);
    const rpcCall = mockProxyFetch.mock.calls[1];
    expect(rpcCall[0]).toBe(8448); // RPC vsock port
    expect(rpcCall[1]).toBe('rpc.gnosischain.com');
    expect(rpcCall[2]).toBe('POST');
    expect(rpcCall[3]).toBe('/');

    // Verify RPC body
    const rpcBody = JSON.parse(rpcCall[5]);
    expect(rpcBody.jsonrpc).toBe('2.0');
    expect(rpcBody.method).toBe('eth_call');
    expect(rpcBody.params[0].to).toBe('0xcB444e90D8198415266c6a2724b7900fb12FC56E');
    expect(rpcBody.params[0].data).toContain('0x70a08231');
    // Address from fixture: 0x1234567890abcdef1234567890abcdef12345678
    expect(rpcBody.params[0].data).toContain('1234567890abcdef1234567890abcdef12345678');
    expect(rpcBody.params[1]).toBe('latest');
  });

  it('handles zero balance', async () => {
    mockBothCalls(moneriumOrder(), '0x0000000000000000000000000000000000000000000000000000000000000000');

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(true);
    expect(result.headers['x-monerium-balance']).toBe('0');
  });

  it('returns 502 for RPC HTTP error', async () => {
    mockProxyFetch
      .mockResolvedValueOnce({ status: 200, headers: {}, body: moneriumOrder() })
      .mockResolvedValueOnce({ status: 503, headers: {}, body: 'Service Unavailable' });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('Gnosis RPC returned HTTP 503');
  });

  it('returns 502 for JSON-RPC error', async () => {
    mockProxyFetch
      .mockResolvedValueOnce({ status: 200, headers: {}, body: moneriumOrder() })
      .mockResolvedValueOnce({ status: 200, headers: {}, body: rpcErrorResponse('execution reverted') });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('Gnosis RPC error');
  });

  it('returns 502 for empty balanceOf result', async () => {
    mockProxyFetch
      .mockResolvedValueOnce({ status: 200, headers: {}, body: moneriumOrder() })
      .mockResolvedValueOnce({ status: 200, headers: {}, body: JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x' }) });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('balanceOf returned empty result');
  });

  it('returns 502 for invalid RPC JSON', async () => {
    mockProxyFetch
      .mockResolvedValueOnce({ status: 200, headers: {}, body: moneriumOrder() })
      .mockResolvedValueOnce({ status: 200, headers: {}, body: 'not json' });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('Gnosis RPC returned invalid JSON');
  });

  it('returns 502 for invalid hex in RPC result', async () => {
    mockProxyFetch
      .mockResolvedValueOnce({ status: 200, headers: {}, body: moneriumOrder() })
      .mockResolvedValueOnce({ status: 200, headers: {}, body: JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0xnotvalidhex' }) });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
  });

  it('normalizes checksummed addresses to lowercase in balanceOf call', async () => {
    const checksummedOrder = moneriumOrder({ address: '0x1234567890AbCdEf1234567890aBcDeF12345678' });
    mockProxyFetch
      .mockResolvedValueOnce({ status: 200, headers: {}, body: checksummedOrder })
      .mockResolvedValueOnce({ status: 200, headers: {}, body: rpcBalanceResponse() });

    await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    const rpcBody = JSON.parse(mockProxyFetch.mock.calls[1][5]);
    // Address in call data should be lowercase
    expect(rpcBody.params[0].data).toContain('1234567890abcdef1234567890abcdef12345678');
    expect(rpcBody.params[0].data).not.toContain('AbCdEf');
  });
});

describe('error handling', () => {
  it('returns transient error without attestation for HTTP 429', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 429,
      headers: { 'retry-after': '2' },
      body: '{"error":"rate_limit"}',
    });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
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
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(true);
    expect(result.status).toBe(500);
    expect(result.attestation).toBeUndefined();
  });

  it('returns transient error without attestation for HTTP 401', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 401,
      headers: {},
      body: '{"error":"unauthorized"}',
    });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'bad-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(true);
    expect(result.status).toBe(401);
    expect(result.attestation).toBeUndefined();
  });

  it('returns 502 for invalid JSON from Monerium', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: 'not json',
    });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('invalid JSON');
  });

  it('returns 502 for missing id in order response', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: JSON.stringify({ state: 'processed', chain: 'gnosis' }),
    });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('missing "id" field');
  });

  it('returns 502 for missing state in order response', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: JSON.stringify({ id: 'order-1', chain: 'gnosis', amount: '100', currency: 'eur', address: '0x1234567890abcdef1234567890abcdef12345678' }),
    });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('missing "state" field');
  });

  it('returns 502 for missing amount in order response', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: JSON.stringify({ id: 'order-1', state: 'processed', chain: 'gnosis', currency: 'eur', address: '0x1234567890abcdef1234567890abcdef12345678' }),
    });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('missing "amount" field');
  });

  it('returns 502 for missing currency in order response', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 200,
      headers: {},
      body: JSON.stringify({ id: 'order-1', state: 'processed', chain: 'gnosis', amount: '100', address: '0x1234567890abcdef1234567890abcdef12345678' }),
    });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.status).toBe(502);
    expect(result.error).toContain('missing "currency" field');
  });
});

describe('404 attestation', () => {
  it('attests 404 responses (order not found is definitive)', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 404,
      headers: {},
      body: JSON.stringify({ error: 'not_found' }),
    });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'nonexistent-order',
    }));

    expect(result.status).toBe(404);
    expect(mockAttest).toHaveBeenCalled();
    expect(result.headers['x-monerium-state']).toBe('not_found');
    // Should NOT make the RPC call
    expect(mockProxyFetch).toHaveBeenCalledTimes(1);
  });
});

describe('security: accessToken handling', () => {
  it('strips Authorization header before attestation', async () => {
    mockBothCalls();

    await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'SECRET_TOKEN',
      orderId: 'test-id',
    }));

    // attest() should be called without Authorization header
    const attestCall = mockAttest.mock.calls[0];
    const attestHeaders = attestCall[4] as Record<string, string>;
    expect(attestHeaders).not.toHaveProperty('Authorization');
    expect(attestHeaders).toHaveProperty('Accept');
  });

  it('redacts Bearer token in error messages', async () => {
    mockProxyFetch.mockRejectedValueOnce(
      new Error('TLS error: Bearer SUPERSECRETTOKEN connection reset'),
    );

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'SUPERSECRETTOKEN',
      orderId: 'test-id',
    }));

    expect(result.success).toBe(false);
    expect(result.error).not.toContain('SUPERSECRETTOKEN');
    expect(result.error).toContain('Bearer [REDACTED]');
  });

  it('handles errors with no Bearer token (no false redaction)', async () => {
    mockProxyFetch.mockRejectedValueOnce(
      new Error('Connection timeout after 25000ms'),
    );

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.error).toBe('Connection timeout after 25000ms');
  });
});

describe('BN254 encoding + attestation chain', () => {
  it('produces exactly 192 bytes (6 fields x 32)', async () => {
    mockBothCalls();

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    const raw = Buffer.from(result.rawBody, 'base64');
    expect(raw.length).toBe(192);
  });

  it('passes bn254Hash as 6th argument to attest()', async () => {
    mockBothCalls();

    await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(mockAttest).toHaveBeenCalledTimes(1);
    const attestArgs = mockAttest.mock.calls[0];
    // 6th argument should be the BN254 hash (hex string, 64 chars)
    expect(attestArgs[5]).toMatch(/^[0-9a-f]{64}$/);
  });

  it('returns bn254 and bn254Headers in response', async () => {
    mockBothCalls();

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.bn254).toBe(result.rawBody);
    expect(result.bn254Headers).toBeDefined();
    expect(result.bn254Headers!['x-monerium-data-hash']).toBeDefined();
  });

  it('includes bn254Hash in attestation object', async () => {
    mockBothCalls();

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.attestation).toBeDefined();
    expect((result.attestation as any).bn254Hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('bn254Hash matches SHA-256 of encoded field elements', async () => {
    const orderBody = moneriumOrder();
    const balanceBody = rpcBalanceResponse('0x56bc75e2d63100000');
    mockProxyFetch
      .mockResolvedValueOnce({ status: 200, headers: {}, body: orderBody })
      .mockResolvedValueOnce({ status: 200, headers: {}, body: balanceBody });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    // Reproduce the encoding independently
    const combinedBody = orderBody + '\n' + balanceBody;
    const dataHash = crypto.createHash('sha256').update(combinedBody, 'utf8').digest('hex');
    const order = JSON.parse(orderBody);
    const balance = BigInt('0x56bc75e2d63100000');

    const expectedEncoded = encodeFieldElements(MONERIUM_PAYMENT_SCHEMA, {
      orderId: order.id,
      state: order.state,
      orderAmount: order.amount,
      currency: order.currency,
      balance,
      dataHash,
    });
    const expectedHash = hashFieldElements(expectedEncoded);

    const attestArgs = mockAttest.mock.calls[0];
    expect(attestArgs[5]).toBe(expectedHash);
  });

  it('deterministic output for identical inputs', async () => {
    const orderBody = moneriumOrder();
    const balanceBody = rpcBalanceResponse();

    mockProxyFetch
      .mockResolvedValueOnce({ status: 200, headers: {}, body: orderBody })
      .mockResolvedValueOnce({ status: 200, headers: {}, body: balanceBody })
      .mockResolvedValueOnce({ status: 200, headers: {}, body: orderBody })
      .mockResolvedValueOnce({ status: 200, headers: {}, body: balanceBody });

    const req = makeRequest({ operation: 'get_order_with_balance', accessToken: 'test-token', orderId: 'test-id' });
    const r1 = await handler(req);
    const r2 = await handler(req);

    expect(r1.rawBody).toBe(r2.rawBody);
  });
});

describe('combined data hash', () => {
  it('data hash covers both order and RPC responses', async () => {
    const orderBody = moneriumOrder();
    const balanceBody = rpcBalanceResponse();
    mockProxyFetch
      .mockResolvedValueOnce({ status: 200, headers: {}, body: orderBody })
      .mockResolvedValueOnce({ status: 200, headers: {}, body: balanceBody });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    const expectedHash = crypto.createHash('sha256')
      .update(orderBody + '\n' + balanceBody, 'utf8')
      .digest('hex');

    expect(result.headers['x-monerium-data-hash']).toBe(expectedHash);
  });
});

describe('order state encoding', () => {
  it('encodes different state values correctly', async () => {
    for (const state of ['placed', 'pending', 'processed', 'rejected']) {
      mockProxyFetch.mockReset();
      mockBothCalls(moneriumOrder({ state }));

      const result = await handler(makeRequest({
        operation: 'get_order_with_balance',
        accessToken: 'test-token',
        orderId: 'test-id',
      }));

      expect(result.success).toBe(true);
      expect(result.headers['x-monerium-state']).toBe(state);
    }
  });

  it('encodes different currency values correctly', async () => {
    for (const currency of ['eur', 'usd', 'gbp', 'isk']) {
      mockProxyFetch.mockReset();
      mockBothCalls(moneriumOrder({ currency }));

      const result = await handler(makeRequest({
        operation: 'get_order_with_balance',
        accessToken: 'test-token',
        orderId: 'test-id',
      }));

      expect(result.success).toBe(true);
      expect(result.headers['x-monerium-currency']).toBe(currency);
    }
  });
});

describe('handler manifest', () => {
  it('manifest hash is present in success response headers', async () => {
    mockBothCalls();

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.headers['x-monerium-manifest-hash']).toBe(MANIFEST_HASH);
    expect(result.headers['x-monerium-manifest-hash']).toMatch(/^[0-9a-f]{64}$/);
  });

  it('manifest hash is present in 404 response headers', async () => {
    mockProxyFetch.mockResolvedValueOnce({
      status: 404,
      headers: {},
      body: JSON.stringify({ error: 'not_found' }),
    });

    const result = await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    expect(result.headers['x-monerium-manifest-hash']).toBe(MANIFEST_HASH);
  });

  it('manifest hash is included in attestation request headers', async () => {
    mockBothCalls();

    await handler(makeRequest({
      operation: 'get_order_with_balance',
      accessToken: 'test-token',
      orderId: 'test-id',
    }));

    const attestCall = mockAttest.mock.calls[0];
    const attestHeaders = attestCall[4] as Record<string, string>;
    expect(attestHeaders['x-manifest-hash']).toBe(MANIFEST_HASH);
  });

  it('manifest hash is stable (deterministic)', () => {
    const hash1 = MANIFEST_HASH;
    const recomputed = crypto.createHash('sha256')
      .update(stableStringify(HANDLER_MANIFEST))
      .digest('hex');
    expect(hash1).toBe(recomputed);
  });

  it('manifest schema fields match actual MONERIUM_PAYMENT_SCHEMA', () => {
    expect(HANDLER_MANIFEST.schema.fields.length).toBe(MONERIUM_PAYMENT_SCHEMA.length);
    for (let i = 0; i < MONERIUM_PAYMENT_SCHEMA.length; i++) {
      expect(HANDLER_MANIFEST.schema.fields[i].name).toBe(MONERIUM_PAYMENT_SCHEMA[i].name);
      expect(HANDLER_MANIFEST.schema.fields[i].encoding).toBe(MONERIUM_PAYMENT_SCHEMA[i].encoding);
    }
  });

  it('manifest query hosts match enclave allowlist', () => {
    const hosts = HANDLER_MANIFEST.queries.map(q => q.host);
    expect(hosts).toContain('api.monerium.app');
    expect(hosts).toContain('rpc.gnosischain.com');
  });

  it('manifest version is semver', () => {
    expect(HANDLER_MANIFEST.version).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
