import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockProxyFetch = vi.fn();
const mockProxyFetchPlain = vi.fn();

vi.mock('../httpProxy.js', () => ({
  proxyFetch: (...args: unknown[]) => mockProxyFetch(...args),
  proxyFetchPlain: (...args: unknown[]) => mockProxyFetchPlain(...args),
}));

import { proxyFetchWithRetry } from '../retryProxy.js';

function makeResponse(status: number, body = '') {
  return { status, headers: {}, body };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('proxyFetchWithRetry', () => {
  it('returns successful response without retrying', async () => {
    mockProxyFetch.mockResolvedValueOnce(makeResponse(200, 'ok'));

    const result = await proxyFetchWithRetry(8443, 'example.com', 'GET', '/', {});
    expect(result.status).toBe(200);
    expect(mockProxyFetch).toHaveBeenCalledTimes(1);
  });

  it('retries on 5xx and returns successful retry', async () => {
    mockProxyFetch
      .mockResolvedValueOnce(makeResponse(502))
      .mockResolvedValueOnce(makeResponse(200, 'recovered'));

    const result = await proxyFetchWithRetry(
      8443, 'example.com', 'GET', '/', {},
      undefined, undefined, true,
      { maxRetries: 1, baseDelayMs: 1 },
    );
    expect(result.status).toBe(200);
    expect(mockProxyFetch).toHaveBeenCalledTimes(2);
  });

  it('returns last 5xx response when all retries exhausted', async () => {
    mockProxyFetch
      .mockResolvedValueOnce(makeResponse(503))
      .mockResolvedValueOnce(makeResponse(502));

    const result = await proxyFetchWithRetry(
      8443, 'example.com', 'GET', '/', {},
      undefined, undefined, true,
      { maxRetries: 1, baseDelayMs: 1 },
    );
    expect(result.status).toBe(502);
    expect(mockProxyFetch).toHaveBeenCalledTimes(2);
  });

  it('does not retry on 4xx', async () => {
    mockProxyFetch.mockResolvedValueOnce(makeResponse(400));

    const result = await proxyFetchWithRetry(
      8443, 'example.com', 'GET', '/', {},
      undefined, undefined, true,
      { maxRetries: 2, baseDelayMs: 1 },
    );
    expect(result.status).toBe(400);
    expect(mockProxyFetch).toHaveBeenCalledTimes(1);
  });

  it('does not retry on 404', async () => {
    mockProxyFetch.mockResolvedValueOnce(makeResponse(404));

    const result = await proxyFetchWithRetry(
      8443, 'example.com', 'GET', '/', {},
      undefined, undefined, true,
      { maxRetries: 2, baseDelayMs: 1 },
    );
    expect(result.status).toBe(404);
    expect(mockProxyFetch).toHaveBeenCalledTimes(1);
  });

  it('retries on network error and returns on success', async () => {
    mockProxyFetch
      .mockRejectedValueOnce(new Error('ECONNRESET'))
      .mockResolvedValueOnce(makeResponse(200));

    const result = await proxyFetchWithRetry(
      8443, 'example.com', 'GET', '/', {},
      undefined, undefined, true,
      { maxRetries: 1, baseDelayMs: 1 },
    );
    expect(result.status).toBe(200);
    expect(mockProxyFetch).toHaveBeenCalledTimes(2);
  });

  it('throws network error when all retries exhausted and no prior response', async () => {
    mockProxyFetch
      .mockRejectedValueOnce(new Error('ECONNRESET'))
      .mockRejectedValueOnce(new Error('ECONNREFUSED'));

    await expect(
      proxyFetchWithRetry(
        8443, 'example.com', 'GET', '/', {},
        undefined, undefined, true,
        { maxRetries: 1, baseDelayMs: 1 },
      ),
    ).rejects.toThrow('ECONNREFUSED');
    expect(mockProxyFetch).toHaveBeenCalledTimes(2);
  });

  it('returns prior 5xx response when last attempt throws (not discard)', async () => {
    mockProxyFetch
      .mockResolvedValueOnce(makeResponse(503, 'service unavailable'))
      .mockRejectedValueOnce(new Error('ECONNRESET'));

    const result = await proxyFetchWithRetry(
      8443, 'example.com', 'GET', '/', {},
      undefined, undefined, true,
      { maxRetries: 1, baseDelayMs: 1 },
    );
    expect(result.status).toBe(503);
    expect(result.body).toBe('service unavailable');
    expect(mockProxyFetch).toHaveBeenCalledTimes(2);
  });

  it('uses proxyFetchPlain when tls=false', async () => {
    mockProxyFetchPlain.mockResolvedValueOnce(makeResponse(200));

    await proxyFetchWithRetry(8445, 'www.sicae.pt', 'GET', '/', {}, undefined, undefined, false);
    expect(mockProxyFetchPlain).toHaveBeenCalledTimes(1);
    expect(mockProxyFetch).not.toHaveBeenCalled();
  });

  it('respects custom retryOnStatus predicate', async () => {
    mockProxyFetch
      .mockResolvedValueOnce(makeResponse(429))
      .mockResolvedValueOnce(makeResponse(200));

    const result = await proxyFetchWithRetry(
      8443, 'example.com', 'GET', '/', {},
      undefined, undefined, true,
      { maxRetries: 1, baseDelayMs: 1, retryOnStatus: (s) => s === 429 || s >= 500 },
    );
    expect(result.status).toBe(200);
    expect(mockProxyFetch).toHaveBeenCalledTimes(2);
  });

  it('handles zero maxRetries (no retry)', async () => {
    mockProxyFetch.mockResolvedValueOnce(makeResponse(500));

    const result = await proxyFetchWithRetry(
      8443, 'example.com', 'GET', '/', {},
      undefined, undefined, true,
      { maxRetries: 0, baseDelayMs: 1 },
    );
    expect(result.status).toBe(500);
    expect(mockProxyFetch).toHaveBeenCalledTimes(1);
  });
});
