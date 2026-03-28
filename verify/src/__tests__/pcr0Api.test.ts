import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fetchPcr0Info } from '../lib/pcr0Api.js';

describe('fetchPcr0Info', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('parses a valid API response', async () => {
    const mockResponse = {
      enclaves: {
        vies: {
          pcr0: 'abc123',
          gitCommit: 'def456',
          repoUrl: 'https://github.com/app-partou/tytle-enclaves',
          buildDir: 'vies',
          history: [],
        },
      },
      verificationGuide: 'https://example.com/VERIFICATION.md',
    };

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(mockResponse), { status: 200 }),
    );

    const result = await fetchPcr0Info('vies');
    expect(result.pcr0).toBe('abc123');
    expect(result.gitCommit).toBe('def456');
  });

  it('maps stripe-payment to stripe_payment key', async () => {
    const mockResponse = {
      enclaves: {
        stripe_payment: {
          pcr0: 'stripe-pcr0',
          gitCommit: 'stripe-commit',
          repoUrl: 'https://github.com/app-partou/tytle-enclaves',
          buildDir: 'stripe-payment',
          history: [],
        },
      },
      verificationGuide: 'https://example.com',
    };

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(mockResponse), { status: 200 }),
    );

    const result = await fetchPcr0Info('stripe-payment');
    expect(result.pcr0).toBe('stripe-pcr0');
  });

  it('throws on non-200 response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response('Internal Server Error', { status: 500 }),
    );

    await expect(fetchPcr0Info('vies')).rejects.toThrow('PCR0 API returned 500');
  });

  it('throws when service not found in response', async () => {
    const mockResponse = {
      enclaves: {
        vies: {
          pcr0: 'abc',
          gitCommit: 'def',
          repoUrl: 'url',
          buildDir: 'vies',
          history: [],
        },
      },
      verificationGuide: '',
    };

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(mockResponse), { status: 200 }),
    );

    await expect(fetchPcr0Info('sicae')).rejects.toThrow('not found in API response');
  });

  it('uses custom API URL when provided', async () => {
    const mockResponse = {
      enclaves: {
        vies: {
          pcr0: 'abc',
          gitCommit: 'def',
          repoUrl: 'url',
          buildDir: 'vies',
          history: [],
        },
      },
      verificationGuide: '',
    };

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify(mockResponse), { status: 200 }),
    );

    await fetchPcr0Info('vies', 'https://api.staging.tytle.io');
    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.staging.tytle.io/api/enclave/pcr0',
      expect.objectContaining({
        headers: { Accept: 'application/json' },
      }),
    );
  });
});
