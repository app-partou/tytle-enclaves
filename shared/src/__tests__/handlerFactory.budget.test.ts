/**
 * The handler factory hands every handler a context bound to its request's budget (enclave audit F6; D-P1-11 "A",
 * LJ 2026-10-08): ctx.fetchWithRetry and ctx.unsealSecret take what is left of it, like ctx.fetch. No service handler
 * uses those two today, so a minimal definition drives them here.
 *
 * MOCK BOUNDARY: the vsock socket to a host proxy and the NSM device (helpers/fakeEnclaveIo.ts), KMS behind them
 * (helpers/fakeKms.ts). createHandler, the retry, the KMS call, the HTTP framing and attest() run for real.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@tytle-enclaves/native', async () => (await import('./helpers/fakeEnclaveIo.js')).nativeModule);
vi.mock('node:tls', async () => (await import('./helpers/fakeEnclaveIo.js')).tlsModule);

import { fakeIo, httpReply } from './helpers/fakeEnclaveIo.js';
import { fakeKms } from './helpers/fakeKms.js';
import { createHandler, type HandlerContext, type HandlerDef } from '../handlerFactory.js';
import type { AllowedHost, EnclaveRequest } from '../types.js';

const UPSTREAM_PORT = 8446;
const KMS_PORT = 8000;
const HOSTS: AllowedHost[] = [
  { hostname: 'api.stripe.com', vsockProxyPort: UPSTREAM_PORT },
  { hostname: 'kms.eu-central-1.amazonaws.com', vsockProxyPort: KMS_PORT },
];
const CREDENTIALS = {
  accessKeyId: 'ASIAEXAMPLEEXAMPLE01',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  sessionToken: 'IQoJb3JpZ2luX2VjEXAMPLETOKEN//////////wEaDGV1LWNlbnRyYWwtMSJHMEUCIQ==',
};

/** A definition whose execute does `step` with the context, then answers one signed value. */
function defDoing(step: (ctx: HandlerContext) => Promise<unknown>): HandlerDef<Record<string, never>> {
  return {
    name: 'budget-test',
    schema: [{ name: 'n', encoding: 'uint' }],
    manifestHash: 'b'.repeat(64),
    policies: [],
    requiredHosts: ['api.stripe.com'],
    parseParams: () => ({}),
    async execute(_params, ctx) {
      await step(ctx);
      return { values: { n: 1 }, apiEndpoint: 'api.stripe.com/v1/x', method: 'GET', url: 'https://api.stripe.com/v1/x', requestHeaders: {}, responseHeaders: {} };
    },
  };
}

const REQUEST: EnclaveRequest = { id: 'b1', url: 'https://api.stripe.com/v1/x', method: 'GET', headers: {}, body: '{}', awsCredentials: CREDENTIALS };

beforeEach(() => {
  fakeIo.reset();
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

describe('the handler context and the request budget (D-P1-11)', () => {
  it('🔴 ctx.fetchWithRetry: each try takes what is left of the budget', async () => {
    fakeIo.reply(UPSTREAM_PORT, httpReply(200, 'ok'));
    const handler = createHandler(defDoing((ctx) => ctx.fetchWithRetry(ctx.hosts[0], 'GET', '/v1/x', {})), HOSTS);

    const res = await handler(REQUEST, { deadlineMs: Date.now() + 7_000 });

    expect(res).toMatchObject({ success: true, status: 200 });
    expect(fakeIo.timeouts(UPSTREAM_PORT)).toEqual([7]);
  });

  it('🔴 ctx.unsealSecret: the KMS call takes what is left of the budget', async () => {
    const kms = fakeKms({ sealed: 'sk_test_TESTONLY_budget' });
    fakeIo.reply(KMS_PORT, kms.reply);
    const handler = createHandler(defDoing((ctx) => ctx.unsealSecret('c2VhbGVkLWJ1ZGdldC10ZXN0', 'stripe_payment')), HOSTS);

    const res = await handler(REQUEST, { deadlineMs: Date.now() + 4_000 });

    expect(res).toMatchObject({ success: true, status: 200 });
    expect(fakeIo.timeouts(KMS_PORT)).toEqual([4]);
  });
});
