/**
 * server.ts, the parent's composition root (enclave audit P1.7): it gives createApp the parent token from
 * ENCLAVE_PARENT_AUTH_TOKEN and a reader of the REAL instance metadata service. createApp and createHostCredentials are
 * replaced here only to see what server.ts hands them; each has its own tests (server.contract.test.ts,
 * hostCredentials.test.ts).
 *
 * Labels: "red" = fails on the release before this one.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const seen = vi.hoisted(() => ({
  appOptions: [] as unknown[],
  credentialOptions: [] as unknown[],
  listen: null as unknown as ReturnType<typeof vi.fn>,
}));
vi.mock('../app.js', () => ({
  createApp: (options: unknown) => {
    seen.appOptions.push(options);
    return { listen: seen.listen };
  },
}));
vi.mock('../hostCredentials.js', () => ({
  createHostCredentials: (...args: unknown[]) => {
    seen.credentialOptions.push(args);
    return { get: async () => null, reader: 'imds' };
  },
}));

let logs: string[];

beforeEach(() => {
  seen.appOptions.length = 0;
  seen.credentialOptions.length = 0;
  seen.listen = vi.fn();
  logs = [];
  vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { logs.push(args.map(String).join(' ')); });
  vi.stubEnv('PORT', '5001');
  vi.resetModules();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

/** Load server.ts as systemd starts it, then run its listen callback. */
async function start(): Promise<void> {
  await import('../server.js');
  expect(seen.listen).toHaveBeenCalledWith(5001, '0.0.0.0', expect.any(Function));
  (seen.listen.mock.calls[0][2] as () => void)();
}

describe('server.ts (red)', () => {
  it('gives the app ENCLAVE_PARENT_AUTH_TOKEN and a reader of the real IMDS', async () => {
    vi.stubEnv('ENCLAVE_PARENT_AUTH_TOKEN', 'testonly-parent-token');
    await start();
    expect(seen.appOptions).toEqual([{ authToken: 'testonly-parent-token', hostCredentials: expect.objectContaining({ reader: 'imds' }) }]);
    // No endpoint: the real instance metadata service (hostCredentials.ts IMDS_ENDPOINT)
    expect(seen.credentialOptions).toEqual([[]]);
    expect(logs.join('\n')).not.toContain('testonly-parent-token');
    expect(logs.join('\n')).not.toContain('is not set');
  });

  it('without the token: the app gets none, and the start says the guarded routes are open', async () => {
    vi.stubEnv('ENCLAVE_PARENT_AUTH_TOKEN', '');
    await start();
    expect(seen.appOptions).toEqual([{ authToken: undefined, hostCredentials: expect.objectContaining({ reader: 'imds' }) }]);
    expect(logs).toContain('[parent] ENCLAVE_PARENT_AUTH_TOKEN is not set: /attest/fetch, /metrics and /routes answer every caller that reaches this port');
  });
});
