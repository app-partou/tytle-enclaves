/**
 * The host role's credentials from IMDSv2 (hostCredentials.ts, enclave audit P1.7): the parent's own fetch calls run
 * for real against a fake IMDS on 127.0.0.1 (helpers/fakeImds.ts, IMDSv2 as a host that requires it answers). Only
 * IMDS and the clock are stand-ins.
 *
 * Labels: "red" = fails on the release before this one (it read no credentials).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { startFakeImds, imdsCredentials, type FakeImds, type ImdsAnswer } from './helpers/fakeImds.js';
import {
  createHostCredentials, IMDS_ENDPOINT, REFRESH_BEFORE_EXPIRY_MS, MIN_READ_INTERVAL_MS,
} from '../hostCredentials.js';

const T0 = Date.parse('2026-10-08T12:00:00Z');
const SIX_HOURS = 6 * 3600_000;

let imds: FakeImds | null = null;
let clock = T0;
let errors: string[];

async function hostWith(answer: (read: number) => ImdsAnswer, role?: string) {
  imds = await startFakeImds({ answer, ...(role === undefined ? {} : { role }) });
  return createHostCredentials({ endpoint: imds.url, now: () => clock, timeoutMs: 2_000 });
}

/** Every read gives fresh credentials that expire six hours after the clock's time of the read. */
const fresh = (read: number) => imdsCredentials(read, clock + SIX_HOURS);

beforeEach(() => {
  clock = T0;
  errors = [];
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => { errors.push(args.map(String).join(' ')); });
});

afterEach(async () => {
  vi.restoreAllMocks();
  await imds?.close();
  imds = null;
});

describe('IMDSv2 (red)', () => {
  it('reads the role\'s credentials with a session token: PUT the token, then every GET carries it', async () => {
    const host = await hostWith(fresh);
    expect(await host.get()).toEqual({
      accessKeyId: 'ASIATESTONLY00000001',
      secretAccessKey: 'testonly-secret-access-key-1',
      sessionToken: 'testonly-session-token-1',
    });
    expect(imds!.calls).toEqual([
      'PUT /latest/api/token',
      'GET /latest/meta-data/iam/security-credentials/ token',
      'GET /latest/meta-data/iam/security-credentials/tytle-staging-enclave-host token',
    ]);
    expect(errors).toEqual([]);
  });

  it('reads the real instance metadata service unless a test names another', () => {
    expect(IMDS_ENDPOINT).toBe('http://169.254.169.254');
  });
});

describe('kept until five minutes before they expire (red)', () => {
  it('reads once, keeps them, and reads again when five minutes are left', async () => {
    const host = await hostWith(fresh);
    await host.get();
    clock = T0 + SIX_HOURS - REFRESH_BEFORE_EXPIRY_MS - 1;
    expect((await host.get())?.accessKeyId).toBe('ASIATESTONLY00000001');
    expect(imds!.reads()).toBe(1);
    clock = T0 + SIX_HOURS - REFRESH_BEFORE_EXPIRY_MS;
    expect((await host.get())?.accessKeyId).toBe('ASIATESTONLY00000002');
    expect(imds!.reads()).toBe(2);
    expect(REFRESH_BEFORE_EXPIRY_MS).toBe(5 * 60_000);
  });

  it('requests that arrive together make one read', async () => {
    const host = await hostWith(fresh);
    const [a, b, c] = await Promise.all([host.get(), host.get(), host.get()]);
    expect(a).toEqual(b);
    expect(b).toEqual(c);
    expect(imds!.calls.filter((call) => call.startsWith('PUT'))).toHaveLength(1);
  });

  it('a read that brings no new credentials yet: they are used, and IMDS is asked again only after 10 s', async () => {
    // Rotation not visible yet: IMDS still answers credentials that expire in four minutes
    const host = await hostWith((read) => imdsCredentials(read, T0 + 4 * 60_000));
    expect((await host.get())?.accessKeyId).toBe('ASIATESTONLY00000001');
    clock = T0 + MIN_READ_INTERVAL_MS - 1;
    expect((await host.get())?.accessKeyId).toBe('ASIATESTONLY00000001');
    expect(imds!.reads()).toBe(1);
    clock = T0 + MIN_READ_INTERVAL_MS;
    await host.get();
    expect(imds!.reads()).toBe(2);
    expect(MIN_READ_INTERVAL_MS).toBe(10_000);
  });
});

describe('IMDS cannot give credentials: null, never a throw, and one line that names no secret (red)', () => {
  it('IMDS down: null and one error line; asked again only after 10 s', async () => {
    const host = await hostWith(fresh);
    imds!.failWith(500);
    expect(await host.get()).toBeNull();
    expect(errors).toEqual(['[parent] IMDSv2: no host role credentials: "IMDS answered 500 to PUT /latest/api/token"']);
    clock = T0 + MIN_READ_INTERVAL_MS - 1;
    expect(await host.get()).toBeNull();
    expect(imds!.calls).toHaveLength(1);
    clock = T0 + MIN_READ_INTERVAL_MS;
    imds!.failWith(null);
    expect((await host.get())?.accessKeyId).toBe('ASIATESTONLY00000001');
  });

  it('IMDS not listening at all: null', async () => {
    const host = createHostCredentials({ endpoint: 'http://127.0.0.1:9', now: () => clock, timeoutMs: 2_000 });
    expect(await host.get()).toBeNull();
    expect(errors).toHaveLength(1);
  });

  it('a failed refresh keeps the old credentials while they last more than a minute, then gives none', async () => {
    const host = await hostWith(fresh);
    await host.get();
    imds!.failWith(500);
    clock = T0 + SIX_HOURS - 4 * 60_000;
    expect((await host.get())?.accessKeyId).toBe('ASIATESTONLY00000001');
    clock = T0 + SIX_HOURS - 60_000;
    expect(await host.get()).toBeNull();
    expect(errors.join('\n')).not.toContain('testonly-secret-access-key');
    expect(errors.join('\n')).not.toContain('testonly-session-token');
  });

  it.each([
    ['a Code other than Success', (read: number) => ({ ...fresh(read), Code: 'Failure' }), /no usable credentials \(Code: Failure\)/],
    ['no session token', (read: number) => ({ ...fresh(read), Token: '' }), /no usable credentials/],
    ['no secret', (read: number) => { const { SecretAccessKey: _secret, ...rest } = fresh(read); return rest; }, /no usable credentials/],
    ['an Expiration that is not a time', (read: number) => ({ ...fresh(read), Expiration: 'soon' }), /no usable credentials/],
    ['not JSON', () => ({ status: 200, body: '<html>' }), /without a JSON object/],
    ['a JSON array', () => ({ status: 200, body: '[]' }), /without a JSON object/],
    ['an error', () => ({ status: 404, body: 'Not Found' }), /IMDS answered 404 to GET/],
  ])('%s: null', async (_label, answer, reason) => {
    const host = await hostWith(answer as (read: number) => ImdsAnswer);
    expect(await host.get()).toBeNull();
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(reason);
  });

  it.each([
    ['no role', ''],
    ['a role name IAM does not allow', 'role/../../x'],
  ])('%s: null, and the credentials are never asked', async (_label, role) => {
    const host = await hostWith(fresh, role);
    expect(await host.get()).toBeNull();
    expect(errors[0]).toMatch(/IMDS names no instance role/);
    expect(imds!.reads()).toBe(0);
  });
});
