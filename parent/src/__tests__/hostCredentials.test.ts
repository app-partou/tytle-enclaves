/**
 * The narrow role's sessions (hostCredentials.ts; enclave audit P1.7, review E2b F-12, the main repository's
 * KMS_ALARM_PLAN.md part 4): the parent's own fetch calls and its SigV4 signature run for real against a fake IMDS and
 * a fake STS on 127.0.0.1 (helpers/fakeImds.ts, IMDSv2 as a host that requires it answers; helpers/fakeSts.ts, STS's
 * Query API). Only IMDS, STS and the clock are stand-ins.
 *
 * Labels: "red" = fails on the release before this one (it handed the enclaves the host role's own credentials).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { signRequest } from '@tytle-enclaves/shared';
import { startFakeImds, imdsCredentials, type FakeImds, type ImdsAnswer } from './helpers/fakeImds.js';
import { startFakeSts, stsSession, stsErrorXml, assumeRoleXml, type FakeSts, type StsAnswer } from './helpers/fakeSts.js';
import {
  createHostCredentials, IMDS_ENDPOINT, STS_ENDPOINT, SESSION_SECONDS, ROLE_SESSION_NAME, REFRESH_BEFORE_EXPIRY_MS,
  MIN_READ_INTERVAL_MS,
} from '../hostCredentials.js';

const ROLE_ARN = 'arn:aws:iam::123456789012:role/tytle-staging-enclave-kms-decrypt';
const T0 = Date.parse('2026-10-08T12:00:00Z');
const SIX_HOURS = 6 * 3600_000;
const SESSION = 15 * 60_000;

let imds: FakeImds | null = null;
let sts: FakeSts | null = null;
let clock = T0;
let errors: string[];

/** Every IMDS read gives the host role fresh credentials for six hours; every AssumeRole a session for 15 minutes. */
const fresh = (read: number) => imdsCredentials(read, clock + SIX_HOURS);
const session = (n: number) => stsSession(n, clock + SESSION);

async function hostWith(answer: (read: number) => ImdsAnswer, opts: { role?: string; sts?: (n: number) => StsAnswer } = {}) {
  imds = await startFakeImds({ answer, ...(opts.role === undefined ? {} : { role: opts.role }) });
  sts = await startFakeSts(opts.sts ?? session);
  return createHostCredentials({ roleArn: ROLE_ARN, endpoint: imds.url, stsEndpoint: sts.url, now: () => clock, timeoutMs: 2_000 });
}

/** What get() gives for the n-th session STS answered (at T0 unless told). */
const sessionCredentials = (n: number, at = T0) => {
  const s = stsSession(n, at + SESSION);
  return { accessKeyId: s.accessKeyId, secretAccessKey: s.secretAccessKey, sessionToken: s.sessionToken };
};

beforeEach(() => {
  clock = T0;
  errors = [];
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => { errors.push(args.map(String).join(' ')); });
});

afterEach(async () => {
  vi.restoreAllMocks();
  await imds?.close();
  await sts?.close();
  imds = null;
  sts = null;
});

describe('a session of the narrow role, never the host role\'s own credentials (red)', () => {
  it('reads the host role\'s credentials from IMDSv2, asks STS for a session of the narrow role with them, and gives only the session', async () => {
    const host = await hostWith(fresh);
    const got = await host.get();
    expect(got).toEqual(sessionCredentials(1));
    expect(JSON.stringify(got)).not.toContain('testonly-secret-access-key');
    expect(JSON.stringify(got)).not.toContain('testonly-session-token');
    expect(imds!.calls).toEqual([
      'PUT /latest/api/token',
      'GET /latest/meta-data/iam/security-credentials/ token',
      'GET /latest/meta-data/iam/security-credentials/tytle-staging-enclave-host token',
    ]);
    expect(sts!.requests).toHaveLength(1);
    const [asked] = sts!.requests;
    expect(asked.method).toBe('POST');
    expect(asked.path).toBe('/');
    expect(asked.form).toEqual({
      Action: 'AssumeRole', Version: '2011-06-15', RoleArn: ROLE_ARN, RoleSessionName: 'tytle-enclave-parent', DurationSeconds: '900',
    });
    expect(asked.headers['content-type']).toBe('application/x-www-form-urlencoded; charset=utf-8');
    expect(asked.headers['x-amz-date']).toBe('20261008T120000Z');
    // Signed with the HOST role's credentials (from IMDS), in the KMS region, for STS
    expect(asked.headers['x-amz-security-token']).toBe('testonly-session-token-1');
    expect(asked.headers.authorization).toMatch(new RegExp(
      '^AWS4-HMAC-SHA256 Credential=ASIATESTONLY00000001/20261008/eu-central-1/sts/aws4_request, '
      + 'SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature=[0-9a-f]{64}$',
    ));
    expect(errors).toEqual([]);
  });

  it('the signature covers exactly what reached STS: its Host, its headers and its body', async () => {
    const host = await hostWith(fresh);
    await host.get();
    expect(sts!.requests).toHaveLength(1);
    const [asked] = sts!.requests;
    const imdsCreds = imdsCredentials(1, T0 + SIX_HOURS);
    const expected = signRequest(
      {
        method: 'POST', host: String(asked.headers.host), path: '/', query: '',
        headers: { 'content-type': String(asked.headers['content-type']) }, body: asked.body,
      },
      {
        service: 'sts', region: 'eu-central-1', now: new Date(T0),
        credentials: { accessKeyId: String(imdsCreds.AccessKeyId), secretAccessKey: String(imdsCreds.SecretAccessKey), sessionToken: String(imdsCreds.Token) },
      },
    );
    expect(asked.headers.authorization).toBe(expected.authorization);
  });

  it('asks STS in the KMS key\'s region (the regional endpoint), for the shortest session, under one session name', () => {
    expect(STS_ENDPOINT).toBe('https://sts.eu-central-1.amazonaws.com');
    expect(SESSION_SECONDS).toBe(900);
    expect(ROLE_SESSION_NAME).toBe('tytle-enclave-parent');
    expect(IMDS_ENDPOINT).toBe('http://169.254.169.254');
  });
});

describe('no narrow role: no credentials at all, never the host role\'s (red)', () => {
  it.each([
    ['no ENCLAVE_KMS_ROLE_ARN', undefined, 'no ENCLAVE_KMS_ROLE_ARN'],
    ['a user\'s ARN', 'arn:aws:iam::123456789012:user/someone', 'ENCLAVE_KMS_ROLE_ARN is not a role ARN'],
    ['a role name, not its ARN', 'tytle-staging-enclave-kms-decrypt', 'ENCLAVE_KMS_ROLE_ARN is not a role ARN'],
  ])('%s: null, IMDS and STS never asked, and one line that says so', async (_label, roleArn, said) => {
    imds = await startFakeImds({ answer: fresh });
    sts = await startFakeSts(session);
    const host = createHostCredentials({ roleArn, endpoint: imds.url, stsEndpoint: sts.url, now: () => clock, timeoutMs: 2_000 });
    expect(await host.get()).toBeNull();
    expect(await host.get()).toBeNull();
    expect(imds.calls).toEqual([]);
    expect(sts.requests).toEqual([]);
    expect(errors).toEqual([`[parent] ${said}: the enclaves get no AWS credentials, so a sealed secret cannot be opened`]);
  });
});

describe('a session is kept until five minutes before it expires (red)', () => {
  it('asks once, keeps it, and asks again when five minutes are left', async () => {
    const host = await hostWith(fresh);
    await host.get();
    clock = T0 + SESSION - REFRESH_BEFORE_EXPIRY_MS - 1;
    expect((await host.get())?.accessKeyId).toBe('ASIATESTONLYSTS00001');
    expect(sts!.requests).toHaveLength(1);
    clock = T0 + SESSION - REFRESH_BEFORE_EXPIRY_MS;
    expect((await host.get())?.accessKeyId).toBe('ASIATESTONLYSTS00002');
    expect(sts!.requests).toHaveLength(2);
    expect(imds!.reads()).toBe(2);
    expect(REFRESH_BEFORE_EXPIRY_MS).toBe(5 * 60_000);
  });

  it('requests that arrive together make one read and one AssumeRole', async () => {
    const host = await hostWith(fresh);
    const [a, b, c] = await Promise.all([host.get(), host.get(), host.get()]);
    expect(a).toEqual(sessionCredentials(1));
    expect(b).toEqual(a);
    expect(c).toEqual(a);
    expect(imds!.calls.filter((call) => call.startsWith('PUT'))).toHaveLength(1);
    expect(sts!.requests).toHaveLength(1);
  });

  it('a session that is already short: used, and asked again only after 10 s', async () => {
    const host = await hostWith(fresh, { sts: (n) => stsSession(n, clock + 4 * 60_000) });
    expect((await host.get())?.accessKeyId).toBe('ASIATESTONLYSTS00001');
    clock = T0 + MIN_READ_INTERVAL_MS - 1;
    expect((await host.get())?.accessKeyId).toBe('ASIATESTONLYSTS00001');
    expect(sts!.requests).toHaveLength(1);
    clock = T0 + MIN_READ_INTERVAL_MS;
    await host.get();
    expect(sts!.requests).toHaveLength(2);
    expect(MIN_READ_INTERVAL_MS).toBe(10_000);
  });
});

describe('IMDS cannot give the host role\'s credentials: null, never a throw, STS never asked, one line that names no secret (red)', () => {
  it('IMDS down: null and one error line; asked again only after 10 s', async () => {
    const host = await hostWith(fresh);
    imds!.failWith(500);
    expect(await host.get()).toBeNull();
    expect(errors).toEqual(['[parent] no AWS credentials for the enclaves: "IMDS answered 500 to PUT /latest/api/token"']);
    clock = T0 + MIN_READ_INTERVAL_MS - 1;
    expect(await host.get()).toBeNull();
    expect(imds!.calls).toHaveLength(1);
    expect(sts!.requests).toEqual([]);
    clock = T0 + MIN_READ_INTERVAL_MS;
    imds!.failWith(null);
    expect((await host.get())?.accessKeyId).toBe('ASIATESTONLYSTS00001');
  });

  it('IMDS not listening at all: null', async () => {
    sts = await startFakeSts(session);
    const host = createHostCredentials({ roleArn: ROLE_ARN, endpoint: 'http://127.0.0.1:9', stsEndpoint: sts.url, now: () => clock, timeoutMs: 2_000 });
    expect(await host.get()).toBeNull();
    expect(errors).toHaveLength(1);
    expect(sts.requests).toEqual([]);
  });

  it('a failed refresh keeps the session while it lasts more than a minute, then gives none', async () => {
    const host = await hostWith(fresh);
    await host.get();
    imds!.failWith(500);
    clock = T0 + SESSION - 4 * 60_000;
    expect((await host.get())?.accessKeyId).toBe('ASIATESTONLYSTS00001');
    clock = T0 + SESSION - 60_000;
    expect(await host.get()).toBeNull();
    for (const secret of ['testonly-secret-access-key', 'testonly-session-token', 'testonly/narrow+role/secret', 'testonly+narrow/role+session/token']) {
      expect(errors.join('\n')).not.toContain(secret);
    }
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
    expect(sts!.requests).toEqual([]);
  });

  it.each([
    ['no role', ''],
    ['a role name IAM does not allow', 'role/../../x'],
  ])('%s: null, and the credentials are never asked', async (_label, role) => {
    const host = await hostWith(fresh, { role });
    expect(await host.get()).toBeNull();
    expect(errors[0]).toMatch(/IMDS names no instance role/);
    expect(imds!.reads()).toBe(0);
    expect(sts!.requests).toEqual([]);
  });
});

describe('STS gives no session: null, never the host role\'s credentials, one line that names no secret (red)', () => {
  it('STS refuses (403 AccessDenied): null, the code logged and never its message; asked again only after 10 s', async () => {
    const host = await hostWith(fresh, {
      sts: (n) => (n === 1
        ? { status: 403, body: stsErrorXml('AccessDenied', `User: ${ROLE_ARN} is not authorized to perform: sts:AssumeRole`) }
        : session(n)),
    });
    expect(await host.get()).toBeNull();
    expect(errors).toEqual(['[parent] no AWS credentials for the enclaves: "STS answered 403 to AssumeRole (AccessDenied)"']);
    clock = T0 + MIN_READ_INTERVAL_MS - 1;
    expect(await host.get()).toBeNull();
    expect(sts!.requests).toHaveLength(1);
    clock = T0 + MIN_READ_INTERVAL_MS;
    expect((await host.get())?.accessKeyId).toBe('ASIATESTONLYSTS00002');
  });

  it('STS down (a 500 without its XML): null', async () => {
    const host = await hostWith(fresh, { sts: () => ({ status: 500, body: 'Internal error' }) });
    expect(await host.get()).toBeNull();
    expect(errors).toEqual(['[parent] no AWS credentials for the enclaves: "STS answered 500 to AssumeRole"']);
  });

  const valid = stsSession(1, T0 + SESSION);
  const xmlWith = (s: Partial<typeof valid>) => assumeRoleXml({ ...valid, ...s });
  it.each([
    ['not its XML', '{"Credentials":{}}', /without one set of credentials/],
    ['two sets of credentials', assumeRoleXml(valid).replace('</AssumeRoleResult>', `<Credentials><AccessKeyId>ASIATESTONLYSTS00009</AccessKeyId></Credentials></AssumeRoleResult>`), /without one set of credentials/],
    ['a long-term key id (AKIA), not a session\'s', xmlWith({ accessKeyId: 'AKIATESTONLY00000001' }), /without a usable AccessKeyId/],
    ['an empty session token', xmlWith({ sessionToken: '' }), /without a usable SessionToken/],
    ['an XML entity in the secret', xmlWith({ secretAccessKey: 'testonly&amp;secret' }), /without a usable SecretAccessKey/],
    ['an Expiration that is not a time', xmlWith({ expiration: 'in fifteen minutes' }), /without a usable Expiration/],
    ['no session token', assumeRoleXml(valid).replace(/<SessionToken>[^<]*<\/SessionToken>/, ''), /without a usable SessionToken/],
    ['two key ids', assumeRoleXml(valid).replace('<SecretAccessKey>', '<AccessKeyId>ASIATESTONLYSTS00009</AccessKeyId><SecretAccessKey>'), /without a usable AccessKeyId/],
  ])('%s: null', async (_label, body, reason) => {
    const host = await hostWith(fresh, { sts: () => ({ status: 200, body }) });
    expect(await host.get()).toBeNull();
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(reason);
    expect(errors[0]).not.toContain('testonly-secret-access-key');
  });
});
