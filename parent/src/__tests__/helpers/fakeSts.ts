/**
 * A stand-in for AWS STS's Query API, AssumeRole only: real HTTP on 127.0.0.1, so hostCredentials.ts runs its own
 * fetch and its own SigV4 signature. Each request is recorded (method, path, headers, the form it sent). The n-th
 * AssumeRole (from 1) answers what `answer(n)` gives: a session, written as STS writes its XML, or a raw status and body.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';

export interface StsSession {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  /** ISO time, as STS writes it */
  expiration: string;
}

export type StsAnswer = StsSession | { status: number; body: string };

export interface StsRequest {
  method: string;
  path: string;
  headers: http.IncomingHttpHeaders;
  /** The body as sent, and as a form */
  body: string;
  form: Record<string, string>;
}

export interface FakeSts {
  url: string;
  requests: StsRequest[];
  close(): Promise<void>;
}

/** The session STS gives for its n-th AssumeRole, expiring at `expiresAt` (ms). Every value is TEST ONLY. */
export function stsSession(n: number, expiresAt: number): StsSession {
  return {
    accessKeyId: `ASIATESTONLYSTS0000${n}`,
    secretAccessKey: `testonly/narrow+role/secret${n}`,
    sessionToken: `testonly+narrow/role+session/token${n}==`,
    expiration: new Date(expiresAt).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
}

/** AssumeRole's answer as STS writes it (API reference, AssumeRole, "Example": the response). */
export function assumeRoleXml(s: StsSession): string {
  return [
    '<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">',
    '  <AssumeRoleResult>',
    '    <AssumedRoleUser>',
    '      <Arn>arn:aws:sts::123456789012:assumed-role/tytle-staging-enclave-kms-decrypt/tytle-enclave-parent</Arn>',
    '      <AssumedRoleId>AROATESTONLY0000000:tytle-enclave-parent</AssumedRoleId>',
    '    </AssumedRoleUser>',
    '    <Credentials>',
    `      <AccessKeyId>${s.accessKeyId}</AccessKeyId>`,
    `      <SecretAccessKey>${s.secretAccessKey}</SecretAccessKey>`,
    `      <SessionToken>${s.sessionToken}</SessionToken>`,
    `      <Expiration>${s.expiration}</Expiration>`,
    '    </Credentials>',
    '    <PackedPolicySize>0</PackedPolicySize>',
    '  </AssumeRoleResult>',
    '  <ResponseMetadata>',
    '    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>',
    '  </ResponseMetadata>',
    '</AssumeRoleResponse>',
  ].join('\n');
}

/** An error as STS writes it. */
export function stsErrorXml(code: string, message: string): string {
  return `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>${code}</Code><Message>${message}</Message></Error><RequestId>c6104cbe</RequestId></ErrorResponse>`;
}

export async function startFakeSts(answer: (n: number) => StsAnswer | Promise<StsAnswer>): Promise<FakeSts> {
  const requests: StsRequest[] = [];
  const server = http.createServer((req, res) => {
    let text = '';
    req.setEncoding('utf8');
    req.on('data', (chunk: string) => { text += chunk; });
    req.on('end', () => {
      requests.push({
        method: req.method ?? '', path: req.url ?? '', headers: req.headers, body: text, form: Object.fromEntries(new URLSearchParams(text)),
      });
      void Promise.resolve(answer(requests.length)).then((out) => {
        if ('status' in out) res.writeHead(out.status, { 'Content-Type': 'text/xml' }).end(out.body);
        else res.writeHead(200, { 'Content-Type': 'text/xml' }).end(assumeRoleXml(out));
      });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
