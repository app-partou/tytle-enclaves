/**
 * A stand-in for the EC2 instance metadata service as IMDSv2 answers on a host that requires it (the enclave host's
 * launch template sets HttpTokens required): real HTTP on 127.0.0.1, so hostCredentials.ts runs its own fetch calls.
 * PUT /latest/api/token needs the TTL header and gives a session token; every GET needs a token it gave (401
 * otherwise, as IMDSv2 answers); GET .../iam/security-credentials/ names the role, and GET .../<role> answers the
 * credentials JSON that `answer(read)` gives for the n-th read (from 1). Every call is recorded.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';

export type ImdsAnswer = Record<string, unknown> | { status: number; body: string };

export interface FakeImds {
  url: string;
  /** `METHOD path`, with ` token` when the call carried a session token this IMDS gave. */
  calls: string[];
  /** How many times the role's credentials were read. */
  reads(): number;
  /** Make every call fail with this status from now on (null: answer again). */
  failWith(status: number | null): void;
  close(): Promise<void>;
}

/** The credentials IMDS gives for its n-th read, expiring at `expiresAt` (ms). Every value is TEST ONLY. */
export function imdsCredentials(n: number, expiresAt: number): Record<string, unknown> {
  return {
    Code: 'Success',
    LastUpdated: new Date(expiresAt - 6 * 3600_000).toISOString(),
    Type: 'AWS-HMAC',
    AccessKeyId: `ASIATESTONLY0000000${n}`,
    SecretAccessKey: `testonly-secret-access-key-${n}`,
    Token: `testonly-session-token-${n}`,
    Expiration: new Date(expiresAt).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
}

export async function startFakeImds({ role = 'tytle-staging-enclave-host', answer }: {
  role?: string;
  answer: (read: number) => ImdsAnswer;
}): Promise<FakeImds> {
  const calls: string[] = [];
  const tokens = new Set<string>();
  let reads = 0;
  let failing: number | null = null;

  const server = http.createServer((req, res) => {
    const token = req.headers['x-aws-ec2-metadata-token'];
    const withToken = typeof token === 'string' && tokens.has(token);
    calls.push(`${req.method} ${req.url}${withToken ? ' token' : ''}`);
    const send = (status: number, body: string) => { res.writeHead(status, { 'Content-Type': 'text/plain' }).end(body); };
    if (failing !== null) return send(failing, 'failing');
    if (req.method === 'PUT' && req.url === '/latest/api/token') {
      if (!req.headers['x-aws-ec2-metadata-token-ttl-seconds']) return send(400, 'missing TTL');
      const issued = `testonly-imds-token-${tokens.size + 1}`;
      tokens.add(issued);
      return send(200, issued);
    }
    if (req.method !== 'GET') return send(405, 'method');
    if (!withToken) return send(401, 'Unauthorized');
    if (req.url === '/latest/meta-data/iam/security-credentials/') return send(200, role);
    if (req.url === `/latest/meta-data/iam/security-credentials/${role}`) {
      const out = answer(++reads);
      return 'status' in out && typeof out.status === 'number' && typeof out.body === 'string'
        ? send(out.status, out.body)
        : send(200, JSON.stringify(out));
    }
    return send(404, 'Not Found');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    calls,
    reads: () => reads,
    failWith: (status) => { failing = status; },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
