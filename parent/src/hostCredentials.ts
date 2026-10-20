/**
 * The AWS credentials the parent hands an enclave that opens a secret sealed to it with KMS (enclave audit P1.7;
 * shared/src/sealedSecret.ts): the enclave signs its KMS Decrypt with them. This is the kmstool pattern: the parent
 * gets them and sends them with the request.
 *
 * They are a session of the NARROW role (`tytle-<env>-enclave-kms-decrypt`, ENCLAVE_KMS_ROLE_ARN in the parent's unit),
 * never the host role's own credentials (enclave review 2026-10-09, E2b F-12; the main repository's
 * docs/enclave-audit-2026-10/plans/KMS_ALARM_PLAN.md part 4, LJ 2026-10-14). The narrow role has no policy of its own:
 * its one power is the KMS key policy's Decrypt, for the Stripe enclave's image only (infra/lib/nitro-enclave-stack.ts).
 * So what the parent hands out opens a sealed secret and nothing more. The host role's credentials can also write the
 * PCR0 pins data-bridge trusts, pull from ECR, write logs and metrics, and use Session Manager: they never leave the
 * parent. And the parent still sends a session only with a request that sends a sealed secret (enclaveRouter.ts
 * sendsSealedSecret): an enclave bug that echoed its request would hand out no more than that session.
 *
 * How: IMDSv2 (the host requires it) gives the host role's credentials - a session token (PUT /latest/api/token), then
 * the role's name and its credentials (GET /latest/meta-data/iam/security-credentials/[<role>]) - and those sign one
 * STS AssumeRole (SigV4, shared/src/sigv4.ts) for the narrow role, in KMS_REGION (the region of the key and of the
 * enclave's KMS calls), for as short a session as STS gives: 15 minutes. A session is asked again when five minutes or
 * fewer are left.
 *
 * No role ARN: no credentials at all, never the host role's (a sealed secret then fails, in the enclave). A failure is
 * never thrown at the caller: the request goes on without credentials, and IMDS and STS are asked again no sooner
 * than MIN_READ_INTERVAL_MS later. Credentials are never logged.
 */
import { KMS_REGION, signRequest } from '@tytle-enclaves/shared';

/** What an enclave signs its KMS call with (shared/src/sigv4.ts AwsCredentials). */
export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
}

export interface HostCredentials {
  /** A session of the narrow role, or null when none can be had. Never throws. */
  get(): Promise<AwsCredentials | null>;
}

export interface HostCredentialsOptions {
  /** The narrow role (the parent unit's ENCLAVE_KMS_ROLE_ARN). Without it, no credentials are ever given. */
  roleArn?: string;
  /** IMDS's address (tests point it at a fake). */
  endpoint?: string;
  /** STS's address (tests point it at a fake). */
  stsEndpoint?: string;
  /** The clock, in ms (tests set it). */
  now?: () => number;
  /** The budget of each IMDS or STS call. */
  timeoutMs?: number;
}

/** The instance metadata service, link-local on every EC2 instance. */
export const IMDS_ENDPOINT = 'http://169.254.169.254';

/** STS in the region of the KMS key: the regional endpoint (STS's own advice), never the global one. */
export const STS_ENDPOINT = `https://sts.${KMS_REGION}.amazonaws.com`;

/** The narrow role's session: as short as STS gives (AssumeRole's DurationSeconds is at least 900). */
export const SESSION_SECONDS = 900;

/** The name each session carries in CloudTrail. */
export const ROLE_SESSION_NAME = 'tytle-enclave-parent';

/** Read again when this little is left of a session. */
export const REFRESH_BEFORE_EXPIRY_MS = 5 * 60 * 1000;

/** IMDS and STS are asked at most once in this long, after a failure or a read that brought no new session. */
export const MIN_READ_INTERVAL_MS = 10 * 1000;

/** Credentials that expire sooner than this are not sent: the enclave's KMS call could outlive them. */
const MIN_VALID_MS = 60 * 1000;

/** The session token's life: one read of the role's credentials. */
const TOKEN_TTL_SECONDS = '300';

/** An IAM role name (IAM: letters, digits and +=,.@_-, at most 64). */
const ROLE_NAME = /^[\w+=,.@-]{1,64}$/;

/** A role's ARN, no path (the narrow role has none): arn:aws:iam::<12 digits>:role/<name>. */
export const ROLE_ARN = /^arn:aws:iam::\d{12}:role\/[\w+=,.@-]{1,64}$/;

/** A session's fields as STS writes them: a temporary key id, a secret and a token in base64's letters, a time. */
const SESSION_FIELDS: ReadonlyArray<readonly [keyof AwsCredentials | 'expiration', string, RegExp]> = [
  ['accessKeyId', 'AccessKeyId', /^ASIA[A-Z0-9]{12,124}$/],
  ['secretAccessKey', 'SecretAccessKey', /^[A-Za-z0-9+/=]{1,256}$/],
  ['sessionToken', 'SessionToken', /^[A-Za-z0-9+/=]{1,8192}$/],
  ['expiration', 'Expiration', /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/],
];

interface Cached {
  credentials: AwsCredentials;
  expiresAt: number;
}

function nonEmptyText(value: unknown): value is string {
  return typeof value === 'string' && value !== '';
}

async function imds(endpoint: string, path: string, init: RequestInit, timeoutMs: number): Promise<string> {
  const res = await fetch(`${endpoint}${path}`, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  const text = await res.text();
  if (!res.ok) throw new Error(`IMDS answered ${res.status} to ${init.method ?? 'GET'} ${path}`);
  return text;
}

/** The host role's credentials: a session token, the role's name, its credentials. Throws with a reason that names no secret. */
async function readFromImds(endpoint: string, timeoutMs: number): Promise<Cached> {
  const token = await imds(endpoint, '/latest/api/token', {
    method: 'PUT',
    headers: { 'X-aws-ec2-metadata-token-ttl-seconds': TOKEN_TTL_SECONDS },
  }, timeoutMs);
  const headers = { 'X-aws-ec2-metadata-token': token.trim() };
  const role = (await imds(endpoint, '/latest/meta-data/iam/security-credentials/', { headers }, timeoutMs))
    .split('\n')[0].trim();
  if (!ROLE_NAME.test(role)) throw new Error('IMDS names no instance role');

  let answer: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(await imds(endpoint, `/latest/meta-data/iam/security-credentials/${role}`, { headers }, timeoutMs));
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('not an object');
    answer = parsed as Record<string, unknown>;
  } catch (err) {
    if (err instanceof Error && err.message.startsWith('IMDS answered')) throw err;
    throw new Error('IMDS answered the role\'s credentials without a JSON object');
  }
  const expiresAt = typeof answer.Expiration === 'string' ? Date.parse(answer.Expiration) : NaN;
  if (answer.Code !== 'Success' || !nonEmptyText(answer.AccessKeyId) || !nonEmptyText(answer.SecretAccessKey)
    || !nonEmptyText(answer.Token) || Number.isNaN(expiresAt)) {
    throw new Error(`IMDS answered no usable credentials (Code: ${typeof answer.Code === 'string' ? answer.Code : 'none'})`);
  }
  return {
    credentials: { accessKeyId: answer.AccessKeyId, secretAccessKey: answer.SecretAccessKey, sessionToken: answer.Token },
    expiresAt,
  };
}

/**
 * The session in AssumeRole's answer. Each field must be there exactly once, inside the one <Credentials>, in the
 * letters STS writes it with (so no XML entity is ever read as a value), and the session must outlive the read.
 */
function sessionOf(xml: string): Cached {
  const blocks = [...xml.matchAll(/<Credentials>([\s\S]*?)<\/Credentials>/g)];
  if (!/^\s*(?:<\?xml[^>]*\?>\s*)?<AssumeRoleResponse[\s>]/.test(xml) || blocks.length !== 1) {
    throw new Error('STS answered AssumeRole without one set of credentials');
  }
  const values: Partial<Record<keyof AwsCredentials | 'expiration', string>> = {};
  for (const [key, element, pattern] of SESSION_FIELDS) {
    const found = [...blocks[0][1].matchAll(new RegExp(`<${element}>([^<]*)</${element}>`, 'g'))];
    if (found.length !== 1 || !pattern.test(found[0][1])) throw new Error(`STS answered AssumeRole without a usable ${element}`);
    values[key] = found[0][1];
  }
  return {
    credentials: { accessKeyId: values.accessKeyId!, secretAccessKey: values.secretAccessKey!, sessionToken: values.sessionToken! },
    expiresAt: Date.parse(values.expiration!),
  };
}

/** The error code of an STS error answer, when it names one (never its message). */
function stsErrorCodeOf(xml: string): string {
  const code = /<Code>([A-Za-z.]{1,64})<\/Code>/.exec(xml)?.[1];
  return code ? ` (${code})` : '';
}

/** One AssumeRole of `roleArn`, signed with the host role's credentials. Throws with a reason that names no secret. */
async function assumeRole(stsEndpoint: string, roleArn: string, signer: AwsCredentials, now: Date, timeoutMs: number): Promise<Cached> {
  const url = new URL('/', stsEndpoint);
  const body = new URLSearchParams({
    Action: 'AssumeRole',
    Version: '2011-06-15',
    RoleArn: roleArn,
    RoleSessionName: ROLE_SESSION_NAME,
    DurationSeconds: String(SESSION_SECONDS),
  }).toString();
  const signed = signRequest(
    { method: 'POST', host: url.host, path: '/', query: '', headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' }, body },
    { service: 'sts', region: KMS_REGION, credentials: signer, now },
  );
  // fetch sends the Host of the URL, the one signed; it is not a header to set
  const headers = Object.fromEntries(Object.entries(signed).filter(([name]) => name !== 'host'));
  const res = await fetch(url, { method: 'POST', headers, body, signal: AbortSignal.timeout(timeoutMs) });
  const text = await res.text();
  if (!res.ok) throw new Error(`STS answered ${res.status} to AssumeRole${stsErrorCodeOf(text)}`);
  return sessionOf(text);
}

export function createHostCredentials(options: HostCredentialsOptions = {}): HostCredentials {
  const roleArn = options.roleArn;
  if (roleArn === undefined || !ROLE_ARN.test(roleArn)) {
    console.error(`[parent] ${roleArn === undefined ? 'no ENCLAVE_KMS_ROLE_ARN' : 'ENCLAVE_KMS_ROLE_ARN is not a role ARN'}: `
      + 'the enclaves get no AWS credentials, so a sealed secret cannot be opened');
    return { async get() { return null; } };
  }
  const arn: string = roleArn;
  const endpoint = options.endpoint ?? IMDS_ENDPOINT;
  const stsEndpoint = options.stsEndpoint ?? STS_ENDPOINT;
  const now = options.now ?? Date.now;
  const timeoutMs = options.timeoutMs ?? 2_000;
  let cached: Cached | null = null;
  let lastReadAt: number | null = null;
  let inflight: Promise<AwsCredentials | null> | null = null;

  /** The kept session, while it still outlives an enclave's KMS call. */
  const usable = (): AwsCredentials | null => (cached && cached.expiresAt - now() > MIN_VALID_MS ? cached.credentials : null);

  async function readOnce(): Promise<AwsCredentials | null> {
    lastReadAt = now();
    try {
      const host = await readFromImds(endpoint, timeoutMs);
      cached = await assumeRole(stsEndpoint, arn, host.credentials, new Date(now()), timeoutMs);
    } catch (err) {
      console.error(`[parent] no AWS credentials for the enclaves: ${JSON.stringify(err instanceof Error ? err.message : String(err))}`);
    }
    return usable();
  }

  return {
    async get() {
      if (cached && cached.expiresAt - now() > REFRESH_BEFORE_EXPIRY_MS) return cached.credentials;
      // One read at a time: requests that arrive while it runs wait for it
      if (inflight) return inflight;
      if (lastReadAt !== null && now() - lastReadAt < MIN_READ_INTERVAL_MS) return usable();
      inflight = readOnce().finally(() => { inflight = null; });
      return inflight;
    },
  };
}
