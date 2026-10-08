/**
 * The host role's temporary AWS credentials, read from IMDSv2, for the enclaves that open secrets sealed to them with
 * KMS (enclave audit P1.7; shared/src/sealedSecret.ts): they sign the enclave's KMS Decrypt, and nothing else. The
 * key policy, not an identity policy, lets this role Decrypt, and only with an attestation document of an enclave
 * image it names, so these credentials alone open nothing. This is the kmstool pattern: the parent reads them and
 * sends them with the request.
 *
 * IMDSv2 (the host requires it): a session token (PUT /latest/api/token), then the role's name and its credentials
 * (GET /latest/meta-data/iam/security-credentials/[<role>]). AWS makes new credentials available at least five
 * minutes before the old ones expire, so they are read again when five minutes or fewer are left. A failure is
 * never thrown at the caller: the request goes on without credentials (only a sealed secret then fails, in the
 * enclave), and IMDS is asked again no sooner than MIN_READ_INTERVAL_MS later. Credentials are never logged.
 */

/** What an enclave signs its KMS call with (shared/src/sigv4.ts AwsCredentials). */
export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
}

export interface HostCredentials {
  /** The host role's credentials, or null when IMDS cannot give any. Never throws. */
  get(): Promise<AwsCredentials | null>;
}

export interface HostCredentialsOptions {
  /** IMDS's address (tests point it at a fake). */
  endpoint?: string;
  /** The clock, in ms (tests set it). */
  now?: () => number;
  /** The budget of each IMDS call. */
  timeoutMs?: number;
}

/** The instance metadata service, link-local on every EC2 instance. */
export const IMDS_ENDPOINT = 'http://169.254.169.254';

/** Read again when this little is left: AWS publishes new credentials at least five minutes before expiry. */
export const REFRESH_BEFORE_EXPIRY_MS = 5 * 60 * 1000;

/** IMDS is asked at most once in this long, after a failure or a read that brought no new credentials. */
export const MIN_READ_INTERVAL_MS = 10 * 1000;

/** Credentials that expire sooner than this are not sent: the enclave's KMS call could outlive them. */
const MIN_VALID_MS = 60 * 1000;

/** The session token's life: one read of the role's credentials. */
const TOKEN_TTL_SECONDS = '300';

/** An IAM role name (IAM: letters, digits and +=,.@_-, at most 64). */
const ROLE_NAME = /^[\w+=,.@-]{1,64}$/;

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

/** One read: a session token, the role's name, its credentials. Throws with a reason that names no secret. */
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

export function createHostCredentials(options: HostCredentialsOptions = {}): HostCredentials {
  const endpoint = options.endpoint ?? IMDS_ENDPOINT;
  const now = options.now ?? Date.now;
  const timeoutMs = options.timeoutMs ?? 2_000;
  let cached: Cached | null = null;
  let lastReadAt: number | null = null;
  let inflight: Promise<AwsCredentials | null> | null = null;

  /** The kept credentials, while they still outlive an enclave's KMS call. */
  const usable = (): AwsCredentials | null => (cached && cached.expiresAt - now() > MIN_VALID_MS ? cached.credentials : null);

  async function readOnce(): Promise<AwsCredentials | null> {
    lastReadAt = now();
    try {
      cached = await readFromImds(endpoint, timeoutMs);
    } catch (err) {
      console.error(`[parent] IMDSv2: no host role credentials: ${JSON.stringify(err instanceof Error ? err.message : String(err))}`);
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
