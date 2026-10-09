/**
 * AWS Signature Version 4 for the enclave's one AWS call, KMS Decrypt (sealedSecret.ts; enclave audit P1.7).
 *
 * Written here instead of pulling the AWS SDK into every enclave image: the SDK is dozens of packages, each in the
 * image and so in PCR0, for one signed POST. The algorithm is AWS's ("Create a signed AWS API request", IAM user
 * guide): a canonical request, a string to sign over its SHA-256, and an HMAC-SHA256 chain from "AWS4" + the secret
 * key through the date, the region, the service and "aws4_request". __tests__/sigv4.test.ts checks it against
 * AWS's own worked example and against the AWS SDK's signer (@smithy/signature-v4) on the KMS request.
 */

import crypto from 'node:crypto';

/** Temporary credentials of the host's instance role, as the parent forwards them (from IMDSv2). */
export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  /** The session token of temporary credentials (an instance role's always have one). */
  sessionToken?: string;
}

export interface SignableRequest {
  method: string;
  host: string;
  /** The path, already URI-encoded as it is sent ("/" for KMS). */
  path: string;
  /** The query string without "?", as it is sent ("" for none). */
  query?: string;
  /** Headers to send and sign, besides host, x-amz-date and x-amz-security-token (added here). */
  headers: Record<string, string>;
  body: string;
}

export interface SigningScope {
  service: string;
  region: string;
  credentials: AwsCredentials;
  /** The signing time (x-amz-date). */
  now: Date;
}

const sha256Hex = (data: string | Buffer): string => crypto.createHash('sha256').update(data).digest('hex');
const hmac = (key: string | Buffer, data: string): Buffer => crypto.createHmac('sha256', key).update(data).digest();

/** RFC 3986 percent-encoding as SigV4 wants it: everything but A-Z a-z 0-9 - _ . ~ */
function uriEncode(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** The query string with each name and value decoded, re-encoded and sorted (by name, then value). */
function canonicalQuery(query: string): string {
  if (query === '') return '';
  return query.split('&')
    .map((pair) => {
      const eq = pair.indexOf('=');
      const name = decodeURIComponent(eq < 0 ? pair : pair.slice(0, eq));
      const value = eq < 0 ? '' : decodeURIComponent(pair.slice(eq + 1));
      return [uriEncode(name), uriEncode(value)] as const;
    })
    .sort(([a, av], [b, bv]) => (a < b ? -1 : a > b ? 1 : av < bv ? -1 : av > bv ? 1 : 0))
    .map(([name, value]) => `${name}=${value}`)
    .join('&');
}

/** `20150830T123600Z`: the ISO time without separators or milliseconds. */
function amzDateOf(now: Date): string {
  return now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
}

/**
 * The headers to send for `request`, signed: the request's own headers plus host, x-amz-date, x-amz-security-token
 * (with a session token) and authorization. Every header sent is signed.
 */
export function signRequest(request: SignableRequest, scope: SigningScope): Record<string, string> {
  const amzDate = amzDateOf(scope.now);
  const dateStamp = amzDate.slice(0, 8);
  const toSign: Record<string, string> = {};
  for (const [name, value] of Object.entries(request.headers)) toSign[name.toLowerCase()] = value;
  toSign.host = request.host;
  toSign['x-amz-date'] = amzDate;
  if (scope.credentials.sessionToken) toSign['x-amz-security-token'] = scope.credentials.sessionToken;

  const names = Object.keys(toSign).sort();
  const canonicalHeaders = names.map((name) => `${name}:${toSign[name].trim().replace(/\s+/g, ' ')}\n`).join('');
  const signedHeaders = names.join(';');
  const canonicalRequest = [
    request.method,
    request.path,
    canonicalQuery(request.query ?? ''),
    canonicalHeaders,
    signedHeaders,
    sha256Hex(request.body),
  ].join('\n');

  const credentialScope = `${dateStamp}/${scope.region}/${scope.service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, sha256Hex(canonicalRequest)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${scope.credentials.secretAccessKey}`, dateStamp), scope.region),
    scope.service), 'aws4_request');
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  return {
    ...toSign,
    authorization: `AWS4-HMAC-SHA256 Credential=${scope.credentials.accessKeyId}/${credentialScope}, `
      + `SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}
