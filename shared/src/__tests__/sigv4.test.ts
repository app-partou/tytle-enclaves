/**
 * The enclave's SigV4 signer (sigv4.ts, enclave audit P1.7) against values it did not compute: AWS's own worked example
 * (IAM user guide, "Signature Version 4 example": GET ListUsers on 2015-08-30), and the AWS SDK's signer
 * (@smithy/signature-v4 5.3.8, run once on 2026-10-08 from the main repo's ai-agent-server; it also agreed with this
 * signer on 200 random KMS Decrypt requests). Nothing is mocked: the signer is a pure function.
 *
 * Labels: "red" = fails on the release before this one (it had no signer).
 */
import { describe, it, expect } from 'vitest';
import { signRequest } from '../sigv4.js';

const KMS = 'kms.eu-central-1.amazonaws.com';

describe('AWS\'s worked example (red)', () => {
  it('signs GET ListUsers exactly as the IAM user guide does', () => {
    const headers = signRequest(
      {
        method: 'GET', host: 'iam.amazonaws.com', path: '/', query: 'Action=ListUsers&Version=2010-05-08',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' }, body: '',
      },
      { service: 'iam', region: 'us-east-1', credentials: { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' }, now: new Date('2015-08-30T12:36:00Z') },
    );
    expect(headers.authorization).toBe('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, '
      + 'SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7');
    expect(headers['x-amz-date']).toBe('20150830T123600Z');
    expect(headers.host).toBe('iam.amazonaws.com');
    expect(headers).not.toHaveProperty('x-amz-security-token');
  });
});

describe('the KMS Decrypt request, as the AWS SDK signs it (red)', () => {
  const credentials = {
    accessKeyId: 'ASIAEXAMPLEEXAMPLE01',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    sessionToken: 'IQoJb3JpZ2luX2VjEXAMPLETOKEN//////////wEaDGV1LWNlbnRyYWwtMSJHMEUCIQ==',
  };
  const body = '{"CiphertextBlob":"AQIDBA==","EncryptionContext":{"enclave":"stripe_payment"},"Recipient":{"AttestationDocument":"hEQ=","KeyEncryptionAlgorithm":"RSAES_OAEP_SHA_256"}}';
  const sign = (headers: Record<string, string>) => signRequest(
    { method: 'POST', host: KMS, path: '/', headers, body },
    { service: 'kms', region: 'eu-central-1', credentials, now: new Date('2026-10-08T12:00:00Z') },
  );
  const SDK_AUTHORIZATION = 'AWS4-HMAC-SHA256 Credential=ASIAEXAMPLEEXAMPLE01/20261008/eu-central-1/kms/aws4_request, '
    + 'SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, '
    + 'Signature=9fbf082669c16152279a6f4f0414764a3e449efc7a729931bbcfeede6f91479c';

  it('signs the session token with the request and sends it', () => {
    const headers = sign({ 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'TrentService.Decrypt' });
    expect(headers.authorization).toBe(SDK_AUTHORIZATION);
    expect(headers['x-amz-security-token']).toBe(credentials.sessionToken);
    expect(headers['x-amz-date']).toBe('20261008T120000Z');
  });

  it('reads header names in any case: the signature is the same', () => {
    expect(sign({ 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': 'TrentService.Decrypt' }).authorization).toBe(SDK_AUTHORIZATION);
  });

  it('signs every header it returns, and returns only lowercase names', () => {
    const headers = sign({ 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': 'TrentService.Decrypt' });
    const signed = /SignedHeaders=([^,]+),/.exec(headers.authorization)![1].split(';');
    expect(Object.keys(headers).filter((name) => name !== 'authorization').sort()).toEqual(signed);
  });

  it('changes the signature when the body changes by one character', () => {
    const other = signRequest(
      { method: 'POST', host: KMS, path: '/', headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'TrentService.Decrypt' }, body: body.replace('AQIDBA==', 'AQIDBQ==') },
      { service: 'kms', region: 'eu-central-1', credentials, now: new Date('2026-10-08T12:00:00Z') },
    );
    expect(other.authorization).not.toBe(SDK_AUTHORIZATION);
  });
});

describe('canonical form, as the AWS SDK signs it (red)', () => {
  it('sorts and re-encodes the query, collapses header whitespace, drops milliseconds, and signs no token without one', () => {
    const headers = signRequest(
      {
        method: 'GET', host: KMS, path: '/',
        // out of order, and with characters encodeURIComponent leaves alone but SigV4 encodes: * ( ) ! '
        query: 'Zeta=last&Alpha=a%20b%2Ac~%28x%29%21&Beta-Key=it%27s',
        headers: { 'X-Custom': '  one   two  three ' }, body: '',
      },
      { service: 'kms', region: 'eu-central-1', credentials: { accessKeyId: 'AKIAEXAMPLEEXAMPLE02', secretAccessKey: 'je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY' }, now: new Date('2026-10-08T12:00:00.789Z') },
    );
    expect(headers.authorization).toBe('AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEEXAMPLE02/20261008/eu-central-1/kms/aws4_request, '
      + 'SignedHeaders=host;x-amz-date;x-custom, Signature=bff6c9a5871ae48b01cb95724136b97e10cf4ca2fcada96e098c1d56d5b114f6');
    expect(headers['x-amz-date']).toBe('20261008T120000Z');
    expect(headers).not.toHaveProperty('x-amz-security-token');
  });
});
