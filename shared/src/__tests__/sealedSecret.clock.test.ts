/**
 * The KMS request is signed with the hypervisor's time, as the attestor keeps it (enclave review 2026-10-09, E1 F-9).
 *
 * The enclave's clock runs free (0.5-0.9 s a day) and the attestor corrects it by its gap to the NSM's signed time. The
 * SigV4 signature of the KMS call took the raw clock, and KMS refuses a signature more than 5 minutes off its own time:
 * an enclave that ran long enough got "Signature expired" on every sealed secret, while its attestations stayed right.
 *
 * MOCK BOUNDARY: as sealedSecret.test.ts - the vsock and TLS sockets and the NSM device (helpers/fakeEnclaveIo.ts), KMS
 * behind them (helpers/fakeKms.ts). The attestor, the signer and unsealSecret run for real. A file of its own: the
 * attestor keeps its gap for the life of the module, and the second test sets it, so the two run in this order.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';

vi.mock('@tytle-enclaves/native', async () => (await import('./helpers/fakeEnclaveIo.js')).nativeModule);
vi.mock('node:tls', async () => (await import('./helpers/fakeEnclaveIo.js')).tlsModule);

import { fakeIo } from './helpers/fakeEnclaveIo.js';
import { fakeKms } from './helpers/fakeKms.js';
import { attest } from '../attestor.js';
import { unsealSecret } from '../sealedSecret.js';
import type { AllowedHost } from '../types.js';

/** The time the fake NSM signs into every document (helpers/fakeNsm.ts) */
const SIGNED_MS = 1_760_000_000_000;
/** The enclave's clock: 7 minutes behind the hypervisor's, past KMS's 5 */
const ENCLAVE_CLOCK_MS = SIGNED_MS - 7 * 60_000;

const KMS_PORT = 8000;
const ALLOWLIST: AllowedHost[] = [{ hostname: 'kms.eu-central-1.amazonaws.com', vsockProxyPort: KMS_PORT }];
const CREDENTIALS = { accessKeyId: 'ASIAEXAMPLEEXAMPLE01', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' };

/** SigV4's X-Amz-Date of an instant: 20251009T085320Z */
const amzDate = (ms: number): string => new Date(ms).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');

/** The X-Amz-Date the KMS request of one unseal was signed with. */
async function signedAt(): Promise<string[]> {
  const kms = fakeKms({ sealed: 'sk_test_TESTONLY_clock' });
  fakeIo.reply(KMS_PORT, kms.reply);
  const ciphertext = crypto.randomBytes(32).toString('base64');
  expect(await unsealSecret(ciphertext, 'stripe_payment', CREDENTIALS, ALLOWLIST)).toBe('sk_test_TESTONLY_clock');
  return kms.requests[0].header('x-amz-date');
}

beforeEach(() => {
  fakeIo.reset();
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(ENCLAVE_CLOCK_MS);
});

afterEach(() => {
  vi.useRealTimers();
});

describe('the KMS request is signed with the hypervisor\'s time (E1 F-9)', () => {
  it('before any attestation, with the clock as it is: the first after a launch, when the clock is the host\'s (lock)', async () => {
    expect(await signedAt()).toEqual([amzDate(ENCLAVE_CLOCK_MS)]);
  });

  it('after an attestation, with the clock plus the gap it measured: 7 minutes behind is no longer 7 minutes off (red)', async () => {
    await attest('ec.europa.eu/x', 'POST', 'body', 'https://ec.europa.eu/x', {});
    expect(await signedAt()).toEqual([amzDate(SIGNED_MS)]);
  });
});
