/**
 * Types for the verification CLI.
 * AttestationDocument is duplicated from shared/src/attestor.ts to keep this package standalone.
 */

/**
 * What a check may rely on: the fields the NSM signs, itself (nsmDocument) or through the nonce (responseHash,
 * apiEndpoint, timestamp, challenge), and the bindings to them (nonce, bn254Hash). `attestationId`, `requestHash` and
 * `apiMethod` are NOT signed: the enclave mints the id and hashes the request, but neither enters the nonce or
 * user_data, so whoever hands over the JSON can write anything there. The CLI reports them as not signed, and never
 * requires them (enclave review 2026-10-09, E2b F-8).
 */
export interface AttestationDocument {
  /** Not signed. */
  attestationId?: string;
  responseHash: string;
  /** Not signed. */
  requestHash?: string;
  apiEndpoint: string;
  /** Not signed. */
  apiMethod?: string;
  timestamp: number;
  nsmDocument: string; // Base64 COSE_Sign1
  pcrs: {
    pcr0: string;
    pcr1: string;
    pcr2: string;
  };
  nonce: string;
  /** SHA-256 (hex) of the BN254 vector: the NSM document's user_data. */
  bn254Hash?: string;
  /** 1 = SHA-256(responseHash|apiEndpoint|timestamp); 2 = the same with `|challenge` appended. Absent = 1. */
  nonceVersion?: 1 | 2;
  /** The caller's challenge (64 lowercase hex), echoed: present exactly when nonceVersion is 2. */
  challenge?: string;
}

export interface Pcr0ServiceInfo {
  pcr0: string;
  gitCommit: string;
  repoUrl: string;
  buildDir: string;
  history: Array<{
    pcr0: string;
    gitCommit: string;
    environment: string;
    deployedAt: string;
  }>;
}

export interface Pcr0ApiResponse {
  enclaves: Record<string, Pcr0ServiceInfo>;
  verificationGuide: string;
}

export type ServiceName = 'vies' | 'sicae' | 'stripe-payment' | 'monerium-payment';

export const VALID_SERVICES: ServiceName[] = ['vies', 'sicae', 'stripe-payment', 'monerium-payment'];

/** Map service name to the key used in the API response and SSM (stripe-payment -> stripe_payment) */
export function apiKeyForService(service: ServiceName): string {
  return service.replace('-', '_');
}

export interface CheckResult {
  name: string;
  /** False for a check that failed, and for one that did not run (`skipped`). */
  passed: boolean;
  /** Set when the check did not run: what is therefore not verified, for the result line. Never a pass. */
  skipped?: string;
  detail?: string;
}
