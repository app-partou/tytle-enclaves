/**
 * Types for the verification CLI.
 * AttestationDocument is duplicated from shared/src/attestor.ts to keep this package standalone.
 */

export interface AttestationDocument {
  attestationId: string;
  responseHash: string;
  requestHash: string;
  apiEndpoint: string;
  apiMethod: string;
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
  passed: boolean;
  detail?: string;
}
