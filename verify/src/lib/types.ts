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
  bn254Hash?: string;
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

export type ServiceName = 'vies' | 'sicae' | 'stripe-payment';

export const VALID_SERVICES: ServiceName[] = ['vies', 'sicae', 'stripe-payment'];

/** Map service name to the key used in the API response (stripe-payment -> stripe_payment) */
export function apiKeyForService(service: ServiceName): string {
  return service.replace('-', '_');
}

export interface CheckResult {
  name: string;
  passed: boolean;
  detail?: string;
}
