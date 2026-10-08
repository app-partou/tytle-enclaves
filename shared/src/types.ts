import type { AwsCredentials } from './sigv4.js';

/** Allowlisted host entry with its vsock-proxy port. */
export interface AllowedHost {
  hostname: string;
  vsockProxyPort: number;
  /** Whether to use TLS (default: true). Set to false for HTTP-only hosts. */
  tls?: boolean;
}

/** Configuration for a specific enclave service. */
export interface EnclaveConfig {
  /** Short name for logging (e.g., 'vies', 'sicae', 'stripe') */
  name: string;
  /** Hosts this enclave is allowed to call. Baked into the image → reflected in PCR0. */
  hosts: AllowedHost[];
  /** Override the generic proxy handler with a custom request handler. */
  customHandler?: (request: EnclaveRequest) => Promise<EnclaveResponse>;
}

/** Request from parent server to enclave via vsock. */
export interface EnclaveRequest {
  id: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  /**
   * 32 random bytes as 64 lowercase hex, minted by the caller (data-bridge) for this one request.
   * Mixed into the NSM nonce (nonce version 2), so the signed document answers THIS request and no other.
   */
  challenge?: string;
  /**
   * The host role's temporary AWS credentials, which the parent adds (from IMDSv2) for an enclave that opens sealed
   * secrets (sealedSecret.ts, enclave audit P1.7): they sign the KMS Decrypt and nothing else. Never logged.
   */
  awsCredentials?: AwsCredentials;
}

/** Response from enclave to parent server via vsock. */
export interface EnclaveResponse {
  success: boolean;
  status: number;
  headers: Record<string, string>;
  rawBody: string;
  error?: string;
  attestation?: {
    attestationId: string;
    responseHash: string;
    requestHash: string;
    apiEndpoint: string;
    apiMethod: string;
    timestamp: number;
    nsmDocument: string;
    pcrs: {
      pcr0: string;
      pcr1: string;
      pcr2: string;
    };
    nonce: string;
    /** 1 = SHA-256(responseHash|apiEndpoint|timestamp); 2 = SHA-256(responseHash|apiEndpoint|timestamp|challenge). */
    nonceVersion: 1 | 2;
    /** The caller's challenge, echoed; present exactly when nonceVersion is 2. */
    challenge?: string;
    /** SHA-256 of BN254 field elements (included in NSM user_data) */
    bn254Hash?: string;
  };
  /** BN254 field elements as base64 (from custom handler encoding) */
  bn254?: string;
  /** Human-readable values for sha256 fields (from custom handler) */
  bn254Headers?: Record<string, string>;
  /**
   * The upstream body the signed dataHash commits to, when the handler's data is that body (Stripe's JSON). Not signed:
   * a reader uses it only when its SHA-256 is the vector's dataHash.
   */
  upstreamBody?: string;
}
