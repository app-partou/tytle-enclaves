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
    /** SHA-256 of BN254 field elements (included in NSM user_data) */
    bn254Hash?: string;
  };
  /** BN254 field elements as base64 (from custom handler encoding) */
  bn254?: string;
  /** Human-readable values for sha256 fields (from custom handler) */
  bn254Headers?: Record<string, string>;
}
