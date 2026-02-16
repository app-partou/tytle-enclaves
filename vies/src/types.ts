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
  };
}

/** Allowlisted host entry with its vsock-proxy port. */
export interface AllowedHost {
  hostname: string;
  vsockProxyPort: number;
}
