/** Enclave routing entry. */
export interface EnclaveRoute {
  /** Enclave CID (unique per enclave instance) */
  cid: number;
  /** vsock port the enclave listens on */
  port: number;
  /** Hostnames this enclave handles */
  hosts: string[];
}

/** Request forwarded to an enclave. */
export interface EnclaveRequest {
  id: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

/** Response from an enclave. */
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
