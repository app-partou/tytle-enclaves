/**
 * Shared helpers for enclave handlers.
 *
 * DRY utilities for error responses and BN254 encode + attest pattern
 * that all three handlers (VIES, SICAE, Stripe) use identically.
 */

import { encodeFieldElements, hashFieldElements } from './bn254Codec.js';
import { attest } from './attestor.js';
import type { FieldDef } from './bn254Codec.js';
import type { AttestationDocument } from './attestor.js';
import type { EnclaveResponse } from './types.js';

// =============================================================================
// Error Response Helper
// =============================================================================

/**
 * Create a standard error EnclaveResponse.
 * Eliminates the repeated { success: false, status, headers: {}, rawBody: '', error } pattern.
 */
export function errorResponse(
  status: number,
  error: string,
  headers: Record<string, string> = {},
): EnclaveResponse {
  return { success: false, status, headers, rawBody: '', error };
}

// =============================================================================
// BN254 Encode + Attest Helper
// =============================================================================

export interface Bn254AttestResult {
  /** Base64-encoded BN254 field elements (also serves as rawBody) */
  rawBody: string;
  /** SHA-256 of the encoded field elements */
  bn254Hash: string;
  /** NSM attestation document with bn254Hash included */
  attestation: AttestationDocument & { bn254Hash: string };
}

/**
 * Encode values as BN254 field elements and create an NSM attestation.
 *
 * This is the core pattern shared by all handlers:
 * 1. Encode values → concatenated 32-byte field elements
 * 2. SHA-256 hash the encoding → bn254Hash
 * 3. Attest with bn254Hash as NSM user_data
 */
export async function encodeBn254AndAttest(
  schema: FieldDef[],
  values: Record<string, string | number | bigint | null>,
  attestArgs: {
    apiEndpoint: string;
    method: string;
    url: string;
    requestHeaders: Record<string, string>;
  },
): Promise<Bn254AttestResult> {
  const encodedBytes = encodeFieldElements(schema, values);
  const rawBody = encodedBytes.toString('base64');
  const bn254Hash = hashFieldElements(encodedBytes);

  const attestation = await attest(
    attestArgs.apiEndpoint,
    attestArgs.method,
    rawBody,
    attestArgs.url,
    attestArgs.requestHeaders,
    bn254Hash,
  );

  return {
    rawBody,
    bn254Hash,
    attestation: { ...attestation, bn254Hash },
  };
}
