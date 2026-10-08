/**
 * COSE_Sign1 signature verification for AWS Nitro attestation documents.
 *
 * The Nitro NSM uses ES384 (ECDSA P-384 with SHA-384), COSE algorithm ID -35.
 * The COSE signature is in IEEE P1363 format (r||s, 96 bytes for P-384).
 *
 * SECURITY:
 * - Algorithm in protected headers is validated (prevents algorithm confusion)
 * - Buffer types are validated (prevents CBOR injection)
 * - Nonce and user_data from the COSE payload are extracted for binding verification
 * - The certificate chain is judged at the payload's signed time (the NSM timestamp), never at "now"
 */

import crypto from 'node:crypto';
import cbor from 'cbor';
import { decodeNsmDocument, extractPcrs } from './attestationDoc.js';
import { verifyCertificateChain } from './certChain.js';

// COSE algorithm ID for ES384 (ECDSA w/ SHA-384 on P-384)
const COSE_ALG_ES384 = -35;

export interface CoseVerificationResult {
  signatureValid: boolean;
  certChainValid: boolean;
  /** From the signed payload: the EIF's PCR0-2, and PCR8 - who signed the EIF ('' or zeroes: unsigned). */
  pcrs: { pcr0: string; pcr1: string; pcr2: string; pcr8: string };
  /** Nonce from the hardware-signed COSE payload (hex). Compare to application nonce. */
  payloadNonce: string | null;
  /** user_data from the hardware-signed COSE payload (hex): the SHA-256 of the BN254 vector. */
  payloadUserData: string | null;
  /** The payload's timestamp (ms since the epoch), stamped by the Nitro hypervisor: THE signing time. */
  payloadTimestampMs: number | null;
  /** Issuer / subject mismatches in the chain where the signatures hold: reported, never fatal. */
  chainWarnings: string[];
  error?: string;
}

/** The payload's signed time in ms: a positive whole number (a uint64; a bignum is read too), else null. */
function signedTimestampMs(raw: unknown): number | null {
  const ms = typeof raw === 'bigint' ? Number(raw) : raw;
  return typeof ms === 'number' && Number.isSafeInteger(ms) && ms > 0 ? ms : null;
}

const hexOrNull = (value: Buffer | null | undefined): string | null => (value ? Buffer.from(value).toString('hex') : null);

/**
 * Verify a COSE_Sign1 NSM attestation document:
 * 1. Decode the COSE_Sign1 structure
 * 2. Validate the algorithm is ES384 (prevents algorithm confusion attacks)
 * 3. Build the Sig_structure and verify the ES384 signature
 * 4. Verify the certificate chain to the AWS Nitro root CA
 * 5. Extract PCR values and nonce from the signed payload
 */
export function verifyCoseSignature(
  nsmDocumentBase64: string,
): CoseVerificationResult {
  const decoded = decodeNsmDocument(nsmDocumentBase64);

  // 1. Validate algorithm in protected headers (RFC 9052 §4.4)
  // This MUST happen before signature verification to prevent algorithm confusion.
  const alg = decoded.protectedHeaders.get(1); // COSE header key 1 = "alg"
  if (alg !== COSE_ALG_ES384) {
    return {
      signatureValid: false,
      certChainValid: false,
      pcrs: { pcr0: '', pcr1: '', pcr2: '', pcr8: '' },
      payloadNonce: null,
      payloadUserData: null,
      payloadTimestampMs: null,
      chainWarnings: [],
      error: `Invalid COSE algorithm: ${alg}. Expected ${COSE_ALG_ES384} (ES384). ` +
        'This may indicate an algorithm confusion attack.',
    };
  }

  // 2. Build the COSE Sig_structure for verification
  //    Sig_structure = ["Signature1", protectedHeaders, externalAad, payload]
  const sigStructure = [
    'Signature1',
    decoded.protectedRaw,
    Buffer.alloc(0), // external_aad is empty for Nitro attestations
    decoded.payloadRaw,
  ];

  const sigStructureEncoded = cbor.encodeOne(sigStructure);

  // 3. Extract leaf certificate from the payload and verify signature
  const leafCert = new crypto.X509Certificate(decoded.payload.certificate);

  const signatureValid = crypto.verify(
    'sha384',
    sigStructureEncoded,
    {
      key: leafCert.publicKey,
      dsaEncoding: 'ieee-p1363',
    },
    decoded.signature,
  );

  // 4. Verify the certificate chain at the signed time
  const payloadTimestampMs = signedTimestampMs(decoded.payload.timestamp);
  const chainResult = verifyCertificateChain(
    decoded.payload.certificate,
    decoded.payload.cabundle,
    new Date(payloadTimestampMs ?? Number.NaN),
  );

  // 5. Extract PCRs and the payload's nonce and user_data
  const pcrs = extractPcrs(decoded);
  const signed = {
    pcrs,
    payloadNonce: hexOrNull(decoded.payload.nonce),
    payloadUserData: hexOrNull(decoded.payload.user_data),
    payloadTimestampMs,
    chainWarnings: chainResult.warnings,
  };

  if (!signatureValid) {
    return {
      signatureValid: false,
      certChainValid: chainResult.valid,
      ...signed,
      error: 'COSE_Sign1 signature verification failed (ES384/P-384)',
    };
  }

  if (!chainResult.valid) {
    return {
      signatureValid: true,
      certChainValid: false,
      ...signed,
      error: chainResult.error,
    };
  }

  return {
    signatureValid: true,
    certChainValid: true,
    ...signed,
  };
}
