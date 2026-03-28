/**
 * Decode and parse NSM attestation documents (COSE_Sign1 / CBOR).
 * Mirrors the decoding logic in shared/src/attestor.ts:137-178.
 */

import cbor from 'cbor';

// Maximum allowed size for a COSE_Sign1 document (1 MB).
// Real Nitro attestations are typically 3-5 KB.
const MAX_COSE_SIZE = 1_048_576;

export interface DecodedAttestation {
  /** Raw protected headers (CBOR-encoded bstr) — MUST be a Buffer per RFC 9052 */
  protectedRaw: Buffer;
  /** Decoded protected headers map */
  protectedHeaders: Map<number, unknown>;
  /** Raw payload bytes */
  payloadRaw: Buffer;
  /** Decoded payload */
  payload: NsmPayload;
  /** Raw signature bytes */
  signature: Buffer;
}

export interface NsmPayload {
  module_id: string;
  digest: string;
  timestamp: number;
  pcrs: Map<number, Buffer>;
  /** Leaf certificate (DER-encoded) */
  certificate: Buffer;
  /** CA bundle: array of DER-encoded certificates (leaf intermediates → root) */
  cabundle: Buffer[];
  /** Nonce included in NSM request (should match application nonce) */
  nonce: Buffer | null;
  user_data: Buffer | null;
  public_key: Buffer | null;
}

/**
 * Decode a Base64-encoded COSE_Sign1 NSM document into its components.
 */
export function decodeNsmDocument(nsmDocumentBase64: string): DecodedAttestation {
  const raw = Buffer.from(nsmDocumentBase64, 'base64');

  if (raw.length > MAX_COSE_SIZE) {
    throw new Error(
      `COSE_Sign1 document too large: ${raw.length} bytes (max ${MAX_COSE_SIZE})`,
    );
  }

  if (raw.length < 100) {
    throw new Error(
      `COSE_Sign1 document too small: ${raw.length} bytes. Not a valid attestation.`,
    );
  }

  return decodeCoseSign1(raw);
}

/**
 * Decode raw COSE_Sign1 bytes.
 */
export function decodeCoseSign1(coseBytes: Buffer): DecodedAttestation {
  const decoded = cbor.decodeFirstSync(coseBytes);

  // Handle CBOR Tag 18 (COSE_Sign1) — may be a Tagged object with .value
  const arr = decoded.value || decoded;

  if (!Array.isArray(arr) || arr.length < 4) {
    throw new Error(
      `Invalid COSE_Sign1 structure: expected array of 4, got ${Array.isArray(arr) ? arr.length : typeof arr}`,
    );
  }

  const [protectedRaw, _unprotected, payloadRaw, signature] = arr;

  // RFC 9052 §4.1: protected MUST be a byte string (bstr)
  if (!Buffer.isBuffer(protectedRaw)) {
    throw new Error(
      `Invalid COSE_Sign1: protected headers must be a byte string (bstr), got ${typeof protectedRaw}`,
    );
  }

  if (!Buffer.isBuffer(payloadRaw)) {
    throw new Error(
      `Invalid COSE_Sign1: payload must be a byte string (bstr), got ${typeof payloadRaw}`,
    );
  }

  if (!Buffer.isBuffer(signature)) {
    throw new Error(
      `Invalid COSE_Sign1: signature must be a byte string (bstr), got ${typeof signature}`,
    );
  }

  // Decode protected headers (CBOR-encoded bstr → map)
  // cbor library decodes integer-keyed CBOR maps as Map, string-keyed as objects.
  // Real Nitro attestations always have integer keys (per COSE spec), so we get Map.
  // For robustness, accept both and normalize to Map.
  let protectedHeaders: Map<number, unknown>;
  if (protectedRaw.length > 0) {
    const decoded = cbor.decodeFirstSync(protectedRaw);
    if (decoded instanceof Map) {
      protectedHeaders = decoded;
    } else if (decoded && typeof decoded === 'object' && !Array.isArray(decoded)) {
      protectedHeaders = new Map(
        Object.entries(decoded).map(([k, v]) => [Number(k), v]),
      );
    } else {
      throw new Error(
        `Invalid COSE_Sign1: decoded protected headers is ${typeof decoded}, expected Map or object`,
      );
    }
  } else {
    protectedHeaders = new Map();
  }

  // Decode payload (CBOR-encoded)
  const payload: NsmPayload = cbor.decodeFirstSync(payloadRaw);

  // Validate critical payload fields
  if (!payload.pcrs || (!(payload.pcrs instanceof Map) && typeof payload.pcrs !== 'object')) {
    throw new Error('NSM payload missing pcrs field');
  }

  if (!payload.certificate || !Buffer.isBuffer(payload.certificate)) {
    throw new Error('NSM payload missing certificate field');
  }

  if (!Array.isArray(payload.cabundle)) {
    throw new Error('NSM payload missing cabundle array');
  }

  return {
    protectedRaw: Buffer.from(protectedRaw),
    protectedHeaders,
    payloadRaw: Buffer.from(payloadRaw),
    payload,
    signature: Buffer.from(signature),
  };
}

/**
 * Extract PCR hex strings from a decoded attestation.
 * Throws if PCR0 is missing or empty (not a valid attestation without it).
 */
export function extractPcrs(decoded: DecodedAttestation): {
  pcr0: string;
  pcr1: string;
  pcr2: string;
} {
  const { pcrs } = decoded.payload;

  const getPcr = (idx: number): string => {
    if (pcrs instanceof Map) {
      const val = pcrs.get(idx);
      return val ? Buffer.from(val).toString('hex') : '';
    }
    const val = (pcrs as any)?.[idx];
    return val ? Buffer.from(val).toString('hex') : '';
  };

  const pcr0 = getPcr(0);
  if (!pcr0) {
    throw new Error('NSM payload pcrs map is missing PCR0 — not a valid Nitro attestation');
  }

  return {
    pcr0,
    pcr1: getPcr(1),
    pcr2: getPcr(2),
  };
}
