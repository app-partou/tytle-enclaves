/**
 * NSM Attestor — creates Nitro Enclave attestation documents.
 *
 * Flow:
 * 1. CBOR-encode the NSM request: {"Attestation": {"nonce": <bytes>, "user_data": null, "public_key": null}}
 * 2. Send via ioctl to /dev/nsm (through native addon)
 * 3. Decode COSE_Sign1 response: [protected, unprotected, payload, signature]
 * 4. Extract PCR0-2 from payload.pcrs Map<number, Buffer>
 *
 * CBOR encoding/decoding is done in TypeScript (cbor npm) for auditability.
 * The Rust layer is just a thin ioctl wrapper.
 */

import crypto from 'node:crypto';
import cbor from 'cbor';
import { nsmRequest } from '@tytle-enclaves/native';

/**
 * A caller challenge: 32 bytes as 64 lowercase hex. The same rule as the verifier's CHALLENGE_PATTERN
 * (packages/attestation-core in the main repo), so a challenge the enclave signs is one it can check.
 */
export const CHALLENGE_PATTERN = /^[0-9a-f]{64}$/;

/** A challenge that is not 64 lowercase hex: refused before anything is fetched or signed. */
export class InvalidChallengeError extends Error {
  readonly code = 'INVALID_CHALLENGE' as const;
  constructor() {
    super('challenge must be 32 bytes of lowercase hex (64 characters)');
    this.name = 'InvalidChallengeError';
  }
}

/** Throws InvalidChallengeError unless `challenge` is absent or 64 lowercase hex. */
export function assertChallenge(challenge: unknown): asserts challenge is string | undefined {
  if (challenge !== undefined && (typeof challenge !== 'string' || !CHALLENGE_PATTERN.test(challenge))) {
    throw new InvalidChallengeError();
  }
}

export interface AttestOptions {
  /** Hex for NSM user_data (e.g., SHA-256 of the BN254 field elements). */
  userDataHex?: string;
  /** The caller's challenge (64 lowercase hex): mixed into the nonce as version 2. */
  challenge?: string;
}

export interface AttestationDocument {
  attestationId: string;
  responseHash: string;
  requestHash: string;
  apiEndpoint: string;
  apiMethod: string;
  /** Unix seconds, in the nonce: the hypervisor's time as the enclave last read it (see attestationTimeSec). */
  timestamp: number;
  nsmDocument: string; // Base64 COSE_Sign1
  pcrs: {
    pcr0: string;
    pcr1: string;
    pcr2: string;
  };
  nonce: string;
  /** 1 = SHA-256(responseHash|apiEndpoint|timestamp); 2 = the same with `|challenge` appended. */
  nonceVersion: 1 | 2;
  /** The caller's challenge, echoed; present exactly when nonceVersion is 2. */
  challenge?: string;
}

/**
 * The attestation time comes from the hypervisor, never from the enclave's own clock (P1.4 row "canonical
 * timestamp", audit §5.1 F1). An enclave has no NTP and no RTC: its Date.now() runs free from the host's time it
 * started with, 0.5-0.9 s a day in the field, and the verifiers refuse a document whose time is more than
 * 10 minutes from its signed one. The NSM payload's `timestamp` is stamped by the Nitro hypervisor and signed -
 * the time every verifier reads - but it exists only after the NSM call, and the nonce needs its time before.
 * So each attestation reads the signed time of its own document and keeps its gap to the enclave's clock, and
 * the next one signs the enclave's clock plus that gap. The first one after a launch signs the clock as it is.
 * Date.now() alone is diagnostic only: the pong carries it, and the parent reports its drift.
 */
let hypervisorGapMs = 0;

/** The time an attestation signs, in Unix seconds: the enclave's clock plus its last measured gap to the hypervisor. */
function attestationTimeSec(): number {
  return Math.floor((Date.now() + hypervisorGapMs) / 1000);
}

/**
 * Create an attestation for a proxied request/response.
 *
 * @param apiEndpoint - host + path of the API call
 * @param apiMethod - HTTP method
 * @param rawBody - Raw response body
 * @param url - Full request URL
 * @param requestHeaders - Request headers (for request hash)
 * @param options - `userDataHex` for NSM user_data; `challenge` (64 lowercase hex) for nonce version 2
 */
export async function attest(
  apiEndpoint: string,
  apiMethod: string,
  rawBody: string,
  url: string,
  requestHeaders: Record<string, string>,
  options: AttestOptions = {},
): Promise<AttestationDocument> {
  const { userDataHex, challenge } = options;
  // Before anything is signed: a malformed challenge is refused, never signed into a nonce.
  assertChallenge(challenge);

  const timestamp = attestationTimeSec();
  const attestationId = `enc-${crypto.randomUUID()}`;

  // Hash the response body
  const responseHash = crypto
    .createHash('sha256')
    .update(rawBody)
    .digest('hex');

  // Hash the request config
  const requestHash = crypto
    .createHash('sha256')
    .update(`${url}|${apiMethod}|${JSON.stringify(requestHeaders)}`)
    .digest('hex');

  // Compute nonce. Version 1: SHA-256(responseHash|apiEndpoint|timestamp). Version 2 appends the
  // caller's challenge, so the document answers THIS request (P1.3). Pipe delimiter prevents domain
  // collisions from field concatenation. The two preimages are written out in full: the main repo's
  // nonceFormula.drift.test.ts reads them as text and holds them to the verifier's nsmNonceOf.
  const nonceVersion: 1 | 2 = challenge === undefined ? 1 : 2;
  const nonceHash = crypto.createHash('sha256');
  if (challenge === undefined) {
    nonceHash.update(`${responseHash}|${apiEndpoint}|${timestamp}`);
  } else {
    nonceHash.update(`${responseHash}|${apiEndpoint}|${timestamp}|${challenge}`);
  }
  const nonce = nonceHash.digest('hex');

  // Request NSM attestation with the nonce and optional user_data
  const { nsmDocument, pcrs, signedAtMs, answeredAtMs } = await requestNsmAttestation(nonce, userDataHex);
  // This document's signed time sets the gap for the next attestation.
  hypervisorGapMs = signedAtMs - answeredAtMs;

  return {
    attestationId,
    responseHash,
    requestHash,
    apiEndpoint,
    apiMethod,
    timestamp,
    nsmDocument,
    pcrs,
    nonce,
    nonceVersion,
    ...(challenge === undefined ? {} : { challenge }),
  };
}

/**
 * An attestation document whose public_key is `publicKeyDer` (an SPKI DER key) and that carries nothing else: the
 * Recipient of a KMS Decrypt (sealedSecret.ts, enclave audit P1.7). KMS encrypts its answer to that key, and the key
 * policy accepts only a document of an enclave image it names. The data attestations (attest) keep public_key null:
 * their nonce, user_data and verifiers are untouched by this one.
 */
export function recipientAttestation(publicKeyDer: Buffer): Buffer {
  const request = cbor.encode({ Attestation: { nonce: null, user_data: null, public_key: publicKeyDer } });
  const envelope = cbor.decodeFirstSync(nsmRequest(Buffer.from(request)));
  const documentBytes = envelope.Attestation?.document;
  if (!documentBytes) {
    throw new Error('NSM response missing Attestation.document');
  }
  return Buffer.from(documentBytes);
}

/**
 * Request an NSM attestation document from /dev/nsm.
 *
 * @param nonceHex - Hex-encoded nonce to include in attestation
 * @param userDataHex - Optional hex-encoded user_data (e.g., SHA-256 of BN254 field elements)
 * @returns Base64 NSM document, its PCR values, its signed time, and the enclave's clock when the NSM answered
 */
async function requestNsmAttestation(nonceHex: string, userDataHex?: string): Promise<{
  nsmDocument: string;
  pcrs: { pcr0: string; pcr1: string; pcr2: string };
  /** The payload's `timestamp`: milliseconds, stamped by the hypervisor and signed. */
  signedAtMs: number;
  /** The enclave's own clock right after the NSM answered, before anything is decoded. */
  answeredAtMs: number;
}> {
  // CBOR encode the NSM request
  const request = cbor.encode({
    Attestation: {
      nonce: Buffer.from(nonceHex, 'hex'),
      user_data: userDataHex ? Buffer.from(userDataHex, 'hex') : null,
      public_key: null,
    },
  });

  // Call native ioctl
  const responseBytes = nsmRequest(Buffer.from(request));
  const answeredAtMs = Date.now();

  // Decode the outer CBOR response envelope: {"Attestation": {"document": <bytes>}}
  const envelope = cbor.decodeFirstSync(responseBytes);
  const documentBytes = envelope.Attestation?.document;

  if (!documentBytes) {
    throw new Error('NSM response missing Attestation.document');
  }

  // The document is a COSE_Sign1 structure: [protected, unprotected, payload, signature]
  // We return the full COSE_Sign1 as base64 (verifiers will decode it themselves)
  const nsmDocument = Buffer.from(documentBytes).toString('base64');

  // One decode of the signed payload: its PCRs, and its time.
  let payload: SignedPayload;
  try {
    payload = payloadOf(documentBytes);
  } catch (err: unknown) {
    throw new Error(`Failed to extract PCRs from COSE_Sign1 document: ${err instanceof Error ? err.message : String(err)}`);
  }

  return { nsmDocument, pcrs: pcrsOf(payload), signedAtMs: signedTimestampOf(payload), answeredAtMs };
}

/** The payload fields this enclave reads from its own document. */
interface SignedPayload {
  pcrs?: Map<number, Uint8Array> | Record<number, Uint8Array>;
  timestamp?: unknown;
}

/**
 * The payload of a COSE_Sign1 document.
 *
 * COSE_Sign1 structure: CBOR Tag 18 → [protected_headers, unprotected_headers, payload, signature]
 * Payload is CBOR-encoded and contains: { pcrs: Map<number, Buffer>, timestamp, ... }
 */
function payloadOf(coseSign1Bytes: Buffer): SignedPayload {
  // Decode COSE_Sign1 array
  const coseArray = cbor.decodeFirstSync(coseSign1Bytes);
  // coseArray is [protected, unprotected, payload, signature]
  // For tagged CBOR, it may be a Tagged object
  const arr = coseArray.value || coseArray;

  if (!Array.isArray(arr) || arr.length < 4) {
    throw new Error('Invalid COSE_Sign1 structure');
  }

  // Payload is at index 2
  return cbor.decodeFirstSync(arr[2]) as SignedPayload;
}

/**
 * The payload's `timestamp`: milliseconds since the epoch (a uint64), stamped by the hypervisor. A document
 * without a valid one is refused here, as every verifier refuses it (attestation-core nsmVerification step 4).
 */
function signedTimestampOf(payload: SignedPayload): number {
  const raw = payload.timestamp;
  const ms = typeof raw === 'bigint' ? Number(raw) : raw;
  if (typeof ms !== 'number' || !Number.isSafeInteger(ms) || ms <= 0) {
    throw new Error('NSM document has no valid signed timestamp');
  }
  return ms;
}

/** PCR0-2 of the payload, as hex ('' for one it lacks). PCRs are a Map<number, Buffer> in the payload. */
function pcrsOf(payload: SignedPayload): { pcr0: string; pcr1: string; pcr2: string } {
  const pcrsMap = payload.pcrs;
  const getPcr = (idx: number): string => {
    if (pcrsMap instanceof Map) {
      const val = pcrsMap.get(idx);
      return val ? Buffer.from(val).toString('hex') : '';
    }
    // Object fallback
    const val = pcrsMap?.[idx];
    return val ? Buffer.from(val).toString('hex') : '';
  };

  return {
    pcr0: getPcr(0),
    pcr1: getPcr(1),
    pcr2: getPcr(2),
  };
}
