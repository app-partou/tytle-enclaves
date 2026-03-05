export { startEnclave } from './createEnclave.js';
export { createRequestHandler } from './requestHandler.js';
export { proxyFetch, proxyFetchPlain } from './httpProxy.js';
export { attest } from './attestor.js';
export {
  encodeFieldElements,
  hashFieldElements,
  schemaByteLength,
  bigintToBytes32,
  BN254_MODULUS,
  SICAE_SCHEMA,
  VIES_SCHEMA,
  STRIPE_PAYMENT_SCHEMA,
} from './bn254Codec.js';
export { errorResponse, encodeBn254AndAttest } from './enclaveHelpers.js';
export type { EnclaveConfig, AllowedHost, EnclaveRequest, EnclaveResponse } from './types.js';
export type { AttestationDocument } from './attestor.js';
export type { Bn254AttestResult } from './enclaveHelpers.js';
export type { HttpResponse } from './httpProxy.js';
export type { FieldDef, FieldEncoding } from './bn254Codec.js';
