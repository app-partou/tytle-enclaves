export { startEnclave } from './createEnclave.js';
export { createRequestHandler } from './requestHandler.js';
export { proxyFetch } from './httpProxy.js';
export { attest } from './attestor.js';
export type { EnclaveConfig, AllowedHost, EnclaveRequest, EnclaveResponse } from './types.js';
export type { AttestationDocument } from './attestor.js';
export type { HttpResponse } from './httpProxy.js';
