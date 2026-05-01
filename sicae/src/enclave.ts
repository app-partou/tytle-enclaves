/**
 * SICAE Portuguese Business CAE Code Lookup Enclave
 *
 * Allowlist: www.sicae.pt (SICAE business activity codes)
 *
 * Uses a custom handler that performs multi-step HTTP + HTML parsing inside
 * the enclave, outputting attested BN254 field elements (192 bytes).
 *
 * TRUST MODEL (no TLS): www.sicae.pt only serves HTTP, not HTTPS. This is a
 * Portuguese government infrastructure limitation. Without TLS, the host's
 * vsock-proxy sees plaintext traffic and could modify responses before the
 * enclave processes them. The NSM attestation still proves:
 *   - Which code ran (PCR0 binds the image hash)
 *   - Which host was contacted (hostname in allowlist, verified at proxy level)
 * But it CANNOT prove the response was not tampered by the host OS.
 *
 * This is acceptable because:
 *   1. SICAE data is public (NIF is a public business identifier)
 *   2. Impact is limited to data integrity, not confidentiality
 *   3. Results are cross-referenced against other sources (AT Portal, VIES)
 *
 * Consumers should check the AllowedHost.tls field to make informed trust
 * decisions about attestation strength.
 */

import { startEnclave, createHandler } from '@tytle-enclaves/shared';
import { sicaeHandlerDef } from './sicaeHandler.js';

const hosts = [
  { hostname: 'www.sicae.pt', vsockProxyPort: 8445, tls: false as const },
];

startEnclave({
  name: 'sicae',
  hosts,
  customHandler: createHandler(sicaeHandlerDef, hosts),
});
