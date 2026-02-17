/**
 * SICAE Portuguese Business CAE Code Lookup Enclave
 *
 * Allowlist: www.sicae.pt (SICAE business activity codes)
 *
 * Uses a custom handler that performs multi-step HTTP + HTML parsing inside
 * the enclave, outputting attested BN254 field elements (192 bytes).
 *
 * NOTE: SICAE only supports HTTP (not HTTPS). The attestation proves which code
 * ran in the enclave, but without TLS the host could read/modify traffic.
 * Acceptable because SICAE data is public and requests contain only a NIF
 * (public business identifier). Results are cross-referenced against other sources.
 */

import { startEnclave } from '@tytle-enclaves/shared';
import { createSicaeHandler } from './sicaeHandler.js';

const SICAE_HOST = { hostname: 'www.sicae.pt', vsockProxyPort: 8445, tls: false as const };

startEnclave({
  name: 'sicae',
  hosts: [SICAE_HOST],
  customHandler: createSicaeHandler({ hostname: SICAE_HOST.hostname, vsockProxyPort: SICAE_HOST.vsockProxyPort }),
});
