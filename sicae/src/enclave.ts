/**
 * SICAE Portuguese Business CAE Code Lookup Enclave
 *
 * Allowlist: www.sicae.pt (SICAE business activity codes)
 *
 * NOTE: SICAE only supports HTTP (not HTTPS). The attestation proves which code
 * ran in the enclave, but without TLS the host could read/modify traffic.
 * Acceptable because SICAE data is public and requests contain only a NIF
 * (public business identifier). Results are cross-referenced against other sources.
 */

import { startEnclave } from '@tytle-enclaves/shared';

startEnclave({
  name: 'sicae',
  hosts: [
    { hostname: 'www.sicae.pt', vsockProxyPort: 8445, tls: false },
  ],
});
