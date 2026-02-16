/**
 * VIES/HMRC VAT Validation Enclave
 *
 * Allowlist: ec.europa.eu (VIES SOAP) + api.service.hmrc.gov.uk (HMRC REST)
 *
 * This is the only VIES-specific file. All enclave infrastructure
 * (accept loop, TLS proxy, attestor, protocol) lives in @tytle-enclaves/shared.
 */

import { startEnclave } from '@tytle-enclaves/shared';

startEnclave({
  name: 'vies',
  hosts: [
    { hostname: 'ec.europa.eu', vsockProxyPort: 8443 },
    { hostname: 'api.service.hmrc.gov.uk', vsockProxyPort: 8444 },
  ],
});
