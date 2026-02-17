/**
 * VIES/HMRC VAT Validation Enclave
 *
 * Allowlist: ec.europa.eu (VIES SOAP) + api.service.hmrc.gov.uk (HMRC REST)
 *
 * Custom handler parses SOAP/JSON responses and encodes results as BN254
 * field elements (5 x 32 = 160 bytes) before attestation. Human-readable
 * values passed via response headers.
 */

import { startEnclave } from '@tytle-enclaves/shared';
import { createViesHandler } from './viesHandler.js';

const VIES_HOST = { hostname: 'ec.europa.eu', vsockProxyPort: 8443 };
const HMRC_HOST = { hostname: 'api.service.hmrc.gov.uk', vsockProxyPort: 8444 };

startEnclave({
  name: 'vies',
  hosts: [VIES_HOST, HMRC_HOST],
  customHandler: createViesHandler({
    viesHostname: VIES_HOST.hostname,
    viesVsockPort: VIES_HOST.vsockProxyPort,
    hmrcHostname: HMRC_HOST.hostname,
    hmrcVsockPort: HMRC_HOST.vsockProxyPort,
  }),
});
