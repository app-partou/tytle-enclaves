/**
 * VIES/HMRC VAT Validation Enclave
 *
 * Allowlist: ec.europa.eu (VIES SOAP), api.service.hmrc.gov.uk (HMRC REST)
 *
 * Uses a custom handler that routes GB to HMRC REST and all other EU
 * countries to VIES SOAP, outputting attested BN254 field elements (160 bytes).
 */

import { startEnclave, createHandler } from '@tytle-enclaves/shared';
import { viesHandlerDef } from './viesHandler.js';

const hosts = [
  { hostname: 'ec.europa.eu', vsockProxyPort: 8443 },
  { hostname: 'api.service.hmrc.gov.uk', vsockProxyPort: 8444 },
];

startEnclave({
  name: 'vies',
  hosts,
  customHandler: createHandler(viesHandlerDef, hosts),
});
