/**
 * VIES/HMRC VAT Validation Enclave
 *
 * Allowlist: ec.europa.eu (VIES SOAP), api.service.hmrc.gov.uk (HMRC REST)
 *
 * Uses a custom handler that routes GB to HMRC REST and all other EU
 * countries to VIES SOAP, outputting attested BN254 field elements (160 bytes).
 */

import { startEnclave, createHandler } from '@tytle-enclaves/shared';
import { viesHandlerDef, VIES_HOSTS } from './viesHandler.js';

startEnclave({
  name: 'vies',
  hosts: VIES_HOSTS,
  customHandler: createHandler(viesHandlerDef, VIES_HOSTS),
});
