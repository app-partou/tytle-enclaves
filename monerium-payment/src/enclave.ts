/**
 * Monerium Payment Enclave
 *
 * Allowlist: api.monerium.app (HTTPS) + rpc.gnosischain.com (HTTPS)
 *
 * Custom handler fetches a Monerium order and the on-chain EURe balance
 * of the order's address, encodes key fields as BN254 field elements
 * (6 x 32 = 192 bytes) before attestation. Human-readable values passed
 * via response headers.
 */

import { startEnclave, createHandler } from '@tytle-enclaves/shared';
import { moneriumPaymentHandlerDef } from './moneriumPaymentHandler.js';

const hosts = [
  { hostname: 'api.monerium.app', vsockProxyPort: 8447 },
  { hostname: 'rpc.gnosischain.com', vsockProxyPort: 8448 },
];

startEnclave({
  name: 'monerium-payment',
  hosts,
  customHandler: createHandler(moneriumPaymentHandlerDef, hosts),
});
