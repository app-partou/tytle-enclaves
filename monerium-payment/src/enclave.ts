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
import { moneriumPaymentHandlerDef, MONERIUM_HOSTS } from './moneriumPaymentHandler.js';

startEnclave({
  name: 'monerium-payment',
  hosts: MONERIUM_HOSTS,
  customHandler: createHandler(moneriumPaymentHandlerDef, MONERIUM_HOSTS),
});
