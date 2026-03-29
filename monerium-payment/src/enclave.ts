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

import { startEnclave } from '@tytle-enclaves/shared';
import { createMoneriumPaymentHandler } from './moneriumPaymentHandler.js';

const MONERIUM_HOST = { hostname: 'api.monerium.app', vsockProxyPort: 8447 };
const RPC_HOST = { hostname: 'rpc.gnosischain.com', vsockProxyPort: 8448 };

startEnclave({
  name: 'monerium-payment',
  hosts: [MONERIUM_HOST, RPC_HOST],
  customHandler: createMoneriumPaymentHandler({
    moneriumHostname: MONERIUM_HOST.hostname,
    moneriumVsockPort: MONERIUM_HOST.vsockProxyPort,
    rpcHostname: RPC_HOST.hostname,
    rpcVsockPort: RPC_HOST.vsockProxyPort,
  }),
});
