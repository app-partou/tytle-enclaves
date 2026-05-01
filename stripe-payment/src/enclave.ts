/**
 * Stripe Payment Enclave
 *
 * Allowlist: api.stripe.com only (HTTPS)
 *
 * Custom handler maps operation names to Stripe REST paths, makes the API call,
 * encodes key fields as BN254 field elements (6 x 32 = 192 bytes) before
 * attestation. Human-readable values passed via response headers.
 */

import { startEnclave, createHandler } from '@tytle-enclaves/shared';
import { stripePaymentHandlerDef } from './stripePaymentHandler.js';

const hosts = [
  { hostname: 'api.stripe.com', vsockProxyPort: 8446 },
];

startEnclave({
  name: 'stripe-payment',
  hosts,
  customHandler: createHandler(stripePaymentHandlerDef, hosts),
});
