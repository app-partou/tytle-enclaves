/**
 * Stripe Payment Enclave
 *
 * Allowlist: api.stripe.com only (HTTPS)
 *
 * Custom handler maps operation names to Stripe REST paths, makes the API call,
 * encodes key fields as BN254 field elements (6 x 32 = 192 bytes) before
 * attestation. Human-readable values passed via response headers.
 */

import { startEnclave } from '@tytle-enclaves/shared';
import { createStripePaymentHandler } from './stripePaymentHandler.js';

const STRIPE_HOST = { hostname: 'api.stripe.com', vsockProxyPort: 8446 };

startEnclave({
  name: 'stripe-payment',
  hosts: [STRIPE_HOST],
  customHandler: createStripePaymentHandler({
    hostname: STRIPE_HOST.hostname,
    vsockPort: STRIPE_HOST.vsockProxyPort,
  }),
});
