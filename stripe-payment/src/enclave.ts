/**
 * Stripe Payment Enclave
 *
 * Allowlist: api.stripe.com, and kms.eu-central-1.amazonaws.com to open a sealed API key (both HTTPS)
 *
 * Custom handler maps operation names to Stripe REST paths, makes the API call,
 * encodes key fields as BN254 field elements (6 x 32 = 192 bytes) before
 * attestation. Human-readable values passed via response headers.
 */

import { startEnclave, createHandler } from '@tytle-enclaves/shared';
import { stripePaymentHandlerDef, STRIPE_HOSTS } from './stripePaymentHandler.js';

startEnclave({
  name: 'stripe-payment',
  hosts: STRIPE_HOSTS,
  customHandler: createHandler(stripePaymentHandlerDef, STRIPE_HOSTS),
});
