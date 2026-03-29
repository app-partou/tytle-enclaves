/**
 * Stripe Payment Handler Manifest
 */

import {
  computeManifestHash, validateManifest, STRIPE_PAYMENT_SCHEMA,
  SKIP_TRANSIENT_ERRORS, ATTEST_NOT_FOUND, STRIP_AUTH, REDACT_BEARER,
} from '@tytle-enclaves/shared';
import type { HandlerManifest } from '@tytle-enclaves/shared';

export const HANDLER_MANIFEST: HandlerManifest = {
  version: '1.0.0',

  queries: [
    {
      id: 'stripe_api',
      description: 'Stripe REST API (list or single-resource operations)',
      method: 'GET',
      host: 'api.stripe.com',
      path: '/v1/{resource}/{resourceId?}',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Stripe-Version': '2025-12-15.clover',
      },
      auth: {
        header: 'Authorization',
        scheme: 'Bearer',
        strippedBeforeAttestation: true,
      },
    },
  ],

  schema: {
    name: 'STRIPE_PAYMENT_SCHEMA',
    outputBytes: 192,
    fields: [
      { name: 'operation',  encoding: 'shortString', source: { from: 'request', param: 'operation' } },
      { name: 'accountId',  encoding: 'shortString', source: { from: 'request', param: 'stripeAccount' } },
      { name: 'objectType', encoding: 'shortString', source: { from: 'response', query: 'stripe_api', path: 'object' } },
      { name: 'dataHash',   encoding: 'sha256',      source: { from: 'derived', inputs: ['stripe_api:rawBody'], join: '', transform: 'sha256' } },
      { name: 'totalCount', encoding: 'uint',         source: { from: 'response', query: 'stripe_api', path: 'data.length', transform: 'array_length' } },
      { name: 'hasMore',    encoding: 'uint',         source: { from: 'response', query: 'stripe_api', path: 'has_more', transform: 'boolean_uint' } },
    ],
  },

  policies: [
    SKIP_TRANSIENT_ERRORS,
    ATTEST_NOT_FOUND,
    STRIP_AUTH,
    REDACT_BEARER,
    {
      id: 'valid_operations',
      check: { type: 'field_required', paths: ['operation'] },
      reason: 'Operation must be one of: list_charges, list_customers, list_invoices, get_payment_intent, get_account, get_charge',
    },
    {
      id: 'api_key_required',
      check: { type: 'field_required', paths: ['apiKey'] },
      reason: 'Stripe API key is required for authentication',
    },
    {
      id: 'resource_id_for_get_ops',
      check: { type: 'behavioral', description: 'Single-resource operations (get_payment_intent, get_account, get_charge) require resourceId' },
      reason: 'Conditional requirement depends on which operation is used',
    },
    {
      id: 'object_type_validation',
      check: { type: 'field_matches', path: 'object', pattern: '^(list|payment_intent|account|charge)$' },
      reason: 'Response object type must match expected type for the requested operation',
    },
  ],

  repeatability: {
    hashAlgorithm: 'sha256',
    dataHashInput: 'stripe_api:rawBody',
    outputFormat: 'BN254 big-endian, 6 × 32 bytes, base64',
    deterministic: true,
  },
};

validateManifest(HANDLER_MANIFEST, STRIPE_PAYMENT_SCHEMA);

export const MANIFEST_HASH = computeManifestHash(HANDLER_MANIFEST);
