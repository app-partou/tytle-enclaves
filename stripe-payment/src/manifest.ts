/**
 * Stripe Payment Handler Manifest
 */

import {
  computeManifestHash, validateManifest, STRIPE_PAYMENT_SCHEMA,
  SKIP_TRANSIENT_ERRORS, ATTEST_NOT_FOUND, STRIP_AUTH, REDACT_BEARER,
} from '@tytle-enclaves/shared';
import type { HandlerManifest } from '@tytle-enclaves/shared';

export const HANDLER_MANIFEST: HandlerManifest = {
  version: '1.1.0',

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
    {
      id: 'stripe_account_format',
      check: { type: 'field_matches', path: 'stripeAccount', pattern: '^acct_[0-9A-Za-z]+$' },
      reason: 'The Stripe-Account header carries a Stripe account id; any other value is refused before the fetch',
    },
    {
      id: 'account_is_the_one_asked',
      check: { type: 'behavioral', description: 'accountId is the Stripe-Account the request named (null when it named none). Stripe refuses a Stripe-Account the API key cannot act as (error code account_invalid): that 4xx is never signed. When the answer names an account in its own Stripe-Account header, it must be the one asked, else the answer is an error' },
      reason: 'The signed account is the one Stripe acted as, never a value the caller only claimed',
    },
    {
      id: 'single_object_is_the_one_asked',
      check: { type: 'behavioral', description: 'get_payment_intent, get_account and get_charge: the answer\'s id must be the resourceId asked, else the answer is an error' },
      reason: 'A signed object is the object the request asked for',
    },
    {
      id: 'list_shape',
      check: { type: 'behavioral', description: 'A list answer must carry its data array and has_more (boolean): totalCount and hasMore are read from them; otherwise the answer is an error' },
      reason: 'A list the handler cannot read is never signed as an empty one',
    },
    {
      id: 'not_found_is_stripes_own',
      check: { type: 'behavioral', description: 'A 404 is signed (objectType not_found) only when its body is Stripe\'s error object with code resource_missing; any other 404 is an error' },
      reason: 'A path Stripe does not know, or a proxy\'s page, is not Stripe saying the object does not exist',
    },
    {
      id: 'body_beside_the_answer',
      check: { type: 'behavioral', description: 'The signed answer carries Stripe\'s body beside it (upstreamBody, not signed); its SHA-256 is the signed dataHash' },
      reason: 'A reader uses the body as attested data only when it matches the signed dataHash',
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
