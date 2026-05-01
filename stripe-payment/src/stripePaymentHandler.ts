/**
 * Stripe Payment Handler Definition
 *
 * Maps operation names to Stripe REST endpoints, makes the API call via
 * vsock proxy, validates the response, and returns structured HandlerResult
 * for BN254 encoding + attestation by the factory.
 *
 * Request body (JSON):
 *   {
 *     "operation": "list_charges" | "list_customers" | "list_invoices" | "get_payment_intent" | "get_account" | "get_charge",
 *     "apiKey": "sk_...",
 *     "stripeAccount": "acct_..." (optional),
 *     "queryParams": { "limit": "100", "created[gte]": "..." } (optional),
 *     "resourceId": "pi_..." (optional, for get_* operations)
 *   }
 *
 * STRIPE_PAYMENT_SCHEMA:
 *   [0..31]    operation    shortString
 *   [32..63]   accountId    shortString
 *   [64..95]   objectType   shortString
 *   [96..127]  dataHash     sha256 (full JSON response)
 *   [128..159] totalCount   uint
 *   [160..191] hasMore      uint (1 = true, 0 = false)
 */

import crypto from 'node:crypto';
import { STRIPE_PAYMENT_SCHEMA } from '@tytle-enclaves/shared';
import type { HandlerDef, HandlerResult, HandlerContext } from '@tytle-enclaves/shared';
import { HANDLER_MANIFEST, MANIFEST_HASH } from './manifest.js';

// =============================================================================
// Types
// =============================================================================

type StripeOperation =
  | 'list_charges'
  | 'list_customers'
  | 'list_invoices'
  | 'get_payment_intent'
  | 'get_account'
  | 'get_charge';

interface StripeParams {
  operation: StripeOperation;
  apiKey: string;
  stripeAccount?: string;
  queryParams?: Record<string, string>;
  resourceId?: string;
}

// =============================================================================
// Constants
// =============================================================================

const OPERATION_PATH_MAP: Record<StripeOperation, string> = {
  list_charges: '/v1/charges',
  list_customers: '/v1/customers',
  list_invoices: '/v1/invoices',
  get_payment_intent: '/v1/payment_intents',
  get_account: '/v1/accounts',
  get_charge: '/v1/charges',
};

/** Expected Stripe `object` field for response validation */
const OPERATION_OBJECT_TYPE: Record<StripeOperation, string> = {
  list_charges: 'list',
  list_customers: 'list',
  list_invoices: 'list',
  get_payment_intent: 'payment_intent',
  get_account: 'account',
  get_charge: 'charge',
};

/** Operations that require a resourceId to fetch a single object */
const SINGLE_RESOURCE_OPS = new Set<string>(['get_payment_intent', 'get_account', 'get_charge']);

const VALID_OPERATIONS = new Set<string>(Object.keys(OPERATION_PATH_MAP));

const STRIPE_API_VERSION = '2025-12-15.clover';

// =============================================================================
// Handler Definition
// =============================================================================

export const stripePaymentHandlerDef: HandlerDef<StripeParams> = {
  name: 'stripe-payment',
  schema: STRIPE_PAYMENT_SCHEMA,
  manifestHash: MANIFEST_HASH,
  policies: HANDLER_MANIFEST.policies,
  requiredHosts: ['api.stripe.com'],

  parseParams(body: unknown): StripeParams {
    const b = body as Record<string, unknown>;
    const operation = b.operation as string | undefined;
    const apiKey = b.apiKey as string | undefined;
    const stripeAccount = b.stripeAccount as string | undefined;
    const queryParams = b.queryParams as Record<string, string> | undefined;
    const resourceId = b.resourceId as string | undefined;

    if (!operation || !VALID_OPERATIONS.has(operation)) {
      throw new Error(`Invalid operation: "${operation}". Supported: ${[...VALID_OPERATIONS].join(', ')}`);
    }

    if (!apiKey) {
      throw new Error('apiKey is required');
    }

    if (SINGLE_RESOURCE_OPS.has(operation) && !resourceId) {
      throw new Error(`${operation} requires resourceId`);
    }

    return {
      operation: operation as StripeOperation,
      apiKey,
      stripeAccount,
      queryParams,
      resourceId,
    };
  },

  async execute(params: StripeParams, ctx: HandlerContext): Promise<HandlerResult> {
    const { operation, apiKey, stripeAccount, queryParams, resourceId } = params;

    const stripeHost = ctx.hosts.find((h: { hostname: string }) => h.hostname === 'api.stripe.com')!;

    // Build Stripe REST path
    let path = OPERATION_PATH_MAP[operation];

    if (SINGLE_RESOURCE_OPS.has(operation) && resourceId) {
      path = `${path}/${encodeURIComponent(resourceId)}`;
    }

    if (queryParams && Object.keys(queryParams).length > 0) {
      const qs = new URLSearchParams(queryParams).toString();
      path = `${path}?${qs}`;
    }

    // Build headers (include Authorization - factory strips it for attestation via STRIP_AUTH policy)
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Stripe-Version': STRIPE_API_VERSION,
    };

    if (stripeAccount) {
      headers['Stripe-Account'] = stripeAccount;
    }

    // Make API call
    const apiEndpoint = `${stripeHost.hostname}${path.split('?')[0]}`;
    const response = await ctx.fetch(stripeHost, 'GET', path, headers);

    // Transient errors (rate limits, auth errors, server errors) - skip attestation.
    // 404 is NOT transient: "entity not found" is a valid definitive answer.
    if (response.status >= 400 && response.status !== 404) {
      ctx.log.warn('Stripe transient error, skipping attestation', { status: response.status, operation });
      return {
        values: {},
        apiEndpoint,
        method: 'GET',
        url: `https://${stripeHost.hostname}${path}`,
        requestHeaders: headers,
        responseHeaders: response.headers,
        rawPassthrough: {
          status: response.status,
          headers: response.headers,
          rawBody: response.body,
        },
      };
    }

    // 404 - resource not found. Attest with objectType='not_found'.
    if (response.status === 404) {
      const dataHash = crypto.createHash('sha256').update(response.body, 'utf8').digest('hex');

      return {
        values: {
          operation,
          accountId: stripeAccount || null,
          objectType: 'not_found',
          dataHash,
          totalCount: 0,
          hasMore: 0,
        },
        apiEndpoint,
        method: 'GET',
        url: `https://${stripeHost.hostname}${path}`,
        requestHeaders: headers,
        responseHeaders: {
          'x-stripe-operation': operation,
          'x-stripe-account-id': stripeAccount || '',
          'x-stripe-object-type': 'not_found',
          'x-stripe-data-hash': dataHash,
          'x-stripe-total-count': '0',
          'x-stripe-has-more': '0',
        },
        status: 404,
        bn254Headers: {
          'x-stripe-data-hash': dataHash,
        },
      };
    }

    // Parse and validate response
    let jsonData: Record<string, unknown>;
    try {
      jsonData = JSON.parse(response.body) as Record<string, unknown>;
    } catch {
      throw new Error('Stripe API returned invalid JSON');
    }

    const expectedType = OPERATION_OBJECT_TYPE[operation];
    if (jsonData.object !== expectedType) {
      throw new Error(`Unexpected Stripe object type: expected "${expectedType}", got "${String(jsonData.object)}"`);
    }

    // Compute attestation fields
    const dataHash = crypto.createHash('sha256').update(response.body, 'utf8').digest('hex');
    const isListOp = expectedType === 'list';
    const listData = jsonData.data as unknown[] | undefined;
    const totalCount = isListOp ? (listData?.length ?? 0) : 0;
    const hasMore = isListOp ? (jsonData.has_more ? 1 : 0) : 0;

    return {
      values: {
        operation,
        accountId: stripeAccount || null,
        objectType: String(jsonData.object),
        dataHash,
        totalCount,
        hasMore,
      },
      apiEndpoint,
      method: 'GET',
      url: `https://${stripeHost.hostname}${path}`,
      requestHeaders: headers,
      responseHeaders: {
        'x-stripe-operation': operation,
        'x-stripe-account-id': stripeAccount || '',
        'x-stripe-object-type': String(jsonData.object),
        'x-stripe-data-hash': dataHash,
        'x-stripe-total-count': String(totalCount),
        'x-stripe-has-more': String(hasMore),
      },
      bn254Headers: {
        'x-stripe-data-hash': dataHash,
      },
    };
  },
};
