/**
 * Stripe Payment Custom Handler
 *
 * Maps operation names to Stripe REST endpoints, makes the API call via
 * vsock proxy, validates the response, encodes as BN254 field elements,
 * and attests the encoded output.
 *
 * Request body (JSON):
 *   {
 *     "operation": "list_charges" | "list_customers" | "list_invoices" | "get_payment_intent" | "get_account",
 *     "apiKey": "sk_...",
 *     "stripeAccount": "acct_..." (optional),
 *     "queryParams": { "limit": "100", "created[gte]": "..." } (optional),
 *     "resourceId": "pi_..." (optional, for get_* operations)
 *   }
 *
 * Response: BN254-encoded field elements (6 x 32 = 192 bytes, base64)
 *           + human-readable headers (x-stripe-*)
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
import { proxyFetch, attest, encodeFieldElements, STRIPE_PAYMENT_SCHEMA } from '@tytle-enclaves/shared';
import type { EnclaveRequest, EnclaveResponse } from '@tytle-enclaves/shared';

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
// Custom Handler
// =============================================================================

interface StripePaymentHandlerConfig {
  hostname: string;
  vsockPort: number;
}

export function createStripePaymentHandler(cfg: StripePaymentHandlerConfig) {
  return async (request: EnclaveRequest): Promise<EnclaveResponse> => {
    try {
      // 1. Parse + validate request
      let operation: StripeOperation;
      let apiKey: string;
      let stripeAccount: string | undefined;
      let queryParams: Record<string, string> | undefined;
      let resourceId: string | undefined;

      try {
        const body = JSON.parse(request.body || '{}');
        operation = body.operation;
        apiKey = body.apiKey;
        stripeAccount = body.stripeAccount;
        queryParams = body.queryParams;
        resourceId = body.resourceId;
      } catch {
        return {
          success: false,
          status: 400,
          headers: {},
          rawBody: '',
          error: 'Invalid request body — expected JSON with { operation, apiKey }',
        };
      }

      if (!operation || !VALID_OPERATIONS.has(operation)) {
        return {
          success: false,
          status: 400,
          headers: {},
          rawBody: '',
          error: `Invalid operation: "${operation}". Supported: ${[...VALID_OPERATIONS].join(', ')}`,
        };
      }

      if (!apiKey) {
        return {
          success: false,
          status: 400,
          headers: {},
          rawBody: '',
          error: 'apiKey is required',
        };
      }

      // Validate single-resource operations require resourceId
      if (SINGLE_RESOURCE_OPS.has(operation) && !resourceId) {
        return {
          success: false,
          status: 400,
          headers: {},
          rawBody: '',
          error: `${operation} requires resourceId`,
        };
      }

      // 2. Build Stripe REST path
      let path = OPERATION_PATH_MAP[operation];

      // For single-resource operations, append resourceId
      if (SINGLE_RESOURCE_OPS.has(operation) && resourceId) {
        path = `${path}/${encodeURIComponent(resourceId)}`;
      }

      // Append query params
      if (queryParams && Object.keys(queryParams).length > 0) {
        const qs = new URLSearchParams(queryParams).toString();
        path = `${path}?${qs}`;
      }

      // 3. Build headers
      const headers: Record<string, string> = {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Stripe-Version': STRIPE_API_VERSION,
      };

      if (stripeAccount) {
        headers['Stripe-Account'] = stripeAccount;
      }

      // 4. Make API call
      const apiEndpoint = `${cfg.hostname}${path.split('?')[0]}`;
      const response = await proxyFetch(
        cfg.vsockPort,
        cfg.hostname,
        'GET',
        path,
        headers,
      );

      // Skip attestation for transient error responses (rate limits, auth errors, server errors).
      // BUT attest definitive responses like 404 (entity not found is a valid answer).
      if (response.status >= 400 && response.status !== 404) {
        console.warn(`[stripe-payment-handler] Stripe API returned ${response.status} for ${operation}`);
        return {
          success: true,
          status: response.status,
          headers: response.headers,
          rawBody: response.body,
          // No attestation — transient errors not worth attesting
        };
      }

      if (response.status !== 200 && response.status !== 404) {
        throw new Error(`Stripe API returned unexpected status ${response.status}`);
      }

      // 5. Parse and validate response
      let jsonData: any;
      try {
        jsonData = JSON.parse(response.body);
      } catch {
        throw new Error('Stripe API returned invalid JSON');
      }

      const expectedType = OPERATION_OBJECT_TYPE[operation];
      if (jsonData.object !== expectedType) {
        throw new Error(`Unexpected Stripe object type: expected "${expectedType}", got "${jsonData.object}"`);
      }

      // 6. Encode as BN254 field elements
      const dataHash = crypto.createHash('sha256').update(response.body, 'utf8').digest('hex');
      const isListOp = expectedType === 'list';
      const totalCount = isListOp ? (jsonData.data?.length ?? 0) : 0;
      const hasMore = isListOp ? (jsonData.has_more ? 1 : 0) : 0;

      const encodedBytes = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
        operation,
        accountId: stripeAccount || null,
        objectType: jsonData.object,
        dataHash,
        totalCount,
        hasMore,
      });

      const rawBody = encodedBytes.toString('base64');

      // 7. Attest
      // Strip Authorization header — the requestHash must be reproducible
      // by external verifiers who don't have the API key.
      const { Authorization: _stripped, ...attestHeaders } = headers;

      const attestation = await attest(
        apiEndpoint,
        'GET',
        rawBody,
        `https://${cfg.hostname}${path}`,
        attestHeaders,
      );

      // 8. Return with human-readable headers
      return {
        success: true,
        status: 200,
        headers: {
          'x-stripe-operation': operation,
          'x-stripe-account-id': stripeAccount || '',
          'x-stripe-object-type': jsonData.object,
          'x-stripe-data-hash': dataHash,
          'x-stripe-total-count': String(totalCount),
          'x-stripe-has-more': String(hasMore),
          'x-stripe-response-body': response.body,
        },
        rawBody,
        attestation,
      };
    } catch (err: any) {
      // Sanitize error message — proxyFetch errors can include request details
      const safeMessage = err.message?.replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]') || 'Unknown error';
      console.error(`[stripe-payment-handler] Error: ${safeMessage}`);
      return {
        success: false,
        status: 502,
        headers: {},
        rawBody: '',
        error: safeMessage,
      };
    }
  };
}
