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
 *     "apiKey": "sk_..."  OR  "sealedApiKey": "<base64>" (exactly one),
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
 *
 * sealedApiKey is the platform key sealed to this enclave with KMS (`aws kms encrypt --encryption-context
 * enclave=stripe_payment`, enclave audit P1.7): only an enclave image the key policy names opens it, with the AWS
 * credentials the parent sends, so the key itself never crosses the host or data-bridge. apiKey (the key in clear)
 * stays accepted until every caller sends the sealed one.
 *
 * Only Stripe's own answer is signed (enclave audit 2026-10, P1.4): a 404 only when Stripe says the object does not
 * exist, a single object only when it is the one asked, a list only with its data array and has_more. The signed
 * answer carries Stripe's body beside it (upstreamBody): its SHA-256 is the signed dataHash, so a reader can use the
 * body as attested data.
 */

import crypto from 'node:crypto';
import { STRIPE_PAYMENT_SCHEMA, isSealedSecretText, SEALED_SECRET_MAX_BYTES } from '@tytle-enclaves/shared';
import type { HandlerDef, HandlerResult, HandlerContext, AllowedHost } from '@tytle-enclaves/shared';
import { HANDLER_MANIFEST, MANIFEST_HASH } from './manifest.js';

/**
 * The enclave's allowlist, each over its host vsock-proxy port, HTTPS: Stripe's API, and KMS to open a sealed key
 * (shared KMS_HOST; the main repo's host test reads these literals to build the host's proxies).
 */
export const STRIPE_HOSTS: AllowedHost[] = [
  { hostname: 'api.stripe.com', vsockProxyPort: 8446 },
  { hostname: 'kms.eu-central-1.amazonaws.com', vsockProxyPort: 8000 },
];

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

/** Where the API key comes from: the key itself, or the key sealed to this enclave (opened in execute). */
type StripeKey = { apiKey: string } | { sealedApiKey: string };

type StripeParams = StripeKey & {
  operation: StripeOperation;
  stripeAccount?: string;
  queryParams?: Record<string, string>;
  resourceId?: string;
};

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

/** The encryption context `enclave` of a key sealed for this enclave: the key policy's name for it. */
export const SEALED_KEY_CONTEXT = 'stripe_payment';

/** A Stripe secret key (sk_) or restricted key (rk_), the two kinds that can make this handler's calls: what a sealed key must open to. */
const STRIPE_KEY = /^(sk|rk)_[0-9A-Za-z_]+$/;

/** A Stripe account id (the Stripe-Account header's value): acct_ followed by letters and digits. */
const STRIPE_ACCOUNT_ID = /^acct_[0-9A-Za-z]+$/;

/**
 * Stripe's error code for "the object does not exist": "The ID provided isn't valid. Either the resource doesn't
 * exist, or an ID for a different resource has been provided." (docs.stripe.com/error-codes, read 2026-10-07).
 */
const NO_SUCH_OBJECT = 'resource_missing';

// =============================================================================
// Caller input and answer rules
// =============================================================================

/** An optional text field: absent, null or '' is absent; any other non-text value is refused. */
function optionalText(value: unknown, name: string): string | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string') throw new Error(`${name} must be text`);
  return value;
}

/**
 * The API key: in clear (apiKey, as every release before took it, with the same refusal when it is missing), or sealed
 * to this enclave (sealedApiKey, opened in execute). Never both: a caller that sends both does not know which is used.
 */
function keyOf(apiKey: unknown, sealedApiKey: unknown): StripeKey {
  if (sealedApiKey === undefined || sealedApiKey === null || sealedApiKey === '') {
    if (typeof apiKey !== 'string' || apiKey === '') throw new Error('apiKey is required');
    return { apiKey };
  }
  if (apiKey !== undefined && apiKey !== null && apiKey !== '') throw new Error('apiKey and sealedApiKey: send one, not both');
  if (!isSealedSecretText(sealedApiKey)) {
    throw new Error(`sealedApiKey must be a KMS ciphertext: base64 of at most ${SEALED_SECRET_MAX_BYTES} bytes`);
  }
  return { sealedApiKey };
}

/** Query parameters: an object of text values (they go into Stripe's query string as they are). */
function queryParamsOf(value: unknown): Record<string, string> | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'object' || Array.isArray(value)) throw new Error('queryParams must be an object of text values');
  const params: Record<string, string> = {};
  for (const [key, v] of Object.entries(value)) {
    if (typeof v !== 'string') throw new Error(`queryParams.${key} must be text`);
    params[key] = v;
  }
  return params;
}

/** Stripe's error code in an error body (`{"error": {"code": ...}}`), or undefined when the body has none. */
function stripeErrorCodeOf(body: string): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return undefined;
  }
  const error = typeof parsed === 'object' && parsed !== null ? (parsed as { error?: unknown }).error : undefined;
  const code = typeof error === 'object' && error !== null ? (error as { code?: unknown }).code : undefined;
  return typeof code === 'string' ? code : undefined;
}

/**
 * The account the answer belongs to: the Stripe-Account the request named, or null (the API key's own account).
 * Stripe refuses a Stripe-Account the key cannot act as (error code account_invalid: a 4xx, never signed). When
 * Stripe's answer names an account in its own Stripe-Account header, it must be the one asked.
 */
function answeredAccount(asked: string | undefined, responseHeaders: Record<string, string>): string | null {
  const named = responseHeaders['stripe-account'];
  if (asked !== undefined && named !== undefined && named !== asked) {
    throw new Error(`Stripe answered for account ${named}, not the one asked`);
  }
  return asked ?? null;
}

// =============================================================================
// Handler Definition
// =============================================================================

export const stripePaymentHandlerDef: HandlerDef<StripeParams> = {
  name: 'stripe-payment',
  schema: STRIPE_PAYMENT_SCHEMA,
  manifestHash: MANIFEST_HASH,
  policies: HANDLER_MANIFEST.policies,
  requiredHosts: ['api.stripe.com', 'kms.eu-central-1.amazonaws.com'],

  parseParams(body: unknown): StripeParams {
    const b = (body ?? {}) as Record<string, unknown>;
    const { operation } = b;

    if (typeof operation !== 'string' || !VALID_OPERATIONS.has(operation)) {
      throw new Error(`Invalid operation: "${String(operation)}". Supported: ${[...VALID_OPERATIONS].join(', ')}`);
    }

    const key = keyOf(b.apiKey, b.sealedApiKey);

    // Checked before the fetch: the value goes into the Stripe-Account header, and a value that is not an account id
    // is never asked (audit 2026-10 agent 1 §2.3a).
    const stripeAccount = optionalText(b.stripeAccount, 'stripeAccount');
    if (stripeAccount !== undefined && !STRIPE_ACCOUNT_ID.test(stripeAccount)) {
      throw new Error('Invalid stripeAccount: a Stripe account id is acct_ followed by letters and digits');
    }

    const resourceId = optionalText(b.resourceId, 'resourceId');
    if (SINGLE_RESOURCE_OPS.has(operation) && resourceId === undefined) {
      throw new Error(`${operation} requires resourceId`);
    }

    return {
      operation: operation as StripeOperation,
      ...key,
      stripeAccount,
      queryParams: queryParamsOf(b.queryParams),
      resourceId,
    };
  },

  async execute(params: StripeParams, ctx: HandlerContext): Promise<HandlerResult> {
    const { operation, stripeAccount, queryParams, resourceId } = params;
    // A sealed key is opened before anything is asked of Stripe; a failure names no byte of it
    const apiKey = 'apiKey' in params ? params.apiKey : await ctx.unsealSecret(params.sealedApiKey, SEALED_KEY_CONTEXT);
    if ('sealedApiKey' in params && !STRIPE_KEY.test(apiKey)) {
      throw new Error('the sealed key is not a Stripe secret or restricted key (sk_ or rk_)');
    }

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

    const accountId = answeredAccount(stripeAccount, response.headers);
    const dataHash = crypto.createHash('sha256').update(response.body, 'utf8').digest('hex');

    // 404 - Stripe's own "no such object" is signed with objectType='not_found'. Any other 404 (a path Stripe does
    // not know, a proxy's page) is no answer: an error, never signed.
    if (response.status === 404) {
      const code = stripeErrorCodeOf(response.body);
      if (code !== NO_SUCH_OBJECT) {
        throw new Error(`Stripe answered 404 without its "${NO_SUCH_OBJECT}" code (code: ${code ?? 'none'})`);
      }

      return {
        values: {
          operation,
          accountId,
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
          'x-stripe-account-id': accountId ?? '',
          'x-stripe-object-type': 'not_found',
          'x-stripe-data-hash': dataHash,
          'x-stripe-total-count': '0',
          'x-stripe-has-more': '0',
        },
        status: 404,
        bn254Headers: {
          'x-stripe-data-hash': dataHash,
        },
        upstreamBody: response.body,
      };
    }

    // Parse and validate response
    let parsed: unknown;
    try {
      parsed = JSON.parse(response.body);
    } catch {
      throw new Error('Stripe API returned invalid JSON');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('Stripe API returned JSON that is not an object');
    }
    const jsonData = parsed as Record<string, unknown>;

    const expectedType = OPERATION_OBJECT_TYPE[operation];
    if (jsonData.object !== expectedType) {
      throw new Error(`Unexpected Stripe object type: expected "${expectedType}", got "${String(jsonData.object)}"`);
    }

    // A single object is signed only as the one asked.
    if (SINGLE_RESOURCE_OPS.has(operation) && jsonData.id !== resourceId) {
      throw new Error(`Stripe answered ${operation} with "${String(jsonData.id)}", not the object asked`);
    }

    // A list is signed only with what its count and has_more are read from.
    const isListOp = expectedType === 'list';
    if (isListOp && (!Array.isArray(jsonData.data) || typeof jsonData.has_more !== 'boolean')) {
      throw new Error('Stripe answered a list without its data array and has_more');
    }

    // Compute attestation fields
    const totalCount = isListOp ? (jsonData.data as unknown[]).length : 0;
    const hasMore = isListOp && jsonData.has_more === true ? 1 : 0;

    return {
      values: {
        operation,
        accountId,
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
        'x-stripe-account-id': accountId ?? '',
        'x-stripe-object-type': String(jsonData.object),
        'x-stripe-data-hash': dataHash,
        'x-stripe-total-count': String(totalCount),
        'x-stripe-has-more': String(hasMore),
      },
      bn254Headers: {
        'x-stripe-data-hash': dataHash,
      },
      upstreamBody: response.body,
    };
  },
};
