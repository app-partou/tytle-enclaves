/**
 * Monerium Payment Handler Definition
 *
 * Fetches a Monerium order and the on-chain EURe balance of the order's
 * address in a single attested snapshot.
 *
 * Two API calls per request:
 *   1. GET /orders/{orderId}          -> api.monerium.app (Monerium REST)
 *   2. POST / (eth_call balanceOf)    -> rpc.gnosischain.com (Gnosis RPC)
 *
 * Request body (JSON):
 *   {
 *     "operation": "get_order_with_balance",
 *     "accessToken": "slBcjO-QTJGGMRbYTJHq8A",
 *     "orderId": "a1b2c3d4-..."
 *   }
 *
 * Response: BN254-encoded field elements (6 x 32 = 192 bytes, base64)
 *           + human-readable headers (x-monerium-*)
 *
 * MONERIUM_PAYMENT_SCHEMA:
 *   [0..31]    orderId      sha256      (UUID > 31 bytes)
 *   [32..63]   state        shortString ('placed'|'pending'|'processed'|'rejected')
 *   [64..95]   orderAmount  shortString (e.g. "100.00")
 *   [96..127]  currency     shortString (e.g. "eur")
 *   [128..159] balance      uint        (raw EURe balance, 18 decimals)
 *   [160..191] dataHash     sha256      (combined order + RPC response)
 *
 * Only Monerium's and the chain's own answers are signed (enclave audit 2026-10, P1.4): the order asked (its id is
 * the orderId), a 404 only as Monerium's error body, a balance only from the JSON-RPC answer to this call.
 */

import crypto from 'node:crypto';
import { MONERIUM_PAYMENT_SCHEMA } from '@tytle-enclaves/shared';
import type { HandlerDef, HandlerResult, HandlerContext, AllowedHost } from '@tytle-enclaves/shared';
import { HANDLER_MANIFEST, MANIFEST_HASH } from './manifest.js';

/** The enclave's allowlist: Monerium's API and the Gnosis RPC, each over its own host vsock-proxy port, both HTTPS. */
export const MONERIUM_HOSTS: AllowedHost[] = [
  { hostname: 'api.monerium.app', vsockProxyPort: 8447 },
  { hostname: 'rpc.gnosischain.com', vsockProxyPort: 8448 },
];

// =============================================================================
// Constants
// =============================================================================

/** EURe token contract on Gnosis (V1 - proxied to V2 behind the scenes). */
const EURE_CONTRACT = '0xcB444e90D8198415266c6a2724b7900fb12FC56E';

/** keccak256("balanceOf(address)") first 4 bytes. */
const BALANCE_OF_SELECTOR = '0x70a08231';

const VALID_OPERATIONS = new Set(['get_order_with_balance']);

const VALID_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

/**
 * A Monerium order id is a UUID (docs.monerium.com/api, read 2026-10-07: the Order object's id is "string, UUID", and
 * the order's payments call answers 400 "the order ID is not a valid UUID"). Any version: the docs' own examples are
 * version-1 UUIDs.
 */
const ORDER_ID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** The JSON-RPC id of the one call this handler makes (a JSON-RPC answer carries the id of the call it answers). */
const RPC_CALL_ID = 1;

/** A balanceOf answer: one ABI word (uint256), as 0x-hex. */
const RPC_UINT256_RE = /^0x[0-9a-fA-F]{1,64}$/;

// =============================================================================
// ERC-20 Helpers
// =============================================================================

/** Encode an ERC-20 balanceOf(address) call data field. */
function encodeBalanceOfCall(address: string): string {
  const addr = address.toLowerCase().replace(/^0x/, '');
  return BALANCE_OF_SELECTOR + addr.padStart(64, '0');
}

/** Build JSON-RPC eth_call request body for balanceOf. */
function buildBalanceOfRpcBody(address: string): string {
  return JSON.stringify({
    jsonrpc: '2.0',
    method: 'eth_call',
    params: [
      { to: EURE_CONTRACT, data: encodeBalanceOfCall(address) },
      'latest',
    ],
    id: RPC_CALL_ID,
  });
}

/** A JSON body that must be an object; anything else is an error naming the service. */
function jsonObjectOf(body: string, service: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error(`${service} returned invalid JSON`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${service} returned JSON that is not an object`);
  }
  return parsed as Record<string, unknown>;
}

/** The `code` of Monerium's error body ({code, status, message, errors}), or undefined when the body is not one. */
function moneriumErrorCodeOf(body: string): unknown {
  try {
    const parsed: unknown = JSON.parse(body);
    return typeof parsed === 'object' && parsed !== null ? (parsed as { code?: unknown }).code : undefined;
  } catch {
    return undefined;
  }
}

/** A field that must be non-empty text, else the answer is no answer. */
function requiredText(data: Record<string, unknown>, field: string): string {
  const value = data[field];
  if (typeof value !== 'string' || value === '') {
    throw new Error(`Monerium order response has no "${field}" text`);
  }
  return value;
}

// =============================================================================
// Handler Definition
// =============================================================================

interface MoneriumPaymentParams {
  operation: string;
  accessToken: string;
  orderId: string;
}

export const moneriumPaymentHandlerDef: HandlerDef<MoneriumPaymentParams> = {
  name: 'monerium-payment',
  schema: MONERIUM_PAYMENT_SCHEMA,
  manifestHash: MANIFEST_HASH,
  policies: HANDLER_MANIFEST.policies,
  requiredHosts: ['api.monerium.app', 'rpc.gnosischain.com'],

  parseParams(body: unknown): MoneriumPaymentParams {
    const b = (body ?? {}) as Record<string, unknown>;
    const { operation, accessToken, orderId } = b;

    if (typeof operation !== 'string' || !VALID_OPERATIONS.has(operation)) {
      throw new Error(`Invalid operation: "${String(operation)}". Supported: ${[...VALID_OPERATIONS].join(', ')}`);
    }
    if (typeof accessToken !== 'string' || accessToken === '') {
      throw new Error('accessToken is required');
    }
    if (orderId === undefined || orderId === null || orderId === '') {
      throw new Error('orderId is required');
    }
    // Checked before the fetch: a value that is not an order id is never asked (audit 2026-10, caller inputs).
    if (typeof orderId !== 'string' || !ORDER_ID_RE.test(orderId)) {
      throw new Error('Invalid orderId: a Monerium order id is a UUID');
    }

    return { operation, accessToken, orderId };
  },

  async execute(params: MoneriumPaymentParams, ctx: HandlerContext): Promise<HandlerResult> {
    const { accessToken, orderId } = params;

    const moneriumHost = ctx.hosts.find((h) => h.hostname === 'api.monerium.app')!;
    const rpcHost = ctx.hosts.find((h) => h.hostname === 'rpc.gnosischain.com')!;

    const orderPath = `/orders/${encodeURIComponent(orderId)}`;
    const apiEndpoint = `${moneriumHost.hostname}${orderPath}`;

    // 1. Fetch order from Monerium API
    const orderResponse = await ctx.fetch(
      moneriumHost, 'GET', orderPath,
      {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.monerium.api-v2+json',
      },
    );

    // Skip attestation for transient errors (rate limits, auth errors, server errors).
    // BUT attest definitive responses like 404 (order not found is a valid answer).
    if (orderResponse.status >= 400 && orderResponse.status !== 404) {
      ctx.log.warn('Monerium transient error, skipping attestation', { status: orderResponse.status, orderId });
      return {
        values: {},
        apiEndpoint,
        method: 'GET',
        url: `https://${moneriumHost.hostname}${orderPath}`,
        requestHeaders: {},
        responseHeaders: orderResponse.headers,
        rawPassthrough: {
          status: orderResponse.status,
          headers: orderResponse.headers,
          rawBody: orderResponse.body,
        },
      };
    }

    if (orderResponse.status !== 200 && orderResponse.status !== 404) {
      throw new Error(`Monerium API returned unexpected status ${orderResponse.status}`);
    }

    // 404 = order not found - a valid, definitive answer, signed. Monerium documents no 404 for this call; its error
    // body is {code, status, message, errors} (docs.monerium.com/api). Only that body with code 404 is Monerium's own
    // answer; any other 404 (a proxy's page, another shape) is an error, never signed.
    if (orderResponse.status === 404) {
      if (moneriumErrorCodeOf(orderResponse.body) !== 404) {
        throw new Error('Monerium answered 404 without its error body (code 404)');
      }
      const dataHash = crypto.createHash('sha256').update(orderResponse.body, 'utf8').digest('hex');

      return {
        values: {
          orderId,
          state: 'not_found',
          orderAmount: null,
          currency: null,
          balance: 0,
          dataHash,
        },
        apiEndpoint,
        method: 'GET',
        url: `https://${moneriumHost.hostname}${orderPath}`,
        requestHeaders: {
          'Accept': 'application/vnd.monerium.api-v2+json',
        },
        responseHeaders: {
          'x-monerium-order-id': orderId,
          'x-monerium-state': 'not_found',
          'x-monerium-order-amount': '',
          'x-monerium-currency': '',
          'x-monerium-balance': '0',
          'x-monerium-data-hash': dataHash,
        },
        status: 404,
        bn254Headers: {},
      };
    }

    // Parse order response
    const orderData = jsonObjectOf(orderResponse.body, 'Monerium API');

    // Validate required order fields: each is text (docs.monerium.com/api: id, state, amount and currency are strings),
    // and the order is the one asked.
    const answeredId = requiredText(orderData, 'id');
    if (answeredId !== orderId) {
      throw new Error(`Monerium answered order ${answeredId}, not the one asked`);
    }
    const state = requiredText(orderData, 'state');
    const amount = requiredText(orderData, 'amount');
    const currency = requiredText(orderData, 'currency');
    if (orderData.chain !== 'gnosis') {
      throw new Error(`Only gnosis chain is supported, got "${orderData.chain as string}"`);
    }
    if (!orderData.address || !VALID_ADDRESS_RE.test(orderData.address as string)) {
      throw new Error(`Invalid address in order response: "${orderData.address as string}"`);
    }

    // 2. Fetch EURe balance from Gnosis RPC
    const rpcBody = buildBalanceOfRpcBody(orderData.address as string);

    const rpcResponse = await ctx.fetch(
      rpcHost, 'POST', '/',
      { 'Content-Type': 'application/json' },
      rpcBody,
    );

    if (rpcResponse.status !== 200) {
      throw new Error(`Gnosis RPC returned HTTP ${rpcResponse.status}`);
    }

    const rpcData = jsonObjectOf(rpcResponse.body, 'Gnosis RPC');

    if (rpcData.error) {
      const rpcError = rpcData.error as Record<string, unknown>;
      throw new Error(`Gnosis RPC error: ${(rpcError.message as string) || JSON.stringify(rpcData.error)}`);
    }

    // The answer to THIS call: a JSON-RPC answer carries the id of the call it answers.
    if (rpcData.id !== RPC_CALL_ID) {
      throw new Error(`Gnosis RPC answered call ${JSON.stringify(rpcData.id)}, not this one`);
    }

    if (typeof rpcData.result !== 'string' || !RPC_UINT256_RE.test(rpcData.result)) {
      throw new Error(`balanceOf returned no uint256 result (${JSON.stringify(rpcData.result)})`);
    }

    const balance = BigInt(rpcData.result);

    // 3. Compute dataHash from combined raw responses
    const combinedBody = orderResponse.body + '\n' + rpcResponse.body;
    const dataHash = crypto.createHash('sha256').update(combinedBody, 'utf8').digest('hex');

    return {
      values: {
        orderId: answeredId,
        state,
        orderAmount: amount,
        currency,
        balance,
        dataHash,
      },
      apiEndpoint,
      method: 'GET',
      url: `https://${moneriumHost.hostname}${orderPath}`,
      requestHeaders: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.monerium.api-v2+json',
      },
      responseHeaders: {
        'x-monerium-order-id': answeredId,
        'x-monerium-state': state,
        'x-monerium-order-amount': amount,
        'x-monerium-currency': currency,
        'x-monerium-balance': balance.toString(),
        'x-monerium-data-hash': dataHash,
      },
      bn254Headers: {
        'x-monerium-data-hash': dataHash,
      },
    };
  },
};
