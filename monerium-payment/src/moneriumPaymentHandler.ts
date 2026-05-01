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
 */

import crypto from 'node:crypto';
import { MONERIUM_PAYMENT_SCHEMA } from '@tytle-enclaves/shared';
import type { HandlerDef, HandlerResult, HandlerContext } from '@tytle-enclaves/shared';
import { HANDLER_MANIFEST, MANIFEST_HASH } from './manifest.js';

// =============================================================================
// Constants
// =============================================================================

/** EURe token contract on Gnosis (V1 - proxied to V2 behind the scenes). */
const EURE_CONTRACT = '0xcB444e90D8198415266c6a2724b7900fb12FC56E';

/** keccak256("balanceOf(address)") first 4 bytes. */
const BALANCE_OF_SELECTOR = '0x70a08231';

const VALID_OPERATIONS = new Set(['get_order_with_balance']);

const VALID_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

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
    id: 1,
  });
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
    const b = body as Record<string, unknown>;
    const operation = b.operation as string | undefined;
    const accessToken = b.accessToken as string | undefined;
    const orderId = b.orderId as string | undefined;

    if (!operation || !VALID_OPERATIONS.has(operation)) {
      throw new Error(`Invalid operation: "${operation}". Supported: ${[...VALID_OPERATIONS].join(', ')}`);
    }
    if (!accessToken) {
      throw new Error('accessToken is required');
    }
    if (!orderId) {
      throw new Error('orderId is required');
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

    // Parse order response
    let orderData: Record<string, unknown>;
    try {
      orderData = JSON.parse(orderResponse.body) as Record<string, unknown>;
    } catch {
      throw new Error('Monerium API returned invalid JSON');
    }

    // 404 = order not found - a valid, definitive answer. Attest it.
    if (orderResponse.status === 404) {
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

    // Validate required order fields
    if (!orderData.id) {
      throw new Error('Monerium order response missing "id" field');
    }
    if (!orderData.state) {
      throw new Error('Monerium order response missing "state" field');
    }
    if (!orderData.amount) {
      throw new Error('Monerium order response missing "amount" field');
    }
    if (!orderData.currency) {
      throw new Error('Monerium order response missing "currency" field');
    }
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

    let rpcData: Record<string, unknown>;
    try {
      rpcData = JSON.parse(rpcResponse.body) as Record<string, unknown>;
    } catch {
      throw new Error('Gnosis RPC returned invalid JSON');
    }

    if (rpcData.error) {
      const rpcError = rpcData.error as Record<string, unknown>;
      throw new Error(`Gnosis RPC error: ${(rpcError.message as string) || JSON.stringify(rpcData.error)}`);
    }

    if (!rpcData.result || rpcData.result === '0x') {
      throw new Error('balanceOf returned empty result');
    }

    const balance = BigInt(rpcData.result as string);

    // 3. Compute dataHash from combined raw responses
    const combinedBody = orderResponse.body + '\n' + rpcResponse.body;
    const dataHash = crypto.createHash('sha256').update(combinedBody, 'utf8').digest('hex');

    return {
      values: {
        orderId: orderData.id as string,
        state: orderData.state as string,
        orderAmount: orderData.amount as string,
        currency: orderData.currency as string,
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
        'x-monerium-order-id': orderData.id as string,
        'x-monerium-state': orderData.state as string,
        'x-monerium-order-amount': orderData.amount as string,
        'x-monerium-currency': orderData.currency as string,
        'x-monerium-balance': balance.toString(),
        'x-monerium-data-hash': dataHash,
      },
      bn254Headers: {
        'x-monerium-data-hash': dataHash,
      },
    };
  },
};
