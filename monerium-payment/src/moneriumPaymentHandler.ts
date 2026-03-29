/**
 * Monerium Payment Custom Handler
 *
 * Fetches a Monerium order and the on-chain EURe balance of the order's
 * address in a single attested snapshot.
 *
 * Two API calls per request:
 *   1. GET /orders/{orderId}          → api.monerium.app (Monerium REST)
 *   2. POST / (eth_call balanceOf)    → rpc.gnosischain.com (Gnosis RPC)
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
import { proxyFetch, errorResponse, encodeBn254AndAttest, MONERIUM_PAYMENT_SCHEMA } from '@tytle-enclaves/shared';
import type { EnclaveRequest, EnclaveResponse } from '@tytle-enclaves/shared';
import { MANIFEST_HASH } from './manifest.js';

// =============================================================================
// Constants
// =============================================================================

/** EURe token contract on Gnosis (V1 — proxied to V2 behind the scenes). */
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
// Custom Handler
// =============================================================================

interface MoneriumPaymentHandlerConfig {
  moneriumHostname: string;
  moneriumVsockPort: number;
  rpcHostname: string;
  rpcVsockPort: number;
}

export function createMoneriumPaymentHandler(cfg: MoneriumPaymentHandlerConfig) {
  return async (request: EnclaveRequest): Promise<EnclaveResponse> => {
    try {
      // 1. Parse + validate request
      let operation: string;
      let accessToken: string;
      let orderId: string;

      try {
        const body = JSON.parse(request.body || '{}');
        operation = body.operation;
        accessToken = body.accessToken;
        orderId = body.orderId;
      } catch {
        return errorResponse(400, 'Invalid request body — expected JSON with { operation, accessToken, orderId }');
      }

      if (!operation || !VALID_OPERATIONS.has(operation)) {
        return errorResponse(400, `Invalid operation: "${operation}". Supported: ${[...VALID_OPERATIONS].join(', ')}`);
      }

      if (!accessToken) {
        return errorResponse(400, 'accessToken is required');
      }

      if (!orderId) {
        return errorResponse(400, 'orderId is required');
      }

      // 2. Fetch order from Monerium API
      const orderPath = `/orders/${encodeURIComponent(orderId)}`;
      const apiEndpoint = `${cfg.moneriumHostname}${orderPath}`;

      const orderHeaders: Record<string, string> = {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/vnd.monerium.api-v2+json',
      };

      const orderResponse = await proxyFetch(
        cfg.moneriumVsockPort,
        cfg.moneriumHostname,
        'GET',
        orderPath,
        orderHeaders,
      );

      // Skip attestation for transient error responses (rate limits, auth errors, server errors).
      // BUT attest definitive responses like 404 (order not found is a valid answer).
      if (orderResponse.status >= 400 && orderResponse.status !== 404) {
        console.warn(`[monerium-payment-handler] Monerium API returned ${orderResponse.status} for ${orderId}`);
        return {
          success: true,
          status: orderResponse.status,
          headers: orderResponse.headers,
          rawBody: orderResponse.body,
        };
      }

      if (orderResponse.status !== 200 && orderResponse.status !== 404) {
        throw new Error(`Monerium API returned unexpected status ${orderResponse.status}`);
      }

      // Parse order response
      let orderData: any;
      try {
        orderData = JSON.parse(orderResponse.body);
      } catch {
        throw new Error('Monerium API returned invalid JSON');
      }

      // 404 = order not found — a valid, definitive answer. Attest it.
      if (orderResponse.status === 404) {
        const dataHash = crypto.createHash('sha256').update(orderResponse.body, 'utf8').digest('hex');

        const { Authorization: _stripped, ...attestHeaders } = orderHeaders;
        const result = await encodeBn254AndAttest(
          MONERIUM_PAYMENT_SCHEMA,
          { orderId, state: 'not_found', orderAmount: null, currency: null, balance: 0, dataHash },
          { apiEndpoint, method: 'GET', url: `https://${cfg.moneriumHostname}${orderPath}`, requestHeaders: { ...attestHeaders, 'x-manifest-hash': MANIFEST_HASH } },
        );

        return {
          success: true,
          status: 404,
          headers: {
            'x-monerium-order-id': orderId,
            'x-monerium-state': 'not_found',
            'x-monerium-order-amount': '',
            'x-monerium-currency': '',
            'x-monerium-balance': '0',
            'x-monerium-data-hash': dataHash,
            'x-monerium-manifest-hash': MANIFEST_HASH,
          },
          rawBody: result.rawBody,
          attestation: result.attestation,
          bn254: result.rawBody,
          bn254Headers: {
            'x-monerium-data-hash': result.attestation.responseHash,
          },
        };
      }

      // Validate order response has all required fields
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
        return errorResponse(400, `Only gnosis chain is supported, got "${orderData.chain}"`);
      }

      if (!orderData.address || !VALID_ADDRESS_RE.test(orderData.address)) {
        throw new Error(`Invalid address in order response: "${orderData.address}"`);
      }

      // 3. Fetch EURe balance from Gnosis RPC
      const rpcBody = buildBalanceOfRpcBody(orderData.address);

      const rpcResponse = await proxyFetch(
        cfg.rpcVsockPort,
        cfg.rpcHostname,
        'POST',
        '/',
        { 'Content-Type': 'application/json' },
        rpcBody,
      );

      if (rpcResponse.status !== 200) {
        throw new Error(`Gnosis RPC returned HTTP ${rpcResponse.status}`);
      }

      let rpcData: any;
      try {
        rpcData = JSON.parse(rpcResponse.body);
      } catch {
        throw new Error('Gnosis RPC returned invalid JSON');
      }

      if (rpcData.error) {
        throw new Error(`Gnosis RPC error: ${rpcData.error.message || JSON.stringify(rpcData.error)}`);
      }

      if (!rpcData.result || rpcData.result === '0x') {
        throw new Error('balanceOf returned empty result');
      }

      const balance = BigInt(rpcData.result);

      // 4. Encode BN254 + attest
      const combinedBody = orderResponse.body + '\n' + rpcResponse.body;
      const dataHash = crypto.createHash('sha256').update(combinedBody, 'utf8').digest('hex');

      // Strip Authorization header — the requestHash must be reproducible
      // by external verifiers who don't have the access token.
      const { Authorization: _stripped, ...attestHeaders } = orderHeaders;

      const result = await encodeBn254AndAttest(
        MONERIUM_PAYMENT_SCHEMA,
        {
          orderId: orderData.id,
          state: orderData.state,
          orderAmount: orderData.amount,
          currency: orderData.currency,
          balance,
          dataHash,
        },
        {
          apiEndpoint,
          method: 'GET',
          url: `https://${cfg.moneriumHostname}${orderPath}`,
          requestHeaders: { ...attestHeaders, 'x-manifest-hash': MANIFEST_HASH },
        },
      );

      // 5. Return with human-readable headers + BN254 data
      return {
        success: true,
        status: 200,
        headers: {
          'x-monerium-order-id': orderData.id,
          'x-monerium-state': orderData.state,
          'x-monerium-order-amount': orderData.amount,
          'x-monerium-currency': orderData.currency,
          'x-monerium-balance': balance.toString(),
          'x-monerium-data-hash': dataHash,
          'x-monerium-manifest-hash': MANIFEST_HASH,
        },
        rawBody: result.rawBody,
        attestation: result.attestation,
        bn254: result.rawBody,
        bn254Headers: {
          'x-monerium-data-hash': result.attestation.responseHash,
        },
      };
    } catch (err: any) {
      // Sanitize error message — proxyFetch errors can include request details
      const safeMessage = err.message?.replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]') || 'Unknown error';
      console.error(`[monerium-payment-handler] Error: ${safeMessage}`);
      return errorResponse(502, safeMessage);
    }
  };
}
