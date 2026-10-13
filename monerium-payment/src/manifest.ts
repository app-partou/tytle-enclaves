/**
 * Monerium Payment Handler Manifest
 *
 * The specification of the handler's queries, field provenance, policies, and repeatability guarantees. Baked into
 * the Docker image, so PCR0 binds it; its hash goes with every answer as a pointer, unsigned. Its status rules are run
 * against the handler by the package's tests (moneriumPaymentHandler.factory.test.ts).
 */

import {
  computeManifestHash, validateManifest, MONERIUM_PAYMENT_SCHEMA,
  SKIP_TRANSIENT_ERRORS, STRIP_AUTH, REDACT_BEARER,
} from '@tytle-enclaves/shared';
import type { HandlerManifest } from '@tytle-enclaves/shared';

export const HANDLER_MANIFEST: HandlerManifest = {
  // 1.1.0 = the 2026-10-09 release; 1.2.0 = the second enclave release (R4)
  version: '1.2.0',

  queries: [
    {
      id: 'fetch_order',
      description: 'Fetch Monerium order by ID',
      method: 'GET',
      host: 'api.monerium.app',
      path: '/orders/{orderId}',
      headers: { 'Accept': 'application/vnd.monerium.api-v2+json' },
      auth: {
        header: 'Authorization',
        scheme: 'Bearer',
        strippedBeforeAttestation: true,
      },
    },
    {
      id: 'fetch_balance',
      description: 'Fetch EURe token balance on Gnosis chain',
      method: 'POST',
      host: 'rpc.gnosischain.com',
      path: '/',
      rpc: {
        protocol: 'json-rpc',
        method: 'eth_call',
        contract: '0xcB444e90D8198415266c6a2724b7900fb12FC56E',
        function: 'balanceOf(address)',
        selector: '0x70a08231',
        blockTag: 'latest',
      },
    },
  ],

  schema: {
    name: 'MONERIUM_PAYMENT_SCHEMA',
    outputBytes: 192,
    fields: [
      { name: 'orderId',     encoding: 'sha256',      source: { from: 'response', query: 'fetch_order', path: 'id' } },
      { name: 'state',       encoding: 'shortString',  source: { from: 'response', query: 'fetch_order', path: 'state' } },
      { name: 'orderAmount', encoding: 'shortString',  source: { from: 'response', query: 'fetch_order', path: 'amount' } },
      { name: 'currency',    encoding: 'shortString',  source: { from: 'response', query: 'fetch_order', path: 'currency' } },
      { name: 'balance',     encoding: 'uint',         source: { from: 'response', query: 'fetch_balance', path: 'result', transform: 'BigInt(hex)' } },
      { name: 'dataHash',    encoding: 'sha256',       source: { from: 'derived', inputs: ['fetch_order:rawBody', 'fetch_balance:rawBody'], join: '\n', transform: 'sha256' } },
    ],
  },

  policies: [
    SKIP_TRANSIENT_ERRORS,
    {
      id: 'not_found_is_never_signed',
      check: { type: 'status_skip', codes: [404] },
      reason: 'Whose view of Monerium answered is not signed: another valid token gets "no such order" for an order it cannot see, so a 404 proves nothing; it is passed on unsigned, like every other error (enclave review 2026-10-09, E-5)',
    },
    STRIP_AUTH,
    REDACT_BEARER,
    {
      id: 'chain_restriction',
      check: { type: 'field_equals', path: 'chain', value: 'gnosis' },
      reason: 'Only Gnosis RPC in enclave allowlist',
    },
    {
      id: 'address_format',
      check: { type: 'field_matches', path: 'address', pattern: '^0x[0-9a-fA-F]{40}$' },
      reason: 'ERC-20 balanceOf requires valid Ethereum address',
    },
    {
      id: 'required_order_fields',
      check: { type: 'field_required', paths: ['id', 'state', 'amount', 'currency', 'chain', 'address'] },
      reason: 'All BN254 schema fields must be populated from order response',
    },
    {
      id: 'valid_operations',
      check: { type: 'field_equals', path: 'operation', value: 'get_order_with_balance' },
      reason: 'Only get_order_with_balance operation is supported',
    },
    {
      id: 'rpc_result_required',
      check: { type: 'field_required', paths: ['result'] },
      reason: 'Gnosis RPC response must contain result field with non-empty hex value',
    },
    {
      id: 'order_id_format',
      check: { type: 'field_matches', path: 'orderId', pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' },
      reason: 'A Monerium order id is a UUID in lower case, as Monerium writes it; any other value is refused before the fetch',
    },
    {
      id: 'order_is_the_one_asked',
      check: { type: 'behavioral', description: 'The answered order\'s id must be the orderId asked, and id, state, amount and currency must be text; otherwise the answer is an error' },
      reason: 'A signed order is the order the request asked for',
    },
    {
      id: 'order_status',
      check: { type: 'behavioral', description: 'fetch_order: a 200 is read as the order; an error (400 or more, a 404 too) is passed on unsigned; any other status throws 502' },
      reason: 'Only Monerium\'s own order is signed',
    },
    {
      id: 'rpc_answer_is_this_call',
      check: { type: 'behavioral', description: 'fetch_balance: the answer must be a 200 whose JSON-RPC body carries the id of the balanceOf call (1) and a 0x-hex uint256 result; otherwise the answer is an error (502), never passed on' },
      reason: 'The signed balance is the chain\'s answer to this call',
    },
  ],

  repeatability: {
    hashAlgorithm: 'sha256',
    dataHashInput: 'fetch_order:rawBody + "\\n" + fetch_balance:rawBody',
    outputFormat: 'BN254 big-endian, 6 × 32 bytes, base64',
    deterministic: true,
  },
};

validateManifest(HANDLER_MANIFEST, MONERIUM_PAYMENT_SCHEMA);

export const MANIFEST_HASH = computeManifestHash(HANDLER_MANIFEST);
