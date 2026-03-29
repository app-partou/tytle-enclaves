/**
 * Monerium Payment Handler Manifest
 *
 * Executable specification of the handler's queries, field provenance,
 * policies, and repeatability guarantees. Baked into the Docker image
 * (contributing to PCR0) and its hash is included in every attestation.
 */

import {
  computeManifestHash, validateManifest, MONERIUM_PAYMENT_SCHEMA,
  SKIP_TRANSIENT_ERRORS, ATTEST_NOT_FOUND, STRIP_AUTH, REDACT_BEARER,
} from '@tytle-enclaves/shared';
import type { HandlerManifest } from '@tytle-enclaves/shared';

export const HANDLER_MANIFEST: HandlerManifest = {
  version: '1.0.0',

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
    ATTEST_NOT_FOUND,
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
