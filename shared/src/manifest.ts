/**
 * Handler Manifest — executable specification for enclave handlers.
 *
 * Every enclave handler declares a manifest describing its queries,
 * field provenance, policies, and repeatability guarantees. The manifest
 * is baked into the Docker image (contributing to PCR0) and its SHA-256
 * hash is included in every attestation, creating a cryptographic chain:
 *
 *   PCR0 → proves which code ran (includes manifest)
 *   requestHash → includes manifest hash → proves which specification
 *   BN254 + dataHash → proves the data transformation
 */

import crypto from 'node:crypto';
import type { FieldDef, FieldEncoding } from './bn254Codec.js';

// =============================================================================
// Field Transforms
// =============================================================================

/** Known transforms applied to raw response values before BN254 encoding. */
export type FieldTransform =
  | 'identity'        // pass through as-is (strings, numbers)
  | 'BigInt(hex)'     // parse hex string → BigInt
  | 'sha256'          // SHA-256 hash the value
  | 'boolean_uint'    // true → 1, false → 0
  | 'array_length'    // array.length → number
  ;

// =============================================================================
// Field Provenance
// =============================================================================

/** Value extracted from a JSON response field. */
export interface ResponseFieldSource {
  from: 'response';
  /** Query ID (must exist in manifest.queries). */
  query: string;
  /** JSON field path in the response body (e.g., 'id', 'state', 'data.length'). */
  path: string;
  /** Transformation applied to the raw value before encoding. */
  transform?: FieldTransform;
}

/** Value taken from the request body. */
export interface RequestParamSource {
  from: 'request';
  /** Parameter name in the request body JSON. */
  param: string;
}

/** Value taken from a request header. */
export interface RequestHeaderSource {
  from: 'request_header';
  /** Header name. */
  header: string;
}

/** Value parsed from a non-JSON response (HTML, XML, SOAP). */
export interface ParsedSource {
  from: 'parsed';
  /** Query ID whose response is parsed. */
  query: string;
  /** What parser is used (e.g., 'soap_xml', 'html_grid'). */
  parser: string;
  /** What is extracted (e.g., 'valid', 'name', 'primaryCAE.code'). */
  field: string;
}

/** Value derived by combining raw bodies from multiple queries. */
export interface DerivedSource {
  from: 'derived';
  /** Input references: 'queryId:rawBody'. */
  inputs: string[];
  /** Separator used to join inputs before transform (e.g., '\n'). */
  join: string;
  /** Transformation applied to the joined value. */
  transform: FieldTransform;
}

/** Where a BN254 field's value comes from. Discriminated by `from`. */
export type FieldSource =
  | ResponseFieldSource
  | RequestParamSource
  | RequestHeaderSource
  | ParsedSource
  | DerivedSource;

/** Maps a BN254 schema field to its data origin and transformation. */
export interface FieldProvenance {
  /** Field name — must match the BN254 schema definition. */
  name: string;
  /** BN254 encoding type — must match the schema definition. */
  encoding: FieldEncoding;
  /** Structured data lineage. */
  source: FieldSource;
}

// =============================================================================
// Query Definitions
// =============================================================================

/** Authentication method used by a query. */
export interface QueryAuth {
  /** HTTP header name (e.g., 'Authorization'). */
  header: string;
  /** Auth scheme (e.g., 'Bearer'). */
  scheme: string;
  /** Whether this header is removed before attestation hash computation. */
  strippedBeforeAttestation: boolean;
}

/** On-chain / JSON-RPC call details. */
export interface RpcCall {
  protocol: 'json-rpc';
  method: string;        // e.g., 'eth_call'
  contract: string;      // e.g., '0xcB444e90...'
  function: string;      // e.g., 'balanceOf(address)'
  selector: string;      // e.g., '0x70a08231'
  blockTag: string;      // e.g., 'latest'
}

/** A single external API call the handler makes. */
export interface QueryDef {
  /** Unique identifier referenced by field provenance. */
  id: string;
  /** What this query does. */
  description: string;
  /** HTTP method. */
  method: 'GET' | 'POST';
  /** Target hostname (from the enclave allowlist). */
  host: string;
  /** URL path template (e.g., '/orders/{orderId}'). */
  path: string;
  /** Static headers (excluding auth). */
  headers?: Record<string, string>;
  /** Authentication, if any. */
  auth?: QueryAuth;
  /** On-chain call details, if this is an RPC query. */
  rpc?: RpcCall;
}

// =============================================================================
// Policy Definitions
// =============================================================================

/** Structured policy checks — machine-evaluatable by verification tools. */
export type PolicyCheck =
  | { type: 'field_equals';   path: string; value: string | number | boolean }
  | { type: 'field_matches';  path: string; pattern: string }
  | { type: 'field_required'; paths: string[] }
  | { type: 'status_skip';    codes: number[]; except?: number[] }
  | { type: 'status_attest';  code: number; overrides?: Record<string, string | number> }
  | { type: 'header_strip';   headers: string[] }
  | { type: 'error_redact';   pattern: string; replacement: string }
  | { type: 'behavioral';     description: string }
  ;

/** A validation or attestation rule enforced by the handler. */
export interface PolicyDef {
  /** Policy identifier. */
  id: string;
  /** Structured check definition. */
  check: PolicyCheck;
  /** Why this policy exists. */
  reason: string;
}

// =============================================================================
// Repeatability
// =============================================================================

/** How a verifier can reproduce the BN254 encoding from raw API responses. */
export interface RepeatabilityDef {
  /** Hash algorithm for dataHash, or null if schema has no dataHash field. */
  hashAlgorithm: 'sha256' | null;
  /** How dataHash input is constructed, or null if not applicable. */
  dataHashInput: string | null;
  /** Output format description. */
  outputFormat: string;
  /** Whether identical inputs always produce identical outputs. */
  deterministic: true;
}

// =============================================================================
// Handler Manifest
// =============================================================================

/**
 * Complete executable specification of what an enclave handler does.
 *
 * Declares every external call, every field derivation, every validation
 * rule, and how to reproduce the encoding. Baked into the Docker image.
 */
export interface HandlerManifest {
  /** Semantic version — bump on any change to queries, schema, or policies. */
  version: string;
  /** Every external API call the handler makes. */
  queries: QueryDef[];
  /** BN254 schema with field-level provenance. */
  schema: {
    name: string;
    outputBytes: number;
    fields: FieldProvenance[];
  };
  /** Validation rules and attestation policies. */
  policies: PolicyDef[];
  /** How to reproduce the encoding from raw responses. */
  repeatability: RepeatabilityDef;
}

// =============================================================================
// Utilities
// =============================================================================

/**
 * Deterministic JSON serialization with recursively sorted object keys.
 * Guarantees the same manifest always produces the same string regardless
 * of property insertion order.
 */
export function stableStringify(value: unknown): string {
  return JSON.stringify(value, (_key, val) => {
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(val).sort()) {
        sorted[k] = (val as Record<string, unknown>)[k];
      }
      return sorted;
    }
    return val;
  });
}

/**
 * Compute a deterministic SHA-256 hash of a handler manifest.
 * Uses stable serialization to ensure reproducibility.
 */
export function computeManifestHash(manifest: HandlerManifest): string {
  return crypto
    .createHash('sha256')
    .update(stableStringify(manifest))
    .digest('hex');
}

/**
 * Validate that a manifest's field provenance matches the actual BN254 schema.
 * Call at module load time to catch manifest drift early.
 *
 * Checks:
 * - Field count matches
 * - Field names match (in order)
 * - Field encodings match
 * - Every direct source references a valid query ID
 *
 * @throws Error if the manifest doesn't match the schema
 */
export function validateManifest(manifest: HandlerManifest, schema: FieldDef[]): void {
  const mFields = manifest.schema.fields;
  const queryIds = new Set(manifest.queries.map(q => q.id));

  if (mFields.length !== schema.length) {
    throw new Error(
      `Manifest declares ${mFields.length} fields but schema has ${schema.length}`,
    );
  }

  for (let i = 0; i < schema.length; i++) {
    if (mFields[i].name !== schema[i].name) {
      throw new Error(
        `Manifest field[${i}] name "${mFields[i].name}" does not match schema "${schema[i].name}"`,
      );
    }
    if (mFields[i].encoding !== schema[i].encoding) {
      throw new Error(
        `Manifest field "${mFields[i].name}" encoding "${mFields[i].encoding}" does not match schema "${schema[i].encoding}"`,
      );
    }

    // Validate query references for source types that reference queries
    const source = mFields[i].source;
    if (source.from === 'response' || source.from === 'parsed') {
      if (!queryIds.has(source.query)) {
        throw new Error(
          `Manifest field "${mFields[i].name}" references unknown query "${source.query}"`,
        );
      }
    }
  }
}
