/**
 * Generic BN254 Field Element Codec
 *
 * Schema-driven encoder for producing concatenated 32-byte BN254 field elements.
 * Each connector defines a schema (ordered list of field definitions), and the
 * encoder produces deterministic bytes consumable by ZK circuits.
 *
 * Field encoding types:
 *   shortString — UTF-8 string as BigInt (recoverable, must be < 31 bytes)
 *   sha256      — SHA-256 hash mod BN254_MODULUS (not recoverable, for long values)
 *   uint        — Numeric value as field element directly (booleans, counts, etc.)
 *
 * Output: N fields x 32 bytes, big-endian, fixed offsets.
 */

import crypto from 'node:crypto';

export const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// =============================================================================
// Schema Types
// =============================================================================

export type FieldEncoding = 'shortString' | 'sha256' | 'uint';

export interface FieldDef {
  name: string;
  encoding: FieldEncoding;
}

// =============================================================================
// Provider Schemas
// =============================================================================

export const SICAE_SCHEMA: FieldDef[] = [
  { name: 'nif',       encoding: 'shortString' },
  { name: 'name',      encoding: 'sha256' },
  { name: 'cae1Code',  encoding: 'shortString' },
  { name: 'cae1Desc',  encoding: 'sha256' },
  { name: 'cae2Code',  encoding: 'shortString' },
  { name: 'cae2Desc',  encoding: 'sha256' },
];

export const VIES_SCHEMA: FieldDef[] = [
  { name: 'countryCode', encoding: 'shortString' },
  { name: 'vatNumber',   encoding: 'shortString' },
  { name: 'valid',       encoding: 'uint' },
  { name: 'name',        encoding: 'sha256' },
  { name: 'address',     encoding: 'sha256' },
];

// =============================================================================
// Encoding Functions
// =============================================================================

export function bigintToBytes32(val: bigint): Buffer {
  const hex = val.toString(16).padStart(64, '0');
  return Buffer.from(hex, 'hex');
}

function shortStringToFe(s: string): Buffer {
  const bytes = Buffer.from(s, 'utf8');
  if (bytes.length > 31) {
    throw new Error(`shortString exceeds 31 bytes: "${s}" (${bytes.length} bytes)`);
  }
  const fe = BigInt('0x' + bytes.toString('hex'));
  return bigintToBytes32(fe);
}

function sha256ToFe(s: string): Buffer {
  const hash = crypto.createHash('sha256').update(s, 'utf8').digest('hex');
  const fe = BigInt('0x' + hash) % BN254_MODULUS;
  return bigintToBytes32(fe);
}

function uintToFe(n: number | bigint): Buffer {
  const val = typeof n === 'bigint' ? n : BigInt(n);
  if (val < 0n || val >= BN254_MODULUS) {
    throw new Error(`uint out of BN254 range: ${val}`);
  }
  return bigintToBytes32(val);
}

function encodeField(def: FieldDef, value: string | number | bigint | null): Buffer {
  // Null/empty → 32 zero bytes (sentinel for absent values)
  if (value === null || value === undefined || value === '') {
    return Buffer.alloc(32);
  }

  switch (def.encoding) {
    case 'shortString':
      return shortStringToFe(String(value));
    case 'sha256':
      return sha256ToFe(String(value));
    case 'uint':
      return uintToFe(typeof value === 'string' ? BigInt(value) : value);
    default:
      throw new Error(`Unknown encoding: ${(def as any).encoding}`);
  }
}

// =============================================================================
// Public API
// =============================================================================

/**
 * Encode a record of values into concatenated BN254 field elements.
 * Returns `schema.length * 32` bytes.
 */
export function encodeFieldElements(
  schema: FieldDef[],
  values: Record<string, string | number | bigint | null>,
): Buffer {
  const buffers: Buffer[] = [];
  for (const def of schema) {
    const value = values[def.name] ?? null;
    buffers.push(encodeField(def, value));
  }
  return Buffer.concat(buffers);
}

/**
 * Expected byte length for a given schema.
 */
export function schemaByteLength(schema: FieldDef[]): number {
  return schema.length * 32;
}
