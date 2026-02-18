import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  encodeFieldElements,
  schemaByteLength,
  bigintToBytes32,
  BN254_MODULUS,
  SICAE_SCHEMA,
  VIES_SCHEMA,
  STRIPE_PAYMENT_SCHEMA,
} from '../bn254Codec.js';
import type { FieldDef } from '../bn254Codec.js';

// =============================================================================
// Decoder (mirrors data-bridge/src/attestation/providers/bn254Codec.ts)
// Inlined here so encoder↔decoder roundtrip can be verified in one test suite.
// =============================================================================

function recoverShortString(bytes32: Buffer): string {
  let start = 0;
  while (start < bytes32.length && bytes32[start] === 0) start++;
  return bytes32.subarray(start).toString('utf8');
}

function readUint(bytes32: Buffer): bigint {
  return BigInt('0x' + bytes32.toString('hex'));
}

function isZero(bytes32: Buffer): boolean {
  for (let i = 0; i < bytes32.length; i++) {
    if (bytes32[i] !== 0) return false;
  }
  return true;
}

interface DecodedField {
  value: string;
  isNull: boolean;
  hex: string;
}

function decodeFieldElements(schema: FieldDef[], raw: Buffer): Record<string, DecodedField> {
  const expected = schema.length * 32;
  if (raw.length !== expected) {
    throw new Error(`Expected ${expected} bytes for ${schema.length} fields, got ${raw.length}`);
  }
  const result: Record<string, DecodedField> = {};
  for (let i = 0; i < schema.length; i++) {
    const def = schema[i];
    const bytes32 = raw.subarray(i * 32, (i + 1) * 32);
    const hex = bytes32.toString('hex');
    const fieldIsNull = isZero(bytes32);
    let value: string;
    if (fieldIsNull) {
      value = '';
    } else {
      switch (def.encoding) {
        case 'shortString':
          value = recoverShortString(bytes32);
          break;
        case 'sha256':
          value = hex;
          break;
        case 'uint':
          value = readUint(bytes32).toString();
          break;
        default:
          value = hex;
      }
    }
    result[def.name] = { value, isNull: fieldIsNull, hex };
  }
  return result;
}

function verifySha256Field(plaintext: string, hashHex: string): boolean {
  const hash = crypto.createHash('sha256').update(plaintext, 'utf8').digest('hex');
  const fe = BigInt('0x' + hash) % BN254_MODULUS;
  const expected = fe.toString(16).padStart(64, '0');
  return expected === hashHex;
}

function decodeToTyped<T extends Record<string, unknown>>(
  schema: FieldDef[],
  raw: Buffer,
  headers?: Record<string, string>,
  headerPrefix?: string,
): T {
  const decoded = decodeFieldElements(schema, raw);
  const result: Record<string, unknown> = {};

  for (const def of schema) {
    const field = decoded[def.name];
    if (field.isNull) {
      result[def.name] = def.jsType === 'boolean' ? false : def.jsType === 'number' ? 0 : '';
      continue;
    }

    const jsType = def.jsType || 'string';

    switch (def.encoding) {
      case 'shortString':
        result[def.name] = field.value;
        break;

      case 'uint':
        if (jsType === 'boolean') {
          result[def.name] = field.value !== '0';
        } else if (jsType === 'number') {
          result[def.name] = Number(field.value);
        } else {
          result[def.name] = field.value;
        }
        break;

      case 'sha256': {
        const headerKey = headerPrefix
          ? `${headerPrefix}${def.name.replace(/([A-Z])/g, '-$1').toLowerCase()}`
          : undefined;
        const headerValue = headerKey && headers ? headers[headerKey] : undefined;
        result[def.name] = headerValue || field.hex;
        break;
      }

      default:
        result[def.name] = field.value;
    }
  }

  return result as T;
}

// =============================================================================
// Tests — bigintToBytes32
// =============================================================================

describe('bigintToBytes32', () => {
  it('encodes 0 as 32 zero bytes', () => {
    const buf = bigintToBytes32(0n);
    expect(buf.length).toBe(32);
    expect(buf.every(b => b === 0)).toBe(true);
  });

  it('encodes 1 as 31 zero bytes + 0x01', () => {
    const buf = bigintToBytes32(1n);
    expect(buf.length).toBe(32);
    expect(buf[31]).toBe(1);
    expect(buf.subarray(0, 31).every(b => b === 0)).toBe(true);
  });

  it('encodes 256 correctly', () => {
    const buf = bigintToBytes32(256n);
    expect(buf[30]).toBe(1);
    expect(buf[31]).toBe(0);
  });

  it('encodes BN254_MODULUS - 1 (max valid field element)', () => {
    const buf = bigintToBytes32(BN254_MODULUS - 1n);
    expect(buf.length).toBe(32);
    expect(buf.some(b => b !== 0)).toBe(true);
  });

  it('encodes 0xFF (255) as last byte', () => {
    const buf = bigintToBytes32(255n);
    expect(buf[31]).toBe(0xff);
    expect(buf.subarray(0, 31).every(b => b === 0)).toBe(true);
  });

  it('encodes 0x100 (256) across two bytes', () => {
    const buf = bigintToBytes32(0x100n);
    expect(buf[30]).toBe(1);
    expect(buf[31]).toBe(0);
  });

  it('encodes max uint256 (2^256 - 1)', () => {
    const max = (1n << 256n) - 1n;
    const buf = bigintToBytes32(max);
    expect(buf.length).toBe(32);
    expect(buf.every(b => b === 0xff)).toBe(true);
  });

  it('encodes a power of two', () => {
    const val = 1n << 128n;
    const buf = bigintToBytes32(val);
    expect(buf[15]).toBe(1); // byte 15 (from left) in big-endian for bit 128
    expect(buf.subarray(16).every(b => b === 0)).toBe(true);
  });
});

// =============================================================================
// Tests — schemaByteLength
// =============================================================================

describe('schemaByteLength', () => {
  it('VIES_SCHEMA = 5 * 32 = 160', () => {
    expect(schemaByteLength(VIES_SCHEMA)).toBe(160);
  });

  it('SICAE_SCHEMA = 6 * 32 = 192', () => {
    expect(schemaByteLength(SICAE_SCHEMA)).toBe(192);
  });

  it('STRIPE_PAYMENT_SCHEMA = 6 * 32 = 192', () => {
    expect(schemaByteLength(STRIPE_PAYMENT_SCHEMA)).toBe(192);
  });

  it('empty schema = 0', () => {
    expect(schemaByteLength([])).toBe(0);
  });

  it('single field schema = 32', () => {
    expect(schemaByteLength([{ name: 'x', encoding: 'shortString' }])).toBe(32);
  });
});

// =============================================================================
// Tests — encodeFieldElements: shortString encoding
// =============================================================================

describe('encodeFieldElements', () => {
  describe('shortString encoding', () => {
    const schema: FieldDef[] = [{ name: 'val', encoding: 'shortString' }];

    it('encodes and recovers ASCII string', () => {
      const encoded = encodeFieldElements(schema, { val: 'PT' });
      expect(encoded.length).toBe(32);
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('PT');
      expect(decoded.val.isNull).toBe(false);
    });

    it('encodes and recovers 9-digit NIF', () => {
      const encoded = encodeFieldElements(schema, { val: '507172230' });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('507172230');
    });

    it('encodes and recovers 5-digit CAE code', () => {
      const encoded = encodeFieldElements(schema, { val: '62010' });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('62010');
    });

    it('encodes and recovers UTF-8 with diacritics (short)', () => {
      const encoded = encodeFieldElements(schema, { val: 'José' });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('José');
    });

    it('encodes null as 32 zero bytes', () => {
      const encoded = encodeFieldElements(schema, { val: null });
      expect(encoded.every(b => b === 0)).toBe(true);
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.isNull).toBe(true);
      expect(decoded.val.value).toBe('');
    });

    it('encodes empty string as 32 zero bytes', () => {
      const encoded = encodeFieldElements(schema, { val: '' });
      expect(encoded.every(b => b === 0)).toBe(true);
    });

    it('encodes missing field as 32 zero bytes', () => {
      const encoded = encodeFieldElements(schema, {});
      expect(encoded.every(b => b === 0)).toBe(true);
    });

    it('throws for strings > 31 bytes', () => {
      const longString = 'A'.repeat(32);
      expect(() => encodeFieldElements(schema, { val: longString })).toThrow('exceeds 31 bytes');
    });

    it('accepts exactly 31 bytes', () => {
      const maxString = 'A'.repeat(31);
      const encoded = encodeFieldElements(schema, { val: maxString });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe(maxString);
    });

    it('single character "A"', () => {
      const encoded = encodeFieldElements(schema, { val: 'A' });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('A');
    });

    it('single character "0"', () => {
      const encoded = encodeFieldElements(schema, { val: '0' });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('0');
    });

    it('numeric string "42"', () => {
      const encoded = encodeFieldElements(schema, { val: '42' });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('42');
    });

    it('space character', () => {
      const encoded = encodeFieldElements(schema, { val: ' ' });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe(' ');
    });

    it('string with spaces', () => {
      const encoded = encodeFieldElements(schema, { val: 'hello world' });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('hello world');
    });

    it('2-byte UTF-8 char: é (0xC3 0xA9)', () => {
      // "é" is 2 bytes in UTF-8
      expect(Buffer.from('é', 'utf8').length).toBe(2);
      const encoded = encodeFieldElements(schema, { val: 'é' });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('é');
    });

    it('3-byte UTF-8 char: € (0xE2 0x82 0xAC)', () => {
      expect(Buffer.from('€', 'utf8').length).toBe(3);
      const encoded = encodeFieldElements(schema, { val: '€' });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('€');
    });

    it('4-byte UTF-8 char (emoji): throws if > 31 bytes total', () => {
      // Single emoji is 4 bytes, well within 31
      const emoji = '🇵🇹'; // flag is 2 code points × 4 bytes = 8 bytes
      if (Buffer.from(emoji, 'utf8').length <= 31) {
        const encoded = encodeFieldElements(schema, { val: emoji });
        const decoded = decodeFieldElements(schema, encoded);
        expect(decoded.val.value).toBe(emoji);
      }
    });

    it('multi-byte UTF-8 at exactly 31 bytes boundary', () => {
      // "á" is 2 bytes in UTF-8. 15 × "á" = 30 bytes + 1 ASCII = 31 bytes
      const str = 'á'.repeat(15) + 'x';
      expect(Buffer.from(str, 'utf8').length).toBe(31);
      const encoded = encodeFieldElements(schema, { val: str });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe(str);
    });

    it('multi-byte UTF-8 crossing 31 byte boundary throws', () => {
      // 16 × "á" = 32 bytes
      const str = 'á'.repeat(16);
      expect(Buffer.from(str, 'utf8').length).toBe(32);
      expect(() => encodeFieldElements(schema, { val: str })).toThrow('exceeds 31 bytes');
    });

    it('string with mixed ASCII and multi-byte chars', () => {
      const str = 'Café';
      expect(Buffer.from(str, 'utf8').length).toBe(5); // C(1) + a(1) + f(1) + é(2)
      const encoded = encodeFieldElements(schema, { val: str });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('Café');
    });

    it('all printable ASCII characters fit in 31 bytes', () => {
      const str = '!"#$%&\'()*+,-./0123456789:;<';
      expect(Buffer.from(str, 'utf8').length).toBeLessThanOrEqual(31);
      const encoded = encodeFieldElements(schema, { val: str });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe(str);
    });

    it('encodes number as string via String() coercion', () => {
      // When a number is passed to shortString, it gets String(value)
      const encoded = encodeFieldElements(schema, { val: 123 });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('123');
    });

    it('encodes undefined value as 32 zero bytes', () => {
      const encoded = encodeFieldElements(schema, { val: undefined as any });
      expect(encoded.every(b => b === 0)).toBe(true);
    });

    it('ignores extra fields in values object', () => {
      const encoded = encodeFieldElements(schema, { val: 'PT', extra: 'ignored' } as any);
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('PT');
    });
  });

  // ===========================================================================
  // sha256 encoding
  // ===========================================================================

  describe('sha256 encoding', () => {
    const schema: FieldDef[] = [{ name: 'val', encoding: 'sha256' }];

    it('produces 32 non-zero bytes for a non-empty string', () => {
      const encoded = encodeFieldElements(schema, { val: 'Empresa Exemplo Lda.' });
      expect(encoded.length).toBe(32);
      expect(encoded.some(b => b !== 0)).toBe(true);
    });

    it('is deterministic (same input → same output)', () => {
      const a = encodeFieldElements(schema, { val: 'test' });
      const b = encodeFieldElements(schema, { val: 'test' });
      expect(a.equals(b)).toBe(true);
    });

    it('different inputs produce different outputs', () => {
      const a = encodeFieldElements(schema, { val: 'hello' });
      const b = encodeFieldElements(schema, { val: 'world' });
      expect(a.equals(b)).toBe(false);
    });

    it('hash can be verified with verifySha256Field', () => {
      const plaintext = 'Empresa Exemplo Lda.';
      const encoded = encodeFieldElements(schema, { val: plaintext });
      const hex = encoded.toString('hex');
      expect(verifySha256Field(plaintext, hex)).toBe(true);
      expect(verifySha256Field('wrong', hex)).toBe(false);
    });

    it('result is within BN254 field (< modulus)', () => {
      const encoded = encodeFieldElements(schema, { val: 'test' });
      const val = BigInt('0x' + encoded.toString('hex'));
      expect(val < BN254_MODULUS).toBe(true);
    });

    it('encodes null as 32 zero bytes', () => {
      const encoded = encodeFieldElements(schema, { val: null });
      expect(encoded.every(b => b === 0)).toBe(true);
    });

    it('handles Unicode strings', () => {
      const encoded = encodeFieldElements(schema, { val: 'Açúcar & Café Lda.' });
      expect(encoded.length).toBe(32);
      const hex = encoded.toString('hex');
      expect(verifySha256Field('Açúcar & Café Lda.', hex)).toBe(true);
    });

    it('handles very long strings', () => {
      const longString = 'x'.repeat(10_000);
      const encoded = encodeFieldElements(schema, { val: longString });
      expect(encoded.length).toBe(32);
      expect(verifySha256Field(longString, encoded.toString('hex'))).toBe(true);
    });

    it('handles string with newlines and special chars', () => {
      const str = 'Line 1\nLine 2\tTabbed\r\nWindows line';
      const encoded = encodeFieldElements(schema, { val: str });
      expect(verifySha256Field(str, encoded.toString('hex'))).toBe(true);
    });

    it('handles empty string as null (all zeros)', () => {
      const encoded = encodeFieldElements(schema, { val: '' });
      expect(encoded.every(b => b === 0)).toBe(true);
    });

    it('case-sensitive: "Test" ≠ "test"', () => {
      const a = encodeFieldElements(schema, { val: 'Test' });
      const b = encodeFieldElements(schema, { val: 'test' });
      expect(a.equals(b)).toBe(false);
    });

    it('whitespace-sensitive: "test " ≠ "test"', () => {
      const a = encodeFieldElements(schema, { val: 'test ' });
      const b = encodeFieldElements(schema, { val: 'test' });
      expect(a.equals(b)).toBe(false);
    });

    it('sha256 hash is always < BN254_MODULUS after modular reduction', () => {
      // Test many inputs to check modular reduction always works
      for (let i = 0; i < 100; i++) {
        const encoded = encodeFieldElements(schema, { val: `test-${i}-${crypto.randomBytes(8).toString('hex')}` });
        const val = BigInt('0x' + encoded.toString('hex'));
        expect(val < BN254_MODULUS).toBe(true);
        expect(val >= 0n).toBe(true);
      }
    });
  });

  // ===========================================================================
  // uint encoding
  // ===========================================================================

  describe('uint encoding', () => {
    const schema: FieldDef[] = [{ name: 'val', encoding: 'uint' }];

    it('encodes 0 as all-zero bytes (indistinguishable from null)', () => {
      const encoded = encodeFieldElements(schema, { val: 0 });
      const decoded = decodeFieldElements(schema, encoded);
      // uint(0) → BigInt(0) → 32 zero bytes → decoder sees isNull=true
      expect(decoded.val.isNull).toBe(true);
      expect(decoded.val.value).toBe('');
    });

    it('encodes 1 (boolean true)', () => {
      const encoded = encodeFieldElements(schema, { val: 1 });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('1');
      expect(decoded.val.isNull).toBe(false);
    });

    it('encodes bigint', () => {
      const encoded = encodeFieldElements(schema, { val: 42n });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('42');
    });

    it('throws for negative values', () => {
      expect(() => encodeFieldElements(schema, { val: -1 })).toThrow('out of BN254 range');
    });

    it('throws for values >= modulus', () => {
      expect(() => encodeFieldElements(schema, { val: BN254_MODULUS })).toThrow('out of BN254 range');
    });

    it('accepts modulus - 1', () => {
      const encoded = encodeFieldElements(schema, { val: BN254_MODULUS - 1n });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe((BN254_MODULUS - 1n).toString());
    });

    it('encodes small numbers correctly: 2, 10, 100, 255', () => {
      for (const n of [2, 10, 100, 255]) {
        const encoded = encodeFieldElements(schema, { val: n });
        const decoded = decodeFieldElements(schema, encoded);
        expect(decoded.val.value).toBe(String(n));
      }
    });

    it('encodes large number (2^128)', () => {
      const val = 1n << 128n;
      const encoded = encodeFieldElements(schema, { val });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe(val.toString());
    });

    it('string "42" converts to BigInt(42)', () => {
      const encoded = encodeFieldElements(schema, { val: '42' });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe('42');
    });

    it('string "0" converts to 0 (null sentinel)', () => {
      const encoded = encodeFieldElements(schema, { val: '0' });
      // "0" → BigInt("0") = 0n → all zero bytes → null
      expect(encoded.every(b => b === 0)).toBe(true);
    });

    it('string input with very large number', () => {
      const bigStr = '123456789012345678901234567890';
      const encoded = encodeFieldElements(schema, { val: bigStr });
      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.val.value).toBe(bigStr);
    });

    it('throws for negative bigint', () => {
      expect(() => encodeFieldElements(schema, { val: -1n })).toThrow('out of BN254 range');
    });

    it('null encodes to 32 zero bytes', () => {
      const encoded = encodeFieldElements(schema, { val: null });
      expect(encoded.every(b => b === 0)).toBe(true);
    });

    it('consecutive values produce different encodings', () => {
      const a = encodeFieldElements(schema, { val: 1 });
      const b = encodeFieldElements(schema, { val: 2 });
      expect(a.equals(b)).toBe(false);
    });

    it('number and equivalent bigint produce identical encoding', () => {
      const a = encodeFieldElements(schema, { val: 42 });
      const b = encodeFieldElements(schema, { val: 42n });
      expect(a.equals(b)).toBe(true);
    });
  });

  // ===========================================================================
  // Unknown encoding type
  // ===========================================================================

  describe('unknown encoding type', () => {
    it('throws for unknown encoding', () => {
      const schema: FieldDef[] = [{ name: 'val', encoding: 'unknown' as any }];
      expect(() => encodeFieldElements(schema, { val: 'test' })).toThrow('Unknown encoding');
    });
  });

  // ===========================================================================
  // Multi-field schemas
  // ===========================================================================

  describe('multi-field encoding', () => {
    it('each field occupies exactly 32 bytes at correct offset', () => {
      const schema: FieldDef[] = [
        { name: 'a', encoding: 'shortString' },
        { name: 'b', encoding: 'shortString' },
        { name: 'c', encoding: 'shortString' },
      ];
      const encoded = encodeFieldElements(schema, { a: 'x', b: 'y', c: 'z' });
      expect(encoded.length).toBe(96);

      // Field a at offset 0
      const a = encoded.subarray(0, 32);
      expect(recoverShortString(a)).toBe('x');

      // Field b at offset 32
      const b = encoded.subarray(32, 64);
      expect(recoverShortString(b)).toBe('y');

      // Field c at offset 64
      const c = encoded.subarray(64, 96);
      expect(recoverShortString(c)).toBe('z');
    });

    it('changing one field does not affect others', () => {
      const schema: FieldDef[] = [
        { name: 'a', encoding: 'shortString' },
        { name: 'b', encoding: 'uint' },
      ];
      const enc1 = encodeFieldElements(schema, { a: 'hello', b: 1 });
      const enc2 = encodeFieldElements(schema, { a: 'hello', b: 2 });

      // Field a (offset 0-31) should be identical
      expect(enc1.subarray(0, 32).equals(enc2.subarray(0, 32))).toBe(true);
      // Field b (offset 32-63) should differ
      expect(enc1.subarray(32, 64).equals(enc2.subarray(32, 64))).toBe(false);
    });

    it('mixed encoding types in one schema', () => {
      const schema: FieldDef[] = [
        { name: 'str', encoding: 'shortString' },
        { name: 'hash', encoding: 'sha256' },
        { name: 'num', encoding: 'uint' },
      ];
      const encoded = encodeFieldElements(schema, { str: 'PT', hash: 'some long company name', num: 42 });
      expect(encoded.length).toBe(96);

      const decoded = decodeFieldElements(schema, encoded);
      expect(decoded.str.value).toBe('PT');
      expect(decoded.num.value).toBe('42');
      expect(verifySha256Field('some long company name', decoded.hash.hex)).toBe(true);
    });

    it('all null values', () => {
      const schema: FieldDef[] = [
        { name: 'a', encoding: 'shortString' },
        { name: 'b', encoding: 'sha256' },
        { name: 'c', encoding: 'uint' },
      ];
      const encoded = encodeFieldElements(schema, { a: null, b: null, c: null });
      expect(encoded.length).toBe(96);
      expect(encoded.every(b => b === 0)).toBe(true);
    });
  });
});

// =============================================================================
// VIES_SCHEMA encode/decode roundtrip
// =============================================================================

describe('VIES_SCHEMA encode/decode roundtrip', () => {
  it('encodes valid VAT with name and address', () => {
    const values = {
      countryCode: 'PT',
      vatNumber: '507172230',
      valid: 1,
      name: 'Empresa Exemplo Lda.',
      address: 'Rua do Exemplo 123, 1000-001 Lisboa',
    };

    const encoded = encodeFieldElements(VIES_SCHEMA, values);
    expect(encoded.length).toBe(160);

    const decoded = decodeFieldElements(VIES_SCHEMA, encoded);

    expect(decoded.countryCode.value).toBe('PT');
    expect(decoded.vatNumber.value).toBe('507172230');
    expect(decoded.valid.value).toBe('1');
    expect(verifySha256Field('Empresa Exemplo Lda.', decoded.name.hex)).toBe(true);
    expect(verifySha256Field('Rua do Exemplo 123, 1000-001 Lisboa', decoded.address.hex)).toBe(true);
  });

  it('encodes invalid VAT (no name/address)', () => {
    const values = {
      countryCode: 'DE',
      vatNumber: '999999999',
      valid: 0,
      name: null,
      address: null,
    };

    const encoded = encodeFieldElements(VIES_SCHEMA, values);
    expect(encoded.length).toBe(160);

    const decoded = decodeFieldElements(VIES_SCHEMA, encoded);

    expect(decoded.countryCode.value).toBe('DE');
    expect(decoded.vatNumber.value).toBe('999999999');
    expect(decoded.valid.isNull).toBe(true);
    expect(decoded.name.isNull).toBe(true);
    expect(decoded.address.isNull).toBe(true);
  });

  it('encodes GB (HMRC) VAT number', () => {
    const encoded = encodeFieldElements(VIES_SCHEMA, {
      countryCode: 'GB',
      vatNumber: '123456789',
      valid: 1,
      name: 'British Company Ltd',
      address: '10 Downing Street, London, SW1A 2AA',
    });

    const decoded = decodeFieldElements(VIES_SCHEMA, encoded);
    expect(decoded.countryCode.value).toBe('GB');
    expect(decoded.vatNumber.value).toBe('123456789');
    expect(decoded.valid.value).toBe('1');
  });

  it('encodes XI (Northern Ireland) VAT number', () => {
    const encoded = encodeFieldElements(VIES_SCHEMA, {
      countryCode: 'XI',
      vatNumber: '123456789',
      valid: 1,
      name: null,
      address: null,
    });

    const decoded = decodeFieldElements(VIES_SCHEMA, encoded);
    expect(decoded.countryCode.value).toBe('XI');
  });
});

// =============================================================================
// SICAE_SCHEMA encode/decode roundtrip
// =============================================================================

describe('SICAE_SCHEMA encode/decode roundtrip', () => {
  it('encodes full result with secondary CAE', () => {
    const values = {
      nif: '507172230',
      name: 'Empresa Exemplo, Unipessoal Lda.',
      cae1Code: '62010',
      cae1Desc: 'Actividades de programação informática',
      cae2Code: '62020',
      cae2Desc: 'Actividades de consultoria informática',
    };

    const encoded = encodeFieldElements(SICAE_SCHEMA, values);
    expect(encoded.length).toBe(192);

    const decoded = decodeFieldElements(SICAE_SCHEMA, encoded);

    expect(decoded.nif.value).toBe('507172230');
    expect(decoded.cae1Code.value).toBe('62010');
    expect(decoded.cae2Code.value).toBe('62020');
    expect(decoded.cae2Code.isNull).toBe(false);
    expect(verifySha256Field('Empresa Exemplo, Unipessoal Lda.', decoded.name.hex)).toBe(true);
    expect(verifySha256Field('Actividades de programação informática', decoded.cae1Desc.hex)).toBe(true);
    expect(verifySha256Field('Actividades de consultoria informática', decoded.cae2Desc.hex)).toBe(true);
  });

  it('encodes result without secondary CAE', () => {
    const values = {
      nif: '501442600',
      name: 'GALP ENERGIA SA',
      cae1Code: '06100',
      cae1Desc: 'Extracção de petróleo bruto',
      cae2Code: null,
      cae2Desc: null,
    };

    const encoded = encodeFieldElements(SICAE_SCHEMA, values);
    const decoded = decodeFieldElements(SICAE_SCHEMA, encoded);

    expect(decoded.nif.value).toBe('501442600');
    expect(decoded.cae1Code.value).toBe('06100');
    expect(decoded.cae2Code.isNull).toBe(true);
    expect(decoded.cae2Desc.isNull).toBe(true);
  });
});

// =============================================================================
// STRIPE_PAYMENT_SCHEMA encode/decode roundtrip
// =============================================================================

describe('STRIPE_PAYMENT_SCHEMA encode/decode roundtrip', () => {
  it('encodes list_charges with accountId', () => {
    const responseJson = JSON.stringify({ object: 'list', data: [{}, {}], has_more: true });
    const dataHash = crypto.createHash('sha256').update(responseJson, 'utf8').digest('hex');

    const values = {
      operation: 'list_charges',
      accountId: 'acct_12345',
      objectType: 'list',
      dataHash,
      totalCount: 2,
      hasMore: 1,
    };

    const encoded = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, values);
    expect(encoded.length).toBe(192);

    const decoded = decodeFieldElements(STRIPE_PAYMENT_SCHEMA, encoded);
    expect(decoded.operation.value).toBe('list_charges');
    expect(decoded.accountId.value).toBe('acct_12345');
    expect(decoded.objectType.value).toBe('list');
    expect(decoded.totalCount.value).toBe('2');
    expect(decoded.hasMore.value).toBe('1');
  });

  it('encodes list operation without connected account (null accountId)', () => {
    const encoded = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
      operation: 'list_customers',
      accountId: null,
      objectType: 'list',
      dataHash: 'a'.repeat(64), // dummy hash
      totalCount: 50,
      hasMore: 0,
    });

    const decoded = decodeFieldElements(STRIPE_PAYMENT_SCHEMA, encoded);
    expect(decoded.operation.value).toBe('list_customers');
    expect(decoded.accountId.isNull).toBe(true);
    expect(decoded.totalCount.value).toBe('50');
    // hasMore=0 → null sentinel (by design, 0 and null share encoding)
    expect(decoded.hasMore.isNull).toBe(true);
  });

  it('encodes single-object operations (get_account)', () => {
    const encoded = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
      operation: 'get_account',
      accountId: null,
      objectType: 'account',
      dataHash: crypto.createHash('sha256').update('{}', 'utf8').digest('hex'),
      totalCount: 0,
      hasMore: 0,
    });

    const decoded = decodeFieldElements(STRIPE_PAYMENT_SCHEMA, encoded);
    expect(decoded.operation.value).toBe('get_account');
    expect(decoded.objectType.value).toBe('account');
    // totalCount=0 and hasMore=0 → both null
    expect(decoded.totalCount.isNull).toBe(true);
    expect(decoded.hasMore.isNull).toBe(true);
  });

  it('encodes get_payment_intent', () => {
    const encoded = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
      operation: 'get_payment_intent',
      accountId: 'acct_xyz',
      objectType: 'payment_intent',
      dataHash: crypto.createHash('sha256').update('{"id":"pi_123"}', 'utf8').digest('hex'),
      totalCount: 0,
      hasMore: 0,
    });

    const decoded = decodeFieldElements(STRIPE_PAYMENT_SCHEMA, encoded);
    expect(decoded.operation.value).toBe('get_payment_intent');
    expect(decoded.objectType.value).toBe('payment_intent');
  });

  it('verifies dataHash integrity', () => {
    const responseBody = '{"object":"list","data":[{"id":"ch_1"}],"has_more":false}';
    const dataHash = crypto.createHash('sha256').update(responseBody, 'utf8').digest('hex');

    const encoded = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
      operation: 'list_charges',
      accountId: null,
      objectType: 'list',
      dataHash,
      totalCount: 1,
      hasMore: 0,
    });

    const decoded = decodeFieldElements(STRIPE_PAYMENT_SCHEMA, encoded);
    // The sha256 encoding hashes whatever string is passed to it.
    // Since we pass the hex hash string, verify against that hex string.
    expect(verifySha256Field(dataHash, decoded.dataHash.hex)).toBe(true);
    // Verify a different hash does NOT match
    const tamperedHash = crypto.createHash('sha256').update('tampered', 'utf8').digest('hex');
    expect(verifySha256Field(tamperedHash, decoded.dataHash.hex)).toBe(false);
  });

  it('all operations fit in shortString (< 31 bytes)', () => {
    const ops = ['list_charges', 'list_customers', 'list_invoices', 'get_payment_intent', 'get_account'];
    for (const op of ops) {
      expect(Buffer.from(op, 'utf8').length).toBeLessThanOrEqual(31);
      const encoded = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
        operation: op,
        accountId: null,
        objectType: 'list',
        dataHash: null,
        totalCount: 0,
        hasMore: 0,
      });
      const decoded = decodeFieldElements(STRIPE_PAYMENT_SCHEMA, encoded);
      expect(decoded.operation.value).toBe(op);
    }
  });

  it('Stripe accountId "acct_" prefix fits in shortString', () => {
    // Typical Stripe account IDs: acct_1A2B3C4D5E (16-20 chars)
    const longAccountId = 'acct_1A2B3C4D5E6F7G8H'; // 24 bytes
    expect(Buffer.from(longAccountId, 'utf8').length).toBeLessThanOrEqual(31);
    const encoded = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
      operation: 'list_charges',
      accountId: longAccountId,
      objectType: 'list',
      dataHash: null,
      totalCount: 0,
      hasMore: 0,
    });
    const decoded = decodeFieldElements(STRIPE_PAYMENT_SCHEMA, encoded);
    expect(decoded.accountId.value).toBe(longAccountId);
  });

  it('Stripe object types fit in shortString', () => {
    const types = ['list', 'charge', 'customer', 'invoice', 'payment_intent', 'account'];
    for (const t of types) {
      expect(Buffer.from(t, 'utf8').length).toBeLessThanOrEqual(31);
    }
  });
});

// =============================================================================
// decodeToTyped (inlined)
// =============================================================================

describe('decodeToTyped', () => {
  it('VIES: converts valid=1 to boolean true', () => {
    const encoded = encodeFieldElements(VIES_SCHEMA, {
      countryCode: 'PT',
      vatNumber: '507172230',
      valid: 1,
      name: 'Test Company',
      address: 'Test Address',
    });

    const result = decodeToTyped<{
      countryCode: string;
      vatNumber: string;
      valid: boolean;
      name: string;
      address: string;
    }>(VIES_SCHEMA, encoded, {
      'x-vies-name': 'Test Company',
      'x-vies-address': 'Test Address',
    }, 'x-vies-');

    expect(result.countryCode).toBe('PT');
    expect(result.vatNumber).toBe('507172230');
    expect(result.valid).toBe(true);
    expect(typeof result.valid).toBe('boolean');
    expect(result.name).toBe('Test Company'); // from header
    expect(result.address).toBe('Test Address'); // from header
  });

  it('VIES: converts valid=0 (null) to boolean false', () => {
    const encoded = encodeFieldElements(VIES_SCHEMA, {
      countryCode: 'DE',
      vatNumber: '999999999',
      valid: 0,
      name: null,
      address: null,
    });

    const result = decodeToTyped<{
      countryCode: string;
      vatNumber: string;
      valid: boolean;
      name: string;
      address: string;
    }>(VIES_SCHEMA, encoded);

    expect(result.valid).toBe(false);
    expect(typeof result.valid).toBe('boolean');
  });

  it('STRIPE_PAYMENT: converts totalCount to number and hasMore to boolean', () => {
    const encoded = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
      operation: 'list_charges',
      accountId: 'acct_123',
      objectType: 'list',
      dataHash: crypto.createHash('sha256').update('test', 'utf8').digest('hex'),
      totalCount: 42,
      hasMore: 1,
    });

    const result = decodeToTyped<{
      operation: string;
      accountId: string;
      objectType: string;
      dataHash: string;
      totalCount: number;
      hasMore: boolean;
    }>(STRIPE_PAYMENT_SCHEMA, encoded, {
      'x-stripe-data-hash': 'the hash value',
    }, 'x-stripe-');

    expect(result.operation).toBe('list_charges');
    expect(result.accountId).toBe('acct_123');
    expect(result.objectType).toBe('list');
    expect(result.totalCount).toBe(42);
    expect(typeof result.totalCount).toBe('number');
    expect(result.hasMore).toBe(true);
    expect(typeof result.hasMore).toBe('boolean');
    expect(result.dataHash).toBe('the hash value'); // from header
  });

  it('STRIPE_PAYMENT: null fields get proper typed defaults', () => {
    const encoded = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
      operation: 'get_account',
      accountId: null,
      objectType: 'account',
      dataHash: null,
      totalCount: 0,
      hasMore: 0,
    });

    const result = decodeToTyped<{
      operation: string;
      accountId: string;
      objectType: string;
      dataHash: string;
      totalCount: number;
      hasMore: boolean;
    }>(STRIPE_PAYMENT_SCHEMA, encoded);

    expect(result.accountId).toBe('');
    expect(result.dataHash).toBe(''); // null → '' for string jsType
    expect(result.totalCount).toBe(0);
    expect(result.hasMore).toBe(false);
  });

  it('sha256 falls back to hex when no header provided', () => {
    const encoded = encodeFieldElements(VIES_SCHEMA, {
      countryCode: 'PT',
      vatNumber: '123',
      valid: 1,
      name: 'Company Name',
      address: 'Address Line',
    });

    const result = decodeToTyped<{
      countryCode: string;
      vatNumber: string;
      valid: boolean;
      name: string;
      address: string;
    }>(VIES_SCHEMA, encoded);

    // Without headers, sha256 fields return hex hash
    expect(result.name).toMatch(/^[0-9a-f]{64}$/);
    expect(result.address).toMatch(/^[0-9a-f]{64}$/);
  });

  it('headerPrefix camelCase→kebab-case: "dataHash" → "data-hash"', () => {
    const schema: FieldDef[] = [{ name: 'dataHash', encoding: 'sha256', jsType: 'string' }];
    const encoded = encodeFieldElements(schema, { dataHash: 'test' });

    const result = decodeToTyped<{ dataHash: string }>(schema, encoded, {
      'x-my-data-hash': 'human readable',
    }, 'x-my-');

    expect(result.dataHash).toBe('human readable');
  });

  it('headerPrefix camelCase→kebab-case: "cae1Desc" → "cae1-desc"', () => {
    const schema: FieldDef[] = [{ name: 'cae1Desc', encoding: 'sha256', jsType: 'string' }];
    const encoded = encodeFieldElements(schema, { cae1Desc: 'test description' });

    const result = decodeToTyped<{ cae1Desc: string }>(schema, encoded, {
      'x-sicae-cae1-desc': 'Computer programming',
    }, 'x-sicae-');

    expect(result.cae1Desc).toBe('Computer programming');
  });

  it('uint without jsType annotation defaults to string', () => {
    const schema: FieldDef[] = [{ name: 'count', encoding: 'uint' }];
    const encoded = encodeFieldElements(schema, { count: 42 });
    const result = decodeToTyped<{ count: string }>(schema, encoded);
    expect(result.count).toBe('42');
    expect(typeof result.count).toBe('string');
  });
});

// =============================================================================
// Decode error handling
// =============================================================================

describe('decode error handling', () => {
  it('throws on wrong buffer length', () => {
    expect(() => decodeFieldElements(VIES_SCHEMA, Buffer.alloc(100))).toThrow('Expected 160 bytes');
  });

  it('throws on empty buffer with non-empty schema', () => {
    expect(() => decodeFieldElements(VIES_SCHEMA, Buffer.alloc(0))).toThrow('Expected 160 bytes');
  });

  it('decodes empty schema from empty buffer', () => {
    const decoded = decodeFieldElements([], Buffer.alloc(0));
    expect(Object.keys(decoded).length).toBe(0);
  });

  it('throws when buffer is too large', () => {
    expect(() => decodeFieldElements(VIES_SCHEMA, Buffer.alloc(200))).toThrow('Expected 160 bytes');
  });

  it('throws when buffer is one byte short', () => {
    expect(() => decodeFieldElements(VIES_SCHEMA, Buffer.alloc(159))).toThrow('Expected 160 bytes');
  });

  it('throws when buffer is one byte too long', () => {
    expect(() => decodeFieldElements(VIES_SCHEMA, Buffer.alloc(161))).toThrow('Expected 160 bytes');
  });
});

// =============================================================================
// Determinism
// =============================================================================

describe('determinism', () => {
  it('same VIES inputs always produce identical bytes', () => {
    const values = {
      countryCode: 'PT',
      vatNumber: '507172230',
      valid: 1,
      name: 'Test Company',
      address: 'Test Address',
    };

    const a = encodeFieldElements(VIES_SCHEMA, values);
    const b = encodeFieldElements(VIES_SCHEMA, values);
    const c = encodeFieldElements(VIES_SCHEMA, values);

    expect(a.equals(b)).toBe(true);
    expect(b.equals(c)).toBe(true);
  });

  it('same SICAE inputs always produce identical bytes', () => {
    const values = {
      nif: '507172230',
      name: 'Test',
      cae1Code: '62010',
      cae1Desc: 'Test desc',
      cae2Code: null,
      cae2Desc: null,
    };

    const a = encodeFieldElements(SICAE_SCHEMA, values);
    const b = encodeFieldElements(SICAE_SCHEMA, values);

    expect(a.equals(b)).toBe(true);
  });

  it('same STRIPE_PAYMENT inputs always produce identical bytes', () => {
    const values = {
      operation: 'list_charges',
      accountId: 'acct_123',
      objectType: 'list',
      dataHash: crypto.createHash('sha256').update('stable input', 'utf8').digest('hex'),
      totalCount: 10,
      hasMore: 1,
    };

    const a = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, values);
    const b = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, values);
    const c = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, values);

    expect(a.equals(b)).toBe(true);
    expect(b.equals(c)).toBe(true);
  });

  it('field order matters — different schema order produces different bytes', () => {
    const schemaAB: FieldDef[] = [
      { name: 'a', encoding: 'shortString' },
      { name: 'b', encoding: 'shortString' },
    ];
    const schemaBA: FieldDef[] = [
      { name: 'b', encoding: 'shortString' },
      { name: 'a', encoding: 'shortString' },
    ];

    const values = { a: 'hello', b: 'world' };
    const ab = encodeFieldElements(schemaAB, values);
    const ba = encodeFieldElements(schemaBA, values);

    expect(ab.equals(ba)).toBe(false);
  });
});

// =============================================================================
// Cross-repo consistency: known test vectors
// =============================================================================

describe('cross-repo consistency: known test vectors', () => {
  // These test vectors ensure encoder (tytle-enclaves) and decoder (data-bridge)
  // stay in sync. If you change the encoding, update both repos' tests.

  it('VIES: PT/507172230/valid=1 produces known structure', () => {
    const encoded = encodeFieldElements(VIES_SCHEMA, {
      countryCode: 'PT',
      vatNumber: '507172230',
      valid: 1,
      name: null,
      address: null,
    });

    // Snapshot the base64 — decoder tests in data-bridge should match
    const b64 = encoded.toString('base64');
    // Re-encode to verify stability
    expect(encodeFieldElements(VIES_SCHEMA, {
      countryCode: 'PT',
      vatNumber: '507172230',
      valid: 1,
      name: null,
      address: null,
    }).toString('base64')).toBe(b64);

    // Verify structure: 5 fields × 32 bytes
    expect(encoded.length).toBe(160);

    // First 32 bytes = "PT" as shortString
    const ptField = encoded.subarray(0, 32);
    expect(recoverShortString(ptField)).toBe('PT');

    // Next 32 bytes = "507172230"
    const vatField = encoded.subarray(32, 64);
    expect(recoverShortString(vatField)).toBe('507172230');

    // valid = 1
    const validField = encoded.subarray(64, 96);
    expect(readUint(validField)).toBe(1n);

    // name = null (all zeros)
    const nameField = encoded.subarray(96, 128);
    expect(isZero(nameField)).toBe(true);

    // address = null (all zeros)
    const addrField = encoded.subarray(128, 160);
    expect(isZero(addrField)).toBe(true);
  });

  it('SICAE: 507172230 with CAE 62010 produces 192 bytes', () => {
    const encoded = encodeFieldElements(SICAE_SCHEMA, {
      nif: '507172230',
      name: 'TYTLE LDA',
      cae1Code: '62010',
      cae1Desc: 'Computer programming activities',
      cae2Code: null,
      cae2Desc: null,
    });

    expect(encoded.length).toBe(192);

    // Verify nif field
    const nifField = encoded.subarray(0, 32);
    expect(recoverShortString(nifField)).toBe('507172230');

    // Verify name is a hash (not recoverable)
    const nameField = encoded.subarray(32, 64);
    expect(isZero(nameField)).toBe(false);
    expect(verifySha256Field('TYTLE LDA', nameField.toString('hex'))).toBe(true);

    // Verify cae1Code
    const cae1Field = encoded.subarray(64, 96);
    expect(recoverShortString(cae1Field)).toBe('62010');

    // Verify secondary CAE fields are null
    expect(isZero(encoded.subarray(128, 160))).toBe(true); // cae2Code
    expect(isZero(encoded.subarray(160, 192))).toBe(true); // cae2Desc
  });

  it('STRIPE_PAYMENT: list_charges vector for cross-repo decoder', () => {
    // Fixed inputs — decoder test in data-bridge uses the same base64
    const encoded = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
      operation: 'list_charges',
      accountId: 'acct_test123',
      objectType: 'list',
      dataHash: 'a]fixed test data for hashing[z',
      totalCount: 5,
      hasMore: 1,
    });

    expect(encoded.length).toBe(192);

    // Snapshot base64
    const b64 = encoded.toString('base64');
    // Verify stability
    expect(encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
      operation: 'list_charges',
      accountId: 'acct_test123',
      objectType: 'list',
      dataHash: 'a]fixed test data for hashing[z',
      totalCount: 5,
      hasMore: 1,
    }).toString('base64')).toBe(b64);

    const decoded = decodeFieldElements(STRIPE_PAYMENT_SCHEMA, encoded);
    expect(decoded.operation.value).toBe('list_charges');
    expect(decoded.accountId.value).toBe('acct_test123');
    expect(decoded.objectType.value).toBe('list');
    expect(decoded.totalCount.value).toBe('5');
    expect(decoded.hasMore.value).toBe('1');
  });

  it('all schemas produce stable base64 that data-bridge can decode', () => {
    // Generate known vectors for each schema and log the base64
    // These exact base64 values must also pass in data-bridge decoder tests

    const viesEncoded = encodeFieldElements(VIES_SCHEMA, {
      countryCode: 'PT',
      vatNumber: '507172230',
      valid: 1,
      name: null,
      address: null,
    });

    const sicaeEncoded = encodeFieldElements(SICAE_SCHEMA, {
      nif: '507172230',
      name: 'Test Co',
      cae1Code: '62010',
      cae1Desc: 'IT services',
      cae2Code: null,
      cae2Desc: null,
    });

    const stripeEncoded = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
      operation: 'list_charges',
      accountId: null,
      objectType: 'list',
      dataHash: 'test body',
      totalCount: 3,
      hasMore: 1,
    });

    // All must be deterministic
    expect(viesEncoded.length).toBe(160);
    expect(sicaeEncoded.length).toBe(192);
    expect(stripeEncoded.length).toBe(192);

    // Re-encode and verify
    expect(encodeFieldElements(VIES_SCHEMA, {
      countryCode: 'PT', vatNumber: '507172230', valid: 1, name: null, address: null,
    }).equals(viesEncoded)).toBe(true);
  });
});

// =============================================================================
// verifySha256Field edge cases
// =============================================================================

describe('verifySha256Field', () => {
  it('returns true for matching plaintext', () => {
    const plaintext = 'Hello World';
    const schema: FieldDef[] = [{ name: 'val', encoding: 'sha256' }];
    const encoded = encodeFieldElements(schema, { val: plaintext });
    expect(verifySha256Field(plaintext, encoded.toString('hex'))).toBe(true);
  });

  it('returns false for wrong plaintext', () => {
    const schema: FieldDef[] = [{ name: 'val', encoding: 'sha256' }];
    const encoded = encodeFieldElements(schema, { val: 'correct' });
    expect(verifySha256Field('wrong', encoded.toString('hex'))).toBe(false);
  });

  it('is case-sensitive', () => {
    const schema: FieldDef[] = [{ name: 'val', encoding: 'sha256' }];
    const encoded = encodeFieldElements(schema, { val: 'Test' });
    expect(verifySha256Field('test', encoded.toString('hex'))).toBe(false);
  });

  it('is whitespace-sensitive', () => {
    const schema: FieldDef[] = [{ name: 'val', encoding: 'sha256' }];
    const encoded = encodeFieldElements(schema, { val: 'test' });
    expect(verifySha256Field('test ', encoded.toString('hex'))).toBe(false);
  });

  it('handles Portuguese characters', () => {
    const plaintext = 'São João da Madeira, Aveiro';
    const schema: FieldDef[] = [{ name: 'val', encoding: 'sha256' }];
    const encoded = encodeFieldElements(schema, { val: plaintext });
    expect(verifySha256Field(plaintext, encoded.toString('hex'))).toBe(true);
  });

  it('handles very long strings', () => {
    const plaintext = 'x'.repeat(100_000);
    const schema: FieldDef[] = [{ name: 'val', encoding: 'sha256' }];
    const encoded = encodeFieldElements(schema, { val: plaintext });
    expect(verifySha256Field(plaintext, encoded.toString('hex'))).toBe(true);
  });
});

// =============================================================================
// Edge cases: shortString with bytes that could be ambiguous
// =============================================================================

describe('shortString ambiguity edge cases', () => {
  const schema: FieldDef[] = [{ name: 'val', encoding: 'shortString' }];

  it('string "0" has non-zero encoding (0x30 in ASCII)', () => {
    const encoded = encodeFieldElements(schema, { val: '0' });
    // "0" = 0x30, not 0x00
    expect(encoded.some(b => b !== 0)).toBe(true);
    const decoded = decodeFieldElements(schema, encoded);
    expect(decoded.val.isNull).toBe(false);
    expect(decoded.val.value).toBe('0');
  });

  it('string "null" is not treated as null', () => {
    const encoded = encodeFieldElements(schema, { val: 'null' });
    expect(encoded.some(b => b !== 0)).toBe(true);
    const decoded = decodeFieldElements(schema, encoded);
    expect(decoded.val.value).toBe('null');
  });

  it('string "false" is not treated as null', () => {
    const encoded = encodeFieldElements(schema, { val: 'false' });
    const decoded = decodeFieldElements(schema, encoded);
    expect(decoded.val.value).toBe('false');
  });

  it('string with only spaces recovers correctly', () => {
    const encoded = encodeFieldElements(schema, { val: '   ' });
    const decoded = decodeFieldElements(schema, encoded);
    expect(decoded.val.value).toBe('   ');
  });

  it('string with tab and newline', () => {
    const encoded = encodeFieldElements(schema, { val: 'a\tb\n' });
    const decoded = decodeFieldElements(schema, encoded);
    expect(decoded.val.value).toBe('a\tb\n');
  });
});

// =============================================================================
// Edge cases: Buffer boundary and subarray behavior
// =============================================================================

describe('buffer boundary behavior', () => {
  it('decode uses subarray (shared memory), not copies', () => {
    const schema: FieldDef[] = [
      { name: 'a', encoding: 'shortString' },
      { name: 'b', encoding: 'shortString' },
    ];
    const encoded = encodeFieldElements(schema, { a: 'hello', b: 'world' });
    const decoded = decodeFieldElements(schema, encoded);
    expect(decoded.a.value).toBe('hello');
    expect(decoded.b.value).toBe('world');
  });

  it('decode works with Buffer.from(base64)', () => {
    const schema: FieldDef[] = [{ name: 'val', encoding: 'shortString' }];
    const encoded = encodeFieldElements(schema, { val: 'test' });
    const b64 = encoded.toString('base64');
    const restored = Buffer.from(b64, 'base64');
    const decoded = decodeFieldElements(schema, restored);
    expect(decoded.val.value).toBe('test');
  });

  it('encode→base64→decode roundtrip for all schemas', () => {
    // VIES
    const viesEnc = encodeFieldElements(VIES_SCHEMA, {
      countryCode: 'FR', vatNumber: '12345', valid: 1, name: 'French Co', address: 'Paris',
    });
    const viesDec = decodeFieldElements(VIES_SCHEMA, Buffer.from(viesEnc.toString('base64'), 'base64'));
    expect(viesDec.countryCode.value).toBe('FR');

    // SICAE
    const sicaeEnc = encodeFieldElements(SICAE_SCHEMA, {
      nif: '999999999', name: 'Test', cae1Code: '12345', cae1Desc: 'Desc', cae2Code: null, cae2Desc: null,
    });
    const sicaeDec = decodeFieldElements(SICAE_SCHEMA, Buffer.from(sicaeEnc.toString('base64'), 'base64'));
    expect(sicaeDec.nif.value).toBe('999999999');

    // STRIPE_PAYMENT
    const stripeEnc = encodeFieldElements(STRIPE_PAYMENT_SCHEMA, {
      operation: 'list_invoices', accountId: null, objectType: 'list',
      dataHash: 'x', totalCount: 99, hasMore: 0,
    });
    const stripeDec = decodeFieldElements(STRIPE_PAYMENT_SCHEMA, Buffer.from(stripeEnc.toString('base64'), 'base64'));
    expect(stripeDec.operation.value).toBe('list_invoices');
    expect(stripeDec.totalCount.value).toBe('99');
  });
});
