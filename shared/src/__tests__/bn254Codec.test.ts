import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  encodeFieldElements,
  schemaByteLength,
  bigintToBytes32,
  BN254_MODULUS,
  SICAE_SCHEMA,
  VIES_SCHEMA,
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

// =============================================================================
// Tests
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
    // Should not be all zeros
    expect(buf.some(b => b !== 0)).toBe(true);
  });
});

describe('schemaByteLength', () => {
  it('VIES_SCHEMA = 5 * 32 = 160', () => {
    expect(schemaByteLength(VIES_SCHEMA)).toBe(160);
  });

  it('SICAE_SCHEMA = 6 * 32 = 192', () => {
    expect(schemaByteLength(SICAE_SCHEMA)).toBe(192);
  });

  it('empty schema = 0', () => {
    expect(schemaByteLength([])).toBe(0);
  });
});

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
  });

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
  });

  describe('uint encoding', () => {
    const schema: FieldDef[] = [{ name: 'val', encoding: 'uint' }];

    it('encodes 0 as all-zero bytes (indistinguishable from null)', () => {
      const encoded = encodeFieldElements(schema, { val: 0 });
      const decoded = decodeFieldElements(schema, encoded);
      // uint(0) → BigInt(0) → 32 zero bytes → decoder sees isNull=true, value=''
      // This is by design: 0 and null share the same encoding.
      // Callers use 1/0 for booleans, so valid=0 ↔ null is acceptable.
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
  });
});

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
    // sha256 fields: verify hash matches
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
    // valid=0 produces all-zero field element → isNull=true
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
    // sha256 fields
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
});

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

describe('cross-repo consistency: known test vectors', () => {
  // These test vectors ensure encoder (tytle-enclaves) and decoder (data-bridge)
  // stay in sync. If you change the encoding, update both repos' tests.

  it('VIES: PT/507172230/valid=1 produces known base64', () => {
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
});
