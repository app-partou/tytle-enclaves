import { describe, it, expect } from 'vitest';
import cbor from 'cbor';
import { decodeCoseSign1, extractPcrs } from '../lib/attestationDoc.js';

describe('decodeCoseSign1', () => {
  function buildValidCose(overrides?: {
    protectedHeaders?: unknown;
    payload?: unknown;
    signature?: unknown;
    tag?: boolean;
  }) {
    const protectedHeaders =
      overrides?.protectedHeaders ?? cbor.encodeOne(new Map([[1, -35]]));
    const pcrsMap = new Map<number, Buffer>([
      [0, Buffer.from('a'.repeat(96), 'hex')],
      [1, Buffer.from('b'.repeat(96), 'hex')],
      [2, Buffer.from('c'.repeat(96), 'hex')],
    ]);
    const payload =
      overrides?.payload ??
      cbor.encodeOne({
        module_id: 'test-module',
        digest: 'SHA384',
        timestamp: Date.now(),
        pcrs: pcrsMap,
        certificate: Buffer.from('test-cert'),
        cabundle: [Buffer.from('test-ca')],
        nonce: Buffer.from('test-nonce'),
        user_data: null,
        public_key: null,
      });
    const signature = overrides?.signature ?? Buffer.from('fake-signature');
    const tag = overrides?.tag ?? true;

    if (tag) {
      return cbor.encodeOne(
        new cbor.Tagged(18, [protectedHeaders, {}, payload, signature]),
      );
    }
    return cbor.encodeOne([protectedHeaders, {}, payload, signature]);
  }

  it('decodes a valid COSE_Sign1 structure', () => {
    const coseBytes = buildValidCose();
    const decoded = decodeCoseSign1(coseBytes);

    expect(decoded.protectedRaw).toBeInstanceOf(Buffer);
    expect(decoded.payloadRaw).toBeInstanceOf(Buffer);
    expect(decoded.signature).toBeInstanceOf(Buffer);
    expect(decoded.payload.module_id).toBe('test-module');
    expect(decoded.payload.pcrs).toBeInstanceOf(Map);
  });

  it('handles untagged COSE_Sign1 arrays', () => {
    const coseBytes = buildValidCose({ tag: false });
    const decoded = decodeCoseSign1(coseBytes);
    expect(decoded.payload.module_id).toBe('test-module');
  });

  it('throws on invalid structure (too few elements)', () => {
    const invalid = cbor.encodeOne([Buffer.alloc(0), {}]);
    expect(() => decodeCoseSign1(invalid)).toThrow('Invalid COSE_Sign1 structure');
  });

  it('throws when protectedRaw is not a Buffer (RFC 9052 bstr)', () => {
    // Pass a string instead of Buffer for protected headers
    const coseBytes = cbor.encodeOne(
      new cbor.Tagged(18, [
        'not-a-buffer',
        {},
        cbor.encodeOne({ module_id: 'x', pcrs: new Map(), certificate: Buffer.from('c'), cabundle: [] }),
        Buffer.from('sig'),
      ]),
    );
    expect(() => decodeCoseSign1(coseBytes)).toThrow('byte string');
  });

  it('throws when payload is not a Buffer', () => {
    const coseBytes = cbor.encodeOne(
      new cbor.Tagged(18, [
        cbor.encodeOne(new Map()),
        {},
        'not-a-buffer', // payload should be bstr
        Buffer.from('sig'),
      ]),
    );
    expect(() => decodeCoseSign1(coseBytes)).toThrow('byte string');
  });

  it('throws when payload is missing pcrs', () => {
    const badPayload = cbor.encodeOne({
      module_id: 'test',
      digest: 'SHA384',
      timestamp: Date.now(),
      // pcrs missing
      certificate: Buffer.from('cert'),
      cabundle: [],
      nonce: null,
      user_data: null,
      public_key: null,
    });
    const coseBytes = cbor.encodeOne(
      new cbor.Tagged(18, [
        cbor.encodeOne(new Map([[1, -35]])),
        {},
        badPayload,
        Buffer.from('sig'),
      ]),
    );
    expect(() => decodeCoseSign1(coseBytes)).toThrow('missing pcrs');
  });

  it('throws when payload is missing certificate', () => {
    const badPayload = cbor.encodeOne({
      module_id: 'test',
      pcrs: new Map([[0, Buffer.alloc(48)]]),
      // certificate missing
      cabundle: [],
    });
    const coseBytes = cbor.encodeOne(
      new cbor.Tagged(18, [
        cbor.encodeOne(new Map([[1, -35]])),
        {},
        badPayload,
        Buffer.from('sig'),
      ]),
    );
    expect(() => decodeCoseSign1(coseBytes)).toThrow('missing certificate');
  });
});

describe('extractPcrs', () => {
  it('extracts PCR hex values from a decoded attestation', () => {
    const pcr0 = Buffer.from('aa'.repeat(48), 'hex');
    const pcr1 = Buffer.from('bb'.repeat(48), 'hex');
    const pcr2 = Buffer.from('cc'.repeat(48), 'hex');

    const protectedHeaders = cbor.encodeOne(new Map([[1, -35]]));
    const payload = cbor.encodeOne({
      module_id: 'test',
      digest: 'SHA384',
      timestamp: Date.now(),
      pcrs: new Map<number, Buffer>([
        [0, pcr0],
        [1, pcr1],
        [2, pcr2],
      ]),
      certificate: Buffer.from('cert'),
      cabundle: [],
      nonce: null,
      user_data: null,
      public_key: null,
    });
    const coseBytes = cbor.encodeOne(
      new cbor.Tagged(18, [protectedHeaders, {}, payload, Buffer.alloc(96)]),
    );

    const decoded = decodeCoseSign1(coseBytes);
    const pcrs = extractPcrs(decoded);

    expect(pcrs.pcr0).toBe('aa'.repeat(48));
    expect(pcrs.pcr1).toBe('bb'.repeat(48));
    expect(pcrs.pcr2).toBe('cc'.repeat(48));
  });

  it('throws when PCR0 is missing', () => {
    const protectedHeaders = cbor.encodeOne(new Map([[1, -35]]));
    const payload = cbor.encodeOne({
      module_id: 'test',
      pcrs: new Map<number, Buffer>(), // empty — no PCR0
      certificate: Buffer.from('cert'),
      cabundle: [],
    });
    const coseBytes = cbor.encodeOne(
      new cbor.Tagged(18, [protectedHeaders, {}, payload, Buffer.alloc(96)]),
    );

    const decoded = decodeCoseSign1(coseBytes);
    expect(() => extractPcrs(decoded)).toThrow('missing PCR0');
  });
});
