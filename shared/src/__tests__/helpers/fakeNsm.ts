/**
 * A stand-in for the NSM device (`nsmRequest` of the native addon) that answers the way /dev/nsm does in
 * shape: it decodes the CBOR request `{Attestation: {nonce, user_data, public_key}}` and returns the CBOR
 * envelope `{Attestation: {document}}`, where the document is a COSE_Sign1 array whose payload echoes the
 * nonce, user_data and public_key it was asked to sign, with fixed PCRs. Nothing is signed (the signature
 * is zero bytes): the enclave never verifies its own document, the verifiers do, with real chains.
 * Every request is recorded so a test can read exactly what the enclave asked the NSM to sign.
 */
import cbor from 'cbor';

export const FAKE_PCRS = {
  pcr0: 'a0'.repeat(48),
  pcr1: 'a1'.repeat(48),
  pcr2: 'a2'.repeat(48),
};

export interface NsmAsk {
  nonce: Buffer | null;
  userData: Buffer | null;
  publicKey: Buffer | null;
}

export function createFakeNsm(timestampMs = 1_760_000_000_000) {
  const asks: NsmAsk[] = [];
  function nsmRequest(request: Buffer): Buffer {
    const decoded = cbor.decodeFirstSync(request) as { Attestation?: { nonce?: Buffer | null; user_data?: Buffer | null; public_key?: Buffer | null } };
    const att = decoded.Attestation;
    if (!att) throw new Error('fake NSM: not an Attestation request');
    const ask: NsmAsk = { nonce: att.nonce ?? null, userData: att.user_data ?? null, publicKey: att.public_key ?? null };
    asks.push(ask);
    const payload = cbor.encode(new Map<string, unknown>([
      ['module_id', 'i-fake-enc0000000000000'],
      ['digest', 'SHA384'],
      ['timestamp', timestampMs],
      ['pcrs', new Map<number, Buffer>([
        [0, Buffer.from(FAKE_PCRS.pcr0, 'hex')],
        [1, Buffer.from(FAKE_PCRS.pcr1, 'hex')],
        [2, Buffer.from(FAKE_PCRS.pcr2, 'hex')],
      ])],
      ['certificate', Buffer.alloc(16)],
      ['cabundle', [] as Buffer[]],
      ['public_key', ask.publicKey],
      ['user_data', ask.userData],
      ['nonce', ask.nonce],
    ]));
    const cose = cbor.encode([cbor.encode(new Map([[1, -35]])), new Map(), payload, Buffer.alloc(96)]);
    return cbor.encode({ Attestation: { document: cose } });
  }
  return { nsmRequest, asks };
}
