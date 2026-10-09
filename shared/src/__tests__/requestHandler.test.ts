/**
 * The generic request handler (used when an enclave has no custom handler; every service today has one)
 * with only the vsock socket and the NSM device replaced. It must treat the caller challenge like the
 * handler factory does.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'node:crypto';
import { createFakeNsm } from './helpers/fakeNsm.js';

const { fake, connect } = vi.hoisted(() => ({
  fake: { current: null as ReturnType<typeof import('./helpers/fakeNsm.js').createFakeNsm> | null },
  connect: vi.fn(),
}));
vi.mock('@tytle-enclaves/native', () => ({
  nsmRequest: (request: Buffer) => fake.current!.nsmRequest(request),
  VsockStream: { connect },
}));

import { createRequestHandler } from '../requestHandler.js';

const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');

/** A plain-HTTP upstream reply over the vsock socket, then EOF. */
function upstreamReplies(raw: string) {
  let sent = false;
  connect.mockReturnValue({
    read: () => {
      if (sent) return Buffer.alloc(0);
      sent = true;
      return Buffer.from(raw, 'utf-8');
    },
    write: (d: Buffer) => d.length,
    close: () => {},
  });
}

const handler = createRequestHandler({ name: 'generic', hosts: [{ hostname: 'www.sicae.pt', vsockProxyPort: 8445, tls: false }] });
const REQUEST = { id: 'g1', url: 'http://www.sicae.pt/Consulta.aspx', method: 'GET', headers: {} };

beforeEach(() => {
  fake.current = createFakeNsm();
  connect.mockReset();
});

describe('createRequestHandler and the caller challenge', () => {
  it('attests the upstream body under nonce version 1 when no challenge is given (lock)', async () => {
    upstreamReplies('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok');
    const res = await handler(REQUEST);
    expect(res).toMatchObject({ success: true, status: 200, rawBody: 'ok' });
    const att = res.attestation!;
    expect(att.nonce).toBe(sha256(`${sha256('ok')}|www.sicae.pt/Consulta.aspx|${att.timestamp}`));
  });

  it('signs the challenge into the nonce (version 2)', async () => {
    upstreamReplies('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok');
    const challenge = 'f'.repeat(64);
    const res = await handler({ ...REQUEST, challenge });
    const att = res.attestation!;
    expect(att.nonceVersion).toBe(2);
    expect(att.challenge).toBe(challenge);
    expect(att.nonce).toBe(sha256(`${sha256('ok')}|www.sicae.pt/Consulta.aspx|${att.timestamp}|${challenge}`));
  });

  it('a malformed challenge is a 400 before the upstream is called', async () => {
    const res = await handler({ ...REQUEST, challenge: 'x' });
    expect(res).toMatchObject({ success: false, status: 400 });
    expect(connect).not.toHaveBeenCalled();
    expect(fake.current!.asks).toHaveLength(0);
  });
});

describe('createRequestHandler and the request budget (D-P1-11)', () => {
  it('🔴 the read takes what is left of the budget', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(3_000_000);
    upstreamReplies('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok');
    const res = await handler(REQUEST, { deadlineMs: 3_000_000 + 12_000 });
    expect(res.success).toBe(true);
    expect(connect.mock.calls[0]?.[2]).toBe(12);
    vi.restoreAllMocks();
  });

  it('🔴 a read that ends after the budget: 504, no document', async () => {
    let now = 3_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    let sent = false;
    connect.mockReturnValue({
      read: () => {
        if (sent) return Buffer.alloc(0);
        sent = true;
        now += 12_001;
        return Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok', 'utf-8');
      },
      write: (d: Buffer) => d.length,
      close: () => {},
    });
    const res = await handler(REQUEST, { deadlineMs: 3_000_000 + 12_000 });
    expect(res).toMatchObject({ success: false, status: 504 });
    expect(fake.current!.asks).toEqual([]);
    vi.restoreAllMocks();
  });

  it('🔴 a budget spent before the read: 504, no read, no document', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(3_000_000);
    upstreamReplies('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok');
    const res = await handler(REQUEST, { deadlineMs: 3_000_000 });
    expect(res).toMatchObject({ success: false, status: 504 });
    expect(connect).not.toHaveBeenCalled();
    expect(fake.current!.asks).toEqual([]);
    vi.restoreAllMocks();
  });
});
