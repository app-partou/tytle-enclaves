/**
 * The parent's /attest/fetch over real HTTP (the app on an ephemeral port) with only the native vsock
 * connect replaced: what reaches the enclave is read back from the bytes the parent framed to it.
 */
import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';

/** A fake enclave connection: records the framed request, answers with one framed response. */
function enclaveConnection(answer: unknown) {
  const payload = Buffer.from(JSON.stringify(answer), 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  const reply = Buffer.concat([header, payload]);
  let offset = 0;
  const written: Buffer[] = [];
  return {
    written,
    request(): Record<string, unknown> {
      const all = Buffer.concat(written);
      return JSON.parse(all.subarray(4, 4 + all.readUInt32BE(0)).toString('utf-8')) as Record<string, unknown>;
    },
    read(size: number): Buffer {
      const out = reply.subarray(offset, Math.min(reply.length, offset + size));
      offset += out.length;
      return out;
    },
    write(data: Buffer): number {
      written.push(Buffer.from(data));
      return data.length;
    },
    close(): void {},
  };
}

const { vsockConnectAsync } = vi.hoisted(() => ({ vsockConnectAsync: vi.fn() }));
vi.mock('@tytle-enclaves/native', () => ({ vsockConnectAsync }));

import { createApp } from '../app.js';

const ANSWER = { success: true, status: 200, headers: {}, rawBody: 'b64', attestation: { nonceVersion: 2, challenge: 'c'.repeat(64) } };
let server: Server;
let base: string;

beforeAll(async () => {
  server = createApp().listen(0, '127.0.0.1');
  await new Promise<void>((r) => server.once('listening', () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

beforeEach(() => {
  vsockConnectAsync.mockReset();
  vi.spyOn(console, 'log').mockImplementation(() => {});
});

function post(body: unknown) {
  return fetch(`${base}/attest/fetch`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

describe('POST /attest/fetch and the caller challenge', () => {
  it('forwards the challenge to the enclave and passes its answer back', async () => {
    const conn = enclaveConnection(ANSWER);
    vsockConnectAsync.mockResolvedValue(conn);
    const res = await post({ id: '7d0f3b2a-1c4e-4f6a-8b9d-0e1f2a3b4c5d', url: 'https://ec.europa.eu/x', method: 'POST', body: '{}', challenge: 'c'.repeat(64) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(ANSWER);
    expect(conn.request()).toEqual({ id: '7d0f3b2a-1c4e-4f6a-8b9d-0e1f2a3b4c5d', url: 'https://ec.europa.eu/x', method: 'POST', headers: {}, body: '{}', challenge: 'c'.repeat(64) });
  });

  it('without a challenge the enclave request carries none (lock: a caller from before the release)', async () => {
    const conn = enclaveConnection({ success: true, status: 200, headers: {}, rawBody: '' });
    vsockConnectAsync.mockResolvedValue(conn);
    const res = await post({ id: '8e1a4c3b-2d5f-4a7b-9c0e-1f2a3b4c5d6e', url: 'https://ec.europa.eu/x', method: 'POST', body: '{}' });
    expect(res.status).toBe(200);
    expect(conn.request()).toEqual({ id: '8e1a4c3b-2d5f-4a7b-9c0e-1f2a3b4c5d6e', url: 'https://ec.europa.eu/x', method: 'POST', headers: {}, body: '{}' });
  });

  it('a challenge that is not a string is a 400 and the enclave is never called', async () => {
    const res = await post({ id: '9f2b5d4c-3e6a-4b8c-8d1f-2a3b4c5d6e7f', url: 'https://ec.europa.eu/x', method: 'POST', body: '{}', challenge: 42 });
    expect(res.status).toBe(400);
    expect(vsockConnectAsync).not.toHaveBeenCalled();
  });
});
