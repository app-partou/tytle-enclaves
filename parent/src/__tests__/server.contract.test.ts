/**
 * The parent's contract (enclave audit P2.5): what a caller may send it, what it frames to an enclave, and what its
 * /health reports. The app runs over real HTTP on an ephemeral port, framing with the real shared protocol; only the
 * outside of the parent is replaced - the native vsock connect, the nitro-cli and systemctl processes, and the
 * listing of the systemd unit directory.
 */
import { describe, it, expect, vi, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { readMessage, writeMessage, type MessageStream } from '@tytle-enclaves/shared';

const io = vi.hoisted(() => ({
  vsockConnectAsync: vi.fn(),
  execSync: vi.fn(),
  execFile: vi.fn(),
  readdir: vi.fn(),
}));
vi.mock('@tytle-enclaves/native', () => ({ vsockConnectAsync: io.vsockConnectAsync }));
vi.mock('node:child_process', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:child_process')>()),
  execSync: io.execSync,
  execFile: io.execFile,
}));
vi.mock('node:fs/promises', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:fs/promises')>()),
  readdir: io.readdir,
}));

import { createApp } from '../app.js';
import { getAllRoutes } from '../enclaveRouter.js';

/** The bytes the shared protocol writes for `message`: what an enclave sends. */
async function frame(message: unknown): Promise<Buffer> {
  const out: Buffer[] = [];
  await writeMessage({ read: () => Buffer.alloc(0), write: (data: Buffer) => { out.push(Buffer.from(data)); return data.length; } }, message);
  return Buffer.concat(out);
}

/** A stream over fixed bytes, for the shared protocol to read. */
function bytesStream(bytes: Buffer): MessageStream {
  let offset = 0;
  return {
    read(size: number): Buffer {
      const out = bytes.subarray(offset, Math.min(bytes.length, offset + size));
      offset += out.length;
      return out;
    },
    write: () => 0,
  };
}

/** A fake enclave connection: records what the parent writes, answers with `answer` framed by the shared protocol. */
async function enclaveConnection(answer: unknown) {
  const reply = bytesStream(await frame(answer));
  const written: Buffer[] = [];
  return {
    read: (size: number): Buffer => reply.read(size),
    write(data: Buffer): number {
      written.push(Buffer.from(data));
      return data.length;
    },
    close(): void {},
    sent: (): Buffer => Buffer.concat(written),
  };
}

const ID = '0b4c6a2e-5d1f-4e8a-9c3b-7f2d1e0a9b8c';
const ANSWER = { success: true, status: 200, headers: { 'content-type': 'text/xml' }, rawBody: 'b64' };

/** A request in the shape data-bridge sends (attestedFetchService.ts executeViaEnclave). */
function request(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: ID,
    url: 'https://ec.europa.eu/x',
    method: 'POST',
    headers: { 'Content-Type': 'text/xml' },
    body: '<soap/>',
    challenge: 'c'.repeat(64),
    ...over,
  };
}

let server: Server;
let base: string;
let logs: string[];
let errors: string[];

beforeAll(async () => {
  server = createApp().listen(0, '127.0.0.1');
  await new Promise<void>((r) => server.once('listening', () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

beforeEach(() => {
  io.vsockConnectAsync.mockReset();
  io.execSync.mockReset();
  io.execFile.mockReset();
  io.readdir.mockReset();
  logs = [];
  errors = [];
  vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { logs.push(args.map(String).join(' ')); });
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => { errors.push(args.map(String).join(' ')); });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

function post(body: unknown, raw?: string): Promise<Response> {
  return fetch(`${base}/attest/fetch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: raw ?? JSON.stringify(body),
  });
}

/** POST `body` to an enclave that answers ANSWER; the connection records what the parent framed. */
async function forward(body: unknown) {
  const conn = await enclaveConnection(ANSWER);
  io.vsockConnectAsync.mockResolvedValue(conn);
  const res = await post(body);
  return { res, conn };
}

/** What the parent framed to the enclave, read back with the shared protocol. */
function framedRequest(conn: { sent(): Buffer }): Promise<Record<string, unknown>> {
  return readMessage<Record<string, unknown>>(bytesStream(conn.sent()));
}

async function expectRefused(body: unknown, error: string): Promise<void> {
  const res = await post(body);
  expect(res.status).toBe(400);
  expect(await res.json()).toEqual({ success: false, error });
  expect(io.vsockConnectAsync).not.toHaveBeenCalled();
}

describe('the router table: hostname to enclave CID and vsock port (lock)', () => {
  it('the three enclaves the infra launches, each on vsock port 5000', () => {
    expect(getAllRoutes()).toEqual([
      { cid: 16, port: 5000, hosts: ['ec.europa.eu', 'api.service.hmrc.gov.uk'] },
      { cid: 17, port: 5000, hosts: ['www.sicae.pt'] },
      { cid: 18, port: 5000, hosts: ['api.stripe.com'] },
    ]);
  });

  it.each([
    ['https://ec.europa.eu/taxation_customs/vies/services/checkVatService', 16],
    ['https://api.service.hmrc.gov.uk/organisations/vat/check-vat-number/lookup/123456789', 16],
    ['http://www.sicae.pt/Consulta.aspx', 17],
    ['https://api.stripe.com/v1/charges', 18],
  ])('%s goes to CID %i', async (url, cid) => {
    const { res } = await forward(request({ url }));
    expect(res.status).toBe(200);
    expect(io.vsockConnectAsync).toHaveBeenCalledWith(cid, 5000, expect.any(Number));
  });

  it('a host no enclave serves is a JSON 404 and no enclave is called', async () => {
    const res = await post(request({ url: 'https://example.com/x' }));
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ success: false, error: 'No enclave configured for URL: https://example.com/x' });
    expect(io.vsockConnectAsync).not.toHaveBeenCalled();
  });

  it('Monerium is routed only when the host names its CID (MONERIUM_PAYMENT_CID)', async () => {
    vi.resetModules();
    expect((await import('../enclaveRouter.js')).findRoute('https://api.monerium.app/orders/x')).toBeNull();
    vi.stubEnv('MONERIUM_PAYMENT_CID', '19');
    vi.resetModules();
    expect((await import('../enclaveRouter.js')).findRoute('https://api.monerium.app/orders/x'))
      .toEqual({ cid: 19, port: 5000, hosts: ['api.monerium.app'] });
  });

  it('a CID the host sets wins over the default (the systemd unit sets all three)', async () => {
    vi.stubEnv('VIES_CID', '26');
    vi.stubEnv('SICAE_CID', '27');
    vi.stubEnv('STRIPE_PAYMENT_CID', '28');
    vi.resetModules();
    expect((await import('../enclaveRouter.js')).getAllRoutes().map((r) => r.cid)).toEqual([26, 27, 28]);
  });
});

describe('the frame the enclave reads: the shared protocol (lock)', () => {
  it('one frame: a 4-byte big-endian length, then that many bytes of UTF-8 JSON, which the shared readMessage reads back', async () => {
    const sent = request({ body: '{"name":"Zoë Café"}' });
    const { res, conn } = await forward(sent);
    expect(res.status).toBe(200);
    const bytes = conn.sent();
    expect(bytes.readUInt32BE(0)).toBe(bytes.length - 4);
    expect(JSON.parse(bytes.subarray(4).toString('utf-8'))).toEqual(sent);
    expect(await framedRequest(conn)).toEqual(sent);
  });

  it('the enclave answer the shared writeMessage framed is the HTTP answer', async () => {
    const { res } = await forward(request());
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(ANSWER);
  });
});

describe('the body limit: 64 KB', () => {
  /** A request whose JSON is exactly `bytes` bytes long. */
  function requestOfSize(bytes: number): Record<string, unknown> {
    const empty = request({ body: '' });
    return { ...empty, body: 'x'.repeat(bytes - Buffer.byteLength(JSON.stringify(empty))) };
  }

  it('a body of 64 KB is read and forwarded (lock)', async () => {
    const body = requestOfSize(64 * 1024);
    expect(Buffer.byteLength(JSON.stringify(body))).toBe(65_536);
    const { res, conn } = await forward(body);
    expect(res.status).toBe(200);
    expect(await framedRequest(conn)).toEqual(body);
  });

  it('one byte more is a JSON 413 and the enclave is never called (red)', async () => {
    const res = await post(requestOfSize(64 * 1024 + 1));
    expect(res.status).toBe(413);
    expect(await res.json()).toEqual({ success: false, error: 'Request body is larger than 64kb' });
    expect(io.vsockConnectAsync).not.toHaveBeenCalled();
  });
});

describe('a body that is not JSON', () => {
  it('is a JSON 400, never Express\'s HTML page (red)', async () => {
    const res = await post(undefined, '{"id":');
    expect(res.status).toBe(400);
    expect(res.headers.get('content-type')).toContain('application/json');
    expect(await res.json()).toEqual({ success: false, error: 'Request body is not readable JSON' });
    expect(io.vsockConnectAsync).not.toHaveBeenCalled();
  });

  it('a JSON array is a 400: the request must be a JSON object (red)', async () => {
    await expectRefused([request()], 'the request must be a JSON object');
  });

  it('a body sent as text is a 400 (lock)', async () => {
    const text = await fetch(`${base}/attest/fetch`, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: JSON.stringify(request()) });
    expect(text.status).toBe(400);
    expect(io.vsockConnectAsync).not.toHaveBeenCalled();
  });
});

describe('the request schema', () => {
  it('a request without its url or method is a 400 (lock)', async () => {
    const { url: _url, ...noUrl } = request();
    const { method: _method, ...noMethod } = request();
    expect((await post(noUrl)).status).toBe(400);
    expect((await post(noMethod)).status).toBe(400);
    expect(io.vsockConnectAsync).not.toHaveBeenCalled();
  });

  it('only the known fields are forwarded; an unknown one is dropped, never a refusal (lock)', async () => {
    const { res, conn } = await forward({ ...request(), extra: 'x' });
    expect(res.status).toBe(200);
    expect(await framedRequest(conn)).toEqual(request());
  });

  it('a request without an id gets a fresh UUID, and one without headers gets none (lock)', async () => {
    const { id: _id, headers: _headers, ...rest } = request();
    const { res, conn } = await forward(rest);
    expect(res.status).toBe(200);
    const framed = await framedRequest(conn);
    expect(framed.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(framed.headers).toEqual({});
  });

  it('an id that is not a UUID is a 400 (red)', async () => {
    await expectRefused(request({ id: 'r1' }), 'id must be a UUID');
    await expectRefused(request({ id: 42 }), 'id must be a UUID');
  });

  it('a url that is not an http or https URL, or holds a space or a control character, is a 400 (red)', async () => {
    const error = 'url must be an http or https URL without spaces or control characters';
    await expectRefused(request({ url: 'ftp://ec.europa.eu/x' }), error);
    await expectRefused(request({ url: 'not a url' }), error);
    await expectRefused(request({ url: 'https://ec.europa.eu/x y' }), error);
    await expectRefused(request({ url: 'https://ec.europa.eu/x\u0007' }), error);
    await expectRefused(request({ url: ['https://ec.europa.eu/x'] }), error);
  });

  it('a method other than GET or POST is a 400 (red)', async () => {
    await expectRefused(request({ method: 'DELETE' }), 'method must be one of GET, POST');
    await expectRefused(request({ method: 'GET /admin HTTP/1.1' }), 'method must be one of GET, POST');
    await expectRefused(request({ method: 'post' }), 'method must be one of GET, POST');
  });

  it('headers that are not an object of HTTP field strings are a 400 (red)', async () => {
    await expectRefused(request({ headers: ['Content-Type: text/xml'] }), 'headers must be an object of strings');
    await expectRefused(request({ headers: 'Content-Type: text/xml' }), 'headers must be an object of strings');
    await expectRefused(request({ headers: { 'Content-Length': 5 } }), 'every header value must be a string');
    await expectRefused(request({ headers: { 'Content Type': 'text/xml' } }), 'a header name is not an HTTP token');
    await expectRefused(request({ headers: { 'X-A:': 'b' } }), 'a header name is not an HTTP token');
    await expectRefused(request({ headers: { 'X-A': 'b\r\nX-Injected: 1' } }), 'a header value holds CR, LF or NUL');
  });

  it('a body that is not a string is a 400 (red)', async () => {
    await expectRefused(request({ body: { vat: '123' } }), 'body must be a string');
  });

  it('a challenge that is not a string is a 400 (lock)', async () => {
    const res = await post(request({ challenge: 42 }));
    expect(res.status).toBe(400);
    expect(io.vsockConnectAsync).not.toHaveBeenCalled();
  });
});

describe('the logs: a caller value never starts a line of its own', () => {
  it('an id that holds a newline is refused, and nothing is logged (red)', async () => {
    const res = await post(request({ id: `${ID}\n[parent] ${ID}: OK (status 200, 1ms)` }));
    expect(res.status).toBe(400);
    expect(logs).toEqual([]);
    expect(io.vsockConnectAsync).not.toHaveBeenCalled();
  });

  it('the routing line names the URL JSON-encoded (red)', async () => {
    await forward(request());
    expect(logs[0]).toBe(`[parent] ${ID}: Routing POST "https://ec.europa.eu/x" -> CID 16:5000`);
  });

  it('an enclave error that holds a newline is logged on one line (red)', async () => {
    io.vsockConnectAsync.mockRejectedValue(new Error('connect failed\n[parent] forged: OK'));
    const res = await post(request());
    expect(res.status).toBe(502);
    expect(errors).toHaveLength(1);
    expect(errors[0]).not.toContain('\n');
    expect(errors[0]).toContain(JSON.stringify('connect failed\n[parent] forged: OK'));
  });
});

describe('GET /health', () => {
  const ALL_RUNNING = [16, 17, 18].map((cid) => ({ EnclaveCID: cid, State: 'RUNNING', EnclaveID: `i-0-enc${cid}` }));
  const UNIT_FILES = [
    'enclave-parent.service',
    'enclave-watchdog.timer',
    'vsock-proxy-vies.service',
    'vsock-proxy-hmrc.service',
    'vsock-proxy-sicae.service',
    'vsock-proxy-stripe.service',
    'vsock-proxy-stripe.service.bak',
  ];

  /** The host: nitro-cli lists `running`, each listed enclave answers its ping, systemd says `active` units are active. */
  async function host({ running = ALL_RUNNING, active = ['vsock-proxy-vies', 'vsock-proxy-hmrc', 'vsock-proxy-sicae', 'vsock-proxy-stripe'], unitFiles = UNIT_FILES as string[] | Error } = {}) {
    io.execSync.mockReturnValue(JSON.stringify(running));
    const pong = await frame({ type: 'pong' });
    io.vsockConnectAsync.mockImplementation(async () => {
      const reply = bytesStream(pong);
      return { read: (size: number) => reply.read(size), write: (data: Buffer) => data.length, close: () => {} };
    });
    if (unitFiles instanceof Error) io.readdir.mockRejectedValue(unitFiles);
    else io.readdir.mockResolvedValue(unitFiles);
    io.execFile.mockImplementation((_cmd: string, args: string[], _opts: unknown, callback: (err: Error | null) => void) => {
      callback(active.includes(args[2]) ? null : Object.assign(new Error('inactive'), { code: 3 }));
    });
  }

  async function health(): Promise<{ status: number; body: Record<string, unknown> }> {
    const res = await fetch(`${base}/health`);
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  }

  it('every enclave answers: 200 and each enclave\'s state (lock)', async () => {
    await host();
    const { status, body } = await health();
    expect(status).toBe(200);
    expect(body.healthy).toBe(true);
    expect(body.enclaves).toEqual([
      { cid: 16, hosts: ['ec.europa.eu', 'api.service.hmrc.gov.uk'], state: 'RUNNING', connectivity: 'responsive', healthy: true },
      { cid: 17, hosts: ['www.sicae.pt'], state: 'RUNNING', connectivity: 'responsive', healthy: true },
      { cid: 18, hosts: ['api.stripe.com'], state: 'RUNNING', connectivity: 'responsive', healthy: true },
    ]);
    expect(typeof body.timestamp).toBe('number');
  });

  it('an enclave that is not RUNNING: 503 (lock)', async () => {
    await host({ running: ALL_RUNNING.slice(0, 2) });
    const { status, body } = await health();
    expect(status).toBe(503);
    expect(body.healthy).toBe(false);
    expect((body.enclaves as Array<Record<string, unknown>>)[2]).toEqual(
      { cid: 18, hosts: ['api.stripe.com'], state: 'NOT_FOUND', connectivity: 'untested', healthy: false },
    );
  });

  it('every proxy unit on the host is reported up or down by its name, sorted (red)', async () => {
    await host({ active: ['vsock-proxy-vies', 'vsock-proxy-hmrc', 'vsock-proxy-sicae'] });
    const { body } = await health();
    expect(body.proxies).toEqual({ hmrc: 'up', sicae: 'up', stripe: 'down', vies: 'up' });
    expect(Object.keys(body.proxies as object)).toEqual(['hmrc', 'sicae', 'stripe', 'vies']);
  });

  it('systemd is asked without a shell, once per proxy unit, and nothing else (red)', async () => {
    await host();
    await health();
    expect(io.execFile.mock.calls.map((call) => [call[0], call[1]])).toEqual(
      ['hmrc', 'sicae', 'stripe', 'vies'].map((name) => ['systemctl', ['is-active', '--quiet', `vsock-proxy-${name}`]]),
    );
  });

  it('a down proxy does not make the parent unhealthy: the watchdog reads 503 as a down enclave (lock)', async () => {
    await host({ active: [] });
    const { status, body } = await health();
    expect(status).toBe(200);
    expect(body.healthy).toBe(true);
  });

  it('a down proxy is reported while an enclave is down too (red)', async () => {
    await host({ running: [], active: ['vsock-proxy-vies'] });
    const { status, body } = await health();
    expect(status).toBe(503);
    expect(body.proxies).toEqual({ hmrc: 'down', sicae: 'down', stripe: 'down', vies: 'up' });
  });

  it('a host without proxy units, or whose unit directory cannot be read, reports none (red)', async () => {
    await host({ unitFiles: ['enclave-parent.service'] });
    expect((await health()).body.proxies).toEqual({});
    await host({ unitFiles: Object.assign(new Error('ENOENT'), { code: 'ENOENT' }) });
    expect((await health()).body.proxies).toEqual({});
    expect(io.execFile).not.toHaveBeenCalled();
  });
});
