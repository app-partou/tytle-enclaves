/**
 * The parent's contract (enclave audit P2.5): what a caller may send it, what it frames to an enclave, and what its
 * /health reports. The app runs over real HTTP on an ephemeral port, framing with the real shared protocol; only the
 * outside of the parent is replaced - the native vsock connect, the nitro-cli and systemctl processes, and the
 * listing of the systemd unit directory.
 */
import { describe, it, expect, vi, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import net, { type AddressInfo } from 'node:net';
import http, { type Server } from 'node:http';
import { once } from 'node:events';
import { readMessage, writeMessage, type MessageStream } from '@tytle-enclaves/shared';
import { blockFor } from '../../../shared/src/__tests__/helpers/blockingVsock.js';

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

import { createApp, listenParent } from '../app.js';
import { getAllRoutes } from '../enclaveRouter.js';
import { startFakeImds, imdsCredentials } from './helpers/fakeImds.js';

/** The bytes the shared protocol writes for `message`: what an enclave sends. */
async function frame(message: unknown): Promise<Buffer> {
  const out: Buffer[] = [];
  await writeMessage({ readWithin: () => Buffer.alloc(0), writeWithin: (data: Buffer) => { out.push(Buffer.from(data)); return data.length; } }, message);
  return Buffer.concat(out);
}

/** A stream over fixed bytes, for the shared protocol to read. */
function bytesStream(bytes: Buffer): MessageStream {
  let offset = 0;
  return {
    readWithin(size: number): Buffer | null {
      const out = bytes.subarray(offset, Math.min(bytes.length, offset + size));
      offset += out.length;
      return out;
    },
    writeWithin: () => 0,
  };
}

/** A fake enclave connection: records what the parent writes, answers with `answer` framed by the shared protocol. */
async function enclaveConnection(answer: unknown) {
  const reply = bytesStream(await frame(answer));
  const written: Buffer[] = [];
  return {
    readWithin: (size: number, timeoutMs: number): Buffer | null => reply.readWithin(size, timeoutMs),
    writeWithin(data: Buffer): number {
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
  // Each /health here reads the host anew: the shared check's cache is off (its own tests start apps of their own)
  server = createApp({ healthCacheMs: 0 }).listen(0, '127.0.0.1');
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

  /**
   * The host: nitro-cli lists `running`; each listed enclave answers its ping with its clock `drift` ms from this
   * host's (no clock in its pong when null), except the `silent` ones; systemd says `active` units are active.
   */
  async function host({
    running = ALL_RUNNING,
    active = ['vsock-proxy-vies', 'vsock-proxy-hmrc', 'vsock-proxy-sicae', 'vsock-proxy-stripe'],
    unitFiles = UNIT_FILES as string[] | Error,
    drift = { 16: 0, 17: 0, 18: 0 } as Record<number, number | null>,
    silent = [] as number[],
  } = {}) {
    io.execSync.mockReturnValue(JSON.stringify(running));
    io.vsockConnectAsync.mockImplementation(async (cid: number) => {
      if (silent.includes(cid)) throw new Error('connection refused');
      const off = drift[cid];
      const reply = bytesStream(await frame(off === null || off === undefined ? { type: 'pong' } : { type: 'pong', timestamp: Date.now() + off }));
      return { readWithin: (size: number, timeoutMs: number) => reply.readWithin(size, timeoutMs), writeWithin: (data: Buffer) => data.length, close: () => {} };
    });
    if (unitFiles instanceof Error) io.readdir.mockRejectedValue(unitFiles);
    else io.readdir.mockResolvedValue(unitFiles);
    io.execFile.mockImplementation((cmd: string, args: string[], _opts: unknown, callback: (err: Error | null, stdout?: string) => void) => {
      if (cmd === 'nitro-cli') {
        callback(null, JSON.stringify(running));
        return;
      }
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
    expect(body.enclaves).toMatchObject([
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
    expect((body.enclaves as Array<Record<string, unknown>>)[2]).toMatchObject(
      { cid: 18, hosts: ['api.stripe.com'], state: 'NOT_FOUND', connectivity: 'untested', healthy: false },
    );
  });

  it('an enclave that does not answer its ping: 503, unresponsive (lock)', async () => {
    await host({ silent: [17] });
    const { status, body } = await health();
    expect(status).toBe(503);
    expect((body.enclaves as Array<Record<string, unknown>>)[1]).toMatchObject(
      { cid: 17, state: 'RUNNING', connectivity: 'unresponsive', healthy: false },
    );
  });

  it('each enclave reports its clock\'s drift from this host, from its pong; null when it was not pinged or did not say (red)', async () => {
    await host({ running: ALL_RUNNING.slice(0, 2), drift: { 16: 90_000, 17: null } });
    const enclaves = (await health()).body.enclaves as Array<{ clockDriftMs: number | null }>;
    expect(Math.abs((enclaves[0].clockDriftMs as number) - 90_000)).toBeLessThan(1_000);
    expect(enclaves[1].clockDriftMs).toBeNull();
    expect(enclaves[2].clockDriftMs).toBeNull();
    await host({ drift: { 16: 0, 17: -45_000, 18: 0 }, silent: [18] });
    const later = (await health()).body.enclaves as Array<{ clockDriftMs: number | null }>;
    expect(Math.abs((later[1].clockDriftMs as number) + 45_000)).toBeLessThan(1_000);
    expect(later[2].clockDriftMs).toBeNull();
  });

  it('every proxy unit on the host is reported up or down by its name, sorted (red)', async () => {
    await host({ active: ['vsock-proxy-vies', 'vsock-proxy-hmrc', 'vsock-proxy-sicae'] });
    const { body } = await health();
    expect(body.proxies).toEqual({ hmrc: 'up', sicae: 'up', stripe: 'down', vies: 'up' });
    expect(Object.keys(body.proxies as object)).toEqual(['hmrc', 'sicae', 'stripe', 'vies']);
  });

  it('nitro-cli and systemd are asked without a shell: nitro-cli once, systemd once per proxy unit, and nothing else (red)', async () => {
    // nitro-cli ran through a shell before (execSync with a command line), and held the event loop while it ran
    await host();
    await health();
    expect(io.execFile.mock.calls.map((call) => [call[0], call[1]])).toEqual([
      ['nitro-cli', ['describe-enclaves']],
      ...['hmrc', 'sicae', 'stripe', 'vies'].map((name) => ['systemctl', ['is-active', '--quiet', `vsock-proxy-${name}`]]),
    ]);
    // Each with its time limit, nitro-cli's as before (5 s)
    expect(io.execFile.mock.calls.map((call) => (call[2] as { timeout?: number }).timeout)).toEqual([5_000, 2_000, 2_000, 2_000, 2_000]);
    expect(io.execSync).not.toHaveBeenCalled();
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
    expect(io.execFile.mock.calls.filter(([cmd]) => cmd === 'systemctl')).toEqual([]);
  });

  it('nitro-cli that fails, or prints no JSON, lists no enclave, whatever it printed: 503, and the parent answers (lock)', async () => {
    await host();
    // The release before ran it with execSync, which throws for a failed run
    io.execSync.mockImplementation(() => { throw Object.assign(new Error('Command failed: nitro-cli describe-enclaves'), { status: 1 }); });
    io.execFile.mockImplementation((cmd: string, args: string[], _opts: unknown, callback: (err: Error | null, stdout?: string) => void) => {
      if (cmd === 'nitro-cli') callback(Object.assign(new Error('Command failed: nitro-cli describe-enclaves'), { code: 1 }), JSON.stringify(ALL_RUNNING));
      else callback(null);
    });
    const failed = await health();
    expect(failed.status).toBe(503);
    expect((failed.body.enclaves as Array<{ state: string }>).map((e) => e.state)).toEqual(['NOT_FOUND', 'NOT_FOUND', 'NOT_FOUND']);

    io.execSync.mockReturnValue('nitro-cli: not JSON');
    io.execFile.mockImplementation((cmd: string, args: string[], _opts: unknown, callback: (err: Error | null, stdout?: string) => void) => {
      callback(null, cmd === 'nitro-cli' ? 'nitro-cli: not JSON' : undefined);
    });
    const garbled = await health();
    expect(garbled.status).toBe(503);
    expect((garbled.body.enclaves as Array<{ state: string }>).map((e) => e.state)).toEqual(['NOT_FOUND', 'NOT_FOUND', 'NOT_FOUND']);
  });

  /** How often nitro-cli was asked, through a shell (the release before) or not. */
  const nitroCliAsks = (): number => io.execSync.mock.calls.length + io.execFile.mock.calls.filter(([cmd]) => cmd === 'nitro-cli').length;

  /**
   * nitro-cli takes `ms` to answer. The release before ran it with execSync, which holds the thread that long (the fake
   * blocks it, as the real wait does); this one runs it with execFile, which calls back after it.
   */
  function slowNitroCli(ms: number): void {
    io.execSync.mockImplementation(() => {
      blockFor(ms);
      return JSON.stringify(ALL_RUNNING);
    });
    const answerAtOnce = io.execFile.getMockImplementation();
    io.execFile.mockImplementation((cmd: string, args: string[], opts: unknown, callback: (err: Error | null, stdout?: string) => void) => {
      if (cmd === 'nitro-cli') setTimeout(() => callback(null, JSON.stringify(ALL_RUNNING)), ms);
      else answerAtOnce?.(cmd, args, opts, callback);
    });
  }

  it('the parent serves its other routes while nitro-cli runs (enclave review 2026-10-09, E2b F-1, F-2) (red)', async () => {
    // /routes is asked 100 ms after /health: a timer, which needs the event loop. Before, nitro-cli held the event loop
    // while it ran (execSync), and /routes waited for it.
    await host();
    slowNitroCli(1_500);
    const own = await listen(createApp());
    try {
      const start = Date.now();
      const probe = fetch(`${own.url}/health`);
      const routesAt = await new Promise<number>((resolve) => {
        setTimeout(() => { void fetch(`${own.url}/routes`).then(() => resolve(Date.now() - start)); }, 100);
      });
      expect(routesAt).toBeLessThan(100 + 400);
      expect((await probe).status).toBe(200);
    } finally {
      await own.close();
    }
  });

  it('probes that come while a check runs share it: nitro-cli is asked once (E2b F-2) (red)', async () => {
    await host();
    slowNitroCli(300);
    const own = await listen(createApp());
    try {
      const answers = await Promise.all([1, 2, 3].map(() => fetch(`${own.url}/health`)));
      expect(answers.map((answer) => answer.status)).toEqual([200, 200, 200]);
      expect(nitroCliAsks()).toBe(1);
    } finally {
      await own.close();
    }
  });

  it('a check answers every probe for 2 s after it, and a probe after that checks again (E2b F-2) (red)', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const own = await listen(createApp());
    try {
      const t0 = 1_760_000_000_000;
      vi.setSystemTime(t0);
      await host();
      expect((await fetch(`${own.url}/health`)).status).toBe(200);
      // An enclave stops. Within the 2 s, a probe gets the last check's answer.
      await host({ running: ALL_RUNNING.slice(0, 2) });
      vi.setSystemTime(t0 + 1_999);
      expect((await fetch(`${own.url}/health`)).status).toBe(200);
      expect(nitroCliAsks()).toBe(1);
      vi.setSystemTime(t0 + 2_000);
      expect((await fetch(`${own.url}/health`)).status).toBe(503);
      expect(nitroCliAsks()).toBe(2);
    } finally {
      vi.useRealTimers();
      await own.close();
    }
  });
});

/** An app of its own on an ephemeral port: its base URL, and how to close it. */
async function listen(app: ReturnType<typeof createApp>): Promise<{ url: string; close(): Promise<void> }> {
  const own = app.listen(0, '127.0.0.1');
  await new Promise<void>((r) => own.once('listening', () => r()));
  return {
    url: `http://127.0.0.1:${(own.address() as AddressInfo).port}`,
    close: () => new Promise<void>((r) => own.close(() => r())),
  };
}

describe('the parent token: ENCLAVE_PARENT_AUTH_TOKEN (enclave audit P1.7, the interim guard) (red)', () => {
  const TOKEN = 'testonly-parent-token-0123456789abcdef';
  let guarded: { url: string; close(): Promise<void> };
  beforeAll(async () => { guarded = await listen(createApp({ authToken: TOKEN })); });
  afterAll(async () => { await guarded.close(); });

  const send = (path: string, init: RequestInit = {}) => fetch(`${guarded.url}${path}`, init);
  const postFetch = (headers: Record<string, string>, body = JSON.stringify(request())) =>
    send('/attest/fetch', { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body });

  it('without it, /attest/fetch is a JSON 401, its body is never read, and no enclave is called', async () => {
    for (const res of [await postFetch({}), await postFetch({}, '{"id":')]) {
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ success: false, error: 'This route needs the parent token' });
    }
    expect(io.vsockConnectAsync).not.toHaveBeenCalled();
    expect(errors).toEqual(Array(2).fill('[parent] Refused POST "/attest/fetch": no parent token'));
  });

  it.each([
    ['a wrong token', { Authorization: 'Bearer testonly-parent-token-0123456789abcdeX' }],
    ['a prefix of the token', { Authorization: `Bearer ${TOKEN.slice(0, -1)}` }],
    ['the token without its scheme', { Authorization: TOKEN }],
    ['the token in another scheme', { Authorization: `Basic ${TOKEN}` }],
    ['the token in another scheme as long as "Bearer "', { Authorization: `Digest ${TOKEN}` }],
    ['the token in another header', { 'X-Parent-Token': TOKEN }],
  ])('%s: 401', async (_label, headers) => {
    expect((await postFetch(headers)).status).toBe(401);
    expect(io.vsockConnectAsync).not.toHaveBeenCalled();
  });

  it('with it: forwarded as before, and nothing of it reaches the enclave or a log line (lock)', async () => {
    const conn = await enclaveConnection(ANSWER);
    io.vsockConnectAsync.mockResolvedValue(conn);
    const res = await postFetch({ Authorization: `Bearer ${TOKEN}` });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(ANSWER);
    expect(await framedRequest(conn)).toEqual(request());
    expect(conn.sent().toString('utf-8')).not.toContain(TOKEN);
    expect([...logs, ...errors].join('\n')).not.toContain(TOKEN);
  });

  it('another spelling of the path is guarded too', async () => {
    for (const path of ['/ATTEST/FETCH', '/Attest/Fetch', '/attest/fetch/']) {
      const res = await send(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request()) });
      expect(res.status, path).toBe(401);
    }
    expect(io.vsockConnectAsync).not.toHaveBeenCalled();
  });

  it('/metrics and /routes need it; /health does not (the host watchdog, the reload script and data-bridge read it)', async () => {
    expect((await send('/metrics')).status).toBe(401);
    expect((await send('/routes')).status).toBe(401);
    expect((await send('/metrics', { headers: { Authorization: `Bearer ${TOKEN}` } })).status).toBe(200);
    expect((await send('/routes', { headers: { Authorization: `Bearer ${TOKEN}` } })).status).toBe(200);
    io.execSync.mockReturnValue('[]');
    io.execFile.mockImplementation((_cmd: string, _args: string[], _opts: unknown, callback: (err: Error | null, stdout?: string) => void) => callback(null, '[]'));
    io.readdir.mockResolvedValue([]);
    const health = await send('/health');
    expect(health.status).toBe(503); // answered without the token: no enclave runs in this test
    expect(await health.json()).toMatchObject({ healthy: false });
  });
});

describe('the host role\'s credentials go only to an enclave that opens sealed secrets (enclave audit P1.7)', () => {
  const STRIPE = 'https://api.stripe.com/v1/charges';
  const EXPIRES = Date.now() + 6 * 3600_000;
  const CREDS = { accessKeyId: 'ASIATESTONLY00000001', secretAccessKey: 'testonly-secret-access-key-1', sessionToken: 'testonly-session-token-1' };
  /** A Stripe request that sends its key sealed: the one kind that needs the credentials (enclave review E2b F-12). */
  const sealed = (over: Record<string, unknown> = {}) =>
    request({ url: STRIPE, body: JSON.stringify({ operation: 'list_charges', sealedApiKey: 'dGVzdG9ubHktc2VhbGVkLWtleQ==' }), ...over });
  const opened: Array<{ close(): Promise<void> }> = [];
  afterEach(async () => {
    for (const each of opened.splice(0)) await each.close();
  });

  /**
   * The parent with the real IMDSv2 reader over a fake IMDS. The reader is loaded here, not at the top: on the release
   * before this one the module does not exist, and only the tests that use it may fail for it.
   */
  async function withImds(failing = false) {
    const imds = await startFakeImds({ answer: (read) => imdsCredentials(read, EXPIRES) });
    if (failing) imds.failWith(500);
    const { createHostCredentials } = await import('../hostCredentials.js');
    const app = await listen(createApp({ hostCredentials: createHostCredentials({ endpoint: imds.url }) }));
    opened.push(app, imds);
    return { imds, url: app.url };
  }

  /** The parent with a stand-in reader that gives CREDS and counts its calls. */
  async function withReader() {
    const reader = { calls: 0, get: async () => { reader.calls++; return CREDS; } };
    const app = await listen(createApp({ hostCredentials: reader } as Parameters<typeof createApp>[0]));
    opened.push(app);
    return { reader, url: app.url };
  }

  /** POST `body` to the parent at `url`; what it framed to the enclave. */
  async function forwardTo(url: string, body: unknown) {
    const conn = await enclaveConnection(ANSWER);
    io.vsockConnectAsync.mockResolvedValue(conn);
    const res = await fetch(`${url}/attest/fetch`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { res, framed: await framedRequest(conn) };
  }

  it('a request to the Stripe enclave that sends a sealed key carries them, read from IMDSv2 (red)', async () => {
    const { imds, url } = await withImds();
    const { res, framed } = await forwardTo(url, sealed());
    expect(res.status).toBe(200);
    expect(io.vsockConnectAsync).toHaveBeenCalledWith(18, 5000, expect.any(Number));
    expect(framed).toEqual({ ...sealed(), awsCredentials: CREDS });
    expect(imds.calls).toContain('GET /latest/meta-data/iam/security-credentials/tytle-staging-enclave-host token');
  });

  it('they are kept: the next Stripe requests do not read IMDS again (red)', async () => {
    const { imds, url } = await withImds();
    await forwardTo(url, sealed());
    await forwardTo(url, sealed());
    await forwardTo(url, sealed());
    expect(imds.reads()).toBe(1);
  });

  // Enclave review 2026-10-09, E2b F-12: they are the whole host role's credentials, which can also write the PCR0 pins
  // in SSM, and before they went with every request to the Stripe enclave. Only a sealed key needs them.
  it('a Stripe request that sends its key in clear (apiKey) gets none, and the host role is not read (red)', async () => {
    const { reader, url } = await withReader();
    const clear = request({ url: STRIPE, body: JSON.stringify({ operation: 'list_charges', apiKey: 'sk_test_testonly' }) });
    const { res, framed } = await forwardTo(url, clear);
    expect(res.status).toBe(200);
    expect(framed).toEqual(clear);
    expect(reader.calls).toBe(0);
  });

  it.each([
    ['no body', undefined],
    ['an empty body', ''],
    ['a body that is not JSON', 'sealedApiKey=dGVzdA=='],
    ['a JSON null', 'null'],
    ['a JSON array', JSON.stringify([{ sealedApiKey: 'dGVzdA==' }])],
    ['an empty sealedApiKey', JSON.stringify({ operation: 'list_charges', sealedApiKey: '' })],
    ['a sealedApiKey that is not text', JSON.stringify({ operation: 'list_charges', sealedApiKey: 7 })],
    ['a sealedApiKey of null', JSON.stringify({ operation: 'list_charges', sealedApiKey: null })],
  ])('a Stripe request with %s sends no sealed key: it gets none (red)', async (_name, body) => {
    const { reader, url } = await withReader();
    const asked = request({ url: STRIPE, body });          // body undefined: JSON leaves it out
    const { framed } = await forwardTo(url, asked);
    expect(framed).toEqual(asked);
    expect(reader.calls).toBe(0);
  });

  it('a sealed key sent to an enclave that opens none gets none (lock)', async () => {
    const { reader, url } = await withReader();
    // A field named "undefined" too: which field carries a sealed key is the enclave's, never the body's
    const toVies = request({ body: JSON.stringify({ sealedApiKey: 'dGVzdA==', undefined: 'dGVzdA==' }) });
    expect((await forwardTo(url, toVies)).framed).toEqual(toVies);
    expect(reader.calls).toBe(0);
  });

  it.each([
    ['VIES', 'https://ec.europa.eu/x'],
    ['SICAE', 'http://www.sicae.pt/Consulta.aspx'],
  ])('a request to %s never carries them, and the reader is not asked for it (lock)', async (_name, url) => {
    const { reader, url: parent } = await withReader();
    const { framed } = await forwardTo(parent, request({ url }));
    expect(framed).toEqual(request({ url }));
    expect(reader.calls).toBe(0);
  });

  it('a caller\'s own awsCredentials field is dropped: only the parent sets one (red)', async () => {
    const { url } = await withReader();
    const forged = { accessKeyId: 'AKIAFORGEDFORGEDFORG', secretAccessKey: 'forged', sessionToken: 'forged' };
    expect((await forwardTo(url, { ...request(), awsCredentials: forged })).framed).not.toHaveProperty('awsCredentials');
    expect((await forwardTo(url, { ...request({ url: STRIPE }), awsCredentials: forged })).framed).not.toHaveProperty('awsCredentials');
    expect((await forwardTo(url, { ...sealed(), awsCredentials: forged })).framed.awsCredentials).toEqual(CREDS);
  });

  it('they never reach a log line (red)', async () => {
    const { url } = await withImds();
    const { framed } = await forwardTo(url, sealed());
    expect(framed.awsCredentials).toEqual(CREDS);
    const all = [...logs, ...errors].join('\n');
    expect(all).not.toContain(CREDS.secretAccessKey);
    expect(all).not.toContain(CREDS.sessionToken);
  });

  it('IMDS down: the Stripe request still goes, without them (only a sealed key then fails, in the enclave) (red)', async () => {
    const { url } = await withImds(true);
    const { res, framed } = await forwardTo(url, sealed());
    expect(res.status).toBe(200);
    expect(framed).toEqual(sealed());
    expect(errors).toEqual(['[parent] IMDSv2: no host role credentials: "IMDS answered 500 to PUT /latest/api/token"']);
  });
});

/** The number of connections `server` holds now. */
function connectionsOf(server: Server): Promise<number> {
  return new Promise((resolve, reject) => server.getConnections((err, count) => (err ? reject(err) : resolve(count))));
}

describe('a caller that has gone (enclave review 2026-10-09, E2b F-1, item 2)', () => {
  it('a request whose caller closed its connection before the parent sent it on never reaches the enclave (red)', async () => {
    // A Stripe request waits for the host role's credentials; its caller gives up meanwhile, as data-bridge does at its
    // own deadline. Before, the parent sent it on anyway: the enclave fetched upstream and minted a document nobody got.
    let asked!: () => void;
    const imdsAsked = new Promise<void>((resolve) => { asked = resolve; });
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    const imds = await startFakeImds({
      answer: async (read) => {
        asked();
        await held;
        return imdsCredentials(read, Date.now() + 6 * 3600_000);
      },
    });
    const { createHostCredentials } = await import('../hostCredentials.js');
    const parent = createApp({ hostCredentials: createHostCredentials({ endpoint: imds.url }) }).listen(0, '127.0.0.1');
    await once(parent, 'listening');
    try {
      const caller = http.request({
        host: '127.0.0.1',
        port: (parent.address() as AddressInfo).port,
        method: 'POST',
        path: '/attest/fetch',
        headers: { 'Content-Type': 'application/json' },
      });
      caller.on('error', () => { /* destroyed below, on purpose */ });
      // A sealed key: the one kind of Stripe request that waits for the host role's credentials
      caller.end(JSON.stringify(request({
        url: 'https://api.stripe.com/v1/charges',
        body: JSON.stringify({ operation: 'list_charges', sealedApiKey: 'dGVzdG9ubHktc2VhbGVkLWtleQ==' }),
      })));
      await imdsAsked;
      caller.destroy();
      await vi.waitFor(async () => expect(await connectionsOf(parent)).toBe(0));
      release();
      await vi.waitFor(() => expect(logs).toContain(`[parent] ${ID}: the caller has gone; not sent to the enclave`));
      expect(io.vsockConnectAsync).not.toHaveBeenCalled();
    } finally {
      release();
      await new Promise<void>((resolve) => parent.close(() => resolve()));
      await imds.close();
    }
  });
});

/** The status of the next response on `socket`: its head, then its Content-Length body. */
function nextResponse(socket: net.Socket): Promise<number> {
  return new Promise((resolve, reject) => {
    let bytes = Buffer.alloc(0);
    const stop = (): void => {
      socket.off('data', onData);
      socket.off('close', onClose);
    };
    const onClose = (): void => {
      stop();
      reject(new Error('the parent closed the connection'));
    };
    const onData = (chunk: Buffer): void => {
      bytes = Buffer.concat([bytes, chunk]);
      const headEnd = bytes.indexOf('\r\n\r\n');
      if (headEnd === -1) return;
      const head = bytes.subarray(0, headEnd).toString('latin1');
      const length = Number(/\r\ncontent-length: *(\d+)/i.exec(head)?.[1] ?? 0);
      if (bytes.length < headEnd + 4 + length) return;
      stop();
      resolve(Number(head.slice('HTTP/1.1 '.length, 'HTTP/1.1 '.length + 3)));
    };
    socket.on('data', onData);
    socket.on('close', onClose);
  });
}

describe('an idle connection is kept for the caller\'s next request (enclave review 2026-10-09, E2b F-1, item 4)', () => {
  it('a connection idle 7 s, past Node\'s 5 s, still serves the next request (red)', async () => {
    // The parent listens as server.ts starts it (listenParent). The release before had none: it listened with Node's
    // defaults, whose 5 s timer closed an idle connection (Node 24 and later wait 1 s more: 7 s is past both).
    const start = typeof listenParent === 'function'
      ? listenParent
      : (app: ReturnType<typeof createApp>, port: number, host: string): Server => app.listen(port, host);
    const parent = start(createApp(), 0, '127.0.0.1');
    await once(parent, 'listening');
    const socket = net.connect((parent.address() as AddressInfo).port, '127.0.0.1');
    let closedByParent = false;
    socket.on('end', () => { closedByParent = true; });
    try {
      await once(socket, 'connect');
      const ask = 'GET /routes HTTP/1.1\r\nHost: parent\r\n\r\n';
      socket.write(ask);
      expect(await nextResponse(socket)).toBe(200);
      await new Promise((resolve) => setTimeout(resolve, 7_000));
      expect(closedByParent).toBe(false);
      const second = nextResponse(socket);
      socket.write(ask);
      expect(await second).toBe(200);
    } finally {
      socket.destroy();
      await new Promise<void>((resolve) => parent.close(() => resolve()));
    }
  }, 15_000);
});
