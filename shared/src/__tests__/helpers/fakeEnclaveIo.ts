/**
 * The enclave's two boundaries, faked for tests that run the REAL handler factory and the REAL handler
 * definitions (P2.4): the network (a vsock socket to a host proxy, plus the TLS layer for HTTPS hosts)
 * and the NSM device. Everything between them - createHandler, ctx.fetch, httpProxy, httpParse, the
 * retry, the BN254 encoder and attest() - runs for real.
 *
 * Use from a test file (vi.mock factories are hoisted, so import the module inside them):
 *   vi.mock('@tytle-enclaves/native', async () => (await import('<path>/fakeEnclaveIo.js')).nativeModule);
 *   vi.mock('node:tls', async () => (await import('<path>/fakeEnclaveIo.js')).tlsModule);
 *   import { fakeIo } from '<path>/fakeEnclaveIo.js';
 *   fakeIo.reset(); fakeIo.reply(8443, 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok');
 *
 * A host proxy is known by its vsock port (each enclave's src/enclave.ts). Each connect to a port takes the
 * next scripted reply for that port; a connect with nothing scripted fails like a proxy that is down.
 */
import { EventEmitter } from 'node:events';
import { createFakeNsm } from './fakeNsm.js';

interface Exchange {
  port: number;
  written: Buffer[];
}

const queues = new Map<number, string[]>();
const exchanges: Exchange[] = [];
let nsm = createFakeNsm();

function nextReply(port: number): string {
  const queue = queues.get(port);
  const raw = queue?.shift();
  if (raw === undefined) throw new Error(`connect(cid=3, port=${port}) failed: Connection refused (nothing scripted)`);
  return raw;
}

/** A vsock socket to a host proxy: hands out the scripted reply (for plain HTTP), records what is written. */
class FakeVsock {
  private reply: Buffer;
  private offset = 0;
  constructor(private readonly exchange: Exchange, raw: string, private readonly plain: boolean) {
    // Under TLS the vsock leg carries only TLS records: the reply arrives through the fake TLS socket instead.
    this.reply = plain ? Buffer.from(raw, 'utf-8') : Buffer.alloc(0);
  }
  read(size: number): Buffer {
    const out = this.reply.subarray(this.offset, this.offset + Math.min(size, 65536));
    this.offset += out.length;
    return out;
  }
  write(data: Buffer): number {
    if (this.plain) this.exchange.written.push(Buffer.from(data));
    return data.length;
  }
  close(): void {}
}

/** Ports whose host is reached over TLS; every other port is plain HTTP (SICAE, port 8445, has no HTTPS at all). */
const PLAIN_PORTS = new Set([8445]);

const pendingTlsReply = new WeakMap<object, { exchange: Exchange; raw: string }>();

export const nativeModule = {
  nsmRequest: (request: Buffer): Buffer => nsm.nsmRequest(request),
  VsockStream: {
    connect(cid: number, port: number): FakeVsock {
      if (cid !== 3) throw new Error(`unexpected CID ${cid}`);
      const raw = nextReply(port);
      const exchange: Exchange = { port, written: [] };
      exchanges.push(exchange);
      const sock = new FakeVsock(exchange, raw, PLAIN_PORTS.has(port));
      if (!PLAIN_PORTS.has(port)) pendingTlsReply.set(sock, { exchange, raw });
      return sock;
    },
  },
  VsockListener: {
    bind(): never {
      throw new Error('VsockListener is not available in these tests');
    },
  },
  vsockConnectAsync(): never {
    throw new Error('vsockConnectAsync is not available in these tests');
  },
};

export const tlsModule = {
  connect(options: { socket: { vsock?: unknown } }, onSecure: () => void): EventEmitter & { write(d: string | Buffer): boolean; destroy(): void } {
    // httpProxy wraps the vsock socket in a VsockDuplex; find the scripted reply through its `vsock` field.
    const duplex = options.socket as unknown as { vsock: object };
    const pending = pendingTlsReply.get(duplex.vsock);
    if (!pending) throw new Error('fake TLS: no scripted reply for this socket');
    const socket = Object.assign(new EventEmitter(), {
      write(d: string | Buffer): boolean {
        pending.exchange.written.push(Buffer.from(d));
        return true;
      },
      destroy(): void {},
    });
    setImmediate(() => {
      onSecure();
      socket.emit('data', Buffer.from(pending.raw, 'utf-8'));
      socket.emit('end');
    });
    return socket;
  },
};

export const fakeIo = {
  /** Script the next reply a connect to `port` gets (raw HTTP/1.1 bytes as text). */
  reply(port: number, raw: string): void {
    const queue = queues.get(port) ?? [];
    queue.push(raw);
    queues.set(port, queue);
  },
  /** The raw requests written to `port`, in order. */
  requests(port: number): string[] {
    return exchanges.filter((e) => e.port === port).map((e) => Buffer.concat(e.written).toString('utf-8'));
  },
  /** What the enclave asked the NSM to sign, in order. */
  get nsmAsks() {
    return nsm.asks;
  },
  /** Ports still holding scripted replies nobody fetched. */
  unusedReplies(): number[] {
    return [...queues.entries()].filter(([, q]) => q.length > 0).map(([p]) => p);
  },
  reset(): void {
    queues.clear();
    exchanges.length = 0;
    nsm = createFakeNsm();
  },
};

/** An HTTP/1.1 reply with an exact Content-Length (the body's UTF-8 bytes). */
export function httpReply(status: number, body: string, headers: Record<string, string> = {}): string {
  const head = [`HTTP/1.1 ${status} X`, ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`), `Content-Length: ${Buffer.byteLength(body, 'utf-8')}`];
  return `${head.join('\r\n')}\r\n\r\n${body}`;
}
