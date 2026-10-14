/**
 * The parent's HTTP app - generic router between data-bridge and the Nitro Enclaves.
 *
 * Receives POST /attest/fetch from data-bridge (via Cloud Map discovery),
 * routes to the appropriate enclave based on URL hostname, and returns
 * the attested response. server.ts starts it; tests drive it on an ephemeral port.
 *
 * Runs on the EC2 host (not inside an enclave) - needs /dev/vsock access.
 * Deployed via systemd, NOT Docker (Docker would block vsock access).
 */

import express from 'express';
import crypto from 'node:crypto';
import type { Server } from 'node:http';
import { findRoute, getAllRoutes, sendsSealedSecret } from './enclaveRouter.js';
import { sendToEnclave } from './vsockClient.js';
import { checkHealth, type HealthStatus } from './healthCheck.js';
import { MAX_REQUEST_BODY, parseFetchRequest } from './requestSchema.js';
import type { HostCredentials } from './hostCredentials.js';
import type { EnclaveRequest } from './types.js';

// ---------------------------------------------------------------------------
// In-memory metrics (reset on restart)
// ---------------------------------------------------------------------------

interface EnclaveMetrics {
  requests: number;
  errors: number;
  latencies: number[];
}

const LATENCY_BUFFER_SIZE = 1000;

function recordMetric(metrics: Map<number, EnclaveMetrics>, cid: number, durationMs: number, isError: boolean): void {
  let m = metrics.get(cid);
  if (!m) {
    m = { requests: 0, errors: 0, latencies: [] };
    metrics.set(cid, m);
  }
  m.requests++;
  if (isError) m.errors++;
  m.latencies.push(durationMs);
  if (m.latencies.length > LATENCY_BUFFER_SIZE) {
    m.latencies = m.latencies.slice(-LATENCY_BUFFER_SIZE);
  }
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
}

/** The HTTP status an error carries (body-parser's errors carry one), if any. */
function statusOf(err: unknown): number | undefined {
  if (typeof err !== 'object' || err === null || !('status' in err)) return undefined;
  const { status } = err as { status: unknown };
  return typeof status === 'number' ? status : undefined;
}

const sha256 = (text: string): Buffer => crypto.createHash('sha256').update(text, 'utf-8').digest();

/**
 * Whether `header` is `Bearer <token>`. Compared as SHA-256 digests with timingSafeEqual: equal lengths, so neither
 * the time nor a length check tells a caller how much of a guess was right.
 */
function carriesToken(header: string | undefined, token: string): boolean {
  if (header === undefined || !header.startsWith('Bearer ')) return false;
  return crypto.timingSafeEqual(sha256(header.slice('Bearer '.length)), sha256(token));
}

/**
 * How long one /health check answers every probe after it, in ms. A probe used to start a check of its own (nitro-cli,
 * a ping per enclave, systemctl per proxy), so a loop of probes, which needs no token, made the host do that work
 * without end (enclave review 2026-10-09, E2b F-2). The host's watchdog reads /health every 30 s and the reload's ready
 * check every 5 s: an answer 2 s old misleads neither.
 */
export const HEALTH_CACHE_MS = 2_000;

/**
 * How long an idle connection is kept for its caller's next request, in ms (Node's default: 5 s). data-bridge's fetch
 * keeps one for the time the parent's Keep-Alive header gives, less a margin, so the parent always closes last; a longer
 * life means fewer connections, and fewer reuses close to the edge. Before, the parent's event loop could stall past
 * that margin, and its timer closed a connection with a request on it, unread (E2b F-1, item 4).
 */
export const PARENT_KEEP_ALIVE_MS = 65_000;

/**
 * Start `app` on `port` as the parent serves: with PARENT_KEEP_ALIVE_MS. server.ts starts the parent with it; the tests
 * start it the same way.
 */
export function listenParent(app: express.Express, port: number, host: string, onListening?: () => void): Server {
  const server = app.listen(port, host, onListening);
  server.keepAliveTimeout = PARENT_KEEP_ALIVE_MS;
  return server;
}

/**
 * The health check behind /health: probes that come while a check runs share it, and its answer serves every probe for
 * `cacheMs` after it ended.
 */
function sharedHealthCheck(cacheMs: number): () => Promise<HealthStatus> {
  let last: { status: HealthStatus; endedAt: number } | null = null;
  let running: Promise<HealthStatus> | null = null;
  return () => {
    if (last !== null && Date.now() - last.endedAt < cacheMs) return Promise.resolve(last.status);
    running ??= checkHealth()
      .then((status) => {
        last = { status, endedAt: Date.now() };
        return status;
      })
      .finally(() => {
        running = null;
      });
    return running;
  };
}

export interface ParentOptions {
  /**
   * The shared secret data-bridge sends as `Authorization: Bearer <token>` (ENCLAVE_PARENT_AUTH_TOKEN, enclave audit
   * P1.7 "interim"): when set, /attest/fetch, /metrics and /routes answer only a request that carries it. /health
   * stays open: the host's watchdog and reload script and data-bridge's health probe read it. Unset: every route is
   * open, as before.
   */
  authToken?: string;
  /**
   * The host role's credentials, for a request that sends a sealed secret to an enclave that opens one
   * (hostCredentials.ts, enclaveRouter.ts sendsSealedSecret). Unset: none sent.
   */
  hostCredentials?: HostCredentials;
  /**
   * How long one /health check answers every probe after it (HEALTH_CACHE_MS when unset). At 0 each probe checks anew,
   * though probes that come while a check runs still share it.
   */
  healthCacheMs?: number;
}

/** The routes the parent token guards. */
export const GUARDED_PATHS: readonly string[] = ['/attest/fetch', '/metrics', '/routes'];

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

export function createApp(options: ParentOptions = {}): express.Express {
  const metrics = new Map<number, EnclaveMetrics>();
  const app = express();
  const { authToken, hostCredentials } = options;
  const health = sharedHealthCheck(options.healthCacheMs ?? HEALTH_CACHE_MS);

  // Before the body is read: a request without the token costs no parsing
  if (authToken) {
    app.use(GUARDED_PATHS as string[], (req, res, next) => {
      if (carriesToken(req.get('authorization'), authToken)) {
        next();
        return;
      }
      // req.path is relative to the guard's mount point: log the path as the caller sent it
      console.error(`[parent] Refused ${req.method} ${JSON.stringify(req.originalUrl.split('?')[0])}: no parent token`);
      res.status(401).json({ success: false, error: 'This route needs the parent token' });
    });
  }
  app.use(express.json({ limit: MAX_REQUEST_BODY }));

  /**
   * POST /attest/fetch - main attestation endpoint.
   *
   * Only a request in the shape requestSchema.ts accepts is forwarded. Every logged value a caller can choose is
   * written through JSON.stringify, so it stays on its own log line; the id and the method are a UUID and a known
   * method by then.
   */
  app.post('/attest/fetch', async (req, res) => {
    // A caller that has gone (data-bridge gave up and closed the connection) gets nothing: its request is not sent to
    // the enclave, which would fetch upstream and mint a document nobody receives (enclave review 2026-10-09, E2b F-1,
    // item 2). The response closes before this handler answers only when the caller's connection does.
    let callerGone = false;
    res.on('close', () => {
      callerGone = true;
    });
    const parsed = parseFetchRequest(req.body);
    if (!parsed.ok) {
      res.status(400).json({ success: false, error: parsed.error });
      return;
    }
    const { url, method } = parsed.request;
    const requestId = parsed.request.id ?? crypto.randomUUID();
    const route = findRoute(url);
    if (!route) {
      res.status(404).json({ success: false, error: `No enclave configured for URL: ${url}` });
      return;
    }

    // The host the request goes to, never its path or query: a SICAE or HMRC lookup carries a NIF, a NIPC or a VRN there
    // (a sole trader's NIF is personal data), and the host's journal ships to CloudWatch, kept 90 days in production
    // (enclave review 2026-10-09, M3 F-11, the log part). findRoute read the same URL, so it parses.
    const host = new URL(url).host;
    console.log(`[parent] ${requestId}: Routing ${method} ${JSON.stringify(host)} -> CID ${route.cid}:${route.port}`);

    const start = Date.now();
    try {
      // The host role's credentials go only with a request that sends a sealed secret to an enclave that opens one
      // (enclaveRouter.ts sendsSealedSecret); without them the request still goes, and only a sealed secret fails, in
      // the enclave (NO_CREDENTIALS)
      const awsCredentials = hostCredentials && sendsSealedSecret(route, parsed.request.body)
        ? await hostCredentials.get()
        : null;
      if (callerGone) {
        console.log(`[parent] ${requestId}: the caller has gone; not sent to the enclave`);
        return;
      }
      const enclaveRequest: EnclaveRequest = { ...parsed.request, id: requestId, ...(awsCredentials ? { awsCredentials } : {}) };

      const response = await sendToEnclave(route.cid, route.port, enclaveRequest);
      const durationMs = Date.now() - start;
      recordMetric(metrics, route.cid, durationMs, !response.success);

      console.log(
        `[parent] ${requestId}: ${response.success ? 'OK' : 'FAILED'} (status ${response.status}, ${durationMs}ms)`,
      );

      res.json(response);
    } catch (err: unknown) {
      const durationMs = Date.now() - start;
      recordMetric(metrics, route.cid, durationMs, true);
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[parent] ${requestId}: Enclave error (${durationMs}ms): ${JSON.stringify(msg)}`);
      res.status(502).json({ success: false, error: `Enclave communication failed: ${msg}` });
    }
  });

  /** GET /health - health check for Cloud Map / load balancer. A probe gets the shared check's answer (HEALTH_CACHE_MS). */
  app.get('/health', async (_req, res) => {
    const status = await health();
    res.status(status.healthy ? 200 : 503).json(status);
  });

  /** GET /metrics - per-enclave request counts and latency percentiles. */
  app.get('/metrics', (_req, res) => {
    const routes = getAllRoutes();
    const result: Record<string, unknown>[] = routes.map((route) => {
      const m = metrics.get(route.cid);
      if (!m || m.latencies.length === 0) {
        return {
          cid: route.cid,
          hosts: route.hosts,
          requests: m?.requests ?? 0,
          errors: m?.errors ?? 0,
          latency: null,
        };
      }
      const sorted = [...m.latencies].sort((a, b) => a - b);
      return {
        cid: route.cid,
        hosts: route.hosts,
        requests: m.requests,
        errors: m.errors,
        latency: {
          p50: percentile(sorted, 50),
          p95: percentile(sorted, 95),
          p99: percentile(sorted, 99),
          samples: sorted.length,
        },
      };
    });
    res.json({ enclaves: result, timestamp: Date.now() });
  });

  /** GET /routes - list configured enclave routes (diagnostics). */
  app.get('/routes', (_req, res) => {
    res.json({ routes: getAllRoutes() });
  });

  /**
   * A body the parent cannot read (not JSON, larger than MAX_REQUEST_BODY) is answered in JSON, as every other
   * answer: Express's own answer is an HTML page. Express knows an error handler by its four parameters.
   */
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = statusOf(err);
    if (status === 413) {
      res.status(413).json({ success: false, error: `Request body is larger than ${MAX_REQUEST_BODY}` });
      return;
    }
    if (status !== undefined && status >= 400 && status < 500) {
      res.status(status).json({ success: false, error: 'Request body is not readable JSON' });
      return;
    }
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[parent] Internal error: ${JSON.stringify(msg)}`);
    res.status(500).json({ success: false, error: 'Internal error' });
  });

  return app;
}
