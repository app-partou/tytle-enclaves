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
import { findRoute, getAllRoutes } from './enclaveRouter.js';
import { sendToEnclave } from './vsockClient.js';
import { checkHealth } from './healthCheck.js';
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

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

export function createApp(): express.Express {
  const metrics = new Map<number, EnclaveMetrics>();
  const app = express();
  app.use(express.json({ limit: '10mb' }));

  /**
   * POST /attest/fetch - main attestation endpoint.
   */
  app.post('/attest/fetch', async (req, res) => {
    const { id, url, method, headers, body, challenge } = req.body;

    if (!url || !method) {
      res.status(400).json({ success: false, error: 'Missing required fields: url, method' });
      return;
    }
    // The caller's challenge (P1.3) goes to the enclave untouched; the enclave checks its format.
    if (challenge !== undefined && typeof challenge !== 'string') {
      res.status(400).json({ success: false, error: 'challenge must be a string' });
      return;
    }

    const requestId = id || crypto.randomUUID();
    const route = findRoute(url);
    if (!route) {
      res.status(404).json({ success: false, error: `No enclave configured for URL: ${url}` });
      return;
    }

    console.log(`[parent] ${requestId}: Routing ${method} ${url} -> CID ${route.cid}:${route.port}`);

    const start = Date.now();
    try {
      const enclaveRequest: EnclaveRequest = {
        id: requestId,
        url,
        method,
        headers: headers || {},
        body,
        ...(challenge === undefined ? {} : { challenge }),
      };

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
      console.error(`[parent] ${requestId}: Enclave error (${durationMs}ms): ${msg}`);
      res.status(502).json({ success: false, error: `Enclave communication failed: ${msg}` });
    }
  });

  /** GET /health - health check for Cloud Map / load balancer. */
  app.get('/health', async (_req, res) => {
    const status = await checkHealth();
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

  return app;
}
