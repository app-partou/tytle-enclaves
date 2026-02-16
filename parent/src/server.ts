/**
 * Parent Server — generic router between Fargate services and Nitro Enclaves.
 *
 * Receives POST /attest/fetch from ai-agent-server (via Cloud Map discovery),
 * routes to the appropriate enclave based on URL hostname, and returns
 * the attested response.
 *
 * Runs on the EC2 host (not inside an enclave) — needs /dev/vsock access.
 * Deployed via systemd, NOT Docker (Docker would block vsock access).
 */

import express from 'express';
import crypto from 'node:crypto';
import { findRoute, getAllRoutes } from './enclaveRouter.js';
import { sendToEnclave } from './vsockClient.js';
import { checkHealth } from './healthCheck.js';
import type { EnclaveRequest } from './types.js';

const PORT = parseInt(process.env.PORT || '5001', 10);

const app = express();
app.use(express.json({ limit: '10mb' }));

/**
 * POST /attest/fetch — main attestation endpoint.
 *
 * Request body matches what attestedFetchService.ts sends:
 * { id, url, method, headers, body }
 *
 * Response: { success, status, headers, rawBody, attestation, error? }
 */
app.post('/attest/fetch', async (req, res) => {
  const { id, url, method, headers, body } = req.body;

  if (!url || !method) {
    res.status(400).json({
      success: false,
      error: 'Missing required fields: url, method',
    });
    return;
  }

  const requestId = id || crypto.randomUUID();

  // Find the enclave that handles this URL
  const route = findRoute(url);
  if (!route) {
    res.status(404).json({
      success: false,
      error: `No enclave configured for URL: ${url}`,
    });
    return;
  }

  console.log(`[parent] ${requestId}: Routing ${method} ${url} → CID ${route.cid}:${route.port}`);

  try {
    const enclaveRequest: EnclaveRequest = {
      id: requestId,
      url,
      method,
      headers: headers || {},
      body,
    };

    const response = await sendToEnclave(route.cid, route.port, enclaveRequest);

    console.log(
      `[parent] ${requestId}: ${response.success ? 'OK' : 'FAILED'} (status ${response.status})`,
    );

    res.json(response);
  } catch (err: any) {
    console.error(`[parent] ${requestId}: Enclave error: ${err.message}`);
    res.status(502).json({
      success: false,
      error: `Enclave communication failed: ${err.message}`,
    });
  }
});

/** GET /health — health check for Cloud Map / load balancer. */
app.get('/health', (_req, res) => {
  const status = checkHealth();
  res.status(status.healthy ? 200 : 503).json(status);
});

/** GET /routes — list configured enclave routes (diagnostics). */
app.get('/routes', (_req, res) => {
  res.json({ routes: getAllRoutes() });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[parent] Enclave parent server listening on port ${PORT}`);
});
