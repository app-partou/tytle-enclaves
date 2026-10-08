/**
 * Parent Server - starts the parent's HTTP app (app.ts) on the host.
 *
 * Runs on the EC2 host (not inside an enclave) - needs /dev/vsock access.
 * Deployed via systemd, NOT Docker (Docker would block vsock access).
 */

import { createApp } from './app.js';
import { createHostCredentials } from './hostCredentials.js';

const PORT = parseInt(process.env.PORT || '5001', 10);
const authToken = process.env.ENCLAVE_PARENT_AUTH_TOKEN || undefined;

createApp({ authToken, hostCredentials: createHostCredentials() }).listen(PORT, '0.0.0.0', () => {
  console.log(`[parent] Enclave parent server listening on port ${PORT}`);
  if (!authToken) {
    console.log('[parent] ENCLAVE_PARENT_AUTH_TOKEN is not set: /attest/fetch, /metrics and /routes answer every caller that reaches this port');
  }
});
