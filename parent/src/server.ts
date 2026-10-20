/**
 * Parent Server - starts the parent's HTTP app (app.ts) on the host.
 *
 * Runs on the EC2 host (not inside an enclave) - needs /dev/vsock access.
 * Deployed via systemd, NOT Docker (Docker would block vsock access).
 */

import { createApp, listenParent } from './app.js';
import { createHostCredentials } from './hostCredentials.js';

const PORT = parseInt(process.env.PORT || '5001', 10);
const authToken = process.env.ENCLAVE_PARENT_AUTH_TOKEN || undefined;

// The narrow role whose sessions the enclaves get (the parent's unit sets it; nitro-enclave-stack.ts)
const roleArn = process.env.ENCLAVE_KMS_ROLE_ARN || undefined;

listenParent(createApp({ authToken, hostCredentials: createHostCredentials({ roleArn }) }), PORT, '0.0.0.0', () => {
  console.log(`[parent] Enclave parent server listening on port ${PORT}`);
  if (!authToken) {
    console.log('[parent] ENCLAVE_PARENT_AUTH_TOKEN is not set: /attest/fetch, /metrics and /routes answer every caller that reaches this port');
  }
});
