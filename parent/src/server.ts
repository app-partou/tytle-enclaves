/**
 * Parent Server - starts the parent's HTTP app (app.ts) on the host.
 *
 * Runs on the EC2 host (not inside an enclave) - needs /dev/vsock access.
 * Deployed via systemd, NOT Docker (Docker would block vsock access).
 */

import { createApp } from './app.js';

const PORT = parseInt(process.env.PORT || '5001', 10);

createApp().listen(PORT, '0.0.0.0', () => {
  console.log(`[parent] Enclave parent server listening on port ${PORT}`);
});
