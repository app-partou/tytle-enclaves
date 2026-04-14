/**
 * Enclave Router — maps URL hostnames to enclave CID + port.
 *
 * CIDs are read from environment variables (set by CDK user data / systemd)
 * to stay in sync with the infrastructure config. Defaults are provided for
 * development / testing.
 *
 * Each enclave has its own CID (assigned when launched via nitro-cli run-enclave)
 * and its own URL allowlist (enforced inside the enclave code).
 */

import type { EnclaveRoute } from './types.js';

/** Read CID from env, fall back to default. Set by CDK user data in production. */
const VIES_CID = parseInt(process.env.VIES_CID || '16', 10);
const SICAE_CID = parseInt(process.env.SICAE_CID || '17', 10);
const STRIPE_PAYMENT_CID = parseInt(process.env.STRIPE_PAYMENT_CID || '18', 10);

/**
 * Routing table: hostname -> enclave CID + port.
 *
 * Only includes enclaves that are actually deployed by the current
 * infrastructure. An enclave in this list means:
 *   1. /health expects its nitro-cli state to be RUNNING
 *   2. findRoute() will dispatch requests to its CID
 *
 * Do NOT add an enclave here until the deploy workflow builds + launches it.
 * Otherwise /health returns 503 (the enclave is never RUNNING) and the
 * staging/prod reload script fails its post-reload health check.
 */
const ROUTES: EnclaveRoute[] = [
  {
    cid: VIES_CID,
    port: 5000,
    hosts: ['ec.europa.eu', 'api.service.hmrc.gov.uk'],
  },
  {
    cid: SICAE_CID,
    port: 5000,
    hosts: ['www.sicae.pt'],
  },
  {
    cid: STRIPE_PAYMENT_CID,
    port: 5000,
    hosts: ['api.stripe.com'],
  },
];

// monerium-payment enclave is opt-in: the deploy workflow does not currently
// build or launch it on staging/prod, so it must not be in the default route
// list. When the infra is ready, set MONERIUM_PAYMENT_CID in the systemd
// unit env (alongside VIES_CID, SICAE_CID, STRIPE_PAYMENT_CID) to enable it.
if (process.env.MONERIUM_PAYMENT_CID) {
  ROUTES.push({
    cid: parseInt(process.env.MONERIUM_PAYMENT_CID, 10),
    port: 5000,
    hosts: ['api.monerium.app'],
  });
}

/**
 * Find the enclave route for a given URL.
 *
 * @param url - Full URL of the request
 * @returns The matching route, or null if no enclave handles this host
 */
export function findRoute(url: string): EnclaveRoute | null {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;

    for (const route of ROUTES) {
      if (route.hosts.includes(hostname)) {
        return route;
      }
    }

    return null;
  } catch {
    return null;
  }
}

/** Get all configured routes (for health check / diagnostics). */
export function getAllRoutes(): EnclaveRoute[] {
  return [...ROUTES];
}
