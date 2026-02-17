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

/** Routing table: hostname → enclave CID + port. */
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
  // Future: Stripe enclave
  // { cid: parseInt(process.env.STRIPE_CID || '18', 10), port: 5000, hosts: ['api.stripe.com'] },
];

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
