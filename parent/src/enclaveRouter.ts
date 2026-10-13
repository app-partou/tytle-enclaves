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

// monerium-payment (CID 19) is routed only when the host's parent unit names
// MONERIUM_PAYMENT_CID. The main repo's service registry
// (infra/lib/enclaveServices.ts) sets it on exactly the hosts that launch the
// enclave, so /health never waits for an enclave the host does not run.
if (process.env.MONERIUM_PAYMENT_CID) {
  ROUTES.push({
    cid: parseInt(process.env.MONERIUM_PAYMENT_CID, 10),
    port: 5000,
    hosts: ['api.monerium.app'],
  });
}

/**
 * The enclaves that open secrets sealed to them with KMS (enclave audit P1.7), each with the field of its request body
 * that carries one. Only a request that sends a sealed secret gets the host role's AWS credentials, to sign that
 * enclave's KMS Decrypt; every other request, and every other enclave, never sees them. They are the whole host role's
 * credentials, which can also write the PCR0 pins (hostCredentials.ts), and before, they went with every request to the
 * Stripe enclave (enclave review 2026-10-09, E2b F-12). Stripe's allowlist names KMS for this; an enclave added here
 * must name it too.
 */
const SEALED_SECRET_FIELDS: ReadonlyMap<number, string> = new Map([[STRIPE_PAYMENT_CID, 'sealedApiKey']]);

/**
 * Whether a request to `route` with this body sends a sealed secret: the enclave opens sealed secrets, and the body is
 * a JSON object whose sealed-secret field is non-empty text. The enclave reads the body with the same JSON.parse, and
 * takes an empty or missing field for no sealed secret; it checks the value itself.
 */
export function sendsSealedSecret(route: EnclaveRoute, body: string | undefined): boolean {
  const field = SEALED_SECRET_FIELDS.get(route.cid);
  if (field === undefined || body === undefined) return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return false;                        // an empty body too
  }
  if (parsed === null || typeof parsed !== 'object') return false;
  const value = (parsed as Record<string, unknown>)[field];
  return typeof value === 'string' && value !== '';
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
