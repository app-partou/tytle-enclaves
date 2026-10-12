/**
 * Enclave Health Monitoring.
 *
 * Two-level check:
 * 1. State: `nitro-cli describe-enclaves` confirms enclave process is RUNNING
 * 2. Connectivity: vsock ping confirms the enclave's accept loop is responsive
 *
 * Both must pass for an enclave to be marked healthy.
 *
 * It also reports each vsock proxy on the host (P0.5 step 3): the enclaves reach their upstreams only through them,
 * and from June to October 2026 every proxy crash-looped while this check said healthy
 * (docs/ENCLAVE_ATTESTATION_AUDIT_2026_10.md §0 in the main repo).
 *
 * Nothing here holds the event loop: nitro-cli and systemctl run as child processes the parent does not wait on, and the
 * pings read in slices (shared vsockWait.ts), all at once. A check took up to 11 s before, and the parent served
 * nothing else meanwhile (enclave review 2026-10-09, E2b F-1, F-2).
 */

import { execFile } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { getAllRoutes } from './enclaveRouter.js';
import { pingEnclave } from './vsockClient.js';

export type ProxyState = 'up' | 'down';

export interface HealthStatus {
  /**
   * Every enclave is RUNNING and answers its ping; /health answers 200 when it is, else 503. A down proxy is
   * reported in `proxies` and does not change it: the host's watchdog (infra/scripts/enclave-watchdog.sh in the
   * main repo) reads 503 as "the parent is up and an enclave is not", its enclave-parent-unhealthy alarm says so,
   * and its proxy gauge pages a down proxy on its own.
   */
  healthy: boolean;
  enclaves: EnclaveStatus[];
  /**
   * Each vsock-proxy unit installed on the host, by its name without the prefix (vsock-proxy-vies → vies): 'up'
   * when systemd says it is active. The same units the watchdog checks. Empty on a host without them.
   */
  proxies: Record<string, ProxyState>;
  timestamp: number;
}

interface EnclaveStatus {
  cid: number;
  hosts: string[];
  state: string;
  connectivity: 'responsive' | 'unresponsive' | 'untested';
  /**
   * The enclave's clock minus this host's, in ms (vsockClient PingResult), from its pong; null when it was not
   * pinged or did not say (audit §5.1 F1). The host's watchdog publishes the largest and alarms on it.
   */
  clockDriftMs: number | null;
  healthy: boolean;
}

/** Where the proxy units are installed (infra/lib/nitro-enclave-stack.ts writes them; the reload and watchdog read them). */
const UNIT_DIR = '/etc/systemd/system';
/** vsock-proxy-<name>.service: the names the infra gives the units (infra/lib/enclaveServices.ts VSOCK_PROXIES). */
const PROXY_UNIT_RE = /^vsock-proxy-([a-z0-9][a-z0-9-]*)\.service$/;
const SYSTEMCTL_TIMEOUT_MS = 2_000;
const NITRO_CLI_TIMEOUT_MS = 5_000;

/** Check the health of all configured enclaves, and report each proxy. */
export async function checkHealth(): Promise<HealthStatus> {
  const [enclaves, proxies] = await Promise.all([enclaveStatuses(), probeProxies()]);
  return {
    healthy: enclaves.every((e) => e.healthy),
    enclaves,
    proxies,
    timestamp: Date.now(),
  };
}

/** Each configured enclave: its state as nitro-cli lists it, then, for a running one, its ping. */
async function enclaveStatuses(): Promise<EnclaveStatus[]> {
  const enclaveStates = await getEnclaveStates();
  return Promise.all(
    getAllRoutes().map(async (route): Promise<EnclaveStatus> => {
      const state = enclaveStates.find((e) => e.EnclaveCID === route.cid);
      const isRunning = state?.State === 'RUNNING';

      let connectivity: EnclaveStatus['connectivity'] = 'untested';
      let clockDriftMs: number | null = null;
      if (isRunning) {
        const ping = await pingEnclave(route.cid, route.port);
        connectivity = ping.responsive ? 'responsive' : 'unresponsive';
        clockDriftMs = ping.clockDriftMs;
      }

      return {
        cid: route.cid,
        hosts: route.hosts,
        state: state?.State || 'NOT_FOUND',
        connectivity,
        clockDriftMs,
        healthy: isRunning && connectivity === 'responsive',
      };
    }),
  );
}

/** Each installed vsock-proxy unit and whether systemd says it is active, sorted by name. */
async function probeProxies(): Promise<Record<string, ProxyState>> {
  let files: string[];
  try {
    files = await readdir(UNIT_DIR);
  } catch {
    return {};
  }
  const units = files
    .map((file) => PROXY_UNIT_RE.exec(file))
    .filter((match): match is RegExpExecArray => match !== null)
    .map((match) => match[1])
    .sort();
  const states = await Promise.all(
    units.map(async (name): Promise<[string, ProxyState]> => [name, (await unitIsActive(`vsock-proxy-${name}`)) ? 'up' : 'down']),
  );
  return Object.fromEntries(states);
}

/** `systemctl is-active --quiet` exits 0 only for an active unit. No shell; a timeout or a missing systemctl is down. */
function unitIsActive(unit: string): Promise<boolean> {
  return new Promise((resolve) => {
    execFile('systemctl', ['is-active', '--quiet', unit], { timeout: SYSTEMCTL_TIMEOUT_MS }, (err) => resolve(err === null));
  });
}

interface NitroEnclaveInfo {
  EnclaveCID: number;
  State: string;
  EnclaveID: string;
}

/**
 * The enclaves nitro-cli lists, from `nitro-cli describe-enclaves`: no shell, and the parent serves on while it runs (it
 * was execSync, which held the event loop up to its 5 s timeout). A failure, a timeout or an output that is not JSON is
 * none.
 */
function getEnclaveStates(): Promise<NitroEnclaveInfo[]> {
  return new Promise((resolve) => {
    execFile('nitro-cli', ['describe-enclaves'], { timeout: NITRO_CLI_TIMEOUT_MS, encoding: 'utf-8' }, (err, stdout) => {
      if (err) {
        resolve([]);
        return;
      }
      try {
        resolve(JSON.parse(stdout) as NitroEnclaveInfo[]);
      } catch {
        resolve([]);
      }
    });
  });
}
