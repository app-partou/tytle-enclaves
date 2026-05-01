/**
 * Enclave Health Monitoring.
 *
 * Two-level check:
 * 1. State: `nitro-cli describe-enclaves` confirms enclave process is RUNNING
 * 2. Connectivity: vsock ping confirms the enclave's accept loop is responsive
 *
 * Both must pass for an enclave to be marked healthy.
 */

import { execSync } from 'node:child_process';
import { getAllRoutes } from './enclaveRouter.js';
import { pingEnclave } from './vsockClient.js';

export interface HealthStatus {
  healthy: boolean;
  enclaves: EnclaveStatus[];
  timestamp: number;
}

interface EnclaveStatus {
  cid: number;
  hosts: string[];
  state: string;
  connectivity: 'responsive' | 'unresponsive' | 'untested';
  healthy: boolean;
}

/** Check the health of all configured enclaves. */
export async function checkHealth(): Promise<HealthStatus> {
  const routes = getAllRoutes();
  const enclaveStates = getEnclaveStates();

  const enclaves: EnclaveStatus[] = await Promise.all(
    routes.map(async (route) => {
      const state = enclaveStates.find((e) => e.EnclaveCID === route.cid);
      const isRunning = state?.State === 'RUNNING';

      let connectivity: EnclaveStatus['connectivity'] = 'untested';
      if (isRunning) {
        const pongReceived = await pingEnclave(route.cid, route.port);
        connectivity = pongReceived ? 'responsive' : 'unresponsive';
      }

      return {
        cid: route.cid,
        hosts: route.hosts,
        state: state?.State || 'NOT_FOUND',
        connectivity,
        healthy: isRunning && connectivity === 'responsive',
      };
    }),
  );

  return {
    healthy: enclaves.every((e) => e.healthy),
    enclaves,
    timestamp: Date.now(),
  };
}

interface NitroEnclaveInfo {
  EnclaveCID: number;
  State: string;
  EnclaveID: string;
}

/** Query nitro-cli for running enclave states. */
function getEnclaveStates(): NitroEnclaveInfo[] {
  try {
    const output = execSync('nitro-cli describe-enclaves', {
      timeout: 5000,
      encoding: 'utf-8',
    });

    return JSON.parse(output) as NitroEnclaveInfo[];
  } catch {
    return [];
  }
}
