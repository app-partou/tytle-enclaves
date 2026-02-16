/**
 * Enclave Health Monitoring.
 *
 * Checks enclave status via `nitro-cli describe-enclaves` and reports
 * health to the parent server's /health endpoint.
 */

import { execSync } from 'node:child_process';
import { getAllRoutes } from './enclaveRouter.js';

export interface HealthStatus {
  healthy: boolean;
  enclaves: EnclaveStatus[];
  timestamp: number;
}

interface EnclaveStatus {
  cid: number;
  hosts: string[];
  state: string;
  healthy: boolean;
}

/** Check the health of all configured enclaves. */
export function checkHealth(): HealthStatus {
  const routes = getAllRoutes();
  const enclaveStates = getEnclaveStates();

  const enclaves: EnclaveStatus[] = routes.map((route) => {
    const state = enclaveStates.find((e) => e.EnclaveCID === route.cid);
    const isRunning = state?.State === 'RUNNING';

    return {
      cid: route.cid,
      hosts: route.hosts,
      state: state?.State || 'NOT_FOUND',
      healthy: isRunning,
    };
  });

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
