/**
 * Fetch PCR0 + commit hash from the public API.
 */

import type {
  Pcr0ApiResponse,
  Pcr0ServiceInfo,
  ServiceName,
} from './types.js';
import { apiKeyForService } from './types.js';

const DEFAULT_API_URL = 'https://api.tytle.io';
const FETCH_TIMEOUT_MS = 15_000;

export async function fetchPcr0Info(
  service: ServiceName,
  apiBaseUrl: string = DEFAULT_API_URL,
): Promise<Pcr0ServiceInfo> {
  const url = `${apiBaseUrl}/api/enclave/pcr0`;

  let response: Response;
  try {
    response = await fetch(url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: { 'Accept': 'application/json' },
    });
  } catch (err: any) {
    if (err.name === 'TimeoutError') {
      throw new Error(`PCR0 API request timed out after ${FETCH_TIMEOUT_MS / 1000}s (${url})`);
    }
    throw new Error(`PCR0 API request failed: ${err.message} (${url})`);
  }

  if (!response.ok) {
    const body = await response.text().catch(() => '(no body)');
    throw new Error(
      `PCR0 API returned ${response.status}: ${body.slice(0, 200)}`,
    );
  }

  let data: Pcr0ApiResponse;
  try {
    data = await response.json();
  } catch {
    throw new Error('PCR0 API returned invalid JSON');
  }

  if (!data.enclaves || typeof data.enclaves !== 'object') {
    throw new Error('PCR0 API response missing "enclaves" object');
  }

  const key = apiKeyForService(service);
  const serviceInfo = data.enclaves[key];

  if (!serviceInfo) {
    const available = Object.keys(data.enclaves).join(', ');
    throw new Error(
      `Service "${service}" (key "${key}") not found in API response. Available: ${available}`,
    );
  }

  if (!serviceInfo.pcr0 || !serviceInfo.gitCommit) {
    throw new Error(
      `API response for "${service}" is missing pcr0 or gitCommit`,
    );
  }

  return serviceInfo;
}
