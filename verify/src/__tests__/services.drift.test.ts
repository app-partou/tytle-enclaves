/**
 * Every enclave service of this repository is in every per-service list (enclave audit P1.9 step 2, D-P1-4).
 * Monerium was code only - in no script and no CLI list - so nothing built, measured or verified it. A service is a
 * top-level directory with src/enclave.ts. The lists: the verify CLI's VALID_SERVICES, scripts/rotate-pcr0.sh (its
 * ENCLAVES and its SSM key for each) and scripts/test-determinism.sh (its ENCLAVES and the services it takes as an
 * argument). The parent routes Monerium only when the host's unit names its CID (its own contract test locks that).
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { VALID_SERVICES, apiKeyForService, type ServiceName } from '../lib/types.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

const SERVICES = readdirSync(ROOT, { withFileTypes: true })
  .filter((d) => d.isDirectory() && existsSync(path.join(ROOT, d.name, 'src/enclave.ts')))
  .map((d) => d.name)
  .sort();

const read = (rel: string): string => readFileSync(path.join(ROOT, rel), 'utf8');

/** The quoted words of a top-level bash array assignment `NAME=("a" "b")`. */
function bashArray(script: string, name: string): string[] {
  const m = new RegExp(`^${name}=\\(([^)]*)\\)`, 'm').exec(script);
  return m ? [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]).sort() : [];
}

describe('every enclave service is in every per-service list', () => {
  it('the services: each directory with src/enclave.ts (lock)', () => {
    expect(SERVICES).toEqual(['monerium-payment', 'sicae', 'stripe-payment', 'vies']);
  });

  it('the verify CLI verifies each (red)', () => {
    expect([...VALID_SERVICES].sort()).toEqual(SERVICES);
  });

  it('rotate-pcr0.sh measures each, under its SSM key (red)', () => {
    const script = read('scripts/rotate-pcr0.sh');
    expect(bashArray(script, 'ENCLAVES')).toEqual(SERVICES);
    for (const svc of SERVICES) {
      expect(script).toContain(`${svc}) key="${apiKeyForService(svc as ServiceName)}" ;;`);
    }
  });

  it('test-determinism.sh builds each, and takes each as its argument (red)', () => {
    const script = read('scripts/test-determinism.sh');
    expect(bashArray(script, 'ENCLAVES')).toEqual(SERVICES);
    expect(/^\s*([a-z|-]+)\) ENCLAVES=\("\$arg"\) ;;/m.exec(script)?.[1].split('|').sort()).toEqual(SERVICES);
  });
});
