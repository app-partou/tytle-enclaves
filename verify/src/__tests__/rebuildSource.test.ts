/**
 * The rebuild always comes from the repository the CLI names, never from the one the API names (enclave audit
 * P2.1): the thing being verified must not choose the code it is compared with. Until 2026-10 the CLI cloned
 * whatever `repoUrl` the PCR0 API returned.
 *
 * The boundary swapped is the one the build crosses, node:child_process (git and docker). The run stops at the clone.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { REPO_URL, runVerification } from '../commands/verify.js';
import { buildDoc } from './helpers/syntheticNsm.js';

const processes = vi.hoisted(() => [] as Array<{ file: string; args: readonly string[] }>);
vi.mock('node:child_process', () => ({
  execFileSync: (file: string, args: readonly string[]) => {
    processes.push({ file, args });
    if (file === 'git' && args[0] === 'clone') throw new Error('stopped at the clone (test)');
    return '';
  },
}));

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  processes.length = 0;
});

describe('the rebuild source', () => {
  it("the clone is the CLI's repository, whatever repoUrl the API returns (red)", async () => {
    const { document } = buildDoc();
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      enclaves: {
        vies: {
          pcr0: document.pcrs.pcr0,
          gitCommit: 'a'.repeat(40),
          repoUrl: 'https://github.com/someone/fork',
          buildDir: 'vies',
          history: [],
        },
      },
      verificationGuide: '',
    }), { status: 200 })));
    const dir = mkdtempSync(path.join(tmpdir(), 'verify-rebuild-'));
    const file = path.join(dir, 'attestation.json');
    writeFileSync(file, JSON.stringify(document));
    vi.spyOn(console, 'log').mockImplementation(() => {});

    try {
      const ok = await runVerification({ service: 'vies', attestation: file });
      expect(ok).toBe(false);                  // the build stopped at the clone
    } finally {
      rmSync(dir, { recursive: true, force: true });
      for (const p of processes) {
        if (p.file === 'git' && p.args[0] === 'clone') rmSync(path.dirname(p.args[3]), { recursive: true, force: true });
      }
    }

    const clones = processes.filter((p) => p.file === 'git' && p.args[0] === 'clone');
    expect(clones).toHaveLength(1);
    expect(clones[0].args[2]).toBe('https://github.com/app-partou/tytle-enclaves');
    expect(REPO_URL).toBe('https://github.com/app-partou/tytle-enclaves');
  });
});
