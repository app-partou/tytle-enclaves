/**
 * The PCR0 changes of a pull request (enclave audit P2.2; scripts/ci/pcr0-changes.mjs, run by CI after the
 * determinism gate). Each enclave whose committed PCR0 changes is listed, and the run fails when none of that
 * enclave's inputs changed: its own directory, the code every image holds (shared/, native/, deps/), the recipe, or
 * the nitro-cli helper that measures it.
 */

import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

interface Change { service: string; before: string | null; after: string | null; inputs: string[] }
interface Pcr0ChangesScript {
  pcr0Changes(base: Record<string, { pcr0: string }>, head: Record<string, { pcr0: string }>, changedFiles: string[]): Change[];
  markdown(changes: Change[]): string;
}
const script = async (): Promise<Pcr0ChangesScript> =>
  (await import(pathToFileURL(path.join(ROOT, 'scripts/ci/pcr0-changes.mjs')).href)) as Pcr0ChangesScript;

const pcr = (c: string) => c.repeat(96);
const BASE = { vies: { pcr0: pcr('a') }, sicae: { pcr0: pcr('b') } };

describe('the PCR0 changes of a pull request', () => {
  it('an enclave whose PCR0 changes is listed with the inputs that changed (red)', async () => {
    const { pcr0Changes } = await script();
    const head = { ...BASE, vies: { pcr0: pcr('c') } };
    expect(pcr0Changes(BASE, head, ['vies/src/viesHandler.ts', 'README.md'])).toEqual([
      { service: 'vies', before: pcr('a'), after: pcr('c'), inputs: ['vies/src/viesHandler.ts'] },
    ]);
  });

  it('a change with none of its inputs changed has no inputs: the run fails on it (red)', async () => {
    const { pcr0Changes, markdown } = await script();
    const head = { ...BASE, sicae: { pcr0: pcr('d') } };
    const changes = pcr0Changes(BASE, head, ['vies/src/viesHandler.ts', 'scripts/expected-digests.json']);
    expect(changes).toEqual([{ service: 'sicae', before: pcr('b'), after: pcr('d'), inputs: [] }]);
    expect(markdown(changes)).toContain('| sicae | `bbbbbbbbbbbbbbbb...` | `dddddddddddddddd...` | **NONE - fails** |');
  });

  it("shared/, native/, deps/, the recipe and the nitro-cli helper are every enclave's inputs (red)", async () => {
    const { pcr0Changes } = await script();
    const head = { vies: { pcr0: pcr('c') }, sicae: { pcr0: pcr('d') } };
    for (const file of ['shared/src/attestor.ts', 'native/src/vsock.rs', 'deps/rust-builder-apks/SHASUMS256.txt',
      'scripts/build-recipe.json', 'scripts/lib/recipe.sh', 'verify/Dockerfile.nitro-cli', '.dockerignore']) {
      expect(pcr0Changes(BASE, head, [file]).map((c) => c.inputs), file).toEqual([[file], [file]]);
    }
    // The CLI's own code and the docs are no enclave's input
    expect(pcr0Changes(BASE, head, ['verify/src/cli.ts', 'VERIFICATION.md']).map((c) => c.inputs)).toEqual([[], []]);
  });

  it('a new enclave, and an unchanged PCR0, are told apart (red)', async () => {
    const { pcr0Changes, markdown } = await script();
    const head = { ...BASE, 'monerium-payment': { pcr0: pcr('e') } };
    const changes = pcr0Changes(BASE, head, ['monerium-payment/Dockerfile']);
    expect(changes.map((c) => [c.service, c.before])).toEqual([['monerium-payment', null]]);
    expect(markdown(changes)).toContain('| monerium-payment | (none) |');
    expect(markdown(pcr0Changes(BASE, BASE, ['shared/src/attestor.ts']))).toBe("### PCR0\n\nNo enclave's PCR0 changes.\n");
  });
});
