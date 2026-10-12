/**
 * End-to-end tests of `verify` through its one entry point, runVerification, on AWS-shaped documents
 * (helpers/syntheticNsm.ts).
 *
 * The synthetic chains are trusted nowhere, so ONE module is swapped: the trust anchor (../lib/trustAnchor.js)
 * returns the synthetic root a test names. Everything else runs for real: the decode, the signature, the chain walk,
 * the nonce, the bindings and the report. The network (the PCR0 API) is replaced by --pcr0 or a stubbed fetch, and
 * the report is read where the CLI writes it, the console.
 *
 * Until 2026-10 these tests used a self-signed document with an EMPTY cabundle and asserted that the run FAILS, so
 * they stayed green while every real document failed (enclave audit P2.1). Each case now names exactly the checks
 * that fail.
 *
 * The clock is pinned: "now" is three days after the synthetic documents were signed (NOW_MS), because a document
 * more than a year old fails the freshness check (enclave review 2026-10-09, E2b F-9).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runVerification, type VerifyOptions } from '../commands/verify.js';
import { computeNonce } from '../lib/nonce.js';
import type { AttestationDocument } from '../lib/types.js';
import { buildDoc, CHAINS, SIGNED_AT_SEC, type DocOptions } from './helpers/syntheticNsm.js';

const anchor = vi.hoisted(() => ({ pem: '' }));
vi.mock('../lib/trustAnchor.js', async () => {
  const { X509Certificate } = await import('node:crypto');
  return { getAwsNitroRootCa: () => new X509Certificate(anchor.pem) };
});

const FRESH = 'Signed time is under a year old, not in the future';

/** Every check a run with --pcr0, --bn254 and --skip-build runs, in report order. */
const ALL_CHECKS = [
  'COSE_Sign1 signature valid',
  'Certificate chain roots to AWS Nitro CA',
  'Enclave ran in release mode (PCR0 not all zeroes)',
  'Nonce matches recomputed value',
  'COSE payload nonce matches application nonce',
  'Attestation time agrees with the signed NSM time',
  FRESH,
  'COSE user_data equals bn254Hash',
  'bn254Hash is SHA-256 of the vector (--bn254)',
  'responseHash is SHA-256 of the vector as base64 (--bn254)',
  'PCR0 matches published value (API)',
];

/** What --skip-build skips: reported SKIP, never PASS. */
const SKIPPED_BUILD = ['Reproducible build verification'];

const MINUTE_MS = 60_000;
const DAY_MS = 86_400_000;
const SIGNED_MS = SIGNED_AT_SEC * 1000;
/** "Now" for these tests: three days after the documents were signed. */
const NOW_MS = SIGNED_MS + 3 * DAY_MS;

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), 'verify-e2e-'));
  anchor.pem = CHAINS.main().anchorPem;
  vi.useFakeTimers({ toFake: ['Date'], now: NOW_MS });
  vi.stubGlobal('fetch', vi.fn(async () => {
    throw new Error('no network in tests');
  }));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const write = (name: string, content: string): string => {
  const file = path.join(dir, name);
  writeFileSync(file, content);
  return file;
};

const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');

interface Run {
  ok: boolean;
  /** Each check of the final report that ran, in order: [name, passed] */
  checks: Array<[string, boolean]>;
  failed: string[];
  /** The checks the report marks SKIP */
  skipped: string[];
  detail: (name: string) => string | undefined;
  output: string;
}

/** Run the CLI's verification on `document`, as `verify --service vies --attestation <file> --skip-build`. */
async function run(document: unknown, options: Partial<VerifyOptions> = {}): Promise<Run> {
  const lines: string[] = [];
  const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    lines.push(stripAnsi(args.map(String).join(' ')));
  });
  let ok: boolean;
  try {
    ok = await runVerification({
      service: 'vies',
      attestation: write('attestation.json', JSON.stringify(document)),
      skipBuild: true,
      ...options,
    });
  } finally {
    spy.mockRestore();
  }
  const checks: Array<[string, boolean]> = [];
  const skipped: string[] = [];
  const details = new Map<string, string>();
  let last: string | undefined;
  for (const line of lines.flatMap((l) => l.split('\n'))) {
    const check = /^║  \[(PASS|FAIL|SKIP)\] (.+?) *║$/.exec(line);
    if (check) {
      if (check[1] === 'SKIP') skipped.push(check[2]);
      else checks.push([check[2], check[1] === 'PASS']);
      last = check[2];
      continue;
    }
    // A check's detail is the line right after it (the report's blank line after the last check is no detail)
    const detail = /^║ {9}(.+?) *║$/.exec(line);
    if (detail && last !== undefined) details.set(last, detail[1]);
    last = undefined;
  }
  return {
    ok,
    checks,
    failed: checks.filter(([, passed]) => !passed).map(([name]) => name),
    skipped,
    detail: (name) => details.get(name),
    output: lines.join('\n'),
  };
}

/** A genuine run: the document, its PCR0 given as published, and the vector it signed given by --bn254. */
async function runGenuine(o: DocOptions = {}, edit: (d: AttestationDocument) => void = () => {}, extra: Partial<VerifyOptions> = {}) {
  const { document, bn254Base64 } = buildDoc(o);
  edit(document);
  return run(document, { pcr0: document.pcrs.pcr0, bn254: write('vector.b64', bn254Base64), ...extra });
}

describe('a genuine document passes every check', () => {
  it('an AWS-shaped document (cabundle root first), with the vector given by --bn254 (red)', async () => {
    const r = await runGenuine();
    expect(r.checks).toEqual(ALL_CHECKS.map((name) => [name, true]));
    expect(r.ok).toBe(true);
  });

  it("AWS's own depth (root, regional, zonal, instance), days after the instance CA expired (red)", async () => {
    const chain = CHAINS.awsDepth();
    anchor.pem = chain.anchorPem;
    const r = await runGenuine({ chain });
    expect(r.failed).toEqual([]);
    expect(r.ok).toBe(true);
  });

  it("a version-2 document (the caller's challenge in the nonce) (red)", async () => {
    const r = await runGenuine({ challenge: crypto.randomBytes(32).toString('hex') });
    expect(r.failed).toEqual([]);
    expect(r.output).toContain('Nonce matches recomputed SHA-256(responseHash|apiEndpoint|timestamp|challenge)');
  });

  it('a document without a BN254 vector (no user_data, no bn254Hash) passes, with no data-binding check (red)', async () => {
    const { document } = buildDoc({ userData: null });
    delete document.bn254Hash;
    const r = await run(document, { pcr0: document.pcrs.pcr0 });
    expect(r.failed).toEqual([]);
    expect(r.checks.map(([name]) => name)).not.toContain('COSE user_data equals bn254Hash');
    expect(r.output).toContain('No user_data and no bn254Hash: this answer carries no BN254 vector');
  });

  it("a signed time exactly 10 minutes from the attestation's own time still agrees (red)", async () => {
    const r = await runGenuine({ payloadTimestampMs: SIGNED_AT_SEC * 1000 + 10 * 60_000 });
    expect(r.failed).toEqual([]);
  });
});

// Enclave review 2026-10-09, E2b F-8: nothing signed covers attestationId, requestHash or apiMethod. Before, the run
// required all three, printed "Attestation ID: <whatever the JSON said>" first and "ALL CHECKS PASSED" last, so whoever
// handed a verifier the JSON could wrap another document's genuine NSM fields in the id they wanted verified.
describe('what a pass vouches for (E2b F-8)', () => {
  it('a document without attestationId, requestHash and apiMethod verifies: nothing signs them (red)', async () => {
    const r = await runGenuine({}, (d) => {
      delete d.attestationId;
      delete d.requestHash;
      delete d.apiMethod;
    });
    expect(r.checks).toEqual(ALL_CHECKS.map((name) => [name, true]));
    expect(r.ok).toBe(true);
    expect(r.output).toContain('  attestationId  absent\n  requestHash    absent\n  apiMethod      absent');
  });

  it('the fields nothing signs are reported as not signed, never as the attestation (red)', async () => {
    const r = await runGenuine({}, (d) => {
      d.attestationId = 'enc-00000000-0000-4000-8000-00000000beef';
      d.requestHash = '00'.repeat(32);
      d.apiMethod = 'DELETE';
    });
    expect(r.failed).toEqual([]);
    expect(r.output).toContain([
      'Not signed (nothing in the signature covers them; never rely on them):',
      '  attestationId  "enc-00000000-0000-4000-8000-00000000beef"',
      `  requestHash    "${'00'.repeat(32)}"`,
      '  apiMethod      "DELETE"',
    ].join('\n'));
    expect(r.output).not.toContain('Attestation ID');
  });

  it('the report names the signed values a pass vouches for (red)', async () => {
    const { document, bn254Base64 } = buildDoc();
    const r = await run(document, { pcr0: document.pcrs.pcr0, bn254: write('vector.b64', bn254Base64) });
    expect(r.output).toContain([
      'What a pass vouches for (signed by the NSM, itself or through the nonce):',
      '  apiEndpoint    "ec.europa.eu/taxation_customs/vies/services/checkVatService"',
      `  responseHash   "${document.responseHash}"`,
      '  signed time    2026-10-05T12:00:00.000Z (3 d 0 h 0 min ago)',
      '  challenge      none',
      `  PCR0           ${document.pcrs.pcr0}`,
      `  user_data      ${document.bn254Hash}`,
    ].join('\n'));

    const challenge = crypto.randomBytes(32).toString('hex');
    const v2 = await runGenuine({ challenge });
    expect(v2.output).toContain(
      `  challenge      "${challenge}" (only the caller who chose it can tell the document answers its request)`);
    const plain = buildDoc({ userData: null }).document;
    delete plain.bn254Hash;
    expect((await run(plain, { pcr0: plain.pcrs.pcr0 })).output).toContain('  user_data      none');
  });

  it('a value from the document cannot write a line of its own into the report (red)', async () => {
    const forged = (name: string) => `x"\n║  [PASS] ${name}${' '.repeat(10)}║\n\x1b[1mResult: ALL CHECKS PASSED`;
    const r = await runGenuine({}, (d) => {
      d.attestationId = forged('Forged A');
      d.requestHash = forged('Forged B');
      d.apiMethod = forged('Forged C');
    });
    const e = await runGenuine({}, (d) => { d.apiEndpoint = forged('Forged D'); });
    for (const each of [r, e]) {
      expect(each.checks.map(([name]) => name).filter((name) => name.startsWith('Forged'))).toEqual([]);
      expect(each.output.split('\n')).not.toContain('Result: ALL CHECKS PASSED');
    }
    // Each is printed as JSON, every character outside printable ASCII escaped
    expect(r.output).toContain('  attestationId  "x\\"\\n\\u2551  [PASS] Forged A          \\u2551\\n\\u001b[1mResult: ALL CHECKS PASSED"');
    expect(e.output).toContain('  apiEndpoint    "x\\"\\n\\u2551  [PASS] Forged D');
    expect(e.failed).toEqual(['Nonce matches recomputed value']);
  });
});

// Enclave review 2026-10-09, E2b F-9: the main repo's verifier refuses a signed time more than 5 minutes ahead or more
// than a year old (packages/attestation-core nsmVerification.ts); the CLI had no bound, and it reported a skipped
// rebuild as PASS, so a --skip-build run ended "ALL CHECKS PASSED".
describe('freshness and the skipped rebuild (E2b F-9)', () => {
  it('a document signed more than a year ago fails only freshness (red)', async () => {
    vi.setSystemTime(SIGNED_MS + 365 * DAY_MS + 1);
    const r = await runGenuine();
    expect(r.failed).toEqual([FRESH]);
    expect(r.detail(FRESH)).toBe('Signed 2026-10-05T12:00:00.000Z: more than a year ago');
    expect(r.ok).toBe(false);
  });

  it('a document signed exactly a year ago still passes (red)', async () => {
    vi.setSystemTime(SIGNED_MS + 365 * DAY_MS);
    const r = await runGenuine();
    expect(r.checks).toContainEqual([FRESH, true]);
    expect(r.failed).toEqual([]);
  });

  it("a signed time more than 5 minutes ahead of this computer's clock fails only freshness (red)", async () => {
    vi.setSystemTime(SIGNED_MS - 5 * MINUTE_MS - 1);
    const r = await runGenuine();
    expect(r.failed).toEqual([FRESH]);
    expect(r.detail(FRESH)).toBe("Signed 2026-10-05T12:00:00.000Z: more than 5 minutes ahead of this computer's clock");
    expect(r.output).toContain("  signed time    2026-10-05T12:00:00.000Z (6 min ahead of this computer's clock)");
  });

  it('a signed time exactly 5 minutes ahead still passes (red)', async () => {
    vi.setSystemTime(SIGNED_MS - 5 * MINUTE_MS);
    const r = await runGenuine();
    expect(r.checks).toContainEqual([FRESH, true]);
    expect(r.failed).toEqual([]);
  });

  it('a skipped rebuild is SKIP, not PASS, and the result says the build was not reproduced (red)', async () => {
    const r = await runGenuine();
    expect(r.skipped).toEqual(SKIPPED_BUILD);
    expect(r.checks.map(([name]) => name)).not.toContain(SKIPPED_BUILD[0]);
    expect(r.detail(SKIPPED_BUILD[0])).toBe('Not run (--skip-build): PCR0 is compared with the published value only');
    expect(r.output).toContain('Result: ALL CHECKS RUN PASSED, 1 SKIPPED');
    expect(r.output).toContain('Not verified: the build was not reproduced');
    expect(r.output).not.toContain('Result: ALL CHECKS PASSED');
    expect(r.ok).toBe(true);
  });
});

describe('the bindings', () => {
  it('a payload without a nonce FAILS the nonce binding (red)', async () => {
    const r = await runGenuine({ omit: ['nonce'] });
    expect(r.failed).toEqual(['COSE payload nonce matches application nonce']);
    expect(r.detail('COSE payload nonce matches application nonce')).toBe(
      'The NSM payload carries no nonce: the document is not bound to this answer',
    );
  });

  it('an application nonce that is not the signed one fails the binding (the envelope swapped) (red)', async () => {
    const { document } = buildDoc();
    const swapped = {
      ...document,
      responseHash: 'ff'.repeat(32),
      nonce: computeNonce('ff'.repeat(32), document.apiEndpoint, document.timestamp),
    };
    const r = await run(swapped, { pcr0: document.pcrs.pcr0 });
    expect(r.failed).toEqual(['COSE payload nonce matches application nonce']);
  });

  it('user_data that is not the bn254Hash fails (red)', async () => {
    const r = await runGenuine({ userData: crypto.randomBytes(32) });
    expect(r.failed).toEqual(['COSE user_data equals bn254Hash']);
  });

  it('user_data with no bn254Hash in the attestation fails (red)', async () => {
    const { document } = buildDoc();
    delete document.bn254Hash;
    const r = await run(document, { pcr0: document.pcrs.pcr0 });
    expect(r.failed).toEqual(['COSE user_data equals bn254Hash']);
    expect(r.detail('COSE user_data equals bn254Hash')).toBe('The document carries user_data, but the attestation names no bn254Hash');
  });

  it('a bn254Hash with no user_data in the payload fails (red)', async () => {
    const r = await runGenuine({ userData: null });
    expect(r.failed).toEqual(['COSE user_data equals bn254Hash']);
  });

  it('--bn254 with a vector that was not the one signed fails both recomputes (red)', async () => {
    const { document } = buildDoc();
    const r = await run(document, { pcr0: document.pcrs.pcr0, bn254: write('other.b64', crypto.randomBytes(160).toString('base64')) });
    expect(r.failed).toEqual([
      'bn254Hash is SHA-256 of the vector (--bn254)',
      'responseHash is SHA-256 of the vector as base64 (--bn254)',
    ]);
  });

  it("a signed time 11 minutes from the attestation's own time fails the time check (red)", async () => {
    const r = await runGenuine({ payloadTimestampMs: SIGNED_AT_SEC * 1000 + 11 * 60_000 });
    expect(r.failed).toEqual(['Attestation time agrees with the signed NSM time']);
  });

  it('a payload without a signed time fails the chain, the time check and freshness (red)', async () => {
    const r = await runGenuine({ payloadTimestampMs: null });
    expect(r.failed).toEqual(['Certificate chain roots to AWS Nitro CA', 'Attestation time agrees with the signed NSM time', FRESH]);
    expect(r.detail('Certificate chain roots to AWS Nitro CA')).toBe('The document has no valid signed time');
    expect(r.detail(FRESH)).toBe('The NSM payload carries no valid signed time');
  });

  it('a time no date can hold is a FAIL, never a crash: the report is written (red)', async () => {
    // Before, the time check's detail called toISOString() on it and the run threw.
    const signed = await runGenuine({ payloadTimestampMs: 9e15 });
    expect(signed.failed).toEqual(['Certificate chain roots to AWS Nitro CA', 'Attestation time agrees with the signed NSM time', FRESH]);
    expect(signed.detail('Attestation time agrees with the signed NSM time'))
      .toBe('Attestation: 2026-10-05T12:00:00.000Z, signed: 9000000000000000 ms (no valid date) (at most 10 minutes apart)');
    const own = await runGenuine({}, (d) => { d.timestamp = 1e300; });
    expect(own.failed).toEqual(['Nonce matches recomputed value', 'Attestation time agrees with the signed NSM time']);
    expect(own.detail('Attestation time agrees with the signed NSM time'))
      .toBe('Attestation: 1e+303 ms (no valid date), signed: 2026-10-05T12:00:00.000Z (at most 10 minutes apart)');
  });

  it('a changed responseHash fails the nonce recompute (red)', async () => {
    const r = await runGenuine({}, (d) => { d.responseHash = 'ff'.repeat(32); });
    expect(r.failed).toEqual(['Nonce matches recomputed value', 'responseHash is SHA-256 of the vector as base64 (--bn254)']);
  });

  it('a changed timestamp fails the nonce recompute (red)', async () => {
    const r = await runGenuine({}, (d) => { d.timestamp += 1; });
    expect(r.failed).toEqual(['Nonce matches recomputed value']);
  });

  it('a changed apiEndpoint fails the nonce recompute (red)', async () => {
    const r = await runGenuine({}, (d) => { d.apiEndpoint = 'evil.example/fake'; });
    expect(r.failed).toEqual(['Nonce matches recomputed value']);
  });

  it('version 2 without its challenge fails the nonce recompute (red)', async () => {
    const r = await runGenuine({ challenge: crypto.randomBytes(32).toString('hex') }, (d) => { delete d.challenge; });
    expect(r.failed).toEqual(['Nonce matches recomputed value']);
    expect(r.detail('Nonce matches recomputed value')).toBe('nonce version 2 needs a challenge of 64 lowercase hex');
  });

  it('a challenge on a version-1 document fails the nonce recompute (red)', async () => {
    const r = await runGenuine({}, (d) => { d.challenge = crypto.randomBytes(32).toString('hex'); });
    expect(r.failed).toEqual(['Nonce matches recomputed value']);
    expect(r.detail('Nonce matches recomputed value')).toBe('a challenge was given but the nonce is version 1');
  });

  it('another challenge than the one signed fails the nonce recompute (red)', async () => {
    const r = await runGenuine({ challenge: crypto.randomBytes(32).toString('hex') }, (d) => {
      d.challenge = crypto.randomBytes(32).toString('hex');
    });
    expect(r.failed).toEqual(['Nonce matches recomputed value']);
  });
});

describe('the signature and the chain', () => {
  it('one flipped bit in the signature fails the signature (red)', async () => {
    const r = await runGenuine({}, (d) => {
      const bytes = Buffer.from(d.nsmDocument, 'base64');
      bytes[bytes.length - 1] ^= 0x01;       // the signature is the COSE array's last item
      d.nsmDocument = bytes.toString('base64');
    });
    expect(r.failed).toEqual(['COSE_Sign1 signature valid']);
  });

  it("a document signed by another key than the leaf's fails the signature (red)", async () => {
    const r = await runGenuine({ signWith: CHAINS.otherRoot().leafKey });
    expect(r.failed).toEqual(['COSE_Sign1 signature valid']);
  });

  it('a flipped byte inside the document fails the signature (lock)', async () => {
    const r = await runGenuine({}, (d) => {
      const bytes = Buffer.from(d.nsmDocument, 'base64');
      bytes[Math.floor(bytes.length / 2)] ^= 0xff;
      d.nsmDocument = bytes.toString('base64');
    });
    expect(r.ok).toBe(false);
    expect(r.failed).toContain('COSE_Sign1 signature valid');
  });

  it('an algorithm other than ES384 fails, and nothing in the payload is trusted (red)', async () => {
    const r = await runGenuine({ alg: -7 });
    expect(r.ok).toBe(false);
    expect(r.failed).toEqual(expect.arrayContaining([
      'COSE_Sign1 signature valid',
      'Certificate chain roots to AWS Nitro CA',
      'COSE payload nonce matches application nonce',
      'PCR0 matches published value (API)',
    ]));
    expect(r.detail('COSE_Sign1 signature valid')).toMatch(/^Invalid COSE algorithm: -7\. Expected -35 \(ES384\)/);
  });

  it('a chain under a root that is not the pin fails only the chain (red)', async () => {
    const r = await runGenuine({ chain: CHAINS.otherRoot() });
    expect(r.failed).toEqual(['Certificate chain roots to AWS Nitro CA']);
    expect(r.detail('Certificate chain roots to AWS Nitro CA')).toMatch(/^cabundle\[0\] \(.+\) is not the AWS Nitro root/);
  });

  it('an intermediate that is not a CA fails only the chain (lock)', async () => {
    const r = await runGenuine({ chain: CHAINS.intermediateNotCa() });
    expect(r.failed).toEqual(['Certificate chain roots to AWS Nitro CA']);
  });

  it('a leaf that is a CA fails only the chain (lock)', async () => {
    const r = await runGenuine({ chain: CHAINS.leafIsCa() });
    expect(r.failed).toEqual(['Certificate chain roots to AWS Nitro CA']);
  });
});

describe('PCR0', () => {
  const published = (pcr0: string, extra: Record<string, unknown> = {}) =>
    vi.fn(async () => new Response(JSON.stringify({
      enclaves: {
        vies: {
          pcr0,
          gitCommit: 'a'.repeat(40),
          repoUrl: 'https://github.com/app-partou/tytle-enclaves',
          buildDir: 'vies',
          history: [],
          ...extra,
        },
      },
      verificationGuide: '',
    }), { status: 200 }));

  it('a PCR0 other than the published one fails, and the skipped rebuild is not counted as a failure (red)', async () => {
    const r = await runGenuine({}, () => {}, { pcr0: 'ff'.repeat(48) });
    expect(r.failed).toEqual(['PCR0 matches published value (API)']);
    expect(r.output).toContain('Result: 1 CHECK(S) FAILED');
    expect(r.ok).toBe(false);
  });

  it('a debug-mode document (PCR0 all zeroes) fails even when the published PCR0 is zeroes (red)', async () => {
    const r = await runGenuine({ pcr0: Buffer.alloc(48) });
    expect(r.failed).toEqual(['Enclave ran in release mode (PCR0 not all zeroes)']);
    expect(r.detail('Enclave ran in release mode (PCR0 not all zeroes)')).toBe('PCR0 is all zeroes: a debug-mode enclave, never trusted');
  });

  it('without --pcr0 the published PCR0 is read from the API (red)', async () => {
    const { document, bn254Base64 } = buildDoc();
    const fetchMock = published(document.pcrs.pcr0);
    vi.stubGlobal('fetch', fetchMock);
    const r = await run(document, { bn254: write('vector.b64', bn254Base64) });
    expect(r.failed).toEqual([]);
    expect(fetchMock).toHaveBeenCalledWith('https://api.tytle.io/api/enclave/pcr0', expect.anything());
  });

  it("a PCR0 found in the API's history passes, and the run says from when (red)", async () => {
    const { document } = buildDoc();
    vi.stubGlobal('fetch', published('ff'.repeat(48), {
      history: [{ pcr0: document.pcrs.pcr0, gitCommit: 'b'.repeat(40), environment: 'production', deployedAt: '2026-09-01T00:00:00Z' }],
    }));
    const r = await run(document);
    expect(r.failed).toEqual([]);
    expect(r.output).toContain('Attestation PCR0 matches historical entry from 2026-09-01T00:00:00Z');
  });

  it('with the API unreachable and no --pcr0, only the PCR0 check fails (red)', async () => {
    const { document } = buildDoc();
    const r = await run(document);
    expect(r.failed).toEqual(['PCR0 matches published value (API)']);
    expect(r.detail('PCR0 matches published value (API)')).toBe('API unreachable and no --pcr0 provided');
  });

  it("the API's repoUrl is reported, never used (the rebuild itself: rebuildSource.test.ts) (red)", async () => {
    const { document } = buildDoc();
    vi.stubGlobal('fetch', published(document.pcrs.pcr0, { repoUrl: 'https://github.com/someone/fork' }));
    const r = await run(document);
    expect(r.failed).toEqual([]);
    expect(r.output).toContain(
      'WARN The API names https://github.com/someone/fork as the source; the build always comes from https://github.com/app-partou/tytle-enclaves',
    );
  });
});

describe('PCR8, the operator binding (--signing-cert)', () => {
  // The certificate and the PCR8 nitro-cli 1.4.4 itself printed for an EIF signed with it (fixtures/signing)
  const signerPem = readFileSync(new URL('./fixtures/signing/signer.pem', import.meta.url), 'utf8');
  const signedOutput = readFileSync(new URL('./fixtures/signing/nitro-cli-1.4.4-signed.stdout.txt', import.meta.url), 'utf8');
  const REAL_PCR8 = Buffer.from((JSON.parse(signedOutput) as { Measurements: { PCR8: string } }).Measurements.PCR8, 'hex');
  const CHECK = "PCR8 is the signing certificate's (--signing-cert)";
  const withCert = () => ({ signingCert: write('signing-cert.pem', signerPem) });

  it("a document from an EIF signed with the certificate passes, and the report names the check (red)", async () => {
    const r = await runGenuine({ pcr8: REAL_PCR8 }, () => {}, withCert());
    expect(r.checks).toEqual([...ALL_CHECKS, CHECK].map((name) => [name, true]));
    expect(r.skipped).toEqual(SKIPPED_BUILD);
    expect(r.output).toContain("PASS PCR8 is the signing certificate's: the EIF that ran was signed with it");
    expect(r.ok).toBe(true);
  });

  it('an unsigned EIF (PCR8 zeroes) fails only that check, and says why (red)', async () => {
    const r = await runGenuine({}, () => {}, withCert());
    expect(r.failed).toEqual([CHECK]);
    expect(r.detail(CHECK)).toBe('PCR8 is zero: the EIF that ran was not signed');
  });

  it("an EIF signed with another key fails only that check (red)", async () => {
    const other = crypto.randomBytes(48);
    const r = await runGenuine({ pcr8: other }, () => {}, withCert());
    expect(r.failed).toEqual([CHECK]);
    expect(r.detail(CHECK)).toBe(`PCR8: ${other.toString('hex').slice(0, 32)}..., the certificate's: ${REAL_PCR8.toString('hex').slice(0, 32)}...`);
    expect(r.output).toContain("FAIL PCR8 is NOT the signing certificate's: another key signed the EIF that ran");
  });

  it('a document with no PCR8 at all is unsigned too (red)', async () => {
    const r = await runGenuine({ pcr8: null }, () => {}, withCert());
    expect(r.failed).toEqual([CHECK]);
    expect(r.detail(CHECK)).toBe('PCR8 is zero: the EIF that ran was not signed');
  });

  it('without --signing-cert there is no PCR8 check: the run says whether the EIF was signed (red)', async () => {
    const signed = await runGenuine({ pcr8: REAL_PCR8 });
    expect(signed.checks.map(([name]) => name)).toEqual(ALL_CHECKS);
    expect(signed.output).toContain(`INFO PCR8 ${REAL_PCR8.toString('hex').slice(0, 16)}...: a signed EIF. --signing-cert <pem> checks whose key signed it`);
    const unsigned = await runGenuine();
    expect(unsigned.checks.map(([name]) => name)).toEqual(ALL_CHECKS);
    expect(unsigned.output).toContain('INFO PCR8 is zero: an unsigned EIF, so the document does not say whose EIF ran');
  });

  it('a --signing-cert that is not a certificate is refused (red)', async () => {
    const key = readFileSync(new URL('./fixtures/signing/signer-TESTONLY.key.pem', import.meta.url), 'utf8');
    await expect(runGenuine({}, () => {}, { signingCert: write('key.pem', key) }))
      .rejects.toThrow('--signing-cert is not an X.509 certificate in PEM');
    await expect(runGenuine({}, () => {}, { signingCert: path.join(dir, 'missing.pem') }))
      .rejects.toThrow('--signing-cert file not found');
  });
});

describe('reading the attestation file', () => {
  const refused = async (document: unknown, message: string) => {
    await expect(run(document)).rejects.toThrow(message);
  };

  it('a missing file is refused (lock)', async () => {
    vi.spyOn(console, 'log').mockImplementationOnce(() => {});
    await expect(runVerification({ service: 'vies', attestation: path.join(dir, 'nonexistent.json'), skipBuild: true }))
      .rejects.toThrow('not found');
  });

  it('a file that is not JSON is refused (lock)', async () => {
    vi.spyOn(console, 'log').mockImplementationOnce(() => {});
    await expect(runVerification({ service: 'vies', attestation: write('bad.json', 'not json'), skipBuild: true }))
      .rejects.toThrow('not valid JSON');
  });

  it('a document without its required fields is refused (lock)', async () => {
    await refused({ attestationId: 'test' }, 'missing or invalid');
  });

  it('an nsmDocument too short to be a COSE_Sign1 is refused (lock)', async () => {
    await refused({ ...buildDoc().document, nsmDocument: Buffer.from('short').toString('base64') }, 'too short');
  });

  it('a nonce that is not hex is refused (lock)', async () => {
    await refused({ ...buildDoc().document, nonce: 'not-hex-at-all!!!' }, 'not a valid hex');
  });

  it('a bn254Hash that is not 64 hex is refused (red)', async () => {
    await refused({ ...buildDoc().document, bn254Hash: 'ab'.repeat(31) }, 'bn254Hash must be 64 hex characters');
  });

  it('a responseHash that is not 64 hex is refused: the enclave writes a SHA-256 in hex (red)', async () => {
    await refused({ ...buildDoc().document, responseHash: 'ab'.repeat(31) }, 'responseHash must be 64 hex characters');
    await refused({ ...buildDoc().document, responseHash: `${'ab'.repeat(32)}\n` }, 'responseHash must be 64 hex characters');
  });

  it('an unsigned field may be absent, but when present it is a string (red)', async () => {
    for (const field of ['attestationId', 'requestHash', 'apiMethod']) {
      await refused({ ...buildDoc().document, [field]: 7 }, `${field} must be a string when present (it is not signed)`);
    }
  });

  it('a nonceVersion other than 1 or 2 is refused (red)', async () => {
    await refused({ ...buildDoc().document, nonceVersion: 3 }, 'nonceVersion must be 1 or 2');
  });

  it("a challenge that is not 64 lowercase hex is refused, the route's null too (red)", async () => {
    await refused({ ...buildDoc().document, challenge: 'AB'.repeat(32) }, 'challenge must be 64 lowercase hex characters');
    await refused({ ...buildDoc().document, nonceVersion: 2, challenge: null }, 'challenge must be 64 lowercase hex characters');
  });
});
