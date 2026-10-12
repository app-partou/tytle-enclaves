import type { CheckResult } from './types.js';

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

export function pass(msg: string): void {
  console.log(`  ${GREEN}PASS${RESET} ${msg}`);
}

export function fail(msg: string): void {
  console.log(`  ${RED}FAIL${RESET} ${msg}`);
}

export function info(msg: string): void {
  console.log(`  ${CYAN}INFO${RESET} ${msg}`);
}

export function warn(msg: string): void {
  console.log(`  ${YELLOW}WARN${RESET} ${msg}`);
}

export function step(n: number, msg: string): void {
  console.log(`\n${BOLD}[${n}]${RESET} ${msg}`);
}

/**
 * A string from the attestation JSON, for the console: JSON with every character outside printable ASCII escaped. So
 * a value can never start a line of its own, colour the terminal or pose as a line of the report: whoever hands over
 * the JSON chooses every byte of it (enclave review 2026-10-09, E2b F-8).
 */
export function quoted(value: string): string {
  return JSON.stringify(value).replace(/[^\x20-\x7e]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/** An instant in ms for the console: ISO 8601, or the number itself when no date holds it (never a throw). */
export function isoTime(ms: number): string {
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? `${ms} ms (no valid date)` : date.toISOString();
}

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

/** How long before `nowMs` the document was signed, or how far ahead of this clock. */
export function ageOf(signedMs: number, nowMs: number): string {
  const ms = nowMs - signedMs;
  if (ms < 0) return `${Math.ceil(-ms / MINUTE_MS)} min ahead of this computer's clock`;
  return `${Math.floor(ms / DAY_MS)} d ${Math.floor((ms % DAY_MS) / HOUR_MS)} h ${Math.floor((ms % HOUR_MS) / MINUTE_MS)} min ago`;
}

/** A label and its value, as printed under printCoverage's headings. */
export type Labelled = readonly [label: string, value: string];

/**
 * What a pass vouches for, and what it does not: the values the NSM signs (itself, or through the nonce), which a
 * verifier compares with what they expected, and the document's fields nothing signs (E2b F-8).
 */
export function printCoverage(signed: readonly Labelled[], unsigned: readonly Labelled[]): void {
  console.log('');
  console.log(`${BOLD}What a pass vouches for${RESET} (signed by the NSM, itself or through the nonce):`);
  for (const [label, value] of signed) console.log(`  ${label.padEnd(15)}${value}`);
  console.log(`${BOLD}Not signed${RESET} (nothing in the signature covers them; never rely on them):`);
  for (const [label, value] of unsigned) console.log(`  ${label.padEnd(15)}${value}`);
}

export function printReport(
  service: string,
  commit: string,
  checks: CheckResult[],
): void {
  const width = 60;
  const line = '═'.repeat(width);
  const thin = '─'.repeat(width);

  console.log('');
  console.log(`╔${line}╗`);
  console.log(`║${BOLD}${center('Tytle Enclave Verification Report', width)}${RESET}║`);
  console.log(`╠${line}╣`);
  console.log(`║${pad(`  Service:  ${service}`, width)}║`);
  console.log(`║${pad(`  Commit:   ${commit}`, width)}║`);
  console.log(`║${pad(`  Time:     ${new Date().toISOString()}`, width)}║`);
  console.log(`╠${line}╣`);
  console.log(`║${pad('', width)}║`);

  for (const check of checks) {
    const icon = check.skipped !== undefined
      ? `${YELLOW}SKIP${RESET}`
      : check.passed
        ? `${GREEN}PASS${RESET}`
        : `${RED}FAIL${RESET}`;
    console.log(`║  [${icon}] ${pad(check.name, width - 10)}║`);
    if (check.detail) {
      console.log(`║${pad(`         ${DIM}${check.detail}${RESET}`, width)}║`);
    }
  }

  console.log(`║${pad('', width)}║`);
  console.log(`║${thin}║`);

  // A skipped check is never a pass, and never a failure: the result line says what was not verified.
  const skipped = checks.filter((c) => c.skipped !== undefined);
  const failCount = checks.filter((c) => !c.passed && c.skipped === undefined).length;
  if (failCount > 0) {
    console.log(
      `║${pad(`  ${RED}${BOLD}Result: ${failCount} CHECK(S) FAILED${RESET}`, width)}║`,
    );
  } else if (skipped.length > 0) {
    console.log(
      `║${pad(`  ${YELLOW}${BOLD}Result: ALL CHECKS RUN PASSED, ${skipped.length} SKIPPED${RESET}`, width)}║`,
    );
  } else {
    console.log(
      `║${pad(`  ${GREEN}${BOLD}Result: ALL CHECKS PASSED${RESET}`, width)}║`,
    );
  }
  for (const check of skipped) {
    console.log(`║${pad(`  ${YELLOW}Not verified: ${check.skipped}${RESET}`, width)}║`);
  }

  console.log(`║${pad('', width)}║`);
  console.log(`╚${line}╝`);
  console.log('');
}

function center(text: string, width: number): string {
  const stripped = stripAnsi(text);
  const padding = Math.max(0, width - stripped.length);
  const left = Math.floor(padding / 2);
  const right = padding - left;
  return ' '.repeat(left) + text + ' '.repeat(right);
}

function pad(text: string, width: number): string {
  const stripped = stripAnsi(text);
  const padding = Math.max(0, width - stripped.length);
  return text + ' '.repeat(padding);
}

function stripAnsi(str: string): string {
  return str.replace(/\x1b\[[0-9;]*m/g, '');
}
