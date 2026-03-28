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

export function printReport(
  service: string,
  commit: string,
  checks: CheckResult[],
): void {
  const allPassed = checks.every((c) => c.passed);
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
    const icon = check.passed
      ? `${GREEN}PASS${RESET}`
      : `${RED}FAIL${RESET}`;
    console.log(`║  [${icon}] ${pad(check.name, width - 10)}║`);
    if (check.detail) {
      console.log(`║${pad(`         ${DIM}${check.detail}${RESET}`, width)}║`);
    }
  }

  console.log(`║${pad('', width)}║`);
  console.log(`║${thin}║`);

  if (allPassed) {
    console.log(
      `║${pad(`  ${GREEN}${BOLD}Result: ALL CHECKS PASSED${RESET}`, width)}║`,
    );
  } else {
    const failCount = checks.filter((c) => !c.passed).length;
    console.log(
      `║${pad(`  ${RED}${BOLD}Result: ${failCount} CHECK(S) FAILED${RESET}`, width)}║`,
    );
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
