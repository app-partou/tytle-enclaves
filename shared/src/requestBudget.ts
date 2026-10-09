/**
 * One time budget for a whole enclave request (enclave audit 2026-10 F6; decision D-P1-11 "A", LJ 2026-10-08).
 *
 * The budgets run from the outside in, each longer than the one inside it, so no step works on for a caller that
 * already gave up: ai-agent-server 60 s for a whole call, data-bridge 45 s, the parent 35 s for the enclave's answer
 * (parent/src/vsockClient.ts), the enclave 30 s for a request from the moment it accepts the connection. Before, the
 * enclave gave a handler 60 s - and that timer did not even stop it - while the parent waited 30 s: a slow upstream let
 * an enclave read on, hold one of its request slots and mint a document long after the parent had answered.
 *
 * Every upstream read, the KMS call, every retry and every pause between retries take what is left of the budget;
 * nothing starts once it is spent, and no document is minted after it (RequestDeadlineError, answered 504).
 */

/** The work of one request: from accept to the last upstream read and the attestation. */
export const REQUEST_BUDGET_MS = 30_000;

/** The time one upstream read may take when its caller names none; the request's budget can only shorten it. */
export const DEFAULT_FETCH_TIMEOUT_MS = 25_000;

/**
 * After the budget, the time left to hand over an answer already on its way (the document minted, the reply
 * written) before the enclave answers 504 itself. 30 s + 2 s stays inside the parent's 35 s.
 */
export const ANSWER_GRACE_MS = 2_000;

export interface RequestBudget {
  /** Epoch ms after which no step of this request starts */
  readonly deadlineMs: number;
}

/** The budget of a request accepted at `acceptedAtMs`. */
export function requestBudget(acceptedAtMs: number): RequestBudget {
  return { deadlineMs: acceptedAtMs + REQUEST_BUDGET_MS };
}

/** The budget was spent before `step` could start; the step never started. */
export class RequestDeadlineError extends Error {
  constructor(readonly step: string) {
    super(`The request's ${REQUEST_BUDGET_MS / 1000} s budget was spent before ${step}`);
    this.name = 'RequestDeadlineError';
  }
}

/**
 * The time `step` may take: what is left of the budget, and at most `wantMs` when given. Throws RequestDeadlineError
 * when nothing is left, so the step never starts.
 */
export function timeFor(budget: RequestBudget, step: string, wantMs?: number): number {
  const left = budget.deadlineMs - Date.now();
  if (left <= 0) throw new RequestDeadlineError(step);
  return wantMs === undefined ? left : Math.min(wantMs, left);
}
