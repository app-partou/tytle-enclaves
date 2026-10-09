/**
 * The request budget (enclave audit F6; D-P1-11 "A", LJ 2026-10-08): what a step may take is what is left of 30 s from
 * the accept, at most what the step asks for; a step with nothing left never starts.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { ANSWER_GRACE_MS, REQUEST_BUDGET_MS, RequestDeadlineError, requestBudget, timeFor } from '../requestBudget.js';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('timeFor', () => {
  it('🔴 30 s from the accept; a step gets what is left, at most what it asks for', () => {
    let now = 1_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const budget = requestBudget(now);
    expect(budget).toEqual({ deadlineMs: 1_030_000 });
    expect(timeFor(budget, 'a read', 25_000)).toBe(25_000);
    now += 20_000;
    expect(timeFor(budget, 'a read', 25_000)).toBe(10_000);
    expect(timeFor(budget, 'the attestation')).toBe(10_000);
  });

  it('🔴 nothing left: RequestDeadlineError naming the step that never started', () => {
    let now = 2_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const budget = requestBudget(now);
    now += REQUEST_BUDGET_MS;
    const err = (() => { try { timeFor(budget, 'the read of www.sicae.pt', 25_000); } catch (e) { return e; } })();
    expect(err).toBeInstanceOf(RequestDeadlineError);
    expect((err as RequestDeadlineError).step).toBe('the read of www.sicae.pt');
    expect((err as Error).message).toBe('The request\'s 30 s budget was spent before the read of www.sicae.pt');
  });

  it('🔴 the budget and its grace fit inside the parent\'s 35 s', () => {
    expect(REQUEST_BUDGET_MS + ANSWER_GRACE_MS).toBeLessThan(35_000);
  });
});
