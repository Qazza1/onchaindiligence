/**
 * diligence.ts
 * ------------
 * Pure helpers for the /diligence combined-check endpoint. Kept free of any
 * config, network, or app-boot dependency so the integrity logic can be
 * unit-tested in isolation (no env vars, no server boot).
 */

/** The result shape settleSafely() produces for each attempted check. */
export type CheckOutcome = { ok: boolean } | null

/**
 * Decides whether a /diligence response represents TOTAL failure — i.e. every
 * check that was actually attempted failed.
 *
 * The point: we must never return a signed, success-shaped 200 attestation
 * over a response that contains no successful check. A signature vouching for
 * a "result" that is nothing but errors would be misleading to an auditor.
 *
 * - false if nothing was attempted (caller-input error is handled elsewhere).
 * - false on partial success (>=1 ok) — that response is still valuable, so 200.
 * - true only when >=1 check ran and ALL attempted checks failed → caller
 *   should return a non-200, unsigned error.
 */
export function isTotalFailure(...outcomes: CheckOutcome[]): boolean {
  const attempted = outcomes.filter((o): o is { ok: boolean } => o !== null)
  return attempted.length > 0 && attempted.every((o) => !o.ok)
}
