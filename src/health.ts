/**
 * health.ts
 * ---------
 * Cheap, cached upstream availability checks used to avoid demanding
 * payment when we already know an upstream provider is down.
 *
 * THE PROBLEM THIS ADDRESSES:
 * In the Tempo charge model the agent pays on-chain BEFORE our handler
 * verifies the credential — so once we issue a 402 and they pay, we can't
 * "abort without settling." The money has already moved. The cleanest
 * mitigation available to us is therefore to NOT issue the 402 in the
 * first place if we can already tell the upstream is unavailable. This
 * doesn't cover an upstream that dies mid-request (after payment) — that
 * residual penny-risk is covered by the no-auto-refund disclosure and the
 * payment logging — but it closes the most common case: "Companies House
 * is having an outage right now."
 *
 * Caching: we cache health for a short TTL so we don't add a full upstream
 * round-trip (and burn rate-limit budget) on every single request just to
 * check liveness.
 *
 * WHAT "HEALTHY" MEANS: the provider can USEFULLY serve a paid request right
 * now, not merely that something answered on the network. A 503 maintenance
 * page, a 429 rate limit, or a 401/403 rejecting our credential all mean a
 * paid call would fail, so each provider declares the exact statuses that
 * prove usability (PROVIDER_READY_STATUSES); anything else, including every
 * 5xx, is unhealthy and feeds the circuit breaker. This is a best-effort
 * pre-payment check only: an upstream can still fail after it passed, and
 * that residual is disclosed, not promised away.
 */

import { config } from './config.js'

/**
 * Circuit breaker state per upstream.
 *
 * Upgrade over a plain cached probe: instead of re-probing a known-down
 * upstream every TTL, we track CONSECUTIVE failures. After `failureThreshold`
 * failures the breaker "opens" — we fail fast for `openCooldownMs` WITHOUT
 * probing at all (don't hammer something that's down). After the cooldown
 * the breaker goes "half-open": the next call is allowed through as a single
 * trial probe. If it succeeds the breaker closes (healthy again); if it
 * fails we re-open for another cooldown.
 *
 * States:
 *   closed    → healthy; probe normally, refreshing within TTL
 *   open      → unhealthy; fail fast, no probing until cooldown elapses
 *   half-open → cooldown elapsed; allow one trial probe to test recovery
 */
type BreakerState = 'closed' | 'open' | 'half-open'

export interface Breaker {
  state: BreakerState
  consecutiveFailures: number
  lastProbeAt: number
  openedAt: number
  lastResult: boolean
}

const TTL_MS = 30_000 // when closed, re-probe at most this often
const TIMEOUT_MS = 3_000 // don't let a hanging probe stall the request
const FAILURE_THRESHOLD = 3 // consecutive failures before the breaker opens
const OPEN_COOLDOWN_MS = 60_000 // how long to fail fast before a trial probe

const breakers = new Map<string, Breaker>()

function newBreaker(): Breaker {
  return {
    state: 'closed',
    consecutiveFailures: 0,
    lastProbeAt: 0,
    openedAt: 0,
    lastResult: true, // optimistic until proven otherwise
  }
}

/**
 * Statuses that prove a provider can serve a real request. Everything else —
 * 401/403 (our credential rejected or we are blocked), 429 (rate-limited),
 * any 5xx (outage/maintenance), unexpected 4xx — is NOT usable.
 */
export const PROVIDER_READY_STATUSES = {
  // A known company lookup with our key: 200, or 404 if the record is ever
  // removed (still a well-formed authenticated API answer). 401 means the key
  // is invalid/revoked, so every paid company check would fail.
  companiesHouse: new Set([200, 404]),
  // A known submissions record with SEC's required User-Agent: only 200. A
  // 403 means SEC is refusing us (missing/blocked User-Agent or rate policy).
  secEdgar: new Set([200]),
} as const

/** Pure classification of one probe response. */
export function isUsableStatus(status: number, ready: ReadonlySet<number>): boolean {
  return ready.has(status)
}

async function probe(url: string, headers: Record<string, string>, ready: ReadonlySet<number>): Promise<boolean> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers,
      signal: controller.signal,
    })
    // Reachability alone is not readiness: a 503 maintenance page or a 429
    // answers on the network but cannot serve a paid request.
    await res.body?.cancel().catch(() => {})
    return isUsableStatus(res.status, ready)
  } catch {
    return false
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Pure decision: given a breaker and the current time, should we probe the
 * upstream, or short-circuit with a cached/fail-fast result? Extracted as a
 * pure function (no I/O, time injected) so the state machine is unit-testable.
 *
 * Returns either { probe: false, result } to short-circuit, or
 * { probe: true } meaning the caller should run the probe then call
 * applyProbeResult().
 */
export function decideProbe(
  b: Breaker,
  now: number
): { probe: false; result: boolean } | { probe: true } {
  if (b.state === 'open') {
    if (now - b.openedAt < OPEN_COOLDOWN_MS) {
      return { probe: false, result: false } // fail fast, no probe
    }
    b.state = 'half-open' // cooldown done — allow a trial probe
  }
  if (b.state === 'closed' && now - b.lastProbeAt < TTL_MS) {
    return { probe: false, result: b.lastResult } // serve cached within TTL
  }
  return { probe: true }
}

/** Pure transition: fold a probe result into the breaker state. */
export function applyProbeResult(b: Breaker, healthy: boolean, now: number): boolean {
  b.lastProbeAt = now
  b.lastResult = healthy
  if (healthy) {
    b.state = 'closed'
    b.consecutiveFailures = 0
  } else {
    b.consecutiveFailures += 1
    if (b.state === 'half-open' || b.consecutiveFailures >= FAILURE_THRESHOLD) {
      b.state = 'open'
      b.openedAt = now
    }
  }
  return healthy
}

// Exported for tests only.
export const __test = { newBreaker, FAILURE_THRESHOLD, OPEN_COOLDOWN_MS, TTL_MS, reset: () => breakers.clear() }

async function getHealth(
  key: string,
  url: string,
  headers: Record<string, string>,
  ready: ReadonlySet<number>
): Promise<boolean> {
  const now = Date.now()
  let b = breakers.get(key)
  if (!b) {
    b = newBreaker()
    breakers.set(key, b)
  }

  const decision = decideProbe(b, now)
  if (!decision.probe) return decision.result

  const healthy = await probe(url, headers, ready)
  return applyProbeResult(b, healthy, now)
}

// The retired Chainalysis oracle has no health probe: wallet screening readiness
// is the OFAC SDN snapshot's freshness (walletSanctions.ts sanctionsDataStatus).

/** Is the Companies House API reachable right now? (cached) */
export function companiesHouseHealthy(): Promise<boolean> {
  const auth = 'Basic ' + Buffer.from(`${config.companiesHouse.apiKey}:`).toString('base64')
  return getHealth(
    'companiesHouse',
    `${config.companiesHouse.baseUrl}/company/00000006`,
    { Authorization: auth },
    PROVIDER_READY_STATUSES.companiesHouse
  )
}

/**
 * Is SEC EDGAR reachable right now? (cached, circuit-broken)
 * Probes a small known submissions record (Apple, CIK 0000320193). SEC requires
 * a descriptive User-Agent on every request, so we send the configured one —
 * without it SEC returns 403, which would look like an outage.
 */
export function edgarHealthy(): Promise<boolean> {
  return getHealth(
    'sec-edgar',
    'https://data.sec.gov/submissions/CIK0000320193.json',
    { 'User-Agent': config.edgar.userAgent },
    PROVIDER_READY_STATUSES.secEdgar
  )
}
