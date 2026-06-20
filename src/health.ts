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

async function probe(url: string, headers: Record<string, string>): Promise<boolean> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers,
      signal: controller.signal,
    })
    // Any HTTP response (even 4xx) means the provider is REACHABLE, which is
    // all we're testing. 401/403/404 here just mean "we hit a real server."
    // Only a thrown error (network down, DNS fail, timeout) is "unhealthy."
    return res.status > 0
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
export const __test = { newBreaker, FAILURE_THRESHOLD, OPEN_COOLDOWN_MS, TTL_MS }

async function getHealth(
  key: string,
  url: string,
  headers: Record<string, string>
): Promise<boolean> {
  const now = Date.now()
  let b = breakers.get(key)
  if (!b) {
    b = newBreaker()
    breakers.set(key, b)
  }

  const decision = decideProbe(b, now)
  if (!decision.probe) return decision.result

  const healthy = await probe(url, headers)
  return applyProbeResult(b, healthy, now)
}

/**
 * Is the sanctions oracle's RPC reachable right now? (cached, circuit-broken)
 *
 * The oracle is read via JSON-RPC (POST), not a REST GET, so we can't use the
 * generic GET probe(). We do the cheapest possible liveness call — eth_chainId
 * — straight against the RPC, and fold the result into the same breaker state
 * machine via decideProbe/applyProbeResult so behaviour matches the other
 * upstream (fail-fast when down, half-open recovery).
 */
export async function chainalysisHealthy(): Promise<boolean> {
  const key = 'sanctions-oracle'
  const now = Date.now()
  let b = breakers.get(key)
  if (!b) {
    b = newBreaker()
    breakers.set(key, b)
  }

  const decision = decideProbe(b, now)
  if (!decision.probe) return decision.result

  let healthy = false
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(config.sanctionsOracle.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }),
      signal: controller.signal,
    })
    healthy = res.ok
  } catch {
    healthy = false
  } finally {
    clearTimeout(timer)
  }

  return applyProbeResult(b, healthy, now)
}

/** Is the Companies House API reachable right now? (cached) */
export function companiesHouseHealthy(): Promise<boolean> {
  const auth = 'Basic ' + Buffer.from(`${config.companiesHouse.apiKey}:`).toString('base64')
  return getHealth(
    'companiesHouse',
    `${config.companiesHouse.baseUrl}/company/00000006`,
    { Authorization: auth }
  )
}
