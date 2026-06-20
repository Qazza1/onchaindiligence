/**
 * rateLimit.ts
 * ------------
 * Per-caller rate limiting for the paid endpoints.
 *
 * WHY THIS EXISTS (the real problem it solves):
 * We charge per call and rely on FREE upstream APIs that have their own
 * rate limits (Chainalysis: 5000 req / 5 min on the key; Companies House:
 * see their docs). A single agent looping our endpoint would happily pay
 * us for every call — but once we blow through the upstream's shared limit,
 * those upstream calls start returning 429, and we'd be charging for a
 * service that then fails. Capping requests PER CALLER, BEFORE payment is
 * required, prevents one caller from exhausting the shared upstream budget
 * for everyone.
 *
 * IMPORTANT LIMITATION — single-instance only:
 * This is an in-memory limiter. On Vercel (serverless, many ephemeral
 * instances) each instance has its own counter, so the effective global
 * limit is higher than the per-instance number set here, and counters
 * reset on cold starts. This is a deliberate, documented tradeoff: it's a
 * genuine safety valve against a single hot caller, NOT a hard global
 * guarantee. For a hard global limit across instances you'd back this with
 * a shared store (e.g. Upstash Redis) — noted as a fast-follow in DEPLOY.md.
 *
 * We intentionally do not pull in a heavy dependency for this; the logic
 * is small and the limitation above would apply to most drop-in libraries
 * on serverless anyway without external state.
 */

export interface RateLimitOptions {
  /** Max requests allowed per caller within the window. */
  max: number
  /** Window length in milliseconds. */
  windowMs: number
}

export interface RateLimitResult {
  allowed: boolean
  /** Requests remaining in the current window (>= 0). */
  remaining: number
  /** Unix ms timestamp when the current window resets. */
  resetAt: number
  /** Seconds until reset — convenient for the Retry-After header. */
  retryAfterSeconds: number
}

interface Bucket {
  count: number
  resetAt: number
}

/**
 * Creates an isolated rate limiter. Each call site (e.g. each route group)
 * can have its own instance with its own window/max so limits don't bleed
 * across endpoints.
 */
export function createRateLimiter(options: RateLimitOptions) {
  const buckets = new Map<string, Bucket>()

  // Opportunistic cleanup so the Map doesn't grow unbounded across many
  // distinct callers. Runs on access, not on a timer (timers don't survive
  // serverless freezes reliably).
  function sweep(now: number) {
    if (buckets.size < 1000) return // cheap guard — only sweep when it's worth it
    for (const [key, bucket] of buckets) {
      if (bucket.resetAt <= now) buckets.delete(key)
    }
  }

  return function check(key: string): RateLimitResult {
    const now = Date.now()
    sweep(now)

    let bucket = buckets.get(key)

    // New caller, or their previous window has fully elapsed → fresh window.
    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + options.windowMs }
      buckets.set(key, bucket)
    }

    bucket.count += 1

    const remaining = Math.max(0, options.max - bucket.count)
    const allowed = bucket.count <= options.max
    const retryAfterSeconds = Math.max(0, Math.ceil((bucket.resetAt - now) / 1000))

    return { allowed, remaining, resetAt: bucket.resetAt, retryAfterSeconds }
  }
}

/**
 * Derives a stable caller key from the request. Order of preference:
 *   1. The paying wallet, if a payment credential is present (most precise —
 *      ties the limit to who actually pays, not just an IP).
 *   2. Client IP from standard proxy headers (Vercel sets x-forwarded-for).
 *   3. A constant fallback so a missing identifier fails closed into one
 *      shared bucket rather than bypassing limiting entirely.
 *
 * NOTE: we read the wallet opportunistically from the Authorization header
 * without trusting it for payment (the SDK still does real verification).
 * It's only used here as a grouping key for rate limiting.
 */
export function callerKeyFromHeaders(headers: {
  authorization?: string | null
  forwardedFor?: string | null
}): string {
  const auth = headers.authorization ?? ''
  // Payment credentials are long base64url blobs; if present, hash-ish key
  // off a stable slice so the same credential family groups together.
  // (We avoid parsing the credential here to keep this dependency-free and
  // fast; precise per-wallet limiting can be layered in later.)
  if (auth.toLowerCase().startsWith('payment ')) {
    return `cred:${auth.slice(8, 64)}`
  }

  const ip = (headers.forwardedFor ?? '').split(',')[0]?.trim()
  if (ip) return `ip:${ip}`

  return 'anon:shared'
}
