/**
 * server.ts
 * ---------
 * Compliance Diligence Suite — three MPP-gated endpoints on Tempo:
 *
 *   GET /screen/:address          — sanctions check only  (Chainalysis)
 *   GET /company/:companyNumber   — UK company check only (Companies House)
 *   GET /diligence                — both, bundled          (?wallet & ?company)
 *
 * Design principle carried through every route: this product answers
 * narrow factual questions and says so. It does not claim to verify that
 * a wallet belongs to a company, does not give legal/compliance advice,
 * and does not pretend to replace a real compliance program. Every
 * response says exactly what was checked and what wasn't.
 */

import { Hono } from 'hono'
import type { MiddlewareHandler } from 'hono'
import { Mppx, tempo, discovery } from 'mppx/hono'
import { config, assertConfigured } from './config.js'
import {
  screenAddress,
  buildAttribution as chainalysisAttribution,
  ChainalysisRateLimitError,
  ChainalysisUpstreamError,
} from './chainalysis.js'
import {
  checkCompany,
  buildAttribution as companiesHouseAttribution,
  CompanyNotFoundError,
  CompaniesHouseUpstreamError,
} from './companiesHouse.js'
import { createRateLimiter, callerKeyFromHeaders } from './rateLimit.js'
import { chainalysisHealthy, companiesHouseHealthy } from './health.js'
import { logPaymentSuccess, logPaymentFailed } from './paymentLog.js'
import { attest, attestationEnabled, getPublicKeyPem, getKeyId } from './attestation.js'
import { isTotalFailure } from './diligence.js'

assertConfigured()

const app = new Hono()

const mppx = Mppx.create({
  // Root-of-trust for challenge binding. MUST be set via env on mainnet;
  // never commit it. See README "Secrets" section.
  secretKey: process.env.MPP_SECRET_KEY,
  methods: [
    tempo.charge({
      currency: config.tempo.currencyAddress,
      recipient: config.tempo.recipient,
      testnet: config.tempo.testnet,
    }),
  ],
})

// Record every settled / failed payment. In the Tempo charge model the
// agent has already paid on-chain by the time we verify, so this log is
// our record of what was actually collected (see paymentLog.ts + the
// refund disclosure in README).
mppx.onPaymentSuccess(({ receipt }) => logPaymentSuccess(receipt))
mppx.onPaymentFailed(({ error }) => logPaymentFailed(error?.message ?? 'unknown payment failure'))

// ---------------------------------------------------------------------
// Pre-payment guards
//
// These run BEFORE mppx.charge in the middleware chain, which is the whole
// point: we want to reject abusive callers and known-down upstreams BEFORE
// issuing a 402 / taking payment. Once a 402 is issued and the agent pays
// on-chain, we can't un-take the money — so the safest lever is to not ask
// for it when we already know the call can't succeed.
// ---------------------------------------------------------------------

// Per-caller limiter. Tuned conservatively below the upstream ceilings so
// one hot caller can't exhaust the shared free-tier budget for everyone.
// (Chainalysis: 5000/5min on the key; Companies House: see their docs.)
const limiter = createRateLimiter({ max: 30, windowMs: 60_000 }) // 30 req/min per caller

const rateLimit: MiddlewareHandler = async (c, next) => {
  const key = callerKeyFromHeaders({
    authorization: c.req.header('authorization') ?? null,
    forwardedFor: c.req.header('x-forwarded-for') ?? null,
  })
  const result = limiter(key)
  c.header('X-RateLimit-Remaining', String(result.remaining))
  if (!result.allowed) {
    c.header('Retry-After', String(result.retryAfterSeconds))
    return c.json(
      {
        error: 'rate limit exceeded',
        detail: 'Too many requests from this caller. This protects the shared upstream rate limits.',
        retry_after_seconds: result.retryAfterSeconds,
      },
      429
    )
  }
  await next()
}

/**
 * Builds a health-gate middleware for a given upstream. If the upstream is
 * known-unavailable (cached liveness probe), we return 503 BEFORE payment
 * is required, so the agent isn't charged for a call we already know will
 * fail. Does not cover an upstream dying mid-request after payment — that
 * residual is covered by the no-auto-refund disclosure + payment logging.
 */
function healthGate(check: () => Promise<boolean>, providerName: string): MiddlewareHandler {
  return async (c, next) => {
    const healthy = await check()
    if (!healthy) {
      c.header('Retry-After', '30')
      return c.json(
        {
          error: 'upstream temporarily unavailable',
          detail: `${providerName} appears to be unreachable right now. No payment was requested. Please retry shortly.`,
        },
        503
      )
    }
    await next()
  }
}

// ---------------------------------------------------------------------
// Route 1: Sanctions screening only
// ---------------------------------------------------------------------
app.get(
  '/screen/:address',
  rateLimit,
  healthGate(chainalysisHealthy, 'Chainalysis'),
  mppx.charge({ amount: config.pricing.sanctionsCheck }),
  async (c) => {
    const address = c.req.param('address')

    if (!address || address.length < 10) {
      return c.json({ error: 'invalid address parameter' }, 400)
    }

    try {
      const result = await screenAddress(address)
      return c.json(
        attest({
          ...result,
          ...chainalysisAttribution(),
          checked_at: new Date().toISOString(),
        })
      )
    } catch (err) {
      return handleUpstreamError(c, err)
    }
  }
)

// ---------------------------------------------------------------------
// Route 2: UK company check only
// ---------------------------------------------------------------------
app.get(
  '/company/:companyNumber',
  rateLimit,
  healthGate(companiesHouseHealthy, 'Companies House'),
  mppx.charge({ amount: config.pricing.companyCheck }),
  async (c) => {
    const companyNumber = c.req.param('companyNumber')

    if (!companyNumber) {
      return c.json({ error: 'companyNumber parameter is required' }, 400)
    }

    try {
      const result = await checkCompany(companyNumber)
      return c.json(
        attest({
          ...result,
          ...companiesHouseAttribution(),
          checked_at: new Date().toISOString(),
        })
      )
    } catch (err) {
      return handleUpstreamError(c, err)
    }
  }
)

// ---------------------------------------------------------------------
// Route 3: Combined diligence bundle
//
// GET /diligence?wallet=0x...&company=12345678
//
// At least one of wallet / company must be supplied. Both run in
// parallel when both are given. The two checks are NEVER presented as
// linked — see the `link_disclaimer` field, which is not optional.
// ---------------------------------------------------------------------
// A pre-payment guard specific to /diligence: only gate on the upstream(s)
// the caller is actually about to use. Gating on Chainalysis when the
// caller only asked for a company check (or vice-versa) would wrongly
// block a call that could have succeeded.
const diligenceHealthGate: MiddlewareHandler = async (c, next) => {
  const wantsWallet = !!c.req.query('wallet')
  const wantsCompany = !!c.req.query('company')

  const checks: Array<Promise<{ name: string; ok: boolean }>> = []
  if (wantsWallet) checks.push(chainalysisHealthy().then((ok) => ({ name: 'Chainalysis', ok })))
  if (wantsCompany) checks.push(companiesHouseHealthy().then((ok) => ({ name: 'Companies House', ok })))

  if (checks.length > 0) {
    const results = await Promise.all(checks)
    const down = results.filter((r) => !r.ok).map((r) => r.name)
    // Only block before payment if EVERY requested upstream is down. If at
    // least one is healthy, we proceed — the handler returns partial
    // results, so the caller still gets value for their payment.
    if (down.length === results.length) {
      c.header('Retry-After', '30')
      return c.json(
        {
          error: 'upstream temporarily unavailable',
          detail: `All requested providers (${down.join(', ')}) appear unreachable right now. No payment was requested. Please retry shortly.`,
        },
        503
      )
    }
  }
  await next()
}

app.get(
  '/diligence',
  rateLimit,
  diligenceHealthGate,
  mppx.charge({ amount: config.pricing.combinedDiligence }),
  async (c) => {
    const wallet = c.req.query('wallet')
    const companyNumber = c.req.query('company')

    if (!wallet && !companyNumber) {
      return c.json(
        { error: 'provide at least one of: ?wallet=<address> or ?company=<company_number>' },
        400
      )
    }

    const response: Record<string, unknown> = {
      checked_at: new Date().toISOString(),
    }

    // Run both lookups concurrently rather than sequentially.
    const [walletOutcome, companyOutcome] = await Promise.all([
      wallet ? settleSafely(() => screenAddress(wallet)) : Promise.resolve(null),
      companyNumber ? settleSafely(() => checkCompany(companyNumber)) : Promise.resolve(null),
    ])

    if (walletOutcome) {
      response.wallet_check = walletOutcome.ok
        ? { ...walletOutcome.value, ...chainalysisAttribution() }
        : { error: walletOutcome.error }
    }

    if (companyOutcome) {
      response.company_check = companyOutcome.ok
        ? { ...companyOutcome.value, ...companiesHouseAttribution() }
        : { error: companyOutcome.error }
    }

    // Integrity guard: never return a signed 200 over a response in which
    // EVERY attempted check failed. A signed, success-shaped attestation
    // wrapping nothing but errors would be misleading for an auditor — the
    // signature would vouch for a "result" that contains no actual result.
    // Partial success (one ok, one failed) is fine and still returns 200,
    // because the caller received real value for at least one check.
    if (isTotalFailure(walletOutcome, companyOutcome)) {
      c.header('Retry-After', '30')
      return c.json(
        {
          error: 'all requested checks failed',
          detail:
            'Every requested provider returned an error during lookup, so there ' +
            'is no result to attest. This response is intentionally unsigned. ' +
            'Please retry shortly.',
          wallet_check: response.wallet_check,
          company_check: response.company_check,
        },
        502
      )
    }

    // This line is the most important part of this endpoint's response.
    // Without it, two independent "clean" results could be misread as
    // "this wallet belongs to this verified company" — which this data
    // does not establish.
    response.link_disclaimer =
      'These are independent checks against separate data sources. ' +
      'No verified link between the wallet address and the company is ' +
      'established by this data, regardless of the individual results above.'

    return c.json(attest(response))
  }
)

// ---------------------------------------------------------------------
// Shared error handling
// ---------------------------------------------------------------------

/** Wraps a lookup so one failing check doesn't take down the other in /diligence. */
async function settleSafely<T>(
  fn: () => Promise<T>
): Promise<{ ok: true; value: T } | { ok: false; error: string }> {
  try {
    return { ok: true, value: await fn() }
  } catch (err) {
    return { ok: false, error: describeError(err) }
  }
}

function describeError(err: unknown): string {
  if (err instanceof ChainalysisRateLimitError) return 'sanctions provider rate-limited, please retry shortly'
  if (err instanceof ChainalysisUpstreamError) return `sanctions provider error (status ${err.status})`
  if (err instanceof CompanyNotFoundError) return err.message
  if (err instanceof CompaniesHouseUpstreamError) return `Companies House error (status ${err.status})`
  return 'unexpected error during lookup'
}

function handleUpstreamError(c: any, err: unknown) {
  if (err instanceof CompanyNotFoundError) {
    return c.json({ error: err.message }, 404)
  }
  if (err instanceof ChainalysisRateLimitError) {
    return c.json({ error: describeError(err) }, 503)
  }
  return c.json({ error: describeError(err) }, 502)
}

// ---------------------------------------------------------------------
// Discovery — lets agents and registries find this service and its
// payment terms automatically.
// ---------------------------------------------------------------------
discovery(app, mppx, {
  auto: true,
  info: config.service,
})

// ---------------------------------------------------------------------
// Attestation public key — verifiers fetch this to check signatures.
// Publishing the public key is safe and is the whole point of signing.
// ---------------------------------------------------------------------
app.get('/.well-known/attestation-key', (c) => {
  if (!attestationEnabled()) {
    return c.json(
      {
        enabled: false,
        note: 'Attestation is not configured on this deployment. Responses are unsigned.',
      },
      404
    )
  }
  return c.json({
    enabled: true,
    key_id: getKeyId(),
    algorithm: 'ed25519',
    public_key_pem: getPublicKeyPem(),
    verify_hint:
      'Signatures are over JSON.stringify({ data, issued_at, key_id }) from the response body, ' +
      'verified with this Ed25519 public key.',
  })
})

// ---------------------------------------------------------------------
// Health — a free, unauthenticated liveness/readiness endpoint.
//
// Reports whether each upstream data source is currently reachable (using
// the same cached, circuit-broken checks the payment gates use, so polling
// this doesn't hammer the providers) and whether response signing is
// configured. The HTTP status reflects reality: 200 when fully healthy,
// 503 when any dependency is degraded — so automated monitors that key off
// the status code behave correctly. No payment, no rate limit.
// ---------------------------------------------------------------------
app.get('/health', async (c) => {
  const [oracleOk, companiesHouseOk] = await Promise.all([
    chainalysisHealthy().catch(() => false),
    companiesHouseHealthy().catch(() => false),
  ])
  const signingConfigured = attestationEnabled()

  // Upstreams determine readiness. Signing being off is a degraded state for
  // a compliance tool (results would be unsigned), so we surface it — but we
  // don't 503 purely on signing, since checks still return correct data.
  const upstreamsHealthy = oracleOk && companiesHouseOk
  const status = upstreamsHealthy ? 'ok' : 'degraded'

  if (!upstreamsHealthy) c.header('Retry-After', '30')

  return c.json(
    {
      status,
      checked_at: new Date().toISOString(),
      upstreams: {
        sanctions_oracle: oracleOk ? 'reachable' : 'unreachable',
        companies_house: companiesHouseOk ? 'reachable' : 'unreachable',
      },
      attestation: signingConfigured ? 'configured' : 'not_configured',
    },
    upstreamsHealthy ? 200 : 503
  )
})

app.get('/', (c) =>
  c.json({
    service: config.service.title,
    routes: {
      'GET /screen/:address': `Sanctions check only — $${config.pricing.sanctionsCheck}`,
      'GET /company/:companyNumber': `UK company check only — $${config.pricing.companyCheck}`,
      'GET /diligence?wallet=&company=': `Combined check — $${config.pricing.combinedDiligence}`,
    },
    health_url: '/health',
    attestation: {
      enabled: attestationEnabled(),
      public_key_url: '/.well-known/attestation-key',
    },
    note: 'See /openapi.json for machine-readable discovery, or README.md for full docs.',
  })
)

export default app
