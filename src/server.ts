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
import { cors } from 'hono/cors'
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
import { chainalysisHealthy, companiesHouseHealthy, edgarHealthy } from './health.js'
import { logPaymentSuccess, logPaymentFailed } from './paymentLog.js'
import { attest, attestationEnabled, getPublicKeyPem, getKeyId } from './attestation.js'
import { isTotalFailure } from './diligence.js'
import { buildOpenApiSpec } from './openapi.js'
import { screenName, buildOfacAttribution, OfacUpstreamError } from './ofac.js'
import {
  checkUSCompany,
  buildAttribution as edgarAttribution,
  USCompanyNotFoundError,
} from './secEdgar.js'
import {
  anchoringEnabled,
  anchorSignature,
  isSignatureAnchored,
} from './anchor.js'
import { resolveToAddress, EnsResolutionError } from './ens.js'

assertConfigured()

const app = new Hono()

// CORS for the browser "instant web check" widget. Scoped to the /web/* routes
// so the rest of the API stays same-origin/agent-facing. Allowed origins are
// the website; overridable via env for local dev. The 402/MPP payment headers
// must be exposed so the browser client can read the challenge.
const WEB_ORIGINS = (process.env.WEB_ALLOWED_ORIGINS ||
  'https://onchaindiligence.com,https://www.onchaindiligence.com,http://localhost:8000,http://localhost:3000')
  .split(',')
  .map((s) => s.trim())
app.use(
  '/web/*',
  cors({
    origin: WEB_ORIGINS,
    allowMethods: ['GET', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    exposeHeaders: ['WWW-Authenticate', 'Authorization'],
    maxAge: 86400,
  })
)

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
    const input = c.req.param('address')

    if (!input || input.length < 7) {
      return c.json({ error: 'invalid address or ENS name parameter' }, 400)
    }

    try {
      // Accept an ENS name (e.g. vitalik.eth) or a hex address. Resolve first
      // so the caller can screen a human-readable name; we surface both.
      const { address, ens } = await resolveToAddress(input)
      const result = await screenAddress(address)
      return c.json(
        attest({
          ...result,
          ...(ens ? { ens_name: ens, resolved_address: address } : {}),
          ...chainalysisAttribution(),
          checked_at: new Date().toISOString(),
        })
      )
    } catch (err) {
      if (err instanceof EnsResolutionError) {
        return c.json({ error: err.message }, 400)
      }
      return handleUpstreamError(c, err)
    }
  }
)

// ---------------------------------------------------------------------
// Route 1b: OFAC SDN name screening
//
// GET /screen-name?name=Vladimir%20Putin[&threshold=0.85]
//
// Fuzzy-matches a person/company name against the official US Treasury OFAC
// SDN list (primary names + strong aliases). Returns scored candidate
// matches — a screening aid, never a determination. See ofac.ts for the
// honest scope notes.
// ---------------------------------------------------------------------
app.get(
  '/screen-name',
  rateLimit,
  mppx.charge({ amount: config.pricing.nameScreen }),
  async (c) => {
    const name = c.req.query('name')
    if (!name || name.trim().length < 2) {
      return c.json(
        { error: 'provide ?name= with at least 2 characters' },
        400
      )
    }

    // Optional caller-tunable threshold (0.5–1.0); defaults to 0.85.
    let threshold = 0.85
    const t = c.req.query('threshold')
    if (t !== undefined) {
      const parsed = Number(t)
      if (!Number.isFinite(parsed) || parsed < 0.5 || parsed > 1) {
        return c.json({ error: 'threshold must be a number between 0.5 and 1.0' }, 400)
      }
      threshold = parsed
    }

    try {
      const result = await screenName(name, threshold)
      return c.json(
        attest({
          ...result,
          ...buildOfacAttribution(),
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
// Route 2b: US public-company check only (SEC EDGAR)
//
// GET /us-company?q=AAPL   (also accepts a CIK like 0000320193 or a name)
//
// Looks up an SEC-registered (PUBLIC) company via EDGAR. Scope is public
// companies and funds only — private US companies register at the state
// level and are not in EDGAR; the result carries an explicit coverage note.
// ---------------------------------------------------------------------
app.get(
  '/us-company',
  rateLimit,
  healthGate(edgarHealthy, 'SEC EDGAR'),
  mppx.charge({ amount: config.pricing.usCompanyCheck }),
  async (c) => {
    const q = c.req.query('q')
    if (!q || q.trim().length < 1) {
      return c.json(
        { error: 'provide ?q= with a ticker, SEC CIK, or company name' },
        400
      )
    }

    try {
      const result = await checkUSCompany(q)
      return c.json(
        attest({
          ...result,
          ...edgarAttribution(),
          checked_at: new Date().toISOString(),
        })
      )
    } catch (err) {
      if (err instanceof USCompanyNotFoundError) {
        return c.json({ error: err.message }, 404)
      }
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
      wallet
        ? settleSafely(async () => {
            const { address } = await resolveToAddress(wallet)
            return screenAddress(address)
          })
        : Promise.resolve(null),
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
// Web tier: the "instant check" convenience layer the website widget uses.
//
// Same checks, same signed attestations — priced for one-off human use via a
// browser wallet rather than high-volume agents. This is a pricing CHANNEL,
// not a different or better service: agents can still use the cheap endpoints
// above. CORS is enabled (scoped to /web/*) so the browser can call these.
// The response carries tier: 'web' so it's transparent which rate applied.
// ---------------------------------------------------------------------
app.get(
  '/web/screen/:address',
  rateLimit,
  mppx.charge({ amount: config.pricing.webSanctionsCheck }),
  async (c) => {
    const input = c.req.param('address')
    if (!input || input.length < 7) {
      return c.json({ error: 'invalid address or ENS name parameter' }, 400)
    }
    try {
      const { address, ens } = await resolveToAddress(input)
      const result = await screenAddress(address)
      return c.json(
        attest({
          ...result,
          ...(ens ? { ens_name: ens, resolved_address: address } : {}),
          ...chainalysisAttribution(),
          tier: 'web',
          checked_at: new Date().toISOString(),
        })
      )
    } catch (err) {
      if (err instanceof EnsResolutionError) {
        return c.json({ error: err.message }, 400)
      }
      return handleUpstreamError(c, err)
    }
  }
)

app.get(
  '/web/company/:companyNumber',
  rateLimit,
  healthGate(companiesHouseHealthy, 'Companies House'),
  mppx.charge({ amount: config.pricing.webCompanyCheck }),
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
          tier: 'web',
          checked_at: new Date().toISOString(),
        })
      )
    } catch (err) {
      return handleUpstreamError(c, err)
    }
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
  if (err instanceof OfacUpstreamError) {
    return c.json(
      { error: 'OFAC SDN list is temporarily unavailable, please retry shortly' },
      err.status === 404 ? 502 : 503
    )
  }
  return c.json({ error: describeError(err) }, 502)
}

// ---------------------------------------------------------------------
// On-chain anchoring (Tempo) — optional, decoupled from paid checks.
//
//   POST /anchor       body: { signature }  → records keccak256(signature)
//                       on the Tempo AttestationRegistry. Paid (gas-backed).
//   GET  /anchored?signature=...            → free: is this attestation
//                       anchored on-chain, and when?
//
// Anchoring proves a signed attestation existed at a point in time, on a
// public chain, without revealing any subject data (only a hash is stored).
// These routes are independent of the compliance checks: a check never waits
// on the chain, and anchoring only happens when explicitly requested.
// ---------------------------------------------------------------------
app.get('/anchored', async (c) => {
  if (!anchoringEnabled() && !config.anchor.contractAddress) {
    return c.json({ error: 'on-chain anchoring is not enabled on this deployment' }, 404)
  }
  const signature = c.req.query('signature')
  if (!signature || signature.length < 16) {
    return c.json({ error: 'provide ?signature= (the attestation signature, base64url)' }, 400)
  }
  try {
    const result = await isSignatureAnchored(signature)
    return c.json({
      anchor_hash: result.anchorHash,
      anchored: result.anchored,
      anchored_at: result.anchoredAt
        ? new Date(result.anchoredAt * 1000).toISOString()
        : null,
      chain: 'Tempo',
      contract: config.anchor.contractAddress,
    })
  } catch (err) {
    return c.json({ error: describeError(err) }, 502)
  }
})

app.post(
  '/anchor',
  rateLimit,
  mppx.charge({ amount: config.pricing.nameScreen }),
  async (c) => {
    if (!anchoringEnabled()) {
      return c.json(
        { error: 'on-chain anchoring is not configured on this deployment' },
        503
      )
    }
    let body: { signature?: string }
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'expected JSON body with a "signature" field' }, 400)
    }
    if (!body.signature || body.signature.length < 16) {
      return c.json({ error: 'provide the attestation "signature" (base64url) to anchor' }, 400)
    }
    try {
      const { anchorHash, txHash, alreadyAnchored } = await anchorSignature(body.signature)
      return c.json(
        attest({
          anchor_hash: anchorHash,
          tx_hash: alreadyAnchored ? null : txHash,
          already_anchored: alreadyAnchored,
          chain: 'Tempo',
          contract: config.anchor.contractAddress,
          note: alreadyAnchored
            ? 'This attestation was already anchored on-chain; no new transaction was sent.'
            : 'Attestation hash anchored on Tempo. Anyone can verify it via GET /anchored.',
        })
      )
    } catch (err) {
      return c.json({ error: describeError(err) }, 502)
    }
  }
)

// ---------------------------------------------------------------------
// OpenAPI — our complete, hand-maintained spec. Registered BEFORE the
// discovery() helper below so this richer document wins the /openapi.json
// route (Hono: first match serves). discovery() still wires up the payment
// challenge behaviour; we just serve a fuller spec than its auto stub.
// ---------------------------------------------------------------------
app.get('/openapi.json', (c) => c.json(buildOpenApiSpec()))

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
  const [oracleOk, companiesHouseOk, edgarOk] = await Promise.all([
    chainalysisHealthy().catch(() => false),
    companiesHouseHealthy().catch(() => false),
    edgarHealthy().catch(() => false),
  ])
  const signingConfigured = attestationEnabled()

  // Upstreams determine readiness. Signing being off is a degraded state for
  // a compliance tool (results would be unsigned), so we surface it — but we
  // don't 503 purely on signing, since checks still return correct data.
  const upstreamsHealthy = oracleOk && companiesHouseOk && edgarOk
  const status = upstreamsHealthy ? 'ok' : 'degraded'

  if (!upstreamsHealthy) c.header('Retry-After', '30')

  return c.json(
    {
      status,
      checked_at: new Date().toISOString(),
      upstreams: {
        sanctions_oracle: oracleOk ? 'reachable' : 'unreachable',
        companies_house: companiesHouseOk ? 'reachable' : 'unreachable',
        sec_edgar: edgarOk ? 'reachable' : 'unreachable',
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
      'GET /screen-name?name=': `OFAC SDN name screening — $${config.pricing.nameScreen}`,
      'GET /company/:companyNumber': `UK company check only — $${config.pricing.companyCheck}`,
      'GET /us-company?q=': `US public company check (SEC EDGAR) — $${config.pricing.usCompanyCheck}`,
      'POST /anchor': `Anchor an attestation on Tempo — $${config.pricing.nameScreen}`,
      'GET /anchored?signature=': 'Check if an attestation is anchored on-chain — free',
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
