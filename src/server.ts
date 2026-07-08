/**
 * server.ts
 * ---------
 * Compliance Diligence Suite — MPP-gated endpoints on Tempo:
 *
 *   GET /screen/:address          — sanctions check only  (Chainalysis)
 *   GET /verdict/:address         — unified signed PASS/BLOCK verdict
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
import { isSandboxVector, sandboxScreen, listVectors } from './sandbox.js'
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
  'https://onchaindiligence.com,https://www.onchaindiligence.com')
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

// Public transparency endpoints: /health and the published attestation key.
// These are unauthenticated, read-only, no-secret reads that are *meant* to be
// fetched from anywhere — the status page reads /health cross-origin, and any
// verifier fetching the public key to check an attestation may call from its
// own origin. So they're readable from any origin (unlike /web/*, which is
// scoped to the site). Nothing sensitive is exposed by opening these.
app.use(
  '/health',
  cors({ origin: '*', allowMethods: ['GET', 'OPTIONS'], maxAge: 86400 })
)
app.use(
  '/.well-known/attestation-key',
  cors({ origin: '*', allowMethods: ['GET', 'OPTIONS'], maxAge: 86400 })
)
// Sandbox is free, read-only test data — safe to read from any origin so
// integrators can build against it from the browser and CI.
app.use(
  '/sandbox/*',
  cors({ origin: '*', allowMethods: ['GET', 'OPTIONS'], maxAge: 86400 })
)
app.use(
  '/sandbox',
  cors({ origin: '*', allowMethods: ['GET', 'OPTIONS'], maxAge: 86400 })
)

// The investigations app (app.onchaindiligence.com) calls /attest to sign
// evidence exports with the same attestation key the rest of the API uses, so
// exports verify through the same /verify page. Scoped to the app origin.
const APP_ORIGINS = (process.env.APP_ALLOWED_ORIGINS ||
  'https://app.onchaindiligence.com,http://localhost:5173')
  .split(',')
  .map((s) => s.trim())
app.use(
  '/attest',
  cors({
    origin: APP_ORIGINS,
    allowMethods: ['POST', 'OPTIONS'],
    allowHeaders: ['Content-Type'],
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
// Route: /verdict/:address — unified, signed PASS / WARN / BLOCK decision.
//
// One call → one signed decision, with reasons. The only *signed* verdict in
// the x402 compliance space. v1 logic is conservative and honest:
//   BLOCK — sanctioned (hard legal line).  PASS — screened clean.
//   WARN  — reserved for genuinely-partial signals; with sanctions-only data
//           there is no honest WARN trigger yet, and any upstream failure
//           ERRORS rather than returning a false PASS. Richer signals (risk
//           score, mixer exposure, wallet age, proximity) feed this same
//           endpoint later with no breaking change; `verdict_basis` discloses
//           exactly which signals are live so callers never over-trust a thin
//           PASS. Paid, same tier as /screen (bundles a real screening call).
// ---------------------------------------------------------------------
app.get(
  '/verdict/:address',
  rateLimit,
  healthGate(chainalysisHealthy, 'Chainalysis'),
  mppx.charge({ amount: config.pricing.sanctionsCheck }),
  async (c) => {
    const input = c.req.param('address')
    if (!input || input.length < 7) {
      return c.json({ error: 'invalid address or ENS name parameter' }, 400)
    }

    try {
      const { address, ens } = await resolveToAddress(input)
      const screen = await screenAddress(address)

      let verdict: 'PASS' | 'WARN' | 'BLOCK'
      const reasons: string[] = []

      if (screen.sanctioned === true) {
        verdict = 'BLOCK'
        reasons.push('Address is on the sanctions list (OFAC via Chainalysis on-chain oracle).')
      } else {
        verdict = 'PASS'
        reasons.push('No sanctions match found.')
      }

      const signals = {
        sanctions: { checked: true, sanctioned: screen.sanctioned === true },
      }

      return c.json(
        attest({
          verdict,
          reasons,
          address,
          ...(ens ? { ens_name: ens, resolved_address: address } : {}),
          signals,
          verdict_basis: {
            live_signals: ['sanctions'],
            not_yet_evaluated: ['risk_score', 'mixer_exposure', 'wallet_age', 'sanctions_proximity'],
            note:
              'v1 verdict is sanctions-driven. PASS means no sanctions match — ' +
              'it is not a full risk clearance. Additional signals will enrich ' +
              'future verdicts under the same response shape.',
          },
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
// Route 1-sandbox: TEST MODE screening — free, no upstream, no payment.
//
// Lets integrators build and CI-test the full flow (including a positive
// sanctions hit) without paying or touching the live oracle. Only documented
// test-vector addresses work; a real address is refused so nobody screens a
// real counterparty against fake data. Every response is loudly flagged and
// UNSIGNED so it can never be mistaken for a real determination.
//   GET /sandbox/screen/:address   (also /sandbox to list vectors)
// ---------------------------------------------------------------------
app.get('/sandbox', rateLimit, (c) => {
  return c.json({
    sandbox: true,
    what: 'Test mode. Screen documented test-vector addresses for free, with no payment and no upstream call, to build and CI-test your integration — including a positive sanctions hit.',
    usage: 'GET /sandbox/screen/:address using one of the test vectors below.',
    important:
      'Sandbox responses are test data only: unsigned, flagged sandbox:true, and never a real determination. Real addresses are refused here — use the production /screen endpoint for real screening.',
    test_vectors: listVectors(),
  })
})

app.get('/sandbox/screen/:address', rateLimit, (c) => {
  const input = c.req.param('address')

  if (!input || input.length < 7) {
    return c.json({ error: 'invalid address parameter', sandbox: true }, 400)
  }

  // Only documented test vectors are allowed in sandbox. A real address is
  // refused — so nobody accidentally screens a real counterparty against fake
  // data and trusts the answer.
  if (!isSandboxVector(input)) {
    return c.json(
      {
        error: 'not a sandbox test vector',
        sandbox: true,
        detail:
          'Sandbox only accepts the documented test-vector addresses, so a real ' +
          'address is never screened against fake data. To screen a real address, ' +
          'use the production endpoint: GET /screen/:address.',
        test_vectors: listVectors(),
      },
      400
    )
  }

  return c.json(sandboxScreen(input))
})


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

app.get(
  '/web/screen-name',
  rateLimit,
  mppx.charge({ amount: config.pricing.webNameScreen }),
  async (c) => {
    const name = c.req.query('name')
    if (!name || name.trim().length < 2) {
      return c.json({ error: 'provide ?name= with at least 2 characters' }, 400)
    }
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
          tier: 'web',
          checked_at: new Date().toISOString(),
        })
      )
    } catch (err) {
      return handleUpstreamError(c, err)
    }
  }
)

app.get(
  '/web/us-company',
  rateLimit,
  healthGate(edgarHealthy, 'SEC EDGAR'),
  mppx.charge({ amount: config.pricing.webUsCompanyCheck }),
  async (c) => {
    const q = c.req.query('q')
    if (!q || q.trim().length < 1) {
      return c.json({ error: 'provide ?q= with a ticker, SEC CIK, or company name' }, 400)
    }
    try {
      const result = await checkUSCompany(q)
      return c.json(
        attest({
          ...result,
          ...edgarAttribution(),
          tier: 'web',
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
// Route: /attest — free attestation endpoint for the app UI
//
// Accepts a caller-supplied evidence object and returns it wrapped in a
// signed Ed25519 attestation envelope (same shape as the paid routes).
// Free (no MPP gating). CORS is handled by the cors() middleware for
// '/attest' registered near the top of the file (APP_ORIGINS).
// ---------------------------------------------------------------------
app.post('/attest', async (c) => {
  // CORS is handled by the cors() middleware registered for '/attest' above.
  if (!attestationEnabled()) {
    return c.json(
      { error: 'attestation is not configured on this deployment' },
      503
    )
  }
  let body: unknown
  try {
    body = await c.req.json()
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400)
  }
  const evidence = (body as Record<string, unknown>)?.evidence
  if (!evidence || typeof evidence !== 'object') {
    return c.json({ error: 'body must be { "evidence": { ... } }' }, 400)
  }
  if (JSON.stringify(evidence).length > 200_000) {
    return c.json({ error: 'evidence payload too large (max ~200KB)' }, 413)
  }
  const signed = attest(evidence as Record<string, unknown>)
  return c.json(signed, 200)
})

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
      'GET /verdict/:address': `Unified signed PASS/BLOCK counterparty verdict — $${config.pricing.sanctionsCheck}`,
      'GET /screen-name?name=': `OFAC SDN name screening — $${config.pricing.nameScreen}`,
      'GET /company/:companyNumber': `UK company check only — $${config.pricing.companyCheck}`,
      'GET /us-company?q=': `US public company check (SEC EDGAR) — $${config.pricing.usCompanyCheck}`,
      'POST /attest': 'Wrap caller-supplied evidence in a signed attestation — free',
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
