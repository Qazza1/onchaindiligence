/**
 * server.ts
 * ---------
 * Compliance Diligence Suite — MPP-gated endpoints on Tempo:
 *
 *   GET /screen/:address          — wallet screen only    (OFAC SDN digital currency addresses)
 *   GET /verdict/:address         — unified signed PASS/WARN/BLOCK verdict
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
  buildAttribution as walletSanctionsAttribution,
  loadUsableSnapshot,
  runWithPinnedSnapshot,
  sanctionsDataStatus,
  sanctionsUnavailableBody,
  invalidAddressBody,
  InvalidWalletAddressError,
  SanctionsUnavailableError,
  SANCTIONS_UNAVAILABLE_CODE,
} from './walletSanctions.js'
import { classifyAddress, screenEvmAddress, type LoadedSnapshot } from './ofacSdnDigitalCurrency.js'
import {
  checkCompany,
  buildAttribution as companiesHouseAttribution,
  CompanyNotFoundError,
  CompaniesHouseUpstreamError,
} from './companiesHouse.js'
import { createRateLimiter, callerKeyFromHeaders } from './rateLimit.js'
import { companiesHouseHealthy, edgarHealthy } from './health.js'
import { logPaymentSuccess, logPaymentFailed } from './paymentLog.js'
import {
  attest,
  attestationEnabled,
  attestationSigningReady,
  getPublicKeyPem,
  getKeyId,
  getAttestationKeyRecords,
  getAttestationKeyRecord,
  getAttestationKeyRegistryReadiness,
  ATTESTATION_ISSUER,
  ATTESTATION_SCHEMA_VERSION,
  ATTESTATION_PURPOSE,
  ATTESTATION_FIXTURE_PURPOSE,
  ATTESTATION_RECEIPT_PURPOSE,
  ATTESTATION_ALLOWANCE_PURPOSE,
  ATTESTATION_BRIDGE_ACTION_PURPOSE,
  ATTESTATION_STAKING_ACTION_PURPOSE,
  verifyAttestationForAnchoring,
  type VerifiedAttestationForAnchoring,
} from './attestation.js'
import { isTotalFailure } from './diligence.js'
import { buildOpenApiSpec } from './openapi.js'
import { screenName, loadSdnIndex, buildOfacAttribution, OfacUpstreamError, OfacNameScreeningUnavailableError } from './ofac.js'
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
  tempoNetworkLabel,
} from './anchor.js'
import { resolveToAddress, looksLikeEns, EnsResolutionError } from './ens.js'
import { authorizeInternalBearer } from './internalAuth.js'
import { evaluateVerdict } from './verdict.js'

assertConfigured()

// Fail startup for contradictory or structurally unsafe registry history. A
// missing activation boundary remains an explicit migration readiness warning.
getAttestationKeyRecords()

const app = new Hono<{
  Variables: { verifiedAnchorAttestation: VerifiedAttestationForAnchoring }
}>()

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
app.use(
  '/.well-known/attestation-keys',
  cors({ origin: '*', allowMethods: ['GET', 'OPTIONS'], maxAge: 86400 })
)
app.use(
  '/.well-known/attestation-keys/*',
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

// POST /attest is an internal server-to-server signing route. CORS remains
// narrow as defence in depth, but the actual security boundary is the bearer
// token checked by the handler. Browser code must never receive that token.
const APP_ORIGINS = (process.env.APP_ALLOWED_ORIGINS ||
  'https://app.onchaindiligence.com,http://localhost:5173')
  .split(',')
  .map((s) => s.trim())
app.use(
  '/attest',
  cors({
    origin: APP_ORIGINS,
    allowMethods: ['POST', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400,
  })
)

const mppx = Mppx.create({
  // Root-of-trust for challenge binding. MUST be set via env on mainnet;
  // never commit it. See README "Secrets" section.
  secretKey: config.tempo.secretKey,
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

// Wallet screening gate, placed BEFORE mppx.charge() on every route that needs
// a sanctions result. Loads the active OFAC SDN snapshot and requires it to be
// fresh (walletSanctions.ts); otherwise 503 sanctions_screening_unavailable and
// no payment is requested. The snapshot judged usable here is pinned for the
// rest of the request, so the paid handler screens against exactly it and
// cannot fail on a second store read after the caller has paid.
async function usableSnapshotOrResponse(c: any): Promise<LoadedSnapshot | Response> {
  try {
    return await loadUsableSnapshot()
  } catch (err) {
    if (err instanceof SanctionsUnavailableError) return c.json(sanctionsUnavailableBody(err), 503)
    throw err
  }
}

const sanctionsSnapshotGate: MiddlewareHandler = async (c, next) => {
  const snapshot = await usableSnapshotOrResponse(c)
  if (snapshot instanceof Response) return snapshot
  return runWithPinnedSnapshot(snapshot, () => next())
}

// OFAC name-screening gate, placed BEFORE mppx.charge(): the validated SDN
// name dataset must be loadable and within its freshness window, or the caller
// gets 503 and no payment is requested. The dataset judged usable here is
// pinned for the handler, which screens against exactly it.
const ofacNameDatasetGate: MiddlewareHandler = async (c, next) => {
  try {
    c.set('ofacNameDataset' as never, (await loadSdnIndex()) as never)
  } catch (err) {
    if (!(err instanceof OfacUpstreamError)) throw err
    c.header('Retry-After', '60')
    return c.json(
      {
        error: 'ofac_name_screening_unavailable',
        detail: 'A validated, current OFAC SDN name dataset is not available. No payment was requested; no screening result (positive or negative) was produced.',
      },
      503
    )
  }
  await next()
}

function unsupportedAddressResponse(c: any, input: string) {
  return classifyAddress(input) === 'unsupported'
    ? c.json(invalidAddressBody(new InvalidWalletAddressError('unsupported_address_format', input)), 400)
    : null
}

// The paid result contract is: pay only if a successful signed result can
// actually be produced. Every paid route must confirm signing is enabled and
// active BEFORE mppx.charge() takes payment -- otherwise attest() throwing
// inside the handler means the caller already paid for a result they can
// never receive. Reuses the exact readiness check the free internal routes
// (/attest/ready, /internal/verdict/ready) already rely on; no parallel
// readiness system.
const requireSigningReadiness: MiddlewareHandler = async (c, next) => {
  if (!attestationEnabled() || !attestationSigningReady()) {
    c.header('Retry-After', '10')
    return c.json(
      {
        error: 'attestation service temporarily unavailable',
        detail: 'No payment was requested. Retry when signing readiness is restored.',
      },
      503
    )
  }
  await next()
}

// Cheap, side-effect-free request validation. These guards run before payment
// middleware so callers are never challenged or charged for malformed input.
const validateAddressOrEns: MiddlewareHandler = async (c, next) => {
  const input = c.req.param('address')?.trim() ?? ''
  const isAddress = /^0x[0-9a-fA-F]{40}$/.test(input)
  if ((!isAddress && !looksLikeEns(input)) || input.length > 255) {
    return unsupportedAddressResponse(c, input) ?? c.json({ error: 'invalid address or ENS name parameter' }, 400)
  }
  await next()
}

const validateNameScreenQuery: MiddlewareHandler = async (c, next) => {
  const name = c.req.query('name')?.trim() ?? ''
  if (name.length < 2 || name.length > 200) {
    return c.json({ error: 'provide ?name= with 2 to 200 characters' }, 400)
  }
  const threshold = c.req.query('threshold')
  if (threshold !== undefined) {
    const parsed = Number(threshold)
    if (!Number.isFinite(parsed) || parsed < 0.5 || parsed > 1) {
      return c.json({ error: 'threshold must be a number between 0.5 and 1.0' }, 400)
    }
  }
  await next()
}

const validateCompanyNumber: MiddlewareHandler = async (c, next) => {
  const companyNumber = c.req.param('companyNumber')?.trim() ?? ''
  if (companyNumber.length < 1 || companyNumber.length > 20) {
    return c.json({ error: 'companyNumber must be 1 to 20 characters' }, 400)
  }
  await next()
}

const validateUsCompanyQuery: MiddlewareHandler = async (c, next) => {
  const query = c.req.query('q')?.trim() ?? ''
  if (query.length < 1 || query.length > 200) {
    return c.json({ error: 'provide ?q= with 1 to 200 characters' }, 400)
  }
  await next()
}

const validateDiligenceQuery: MiddlewareHandler = async (c, next) => {
  const wallet = c.req.query('wallet')?.trim()
  const company = c.req.query('company')?.trim()
  if (!wallet && !company) {
    return c.json(
      { error: 'provide at least one of: ?wallet=<address> or ?company=<company_number>' },
      400
    )
  }
  if (wallet) {
    const isAddress = /^0x[0-9a-fA-F]{40}$/.test(wallet)
    if ((!isAddress && !looksLikeEns(wallet)) || wallet.length > 255) {
      return unsupportedAddressResponse(c, wallet) ?? c.json({ error: 'invalid wallet address or ENS name' }, 400)
    }
  }
  if (company && company.length > 20) {
    return c.json({ error: 'company number must be at most 20 characters' }, 400)
  }
  await next()
}

const validateAnchorRequest: MiddlewareHandler = async (c, next) => {
  if (!anchoringEnabled()) {
    return c.json({ error: 'on-chain anchoring is not configured on this deployment' }, 503)
  }
  const declaredLength = Number(c.req.header('content-length') ?? '0')
  if (Number.isFinite(declaredLength) && declaredLength > 256 * 1024) {
    return c.json({ error: 'attestation envelope must be at most 256 KiB' }, 413)
  }

  let body: unknown
  try {
    // The verified envelope is stored on the context; no downstream handler
    // needs to re-read the request body. Reading the original stream avoids
    // the unresolved cloned-stream behaviour observed in Vercel's Node
    // adapter for malformed POST /anchor requests (OD-034).
    const rawBody = await c.req.text()
    if (Buffer.byteLength(rawBody, 'utf8') > 256 * 1024) {
      return c.json({ error: 'attestation envelope must be at most 256 KiB' }, 413)
    }
    body = JSON.parse(rawBody)
  } catch {
    return c.json({ error: 'expected a complete signed attestation envelope as JSON' }, 400)
  }

  const verification = verifyAttestationForAnchoring(body)
  if (!verification.valid) {
    return c.json({ error: verification.error }, verification.status)
  }
  c.set('verifiedAnchorAttestation', verification.attestation)
  await next()
}

const requireInternalAttestationAuth: MiddlewareHandler = async (c, next) => {
  const auth = authorizeInternalBearer(
    c.req.header('authorization'),
    config.attestation.serviceToken
  )
  if (auth === 'unconfigured') {
    return c.json({ error: 'internal attestation service is not configured' }, 503)
  }
  if (auth !== 'authorized') {
    c.header('WWW-Authenticate', 'Bearer realm="internal-attestation"')
    return c.json({ error: 'unauthorized' }, 401)
  }
  await next()
}

// ---------------------------------------------------------------------
// Route 1: Sanctions screening only
// ---------------------------------------------------------------------
app.get(
  '/screen/:address',
  rateLimit,
  validateAddressOrEns,
  sanctionsSnapshotGate,
  requireSigningReadiness,
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
          ...walletSanctionsAttribution(),
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
//   BLOCK — subject address sanctioned (hard legal line).
//   WARN  — direct sanctioned-counterparty exposure or incomplete exposure.
//   PASS  — subject clean and the bounded exposure check completed cleanly.
// The policy lives in verdict.ts and is reused by internal paid transports.
// ---------------------------------------------------------------------
app.get(
  '/verdict/:address',
  rateLimit,
  validateAddressOrEns,
  sanctionsSnapshotGate,
  requireSigningReadiness,
  mppx.charge({ amount: config.pricing.sanctionsCheck }),
  async (c) => {
    const input = c.req.param('address')
    if (!input || input.length < 7) {
      return c.json({ error: 'invalid address or ENS name parameter' }, 400)
    }

    try {
      return c.json(attest(await evaluateVerdict(input)))
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

app.get('/sandbox/attestation-sample', rateLimit, (c) => {
  return c.json(
    attest(
      {
        sandbox: true,
        fixture_id: 'verifier-sample-v1',
        not_a_screening_result: true,
        description:
          'Fixed cryptographic verification fixture. No real counterparty was screened and no upstream was queried.',
      },
      { purpose: ATTESTATION_FIXTURE_PURPOSE }
    )
  )
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
  validateNameScreenQuery,
  requireSigningReadiness,
  ofacNameDatasetGate,
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
      const result = await screenName(name, threshold, c.get('ofacNameDataset' as never))
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
  validateCompanyNumber,
  healthGate(companiesHouseHealthy, 'Companies House'),
  requireSigningReadiness,
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
  validateUsCompanyQuery,
  healthGate(edgarHealthy, 'SEC EDGAR'),
  requireSigningReadiness,
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
// the caller is actually about to use. Gating on sanctions data when the
// caller only asked for a company check (or vice-versa) would wrongly
// block a call that could have succeeded.
const diligenceHealthGate: MiddlewareHandler = async (c, next) => {
  const wantsWallet = !!c.req.query('wallet')
  const wantsCompany = !!c.req.query('company')

  // A requested wallet check needs usable sanctions data. Without it, refuse the
  // whole request before payment rather than charge for (and sign) a bundle with
  // a missing sanctions result. With it, the snapshot is pinned for the handler.
  let snapshot: LoadedSnapshot | null = null
  if (wantsWallet) {
    const loaded = await usableSnapshotOrResponse(c)
    if (loaded instanceof Response) return loaded
    snapshot = loaded
  }

  const checks: Array<Promise<{ name: string; ok: boolean }>> = []
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
  if (snapshot) return runWithPinnedSnapshot(snapshot, () => next())
  await next()
}

app.get(
  '/diligence',
  rateLimit,
  validateDiligenceQuery,
  diligenceHealthGate,
  requireSigningReadiness,
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
        ? { ...walletOutcome.value, ...walletSanctionsAttribution() }
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
  validateAddressOrEns,
  sanctionsSnapshotGate,
  requireSigningReadiness,
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
          ...walletSanctionsAttribution(),
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
  validateCompanyNumber,
  healthGate(companiesHouseHealthy, 'Companies House'),
  requireSigningReadiness,
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
  validateNameScreenQuery,
  requireSigningReadiness,
  ofacNameDatasetGate,
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
      const result = await screenName(name, threshold, c.get('ofacNameDataset' as never))
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
  validateUsCompanyQuery,
  healthGate(edgarHealthy, 'SEC EDGAR'),
  requireSigningReadiness,
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
// Route: /attest — authenticated internal attestation endpoint
//
// The signing key is a product root of trust. Only trusted backend services
// may submit results here; CORS alone is never authentication. The app's
// browser-side evidence export remains disabled until it has an authenticated
// backend that reconstructs evidence from authoritative stored records.
// ---------------------------------------------------------------------
app.get('/attest/ready', rateLimit, requireInternalAttestationAuth, (c) => {
  if (!attestationEnabled() || !attestationSigningReady()) {
    return c.json({ ready: false, error: 'attestation signer is not active' }, 503)
  }
  return c.json({ ready: true, key_id: getKeyId(), algorithm: 'ed25519' })
})

// MCP's paid verdict route probes this before presenting an x402 challenge.
// This confirms both the signing root and the verdict's mandatory sanctions
// provider are available. Counterparty exposure is enrichment and degrades to
// WARN, so it is deliberately not a readiness requirement.
app.get(
  '/internal/verdict/ready',
  rateLimit,
  requireInternalAttestationAuth,
  async (c) => {
    if (!attestationEnabled() || !attestationSigningReady()) {
      return c.json({ ready: false, error: 'attestation signer is not active' }, 503)
    }
    try {
      await loadUsableSnapshot()
    } catch (err) {
      const reason = err instanceof SanctionsUnavailableError ? err.reason : 'store_unavailable'
      return c.json({ ready: false, error: SANCTIONS_UNAVAILABLE_CODE, reason }, 503)
    }
    return c.json({ ready: true })
  }
)

// Canonical server-to-server verdict for paid transports such as MCP. The
// caller cannot submit arbitrary evidence: it supplies only an address/ENS,
// and this service performs the authoritative checks and decision itself.
app.get(
  '/internal/verdict/:address',
  rateLimit,
  requireInternalAttestationAuth,
  validateAddressOrEns,
  sanctionsSnapshotGate,
  async (c) => {
    if (!attestationEnabled() || !attestationSigningReady()) {
      return c.json({ error: 'attestation signer is not active' }, 503)
    }
    try {
      return c.json(attest(await evaluateVerdict(c.req.param('address'))))
    } catch (err) {
      if (err instanceof EnsResolutionError) return c.json({ error: err.message }, 400)
      return handleUpstreamError(c, err)
    }
  }
)

// ---------------------------------------------------------------------
// Route: POST /internal/sanctions/screen — Dashboard backend SDN lookup
//
// Free, UNSIGNED, server-to-server only. Lets the Dashboard show current
// OFAC SDN digital-currency-address results without buying a paid x402/MPP
// screen per graph node and without ever holding a signing credential. It uses
// the exact same validated, freshness-checked snapshot and matcher as the paid
// routes (walletSanctions.ts), pinned once per request so every address in a
// batch is screened against one snapshot. Stale/unavailable data is a 503,
// never a "not listed". The credential is SANCTIONS_SCREENING_SERVICE_TOKEN and
// is refused outright if it equals the attestation (signing) token.
// ---------------------------------------------------------------------
const MAX_INTERNAL_SCREEN_BATCH = 50

const requireInternalScreeningAuth: MiddlewareHandler = async (c, next) => {
  const token = config.sanctionsScreening.serviceToken
  // Never let the signing credential double as the screening credential.
  const configured = token.length >= 32 && token !== config.attestation.serviceToken ? token : ''
  const auth = authorizeInternalBearer(c.req.header('authorization'), configured)
  if (auth === 'unconfigured') {
    return c.json({ error: 'internal sanctions screening is not configured' }, 503)
  }
  if (auth !== 'authorized') {
    c.header('WWW-Authenticate', 'Bearer realm="internal-sanctions-screening"')
    return c.json({ error: 'unauthorized' }, 401)
  }
  await next()
}

app.post(
  '/internal/sanctions/screen',
  rateLimit,
  requireInternalScreeningAuth,
  async (c) => {
    let body: unknown
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'invalid JSON body' }, 400)
    }
    const addresses = (body as { addresses?: unknown })?.addresses
    if (!Array.isArray(addresses) || addresses.length === 0 || addresses.length > MAX_INTERNAL_SCREEN_BATCH) {
      return c.json({ error: `body must be { "addresses": [1..${MAX_INTERNAL_SCREEN_BATCH} strings] }` }, 400)
    }
    if (addresses.some((a) => typeof a !== 'string' || a.length > 128)) {
      return c.json({ error: 'every address must be a string of at most 128 characters' }, 400)
    }
    const snapshot = await usableSnapshotOrResponse(c)
    if (snapshot instanceof Response) return snapshot
    const results = (addresses as string[]).map((input) => {
      const kind = classifyAddress(input)
      if (kind !== 'evm') {
        return { address: input, status: kind === 'unsupported' ? 'unsupported_network' : 'invalid_address', matches: [] }
      }
      const r = screenEvmAddress(snapshot, input.trim())
      return {
        address: r.address.toLowerCase(),
        status: r.match_status,
        matches: r.matches.map((m) => ({ sdn_uid: m.sdn_uid, sdn_name: m.sdn_name, programs: m.programs, entry_url: m.entry_url })),
      }
    })
    const provenance = screenEvmAddress(snapshot, '0x0000000000000000000000000000000000000000').screening
    return c.json({
      signed: false,
      results,
      screening: provenance,
      notice: 'Unsigned internal lookup for display only. Not a signed attestation, not legal clearance.',
    })
  }
)

app.post('/attest', rateLimit, requireInternalAttestationAuth, async (c) => {
  if (!attestationEnabled() || !attestationSigningReady()) {
    return c.json(
      { error: 'attestation signer is not active' },
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
  // Optional purpose override, strictly allowlisted: a caller can never make
  // this endpoint sign under an arbitrary self-declared purpose string.
  // Omitted -> unchanged default behaviour (ATTESTATION_PURPOSE).
  const rawPurpose = (body as Record<string, unknown>)?.purpose
  if (rawPurpose !== undefined) {
    const allowedPurposes: unknown[] = [
      ATTESTATION_PURPOSE,
      ATTESTATION_RECEIPT_PURPOSE,
      ATTESTATION_ALLOWANCE_PURPOSE,
      'swap-action',
      ATTESTATION_BRIDGE_ACTION_PURPOSE,
      ATTESTATION_STAKING_ACTION_PURPOSE,
    ]
    if (!allowedPurposes.includes(rawPurpose)) {
      return c.json({ error: `purpose must be one of: ${allowedPurposes.join(', ')}` }, 400)
    }
  }
  const purpose = rawPurpose as
    | typeof ATTESTATION_PURPOSE
    | typeof ATTESTATION_RECEIPT_PURPOSE
    | typeof ATTESTATION_ALLOWANCE_PURPOSE
    | 'swap-action'
    | typeof ATTESTATION_BRIDGE_ACTION_PURPOSE
    | typeof ATTESTATION_STAKING_ACTION_PURPOSE
    | undefined
  const signed = attest(evidence as Record<string, unknown>, purpose ? { purpose } : {})
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
  if (err instanceof SanctionsUnavailableError) return err.message
  if (err instanceof InvalidWalletAddressError) return err.message
  if (err instanceof CompanyNotFoundError) return err.message
  if (err instanceof CompaniesHouseUpstreamError) return `Companies House error (status ${err.status})`
  return 'unexpected error during lookup'
}

function handleUpstreamError(c: any, err: unknown) {
  if (err instanceof SanctionsUnavailableError) return c.json(sanctionsUnavailableBody(err), 503)
  if (err instanceof InvalidWalletAddressError) return c.json(invalidAddressBody(err), 400)
  if (err instanceof CompanyNotFoundError) {
    return c.json({ error: err.message }, 404)
  }
  if (err instanceof OfacNameScreeningUnavailableError) {
    return c.json({ error: 'ofac_name_screening_unavailable', detail: 'No validated, current OFAC SDN name dataset; no screening result was produced.' }, 503)
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
//   POST /anchor       body: complete signed envelope → verifies it, then
//                       records keccak256(signature)
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
      network: tempoNetworkLabel(),
      contract: config.anchor.contractAddress,
    })
  } catch (err) {
    return c.json({ error: describeError(err) }, 502)
  }
})

// Pre-payment readiness for /anchor specifically: anchoring itself needs the
// Tempo anchor wallet/RPC (anchoringEnabled()), separate from the Ed25519
// attestation signer (requireSigningReadiness) that signs this route's own
// response. Both must be healthy before payment, not just one.
const requireAnchoringReadiness: MiddlewareHandler = async (c, next) => {
  if (!anchoringEnabled()) {
    return c.json(
      { error: 'on-chain anchoring is not configured on this deployment' },
      503
    )
  }
  await next()
}

app.post(
  '/anchor',
  rateLimit,
  validateAnchorRequest,
  requireAnchoringReadiness,
  requireSigningReadiness,
  mppx.charge({ amount: config.pricing.nameScreen }),
  async (c) => {
    const verified = c.get('verifiedAnchorAttestation')
    try {
      const { anchorHash, txHash, alreadyAnchored } = await anchorSignature(verified.signature)
      return c.json(
        attest({
          anchor_hash: anchorHash,
          tx_hash: alreadyAnchored ? null : txHash,
          already_anchored: alreadyAnchored,
          chain: 'Tempo',
          network: tempoNetworkLabel(),
          contract: config.anchor.contractAddress,
          attestation_key_id: verified.keyId,
          attestation_key_status: verified.keyStatus,
          attestation_issued_at: verified.issuedAt,
          note: alreadyAnchored
            ? 'This verified OnchainDiligence attestation was already anchored; no new transaction was sent.'
            : 'Verified OnchainDiligence attestation hash anchored on Tempo. Anyone can check it via GET /anchored.',
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
  if (!attestationEnabled() || !attestationSigningReady()) {
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
    status: 'active',
    registry_url: '/.well-known/attestation-keys',
    verify_hint:
      'Resolve the attestation key_id through the registry. Version 2 uses RFC 8785 canonical JSON ' +
      'with explicit issuer and purpose; legacy version 1 uses JSON.stringify.',
  })
})

app.get('/.well-known/attestation-keys', (c) => {
  const keys = getAttestationKeyRecords()
  const readiness = getAttestationKeyRegistryReadiness()
  c.header('Cache-Control', 'public, max-age=300, stale-while-revalidate=3600')
  return c.json({
    registry_version: 1,
    issuer: ATTESTATION_ISSUER,
    active_key_id: getKeyId(),
    supported_attestation_versions: [ATTESTATION_SCHEMA_VERSION, 'legacy-v1'],
    strict_offline_verification_ready: readiness.strict_ready,
    trust_warnings: readiness.warnings,
    keys,
  })
})

app.get('/.well-known/attestation-keys/:keyId', (c) => {
  const requestedKeyId = c.req.param('keyId')
  if (!/^ed25519-[A-Za-z0-9_-]{16}$/.test(requestedKeyId)) {
    return c.json({ error: 'invalid attestation key id' }, 400)
  }
  const record = getAttestationKeyRecord(requestedKeyId)
  if (!record) return c.json({ error: 'attestation key not found' }, 404)
  c.header('Cache-Control', 'public, max-age=300, stale-while-revalidate=3600')
  return c.json({
    registry_version: 1,
    issuer: ATTESTATION_ISSUER,
    attestation_purpose: ATTESTATION_PURPOSE,
    key: record,
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
  const [sanctionsData, companiesHouseOk, edgarOk] = await Promise.all([
    sanctionsDataStatus(),
    companiesHouseHealthy().catch(() => false),
    edgarHealthy().catch(() => false),
  ])
  const signingConfigured = attestationEnabled()

  // Upstreams determine readiness. Signing being off is a degraded state for
  // a compliance tool (results would be unsigned), so we surface it — but we
  // don't 503 purely on signing, since checks still return correct data.
  const upstreamsHealthy = sanctionsData.status === 'current' && companiesHouseOk && edgarOk
  const status = upstreamsHealthy ? 'ok' : 'degraded'

  if (!upstreamsHealthy) c.header('Retry-After', '30')

  return c.json(
    {
      status,
      checked_at: new Date().toISOString(),
      upstreams: {
        // The Chainalysis oracle is retired permanently; wallet screening uses
        // the OFAC SDN snapshot reported in ofac_sdn / sanctions_data.
        sanctions_oracle: 'retired',
        ofac_sdn: sanctionsData.status,
        companies_house: companiesHouseOk ? 'reachable' : 'unreachable',
        sec_edgar: edgarOk ? 'reachable' : 'unreachable',
      },
      sanctions_data: sanctionsData,
      attestation: signingConfigured ? 'configured' : 'not_configured',
    },
    upstreamsHealthy ? 200 : 503
  )
})

app.get('/', (c) =>
  c.json({
    service: config.service.title,
    routes: {
      'GET /screen/:address': `Exact OFAC SDN digital-currency-address match for an EVM address (503 before payment if the snapshot is not current) — $${config.pricing.sanctionsCheck}`,
      'GET /verdict/:address': `Unified signed PASS/WARN/BLOCK counterparty verdict on the same OFAC SDN data — $${config.pricing.sanctionsCheck}`,
      'GET /screen-name?name=': `OFAC SDN name screening — $${config.pricing.nameScreen}`,
      'GET /company/:companyNumber': `UK company check only — $${config.pricing.companyCheck}`,
      'GET /us-company?q=': `US public company check (SEC EDGAR) — $${config.pricing.usCompanyCheck}`,
      'POST /attest': 'Internal authenticated result-signing service',
      'POST /anchor': `Anchor an attestation on Tempo — $${config.pricing.nameScreen}`,
      'GET /anchored?signature=': 'Check if an attestation is anchored on-chain — free',
      'GET /diligence?wallet=&company=': `Combined check (wallet= needs a current OFAC SDN snapshot; 503 before payment otherwise) — $${config.pricing.combinedDiligence}`,
    },
    health_url: '/health',
    attestation: {
      enabled: attestationEnabled(),
      public_key_url: '/.well-known/attestation-key',
      key_registry_url: '/.well-known/attestation-keys',
      schema_version: ATTESTATION_SCHEMA_VERSION,
    },
    note: 'See /openapi.json for machine-readable discovery, or README.md for full docs.',
  })
)

export default app
