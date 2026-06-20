# Compliance Diligence Suite

A pay-per-call API that does two compliance checks — **crypto sanctions
screening** and **UK company verification** — either separately or
bundled, with payment collected per request via the **Machine Payments
Protocol (MPP)** on **Tempo**.

It's built so an AI agent (or a human script, or another service) can ask
"is this wallet sanctioned?" and "is this UK company real and who controls
it?" and pay a few cents per answer, with no account, subscription, or
sales conversation.

---

## What it actually checks (and what it does NOT)

This product answers narrow factual questions and is deliberately honest
about their limits. Read this section before doing anything else.

**Sanctions check** (`/screen`) — takes a crypto address, asks
Chainalysis's free sanctions API whether it's on a sanctions list (OFAC
SDN etc.). Address in, yes/no + details out. It knows nothing about who
owns the address or what they do.

**Company check** (`/company`) — takes a UK company number, returns the
company's status (active/dissolved/liquidation), basic profile, and —
importantly — its **PSC data** (People with Significant Control: who
actually owns/controls the company). It knows nothing about crypto.

**The critical limitation of the combined check** (`/diligence`): it runs
both checks, but **it does not and cannot establish that a given wallet
belongs to a given company.** That link doesn't exist in either data
source — companies don't register their wallets with the government, and
Chainalysis doesn't map addresses to company numbers. Two "clean" results
mean "this address isn't sanctioned" AND "this company is real" — NOT
"this verified company controls this wallet." Every `/diligence` response
says this explicitly in a `link_disclaimer` field. Don't remove it.

This is a **compliance utility**, not a compliance program, and not legal
advice. It's one input a real diligence process could use, not a
replacement for one.

---

## Routes

| Route | What it does | Price |
|-------|--------------|-------|
| `GET /` | Service info, incl. attestation status (free) | free |
| `GET /screen/:address` | Sanctions check only | $0.01 |
| `GET /company/:companyNumber` | UK company check only | $0.01 |
| `GET /diligence?wallet=&company=` | Both, bundled (either param optional) | $0.015 |
| `GET /openapi.json` | Machine-readable discovery (free) | free |
| `GET /.well-known/attestation-key` | Public key for verifying signatures (free) | free |

The two single-purpose routes are $0.01 each; the bundle is $0.015 (a
small discount vs. paying for both separately).

There are also **three MCP tools** (`screen_wallet`, `verify_uk_company`,
`diligence`) exposing the same checks to AI agent frameworks — see the MCP
section below.

---

## Cryptographic attestation (signed responses)

Every paid response is wrapped in a **signed attestation**, so the caller
has verifiable evidence — not just a JSON blob they could have faked.

```jsonc
{
  "data": { "address": "0x…", "sanctioned": false, "checked_at": "…" },
  "attestation": {
    "signed": true,
    "issued_at": "2026-06-18T…Z",
    "key_id": "ed25519-…",
    "algorithm": "ed25519",
    "signature": "…base64url…",
    "signing_input_hint": "signature is over JSON.stringify({ data, issued_at, key_id }) …"
  }
}
```

**Why this matters (the compliance point):** if an operator transacted
because this service said a wallet was clean, an auditor will later ask
them to *prove* they checked. The signature lets them prove
"nanoscreen attested this wallet was clean at this exact moment," and
anyone can verify it against the public key at
`/.well-known/attestation-key` — without contacting the service. Tampering
with the data invalidates the signature.

**To verify a stored attestation** (Node example):

```js
import crypto from 'node:crypto'
const signingInput = JSON.stringify({
  data: envelope.data,
  issued_at: envelope.attestation.issued_at,
  key_id: envelope.attestation.key_id,
})
const pub = crypto.createPublicKey(fetchedPublicKeyPem)
const ok = crypto.verify(null, Buffer.from(signingInput), pub,
  Buffer.from(envelope.attestation.signature, 'base64url'))
```

**Setup:** set `ATTESTATION_PRIVATE_KEY` (Ed25519 PKCS8 PEM) — see
`.env.example` for the one-line generator. If it's unset, the service
still runs but returns responses flagged `"signed": false`, so callers are
never misled into treating an unsigned response as evidence. **Set it for
production.**

---

## MCP (Model Context Protocol) front door

The same three checks are exposed as **MCP tools**, so agent frameworks
(Claude Desktop, IDE agents, custom MCP clients) can discover and call them
without a developer hand-writing HTTP requests.

This is **not a second product** — it's a second front door to the same
paid checks. MCP is the discovery/invocation layer; MPP is still the
payment layer. Payment flows through the *same* 402 challenge-response,
just carried over MCP's JSON-RPC metadata instead of HTTP headers. The
tool handlers reuse the exact same `chainalysis.ts` / `companiesHouse.ts`
logic and the same attestation, so there's one source of truth.

Tools: `screen_wallet`, `verify_uk_company`, `diligence`.

**Run the MCP server (stdio transport):**

```bash
npm run mcp
```

Then point an MCP client at it. For Claude Desktop, add to its MCP config
(adjust the path):

```jsonc
{
  "mcpServers": {
    "nanoscreen": { "command": "npx", "args": ["tsx", "src/mcp.ts"] }
  }
}
```

**Limitation:** this runs over **stdio**, the standard local-MCP transport.
MCP also supports streamable-HTTP for remote servers; wiring that is a
larger job and is left as a follow-up. (Over stdio, payment logs go to
**stderr** so they don't corrupt the JSON-RPC stream on stdout.)

---

## Setup

### 1. Get the one free API key (you must do this — it needs your details)

- **Companies House API** — register at
  https://developer.company-information.service.gov.uk , then register an
  "application" (live environment) to get a REST key. Free, UK government
  open data. This is the only key the service needs.

That's it for keys. **Sanctions screening needs no key at all** — it uses
the Chainalysis on-chain sanctions oracle, a public smart contract that, in
Chainalysis's words, "is available for anyone to use and does not require a
customer relationship with Chainalysis." The service reads it on Ethereum
mainnet via a public RPC (overridable; see `.env.example`). Same US/EU/UN
sanctions data as their paid API, zero gatekeeping.

### 2. Get a Tempo wallet

You need a wallet address to receive payments. See
https://docs.tempo.xyz for wallet setup.

### 3. Configure

```bash
cp .env.example .env
# then edit .env and fill in all four values
```

### 4. Install and run

```bash
npm install
npm run dev      # starts on http://localhost:3000
```

### 5. Verify it's working

```bash
curl http://localhost:3000/                    # service info
curl -i http://localhost:3000/screen/0xabc...  # should return HTTP 402
```

A `402 Payment Required` with a `WWW-Authenticate: Payment` header is the
**correct** response to an unpaid request — it's the payment challenge,
not an error.

---

## Testing

### Logic tests (no keys, no network, no payment needed)

```bash
npm test
```

This runs `test/smoke.ts`, which mocks the upstream APIs and checks the
parsing, error handling, and PSC-handling logic. 7 tests; all should pass.

### Testing real paid calls

Use the mppx CLI to inspect the payment challenge without paying:

```bash
npx mppx --inspect http://localhost:3000/screen/0xabc...
```

To make a real paid call, you'll need a funded Tempo account. See
**DEPLOY.md** for the full mainnet deployment + first-paid-call walkthrough.

---

## Before you deploy — IMPORTANT

**For full deploy steps, see `DEPLOY.md`.** The essentials:

**You must supply the mainnet currency address.** The code ships with NO
currency address and reads it from the `TEMPO_CURRENCY_ADDRESS` env var.
On mainnet this must be the live-mode pathUSD/USDC token address from your
Stripe Dashboard ("Run live mode transactions" section). The address
`0x20c0…0000` seen in most MPP examples is the **testnet** token and does
not exist on mainnet — the server is built to **refuse to start** if it
detects that token while `TEMPO_TESTNET` is not `true`, so you cannot
deploy this misconfiguration by accident.

**Network is explicit, not defaulted.** `TEMPO_TESTNET` drives it —
`false` for mainnet (confirmed chain ID 4217). This is passed explicitly
to the SDK rather than relying on its default.

**Verify the upstream response shapes against real keys.** The field
names this code reads (Chainalysis `identifications`, Companies House
`company_status` / PSC `natures_of_control`, etc.) are based on those
APIs' documented formats. Once you have real keys, make one real call to
each and confirm the response shapes match — API responses sometimes
drift from their docs. The mocked tests prove the *logic* is right, not
that the *field names* still match production.

---

## Licensing & pricing rationale (read before changing the price)

The two data sources sit in **different legal positions**, and the design
respects both:

**Companies House** is UK government open data, free for commercial use
with no resale restriction. No issue here. The only caveat is
operational: it's a free service with no SLA, so expect occasional
downtime.

**Chainalysis** built its sanctions API as a **free public-good tool** for
the crypto ecosystem (DEXs, DeFi, DAOs, dapp developers) — but its
Acceptable Use Policy still prohibits **reselling** the data "on a service
bureau basis" and prohibits **caching** results. To stay on the right side
of that:

- **The fee is framed and priced as an infrastructure/anti-spam cost, not
  a markup on Chainalysis's data.** That's why it's $0.01, not $0.50.
- **Nothing is ever cached.** Every call hits the upstream API live. There
  is no database. Do not add one for results.
- **Every response carries attribution** naming Chainalysis as the source
  and stating the fee covers infra only.

If you ever want to take this to meaningful volume or represent it as a
compliance product, **get an actual reseller/partner agreement with
Chainalysis first.** This README is not legal advice — it's a description
of the design choices made to stay inside the documented free-tier intent.

---

## Architecture

```
src/
  config.ts          — all env vars, prices, endpoints; validates at boot
  chainalysis.ts     — sanctions screening via on-chain oracle (no key)
  companiesHouse.ts  — company profile + PSC client
  rateLimit.ts       — per-caller rate limiting (pre-payment)
  health.ts          — upstream circuit breaker (open/half-open/closed)
  attestation.ts     — Ed25519 signing of every response
  paymentLog.ts      — logs every settled / failed payment (to stderr)
  server.ts          — HTTP routes + guards + MPP gating + discovery
  mcp.ts             — MCP server (stdio): same checks as MCP tools
  index.ts           — Node HTTP entrypoint (loads .env, starts listener)
api/
  index.ts           — Vercel serverless entrypoint (same app)
test/
  smoke.ts           — logic + rate-limiter + circuit-breaker + attestation tests
```

The HTTP API (`server.ts` / `index.ts` / `api/index.ts`) and the MCP
server (`mcp.ts`) are two front doors to the same check logic. Both gate
on MPP payment; both return the same signed attestations.

`server.ts` exports the bare Hono `app`, so it can also be deployed to
edge runtimes (Cloudflare Workers etc.). `src/index.ts` runs it under
plain Node; `api/index.ts` runs it on Vercel.

**Middleware order per paid route (this ordering is the point):**

```
rateLimit  →  healthGate  →  mppx.charge  →  handler
```

1. **rateLimit** — caps requests per caller BEFORE anything else, so one
   hot caller can't burn the shared free-tier upstream budget. Returns
   429 + `Retry-After`.
2. **healthGate** — backed by a **circuit breaker**: after repeated
   upstream failures it "trips" and fails fast (503) for a cooldown without
   probing, then tests recovery with a single trial probe (half-open)
   before closing again. Returns 503 BEFORE payment is requested, so the
   agent isn't charged for a call we already know will fail.
3. **mppx.charge** — issues the 402 / verifies the credential. Note this
   fires before the handler's own input validation, which is correct: a
   caller shouldn't probe inputs for free.
4. **handler** — runs the actual lookup.

---

## Payment failure handling & refund policy (important, read this)

In the Tempo charge model, **the agent's payment settles on-chain before
our server verifies it** — the credential they send is proof of an
already-broadcast transaction. There is no "authorize now, capture later"
step we control, and therefore **no way to verify-but-not-settle and abort
afterward**. The mppx SDK fuses verification and settlement into one step
(`verifyCredential`); there is no separate `settle()` method. (If you've
seen a "deferred settlement" pattern suggested elsewhere that calls
`mppx.settle()` / `mppx.generateChallengeHeader()` — those methods do not
exist in this SDK. The pattern can't be implemented as written.)

Given that, the failure window is: payment settles, then an upstream call
fails (e.g. Companies House 502, or a Vercel timeout) → the agent paid and
got an error. We handle this in three layers, in order of how much they
help:

1. **Health gate (prevention).** We don't issue a 402 at all if the needed
   upstream is already known-down. Closes the most common case.
2. **Rate limiting (prevention).** Stops the runaway-loop case that would
   otherwise trigger upstream 429s mid-flight.
3. **`/diligence` partial success (mitigation).** If one of the two
   sources fails, the other still returns and the caller gets value for
   their payment. Only if *all* requested sources are down do we 503
   before payment.

**Residual risk we explicitly accept at launch:** an upstream that dies
*mid-request, after* payment has settled. In that case the agent paid
~$0.01–0.015 for an error. **We do NOT auto-refund this at launch** — at
penny-scale per call, building refund infrastructure (which requires
extracting the payer address from the credential, a funded refund wallet,
and double-refund guards) is disproportionate. Instead, **every payment is
logged** (`paymentLog.ts`, via the SDK's `onPaymentSuccess` /
`onPaymentFailed` hooks) so there's a durable record for manual or
automated refunds later if traffic ever justifies it. This no-auto-refund
policy is disclosed in the service's responses/docs so callers know it up
front.

This is a deliberate, disclosed tradeoff — not an oversight.

---

## Known limitations

- **Sanctions = match flag only, not a risk score.** The on-chain oracle
  answers one boolean: is this address on US/EU/UN sanctions lists? It does
  NOT do general risk scoring, exposure analysis, or transaction monitoring
  (those are paid Chainalysis products). It also returns only a flag, not
  the specific designation details. Don't oversell what `/screen` returns.
- **Oracle freshness & accuracy are Chainalysis's.** Chainalysis maintains
  the oracle and updates it for new designations, but their docs state they
  "cannot guarantee the accuracy, timeliness, suitability, or validity of
  the data." That's fine for a factual-relay tool, and it's disclosed in
  the response attribution — but it's why the product never claims to be a
  complete compliance program.
- **Sanctions read depends on an Ethereum RPC.** The oracle isn't on Tempo,
  so the check reads it on Ethereum mainnet via a public RPC. The default
  public RPC is fine for low volume; under real load, set
  `SANCTIONS_ORACLE_RPC_URL` to a dedicated RPC (Alchemy/Infura/etc.) so
  you're not throttled. RPC failures are handled by the health gate +
  no-auto-refund disclosure, same as any upstream.
- **UK only.** Company verification is Companies House — UK companies
  only. No US, EU, or other jurisdictions.
- **Companies House rate limit.** Companies House publishes its own limit
  (confirm the current figure in their developer docs rather than trusting
  any single source, including this README). Our per-caller limiter
  (default 30/min) sits below it to protect the shared budget.
- **Rate limiter & circuit breaker are single-instance.** Both are
  in-memory, so on Vercel (many ephemeral instances) the rate-limit cap is
  effectively per-instance and breaker state isn't shared, and both reset
  on cold starts. They're genuine safety valves, NOT hard global
  guarantees. For hard global behavior, back them with a shared store
  (e.g. Upstash Redis) — noted as a fast-follow.
- **No auto-refund on post-payment upstream failure** — see the payment
  failure section above. Logged, not refunded, at launch.
- **MCP runs over stdio only.** Remote/streamable-HTTP MCP transport is a
  follow-up, so the MCP front door is best for local agent setups today.
- **Attestation uses a single signing key.** `key_id` supports future
  rotation, but there's no automated rotation flow yet; rotating means
  generating a new key and updating the env var (old attestations remain
  verifiable only if you keep publishing the old public key).
- **Demand is unproven.** The MPP ecosystem is new (Tempo mainnet went
  live March 2026). This fills a real gap in the services directory, but
  whether agents will actually call it at volume is not yet known. Build
  it because it's a genuine, shippable, portfolio-worthy artifact — not
  on the assumption of guaranteed revenue.

---

## Deploying & getting discovered

1. Deploy anywhere Fetch-API compatible (Cloudflare Workers, Railway,
   Fly, a VPS — your call).
2. Confirm `GET /openapi.json` resolves on the deployed URL — that's what
   discovery tooling and agent registries read.
3. List the service at https://mpp.dev/services and/or on MPPScan so
   agents can find it.
```
