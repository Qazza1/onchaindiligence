# OnChainDiligence product and technical audit — 2026-09-28

Status: **audit snapshot**, not a permanent product specification. It records
what was verifiable on 2026-09-28 and the recommendations drawn from it.
`PRODUCT_ROADMAP.md` is the living plan.

Scope: default branches of the four named repositories, plus the CLI and app
where a capability depends on them. No product code, schema, SDK API, MCP tool,
website code, package version or deployment configuration was changed. Every
live check was a read: GET requests, read-only JSON-RPC calls, and MCP
`initialize`/`tools/list`. No payment, receipt, submission, listing or message
was created.

## Evidence baseline

| Repository | Default-branch head audited | Latest production deployment (GitHub deployments API) |
|---|---|---|
| `Qazza1/onchaindiligence` (core, HTTP API, specs, packages) | `9ed3853` (2026-09-27) | `9ed3853`, 2026-09-27 |
| `Qazza1/onchaindiligence-mcp` (MCP, commerce lifecycle, receipts) | `22931ba` (2026-09-27) | `22931ba`, 2026-09-27 |
| `Qazza1/onchaindiligence-sdk` | `89cbcc6` (2026-09-26) | npm `@onchaindiligence/sdk@0.8.0` (2026-09-26) |
| `Qazza1/onchaindiligence-site` | `5c2eaec` (2026-09-27) | `5c2eaec`, 2026-09-27 |
| `Qazza1/onchaindiligence-cli` | `92288a9` (2026-09-14) | npm `@onchaindiligence/cli@0.4.0` (2026-09-14) |

Published packages checked on the npm registry (2026-09-28):

- `@onchaindiligence/agent-evidence@0.5.0`, published 2026-09-27;
- `@onchaindiligence/sdk@0.8.0`, published 2026-09-26;
- `@onchaindiligence/cli@0.4.0`, published 2026-09-14.

The Python package `onchaindiligence-agent-evidence` (`python/pyproject.toml`,
version `0.1.0`) is **not on PyPI** (the PyPI JSON API returns 404). It installs
from the repository only.

Public MCP and live telemetry (read-only, 2026-09-28):

- **Public MCP.** `POST https://mcp.onchaindiligence.com/public/mcp` `tools/list`
  returns exactly `inspect_payment`, `get_receipt` and `verify_receipt`. All
  three carry `title`, `readOnlyHint: true`, `destructiveHint: false` and
  `openWorldHint: false`.
- **Paid MCP.** `POST https://mcp.onchaindiligence.com/mcp` `tools/list` returns
  **21** tools: 5 evidence-provider tools, `preflight_payment`, 12
  allowance/swap/bridge/staking inspect/preflight/observe tools, and the 3 free
  tools.
- **Activity, 7-day window.** `GET https://mcp.onchaindiligence.com/public/activity?window=7d`
  (telemetry since 2026-09-18):

  | Metric | 7-day value |
  |---|---|
  | Sessions | 4,136 (108 public, 4,028 paid-surface) |
  | Tool calls | 144 |
  | Successful tool calls | 8 |
  | x402 challenges | 566 |
  | Receipts | 1 |
  | `completed_paid_executions` | `null` (not measured) |

  The largest named clients are MCP directories, crawlers and discovery probes:
  Glimind, MCPDD, Glama, MCPBeat, RokMCP and others.
- **Trust canary.** The scheduled `production-canary` workflow in the core repo
  passed three times between 2026-09-27 and 2026-09-28. It includes
  `internal-attest-rejects`: `POST /attest` without the internal bearer returns
  401/503.
- **Key registry.** `GET https://api.onchaindiligence.com/.well-known/attestation-keys`
  shows active key `ed25519-P2jIwhCn-Af6pTz4`, valid from 2026-09-03, and
  `strict_offline_verification_ready: false`, because retired key
  `ed25519-D8wfc7civVNG05Ds` has no `valid_from`.

## 1. Executive summary

1. **Build maturity is high, and external adoption has not been demonstrated.**
   Every default branch is deployed to production.
   - The public MCP is correct and live.
   - Discovery traffic is real: about 4.1k MCP sessions in 7 days, mostly from
     directories and crawlers.
   - Conversion is not demonstrated: 8 successful tool calls, 1 receipt, and
     no measured paid execution in that window.
   - No external pilot, partner or customer is evidenced in any repository.
2. **Several "COMPLETE / LIVE" labels in the 2026-09-16 roadmap overstate
   activation.** The Turnkey, Crossmint, CDP and Circle provider-evidence
   adapters (D3.4C3–C6) and the matching SDK executors are code-complete and
   deployed. No repository records a real delivery or live reference payment
   through any of them. The site itself says a live reference payment through
   PayBox "has not yet run." They should read *deployed, not activated*.
3. **Material work shipped since 2026-09-16 is missing from the roadmap:**
   - Signed Payment Claim v1 (published) and its production ingestion
     (deployed, fail-closed);
   - observation-only receipts (`POST /observe-payment`);
   - SDK 0.8.0 (`withOcd` x402 wrapper);
   - the Technocore provenance, explorer, attribution and leaderboard milestones
     D5.1–D5.5;
   - the `/live` activity dashboard and public activity telemetry;
   - Claude-compatible public tool schemas;
   - the site accuracy pass and SEO structured data.
4. **Two blockers have moved:**
   - **Arc:** official Arc docs now publish **mainnet ERC-8004** registry
     addresses, verified on-chain today, and a mainnet explorer. ERC-8183 mainnet
     is still unpublished.
   - **Claude:** the Claude Connectors Directory now accepts remote,
     no-authentication MCP servers from any paid Claude plan. The existing
     public MCP already meets its annotation requirements.
5. **The cheapest distribution gap is stale metadata.** The official MCP
   Registry entry `com.onchaindiligence/compliance` is active but still
   describes the pre-pivot "pay-per-call compliance" product. It advertises only
   the paid `/mcp` endpoint. It is the source Glama and other directories
   import from, and the telemetry shows those same directories are the main
   traffic source.
6. **The Turnkey opportunity is well matched to existing code.** An independently
   built `TurnkeyCommerceExecutor` and a Turnkey signed-webhook ingestion route
   already exist and are deployed. The smallest credible step is one live,
   public, end-to-end reference run: OCD preflight → Turnkey policy/sign/send →
   Turnkey-signed status claim → OCD independent Base observation → reconciled
   receipt. No new product surface is required.

## 2. Current inventory

Legend:

- **LIVE / COMPLETE**: deployed and working as described.
- **LIVE BUT LIMITED**: deployed, with a material scope or activation limit.
- **IMPLEMENTED BUT NOT ACTIVATED**: code complete and deployed, but not
  exercised with a real external counterparty.
- **BLOCKED**: an external dependency prevents it.
- **WATCH**: no build until an external trigger.
- **DEPRECATED / SUPERSEDED**.

Columns: Code = code complete; Deployed = in production; Activated = exercised
with real counterparties or configuration; Adopted = used by an external party.

### Payment evidence core

| Capability | Status | Code | Deployed | Activated | Adopted | Evidence |
|---|---|---|---|---|---|---|
| Payment inspection (`inspect_payment`, free) | LIVE / COMPLETE | ✓ | ✓ | ✓ | not evidenced | `mcp/src/publicMcp.ts`, `src/preflight.ts`; live `tools/list` 2026-09-28 |
| Payment preflight (`preflight_payment`, $0.01 x402) | LIVE BUT LIMITED | ✓ | ✓ | ✓ | not evidenced | `mcp/src/server.ts`, `docs/PAYMENT_PREFLIGHT.md`. `completed_paid_executions` is not measured (`/public/activity`) |
| Public Action Receipts (signed, content-addressed; `get_receipt`, `verify_receipt`, `/r/:id` explorer) | LIVE / COMPLETE | ✓ | ✓ | ✓ | 1 receipt in 7d | `mcp/src/receiptTools.ts`, `core/docs/PUBLIC_ACTION_RECEIPT_V1.md`, `site/receipt.html` |
| Observation-only receipt (`POST /observe-payment`) | LIVE BUT LIMITED | ✓ | ✓ (`3d08ba4`, PR #12, 2026-09-26) | ✓ | not evidenced | `mcp/src/observePaymentRoute.ts`, `src/observationOnlyReceipt.ts`, `site/llms.txt`, `developers.html`, `docs.html`. Free, unauthenticated, decision `UNKNOWN`, unlisted (not private), dedupe on (network, tx), per-instance best-effort rate limit. No site form; the SDK only reaches it through the `withOcd` `onOcdUnavailable: 'proceed'` fallback (`sdk/src/commerce/withOcd.ts:208`) |
| Commerce lifecycle (open → preflight → execute → observe/finalize) | LIVE BUT LIMITED | ✓ | ✓ | OCD-as-seller only | not evidenced | `mcp/src/commerceLifecycle.ts`, `docs/COMMERCE_RECEIPTS.md` §"First real Commerce Receipt" (OCD was both seller and issuer; a third-party follow-up is still owed) |
| Offline verification (D4.1) | LIVE / COMPLETE | ✓ | npm | ✓ | not evidenced | `agent-evidence@0.5.0`, `cli@0.4.0`. Caveat: `strict_offline_verification_ready: false` (retired key lacks `valid_from`; owner decision, `docs/MIGRATION_PLAN.md` P0 item 4) |
| Signed Evidence Bundles (D4.2) | LIVE / COMPLETE | ✓ | npm + `/verify` | ✓ | not evidenced | `core/packages/agent-evidence`, `site/verify.html` |
| Signed Payment Claim v1, Phase 1 (portable format, TS + Python verifiers) | LIVE / COMPLETE (published) | ✓ | npm `0.5.0` 2026-09-27 | n/a (portable) | not evidenced | `core/docs/SIGNED_PAYMENT_CLAIM_V1.md`, `spec/.../signed-claim-payment.v1.schema.json`, `python/.../payment_claims.py`, core PRs #11/#12 |
| Signed Payment Claim, Phase 2 (server ingestion) | IMPLEMENTED BUT NOT ACTIVATED | ✓ | ✓ (MCP PR #14, 2026-09-27) | ✗, fails closed | ✗ | `mcp/src/signedPaymentClaimEvidence.ts`: throws `signed payment claim trust is not configured` unless `SIGNED_PAYMENT_CLAIM_TRUST_JSON` holds an explicit issuer→key binding. That the production variable is unset is the founder's statement; this audit did not read deployment env |
| Browser verification (bundles, attestations, receipts) | LIVE / COMPLETE | ✓ | ✓ | ✓ | ArcFX handoff | `site/verify.html`, `receipt.html` |
| HTTP compliance API (sanctions, OFAC, Companies House, EDGAR, verdict, anchor) | LIVE / COMPLETE (evidence provider) | ✓ | ✓ | ✓ | not evidenced | `core/README.md`, `api/health` 200 |
| Accounts, workspaces, API keys, outbound webhooks, operation history, investigation export | LIVE BUT LIMITED | ✓ | ✓ | ✓ | not evidenced | `mcp/src/accounts.ts`, `workspaceRoute.ts`, `webhookRoute.ts`, `accountHistoryRoute.ts`, `savedReceiptsRoute.ts`; app `src/components/History.jsx`, `src/lib/webhooks.js` |

### Settlement observation

| Network | Status | Evidence |
|---|---|---|
| Base (`eip155:8453`, USDC) | LIVE / COMPLETE | `mcp/src/settlementNetworks.ts` |
| Ethereum (`eip155:1`, USDC, finalized head) | LIVE / COMPLETE | `settlementNetworks.ts`; roadmap D3.5C1 record |
| Tempo (`eip155:4217`, pathUSD TIP-20) | LIVE / COMPLETE | `settlementNetworks.ts`; D3.5C2 record |
| Solana (`solana:mainnet`, USDC SPL, finalized) | LIVE BUT LIMITED (cannot claim `PAYMENT_IDENTITY_LINKED`) | `mcp/src/solanaSettlement.ts` |
| Arc (`eip155:5042`) | BLOCKED / NOT IMPLEMENTED (see §3.7) | `settlementNetworks.ts` has no Arc entry. `src/arc/config.ts` mainnet mode requires all four ERC-8004/8183 addresses; `src/arc` is not imported by production code |

### Provider and executor evidence

| Provider | Status | Evidence and caveat |
|---|---|---|
| x402 (paid MCP v1 rail; `/x402/*` HTTP v2 routes; Bazaar metadata) | LIVE BUT LIMITED | `mcp/src/server.ts`, `discovery.ts`, `docs/MCP_X402_MIGRATION.md` (MCP rail still x402 v1). 566 challenges and 8 successful tool calls in 7 days. SDK `withOcd` supports x402 v2 `exact` only |
| PayBox | LIVE BUT LIMITED; live-reference status inconsistent | `sdk/src/commerce/payboxExecutor.ts`, `mcp/src/providerEvidence.ts`. `site/integrations.html` says a live reference payment through the adapter "has not yet run". `mcp/docs/FIRST_PILOT_PACKAGE.md` says PayBox is proved "end-to-end" (D2.6). Resolve before a pilot conversation |
| Turnkey | IMPLEMENTED BUT NOT ACTIVATED | `sdk/src/commerce/turnkeyExecutor.ts`, `mcp/src/turnkeyWebhookRoute.ts` + `turnkeyWebhookVerification.ts` (Ed25519, public JWKS). No recorded real delivery. No partnership |
| Crossmint | IMPLEMENTED BUT NOT ACTIVATED | `crossmintExecutor.ts`, `crossmintWebhookRoute.ts` |
| Coinbase CDP | IMPLEMENTED BUT NOT ACTIVATED | `cdpExecutor.ts` (caller-reported claim path; CDP has no wallet webhook) |
| Circle Developer-Controlled Wallets | IMPLEMENTED BUT NOT ACTIVATED | `circleExecutor.ts`, `circleWebhookRoute.ts`. The 2026-09-16 roadmap already said "awaiting the first organic outbound event" |

### Action evidence (paid MCP only)

| Action | Status | Scope |
|---|---|---|
| ERC-20 allowance / revocation (D3.6A) | LIVE BUT LIMITED | Base USDC; artifacts not stored in the operation ledger |
| Swaps (D3.6B) | LIVE BUT LIMITED | One Uniswap V3 `exactInputSingle` USDC→WETH profile |
| Bridge (D3.6C) | LIVE BUT LIMITED | Circle CCTP V2 Base→Ethereum |
| Staking (D3.6D) | LIVE BUT LIMITED | Lido |

None of these has a free/public or website demo surface. They are reachable only
through the 21-tool paid MCP.

### Agent Evidence and provenance

| Capability | Status | Evidence |
|---|---|---|
| Agent Evidence v0 protocol, schemas, conformance | LIVE / COMPLETE | `core/docs/AGENT_EVIDENCE_V0.md`, `spec/agent-evidence/v0/schema`, `conformance/` |
| TypeScript package | LIVE / COMPLETE | npm `@onchaindiligence/agent-evidence@0.5.0` |
| Python package | LIVE BUT LIMITED (repo install only; not on PyPI; `pyproject` says 0.1.0) | `core/python/` |
| Interoperability Profile v1 (`/.well-known/agent-evidence-keys`, trust-policy helpers) | LIVE BUT LIMITED (one integrator: ArcFX) | `core/docs/AGENT_EVIDENCE_INTEROP.md` |
| D5.1 operation-bound Technocore provenance | LIVE / COMPLETE | MCP PR #15 (`7360595`); `POST /operations/:operationId/agent-provenance` (`mcp/src/agentProvenanceRoute.ts`) |
| D5.2 portable provenance export | LIVE / COMPLETE | MCP PR #16 (`fad1412`) |
| D5.3 DID / Agent Provenance Explorer | LIVE / COMPLETE | MCP PR #19, site PR #5; `/agents` 200; `GET /public/technocore/agents/:did` |
| D5.4 verified competition attribution | LIVE BUT LIMITED | MCP PR #20, site PR #8. Organizer metadata is kept separate from signed DID evidence; the Close Call launch still reads as **not verified** (the official organizer repo is a draft) |
| D5.5 Close Call leaderboard | LIVE BUT LIMITED (provisional until launch verification) | MCP PR #21, site PR #9; `/leaderboard` 200; `GET /public/technocore/competitions/close-1/leaderboard` 200; `site/llms.txt` labels it provisional |
| Evidence boundary | Holds in code and copy | `core/docs/TECHNOCORE_EVIDENCE_BOUNDARIES.md`; `site/llms.txt` says a DID signature "proves that a key signed exact bytes, not truth or real-world identity" |

### Developer and distribution surfaces

| Surface | Status | Evidence |
|---|---|---|
| Public MCP (exactly 3 read-only tools) | LIVE / COMPLETE | Live `tools/list` 2026-09-28; `mcp/src/publicMcp.ts` |
| Paid MCP | LIVE; README drift | Live `tools/list` returns 21 tools. `mcp/README.md` §4 still says "nine" |
| SDK | LIVE / COMPLETE (0.8.0) | `withOcd` x402 wrapper, 6 production executors, commerce client |
| CLI | LIVE (0.4.0); unchanged since 2026-09-14 | No observe or signed-claim command |
| Agent Plugin (`agent-plugin/`, Agent Plugins 1.0.0) | IMPLEMENTED BUT NOT DISTRIBUTED | `core/agent-plugin/{plugin.json,mcp.json,skills/payment-diligence/SKILL.md}`; declares `/public/mcp` |
| Official MCP Registry | LIVE BUT STALE | `registry.modelcontextprotocol.io/v0/servers?search=onchaindiligence`: `com.onchaindiligence/compliance` v1.1.0, published 2026-06-27, `isLatest`. Description "Pay-per-call compliance via x402…". Lists only paid `/mcp`, not `/public/mcp`. Same content in `mcp/server.json` |
| ChatGPT Plugin Directory | IMPLEMENTED; submission state UNKNOWN | `mcp/docs/OPENAI_PLUGIN_SUBMISSION.md` says "NOT SUBMITTED" (2026-09-07). Yet `/.well-known/openai-apps-challenge` now returns 200 with a 43-byte token, which suggests the portal flow was started later. Not claimed as submitted |
| Claude custom connector | LIVE (manual add) | `mcp/README.md` §3/§7, validated through a Claude host loop; MCP commit `aa20693` (Claude-compatible schemas) |
| Claude Connectors Directory | NOT SUBMITTED; path now open (see §3.8) | — |
| Website | LIVE | 19 sitemap URLs, all 200. `observe-payment` documented on `/developers`, `/docs` and `llms.txt`; SEO structured data (`0a23ba1`, `1aac220`); `/live` dashboard |
| GitHub Action | FIXED LOCALLY; new immutable tag pending | `AUDIT_FINDINGS.md` OD-010, OD-030 |

### Commercial readiness

| Item | Status | Evidence |
|---|---|---|
| Pilot package (quickstart, terms, support, data handling) | LIVE BUT LIMITED (discussion drafts) | `mcp/docs/FIRST_PILOT_PACKAGE.md`, `PILOT_TERMS.md`, `PILOT_SUPPORT.md`, `DATA_HANDLING.md`; `site/pilot.html` |
| Legal identity, reviewed terms | BLOCKED (owner decision) | `AUDIT_FINDINGS.md` OD-011 is DECISION REQUIRED; `OPENAI_PLUGIN_SUBMISSION.md` needs publisher legal identity confirmed |
| External pilot / customer / partner | None evidenced | No repository, receipt or telemetry record |

### Superseded

| Item | Status |
|---|---|
| Original Phase 1–4 roadmap (trustworthy core, FLOP decision, feature backlog, re-audit gates) | DEPRECATED / SUPERSEDED on 2026-08-27; historical audit context only |
| FLOP inference-network integration (Phase 2) | SUPERSEDED for now by bounded Technocore participation (FLOP-A, D5.x). WATCH for an official testnet/SDK |
| "Two payment rails" framing in `core/README.md` | Still accurate for the evidence-provider API; no longer the product's headline |

## 3. Roadmap drift found

Compared with `PRODUCT_ROADMAP.md` dated 2026-09-16.

### 3.1 Marked incomplete but actually complete

- **`docs/MIGRATION_PLAN.md` (dated 2026-08-30) still calls P1 item 9 "the next
  implementation slice."** The typed record helpers shipped in `0.4.0`. The
  roadmap already said so, but the migration plan was not updated.
- **Arc D3.5C3-REGISTRIES is only partly blocked now.** The ERC-8004 mainnet
  registries and explorer are published (§3.7).

### 3.2 Marked complete but no longer accurate

- **D3.4C3 Turnkey, C4 Crossmint, C5 CDP and C6 Circle are marked
  "COMPLETE / LIVE".** Accurate wording is *code complete + deployed; not
  activated*: no real provider delivery or live reference payment is recorded
  for any of them. D3.4C2 PayBox has the inconsistency noted in §2.
- **Agent Plugins "not yet distributed through… MCP Registry" is incomplete.**
  The MCP **server** is in the MCP Registry, with stale pre-pivot metadata. The
  roadmap never recorded that.
- **The CLAUDE.md premise "No competitor signs" no longer holds in the adjacent
  agent-receipt space** (§4.4). OCD's defensible difference is narrower (§6).
  CLAUDE.md is outside this task's allowed files; flagged only.

### 3.3 Shipped since the 2026-09-16 update and absent from the roadmap

| Date | Work | Evidence |
|---|---|---|
| 2026-09-16 | Arc mainnet config fails closed on missing addresses | MCP PR #5 |
| 2026-09-17/18 | Privacy-safe MCP usage telemetry; fluid compute; `GET /public/activity` | MCP PRs #7, #8, #9 |
| 2026-09-19 | `/live` network-activity dashboard and homepage preview | Site PR #3 |
| 2026-09-20 | Bazaar resource metadata enrichment; flagship autonomous-payment reference; pilot setup doc fixes | MCP `a8caeb8`, `8525714`, `5483daf` |
| 2026-09-23/24 | Organization/WebSite structured data | Site `0a23ba1`, `1aac220` |
| 2026-09-26 | Claude-compatible public tool schemas; MCP favicon | MCP PRs #10, #11 |
| 2026-09-26 | Observation-only receipts, `POST /observe-payment` | MCP PR #12 |
| 2026-09-26 | x402 facilitator-init unhandled rejection fixed | MCP PR #13 |
| 2026-09-26 | SDK `withOcd` x402 lifecycle wrapper; SDK 0.8.0 published | SDK PRs #2, #3 |
| 2026-09-26/27 | Signed Payment Claim v1 format, issuer binding, conformance corpus; `agent-evidence@0.5.0` published | Core PRs #11, #12 |
| 2026-09-27 | Signed Payment Claim ingestion (fail-closed) | MCP PR #14 |
| 2026-09-27 | D5.1–D5.5 Technocore provenance, export, explorer, attribution, leaderboard | MCP PRs #15, #16, #19, #20, #21; site PRs #5, #8, #9 |
| 2026-09-27 | Site product clarity and accuracy pass | Site PR #4 |
| 2026-09-27 | Vercel main-only deployments | MCP PR #18 |

### 3.4 Stale references, packages and versions

- **`core/README.md`** pins `@onchaindiligence/agent-evidence@0.2.0`; current
  is `0.5.0`. Its table omits US company (`/company` is UK-only in the table).
- **`PRODUCT_ROADMAP.md` SHIPPED** says `agent-evidence@0.1.0` "is publicly
  available". It is historically true but should not read as current.
- **`mcp/README.md`** says the paid `/mcp` lists "nine" tools; live is 21. It
  also does not mention `POST /observe-payment`.
- **`mcp/server.json` / MCP Registry v1.1.0** carry the pre-pivot description
  and list only `/mcp`.
- **Stale governing docs:**
  - `docs/MIGRATION_PLAN.md` (2026-08-30);
  - `AUDIT_FINDINGS.md` (2026-09-12). OD-001 is still "IN PROGRESS", yet the
    production canary confirms `/attest` rejects unauthenticated callers and
    the key has been rotated (2026-09-03). The remaining gap is the retired
    key's missing `valid_from`, so the register needs re-closure review.
- **`mcp/docs/OPENAI_PLUGIN_SUBMISSION.md`** says "NOT SUBMITTED", but the
  challenge route is now configured.

### 3.5 Duplicated roadmap items (2026-09-16 version)

- **Agent Plugins 1.0** appears in LATER and in WATCH / FUTURE.
- **The Interoperability Profile** appears in SHIPPED and in CURRENT.
- **Agent Evidence ergonomics** appears in "NEXT BUILD" and in CURRENT.
- **D3.5C3 Arc** appears in NOW and in CURRENT.
- **First-Pilot Activation** appears in PRIMARY and in CURRENT.

### 3.6 Historical sections that must stay clearly historical

- Phase 1 (trustworthy core), Phase 2 (FLOP decision, 2026-08-26), Phase 3
  (feature backlog) and Phase 4 (re-audit gates). Several Phase 3 items now
  exist in narrower form, such as API keys, webhooks and a dashboard. The
  backlog must not be read as an active plan.

### 3.7 Blockers that disappeared or changed

**Arc ERC-8004 mainnet registries: unblocked on 2026-09-28.** The official
`docs.arc.io/arc/references/contract-addresses` (which `docs.arc.network`
redirects to) lists these Arc Mainnet addresses:

| Registry | Arc Mainnet address |
|---|---|
| IdentityRegistry | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` |
| ReputationRegistry | `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` |
| ValidationRegistry | `0x8004Cc8439f36fd5F9F049D9fF86523Df6dAAB58` |

It also names the mainnet explorer `explorer.arc.io`, which returns HTTP 200.
Read-only checks against `https://rpc.mainnet.arc.io` returned `eth_chainId`
`0x13b2` (5042) and non-empty bytecode at all three addresses (130 bytes each,
consistent with proxies). These differ from the testnet addresses
(`0x8004A818…`, `0x8004B663…`, `0x8004Cb1B…`), which remain the testnet
defaults in `mcp/src/arc/config.ts` and must not be reused.

**Arc ERC-8183 mainnet: still blocked.** The official ERC-8183 tutorial
(`docs.arc.io/arc/tutorials/create-your-first-erc-8183-job`) is testnet-only
(`0x0747EEf0706327138c69792bF28Cd525089e4583`). The contract-address page lists
no ERC-8183 contract, and the EIP defines no canonical address.

**Arc settlement observation was never registry-dependent.** Arc USDC
observation (`0x3600…0000`, the native-balance ERC-20 interface) is not
implemented in `settlementNetworks.ts`. The old roadmap tied Arc activation to
the registries, but settlement observation does not need them. It is a
separate, unbuilt item with no pilot demand today.

**Claude Connectors Directory:** a distribution path is now open. The official
submission doc (`claude.com/docs/connectors/building/submission`, accessed
2026-09-28) states:

- remote HTTPS servers with "no authentication for public data" are accepted;
- every tool needs a `title` and `readOnlyHint` or `destructiveHint`, which the
  public MCP already has;
- "Anyone on a paid Claude plan can submit";
- submissions are auto-scanned and listed as Community connectors by default.

**OD-001 (public `/attest`) is operationally mitigated** according to the
production canary; the register is stale.

### 3.8 Capabilities with no usable public or product surface

- **Signed Payment Claim ingestion:** correctly not advertised, because it is
  not activated.
- **Observe-payment** is documented, but there is no try-it form on the site
  and no standalone SDK method.
- **Allowance, swap, bridge and staking evidence** are reachable only through
  the paid MCP. There is no site demo, public receipt example or SDK helper.
- **Accounts, workspaces, API keys and outbound webhooks** exist server-side and
  in the app, but are barely present in public docs.
- **The Python Agent Evidence package** is not installable from PyPI.
- **The agent plugin package** is in no directory.
- **None of the five third-party executor adapters** has a public live-reference
  receipt.

## 4. Market and ecosystem research (all accessed 2026-09-28)

Primary sources were used where available; secondary reporting is marked
**[secondary]**. Adoption figures quoted by vendors are vendor claims, not
verified facts.

### 4.1 Payment protocols and standards

- **x402.** The Linux Foundation launched the x402 Foundation on 2026-04-02 and
  accepted the protocol contribution from Coinbase. Named launch supporters
  include:
  - Adyen, AWS, American Express, Base, Circle, Cloudflare, Coinbase, Fiserv;
  - Google, KakaoPay, Mastercard, Microsoft, Polygon Labs, PPRO;
  - Shopify, Solana Foundation, Stripe, thirdweb, Visa, and others.

  x402 is now a neutral, multi-vendor standard. The protocol itself carries no
  independent post-settlement evidence layer. (Per the task instructions, the
  Block / x402 / Lightning development is deferred to a post-audit review.)
- **AP2 (Agent Payments Protocol).** Google announced AP2, and in April 2026
  donated it to the FIDO Alliance with a v0.2 release **[secondary for the
  date; the FIDO/Google announcement pages exist]**. AP2 is positioned as an
  A2A/MCP extension for mandates and authorization.
- **Mastercard Verifiable Intent.** The open specification (Apache-2.0, draft
  v0.1, github.com/agent-intent/verifiable-intent) defines layered SD-JWT
  credentials proving that an agent acted within human-delegated scope. It
  explicitly excludes transport, key management, dispute resolution and
  settlement/outcome evidence. Reported as contributed to FIDO alongside AP2
  **[secondary]**.
- **Visa Trusted Agent Protocol and Know-Your-Agent.** Ant International, Visa
  and Mastercard announced a Know-Your-Agent interoperability collaboration on
  2026-09-10, bridging TAP, Verifiable Intent and Ant's AMP **[secondary;
  consistent with the roadmap's existing WATCH entry]**. There is still no
  published interoperable credential format for OCD to adopt.
- **Stripe.** Stripe has an Agentic Commerce Suite and Shared Payment Tokens,
  extending to network agentic programs (stripe.com blog, "Supporting additional
  payment methods for agentic commerce"). It is card and processor-centred and
  offers no independent evidence layer.
- **ERC-8004 (Trustless Agents).** Status: Draft (created 2025-08-13). It
  defines Identity, Reputation and Validation registries. Its off-chain feedback
  file has an optional `proofOfPayment` field (x402 sender, recipient, chain,
  tx hash). That field is a natural place for an OCD receipt reference later,
  but no build is justified yet.
- **ERC-8183 (Agentic Commerce).** Per-chain deployments with no canonical
  address. Arc publishes testnet only.

### 4.2 Wallets and signing infrastructure

- **Turnkey** (docs.turnkey.com, accessed 2026-09-28):
  - Secure-enclave key management.
  - A policy engine evaluated inside the enclave before any signature, scoped by
    recipient, contract, selector, chain and value.
  - Consensus approvals and delegated agent access.
  - Webhooks including `SEND_TRANSACTION_STATUS_UPDATES` (BROADCASTING →
    INCLUDED/FAILED), `BALANCE_CONFIRMED_UPDATES` and
    `BALANCE_FINALIZED_UPDATES`, signed with Ed25519 (`X-Turnkey-Signature`).

  Turnkey is authoritative for *what it authorized and signed*. It does not
  offer an independent, portable, third-party-verifiable record reconciling
  intent, policy and independently observed settlement.
- **Coinbase CDP Agentic Wallets:** launched February 2026 per Coinbase's launch
  page (403 to the fetcher; content via **[secondary]**). MPC wallet, spend and
  session limits, native x402, Bazaar discovery.
- **Circle.** Arc public mainnet launched 2026-09-16 (circle.com pressroom).
  Circle Agent Stack (Agent Wallets, Nanopayments via Gateway, an emerging
  marketplace) was reported as launched May 2026 **[secondary]**.
- **Crossmint, Privy and others:** agent-wallet comparisons exist (crossmint.com
  "agent wallets compared"). The segment is crowded and controls-centric.

### 4.3 Agent directories and distribution

- **Official MCP Registry.** Unopinionated metadata, namespace-authenticated.
  Downstream directories (Glama, MCP.Directory and others) import from it
  **[secondary: dev.to directory survey, September 2026]**. OCD's own telemetry
  confirms directory crawlers are the main traffic source.
- **Claude Connectors Directory.** Portal at `claude.ai/directory/manage`, open
  to any paid Claude plan. Accepts remote MCP connectors (no-auth allowed for
  public data) and plugin bundles; skills are distributed only inside plugins.
  Auto-scan, then a Community listing (primary doc, §3.7). A portal launch date
  of 2026-09-25 is reported **[secondary]**.
- **ChatGPT Plugin Directory.** Per `developers.openai.com/plugins/deploy/submission`:
  - submitters need Apps Management write access and individual or business
    verification;
  - every tool must carry `readOnlyHint`, `openWorldHint` and `destructiveHint`;
  - approval happens before publishing.

  The OCD package already meets the annotation rule. Identity and legal details
  are the operator gate.

### 4.4 Adjacent "signed receipt" work (positioning risk)

- **Microsoft Agent Governance Toolkit:** a "Verifiable Compliance Receipts"
  proposal (Draft, 2026-04-21). Ed25519 over RFC 8785 JCS, hash-chained. It
  covers compliance checks, not payments or settlement.
- **Agent Receipts / Obsigna** (agentreceipts.ai; open source, SDKs in Go,
  Python and TS): Ed25519 W3C Verifiable Credentials for agent tool calls. It
  does not observe payment settlement.
- Other hash-chained audit-trail projects appear in 2026 research and blogs.
- **Conclusion:** "we sign" is no longer a differentiator on its own. What
  remains uncommon is:
  1. independent settlement observation across Base, Ethereum, Tempo and Solana
     under explicit finality policies;
  2. reconciliation of provider/executor claims against that observation, with
     contradictions preserved;
  3. binding to a pre-execution policy decision;
  4. doing all of this without custody or execution.

### 4.5 FLOP / Technocore

- FLOP Network's draft yellow paper (v0.5.0) targets a testnet in Q4 2026 and
  mainnet in Q1 2027 **[secondary]**.
- Technocore.chat is live, with a DID-gated faucet **[secondary]**.
- No official stable public testnet SDK was confirmed in this audit. The
  roadmap's WATCH position holds.

## 5. What is missing

### A. Product gaps (value to an agent developer today)

1. **A live third-party execution reference.** All five executor adapters are
   unexercised in public. The single real Commerce Receipt had OCD as both
   seller and issuer. A developer cannot see OCD witnessing someone else's
   executor.
2. **A zero-integration entry point.** `observe-payment` is the lowest-friction
   capability (tx hash → signed receipt), but there is no site form and no
   standalone SDK call. It is the easiest thing to try and share.
3. **Measured paid execution.** `completed_paid_executions` is `null`. The
   funnel cannot show whether any paid lifecycle has completed.

Not supported by the evidence as current gaps:

- An organization or team model, API keys, webhooks, a dashboard or audit
  export. Narrow versions already exist.
- Enterprise SSO or SLAs. No pilot has asked.

### B. Integration gaps (what stops a wallet or executor adopting OCD)

1. **No executor-side "claim issuer" path is in use.** Signed Payment Claim
   ingestion needs a real platform issuer key and approved trust configuration.
   None exists, and none should be manufactured.
2. **Turnkey webhook naming needs a re-check before any demo.**
   - OCD code and docs refer to a Turnkey `transaction:status` webhook at
     `POST /webhooks/turnkey/transaction-status`.
   - Current Turnkey docs list the event type as
     `SEND_TRANSACTION_STATUS_UPDATES`.
   - This may only be naming, but confirm it against current Turnkey docs
     before a live run.
3. **The PayBox live-reference contradiction.**

### C. Distribution gaps (built but not reaching users)

1. **Stale MCP Registry entry.** It carries the pre-pivot description, lists
   only the paid endpoint, and downstream directories inherit it.
2. **The public MCP is not in the Claude Connectors Directory**, even though it
   already meets the stated requirements.
3. **ChatGPT Plugin Directory submission state is unknown.**
4. **The agent plugin package is in no directory**, and its format compatibility
   with Claude plugin bundles is unverified.
5. **`mcp/README.md` and `core/README.md` are stale**, with the wrong tool count
   and an old package pin.
6. **The Python package is not on PyPI.**

### D. Commercial gaps (what stops a pilot or partner saying yes)

1. **Publisher legal identity and reviewed terms** (OD-011, DECISION REQUIRED).
   This gates the ChatGPT directory and any formal pilot.
2. **No public third-party reference or case study.**
3. **Pilot terms, support and data-handling documents are discussion drafts.**
4. **No paid-conversion evidence to show a partner.**
5. **`strict_offline_verification_ready: false`.** A sophisticated verifier
   (auditor or partner) will notice the retired key lacks an activation
   boundary.

## 6. Competitive differentiation

What OCD provides that each category does not:

| Category | What they provide | What OCD adds |
|---|---|---|
| Turnkey and other wallet/signing infrastructure | Key custody or isolation; policy enforced before signing; provider-authored activity and status records | A record **not authored by the executor**: pre-execution policy evaluation evidence, independent on-chain settlement observation, and reconciliation of the executor's own claim against that observation, in a portable signed receipt verifiable offline. OCD never needs the key or the execution path |
| x402 facilitators (Coinbase, others) | Verify and settle the payment they facilitate | Evidence independent of the facilitator; binding to the agent's policy decision; the same receipt model across rails and executors |
| Chain explorers | Raw public transaction data | Interpretation under an explicit finality policy, binding to an intended action and policy, contradiction detection, and a signed, versioned artifact that cannot be quietly edited |
| Payment processors and card-network agent programs (Stripe, Visa TAP, Mastercard Verifiable Intent, AP2) | Authorization and intent credentials, tokenized credentials, checkout | These explicitly exclude settlement and outcome evidence (Verifiable Intent scope). OCD can later *reference* such mandates as evidence inputs, without replacing them |
| Compliance screening vendors | Risk scores, attribution, screening | OCD keeps screening as an evidence provider. It does not sell attribution or risk scores (`core/README.md`). Its product is accountability for an agent's payment action, not a risk opinion |
| Signed agent-receipt projects (Agent Receipts, the Microsoft AGT proposal) | Signed or hash-chained records of agent tool calls or compliance checks | Independent **settlement** observation and provider-claim reconciliation for real money movement across four networks |

**Is the stated thesis coherent in the implementation?** Mostly yes.

| Thesis step | Implementation |
|---|---|
| Agent intends to pay → OCD inspects | `inspect_payment` (free) / `preflight_payment` (signed PREFLIGHT receipt) |
| Wallet or executor executes | `CommerceExecutor` contract; OCD never signs (`sdk/src/commerce/*Executor.ts`) |
| OCD independently observes | Settlement observers for Base, Ethereum, Tempo and Solana |
| Verifiable evidence | Signed receipts, offline verifier, bundles |
| Already-paid flow | `POST /observe-payment` → observation-only receipt, decision `UNKNOWN` |

The gap is proof, not coherence. No public receipt yet shows the full loop with
an **independent** executor. That is exactly what a Turnkey reference run would
demonstrate.

## 7. Recommended next builds

Each item includes the external dependency, size, value and funding/demo
leverage.

### NOW: founder actions, no product code

1. **Turnkey follow-up.** Offer the reference-run demo below as the concrete
   next step. Ask whether Turnkey would review or co-announce it. Do not claim
   a partnership.
2. **Submit `https://mcp.onchaindiligence.com/public/mcp` to the Claude
   Connectors Directory.**
   - It meets the stated requirements today: remote, no-auth, titled and
     annotated read-only tools, privacy, terms and support pages.
   - Dependency: a paid Claude plan.
   - Size: XS.
   - Value: distribution. It opens a directory whose users may have some intent
     to try the tools, unlike most of the crawler traffic seen so far.
3. **Decide OD-011** (publisher legal identity and reviewed terms). It unblocks
   the ChatGPT directory and formal pilots.
4. **Confirm the ChatGPT Plugin Directory portal state**, then update
   `OPENAI_PLUGIN_SUBMISSION.md` accordingly.

### NEXT: at most 3 implementation items

**N1 — Turnkey reference integration run (the live independent-executor proof).**

- **Outcome:** a public, verifiable Commerce Receipt showing:
  1. OCD preflight ALLOW;
  2. Turnkey policy-constrained `ethSendTransaction` (Base mainnet, small USDC);
  3. a Turnkey-signed send-transaction-status claim ingested by OCD;
  4. OCD's independent Base observation;
  5. a reconciled receipt.

  Plus one negative case (an OCD BLOCK, or a Turnkey policy denial) recorded
  honestly. Published as a reference page, a runnable example and a write-up.
- **Why it matters:**
  - It is the first proof of the thesis with an independent executor.
  - It converts D3.4C3 from *deployed* to *activated*.
  - It is the smallest credible demo for Turnkey.
- **External dependency:**
  - the founder's own Turnkey organization and a small USDC amount;
  - re-confirming Turnkey's webhook event naming;
  - no Turnkey agreement needed (built from public docs, stated as independent).
- **Size:** S. The adapter and webhook route exist; the work is a runnable
  example, ops setup and a write-up.
- **Value:**
  - pilot value: high;
  - distribution: medium;
  - revenue: indirect (pilot enabler);
  - grant, competition or demo value: high.
- **Unlocks:** a possible Turnkey pilot; the same pattern for Crossmint, CDP and
  Circle; a first public third-party case for any pilot conversation.

**N2 — Distribution metadata sync.**

- **Outcome:**
  - The MCP Registry entry is republished with an accurate description, adding
    the free `/public/mcp` remote.
  - `mcp/README.md` shows the correct tool count and documents
    `/observe-payment`.
  - `core/README.md` has the current package pin.
  - `OPENAI_PLUGIN_SUBMISSION.md` status is corrected.
- **Why it matters:** the registry feeds the directories that generate most
  current traffic, and it currently mis-describes the product.
- **External dependency:** MCP Registry publisher authentication (namespace
  `com.onchaindiligence`).
- **Size:** XS–S.
- **Value:** distribution high; pilot, revenue and grant value low to medium.
- **Unlocks:** accurate downstream listings; the Claude and ChatGPT directory
  descriptions reuse the same copy.

**N3 — "Receipt for a past payment" try-it page plus an SDK helper.**

- **Outcome:**
  - A site form on the existing Receipt Explorer calls the existing free
    `POST /observe-payment`. The site CSP already allows
    `mcp.onchaindiligence.com`.
  - It renders the signed observation-only receipt, with a verify link and its
    `UNKNOWN`-decision disclosure.
  - A standalone SDK `observePayment()` wraps the same route, as an additive
    minor release.
- **Why it matters:**
  - It is the lowest-friction way for anyone, including a Turnkey or x402 user,
    to get independent evidence for a payment they already made, with no
    integration.
  - It is shareable and makes a good demo, content piece and grant evidence.
- **External dependency:** none.
- **Pre-condition:** review abuse and cost. The rate limit is best-effort and
  per-instance; dedupe bounds repeat signing but not RPC load. Decide whether
  that is acceptable before promoting widely.
- **Size:** S.
- **Value:**
  - pilot value: medium;
  - distribution: high;
  - revenue: low directly (free), but a funnel into the paid preflight
    lifecycle;
  - demo value: high.
- **Unlocks:** content and SEO; a public dataset of independently observed
  receipts, if the owner later chooses to make any public.

### LATER (only with a trigger)

- **Signed Payment Claim activation with the first real platform issuer.**
  Trigger: a platform agrees to sign claims and publish keys. Size S (config and
  trust review). Never manufacture an issuer.
- **Revisit the x402 settlement-rail abstraction after this audit**, including
  the separately flagged Block / x402 / Lightning development.
- **Arc.** Arc USDC settlement observation, then ERC-8004 mainnet registry
  wiring (decoupled from ERC-8183 if a use case appears). Trigger: pilot demand
  or a Circle/Arc ecosystem program. Grant leverage is plausible, but the Arc
  ecosystem has 100+ apps and OCD has no demand signal from it.
- **Measure `completed_paid_executions`**, so the funnel can show paid lifecycle
  completion. Size XS. It could move to NEXT if a pilot needs metrics.
- **Publish the Python package to PyPI.** Requires owner decision on trusted
  publishing (`MIGRATION_PLAN.md` §8).
- **Set the retired key's activation boundary**, so strict offline verification
  is ready. Owner decision.
- **Existing LATER items stay parked:**
  - D4.3 Evidence of Absence;
  - A2A conformance;
  - bundle-aware browser inspection;
  - allowance/swap/bridge/staking public demos.

### WATCH / BLOCKED

- **Arc ERC-8183 mainnet address:** unpublished.
- **Know-Your-Agent / TAP / Verifiable Intent / AP2:** watch for a stable
  credential format to *reference* as mandate evidence.
- **MCP 2026-07-28 dual-era support:** dependency-blocked on `@x402/mcp` and
  MCP SDK v2. Not re-checked in this audit.
- **FLOP official testnet/SDK.**
- **Close Call launch verification:** D5.4 and D5.5 remain provisional until the
  organizer publishes a verifiable launch.

### Funding and demo leverage

| Build | Partner demo | Grant evidence | Competition/demo | Blog/content | Public dataset/provenance | Investor demo |
|---|---|---|---|---|---|---|
| N1 Turnkey reference run | ✓ (Turnkey) | ✓ | ✓ | ✓ | ✓ (public receipt) | ✓ |
| N2 Distribution sync | — | — | — | — | — | indirect |
| N3 Past-payment receipt page | ✓ (any wallet) | ✓ | ✓ | ✓ | ✓ (opt-in only) | ✓ |
| Claude directory submission (NOW) | — | — | — | ✓ | — | ✓ (listing) |
| D5.x Technocore (already shipped) | — | ✓ | ✓ | ✓ | ✓ | — |

## 8. What NOT to build yet

- **Lightning support or an x402 redesign:** review after this audit, as agreed.
- **Additional public MCP tools.** The public surface stays exactly three
  read-only tools. No external demand justifies more.
- **More chains, actions or executor adapters** (e.g. Arc ERC-8183, more swap
  profiles). Five adapters are already unactivated.
- **A Signed Payment Claim issuer SDK, hosted issuer or trust directory** before
  a real issuer commits.
- **A KYA/identity adapter** before a concrete interoperable credential exists.
- **Enterprise SSO/SCIM, org RBAC expansion, SLAs or billing systems** before a
  pilot asks.
- **More Technocore features** beyond keeping D5.x correct. Wait for the
  organizer's launch verification.
- **A partial MCP 2026-07-28 stack, or FLOP inference integration.**

## 9. Unresolved questions

1. What is the actual ChatGPT Plugin Directory portal state, given the challenge
   token is configured?
2. Did a live PayBox reference payment run (D2.6) or not? `integrations.html`
   and `FIRST_PILOT_PACKAGE.md` disagree.
3. Does OCD's Turnkey webhook route match Turnkey's current
   `SEND_TRANSACTION_STATUS_UPDATES` event and payload?
4. Is `SIGNED_PAYMENT_CLAIM_TRUST_JSON` unset in production? This is
   founder-stated and was not independently read.
5. Should the retired signing key receive a defensible `valid_from`?
6. Can `agent-plugin/` (Agent Plugins 1.0) be submitted as a Claude plugin
   bundle, or does it need a Claude-specific manifest? Unverified.
7. What does Turnkey want from a pilot: an evidence layer for their customers, a
   co-marketing reference, or a policy-hook integration? That answer determines
   whether N1 stays a reference run or grows.
8. Who is the publisher legal entity (OD-011)?

## 10. Sources (accessed 2026-09-28 unless stated)

Repositories (default branches):

- github.com/Qazza1/onchaindiligence @ `9ed3853`
- github.com/Qazza1/onchaindiligence-mcp @ `22931ba`
- github.com/Qazza1/onchaindiligence-sdk @ `89cbcc6`
- github.com/Qazza1/onchaindiligence-site @ `5c2eaec`
- github.com/Qazza1/onchaindiligence-cli @ `92288a9`

Production surfaces:

- https://mcp.onchaindiligence.com/public/mcp (`tools/list`)
- https://mcp.onchaindiligence.com/mcp (`tools/list`)
- https://mcp.onchaindiligence.com/public/activity?window=7d
- https://mcp.onchaindiligence.com/public/technocore/competitions/close-1/leaderboard
- https://api.onchaindiligence.com/.well-known/attestation-keys
- https://onchaindiligence.com (the 19 sitemap URLs)

Registries:

- https://registry.npmjs.org/@onchaindiligence/agent-evidence
- https://registry.npmjs.org/@onchaindiligence/sdk
- https://registry.npmjs.org/@onchaindiligence/cli
- https://pypi.org/pypi/onchaindiligence-agent-evidence/json (404)
- https://registry.modelcontextprotocol.io/v0/servers?search=onchaindiligence

Arc:

- https://docs.arc.io/arc/references/contract-addresses
- https://docs.arc.io/arc/tutorials/register-your-first-ai-agent
- https://docs.arc.io/arc/tutorials/create-your-first-erc-8183-job
- https://rpc.mainnet.arc.io (`eth_chainId`, `eth_getCode`)
- https://explorer.arc.io
- https://www.circle.com/pressroom/circle-launches-arc-mainnet-an-economic-operating-system-for-the-internet (2026-09-16)

Standards:

- https://eips.ethereum.org/EIPS/eip-8004
- https://eips.ethereum.org/EIPS/eip-8183
- https://www.linuxfoundation.org/press/linux-foundation-is-launching-the-x402-foundation-and-welcoming-the-contribution-of-the-x402-protocol (2026-04-02)
- https://github.com/agent-intent/verifiable-intent
- https://blog.google/products-and-platforms/platforms/google-pay/agent-payments-protocol-fido-alliance/
- https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol
- https://stripe.com/blog/supporting-additional-payment-methods-for-agentic-commerce

Wallets:

- https://docs.turnkey.com/features/policies/delegated-access/agentic-wallets
- https://docs.turnkey.com/developer-reference/webhooks
- https://www.turnkey.com/solutions/ai-agents
- https://www.coinbase.com/developer-platform/discover/launches/agentic-wallets (403 to the fetcher; content via secondary reporting)

Directories:

- https://claude.com/docs/connectors/building/submission
- https://developers.openai.com/plugins/deploy/submission

Adjacent receipt work:

- https://microsoft.github.io/agent-governance-toolkit/proposals/verifiable-compliance-receipts/ (draft, 2026-04-21)
- https://agentreceipts.ai/

Secondary (used only where noted):

- dev.to MCP directory survey (September 2026)
- Forkast / TNGlobal / PYMNTS coverage of the 2026-09-10 Know-Your-Agent announcement
- KuCoin / Gate coverage of FLOP yellow paper v0.5.0 and Technocore
- PYMNTS / The Paypers coverage of the AP2 FIDO donation and Circle Agent Stack
