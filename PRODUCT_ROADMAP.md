# OnchainDiligence product roadmap

Last updated: 2026-09-28. Evidence, sources and full drift analysis:
[`docs/PRODUCT_AUDIT_2026-09-28.md`](docs/PRODUCT_AUDIT_2026-09-28.md).

## Current strategic focus — 2026-09-28

The build side is mature. **External adoption has not been demonstrated.**

- **Deployed:** every default branch is in production.
- **Discovery traffic:** about 4.1k MCP sessions in 7 days, mostly directories
  and crawlers (`GET mcp.onchaindiligence.com/public/activity?window=7d`).
- **Usage and conversion:** 8 successful tool calls, 1 receipt, and paid
  execution not yet measured.
- **Customers:** no pilot, partner or customer is evidenced.

The next priorities, in order:

1. **First external pilot.** A real Turnkey conversation happened on
   2026-09-28. It is a *potential pilot*: no partnership, agreement or
   integration exists or may be claimed.
2. **Prove the thesis with an independent executor.** Run one public Turnkey
   reference: OCD inspect/preflight → Turnkey policy/sign/send → Turnkey-signed
   status claim → OCD independent observation → signed receipt. The code
   already exists; it has never been exercised with a real Turnkey
   organization.
3. **Fix distribution that is already built but mis-described or unlisted:**
   - the stale MCP Registry entry;
   - Claude Connectors Directory submission of the free public MCP;
   - the ChatGPT Plugin Directory state.
4. **Make the free "receipt for a past payment" capability**
   (`POST /observe-payment`) usable without integration.

Do not start new chains, actions, adapters, public MCP tools, or the x402 /
Lightning redesign until items 1–3 move. Revisit the x402 settlement-rail
abstraction only after this audit.

## Status vocabulary

- **Code complete:** merged on the default branch.
- **Deployed:** running in production, or published to a registry.
- **Activated:** exercised with a real external counterparty or real
  configuration. For example, a provider webhook actually delivered, or a trust
  issuer actually configured.
- **Externally adopted:** used by a party other than OnChainDiligence.

**LIVE** is used only when deployed and activated. Nothing below is externally
adopted unless it says so.

## External adoption and first pilot

- **D3.4A First-Pilot Activation Path: ACTIVE and PRIMARY.**
  - The pilot package exists: `onchaindiligence-mcp/docs/FIRST_PILOT_PACKAGE.md`,
    `PILOT_QUICKSTART.md`, `PILOT_TERMS.md`, `PILOT_SUPPORT.md` and
    `DATA_HANDLING.md`, plus `onchaindiligence.com/pilot`. The terms, support
    and data documents are discussion drafts.
  - No external pilot has started.
- **Turnkey: RECENT CONVERSATION / POTENTIAL PILOT (2026-09-28).** Product fit
  under discussion:
  - Turnkey owns secure keys, policy-controlled signing and execution.
  - OCD owns independent inspection, observation, reconciliation and signed
    evidence.
  - Target architecture:
    `agent → OCD inspect → Turnkey policy/sign/execute → OCD independently observe → signed receipt`.
  - Smallest credible demo if Turnkey is interested: NEXT item N1 below.
- **Commercial blockers:**
  - Publisher legal identity and reviewed terms (`AUDIT_FINDINGS.md` OD-011,
    DECISION REQUIRED). This gates the ChatGPT directory and formal pilots.
  - No public third-party reference receipt.
  - Paid lifecycle completion is not measured (`completed_paid_executions`
    is `null`).
  - `strict_offline_verification_ready: false`: the retired key lacks a
    `valid_from` boundary (owner decision).

## Forward sequence

### NOW: founder actions, no product code

1. Follow up with Turnkey, offering the N1 reference run as the concrete next
   step. Claim no partnership.
2. Submit `https://mcp.onchaindiligence.com/public/mcp` to the Claude
   Connectors Directory (`claude.ai/directory/manage`).
   - The official docs accept remote no-authentication servers from any paid
     Claude plan.
   - The three public tools already carry `title`, `readOnlyHint` and
     `destructiveHint`.
3. Decide OD-011 (publisher legal identity and reviewed terms).
4. Confirm the ChatGPT Plugin Directory portal state.
   - `onchaindiligence-mcp/docs/OPENAI_PLUGIN_SUBMISSION.md` still says
     "NOT SUBMITTED".
   - `/.well-known/openai-apps-challenge` now serves a configured token.
   - Do not claim a submission or listing until the portal confirms it.

### NEXT: at most three implementation items

1. **N1 — Turnkey reference integration run (S).**
   - **Outcome:** a public, verifiable Commerce Receipt for one small Base-USDC
     payment. It shows OCD preflight ALLOW, Turnkey policy-constrained
     `ethSendTransaction`, the Turnkey-signed send-status claim ingested by OCD,
     OCD's independent Base observation, and the reconciled result.
   - Also record one honest negative case: an OCD BLOCK, or a Turnkey policy
     denial.
   - Publish a runnable example and a write-up. Uses the existing
     `TurnkeyCommerceExecutor` and `turnkeyWebhookRoute.ts`.
   - Re-confirm Turnkey's current webhook event naming
     (`SEND_TRANSACTION_STATUS_UPDATES`) against OCD's route first.
   - **Dependency:** the founder's own Turnkey organization and a small USDC
     balance. No Turnkey agreement is required; state that it is independent.
   - **Unlocks:** D3.4C3 activation, a Turnkey pilot, the same pattern for the
     other executors, and partner, grant and investor demos.
2. **N2 — Distribution metadata sync (XS–S).**
   - **Outcome:** the MCP Registry entry `com.onchaindiligence/compliance`
     (v1.1.0, pre-pivot "pay-per-call compliance" copy, paid `/mcp` only) is
     republished with accurate copy and the free `/public/mcp` remote.
   - Also fix:
     - `onchaindiligence-mcp/README.md`: it says the paid `/mcp` lists "nine"
       tools, live is 21, and `/observe-payment` is undocumented;
     - `README.md` here: it pins `agent-evidence@0.2.0`, current is 0.5.0;
     - the OpenAI submission status doc.
   - **Dependency:** MCP Registry namespace authentication.
3. **N3 — Past-payment receipt page plus SDK helper (S).**
   - **Outcome:** a Receipt Explorer form calls the existing free
     `POST /observe-payment` and renders the signed observation-only receipt
     (decision `UNKNOWN`, with its disclosure and a verify link).
   - An additive `observePayment()` joins the SDK. Today the route is reachable
     from the SDK only through the `withOcd` fallback.
   - **Pre-condition:** review abuse and cost first. Rate limiting is
     best-effort and per-instance; dedupe is per (network, tx).

### LATER: trigger required

- **Signed Payment Claim Phase 2 activation.** Trigger: a real platform issuer
  signs claims and publishes keys. Never manufacture an issuer to call this
  live.
- **Revisit the x402 settlement-rail abstraction**, including the separately
  flagged Block / x402 / Lightning development. Post-audit review; not
  pre-decided.
- **Arc.**
  - Arc USDC settlement observation is not implemented. It is independent of
    the registries.
  - ERC-8004 mainnet registry wiring is now possible. The addresses are
    published; see Arc below.
  - Trigger: pilot demand or an Arc/Circle ecosystem program.
- **Measure completed paid executions** in public telemetry (XS).
- **Publish the Python Agent Evidence package to PyPI.** Needs the owner's
  trusted-publishing decision; today it is repository install only.
- **Set the retired key's activation boundary**, making strict offline
  verification ready (owner decision).
- **Existing parked items:**
  - D4.3 Evidence of Absence (PREP, no semantics frozen);
  - A2A official conformance spike (demand-driven);
  - bundle-aware browser inspection (onboarding-driven);
  - public demos for allowance, swap, bridge and staking evidence.
- **Agent Plugins 1.0 distribution.** Verify whether a Claude plugin bundle can
  carry `agent-plugin/` unchanged before building anything.

### WATCH / BLOCKED

- **Arc ERC-8183 mainnet: BLOCKED.** No official mainnet address; the tutorial
  is testnet-only.
- **Know-Your-Agent / Visa TAP / Mastercard Verifiable Intent / AP2: WATCH.**
  These cover authorization and intent, and Verifiable Intent explicitly
  excludes settlement and outcome evidence. OCD may later *reference* such a
  credential as mandate evidence once a stable interoperable format exists. No
  schema or adapter before then; see `docs/PRODUCT_DIRECTION.md`.
- **MCP 2026-07-28 dual-era support: PREP / DEPENDENCY-BLOCKED** on
  `@x402/mcp` and MCP SDK v2. MCP Tasks is parked with it. Not re-checked in
  the 2026-09-28 audit.
- **FLOP inference testnet integration: WATCH** for an official stable
  testnet/SDK. None was confirmed on 2026-09-28.
- **Technocore Close Call launch verification: WATCH.** D5.4 attribution and
  the D5.5 leaderboard stay provisional until the organizer publishes a
  verifiable launch.

## Capability status (2026-09-28)

Full table with evidence: audit §2.

**Deployed and activated (LIVE):**

- **Payment inspection and receipts:** `inspect_payment`; signed Public Action
  Receipts; `get_receipt` / `verify_receipt`; the `/r/:id` Receipt Explorer.
- **Public MCP:** exactly three read-only tools, verified live on 2026-09-28.
- **Settlement observation:** Base, Ethereum, Tempo and Solana (Solana cannot
  claim `PAYMENT_IDENTITY_LINKED`).
- **Verification:** offline verifier (D4.1), Signed Evidence Bundles (D4.2),
  and browser verification.
- **Evidence-provider HTTP API and anchoring.**
- **Packages:** Agent Evidence v0 (npm `0.5.0`), SDK `0.8.0`, CLI `0.4.0`.
- **Technocore provenance:** D5.1, D5.2 and D5.3.

**LIVE BUT LIMITED:**

| Capability | Limit |
|---|---|
| `preflight_payment` and the commerce lifecycle | The only real Commerce Receipt had OCD as both seller and issuer |
| `POST /observe-payment` | No site form; no standalone SDK method |
| Paid MCP (21 tools) | Allowance, swap, bridge and staking evidence (D3.6A–D) are single-profile and reachable only through the paid MCP |
| x402 | The MCP rail is still on x402 v1 |
| Interoperability Profile v1 | One integrator (ArcFX) |
| Python package | Not on PyPI |
| D5.4 attribution, D5.5 leaderboard | Provisional |
| Accounts, workspaces, API keys, outbound webhooks | Little public documentation |
| MCP Registry listing | Stale copy |

**IMPLEMENTED BUT NOT ACTIVATED** (code complete and deployed, no real
counterparty):

- **Provider-evidence adapters and SDK executors** for Turnkey (D3.4C3),
  Crossmint (D3.4C4), Coinbase CDP (D3.4C5) and Circle (D3.4C6).
- **PayBox (D3.4C2):** deployed, but its live-reference status is
  inconsistent. `onchaindiligence.com/integrations` says a live reference
  payment "has not yet run", while `FIRST_PILOT_PACKAGE.md` says end-to-end.
  Resolve before citing it.
- **Signed Payment Claim Phase 2 ingestion.** It fails closed without
  `SIGNED_PAYMENT_CLAIM_TRUST_JSON` holding an explicit issuer→key binding.
- **Agent Plugins 1.0 package:** in no directory.
- **ChatGPT Plugin package:** submission state unconfirmed.

**BLOCKED:**

- Arc ERC-8183 mainnet.
- Arc production integration (`src/arc` is unwired, and its mainnet mode
  requires ERC-8183).
- Formal pilots and the ChatGPT directory, pending OD-011.

## Shipped since the 2026-09-16 update

- **Signed Payment Claim v1 (2026-09-26/27): Phase 1 published.** Portable
  DSSE platform claim:
  - tri-state `VALID` / `INVALID` / `UNVERIFIABLE`;
  - issuer-origin to trusted-key binding;
  - canonical HTTPS origin rules;
  - embedded claims inherit issuer binding;
  - correlation, reconciliation and versioning rules;
  - DSSE domain separation from receipts;
  - TypeScript and Python verifiers and a conformance corpus.

  Published as `@onchaindiligence/agent-evidence@0.5.0` (2026-09-27; core PRs
  #11, #12). Spec: `docs/SIGNED_PAYMENT_CLAIM_V1.md`. A Signed Payment Claim is
  **not** an OCD receipt, and a platform claim is **not** settlement.
- **Signed Payment Claim Phase 2 ingestion (2026-09-27): deployed,
  intentionally fail-closed** (MCP PR #14). Not activated: no approved issuer
  trust configuration exists.
- **Observation-only receipts (2026-09-26): deployed** (MCP PR #12).
  `POST /observe-payment`:
  - free and unauthenticated;
  - observes an already-completed Base, Ethereum, Tempo or Solana stablecoin
    payment;
  - signs an observation-only COMMERCE receipt with decision `UNKNOWN` and no
    preflight or authorization claim;
  - the receipt is retrievable by exact ID (unlisted, not private);
  - dedupe per (network, tx), with best-effort rate limiting.
- **SDK `0.8.0` (2026-09-26):** the `withOcd` wrapper around an existing
  `@x402/core` v2 client adds preflight, binding, observation and a receipt.
  Its `onOcdUnavailable: 'proceed'` fallback uses `/observe-payment` (SDK PRs
  #2, #3).
- **Technocore provenance D5.1–D5.5 (2026-09-27):** deployed. The site's
  `/agents` and `/leaderboard` pages serve.

  | Milestone | Scope | PRs |
  |---|---|---|
  | D5.1 | Operation-bound provenance | MCP #15 |
  | D5.2 | Portable provenance export | MCP #16 |
  | D5.3 | Public DID / Agent Provenance Explorer (`onchaindiligence.com/agents`) | MCP #19, site #5 |
  | D5.4 | Verified competition attribution, with organizer metadata kept separate from signed DID evidence | MCP #20, site #8 |
  | D5.5 | Public Close Call leaderboard (`onchaindiligence.com/leaderboard`, provisional) | MCP #21, site #9 |

  Evidence boundary: a `did:key` signature proves control of the key over exact
  signed bytes. It does not prove real-world identity, authorization, honesty
  or payment settlement.
- **Distribution and telemetry:**
  - privacy-safe MCP usage telemetry and `GET /public/activity` (MCP PRs #7–#9);
  - the `/live` dashboard (site PR #3);
  - Bazaar metadata enrichment and the flagship autonomous-payment reference;
  - Claude-compatible public tool schemas and the MCP favicon (MCP PRs #10,
    #11);
  - the site accuracy pass (site PR #4);
  - Organization/WebSite structured data.
- **Hardening:**
  - Arc mainnet config fails closed (MCP PR #5);
  - x402 facilitator-init rejection handled (MCP PR #13);
  - Vercel main-only deployments (MCP PR #18).

## Arc (D3.5C3), re-checked 2026-09-28

- **D3.5C3-CORE-NETWORK: VERIFIED.**
  - Chain ID `5042` (`eth_chainId` returns `0x13b2`).
  - RPC `https://rpc.mainnet.arc.io`.
  - Canonical USDC `0x3600000000000000000000000000000000000000`.
  - Arc public mainnet launched on 2026-09-16 (Circle pressroom).
- **D3.5C3-REGISTRIES: PARTLY UNBLOCKED.** The official
  `docs.arc.io/arc/references/contract-addresses` now lists these Arc Mainnet
  addresses. Bytecode is present at all three (read-only `eth_getCode`,
  2026-09-28).

  | Registry | Arc Mainnet address |
  |---|---|
  | IdentityRegistry | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` |
  | ReputationRegistry | `0x8004BAa17C55a88189AE136b182e5fdA19dE9b63` |
  | ValidationRegistry | `0x8004Cc8439f36fd5F9F049D9fF86523Df6dAAB58` |

  The mainnet explorer is `explorer.arc.io`. **ERC-8183 mainnet is still
  unpublished.** Do not use the testnet addresses (`0x8004A818…`,
  `0x8004B663…`, `0x8004Cb1B…`, ERC-8183 `0x0747EEf0…`) for mainnet.
- **No production Arc integration is live.** `src/arc` remains unwired, and its
  mainnet configuration requires all four addresses. Arc USDC settlement
  observation is a separate item: unbuilt, not registry-dependent, and with no
  pilot demand.

## Milestone record through 2026-09-16 (historical; status corrected 2026-09-28)

Kept for audit context. Where the 2026-09-16 label overstated activation, the
correction is marked **[corrected]**.

- **D3.4C1–C6: x402, PayBox, Turnkey, Crossmint, Coinbase/CDP and Circle
  provider evidence.**
  - Originally recorded as "COMPLETE / LIVE".
  - **[corrected]** x402 is live, and the MCP rail is on x402 v1. PayBox,
    Turnkey, Crossmint, CDP and Circle are code complete and deployed, **not
    activated**: no real provider delivery or live reference payment is
    recorded.
  - Turnkey's webhook uses Turnkey's public JWKS. The Circle listener is
    configured and still awaits the first organic outbound event.
- **D3.5C1: Ethereum Mainnet canonical USDC settlement observation: LIVE.**
  - `eip155:1` canonical Circle USDC is independently decoded from transaction
    receipts under `ethereum-usdc-finalized-head.v1`.
  - A historical transfer was observed with finality confirmed from the native
    `finalized` head.
- **D3.5C2: Tempo Mainnet settlement observation: LIVE.**
  - `eip155:4217` `pathUSD` TIP-20 transfers are decoded under
    `tempo-tip20-finalized-head.v1`.
  - The native `finalized` head is the evidentiary basis; inclusion or a
    confirmation count is never substituted.
- **D3.5C4: Solana settlement observation: LIVE.**
  - `solana:mainnet` canonical USDC SPL transfers are decoded at `finalized`
    commitment under `solana-usdc-finalized.v1`.
  - Token-account owners are resolved; top-level and inner transfers are
    supported.
  - Cannot claim `PAYMENT_IDENTITY_LINKED`.
- **D3.6A: ERC-20 allowance / revocation. LIVE BUT LIMITED.**
  - Base canonical USDC; policy preflight, uint256-max handling and
    `approve(spender, 0)` revocation.
  - Independent `Approval` observation, safe-head finality, and an optional
    historical allowance read.
  - Artifacts are not stored in the payment-only operation ledger.
- **D3.6B: token swaps. LIVE BUT LIMITED.**
  - One strict Base USDC→WETH Uniswap V3 `SwapRouter02` `exactInputSingle`
    profile.
  - Multicall, aggregators, multi-hop and native-asset boundaries are
    unsupported shapes, never inferred.
- **D3.6C: bridge. LIVE BUT LIMITED.** Circle CCTP V2 Base→Ethereum.
- **D3.6D: staking. LIVE BUT LIMITED.** Lido.
- **D4.0: self-enforcing trust invariants. COMPLETE.** Production trust canary
  (scheduled runs passing on 2026-09-28) and a CI docs-drift guard
  (`onchaindiligence-site/test/docs-drift.test.mjs`).
- **D4.1: offline verifier. COMPLETE / PUBLISHED.** Caller-supplied trust,
  zero-network verification, explicit tri-state outcomes, offline CLI.
- **D4.2: Signed Evidence Bundles. COMPLETE / PUBLISHED.**
  - `bundle_integrity`, per-artifact verifications, reconciliation and
    `limitations`.
  - First published in `agent-evidence@0.3.0`, `sdk@0.7.0` and `cli@0.4.0`;
    later versions supersede them.
- **Agent Evidence production ergonomics: PUBLISHED in `agent-evidence@0.4.0`.**
  - Six typed record helpers: `createMandateRecord`, `createRunRecord`,
    `createEvidenceRecord`, `createPolicyRecord`, `createDecisionRecord` and
    `createExecutionRecord`.
  - TypeScript only.
  - This closes `docs/MIGRATION_PLAN.md` P1 item 9. That document, dated
    2026-08-30, still lists it as next.
- **Agent Plugins 1.0 package: IMPLEMENTED / VALIDATED / MERGED, NOT
  DISTRIBUTED.**
  - `agent-plugin/`: `plugin.json`, one payment-diligence `SKILL.md`, and an
    `mcp.json` declaring `/public/mcp`.
  - Validates against the official 1.0.0 schemas.
  - Packaging only; no second integration stack.
  - Do not claim any client supports the format unless independently verified.
- **FLOP-A Technocore participation: COMPLETE.** One persistent DID, a signed
  introduction, a durable contribution and a same-DID public proof
  (`docs/TECHNOCORE_PARTICIPATION.json`). Bounded ecosystem participation, not
  token-eligibility activity.

## Shipped foundations (historical)

- **Agent Evidence v0:** specification, JSON Schemas and conformance corpus
  (P1.6).
- **Python construction and offline verification package (P1.7).** Repository
  install; not published to PyPI.
- **Real multi-provider production evidence bundle and public proof (P1.8,
  `examples/production/p1_8`).**
- **Public TypeScript/Node package (P1.9).** First published as
  `@onchaindiligence/agent-evidence@0.1.0`; current release `0.5.0`.
- **Browser-local bundle verification** on `onchaindiligence.com/verify`.
- **Technocore signed-message adapter** (`createTechnocoreEvidence`,
  `verifyTechnocoreMessage`): a verified `did:key` assertion with no truth
  claim.
- **tclk/1 coordination-evidence adapter**, plus a live non-value-bearing
  interoperability rehearsal (`docs/TCLK_REHEARSAL_RECEIPT.json`).
- **ArcFX production integration.** A sealed-bundle browser handoff, ArcFX's
  independent signer registry consulted for trust, and the key-`id`-spoofing
  regression closed.
- **Agent Evidence Interoperability Profile v1**
  (`docs/AGENT_EVIDENCE_INTEROP.md`). Signer discovery
  (`/.well-known/agent-evidence-keys`), trust-policy helpers, and a browser
  verifier handoff profile.

## WATCH detail

- **Know-Your-Agent / external agent identity.** Following the 2026-09-10
  Visa / Mastercard / Ant International announcement, await:
  - a concrete interoperable credential format;
  - a registration mechanism;
  - a portable agent identifier; or
  - a mandate/intent reference.

  Identity assertion is not authorization; authorization is not execution; a
  provider claim is not settlement. The trust boundary is in
  `docs/PRODUCT_DIRECTION.md`.
- **MCP 2026-07-28.** Keep the production legacy-compatible MCP stack unchanged
  while official `@x402/mcp` is bound to MCP SDK v1. Reopen for dual-era
  `2025-11-25` + `2026-07-28` support only when upstream preserves paid-tool
  behavior.
- **FLOP inference.** The Phase 2 caution below is unchanged; FLOP inference
  integration does not exist.

## Historical plan (superseded 2026-08-27; retained verbatim for audit context)

> **Superseded for forward implementation on 2026-08-27.** The governing
> direction is Agent Evidence and Decision Provenance. Use
> `docs/PRODUCT_DIRECTION.md`, `docs/AGENT_EVIDENCE_V0.md`,
> `docs/AGENT_EVIDENCE_INTEROP.md`, `docs/MIGRATION_PLAN.md`, and
> `docs/THREAT_MODEL.md`. The phases below are retained only as historical
> audit context; the FLOP phase is not an active implementation priority.

Security and correctness findings in `AUDIT_FINDINGS.md` take precedence over
new product surface. Compliance features should not multiply until the shared
trust model is reliable.

## Phase 1 — Trustworthy core

1. Close arbitrary signing and rotate the signing key.
2. Add user/organisation authentication, RBAC and tenant-safe database access.
3. Enforce fail-closed three-state screening (`sanctioned`, `clean`, `unknown`).
4. Repair webhook idempotency and introduce versioned database migrations.
5. Validate and check readiness before payment.
6. Centralize verdict logic across HTTP, MCP, SDK, CLI and Action.
7. Add a historical key registry and canonical, versioned attestations.
8. Patch dependencies and establish CI/security gates.

## Phase 2 — FLOP Network decision

Decision on 2026-08-26: **prepare, but do not integrate protocol code yet**.

The published FLOP material is a version 0.1 draft. Its Yellow Paper is not
final, testnet is planned for Q4 2026, mainnet for Q1 2027, and no stable public
SDK/API is currently published. The proposed agent airdrop is based largely on
testnet inference spend, but eligibility and token value are not guaranteed.

When a testnet SDK and definitive specification exist, implement an isolated
experimental adapter with these controls:

- separate package or spike repository, feature flag off by default;
- dedicated low-value testnet wallet with hard spend limits;
- no access to Ed25519 signing keys, production payer keys, customer records,
  watchlists, case notes or private compliance inputs;
- use only public/non-sensitive workloads initially, such as public sanctions
  dataset parsing, benchmark generation or documentation jobs;
- record request, model, proof, cost, latency and output hash for every job;
- verify the network's compute proof rather than trusting a successful HTTP
  response;
- set a fixed experimental budget and stop automatically at the cap;
- reassess protocol, legal, privacy and token risk before mainnet use.

This approach can establish legitimate agent testnet activity for potential
airdrop eligibility without coupling the compliance trust boundary to an
unfinished chain. Never manufacture volume solely to game eligibility rules.

## Phase 3 — Feature backlog

### P0: platform and trust

- Organisation accounts, invitations, RBAC and service accounts.
- Immutable audit log for every view, mutation, screen, export and key event.
- Versioned attestation/key registry with offline verification packages.
- Policy engine separating factual signals from configurable PASS/WARN/BLOCK
  decisions.
- Payment receipt ledger, preflight checks, idempotency keys and refund/admin
  tooling.
- Database migrations, retention policies, encrypted backups and restore drills.
- Central observability: structured logs, traces, provider health, signing
  health, payment reconciliation and alerting.

### P1: core compliance product

- Batch wallet/name/company screening with resumable jobs and signed manifests.
- Continuous monitoring with event subscriptions, scheduled rescreening and
  change alerts.
- Case workflow: assignments, comments, evidence attachments, review states and
  four-eyes approval.
- Evidence packages containing exact inputs, source versions, results,
  timestamps, policy version, signature, key status and anchor proof.
- Configurable risk rules and explicit `INCONCLUSIVE` outcomes.
- Address exposure graph with complete/partial coverage indicators and tunable
  depth/limits.
- Additional authoritative sources only where licensing and update guarantees
  are clear.

### P2: developer and agent ecosystem

- Generated SDKs from OpenAPI plus first-class `verdict`, batch and verify APIs.
- One MCP implementation backed by the canonical verdict service.
- CLI commands for offline verification, key-registry checks and batch jobs.
- GitHub Action with bundled immutable dependencies and fail-closed policies.
- Webhooks for screening completion, status changes and key rotation.
- Signed sandbox fixtures, deterministic integration tests and a public status
  page.

### P3: commercial readiness

- Usage dashboard, API-key/service-account management and spend limits.
- Receipts/invoices, organisation billing and exportable payment reconciliation.
- Published SLA, incident history, subprocessors, data processing terms and
  retention controls.
- Enterprise SSO/SCIM, regional processing choices and customer-managed
  retention/deletion.

## Phase 4 — Re-audit gates

The follow-up audit should not begin until Phase 1 changes are deployed to a
staging environment. It must include authorization/tenant tests, malicious RPC
responses, webhook concurrency/retries, payment-before-validation checks,
signature/key-rotation interoperability, dependency/secret scans, contract
tests, and production-safe canaries that spend no real money.
