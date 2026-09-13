# OnchainDiligence audit findings register

Last updated: 2026-09-12

This is the durable source of truth for the August 2026 audit. A finding is not
closed merely because code was written: `FIXED LOCALLY` still requires review,
deployment, configuration where applicable, and production verification.

Status values: `OPEN`, `IN PROGRESS`, `DECISION REQUIRED`, `FIXED LOCALLY`,
`VERIFIED`, `ACCEPTED RISK`. The 2026-09-12 pass additionally distinguishes
`VERIFIED PREVIEW` (confirmed on a non-production deployment only) from
`VERIFIED PRODUCTION` (confirmed against the live production endpoint) where
that distinction changes what a reader should trust; older rows keep their
original `VERIFIED` wording and were not re-audited unless noted below.

## Critical

| ID | Finding | Repository | Status | Exit criteria |
|---|---|---|---|---|
| OD-001 | Public `/attest` signs arbitrary caller-supplied claims with the production key | API, app, MCP | IN PROGRESS | Authenticated server-to-server route deployed and production canary receives 401; app export rebuilt behind authenticated backend; old key rotated and historical key status published |
| OD-002 | Watchlist, case, notes, deletion and rescreen APIs have no authentication or tenant isolation | App | VERIFIED PRODUCTION | 2026-09-12: `requireAuth()` (Clerk `verifyToken().sub`) replaces the hardcoded `OWNER='default'` constant on every case/watchlist route; `rescreen.js` uses a separate `CRON_SECRET` bearer path for Vercel Cron. Merged `main` (`dec1a3c`+merge), deployed production (`dpl_BVRnJD9fAvvHJCSWKnNQWjFxicUD`), 8/8 focused tests pass. 2026-09-13: full production verification completed with two real, independently-authenticated Clerk accounts (a live browser session, not faked): own-workspace read and write both succeed; a second account's read/write against the first account's case both correctly rejected (404 "case not found"). One response-honesty bug found in the process (see OD-035) — the owner boundary itself was already correctly enforced, only the response code was wrong |
| OD-003 | JSON-RPC errors/malformed oracle responses become or are cached as clean | App | FIXED LOCALLY | Exact ABI boolean decoder deployed in browser and server functions; error/malformed-result tests pass; existing clean cache invalidated |
| OD-004 | Tempo webhook reserves its dedupe ID before processing, permanently dropping failed retries | App | FIXED LOCALLY | Failure releases reservation or uses a transactional state machine; failed screening returns non-2xx; retry integration test passes |

## High

| ID | Finding | Repository | Status | Exit criteria |
|---|---|---|---|---|
| OD-005 | Multiple paid routes validate inputs after payment middleware | API | VERIFIED | All paid routes have offline no-challenge regression tests; representative production wallet, name, company, US company, diligence and web inputs returned 400 without a payment challenge |
| OD-006 | `/verdict` can PASS after zero or partial counterparty screening and only examines the first 25 | API | FIXED LOCALLY | Exposure distinguishes complete/partial/failed and incomplete work yields WARN; regression tests cover screen failures and 26 counterparties with one omitted; verify a paid/live WARN response before closing |
| OD-007 | Standalone MCP verdict logic has diverged from the HTTP verdict | MCP, API | VERIFIED | API owns one canonical evaluator used by public and authenticated internal routes; MCP delegation and policy contract tests pass; production internal readiness rejects unauthenticated calls, healthy MCP verdict requests reach the 402 challenge, and malformed input returns 400 without a payment challenge |
| OD-008 | Paid MCP/API responses may be returned unsigned when signing is unavailable | MCP, API | FIXED LOCALLY | Production boot requires signing; MCP probes authenticated signing readiness before payment and never returns unsigned success; add outage integration test, deploy and verify no settlement |
| OD-009 | Required payment/signing configuration can fail open; MCP defaults to testnet | API, MCP | VERIFIED | API and MCP require explicit payment/signing configuration; production was observed failing closed when the signing token was absent, then recovered only after the shared credential was configured and both services were redeployed |
| OD-010 | GitHub Action downloads executable code while exposing the payer key and exits green after screening failures | Action | FIXED LOCALLY | Action uses a committed bundled payment client with pinned/locked build dependencies, passes only the payer key to it, verifies fresh signatures, and fails closed; verify bundle reproducibility in CI and publish a new immutable Action tag |
| OD-011 | Live terms/privacy documents contain unresolved legal placeholders | Site | DECISION REQUIRED | Qualified legal review; entity, refunds, SLA, liability, governing law, retention, controller, subprocessors and transfers completed and published |
| OD-012 | Production dependency vulnerabilities, especially API/MCP/SDK/Tempo `viem`/`ws` chains | API, MCP, SDK, Tempo | IN PROGRESS | API, SDK and Tempo are upgraded, compatibility-tested and at zero npm advisories; MCP still has six high findings, mostly from the legacy `x402-mcp`/`x402` wallet dependency graph, and its pre-existing dirty package files are excluded from current commits |
| OD-013 | Attestation verifier renders untrusted metadata through `innerHTML` | Site | FIXED LOCALLY | Metadata/data now use DOM nodes and `textContent`, classes are allowlisted, and baseline security headers/CSP are configured; add browser regression test, deploy and verify headers |
| OD-014 | App database has no versioned schema, migrations, constraints or restore procedure | App | FIXED LOCALLY | Versioned baseline now defines tables, foreign keys, checks and indexes with application guidance; compare/apply in staging and complete a backup/restore drill |
| OD-030 | GitHub Action verifies legacy v1 bytes while production paid routes emit v2 attestations | Action | FIXED LOCALLY | Action resolves the exact key, verifies v2 RFC8785 issuer/purpose bytes, retains explicit v1 compatibility, enforces lifecycle intervals/status, and passes tamper/lifecycle tests; publish a new immutable Action tag and run a paid production canary |
| OD-033 | `/x402/*` payment-challenge middleware discarded its own return value; every paid HTTP route on mcp.onchaindiligence.com returned 500 instead of 402 with no payment header, so no agent could pay on the HTTP x402 rail | MCP | VERIFIED PRODUCTION | Self-inflicted regression from an earlier session's OPS-V2 work, found while live-verifying an unrelated pricing fix. `return await x402PaymentMiddleware(c, next)` (commit `41986bf`, merged `main` `8a8a023`, deployed `dpl_9Nf5dzMSSipLzbxqp1Yx4KFpySPi`). Confirmed live: `/x402/screen`, `/x402/verdict`, `/x402/preflight-bridge`, `/x402/preflight-staking` all correctly 402 with no payment header, no 500s |
| OD-034 | `POST /anchor` hangs for the full 300-second Vercel function timeout regardless of body validity, instead of failing fast | API | VERIFIED PRODUCTION | Discovered 2026-09-12 via Vercel runtime logs (`Vercel Runtime Timeout Error: Task timed out after 300 seconds`). Fixed (`2675400` "bound anchor request handling", `259b689` "lock anchor body-read boundary") and merged to `main`. 2026-09-13: confirmed live in production -- `POST /anchor` with a malformed body now responds in ~250ms with a normal `400`, never a hang. Also covered by the new production trust canary's `malformed-artifact-safe` check (see OD-018) |
| OD-035 | `DELETE /api/cases?id=<non-owned-or-missing-id>` returned `200 {ok:true}` even when zero rows matched the owner-scoped delete | App | FIXED LOCALLY | Found 2026-09-13 during OD-002's live cross-workspace verification: a second account's delete against the first account's case returned a false success. The owner boundary itself was already correct (`DELETE FROM cases WHERE id = ? AND owner = ?` cannot match another owner's row) -- this was a response-honesty bug, not a security defect. Fixed by checking `RETURNING id` and returning 404 on zero rows, matching the existing pattern already used by the wallet-delete and add-wallet branches in the same file. 2/2 new focused tests pass (`test/cases-delete.test.mjs`), 28/28 total, build clean. Not yet deployed to production this pass |

## Medium

| ID | Finding | Repository | Status | Exit criteria |
|---|---|---|---|---|
| OD-015 | Only the current attestation key is published; rotation breaks historical verification | API, site, SDK | IN PROGRESS | Source-controlled registry and exact-key verification are implemented locally; deploy them, record the current key's activation time, perform the first controlled rotation, and retain the old public key with explicit status |
| OD-016 | Signing uses ordinary `JSON.stringify`, not canonical cross-language encoding or domain separation | API, SDK, site | VERIFIED | Production version 2 uses RFC 8785 canonical JSON with issuer, purpose and schema version; browser verification passed against the exact registry key and rejected one-field tampering; SDK/site retain legacy v1 verification |
| OD-017 | Serverless rate limiting is instance-local; webhook body was unbounded; app mutations are unlimited | API, app | IN PROGRESS | Webhook now has a local 1 MiB cap; shared rate limits and route-specific quotas remain to be implemented and load-tested |
| OD-018 | Health checks often prove reachability rather than authenticated readiness | API | IN PROGRESS | 2026-09-13: added a scheduled, read-only production trust canary (`tools/canary/run.ts`, `.github/workflows/canary.yml`, runs every 6h and on demand) covering 7 invariants: internal `/attest` rejects unauthorized callers, a malformed attestation envelope is safely rejected (never `VALID`, never a hang -- also the OD-034 regression guard), `HEAD /mcp` stays bounded, a malformed paid request fails before payment, the published key registry is internally consistent, the app's data-plane API rejects unauthenticated calls, and the MCP server's public discovery still advertises its core capabilities. Results post to the workflow run's own step summary (`GITHUB_STEP_SUMMARY`) -- no new secrets or external services. Still open: this covers 7 specific invariants, not full authenticated-readiness coverage of every provider/route |
| OD-019 | Documentation, prices, versions, tool counts and implementation claims have drifted | All | IN PROGRESS | 2026-09-13: added `onchaindilige-site`'s `test/docs-drift.test.mjs`, wired into that repo's CI, guarding docs.html's per-route prices (vs the live API's own root manifest), SDK method casing, MCP action-evidence categories and networks (vs the MCP server's own public `/.well-known/x402` manifest), anchor network wording, and the CLI minimum-version note (vs npm's published latest) against live authoritative sources. Still open: this guards five specific facts, not the full drift-detection automation across every doc page the original exit criteria calls for |
| OD-020 | SEC company name matching silently selects ambiguous prefix/substring results | API, MCP | FIXED LOCALLY | CIK/ticker/exact-name matches resolve deterministically; prefix/substring resolves only when unique; ambiguous queries return bounded sorted candidates with no selected CIK; API tests and both typechecks pass; deploy and verify a live ambiguous query |
| OD-021 | OFAC `list_date` is the local retrieval date, not the source list publication date | API, MCP | FIXED LOCALLY | Both surfaces now return the full local fetch timestamp as `retrieved_at`, explicitly documented as retrieval rather than OFAC publication time; typechecks and API tests pass; deploy and verify a paid response |
| OD-022 | `/anchor` accepts arbitrary signature-shaped data without proving it is an OnchainDiligence attestation | API, Anchor | FIXED LOCALLY | The complete v2 compliance envelope is size-bounded and cryptographically verified against a known active/retired key before payment; tampering, unknown keys, fixture purpose, and revoked/compromised keys are rejected; deploy and verify invalid envelopes never receive a payment challenge |
| OD-023 | Registry issuer transfer is one-step and vulnerable to irreversible operator error | Anchor | FIXED LOCALLY | Governance and operational issuer roles are separated; issuer and ownership transfers are two-step and cancellable; mainnet deployment requires an explicit contract-based owner distinct from the issuer; 15 contract tests and a rotation/compromise runbook pass; redeploy and verify roles on-chain |
| OD-024 | CI and secret scanning are incomplete; broad allowlists can suppress real secrets | All | OPEN | Test/typecheck/build/security workflows cover all repos; actions pinned to commits; secret allowlists narrowed |
| OD-025 | Case wallet insertion does not first authorize ownership of the parent case | App | FIXED LOCALLY | Add-wallet now inserts through an owner-filtered parent SELECT and deletion joins through the owner-filtered case; add cross-tenant tests after authentication lands |
| OD-026 | User strings are weakly bounded and raw database error messages can reach clients | App | FIXED LOCALLY | Case/watchlist strings now have application and database size limits; database details remain server-side and clients receive stable generic errors |
| OD-027 | MCP claims a matching sanctions programme although the oracle returns only a boolean | MCP | FIXED LOCALLY | Tool description now states that the oracle returns a boolean without programme-level case detail; publish and verify registry metadata |
| OD-028 | Live verifier sample fetches a paid endpoint without a payment client | Site | VERIFIED | Production verifier fetches the free fixed signed `verification-fixture`; end-to-end browser verification passed without payment or a real counterparty screen |
| OD-029 | Tempo spike documentation/scripts do not match the repository state | Tempo spike | OPEN | Decide promote/archive; align scripts, README and tested deployment path |
| OD-031 | SDK, CLI and website still send signature-only `/anchor` requests after the API began requiring a complete authentic v2 envelope | SDK, CLI, Site | OPEN | All clients submit the complete envelope, compatibility impact is documented, tests reject signature-only calls, and published docs contain only functioning examples |
| OD-032 | SDK, CLI and browser call verification local/offline while requiring live key-registry access and not enforcing key validity intervals | SDK, CLI, Site | VERIFIED PRODUCTION | 2026-09-12, CLI: `verify` requires either `--trust <keys.json>` (genuinely offline — `test/prevent-network.mjs` patches `globalThis.fetch` to throw and the test still passes) or the separate explicit `--fetch-keys` flag; omitting both is a hard error, never a silent default. 4/4 focused tests pass, merged `main` (`664cd60`). SDK's existing offline-verification test suite re-ran clean (153/153); site's existing offline-trust test re-ran clean (75/75). 2026-09-13: CLI 0.2.0 and SDK 0.6.0 both published to npm (`npm view` confirms both live), CLI tagged `v0.2.0` at `664cd60` |

## Phase 1 change log

- 2026-08-26: added strict shared JSON-RPC/ABI decoding. RPC errors, missing
  results and malformed values now become unknown/errors and are not cached as
  clean.
- 2026-08-26: bounded Tempo webhook raw bodies to 1 MiB.
- 2026-08-26: failed webhook processing now releases the dedupe reservation and
  failed wallet screens cause a retryable response.
- 2026-08-26: protected `/attest` with a constant-time server-to-server bearer
  check and a rate limit; API production configuration now requires its payment
  challenge secret, signing key and internal attestation token.
- 2026-08-26: standalone MCP sends the internal bearer credential when signing.
- 2026-08-26: direct exposure now reports complete/partial/failed coverage;
  incomplete or failed exposure can no longer produce a full PASS verdict.
- 2026-08-26: all paid routes now run cheap input validation before payment;
  web wallet screening also checks oracle readiness before issuing a challenge.
- 2026-08-26: verifier metadata/data rendering no longer uses attacker-controlled
  `innerHTML`; class names are allowlisted and baseline browser security headers
  are configured for the site.
- 2026-08-26: MCP now requires an explicit x402 network and signing credential,
  probes an authenticated signing-readiness endpoint before payment middleware,
  and cannot return unsigned paid success envelopes.
- 2026-08-26: GitHub Action now pins the CLI release, disables install scripts,
  avoids shell execution, verifies fresh Ed25519 envelopes/address binding, and
  fails closed on errors or unscreened addresses by default. Bundling remains.
- 2026-08-26: Action payment execution now uses a committed esbuild artifact
  generated from exact dependency versions. Runtime `npm`/`npx` installation is
  removed and the child process receives only `PAYER_KEY`.
- 2026-08-26: app now has a versioned PostgreSQL baseline with keys, foreign
  keys, checks and indexes. Case-wallet mutation is owner-bound in SQL; user
  strings are bounded and raw database errors no longer reach clients.
- 2026-08-27: configured one generated Production-only internal attestation
  credential in the API and MCP Vercel projects, redeployed both, and verified
  API health 200, unauthenticated signer calls 401, MCP root 200 and unpaid paid
  route 402. No `.env` file was accessed.
- 2026-08-27: added version 2 domain-separated RFC 8785 attestation signing,
  an exact-key status registry, legacy verification in SDK/site, and a fixed
  signed sandbox fixture for the verifier sample. First controlled key rotation
  and production interoperability verification remain.
- 2026-08-27: production browser verification resolved the exact active key,
  verified the version 2 fixture locally, and rejected a copy with one signed
  boolean changed. Canonical signing and the free sample are now verified.
- 2026-08-27: centralized PASS/WARN/BLOCK policy in the API; MCP now delegates
  verdicts to an authenticated canonical route and checks its readiness before
  payment. Offline contracts and production 401/402/invalid-input paths passed.
- 2026-08-27: API, SDK and Tempo dependency trees were upgraded to fixed
  viem/ws and Hono-related versions. All three report zero npm advisories and
  pass their available build/type/test checks; MCP's legacy payment wrapper
  remains the dependency-remediation blocker.
- 2026-08-27: added pre-payment route regression coverage and a 26-counterparty
  truncation case. The API now has 49 passing tests, and representative
  malformed production requests returned 400 without payment challenges.
- 2026-08-27: SEC EDGAR lookup no longer selects the first prefix/substring
  match. Ambiguous names return a bounded deterministic candidate set with
  `match_status: ambiguous` and no selected CIK on both API and MCP surfaces.
- 2026-08-27: OFAC name-screen provenance now reports the full local source
  fetch timestamp as `retrieved_at`; the misleading `list_date` field was
  removed from API, MCP and the OpenAPI schema.
- 2026-08-27: adopted Agent Evidence and Decision Provenance as the governing
  product direction; added the v0 specification, migration plan and threat
  model after auditing the current multi-repository implementation.
- 2026-08-27: repaired the GitHub Action's production v2 verifier. It now
  resolves the exact historical key, reconstructs RFC8785 issuer/purpose bytes,
  enforces key status and validity windows, and retains an explicit legacy v1
  path without downgrade fallback.
- 2026-09-12: fixed a critical self-inflicted regression (OD-033) that broke
  the 402 payment-challenge path on every paid HTTP route on
  mcp.onchaindiligence.com; found, fixed and verified live in production the
  same session it was introduced would have been caught in.
- 2026-09-12: onchaindilige (API): C1 direct-exposure now fails closed on an
  HTTP 200 response with a missing/unexpected `data` shape instead of treating
  it as "no transfers found"; M6 every paid route (including `/anchor`) now
  gates on signing readiness before payment; M12 removed the hardcoded default
  Tempo RPC URL/chain ID so `/anchor` requires explicit configuration and
  `/anchor`/`/anchored` report the real network (mainnet/moderato-testnet/
  unknown) instead of assuming. 73/73 tests pass, typecheck clean, merged
  `main` (`373a705`), deployed production (`dpl_GSx8QrEc2uHyFattAGYqKKcCtFVD`).
  While verifying this, discovered OD-034 (`/anchor` request hang), which this
  fix does not resolve — recorded separately, still open.
- 2026-09-12: app (OD-002): wired Clerk server-side session verification into
  every case/watchlist/rescreen route, replacing the hardcoded shared owner.
  Fail-closed unauthenticated rejection verified in production; per-workspace
  isolation verification remains open pending a real browser session (see
  OD-002 row).
- 2026-09-12: CLI and SDK (OD-032): confirmed the offline-verification
  contract is genuine end-to-end (CLI, SDK, site), fixed a stale SDK-tarball
  dependency pin in the CLI, fixed a missing `BASE_USDC` import in the SDK
  README and in the site's `developers.html` quickstart sample (same bug
  class, caught independently in each surface), and documented
  `CircleCommerceExecutor`. Both packages merged to `main` (CLI 0.2.0,
  `664cd60`; SDK 0.6.0, `cfcbfcb`) but not published — npm auth unavailable
  in this environment. SDK 0.5.0 was left untouched on the registry.
- 2026-09-12: site (OD-019, partial): added a "What's shipped today" coverage
  summary to `developers.html` (settlement networks, commerce executors,
  action-evidence types) with every listed item individually confirmed
  against the actual MCP/SDK source before publishing. This closes only the
  specific items touched this pass, not the full drift-detection automation
  OD-019's exit criteria calls for, and does not include the larger docs
  information-architecture rewrite (settlement-network pages, provider-
  evidence pages, Arc docs) — that remains explicitly deferred, not done.
- 2026-09-13 (D4.0, ops/docs track): confirmed OD-034 fixed and live in
  production (a separate, concurrent fix -- not this track's work). Ran
  full production cross-workspace auth verification for OD-002 with two
  real Clerk accounts, closing it; found and fixed OD-035 (the delete
  response-honesty bug this surfaced). Added a scheduled, read-only
  production trust canary (`onchaindilige/tools/canary/run.ts` +
  `.github/workflows/canary.yml`, every 6h and on demand, 7 invariants,
  results in the workflow's own step summary) advancing OD-018. Added a
  docs-drift CI guard (`onchaindilige-site/test/docs-drift.test.mjs`,
  wired into that repo's CI) advancing OD-019, and committed that repo's
  `.github/workflows/` and `.gitleaks.toml`, which existed locally but had
  never actually been committed (so no CI had ever run there). Confirmed
  CLI 0.2.0 and SDK 0.6.0 are both now published to npm and the CLI's
  `v0.2.0` tag is pushed, closing the publish blocker noted in OD-032.
