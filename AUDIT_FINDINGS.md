# OnchainDiligence audit findings register

Last updated: 2026-08-26

This is the durable source of truth for the August 2026 audit. A finding is not
closed merely because code was written: `FIXED LOCALLY` still requires review,
deployment, configuration where applicable, and production verification.

Status values: `OPEN`, `IN PROGRESS`, `DECISION REQUIRED`, `FIXED LOCALLY`,
`VERIFIED`, `ACCEPTED RISK`.

## Critical

| ID | Finding | Repository | Status | Exit criteria |
|---|---|---|---|---|
| OD-001 | Public `/attest` signs arbitrary caller-supplied claims with the production key | API, app, MCP | FIXED LOCALLY | Authenticated server-to-server route deployed; app export rebuilt behind authenticated backend; old key rotated and historical key status published; production canary receives 401 |
| OD-002 | Watchlist, case, notes, deletion and rescreen APIs have no authentication or tenant isolation | App | DECISION REQUIRED | Identity provider selected; organisation/user IDs replace `OWNER = default`; every query is authorized; cron uses separate machine authentication; access-control tests pass |
| OD-003 | JSON-RPC errors/malformed oracle responses become or are cached as clean | App | FIXED LOCALLY | Exact ABI boolean decoder deployed in browser and server functions; error/malformed-result tests pass; existing clean cache invalidated |
| OD-004 | Tempo webhook reserves its dedupe ID before processing, permanently dropping failed retries | App | FIXED LOCALLY | Failure releases reservation or uses a transactional state machine; failed screening returns non-2xx; retry integration test passes |

## High

| ID | Finding | Repository | Status | Exit criteria |
|---|---|---|---|---|
| OD-005 | Multiple paid routes validate inputs after payment middleware | API | FIXED LOCALLY | Side-effect-free guards now precede payment on all paid routes and web wallet checks have a health gate; add route-level no-challenge tests, deploy and verify |
| OD-006 | `/verdict` can PASS after zero or partial counterparty screening and only examines the first 25 | API | FIXED LOCALLY | Exposure now distinguishes complete/partial/failed and incomplete work yields WARN; add route-level and truncation regression tests, deploy and verify |
| OD-007 | Standalone MCP verdict logic has diverged from the HTTP verdict | MCP, API | OPEN | One shared verdict implementation or one canonical signed API call serves every channel; contract tests compare outputs |
| OD-008 | Paid MCP/API responses may be returned unsigned when signing is unavailable | MCP, API | FIXED LOCALLY | Production boot requires signing; MCP probes authenticated signing readiness before payment and never returns unsigned success; add outage integration test, deploy and verify no settlement |
| OD-009 | Required payment/signing configuration can fail open; MCP defaults to testnet | API, MCP | FIXED LOCALLY | API requires payment/signing credentials; MCP requires explicit network, payment credentials and signing token with length validation; deploy and verify startup failures |
| OD-010 | GitHub Action downloads executable code while exposing the payer key and exits green after screening failures | Action | FIXED LOCALLY | Action uses a committed bundled payment client with pinned/locked build dependencies, passes only the payer key to it, verifies fresh signatures, and fails closed; verify bundle reproducibility in CI and publish a new immutable Action tag |
| OD-011 | Live terms/privacy documents contain unresolved legal placeholders | Site | DECISION REQUIRED | Qualified legal review; entity, refunds, SLA, liability, governing law, retention, controller, subprocessors and transfers completed and published |
| OD-012 | Production dependency vulnerabilities, especially API/MCP/SDK/Tempo `viem`/`ws` chains | API, MCP, SDK, Tempo | OPEN | Dependencies upgraded and compatibility-tested; unused MCP packages removed; production audit has no unaccepted high findings |
| OD-013 | Attestation verifier renders untrusted metadata through `innerHTML` | Site | FIXED LOCALLY | Metadata/data now use DOM nodes and `textContent`, classes are allowlisted, and baseline security headers/CSP are configured; add browser regression test, deploy and verify headers |
| OD-014 | App database has no versioned schema, migrations, constraints or restore procedure | App | FIXED LOCALLY | Versioned baseline now defines tables, foreign keys, checks and indexes with application guidance; compare/apply in staging and complete a backup/restore drill |

## Medium

| ID | Finding | Repository | Status | Exit criteria |
|---|---|---|---|---|
| OD-015 | Only the current attestation key is published; rotation breaks historical verification | API, site, SDK | OPEN | Immutable registry indexed by `key_id` publishes active/retired/revoked/compromised keys; verifier selects the exact key |
| OD-016 | Signing uses ordinary `JSON.stringify`, not canonical cross-language encoding or domain separation | API, SDK, site | OPEN | Versioned RFC 8785 JCS or equivalent scheme added with issuer, purpose and schema version; legacy verification retained |
| OD-017 | Serverless rate limiting is instance-local; webhook body was unbounded; app mutations are unlimited | API, app | IN PROGRESS | Webhook now has a local 1 MiB cap; shared rate limits and route-specific quotas remain to be implemented and load-tested |
| OD-018 | Health checks often prove reachability rather than authenticated readiness | API | OPEN | Provider-specific probes validate usable responses/credentials and payment routes consume readiness, not generic reachability |
| OD-019 | Documentation, prices, versions, tool counts and implementation claims have drifted | All | OPEN | Generated reference docs and automated drift checks agree with shipped route/tool manifests and package versions |
| OD-020 | SEC company name matching silently selects ambiguous prefix/substring results | API, MCP | OPEN | Exact ticker/CIK/name resolution or explicit candidates; ambiguity can never be signed as a definitive company result |
| OD-021 | OFAC `list_date` is the local retrieval date, not the source list publication date | API, MCP | OPEN | Field renamed to `retrieved_at` or populated from authoritative source metadata |
| OD-022 | `/anchor` accepts arbitrary signature-shaped data without proving it is an OnchainDiligence attestation | API, Anchor | OPEN | Complete envelope and known `key_id` signature verified before anchoring, or endpoint/documentation explicitly becomes generic blob anchoring |
| OD-023 | Registry issuer transfer is one-step and vulnerable to irreversible operator error | Anchor | OPEN | Two-step `pendingIssuer`/`acceptIssuer`, tests, multisig ownership and operational runbook |
| OD-024 | CI and secret scanning are incomplete; broad allowlists can suppress real secrets | All | OPEN | Test/typecheck/build/security workflows cover all repos; actions pinned to commits; secret allowlists narrowed |
| OD-025 | Case wallet insertion does not first authorize ownership of the parent case | App | FIXED LOCALLY | Add-wallet now inserts through an owner-filtered parent SELECT and deletion joins through the owner-filtered case; add cross-tenant tests after authentication lands |
| OD-026 | User strings are weakly bounded and raw database error messages can reach clients | App | FIXED LOCALLY | Case/watchlist strings now have application and database size limits; database details remain server-side and clients receive stable generic errors |
| OD-027 | MCP claims a matching sanctions programme although the oracle returns only a boolean | MCP | FIXED LOCALLY | Tool description now states that the oracle returns a boolean without programme-level case detail; publish and verify registry metadata |
| OD-028 | Live verifier sample fetches a paid endpoint without a payment client | Site | OPEN | Static valid signed fixture or dedicated non-production sample endpoint verifies successfully without payment |
| OD-029 | Tempo spike documentation/scripts do not match the repository state | Tempo spike | OPEN | Decide promote/archive; align scripts, README and tested deployment path |

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
