# Agent Evidence migration plan

Status: governing incremental migration plan
Last updated: 2026-08-28

P0 implementation status: **code-complete**. Items 1–5 have shipped as scoped
repository changes and are covered by cross-surface tests. Production remains
intentionally **not strict-offline-ready** until the owner supplies the current
key's first defensible activation boundary; the public registry exposes this as
readiness metadata instead of allowing verifiers to infer a date.

P1 items 6, 7, and 8 are **complete**. The v0 representation boundary now has
strict Draft 2020-12 JSON Schemas, public schema URLs, deterministic
all-record-kind DSSE fixtures, language-neutral negative/tri-state cases, and a
typed Python producer/verifier package. A public-safe production bundle now
binds two real provider observations into the complete evidence-to-decision
graph. P1 item 9 (reusable first-class policy and decision production
adapters/APIs) is the next implementation slice.

### P0 completion record (2026-08-28)

- The TypeScript SDK now exports a zero-network, isomorphic v1/v2 verifier with
  caller-supplied trust material, exact `VALID | INVALID | UNVERIFIABLE` states,
  component reports, SPKI-derived key-ID validation, strict lifecycle windows,
  explicit legacy support, and no downgrade or fallback behavior.
- Online registry discovery is a separate wrapper and requires an explicit
  trust decision. The compatibility class method remains online and is clearly
  documented as such.
- CLI `verify <file> --trust <registry>` requires no account and performs no
  network access. `--fetch-keys` is explicit; exit codes are 0/3/4 for
  VALID/INVALID/UNVERIFIABLE, with 2 reserved for usage errors.
- Registry records are validated at startup/test for derived IDs, duplicates,
  algorithms, exact timestamps, intervals, lifecycle requirements, and
  replacement links. Historical source records are frozen. The registry
  publishes `strict_offline_verification_ready` and `trust_warnings`.
- A normal-rotation and emergency-compromise runbook inventories the real live
  production key without inventing its missing activation time.
- A language-neutral corpus covers RFC8785 and seven v1/v2 trust outcomes. API,
  SDK, Action, and browser canonicalizers execute the shared vectors; CLI tests
  prove zero-network behavior and online-wrapper separation.
- SDK, CLI, website examples, browser copy, and OpenAPI now use the complete
  authentic envelope for anchoring. No MCP anchor consumer exists. Existing
  anchor hashes and the API's signing bytes are unchanged.
- OpenAPI now models paid responses as `{data, attestation}`, documents all v2
  signed fields and registry readiness, and describes `issued_at` as the
  signer's assertion rather than objective time.

### P1.6 completion record (2026-08-28)

- Seven strict Draft 2020-12 schemas define common values, key records, DSSE,
  source proofs, all eight record kinds, signed payloads, and portable files.
- Exact timestamp syntax, proof discriminators, verification-material
  containers, response embedding/reference exclusivity, and precision-safe
  numeric representations are closed at the schema boundary.
- The deterministic corpus contains a real Ed25519 DSSE full graph plus cases
  for invalid signature, valid-but-noncanonical signed bytes, missing parents,
  outer/inner version mismatch, absent caller trust, and duplicate JSON names.
- Automated tests compile every schema in strict mode, recompute every record
  and bundle ID, validate graph roots/reachability, verify DSSE PAE bytes, and
  prove static fixtures match their deterministic generator.
- Schema copies are published from the website repository at the stable `$id`
  paths; embedded test keys remain explicitly untrusted hints.

### P1.7 completion record (2026-08-28)

- `python/` now contains the typed `onchaindiligence-agent-evidence` package,
  a zero-network CLI, minimal runnable examples, and build metadata suitable
  for a future PyPI release.
- The public API constructs deterministic records and payloads, validates the
  complete evidence DAG, seals Ed25519 DSSE envelopes, and returns explicit
  component-aware `VALID`, `INVALID`, or `UNVERIFIABLE` verification reports.
- Verification accepts trust only through a caller-supplied `TrustPolicy`.
  Embedded keys remain untrusted hints; missing activation boundaries,
  unavailable referenced evidence, unsupported anchor material, signature
  thresholds, lifecycle history, expiration, and freshness remain visible.
- The wheel embeds byte-identical P1.6 schemas, catalog, and core conformance
  corpus and resolves every schema reference locally. Python reproduces the
  TypeScript full-graph fixture exactly and executes the shared positive,
  negative, parser, canonicalization, and tri-state cases.
- Source DSSE, current v2, and legacy v1 proofs are supported conservatively.
  Current/legacy OnChainDiligence proofs cannot be relabeled as a different
  publisher; retired DSSE source keys without a signed proof time and legacy
  object-order ambiguity resolve to `UNVERIFIABLE` rather than invented facts.
- The local release gate is 31 Python tests, strict MyPy, Ruff formatting and
  security lint, dependency consistency/audit, wheel/sdist build and isolated
  wheel import, plus the unchanged API's 63 tests, four schema/corpus tests,
  and TypeScript typecheck. CI repeats Python tests on 3.10, 3.11, and 3.12.

### P1.8 completion record (2026-08-28)

- A repeatable workflow now captures the existing Chainalysis onchain
  sanctions oracle and SEC EDGAR production clients and signs their complete
  responses through the unchanged v2 attestation implementation.
- The committed public-safe artifact preserves each signed response object
  exactly and binds both parallel Evidence records into a complete Principal,
  Agent, Mandate, Run, Policy, Decision, and Execution DAG.
- Policy refuses execution without evidence binding the independently queried
  wallet to the SEC filer. Decision records the exact evidence and policy
  references; Execution records `withheld-not-submitted` and claims no external
  transaction.
- The P1.7 Python API creates every content ID, validates the graph, seals the
  DSSE bundle, and verifies it fully offline under an explicit caller-supplied
  trust policy. Tests prove genuine `VALID`, tamper `INVALID`, missing-trust
  `UNVERIFIABLE`, historical retirement, and zero socket access.
- Dedicated source-witness and bundle keys were generated for this reference
  capture and their private material was never persisted. This does not alter
  or work around the unresolved production API key activation boundary.

## 1. Verified current architecture

This audit covered the API, website, investigations app, TypeScript SDK, CLI,
GitHub Action, MCP server, anchoring contract, Robinhood indexer, and Tempo
spike. No `.env` file was read. Environment requirements were derived from
source references and deployment documentation only.

### API (`onchaindilige`)

- Hono/TypeScript service deployed through Vercel, stateless except for
  provider caches/circuit breakers and external chain interactions.
- MPP/Tempo payment middleware protects paid compliance routes.
- Production signing uses Node Ed25519 with a PKCS8 private key supplied by the
  hosting secret store.
- Current v2 signing input is RFC8785 JSON over
  `{schema_version, issuer, purpose, data, issued_at, key_id}`. The issuer is
  `https://api.onchaindiligence.com`; the compliance purpose is
  `compliance-screening-result`.
- Key ID is `ed25519-` plus the first 16 base64url characters of SHA-256 over
  SPKI DER.
- A versioned key-registry endpoint and exact-key endpoint exist. The active
  record comes from the loaded key; immutable historical records are
  source-controlled, but the history is currently empty.
- `valid_from` for the active key is optional configuration and can be null.
- Internal `/attest` is bearer-authenticated, but still signs arbitrary objects
  from trusted services. The app's former browser caller is now broken by
  design until an authenticated backend reconstructs authoritative evidence.
- API anchoring now accepts only a complete authentic v2 compliance envelope,
  then anchors `keccak256(signature bytes)`.
- API trust-foundation baseline: 63 tests pass plus TypeScript typecheck.
- OpenAPI accurately models v2 metadata, full signed envelopes, full-envelope
  anchoring, and the versioned key registry.
- Operational logging is partial. Payment events are structured stderr JSON,
  but there is no shared request ID, durable payment ledger, verification
  metric, or signing/anchor failure metric.

### Verification surfaces

- The SDK has a zero-network shared verifier and a separate explicit online
  discovery wrapper. The browser remains an online convenience surface but
  derives the exact key ID, enforces intervals/lifecycle, and reports the same
  three top-level states.
- The CLI consumes the shared verifier with explicit trust files and has a real
  offline/online/exit-code test suite. It sends complete envelopes to `/anchor`.
- The SDK sends complete envelopes to `/anchor`. Its older OFAC/SEC response
  type drift is outside this trust-foundation slice and remains tracked.
- The GitHub Action verifies v2 and explicit v1 exact-key results, freshness,
  SPKI identity, lifecycle, and strict validity boundaries, and runs the shared
  RFC8785 vectors.

### Evidence producers and consumers

- Compliance providers are real data integrations: Chainalysis's public
  sanctions oracle, OFAC data, Companies House, SEC EDGAR, and Tempo transfer
  exposure. They are suitable first Evidence Providers when their exact scope
  and provenance are preserved.
- API and MCP duplicate some provider clients. MCP delegates signing and the
  canonical verdict to the API, which correctly limits private-key exposure,
  but it validates returned envelope shape rather than cryptographic validity.
- The investigations app has Neon PostgreSQL migrations and real current graph
  data in code, although its README still says mock. It has no user
  authentication or tenant isolation (`OWNER = default`). Its browser evidence
  export calls the now-authenticated `/attest` route without a credential and
  is nonfunctional. It must not become the canonical evidence store.
- The Robinhood indexer is a separate read-only risk/data service backed by
  SQLite on a Railway volume. It may become a managed Evidence Provider later,
  but it is not part of the trust root. Its current test baseline has one API
  startup-responsiveness failure.
- The Tempo spike contains a separate legacy v1 signer and explicitly describes
  itself as disposable. It must not be promoted into the production evidence
  architecture. Keep it isolated or archive it after extracting any useful
  integration knowledge.

### Anchoring

- The Solidity registry is append-only, batch capable, and separates multisig
  governance from the hot issuer. Role transfers are two-step.
- It records one hash and block timestamp per item. It has no Merkle inclusion
  format or transparency-log checkpoint yet.
- Contract tests were previously present; this audit run was blocked before
  execution by a sandbox-specific Hardhat global config-directory collision,
  not a reported Solidity failure.

## 2. Highest cryptographic risks

1. **Production activation boundary:** historical source data is empty, active
   activation time is optional, no first controlled rotation has proven the
   process, and the live record currently has no defensible `valid_from`.
2. **Unsigned registry trust:** registry JSON is protected only by live HTTPS.
   A downloaded/embedded key record has no authenticated snapshot or pinned
   root, so it cannot alone establish offline publisher identity.
3. **Legacy duplicate signer:** the Tempo spike claims production equivalence
   but implements only legacy v1 semantics.
4. **First controlled rotation:** code and runbooks are ready, but production
   history cannot be proven until an intentionally bounded rotation is run.

## 3. Target architecture

The canonical artifact is the portable Agent Evidence v0 DSSE bundle specified
in `AGENT_EVIDENCE_V0.md`. The operational database may index bundle IDs,
publishers, runs, decisions, and anchors, but reconstruction from the database
is never required for verification.

Components:

- a small cross-language evidence specification and conformance corpus;
- a Python-first builder/verifier and command-line workflow;
- a TypeScript verifier used by browser, SDK, Action, and MCP where practical;
- additive `/evidence/v0` API endpoints and compliance-envelope adapters;
- explicit trust-policy inputs and signed/pinned registry snapshots;
- optional anchor/transparency proof modules; and
- adapters for existing compliance, MCP, OTel, x402/MPP, and execution receipts.

## 4. Reuse, modify, and leave unchanged

### Reuse

- Ed25519 operational signing infrastructure and SPKI-derived key IDs.
- Current attestation v2 bytes and exact-key endpoints.
- Compliance route implementations and canonical verdict evaluator.
- API-to-MCP authenticated signing boundary.
- Append-only anchor registry and role separation.
- Browser verifier security controls and client-side WebCrypto.
- Existing payment rails as economic/execution evidence sources.

### Modify incrementally

- Validate and publish complete key intervals and lifecycle metadata.
- Add authenticated, signed registry snapshots and explicit verifier trust
  policy; do not infer trust from embedded keys.
- Centralize conformance vectors and verification-state semantics.
- Fix Action, SDK, CLI, site, OpenAPI, and MCP drift.
- Add bundle/DAG/decision/execution libraries and additive APIs.
- Put app signing behind an authenticated backend that reconstructs evidence
  from authorized stored records.
- Add request IDs, structured security events, verification metrics, and a
  durable payment/anchor operational ledger.

### Leave unchanged initially

- Existing paid route URLs, response envelopes, prices, and payment middleware.
- Legacy v1 verification behavior for stored records.
- The anchoring hash used by already-created anchors.
- Provider-specific factual result shapes until versioned adapters exist.
- The main homepage until shipped evidence functionality supports its claims.
- The indexer's independent Railway/SQLite operation.

## 5. Schema and persistence migration

Stages 1-4 require no customer-data database migration. Key history remains
source-controlled initially, while a signed public snapshot becomes the
portable distribution artifact.

When optional hosted bundle indexing ships, add versioned migrations for:

- `publishers` and immutable `publisher_keys` metadata;
- `bundles` (`bundle_id`, version, owner, storage reference, verification
  summary, created time), without making stored JSON authoritative;
- `bundle_records` as an index of IDs/kinds/relations, not reconstructed truth;
- `anchors` and inclusion proofs; and
- append-only key/publisher security events.

Tenant authentication must land before customer bundle or run persistence in
the app. Existing `OWNER = default` tables cannot safely store multi-customer
evidence.

## 6. API and deployment migration

- Add new routes under `/evidence/v0`; never overload `/attest`.
- Publish OpenAPI schemas generated or tested against shared fixtures.
- Introduce new deployment configuration in report-only mode before making it
  boot-critical. In particular, inventory the current key activation time and
  publish the old key record before the first production key swap.
- Perform normal rotation as two deployments: publish the retiring record
  first, verify exact-key lookup, then activate the replacement key and verify
  old/new fixtures across API, Python, TS, CLI, Action, and browser.
- Emergency compromise uses a separate runbook and fails closed; do not label a
  compromise as ordinary retirement.
- Homepage repositioning follows a real vertical slice: bundle construction,
  multi-source DAG, decision, execution, and independent verification must be
  operational before the full new headline is deployed.

## 7. Prioritized production implementation queue

### P0 — repair the existing trust foundation

1. **Complete.** Fix the GitHub Action to verify v2 exact-key envelopes, key validity windows,
   lifecycle status, issuer/purpose, freshness, and legacy v1 explicitly. Add
   tamper, unknown, retired, compromised, validity-window, and unsupported
   version tests.
2. **Complete.** Add an isomorphic verifier API that accepts caller-supplied key records with
   no network behavior; keep online discovery as an explicit wrapper. Introduce
   `VALID`, `INVALID`, and `UNVERIFIABLE` component-aware reports.
3. **Complete.** Make CLI verification truly offline with an explicit trust-root/key-registry
   file and add tests. Network key fetching becomes opt-in.
4. **Complete (owner activation boundary pending).** Validate registry history at boot/test, publish full lifecycle fields, add
   RFC8785 conformance vectors, and document/test normal and emergency rotation.
5. **Complete.** Correct SDK/CLI/site `/anchor` calls and OpenAPI/docs without changing the
   server's new complete-envelope requirement.

### P1 — portable evidence foundation

6. **Complete.** Publish the Agent Evidence v0 JSON Schemas and language-neutral conformance
   fixtures.
7. **Complete.** Implement the Python package first: deterministic records,
   DSSE sealing, DAG validation, trust policy, and offline verification.
8. **Complete.** Implement a real bundle slice using at least two existing production
   compliance results; preserve each original envelope verbatim.
9. Add reusable first-class policy and decision production adapters/APIs with
   exact evidence references. P1.8 exercises the record kinds in the reference
   workflow; this item productizes their construction without changing paid
   routes.
10. Attach and verify one real onchain/financial execution receipt without
    claiming unsupported causality.

### P2 — product surfaces

11. Add compliance-to-evidence adapters behind additive API routes.
12. Reposition the main website using only shipped APIs and link the real CLI
    and browser verifier.
13. Upgrade the public browser verifier to inspect the bundle DAG, decisions,
    executions, trust modes, and uncertainty.
14. Add minimal MCP verify/bundle metadata support, then selective OTel mapping.
15. Add the TypeScript construction SDK after the Python behavior and fixtures
    are stable.

### Deferred

Managed witness, local witness, transparency enhancements, broader publisher
registry, and selective disclosure follow the core. An unrestricted HTTP proxy,
custody, a token, a proprietary identity system, and broad workflow engine are
not planned.

## 8. Decisions requiring owner input

Normal implementation is unblocked. These later decisions need the owner:

- choose and commit the package/repository license, confirm the public package
  name, and configure a PyPI Trusted Publisher before the first public release;
- the offline registry root custody model and threshold signers;
- the customer identity provider before app persistence becomes multi-tenant;
- retention/privacy policy for optional hosted raw evidence;
- the legal entity and reviewed terms before stronger compliance claims; and
- whether the Tempo spike is archived or retained as a clearly isolated lab.
