# Agent Evidence migration plan

Status: governing incremental migration plan
Last updated: 2026-08-27

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
- API baseline: 59 tests pass. Canonicalization has only a small happy-path
  test set, not the RFC8785 conformance corpus.
- OpenAPI has drift: its generic Attestation description still describes the
  legacy three-field signing input, and some response schemas do not accurately
  model the outer `{data, attestation}` envelope.
- Operational logging is partial. Payment events are structured stderr JSON,
  but there is no shared request ID, durable payment ledger, verification
  metric, or signing/anchor failure metric.

### Verification surfaces

- The SDK and browser reconstruct v2 JCS and retain an explicit legacy v1 path.
  Both fetch the exact key live and accept active/retired status, but neither is
  offline. Neither currently enforces the key validity interval.
- The CLI calls the SDK using an inert account object for free verification,
  needs live key discovery, collapses results to valid/invalid, has no test
  suite, and still sends only a signature to `/anchor`.
- The SDK also sends only a signature to `/anchor`, while the API now requires
  a full envelope. The SDK's OFAC and SEC types have drifted from API responses.
- The GitHub Action's paid-result verifier still reconstructs legacy v1 bytes
  and fetches only the current key. Production v2 paid results therefore fail
  its verification path even though its two legacy-oriented tests pass.
- The website's verifier is client-side but online-key-dependent. Some copy
  overstates the signed timestamp and source truth. Public SDK/anchor examples
  still use the removed signature-only request.

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

1. **Consumer/signing-format drift:** the Action verifies legacy bytes against
   production v2 responses. SDK/CLI/site anchoring also uses an obsolete body.
2. **Offline-verification claim gap:** all current consumer verifiers need a
   live registry and have no pinned trust-root input.
3. **Incomplete key lifecycle:** historical source data is empty, active
   activation time is optional, no first controlled rotation has proven the
   process, and consumers do not uniformly enforce validity intervals.
4. **Unsigned registry trust:** registry JSON is protected only by live HTTPS.
   A downloaded/embedded key record has no authenticated snapshot or pinned
   root, so it cannot alone establish offline publisher identity.
5. **Insufficient canonicalization conformance tests:** three implementations
   duplicate security-sensitive JCS code with no official number/string corpus
   and no duplicate-key parser test.
6. **Verification result ambiguity:** current `valid: boolean` loses the
   difference between tampered, distrusted, unknown-key, stale, and unsupported.
7. **Legacy duplicate signer:** the Tempo spike claims production equivalence
   but implements only legacy v1 semantics.
8. **Timestamp overclaim:** an Ed25519 signature authenticates the signer's
   timestamp assertion; only an independently verified checkpoint establishes
   an external no-later-than time.

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

1. Fix the GitHub Action to verify v2 exact-key envelopes, key validity windows,
   lifecycle status, issuer/purpose, freshness, and legacy v1 explicitly. Add
   tamper, unknown, retired, compromised, validity-window, and unsupported
   version tests.
2. Add an isomorphic verifier API that accepts caller-supplied key records with
   no network behavior; keep online discovery as an explicit wrapper. Introduce
   `VALID`, `INVALID`, and `UNVERIFIABLE` component-aware reports.
3. Make CLI verification truly offline with an explicit trust-root/key-registry
   file and add tests. Network key fetching becomes opt-in.
4. Validate registry history at boot/test, publish full lifecycle fields, add
   RFC8785 conformance vectors, and document/test normal and emergency rotation.
5. Correct SDK/CLI/site `/anchor` calls and OpenAPI/docs without changing the
   server's new complete-envelope requirement.

### P1 — portable evidence foundation

6. Publish the Agent Evidence v0 JSON Schemas and language-neutral conformance
   fixtures.
7. Implement the Python package first: deterministic records, DSSE sealing,
   DAG validation, trust policy, and offline verification.
8. Implement a real bundle slice using at least two existing production
   compliance results; preserve each original envelope verbatim.
9. Add first-class policy and decision records with exact evidence references.
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

- the offline registry root custody model and threshold signers;
- the customer identity provider before app persistence becomes multi-tenant;
- retention/privacy policy for optional hosted raw evidence;
- the legal entity and reviewed terms before stronger compliance claims; and
- whether the Tempo spike is archived or retained as a clearly isolated lab.
