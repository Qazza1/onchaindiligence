# OnchainDiligence product roadmap

Last updated: 2026-08-26

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

