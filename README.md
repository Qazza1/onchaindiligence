# OnChainDiligence — Verifiable evidence infrastructure for autonomous agents

OnChainDiligence is verifiable evidence infrastructure for autonomous agents,
starting with financial agents.

**Mandate → Evidence → Policy → Decision → Execution → Verification**

The project includes the Agent Evidence protocol, Python and TypeScript SDKs,
signed evidence bundles, and fully offline verification. It also ships real
reference integrations, including [Technocore signed-message evidence](./packages/agent-evidence/README.md#technocore-signed-message-evidence)
and its [public contribution receipt](./docs/TECHNOCORE_PUBLIC_RECEIPT.json).

The existing pay-per-call compliance API is a production Evidence Provider /
reference implementation: crypto sanctions screening, OFAC name screening, and
UK company verification, with cryptographically signed attestations and optional
on-chain anchoring.

Live API: **`https://api.onchaindiligence.com`** · Docs: [onchaindiligence.com/docs](https://onchaindiligence.com/docs) · Agent/MCP version: [onchaindiligence-mcp](https://github.com/Qazza1/onchaindiligence-mcp) · On-chain anchoring: [onchaindiligence-anchor](https://github.com/Qazza1/onchaindiligence-anchor).

---

## What it checks — and what it does not

This API answers narrow factual questions and is deliberately honest about their limits.

| Endpoint | Checks | Price |
|----------|--------|-------|
| `GET /screen/:address` | Is this wallet on a sanctions list? (Chainalysis on-chain oracle, US/EU/UN.) Address in, yes/no + details out. Says nothing about who owns it. | $0.01 |
| `GET /screen-name?name=` | Is this person or company on the OFAC SDN list? Fuzzy name match against primary names + strong aliases, with confidence scores. Returns candidate matches, not a verdict. | $0.02 |
| `GET /company/:companyNumber` | UK company status, profile, and PSC data (People with Significant Control — who actually owns/controls it). Says nothing about crypto. | $0.05 |
| `GET /diligence?wallet=&company=` | Wallet + company checks in parallel. | $0.05 |
| `POST /anchor` | Anchor an attestation's hash on Tempo for immutable, timestamped proof. | $0.01 |

**The critical limitation of the combined check:** `/diligence` runs the two checks independently and returns both — it does **not** establish any link between the wallet and the company. The response says so explicitly. Drawing a connection between them is the caller's judgement, not a claim this API makes.

Free endpoints (no payment): `GET /` (service info), `GET /health` (upstream + signing status), `GET /openapi.json` (machine-readable discovery), and `GET /anchored?signature=` (check whether an attestation is anchored on-chain).

## Pricing & access model

Prices are differentiated by value delivered and cost to serve, not a flat rate:

| Check | Price | Why |
|-------|-------|-----|
| Wallet sanctions (`/screen`) | $0.01 | One on-chain oracle read — a commodity, high-volume call agents make before transfers. |
| OFAC name screen (`/screen-name`) | $0.02 | Parses and fuzzy-matches the full OFAC SDN list. |
| UK company / KYB (`/company`) | $0.05 | Returns a structured corporate record (status + ownership). Higher value, lower volume. |
| Combined diligence (`/diligence`) | $0.05 | Wallet + company together — a discount vs. $0.06 apart. |
| Anchor (`/anchor`) | $0.01 | An on-chain write on Tempo. |

**Two access models, by design.** The pay-per-call 402 model fits agents, indie developers, and bursty workloads — no account, no commitment. A standing enterprise integration with predictable monthly budgets and SLAs is a different shape: that would be a prepaid, API-key tier (e.g. a monthly USDC subscription granting a call allowance), layered on top of the same checks. The per-call rail is built and live; the subscription rail is a planned addition, not yet implemented. The architecture supports both because the checks, signing, and attestation are independent of how a call is paid for.

**What it deliberately does *not* sell.** There is no premium "risk score" or "wallet exposure history" tier. Those require proprietary attribution data this service does not have and would not honestly possess from free public sources. Selling a risk score we can't substantiate would be exactly the wrong move for a compliance tool — so the product stays within what its data can actually support.



## Signed attestations

Every paid response includes a versioned Ed25519 attestation. Version 2 signs RFC 8785 canonical JSON containing the result, issue timestamp, exact key ID, issuer, purpose, and schema version. Verifiers resolve that key ID through `/.well-known/attestation-keys/{key_id}`, which publishes active, retired, revoked, and compromised status. Legacy version 1 verification remains supported. Change one signed field and verification fails.

## How payment works

Payment uses the HTTP `402 Payment Required` flow over MPP on Tempo:

1. The client calls an endpoint with no payment.
2. The server responds `402` with a payment challenge (amount, currency, recipient, chain).
3. The client pays the requested pathUSD on Tempo and retries with proof.
4. The server verifies payment, runs the check, and returns a signed result.

If an upstream data source is unreachable, the server returns `503` **before** requesting payment — you are never charged for a check that can't complete.

## Data provenance

**Wallet screening** reads the **Chainalysis on-chain sanctions oracle** — a free, public smart contract on Ethereum mainnet (`0x40C57923924B5c5c5455c48D93317139ADDaC8fb`), via a read-only `isSanctioned()` call. No Chainalysis API key or commercial relationship is required; it's a public good reflecting US/EU/UN lists.

**Name screening** matches against the official **U.S. Treasury OFAC SDN list** (public-domain government data), including strong aliases. It uses transparent fuzzy matching (token overlap + edit distance) and returns confidence-scored candidates — deliberately not weak AKAs, per OFAC's own guidance. A match is a candidate to investigate with secondary identifiers, never a determination.

The per-call fee covers infrastructure, not the data, which is free and public.

## On-chain anchoring (optional)

Submit the complete signed response envelope (`data` plus `attestation`) to `POST /anchor`. Before payment, the API verifies the v2 issuer/schema/purpose, resolves the exact key ID from its published registry, rejects revoked or compromised keys, and verifies the Ed25519 signature over the canonical data. Only then does the Tempo contract store the `keccak256` of the signature, giving an immutable, timestamped, tamper-evident record that a check existed — without putting any subject data on-chain. Anyone can verify via the free `GET /anchored?signature=`. Anchoring is decoupled from checks: it never blocks or delays a paid response. The contract lives in [onchaindiligence-anchor](https://github.com/Qazza1/onchaindiligence-anchor).

## Architecture

```
client (any language, or an AI agent)
      │  HTTP + 402 / MPP
      ▼
src/server.ts ──── Hono routes, payment gating, attestation signing
      ├── src/chainalysis.ts ──── sanctions oracle read (viem, Ethereum mainnet)
      ├── src/ofac.ts ─────────── OFAC SDN parser + fuzzy name matcher
      ├── src/companiesHouse.ts ─ UK Companies House lookup (profile + PSC)
      ├── src/attestation.ts ──── Ed25519 signing + /.well-known key
      ├── src/anchor.ts ───────── optional on-chain anchoring (viem, Tempo)
      ├── src/diligence.ts ────── combined-check integrity guard
      ├── src/health.ts ───────── upstream health + circuit breaker
      ├── src/rateLimit.ts ────── per-client rate limiting
      └── src/paymentLog.ts ───── settlement records
```

Built with [Hono](https://hono.dev) + TypeScript, deployed on Vercel. See [`DEPLOY.md`](./DEPLOY.md) for deployment and the full environment-variable list.

## Agent Evidence developer packages

The repository contains production Agent Evidence v0 implementations for
Python and Node.js/TypeScript. The focused
`@onchaindiligence/agent-evidence` package under
[`packages/agent-evidence`](./packages/agent-evidence) provides deterministic
record and bundle construction, Ed25519 DSSE sealing, explicit caller trust,
and fully offline `VALID` / `INVALID` / `UNVERIFIABLE` verification. It is
publicly available on npm:

```sh
npm install @onchaindiligence/agent-evidence
# or pin the current release
npm install @onchaindiligence/agent-evidence@0.2.0
```

## Two payment rails

OnchainDiligence settles two ways. This repo is the HTTP API (MPP / pathUSD / Tempo). The [MCP server](https://github.com/Qazza1/onchaindiligence-mcp) exposes the same checks to AI agents and settles in USDC on Base via x402. Same checks, same signed results, different rails for different ecosystems.

## Not a compliance program

OnchainDiligence returns factual checks and signed attestations. It is **not** legal or compliance advice and is not a substitute for a full compliance program. The sanctions oracle returns a match flag, not rich case detail. Results are never cached.

## License

MIT — see [LICENSE](./LICENSE).
