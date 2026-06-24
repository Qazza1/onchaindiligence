# OnchainDiligence — HTTP API

A pay-per-call compliance API: **crypto sanctions screening**, **OFAC name screening**, and **UK company verification**, separately or bundled, with payment collected per request via the **Machine Payments Protocol (MPP)** on **Tempo**. Every response is a cryptographically signed attestation you can verify yourself — and optionally anchor on-chain.

Live at **`https://api.onchaindiligence.com`** · Docs at [onchaindiligence.com/docs](https://onchaindiligence.com/docs) · Agent/MCP version: [onchaindiligence-mcp](https://github.com/Qazza1/onchaindiligence-mcp) · On-chain anchoring: [onchaindiligence-anchor](https://github.com/Qazza1/onchaindiligence-anchor).

No account, subscription, or sales conversation — an agent (or a script, or another service) asks "is this wallet sanctioned?" or "is this UK company real and who controls it?" and pays a few cents per answer.

---

## What it checks — and what it does not

This API answers narrow factual questions and is deliberately honest about their limits.

| Endpoint | Checks | Price |
|----------|--------|-------|
| `GET /screen/:address` | Is this wallet on a sanctions list? (Chainalysis on-chain oracle, US/EU/UN.) Address in, yes/no + details out. Says nothing about who owns it. | $0.01 |
| `GET /screen-name?name=` | Is this person or company on the OFAC SDN list? Fuzzy name match against primary names + strong aliases, with confidence scores. Returns candidate matches, not a verdict. | $0.01 |
| `GET /company/:companyNumber` | UK company status, profile, and PSC data (People with Significant Control — who actually owns/controls it). Says nothing about crypto. | $0.01 |
| `GET /diligence?wallet=&company=` | Wallet + company checks in parallel. | $0.015 |
| `POST /anchor` | Anchor an attestation's hash on Tempo for immutable, timestamped proof. | $0.01 |

**The critical limitation of the combined check:** `/diligence` runs the two checks independently and returns both — it does **not** establish any link between the wallet and the company. The response says so explicitly. Drawing a connection between them is the caller's judgement, not a claim this API makes.

Free endpoints (no payment): `GET /` (service info), `GET /health` (upstream + signing status), `GET /openapi.json` (machine-readable discovery), and `GET /anchored?signature=` (check whether an attestation is anchored on-chain).

## Signed attestations

Every paid response includes an Ed25519 signature over the result data plus an issue timestamp. Anyone can verify a stored response against the public key at `/.well-known/attestation-key` — without trusting or re-contacting this service. Change one field of a stored result and verification fails. This is the point of the product: an auditable, tamper-evident record that a check happened, at a specific moment, with a specific answer.

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

Any signed attestation can be anchored on **Tempo** via `POST /anchor`: the contract stores the `keccak256` of the attestation signature, giving an immutable, timestamped, tamper-evident record that a check existed — without putting any subject data on-chain. Anyone can verify via the free `GET /anchored?signature=`. Anchoring is decoupled from checks: it never blocks or delays a paid response. The contract lives in [onchaindiligence-anchor](https://github.com/Qazza1/onchaindiligence-anchor).

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

## Two payment rails

OnchainDiligence settles two ways. This repo is the HTTP API (MPP / pathUSD / Tempo). The [MCP server](https://github.com/Qazza1/onchaindiligence-mcp) exposes the same checks to AI agents and settles in USDC on Base via x402. Same checks, same signed results, different rails for different ecosystems.

## Not a compliance program

OnchainDiligence returns factual checks and signed attestations. It is **not** legal or compliance advice and is not a substitute for a full compliance program. The sanctions oracle returns a match flag, not rich case detail. Results are never cached.

## License

MIT — see [LICENSE](./LICENSE).
