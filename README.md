# OnchainDiligence — HTTP API

A pay-per-call compliance API: **crypto sanctions screening** and **UK company verification**, separately or bundled, with payment collected per request via the **Machine Payments Protocol (MPP)** on **Tempo**. Every response is a cryptographically signed attestation you can verify yourself.

Live at **`https://api.onchaindiligence.com`** · Docs at [onchaindiligence.com/docs](https://onchaindiligence.com/docs) · Agent/MCP version: [onchaindiligence-mcp](https://github.com/Qazza1/onchaindiligence-mcp).

No account, subscription, or sales conversation — an agent (or a script, or another service) asks "is this wallet sanctioned?" or "is this UK company real and who controls it?" and pays a few cents per answer.

---

## What it checks — and what it does not

This API answers narrow factual questions and is deliberately honest about their limits.

| Endpoint | Checks | Price |
|----------|--------|-------|
| `GET /screen/:address` | Is this wallet on a sanctions list? (Chainalysis on-chain oracle, US/EU/UN.) Address in, yes/no + details out. Says nothing about who owns it. | $0.01 |
| `GET /company/:companyNumber` | UK company status, profile, and PSC data (People with Significant Control — who actually owns/controls it). Says nothing about crypto. | $0.01 |
| `GET /diligence?wallet=&company=` | Both checks in parallel. | $0.015 |

**The critical limitation of the combined check:** `/diligence` runs the two checks independently and returns both — it does **not** establish any link between the wallet and the company. The response says so explicitly. Drawing a connection between them is the caller's judgement, not a claim this API makes.

Two endpoints are free: `GET /` (service info) and `GET /openapi.json` (machine-readable discovery).

## Signed attestations

Every paid response includes an Ed25519 signature over the result data plus an issue timestamp. Anyone can verify a stored response against the public key at `/.well-known/attestation-key` — without trusting or re-contacting this service. Change one field of a stored result and verification fails. This is the point of the product: an auditable, tamper-evident record that a check happened, at a specific moment, with a specific answer.

## How payment works

Payment uses the HTTP `402 Payment Required` flow over MPP on Tempo:

1. The client calls an endpoint with no payment.
2. The server responds `402` with a payment challenge (amount, currency, recipient, chain).
3. The client pays the requested pathUSD on Tempo and retries with proof.
4. The server verifies payment, runs the check, and returns a signed result.

If an upstream data source is unreachable, the server returns `503` **before** requesting payment — you are never charged for a check that can't complete.

## Sanctions data provenance

Screening reads the **Chainalysis on-chain sanctions oracle** — a free, public smart contract on Ethereum mainnet (`0x40C57923924B5c5c5455c48D93317139ADDaC8fb`), via a read-only `isSanctioned()` call. No Chainalysis API key or commercial relationship is required; it's a public good reflecting US/EU/UN lists. The per-call fee covers infrastructure, not the data, which is free and public.

## Architecture

```
client (any language, or an AI agent)
      │  HTTP + 402 / MPP
      ▼
src/server.ts ──── Hono routes, payment gating, attestation signing
      ├── src/chainalysis.ts ──── sanctions oracle read (viem, Ethereum mainnet)
      ├── src/companiesHouse.ts ─ UK Companies House lookup (profile + PSC)
      ├── src/attestation.ts ──── Ed25519 signing + /.well-known key
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
