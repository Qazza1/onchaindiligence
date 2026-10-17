# Payments Evidence Workspace roadmap

Updated: 2026-09-29

This document extends the 2026-09-28 product audit with the next product direction.
It does not replace Receipt v1, Signed Payment Claim v1, or the existing evidence boundaries.

## Product thesis

OnChainDiligence should be useful before a user asks for a receipt.

The product direction is an **independent evidence and reconciliation layer for autonomous payments**:

- what was proposed or allowed;
- what an agent / executor / provider claims it did;
- what the wallet and chain actually show;
- whether those sources agree;
- and, when useful, a signed OCD receipt that preserves the evidence snapshot.

A receipt is therefore an **output artifact**, not the primary product object.

## Primary dashboard model

Use **Payments** as the primary workspace object, while keeping transaction inspection as the simplest entry point.

Recommended navigation direction:

- **Overview** — what needs attention now;
- **Payments** — payment feed + transaction inspector + evidence detail;
- **Operations** — proposal, policy, execution, recovery, provider context;
- **Receipts** — signed artifacts, retrieval, verification, sharing;
- **Investigations / Wallets** — linked activity and deeper evidence views where already supported.

A payment may have zero, one, or multiple transaction references. A transaction alone does not prove payment intent, agent identity, merchant identity, or service delivery.

## Evidence stack

Every payment detail view should keep these layers separate:

1. **Observed on-chain** — direct chain facts and finality state.
2. **Derived interpretation** — narrow rule-based classification with the rule stated.
3. **Execution / provider claim** — Turnkey, x402, Circle, CDP, Crossmint, PayBox, wallet executor, etc., only when supported evidence exists.
4. **Policy / preflight** — what OCD inspected or decided before execution, when linked.
5. **OCD signed receipt** — optional signed artifact preserving a particular observation/evidence snapshot.

Receipt `VALID` retains its narrow meaning: the signed receipt bytes verify against a trusted OCD signing key. It does not prove all underlying claims are true.

## Manual inspection vs recurring product

### Manual inspector

Manual hash/signature paste is a **playground, debugging, onboarding and demo surface**.

Flow:

`paste transaction -> inspect live evidence -> understand what OCD can establish -> optionally save -> optionally issue/open signed receipt`

Pasting must not automatically sign a receipt. Inspection is a read; issuing a receipt is an explicit action.

### Recurring product

The long-term useful product is an **automatically populated Payments feed**.

Payments should arrive from OCD SDK / MCP operations and linked executor flows without a human copying transaction hashes.

A payment record can accumulate over time:

`preflight / policy -> agent or operation -> executor claim -> transaction reference(s) -> chain observation -> reconciliation -> signed receipt`

The dashboard should highlight evidence states such as:

- policy allowed, executor succeeded, chain confirmed, reconciliation MATCH;
- executor says succeeded, chain not yet observed — needs attention;
- policy blocked, no transaction — expected stop;
- receipt exists and verifies VALID;
- evidence missing or contradictory.

## Live qualification checkpoint — 2026-09-29

The production SDK paid-preflight path was exercised from a real Base payer wallet without calling execution.

- operation: `OCD-OP-IQW7OMmgvfAss63YFn5NfUw9j9k`;
- paid route: production `/x402/lifecycle/preflight-payment` at the configured `$0.01` USDC preflight price;
- SDK result: `ready`;
- policy decision: `ALLOW`;
- receipt: `OCD-RCP-DD40-SBF9-H6JP-QFJE`;
- proposed target payment: `1.00 USDC`, **not executed**.

This qualifies the paid preflight path and workspace-linked operation flow. It is not evidence of a third-party provider reference payment, customer adoption, or settlement of the proposed `1.00 USDC` payment.

## Wallet and agent activity

Add this progressively, opt-in and evidence-bound.

### Wallet activity

For wallets explicitly pasted, connected or watched by the workspace, OCD may correlate supported activity:

- supported payment transactions and stablecoin transfers;
- approvals, swaps, bridges and other strict OCD observers where available;
- operation / payment links;
- execution-provider claims;
- receipt and reconciliation state.

Two entry modes are useful and should remain distinct:

- **Paste wallet address** — read-only activity lookup, no signature and no ownership claim.
- **Connect wallet** — optional message-signature proof that the current workspace controls the address. This proves address control only; it does not establish a person's identity, a company's identity, or which agent created historical transactions.

Do not infer commercial intent from an arbitrary wallet transaction.

### Agent activity

Show which agent / SDK client / MCP operation acted only when attribution is supported by OCD-authenticated context, a linked operation, signed provenance, or authenticated provider evidence.

Examples:

- agent/service requested preflight;
- policy decision returned;
- MCP / SDK operation created;
- executor submitted a transaction;
- chain settlement observed;
- provider and chain reconciled;
- user opened or saved the evidence in the dashboard.

If OCD only sees a wallet transaction, label it **wallet transaction observed**. Do not invent agent attribution.

A PayBox, Turnkey, Circle, CDP, Crossmint or other provider label must come from a linked OCD operation, provider reference, authenticated/signed provider evidence, or another explicit evidence link. Never classify a transaction as provider-originated from chain shape alone.

### Activity timeline

Long-term detail view should support an evidence timeline such as:

`12:01 agent requested payment inspection`
`12:01 OCD policy ALLOW`
`12:02 executor reported submitted`
`12:02 Base transaction observed`
`12:03 USDC settlement CONFIRMED`
`12:03 provider <-> chain reconciliation MATCH`
`12:04 signed OCD receipt issued`

This is an accountability timeline, not surveillance of unrelated external activity.

## Phase plan

### P-E1 — Payments inspector v1 — NOW

Goal: immediate user value before receipt creation.

Build:

- authenticated read-only transaction inspection endpoint reusing existing chain observers;
- Payments tab / evidence detail screen;
- four current canonical scopes only: Base USDC, Ethereum USDC, Tempo pathUSD, Solana USDC;
- status, block/slot, time, finality, supported transfer candidates, sender/recipient/asset/amount where established;
- clear live-read / unsigned label;
- existing receipt lookup;
- linked operation / policy / provider sections only when authorized and available;
- explicit **Issue signed receipt** or **Open existing receipt** action.

Do not make gas, arbitrary token decoding, traces, address labels or generic explorer features release blockers.

Acceptance: a new user can explain what OCD observed, what it could not establish, and what a receipt proves before downloading anything.

### P-E2 — Turnkey reference reconciliation — NEXT

Use the Payments detail screen for the first third-party executor showcase.

Target presentation:

- Turnkey provider claim;
- referenced transaction;
- OCD independent settlement observation;
- field-level comparison where evidence exists;
- signed OCD receipt as the portable output.

No partnership claim is implied by an independent reference run.

Acceptance: one bounded real reference flow can be opened in the dashboard and shows provider evidence separately from independent chain evidence and receipt proof.

### P-E3 — Wallet Evidence v1 — NEXT AFTER TURNKEY

Goal: let a user paste a wallet and immediately see supported payment activity, then enrich only the transactions OCD can actually link to operations, providers, agents or receipts.

Keep v1 intentionally narrow:

- Base mainnet only;
- canonical USDC activity only;
- paste wallet address first — no wallet signature required;
- show recent supported incoming/outgoing USDC transfers with transaction hash, counterparty, amount, time and finality where established;
- correlate by exact transaction reference to existing OCD receipts, workspace operations and provider evidence;
- show PayBox / Turnkey / other provider attribution only when explicit OCD/provider evidence supports it;
- show agent / MCP / SDK attribution only when explicit provenance or operation context supports it;
- allow saving/watching the wallet in the workspace without implying ownership;
- reuse the Payments evidence-detail model rather than building a separate explorer.

Useful evidence labels include:

- **Wallet transaction observed** — chain fact only;
- **OCD-linked payment** — exact transaction linked to an OCD operation or receipt;
- **Provider evidence available** — provider identity/status supported by evidence;
- **Agent attribution available** — agent/SDK/MCP identity supported by evidence;
- **Unlinked** — no supported provenance beyond the chain transaction.

Do not build portfolio balances, token discovery, price charts, address-label guessing, generic traces, or provider inference from transaction shape.

Acceptance: pasting a known Base wallet shows canonical USDC activity; a transaction already linked to OCD/PayBox/provider evidence displays those links; an unrelated transfer remains explicitly unlinked rather than being guessed.

### P-E4 — Automatic Payments feed — NEXT / AFTER THE FIRST WALLET EVIDENCE SLICE

Goal: make the dashboard useful without manual hash or wallet pasting.

Build around existing SDK / MCP operations so payment records appear automatically as operations progress.

Feed should reconcile:

- policy/preflight;
- agent / operation identity where supported;
- executor/provider status;
- transaction reference(s);
- independent chain observation;
- receipt state;
- attention state for missing or contradictory evidence.

Manual inspection, wallet-linked activity and automatically ingested payments must use the same detail UI/data model.

### P-E5 — Connected wallet proof-of-control — LATER

After read-only Wallet Evidence v1 proves useful, add optional wallet connection and message-signature proof of control.

Requirements:

- no custody and no spending authority;
- never request or store a private key;
- signed challenge must be scoped to the workspace, wallet, nonce and expiry;
- proof of wallet control must stay separate from real-world identity and from historical agent attribution;
- disconnecting/removing the wallet removes the workspace association, not public chain history or public receipts.

### P-E6 — Expand from demonstrated use — LATER

Only after real usage:

- richer multi-transaction payments;
- additional providers;
- additional strict action observers;
- reliable fee/native-value metadata and allowlisted decoding;
- richer wallet monitoring;
- optional notifications / webhooks for attention states;
- signed evidence packs combining receipt + provider claim + policy context.

## Explicit non-goals for the next milestone

Do not build:

- a generic block explorer;
- arbitrary ABI / 4byte decoding;
- wallet portfolios or price feeds;
- broad address labels or identity inference;
- AI narratives presented as evidence;
- risk / scam scores;
- new chains merely for breadth;
- live provider API scraping with user custody credentials;
- a new receipt format;
- a signed artifact for every unsigned inspection.

## Positioning

Short form:

> **OnChainDiligence is the independent evidence and reconciliation layer for autonomous payments.**

Product flow:

> **Understand what happened -> compare what was intended and claimed -> verify what the chain shows -> preserve the result as signed evidence when needed.**

For agent developers:

> **See what your agents attempted, what executors claimed, what your wallets actually did, and what the chain proves.**

For Turnkey-style execution providers:

> **The provider controls signing and execution; OCD independently observes, reconciles and preserves the evidence.**
