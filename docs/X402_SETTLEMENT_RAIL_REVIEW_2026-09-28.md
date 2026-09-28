# x402 settlement-rail architecture review — 2026-09-28

Status: **architecture review snapshot** (documentation only). No product code,
schema, SDK API, MCP tool, website code, package version or deployment
configuration was changed.

Question: *does OnChainDiligence need an architectural or schema change now so
that x402 payment inspection and evidence stay settlement-rail-neutral, or is
the current model already sufficient?*

Follows the 2026-09-28 product audit (`docs/PRODUCT_AUDIT_2026-09-28.md`,
proposed in Qazza1/onchaindiligence#13, not yet merged), which classified
x402 as LIVE BUT LIMITED.

## 1. Executive conclusion

**Decision: A — NO SCHEMA OR ARCHITECTURE CHANGE NEEDED NOW.**

- **Block's claim is verified from primary sources.** Block joined the x402
  Foundation (Block, 2026-09-24). An `exact` scheme for Bitcoin Lightning on a
  new `lnbtc` CAIP-2 namespace was merged into the official
  `x402-foundation/x402` specification on 2026-09-23.
  - Lightning is a **network binding of the existing `exact` scheme**
    (network `lnbtc:…`, asset `BTC`, transfer method `bolt11`, flow `upfront`).
    It is not a new protocol, a new core type, or a facilitator product.
  - The x402 v2 core types (`PaymentRequirements`, `PaymentPayload`,
    `SettlementResponse`) were **not changed** by the Lightning commit.
  - As of 2026-09-28 it is a merged spec only. The official reference SDKs have
    **no merged Lightning implementation**; TypeScript and Python PRs are open.
- **OCD's portable artifacts are already rail-neutral at the type level.**
  - In Public Action Receipt v1 and Signed Payment Claim v1, `network`,
    `asset`, `sender`, `recipient` and `transaction_hash` are unconstrained
    non-empty strings or null. No chain ID, EVM address pattern, token-contract
    requirement or block number is forced.
  - A Lightning payment could be described in a v1 receipt without a schema
    migration, provided the settlement semantics are kept honest (§5).
- **Rail-specific assumptions live in adapters, validators and SDK scope gates.**
  That is the correct place for them, and they fail closed. They do not need
  migrating for Lightning.
- **The review found two existing x402 v2 interop defects unrelated to
  Lightning.** Both are in the SDK `withOcd` wrapper:
  1. It treats the x402 v2 `settlement_pending` result (success `false`, but
     with a broadcast transaction) as `payment-failed`. That reports
     uncertainty as failure in exactly the case OCD's independent observation
     exists for.
  2. It keys Solana on OCD's internal label `solana:mainnet`, while x402 v2
     requirements use `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`. The wrapper's
     Solana canonical-asset entry can therefore never match a real x402 Solana
     requirement, and such payments are aborted. This is fail-closed but
     unadvertised.

  These are the recommended follow-up (§7). They are SDK behavior fixes, not
  schema changes.
- **Lightning cannot reach the evidentiary class OCD has for Base, Ethereum,
  Tempo or Solana.** There is no public ledger to observe independently.
  - What any third party *can* verify offline: a payee-signed BOLT11 invoice
    committing to amount, payment hash and request, plus the disclosed
    preimage.
  - That is a real cryptographic proof, stronger than a provider's word. But it
    is a proof of *preimage release under the payee's commitment*, not an
    observation of value movement. It must never be labelled settlement
    `CONFIRMED` under the current receipt definition.
- **Do not build Lightning now.** There is no user or pilot demand, no official
  reference implementation, and a weaker evidence class. Base-USDC remains the
  concrete production profile.

## 2. Verified ecosystem development (dated)

All accessed on 2026-09-28. The x402 repository was read at `a9955ae`
(`x402-foundation/x402` `main`, committed 2026-09-29 01:37 +09:00, which is
2026-09-28 UTC).

| # | Claim | Verified? | Primary evidence |
|---|---|---|---|
| 1 | Block joined the x402 Foundation | **Yes** | Block, "Block Joins the x402 Foundation to Advance Open, Agentic Commerce", **published 2026-09-24**, by Steve Reis (Head of Product, Block Financial Platform): "Block has joined the x402 Foundation". The post includes a quote from Steve Lee, Head of Spiral. The foundation's launch-member list (Linux Foundation press release, 2026-04-02) predates Block's membership |
| 2 | Lightning support was contributed | **Yes, as a specification** | PR #2861 "Specify exact Lightning on BIP-122" by `benthecarman`, **merged 2026-09-23** (commit `6fe0d4b`). It adds `specs/schemes/exact/scheme_exact_lnbtc.md` (760 lines) and a one-line change listing it in `scheme_exact.md`. Doc link PR #3578 merged 2026-09-27. Block's post says: "Block has contributed Bitcoin Lightning payments to the x402 protocol". This review does not independently establish the commit author's employer; attribution is Block's own statement |
| 3 | Standardized vs experimental | **Spec merged; implementations not merged** | No `lnbtc` code under the official `typescript/`, `python/` or `go/` reference SDKs (`git grep lnbtc` hits only `specs/` and `docs/`). Open PRs: #2262 (TS `bip122/exact` mechanism), #1873 (Python request-bound Lightning upfront), #3572 (an alternative `invoice` asset-transfer method). A further `invoice`-method PR (#3571) was closed |
| 4 | How Lightning is represented | **Network binding of scheme `exact`** | `scheme: "exact"`. `network: "lnbtc:000000000019d6689c085ae165831e93"` (mainnet; the reference is the first 32 hex characters of the Bitcoin genesis hash, per the BIP-122 CAIP-2 convention). Testnet is `lnbtc:000000000933ea01ad0ee984209779ba`. `asset: "BTC"`; `extra.assetTransferMethod: "bolt11"`; `extra.paymentFlow: "upfront"`. The facilitator is still the generic x402 facilitator role: `/settle` only, no `/verify` |
| 5 | Core request/response semantics changed? | **No** | The Lightning commit touched only scheme files. The last core changes in `x402-specification-v2.md` were `settlement_pending` (PR #3083, 2026-08-17) and discovery/extension fixes (2026-08-31), all before Lightning |
| 6 | HTTP negotiation still transport-neutral? | **Yes** | v2 §Architecture separates Types (transport- and scheme-independent), Logic (scheme + network) and Representation (transport: HTTP, MCP, A2A). The Lightning scheme adds request-binding profiles `http:1` and `mcp:1` inside `extra`; it does not alter the transports |

Secondary coverage (crypto.news, Cryptonomist and others, 2026-09-25) matches
the primary sources. It was not relied on.

## 3. Current x402 v2 architecture

Source: `specs/x402-specification-v2.md` and `specs/schemes/exact/*` at
`a9955ae`.

| Concept | x402 v2 definition | Universal or scheme/network-specific |
|---|---|---|
| Protocol | `x402Version: 2`; types independent of transport and scheme (§5) | Universal |
| PaymentRequired | `resource` (ResourceInfo), `accepts[]`, optional `extensions` | Universal |
| PaymentRequirements | `scheme`, `network`, `amount`, `asset`, `payTo`, `maxTimeoutSeconds`, `extra` | **Field names** universal. **Value formats** are per scheme and network, e.g. EVM `asset` = token contract; Lightning `asset` = `"BTC"`; Lightning `payTo` = 33-byte node pubkey hex |
| Scheme | The logic: how the payload is formed, validated and settled (`exact`, `upto`, `batch-settlement`, `auth-capture`) | Scheme-level, bound per network |
| Network | CAIP-2 `namespace:reference`; non-blockchain networks encouraged to follow CAIP-2 (`ach:us`, `sepa:eu`) | Universal format, open namespace |
| Asset | "Token contract address or ISO 4217 currency code for fiat"; Lightning uses `"BTC"` | Value is per network |
| Amount | "Atomic token units" (EVM USDC = 10⁻⁶; Lightning = **millisatoshis**) | Universal field, per-asset unit |
| payTo | "Recipient wallet address or role constant"; Lightning = receiver **node public key**, which must equal the invoice signer | Value per network |
| `extra.assetTransferMethod` / `extra.paymentFlow` | Protocol-reserved keys (§6.1). Flows: `authorization` (verify → resource → settle), `upfront` (settle → resource), `escrow` | Keys universal; allowed values per mechanism |
| Facilitator | `/verify` (read-only), `/settle` ("durably commits payment state"; "need not be an onchain write" and may bind a prepaid proof to a request), `/supported` | Universal role; behavior per scheme |
| PaymentPayload | `x402Version`, `accepted` (the chosen requirement), `payload` (**scheme-specific**), optional `resource` and `extensions` | Envelope universal; `payload` scheme-specific. EVM: EIP-3009 signature and authorization. Lightning: `{ preimage }` |
| SettlementResponse | `success`, `errorReason?`, `payer?`, `transaction`, `network`, `amount?`, `extensions?` | Field names universal. `transaction` is described as a "blockchain transaction hash", but **for `lnbtc` it is the invoice payment hash** and `payer` MUST be omitted |
| Pending settlement | `settlement_pending`: non-terminal; `success:false` with a non-empty `transaction` "so the caller can reconcile on chain" | Universal error code (added 2026-08-17) |

**Takeaway.** x402 already treats `transaction` as an opaque rail reference,
`asset` and `payTo` as network-defined strings, and `payer` as optional. The
core is rail-neutral. EVM terminology survives only in descriptions and
examples.

## 4. OCD evidence boundaries

The five concepts already exist as separate artifacts in OCD. They are not yet
named uniformly.

| Concept | Where OCD represents it today | Rail-neutral? |
|---|---|---|
| **A. Payment requirement** (what must be paid) | Receipt `action` {`kind`, `resource`, `network`, `asset`, `amount`, `sender`, `recipient`} (`onchaindiligence-mcp/src/receipts.ts`, `packages/agent-evidence/schemas/public-action-receipt.schema.json` `receiptAction`); preflight input; SDK `withOcd` maps x402 `PaymentRequirements` into it | **Schema yes.** All strings or null; `network` "CAIP-2 where applicable". The x402 `scheme` and `extra` are not in the receipt; they can go in an evidence-digested check or a linked Agent Evidence bundle. The `sender`/`recipient` descriptions say "wallet address", which is slightly EVM-flavoured wording, not a constraint |
| **B. Policy / preflight decision** | Receipt `decision` {`status`, `authorized`, `reasons`}; PREFLIGHT receipt; `inspect_payment` | Yes |
| **C. Execution claim** | Receipt `execution` {`provider`, `status`, `transaction_hash`, …}; provider evidence (PayBox, Turnkey, Crossmint, CDP, Circle); **Signed Payment Claim v1** (`execution.claimed_status`, optional `transaction_hash`), verified with scope `PLATFORM_CLAIM_SIGNATURE` | **Schema yes.** `transaction_hash` is an opaque 1–4096-character string, the same move x402 makes with `SettlementResponse.transaction` |
| **D. Settlement evidence** | Receipt `settlement` {`status` ∈ CONFIRMED / NOT_CONFIRMED / UNVERIFIED / NOT_APPLICABLE, `detail`} plus `checks[]`. Per-rail observers with versioned policies: `ethereum-usdc-finalized-head.v1`, `tempo-tip20-finalized-head.v1`, `solana-usdc-finalized.v1`, Base safe/finalized | **Semantics are rail-neutral but single-class.** `CONFIRMED` means "value movement independently confirmed" (`docs/PUBLIC_ACTION_RECEIPT_V1.md` §8). There is no field naming the *evidence class*; it is carried in `detail` / `checks[]` |
| **E. Receipt / reconciliation** | Findings taxonomy (`CONTRADICTION`, `INSUFFICIENT_EVIDENCE`); binding strength; bundle `agreements` / `contradictions` / `insufficient_evidence` | Yes |

The existing invariants already carry most of the weight:

- Signed Payment Claim ≠ OCD Receipt (DSSE domain separation).
- A provider claim ≠ settlement.
- Missing evidence ≠ contradiction (`INSUFFICIENT_EVIDENCE`).
- `VALID` means cryptographic integrity and authenticity only.

**Does the model naturally support Lightning?** Mostly yes: A, B, C and E
without change. D is the only place needing care. A Lightning proof is neither
"nothing observed" nor "independently observed value movement". Under the
current enum it must be `UNVERIFIED`, with the proof verification expressed as a
`checks[]` entry. That is honest but coarse (§5, §6).

**Future generic representation (conceptual, no schema proposed).** A rail-neutral
evidence object would carry:

- protocol, scheme, network, asset, amount, recipient;
- facilitator or executor;
- execution reference;
- settlement evidence **type**, settlement reference;
- observation status and finality policy.

OCD already has almost all of these: the receipt `action`, `execution` and
`settlement`, plus the per-profile observer policy IDs. Only an explicit
**evidence-class** field and the x402 **scheme** are missing from the receipt,
and neither is needed until a second evidence class ships. Chain ID, EVM
address, token contract, tx hash and block number correctly stay profile-level:
in observer artifacts and allowance/swap/bridge profiles, not the shared
receipt.

## 5. Lightning evidence limitations

Source: `scheme_exact_lnbtc.md` (merged 2026-09-23) and
[BOLT11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md).
The word *independent* is used strictly below.

**What any third party, including OCD, can verify offline with no node and no
trust in the facilitator:**

1. The BOLT11 invoice signature. The signing key is the payee node pubkey,
   which must equal `payTo`.
2. The invoice's signed commitments: amount (integral msat), currency
   (network), payment hash, description hash (= the x402 request hash, binding
   the invoice to the exact HTTP request or MCP tool call), creation time and
   expiry.
3. That a disclosed preimage satisfies `SHA-256(preimage) == payment_hash`.

**What this establishes.** The payee committed to receive exactly this amount
for exactly this request, and the preimage the payee generated has been
disclosed. By Lightning protocol convention, a compliant receiver releases the
preimage only after accepting HTLCs totalling at least the invoice amount.

**What it does NOT establish independently:**

- **That value moved.** No globally queryable ledger records Lightning HTLC
  settlement. The preimage's release is controlled by the payee, who can
  disclose it without being paid (self-dealing, collusion, a leak). Preimage
  release is *payee behavior*, not third-party observation.
- **Who paid.** Lightning reveals no stable payer. The spec requires
  facilitators to omit `payer` and not infer it. The preimage is a **bearer
  proof**: holding it does not make someone the payer.
- **The amount actually received.** The preimage "does not reveal the amount
  actually received". Overpayment is possible, and routing fees are invisible.
- **When settlement happened.** There is no block, timestamp or finality event;
  only invoice creation/expiry and the facilitator's settle time.
- **Anything a node reports.** Payer or payee node APIs (e.g. invoice status
  "settled") are **self-reported claims** by a party to the payment: class C,
  not class D.
- **The recipient's real-world identity.** A node pubkey is not an identity.
  Shared custodial nodes break even the payee-key binding; the spec forbids them
  for this reason.

**The honest evidence class.** Call it *payee-committed payment proof*
(signed-invoice commitment + preimage disclosure).

- **Weaker than** Base, Ethereum, Tempo or Solana independent ledger
  observation under a finality policy. Those let OCD itself read a public,
  finalized record of the transfer's sender, recipient and amount.
- **Stronger than** a caller-reported or provider-signed claim. It is
  mathematically checkable and binds the payee's own signature to the terms and
  request.

**Receipt v1 mapping, if ever built:**

| Field | Value |
|---|---|
| `network` | `lnbtc:000000000019d6689c085ae165831e93` |
| `asset` | `BTC` |
| `recipient` | payee node pubkey |
| `sender` | `null` |
| `execution.transaction_hash` | payment hash (as x402 does) |
| `settlement.status` | `UNVERIFIED` (not `CONFIRMED`) |
| `checks[]` | a proof-verification check with `evidence_digest` |
| `limitations[]` | state the gaps above |

The preimage itself must never be published in a receipt while it can still be
presented against any replay store. Record only digests.

## 6. Compatibility decision

**A — NO CHANGE NEEDED NOW.**

- **Why.** The shared portable schemas (Public Action Receipt v1, Signed
  Payment Claim v1, Agent Evidence bundles) use opaque strings for network,
  asset, parties and execution reference, and CAIP-2 wording that already
  admits `lnbtc:`. EVM-specific structure lives in profile-level observers and
  action artifacts, where it belongs. Lightning would be a new *profile and
  evidence class*, not a core change.
- **Migration risk.** None, because nothing migrates.
  - A premature receipt v2 adding `evidence_class` / `scheme` would force dual
    verification paths across the TS/Python verifiers, the MCP, the site and
    the CLI, for a rail with no demand.
  - Defer it until a second settlement evidence class actually ships.
    Candidates: Lightning, a card/processor rail, or a signed-claim-only rail.
- **Backward compatibility.** Preserved. Receipt v1 stays frozen; `CONFIRMED`
  keeps its meaning.
- **Receipt compatibility.** No existing receipt or schema breaks for
  Lightning. Receipt v1 can represent a Lightning payment honestly, at coarse
  granularity (`UNVERIFIED` + checks).
- **SDK impact.** None required for Lightning. `withOcd` already refuses
  requirements outside its canonical scope: unknown network or asset → abort,
  no fabricated receipt. The two defects in §7 are separate.
- **MCP impact.** None.
  - `inspect_payment` / `preflight_payment` validation dispatches
    `isValidPaymentAddress(network, …)` to EVM rules for every non-`solana:mainnet`
    network. A `lnbtc` request is therefore rejected, fail-closed, with a
    misleading "must be a 0x… EVM address" message.
  - `observe-payment` rightly has no Lightning path: there is no chain to
    observe.
  - The public MCP stays at three tools.
- **Website impact.** None. The site must not claim Lightning support.
- **Tests required.** None for decision A. Any future Lightning profile needs:
  - the spec's HTTP/MCP request-binding vectors;
  - invoice/preimage negative cases;
  - a test that `settlement.status` can never be `CONFIRMED` for this class;
  - a test that the preimage is never persisted in a public receipt.

## 7. Exact recommended follow-up

These are not required for Lightning and not schema work. They are x402 v2
correctness issues found while reviewing rail neutrality. Both sit in
`onchaindiligence-sdk/src/commerce/withOcd.ts` (SDK `0.8.0`) and were found by
reading the code; neither has been exercised live.

1. **Handle `settlement_pending` (S).**
   - **Defect.** `settlementTransaction()` returns
     `{ kind: 'no-receipt', reason: 'payment-failed' }` whenever
     `settleResponse.success` is false. x402 v2 defines `settlement_pending` as
     non-terminal, with a non-empty broadcast `transaction`. Funds may still
     move. Labelling that `payment-failed` reports uncertainty as failure.
   - **Change.** When `errorReason === 'settlement_pending'` and `transaction`
     is non-empty, continue the operation's OCD observation/finalization using
     that reference. Independent observation resolving an ambiguous facilitator
     outcome is the core product thesis. Surface a pending result with
     `mayAlreadyHavePaid: true`, consistent with the commerce client's
     discriminated unions. Never emit `payment-failed` in that case.
   - **Tests.**
     - A pending response with a transaction → observation continues.
     - A pending response with an empty transaction → honest no-receipt.
     - Terminal failures still stay no-receipt.
     - A later confirmation finalizes.
2. **Fix the x402 Solana network identifier mismatch (XS).**
   - **Defect.** `CANONICAL_ASSETS` keys Solana as `solana:mainnet`, OCD's
     internal label (`onchaindiligence-mcp/src/solanaSettlement.ts`). x402 v2
     requirements use `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` (spec §11.1;
     `scheme_exact_svm.md`). The entry can never match, so real x402 Solana
     payments are aborted as out of scope.
   - **Change (either option).**
     - Map the x402 CAIP-2 identifier to OCD's internal Solana profile at the
       wrapper boundary, and pass OCD's accepted identifier to `open()` and
       `/observe-payment`.
     - Or remove the dead entry and document that `withOcd` covers EVM
       networks only.
   - **Tests.** A real x402 Solana USDC requirement is recognized (or
     explicitly unsupported); mint comparison stays case-sensitive.

**Optional XS.** Make `isValidPaymentAddress` reject unknown CAIP-2 namespaces
as *unsupported network*, instead of defaulting to EVM rules and returning an
EVM-address error. Behavior stays fail-closed; only the error becomes accurate.

After those, revisit only when a trigger appears: a pilot needing Lightning, or
a second evidence class. At that point, design an explicit settlement
evidence-class concept (a receipt minor/major version decision) together with a
`lnbtc` verification profile.

## 8. Things not to build

- **Lightning support** (verification profile, SDK Lightning client, facilitator
  or receipt changes). There is no user or pilot demand, no merged official
  reference implementation, and a weaker evidence class. x402 supporting it is
  not a reason.
- **A receipt v2 or a generic "settlement rail" schema** before a second
  evidence class ships.
- **An `observe-payment` path for Lightning.** Nothing is independently
  observable. Any future endpoint must be named and labelled as proof
  verification, not observation.
- **Any site, MCP or README claim of Lightning or "multi-rail" settlement
  support.**
- **Base-USDC stays** the concrete production profile, alongside the existing
  Ethereum, Tempo and Solana observers. Add no new rail without adoption value.

## 9. Competitive implication

x402 becoming multi-rail **strengthens** the positioning "OnChainDiligence
independently evaluates payment intent and evidence across executors and
settlement rails". It also makes the honesty requirement sharper: evidence
strength now differs visibly by rail, and OCD's job is to say which class each
payment has.

| Layer | What it does | OCD's complement |
|---|---|---|
| x402 itself | Negotiation, payload formats, per-rail scheme logic | Records what was required and decided, and grades the resulting evidence per rail. Does not reimplement schemes |
| Facilitators | Verify and settle their own payments; for `lnbtc`, `/settle` "does not move funds" and records a replay key | A second party's evidence, not the facilitator's own `success: true`. Reconciles `settlement_pending` and contradictions |
| Wallet providers / Turnkey | Custody, policy-controlled signing, provider status | Evidence not authored by the executor: the independent observation (where a ledger exists) and reconciliation of the executor's claim |
| Chain explorers | Raw public ledger data (none for Lightning) | Interpretation under a finality policy, bound to intent and decision, signed and portable. For rails with no ledger, an explicit weaker evidence class instead of silence |

## 10. Primary sources (publication date / accessed)

| Source | Published | Accessed |
|---|---|---|
| Block, "Block Joins the x402 Foundation to Advance Open, Agentic Commerce", https://block.xyz/inside/block-joins-the-x402-foundation-to-advance-open-agentic-commerce | 2026-09-24 | 2026-09-28 |
| x402 v2 core spec, https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md (read at `a9955ae`; last core change 2026-08-31) | v2.0 2025-12-09 | 2026-09-28 |
| x402 `exact` on Lightning, https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_lnbtc.md | merged 2026-09-23 | 2026-09-28 |
| x402 `exact` family, https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact.md | last changed 2026-09-24 | 2026-09-28 |
| x402 `exact` on SVM, https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_svm.md | — | 2026-09-28 |
| PR #2861, https://github.com/x402-foundation/x402/pull/2861 | merged 2026-09-23 | 2026-09-28 |
| PR #3578, https://github.com/x402-foundation/x402/pull/3578 | merged 2026-09-27 | 2026-09-28 |
| PR #3083, `settlement_pending` (commit `6dba93e`), https://github.com/x402-foundation/x402/pull/3083 | merged 2026-08-17 | 2026-09-28 |
| Open implementation PRs: #2262 (TS), #1873 (Python), #3572 (invoice method) | open | 2026-09-28 |
| Linux Foundation, x402 Foundation launch, https://www.linuxfoundation.org/press/linux-foundation-is-launching-the-x402-foundation-and-welcoming-the-contribution-of-the-x402-protocol | 2026-04-02 | 2026-09-28 |
| BOLT11, https://github.com/lightning/bolts/blob/master/11-payment-encoding.md | — | 2026-09-28 |
| CAIP-2, https://chainagnostic.org/CAIPs/caip-2; BIP-122 namespace, https://namespaces.chainagnostic.org/bip122/caip2 | — | 2026-09-28 |

OCD code and specs reviewed:

| Repository | Revision | Files |
|---|---|---|
| `onchaindiligence-mcp` | `22931ba` | `src/receipts.ts`, `src/inputValidation.ts`, `src/preflight.ts`, `src/observePaymentRoute.ts`, `src/solanaSettlement.ts`, `src/signedPaymentClaimEvidence.ts` |
| `onchaindiligence-sdk` | `89cbcc6` | `src/commerce/withOcd.ts` |
| `onchaindiligence` | `9ed3853` | `docs/PUBLIC_ACTION_RECEIPT_V1.md`, `docs/SIGNED_PAYMENT_CLAIM_V1.md`, `packages/agent-evidence/schemas/public-action-receipt.schema.json`, `spec/agent-evidence/v0/schema/signed-claim-payment.v1.schema.json` |
