# Public Action Receipt v1 specification

Status: design specification; implementation must cite the exact revision it
implements.

Schema identifier: `onchaindiligence.public-action-receipt.v1`
Canonical schema: `spec/agent-evidence/v0/schema/public-action-receipt.schema.json`
Last updated: 2026-09-04

## 1. Scope

A public action receipt is a human-facing, **opt-in**, redacted projection of
one agent action: what was proposed, what was decided, whether it executed,
whether it settled, and what remains unknown. It is designed to be published
and independently verified by anyone, without that party trusting OnChain
Diligence's servers.

A receipt is **not** itself Agent Evidence. Building a receipt from an Agent
Evidence bundle never makes that bundle public — publication of a receipt is
always a separate, explicit act by whoever assembles its fields. Private
evidence is referenceable from a receipt only by content digest
(`links.agent_evidence_bundle_digest`, `checks[].evidence_digest`), never by
value.

Normative terms `MUST`, `MUST NOT`, `SHOULD`, and `MAY` are used as in RFC 2119.

## 2. Four independent statements

Every receipt carries four statements that a verifier or reader MUST keep
separate and MUST NOT collapse into one another:

| Statement  | Values | Answers |
|---|---|---|
| **PROOF** | `VALID` / `INVALID` / `UNVERIFIABLE` | Did the signer assert this exact receipt content, from a key still trusted? |
| **DECISION** | `ALLOW` / `REQUIRE_APPROVAL` / `BLOCK` / `UNKNOWN` | What did policy/mandate evaluation conclude? |
| **EXECUTION** | `NOT_SUBMITTED` / `SUBMITTED` / `CONFIRMED` / `FAILED` / `UNKNOWN` | Was the action actually submitted anywhere? |
| **SETTLEMENT** | `CONFIRMED` / `NOT_CONFIRMED` / `UNVERIFIED` / `NOT_APPLICABLE` | Was value movement independently confirmed? |

A receipt reading `PROOF: VALID` / `DECISION: REQUIRE_APPROVAL` /
`EXECUTION: NOT_SUBMITTED` / `SETTLEMENT: NOT_APPLICABLE` is a normal, honest,
and desirable result. `VALID` means the cryptographic assertion is genuine —
it never means the action was approved, executed, or settled, and it never
means the receipt's factual inputs (e.g. a claimed identity binding) were
objectively correct. A transaction hash being present is not settlement
confirmation; `SETTLEMENT: CONFIRMED` MUST NOT be set unless confirmation was
independently verified.

## 3. Envelope

```json
{
  "schema": "onchaindiligence.public-action-receipt.v1",
  "receipt": { "...": "see section 4" },
  "proof": { "...": "see section 6" }
}
```

`additionalProperties` is `false` at every object level in the schema — an
envelope, receipt, or nested object carrying an unexpected field is rejected,
not silently ignored.

## 4. Receipt fields

| Field | Type | Notes |
|---|---|---|
| `receipt_id` | string | Locator only. See section 5. NOT authoritative. |
| `receipt_digest` | string | `sha256:<base64url>`. Authoritative. See section 5. |
| `receipt_type` | `PREFLIGHT` \| `COMMERCE` \| `ACTION` | See section 4.1. |
| `issued_at` | timestamp | Exact `YYYY-MM-DDTHH:mm:ss.sssZ`, per Agent Evidence v0 §2. |
| `action` | object | `kind`, `resource`, `network`, `asset`, `amount`, `sender`, `recipient`. `sender`/`recipient` are wallet addresses; they are never identity claims (section 8). |
| `decision` | object | `status`, `authorized` (boolean or null), `reasons` (string array). |
| `execution` | object | `provider`, `status`, `transaction_hash`, `submitted_at`, `confirmed_at` — all nullable except `status`. |
| `settlement` | object | `status`, `detail`. |
| `checks` | array | Each: `id` (stable kebab-case), `result` (`PASS`/`FAIL`/`UNKNOWN`/`NOT_CHECKED`), `summary` (concise, public-safe text), `evidence_digest` (nullable digest reference, never raw evidence). |
| `links` | object | `agent_evidence_bundle_digest`, `preflight_receipt_id` — both nullable. A `COMMERCE` receipt SHOULD set `preflight_receipt_id` when a preflight preceded it. |
| `limitations` | array of strings | Plain-language disclosures of what this receipt does not establish. MUST travel with the receipt itself — a disclosure that lives only in a UI does not satisfy this. |

Nullable fields use explicit `null`/`UNKNOWN`/`NOT_CHECKED`/`NOT_APPLICABLE`
values rather than being omitted. A field is never left out merely because a
truthful receipt does not know its value.

### 4.1 Receipt types

- **PREFLIGHT** — issued before execution. Describes the proposed action, the
  evidence considered, the policy decision, and whether the caller is
  authorized to proceed. `execution.status` is typically `NOT_SUBMITTED` or
  `UNKNOWN`; it MUST NOT be `CONFIRMED`.
- **COMMERCE** — issued after a payment/execution attempt. References its
  originating preflight via `links.preflight_receipt_id` when one exists,
  states the execution provider, the exact payment facts, the transaction
  reference, and settlement status.
- **ACTION** — a general, non-payment receipt. Exists so the Receipt Explorer
  can launch, and a receipt resolver can be exercised end-to-end, without
  fabricating commerce before the first real x402 payment happens.

## 5. Receipt ID and digest — canonicalization, no circularity

`receipt_digest` is computed over the **receipt core**: every receipt field
*except* `receipt_id` and `receipt_digest` themselves —
`receipt_type`, `issued_at`, `action`, `decision`, `execution`, `settlement`,
`checks`, `links`, `limitations`. This is exactly the `ReceiptCoreFields`
shape in `packages/agent-evidence/src/receipts.ts`.

Algorithm (`computeReceiptDigest`, implemented via this package's existing
`contentId`):

1. Take the receipt core object.
2. Serialize it as RFC 8785 canonical JSON (same canonicalizer as Agent
   Evidence content IDs — `packages/agent-evidence/src/canonical.ts`).
3. SHA-256 the canonical bytes.
4. Format as `sha256:<base64url-of-digest>` (unpadded).

`receipt_id` is derived **from** `receipt_digest`, never the reverse — this is
what makes the two non-circular:

1. Decode the `sha256:<base64url>` digest to raw bytes.
2. Take the first 10 bytes (80 bits).
3. Encode those bytes as [Crockford Base32](https://www.crockford.com/base32.html)
   (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, excluding the visually
   ambiguous `I`, `L`, `O`, `U`). 80 bits divides evenly into 16 five-bit
   Crockford characters, so there is no padding ambiguity.
4. Group into four blocks of four characters and prefix: `OCD-RCP-XXXX-XXXX-XXXX-XXXX`.

`receipt_id` is a **locator, not an authority**. It is deterministic (the same
receipt content always yields the same id) and is not sequential — it carries
no counter, so it never leaks activity volume and is not guessable from a
neighboring receipt. It is not itself proof of anything: a resolver or
verifier MUST independently recompute `formatReceiptId(receipt_digest)` and
confirm it equals the received `receipt_id` before trusting a lookup result
(`verifyReceiptEnvelope`'s `id-mismatch` check). Because only 80 of the
digest's 256 bits are encoded into the id, decoding is one-directional:
correctness is always checked forward (core → digest → id), never backward.

Finalizing a receipt (`finalizeReceiptCore`) therefore proceeds strictly in
this order: build and validate the core → compute `receipt_digest` from the
core → derive `receipt_id` from `receipt_digest` → attach both to produce the
signable `receipt` object. Nothing in this order can create a circular
dependency between `receipt_id`, `receipt_digest`, and `proof`.

## 6. Cryptographic proof

Public action receipts reuse the product's existing
`onchaindiligence.attestation.v2` signing scheme unchanged — no new trust
primitive was introduced. The `proof` object has the same shape as every other
attestation v2 signature in this product:

```json
{
  "signed": true,
  "schema_version": "onchaindiligence.attestation.v2",
  "issuer": "https://api.onchaindiligence.com",
  "purpose": "public-action-receipt",
  "issued_at": "2026-09-04T11:00:01.000Z",
  "key_id": "ed25519-...",
  "algorithm": "ed25519",
  "signature": "<86-char unpadded base64url>"
}
```

The signing input (`receiptAttestationSigningInput`) is RFC 8785 canonical
JSON over:

```json
{
  "schema_version": "onchaindiligence.attestation.v2",
  "issuer": "<issuer>",
  "purpose": "public-action-receipt",
  "data": { "...": "the complete finalized receipt object, including receipt_id and receipt_digest" },
  "issued_at": "<issued_at>",
  "key_id": "<key_id>"
}
```

This module never signs anything itself and holds no private key. In
production, the caller obtains `proof` by calling the existing `POST /attest`
endpoint in `onchaindilige` (the only process holding
`ATTESTATION_PRIVATE_KEY`) with `purpose: "public-action-receipt"` and the
finalized receipt as `data`.

### 6.1 Verification and the tri-state result

`verifyReceiptEnvelope(envelope, policy)` performs, in order, each step
fail-closed:

1. Validate the envelope against `public-action-receipt.schema.json`. Failure
   → `INVALID` (`schema-invalid`).
2. Recompute `receipt_digest` from the receipt core and compare. Mismatch →
   `INVALID` (`digest-mismatch`).
3. Recompute `receipt_id` from `receipt_digest` and compare. Mismatch →
   `INVALID` (`id-mismatch`).
4. Verify `proof` as an `onchaindiligence.attestation.v2` signature over the
   complete `receipt` object via `verifyAttestationV2`, checking exact
   `issuer`/`purpose` match, Ed25519 signature validity against the
   caller-supplied `TrustPolicy`, and the signing key's lifecycle at
   `proof.issued_at` (`evaluateKeyLifecycle` — the same function Agent
   Evidence bundle verification uses).

This reuses `packages/agent-evidence`'s existing tri-state philosophy exactly:

- **VALID** — schema-conformant, digest and id both match, signature verifies
  against a key the caller's `TrustPolicy` trusts, and that key's lifecycle
  covers `issued_at`.
- **INVALID** — any of: schema violation, digest/id mismatch, wrong
  issuer/purpose, malformed or non-verifying signature, a revoked or
  compromised key, or a signed time outside the key's validity window. Content
  tampering after signing always lands here (digest or signature mismatch).
- **UNVERIFIABLE** — the signing key is absent from the caller's
  `TrustPolicy` (unknown signer, or the trust registry was unreachable), or
  the key has no defensible `valid_from` boundary. Unavailability of trust
  material is never treated as evidence of tampering, and never silently
  upgraded to `VALID`.

`verifyAttestationV2` (`packages/agent-evidence/src/attestationV2.ts`) is
intentionally generic and reusable — it is the same small,
lifecycle-aware verifier the previously deferred free MCP `verify_attestation`
tool can use, since that tool was deferred for lack of exactly this: a
tri-state verifier consulting the real key-lifecycle registry instead of a
boolean. No further SDK redesign was performed or is implied by this reuse.

## 7. Public / private boundary

A public receipt MAY expose: `receipt_id`, `receipt_digest`, `issued_at`,
`receipt_type`, public wallet addresses, network, asset, amount, decision
status/reasons, execution status/transaction hash, high-level check
results and summaries, evidence digests (references only), and limitations.

A public receipt MUST NOT expose: internal mandate text, customer names,
supplier documents, raw KYC/KYB evidence, private notes, credentials, tokens,
private API responses, or any other secret. Private evidence is referenceable
only by digest (`links.agent_evidence_bundle_digest`, `checks[].evidence_digest`).

Publication is opt-in per receipt. Nothing in this schema or in
`packages/agent-evidence` makes an existing or future Agent Evidence bundle
public; a receipt is a deliberately constructed, redacted projection assembled
by a caller who decides what to disclose.

## 8. Identity and settlement language

`action.sender` / `action.recipient` are wallet addresses. A receipt MUST NOT
imply that a wallet address belongs to a named legal entity unless a separate,
referenced evidence record establishes that binding. Where a claimed
counterparty identity is asserted, it MUST be represented as its own checked
claim (e.g. a `receiptCheck` with id `recipient-wallet-bound-to-counterparty`)
rather than folded into the wallet field itself — "recipient wallet is
`0x...`" and "this wallet belongs to Acme Ltd" are different claims with
different evidence, and a receipt keeps them visibly separate.

Likewise, `execution.transaction_hash` being present is a claim that a
transaction was submitted, not that it settled. `settlement.status` MUST only
be `CONFIRMED` when settlement was independently verified; otherwise
`NOT_CONFIRMED`, `UNVERIFIED`, or `NOT_APPLICABLE` applies.

## 9. Schema and packaging

The canonical schema lives at
`spec/agent-evidence/v0/schema/public-action-receipt.schema.json` and is
listed in that directory's `catalog.json` (`schemas[]` and
`entry_points.public_action_receipt`). Per the existing asset-sync contract,
it is mirrored byte-for-byte into:

- `packages/agent-evidence/schemas/public-action-receipt.schema.json` (TypeScript package, synced via `npm run sync-assets`)
- `python/src/onchaindiligence/agent_evidence/schemas/public-action-receipt.schema.json` (Python package, manual copy)

Both mirrors are covered by the existing byte-exact-copy conformance test
(`test_packaged_schemas_are_exact_contract_copies` in the Python suite, and
the analogous check in the TypeScript `npm run check:assets` step). Neither
package was published to npm/PyPI as part of introducing this schema.

## 10. Resolution

A receipt resolver serves `GET /receipts/:receiptId`, returning the complete
envelope of section 3 for a known id, or 404 for an unknown one. A resolver
MUST perform the full section 6.1 verification pipeline before considering a
stored receipt servable, and MUST NOT serve a receipt whose stored
`receipt_id`/`receipt_digest` fail to match a fresh recomputation. Resolvers do
not accept public, unauthenticated writes; publication into a resolver's store
is a separate, authenticated act.
