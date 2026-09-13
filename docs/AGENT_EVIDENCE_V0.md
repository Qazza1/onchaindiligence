# Agent Evidence v0 specification

Status: design specification; implementation must cite the exact revision it
implements.

Specification ID: `onchaindiligence.agent-evidence.v0`
Last updated: 2026-08-28

The Python reference implementation at `python/` version `0.1.0` implements
this 2026-08-28 revision and consumes the same packaged conformance corpus.

Normative JSON Schemas are indexed by
`spec/agent-evidence/v0/schema/catalog.json` and published at
`https://onchaindiligence.com/schemas/agent-evidence/v0/catalog.json`. The
language-neutral corpus is under `spec/agent-evidence/v0/conformance`; its
manifest records the expected tri-state result for every case.

## 1. Scope

Agent Evidence v0 defines a portable, deterministic, signed evidence graph for
one consequential agent run. It specifies representation and verification, not
universal identity, authorization, policy execution, or objective truth.

Normative terms `MUST`, `MUST NOT`, `SHOULD`, and `MAY` are used as in RFC 2119.

## 2. Encoding and cryptographic profile

- JSON text MUST be UTF-8.
- Values covered by deterministic IDs MUST satisfy the I-JSON constraints used
  by [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html): no duplicate
  object names, only Unicode strings, and IEEE-754-safe JSON numbers. Monetary
  amounts, chain IDs, block numbers, counters, and other precision-sensitive
  integers MUST be decimal strings.
- Normative timestamp fields MUST be valid UTC date-times in the exact lexical
  form `YYYY-MM-DDTHH:mm:ss.sssZ`. This removes cross-runtime ambiguity around
  offsets and fractional precision. These values remain signer assertions
  unless backed by an independent timestamp proof.
- SHA-256 is the v0 content-digest algorithm.
- New signatures use Ed25519 in a
  [DSSE v1](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md)
  envelope. DSSE signs `PAE(payloadType, payload)` and therefore does not rely
  on reparsing JSON before signature verification.
- The DSSE `payload` and `sig` fields use standard padded base64, as specified
  by DSSE. Existing attestation v2 signatures retain unpadded base64url.
- A v0 producer MUST serialize the DSSE payload using RFC 8785 before signing.
  A verifier first verifies the exact DSSE payload bytes, then parses them, and
  MUST reject a payload whose bytes are not its RFC 8785 representation.
- The v0 DSSE payload type is
  `application/vnd.onchaindiligence.agent-evidence.bundle.v0+json`.

This adopts DSSE's domain separation and byte-oriented verification without
replacing the existing `onchaindiligence.attestation.v2` signing scheme.

## 3. Portable file

The portable file is a JSON object:

```json
{
  "media_type": "application/vnd.onchaindiligence.agent-evidence+json",
  "bundle_version": "onchaindiligence.agent-evidence.bundle.v0",
  "envelope": {
    "payloadType": "application/vnd.onchaindiligence.agent-evidence.bundle.v0+json",
    "payload": "<standard-base64 RFC8785 payload bytes>",
    "signatures": [{ "keyid": "ed25519-...", "sig": "<standard-base64>" }]
  },
  "verification_material": {
    "keys": [],
    "registry_snapshots": [],
    "anchors": []
  }
}
```

`bundle_version` outside the envelope is a routing hint only. The signed
payload contains the authoritative version. A mismatch is `INVALID`.

`verification_material` is deliberately outside the DSSE envelope. It may be
updated with a newer trust snapshot or inclusion proof without changing the
signed evidence. Embedded material is never trusted merely because it is
embedded.

The v0 portable-file schema uses three typed containers: `keys` contains the
key-record shape from section 7; each `registry_snapshots` item contains
`media_type`, a SHA-256 `digest`, and `value`; each `anchors` item contains an
`anchor_type` and `value`. Snapshot and anchor payload formats are selected by
their discriminator and are verified only when the caller's policy supports
that format. Unknown or untrusted material remains a hint, not a trust root.

## 4. Signed bundle payload

After base64 decoding, `envelope.payload` is:

```json
{
  "bundle_version": "onchaindiligence.agent-evidence.bundle.v0",
  "bundle_id": "sha256:<base64url digest>",
  "created_at": "2026-08-27T12:00:00.000Z",
  "run_id": "sha256:<record digest>",
  "root_ids": ["sha256:<record digest>"],
  "records": [],
  "extensions": {}
}
```

- `records` MUST be sorted lexicographically by `id` and contain no duplicate
  IDs.
- `root_ids` MUST be sorted, unique, and equal the complete set of records with
  no children in this bundle. Every record MUST be reachable by walking parent
  links from those roots. This makes removal of a terminal decision or
  execution detectable even if the remaining records still form a valid DAG.
- `run_id` MUST resolve to exactly one `run` record.
- `extensions` keys MUST be absolute URIs. Unknown extensions do not change
  core semantics; an extension marked critical by a future version makes v0
  verification `UNVERIFIABLE`.
- `created_at` is the bundle sealer's asserted time. It is not a trusted
  timestamp.
- `bundle_id` is `sha256:` plus unpadded base64url SHA-256 of RFC8785 bytes for
  the payload with `bundle_id` omitted.

## 5. Common record

Every graph record has this shape:

```json
{
  "id": "sha256:<base64url digest>",
  "record_version": "onchaindiligence.agent-evidence.record.v0",
  "kind": "evidence",
  "parents": ["sha256:<record digest>"],
  "statement": {},
  "proofs": []
}
```

`id` is `sha256:` plus unpadded base64url SHA-256 of RFC8785 bytes over the
record with `id` omitted. Consequently the ID binds `record_version`, `kind`,
`parents`, `statement`, and `proofs`.

`parents` MUST be sorted, unique, and refer to records in the same payload. A
parent is an input or predecessor, so edges point from a record to what it
depends on. Self references, missing parents, and cycles are invalid.

`proofs` contains source-level proofs for the statement. Bundle signatures bind
graph placement; source proofs bind what a source asserted. A source proof does
not imply the source selected the graph parents unless its signed statement
explicitly includes them.

## 6. Record kinds

### 6.1 Principal

`kind: "principal"`; no parents.

```json
{
  "principal_id": "urn:example:treasury:acme",
  "principal_type": "organization",
  "identity_refs": [{ "type": "oidc-subject", "issuer": "https://id.example", "subject": "..." }],
  "display_name": "Acme Treasury"
}
```

Identity references are assertions or external identifiers. OnChainDiligence
does not become their source of truth. `display_name` is optional presentation
metadata and MUST NOT be used as an authorization identity.

### 6.2 Agent

`kind: "agent"`; parents include its operator principal when one is asserted.

Required fields are `agent_id` and `agent_version`. Optional stable fields are
`framework`, `deployment_ref`, `model_ref`, and `operator_ref`. Prompts,
ephemeral runtime statistics, and mutable labels SHOULD NOT be included unless
they are relevant evidence.

### 6.3 Mandate

`kind: "mandate"`; parents MUST include the delegating principal.

Required fields: `mandate_id`, `principal_ref`, `scope`, `valid_from`, and
`valid_until`. Optional fields: structured `limits`, `policy_refs`, an external
`authorization_ref`, and `authorization_digest`.

A mandate records the authorization presented to the run. It does not mean
OnChainDiligence granted the authorization. A mandate without a trusted
principal proof remains an agent assertion.

### 6.4 Run

`kind: "run"`; parents MUST include one agent and one mandate.

Required fields: `run_external_id`, `agent_ref`, `mandate_ref`, and
`started_at`. `ended_at` is optional until sealed. A v0 bundle contains exactly
one run record.

### 6.5 Evidence Node

`kind: "evidence"`; parents MUST include the run and MAY include prior evidence
records.

```json
{
  "evidence_type": "sanctions-screen",
  "run_ref": "sha256:...",
  "trust_mode": "publisher-signed",
  "source": { "id": "https://api.onchaindiligence.com", "type": "https-api" },
  "tool": { "name": "screen_wallet", "version": "1" },
  "request": { "digest": { "sha256": "..." }, "media_type": "application/json" },
  "response": {
    "mode": "embedded",
    "media_type": "application/vnd.onchaindiligence.attestation.v2+json",
    "value": { "data": {}, "attestation": {} },
    "digest": { "sha256": "..." }
  },
  "observed_at": "2026-08-27T12:00:01.000Z",
  "expires_at": null,
  "scope": { "query": "0x...", "coverage": "one address at one observation time" }
}
```

`trust_mode` is exactly one of:

- `publisher-signed`: the upstream publisher signed its assertion;
- `local-witness`: a customer-controlled witness observed and signed it;
- `managed-witness`: OnChainDiligence observed an upstream response and signed
  that observation;
- `agent-assertion`: the agent asserted it.

The verifier MUST display the trust mode. It MUST NOT elevate an
`agent-assertion` or witness observation to `publisher-signed`.

The request and response may be embedded or digest-and-reference. References
MUST use HTTPS or another explicitly supported immutable scheme. If content
needed by a verification policy is absent and cannot be resolved, the result is
`UNVERIFIABLE`, never valid. Secrets, credentials, and unnecessary personal
data MUST NOT be embedded.

Negative evidence is valid only within `scope`. A no-match sanctions response
means no match for the exact query, provider, dataset behavior, and observation
time represented by the node; it is not universal absence.

### 6.6 Policy reference

`kind: "policy"`; parents include the run or mandate.

Required fields: `policy_id`, `version`, `digest`, `source`, and
`effective_from`. `effective_until` and an embedded policy are optional. The
digest MUST cover the exact policy bytes or canonical object the decision
claims to have used. V0 proves association, not correct policy execution.

### 6.7 Decision

`kind: "decision"`; parents MUST be exactly the sorted unique union of the run,
the referenced policy, and all `evidence_refs`.

Required fields: `decision_id`, `run_ref`, `agent_ref`, `decision_type`,
`outcome`, non-empty `evidence_refs`, `policy_ref`, `policy_digest`, and
`decided_at`. Every evidence reference MUST resolve to an `evidence` record in
this bundle. `policy_digest` MUST equal the referenced policy record's digest.

This explicit reference rule is mandatory: a decision that does not identify
its evidence cannot be valid Agent Evidence v0.

### 6.8 Execution

`kind: "execution"`; parents MUST include exactly one decision plus any receipt
records explicitly used.

Required fields: `execution_id`, `decision_ref`, `execution_type`, `status`, and
`submitted_at`. Onchain execution additionally requires `network` as CAIP-2,
`transaction_hash`, and a digest of the intended or submitted transaction.
`sender`, `recipient`, `asset`, `amount`, `confirmed_at`, and `block_number` are
included when known; quantities are strings.

The verifier reports whether a transaction/receipt is internally bound and
whether an optional external resolver confirmed it. It MUST NOT claim the
agent caused the execution unless a trusted authorization or wallet proof binds
the agent/mandate to the transaction.

## 7. Proofs and key records

Proof types supported by v0:

1. `dsse-ed25519-v1`: a DSSE envelope over the record's RFC8785 `statement`.
2. `onchaindiligence-attestation-v2`: an embedded, unmodified current
   `{data, attestation}` envelope. The verifier applies the existing v2 rules.
3. `onchaindiligence-attestation-v1`: an embedded legacy envelope verified only
   with its original `JSON.stringify({data, issued_at, key_id})` semantics.
4. `external-digest`: a typed digest/reference with no source signature. It can
   establish graph integrity but does not establish source attribution.

Proof objects use the following exact discriminated shapes. This closes the
representation boundary without changing the trust semantics above:

```json
{
  "proof_type": "dsse-ed25519-v1",
  "statement_media_type": "application/example+json",
  "envelope": { "payloadType": "...", "payload": "...", "signatures": [] }
}
```

```json
{
  "proof_type": "onchaindiligence-attestation-v2",
  "envelope": { "data": {}, "attestation": {} }
}
```

The v1 proof has the same outer shape with
`proof_type: "onchaindiligence-attestation-v1"`; its attestation MUST omit
`schema_version`. An external digest proof is:

```json
{
  "proof_type": "external-digest",
  "media_type": "application/example",
  "digest": { "sha256": "<43-character unpadded base64url>" },
  "reference": "https://example.invalid/optional-immutable-reference"
}
```

`reference` is optional. A digest proof never becomes publisher-signed merely
because referenced content is retrievable.

A key record is:

```json
{
  "key_id": "ed25519-...",
  "algorithm": "ed25519",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----...",
  "status": "active",
  "valid_from": "2026-08-27T00:00:00.000Z",
  "valid_until": null,
  "status_changed_at": "2026-08-27T00:00:00.000Z",
  "replacement_key_id": null,
  "compromised_at": null
}
```

Statuses are `active`, `retired`, `revoked`, or `compromised`. Normal retirement
keeps historical signatures trusted when their signed time falls inside the
key validity interval. A revoked or compromised key is not trusted. A future
profile may allow pre-compromise verification only with independently
timestamped evidence; v0 fails closed.

## 8. Trust model and offline key resolution

Cryptographic validity and identity trust are independent.

- Embedded public keys are untrusted verification hints.
- A verifier MUST receive a trust policy out-of-band, such as pinned key IDs,
  a pinned registry root, or a previously trusted signed registry snapshot.
- Online HTTPS key discovery is convenience, not offline verification and not
  a substitute for an explicit trust decision.
- A signed registry snapshot may supply historical keys only when its signing
  root is already pinned by the verifier and the snapshot version/freshness
  satisfies policy.
- Key IDs are hints. The verifier MUST derive the expected ID from the SPKI key
  bytes and reject a mismatch.
- `issued_at` MUST fall within `valid_from` and `valid_until` inclusive. A v0
  key lacking `valid_from` is `UNVERIFIABLE` under the default policy.

This follows the central Sigstore lesson: bundled verification material is not
itself a trust root. Sigstore similarly separates artifact bundles from a
client's trusted root and distributes changing trust material through TUF. See
the [Sigstore threat model](https://docs.sigstore.dev/about/threat-model/) and
[TrustedRoot schema](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto).

## 9. Timestamp and freshness semantics

- `issued_at`, `observed_at`, `decided_at`, `submitted_at`, and `created_at` are
  signer assertions unless backed by an independent timestamp proof.
- An anchor or transparency-log checkpoint proves the commitment existed no
  later than the externally verified checkpoint time.
- `expires_at` and a policy's `max_age` are business freshness constraints.
  They do not change whether old bytes have a valid signature.
- Verification reports signature time validity, external timestamp state, and
  freshness state separately.
- Future timestamps beyond a caller-configured clock skew are invalid under
  the default policy.

## 10. Deterministic verification algorithm

In order, a verifier MUST:

1. Parse the outer JSON with duplicate-key rejection and bounded depth, size,
   record count, string length, and array length.
2. Recognize `media_type`, outer version, DSSE payload type, and algorithm.
3. Resolve each DSSE key from the supplied trust policy/material.
4. Verify DSSE PAE signatures over the exact decoded payload bytes.
5. Parse payload JSON with duplicate-key rejection and reject non-RFC8785 bytes.
6. Confirm inner/outer versions, recompute `bundle_id`, and enforce ordering.
7. Recompute every record ID; reject duplicates and unresolved parents.
8. Detect cycles using a complete topological traversal.
9. Enforce kind-specific parent and reference invariants.
10. Verify every required source proof, key ID, key status, and key validity
    interval without silently falling back to another key.
11. Evaluate timestamp and caller-supplied freshness policy.
12. Verify optional anchor/inclusion proofs separately. An unavailable optional
    anchor is reported, not treated as a valid anchor.
13. Return a machine-readable report plus one overall state.

Overall states:

- `VALID`: all required structures and signatures verify, every required key is
  trusted for the relevant time, and caller policy passes.
- `INVALID`: definite tampering or policy violation, including a bad signature,
  changed ID, duplicate/missing reference, cycle, forbidden key status,
  version mismatch, stale required evidence, or changed decision/execution.
- `UNVERIFIABLE`: the verifier lacks necessary trust material or support, such
  as an unknown key, unavailable digest-only payload required by policy, or an
  unsupported critical extension.

The report MUST retain component states so a cryptographically valid signature
under a distrusted key is visible without being called valid.

## 11. Backwards compatibility

- Existing API routes and `onchaindiligence.attestation.v2` signing bytes remain
  unchanged.
- Legacy v1 remains an explicit verification profile; absence of
  `schema_version` is never interpreted as v0.
- Existing envelopes may be embedded as the response of an Evidence Node. The
  v0 node and bundle bind that envelope without re-signing or changing its
  historical meaning.
- New APIs use additive `/evidence/v0` paths and new media types.
- No v0 verifier may fall back from an unknown v0 version to legacy behavior.

## 12. Standards interoperability

- DSSE is adopted for new envelopes because its PAE authenticates payload type
  and exact bytes and supports multiple signatures.
- The
  [in-toto Attestation Framework](https://github.com/in-toto/attestation/blob/main/spec/README.md)
  informs the separation of statement, envelope, and bundle. Agent Evidence is
  not labeled as an in-toto Statement because its subject is an agent run and
  evidence DAG rather than software artifacts.
- Sigstore/TUF concepts inform trust-root distribution and transparency, but
  Sigstore keyless identity is not required in v0.
- MCP tool results can carry a bundle reference in `structuredContent` or
  namespaced `_meta`; MCP annotations remain untrusted unless the server is
  trusted. See the current
  [MCP tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools).
- OpenTelemetry remains the observability source. Evidence may reference trace
  and span IDs and selectively digest consequential attributes. Sensitive tool
  arguments/results are opt-in, matching the warnings in the current
  [OpenTelemetry GenAI conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/).
- OIDC issuer/subject pairs may identify principals, following
  [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0-final.html),
  but are not automatically authorization evidence.
- x402 v2 and MPP receipts may be execution/economic evidence. A payment proves
  its own authorization/settlement fields, not the truth of the purchased API
  response. x402 v2 is versioned and uses CAIP-2 network identifiers; see the
  [official specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md).

## 13. V0 limits

V0 does not define selective disclosure, redaction-preserving signatures,
multi-run bundles, universal principal identity, policy execution proofs,
custody, a publisher reputation system, mandatory transparency, or causal
proof between a model decision and a transaction. These require later,
versioned profiles.

## 14. Portable evidence bundles (D4.2)

This section documents additive changes to `bundle-payload.schema.json` that
let one bundle package a heterogeneous set of already-existing signed OCD
artifacts for external distribution, and the current, honest limits of what
today's reference verifiers can check about that packaging. It does not
introduce a new format, does not replace any existing artifact, and does not
change any required field, so every existing v0 bundle remains valid.

### 14.1 Bundle-level additions

Three new OPTIONAL top-level fields on `bundle-payload.schema.json`:

- `issuer` (string) -- the bundle sealer's asserted identity, following the
  same convention as `onchaindiligence.attestation.v2`'s `issuer` field. It is
  an assertion, not itself a trust root; omitting it does not change
  `bundle_id` or verification.
- `reconciliation` (object) -- a bounded summary of facts already established
  by the bundle's own records: `agreements[]`, `contradictions[]`, and
  `insufficient_evidence[]`, each entry naming the `record_ids` it draws on.
  It MUST NOT introduce a claim not otherwise evidenced by a record in the
  same bundle. Missing evidence for a subject belongs in
  `insufficient_evidence`, never `contradictions` -- a contradiction requires
  at least two referenced records whose own statements/proofs disagree.
- `limitations` (string array) -- same convention as
  `public-action-receipt.schema.json`'s `limitations` field. A bundle intended
  for external distribution SHOULD state at minimum that bundle validity
  proves cryptographic integrity under the verifier contract and does not by
  itself establish authorization, safety, settlement, delivery, compliance,
  service quality, or economic outcome.

No new `$id`, no new schema version, no change to `records`, no change to any
required field. `bundle_id` continues to be the digest of the full payload
(now inclusive of these three fields when present), so populating or omitting
them changes `bundle_id` exactly like any other payload content does today --
no special-casing was added.

### 14.2 Embedding heterogeneous artifacts

The v0 record-graph model (`record.schema.json`, `proof.schema.json`) already
supports embedding an existing signed artifact unmodified as the `response` of
an Evidence Node (section 11). D4.2 does not add a fifth `proof_type`. Instead
it uses the two that already exist, matched to what each real production
artifact shape actually is:

- Artifacts already shaped as `{data, attestation}`
  (`onchaindiligence.attestation.v2`) -- `erc20-allowance-action`,
  `swap-action`, `bridge-action`, `staking-action`, and compliance-screening
  results -- embed via the existing `onchaindiligence-attestation-v2` proof
  type with zero changes. The verifier already checks this proof's signature,
  issuer, and (for one purpose today -- see 14.4) attestation purpose.
- `onchaindiligence.public-action-receipt.v1` is shaped `{schema, receipt,
  proof}`, not `{data, attestation}`, so it does not fit `v2Envelope`. It
  embeds via the existing `external-digest` proof type, which honestly reports
  "digest is bound by the record ID but does not establish source
  attribution" (`record.schema.json`'s own documented semantics for that
  proof type, unchanged). An evidence node embedded this way MUST use
  `trust_mode: "agent-assertion"` -- any other `trust_mode` value requires a
  record-level cryptographic source proof
  (`verifier.py::_verify_record_proofs`, no else branch beyond
  `agent-assertion`), which `external-digest` does not provide. This was
  caught empirically during fixture construction: an earlier draft fixture
  used `trust_mode: "publisher-signed"` for a receipt embedded via
  `external-digest` and the reference verifier correctly rejected it
  (`cryptographic-proof-missing`).

  A second, separate defect was caught the same way, one layer deeper: a
  receipt's own internal `proof` (independent of the outer graph proof above)
  must be `receiptAttestationSigningInput`'s exact contract
  (`packages/agent-evidence/src/receipts.ts`) -- RFC 8785 canonical JSON over
  `{schema_version, issuer, purpose, data, issued_at, key_id}` where `data` is
  the **full finalized receipt** (i.e. including `receipt_id`/`receipt_digest`,
  never the pre-digest core), `issuer` is `PUBLIC_ACTION_RECEIPT_ISSUER`
  (`https://api.onchaindiligence.com`), and `purpose` is exactly
  `PUBLIC_ACTION_RECEIPT_PURPOSE` (`"public-action-receipt"`) -- **not** the
  receipt's own underlying action kind (`erc20-allowance-action`, etc.; that
  string is the purpose used for signing the *evidence-node's own*
  `onchaindiligence-attestation-v2` artifacts elsewhere in this bundle, a
  different signing site entirely). An earlier committed fixture signed the
  pre-digest core under the wrong purpose and used a hand-picked, non-digest
  -derived `receipt_id` -- `verifyReceiptEnvelope`'s real digest/id-recompute
  and `verifyAttestationV2`'s real purpose/signature checks (both unmodified,
  `packages/agent-evidence/src/receipts.ts` and `attestationV2.ts`) correctly
  caught this before merge. The fixture generator (`generate.mjs`) now derives
  `receipt_id` from `receipt_digest` via the same Crockford Base32 encoding as
  `receiptId.ts::formatReceiptId`, and signs the full finalized receipt under
  the correct purpose.
- No standalone "provider evidence" or "settlement/payment evidence" artifact
  schema exists in the current codebase (confirmed by inspection of
  `onchaindiligence-mcp/src/providerEvidence.ts`). That evidence is only
  reachable today via a `public-action-receipt.v1`'s own `checks[]` /
  `execution` / `settlement` / `links` fields, so it is covered by the same
  `external-digest` embedding as any other receipt.
- A well-formed artifact of a schema/family the verifier does not recognize
  embeds the same way: `external-digest`, `trust_mode: "agent-assertion"`. See
  14.4 for how this is reported today versus the D4.2 goal.

`public-action-receipt.schema.json` already defines
`links.agent_evidence_bundle_digest`, confirming receipts are already meant to
reference back to a containing bundle by digest -- this bundle design is the
intended container, not a new parallel one.

### 14.3 Bundle vs. child verification (and today's actual gap)

The task goal is to keep two results visibly distinct: (1) bundle integrity
(does the outer DSSE signature cover the exact manifest and artifact
inventory, unmodified) and (2) each embedded artifact's own verification
result (VALID / INVALID / UNVERIFIABLE). A cryptographically valid bundle must
never be reported in a way that implies every embedded artifact is valid.

**Today's `verify_bundle()` / `verifyBundle()` do not yet separate these.**
Both aggregate every component -- outer DSSE check, graph check, and every
per-record proof check -- into one `overall_state` via a single precedence
rule (`models.py::overall_state`: any required `INVALID` wins, else any
`UNVERIFIABLE` wins, else `VALID`). This was verified directly, not asserted:
the `bundle-invalid-child` fixture is sealed *after* corrupting one embedded
attestation signature, so its outer DSSE signature is genuinely valid over its
exact (tampered) content -- yet `verify_bundle()` reports the whole bundle
`INVALID`, because the corrupted child's `source-proof` component is required
and INVALID. Symmetrically, `bundle-unverifiable-child` (one artifact signed
by a key outside the caller's trust set) makes the whole bundle
`UNVERIFIABLE`, not just that one artifact.

This is an honest, code-verified gap, not a hypothetical one -- see 14.7 for
the recommended fix. Every other bundle-tamper fixture in this pass (tampered
manifest, removed artifact, inserted artifact) already gets the correct
`INVALID` result today, because those failures live entirely in the DSSE/graph
layer that `overall_state` already isolates correctly when no per-child proof
is also failing.

### 14.4 Unknown artifact types

An unrecognized `proof_type` string cannot reach a verifier at runtime at all:
`proof.schema.json`'s `oneOf` is closed over exactly four variants, so schema
validation rejects it before any verifier code runs. This is why D4.2 does not
add a fifth `proof_type` -- `_verify_record_proofs` has no default/else branch
for an unrecognized `proof_type`, so a producer who added one without a
matching verifier update would get a silent skip (no result at all), which is
worse than any tri-state outcome and exactly the "silently trusted" failure
mode this task warns against.

What CAN vary is the artifact's own *content family* (`evidence_type`, or an
embedded object's own `schema` field) -- a free-form string the verifier's
proof-type dispatch never inspects. The `bundle-unknown-artifact-type` fixture
confirms today's actual behavior: a well-formed record of schema
`onchaindiligence.some-future-action.v9`, embedded via `external-digest`,
verifies `VALID` (graph-bound, no source-attribution claim -- which is true as
far as it goes). It does **not** become `UNVERIFIABLE` for being an
unrecognized family, which is the outcome this task asked for
("unknown-but-well-formed artifact type should normally become
UNVERIFIABLE, not silently trusted"). See 14.7 for the recommended fix.

### 14.5 Size / safety bounds

`bundle-payload.schema.json` already enforces hard structural caps unchanged
by D4.2: `records` 1-10,000 items, `extensions` <=256 properties. The three
new fields add their own hard caps: `reconciliation.agreements` and
`.contradictions` <=256 entries each, `.insufficient_evidence` <=256 entries,
`limitations` <=64 entries. `TrustPolicy` (`trust.py`) already enforces
operational bounds at the portable-file level regardless of bundle content:
`max_file_size` (10 MiB default), `max_depth` (64), `max_string_length` (1
MiB), `max_array_length` (10,000) -- these already bound a bundle carrying many
artifacts without any D4.2-specific change.

Recommended operational bounds for a future bundle-aware CLI/API layer (not
schema-level, and not implemented in this pass): a caller-configurable maximum
artifact count per bundle distinct from the schema's structural ceiling (e.g.
default 100, since 10,000 heterogeneous signed artifacts is a DoS surface
long before it is a realistic single-session evidence set); reject a bundle
containing two records with the same `id` (already impossible today --
`record.schema.json` content-addresses every record, so a true duplicate
collapses to the same `id` and the graph check already treats non-unique
`root_ids`/duplicate references as a defect); and treat a malformed nested
artifact (valid JSON, invalid against its own claimed schema) as
`UNVERIFIABLE` for that artifact rather than a hard parse failure for the
whole bundle -- this behavior should fall out naturally once 14.7's
per-artifact recognition layer exists.

### 14.6 What is schema-conformant today vs. behaviorally verified today

Every fixture in `spec/agent-evidence/v0/conformance/bundle-*.json` was
validated against the REAL Python reference `verify_bundle()`
(`onchaindiligence-agent-evidence==0.1.0`, editable-installed from this
repository) -- not asserted by hand. But two things are schema-conformant only,
not behaviorally checked by any current verifier:

- `reconciliation` and `limitations` content is inert data to
  `verify_bundle()` today. The verifier does not check that
  `reconciliation.agreements[].record_ids` actually resolve to records in the
  bundle, does not check that a `contradictions` entry actually cites
  disagreeing records, and does not check `limitations` wording. Schema
  validation enforces shape (required sub-fields, cardinality caps); it does
  not enforce the semantic rules stated in each field's own schema
  description. This is a real, disclosed gap for 14.7.
- A `public-action-receipt.v1` embedded via `external-digest` is bound into
  the graph by digest, but its own internal `receipt.proof` (a real, correctly
  formed v2 attestation) is never independently verified by the v0 graph
  verifier. `bundle-with-artifacts.json`'s receipt is genuinely, correctly
  signed, but that fact is not what makes the fixture's overall result VALID
  -- graph/digest binding is what makes it VALID.

### 14.7 Codex implementation plan (not implemented in this pass)

In priority order, each independently shippable and independently testable
against the existing conformance corpus:

1. **Broaden `ATTESTATION_PURPOSE`.** `constants.py` hardcodes
   `ATTESTATION_PURPOSE = "compliance-screening-result"` as the *only* purpose
   `_verify_attestation_proof` accepts for `onchaindiligence-attestation-v2`.
   `attest.ts`'s real purpose union is `compliance-screening-result |
   public-action-receipt | erc20-allowance-action | swap-action |
   bridge-action | staking-action`. Today, a real, validly-signed
   `erc20-allowance-action` (etc.) envelope embedded via
   `onchaindiligence-attestation-v2` is misreported `INVALID`
   (`attestation-purpose`) purely because of this hardcoded string. Fix:
   replace the single constant with the real accepted-purpose set from
   `attest.ts`. Low risk, additive, and directly fixes a live correctness gap
   independent of anything else in this plan.
2. **Separate bundle integrity from per-artifact verification.** Change
   `overall_state`'s single aggregate into a structured report:
   `bundle_integrity` (outer DSSE + payload canonicalization + graph
   structure only, explicitly excluding per-record `source-proof`/
   `trust-mode` components) and `artifact_verifications[]` (one tri-state
   result per record, using exactly the same component data already
   produced). `bundle-invalid-child` and `bundle-unverifiable-child` become
   the regression fixtures proving `bundle_integrity: VALID` alongside a
   distinct `INVALID`/`UNVERIFIABLE` entry in `artifact_verifications[]` --
   today their component lists already contain everything needed; only the
   aggregation needs to change; no new verification logic is required.
3. **Add an explicit artifact-family recognition check**, additive to (not a
   replacement for) `external-digest`'s existing graph-binding result: an
   evidence record whose `evidence_type` (or embedded object's `schema`) is
   not in a maintained allow-list of recognized OCD artifact families gets an
   explicit `UNVERIFIABLE` / `unknown-artifact-family` component alongside the
   existing `VALID` / `external-digest-bound` one, rather than only the
   latter. `bundle-unknown-artifact-type.json` is the regression fixture;
   its expected top-level result should change from `VALID` to
   `UNVERIFIABLE` once this ships (a manifest.json update, not a fixture
   change).
4. **Implement receipt-aware child verification.** For a
   `public-action-receipt.v1` embedded via `external-digest`, independently
   verify `receipt.proof` (already a real, checkable v2 attestation) as part
   of that record's `artifact_verifications[]` entry, using the purpose set
   widened in (1). This turns "digest-bound only" into a real per-artifact
   VALID/INVALID/UNVERIFIABLE result for the most common non-`{data,
   attestation}` artifact family, without touching the receipt schema itself.
5. **Implement `reconciliation` structural checks**, gated behind (2)'s
   report shape so they populate `reconciliation` in the new output rather
   than affecting `bundle_integrity`: verify every `record_ids` entry
   resolves to a record actually present in the bundle (an unresolved ID is a
   structural defect in the reconciliation section itself, not evidence about
   the subject -- already stated in the schema description, not yet
   enforced).
6. **CLI/API integration.** Deliberately out of scope for this pass and for
   items 1-5. Once (1)-(5) ship, `onchaindiligence-cli`'s existing
   `--trust`/`--fetch-keys` offline-verification path (section 8, and the
   D4.1 docs work) is the natural place to expose bundle verification --
   `bundle_integrity` / `artifact_verifications[]` / `reconciliation` should
   map directly onto that CLI's existing tri-state exit-code contract
   (0/3/4/2) with one exit code reflecting the worst
   `artifact_verifications[]` entry alongside `bundle_integrity`, kept
   visibly separate in output exactly as required here.

## Appendix A. Production reference artifact (non-normative)

The repository's [`examples/production/p1_8`](../examples/production/p1_8/README.md)
artifact applies this contract to two real observations captured through the
existing Chainalysis sanctions-oracle and SEC EDGAR provider clients. It embeds
the complete signed v2 envelopes without transforming signed fields, constructs
the full evidence DAG through the Python reference API, and verifies offline
with explicit caller-supplied trust.

The artifact is an interoperability and production-workflow reference, not an
additional format or normative fixture. Its dedicated reference keys are not
the live production API key, its timestamps are signer assertions, and its
withheld Execution record deliberately makes no transaction or causality claim.
