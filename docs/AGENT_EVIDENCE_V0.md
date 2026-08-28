# Agent Evidence v0 specification

Status: design specification; implementation must cite the exact revision it
implements.

Specification ID: `onchaindiligence.agent-evidence.v0`
Last updated: 2026-08-28

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
