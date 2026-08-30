# @onchaindiligence/agent-evidence

Production Node.js/TypeScript implementation of the published
OnChainDiligence Agent Evidence v0 protocol. It creates deterministic records,
validates the complete evidence DAG, seals bundles with Ed25519 DSSE, and
verifies portable bundles offline with caller-supplied trust.

The package is currently **packable and publish-ready, but not yet published to
npm**. Do not advertise a registry install until the owner completes npm trusted
publishing. From this repository, test the exact public artifact with:

```sh
npm pack ./packages/agent-evidence
npm install ./onchaindiligence-agent-evidence-0.1.0.tgz
```

Node.js 20.19 or newer and ESM are required.

## What a signature proves

A valid signature proves that the identified key signed the exact canonical
bundle bytes and that the bundle satisfies the protocol and caller's trust
policy. It does not prove that an upstream fact is objectively true. Source
proofs establish attribution to a witness; the verifier never turns embedded
keys into trust and never contacts OnChainDiligence, a blockchain, a schema
server, or an evidence provider.

## Stable public API

- `createRecord(kind, statement, options)` creates a schema-valid v0 record and
  derives its deterministic content ID.
- `contentId(value)` and `canonicalize(value)` expose the protocol's exact
  RFC 8785 content-addressing boundary.
- `createBundlePayload(records, options)` sorts records and validates IDs,
  roots, references, required relationships, graph completeness, and cycles.
- `createEd25519Signer(privateKey)` creates a local Node Ed25519 signer.
- `sealBundle(payload, signer, options)` validates, canonicalizes, performs
  exact DSSE PAE, verifies the caller signer result, and returns portable data.
- `createKeyRecord(publicKey, options)` produces a validated lifecycle record.
- `TrustPolicy.fromKeyRecords(records, options)` creates explicit caller trust.
- `verifyBundle(bundle, trustPolicy)` returns a machine-readable tri-state
  `VerificationReport` without network access.
- `validateBundlePayload` and `validateDocument` support explicit validation.
- `parseJson`, `parseTimestamp`, `formatTimestamp`, `deriveKeyId`, `dssePae`,
  and the documented constants/types cover protocol-safe lower-level use.

Construction/configuration errors are typed as `AgentEvidenceError` subclasses:
`CanonicalizationError`, `ParseError`, `SchemaValidationError`,
`EvidenceValidationError`, `SigningError`, and `TrustPolicyError`.

## Verification states

- `VALID`: every required structural, graph, cryptographic, lifecycle,
  freshness, and caller-trust component passed.
- `INVALID`: the document violates the protocol, such as a bad signature,
  altered content ID, invalid edge, unsupported version, or invalid key window.
- `UNVERIFIABLE`: the document may be coherent, but caller trust or required
  evidence material is insufficient.

`UNVERIFIABLE` is never promoted to `VALID` or collapsed into `INVALID`.
Inspect `report.components` for stable codes, key/record references, and
diagnostics.

## Trust and key rotation

Trust is supplied only through `TrustPolicy`. Keys carried inside the portable
bundle are untrusted hints. Active and retired historical Ed25519 keys are
evaluated against the bundle's signed `created_at` and their explicit validity
interval. Revoked or compromised keys are invalid. A missing defensible
`valid_from` is `UNVERIFIABLE`, not guessed. Replacement links must be distinct
and resolve inside the caller's trust set.

## Signing

`sealBundle` accepts an `Ed25519Signer` containing a key ID, public key, and
sync/async signing callback. It verifies that the key ID matches the public key
and that the returned signature is valid before emitting a bundle. This allows
external signing implementations without introducing remote signing or key
fetching into the protocol. `createEd25519Signer` is the local PKCS8/`KeyObject`
convenience implementation.

Private key material is never loaded from files or configuration by this
package and no production signing key is bundled.

## Financial-agent example

[`examples/withheld-payment.mjs`](./examples/withheld-payment.mjs) builds
Principal → Agent → Mandate → Run → Evidence/Policy → Decision → Execution,
where policy withholds an invoice payment because recipient ownership evidence
is missing. The execution is `withheld-not-submitted`; the example does not
fabricate a transaction or settlement.

## Schemas and interoperability

The npm artifact includes the canonical v0 schemas and public conformance
corpus. Build tests fail if packaged files differ byte-for-byte from
`spec/agent-evidence/v0`. The same deterministic fixture is produced and
verified by both the TypeScript and Python implementations.
