# @onchaindiligence/agent-evidence

Production Node.js/TypeScript implementation of the published
OnChainDiligence Agent Evidence v0 protocol. It creates deterministic records,
validates the complete evidence DAG, seals bundles with Ed25519 DSSE, and
verifies portable bundles offline with caller-supplied trust.

The package is publicly available on npm:

```sh
npm install @onchaindiligence/agent-evidence
# or pin the first release
npm install @onchaindiligence/agent-evidence@0.1.0
```

This source README reflects the public release. The immutable README embedded
in the already-published `0.1.0` tarball still carries its pre-release wording;
the correction will be included in the next package version.

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

## Technocore signed-message evidence

`technocore.chat` signed-lane messages can be captured as attributable, offline
verifiable input with no resolver or network call. The adapter mirrors the
official single-line sweep and verifies the exact UTF-8
`<room>|<nonce>|<stored-text>` string against the Ed25519 public key embedded in
the sender's `did:key`.

```js
import { createTechnocoreEvidence, verifyTechnocoreMessage } from '@onchaindiligence/agent-evidence'

// Treat every field as untrusted data obtained from Technocore's JSON response.
if (!verifyTechnocoreMessage({ did, room, nonce, text, sig })) throw new Error('invalid assertion')
const evidence = createTechnocoreEvidence({ did, room, nonce, text, sig }, {
  runRef: run.id,
  observedAt: '2026-09-01T12:00:01.000Z',
  serverMetadata: { seq: String(seq), ts: String(ts), generation: String(generation) },
})
```

The resulting record preserves the DID, room, nonce, exact stored text, its
SHA-256 digest, signature, signing format, and optional server metadata. It
always uses `trust_mode: 'agent-assertion'`: a valid signature proves only that
that `did:key` asserted those bytes. It never proves the message is true,
authorizes an action, supplies a trusted instruction, or permits a wallet/
network action. `verifyTechnocoreMessage` and normal bundle verification are
fully offline and make no HTTP requests.

[`examples/technocore-evidence.mjs`](./examples/technocore-evidence.mjs) builds
Mandate → Technocore Evidence → Policy → Decision → non-execution → DSSE-sealed
bundle → offline `VALID` verification.

## tclk/1 (Technocore Lock Protocol) transcript evidence

Signed agent-to-agent deal coordination on [`technocore.chat`](https://github.com/flop-labs/technocore-chat)
using FLOP Labs' [`@flop-labs/tclk`](https://github.com/flop-labs/tclk) (`offer →
accept → lock → reveal/refund`) can be captured as Agent Evidence. This adapter
uses the official `@flop-labs/tclk` package directly — it never reimplements
frame validation or the state machine, and never uses tclk's unaudited
PTLC/adaptor-signature path.

```js
import { verifyTclkTranscript, createTclkEvidence } from '@onchaindiligence/agent-evidence'

// Each entry is a Technocore signed message whose text is a tclk/1 frame line,
// plus the wall-clock time (ms) at which that frame was applied.
const transcript = verifyTclkTranscript([
  { message: offerMsg, atMs }, { message: acceptMsg, atMs }, { message: lockMsg, atMs },
])
const evidence = createTclkEvidence(transcript, {
  runRef: run.id, observedAt, messageEvidenceRefs: [/* one createTechnocoreEvidence(...).id per message */],
})
```

`verifyTclkTranscript` verifies, independently, per frame: the Technocore
transport signature (reusing `verifyTechnocoreMessage`, not a second
implementation), the tclk frame's own validity, that the frame's `from` matches
the transport-authenticated DID, and the official state-machine transition. It
fails closed on a bad signature, a malformed frame, or a sender/DID mismatch; a
frame the *official* machine itself rejects as a designed-in no-op (a replay, a
duplicate, an out-of-order transition) is recorded in the result rather than
treated as fatal, per tclk's own spec.

**Valid signed coordination is evidence of what the agents agreed/asserted. The
named settlement rail remains authoritative for actual value movement** — a
`lock` frame is captured as "payer asserted/announced lock on rail X," never as
"funds were locked," unless the caller separately supplies an independently
verified `settlementRail` observation (this package implements no rail).

[`examples/tclk-evidence.mjs`](./examples/tclk-evidence.mjs) builds a full
hash-lock transcript (offer → accept → lock → reveal) between two local test
identities and turns it into Mandate → tclk Evidence → Policy → Decision
(`ACCEPT_COORDINATION_EVIDENCE`) → Execution (`NO_REAL_VALUE_SETTLEMENT`, since
no real rail is wired up) → sealed bundle → offline `VALID` verification.

## Schemas and interoperability

The npm artifact includes the canonical v0 schemas and public conformance
corpus. Build tests fail if packaged files differ byte-for-byte from
`spec/agent-evidence/v0`. The same deterministic fixture is produced and
verified by both the TypeScript and Python implementations.
