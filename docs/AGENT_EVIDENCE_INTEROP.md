# Agent Evidence Interoperability Profile v1

Status: design specification for an optional, additive profile on top of
Agent Evidence v0. Implementation must cite the exact revision it implements.

Profile ID: `onchaindiligence.agent-evidence.interop.v1`
Last updated: 2026-09-03

Reference implementation: `@onchaindiligence/agent-evidence` (TypeScript),
`packages/agent-evidence/src/registry.ts`. Reference production integration:
ArcFX (see §5).

Normative terms `MUST`, `MUST NOT`, `SHOULD`, and `MAY` are used as in
RFC 2119.

## 0. What this profile is

Agent Evidence v0 ([`AGENT_EVIDENCE_V0.md`](AGENT_EVIDENCE_V0.md)) defines the
evidence graph, the DSSE envelope, and tri-state (`VALID` / `INVALID` /
`UNVERIFIABLE`) verification. It deliberately does not define *how a verifier
learns which keys to trust* or *how a bundle physically reaches a verifier* —
those are left to the caller by design (§8 of v0: "the verifier obtains a
trust policy from its own configuration or an out-of-band channel it already
trusts").

This profile formalizes two optional, independent conventions that answer
those two questions in a way any application can implement without
issuer-specific knowledge, generalized from ArcFX's production integration:

1. **Signer discovery** (§1–§2): a recommended public HTTP endpoint and JSON
   shape for an issuer to publish its own signer keys and their lifecycle.
2. **Browser verifier handoff** (§4): a recommended `window.postMessage`
   convention for handing a sealed bundle from an application's own browser
   tab to an independent verifier tab.

Neither convention changes v0's verification algorithm, its trust model, or
its tri-state semantics. Both are additive: a verifier or issuer that ignores
this profile entirely and supplies trust some other way remains fully
v0-compliant.

**Non-goals.** This profile does not define a certificate authority, a
reputation system, or any claim that publishing the discovery endpoint in §1
makes an issuer trustworthy. It does not require `window.postMessage` for
every integration — §4 is one browser-specific interoperability profile, not
the only valid transport for a sealed bundle. It does not weaken v0's rule
that embedded bundle keys are hints, never trust roots.

## 1. Signer discovery profile

An issuer that seals Agent Evidence bundles MAY publish its current and
historical signer keys at:

```
GET /.well-known/agent-evidence-keys
```

on the origin it wants callers to trust as "this issuer's own domain." This
is the recommended path; an issuer MAY publish the same document at another
URL and communicate that URL out of band, in which case the path convention
does not apply but the response shape (§2) still SHOULD be used.

### 1.1 What this endpoint is, and is not

- It is **public metadata**: an issuer's own `key_id`, Ed25519 public key, and
  lifecycle. It MUST NOT ever contain private key material.
- It is **one possible trust source**, not a universal CA. A verifier decides,
  on its own, which issuers' discovery endpoints (if any) it is willing to
  fetch and trust; nothing in this profile requires a verifier to trust every
  origin that hosts this endpoint. **Merely hosting this endpoint does not
  make an issuer trustworthy** — it makes the issuer's own claimed keys
  discoverable, exactly as a `.well-known` file always has, no more.
- **`key_id` alone is never sufficient to establish trust**, and an **embedded
  bundle key never establishes trust**, regardless of what this registry (or
  any registry) says. This mirrors v0 §8 exactly: cryptographic verification
  of a signature MUST use the public key from the caller's own trust record
  for that `key_id`, never a public key the bundle itself supplies. A verifier
  that resolves the correct trust record but still performs the cryptographic
  check against a *different*, bundle-declared key for the same `key_id`
  reintroduces exactly the spoofing this profile exists to close (§6.D of the
  companion conformance suite): an attacker who knows a trusted `key_id`
  string can embed their own key under that label, and a verifier that trusts
  the label instead of re-deriving the key from its own trust source will
  wrongly accept a signature the real issuer never made.
- A verifier's `TrustPolicy` (or equivalent) remains entirely caller-
  controlled. Fetching and parsing a discovery document is a way to
  *populate* a trust policy, never a bypass of having one. A verifier MAY, and
  for any non-interactive or security-sensitive use SHOULD, pin a specific
  registry snapshot or an explicit key list out of band instead of fetching
  live — nothing in this profile requires live network discovery.

### 1.2 Response shape

Normative schema:
[`agent-evidence-key-registry.schema.json`](../spec/agent-evidence/v0/schema/agent-evidence-key-registry.schema.json)
(Draft 2020-12, `additionalProperties: false`), catalogued in
[`catalog.json`](../spec/agent-evidence/v0/schema/catalog.json) as
`agent_evidence_key_registry`.

```json
{
  "schema_version": 1,
  "issuer": "ArcFX",
  "environment": "production",
  "keys": [
    {
      "key_id": "ed25519-fStXioNoRN9r1w6h",
      "algorithm": "Ed25519",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
      "valid_from": "2026-08-30T14:57:33.462Z",
      "valid_until": null,
      "revoked_at": null,
      "status": "active"
    }
  ]
}
```

- `schema_version` MUST be the integer `1` for this revision of the profile.
- `issuer` and `environment` are free-form, non-empty strings the *caller*
  compares against what it expects (`"ArcFX"` / `"production"` in the example
  above) — they are not validated against any external registrar. A caller
  SHOULD reject a document whose `issuer`/`environment` do not match what it
  expected for that origin, rather than trusting whatever the document claims
  about itself.
- `key_id` MUST match `^ed25519-[A-Za-z0-9_-]{16}$` and SHOULD be
  self-certifying: `ed25519-` followed by the first 16 base64url characters
  of the SHA-256 digest of the key's SPKI DER encoding — the exact convention
  Agent Evidence's own `AttestationKey`/`deriveKeyId` already use. A verifier
  SHOULD independently re-derive this from `public_key_pem` and reject a
  mismatch, exactly as `AttestationKey.fromRecord` already does for the
  existing key-record format.
- `algorithm` MUST be the literal string `"Ed25519"`.
- `valid_from`, `valid_until`, and `revoked_at` reuse Agent Evidence's own key
  lifecycle terminology and are each either an exact
  `YYYY-MM-DDTHH:mm:ss.sssZ` timestamp or `null`. `valid_from: null` means the
  issuer has published no defensible activation boundary; a verifier MUST
  then treat that key as `UNVERIFIABLE`, never `VALID` — the same rule v0 §8
  already applies to a caller-supplied key record with no `valid_from`.
- `status` MUST be one of `active`, `retired`, `revoked`, `compromised` — the
  same vocabulary as the existing `AttestationKeyRecord.status`. When `status`
  is `revoked` or `compromised`, `revoked_at` MUST be a timestamp, not `null`.
- Revoked, expired, or out-of-validity-window keys follow the **existing**
  verifier lifecycle semantics exactly (`evaluateKeyLifecycle`): a revoked or
  compromised key fails closed to `INVALID` for anything it signs; a
  cryptographically valid signature whose signed time falls outside
  `[valid_from, valid_until]` is `INVALID`; a key with no usable activation
  boundary is `UNVERIFIABLE`. This profile does not introduce any new
  lifecycle rule — it only gets keys into the same trust structure that
  already enforces these rules.

### 1.3 Transport and failure handling

- Discovery over the network MUST use HTTPS. A verifier MUST NOT accept this
  document over plain HTTP for a live fetch.
- Registry unavailability (network error, non-2xx status, timeout) SHOULD
  normally produce `UNVERIFIABLE` for whatever depended on it — never
  `INVALID`. A registry being unreachable is not evidence that a bundle's
  signature is fraudulent; it is only evidence that this particular trust
  source could not be consulted this time.
- A malformed response (wrong shape, wrong `schema_version`, a key entry that
  fails its own field constraints) MUST fail closed: reject the whole
  document rather than best-effort salvaging the parts that happen to parse.
  `parseAgentEvidenceKeyRegistry` (§3) throws in this case; the caller decides
  how that becomes a verification outcome (typically `UNVERIFIABLE`, per the
  point above — see §3's documented recommended pattern).

## 2. Machine-readable schema

[`agent-evidence-key-registry.schema.json`](../spec/agent-evidence/v0/schema/agent-evidence-key-registry.schema.json)
is the normative schema. It is additive to the v0 schema family (same
`https://onchaindiligence.com/schemas/agent-evidence/v0/` `$id` namespace,
listed in the same `catalog.json`) and does not modify any existing v0
schema. It was validated against ArcFX's live production response before
being committed.

## 3. Reusable SDK APIs

`@onchaindiligence/agent-evidence` exports two functions
(`packages/agent-evidence/src/registry.ts`) that turn an untrusted, parsed
registry payload into the existing trust primitives — no ArcFX-specific
logic anywhere in the core package:

```ts
import { parseAgentEvidenceKeyRegistry, trustPolicyFromKeyRegistry } from '@onchaindiligence/agent-evidence'

// Validate shape only (does not build trust):
const registry = parseAgentEvidenceKeyRegistry(payload, {
  expectedIssuer: 'ArcFX',
  expectedEnvironment: 'production',
})

// Or, the one-call path straight to a usable TrustPolicy:
const policy = trustPolicyFromKeyRegistry(payload, {
  expectedIssuer: 'ArcFX',
  expectedEnvironment: 'production',
  trustPolicy: { now: new Date() },
})
```

- Both functions are **pure and offline** — neither performs a network
  request. Fetching the document over HTTPS is the caller's job, matching the
  existing package design (the core SDK stays fully usable offline; see v0
  §8 and the existing `TrustPolicy.fromKeyRecords` for the same separation of
  "getting key material" from "verifying with it").
- `trustPolicyFromKeyRegistry` maps each validated entry onto the existing
  `AttestationKeyRecord` shape and calls the existing
  `TrustPolicy.fromKeyRecords` — it is a convenience on-ramp, not a new trust
  model. Every existing guarantee (`evaluateKeyLifecycle`, duplicate-key
  rejection, dangling-replacement rejection) applies unchanged.
- Both throw `TrustPolicyError` on a structurally invalid document or an
  issuer/environment mismatch. **Recommended caller pattern:**

  ```ts
  let policy
  try {
    const res = await fetch(registryUrl) // caller's own fetch, own timeout
    if (!res.ok) throw new Error(`registry fetch failed: ${res.status}`)
    policy = trustPolicyFromKeyRegistry(await res.json(), { expectedIssuer, expectedEnvironment })
  } catch {
    policy = TrustPolicy.fromKeyRecords([]) // no trust available -> UNVERIFIABLE, not a crash
  }
  const report = verifyBundle(bundle, policy)
  ```

  This is exactly the shape of the fallback already used in the ArcFX
  browser handoff (see `verify.html`'s `loadArcfxTrustedKeys`), generalized.
- The core verifier (`verifyBundle`) is unchanged by this profile. It has
  never read a public key from a bundle's own `verification_material` for the
  actual cryptographic check — `policy.key(keyId)` (the caller's trust
  policy) has always been the sole source of the key used to verify a
  signature. This profile does not need to "fix" that in the verifier; it
  only needs a clean way to *populate* the policy from a public registry,
  which is what §3 provides.
- ArcFX (or any other issuer) is not special-cased anywhere in
  `registry.ts`, `trust.ts`, or `verifier.ts`. The current production ArcFX
  endpoint (§5) is reference *configuration*, not SDK code.

## 4. Browser verifier handoff profile

Generalizes the working ArcFX handoff (`onchaindiligence-site`'s
`/verify?source=arcfx` flow) into an optional profile any application can
adopt. This is **one** browser interoperability profile among possible
transports for a sealed bundle (a QR code, a copy/paste textarea, a direct
API call to a verifier service are all equally valid v0-compliant ways to
hand a bundle to a verifier) — it is not required to use Agent Evidence at
all.

### 4.1 Message shapes

Verifier tab → opener (announces readiness):

```json
{ "type": "onchaindiligence:verifier-ready", "version": 1 }
```

Application (opener) → verifier tab (hands off the bundle):

```json
{
  "type": "onchaindiligence:verify-bundle",
  "version": 1,
  "source": "arcfx",
  "bundle": { "...": "the sealed portable Agent Evidence bundle" }
}
```

`version` is the message-shape version, independent of `schema_version` in
§1 and independent of the Agent Evidence bundle version inside `bundle`.
`source` is a self-declared, free-form application identifier. **`source` is
never a trust signal** (§4.3) — it exists only so a verifier's UI can label
which application it received a bundle from before any cryptographic
conclusion exists.

### 4.2 Reference implementation

The current production implementation (`onchaindilige-site/verify.html`,
`arcfx-handoff-script`) predates this document and remains the compatibility
baseline — this profile describes what it already does, not a change to it.
It is exercised by
`onchaindilige-site/test/arcfx-handoff.test.mjs`.

### 4.3 Security requirements

A conforming verifier implementation:

- MUST send its `verifier-ready` message to an **exact** expected origin,
  never `"*"` as `targetOrigin`.
- MUST validate that an incoming message's `event.origin` is the **exact**
  expected origin before reading anything else from it.
- MUST validate `event.source === window.opener` (or the equivalent handle
  for whichever window relationship the integration uses) — origin alone
  does not prove the message came from the specific window that opened the
  verifier.
- MUST treat the entire payload, including `bundle`, as **untrusted input**
  until independently verified. It MUST NOT `eval` any part of it or execute
  code derived from it.
- MUST NOT require, request, or accept a wallet handle, session token,
  authentication credential, or payment token as part of the handoff. A
  sealed Agent Evidence bundle is self-contained evidence; this protocol has
  no field for secrets, and a conforming bundle payload has none either (v0's
  schemas define no credential-shaped field anywhere in the record kinds).
- MUST NOT place the bundle in a URL (query string, fragment, or path) —
  bundles can be large, and URLs leak into browser history, referrers, and
  server logs in ways an in-memory `postMessage` payload does not.
- MUST establish trust for the bundle's signer **independently of the
  handoff itself** — via a caller-configured `TrustPolicy` (§3, or any other
  out-of-band trust source), never by inferring trust from the fact that a
  message arrived, from `source`, or from anything embedded in the bundle. A
  successful, well-formed handoff proves only that *some* postMessage arrived
  from the expected window; it proves nothing about who signed the bundle
  inside it. That is exactly what `verifyBundle` + `TrustPolicy` establishes
  next, independently.
- MUST NOT introduce a wildcard `targetOrigin` at any point in the flow, in
  either direction.

## 5. Reference integration: ArcFX

ArcFX (`arcfx.app`) is the current production reference implementation of
this entire profile — **an example implementation, not a requirement**. Any
other application MAY implement this profile without any ArcFX-specific
knowledge, and ArcFX's own integration required no changes to the core SDK.

Current architecture, end to end:

```
ArcFX financial-agent workflow
  -> sealed Agent Evidence bundle (Mandate/Evidence/Policy/Decision/Execution)
  -> browser-local handoff (§4, window.postMessage, /verify?source=arcfx)
  -> OnChainDiligence verifier (runs entirely in the browser tab)
  -> independent fetch of ArcFX's own public signer registry (§1)
  -> lifecycle-aware trust construction (§3's mapping, applied inline in
     verify.html today; the generic SDK path in §3 is the same construction)
  -> VALID / INVALID / UNVERIFIABLE
```

Current production discovery endpoint (configuration, not SDK-hard-coded):

```
https://arcfx-backend-production.up.railway.app/.well-known/agent-evidence-keys
```

No copy/paste is required in the current ArcFX flow: the sealed bundle moves
directly from ArcFX's tab to the verifier tab via `postMessage`.

## 6. Conformance

`packages/agent-evidence/test/interop.test.mjs` is the conformance suite for
§1–§3 (signer discovery, schema, SDK APIs): known-trusted-signer `VALID`,
tampered-bundle `INVALID`, unknown-signer `UNVERIFIABLE`, the `key_id`
spoofing regression (`MUST NOT` verify `VALID`), unavailable/malformed
registry handling, and revoked/out-of-window lifecycle cases — all against
deterministic, freshly generated test keys, plus one case validating the
real, live ArcFX registry response shape against the schema.

`onchaindilige-site/test/arcfx-handoff.test.mjs` is the existing conformance
suite for §4 (browser handoff): exact-origin acceptance, wrong-origin
rejection, wrong-window-source rejection, and malformed-payload rejection,
exercised against the real production handoff script.

## 7. Versioning

This document is Profile v1. A future incompatible revision to either the
registry response shape or the handoff message shapes increments the
relevant `schema_version` / message `version` field and this document's
title, never silently changes field semantics under the same version number.
