# Agent Evidence v0 conformance corpus

These fixtures are language-neutral inputs for Agent Evidence v0 producers and
verifiers. `manifest.json` is the case index and records the exact expected
overall state. `valid-full-graph.json` contains all eight v0 record kinds and a
real Ed25519 DSSE signature. The other static files isolate canonicalization,
graph, and duplicate-name failures; JSON Patch mutations use RFC 6902 paths.

The deterministic private seed in `generate.mjs` is public test material. It
MUST NOT be deployed, configured as a production trust root, or accepted
outside conformance tests. Regeneration is deterministic:

```text
node generate.mjs portable
node generate.mjs noncanonicalPayload
node generate.mjs missingParent
```

## D4.2 portable evidence bundle fixtures

These seven cases exercise the bundle-level `issuer` / `reconciliation` /
`limitations` additions to `bundle-payload.schema.json` and the bundle-vs-child
verification distinction described in `docs/AGENT_EVIDENCE_V0.md` section 14.
A second, distinct deterministic test key ("child seed") signs one embedded
artifact in the unverifiable-child case; it is public test material only, same
as the bundle-sealer key.

```text
node generate.mjs bundleWithArtifacts        > bundle-with-artifacts.json
node generate.mjs bundleTamperedManifest     > bundle-tampered-manifest.json
node generate.mjs bundleRemovedArtifact      > bundle-removed-artifact.json
node generate.mjs bundleInsertedArtifact     > bundle-inserted-artifact.json
node generate.mjs bundleInvalidChild         > bundle-invalid-child.json
node generate.mjs bundleUnverifiableChild    > bundle-unverifiable-child.json
node generate.mjs bundleUnknownArtifactType  > bundle-unknown-artifact-type.json
node generate.mjs childKeyRecord
```

| case | fixture | expected | what it proves |
| --- | --- | --- | --- |
| `bundle-with-artifacts` | `bundle-with-artifacts.json` | VALID | Base case: one `onchaindiligence-attestation-v2` evidence artifact plus one `public-action-receipt.v1` embedded via `external-digest`, with `issuer`/`reconciliation`/`limitations` populated. |
| `bundle-tampered-manifest` | `bundle-tampered-manifest.json` | INVALID | `created_at` changed post-signing; DSSE signature no longer matches the payload bytes. |
| `bundle-removed-artifact` | `bundle-removed-artifact.json` | INVALID | An evidence record deleted post-signing invalidates the bundle proof. |
| `bundle-inserted-artifact` | `bundle-inserted-artifact.json` | INVALID | An extra record spliced in post-signing invalidates the bundle proof. |
| `bundle-invalid-child` | `bundle-invalid-child.json` | INVALID | Sealed *after* corrupting one embedded attestation signature, so the outer DSSE signature is genuinely valid over its exact (tampered-child) content -- only the child's own source-proof fails. Reports `bundle_integrity: VALID` with an INVALID entry in `artifact_verifications[]`; the convenience overall state is INVALID. |
| `bundle-unverifiable-child` | `bundle-unverifiable-child.json` | UNVERIFIABLE | One embedded artifact is correctly signed but by a key this fixture's own `verification_material` does not include. Reports `bundle_integrity: VALID` with an UNVERIFIABLE entry in `artifact_verifications[]`; the convenience overall state is UNVERIFIABLE. |
| `bundle-unknown-artifact-type` | `bundle-unknown-artifact-type.json` | UNVERIFIABLE | A well-formed evidence record of an unrecognized schema (`onchaindiligence.some-future-action.v9`), embedded via `external-digest`. `bundle_integrity` stays VALID (the record is genuinely bound by the seal) while the artifact itself reports UNVERIFIABLE via `unknown-artifact-family` -- an unrecognized type is never silently accepted on digest binding alone. |

All seven `expected` values above were confirmed against the real Python
reference `verify_bundle()` and the real TypeScript `verifyBundle()`, not
asserted by hand. `expected` is the convenience overall state (the worst of
bundle integrity and every artifact result); `bundle_integrity` and
`artifact_verifications[]` are reported separately and are what a consumer
should read. See `docs/AGENT_EVIDENCE_V0.md` section 14 for the full audit
trail, including two known ways the in-bundle receipt check is weaker than the
dedicated `verifyReceiptEnvelope`.

Verification rules:

1. Parse with duplicate-name rejection before ordinary JSON-schema validation.
2. Validate the portable file and the decoded payload against the schemas in
   `../schema`.
3. Apply caller trust from `trusted_key_ids`; embedded keys are hints only.
4. Verify DSSE over the exact decoded bytes before parsing the payload.
5. Enforce RFC 8785 bytes, IDs, ordering, DAG, references, key lifecycle, and
   policy in the normative order from `docs/AGENT_EVIDENCE_V0.md`.

JSON Schema covers representation constraints. Graph relationships,
canonical bytes, signatures, key derivation/trust, and tri-state outcomes are
semantic conformance requirements and therefore have explicit corpus cases.
