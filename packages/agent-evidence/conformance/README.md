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
