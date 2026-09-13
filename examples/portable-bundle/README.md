# Portable evidence bundle example (D4.2)

This directory is a developer-facing, non-sensitive illustration of the D4.2
portable evidence bundle additions to `bundle-payload.schema.json` (`issuer`,
`reconciliation`, `limitations`) and of embedding two heterogeneous existing
artifact families in one bundle. It is **not** a production capture like
[`examples/production/p1_8`](../production/p1_8/README.md) -- `bundle.json` is
the committed D4.2 conformance fixture `bundle-with-artifacts.json`
(`spec/agent-evidence/v0/conformance/bundle-with-artifacts.json`), signed with
the corpus's public deterministic test key
(`ed25519-3rLe053Cb84OYIW2`, seed published in
`spec/agent-evidence/v0/conformance/generate.mjs`). That key **must never be
trusted or deployed** outside conformance/example material.

## What this bundle contains

Two independent, heterogeneous artifacts about one synthetic action, embedded
without modification:

- an `onchaindiligence.attestation.v2` compliance-screening result for a
  synthetic test address (`0x00...02`), embedded via the
  `onchaindiligence-attestation-v2` proof type -- its own signature is
  verified as part of bundle verification; and
- a synthetic `onchaindiligence.public-action-receipt.v1` PREFLIGHT receipt
  (an `ERC20_ALLOWANCE` check for 1.00 test USDC on Base, decision `ALLOW`),
  embedded via the `external-digest` proof type -- graph-bound by digest, not
  independently source-verified by this bundle proof (see "What this bundle
  does not prove" below).

Both addresses and the receipt's asset/amount are synthetic test values. No
real customer or wallet activity is represented.

`reconciliation.agreements` notes that the two artifacts independently agree
the proposed action is not blocked; `reconciliation.insufficient_evidence`
honestly notes that no settlement/execution record exists in this bundle, so
whether the action was ever submitted is not established either way.
`limitations` states the standard bundle-validity boundary (integrity, not
authorization/safety/settlement/compliance/economic outcome).

## Verifying it

From the repository root, with the Python package installed (`pip install -e
python` or `python -m pip install -e ".[dev]"` from `python/`):

```text
python -m onchaindiligence.agent_evidence.cli verify \
  examples/portable-bundle/bundle.json \
  --trust examples/portable-bundle/trust-policy.json \
  --now 2026-08-28T12:01:00.000Z
```

Exits `0` with overall `VALID`, fully offline (no network access). The report
also carries `bundle_integrity` (the outer seal, canonical payload and graph
only) and `artifact_verifications[]` (one visible tri-state per record)
side by side -- read those rather than the single overall `state`, which is
just the worst of them. See
[`docs/AGENT_EVIDENCE_V0.md`](../../docs/AGENT_EVIDENCE_V0.md) section 14.3.

## What this bundle proves, and what it does not

- It proves: the exact manifest and artifact inventory embedded here were
  sealed together by the holder of `ed25519-3rLe053Cb84OYIW2` (a test key);
  the embedded `onchaindiligence-attestation-v2` screening result's own
  signature independently verifies; and the embedded receipt's own internal
  `receipt.proof` independently verifies as a separate artifact result.
- It does **not** prove: that any action was authorized, safe, settled,
  delivered, compliant, or economically sound; or anything about a real
  wallet, company, or transaction -- every identifier here is synthetic test
  material. Note also that the in-bundle receipt check is weaker than the
  dedicated `verifyReceiptEnvelope`, which additionally pins the attestation
  purpose and recomputes `receipt_digest`/`receipt_id`
  (`docs/AGENT_EVIDENCE_V0.md` section 14.6).

See the other D4.2 conformance fixtures in
[`spec/agent-evidence/v0/conformance/`](../../spec/agent-evidence/v0/conformance/README.md)
for the tampered/removed/inserted-artifact, invalid-child,
unverifiable-child, and unknown-artifact-type cases this bundle format is
also designed to detect.
