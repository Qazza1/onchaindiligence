# P1.8 production Agent Evidence reference

This directory contains the first public-safe production Agent Evidence bundle
produced by OnChainDiligence. It was captured on 2026-08-28 through the existing
production provider clients and v2 attestation implementation, then built and
sealed through the public P1.7 Python API.

The committed bundle ID is
`sha256:b3Y51kb7-JfTCzA-MbVBHAiLdo43xlJLpAbT4eed6rw` and genuine verification
returns `VALID` under the explicit policy in `trust-policy.json`.

## What the bundle proves

Two independent, real observations were collected in parallel from the run:

- the public burn address `0x000000000000000000000000000000000000dEaD`
  was read through `isSanctioned()` on Chainalysis's Ethereum mainnet sanctions
  oracle and returned `sanctioned: false`; and
- ticker `AAPL` resolved to Apple Inc. through the SEC EDGAR submissions data.

Each complete `onchaindiligence.attestation.v2` response envelope is embedded
object-exact in its Evidence record and copied object-exact to `providers/`.
The response digest and source signature bind the same object. No signed field
was redacted, replaced, summarized, or fabricated for publication. The inputs
were deliberately selected public identifiers, and the production clients
retain their normal attribution and scope limitations.

These observations do **not** prove that the wallet belongs to Apple or that a
payment would be lawful. The policy therefore requires an entity-to-wallet
binding, the decision returns `manual-review` with execution unauthorized, and
the Execution record honestly says `withheld-not-submitted`. There is no
transaction hash, settlement claim, or invented causal link.

## Evidence DAG

```text
Principal -> Agent ----\
    |                   +-> Run -> Evidence (Chainalysis) --\
    +-> Mandate -------/      |                            |
                              +-> Evidence (SEC EDGAR) -----+-> Decision -> Execution
                              +-> Policy ------------------/
```

The Execution record is the only graph root. The Decision parents are exactly
the Run, Policy, and two Evidence IDs; its statement repeats the exact evidence
references and policy digest. `manifest.json` exposes the committed IDs and
provider-envelope digests for inspection.

## Trust and signing boundary

The two provider results were signed through the production v2 code path using
a dedicated P1.8 `managed-witness` Ed25519 key. A separate Ed25519 key sealed
the DSSE bundle. Both private keys existed only in process memory for this
capture and were not written or published. The committed public key records
have explicit `valid_from` values matching their real creation boundary.

These are reference-artifact keys, not the unresolved live production API key.
P1.8 does not infer, backfill, or alter the P0 production-key activation date.
The embedded keys remain untrusted hints: verification succeeds only when the
caller independently supplies `trust-policy.json`. This file is an example
pinset, not a claim that downloading trust material beside an artifact creates
an independent distribution channel.

Timestamps prove what the signers asserted. They are not independently
timestamped or anchored. Provider signatures preserve provenance and integrity;
they do not turn provider assertions into objective truth.

## Offline verification

From the repository root, with the Python package installed or `PYTHONPATH`
pointing at `python/src`:

```text
ocd-evidence verify examples/production/p1_8/bundle.json \
  --trust examples/production/p1_8/trust-policy.json \
  --now 2026-08-28T19:53:52.415Z
```

The command performs no discovery or network access and exits 0 with `VALID`.
Removing either required public key produces `UNVERIFIABLE`; changing a signed
byte, embedded response, digest, record ID, graph edge, decision reference, or
execution produces `INVALID`. Python tests enforce all three states and patch
`socket.socket` to fail if genuine verification attempts network access.

## Rebuilding a new live capture

`tools/p1_8/build_reference.py` generates new ephemeral signing keys, calls the
real public providers, and writes a new content-addressed artifact:

```text
npm run p1.8:capture -- --output <capture.json>
python tools/p1_8/build_reference.py --output <directory>
```

The first command is the lower-level capture surface and requires the caller to
supply its dedicated signing key and activation time in the process environment.
The Python builder handles that boundary in memory. It does not read dotenv
files. A later capture will correctly have different timestamps, signatures,
record IDs, and bundle ID while remaining deterministic for its exact content.
