# OnChainDiligence Agent Evidence for Python

`onchaindiligence-agent-evidence` is the Python reference implementation of
Agent Evidence v0. It constructs deterministic records and evidence DAGs,
seals canonical payloads with Ed25519 DSSE, and verifies portable bundles with
an explicit caller-supplied trust policy.

The verifier is fully offline. It does not import an HTTP client, discover
keys, read ambient configuration, or trust keys merely because a bundle embeds
them. Its only outcomes are `VALID`, `INVALID`, and `UNVERIFIABLE`, with
component-level reasons retained in the report.

The normative contract is the repository's
[`AGENT_EVIDENCE_V0.md`](../docs/AGENT_EVIDENCE_V0.md), published JSON Schemas,
and language-neutral conformance corpus. Packaged schemas and core conformance
vectors are byte-for-byte copies of that contract and all `$ref` resolution is
local.

## Installation

The package is prepared for an eventual PyPI release but is not published yet:

```text
python -m pip install ./python
```

Python 3.10 or newer is required.

## Production reference bundle

[`examples/production/p1_8`](../examples/production/p1_8/README.md) contains a
public-safe bundle built from real Chainalysis oracle and SEC EDGAR observations
through the production provider and v2 signing code paths. It exercises the
complete Mandate/Evidence/Policy/Decision/Execution graph and verifies offline
under caller-supplied trust. The artifact documentation states its signing,
publication, timestamp, and withheld-execution boundaries explicitly.

## Offline verification

```python
from datetime import datetime, timezone
from pathlib import Path

from onchaindiligence.agent_evidence import TrustPolicy, parse_json, verify_bundle

trusted = parse_json(Path("trusted-keys.json").read_bytes())
policy = TrustPolicy.from_key_records(
    trusted["keys"],
    now=datetime.now(timezone.utc),
)
report = verify_bundle(Path("evidence.json").read_bytes(), policy)

print(report.state.value)
for component in report.components:
    print(component.component, component.state.value, component.code)
```

`trusted-keys.json` is an out-of-band caller decision. A key record needs an
SPKI-derived `key_id`, Ed25519 public key, status, and defensible lifecycle
interval. An active key with `valid_from: null` produces `UNVERIFIABLE`; the
verifier never invents an activation boundary.

The equivalent CLI is also zero-network:

```text
ocd-evidence verify evidence.json --trust trusted-keys.json
```

Exit status is 0 for `VALID`, 3 for `INVALID`, 4 for `UNVERIFIABLE`, and 2 for
usage, trust-file, or local I/O errors.

## Construction and sealing

```python
from pathlib import Path
from onchaindiligence.agent_evidence import (
    canonicalize,
    create_bundle_payload,
    load_private_key_pem,
    parse_json,
    seal_bundle,
)

records = parse_json(Path("records.json").read_bytes())
key_record = parse_json(Path("signing-key-record.json").read_bytes())
private_key = load_private_key_pem(Path("signing-key.pem").read_bytes())
payload = create_bundle_payload(records, created_at="2026-08-28T12:00:00.000Z")
portable = seal_bundle(payload, private_key, keys=[key_record])
Path("evidence.json").write_bytes(canonicalize(portable))
```

`seal_bundle` validates the complete graph before signing. The `keys` argument
adds portable verification hints only; verifiers still require the same record
through `TrustPolicy`. `examples/seal_records.py` provides this as a runnable
command; application code normally creates each input with `create_record`.

## Public API

- `create_record`, `create_bundle_payload`, `validate_bundle_payload`
- `seal_bundle`, `dsse_pae`, `load_private_key_pem`
- `TrustPolicy`, `AttestationKey`, `create_key_record`, `derive_key_id`
- `verify_bundle`, `VerificationReport`, `ComponentResult`, `VerificationState`
- `canonicalize`, `content_id`, `parse_json`, timestamp helpers

Builder failures raise typed package exceptions. Untrusted artifact failures
are returned as reports rather than raised.

## Security and compatibility notes

- Bundle and source DSSE signatures cover exact PAE bytes.
- Current and legacy OnChainDiligence attestation proofs require the record's
  source ID to match the exact OnChainDiligence issuer, preventing a valid
  signature from being relabeled as another publisher.
- RFC 8785 bytes, IDs, roots, ordering, cycles, references, kind-specific
  parents, embedded response/policy digests, key status, and time windows are
  checked independently.
- Revoked or compromised keys are always invalid. Retired keys require a
  signed time inside their historical interval.
- A `dsse-ed25519-v1` source proof has no signed issuance-time field. It may use
  a currently active key, but a retired-key proof is `UNVERIFIABLE` rather than
  receiving an invented timestamp.
- Legacy v1 attestations depend on historical JavaScript object order. When
  that order cannot be recovered from the canonical enclosing bundle, a failed
  v1 signature is `UNVERIFIABLE`, not falsely labeled tampered.
- Timestamps remain signer assertions unless an independently verified anchor
  or timestamp proof establishes an external bound.
