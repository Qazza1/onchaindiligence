from __future__ import annotations

import base64
import copy
import socket
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from onchaindiligence.agent_evidence import (
    BUNDLE_PAYLOAD_TYPE,
    TrustPolicy,
    VerificationState,
    canonicalize,
    content_id,
    create_bundle_payload,
    create_key_record,
    create_record,
    dsse_pae,
    parse_json,
    parse_timestamp,
    validate_bundle_payload,
    verify_bundle,
)
from onchaindiligence.agent_evidence.errors import EvidenceValidationError

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "examples" / "production" / "p1_8"


def load_reference() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    bundle = parse_json((REFERENCE / "bundle.json").read_bytes())
    trust = parse_json((REFERENCE / "trust-policy.json").read_bytes())
    manifest = parse_json((REFERENCE / "manifest.json").read_bytes())
    assert isinstance(bundle, dict) and isinstance(trust, dict) and isinstance(manifest, dict)
    return bundle, trust, manifest


def signed_payload(bundle: dict[str, object]) -> dict[str, object]:
    envelope = bundle["envelope"]
    assert isinstance(envelope, dict)
    payload = parse_json(base64.b64decode(str(envelope["payload"])))
    assert isinstance(payload, dict)
    return payload


def policy_from(trust: dict[str, object], *, keys: list[dict[str, object]] | None = None) -> TrustPolicy:
    records = keys if keys is not None else trust["keys"]
    assert isinstance(records, list)
    required = trust["required_signature_key_ids"] if keys is None else []
    minimum = trust["minimum_valid_signatures"] if keys is None else 1
    assert isinstance(required, list) and all(isinstance(item, str) for item in required)
    assert isinstance(minimum, int)
    return TrustPolicy.from_key_records(
        records,
        now=parse_timestamp(str(trust["reference_verification_time"])),
        required_signature_key_ids=frozenset(required),
        minimum_valid_signatures=minimum,
    )


def test_reference_bundle_is_valid_and_fully_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, trust, manifest = load_reference()

    def network_forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline verification attempted network access")

    monkeypatch.setattr(socket, "socket", network_forbidden)
    report = verify_bundle(bundle, policy_from(trust))
    assert report.state is VerificationState.VALID
    assert manifest["verification"] == {
        "genuine": "VALID",
        "offline": True,
        "trust_is_caller_supplied": True,
    }


def test_provider_envelopes_are_preserved_exactly_and_form_parallel_evidence() -> None:
    bundle, _trust, manifest = load_reference()
    payload = signed_payload(bundle)
    validate_bundle_payload(payload)
    records = payload["records"]
    assert isinstance(records, list)
    evidence = [record for record in records if record["kind"] == "evidence"]
    assert len(evidence) == 2
    run_id = payload["run_id"]
    assert all(record["parents"] == [run_id] for record in evidence)

    by_provider = {item["provider_id"]: item for item in manifest["provider_envelopes"]}
    for record in evidence:
        envelope = record["statement"]["response"]["value"]
        proof_envelope = record["proofs"][0]["envelope"]
        assert proof_envelope == envelope
        provider = (
            "chainalysis-onchain-sanctions-oracle"
            if record["statement"]["evidence_type"] == "sanctions-screen"
            else "sec-edgar-submissions"
        )
        source = parse_json((REFERENCE / by_provider[provider]["path"]).read_bytes())
        assert envelope == source
        assert record["statement"]["response"]["digest"]["sha256"] == content_id(source).removeprefix("sha256:")


def test_decision_and_withheld_execution_bind_exact_graph_inputs() -> None:
    bundle, _trust, _manifest = load_reference()
    payload = signed_payload(bundle)
    records = payload["records"]
    by_kind = {record["kind"]: record for record in records if record["kind"] != "evidence"}
    evidence = [record for record in records if record["kind"] == "evidence"]
    decision = by_kind["decision"]
    policy = by_kind["policy"]
    execution = by_kind["execution"]
    expected_parents = sorted([payload["run_id"], policy["id"], *(record["id"] for record in evidence)])
    assert decision["parents"] == expected_parents
    assert decision["statement"]["evidence_refs"] == sorted(record["id"] for record in evidence)
    assert decision["statement"]["policy_ref"] == policy["id"]
    assert decision["statement"]["policy_digest"] == policy["statement"]["digest"]
    assert decision["statement"]["outcome"]["authorized_to_execute"] is False
    assert execution["parents"] == [decision["id"]]
    assert execution["statement"]["status"] == "withheld-not-submitted"
    assert "transaction_hash" not in execution["statement"]


def test_deterministic_ids_and_bundle_id_recompute() -> None:
    bundle, _trust, _manifest = load_reference()
    payload = signed_payload(bundle)
    for record in payload["records"]:
        body = {key: value for key, value in record.items() if key != "id"}
        assert record["id"] == content_id(body)
    rebuilt = create_bundle_payload(
        payload["records"],
        created_at=payload["created_at"],
        run_id=payload["run_id"],
        root_ids=payload["root_ids"],
        extensions=payload["extensions"],
    )
    assert rebuilt == payload


def test_unknown_record_kind_is_rejected_by_the_published_schema() -> None:
    bundle, _trust, _manifest = load_reference()
    payload = signed_payload(bundle)
    record = copy.deepcopy(payload["records"][0])
    record["kind"] = "python-only-record-kind"
    record["id"] = content_id({key: value for key, value in record.items() if key != "id"})
    with pytest.raises(EvidenceValidationError, match="not valid under any of the given schemas"):
        validate_bundle_payload({**payload, "records": [record, *payload["records"][1:]]})


def test_cryptographic_and_content_tampering_are_invalid() -> None:
    bundle, trust, _manifest = load_reference()
    changed_signature = copy.deepcopy(bundle)
    signature = changed_signature["envelope"]["signatures"][0]["sig"]
    changed_signature["envelope"]["signatures"][0]["sig"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    assert verify_bundle(changed_signature, policy_from(trust)).state is VerificationState.INVALID

    changed_content = copy.deepcopy(bundle)
    payload = signed_payload(changed_content)
    evidence = next(record for record in payload["records"] if record["kind"] == "evidence")
    evidence["statement"]["response"]["value"]["data"]["checked_at"] = "2000-01-01T00:00:00.000Z"
    changed_content["envelope"]["payload"] = base64.b64encode(canonicalize(payload)).decode("ascii")
    assert verify_bundle(changed_content, policy_from(trust)).state is VerificationState.INVALID


def test_graph_and_digest_tampering_are_invalid_even_with_a_valid_dsse_signature() -> None:
    bundle, trust, _manifest = load_reference()
    payload = signed_payload(bundle)
    execution = next(record for record in payload["records"] if record["kind"] == "execution")
    execution["parents"] = [payload["run_id"]]

    attacker = Ed25519PrivateKey.generate()
    attacker_record = create_key_record(attacker.public_key(), valid_from=payload["created_at"])
    payload_bytes = canonicalize(payload)
    changed = copy.deepcopy(bundle)
    changed["envelope"]["payload"] = base64.b64encode(payload_bytes).decode("ascii")
    changed["envelope"]["signatures"] = [
        {
            "keyid": attacker_record["key_id"],
            "sig": base64.b64encode(attacker.sign(dsse_pae(BUNDLE_PAYLOAD_TYPE, payload_bytes))).decode("ascii"),
        }
    ]
    source_keys = [
        record for record in trust["keys"] if record["key_id"] != bundle["envelope"]["signatures"][0]["keyid"]
    ]
    graph_policy = policy_from(trust, keys=[*source_keys, attacker_record])
    report = verify_bundle(changed, graph_policy)
    assert report.state is VerificationState.INVALID
    assert any(component.code == "graph-invalid" for component in report.components)

    original = signed_payload(bundle)
    evidence = next(record for record in original["records"] if record["kind"] == "evidence")
    bad_statement = copy.deepcopy(evidence["statement"])
    bad_statement["response"]["value"]["data"]["checked_at"] = "2000-01-01T00:00:00.000Z"
    rebuilt_evidence = create_record(
        "evidence",
        bad_statement,
        parents=evidence["parents"],
        proofs=evidence["proofs"],
    )
    original_decision = next(record for record in original["records"] if record["kind"] == "decision")
    decision_statement = copy.deepcopy(original_decision["statement"])
    decision_statement["evidence_refs"] = sorted(
        rebuilt_evidence["id"] if item == evidence["id"] else item for item in decision_statement["evidence_refs"]
    )
    rebuilt_decision = create_record(
        "decision",
        decision_statement,
        parents=[
            decision_statement["run_ref"],
            decision_statement["policy_ref"],
            *decision_statement["evidence_refs"],
        ],
    )
    original_execution = next(record for record in original["records"] if record["kind"] == "execution")
    execution_statement = copy.deepcopy(original_execution["statement"])
    execution_statement["decision_ref"] = rebuilt_decision["id"]
    rebuilt_execution = create_record(
        "execution",
        execution_statement,
        parents=[rebuilt_decision["id"]],
    )
    replacements = {
        evidence["id"]: rebuilt_evidence,
        original_decision["id"]: rebuilt_decision,
        original_execution["id"]: rebuilt_execution,
    }
    with pytest.raises(EvidenceValidationError, match="embedded evidence response digest"):
        create_bundle_payload(
            [replacements.get(record["id"], record) for record in original["records"]],
            created_at=original["created_at"],
            run_id=original["run_id"],
        )


def test_missing_trust_is_unverifiable_and_historical_source_key_remains_valid() -> None:
    bundle, trust, _manifest = load_reference()
    bundle_key_id = bundle["envelope"]["signatures"][0]["keyid"]
    bundle_key = next(record for record in trust["keys"] if record["key_id"] == bundle_key_id)
    source_key = next(record for record in trust["keys"] if record["key_id"] != bundle_key_id)
    assert verify_bundle(bundle, policy_from(trust, keys=[source_key])).state is VerificationState.UNVERIFIABLE
    assert verify_bundle(bundle, policy_from(trust, keys=[bundle_key])).state is VerificationState.UNVERIFIABLE

    payload = signed_payload(bundle)
    issued_at = max(
        parse_timestamp(record["statement"]["observed_at"])
        for record in payload["records"]
        if record["kind"] == "evidence"
    )
    retired_source = copy.deepcopy(source_key)
    retired_at = issued_at + timedelta(seconds=1)
    retired_source.update(
        status="retired",
        valid_until=retired_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        status_changed_at=retired_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    )
    assert verify_bundle(bundle, policy_from(trust, keys=[bundle_key, retired_source])).state is VerificationState.VALID
