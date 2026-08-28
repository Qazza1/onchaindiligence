from __future__ import annotations

import copy

import pytest

from onchaindiligence.agent_evidence import (
    TrustPolicy,
    TrustPolicyError,
    VerificationState,
    parse_timestamp,
    verify_bundle,
)

from .helpers import build_conformance_portable

NOW = parse_timestamp("2026-08-28T12:01:00.000Z")


def verify_with_record(record: dict[str, object]) -> VerificationState:
    portable, _, _ = build_conformance_portable()
    policy = TrustPolicy.from_key_records([record], now=NOW)
    return verify_bundle(portable, policy).state


def test_active_retired_revoked_and_compromised_lifecycle() -> None:
    _, active, _ = build_conformance_portable()
    assert verify_with_record(active) is VerificationState.VALID

    retired = copy.deepcopy(active)
    retired.update(
        status="retired",
        valid_until="2026-08-28T12:30:00.000Z",
        status_changed_at="2026-08-28T12:30:00.000Z",
    )
    assert verify_with_record(retired) is VerificationState.VALID

    expired = copy.deepcopy(retired)
    expired["valid_until"] = "2026-08-28T12:00:05.000Z"
    expired["status_changed_at"] = "2026-08-28T12:00:05.000Z"
    assert verify_with_record(expired) is VerificationState.INVALID

    revoked = copy.deepcopy(active)
    revoked.update(
        status="revoked",
        status_reason="test revocation",
        status_changed_at="2026-08-28T12:30:00.000Z",
    )
    assert verify_with_record(revoked) is VerificationState.INVALID

    compromised = copy.deepcopy(active)
    compromised.update(
        status="compromised",
        status_changed_at="2026-08-28T12:30:00.000Z",
        compromised_at="2026-08-28T12:30:00.000Z",
    )
    assert verify_with_record(compromised) is VerificationState.INVALID


def test_missing_activation_boundary_is_unverifiable() -> None:
    _, active, _ = build_conformance_portable()
    active["valid_from"] = None
    assert verify_with_record(active) is VerificationState.UNVERIFIABLE


def test_embedded_key_never_becomes_trusted() -> None:
    portable, _, _ = build_conformance_portable()
    assert portable["verification_material"]["keys"]
    assert verify_bundle(portable, TrustPolicy(now=NOW)).state is VerificationState.UNVERIFIABLE


def test_spki_key_id_mismatch_is_rejected_as_caller_configuration() -> None:
    _, active, _ = build_conformance_portable()
    active["key_id"] = "ed25519-AAAAAAAAAAAAAAAA"
    with pytest.raises(TrustPolicyError, match="does not match SPKI"):
        TrustPolicy.from_key_records([active], now=NOW)


def test_replacement_links_must_be_distinct_and_present_in_caller_trust() -> None:
    _, active, _ = build_conformance_portable()
    active["replacement_key_id"] = active["key_id"]
    with pytest.raises(TrustPolicyError, match="cannot name itself"):
        TrustPolicy.from_key_records([active], now=NOW)

    active["replacement_key_id"] = "ed25519-AAAAAAAAAAAAAAAA"
    with pytest.raises(TrustPolicyError, match="absent replacement"):
        TrustPolicy.from_key_records([active], now=NOW)


def test_caller_signature_threshold_is_explicit() -> None:
    portable, active, _ = build_conformance_portable()
    policy = TrustPolicy.from_key_records(
        [active],
        now=NOW,
        required_signature_key_ids=frozenset({active["key_id"]}),
        minimum_valid_signatures=1,
    )
    assert verify_bundle(portable, policy).state is VerificationState.VALID


def test_duplicate_dsse_key_cannot_satisfy_a_signature_threshold() -> None:
    portable, active, _ = build_conformance_portable()
    portable["envelope"]["signatures"].append(copy.deepcopy(portable["envelope"]["signatures"][0]))
    policy = TrustPolicy.from_key_records([active], now=NOW, minimum_valid_signatures=2)
    report = verify_bundle(portable, policy)
    assert report.state is VerificationState.INVALID
    assert any(component.code == "duplicate-signature-key" for component in report.components)


def test_digest_only_evidence_requires_explicit_caller_policy() -> None:
    portable, active, _ = build_conformance_portable(evidence_reference="https://example.invalid/immutable/result.json")
    strict = TrustPolicy.from_key_records([active], now=NOW)
    assert verify_bundle(portable, strict).state is VerificationState.UNVERIFIABLE
    digest_only = TrustPolicy.from_key_records(
        [active],
        now=NOW,
        allow_digest_only_evidence=True,
    )
    assert verify_bundle(portable, digest_only).state is VerificationState.VALID


def test_non_agent_trust_mode_requires_a_cryptographic_proof() -> None:
    portable, active, _ = build_conformance_portable(evidence_trust_mode="publisher-signed")
    policy = TrustPolicy.from_key_records([active], now=NOW)
    assert verify_bundle(portable, policy).state is VerificationState.INVALID


def test_optional_material_never_becomes_ambient_trust_or_required_success() -> None:
    portable, active, _ = build_conformance_portable()
    portable["verification_material"]["anchors"] = [{"anchor_type": "test-only", "value": {}}]
    default_policy = TrustPolicy.from_key_records([active], now=NOW)
    report = verify_bundle(portable, default_policy)
    assert report.state is VerificationState.VALID
    assert any(
        component.code == "anchor-format-unsupported" and not component.required for component in report.components
    )

    required_policy = TrustPolicy.from_key_records([active], now=NOW, require_verified_anchor=True)
    assert verify_bundle(portable, required_policy).state is VerificationState.UNVERIFIABLE

    no_anchor, _, _ = build_conformance_portable()
    assert verify_bundle(no_anchor, required_policy).state is VerificationState.UNVERIFIABLE
