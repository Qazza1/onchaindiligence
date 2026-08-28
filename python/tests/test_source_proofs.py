from __future__ import annotations

import base64
import copy
import json

from onchaindiligence.agent_evidence import (
    TrustPolicy,
    VerificationState,
    canonicalize,
    derive_key_id,
    dsse_pae,
    parse_timestamp,
    verify_bundle,
)

from .helpers import TEST_SEED, build_conformance_portable, digest

NOW = parse_timestamp("2026-08-28T12:01:00.000Z")
STATEMENT_MEDIA_TYPE = "application/vnd.example.sanctions-result+json"


def evidence_statement(*, trust_mode: str = "agent-assertion") -> dict[str, object]:
    request = {"address": "0x0000000000000000000000000000000000000001"}
    response = {"sanctioned": False}
    # run_ref is replaced with the deterministic conformance run ID below.
    portable, _, _ = build_conformance_portable()
    import base64 as base64_module

    payload = json.loads(base64_module.b64decode(portable["envelope"]["payload"]))
    run_id = payload["run_id"]
    return {
        "evidence_type": "sanctions-screen",
        "run_ref": run_id,
        "trust_mode": trust_mode,
        "source": {"id": "https://api.example.invalid", "type": "https-api"},
        "tool": {"name": "screen_wallet", "version": "1"},
        "request": {"digest": digest(request), "media_type": "application/json"},
        "response": {
            "mode": "embedded",
            "media_type": "application/json",
            "value": response,
            "digest": digest(response),
        },
        "observed_at": "2026-08-28T12:00:01.000Z",
        "expires_at": None,
        "scope": {"query": request["address"], "coverage": "one test address"},
    }


def test_source_dsse_verifies_exact_canonical_statement() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    statement = evidence_statement(trust_mode="local-witness")
    payload = canonicalize(statement)
    signature = private_key.sign(dsse_pae(STATEMENT_MEDIA_TYPE, payload))
    proof = {
        "proof_type": "dsse-ed25519-v1",
        "statement_media_type": STATEMENT_MEDIA_TYPE,
        "envelope": {
            "payloadType": STATEMENT_MEDIA_TYPE,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [
                {
                    "keyid": derive_key_id(private_key.public_key()),
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        },
    }
    portable, key_record, _ = build_conformance_portable(
        evidence_proofs=[proof],
        evidence_trust_mode="local-witness",
    )
    policy = TrustPolicy.from_key_records([key_record], now=NOW)
    assert verify_bundle(portable, policy).state is VerificationState.VALID

    retired = copy.deepcopy(key_record)
    retired.update(
        status="retired",
        valid_until="2026-08-28T12:30:00.000Z",
        status_changed_at="2026-08-28T12:30:00.000Z",
    )
    retired_policy = TrustPolicy.from_key_records([retired], now=NOW)
    assert verify_bundle(portable, retired_policy).state is VerificationState.UNVERIFIABLE


def test_v2_attestation_proof_and_tamper_detection() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    key_id = derive_key_id(private_key.public_key())
    data = {"address": "0x0000000000000000000000000000000000000001", "sanctioned": False}
    attestation = {
        "signed": True,
        "schema_version": "onchaindiligence.attestation.v2",
        "issuer": "https://api.onchaindiligence.com",
        "purpose": "compliance-screening-result",
        "issued_at": "2026-08-28T12:00:00.000Z",
        "key_id": key_id,
        "algorithm": "ed25519",
        "canonicalization": "RFC8785",
    }
    signed_input = {
        "schema_version": attestation["schema_version"],
        "issuer": attestation["issuer"],
        "purpose": attestation["purpose"],
        "data": data,
        "issued_at": attestation["issued_at"],
        "key_id": key_id,
    }
    attestation["signature"] = (
        base64.urlsafe_b64encode(private_key.sign(canonicalize(signed_input))).decode().rstrip("=")
    )
    envelope = {"data": data, "attestation": attestation}
    proof = {"proof_type": "onchaindiligence-attestation-v2", "envelope": envelope}
    portable, key_record, _ = build_conformance_portable(
        evidence_proofs=[proof],
        evidence_response=envelope,
        evidence_trust_mode="publisher-signed",
        evidence_source_id="https://api.onchaindiligence.com",
    )
    policy = TrustPolicy.from_key_records([key_record], now=NOW)
    assert verify_bundle(portable, policy).state is VerificationState.VALID

    tampered_attestation = copy.deepcopy(attestation)
    tampered_attestation["signature"] = "A" + tampered_attestation["signature"][1:]
    tampered_envelope = {"data": data, "attestation": tampered_attestation}
    tampered_proof = {
        "proof_type": "onchaindiligence-attestation-v2",
        "envelope": tampered_envelope,
    }
    tampered, _, _ = build_conformance_portable(
        evidence_proofs=[tampered_proof],
        evidence_response=tampered_envelope,
        evidence_trust_mode="publisher-signed",
        evidence_source_id="https://api.onchaindiligence.com",
    )
    assert verify_bundle(tampered, policy).state is VerificationState.INVALID


def test_legacy_v1_proof_preserves_representable_json_stringify_order() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    key_id = derive_key_id(private_key.public_key())
    data = {"address": "0x0000000000000000000000000000000000000001", "sanctioned": False}
    issued_at = "2026-08-28T12:00:00.000Z"
    signed_input = {"data": data, "issued_at": issued_at, "key_id": key_id}
    message = json.dumps(signed_input, ensure_ascii=False, separators=(",", ":")).encode()
    envelope = {
        "data": data,
        "attestation": {
            "signed": True,
            "issued_at": issued_at,
            "key_id": key_id,
            "algorithm": "ed25519",
            "signature": base64.urlsafe_b64encode(private_key.sign(message)).decode().rstrip("="),
        },
    }
    proof = {"proof_type": "onchaindiligence-attestation-v1", "envelope": envelope}
    portable, key_record, _ = build_conformance_portable(
        evidence_proofs=[proof],
        evidence_response=envelope,
        evidence_trust_mode="publisher-signed",
        evidence_source_id="https://api.onchaindiligence.com",
    )
    policy = TrustPolicy.from_key_records([key_record], now=NOW)
    assert verify_bundle(portable, policy).state is VerificationState.VALID


def test_onchaindiligence_attestation_cannot_substitute_source_identity() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    key_id = derive_key_id(private_key.public_key())
    data = {"sanctioned": False}
    attestation = {
        "signed": True,
        "schema_version": "onchaindiligence.attestation.v2",
        "issuer": "https://api.onchaindiligence.com",
        "purpose": "compliance-screening-result",
        "issued_at": "2026-08-28T12:00:00.000Z",
        "key_id": key_id,
        "algorithm": "ed25519",
        "canonicalization": "RFC8785",
    }
    signed_input = {
        "schema_version": attestation["schema_version"],
        "issuer": attestation["issuer"],
        "purpose": attestation["purpose"],
        "data": data,
        "issued_at": attestation["issued_at"],
        "key_id": key_id,
    }
    attestation["signature"] = (
        base64.urlsafe_b64encode(private_key.sign(canonicalize(signed_input))).decode().rstrip("=")
    )
    envelope = {"data": data, "attestation": attestation}
    portable, key_record, _ = build_conformance_portable(
        evidence_proofs=[{"proof_type": "onchaindiligence-attestation-v2", "envelope": envelope}],
        evidence_response=envelope,
        evidence_trust_mode="publisher-signed",
        evidence_source_id="https://attacker.example",
    )
    report = verify_bundle(portable, TrustPolicy.from_key_records([key_record], now=NOW))
    assert report.state is VerificationState.INVALID
    assert any(component.code == "attestation-source-mismatch" for component in report.components)
