from __future__ import annotations

import base64
import json
import socket

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from onchaindiligence.agent_evidence import (
    TrustPolicy,
    VerificationState,
    canonicalize,
    content_id,
    create_key_record,
    dsse_pae,
    parse_timestamp,
    verify_signed_payment_claim,
)
from onchaindiligence.agent_evidence.payment_claims import SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE


def fixture() -> tuple[dict[str, object], TrustPolicy]:
    private_key = Ed25519PrivateKey.generate()
    key = create_key_record(private_key.public_key(), valid_from="2026-09-01T00:00:00.000Z")
    core: dict[str, object] = {
        "claim_version": "onchaindiligence.signed-claim.payment.v1",
        "issuer": {"id": "https://payments.example"},
        "issued_at": "2026-09-26T11:00:00.000Z",
        "provider_reference": "provider-payment-123",
        "payment": {"network": "eip155:8453", "asset": "USDC", "amount": "0.01"},
        "execution": {"claimed_status": "SUCCEEDED", "transaction_hash": "0xtx"},
        "extensions": {},
    }
    claim = {**core, "claim_id": content_id(core)}
    payload = canonicalize(claim)
    envelope = {
        "payloadType": SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {
                "keyid": key["key_id"],
                "sig": base64.b64encode(private_key.sign(dsse_pae(SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE, payload))).decode(
                    "ascii"
                ),
            }
        ],
    }
    policy = TrustPolicy.from_key_records(
        [key],
        now=parse_timestamp("2026-09-26T12:00:00.000Z"),
        payment_claim_issuer_key_ids={"https://payments.example": frozenset({key["key_id"]})},
    )
    return envelope, policy


def test_signed_payment_claim_tri_state_and_offline_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    envelope, policy = fixture()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline payment-claim verification attempted network access")

    monkeypatch.setattr(socket, "socket", forbidden)
    assert verify_signed_payment_claim(envelope, policy).state is VerificationState.VALID
    assert verify_signed_payment_claim(envelope, TrustPolicy(now=policy.now)).state is VerificationState.UNVERIFIABLE
    tampered = json.loads(json.dumps(envelope))
    tampered["payload"] = base64.b64encode(b"{}").decode("ascii")
    assert verify_signed_payment_claim(tampered, policy).state is VerificationState.INVALID


def test_payment_claim_issuer_pinning_and_replay_protection() -> None:
    envelope, policy = fixture()
    assert (
        verify_signed_payment_claim(envelope, policy, expected_issuer="https://other.example").state
        is VerificationState.INVALID
    )
    replay = {**envelope, "payloadType": "application/vnd.onchaindiligence.public-action-receipt.v1+json"}
    assert verify_signed_payment_claim(replay, policy).state is VerificationState.INVALID


def test_payment_claim_requires_explicit_issuer_key_binding() -> None:
    envelope, policy = fixture()
    unbound = TrustPolicy(
        keys=policy.keys,
        now=policy.now,
        payment_claim_issuer_key_ids={"https://issuer-a.example": frozenset(policy.keys)},
    )
    checked = verify_signed_payment_claim(envelope, unbound)
    assert checked.state is VerificationState.UNVERIFIABLE
    assert checked.code == "issuer-key-binding-missing"
