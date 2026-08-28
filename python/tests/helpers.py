"""Shared builders that reproduce the language-neutral conformance graph."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from onchaindiligence.agent_evidence import (
    content_id,
    create_bundle_payload,
    create_key_record,
    create_record,
    seal_bundle,
)

TEST_SEED = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")


def digest(value: Any) -> dict[str, str]:
    return {"sha256": content_id(value).removeprefix("sha256:")}


def build_conformance_portable(
    *,
    evidence_proofs: Sequence[Mapping[str, Any]] | None = None,
    evidence_response: Mapping[str, Any] | None = None,
    evidence_trust_mode: str = "agent-assertion",
    evidence_reference: str | None = None,
    evidence_source_id: str = "https://api.example.invalid",
) -> tuple[dict[str, Any], dict[str, Any], Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    principal = create_record(
        "principal",
        {
            "principal_id": "urn:onchaindiligence:test:treasury",
            "principal_type": "organization",
            "display_name": "Conformance Treasury",
        },
    )
    agent = create_record(
        "agent",
        {
            "agent_id": "urn:onchaindiligence:test:agent",
            "agent_version": "1.0.0",
            "operator_ref": principal["id"],
        },
        parents=[principal["id"]],
    )
    mandate = create_record(
        "mandate",
        {
            "mandate_id": "mandate-conformance-001",
            "principal_ref": principal["id"],
            "scope": {"action": "pay", "asset": "pathUSD", "max_amount": "10.00"},
            "valid_from": "2026-08-28T00:00:00.000Z",
            "valid_until": "2026-08-29T00:00:00.000Z",
            "limits": {"amount": "10.00"},
        },
        parents=[principal["id"]],
    )
    run = create_record(
        "run",
        {
            "run_external_id": "run-conformance-001",
            "agent_ref": agent["id"],
            "mandate_ref": mandate["id"],
            "started_at": "2026-08-28T12:00:00.000Z",
            "ended_at": "2026-08-28T12:00:05.000Z",
        },
        parents=[agent["id"], mandate["id"]],
    )
    request = {"address": "0x0000000000000000000000000000000000000001"}
    response = dict(evidence_response or {"sanctioned": False})
    proofs = list(
        evidence_proofs
        or [
            {
                "proof_type": "external-digest",
                "media_type": "application/json",
                "digest": digest(response),
            }
        ]
    )
    response_statement: dict[str, Any]
    if evidence_reference is None:
        response_statement = {
            "mode": "embedded",
            "media_type": "application/json",
            "value": response,
            "digest": digest(response),
        }
    else:
        response_statement = {
            "mode": "reference",
            "media_type": "application/json",
            "reference": evidence_reference,
            "digest": digest(response),
        }
    evidence = create_record(
        "evidence",
        {
            "evidence_type": "sanctions-screen",
            "run_ref": run["id"],
            "trust_mode": evidence_trust_mode,
            "source": {"id": evidence_source_id, "type": "https-api"},
            "tool": {"name": "screen_wallet", "version": "1"},
            "request": {"digest": digest(request), "media_type": "application/json"},
            "response": response_statement,
            "observed_at": "2026-08-28T12:00:01.000Z",
            "expires_at": None,
            "scope": {"query": request["address"], "coverage": "one test address"},
        },
        parents=[run["id"]],
        proofs=proofs,
    )
    policy_value = {"rule": "sanctioned must be false"}
    policy = create_record(
        "policy",
        {
            "policy_id": "urn:onchaindiligence:test:policy",
            "version": "1",
            "digest": digest(policy_value),
            "source": "https://example.invalid/policy/1",
            "effective_from": "2026-08-28T00:00:00.000Z",
            "policy": policy_value,
        },
        parents=[run["id"]],
    )
    decision = create_record(
        "decision",
        {
            "decision_id": "decision-conformance-001",
            "run_ref": run["id"],
            "agent_ref": agent["id"],
            "decision_type": "payment-approval",
            "outcome": {"approved": True},
            "evidence_refs": [evidence["id"]],
            "policy_ref": policy["id"],
            "policy_digest": policy["statement"]["digest"],
            "decided_at": "2026-08-28T12:00:03.000Z",
        },
        parents=[run["id"], evidence["id"], policy["id"]],
    )
    execution = create_record(
        "execution",
        {
            "execution_id": "execution-conformance-001",
            "decision_ref": decision["id"],
            "execution_type": "onchain-transfer",
            "status": "confirmed",
            "submitted_at": "2026-08-28T12:00:04.000Z",
            "network": "eip155:1",
            "transaction_hash": "0x" + "11" * 32,
            "transaction_digest": digest({"to": "0x" + "22" * 20, "value": "1.00"}),
            "sender": "0x" + "33" * 20,
            "recipient": "0x" + "22" * 20,
            "asset": "pathUSD",
            "amount": "1.00",
            "confirmed_at": "2026-08-28T12:00:05.000Z",
            "block_number": "12345678",
        },
        parents=[decision["id"]],
    )
    records = [principal, agent, mandate, run, evidence, policy, decision, execution]
    payload = create_bundle_payload(records, created_at="2026-08-28T12:00:06.000Z")
    key_record = create_key_record(
        private_key.public_key(),
        valid_from="2026-08-28T00:00:00.000Z",
    )
    portable = seal_bundle(payload, private_key, keys=[key_record])
    return portable, key_record, private_key
