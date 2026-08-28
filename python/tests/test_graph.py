from __future__ import annotations

import base64
import copy
import json

import pytest

from onchaindiligence.agent_evidence import (
    EvidenceValidationError,
    content_id,
    validate_bundle_payload,
)

from .helpers import build_conformance_portable


def payload_fixture() -> dict[str, object]:
    portable, _, _ = build_conformance_portable()
    return json.loads(base64.b64decode(portable["envelope"]["payload"]))


def rebind_bundle(payload: dict[str, object]) -> None:
    without_id = {key: value for key, value in payload.items() if key != "bundle_id"}
    payload["bundle_id"] = content_id(without_id)


def rebind_record(record: dict[str, object]) -> tuple[str, str]:
    previous = str(record["id"])
    body = {key: value for key, value in record.items() if key != "id"}
    record["id"] = content_id(body)
    return previous, str(record["id"])


def test_root_set_and_record_order_are_complete_and_deterministic() -> None:
    payload = payload_fixture()
    payload["root_ids"] = [payload["run_id"]]
    rebind_bundle(payload)
    with pytest.raises(EvidenceValidationError, match="complete sorted set"):
        validate_bundle_payload(payload)

    payload = payload_fixture()
    payload["records"] = list(reversed(payload["records"]))
    rebind_bundle(payload)
    with pytest.raises(EvidenceValidationError, match="sorted lexicographically"):
        validate_bundle_payload(payload)


def test_decision_parent_union_is_exact_even_when_ids_are_recomputed() -> None:
    payload = payload_fixture()
    records = payload["records"]
    decision = next(record for record in records if record["kind"] == "decision")
    agent = next(record for record in records if record["kind"] == "agent")
    execution = next(record for record in records if record["kind"] == "execution")

    decision["parents"] = sorted([*decision["parents"], agent["id"]])
    old_decision, new_decision = rebind_record(decision)
    execution["parents"] = [new_decision]
    execution["statement"]["decision_ref"] = new_decision
    _, new_execution = rebind_record(execution)
    payload["root_ids"] = [new_execution]
    payload["records"] = sorted(records, key=lambda record: record["id"])
    rebind_bundle(payload)

    assert old_decision != new_decision
    with pytest.raises(EvidenceValidationError, match="decision parents must exactly equal"):
        validate_bundle_payload(payload)


def test_onchain_execution_requires_transaction_binding() -> None:
    payload = payload_fixture()
    records = payload["records"]
    execution = next(record for record in records if record["kind"] == "execution")
    del execution["statement"]["transaction_digest"]
    _, new_execution = rebind_record(execution)
    payload["root_ids"] = [new_execution]
    payload["records"] = sorted(records, key=lambda record: record["id"])
    rebind_bundle(payload)
    with pytest.raises(EvidenceValidationError, match="transaction_digest"):
        validate_bundle_payload(payload)


def test_mutation_without_content_id_rebinding_is_rejected() -> None:
    payload = payload_fixture()
    mutated = copy.deepcopy(payload)
    evidence = next(record for record in mutated["records"] if record["kind"] == "evidence")
    evidence["statement"]["response"]["value"]["sanctioned"] = True
    rebind_bundle(mutated)
    with pytest.raises(EvidenceValidationError, match="record id mismatch"):
        validate_bundle_payload(mutated)
