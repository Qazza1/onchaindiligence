"""Complete deterministic Agent Evidence v0 DAG validation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .canonical import content_id, parse_timestamp
from .errors import EvidenceValidationError, ParseError, SchemaValidationError
from .models import JsonObject
from .schema import validate_document


def _fail(message: str) -> None:
    raise EvidenceValidationError(message)


def _require_record(
    by_id: Mapping[str, JsonObject],
    record_id: Any,
    kind: str,
    field: str,
) -> JsonObject:
    if not isinstance(record_id, str) or record_id not in by_id:
        _fail(f"{field} does not resolve in this bundle")
    record = by_id[record_id]
    if record.get("kind") != kind:
        _fail(f"{field} must resolve to a {kind} record")
    return record


def _assert_interval(start: Any, end: Any, label: str) -> None:
    if not isinstance(start, str) or not isinstance(end, str):
        return
    try:
        if parse_timestamp(end) < parse_timestamp(start):
            _fail(f"{label} end precedes start")
    except ParseError as exc:
        _fail(f"{label} contains an invalid timestamp: {exc}")


def _validate_embedded_digests(record: JsonObject) -> None:
    statement = record["statement"]
    if record["kind"] == "evidence":
        response = statement["response"]
        if response["mode"] == "embedded":
            expected = content_id(response["value"])[len("sha256:") :]
            if response["digest"]["sha256"] != expected:
                _fail("embedded evidence response digest does not match value")
    if record["kind"] == "policy" and "policy" in statement:
        expected = content_id(statement["policy"])[len("sha256:") :]
        if statement["digest"]["sha256"] != expected:
            _fail("embedded policy digest does not match policy value")


def validate_bundle_payload(payload: Mapping[str, Any]) -> None:
    """Validate schemas, IDs, complete roots, DAG, references, and kind invariants."""

    value = dict(payload)
    try:
        validate_document("bundle-payload.schema.json", value)
    except SchemaValidationError as exc:
        raise EvidenceValidationError(str(exc)) from exc

    records = value["records"]
    ids = [record["id"] for record in records]
    if ids != sorted(ids):
        _fail("records must be sorted lexicographically by id")
    if len(ids) != len(set(ids)):
        _fail("record ids must be unique")
    by_id: dict[str, JsonObject] = {record["id"]: record for record in records}

    for record in records:
        record_id = record["id"]
        body = {key: item for key, item in record.items() if key != "id"}
        if content_id(body) != record_id:
            _fail(f"record id mismatch: {record_id}")
        parents = record["parents"]
        if parents != sorted(parents) or len(parents) != len(set(parents)):
            _fail(f"parents must be sorted and unique: {record_id}")
        for parent in parents:
            if parent == record_id:
                _fail(f"record cannot parent itself: {record_id}")
            if parent not in by_id:
                _fail(f"missing parent {parent} referenced by {record_id}")
        _validate_embedded_digests(record)

    run_records = [record for record in records if record["kind"] == "run"]
    if len(run_records) != 1:
        _fail("a v0 bundle must contain exactly one run record")
    if value["run_id"] != run_records[0]["id"]:
        _fail("run_id must resolve to the bundle's single run record")

    parent_ids = {parent for record in records for parent in record["parents"]}
    expected_roots = sorted(record_id for record_id in ids if record_id not in parent_ids)
    if value["root_ids"] != expected_roots:
        _fail("root_ids must equal the complete sorted set of records with no children")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(record_id: str) -> None:
        if record_id in visiting:
            _fail(f"cycle detected at {record_id}")
        if record_id in visited:
            return
        visiting.add(record_id)
        for parent in by_id[record_id]["parents"]:
            visit(parent)
        visiting.remove(record_id)
        visited.add(record_id)

    for root_id in expected_roots:
        visit(root_id)
    if visited != set(ids):
        _fail("every record must be reachable from the complete root set")

    for record in records:
        kind = record["kind"]
        parents = record["parents"]
        statement = record["statement"]
        if kind == "principal":
            if parents:
                _fail("principal records cannot have parents")
        elif kind == "agent":
            operator = statement.get("operator_ref")
            if operator is not None:
                _require_record(by_id, operator, "principal", "agent.operator_ref")
                if operator not in parents:
                    _fail("agent parents must include operator_ref")
            if any(by_id[parent]["kind"] != "principal" for parent in parents):
                _fail("agent parents may only be principal records")
        elif kind == "mandate":
            principal = statement["principal_ref"]
            _require_record(by_id, principal, "principal", "mandate.principal_ref")
            if principal not in parents:
                _fail("mandate parents must include principal_ref")
            if any(by_id[parent]["kind"] != "principal" for parent in parents):
                _fail("mandate parents may only be principal records")
            _assert_interval(statement["valid_from"], statement["valid_until"], "mandate")
        elif kind == "run":
            agent = statement["agent_ref"]
            mandate = statement["mandate_ref"]
            _require_record(by_id, agent, "agent", "run.agent_ref")
            mandate_record = _require_record(by_id, mandate, "mandate", "run.mandate_ref")
            if parents != sorted([agent, mandate]):
                _fail("run parents must be exactly agent_ref and mandate_ref")
            if "ended_at" in statement:
                _assert_interval(statement["started_at"], statement["ended_at"], "run")
            started = parse_timestamp(statement["started_at"])
            mandate_statement = mandate_record["statement"]
            if not (
                parse_timestamp(mandate_statement["valid_from"])
                <= started
                <= parse_timestamp(mandate_statement["valid_until"])
            ):
                _fail("run.started_at is outside the presented mandate interval")
        elif kind == "evidence":
            run_ref = statement["run_ref"]
            _require_record(by_id, run_ref, "run", "evidence.run_ref")
            if run_ref not in parents:
                _fail("evidence parents must include run_ref")
            if any(by_id[parent]["kind"] not in {"run", "evidence"} for parent in parents):
                _fail("evidence parents may only be run or evidence records")
            if statement["expires_at"] is not None:
                _assert_interval(statement["observed_at"], statement["expires_at"], "evidence")
        elif kind == "policy":
            if not any(by_id[parent]["kind"] in {"run", "mandate"} for parent in parents):
                _fail("policy parents must include a run or mandate")
            if any(by_id[parent]["kind"] not in {"run", "mandate"} for parent in parents):
                _fail("policy parents may only be run or mandate records")
            if "effective_until" in statement:
                _assert_interval(statement["effective_from"], statement["effective_until"], "policy")
        elif kind == "decision":
            run_ref = statement["run_ref"]
            policy_ref = statement["policy_ref"]
            agent_ref = statement["agent_ref"]
            _require_record(by_id, run_ref, "run", "decision.run_ref")
            _require_record(by_id, agent_ref, "agent", "decision.agent_ref")
            policy_record = _require_record(by_id, policy_ref, "policy", "decision.policy_ref")
            for evidence_ref in statement["evidence_refs"]:
                _require_record(by_id, evidence_ref, "evidence", "decision.evidence_refs")
            expected = sorted({run_ref, policy_ref, *statement["evidence_refs"]})
            if parents != expected:
                _fail("decision parents must exactly equal run, policy, and evidence references")
            if statement["policy_digest"] != policy_record["statement"]["digest"]:
                _fail("decision.policy_digest does not match the referenced policy")
            decided_at = parse_timestamp(statement["decided_at"])
            policy_statement = policy_record["statement"]
            if decided_at < parse_timestamp(policy_statement["effective_from"]):
                _fail("decision predates the referenced policy's effective interval")
            if policy_statement.get("effective_until") is not None and decided_at > parse_timestamp(
                policy_statement["effective_until"]
            ):
                _fail("decision follows the referenced policy's effective interval")
        elif kind == "execution":
            decision_ref = statement["decision_ref"]
            _require_record(by_id, decision_ref, "decision", "execution.decision_ref")
            if parents != [decision_ref]:
                _fail("v0 execution parents must contain exactly decision_ref")
            if str(statement["execution_type"]).startswith("onchain"):
                required = {"network", "transaction_hash", "transaction_digest"}
                missing = sorted(required - statement.keys())
                if missing:
                    _fail(f"onchain execution is missing: {', '.join(missing)}")
            if "confirmed_at" in statement:
                _assert_interval(statement["submitted_at"], statement["confirmed_at"], "execution")

    without_id = {key: item for key, item in value.items() if key != "bundle_id"}
    if value["bundle_id"] != content_id(without_id):
        _fail("bundle_id does not match the canonical payload without bundle_id")
