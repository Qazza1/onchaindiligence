from __future__ import annotations

import copy
import json
import socket
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from onchaindiligence.agent_evidence import (
    ParseError,
    TrustPolicy,
    VerificationState,
    canonicalize,
    parse_json,
    parse_timestamp,
    verify_bundle,
)

from .helpers import build_conformance_portable

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "spec" / "agent-evidence" / "v0" / "conformance"
SCHEMAS = ROOT / "spec" / "agent-evidence" / "v0" / "schema"
NOW = parse_timestamp("2026-08-28T12:01:00.000Z")


def load_json(path: Path) -> dict[str, Any]:
    value = parse_json(path.read_bytes())
    assert isinstance(value, dict)
    return value


def trusted_policy(valid: dict[str, Any]) -> TrustPolicy:
    return TrustPolicy.from_key_records(valid["verification_material"]["keys"], now=NOW)


def test_python_producer_exactly_matches_typescript_fixture() -> None:
    produced, _, _ = build_conformance_portable()
    assert produced == load_json(CORPUS / "valid-full-graph.json")


def test_manifest_tri_state_cases() -> None:
    manifest = load_json(CORPUS / "manifest.json")
    valid = load_json(CORPUS / "valid-full-graph.json")
    policy = trusted_policy(valid)
    for case in manifest["cases"]:
        if case["id"] == "duplicate-outer-key":
            document: Any = (CORPUS / case["fixture"]).read_bytes()
        else:
            document = load_json(CORPUS / case["fixture"])
            for operation in case.get("outer_json_patch", []):
                assert operation["op"] == "replace"
                if operation["path"] == "/bundle_version":
                    document["bundle_version"] = operation["value"]
                elif operation["path"] == "/envelope/signatures/0/sig":
                    document["envelope"]["signatures"][0]["sig"] = operation["value"]
                else:
                    pytest.fail(f"unsupported conformance patch {operation['path']}")
        case_policy = TrustPolicy(now=NOW) if case["id"] == "unknown-key" else policy
        report = verify_bundle(document, case_policy)
        assert report.state.value == case["expected"], case["id"]


def test_rfc8785_and_strict_parser_shared_vectors() -> None:
    corpus = load_json(ROOT / "conformance" / "rfc8785-vectors.json")
    for vector in corpus["canonicalization"]:
        assert canonicalize(vector["input"]).decode("utf-8") == vector["expected"], vector["id"]
    for vector in corpus["invalid_json"]:
        with pytest.raises(ParseError):
            parse_json(vector["input"])


def test_packaged_schemas_are_exact_contract_copies() -> None:
    packaged = files("onchaindiligence.agent_evidence").joinpath("schemas")
    for source in SCHEMAS.glob("*.schema.json"):
        assert packaged.joinpath(source.name).read_bytes() == source.read_bytes(), source.name
    assert packaged.joinpath("catalog.json").read_bytes() == (SCHEMAS / "catalog.json").read_bytes()


def test_packaged_conformance_files_are_exact_contract_copies() -> None:
    packaged = files("onchaindiligence.agent_evidence").joinpath("conformance")
    sources = {
        "manifest.json": CORPUS / "manifest.json",
        "valid-full-graph.json": CORPUS / "valid-full-graph.json",
        "noncanonical-payload.json": CORPUS / "noncanonical-payload.json",
        "missing-parent.json": CORPUS / "missing-parent.json",
        "duplicate-outer-key.json": CORPUS / "duplicate-outer-key.json",
        "rfc8785-vectors.json": ROOT / "conformance" / "rfc8785-vectors.json",
    }
    for name, source in sources.items():
        assert packaged.joinpath(name).read_bytes() == source.read_bytes(), name


def test_offline_verifier_has_no_socket_path(monkeypatch: pytest.MonkeyPatch) -> None:
    valid = load_json(CORPUS / "valid-full-graph.json")

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("offline verification attempted network access")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    assert verify_bundle(valid, trusted_policy(valid)).state is VerificationState.VALID


def test_mapping_input_is_defensively_copied() -> None:
    valid = load_json(CORPUS / "valid-full-graph.json")
    original = copy.deepcopy(valid)
    verify_bundle(valid, trusted_policy(valid))
    assert valid == original


def test_duplicate_fixture_is_not_accepted_by_plain_contract_parser() -> None:
    with pytest.raises(ParseError, match="duplicate"):
        parse_json((CORPUS / "duplicate-outer-key.json").read_bytes())
    # Demonstrate why ordinary JSON parsing is insufficient for implementers.
    assert isinstance(json.loads((CORPUS / "duplicate-outer-key.json").read_text()), dict)


def test_numeric_overflow_is_rejected_during_parsing() -> None:
    with pytest.raises(ParseError, match="finite IEEE-754"):
        parse_json('{"n":1e999}')
