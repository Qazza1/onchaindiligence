from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from onchaindiligence.agent_evidence.cli import main

from .helpers import build_conformance_portable


def write_inputs(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    portable, key_record, _ = build_conformance_portable()
    bundle = tmp_path / "bundle.json"
    trust = tmp_path / "trust.json"
    bundle.write_text(json.dumps(portable), encoding="utf-8")
    trust.write_text(json.dumps({"keys": [key_record]}), encoding="utf-8")
    return bundle, trust, portable


@pytest.mark.parametrize(
    ("mutation", "trust_keys", "expected_exit", "expected_state"),
    [
        (False, True, 0, "VALID"),
        (True, True, 3, "INVALID"),
        (False, False, 4, "UNVERIFIABLE"),
    ],
)
def test_cli_tri_state_exit_contract(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mutation: bool,
    trust_keys: bool,
    expected_exit: int,
    expected_state: str,
) -> None:
    bundle, trust, portable = write_inputs(tmp_path)
    if mutation:
        changed = copy.deepcopy(portable)
        changed["envelope"]["signatures"][0]["sig"] = "A" * 86 + "=="
        bundle.write_text(json.dumps(changed), encoding="utf-8")
    if not trust_keys:
        trust.write_text('{"keys":[]}', encoding="utf-8")
    exit_code = main(
        [
            "verify",
            str(bundle),
            "--trust",
            str(trust),
            "--now",
            "2026-08-28T12:01:00.000Z",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert exit_code == expected_exit
    assert output["state"] == expected_state


def test_cli_trust_file_error_is_usage_exit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bundle, trust, _ = write_inputs(tmp_path)
    trust.write_text('{"not_keys":[]}', encoding="utf-8")
    assert main(["verify", str(bundle), "--trust", str(trust)]) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["state"] == "ERROR"
