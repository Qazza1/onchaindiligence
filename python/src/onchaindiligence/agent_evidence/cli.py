"""Small zero-network command-line surface for portable verification."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

from .canonical import parse_json, parse_timestamp
from .errors import AgentEvidenceError
from .models import VerificationState
from .trust import TrustPolicy
from .verifier import verify_bundle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ocd-evidence")
    subcommands = parser.add_subparsers(dest="command", required=True)
    verify = subcommands.add_parser("verify", help="verify a portable bundle without network access")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--trust", type=Path, required=True, help="JSON key registry or key-record array")
    verify.add_argument("--now", help="exact policy time (YYYY-MM-DDTHH:mm:ss.sssZ)")
    verify.add_argument("--max-bundle-age-seconds", type=int)
    verify.add_argument("--allow-expired-evidence", action="store_true")
    verify.add_argument("--include-payload", action="store_true")
    return parser


def _key_records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        return cast(list[dict[str, Any]], value)
    if isinstance(value, dict) and isinstance(value.get("keys"), list):
        records = value["keys"]
        if all(isinstance(item, dict) for item in records):
            return cast(list[dict[str, Any]], records)
    raise ValueError("trust file must be a key-record array or an object containing a keys array")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return its stable process status."""

    arguments = _parser().parse_args(argv)
    try:
        bundle_bytes = arguments.bundle.read_bytes()
        trust_value = parse_json(arguments.trust.read_bytes())
        options: dict[str, Any] = {
            "enforce_evidence_expiration": not arguments.allow_expired_evidence,
        }
        if arguments.now is not None:
            options["now"] = parse_timestamp(arguments.now)
        if arguments.max_bundle_age_seconds is not None:
            if arguments.max_bundle_age_seconds < 0:
                raise ValueError("max bundle age cannot be negative")
            options["max_bundle_age"] = timedelta(seconds=arguments.max_bundle_age_seconds)
        policy = TrustPolicy.from_key_records(_key_records(trust_value), **options)
        report = verify_bundle(bundle_bytes, policy)
    except (AgentEvidenceError, OSError, ValueError) as exc:
        print(json.dumps({"state": "ERROR", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report.to_dict(include_payload=arguments.include_payload), indent=2, sort_keys=True))
    if report.state is VerificationState.VALID:
        return 0
    if report.state is VerificationState.INVALID:
        return 3
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
