"""Verify a real portable bundle against a caller-owned key file, without network access."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from onchaindiligence.agent_evidence import TrustPolicy, parse_json, verify_bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("trust", type=Path)
    arguments = parser.parse_args()
    trust_document = parse_json(arguments.trust.read_bytes())
    policy = TrustPolicy.from_key_records(trust_document["keys"], now=datetime.now(timezone.utc))
    report = verify_bundle(arguments.bundle.read_bytes(), policy)
    print(report.state.value)
    for component in report.components:
        print(component.state.value, component.component, component.code)
    return 0 if report.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
