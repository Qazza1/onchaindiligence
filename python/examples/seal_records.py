"""Validate and seal a JSON array of Agent Evidence records with an explicit key."""

from __future__ import annotations

import argparse
from pathlib import Path

from onchaindiligence.agent_evidence import (
    canonicalize,
    create_bundle_payload,
    load_private_key_pem,
    parse_json,
    seal_bundle,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("records", type=Path, help="JSON array of create_record-compatible records")
    parser.add_argument("private_key", type=Path, help="PKCS8 Ed25519 PEM")
    parser.add_argument("key_record", type=Path, help="public lifecycle key record JSON")
    parser.add_argument("output", type=Path)
    parser.add_argument("--created-at", required=True, help="exact millisecond UTC timestamp")
    arguments = parser.parse_args()

    records = parse_json(arguments.records.read_bytes())
    key_record = parse_json(arguments.key_record.read_bytes())
    private_key = load_private_key_pem(arguments.private_key.read_bytes())
    payload = create_bundle_payload(records, created_at=arguments.created_at)
    portable = seal_bundle(payload, private_key, keys=[key_record])
    arguments.output.write_bytes(canonicalize(portable))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
