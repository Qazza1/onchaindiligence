from __future__ import annotations

import json
import sys
from pathlib import Path

from onchaindiligence.agent_evidence import TrustPolicy, parse_timestamp, verify_bundle


def main() -> int:
    portable = Path(sys.argv[1]).read_bytes()
    trust_document = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    policy = TrustPolicy.from_key_records(
        trust_document["keys"],
        now=parse_timestamp("2026-08-28T12:01:00.000Z"),
    )
    report = verify_bundle(portable, policy)
    print(json.dumps(report.to_dict(), separators=(",", ":")))
    return 0 if report.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
