"""Build the P1.8 public-safe production reference bundle.

The workflow captures live observations through the production TypeScript
provider and attestation modules, then constructs and seals the Agent Evidence
DAG exclusively through the public Python package API.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from onchaindiligence.agent_evidence import (
    TrustPolicy,
    VerificationState,
    canonicalize,
    content_id,
    create_bundle_payload,
    create_key_record,
    create_record,
    parse_json,
    parse_timestamp,
    seal_bundle,
    verify_bundle,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURE_SCRIPT = REPO_ROOT / "tools" / "p1_8" / "capture-providers.ts"
DEFAULT_OUTPUT = REPO_ROOT / "examples" / "production" / "p1_8"
SOURCE_ID = "https://api.onchaindiligence.com"
ENVELOPE_MEDIA_TYPE = "application/vnd.onchaindiligence.attestation.v2+json"


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _digest(value: Any) -> dict[str, str]:
    return {"sha256": content_id(value).removeprefix("sha256:")}


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonicalize(value) + b"\n")


def _private_key_pem(private_key: Ed25519PrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _capture(source_private_key: Ed25519PrivateKey, activated_at: str, target: Path) -> dict[str, Any]:
    tsx_name = "tsx.cmd" if os.name == "nt" else "tsx"
    tsx = REPO_ROOT / "node_modules" / ".bin" / tsx_name
    if not tsx.exists():
        raise RuntimeError("local TypeScript dependencies are missing; run npm install without changing versions")

    inherited = {
        name: value
        for name in (
            "PATH",
            "Path",
            "PATHEXT",
            "COMSPEC",
            "ComSpec",
            "SYSTEMROOT",
            "SystemRoot",
            "TEMP",
            "TMP",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "no_proxy",
        )
        if (value := os.environ.get(name)) is not None
    }
    capture_env = {
        **inherited,
        "ATTESTATION_PRIVATE_KEY": _private_key_pem(source_private_key),
        "ATTESTATION_KEY_ACTIVATED_AT": activated_at,
        "SANCTIONS_ORACLE_ADDRESS": "0x40C57923924B5c5c5455c48D93317139ADDaC8fb",
        "SANCTIONS_ORACLE_RPC_URL": "https://ethereum-rpc.publicnode.com",
        "EDGAR_USER_AGENT": "OnchainDiligence/1.0 (support@onchaindiligence.com)",
        "NODE_OPTIONS": "--use-env-proxy",
    }
    # Both executables are resolved beneath this repository; no captured value
    # or caller-controlled shell fragment participates in command selection.
    subprocess.run(  # noqa: S603
        [str(tsx), str(CAPTURE_SCRIPT), "--output", str(target)],
        cwd=REPO_ROOT,
        env=capture_env,
        check=True,
    )
    captured = parse_json(target.read_bytes())
    if not isinstance(captured, dict):
        raise TypeError("provider capture must be a JSON object")
    return captured


def _records(capture: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    observations = capture.get("observations")
    if not isinstance(observations, list) or len(observations) != 2:
        raise RuntimeError("P1.8 requires exactly the selected two provider observations")

    issued_times = [parse_timestamp(item["signed_envelope"]["attestation"]["issued_at"]) for item in observations]
    started_at = min(issued_times) - timedelta(seconds=1)
    decided_at = max(issued_times) + timedelta(seconds=1)
    execution_at = decided_at + timedelta(seconds=1)
    ended_at = execution_at

    principal = create_record(
        "principal",
        {
            "principal_id": "urn:onchaindiligence:public-reference-operator",
            "principal_type": "organization",
            "display_name": "OnChainDiligence public reference operator",
        },
    )
    agent = create_record(
        "agent",
        {
            "agent_id": "urn:onchaindiligence:agent:p1.8-financial-preflight",
            "agent_version": "1.0.0",
            "framework": "OnChainDiligence Agent Evidence reference workflow",
            "operator_ref": principal["id"],
        },
        parents=[principal["id"]],
    )
    mandate = create_record(
        "mandate",
        {
            "mandate_id": "p1.8-public-financial-preflight",
            "principal_ref": principal["id"],
            "scope": {
                "action": "evaluate-planned-financial-transfer",
                "asset": "pathUSD",
                "max_amount": "1.00",
                "recipient_wallet": observations[0]["request"]["address"],
                "counterparty_query": observations[1]["request"]["query"],
            },
            "valid_from": _timestamp(started_at - timedelta(minutes=1)),
            "valid_until": _timestamp(started_at + timedelta(hours=24)),
            "limits": {
                "no_external_execution_without_wallet_entity_binding": True,
                "maximum_amount": "1.00",
            },
        },
        parents=[principal["id"]],
    )
    run = create_record(
        "run",
        {
            "run_external_id": f"p1.8-{capture['captured_at']}",
            "agent_ref": agent["id"],
            "mandate_ref": mandate["id"],
            "started_at": _timestamp(started_at),
            "ended_at": _timestamp(ended_at),
        },
        parents=[agent["id"], mandate["id"]],
    )

    evidence_records: list[dict[str, Any]] = []
    for observation in observations:
        envelope = copy.deepcopy(observation["signed_envelope"])
        issued_at = envelope["attestation"]["issued_at"]
        evidence_records.append(
            create_record(
                "evidence",
                {
                    "evidence_type": observation["evidence_type"],
                    "run_ref": run["id"],
                    "trust_mode": "managed-witness",
                    "source": {"id": SOURCE_ID, "type": observation["source_type"]},
                    "tool": observation["tool"],
                    "request": {
                        "digest": _digest(observation["request"]),
                        "media_type": "application/json",
                    },
                    "response": {
                        "mode": "embedded",
                        "media_type": ENVELOPE_MEDIA_TYPE,
                        "value": envelope,
                        "digest": _digest(envelope),
                    },
                    "observed_at": issued_at,
                    "expires_at": None,
                    "scope": observation["scope"],
                },
                parents=[run["id"]],
                proofs=[
                    {
                        "proof_type": "onchaindiligence-attestation-v2",
                        "envelope": envelope,
                    }
                ],
            )
        )

    policy_value = {
        "policy_type": "financial-agent-payment-preflight",
        "rules": [
            {"id": "recipient-wallet-not-sanctioned", "required": True},
            {"id": "counterparty-sec-filer-resolved", "required": True},
            {"id": "recipient-wallet-bound-to-counterparty", "required": True},
        ],
        "if_required_binding_is_absent": "withhold-and-escalate",
        "trust_boundary": (
            "Provider assertions are evidence inputs. Their signatures do not establish "
            "objective truth or a relationship between independently queried subjects."
        ),
    }
    policy = create_record(
        "policy",
        {
            "policy_id": "urn:onchaindiligence:policy:p1.8-financial-preflight",
            "version": "1",
            "digest": _digest(policy_value),
            "source": "https://github.com/Qazza1/onchaindiligence/blob/main/examples/production/p1_8/README.md",
            "effective_from": _timestamp(started_at - timedelta(minutes=1)),
            "policy": policy_value,
        },
        parents=[run["id"]],
    )
    decision = create_record(
        "decision",
        {
            "decision_id": "p1.8-withhold-unbound-recipient",
            "run_ref": run["id"],
            "agent_ref": agent["id"],
            "decision_type": "planned-payment-preflight",
            "outcome": {
                "disposition": "manual-review",
                "authorized_to_execute": False,
                "reason_codes": ["recipient-wallet-not-bound-to-sec-filer"],
                "provider_observations_independent": True,
            },
            "evidence_refs": sorted(record["id"] for record in evidence_records),
            "policy_ref": policy["id"],
            "policy_digest": policy["statement"]["digest"],
            "decided_at": _timestamp(decided_at),
        },
        parents=[
            run["id"],
            policy["id"],
            *(record["id"] for record in evidence_records),
        ],
    )
    execution = create_record(
        "execution",
        {
            "execution_id": "p1.8-financial-transfer-withheld",
            "decision_ref": decision["id"],
            "execution_type": "decision-enforcement",
            "status": "withheld-not-submitted",
            "submitted_at": _timestamp(execution_at),
            "recipient": observations[0]["request"]["address"],
            "asset": "pathUSD",
            "amount": "1.00",
        },
        parents=[decision["id"]],
    )
    return [
        principal,
        agent,
        mandate,
        run,
        *evidence_records,
        policy,
        decision,
        execution,
    ], {
        "run": run,
        "evidence": evidence_records,
        "policy": policy,
        "decision": decision,
        "execution": execution,
        "created_at": _timestamp(execution_at + timedelta(seconds=1)),
    }


def _assert_public_safe(value: Any) -> None:
    encoded = canonicalize(value).lower()
    forbidden = (
        b"private key",
        b"bearer ",
        b'authorization"',
        b"api_token",
        b"client_secret",
    )
    matched = [item.decode("ascii") for item in forbidden if item in encoded]
    if matched:
        raise RuntimeError("public artifact contains forbidden sensitive marker(s): " + ", ".join(matched))


def build(output: Path) -> None:
    activated = datetime.now(timezone.utc)
    activated_at = _timestamp(activated)
    source_private = Ed25519PrivateKey.generate()
    bundle_private = Ed25519PrivateKey.generate()

    with tempfile.TemporaryDirectory(prefix="ocd-p1-8-") as temporary:
        capture_path = Path(temporary) / "capture.json"
        capture = _capture(source_private, activated_at, capture_path)

    source_key = capture["witness"]["key_record"]
    bundle_key = create_key_record(
        bundle_private.public_key(),
        valid_from=activated_at,
        status_reason=(
            "Dedicated P1.8 public reference bundle signer; private material was ephemeral and is not published."
        ),
    )
    records, graph = _records(capture)
    payload = create_bundle_payload(
        records,
        created_at=graph["created_at"],
        extensions={
            "https://onchaindiligence.com/extensions/production-reference/v1": {
                "roadmap_item": "P1.8",
                "provider_count": 2,
                "execution_boundary": "withheld-not-submitted",
            }
        },
    )
    portable = seal_bundle(payload, bundle_private, keys=[source_key, bundle_key])
    verification_now = parse_timestamp(graph["created_at"]) + timedelta(seconds=1)
    policy = TrustPolicy.from_key_records(
        [source_key, bundle_key],
        now=verification_now,
        required_signature_key_ids=frozenset({bundle_key["key_id"]}),
    )
    report = verify_bundle(portable, policy)
    if report.state is not VerificationState.VALID:
        raise RuntimeError(f"fresh P1.8 bundle did not verify: {report.to_dict()}")

    trust_file = {
        "trust_policy_version": "onchaindiligence.agent-evidence.trust-policy.p1.8.v1",
        "keys": [source_key, bundle_key],
        "required_signature_key_ids": [bundle_key["key_id"]],
        "minimum_valid_signatures": 1,
        "reference_verification_time": _timestamp(verification_now),
        "note": (
            "Keys become trusted only because the caller supplies this file out of band. "
            "Embedded bundle keys remain untrusted hints."
        ),
    }
    provider_files: list[dict[str, Any]] = []
    for observation in capture["observations"]:
        name = (
            "chainalysis-envelope.json"
            if observation["provider_id"].startswith("chainalysis")
            else "sec-edgar-envelope.json"
        )
        envelope_path = output / "providers" / name
        _write_json(envelope_path, observation["signed_envelope"])
        provider_files.append(
            {
                "provider_id": observation["provider_id"],
                "path": f"providers/{name}",
                "envelope_digest": _digest(observation["signed_envelope"]),
                "attestation_key_id": observation["signed_envelope"]["attestation"]["key_id"],
            }
        )

    manifest = {
        "artifact_version": "onchaindiligence.agent-evidence.production-reference.p1.8.v1",
        "bundle_id": payload["bundle_id"],
        "bundle_path": "bundle.json",
        "trust_policy_path": "trust-policy.json",
        "provider_envelopes": provider_files,
        "graph": {
            "run_id": graph["run"]["id"],
            "evidence_ids": [record["id"] for record in graph["evidence"]],
            "policy_id": graph["policy"]["id"],
            "decision_id": graph["decision"]["id"],
            "execution_id": graph["execution"]["id"],
            "root_ids": payload["root_ids"],
        },
        "verification": {
            "genuine": report.state.value,
            "offline": True,
            "trust_is_caller_supplied": True,
        },
        "execution_boundary": {
            "status": "withheld-not-submitted",
            "external_transaction_occurred": False,
            "reason": (
                "The live wallet and SEC observations are independent and do not prove "
                "that the wallet belongs to the filer."
            ),
        },
        "source_signing_boundary": (
            "Provider observations were signed by a dedicated P1.8 managed-witness key "
            "through the production v2 attestation implementation, not by the unresolved "
            "live production key."
        ),
        "generated_at": capture["captured_at"],
    }
    for value in (portable, trust_file, manifest):
        _assert_public_safe(value)
    _write_json(output / "bundle.json", portable)
    _write_json(output / "trust-policy.json", trust_file)
    _write_json(output / "manifest.json", manifest)
    print(
        json.dumps(
            {
                "bundle_id": payload["bundle_id"],
                "state": report.state.value,
                "output": str(output),
            }
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    build(args.output.resolve())


if __name__ == "__main__":
    main()
