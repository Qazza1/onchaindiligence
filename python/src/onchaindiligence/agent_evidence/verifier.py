"""Fully offline Agent Evidence v0 tri-state verification."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature

from .canonical import canonicalize, enforce_limits, parse_json, parse_timestamp
from .constants import (
    ATTESTATION_ISSUER,
    ATTESTATION_PURPOSE,
    ATTESTATION_V2,
    BUNDLE_PAYLOAD_TYPE,
    BUNDLE_VERSION,
    MEDIA_TYPE,
)
from .dsse import dsse_pae
from .errors import (
    CanonicalizationError,
    EvidenceValidationError,
    ParseError,
    SchemaValidationError,
)
from .graph import validate_bundle_payload
from .models import (
    ComponentResult,
    JsonObject,
    VerificationReport,
    VerificationState,
    overall_state,
)
from .schema import validate_document
from .trust import AttestationKey, TrustPolicy, evaluate_key_lifecycle

_BASE64URL_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")


def _result(
    component: str,
    state: VerificationState,
    code: str,
    message: str,
    *,
    key_id: str | None = None,
    record_id: str | None = None,
    required: bool = True,
) -> ComponentResult:
    return ComponentResult(component, state, code, message, key_id, record_id, required)


def _report(
    components: list[ComponentResult],
    *,
    payload: JsonObject | None = None,
) -> VerificationReport:
    return VerificationReport(
        state=overall_state(components),
        components=tuple(components),
        bundle_id=payload.get("bundle_id") if payload is not None else None,
        payload=payload,
    )


def _decode_base64(value: str, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ParseError(f"{label} is not strict padded base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ParseError(f"{label} is not canonical padded base64")
    return decoded


def _decode_base64url_signature(value: str) -> bytes:
    if not _BASE64URL_SIGNATURE.fullmatch(value):
        raise ParseError("attestation signature must be 86-character unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "==")
    except (binascii.Error, ValueError) as exc:
        raise ParseError("attestation signature is not valid base64url") from exc
    if len(decoded) != 64:
        raise ParseError("Ed25519 signature must contain 64 bytes")
    return decoded


def _strict_input(document: str | bytes | Mapping[str, Any], policy: TrustPolicy) -> JsonObject:
    if isinstance(document, bytes):
        if len(document) > policy.max_file_size:
            raise ParseError(f"portable file exceeds maximum size {policy.max_file_size}")
        value = parse_json(document)
    elif isinstance(document, str):
        encoded = document.encode("utf-8")
        if len(encoded) > policy.max_file_size:
            raise ParseError(f"portable file exceeds maximum size {policy.max_file_size}")
        value = parse_json(document)
    else:
        value = parse_json(canonicalize(dict(document)))
    if not isinstance(value, dict):
        raise ParseError("portable file must be a JSON object")
    enforce_limits(
        value,
        max_depth=policy.max_depth,
        max_string_length=policy.max_string_length,
        max_array_length=policy.max_array_length,
    )
    return value


def _verify_ed25519_signature(
    key: AttestationKey,
    signature: bytes,
    message: bytes,
) -> bool:
    try:
        key.public_key.verify(signature, message)
    except InvalidSignature:
        return False
    return True


def _verify_signature_set(
    envelope: Mapping[str, Any],
    payload_bytes: bytes,
    policy: TrustPolicy,
    *,
    signed_at: datetime | None,
    component_prefix: str,
    record_id: str | None = None,
) -> list[ComponentResult]:
    components: list[ComponentResult] = []
    signatures = envelope["signatures"]
    valid_count = 0
    seen_key_ids: set[str] = set()
    for signature in signatures:
        key_id = signature["keyid"]
        if key_id in seen_key_ids:
            components.append(
                _result(
                    component_prefix,
                    VerificationState.INVALID,
                    "duplicate-signature-key",
                    "a DSSE signature set may contain each key ID at most once",
                    key_id=key_id,
                    record_id=record_id,
                )
            )
            continue
        seen_key_ids.add(key_id)
        key = policy.keys.get(key_id)
        if key is None:
            components.append(
                _result(
                    component_prefix,
                    VerificationState.UNVERIFIABLE,
                    "key-not-trusted",
                    "signature key is absent from caller-supplied trust",
                    key_id=key_id,
                    record_id=record_id,
                )
            )
            continue
        try:
            signature_bytes = _decode_base64(signature["sig"], "DSSE signature")
        except ParseError as exc:
            components.append(
                _result(
                    component_prefix,
                    VerificationState.INVALID,
                    "signature-encoding",
                    str(exc),
                    key_id=key_id,
                    record_id=record_id,
                )
            )
            continue
        if len(signature_bytes) != 64 or not _verify_ed25519_signature(
            key,
            signature_bytes,
            dsse_pae(str(envelope["payloadType"]), payload_bytes),
        ):
            components.append(
                _result(
                    component_prefix,
                    VerificationState.INVALID,
                    "signature-invalid",
                    "Ed25519 signature does not verify over the exact DSSE PAE bytes",
                    key_id=key_id,
                    record_id=record_id,
                )
            )
            continue
        state, code, message = evaluate_key_lifecycle(key, signed_at=signed_at, policy=policy)
        components.append(
            _result(
                component_prefix,
                state,
                code,
                message,
                key_id=key_id,
                record_id=record_id,
            )
        )
        if state is VerificationState.VALID:
            valid_count += 1

    if valid_count < 1:
        components.append(
            _result(
                component_prefix,
                VerificationState.UNVERIFIABLE,
                "signature-threshold-not-met",
                f"required one valid caller-trusted source signature, got {valid_count}",
                record_id=record_id,
            )
        )
    return components


def _javascript_stringify(value: Any) -> bytes:
    """Serialize v1 values with JCS primitive encoding but insertion-order objects."""

    if isinstance(value, dict):
        members = []
        for key, item in value.items():
            members.append(canonicalize(str(key)) + b":" + _javascript_stringify(item))
        return b"{" + b",".join(members) + b"}"
    if isinstance(value, list):
        return b"[" + b",".join(_javascript_stringify(item) for item in value) + b"]"
    return canonicalize(value)


def _verify_attestation_proof(
    proof: Mapping[str, Any],
    policy: TrustPolicy,
    record_id: str,
) -> ComponentResult:
    proof_type = proof["proof_type"]
    envelope = proof["envelope"]
    attestation = envelope["attestation"]
    key_id = attestation["key_id"]
    key = policy.keys.get(key_id)
    if key is None:
        return _result(
            "source-proof",
            VerificationState.UNVERIFIABLE,
            "key-not-trusted",
            "attestation key is absent from caller-supplied trust",
            key_id=key_id,
            record_id=record_id,
        )
    try:
        issued_at = parse_timestamp(attestation["issued_at"])
        signature = _decode_base64url_signature(attestation["signature"])
    except ParseError as exc:
        return _result(
            "source-proof",
            VerificationState.INVALID,
            "attestation-encoding",
            str(exc),
            key_id=key_id,
            record_id=record_id,
        )

    if proof_type == "onchaindiligence-attestation-v2":
        if attestation["issuer"] != ATTESTATION_ISSUER:
            return _result(
                "source-proof",
                VerificationState.INVALID,
                "attestation-issuer",
                "v2 attestation issuer is not the exact OnChainDiligence issuer",
                key_id=key_id,
                record_id=record_id,
            )
        if attestation["purpose"] != ATTESTATION_PURPOSE:
            return _result(
                "source-proof",
                VerificationState.INVALID,
                "attestation-purpose",
                "v2 attestation purpose is not a compliance result",
                key_id=key_id,
                record_id=record_id,
            )
        signed_input = {
            "schema_version": ATTESTATION_V2,
            "issuer": attestation["issuer"],
            "purpose": attestation["purpose"],
            "data": envelope["data"],
            "issued_at": attestation["issued_at"],
            "key_id": key_id,
        }
        message = canonicalize(signed_input)
    else:
        signed_input = {
            "data": envelope["data"],
            "issued_at": attestation["issued_at"],
            "key_id": key_id,
        }
        message = _javascript_stringify(signed_input)

    if not _verify_ed25519_signature(key, signature, message):
        code = "legacy-signature-unverifiable" if proof_type.endswith("-v1") else "signature-invalid"
        state = VerificationState.UNVERIFIABLE if proof_type.endswith("-v1") else VerificationState.INVALID
        detail = (
            "v1 signature did not verify from the object order representable in the canonical bundle"
            if state is VerificationState.UNVERIFIABLE
            else "attestation signature does not verify"
        )
        return _result("source-proof", state, code, detail, key_id=key_id, record_id=record_id)
    state, code, message_text = evaluate_key_lifecycle(key, signed_at=issued_at, policy=policy)
    return _result(
        "source-proof",
        state,
        code,
        message_text,
        key_id=key_id,
        record_id=record_id,
    )


def _verify_record_proofs(
    payload: JsonObject,
    policy: TrustPolicy,
) -> list[ComponentResult]:
    components: list[ComponentResult] = []
    for record in payload["records"]:
        record_id = record["id"]
        for proof in record["proofs"]:
            proof_type = proof["proof_type"]
            if proof_type == "external-digest":
                components.append(
                    _result(
                        "source-proof",
                        VerificationState.VALID,
                        "external-digest-bound",
                        "digest is bound by the record ID but does not establish source attribution",
                        record_id=record_id,
                    )
                )
            elif proof_type in {
                "onchaindiligence-attestation-v1",
                "onchaindiligence-attestation-v2",
            }:
                response = record["statement"].get("response")
                source = record["statement"].get("source")
                if not isinstance(source, dict) or source.get("id") != ATTESTATION_ISSUER:
                    components.append(
                        _result(
                            "source-proof",
                            VerificationState.INVALID,
                            "attestation-source-mismatch",
                            "OnChainDiligence attestation proof requires the exact OnChainDiligence source ID",
                            record_id=record_id,
                        )
                    )
                    continue
                if (
                    record["kind"] != "evidence"
                    or not isinstance(response, dict)
                    or response.get("mode") != "embedded"
                    or response.get("value") != proof["envelope"]
                ):
                    components.append(
                        _result(
                            "source-proof",
                            VerificationState.INVALID,
                            "attestation-response-mismatch",
                            "attestation proof must exactly equal the embedded evidence response",
                            record_id=record_id,
                        )
                    )
                    continue
                components.append(_verify_attestation_proof(proof, policy, record_id))
            elif proof_type == "dsse-ed25519-v1":
                envelope = proof["envelope"]
                try:
                    proof_bytes = _decode_base64(envelope["payload"], "source DSSE payload")
                except ParseError as exc:
                    components.append(
                        _result(
                            "source-proof",
                            VerificationState.INVALID,
                            "proof-payload-encoding",
                            str(exc),
                            record_id=record_id,
                        )
                    )
                    continue
                if envelope["payloadType"] != proof["statement_media_type"]:
                    components.append(
                        _result(
                            "source-proof",
                            VerificationState.INVALID,
                            "proof-payload-type",
                            "source DSSE payloadType does not equal statement_media_type",
                            record_id=record_id,
                        )
                    )
                    continue
                expected = canonicalize(record["statement"])
                if proof_bytes != expected:
                    components.append(
                        _result(
                            "source-proof",
                            VerificationState.INVALID,
                            "proof-statement-mismatch",
                            "source DSSE payload is not the canonical record statement",
                            record_id=record_id,
                        )
                    )
                    continue
                components.extend(
                    _verify_signature_set(
                        envelope,
                        proof_bytes,
                        policy,
                        signed_at=None,
                        component_prefix="source-proof",
                        record_id=record_id,
                    )
                )
    return components


def _verify_evidence_semantics(
    payload: JsonObject,
    proof_components: list[ComponentResult],
    policy: TrustPolicy,
) -> list[ComponentResult]:
    components: list[ComponentResult] = []
    cryptographic_types = {
        "dsse-ed25519-v1",
        "onchaindiligence-attestation-v1",
        "onchaindiligence-attestation-v2",
    }
    for record in payload["records"]:
        if record["kind"] != "evidence":
            continue
        record_id = record["id"]
        statement = record["statement"]
        trust_mode = statement["trust_mode"]
        response = statement["response"]
        if response["mode"] == "reference":
            state = VerificationState.VALID if policy.allow_digest_only_evidence else VerificationState.UNVERIFIABLE
            code = "digest-only-allowed" if policy.allow_digest_only_evidence else "evidence-content-unavailable"
            message = (
                "caller policy permits digest-only evidence"
                if policy.allow_digest_only_evidence
                else "offline verifier cannot resolve referenced evidence required by default policy"
            )
            components.append(_result("evidence-content", state, code, message, record_id=record_id))
        else:
            components.append(
                _result(
                    "evidence-content",
                    VerificationState.VALID,
                    "evidence-embedded",
                    "evidence response is embedded and its digest matches",
                    record_id=record_id,
                )
            )

        if trust_mode == "agent-assertion":
            components.append(
                _result(
                    "trust-mode",
                    VerificationState.VALID,
                    "agent-assertion",
                    "statement is explicitly limited to an agent assertion",
                    record_id=record_id,
                )
            )
            continue
        crypto_proofs = [proof for proof in record["proofs"] if proof["proof_type"] in cryptographic_types]
        if not crypto_proofs:
            components.append(
                _result(
                    "trust-mode",
                    VerificationState.INVALID,
                    "cryptographic-proof-missing",
                    f"{trust_mode} requires a cryptographic source proof",
                    record_id=record_id,
                )
            )
            continue
        relevant = [
            item for item in proof_components if item.record_id == record_id and item.code != "external-digest-bound"
        ]
        if any(item.state is VerificationState.INVALID for item in relevant):
            state = VerificationState.INVALID
            code = "trust-proof-invalid"
        elif any(item.state is VerificationState.UNVERIFIABLE for item in relevant):
            state = VerificationState.UNVERIFIABLE
            code = "trust-proof-unverifiable"
        else:
            state = VerificationState.VALID
            code = "trust-proof-valid"
        components.append(
            _result(
                "trust-mode",
                state,
                code,
                f"{trust_mode} is reported exactly and backed by the source-proof result",
                record_id=record_id,
            )
        )
    return components


def _verification_material_components(portable: JsonObject, policy: TrustPolicy) -> list[ComponentResult]:
    components: list[ComponentResult] = []
    material = portable["verification_material"]
    if material["keys"]:
        components.append(
            _result(
                "verification-material",
                VerificationState.UNVERIFIABLE,
                "embedded-keys-untrusted",
                "embedded public keys are verification hints, never caller trust",
                required=False,
            )
        )
    for _snapshot in material["registry_snapshots"]:
        components.append(
            _result(
                "registry-snapshot",
                VerificationState.UNVERIFIABLE,
                "snapshot-format-unsupported",
                "registry snapshot is preserved but not trusted or verified by v0 core",
                required=False,
            )
        )
    if policy.require_verified_anchor and not material["anchors"]:
        components.append(
            _result(
                "anchor",
                VerificationState.UNVERIFIABLE,
                "anchor-required-missing",
                "caller policy requires an independently verified anchor",
            )
        )
    for _anchor in material["anchors"]:
        components.append(
            _result(
                "anchor",
                VerificationState.UNVERIFIABLE,
                "anchor-format-unsupported",
                "anchor is preserved but no v0 core anchor format is verified",
                required=policy.require_verified_anchor,
            )
        )
    return components


def _verify_freshness(payload: JsonObject, policy: TrustPolicy) -> list[ComponentResult]:
    components: list[ComponentResult] = []
    try:
        created_at = parse_timestamp(payload["created_at"])
    except ParseError as exc:
        return [_result("freshness", VerificationState.INVALID, "timestamp-invalid", str(exc))]
    if created_at > policy.now + policy.max_future_skew:
        components.append(
            _result(
                "freshness",
                VerificationState.INVALID,
                "bundle-time-future",
                "bundle created_at exceeds allowed clock skew",
            )
        )
    elif policy.max_bundle_age is not None and policy.now - created_at > policy.max_bundle_age:
        components.append(
            _result(
                "freshness",
                VerificationState.INVALID,
                "bundle-stale",
                "bundle exceeds caller-supplied maximum age",
            )
        )
    else:
        components.append(
            _result(
                "freshness",
                VerificationState.VALID,
                "bundle-freshness-valid",
                "bundle satisfies caller-supplied time policy",
            )
        )

    asserted_fields = {
        "evidence": ("observed_at",),
        "decision": ("decided_at",),
        "execution": ("submitted_at", "confirmed_at"),
        "run": ("started_at", "ended_at"),
    }
    for record in payload["records"]:
        statement = record["statement"]
        for name in asserted_fields.get(record["kind"], ()):
            raw = statement.get(name)
            if raw is not None and parse_timestamp(raw) > policy.now + policy.max_future_skew:
                components.append(
                    _result(
                        "freshness",
                        VerificationState.INVALID,
                        "asserted-time-future",
                        f"{record['kind']}.{name} exceeds allowed clock skew",
                        record_id=record["id"],
                    )
                )
        if (
            policy.enforce_evidence_expiration
            and record["kind"] == "evidence"
            and statement["expires_at"] is not None
            and policy.now > parse_timestamp(statement["expires_at"])
        ):
            components.append(
                _result(
                    "freshness",
                    VerificationState.INVALID,
                    "evidence-expired",
                    "evidence expires_at is before policy time",
                    record_id=record["id"],
                )
            )
    return components


def verify_bundle(
    document: str | bytes | Mapping[str, Any],
    policy: TrustPolicy,
) -> VerificationReport:
    """Verify a portable Agent Evidence file with no network or ambient trust."""

    components: list[ComponentResult] = []
    try:
        portable = _strict_input(document, policy)
    except (ParseError, CanonicalizationError) as exc:
        return _report([_result("outer", VerificationState.INVALID, "json-invalid", str(exc))])
    try:
        validate_document("portable-file.schema.json", portable)
    except SchemaValidationError as exc:
        return _report([_result("outer", VerificationState.INVALID, "schema-invalid", str(exc))])
    if portable["media_type"] != MEDIA_TYPE or portable["bundle_version"] != BUNDLE_VERSION:
        return _report(
            [
                _result(
                    "outer",
                    VerificationState.INVALID,
                    "version-unsupported",
                    "unsupported outer format",
                )
            ]
        )
    components.append(
        _result(
            "outer",
            VerificationState.VALID,
            "outer-valid",
            "portable file schema and version are valid",
        )
    )
    components.extend(_verification_material_components(portable, policy))

    envelope = portable["envelope"]
    if envelope["payloadType"] != BUNDLE_PAYLOAD_TYPE:
        components.append(
            _result(
                "payload",
                VerificationState.INVALID,
                "payload-type-unsupported",
                "unsupported DSSE payload type",
            )
        )
        return _report(components)
    try:
        payload_bytes = _decode_base64(envelope["payload"], "DSSE payload")
    except ParseError as exc:
        components.append(_result("payload", VerificationState.INVALID, "payload-encoding", str(exc)))
        return _report(components)

    # Cryptographic verification precedes parsing the signed payload. Lifecycle
    # checks follow parsing because the authoritative created_at is inside it.
    cryptographic: list[tuple[AttestationKey, str]] = []
    signature_failure = False
    seen_key_ids: set[str] = set()
    for signature in envelope["signatures"]:
        key_id = signature["keyid"]
        if key_id in seen_key_ids:
            components.append(
                _result(
                    "bundle-signature",
                    VerificationState.INVALID,
                    "duplicate-signature-key",
                    "a DSSE signature set may contain each key ID at most once",
                    key_id=key_id,
                )
            )
            signature_failure = True
            continue
        seen_key_ids.add(key_id)
        key = policy.keys.get(key_id)
        if key is None:
            components.append(
                _result(
                    "bundle-signature",
                    VerificationState.UNVERIFIABLE,
                    "key-not-trusted",
                    "bundle key is absent from caller-supplied trust; embedded keys are hints only",
                    key_id=key_id,
                )
            )
            continue
        try:
            signature_bytes = _decode_base64(signature["sig"], "DSSE signature")
        except ParseError as exc:
            components.append(
                _result(
                    "bundle-signature",
                    VerificationState.INVALID,
                    "signature-encoding",
                    str(exc),
                    key_id=key_id,
                )
            )
            signature_failure = True
            continue
        if len(signature_bytes) != 64 or not _verify_ed25519_signature(
            key,
            signature_bytes,
            dsse_pae(BUNDLE_PAYLOAD_TYPE, payload_bytes),
        ):
            components.append(
                _result(
                    "bundle-signature",
                    VerificationState.INVALID,
                    "signature-invalid",
                    "bundle signature does not verify over the exact DSSE PAE bytes",
                    key_id=key_id,
                )
            )
            signature_failure = True
            continue
        cryptographic.append((key, key_id))
    if signature_failure:
        return _report(components)
    if not cryptographic:
        components.append(
            _result(
                "bundle-signature",
                VerificationState.UNVERIFIABLE,
                "signature-threshold-not-met",
                "no bundle signature uses a caller-trusted key",
            )
        )
        return _report(components)

    try:
        parsed_payload = parse_json(payload_bytes)
        if not isinstance(parsed_payload, dict):
            raise ParseError("signed payload must be a JSON object")
        enforce_limits(
            parsed_payload,
            max_depth=policy.max_depth,
            max_string_length=policy.max_string_length,
            max_array_length=policy.max_array_length,
        )
        payload: JsonObject = parsed_payload
        validate_document("bundle-payload.schema.json", payload)
    except (ParseError, SchemaValidationError) as exc:
        components.append(_result("payload", VerificationState.INVALID, "payload-invalid", str(exc)))
        return _report(components)
    try:
        if canonicalize(payload) != payload_bytes:
            components.append(
                _result(
                    "payload",
                    VerificationState.INVALID,
                    "payload-not-rfc8785",
                    "signed payload bytes are not their RFC 8785 representation",
                )
            )
            return _report(components, payload=payload)
    except CanonicalizationError as exc:
        components.append(_result("payload", VerificationState.INVALID, "payload-not-ijson", str(exc)))
        return _report(components, payload=payload)
    if payload["bundle_version"] != BUNDLE_VERSION or portable["bundle_version"] != payload["bundle_version"]:
        components.append(
            _result(
                "payload",
                VerificationState.INVALID,
                "outer-inner-version-mismatch",
                "authoritative and routing versions do not match",
            )
        )
        return _report(components, payload=payload)
    components.append(
        _result(
            "payload",
            VerificationState.VALID,
            "payload-valid",
            "signed payload is canonical v0 JSON",
        )
    )

    created_at = parse_timestamp(payload["created_at"])
    valid_lifecycle_count = 0
    for key, key_id in cryptographic:
        state, code, message = evaluate_key_lifecycle(key, signed_at=created_at, policy=policy)
        components.append(_result("bundle-signature", state, code, message, key_id=key_id))
        if state is VerificationState.VALID:
            valid_lifecycle_count += 1
    presented_ids = {signature["keyid"] for signature in envelope["signatures"]}
    for required in sorted(policy.required_signature_key_ids - presented_ids):
        components.append(
            _result(
                "bundle-signature",
                VerificationState.UNVERIFIABLE,
                "required-signature-missing",
                "a caller-required bundle signature is not present",
                key_id=required,
            )
        )
    if valid_lifecycle_count < policy.minimum_valid_signatures:
        components.append(
            _result(
                "bundle-signature",
                VerificationState.UNVERIFIABLE,
                "signature-threshold-not-met",
                f"required {policy.minimum_valid_signatures} valid signature(s), got {valid_lifecycle_count}",
            )
        )

    try:
        validate_bundle_payload(payload)
    except EvidenceValidationError as exc:
        components.append(_result("graph", VerificationState.INVALID, "graph-invalid", str(exc)))
        return _report(components, payload=payload)
    components.append(
        _result(
            "graph",
            VerificationState.VALID,
            "graph-valid",
            "IDs, roots, DAG, references, and kind rules are valid",
        )
    )
    proof_components = _verify_record_proofs(payload, policy)
    components.extend(proof_components)
    components.extend(_verify_evidence_semantics(payload, proof_components, policy))
    components.extend(_verify_freshness(payload, policy))
    return _report(components, payload=payload)
