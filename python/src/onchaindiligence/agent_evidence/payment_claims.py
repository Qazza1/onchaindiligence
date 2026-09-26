"""Offline verification for portable platform-signed payment claims."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature

from .canonical import canonicalize, content_id, parse_timestamp
from .dsse import dsse_pae
from .errors import CanonicalizationError, ParseError, SchemaValidationError
from .models import VerificationState
from .schema import validate_document
from .trust import TrustPolicy, evaluate_key_lifecycle

SIGNED_PAYMENT_CLAIM_VERSION = "onchaindiligence.signed-claim.payment.v1"
SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE = "application/vnd.onchaindiligence.signed-claim.payment.v1+json"
PLATFORM_CLAIM_SIGNATURE_SCOPE = "PLATFORM_CLAIM_SIGNATURE"
_LIMITATION = (
    "Proves only that a key trusted for this issuer signed this exact claim; "
    "not settlement, authorization, delivery, safety or compliance."
)
_BASE64 = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")


@dataclass(frozen=True, slots=True)
class PaymentClaimVerificationResult:
    """Tri-state result for a portable payment-claim signature only."""

    state: VerificationState
    scope: str
    code: str
    message: str
    issuer: str | None = None
    key_id: str | None = None
    claim_id: str | None = None
    limitations: tuple[str, ...] = (_LIMITATION,)


def _result(
    state: VerificationState,
    code: str,
    message: str,
    *,
    issuer: str | None = None,
    key_id: str | None = None,
    claim_id: str | None = None,
) -> PaymentClaimVerificationResult:
    return PaymentClaimVerificationResult(
        state, PLATFORM_CLAIM_SIGNATURE_SCOPE, code, message, issuer, key_id, claim_id
    )


def _assert_https_origin(value: Any) -> None:
    if not isinstance(value, str):
        raise ParseError("issuer.id must be an exact HTTPS origin")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
        or value != f"https://{parsed.netloc}"
    ):
        raise ParseError("issuer.id must be an exact HTTPS origin")


def _decode_base64(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or _BASE64.fullmatch(value) is None:
        raise ParseError(f"{label} is not strict padded base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ParseError(f"{label} is not strict padded base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ParseError(f"{label} is not canonical padded base64")
    return decoded


def _validate_claim(value: Any) -> dict[str, Any]:
    validate_document("signed-claim-payment.v1.schema.json", value)
    if not isinstance(value, dict):
        raise ParseError("signed payment claim must be an object")
    _assert_https_origin(value["issuer"]["id"])
    parse_timestamp(value["issued_at"])
    return value


def verify_signed_payment_claim(
    envelope: Any,
    policy: TrustPolicy,
    *,
    expected_issuer: str | None = None,
) -> PaymentClaimVerificationResult:
    """Verify a DSSE v1 claim with explicit, caller-provided offline trust."""

    try:
        validate_document("dsse-envelope.schema.json", envelope)
    except SchemaValidationError as exc:
        return _result(VerificationState.INVALID, "schema-invalid", str(exc))
    if not isinstance(envelope, dict):
        return _result(VerificationState.INVALID, "schema-invalid", "claim envelope must be an object")
    if envelope["payloadType"] != SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE:
        return _result(
            VerificationState.INVALID, "payload-type-mismatch", "DSSE payloadType is not Signed Payment Claim v1"
        )
    signatures = envelope["signatures"]
    if len(signatures) != 1:
        return _result(
            VerificationState.INVALID,
            "signature-count-invalid",
            "Signed Payment Claim v1 requires exactly one signature",
        )
    try:
        payload = _decode_base64(envelope["payload"], "DSSE payload")
        parsed = json.loads(payload)
        claim = _validate_claim(parsed)
        if canonicalize(claim) != payload:
            return _result(
                VerificationState.INVALID, "payload-not-rfc8785", "DSSE payload is not RFC8785 canonical JSON"
            )
    except (UnicodeDecodeError, json.JSONDecodeError, ParseError, SchemaValidationError) as exc:
        return _result(VerificationState.INVALID, "payload-invalid", str(exc))
    key_id = signatures[0]["keyid"]
    fields = {"issuer": claim["issuer"]["id"], "claim_id": claim["claim_id"], "key_id": key_id}
    if expected_issuer is not None and claim["issuer"]["id"] != expected_issuer:
        return _result(
            VerificationState.INVALID,
            "issuer-mismatch",
            "claim issuer does not match the caller-pinned issuer",
            **fields,
        )
    core = {name: value for name, value in claim.items() if name != "claim_id"}
    try:
        recomputed_id = content_id(core)
    except CanonicalizationError as exc:
        return _result(VerificationState.INVALID, "claim-canonicalization", str(exc), **fields)
    if claim["claim_id"] != recomputed_id:
        return _result(
            VerificationState.INVALID,
            "claim-id-mismatch",
            "claim_id does not match RFC8785 canonical payload without claim_id",
            **fields,
        )
    key = policy.keys.get(key_id)
    if key is None:
        return _result(
            VerificationState.UNVERIFIABLE,
            "key-not-trusted",
            "signing key is absent from caller-supplied trust",
            **fields,
        )
    try:
        signature = _decode_base64(signatures[0]["sig"], "DSSE signature")
    except ParseError as exc:
        return _result(VerificationState.INVALID, "signature-encoding", str(exc), **fields)
    if len(signature) != 64:
        return _result(VerificationState.INVALID, "signature-invalid", "Ed25519 signature is not 64 bytes", **fields)
    try:
        key.public_key.verify(signature, dsse_pae(SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE, payload))
    except InvalidSignature:
        return _result(
            VerificationState.INVALID,
            "signature-invalid",
            "Ed25519 signature does not verify over Signed Payment Claim DSSE PAE bytes",
            **fields,
        )
    try:
        issued_at = parse_timestamp(claim["issued_at"])
    except ParseError as exc:
        return _result(VerificationState.INVALID, "issued-at-invalid", str(exc), **fields)
    state, code, message = evaluate_key_lifecycle(key, signed_at=issued_at, policy=policy)
    return _result(state, code, message, **fields)
