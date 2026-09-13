"""Dedicated Public Action Receipt v1 verification for offline bundle consumers."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature

from .canonical import canonicalize, content_id, parse_timestamp
from .constants import ATTESTATION_ISSUER, ATTESTATION_V2
from .errors import CanonicalizationError, ParseError, SchemaValidationError
from .models import JsonObject, VerificationState
from .schema import validate_document
from .trust import TrustPolicy, evaluate_key_lifecycle

PUBLIC_ACTION_RECEIPT_SCHEMA = "onchaindiligence.public-action-receipt.v1"
PUBLIC_ACTION_RECEIPT_PURPOSE = "public-action-receipt"
PUBLIC_ACTION_RECEIPT_ISSUER = ATTESTATION_ISSUER
_DIGEST = re.compile(r"^sha256:([A-Za-z0-9_-]{43})$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


@dataclass(frozen=True, slots=True)
class ReceiptVerificationResult:
    state: VerificationState
    code: str
    message: str
    key_id: str | None = None


def _invalid(code: str, message: str) -> ReceiptVerificationResult:
    return ReceiptVerificationResult(VerificationState.INVALID, code, message)


def _format_receipt_id(receipt_digest: str) -> str:
    match = _DIGEST.fullmatch(receipt_digest)
    if match is None:
        raise CanonicalizationError("receipt digest is not a valid sha256 content id")
    try:
        raw = base64.urlsafe_b64decode(match.group(1) + "=")
    except (binascii.Error, ValueError) as exc:
        raise CanonicalizationError("receipt digest is not valid base64url") from exc
    if len(raw) != 32:
        raise CanonicalizationError("receipt digest is not 32 bytes")
    bits = 0
    value = 0
    encoded = ""
    for byte in raw[:10]:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            encoded += _CROCKFORD[(value >> bits) & 0x1F]
    return "OCD-RCP-" + "-".join(encoded[index : index + 4] for index in range(0, 16, 4))


def verify_receipt_envelope(
    envelope: Any,
    policy: TrustPolicy,
    *,
    expected_issuer: str = PUBLIC_ACTION_RECEIPT_ISSUER,
    expected_purpose: str = PUBLIC_ACTION_RECEIPT_PURPOSE,
) -> ReceiptVerificationResult:
    """Verify the complete receipt contract, not merely its generic attestation."""

    try:
        validate_document("public-action-receipt.schema.json", envelope)
    except SchemaValidationError as exc:
        return _invalid("schema-invalid", str(exc))
    if not isinstance(envelope, dict):
        return _invalid("schema-invalid", "receipt envelope must be an object")
    receipt = envelope["receipt"]
    proof = envelope["proof"]
    core = {key: value for key, value in receipt.items() if key not in {"receipt_id", "receipt_digest"}}
    try:
        recomputed_digest = content_id(core)
        recomputed_id = _format_receipt_id(recomputed_digest)
    except CanonicalizationError as exc:
        return _invalid("receipt-canonicalization", str(exc))
    if recomputed_digest != receipt["receipt_digest"]:
        return _invalid("digest-mismatch", "receipt_digest does not match a fresh digest of the receipt content")
    if recomputed_id != receipt["receipt_id"]:
        return _invalid("id-mismatch", "receipt_id does not match formatReceiptId(receipt_digest)")
    key_id = proof["key_id"]
    if proof["issuer"] != expected_issuer:
        return _invalid("issuer-mismatch", "receipt proof issuer is not the expected issuer")
    if proof["purpose"] != expected_purpose:
        return _invalid("purpose-mismatch", "receipt proof purpose is not public-action-receipt")
    if proof["schema_version"] != ATTESTATION_V2:
        return _invalid("schema-version-mismatch", "receipt proof is not an attestation v2 proof")
    key = policy.keys.get(key_id)
    if key is None:
        return ReceiptVerificationResult(
            VerificationState.UNVERIFIABLE,
            "key-not-trusted",
            "attestation key is absent from caller-supplied trust",
            key_id,
        )
    try:
        issued_at = parse_timestamp(proof["issued_at"])
        signature_text = proof["signature"]
        if not isinstance(signature_text, str) or _SIGNATURE.fullmatch(signature_text) is None:
            raise ParseError("attestation signature must be 86-character unpadded base64url")
        signature = base64.urlsafe_b64decode(signature_text + "==")
    except (ParseError, binascii.Error, ValueError) as exc:
        return ReceiptVerificationResult(VerificationState.INVALID, "attestation-encoding", str(exc), key_id)
    signed_input: JsonObject = {
        "schema_version": ATTESTATION_V2,
        "issuer": proof["issuer"],
        "purpose": proof["purpose"],
        "data": receipt,
        "issued_at": proof["issued_at"],
        "key_id": key_id,
    }
    try:
        key.public_key.verify(signature, canonicalize(signed_input))
    except InvalidSignature:
        return ReceiptVerificationResult(
            VerificationState.INVALID,
            "signature-invalid",
            "attestation signature does not verify",
            key_id,
        )
    state, code, message = evaluate_key_lifecycle(key, signed_at=issued_at, policy=policy)
    return ReceiptVerificationResult(state, code, message, key_id)
