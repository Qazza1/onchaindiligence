"""DSSE v1 Ed25519 sealing helpers."""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonicalize, parse_json
from .constants import BUNDLE_PAYLOAD_TYPE, BUNDLE_VERSION, MEDIA_TYPE
from .errors import SchemaValidationError, SigningError
from .graph import validate_bundle_payload
from .models import JsonObject
from .schema import validate_document
from .trust import derive_key_id


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Construct DSSE v1 Pre-Authentication Encoding bytes."""

    type_bytes = payload_type.encode("utf-8")
    return b"".join(
        (
            b"DSSEv1 ",
            str(len(type_bytes)).encode("ascii"),
            b" ",
            type_bytes,
            b" ",
            str(len(payload)).encode("ascii"),
            b" ",
            payload,
        )
    )


def load_private_key_pem(value: str | bytes, password: bytes | None = None) -> Ed25519PrivateKey:
    """Load a PKCS8 Ed25519 private key without reading files or configuration."""

    raw = value.encode("utf-8") if isinstance(value, str) else value
    try:
        key = serialization.load_pem_private_key(raw, password=password)
    except (TypeError, ValueError) as exc:
        raise SigningError("private key is not a valid PKCS8 PEM") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError("private key must be Ed25519")
    return key


def seal_bundle(
    payload: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    key_id: str | None = None,
    keys: Sequence[Mapping[str, Any]] = (),
    registry_snapshots: Sequence[Mapping[str, Any]] = (),
    anchors: Sequence[Mapping[str, Any]] = (),
) -> JsonObject:
    """Seal a valid payload into the portable v0 file without network access."""

    authoritative = dict(payload)
    validate_bundle_payload(authoritative)
    expected_key_id = derive_key_id(private_key.public_key())
    if key_id is not None and key_id != expected_key_id:
        raise SigningError(f"key_id does not match private key; expected {expected_key_id}")
    payload_bytes = canonicalize(authoritative)
    signature = private_key.sign(dsse_pae(BUNDLE_PAYLOAD_TYPE, payload_bytes))
    portable: JsonObject = {
        "media_type": MEDIA_TYPE,
        "bundle_version": BUNDLE_VERSION,
        "envelope": {
            "payloadType": BUNDLE_PAYLOAD_TYPE,
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "signatures": [
                {
                    "keyid": expected_key_id,
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        },
        "verification_material": {
            "keys": parse_json(canonicalize(list(keys))),
            "registry_snapshots": parse_json(canonicalize(list(registry_snapshots))),
            "anchors": parse_json(canonicalize(list(anchors))),
        },
    }
    try:
        validate_document("portable-file.schema.json", portable)
    except SchemaValidationError as exc:
        raise SigningError(str(exc)) from exc
    return portable
