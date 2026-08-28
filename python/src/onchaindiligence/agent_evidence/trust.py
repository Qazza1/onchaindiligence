"""Explicit caller-supplied trust policy and key lifecycle evaluation."""

from __future__ import annotations

import base64
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from types import MappingProxyType
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import format_timestamp, parse_timestamp
from .errors import ParseError, SchemaValidationError, TrustPolicyError
from .models import JsonObject, VerificationState
from .schema import validate_document

_KEY_ID = re.compile(r"^ed25519-[A-Za-z0-9_-]{16}$")


def derive_key_id(public_key: Ed25519PublicKey) -> str:
    """Derive the required key ID from Ed25519 SPKI DER bytes."""

    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = base64.urlsafe_b64encode(sha256(der).digest()).decode("ascii").rstrip("=")
    return f"ed25519-{digest[:16]}"


def load_public_key_pem(value: str | bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key, rejecting every other algorithm."""

    raw = value.encode("utf-8") if isinstance(value, str) else value
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as exc:
        raise TrustPolicyError("public_key_pem is not a valid SubjectPublicKeyInfo PEM") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise TrustPolicyError("public_key_pem must contain an Ed25519 public key")
    return key


def create_key_record(
    public_key: Ed25519PublicKey,
    *,
    valid_from: str | datetime | None,
    status: str = "active",
    valid_until: str | datetime | None = None,
    status_changed_at: str | datetime | None = None,
    replacement_key_id: str | None = None,
    compromised_at: str | datetime | None = None,
    status_reason: str | None = None,
) -> JsonObject:
    """Create and validate a portable lifecycle record for a public key."""

    def timestamp(value: str | datetime | None) -> str | None:
        if isinstance(value, datetime):
            return format_timestamp(value)
        return value

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    changed = status_changed_at
    if changed is None and status == "active":
        changed = valid_from
    record: JsonObject = {
        "key_id": derive_key_id(public_key),
        "algorithm": "ed25519",
        "public_key_pem": pem,
        "status": status,
        "valid_from": timestamp(valid_from),
        "valid_until": timestamp(valid_until),
        "status_changed_at": timestamp(changed),
        "replacement_key_id": replacement_key_id,
        "compromised_at": timestamp(compromised_at),
    }
    if status_reason is not None:
        record["status_reason"] = status_reason
    return AttestationKey.from_record(record).to_record()


def _optional_timestamp(record: Mapping[str, Any], name: str) -> datetime | None:
    value = record.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TrustPolicyError(f"{name} must be an exact timestamp or null")
    try:
        return parse_timestamp(value)
    except ParseError as exc:
        raise TrustPolicyError(f"invalid key {name}: {exc}") from exc


@dataclass(frozen=True, slots=True)
class AttestationKey:
    """Validated caller-trusted Ed25519 lifecycle record."""

    key_id: str
    public_key: Ed25519PublicKey = field(repr=False, compare=False)
    public_key_pem: str
    status: str
    valid_from: datetime | None
    valid_until: datetime | None
    status_changed_at: datetime | None
    replacement_key_id: str | None = None
    compromised_at: datetime | None = None
    status_reason: str | None = None

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> AttestationKey:
        """Validate schema, SPKI identity, timestamps, and lifecycle coherence."""

        material = dict(record)
        try:
            validate_document("attestation-key.schema.json", material)
        except SchemaValidationError as exc:
            raise TrustPolicyError(str(exc)) from exc
        key_id = material.get("key_id")
        pem = material.get("public_key_pem")
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise TrustPolicyError("invalid Ed25519 key_id")
        if not isinstance(pem, str):
            raise TrustPolicyError("public_key_pem must be a string")
        public_key = load_public_key_pem(pem)
        derived = derive_key_id(public_key)
        if derived != key_id:
            raise TrustPolicyError(f"key_id does not match SPKI public key: expected {derived}")

        valid_from = _optional_timestamp(material, "valid_from")
        valid_until = _optional_timestamp(material, "valid_until")
        changed = _optional_timestamp(material, "status_changed_at")
        compromised = _optional_timestamp(material, "compromised_at")
        status = str(material["status"])
        if valid_from is not None and valid_until is not None and valid_until < valid_from:
            raise TrustPolicyError("valid_until precedes valid_from")
        if valid_from is not None and changed is not None and changed < valid_from:
            raise TrustPolicyError("status_changed_at precedes valid_from")
        if valid_from is not None and compromised is not None and compromised < valid_from:
            raise TrustPolicyError("compromised_at precedes valid_from")
        if status in {"revoked", "compromised"} and changed is None:
            raise TrustPolicyError(f"{status} key requires status_changed_at")
        replacement_key_id = material.get("replacement_key_id")
        if replacement_key_id == key_id:
            raise TrustPolicyError("a key cannot name itself as its replacement")

        return cls(
            key_id=key_id,
            public_key=public_key,
            public_key_pem=pem,
            status=status,
            valid_from=valid_from,
            valid_until=valid_until,
            status_changed_at=changed,
            replacement_key_id=replacement_key_id,
            compromised_at=compromised,
            status_reason=material.get("status_reason"),
        )

    def to_record(self) -> JsonObject:
        """Return the portable public record shape."""

        def timestamp(value: datetime | None) -> str | None:
            if value is None:
                return None
            return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        record: JsonObject = {
            "key_id": self.key_id,
            "algorithm": "ed25519",
            "public_key_pem": self.public_key_pem,
            "status": self.status,
            "valid_from": timestamp(self.valid_from),
            "valid_until": timestamp(self.valid_until),
            "status_changed_at": timestamp(self.status_changed_at),
            "replacement_key_id": self.replacement_key_id,
            "compromised_at": timestamp(self.compromised_at),
        }
        if self.status_reason is not None:
            record["status_reason"] = self.status_reason
        return record


@dataclass(frozen=True, slots=True)
class TrustPolicy:
    """All trust and freshness inputs used by the zero-network verifier."""

    keys: Mapping[str, AttestationKey] = field(default_factory=dict)
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    required_signature_key_ids: frozenset[str] = field(default_factory=frozenset)
    minimum_valid_signatures: int = 1
    max_future_skew: timedelta = timedelta(minutes=5)
    max_bundle_age: timedelta | None = None
    enforce_evidence_expiration: bool = True
    allow_digest_only_evidence: bool = False
    require_verified_anchor: bool = False
    max_file_size: int = 10 * 1024 * 1024
    max_depth: int = 64
    max_string_length: int = 1024 * 1024
    max_array_length: int = 10_000

    def __post_init__(self) -> None:
        if self.now.tzinfo is None:
            raise TrustPolicyError("policy now must be timezone-aware")
        if self.minimum_valid_signatures < 1:
            raise TrustPolicyError("minimum_valid_signatures must be at least one")
        if self.max_future_skew < timedelta(0):
            raise TrustPolicyError("max_future_skew cannot be negative")
        if self.max_bundle_age is not None and self.max_bundle_age < timedelta(0):
            raise TrustPolicyError("max_bundle_age cannot be negative")
        if min(self.max_file_size, self.max_depth, self.max_string_length, self.max_array_length) < 1:
            raise TrustPolicyError("parser limits must be positive")
        copied = dict(self.keys)
        for key_id, key in copied.items():
            if key_id != key.key_id:
                raise TrustPolicyError("trust mapping key does not match key record")
        object.__setattr__(self, "keys", MappingProxyType(copied))
        object.__setattr__(self, "now", self.now.astimezone(timezone.utc))
        missing_required = self.required_signature_key_ids - copied.keys()
        if missing_required:
            raise TrustPolicyError(
                "required signature keys are absent from caller trust: " + ", ".join(sorted(missing_required))
            )

    @classmethod
    def from_key_records(
        cls,
        records: Iterable[Mapping[str, Any]],
        **options: Any,
    ) -> TrustPolicy:
        """Build an explicit trust policy; embedded bundle keys are never consulted."""

        keys: dict[str, AttestationKey] = {}
        for raw in records:
            key = AttestationKey.from_record(raw)
            if key.key_id in keys:
                raise TrustPolicyError(f"duplicate caller-trusted key: {key.key_id}")
            keys[key.key_id] = key
        for key in keys.values():
            if key.replacement_key_id is not None and key.replacement_key_id not in keys:
                raise TrustPolicyError(
                    f"key {key.key_id} references an absent replacement key: {key.replacement_key_id}"
                )
        return cls(keys=keys, **options)


def evaluate_key_lifecycle(
    key: AttestationKey,
    *,
    signed_at: datetime | None,
    policy: TrustPolicy,
) -> tuple[VerificationState, str, str]:
    """Evaluate status/window without treating asserted time as external time proof."""

    if key.status == "revoked":
        return VerificationState.INVALID, "key-revoked", "the caller-trusted key is revoked"
    if key.status == "compromised":
        return VerificationState.INVALID, "key-compromised", "the caller-trusted key is compromised"
    if key.valid_from is None:
        return (
            VerificationState.UNVERIFIABLE,
            "key-valid-from-missing",
            "the caller-trusted key has no defensible activation boundary",
        )
    if signed_at is None:
        if key.status == "retired":
            return (
                VerificationState.UNVERIFIABLE,
                "signature-time-missing",
                "a retired key cannot validate a proof that carries no signed issuance time",
            )
        if policy.now < key.valid_from:
            return (
                VerificationState.INVALID,
                "key-not-yet-valid",
                "the key is not active at policy time",
            )
        return VerificationState.VALID, "key-active", "the caller-trusted key is currently active"
    if signed_at > policy.now + policy.max_future_skew:
        return (
            VerificationState.INVALID,
            "signature-time-future",
            "signed time exceeds allowed clock skew",
        )
    if signed_at < key.valid_from:
        return VerificationState.INVALID, "key-not-yet-valid", "signed time precedes key activation"
    if key.valid_until is not None and signed_at > key.valid_until:
        return (
            VerificationState.INVALID,
            "key-expired",
            "signed time follows the key validity interval",
        )
    return (
        VerificationState.VALID,
        "key-window-valid",
        "signed time is inside the key validity interval",
    )
