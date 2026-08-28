"""Deterministic record and bundle construction."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any

from .canonical import canonicalize, content_id, format_timestamp, parse_json
from .constants import BUNDLE_VERSION, RECORD_VERSION
from .errors import EvidenceValidationError, SchemaValidationError
from .graph import validate_bundle_payload
from .models import JsonObject
from .schema import validate_document


def _clone(value: Any) -> Any:
    return parse_json(canonicalize(value))


def create_record(
    kind: str,
    statement: Mapping[str, Any],
    *,
    parents: Sequence[str] = (),
    proofs: Sequence[Mapping[str, Any]] = (),
) -> JsonObject:
    """Create one schema-valid record whose ID binds every non-ID field."""

    body: JsonObject = {
        "record_version": RECORD_VERSION,
        "kind": kind,
        "parents": sorted(set(parents)),
        "statement": _clone(dict(statement)),
        "proofs": _clone([dict(proof) for proof in proofs]),
    }
    record: JsonObject = {"id": content_id(body), **body}
    try:
        validate_document("record.schema.json", record)
    except SchemaValidationError as exc:
        raise EvidenceValidationError(str(exc)) from exc
    return record


def create_bundle_payload(
    records: Iterable[Mapping[str, Any]],
    *,
    created_at: str | datetime,
    run_id: str | None = None,
    root_ids: Sequence[str] | None = None,
    extensions: Mapping[str, Any] | None = None,
) -> JsonObject:
    """Create and fully validate the authoritative signed payload."""

    copied = [_clone(dict(record)) for record in records]
    copied.sort(key=lambda record: str(record["id"]))
    runs = [record for record in copied if record.get("kind") == "run"]
    if run_id is None:
        if len(runs) != 1:
            raise EvidenceValidationError("run_id can only be inferred when exactly one run exists")
        run_id = str(runs[0]["id"])
    parent_ids = {parent for record in copied for parent in record.get("parents", [])}
    computed_roots = sorted(str(record["id"]) for record in copied if record["id"] not in parent_ids)
    timestamp = format_timestamp(created_at) if isinstance(created_at, datetime) else created_at
    without_id: JsonObject = {
        "bundle_version": BUNDLE_VERSION,
        "created_at": timestamp,
        "run_id": run_id,
        "root_ids": list(root_ids) if root_ids is not None else computed_roots,
        "records": copied,
        "extensions": _clone(dict(extensions or {})),
    }
    payload: JsonObject = {
        "bundle_version": BUNDLE_VERSION,
        "bundle_id": content_id(without_id),
        "created_at": timestamp,
        "run_id": run_id,
        "root_ids": without_id["root_ids"],
        "records": copied,
        "extensions": without_id["extensions"],
    }
    validate_bundle_payload(payload)
    return payload
