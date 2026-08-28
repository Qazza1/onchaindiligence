"""Offline JSON Schema loading and validation."""

from __future__ import annotations

import json
from functools import cache, lru_cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from .errors import SchemaValidationError

SCHEMA_BASE = "https://onchaindiligence.com/schemas/agent-evidence/v0/"
SCHEMA_NAMES = (
    "common.schema.json",
    "attestation-key.schema.json",
    "dsse-envelope.schema.json",
    "proof.schema.json",
    "record.schema.json",
    "bundle-payload.schema.json",
    "portable-file.schema.json",
)


@lru_cache(maxsize=1)
def _schemas() -> dict[str, dict[str, Any]]:
    directory = files("onchaindiligence.agent_evidence").joinpath("schemas")
    loaded: dict[str, dict[str, Any]] = {}
    for name in SCHEMA_NAMES:
        raw = directory.joinpath(name).read_text(encoding="utf-8")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise RuntimeError(f"packaged schema {name} is not an object")
        loaded[name] = value
    return loaded


@lru_cache(maxsize=1)
def _registry() -> Registry[Any]:
    resources = [
        (
            str(schema["$id"]),
            Resource.from_contents(schema, default_specification=DRAFT202012),
        )
        for schema in _schemas().values()
    ]
    return Registry().with_resources(resources)


@cache
def validator(name: str) -> Draft202012Validator:
    """Return a validator whose references are resolved only from package data."""

    try:
        schema = _schemas()[name]
    except KeyError as exc:
        raise ValueError(f"unknown Agent Evidence schema: {name}") from exc
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=_registry(), format_checker=FormatChecker())


def validate_document(name: str, value: Any) -> None:
    """Validate a document and raise one deterministic, path-aware error."""

    errors = sorted(validator(name).iter_errors(value), key=lambda item: list(item.absolute_path))
    if not errors:
        return
    error = errors[0]
    path = "/" + "/".join(str(part) for part in error.absolute_path)
    raise SchemaValidationError(f"{name}{path}: {error.message}")
