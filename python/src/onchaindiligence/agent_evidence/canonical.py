"""Strict JSON parsing and RFC 8785 canonicalization."""

from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

import rfc8785

from .errors import CanonicalizationError, ParseError
from .models import JsonObject

_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise ParseError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _safe_integer(value: str) -> int:
    parsed = int(value)
    if abs(parsed) > _MAX_SAFE_INTEGER:
        raise ParseError("JSON integer exceeds the interoperable safe-integer range")
    return parsed


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ParseError("JSON number exceeds the finite IEEE-754 range")
    return parsed


def _reject_constant(value: str) -> None:
    raise ParseError(f"non-finite JSON number is forbidden: {value}")


def parse_json(data: str | bytes) -> Any:
    """Parse untrusted JSON with duplicate-name and unsafe-integer rejection."""

    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ParseError("JSON must be valid UTF-8") from exc
    else:
        text = data
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_no_duplicates,
            parse_int=_safe_integer,
            parse_float=_finite_float,
            parse_constant=_reject_constant,
        )
    except ParseError:
        raise
    except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError) as exc:
        raise ParseError(f"invalid JSON: {exc}") from exc


def enforce_limits(
    value: Any,
    *,
    max_depth: int,
    max_string_length: int,
    max_array_length: int,
) -> None:
    """Enforce policy limits not expressible across every open schema value."""

    def visit(item: Any, depth: int) -> None:
        if depth > max_depth:
            raise ParseError(f"JSON exceeds maximum depth {max_depth}")
        if isinstance(item, str):
            if len(item) > max_string_length:
                raise ParseError(f"JSON string exceeds maximum length {max_string_length}")
            return
        if isinstance(item, list):
            if len(item) > max_array_length:
                raise ParseError(f"JSON array exceeds maximum length {max_array_length}")
            for child in item:
                visit(child, depth + 1)
            return
        if isinstance(item, dict):
            if len(item) > max_array_length:
                raise ParseError(f"JSON object exceeds maximum members {max_array_length}")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ParseError("JSON object names must be strings")
                visit(key, depth + 1)
                visit(child, depth + 1)
            return
        if isinstance(item, int) and not isinstance(item, bool) and abs(item) > _MAX_SAFE_INTEGER:
            raise ParseError("JSON integer exceeds the interoperable safe-integer range")
        if isinstance(item, float) and (item != item or item in (float("inf"), float("-inf"))):
            raise ParseError("non-finite JSON number is forbidden")

    visit(value, 0)


def canonicalize(value: Any) -> bytes:
    """Return RFC 8785 bytes or raise a stable package exception."""

    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, TypeError, ValueError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def content_id(value: Any) -> str:
    """Compute the v0 SHA-256 unpadded-base64url content identifier."""

    import base64

    digest = base64.urlsafe_b64encode(sha256(canonicalize(value)).digest()).decode("ascii").rstrip("=")
    return f"sha256:{digest}"


def parse_timestamp(value: str) -> datetime:
    """Parse the exact millisecond UTC timestamp profile."""

    if not _TIMESTAMP.fullmatch(value):
        raise ParseError("timestamp must use exact YYYY-MM-DDTHH:mm:ss.sssZ syntax")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ParseError(f"invalid UTC timestamp: {value}") from exc
    return parsed.astimezone(timezone.utc)


def format_timestamp(value: datetime) -> str:
    """Format an aware datetime in the normative millisecond UTC profile."""

    if value.tzinfo is None:
        raise ValueError("timestamp datetime must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
