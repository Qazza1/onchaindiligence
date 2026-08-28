"""Typed verification results and JSON aliases."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeAlias

JsonObject: TypeAlias = dict[str, Any]


class VerificationState(str, Enum):
    """The only permitted top-level and component verification states."""

    VALID = "VALID"
    INVALID = "INVALID"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True, slots=True)
class ComponentResult:
    """One independently visible verification decision."""

    component: str
    state: VerificationState
    code: str
    message: str
    key_id: str | None = None
    record_id: str | None = None
    required: bool = True

    def to_dict(self) -> JsonObject:
        result: JsonObject = {
            "component": self.component,
            "state": self.state.value,
            "code": self.code,
            "message": self.message,
            "required": self.required,
        }
        if self.key_id is not None:
            result["key_id"] = self.key_id
        if self.record_id is not None:
            result["record_id"] = self.record_id
        return result


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Machine-readable offline verification report."""

    state: VerificationState
    components: tuple[ComponentResult, ...]
    bundle_id: str | None = None
    payload: JsonObject | None = field(default=None, repr=False, compare=False)

    @property
    def valid(self) -> bool:
        return self.state is VerificationState.VALID

    def to_dict(self, *, include_payload: bool = False) -> JsonObject:
        result: JsonObject = {
            "state": self.state.value,
            "bundle_id": self.bundle_id,
            "components": [component.to_dict() for component in self.components],
        }
        if include_payload and self.payload is not None:
            result["payload"] = self.payload
        return result


def overall_state(components: list[ComponentResult]) -> VerificationState:
    """Aggregate components without collapsing uncertainty into success."""

    required = [item for item in components if item.required]
    if any(item.state is VerificationState.INVALID for item in required):
        return VerificationState.INVALID
    if any(item.state is VerificationState.UNVERIFIABLE for item in required):
        return VerificationState.UNVERIFIABLE
    return VerificationState.VALID
