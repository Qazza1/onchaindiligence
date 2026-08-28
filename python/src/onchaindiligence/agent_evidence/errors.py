"""Public exception hierarchy."""


class AgentEvidenceError(Exception):
    """Base error for package-level construction and configuration failures."""


class CanonicalizationError(AgentEvidenceError):
    """A value cannot be represented by the Agent Evidence RFC 8785 profile."""


class ParseError(AgentEvidenceError):
    """Input is not strict I-JSON accepted by the verifier."""


class SchemaValidationError(AgentEvidenceError):
    """Input does not conform to a published Agent Evidence JSON Schema."""


class EvidenceValidationError(AgentEvidenceError):
    """A record or bundle violates deterministic graph invariants."""


class TrustPolicyError(AgentEvidenceError):
    """Caller-supplied trust material is malformed or internally inconsistent."""


class SigningError(AgentEvidenceError):
    """A signing key or payload is not valid for Agent Evidence v0."""
