"""Production Agent Evidence v0 construction and offline verification API."""

from .canonical import canonicalize, content_id, format_timestamp, parse_json, parse_timestamp
from .constants import (
    BUNDLE_PAYLOAD_TYPE,
    BUNDLE_VERSION,
    MEDIA_TYPE,
    RECORD_VERSION,
    SPECIFICATION_ID,
)
from .dsse import dsse_pae, load_private_key_pem, seal_bundle
from .errors import (
    AgentEvidenceError,
    CanonicalizationError,
    EvidenceValidationError,
    ParseError,
    SchemaValidationError,
    SigningError,
    TrustPolicyError,
)
from .graph import validate_bundle_payload
from .models import BundleIntegrityVerification, ComponentResult, VerificationReport, VerificationState
from .payment_claims import (
    PLATFORM_CLAIM_SIGNATURE_SCOPE,
    SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE,
    SIGNED_PAYMENT_CLAIM_VERSION,
    PaymentClaimVerificationResult,
    verify_signed_payment_claim,
)
from .receipts import verify_receipt_envelope
from .records import create_bundle_payload, create_record
from .trust import (
    AttestationKey,
    TrustPolicy,
    create_key_record,
    derive_key_id,
    load_public_key_pem,
)
from .verifier import verify_bundle

__all__ = [
    "BUNDLE_PAYLOAD_TYPE",
    "BUNDLE_VERSION",
    "MEDIA_TYPE",
    "PLATFORM_CLAIM_SIGNATURE_SCOPE",
    "RECORD_VERSION",
    "SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE",
    "SIGNED_PAYMENT_CLAIM_VERSION",
    "SPECIFICATION_ID",
    "AgentEvidenceError",
    "AttestationKey",
    "BundleIntegrityVerification",
    "CanonicalizationError",
    "ComponentResult",
    "EvidenceValidationError",
    "ParseError",
    "PaymentClaimVerificationResult",
    "SchemaValidationError",
    "SigningError",
    "TrustPolicy",
    "TrustPolicyError",
    "VerificationReport",
    "VerificationState",
    "canonicalize",
    "content_id",
    "create_bundle_payload",
    "create_key_record",
    "create_record",
    "derive_key_id",
    "dsse_pae",
    "format_timestamp",
    "load_private_key_pem",
    "load_public_key_pem",
    "parse_json",
    "parse_timestamp",
    "seal_bundle",
    "validate_bundle_payload",
    "verify_bundle",
    "verify_receipt_envelope",
    "verify_signed_payment_claim",
]

__version__ = "0.1.0"
