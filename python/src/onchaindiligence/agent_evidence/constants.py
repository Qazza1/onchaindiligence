"""Normative Agent Evidence v0 constants."""

SPECIFICATION_ID = "onchaindiligence.agent-evidence.v0"
RECORD_VERSION = "onchaindiligence.agent-evidence.record.v0"
BUNDLE_VERSION = "onchaindiligence.agent-evidence.bundle.v0"
MEDIA_TYPE = "application/vnd.onchaindiligence.agent-evidence+json"
BUNDLE_PAYLOAD_TYPE = "application/vnd.onchaindiligence.agent-evidence.bundle.v0+json"
ATTESTATION_V2 = "onchaindiligence.attestation.v2"
ATTESTATION_ISSUER = "https://api.onchaindiligence.com"
ATTESTATION_PURPOSE = "compliance-screening-result"
ATTESTATION_PURPOSES = frozenset(
    {
        ATTESTATION_PURPOSE,
        "verification-fixture",
        "public-action-receipt",
        "erc20-allowance-action",
        "swap-action",
        "bridge-action",
        "staking-action",
    }
)
