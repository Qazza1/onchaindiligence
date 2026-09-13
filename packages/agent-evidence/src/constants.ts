export const SPECIFICATION_ID = 'onchaindiligence.agent-evidence.v0' as const
export const RECORD_VERSION = 'onchaindiligence.agent-evidence.record.v0' as const
export const BUNDLE_VERSION = 'onchaindiligence.agent-evidence.bundle.v0' as const
export const MEDIA_TYPE = 'application/vnd.onchaindiligence.agent-evidence+json' as const
export const BUNDLE_PAYLOAD_TYPE =
  'application/vnd.onchaindiligence.agent-evidence.bundle.v0+json' as const
export const ATTESTATION_V2 = 'onchaindiligence.attestation.v2' as const
export const ATTESTATION_ISSUER = 'https://api.onchaindiligence.com' as const
export const ATTESTATION_PURPOSE = 'compliance-screening-result' as const
/** Exact purpose union issued by the production attestation endpoint. */
export const ATTESTATION_PURPOSES = [
  ATTESTATION_PURPOSE,
  'verification-fixture',
  'public-action-receipt',
  'erc20-allowance-action',
  'swap-action',
  'bridge-action',
  'staking-action',
] as const
