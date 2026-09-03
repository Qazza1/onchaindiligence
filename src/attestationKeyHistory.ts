import { createHash, createPublicKey } from 'node:crypto'

/**
 * Immutable history for attestation keys that are no longer active.
 *
 * Rotation procedure:
 * 1. Before replacing the private key, copy the current public record here.
 * 2. Mark it `retired` for an ordinary rotation, or `compromised`/`revoked`
 *    when past signatures must carry a trust warning.
 * 3. Commit and deploy this history before changing the production key.
 *
 * Public keys are intentionally public. Private keys never belong here.
 */
export type AttestationKeyStatus = 'active' | 'retired' | 'revoked' | 'compromised'

export interface AttestationKeyRecord {
  key_id: string
  algorithm: 'ed25519'
  public_key_pem: string
  status: AttestationKeyStatus
  valid_from: string | null
  valid_until: string | null
  status_changed_at: string | null
  status_reason?: string
  replacement_key_id?: string | null
  compromised_at?: string | null
}

export interface AttestationKeyRegistryReadiness {
  strict_ready: boolean
  warnings: string[]
}

const KEY_ID_PATTERN = /^ed25519-[A-Za-z0-9_-]{16}$/

function requireExactTimestamp(value: string | null | undefined, field: string, keyId: string): void {
  if (value === null || value === undefined) return
  const parsed = Date.parse(value)
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new Error(`attestation key ${keyId} has an invalid ${field}; use an exact ISO 8601 UTC timestamp`)
  }
}

function deriveKeyId(publicKeyPem: string): string {
  let key
  try {
    key = createPublicKey(publicKeyPem)
  } catch {
    throw new Error('attestation public key is not a parseable SPKI PEM')
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error('attestation public key must be Ed25519')
  }
  const digest = createHash('sha256')
    .update(key.export({ type: 'spki', format: 'der' }))
    .digest('base64url')
  return `ed25519-${digest.slice(0, 16)}`
}

/** Validate registry integrity before publishing it or trusting it operationally. */
export function validateAttestationKeyRegistry(
  records: readonly AttestationKeyRecord[],
  options: { requireValidFrom?: boolean } = {}
): AttestationKeyRegistryReadiness {
  const warnings: string[] = []
  const ids = new Set<string>()
  let activeKeys = 0

  for (const record of records) {
    if (!KEY_ID_PATTERN.test(record.key_id)) {
      throw new Error(`attestation key id ${record.key_id} does not match the derived-key format`)
    }
    if (ids.has(record.key_id)) throw new Error(`duplicate attestation key id ${record.key_id}`)
    ids.add(record.key_id)
    if (record.algorithm !== 'ed25519') {
      throw new Error(`attestation key ${record.key_id} uses unsupported algorithm ${record.algorithm}`)
    }

    let derived: string
    try {
      derived = deriveKeyId(record.public_key_pem)
    } catch (error) {
      throw new Error(`attestation key ${record.key_id}: ${(error as Error).message}`)
    }
    if (derived !== record.key_id) {
      throw new Error(`attestation key ${record.key_id} does not match its public key (derived ${derived})`)
    }

    requireExactTimestamp(record.valid_from, 'valid_from', record.key_id)
    requireExactTimestamp(record.valid_until, 'valid_until', record.key_id)
    requireExactTimestamp(record.status_changed_at, 'status_changed_at', record.key_id)
    requireExactTimestamp(record.compromised_at, 'compromised_at', record.key_id)

    if (!record.valid_from) {
      const warning = `attestation key ${record.key_id} has no valid_from activation boundary`
      if (options.requireValidFrom) throw new Error(warning)
      warnings.push(warning)
    }
    if (
      record.valid_from &&
      record.valid_until &&
      Date.parse(record.valid_until) < Date.parse(record.valid_from)
    ) {
      throw new Error(`attestation key ${record.key_id} has valid_until before valid_from`)
    }

    if (record.status === 'active') {
      activeKeys += 1
      if (record.valid_until) throw new Error(`active attestation key ${record.key_id} cannot have valid_until`)
    }
    if (record.status === 'retired' && (!record.valid_until || !record.status_changed_at)) {
      throw new Error(`retired attestation key ${record.key_id} requires valid_until and status_changed_at`)
    }
    if (record.status === 'compromised' && (!record.compromised_at || !record.status_changed_at)) {
      throw new Error(`compromised attestation key ${record.key_id} requires compromised_at and status_changed_at`)
    }
    if (record.status === 'revoked' && (!record.status_changed_at || !record.status_reason)) {
      throw new Error(`revoked attestation key ${record.key_id} requires status_changed_at and status_reason`)
    }
  }

  if (activeKeys > 1) throw new Error('attestation key registry cannot contain more than one active key')
  for (const record of records) {
    if (!record.replacement_key_id) continue
    if (record.replacement_key_id === record.key_id) {
      throw new Error(`attestation key ${record.key_id} cannot replace itself`)
    }
    if (!ids.has(record.replacement_key_id)) {
      throw new Error(`attestation key ${record.key_id} references unknown replacement ${record.replacement_key_id}`)
    }
  }

  return { strict_ready: warnings.length === 0, warnings }
}

const historicalAttestationKeys: AttestationKeyRecord[] = [
  {
    key_id: 'ed25519-D8wfc7civVNG05Ds',
    algorithm: 'ed25519',
    public_key_pem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAfnv7489CJ2vQLMYimr8Ot9g/8ZFYbs3dH5M5tDFBV+w=\n-----END PUBLIC KEY-----\n',
    status: 'retired',
    // This key pre-dates the authoritative lifecycle record. Its activation
    // remains unknown by design and is never reconstructed from observations.
    valid_from: null,
    valid_until: '2026-09-03T19:50:00.000Z',
    status_changed_at: '2026-09-03T19:50:00.000Z',
    // The replacement is supplied by the production rotation configuration so
    // tests using an ephemeral signer do not misrepresent that signer as a
    // production successor. Production deploys must set this exact public ID.
    replacement_key_id: process.env.ATTESTATION_ROTATION_REPLACEMENT_KEY_ID ?? null,
    compromised_at: null,
  },
]

export const HISTORICAL_ATTESTATION_KEYS: readonly Readonly<AttestationKeyRecord>[] = Object.freeze(
  historicalAttestationKeys.map((record) => Object.freeze({ ...record }))
)
