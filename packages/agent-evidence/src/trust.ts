import {
  createHash,
  createPublicKey,
  KeyObject,
} from 'node:crypto'
import { formatTimestamp, parseTimestamp } from './canonical.js'
import { SchemaValidationError, TrustPolicyError } from './errors.js'
import { validateDocument } from './schema.js'
import type { AttestationKeyRecord, KeyInput, VerificationState } from './types.js'

const KEY_ID = /^ed25519-[A-Za-z0-9_-]{16}$/

function asBuffer(value: Uint8Array): Buffer {
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength)
}

export function loadPublicKey(value: KeyInput): KeyObject {
  try {
    const key = value instanceof KeyObject
      ? value
      : value instanceof Uint8Array && !Buffer.isBuffer(value)
      ? createPublicKey(asBuffer(value))
      : createPublicKey(value as string | Buffer)
    if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
      throw new TrustPolicyError('public key must be Ed25519')
    }
    return key
  } catch (error) {
    if (error instanceof TrustPolicyError) throw error
    throw new TrustPolicyError('public key is not a valid Ed25519 SubjectPublicKeyInfo key', { cause: error })
  }
}

export function deriveKeyId(publicKey: KeyInput): string {
  const key = loadPublicKey(publicKey)
  const der = key.export({ format: 'der', type: 'spki' })
  return `ed25519-${createHash('sha256').update(der).digest('base64url').slice(0, 16)}`
}

function optionalTimestamp(record: AttestationKeyRecord, name: keyof AttestationKeyRecord): Date | null {
  const value = record[name]
  if (value === null || value === undefined) return null
  if (typeof value !== 'string') throw new TrustPolicyError(`${String(name)} must be an exact timestamp or null`)
  try {
    return parseTimestamp(value)
  } catch (error) {
    throw new TrustPolicyError(`invalid key ${String(name)}: ${error instanceof Error ? error.message : String(error)}`, {
      cause: error,
    })
  }
}

export class AttestationKey {
  readonly keyId: string
  readonly publicKey: KeyObject
  readonly publicKeyPem: string
  readonly status: AttestationKeyRecord['status']
  readonly replacementKeyId: string | null
  readonly statusReason?: string
  readonly #validFromMs: number | null
  readonly #validUntilMs: number | null
  readonly #statusChangedAtMs: number | null
  readonly #compromisedAtMs: number | null

  private constructor(record: AttestationKeyRecord, publicKey: KeyObject) {
    this.keyId = record.key_id
    this.publicKey = publicKey
    this.publicKeyPem = record.public_key_pem
    this.status = record.status
    this.#validFromMs = optionalTimestamp(record, 'valid_from')?.getTime() ?? null
    this.#validUntilMs = optionalTimestamp(record, 'valid_until')?.getTime() ?? null
    this.#statusChangedAtMs = optionalTimestamp(record, 'status_changed_at')?.getTime() ?? null
    this.replacementKeyId = record.replacement_key_id
    this.#compromisedAtMs = optionalTimestamp(record, 'compromised_at')?.getTime() ?? null
    if (record.status_reason !== undefined) this.statusReason = record.status_reason
  }

  get validFrom(): Date | null { return this.#validFromMs === null ? null : new Date(this.#validFromMs) }
  get validUntil(): Date | null { return this.#validUntilMs === null ? null : new Date(this.#validUntilMs) }
  get statusChangedAt(): Date | null {
    return this.#statusChangedAtMs === null ? null : new Date(this.#statusChangedAtMs)
  }
  get compromisedAt(): Date | null {
    return this.#compromisedAtMs === null ? null : new Date(this.#compromisedAtMs)
  }

  static fromRecord(input: AttestationKeyRecord | Record<string, unknown>): AttestationKey {
    const record = structuredClone(input) as AttestationKeyRecord
    try {
      validateDocument('attestation-key.schema.json', record)
    } catch (error) {
      if (error instanceof SchemaValidationError) throw new TrustPolicyError(error.message, { cause: error })
      throw error
    }
    if (!KEY_ID.test(record.key_id)) throw new TrustPolicyError('invalid Ed25519 key_id')
    const publicKey = loadPublicKey(record.public_key_pem)
    const derived = deriveKeyId(publicKey)
    if (derived !== record.key_id) {
      throw new TrustPolicyError(`key_id does not match SPKI public key: expected ${derived}`)
    }
    const key = new AttestationKey(record, publicKey)
    if (key.validFrom && key.validUntil && key.validUntil.getTime() < key.validFrom.getTime()) {
      throw new TrustPolicyError('valid_until precedes valid_from')
    }
    if (key.validFrom && key.statusChangedAt && key.statusChangedAt.getTime() < key.validFrom.getTime()) {
      throw new TrustPolicyError('status_changed_at precedes valid_from')
    }
    if (key.validFrom && key.compromisedAt && key.compromisedAt.getTime() < key.validFrom.getTime()) {
      throw new TrustPolicyError('compromised_at precedes valid_from')
    }
    if ((key.status === 'revoked' || key.status === 'compromised') && !key.statusChangedAt) {
      throw new TrustPolicyError(`${key.status} key requires status_changed_at`)
    }
    if (key.replacementKeyId === key.keyId) throw new TrustPolicyError('a key cannot name itself as its replacement')
    return key
  }

  toRecord(): AttestationKeyRecord {
    const record: AttestationKeyRecord = {
      key_id: this.keyId,
      algorithm: 'ed25519',
      public_key_pem: this.publicKeyPem,
      status: this.status,
      valid_from: this.validFrom?.toISOString() ?? null,
      valid_until: this.validUntil?.toISOString() ?? null,
      status_changed_at: this.statusChangedAt?.toISOString() ?? null,
      replacement_key_id: this.replacementKeyId,
      compromised_at: this.compromisedAt?.toISOString() ?? null,
    }
    if (this.statusReason !== undefined) record.status_reason = this.statusReason
    return record
  }
}

export interface CreateKeyRecordOptions {
  validFrom: string | Date | null
  status?: AttestationKeyRecord['status']
  validUntil?: string | Date | null
  statusChangedAt?: string | Date | null
  replacementKeyId?: string | null
  compromisedAt?: string | Date | null
  statusReason?: string
}

function timestamp(value: string | Date | null | undefined): string | null {
  if (value instanceof Date) return formatTimestamp(value)
  return value ?? null
}

export function createKeyRecord(publicKeyInput: KeyInput, options: CreateKeyRecordOptions): AttestationKeyRecord {
  const publicKey = loadPublicKey(publicKeyInput)
  const status = options.status ?? 'active'
  const validFrom = timestamp(options.validFrom)
  const changed = options.statusChangedAt === undefined && status === 'active'
    ? validFrom
    : timestamp(options.statusChangedAt)
  const record: AttestationKeyRecord = {
    key_id: deriveKeyId(publicKey),
    algorithm: 'ed25519',
    public_key_pem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    status,
    valid_from: validFrom,
    valid_until: timestamp(options.validUntil),
    status_changed_at: changed,
    replacement_key_id: options.replacementKeyId ?? null,
    compromised_at: timestamp(options.compromisedAt),
  }
  if (options.statusReason !== undefined) record.status_reason = options.statusReason
  return AttestationKey.fromRecord(record).toRecord()
}

export interface TrustPolicyOptions {
  now?: Date
  requiredSignatureKeyIds?: Iterable<string>
  minimumValidSignatures?: number
  maxFutureSkewMs?: number
  maxBundleAgeMs?: number | null
  enforceEvidenceExpiration?: boolean
  allowDigestOnlyEvidence?: boolean
  requireVerifiedAnchor?: boolean
  maxFileSize?: number
  maxDepth?: number
  maxStringLength?: number
  maxArrayLength?: number
}

export class TrustPolicy {
  readonly minimumValidSignatures: number
  readonly maxFutureSkewMs: number
  readonly maxBundleAgeMs: number | null
  readonly enforceEvidenceExpiration: boolean
  readonly allowDigestOnlyEvidence: boolean
  readonly requireVerifiedAnchor: boolean
  readonly maxFileSize: number
  readonly maxDepth: number
  readonly maxStringLength: number
  readonly maxArrayLength: number
  readonly #keys: ReadonlyMap<string, AttestationKey>
  readonly #nowMs: number
  readonly #requiredSignatureKeyIds: ReadonlySet<string>

  private constructor(keys: Map<string, AttestationKey>, options: TrustPolicyOptions) {
    this.#nowMs = options.now?.getTime() ?? Date.now()
    if (Number.isNaN(this.#nowMs)) throw new TrustPolicyError('policy now must be a valid Date')
    this.#requiredSignatureKeyIds = new Set(options.requiredSignatureKeyIds ?? [])
    this.minimumValidSignatures = options.minimumValidSignatures ?? 1
    this.maxFutureSkewMs = options.maxFutureSkewMs ?? 5 * 60 * 1000
    this.maxBundleAgeMs = options.maxBundleAgeMs ?? null
    this.enforceEvidenceExpiration = options.enforceEvidenceExpiration ?? true
    this.allowDigestOnlyEvidence = options.allowDigestOnlyEvidence ?? false
    this.requireVerifiedAnchor = options.requireVerifiedAnchor ?? false
    this.maxFileSize = options.maxFileSize ?? 10 * 1024 * 1024
    this.maxDepth = options.maxDepth ?? 64
    this.maxStringLength = options.maxStringLength ?? 1024 * 1024
    this.maxArrayLength = options.maxArrayLength ?? 10_000
    if (!Number.isInteger(this.minimumValidSignatures) || this.minimumValidSignatures < 1) {
      throw new TrustPolicyError('minimumValidSignatures must be at least one')
    }
    if (this.maxFutureSkewMs < 0) throw new TrustPolicyError('maxFutureSkewMs cannot be negative')
    if (this.maxBundleAgeMs !== null && this.maxBundleAgeMs < 0) {
      throw new TrustPolicyError('maxBundleAgeMs cannot be negative')
    }
    if ([this.maxFileSize, this.maxDepth, this.maxStringLength, this.maxArrayLength].some((value) => value < 1)) {
      throw new TrustPolicyError('parser limits must be positive')
    }
    const missing = [...this.#requiredSignatureKeyIds].filter((keyId) => !keys.has(keyId))
    if (missing.length) {
      throw new TrustPolicyError(`required signature keys are absent from caller trust: ${missing.sort().join(', ')}`)
    }
    this.#keys = new Map(keys)
  }

  static fromKeyRecords(
    records: Iterable<AttestationKeyRecord | Record<string, unknown>>,
    options: TrustPolicyOptions = {},
  ): TrustPolicy {
    const keys = new Map<string, AttestationKey>()
    for (const record of records) {
      const key = AttestationKey.fromRecord(record)
      if (keys.has(key.keyId)) throw new TrustPolicyError(`duplicate caller-trusted key: ${key.keyId}`)
      keys.set(key.keyId, key)
    }
    for (const key of keys.values()) {
      if (key.replacementKeyId && !keys.has(key.replacementKeyId)) {
        throw new TrustPolicyError(
          `key ${key.keyId} references an absent replacement key: ${key.replacementKeyId}`,
        )
      }
    }
    return new TrustPolicy(keys, options)
  }

  key(keyId: string): AttestationKey | undefined {
    return this.#keys.get(keyId)
  }

  get now(): Date { return new Date(this.#nowMs) }

  get requiredSignatureKeyIds(): ReadonlySet<string> {
    return new Set(this.#requiredSignatureKeyIds)
  }
}

export function evaluateKeyLifecycle(
  key: AttestationKey,
  signedAt: Date | null,
  policy: TrustPolicy,
): readonly [VerificationState, string, string] {
  if (key.status === 'revoked') return ['INVALID', 'key-revoked', 'the caller-trusted key is revoked']
  if (key.status === 'compromised') return ['INVALID', 'key-compromised', 'the caller-trusted key is compromised']
  if (!key.validFrom) {
    return ['UNVERIFIABLE', 'key-valid-from-missing', 'the caller-trusted key has no defensible activation boundary']
  }
  if (!signedAt) {
    if (key.status === 'retired') {
      return ['UNVERIFIABLE', 'signature-time-missing', 'a retired key cannot validate a proof that carries no signed issuance time']
    }
    if (policy.now.getTime() < key.validFrom.getTime()) {
      return ['INVALID', 'key-not-yet-valid', 'the key is not active at policy time']
    }
    return ['VALID', 'key-active', 'the caller-trusted key is currently active']
  }
  if (signedAt.getTime() > policy.now.getTime() + policy.maxFutureSkewMs) {
    return ['INVALID', 'signature-time-future', 'signed time exceeds allowed clock skew']
  }
  if (signedAt.getTime() < key.validFrom.getTime()) {
    return ['INVALID', 'key-not-yet-valid', 'signed time precedes key activation']
  }
  if (key.validUntil && signedAt.getTime() > key.validUntil.getTime()) {
    return ['INVALID', 'key-expired', 'signed time follows the key validity interval']
  }
  return ['VALID', 'key-window-valid', 'signed time is inside the key validity interval']
}
