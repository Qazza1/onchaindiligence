/**
 * attestation.ts
 * --------------
 * Turns each API response into a cryptographically verifiable ATTESTATION.
 *
 * WHY THIS EXISTS (the compliance point):
 * In compliance, an unverifiable check is close to worthless — the entire
 * purpose is producing defensible evidence for an auditor later. A plain
 * JSON response could be fabricated after the fact. By signing every
 * response with a dedicated key plus a signed timestamp assertion, the caller
 * gets a tamper-evident statement they can store and later show an auditor:
 * "OnChainDiligence signed this exact result and asserted this issuance time."
 * Anyone with independently trusted key records can verify it offline. Only a
 * separately verified anchor can establish an external no-later-than bound.
 *
 * Crypto choice: Ed25519 via Node's built-in `crypto`. Fast, tiny (64-byte)
 * signatures, no extra dependency, widely supported for verification.
 *
 * What we sign: RFC 8785 canonical JSON containing the normalized response
 * data, issued-at timestamp, key id, issuer, purpose and schema version.
 *
 * KEY MANAGEMENT (important):
 *   - The private key lives ONLY in the ATTESTATION_PRIVATE_KEY env var
 *     (PEM, PKCS8). Generate it once, store it in your hosting platform's
 *     secrets manager, never commit it.
 *   - Public keys and status are served by key id at
 *     /.well-known/attestation-keys. Publishing public keys is safe and is the
 *     whole point.
 *   - The production server refuses to boot without a signing key. The
 *     unsigned branch remains only for isolated tests and library reuse.
 *
 * Generate a keypair (run locally, once):
 *   node -e "const c=require('crypto');const {publicKey,privateKey}=c.generateKeyPairSync('ed25519');console.log('PRIVATE (set as ATTESTATION_PRIVATE_KEY, keep secret):\\n'+privateKey.export({type:'pkcs8',format:'pem'}));console.log('PUBLIC (informational):\\n'+publicKey.export({type:'spki',format:'pem'}))"
 */

import {
  createPrivateKey,
  createPublicKey,
  createHash,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto'
import { canonicalizeJson, normalizeJson } from './canonicalJson.js'
import {
  HISTORICAL_ATTESTATION_KEYS,
  type AttestationKeyRecord,
  validateAttestationKeyRegistry,
} from './attestationKeyHistory.js'

export const ATTESTATION_SCHEMA_VERSION = 'onchaindiligence.attestation.v2'
export const ATTESTATION_ISSUER = 'https://api.onchaindiligence.com'
export const ATTESTATION_PURPOSE = 'compliance-screening-result'
export const ATTESTATION_FIXTURE_PURPOSE = 'verification-fixture'

let privateKey: KeyObject | null = null
let publicKeyPem: string | null = null
let keyId: string | null = null

/**
 * Loads (or reloads) the signing key from the ATTESTATION_PRIVATE_KEY env
 * var. Called once at module load below. Exposed (via __reinit in tests) so
 * tests can re-run it after changing the env var, without import-cache hacks.
 */
function loadKey(): void {
  const pem = process.env.ATTESTATION_PRIVATE_KEY
  privateKey = null
  publicKeyPem = null
  keyId = null

  if (!pem || pem.trim().length === 0) return

  try {
    // Allow the PEM to be provided with literal "\n" sequences (common when
    // pasting a multi-line key into a single-line env var field).
    const normalized = pem.includes('\\n') ? pem.replace(/\\n/g, '\n') : pem
    privateKey = createPrivateKey(normalized)
    const pub = createPublicKey(privateKey)
    publicKeyPem = pub.export({ type: 'spki', format: 'pem' }).toString()
    // A short, stable key id derived from a HASH of the raw public key bytes,
    // so it's genuinely unique per key (supports future rotation). Deriving
    // it from the PEM string directly would collide, since every Ed25519 PEM
    // shares the same "-----BEGIN PUBLIC KEY-----" prefix.
    const rawPub = pub.export({ type: 'spki', format: 'der' })
    const digest = createHash('sha256').update(rawPub).digest('base64url')
    keyId = 'ed25519-' + digest.slice(0, 16)
  } catch (err) {
    // Bad key material is worth failing loudly about, because a
    // misconfigured signing key silently producing garbage would be worse.
    throw new Error(
      'ATTESTATION_PRIVATE_KEY is set but could not be parsed as a PKCS8 ' +
        'Ed25519 PEM private key. Generate one with the snippet in ' +
        'attestation.ts, or unset it to run without attestation.'
    )
  }
}

loadKey()

// Test-only: re-read the env var and reload the key.
export const __reinit = loadKey

export function attestationEnabled(): boolean {
  return privateKey !== null
}

export function getPublicKeyPem(): string | null {
  return publicKeyPem
}

export function getKeyId(): string | null {
  return keyId
}

export function getAttestationKeyRecords(): AttestationKeyRecord[] {
  const historical = HISTORICAL_ATTESTATION_KEYS.map((record) => ({ ...record }))
  if (!keyId || !publicKeyPem) {
    validateAttestationKeyRegistry(historical, { requireValidFrom: false })
    return historical
  }

  if (historical.some((record) => record.key_id === keyId)) {
    throw new Error(`active attestation key ${keyId} is duplicated in immutable history`)
  }

  const records: AttestationKeyRecord[] = [
    {
      key_id: keyId,
      algorithm: 'ed25519',
      public_key_pem: publicKeyPem,
      status: 'active',
      valid_from: process.env.ATTESTATION_KEY_ACTIVATED_AT || null,
      valid_until: null,
      status_changed_at: process.env.ATTESTATION_KEY_ACTIVATED_AT || null,
      replacement_key_id: null,
      compromised_at: null,
    },
    ...historical,
  ]
  validateAttestationKeyRegistry(records, { requireValidFrom: false })
  return records
}

export function getAttestationKeyRegistryReadiness(): {
  strict_ready: boolean
  warnings: string[]
} {
  return validateAttestationKeyRegistry(getAttestationKeyRecords(), { requireValidFrom: false })
}

export function getAttestationKeyRecord(requestedKeyId: string): AttestationKeyRecord | null {
  return getAttestationKeyRecords().find((record) => record.key_id === requestedKeyId) ?? null
}

export function buildAttestationSigningInput(
  data: unknown,
  issuedAt: string,
  signingKeyId: string,
  purpose = ATTESTATION_PURPOSE
): string {
  return canonicalizeJson({
    schema_version: ATTESTATION_SCHEMA_VERSION,
    issuer: ATTESTATION_ISSUER,
    purpose,
    data,
    issued_at: issuedAt,
    key_id: signingKeyId,
  })
}

export interface VerifiedAttestationForAnchoring {
  signature: string
  keyId: string
  keyStatus: AttestationKeyRecord['status']
  issuedAt: string
}

export type AnchorAttestationVerification =
  | { valid: true; attestation: VerifiedAttestationForAnchoring }
  | { valid: false; status: 400 | 422; error: string }

type AttestationKeyResolver = (requestedKeyId: string) => AttestationKeyRecord | null

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Verify that an anchor request contains a complete, authentic v2 compliance
 * attestation issued by this service. Syntax-only signature checks are not
 * enough: arbitrary 64-byte values must never be written to the registry as
 * though OnchainDiligence had attested them.
 *
 * The resolver parameter exists so key-state policy can be tested without
 * mutating the immutable production key history.
 */
export function verifyAttestationForAnchoring(
  envelope: unknown,
  resolveKey: AttestationKeyResolver = getAttestationKeyRecord
): AnchorAttestationVerification {
  if (!isObject(envelope) || !Object.hasOwn(envelope, 'data') || !isObject(envelope.attestation)) {
    return {
      valid: false,
      status: 400,
      error: 'expected a complete signed attestation envelope with "data" and "attestation" fields',
    }
  }

  const metadata = envelope.attestation
  if (
    metadata.signed !== true ||
    metadata.schema_version !== ATTESTATION_SCHEMA_VERSION ||
    metadata.issuer !== ATTESTATION_ISSUER ||
    metadata.purpose !== ATTESTATION_PURPOSE ||
    metadata.algorithm !== 'ed25519' ||
    metadata.canonicalization !== 'RFC8785'
  ) {
    return {
      valid: false,
      status: 422,
      error: 'attestation metadata is not an anchorable OnchainDiligence v2 compliance attestation',
    }
  }

  const issuedAt = metadata.issued_at
  const requestedKeyId = metadata.key_id
  const signature = metadata.signature
  if (
    typeof issuedAt !== 'string' ||
    !Number.isFinite(Date.parse(issuedAt)) ||
    new Date(issuedAt).toISOString() !== issuedAt ||
    typeof requestedKeyId !== 'string' ||
    requestedKeyId.length === 0 ||
    requestedKeyId.length > 128 ||
    typeof signature !== 'string' ||
    !/^[A-Za-z0-9_-]{86}$/.test(signature) ||
    Buffer.from(signature, 'base64url').length !== 64
  ) {
    return {
      valid: false,
      status: 400,
      error: 'attestation issued_at, key_id, or Ed25519 signature has an invalid format',
    }
  }

  const key = resolveKey(requestedKeyId)
  if (!key) {
    return { valid: false, status: 422, error: 'attestation key_id is not in the issuer key registry' }
  }
  if (key.status === 'revoked' || key.status === 'compromised') {
    return {
      valid: false,
      status: 422,
      error: `attestation key is ${key.status} and cannot be used for anchoring`,
    }
  }

  const issuedAtMs = Date.parse(issuedAt)
  if (!key.valid_from) {
    return {
      valid: false,
      status: 422,
      error: 'attestation key has no registered valid_from boundary',
    }
  }
  if (key.status === 'retired' && !key.valid_until) {
    return {
      valid: false,
      status: 422,
      error: 'retired attestation key has no registered valid_until boundary',
    }
  }
  const validFromMs = Date.parse(key.valid_from)
  const validUntilMs = key.valid_until ? Date.parse(key.valid_until) : Number.POSITIVE_INFINITY
  if (
    !Number.isFinite(validFromMs) ||
    new Date(validFromMs).toISOString() !== key.valid_from ||
    (!Number.isFinite(validUntilMs) && validUntilMs !== Number.POSITIVE_INFINITY) ||
    (key.valid_until && new Date(validUntilMs).toISOString() !== key.valid_until) ||
    issuedAtMs < validFromMs ||
    issuedAtMs > validUntilMs
  ) {
    return {
      valid: false,
      status: 422,
      error: 'attestation was issued outside the registered validity period for its key',
    }
  }

  try {
    const signingInput = buildAttestationSigningInput(
      envelope.data,
      issuedAt,
      requestedKeyId,
      ATTESTATION_PURPOSE
    )
    const verified = cryptoVerify(
      null,
      Buffer.from(signingInput, 'utf8'),
      createPublicKey(key.public_key_pem),
      Buffer.from(signature, 'base64url')
    )
    if (!verified) {
      return { valid: false, status: 422, error: 'attestation signature verification failed' }
    }
  } catch {
    return { valid: false, status: 422, error: 'attestation could not be cryptographically verified' }
  }

  return {
    valid: true,
    attestation: {
      signature,
      keyId: requestedKeyId,
      keyStatus: key.status,
      issuedAt,
    },
  }
}

/**
 * Wraps a result object into a signed attestation envelope.
 *
 * The returned shape is:
 * {
 *   data:        <the original result, untouched>,
 *   attestation: {
 *     issued_at:  ISO timestamp,
 *     key_id:     which key signed this,
 *     algorithm:  "ed25519",
 *     signature:  base64url signature over the canonical signing input,
 *     signing_input_hint: how to reconstruct what was signed (for verifiers)
 *   }
 * }
 *
 * If attestation is disabled (no key configured), returns the data with an
 * explicit `attestation: { signed: false, ... }` so callers are never
 * misled into thinking an unsigned response was signed.
 */
export function attest<T extends Record<string, unknown>>(
  data: T,
  options: { purpose?: typeof ATTESTATION_PURPOSE | typeof ATTESTATION_FIXTURE_PURPOSE } = {}
): Record<string, unknown> {
  const issuedAt = new Date().toISOString()
  const normalizedData = normalizeJson(data)
  const purpose = options.purpose ?? ATTESTATION_PURPOSE

  if (!privateKey || !keyId) {
    return {
      data: normalizedData,
      attestation: {
        signed: false,
        issued_at: issuedAt,
        note:
          'Attestation is not configured on this deployment (no signing key). ' +
          'Response is unsigned and should not be treated as verifiable evidence.',
      },
    }
  }

  const signingInput = buildAttestationSigningInput(normalizedData, issuedAt, keyId, purpose)

  // Ed25519 in Node: pass null as the algorithm; sign the raw bytes.
  const signature = cryptoSign(null, Buffer.from(signingInput, 'utf8'), privateKey)

  return {
    data: normalizedData,
    attestation: {
      signed: true,
      schema_version: ATTESTATION_SCHEMA_VERSION,
      issuer: ATTESTATION_ISSUER,
      purpose,
      issued_at: issuedAt,
      key_id: keyId,
      algorithm: 'ed25519',
      canonicalization: 'RFC8785',
      signature: signature.toString('base64url'),
      signing_input_hint:
        'RFC 8785 canonical JSON over { schema_version, issuer, purpose, data, issued_at, key_id }; ' +
        'resolve key_id through /.well-known/attestation-keys/{key_id}',
    },
  }
}
