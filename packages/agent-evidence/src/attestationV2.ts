/**
 * attestationV2.ts — a small, generic, lifecycle-aware verifier for the
 * EXISTING `onchaindiligence.attestation.v2` signing scheme (RFC 8785
 * canonical JSON over `{schema_version, issuer, purpose, data, issued_at,
 * key_id}`, Ed25519). This is the same scheme the HTTP API, the MCP server,
 * and every existing paid check already sign with — not a new trust
 * primitive. It reuses this package's own `TrustPolicy` / `AttestationKey` /
 * `evaluateKeyLifecycle`, so a v2 attestation and a v0 Agent Evidence bundle
 * share the exact same key-lifecycle rules and the exact same tri-state
 * philosophy: VALID / INVALID / UNVERIFIABLE.
 *
 * `verifyAttestationV2` is the "small generic lifecycle-aware verifier"
 * public-action-receipt verification is built on (see receipts.ts), and it is
 * intentionally reusable for the deferred free MCP `verify_attestation` tool:
 * that tool was deferred earlier for lack of exactly this — a tri-state
 * verifier consulting the real key-lifecycle registry instead of a boolean.
 *
 * As with `verifyBundle`, the cryptographic check ALWAYS uses the public key
 * from the caller-supplied `TrustPolicy` for the presented `key_id` — never
 * any key material the caller of this function might otherwise be tempted to
 * embed alongside the data being verified.
 */
import { verify as ed25519Verify } from 'node:crypto'
import { canonicalize, parseTimestamp } from './canonical.js'
import { evaluateKeyLifecycle, type TrustPolicy } from './trust.js'
import type { VerificationState } from './types.js'

/** The `attestation` (or `proof`) fields of a v2-signed envelope. */
export interface AttestationV2Fields {
  signed: boolean
  schema_version: string
  issuer: string
  purpose: string
  issued_at: string
  key_id: string
  algorithm: string
  signature: string
}

export interface AttestationV2VerifyOptions {
  /** The exact issuer this verifier will accept. Never trust a caller-varying issuer. */
  expectedIssuer: string
  /** The exact purpose this verifier will accept for this content type. */
  expectedPurpose: string
}

export interface AttestationV2VerifyResult {
  state: VerificationState
  code: string
  message: string
  keyId?: string
}

const BASE64URL_SIGNATURE = /^[A-Za-z0-9_-]{86}$/

function outcome(
  state: VerificationState,
  code: string,
  message: string,
  keyId?: string,
): AttestationV2VerifyResult {
  return keyId === undefined ? { state, code, message } : { state, code, message, keyId }
}

/**
 * Verifies that `attestation` is a genuine `onchaindiligence.attestation.v2`
 * signature over exactly `data`, from a key the caller's `policy` trusts, and
 * currently within that key's lifecycle window as of `attestation.issued_at`.
 *
 * A mismatched issuer/purpose/schema_version, a malformed signature encoding,
 * or a signature that fails to verify is INVALID. An unknown or untrusted
 * `key_id` — including "the registry was unavailable, so `policy` has no
 * keys" — is UNVERIFIABLE, never INVALID: unavailability of trust material is
 * not evidence of tampering.
 */
export function verifyAttestationV2(
  data: unknown,
  attestation: AttestationV2Fields,
  policy: TrustPolicy,
  options: AttestationV2VerifyOptions,
): AttestationV2VerifyResult {
  if (attestation.signed !== true) {
    return outcome('INVALID', 'not-signed', 'attestation is not marked as signed')
  }
  if (attestation.schema_version !== 'onchaindiligence.attestation.v2') {
    return outcome('INVALID', 'schema-version-unsupported', `unsupported attestation schema_version: ${attestation.schema_version}`)
  }
  if (attestation.algorithm !== 'ed25519') {
    return outcome('INVALID', 'algorithm-unsupported', `unsupported attestation algorithm: ${attestation.algorithm}`)
  }
  if (attestation.issuer !== options.expectedIssuer) {
    return outcome('INVALID', 'issuer-mismatch', 'attestation issuer does not match the exact expected issuer')
  }
  if (attestation.purpose !== options.expectedPurpose) {
    return outcome('INVALID', 'purpose-mismatch', 'attestation purpose does not match the exact expected purpose')
  }
  if (!BASE64URL_SIGNATURE.test(attestation.signature)) {
    return outcome('INVALID', 'signature-encoding', 'signature is not 86-character unpadded base64url')
  }

  const key = policy.key(attestation.key_id)
  if (!key) {
    return outcome(
      'UNVERIFIABLE',
      'key-not-trusted',
      'signing key is absent from caller-supplied trust (unknown signer, or the trust registry was unavailable)',
      attestation.key_id,
    )
  }

  const signingInput = canonicalize({
    schema_version: attestation.schema_version,
    issuer: attestation.issuer,
    purpose: attestation.purpose,
    data,
    issued_at: attestation.issued_at,
    key_id: attestation.key_id,
  })
  const signatureBytes = Buffer.from(attestation.signature, 'base64url')
  if (
    signatureBytes.length !== 64 ||
    !ed25519Verify(null, Buffer.from(signingInput), key.publicKey, signatureBytes)
  ) {
    return outcome(
      'INVALID',
      'signature-invalid',
      'Ed25519 signature does not verify over the exact canonical signing input',
      attestation.key_id,
    )
  }

  let signedAt: Date
  try {
    signedAt = parseTimestamp(attestation.issued_at)
  } catch (error) {
    return outcome(
      'INVALID',
      'issued-at-invalid',
      error instanceof Error ? error.message : 'issued_at is not an exact timestamp',
      attestation.key_id,
    )
  }

  const [state, code, message] = evaluateKeyLifecycle(key, signedAt, policy)
  return outcome(state, code, message, attestation.key_id)
}
