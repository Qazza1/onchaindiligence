/** Portable, platform-signed payment execution assertions. This module does
 * not issue OCD receipts and does not infer authorization or settlement. */
import { verify as ed25519Verify } from 'node:crypto'
import { canonicalize, cloneJson, contentId, formatTimestamp, parseJson, parseTimestamp } from './canonical.js'
import { dssePae } from './dsse.js'
import { EvidenceValidationError, ParseError, SchemaValidationError, SigningError } from './errors.js'
import { validateDocument } from './schema.js'
import { evaluateKeyLifecycle, type TrustPolicy } from './trust.js'
import type { DsseEnvelope, JsonObject, JsonValue, VerificationState } from './types.js'

export const SIGNED_PAYMENT_CLAIM_VERSION = 'onchaindiligence.signed-claim.payment.v1' as const
export const SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE =
  'application/vnd.onchaindiligence.signed-claim.payment.v1+json' as const
export const PLATFORM_CLAIM_SIGNATURE_SCOPE = 'PLATFORM_CLAIM_SIGNATURE' as const

const LIMITATION = 'Proves only that a key trusted for this issuer signed this exact claim; not settlement, authorization, delivery, safety or compliance.'
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/

export type PaymentClaimedStatus = 'SUBMITTED' | 'SUCCEEDED' | 'FAILED' | 'UNKNOWN'

export interface SignedPaymentClaim {
  claim_version: typeof SIGNED_PAYMENT_CLAIM_VERSION
  claim_id: string
  issuer: { id: string; name?: string }
  issued_at: string
  provider_reference: string
  payment: { network: string; asset?: string; amount?: string; sender?: string; recipient?: string }
  execution: { claimed_status: PaymentClaimedStatus; transaction_hash?: string }
  links?: {
    ocd_operation_id?: string | null
    ocd_execution_request_id?: string | null
    ocd_preflight_receipt_id?: string | null
    client_submission_key?: string | null
  }
  evidence_digest?: { sha256: string }
  extensions: JsonObject
}

export interface CreateSignedPaymentClaimInput {
  issuer: SignedPaymentClaim['issuer']
  issuedAt?: string | Date
  providerReference: string
  payment: SignedPaymentClaim['payment']
  execution: SignedPaymentClaim['execution']
  links?: SignedPaymentClaim['links']
  evidenceDigest?: SignedPaymentClaim['evidence_digest']
  extensions?: JsonObject
}

export interface PaymentClaimSigner {
  keyId: string
  sign(bytes: Uint8Array): Uint8Array | Promise<Uint8Array>
}

export interface PaymentClaimVerificationResult {
  state: VerificationState
  scope: typeof PLATFORM_CLAIM_SIGNATURE_SCOPE
  issuer?: string
  key_id?: string
  claim_id?: string
  code: string
  message: string
  limitations: [string]
}

function result(
  state: VerificationState,
  code: string,
  message: string,
  fields: Partial<Pick<PaymentClaimVerificationResult, 'issuer' | 'key_id' | 'claim_id'>> = {},
): PaymentClaimVerificationResult {
  return { state, scope: PLATFORM_CLAIM_SIGNATURE_SCOPE, code, message, limitations: [LIMITATION], ...fields }
}

function assertHttpsOrigin(value: string): void {
  try {
    const url = new URL(value)
    if (url.protocol !== 'https:' || url.origin !== value) throw new Error('not an HTTPS origin')
  } catch {
    throw new EvidenceValidationError('issuer.id must be an exact HTTPS origin')
  }
}

function validateClaim(value: unknown): SignedPaymentClaim {
  try {
    validateDocument('signed-claim-payment.v1.schema.json', value)
    const claim = value as SignedPaymentClaim
    assertHttpsOrigin(claim.issuer.id)
    parseTimestamp(claim.issued_at)
    return claim
  } catch (error) {
    if (error instanceof EvidenceValidationError || error instanceof SchemaValidationError) throw error
    throw new EvidenceValidationError(error instanceof Error ? error.message : 'invalid signed payment claim')
  }
}

/** Build the deterministic public payload. claim_id covers every field except itself. */
export function createSignedPaymentClaim(input: CreateSignedPaymentClaimInput): SignedPaymentClaim {
  assertHttpsOrigin(input.issuer.id)
  const core: Omit<SignedPaymentClaim, 'claim_id'> = {
    claim_version: SIGNED_PAYMENT_CLAIM_VERSION,
    issuer: cloneJson(input.issuer as unknown as JsonObject) as unknown as SignedPaymentClaim['issuer'],
    issued_at: input.issuedAt === undefined ? formatTimestamp(new Date()) : input.issuedAt instanceof Date ? formatTimestamp(input.issuedAt) : input.issuedAt,
    provider_reference: input.providerReference,
    payment: cloneJson(input.payment as unknown as JsonObject) as unknown as SignedPaymentClaim['payment'],
    execution: cloneJson(input.execution as unknown as JsonObject) as unknown as SignedPaymentClaim['execution'],
    extensions: cloneJson((input.extensions ?? {}) as JsonObject),
  }
  if (input.links !== undefined) {
    core.links = cloneJson(input.links as unknown as JsonObject) as NonNullable<SignedPaymentClaim['links']>
  }
  if (input.evidenceDigest !== undefined) {
    core.evidence_digest = cloneJson(input.evidenceDigest as unknown as JsonObject) as NonNullable<SignedPaymentClaim['evidence_digest']>
  }
  const claim = { ...core, claim_id: contentId(core as unknown as JsonValue) }
  return cloneJson(validateClaim(claim) as unknown as JsonObject) as unknown as SignedPaymentClaim
}

/** DSSE v1 signing over RFC8785 claim bytes. The callback owns all private-key access. */
export async function signSignedPaymentClaim(claim: SignedPaymentClaim, signer: PaymentClaimSigner): Promise<DsseEnvelope> {
  const validated = validateClaim(claim)
  const { claim_id, ...core } = validated
  if (claim_id !== contentId(core as unknown as JsonValue)) {
    throw new SigningError('claim_id does not match the canonical payload without claim_id')
  }
  const payload = canonicalize(validated as unknown as JsonValue)
  const signature = Buffer.from(await signer.sign(dssePae(SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE, payload)))
  if (signature.length !== 64) throw new SigningError('signer did not return a 64-byte Ed25519 signature')
  const envelope: DsseEnvelope = {
    payloadType: SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE,
    payload: Buffer.from(payload).toString('base64'),
    signatures: [{ keyid: signer.keyId, sig: signature.toString('base64') }],
  }
  try {
    validateDocument('dsse-envelope.schema.json', envelope)
  } catch (error) {
    throw new SigningError(error instanceof Error ? error.message : 'invalid DSSE envelope')
  }
  return envelope
}

function decodeBase64(value: unknown, label: string): Buffer {
  if (typeof value !== 'string' || !BASE64.test(value)) throw new ParseError(`${label} is not strict padded base64`)
  const bytes = Buffer.from(value, 'base64')
  if (bytes.toString('base64') !== value) throw new ParseError(`${label} is not canonical padded base64`)
  return bytes
}

/** Offline tri-state verification. Keys are only read from caller-supplied TrustPolicy. */
export function verifySignedPaymentClaim(
  envelope: unknown,
  policy: TrustPolicy,
  options: { expectedIssuer?: string } = {},
): PaymentClaimVerificationResult {
  try {
    validateDocument('dsse-envelope.schema.json', envelope)
  } catch (error) {
    return result('INVALID', 'schema-invalid', error instanceof Error ? error.message : 'claim envelope schema is invalid')
  }
  const dsse = envelope as DsseEnvelope
  if (dsse.payloadType !== SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE) {
    return result('INVALID', 'payload-type-mismatch', 'DSSE payloadType is not Signed Payment Claim v1')
  }
  if (dsse.signatures.length !== 1) return result('INVALID', 'signature-count-invalid', 'Signed Payment Claim v1 requires exactly one signature')
  const signatureEntry = dsse.signatures[0]
  if (!signatureEntry) return result('INVALID', 'signature-count-invalid', 'Signed Payment Claim v1 requires exactly one signature')
  let payloadBytes: Buffer
  let claim: SignedPaymentClaim
  try {
    payloadBytes = decodeBase64(dsse.payload, 'DSSE payload')
    const parsed = parseJson(payloadBytes)
    if (parsed === null || Array.isArray(parsed) || typeof parsed !== 'object') throw new ParseError('claim payload must be a JSON object')
    claim = validateClaim(parsed)
    if (!Buffer.from(canonicalize(claim as unknown as JsonValue)).equals(payloadBytes)) {
      return result('INVALID', 'payload-not-rfc8785', 'DSSE payload is not RFC8785 canonical JSON')
    }
  } catch (error) {
    return result('INVALID', 'payload-invalid', error instanceof Error ? error.message : 'claim payload is invalid')
  }
  const fields = { issuer: claim.issuer.id, claim_id: claim.claim_id, key_id: signatureEntry.keyid }
  if (options.expectedIssuer !== undefined && claim.issuer.id !== options.expectedIssuer) {
    return result('INVALID', 'issuer-mismatch', 'claim issuer does not match the caller-pinned issuer', fields)
  }
  const { claim_id, ...core } = claim
  if (claim_id !== contentId(core as unknown as JsonValue)) {
    return result('INVALID', 'claim-id-mismatch', 'claim_id does not match RFC8785 canonical payload without claim_id', fields)
  }
  const key = policy.key(signatureEntry.keyid)
  if (!key) return result('UNVERIFIABLE', 'key-not-trusted', 'signing key is absent from caller-supplied trust', fields)
  let signature: Buffer
  try {
    signature = decodeBase64(signatureEntry.sig, 'DSSE signature')
  } catch (error) {
    return result('INVALID', 'signature-encoding', error instanceof Error ? error.message : 'signature is invalid', fields)
  }
  if (signature.length !== 64 || !ed25519Verify(null, dssePae(SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE, payloadBytes), key.publicKey, signature)) {
    return result('INVALID', 'signature-invalid', 'Ed25519 signature does not verify over Signed Payment Claim DSSE PAE bytes', fields)
  }
  let issuedAt: Date
  try {
    issuedAt = parseTimestamp(claim.issued_at)
  } catch (error) {
    return result('INVALID', 'issued-at-invalid', error instanceof Error ? error.message : 'issued_at is invalid', fields)
  }
  const [state, code, message] = evaluateKeyLifecycle(key, issuedAt, policy)
  return result(state, code, message, fields)
}
