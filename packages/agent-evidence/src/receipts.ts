/**
 * receipts.ts — Public Action Receipt v1 (D2.0A protocol foundation).
 *
 * A receipt is a human-facing, OPT-IN, redacted projection of an Agent
 * Evidence run: what was proposed, what evidence existed, what was decided,
 * whether it executed, whether it settled, and what remains unknown. It is
 * NOT itself private evidence, and building one here NEVER makes any existing
 * Agent Evidence bundle public — publication is always an explicit, separate
 * act by whoever assembles a receipt's fields.
 *
 * Four independent statements live on every receipt, and none of them
 * collapses into the others:
 *   - PROOF:      did the signer assert this exact receipt content?
 *                 (VALID / INVALID / UNVERIFIABLE — see verifyReceiptEnvelope)
 *   - DECISION:   what did policy/mandate decide?      (ALLOW / REQUIRE_APPROVAL / BLOCK / UNKNOWN)
 *   - EXECUTION:  was the action actually submitted?    (NOT_SUBMITTED / SUBMITTED / CONFIRMED / FAILED / UNKNOWN)
 *   - SETTLEMENT: was value movement confirmed?          (CONFIRMED / NOT_CONFIRMED / UNVERIFIED / NOT_APPLICABLE)
 * A receipt reporting REQUIRE_APPROVAL / NOT_SUBMITTED / NOT_APPLICABLE with
 * PROOF: VALID is a perfectly normal, honest result — VALID means the proof
 * is genuine, not that the payment happened.
 *
 * SIGNING: this module builds and verifies receipts but never signs one
 * itself — it has no private key and never will. Producing `proof` is the
 * caller's job, via whatever already-live signing surface holds the key (in
 * production, a network call to the existing `POST /attest` endpoint with
 * `purpose: "public-action-receipt"` — see docs/PUBLIC_ACTION_RECEIPT_V1.md).
 * That keeps this package's existing guarantee intact: it never touches a
 * private key, in-process or otherwise.
 */
import { canonicalize, contentId, cloneJson } from './canonical.js'
import { EvidenceValidationError, SchemaValidationError } from './errors.js'
import { verifyAttestationV2, type AttestationV2Fields } from './attestationV2.js'
import { formatReceiptId } from './receiptId.js'
import { validateDocument } from './schema.js'
import type { TrustPolicy } from './trust.js'
import type { JsonObject, VerificationState } from './types.js'

export const PUBLIC_ACTION_RECEIPT_SCHEMA = 'onchaindiligence.public-action-receipt.v1'
export const PUBLIC_ACTION_RECEIPT_PURPOSE = 'public-action-receipt'
export const PUBLIC_ACTION_RECEIPT_ISSUER = 'https://api.onchaindiligence.com'

export type ReceiptType = 'PREFLIGHT' | 'COMMERCE' | 'ACTION'
export type DecisionStatus = 'ALLOW' | 'REQUIRE_APPROVAL' | 'BLOCK' | 'UNKNOWN'
export type ExecutionStatus = 'NOT_SUBMITTED' | 'SUBMITTED' | 'CONFIRMED' | 'FAILED' | 'UNKNOWN'
export type SettlementStatus = 'CONFIRMED' | 'NOT_CONFIRMED' | 'UNVERIFIED' | 'NOT_APPLICABLE'
export type CheckResult = 'PASS' | 'FAIL' | 'UNKNOWN' | 'NOT_CHECKED'

export interface ReceiptAction {
  kind: string
  resource: string | null
  network: string | null
  asset: string | null
  amount: string | null
  sender: string | null
  recipient: string | null
}

export interface ReceiptDecision {
  status: DecisionStatus
  authorized: boolean | null
  reasons: string[]
}

export interface ReceiptExecution {
  provider: string | null
  status: ExecutionStatus
  transaction_hash: string | null
  submitted_at: string | null
  confirmed_at: string | null
}

export interface ReceiptSettlement {
  status: SettlementStatus
  detail: string | null
}

export interface ReceiptCheck {
  id: string
  result: CheckResult
  summary: string
  evidence_digest: string | null
}

export interface ReceiptLinks {
  agent_evidence_bundle_digest: string | null
  preflight_receipt_id: string | null
}

/** Every receipt field EXCEPT `receipt_id` and `receipt_digest` — the digest input. */
export interface ReceiptCoreFields {
  receipt_type: ReceiptType
  issued_at: string
  action: ReceiptAction
  decision: ReceiptDecision
  execution: ReceiptExecution
  settlement: ReceiptSettlement
  checks: ReceiptCheck[]
  links: ReceiptLinks
  limitations: string[]
}

export interface Receipt extends ReceiptCoreFields {
  receipt_id: string
  receipt_digest: string
}

export interface PublicActionReceiptEnvelope {
  schema: typeof PUBLIC_ACTION_RECEIPT_SCHEMA
  receipt: Receipt
  proof: AttestationV2Fields
}

const DECISION_STATUSES: ReadonlySet<string> = new Set(['ALLOW', 'REQUIRE_APPROVAL', 'BLOCK', 'UNKNOWN'])
const EXECUTION_STATUSES: ReadonlySet<string> = new Set(['NOT_SUBMITTED', 'SUBMITTED', 'CONFIRMED', 'FAILED', 'UNKNOWN'])
const SETTLEMENT_STATUSES: ReadonlySet<string> = new Set(['CONFIRMED', 'NOT_CONFIRMED', 'UNVERIFIED', 'NOT_APPLICABLE'])
const RECEIPT_TYPES: ReadonlySet<string> = new Set(['PREFLIGHT', 'COMMERCE', 'ACTION'])
const CHECK_RESULTS: ReadonlySet<string> = new Set(['PASS', 'FAIL', 'UNKNOWN', 'NOT_CHECKED'])

/**
 * Assembles and lightly validates the receipt CORE (no id/digest yet — those
 * are computed FROM this object by `finalizeReceiptCore`, so they cannot be
 * inputs to it without creating a circular dependency). This performs cheap
 * structural/enum checks; the full JSON Schema is enforced once, on the
 * completed envelope, by `verifyReceiptEnvelope` (and should be by any
 * caller assembling one for signing).
 */
export function buildReceiptCore(fields: ReceiptCoreFields): ReceiptCoreFields {
  if (!RECEIPT_TYPES.has(fields.receipt_type)) {
    throw new EvidenceValidationError(`invalid receipt_type: ${fields.receipt_type}`)
  }
  if (!DECISION_STATUSES.has(fields.decision.status)) {
    throw new EvidenceValidationError(`invalid decision.status: ${fields.decision.status}`)
  }
  if (!EXECUTION_STATUSES.has(fields.execution.status)) {
    throw new EvidenceValidationError(`invalid execution.status: ${fields.execution.status}`)
  }
  if (!SETTLEMENT_STATUSES.has(fields.settlement.status)) {
    throw new EvidenceValidationError(`invalid settlement.status: ${fields.settlement.status}`)
  }
  for (const check of fields.checks) {
    if (!CHECK_RESULTS.has(check.result)) {
      throw new EvidenceValidationError(`invalid check result for "${check.id}": ${check.result}`)
    }
  }
  return cloneJson(fields as unknown as JsonObject) as unknown as ReceiptCoreFields
}

/** sha256 content digest over the RFC 8785 canonical JSON of the receipt core. Same algorithm as `contentId` elsewhere in this package. */
export function computeReceiptDigest(core: ReceiptCoreFields): string {
  return contentId(core)
}

/**
 * Adds `receipt_id` (derived from the digest) and `receipt_digest` to a
 * receipt core, producing the object a signer should sign. No circularity:
 * the digest is computed over the core WITHOUT these two fields, and the id
 * is derived from the digest, never the reverse.
 */
export function finalizeReceiptCore(core: ReceiptCoreFields): Receipt {
  const receipt_digest = computeReceiptDigest(core)
  const receipt_id = formatReceiptId(receipt_digest)
  return { ...cloneJson(core as unknown as JsonObject) as unknown as ReceiptCoreFields, receipt_id, receipt_digest }
}

/**
 * The exact bytes a `proof` must sign: RFC 8785 canonical JSON over
 * `{schema_version, issuer, purpose, data: receipt, issued_at, key_id}` —
 * identical in shape to every other `onchaindiligence.attestation.v2`
 * signing input in this product. Exposed so a real signer (which controls
 * `issued_at` and `key_id` itself, e.g. the `/attest` endpoint) or a test
 * fixture can compute exactly what to sign.
 */
export function receiptAttestationSigningInput(
  receipt: Receipt,
  fields: { issuer: string; purpose: string; issuedAt: string; keyId: string },
): Uint8Array {
  return canonicalize({
    schema_version: 'onchaindiligence.attestation.v2',
    issuer: fields.issuer,
    purpose: fields.purpose,
    data: receipt,
    issued_at: fields.issuedAt,
    key_id: fields.keyId,
  })
}

export interface ReceiptVerificationResult {
  state: VerificationState
  code: string
  message: string
  receipt?: Receipt
  keyId?: string
}

function fail(code: string, message: string): ReceiptVerificationResult {
  return { state: 'INVALID', code, message }
}

/**
 * Full tri-state verification of a public receipt envelope, independent of
 * everything the receipt *reports* (decision/execution/settlement are just
 * data at this point — this function only answers "did the signer assert
 * this exact content, from a key I currently trust?").
 *
 * Order of checks, each fail-closed:
 *   1. envelope conforms to the public-action-receipt.v1 schema  -> INVALID
 *   2. receipt_digest matches a fresh recomputation                -> INVALID
 *   3. receipt_id matches formatReceiptId(receipt_digest)          -> INVALID
 *   4. onchaindiligence.attestation.v2 signature verifies against
 *      the caller-supplied `policy` (never embedded key material),
 *      and the signing key's lifecycle covers `proof.issued_at`     -> VALID / INVALID / UNVERIFIABLE
 */
export function verifyReceiptEnvelope(
  envelope: unknown,
  policy: TrustPolicy,
  options: { expectedIssuer?: string; expectedPurpose?: string } = {},
): ReceiptVerificationResult {
  try {
    validateDocument('public-action-receipt.schema.json', envelope)
  } catch (error) {
    if (error instanceof SchemaValidationError) return fail('schema-invalid', error.message)
    throw error
  }
  const parsed = envelope as PublicActionReceiptEnvelope
  const receipt = parsed.receipt

  const { receipt_id, receipt_digest, ...core } = receipt
  const recomputedDigest = computeReceiptDigest(core as ReceiptCoreFields)
  if (recomputedDigest !== receipt_digest) {
    return fail('digest-mismatch', 'receipt_digest does not match a fresh digest of the receipt content')
  }
  const recomputedId = formatReceiptId(recomputedDigest)
  if (recomputedId !== receipt_id) {
    return fail('id-mismatch', 'receipt_id does not match formatReceiptId(receipt_digest)')
  }

  const verification = verifyAttestationV2(receipt, parsed.proof, policy, {
    expectedIssuer: options.expectedIssuer ?? PUBLIC_ACTION_RECEIPT_ISSUER,
    expectedPurpose: options.expectedPurpose ?? PUBLIC_ACTION_RECEIPT_PURPOSE,
  })
  return {
    state: verification.state,
    code: verification.code,
    message: verification.message,
    receipt,
    ...(verification.keyId !== undefined ? { keyId: verification.keyId } : {}),
  }
}
