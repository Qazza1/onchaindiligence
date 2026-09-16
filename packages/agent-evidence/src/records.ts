import { BUNDLE_VERSION, RECORD_VERSION } from './constants.js'
import { cloneJson, contentId, formatTimestamp } from './canonical.js'
import { EvidenceValidationError, SchemaValidationError } from './errors.js'
import { validateBundlePayload } from './graph.js'
import { validateDocument } from './schema.js'
import type { AgentEvidenceRecord, BundlePayload, JsonObject, JsonValue, RecordKind } from './types.js'

function timestamp(value: string | Date): string {
  return value instanceof Date ? formatTimestamp(value) : value
}

function nullableTimestamp(value: string | Date | null): string | null {
  return value === null ? null : timestamp(value)
}

function requireKind(record: AgentEvidenceRecord, kind: RecordKind, field: string): void {
  if (record.kind !== kind) {
    throw new EvidenceValidationError(`${field} must reference a '${kind}' record, got '${record.kind}'`)
  }
}

/** `{sha256: <base64url>}` shape used by request/response/policy digests -- not `contentId`'s `sha256:`-prefixed string. Private: not part of this package's public API. */
function digestObject(value: JsonValue): { sha256: string } {
  return { sha256: contentId(value).slice('sha256:'.length) }
}

export interface CreateRecordOptions {
  parents?: readonly string[]
  proofs?: readonly JsonObject[]
}

export function createRecord(
  kind: RecordKind,
  statement: JsonObject,
  options: CreateRecordOptions = {},
): AgentEvidenceRecord {
  const body = {
    record_version: RECORD_VERSION,
    kind,
    parents: [...new Set(options.parents ?? [])].sort(),
    statement: cloneJson(statement),
    proofs: cloneJson([...(options.proofs ?? [])] as JsonValue[]) as JsonObject[],
  }
  const record = { id: contentId(body), ...body }
  try {
    validateDocument('record.schema.json', record)
  } catch (error) {
    if (error instanceof SchemaValidationError) throw new EvidenceValidationError(error.message, { cause: error })
    throw error
  }
  return record
}

export interface CreateBundlePayloadOptions {
  createdAt: string | Date
  runId?: string
  rootIds?: readonly string[]
  /** Asserted bundle assembler identity. This is not a signing trust root. */
  issuer?: string
  /** Existing v0 reconciliation summary; every record reference is validated. */
  reconciliation?: JsonObject
  /** Publisher-asserted limitations retained separately from proof results. */
  limitations?: readonly string[]
  extensions?: JsonObject
}

export function createBundlePayload(
  inputRecords: Iterable<AgentEvidenceRecord>,
  options: CreateBundlePayloadOptions,
): BundlePayload {
  const records = [...inputRecords].map((record) => cloneJson(record as unknown as JsonValue) as unknown as AgentEvidenceRecord)
  records.sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0)
  const runs = records.filter((record) => record.kind === 'run')
  const runId = options.runId ?? (runs.length === 1 ? runs[0]?.id : undefined)
  if (!runId) throw new EvidenceValidationError('run_id can only be inferred when exactly one run exists')
  const parentIds = new Set(records.flatMap((record) => record.parents))
  const computedRoots = records.map((record) => record.id).filter((id) => !parentIds.has(id)).sort()
  const createdAt = options.createdAt instanceof Date ? formatTimestamp(options.createdAt) : options.createdAt
  const withoutId = {
    bundle_version: BUNDLE_VERSION,
    created_at: createdAt,
    ...(options.issuer === undefined ? {} : { issuer: options.issuer }),
    run_id: runId,
    root_ids: [...(options.rootIds ?? computedRoots)],
    records,
    ...(options.reconciliation === undefined ? {} : {
      reconciliation: cloneJson(options.reconciliation as JsonValue) as JsonObject,
    }),
    ...(options.limitations === undefined ? {} : {
      limitations: cloneJson([...options.limitations] as JsonValue) as string[],
    }),
    extensions: cloneJson((options.extensions ?? {}) as JsonValue) as JsonObject,
  }
  const payload: BundlePayload = {
    bundle_version: BUNDLE_VERSION,
    bundle_id: contentId(withoutId),
    created_at: createdAt,
    ...(withoutId.issuer === undefined ? {} : { issuer: withoutId.issuer }),
    run_id: runId,
    root_ids: withoutId.root_ids,
    records,
    ...(withoutId.reconciliation === undefined ? {} : { reconciliation: withoutId.reconciliation }),
    ...(withoutId.limitations === undefined ? {} : { limitations: withoutId.limitations }),
    extensions: withoutId.extensions,
  }
  validateBundlePayload(payload)
  return payload
}

// ---------------------------------------------------------------------------
// First-class construction helpers for Mandate, Policy, and Decision.
//
// These are convenience constructors over the existing canonical record
// model, not a second representation: each one builds the exact `statement`
// object and `parents` list a caller would otherwise write by hand, then
// calls the same createRecord() used everywhere else. No new fields, no
// schema changes, no inferred facts -- every derived value (a parent's own
// id, a policy's own digest) is copied from a record the caller already
// constructed and passed in, never invented. See AGENT_EVIDENCE_V0.md
// sections 6.3, 6.6, and 6.7 for the normative parent/reference rules this
// mirrors, and graph.ts for where they are actually enforced.

export interface CreateMandateRecordOptions extends CreateRecordOptions {}

export interface CreateMandateRecordInput {
  /** The delegating principal. Mandate parents are exactly this record's id. */
  principal: AgentEvidenceRecord
  mandateId: string
  scope: JsonObject
  validFrom: string | Date
  validUntil: string | Date
  limits?: JsonObject
  policyRefs?: readonly string[]
  authorizationRef?: string
  authorizationDigest?: { sha256: string }
}

/**
 * Build a `kind: "mandate"` record. Parents are derived from `principal`,
 * matching the rule graph.ts enforces: mandate parents must include, and may
 * only be, principal records.
 */
export function createMandateRecord(
  input: CreateMandateRecordInput,
  options: CreateMandateRecordOptions = {},
): AgentEvidenceRecord {
  requireKind(input.principal, 'principal', 'principal')
  const statement: JsonObject = {
    mandate_id: input.mandateId,
    principal_ref: input.principal.id,
    scope: input.scope,
    valid_from: timestamp(input.validFrom),
    valid_until: timestamp(input.validUntil),
    ...(input.limits === undefined ? {} : { limits: input.limits }),
    ...(input.policyRefs === undefined ? {} : { policy_refs: [...input.policyRefs] }),
    ...(input.authorizationRef === undefined ? {} : { authorization_ref: input.authorizationRef }),
    ...(input.authorizationDigest === undefined ? {} : { authorization_digest: input.authorizationDigest }),
  }
  return createRecord('mandate', statement, { ...options, parents: [input.principal.id] })
}

export interface CreatePolicyRecordOptions extends CreateRecordOptions {}

export interface CreatePolicyRecordInput {
  /** The run(s) and/or mandate(s) this policy is associated with. At least one, run or mandate kind only. */
  parents: readonly AgentEvidenceRecord[]
  policyId: string
  version: string
  source: string
  effectiveFrom: string | Date
  effectiveUntil?: string | Date
  /** The embedded policy value, if any. When provided without `digest`, the digest is derived from it. */
  policy?: JsonValue
  /**
   * Digest of the exact policy bytes/object a decision claims to have used.
   * Required unless `policy` is provided, in which case it is derived from
   * `policy` -- never silently substituted if the caller supplies both.
   */
  digest?: { sha256: string }
}

/**
 * Build a `kind: "policy"` record. Parents are the supplied run/mandate
 * records; when `policy` is embedded and `digest` is omitted, the digest is
 * computed the same way graph.ts verifies it (`contentId(policy)` without the
 * `sha256:` prefix), so the two can never silently drift apart.
 */
export function createPolicyRecord(
  input: CreatePolicyRecordInput,
  options: CreatePolicyRecordOptions = {},
): AgentEvidenceRecord {
  if (input.parents.length === 0) {
    throw new EvidenceValidationError('policy requires at least one run or mandate parent')
  }
  for (const parent of input.parents) {
    if (parent.kind !== 'run' && parent.kind !== 'mandate') {
      throw new EvidenceValidationError(`policy parents must be 'run' or 'mandate' records, got '${parent.kind}'`)
    }
  }
  const embeddedDigest = input.policy === undefined ? undefined : digestObject(input.policy)
  if (input.digest !== undefined && embeddedDigest !== undefined
    && input.digest.sha256 !== embeddedDigest.sha256) {
    throw new EvidenceValidationError('policy `digest` does not match the embedded `policy` value')
  }
  const digest = input.digest ?? embeddedDigest
  if (digest === undefined) throw new EvidenceValidationError('policy requires `digest` when no `policy` value is embedded')
  const statement: JsonObject = {
    policy_id: input.policyId,
    version: input.version,
    digest,
    source: input.source,
    effective_from: timestamp(input.effectiveFrom),
    ...(input.effectiveUntil === undefined ? {} : { effective_until: timestamp(input.effectiveUntil) }),
    ...(input.policy === undefined ? {} : { policy: input.policy }),
  }
  return createRecord('policy', statement, {
    ...options,
    parents: input.parents.map((parent) => parent.id),
  })
}

export interface CreateDecisionRecordOptions extends CreateRecordOptions {}

export interface CreateDecisionRecordInput {
  run: AgentEvidenceRecord
  agent: AgentEvidenceRecord
  policy: AgentEvidenceRecord
  /** At least one evidence record; every one becomes a parent and an evidence_refs entry. */
  evidence: readonly AgentEvidenceRecord[]
  decisionId: string
  decisionType: string
  outcome: JsonValue
  decidedAt: string | Date
}

/**
 * Build a `kind: "decision"` record. `policy_ref`/`policy_digest` are copied
 * from `policy` (never re-derived or re-typed by the caller), `evidence_refs`
 * preserves the caller's own ordering, and parents are exactly the sorted
 * unique union of run, policy, and evidence ids -- matching graph.ts's
 * "decision parents must exactly equal run, policy, and evidence references"
 * check by construction rather than by the caller getting the union right.
 */
export function createDecisionRecord(
  input: CreateDecisionRecordInput,
  options: CreateDecisionRecordOptions = {},
): AgentEvidenceRecord {
  requireKind(input.run, 'run', 'run')
  requireKind(input.agent, 'agent', 'agent')
  requireKind(input.policy, 'policy', 'policy')
  if (input.evidence.length === 0) throw new EvidenceValidationError('decision requires at least one evidence record')
  for (const evidence of input.evidence) requireKind(evidence, 'evidence', 'evidence')
  const evidenceRefs = input.evidence.map((evidence) => evidence.id)
  const statement: JsonObject = {
    decision_id: input.decisionId,
    run_ref: input.run.id,
    agent_ref: input.agent.id,
    decision_type: input.decisionType,
    outcome: input.outcome,
    evidence_refs: evidenceRefs,
    policy_ref: input.policy.id,
    // Schema-required on any policy record that already passed createRecord's
    // own validation, so this is a copy of an established fact, not a guess.
    policy_digest: input.policy.statement.digest as JsonValue,
    decided_at: timestamp(input.decidedAt),
  }
  return createRecord('decision', statement, {
    ...options,
    parents: [input.run.id, input.policy.id, ...evidenceRefs],
  })
}

export interface CreateEvidenceRecordOptions extends CreateRecordOptions {}

export interface EvidenceRequestInput {
  mediaType: string
  /** The actual request value, if available; `digest` is derived from it when omitted. */
  value?: JsonValue
  /** Required unless `value` is given. If both are given, they must agree. */
  digest?: { sha256: string }
}

/**
 * `response` has no embedded/reference field until `mode` is known -- this is
 * a true discriminated union, matching evidenceStatement's own `if/then`
 * schema split exactly: embedded requires `value` and forbids `reference`;
 * reference requires `reference` and forbids `value`.
 */
export type EvidenceResponseInput =
  | { mode: 'embedded'; mediaType: string; value: JsonValue; digest?: { sha256: string } }
  | { mode: 'reference'; mediaType: string; reference: string; digest: { sha256: string } }

export interface CreateEvidenceRecordInput {
  /** parents always include this run's id. */
  run: AgentEvidenceRecord
  /** Optional prior evidence this record builds on; each becomes an additional parent. */
  priorEvidence?: readonly AgentEvidenceRecord[]
  evidenceType: string
  trustMode: 'publisher-signed' | 'local-witness' | 'managed-witness' | 'agent-assertion'
  source: { id: string; type: string }
  tool: { name: string; version: string }
  request: EvidenceRequestInput
  response: EvidenceResponseInput
  observedAt: string | Date
  expiresAt: string | Date | null
  scope: JsonObject
}

function resolveDigest(
  value: JsonValue | undefined,
  explicit: { sha256: string } | undefined,
  field: string,
): { sha256: string } {
  const derived = value === undefined ? undefined : digestObject(value)
  if (explicit !== undefined && derived !== undefined && explicit.sha256 !== derived.sha256) {
    throw new EvidenceValidationError(`${field} \`digest\` does not match the derived digest of \`value\``)
  }
  const digest = explicit ?? derived
  if (digest === undefined) throw new EvidenceValidationError(`${field} requires \`digest\` when no \`value\` is available to derive it from`)
  return digest
}

/**
 * Build a `kind: "evidence"` record. Parents are the supplied `run` plus any
 * `priorEvidence`, matching graph.ts's rule that evidence parents must
 * include run_ref and may only be run or evidence records. Request/response
 * digests are derived from the caller's own `value` where available, and
 * checked (never silently overridden) when an explicit digest is also given.
 */
export function createEvidenceRecord(
  input: CreateEvidenceRecordInput,
  options: CreateEvidenceRecordOptions = {},
): AgentEvidenceRecord {
  requireKind(input.run, 'run', 'run')
  const priorEvidence = input.priorEvidence ?? []
  for (const evidence of priorEvidence) requireKind(evidence, 'evidence', 'priorEvidence')

  const requestDigest = resolveDigest(input.request.value, input.request.digest, 'request')
  const response = input.response
  const responseStatement: JsonObject = response.mode === 'embedded'
    ? {
      mode: 'embedded',
      media_type: response.mediaType,
      value: response.value,
      digest: resolveDigest(response.value, response.digest, 'response'),
    }
    : {
      mode: 'reference',
      media_type: response.mediaType,
      reference: response.reference,
      // No `value` exists in reference mode to derive a digest from, so this
      // reduces to "require an explicit digest" -- reusing resolveDigest
      // keeps that failure message consistent with the embedded branch
      // instead of falling through to a lower-level canonicalization error.
      digest: resolveDigest(undefined, response.digest, 'response'),
    }

  const statement: JsonObject = {
    evidence_type: input.evidenceType,
    run_ref: input.run.id,
    trust_mode: input.trustMode,
    source: input.source,
    tool: input.tool,
    request: { digest: requestDigest, media_type: input.request.mediaType },
    response: responseStatement,
    observed_at: timestamp(input.observedAt),
    expires_at: nullableTimestamp(input.expiresAt),
    scope: input.scope,
  }
  return createRecord('evidence', statement, {
    ...options,
    parents: [input.run.id, ...priorEvidence.map((evidence) => evidence.id)],
  })
}

export interface CreateRunRecordOptions extends CreateRecordOptions {}

export interface CreateRunRecordInput {
  /** Parents are exactly this record's id plus `mandate`'s. */
  agent: AgentEvidenceRecord
  /** Parents are exactly this record's id plus `agent`'s. */
  mandate: AgentEvidenceRecord
  runExternalId: string
  startedAt: string | Date
  endedAt?: string | Date
}

/**
 * Build a `kind: "run"` record. Parents are derived from `agent` and
 * `mandate`, matching the rule graph.ts enforces exactly: run parents must be
 * exactly `agent_ref` and `mandate_ref`, no more and no fewer. `ended_at` is
 * never inferred -- omit it, don't guess it.
 */
export function createRunRecord(
  input: CreateRunRecordInput,
  options: CreateRunRecordOptions = {},
): AgentEvidenceRecord {
  requireKind(input.agent, 'agent', 'agent')
  requireKind(input.mandate, 'mandate', 'mandate')
  const statement: JsonObject = {
    run_external_id: input.runExternalId,
    agent_ref: input.agent.id,
    mandate_ref: input.mandate.id,
    started_at: timestamp(input.startedAt),
    ...(input.endedAt === undefined ? {} : { ended_at: timestamp(input.endedAt) }),
  }
  return createRecord('run', statement, { ...options, parents: [input.agent.id, input.mandate.id] })
}
