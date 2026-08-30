import { contentId, parseTimestamp } from './canonical.js'
import { EvidenceValidationError, ParseError, SchemaValidationError } from './errors.js'
import { validateDocument } from './schema.js'
import type { AgentEvidenceRecord, BundlePayload, JsonObject } from './types.js'

function fail(message: string): never {
  throw new EvidenceValidationError(message)
}

function requireRecord(
  byId: Map<string, AgentEvidenceRecord>,
  recordId: unknown,
  kind: AgentEvidenceRecord['kind'],
  field: string,
): AgentEvidenceRecord {
  if (typeof recordId !== 'string' || !byId.has(recordId)) fail(`${field} does not resolve in this bundle`)
  const record = byId.get(recordId)
  if (!record || record.kind !== kind) fail(`${field} must resolve to a ${kind} record`)
  return record
}

function assertInterval(start: unknown, end: unknown, label: string): void {
  if (typeof start !== 'string' || typeof end !== 'string') return
  try {
    if (parseTimestamp(end).getTime() < parseTimestamp(start).getTime()) fail(`${label} end precedes start`)
  } catch (error) {
    if (error instanceof EvidenceValidationError) throw error
    if (error instanceof ParseError) fail(`${label} contains an invalid timestamp: ${error.message}`)
    throw error
  }
}

function digestValue(value: unknown): string {
  return contentId(value).slice('sha256:'.length)
}

function validateEmbeddedDigests(record: AgentEvidenceRecord): void {
  const statement = record.statement
  if (record.kind === 'evidence') {
    const response = statement.response as JsonObject
    if (response.mode === 'embedded') {
      const digest = response.digest as JsonObject
      if (digest.sha256 !== digestValue(response.value)) fail('embedded evidence response digest does not match value')
    }
  }
  if (record.kind === 'policy' && Object.hasOwn(statement, 'policy')) {
    const digest = statement.digest as JsonObject
    if (digest.sha256 !== digestValue(statement.policy)) fail('embedded policy digest does not match policy value')
  }
}

function values(record: AgentEvidenceRecord, field: string): string[] {
  const value = record.statement[field]
  return Array.isArray(value) ? value as string[] : []
}

export function validateBundlePayload(input: BundlePayload | Record<string, unknown>): void {
  const payload = input as BundlePayload
  try {
    validateDocument('bundle-payload.schema.json', payload)
  } catch (error) {
    if (error instanceof SchemaValidationError) throw new EvidenceValidationError(error.message, { cause: error })
    throw error
  }

  const records = payload.records
  const ids = records.map((record) => record.id)
  if (ids.join('\u0000') !== [...ids].sort().join('\u0000')) fail('records must be sorted lexicographically by id')
  if (new Set(ids).size !== ids.length) fail('record ids must be unique')
  const byId = new Map(records.map((record) => [record.id, record]))

  for (const record of records) {
    const { id, ...body } = record
    if (contentId(body) !== id) fail(`record id mismatch: ${id}`)
    const sortedParents = [...new Set(record.parents)].sort()
    if (record.parents.join('\u0000') !== sortedParents.join('\u0000')) {
      fail(`parents must be sorted and unique: ${id}`)
    }
    for (const parent of record.parents) {
      if (parent === id) fail(`record cannot parent itself: ${id}`)
      if (!byId.has(parent)) fail(`missing parent ${parent} referenced by ${id}`)
    }
    validateEmbeddedDigests(record)
  }

  const runs = records.filter((record) => record.kind === 'run')
  if (runs.length !== 1) fail('a v0 bundle must contain exactly one run record')
  if (payload.run_id !== runs[0]?.id) fail("run_id must resolve to the bundle's single run record")

  const parentIds = new Set(records.flatMap((record) => record.parents))
  const expectedRoots = ids.filter((id) => !parentIds.has(id)).sort()
  if (payload.root_ids.join('\u0000') !== expectedRoots.join('\u0000')) {
    fail('root_ids must equal the complete sorted set of records with no children')
  }

  const visiting = new Set<string>()
  const visited = new Set<string>()
  const visit = (recordId: string): void => {
    if (visiting.has(recordId)) fail(`cycle detected at ${recordId}`)
    if (visited.has(recordId)) return
    visiting.add(recordId)
    for (const parent of byId.get(recordId)?.parents ?? []) visit(parent)
    visiting.delete(recordId)
    visited.add(recordId)
  }
  for (const root of expectedRoots) visit(root)
  if (visited.size !== ids.length) fail('every record must be reachable from the complete root set')

  for (const record of records) {
    const statement = record.statement
    const parents = record.parents
    if (record.kind === 'principal') {
      if (parents.length) fail('principal records cannot have parents')
    } else if (record.kind === 'agent') {
      const operator = statement.operator_ref
      if (operator !== undefined) {
        requireRecord(byId, operator, 'principal', 'agent.operator_ref')
        if (!parents.includes(String(operator))) fail('agent parents must include operator_ref')
      }
      if (parents.some((parent) => byId.get(parent)?.kind !== 'principal')) {
        fail('agent parents may only be principal records')
      }
    } else if (record.kind === 'mandate') {
      const principal = String(statement.principal_ref)
      requireRecord(byId, principal, 'principal', 'mandate.principal_ref')
      if (!parents.includes(principal)) fail('mandate parents must include principal_ref')
      if (parents.some((parent) => byId.get(parent)?.kind !== 'principal')) {
        fail('mandate parents may only be principal records')
      }
      assertInterval(statement.valid_from, statement.valid_until, 'mandate')
    } else if (record.kind === 'run') {
      const agent = String(statement.agent_ref)
      const mandate = String(statement.mandate_ref)
      requireRecord(byId, agent, 'agent', 'run.agent_ref')
      const mandateRecord = requireRecord(byId, mandate, 'mandate', 'run.mandate_ref')
      if (parents.join('\u0000') !== [agent, mandate].sort().join('\u0000')) {
        fail('run parents must be exactly agent_ref and mandate_ref')
      }
      if (statement.ended_at !== undefined) assertInterval(statement.started_at, statement.ended_at, 'run')
      const started = parseTimestamp(String(statement.started_at)).getTime()
      const mandateStatement = mandateRecord.statement
      if (
        started < parseTimestamp(String(mandateStatement.valid_from)).getTime()
        || started > parseTimestamp(String(mandateStatement.valid_until)).getTime()
      ) fail('run.started_at is outside the presented mandate interval')
    } else if (record.kind === 'evidence') {
      const runRef = String(statement.run_ref)
      requireRecord(byId, runRef, 'run', 'evidence.run_ref')
      if (!parents.includes(runRef)) fail('evidence parents must include run_ref')
      if (parents.some((parent) => !['run', 'evidence'].includes(byId.get(parent)?.kind ?? ''))) {
        fail('evidence parents may only be run or evidence records')
      }
      if (statement.expires_at !== null) assertInterval(statement.observed_at, statement.expires_at, 'evidence')
    } else if (record.kind === 'policy') {
      if (!parents.some((parent) => ['run', 'mandate'].includes(byId.get(parent)?.kind ?? ''))) {
        fail('policy parents must include a run or mandate')
      }
      if (parents.some((parent) => !['run', 'mandate'].includes(byId.get(parent)?.kind ?? ''))) {
        fail('policy parents may only be run or mandate records')
      }
      if (statement.effective_until !== undefined) {
        assertInterval(statement.effective_from, statement.effective_until, 'policy')
      }
    } else if (record.kind === 'decision') {
      const runRef = String(statement.run_ref)
      const policyRef = String(statement.policy_ref)
      const agentRef = String(statement.agent_ref)
      requireRecord(byId, runRef, 'run', 'decision.run_ref')
      requireRecord(byId, agentRef, 'agent', 'decision.agent_ref')
      const policyRecord = requireRecord(byId, policyRef, 'policy', 'decision.policy_ref')
      for (const evidenceRef of values(record, 'evidence_refs')) {
        requireRecord(byId, evidenceRef, 'evidence', 'decision.evidence_refs')
      }
      const expected = [...new Set([runRef, policyRef, ...values(record, 'evidence_refs')])].sort()
      if (parents.join('\u0000') !== expected.join('\u0000')) {
        fail('decision parents must exactly equal run, policy, and evidence references')
      }
      if (JSON.stringify(statement.policy_digest) !== JSON.stringify(policyRecord.statement.digest)) {
        fail('decision.policy_digest does not match the referenced policy')
      }
      const decidedAt = parseTimestamp(String(statement.decided_at)).getTime()
      const policyStatement = policyRecord.statement
      if (decidedAt < parseTimestamp(String(policyStatement.effective_from)).getTime()) {
        fail("decision predates the referenced policy's effective interval")
      }
      if (
        policyStatement.effective_until !== undefined
        && decidedAt > parseTimestamp(String(policyStatement.effective_until)).getTime()
      ) fail("decision follows the referenced policy's effective interval")
    } else if (record.kind === 'execution') {
      const decisionRef = String(statement.decision_ref)
      requireRecord(byId, decisionRef, 'decision', 'execution.decision_ref')
      if (parents.length !== 1 || parents[0] !== decisionRef) {
        fail('v0 execution parents must contain exactly decision_ref')
      }
      if (String(statement.execution_type).startsWith('onchain')) {
        const missing = ['network', 'transaction_hash', 'transaction_digest']
          .filter((name) => !Object.hasOwn(statement, name))
        if (missing.length) fail(`onchain execution is missing: ${missing.join(', ')}`)
      }
      if (statement.confirmed_at !== undefined) {
        assertInterval(statement.submitted_at, statement.confirmed_at, 'execution')
      }
    }
  }

  const { bundle_id: _bundleId, ...withoutId } = payload
  if (payload.bundle_id !== contentId(withoutId)) {
    fail('bundle_id does not match the canonical payload without bundle_id')
  }
}
