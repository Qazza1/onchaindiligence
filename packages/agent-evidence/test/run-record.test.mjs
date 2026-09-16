import assert from 'node:assert/strict'
import test from 'node:test'
import {
  createRecord,
  createRunRecord,
  EvidenceValidationError,
} from '../dist/index.js'

function fixtureAgentAndMandate() {
  const principal = createRecord('principal', { principal_id: 'urn:test:treasury', principal_type: 'organization' })
  const agent = createRecord(
    'agent',
    { agent_id: 'urn:test:agent', agent_version: '1.0.0', operator_ref: principal.id },
    { parents: [principal.id] },
  )
  const mandate = createRecord(
    'mandate',
    {
      mandate_id: 'mandate-001', principal_ref: principal.id, scope: { action: 'pay' },
      valid_from: '2026-08-28T00:00:00.000Z', valid_until: '2026-08-29T00:00:00.000Z',
    },
    { parents: [principal.id] },
  )
  return { agent, mandate }
}

test('createRunRecord produces a schema-valid record with a deterministic id', () => {
  const { agent, mandate } = fixtureAgentAndMandate()
  const run = createRunRecord({
    agent, mandate, runExternalId: 'run-001', startedAt: '2026-08-28T12:00:00.000Z',
  })
  assert.equal(run.kind, 'run')
  assert.deepEqual(run.parents, [agent.id, mandate.id].sort())
  assert.equal(run.statement.agent_ref, agent.id)
  assert.equal(run.statement.mandate_ref, mandate.id)
  assert.match(run.id, /^sha256:[A-Za-z0-9_-]{43}$/)

  const again = createRunRecord({
    agent, mandate, runExternalId: 'run-001', startedAt: '2026-08-28T12:00:00.000Z',
  })
  assert.equal(run.id, again.id)
})

test('createRunRecord is exactly equivalent to manual createRecord construction', () => {
  const { agent, mandate } = fixtureAgentAndMandate()
  const viaHelper = createRunRecord({
    agent, mandate, runExternalId: 'run-001', startedAt: '2026-08-28T12:00:00.000Z', endedAt: '2026-08-28T12:00:05.000Z',
  })
  const viaGeneric = createRecord(
    'run',
    {
      run_external_id: 'run-001',
      agent_ref: agent.id,
      mandate_ref: mandate.id,
      started_at: '2026-08-28T12:00:00.000Z',
      ended_at: '2026-08-28T12:00:05.000Z',
    },
    { parents: [agent.id, mandate.id] },
  )
  assert.deepEqual(viaHelper, viaGeneric)
  assert.equal(viaHelper.id, viaGeneric.id)
})

test('agent_ref and mandate_ref are derived from the actual records, not retyped', () => {
  const { agent, mandate } = fixtureAgentAndMandate()
  const run = createRunRecord({ agent, mandate, runExternalId: 'run-001', startedAt: '2026-08-28T12:00:00.000Z' })
  assert.equal(run.statement.agent_ref, agent.id)
  assert.equal(run.statement.mandate_ref, mandate.id)
})

test('parents are exactly agent and mandate -- no more, no fewer', () => {
  const { agent, mandate } = fixtureAgentAndMandate()
  const run = createRunRecord({ agent, mandate, runExternalId: 'run-001', startedAt: '2026-08-28T12:00:00.000Z' })
  assert.deepEqual(run.parents, [agent.id, mandate.id].sort())
  assert.equal(run.parents.length, 2)
})

test('Date and string startedAt/endedAt produce identical output', () => {
  const { agent, mandate } = fixtureAgentAndMandate()
  const viaDate = createRunRecord({
    agent, mandate, runExternalId: 'run-001',
    startedAt: new Date('2026-08-28T12:00:00.000Z'), endedAt: new Date('2026-08-28T12:00:05.000Z'),
  })
  const viaString = createRunRecord({
    agent, mandate, runExternalId: 'run-001',
    startedAt: '2026-08-28T12:00:00.000Z', endedAt: '2026-08-28T12:00:05.000Z',
  })
  assert.equal(viaDate.id, viaString.id)
})

test('ended_at is never inferred -- omitting it omits the field entirely', () => {
  const { agent, mandate } = fixtureAgentAndMandate()
  const run = createRunRecord({ agent, mandate, runExternalId: 'run-001', startedAt: '2026-08-28T12:00:00.000Z' })
  assert.equal('ended_at' in run.statement, false)
})

test('a non-agent record supplied as agent is rejected', () => {
  const { agent, mandate } = fixtureAgentAndMandate()
  assert.throws(
    () => createRunRecord({ agent: mandate, mandate, runExternalId: 'run-001', startedAt: '2026-08-28T12:00:00.000Z' }),
    EvidenceValidationError,
  )
  void agent
})

test('a non-mandate record supplied as mandate is rejected', () => {
  const { agent, mandate } = fixtureAgentAndMandate()
  assert.throws(
    () => createRunRecord({ agent, mandate: agent, runExternalId: 'run-001', startedAt: '2026-08-28T12:00:00.000Z' }),
    EvidenceValidationError,
  )
  void mandate
})

test('a malformed timestamp fails through the existing schema validation path', () => {
  const { agent, mandate } = fixtureAgentAndMandate()
  assert.throws(
    () => createRunRecord({ agent, mandate, runExternalId: 'run-001', startedAt: 'not-a-timestamp' }),
  )
})

test('proofs/options are preserved', () => {
  const { agent, mandate } = fixtureAgentAndMandate()
  const proof = { proof_type: 'external-digest', media_type: 'application/json', digest: { sha256: 'A'.repeat(43) } }
  const run = createRunRecord(
    { agent, mandate, runExternalId: 'run-001', startedAt: '2026-08-28T12:00:00.000Z' },
    { proofs: [proof] },
  )
  assert.deepEqual(run.proofs, [proof])
})

test('createRunRecord requires no network access', async (t) => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = () => { throw new Error('network access attempted') }
  t.after(() => { globalThis.fetch = originalFetch })
  const { agent, mandate } = fixtureAgentAndMandate()
  const run = createRunRecord({ agent, mandate, runExternalId: 'run-001', startedAt: '2026-08-28T12:00:00.000Z' })
  assert.ok(run.id)
})
