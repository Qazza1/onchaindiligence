import assert from 'node:assert/strict'
import test from 'node:test'
import {
  createDecisionRecord,
  createEvidenceRecord,
  createExecutionRecord,
  createRecord,
  createRunRecord,
  EvidenceValidationError,
} from '../dist/index.js'

function fixtureDecision() {
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
  const run = createRunRecord({ agent, mandate, runExternalId: 'run-001', startedAt: '2026-08-28T12:00:00.000Z' })
  const evidence = createEvidenceRecord({
    run,
    evidenceType: 'sanctions-screen',
    trustMode: 'agent-assertion',
    source: { id: 'urn:test:screener', type: 'internal' },
    tool: { name: 'screen', version: '1' },
    request: { mediaType: 'application/json', value: { address: '0x0' } },
    response: { mode: 'embedded', mediaType: 'application/json', value: { sanctioned: false } },
    observedAt: '2026-08-28T12:00:01.000Z',
    expiresAt: null,
    scope: { query: 'wallet' },
  })
  const rules = { require_recipient_verification: true }
  const policy = createRecord(
    'policy',
    { policy_id: 'p', version: '1', digest: { sha256: 'A'.repeat(43) }, source: 'https://example.invalid/p', effective_from: '2026-08-28T00:00:00.000Z', policy: rules },
    { parents: [run.id] },
  )
  return createDecisionRecord({
    run, agent, policy, evidence: [evidence],
    decisionId: 'decision-001', decisionType: 'payment-authorization',
    outcome: { authorized: true }, decidedAt: '2026-08-28T12:00:02.000Z',
  })
}

test('createExecutionRecord produces a schema-valid minimal record', () => {
  const decision = fixtureDecision()
  const execution = createExecutionRecord({
    decision,
    executionId: 'execution-001',
    executionType: 'payment-withheld',
    status: 'withheld-not-submitted',
    submittedAt: '2026-08-28T12:00:03.000Z',
  })
  assert.equal(execution.kind, 'execution')
  assert.deepEqual(execution.parents, [decision.id])
  assert.equal(execution.statement.decision_ref, decision.id)
  assert.match(execution.id, /^sha256:[A-Za-z0-9_-]{43}$/)
})

test('createExecutionRecord produces a schema-valid fully populated record', () => {
  const decision = fixtureDecision()
  const execution = createExecutionRecord({
    decision,
    executionId: 'execution-002',
    executionType: 'onchain-transfer',
    status: 'confirmed',
    submittedAt: '2026-08-28T12:00:03.000Z',
    confirmedAt: '2026-08-28T12:00:05.000Z',
    network: 'eip155:1',
    transactionHash: '0x' + '11'.repeat(32),
    transactionDigest: { sha256: 'B'.repeat(43) },
    sender: '0x' + '33'.repeat(20),
    recipient: '0x' + '22'.repeat(20),
    asset: 'USDC',
    amount: '1.00',
    blockNumber: '12345678',
  })
  assert.equal(execution.statement.network, 'eip155:1')
  assert.equal(execution.statement.transaction_hash, '0x' + '11'.repeat(32))
  assert.deepEqual(execution.statement.transaction_digest, { sha256: 'B'.repeat(43) })
  assert.equal(execution.statement.sender, '0x' + '33'.repeat(20))
  assert.equal(execution.statement.recipient, '0x' + '22'.repeat(20))
  assert.equal(execution.statement.asset, 'USDC')
  assert.equal(execution.statement.amount, '1.00')
  assert.equal(execution.statement.block_number, '12345678')
  assert.equal(execution.statement.confirmed_at, '2026-08-28T12:00:05.000Z')
})

test('createExecutionRecord is deterministic', () => {
  const decision = fixtureDecision()
  const a = createExecutionRecord({
    decision, executionId: 'execution-001', executionType: 'payment-withheld',
    status: 'withheld-not-submitted', submittedAt: '2026-08-28T12:00:03.000Z',
  })
  const decisionAgain = fixtureDecision()
  const b = createExecutionRecord({
    decision: decisionAgain, executionId: 'execution-001', executionType: 'payment-withheld',
    status: 'withheld-not-submitted', submittedAt: '2026-08-28T12:00:03.000Z',
  })
  assert.equal(a.id, b.id)
  assert.deepEqual(a, b)
})

test('createExecutionRecord is exactly equivalent to manual createRecord construction', () => {
  const decision = fixtureDecision()
  const viaHelper = createExecutionRecord({
    decision,
    executionId: 'execution-002',
    executionType: 'onchain-transfer',
    status: 'confirmed',
    submittedAt: '2026-08-28T12:00:03.000Z',
    confirmedAt: '2026-08-28T12:00:05.000Z',
    network: 'eip155:1',
    transactionHash: '0x' + '11'.repeat(32),
    transactionDigest: { sha256: 'B'.repeat(43) },
    sender: '0x' + '33'.repeat(20),
    recipient: '0x' + '22'.repeat(20),
    asset: 'USDC',
    amount: '1.00',
    blockNumber: '12345678',
  })
  const viaGeneric = createRecord(
    'execution',
    {
      execution_id: 'execution-002',
      decision_ref: decision.id,
      execution_type: 'onchain-transfer',
      status: 'confirmed',
      submitted_at: '2026-08-28T12:00:03.000Z',
      network: 'eip155:1',
      transaction_hash: '0x' + '11'.repeat(32),
      transaction_digest: { sha256: 'B'.repeat(43) },
      sender: '0x' + '33'.repeat(20),
      recipient: '0x' + '22'.repeat(20),
      asset: 'USDC',
      amount: '1.00',
      confirmed_at: '2026-08-28T12:00:05.000Z',
      block_number: '12345678',
    },
    { parents: [decision.id] },
  )
  assert.deepEqual(viaHelper, viaGeneric)
  assert.equal(viaHelper.id, viaGeneric.id)
})

test('decision_ref is derived from the supplied Decision record, not retyped', () => {
  const decision = fixtureDecision()
  const execution = createExecutionRecord({
    decision, executionId: 'execution-001', executionType: 'payment-withheld',
    status: 'withheld-not-submitted', submittedAt: '2026-08-28T12:00:03.000Z',
  })
  assert.equal(execution.statement.decision_ref, decision.id)
})

test('parents are exactly [decision.id] -- no more, no fewer', () => {
  const decision = fixtureDecision()
  const execution = createExecutionRecord({
    decision, executionId: 'execution-001', executionType: 'payment-withheld',
    status: 'withheld-not-submitted', submittedAt: '2026-08-28T12:00:03.000Z',
  })
  assert.deepEqual(execution.parents, [decision.id])
  assert.equal(execution.parents.length, 1)
})

test('optional fields are absent unless explicitly supplied -- none are inferred', () => {
  const decision = fixtureDecision()
  const execution = createExecutionRecord({
    decision, executionId: 'execution-001', executionType: 'onchain-transfer',
    status: 'submitted', submittedAt: '2026-08-28T12:00:03.000Z',
  })
  for (const field of ['network', 'transaction_hash', 'transaction_digest', 'sender', 'recipient', 'asset', 'amount', 'confirmed_at', 'block_number']) {
    assert.equal(field in execution.statement, false, `${field} should be absent`)
  }
})

test('Date and string submittedAt/confirmedAt produce identical output', () => {
  const decision = fixtureDecision()
  const viaDate = createExecutionRecord({
    decision, executionId: 'execution-001', executionType: 'onchain-transfer', status: 'confirmed',
    submittedAt: new Date('2026-08-28T12:00:03.000Z'), confirmedAt: new Date('2026-08-28T12:00:05.000Z'),
  })
  const viaString = createExecutionRecord({
    decision, executionId: 'execution-001', executionType: 'onchain-transfer', status: 'confirmed',
    submittedAt: '2026-08-28T12:00:03.000Z', confirmedAt: '2026-08-28T12:00:05.000Z',
  })
  assert.equal(viaDate.id, viaString.id)
})

test('a non-decision record supplied as decision is rejected', () => {
  const decision = fixtureDecision()
  const notADecision = createRecord('agent', { agent_id: 'urn:test:agent2', agent_version: '1' })
  assert.throws(
    () => createExecutionRecord({
      decision: notADecision, executionId: 'execution-001', executionType: 'payment-withheld',
      status: 'withheld-not-submitted', submittedAt: '2026-08-28T12:00:03.000Z',
    }),
    EvidenceValidationError,
  )
  void decision
})

test('malformed optional fields are rejected through the existing schema validation path', () => {
  const decision = fixtureDecision()
  assert.throws(() => createExecutionRecord({
    decision, executionId: 'execution-001', executionType: 'onchain-transfer', status: 'confirmed',
    submittedAt: '2026-08-28T12:00:03.000Z', network: 'not-a-caip2-network',
  }))
  assert.throws(() => createExecutionRecord({
    decision, executionId: 'execution-001', executionType: 'onchain-transfer', status: 'confirmed',
    submittedAt: '2026-08-28T12:00:03.000Z', amount: 'not-a-decimal',
  }))
  assert.throws(() => createExecutionRecord({
    decision, executionId: 'execution-001', executionType: 'onchain-transfer', status: 'confirmed',
    submittedAt: '2026-08-28T12:00:03.000Z', blockNumber: 'not-a-number',
  }))
  assert.throws(() => createExecutionRecord({
    decision, executionId: 'execution-001', executionType: 'onchain-transfer', status: 'confirmed',
    submittedAt: 'not-a-timestamp',
  }))
})

test('proofs/options are preserved', () => {
  const decision = fixtureDecision()
  const proof = { proof_type: 'external-digest', media_type: 'application/json', digest: { sha256: 'C'.repeat(43) } }
  const execution = createExecutionRecord(
    { decision, executionId: 'execution-001', executionType: 'payment-withheld', status: 'withheld-not-submitted', submittedAt: '2026-08-28T12:00:03.000Z' },
    { proofs: [proof] },
  )
  assert.deepEqual(execution.proofs, [proof])
})

test('createExecutionRecord requires no network access', async (t) => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = () => { throw new Error('network access attempted') }
  t.after(() => { globalThis.fetch = originalFetch })
  const decision = fixtureDecision()
  const execution = createExecutionRecord({
    decision, executionId: 'execution-001', executionType: 'payment-withheld',
    status: 'withheld-not-submitted', submittedAt: '2026-08-28T12:00:03.000Z',
  })
  assert.ok(execution.id)
})
