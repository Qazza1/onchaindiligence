import assert from 'node:assert/strict'
import test from 'node:test'
import {
  createDecisionRecord,
  createMandateRecord,
  createPolicyRecord,
  createRecord,
  EvidenceValidationError,
} from '../dist/index.js'

function fixturePrincipal() {
  return createRecord('principal', { principal_id: 'urn:test:treasury', principal_type: 'organization' })
}

function fixtureAgentAndRun(principal) {
  const agent = createRecord(
    'agent',
    { agent_id: 'urn:test:agent', agent_version: '1.0.0', operator_ref: principal.id },
    { parents: [principal.id] },
  )
  const mandate = createMandateRecord({
    principal,
    mandateId: 'mandate-001',
    scope: { action: 'pay', asset: 'USDC' },
    validFrom: '2026-08-28T00:00:00.000Z',
    validUntil: '2026-08-29T00:00:00.000Z',
  })
  const run = createRecord(
    'run',
    { run_external_id: 'run-001', agent_ref: agent.id, mandate_ref: mandate.id, started_at: '2026-08-28T12:00:00.000Z' },
    { parents: [agent.id, mandate.id] },
  )
  return { agent, mandate, run }
}

function fixtureEvidence(run) {
  const observation = { sanctioned: false }
  return createRecord(
    'evidence',
    {
      evidence_type: 'sanctions-screen',
      run_ref: run.id,
      trust_mode: 'agent-assertion',
      source: { id: 'urn:test:screener', type: 'internal' },
      tool: { name: 'screen', version: '1' },
      request: { digest: { sha256: 'A'.repeat(43) }, media_type: 'application/json' },
      response: {
        mode: 'reference',
        media_type: 'application/json',
        reference: 'https://example.invalid/observations/1',
        digest: { sha256: 'B'.repeat(43) },
      },
      observed_at: '2026-08-28T12:00:01.000Z',
      expires_at: null,
      scope: { query: 'wallet' },
    },
    { parents: [run.id] },
  )
}

test('createMandateRecord produces a schema-valid record with a deterministic id', () => {
  const principal = fixturePrincipal()
  const mandate = createMandateRecord({
    principal,
    mandateId: 'mandate-001',
    scope: { action: 'pay', asset: 'USDC' },
    validFrom: '2026-08-28T00:00:00.000Z',
    validUntil: '2026-08-29T00:00:00.000Z',
  })
  assert.equal(mandate.kind, 'mandate')
  assert.deepEqual(mandate.parents, [principal.id])
  assert.equal(mandate.statement.principal_ref, principal.id)
  assert.match(mandate.id, /^sha256:[A-Za-z0-9_-]{43}$/)
})

test('createMandateRecord is exactly equivalent to manual createRecord construction', () => {
  const principal = fixturePrincipal()
  const viaHelper = createMandateRecord({
    principal,
    mandateId: 'mandate-001',
    scope: { action: 'pay', asset: 'USDC' },
    validFrom: '2026-08-28T00:00:00.000Z',
    validUntil: '2026-08-29T00:00:00.000Z',
    limits: { amount: '10.00' },
  })
  const viaGeneric = createRecord(
    'mandate',
    {
      mandate_id: 'mandate-001',
      principal_ref: principal.id,
      scope: { action: 'pay', asset: 'USDC' },
      valid_from: '2026-08-28T00:00:00.000Z',
      valid_until: '2026-08-29T00:00:00.000Z',
      limits: { amount: '10.00' },
    },
    { parents: [principal.id] },
  )
  assert.deepEqual(viaHelper, viaGeneric)
  assert.equal(viaHelper.id, viaGeneric.id)
})

test('createMandateRecord accepts a Date and formats it identically to a caller-supplied string', () => {
  const principal = fixturePrincipal()
  const viaDate = createMandateRecord({
    principal,
    mandateId: 'mandate-001',
    scope: { action: 'pay' },
    validFrom: new Date('2026-08-28T00:00:00.000Z'),
    validUntil: new Date('2026-08-29T00:00:00.000Z'),
  })
  const viaString = createMandateRecord({
    principal,
    mandateId: 'mandate-001',
    scope: { action: 'pay' },
    validFrom: '2026-08-28T00:00:00.000Z',
    validUntil: '2026-08-29T00:00:00.000Z',
  })
  assert.equal(viaDate.id, viaString.id)
})

test('createMandateRecord rejects a non-principal parent through the existing validation boundary', () => {
  const principal = fixturePrincipal()
  const notAPrincipal = createRecord(
    'agent',
    { agent_id: 'urn:test:agent', agent_version: '1' },
  )
  assert.throws(
    () => createMandateRecord({
      principal: notAPrincipal,
      mandateId: 'mandate-001',
      scope: {},
      validFrom: '2026-08-28T00:00:00.000Z',
      validUntil: '2026-08-29T00:00:00.000Z',
    }),
    EvidenceValidationError,
  )
  void principal
})

test('createPolicyRecord derives the digest from an embedded policy value, matching graph.ts\'s own check', () => {
  const principal = fixturePrincipal()
  const { run } = fixtureAgentAndRun(principal)
  const rules = { require_recipient_verification: true }
  const policy = createPolicyRecord({
    parents: [run],
    policyId: 'payment-policy',
    version: '1',
    source: 'https://example.invalid/policy/1',
    effectiveFrom: '2026-08-28T00:00:00.000Z',
    policy: rules,
  })
  assert.equal(policy.kind, 'policy')
  assert.deepEqual(policy.parents, [run.id])
  assert.match(policy.statement.digest.sha256, /^[A-Za-z0-9_-]{43}$/)

  const viaGeneric = createRecord(
    'policy',
    {
      policy_id: 'payment-policy',
      version: '1',
      digest: policy.statement.digest,
      source: 'https://example.invalid/policy/1',
      effective_from: '2026-08-28T00:00:00.000Z',
      policy: rules,
    },
    { parents: [run.id] },
  )
  assert.deepEqual(policy, viaGeneric)
})

test('createPolicyRecord accepts a matching explicit digest for an embedded policy without changing output', () => {
  const principal = fixturePrincipal()
  const { run } = fixtureAgentAndRun(principal)
  const input = {
    parents: [run],
    policyId: 'payment-policy',
    version: '1',
    source: 'https://example.invalid/policy/1',
    effectiveFrom: '2026-08-28T00:00:00.000Z',
    policy: { require_recipient_verification: true },
  }
  const derived = createPolicyRecord(input)
  const explicit = createPolicyRecord({ ...input, digest: derived.statement.digest })
  assert.deepEqual(explicit, derived)
})

test('createPolicyRecord rejects a mismatching explicit digest for an embedded policy', () => {
  const principal = fixturePrincipal()
  const { run } = fixtureAgentAndRun(principal)
  assert.throws(
    () => createPolicyRecord({
      parents: [run],
      policyId: 'payment-policy',
      version: '1',
      source: 'https://example.invalid/policy/1',
      effectiveFrom: '2026-08-28T00:00:00.000Z',
      policy: { require_recipient_verification: true },
      digest: { sha256: 'C'.repeat(43) },
    }),
    /digest.*does not match.*embedded.*policy/,
  )
})

test('createPolicyRecord accepts an explicit digest for an external policy', () => {
  const principal = fixturePrincipal()
  const { run } = fixtureAgentAndRun(principal)
  const explicitDigest = { sha256: 'C'.repeat(43) }
  const policy = createPolicyRecord({
    parents: [run],
    policyId: 'payment-policy',
    version: '1',
    source: 'https://example.invalid/policy/1',
    effectiveFrom: '2026-08-28T00:00:00.000Z',
    digest: explicitDigest,
  })
  assert.deepEqual(policy.statement.digest, explicitDigest)
})

test('createPolicyRecord requires at least one run/mandate parent and rejects other kinds', () => {
  const principal = fixturePrincipal()
  assert.throws(
    () => createPolicyRecord({
      parents: [],
      policyId: 'p', version: '1', source: 'https://example.invalid/p',
      effectiveFrom: '2026-08-28T00:00:00.000Z', digest: { sha256: 'D'.repeat(43) },
    }),
    EvidenceValidationError,
  )
  assert.throws(
    () => createPolicyRecord({
      parents: [principal],
      policyId: 'p', version: '1', source: 'https://example.invalid/p',
      effectiveFrom: '2026-08-28T00:00:00.000Z', digest: { sha256: 'D'.repeat(43) },
    }),
    EvidenceValidationError,
  )
})

test('createPolicyRecord requires a digest when no policy value is embedded', () => {
  const principal = fixturePrincipal()
  const { run } = fixtureAgentAndRun(principal)
  assert.throws(
    () => createPolicyRecord({
      parents: [run], policyId: 'p', version: '1',
      source: 'https://example.invalid/p', effectiveFrom: '2026-08-28T00:00:00.000Z',
    }),
    EvidenceValidationError,
  )
})

test('createDecisionRecord derives parents as the exact sorted union of run, policy, and evidence', () => {
  const principal = fixturePrincipal()
  const { agent, run } = fixtureAgentAndRun(principal)
  const evidence = fixtureEvidence(run)
  const rules = { require_recipient_verification: true }
  const policy = createPolicyRecord({
    parents: [run], policyId: 'p', version: '1',
    source: 'https://example.invalid/p', effectiveFrom: '2026-08-28T00:00:00.000Z', policy: rules,
  })
  const decision = createDecisionRecord({
    run, agent, policy, evidence: [evidence],
    decisionId: 'decision-001', decisionType: 'payment-authorization',
    outcome: { authorized: true }, decidedAt: '2026-08-28T12:00:02.000Z',
  })
  const expectedParents = [run.id, policy.id, evidence.id].sort()
  assert.deepEqual(decision.parents, expectedParents)
  assert.equal(decision.statement.run_ref, run.id)
  assert.equal(decision.statement.agent_ref, agent.id)
  assert.equal(decision.statement.policy_ref, policy.id)
  assert.deepEqual(decision.statement.evidence_refs, [evidence.id])
  assert.deepEqual(decision.statement.policy_digest, policy.statement.digest)
})

test('createDecisionRecord is exactly equivalent to manual createRecord construction', () => {
  const principal = fixturePrincipal()
  const { agent, run } = fixtureAgentAndRun(principal)
  const evidence = fixtureEvidence(run)
  const policy = createPolicyRecord({
    parents: [run], policyId: 'p', version: '1',
    source: 'https://example.invalid/p', effectiveFrom: '2026-08-28T00:00:00.000Z', policy: { rule: true },
  })
  const viaHelper = createDecisionRecord({
    run, agent, policy, evidence: [evidence],
    decisionId: 'decision-001', decisionType: 'payment-authorization',
    outcome: { authorized: true }, decidedAt: '2026-08-28T12:00:02.000Z',
  })
  const viaGeneric = createRecord(
    'decision',
    {
      decision_id: 'decision-001',
      run_ref: run.id,
      agent_ref: agent.id,
      decision_type: 'payment-authorization',
      outcome: { authorized: true },
      evidence_refs: [evidence.id],
      policy_ref: policy.id,
      policy_digest: policy.statement.digest,
      decided_at: '2026-08-28T12:00:02.000Z',
    },
    { parents: [run.id, policy.id, evidence.id] },
  )
  assert.deepEqual(viaHelper, viaGeneric)
  assert.equal(viaHelper.id, viaGeneric.id)
})

test('createDecisionRecord rejects wrong-kind inputs and requires at least one evidence record', () => {
  const principal = fixturePrincipal()
  const { agent, run } = fixtureAgentAndRun(principal)
  const evidence = fixtureEvidence(run)
  const policy = createPolicyRecord({
    parents: [run], policyId: 'p', version: '1',
    source: 'https://example.invalid/p', effectiveFrom: '2026-08-28T00:00:00.000Z', digest: { sha256: 'E'.repeat(43) },
  })
  assert.throws(
    () => createDecisionRecord({
      run: agent, agent, policy, evidence: [evidence],
      decisionId: 'd', decisionType: 't', outcome: {}, decidedAt: '2026-08-28T12:00:02.000Z',
    }),
    EvidenceValidationError,
  )
  assert.throws(
    () => createDecisionRecord({
      run, agent, policy, evidence: [],
      decisionId: 'd', decisionType: 't', outcome: {}, decidedAt: '2026-08-28T12:00:02.000Z',
    }),
    EvidenceValidationError,
  )
})

test('the full Mandate -> Policy -> Decision chain requires no network access', async (t) => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = () => { throw new Error('network access attempted') }
  t.after(() => { globalThis.fetch = originalFetch })
  const principal = fixturePrincipal()
  const { agent, run } = fixtureAgentAndRun(principal)
  const evidence = fixtureEvidence(run)
  const policy = createPolicyRecord({
    parents: [run], policyId: 'p', version: '1',
    source: 'https://example.invalid/p', effectiveFrom: '2026-08-28T00:00:00.000Z', policy: { rule: true },
  })
  const decision = createDecisionRecord({
    run, agent, policy, evidence: [evidence],
    decisionId: 'd', decisionType: 't', outcome: { authorized: true }, decidedAt: '2026-08-28T12:00:02.000Z',
  })
  assert.ok(decision.id)
})
