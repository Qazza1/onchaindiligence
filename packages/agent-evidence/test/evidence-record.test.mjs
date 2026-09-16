import assert from 'node:assert/strict'
import test from 'node:test'
import {
  createEvidenceRecord,
  createRecord,
  EvidenceValidationError,
} from '../dist/index.js'

function fixtureRun() {
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
  return createRecord(
    'run',
    { run_external_id: 'run-001', agent_ref: agent.id, mandate_ref: mandate.id, started_at: '2026-08-28T12:00:00.000Z' },
    { parents: [agent.id, mandate.id] },
  )
}

function baseInput(run, overrides = {}) {
  return {
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
    ...overrides,
  }
}

test('createEvidenceRecord produces a schema-valid embedded-response record', () => {
  const run = fixtureRun()
  const evidence = createEvidenceRecord(baseInput(run))
  assert.equal(evidence.kind, 'evidence')
  assert.deepEqual(evidence.parents, [run.id])
  assert.equal(evidence.statement.run_ref, run.id)
  assert.equal(evidence.statement.response.mode, 'embedded')
  assert.deepEqual(evidence.statement.response.value, { sanctioned: false })
  assert.match(evidence.statement.response.digest.sha256, /^[A-Za-z0-9_-]{43}$/)
  assert.match(evidence.statement.request.digest.sha256, /^[A-Za-z0-9_-]{43}$/)
  assert.match(evidence.id, /^sha256:[A-Za-z0-9_-]{43}$/)
})

test('createEvidenceRecord produces a schema-valid reference-response record', () => {
  const run = fixtureRun()
  const evidence = createEvidenceRecord(baseInput(run, {
    response: {
      mode: 'reference',
      mediaType: 'application/json',
      reference: 'https://example.invalid/observations/1',
      digest: { sha256: 'A'.repeat(43) },
    },
  }))
  assert.equal(evidence.statement.response.mode, 'reference')
  assert.equal(evidence.statement.response.reference, 'https://example.invalid/observations/1')
  assert.deepEqual(evidence.statement.response.digest, { sha256: 'A'.repeat(43) })
  assert.equal('value' in evidence.statement.response, false)
})

test('embedded and reference response modes are mutually exclusive at the type/runtime level', () => {
  const run = fixtureRun()
  // embedded never carries `reference`, reference never carries `value` -- assert the
  // constructed statement itself, since TypeScript already forbids mixing them at compile time.
  const embedded = createEvidenceRecord(baseInput(run))
  assert.equal('reference' in embedded.statement.response, false)

  const referenced = createEvidenceRecord(baseInput(run, {
    response: { mode: 'reference', mediaType: 'application/json', reference: 'https://example.invalid/o/1', digest: { sha256: 'B'.repeat(43) } },
  }))
  assert.equal('value' in referenced.statement.response, false)
})

test('createEvidenceRecord is deterministic', () => {
  const run = fixtureRun()
  const a = createEvidenceRecord(baseInput(run))
  const runAgain = fixtureRun()
  const b = createEvidenceRecord(baseInput(runAgain))
  assert.equal(a.id, b.id)
  assert.deepEqual(a, b)
})

test('createEvidenceRecord is exactly equivalent to manual createRecord construction', () => {
  const run = fixtureRun()
  const viaHelper = createEvidenceRecord(baseInput(run))
  const requestDigest = { sha256: viaHelper.statement.request.digest.sha256 }
  const responseDigest = { sha256: viaHelper.statement.response.digest.sha256 }
  const viaGeneric = createRecord(
    'evidence',
    {
      evidence_type: 'sanctions-screen',
      run_ref: run.id,
      trust_mode: 'agent-assertion',
      source: { id: 'urn:test:screener', type: 'internal' },
      tool: { name: 'screen', version: '1' },
      request: { digest: requestDigest, media_type: 'application/json' },
      response: { mode: 'embedded', media_type: 'application/json', value: { sanctioned: false }, digest: responseDigest },
      observed_at: '2026-08-28T12:00:01.000Z',
      expires_at: null,
      scope: { query: 'wallet' },
    },
    { parents: [run.id] },
  )
  assert.deepEqual(viaHelper, viaGeneric)
  assert.equal(viaHelper.id, viaGeneric.id)
})

test('run_ref and the run parent are derived from the actual Run record, not retyped', () => {
  const run = fixtureRun()
  const evidence = createEvidenceRecord(baseInput(run))
  assert.equal(evidence.statement.run_ref, run.id)
  assert.ok(evidence.parents.includes(run.id))
})

test('prior evidence records are preserved as additional parents', () => {
  const run = fixtureRun()
  const first = createEvidenceRecord(baseInput(run))
  const second = createEvidenceRecord(baseInput(run, {
    evidenceType: 'recipient-check',
    priorEvidence: [first],
  }))
  assert.deepEqual(second.parents, [first.id, run.id].sort())
})

test('embedded request/response digests are derived canonically from the given value', () => {
  const run = fixtureRun()
  const value = { sanctioned: false, note: 'deterministic' }
  const evidence = createEvidenceRecord(baseInput(run, { response: { mode: 'embedded', mediaType: 'application/json', value } }))
  // Re-deriving through a second, independent evidence record with the same value must
  // produce the same digest -- proving it's a real canonical derivation, not a random id.
  const second = createEvidenceRecord(baseInput(fixtureRun(), { response: { mode: 'embedded', mediaType: 'application/json', value } }))
  assert.equal(evidence.statement.response.digest.sha256, second.statement.response.digest.sha256)
})

test('a matching explicit digest is accepted', () => {
  const run = fixtureRun()
  const value = { sanctioned: false }
  const derived = createEvidenceRecord(baseInput(run, { response: { mode: 'embedded', mediaType: 'application/json', value } }))
  const withExplicit = createEvidenceRecord(baseInput(fixtureRun(), {
    response: { mode: 'embedded', mediaType: 'application/json', value, digest: derived.statement.response.digest },
  }))
  assert.equal(withExplicit.statement.response.digest.sha256, derived.statement.response.digest.sha256)
})

test('a mismatching explicit digest is rejected', () => {
  const run = fixtureRun()
  assert.throws(
    () => createEvidenceRecord(baseInput(run, {
      response: { mode: 'embedded', mediaType: 'application/json', value: { sanctioned: false }, digest: { sha256: 'C'.repeat(43) } },
    })),
    EvidenceValidationError,
  )
  assert.throws(
    () => createEvidenceRecord(baseInput(run, {
      request: { mediaType: 'application/json', value: { address: '0x0' }, digest: { sha256: 'D'.repeat(43) } },
    })),
    EvidenceValidationError,
  )
})

test('reference mode without a digest is rejected', () => {
  const run = fixtureRun()
  assert.throws(
    () => createEvidenceRecord(baseInput(run, {
      response: { mode: 'reference', mediaType: 'application/json', reference: 'https://example.invalid/o/1' },
    })),
    EvidenceValidationError,
  )
})

test('request without a value and without a digest is rejected', () => {
  const run = fixtureRun()
  assert.throws(
    () => createEvidenceRecord(baseInput(run, { request: { mediaType: 'application/json' } })),
    EvidenceValidationError,
  )
})

test('a wrong-kind run or prior-evidence parent is rejected', () => {
  const run = fixtureRun()
  const notARun = createRecord('agent', { agent_id: 'urn:test:agent2', agent_version: '1' })
  assert.throws(() => createEvidenceRecord(baseInput(notARun)), EvidenceValidationError)

  const notEvidence = createRecord('agent', { agent_id: 'urn:test:agent3', agent_version: '1' })
  assert.throws(
    () => createEvidenceRecord(baseInput(run, { priorEvidence: [notEvidence] })),
    EvidenceValidationError,
  )
})

test('createEvidenceRecord requires no network access', async (t) => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = () => { throw new Error('network access attempted') }
  t.after(() => { globalThis.fetch = originalFetch })
  const run = fixtureRun()
  const evidence = createEvidenceRecord(baseInput(run))
  assert.ok(evidence.id)
})
