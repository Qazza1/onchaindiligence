import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import {
  contentId,
  EvidenceValidationError,
  TrustPolicy,
  TrustPolicyError,
  validateBundlePayload,
  verifyBundle,
} from '../dist/index.js'

const fixtureUrl = new URL('../conformance/valid-full-graph.json', import.meta.url)
const now = new Date('2026-08-28T12:01:00.000Z')

async function fixture() {
  return JSON.parse(await readFile(fixtureUrl, 'utf8'))
}

function policy(record, options = {}) {
  return TrustPolicy.fromKeyRecords([record], { now, ...options })
}

function rebindBundle(payload) {
  const { bundle_id: _, ...body } = payload
  payload.bundle_id = contentId(body)
}

test('active and historical retired keys verify only inside their validity interval', async () => {
  const portable = await fixture()
  const active = portable.verification_material.keys[0]
  assert.equal(verifyBundle(portable, policy(active)).state, 'VALID')

  const retired = structuredClone(active)
  Object.assign(retired, {
    status: 'retired',
    valid_until: '2026-08-28T12:30:00.000Z',
    status_changed_at: '2026-08-28T12:30:00.000Z',
  })
  assert.equal(verifyBundle(portable, policy(retired)).state, 'VALID')

  retired.valid_until = '2026-08-28T12:00:05.000Z'
  retired.status_changed_at = retired.valid_until
  assert.equal(verifyBundle(portable, policy(retired)).state, 'INVALID')
})

test('revoked, compromised, missing activation, and malformed replacement trust are explicit', async () => {
  const portable = await fixture()
  const active = portable.verification_material.keys[0]

  const revoked = structuredClone(active)
  Object.assign(revoked, {
    status: 'revoked',
    status_reason: 'test revocation',
    status_changed_at: '2026-08-28T12:30:00.000Z',
  })
  assert.equal(verifyBundle(portable, policy(revoked)).state, 'INVALID')

  const compromised = structuredClone(active)
  Object.assign(compromised, {
    status: 'compromised',
    status_changed_at: '2026-08-28T12:30:00.000Z',
    compromised_at: '2026-08-28T12:30:00.000Z',
  })
  assert.equal(verifyBundle(portable, policy(compromised)).state, 'INVALID')

  const unknownActivation = structuredClone(active)
  unknownActivation.valid_from = null
  assert.equal(verifyBundle(portable, policy(unknownActivation)).state, 'UNVERIFIABLE')

  const selfReplacement = structuredClone(active)
  selfReplacement.replacement_key_id = selfReplacement.key_id
  assert.throws(() => policy(selfReplacement), TrustPolicyError)

  const missingReplacement = structuredClone(active)
  missingReplacement.replacement_key_id = 'ed25519-AAAAAAAAAAAAAAAA'
  assert.throws(() => policy(missingReplacement), /absent replacement/)
})

test('duplicate signatures cannot satisfy a trust threshold', async () => {
  const portable = await fixture()
  const active = portable.verification_material.keys[0]
  portable.envelope.signatures.push(structuredClone(portable.envelope.signatures[0]))
  const report = verifyBundle(portable, policy(active, { minimumValidSignatures: 2 }))
  assert.equal(report.state, 'INVALID')
  assert.ok(report.components.some((component) => component.code === 'duplicate-signature-key'))
})

test('caller trust policy cannot be mutated after construction', async () => {
  const portable = await fixture()
  const active = portable.verification_material.keys[0]
  const immutable = policy(active, { requiredSignatureKeyIds: [active.key_id] })
  immutable.now.setTime(0)
  immutable.requiredSignatureKeyIds.clear()
  immutable.key(active.key_id).validFrom.setTime(Date.UTC(2099, 0, 1))
  assert.equal(verifyBundle(portable, immutable).state, 'VALID')
  assert.deepEqual([...immutable.requiredSignatureKeyIds], [active.key_id])
})

test('graph mutation, decision parent substitution, and onchain binding omissions are rejected', async () => {
  const portable = await fixture()
  const payload = JSON.parse(Buffer.from(portable.envelope.payload, 'base64').toString('utf8'))
  const evidence = payload.records.find((record) => record.kind === 'evidence')
  evidence.statement.response.value.sanctioned = true
  rebindBundle(payload)
  assert.throws(() => validateBundlePayload(payload), EvidenceValidationError)

  const fresh = JSON.parse(Buffer.from(portable.envelope.payload, 'base64').toString('utf8'))
  const execution = fresh.records.find((record) => record.kind === 'execution')
  delete execution.statement.transaction_digest
  const previous = execution.id
  const { id: _, ...executionBody } = execution
  execution.id = contentId(executionBody)
  fresh.root_ids = fresh.root_ids.map((id) => id === previous ? execution.id : id)
  fresh.records.sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0)
  rebindBundle(fresh)
  assert.throws(() => validateBundlePayload(fresh), /transaction_digest/)
})

test('signature, payload type, source label, and stale content mutations never become valid', async () => {
  const portable = await fixture()
  const active = portable.verification_material.keys[0]
  const mutatedSignature = structuredClone(portable)
  const bytes = Buffer.from(mutatedSignature.envelope.signatures[0].sig, 'base64')
  bytes[0] ^= 1
  mutatedSignature.envelope.signatures[0].sig = bytes.toString('base64')
  assert.equal(verifyBundle(mutatedSignature, policy(active)).state, 'INVALID')

  const wrongType = structuredClone(portable)
  wrongType.envelope.payloadType = 'application/json'
  assert.equal(verifyBundle(wrongType, policy(active)).state, 'INVALID')
})
