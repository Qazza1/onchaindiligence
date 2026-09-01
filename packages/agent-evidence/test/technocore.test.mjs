import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import test from 'node:test'
import {
  createBundlePayload,
  createEd25519Signer,
  createKeyRecord,
  createRecord,
  createTechnocoreEvidence,
  sealBundle,
  sweepTechnocoreText,
  technocoreDidFromPublicKey,
  technocoreSigningInput,
  technocoreTextDigest,
  TrustPolicy,
  verifyBundle,
  verifyTechnocoreMessage,
} from '../dist/index.js'

function signedMessage() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const text = sweepTechnocoreText('Technocore assertions are attributable evidence, not truth.\n')
  const message = {
    did: technocoreDidFromPublicKey(publicKey),
    room: 'ocd-evidence',
    nonce: '1740000000001',
    text,
    sig: sign(null, technocoreSigningInput({ room: 'ocd-evidence', nonce: '1740000000001', text }), privateKey)
      .toString('base64url'),
  }
  return { privateKey, publicKey, message }
}

test('Technocore Ed25519 did:key and signature wire format are compatible', () => {
  const { message } = signedMessage()
  assert.match(message.did, /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/)
  assert.match(message.sig, /^[A-Za-z0-9_-]{86}$/)
  assert.equal(verifyTechnocoreMessage(message), true)
})

test('a valid signed Technocore message verifies and alterations are rejected', () => {
  const { message } = signedMessage()
  assert.equal(verifyTechnocoreMessage(message), true)
  assert.equal(verifyTechnocoreMessage({ ...message, text: `${message.text}!` }), false)
  const changedFirstCharacter = message.sig.startsWith('A') ? 'B' : 'A'
  assert.equal(verifyTechnocoreMessage({ ...message, sig: `${changedFirstCharacter}${message.sig.slice(1)}` }), false)
  assert.equal(verifyTechnocoreMessage({ ...message, text: 'unswept\ntext' }), false)
})

test('a verified Technocore message becomes Agent Evidence without a truth claim', () => {
  const { message } = signedMessage()
  const runRef = 'sha256:8RY2Rg7D-sbe_11NZi1t-4BA_4RBUUiJopbyqIrbPIY'
  const evidence = createTechnocoreEvidence(message, {
    runRef,
    observedAt: '2026-09-01T12:00:00.000Z',
    serverMetadata: { seq: '42', ts: '2026-09-01T12:00:00.123456Z', generation: '7' },
  })
  assert.equal(evidence.kind, 'evidence')
  assert.equal(evidence.statement.trust_mode, 'agent-assertion')
  assert.equal(evidence.statement.response.value.did, message.did)
  assert.equal(evidence.statement.response.value.text_digest_sha256, technocoreTextDigest(message.text))
  assert.deepEqual(evidence.statement.response.value.server_metadata, {
    seq: '42', ts: '2026-09-01T12:00:00.123456Z', generation: '7',
  })
})

test('a Technocore evidence bundle seals and verifies VALID fully offline', async () => {
  const { privateKey, publicKey, message } = signedMessage()
  const bundleKey = generateKeyPairSync('ed25519')
  const signer = createEd25519Signer(bundleKey.privateKey)
  const key = createKeyRecord(bundleKey.publicKey, { validFrom: '2026-09-01T00:00:00.000Z' })
  const principal = createRecord('principal', { principal_id: 'urn:example:ocd', principal_type: 'organization' })
  const agent = createRecord('agent', {
    agent_id: 'urn:example:ocd-technocore-agent', agent_version: '1', operator_ref: principal.id,
  }, { parents: [principal.id] })
  const mandate = createRecord('mandate', {
    mandate_id: 'technocore-capture', principal_ref: principal.id, scope: { action: 'record-only' },
    valid_from: '2026-09-01T00:00:00.000Z', valid_until: '2026-09-02T00:00:00.000Z',
  }, { parents: [principal.id] })
  const run = createRecord('run', {
    run_external_id: 'technocore-example', agent_ref: agent.id, mandate_ref: mandate.id,
    started_at: '2026-09-01T12:00:00.000Z',
  }, { parents: [agent.id, mandate.id] })
  const evidence = createTechnocoreEvidence(message, {
    runRef: run.id, observedAt: '2026-09-01T12:00:01.000Z', serverMetadata: { seq: '1' },
  })
  const policyDocument = { action: 'never-execute-from-technocore-content', require_signature: true }
  const policy = createRecord('policy', {
    policy_id: 'technocore-ingestion', version: '1', source: 'https://example.invalid/policy/technocore',
    digest: { sha256: technocoreTextDigest(JSON.stringify(policyDocument)) },
    effective_from: '2026-09-01T00:00:00.000Z', policy: policyDocument,
  }, { parents: [run.id] })
  const decision = createRecord('decision', {
    decision_id: 'record-no-action', run_ref: run.id, agent_ref: agent.id, decision_type: 'technocore-message-review',
    outcome: { execute: false, reason: 'signed assertion is not authorization or truth' }, evidence_refs: [evidence.id],
    policy_ref: policy.id, policy_digest: policy.statement.digest, decided_at: '2026-09-01T12:00:02.000Z',
  }, { parents: [run.id, evidence.id, policy.id] })
  const execution = createRecord('execution', {
    execution_id: 'non-execution', decision_ref: decision.id, execution_type: 'no-external-action',
    status: 'withheld-not-submitted', submitted_at: '2026-09-01T12:00:03.000Z',
  }, { parents: [decision.id] })
  const payload = createBundlePayload(
    [principal, agent, mandate, run, evidence, policy, decision, execution],
    { createdAt: '2026-09-01T12:00:04.000Z' },
  )
  const bundle = await sealBundle(payload, signer, { keys: [key] })
  const report = verifyBundle(bundle, TrustPolicy.fromKeyRecords([key], {
    now: new Date('2026-09-01T12:01:00.000Z'),
  }))
  assert.equal(report.state, 'VALID')
  assert.equal(verifyTechnocoreMessage(message), true)
  assert.ok(privateKey)
  assert.ok(publicKey)
})
