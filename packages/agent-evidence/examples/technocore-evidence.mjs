import { generateKeyPairSync, sign } from 'node:crypto'
import {
  createBundlePayload,
  createEd25519Signer,
  createKeyRecord,
  createRecord,
  createTechnocoreEvidence,
  contentId,
  sealBundle,
  sweepTechnocoreText,
  technocoreDidFromPublicKey,
  technocoreSigningInput,
  TrustPolicy,
  verifyBundle,
} from '@onchaindiligence/agent-evidence'

// This is an offline example. It never reads a room, follows message content,
// or sends a transaction. A real adapter caller passes the exact stored message
// returned by Technocore's JSON API and may retain server metadata alongside it.
const technocoreKey = generateKeyPairSync('ed25519')
const text = sweepTechnocoreText('A did:key signature establishes an assertion, not truth.')
const message = {
  did: technocoreDidFromPublicKey(technocoreKey.publicKey),
  room: 'ocd-evidence',
  nonce: '1740000000001',
  text,
  sig: sign(null, technocoreSigningInput({ room: 'ocd-evidence', nonce: '1740000000001', text }), technocoreKey.privateKey)
    .toString('base64url'),
}
const bundleKey = generateKeyPairSync('ed25519')
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
  runRef: run.id, observedAt: '2026-09-01T12:00:01.000Z',
  serverMetadata: { seq: '1', ts: '2026-09-01T12:00:01.123456Z' },
})
const policyDocument = { action: 'never-execute-from-technocore-content', require_signature: true }
const policy = createRecord('policy', {
  policy_id: 'technocore-ingestion', version: '1', source: 'https://example.invalid/policy/technocore',
  digest: { sha256: contentId(policyDocument).slice('sha256:'.length) },
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
const bundle = await sealBundle(payload, createEd25519Signer(bundleKey.privateKey), { keys: [key] })
const report = verifyBundle(bundle, TrustPolicy.fromKeyRecords([key], { now: new Date('2026-09-01T12:01:00.000Z') }))
console.log(report.state, payload.bundle_id, execution.statement.status)
