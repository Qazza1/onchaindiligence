import { generateKeyPairSync } from 'node:crypto'
import {
  contentId,
  createBundlePayload,
  createEd25519Signer,
  createKeyRecord,
  createRecord,
  sealBundle,
  TrustPolicy,
  verifyBundle,
} from '@onchaindiligence/agent-evidence'

// Concise financial-agent example. It deliberately records non-execution;
// no blockchain settlement is fabricated.
const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const signer = createEd25519Signer(privateKey)
const key = createKeyRecord(publicKey, { validFrom: '2026-08-28T00:00:00.000Z' })
const principal = createRecord('principal', {
  principal_id: 'urn:example:treasury', principal_type: 'organization',
})
const agent = createRecord('agent', {
  agent_id: 'urn:example:payment-agent', agent_version: '1.0.0', operator_ref: principal.id,
}, { parents: [principal.id] })
const mandate = createRecord('mandate', {
  mandate_id: 'INV-1042', principal_ref: principal.id,
  scope: { action: 'pay', recipient: 'vendor-X', asset: 'USDC', chain: 'eip155:5042002' },
  limits: { maximum: '500.00' },
  valid_from: '2026-08-28T00:00:00.000Z', valid_until: '2026-08-29T00:00:00.000Z',
}, { parents: [principal.id] })
const run = createRecord('run', {
  run_external_id: 'run-INV-1042', agent_ref: agent.id, mandate_ref: mandate.id,
  started_at: '2026-08-28T12:00:00.000Z',
}, { parents: [agent.id, mandate.id] })
const observation = { recipient_verified: false }
const evidence = createRecord('evidence', {
  evidence_type: 'recipient-check', run_ref: run.id, trust_mode: 'agent-assertion',
  source: { id: 'urn:example:ledger', type: 'internal-ledger' },
  tool: { name: 'recipient-check', version: '1' },
  request: { digest: { sha256: contentId({ invoice: 'INV-1042' }).slice(7) }, media_type: 'application/json' },
  response: { mode: 'embedded', media_type: 'application/json', value: observation,
    digest: { sha256: contentId(observation).slice(7) } },
  observed_at: '2026-08-28T12:00:01.000Z', expires_at: null, scope: { invoice: 'INV-1042' },
}, { parents: [run.id] })
const rules = { require_recipient_verification: true }
const policy = createRecord('policy', {
  policy_id: 'payment-policy', version: '1', digest: { sha256: contentId(rules).slice(7) },
  source: 'https://example.invalid/policy/1', effective_from: '2026-08-28T00:00:00.000Z', policy: rules,
}, { parents: [run.id] })
const decision = createRecord('decision', {
  decision_id: 'decision-INV-1042', run_ref: run.id, agent_ref: agent.id,
  decision_type: 'payment-authorization', outcome: { authorized: false }, evidence_refs: [evidence.id],
  policy_ref: policy.id, policy_digest: policy.statement.digest, decided_at: '2026-08-28T12:00:02.000Z',
}, { parents: [run.id, evidence.id, policy.id] })
const execution = createRecord('execution', {
  execution_id: 'execution-INV-1042', decision_ref: decision.id,
  execution_type: 'payment-withheld', status: 'withheld-not-submitted',
  submitted_at: '2026-08-28T12:00:03.000Z',
}, { parents: [decision.id] })
const payload = createBundlePayload(
  [principal, agent, mandate, run, evidence, policy, decision, execution],
  { createdAt: '2026-08-28T12:00:04.000Z' },
)
const bundle = await sealBundle(payload, signer, { keys: [key] })
const report = verifyBundle(bundle, TrustPolicy.fromKeyRecords([key], {
  now: new Date('2026-08-28T12:01:00.000Z'),
}))
console.log(report.state, payload.bundle_id, execution.statement.status)
