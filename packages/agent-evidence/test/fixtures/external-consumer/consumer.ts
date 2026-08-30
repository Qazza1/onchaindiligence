import assert from 'node:assert/strict'
import { createPublicKey, generateKeyPairSync } from 'node:crypto'
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

const { privateKey } = generateKeyPairSync('ed25519')
const signer = createEd25519Signer(privateKey)
const keyRecord = createKeyRecord(createPublicKey(privateKey), {
  validFrom: '2026-08-28T00:00:00.000Z',
})

const principal = createRecord('principal', {
  principal_id: 'urn:example:treasury',
  principal_type: 'organization',
  display_name: 'Example Treasury',
})
const agent = createRecord('agent', {
  agent_id: 'urn:example:payment-agent',
  agent_version: '1.0.0',
  operator_ref: principal.id,
}, { parents: [principal.id] })
const mandate = createRecord('mandate', {
  mandate_id: 'mandate-inv-1042',
  principal_ref: principal.id,
  scope: {
    action: 'pay-invoice',
    invoice_id: 'INV-1042',
    approved_recipient: 'acct:vendor-1042',
    asset: 'USDC',
    network: 'eip155:5042002',
  },
  limits: { maximum_amount: '500.00' },
  valid_from: '2026-08-28T00:00:00.000Z',
  valid_until: '2026-08-29T00:00:00.000Z',
}, { parents: [principal.id] })
const run = createRecord('run', {
  run_external_id: 'run-inv-1042',
  agent_ref: agent.id,
  mandate_ref: mandate.id,
  started_at: '2026-08-28T12:00:00.000Z',
  ended_at: '2026-08-28T12:00:05.000Z',
}, { parents: [agent.id, mandate.id] })

const request = { invoice_id: 'INV-1042', recipient: 'acct:vendor-1042' }
const observation = { recipient_verified: false, reason: 'recipient ownership evidence is missing' }
const evidence = createRecord('evidence', {
  evidence_type: 'recipient-binding-check',
  run_ref: run.id,
  trust_mode: 'agent-assertion',
  source: { id: 'urn:example:accounts-payable', type: 'internal-ledger' },
  tool: { name: 'recipient-binding-check', version: '1.0.0' },
  request: {
    digest: { sha256: contentId(request).slice('sha256:'.length) },
    media_type: 'application/json',
  },
  response: {
    mode: 'embedded',
    media_type: 'application/json',
    value: observation,
    digest: { sha256: contentId(observation).slice('sha256:'.length) },
  },
  observed_at: '2026-08-28T12:00:01.000Z',
  expires_at: null,
  scope: { invoice_id: 'INV-1042' },
}, {
  parents: [run.id],
  proofs: [{
    proof_type: 'external-digest',
    media_type: 'application/json',
    digest: { sha256: contentId(observation).slice('sha256:'.length) },
  }],
})

const policyDocument = {
  rule: 'recipient ownership must be verified before payment submission',
  on_failure: 'withhold',
}
const policy = createRecord('policy', {
  policy_id: 'urn:example:payment-policy',
  version: '1.0.0',
  digest: { sha256: contentId(policyDocument).slice('sha256:'.length) },
  source: 'https://example.invalid/policies/payment/1.0.0',
  effective_from: '2026-08-28T00:00:00.000Z',
  policy: policyDocument,
}, { parents: [run.id] })
const decision = createRecord('decision', {
  decision_id: 'decision-inv-1042',
  run_ref: run.id,
  agent_ref: agent.id,
  decision_type: 'payment-authorization',
  outcome: { authorized_to_execute: false, reason: 'recipient ownership evidence is missing' },
  evidence_refs: [evidence.id],
  policy_ref: policy.id,
  policy_digest: policy.statement.digest,
  decided_at: '2026-08-28T12:00:03.000Z',
}, { parents: [run.id, evidence.id, policy.id] })
const execution = createRecord('execution', {
  execution_id: 'execution-inv-1042',
  decision_ref: decision.id,
  execution_type: 'payment-withheld',
  status: 'withheld-not-submitted',
  submitted_at: '2026-08-28T12:00:04.000Z',
}, { parents: [decision.id] })

const payload = createBundlePayload([
  principal,
  agent,
  mandate,
  run,
  evidence,
  policy,
  decision,
  execution,
], { createdAt: '2026-08-28T12:00:06.000Z' })
const portable = await sealBundle(payload, signer, { keys: [keyRecord] })
const trust = TrustPolicy.fromKeyRecords([keyRecord], {
  now: new Date('2026-08-28T12:01:00.000Z'),
})

const valid = verifyBundle(portable, trust)
assert.equal(valid.state, 'VALID')

const tampered = structuredClone(portable)
const signature = Buffer.from(tampered.envelope.signatures[0]!.sig, 'base64')
signature[0] = signature[0]! ^ 1
tampered.envelope.signatures[0]!.sig = signature.toString('base64')
const invalid = verifyBundle(tampered, trust)
assert.equal(invalid.state, 'INVALID')

const missingTrust = verifyBundle(portable, TrustPolicy.fromKeyRecords([], {
  now: new Date('2026-08-28T12:01:00.000Z'),
}))
assert.equal(missingTrust.state, 'UNVERIFIABLE')

process.stdout.write(JSON.stringify({
  bundle_id: payload.bundle_id,
  record_kinds: payload.records.map((record) => record.kind).sort(),
  execution_status: execution.statement.status,
  valid: valid.state,
  invalid: invalid.state,
  unverifiable: missingTrust.state,
}) + '\n')
