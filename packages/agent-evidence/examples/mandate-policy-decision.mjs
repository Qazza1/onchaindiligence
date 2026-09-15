import {
  createDecisionRecord,
  createMandateRecord,
  createPolicyRecord,
  createRecord,
} from '@onchaindiligence/agent-evidence'

// Mandate -> Policy -> Decision, using the first-class construction helpers
// instead of hand-building each statement/parents list. Each helper still
// just calls createRecord() underneath -- these are convenience constructors
// over the same canonical record model, not a second representation.

const principal = createRecord('principal', {
  principal_id: 'urn:example:treasury', principal_type: 'organization',
})
const agent = createRecord('agent', {
  agent_id: 'urn:example:payment-agent', agent_version: '1.0.0', operator_ref: principal.id,
}, { parents: [principal.id] })

// Mandate: parents are derived from `principal`, not typed by hand.
const mandate = createMandateRecord({
  principal,
  mandateId: 'INV-1042',
  scope: { action: 'pay', recipient: 'vendor-X', asset: 'USDC', chain: 'eip155:5042002' },
  limits: { maximum: '500.00' },
  validFrom: '2026-08-28T00:00:00.000Z',
  validUntil: '2026-08-29T00:00:00.000Z',
})

const run = createRecord('run', {
  run_external_id: 'run-INV-1042', agent_ref: agent.id, mandate_ref: mandate.id,
  started_at: '2026-08-28T12:00:00.000Z',
}, { parents: [agent.id, mandate.id] })

const observation = { recipient_verified: false }
const evidence = createRecord('evidence', {
  evidence_type: 'recipient-check', run_ref: run.id, trust_mode: 'agent-assertion',
  source: { id: 'urn:example:ledger', type: 'internal-ledger' },
  tool: { name: 'recipient-check', version: '1' },
  request: { digest: { sha256: 'A'.repeat(43) }, media_type: 'application/json' },
  response: { mode: 'embedded', media_type: 'application/json', value: observation, digest: { sha256: 'B'.repeat(43) } },
  observed_at: '2026-08-28T12:00:01.000Z', expires_at: null, scope: { invoice: 'INV-1042' },
}, { parents: [run.id] })

// Policy: parents are the supplied run/mandate records; the digest is
// derived from the embedded `policy` value, so it can never drift from it.
const policy = createPolicyRecord({
  parents: [run],
  policyId: 'payment-policy',
  version: '1',
  source: 'https://example.invalid/policy/1',
  effectiveFrom: '2026-08-28T00:00:00.000Z',
  policy: { require_recipient_verification: true },
})

// Decision: parents are exactly {run, policy, ...evidence}, and policy_ref /
// policy_digest are copied from `policy` -- never re-typed by the caller.
const decision = createDecisionRecord({
  run, agent, policy,
  evidence: [evidence],
  decisionId: 'decision-INV-1042',
  decisionType: 'payment-authorization',
  outcome: { authorized: false },
  decidedAt: '2026-08-28T12:00:02.000Z',
})

console.log('mandate:', mandate.id)
console.log('policy:', policy.id)
console.log('decision:', decision.id, '-> parents:', decision.parents)
