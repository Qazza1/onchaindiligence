import { generateKeyPairSync, sign } from 'node:crypto'
import { encodeFrame, generateHashLock, makeAccept, makeOffer } from '@flop-labs/tclk'
import {
  createBundlePayload,
  createEd25519Signer,
  createKeyRecord,
  createRecord,
  createTclkEvidence,
  createTechnocoreEvidence,
  contentId,
  sealBundle,
  sweepTechnocoreText,
  technocoreDidFromPublicKey,
  technocoreSigningInput,
  TrustPolicy,
  verifyBundle,
  verifyTclkTranscript,
} from '@onchaindiligence/agent-evidence'

// This is an offline example: no real money, no real Technocore room, no
// PTLC/adaptor-signature material (SAFE hash-lock path only). It shows the
// generic shape a real integration follows: two agents coordinate a deal as
// signed tclk/1 frames, OnChainDiligence captures the verified transcript as
// Agent Evidence, and — because no real settlement rail is wired up here — the
// resulting execution record says so honestly rather than claiming a payment
// happened.
const ROOM = 'tclk-offers'
function frameMessage(privateKey, did, nonce, frame) {
  const text = sweepTechnocoreText(encodeFrame(frame))
  const sig = sign(null, technocoreSigningInput({ room: ROOM, nonce, text }), privateKey).toString('base64url')
  return { did, room: ROOM, nonce, text, sig }
}

const payerKey = generateKeyPairSync('ed25519')
const payeeKey = generateKeyPairSync('ed25519')
const payerDid = technocoreDidFromPublicKey(payerKey.publicKey)
const payeeDid = technocoreDidFromPublicKey(payeeKey.publicKey)

const nowMs = Date.parse('2026-09-02T12:00:00.000Z')
const claimByMs = nowMs + 60 * 60 * 1000
const refundAfterMs = claimByMs + 60 * 60 * 1000
const expiresMs = nowMs + 30 * 60 * 1000

// offer -> accept -> lock announcement -> reveal (hash-lock path only).
const offer = makeOffer({
  from: payerDid, role: 'payer', amount: '1000000', asset: 'FLOP', lock: 'hash',
  rails: ['flop-htlc'], claimByMs, refundAfterMs, expiresMs,
})
const hashLock = generateHashLock()
const accept = makeAccept(offer, { from: payeeDid, statement: hashLock.hash })
const lock = { type: 'lock', from: payerDid, contract: accept.contract, rail: 'flop-htlc', ref: 'paper-escrow-1' }
const reveal = { type: 'reveal', from: payeeDid, contract: accept.contract, secret: hashLock.preimage }

const offerMsg = frameMessage(payerKey.privateKey, payerDid, '1756814400001', offer)
const acceptMsg = frameMessage(payeeKey.privateKey, payeeDid, '1756814400002', accept)
const lockMsg = frameMessage(payerKey.privateKey, payerDid, '1756814400003', lock)
const revealMsg = frameMessage(payeeKey.privateKey, payeeDid, '1756814400004', reveal)

// Verify: transport signature + tclk frame validity + sender attribution +
// official state-machine replay, each independently.
const transcript = verifyTclkTranscript([
  { message: offerMsg, atMs: nowMs },
  { message: acceptMsg, atMs: nowMs },
  { message: lockMsg, atMs: nowMs },
  { message: revealMsg, atMs: claimByMs - 1000 },
])

const bundleKey = generateKeyPairSync('ed25519')
const key = createKeyRecord(bundleKey.publicKey, { validFrom: '2026-09-01T00:00:00.000Z' })
const principal = createRecord('principal', { principal_id: 'urn:example:ocd', principal_type: 'organization' })
const agent = createRecord('agent', {
  agent_id: 'urn:example:ocd-tclk-agent', agent_version: '1', operator_ref: principal.id,
}, { parents: [principal.id] })
const mandate = createRecord('mandate', {
  mandate_id: 'tclk-coordination-capture', principal_ref: principal.id, scope: { action: 'record-only' },
  valid_from: '2026-09-01T00:00:00.000Z', valid_until: '2026-09-03T00:00:00.000Z',
}, { parents: [principal.id] })
const run = createRecord('run', {
  run_external_id: 'tclk-example', agent_ref: agent.id, mandate_ref: mandate.id,
  started_at: '2026-09-02T12:00:00.000Z',
}, { parents: [agent.id, mandate.id] })

// One Technocore evidence record per underlying signed message (reusing the
// existing Technocore adapter, not a second implementation of it) ...
const messageEvidence = [offerMsg, acceptMsg, lockMsg, revealMsg].map((message, i) =>
  createTechnocoreEvidence(message, { runRef: run.id, observedAt: `2026-09-02T12:0${i}:00.000Z` }))
// ... plus one tclk-transcript evidence record summarizing the verified replay.
const tclkEvidence = createTclkEvidence(transcript, {
  runRef: run.id, observedAt: '2026-09-02T12:05:00.000Z',
  messageEvidenceRefs: messageEvidence.map((e) => e.id),
})

const policyDocument = { action: 'accept-coordination-evidence-only', require_real_rail_for_settlement_claim: true }
const policy = createRecord('policy', {
  policy_id: 'tclk-coordination-capture', version: '1', source: 'https://example.invalid/policy/tclk',
  digest: { sha256: contentId(policyDocument).slice('sha256:'.length) },
  effective_from: '2026-09-01T00:00:00.000Z', policy: policyDocument,
}, { parents: [run.id] })

const evidenceRefs = [...messageEvidence.map((e) => e.id), tclkEvidence.id]
const decision = createRecord('decision', {
  decision_id: 'accept-tclk-coordination-evidence', run_ref: run.id, agent_ref: agent.id,
  decision_type: 'tclk-transcript-review',
  outcome: {
    disposition: 'ACCEPT_COORDINATION_EVIDENCE',
    authorized_to_execute: false,
    reason: 'valid signed coordination is evidence of what the agents agreed/asserted, not proof of settlement',
  },
  evidence_refs: evidenceRefs,
  policy_ref: policy.id, policy_digest: policy.statement.digest,
  decided_at: '2026-09-02T12:06:00.000Z',
}, { parents: [run.id, policy.id, ...evidenceRefs] })

// PaperRail-equivalent here: no real rail is wired up, so execution must say so.
const execution = createRecord('execution', {
  execution_id: 'no-real-value-settlement', decision_ref: decision.id, execution_type: 'no-external-action',
  status: 'NO_REAL_VALUE_SETTLEMENT', submitted_at: '2026-09-02T12:06:01.000Z',
}, { parents: [decision.id] })

const payload = createBundlePayload(
  [principal, agent, mandate, run, ...messageEvidence, tclkEvidence, policy, decision, execution],
  { createdAt: '2026-09-02T12:07:00.000Z' },
)
const bundle = await sealBundle(payload, createEd25519Signer(bundleKey.privateKey), { keys: [key] })
const report = verifyBundle(bundle, TrustPolicy.fromKeyRecords([key], { now: new Date('2026-09-02T12:08:00.000Z') }))

console.log(report.state, payload.bundle_id)
console.log('decision:', decision.statement.outcome.disposition)
console.log('execution:', execution.statement.status)
console.log('tclk transcript status:', transcript.status, '(terminal:', transcript.terminal + ')')
