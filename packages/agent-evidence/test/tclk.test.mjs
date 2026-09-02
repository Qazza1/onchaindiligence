import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import test from 'node:test'
import {
  encodeFrame,
  generateHashLock,
  makeAccept,
  makeOffer,
  TCLK_PREFIX,
} from '@flop-labs/tclk'
import {
  createBundlePayload,
  createEd25519Signer,
  createKeyRecord,
  createRecord,
  createTclkEvidence,
  createTechnocoreEvidence,
  contentId,
  EvidenceValidationError,
  sealBundle,
  sweepTechnocoreText,
  technocoreDidFromPublicKey,
  technocoreSigningInput,
  TrustPolicy,
  verifyBundle,
  verifyTclkTranscript,
} from '../dist/index.js'

// Focused tests for the tclk/1 (Technocore Lock Protocol, by FLOP Labs) adapter.
// Uses the official @flop-labs/tclk package directly -- this adapter never
// reimplements frame validation or the state machine. Only the SAFE hash-lock
// path is exercised; no PTLC/adaptor-signature material is used anywhere here.

const ROOM = 'tclk-offers'
const NOW = Date.parse('2026-09-02T12:00:00.000Z')
const CLAIM_BY = NOW + 60 * 60 * 1000
const REFUND_AFTER = CLAIM_BY + 60 * 60 * 1000
const EXPIRES = NOW + 30 * 60 * 1000

function party() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  return { privateKey, publicKey, did: technocoreDidFromPublicKey(publicKey) }
}

let nonceCounter = 1700000000000
function nextNonce() {
  nonceCounter += 1
  return String(nonceCounter)
}

/** Wrap a tclk frame as a signed Technocore message, exactly like a real caller would. */
function frameMessage(signer, frame, { room = ROOM, nonce = nextNonce() } = {}) {
  const text = sweepTechnocoreText(encodeFrame(frame))
  const sig = sign(null, technocoreSigningInput({ room, nonce, text }), signer.privateKey).toString('base64url')
  return { did: signer.did, room, nonce, text, sig }
}

/** Pair a message with the wall-clock time at which it is being applied. */
function at(message, atMs) {
  return { message, atMs }
}

/** A full, honest offer -> accept -> lock -> reveal/refund transcript (hash-lock path only). */
function happyPathMessages() {
  const payer = party()
  const payee = party()
  const offer = makeOffer({
    from: payer.did, role: 'payer', amount: '1000000', asset: 'FLOP', lock: 'hash',
    rails: ['flop-htlc'], claimByMs: CLAIM_BY, refundAfterMs: REFUND_AFTER, expiresMs: EXPIRES,
  })
  const hashLock = generateHashLock()
  const accept = makeAccept(offer, { from: payee.did, statement: hashLock.hash })
  const lock = { type: 'lock', from: payer.did, contract: accept.contract, rail: 'flop-htlc', ref: 'paper-escrow-1' }
  const reveal = { type: 'reveal', from: payee.did, contract: accept.contract, secret: hashLock.preimage }
  const refund = { type: 'refund', from: payer.did, contract: accept.contract }
  return {
    payer, payee, offer, accept, lock, reveal, refund, hashLock,
    offerMsg: frameMessage(payer, offer),
    acceptMsg: frameMessage(payee, accept),
    lockMsg: frameMessage(payer, lock),
    revealMsg: frameMessage(payee, reveal),
    refundMsg: frameMessage(payer, refund),
  }
}

test('valid offer -> accept transcript reaches "accepted" with correct parties/terms', () => {
  const t = happyPathMessages()
  const result = verifyTclkTranscript([at(t.offerMsg, NOW), at(t.acceptMsg, NOW)])
  assert.equal(result.status, 'accepted')
  assert.equal(result.terminal, false)
  assert.equal(result.payerDid, t.payer.did)
  assert.equal(result.payeeDid, t.payee.did)
  assert.equal(result.amount, '1000000')
  assert.equal(result.asset, 'FLOP')
  assert.equal(result.lock, 'hash')
  assert.deepEqual(result.offeredRails, ['flop-htlc'])
  assert.equal(result.contract, t.accept.contract)
  assert.equal(result.steps.length, 2)
  assert.ok(result.steps.every((step) => step.accepted))
})

test('valid lock transition reaches "locked" and records the asserted rail', () => {
  const t = happyPathMessages()
  const result = verifyTclkTranscript([at(t.offerMsg, NOW), at(t.acceptMsg, NOW), at(t.lockMsg, NOW)])
  assert.equal(result.status, 'locked')
  assert.equal(result.rail, 'flop-htlc')
  assert.equal(result.railRef, 'paper-escrow-1')
  assert.equal(result.terminal, false)
})

test('valid reveal terminal transition reaches "claimed"', () => {
  const t = happyPathMessages()
  const result = verifyTclkTranscript([
    at(t.offerMsg, NOW), at(t.acceptMsg, NOW), at(t.lockMsg, NOW), at(t.revealMsg, CLAIM_BY - 1000),
  ])
  assert.equal(result.status, 'claimed')
  assert.equal(result.terminal, true)
  assert.equal(result.outcome, 'claimed')
})

test('valid refund terminal transition reaches "refunded"', () => {
  const t = happyPathMessages()
  const result = verifyTclkTranscript([
    at(t.offerMsg, NOW), at(t.acceptMsg, NOW), at(t.lockMsg, NOW), at(t.refundMsg, REFUND_AFTER + 1000),
  ])
  assert.equal(result.status, 'refunded')
  assert.equal(result.terminal, true)
  assert.equal(result.outcome, 'refunded')
})

test('malformed frame is rejected (fails closed, throws)', () => {
  const payer = party()
  // A structurally invalid tclk line (missing required offer fields) that still
  // carries a genuine Technocore transport signature over its own bytes.
  const text = sweepTechnocoreText(`${TCLK_PREFIX}${JSON.stringify({ type: 'offer', from: payer.did })}`)
  const nonce = nextNonce()
  const sig = sign(null, technocoreSigningInput({ room: ROOM, nonce, text }), payer.privateKey).toString('base64url')
  const badMessage = { did: payer.did, room: ROOM, nonce, text, sig }
  assert.throws(() => verifyTclkTranscript([at(badMessage, NOW)]), EvidenceValidationError)
  assert.throws(() => verifyTclkTranscript([at(badMessage, NOW)]), /not a valid tclk\/1 frame/)
})

test('wrong transport signer is rejected (fails closed, throws)', () => {
  const t = happyPathMessages()
  const impostor = party()
  // Same claimed DID, but actually signed by a different key -- the Technocore
  // transport signature must fail even though the frame content is untouched.
  const forgedSig = sign(null, technocoreSigningInput(t.offerMsg), impostor.privateKey).toString('base64url')
  const forged = { ...t.offerMsg, sig: forgedSig }
  assert.throws(() => verifyTclkTranscript([at(forged, NOW)]), EvidenceValidationError)
  assert.throws(() => verifyTclkTranscript([at(forged, NOW)]), /invalid Technocore transport signature/)
})

test('frame sender / transport DID mismatch is rejected (fails closed, throws)', () => {
  const t = happyPathMessages()
  // The accept frame honestly says payee.from, but is wrapped as though the
  // PAYER's transport DID sent it (signed for real by the payer's own key over
  // this exact text, so the transport signature itself is genuine).
  const relabelled = frameMessage(t.payer, t.accept, { nonce: t.acceptMsg.nonce })
  assert.throws(() => verifyTclkTranscript([at(t.offerMsg, NOW), at(relabelled, NOW)]), EvidenceValidationError)
  assert.throws(
    () => verifyTclkTranscript([at(t.offerMsg, NOW), at(relabelled, NOW)]),
    /does not match the transport-authenticated DID/,
  )
})

test('out-of-order transition is officially rejected, not thrown, and is recorded', () => {
  const t = happyPathMessages()
  // lock before accept: contract is still "proposed".
  const result = verifyTclkTranscript([at(t.offerMsg, NOW), at(t.lockMsg, NOW)])
  assert.equal(result.status, 'proposed')
  assert.equal(result.steps.length, 2)
  assert.equal(result.steps[1].accepted, false)
  assert.match(result.steps[1].reason, /lock in status proposed/)
})

test('a replayed/duplicate frame is handled per official tclk semantics: rejected, transcript unaffected', () => {
  const t = happyPathMessages()
  const result = verifyTclkTranscript([at(t.offerMsg, NOW), at(t.acceptMsg, NOW), at(t.acceptMsg, NOW)])
  assert.equal(result.status, 'accepted')
  assert.equal(result.steps.length, 3)
  assert.equal(result.steps[0].accepted, true)
  assert.equal(result.steps[1].accepted, true)
  assert.equal(result.steps[2].accepted, false)
  assert.match(result.steps[2].reason, /accept in status accepted/)
})

test('a content-tampered frame is caught by tclk\'s own id check and rejected, not silently accepted', () => {
  const t = happyPathMessages()
  // Tamper the accept's contract id after it was honestly signed over the
  // original bytes -- decode succeeds (still structurally valid), but the
  // official machine's own contractId recomputation must catch the mismatch.
  const tamperedAccept = { ...t.accept, contract: t.accept.contract.replace(/.$/, t.accept.contract.endsWith('0') ? '1' : '0') }
  const tamperedMsg = frameMessage(t.payee, tamperedAccept, { nonce: t.acceptMsg.nonce })
  const result = verifyTclkTranscript([at(t.offerMsg, NOW), at(tamperedMsg, NOW)])
  assert.equal(result.status, 'proposed')
  assert.equal(result.steps[1].accepted, false)
  assert.match(result.steps[1].reason, /contract id mismatch/)
})

test('an Evidence record is created from a verified transcript, correctly parented', () => {
  const t = happyPathMessages()
  const result = verifyTclkTranscript([at(t.offerMsg, NOW), at(t.acceptMsg, NOW), at(t.lockMsg, NOW)])
  const runRef = 'sha256:8RY2Rg7D-sbe_11NZi1t-4BA_4RBUUiJopbyqIrbPIY'
  const messageEvidence = [t.offerMsg, t.acceptMsg, t.lockMsg].map((message, i) =>
    createTechnocoreEvidence(message, { runRef, observedAt: `2026-09-02T12:0${i}:00.000Z` }))
  const evidence = createTclkEvidence(result, {
    runRef, observedAt: '2026-09-02T12:05:00.000Z',
    messageEvidenceRefs: messageEvidence.map((e) => e.id),
  })
  assert.equal(evidence.kind, 'evidence')
  assert.equal(evidence.statement.evidence_type, 'tclk-transcript')
  assert.equal(evidence.statement.response.value.protocol, 'tclk/1')
  assert.equal(evidence.statement.response.value.offer_id, t.offer.id)
  assert.equal(evidence.statement.response.value.contract_id, t.accept.contract)
  assert.equal(evidence.statement.response.value.payer_did, t.payer.did)
  assert.equal(evidence.statement.response.value.payee_did, t.payee.did)
  assert.equal(evidence.statement.response.value.transcript_status, 'locked')
  assert.deepEqual(new Set(evidence.parents), new Set([runRef, ...messageEvidence.map((e) => e.id)]))
})

test('no claim of real settlement is made without independent rail evidence', () => {
  const t = happyPathMessages()
  const result = verifyTclkTranscript([at(t.offerMsg, NOW), at(t.acceptMsg, NOW), at(t.lockMsg, NOW)])
  const evidence = createTclkEvidence(result, {
    runRef: 'sha256:8RY2Rg7D-sbe_11NZi1t-4BA_4RBUUiJopbyqIrbPIY',
    observedAt: '2026-09-02T12:05:00.000Z',
    messageEvidenceRefs: ['sha256:8RY2Rg7D-sbe_11NZi1t-4BA_4RBUUiJopbyqIrbPIY'],
  })
  const note = evidence.statement.response.value.settlement_note
  assert.match(note, /asserted\/announced lock/)
  assert.doesNotMatch(note, /funds were (definitely )?locked/)
  assert.equal('independent_settlement_observation' in evidence.statement.response.value, false)

  const withRail = createTclkEvidence(result, {
    runRef: 'sha256:8RY2Rg7D-sbe_11NZi1t-4BA_4RBUUiJopbyqIrbPIY',
    observedAt: '2026-09-02T12:05:00.000Z',
    messageEvidenceRefs: ['sha256:8RY2Rg7D-sbe_11NZi1t-4BA_4RBUUiJopbyqIrbPIY'],
    settlementRail: { rail: 'flop-htlc', ref: 'paper-escrow-1', observedAt: '2026-09-02T12:06:00.000Z', detail: { note: 'test-only, not real settlement' } },
  })
  assert.equal(withRail.statement.response.value.independent_settlement_observation.rail, 'flop-htlc')
})

test('a tclk evidence bundle seals and verifies VALID fully offline, end to end', async () => {
  const t = happyPathMessages()
  const result = verifyTclkTranscript([
    at(t.offerMsg, NOW), at(t.acceptMsg, NOW), at(t.lockMsg, NOW), at(t.revealMsg, CLAIM_BY - 1000),
  ])

  const bundleKey = generateKeyPairSync('ed25519')
  const signer = createEd25519Signer(bundleKey.privateKey)
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

  const messageEvidence = [t.offerMsg, t.acceptMsg, t.lockMsg, t.revealMsg].map((message, i) =>
    createTechnocoreEvidence(message, { runRef: run.id, observedAt: `2026-09-02T12:0${i}:00.000Z` }))
  const tclkEvidence = createTclkEvidence(result, {
    runRef: run.id, observedAt: '2026-09-02T12:05:00.000Z',
    messageEvidenceRefs: messageEvidence.map((e) => e.id),
  })

  const policyDocument = { action: 'accept-coordination-evidence-only', require_real_rail_for_settlement_claim: true }
  const realPolicy = createRecord('policy', {
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
    policy_ref: realPolicy.id, policy_digest: realPolicy.statement.digest,
    decided_at: '2026-09-02T12:06:00.000Z',
  }, { parents: [run.id, realPolicy.id, ...evidenceRefs] })
  const execution = createRecord('execution', {
    execution_id: 'no-real-value-settlement', decision_ref: decision.id, execution_type: 'no-external-action',
    status: 'NO_REAL_VALUE_SETTLEMENT', submitted_at: '2026-09-02T12:06:01.000Z',
  }, { parents: [decision.id] })

  const payload = createBundlePayload(
    [principal, agent, mandate, run, ...messageEvidence, tclkEvidence, realPolicy, decision, execution],
    { createdAt: '2026-09-02T12:07:00.000Z' },
  )
  const bundle = await sealBundle(payload, signer, { keys: [key] })
  const report = verifyBundle(bundle, TrustPolicy.fromKeyRecords([key], { now: new Date('2026-09-02T12:08:00.000Z') }))
  assert.equal(report.state, 'VALID')
  assert.equal(execution.statement.status, 'NO_REAL_VALUE_SETTLEMENT')
  assert.equal(decision.statement.outcome.disposition, 'ACCEPT_COORDINATION_EVIDENCE')
  assert.equal(decision.statement.outcome.authorized_to_execute, false)
})
