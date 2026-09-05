import assert from 'node:assert/strict'
import { generateKeyPairSync, sign as ed25519Sign } from 'node:crypto'
import test from 'node:test'
import {
  buildReceiptCore,
  computeReceiptDigest,
  createKeyRecord,
  finalizeReceiptCore,
  formatReceiptId,
  isValidReceiptIdFormat,
  normalizeReceiptId,
  PUBLIC_ACTION_RECEIPT_ISSUER,
  PUBLIC_ACTION_RECEIPT_PURPOSE,
  PUBLIC_ACTION_RECEIPT_SCHEMA,
  receiptAttestationSigningInput,
  TrustPolicy,
  verifyReceiptEnvelope,
} from '../dist/index.js'

// Focused conformance tests for D2.0A: Public Action Receipt v1.
// No production private keys anywhere here -- every keypair is freshly
// generated per test run, and every registry is caller-supplied.

const NOW = new Date('2026-09-04T12:00:00.000Z')

function sampleCore(overrides = {}) {
  return buildReceiptCore({
    receipt_type: 'ACTION',
    issued_at: '2026-09-04T11:00:00.000Z',
    action: {
      kind: 'payment-preflight', resource: null, network: null, asset: 'pathUSD',
      amount: '1.00', sender: null, recipient: '0x000000000000000000000000000000000000dEaD',
    },
    decision: { status: 'REQUIRE_APPROVAL', authorized: false, reasons: ['recipient-wallet-not-bound-to-sec-filer'] },
    execution: { provider: null, status: 'NOT_SUBMITTED', transaction_hash: null, submitted_at: null, confirmed_at: null },
    settlement: { status: 'NOT_APPLICABLE', detail: 'No execution was submitted; there is nothing to settle.' },
    checks: [
      { id: 'wallet-sanctions-screen', result: 'PASS', summary: 'Not sanctioned.', evidence_digest: null },
      { id: 'recipient-wallet-bound-to-counterparty', result: 'FAIL', summary: 'No binding evidence exists.', evidence_digest: null },
    ],
    links: { agent_evidence_bundle_digest: null, preflight_receipt_id: null },
    limitations: ['This is a test fixture, not a real check.'],
    ...overrides,
  })
}

/** Simulates the real production signer (the existing /attest endpoint): mints its own keypair, signs the exact bytes this package says to sign. Test-only. */
async function sealForTest(receipt, { issuedAt = '2026-09-04T11:00:01.000Z', purpose = PUBLIC_ACTION_RECEIPT_PURPOSE, issuer = PUBLIC_ACTION_RECEIPT_ISSUER } = {}) {
  const keyPair = generateKeyPairSync('ed25519')
  const keyRecord = createKeyRecord(keyPair.publicKey, { validFrom: '2026-09-01T00:00:00.000Z' })
  const signingInput = receiptAttestationSigningInput(receipt, { issuer, purpose, issuedAt, keyId: keyRecord.key_id })
  const signature = ed25519Sign(null, Buffer.from(signingInput), keyPair.privateKey).toString('base64url')
  const proof = {
    signed: true, schema_version: 'onchaindiligence.attestation.v2', issuer, purpose,
    issued_at: issuedAt, key_id: keyRecord.key_id, algorithm: 'ed25519', canonicalization: 'RFC8785', signature,
  }
  return { envelope: { schema: PUBLIC_ACTION_RECEIPT_SCHEMA, receipt, proof }, keyRecord }
}

// --- receipt id: deterministic, not sequential, well-defined encoding ---

test('receipt id is deterministic, human-friendly, and derived from the digest', () => {
  const core = sampleCore()
  const receipt = finalizeReceiptCore(core)
  assert.equal(receipt.receipt_id, formatReceiptId(receipt.receipt_digest))
  assert.match(receipt.receipt_id, /^OCD-RCP-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/)
  // Crockford Base32 excludes I, L, O, U entirely -- check only the generated
  // body, since the literal "OCD" prefix itself contains an O.
  const body = receipt.receipt_id.slice('OCD-RCP-'.length)
  assert.doesNotMatch(body, /[ILOU]/)
  // Same core -> same id, every time (deterministic, not a random/sequential counter).
  const again = finalizeReceiptCore(sampleCore())
  assert.equal(again.receipt_id, receipt.receipt_id)
  assert.equal(again.receipt_digest, receipt.receipt_digest)
})

test('receipt ids are not sequential: unrelated receipts do not differ by a small counter', () => {
  const ids = [0, 1, 2, 3, 4].map((i) =>
    finalizeReceiptCore(sampleCore({ issued_at: `2026-09-04T11:00:0${i}.000Z` })).receipt_id
  )
  assert.equal(new Set(ids).size, ids.length, 'each distinct receipt must get a distinct id')
  // "Sequential" would mean adjacent ids share every character but the last
  // group; Crockford-encoded digest fragments must not.
  for (let i = 1; i < ids.length; i++) {
    assert.notEqual(ids[i].slice(0, 'OCD-RCP-XXXX'.length), ids[i - 1].slice(0, 'OCD-RCP-XXXX'.length))
  }
})

test('normalizeReceiptId tolerates case and Crockford look-alikes, isValidReceiptIdFormat is strict', () => {
  const id = finalizeReceiptCore(sampleCore()).receipt_id
  assert.equal(normalizeReceiptId(id.toLowerCase()), id)
  assert.equal(isValidReceiptIdFormat(id), true)
  assert.equal(isValidReceiptIdFormat('not-a-receipt-id'), false)
  assert.equal(normalizeReceiptId('OCD-RCP-0000-0000-0000-000!'), null)
})

// --- digest changes if any claim changes ---

test('digest changes if any receipt claim changes, and is stable otherwise', () => {
  const base = computeReceiptDigest(sampleCore())
  const changedDecision = computeReceiptDigest(sampleCore({ decision: { status: 'BLOCK', authorized: false, reasons: [] } }))
  const changedAmount = computeReceiptDigest({ ...sampleCore(), action: { ...sampleCore().action, amount: '2.00' } })
  const changedLimitations = computeReceiptDigest(sampleCore({ limitations: [] }))
  assert.notEqual(changedDecision, base)
  assert.notEqual(changedAmount, base)
  assert.notEqual(changedLimitations, base)
  assert.equal(computeReceiptDigest(sampleCore()), base, 'identical content must reproduce the identical digest')
})

// --- proof: VALID / INVALID / UNVERIFIABLE, same philosophy as Agent Evidence ---

test('A: a genuinely signed, untampered receipt verifies VALID', async () => {
  const receipt = finalizeReceiptCore(sampleCore())
  const { envelope, keyRecord } = await sealForTest(receipt)
  const policy = TrustPolicy.fromKeyRecords([keyRecord], { now: NOW })
  const result = verifyReceiptEnvelope(envelope, policy)
  assert.equal(result.state, 'VALID')
  assert.equal(result.receipt.receipt_id, receipt.receipt_id)
})

test('B: exact content tampering after signing is rejected -> INVALID', async () => {
  const receipt = finalizeReceiptCore(sampleCore())
  const { envelope, keyRecord } = await sealForTest(receipt)
  const policy = TrustPolicy.fromKeyRecords([keyRecord], { now: NOW })

  const tampered = structuredClone(envelope)
  tampered.receipt.decision.status = 'ALLOW' // an attacker "approving" a withheld payment
  tampered.receipt.decision.authorized = true
  const result = verifyReceiptEnvelope(tampered, policy)
  assert.equal(result.state, 'INVALID')
  assert.match(result.code, /digest-mismatch|signature-invalid/)
})

test('unknown signer / unavailable trust registry -> UNVERIFIABLE, never INVALID', async () => {
  const receipt = finalizeReceiptCore(sampleCore())
  const { envelope } = await sealForTest(receipt)
  const emptyPolicy = TrustPolicy.fromKeyRecords([], { now: NOW }) // simulates "registry unreachable"
  const result = verifyReceiptEnvelope(envelope, emptyPolicy)
  assert.equal(result.state, 'UNVERIFIABLE')
  assert.equal(result.code, 'key-not-trusted')
})

test('receipt_id / receipt_digest mismatch is rejected even with a valid signature', async () => {
  const receipt = finalizeReceiptCore(sampleCore())
  const { envelope, keyRecord } = await sealForTest(receipt)
  const policy = TrustPolicy.fromKeyRecords([keyRecord], { now: NOW })

  // Forge a plausible-looking but wrong id, re-sign over the forged receipt so
  // the SIGNATURE itself is genuine -- only the digest/id relationship is broken.
  const forgedReceipt = { ...envelope.receipt, receipt_id: 'OCD-RCP-0000-0000-0000-0000' }
  const reSigned = await sealForTest(forgedReceipt, {})
  const result = verifyReceiptEnvelope(reSigned.envelope, TrustPolicy.fromKeyRecords([reSigned.keyRecord], { now: NOW }))
  assert.equal(result.state, 'INVALID')
  assert.equal(result.code, 'id-mismatch')
})

test('revoked signer fails closed to INVALID, matching existing key lifecycle semantics', async () => {
  const receipt = finalizeReceiptCore(sampleCore())
  const { envelope, keyRecord } = await sealForTest(receipt)
  const revoked = { ...keyRecord, status: 'revoked', status_changed_at: '2026-09-04T11:30:00.000Z', status_reason: 'test revocation' }
  const policy = TrustPolicy.fromKeyRecords([revoked], { now: NOW })
  const result = verifyReceiptEnvelope(envelope, policy)
  assert.equal(result.state, 'INVALID')
  assert.equal(result.code, 'key-revoked')
})

test('a key with no valid_from boundary is UNVERIFIABLE, never silently VALID', async () => {
  const receipt = finalizeReceiptCore(sampleCore())
  const { envelope, keyRecord } = await sealForTest(receipt)
  const noActivation = { ...keyRecord, valid_from: null, status_changed_at: null }
  const policy = TrustPolicy.fromKeyRecords([noActivation], { now: NOW })
  const result = verifyReceiptEnvelope(envelope, policy)
  assert.equal(result.state, 'UNVERIFIABLE')
  assert.equal(result.code, 'key-valid-from-missing')
})

test('wrong issuer or purpose is rejected -> INVALID (this verifier is not a generic attestation checker)', async () => {
  const receipt = finalizeReceiptCore(sampleCore())
  const { envelope: wrongPurpose, keyRecord: k1 } = await sealForTest(receipt, { purpose: 'compliance-screening-result' })
  const r1 = verifyReceiptEnvelope(wrongPurpose, TrustPolicy.fromKeyRecords([k1], { now: NOW }))
  assert.equal(r1.state, 'INVALID')
  assert.equal(r1.code, 'purpose-mismatch')

  const { envelope: wrongIssuer, keyRecord: k2 } = await sealForTest(receipt, { issuer: 'https://evil.example' })
  const r2 = verifyReceiptEnvelope(wrongIssuer, TrustPolicy.fromKeyRecords([k2], { now: NOW }))
  assert.equal(r2.state, 'INVALID')
  assert.equal(r2.code, 'issuer-mismatch')
})

// --- schema strictness ---

test('schema strictness: an envelope with an extra or missing field is rejected', async () => {
  const receipt = finalizeReceiptCore(sampleCore())
  const { envelope, keyRecord } = await sealForTest(receipt)
  const policy = TrustPolicy.fromKeyRecords([keyRecord], { now: NOW })

  const extraField = structuredClone(envelope)
  extraField.receipt.unexpected_field = 'nope'
  assert.equal(verifyReceiptEnvelope(extraField, policy).state, 'INVALID')

  const missingField = structuredClone(envelope)
  delete missingField.receipt.limitations
  assert.equal(verifyReceiptEnvelope(missingField, policy).state, 'INVALID')

  const wrongSchemaTag = structuredClone(envelope)
  wrongSchemaTag.schema = 'onchaindiligence.public-action-receipt.v2'
  assert.equal(verifyReceiptEnvelope(wrongSchemaTag, policy).state, 'INVALID')

  const badDecisionEnum = structuredClone(envelope)
  badDecisionEnum.receipt.decision.status = 'MAYBE'
  assert.equal(verifyReceiptEnvelope(badDecisionEnum, policy).state, 'INVALID')
})

test('buildReceiptCore rejects an invalid enum value before a digest is ever computed', () => {
  assert.throws(() => sampleCore({ decision: { status: 'MAYBE', authorized: null, reasons: [] } }))
  assert.throws(() => sampleCore({ execution: { provider: null, status: 'SOMEDAY', transaction_hash: null, submitted_at: null, confirmed_at: null } }))
  assert.throws(() => sampleCore({ receipt_type: 'INVOICE' }))
})

// --- decision / proof / execution / settlement independence ---

test('decision, execution, settlement and proof never collapse into one flag: REQUIRE_APPROVAL + NOT_SUBMITTED + NOT_APPLICABLE + VALID is a coherent, expected result', async () => {
  const receipt = finalizeReceiptCore(sampleCore())
  const { envelope, keyRecord } = await sealForTest(receipt)
  const policy = TrustPolicy.fromKeyRecords([keyRecord], { now: NOW })
  const result = verifyReceiptEnvelope(envelope, policy)

  assert.equal(result.state, 'VALID', 'the SIGNATURE is genuine')
  assert.equal(result.receipt.decision.status, 'REQUIRE_APPROVAL', 'policy did not allow the action')
  assert.equal(result.receipt.decision.authorized, false)
  assert.equal(result.receipt.execution.status, 'NOT_SUBMITTED', 'nothing was executed')
  assert.equal(result.receipt.settlement.status, 'NOT_APPLICABLE', 'nothing to settle')
  // These four fields are independently readable -- proof VALID never implies
  // authorized:true, and REQUIRE_APPROVAL never implies the proof is fake.
  assert.equal(typeof result.state, 'string')
  assert.equal(typeof result.receipt.decision.status, 'string')
  assert.equal(typeof result.receipt.execution.status, 'string')
  assert.equal(typeof result.receipt.settlement.status, 'string')
})
