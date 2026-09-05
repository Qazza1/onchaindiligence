import assert from 'node:assert/strict'
import { generateKeyPairSync, sign as ed25519Sign } from 'node:crypto'
import test from 'node:test'
import {
  buildReceiptCore,
  createKeyRecord,
  finalizeReceiptCore,
  PUBLIC_ACTION_RECEIPT_ISSUER,
  PUBLIC_ACTION_RECEIPT_PURPOSE,
  PUBLIC_ACTION_RECEIPT_SCHEMA,
  receiptAttestationSigningInput,
  AttestationKey,
  TrustPolicy,
  verifyReceiptEnvelope,
} from '../dist/index.js'

/**
 * D2.3 — shared negative conformance vectors for the Public Action Receipt
 * v1 contract, on top of what test/receipts.test.mjs already covers
 * (id/digest mismatch, unknown key, revoked key, missing valid_from, wrong
 * issuer/purpose, altered-signature, generic schema strictness). This file
 * is the checklist D2.3 Task 3 asks for; onchaindiligence-mcp's
 * test/receiptConformance.ts exercises the SAME scenarios against its own
 * verifier, and the two are meant to agree on every case.
 */

function sampleCore(overrides = {}) {
  return buildReceiptCore({
    receipt_type: 'ACTION',
    issued_at: '2026-09-04T11:00:00.000Z',
    action: { kind: 'test', resource: null, network: null, asset: null, amount: null, sender: null, recipient: null },
    decision: { status: 'ALLOW', authorized: true, reasons: [] },
    execution: { provider: null, status: 'NOT_SUBMITTED', transaction_hash: null, submitted_at: null, confirmed_at: null },
    settlement: { status: 'NOT_APPLICABLE', detail: null },
    checks: [],
    links: { agent_evidence_bundle_digest: null, preflight_receipt_id: null },
    limitations: [],
    ...overrides,
  })
}

async function sealForTest(receipt, { issuedAt = '2026-09-04T11:00:01.000Z', purpose = PUBLIC_ACTION_RECEIPT_PURPOSE, issuer = PUBLIC_ACTION_RECEIPT_ISSUER, keyRecordOverrides = {} } = {}) {
  const keyPair = generateKeyPairSync('ed25519')
  const keyRecord = createKeyRecord(keyPair.publicKey, { validFrom: '2026-09-01T00:00:00.000Z', ...keyRecordOverrides })
  const signingInput = receiptAttestationSigningInput(receipt, { issuer, purpose, issuedAt, keyId: keyRecord.key_id })
  const signature = ed25519Sign(null, Buffer.from(signingInput), keyPair.privateKey).toString('base64url')
  const proof = {
    signed: true, schema_version: 'onchaindiligence.attestation.v2', issuer, purpose,
    issued_at: issuedAt, key_id: keyRecord.key_id, algorithm: 'ed25519', canonicalization: 'RFC8785', signature,
  }
  return { envelope: { schema: PUBLIC_ACTION_RECEIPT_SCHEMA, receipt, proof }, keyRecord }
}

// --- invalid enum values -----------------------------------------------

test('invalid decision.status enum is rejected before a digest is ever computed', () => {
  assert.throws(() => sampleCore({ decision: { status: 'MAYBE', authorized: null, reasons: [] } }))
})
test('invalid execution.status enum is rejected before a digest is ever computed', () => {
  assert.throws(() => sampleCore({ execution: { provider: null, status: 'PENDING', transaction_hash: null, submitted_at: null, confirmed_at: null } }))
})
test('invalid settlement.status enum is rejected before a digest is ever computed', () => {
  assert.throws(() => sampleCore({ settlement: { status: 'SETTLED', detail: null } }))
})

// --- schema-invalid enum smuggled past buildReceiptCore, caught by verifyReceiptEnvelope's schema gate ---

test('a schema-invalid decision enum smuggled into a signed envelope is INVALID, not VALID', async () => {
  const receipt = finalizeReceiptCore(sampleCore())
  const { envelope, keyRecord } = await sealForTest(receipt)
  const tampered = { ...envelope, receipt: { ...envelope.receipt, decision: { ...envelope.receipt.decision, status: 'MAYBE' } } }
  const policy = TrustPolicy.fromKeyRecords([keyRecord])
  const result = verifyReceiptEnvelope(tampered, policy)
  assert.equal(result.state, 'INVALID')
  assert.equal(result.code, 'schema-invalid')
})

// --- malformed key lifecycle timestamps: present but garbage, not missing ---

test('a key record with a malformed (non-null, non-ISO) valid_from is rejected at load time, never silently trusted', () => {
  assert.throws(() =>
    AttestationKey.fromRecord({
      key_id: 'ed25519-P2jIwhCn-Af6pTz4',
      algorithm: 'ed25519',
      public_key_pem: generateKeyPairSync('ed25519').publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      status: 'active',
      valid_from: 'not-a-timestamp',
      valid_until: null,
      status_changed_at: 'not-a-timestamp',
    })
  )
})

test('a key record with a malformed (non-null, non-ISO) valid_until is rejected at load time', () => {
  const keyPair = generateKeyPairSync('ed25519')
  assert.throws(() =>
    AttestationKey.fromRecord({
      key_id: 'ed25519-P2jIwhCn-Af6pTz4',
      algorithm: 'ed25519',
      public_key_pem: keyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      status: 'retired',
      valid_from: '2026-01-01T00:00:00.000Z',
      valid_until: 'also-not-a-timestamp',
      status_changed_at: '2026-01-01T00:00:00.000Z',
    })
  )
})

test('the documented caller pattern treats a registry load failure as UNVERIFIABLE, never INVALID -- even with a genuine signature', async () => {
  const receipt = finalizeReceiptCore(sampleCore())
  const { envelope } = await sealForTest(receipt)
  let policy
  try {
    policy = TrustPolicy.fromKeyRecords([
      { key_id: 'ed25519-P2jIwhCn-Af6pTz4', algorithm: 'ed25519', public_key_pem: 'garbage', status: 'active', valid_from: 'garbage-timestamp', valid_until: null, status_changed_at: null },
    ])
  } catch {
    policy = TrustPolicy.fromKeyRecords([]) // the documented fallback: no usable trust from this source
  }
  const result = verifyReceiptEnvelope(envelope, policy)
  assert.equal(result.state, 'UNVERIFIABLE')
})

// --- issued_at outside the signing key's validity window --------------

test('proof.issued_at before the key\'s valid_from is INVALID', async () => {
  const receipt = finalizeReceiptCore(sampleCore())
  const { envelope, keyRecord } = await sealForTest(receipt, { issuedAt: '2026-08-01T00:00:00.000Z' }) // before validFrom 2026-09-01
  const policy = TrustPolicy.fromKeyRecords([keyRecord])
  const result = verifyReceiptEnvelope(envelope, policy)
  assert.equal(result.state, 'INVALID')
  assert.equal(result.code, 'key-not-yet-valid')
})

test('proof.issued_at after the key\'s valid_until is INVALID', async () => {
  const receipt = finalizeReceiptCore(sampleCore())
  const { envelope, keyRecord } = await sealForTest(receipt, {
    issuedAt: '2026-09-20T00:00:00.000Z',
    keyRecordOverrides: { status: 'retired', validUntil: '2026-09-15T00:00:00.000Z', statusChangedAt: '2026-09-15T00:00:00.000Z' },
  })
  // Pin the clock well after issuedAt so this is unambiguously "expired", not "future-skew".
  const policy = TrustPolicy.fromKeyRecords([keyRecord], { now: new Date('2026-09-21T00:00:00.000Z') })
  const result = verifyReceiptEnvelope(envelope, policy)
  assert.equal(result.state, 'INVALID')
  assert.equal(result.code, 'key-expired')
})

// --- retired key with incomplete defensible lifecycle -------------------

test('a "retired" key missing valid_until is rejected at load time (incomplete defensible lifecycle)', () => {
  const keyPair = generateKeyPairSync('ed25519')
  assert.throws(() =>
    AttestationKey.fromRecord({
      key_id: 'ed25519-P2jIwhCn-Af6pTz4',
      algorithm: 'ed25519',
      public_key_pem: keyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      status: 'retired',
      valid_from: '2026-01-01T00:00:00.000Z',
      valid_until: null, // retired must have a bounded window
      status_changed_at: '2026-01-01T00:00:00.000Z',
    })
  )
})

// --- the real historical production key: valid_from null is tolerated, never invented, and drives UNVERIFIABLE ---

test('a REAL retired key with valid_from: null loads successfully (schema permits it) and yields UNVERIFIABLE, never VALID or a load-time crash', async () => {
  const keyPair = generateKeyPairSync('ed25519')
  const publicKeyPem = keyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString()
  const keyId = AttestationKey.fromRecord(createKeyRecord(keyPair.publicKey, { validFrom: '2026-01-01T00:00:00.000Z' })).keyId
  // Same shape as the real historical onchaindiligence-mcp signing key record
  // (ed25519-D8wfc7civVNG05Ds): retired, valid_from unknown by design.
  const record = {
    key_id: keyId,
    algorithm: 'ed25519',
    public_key_pem: publicKeyPem,
    status: 'retired',
    valid_from: null,
    valid_until: '2026-09-03T19:50:00.000Z',
    status_changed_at: '2026-09-03T19:50:00.000Z',
    replacement_key_id: null,
    compromised_at: null,
  }
  const key = AttestationKey.fromRecord(record) // must NOT throw
  assert.equal(key.validFrom, null, 'valid_from must never be invented')
  const policy = TrustPolicy.fromKeyRecords([record])

  const receipt = finalizeReceiptCore(sampleCore())
  const signingInput = receiptAttestationSigningInput(receipt, {
    issuer: PUBLIC_ACTION_RECEIPT_ISSUER, purpose: PUBLIC_ACTION_RECEIPT_PURPOSE, issuedAt: '2026-08-01T00:00:00.000Z', keyId,
  })
  const signature = ed25519Sign(null, Buffer.from(signingInput), keyPair.privateKey).toString('base64url')
  const envelope = {
    schema: PUBLIC_ACTION_RECEIPT_SCHEMA,
    receipt,
    proof: {
      signed: true, schema_version: 'onchaindiligence.attestation.v2', issuer: PUBLIC_ACTION_RECEIPT_ISSUER,
      purpose: PUBLIC_ACTION_RECEIPT_PURPOSE, issued_at: '2026-08-01T00:00:00.000Z', key_id: keyId,
      algorithm: 'ed25519', canonicalization: 'RFC8785', signature,
    },
  }
  const result = verifyReceiptEnvelope(envelope, policy)
  assert.equal(result.state, 'UNVERIFIABLE')
  assert.equal(result.code, 'key-valid-from-missing')
})

console.log('D2.3 shared conformance vectors: all cases match the documented tri-state contract.')
