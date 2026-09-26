import assert from 'node:assert/strict'
import { generateKeyPairSync, sign as ed25519Sign } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import {
  createKeyRecord,
  createSignedPaymentClaim,
  canonicalize,
  dssePae,
  signSignedPaymentClaim,
  SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE,
  TrustPolicy,
  verifySignedPaymentClaim,
  verifyReceiptEnvelope,
} from '../dist/index.js'

const NOW = new Date('2026-09-26T12:00:00.000Z')

function fixture() {
  const pair = generateKeyPairSync('ed25519')
  const key = createKeyRecord(pair.publicKey, { validFrom: '2026-09-01T00:00:00.000Z' })
  const claim = createSignedPaymentClaim({
    issuer: { id: 'https://payments.example', name: 'Example Payments' },
    issuedAt: '2026-09-26T11:00:00.000Z',
    providerReference: 'provider-payment-123',
    payment: { network: 'eip155:8453', asset: 'USDC', amount: '0.01', recipient: '0xrecipient' },
    execution: { claimed_status: 'SUCCEEDED', transaction_hash: '0xtx' },
  })
  const signer = { keyId: key.key_id, sign: (bytes) => ed25519Sign(null, bytes, pair.privateKey) }
  const policy = TrustPolicy.fromKeyRecords([key], {
    now: NOW, paymentClaimIssuerKeyIds: { 'https://payments.example': [key.key_id] },
  })
  return { claim, signer, policy, key, privateKey: pair.privateKey }
}

test('signed payment claim is a trusted-issuer signature claim, not a settlement assertion', async () => {
  const { claim, signer, policy } = fixture()
  const envelope = await signSignedPaymentClaim(claim, signer)
  const verified = verifySignedPaymentClaim(envelope, policy, { expectedIssuer: 'https://payments.example' })
  assert.equal(verified.state, 'VALID')
  assert.equal(verified.scope, 'PLATFORM_CLAIM_SIGNATURE')
  assert.match(verified.limitations[0], /not settlement, authorization/)
})

test('tampering, wrong payload type, and claim-id mismatch fail closed', async () => {
  const { claim, signer, policy, privateKey } = fixture()
  const envelope = await signSignedPaymentClaim(claim, signer)
  const tampered = structuredClone(envelope)
  tampered.payload = Buffer.from(JSON.stringify({ ...claim, provider_reference: 'changed' })).toString('base64')
  assert.equal(verifySignedPaymentClaim(tampered, policy).state, 'INVALID')
  assert.equal(verifySignedPaymentClaim({ ...envelope, payloadType: 'text/plain' }, policy).state, 'INVALID')
  const forged = structuredClone(claim)
  forged.claim_id = 'sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
  const forgedPayload = canonicalize(forged)
  const mismatch = {
    ...envelope,
    payload: Buffer.from(forgedPayload).toString('base64'),
    signatures: [{
      keyid: signer.keyId,
      sig: ed25519Sign(null, dssePae(SIGNED_PAYMENT_CLAIM_PAYLOAD_TYPE, forgedPayload), privateKey).toString('base64'),
    }],
  }
  // A valid signature is deliberately not enough if the self-identifying claim is inconsistent.
  assert.equal(verifySignedPaymentClaim(mismatch, policy).state, 'INVALID')
})

test('unknown, revoked, and out-of-window issuer keys never become VALID', async () => {
  const { claim, signer, key } = fixture()
  const envelope = await signSignedPaymentClaim(claim, signer)
  assert.equal(verifySignedPaymentClaim(envelope, TrustPolicy.fromKeyRecords([], { now: NOW })).state, 'UNVERIFIABLE')
  const revoked = { ...key, status: 'revoked', status_changed_at: '2026-09-26T11:30:00.000Z', status_reason: 'test' }
  assert.equal(verifySignedPaymentClaim(envelope, TrustPolicy.fromKeyRecords([revoked], {
    now: NOW, paymentClaimIssuerKeyIds: { 'https://payments.example': [key.key_id] },
  })).state, 'INVALID')
  const future = { ...key, valid_from: '2026-09-26T11:30:00.000Z', status_changed_at: '2026-09-26T11:30:00.000Z' }
  assert.equal(verifySignedPaymentClaim(envelope, TrustPolicy.fromKeyRecords([future], {
    now: NOW, paymentClaimIssuerKeyIds: { 'https://payments.example': [key.key_id] },
  })).state, 'INVALID')
})

test('a caller-trusted key is not automatically trusted for an arbitrary issuer', async () => {
  const { claim, signer, key } = fixture()
  const envelope = await signSignedPaymentClaim(claim, signer)
  const wrongIssuerBinding = TrustPolicy.fromKeyRecords([key], {
    now: NOW, paymentClaimIssuerKeyIds: { 'https://issuer-a.example': [key.key_id] },
  })
  assert.equal(verifySignedPaymentClaim(envelope, wrongIssuerBinding).state, 'UNVERIFIABLE')
  assert.equal(verifySignedPaymentClaim(envelope, wrongIssuerBinding).code, 'issuer-key-binding-missing')
})

test('issuer is caller-pinned and claim/receipt formats cannot be replayed across contracts', async () => {
  const { claim, signer, policy } = fixture()
  const envelope = await signSignedPaymentClaim(claim, signer)
  assert.equal(verifySignedPaymentClaim(envelope, policy, { expectedIssuer: 'https://other.example' }).state, 'INVALID')
  assert.equal(verifySignedPaymentClaim({ ...envelope, payloadType: 'application/vnd.onchaindiligence.public-action-receipt.v1+json' }, policy).state, 'INVALID')
  assert.throws(() => createSignedPaymentClaim({
    issuer: { id: 'https://payments.example/path' }, providerReference: 'x',
    payment: { network: 'eip155:8453' }, execution: { claimed_status: 'UNKNOWN' },
  }))
})

test('canonical issuer origin accepts lowercase non-default ports and rejects URL variants identically', () => {
  for (const issuer of ['https://issuer.example:8443']) {
    assert.doesNotThrow(() => createSignedPaymentClaim({ issuer: { id: issuer }, providerReference: 'x', payment: { network: 'eip155:1' }, execution: { claimed_status: 'UNKNOWN' } }))
  }
  for (const issuer of ['https://Issuer.example', 'https://issuer.example:443', 'https://issuer.example/', 'https://issuer.example/a', 'https://issuer.example?q', 'https://issuer.example#f', 'https://u@issuer.example']) {
    assert.throws(() => createSignedPaymentClaim({ issuer: { id: issuer }, providerReference: 'x', payment: { network: 'eip155:1' }, execution: { claimed_status: 'UNKNOWN' } }), issuer)
  }
})

test('public signed-payment-claim corpus is authoritative', async () => {
  const corpus = JSON.parse(await readFile(new URL('../conformance/signed-payment-claim-v1.json', import.meta.url)))
  for (const item of corpus.cases) {
    const records = item.keys === 'none' ? [] : [corpus.keys[item.keys]]
    const policy = TrustPolicy.fromKeyRecords(records, { now: new Date(corpus.now), paymentClaimIssuerKeyIds: item.trust })
    if (item.expected) {
      const checked = verifySignedPaymentClaim(corpus.envelopes[item.envelope], policy)
      assert.equal(checked.state, item.expected, item.id)
      assert.equal(checked.scope, item.scope, item.id)
    }
    if (item.expected_receipt) {
      assert.equal(verifyReceiptEnvelope(corpus.envelopes[item.envelope], policy).state, item.expected_receipt, item.id)
    }
  }
  for (const [issuer, accepted] of corpus.issuer_origins) {
    const build = () => createSignedPaymentClaim({ issuer: { id: issuer }, providerReference: 'x', payment: { network: 'eip155:1' }, execution: { claimed_status: 'UNKNOWN' } })
    if (accepted) assert.doesNotThrow(build, issuer); else assert.throws(build, issuer)
  }
})
