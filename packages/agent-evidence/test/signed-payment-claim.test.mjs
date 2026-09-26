import assert from 'node:assert/strict'
import { generateKeyPairSync, sign as ed25519Sign } from 'node:crypto'
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
  const policy = TrustPolicy.fromKeyRecords([key], { now: NOW })
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
  assert.equal(verifySignedPaymentClaim(envelope, TrustPolicy.fromKeyRecords([revoked], { now: NOW })).state, 'INVALID')
  const future = { ...key, valid_from: '2026-09-26T11:30:00.000Z', status_changed_at: '2026-09-26T11:30:00.000Z' }
  assert.equal(verifySignedPaymentClaim(envelope, TrustPolicy.fromKeyRecords([future], { now: NOW })).state, 'INVALID')
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
