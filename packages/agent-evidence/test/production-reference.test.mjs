import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { TrustPolicy, verifyBundle } from '../dist/index.js'

const reference = new URL('../../../examples/production/p1_8/', import.meta.url)

async function json(name) {
  return JSON.parse(await readFile(new URL(name, reference), 'utf8'))
}

test('the real P1.8 multi-provider production reference verifies offline in TypeScript', async () => {
  const [bundle, trust, manifest] = await Promise.all([
    json('bundle.json'),
    json('trust-policy.json'),
    json('manifest.json'),
  ])
  const policy = TrustPolicy.fromKeyRecords(trust.keys, {
    now: new Date(trust.reference_verification_time),
    minimumValidSignatures: trust.minimum_valid_signatures,
    requiredSignatureKeyIds: trust.required_signature_key_ids,
  })
  const report = verifyBundle(bundle, policy)
  assert.equal(report.state, 'VALID')
  assert.equal(report.bundle_id, manifest.bundle_id)
  assert.equal(report.payload.records.filter((record) => record.kind === 'evidence').length, 2)
  assert.equal(report.payload.records.find((record) => record.kind === 'execution').statement.status,
    'withheld-not-submitted')
})

test('missing the P1.8 source-witness trust remains UNVERIFIABLE', async () => {
  const [bundle, trust] = await Promise.all([json('bundle.json'), json('trust-policy.json')])
  const bundleSigner = bundle.envelope.signatures[0].keyid
  const bundleKey = trust.keys.find((key) => key.key_id === bundleSigner)
  assert.ok(bundleKey)
  const report = verifyBundle(bundle, TrustPolicy.fromKeyRecords([bundleKey], {
    now: new Date(trust.reference_verification_time),
  }))
  assert.equal(report.state, 'UNVERIFIABLE')
  assert.ok(report.components.some((component) =>
    component.component === 'source-proof' && component.code === 'key-not-trusted'))
})
