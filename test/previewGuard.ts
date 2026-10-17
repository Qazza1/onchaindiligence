/** Preview deployments never sign, anchor on mainnet, or take mainnet payments. Run: npx tsx test/previewGuard.ts */
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'

const { privateKey } = generateKeyPairSync('ed25519')
process.env.ATTESTATION_PRIVATE_KEY = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
process.env.ATTESTATION_KEY_ACTIVATED_AT = '2026-01-01T00:00:00.000Z'

const { previewMaySign, previewMayAnchor, previewBootViolations } = await import('../src/previewGuard.js')
const attestation = await import('../src/attestation.js')

const prod = { VERCEL_ENV: 'production' } as NodeJS.ProcessEnv
const preview = { VERCEL_ENV: 'preview' } as NodeJS.ProcessEnv
assert.equal(previewMaySign('ed25519-anything', prod), true)
assert.equal(previewMaySign('ed25519-anything', {}), true, 'local/dev unaffected')
assert.equal(previewMaySign('ed25519-anything', preview), false, 'preview never signs by default')
assert.equal(previewMaySign('ed25519-PRODUCTIONKEY0000', { ...preview, OCD_PREVIEW_ISOLATED_SIGNER: 'true', ATTESTATION_ROTATION_REPLACEMENT_KEY_ID: 'ed25519-PRODUCTIONKEY0000' }), false, 'declared production key refused even when opted in')
assert.equal(previewMaySign('ed25519-D8wfc7civVNG05Ds', { ...preview, OCD_PREVIEW_ISOLATED_SIGNER: 'true' }), false, 'historical production key refused')
assert.equal(previewMaySign('ed25519-SEPARATEPREVIEWKEY', { ...preview, OCD_PREVIEW_ISOLATED_SIGNER: 'true', ATTESTATION_ROTATION_REPLACEMENT_KEY_ID: 'ed25519-PRODUCTIONKEY0000' }), true)
console.log('ok  preview signing requires an explicitly separate, non-production key')

// The real signer chokepoint honours it.
process.env.VERCEL_ENV = 'production'
assert.equal(attestation.attestationSigningReady(), true)
process.env.VERCEL_ENV = 'preview'
assert.equal(attestation.attestationSigningReady(), false, 'attestationSigningReady is false in preview')
delete process.env.VERCEL_ENV
console.log('ok  attestationSigningReady refuses in preview')

assert.equal(previewMayAnchor(4217, preview), false)
assert.equal(previewMayAnchor(42431, preview), true)
assert.equal(previewMayAnchor(null, preview), false)
assert.equal(previewMayAnchor(4217, prod), true)
console.log('ok  preview never anchors on Tempo mainnet')

assert.equal(previewBootViolations({ tempoTestnet: false }, preview).length, 1)
assert.deepEqual(previewBootViolations({ tempoTestnet: true }, preview), [])
assert.deepEqual(previewBootViolations({ tempoTestnet: false }, prod), [])
assert.doesNotMatch(previewBootViolations({ tempoTestnet: false }, preview).join(), /0x|sk_|secret=/i, 'names only, never values')
console.log('ok  preview refuses to boot with mainnet MPP payments')
