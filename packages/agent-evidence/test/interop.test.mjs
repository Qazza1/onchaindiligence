import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import test from 'node:test'
import {
  contentId,
  createBundlePayload,
  createEd25519Signer,
  createRecord,
  deriveKeyId,
  parseAgentEvidenceKeyRegistry,
  sealBundle,
  TrustPolicy,
  TrustPolicyError,
  trustPolicyFromKeyRegistry,
  verifyBundle,
} from '../dist/index.js'

// Focused conformance tests for the Agent Evidence Interoperability Profile v1
// (docs/AGENT_EVIDENCE_INTEROP.md): the generic public signer key registry
// (schema `agent-evidence-key-registry.schema.json`) and the reusable
// parseAgentEvidenceKeyRegistry / trustPolicyFromKeyRegistry SDK APIs.
//
// No production private keys are used anywhere here -- every keypair is
// freshly generated per test run.

const NOW = new Date('2026-09-03T12:00:00.000Z')

function registry(entries, overrides = {}) {
  return { schema_version: 1, issuer: 'urn:example:test-issuer', environment: 'production', keys: entries, ...overrides }
}

function registryEntry(pem, keyId, overrides = {}) {
  return {
    key_id: keyId,
    algorithm: 'Ed25519',
    public_key_pem: pem,
    valid_from: '2026-09-01T00:00:00.000Z',
    valid_until: null,
    revoked_at: null,
    status: 'active',
    ...overrides,
  }
}

/** A minimal, deterministic Mandate -> Evidence -> Policy -> Decision -> Execution bundle, sealed with `signerKeyPair`. */
async function buildSignedBundle(signerKeyPair, { claimedVerificationKeyPem } = {}) {
  const principal = createRecord('principal', { principal_id: 'urn:example:org', principal_type: 'organization' })
  const agent = createRecord('agent', {
    agent_id: 'urn:example:interop-test-agent', agent_version: '1', operator_ref: principal.id,
  }, { parents: [principal.id] })
  const mandate = createRecord('mandate', {
    mandate_id: 'interop-test-mandate', principal_ref: principal.id, scope: { action: 'record-only' },
    valid_from: '2026-09-01T00:00:00.000Z', valid_until: '2026-09-05T00:00:00.000Z',
  }, { parents: [principal.id] })
  const run = createRecord('run', {
    run_external_id: 'interop-test-run', agent_ref: agent.id, mandate_ref: mandate.id, started_at: '2026-09-03T12:00:00.000Z',
  }, { parents: [agent.id, mandate.id] })
  const evidenceValue = { observation: 'interop conformance fixture', trust_mode: 'agent-assertion' }
  const evidence = createRecord('evidence', {
    evidence_type: 'interop-fixture', run_ref: run.id, trust_mode: 'agent-assertion',
    source: { id: 'urn:example:fixture', type: 'test' }, tool: { name: 'interop-test', version: '1' },
    request: { digest: { sha256: contentId({}).slice('sha256:'.length) }, media_type: 'application/json' },
    response: { mode: 'embedded', media_type: 'application/json', value: evidenceValue, digest: { sha256: contentId(evidenceValue).slice('sha256:'.length) } },
    observed_at: '2026-09-03T12:00:01.000Z', expires_at: null, scope: {},
  }, { parents: [run.id] })
  const policyDocument = { action: 'record-only' }
  const policy = createRecord('policy', {
    policy_id: 'interop-test-policy', version: '1', source: 'https://example.invalid/policy',
    digest: { sha256: contentId(policyDocument).slice('sha256:'.length) },
    effective_from: '2026-09-01T00:00:00.000Z', policy: policyDocument,
  }, { parents: [run.id] })
  const decision = createRecord('decision', {
    decision_id: 'interop-test-decision', run_ref: run.id, agent_ref: agent.id, decision_type: 'interop-conformance',
    outcome: { disposition: 'ACCEPT_COORDINATION_EVIDENCE', authorized_to_execute: false }, evidence_refs: [evidence.id],
    policy_ref: policy.id, policy_digest: policy.statement.digest, decided_at: '2026-09-03T12:00:02.000Z',
  }, { parents: [run.id, evidence.id, policy.id] })
  const execution = createRecord('execution', {
    execution_id: 'interop-test-execution', decision_ref: decision.id, execution_type: 'no-external-action',
    status: 'NO_REAL_VALUE_SETTLEMENT', submitted_at: '2026-09-03T12:00:03.000Z',
  }, { parents: [decision.id] })

  const payload = createBundlePayload(
    [principal, agent, mandate, run, evidence, policy, decision, execution],
    { createdAt: '2026-09-03T12:00:04.000Z' },
  )
  const signer = createEd25519Signer(signerKeyPair.privateKey)
  const keyId = deriveKeyId(signerKeyPair.publicKey)
  const embeddedPem = claimedVerificationKeyPem ?? signerKeyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString()
  const bundle = await sealBundle(payload, signer, {
    keys: [{
      key_id: keyId, algorithm: 'ed25519', public_key_pem: embeddedPem, status: 'active',
      valid_from: '2026-08-01T00:00:00.000Z', valid_until: null, status_changed_at: '2026-08-01T00:00:00.000Z',
      replacement_key_id: null, compromised_at: null,
    }],
  })
  return { bundle, payload, keyId, pem: signerKeyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString() }
}

// --- A. known trusted signer -> VALID ---

test('A: a bundle signed by the exact trusted key registry entry verifies VALID', async () => {
  const key = generateKeyPairSync('ed25519')
  const { bundle, keyId, pem } = await buildSignedBundle(key)
  const policy = trustPolicyFromKeyRegistry(registry([registryEntry(pem, keyId)]), { trustPolicy: { now: NOW } })
  assert.equal(verifyBundle(bundle, policy).state, 'VALID')
})

// --- B. tampered bundle -> INVALID ---

test('B: a trusted signer whose signed content was mutated after sealing verifies INVALID', async () => {
  const key = generateKeyPairSync('ed25519')
  const { bundle, keyId, pem } = await buildSignedBundle(key)
  const policy = trustPolicyFromKeyRegistry(registry([registryEntry(pem, keyId)]), { trustPolicy: { now: NOW } })
  const tampered = structuredClone(bundle)
  // Flip one base64 character of the signed payload -- content changes, signature does not.
  const chars = tampered.envelope.payload.split('')
  const i = Math.floor(chars.length / 2)
  chars[i] = chars[i] === 'A' ? 'B' : 'A'
  tampered.envelope.payload = chars.join('')
  assert.equal(verifyBundle(tampered, policy).state, 'INVALID')
})

// --- C. unknown signer -> UNVERIFIABLE ---

test('C: a cryptographically valid signature from a signer absent from the registry is UNVERIFIABLE', async () => {
  const signerKey = generateKeyPairSync('ed25519')
  const otherKey = generateKeyPairSync('ed25519')
  const { bundle } = await buildSignedBundle(signerKey)
  const otherKeyId = deriveKeyId(otherKey.publicKey)
  const otherPem = otherKey.publicKey.export({ format: 'pem', type: 'spki' }).toString()
  const policy = trustPolicyFromKeyRegistry(registry([registryEntry(otherPem, otherKeyId)]), { trustPolicy: { now: NOW } })
  assert.equal(verifyBundle(bundle, policy).state, 'UNVERIFIABLE')
})

// --- D. key_id spoofing regression: MUST NOT verify as VALID ---

test('D: an attacker embedding their own key under a trusted key_id cannot forge VALID', async () => {
  const trusted = generateKeyPairSync('ed25519')
  const attacker = generateKeyPairSync('ed25519')
  const trustedKeyId = deriveKeyId(trusted.publicKey)
  const trustedPem = trusted.publicKey.export({ format: 'pem', type: 'spki' }).toString()

  // A normal, self-consistent bundle honestly signed by the ATTACKER's own
  // key (sealBundle refuses to let a signer claim any keyid but its own --
  // see dsse.ts -- so a real attacker forging the label has to do it by hand
  // afterward, exactly like a hostile bundle built without this SDK would).
  const { bundle: honestlySealed } = await buildSignedBundle(attacker)
  const spoofedBundle = structuredClone(honestlySealed)
  // Forge BOTH the DSSE signature's keyid and the embedded verification hint
  // to claim the trusted issuer's key_id, while the embedded PEM stays the
  // attacker's own -- "attacker declares the key_id of a trusted issuer" and
  // "bundle embeds attacker's public key" exactly as specified.
  spoofedBundle.envelope.signatures[0].keyid = trustedKeyId
  spoofedBundle.verification_material.keys[0].key_id = trustedKeyId

  const policy = trustPolicyFromKeyRegistry(registry([registryEntry(trustedPem, trustedKeyId)]), { trustPolicy: { now: NOW } })
  const report = verifyBundle(spoofedBundle, policy)
  assert.notEqual(report.state, 'VALID')
  // Cryptographic verification used the TRUST RECORD's real public key, not
  // the bundle's self-declared one -- so the attacker's signature (made with
  // a different private key) fails outright: INVALID, not merely UNVERIFIABLE.
  assert.equal(report.state, 'INVALID')
})

// --- E. registry unavailable -> UNVERIFIABLE (caller pattern) ---

test('E: a registry that could not be fetched yields UNVERIFIABLE, never INVALID, via the recommended caller pattern', async () => {
  const key = generateKeyPairSync('ed25519')
  const { bundle } = await buildSignedBundle(key)

  async function fetchRegistryThatFails() {
    throw new Error('network unreachable (simulated)')
  }
  let policy
  try {
    const payload = await fetchRegistryThatFails()
    policy = trustPolicyFromKeyRegistry(payload, { trustPolicy: { now: NOW } })
  } catch {
    // Recommended pattern: registry fetch/parse failure -> empty trust, not a crash.
    policy = TrustPolicy.fromKeyRecords([], { now: NOW })
  }
  assert.equal(verifyBundle(bundle, policy).state, 'UNVERIFIABLE')
})

// --- F. malformed registry -> rejected trust construction ---

test('F: a structurally malformed registry is rejected by parseAgentEvidenceKeyRegistry', () => {
  assert.throws(() => parseAgentEvidenceKeyRegistry({ schema_version: 2, issuer: 'x', environment: 'y', keys: [] }), TrustPolicyError)
  assert.throws(() => parseAgentEvidenceKeyRegistry({ issuer: 'x', environment: 'y', keys: [] }), TrustPolicyError)
  assert.throws(() => parseAgentEvidenceKeyRegistry({ schema_version: 1, issuer: 'x', environment: 'y', keys: [{ key_id: 'not-a-real-key-id' }] }), TrustPolicyError)
  assert.throws(
    () => parseAgentEvidenceKeyRegistry(registry([registryEntry('pem', 'ed25519-fStXioNoRN9r1w6h')]), { expectedIssuer: 'someone-else' }),
    TrustPolicyError,
  )
})

// --- G. revoked signer -> existing lifecycle semantics (INVALID) ---

test('G: a registry-reported revoked signer fails closed to INVALID, per existing key lifecycle semantics', async () => {
  const key = generateKeyPairSync('ed25519')
  const { bundle, keyId, pem } = await buildSignedBundle(key)
  const policy = trustPolicyFromKeyRegistry(
    registry([registryEntry(pem, keyId, { status: 'revoked', revoked_at: '2026-09-02T00:00:00.000Z' })]),
    { trustPolicy: { now: NOW } },
  )
  assert.equal(verifyBundle(bundle, policy).state, 'INVALID')
})

// --- H. outside valid_from/valid_until -> existing lifecycle semantics (INVALID) ---

test('H: a bundle created before the registry key\'s valid_from fails closed to INVALID', async () => {
  const key = generateKeyPairSync('ed25519')
  const { bundle, keyId, pem } = await buildSignedBundle(key) // created_at: 2026-09-03T12:00:04.000Z
  const policy = trustPolicyFromKeyRegistry(
    registry([registryEntry(pem, keyId, { valid_from: '2027-01-01T00:00:00.000Z' })]),
    { trustPolicy: { now: NOW } },
  )
  assert.equal(verifyBundle(bundle, policy).state, 'INVALID')
})

test('H: a bundle created after the registry key\'s valid_until fails closed to INVALID', async () => {
  const key = generateKeyPairSync('ed25519')
  const { bundle, keyId, pem } = await buildSignedBundle(key) // created_at: 2026-09-03T12:00:04.000Z
  const policy = trustPolicyFromKeyRegistry(
    registry([registryEntry(pem, keyId, { valid_until: '2026-09-01T00:00:00.000Z' })]),
    { trustPolicy: { now: NOW } },
  )
  assert.equal(verifyBundle(bundle, policy).state, 'INVALID')
})

// --- the real, live ArcFX registry shape validates and builds a usable policy ---

test('the real ArcFX production registry response shape validates and yields a working TrustPolicy', () => {
  const arcfxLikeRegistry = registry(
    [registryEntry(
      '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEARqUvJhvrC2qNwHESO2ExPWlhyH46zRhqeTDS60vot8A=\n-----END PUBLIC KEY-----',
      'ed25519-fStXioNoRN9r1w6h',
      { valid_from: '2026-08-30T14:57:33.462Z' },
    )],
    { issuer: 'ArcFX', environment: 'production' },
  )
  const policy = trustPolicyFromKeyRegistry(arcfxLikeRegistry, {
    expectedIssuer: 'ArcFX', expectedEnvironment: 'production', trustPolicy: { now: NOW },
  })
  assert.ok(policy.key('ed25519-fStXioNoRN9r1w6h'))
})
