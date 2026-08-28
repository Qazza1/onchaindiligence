/** Regenerate deterministic Agent Evidence v0 fixtures from a public test-only seed. */
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto'

const BUNDLE_TYPE = 'application/vnd.onchaindiligence.agent-evidence.bundle.v0+json'
const RECORD_VERSION = 'onchaindiligence.agent-evidence.record.v0'
const seed = Buffer.from('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', 'hex')
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
  format: 'der',
  type: 'pkcs8',
})
const publicKey = createPublicKey(privateKey)

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite fixture number')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
  }
  throw new TypeError('fixture value is not JSON')
}

function digestBytes(bytes) {
  return createHash('sha256').update(bytes).digest('base64url')
}
function digest(value) {
  return digestBytes(Buffer.from(canonical(value)))
}
function record(kind, parents, statement, proofs = []) {
  const body = { record_version: RECORD_VERSION, kind, parents: [...parents].sort(), statement, proofs }
  return { id: `sha256:${digest(body)}`, ...body }
}
function digestObject(value) {
  return { sha256: digest(value) }
}

const principal = record('principal', [], {
  principal_id: 'urn:onchaindiligence:test:treasury',
  principal_type: 'organization',
  display_name: 'Conformance Treasury',
})
const agent = record('agent', [principal.id], {
  agent_id: 'urn:onchaindiligence:test:agent',
  agent_version: '1.0.0',
  operator_ref: principal.id,
})
const mandate = record('mandate', [principal.id], {
  mandate_id: 'mandate-conformance-001',
  principal_ref: principal.id,
  scope: { action: 'pay', asset: 'pathUSD', max_amount: '10.00' },
  valid_from: '2026-08-28T00:00:00.000Z',
  valid_until: '2026-08-29T00:00:00.000Z',
  limits: { amount: '10.00' },
})
const run = record('run', [agent.id, mandate.id], {
  run_external_id: 'run-conformance-001',
  agent_ref: agent.id,
  mandate_ref: mandate.id,
  started_at: '2026-08-28T12:00:00.000Z',
  ended_at: '2026-08-28T12:00:05.000Z',
})
const request = { address: '0x0000000000000000000000000000000000000001' }
const response = { sanctioned: false }
const evidence = record('evidence', [run.id], {
  evidence_type: 'sanctions-screen',
  run_ref: run.id,
  trust_mode: 'agent-assertion',
  source: { id: 'https://api.example.invalid', type: 'https-api' },
  tool: { name: 'screen_wallet', version: '1' },
  request: { digest: digestObject(request), media_type: 'application/json' },
  response: { mode: 'embedded', media_type: 'application/json', value: response, digest: digestObject(response) },
  observed_at: '2026-08-28T12:00:01.000Z',
  expires_at: null,
  scope: { query: request.address, coverage: 'one test address' },
}, [{ proof_type: 'external-digest', media_type: 'application/json', digest: digestObject(response) }])
const policyValue = { rule: 'sanctioned must be false' }
const policy = record('policy', [run.id], {
  policy_id: 'urn:onchaindiligence:test:policy',
  version: '1',
  digest: digestObject(policyValue),
  source: 'https://example.invalid/policy/1',
  effective_from: '2026-08-28T00:00:00.000Z',
  policy: policyValue,
})
const decision = record('decision', [run.id, evidence.id, policy.id], {
  decision_id: 'decision-conformance-001',
  run_ref: run.id,
  agent_ref: agent.id,
  decision_type: 'payment-approval',
  outcome: { approved: true },
  evidence_refs: [evidence.id],
  policy_ref: policy.id,
  policy_digest: policy.statement.digest,
  decided_at: '2026-08-28T12:00:03.000Z',
})
const execution = record('execution', [decision.id], {
  execution_id: 'execution-conformance-001',
  decision_ref: decision.id,
  execution_type: 'onchain-transfer',
  status: 'confirmed',
  submitted_at: '2026-08-28T12:00:04.000Z',
  network: 'eip155:1',
  transaction_hash: '0x' + '11'.repeat(32),
  transaction_digest: digestObject({ to: '0x' + '22'.repeat(20), value: '1.00' }),
  sender: '0x' + '33'.repeat(20),
  recipient: '0x' + '22'.repeat(20),
  asset: 'pathUSD',
  amount: '1.00',
  confirmed_at: '2026-08-28T12:00:05.000Z',
  block_number: '12345678',
})

const records = [principal, agent, mandate, run, evidence, policy, decision, execution]
  .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
const payloadWithoutId = {
  bundle_version: 'onchaindiligence.agent-evidence.bundle.v0',
  created_at: '2026-08-28T12:00:06.000Z',
  run_id: run.id,
  root_ids: [execution.id],
  records,
  extensions: {},
}
const payload = { ...payloadWithoutId, bundle_id: `sha256:${digest(payloadWithoutId)}` }
const payloadBytes = Buffer.from(canonical(payload))
const pae = Buffer.concat([
  Buffer.from(`DSSEv1 ${Buffer.byteLength(BUNDLE_TYPE)} ${BUNDLE_TYPE} ${payloadBytes.length} `),
  payloadBytes,
])
const der = publicKey.export({ type: 'spki', format: 'der' })
const keyId = `ed25519-${digestBytes(der).slice(0, 16)}`
const envelope = {
  payloadType: BUNDLE_TYPE,
  payload: payloadBytes.toString('base64'),
  signatures: [{ keyid: keyId, sig: sign(null, pae, privateKey).toString('base64') }],
}
const keyRecord = {
  key_id: keyId,
  algorithm: 'ed25519',
  public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  status: 'active',
  valid_from: '2026-08-28T00:00:00.000Z',
  valid_until: null,
  status_changed_at: '2026-08-28T00:00:00.000Z',
  replacement_key_id: null,
  compromised_at: null,
}
const portable = {
  media_type: 'application/vnd.onchaindiligence.agent-evidence+json',
  bundle_version: 'onchaindiligence.agent-evidence.bundle.v0',
  envelope,
  verification_material: { keys: [keyRecord], registry_snapshots: [], anchors: [] },
}

const invalidSignature = structuredClone(portable)
const signature = Buffer.from(invalidSignature.envelope.signatures[0].sig, 'base64')
signature[0] ^= 1
invalidSignature.envelope.signatures[0].sig = signature.toString('base64')

const noncanonicalPayload = structuredClone(portable)
// Leading JSON whitespace is legal but cannot be an RFC 8785 serialization.
// This keeps the vector independent of runtime object-property iteration order.
const noncanonicalBytes = Buffer.concat([Buffer.from(' '), payloadBytes])
const noncanonicalPae = Buffer.concat([
  Buffer.from(`DSSEv1 ${Buffer.byteLength(BUNDLE_TYPE)} ${BUNDLE_TYPE} ${noncanonicalBytes.length} `),
  noncanonicalBytes,
])
noncanonicalPayload.envelope.payload = noncanonicalBytes.toString('base64')
noncanonicalPayload.envelope.signatures[0].sig = sign(null, noncanonicalPae, privateKey).toString('base64')

const outerVersionMismatch = structuredClone(portable)
outerVersionMismatch.bundle_version = 'onchaindiligence.agent-evidence.bundle.v9'

const missingParent = structuredClone(portable)
const decoded = JSON.parse(Buffer.from(missingParent.envelope.payload, 'base64').toString('utf8'))
decoded.records.find((item) => item.kind === 'evidence').parents = [`sha256:${'A'.repeat(43)}`]
const missingParentBytes = Buffer.from(canonical(decoded))
const missingParentPae = Buffer.concat([
  Buffer.from(`DSSEv1 ${Buffer.byteLength(BUNDLE_TYPE)} ${BUNDLE_TYPE} ${missingParentBytes.length} `),
  missingParentBytes,
])
missingParent.envelope.payload = missingParentBytes.toString('base64')
missingParent.envelope.signatures[0].sig = sign(null, missingParentPae, privateKey).toString('base64')

const generated = { portable, invalidSignature, noncanonicalPayload, outerVersionMismatch, missingParent, keyRecord }
const selected = process.argv[2]
if (selected && !Object.hasOwn(generated, selected)) throw new Error(`unknown fixture: ${selected}`)
process.stdout.write(JSON.stringify(selected ? generated[selected] : generated, null, 2) + '\n')
