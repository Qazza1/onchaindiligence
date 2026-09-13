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

// Mirrors packages/agent-evidence/src/receiptId.ts::formatReceiptId exactly
// (Crockford Base32 over the first 10 digest bytes) so a fixture receipt_id
// is genuinely derivable from receipt_digest, not a fabricated placeholder --
// a real verifier recomputes and compares this, so a mismatch is INVALID.
const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
function formatReceiptId(receiptDigest) {
  const match = /^sha256:([A-Za-z0-9_-]{43})$/.exec(receiptDigest)
  if (!match) throw new Error(`not a valid sha256 content id: ${receiptDigest}`)
  const bytes = Buffer.from(match[1], 'base64url').subarray(0, 10)
  let bits = 0, value = 0, output = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      output += CROCKFORD_ALPHABET[(value >> bits) & 0x1f]
    }
  }
  if (bits > 0) output += CROCKFORD_ALPHABET[(value << (5 - bits)) & 0x1f]
  const groups = []
  for (let i = 0; i < output.length; i += 4) groups.push(output.slice(i, i + 4))
  return `OCD-RCP-${groups.join('-')}`
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

// ---------------------------------------------------------------------
// D4.2 portable evidence bundle fixtures.
//
// These reuse the same deterministic bundle-sealer key as the fixtures
// above. A SECOND, distinct deterministic test key ("child seed") signs
// one embedded onchaindiligence-attestation-v2 evidence proof in the
// unverifiable-child fixture, to demonstrate a bundle DSSE signature
// verifying under a trusted key while one embedded child artifact's own
// signature is from a key the caller has NOT trusted for that check --
// both are public test material only, never a production trust root.
// ---------------------------------------------------------------------
const childSeed = Buffer.from('9f1c6a3e7d0b52c88a41f6de3b7c905e2a4d81f0c6b3e9a75d2f1c8b6e4a3091', 'hex')
const childPrivateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), childSeed]),
  format: 'der',
  type: 'pkcs8',
})
const childPublicKey = createPublicKey(childPrivateKey)
const childDer = childPublicKey.export({ type: 'spki', format: 'der' })
const childKeyId = `ed25519-${digestBytes(childDer).slice(0, 16)}`

function signV2(privKey, kid, data, purpose, issuedAt) {
  const attestationWithoutSig = {
    schema_version: 'onchaindiligence.attestation.v2',
    issuer: 'https://api.onchaindiligence.com',
    purpose,
    issued_at: issuedAt,
    key_id: kid,
    algorithm: 'ed25519',
    canonicalization: 'RFC8785',
  }
  const signedInput = { schema_version: attestationWithoutSig.schema_version, issuer: attestationWithoutSig.issuer, purpose, data, issued_at: issuedAt, key_id: kid }
  const signature = sign(null, Buffer.from(canonical(signedInput)), privKey).toString('base64url').replace(/=+$/, '')
  return { data, attestation: { ...attestationWithoutSig, signed: true, signature } }
}

// A real "compliance-screening-result" v2 envelope -- the one purpose the
// current v0 reference verifier already checks -- standing in for any
// onchaindiligence.attestation.v2 artifact (screening results today;
// allowance/swap/bridge/staking-action share the exact same {data,
// attestation} envelope shape once a verifier accepts their purposes too;
// see the D4.2 audit note on this in AGENT_EVIDENCE_V0.md section 14).
const screeningIssuedAt = '2026-08-28T12:00:02.000Z'
const screeningV2Envelope = signV2(privateKey, keyId, { address: '0x0000000000000000000000000000000000000002', sanctioned: false }, 'compliance-screening-result', screeningIssuedAt)
const screeningEvidence = record('evidence', [run.id], {
  evidence_type: 'sanctions-screen',
  run_ref: run.id,
  trust_mode: 'publisher-signed',
  source: { id: 'https://api.onchaindiligence.com', type: 'https-api' },
  tool: { name: 'screen_wallet', version: '1' },
  request: { digest: digestObject({ address: screeningV2Envelope.data.address }), media_type: 'application/json' },
  response: { mode: 'embedded', media_type: 'application/json', value: screeningV2Envelope, digest: digestObject(screeningV2Envelope) },
  observed_at: screeningIssuedAt,
  expires_at: null,
  scope: { query: screeningV2Envelope.data.address, coverage: 'one test address' },
}, [{ proof_type: 'onchaindiligence-attestation-v2', envelope: screeningV2Envelope }])

// A real-shaped onchaindiligence.public-action-receipt.v1 object (not a
// {data,attestation} envelope, so it is embedded via external-digest for
// outer graph binding -- its own internal `proof` is independently
// verifiable by a receipt-aware verifier, a step this v0 graph proof does
// not itself perform; see the D4.2 note on this distinction).
const receiptIssuedAt = '2026-08-28T12:00:03.000Z'
// Exactly packages/agent-evidence/src/receipts.ts's ReceiptCoreFields -- every
// receipt field EXCEPT receipt_id/receipt_digest, which are DERIVED from this
// object's own digest below, never supplied by hand (receiptId.ts's own
// comment: "the id is derived from the digest, never the reverse").
const receiptCoreFields = {
  receipt_type: 'PREFLIGHT',
  issued_at: receiptIssuedAt,
  action: { kind: 'ERC20_ALLOWANCE', resource: null, network: 'eip155:8453', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', amount: '1.00', sender: '0x' + '44'.repeat(20), recipient: null },
  decision: { status: 'ALLOW', authorized: true, reasons: ['All configured policy checks passed.'] },
  execution: { provider: null, status: 'NOT_SUBMITTED', transaction_hash: null, submitted_at: null, confirmed_at: null },
  settlement: { status: 'NOT_APPLICABLE', detail: null },
  checks: [{ id: 'amount-within-max', result: 'PASS', summary: 'The proposed amount is within the caller-configured maximum.', evidence_digest: null }],
  links: { agent_evidence_bundle_digest: null, preflight_receipt_id: null },
  limitations: ['Policy evaluation only -- OCD never holds, moves, or authorizes funds.'],
}
const receiptDigest = `sha256:${digest(receiptCoreFields)}`
const receiptId = formatReceiptId(receiptDigest)
// finalizeReceiptCore's exact output: core fields + the id/digest just derived.
const finalizedReceipt = { ...receiptCoreFields, receipt_id: receiptId, receipt_digest: receiptDigest }
// receiptAttestationSigningInput signs the FULL finalized receipt (data:
// receipt, including receipt_id/receipt_digest) under purpose
// PUBLIC_ACTION_RECEIPT_PURPOSE = 'public-action-receipt' -- NOT the
// underlying action kind. An earlier draft signed the pre-digest core under
// purpose 'erc20-allowance-action' and was caught by verifyReceiptEnvelope's
// real purpose-mismatch / signature-invalid checks before merge.
const receiptProof = signV2(privateKey, keyId, finalizedReceipt, 'public-action-receipt', receiptIssuedAt).attestation
const receipt = {
  schema: 'onchaindiligence.public-action-receipt.v1',
  receipt: finalizedReceipt,
  proof: receiptProof,
}
const receiptEvidence = record('evidence', [run.id], {
  evidence_type: 'onchaindiligence.public-action-receipt.v1',
  run_ref: run.id,
  // external-digest only binds this record into the graph by digest; it does
  // not give the v0 graph verifier a cryptographic source proof to check, so
  // 'publisher-signed' would be a claim this verifier cannot back today. The
  // receipt's own internal `proof` IS a real, independently verifiable v2
  // attestation -- but checking it is receipt-aware verification this graph
  // proof does not itself perform (see the D4.2 note above and
  // AGENT_EVIDENCE_V0.md section 14).
  trust_mode: 'agent-assertion',
  source: { id: 'https://api.onchaindiligence.com', type: 'https-api' },
  tool: { name: 'erc20_allowance_preflight', version: '1' },
  request: { digest: digestObject({ asset: receiptCoreFields.action.asset }), media_type: 'application/json' },
  response: { mode: 'embedded', media_type: 'application/json', value: receipt, digest: digestObject(receipt) },
  observed_at: receiptIssuedAt,
  expires_at: null,
  scope: { query: receiptCoreFields.action.asset, coverage: 'one preflight artifact' },
}, [{ proof_type: 'external-digest', media_type: 'onchaindiligence.public-action-receipt.v1', digest: digestObject(receipt) }])

// A well-formed evidence node whose artifact family the verifier does not
// (and, absent a schema update, cannot) recognize -- graph-bound via the
// same safe external-digest mechanism, so it MUST surface as UNVERIFIABLE
// per-artifact without affecting bundle_integrity.
const unknownIssuedAt = '2026-08-28T12:00:04.000Z'
const unknownArtifact = { schema: 'onchaindiligence.some-future-action.v9', data: { note: 'a family this verifier has never heard of' } }
const unknownEvidence = record('evidence', [run.id], {
  evidence_type: 'onchaindiligence.some-future-action.v9',
  run_ref: run.id,
  trust_mode: 'agent-assertion',
  source: { id: 'urn:onchaindiligence:test:future-tool', type: 'unknown' },
  tool: { name: 'future_tool', version: '9' },
  request: { digest: digestObject({}), media_type: 'application/json' },
  response: { mode: 'embedded', media_type: 'application/json', value: unknownArtifact, digest: digestObject(unknownArtifact) },
  observed_at: unknownIssuedAt,
  expires_at: null,
  scope: { query: 'n/a', coverage: 'unrecognized artifact family, included to exercise unknown-type handling' },
}, [{ proof_type: 'external-digest', media_type: 'onchaindiligence.some-future-action.v9', digest: digestObject(unknownArtifact) }])

function buildBundlePayload(evidenceRecords) {
  const allRecords = [principal, agent, mandate, run, ...evidenceRecords].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  const rootIds = evidenceRecords.map((r) => r.id).sort()
  const agreementRecordIds = evidenceRecords.map((r) => r.id).sort()
  const payloadWithoutId = {
    bundle_version: 'onchaindiligence.agent-evidence.bundle.v0',
    created_at: '2026-08-28T12:00:06.000Z',
    issuer: 'https://api.onchaindiligence.com',
    run_id: run.id,
    root_ids: rootIds,
    records: allRecords,
    reconciliation: {
      agreements: [
        {
          subject: 'sanctions-screen-agrees-with-allowance-preflight-policy',
          record_ids: agreementRecordIds,
          summary: 'The sanctions screen found no match for the counterparty, and the allowance preflight independently reached ALLOW under its own policy -- both checks agree the proposed action is not blocked by either evidence source.',
        },
      ],
      contradictions: [],
      insufficient_evidence: [
        {
          subject: 'settlement-confirmation',
          record_ids: [],
          summary: 'This bundle contains a PREFLIGHT receipt only; no execution or settlement record is present, so whether the allowance action was ever submitted or settled is not established one way or the other.',
        },
      ],
    },
    limitations: [
      'Bundle validity proves cryptographic integrity under the Agent Evidence v0 verifier contract. It does not by itself establish authorization, safety, settlement, delivery, compliance, service quality, or economic outcome.',
      'Per-artifact verification is reported separately from bundle integrity; a valid bundle signature does not make every embedded artifact VALID.',
    ],
    extensions: {},
  }
  return { ...payloadWithoutId, bundle_id: `sha256:${digest(payloadWithoutId)}` }
}

function sealPortable(payload, signingKey, signingKeyId) {
  const payloadBytes = Buffer.from(canonical(payload))
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 ${Buffer.byteLength(BUNDLE_TYPE)} ${BUNDLE_TYPE} ${payloadBytes.length} `),
    payloadBytes,
  ])
  return {
    media_type: 'application/vnd.onchaindiligence.agent-evidence+json',
    bundle_version: 'onchaindiligence.agent-evidence.bundle.v0',
    envelope: {
      payloadType: BUNDLE_TYPE,
      payload: payloadBytes.toString('base64'),
      signatures: [{ keyid: signingKeyId, sig: sign(null, pae, signingKey).toString('base64') }],
    },
    verification_material: { keys: [keyRecord], registry_snapshots: [], anchors: [] },
  }
}

// Case: valid bundle with heterogeneous embedded artifacts + reconciliation.
const bundleWithArtifactsPayload = buildBundlePayload([screeningEvidence, receiptEvidence])
const bundleWithArtifacts = sealPortable(bundleWithArtifactsPayload, privateKey, keyId)

// Case: tampered manifest -- created_at changed post-signing, so the DSSE
// signature no longer matches the bytes it was computed over.
const bundleTamperedManifest = structuredClone(bundleWithArtifacts)
{
  const decoded = JSON.parse(Buffer.from(bundleTamperedManifest.envelope.payload, 'base64').toString('utf8'))
  decoded.created_at = '2099-01-01T00:00:00.000Z'
  bundleTamperedManifest.envelope.payload = Buffer.from(canonical(decoded)).toString('base64')
}

// Case: removed artifact -- one evidence record deleted post-signing.
const bundleRemovedArtifact = structuredClone(bundleWithArtifacts)
{
  const decoded = JSON.parse(Buffer.from(bundleRemovedArtifact.envelope.payload, 'base64').toString('utf8'))
  decoded.records = decoded.records.filter((r) => r.id !== receiptEvidence.id)
  bundleRemovedArtifact.envelope.payload = Buffer.from(canonical(decoded)).toString('base64')
}

// Case: inserted artifact -- an extra record spliced in post-signing.
const bundleInsertedArtifact = structuredClone(bundleWithArtifacts)
{
  const decoded = JSON.parse(Buffer.from(bundleInsertedArtifact.envelope.payload, 'base64').toString('utf8'))
  decoded.records = [...decoded.records, unknownEvidence].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  bundleInsertedArtifact.envelope.payload = Buffer.from(canonical(decoded)).toString('base64')
}

// Case: bundle DSSE signature is genuinely VALID over its exact content,
// but one embedded child artifact's own signature is corrupt. Built by
// tampering the child BEFORE sealing (so the outer signature is fresh and
// correct over the tampered content) -- this is the "valid bundle, one
// INVALID child" case the tri-state report must keep visibly distinct.
const corruptV2Envelope = structuredClone(screeningV2Envelope)
{
  const sigBytes = Buffer.from(corruptV2Envelope.attestation.signature, 'base64url')
  sigBytes[0] ^= 1
  corruptV2Envelope.attestation.signature = sigBytes.toString('base64url').replace(/=+$/, '')
}
const corruptScreeningEvidence = record('evidence', [run.id], {
  ...screeningEvidence.statement,
  // digest is recomputed over the tampered envelope so the fixture isolates
  // a cryptographic signature failure -- leaving the original digest here
  // would trip the earlier "response digest matches value" structural check
  // instead of ever reaching signature verification.
  response: { ...screeningEvidence.statement.response, value: corruptV2Envelope, digest: digestObject(corruptV2Envelope) },
}, [{ proof_type: 'onchaindiligence-attestation-v2', envelope: corruptV2Envelope }])
const bundleInvalidChildPayload = buildBundlePayload([corruptScreeningEvidence, receiptEvidence])
const bundleInvalidChild = sealPortable(bundleInvalidChildPayload, privateKey, keyId)

// Case: bundle DSSE signature is VALID and trusted; one embedded child
// artifact is correctly signed but by a key the caller's trust material
// (in this fixture's own verification_material) does not include --
// UNVERIFIABLE for that child, distinct from both VALID and INVALID.
const untrustedV2Envelope = signV2(childPrivateKey, childKeyId, { address: '0x0000000000000000000000000000000000000003', sanctioned: false }, 'compliance-screening-result', screeningIssuedAt)
const untrustedScreeningEvidence = record('evidence', [run.id], {
  ...screeningEvidence.statement,
  response: { ...screeningEvidence.statement.response, value: untrustedV2Envelope, digest: digestObject(untrustedV2Envelope) },
  scope: { query: untrustedV2Envelope.data.address, coverage: 'one test address' },
}, [{ proof_type: 'onchaindiligence-attestation-v2', envelope: untrustedV2Envelope }])
const bundleUnverifiableChildPayload = buildBundlePayload([untrustedScreeningEvidence, receiptEvidence])
const bundleUnverifiableChild = sealPortable(bundleUnverifiableChildPayload, privateKey, keyId)
// This fixture's own verification_material intentionally omits childKeyId --
// a manifest case may additionally supply it via trusted_key_ids to invert
// the expectation and confirm the untrusted-key child becomes VALID once
// trusted, but the DEFAULT trust here is the bundle-sealer key only.

// Case: well-formed but unrecognized artifact type, alongside a known one.
const bundleUnknownArtifactTypePayload = buildBundlePayload([screeningEvidence, unknownEvidence])
const bundleUnknownArtifactType = sealPortable(bundleUnknownArtifactTypePayload, privateKey, keyId)

const generated = {
  portable,
  invalidSignature,
  noncanonicalPayload,
  outerVersionMismatch,
  missingParent,
  keyRecord,
  bundleWithArtifacts,
  bundleTamperedManifest,
  bundleRemovedArtifact,
  bundleInsertedArtifact,
  bundleInvalidChild,
  bundleUnverifiableChild,
  bundleUnknownArtifactType,
  childKeyRecord: {
    key_id: childKeyId,
    algorithm: 'ed25519',
    public_key_pem: childPublicKey.export({ type: 'spki', format: 'pem' }).toString(),
    status: 'active',
    valid_from: '2026-08-28T00:00:00.000Z',
    valid_until: null,
    status_changed_at: '2026-08-28T00:00:00.000Z',
    replacement_key_id: null,
    compromised_at: null,
  },
}
const selected = process.argv[2]
if (selected && !Object.hasOwn(generated, selected)) throw new Error(`unknown fixture: ${selected}`)
process.stdout.write(JSON.stringify(selected ? generated[selected] : generated, null, 2) + '\n')
