/**
 * test/smoke.ts
 * --------------
 * Exercises the core business logic (chainalysis.ts, companiesHouse.ts,
 * and the bundling logic in server.ts) WITHOUT making real network calls
 * or requiring a real MPP payment — both of which aren't available in
 * every environment this gets tested in.
 *
 * This is not a replacement for testing against the real APIs once you
 * have real keys — it's a fast check that the parsing, error handling,
 * and bundling logic behave correctly given known input/output shapes.
 *
 * Run with: npm test
 */

import assert from 'node:assert'
import { readFileSync } from 'node:fs'

// --- Mock global fetch before importing anything that uses it ---------
const originalFetch = global.fetch

type MockResponse = { status: number; body: unknown }
let mockQueue: MockResponse[] = []

function queueMock(status: number, body: unknown) {
  mockQueue.push({ status, body })
}

global.fetch = (async (..._args: any[]) => {
  const next = mockQueue.shift()
  if (!next) throw new Error('Test error: no mock queued for this fetch call')
  return new Response(JSON.stringify(next.body), {
    status: next.status,
    headers: { 'Content-Type': 'application/json' },
  })
}) as typeof fetch

// Set fake env vars before config.ts reads them.
process.env.COMPANIES_HOUSE_API_KEY = 'fake-key-for-tests'
process.env.MPP_RECIPIENT_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb9226d'
process.env.TEMPO_CURRENCY_ADDRESS = '0x20c0000000000000000000000000000000000000'
process.env.MPP_SECRET_KEY = 'test-mpp-secret-that-is-at-least-32-characters'
process.env.ATTESTATION_SERVICE_TOKEN = 'test-attestation-token-at-least-32-characters'
process.env.ATTESTATION_KEY_ACTIVATED_AT = '2026-01-01T00:00:00.000Z'
process.env.TEMPO_TESTNET = 'true'
process.env.ANCHOR_RPC_URL = 'http://127.0.0.1:18546'
process.env.ANCHOR_CHAIN_ID = '42431'
process.env.ANCHOR_CONTRACT_ADDRESS = '0x1111111111111111111111111111111111111111'
process.env.ANCHOR_PRIVATE_KEY = '0x' + '11'.repeat(32)

const { screenAddress } = await import('../src/chainalysis.js')
const { checkCompany, CompanyNotFoundError } = await import('../src/companiesHouse.js')
const { authorizeInternalBearer } = await import('../src/internalAuth.js')
const { checkDirectExposure } = await import('../src/exposure.js')
const { buildVerdictData } = await import('../src/verdict.js')

let passed = 0
let failed = 0

async function test(name: string, fn: () => Promise<void>) {
  try {
    await fn()
    console.log(`  ✓ ${name}`)
    passed++
  } catch (err) {
    console.log(`  ✗ ${name}`)
    console.log(`    ${err instanceof Error ? err.message : err}`)
    failed++
  }
}

console.log('Sanctions oracle client:')

await test('internal attestation auth fails closed and accepts only the configured bearer', async () => {
  const token = 'a-secure-internal-token-that-is-long-enough'
  assert.strictEqual(authorizeInternalBearer(undefined, ''), 'unconfigured')
  assert.strictEqual(authorizeInternalBearer(undefined, token), 'unauthorized')
  assert.strictEqual(authorizeInternalBearer('Bearer wrong-token', token), 'unauthorized')
  assert.strictEqual(authorizeInternalBearer(`Bearer ${token}`, token), 'authorized')
})

await test('OpenAPI models signed envelopes and full-envelope anchoring accurately', async () => {
  const { buildOpenApiSpec } = await import('../src/openapi.js')
  const spec: any = buildOpenApiSpec()
  for (const name of [
    'SignedSanctionsResult',
    'SignedNameScreenResult',
    'SignedCompanyResult',
    'SignedUsCompanyResult',
    'SignedDiligenceResult',
    'SignedAnchorResult',
  ]) {
    assert.deepStrictEqual(spec.components.schemas[name].required, ['data', 'attestation'])
    assert.ok(spec.components.schemas[name].properties.data)
  }
  assert.strictEqual(
    spec.paths['/anchor'].post.requestBody.content['application/json'].schema.$ref,
    '#/components/schemas/AnchorableAttestationEnvelope'
  )
  assert.match(spec.components.schemas.Attestation.description, /signer assertion/)
})

await test('invalid address is rejected as a 400-class error (no network call)', async () => {
  const { ChainalysisUpstreamError } = await import('../src/chainalysis.js')
  try {
    await screenAddress('not-an-address')
    assert.fail('expected an error to be thrown')
  } catch (err: any) {
    assert.ok(err instanceof ChainalysisUpstreamError)
    assert.strictEqual(err.status, 400)
  }
})

await test('too-short hex is rejected as a 400-class error', async () => {
  const { ChainalysisUpstreamError } = await import('../src/chainalysis.js')
  try {
    await screenAddress('0x123')
    assert.fail('expected an error to be thrown')
  } catch (err: any) {
    assert.ok(err instanceof ChainalysisUpstreamError)
    assert.strictEqual(err.status, 400)
  }
})

await test('attribution is present, honest, and oracle-aware', async () => {
  const { buildAttribution } = await import('../src/chainalysis.js')
  const a = buildAttribution()
  assert.ok(a.source && a.note)
  assert.match(a.source, /oracle/i)
  assert.match(a.note, /not legal advice|not a complete compliance/i)
})

await test('direct exposure is complete when the supported window has no counterparties', async () => {
  queueMock(200, { data: [] })
  const result = await checkDirectExposure('0x0000000000000000000000000000000000000001')
  assert.strictEqual(result.status, 'complete')
  assert.strictEqual(result.evaluated, true)
  assert.strictEqual(result.counterparties_screened, 0)
})

await test('direct exposure is partial, never complete, when a counterparty screen fails', async () => {
  queueMock(200, {
    data: [
      {
        sender: '0x0000000000000000000000000000000000000001',
        recipient: '0x0000000000000000000000000000000000000002',
      },
    ],
  })
  queueMock(200, { jsonrpc: '2.0', id: 1, error: { code: -32603, message: 'upstream failed' } })
  const result = await checkDirectExposure('0x0000000000000000000000000000000000000001')
  assert.strictEqual(result.status, 'partial')
  assert.strictEqual(result.evaluated, false)
  assert.strictEqual(result.screening_failures, 1)
})

await test('the 25-counterparty cap is reported as partial rather than clean', async () => {
  const subject = '0x0000000000000000000000000000000000000001'
  const rows = Array.from({ length: 26 }, (_, index) => ({
    sender: subject,
    recipient: `0x${(index + 2).toString(16).padStart(40, '0')}`,
  }))
  queueMock(200, { data: rows })
  for (let index = 0; index < 25; index++) {
    queueMock(200, { jsonrpc: '2.0', id: index + 1, result: `0x${'0'.repeat(64)}` })
  }

  const result = await checkDirectExposure(subject)
  assert.strictEqual(result.status, 'partial')
  assert.strictEqual(result.evaluated, false)
  assert.strictEqual(result.counterparties_found, 26)
  assert.strictEqual(result.counterparties_considered, 25)
  assert.strictEqual(result.counterparties_screened, 25)
  assert.strictEqual(result.counterparties_omitted, 1)
})

console.log('\nCanonical verdict policy:')

const exposureFixture = (
  overrides: Partial<Awaited<ReturnType<typeof checkDirectExposure>>> = {}
) => ({
  evaluated: true,
  status: 'complete' as const,
  transfers_scanned: 1,
  counterparties_found: 1,
  counterparties_considered: 1,
  counterparties_screened: 1,
  counterparties_omitted: 0,
  screening_failures: 0,
  sanctioned_counterparties: [] as string[],
  scope: 'bounded test scope',
  ...overrides,
})

const screenFixture = (sanctioned: boolean) => ({
  address: '0x0000000000000000000000000000000000000001',
  sanctioned,
  identifications: [],
})

await test('BLOCK takes precedence when the subject address is sanctioned', async () => {
  const result = buildVerdictData({
    address: screenFixture(true).address,
    screen: screenFixture(true),
    exposure: exposureFixture(),
    checkedAt: '2026-01-01T00:00:00.000Z',
  })
  assert.strictEqual(result.verdict, 'BLOCK')
  assert.strictEqual(result.checked_at, '2026-01-01T00:00:00.000Z')
})

await test('WARN is returned for direct sanctioned-counterparty exposure', async () => {
  const sanctionedCounterparty = '0x0000000000000000000000000000000000000002'
  const result = buildVerdictData({
    address: screenFixture(false).address,
    screen: screenFixture(false),
    exposure: exposureFixture({ sanctioned_counterparties: [sanctionedCounterparty] }),
  })
  assert.strictEqual(result.verdict, 'WARN')
  assert.deepStrictEqual(
    result.signals.direct_counterparty_exposure.sanctioned_counterparties,
    [sanctionedCounterparty]
  )
})

await test('incomplete exposure warns and can never produce a false PASS', async () => {
  const result = buildVerdictData({
    address: screenFixture(false).address,
    screen: screenFixture(false),
    exposure: exposureFixture({
      evaluated: false,
      status: 'partial',
      counterparties_screened: 0,
      screening_failures: 1,
    }),
  })
  assert.strictEqual(result.verdict, 'WARN')
  assert.ok(result.verdict_basis.not_yet_evaluated.includes('direct_counterparty_exposure'))
})

await test('PASS requires a clean subject and complete exposure evaluation', async () => {
  const result = buildVerdictData({
    address: screenFixture(false).address,
    ens: 'clean.eth',
    screen: screenFixture(false),
    exposure: exposureFixture(),
  })
  assert.strictEqual(result.verdict, 'PASS')
  assert.strictEqual(result.ens_name, 'clean.eth')
  assert.ok(result.verdict_basis.live_signals.includes('direct_counterparty_exposure'))
})

console.log('\nSEC EDGAR query resolution:')

const { resolveCompanyQuery, checkUSCompany } = await import('../src/secEdgar.js')
const edgarEntries = [
  { cik_str: 1, ticker: 'ALP', title: 'ALPHA HOLDINGS INC' },
  { cik_str: 2, ticker: 'ALPS', title: 'ALPHA SOFTWARE CORP' },
  { cik_str: 3, ticker: 'BETA', title: 'BETA SYSTEMS INC' },
  { cik_str: 4, ticker: 'BETA.B', title: 'BETA SYSTEMS INC' },
]

await test('explicit CIK and exact ticker resolve deterministically', async () => {
  assert.deepStrictEqual(resolveCompanyQuery('CIK3', edgarEntries), {
    status: 'resolved',
    cik: '0000000003',
    matched_by: 'cik',
  })
  assert.deepStrictEqual(resolveCompanyQuery('ALP', edgarEntries), {
    status: 'resolved',
    cik: '0000000001',
    matched_by: 'ticker',
  })
})

await test('duplicate exact legal names return candidates, never a selected filer', async () => {
  const result = resolveCompanyQuery('Beta Systems Inc', edgarEntries)
  assert.strictEqual(result?.status, 'ambiguous')
  if (result?.status !== 'ambiguous') assert.fail('expected ambiguous resolution')
  assert.strictEqual(result.candidate_count, 2)
  assert.deepStrictEqual(result.candidates.map((candidate) => candidate.cik), [
    '0000000003',
    '0000000004',
  ])
})

await test('ambiguous prefixes return a deterministic candidate set', async () => {
  const result = resolveCompanyQuery('Alpha', edgarEntries)
  assert.strictEqual(result?.status, 'ambiguous')
  if (result?.status !== 'ambiguous') assert.fail('expected ambiguous resolution')
  assert.deepStrictEqual(result.candidates.map((candidate) => candidate.ticker), ['ALP', 'ALPS'])
})

await test('a unique substring may resolve and an absent name does not', async () => {
  assert.deepStrictEqual(resolveCompanyQuery('Software', edgarEntries), {
    status: 'resolved',
    cik: '0000000002',
    matched_by: 'unique_substring',
  })
  assert.strictEqual(resolveCompanyQuery('No Such Filer', edgarEntries), null)
})

await test('ambiguous company lookup returns candidates without fetching a selected filing', async () => {
  queueMock(200, Object.fromEntries(edgarEntries.map((entry, index) => [index, entry])))
  const result = await checkUSCompany('Alpha')
  assert.strictEqual(result.match_status, 'ambiguous')
  if (result.match_status !== 'ambiguous') assert.fail('expected ambiguous company result')
  assert.strictEqual(result.candidate_count, 2)
  assert.strictEqual('cik' in result, false)
})

// NOTE: the live true/false behaviour of the oracle (clean address -> false,
// sanctioned address -> true) requires a real Ethereum RPC call and is
// verified on deploy, not in these offline tests. Chainalysis's documented
// test pair: clean 0x7f268357A8c2552623316e2562D90e642bB538E5 -> false;
// sanctioned 0x7F367cC41522cE07553e823bf3be79A889DEbe1B -> true.

console.log('\nCompanies House client:')

await test('active company returns parsed profile + empty PSC list', async () => {
  queueMock(200, {
    company_number: '00000006',
    company_name: 'TEST COMPANY LIMITED',
    company_status: 'active',
    type: 'ltd',
    date_of_creation: '1990-01-01',
    registered_office_address: { address_line_1: '1 Test St', locality: 'London', postal_code: 'EC1 1AA' },
  })
  queueMock(200, { items: [], total_results: 0 })

  const result = await checkCompany('00000006')
  assert.strictEqual(result.profile.companyName, 'TEST COMPANY LIMITED')
  assert.strictEqual(result.profile.status, 'active')
  assert.strictEqual(result.pscList.length, 0)
})

await test('company with PSC entries parses names and nature of control', async () => {
  queueMock(200, {
    company_number: '00000007',
    company_name: 'PSC TEST LTD',
    company_status: 'active',
    type: 'ltd',
  })
  queueMock(200, {
    items: [
      {
        name: 'Jane Test',
        kind: 'individual-person-with-significant-control',
        natures_of_control: ['ownership-of-shares-75-to-100-percent'],
        notified_on: '2020-01-01',
      },
    ],
    total_results: 1,
  })

  const result = await checkCompany('00000007')
  assert.strictEqual(result.pscList.length, 1)
  assert.strictEqual(result.pscList[0].name, 'Jane Test')
  assert.strictEqual(result.pscListTruncated, false)
})

await test('404 from company profile throws CompanyNotFoundError', async () => {
  queueMock(404, {})
  try {
    await checkCompany('99999999')
    assert.fail('expected an error to be thrown')
  } catch (err) {
    assert.ok(err instanceof CompanyNotFoundError)
  }
})

await test('404 from PSC endpoint is treated as empty list, not an error', async () => {
  queueMock(200, {
    company_number: '00000008',
    company_name: 'NO PSC LTD',
    company_status: 'active',
    type: 'ltd',
  })
  queueMock(404, {}) // PSC 404 = "no PSC records", not a failure

  const result = await checkCompany('00000008')
  assert.strictEqual(result.pscList.length, 0)
  assert.strictEqual(result.profile.companyName, 'NO PSC LTD')
})

// --- Rate limiter --------------------------------------------------------
console.log('\nRate limiter:')

const { createRateLimiter, callerKeyFromHeaders } = await import('../src/rateLimit.js')

await test('allows up to max, then blocks', async () => {
  const limiter = createRateLimiter({ max: 3, windowMs: 60_000 })
  const key = 'ip:1.2.3.4'
  assert.strictEqual(limiter(key).allowed, true) // 1
  assert.strictEqual(limiter(key).allowed, true) // 2
  assert.strictEqual(limiter(key).allowed, true) // 3
  assert.strictEqual(limiter(key).allowed, false) // 4 — over
})

await test('separate callers have separate buckets', async () => {
  const limiter = createRateLimiter({ max: 1, windowMs: 60_000 })
  assert.strictEqual(limiter('ip:a').allowed, true)
  assert.strictEqual(limiter('ip:a').allowed, false) // a is now over
  assert.strictEqual(limiter('ip:b').allowed, true) // b unaffected
})

await test('window reset allows requests again', async () => {
  const limiter = createRateLimiter({ max: 1, windowMs: 10 }) // tiny window
  assert.strictEqual(limiter('ip:c').allowed, true)
  assert.strictEqual(limiter('ip:c').allowed, false)
  await new Promise((r) => setTimeout(r, 20)) // wait past the window
  assert.strictEqual(limiter('ip:c').allowed, true) // fresh window
})

await test('callerKeyFromHeaders prefers credential, then IP, then fallback', async () => {
  assert.ok(
    callerKeyFromHeaders({ authorization: 'Payment abc123def', forwardedFor: '9.9.9.9' }).startsWith('cred:')
  )
  assert.strictEqual(
    callerKeyFromHeaders({ authorization: null, forwardedFor: '9.9.9.9, 8.8.8.8' }),
    'ip:9.9.9.9'
  )
  assert.strictEqual(callerKeyFromHeaders({ authorization: null, forwardedFor: null }), 'anon:shared')
})

// --- Circuit breaker (health.ts) ----------------------------------------
console.log('\nCircuit breaker:')

const { decideProbe, applyProbeResult, __test } = await import('../src/health.js')

await test('healthy probes keep breaker closed and serve cache within TTL', async () => {
  const b = __test.newBreaker()
  let now = 1_000_000
  // First call: closed but stale (lastProbeAt=0) → should probe.
  assert.deepStrictEqual(decideProbe(b, now), { probe: true })
  applyProbeResult(b, true, now)
  // Immediately after: within TTL → serve cached, no probe.
  const d = decideProbe(b, now + 1000)
  assert.deepStrictEqual(d, { probe: false, result: true })
})

await test('trips open after threshold consecutive failures', async () => {
  const b = __test.newBreaker()
  let now = 2_000_000
  for (let i = 0; i < __test.FAILURE_THRESHOLD; i++) {
    // Force a probe each time by advancing past TTL.
    now += __test.TTL_MS + 1
    const d = decideProbe(b, now)
    assert.deepStrictEqual(d, { probe: true })
    applyProbeResult(b, false, now)
  }
  // Now the breaker should be open → fail fast without probing.
  const d = decideProbe(b, now + 1)
  assert.deepStrictEqual(d, { probe: false, result: false })
})

await test('open → half-open after cooldown, then closes on recovery', async () => {
  const b = __test.newBreaker()
  let now = 3_000_000
  // Trip it.
  for (let i = 0; i < __test.FAILURE_THRESHOLD; i++) {
    now += __test.TTL_MS + 1
    decideProbe(b, now)
    applyProbeResult(b, false, now)
  }
  // Still in cooldown → fail fast.
  assert.deepStrictEqual(decideProbe(b, now + 1000), { probe: false, result: false })
  // After cooldown → half-open → allows a trial probe.
  now += __test.OPEN_COOLDOWN_MS + 1
  assert.deepStrictEqual(decideProbe(b, now), { probe: true })
  // Trial probe succeeds → breaker closes, healthy again.
  applyProbeResult(b, true, now)
  assert.deepStrictEqual(decideProbe(b, now + 1000), { probe: false, result: true })
})

await test('half-open trial failure re-opens the breaker', async () => {
  const b = __test.newBreaker()
  let now = 4_000_000
  for (let i = 0; i < __test.FAILURE_THRESHOLD; i++) {
    now += __test.TTL_MS + 1
    decideProbe(b, now)
    applyProbeResult(b, false, now)
  }
  now += __test.OPEN_COOLDOWN_MS + 1
  decideProbe(b, now) // → half-open, probe allowed
  applyProbeResult(b, false, now) // trial fails → re-open
  assert.deepStrictEqual(decideProbe(b, now + 1000), { probe: false, result: false })
})

// --- Attestation (attestation.ts) ---------------------------------------
console.log('\nAttestation:')

const crypto = await import('node:crypto')
const att = await import('../src/attestation.js')
const { canonicalizeJson } = await import('../src/canonicalJson.js')
const { validateAttestationKeyRegistry } = await import('../src/attestationKeyHistory.js')

function makeKeyRecord(status: 'active' | 'retired' | 'revoked' | 'compromised' = 'active') {
  const { publicKey } = crypto.generateKeyPairSync('ed25519')
  const public_key_pem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const digest = crypto.createHash('sha256')
    .update(publicKey.export({ type: 'spki', format: 'der' }))
    .digest('base64url')
  return {
    key_id: `ed25519-${digest.slice(0, 16)}`,
    algorithm: 'ed25519' as const,
    public_key_pem,
    status,
    valid_from: '2026-01-01T00:00:00.000Z',
    valid_until: status === 'retired' ? '2026-02-01T00:00:00.000Z' : null,
    status_changed_at: status === 'active' ? '2026-01-01T00:00:00.000Z' : '2026-02-01T00:00:00.000Z',
    status_reason: status === 'revoked' ? 'operator-requested revocation' : undefined,
    compromised_at: status === 'compromised' ? '2026-01-15T00:00:00.000Z' : null,
    replacement_key_id: null as string | null,
  }
}

await test('canonical JSON sorts object keys recursively and preserves array order', async () => {
  assert.strictEqual(
    canonicalizeJson({ z: 2, a: { y: true, x: ['b', 'a'] }, n: -0 }),
    '{"a":{"x":["b","a"],"y":true},"n":0,"z":2}'
  )
})

await test('shared RFC8785 language-neutral vectors match API canonicalization', async () => {
  const corpus = JSON.parse(
    readFileSync(new URL('../conformance/rfc8785-vectors.json', import.meta.url), 'utf8')
  ) as {
    canonicalization: Array<{ id: string; input: unknown; expected: string }>
    invalid_json: Array<{ id: string; input: string; error_code: string }>
  }
  for (const vector of corpus.canonicalization) {
    assert.strictEqual(canonicalizeJson(vector.input), vector.expected, vector.id)
  }
})

await test('key registry validates SPKI identity, lifecycle and strict readiness', async () => {
  const active = makeKeyRecord()
  assert.deepStrictEqual(validateAttestationKeyRegistry([active], { requireValidFrom: true }), {
    strict_ready: true,
    warnings: [],
  })

  const missingBoundary = { ...active, valid_from: null }
  const migration = validateAttestationKeyRegistry([missingBoundary])
  assert.strictEqual(migration.strict_ready, false)
  assert.match(migration.warnings[0], /no valid_from/)
  assert.throws(
    () => validateAttestationKeyRegistry([missingBoundary], { requireValidFrom: true }),
    /no valid_from/
  )

  assert.throws(() => validateAttestationKeyRegistry([active, active]), /duplicate/)
  assert.throws(
    () => validateAttestationKeyRegistry([{ ...active, key_id: 'ed25519-AAAAAAAAAAAAAAAA' }]),
    /does not match its public key/
  )
  assert.throws(
    () => validateAttestationKeyRegistry([{ ...active, valid_from: '2026-01-01' }]),
    /invalid valid_from/
  )
})

await test('key registry rejects incoherent transition records and replacement links', async () => {
  const active = makeKeyRecord()
  const retired = makeKeyRecord('retired')
  retired.replacement_key_id = active.key_id
  assert.strictEqual(validateAttestationKeyRegistry([active, retired]).strict_ready, true)

  assert.throws(
    () => validateAttestationKeyRegistry([{ ...retired, valid_until: null }]),
    /requires valid_until/
  )
  assert.throws(
    () => validateAttestationKeyRegistry([{ ...retired, replacement_key_id: 'ed25519-AAAAAAAAAAAAAAAA' }]),
    /unknown replacement/
  )
  assert.throws(
    () => validateAttestationKeyRegistry([{ ...makeKeyRecord('compromised'), compromised_at: null }]),
    /requires compromised_at/
  )
  assert.throws(
    () => validateAttestationKeyRegistry([{ ...makeKeyRecord('revoked'), status_reason: undefined }]),
    /requires status_changed_at and status_reason/
  )
  assert.throws(
    () => validateAttestationKeyRegistry([{ ...retired, valid_until: '2025-12-31T00:00:00.000Z' }]),
    /before valid_from/
  )
})

await test('signs a response and the signature verifies with the public key', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519')
  process.env.ATTESTATION_PRIVATE_KEY = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
  att.__reinit()

  assert.strictEqual(att.attestationEnabled(), true)
  const envelope: any = att.attest({ address: '0xABC', sanctioned: false })
  assert.strictEqual(envelope.attestation.signed, true)
  assert.strictEqual(envelope.attestation.schema_version, att.ATTESTATION_SCHEMA_VERSION)
  assert.strictEqual(envelope.attestation.issuer, att.ATTESTATION_ISSUER)
  assert.strictEqual(envelope.attestation.purpose, att.ATTESTATION_PURPOSE)
  assert.strictEqual(envelope.attestation.canonicalization, 'RFC8785')

  const signingInput = att.buildAttestationSigningInput(
    envelope.data,
    envelope.attestation.issued_at,
    envelope.attestation.key_id
  )
  const pub = crypto.createPublicKey(att.getPublicKeyPem()!)
  const ok = crypto.verify(
    null,
    Buffer.from(signingInput, 'utf8'),
    pub,
    Buffer.from(envelope.attestation.signature, 'base64url')
  )
  assert.strictEqual(ok, true)

  const records = att.getAttestationKeyRecords()
  assert.strictEqual(records.length, 1)
  assert.strictEqual(records[0].key_id, envelope.attestation.key_id)
  assert.strictEqual(records[0].status, 'active')
  assert.strictEqual(att.getAttestationKeyRecord(envelope.attestation.key_id)?.public_key_pem, att.getPublicKeyPem())
})

await test('tampered data fails verification', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519')
  process.env.ATTESTATION_PRIVATE_KEY = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
  att.__reinit()

  const envelope: any = att.attest({ sanctioned: false })
  const tampered = att.buildAttestationSigningInput(
    { sanctioned: true }, // flipped
    envelope.attestation.issued_at,
    envelope.attestation.key_id
  )
  const pub = crypto.createPublicKey(att.getPublicKeyPem()!)
  const ok = crypto.verify(
    null,
    Buffer.from(tampered, 'utf8'),
    pub,
    Buffer.from(envelope.attestation.signature, 'base64url')
  )
  assert.strictEqual(ok, false)
})

await test('only a complete authentic compliance envelope is anchorable', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519')
  process.env.ATTESTATION_PRIVATE_KEY = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
  att.__reinit()

  const envelope: any = att.attest({ sanctioned: false, address: '0xABC' })
  const verified = att.verifyAttestationForAnchoring(envelope)
  assert.strictEqual(verified.valid, true)
  if (verified.valid) {
    assert.strictEqual(verified.attestation.signature, envelope.attestation.signature)
    assert.strictEqual(verified.attestation.keyId, envelope.attestation.key_id)
    assert.strictEqual(verified.attestation.keyStatus, 'active')
  }

  const tampered = structuredClone(envelope)
  tampered.data.sanctioned = true
  const tamperedResult = att.verifyAttestationForAnchoring(tampered)
  assert.strictEqual(tamperedResult.valid, false)
  if (!tamperedResult.valid) assert.strictEqual(tamperedResult.status, 422)

  const randomSignature = structuredClone(envelope)
  randomSignature.attestation.signature = Buffer.alloc(64, 7).toString('base64url')
  assert.strictEqual(att.verifyAttestationForAnchoring(randomSignature).valid, false)

  const unknownKey = structuredClone(envelope)
  unknownKey.attestation.key_id = 'ed25519-unknown'
  const unknownResult = att.verifyAttestationForAnchoring(unknownKey)
  assert.strictEqual(unknownResult.valid, false)
  if (!unknownResult.valid) assert.match(unknownResult.error, /key_id is not in/)
})

await test('anchor verification rejects disallowed key states and non-compliance purposes', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519')
  process.env.ATTESTATION_PRIVATE_KEY = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
  att.__reinit()

  const envelope: any = att.attest({ sanctioned: false })
  const currentKey = att.getAttestationKeyRecord(envelope.attestation.key_id)!

  const retired = att.verifyAttestationForAnchoring(envelope, () => ({
    ...currentKey,
    status: 'retired',
    valid_until: new Date(Date.parse(envelope.attestation.issued_at) + 60_000).toISOString(),
    status_changed_at: new Date(Date.parse(envelope.attestation.issued_at) + 60_000).toISOString(),
  }))
  assert.strictEqual(retired.valid, true)

  const missingBoundary = att.verifyAttestationForAnchoring(envelope, () => ({
    ...currentKey,
    valid_from: null,
  }))
  assert.strictEqual(missingBoundary.valid, false)
  if (!missingBoundary.valid) assert.match(missingBoundary.error, /valid_from/)

  for (const status of ['revoked', 'compromised'] as const) {
    const result = att.verifyAttestationForAnchoring(envelope, () => ({ ...currentKey, status }))
    assert.strictEqual(result.valid, false)
    if (!result.valid) assert.match(result.error, new RegExp(status))
  }

  const fixture: any = att.attest(
    { fixture: true },
    { purpose: att.ATTESTATION_FIXTURE_PURPOSE }
  )
  const fixtureResult = att.verifyAttestationForAnchoring(fixture)
  assert.strictEqual(fixtureResult.valid, false)
  if (!fixtureResult.valid) assert.match(fixtureResult.error, /not an anchorable/)
})

await test('disabled when no key configured (graceful, not signed)', async () => {
  delete process.env.ATTESTATION_PRIVATE_KEY
  att.__reinit()
  assert.strictEqual(att.attestationEnabled(), false)
  const envelope: any = att.attest({ x: 1 })
  assert.strictEqual(envelope.attestation.signed, false)
})

console.log('\nENS resolution:')

await test('looksLikeEns distinguishes names from addresses', async () => {
  const { looksLikeEns } = await import('../src/ens.js')
  assert.strictEqual(looksLikeEns('0x7f268357A8c2552623316e2562D90e642bB538E5'), false)
  assert.strictEqual(looksLikeEns('vitalik.eth'), true)
  assert.strictEqual(looksLikeEns('hello'), false)
  assert.strictEqual(looksLikeEns(' vitalik.eth '), true)
})

await test('resolveToAddress passes a hex address through unchanged', async () => {
  const { resolveToAddress } = await import('../src/ens.js')
  const addr = '0x7f268357A8c2552623316e2562D90e642bB538E5'
  const r = await resolveToAddress(addr)
  assert.strictEqual(r.address, addr)
  assert.strictEqual(r.ens, null)
})

console.log('\nOFAC SDN name screening:')

await test('parseOfacLine handles quotes and the -0- null sentinel', async () => {
  const { parseOfacLine } = await import('../src/ofac.js')
  const f = parseOfacLine('306,"PUTIN, Vladimir Vladimirovich","individual","-0-"')
  assert.strictEqual(f[0], '306')
  assert.strictEqual(f[1], 'PUTIN, Vladimir Vladimirovich')
  assert.strictEqual(f[3], null)
  // Real OFAC data pads fields: the null sentinel can arrive as "-0- ".
  const g = parseOfacLine('36,"AEROCARIBBEAN AIRLINES",-0- ,"CUBA",-0- ,-0-')
  assert.strictEqual(g[1], 'AEROCARIBBEAN AIRLINES') // internal space kept
  assert.strictEqual(g[2], null) // padded "-0- " → null
  assert.strictEqual(g[3], 'CUBA')
  assert.strictEqual(g[4], null)
})

await test('buildSdnIndex links strong aliases by ent_num', async () => {
  const { buildSdnIndex } = await import('../src/ofac.js')
  const sdn = '306,"PUTIN, Vladimir Vladimirovich","individual","RUSSIA-EO14024"'
  const alt = '306,2,"aka","PUTIN, Vladimir","-0-"\n306,3,"aka","POUTINE, Vladimir","-0-"'
  const idx = buildSdnIndex(sdn, alt)
  assert.strictEqual(idx.length, 1)
  assert.strictEqual(idx[0].aliases.length, 2)
})

await test('similarity scores word-order / middle-name variants high', async () => {
  const { similarity } = await import('../src/ofac.js')
  assert.ok(similarity('Vladimir Putin', 'PUTIN, Vladimir Vladimirovich') >= 0.85)
  assert.ok(similarity('vladimir putin', 'PUTIN, Vladimir') >= 0.85)
})

await test('similarity scores unrelated names low (false-positive control)', async () => {
  const { similarity } = await import('../src/ofac.js')
  assert.ok(similarity('John Smith', 'PUTIN, Vladimir Vladimirovich') < 0.5)
  assert.ok(similarity('Jane Doe', 'AL-ZAWAHIRI, Ayman') < 0.5)
})

await test('screenNameAgainstIndex hits sanctioned, misses clean, catches alias', async () => {
  const { buildSdnIndex, screenNameAgainstIndex } = await import('../src/ofac.js')
  const sdn =
    '306,"PUTIN, Vladimir Vladimirovich","individual","RUSSIA-EO14024"\n' +
    '7522,"AL-ZAWAHIRI, Ayman","individual","SDGT"'
  const alt = '306,3,"aka","POUTINE, Vladimir","-0-"'
  const idx = buildSdnIndex(sdn, alt)
  assert.strictEqual(screenNameAgainstIndex('Vladimir Putin', idx, 0.85)[0]?.ent_num, 306)
  const aliasHit = screenNameAgainstIndex('Vladimir Poutine', idx, 0.85)
  assert.ok(aliasHit.length >= 1 && aliasHit[0].matched_on === 'alias')
  assert.strictEqual(screenNameAgainstIndex('Jane Doe', idx, 0.85).length, 0)
})

console.log('\n/diligence total-failure integrity guard:')

await test('both checks failed → treated as total failure (502, not signed 200)', async () => {
  const { isTotalFailure } = await import('../src/diligence.js')
  assert.strictEqual(isTotalFailure({ ok: false }, { ok: false }), true)
})

await test('partial success (one ok) → NOT total failure (still returns 200)', async () => {
  const { isTotalFailure } = await import('../src/diligence.js')
  assert.strictEqual(isTotalFailure({ ok: true }, { ok: false }), false)
  assert.strictEqual(isTotalFailure({ ok: false }, { ok: true }), false)
})

await test('single failed check → total failure', async () => {
  const { isTotalFailure } = await import('../src/diligence.js')
  assert.strictEqual(isTotalFailure({ ok: false }, null), true)
})

await test('single ok / nothing attempted → not total failure', async () => {
  const { isTotalFailure } = await import('../src/diligence.js')
  assert.strictEqual(isTotalFailure({ ok: true }, null), false)
  assert.strictEqual(isTotalFailure(null, null), false)
})

// --- Paid-route preflight ordering --------------------------------------
console.log('\nPaid route preflight guards:')

// Re-enable signing after the attestation-disabled test, then import the app.
// All requests below fail in side-effect-free validation before health probes
// or payment middleware, so no network mock is consumed and no 402 is issued.
const { privateKey: routeTestKey } = crypto.generateKeyPairSync('ed25519')
process.env.ATTESTATION_PRIVATE_KEY = routeTestKey.export({
  type: 'pkcs8',
  format: 'pem',
}) as string
att.__reinit()
const { default: routeApp } = await import('../src/server.js')

const expectPrePaymentRejection = async (
  path: string,
  expectedStatus: 400 | 413 | 422 | 503,
  init?: RequestInit
) => {
  const response = await routeApp.request(path, init)
  assert.strictEqual(response.status, expectedStatus)
  assert.notStrictEqual(response.status, 402)
  assert.strictEqual(response.headers.get('WWW-Authenticate'), null)
}

const invalidPaidRequests: Array<[string, 400 | 413 | 422 | 503, RequestInit?]> = [
  ['/screen/not-an-address', 400],
  ['/verdict/not-an-address', 400],
  ['/screen-name?name=x', 400],
  ['/company/123456789012345678901', 400],
  ['/us-company', 400],
  ['/diligence', 400],
  ['/web/screen/not-an-address', 400],
  ['/web/screen-name?name=x', 400],
  ['/web/company/123456789012345678901', 400],
  ['/web/us-company', 400],
  [
    '/anchor',
    400,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ signature: 'invalid' }),
    },
  ],
]

for (const [path, status, init] of invalidPaidRequests) {
  await test(`${path} rejects before payment`, async () => {
    await expectPrePaymentRejection(path, status, init)
  })
}

await test('/anchor rejects a tampered full envelope before payment', async () => {
  const envelope: any = att.attest({ sanctioned: false })
  envelope.data.sanctioned = true
  await expectPrePaymentRejection('/anchor', 422, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(envelope),
  })
})

await test('/anchor rejects an oversized envelope before payment', async () => {
  await expectPrePaymentRejection('/anchor', 413, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ padding: 'x'.repeat(256 * 1024) }),
  })
})

await test('/anchor accepts an authentic envelope into the payment gate', async () => {
  const envelope = att.attest({ sanctioned: false })
  const response = await routeApp.request('/anchor', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(envelope),
  })
  assert.strictEqual(response.status, 402)
})

console.log(`\n${passed} passed, ${failed} failed`)

global.fetch = originalFetch

if (failed > 0) {
  process.exitCode = 1
}
