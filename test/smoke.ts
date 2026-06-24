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
  return {
    ok: next.status >= 200 && next.status < 300,
    status: next.status,
    json: async () => next.body,
  } as Response
}) as typeof fetch

// Set fake env vars before config.ts reads them.
process.env.COMPANIES_HOUSE_API_KEY = 'fake-key-for-tests'
process.env.MPP_RECIPIENT_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb9226d'

const { screenAddress } = await import('../src/chainalysis.js')
const { checkCompany, CompanyNotFoundError } = await import('../src/companiesHouse.js')

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

await test('signs a response and the signature verifies with the public key', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519')
  process.env.ATTESTATION_PRIVATE_KEY = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
  att.__reinit()

  assert.strictEqual(att.attestationEnabled(), true)
  const envelope: any = att.attest({ address: '0xABC', sanctioned: false })
  assert.strictEqual(envelope.attestation.signed, true)

  const signingInput = JSON.stringify({
    data: envelope.data,
    issued_at: envelope.attestation.issued_at,
    key_id: envelope.attestation.key_id,
  })
  const pub = crypto.createPublicKey(att.getPublicKeyPem()!)
  const ok = crypto.verify(
    null,
    Buffer.from(signingInput, 'utf8'),
    pub,
    Buffer.from(envelope.attestation.signature, 'base64url')
  )
  assert.strictEqual(ok, true)
})

await test('tampered data fails verification', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519')
  process.env.ATTESTATION_PRIVATE_KEY = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
  att.__reinit()

  const envelope: any = att.attest({ sanctioned: false })
  const tampered = JSON.stringify({
    data: { sanctioned: true }, // flipped
    issued_at: envelope.attestation.issued_at,
    key_id: envelope.attestation.key_id,
  })
  const pub = crypto.createPublicKey(att.getPublicKeyPem()!)
  const ok = crypto.verify(
    null,
    Buffer.from(tampered, 'utf8'),
    pub,
    Buffer.from(envelope.attestation.signature, 'base64url')
  )
  assert.strictEqual(ok, false)
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

console.log(`\n${passed} passed, ${failed} failed`)

global.fetch = originalFetch

if (failed > 0) {
  process.exitCode = 1
}
