/**
 * test/ofacSdnScreening.ts — OFAC SDN digital-currency-address screening (offline).
 *
 * Fixture: test/fixtures/ofac-sdn/sdn-2026-10-15-excerpt.xml is three entries
 * copied from the official SDN.XML published 2026-10-15 (personal e-mail,
 * date and place of birth fields trimmed). Entry 24003 lists the incident
 * address 0x252a8bd2319d8a555b872990601221b3a2053bce as "Digital Currency
 * Address - ETH". No network, database, payment or chain call is made.
 *
 * Run: npx tsx test/ofacSdnScreening.ts
 */
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { readFileSync } from 'node:fs'

process.env.COMPANIES_HOUSE_API_KEY = 'fake-key-for-tests'
process.env.MPP_RECIPIENT_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb9226d'
process.env.TEMPO_CURRENCY_ADDRESS = '0x20c0000000000000000000000000000000000000'
process.env.MPP_SECRET_KEY = 'test-mpp-secret-that-is-at-least-32-characters'
const serviceToken = 'test-attestation-token-at-least-32-characters'
process.env.ATTESTATION_SERVICE_TOKEN = serviceToken
process.env.ATTESTATION_KEY_ACTIVATED_AT = '2026-01-01T00:00:00.000Z'
process.env.TEMPO_TESTNET = 'true'
process.env.ATTESTATION_PRIVATE_KEY = crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
delete process.env.SANCTIONS_DATABASE_URL
delete process.env.DATABASE_URL
delete process.env.SANCTIONS_MAX_STALENESS_HOURS

// Counterparty rows served for the Tempo transfer lookup; everything else answers {}.
let tempoRows: Array<Record<string, unknown>> = []
globalThis.fetch = (async (input: string | URL | Request) => {
  const url = String(input)
  const body = url.startsWith('https://api.tempo.xyz/') ? { data: tempoRows } : {}
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}) as typeof fetch

const REPORTED = '0x252a8bd2319d8a555b872990601221b3a2053bce'
const REPORTED_CHECKSUM = '0x252A8bD2319D8A555B872990601221b3A2053bCE'
const NON_MATCH = '0x000000000000000000000000000000000000dEaD'
const USDT_LABELLED_EVM = '0x2f389ce8bd8ff92de3402ffce4691d17fc4f6535'
const XBT_LISTED = '12aNKp2iDKuhEde2YfPdd4DFGenRUTKupL'
const TRX_LISTED = 'TAbbVaBKgH4VBLXgWqACuwoKF4cH1HinQh'

const shared = await import('../src/ofacSdnDigitalCurrency.js')
const ws = await import('../src/walletSanctions.js')
const { default: app } = await import('../src/server.js')

// 0. Shared-module divergence tripwire: the same pins live in the MCP repo's test.
const PINS: Record<string, string> = {
  'src/ofacSdnDigitalCurrency.ts': '3a2d99b7075be154468e0eb663401e0a4a29aaf1ea22f726470c791a62373847',
  'src/walletSanctions.ts': '32a2384ab97760e7cb8c15415cbd5f11793336b65fbfc18d795eeb3922fe0848',
}
for (const [file, pin] of Object.entries(PINS)) {
  const text = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8').replace(/\r\n/g, '\n')
  assert.equal(crypto.createHash('sha256').update(text).digest('hex'), pin, `${file} diverged from the pinned shared copy`)
}

// 1. Parser on the frozen official excerpt.
const fixtureBytes = readFileSync(new URL('./fixtures/ofac-sdn/sdn-2026-10-15-excerpt.xml', import.meta.url))
const fixture = fixtureBytes.toString('utf8')
const fixtureSha = crypto.createHash('sha256').update(fixtureBytes).digest('hex')
const parsed = shared.parseSdnXml(fixture)
assert.equal(parsed.publish_date, '2026-10-15')
assert.equal(parsed.record_count, 3)
assert.equal(parsed.entry_count, 3)
const stated = fixture.split('<idType>Digital Currency Address - ').length - 1
assert.equal(parsed.identifiers.length, stated, 'every digital currency identifier is extracted')
const reportedIds = parsed.identifiers.filter((i) => i.normalized_value === REPORTED)
assert.equal(reportedIds.length, 1)
assert.deepEqual(
  { sdn_uid: reportedIds[0].sdn_uid, id_uid: reportedIds[0].id_uid, currency: reportedIds[0].currency, programs: reportedIds[0].programs, name: reportedIds[0].sdn_name },
  { sdn_uid: 24003, id_uid: 196530, currency: 'ETH', programs: ['CYBER2', 'HRIT-IR'], name: 'MESRI, Behzad' }
)
assert.equal(parsed.identifiers.find((i) => i.normalized_value === USDT_LABELLED_EVM)?.currency, 'USDT')
const xbt = parsed.identifiers.find((i) => i.listed_value === XBT_LISTED)!
assert.equal(xbt.address_format, 'other')
assert.equal(xbt.normalized_value, XBT_LISTED, 'non-EVM identifiers keep their case')
assert.match(shared.identifierIndexSha256(parsed.identifiers), /^[0-9a-f]{64}$/)

// 2. Malformed or altered documents never become an index.
const rejects = (xml: string, reason: string) =>
  assert.throws(() => shared.parseSdnXml(xml), (e: any) => e instanceof shared.SdnParseError && e.reason === reason, reason)
rejects(fixture.replace('<?xml version="1.0" standalone="yes"?>', '<?xml version="1.0"?><!DOCTYPE sdnList [<!ENTITY x "y">]>'), 'dtd_not_allowed')
rejects(fixture.slice(0, fixture.length - 30), 'truncated')
rejects(fixture.replace('<Record_Count>3</Record_Count>', '<Record_Count>4</Record_Count>'), 'record_count_mismatch')
rejects('<html><body>Service Unavailable</body></html>', 'not_xml')
rejects(fixture.replace('exports/XML"', 'exports/XML2"'), 'unexpected_namespace')
rejects(fixture.replace(`<idNumber>${REPORTED}</idNumber>`, `<idNumber>${REPORTED}&evil;</idNumber>`), 'malformed_entity')
rejects(fixture.replace('<Publish_Date>10/15/2026</Publish_Date>', '<Publish_Date>13/45/2026</Publish_Date>'), 'bad_publish_date')
rejects(fixture.replace('<remarks>(Linked To: NET PEYGARD SAMAVAT COMPANY)</remarks>',
  '<remarks>Digital Currency Address - ETH 0x1111111111111111111111111111111111111111</remarks>'), 'identifier_outside_id_list')
rejects(fixture.replace('<idNumber>0x252a8bd2319d8a555b872990601221b3a2053bce</idNumber>', '<idNumber>0x252a 8bd2</idNumber>'), 'bad_identifier_value')
rejects('', 'empty')

// 3. Candidate validation: floors, abnormal shrinkage (quarantine), rollback, future dates.
const now = new Date('2026-10-16T12:00:00.000Z')
assert.equal((shared.validateCandidate(parsed, null, now) as any).reason, 'too_few_entries', 'default floors reject toy-sized lists')
const testPolicy = { ...shared.DEFAULT_SNAPSHOT_POLICY, minRecordCount: 1, minDigitalCurrencyIdentifiers: 1, minEvmIdentifiers: 1 }
const summary = shared.summarizeIdentifiers(parsed.identifiers)
const previousOf = (p = parsed) => {
  const s = shared.summarizeIdentifiers(p.identifiers)
  return { publish_date: p.publish_date, entry_count: p.entry_count, digital_currency_identifiers: s.digital_currency_identifiers, evm_identifiers: s.evm_identifiers }
}
assert.deepEqual(shared.validateCandidate(parsed, null, now, testPolicy), { ok: true })
assert.deepEqual(shared.validateCandidate(parsed, previousOf(), now, testPolicy), { ok: true })
const without24003 = fixture
  .replace(/  <sdnEntry>\r?\n    <uid>24003<\/uid>[\s\S]*?<\/sdnEntry>\r?\n/, '')
  .replace('<Record_Count>3</Record_Count>', '<Record_Count>2</Record_Count>')
const delisted = shared.parseSdnXml(without24003)
const shrink = shared.validateCandidate(delisted, previousOf(), now, testPolicy) as any
assert.equal(shrink.disposition, 'quarantine')
assert.equal(shrink.reason, 'abnormal_shrinkage')
assert.deepEqual(shared.validateCandidate(delisted, previousOf(), now, testPolicy, { acceptShrinkage: true }), { ok: true })
assert.equal((shared.validateCandidate(parsed, { ...previousOf(), publish_date: '2026-10-16' }, now, testPolicy) as any).reason, 'publication_rollback')
assert.equal((shared.validateCandidate(parsed, null, new Date('2026-10-01T00:00:00Z'), testPolicy) as any).reason, 'publish_date_in_future')
assert.ok(summary.evm_identifiers > 0 && summary.digital_currency_identifiers > summary.evm_identifiers)

// 4. Freshness of a stored snapshot.
function recordFor(p: typeof parsed, sha: string, revalidatedAt: Date, extra: Partial<Record<string, unknown>> = {}) {
  const s = shared.summarizeIdentifiers(p.identifiers)
  return {
    snapshot_id: crypto.randomUUID(),
    dataset: shared.OFAC_SDN_DATASET,
    status: 'active',
    source_url: shared.OFAC_SDN_XML_URL,
    source_object: 'wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com/Published/x/2026-10-15/y/SDN.XML',
    publication_id: '1054',
    publish_date: p.publish_date,
    record_count: p.record_count,
    entry_count: p.entry_count,
    retrieved_at: new Date(revalidatedAt.getTime() - 60_000).toISOString(),
    revalidated_at: revalidatedAt.toISOString(),
    source_sha256: sha,
    index_sha256: shared.identifierIndexSha256(p.identifiers),
    parser_version: shared.OFAC_SDN_PARSER_VERSION,
    digital_currency_identifiers: s.digital_currency_identifiers,
    evm_identifiers: s.evm_identifiers,
    evm_unique_addresses: s.evm_unique_addresses,
    ...extra,
  } as any
}
const hour = 3_600_000
assert.equal(shared.assessSnapshot(recordFor(parsed, fixtureSha, new Date(now.getTime() - hour)), now).usable, true)
const reasonOf = (r: any) => (shared.assessSnapshot(r, now) as any).reason
assert.equal(reasonOf(recordFor(parsed, fixtureSha, new Date(now.getTime() - 7 * hour))), 'stale')
assert.equal(reasonOf(recordFor(parsed, fixtureSha, new Date(now.getTime() + hour))), 'future_timestamp')
assert.equal(reasonOf(recordFor(parsed, fixtureSha, new Date(now.getTime() - hour), { parser_version: 'ocd-ofac-sdn-dca/0' })), 'unsupported_parser_version')
assert.equal(reasonOf(recordFor(parsed, fixtureSha, new Date(now.getTime() - hour), { status: 'superseded' })), 'not_active')
assert.equal(reasonOf(recordFor(parsed, 'not-a-digest', new Date(now.getTime() - hour))), 'invalid_record')
assert.equal(shared.maxStalenessMsFromEnv(undefined), 6 * hour)
assert.equal(shared.maxStalenessMsFromEnv('100'), 24 * hour, 'staleness is capped at 24h')
assert.equal(shared.maxStalenessMsFromEnv('0.1'), 1 * hour)

// 5. Screening semantics against an in-memory snapshot.
const loaded = (p: typeof parsed, sha: string) => ({
  record: recordFor(p, sha, new Date(now.getTime() - hour)),
  evm: shared.indexEvmIdentifiers(p.identifiers),
  assessed_at: now.toISOString(),
})
const snapA = loaded(parsed, fixtureSha)
for (const variant of [REPORTED, REPORTED.toUpperCase().replace('0X', '0x'), REPORTED_CHECKSUM]) {
  const r = shared.screenEvmAddress(snapA, variant)
  assert.equal(r.match_status, 'listed')
  assert.equal(r.sanctioned, true)
  assert.equal(r.matches[0].sdn_uid, 24003)
  assert.equal(r.matches[0].identifier_type, 'Digital Currency Address - ETH')
  assert.equal(r.matches[0].listed_value, REPORTED)
  assert.equal(r.matches[0].entry_url, 'https://sanctionssearch.ofac.treas.gov/Details.aspx?id=24003')
  assert.equal(r.identifications[0].category, 'OFAC SDN List')
  assert.equal(r.screening.dataset.source_sha256, fixtureSha)
  assert.equal(r.screening.dataset.publish_date, '2026-10-15')
}
assert.equal(shared.screenEvmAddress(snapA, USDT_LABELLED_EVM).matches[0].identifier_type, 'Digital Currency Address - USDT')
const clean = shared.screenEvmAddress(snapA, NON_MATCH)
assert.equal(clean.match_status, 'not_listed')
assert.equal(clean.sanctioned, false)
assert.deepEqual(clean.matches, [])
assert.equal(clean.screening.scope, 'ofac_sdn_digital_currency_address')
assert.match(clean.screening.coverage, /SDN List .* only.*Not the OFAC non-SDN/s)
assert.ok(clean.screening.limitations.some((l) => /not legal clearance/.test(l)))
assert.ok(clean.screening.limitations.some((l) => /FAQ 562/.test(l)))
assert.ok(clean.screening.limitations.some((l) => /50 Percent Rule/.test(l)))
assert.ok(clean.screening.limitations.some((l) => /EU, UN, UK/.test(l)))
assert.deepEqual(Object.keys(clean.screening.dataset).sort(), [
  'dataset', 'digital_currency_identifiers', 'evm_identifiers', 'index_sha256', 'matching_version', 'name',
  'parser_version', 'publication_id', 'publish_date', 'record_count', 'retrieved_at', 'revalidated_at',
  'snapshot_id', 'source_object', 'source_sha256', 'source_url',
])
assert.doesNotMatch(JSON.stringify(clean.screening.dataset), /X-Amz|Signature=|\?/, 'no pre-signed query string in provenance')
// Unsupported formats are never "not listed", even when OFAC lists them under another currency.
assert.equal(shared.classifyAddress(XBT_LISTED), 'unsupported')
assert.equal(shared.classifyAddress(TRX_LISTED), 'unsupported')
assert.equal(shared.classifyAddress('0x123'), 'invalid')
assert.equal(shared.classifyAddress('hello world'), 'invalid')
await assert.rejects(ws.screenAddress(XBT_LISTED), (e: any) => e instanceof ws.InvalidWalletAddressError && e.code === 'unsupported_address_format')
await assert.rejects(ws.screenAddress('0x123'), (e: any) => e instanceof ws.InvalidWalletAddressError && e.code === 'invalid_address')
// Delisting / snapshot transition: each result is bound to the snapshot that produced it.
const delistedSha = crypto.createHash('sha256').update(without24003).digest('hex')
const snapB = loaded(delisted, delistedSha)
const before = shared.screenEvmAddress(snapA, REPORTED)
const after = shared.screenEvmAddress(snapB, REPORTED)
assert.equal(before.match_status, 'listed')
assert.equal(after.match_status, 'not_listed')
assert.notEqual(before.screening.dataset.source_sha256, after.screening.dataset.source_sha256)
assert.notEqual(before.screening.dataset.snapshot_id, after.screening.dataset.snapshot_id)
assert.equal(shared.sourceEvidenceDigest(fixtureSha), `sha256:${Buffer.from(fixtureSha, 'hex').toString('base64url')}`)

// 6. Store reader: every failure is UNKNOWN (an error), never a negative.
const stored = (p: typeof parsed, sha: string, revalidatedAt: Date) => ({
  record: recordFor(p, sha, revalidatedAt),
  evm_identifiers: p.identifiers.filter((i) => i.address_format === 'evm'),
})
const unavailable = async (reason: string) =>
  assert.rejects(ws.screenAddress(REPORTED), (e: any) => e instanceof ws.SanctionsUnavailableError && e.reason === reason, reason)
await unavailable('not_configured') // no override, no SANCTIONS_DATABASE_URL
ws.setSanctionsSnapshotSource(async () => null)
await unavailable('no_snapshot')
ws.setSanctionsSnapshotSource(async () => { throw new Error('connect ECONNREFUSED db.internal:5432 role=writer') })
await unavailable('store_unavailable')
await assert.rejects(ws.screenAddress(REPORTED), (e: any) => !/ECONNREFUSED|db\.internal|role=/.test(e.message), 'driver details never leak')
ws.setSanctionsSnapshotSource(async () => stored(parsed, fixtureSha, new Date(Date.now() - 7 * hour)))
await unavailable('stale')
ws.setSanctionsSnapshotSource(async () => ({ ...stored(parsed, fixtureSha, new Date()), evm_identifiers: [] }))
await unavailable('invalid_record')
let loads = 0
const freshSource = async () => { loads++; return stored(parsed, fixtureSha, new Date(Date.now() - hour)) }
ws.setSanctionsSnapshotSource(freshSource)
assert.equal((await ws.screenAddress(REPORTED)).match_status, 'listed')
assert.equal((await ws.screenAddress(NON_MATCH)).match_status, 'not_listed')

// 7. HTTP routes. Fresh data: the gate passes and payment is requested (402).
const routes = [`/screen/${REPORTED}`, `/verdict/${REPORTED}`, `/web/screen/${REPORTED}`, `/diligence?wallet=${REPORTED}`]
for (const path of routes) {
  const res = await app.request(path)
  assert.equal(res.status, 402, `${path} reaches its payment challenge when data is current`)
  assert.ok(res.headers.get('WWW-Authenticate'))
}
// Stale data: refused BEFORE payment, explicitly, unsigned — with or without a payment credential.
ws.setSanctionsSnapshotSource(async () => stored(parsed, fixtureSha, new Date(Date.now() - 7 * hour)))
for (const headers of [{}, { authorization: 'Payment synthetic-must-not-be-processed' }] as Record<string, string>[]) {
  for (const path of [...routes, `/diligence?wallet=${REPORTED}&company=00000006`]) {
    const res = await app.request(path, { headers })
    const body = (await res.json()) as any
    assert.equal(res.status, 503, path)
    assert.equal(body.error, 'sanctions_screening_unavailable', path)
    assert.equal(body.reason, 'stale', path)
    assert.equal(res.headers.get('WWW-Authenticate'), null, `${path} must not issue a payment challenge`)
    assert.equal(body.attestation, undefined)
    assert.doesNotMatch(JSON.stringify(body), /"sanctioned":\s*false|not_listed/)
  }
}
assert.equal((await app.request('/diligence?company=00000006')).status, 402, 'company-only diligence does not need sanctions data')
const unsupported = await app.request(`/screen/${XBT_LISTED}`)
assert.equal(unsupported.status, 400)
assert.equal(((await unsupported.json()) as any).error, 'unsupported_address_format')
assert.equal(unsupported.headers.get('WWW-Authenticate'), null)
const internal = { authorization: `Bearer ${serviceToken}` }
const notReady = await app.request('/internal/verdict/ready', { headers: internal })
assert.equal(notReady.status, 503)
assert.deepEqual(await notReady.json(), { ready: false, error: 'sanctions_screening_unavailable', reason: 'stale' })
const staleHealth = (await (await app.request('/health')).json()) as any
assert.equal(staleHealth.upstreams.ofac_sdn, 'stale')
assert.equal(staleHealth.upstreams.sanctions_oracle, 'retired')
assert.equal(staleHealth.status, 'degraded')

// Fresh again: signed verdicts carry the snapshot provenance and the limits of a non-match.
ws.setSanctionsSnapshotSource(freshSource)
assert.deepEqual(await (await app.request('/internal/verdict/ready', { headers: internal })).json(), { ready: true })
const health = (await (await app.request('/health')).json()) as any
assert.equal(health.upstreams.ofac_sdn, 'current')
assert.equal(health.sanctions_data.source_sha256, fixtureSha)
tempoRows = []
const block = (await (await app.request(`/internal/verdict/${REPORTED}`, { headers: internal })).json()) as any
assert.equal(block.attestation.signed, true)
assert.equal(block.data.verdict, 'BLOCK')
assert.equal(block.data.signals.sanctions.match_status, 'listed')
assert.equal(block.data.signals.sanctions.matches[0].sdn_uid, 24003)
assert.equal(block.data.signals.sanctions.screening.dataset.source_sha256, fixtureSha)
assert.match(block.data.source, /OFAC.*SDN/)
const pass = (await (await app.request(`/internal/verdict/${NON_MATCH}`, { headers: internal })).json()) as any
assert.equal(pass.data.verdict, 'PASS')
assert.equal(pass.data.signals.sanctions.match_status, 'not_listed')
assert.ok(pass.data.signals.sanctions.screening.limitations.some((l: string) => /not legal clearance/.test(l)))
assert.ok(pass.data.verdict_basis.not_yet_evaluated.includes('other_sanctions_regimes'))
assert.match(pass.data.verdict_basis.note, /not legal clearance/)

// Pinning: one snapshot load per paid request; counterparties are screened against that same
// snapshot even if the store fails right after the gate.
let calls = 0
ws.setSanctionsSnapshotSource(async () => {
  if (calls++ > 0) throw new Error('store went away after the gate')
  return stored(parsed, fixtureSha, new Date(Date.now() - hour))
})
tempoRows = [{ sender: NON_MATCH.toLowerCase(), recipient: REPORTED }, { sender: '0x00000000000000000000000000000000000000a1', recipient: NON_MATCH.toLowerCase() }]
const warnRes = await app.request(`/internal/verdict/${NON_MATCH}`, { headers: internal })
const warn = (await warnRes.json()) as any
assert.equal(warnRes.status, 200)
assert.equal(calls, 1, 'the gate loaded once; subject and counterparties used the pinned snapshot')
assert.equal(warn.data.verdict, 'WARN')
assert.deepEqual(warn.data.signals.direct_counterparty_exposure.sanctioned_counterparties, [REPORTED])
assert.equal(warn.data.signals.direct_counterparty_exposure.counterparties_screened, 2)
assert.equal(warn.data.signals.direct_counterparty_exposure.screening_failures, 0)
// Outside a pinned request the same failing store is an error, never a clean result.
await assert.rejects(ws.screenAddress(NON_MATCH), ws.SanctionsUnavailableError)

ws.setSanctionsSnapshotSource(null)
console.log('PASS: OFAC SDN parser/validation/freshness, exact EVM matching, delisting transition, fail-closed store, pre-payment gates, signed provenance, request pinning')
process.exit(0)
