/**
 * test/ofacNameDataset.ts — OFAC SDN name-screening dataset integrity (offline).
 *
 * Regression for the reported defect: HTTP 200 responses carrying HTML
 * maintenance pages (or other non-list bodies) used to build an EMPTY index
 * and a signable `hit: false, matches: []`. Every response is now validated
 * before it can replace the cached index, and missing/corrupt/stale data is
 * never a negative. Fetch is stubbed; no network, payment or signing call.
 *
 * Run: npx tsx test/ofacNameDataset.ts
 */
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { readFileSync } from 'node:fs'

process.env.COMPANIES_HOUSE_API_KEY = 'fake-key-for-tests'
process.env.MPP_RECIPIENT_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb9226d'
process.env.TEMPO_CURRENCY_ADDRESS = '0x20c0000000000000000000000000000000000000'
process.env.MPP_SECRET_KEY = 'test-mpp-secret-that-is-at-least-32-characters'
process.env.ATTESTATION_SERVICE_TOKEN = 'test-attestation-token-at-least-32-characters'
process.env.ATTESTATION_KEY_ACTIVATED_AT = '2026-01-01T00:00:00.000Z'
process.env.TEMPO_TESTNET = 'true'
process.env.ATTESTATION_PRIVATE_KEY = crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
delete process.env.OFAC_NAME_SCREENING_MAX_STALENESS_HOURS

// --- synthetic but layout-faithful SDN.CSV / ALT.CSV ------------------------
const pad = Array(8).fill('-0-').join(',') // Title .. Remarks
function sdnCsv(count: number): string {
  const rows = ['306,"PUTIN, Vladimir Vladimirovich","individual","RUSSIA-EO14024",' + pad]
  for (let i = 1; i <= count - 1; i++) rows.push(`${1000 + i},"SYNTHETIC ENTITY ${i} LIMITED",-0- ,"SDGT",${pad}`)
  return rows.join('\r\n') + '\r\n\u001a\r\n' // OFAC's legacy EOF marker
}
function altCsv(count: number): string {
  const rows = ['306,1,"aka","POUTINE, Vladimir",-0-']
  for (let i = 1; i <= count - 1; i++) rows.push(`${1000 + i},${i + 1},"aka","SYNTHETIC ALIAS ${i}",-0-`)
  return rows.join('\r\n') + '\r\n'
}
const GOOD = { sdn: sdnCsv(5_200), alt: altCsv(2_400) }
const HTML_MAINTENANCE = '<!DOCTYPE html>\n<html><head><title>Site Maintenance</title></head><body><h1>We will be back shortly</h1></body></html>'

let served: { sdn: string; alt: string; sdnType?: string; altType?: string; status?: number } = { ...GOOD }
let fetches = 0
globalThis.fetch = (async (input: string | URL | Request) => {
  const url = String(input)
  if (/sdn\.csv$/.test(url) || /alt\.csv$/.test(url)) {
    fetches++
    const isSdn = /sdn\.csv$/.test(url)
    return new Response(isSdn ? served.sdn : served.alt, {
      status: served.status ?? 200,
      headers: { 'Content-Type': (isSdn ? served.sdnType : served.altType) ?? 'text/csv' },
    })
  }
  return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } })
}) as typeof fetch

const ofac = await import('../src/ofac.js')

// 0. Divergence tripwire: the same pin lives in the MCP repository's test.
const OFAC_TS_PIN = '9066d4370d92aaf4c3c57764bbda3bf4ee94ebbd502406795a1e6fcb106a1968'
const ofacText = readFileSync(new URL('../src/ofac.ts', import.meta.url), 'utf8').replace(/\r\n/g, '\n')
assert.equal(crypto.createHash('sha256').update(ofacText).digest('hex'), OFAC_TS_PIN, 'src/ofac.ts diverged from the pinned shared copy')

// 1. The reported case: two HTTP 200 HTML maintenance pages never become a negative.
served = { sdn: HTML_MAINTENANCE, alt: HTML_MAINTENANCE, sdnType: 'text/html; charset=utf-8', altType: 'text/html; charset=utf-8' }
ofac.__test.reset()
await assert.rejects(ofac.screenName('Jane Doe'), (e: any) => e instanceof ofac.OfacNameScreeningUnavailableError)
// ... also when the HTML arrives with a non-HTML content type.
served = { sdn: HTML_MAINTENANCE, alt: HTML_MAINTENANCE, sdnType: 'application/octet-stream', altType: 'text/plain' }
ofac.__test.reset()
await assert.rejects(ofac.screenName('Jane Doe'), (e: any) => e instanceof ofac.OfacNameScreeningUnavailableError)
console.log('ok  HTML maintenance pages (any content type) yield "unavailable", never hit:false')

// 2. Validation rejects every non-list shape, with a specific reason.
const rejects = (sdn: string, alt: string, reason: string, previous: any = null) =>
  assert.throws(() => ofac.validateOfacDataset(sdn, alt, previous), (e: any) => e instanceof ofac.OfacDatasetInvalidError && e.reason === reason, reason)
rejects('', GOOD.alt, 'empty_file')
rejects(GOOD.sdn, '\r\n\u001a\r\n', 'empty_file')
rejects(GOOD.sdn, HTML_MAINTENANCE, 'html_response')
rejects(GOOD.sdn.slice(0, GOOD.sdn.indexOf('"SYNTHETIC ENTITY 2600 ') + 12), GOOD.alt, 'malformed_row') // cut mid-quoted field
rejects(GOOD.sdn.slice(0, GOOD.sdn.indexOf('"SYNTHETIC ENTITY 2600 ') - 1), GOOD.alt, 'unexpected_column_count') // cut between fields
rejects(GOOD.sdn.replace('"SDGT",' + pad, '"SDGT"'), GOOD.alt, 'unexpected_column_count') // missing schema fields
rejects('{"error":"rate limited"}\n', GOOD.alt, 'unexpected_column_count')
rejects(sdnCsv(4_000), altCsv(2_400), 'too_few_records') // truncated at a row boundary
rejects(GOOD.sdn, altCsv(1_000), 'too_few_records')
rejects(GOOD.sdn + `1001,"DUPLICATE",-0- ,"SDGT",${pad}\r\n`, GOOD.alt, 'duplicate_record')
rejects(GOOD.sdn, GOOD.alt.replace(/^1(\d{3}),/gm, '9$1,'), 'alias_primary_mismatch') // ALT from another snapshot
rejects(GOOD.sdn, GOOD.alt, 'implausible_reduction', { sdn_records: 7_000, alt_records: 2_400 })
rejects(GOOD.sdn.replace('"individual"', '"spaceship"'), GOOD.alt, 'invalid_record')
const ok = ofac.validateOfacDataset(GOOD.sdn, GOOD.alt, { sdn_records: 5_300, alt_records: 2_450 })
assert.deepEqual(ok.stats, { sdn_records: 5_200, alt_records: 2_400, orphan_aliases: 0 })
console.log('ok  empty, HTML, truncated, malformed, missing-field, duplicate, orphaned and shrunken datasets are rejected')

// 3. A valid dataset screens, and the result carries source identity, digest and freshness.
served = { ...GOOD }
ofac.__test.reset()
const hit = await ofac.screenName('Vladimir Putin')
assert.equal(hit.hit, true)
assert.equal(hit.matches[0]?.ent_num, 306)
const expectedSdnSha = crypto.createHash('sha256').update(GOOD.sdn).digest('hex')
assert.equal(hit.dataset.sdn_sha256, expectedSdnSha)
assert.equal(hit.dataset.sha256, crypto.createHash('sha256').update(expectedSdnSha + crypto.createHash('sha256').update(GOOD.alt).digest('hex')).digest('hex'))
assert.equal(hit.dataset.sdn_records, 5_200)
assert.equal(hit.dataset.freshness, 'current')
assert.equal(hit.dataset.source, 'us-treasury-ofac-sdn-legacy-csv')
const miss = await ofac.screenName('Jane Doe')
assert.equal(miss.hit, false, 'a negative only from a validated dataset')
console.log('ok  validated dataset screens; result names source, digest, record counts and freshness')

// 4. A bad refresh never replaces a good snapshot; the good one serves only within its window.
const before = fetches
ofac.__test.setCachedAt(Date.now() - ofac.__test.REFRESH_AFTER_MS - 1000) // refresh due
served = { sdn: HTML_MAINTENANCE, alt: HTML_MAINTENANCE }
const stale = await ofac.screenName('Vladimir Putin')
assert.equal(fetches, before + 2, 'a refresh was attempted')
assert.equal(stale.dataset.sdn_sha256, expectedSdnSha, 'the previous validated dataset kept serving')
assert.equal(stale.dataset.freshness, 'refresh_overdue')
assert.equal(ofac.ofacNameScreeningStatus().last_refresh_failure, 'dataset_rejected:html_response')
await ofac.screenName('Vladimir Putin')
assert.equal(fetches, before + 2, 'failed refreshes are rate-limited, not retried on every request')
ofac.__test.setCachedAt(Date.now() - ofac.maxDatasetAgeMs() - 1000) // beyond the freshness window
await assert.rejects(ofac.screenName('Jane Doe'), (e: any) => e instanceof ofac.OfacNameScreeningUnavailableError)
assert.equal(ofac.ofacNameScreeningStatus().state, 'expired')
console.log('ok  rejected refresh keeps the validated snapshot only within its window, then fails closed')

// 5. A pinned snapshot that has aged out is refused even if a caller passes it in.
served = { ...GOOD }
ofac.__test.reset()
const pinned = await ofac.loadSdnIndex()
await assert.rejects(ofac.screenName('Jane Doe', 0.85, { ...pinned, fetchedAt: Date.now() - ofac.maxDatasetAgeMs() - 1 }), ofac.OfacNameScreeningUnavailableError)
await assert.rejects(ofac.screenName('Jane Doe', 0.85, { ...pinned, index: [] }), ofac.OfacNameScreeningUnavailableError)
console.log('ok  an empty or expired pinned snapshot can never produce a result')

// 6. Paid routes: unavailable data is refused BEFORE payment (no 402 challenge, nothing signed).
const { default: app } = await import('../src/server.js')
served = { sdn: HTML_MAINTENANCE, alt: HTML_MAINTENANCE }
ofac.__test.reset()
for (const path of ['/screen-name?name=Jane+Doe', '/web/screen-name?name=Jane+Doe']) {
  for (const headers of [{}, { authorization: 'Payment synthetic-must-not-be-processed' }] as Record<string, string>[]) {
    const res = await app.request(path, { headers })
    const body = (await res.json()) as any
    assert.equal(res.status, 503, path)
    assert.equal(body.error, 'ofac_name_screening_unavailable', path)
    assert.equal(res.headers.get('WWW-Authenticate'), null, `${path} must not issue a payment challenge`)
    assert.equal(body.attestation, undefined)
    assert.equal(body.hit, undefined)
  }
}
served = { ...GOOD }
ofac.__test.reset()
for (const path of ['/screen-name?name=Jane+Doe', '/web/screen-name?name=Jane+Doe']) {
  const res = await app.request(path)
  assert.equal(res.status, 402, `${path} reaches its payment challenge when the dataset is validated`)
}
console.log('ok  /screen-name and /web/screen-name refuse unavailable data before payment; validated data reaches 402')
process.exit(0)
