/**
 * test/readinessProbes.ts — pre-payment readiness distinguishes "answered on
 * the network" from "can serve a paid request" (offline; fetch is stubbed).
 *
 * Run: npx tsx test/readinessProbes.ts
 */
import assert from 'node:assert/strict'
import crypto from 'node:crypto'

process.env.COMPANIES_HOUSE_API_KEY = 'fake-key-for-tests'
process.env.MPP_RECIPIENT_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb9226d'
process.env.TEMPO_CURRENCY_ADDRESS = '0x20c0000000000000000000000000000000000000'
process.env.MPP_SECRET_KEY = 'test-mpp-secret-that-is-at-least-32-characters'
process.env.ATTESTATION_SERVICE_TOKEN = 'test-attestation-token-at-least-32-characters'
process.env.ATTESTATION_KEY_ACTIVATED_AT = '2026-01-01T00:00:00.000Z'
process.env.TEMPO_TESTNET = 'true'
process.env.ATTESTATION_PRIVATE_KEY = crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }) as string

let respond: (url: string) => Response | Promise<Response> = () => new Response('{}', { status: 200 })
const probes: string[] = []
globalThis.fetch = (async (input: string | URL | Request) => {
  const url = String(input)
  if (/company-information|data\.sec\.gov/.test(url)) probes.push(url)
  return respond(url)
}) as typeof fetch

const health = await import('../src/health.js')
const status = (code: number) => () => new Response(code === 503 ? '<html>maintenance</html>' : '{}', { status: code })

// 1. Provider-specific status semantics.
const cases: Array<[() => Promise<boolean>, number, boolean]> = [
  [health.companiesHouseHealthy, 200, true],
  [health.companiesHouseHealthy, 404, true],
  [health.companiesHouseHealthy, 401, false],
  [health.companiesHouseHealthy, 403, false],
  [health.companiesHouseHealthy, 429, false],
  [health.companiesHouseHealthy, 500, false],
  [health.companiesHouseHealthy, 503, false],
  [health.edgarHealthy, 200, true],
  [health.edgarHealthy, 403, false],
  [health.edgarHealthy, 404, false],
  [health.edgarHealthy, 429, false],
  [health.edgarHealthy, 503, false],
]
for (const [check, code, expected] of cases) {
  health.__test.reset()
  respond = status(code)
  assert.equal(await check(), expected, `${check.name} with HTTP ${code}`)
}
health.__test.reset()
respond = () => { throw new TypeError('network down') }
assert.equal(await health.companiesHouseHealthy(), false, 'network failure')
console.log('ok  HTTP 401/403/429/5xx are unusable; only provider-specific ready statuses pass')

// 2. A cached unusable result is reused within the TTL: repeated checks do not re-probe.
health.__test.reset()
respond = status(503)
const before = probes.length
for (let i = 0; i < 3; i++) assert.equal(await health.edgarHealthy(), false)
assert.equal(probes.length - before, 1, 'one probe, then the cached result')
console.log('ok  readiness results are cached; repeated checks do not re-probe within the TTL')

// 3. Pre-payment gate: an upstream 503 maintenance page means 503 with no payment challenge.
const { default: app } = await import('../src/server.js')
health.__test.reset()
respond = (url) => /company-information/.test(url) ? status(503)() : new Response('{}', { status: 200 })
for (const path of ['/company/00000006', '/web/company/00000006']) {
  const res = await app.request(path)
  assert.equal(res.status, 503, path)
  assert.equal(res.headers.get('WWW-Authenticate'), null, `${path} must not issue a payment challenge`)
  assert.match(((await res.json()) as any).detail, /No payment was requested/)
}
health.__test.reset()
respond = () => new Response('{}', { status: 200 })
assert.equal((await app.request('/company/00000006')).status, 402, 'usable upstream reaches the payment challenge')
console.log('ok  an upstream 503 is refused before payment; a usable upstream reaches 402')
process.exit(0)
