/**
 * test/sanctionsContainment.ts — incident regression (offline).
 *
 * The Chainalysis oracle is deprecated (last update 2026-03-18). OFAC lists
 * 0x252a8bd2319d8a555b872990601221b3a2053bce, yet the old reader could sign a
 * "not sanctioned" for it. The oracle is never read again, and with NO usable
 * OFAC SDN snapshot (here: no store configured) every wallet-screening route
 * must fail closed, BEFORE any payment is requested, and nothing may be signed.
 * The data-available paths are covered by test/ofacSdnScreening.ts.
 *
 * Run: npx tsx test/sanctionsContainment.ts
 */
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { spawn } from 'node:child_process'

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

const outbound: string[] = []
globalThis.fetch = (async (input: string | URL | Request) => {
  outbound.push(String(input))
  return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } })
}) as typeof fetch

const reported = '0x252a8bd2319d8a555b872990601221b3a2053bce'
const { config } = await import('../src/config.js')
const { screenAddress, SanctionsUnavailableError, InvalidWalletAddressError, SANCTIONS_UNAVAILABLE_CODE } = await import('../src/walletSanctions.js')
const { evaluateVerdict } = await import('../src/verdict.js')
const { default: app } = await import('../src/server.js')

// 1. The reader never returns a finding (positive OR negative) and never reads the oracle.
for (const address of [reported, reported.toUpperCase().replace('0X', '0x'), '0x0000000000000000000000000000000000000001']) {
  await assert.rejects(screenAddress(address), SanctionsUnavailableError)
}
await assert.rejects(screenAddress('bad'), (e: unknown) => e instanceof InvalidWalletAddressError && (e as any).status === 400)
await assert.rejects(evaluateVerdict(reported), SanctionsUnavailableError) // never a PASS/WARN/BLOCK verdict
assert.ok(!outbound.some((u) => u.startsWith(config.sanctionsOracle.rpcUrl)), 'the retired oracle RPC must never be queried')

// 2. Every oracle-dependent HTTP route: 503 + explicit code, BEFORE payment, nothing signed.
const paymentHeaders: Record<string, string>[] = [{}, { authorization: 'Payment synthetic-must-not-be-processed' }]
const routes = [
  `/screen/${reported}`,
  `/verdict/${reported}`,
  `/web/screen/${reported}`,
  `/diligence?wallet=${reported}`,
  `/diligence?wallet=${reported}&company=00000006`,
]
for (const headers of paymentHeaders) {
  for (const path of routes) {
    const response = await app.request(path, { headers })
    const body = (await response.json()) as any
    assert.equal(response.status, 503, path)
    assert.equal(body.error, SANCTIONS_UNAVAILABLE_CODE, path)
    assert.equal(response.headers.get('WWW-Authenticate'), null, `${path} must not issue a payment challenge`)
    assert.equal(body.attestation, undefined, `${path} must not be signed`)
    assert.equal(body.data, undefined)
    assert.doesNotMatch(JSON.stringify(body), /"sanctioned":\s*false/)
  }
}

// 3. Delegated internal verdict and its readiness probe (used by the MCP paid route).
const internal = { authorization: `Bearer ${serviceToken}` }
const delegated = await app.request(`/internal/verdict/${reported}`, { headers: internal })
assert.equal(delegated.status, 503)
assert.equal(((await delegated.json()) as any).error, SANCTIONS_UNAVAILABLE_CODE)
const ready = await app.request('/internal/verdict/ready', { headers: internal })
assert.equal(ready.status, 503)
assert.equal(((await ready.json()) as any).ready, false)

// 4. Malformed input is still a plain 400; unrelated paid routes are not blocked.
assert.equal((await app.request('/screen/not-an-address')).status, 400)
const companyOnly = await app.request('/diligence?company=00000006')
assert.equal(companyOnly.status, 402, 'company-only diligence still reaches its payment challenge')
assert.ok(companyOnly.headers.get('WWW-Authenticate'))
const nameScreen = await app.request('/screen-name?name=Vladimir+Putin')
assert.notEqual(((await nameScreen.json().catch(() => ({}))) as any).error, SANCTIONS_UNAVAILABLE_CODE)

// 5. /health must not call the retired oracle "reachable".
const health = (await (await app.request('/health')).json()) as any
assert.equal(health.upstreams.sanctions_oracle, 'retired')
assert.equal(health.status, 'degraded')

// 6. Legacy stdio MCP: screen_wallet / diligence(wallet) return a tool error before any payment challenge.
const child = spawn(process.execPath, ['--import', 'tsx', 'src/mcp.ts'], { env: process.env, stdio: ['pipe', 'pipe', 'pipe'] })
const replies = new Map<number, any>()
let buffer = ''
child.stdout.on('data', (chunk) => {
  buffer += chunk.toString()
  for (let nl = buffer.indexOf('\n'); nl >= 0; nl = buffer.indexOf('\n')) {
    const line = buffer.slice(0, nl).trim()
    buffer = buffer.slice(nl + 1)
    try { const m = JSON.parse(line); if (m.id !== undefined) replies.set(m.id, m) } catch { /* not JSON-RPC */ }
  }
})
const send = (m: object) => child.stdin.write(JSON.stringify(m) + '\n')
const reply = async (id: number) => {
  for (let i = 0; i < 100 && !replies.has(id); i++) await new Promise((r) => setTimeout(r, 100))
  assert.ok(replies.has(id), `no MCP reply for ${id}`)
  return replies.get(id)
}
try {
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '0' } } })
  await reply(1)
  send({ jsonrpc: '2.0', method: 'notifications/initialized' })
  send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'screen_wallet', arguments: { address: reported } } })
  send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'diligence', arguments: { wallet: reported, company: '00000006' } } })
  for (const id of [2, 3]) {
    const r = await reply(id)
    assert.equal(r.error, undefined, 'must be a tool error, not a payment challenge (-32042)')
    assert.equal(r.result.isError, true)
    assert.match(r.result.content[0].text, /unavailable/i)
    assert.doesNotMatch(JSON.stringify(r), /"sanctioned":\s*false|attestation/)
  }
} finally {
  child.kill()
}

console.log('PASS: oracle never read; with no usable snapshot /screen, /verdict, /web/screen, /diligence?wallet, /internal/verdict, stdio MCP fail closed before payment; unrelated routes unaffected')
process.exit(0)
