/**
 * Regression for OD-034: a malformed /anchor request must be rejected before
 * payment and must not leave the Node/Vercel request stream unresolved.
 */
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer, request } from 'node:http'
import { once } from 'node:events'

process.env.COMPANIES_HOUSE_API_KEY = 'test-companies-house-key'
process.env.MPP_RECIPIENT_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb9226d'
process.env.TEMPO_CURRENCY_ADDRESS = '0x20c0000000000000000000000000000000000000'
process.env.MPP_SECRET_KEY = 'test-mpp-secret-that-is-at-least-32-characters'
process.env.ATTESTATION_SERVICE_TOKEN = 'test-attestation-token-at-least-32-characters'
process.env.ATTESTATION_KEY_ACTIVATED_AT = '2026-01-01T00:00:00.000Z'
const { privateKey } = generateKeyPairSync('ed25519')
process.env.ATTESTATION_PRIVATE_KEY = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
process.env.TEMPO_TESTNET = 'true'
process.env.ANCHOR_RPC_URL = 'http://127.0.0.1:18546'
process.env.ANCHOR_CHAIN_ID = '42431'
process.env.ANCHOR_CONTRACT_ADDRESS = '0x1111111111111111111111111111111111111111'
process.env.ANCHOR_PRIVATE_KEY = `0x${'11'.repeat(32)}`

const serverSource = readFileSync(new URL('../src/server.ts', import.meta.url), 'utf8')
assert.doesNotMatch(serverSource, /c\.req\.raw\.clone\(\)\.text\(\)/)
assert.match(serverSource, /const rawBody = await c\.req\.text\(\)/)

const { getRequestListener } = await import('@hono/node-server')
const { default: app } = await import('../src/server.js')

const server = createServer(getRequestListener(app.fetch))
server.listen(0, '127.0.0.1')
await once(server, 'listening')

try {
  const address = server.address()
  assert.ok(address && typeof address !== 'string')

  const response = await new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port: address.port,
        path: '/anchor',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': '2' },
      },
      (res) => {
        let body = ''
        res.setEncoding('utf8')
        res.on('data', (chunk) => {
          body += chunk
        })
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }))
      }
    )
    req.setTimeout(1_000, () => req.destroy(new Error('OD-034: malformed /anchor request did not finish')))
    req.once('error', reject)
    req.end('{}')
  })

  assert.equal(response.status, 400)
  assert.match(response.body, /complete signed attestation envelope/)
  console.log('OD-034 anchor bounded-request regression passed')
} finally {
  server.close()
  await once(server, 'close')
}
