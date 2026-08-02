/**
 * test/exposure.ts — direct counterparty exposure.
 *
 * Run: npx tsx test/exposure.ts
 *
 * The Tempo lookup is stubbed for the detection cases (Tempo mainnet currently
 * has no sanctioned activity, so the WARN path is not reachable with live data
 * — that is a fact about the chain, not a reason to leave the path untested).
 * The sanctions ORACLE call is always real, so what's under test is the actual
 * detection path, not a mock of it.
 */

import 'dotenv/config'
import { checkDirectExposure } from '../src/exposure.js'

let pass = 0
let fail = 0
const check = (name: string, ok: boolean, extra = '') => {
  if (ok) {
    pass++
    console.log(`  PASS  ${name}`)
  } else {
    fail++
    console.log(`  FAIL  ${name}  ${extra}`)
  }
}

const realFetch = globalThis.fetch

/** Intercept ONLY api.tempo.xyz; let oracle traffic hit the real network. */
function stubTempo(handler: () => Response | Promise<Response>) {
  globalThis.fetch = (async (input: any, init?: any) => {
    const url = typeof input === 'string' ? input : input?.url ?? ''
    if (String(url).includes('api.tempo.xyz')) return handler()
    return realFetch(input, init)
  }) as typeof fetch
}
const restore = () => {
  globalThis.fetch = realFetch
}

const SUBJECT = '0x66fa4d79ca84016b42352be33c908dd812952ec8'
const SANCTIONED = '0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c' // still OFAC-designated
const CLEAN = '0xd8da6bf26964af9d7eed9e03e53415d37aa96045' // vitalik.eth

const transfersPayload = (rows: Array<{ sender: string; recipient: string }>) =>
  new Response(JSON.stringify({ data: rows, nextCursor: null }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })

async function main() {
  console.log('\n1. LIVE: real Tempo address resolves counterparties')
  const live = await checkDirectExposure(SUBJECT)
  console.log(
    `   evaluated=${live.evaluated} transfers=${live.transfers_scanned} ` +
      `found=${live.counterparties_found} screened=${live.counterparties_screened} ` +
      `sanctioned=${live.sanctioned_counterparties.length}`
  )
  check('evaluated against live data', live.evaluated === true)
  check('found counterparties', live.counterparties_found > 0)
  check('screened a bounded set (<=25)', live.counterparties_screened <= 25)
  check('scope note present', live.scope.includes('one-hop'))
  check('scope discloses Tempo-only', live.scope.includes('Tempo mainnet only'))

  console.log('\n2. DETECTION: a sanctioned counterparty produces a hit (real oracle)')
  stubTempo(() =>
    transfersPayload([
      { sender: SUBJECT, recipient: CLEAN },
      { sender: SANCTIONED, recipient: SUBJECT },
      { sender: SUBJECT, recipient: CLEAN },
    ])
  )
  const hit = await checkDirectExposure(SUBJECT)
  restore()
  console.log(`   sanctioned_counterparties=${JSON.stringify(hit.sanctioned_counterparties)}`)
  check('evaluated', hit.evaluated === true)
  check('flags the sanctioned counterparty', hit.sanctioned_counterparties.includes(SANCTIONED))
  check('does not flag the clean one', !hit.sanctioned_counterparties.includes(CLEAN))
  check('counted both counterparties', hit.counterparties_found === 2, String(hit.counterparties_found))
  check('screened both', hit.counterparties_screened === 2, String(hit.counterparties_screened))

  console.log('\n3. CLEAN: no sanctioned counterparty -> no hit')
  stubTempo(() => transfersPayload([{ sender: SUBJECT, recipient: CLEAN }]))
  const clean = await checkDirectExposure(SUBJECT)
  restore()
  check('evaluated', clean.evaluated === true)
  check('no false positive', clean.sanctioned_counterparties.length === 0)

  console.log('\n4. FAILURE: upstream down -> evaluated:false, never throws, never "clean"')
  stubTempo(() => new Response('upstream exploded', { status: 503 }))
  let threw: unknown = null
  let down: Awaited<ReturnType<typeof checkDirectExposure>> | null = null
  try {
    down = await checkDirectExposure(SUBJECT)
  } catch (e) {
    threw = e
  }
  restore()
  check('did not throw', threw === null)
  check('evaluated === false', down?.evaluated === false)
  check('reason given', Boolean(down?.unevaluated_reason), String(down?.unevaluated_reason))
  check('no sanctioned list implying a clean check', down?.sanctioned_counterparties.length === 0)
  check(
    'counterparties_screened is 0 (nothing was verified)',
    down?.counterparties_screened === 0
  )

  console.log('\n5. Self-reference is excluded')
  stubTempo(() => transfersPayload([{ sender: SUBJECT, recipient: SUBJECT }]))
  const self = await checkDirectExposure(SUBJECT)
  restore()
  check('subject is not its own counterparty', self.counterparties_found === 0)

  console.log(`\n${pass} passed, ${fail} failed\n`)
  process.exit(fail ? 1 : 0)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
