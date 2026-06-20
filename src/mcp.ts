/**
 * mcp.ts — Model Context Protocol (MCP) server entrypoint.
 * --------------------------------------------------------
 * Exposes the same compliance checks as MCP TOOLS, so agent frameworks
 * (Claude Desktop, IDE agents, custom MCP clients) can DISCOVER and call
 * them automatically — without a developer hand-writing HTTP calls.
 *
 * HOW THIS RELATES TO THE HTTP API (important — they're complementary):
 *   - MCP is the discovery/invocation layer: it tells an agent "here are
 *     the tools, here are their parameters."
 *   - MPP is the payment layer: it still charges the agent per call, using
 *     the SAME 402 challenge-response, just carried over MCP's JSON-RPC
 *     metadata instead of HTTP headers.
 *   So this is NOT a second product — it's a second front door to the same
 *   paid checks. An agent that speaks MCP discovers the tool here; payment
 *   still flows through MPP/Tempo exactly as in the HTTP API.
 *
 * Transport: this runs over STDIO, the standard transport agent frameworks
 * use for local MCP servers. (MCP also supports streamable-HTTP; that's a
 * larger wiring job and is noted as a follow-up in the README.)
 *
 * The actual lookups reuse chainalysis.ts / companiesHouse.ts unchanged, so
 * there's a single source of truth for the check logic and its attestation.
 *
 * Run:  npm run mcp      (after building / with tsx)
 */

import 'dotenv/config'
import { z } from 'zod'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { Mppx, tempo, Transport } from 'mppx/server'
import { config, assertConfigured } from './config.js'
import { screenAddress, buildAttribution as chainalysisAttribution } from './chainalysis.js'
import { checkCompany, buildAttribution as companiesHouseAttribution } from './companiesHouse.js'
import { attest } from './attestation.js'
import { logPaymentSuccess, logPaymentFailed } from './paymentLog.js'

assertConfigured()

// Payment handler wired to MCP's transport (challenges become MCP errors
// with code -32042; receipts ride back in result metadata).
const payment = Mppx.create({
  secretKey: process.env.MPP_SECRET_KEY,
  methods: [
    tempo.charge({
      currency: config.tempo.currencyAddress,
      recipient: config.tempo.recipient,
      testnet: config.tempo.testnet,
    }),
  ],
  transport: Transport.mcpSdk(),
})

payment.onPaymentSuccess(({ receipt }) => logPaymentSuccess(receipt))
payment.onPaymentFailed(({ error }) => logPaymentFailed(error?.message ?? 'unknown payment failure'))

const server = new McpServer({
  name: config.service.title,
  version: config.service.version,
})

// Helper: shape a successful lookup into an MCP tool result (text content),
// attested exactly like the HTTP API, with the payment receipt attached.
function toolResult(charge: { withReceipt: (r: unknown) => unknown }, payload: Record<string, unknown>) {
  return charge.withReceipt({
    content: [{ type: 'text', text: JSON.stringify(attest(payload)) }],
  })
}

// --- Tool 1: sanctions screening ----------------------------------------
server.registerTool(
  'screen_wallet',
  {
    title: 'Screen a crypto wallet for sanctions',
    description:
      'Checks whether a crypto wallet address appears on a sanctions list ' +
      '(via Chainalysis free sanctions data). Returns a signed attestation. ' +
      'Charges a small stablecoin fee per call via MPP on Tempo.',
    inputSchema: { address: z.string().min(10).describe('The crypto wallet address to screen') },
  },
  async (args, extra) => {
    const charge = (await payment.tempo.charge({ amount: config.pricing.sanctionsCheck })(extra)) as any
    if (charge.status === 402) throw charge.challenge
    const result = await screenAddress(args.address)
    return toolResult(charge, {
      ...result,
      ...chainalysisAttribution(),
      checked_at: new Date().toISOString(),
    }) as any
  }
)

// --- Tool 2: UK company verification ------------------------------------
server.registerTool(
  'verify_uk_company',
  {
    title: 'Verify a UK company',
    description:
      'Looks up a UK company by its company number and returns status plus ' +
      'people-with-significant-control (PSC) data (via Companies House open ' +
      'data). Returns a signed attestation. Charges a small stablecoin fee ' +
      'per call via MPP on Tempo.',
    inputSchema: { companyNumber: z.string().min(1).describe('The UK Companies House company number') },
  },
  async (args, extra) => {
    const charge = (await payment.tempo.charge({ amount: config.pricing.companyCheck })(extra)) as any
    if (charge.status === 402) throw charge.challenge
    const result = await checkCompany(args.companyNumber)
    return toolResult(charge, {
      ...result,
      ...companiesHouseAttribution(),
      checked_at: new Date().toISOString(),
    }) as any
  }
)

// --- Tool 3: combined diligence -----------------------------------------
server.registerTool(
  'diligence',
  {
    title: 'Combined sanctions + UK company diligence',
    description:
      'Runs a sanctions check on a wallet and/or a UK company verification, ' +
      'whichever is provided. NOTE: these are independent checks — a clean ' +
      'result does NOT establish that the wallet belongs to the company. ' +
      'Returns a signed attestation. Charges a small stablecoin fee per call.',
    inputSchema: {
      wallet: z.string().optional().describe('Crypto wallet address to screen (optional)'),
      company: z.string().optional().describe('UK company number to verify (optional)'),
    },
  },
  async (args, extra) => {
    if (!args.wallet && !args.company) {
      // No payment taken — this is a usage error, surfaced before charging.
      return {
        content: [
          { type: 'text', text: 'Error: provide at least one of "wallet" or "company".' },
        ],
        isError: true,
      } as any
    }

    const charge = (await payment.tempo.charge({ amount: config.pricing.combinedDiligence })(extra)) as any
    if (charge.status === 402) throw charge.challenge

    const response: Record<string, unknown> = { checked_at: new Date().toISOString() }

    const [walletOutcome, companyOutcome] = await Promise.all([
      args.wallet ? safe(() => screenAddress(args.wallet!)) : Promise.resolve(null),
      args.company ? safe(() => checkCompany(args.company!)) : Promise.resolve(null),
    ])

    if (walletOutcome) {
      response.wallet_check = walletOutcome.ok
        ? { ...walletOutcome.value, ...chainalysisAttribution() }
        : { error: walletOutcome.error }
    }
    if (companyOutcome) {
      response.company_check = companyOutcome.ok
        ? { ...companyOutcome.value, ...companiesHouseAttribution() }
        : { error: companyOutcome.error }
    }
    response.link_disclaimer =
      'These are independent checks against separate data sources. No verified ' +
      'link between the wallet address and the company is established by this data.'

    return toolResult(charge, response) as any
  }
)

async function safe<T>(fn: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: string }> {
  try {
    return { ok: true, value: await fn() }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'lookup failed' }
  }
}

const transport = new StdioServerTransport()
await server.connect(transport)
// Note: over stdio, the server communicates on stdin/stdout — do not write
// arbitrary console output to stdout here, it would corrupt the JSON-RPC
// stream. Payment logs go to stderr-safe console.log in paymentLog (Vercel
// captures stdout/stderr separately; for stdio MCP, prefer a file/stderr
// sink if you see stream issues).
