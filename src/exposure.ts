/**
 * exposure.ts
 * -----------
 * Direct counterparty exposure: "has this address transacted directly with a
 * currently-sanctioned address?"
 *
 * This is the first signal beyond the subject's own sanctions status, and it
 * powers the only honest WARN trigger /verdict has. It is deliberately narrow:
 *
 *   - ONE HOP ONLY. We look at addresses this wallet transacted with directly.
 *     We do not follow chains of counterparties. "Sanctions proximity" (N hops)
 *     is a different, much stronger claim and is NOT what this measures.
 *   - TEMPO MAINNET ONLY. Counterparties come from Tempo's transfer index. An
 *     address active on Ethereum, Base, or anywhere else will show no Tempo
 *     counterparties here. Zero exposure on Tempo is NOT zero exposure.
 *   - A BOUNDED RECENT WINDOW. Tempo's free endpoint returns at most 200 rows
 *     per page, newest first, with no time filter. We scan one page. A wallet
 *     with a long history is only partially covered.
 *
 * Every one of those limits is reported in the result and surfaced in the
 * verdict response, because a caller who reads "no exposure found" as "clean"
 * would be over-trusting this signal — exactly the failure mode this product
 * exists to avoid.
 *
 * Data source: Tempo's public REST API — free, keyless, no payment.
 */

import { screenAddress } from './chainalysis.js'

const TEMPO_API = 'https://api.tempo.xyz/v1'
const CHAIN_ID = 4217 // Tempo mainnet

// Tempo's API 403s requests without a User-Agent.
const USER_AGENT = 'OnchainDiligence/1.0 (support@onchaindiligence.com)'

// Optional. `/v1/transfers` is public, but an API key raises throughput. Never
// required: without it this module behaves identically, just on anonymous limits.
const TEMPO_API_KEY = process.env.TEMPO_API_KEY || ''

const PAGE_SIZE = 200 // hard maximum the endpoint accepts
const MAX_COUNTERPARTIES_TO_SCREEN = 25 // bounds oracle reads per verdict
const SCREEN_CONCURRENCY = 8

export interface ExposureResult {
  /** True only when every discovered counterparty in the supported window was screened. */
  evaluated: boolean
  status: 'complete' | 'partial' | 'failed'
  transfers_scanned: number
  counterparties_found: number
  counterparties_considered: number
  counterparties_screened: number
  counterparties_omitted: number
  screening_failures: number
  /** Counterparties the oracle currently designates as sanctioned. */
  sanctioned_counterparties: string[]
  /** Present only when evaluated === false. */
  unevaluated_reason?: string
  scope: string
}

const SCOPE_NOTE =
  'Direct (one-hop) counterparties observed on Tempo mainnet only, from the ' +
  'most recent transfers available (single page, newest first). This is not a ' +
  'multi-hop proximity score, and it does not cover activity on other chains ' +
  'or older history. No sanctioned counterparty found does not mean none exists.'

/** One page of transfers involving `address`. Throws on upstream failure. */
async function fetchRecentCounterparties(
  address: string
): Promise<{ counterparties: string[]; transfersScanned: number }> {
  const url =
    `${TEMPO_API}/transfers?chainId=${CHAIN_ID}` +
    `&limit=${PAGE_SIZE}&address=${address.toLowerCase()}`

  const headers: Record<string, string> = {
    'User-Agent': USER_AGENT,
    Accept: 'application/json',
  }
  if (TEMPO_API_KEY) headers.Authorization = `Bearer ${TEMPO_API_KEY}`

  const res = await fetch(url, { headers })
  if (!res.ok) {
    throw new Error(`Tempo transfer lookup failed (status ${res.status})`)
  }
  const json = (await res.json()) as { data?: Array<Record<string, unknown>> }
  const rows = Array.isArray(json.data) ? json.data : []

  const subject = address.toLowerCase()
  const set = new Set<string>()
  for (const row of rows) {
    const sender = String(row.sender ?? '').toLowerCase()
    const recipient = String(row.recipient ?? '').toLowerCase()
    let other: string | null = null
    if (sender === subject) other = recipient
    else if (recipient === subject) other = sender
    if (other && /^0x[0-9a-f]{40}$/.test(other) && other !== subject) set.add(other)
  }
  return { counterparties: [...set], transfersScanned: rows.length }
}

/**
 * Screen a bounded set of counterparties with bounded concurrency.
 *
 * A counterparty whose screen throws is counted as NOT screened rather than as
 * clean — the returned `screened` count is what we actually verified, so the
 * caller can never mistake an unchecked address for a cleared one.
 */
async function screenCounterparties(
  addresses: string[]
): Promise<{ sanctioned: string[]; screened: number }> {
  const sanctioned: string[] = []
  let screened = 0

  let next = 0
  const worker = async (): Promise<void> => {
    for (let i = next++; i < addresses.length; i = next++) {
      try {
        const result = await screenAddress(addresses[i])
        screened++
        if (result.sanctioned) sanctioned.push(addresses[i])
      } catch {
        // Not screened. Deliberately not counted as clean.
      }
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(SCREEN_CONCURRENCY, addresses.length) }, () => worker())
  )

  return { sanctioned, screened }
}

/**
 * Check direct counterparty exposure for `address`.
 *
 * Never throws: exposure enriches a verdict whose primary signal is the
 * subject's own sanctions status, and an enrichment outage must not fail a
 * request the caller already paid for. On failure it returns
 * `evaluated: false` with a reason, and the verdict discloses that the signal
 * was not evaluated rather than implying it came back clean.
 */
export async function checkDirectExposure(address: string): Promise<ExposureResult> {
  const base = {
    transfers_scanned: 0,
    counterparties_found: 0,
    counterparties_considered: 0,
    counterparties_screened: 0,
    counterparties_omitted: 0,
    screening_failures: 0,
    sanctioned_counterparties: [] as string[],
    scope: SCOPE_NOTE,
  }

  let counterparties: string[]
  let transfersScanned: number
  try {
    const found = await fetchRecentCounterparties(address)
    counterparties = found.counterparties
    transfersScanned = found.transfersScanned
  } catch (err) {
    return {
      ...base,
      evaluated: false,
      status: 'failed' as const,
      unevaluated_reason:
        err instanceof Error ? err.message : 'counterparty lookup failed',
    }
  }

  const toScreen = counterparties.slice(0, MAX_COUNTERPARTIES_TO_SCREEN)
  const { sanctioned, screened } = await screenCounterparties(toScreen)
  const omitted = Math.max(0, counterparties.length - toScreen.length)
  const screeningFailures = Math.max(0, toScreen.length - screened)
  const complete = omitted === 0 && screeningFailures === 0

  return {
    evaluated: complete,
    status: complete ? 'complete' : 'partial',
    transfers_scanned: transfersScanned,
    counterparties_found: counterparties.length,
    counterparties_considered: toScreen.length,
    counterparties_screened: screened,
    counterparties_omitted: omitted,
    screening_failures: screeningFailures,
    sanctioned_counterparties: sanctioned,
    scope: SCOPE_NOTE,
  }
}
