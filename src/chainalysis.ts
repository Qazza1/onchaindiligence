/**
 * chainalysis.ts
 * --------------
 * INCIDENT CONTAINMENT. The Chainalysis on-chain sanctions oracle this module
 * used to read is deprecated and unmaintained (last update 2026-03-18). A
 * successful `isSanctioned()` read is NOT evidence of current sanctions
 * coverage: an address OFAC lists today can still return `false`, and a signed
 * "not sanctioned" built on that boolean is misleading.
 * https://go.chainalysis.com/chainalysis-oracle-docs.html
 *
 * So no address is screened here any more. Every valid address yields an
 * explicit "unavailable" error and NO oracle read is issued; there is no flag
 * to re-enable it. A maintained data source is a separate piece of work.
 * Malformed-address validation is preserved (400, not an outage).
 */
import { getAddress } from 'viem'

export interface SanctionsIdentification {
  category: string
  name: string
  description: string
  url?: string
}

export interface SanctionsResult {
  address: string
  sanctioned: boolean
  identifications: SanctionsIdentification[]
}

// Retained so existing callers/tests keep compiling; no oracle reads are issued.
export class ChainalysisRateLimitError extends Error {
  constructor() {
    super('Sanctions oracle RPC rate limit hit')
    this.name = 'ChainalysisRateLimitError'
  }
}

export class ChainalysisUpstreamError extends Error {
  constructor(public status: number) {
    super(`Sanctions oracle read failed (status ${status})`)
    this.name = 'ChainalysisUpstreamError'
  }
}

export const SANCTIONS_UNAVAILABLE_CODE = 'sanctions_screening_unavailable'

export const SANCTIONS_UNAVAILABLE_MESSAGE =
  'Wallet sanctions screening is unavailable: the Chainalysis oracle is deprecated ' +
  'and unmaintained (last update 2026-03-18). No current sanctions finding was made. ' +
  'An unchecked address must not be treated as not sanctioned.'

export class SanctionsUnavailableError extends ChainalysisUpstreamError {
  readonly code = SANCTIONS_UNAVAILABLE_CODE
  constructor() {
    super(503)
    this.name = 'SanctionsUnavailableError'
    this.message = SANCTIONS_UNAVAILABLE_MESSAGE
  }
}

/** MCP tool error result, returned BEFORE any payment is requested or taken. */
export function sanctionsUnavailableToolResult() {
  return { content: [{ type: 'text' as const, text: SANCTIONS_UNAVAILABLE_MESSAGE }], isError: true as const }
}

/** Preserves input errors, but never returns a positive OR a negative finding. */
export async function screenAddress(address: string): Promise<SanctionsResult> {
  try {
    getAddress(address)
  } catch {
    // 400-class: bad address. Distinct from an outage.
    const err = new ChainalysisUpstreamError(400)
    err.message = `"${address}" is not a valid EVM address`
    throw err
  }
  throw new SanctionsUnavailableError()
}

/** Historical source attribution only; this is not a current coverage claim. */
export function buildAttribution() {
  return {
    source: 'Chainalysis on-chain sanctions oracle (deprecated)',
    method: 'Unavailable; no oracle lookup performed',
    note: SANCTIONS_UNAVAILABLE_MESSAGE,
  }
}
