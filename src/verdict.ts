/**
 * Canonical PASS / WARN / BLOCK verdict construction.
 *
 * Every transport must call this implementation rather than reimplementing
 * decision rules. The public MPP route and the MCP x402 route therefore return
 * the same evidence for the same underlying checks.
 */

import {
  screenAddress,
  buildAttribution as chainalysisAttribution,
  type SanctionsResult,
} from './chainalysis.js'
import { resolveToAddress } from './ens.js'
import { checkDirectExposure, type ExposureResult } from './exposure.js'

export type Verdict = 'PASS' | 'WARN' | 'BLOCK'

export interface VerdictData extends Record<string, unknown> {
  verdict: Verdict
  reasons: string[]
  address: string
  ens_name?: string
  resolved_address?: string
  signals: {
    sanctions: { checked: true; sanctioned: boolean }
    direct_counterparty_exposure: Record<string, unknown>
  }
  verdict_basis: {
    live_signals: string[]
    not_yet_evaluated: string[]
    note: string
  }
  source: string
  method: string
  note: string
  checked_at: string
}

export interface VerdictInputs {
  address: string
  ens?: string | null
  screen: SanctionsResult
  exposure: ExposureResult
  checkedAt?: string
}

/** Pure verdict builder used by the evaluator and contract tests. */
export function buildVerdictData({
  address,
  ens = null,
  screen,
  exposure,
  checkedAt = new Date().toISOString(),
}: VerdictInputs): VerdictData {
  const exposureHit = exposure.sanctioned_counterparties.length > 0

  let verdict: Verdict
  const reasons: string[] = []

  if (screen.sanctioned === true) {
    verdict = 'BLOCK'
    reasons.push('Address is on the sanctions list (OFAC via Chainalysis on-chain oracle).')
  } else if (exposureHit) {
    // Exposure is a risk signal, not a designation of the subject address.
    verdict = 'WARN'
    const count = exposure.sanctioned_counterparties.length
    reasons.push(
      `Address is not itself sanctioned, but transacted directly with ` +
        `${count} sanctioned address${count === 1 ? '' : 'es'} on Tempo mainnet.`
    )
    reasons.push('This is a counterparty risk signal, not a designation of this address.')
  } else if (exposure.status !== 'complete') {
    verdict = 'WARN'
    reasons.push('No sanctions match found for the subject address.')
    reasons.push(
      exposure.status === 'failed'
        ? 'Direct counterparty exposure could not be evaluated.'
        : `Direct counterparty exposure was incomplete: ` +
            `${exposure.screening_failures} screen failure(s), ` +
            `${exposure.counterparties_omitted} counterparty/counterparties omitted by the safety limit.`
    )
  } else {
    verdict = 'PASS'
    reasons.push('No sanctions match found.')
  }

  const directExposure: Record<string, unknown> = {
    checked: exposure.status !== 'failed',
    complete: exposure.status === 'complete',
    status: exposure.status,
    ...(exposure.status !== 'failed'
      ? {
          transfers_scanned: exposure.transfers_scanned,
          counterparties_found: exposure.counterparties_found,
          counterparties_considered: exposure.counterparties_considered,
          counterparties_screened: exposure.counterparties_screened,
          counterparties_omitted: exposure.counterparties_omitted,
          screening_failures: exposure.screening_failures,
          sanctioned_counterparties: exposure.sanctioned_counterparties,
        }
      : { not_evaluated_reason: exposure.unevaluated_reason }),
    scope: exposure.scope,
  }

  const liveSignals = ['sanctions']
  const notEvaluated = ['risk_score', 'mixer_exposure', 'wallet_age', 'sanctions_proximity']
  if (exposure.status === 'complete') liveSignals.push('direct_counterparty_exposure')
  else notEvaluated.unshift('direct_counterparty_exposure')

  return {
    verdict,
    reasons,
    address,
    ...(ens ? { ens_name: ens, resolved_address: address } : {}),
    signals: {
      sanctions: { checked: true, sanctioned: screen.sanctioned === true },
      direct_counterparty_exposure: directExposure,
    },
    verdict_basis: {
      live_signals: liveSignals,
      not_yet_evaluated: notEvaluated,
      note:
        'BLOCK means the address itself is sanctioned. WARN means it is not ' +
        'sanctioned but transacted directly with an address that is — a ' +
        'counterparty risk signal, not a designation. PASS means neither was ' +
        'found within the scope described in signals.direct_counterparty_exposure.scope; ' +
        'it is not a full risk clearance. Exposure is one-hop, Tempo-mainnet-only, ' +
        'and covers a bounded recent window.',
    },
    ...chainalysisAttribution(),
    checked_at: checkedAt,
  }
}

/** Resolve, evaluate, and build one canonical verdict. */
export async function evaluateVerdict(input: string): Promise<VerdictData> {
  const { address, ens } = await resolveToAddress(input)
  const [screen, exposure] = await Promise.all([
    screenAddress(address),
    checkDirectExposure(address),
  ])
  return buildVerdictData({ address, ens, screen, exposure })
}
