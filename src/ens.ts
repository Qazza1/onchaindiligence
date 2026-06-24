/**
 * ens.ts
 * ------
 * Resolves ENS names (e.g. "vitalik.eth") to addresses, so callers can screen
 * a human-readable name instead of a raw 0x address. ENS is public on-chain
 * data on Ethereum mainnet — no API key, no licence.
 *
 * Used by the wallet-screening paths: if the supplied identifier looks like an
 * ENS name, we resolve it first and screen the resolved address, surfacing both
 * in the response so the caller can see exactly what was screened.
 */

import { createPublicClient, http, isAddress, type Address } from 'viem'
import { mainnet } from 'viem/chains'
import { normalize } from 'viem/ens'
import { config } from './config.js'

let client: ReturnType<typeof createPublicClient> | null = null
function ensClient() {
  if (!client) {
    client = createPublicClient({
      chain: mainnet,
      transport: http(config.sanctionsOracle.rpcUrl),
    })
  }
  return client
}

/** True if the string looks like an ENS name rather than a hex address. */
export function looksLikeEns(input: string): boolean {
  return !isAddress(input) && /\.(eth|xyz|com|org|io|app|art)$/i.test(input.trim())
}

export class EnsResolutionError extends Error {
  constructor(public name: string) {
    super(`ENS name "${name}" could not be resolved to an address`)
    this.name = 'EnsResolutionError'
  }
}

/**
 * Resolve an identifier to an address. If it's already a hex address, returns
 * it unchanged with ens=null. If it's an ENS name, resolves it on mainnet and
 * returns both. Throws EnsResolutionError if a name doesn't resolve.
 */
export async function resolveToAddress(
  input: string
): Promise<{ address: string; ens: string | null }> {
  const trimmed = input.trim()
  if (isAddress(trimmed)) {
    return { address: trimmed, ens: null }
  }
  if (!looksLikeEns(trimmed)) {
    // Not an address and not name-shaped — let downstream validation reject it.
    return { address: trimmed, ens: null }
  }
  let resolved: Address | null = null
  try {
    resolved = await ensClient().getEnsAddress({ name: normalize(trimmed) })
  } catch {
    throw new EnsResolutionError(trimmed)
  }
  if (!resolved) throw new EnsResolutionError(trimmed)
  return { address: resolved, ens: trimmed }
}
