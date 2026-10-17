/**
 * previewGuard.ts — app-level guard for Vercel preview deployments.
 *
 * Production credentials belong to the production environment only; a
 * preview gets nothing or separate, non-production credentials. This module
 * is a fail-closed backstop for a preview that is configured otherwise:
 *
 *   - it never signs an attestation, unless the operator declared a
 *     separate preview signer (OCD_PREVIEW_ISOLATED_SIGNER=true) AND the
 *     loaded key is neither the declared production key nor a historical
 *     production key;
 *   - it never anchors on Tempo mainnet;
 *   - it refuses to boot accepting mainnet MPP payments.
 *
 * It cannot stop code running in a preview from reading its own environment;
 * only removing the values from the preview target does that.
 */
import { HISTORICAL_ATTESTATION_KEYS } from './attestationKeyHistory.js'

const TEMPO_MAINNET_CHAIN_ID = 4217

export function isPreviewDeployment(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.VERCEL_ENV === 'preview'
}

export function previewMaySign(keyId: string | null, env: NodeJS.ProcessEnv = process.env): boolean {
  if (!isPreviewDeployment(env)) return true
  if (env.OCD_PREVIEW_ISOLATED_SIGNER !== 'true' || !keyId) return false
  const productionKeyIds = new Set([env.ATTESTATION_ROTATION_REPLACEMENT_KEY_ID, ...HISTORICAL_ATTESTATION_KEYS.map((k) => k.key_id)].filter(Boolean))
  return !productionKeyIds.has(keyId)
}

export function previewMayAnchor(chainId: number | null, env: NodeJS.ProcessEnv = process.env): boolean {
  return !isPreviewDeployment(env) || (chainId !== null && chainId !== TEMPO_MAINNET_CHAIN_ID)
}

/** Names (never values) of the settings that make this preview unsafe to boot. */
export function previewBootViolations(settings: { tempoTestnet: boolean }, env: NodeJS.ProcessEnv = process.env): string[] {
  if (!isPreviewDeployment(env)) return []
  const violations: string[] = []
  if (!settings.tempoTestnet) violations.push('TEMPO_TESTNET must be "true" in a preview deployment (mainnet MPP payments are production-only)')
  return violations
}
