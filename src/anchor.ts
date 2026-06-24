/**
 * anchor.ts
 * ---------
 * Optional on-chain anchoring of attestations to the Tempo AttestationRegistry
 * contract. Turns "the server signed this" into independent, timestamped,
 * tamper-evident proof on a public chain.
 *
 * DESIGN: decoupled and best-effort.
 * Anchoring is deliberately NOT in the hot path of a paid check. A check
 * returns its signed attestation immediately, exactly as before. Anchoring is
 * a separate, opt-in action (an explicit endpoint, or a batch job) so that:
 *   - a slow or failing chain write never delays or fails a paid response, and
 *   - you only pay Tempo gas (pathUSD) when you actually want a permanent record.
 *
 * WHAT WE ANCHOR: keccak256 of the attestation's Ed25519 signature. The
 * signature is already a unique fingerprint of the exact signed response, so
 * its hash is a compact, privacy-preserving anchor — no wallet, name, company,
 * or result ever touches the chain. A holder of the attestation can recompute
 * keccak256(signature) and check it on-chain.
 *
 * Tempo specifics: uses viem (the recommended Tempo client). Tempo has no
 * native gas token — the anchoring wallet pays gas in pathUSD — and contract
 * writes are comparatively expensive, which is another reason anchoring is
 * opt-in / batchable rather than per-call.
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  keccak256,
  getContract,
  type Hex,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { config } from './config.js'

// Minimal ABI — just what we call.
const REGISTRY_ABI = [
  {
    type: 'function',
    name: 'anchor',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'attestationHash', type: 'bytes32' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'anchorBatch',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'hashes', type: 'bytes32[]' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'isAnchored',
    stateMutability: 'view',
    inputs: [{ name: 'attestationHash', type: 'bytes32' }],
    outputs: [{ type: 'bool' }],
  },
  {
    type: 'function',
    name: 'anchoredAt',
    stateMutability: 'view',
    inputs: [{ name: '', type: 'bytes32' }],
    outputs: [{ type: 'uint64' }],
  },
] as const

const tempoChain = {
  id: config.anchor.chainId,
  name: 'Tempo',
  nativeCurrency: { name: 'pathUSD', symbol: 'USD', decimals: 6 },
  rpcUrls: { default: { http: [config.anchor.rpcUrl] } },
} as const

export function anchoringEnabled(): boolean {
  return Boolean(
    config.anchor.contractAddress &&
      config.anchor.privateKey &&
      config.anchor.rpcUrl
  )
}

/** The on-chain anchor hash for an attestation signature (keccak256 of it). */
export function anchorHashForSignature(signatureBase64url: string): Hex {
  const sigHex = ('0x' + Buffer.from(signatureBase64url, 'base64url').toString('hex')) as Hex
  return keccak256(sigHex)
}

function publicClient() {
  return createPublicClient({ chain: tempoChain, transport: http(config.anchor.rpcUrl) })
}
function walletClient() {
  const account = privateKeyToAccount(config.anchor.privateKey as Hex)
  return createWalletClient({ account, chain: tempoChain, transport: http(config.anchor.rpcUrl) })
}

/**
 * Anchor a single attestation signature on-chain. Returns the tx hash and the
 * anchor hash. Throws if anchoring isn't configured or the write fails — the
 * CALLER decides whether that's fatal (for the /anchor endpoint it's a 503;
 * it never affects a normal paid check, which doesn't call this).
 */
export async function anchorSignature(
  signatureBase64url: string
): Promise<{ anchorHash: Hex; txHash: Hex; alreadyAnchored: boolean }> {
  if (!anchoringEnabled()) {
    throw new Error('On-chain anchoring is not configured on this deployment')
  }
  const anchorHash = anchorHashForSignature(signatureBase64url)

  const reader = getContract({
    address: config.anchor.contractAddress as Hex,
    abi: REGISTRY_ABI,
    client: publicClient(),
  })

  // Idempotent: if already anchored, don't pay gas to do it again.
  const already = await reader.read.isAnchored([anchorHash])
  if (already) {
    return { anchorHash, txHash: '0x' as Hex, alreadyAnchored: true }
  }

  const wallet = walletClient()
  const txHash = await wallet.writeContract({
    address: config.anchor.contractAddress as Hex,
    abi: REGISTRY_ABI,
    functionName: 'anchor',
    args: [anchorHash],
  })
  return { anchorHash, txHash, alreadyAnchored: false }
}

/** Check whether a given attestation signature has been anchored on-chain. */
export async function isSignatureAnchored(
  signatureBase64url: string
): Promise<{ anchorHash: Hex; anchored: boolean; anchoredAt: number | null }> {
  if (!config.anchor.contractAddress || !config.anchor.rpcUrl) {
    throw new Error('On-chain anchoring is not configured on this deployment')
  }
  const anchorHash = anchorHashForSignature(signatureBase64url)
  const reader = getContract({
    address: config.anchor.contractAddress as Hex,
    abi: REGISTRY_ABI,
    client: publicClient(),
  })
  const ts = await reader.read.anchoredAt([anchorHash])
  const tsNum = Number(ts)
  return {
    anchorHash,
    anchored: tsNum > 0,
    anchoredAt: tsNum > 0 ? tsNum : null,
  }
}
