/**
 * attestation.ts
 * --------------
 * Turns each API response into a cryptographically verifiable ATTESTATION.
 *
 * WHY THIS EXISTS (the compliance point):
 * In compliance, an unverifiable check is close to worthless — the entire
 * purpose is producing defensible evidence for an auditor later. A plain
 * JSON response could be fabricated after the fact. By signing every
 * response with a dedicated key plus a strict timestamp, the caller gets
 * proof they can store and later show an auditor: "nanoscreen attested
 * that this wallet was clean at this exact moment, and here is the
 * signature." Anyone can verify it against our published public key
 * without contacting us.
 *
 * Crypto choice: Ed25519 via Node's built-in `crypto`. Fast, tiny (64-byte)
 * signatures, no extra dependency, widely supported for verification.
 *
 * What we sign: the EXACT bytes of the canonical JSON we return, plus an
 * issued-at timestamp and a key id. The signature covers the response body
 * verbatim, so any tampering invalidates it.
 *
 * KEY MANAGEMENT (important):
 *   - The private key lives ONLY in the ATTESTATION_PRIVATE_KEY env var
 *     (PEM, PKCS8). Generate it once, store it in your hosting platform's
 *     secrets manager, never commit it.
 *   - The matching public key is served at /.well-known/attestation-key so
 *     verifiers can fetch it. Publishing the public key is safe and is the
 *     whole point.
 *   - If the env var is absent, attestation is DISABLED gracefully:
 *     responses are returned unsigned with a clear flag, rather than the
 *     server refusing to boot. This keeps the service usable while you set
 *     the key up, but you should set it for production.
 *
 * Generate a keypair (run locally, once):
 *   node -e "const c=require('crypto');const {publicKey,privateKey}=c.generateKeyPairSync('ed25519');console.log('PRIVATE (set as ATTESTATION_PRIVATE_KEY, keep secret):\\n'+privateKey.export({type:'pkcs8',format:'pem'}));console.log('PUBLIC (informational):\\n'+publicKey.export({type:'spki',format:'pem'}))"
 */

import { createPrivateKey, createPublicKey, createHash, sign as cryptoSign, type KeyObject } from 'node:crypto'

let privateKey: KeyObject | null = null
let publicKeyPem: string | null = null
let keyId: string | null = null

/**
 * Loads (or reloads) the signing key from the ATTESTATION_PRIVATE_KEY env
 * var. Called once at module load below. Exposed (via __reinit in tests) so
 * tests can re-run it after changing the env var, without import-cache hacks.
 */
function loadKey(): void {
  const pem = process.env.ATTESTATION_PRIVATE_KEY
  privateKey = null
  publicKeyPem = null
  keyId = null

  if (!pem || pem.trim().length === 0) return

  try {
    // Allow the PEM to be provided with literal "\n" sequences (common when
    // pasting a multi-line key into a single-line env var field).
    const normalized = pem.includes('\\n') ? pem.replace(/\\n/g, '\n') : pem
    privateKey = createPrivateKey(normalized)
    const pub = createPublicKey(privateKey)
    publicKeyPem = pub.export({ type: 'spki', format: 'pem' }).toString()
    // A short, stable key id derived from a HASH of the raw public key bytes,
    // so it's genuinely unique per key (supports future rotation). Deriving
    // it from the PEM string directly would collide, since every Ed25519 PEM
    // shares the same "-----BEGIN PUBLIC KEY-----" prefix.
    const rawPub = pub.export({ type: 'spki', format: 'der' })
    const digest = createHash('sha256').update(rawPub).digest('base64url')
    keyId = 'ed25519-' + digest.slice(0, 16)
  } catch (err) {
    // Bad key material is worth failing loudly about, because a
    // misconfigured signing key silently producing garbage would be worse.
    throw new Error(
      'ATTESTATION_PRIVATE_KEY is set but could not be parsed as a PKCS8 ' +
        'Ed25519 PEM private key. Generate one with the snippet in ' +
        'attestation.ts, or unset it to run without attestation.'
    )
  }
}

loadKey()

// Test-only: re-read the env var and reload the key.
export const __reinit = loadKey

export function attestationEnabled(): boolean {
  return privateKey !== null
}

export function getPublicKeyPem(): string | null {
  return publicKeyPem
}

export function getKeyId(): string | null {
  return keyId
}

/**
 * Wraps a result object into a signed attestation envelope.
 *
 * The returned shape is:
 * {
 *   data:        <the original result, untouched>,
 *   attestation: {
 *     issued_at:  ISO timestamp,
 *     key_id:     which key signed this,
 *     algorithm:  "ed25519",
 *     signature:  base64url signature over the canonical signing input,
 *     signing_input_hint: how to reconstruct what was signed (for verifiers)
 *   }
 * }
 *
 * If attestation is disabled (no key configured), returns the data with an
 * explicit `attestation: { signed: false, ... }` so callers are never
 * misled into thinking an unsigned response was signed.
 */
export function attest<T extends Record<string, unknown>>(data: T): Record<string, unknown> {
  const issuedAt = new Date().toISOString()

  if (!privateKey || !keyId) {
    return {
      data,
      attestation: {
        signed: false,
        issued_at: issuedAt,
        note:
          'Attestation is not configured on this deployment (no signing key). ' +
          'Response is unsigned and should not be treated as verifiable evidence.',
      },
    }
  }

  // Canonical signing input: a deterministic JSON string of the data plus
  // the issued_at and key_id. Verifiers reconstruct this exact string and
  // check the signature against the published public key.
  const signingObject = { data, issued_at: issuedAt, key_id: keyId }
  const signingInput = JSON.stringify(signingObject)

  // Ed25519 in Node: pass null as the algorithm; sign the raw bytes.
  const signature = cryptoSign(null, Buffer.from(signingInput, 'utf8'), privateKey)

  return {
    data,
    attestation: {
      signed: true,
      issued_at: issuedAt,
      key_id: keyId,
      algorithm: 'ed25519',
      signature: signature.toString('base64url'),
      signing_input_hint:
        'signature is over JSON.stringify({ data, issued_at, key_id }) using these exact field values; ' +
        'verify with the Ed25519 public key at /.well-known/attestation-key',
    },
  }
}
