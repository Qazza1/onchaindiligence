/**
 * receiptId.ts — deterministic, human-friendly receipt locators.
 *
 * A receipt_id is NOT sequential (no #1001-style counter that leaks activity
 * volume or is guessable) and is NOT itself authoritative — it is a locator
 * derived from `receipt_digest`, the full SHA-256 content digest, which
 * remains the authoritative value. A resolver MUST recompute
 * `formatReceiptId(receipt.receipt_digest)` and confirm it equals the
 * requested id before serving a lookup result (see `receipts.ts`).
 *
 * Encoding: Crockford Base32 (https://www.crockford.com/base32.html) — a
 * well-defined, published, widely-used encoding chosen specifically because it
 * excludes the visually ambiguous characters I, L, O, U, is case-insensitive
 * on decode, and is a standard scheme rather than a bespoke one invented for
 * this feature.
 *
 * We encode the first 10 bytes (80 bits) of the digest — enough that a
 * resolver keyed on the full id has a vanishingly small accidental-collision
 * probability, while staying short enough to read aloud and copy/paste
 * (16 Crockford characters, grouped as OCD-RCP-XXXX-XXXX-XXXX-XXXX). 80 bits
 * divides evenly into 5-bit Crockford characters (80 / 5 = 16), so there is no
 * padding ambiguity.
 */
import { CanonicalizationError } from './errors.js'

const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
// Case-insensitive decode map, including Crockford's documented look-alike
// substitutions (O -> 0, I and L -> 1) so a human-transcribed id still decodes.
const DECODE_MAP: ReadonlyMap<string, number> = new Map([
  ...[...CROCKFORD_ALPHABET].map((char, index) => [char, index] as const),
  ['O', 0], ['I', 1], ['L', 1],
])

const DIGEST_BYTES_USED = 10 // 80 bits -> exactly 16 Crockford characters
const CHARS_PER_GROUP = 4
const GROUP_COUNT = 4 // 16 chars / 4 per group
const PREFIX = 'OCD-RCP-'

const RECEIPT_DIGEST_PATTERN = /^sha256:([A-Za-z0-9_-]{43})$/
const RECEIPT_ID_PATTERN = new RegExp(
  `^OCD-RCP-([0-9A-Z]{${CHARS_PER_GROUP}}-){${GROUP_COUNT - 1}}[0-9A-Z]{${CHARS_PER_GROUP}}$`,
)

/** Decode this package's `sha256:<base64url>` content-id format to raw bytes. */
function digestToBytes(receiptDigest: string): Buffer {
  const match = RECEIPT_DIGEST_PATTERN.exec(receiptDigest)
  if (!match) {
    throw new CanonicalizationError(`receipt digest is not a valid sha256 content id: ${receiptDigest}`)
  }
  return Buffer.from(match[1] as string, 'base64url')
}

function encodeCrockford(bytes: Uint8Array): string {
  let bits = 0
  let value = 0
  let output = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      output += CROCKFORD_ALPHABET[(value >> bits) & 0x1f]
    }
  }
  if (bits > 0) {
    output += CROCKFORD_ALPHABET[(value << (5 - bits)) & 0x1f]
  }
  return output
}

/** Derive the public receipt_id from a full `receipt_digest`. Pure and deterministic. */
export function formatReceiptId(receiptDigest: string): string {
  const bytes = digestToBytes(receiptDigest).subarray(0, DIGEST_BYTES_USED)
  if (bytes.length !== DIGEST_BYTES_USED) {
    throw new CanonicalizationError('receipt digest is too short to derive a receipt id')
  }
  const encoded = encodeCrockford(bytes) // exactly 16 characters
  const groups: string[] = []
  for (let i = 0; i < encoded.length; i += CHARS_PER_GROUP) {
    groups.push(encoded.slice(i, i + CHARS_PER_GROUP))
  }
  return PREFIX + groups.join('-')
}

/** Structural validation only — this does NOT prove the id matches any real digest. */
export function isValidReceiptIdFormat(receiptId: string): boolean {
  return RECEIPT_ID_PATTERN.test(receiptId.toUpperCase())
}

/**
 * Normalizes a caller-supplied receipt id (case/look-alike-tolerant) to the
 * canonical uppercase form, or returns null if it is not structurally a
 * receipt id. This does NOT decode back to digest bytes — 80 bits is a
 * fragment of the 256-bit digest, not the whole thing, so the only safe
 * verification is forward (recompute `formatReceiptId` from a candidate
 * receipt's own digest and compare), never backward.
 */
export function normalizeReceiptId(input: string): string | null {
  const upper = input.trim().toUpperCase()
  if (!isValidReceiptIdFormat(upper)) return null
  // Re-run every character through the decode map so an input using
  // look-alike substitutes (O/I/L) still normalizes to the canonical form.
  const body = upper.slice(PREFIX.length).replace(/-/g, '')
  let canonicalBody = ''
  for (const char of body) {
    const decoded = DECODE_MAP.get(char)
    if (decoded === undefined) return null
    canonicalBody += CROCKFORD_ALPHABET[decoded]
  }
  const groups: string[] = []
  for (let i = 0; i < canonicalBody.length; i += CHARS_PER_GROUP) {
    groups.push(canonicalBody.slice(i, i + CHARS_PER_GROUP))
  }
  return PREFIX + groups.join('-')
}
