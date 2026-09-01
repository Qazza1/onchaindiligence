import { createHash, createPublicKey, KeyObject, verify } from 'node:crypto'
import { contentId } from './canonical.js'
import { EvidenceValidationError } from './errors.js'
import { createRecord } from './records.js'
import type { AgentEvidenceRecord, JsonObject, KeyInput } from './types.js'

const DID_PREFIX = 'did:key:'
const BASE58BTC_PREFIX = 'z'
const ED25519_MULTICODEC = Buffer.from([0xed, 0x01])
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')
const BASE58BTC = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const ROOM = /^[a-z0-9][a-z0-9_-]{0,47}$/
const NONCE = /^[0-9]{1,19}$/
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu

/** A stored Technocore signed-lane message. All fields are untrusted input. */
export interface TechnocoreSignedMessage {
  did: string
  room: string
  nonce: string
  text: string
  sig: string
}

/**
 * Explicit server observations accompanying a message. Keep numeric server values
 * as strings when they might exceed JavaScript's safe-integer range.
 */
export interface TechnocoreEvidenceOptions {
  runRef: string
  observedAt: string
  parents?: readonly string[]
  expiresAt?: string | null
  serverMetadata?: JsonObject
  toolVersion?: string
}

/** Mirrors Technocore's documented single-line sweep before it signs or stores text. */
export function sweepTechnocoreText(text: string): string {
  return text.replace(INVISIBLE, ' ').trim()
}

/** The exact UTF-8 string verified by Technocore's signed message lane. */
export function technocoreSigningInput(message: Pick<TechnocoreSignedMessage, 'room' | 'nonce' | 'text'>): Uint8Array {
  return Buffer.from(`${message.room}|${message.nonce}|${message.text}`, 'utf8')
}

/** SHA-256 of the exact stored message text, encoded as unpadded base64url. */
export function technocoreTextDigest(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('base64url')
}

/** Derives the Ed25519 did:key identifier used by Technocore from a public key. */
export function technocoreDidFromPublicKey(publicKey: KeyInput): string {
  const key = publicKey instanceof KeyObject && publicKey.type === 'public'
    ? publicKey
    : createPublicKey(publicKey instanceof Uint8Array ? Buffer.from(publicKey) : publicKey)
  const spki = key.export({ format: 'der', type: 'spki' })
  if (!Buffer.isBuffer(spki) || spki.length !== ED25519_SPKI_PREFIX.length + 32 ||
    !spki.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
    throw new EvidenceValidationError('Technocore requires an Ed25519 public key')
  }
  return `${DID_PREFIX}${BASE58BTC_PREFIX}${base58Encode(Buffer.concat([
    ED25519_MULTICODEC,
    spki.subarray(ED25519_SPKI_PREFIX.length),
  ]))}`
}

/**
 * Verifies a Technocore signed message entirely offline. A true result proves
 * only that the embedded did:key signed this stored message, never that its text
 * is true or safe to act on.
 */
export function verifyTechnocoreMessage(message: TechnocoreSignedMessage): boolean {
  try {
    if (!ROOM.test(message.room) || !NONCE.test(message.nonce) || !SIGNATURE.test(message.sig)) return false
    if (message.text !== sweepTechnocoreText(message.text) || Array.from(message.text).length > 4096) return false
    const signature = Buffer.from(message.sig, 'base64url')
    if (signature.length !== 64 || signature.toString('base64url') !== message.sig) return false
    const publicKey = publicKeyFromDid(message.did)
    return verify(null, technocoreSigningInput(message), publicKey, signature)
  } catch {
    return false
  }
}

/**
 * Converts a verified Technocore assertion into schema-valid Agent Evidence.
 * The embedded message remains untrusted data and uses agent-assertion trust mode.
 */
export function createTechnocoreEvidence(
  message: TechnocoreSignedMessage,
  options: TechnocoreEvidenceOptions,
): AgentEvidenceRecord {
  if (!verifyTechnocoreMessage(message)) {
    throw new EvidenceValidationError('Technocore message has an invalid did:key signature or canonical form')
  }

  const captured: JsonObject = {
    did: message.did,
    room: message.room,
    nonce: message.nonce,
    text: message.text,
    text_digest_sha256: technocoreTextDigest(message.text),
    signature: message.sig,
    signature_algorithm: 'ed25519',
    signing_input: '<room>|<nonce>|<text-after-technocore-sweep>',
    verification: 'valid-did-key-signature',
  }
  if (options.serverMetadata !== undefined) captured.server_metadata = options.serverMetadata

  const request: JsonObject = { did: message.did, room: message.room, nonce: message.nonce }
  return createRecord('evidence', {
    evidence_type: 'technocore-signed-message',
    run_ref: options.runRef,
    trust_mode: 'agent-assertion',
    source: { id: 'https://technocore.chat', type: 'technocore-chat' },
    tool: { name: 'onchaindiligence-technocore-adapter', version: options.toolVersion ?? '1' },
    request: {
      digest: { sha256: contentId(request).slice('sha256:'.length) },
      media_type: 'application/vnd.technocore.signed-message-request+json',
    },
    response: {
      mode: 'embedded',
      media_type: 'application/vnd.technocore.signed-message+json',
      value: captured,
      digest: { sha256: contentId(captured).slice('sha256:'.length) },
    },
    observed_at: options.observedAt,
    expires_at: options.expiresAt ?? null,
    scope: { did: message.did, room: message.room, nonce: message.nonce },
  }, { parents: options.parents ?? [options.runRef] })
}

function publicKeyFromDid(did: string) {
  if (!did.startsWith(`${DID_PREFIX}${BASE58BTC_PREFIX}`)) throw new EvidenceValidationError('not a base58btc did:key')
  const decoded = base58Decode(did.slice(`${DID_PREFIX}${BASE58BTC_PREFIX}`.length))
  if (decoded.length !== 34 || !decoded.subarray(0, 2).equals(ED25519_MULTICODEC)) {
    throw new EvidenceValidationError('Technocore did:key is not an Ed25519 multicodec key')
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, decoded.subarray(2)]),
    format: 'der',
    type: 'spki',
  })
}

function base58Encode(bytes: Uint8Array): string {
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  let encoded = ''
  while (value > 0n) {
    const remainder = Number(value % 58n)
    encoded = BASE58BTC[remainder] + encoded
    value /= 58n
  }
  for (const byte of bytes) {
    if (byte !== 0) break
    encoded = `1${encoded}`
  }
  return encoded || '1'
}

function base58Decode(value: string): Buffer {
  if (value.length === 0) throw new EvidenceValidationError('empty base58btc identifier')
  let decoded = 0n
  for (const character of value) {
    const index = BASE58BTC.indexOf(character)
    if (index < 0) throw new EvidenceValidationError('invalid base58btc identifier')
    decoded = decoded * 58n + BigInt(index)
  }
  let hex = decoded.toString(16)
  if (hex.length % 2 !== 0) hex = `0${hex}`
  const bytes = decoded === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex')
  let leadingZeros = 0
  for (const character of value) {
    if (character !== '1') break
    leadingZeros += 1
  }
  return Buffer.concat([Buffer.alloc(leadingZeros), bytes])
}
