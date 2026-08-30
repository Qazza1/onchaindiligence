import {
  createPrivateKey,
  createPublicKey,
  KeyObject,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from 'node:crypto'
import { canonicalize, cloneJson } from './canonical.js'
import { BUNDLE_PAYLOAD_TYPE, BUNDLE_VERSION, MEDIA_TYPE } from './constants.js'
import { SchemaValidationError, SigningError } from './errors.js'
import { validateBundlePayload } from './graph.js'
import { validateDocument } from './schema.js'
import { deriveKeyId, loadPublicKey } from './trust.js'
import type {
  AttestationKeyRecord,
  BundlePayload,
  Ed25519Signer,
  JsonObject,
  JsonValue,
  KeyInput,
  PortableBundle,
} from './types.js'

export function dssePae(payloadType: string, payload: Uint8Array): Uint8Array {
  const typeBytes = Buffer.from(payloadType, 'utf8')
  return Buffer.concat([
    Buffer.from('DSSEv1 ', 'ascii'),
    Buffer.from(String(typeBytes.length), 'ascii'),
    Buffer.from(' ', 'ascii'),
    typeBytes,
    Buffer.from(' ', 'ascii'),
    Buffer.from(String(payload.byteLength), 'ascii'),
    Buffer.from(' ', 'ascii'),
    Buffer.from(payload),
  ])
}

function loadPrivateKey(value: KeyInput): KeyObject {
  try {
    const key = value instanceof KeyObject
      ? value
      : createPrivateKey(value instanceof Uint8Array && !Buffer.isBuffer(value) ? Buffer.from(value) : value as string | Buffer)
    if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
      throw new SigningError('private key must be Ed25519')
    }
    return key
  } catch (error) {
    if (error instanceof SigningError) throw error
    throw new SigningError('private key is not a valid Ed25519 PKCS8 key', { cause: error })
  }
}

export function createEd25519Signer(privateKeyInput: KeyInput): Ed25519Signer {
  const privateKey = loadPrivateKey(privateKeyInput)
  const publicKey = createPublicKey(privateKey)
  return Object.freeze({
    keyId: deriveKeyId(publicKey),
    publicKey,
    sign(message: Uint8Array): Uint8Array {
      return ed25519Sign(null, Buffer.from(message), privateKey)
    },
  })
}

export interface SealBundleOptions {
  keys?: readonly AttestationKeyRecord[]
  registrySnapshots?: readonly JsonObject[]
  anchors?: readonly JsonObject[]
}

export async function sealBundle(
  payload: BundlePayload,
  signer: Ed25519Signer,
  options: SealBundleOptions = {},
): Promise<PortableBundle> {
  validateBundlePayload(payload)
  const publicKey = loadPublicKey(signer.publicKey)
  const expectedKeyId = deriveKeyId(publicKey)
  if (signer.keyId !== expectedKeyId) {
    throw new SigningError(`signer keyId does not match public key; expected ${expectedKeyId}`)
  }
  const payloadBytes = canonicalize(payload)
  const message = dssePae(BUNDLE_PAYLOAD_TYPE, payloadBytes)
  const signature = Buffer.from(await signer.sign(message))
  if (signature.length !== 64 || !ed25519Verify(null, Buffer.from(message), publicKey, signature)) {
    throw new SigningError('signer did not return a valid Ed25519 signature for the DSSE PAE bytes')
  }
  const portable: PortableBundle = {
    media_type: MEDIA_TYPE,
    bundle_version: BUNDLE_VERSION,
    envelope: {
      payloadType: BUNDLE_PAYLOAD_TYPE,
      payload: Buffer.from(payloadBytes).toString('base64'),
      signatures: [{ keyid: signer.keyId, sig: signature.toString('base64') }],
    },
    verification_material: {
      keys: cloneJson([...(options.keys ?? [])] as JsonValue[]) as AttestationKeyRecord[],
      registry_snapshots: cloneJson([...(options.registrySnapshots ?? [])] as JsonValue[]) as JsonObject[],
      anchors: cloneJson([...(options.anchors ?? [])] as JsonValue[]) as JsonObject[],
    },
  }
  try {
    validateDocument('portable-file.schema.json', portable)
  } catch (error) {
    if (error instanceof SchemaValidationError) throw new SigningError(error.message, { cause: error })
    throw error
  }
  return portable
}
