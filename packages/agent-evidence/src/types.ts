import type { KeyObject } from 'node:crypto'
import type { BUNDLE_VERSION, RECORD_VERSION } from './constants.js'

export type JsonPrimitive = null | boolean | number | string
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue }
export type JsonObject = { [key: string]: JsonValue }

export type RecordKind =
  | 'principal'
  | 'agent'
  | 'mandate'
  | 'run'
  | 'evidence'
  | 'policy'
  | 'decision'
  | 'execution'

export interface AgentEvidenceRecord {
  id: string
  record_version: typeof RECORD_VERSION
  kind: RecordKind
  parents: string[]
  statement: JsonObject
  proofs: JsonObject[]
}

export interface BundlePayload {
  bundle_version: typeof BUNDLE_VERSION
  bundle_id: string
  created_at: string
  run_id: string
  root_ids: string[]
  records: AgentEvidenceRecord[]
  extensions: JsonObject
}

export interface DsseSignature {
  keyid: string
  sig: string
}

export interface DsseEnvelope {
  payloadType: string
  payload: string
  signatures: DsseSignature[]
}

export interface AttestationKeyRecord extends JsonObject {
  key_id: string
  algorithm: 'ed25519'
  public_key_pem: string
  status: 'active' | 'retired' | 'revoked' | 'compromised'
  valid_from: string | null
  valid_until: string | null
  status_changed_at: string | null
  replacement_key_id: string | null
  compromised_at: string | null
  status_reason?: string
}

export interface VerificationMaterial {
  keys: AttestationKeyRecord[]
  registry_snapshots: JsonObject[]
  anchors: JsonObject[]
}

export interface PortableBundle {
  media_type: string
  bundle_version: typeof BUNDLE_VERSION
  envelope: DsseEnvelope
  verification_material: VerificationMaterial
}

export type KeyInput = string | Buffer | Uint8Array | KeyObject

export interface Ed25519Signer {
  readonly keyId: string
  readonly publicKey: KeyInput
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>
}

export type VerificationState = 'VALID' | 'INVALID' | 'UNVERIFIABLE'

export interface ComponentResult {
  component: string
  state: VerificationState
  code: string
  message: string
  required: boolean
  key_id?: string
  record_id?: string
}

export interface VerificationReport {
  state: VerificationState
  valid: boolean
  bundle_id: string | null
  components: ComponentResult[]
  payload?: BundlePayload
}
