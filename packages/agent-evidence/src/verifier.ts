import { verify as ed25519Verify } from 'node:crypto'
import {
  ATTESTATION_ISSUER,
  ATTESTATION_PURPOSE,
  ATTESTATION_V2,
  BUNDLE_PAYLOAD_TYPE,
  BUNDLE_VERSION,
  MEDIA_TYPE,
} from './constants.js'
import { canonicalize, enforceLimits, parseJson, parseTimestamp } from './canonical.js'
import { dssePae } from './dsse.js'
import {
  CanonicalizationError,
  EvidenceValidationError,
  ParseError,
  SchemaValidationError,
} from './errors.js'
import { validateBundlePayload } from './graph.js'
import { validateDocument } from './schema.js'
import { evaluateKeyLifecycle, type AttestationKey, TrustPolicy } from './trust.js'
import type {
  AgentEvidenceRecord,
  BundlePayload,
  ComponentResult,
  DsseEnvelope,
  JsonObject,
  JsonValue,
  PortableBundle,
  VerificationReport,
  VerificationState,
} from './types.js'

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
const BASE64URL_SIGNATURE = /^[A-Za-z0-9_-]{86}$/

function result(
  component: string,
  state: VerificationState,
  code: string,
  message: string,
  options: {
    keyId?: string | undefined
    recordId?: string | undefined
    required?: boolean | undefined
  } = {},
): ComponentResult {
  const item: ComponentResult = {
    component,
    state,
    code,
    message,
    required: options.required ?? true,
  }
  if (options.keyId !== undefined) item.key_id = options.keyId
  if (options.recordId !== undefined) item.record_id = options.recordId
  return item
}

export function overallState(components: readonly ComponentResult[]): VerificationState {
  const required = components.filter((item) => item.required)
  if (required.some((item) => item.state === 'INVALID')) return 'INVALID'
  if (required.some((item) => item.state === 'UNVERIFIABLE')) return 'UNVERIFIABLE'
  return 'VALID'
}

function report(components: ComponentResult[], payload?: BundlePayload): VerificationReport {
  const state = overallState(components)
  const value: VerificationReport = {
    state,
    valid: state === 'VALID',
    bundle_id: payload?.bundle_id ?? null,
    components,
  }
  if (payload) value.payload = payload
  return value
}

function decodeBase64(value: string, label: string): Buffer {
  if (!BASE64.test(value)) throw new ParseError(`${label} is not strict padded base64`)
  const decoded = Buffer.from(value, 'base64')
  if (decoded.toString('base64') !== value) throw new ParseError(`${label} is not canonical padded base64`)
  return decoded
}

function decodeBase64UrlSignature(value: string): Buffer {
  if (!BASE64URL_SIGNATURE.test(value)) {
    throw new ParseError('attestation signature must be 86-character unpadded base64url')
  }
  const decoded = Buffer.from(value, 'base64url')
  if (decoded.length !== 64 || decoded.toString('base64url') !== value) {
    throw new ParseError('Ed25519 signature must contain 64 canonical base64url bytes')
  }
  return decoded
}

function strictInput(
  document: string | Uint8Array | PortableBundle | Record<string, unknown>,
  policy: TrustPolicy,
): PortableBundle {
  let value: JsonValue
  if (typeof document === 'string' || document instanceof Uint8Array) {
    const bytes = typeof document === 'string' ? Buffer.from(document, 'utf8') : Buffer.from(document)
    if (bytes.length > policy.maxFileSize) {
      throw new ParseError(`portable file exceeds maximum size ${policy.maxFileSize}`)
    }
    value = parseJson(bytes)
  } else {
    value = parseJson(canonicalize(document))
  }
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    throw new ParseError('portable file must be a JSON object')
  }
  enforceLimits(value, {
    maxDepth: policy.maxDepth,
    maxStringLength: policy.maxStringLength,
    maxArrayLength: policy.maxArrayLength,
  })
  return value as unknown as PortableBundle
}

function verifySignature(key: AttestationKey, signature: Uint8Array, message: Uint8Array): boolean {
  return ed25519Verify(null, Buffer.from(message), key.publicKey, Buffer.from(signature))
}

function verifySignatureSet(
  envelope: DsseEnvelope,
  payloadBytes: Uint8Array,
  policy: TrustPolicy,
  options: { signedAt: Date | null; component: string; recordId?: string },
): ComponentResult[] {
  const components: ComponentResult[] = []
  const seen = new Set<string>()
  let validCount = 0
  for (const signature of envelope.signatures) {
    const keyId = signature.keyid
    if (seen.has(keyId)) {
      components.push(result(options.component, 'INVALID', 'duplicate-signature-key',
        'a DSSE signature set may contain each key ID at most once', { keyId, recordId: options.recordId }))
      continue
    }
    seen.add(keyId)
    const key = policy.key(keyId)
    if (!key) {
      components.push(result(options.component, 'UNVERIFIABLE', 'key-not-trusted',
        'signature key is absent from caller-supplied trust', { keyId, recordId: options.recordId }))
      continue
    }
    let signatureBytes: Buffer
    try {
      signatureBytes = decodeBase64(signature.sig, 'DSSE signature')
    } catch (error) {
      components.push(result(options.component, 'INVALID', 'signature-encoding',
        error instanceof Error ? error.message : String(error), { keyId, recordId: options.recordId }))
      continue
    }
    if (
      signatureBytes.length !== 64
      || !verifySignature(key, signatureBytes, dssePae(envelope.payloadType, payloadBytes))
    ) {
      components.push(result(options.component, 'INVALID', 'signature-invalid',
        'Ed25519 signature does not verify over the exact DSSE PAE bytes', { keyId, recordId: options.recordId }))
      continue
    }
    const [state, code, message] = evaluateKeyLifecycle(key, options.signedAt, policy)
    components.push(result(options.component, state, code, message, { keyId, recordId: options.recordId }))
    if (state === 'VALID') validCount += 1
  }
  if (validCount < 1) {
    components.push(result(options.component, 'UNVERIFIABLE', 'signature-threshold-not-met',
      `required one valid caller-trusted source signature, got ${validCount}`, { recordId: options.recordId }))
  }
  return components
}

function javascriptStringify(value: unknown): Uint8Array {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const parts = Object.entries(value).map(([key, item]) => Buffer.concat([
      Buffer.from(canonicalize(key)),
      Buffer.from(':'),
      Buffer.from(javascriptStringify(item)),
    ]))
    return Buffer.concat([Buffer.from('{'), ...parts.flatMap((part, index) =>
      index === parts.length - 1 ? [part] : [part, Buffer.from(',')]), Buffer.from('}')])
  }
  if (Array.isArray(value)) {
    const parts = value.map((item) => Buffer.from(javascriptStringify(item)))
    return Buffer.concat([Buffer.from('['), ...parts.flatMap((part, index) =>
      index === parts.length - 1 ? [part] : [part, Buffer.from(',')]), Buffer.from(']')])
  }
  return canonicalize(value)
}

function verifyAttestationProof(
  proof: JsonObject,
  policy: TrustPolicy,
  recordId: string,
): ComponentResult {
  const proofType = String(proof.proof_type)
  const envelope = proof.envelope as JsonObject
  const attestation = envelope.attestation as JsonObject
  const keyId = String(attestation.key_id)
  const key = policy.key(keyId)
  if (!key) {
    return result('source-proof', 'UNVERIFIABLE', 'key-not-trusted',
      'attestation key is absent from caller-supplied trust', { keyId, recordId })
  }
  let issuedAt: Date
  let signature: Buffer
  try {
    issuedAt = parseTimestamp(String(attestation.issued_at))
    signature = decodeBase64UrlSignature(String(attestation.signature))
  } catch (error) {
    return result('source-proof', 'INVALID', 'attestation-encoding',
      error instanceof Error ? error.message : String(error), { keyId, recordId })
  }

  let message: Uint8Array
  if (proofType === 'onchaindiligence-attestation-v2') {
    if (attestation.issuer !== ATTESTATION_ISSUER) {
      return result('source-proof', 'INVALID', 'attestation-issuer',
        'v2 attestation issuer is not the exact OnChainDiligence issuer', { keyId, recordId })
    }
    if (attestation.purpose !== ATTESTATION_PURPOSE) {
      return result('source-proof', 'INVALID', 'attestation-purpose',
        'v2 attestation purpose is not a compliance result', { keyId, recordId })
    }
    message = canonicalize({
      schema_version: ATTESTATION_V2,
      issuer: attestation.issuer,
      purpose: attestation.purpose,
      data: envelope.data,
      issued_at: attestation.issued_at,
      key_id: keyId,
    })
  } else {
    message = javascriptStringify({
      data: envelope.data,
      issued_at: attestation.issued_at,
      key_id: keyId,
    })
  }
  if (!verifySignature(key, signature, message)) {
    const legacy = proofType.endsWith('-v1')
    return result('source-proof', legacy ? 'UNVERIFIABLE' : 'INVALID',
      legacy ? 'legacy-signature-unverifiable' : 'signature-invalid',
      legacy
        ? 'v1 signature did not verify from the object order representable in the canonical bundle'
        : 'attestation signature does not verify',
      { keyId, recordId })
  }
  const [state, code, messageText] = evaluateKeyLifecycle(key, issuedAt, policy)
  return result('source-proof', state, code, messageText, { keyId, recordId })
}

function verifyRecordProofs(payload: BundlePayload, policy: TrustPolicy): ComponentResult[] {
  const components: ComponentResult[] = []
  for (const record of payload.records) {
    for (const proof of record.proofs) {
      const proofType = String(proof.proof_type)
      if (proofType === 'external-digest') {
        components.push(result('source-proof', 'VALID', 'external-digest-bound',
          'digest is bound by the record ID but does not establish source attribution', { recordId: record.id }))
      } else if (
        proofType === 'onchaindiligence-attestation-v1'
        || proofType === 'onchaindiligence-attestation-v2'
      ) {
        const response = record.statement.response
        const source = record.statement.source
        if (
          source === null || typeof source !== 'object' || Array.isArray(source)
          || (source as JsonObject).id !== ATTESTATION_ISSUER
        ) {
          components.push(result('source-proof', 'INVALID', 'attestation-source-mismatch',
            'OnChainDiligence attestation proof requires the exact OnChainDiligence source ID',
            { recordId: record.id }))
          continue
        }
        if (
          record.kind !== 'evidence'
          || response === null || typeof response !== 'object' || Array.isArray(response)
          || (response as JsonObject).mode !== 'embedded'
          || Buffer.compare(Buffer.from(canonicalize((response as JsonObject).value)), Buffer.from(canonicalize(proof.envelope))) !== 0
        ) {
          components.push(result('source-proof', 'INVALID', 'attestation-response-mismatch',
            'attestation proof must exactly equal the embedded evidence response', { recordId: record.id }))
          continue
        }
        components.push(verifyAttestationProof(proof, policy, record.id))
      } else if (proofType === 'dsse-ed25519-v1') {
        const envelope = proof.envelope as unknown as DsseEnvelope
        let proofBytes: Buffer
        try {
          proofBytes = decodeBase64(envelope.payload, 'source DSSE payload')
        } catch (error) {
          components.push(result('source-proof', 'INVALID', 'proof-payload-encoding',
            error instanceof Error ? error.message : String(error), { recordId: record.id }))
          continue
        }
        if (envelope.payloadType !== proof.statement_media_type) {
          components.push(result('source-proof', 'INVALID', 'proof-payload-type',
            'source DSSE payloadType does not equal statement_media_type', { recordId: record.id }))
          continue
        }
        if (Buffer.compare(proofBytes, Buffer.from(canonicalize(record.statement))) !== 0) {
          components.push(result('source-proof', 'INVALID', 'proof-statement-mismatch',
            'source DSSE payload is not the canonical record statement', { recordId: record.id }))
          continue
        }
        components.push(...verifySignatureSet(envelope, proofBytes, policy, {
          signedAt: null,
          component: 'source-proof',
          recordId: record.id,
        }))
      }
    }
  }
  return components
}

function verifyEvidenceSemantics(
  payload: BundlePayload,
  proofComponents: ComponentResult[],
  policy: TrustPolicy,
): ComponentResult[] {
  const components: ComponentResult[] = []
  const cryptographicTypes = new Set([
    'dsse-ed25519-v1',
    'onchaindiligence-attestation-v1',
    'onchaindiligence-attestation-v2',
  ])
  for (const record of payload.records.filter((candidate) => candidate.kind === 'evidence')) {
    const statement = record.statement
    const response = statement.response as JsonObject
    if (response.mode === 'reference') {
      components.push(result('evidence-content', policy.allowDigestOnlyEvidence ? 'VALID' : 'UNVERIFIABLE',
        policy.allowDigestOnlyEvidence ? 'digest-only-allowed' : 'evidence-content-unavailable',
        policy.allowDigestOnlyEvidence
          ? 'caller policy permits digest-only evidence'
          : 'offline verifier cannot resolve referenced evidence required by default policy',
        { recordId: record.id }))
    } else {
      components.push(result('evidence-content', 'VALID', 'evidence-embedded',
        'evidence response is embedded and its digest matches', { recordId: record.id }))
    }
    if (statement.trust_mode === 'agent-assertion') {
      components.push(result('trust-mode', 'VALID', 'agent-assertion',
        'statement is explicitly limited to an agent assertion', { recordId: record.id }))
      continue
    }
    const cryptoProofs = record.proofs.filter((proof) => cryptographicTypes.has(String(proof.proof_type)))
    if (!cryptoProofs.length) {
      components.push(result('trust-mode', 'INVALID', 'cryptographic-proof-missing',
        `${String(statement.trust_mode)} requires a cryptographic source proof`, { recordId: record.id }))
      continue
    }
    const relevant = proofComponents.filter((item) =>
      item.record_id === record.id && item.code !== 'external-digest-bound')
    const state: VerificationState = relevant.some((item) => item.state === 'INVALID')
      ? 'INVALID'
      : relevant.some((item) => item.state === 'UNVERIFIABLE') ? 'UNVERIFIABLE' : 'VALID'
    const code = state === 'INVALID' ? 'trust-proof-invalid'
      : state === 'UNVERIFIABLE' ? 'trust-proof-unverifiable' : 'trust-proof-valid'
    components.push(result('trust-mode', state, code,
      `${String(statement.trust_mode)} is reported exactly and backed by the source-proof result`,
      { recordId: record.id }))
  }
  return components
}

function verificationMaterialComponents(portable: PortableBundle, policy: TrustPolicy): ComponentResult[] {
  const components: ComponentResult[] = []
  if (portable.verification_material.keys.length) {
    components.push(result('verification-material', 'UNVERIFIABLE', 'embedded-keys-untrusted',
      'embedded public keys are verification hints, never caller trust', { required: false }))
  }
  for (const _snapshot of portable.verification_material.registry_snapshots) {
    components.push(result('registry-snapshot', 'UNVERIFIABLE', 'snapshot-format-unsupported',
      'registry snapshot is preserved but not trusted or verified by v0 core', { required: false }))
  }
  if (policy.requireVerifiedAnchor && !portable.verification_material.anchors.length) {
    components.push(result('anchor', 'UNVERIFIABLE', 'anchor-required-missing',
      'caller policy requires an independently verified anchor'))
  }
  for (const _anchor of portable.verification_material.anchors) {
    components.push(result('anchor', 'UNVERIFIABLE', 'anchor-format-unsupported',
      'anchor is preserved but no v0 core anchor format is verified', { required: policy.requireVerifiedAnchor }))
  }
  return components
}

function verifyFreshness(payload: BundlePayload, policy: TrustPolicy): ComponentResult[] {
  const components: ComponentResult[] = []
  let createdAt: Date
  try {
    createdAt = parseTimestamp(payload.created_at)
  } catch (error) {
    return [result('freshness', 'INVALID', 'timestamp-invalid', error instanceof Error ? error.message : String(error))]
  }
  if (createdAt.getTime() > policy.now.getTime() + policy.maxFutureSkewMs) {
    components.push(result('freshness', 'INVALID', 'bundle-time-future',
      'bundle created_at exceeds allowed clock skew'))
  } else if (policy.maxBundleAgeMs !== null && policy.now.getTime() - createdAt.getTime() > policy.maxBundleAgeMs) {
    components.push(result('freshness', 'INVALID', 'bundle-stale',
      'bundle exceeds caller-supplied maximum age'))
  } else {
    components.push(result('freshness', 'VALID', 'bundle-freshness-valid',
      'bundle satisfies caller-supplied time policy'))
  }
  const fields: Partial<Record<AgentEvidenceRecord['kind'], readonly string[]>> = {
    evidence: ['observed_at'],
    decision: ['decided_at'],
    execution: ['submitted_at', 'confirmed_at'],
    run: ['started_at', 'ended_at'],
  }
  for (const record of payload.records) {
    for (const name of fields[record.kind] ?? []) {
      const raw = record.statement[name]
      if (typeof raw === 'string' && parseTimestamp(raw).getTime() > policy.now.getTime() + policy.maxFutureSkewMs) {
        components.push(result('freshness', 'INVALID', 'asserted-time-future',
          `${record.kind}.${name} exceeds allowed clock skew`, { recordId: record.id }))
      }
    }
    if (
      policy.enforceEvidenceExpiration
      && record.kind === 'evidence'
      && typeof record.statement.expires_at === 'string'
      && policy.now.getTime() > parseTimestamp(record.statement.expires_at).getTime()
    ) {
      components.push(result('freshness', 'INVALID', 'evidence-expired',
        'evidence expires_at is before policy time', { recordId: record.id }))
    }
  }
  return components
}

export function verifyBundle(
  document: string | Uint8Array | PortableBundle | Record<string, unknown>,
  policy: TrustPolicy,
): VerificationReport {
  const components: ComponentResult[] = []
  let portable: PortableBundle
  try {
    portable = strictInput(document, policy)
  } catch (error) {
    if (error instanceof ParseError || error instanceof CanonicalizationError) {
      return report([result('outer', 'INVALID', 'json-invalid', error.message)])
    }
    throw error
  }
  try {
    validateDocument('portable-file.schema.json', portable)
  } catch (error) {
    if (error instanceof SchemaValidationError) {
      return report([result('outer', 'INVALID', 'schema-invalid', error.message)])
    }
    throw error
  }
  if (portable.media_type !== MEDIA_TYPE || portable.bundle_version !== BUNDLE_VERSION) {
    return report([result('outer', 'INVALID', 'version-unsupported', 'unsupported outer format')])
  }
  components.push(result('outer', 'VALID', 'outer-valid', 'portable file schema and version are valid'))
  components.push(...verificationMaterialComponents(portable, policy))

  const envelope = portable.envelope
  if (envelope.payloadType !== BUNDLE_PAYLOAD_TYPE) {
    components.push(result('payload', 'INVALID', 'payload-type-unsupported', 'unsupported DSSE payload type'))
    return report(components)
  }
  let payloadBytes: Buffer
  try {
    payloadBytes = decodeBase64(envelope.payload, 'DSSE payload')
  } catch (error) {
    components.push(result('payload', 'INVALID', 'payload-encoding',
      error instanceof Error ? error.message : String(error)))
    return report(components)
  }

  const cryptographic: Array<readonly [AttestationKey, string]> = []
  const seen = new Set<string>()
  let signatureFailure = false
  for (const signature of envelope.signatures) {
    const keyId = signature.keyid
    if (seen.has(keyId)) {
      components.push(result('bundle-signature', 'INVALID', 'duplicate-signature-key',
        'a DSSE signature set may contain each key ID at most once', { keyId }))
      signatureFailure = true
      continue
    }
    seen.add(keyId)
    const key = policy.key(keyId)
    if (!key) {
      components.push(result('bundle-signature', 'UNVERIFIABLE', 'key-not-trusted',
        'bundle key is absent from caller-supplied trust; embedded keys are hints only', { keyId }))
      continue
    }
    let signatureBytes: Buffer
    try {
      signatureBytes = decodeBase64(signature.sig, 'DSSE signature')
    } catch (error) {
      components.push(result('bundle-signature', 'INVALID', 'signature-encoding',
        error instanceof Error ? error.message : String(error), { keyId }))
      signatureFailure = true
      continue
    }
    if (
      signatureBytes.length !== 64
      || !verifySignature(key, signatureBytes, dssePae(BUNDLE_PAYLOAD_TYPE, payloadBytes))
    ) {
      components.push(result('bundle-signature', 'INVALID', 'signature-invalid',
        'bundle signature does not verify over the exact DSSE PAE bytes', { keyId }))
      signatureFailure = true
      continue
    }
    cryptographic.push([key, keyId])
  }
  if (signatureFailure) return report(components)
  if (!cryptographic.length) {
    components.push(result('bundle-signature', 'UNVERIFIABLE', 'signature-threshold-not-met',
      'no bundle signature uses a caller-trusted key'))
    return report(components)
  }

  let payload: BundlePayload
  try {
    const parsed = parseJson(payloadBytes)
    if (parsed === null || Array.isArray(parsed) || typeof parsed !== 'object') {
      throw new ParseError('signed payload must be a JSON object')
    }
    enforceLimits(parsed, {
      maxDepth: policy.maxDepth,
      maxStringLength: policy.maxStringLength,
      maxArrayLength: policy.maxArrayLength,
    })
    payload = parsed as unknown as BundlePayload
    validateDocument('bundle-payload.schema.json', payload)
  } catch (error) {
    if (error instanceof ParseError || error instanceof SchemaValidationError) {
      components.push(result('payload', 'INVALID', 'payload-invalid', error.message))
      return report(components)
    }
    throw error
  }
  try {
    if (Buffer.compare(Buffer.from(canonicalize(payload)), payloadBytes) !== 0) {
      components.push(result('payload', 'INVALID', 'payload-not-rfc8785',
        'signed payload bytes are not their RFC 8785 representation'))
      return report(components, payload)
    }
  } catch (error) {
    if (error instanceof CanonicalizationError) {
      components.push(result('payload', 'INVALID', 'payload-not-ijson', error.message))
      return report(components, payload)
    }
    throw error
  }
  if (payload.bundle_version !== BUNDLE_VERSION || portable.bundle_version !== payload.bundle_version) {
    components.push(result('payload', 'INVALID', 'outer-inner-version-mismatch',
      'authoritative and routing versions do not match'))
    return report(components, payload)
  }
  components.push(result('payload', 'VALID', 'payload-valid', 'signed payload is canonical v0 JSON'))

  const createdAt = parseTimestamp(payload.created_at)
  let lifecycleCount = 0
  for (const [key, keyId] of cryptographic) {
    const [state, code, message] = evaluateKeyLifecycle(key, createdAt, policy)
    components.push(result('bundle-signature', state, code, message, { keyId }))
    if (state === 'VALID') lifecycleCount += 1
  }
  const presented = new Set(envelope.signatures.map((signature) => signature.keyid))
  for (const keyId of [...policy.requiredSignatureKeyIds].filter((id) => !presented.has(id)).sort()) {
    components.push(result('bundle-signature', 'UNVERIFIABLE', 'required-signature-missing',
      'a caller-required bundle signature is not present', { keyId }))
  }
  if (lifecycleCount < policy.minimumValidSignatures) {
    components.push(result('bundle-signature', 'UNVERIFIABLE', 'signature-threshold-not-met',
      `required ${policy.minimumValidSignatures} valid signature(s), got ${lifecycleCount}`))
  }

  try {
    validateBundlePayload(payload)
  } catch (error) {
    if (error instanceof EvidenceValidationError) {
      components.push(result('graph', 'INVALID', 'graph-invalid', error.message))
      return report(components, payload)
    }
    throw error
  }
  components.push(result('graph', 'VALID', 'graph-valid',
    'IDs, roots, DAG, references, and kind rules are valid'))
  const proofComponents = verifyRecordProofs(payload, policy)
  components.push(...proofComponents)
  components.push(...verifyEvidenceSemantics(payload, proofComponents, policy))
  components.push(...verifyFreshness(payload, policy))
  return report(components, payload)
}
