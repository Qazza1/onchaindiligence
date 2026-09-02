import { SchemaValidationError, TrustPolicyError } from './errors.js'
import { validateDocument } from './schema.js'
import { TrustPolicy, type TrustPolicyOptions } from './trust.js'
import type { AttestationKeyRecord, JsonObject } from './types.js'

/**
 * Agent Evidence Interoperability Profile v1 — public signer key registry.
 *
 * See docs/AGENT_EVIDENCE_INTEROP.md for the full profile. This module parses
 * and validates the WIRE format any issuer (ArcFX is the current production
 * reference) can publish at `GET /.well-known/agent-evidence-keys`, and maps
 * validated entries into the existing `AttestationKeyRecord` shape so they
 * flow through the same `TrustPolicy` / `evaluateKeyLifecycle` machinery as
 * every other trusted key in this package — no second lifecycle model.
 *
 * This module does NOT fetch anything over the network. Network fetching is
 * the caller's concern (see the profile doc for the recommended pattern); the
 * core SDK stays fully usable offline. Hosting this endpoint is a discovery
 * convenience only — it does not by itself make an issuer trustworthy, and an
 * embedded bundle key never establishes trust regardless of what any registry
 * says. Trust is always the caller's `TrustPolicy`.
 */

export interface AgentEvidenceKeyRegistryEntry extends JsonObject {
  key_id: string
  algorithm: 'Ed25519'
  public_key_pem: string
  valid_from: string | null
  valid_until: string | null
  revoked_at: string | null
  status: 'active' | 'retired' | 'revoked' | 'compromised'
}

export interface AgentEvidenceKeyRegistry extends JsonObject {
  schema_version: 1
  issuer: string
  environment: string
  keys: AgentEvidenceKeyRegistryEntry[]
}

export interface ParseAgentEvidenceKeyRegistryOptions {
  /** Reject the registry unless `issuer` equals exactly this string. */
  expectedIssuer?: string
  /** Reject the registry unless `environment` equals exactly this string. */
  expectedEnvironment?: string
}

/**
 * Validates untrusted parsed JSON as an Agent Evidence key registry (schema
 * `agent-evidence-key-registry.schema.json`), optionally pinning the exact
 * `issuer`/`environment` a caller expects.
 *
 * Fails closed: throws `TrustPolicyError` on any structural violation
 * (missing/extra fields, wrong types, a malformed key entry anywhere in the
 * array, an issuer/environment mismatch) rather than returning a partial or
 * best-effort result. A caller integrating this over the network should treat
 * a thrown error here — like a failed fetch — as "no trust available from
 * this source" (typically UNVERIFIABLE for anything that key would have
 * signed), never as INVALID: an unreachable or misconfigured registry is not
 * evidence that a bundle's signature is fraudulent.
 *
 * `key_id` alone is never sufficient to establish trust, and this function
 * does not establish trust either — it only validates shape. Feed the result
 * to `trustPolicyFromKeyRegistry`, or your own mapping, to actually build a
 * `TrustPolicy`.
 */
export function parseAgentEvidenceKeyRegistry(
  payload: unknown,
  options: ParseAgentEvidenceKeyRegistryOptions = {},
): AgentEvidenceKeyRegistry {
  try {
    validateDocument('agent-evidence-key-registry.schema.json', payload)
  } catch (error) {
    if (error instanceof SchemaValidationError) throw new TrustPolicyError(error.message, { cause: error })
    throw error
  }
  const registry = payload as AgentEvidenceKeyRegistry
  if (options.expectedIssuer !== undefined && registry.issuer !== options.expectedIssuer) {
    throw new TrustPolicyError(
      `registry issuer "${registry.issuer}" does not match the expected issuer "${options.expectedIssuer}"`,
    )
  }
  if (options.expectedEnvironment !== undefined && registry.environment !== options.expectedEnvironment) {
    throw new TrustPolicyError(
      `registry environment "${registry.environment}" does not match the expected environment "${options.expectedEnvironment}"`,
    )
  }
  return registry
}

/**
 * Maps one validated registry entry onto the package's own trusted-key record
 * shape. The internal `AttestationKeyRecord` model requires an "active" key to
 * carry no `valid_until` (open-ended) -- a bounded validity window is what
 * "retired" means internally. A generic registry has no such constraint (an
 * issuer's own "active" just means "not revoked"), so a registry-reported
 * active key with a bounded `valid_until` maps to the internal "retired"
 * status; the underlying lifecycle window is honored either way via
 * `evaluateKeyLifecycle`, only the label changes.
 */
function toAttestationKeyRecord(entry: AgentEvidenceKeyRegistryEntry): AttestationKeyRecord {
  const revoked = entry.status === 'revoked' || entry.status === 'compromised'
  const status = entry.status === 'active' && entry.valid_until !== null ? 'retired' : entry.status
  return {
    key_id: entry.key_id,
    algorithm: 'ed25519',
    public_key_pem: entry.public_key_pem,
    status,
    valid_from: entry.valid_from,
    valid_until: entry.valid_until,
    status_changed_at: revoked ? entry.revoked_at : entry.valid_from,
    replacement_key_id: null,
    compromised_at: entry.status === 'compromised' ? entry.revoked_at : null,
    ...(revoked ? { status_reason: `registry-reported ${entry.status} at ${entry.revoked_at ?? 'unknown time'}` } : {}),
  }
}

/**
 * Parses and validates an Agent Evidence key registry, then constructs a
 * `TrustPolicy` from its keys — the recommended one-call path from an
 * untrusted registry payload to a usable trust policy.
 *
 * Equivalent to `TrustPolicy.fromKeyRecords(parseAgentEvidenceKeyRegistry(payload, opts).keys.map(...), trustPolicyOptions)`,
 * so it inherits every existing `TrustPolicy`/`evaluateKeyLifecycle` guarantee:
 * a revoked or compromised key still fails closed to INVALID when it signs
 * something, a key with no `valid_from` is UNVERIFIABLE, and so on — this
 * function adds no new trust semantics, only a convenient on-ramp into the
 * existing ones.
 */
export function trustPolicyFromKeyRegistry(
  payload: unknown,
  options: ParseAgentEvidenceKeyRegistryOptions & { trustPolicy?: TrustPolicyOptions } = {},
): TrustPolicy {
  const registry = parseAgentEvidenceKeyRegistry(payload, options)
  return TrustPolicy.fromKeyRecords(registry.keys.map(toAttestationKeyRecord), options.trustPolicy)
}
