/**
 * Immutable history for attestation keys that are no longer active.
 *
 * Rotation procedure:
 * 1. Before replacing the private key, copy the current public record here.
 * 2. Mark it `retired` for an ordinary rotation, or `compromised`/`revoked`
 *    when past signatures must carry a trust warning.
 * 3. Commit and deploy this history before changing the production key.
 *
 * Public keys are intentionally public. Private keys never belong here.
 */
export type AttestationKeyStatus = 'active' | 'retired' | 'revoked' | 'compromised'

export interface AttestationKeyRecord {
  key_id: string
  algorithm: 'ed25519'
  public_key_pem: string
  status: AttestationKeyStatus
  valid_from: string | null
  valid_until: string | null
  status_changed_at: string | null
  status_reason?: string
}

export const HISTORICAL_ATTESTATION_KEYS: readonly AttestationKeyRecord[] = []
