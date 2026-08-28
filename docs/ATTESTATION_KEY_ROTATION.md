# Attestation key lifecycle and rotation

This runbook governs the public Ed25519 keys used to sign OnChainDiligence
attestations. It deliberately separates ordinary rotation from emergency
compromise response. Never replace a key without first preserving its public
record and validity interval.

## Current production inventory (2026-08-27)

The public registry at `https://api.onchaindiligence.com/.well-known/attestation-keys`
currently publishes one active key:

- key ID: `ed25519-D8wfc7civVNG05Ds`
- status: `active`
- `valid_from`: `null`
- `valid_until`: `null`
- `status_changed_at`: `null`

The missing activation boundary means a verifier can validate the signature but
cannot prove that the key was valid at the claimed issuance time. Strict offline
verification must therefore return `UNVERIFIABLE` for this key. Do not infer an
activation time from a deployment, commit, log, or certificate timestamp.

Owner action: determine the earliest defensible activation instant from an
authoritative operational record, set `ATTESTATION_KEY_ACTIVATED_AT` to that
exact UTC timestamp, deploy, and archive the resulting registry document. If no
defensible boundary exists, rotate normally to a new key with a recorded
activation boundary; keep the current key's boundary unknown.

## Normal rotation

1. Choose and record a UTC activation instant for the new key. Assign an owner
   and change ticket.
2. Generate the Ed25519 key pair in the approved secrets environment. Never put
   private key material in source control, tickets, chat, or this registry.
3. Derive the new key ID from SHA-256 of its SPKI DER bytes using the production
   implementation. Independently verify the derived ID.
4. Add the new public record as `active` with `valid_from` and
   `status_changed_at` equal to the recorded activation instant.
5. Copy the old public record into `HISTORICAL_ATTESTATION_KEYS`, mark it
   `retired`, set `valid_until` and `status_changed_at` to the handover instant,
   and set `replacement_key_id` to the new key ID.
6. Run registry validation, attestation conformance tests, and an offline
   verification test for attestations immediately before and after the boundary.
7. Deploy the public registry/history first and confirm both keys are available.
   Do not switch signing while verifiers can only resolve the old record.
8. Activate the new private key at the recorded boundary. Confirm newly issued
   attestations use the new key and validate offline against the archived
   registry.
9. Archive the registry response, deployment evidence, test output, and change
   approval. Retain the retired public record indefinitely.

There must be no overlap ambiguity: the old key's `valid_until` and the new
key's `valid_from` define the handover. If the service cannot coordinate the
boundary precisely, pause issuance during rotation.

## Emergency compromise or revocation

1. Stop attestation issuance and anchoring immediately. Preserve logs and
   evidence; do not destroy or silently replace the affected key record.
2. Record when compromise is known or conservatively believed to have begun.
3. Mark the public record `compromised`, set `compromised_at`,
   `status_changed_at`, and a factual `status_reason`. Use `revoked` only when
   the key is invalidated for a reason that is not a known compromise, and still
   provide `status_changed_at` and `status_reason`.
4. Publish the status change before resuming issuance. Verifiers must treat
   attestations made by a compromised or revoked key as `INVALID`, not merely
   stale or unknown.
5. Generate and activate a replacement using the normal controls above. Set
   `replacement_key_id` on the affected record after the replacement is in the
   registry.
6. Identify affected attestations and anchors, notify relying parties, and
   preserve an incident record. Never rewrite historical status to make old
   signatures appear valid.
7. Resume only after registry, offline verifier, signing, and anchor tests pass
   with the replacement key.

## Required checks

The registry validator rejects duplicate IDs, malformed timestamps, key IDs
that do not match their SPKI public key, multiple active keys, invalid
intervals, incomplete retirement/compromise/revocation records, and missing or
self-referential replacement keys. A missing `valid_from` is exposed as a trust
warning for migration, and is a hard failure in strict validation.
