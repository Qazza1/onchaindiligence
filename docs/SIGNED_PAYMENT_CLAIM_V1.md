# Signed Payment Claim v1

Signed Payment Claim v1 is a portable, platform-signed assertion about a payment execution. It lets a payment platform sign the exact claim it makes without giving OnChainDiligence custody, authority to execute, or the ability to alter the platform's controls.

It is **not** a settlement receipt, authorization, proof of delivery, safety statement, or compliance conclusion. A successful verification result has scope `PLATFORM_CLAIM_SIGNATURE`: it proves only that a key the verifier explicitly trusts for the issuer signed the exact claim bytes.

## Payload and signing

The payload family is `onchaindiligence.signed-claim.payment.v1`; its DSSE v1 payload type is `application/vnd.onchaindiligence.signed-claim.payment.v1+json`. Claims use Ed25519 over DSSE PAE and RFC8785 canonical JSON. `claim_id` is the SHA-256 content ID of the canonical claim with `claim_id` omitted.

The canonical schema is [signed-claim-payment.v1.schema.json](../spec/agent-evidence/v0/schema/signed-claim-payment.v1.schema.json). Required data is deliberately small: issuer HTTPS origin, issuance time, provider reference, payment network, claimed execution status, and an empty or explicitly populated `extensions` object. Amount, asset, sender, recipient, transaction hash, OCD links, and evidence digest are optional because a platform may not know them.

## Trust and verification

Core verification is offline and never fetches a key. The caller supplies an existing Agent Evidence `TrustPolicy`, normally built from issuer key material obtained separately. Issuers may publish discovery material at `https://issuer.example/.well-known/agent-evidence-keys`; fetching and accepting it is outside this format and must remain a caller-controlled trust decision.

Verification returns `VALID`, `INVALID`, or `UNVERIFIABLE`. An absent trusted key is `UNVERIFIABLE`; an invalid signature, wrong type, malformed claim, inconsistent `claim_id`, expired/not-yet-valid key, revoked key, or issuer mismatch is `INVALID`.

## Agent Evidence embedding

An embedded claim is evidence type `onchaindiligence.signed-claim.payment.v1`, with `trust_mode: publisher-signed`. Its embedded response value must exactly equal the DSSE envelope in its `dsse-ed25519-v1` source proof, and both the response and proof use the claim payload type above. The bundle verifier then reports the platform-claim result separately from any independent settlement observation or receipt proof.

## Privacy and lifecycle

Do not put customer PII, wallet secrets, credentials, or full provider logs in a claim. Use a provider reference, opaque client submission key, or a digest where correlation is needed. Issuers should publish versioned public keys and lifecycle status; verifiers must not treat an untrusted key, a current key alone, or an issuer URL as sufficient trust.

Phase 1 is portable evidence only. It does not add server ingestion, receipt changes, new payment rails, key fetching, or provider-specific settlement logic.
