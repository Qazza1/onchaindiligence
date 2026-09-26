# Signed Payment Claim v1

Signed Payment Claim v1 is a portable, platform-signed assertion about a payment execution. It lets a payment platform sign the exact claim it makes without giving OnChainDiligence custody, authority to execute, or the ability to alter the platform's controls.

It is **not** a settlement receipt, authorization, proof of delivery, safety statement, or compliance conclusion. A successful verification result has scope `PLATFORM_CLAIM_SIGNATURE`: it proves only that a key the verifier explicitly trusts for the issuer signed the exact claim bytes.

## Payload and signing

The payload family is `onchaindiligence.signed-claim.payment.v1`; its DSSE v1 payload type is `application/vnd.onchaindiligence.signed-claim.payment.v1+json`. Claims use Ed25519 over DSSE PAE and RFC8785 canonical JSON. `claim_id` is the SHA-256 content ID of the canonical claim with `claim_id` omitted.

The canonical schema is [signed-claim-payment.v1.schema.json](../spec/agent-evidence/v0/schema/signed-claim-payment.v1.schema.json). Required data is deliberately small: issuer HTTPS origin, issuance time, provider reference, payment network, claimed execution status, and an empty or explicitly populated `extensions` object. Amount, asset, sender, recipient, transaction hash, OCD links, and evidence digest are optional because a platform may not know them.

## Trust and verification

Core verification is offline and never fetches a key. The caller supplies an existing Agent Evidence `TrustPolicy` with an explicit `paymentClaimIssuerKeyIds` mapping from issuer origin to trusted key IDs. A key in general caller trust is not automatically trusted for every issuer; absent issuer/key binding is `UNVERIFIABLE`. Issuers may publish discovery material at `https://issuer.example/.well-known/agent-evidence-keys`; fetching and accepting it is outside this format and must remain a caller-controlled trust decision.

Verification returns `VALID`, `INVALID`, or `UNVERIFIABLE`. An absent trusted key is `UNVERIFIABLE`; an invalid signature, wrong type, malformed claim, inconsistent `claim_id`, expired/not-yet-valid key, revoked key, or issuer mismatch is `INVALID`.

An issuer ID is a canonical HTTPS origin: a lowercase hostname, no path, query, fragment, userinfo, or trailing slash; default port `:443` is omitted, while a non-default port through `65535` is permitted. This rule is identical in the TypeScript and Python verifiers.

## Agent Evidence embedding

An embedded claim is evidence type `onchaindiligence.signed-claim.payment.v1`, with `trust_mode: publisher-signed`. Its embedded response value must exactly equal the DSSE envelope in its `dsse-ed25519-v1` source proof, and both the response and proof use the claim payload type above. The bundle verifier then reports the platform-claim result separately from any independent settlement observation or receipt proof.

## Privacy and lifecycle

Do not put customer PII, wallet secrets, credentials, or full provider logs in a claim. Use a provider reference, opaque client submission key, or a digest where correlation is needed. Issuers should publish versioned public keys and lifecycle status; verifiers must not treat an untrusted key, a current key alone, or an issuer URL as sufficient trust.

Phase 1 is portable evidence only. It does not add server ingestion, receipt changes, new payment rails, key fetching, or provider-specific settlement logic.

## Correlation and reconciliation

Correlation strength is, from strongest to weakest: an `ocd_execution_request_id` with matching `provider_reference`; a `provider_reference` matching the durable execution binding; an independently observed `transaction_hash`; and operation or preflight IDs alone, which remain assertions. Address or amount similarity alone does not establish linkage. Signed Payment Claim v1 does not change `deriveBindingStrength`.

A valid platform signature never suppresses reconciliation findings. A claim for transaction A against independent observation of B, or recipient X against Y, remains a `CONTRADICTION`. A `SUCCEEDED` claim while observation is pending or unavailable is `INSUFFICIENT_EVIDENCE`; so is a valid signature without enough settlement evidence. This format creates no new findings taxonomy.

## Versioning and domain separation

Payment v1 is immutable once released. Future action families are siblings, for example `signed-claim.swap.v1`, `signed-claim.bridge.v1`, `signed-claim.staking.v1`, and `signed-claim.allowance.v1`; Payment v1 will not become a universal action schema.

The DSSE payload type is domain-separated from Public Action Receipt v1. A Signed Payment Claim cannot verify as an OCD Action Receipt, and a receipt cannot verify as a Signed Payment Claim.
