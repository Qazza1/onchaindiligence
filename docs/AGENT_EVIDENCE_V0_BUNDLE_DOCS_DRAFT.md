# Portable evidence bundle docs -- DRAFT wording (D4.2 integration/UX prep)

**Status: the core-verifier gate has LIFTED.** Section 14.7 items 1-5 have
landed in both reference implementations: broadened attestation purposes,
`bundle_integrity` / `artifact_verifications[]` separation, unknown-artifact-
family UNVERIFIABLE, embedded-receipt proof verification, and reconciliation
reference resolution. The five paragraphs below are now accurate statements
about the shipped verifiers.

**Still do not publish yet**, for a different reason than before: no published
surface can create or verify a bundle. The CLI has no bundle path, the SDK
exports no bundle verification, and `createBundlePayload` cannot emit the
`issuer` / `reconciliation` / `limitations` fields this copy describes. Copy
that tells a reader "you can verify a bundle offline" should ship in the same
change that gives them a command to do it -- see section 6 of the D4.2
integration/UX report for the remaining wiring.

Each block below is written as end-user-facing prose, sized for the
`docs.html` "Offline verification" section (D4.1) or a future dedicated
bundle section next to it.

---

## What a bundle proves

> A signed portable evidence bundle proves that an identified issuer sealed an
> exact set of evidence artifacts together, at a stated time, and that the set
> has not been added to, removed from, or altered since. Each artifact
> embedded in the bundle keeps its own independent signature and can be
> verified on its own, outside the bundle, exactly as if it had been handed to
> you separately.

## What it does not prove

> Bundle validity proves cryptographic integrity under the verifier contract.
> It does not by itself prove authorization, safety, settlement, delivery,
> compliance, service quality, or economic outcome. A bundle can be
> cryptographically perfect and still describe an action that was never
> authorized, never settled, or later reversed -- the bundle only tells you
> that the evidence describing it hasn't been tampered with.

## Who signed what (assembly is not endorsement)

> A bundle carries two different kinds of signature, and they mean different
> things. Each artifact inside was signed by whoever issued it, when they
> issued it. The bundle as a whole was signed by whoever assembled it --
> usually you, on your own machine, with your own key, from artifacts you
> already held. The outer signature proves that assembler collected exactly
> these artifacts together and that nobody has changed the set since. It does
> not mean OnChainDiligence endorses, republished, or re-checked what is
> inside, and it does not extend anyone's attestation to anything else in the
> bundle. Every embedded artifact carries exactly the authority its own
> signature already carried -- being placed in a bundle adds none.

## Outer bundle validity vs. child validity

> A bundle has two things worth knowing separately: whether the bundle itself
> was sealed intact (nothing added, removed, or changed since signing), and
> whether each artifact inside it independently checks out. A cryptographically
> valid bundle does **not** mean every artifact inside it is valid -- one
> artifact can fail verification (a bad signature, an untrusted key) while the
> bundle it's sealed inside remains genuinely, verifiably unmodified. Treat
> these as two questions, not one: "was this bundle tampered with?" and "does
> each thing inside it hold up?"

## Offline verification

> Verifying a bundle needs no network access. You supply the public keys you
> trust; the verifier checks the bundle's signature, checks that its contents
> match exactly what was signed, and checks each embedded artifact against
> your trust list -- all locally. It never fetches a key or a missing artifact
> on your behalf, and it never treats a key embedded in the bundle itself as
> trusted just because it's there. If you don't supply a key, an artifact
> signed by it is UNVERIFIABLE, not silently accepted and not silently
> rejected.

## Unknown artifact handling

> A bundle can carry an artifact type the verifier doesn't recognize. That
> artifact still counts toward the bundle's own tamper-evidence (removing or
> altering it still invalidates the bundle), but the verifier reports it as
> UNVERIFIABLE rather than guessing at its meaning or silently trusting it. An
> unrecognized artifact type is never treated as equivalent to a recognized,
> independently checked one.

---

## Implementation note for whoever publishes this

All five paragraphs now match shipped verifier behavior, including "Outer
bundle validity vs. child validity" (section 14.3, `bundle_integrity` +
`artifact_verifications[]`) and "Unknown artifact handling" (section 14.4,
`unknown-artifact-family` → UNVERIFIABLE), which were the two previously
blocked on core work.

One accuracy caveat to carry into whatever ships: the "What a bundle proves"
paragraph says each embedded artifact "can be verified on its own." That is
true, but for a `public-action-receipt.v1` the dedicated
`verifyReceiptEnvelope` is stricter than the in-bundle check (it pins the
attestation purpose and recomputes `receipt_digest`/`receipt_id` -- see
section 14.6). Do not write copy implying the two always agree; they can
disagree about the same receipt today.
