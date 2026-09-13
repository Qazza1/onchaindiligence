# Portable evidence bundle docs -- DRAFT wording (D4.2 integration/UX prep)

**Status: draft only. Do not publish to onchaindiligence.com/onchaindilige-site
until Codex's core verifier work (`docs/AGENT_EVIDENCE_V0.md` section 14.7)
ships** -- specifically items 1-2 (broadened attestation purposes,
`bundle_integrity` / `artifact_verifications[]` separation). Publishing this
wording before then would describe a distinction (bundle-valid-but-child-
invalid staying visible) that today's `verify_bundle()` does not actually
make -- see section 14.3. This file exists so the exact copy is ready the
moment that lands, not to be shipped now.

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

The "Outer bundle validity vs. child validity" and "Unknown artifact
handling" paragraphs describe the *target* behavior specified in
`docs/AGENT_EVIDENCE_V0.md` section 14, not what `verify_bundle()` /
`verifyBundle()` do today (section 14.3, 14.4: both currently collapse into
one aggregate state, and an unrecognized-but-well-formed artifact type
currently reports VALID, not UNVERIFIABLE). Ship these two paragraphs only
once Codex's core work lands; "What a bundle proves" / "does not prove" /
"Offline verification" are already accurate today at the single-artifact
level (D4.1) and become accurate at the bundle level as soon as
`bundle-payload.schema.json`'s D4.2 additions have any real producer, which is
also gated on Codex's `createBundlePayload` update (see the main D4.2
integration/UX report, section 6).
