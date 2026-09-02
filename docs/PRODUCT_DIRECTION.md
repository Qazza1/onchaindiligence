# OnChainDiligence product direction

Status: governing product direction
Last updated: 2026-08-27

## Positioning

OnChainDiligence is becoming **verifiable evidence infrastructure for autonomous
agents**, built first for agents that move money or perform other
high-consequence financial and onchain actions.

> OnChainDiligence creates independently verifiable evidence of what AI agents
> were authorized to do, what they observed, why they acted, and what happened
> next.

The product's central question is:

> **Can you prove why this agent did that?**

The long-term model is:

`Mandate -> Evidence -> Policy -> Decision -> Execution -> Verification`

## Initial customer

The first users are developers of agent wallets, treasury agents, autonomous
payments, stablecoin infrastructure, trading agents, institutional DeFi,
financial MCP servers, and compliance-sensitive fintech agents. The initial
vertical is deliberately narrow: **agents that move money**.

## Problem owned by OnChainDiligence

Normal application and observability logs are useful but remain controlled by
their operator. A consequential agent action needs a portable record that a
different party can verify without relying on the operator's database or the
OnChainDiligence website.

OnChainDiligence owns the evidence and decision-provenance layer:

- bind a principal and mandate to an agent run;
- preserve signed or witnessed observations from multiple sources;
- identify the policy associated with a decision;
- make decisions cite the exact evidence they claim to depend on;
- attach an execution without overstating causality;
- make omission, substitution, mutation, and graph tampering detectable;
- preserve historical verification through normal key rotation; and
- support offline verification with an explicit trust policy.

## What the product does not solve

OnChainDiligence is not a universal identity provider, authorization platform,
policy engine, observability backend, wallet, custodian, or oracle of truth. It
records references and proofs produced by those systems instead of replacing
them.

An attestation proves what its signer observed or asserted. It does not prove
that the underlying real-world claim is objectively true. A recorded decision
does not prove the decision was correct. An execution record does not prove
causality unless the supplied authorization and execution proofs establish it.
An external anchor proves a commitment existed no later than a checkpoint; it
does not make the committed claim true.

## Existing production product

The current compliance API is the first production Evidence Provider. Existing
wallet sanctions, OFAC name, UK Companies House, SEC EDGAR, diligence, verdict,
Ed25519 attestation, key publication, browser verification, anchoring, SDK,
CLI, Action, MCP, investigation, and indexer capabilities are retained where
they are real and correctly represented. The Agent Evidence Interoperability
Profile (`docs/AGENT_EVIDENCE_INTEROP.md`) generalizes the working ArcFX
integration -- public signer discovery and a browser verifier handoff -- into
conventions any other agent application can implement.

Existing `onchaindiligence.attestation.v2` signatures keep their exact meaning.
They are not silently reinterpreted as Agent Evidence v0. A v2 envelope can be
embedded byte-for-byte as evidence inside a new bundle, allowing old clients
and new bundle verifiers to coexist.

## Product principles

1. Integrity and truth are different claims.
2. Trust mode is explicit for every evidence assertion.
3. Evidence remains portable and user-controlled by default.
4. A database may index bundles but is not the verification root.
5. Uncertainty is never reported as success.
6. Signing and verification formats are versioned and independently specified.
7. Existing production interfaces change only through additive, versioned
   migration.
8. Blockchain is optional infrastructure for historical existence, not the
   product headline.
9. Production vertical slices ship before speculative UI or broad platform
   work.
10. The website only claims capabilities that are operational.

## Product success

The pivot is successful when an external developer can construct a run with a
principal and mandate, collect evidence from several real sources, record a
policy-linked decision, attach a real execution, export the bundle, and hand it
to another party who can verify its integrity, graph, signers, trust modes, key
history, and tamper state offline.
