# P1.9 TypeScript package decision

Date: 2026-08-30

P1.9 ships as the focused `@onchaindiligence/agent-evidence` package rather
than adding the protocol implementation to `@onchaindiligence/sdk`.

The existing SDK is an online compliance client with MPP/Tempo and Viem peer
dependencies. Agent Evidence construction and verification is a separate,
offline Node.js concern with bundled JSON Schemas, Ed25519/DSSE cryptography,
strict parsing, graph validation, explicit trust policy, and independent
protocol-security versioning. Folding it into the SDK would enlarge the
dependency and security surface for existing API users and blur online API
trust with offline verifier trust.

The focused package therefore has:

- no OnChainDiligence API dependency;
- no wallet, chain, MPP, x402, database, or hosted-verification dependency;
- Node built-in cryptography plus Ajv and `ajv-formats` only;
- ESM and TypeScript declarations;
- packaged schemas and conformance vectors;
- package version `0.2.0`, independent of Agent Evidence protocol v0;
- an external packed-artifact consumer test outside `src`;
- a caller-controlled signing and trust boundary.

`@onchaindiligence/agent-evidence@0.2.0` is publicly available on npm. It adds
the registry, interoperability, Technocore, and tclk/1 public surfaces while
retaining caller-controlled offline tri-state verification. Releases use the
GitHub OIDC Trusted Publishing workflow.
