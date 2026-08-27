# Agent Evidence threat model

Status: v0 design threat model
Last updated: 2026-08-27

## Security objectives

The system aims to detect alteration, substitution, omission relative to a
sealed manifest, invalid graph relationships, and untrusted source attribution.
It aims to preserve historical verification across normal rotation and make
uncertainty explicit. It does not guarantee source honesty, real-world truth,
decision correctness, or causal execution unless additional proofs establish
those properties.

## Trust boundaries

- principal and authorization system;
- agent runtime and model;
- publisher, managed witness, and local witness;
- MCP/HTTP/payment transports;
- OnChainDiligence signing service and key registry;
- portable bundle builder/sealer;
- verifier and its out-of-band trust policy;
- optional database, object store, transparency log, and blockchain anchor.

## Threats

| Threat | Attacker capability | Impact | Mitigation | Residual risk |
|---|---|---|---|---|
| Compromised signing key | Uses a publisher or bundle private key | Forges authentic-looking assertions | Isolated secret storage, unique purpose keys, validity intervals, rapid status publication, emergency rotation, pinned registry snapshots, monitoring | Offline verifiers with stale trust data may accept post-compromise signatures; v0 rejects a key marked compromised rather than reconstructing a pre-compromise boundary without external time |
| Malicious evidence provider | Correctly signs false or selective data | Strong integrity over a lie | Explicit publisher identity/trust mode/scope, corroborating sources, policy controls, precise copy | Cryptography cannot make a dishonest source truthful |
| Malicious managed witness | Signs a fabricated observation | False `managed-witness` evidence | Hardened fetch path, request/response digests, audit logs, optional upstream receipts, separation from publisher-signed status | Customer still trusts witness operation |
| Compromised local witness | Attacker controls customer-side witness | Fabricated private observations | Per-install keys, least privilege, hardware-backed keys where possible, attested deployment references, revocation | Customer environment compromise may defeat local guarantees |
| Compromised agent | Chooses/omits evidence or fabricates assertions | Misleading decision provenance | Distinguish agent assertions, mandate constraints, required evidence policy, independent witnesses, sealed root manifest | Agent may exploit evidence that is valid but incomplete unless policy requires coverage |
| Compromised principal | Issues malicious mandate or loses identity control | Apparently authorized harmful action | External identity/auth proof, short mandate validity, limits, revocation evidence, strong authentication | Evidence can prove authorization was presented, not that the human intended it |
| Compromised MCP server | Alters tool schemas/results/annotations | False tool evidence | Treat annotations as untrusted, publisher/local witness signatures, exact tool identity, MCP authorization, content digests | A trusted but malicious MCP publisher can still lie |
| Upstream API lies | Returns incorrect data to a witness | Incorrect but faithfully observed evidence | Label managed observation, preserve scope/source/time, use publisher signatures or corroboration when available | Witness cannot establish objective truth |
| Response tampering | Modifies bytes after production | Changed evidence accepted | Source signatures, node IDs, bundle DSSE signature | None for supported cryptography if trust material is correct; metadata outside signed payload remains untrusted |
| Evidence omission | Removes an inconvenient node | Decision appears better supported | Decision's explicit references, root manifest, bundle ID/signature, policy-required evidence classes | A malicious sealer can omit evidence before sealing unless an external policy or source log detects it |
| Evidence substitution | Replaces a node or reference | Decision points to different input | Content-addressed IDs, exact references, record-kind invariants, signature verification | Semantically equivalent but differently encoded data yields a new ID, by design |
| Replay | Reuses valid old evidence/run/mandate | Action based on old authorization/data | Unique run/mandate IDs, validity periods, freshness policy, execution nonce/transaction binding | Signature validity alone does not prevent business replay |
| Stale evidence | Uses old but validly signed observation | Bad current decision | `observed_at`, `expires_at`, policy max age, separate freshness result | Source and verifier clocks may differ |
| Timestamp manipulation | Signer lies about time or clock is wrong | False historical narrative/key-window bypass | Validity checks, bounded future skew, independent transparency/anchor timestamp | Without external time, signed timestamps remain assertions |
| Graph reordering | Reorders records/parents | Non-deterministic IDs or verifier disagreement | Required lexical ordering and RFC8785 payload | Ordering is not semantic beyond deterministic encoding |
| Missing parent | Deletes dependency | Broken provenance hidden | Resolve every parent, recompute roots, reject missing IDs | None for a sealed supported bundle |
| Cyclic graph | Crafts recursion/resource exhaustion | Verifier crash or ambiguous provenance | Bounded parse and complete topological cycle detection | Very large valid DAGs still require configured resource limits |
| Signature downgrade | Removes v2 fields to trigger legacy path | Verifies different bytes/rules | Explicit version dispatch; legacy only when `schema_version` is absent in a recognized legacy envelope; no fallback after v0/v2 failure | Legacy format remains weaker but historically necessary |
| Version downgrade | Changes bundle/version hints | Old parser accepts altered meaning | Signed inner version, outer/inner equality, unsupported critical versions are `UNVERIFIABLE` | Old deployed verifiers cannot understand later versions; clients need update policy |
| Unknown key injection | Embeds attacker key beside signature | Self-signed evidence appears trusted | Embedded keys are hints only; out-of-band pinned policy; derive key ID from SPKI | Users can still choose an unsafe trust policy |
| Key registry compromise | Alters live key/status responses | Attacker key or hidden compromise accepted | Signed/pinned snapshots, offline trust root, threshold/offline root plan, monotonic snapshot versions, HTTPS | Initial trust/bootstrap remains an operational responsibility |
| Key rotation failure | Old key removed or intervals overlap incorrectly | Historical records fail or ambiguous signer | Immutable history, pre-publish retiring key, interval validation, cross-client rotation canary, never delete historical public keys | Manual production configuration can still be wrong until automated custody exists |
| Anchor failure | Chain/log unavailable or transaction missing | False historical-existence claim | Anchoring optional and separately reported; require receipt/inclusion proof before `anchored` | Signed evidence remains valid but lacks external time |
| Anchor issuer compromise | Adds arbitrary hashes | Misleading existence entries | API authenticates complete attestations before anchoring, separate hot issuer/multisig owner, rotate and record incident window | Contract cannot delete unauthorized append-only entries |
| SSRF in managed witness | Requests internal/cloud metadata endpoints | Secret/network disclosure | No unrestricted proxy; HTTPS allowlists, IP-range denial, DNS pin/recheck, redirect policy, size/time limits, auth/rate limits | Complex DNS/proxy stacks need dedicated review and tests |
| Credential leakage | Logs or embeds API/payment/signing secrets | Account/key compromise | Digest sensitive inputs, redaction, isolated signer, constrained child environments, no secret logging | User-supplied payloads may contain secrets unless scanning/policy blocks them |
| Privacy leakage | Portable bundle contains PII or commercial data | Unauthorized disclosure | Data minimization, digest/reference mode, encryption outside v0, access control for hosted copies, warnings | Portable plaintext bundles are readable by every recipient |
| Bundle truncation | Removes terminal records while leaving a valid subgraph | Hides decision/execution | Signed `root_ids`, exact bundle ID/signature, expected run/policy checks | A deliberately sealed partial bundle must be identified by policy/context |
| Selective disclosure misuse | Shares only favorable evidence | Misleading third party | V0 does not claim redaction-safe selective disclosure; verifier reports bundle scope/root; disclose original sealed bundle | No cryptographic proof of completeness against data never committed |
| Decision reference change | Adds/removes evidence or changes policy digest | False rationale | Content-addressed decision, exact parent union, bundle signature | A malicious agent can make a new, validly signed decision assertion |
| Execution mutation | Changes recipient/amount/hash/status | Misrepresents action | Execution record digest, bundle signature, external chain/payment receipt verification | External confirmation may be unavailable offline; causality remains limited |
| Canonicalization differential | Runtimes compute different bytes | False rejects or cross-language ambiguity | RFC8785, I-JSON constraints, official conformance corpus, DSSE exact-byte verification | Existing legacy v1 remains runtime-order dependent |
| Parser/resource attack | Deep/large/duplicate-key JSON | Crash, bypass, denial of service | Duplicate-key rejection, byte/depth/count/string limits before crypto/graph work | Limits may reject legitimate unusually large bundles; callers can use an explicit higher trusted limit |

## Required security tests

The release gate includes good signature, one-byte mutation, wrong/unknown key,
retired-key historical validity, compromised key, rotation, unsupported
version, duplicate JSON keys, canonicalization vectors, changed/removed node,
changed parent, missing parent, cycle, duplicate ID, root truncation, changed
decision evidence/policy, changed execution, stale evidence, corrupted DSSE,
legacy v1/v2 compatibility, and anchor inclusion/timestamp failure behavior.

Managed-witness work additionally requires dedicated SSRF, DNS rebinding,
redirect, protocol, body-size, timeout, credential, and private-address tests
before deployment.
