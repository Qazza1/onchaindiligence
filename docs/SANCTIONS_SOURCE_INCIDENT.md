# Wallet sanctions source incident: canonical API containment

Companion to `Qazza1/onchaindiligence-mcp` PR #65 (`docs/SANCTIONS_SOURCE_INCIDENT.md` there has the
source facts, the OFAC entry and the proposed permanent replacement). This change contains the same
defect in this repository. It adds **no** replacement provider.

## What was vulnerable
`screenAddress()` returned the Chainalysis oracle's boolean with no freshness check. The oracle is
deprecated (last update 2026-03-18), so an address OFAC lists today (reported:
`0x252a8bd2319d8a555b872990601221b3a2053bce`) could read `false`, and the API would sign and charge for
`sanctioned: false`, a `PASS` verdict, or a clean diligence wallet check. A reachable RPC (`/health`) was
treated as proof of coverage.

## Containment
| Surface | Behaviour now |
| --- | --- |
| `GET /screen/:address`, `GET /web/screen/:address` | 503 `sanctions_screening_unavailable`, before payment |
| `GET /verdict/:address` | same |
| `GET /diligence?wallet=...` (with or without `company`) | same; company-only requests are unchanged |
| `GET /internal/verdict/:address` (MCP-delegated verdict) | same |
| `GET /internal/verdict/ready` | 503 `ready:false` |
| stdio MCP `screen_wallet`, `diligence` with `wallet` | tool error before the payment challenge |
| `GET /health` | `sanctions_oracle: "retired"`, overall `degraded` (503, as for any degraded upstream) |
| `screenAddress()` | validates the address, then always throws; no RPC read; no finding |

Unchanged: OFAC name screening, UK/US company checks, signing, receipts, key registry, anchoring,
sandbox (unsigned test vectors), and every historical attestation (not rewritten; previously signed wallet
results are historical claims, not current clearance).

## Remaining
Counterparty exposure inside the verdict is unreachable (the verdict is refused first) and would report
`partial` (never clean) if reached. Tooling that calls the oracle directly (`tools/p1_8/capture-providers.ts`,
`test/exposure.ts`) will now fail or no longer exercise a live oracle. A maintained OFAC-based source,
freshness policy and provenance binding are separate work (see the MCP incident document).

## Permanent remediation
Wallet screening now uses validated, freshness-checked snapshots of the official OFAC SDN List
digital currency address identifiers (`docs/OFAC_SDN_SCREENING.md`). The containment behaviour above is
what every wallet route still does whenever no current snapshot is available: `503
sanctions_screening_unavailable` (now with a `reason`) before payment, never a negative. The Chainalysis
oracle is never read; `src/chainalysis.ts` is removed. `tools/p1_8/capture-providers.ts` (a one-off
historical fixture capture tool, not built or run in CI) still imports it and no longer runs.
