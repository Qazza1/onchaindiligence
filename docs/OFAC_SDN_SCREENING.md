# Wallet screening: OFAC SDN digital currency addresses

Replacement for the retired Chainalysis oracle (`docs/SANCTIONS_SOURCE_INCIDENT.md`). The same design
and the same shared code run in this repository (canonical API) and in `Qazza1/onchaindiligence-mcp`.

## Claim

**Exact matching of an EVM-format address against the digital currency address identifiers on the
U.S. Treasury OFAC SDN List, in a validated snapshot that was confirmed against OFAC within the last
6 hours.** Nothing more:

- OFAC SDN List only: not the OFAC non-SDN (Consolidated) lists, EU, UN, UK or any other regime.
  The historical oracle's US/EU/UN coverage is **not** preserved.
- Identifiers only. OFAC says its address listings are not likely to be exhaustive (FAQ 562).
- EVM-format input only (`0x` + 40 hex). Other formats return `400 unsupported_address_format`, never
  "not listed", even though OFAC lists XBT, TRX, SOL and other addresses.
- No ownership, 50 Percent Rule, proximity, exposure or name analysis in this check. (The verdict adds
  its own bounded one-hop Tempo exposure signal, disclosed separately.)
- A non-match is not legal clearance and does not establish wallet ownership, beneficial ownership or
  safety. Every result carries these limits in `screening.limitations`, inside the signed data.

## Source

Verified on 2026-10-16 against the live service:

- `GET https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML` answers
  `302` to a short-lived pre-signed URL on the SLS publication bucket
  (`wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com/Published/<id>/<date>/<id>/SDN.XML`),
  which serves `text/xml` with `Content-Length` and an `x-amz-meta-publication-id` header. The legacy
  `treasury.gov/ofac/downloads/sdn.xml` URL redirects to the same service.
- Root `<sdnList xmlns="https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML">`,
  `<publshInformation>` (OFAC's spelling) with `<Publish_Date>MM/DD/YYYY` and `<Record_Count>`.
- Identifiers are `<sdnEntry><idList><id>` elements whose `<idType>` is `Digital Currency Address - <SYMBOL>`
  (structure documented in OFAC FAQ 563) and whose `<idNumber>` is the address.
- Publication of 2026-10-15: 29,231,187 bytes, SHA-256
  `5d1d98a80db5790ebba11eccaad0c597826bf54e52327c61258a364cd774f715`, 19,457 entries, 1,066 digital
  currency identifiers across 20 currency labels, 133 EVM-format identifiers (124 distinct addresses:
  ETH 120, USDT 8, USDC 2, ARB 1, BSC 1, ETC 1). Entry 24003 lists
  `0x252a8bd2319d8a555b872990601221b3a2053bce` as `Digital Currency Address - ETH`.
- OFAC FAQ 90 recommends refreshing from the comprehensive file rather than applying delta files, which
  is what the refresh does. OFAC publishes irregularly (FAQ 88 leaves the schedule to the institution).

The existing name-screening CSV index (`src/ofac.ts`) is not used: it drops the identifier fields.

## Data flow

```
OFAC SLS (SDN.XML) ──hourly──> MCP: POST /internal/sanctions/refresh  (src/ofacSdnRefresh.ts)
                                 download (allow-listed hosts, ≤200 MB, Content-Length checked, SHA-256)
                                 same SHA as active? ── yes ──> revalidated_at = now
                                 parse (src/ofacSdnDigitalCurrency.ts) + validate
                                 ok ──> one transaction: supersede previous, insert active + identifiers
                                 abnormal shrinkage ──> quarantined (needs approval by SHA-256)
                                 anything else ──> rejected; active snapshot untouched (and ages)
                                         │
                       Neon Postgres (the MCP's existing DATABASE_URL):
                       sanctions_snapshots / sanctions_snapshot_identifiers / sanctions_refresh_runs
                                         │ read per request (src/walletSanctions.ts)
                   ┌─────────────────────┴──────────────────────┐
           canonical API (SELECT-only role,              MCP service (DATABASE_URL)
           SANCTIONS_DATABASE_URL)
```

Triggers: `.github/workflows/ofac-sdn-refresh.yml` here (hourly; fails and notifies on any non-success or
if this API's `/health` stops reporting `ofac_sdn: current`) and a daily Vercel Cron on the MCP project
as a backstop. Both call the same token-protected endpoint (`CRON_SECRET`).

## Freshness

- A snapshot is usable only if it is the single `active` row, its parser version is supported, its digests
  are well-formed, and `now - revalidated_at <= SANCTIONS_MAX_STALENESS_HOURS` (default 6, clamped 1-24),
  with no future timestamps beyond 5 minutes of skew.
- `revalidated_at` moves only when the full file is downloaded again and its SHA-256 equals the active
  snapshot's. A publication date that is old is not by itself a failure (OFAC can go days without
  publishing); having not re-confirmed the official file recently is.
- Nothing is cached across requests. Each request reads the durable record, so every serverless instance
  applies the same rule. Within one paid request the snapshot judged usable before payment is pinned
  (`AsyncLocalStorage`) and reused after payment, so a paid request cannot fail on a second read, and the
  subject and every counterparty in a verdict are screened against the same snapshot.

## Validation before activation

Rejected outright: DTD/entity declarations, HTML, wrong root or namespace, missing closing root
(truncation), malformed entities, bad publish date or record count, `Record_Count` ≠ parsed entries,
duplicate entry or identifier UIDs, any `Digital Currency Address - ` text not extracted as an identifier,
bad currency labels or values, non-UTF-8 bytes, wrong content type, short or oversized downloads,
redirects off the allow-list, fewer than 5,000 entries / 200 identifiers / 25 EVM identifiers, publication
dates in the future (>36 h) or older than the active snapshot (rollback).

Quarantined: a drop of more than 5% in entries or more than 20% in digital currency / EVM identifiers
versus the active snapshot. A large delisting is legitimate (it happened for Tornado Cash in 2025), so the
candidate is stored for inspection and activated only when an operator approves that exact SHA-256.
Until then the active snapshot stops being revalidated and wallet screening fails closed after 6 hours.

## Contracts

Wallet screening data (`/screen`, `/web/screen`, `diligence.wallet_check`, MCP `screen_wallet`,
`/x402/screen`, `/x402/diligence`):

| Field | Meaning |
| --- | --- |
| `match_status` | `listed` or `not_listed` (new) |
| `sanctioned` | kept for compatibility: `true` iff `listed` |
| `matches[]` | `sdn_uid`, `sdn_name`, `sdn_type`, `programs`, `identifier_type`, `listed_value`, `entry_url` (new) |
| `identifications[]` | kept: `{category: 'OFAC SDN List', name, description, url}` per match |
| `screening` | `scope`, `coverage`, `matching`, `evaluated_at`, `dataset` (source URL/object, publication id/date, record count, retrieved/revalidated, source and index SHA-256, parser and matching versions, snapshot id), `limitations[]` (new) |
| `source`, `method`, `note` | now name the OFAC SDN source |

Verdict: `signals.sanctions` gains `match_status`, `matches`, `screening`; reasons and `verdict_basis.note`
name the OFAC SDN scope; `not_yet_evaluated` gains `other_sanctions_regimes`.

Errors: `503 {error: 'sanctions_screening_unavailable', reason, message}` before payment, with `reason` one
of `not_configured`, `store_unavailable`, `no_snapshot`, `stale`, `future_timestamp`, `not_active`,
`unsupported_parser_version`, `unsupported_dataset`, `invalid_record`. `400 {error:
'unsupported_address_format'}` for non-EVM addresses. `/health` keeps `upstreams.sanctions_oracle:
'retired'`, adds `upstreams.ofac_sdn` and `sanctions_data`, and is `200 ok` again once the snapshot is
current (and the other upstreams are reachable).

Compatibility: additions are additive; the attestation envelope, signing, purpose and key registry are
unchanged. A client that treats `sanctioned: false` as clearance was already wrong and stays wrong; the
signed `screening.limitations` now say so in the artifact. Wallet results signed before this change were
produced from the retired oracle; they verify as before and are not re-evaluated or rewritten.

## Ongoing cost (estimate)

OFAC data is free. One refresh per hour is one Vercel function run of roughly 10 s that downloads ~29 MB
and parses it in ~0.1 s; a new snapshot (~1,100 identifier rows, well under 1 MB with indexes) is written
only when OFAC publishes. Neon storage grows by at most a few tens of MB a year; the hourly write can wake
an otherwise idle database (up to ~2 compute-hours a day at the smallest size if nothing else keeps it
awake). Paid wallet routes and `/health` add one small query. The GitHub workflow runs in a public
repository (no minutes billed). Plans and prices were not checked; verify against the Vercel and Neon
dashboards.

## Rollout

1. Apply `db/schema.sql` in the MCP repo to the production Neon database (additive tables only).
2. Create a SELECT-only role for this API (run as the database owner; choose the password yourself):
   ```sql
   CREATE ROLE ocd_sanctions_reader LOGIN PASSWORD '<generated>';
   GRANT USAGE ON SCHEMA public TO ocd_sanctions_reader;
   GRANT SELECT ON sanctions_snapshots, sanctions_snapshot_identifiers TO ocd_sanctions_reader;
   ```
3. Env vars: MCP `CRON_SECRET` (≥32 random characters); this API `SANCTIONS_DATABASE_URL` (the reader
   role's connection string); GitHub secret `OFAC_REFRESH_TOKEN` in this repository = the MCP `CRON_SECRET`.
4. Merge and deploy the MCP change. Its wallet routes keep answering `503 no_snapshot` until step 5.
   Readers require parser `ocd-ofac-sdn-dca/2`; a prior `/1` index is unavailable until a refresh
   rebuilds it, even if OFAC's source bytes have not changed. Historical signed evidence is unchanged.
5. Trigger one refresh (`curl -X POST -H "Authorization: Bearer $CRON_SECRET" https://mcp.onchaindiligence.com/internal/sanctions/refresh`)
   and expect `200 {"outcome":"activated", ...}` with the expected `source_sha256` and `publish_date`.
6. Merge and deploy this change (a new deploy is needed for the env var). Check `GET /health` shows
   `ofac_sdn: current` and `GET /screen/0x252a8bd2319d8a555b872990601221b3a2053bce` answers `402` (do not pay).
7. Watch the first hourly workflow runs; any failure is an incident.

## Rollback and emergency stop

- **Stop all wallet screening immediately** (fail closed everywhere, no deploy needed):
  `UPDATE sanctions_snapshots SET status = 'superseded', status_reason = 'operator stop' WHERE status = 'active';`
  then disable the workflow and the Vercel Cron until the cause is fixed, or the next refresh re-activates.
- **Code rollback**: revert to the containment versions (API #15, MCP #65), which refuse wallet screening.
  Never roll back to code that reads the Chainalysis oracle.
- **Approve a quarantined publication**: inspect the row (`status = 'quarantined'`), confirm the change on
  OFAC Recent Actions, then run the workflow manually with `accept_shrinkage_sha256` set to its SHA-256.
