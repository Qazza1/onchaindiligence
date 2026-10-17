/**
 * walletSanctions.ts — SHARED MODULE.
 *
 * Keep this file byte-identical in Qazza1/onchaindiligence (src/) and
 * Qazza1/onchaindiligence-mcp (src/); both repos pin its SHA-256 in
 * test/ofacSdnScreening.ts.
 *
 * The one wallet-screening entry point for every route in both services.
 * It reads the ACTIVE OFAC SDN snapshot from the shared Postgres store (written
 * only by the MCP service's refresh job, see ofacSdnRefresh.ts there), refuses
 * unless that snapshot is fresh (assessSnapshot), and screens by exact match.
 *
 * Serverless model: nothing here caches a snapshot across requests. Freshness
 * is decided per request from the durable record, so every instance applies
 * the same rule. Within ONE paid request the snapshot judged usable before
 * payment is pinned (AsyncLocalStorage) and reused after payment, so a request
 * the caller has paid for cannot fail on a second store read, and every
 * screen in that request (subject + counterparties) uses the same snapshot.
 *
 * Unavailable, stale, missing or unreadable data is always an error
 * (SanctionsUnavailableError), never a "not listed" result.
 */
import { AsyncLocalStorage } from 'node:async_hooks'
import { neon } from '@neondatabase/serverless'
import {
  OFAC_SDN_DATASET,
  OFAC_SDN_DATASET_NAME,
  SCREENING_MATCHING,
  assessSnapshot,
  classifyAddress,
  indexEvmIdentifiers,
  maxStalenessMsFromEnv,
  screenEvmAddress,
  type DigitalCurrencyIdentifier,
  type LoadedSnapshot,
  type SanctionsResult,
  type SnapshotRecord,
} from './ofacSdnDigitalCurrency.js'

export type { SanctionsResult, SanctionsIdentification, SanctionsMatch } from './ofacSdnDigitalCurrency.js'

export const SANCTIONS_UNAVAILABLE_CODE = 'sanctions_screening_unavailable'

export class SanctionsUnavailableError extends Error {
  readonly code = SANCTIONS_UNAVAILABLE_CODE
  readonly status = 503
  constructor(public reason: string, detail: string) {
    super(
      `Wallet sanctions screening is unavailable (${reason}): ${detail}. No sanctions finding ` +
        'was made; an unchecked address must not be treated as not listed.'
    )
    this.name = 'SanctionsUnavailableError'
  }
}

export class InvalidWalletAddressError extends Error {
  readonly status = 400
  constructor(public code: 'invalid_address' | 'unsupported_address_format', address: string) {
    super(
      code === 'unsupported_address_format'
        ? `"${address}" is not an EVM address. Only EVM (0x, 20-byte) addresses are screened; ` +
            'OFAC also lists other currencies\' addresses, but this service does not screen them, ' +
            'so no finding was made.'
        : `"${address}" is not a valid EVM address`
    )
    this.name = 'InvalidWalletAddressError'
  }
}

export function sanctionsUnavailableBody(err: SanctionsUnavailableError) {
  return { error: SANCTIONS_UNAVAILABLE_CODE, reason: err.reason, message: err.message }
}

export function invalidAddressBody(err: InvalidWalletAddressError) {
  return { error: err.code, message: err.message }
}

/** MCP tool error result; returned before any payment is requested. */
export function sanctionsUnavailableToolResult(err: SanctionsUnavailableError) {
  return { content: [{ type: 'text' as const, text: err.message }], isError: true as const }
}

// --- Snapshot source -------------------------------------------------------

export interface StoredSnapshot {
  record: SnapshotRecord
  evm_identifiers: DigitalCurrencyIdentifier[]
}
export type SnapshotSource = () => Promise<StoredSnapshot | null>

let sourceOverride: SnapshotSource | null = null

/** Replace the store reader (tests only). Pass null to restore the database reader. */
export function setSanctionsSnapshotSource(source: SnapshotSource | null): void {
  sourceOverride = source
}

// Safe default for the canonical API: only its dedicated SELECT-only reader.
let databaseUrl = (): string | null => process.env.SANCTIONS_DATABASE_URL || null

/** Trusted service bootstrap only. MCP explicitly selects its own snapshot store. */
export function configureSanctionsDatabaseUrl(resolve: () => string | null): void {
  databaseUrl = resolve
}

const ISO = `'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'`
const SELECT_ACTIVE = `
  SELECT s.snapshot_id::text AS snapshot_id, s.dataset, s.status, s.source_url, s.source_object,
         s.publication_id, to_char(s.publish_date, 'YYYY-MM-DD') AS publish_date,
         s.record_count, s.entry_count,
         to_char(s.retrieved_at AT TIME ZONE 'UTC', ${ISO}) AS retrieved_at,
         to_char(s.revalidated_at AT TIME ZONE 'UTC', ${ISO}) AS revalidated_at,
         s.source_sha256, s.index_sha256, s.parser_version,
         s.digital_currency_identifiers, s.evm_identifiers, s.evm_unique_addresses,
         COALESCE((
           SELECT json_agg(json_build_object(
             'sdn_uid', i.sdn_uid, 'id_uid', i.id_uid, 'sdn_name', i.sdn_name, 'sdn_type', i.sdn_type,
             'programs', i.programs, 'currency', i.currency, 'listed_value', i.listed_value,
             'address_format', i.address_format, 'normalized_value', i.normalized_value))
           FROM sanctions_snapshot_identifiers i
           WHERE i.snapshot_id = s.snapshot_id AND i.address_format = 'evm'
         ), '[]'::json) AS evm_identifier_rows
  FROM sanctions_snapshots s
  WHERE s.dataset = $1 AND s.status = 'active'
  LIMIT 2`

async function readActiveFromDatabase(): Promise<StoredSnapshot | null> {
  const url = databaseUrl()
  if (!url) throw new SanctionsUnavailableError('not_configured', 'no sanctions snapshot store is configured')
  const rows = (await neon(url).query(SELECT_ACTIVE, [OFAC_SDN_DATASET])) as unknown as Array<Record<string, any>>
  if (rows.length === 0) return null
  if (rows.length > 1) throw new SanctionsUnavailableError('invalid_record', 'more than one active snapshot')
  // evm_identifier_rows must not share a name with the evm_identifiers count column.
  const { evm_identifier_rows, ...rest } = rows[0]
  const record: SnapshotRecord = {
    ...(rest as SnapshotRecord),
    record_count: Number(rest.record_count),
    entry_count: Number(rest.entry_count),
    digital_currency_identifiers: Number(rest.digital_currency_identifiers),
    evm_identifiers: Number(rest.evm_identifiers),
    evm_unique_addresses: Number(rest.evm_unique_addresses),
  }
  return { record, evm_identifiers: evm_identifier_rows as DigitalCurrencyIdentifier[] }
}

async function readActive(): Promise<StoredSnapshot | null> {
  try {
    return await (sourceOverride ?? readActiveFromDatabase)()
  } catch (err) {
    if (err instanceof SanctionsUnavailableError) throw err
    // Never surface driver errors (they can name hosts or roles).
    throw new SanctionsUnavailableError('store_unavailable', 'the sanctions snapshot store could not be read')
  }
}

function maxStalenessMs(): number {
  return maxStalenessMsFromEnv(process.env.SANCTIONS_MAX_STALENESS_HOURS)
}

/** Shared by screening and health; no index construction or second database read. */
function requireUsableStoredIndex(stored: StoredSnapshot): DigitalCurrencyIdentifier[] {
  const evm = stored.evm_identifiers
  const ids = new Set<number>()
  const addresses = new Set<string>()
  const invalid = () => new SanctionsUnavailableError('invalid_record', 'stored identifiers do not match the snapshot record')
  if (!Array.isArray(evm) || !Number.isSafeInteger(stored.record.evm_identifiers) ||
      stored.record.evm_identifiers < 1 || evm.length !== stored.record.evm_identifiers) throw invalid()
  for (const i of evm) {
    if (!i || i.address_format !== 'evm' || typeof i.normalized_value !== 'string' ||
        !/^0x[0-9a-f]{40}$/.test(i.normalized_value) || typeof i.listed_value !== 'string' ||
        i.listed_value.toLowerCase() !== i.normalized_value ||
        !Number.isSafeInteger(i.id_uid) || i.id_uid < 1 || ids.has(i.id_uid) ||
        !Number.isSafeInteger(i.sdn_uid) || i.sdn_uid < 1 || typeof i.sdn_name !== 'string' ||
        !(i.sdn_type === null || typeof i.sdn_type === 'string') ||
        typeof i.currency !== 'string' || !/^[A-Z0-9]{2,12}$/.test(i.currency) ||
        !Array.isArray(i.programs) || i.programs.some((p) => typeof p !== 'string')) throw invalid()
    ids.add(i.id_uid)
    addresses.add(i.normalized_value)
  }
  if (addresses.size !== stored.record.evm_unique_addresses) throw invalid()
  return evm
}

/** Load the active snapshot and require it to be fresh. Throws SanctionsUnavailableError otherwise. */
export async function loadUsableSnapshot(now: Date = new Date()): Promise<LoadedSnapshot> {
  const stored = await readActive()
  if (!stored) throw new SanctionsUnavailableError('no_snapshot', 'no validated OFAC SDN snapshot has been activated')
  const verdict = assessSnapshot(stored.record, now, maxStalenessMs())
  if (!verdict.usable) throw new SanctionsUnavailableError(verdict.reason, verdict.detail)
  const evm = requireUsableStoredIndex(stored)
  return { record: stored.record, evm: indexEvmIdentifiers(evm), assessed_at: now.toISOString() }
}

export interface SanctionsDataStatus {
  status: 'current' | 'stale' | 'unavailable' | 'not_configured'
  reason?: string
  dataset: string
  max_staleness_hours: number
  publish_date?: string
  revalidated_at?: string
  source_sha256?: string
  snapshot_id?: string
}

/** Health summary. Never throws. */
export async function sanctionsDataStatus(now: Date = new Date()): Promise<SanctionsDataStatus> {
  const base = { dataset: OFAC_SDN_DATASET, max_staleness_hours: maxStalenessMs() / 3_600_000 }
  let stored: StoredSnapshot | null
  try {
    stored = await readActive()
  } catch (err) {
    const reason = err instanceof SanctionsUnavailableError ? err.reason : 'store_unavailable'
    return { ...base, status: reason === 'not_configured' ? 'not_configured' : 'unavailable', reason }
  }
  if (!stored) return { ...base, status: 'unavailable', reason: 'no_snapshot' }
  const { record } = stored
  const meta = {
    publish_date: record.publish_date,
    revalidated_at: record.revalidated_at,
    source_sha256: record.source_sha256,
    snapshot_id: record.snapshot_id,
  }
  const verdict = assessSnapshot(record, now, maxStalenessMs())
  if (verdict.usable) {
    try { requireUsableStoredIndex(stored) } catch {
      return { ...base, status: 'unavailable', reason: 'invalid_record', ...meta }
    }
    return { ...base, status: 'current', ...meta }
  }
  return { ...base, status: verdict.reason === 'stale' ? 'stale' : 'unavailable', reason: verdict.reason, ...meta }
}

// --- Per-request pinning ----------------------------------------------------

const pinned = new AsyncLocalStorage<LoadedSnapshot>()

/** Run `fn` (e.g. the rest of a middleware chain, including payment) with `snapshot` pinned. */
export function runWithPinnedSnapshot<T>(snapshot: LoadedSnapshot, fn: () => T): T {
  return pinned.run(snapshot, fn)
}

export function pinnedSnapshot(): LoadedSnapshot | undefined {
  return pinned.getStore()
}

// --- Screening ------------------------------------------------------------------

/** Throws InvalidWalletAddressError unless `address` is a screenable EVM address. */
export function assertScreenableAddress(address: string): void {
  const kind = classifyAddress(address)
  if (kind === 'unsupported') throw new InvalidWalletAddressError('unsupported_address_format', address)
  if (kind !== 'evm') throw new InvalidWalletAddressError('invalid_address', address)
}

/**
 * Screen one EVM address: the pinned snapshot if this request has one, otherwise
 * a freshly loaded and assessed one. Result is 'listed' or 'not_listed', always
 * with dataset provenance and limitations; anything else throws.
 */
export async function screenAddress(address: string): Promise<SanctionsResult> {
  assertScreenableAddress(address)
  const snapshot = pinnedSnapshot() ?? (await loadUsableSnapshot())
  return screenEvmAddress(snapshot, address.trim())
}

/** Attribution block carried next to every wallet-screening result. */
export function buildAttribution() {
  return {
    source: `${OFAC_SDN_DATASET_NAME} (U.S. government data, public domain)`,
    method: SCREENING_MATCHING,
    note:
      'Screening aid, not legal advice or clearance. Scope, the exact dataset snapshot ' +
      '(publication date, SHA-256, retrieval and revalidation times) and the limits of a ' +
      'non-match are in the screening object of this signed result.',
  }
}
