/**
 * ofac.ts
 * -------
 * Name screening against the official U.S. Treasury OFAC Specially Designated
 * Nationals (SDN) list. This is the canonical, public-domain U.S. sanctions
 * list — no API key, no licence: it is U.S. government data.
 *
 * WHY THIS IS HARDER THAN THE WALLET CHECK:
 * The wallet oracle answers a clean boolean. Name screening is fuzzy by
 * nature — "Vladimir Putin" must match "PUTIN, Vladimir Vladimirovich", and
 * aliases / transliterations ("POUTINE") must be caught — while NOT drowning
 * the caller in false positives. There is no "correct" yes/no; there is a
 * confidence score and a human (or downstream policy) decision.
 *
 * HONEST SCOPE — READ THIS:
 * This is a screening *aid*, not a production AML system. It implements
 * transparent, explainable fuzzy matching over the primary SDN names and
 * their STRONG aliases (ALT file). It deliberately does NOT screen weak AKAs:
 * OFAC itself states it "does not expect that persons will screen for weak
 * AKAs" because they generate excessive false positives. A real compliance
 * programme adds secondary identifiers (DOB, nationality, ID numbers) to
 * disposition hits; this returns the match candidates and scores so that a
 * caller can do exactly that.
 *
 * DATA SOURCE (relational, linked by ENT_NUM):
 *   SDN.CSV  — primary records: ent_num, name, type, ...remarks
 *   ALT.CSV  — strong aliases:  ent_num, alt_num, alt_type, alt_name, ...
 * Null values are the literal string "-0-". Fields are comma-delimited and
 * double-quote quoted. We fetch fresh and cache by date — never bundle a
 * stale list. Every download is validated before use (see "Dataset
 * validation" below): missing, partial or corrupt data is never a negative.
 */

import { createHash } from 'node:crypto'
import { config } from './config.js'

export interface SdnMatch {
  ent_num: number
  matched_name: string
  matched_on: 'primary' | 'alias'
  sdn_type: string | null
  program: string | null
  score: number // 0..1 confidence
}

export interface NameScreenResult {
  query: string
  normalized_query: string
  hit: boolean
  matches: SdnMatch[]
  /** When this service fetched the source files; not OFAC's publication date. */
  retrieved_at: string
  threshold: number
  /** Identity, digest and freshness of the validated dataset this result was computed against. */
  dataset: OfacNameDataset & { freshness: OfacNameDatasetFreshness; max_age_hours: number }
}

// --- Parsing ---------------------------------------------------------------

const OFAC_NULL = '-0-'

/**
 * Parse one line of an OFAC delimited file. Fields are comma-separated and
 * double-quote quoted; quotes may contain commas. Returns raw string fields
 * with the "-0-" null sentinel converted to null.
 */
export function parseOfacLine(line: string): (string | null)[] {
  const fields: (string | null)[] = []
  let cur = ''
  let inQuotes = false
  const push = (v: string) => {
    const trimmed = v.trim()
    // OFAC pads fields, so the null sentinel can arrive as "-0- " etc.
    fields.push(trimmed === OFAC_NULL ? null : trimmed)
  }
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (ch === '"') {
      inQuotes = !inQuotes
    } else if (ch === ',' && !inQuotes) {
      push(cur)
      cur = ''
    } else {
      cur += ch
    }
  }
  push(cur)
  return fields
}

export interface SdnRecord {
  ent_num: number
  name: string
  sdn_type: string | null
  program: string | null
  aliases: string[]
}

/**
 * Build the screening index from the raw SDN.CSV and ALT.CSV text. Strong
 * aliases from ALT are attached to their primary record by ent_num.
 *
 * SDN.CSV columns (1-indexed in OFAC docs): 1 ent_num, 2 name, 3 sdn_type,
 * 4 program, ... (we only need the first four reliably).
 * ALT.CSV columns: 1 ent_num, 2 alt_num, 3 alt_type, 4 alt_name, 5 remarks.
 */
export function buildSdnIndex(sdnCsv: string, altCsv: string): SdnRecord[] {
  const byEnt = new Map<number, SdnRecord>()

  for (const raw of sdnCsv.split(/\r?\n/)) {
    if (!raw.trim()) continue
    const f = parseOfacLine(raw)
    const ent = Number(f[0])
    if (!Number.isFinite(ent)) continue
    byEnt.set(ent, {
      ent_num: ent,
      name: f[1] ?? '',
      sdn_type: f[2],
      program: f[3],
      aliases: [],
    })
  }

  for (const raw of altCsv.split(/\r?\n/)) {
    if (!raw.trim()) continue
    const f = parseOfacLine(raw)
    const ent = Number(f[0])
    const altName = f[3]
    if (!Number.isFinite(ent) || !altName) continue
    const rec = byEnt.get(ent)
    if (rec) rec.aliases.push(altName)
  }

  return [...byEnt.values()]
}

// --- Fuzzy matching (pure, the interesting part) ---------------------------

/**
 * Normalize a name for comparison: lowercase, strip punctuation, collapse
 * whitespace, and sort tokens so word order doesn't matter ("Vladimir Putin"
 * and "Putin, Vladimir" normalize to the same token set order). Diacritics
 * are folded so "Putín" == "Putin".
 */
export function normalizeName(name: string): string {
  return name
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '') // strip diacritics
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ') // punctuation -> space
    .replace(/\s+/g, ' ')
    .trim()
}

function tokenSet(name: string): string[] {
  const seen = new Set(normalizeName(name).split(' ').filter(Boolean))
  return [...seen].sort()
}

/** Levenshtein distance between two short strings. */
export function levenshtein(a: string, b: string): number {
  const m = a.length
  const n = b.length
  if (m === 0) return n
  if (n === 0) return m
  let prev = Array.from({ length: n + 1 }, (_, i) => i)
  let cur = new Array(n + 1).fill(0)
  for (let i = 1; i <= m; i++) {
    cur[0] = i
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
    }
    ;[prev, cur] = [cur, prev]
  }
  return prev[n]
}

/**
 * Score the similarity of a query name to a candidate name in [0,1].
 *
 * Combines two transparent signals:
 *  - Token overlap (Jaccard) so word order and extra middle names don't break
 *    a match: "vladimir putin" vs "putin vladimir vladimirovich".
 *  - Character-level closeness (normalized Levenshtein) so near-spellings and
 *    transliterations ("poutine" ~ "putin") still score.
 * The final score weights token overlap higher (it's the stronger signal for
 * person/company names) but lets a very close string rescue a partial token
 * match. Explainable on purpose — no opaque ML.
 */
export function similarity(query: string, candidate: string): number {
  const qn = normalizeName(query)
  const cn = normalizeName(candidate)
  if (!qn || !cn) return 0
  if (qn === cn) return 1

  const qt = new Set(qn.split(' '))
  const ct = new Set(cn.split(' '))
  const inter = [...qt].filter((t) => ct.has(t)).length
  const union = new Set([...qt, ...ct]).size
  const jaccard = union === 0 ? 0 : inter / union

  const dist = levenshtein(qn, cn)
  const maxLen = Math.max(qn.length, cn.length)
  const charSim = maxLen === 0 ? 0 : 1 - dist / maxLen

  // Token overlap weighted higher; char similarity fills in near-spellings.
  let score = 0.65 * jaccard + 0.35 * charSim

  // Bonus: every query token appears somewhere in the candidate (subset),
  // e.g. "vladimir putin" fully contained in "putin vladimir vladimirovich".
  const allQueryTokensPresent = [...qt].every((t) => ct.has(t))
  if (allQueryTokensPresent && qt.size > 0) score = Math.max(score, 0.9)

  return Math.min(1, score)
}

/**
 * Screen a name against a prebuilt SDN index. Returns matches at or above the
 * threshold, scored against both primary names and strong aliases, best first.
 */
export function screenNameAgainstIndex(
  query: string,
  index: SdnRecord[],
  threshold = 0.85
): SdnMatch[] {
  const matches: SdnMatch[] = []
  for (const rec of index) {
    let best = similarity(query, rec.name)
    let bestName = rec.name
    let on: 'primary' | 'alias' = 'primary'
    for (const alias of rec.aliases) {
      const s = similarity(query, alias)
      if (s > best) {
        best = s
        bestName = alias
        on = 'alias'
      }
    }
    if (best >= threshold) {
      matches.push({
        ent_num: rec.ent_num,
        matched_name: bestName,
        matched_on: on,
        sdn_type: rec.sdn_type,
        program: rec.program,
        score: Math.round(best * 1000) / 1000,
      })
    }
  }
  return matches.sort((a, b) => b.score - a.score)
}

// --- Dataset validation (fail closed) --------------------------------------
//
// A screening NEGATIVE ("hit: false") is only meaningful if the index it was
// computed against is the complete, current OFAC list. An HTTP 200 carrying a
// maintenance page, an empty or truncated body, or a changed file layout used
// to produce an EMPTY index -- and therefore a signable "no match" for every
// name. Every downloaded pair is now validated before it can replace the
// cached index; anything that does not look like a complete OFAC SDN/ALT
// pair is rejected, and no index means no result (never a negative).

/** Documented column counts of OFAC's legacy delimited files. */
export const SDN_CSV_COLUMNS = 12 // ent_num, SDN_Name, SDN_Type, Program, Title, Call_Sign, Vess_type, Tonnage, GRT, Vess_flag, Vess_owner, Remarks
export const ALT_CSV_COLUMNS = 5 // ent_num, alt_num, alt_type, alt_name, alt_remarks
/** Far below the real list sizes (thousands of each); a body under these is not the list. */
export const MIN_SDN_RECORDS = 5_000
export const MIN_ALT_RECORDS = 2_000
/** A day-to-day drop larger than this versus the last validated dataset is implausible. */
export const MAX_REDUCTION_FRACTION = 0.1
/** Aliases must point at primary records; more orphans than this means the pair is inconsistent. */
export const MAX_ORPHAN_ALIAS_FRACTION = 0.01

const SDN_TYPES = new Set(['individual', 'vessel', 'aircraft'])

export type OfacDatasetRejection =
  | 'html_response'
  | 'unexpected_content_type'
  | 'empty_file'
  | 'malformed_row'
  | 'unexpected_column_count'
  | 'invalid_record'
  | 'duplicate_record'
  | 'too_few_records'
  | 'implausible_reduction'
  | 'alias_primary_mismatch'

export class OfacUpstreamError extends Error {
  constructor(public status: number, message?: string) {
    super(message ?? `OFAC SDN list fetch failed (status ${status})`)
    this.name = 'OfacUpstreamError'
  }
}

/** The downloaded files are not a complete, well-formed OFAC SDN/ALT pair. */
export class OfacDatasetInvalidError extends OfacUpstreamError {
  constructor(public reason: OfacDatasetRejection, public file: 'sdn' | 'alt' | 'pair', detail?: string) {
    super(502, `OFAC SDN ${file} dataset rejected: ${reason}${detail ? ` (${detail})` : ''}`)
    this.name = 'OfacDatasetInvalidError'
  }
}

/**
 * No validated dataset within its freshness window is available, so no
 * screening result (positive or negative) can be produced. Paid routes map
 * this to 503 before payment; it is never turned into "hit: false".
 */
export class OfacNameScreeningUnavailableError extends OfacUpstreamError {
  constructor(public reason: string) {
    super(503, `OFAC SDN name screening unavailable: ${reason}`)
    this.name = 'OfacNameScreeningUnavailableError'
  }
}

function looksLikeHtml(text: string): boolean {
  const head = text.replace(/^﻿/, '').trimStart().slice(0, 512).toLowerCase()
  return head.startsWith('<') || /<!doctype|<html|<head|<body|<title/.test(head)
}

/** Data rows of one file: blank lines and OFAC's trailing EOF marker (0x1A) are not records. */
function dataRows(text: string): string[] {
  return text.split(/\r?\n/).filter((line) => line.trim() !== '' && line.trim() !== '\u001a')
}

function rowsOf(text: string, file: 'sdn' | 'alt', columns: number): (string | null)[][] {
  if (looksLikeHtml(text)) throw new OfacDatasetInvalidError('html_response', file)
  const lines = dataRows(text)
  if (lines.length === 0) throw new OfacDatasetInvalidError('empty_file', file)
  return lines.map((line, i) => {
    // An odd number of quotes means a field was cut off mid-value (truncation).
    if ((line.match(/"/g)?.length ?? 0) % 2 !== 0) throw new OfacDatasetInvalidError('malformed_row', file, `row ${i + 1}`)
    const fields = parseOfacLine(line)
    if (fields.length !== columns) throw new OfacDatasetInvalidError('unexpected_column_count', file, `row ${i + 1}: ${fields.length} != ${columns}`)
    return fields
  })
}

export interface OfacDatasetStats {
  sdn_records: number
  alt_records: number
  orphan_aliases: number
}

/**
 * Pure validation + index build. Throws OfacDatasetInvalidError on anything
 * that is not a complete, internally consistent SDN/ALT pair, including an
 * implausible reduction versus the previously validated dataset.
 */
export function validateOfacDataset(
  sdnCsv: string,
  altCsv: string,
  previous: { sdn_records: number; alt_records: number } | null = null
): { index: SdnRecord[]; stats: OfacDatasetStats } {
  const byEnt = new Map<number, SdnRecord>()
  for (const [i, f] of rowsOf(sdnCsv, 'sdn', SDN_CSV_COLUMNS).entries()) {
    const ent = Number(f[0])
    const name = f[1]
    if (!/^\d+$/.test(f[0] ?? '') || ent <= 0 || !name) throw new OfacDatasetInvalidError('invalid_record', 'sdn', `row ${i + 1}`)
    if (f[2] !== null && !SDN_TYPES.has(f[2].toLowerCase())) throw new OfacDatasetInvalidError('invalid_record', 'sdn', `row ${i + 1}: sdn_type`)
    if (byEnt.has(ent)) throw new OfacDatasetInvalidError('duplicate_record', 'sdn', `ent_num ${ent}`)
    byEnt.set(ent, { ent_num: ent, name, sdn_type: f[2], program: f[3], aliases: [] })
  }

  let altRecords = 0
  let orphans = 0
  for (const [i, f] of rowsOf(altCsv, 'alt', ALT_CSV_COLUMNS).entries()) {
    const altName = f[3]
    if (!/^\d+$/.test(f[0] ?? '') || !/^\d+$/.test(f[1] ?? '') || !altName) throw new OfacDatasetInvalidError('invalid_record', 'alt', `row ${i + 1}`)
    altRecords += 1
    const rec = byEnt.get(Number(f[0]))
    if (rec) rec.aliases.push(altName)
    else orphans += 1
  }

  const stats: OfacDatasetStats = { sdn_records: byEnt.size, alt_records: altRecords, orphan_aliases: orphans }
  if (stats.sdn_records < MIN_SDN_RECORDS) throw new OfacDatasetInvalidError('too_few_records', 'sdn', `${stats.sdn_records} < ${MIN_SDN_RECORDS}`)
  if (stats.alt_records < MIN_ALT_RECORDS) throw new OfacDatasetInvalidError('too_few_records', 'alt', `${stats.alt_records} < ${MIN_ALT_RECORDS}`)
  if (orphans > altRecords * MAX_ORPHAN_ALIAS_FRACTION) throw new OfacDatasetInvalidError('alias_primary_mismatch', 'pair', `${orphans} aliases reference no primary record`)
  if (previous) {
    if (stats.sdn_records < previous.sdn_records * (1 - MAX_REDUCTION_FRACTION)) throw new OfacDatasetInvalidError('implausible_reduction', 'sdn', `${previous.sdn_records} -> ${stats.sdn_records}`)
    if (stats.alt_records < previous.alt_records * (1 - MAX_REDUCTION_FRACTION)) throw new OfacDatasetInvalidError('implausible_reduction', 'alt', `${previous.alt_records} -> ${stats.alt_records}`)
  }
  return { index: [...byEnt.values()], stats }
}

// --- Fetching + caching ----------------------------------------------------

export interface OfacNameDataset {
  source: 'us-treasury-ofac-sdn-legacy-csv'
  source_urls: { sdn: string; alt: string }
  /** sha256 over the two files' own sha256 digests (sdn, then alt). */
  sha256: string
  sdn_sha256: string
  alt_sha256: string
  sdn_records: number
  alt_records: number
  /** When this service fetched the files; not OFAC's publication date. */
  retrieved_at: string
  validated_at: string
}

export interface CachedList {
  index: SdnRecord[]
  fetchedAt: number
  retrievedAt: string
  dataset: OfacNameDataset
}

const REFRESH_AFTER_MS = 6 * 60 * 60 * 1000 // try to refresh after 6h -- OFAC updates ~daily
const REFRESH_RETRY_MS = 60_000 // after a failed refresh, don't re-fetch on every request
const DEFAULT_MAX_AGE_HOURS = 24

/**
 * How long a validated dataset may keep serving results when refreshes fail.
 * OFAC_NAME_SCREENING_MAX_STALENESS_HOURS, clamped to 6..48 (default 24).
 * Beyond it there is no result at all, never a negative.
 */
export function maxDatasetAgeMs(): number {
  const raw = Number(process.env.OFAC_NAME_SCREENING_MAX_STALENESS_HOURS)
  const hours = Number.isFinite(raw) && raw > 0 ? Math.min(Math.max(raw, 6), 48) : DEFAULT_MAX_AGE_HOURS
  return hours * 60 * 60 * 1000
}

let cache: CachedList | null = null
let lastRefreshFailure: { at: number; reason: string } | null = null
let inflight: Promise<CachedList> | null = null

async function fetchText(url: string, file: 'sdn' | 'alt'): Promise<{ text: string; sha256: string }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 15_000)
  try {
    const res = await fetch(url, { signal: controller.signal })
    if (!res.ok) throw new OfacUpstreamError(res.status)
    const type = (res.headers.get('content-type') ?? '').toLowerCase()
    if (type.includes('text/html') || type.includes('application/xhtml')) throw new OfacDatasetInvalidError('unexpected_content_type', file, type)
    const bytes = Buffer.from(await res.arrayBuffer())
    return { text: bytes.toString('utf8'), sha256: createHash('sha256').update(bytes).digest('hex') }
  } catch (err) {
    if (err instanceof OfacUpstreamError) throw err
    throw new OfacUpstreamError(502)
  } finally {
    clearTimeout(timer)
  }
}

async function refresh(now: number): Promise<CachedList> {
  const urls = { sdn: config.ofac.sdnUrl, alt: config.ofac.altUrl }
  const [sdn, alt] = await Promise.all([fetchText(urls.sdn, 'sdn'), fetchText(urls.alt, 'alt')])
  // Validate BEFORE replacing the cache: a rejected pair never displaces a good one.
  const previous = cache ? { sdn_records: cache.dataset.sdn_records, alt_records: cache.dataset.alt_records } : null
  const { index, stats } = validateOfacDataset(sdn.text, alt.text, previous)
  const at = new Date(now).toISOString()
  return {
    index,
    fetchedAt: now,
    retrievedAt: at,
    dataset: {
      source: 'us-treasury-ofac-sdn-legacy-csv',
      source_urls: urls,
      sha256: createHash('sha256').update(`${sdn.sha256}${alt.sha256}`).digest('hex'),
      sdn_sha256: sdn.sha256,
      alt_sha256: alt.sha256,
      sdn_records: stats.sdn_records,
      alt_records: stats.alt_records,
      retrieved_at: at,
      validated_at: new Date().toISOString(),
    },
  }
}

/**
 * Load the validated SDN index. Refreshes when due; if a refresh fails or is
 * rejected, the previous VALIDATED dataset keeps serving only while it is
 * within maxDatasetAgeMs(). Otherwise throws OfacNameScreeningUnavailableError.
 */
export async function loadSdnIndex(): Promise<CachedList> {
  const now = Date.now()
  const usable = cache && now - cache.fetchedAt < maxDatasetAgeMs() ? cache : null
  if (usable && now - usable.fetchedAt < REFRESH_AFTER_MS) return usable
  if (usable && lastRefreshFailure && now - lastRefreshFailure.at < REFRESH_RETRY_MS) return usable
  try {
    inflight ??= refresh(now).finally(() => { inflight = null })
    cache = await inflight
    lastRefreshFailure = null
    return cache
  } catch (err) {
    const reason = err instanceof OfacDatasetInvalidError ? `dataset_rejected:${err.reason}` : err instanceof OfacUpstreamError ? `upstream_status_${err.status}` : 'refresh_failed'
    lastRefreshFailure = { at: now, reason }
    console.error('OFAC SDN name dataset refresh failed:', err instanceof Error ? err.message : reason)
    if (usable) return usable
    throw new OfacNameScreeningUnavailableError(reason)
  }
}

export type OfacNameDatasetFreshness = 'current' | 'refresh_overdue'

/** Cheap status for health/readiness reporting: never fetches. */
export function ofacNameScreeningStatus(now = Date.now()): { state: 'current' | 'refresh_overdue' | 'not_loaded' | 'expired'; retrieved_at: string | null; last_refresh_failure: string | null } {
  const failure = lastRefreshFailure?.reason ?? null
  if (!cache) return { state: 'not_loaded', retrieved_at: null, last_refresh_failure: failure }
  const age = now - cache.fetchedAt
  const state = age >= maxDatasetAgeMs() ? 'expired' : age >= REFRESH_AFTER_MS ? 'refresh_overdue' : 'current'
  return { state, retrieved_at: cache.retrievedAt, last_refresh_failure: failure }
}

/**
 * Screen a name against the validated OFAC SDN list. Pass the snapshot a
 * pre-payment readiness gate already loaded so the paid result is computed
 * against exactly the dataset that was judged usable.
 */
export async function screenName(
  query: string,
  threshold = 0.85,
  snapshot?: CachedList
): Promise<NameScreenResult> {
  const list = snapshot ?? (await loadSdnIndex())
  const now = Date.now()
  if (list.index.length === 0 || now - list.fetchedAt >= maxDatasetAgeMs()) {
    throw new OfacNameScreeningUnavailableError('no validated dataset within its freshness window')
  }
  const matches = screenNameAgainstIndex(query, list.index, threshold)
  return {
    query,
    normalized_query: normalizeName(query),
    hit: matches.length > 0,
    matches,
    retrieved_at: list.retrievedAt,
    threshold,
    dataset: {
      ...list.dataset,
      freshness: now - list.fetchedAt < REFRESH_AFTER_MS ? 'current' : 'refresh_overdue',
      max_age_hours: maxDatasetAgeMs() / 3_600_000,
    },
  }
}

/** Attribution block — every response that includes OFAC data must carry it. */
export function buildOfacAttribution() {
  return {
    source: 'U.S. Treasury OFAC Specially Designated Nationals (SDN) list (public domain)',
    method:
      'Fuzzy name match (token overlap + edit distance) against primary names ' +
      'and strong aliases. Weak AKAs are not screened, per OFAC guidance.',
    note:
      'This is a screening aid, not legal advice and not a complete compliance ' +
      'program. A match is a candidate to investigate using secondary ' +
      'identifiers (date of birth, nationality, ID numbers), not a determination. ' +
      'SDN list only: not non-SDN lists, other jurisdictions\' lists, the 50% rule, ' +
      'or beneficial ownership. Always confirm against the official OFAC list before acting.',
  }
}

// For tests.
export const __test = {
  REFRESH_AFTER_MS,
  REFRESH_RETRY_MS,
  reset() { cache = null; lastRefreshFailure = null; inflight = null },
  setCachedAt(fetchedAt: number) { if (cache) cache = { ...cache, fetchedAt } },
}
