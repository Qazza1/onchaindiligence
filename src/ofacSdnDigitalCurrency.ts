/**
 * ofacSdnDigitalCurrency.ts — SHARED MODULE.
 *
 * Keep this file byte-identical in Qazza1/onchaindiligence (src/) and
 * Qazza1/onchaindiligence-mcp (src/). Both repos pin its SHA-256 in
 * test/ofacSdnScreening.ts, so an edit in one repo fails that repo's tests
 * until the pin (and the other copy) is updated deliberately.
 *
 * What this is: pure, dependency-free logic for wallet screening against the
 * official U.S. Treasury OFAC SDN List — parsing the digital currency address
 * identifiers out of SDN.XML, validating a candidate snapshot, deciding whether
 * a stored snapshot is fresh enough to use, and exact address matching.
 *
 * Claim ceiling (do not widen without implementing and validating it):
 *   - OFAC SDN List only. Not the OFAC non-SDN (Consolidated) lists, EU, UN, UK
 *     or any other regime.
 *   - Digital currency address IDENTIFIERS only ("Digital Currency Address - XBT"
 *     etc., OFAC FAQ 563). OFAC says these listings are not exhaustive (FAQ 562).
 *   - Exact matching of EVM-format (0x + 20 bytes) input only, compared
 *     case-insensitively against every SDN identifier whose value is EVM-format,
 *     whatever currency label OFAC gave it. Non-EVM inputs are "unsupported".
 *   - No ownership / 50 Percent Rule resolution, no proximity, no name matching.
 *
 * Source facts (verified against the official file, publication of 2026-10-15):
 *   GET https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML
 *   302 -> a short-lived pre-signed URL on the SLS publication bucket. Root
 *   element <sdnList xmlns="https://sanctionslistservice.ofac.treas.gov/api/
 *   PublicationPreview/exports/XML">, <publshInformation> (sic) carries
 *   <Publish_Date>MM/DD/YYYY</Publish_Date> and <Record_Count>, and each
 *   <sdnEntry> holds identifiers as <idList><id><uid/><idType/><idNumber/></id>.
 */
import { createHash } from 'node:crypto'

export const OFAC_SDN_XML_URL =
  'https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML'
export const OFAC_SDN_XML_NAMESPACE =
  'https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML'
export const OFAC_SDN_DATASET = 'ofac_sdn_xml'
export const OFAC_SDN_DATASET_NAME = 'U.S. Treasury OFAC Specially Designated Nationals (SDN) List, SDN.XML'
export const OFAC_SDN_PARSER_VERSION = 'ocd-ofac-sdn-dca/2'
export const OFAC_SDN_MATCHING_VERSION = 'exact-evm-address/1'
export const SANCTIONS_SCREENING_SCOPE = 'ofac_sdn_digital_currency_address'

export const SCREENING_COVERAGE =
  'OFAC SDN List digital currency address identifiers only. Not the OFAC non-SDN (Consolidated) ' +
  'lists, EU, UN, UK or any other sanctions regime.'

export const SCREENING_MATCHING =
  'Exact match. The 20-byte EVM address is compared case-insensitively with every SDN ' +
  '"Digital Currency Address - <currency>" identifier whose value is an EVM-format address, ' +
  'whatever currency label OFAC assigned. A match reports OFAC\'s label; no claim is made ' +
  'about which networks the address was used on.'

export const SCREENING_LIMITATIONS: readonly string[] = Object.freeze([
  'A non-match means only that this exact address is not listed as an SDN digital currency ' +
    'address identifier in the snapshot described in dataset. It is not legal clearance.',
  'OFAC states that its digital currency address listings are not likely to be exhaustive ' +
    '(OFAC FAQ 562). A sanctioned person can control addresses OFAC has not listed.',
  'This check does not establish wallet ownership, beneficial ownership or general safety, ' +
    'and does not apply the OFAC 50 Percent Rule or any ownership, proximity or exposure analysis.',
  'Other regimes (EU, UN, UK and others) and OFAC non-SDN lists are not covered.',
])

/** Official SDN entry page, for a listed match. */
export function ofacEntryUrl(sdnUid: number): string {
  return `https://sanctionssearch.ofac.treas.gov/Details.aspx?id=${sdnUid}`
}

// --- Parsing -------------------------------------------------------------

export type AddressFormat = 'evm' | 'other'

export interface DigitalCurrencyIdentifier {
  sdn_uid: number
  id_uid: number
  sdn_name: string
  sdn_type: string | null
  programs: string[]
  /** OFAC currency label, e.g. ETH, XBT, USDT. */
  currency: string
  /** Value exactly as published (after XML entity decoding and trimming). */
  listed_value: string
  address_format: AddressFormat
  /** Lower-cased for EVM-format values; unchanged (case-sensitive) otherwise. */
  normalized_value: string
}

export interface ParsedSdnList {
  namespace: string
  publish_date: string // YYYY-MM-DD, as stated by OFAC
  record_count: number // as stated by OFAC
  entry_count: number // as parsed
  identifiers: DigitalCurrencyIdentifier[]
}

export class SdnParseError extends Error {
  constructor(public reason: string, detail: string) {
    super(`OFAC SDN.XML rejected (${reason}): ${detail}`)
    this.name = 'SdnParseError'
  }
}

const DCA_TYPE_PREFIX = 'Digital Currency Address - '
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/

function decodeXmlText(raw: string, where: string): string {
  return raw.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos);?/g, (whole, ent: string) => {
    if (!whole.endsWith(';')) throw new SdnParseError('malformed_entity', `${where}: ${whole}`)
    switch (ent) {
      case 'amp': return '&'
      case 'lt': return '<'
      case 'gt': return '>'
      case 'quot': return '"'
      case 'apos': return "'"
      default: {
        const code = ent.startsWith('#x') ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10)
        if (!Number.isFinite(code) || code > 0x10ffff) throw new SdnParseError('malformed_entity', `${where}: ${whole}`)
        return String.fromCodePoint(code)
      }
    }
  })
}

function assertNoStrayEntities(raw: string, where: string): void {
  // Any "&" left that is not one of the five predefined or a numeric reference.
  const stray = raw.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos);/g, '')
  if (stray.includes('&')) throw new SdnParseError('malformed_entity', where)
}

function textOf(block: string, tag: string, where: string): string | null {
  const m = block.match(new RegExp(`<${tag}>([^<]*)</${tag}>`))
  if (!m) return null
  assertNoStrayEntities(m[1], `${where} <${tag}>`)
  return decodeXmlText(m[1], `${where} <${tag}>`).trim()
}

function countOccurrences(haystack: string, needle: string): number {
  let n = 0
  for (let i = haystack.indexOf(needle); i !== -1; i = haystack.indexOf(needle, i + needle.length)) n++
  return n
}

/** Count and decode every idType independently of entry/id extraction. */
function identifierTypes(block: string, where: string): string[] {
  const types = [...block.matchAll(/<idType>([^<]*)<\/idType>/g)]
  if (types.length !== countOccurrences(block, '<idType') ||
      types.length !== countOccurrences(block, '</idType>')) {
    throw new SdnParseError('malformed_identifier_type', where)
  }
  return types.map((m) => {
    assertNoStrayEntities(m[1], where)
    return decodeXmlText(m[1], where).trim()
  })
}

/**
 * Parse SDN.XML and extract every digital currency address identifier.
 *
 * Deliberately strict: anything unexpected throws, so a partial or altered file
 * can never become an index. DTDs/entities are refused outright (no XXE or
 * entity expansion is possible because no DTD is ever processed), the document
 * must be complete (closing root), the stated Record_Count must equal the parsed
 * entry count, and every decoded digital-currency identifier type in the
 * document must have been extracted as an identifier.
 */
export function parseSdnXml(xml: string): ParsedSdnList {
  if (typeof xml !== 'string' || xml.length === 0) throw new SdnParseError('empty', 'no content')
  const doc = xml.charCodeAt(0) === 0xfeff ? xml.slice(1) : xml
  if (/<!DOCTYPE|<!ENTITY/i.test(doc)) throw new SdnParseError('dtd_not_allowed', 'document declares a DTD or entity')
  const stated = identifierTypes(doc, 'document').filter((t) => t.startsWith(DCA_TYPE_PREFIX)).length
  const head = doc.slice(0, 2048)
  if (/<html[\s>]/i.test(head)) throw new SdnParseError('not_xml', 'received an HTML document')
  const root = head.match(/<sdnList\b([^>]*)>/)
  if (!root) throw new SdnParseError('unexpected_root', 'missing <sdnList> root element')
  const ns = root[1].match(/\sxmlns="([^"]*)"/)?.[1] ?? ''
  if (ns !== OFAC_SDN_XML_NAMESPACE) throw new SdnParseError('unexpected_namespace', ns || '(none)')
  if (!doc.trimEnd().endsWith('</sdnList>')) throw new SdnParseError('truncated', 'missing closing </sdnList>')

  const pub = doc.match(/<publshInformation>([\s\S]*?)<\/publshInformation>/)
  if (!pub) throw new SdnParseError('missing_publication_info', 'no <publshInformation>')
  const rawDate = textOf(pub[1], 'Publish_Date', 'publshInformation')
  const dm = rawDate?.match(/^(\d{2})\/(\d{2})\/(\d{4})$/)
  if (!dm) throw new SdnParseError('bad_publish_date', String(rawDate))
  const publishDate = `${dm[3]}-${dm[1]}-${dm[2]}`
  const asDate = new Date(`${publishDate}T00:00:00.000Z`)
  if (Number.isNaN(asDate.getTime()) || asDate.toISOString().slice(0, 10) !== publishDate) {
    throw new SdnParseError('bad_publish_date', String(rawDate))
  }
  const rawCount = textOf(pub[1], 'Record_Count', 'publshInformation')
  if (!rawCount || !/^\d+$/.test(rawCount)) throw new SdnParseError('bad_record_count', String(rawCount))
  const recordCount = Number(rawCount)

  const opens = countOccurrences(doc, '<sdnEntry>')
  const closes = countOccurrences(doc, '</sdnEntry>')
  if (opens !== closes) throw new SdnParseError('unbalanced_entries', `${opens} open / ${closes} close`)

  const identifiers: DigitalCurrencyIdentifier[] = []
  const seenEntryUids = new Set<number>()
  const seenIdUids = new Set<number>()
  let entryCount = 0
  const entryRe = /<sdnEntry>([\s\S]*?)<\/sdnEntry>/g
  for (let m = entryRe.exec(doc); m; m = entryRe.exec(doc)) {
    entryCount++
    const body = m[1]
    const uidMatch = body.match(/^\s*<uid>(\d+)<\/uid>/)
    if (!uidMatch) throw new SdnParseError('entry_without_uid', `entry #${entryCount}`)
    const sdnUid = Number(uidMatch[1])
    if (seenEntryUids.has(sdnUid)) throw new SdnParseError('duplicate_entry_uid', String(sdnUid))
    seenEntryUids.add(sdnUid)
    if (!identifierTypes(body, 'sdnEntry ' + sdnUid).some((t) => t.startsWith(DCA_TYPE_PREFIX))) continue

    const where = `sdnEntry ${sdnUid}`
    // Entry-level name/type precede the first nested <...List> element.
    const listStart = body.search(/<[A-Za-z]+List>/)
    const entryHead = listStart === -1 ? body : body.slice(0, listStart)
    const lastName = textOf(entryHead, 'lastName', where) ?? ''
    const firstName = textOf(entryHead, 'firstName', where)
    const sdnName = firstName ? `${lastName}, ${firstName}` : lastName
    const sdnType = textOf(entryHead, 'sdnType', where)
    const programList = body.match(/<programList>([\s\S]*?)<\/programList>/)?.[1] ?? ''
    const programs = [...programList.matchAll(/<program>([^<]*)<\/program>/g)].map((p) =>
      decodeXmlText(p[1], `${where} <program>`).trim()
    )

    const idLists = [...body.matchAll(/<idList>([\s\S]*?)<\/idList>/g)]
    if (idLists.length !== 1) throw new SdnParseError('unexpected_id_list', `${where}: ${idLists.length} <idList>`)
    for (const idm of idLists[0][1].matchAll(/<id>([\s\S]*?)<\/id>/g)) {
      const idBody = idm[1]
      const types = identifierTypes(idBody, where)
      if (types.length !== 1) throw new SdnParseError('malformed_identifier_type', where)
      const [idType] = types
      if (!idType.startsWith(DCA_TYPE_PREFIX)) continue
      const idUidRaw = idBody.match(/<uid>(\d+)<\/uid>/)?.[1]
      if (!idUidRaw) throw new SdnParseError('identifier_without_uid', where)
      const idUid = Number(idUidRaw)
      if (seenIdUids.has(idUid)) throw new SdnParseError('duplicate_identifier_uid', String(idUid))
      seenIdUids.add(idUid)
      const currency = idType.slice(DCA_TYPE_PREFIX.length).trim()
      if (!/^[A-Z0-9]{2,12}$/.test(currency)) throw new SdnParseError('bad_currency_label', `${where}: ${idType}`)
      const value = textOf(idBody, 'idNumber', where)
      if (!value || value.length > 256 || /\s/.test(value)) {
        throw new SdnParseError('bad_identifier_value', `${where} id ${idUid}`)
      }
      const isEvm = EVM_ADDRESS.test(value)
      identifiers.push({
        sdn_uid: sdnUid,
        id_uid: idUid,
        sdn_name: sdnName,
        sdn_type: sdnType,
        programs,
        currency,
        listed_value: value,
        address_format: isEvm ? 'evm' : 'other',
        normalized_value: isEvm ? value.toLowerCase() : value,
      })
    }
  }

  if (entryCount !== opens) throw new SdnParseError('unparsed_entries', `${opens - entryCount} not parsed`)
  if (entryCount !== recordCount) {
    throw new SdnParseError('record_count_mismatch', `Record_Count ${recordCount}, parsed ${entryCount}`)
  }
  if (stated !== identifiers.length) {
    throw new SdnParseError('identifier_count_mismatch', `${stated} in document, ${identifiers.length} extracted`)
  }
  // Decode only for this independent coverage check, never as parser markup.
  // Thus an encoded type cannot evade the count, nor can encoded outside text.
  assertNoStrayEntities(doc, 'document')
  if (countOccurrences(decodeXmlText(doc, 'document'), DCA_TYPE_PREFIX) !== stated) {
    throw new SdnParseError('identifier_outside_id_list', 'digital currency address text outside <idType>')
  }

  return { namespace: ns, publish_date: publishDate, record_count: recordCount, entry_count: entryCount, identifiers }
}

export interface IdentifierSummary {
  digital_currency_identifiers: number
  evm_identifiers: number
  evm_unique_addresses: number
  currencies: Record<string, number>
}

export function summarizeIdentifiers(identifiers: DigitalCurrencyIdentifier[]): IdentifierSummary {
  const currencies: Record<string, number> = {}
  const evm = new Set<string>()
  let evmCount = 0
  for (const id of identifiers) {
    currencies[id.currency] = (currencies[id.currency] ?? 0) + 1
    if (id.address_format === 'evm') {
      evmCount++
      evm.add(id.normalized_value)
    }
  }
  const sorted: Record<string, number> = {}
  for (const k of Object.keys(currencies).sort()) sorted[k] = currencies[k]
  return {
    digital_currency_identifiers: identifiers.length,
    evm_identifiers: evmCount,
    evm_unique_addresses: evm.size,
    currencies: sorted,
  }
}

/**
 * Deterministic digest of the extracted index (hex SHA-256). Re-running this
 * parser version on the file whose source_sha256 is recorded reproduces it.
 */
export function identifierIndexSha256(identifiers: DigitalCurrencyIdentifier[]): string {
  const lines = [...identifiers]
    .sort((a, b) => a.id_uid - b.id_uid)
    .map((i) => JSON.stringify([i.id_uid, i.sdn_uid, i.currency, i.listed_value, i.address_format, i.normalized_value]))
  return createHash('sha256').update(lines.join('\n'), 'utf8').digest('hex')
}

// --- Candidate validation (before a snapshot may become active) ----------

export interface SnapshotPolicy {
  minRecordCount: number
  minDigitalCurrencyIdentifiers: number
  minEvmIdentifiers: number
  /** Reject a drop larger than this fraction versus the active snapshot (quarantine). */
  maxEntryShrink: number
  maxIdentifierShrink: number
  /** Tolerated clock skew for a publication date "in the future". */
  maxFuturePublishMs: number
}

// Floors sit far below the 2026-10-15 publication (19,457 entries, 1,066
// digital currency identifiers, 133 EVM-format), so they only catch empty,
// truncated or wrong documents, not ordinary delistings.
export const DEFAULT_SNAPSHOT_POLICY: SnapshotPolicy = Object.freeze({
  minRecordCount: 5000,
  minDigitalCurrencyIdentifiers: 200,
  minEvmIdentifiers: 25,
  maxEntryShrink: 0.05,
  maxIdentifierShrink: 0.2,
  maxFuturePublishMs: 36 * 60 * 60 * 1000,
})

export interface PreviousSnapshotSummary {
  publish_date: string
  entry_count: number
  digital_currency_identifiers: number
  evm_identifiers: number
}

export type CandidateValidation =
  | { ok: true }
  | { ok: false; disposition: 'reject' | 'quarantine'; reason: string; detail: string }

export function validateCandidate(
  parsed: ParsedSdnList,
  previous: PreviousSnapshotSummary | null,
  now: Date,
  policy: SnapshotPolicy = DEFAULT_SNAPSHOT_POLICY,
  options: { acceptShrinkage?: boolean } = {}
): CandidateValidation {
  const s = summarizeIdentifiers(parsed.identifiers)
  const reject = (reason: string, detail: string): CandidateValidation => ({ ok: false, disposition: 'reject', reason, detail })
  if (parsed.entry_count < policy.minRecordCount) return reject('too_few_entries', `${parsed.entry_count}`)
  if (s.digital_currency_identifiers < policy.minDigitalCurrencyIdentifiers) {
    return reject('too_few_identifiers', `${s.digital_currency_identifiers}`)
  }
  if (s.evm_identifiers < policy.minEvmIdentifiers) return reject('too_few_evm_identifiers', `${s.evm_identifiers}`)
  const published = Date.parse(`${parsed.publish_date}T00:00:00.000Z`)
  if (published - now.getTime() > policy.maxFuturePublishMs) return reject('publish_date_in_future', parsed.publish_date)
  if (previous) {
    if (parsed.publish_date < previous.publish_date) {
      return reject('publication_rollback', `${parsed.publish_date} is older than active ${previous.publish_date}`)
    }
    if (!options.acceptShrinkage) {
      const shrink = (now_: number, before: number) => (before > 0 ? (before - now_) / before : 0)
      const checks: Array<[string, number, number, number]> = [
        ['entries', parsed.entry_count, previous.entry_count, policy.maxEntryShrink],
        ['digital_currency_identifiers', s.digital_currency_identifiers, previous.digital_currency_identifiers, policy.maxIdentifierShrink],
        ['evm_identifiers', s.evm_identifiers, previous.evm_identifiers, policy.maxIdentifierShrink],
      ]
      for (const [name, current, before, max] of checks) {
        if (shrink(current, before) > max) {
          return {
            ok: false,
            disposition: 'quarantine',
            reason: 'abnormal_shrinkage',
            detail: `${name} fell from ${before} to ${current}; operator approval required`,
          }
        }
      }
    }
  }
  return { ok: true }
}

// --- Stored snapshot freshness ---------------------------------------------

export interface SnapshotRecord {
  snapshot_id: string
  dataset: string
  status: string
  source_url: string
  source_object: string | null
  publication_id: string | null
  publish_date: string
  record_count: number
  entry_count: number
  retrieved_at: string
  revalidated_at: string
  source_sha256: string
  index_sha256: string
  parser_version: string
  digital_currency_identifiers: number
  evm_identifiers: number
  evm_unique_addresses: number
}

export const DEFAULT_MAX_STALENESS_MS = 6 * 60 * 60 * 1000
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000

/** Hours from SANCTIONS_MAX_STALENESS_HOURS, clamped to [1, 24]; default 6. */
export function maxStalenessMsFromEnv(raw: string | undefined): number {
  const hours = Number(raw)
  if (!raw || !Number.isFinite(hours)) return DEFAULT_MAX_STALENESS_MS
  return Math.min(24, Math.max(1, hours)) * 60 * 60 * 1000
}

export type SnapshotAssessment =
  | { usable: true; age_ms: number }
  | { usable: false; reason: string; detail: string }

/**
 * Freshness is measured from the last successful revalidation against the
 * official source (the active snapshot's content was re-downloaded and its
 * SHA-256 matched), not from OFAC's publication date: OFAC can legitimately go
 * days without publishing, but we must have confirmed recently that the
 * official list is still exactly what we hold.
 */
export function assessSnapshot(
  record: SnapshotRecord,
  now: Date,
  maxStalenessMs: number = DEFAULT_MAX_STALENESS_MS
): SnapshotAssessment {
  if (record.dataset !== OFAC_SDN_DATASET) return { usable: false, reason: 'unsupported_dataset', detail: record.dataset }
  if (record.status !== 'active') return { usable: false, reason: 'not_active', detail: record.status }
  if (record.parser_version !== OFAC_SDN_PARSER_VERSION) {
    return { usable: false, reason: 'unsupported_parser_version', detail: record.parser_version }
  }
  if (!/^[0-9a-f]{64}$/.test(record.source_sha256) || !/^[0-9a-f]{64}$/.test(record.index_sha256)) {
    return { usable: false, reason: 'invalid_record', detail: 'digest format' }
  }
  const revalidated = Date.parse(record.revalidated_at)
  const retrieved = Date.parse(record.retrieved_at)
  if (!Number.isFinite(revalidated) || !Number.isFinite(retrieved) || revalidated < retrieved) {
    return { usable: false, reason: 'invalid_record', detail: 'timestamps' }
  }
  const age = now.getTime() - revalidated
  if (age < -MAX_CLOCK_SKEW_MS) return { usable: false, reason: 'future_timestamp', detail: record.revalidated_at }
  if (age > maxStalenessMs) {
    return {
      usable: false,
      reason: 'stale',
      detail: `last revalidated against OFAC at ${record.revalidated_at}, older than ${Math.round(maxStalenessMs / 3_600_000)}h`,
    }
  }
  return { usable: true, age_ms: Math.max(0, age) }
}

// --- Matching -----------------------------------------------------------

export type AddressClass = 'evm' | 'unsupported' | 'invalid'

/**
 * 'evm' — screenable. 'unsupported' — plausibly another currency's address
 * (base58 / bech32 / similar), which this service does not screen; no finding
 * is made. 'invalid' — not an address at all.
 */
export function classifyAddress(input: string): AddressClass {
  const value = typeof input === 'string' ? input.trim() : ''
  if (EVM_ADDRESS.test(value)) return 'evm'
  if (/^0x/i.test(value)) return 'invalid'
  if (/^[A-Za-z0-9]{25,128}$/.test(value)) return 'unsupported'
  return 'invalid'
}

export interface LoadedSnapshot {
  record: SnapshotRecord
  /** EVM-format identifiers only, keyed by lower-case address. */
  evm: Map<string, DigitalCurrencyIdentifier[]>
  /** When the snapshot was judged usable for this request. */
  assessed_at: string
}

export function indexEvmIdentifiers(identifiers: DigitalCurrencyIdentifier[]): Map<string, DigitalCurrencyIdentifier[]> {
  const map = new Map<string, DigitalCurrencyIdentifier[]>()
  for (const id of identifiers) {
    if (id.address_format !== 'evm') continue
    const list = map.get(id.normalized_value)
    if (list) list.push(id)
    else map.set(id.normalized_value, [id])
  }
  return map
}

export interface SanctionsMatch {
  sdn_uid: number
  sdn_name: string
  sdn_type: string | null
  programs: string[]
  identifier_type: string
  listed_value: string
  entry_url: string
}

export interface SanctionsIdentification {
  category: string
  name: string
  description: string
  url?: string
}

export interface SanctionsDatasetProvenance {
  name: string
  dataset: string
  source_url: string
  source_object: string | null
  publication_id: string | null
  publish_date: string
  record_count: number
  retrieved_at: string
  revalidated_at: string
  source_sha256: string
  index_sha256: string
  parser_version: string
  matching_version: string
  snapshot_id: string
  digital_currency_identifiers: number
  evm_identifiers: number
}

export interface SanctionsResult {
  address: string
  /** Compatibility field: true iff match_status === 'listed'. Read match_status and screening. */
  sanctioned: boolean
  match_status: 'listed' | 'not_listed'
  matches: SanctionsMatch[]
  /** Compatibility field (pre-incident shape); mirrors matches. */
  identifications: SanctionsIdentification[]
  screening: {
    scope: string
    coverage: string
    matching: string
    evaluated_at: string
    dataset: SanctionsDatasetProvenance
    limitations: string[]
  }
}

export function datasetProvenance(record: SnapshotRecord): SanctionsDatasetProvenance {
  return {
    name: OFAC_SDN_DATASET_NAME,
    dataset: record.dataset,
    source_url: record.source_url,
    source_object: record.source_object,
    publication_id: record.publication_id,
    publish_date: record.publish_date,
    record_count: record.record_count,
    retrieved_at: record.retrieved_at,
    revalidated_at: record.revalidated_at,
    source_sha256: record.source_sha256,
    index_sha256: record.index_sha256,
    parser_version: record.parser_version,
    matching_version: OFAC_SDN_MATCHING_VERSION,
    snapshot_id: record.snapshot_id,
    digital_currency_identifiers: record.digital_currency_identifiers,
    evm_identifiers: record.evm_identifiers,
  }
}

/** Exact screening of an EVM address against a usable snapshot. Caller validates the format. */
export function screenEvmAddress(snapshot: LoadedSnapshot, address: string): SanctionsResult {
  if (classifyAddress(address) !== 'evm') throw new Error('screenEvmAddress requires an EVM address')
  const hits = snapshot.evm.get(address.trim().toLowerCase()) ?? []
  const matches: SanctionsMatch[] = hits.map((h) => ({
    sdn_uid: h.sdn_uid,
    sdn_name: h.sdn_name,
    sdn_type: h.sdn_type,
    programs: [...h.programs],
    identifier_type: `${DCA_TYPE_PREFIX}${h.currency}`,
    listed_value: h.listed_value,
    entry_url: ofacEntryUrl(h.sdn_uid),
  }))
  return {
    address,
    sanctioned: matches.length > 0,
    match_status: matches.length > 0 ? 'listed' : 'not_listed',
    matches,
    identifications: matches.map((m) => ({
      category: 'OFAC SDN List',
      name: m.sdn_name,
      description: `${m.identifier_type}; programs: ${m.programs.join(', ') || 'none stated'}`,
      url: m.entry_url,
    })),
    screening: {
      scope: SANCTIONS_SCREENING_SCOPE,
      coverage: SCREENING_COVERAGE,
      matching: SCREENING_MATCHING,
      evaluated_at: snapshot.assessed_at,
      dataset: datasetProvenance(snapshot.record),
      limitations: [...SCREENING_LIMITATIONS],
    },
  }
}

/** `sha256:<base64url>` form of the source file digest, for receipt evidence_digest fields. */
export function sourceEvidenceDigest(sourceSha256Hex: string): string {
  return `sha256:${Buffer.from(sourceSha256Hex, 'hex').toString('base64url')}`
}
