import { BUNDLE_VERSION, RECORD_VERSION } from './constants.js'
import { cloneJson, contentId, formatTimestamp } from './canonical.js'
import { EvidenceValidationError, SchemaValidationError } from './errors.js'
import { validateBundlePayload } from './graph.js'
import { validateDocument } from './schema.js'
import type { AgentEvidenceRecord, BundlePayload, JsonObject, JsonValue, RecordKind } from './types.js'

export interface CreateRecordOptions {
  parents?: readonly string[]
  proofs?: readonly JsonObject[]
}

export function createRecord(
  kind: RecordKind,
  statement: JsonObject,
  options: CreateRecordOptions = {},
): AgentEvidenceRecord {
  const body = {
    record_version: RECORD_VERSION,
    kind,
    parents: [...new Set(options.parents ?? [])].sort(),
    statement: cloneJson(statement),
    proofs: cloneJson([...(options.proofs ?? [])] as JsonValue[]) as JsonObject[],
  }
  const record = { id: contentId(body), ...body }
  try {
    validateDocument('record.schema.json', record)
  } catch (error) {
    if (error instanceof SchemaValidationError) throw new EvidenceValidationError(error.message, { cause: error })
    throw error
  }
  return record
}

export interface CreateBundlePayloadOptions {
  createdAt: string | Date
  runId?: string
  rootIds?: readonly string[]
  extensions?: JsonObject
}

export function createBundlePayload(
  inputRecords: Iterable<AgentEvidenceRecord>,
  options: CreateBundlePayloadOptions,
): BundlePayload {
  const records = [...inputRecords].map((record) => cloneJson(record as unknown as JsonValue) as unknown as AgentEvidenceRecord)
  records.sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0)
  const runs = records.filter((record) => record.kind === 'run')
  const runId = options.runId ?? (runs.length === 1 ? runs[0]?.id : undefined)
  if (!runId) throw new EvidenceValidationError('run_id can only be inferred when exactly one run exists')
  const parentIds = new Set(records.flatMap((record) => record.parents))
  const computedRoots = records.map((record) => record.id).filter((id) => !parentIds.has(id)).sort()
  const createdAt = options.createdAt instanceof Date ? formatTimestamp(options.createdAt) : options.createdAt
  const withoutId = {
    bundle_version: BUNDLE_VERSION,
    created_at: createdAt,
    run_id: runId,
    root_ids: [...(options.rootIds ?? computedRoots)],
    records,
    extensions: cloneJson((options.extensions ?? {}) as JsonValue) as JsonObject,
  }
  const payload: BundlePayload = {
    bundle_version: BUNDLE_VERSION,
    bundle_id: contentId(withoutId),
    created_at: createdAt,
    run_id: runId,
    root_ids: withoutId.root_ids,
    records,
    extensions: withoutId.extensions,
  }
  validateBundlePayload(payload)
  return payload
}
