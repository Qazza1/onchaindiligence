import { readFileSync } from 'node:fs'
import Ajv2020Import, { type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js'
import addFormatsImport from 'ajv-formats'
import { SchemaValidationError } from './errors.js'

export const SCHEMA_BASE = 'https://onchaindiligence.com/schemas/agent-evidence/v0/'
export const SCHEMA_NAMES = [
  'common.schema.json',
  'attestation-key.schema.json',
  'dsse-envelope.schema.json',
  'proof.schema.json',
  'record.schema.json',
  'bundle-payload.schema.json',
  'portable-file.schema.json',
] as const

interface AjvRuntime {
  addSchema(schema: unknown): void
  getSchema(id: string): ValidateFunction | undefined
}

const Ajv2020 = Ajv2020Import as unknown as new (options: Record<string, unknown>) => AjvRuntime
const addFormats = addFormatsImport as unknown as (instance: AjvRuntime) => void
const ajv = new Ajv2020({ allErrors: true, strict: true })
addFormats(ajv)
for (const name of SCHEMA_NAMES) {
  const bytes = readFileSync(new URL(`../schemas/${name}`, import.meta.url), 'utf8')
  ajv.addSchema(JSON.parse(bytes))
}

function validator(name: string): ValidateFunction {
  if (!(SCHEMA_NAMES as readonly string[]).includes(name)) {
    throw new RangeError(`unknown Agent Evidence schema: ${name}`)
  }
  const validate = ajv.getSchema(`${SCHEMA_BASE}${name}`)
  if (!validate) throw new Error(`packaged Agent Evidence schema did not compile: ${name}`)
  return validate
}

function errorSortKey(error: ErrorObject): string {
  return `${error.instancePath}\u0000${error.schemaPath}\u0000${error.keyword}`
}

export function validateDocument(name: string, value: unknown): void {
  const validate = validator(name)
  if (validate(value)) return
  const errors = [...(validate.errors ?? [])].sort((left, right) => errorSortKey(left).localeCompare(errorSortKey(right)))
  const error = errors[0]
  if (!error) throw new SchemaValidationError(`${name}/: schema validation failed`)
  throw new SchemaValidationError(`${name}${error.instancePath || '/'}: ${error.message ?? error.keyword}`)
}
