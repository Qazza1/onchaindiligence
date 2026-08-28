import assert from 'node:assert/strict'
import { createHash, createPublicKey, verify } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'

const schemaDirectory = fileURLToPath(new URL('../spec/agent-evidence/v0/schema/', import.meta.url))
const fixtureDirectory = fileURLToPath(new URL('../spec/agent-evidence/v0/conformance/', import.meta.url))
const generatorFile = fileURLToPath(new URL('../spec/agent-evidence/v0/conformance/generate.mjs', import.meta.url))
const schemaBase = 'https://onchaindiligence.com/schemas/agent-evidence/v0/'
const payloadType = 'application/vnd.onchaindiligence.agent-evidence.bundle.v0+json'

async function jsonFile(directory, name) {
  return JSON.parse(await readFile(`${directory}/${name}`, 'utf8'))
}

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite JSON number')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
  }
  throw new TypeError(`value of type ${typeof value} is not JSON`)
}

function contentId(value) {
  return `sha256:${createHash('sha256').update(canonical(value)).digest('base64url')}`
}

function pae(type, bytes) {
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${bytes.length} `),
    bytes,
  ])
}

function decodePayload(portable) {
  const bytes = Buffer.from(portable.envelope.payload, 'base64')
  return { bytes, value: JSON.parse(bytes.toString('utf8')) }
}

function signatureValid(portable) {
  const key = portable.verification_material.keys.find(
    (candidate) => candidate.key_id === portable.envelope.signatures[0].keyid,
  )
  assert.ok(key, 'fixture must carry its untrusted verification hint')
  return verify(
    null,
    pae(portable.envelope.payloadType, Buffer.from(portable.envelope.payload, 'base64')),
    createPublicKey(key.public_key_pem),
    Buffer.from(portable.envelope.signatures[0].sig, 'base64'),
  )
}

function parseJsonNoDuplicateKeys(text, maxDepth = 64) {
  const parsed = JSON.parse(text)
  let index = 0
  const whitespace = () => {
    while (/\s/.test(text[index] ?? '')) index += 1
  }
  const stringToken = () => {
    const start = index
    index += 1
    while (index < text.length) {
      if (text[index] === '\\') index += 2
      else if (text[index] === '"') {
        index += 1
        return text.slice(start, index)
      } else index += 1
    }
    throw new SyntaxError('unterminated JSON string')
  }
  const value = (depth) => {
    if (depth > maxDepth) throw new SyntaxError(`JSON exceeds maximum depth ${maxDepth}`)
    whitespace()
    const character = text[index]
    if (character === '{') {
      index += 1
      whitespace()
      const keys = new Set()
      if (text[index] === '}') {
        index += 1
        return
      }
      while (true) {
        whitespace()
        if (text[index] !== '"') throw new SyntaxError('expected JSON object key')
        const key = JSON.parse(stringToken())
        if (keys.has(key)) throw new SyntaxError(`duplicate JSON object key: ${key}`)
        keys.add(key)
        whitespace()
        if (text[index] !== ':') throw new SyntaxError('expected colon')
        index += 1
        value(depth + 1)
        whitespace()
        if (text[index] === '}') {
          index += 1
          return
        }
        if (text[index] !== ',') throw new SyntaxError('expected comma')
        index += 1
      }
    }
    if (character === '[') {
      index += 1
      whitespace()
      if (text[index] === ']') {
        index += 1
        return
      }
      while (true) {
        value(depth + 1)
        whitespace()
        if (text[index] === ']') {
          index += 1
          return
        }
        if (text[index] !== ',') throw new SyntaxError('expected comma')
        index += 1
      }
    }
    if (character === '"') {
      stringToken()
      return
    }
    const match = text.slice(index).match(/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/)
    if (!match) throw new SyntaxError('invalid JSON value')
    if (/^-?(?:0|[1-9]\d*)$/.test(match[0])) {
      const integer = BigInt(match[0])
      if (integer > BigInt(Number.MAX_SAFE_INTEGER) || integer < BigInt(Number.MIN_SAFE_INTEGER)) {
        throw new SyntaxError('JSON integer exceeds safe range')
      }
    }
    index += match[0].length
  }
  value(0)
  whitespace()
  if (index !== text.length) throw new SyntaxError('unexpected trailing data')
  return parsed
}

function assertValidGraph(payload) {
  const byId = new Map(payload.records.map((record) => [record.id, record]))
  assert.equal(byId.size, payload.records.length, 'record IDs must be unique')
  assert.deepEqual(payload.records.map(({ id }) => id), [...byId.keys()].sort(), 'records must be sorted')

  for (const record of payload.records) {
    const { id, ...body } = record
    assert.equal(id, contentId(body), `record ID must bind ${record.kind}`)
    assert.deepEqual(record.parents, [...new Set(record.parents)].sort(), 'parents must be sorted and unique')
    for (const parent of record.parents) assert.ok(byId.has(parent), `missing parent ${parent}`)
  }

  const run = payload.records.filter(({ kind }) => kind === 'run')
  assert.equal(run.length, 1)
  assert.equal(payload.run_id, run[0].id)

  const parentIds = new Set(payload.records.flatMap(({ parents }) => parents))
  const roots = payload.records.map(({ id }) => id).filter((id) => !parentIds.has(id)).sort()
  assert.deepEqual(payload.root_ids, roots)

  const state = new Map()
  const visit = (id) => {
    if (state.get(id) === 'visiting') assert.fail(`cycle at ${id}`)
    if (state.get(id) === 'visited') return
    state.set(id, 'visiting')
    for (const parent of byId.get(id).parents) visit(parent)
    state.set(id, 'visited')
  }
  for (const root of roots) visit(root)
  assert.equal(state.size, payload.records.length, 'every record must be reachable from a root')

  const withoutId = { ...payload }
  delete withoutId.bundle_id
  assert.equal(payload.bundle_id, contentId(withoutId), 'bundle ID must bind the canonical payload')
}

const catalog = await jsonFile(schemaDirectory, 'catalog.json')
const ajv = new Ajv2020({ allErrors: true, strict: true })
addFormats(ajv)
for (const name of catalog.schemas) ajv.addSchema(await jsonFile(schemaDirectory, name))
const validatePortable = ajv.getSchema(`${schemaBase}portable-file.schema.json`)
const validatePayload = ajv.getSchema(`${schemaBase}bundle-payload.schema.json`)
assert.ok(validatePortable)
assert.ok(validatePayload)

test('all published schemas compile and the full graph fixture conforms', async () => {
  for (const name of catalog.schemas) assert.ok(ajv.getSchema(`${schemaBase}${name}`), `${name} was not registered`)
  const portable = await jsonFile(fixtureDirectory, 'valid-full-graph.json')
  assert.equal(validatePortable(portable), true, JSON.stringify(validatePortable.errors))
  const { bytes, value: payload } = decodePayload(portable)
  assert.equal(validatePayload(payload), true, JSON.stringify(validatePayload.errors))
  assert.equal(bytes.toString('utf8'), canonical(payload), 'payload bytes must be RFC 8785')
  assert.equal(signatureValid(portable), true)
  assertValidGraph(payload)
  assert.deepEqual(new Set(payload.records.map(({ kind }) => kind)), new Set([
    'principal', 'agent', 'mandate', 'run', 'evidence', 'policy', 'decision', 'execution',
  ]))
})

test('static fixtures exactly match deterministic generator output', async () => {
  for (const [selector, name] of [
    ['portable', 'valid-full-graph.json'],
    ['noncanonicalPayload', 'noncanonical-payload.json'],
    ['missingParent', 'missing-parent.json'],
  ]) {
    const generated = JSON.parse(execFileSync(process.execPath, [generatorFile, selector], { encoding: 'utf8' }))
    assert.deepEqual(generated, await jsonFile(fixtureDirectory, name), name)
  }
})

test('corpus isolates signature, canonicalization, graph, version, trust, and parser failures', async () => {
  const manifest = await jsonFile(fixtureDirectory, 'manifest.json')
  assert.deepEqual(manifest.cases.map(({ expected }) => expected), [
    'VALID', 'INVALID', 'INVALID', 'INVALID', 'INVALID', 'UNVERIFIABLE', 'INVALID',
  ])

  const valid = await jsonFile(fixtureDirectory, 'valid-full-graph.json')
  const invalidSignature = structuredClone(valid)
  invalidSignature.envelope.signatures[0].sig = manifest.cases.find(({ id }) => id === 'invalid-signature')
    .outer_json_patch[0].value
  assert.equal(signatureValid(invalidSignature), false)

  const versionMismatch = structuredClone(valid)
  versionMismatch.bundle_version = 'onchaindiligence.agent-evidence.bundle.v9'
  assert.equal(validatePortable(versionMismatch), false)

  const noncanonical = await jsonFile(fixtureDirectory, 'noncanonical-payload.json')
  const noncanonicalDecoded = decodePayload(noncanonical)
  assert.equal(validatePortable(noncanonical), true, JSON.stringify(validatePortable.errors))
  assert.equal(validatePayload(noncanonicalDecoded.value), true, JSON.stringify(validatePayload.errors))
  assert.equal(signatureValid(noncanonical), true, 'the canonicalization case must not also be a signature failure')
  assert.notEqual(noncanonicalDecoded.bytes.toString('utf8'), canonical(noncanonicalDecoded.value))
  assert.equal(noncanonicalDecoded.bytes[0], 0x20)

  const missingParent = await jsonFile(fixtureDirectory, 'missing-parent.json')
  const missingPayload = decodePayload(missingParent).value
  assert.equal(signatureValid(missingParent), true, 'the graph case must not also be a signature failure')
  assert.equal(validatePayload(missingPayload), true, JSON.stringify(validatePayload.errors))
  assert.throws(() => assertValidGraph(missingPayload), /record ID|missing parent/)

  const duplicate = await readFile(`${fixtureDirectory}/duplicate-outer-key.json`, 'utf8')
  assert.throws(() => parseJsonNoDuplicateKeys(duplicate), /duplicate JSON object key/)

  const unknownKey = manifest.cases.find(({ id }) => id === 'unknown-key')
  assert.deepEqual(unknownKey.trusted_key_ids, [])
  assert.equal(unknownKey.expected, 'UNVERIFIABLE')
})

test('schema rejects lexical drift and loose proof shapes', () => {
  const portable = {
    media_type: 'application/vnd.onchaindiligence.agent-evidence+json',
    bundle_version: 'onchaindiligence.agent-evidence.bundle.v0',
    envelope: { payloadType, payload: 'e30=', signatures: [{ keyid: 'ed25519-AAAAAAAAAAAAAAAA', sig: 'AA==' }] },
    verification_material: { keys: [], registry_snapshots: [], anchors: [] },
  }
  assert.equal(validatePortable(portable), true, JSON.stringify(validatePortable.errors))

  const validateProof = ajv.getSchema(`${schemaBase}proof.schema.json`)
  assert.equal(validateProof({
    proof_type: 'external-digest',
    media_type: 'application/json',
    digest: { sha256: 'A'.repeat(43) },
    unexpected: true,
  }), false)

  const valid = {
    bundle_version: 'onchaindiligence.agent-evidence.bundle.v0',
    bundle_id: `sha256:${'A'.repeat(43)}`,
    created_at: '2026-08-28T12:00:00Z',
    run_id: `sha256:${'B'.repeat(43)}`,
    root_ids: [`sha256:${'B'.repeat(43)}`],
    records: [],
    extensions: {},
  }
  assert.equal(validatePayload(valid), false, 'timestamps without exactly three fractional digits must fail')
})
