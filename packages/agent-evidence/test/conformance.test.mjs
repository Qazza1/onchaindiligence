import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import {
  canonicalizeText,
  parseJson,
  TrustPolicy,
  verifyBundle,
} from '../dist/index.js'

const conformance = new URL('../conformance/', import.meta.url)
const schemas = new URL('../schemas/', import.meta.url)
const repositorySchemas = new URL('../../../spec/agent-evidence/v0/schema/', import.meta.url)
const repositoryConformance = new URL('../../../spec/agent-evidence/v0/conformance/', import.meta.url)

async function json(url) {
  return JSON.parse(await readFile(url, 'utf8'))
}

function policyFor(portable, keyIds) {
  const keys = portable.verification_material.keys.filter((key) => keyIds.includes(key.key_id))
  return TrustPolicy.fromKeyRecords(keys, { now: new Date('2026-08-28T12:01:00.000Z') })
}

function applyPatch(value, patches) {
  const copy = structuredClone(value)
  for (const patch of patches ?? []) {
    assert.equal(patch.op, 'replace')
    const path = patch.path.split('/').slice(1).map((part) => part.replaceAll('~1', '/').replaceAll('~0', '~'))
    let target = copy
    for (const part of path.slice(0, -1)) target = target[part]
    target[path.at(-1)] = patch.value
  }
  return copy
}

test('packaged schemas and corpus are byte-identical to the canonical repository contract', async () => {
  const catalog = await json(new URL('catalog.json', schemas))
  for (const name of catalog.schemas) {
    assert.deepEqual(
      await readFile(new URL(name, schemas)),
      await readFile(new URL(name, repositorySchemas)),
      name,
    )
  }
  for (const name of [
    'manifest.json',
    'valid-full-graph.json',
    'noncanonical-payload.json',
    'missing-parent.json',
    'duplicate-outer-key.json',
  ]) {
    assert.deepEqual(
      await readFile(new URL(name, conformance)),
      await readFile(new URL(name, repositoryConformance)),
      name,
    )
  }
})

test('shared RFC 8785 and strict-parser vectors pass without a TypeScript-only dialect', async () => {
  const vectors = await json(new URL('rfc8785-vectors.json', conformance))
  for (const vector of vectors.canonicalization) {
    assert.equal(canonicalizeText(vector.input), vector.expected, vector.id)
  }
  for (const vector of vectors.invalid_json) {
    assert.throws(() => parseJson(vector.input), undefined, vector.id)
  }
  assert.throws(() => canonicalizeText('\ud800'), /unpaired surrogate/)
  assert.throws(() => canonicalizeText({ unsafe: Number.MAX_SAFE_INTEGER + 1 }), /safe-integer/)
})

test('the public verifier consumes every canonical tri-state corpus case', async () => {
  const manifest = await json(new URL('manifest.json', conformance))
  for (const vector of manifest.cases) {
    if (vector.id === 'duplicate-outer-key') {
      const raw = await readFile(new URL(vector.fixture, conformance), 'utf8')
      const valid = await json(new URL(manifest.base_fixture, conformance))
      assert.equal(verifyBundle(raw, policyFor(valid, vector.trusted_key_ids)).state, vector.expected, vector.id)
      continue
    }
    const portable = applyPatch(await json(new URL(vector.fixture, conformance)), vector.outer_json_patch)
    assert.equal(verifyBundle(portable, policyFor(portable, vector.trusted_key_ids)).state, vector.expected, vector.id)
  }
})

test('embedded verification keys remain hints and never become ambient trust', async () => {
  const portable = await json(new URL('valid-full-graph.json', conformance))
  assert.ok(portable.verification_material.keys.length)
  const report = verifyBundle(portable, TrustPolicy.fromKeyRecords([], {
    now: new Date('2026-08-28T12:01:00.000Z'),
  }))
  assert.equal(report.state, 'UNVERIFIABLE')
  assert.ok(report.components.some((component) => component.code === 'key-not-trusted'))
})
