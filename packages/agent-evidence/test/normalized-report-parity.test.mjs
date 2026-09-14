import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFile, writeFile } from 'node:fs/promises'
import { delimiter, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { TrustPolicy, verifyBundle } from '../dist/index.js'

const repositoryRoot = fileURLToPath(new URL('../../../', import.meta.url))
const corpus = new URL('../conformance/', import.meta.url)
const pythonVerifier = fileURLToPath(new URL('./python-verify.py', import.meta.url))
const python = process.env.P1_9_PYTHON ?? 'python'
const pythonPath = [join(repositoryRoot, 'python', 'src'), process.env.PYTHONPATH].filter(Boolean).join(delimiter)
const environment = { ...process.env, PYTHONPATH: pythonPath }

async function json(name) {
  return JSON.parse(await readFile(new URL(name, corpus), 'utf8'))
}

function normalized(report) {
  return {
    bundle_integrity: report.bundle_integrity,
    artifact_verifications: report.artifact_verifications,
    reconciliation: report.reconciliation,
    limitations: report.limitations,
  }
}

test('TypeScript and Python expose the same normalized portable bundle report', async (t) => {
  const base = await json('valid-full-graph.json')
  const trust = { keys: base.verification_material.keys }
  const trustPath = fileURLToPath(new URL(`./d42-parity-${process.pid}.json`, corpus))
  await writeFile(trustPath, JSON.stringify(trust))
  t.after(async () => { await import('node:fs/promises').then(({ unlink }) => unlink(trustPath)) })
  const policy = TrustPolicy.fromKeyRecords(trust.keys, { now: new Date('2026-08-28T12:01:00.000Z') })
  for (const fixture of [
    'bundle-with-artifacts.json',
    'bundle-invalid-child.json',
    'bundle-invalid-embedded-receipt-no-external-proof.json',
    'bundle-unverifiable-referenced-receipt.json',
    'bundle-unverifiable-child.json',
    'bundle-unknown-artifact-type.json',
    'bundle-bad-reconciliation-reference.json',
  ]) {
    const path = fileURLToPath(new URL(fixture, corpus))
    const typescript = verifyBundle(await json(fixture), policy)
    const child = spawnSync(python, [pythonVerifier, path, trustPath], { cwd: repositoryRoot, env: environment, encoding: 'utf8' })
    assert.equal(child.error, undefined, fixture)
    assert.ok(child.stdout, `${fixture}: Python verifier produced no report: ${child.stderr}`)
    const pythonReport = JSON.parse(child.stdout)
    assert.deepEqual(normalized(typescript), normalized(pythonReport), fixture)
  }
})
