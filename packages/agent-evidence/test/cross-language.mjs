import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { delimiter, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { TrustPolicy, verifyBundle } from '../dist/index.js'

const repositoryRoot = fileURLToPath(new URL('../../../', import.meta.url))
const fixturePath = fileURLToPath(new URL('../conformance/valid-full-graph.json', import.meta.url))
const pythonVerifier = fileURLToPath(new URL('./python-verify.py', import.meta.url))
const portable = JSON.parse(await readFile(fixturePath, 'utf8'))
const trust = { keys: portable.verification_material.keys }
const scratch = await mkdtemp(join(tmpdir(), 'ocd-agent-evidence-cross-language-'))
const trustPath = join(scratch, 'trust.json')
await writeFile(trustPath, JSON.stringify(trust))

const typescriptReport = verifyBundle(portable, TrustPolicy.fromKeyRecords(trust.keys, {
  now: new Date('2026-08-28T12:01:00.000Z'),
}))
assert.equal(typescriptReport.state, 'VALID')

const pythonPath = [
  join(repositoryRoot, 'python', 'src'),
  process.env.PYTHONPATH,
].filter(Boolean).join(delimiter)
const environment = { ...process.env, PYTHONPATH: pythonPath }
const python = process.env.P1_9_PYTHON ?? 'python'
const pythonOutput = execFileSync(python, [pythonVerifier, fixturePath, trustPath], {
  cwd: repositoryRoot,
  env: environment,
  encoding: 'utf8',
})
const pythonReport = JSON.parse(pythonOutput)
assert.equal(pythonReport.state, 'VALID')
assert.equal(pythonReport.bundle_id, typescriptReport.bundle_id)

// The canonical Python producer must still reproduce the TypeScript-generated
// immutable vector byte-for-byte.
execFileSync(python, [
  '-m', 'pytest',
  'python/tests/test_conformance.py::test_python_producer_exactly_matches_typescript_fixture',
  '-q',
], { cwd: repositoryRoot, env: environment, stdio: 'inherit' })

process.stdout.write(JSON.stringify({
  vector: fixturePath,
  typescript: typescriptReport.state,
  python: pythonReport.state,
  bundle_id: typescriptReport.bundle_id,
  python_producer_matches_typescript_vector: true,
}) + '\n')
