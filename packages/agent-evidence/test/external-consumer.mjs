import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { cp, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { delimiter, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = fileURLToPath(new URL('../', import.meta.url))
const fixture = fileURLToPath(new URL('./fixtures/external-consumer/', import.meta.url))
const scratch = await mkdtemp(join(tmpdir(), 'ocd-agent-evidence-external-'))
const packDirectory = join(scratch, 'packed')
const npmEnvironment = { ...process.env, npm_config_cache: join(scratch, '.npm-cache') }
const npmCli = process.env.npm_execpath
assert.ok(npmCli, 'test:external must be launched through npm')
await cp(fixture, scratch, { recursive: true })
await mkdir(packDirectory)

const packOutput = execFileSync(process.execPath, [npmCli, 'pack', '--json', '--pack-destination', packDirectory], {
  cwd: packageRoot,
  encoding: 'utf8',
  env: npmEnvironment,
})
const packed = JSON.parse(packOutput)
assert.equal(packed.length, 1)
const files = packed[0].files.map((entry) => entry.path)
assert.ok(files.includes('dist/index.js'))
assert.ok(files.includes('dist/index.d.ts'))
assert.ok(files.includes('schemas/portable-file.schema.json'))
assert.ok(files.includes('conformance/valid-full-graph.json'))
assert.equal(files.some((name) => name.startsWith('src/') || name.startsWith('test/')), false)

const tarball = join(packDirectory, packed[0].filename)
await writeFile(join(scratch, 'package.json'), JSON.stringify({
  name: 'external-agent-evidence-consumer',
  private: true,
  type: 'module',
  dependencies: {
    '@onchaindiligence/agent-evidence': `file:${tarball.replaceAll('\\', '/')}`,
  },
  devDependencies: {
    '@types/node': '^22.0.0',
    typescript: '^5.6.0',
  },
}, null, 2))

execFileSync(process.execPath, [npmCli, 'install', '--ignore-scripts', '--no-audit', '--no-fund'], {
  cwd: scratch,
  stdio: 'inherit',
  env: npmEnvironment,
})

const consumerSource = await readFile(join(scratch, 'consumer.ts'), 'utf8')
assert.equal(consumerSource.includes('../src'), false)
assert.equal(consumerSource.includes('onchaindilige/'), false)

const compiler = join(scratch, 'node_modules', 'typescript', 'bin', 'tsc')
execFileSync(process.execPath, [compiler, '-p', 'tsconfig.json'], { cwd: scratch, stdio: 'inherit' })
const output = execFileSync(process.execPath, ['--import', './deny-network.mjs', './dist/consumer.js'], {
  cwd: scratch,
  encoding: 'utf8',
  env: { ...process.env, PATH: process.env.PATH?.split(delimiter).join(delimiter) },
})
const result = JSON.parse(output)
assert.deepEqual(result.record_kinds, [
  'agent', 'decision', 'evidence', 'execution', 'mandate', 'policy', 'principal', 'run',
])
assert.equal(result.execution_status, 'withheld-not-submitted')
assert.equal(result.valid, 'VALID')
assert.equal(result.invalid, 'INVALID')
assert.equal(result.unverifiable, 'UNVERIFIABLE')
process.stdout.write(`${JSON.stringify({ scratch, tarball, ...result })}\n`)
