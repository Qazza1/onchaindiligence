import { cp, mkdir, readFile, readdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const check = process.argv.includes('--check')
const packageRoot = new URL('../', import.meta.url)
const repositoryRoot = new URL('../../../', import.meta.url)
const sources = [
  [new URL('spec/agent-evidence/v0/schema/', repositoryRoot), new URL('schemas/', packageRoot)],
  [new URL('spec/agent-evidence/v0/conformance/', repositoryRoot), new URL('conformance/', packageRoot)],
  [new URL('conformance/rfc8785-vectors.json', repositoryRoot), new URL('conformance/rfc8785-vectors.json', packageRoot)],
]

async function sameFile(source, destination) {
  try {
    const [left, right] = await Promise.all([readFile(source), readFile(destination)])
    return left.equals(right)
  } catch {
    return false
  }
}

for (const [source, destination] of sources) {
  if (source.pathname.endsWith('/')) {
    const entries = (await readdir(source, { withFileTypes: true }))
      .filter((entry) => entry.isFile() && (entry.name.endsWith('.json') || entry.name === 'README.md'))
    if (!check) await mkdir(destination, { recursive: true })
    for (const entry of entries) {
      const from = new URL(entry.name, source)
      const to = new URL(entry.name, destination)
      if (check) {
        if (!(await sameFile(from, to))) {
          throw new Error(`packaged asset drift: ${fileURLToPath(to)}`)
        }
      } else {
        await cp(from, to)
      }
    }
  } else if (check) {
    if (!(await sameFile(source, destination))) {
      throw new Error(`packaged asset drift: ${fileURLToPath(destination)}`)
    }
  } else {
    await mkdir(new URL('./', destination), { recursive: true })
    await cp(source, destination)
  }
}
