import { cp, readFile, writeFile } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const check = process.argv.includes('--check')
const directory = new URL('./', import.meta.url)
const generated = JSON.parse(execFileSync(process.execPath, [fileURLToPath(new URL('./generate.mjs', directory))], { encoding: 'utf8' }))
const fixtures = {
  portable: 'valid-full-graph.json',
  noncanonicalPayload: 'noncanonical-payload.json',
  missingParent: 'missing-parent.json',
  bundleWithArtifacts: 'bundle-with-artifacts.json',
  bundleTamperedManifest: 'bundle-tampered-manifest.json',
  bundleRemovedArtifact: 'bundle-removed-artifact.json',
  bundleInsertedArtifact: 'bundle-inserted-artifact.json',
  bundleInvalidChild: 'bundle-invalid-child.json',
  bundleUnverifiableChild: 'bundle-unverifiable-child.json',
  bundleUnknownArtifactType: 'bundle-unknown-artifact-type.json',
  bundleBadReconciliationReference: 'bundle-bad-reconciliation-reference.json',
  bundleSingletonContradiction: 'bundle-singleton-contradiction.json',
}

for (const [selector, filename] of Object.entries(fixtures)) {
  const target = new URL(filename, directory)
  const expected = `${JSON.stringify(generated[selector], null, 2)}\n`
  const actual = await readFile(target, 'utf8').catch(() => null)
  if (check) {
    if (actual !== expected) throw new Error(`generated fixture drift: ${filename}`)
  } else if (actual !== expected) {
    await writeFile(target, expected)
  }
}

const packageConformance = new URL('../../../../packages/agent-evidence/conformance/', directory)
const pythonConformance = new URL('../../../../python/src/onchaindiligence/agent_evidence/conformance/', directory)
for (const filename of [...Object.values(fixtures), 'manifest.json', 'recognized-evidence-families.json']) {
  const source = new URL(filename, directory)
  for (const destination of [packageConformance, pythonConformance]) {
    const target = new URL(filename, destination)
    if (check) {
      const [left, right] = await Promise.all([readFile(source), readFile(target).catch(() => null)])
      if (!right || !left.equals(right)) throw new Error(`packaged fixture drift: ${target.pathname}`)
    } else {
      await cp(source, target)
    }
  }
}
