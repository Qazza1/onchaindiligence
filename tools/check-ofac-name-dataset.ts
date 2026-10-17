/**
 * Read-only pre-deploy check: downloads the live OFAC SDN.CSV / ALT.CSV that
 * name screening uses, runs the exact validator the service applies, and
 * prints the outcome and record counts. Writes nothing, signs nothing, caches
 * nothing. Run before deploying the dataset-validation change:
 *
 *   npx tsx tools/check-ofac-name-dataset.ts
 */
import { config } from '../src/config.js'
import { validateOfacDataset, OfacDatasetInvalidError } from '../src/ofac.js'

async function get(url: string) {
  const res = await fetch(url)
  return { status: res.status, type: res.headers.get('content-type'), text: await res.text() }
}

const [sdn, alt] = await Promise.all([get(config.ofac.sdnUrl), get(config.ofac.altUrl)])
console.log(`SDN ${config.ofac.sdnUrl}: HTTP ${sdn.status}, ${sdn.type}, ${sdn.text.length} chars`)
console.log(`ALT ${config.ofac.altUrl}: HTTP ${alt.status}, ${alt.type}, ${alt.text.length} chars`)
try {
  const { stats } = validateOfacDataset(sdn.text, alt.text)
  console.log('VALID', stats)
} catch (err) {
  if (!(err instanceof OfacDatasetInvalidError)) throw err
  console.log('REJECTED', err.reason, err.file, err.message)
  process.exitCode = 1
}
