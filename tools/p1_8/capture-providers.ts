/**
 * Capture two public-safe live provider observations through the same clients
 * and v2 attestation path used by the production API.
 *
 * The caller supplies a dedicated Ed25519 managed-witness key through the
 * process environment. This script never reads dotenv files and never writes
 * private key material to disk.
 */

import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import {
  attest,
  attestationEnabled,
  getAttestationKeyRecord,
  getKeyId,
} from '../../src/attestation.js'
import {
  buildAttribution as chainalysisAttribution,
  screenAddress,
} from '../../src/chainalysis.js'
import { canonicalizeJson } from '../../src/canonicalJson.js'
import {
  buildAttribution as edgarAttribution,
  checkUSCompany,
} from '../../src/secEdgar.js'

const PUBLIC_WALLET = '0x000000000000000000000000000000000000dEaD'
const PUBLIC_COMPANY_QUERY = 'AAPL'

function outputPath(): string {
  const index = process.argv.indexOf('--output')
  const value = index >= 0 ? process.argv[index + 1] : undefined
  if (!value) throw new Error('usage: npm run p1.8:capture -- --output <capture.json>')
  return resolve(value)
}

function requireSignedEnvelope(value: Record<string, unknown>): Record<string, unknown> {
  const metadata = value.attestation
  if (
    !metadata ||
    typeof metadata !== 'object' ||
    (metadata as Record<string, unknown>).signed !== true
  ) {
    throw new Error('provider observation was not signed by the managed-witness key')
  }
  return value
}

async function main(): Promise<void> {
  if (!attestationEnabled()) {
    throw new Error('ATTESTATION_PRIVATE_KEY must contain a dedicated Ed25519 PKCS8 key')
  }
  const keyId = getKeyId()
  const keyRecord = keyId ? getAttestationKeyRecord(keyId) : null
  if (!keyId || !keyRecord || !keyRecord.valid_from) {
    throw new Error('the managed-witness key requires an explicit ATTESTATION_KEY_ACTIVATED_AT')
  }

  const walletRequest = { address: PUBLIC_WALLET }
  const walletResult = await screenAddress(PUBLIC_WALLET)
  const walletEnvelope = requireSignedEnvelope(
    attest({
      ...walletResult,
      ...chainalysisAttribution(),
      checked_at: new Date().toISOString(),
    })
  )

  const companyRequest = { query: PUBLIC_COMPANY_QUERY }
  const companyResult = await checkUSCompany(PUBLIC_COMPANY_QUERY)
  const companyEnvelope = requireSignedEnvelope(
    attest({
      ...companyResult,
      ...edgarAttribution(),
      checked_at: new Date().toISOString(),
    })
  )

  const capture = {
    capture_version: 'onchaindiligence.p1.8.provider-capture.v1',
    captured_at: new Date().toISOString(),
    witness: {
      role: 'dedicated-p1.8-managed-witness',
      key_record: keyRecord,
      boundary:
        'This dedicated reference key proves what OnChainDiligence observed through its production provider clients. It is not the unresolved live production API key.',
    },
    observations: [
      {
        provider_id: 'chainalysis-onchain-sanctions-oracle',
        evidence_type: 'sanctions-screen',
        source_type: 'public-onchain-read',
        tool: { name: 'screen_wallet', version: '1' },
        request: walletRequest,
        scope: {
          query: PUBLIC_WALLET,
          coverage:
            'One public burn address checked through isSanctioned() on the Chainalysis Ethereum mainnet oracle at the signed observation time.',
        },
        signed_envelope: walletEnvelope,
      },
      {
        provider_id: 'sec-edgar-submissions',
        evidence_type: 'us-public-company-record',
        source_type: 'public-https-api',
        tool: { name: 'verify_us_company', version: '1' },
        request: companyRequest,
        scope: {
          query: PUBLIC_COMPANY_QUERY,
          coverage:
            'One SEC filer resolved by public ticker and observed through SEC EDGAR; private companies are outside this provider scope.',
        },
        signed_envelope: companyEnvelope,
      },
    ],
  }

  const target = outputPath()
  await mkdir(dirname(target), { recursive: true })
  await writeFile(target, canonicalizeJson(capture) + '\n', { encoding: 'utf8', flag: 'w' })
  process.stdout.write(`captured 2 signed provider envelopes with ${keyId}\n`)
}

await main()
