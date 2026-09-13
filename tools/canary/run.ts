#!/usr/bin/env -S npx tsx
/**
 * D4.0 production trust canary.
 *
 * Read-only, external probe of the live production surfaces (API, app,
 * and the public MCP server over plain HTTP). Never sends a payment, never
 * writes to chain, never touches this repo's own signing key. Every check
 * hits a real, already-deployed production endpoint from the outside --
 * it does not import or execute this repo's own server code, so it cannot
 * silently pass just because the code it would have exercised didn't run.
 *
 * Deliberately does NOT touch onchaindiligence-mcp's source or implementation
 * -- it only calls its already-public HTTP endpoints, the same way any
 * external agent would. This keeps the canary out of the way of concurrent
 * MCP implementation work in that repo.
 *
 * Usage: npx tsx tools/canary/run.ts
 * Exit code: 0 if every invariant held, 1 if any failed.
 * Output: one JSON object on stdout (machine-readable), a short human
 * summary on stderr.
 */

const API = 'https://api.onchaindiligence.com'
const APP = 'https://app.onchaindiligence.com'
const MCP = 'https://mcp.onchaindiligence.com'
const TIMEOUT_MS = 12000

type Result = {
  id: string
  description: string
  ok: boolean
  detail: string
  ms: number
}

const results: Result[] = []

async function timed<T>(fn: () => Promise<T>): Promise<{ value: T; ms: number }> {
  const start = Date.now()
  const value = await fn()
  return { value, ms: Date.now() - start }
}

async function fetchWithTimeout(url: string, init: RequestInit = {}): Promise<Response> {
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS)
  try {
    return await fetch(url, { ...init, signal: ctl.signal })
  } finally {
    clearTimeout(timer)
  }
}

async function check(id: string, description: string, fn: () => Promise<{ ok: boolean; detail: string }>) {
  try {
    const { value, ms } = await timed(fn)
    results.push({ id, description, ok: value.ok, detail: value.detail, ms })
  } catch (err) {
    results.push({
      id,
      description,
      ok: false,
      detail: `threw: ${err instanceof Error ? err.message : String(err)}`,
      ms: TIMEOUT_MS,
    })
  }
}

// ---------------------------------------------------------------------
// 1. Unauthorized/internal attestation access rejects.
// ---------------------------------------------------------------------
await check(
  'internal-attest-rejects',
  'POST /attest with no/invalid internal bearer rejects before signing anything',
  async () => {
    const res = await fetchWithTimeout(`${API}/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer not-a-real-token' },
      body: JSON.stringify({ data: { probe: true } }),
    })
    const ok = res.status === 401 || res.status === 503
    return { ok, detail: `status=${res.status} (expected 401 unauthorized, or 503 if the internal token is unconfigured)` }
  }
)

// ---------------------------------------------------------------------
// 2. Malformed artifact -> INVALID/UNVERIFIABLE safely (never VALID, never
//    a thrown exception surfaced as a 500, never treated as trustworthy).
// ---------------------------------------------------------------------
await check(
  'malformed-artifact-safe',
  'A structurally tampered attestation envelope is safely rejected, not accepted or thrown',
  async () => {
    // A real key id shape, deliberately wrong signature -- exercises the
    // "cryptographically checked, not just shape-checked" path via /anchor's
    // own envelope verification (fails fast, before payment, per M6/OD-022).
    const fakeEnvelope = {
      data: { address: '0x0000000000000000000000000000000000000001', sanctioned: false },
      attestation: {
        signed: true,
        schema_version: 'onchaindiligence.attestation.v2',
        issuer: API,
        purpose: 'compliance-screening-result',
        issued_at: new Date().toISOString(),
        key_id: 'ed25519-canary-nonexistent-key',
        algorithm: 'ed25519',
        canonicalization: 'RFC8785',
        signature: 'dGFtcGVyZWQtc2lnbmF0dXJlLWJ5dGVzLW5vdC1yZWFs',
      },
    }
    const res = await fetchWithTimeout(`${API}/anchor`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(fakeEnvelope),
    })
    const body = await res.json().catch(() => ({}))
    // Must never be 200 (that would mean a fake envelope anchored) and must
    // respond fast (never the old OD-034 hang).
    const ok = res.status !== 200 && res.status < 500
    return { ok, detail: `status=${res.status} body=${JSON.stringify(body).slice(0, 160)}` }
  }
)

// ---------------------------------------------------------------------
// 3. HEAD /mcp is bounded and returns the correct fast rejection.
// ---------------------------------------------------------------------
await check(
  'head-mcp-bounded',
  'HEAD /mcp returns fast (bounded) with the correct status, not a hang',
  async () => {
    const res = await fetchWithTimeout(`${MCP}/mcp`, { method: 'HEAD' })
    const contentLength = res.headers.get('content-length')
    const ok = res.status === 405 && (contentLength === '0' || contentLength === null)
    return { ok, detail: `status=${res.status} content-length=${contentLength}` }
  }
)

// ---------------------------------------------------------------------
// 4. Malformed paid request fails before payment (never a 402 for garbage
//    input, and never a 500).
// ---------------------------------------------------------------------
await check(
  'malformed-paid-request-precheck',
  'A malformed paid request (invalid address) is rejected before any payment challenge',
  async () => {
    const res = await fetchWithTimeout(`${API}/screen/not-a-valid-address`)
    const ok = res.status === 400
    return { ok, detail: `status=${res.status} (expected 400, never 402 or 500)` }
  }
)

// ---------------------------------------------------------------------
// 5. Key registry is internally consistent.
// ---------------------------------------------------------------------
await check(
  'key-registry-consistent',
  'The published attestation key registry is well-formed and internally consistent',
  async () => {
    const res = await fetchWithTimeout(`${API}/.well-known/attestation-keys`)
    if (!res.ok) return { ok: false, detail: `registry fetch failed: status=${res.status}` }
    const registry = await res.json()
    const keys = registry?.keys
    if (!Array.isArray(keys) || keys.length === 0) {
      return { ok: false, detail: 'registry has no keys array or it is empty' }
    }
    const activeKeys = keys.filter((k: any) => k.status === 'active')
    if (activeKeys.length !== 1) {
      return { ok: false, detail: `expected exactly 1 active key, found ${activeKeys.length}` }
    }
    for (const k of keys) {
      if (!k.key_id || !k.public_key_pem || !k.status) {
        return { ok: false, detail: `a key record is missing key_id/public_key_pem/status: ${JSON.stringify(k).slice(0, 120)}` }
      }
      if (k.status === 'retired' && !k.valid_until) {
        return { ok: false, detail: `retired key ${k.key_id} has no valid_until boundary` }
      }
    }
    return { ok: true, detail: `${keys.length} key(s), ${activeKeys.length} active, all well-formed` }
  }
)

// ---------------------------------------------------------------------
// 6. Unauthenticated app API rejects.
// ---------------------------------------------------------------------
await check(
  'app-api-unauthenticated-rejects',
  'The app\'s data-plane API rejects an unauthenticated request',
  async () => {
    const res = await fetchWithTimeout(`${APP}/api/cases`)
    const ok = res.status === 401
    return { ok, detail: `status=${res.status} (expected 401)` }
  }
)

// ---------------------------------------------------------------------
// 7. Public MCP discovery exposes the expected core capabilities.
// ---------------------------------------------------------------------
await check(
  'mcp-discovery-core-capabilities',
  'The MCP server\'s public x402 discovery manifest still advertises the core paid checks',
  async () => {
    const res = await fetchWithTimeout(`${MCP}/.well-known/x402`)
    if (!res.ok) return { ok: false, detail: `discovery fetch failed: status=${res.status}` }
    const manifest = await res.json()
    const paths: string[] = (manifest.resources || []).map((r: any) => {
      try {
        return new URL(r.url).pathname
      } catch {
        return r.url
      }
    })
    const expectedCore = ['/x402/screen/:address', '/x402/verdict/:address', '/x402/diligence']
    const missing = expectedCore.filter((p) => !paths.includes(p))
    return {
      ok: missing.length === 0,
      detail: missing.length === 0
        ? `all ${expectedCore.length} core capabilities present (${paths.length} total resources advertised)`
        : `missing core capabilities: ${missing.join(', ')}`,
    }
  }
)

// ---------------------------------------------------------------------
// Report.
// ---------------------------------------------------------------------
const allOk = results.every((r) => r.ok)
const report = {
  schema: 'onchaindiligence.production-trust-canary.v1',
  checked_at: new Date().toISOString(),
  ok: allOk,
  results,
}

process.stdout.write(JSON.stringify(report, null, 2) + '\n')

for (const r of results) {
  process.stderr.write(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id.padEnd(32)} ${r.ms}ms  ${r.detail}\n`)
}
process.stderr.write(allOk ? '\nAll invariants held.\n' : '\nAt least one invariant FAILED -- see above.\n')

process.exit(allOk ? 0 : 1)
