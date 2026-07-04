/**
 * sandbox.ts — test-mode screening with documented, deterministic vectors.
 *
 * WHY THIS EXISTS
 * Integrators need to build and CI-test the full screen → result → verify flow,
 * INCLUDING a positive sanctions hit, without paying real money or touching the
 * live oracle. Almost no compliance API offers this; it's the biggest source of
 * integration friction.
 *
 * SAFETY (non-negotiable — this is a compliance product)
 * A sandbox result must NEVER be mistakable for a real determination:
 *   1. Sandbox lives on its own path (/sandbox/*), so you always know you're in it.
 *   2. Only documented fake test-vector addresses work. A REAL address in sandbox
 *      is refused — so nobody accidentally screens a real counterparty against
 *      fake data and trusts the answer.
 *   3. Every sandbox response is loudly flagged `sandbox: true` with a warning,
 *      and is NEVER signed with the production attestation key — the `attestation`
 *      block explicitly says this is test data, not verifiable evidence.
 *   4. No payment is taken and no upstream is called.
 */

/** Documented sandbox test vectors. These are NOT real addresses. */
export const SANDBOX_VECTORS: Record<string, { sanctioned: boolean; label: string }> = {
  // Deterministic "sanctioned" — use this to test your block/deny path.
  '0x00000000000000000000000000000000000000ba': {
    sanctioned: true,
    label: 'Test vector: always returns SANCTIONED. Use to exercise your positive-hit path.',
  },
  // Deterministic "clean" — use this to test your allow path.
  '0x00000000000000000000000000000000c1ea0000': {
    sanctioned: false,
    label: 'Test vector: always returns CLEAN. Use to exercise your allow path.',
  },
  // Deterministic "clean" alt (a second clean vector for list/batch tests).
  '0x0000000000000000000000000000000000000001': {
    sanctioned: false,
    label: 'Test vector: always returns CLEAN.',
  },
}

/** Normalize for lookup: lowercase, no surrounding whitespace. */
function norm(addr: string): string {
  return addr.trim().toLowerCase()
}

export function isSandboxVector(address: string): boolean {
  return norm(address) in SANDBOX_VECTORS
}

export interface SandboxError {
  error: string
  detail: string
  test_vectors: Array<{ address: string; returns: string; label: string }>
}

/** The list of vectors, shaped for a helpful error/discovery response. */
export function listVectors(): SandboxError['test_vectors'] {
  return Object.entries(SANDBOX_VECTORS).map(([address, v]) => ({
    address,
    returns: v.sanctioned ? 'sanctioned' : 'clean',
    label: v.label,
  }))
}

/**
 * Build a sandbox screening response for a known test vector.
 * The shape mirrors a real /screen response so integrators can code against the
 * same structure — but it is explicitly, loudly flagged as test data and is
 * NOT signed with the production key.
 */
export function sandboxScreen(address: string): Record<string, unknown> {
  const vector = SANDBOX_VECTORS[norm(address)]
  // Callers must gate with isSandboxVector() first; this is a defensive guard.
  if (!vector) {
    throw new Error('sandboxScreen called with a non-vector address')
  }

  return {
    data: {
      address,
      sanctioned: vector.sanctioned,
      identifications: vector.sanctioned
        ? [
            {
              category: 'sanctioned',
              name: 'SANDBOX test hit — not a real designation',
              description:
                'This is a deterministic sandbox test vector, not a real screening result. ' +
                'It exists so you can exercise your positive-hit handling in development and CI.',
              url: 'https://onchaindiligence.com/docs#sandbox',
            },
          ]
        : [],
      source: 'sandbox',
      checked_at: new Date().toISOString(),
    },
    // A real response carries a signed Ed25519 attestation. Sandbox NEVER does —
    // it carries this explicit non-attestation so the result can't be mistaken
    // for verifiable evidence.
    attestation: {
      signed: false,
      sandbox: true,
      note:
        'SANDBOX RESULT — test data only. This response is intentionally UNSIGNED and ' +
        'must not be treated as a real compliance determination or verifiable evidence. ' +
        'Use the production endpoints for real screening.',
    },
    sandbox: true,
  }
}
