import { createHash, timingSafeEqual } from 'node:crypto'

export type InternalAuthResult = 'authorized' | 'unauthorized' | 'unconfigured'

/** Authenticate an internal service without leaking token length or content. */
export function authorizeInternalBearer(
  authorization: string | undefined,
  configuredToken: string
): InternalAuthResult {
  if (!configuredToken) return 'unconfigured'
  if (!authorization?.startsWith('Bearer ')) return 'unauthorized'

  const suppliedToken = authorization.slice('Bearer '.length)
  const suppliedDigest = createHash('sha256').update(suppliedToken).digest()
  const configuredDigest = createHash('sha256').update(configuredToken).digest()

  return timingSafeEqual(suppliedDigest, configuredDigest)
    ? 'authorized'
    : 'unauthorized'
}
