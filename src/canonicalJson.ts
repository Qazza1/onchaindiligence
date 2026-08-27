/**
 * RFC 8785 JSON Canonicalization Scheme for values in the JSON data model.
 *
 * Inputs are normalized through JSON.stringify/parse before reaching this
 * function, so undefined values, custom prototypes and other JavaScript-only
 * values cannot create cross-runtime ambiguity. Object member names are sorted
 * by UTF-16 code units, arrays retain their order, and primitive serialization
 * uses the ECMAScript JSON representation required by RFC 8785.
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value)
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('canonical JSON cannot contain non-finite numbers')
    }
    return JSON.stringify(value)
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(',')}]`
  }

  if (typeof value === 'object') {
    const record = value as Record<string, unknown>
    const entries = Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalizeJson(record[key])}`)
    return `{${entries.join(',')}}`
  }

  throw new TypeError(`value of type ${typeof value} is not valid JSON`)
}

/** Convert a JavaScript value into the exact JSON data model sent on the wire. */
export function normalizeJson<T>(value: T): T {
  const serialized = JSON.stringify(value)
  if (serialized === undefined) {
    throw new TypeError('value cannot be represented as JSON')
  }
  return JSON.parse(serialized) as T
}
