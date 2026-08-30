import { createHash } from 'node:crypto'
import { CanonicalizationError, ParseError } from './errors.js'
import type { JsonValue } from './types.js'

const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/

function assertUnicodeScalarValue(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new CanonicalizationError('canonical JSON cannot contain an unpaired surrogate')
      }
      index += 1
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new CanonicalizationError('canonical JSON cannot contain an unpaired surrogate')
    }
  }
}

function canonical(value: unknown, seen: Set<object>): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'string') {
    assertUnicodeScalarValue(value)
    return JSON.stringify(value)
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new CanonicalizationError('canonical JSON cannot contain non-finite numbers')
    if (Number.isInteger(value) && !Number.isSafeInteger(value) && !JSON.stringify(value).includes('e')) {
      throw new CanonicalizationError('canonical JSON integer exceeds the interoperable safe-integer range')
    }
    return JSON.stringify(value)
  }
  if (typeof value !== 'object') {
    throw new CanonicalizationError(`value of type ${typeof value} is not valid JSON`)
  }
  if (seen.has(value)) throw new CanonicalizationError('canonical JSON cannot contain cycles')
  seen.add(value)
  try {
    if (Array.isArray(value)) return `[${value.map((item) => canonical(item, seen)).join(',')}]`
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) {
      throw new CanonicalizationError('canonical JSON objects must have a plain object prototype')
    }
    const record = value as Record<string, unknown>
    const entries = Object.keys(record)
      .sort()
      .map((key) => {
        assertUnicodeScalarValue(key)
        return `${JSON.stringify(key)}:${canonical(record[key], seen)}`
      })
    return `{${entries.join(',')}}`
  } finally {
    seen.delete(value)
  }
}

export function canonicalize(value: unknown): Uint8Array {
  return Buffer.from(canonical(value, new Set()), 'utf8')
}

export function canonicalizeText(value: unknown): string {
  return Buffer.from(canonicalize(value)).toString('utf8')
}

export function contentId(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalize(value)).digest('base64url')}`
}

export function formatTimestamp(value: Date): string {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) throw new TypeError('timestamp must be a valid Date')
  return value.toISOString()
}

export function parseTimestamp(value: string): Date {
  if (!TIMESTAMP.test(value)) throw new ParseError('timestamp must use exact YYYY-MM-DDTHH:mm:ss.sssZ syntax')
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new ParseError(`invalid UTC timestamp: ${value}`)
  }
  return parsed
}

export function cloneJson<T extends JsonValue>(value: T): T {
  return parseJson(canonicalize(value)) as T
}

export function enforceLimits(
  value: unknown,
  limits: { maxDepth: number; maxStringLength: number; maxArrayLength: number },
): void {
  const visit = (item: unknown, depth: number): void => {
    if (depth > limits.maxDepth) throw new ParseError(`JSON exceeds maximum depth ${limits.maxDepth}`)
    if (typeof item === 'string') {
      if (item.length > limits.maxStringLength) {
        throw new ParseError(`JSON string exceeds maximum length ${limits.maxStringLength}`)
      }
      return
    }
    if (Array.isArray(item)) {
      if (item.length > limits.maxArrayLength) {
        throw new ParseError(`JSON array exceeds maximum length ${limits.maxArrayLength}`)
      }
      for (const child of item) visit(child, depth + 1)
      return
    }
    if (item !== null && typeof item === 'object') {
      const entries = Object.entries(item)
      if (entries.length > limits.maxArrayLength) {
        throw new ParseError(`JSON object exceeds maximum members ${limits.maxArrayLength}`)
      }
      for (const [key, child] of entries) {
        visit(key, depth + 1)
        visit(child, depth + 1)
      }
      return
    }
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) throw new ParseError('non-finite JSON number is forbidden')
      if (Number.isInteger(item) && !Number.isSafeInteger(item) && !JSON.stringify(item).includes('e')) {
        throw new ParseError('JSON integer exceeds the interoperable safe-integer range')
      }
    }
  }
  visit(value, 0)
}

export function parseJson(data: string | Uint8Array): JsonValue {
  const text = typeof data === 'string' ? data : new TextDecoder('utf-8', { fatal: true }).decode(data)
  scanStrictJson(text)
  try {
    return JSON.parse(text) as JsonValue
  } catch (error) {
    throw new ParseError(`invalid JSON: ${error instanceof Error ? error.message : String(error)}`, { cause: error })
  }
}

function scanStrictJson(text: string): void {
  let index = 0
  const whitespace = (): void => {
    while (text[index] === ' ' || text[index] === '\t' || text[index] === '\r' || text[index] === '\n') index += 1
  }
  const stringToken = (): string => {
    const start = index
    index += 1
    while (index < text.length) {
      const character = text[index]
      if (character === '\\') {
        index += 1
        const escaped = text[index]
        if (escaped === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(index + 1, index + 5))) throw new ParseError('invalid JSON unicode escape')
          index += 5
        } else if ('"\\/bfnrt'.includes(escaped ?? '')) index += 1
        else throw new ParseError('invalid JSON escape')
      } else if (character === '"') {
        index += 1
        const raw = text.slice(start, index)
        const parsed = JSON.parse(raw) as string
        assertUnicodeScalarValue(parsed)
        return parsed
      } else {
        if (character === undefined || character.charCodeAt(0) < 0x20) throw new ParseError('invalid JSON string')
        index += 1
      }
    }
    throw new ParseError('unterminated JSON string')
  }
  const value = (depth: number): void => {
    if (depth > 64) throw new ParseError('JSON exceeds maximum parser depth 64')
    whitespace()
    const character = text[index]
    if (character === '{') {
      index += 1
      whitespace()
      const keys = new Set<string>()
      if (text[index] === '}') { index += 1; return }
      while (true) {
        whitespace()
        if (text[index] !== '"') throw new ParseError('expected JSON object key')
        const key = stringToken()
        if (keys.has(key)) throw new ParseError(`duplicate JSON object key: ${key}`)
        keys.add(key)
        whitespace()
        if (text[index] !== ':') throw new ParseError('expected colon')
        index += 1
        value(depth + 1)
        whitespace()
        if (text[index] === '}') { index += 1; return }
        if (text[index] !== ',') throw new ParseError('expected comma')
        index += 1
      }
    }
    if (character === '[') {
      index += 1
      whitespace()
      if (text[index] === ']') { index += 1; return }
      while (true) {
        value(depth + 1)
        whitespace()
        if (text[index] === ']') { index += 1; return }
        if (text[index] !== ',') throw new ParseError('expected comma')
        index += 1
      }
    }
    if (character === '"') { stringToken(); return }
    const token = text.slice(index).match(/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/)?.[0]
    if (!token) throw new ParseError('invalid JSON value')
    if (/^-?(?:0|[1-9]\d*)$/.test(token) && !Number.isSafeInteger(Number(token))) {
      throw new ParseError('JSON integer exceeds the interoperable safe-integer range')
    }
    if (/^-?(?:0|[1-9]\d*)(?:\.\d+|[eE])/.test(token) && !Number.isFinite(Number(token))) {
      throw new ParseError('JSON number exceeds the finite IEEE-754 range')
    }
    index += token.length
  }
  value(0)
  whitespace()
  if (index !== text.length) throw new ParseError('unexpected trailing JSON data')
}
