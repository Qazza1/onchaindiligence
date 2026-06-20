/**
 * paymentLog.ts
 * -------------
 * Records every settled and failed payment via mppx's lifecycle hooks
 * (onPaymentSuccess / onPaymentFailed).
 *
 * WHY: In the Tempo charge model the agent has already paid on-chain by
 * the time we verify. If an upstream then fails, they paid for an error,
 * and we do NOT auto-refund at launch (see refund disclosure in README).
 * The least we owe — operationally and ethically — is a durable record of
 * what was paid, so that (a) we can investigate disputes, and (b) we have
 * the data to issue manual or automated refunds later if we choose to.
 *
 * This is intentionally a thin console logger right now. The shape is
 * structured (JSON) so it's trivial to later pipe into a real sink (a DB,
 * a log drain, Upstash, etc.) without changing the call sites. Swapping
 * the `sink` function is the only change needed.
 */

import type { Receipt } from 'mppx'

// The mppx package exports Receipt as a namespace; the receipt type itself
// is Receipt.Receipt.
type ReceiptType = Receipt.Receipt

export interface PaymentRecord {
  event: 'payment.success' | 'payment.failed'
  method?: string
  /** On-chain tx hash for Tempo (receipt.reference). Present on success. */
  reference?: string
  timestamp: string
  /** Human note, e.g. the failure reason. */
  detail?: string
}

// Swap this single function to send records somewhere durable later.
function sink(record: PaymentRecord) {
  // Structured one-line JSON. Written to STDERR, not stdout: the MCP stdio
  // transport uses stdout for the JSON-RPC protocol stream, so logging to
  // stdout there would corrupt it. stderr is safe in all our runtimes
  // (Vercel captures both streams; HTTP server is unaffected).
  process.stderr.write(JSON.stringify({ kind: 'payment', ...record }) + '\n')
}

export function logPaymentSuccess(receipt: ReceiptType) {
  sink({
    event: 'payment.success',
    method: receipt.method,
    reference: receipt.reference,
    timestamp: receipt.timestamp ?? new Date().toISOString(),
  })
}

export function logPaymentFailed(detail: string) {
  sink({
    event: 'payment.failed',
    timestamp: new Date().toISOString(),
    detail,
  })
}
