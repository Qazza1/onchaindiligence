import {
  applyFrame,
  decodeFrame,
  openContract,
  validateFrame,
  type ContractState,
  type LockKind,
  type OfferFrame,
  type TclkFrame,
  type TclkStatus,
} from '@flop-labs/tclk'
import { contentId } from './canonical.js'
import { EvidenceValidationError } from './errors.js'
import { createRecord } from './records.js'
import { verifyTechnocoreMessage, type TechnocoreSignedMessage } from './technocore.js'
import type { AgentEvidenceRecord, JsonObject } from './types.js'

/**
 * Technocore Lock Protocol (`tclk/1`, by FLOP Labs — https://github.com/flop-labs/tclk)
 * adapter: turns a Technocore-carried tclk transcript into Agent Evidence.
 *
 * tclk is a coordination convention, not a settlement service: it proves which
 * `did:key` signed a deal-coordination frame (offer/accept/lock/reveal/refund/
 * cancel/receipt) and whether the transcript is valid under tclk's own
 * fail-closed state machine (`applyFrame`). It does NOT prove the counterparty
 * is trustworthy, that an asserted statement is objectively true, or that money
 * actually moved — a named settlement rail remains authoritative for that. This
 * module never implements a rail, never moves value, and deliberately does not
 * use tclk's unaudited PTLC/adaptor-signature path (see SPEC.md §7).
 *
 * Verification here is layered and independently distinguishable, per frame:
 *   1. transport   — `verifyTechnocoreMessage` (the existing Technocore adapter;
 *                     not reimplemented here)
 *   2. frame       — `decodeFrame`/`validateFrame` from the official `@flop-labs/tclk`
 *                     package (not reimplemented here)
 *   3. attribution — the frame's own `from` must equal the transport-verified DID
 *   4. state       — `openContract`/`applyFrame`, the official state machine
 */

/** One Technocore message believed to carry a tclk/1 frame as its text. */
export type TclkTranscriptMessage = TechnocoreSignedMessage

/**
 * One transcript entry: a message plus the wall-clock time (unix ms) at which
 * THAT frame was applied. tclk's deadline checks (`expiresMs`, `refundAfterMs`)
 * are transition guards evaluated at the moment of each transition (see
 * `applyFrame`'s `nowMs` parameter) — an `accept` many minutes after `offer` and
 * a `refund` days later are each checked against their own real time, not a
 * single "verification time" for the whole historical transcript. Reusing one
 * frozen instant for every step would make it impossible to correctly replay a
 * transcript that legitimately spans an offer's expiry window through to its
 * refund window.
 */
export interface TclkTranscriptEntry {
  message: TclkTranscriptMessage
  atMs: number
}

/** One step of a verified transcript: either an accepted transition or an official rejection. */
export interface TclkTranscriptStep {
  message: TclkTranscriptMessage
  frameType: TclkFrame['type']
  accepted: boolean
  /** Present when `accepted` is false — the official machine's own rejection reason. */
  reason?: string
}

/** The result of successfully replaying a tclk transcript through the official state machine. */
export interface TclkTranscriptResult {
  offer: OfferFrame
  /** Set once an `accept` frame is itself accepted. */
  contract: string | null
  status: TclkStatus
  terminal: boolean
  outcome: 'claimed' | 'refunded' | 'cancelled' | null
  payerDid: string | null
  payeeDid: string | null
  amount: string
  asset: string
  lock: LockKind
  offeredRails: readonly string[]
  /** Set once a `lock` frame is accepted — the rail the payer announced, not independently verified. */
  rail: string | null
  railRef: string | null
  claimByMs: number
  refundAfterMs: number
  expiresMs: number
  /** Every message processed, in order, whether accepted or officially rejected. */
  steps: readonly TclkTranscriptStep[]
}

const TERMINAL_STATUSES: ReadonlySet<TclkStatus> = new Set(['claimed', 'refunded', 'cancelled']);

/**
 * Verifies a Technocore-carried tclk/1 transcript end to end and replays it
 * through the official `@flop-labs/tclk` state machine.
 *
 * Fails closed (throws `EvidenceValidationError`) when:
 *  - a message's Technocore transport signature does not verify
 *  - a message's text does not decode/validate as a tclk/1 frame
 *  - a frame's own `from` does not match its message's transport-verified DID
 *  - the transcript does not open with a valid `offer` frame, or a second
 *    `offer` appears mid-transcript (which contract would the rest belong to?)
 *
 * A frame that decodes and is honestly attributed but that the OFFICIAL state
 * machine itself rejects (wrong sender for the transition, a replay, a
 * duplicate, an out-of-order transition, a tampered `contract`/`ref` id that
 * fails the machine's own recomputation) is NOT a fail-closed error here: per
 * tclk's own spec (SPEC.md §2, §4), those are designed-in no-op rejections a
 * reader in a world-writable room must expect, not evidence the transcript
 * itself is corrupt. Every such rejection is still recorded in `steps` with its
 * reason — it is never silently discarded — and does not advance contract state.
 *
 * Each entry supplies its own `atMs` (see `TclkTranscriptEntry`); deadline
 * guards are evaluated per-transition against that entry's own time, not a
 * single instant for the whole replay.
 */
export function verifyTclkTranscript(
  entries: readonly TclkTranscriptEntry[],
): TclkTranscriptResult {
  if (entries.length === 0) {
    throw new EvidenceValidationError('tclk transcript: no messages supplied')
  }

  const steps: TclkTranscriptStep[] = []
  let offer: OfferFrame | null = null
  let state: ContractState | null = null

  for (const { message, atMs } of entries) {
    if (!verifyTechnocoreMessage(message)) {
      throw new EvidenceValidationError(
        `tclk transcript: message (room ${message.room}, nonce ${message.nonce}) has an invalid Technocore transport signature`,
      )
    }

    let frame: TclkFrame
    try {
      frame = decodeFrame(message.text)
    } catch (error) {
      throw new EvidenceValidationError(
        `tclk transcript: message (room ${message.room}, nonce ${message.nonce}) is not a valid tclk/1 frame: ${
          error instanceof Error ? error.message : String(error)
        }`,
      )
    }

    if (frame.from !== message.did) {
      throw new EvidenceValidationError(
        `tclk transcript: frame sender ${frame.from} does not match the transport-authenticated DID ${message.did}`,
      )
    }

    if (frame.type === 'offer') {
      if (offer !== null) {
        throw new EvidenceValidationError(
          'tclk transcript: a second offer frame cannot open a new contract mid-transcript',
        )
      }
      try {
        offer = validateFrame(frame) as OfferFrame
        state = openContract(offer)
      } catch (error) {
        throw new EvidenceValidationError(
          `tclk transcript: invalid opening offer: ${error instanceof Error ? error.message : String(error)}`,
        )
      }
      steps.push({ message, frameType: frame.type, accepted: true })
      continue
    }

    if (state === null) {
      throw new EvidenceValidationError(
        'tclk transcript: no opening offer frame appears before a subsequent frame',
      )
    }

    const result = applyFrame(state, frame, atMs)
    if (!result.ok) {
      // Official, designed-in rejection (replay, duplicate, wrong sender for
      // this transition, tampered id, out-of-order transition, …) — recorded,
      // never dropped, never treated as fatal to the whole transcript.
      steps.push({ message, frameType: frame.type, accepted: false, reason: result.reason ?? 'rejected' })
      continue
    }
    state = result.state
    steps.push({ message, frameType: frame.type, accepted: true })
  }

  if (offer === null || state === null) {
    throw new EvidenceValidationError('tclk transcript: transcript never opened a contract')
  }

  const outcome: TclkTranscriptResult['outcome'] = TERMINAL_STATUSES.has(state.status)
    ? (state.status as 'claimed' | 'refunded' | 'cancelled')
    : null

  return {
    offer,
    contract: state.contract ?? null,
    status: state.status,
    terminal: TERMINAL_STATUSES.has(state.status),
    outcome,
    payerDid: state.payerDid ?? null,
    payeeDid: state.payeeDid ?? null,
    amount: offer.amount,
    asset: offer.asset,
    lock: offer.lock,
    offeredRails: offer.rails,
    rail: state.rail ?? null,
    railRef: state.railRef ?? null,
    claimByMs: offer.claimByMs,
    refundAfterMs: offer.refundAfterMs,
    expiresMs: offer.expiresMs,
    steps,
  }
}

/**
 * An OPTIONAL, independently-verified observation from a real settlement rail —
 * NOT implemented, simulated, or connected to by this module. tclk coordination
 * evidence plus a caller-supplied `SettlementRailObservation` is what would let a
 * decision claim actual value movement; without one, a decision built on tclk
 * evidence alone must describe the lock as asserted/announced, never as settled.
 */
export interface SettlementRailObservation {
  rail: string
  ref: string
  observedAt: string
  /** Free-form, source-specific detail the caller already independently verified. */
  detail: JsonObject
}

export interface TclkEvidenceOptions {
  runRef: string
  observedAt: string
  /**
   * Parent evidence ids for the underlying signed Technocore messages — recommended:
   * one `createTechnocoreEvidence(...)` call per transcript step, so the raw signed
   * room messages remain independently inspectable evidence in their own right.
   */
  messageEvidenceRefs: readonly string[]
  expiresAt?: string | null
  toolVersion?: string
  /** See `SettlementRailObservation`. Never fabricated by this module. */
  settlementRail?: SettlementRailObservation
}

/**
 * Converts a verified tclk transcript into schema-valid Agent Evidence. The
 * transcript must already have passed `verifyTclkTranscript` — this function
 * does not re-verify signatures or replay frames, only records what was found.
 *
 * A `lock` frame is reported as "payer asserted/announced lock on rail X",
 * never as "funds were locked" — this module has no independent way to observe
 * a settlement rail. If the caller supplies a verified `settlementRail`
 * observation, that is captured alongside the coordination evidence and
 * labeled as independently observed, but it is still the caller's evidence,
 * not something this adapter establishes.
 */
export function createTclkEvidence(
  transcript: TclkTranscriptResult,
  options: TclkEvidenceOptions,
): AgentEvidenceRecord {
  const lockNote = transcript.rail === null
    ? 'no lock frame observed in this transcript'
    : `payer asserted/announced lock on rail "${transcript.rail}"` +
      (transcript.railRef !== null ? ` (rail ref: ${transcript.railRef})` : '') +
      '; this is the payer\'s claim, not independent proof that funds were escrowed'

  const captured: JsonObject = {
    protocol: 'tclk/1',
    offer_id: transcript.offer.id,
    contract_id: transcript.contract,
    payer_did: transcript.payerDid,
    payee_did: transcript.payeeDid,
    amount: transcript.amount,
    asset: transcript.asset,
    lock_kind: transcript.lock,
    offered_rails: [...transcript.offeredRails],
    asserted_settlement_rail: transcript.rail,
    asserted_settlement_rail_ref: transcript.railRef,
    settlement_note: lockNote,
    claim_by_ms: transcript.claimByMs,
    refund_after_ms: transcript.refundAfterMs,
    expires_ms: transcript.expiresMs,
    transcript_status: transcript.status,
    terminal: transcript.terminal,
    outcome: transcript.outcome,
    frame_sequence: transcript.steps.map((step) => ({
      type: step.frameType,
      from: step.message.did,
      room: step.message.room,
      nonce: step.message.nonce,
      accepted: step.accepted,
      reason: step.reason ?? null,
    })),
    ...(options.settlementRail !== undefined
      ? {
        independent_settlement_observation: {
          rail: options.settlementRail.rail,
          ref: options.settlementRail.ref,
          observed_at: options.settlementRail.observedAt,
          detail: options.settlementRail.detail,
        },
      }
      : {}),
    verification: 'technocore-transport-and-tclk-state-machine-verified',
  }

  const request: JsonObject = { offer_id: transcript.offer.id, contract_id: transcript.contract }
  return createRecord('evidence', {
    evidence_type: 'tclk-transcript',
    run_ref: options.runRef,
    trust_mode: 'agent-assertion',
    source: { id: 'https://github.com/flop-labs/tclk', type: 'tclk-technocore-lock-protocol' },
    tool: { name: 'onchaindiligence-tclk-adapter', version: options.toolVersion ?? '1' },
    request: {
      digest: { sha256: contentId(request).slice('sha256:'.length) },
      media_type: 'application/vnd.tclk.transcript-request+json',
    },
    response: {
      mode: 'embedded',
      media_type: 'application/vnd.tclk.transcript+json',
      value: captured,
      digest: { sha256: contentId(captured).slice('sha256:'.length) },
    },
    observed_at: options.observedAt,
    expires_at: options.expiresAt ?? null,
    scope: {
      offer_id: transcript.offer.id,
      contract_id: transcript.contract,
      payer_did: transcript.payerDid,
      payee_did: transcript.payeeDid,
    },
  }, { parents: [options.runRef, ...options.messageEvidenceRefs] })
}
