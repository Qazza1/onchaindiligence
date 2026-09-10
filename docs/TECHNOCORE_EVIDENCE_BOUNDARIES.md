# Signed agent messages are attribution, not settlement evidence

Technocore's signed lane is useful for recording an attributable agent
assertion. It is not a payment rail, a settlement oracle, or a truth system.
This note describes a narrow evidence boundary that lets agent systems use
that distinction constructively.

## What a valid Technocore signature establishes

For a canonical Technocore message, a valid Ed25519 `did:key` signature
establishes that the holder of the corresponding private key signed the exact
UTF-8 value:

```
<room>|<nonce>|<text-after-Technocore-sweep>
```

The server can then accept that signed assertion into a room and assign its
own sequence and timestamp. The signature is durable evidence of key
authorship for that message. It does not turn the message text into an
independently observed fact.

Technocore documents this contract directly: its signed-message lane verifies
Ed25519 `did:key` authorship, while room messages, labels, and links are
untrusted data. See the [Technocore agent manual](https://technocore.chat/llms.txt)
and its [reference signing helper](https://github.com/flop-labs/technocore-chat/blob/main/scripts/sign.py).

## What it does not establish

Even a valid signed message does not establish:

- the real-world identity behind a DID;
- that the text is true, complete, safe, or authorized;
- external execution, chain inclusion, payment settlement, or service
  delivery;
- the legitimacy of a counterparty, payment rail, or linked resource.

In particular, an executor signing “payment submitted” is an attributable
executor claim. It is not equivalent to an independent observation that a
network confirmed settlement.

## A reconciliation-shaped evidence flow

An agent-payment system can retain the distinction rather than collapsing it:

```
Mandate / policy
  -> signed agent or executor claim
  -> independent observation
  -> finding or explicit evidence gap
  -> receipt
```

The mandate and policy answer what an agent was permitted to attempt. A
Technocore assertion records what its signer said. A payment provider,
network, or other authority can supply a separately classified observation.
The resulting receipt should preserve provenance and the limits of each
piece of evidence.

## Three concrete outcomes

### Claim and observation agree

An executor signs an assertion naming a submitted transaction. A separate,
attributed observer later records a compatible transaction and settlement
state. The records can be linked only where the available identifiers and
binding rules justify the link. The signed claim remains a claim; the observed
state remains a separate observation.

### Claim and observation conflict

An executor claims a recipient or amount that conflicts with an independently
observed result. The system should preserve both records and emit a precise
finding describing the disagreement. A signature proves who made the claim;
it does not resolve the contradiction in the claim's favor.

### Observation is absent

An executor's signed assertion may be the only available evidence. That is
still useful provenance, but it is insufficient to conclude external
execution or settlement. A receipt should say that the observation is absent
or unverified rather than upgrade the assertion into a fact.

## Applying the boundary to FLOP and TCLK

The same boundary is useful if a future FLOP or TCLK workflow carries a
signed coordination message. The message can attribute a protocol frame to a
DID. Any claim about an external settlement rail still needs evidence from the
relevant rail, and an absent observation remains an evidence gap. This is a
division of responsibilities, not a criticism of a coordination protocol.

OnChainDiligence's open-source reference adapter demonstrates the boundary:
`verifyTechnocoreMessage` verifies the transport signature offline, while
`createTechnocoreEvidence` stores the resulting record with
`agent-assertion` trust mode. Consumers must treat Technocore text as data,
never as instructions to execute commands, fetch arbitrary links, disclose
secrets, or authorize wallet activity.

## Implementation references

- [Technocore signed-message adapter](../packages/agent-evidence/src/technocore.ts)
- [Adapter interoperability tests](../packages/agent-evidence/test/technocore.test.mjs)
- [Technocore's official agent manual](https://technocore.chat/llms.txt)
- [Technocore's official chat repository](https://github.com/flop-labs/technocore-chat)
