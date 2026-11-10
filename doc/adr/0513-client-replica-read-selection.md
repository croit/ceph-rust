<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0513 Replica reads retain a request-stable selection proof

Status: accepted
Date: 2026-10-22

## Context

Both client pins expose BALANCE_READS and LOCALIZE_READS on replicated reads,
plus a runtime replica policy and a CRUSH location (read-target-policy.md).
Native sessions currently cache only the acting primary. Selecting randomly
again during connection wait or send validation can choose a different peer and
prevent progress. EC direct/split reads have separate shard/aggregation contracts.

## Decision

- The shared coordinator passes the logical request identity with routing flags.
  Replica selection remains stable for that request and installed map.
- Placement memoization retains the acting set and canonical primary once per
  PG/map generation. The ordinary primary path keeps its existing fast lookup.
- BALANCE selects an acting rank from an owner-seeded hash of request identity
  and PG; LOCALIZE uses cached CRUSH ancestor distances and acting-rank tie order.
- Send validation checks the selected current acting member rather than sampling
  a new destination. Interval/map validation retains existing resend ordering.
- Captured global read-policy flags are distinct from per-call flags and the
  exec-specific replica mask. Write and read/write operations retain primary
  routing. Caller RWORDERED and the captured exec mask suppress replica reads.
- A validated EAGAIN fallback clears replica flags and allocates a fresh wire
  TID while retaining logical ownership, inputs and the original deadline.
- Configuration publishes read-policy bits atomically; cold location changes
  invalidate locality caches. No configuration mutex is added to native routing.
- Kernel TCP/io_uring/RDMA and C/C++, sync/async share selection and fallback.

## Rationale

Request identity provides a stable selection key without a per-operation RNG
allocation or changing the public ABI. Placement and ancestor caches avoid CRUSH
work at each send. Separating configured policy from explicit flags preserves
caller masks and makes switching policy back to default effective.

## Consequences

- Replica draws differ from the reference process-global rand sequence while
  retaining access to every acting rank; no sequence is an application contract.
- Switching policy back to default clears the native policy, fixing the verified
  sticky-policy reference defect (ADR0256; both-pin sources in the read spec).
- Native route drivers accept the selection context; existing strict drivers
  retain conservative default behavior until they implement the optional method.
- Direct shard/split result assembly is specified and implemented in subsequent
  G07 increments, not declared covered by replicated routing.

## Alternatives

- Draw on every route call: connection wait and send validation can disagree.
- Hash only the object: repeated reads of one hot object never balance.
- Recompute CRUSH ancestry on every read: unnecessary hot-path work.
- Capture policy in the same field as caller flags: loses mask provenance.

## Open questions

Location defaults and parsing are specified in crush-read-locality.md. Startup
location hooks remain in the G08 configuration audit. EC direct/split assembly
remains G07b/G07c, specified separately in split-read-contract.md.

## Primary-owned control effects

Typed watch/notify controls operate on authoritative primary-owned notification
state; they are not object-data replica reads. Preserve their READ/WRITE wire
classification and snapshot metadata, while excluding object-data replica
policy. Both pins incorrectly apply the global read policy to NOTIFY_ACK:
acting replicas can acknowledge a no-op because their object contexts have no
loaded primary watchers (notify-ack-read-policy.md). Native ACKs target the
current primary so the accepted notification can finish. This is a documented
ADR0256 correctness improvement, not a pressure/timeout fallback or a new option.
