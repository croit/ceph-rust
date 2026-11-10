<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0551 Linear RDMA placement progress over retained sources

Status: accepted
Date: 2026-10-24

## Context

KNet removes and reinserts every pending placed-read owner on each progress
pass, shifting the remaining vector twice. SQ refusal creates another queue
for sources already owned by a Vec. Long fragmented READs repeatedly inspect
WRITE completions that already reached their terminal successful state.

## Decision

- Progress borrows pending owners in place; only terminal owners leave the list.
- One reusable source-slot vector owns pending and posted pieces. SQ refusal
  restores the same slot without allocating a second queue or source vector.
- Per-connection retired-owner caches retain source slots and completion
  markers at their observed high-water mark. The next preflight reuses them;
  only new concurrency/fragmentation high-water marks allocate metadata.
  Payload owners are released only after every accepted WRITE CQE succeeds.
- PlacedReadWrite caches the contiguous successfully retired prefix. Successful
  WRITE markers are immutable while their handles are retained; later polls
  inspect only the remaining suffix, including failures after a pending entry.
- A failed terminal receipt encoding faults the attempt instead of retrying an
  immutable malformed sidecar on every progress pass.
- The client verification worker drains the available bounded job batch and
  wakes its owner once per batch, preserving the reserved-answer capacity and
  unpark-permit handshake.
- Preserve shared payload owners, same-QP order, cancellation and quarantine.

## Rationale

Avoid metadata movement and redundant completion loads without copying payloads,
adding a pool, changing the wire format or reordering parallel attempts.

## Consequences

- + No separate source/pending vector or per-piece marker allocation after warm-up.
- + Pending-owner traversal does not shift the vector on every visit.
- + A completed WRITE prefix is checked once across progress calls.
- - Terminal removal still preserves admission order by shifting the suffix once.
- - Metadata high-water capacity remains until connection close; receipt/control framing still allocates. Explicit off-progress prewarming and bounded capacity admission remain future work.

## Alternatives

- Unordered swap-remove: changes the existing admission ordering.
- Rebuild a pending VecDeque: duplicates already available source bookkeeping.
