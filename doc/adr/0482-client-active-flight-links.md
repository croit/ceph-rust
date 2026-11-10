<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0482 Constant-time ordered flight unlinking

Status: accepted
Date: 2026-10-21

## Context

Review m1 identifies quadratic FIFO release bookkeeping. The targeted debug
measurement confirms superlinear drain time at depths256/1024; measurements
are in doc/perf/rustyrados-completion-drain-2026-10-21.md.

## Decision

Live flight slots form an ordered doubly linked index in preallocated storage.
Admission appends; release unlinks only adjacent indices.
The dispatch cursor names the next exact live slot and wraps to the head.
Older-resend barriers traverse earlier live slots in submission order.

## Rationale

Constant-time unlinking removes suffix updates without changing operation order
or allocating per completion. A stable slot identity survives unrelated removal.

## Consequences

- + FIFO release bookkeeping scales linearly over a full drain.
- + Callback cancellation and slot reuse keep existing cursor semantics.
- - Two neighbor indices per reserved slot replace the compact active vector.

## Alternatives

- Swap removal disrupts ordered iteration and cursor fairness.
