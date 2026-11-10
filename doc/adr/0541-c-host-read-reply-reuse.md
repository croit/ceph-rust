<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0541 C host READ control replies reuse owned caller storage

Status: accepted
Date: 2026-10-25

## Context

Submit/cancel/release post ordered worker actions borrowing C metadata arrays.
Each action allocated an Arc/OnceLock completion latch. Returning to the caller
requires proof that every worker access to those arrays has ended; notification
can still be executing when the caller observes completion.

## Decision

- Each calling thread caches at most one idle owned reply cell. A nested
  outstanding operation obtains independent storage; pending cells never recycle.
- A cell contains one atomic result and its caller's owned Thread handle.
  Completion guards cannot move to another thread. Idle storage drops at exit.
- Before enqueueing an action, the caller resets its exclusive cell to pending.
  Worker publication releases the last array access; caller acquisition ends
  the wait. Signed i32 success/error results have distinct nonpending encodings.
- Explicit send consumes the publisher; Drop publishes a disconnected error
  only when no explicit send occurred. Publication is the last state write.
- After publication the publisher may only notify the caller, retaining its Arc
  through that notification. A late wake cannot modify a recycled result and
  carries no borrowed pointer. Waiters recheck after every park return.
- C ordering, bounded queues, partial-admission recovery, CPU grants and shutdown
  remain unchanged. No payload ownership or progress execution moves to TLS.

## Rationale

Owned storage separates result readiness from notification lifetime. A single
release/acquire result atomically hands back the borrowed arrays. Resetting the
cell requires no uniqueness of Arc references: old publishers have already
performed their last state write. Thread-local reuse removes per-call allocation
without a global pool lock, polling loop, load threshold or stack-lifetime hazard.

## Consequences

- + Warm sequential control calls allocate no reply storage.
- + Dropped queued actions still release blocked callers and preserve admitted IDs.
- + Poll/capacity retain their direct preallocated metadata path.
- - First use and additional nested outstanding calls allocate owned storage.
- - Control calls retain queue handoff, reference counting and worker wake costs.
- - Idle storage and its Thread handle remain until caller exit; arbitrary
  persistent-caller/platform library unload is not newly qualified.
- - Connected fault/resource and production throughput evidence remain required.

## Alternatives

- Stack latch: a publisher wake can outlive the borrowed stack allocation.
- Reset OnceLock only after Arc uniqueness: result readiness need not coincide
  with publisher Arc destruction; this cannot guarantee allocation-free reuse.
- Global latch pool: adds shared synchronization to every control call.
- Remove the ordered worker action: changes admission/control/ownership semantics.

## Open questions

None; implementation gates and remaining qualification live in the RDMA GAPs.
