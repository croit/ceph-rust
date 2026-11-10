<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0540 C host READ results use preallocated atomic publication

Status: accepted
Date: 2026-10-25

## Context

Every nonempty C host READ poll allocated an owning completion latch, posted a
control action and waited for the existing worker. The worker already retained
terminal CPU grants and immutable result metadata until explicit release.

## Decision

- The worker publishes host READ metadata into a cold-allocated atomic slot
  table, retained by the worker's admission ledger, registered READ owner and
  successfully finalized cluster handle.
- C poll/capacity read that table directly after existing argument validation.
  Submit/cancel/release remain ordered worker actions.
- Publication follows logical completion, provider retirement and CPU grant
  acquisition. Release invalidates publication before returning the grant.
  Close and owner destruction close publication before destroying held views.
- A pending snapshot remains valid if the same admission completes during its
  final check: returning pending is conservative and grants no address. Final
  state must remain active; terminal snapshots require their exact state/flags.
  Invalidation, generation changes and shutdown remain errors.
- Each reusable field uses release/acquire atomics. Readers validate state
  followed by generation after reading fields; generation never wraps.
  No plain-data seqlock, payload copy, reader spin or per-query allocation.
- Successful connect publishes the cluster's immutable table reference only
  after optional service registration succeeds. Failed starts leave it empty;
  successfully connected handles cannot reconnect. Healthy poll/capacity borrow
  this reference without endpoint lookup, reference-count updates or mutexes.
- Worker destruction closes publication before stopping its I/O owner. Closed
  and unsupported queries preserve the existing endpoint/error path.
- The I/O thread returns its registration owner as its join result. Local fatal
  exit closes publication/provider access but retains already delivered CPU
  grants until explicit quiesced shutdown consumes/drops that result.
- The worker stores result metadata only in the published table. Its retained
  `Held` state decides pending versus terminal for cancellation/release.
  Control operations still use the worker; no GPU visibility claim follows.

## Rationale

The C caller needs stable result metadata, not another progress command. Keeping
payload ownership in the existing worker preserves grant lifetime. Observing
any field from a newer admission imports its preceding generation store; the
final generation check rejects mixed results on weak memory. The terminal
state release publishes all same-generation fields and preceding payload work.

## Consequences

- + Polling introduces no worker wake or completion-latch allocation.
- + Existing C layouts and retained-owner release contracts are unchanged.
- - Each configured request slot adds a fixed cold metadata allocation charge.
- - First-use/nested control replies and accepted native identity metadata
  still allocate; warm reply reuse is a separate decision.
- - Concurrency stress is not an exhaustive weak-memory model or a substitute
  for connected C ownership/fault and platform qualification.

## Alternatives

- Borrowed stack completion latch: publisher notification may outlive the caller.
- Plain-data seqlock: concurrent non-atomic field access is a Rust data race.
- Cached numeric payload address without owner: cannot establish allocation life.

## Open questions

None; remaining qualification is tracked in the RDMA GAP documents.
