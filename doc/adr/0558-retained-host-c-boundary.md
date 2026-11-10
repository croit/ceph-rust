<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0558 Retained host registrations share the existing C client's native worker

Status: accepted
Date: 2026-10-25

## Context

The native runtime has retained foreign host allocation, shared parent MR/window
ownership and a borrowed registered READ owner. The compatible C adapter owns one
native Client in its existing worker and routes ordinary results there. It has
no registered-memory C surface. Native provider preparation is asynchronous;
registration currently returns the original owner when the provider is not ready.

## Decision

- Add an extension in the rustyrados namespace; existing librados ABI functions
  and parity counts keep their reference contracts and separate qualification.
- Use the existing worker/Client for retained-host control and READ batches.
  Keep runtime opt-in and the ordinary SEND defaults.
- Expose explicit provider preparation/readiness and asynchronous registration.
  A not-ready provider rejects admission while the caller retains its original
  storage; READ dispatch never hides registration or silently stages payload.
- Retain one initialized writable CPU allocation with one parent admission
  charge and one prepared window pool. Per-operation leases grant checked
  disjoint ranges and keep their exact parent/provider identity.
- Route provider lease events before logical completions through the borrowed
  owner. Ordinary completions stay with their existing worker consumers.
- Provide bounded opaque registration/request identities, batch submit and result
  polling, cancellation and release. Validate full context/generation identity;
  a released or foreign identity cannot designate another allocation.
- Admission errors preserve the caller's lifetime ownership. After acceptance,
  release the retained owner exactly once after proved final provider teardown;
  quarantine retains backing and its charge instead of invoking release.
- Keep metadata preparation and final provider destruction on control paths;
  batch operations move descriptors/owners without copying payload bytes.
- The registration implementation uses startup-only `rustyrados_rdma_host_bytes`
  (decimal bytes, default zero) and native count/byte admission. C identities carry
  worker context, slot and generation; exhausted generations are retired.
- Accepted allocation retirement runs its release callback on the existing
  callback executor. Provider retirement and admission may occur in either order;
  the second transition schedules exactly one callback. A completion notice keeps
  the address/slot unavailable until that callback returns. Quarantine retains
  the callback context with the allocation. Provider destruction stays off I/O.
- Publish cold registration results (including panic/disconnection) before waking
  progress. Thread exit is not a result-publication proof.
- Completed CPU range grants own the exact unbound destination, including its
  parent backing/charge. Foreign consumers use a derived pointer, not a saved
  original allocation alias. Ending the grant requires all CPU uses to stop
  before the destination returns to provider reuse. Parent/controller destruction
  does not revoke a live grant. Shutdown and cancellation preserve that interval.
- C batches borrow their metadata/output arrays for one synchronous existing
  mailbox call. Submit follows the data FIFO after older ordinary admissions;
  poll/cancel/release retain independent control progress. Native object identity metadata is owned through retries;
  no payload is staged. Bound batch size by the worker's captured native capacity.
- One owning result latch publishes each batch completion, including dropped
  work. Waiting on that value establishes output-array visibility on success and
  failure without a separate reply queue. Completion allocation and native
  identity ownership costs remain explicit performance qualification work.
- Request identities use a separate context nonce and preallocated generational
  slots. Completed results retain their exact child/window until explicit release.
  Route provider events before logical results; classify ordinary results by
  full native token identity before offering registered results to the owner.
- Foreign CPU use ends before C request release or cluster shutdown. Registration
  release and cancellation do not revoke result grants. Shutdown routes remaining
  provider events and defers result/owner destruction to the callback executor.
- Host contracts exclude device memory. Do not freeze a GPU import/visibility or
  integrity ABI before dedicated nonproduction registration/revocation evidence.

## Rationale

The existing worker already serializes native control and routes multiple
completion consumers. Explicit provider readiness avoids another waiting queue
of uncharged application allocations and keeps setup out of data progress.
Shared parent ownership avoids per-block MR registration and duplicated retained
byte charges. CPU-only handles avoid assuming GPU memory has host semantics.

## Consequences

- + One client/connection/progress owner serves ordinary and direct requests.
- + Accepted lifetime ownership is independent of logical cancellation.
- - Callers must prepare the selected provider before registering a pool.
- - Handle, callback, shutdown and batch routing require independent ABI/foreign
  consumer tests, resource/fault gates and measured metadata/CPU costs.

## Alternatives

- Another C-side client or I/O thread: duplicates sessions and changes ordering.
- Register on each READ: repeats provider setup on the data path.
- Queue allocation ownership before provider readiness without admission: retained
  resources would not have the native registration budget's bound.
- Interpret host pointers as GPU memory: violates the native CPU-view contract.

## Open questions

- Broaden registered C request/result fault, resource and metadata-cost gates;
  capability reporting and post-shutdown library finalization/unload remain
  unqualified. Host declarations live in include/rustyrados/rdma.h, checked
  as C11/C++17 with the independent ABI consumer. API behavior stays
  authoritative in function Rustdoc.
- Physical RDMA, full mixed ordinary/registered fault/cancel/retry/resource gates.
- Separate GPU registration/revocation, visibility/integrity and source-write work.
