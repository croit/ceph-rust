<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0629 Reentrant RBD completion waits

Status: accepted
Date: 2026-10-30

## Context

Image completion callbacks use a serial, ordered strand. A callback that waits
for a later completion on the same image blocks the strand needed to run that
completion's callback.

## Decision

A same-image callback waiting for a later callback-bearing completion drains
the strand's queued prefix on its own thread until that completion runs.
The drain preserves callback start order and does not run callbacks in parallel.
An asynchronous close submitted from a nested callback excludes its active
same-image callback stack from its callback-prefix fence.

## Rationale

The executor cannot otherwise complete the awaited operation. Running the
prefix on the waiting thread retains ordered delivery and avoids a second
concurrent executor. Nested callbacks may be entered before the outer callback
returns, so close must not wait for that active stack.

## Consequences

- + A callback can synchronously wait for a later same-image completion.
- - Nested callback entry is observable; classic-provider behavior remains
  unqualified and needs a targeted oracle.
- - Cyclic waits, including waits on an active ancestor, are not resolvable.

## Alternatives

- Wait for the strand worker: deadlocks because the worker runs the waiter.
- Run the later callback on a second worker: breaks serial delivery.

## Amendment (2026-11-02): callbacks in completion order (am. 1)

- The image strand stays serial (one callback at a time per image) but runs
  callbacks in completion order, FIFO of finished operations, instead of
  submission order. A finished operation no longer waits for the callback
  of an earlier operation still in flight.
- A callback waiting for another same-image completion that has not run,
  earlier or later, runs queued callbacks on its own thread until that
  completion is done. A callback waiting for a callback-free close runs
  them until every callback accepted before the close, except its own
  stack, returned. Waits on an active ancestor stay unresolvable.
- The close callback-prefix fence (adr 0527) is unchanged: it uses the
  accepted-callback set, not queue order.
- The strand and its worker live from the image's first callback until
  the image handle is dropped; queued callbacks keep it until they ran.
  It no longer retires whenever no callback is reserved, which created a
  thread per operation at QD1.
- Callbacks of independent operations have no mutual order, also a flush
  and earlier writes: a flush completion reports that the earlier accepted
  writes are durable, not that their callbacks returned.

Rationale: submission-order delivery held every finished operation behind
the slowest earlier one (head-of-line blocking). At QD8/QD32 it cost 15-30 %
IOPS on 4k reads and writes against stock librbd, which delivers callbacks
as operations finish; completion order reached stock (doc/perf/rbd-qd-20261102.md).

## Amendment (2026-11-02): run image callbacks on the completing thread (am. 2)

Status: accepted 2026-11-02 (lead), implemented.

- Before this change one completion was dispatched twice: the provider's AIO
  callback domain thread pushed the task into the image strand, whose own
  worker ran the user callback. That second hop was one thread switch per
  completion and a second serialization point per image.
- The image now runs the callback inline on the thread that delivers the
  provider completion when the image has no callback running; otherwise it
  enqueues as today. An `active` counter (inline or worker) keeps one
  callback at a time per image; the worker waits while it is non-zero. The
  strand keeps serving foreign providers, refused inline deliveries, close
  callbacks submitted from a user thread, and reentrant waits.
- Reentrancy stays resolvable: a callback that waits for another completion
  of the same image, or for a callback-free close, drains the handle's AIO
  callback domain on its own thread through one private provider entry
  (`rustyrados_rt_callback_op`, version node `RUSTYRADOS_PRIVATE_1`: op 1
  reports that the caller runs a callback of its own domain, op 2 drains that
  domain and returns the number run), until the awaited completion ran. A
  queued callback found on the image is run nested first; the wait re-checks
  the queue under the strand lock before blocking, so a delivery that raced
  the unlock cannot be lost. Waiting for the strand worker deadlock remains
  unresolvable as before.
- The private symbol is the only addition to the packaged library: the export
  gate (`lab/rados-client/package-elf.sh`) whitelists exactly this name with
  a pointer to this amendment, the version node keeps it out of the librados
  ABI nodes, the C function inventory stays at 246 and
  `scripts/check-rados-stock-imports.sh` stays green (verified on the built
  package). A provider without the symbol (stock librados, any foreign
  loader) keeps strand delivery, so our librbd next to stock librados and
  stock librbd next to stock librados are unaffected; `stock-librbd-live.sh`
  (control on stock librados + stock librbd on our librados) passes on the
  packaged C++ build.
- The completion's done state is still published after the callback returns
  (`doc/spec/rustyrbd/ffi-async-completion.md`); the drain is therefore the
  only way a reentrant wait can resolve, and the observable contract is
  unchanged. The close callback-prefix fence (adr 0527) and the
  accepted-callback set stay as they are; a close submitted inside a
  callback still excludes its own stack.
- Tests: `image_callback_runs_on_the_completing_thread_when_the_domain_allows_it`
  (thread id inside the callback), `callback_issues_and_waits_for_a_second_io_through_the_provider_drain`
  (the waiting callback resolves a second I/O through op 2), plus the
  existing nested-wait and close-fence tests; 667 lib tests green on x86_64
  and linux/arm64, clippy `-D warnings` and the ABI gates green.
- Gate: ice-a `ab6-1442`, 3 interleaved rounds, medians: def 4k read QD32
  **1.02x stock** (p50 67 vs 68 us, p99 176 vs 189), QD1 read 1.05x, QD1
  write 1.07x (no regression), def 4k read QD8 1.04x, def writes QD1/QD8
  1.07x/1.06x, 4m write 1.10x; client CPU per op at QD1 read 213 vs 234 us
  (0.91x stock). Remaining below stock: def write QD32 0.98x, nof read QD32
  0.97x (p99 better in both).

Rationale: one fewer dispatch per completion, and the second serialization
point per image disappears; the remaining per-op cost is admission and
bookkeeping. Measured in `doc/perf/rbd-qd-20261102.md` (blocks `ab4` and
`ab6`).

Alternatives:
- Keep the strand and batch provider wakes per pass: measured for librados
  (`archive/rados-callback-wake-hold-q32-loss`), -3..-12 % client CPU but
  -7 % randread q32; rejected.
- Run callbacks on the owner thread: blocks the owner and deadlocks reentrant
  waits (adr 0467).
- A second strand worker per image: breaks serial delivery per image.
