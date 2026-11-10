<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0724 Page-only queue handoff profiling

Status: proposed; diagnostic candidate
Date: 2026-11-08
Amends: 0718-rocksdb-batch-and-page-stage-profiling

## Decision

Use the existing default-off RocksDB profiling option. For accepted Page requests
only, carry inline optional timestamps through the request/response rings:

- A: immediately before the successful request-push attempt, after query cloning.
- B: immediately after worker dequeue, before the test hold and execution.
- C: after outcome construction/accounting, before completion enqueue attempts.
- D: immediately before the final successful completion-push attempt.
- E: on owner dequeue, before cache/refusal/failure handling.

Export B−A request publication/dequeue, C−B worker occupancy, D−C completion retry,
E−D publication-attempt to owner-dequeue, and E−A total elapsed sums. No CPU or
full RPC interpretation; E−D includes push cost and receipt bookkeeping. Existing
worker stages overlap these intervals and are not additional summands.
D−C includes fixed envelope/counter preparation even with no full-ring retries;
it is not pure backpressure time. E−D is not pure blocked or wakeup time.

Count accepted, dequeued, ready, published and consumed messages separately.
Consumed success/refusal/failure counts include invalid-time samples; valid
samples and ordering/overflow/missing-metadata errors are distinct. Full-ring
retries retain C and change only D. Rejected request pushes, repeated pending
probes and cache hits are not accepted pages. Periodic unrelated failures remain
unprofiled. Cancellation/worker exit can leave accepted-minus-consumed incomplete;
do not add a new failure-publication path to close that accounting gap.

Use checked monotonic differences and checked u64 nanosecond conversion. Bad
metadata never produces a fabricated zero interval. Atomic counter fields are
independent lifetime totals, not a coherent trace: reconcile settled windows or
label mismatch. This first diagnostic exports counts/sums, not tail distributions.

No added off-mode clock calls, per-entry clocks, per-request measurement heap
allocations, locks or trait objects. Fixed ring slots grow even in off-mode;
record their sizes and compare diagnostic-on/off artifacts separately from the
already measured control binary. No claim that instrumentation is free.
The sixteen added atomic counters also reserve128bytes per worker profile,
including when disabled; this is separate from the ring-slot footprint.

## Boundaries and validation

Do not alter notification, owner parking, fairness, leases, cache policy, credits,
native LSM, wire/disk formats, WAL/sync/watermark/ACK or shutdown/detachment policy.
No iterator or borrowed page entry crosses the worker boundary.

Require fixed endpoint vectors, equal/backward/overflow/missing ticks, real full
ring retries and rejected enqueue tests, disabled clocks, held worker/owner,
cache/pending behavior, refusal/error/cancellation and unchanged logical output.
Extend schema expectations without reusing offsets. Affected Store/adapter/OSD
schema and production checks, independent review and source-bound builds precede
any separately labeled diagnostic campaign. No speedup or park-policy change is
authorized by these counters alone.
