<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0675 Bound RocksDB worker diagnostic amplification

Status: proposed; performance candidate
Date: 2026-11-05
Amends: 0681 (worker diagnostics, not durability or engine selection)

## Context

The actual RocksDB worker refreshes properties and enumerates/stats every database
file after each native materialization, in addition to its250ms periodic sample.
The same worker serves point/scan requests. A real-database regression produces
65diagnostic walks for64small durable batches in14ms. This is integration work,
not missing filesystem buffering: current RocksDB already uses buffered SST I/O,
LZ4, block cache, Linux page cache and automatic iterator readahead.

## Decision

- Retain immediate filesystem-free-space refresh after each materialization. It
  is admission information, not merely a diagnostic.
- Bound DB property/file-accounting sampling to the existing250ms worker cadence
  plus bootstrap. Materialization must not reset/starve the periodic clock.
- Preserve explicit invalid/aged/error samples. Delayed allocated-file accounting
  is diagnostic only; it does not authorize writes or release native redo.
- Keep synchronous RocksDB WAL/batch+watermark persistence, native WAL authority,
  publication ordering, session credits, failure propagation and on-disk format.
- Observe worker attempt counts/elapsed time for materializations, point queries,
  internal scan pages and diagnostics; native charged bytes per materialization;
  actual configured block-cache capacity separately from its sampled usage.
  Attempts include refusals/failures, elapsed includes worker-call allocation/copy
  work, not owner queue wait or whole-service CPU. Snapshots of lifetime counters
  are approximate independently loaded totals, not an atomic operation trace.

## Qualification

Require the real-worker sampling regression, invalid/stale telemetry tests,
RocksDB/native publication crash regressions and independent ordered-map OMAP
integration/restart tests. Then build on the build host, transfer hash-verified artifacts
to the OSD test host, and run fresh sequential1M Phase1 arms for actual RocksDB, unchanged
native LSM and classic BlueStore. Report gains/losses and settle-inclusive costs;
never substitute older reference runs. One pass is not statistical significance.

This candidate cannot by itself improve a fully settled read-only scan. Further
overlay iteration, page sizing, shared cache budgets or materialization coalescing
require separate evidence and contracts; disabling durability is not an option.

## Second iteration: readiness-driven Rocks retries

Fresh1M control/iter1 Rocks foreground totals274.006/279.050s show no aggregate
win from diagnostic de-amplification. Iter1 worker point calls consume9.21s in a
117.51s mixed-delete cell. Worker time is not RPC time, but this motivates checking
the owner/worker execution boundary rather than assuming missing buffered I/O.

The Rocks read/admission wrappers set a completion-style wake on every Miss,
including an already-pending read. That wake retriggers parked request execution;
the same pending read returns Miss and generates another wake without progress.
A held-worker64-key regression fails with an immediate false Wake.

The second candidate removes pending/admission self-wakes only from Rocks paths.
Pending worker work remains pollable through the existing busy predicate. A
credit-blocked session also remains pollable; actual completion/failure, explicit
credit release/cancellation and abandoned-owner expiry wake waiters. Idle expiry
alone must not be mistaken for worker completion or repeatedly generate wakes.
Native LSM scheduling and executor-wide retry policy are unchanged.

Polling readiness is separate from the worker-busy predicate used to admit native
materialization: a credit waiter cannot stop an idle worker from publishing
durable data. Expiry uses one sampled idle duration, then reports whether it
actually removed an owner; crossing the30s boundary cannot clear polling without
the corresponding readiness wake. Independent durable-buffer/credit-wait and
30s-minus1ns/exact30s/plus1ns fixtures guard these liveness boundaries.

Tests hold a real worker completion, retry128times with no false Wake/one queued
read, release and check all64values; worker failure must still wake/fail the
owner. Separate competing-session fixtures cover real cancellation/release and
30s abandoned-credit expiry without real-time sleeps. Existing nested-session,
budget, scan and crash tests remain required. Owner query/enqueue/pending-miss
and consumed-completion counters distinguish request retries from library work.

## Matched1M result

One unchanged RocksDB control plus two fresh three-engine iterations completed
63cells with zero workload errors and identical corresponding model checkpoints.
Native candidates were built on the build host, hash-verified and executed sequentially
on the OSD test host. Classic used its existing pinned OSD-host reference build.

Foreground seconds:

| engine | control | iteration1 | iteration2 |
|---|---:|---:|---:|
| actual RocksDB |274.006|279.050|110.598|
| unchanged native LSM |—|110.416|109.217|
| classic BlueStore |—|120.660|121.631|

Iteration2 is59.64% shorter than control in this pass. Mixed point-read means
drop from iteration1's5.692/6.363ms to0.983/1.048ms, while worker point-call time
remains similar. This supports fixing readiness/retry amplification rather than
claiming an I/O-buffering gain. No cache capacity, prefetch mode or durability
change explains the difference. One pass gives no variance/significance estimate.

Remaining costs matter: final Rocks sample uses113.82CPU-s versus72.95nativeLSM/
86.17classic and writes14.68GB versus7.65/6.02GB. All three Rocks scans remain
slower than classic. Separate per-DB cache capacity is not a shared active-owner
budget; Linux page cache is outside the OSD target. These are full-profile
observations, not universal engine rankings or physical-power-loss qualification.

Final affected checks: Store library281passed12ignored, Rocks integration4passed,
focused Rocks unit29passed1ignored, native/feature perf schema, matching-feature
all-target Clippy and changed-file formatting pass. Independent review findings
on credit-wait materialization and exact expiry wakes were fixed with regressions
before deployment. All owned clusters ended stopped; storage layout/mount identity
was preserved. Status remains proposed pending broader performance/production
qualification; full evidence is in the separate RocksDB1M campaign reports.
