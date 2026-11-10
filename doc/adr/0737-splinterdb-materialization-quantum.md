<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0737 SplinterDB materialization quantum experiment

Status: rejected for the current throughput campaign; experimental implementation reverted
Date: 2026-11-08
Amends: 0732-splinterdb-throughput-pipeline (selected size threshold only)

## Experiment outcome

The bounded9-cell arm passed exact per-run correctness/QD32, effective half-limit
readback and full teardown. Its foreground sum was680.638s versus586.245s in the
earlier full-quantum arm. Pure-write throughput regressed; mixed-range tails improved
but mixed throughput did not. Restore the original freeze/admission threshold and
its schema/tests. Preserve the experimental source, tests, binaries and evidence
under splinterdb-assist-qd4-20261108/half-batch-* andbin/half-batch/.

These are descriptive single-pass observations under completion-dependent v3
selection, not identical realized traces or a statistically proven causal result.
The tradeoff does not justify adopting the half quantum for this throughput goal.

## Context

The corrected101/1MiB arm completed all nine cells but mixed workloads dominate
foreground time. Its foreign worker serializes a complete overlay flush with
point reads; observed read-queue sums are substantial. Earlier diagnostic flush
turns averaged roughly250ms. These are observations, not a promised batching gain.
Smaller extent prefetch was inconsistent and is not combined with this change.

## Decision

For the selected Splinter engine only, freeze at half the existing native logical
memtable soft threshold (round up, minimum1byte). Use the SAME selected threshold
for active-full admission while an older frozen batch remains. Changing freeze
alone lets saturated writers refill to the old admission bound and defeats the
experiment. Export the selected quantum and original base as gauges for readback.

Do not change the native threshold, allocated cache/memory budgets, foreign library
memtable sizing, checkpoint-age clock, force latch, WAL-pressure progress, worker
placement or helper policy. Native LSM/Rocks/B-tree paths stay unchanged. Existing
whole-record/first-batch overshoot remains legal; this is not a hard peak-byte cap.

Both foreign barriers and native publication remain per materialization, with the
same native durable ACK/replay authority. No on-disk or peer protocol change.
More smaller flushes may increase barrier/publication CPU and reduce pure-write
throughput. Hold scale101,1MiB extent prefetch and all other campaign settings fixed.

## Acceptance

Independent threshold/admission boundary and rounding tests; retain age, force,
WAL pressure, capacity, native/Rocks isolation and crash/replay regressions. Require
effective base/quantum readback. Measure actual turns/counts, worker queueing,
CPU/useful key, tails, selected settlement and exact/QD32 workload results, not
only foreground sum. Reject or restrict the policy if pure-write or full-suite
cost outweighs mixed-latency gains. No production promotion is implied.
