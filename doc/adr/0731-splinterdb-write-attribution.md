<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0731 SplinterDB materialization attribution

Status: proposed; implementation and comparative qualification in progress
Date: 2026-11-08
Extends: 0734-splinterdb-maintenance-offload

## Context

Normal maintenance offloading did not remove the insertion/update gap. Retained
observations show extra process CPU/key, a nearly occupied file-worker core,
roughly twice the materialization cadence and rare long RPCs. Flat sampled
packing leaves do not distinguish memtable versus normal callbacks.

## Decision

Measure coarse worker stages with cumulative attempt count, elapsed wall time,
thread CPU time and maximum elapsed wall time: overlay application (including
range expansion and synchronous engine assistance), data barrier, watermark put,
watermark barrier, point/inventory reads, scans and sampling. Separately record
enqueue-to-worker-pop wall time for reads/flushes. No per-key clock or new lock,
allocation, raw engine-statistics sampling or timing-dependent control policy.
Failed stage attempts count; a CPU-clock error increments an explicit counter,
not a successful zero-CPU observation. These best-effort concurrent snapshots
are not transactionally consistent, independent task CPU, or proof of drain.
The clock calls have nonzero cost, matched in baseline/candidate binaries.

Do not confuse queue delay with owner publication/admission wait. Helper CPU is
not included in a file-worker CPU stage. Restore task ancestry in a separate
diagnostic build/profile if needed, without changing the pinned library source;
do not combine intrusive diagnostic throughput with comparison-arm rates.

Capacity admission uses selected SplinterDB active plus frozen buffers, including
native-replayed data. The native manifest is not the overlay owner. Filesystem
reservations remain a separate bound; zero-growth recovery/publication retains
progress. No acknowledgement, replay, format, watermark or barrier change.

## Qualification and alternatives

Independent regressions reproduce missing active/replayed debt before the fix,
then cover active+frozen accumulation, pre-acceptance refusal/retry, replay and
zero-growth progress. Stage arithmetic/error vectors and existing two-barrier
failure matrix cover telemetry boundaries. Runtime/benchmark qualification is
separate. Do not promote a scheduling or I/O candidate from static cost alone;
no larger CPU/memory budget or removal of foreign persistence is authorized by
these counters. Native/Rocks/B-tree paths do not execute this instrumentation.
