<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0718 Bounded batch-formation and worker-page profiling

Status: proposed
Date: 2026-11-07
Amends: 0713-rocksdb-materialization-profiling

## Decision

Extend the existing default-off profiling option, not the production policy.
Record once per eager owner freeze: charged bytes, five disjoint size buckets
(<=4KiB, <=64KiB, <=1MiB, <=8MiB, larger), and whether the high LSN initially
exceeds native durability. Time tagged freeze to successful enqueue separately
from worker queue time. Busy retries retain the tag/start; missing tags yield no
latency sample, mismatched/replaced tags increment an error. Enqueue is not ACK.
Record the same size buckets for serialized DB batches, including failed writes
with a separate failure count. Charged bytes and serialized bytes are distinct.

Each executed page additionally measures four exclusive elapsed/thread-CPU stages:
iterator setup/construction; overlay setup and initial positioning; merged walk
and owned output construction; explicit iterator destruction. Range-skip seeks
stay in walk. Failure/refusal after iterator creation still records an attempt
and its reached stages. An invalid non-page query is not a page attempt. Absent or
nonmonotonic CPU clocks invalidate the entire page CPU sample, not elapsed time.
No per-entry clocks, property reads, logging, diagnostic allocation or locks.
Disabled profiling reads no new clocks; runtime option checks remain.

Keep the existing outer page timer as an inclusive reconciliation reference. It
also includes completion construction and surrounding cleanup; stage totals are
not a claim about client latency, owner encoding or physical NIC CPU placement.
The stage boundaries themselves perturb instrumented runs. Counters are sampled
independently, not an atomic event trace; compare conservation at settled points.

## Invariants

No change to eager freeze eligibility, one frozen/worker batch, native durability
gate, synced external watermark, native marker submission, WAL floor or ACKs.
No retained iterator/snapshot, changed page/credit bound or owner scheduling. All
replies remain owned. Default native LSM does not instantiate this profiling state.

## Validation

Independent fixed bucket/timing/error vectors; disabled-clock refusal; failed and
credit-limited real pages; tagged enqueue retry/mismatch checks; delayed native
durability and ACK/replay anchors; unchanged binary-prefix, overlay, continuation,
reopen/owner-yield regressions. Affected Store/adapter/schema/production checks and
source-bound builds precede a new instrumented campaign. No speedup is assumed.
