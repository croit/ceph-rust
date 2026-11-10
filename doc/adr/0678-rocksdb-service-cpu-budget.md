<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0678 RocksDB blocking work within the selected service CPU budget

Status: proposed; offline and focused single-pass comparison checked
Date: 2026-11-05
Amends: 0681 (worker/background placement only)

## Context

One object's foreground requests share a PG/store owner, not an entire-service
single-core execution limit. Native LSM can send bounded flush/merge rounds to
other selected OSD cores. The Rocks worker previously inherits and explicitly
pins the owner's logical CPU; first-created shared DB pools inherit that mask.
An asynchronous boundary on the same CPU still competes with owner execution.

## Decision

- Both multi-core transport launchers carry their actual selected CPU-ID vector
  through shared startup into each store mount. Do not infer the budget from an
  already-pinned owner's affinity, logical core number, or support-thread pool.
- Pin an owner's blocking DB worker to the next CPU in that vector, wrapping at
  its end. Multiple shards of one owner share this placement. A one-CPU budget
  keeps the worker on that CPU. Empty/duplicate/out-of-range selections refuse.
- Initialize the DB under the entire selected service mask, then narrow the
  worker. RocksDB's bounded process-wide low/high pools inherit this admitted
  mask from their first initializer, rather than an accidental single owner.
  No new pool, helper CPU, host-affinity change or scheduling delay is introduced.
- Existing single-owner/offline consumers without an explicit service vector
  preserve their current configured/inherited placement.
- Preserve native WAL authority, synchronous Rocks WAL plus watermark, bounded
  read sessions/credits, owner-only allocation/publication and ACK_ONDISK.

## Rationale

Separate blocking work from its serialized owner using already-admitted capacity.
Explicit physical IDs handle sparse CPU selections and keep kernel/own-stack
transports on one policy. Kernel scheduling of shared DB pools remains bounded
by the same service allocation; another selected CPU is not promised idle.

## Consequences and alternatives

Hot-object work can use additional service cores. Fully loaded multi-object
stores may contend on the next owner's CPU; rotation does not guarantee a gain.
Unbounded support CPUs, disabling durability, and changing the benchmark client
are rejected. Read-session concurrency and materialization policy are unchanged.

## Validation and open questions

Require independent sparse/single/invalid mapping and actual thread-mask tests,
both launcher builds, existing store/OMAP/restart checks, and a fresh sequential
matched-budget comparison. Capture actual owner/worker/background masks and
per-thread CPU/queue delay when available. Structural separation alone is not a
throughput, owner-saturation, or statistical performance qualification.

Focused comparison:27 cells pass with the8M working set and one-eighth mixed
quota; actual worker/pool masks stay within the four selected service CPUs.
Observed foreground is20.10% shorter than a fresh clean control; total sampled
CPU is6.45% lower. Full mixed quota and multi-object/topology qualification remain
open. Mixed p99 worsens8–12% in this pass; throughput gains do not establish a
tail-latency win. See ../perf/rocksdb-q4-placement.md for workload differences and
remaining CPU/write costs; this is not a general nativeLSM superiority claim.
