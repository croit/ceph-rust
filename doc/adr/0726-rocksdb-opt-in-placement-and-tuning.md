<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0726 Opt-in RocksDB worker placement and engine tuning

Status: proposed; am. 1 sets two engine-limit defaults
Date: 2026-11-08
Amends: 0678-rocksdb-service-cpu-budget

## Context

The rocksdb-10h campaign (single-object OMAP workload, 4 service CPUs) showed the
RocksDB backend about 2x the native OSD CPU per key, write stalls of about 4 s per
16 s update cell, and a heavily preempted worker (about 27k involuntary switches
per cell). Code facts: each worker is pinned to the next owner's CPU; the shared
DB pools have one low and one high thread on the same budget; most stall and L0
limits are library defaults. Evidence does not show which placement or limits
help: with one hot shard the neighbour owner is mostly idle, and the IRQ-parking
series changed CPU contention in both directions.

## Decision

Expose the candidates as startup options whose defaults reproduce the measured
behavior exactly, so fresh matched A/B arms decide defaults later:

- `flashstore_rocksdb_worker_cpu`: `next` (default, owner+1), `owner` (the
  owner's CPU: worker and owner alternate, no cross-core contention), `float`
  (whole selected budget, scheduler-balanced). Always inside the selected
  service budget; invalid values fail startup.
- Engine limits, defaults = historical fixed values: `flashstore_rocksdb_low_threads`
  (1, shared compaction pool, 1..=8), `_high_threads` (1, shared flush pool,
  1..=4), `_background_jobs` (2, 1..=16), `_write_buffer_number` (2, 2..=8),
  `_l0_slowdown_trigger` / `_l0_stop_trigger` (0 = library default, at most 1024,
  stop not below slowdown). Pools are process-wide and share the selected service
  CPU budget: more threads are not free capacity. Out-of-range values or
  non-numbers refuse startup.
- Every `flashstore_rocksdb_*` key, including the profile switch, is read and
  validated only when `flashstore_rocksdb_dir` is set. Without a root no RocksDB
  store can open, so native LSM/B-tree OSDs sharing a config ignore these keys.

Placement and tuning never change data, ordering, sync policy, durability or
replay. No default changes without repeated fresh-arm measurements that hold
hardware, workload and durability constant.

## Verification

Unit: parsing (including rejection), defaults equal historical values, budget
validation stays atomic for every mode. Live: pending; one variable per A/B.

## Amendment 1 (2026-11-09): two compaction threads and four background jobs

Defaults become `flashstore_rocksdb_low_threads=2` and
`flashstore_rocksdb_background_jobs=4` (previously 1 and 2). High threads, write
buffers, L0 triggers, worker placement and profiling keep their defaults; ranges
and validation are unchanged and explicit values still override.

Matched fresh first-five arms (two per setting) removed the update-cell write
stall and its multi-second tail at unchanged OSD CPU, with insert and scan
changes inside run-to-run noise; a full nine-cell run with these values completed
without a stall above 0.3 s (perf/rocksdb-tuning-defaults-20261109.md). The
compaction pool is process-wide and shares the selected service CPU budget:
budgets below four CPUs should set 1 and 2. Evidence covers one platform and one
OMAP workload; requalify elsewhere.
