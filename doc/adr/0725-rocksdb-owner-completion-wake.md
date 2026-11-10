<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0725 RocksDB worker completions wake the owner core

Status: proposed; performance candidate (not yet live-qualified)
Date: 2026-11-08
Amends: 0724-rocksdb-page-handoff-profiling

## Context

RocksDB OMAP work (pages, point reads, materializations) runs on a blocking
worker thread per shard and returns through a bounded completion ring. Pending
worker work keeps the shard non-quiet, so a kernel-tier owner that goes idle
takes the store-busy sleep. With store IRQ parking at 100 % that sleep ends only
on a device completion, the mesh/admin wake or the 200 µs cap. A worker
publication raised none of these. The v5 diagnostic measured mean 129 µs from
final publication attempt to owner dequeue per page; at QD1 this sits on the
critical path of every scan page and every materialization cycle. Parking 0 %
removed the latency but made owners spin (owner scan CPU about 4x) without an
elapsed gain.

## Decision

- The driver's core wake handle (the one mesh senders and admin socket workers
  already use) is handed to the store after mount: `Osd::set_core_waker` ->
  `PgStoreOps::set_owner_wake` -> `Store::set_owner_wake` -> each owned shard's
  RocksDB client. First install wins; without one, behavior is unchanged.
- The worker calls it after every published completion (success, refusal,
  failure, and while retrying a full ring). The wake costs one fence and one
  flag load when the owner is awake; a syscall only when it announced a sleep.
- The owner's post-announcement re-check (`Osd::handed_work`) also reports a
  published, unconsumed worker completion (`PgStoreOps::handed_completion`).
  Publish-then-wake on the worker and announce-then-recheck on the owner close
  the lost-wake window (same argument as `rt::wake`). A store borrow conflict in
  the re-check reports work (no sleep), never idle.

No data, ordering, durability, replay or admission change: only when the owner
learns of a completion. Parking policy and defaults are unchanged.

The wake is a `dyn Fn` call per worker completion (per page or batch), not per
client op; it stays off the owner's hot path (ADR 0024).

## Verification

- Unit: page and flush completions wake the owner only after publication and
  stay visible to the re-check until polled; first wake wins; no wake keeps the
  polled behavior.
- Live, one matched fresh-arm A/B per arm at parking 100 % (dev lab, 8 Mi-key
  single-object OMAP phase 1, first five cells, 8 sessions x QD4): wakes are
  delivered (worker wake writes rise); write-cell throughput within run-to-run
  noise (about 10-15 %); scan +8 % with lower p99. No speedup claim before
  repeated matched runs.
