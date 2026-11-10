<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0643 Device admission: data writes of all shards enter the device in arrival order through one window

Status: accepted
Date: 2026-11-03
Amends: 0160 (one device queue per store shard), 0066 (store admission of a txn with data), 0477 (pre-write)

## Context

Each store shard (one per core, adr 0160) submits through its own NVMe submission queue (kernel tier: the core's blk-mq queue; SPDK: the shard's qpair) and put every admitted data command in it at once. NVMe controllers arbitrate between submission queues round robin. A PM9A3 fetches about 12 ms of work (~32 MiB at 2.67 GB/s); beyond that the commands wait in their queues and each queue is served at 1/N of the device. PGs map to cores by hash, so the per-core backlogs differ at every instant and a write's store time follows its own core's backlog: 4 MiB randwrite at 32 in flight, 8 % fill, p99 121 ms vs BlueStore 66 ms at equal bandwidth; device latency at >= 768 commands in flight 12 ms on an empty queue, 87 ms on a queue with 512 ahead. A deeper shard queue (1023) does not change the split (p99 101 ms). A PM1743 fetches the whole backlog (~540 commands, 41 ms) and shows no split. At 80 % fill the PG gate waits are metadata page reads queued behind the same backlog. Evidence: doc/perf/w4m-p99-20261102.md.

## Decision

- Scope: the data extents of store txns (`Txn::data`: client writes, recovery pushes, EC sub-writes, replicated and EC alike) and pre-writes (adr 0477) take the device window. Bypass, unchanged: reads, WAL units / pads / root slot, tree and PG-log page reads, checkpoint page writes (their own per-device budget of one largest write, adr 0021 am. 76), olsm IO, trims.
- Order (`store::admit`, `DevAdmit` in the per-device table `DevIdle`, adr 0533): a txn's data bytes take one range of the device's write byte stream at commit (one `fetch_add` on the tail line). A write whose range ends at `end` goes to the device once `end <= done + window`; `done` counts the window bytes completed so far, all shards (one `fetch_add` per reap with window completions). The limit only grows with completions, so writes become admissible strictly in stream order; nobody grants: any shard's completion moves the limit for all. A core that does not run delays only its own admissible writes (their bytes stay counted until it submits them); later writes of other shards go as the rest completes. Liveness: the oldest incomplete position is always admissible while `window >= one largest device write`.
- Uncontended path (`Admit::free`): a txn whose data is at most one largest device write, on a shard with no data in flight or waiting, while no ticketed byte is incomplete (nothing is ahead of it), goes to the device outside the window: no ticket, no probe, no shared line written (it loads `tail` and `done`, which nobody writes while every write takes this path, e.g. QD1 4K). Order is not at stake with nothing ahead. Bound: one such txn per shard (its next txn takes a ticket; any outstanding ticket sends every shard's txns through the window), so the device holds at most one largest write per shard beyond the window. Larger txns always take a ticket (their shared-line cost is per MiB, and their order is what the window exists for).
- Each shard keeps its waiting writes in its existing data backlog (adr 0066) and drains it after its reap and at commit: a write goes out when its shard queue has room above the WAL floor and its range is admissible. A window-blocked shard's core re-polls at most every `IRQ_PARK` (200 us, kernel tier) since its pipeline is not empty; no new cross-core wake.
- Window rule, per probe (`Admit::probe_landed`): a window write submitted while its shard has no window bytes in flight is a probe (one with nothing ahead, `ahead = 0`, is a growth signal: the device drained the stream while the window held a write back). `ahead` = stream bytes before it not complete at its submission; `est` = window bytes completed while it was in the device, itself included. `est >= ahead` (the device served everything ahead: FIFO or a window within its fetch depth): grow by `step = window / 8` if the window held back a write of that shard since its last probe, else keep. `est < ahead` (the device served the fresh command after `est`): `target = est + est / 8`; move toward it by at most `step` if the window held back a write, else only down. The window settles 1/8 above the depth the device serves ahead of a fresh command, or opens past the demand on a device that holds everything.
- Bounds from geometry, no knob: at least one largest device write per shard of the device, at most every shard's queue slots above the WAL floor filled with largest writes. Start: the upper bound (the first shard of the device sets it; later mounts keep the running window): a device behaves as without the window until a probe measures a fetch limit.
- Pre-write (amends 0477): a piece is written ahead only when its range is admissible at once (`take_now`: nothing waits for the window); else it is skipped and the txn writes the data itself, as without pre-write. The window is asked before any block is reserved: a reservation given back stays a hole behind the allocator's next-fit cursor, and a stream whose pieces are all refused would spread its data over such holes (tsrv2: 1-2.2 M free blocks outside whole windows after the blk image fill, +4 % checkpoint pages per op in the QD1 4K write cell after it).
- Store admission (amends 0066): a txn with data is `Busy` only while the backlog waits for the shard's own queue room; data waiting for the window does not refuse the txn (its range is its place in the device order). The other admission rules are unchanged.
- Failure and remount: each shard's ticketed, not completed bytes are counted in its slot; a failed shard and a mount after an earlier instance give them back at once, late completions give nothing twice.
- The per-shard queue depth (adr 0160) stays the submission limit of a shard; it no longer partitions the device.
- Tiers: one mechanism in the store shard above `BlockDev`: kernel NVMe (passthrough and block), SPDK and the lab devices share it; the tag bits `ADM_PROBE` (bit 55 of the `K_DATA` / `K_PRE` tag id) and `ADM_OFF` (bit 54, `K_DATA`: outside the window) are opaque to every backend.
- Counters (`perf dump`, `flashstore_store_N`): `adm_window_bytes`, `adm_outstanding_bytes` (gauges), `adm_waits`, `adm_free` (data writes on the uncontended path), `adm_probes`, `adm_grows`, `adm_shrinks`.

## Rationale

Model (`admit::tests`, 4 shards, 32 x 128 KiB extents per txn, 49 us per extent, device fetch depth 33.75 MiB, queues 222 deep): round-robin device without window p99 118 ms at mean 50 ms; with the window from the lower or the upper bound p99 52.7 ms, the window settles at 39.8 MiB (1.18 x the fetch depth); at 4 clients (demand 16 MiB) p99 = mean, window not binding; a FIFO device keeps mean and p99, window opens to >= 3/4 of the queue capacity. BlueStore keeps ~14 ms in the device and one FIFO above it. Position-based admission needs no grant step and no per-ticket state: the same order as an explicit ticket/grant queue with one atomic per data txn. The probe measures the served depth directly; a throughput x idle-latency rule needs idle-latency samples a loaded device never shows. Accepted trade-off: shared lines per device (tail, done, window on separate cache lines, Relaxed) against thread-per-core isolation (adr 0006); atomics are a resource count, not data publication.

## Consequences

- + 4 MiB write p99 near the mean on drives that fetch less than the OSD queues; no change where the drive fetches everything (the window stays at the upper bound).
- + reads and metadata page reads wait behind about the device's fetch depth instead of the whole OSD backlog (the `obj_page` / `log_page` PG gates at 80 % fill).
- - one `fetch_add` per window txn and one per reap with window completions on shared lines; a txn with nothing ahead writes none (QD1).
- - window bytes of a descheduled core stay reserved until it runs; a probe sees bytes completed but not reaped yet by another shard as not served (shrink bias of about the reap delay over the probe latency).
- - after the first mount the window closes by at most 1/8 per probe (round-robin drives: ~25 probes from the upper bound to the fetch depth); after a shrink it reopens by 1/8 per probe that saw no limit while blocked.

## Alternatives

- Explicit tickets with grants by any shard (first draft of this ADR): same order, needs per-ticket state and a grant step; position-based admission gives it with the stream counters alone.
- Deeper per-shard queues (blk-mq tags): measured, the split stays (p99 101 ms); branch archive/w4m-shard-queue-depth-1023.
- Per-shard caps of any size: partition by construction.
- NVMe arbitration burst or weighted round robin (Set Features): a controller setting that orders per queue, not by arrival; not owned by the store.
- One shared submission queue for data: kernel queues are per CPU (blk-mq), SPDK qpairs are single-threaded; needs locks or a forwarding core.
- Moving PGs between cores by load: the imbalance is per instant (random arrivals), not per PG count (adr 0639 balances counts).

## Open questions

- Gate (doc/perf/w4m-p99-20261102.md step 3): 4 MiB p99 -56 to -58 % / -65.5 % at 8 % / 80 % fill (below BlueStore), reads behind the stream p99 -91 to -94 %, zen4b no regression. QD1 4K writes take the uncontended path (no window work): CPU/op, IOPS and p99.9 = main once a refused pre-write no longer leaves an allocator hole (before: holes from the blk image fill, +4 % checkpoint pages per op, p99.9 +2-4 %). `w4mj2q2`: p99 0 to -15 %, p99.9 -6 to +5 % between runs, A/A +5.2 %.
- `done` counts a completion at its core's reap: completions other cores have not reaped yet read as not served, so `est` reads low and the window settles below the demand at moderate depth (tsrv2 `w4mj2q2`, 16 MiB in flight: anywhere from 4 to 13 MiB per repeat, throughput equal, p99.9 varies -6 to +5 % vs main). Count `done` for the probe at completion time instead?
- Checkpoint page writes bypass the window with their own budget of one largest write per device: enough at 80 % fill? (80 % gate: no sign of a checkpoint stall.)
- Pre-writes are refused while the window binds (all of them in the saturated fill cells; the data goes with the txn, CPU/op still -7 %): cost on QD1 large writes?
- Data waiting for the window does not refuse a txn (am. 5 of 0066): the backlog is bounded only by WAL ring room and the upstream message throttles. Measure the backlog bytes under a stalled window head before relying on that bound (memory target, adr 0175).
- A shard whose writes all wait for the window has no cross-core wake; it re-polls within IRQ_PARK only with the default `store_irq_park_pct` 100 (`irq_full`), else up to DEEP_IDLE (1 ms). Also: `est` counts bytes given back without reaching the device (refused pre-write, unsubmitted, reset), and a cached limit lags another shard's shrink by up to one step (review 2026-11-04 round 1).
