<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0524 PG removal never blocks the PG core: queued deletion txns, one in flight, one drain slice per step

Status: accepted
Date: 2026-10-23
Amends: 0021 (S4 deletion at NoSpace, S11; am. 33 background pacing), 0522 (same core-share rule)

## Context

Deleting a pool stalled the foreground I/O of other pools (rental 2026-10-22: max latency 435 ms during a pool delete on croit-flashstore-osd, 57 ms on BlueStore). A lab repro (doc/perf/pg-remove-stall-20261023.md, `oprobe rmstall`, `lab/baremetal/pgrm-ab.sh`) found two causes on the PG core: (1) every deletion slice ran blocking store calls (`Store::commit` = drain the store queue, wait for durability; `wait_loads`; a cold `list`), paced by constants (2 ms slice, 10 ms gap): foreground throughput fell 45 % during the removal, p99 x5; (2) `RemovePg` set its durable marker with a blocking commit plus a queue barrier per PG, all PGs of the pool in one burst: a 14-20 ms stall at the delete in the repro (64 PGs, 4 cores per OSD), growing with the PGs per core.

## Decision

- `RemovePg` (the PG's `Delete` txn) queues the marker txn through the store queue (`StoreAdapter::queue_remove_pg`); the PG's token completes when it is durable. The deletion txns queue behind it in the same shard FIFO, so the marker is durable before the first object goes. A full store queue falls back to the blocking marker.
- Deletion is `StoreAdapter::step_removals(bound_ns)`: one non-blocking step lists the next batch (<= `remove_batch` 24 objects, or the closing txn of a PG) with non-blocking reads (a cold leaf starts its load and the step retries) and queues one txn. One deletion txn is in flight per core; `poll_store` reaps it. Nothing waits for a page load or durability.
- The OSD passes `xcore::SLICE_NS` (one drain slice, adr 0522) as the bound: the batch is cut to what the learned cost per object (EWMA of the step's CPU) fits in it; the first step of a core removes one object. `flashstore_delete_slice*_ms` / `_gap_ms` are gone; `osd_delete_sleep*` stay registered and are ignored.
- Deletion is background work of the store and follows its pacing rule (adr 0021 am. 33, adr 0533; am. 1): steps run back to back (one txn in flight) once the core had no client demand for one background gap (`store::shard::BG_BUSY_GAP_NS`); under client demand one step per gap. Client demand = an op or peer PG message handed to the core's PG work (`Utilization::ops`), sampled every pass (`pgs::RmPace`). Above the failsafe fill (client writes refused for space) the steps run back to back. Counters `flashstore_core_<n>.rm_free_steps` / `rm_paced_steps`.
- NoSpace (from `queue` or as a staging error) halves the batch down to one object, then backs off 1 s; the deletion is never dropped (unchanged semantics).
- The driver hook returns progress only when the call queued a txn (a txn in flight or a loading page is store I/O that keeps the driver polling).
- Blocking forms stay for synchronous callers (`remove_pg`, a re-create finishing the old deletion, tools, tests): `finish_removals` / `finish_removal_blocking` drive the same queued steps and poll the store.

## Rationale

- The stall was blocking inside the PG core's loop, not CPU: removal CPU on the cores was < 0.1 % of samples; a blocking durable commit also serialises the shard's WAL pipeline with the foreground writes. Removing the waits fixes the cause; bounding the step CPU by the same slice as the inbox drain gives clients a hard wait bound without a rate.
- A non-preemptible step delays every client message that arrives while it runs; at any duty that fills the idle time the clients pay on every hop. Client demand on the core is the signal that decides whether idle time is really idle; the pacing period is the store's one background period (tree compaction, defrag, recompaction use it), no new constant. The failsafe override keeps space recovery fast exactly when the clients need the space.
- The step bound costs no removal speed where steps are small (the learned cost per object is ~4 us; a 24-object step is about one slice) and trims cold outliers.

## Consequences

- + Pool delete (1M objects x3, zen4a/b): removal 28-31 s -> 5-8 s; the delete-time stall and the 25-28k long loop iterations are gone (~1k); omap-heavy PGs 3.3-4.1 -> 2.5 s, p99 5-8 -> 2.4 ms (doc/perf/pg-remove-stall-20261023.md).
- + Fewer long loop iterations (>= 1 ms: 26-28k -> ~1k per run).
- + Clients of other pools keep their ops/s and p99 while a deletion runs (am. 1); under steady client load the deletion advances one step per gap per core (4.5-5.7k objects/s over 3 OSDs x 4 cores, 1M objects x3 in ~9-11 min; BlueStore ~22 min on zen4a) and runs back to back once the clients pause (doc/perf/pg-remove-clients-20261026.md).
- - Under steady client load the deletion leaves idle core time unused; its speed there is the per-object cost (~14 us of tree work per object) times one bounded step per gap.
- - Deletion progress depends on the store queue being empty (`queued_count() == 0`): a core whose store queue never drains makes no deletion progress (as before).
- - Removal of one huge object is one op in one step (its cost is not bounded by the batch cut); huge omap objects delete by range (adr 0021 S11), data-heavy objects by extents (see perf doc, siblings).

## Alternatives

- Keep the blocking slice and tune the constants (2 ms / 10 ms): a constant per workload; the loss was the blocking, not the duty cycle.
- Detect client activity per core to bound steps only while clients run (tried): the signal missed most steps; always bounded is simpler. Removed.
- Idle-iteration / 1:1 CPU credit gate, and no step while client txns are in flight with a 1:1 occupancy guard (both tried): removal 6 s, clients -45 % as without. Removed.
- Unpaced back-to-back steps bounded by `SLICE_NS` only (the first form of this ADR): the deletion took 65-75 % of every PG core (~14 us of tree work per object, steps of ~100 us); clients lost ~35-47 % ops/s and p99 x2 for the 5-8 s it ran (am. 1).
- Steps only in idle iterations, or a CPU credit 1:1 with client work: both still fill the idle time; a client message arriving during a step waits for it on every hop (measured -45 %).
- A gap derived from client latency (feedback on commit latency vs its idle value): needs a tolerance constant and a baseline window; the client-demand gate needs neither.
- Several deletion txns in flight: more removal speed, more WAL/checkpoint pressure next to clients; not needed (6 s per 1M objects x3 on 3 OSDs).

## Open questions

- Deletion speed under steady client load: one step per gap; a cheaper deletion (range removal of a PG's keys instead of per-object tree deletes) would raise it at the same client cost (OQ 100).

## Amendment 1 (2026-10-26): deletion paced as background work

Cause of the client loss (doc/perf/pg-remove-clients-20261026.md): CPU, not store I/O. Unpaced steps (each <= `SLICE_NS`, ~6 objects) ran whenever the previous deletion txn was durable: 65-75 % of every PG core, ~14 us per object, 62 % of it applying the tree deletes and 32 % preparing them; device busy < 10 %. Every client hop (primary, replicas, commit, reply) waited for a running step and for the deletion's WAL unit (one unit in flight, `wal_coalesce` 1): replica store 47 -> 175 us, xcore_in 30 -> 130 us, primary repop rtt 375 -> 1165 us. Decision: the bullet "Deletion is background work ..." above (gate in the OSD core loop, `pgs::RmPace`; store and adapter unchanged).
