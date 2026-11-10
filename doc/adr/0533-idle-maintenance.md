<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0533 Idle maintenance: device idle signal for background work, idle recompaction of compressed pools, extent census

Status: accepted
Date: 2026-10-23
Amends: 0021 (S6 pacing of background work), 0059 (space of cut chunks), 0474 (busy periods as a scheduling input)

## Context

The store paces background work per shard (adr 0021 am. 33): `BG_STEPS` steps per call while the shard has no txn in flight, one step per `BG_BUSY_GAP_NS` (10 ms) under client IO; defrag, cell sweep and evacuation use the same rule. A shard sees only its own queue: an idle shard bursts background IO onto a device that another shard (another core) saturates with client IO.
Overwrites inside a compressed chunk keep the rest of the chunk as windows (adr 0059 am. 4). The chunk's blocks stay until the space rule merges it at write time (fewer live blocks than the chunk occupies), and the merged blocks and the overwrites land as small raw records: after 4K aging most of a compressed image is plain (census, doc/perf/idle-maintenance-20261023.md). Nothing compresses it again later.
Requirement (user, 2026-10-23): idle time reclaims space, aged compressed space <= BlueStore; background IO goes into real device gaps; no cache prewarm after restart (recovery must be fast). Measure first (aging script, census).

## Decision

D1 Device idle signal (`store::devidle::DevIdle`, `ShardCfg::dev_idle`):
- The shards of one device publish the busy/idle edges of their queue (adr 0474 busy periods) in one table: one slot per shard on its own cache line holding an edge count (odd = commands in flight); written by the owner at an edge only (one relaxed store), read by other cores only when they have background work due. No time crosses cores: each shard keeps a view (`DevView`) of the counts it last saw and when, on its own clock (core clocks need not agree: the first version compared store-clock stamps across cores and saw a busy primary as quiet, doc/perf/idle-maintenance-20261023.md).
- `Shard::dev_quiet(now)`: no OTHER queue of the device is busy, and none changed during the last `BG_BUSY_GAP_NS` of this shard's watching (a count that moved between two looks counts as a change at the second look). Tree compaction and defrag / cell sweep treat a non-quiet device like client IO of their own shard (one step per gap); an evacuation runs only for a shard that waits for the chunk, at `reclaim_mbps` either way (adr 0021 am. 82). The gap is the existing pacing period; no new constant.
- The daemon shares one table among its per-core stores (`nvmestore::DEV_IDLE`); a `Store` without a shared table makes one for its own shards. Background IO of one shard defers the background work of the others: one background stream per device at a time.

D2 Idle recompaction of compressed pools (`obj::recompact`, `Stage::recompact`):
- The adapter hands the store each pool's compression as a write without client hints resolves it (`Store::set_pool_comp`, `PoolComp::resolve(0)`: aggressive / force pools; passive and none pools have none).
- A sweep walks the collections with non-zero compressed counters or a pool compression (`C`), their names (`N`, `L`), and per object its extent records (`e`), with listing cursors (no CLOCK reference: the working set stays). Candidates: (a) chunks with at least one window whose span is one aligned chunk (compressed again with the chunk's algorithm); (b) in a pool with compression, aligned chunk ranges (`max_blob`) made only of plain records, at least two of them, no hole (small overwrites and space-rule merges; a range written as one plain record was judged by its write).
- Per candidate one ordinary txn: the blocks a rewrite frees (chunks owned only by records of the range, plain blocks with one owner) are compared with the range compressed again (encoding computed once and handed to `write_chunk`; (b) sampled first with `sample_incompressible`, kept only within the pool's required ratio); only a rewrite into fewer blocks is staged, else counted `no_gain`. The txn is a regular write of the logical range: parallel commit, data crcs validated at replay, old blocks held until a checkpoint passed, windows release their chunk through the refcounts (adr 0021 am. 32). A chunk or block shared with another object (clone, snapshot) frees nothing and is never rewritten by it.
- Scheduling: only while the shard has no client work for at least `BG_BUSY_GAP_NS` and `dev_quiet`. Client work = a parked or foreign txn in flight, a client read (prefetch run, rolling read of another session), or the shard's queue busy while the walk has no IO of its own. One unit per call (a scan batch of `SCAN_BATCH` entries or one chunk txn), at most one chunk txn in flight; the walk keeps no shard active (a core with nothing else to do sleeps; the walk takes its next unit in the next store round). A staging refused for a read keeps its reads only while no client work arrives (then the read slot and the reader pin are given back).
- Trigger: checked every `CHECK_NS` (defrag's cadence): after mount (once), when windows were cut since the last sweep began (`comp_windows`), or on request. Under constant client IO it does not run; the space rule of adr 0059 am. 4 still bounds a chunk plus its overwrites by its logical span.
- Kill switch `ShardCfg::recompact` (tests); no daemon option (as `bg_compact`, `defrag`).

D3 Census and counters:
- The sweep counts per object (state before its own rewrites): objects with extents, records, plain blocks, chunks, chunk blocks, logical blocks in compressed records, windows, cut chunks with their live and span blocks; collections without compressed data (`unc_*`) only after `Store::request_census`. Published at the end of a sweep with a sweep sequence.
- `perf dump` `flashstore_store_<core>`: `bg_compacted_leaves`, `defrag_sweeps`, `defrag_cell_sweeps`, `defrag_moved_extents`, `defrag_moved_blocks`, `recompact_sweeps`, `recompact_chunks`, `recompact_freed_blocks`, `recompact_new_blocks`, `recompact_no_gain`, `recompact_skipped` (counters), `census_seq` and `census_*` (gauges).
- Tell `store census [request=true]` (scattered, summed over cores): the census, the recompaction counters; `request=true` walks every collection in the next idle sweep.
- Measurement: `lab/baremetal/aging.sh` (+ `aging-hook.sh`): aging of a plain and a compressed rbd image + omap, snapshots aged / idle / census, client cells; croit-flashstore-osd A/B arms and the BlueStore reference.

## Rationale

- Edges are already where the store knows queue occupancy (adr 0474): the signal costs one store per edge and nothing on a saturated queue; a per-command shared counter would put a contended cache line on every IO. Edge counts instead of timestamps: no assumption that TSC-based clocks of different cores (vCPUs) agree.
- Reusing the existing busy pacing for the device case keeps one rule: a shard behaves the same whether the client IO is its own or another core's.
- Recompaction through the ordinary staging path inherits every invariant (crash safety, refcounts, counters, caches, read-after-write ordering) instead of a second move protocol; comparing freed vs new blocks before staging makes every rewrite a net gain.
- A walk of names (not a write-path hint list) survives restarts without prewarming anything and gives the census; it touches only compressed collections unless asked.

## Consequences

- + Idle time compresses aged compressed pools again: ice-a 2 x 2 GiB aging, data used -7.9 % vs main, -9.5 % vs BlueStore (compressed pool -20 %); the census shows extents per object, windows and cut chunks per OSD (`store census`, `perf dump`).
- + An idle shard no longer bursts background IO onto a device another core keeps busy.
- - Background work of different shards of one device is serialized; its throughput on an idle device is that of one shard.
- - Each sweep re-tests no-gain candidates (read, sample or compress) when windows were cut anywhere since the last sweep.
- - An OSD without client IO next to a busy peer (a replica while the primary serves reads) does its idle work then: its CPU counts in cluster CPU per op.
- - Shards whose collections share a test process with another OSD's stores (in-process test clusters) share one table by index: only timing changes.

## Alternatives

- Cache prewarm after restart: rejected by the user (recovery must be fast).
- Candidate hints from the write path (punch): lost at restart, no census; the walk replaces them.
- Lower the space-rule threshold (merge at write time earlier): costs a read + decompress + compress on the client path, the latency am. 4 removed.
- Load-based throttle of background work (utilization threshold): a load switch; the edge signal schedules into gaps instead.
- Device-wide in-flight counter per command: contended atomic on the hot path.

## Open questions

- A chunk that stops being shared (clone removed) is only reconsidered at the next sweep trigger (windows cut, census request).
- No memo of no-gain chunks: incompressible overwrites are re-tested at every triggered sweep.
- A walk unit is not preemptible (compress + stage of one candidate or one scan batch, up to 2.7 ms on the PG core, doc/perf/idle-maintenance-20261023.md): a client op arriving during it waits. Units start only after a device gap of `BG_BUSY_GAP_NS`; no client cell showed it (QD1 read p99 within the spread of main, interleaved A B B A, both tiers).
