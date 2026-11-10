# 0474 Device busy time and throughput per store shard (iostat %util, MB/s for SPDK devices)

Status: accepted
Date: 2026-10-20

## Context

SPDK owns the NVMe device: `iostat` sees nothing. Perf regression runs (vstart fio suite) need a device utilization number per OSD to tell device-bound cells from CPU-bound ones. SMART `controller_busy_time` counts whole minutes and is controller-wide (useless for 30 s cells and for several OSDs on one controller, adr 0463).

## Decision

- Each shard (one device queue) counts `dev_busy_ns`: wall time with >= 1 command in flight (`queue_depth - queue_space > 0`), same semantics as iostat `%util` (in flight until the completion is reaped).
- Edge-based: `Shard::dev_note` opens a busy period when the queue has commands and none is open, closes it when the queue is empty. Called after `Shard::submit` / `submit_read` (submits between polls) and before and after the reap in `Shard::poll` (submits inside or outside poll not yet noted; completions). The clock (`fastclock::Mono`, TSC) is read only on an edge: zero cost on a saturated queue, <= 2 reads per idle period at QD1.
- `Shard::dev_busy_ns()` includes the open period (a saturated queue may never drain).
- Device throughput: `dev_read_bytes` / `dev_write_bytes` = buffer length of each successful Read / Write completion, counted in the reap loop of `Shard::poll` (WAL, data, checkpoint, page loads; trim and write-zeroes excluded). No clock read.
- `perf dump` logger `flashstore_store_<core>`: `dev_busy_ns`, `dev_read_bytes`, `dev_write_bytes` (counters), `dev_completions` (counter, `ShardStats::io_completions`), `dev_qpairs` (gauge, shards of the core). Core %util = Δ`dev_busy_ns` / (Δt x `dev_qpairs`). Lifetime values; other cores' values are 1 s stale (`CoreStats`).
- No queue-depth integral (`inflight x dt`): it needs a clock read per poll. Average queue depth is left to the client side (fio) or Little's law.

## Rationale

Edge accounting gives exact busy time where the store already knows queue occupancy, with no per-command timestamps and no change to the device trait or the four device backends.

## Consequences

+ Device %util, IOPS and MB/s per core / OSD in `perf dump`, also for SPDK multi-process OSDs on one controller (per namespace queue, where SMART is controller-wide). Write amplification = Δ`dev_write_bytes` / client bytes written.
+ No hot-path cost while the queue stays busy.
- A submit made outside `submit`/`submit_read` and outside `poll` (prefetch, page loads, background) opens its period at the next poll: undercount <= one core loop pass.
- Several shards on one core sum their busy times; %util divides by `dev_qpairs`. Shards sharing one device overlap: the device-level union is not available (iostat has the same limit per queue).

## Alternatives

- Account in each device backend (SPDK, kernel, file, sim): exact submit time, but four implementations and a trait change.
- Sample in-flight count per poll with the poll's `now`: overcounts the idle gap before a submit made between polls (up to one idle sleep, ~20 us per op at QD1).
- SMART `controller_busy_time`: minute resolution, controller-wide.

## Tests

`services/osd/store/tests/wal.rs::dev_busy_counts_wall_time_with_commands_in_flight_only`: idle time not counted, open period visible, closed period counted, completions and write bytes counted.

Used by: adr 0533 (the busy/idle edges also feed the device idle signal of background work).

## Amendment 1 (2026-10-20): kernel tier transport diagnostics per core

- `perf dump` logger `flashstore_core_<n>` also carries the kernel tier transport counters of the core, cumulative: `rx_bytes`, `rx_pauses` + `rx_pause_ms` (receive paused, ingress pool full, adr 0175), `long_1ms` / `long_10ms` / `long_100ms` (working loop iterations at least that long = every socket of the core unread that long).
- Source: `KStats` + `KCore::busy_hist`, handed to the OSD every loop iteration (`Osd::note_net_diag`, absolute values, next to `note_ring_enters`), stored in `Utilization`, shipped to the control core in `CoreStats` like `busy_ns`. No lock, no allocation; never in the mgr counter catalogue.
- Counters, not maxima: a bench takes per-cell deltas (`lab/vstart-bench.sh`: busiest core %, pauses, long iterations per cell). Test: `xcore_tests::utilization_worker_snapshots_and_counter_only_updates`.
