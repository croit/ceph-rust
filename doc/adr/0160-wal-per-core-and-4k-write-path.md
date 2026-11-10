# 0160 Store 4K write path: one WAL per core (shard = core), direct op translation, per-core object-state cache

Status: accepted, amended (am. 9)
Date: 2026-10-15
Consolidated 2026-10-19; full pre-consolidation text: git show 60868596d:doc/adr/0160-wal-per-core-and-4k-write-path.md
Measurements and the unbuilt D2 design: doc/perf/adr-0160-history.md

## Context

Group commit (adr 0021 am. 37) shares a WAL unit only between txns of one shard. With 32 shards per device, per-shard depth is QD/(32/cores) and a 4K txn costs data plus up to one 4 KiB WAL block. PM1743 is write-bandwidth bound (~3.05 GB/s = 748k 4K IOPS), so device bytes per txn is the lever. QD1 CPU targets (Mac `w4k_bench`): primary < 10 us, replica < 5 us (not reached, see Open questions). Related: adr 0021, 0006, 0031, 0093, open question 36.

## Decision

D1. Store shard count is an explicit mkfs parameter `store_shards` (conf `flashstore_store_shards`, `croit-flashstore-tool prepare|mkfs --store-shards auto|N`).
- Default `auto` = the OSD's configured cores at mkfs (`--cores` / `flashstore_cores` / `flashstore_lcores`; unknown: 8). Any N in 1..=256 (`layout::plan`). One shard = one WAL ring + one qpair, so auto = one ring per core.
- Routing, replay, checkpoint, crash contract unchanged: `pg_core` = ((pool+seed) % S) % n (adr 0031).
- Core c of n owns shards `s % n == c`. n != S logs a WARNING naming the fix (redeploy with the wanted cores; cluster backfills). Core-count changes across restarts work (PGs follow their shard).
- WAL rings: device budget `WAL_TOTAL_MAX` = 4 GiB: `min(4 GiB, device/64)` / S, clamped 64 MiB..4 GiB (`layout::wal_blocks_for`). Mkfs-time only. Max txn = ring/2 (adr 0028). Lab devices (< 256 GiB) keep 1 MiB alignment + meta_pct 2.
- Per-shard sizing checked: ingress windows (128 ops / 64 MiB per shard = per core), mesh lanes (shard % n), `CoreSpec` (n <= S). Mkfs/fsck/`inspect` use the new default; old stores keep their S (no compat path).
- `mount_dev_core` splits `osd_memory_target` per device shard.
- Device qpair depth default 256 (`nvme::any::set_queue_depth`, bench `--qdepth`).
- Counters `wal_hw_pct_max`, `ring_full` (perf dump); `prepare|mkfs --wal-mib N` overrides the per-shard ring (lab A/B). Any non-zero `ring_full` / `ckpt_forced` in production = ring too small for that workload.
- Margin rule: smallest clean total tested 0.5 GiB, shipped 4 GiB. Revisit when drives > 7 GB/s write bandwidth are qualified.

D2. Shared per-core ring over many shards: NOT built (increment over D1: 0 at 8 cores, +7 % at 4, +10 % at 2). Reopen on any trigger: (a) > 8 or non-power-of-two cores per OSD needed, (b) <= 2 cores per OSD on fast drives, (c) measured per-shard FIFO / ack head-of-line problem more shards would fix. Design: history file.

D3. Direct op -> store txn translation.
- Built: replica/all `ApplyTxn*` stream-decode straight into TOps (`replwire::OpStream`, `storeadapt::apply`; `Transaction::decode` built on it). Malformed input refused before anything is logged (adr 0066). The old decode-then-translate path lives only in `storeadapt/src/apply_tests.rs` as oracle (random txns, same TOps/hints/errors).
- Local apply goes through `translate_txn` / `ApplyTxnSplit` (`store::obj::OTxn` TOps); the primary's own blob is the plain v9 blob (skeleton only for >= 64 KiB payloads).
- NOT built: primary `StoreOp::ApplyOps` and ecback-emitted local TOps (bound <= ~0.1 us per txn). Reopen only for size-1 pools.
- EC without `_loghead` read-back: `StoreOp::LogHeadIs(head, crt, rit)` hint pushed by `ec_append_log` (skipped while `head_stale`); Translator uses it when it has not read/written the head in this txn; debug builds compare with the stored value.
- Lazy PG info for legacy EC (adr 0021 am. 27 rules, store bit `FEAT_LAZY_PGINFO`): EC write / sub-write / roll-forward on a `!opt` PG that is applied, nothing missing, history as persisted, sets `info_adv` (or nothing) instead of `info_dirty`; `_loghead` still written; `PersistedPg::normalize` rebuilds at load. Mode O stays eager; trims stay eager (`ec_trim_log_to` sets `info_dirty`). Lazy-capable kinds: `LocalWrite`, `RepOpReply`, `EcWriteReply`, `Pending::EcRollForward`.
- Adaptive EC idle roll-forward: `ec_idle_rollforward` defers the dummy round when the PG's client write gap EWMA (1/8, gaps capped 1 s) satisfies `2 * gap <= ec_rollforward_defer_us` (default 20000; 0 = classic immediate). The gap is sampled at `ec_submit_write`; the classic trigger is `pct > crt` (pipeline idle), `pg_committed_to` on any sub-write rolls classic shards forward. Deadline = idle start + 2 gaps (`ep.rf_due`, read by `ec_next_deadline` only while idle); a write meanwhile carries `pct` (`rf_piggy`), an expired deadline sends the dummy (`rf_dummies`). Sparse writes keep the immediate dummy. Wire unchanged; mode O `pending_rf` members keep state until the next dummy.

D4. Tree apply batching per WAL unit: REJECTED. Deferred visibility conflicts with read-your-writes of staging/opexec (the pending overlay of adr 0021 am. 28, removed). Unit bookkeeping amortization comes from D1.

D5. Decoded object-state cache (read cache, never write cache), per PG engine (opexec `objcache.rs`), default on (`flashstore_obj_cache`).
- Key head `Hobject`, value decoded `ObjState` (object_info, snapset). Two-generation map (`new`/`old`, cap/2 each, swap when `new` is full; no per-entry bookkeeping, no allocation after warm-up).
- Size from the memory budget (`osd_memory_target - osd_memory_base`, adr 0062): split per store cache unit (`osd::nvmestore::split_cache_budget`), 16384 heads x `OBJ_HEAD_BYTES` (677 B) per unit; per PG = share / the PGs this OSD hosts (all cores, primary and replica: the OSD-wide count the control core sums every tick and broadcasts on change, the same count as the PG log target, pglog.md 6.3; 0 counts as 1), so the caches of all hosted PGs stay within the share at every PG count; a count change re-sizes every core's per-PG cap (rare: PG create/remove/split/merge; the power-of-two rounding below changes the cap only at count thresholds a factor of 2 apart; a lower cap drops the PG's cache on its next op, a higher one clears it); each table half, rounded down to a power-of-two bucket count, filled to 7/8 (`obj_cache_cap`). No budget (dev/tests): the share of the default target.
- Filled on a `load_state` miss and write-through at `idle` (post-write state). EC pools excluded.
- Validity = PG object-state generation (`peering::Pg::obj_gen`, process-unique): bumped when a txn that may touch objects (`StoreOp::touches_objects`) and is not the replicated client write path (`own_txn_next`) is queued AND when it commits; a new generation drops the PG's whole cache. Covers recovery, rollback, snap trim, scrub repair, split/merge, PG removal, backfill. A write chain started under an older generation is not cached at idle; trim steps and cut undo drop the head. Debug builds verify every hit (`verify_hit`).
- `flashstore_obj_cache=false` is an operator knob, not an A/B switch.

Read path (after D5):
- Direct run (opexec `retry_inner`): a parked replicated read whose named cause (prefetch batch) the wake hits runs without a second gate probe. A non-blocking read of a range whose prefetch is in flight returns WouldBlock naming that batch. Writes and EC keep the probe.
- `Engine::skip_wake`: a store wake skips PGs whose parked ops all wait on named causes the wake misses (no all-wake, no parked objects, no live backoffs, admission unchanged).
- Counters (debug prio): `gate_probe`, `gate_skip`, `gate_direct`; knet `idle_sleeps`, `idle_sleep_ns`, `mesh_wakes`, `mesh_wake_ns`.

Plain-overwrite executor and log index:
- opexec `fast::overwrite`: one `write` onto an existing non-whiteout object with stored snapset, no clones, empty client snaps, snap_seq <= object seq, no truncate_seq, no RETURNVEC/ORDERSNAP, pool not full, store has room, no pool-snap mode. Same `Outcome` as the general `Exec` (same log entry, txn bytes, state). Anything else falls through (`Counters::fast_writes`). Test `tests/fast_overwrite.rs` compares both paths on replicated and EC mocks.
- `IndexedLog.objects` (debug builds assert `existing_version` against it) is `HashMap<Hobject, (Eversion, deleted)>`; `IndexedLog::trim_ex` gallops from the front.

## Rationale

Measured on the test VM (history file): one WAL per core raises the 4K write ceiling +21..32 % at QD32, cuts wr cmds/txn to 1.02-1.15, lowers store CPU/op 14-20 %, and does not worsen 4K tail under 4 MiB traffic. D2 adds nothing at 8 cores. D3-D5 and the executor changes reduce QD1 CPU; each was gated by A/B. Rejected optimizations were measured within noise or coupling cost > gain.

## Consequences

+ 4K write ceiling and device cmds/txn near raw at depth; one ring per core, simple routing.
+ Read CPU -7..15 % (D5, direct run, skip_wake); write CPU -1.5..3 % (fast overwrite).
- Per-shard FIFO / ack stream shared by all PGs of a core; checkpoint per shard is larger.
- 1 core with S=1: QD1 -6 % IOPS and single-shard checkpoint p99.9 stall (OQ 36).
- D5: a stale entry = wrong object_info served/written (corruption class); mitigated by coarse per-PG invalidation, verify-on-hit in debug, mutation-checked hooks, model test (opexec `tests/objcache.rs`, peering `obj_gen_tests`, osd `xcore_tests`).
- Cores != shards is warned, not refused.

## Alternatives

- Inline small data in the WAL: every byte written twice on a bandwidth-bound device.
- Sub-4 KiB WAL LBA format: FTL read-modify-write on most drives.
- Tree apply batching with deferred visibility (D4).
- D2 now: same gain as D1 at 8 cores, large durability surface.
- Per-shard pooling of txn containers / key-value buffers: bookkeeping cost equals saved mimalloc fast path (op-cpu-gate noise to +1 %).
- Cross-txn onode cache next to D5: cacheable part <= ~0.7 % CPU and a second invalidation site.
- `probe_path` leaf handover to `State::apply`: gain <= ~1 %, couples admission to apply.
- knet idle linger (spin / adaptive): QD1 +12..17 % CPU/op, violates never-worse-than-BlueStore; code removed, counters kept.
- Further per-site allocation removal: flat profile, 1-3 allocs per site.

## Open questions

- Remaining QD1 CPU gap to the < 10 / < 5 us targets (staging ~1.6 us, tree apply ~1.5 us per node; one descent per key per txn, fewer staging copies). Not tracked in 90-open-questions.md before; status of "encode the record directly into the open unit payload" (old step 5) is unverified against code.
- icelake-6330/rented A/B rep3 4K QD16/32 per client of D1 with real OSD traffic; 1-core single-shard checkpoint tail (OQ 36).
- EC `LogAppendKeep`/`LogCursors` and Translator pg-log small allocations: follow-ups with a measured basis, unscheduled.

## Amendment map

Consolidated 2026-10-19; see top line for the pre-consolidation sha.
- am. 1 (2026-10-15): D3 measured, replica streaming decode -> D3
- am. 2 (2026-10-15): EC without `_loghead` read-back, lazy info -> D3
- am. 3 (2026-10-15): adaptive EC idle roll-forward -> D3
- am. 4 (2026-10-17): WAL budget 32 -> 4 GiB -> D1
- am. 5 (2026-10-18): read path, skip_wake, linger rejected -> Read path, Alternatives
- am. 6 (2026-10-18): allocation pooling etc. rejected -> Alternatives
- am. 7 (2026-10-18): plain-overwrite executor, log index -> Plain-overwrite executor
- am. 8 (2026-11-03): the shards' data writes of one device enter it in arrival order through one window; the shard queue depth no longer partitions the device -> adr 0643-device-admission-fifo
- am. 9 (2026-11-08): object-state cache per PG = share / hosted PG count instead of share / `mon_max_pg_per_osd`. The mon option is a placement limit (default 250 -> 500 in v21.2.0) and silently halved every PG's cache at typical 100-200 PGs; the total bound now holds at every count, also above the mon limit (up to the hard ratio during remaps). Alternatives: one OSD-wide cache (cross-core state on the hot path, adr 0006); per-core share / core's PGs (no cross-core count, but uneven core PG counts waste the share); a fixed per-PG cap (no total bound). Count lag: a PG created on another core counts from the next tick, so the bound can be exceeded by the new PGs' caches for <= one tick (they start empty). Measured: doc/perf/adr-0160-history.md (am. 9) -> D5
