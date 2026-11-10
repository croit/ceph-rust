# 0058 pool snapshots (rados mksnap / rmsnap) on replicated pools
Status: accepted
Date: 2026-10-11
Context: adr/0013 scoped RBD/self-managed snaps only; `rados mksnap/rmsnap/lssnap/rollback` and old tooling use POOL_SNAPS mode (flag 14): the mon owns snap ids (`pool.snaps`, `snap_seq`), the OSD must apply the POOL's snap context to writes. Trimming of removed pool snaps was already wire-identical (adr 0037: rmsnap erases from `pool.snaps` AND queues the id in `removed_snaps_queue`).
Decision:
1. Engine: `Env::pool_snapc()` (None unless the pool has POOL_SNAPS) = `(pool.snap_seq, pool.snaps keys descending)` read from the current map on every write (no cache: pool-snap pools are rare, building the vec is O(#snaps)). A mutating message without ENFORCE_SNAPC uses it; the client's `(snap_seq, snaps)` is ignored entirely (not validated, not filtered; classic validates the effective context, which is valid by construction). ENFORCE_SNAPC -> client path unchanged (validate, drop removed/trimming snaps). ORDERSNAP compares the effective seq.
2. Reads at a pool snap id, list-snaps, rollback, clone-on-write, trimming: unchanged (snap ids are just ids).
3. No peering/on-disk change; mon behaviour (`osd pool mksnap`) is the mon's.
Consequences: + `rados mksnap/rollback/lssnap -s` work on all-croit-flashstore-osd and mixed clusters; + 20 lines. - no per-epoch cache (classic caches the snapc per PG per map); revisit only if a pool-snap pool becomes write-hot.
Tests: opexec/tests/poolsnap.rs, osd xcore_tests `pool_snapshot_clones_come_from_the_map` (map-driven mksnap, read at snap, rmsnap, trimmer).
Alternatives: cache snapc in the engine keyed by epoch (rejected: KISS); validate the client snapc even in pool mode (rejected: differs from classic).
