# 0021 Storage engine: COW extents + redo WAL + COW B+tree per shard

Status: accepted, amended (am. 70-84; 0491 amends S8)
Date: 2026-10-09
Consolidated 2026-10-22 (second pass; first 2026-10-19); full pre-consolidation text: `git show 811a93946:doc/adr/0021-storage-engine.md`
History (measurements, incidents, rejected variants per amendment) and the full per-section rule text with constants (Part B, "B-Sn"): doc/perf/adr-0021-history.md
Basis: doc/design/storage-engine.md (architecture C; A in-place+WAL and B log-structured rejected there).
Section ids S1..S16 are stable anchors (code/docs cite "adr 0021 Sn" and "adr 0021 am. N"); the map at the end resolves every amendment.

## Context

croit-flashstore-osd needs a store for NVMe-only OSDs: crash-safe on PLP media (adr 0008), ack only when durable, thread-per-core without locks (adr 0006), wire-compatible with classic OSDs. It carries RBD (4 MiB objects, snapshots) and the omap/xattr/cls load of RGW and CephFS (billions of keys, 4 KiB values, long keys), and must not need more space, CPU or latency than BlueStore on the same hardware. Format changes are free (prototype: every deploy is a fresh mkfs, no in-place upgrade).

## Decision

Constants, option names, counters, mechanisms: history doc B-Sn.

### S1 Layout, shards, ownership
- Device = S shards (mkfs `store_shards`, `auto` = one per OSD core, adr 0160); PG -> shard `(pool + pg_seed) mod S`; core i of n mounts shards {i, i+n, ..}, shard 0 = meta collection = core 0; a foreign-shard op fails `NotMounted`. No cross-shard locks.
- Per shard: WAL ring, meta area, data region, A/B root slots, own allocator. One COW B+tree per shard holds everything (collections, onodes, xattrs, extent maps with per-4k crc32c, omap, pg log/info, refcounts, allocator bitmap chunks). Omap sits behind a KV seam.
- Data is never overwritten in place and never journaled (except inline data, S9): fresh 4k-aligned extents. Clones are metadata only (S10). Correctness never depends on NVMe atomic writes > 1 LBA. One object lives in one shard (S14 relaxes the capacity bound).

### S2 WAL, commit, replay
- Redo WAL ring per shard; units hold records of several txns and are validated/acked atomically; larger txns use PART/END chains (adr 0028).
- Parallel commit: data extents and the WAL unit go out concurrently; the record carries crc32c of every new data block. Ack strictly in LSN order, only when data, WAL and all earlier txns are durable. An idle WAL (no unit in flight or ready) seals where the device issues IO: in `submit` if it issues at submit (SPDK; QD1, am. 8), else at the end of the core loop's pass (`end_pass`, before the kernel tier's ring flush: one unit per pass, am. 67); otherwise the open unit seals at the end of the shard's `poll` or pass (group commit) when fewer than `wal_coalesce` K (default 1) units are in flight, or when its last block cannot take another txn of the unit's average size (am. 66). Every checkpoint, idle ones too, releases the PAD units at the released ring end.
- Mount = best root slot + replay after `ckpt_lsn`, validating data crcs; a bad data block ends the log only at a torn tail.
- Torn tail vs lost acked unit: each unit header carries `acked_lsn` (crc-covered); after the chain ends, replay scans `scan_blocks` ring blocks for a unit of this store (`store_id`, epoch >= root's) with `E <= acked_lsn < first_lsn`. Found = `WalLost`, mount fails, the OSD never boots, replicas recover it (size 1 = operator decision); not found = torn tail. A mount persists its new epoch first: a newer-epoch chain unit (lost root slot) refuses the mount.
- `--accept-wal-loss` (OSD, `croit-flashstore-tool fsck`) mounts at the last good lsn with a CRITICAL line; skipping a bad record and replaying later ones is wrong. Residual, accepted (am. 84): corrupt data of the newest acked units with nothing after them replays as torn tail (logged, no alert); durable data is the device's job (adr 0008).

### S3 Allocator
- Freed blocks stay held until a CHECKPOINT passed the freeing record (replay would misread a reused block as torn); reader epochs pin blocks (adr 0043); `alloc` answers Busy + forced checkpoint before NoSpace while blocks are held.
- Bitmap chunks enter the tree only at checkpoint freeze. RAM ~67 MiB/TB, no hot-path allocation. Shard extents (expand, chunks) are one bit index; runs never span extents.
- Hole-first (`keep_windows`): near the last whole free 1 MiB windows, short runs fill holes of partly used windows before next-fit breaks one (elastic meta only).

### S4 Space, reserves, NoSpace
- Three tiers per shard (data and meta): user floor F (1.5 x `data_reserve_pct`, 2 %), sys txns stop at F/3, pure shrinks (Remove, RmColl, Truncate, Zero, RmAttr(s), omap removals) use everything. sys class = PG state, osdmaps, superblock, identity, every PG txn of the adapter, freeing txns.
- NoSpace is an admission decision: `Store::write_room` (data + meta incl. growable pages, parked txns charged, omap/xattr entries counted); no room = plain -ENOSPC before any log entry for every may_write op that is not pure shrink, also with FULL_TRY/FULL_FORCE. A cls call's writes are only known after it ran: its planned txn (bytes, entries) passes the same check after execution, no room = the same -ENOSPC, nothing applied (am. 71). Primary `local_failsafe()` (max(osd_failsafe_full_ratio, full_ratio)) drops client writes without FULL_TRY except pure shrink. Replica writes / EC sub-writes pass `apply_room` (same model, sys floors): no room = held unacked, never forced, applied after store progress (am. 71). Pure shrink (floor 0) also covers a PG delete with its bounded pgmeta log/info write and the removal marker (`OTxn::frees`) (am. 71). NoSpace reaching a PG persist = fatal `store_failed` (adr 0066).
- statfs = real device usage (pool free counted once, by the owner), but at least the fullest shard's fill; a pooled shard's fill = its usage vs its capacity + the free pool and the other shards' spare it can still get (am. 71, 72, N?): full only when neither is left; fullness checked every tick, sent at once on change, `fresh_nonce()` as messenger nonce. Near full (`space_ckpt`): a checkpoint starts when free space above the floor < 2 x acked frees awaiting one.
- Recovery from full: idle checkpoints give back empty meta cells (also while growth is blocked). PG deletion at NoSpace never fails start or re-create (`resume_removals`, `step_removals`; `CreatePg` behind a queued deletion waits in `deferred`); split/merge keep fail-stop. Txn page estimates count only pages a txn can dirty.

### S5 B+tree and cache
- 8 KiB pages (`node_size`), per-page key prefix, shortest separators; interiors compact (`FEAT_COMPACT_INT`: front-coded runs, 5-byte child addresses, < 2 PiB), format-0 interiors convert lazily; in-place edits, a removal never grows a page; `page::validate`.
- Limits: `max_entry` psz/2-256, user omap/xattr key <= 3308 B, xattr names <= 100; a page plus one entry always splits 2-way with both halves fitting. Leaf split at the end of a key run for append patterns (pg log, dup, index).
- Cache `cache_pages` per shard from the process memory budget (adr 0175), `dirty_soft` pages/8, `dirty_hard` 3/8; CLOCK, interiors resident, loaded pages protected. Listing cursors set no reference bit and cache leaves in a scan queue evicted first (am. 63): a cold listing leaves the point working set resident.
- Hot point-key cache `State::pc` fed from the applied record stream only (live + replay); locate hints, one-descent `scan_pred`; a txn's apply puts/deletes at the leaves its probe located (one walk per key per txn, am. 64). A read whose page is freed before completion is dropped or marked stale.

### S6 Tree maintenance
- Range delete `[a, b)` descends only into pages holding `a` or the keys right below `b`; the rest of the range is dropped whole, so a probed record never misses (am. 83, OQ 133). Lazy subtree free (`FEAT_LAZY_FREE`): covered non-resident interiors go to the durable dead list (`DEA1`), drained in the background. Admission answers Busy while the list is over `DEAD_SOFT`.
- Leaf deltas (`FEAT_LEAF_DELTA`): a leaf with a small net change is written as an entry in a shared DELTA page; chains apply only when (addr, crc) match, directory `DEL1`; bounded by `delta_cap_bytes`, `fold_budget`, `ckpt_delta_leaves` (default 0 = unbounded). Segment cleaning (`FEAT_DELTA_RELOG`, am. 65): while the segments exceed `delta_max_pages` minus the freeze's own delta pages, the chains holding the oldest segment are copied into the freeze's segment (first entry restart-flagged) and that segment is freed with the checkpoint; the fold (oldest first) is the backstop and frees the RAM cap for hot leaves (dirty in consecutive freezes) the last freeze declined (am. 74). `delta_max_pages` = min(4 x `delta_cap_bytes`, 1/16 of the meta pages plus the pages elastic growth can still take, am. 66).
- Underfull leaf merge (`leaf_merge`, merges only with a resident sibling, never reads), background compaction (`bg_compact`), free-space defrag (`defrag`, parallel-commit moves, shared extents never move) and cell sweep (`defrag_cells`) run bounded and paced under client IO. Given-up victims (windows, chunks) wait for a freed pinning block, no timer (am. 79).
- Drains (cell sweep, evacuation; am. 70) end by victim state, no deadline: an allocated block left after the moves pins them (given up at once); held blocks: the drain asks for the checkpoint past the newest victim free, also under client IO. Detection: `defrag_drain*` gauges (history am. 70).

### S7 Checkpoint
- Triggers: WAL ring 50 %, 5 s after the last checkpoint while something is unpersisted (idle restarts the clock; the first after a mount or idle stretch waits one interval plus the shard's identity phase: fsid-derived OSD offset + shard/shards of the interval, mod interval; no lockstep across shards or OSDs, am. 75), `dirty_soft`, space (S4) and idle triggers. Above `dirty_hard` txns get Busy and a checkpoint is forced, checked first in `Shard::validate` (refused txns cost no work per retry, am. 62). Root slot A/B written after all pages; ring release, frees and cell give-back only after the root is durable.
- Sliced checkpoint (am. 80): start (delta folds, stale bitmap chunks; begin: housekeeping, last chunks), freeze (each page as of `lsn`: barrier `fz_touch`; leaf at once, interior copied as `Shadow`), end (address fix, unalias, relog); no device write before the end, txns go on. Pacing: `ckpt_slice` units/poll, deadline `ckpt_fz_polls` (start: fixed).
- Checkpoint writes: at most one largest device write of checkpoint bytes in flight (at least one write). Background checkpoints share that budget per device, whichever shard (adr 0533 table), so a WAL write of any shard queues behind at most one bulk write (the kernel tier has no per-IO priority); a checkpoint a caller waits on (refused admission, request, mount replay) keeps its own budget and never depends on another shard's poll (am. 76).
- Freeze page images in fixed chunks (largest device write) reused by every checkpoint, kept up to the `dirty_soft` share + 1 chunk (am. 71); a write job never crosses a chunk (am. 68). A clean shutdown checkpoints every store (am. 71). A leaf's delta entry enters the freeze's segment and the chains when it settles; the freeze end only relogs and seals.
- Background (idle) omap merges stop at `dirty_soft`; pressed merges run to `dirty_hard` (am. 68, adr 0476 am. 7).
- Back-pressure counters per core in `perf dump` logger `flashstore_store_<core>` (list: B-S7); alarm = `dirty_pages` near `dirty_hard` with `busy_dirty_hard` growing.

### S8 Non-blocking reads and parking (no PG core ever spins on a tree page)
- Probe-and-park: `Store::warm` walks the pages an op reads non-blocking; the engine probes every object op and parks cold ops at the PG gate (strict per-PG FIFO); `take_wake` -> `retry`. Primary gate probes `_` only (not `snapset`). Executor passes are non-blocking: a cold page refuses the pass (plan only; omap get by keys queues all cold keys, am. 81), the op re-runs after loads; after `MAX_SCAN_TRIES` refused passes without progress it runs blocking. Blocking by design: write-path staging beyond the probe, scrub, recovery reads.
- Listings never block or hog the core (am. 63): omap listings keep progress in a per-shard scan memo keyed by the read session and scan parameters; cold leaf or CPU slice (`SCAN_SLICE_*`) ends the pass with `WouldBlock`, the next run continues at the stopped key (same reply as an uninterrupted run); memo dropped at request end, on any staged op of the object, or idle TTL. Rolling read-ahead per listing; a slice names its own wake token. Progress refusals never count against `MAX_SCAN_TRIES`. 0491: the memo holds the reply-encoded buffer written straight from the leaves.
- PGLS/PGNLS (+ filters, SCRUBLS) run non-blocking with a resumable run; object listings list at most one slice and wait only for txns parked when they first listed (`list_barrier`).
- The PG core never waits for the store (am. 77): a big write's size pre-flight (`check_write` -> `Store::check_txn`) runs non-blocking; a cold page submits its load and refuses the write (`WriteErr::Blocked`, nothing logged/sent/applied) until the wake; no run-room wait (sizes the tree path). No txn waits for a superblock write (`FEAT_LOG_DUPS` at mount, S15). Open: lazy compression bit (adr 0059), dedup gate (adr 0593).
- Gate order: a message waits behind a gated message of the same object unless both are pure reads (any sessions, adr 0043 am. 21); writes keep order. Removal gate `warm_rm`. Parked-txn lookahead (`park_lookahead`) loads pages of the next parked txns; replica repops with cold pages wait in `Pg::held` (bounds as S11).

### S9 Object layer
- Keys by onode id; name index tag `N` (+ `L`); per-object flags are "may exist" except `F_INLINE`/`F_OCNT`.
- Inline data (`FEAT_INLINE_DATA`, `inline_max` 2048): small objects without extents keep data as the value of key `d`+id (= block 0); one WAL write is the whole commit.
- No per-object omap counters (`FEAT_OMAP_UNCOUNTED`, adr 0647-omap-blind-removals): removals are blind, omap usage comes from deep scrub (adr 0614); onode format 2 / counter slots of earlier builds are read and ignored, their `c` records removed at mount.
- Long names (`FEAT_LONG_NAME`): names whose `N` key exceeds `max_key` live in the `L` index, a pure function of name and page size; classic name limits kept. A primary accepts a write needing `L` only if every up+acting member advertises `flashstore_long_names`; a replica that still gets one exits `EXIT_REFUSED` (3).
- External values (`FEAT_EXT_VALUE`, `val_ext_min` 2048..64 KiB): omap/xattr/header values as one data-block run with per-block crc, parallel commit.
- Omap value compression (`FEAT_VAL_COMP`, am. 59): zstd with trained 1 KiB dictionaries per value class, stored immutable as `Z`+class; only counted objects' omap values 64 B..`val_ext_min` that save >= 1/8; xattrs and pg logs excluded. Training (am. 69): zstd's default trainer (fastCover d 8, 4 k steps) with the hash table sized to the samples (4 slots per sample byte, <= 2^20).

### S10 Clones and refcounts
- Clone references the source's blocks (`FEAT_SHARED_EXT`, `shared_clone`): `e` records flagged `EXT_SHARED`, refcount runs `r` (owners >= 2, absent = 1, runs <= 64); overwrite/zero/truncate/remove free through the count; sources with dirty runs, inline or > 1024 runs are copied.
- `clone_range` shares the block-aligned middle when offsets agree mod 4 KiB (`shared_range`): the EC legacy stash costs metadata only. `shared_clone=false` disables both.
- Compressed chunks share whole; export, push, backfill and migrate read logical bytes. fsck: owners == records, bitmap == union. Defrag and evacuation never move shared extents (OQ 59).

### S11 Omap range removal, held repops
- `OmapRmKeyRange` stages one range delete, no count (adr 0647-omap-blind-removals); its commit probes the boundary leaves like any txn (S8).
- Replica: `Pg::on_repop` probes cold pages; a cold repop = nothing logged/applied/acked, it sits in `Pg::held` (adr 0636) and later replica data-path messages of the PG queue behind it (`held_behind`; notify/query/log/remove/leases pass); replay after a store wake. It waits for load completions only, no apply/ack by time; held > 30 s = `WARNING TIMEOUT` + slow op. EC sub-writes and the EC primary's own-shard prefetch wait alike. `REPOP_WAIT_*` forces; a new interval clears it.

### S12 PG layer on the store
- Lazy PG info (`FEAT_LAZY_PGINFO`): a replicated client write whose only info change is log progress writes entries with `LogAppendFast` and no `PutInfo`; every other txn, trim and history change writes `_info`; `meta::load` normalizes. EC never uses it.
- `IndexedLog::dup_idx`; `LogTrim` reads nothing per trim and drops dups as one range; unchanged `snapset` is not re-set.
- Recovery/backfill: push chunking by omap entries/bytes, `recovery_info` from `omap_stats`, heavy objects get a backfill batch of their own. Deep scrub streams omap digests in 1024-key batches with a per-PG park slot, honours the large-omap thresholds; an EC scrub chunk waits for queued EC writes of its range.

### S13 Elastic meta space
- Tree pages live in the base area plus CELLS (~1 MiB runs, `cell_pages`) taken from the data allocator on demand (`FEAT_ELASTIC_META`); fixed-region formats are test-only.
- Grow in admission (sys txns too; a checkpoint grows itself when replayed state needs it); also while a sliced freeze runs (the reserved cell joins the meta space at its end, am. 68); a miss that pending frees (>= 1 cell) cure waits for the next checkpoint (requested, not meta-bound, am. 78), else or right after a wait sets `meta_blocked` (statfs charges the stricter fill, no cell given back). Shrink at checkpoint start gives back empty cells beyond `meta_slack_cells` (never free data) and the meta peak (max need of 2 cycles; 0 when idle, on a data alloc miss or deferred growth; am. 80); blocks leave `held` after the root is durable.
- Image (bitmap + cell table in BLOB pages, sections `DEA1`, `DEL1`) verified at mount; fsck counts it. Mount of a crash anywhere on a meta-bound shard must not fail.

### S14 Elastic shard capacity (chunked store, production default)
- `FEAT_CHUNKED` (cargo `elastic`, default in `croit-flashstore-osd`/`croit-flashstore-tool`): data region = 1 GiB chunks; `store_base_pct` (prod 25) of a shard's data space is its base; the pool is the unowned tail of every region (devices < 256 GiB plain).
- Device-wide lending table (A/B copies per block, higher valid seq wins): grant = table durable first, then the chunk enters the allocator; return only when no block is allocated/reserved/held. Allocation: base first (closes below 5 % free), then borrowed space.
- Requests go through the pool owner (core 0) via `XMsg::Pool` (exactly once by construction); `lend_auto` default on in the daemon; `Deny` closes the pool for `lend_retry_ms`. The owner sends every shard its view (`Size`: free pool, the other shards' spare, its return target) after mount and on change (am. 72): fullness and room checks see the true pool, never the mount placeholder. No per-shard borrow limit.
- Reclaim (am. 61, on demand am. 82): an empty borrowed chunk goes back while the shard keeps `reclaim_keep` (floor + wm + hyst, whole free windows). Live data moves only for a waiting shard: a `short` request meeting a dry pool waits (txn parked, S4) while another shard reports `Spare` (chunks it could empty, moves into holes); the owner asks returns (`Size` target), denies waiters nobody can serve. Guarantee: a shard reaches the fresh-device level minus the others' headroom; not covered: shared extents, ext values, non-empty cells (OQ 59).

### S15 mkfs, format, features, expand
- Superblock `FORMAT_VERSION` 1 + feature bits; a mount refuses another version or an unknown bit; the daemon refuses a store missing a bit of `FEATURES_REQUIRED` ("re-mkfs"). No in-place upgrade (supersedes am. 22); mounts add the sticky bits `FEAT_LOG_DUPS` (adr 0634, am. 77) `FEAT_OMAP_UNCOUNTED` and `FEAT_OMAP_TOMBS` (adr 0647-omap-blind-removals), all copies durable before the store takes a txn; `heal_super` rewrites a differing copy; the daemon opens its device exclusively. Boot metadata `flashstore_store_features`.
- mkfs wipes everything replay reads (superblocks, WAL rings, directory + roots, superblock copies last): a crash leaves "not formatted", never a mix. Production layout (>= 256 GiB): 64 MiB alignment, capped base meta, WAL min(4 GiB, device/64) (adr 0160 am. 4).
- Expand (`FEAT_EXPAND`, offline `croit-flashstore-tool expand`): extra data extents per shard; never shrinks; refused on chunked stores. Online expand not done.

### S16 Tools, config, observability
- `croit-flashstore-tool`: `fsck [--deep]`, `repair`, `sizes`, `expand`, `free`, `bench*`, all with `--format plain|json|json-pretty`; online `bluestore allocator ...` tell commands kept for scripts.
- `croit-flashstore-osd run --set k=v` merges into the conf map (CLI > `--set` > conf > mon db); unknown keys exit 3, valid unused Ceph options are listed as `ignored_options` in `status`. Store keys `flashstore_store_*` are read once at start; per-request limits follow Ceph options. Kill switches that remain: `leaf_merge`, `bg_compact`, `defrag`, `space_ckpt`, `shared_*`; test knobs behind `test-knobs`, lab counters behind feature `lab`.

## Rationale

- One structure for data, metadata, omap and PG state; no double write of data; shard = unit of core ownership and recovery, so no locks; parallel commit gives one device latency per ack.
- Held-until-checkpoint frees and the acked-lsn witness exist because replay validates data crcs and must tell a torn tail from rot in the acked region.
- NoSpace is an admission decision, because fail-stop of a PG on a full replica repeats at every restart.
- Probe-and-park, non-blocking passes and count-ahead keep one cold page or one huge delete from stalling every PG of a core.
- Elastic meta and shard capacity remove static splits that stranded 30-90 % of a device. Accepted: freed space lags <= one checkpoint; PG log in the tree costs more store CPU.

## Consequences

- + Ack = data + WAL durable; validated by fault-injecting simulated devices, crash matrices (every IO boundary x 3 policies) + fsck, lab power-cut tests.
- + Snapshots, EC stash and removals cost metadata only; huge omap objects delete in O(1) pages; space at parity or below BlueStore; omap values compress.
- - Every format change means mkfs; unknown bits refuse mount (no downgrade).
- - One object is bounded by its shard share unless the pool is on; pinned chunks strand pool space (OQ 59).
- - Interior/delta pages cost RAM; checkpoint begin and freeze blob stay single pieces; write-path staging, scrub and recovery reads still block on cold pages (OQ 76).

## Alternatives

- A in-place + WAL, B log-structured (design doc); WAL record inline data; one WAL per core (OQ 36); skipping bad WAL records; superblock-id check instead of mkfs zeroing.
- Per-object omap subtree/root, per-subtree counts, approximate counters; LSM for omap (seam stays); B-epsilon buffers; page compression; per-leaf front coding; LZ4 + template values (zstd dictionaries chosen).
- Long-key overflow, bigger nodes, rekeying (`L` index chosen); tree pages from the data allocator (cells chosen); lending by WAL records (A/B table chosen).
- Deferred tree apply of PG metadata, fill-fraction checkpoint trigger, adaptive freeze budget, staged-key arena, `snapset` probe in the gate (lost the QD16 A/B): measured and dropped (history).

## Open questions

- OQ 27: store CPU per replicated 4k write (-20 % needs one descent per key, fewer staging copies).
- OQ 36: 4K write bytes per txn at low per-shard depth (WAL ring per core).
- OQ 40: real-NVMe A/B of omap 4K stop-go after fill + purge (am. 48 fix is sim-proven).
- OQ 59: elastic reclaim residue (shared extents, ext values, non-empty meta cells pin borrowed chunks).
- OQ 76: write-path tree staging blocks on cold pages beyond `warm` (pgmeta log head leaf); needs a PG-layer probe of the next log key.
- OQ 97 / OQ 103 (am. 62, adr 0476): big-object omap populate (R1) per-key cost vs BlueStore, gap to close (user 2026-10-21); numbers: doc/perf/omap-{populate-20261020,runs-compaction-20261023,1obj-tail-20261024}.md.

## Amendment map

Format: `am. N (date): topic -> section | superseded by | removed`. "H" = only history in doc/perf/adr-0021-history.md.

am. 1-83 and REVIEW am. 12-15, 17-19, 21-23 (2026-10-09..11-06): map lines in doc/perf/adr-0021-history.md (Amendment map am. 1-23, 24-43, 44-55, 56-63, 64-71, 72-83)
am. 84 (2026-11-07): S2 residual accepted -> S2, H
adr 0491 (2026-10-22, own ADR, amends S8): omap listing replies encoded from the leaves -> S8
adr 0647-omap-blind-removals (2026-11-04, own ADR): no omap counters, blind removals, removal runs -> S8, S9, S11, S15
