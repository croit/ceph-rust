// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Shard engine (M2.1 + M2.2 + M2.3): group-committed WAL with PARALLEL commit, COW B+tree state, paced
//! incremental checkpoints, bitmap allocator.
//!
//! A txn = optional new data blocks + one WAL record (KV ops, per-block crc32c + LBAs of the new data, frees).
//! `submit` applies the record to the in-memory tree/allocator (visible immediately), sends the data writes to
//! the device and appends the record to the open WAL unit; the unit is written concurrently with (not after)
//! the data. A txn is acked in LSN order once its unit, the data writes of every txn in that unit, and all
//! earlier units are durable. Replay re-validates data crcs, so a unit whose data did not land ends the log
//! (nothing after it was acked).
//!
//! Checkpoint (design 2.6): `freeze` snapshots the dirty tree pages at LSN L (the newest sealed unit), the
//! snapshots are written to fresh meta pages (paced), then the meta bitmap, then - once the WAL is durable
//! through L - the A/B root slot. Only then the WAL ring up to L is released, superseded tree pages become
//! reusable, and blocks freed by txns <= L leave `held` (via the reader-epoch gate). Blocks freed by a txn are
//! thus reusable only after ack AND checkpoint (amendment 2): replay validates the data crcs of every record in
//! the WAL window, so those blocks must not be recycled before the record leaves the window.
//!
//! Sans-IO: `submit`/`poll(now)` only; the caller owns the loop. No locks, no threads.

use crate::BLK;

/// Only the selected foreign engine needs an immutable copy across native mount.
/// Keep unselected SplinterDB builds out of native/Rocks replay allocation work.
#[cfg(feature = "splinterdb")]
fn splinter_replay_ops(
    selected: bool,
    replay: &Option<Vec<(u64, crate::olsm::wire::OOp)>>,
) -> Option<Vec<(u64, crate::olsm::wire::OOp)>> {
    selected.then(|| replay.clone().unwrap_or_default())
}

use crate::admit::{ADM_OFF, ADM_TAGS, Admit, Stop};
use crate::alloc::MetaExtent;
use crate::codec::{Enc, blk_crc, crc};
use crate::dev::{BlockDev, Clock, Completion, IoBuf, IoError, Nanos, SubmitError};
use crate::error::{Result, StoreError};
use crate::layout::{
    FEAT_ELASTIC_META, MetaGeom, RootSlot, ShardDir, Superblock, read_meta_image_checked,
    read_root, wal_store_id,
};
use crate::runs::is_tomb;
use crate::sio::{Sio, Stall};
use crate::state::{Extent, Op, Record, State};
use crate::tree::{AddrHasher, Frozen, ScanCursor, ScanStatus, Tree, TreeCfg, Want};
use crate::trim::Trim;
use crate::wal::{
    FLAG_END, FLAG_PAD, FLAG_PART, HDR_LEN, REC_HDR_LEN, ReplayCfg, ReplayStats, RingUnit,
    UnitHeader, encode_record, replay,
};
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasherDefault;

const K_DATA: u64 = 1 << 56;
const K_WAL: u64 = 2 << 56;
const K_PAD: u64 = 3 << 56;
const K_ROOT: u64 = 4 << 56;
const K_READ: u64 = 5 << 56;
const K_CKPT: u64 = 6 << 56;
const K_PAGE: u64 = 7 << 56;
/// Deallocate of freed data blocks (adr 0642, [`crate::trim`]): one per shard in flight, its runs held until the completion.
const K_TRIM: u64 = 8 << 56;
/// Pre-write of a payload piece (adr 0477; id = slot of `pre`).
const K_PRE: u64 = 9 << 56;
const K_MASK: u64 = 0xff << 56;

#[path = "shard_olsm.rs"]
mod olsm_drv;
#[cfg(feature = "rocksdb")]
#[path = "shard_rocks.rs"]
mod rocks_drv;
#[cfg(feature = "splinterdb")]
#[path = "shard_splinter.rs"]
mod splinter_drv;
pub(crate) use olsm_drv::SioRead;
use olsm_drv::{K_OLSM, K_OREAD};
pub use olsm_drv::{LSM_RUN_PREFIX, OlsmJob, OlsmStats, T_LSM};

#[cfg(test)]
#[path = "shard_admit_tests.rs"]
mod admit_tests;
/// Group commit (adr 0021 S2): an open WAL unit of `ntxn` records in `payload` bytes is full when its last block has
/// no room for one more record of the unit's mean size: sealing it now pads less than the mean record, waiting for one
/// more record would open a block it does not fill (doc/perf/store-create-bytes-20261024.md).
fn unit_full(payload: usize, ntxn: u32) -> bool {
    let used = HDR_LEN + payload;
    let room = used.div_ceil(BLK) * BLK - used;
    ntxn > 0 && room * (ntxn as usize) < payload
}

/// Queue slots of a shard's device queue (`depth`) that data writes, checkpoint writes and page reads leave free for WAL
/// units (`units` in flight), pads and the root slot: at most half the queue, so every class still issues on a shallow
/// queue (`nvme::set_queue_depth` allows 2).
fn wal_floor(units: usize, depth: usize) -> usize {
    (2 * units + 2).min(depth / 2)
}

/// First interval checkpoint wait after a mount or an idle stretch (adr 0021 am. 75), in `[interval, 2 x interval)`:
/// one interval plus the OSD's offset (its fsid, mixed) plus `shard / shards` of the interval, modulo the interval. The shards
/// of one device start their interval checkpoints evenly spread, OSDs at independent offsets, none sooner than one interval
/// after the clock started; 0 for an interval of 0.
fn ckpt_phase(fsid: &[u8; 16], shard: u32, shards: u32, interval: Nanos) -> Nanos {
    if interval == 0 {
        return 0;
    }
    // splitmix64 finalizer over both fsid halves: any fsid bit moves the offset
    let mut h = u64::from_le_bytes(fsid[..8].try_into().unwrap())
        ^ u64::from_le_bytes(fsid[8..].try_into().unwrap()).rotate_left(29);
    h = (h ^ (h >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^= h >> 31;
    let step = u128::from(interval / u64::from(shards.max(1)));
    let off = (u128::from(h % interval) + u128::from(shard) * step) % u128::from(interval);
    interval.saturating_add(off as u64)
}

/// Detached-subtree page reads (lazy free, adr 0021 am. 18) in flight per shard.
const DEAD_INFLIGHT: usize = 4;
/// Background work (adr 0021 am. 33): steps per call while the shard is idle; gap between single steps while client IO runs.
const BG_STEPS: usize = 16;
/// Pacing period of background work under client IO (adr 0021 am. 33): one step per period; also the client-quiet gap
/// before background work runs back to back (recompaction, adr 0533; PG deletion, adr 0524 am. 1).
pub const BG_BUSY_GAP_NS: u64 = 10_000_000;
/// Candidates probed per call while idle (their reads overlap).
const BG_PROBE: usize = 16;
/// Sliced checkpoint start (adr 0021 am. 40): longest hold-back of a wanted checkpoint, in polls and ns.
const DEFER_POLLS: u32 = 1024;
const DEFER_NS: u64 = 20_000_000;
/// Largest caller token usable for `submit_read`.
pub const MAX_READ_TOKEN: u64 = (1 << 56) - 1;
/// Token bit of object-layer data prefetches: the reader pin of a completed read stays held until `read_release`.
pub const PF_TOKEN: u64 = 1 << 55;
/// Token of the shard's own omap run merge txns (adr 0476): never reported in `Event::Acked`; callers use
/// other tokens.
pub const MERGE_TOKEN: u64 = u64::MAX;
/// Most entries one run merge slice moves into the tree.
const MERGE_ENTS: usize = 4096;
/// Core time one idle-object run merge slice may take (plan + prepare + apply): sized by the learned cost per entry
/// (`Shard::mg_ps_per_ent`), so the merge interleaves with the core's message drains at sub-ms granularity instead of
/// holding the core for ms per slice (`Shard::merge_pace`).
const MERGE_SLICE_NS: u64 = 500_000;
/// Input entries a run compaction merges per poll (adr 0476 step 4).
const COMPACT_ENTS: usize = 4096;

/// Maximum foreground listing look-ahead window (target chunks per active run); shared admission stays bounded.
pub const OMAP_SCAN_PREFETCH_MAX_CHUNKS: usize = 16;

#[derive(Clone, Debug)]
pub struct ShardCfg {
    #[cfg(feature = "rocksdb")]
    pub rocksdb: Option<crate::rocks_omap::Config>,
    #[cfg(feature = "splinterdb")]
    pub splinterdb: Option<crate::splinter_omap::Config>,
    /// Max WAL unit size (header + payload) in blocks, capped by the device at mount.
    /// Larger transaction records use atomic PART/END chains (ADR 0028).
    pub max_unit_blocks: u32,
    /// Max WAL unit writes in flight (design: 16).
    pub max_inflight_units: usize,
    /// Max closed-but-not-yet-submitted units before `submit` returns Busy.
    pub ready_cap: usize,
    pub replay: ReplayCfg,
    /// Tree page cache budget in pages (per shard).
    pub cache_pages: usize,
    /// Batch foreground listing head misses and hint future run chunks (default true; adr 0644).
    ///
    /// Startup configuration, shared by kernel NVMe and SPDK:
    /// - `flashstore_omap_scan_prefetch=true`: batch misses and enable look-ahead; false selects demand-only reads.
    /// - `flashstore_omap_scan_prefetch_chunks=1`: fixed logical future chunks per active run, 1..=16.
    /// - `flashstore_omap_scan_prefetch_adaptive=true`: use the persistent shard controller (adr 0645).
    /// - `flashstore_omap_scan_prefetch_max_chunks=16`: adaptive ceiling, 1..=16; adaptive starts at one chunk.
    ///
    /// Fixed four-chunk mode: enable prefetch, set chunks to 4 and adaptive false. Adaptive mode:
    /// enable prefetch and adaptive, leave max_chunks at 16 (fixed chunks is ignored). Invalid numeric
    /// values fail configuration/mount, including when disabled. Cache/queue caps apply in both modes.
    pub omap_scan_prefetch: bool,
    /// Adapt the per-shard listing window within `omap_scan_prefetch_max_chunks`; requires scan prefetch.
    pub omap_scan_prefetch_adaptive: bool,
    /// Logical next chunks per active cursor: 1..=16, default 1. See [`Self::omap_scan_prefetch`].
    pub omap_scan_prefetch_chunks: usize,
    /// Adaptive ceiling in logical future chunks: 1..=16, default 16. See [`Self::omap_scan_prefetch`].
    pub omap_scan_prefetch_max_chunks: usize,
    /// LSM range removals whose metadata-only candidate upper bound is strictly below this use
    /// exact live-key enumeration and point tombstones. Zero keeps native range tombstones.
    /// Runtime option `flashstore_omap_delete_range_threshold`; no disk-format effect.
    pub omap_delete_range_threshold: u64,
    /// Max tree pages a single DelRange may touch.
    pub max_walk_pages: usize,
    /// Checkpoint when the WAL ring is this percent full ...
    pub ckpt_wal_pct: u32,
    /// ... or this many ns after the previous one while there is something to persist (the first one after a mount or an
    /// idle stretch one interval plus the shard's identity offset later: adr 0021 am. 75) ...
    pub ckpt_interval_ns: u64,
    /// ... or when this many tree pages are dirty.
    pub dirty_soft_pages: usize,
    /// Omap runs (adr 0476): soft size of the runs' memory; above it the shard merges runs into the tree,
    /// the object layer stops logging runs at twice this. 0 = no runs.
    pub run_soft_bytes: usize,
    /// Runs one object may hold (point reads probe each): at this count a further batch of the object waits for the
    /// compaction under way (blocking callers take the tree path); a compaction takes the newest runs then.
    pub run_max: usize,
    /// Run compaction fan-in (2..=64): the newest `run_fan` runs of an object of one size tier (entries in
    /// `[run_fan^t, run_fan^(t+1))`) are merged into one run in memory (adr 0476 step 4).
    pub run_fan: usize,
    /// Opt-in immutable run compaction on other daemon cores (standalone stores stay inline).
    pub run_helpers: bool,
    /// Run budget the shard shares with others (`None` = its own): the soft and hard sizes then apply to the pool total, a
    /// shard merges for size only while over its own soft size as well.
    pub run_pool: Option<std::sync::Arc<crate::runs::RunPool>>,
    /// `submit` returns Busy (and forces a checkpoint) above this many dirty pages.
    pub dirty_hard_pages: usize,
    /// Percent of the data region only `alloc_priv` (txns that free space) may use.
    pub data_reserve_pct: u32,
    /// Automatic checkpoint triggers (WAL fill, interval, dirty pages, ENOSPC/WalFull forcing). Tests only:
    /// `false` leaves checkpoints to explicit `request_checkpoint`.
    pub auto_ckpt: bool,
    /// Max entries of the hot point-key cache (see `state::PointCache`); 0 = off.
    pub point_cache: usize,
    /// `Store` mount: refuse a store that lacks any of `layout::FEATURES_REQUIRED` ("re-mkfs"; no in-place upgrade, every
    /// deploy is a fresh mkfs). Default `false` so format-variant tests and lab stores keep mounting; the daemon sets it.
    pub require_current: bool,
    /// Offline fsck/repair only: allow root usage/metadata counter drift; bitmaps remain authoritative.
    /// Checkpoint recomputes counters. Geometry, bitmap CRC and metadata-cell validation still apply;
    /// repair must complete the fsck ownership walk before reclaiming anything.
    pub repair_counters: bool,
    /// Offline repair mounts only (dry pass and writable): before replay, reserve the data blocks the durable state
    /// references but marks free (census of this shard, `fsck::repair_plan_shard`), so neither replay nor the
    /// post-replay checkpoint can place metadata there. The repair publishes them through ordinary txns.
    /// False-free persisted metadata-cell blocks use cell_take instead (mutable pages cannot carry WAL data CRCs),
    /// then a forced mount checkpoint publishes their bitmap chunks and metadata image atomically.
    pub repair_fence: bool,
    /// Elastic meta: free pages (in cells) kept beyond the checkpoint's own needs before an empty cell is given back,
    /// never counted as free data (`reclaim`): room for the pure shrinks that recover a full shard (adr 0021 am. 21; the
    /// deletes on a full shard grow the bitmap leaves before their frees can grow a cell). The meta peak hold (am. 80)
    /// comes on top of it.
    pub meta_slack_cells: u32,
    /// Largest object (bytes) whose data is stored inline in the tree instead of a 4 KiB block (adr 0021 am. 14); 0 = off.
    /// Capped by the page size (a quarter page) and the block size; only effective on stores with `FEAT_INLINE_DATA`.
    pub inline_max: u32,
    /// RAM the leaf delta chains may hold per shard (adr 0021 am. 19); over it the chains of the oldest delta segment are
    /// folded back into whole pages at the next checkpoint. 0 = write no deltas (existing ones are still read and drained).
    pub delta_cap_bytes: usize,
    /// Chunks (512 B) the allocator keeps pre-filled for its sparse reserved layer (adr 0021 am. 24; topped up at every
    /// `poll`); 0 = derived from the shard size (`alloc::pool_target_for`, 1/64 of the 16 MiB chunks, 16..1024).
    pub alloc_pool_chunks: usize,
    /// Clones share the source's data blocks (refcounted, adr 0021 am. 32) instead of copying them. Only on a store
    /// with `FEAT_SHARED_EXT` (mkfs); without it clones copy. false = kill switch (eager copy).
    pub shared_clone: bool,
    /// Background compaction of the sparse leaves the txn-time merge leaves (adr 0021 am. 33). Always on in prod; the
    /// defrag tests switch it off to keep their hole layouts.
    pub bg_compact: bool,
    /// Free-space defragmentation of sparse 1 MiB windows (adr 0021 am. 33); false = kill switch.
    pub defrag: bool,
    /// Cell sweep (adr 0021 am. 51): while elastic meta growth is blocked for want of a contiguous cell, defrag empties
    /// the cheapest cell-sized window group whatever its fill, splitting plain extents over small holes. Needs `defrag`.
    /// Always on in prod; the am. 51 fixtures build their blocked-meta state with it off.
    pub defrag_cells: bool,
    /// Hole-first allocation (adr 0021 am. 51): with at most this many whole free 1 MiB windows left, short data runs
    /// (<= `WIN / 8` blocks) fill holes in partly used windows before next-fit may break a whole one (kept for meta
    /// cells). Elastic meta and shards of at least 4 x this many windows only. 0 = kill switch (plain next-fit).
    pub keep_windows: u32,
    /// Size-segregated placement (adr 0475): data runs of at most this many blocks fill holes in partly used windows first
    /// (`Alloc::reserve_dense`), so next-fit keeps long free runs for large writes (16 = 64 KiB). 0 = kill switch.
    pub small_dense: u32,
    /// A prefetched data run stays in the prefetch table for `PF_RETAIN_NS` after the read it served (adr 0043 am. 5): the
    /// EC stash `clone_range` of an RMW overwrite reads the same blocks again right after the RMW read. Always on in prod;
    /// off = read-cache bypass for device-path measurements (`flashstore_store_pf_retain=false`).
    pub pf_retain: bool,
    /// Blocks the data cache may hold whatever the tree uses (adr 0633-data-cache-envelope): its floor, on top of which it
    /// borrows the unallocated tree page budget. [`crate::obj::StoreCfg::for_memory`] takes it out of the cache share (up to
    /// [`crate::obj::DATA_FLOOR_BYTES`], less when the share is small).
    pub data_floor_blocks: u64,
    /// Group commit (adr 0021 am. 37): at `poll` the open WAL unit is sealed only while fewer than this many units are in
    /// flight, or once its records fill a block; otherwise it waits for the next WAL completion (bounded: one device write)
    /// and collects the txns queued meanwhile. An idle WAL (nothing in flight) still seals at `submit` (QD1 unchanged).
    /// 0 = seal whenever one of `max_inflight_units` is free (kill switch). Default 1.
    pub wal_coalesce: usize,
    /// Most dirty leaves one checkpoint turns into deltas (adr 0021 am. 19); the rest are written whole. Building a delta
    /// (`delta::build_ops`) costs ~3 us of core time per leaf (x86) inside the synchronous checkpoint start, which
    /// stalls every op of the shard's core: ~1000 dirty leaves = a 3-4 ms stall (tail latency,
    /// doc/perf/tail-latency-20261015.md). A whole page costs ~0.3 us there but 8 KiB of device writes. 0 = no bound.
    pub ckpt_delta_leaves: usize,
    /// Sliced freeze (adr 0021 am. 40): per core poll at most this many dirty pages of a checkpoint are frozen (delta
    /// entry or sealed copy, ~1-3 us each), and a freeze begins only in a poll that did no other checkpoint work of the core
    /// (at most one begin per `Store::poll`; the budget is shared by the shards of a `Store`). 0 = kill switch (the whole
    /// freeze in one call at the start, as before).
    pub ckpt_slice: usize,
    /// Freeze deadline (adr 0021 am. 48): a running sliced freeze takes at least `pending pages / N` pages per poll (capped at
    /// 512), so it ends within about N polls however small the core budget `ckpt_slice` is or however many shards share it
    /// (before: it fell behind the dirtying rate, hit `dirty_hard`, every txn got Busy). A checkpoint start (am. 80) ends
    /// within N polls: its units spread over the polls left of that window, the last one takes the rest, however fast
    /// txns dirty bitmap chunks meanwhile. 0 = off (am. 40 behavior).
    pub ckpt_fz_polls: usize,
    /// Parked-txn lookahead (adr 0021 am. 44): while the shard FIFO head waits, the object pages (name, onode, `_` attr) of up
    /// to this many txns behind it are loaded (reads only, order unchanged), so their misses overlap instead of stalling the FIFO one
    /// device read at a time. 0 = off.
    pub park_lookahead: usize,
    /// Omap / xattr / header values of at least this many bytes are written as data blocks, the tree keeps a ~20 B reference
    /// (adr 0021 am. 46; store with `FEAT_EXT_VALUE`): a 4 KiB omap value dirties a leaf share of ~20 B instead of half a page.
    /// Values above `V_EXT_MAX` keep the fragment form. 0 = off.
    pub val_ext_min: u32,
    /// User omap values (counted objects; not PG logs) of at least this many bytes are stored zstd-compressed inline when that saves >= 1/8 (adr 0021 am. 58, 59; store with `FEAT_VAL_COMP`). 0 = off.
    pub val_comp_min: u32,
    /// Values a value class collects before its compression dictionary is trained (`obj::onode::DICT_SAMPLES`; tests lower it).
    pub val_dict_samples: u32,
    /// Elastic pool (adr 0021 am. 52; chunked store): the shard asks the pool owner for chunks (below `lend_wm_pct` percent of a chunk
    /// of free space above the user reserve, in its poll; fallback at the allocation gate) and counts the lendable space in
    /// its checkpoint trigger and admission. false = step 2 behavior (chunks only by `Store::grant_chunk`).
    #[cfg(feature = "elastic")]
    pub lend_auto: bool,
    #[cfg(feature = "elastic")]
    pub lend_wm_pct: u32,
    /// Pause before a shard asks again after the pool answered empty.
    #[cfg(feature = "elastic")]
    pub lend_retry_ms: u64,
    /// This store may own the pool (writes the lending table, answers requests). Only the store that mounts shard 0 does
    /// (one writer per device by construction). Default true.
    #[cfg(feature = "elastic")]
    pub lend_owner: bool,
    /// Reclaim (adr 0021 am. 57, am. 61: always on with `lend_auto`; am. 82: on demand): a borrowed chunk that became
    /// empty since a durable checkpoint goes back to the pool; while another shard waits for a chunk (pool dry), the
    /// cheapest borrowed chunk is evacuated (fenced, live extents moved into holes by paced background txns, drained by
    /// checkpoints) and returned while the shard keeps `lend_wm_pct` of a chunk plus `reclaim_hyst_pct` % of its base in
    /// whole free windows without it, else kept as that headroom.
    #[cfg(feature = "elastic")]
    pub reclaim_hyst_pct: u32,
    /// Evacuation move rate in MB/s.
    #[cfg(feature = "elastic")]
    pub reclaim_mbps: u32,
    /// Queue state of every shard of the device (adr 0533): background work runs as under client IO
    /// while another shard's queue is busy. `None` = the shard's store shares one table among its own shards
    /// (`Store::mount_shards`); the daemon shares one per device among its per-core stores.
    pub dev_idle: Option<std::sync::Arc<crate::devidle::DevIdle>>,
    /// Tree page budget of every shard of the device (adr 0062 am. 3): a shard's page cache grows into the share idle
    /// shards do not use and gives back what a faster-evicting shard needs. `None` = the shard's store shares one pool
    /// among its own shards (`Store::mount_shards`); the daemon shares one per device among its per-core stores.
    pub page_pool: Option<std::sync::Arc<crate::pagepool::PagePool>>,
}

impl Default for ShardCfg {
    fn default() -> Self {
        ShardCfg {
            #[cfg(feature = "rocksdb")]
            rocksdb: None,
            #[cfg(feature = "splinterdb")]
            splinterdb: None,
            max_unit_blocks: 16,
            max_inflight_units: 16,
            ready_cap: 32,
            replay: ReplayCfg::default(),
            cache_pages: 16384, // 128 MiB of 8 KiB pages; txn budget = half (a 10 MiB dirfrag batch needs ~2-4k pages)
            omap_scan_prefetch: true,
            omap_scan_prefetch_adaptive: true,
            omap_scan_prefetch_chunks: 1,
            omap_scan_prefetch_max_chunks: 16,
            omap_delete_range_threshold: 0,
            max_walk_pages: 2048,
            ckpt_wal_pct: 50,
            ckpt_interval_ns: 5_000_000_000,
            dirty_soft_pages: 2048,
            dirty_hard_pages: 6144,
            run_soft_bytes: 16 << 20,
            run_max: 24,
            run_fan: 4,
            run_helpers: false,
            run_pool: None,
            data_reserve_pct: 2,
            auto_ckpt: true,
            point_cache: 32768,
            require_current: false,
            repair_counters: false,
            repair_fence: false,
            meta_slack_cells: 2,
            inline_max: 2048,
            delta_cap_bytes: 16 << 20,
            alloc_pool_chunks: 0,
            shared_clone: true,
            bg_compact: true,
            defrag: true,
            defrag_cells: true,
            keep_windows: 8,
            small_dense: 16,
            pf_retain: true,
            data_floor_blocks: crate::obj::DATA_FLOOR_BYTES / crate::BLK as u64,
            wal_coalesce: 1,
            ckpt_delta_leaves: 0,
            ckpt_slice: 32,
            ckpt_fz_polls: 64,
            park_lookahead: 32,
            val_ext_min: 2048,
            val_comp_min: 64,
            val_dict_samples: crate::obj::onode::DICT_SAMPLES as u32,
            #[cfg(feature = "elastic")]
            lend_auto: false,
            #[cfg(feature = "elastic")]
            lend_wm_pct: 25,
            #[cfg(feature = "elastic")]
            lend_retry_ms: 100,
            #[cfg(feature = "elastic")]
            lend_owner: true,
            #[cfg(feature = "elastic")]
            reclaim_hyst_pct: 10,
            #[cfg(feature = "elastic")]
            reclaim_mbps: 64,
            dev_idle: None,
            page_pool: None,
        }
    }
}

/// Chunk under evacuation: `(engine block, blocks, fenced runs)` (adr 0021 am. 57).
#[cfg(feature = "elastic")]
type EvacFence = (u64, u64, Vec<(u64, u32)>);

/// A transaction handed to `submit` (also the KV txn builder: `put`/`del`/`delrange`).
#[derive(Debug)]
pub struct Txn<B> {
    /// Opaque, returned in `Event::Acked`.
    pub token: u64,
    pub ops: Vec<Op>,
    /// New data: `(blk, buf)` with blk reserved via `Shard::alloc`; buf length multiple of 4 KiB and at most
    /// the device transfer limit (split larger writes into several entries).
    pub data: Vec<(u64, B)>,
    /// Optional per-block crcs of `data` (`blk_crc`), same order. Only trusted when `len == data.len()` (the object
    /// layer already hashed while copying); otherwise `submit` hashes the buffers itself.
    pub data_crcs: Vec<Vec<u32>>,
    /// New data whose copy into a device buffer waits for the submit (the DMA budget refused the staging copy, adr 0175
    /// am. 4): like `data`, reserved via `Shard::alloc`, with its block crcs; written after the `data` runs.
    pub copies: Vec<CopyRun>,
    /// Indexes into `data` of the runs whose last block is the partial last block of an object: committed, the
    /// object layer keeps that block resident for the next append ([`crate::obj::shardio::ShardStore::cache_tails`]).
    pub tails: Vec<u32>,
    /// Blocks released by this txn; must currently be allocated.
    pub frees: Vec<(u64, u32)>,
    /// Pre-written pieces this txn claims (adr 0477): extents of the record whose data the device already has (or gets
    /// from the pre-write in flight; the unit waits for it like for `data`).
    pub pre: Vec<crate::pre::PreClaim>,
    /// System txn (osdmaps, PG state, replica applies, removes): stop at a third of the user reserves (adr 0021
    /// am. 4/6/21).
    pub sys: bool,
    /// Pure shrink (removes, truncates, no writes; adr 0021 am. 21): may use every reserve down to zero, the last
    /// headroom is for deletes only. Implies `sys`.
    pub shrink: bool,
    /// Already-durable extents (omap LSM manifest publication, or offline false-free allocation).
    /// Reserved, with checksums of immutable bytes. Allocated with the record like `data`, without payload writes.
    pub olsm: Option<Vec<Extent>>,
}

/// A data run of a [`Txn`] staged without a device buffer: the DMA budget refused the staging copy (adr 0175 am. 4).
/// The shard copies `src` into in-flight IO memory ([`BlockDev::try_alloc_io_uninit`]) right before its device write;
/// refused there, the write waits in the shard's data backlog and is retried at every poll (IO in flight returns memory),
/// counted in its unit's pending data like any data write, so the txn is acked only once it landed.
#[derive(Debug, Clone)]
pub struct CopyRun {
    /// First block, reserved via `Shard::alloc`.
    pub blk: u64,
    /// The bytes (whole blocks, at most the device transfer limit).
    pub src: bytes::Bytes,
    /// Block crcs (`blk_crc`) of `src` at `blk`.
    pub crcs: Vec<u32>,
    /// The run ends in the partial last block of an object (`Txn::tails` of a run in `data`).
    pub tail: bool,
}

/// KV transaction (design 2.2): same type as `Txn`; read-your-writes via `Shard::txn_get`.
pub type KvTxn<B> = Txn<B>;

impl<B> Txn<B> {
    pub fn new(token: u64) -> Txn<B> {
        Txn {
            token,
            ops: Vec::new(),
            data: Vec::new(),
            data_crcs: Vec::new(),
            copies: Vec::new(),
            tails: Vec::new(),
            frees: Vec::new(),
            pre: Vec::new(),
            sys: false,
            shrink: false,
            olsm: None,
        }
    }
    pub fn put(&mut self, k: &[u8], v: &[u8]) -> &mut Self {
        self.ops.push(Op::Put(k.to_vec(), v.to_vec()));
        self
    }
    pub fn del(&mut self, k: &[u8]) -> &mut Self {
        self.ops.push(Op::Del(k.to_vec()));
        self
    }
    /// Delete `[a, b)`.
    pub fn delrange(&mut self, a: &[u8], b: &[u8]) -> &mut Self {
        self.ops.push(Op::DelRange(a.to_vec(), b.to_vec()));
        self
    }
}

#[derive(Debug)]
pub enum Event<B> {
    /// Txn durable (data + WAL, and everything before it).
    Acked(u64),
    Read {
        token: u64,
        result: std::result::Result<B, IoError>,
    },
    /// Checkpoint finished: root slot durable, ring space up to `ckpt_lsn` reusable, superseded pages freed.
    Released { ckpt_lsn: u64 },
    /// Tree pages were loaded (or failed) in a way not named by [`Event::Page`], or other state changed: retry every operation
    /// that returned `Miss`.
    Wake,
    /// Tree page `addr` was loaded: only operations that missed exactly that page may run (the page-load part of
    /// [`Event::Wake`], adr 0043 am. 9; counts as a wake for blocking waiters).
    Page(u64),
    /// Fatal; the shard accepts nothing more.
    Failed(StoreError),
}

/// Space class of an allocation (floors: `alloc`, `alloc_sys`, `alloc_priv`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AllocClass {
    User,
    Sys,
    Priv,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UState {
    Open,
    Ready,
    InFlight,
}

struct Unit {
    seq: u64,
    st: UState,
    payload: Vec<u8>,
    first_lsn: u64,
    ntxn: u32,
    /// `FLAG_PART` / `FLAG_END` for the units of a multi-part txn (ADR 0028), else 0.
    flags: u16,
    part_idx: u32,
    tokens: Vec<u64>,
    frees: Vec<(u64, u32)>,
    pending_data: u32,
    wal_done: bool,
    pad_pending: bool,
    pos: u64,
    pad_pos: u64,
    /// Sealed: the unit header (its block image is built from it and `payload` at submit, adr 0175 am. 4), and the
    /// header of the ring-end PAD written before it.
    hdr: [u8; HDR_LEN],
    pad_hdr: Option<[u8; HDR_LEN]>,
    /// Commit-latency probe (`ShardStats::cm_*`): ns of the first txn's submit (0 = none yet), device commands in
    /// flight then, checkpoint running then, a checkpoint write of any shard in flight on the device when the WAL write
    /// was submitted, data write held in the backlog, ns of the WAL / last data completion.
    t_open: u64,
    ahead: u32,
    ckpt: bool,
    ck_dev: bool,
    backlog: bool,
    t_wal: u64,
    /// ns the unit was sealed (header written) and handed to the device (`ShardStats::cm_*_ns` split).
    t_seal: u64,
    t_sub: u64,
    t_data: u64,
}

#[derive(Debug)]
struct WJob {
    blk: u64,
    bitmap: bool,
    /// Bitmap: byte offset; tree pages: first arena page (the job's pages lie in one arena chunk).
    off: usize,
    /// Bytes.
    len: usize,
    /// Went out on the device's background checkpoint write budget (adr 0021 am. 76).
    dev: bool,
}

#[derive(Debug)]
struct CkJob {
    lsn: u64,
    fr: Frozen,
    jobs: Vec<WJob>,
    next: usize,
    inflight: usize,
    /// Bytes of `inflight`.
    inflight_bytes: u64,
    root_seq: u64,
    root_sent: bool,
    n_units: usize,
    bm: Option<(u64, u32, u32)>,
    used_blocks: u64,
    /// Meta cells returned to the data region by this checkpoint (held until its root is durable).
    released: Vec<(u64, u32)>,
    /// Nothing was logged since the previous checkpoint (adr 0021 am. 18): same lsn, same WAL tail.
    idle: bool,
    /// WAL tail this checkpoint's root slot records (position, crc of the unit before it, first lsn of the tail unit).
    tail: (u64, u32, u64),
    /// Lsn of the oldest omap run live at `lsn` (`lsn + 1`: none; adr 0476): units from it on stay.
    floor: u64,
}

/// The inputs of the store's space preflight (`Store::write_room` / `Store::apply_room`, [`Shard::room_view`]): a few
/// counters instead of a full [`Statfs`] per replica write, EC sub-write and push.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RoomView {
    /// Data blocks the class leaves free ([`Shard::floors`], migration headroom included).
    pub data_floor: u64,
    /// Meta pages the class leaves free: its meta floor, for user txns plus the pages the omap runs need once merged.
    pub meta_floor: u64,
    /// Free data blocks; held and reclaimable ones (empty meta cells) count, the alloc path forces the checkpoint that
    /// releases them (elastic pool: plus the lendable blocks).
    pub data_free: u64,
    pub data_reclaim: u64,
    pub meta_used: u64,
    pub meta_free: u64,
    pub dirty_pages: u64,
    pub meta_bpp: u64,
    /// Elastic meta that can still grow into the data region.
    pub meta_growable: bool,
}

/// Capacity numbers (statfs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statfs {
    #[cfg(any(feature = "rocksdb", feature = "splinterdb"))]
    pub external_space: Option<(u64, u64)>,
    pub data_blocks: u64,
    pub data_used: u64,
    pub data_free: u64,
    /// Freed but not yet reusable (waiting for a checkpoint / readers).
    pub data_held: u64,
    /// Blocks of empty meta cells the next checkpoint gives back (adr 0021 am. 21): free capacity like `data_held`.
    pub data_reclaim: u64,
    /// Free blocks of the shared pool the shard may still get (elastic pool, adr 0021 am. 52; last reported by the owner).
    #[cfg(feature = "elastic")]
    pub data_lendable: u64,
    pub data_reserved: u64,
    /// User floors (adr 0021 am. 4/21): user txns leave these blocks / meta pages free; sys txns a third of them,
    /// pure shrinks nothing.
    pub data_reserve: u64,
    /// Migration headroom held (adr 0031 am. 4): on top of the user and system floors.
    pub mig_hold: u64,
    pub meta_reserve: u64,
    pub meta_pages: u64,
    pub meta_used: u64,
    pub meta_free: u64,
    /// Elastic meta space (adr 0021 am. 12): meta cells taken from the data region (`data_*` counts include their
    /// blocks as used), pages in use inside cells, pages of the base area, blocks per page; `elastic` false =
    /// legacy fixed meta region.
    pub elastic: bool,
    pub meta_cells: u64,
    pub meta_cell_blocks: u64,
    pub meta_cell_used: u64,
    pub meta_base_pages: u64,
    pub meta_bpp: u64,
    /// Elastic meta cannot grow right now (see `Shard::grow_meta`): judge fullness by the present meta pages.
    pub meta_grow_blocked: bool,
    pub dirty_pages: u64,
    /// Tree pages the omap runs still need once merged (adr 0476, [`Shard::run_pages`]): charged like
    /// dirty pages by admission, `write_room` and the fill.
    pub run_pages: u64,
    /// Omap bytes of the store's format: 0 for tree omap (those bytes are part of the used/run pages), or for the LSM
    /// engine (adr 0610) the device blocks of the live runs plus the bytes buffered in both memtables.
    pub omap_bytes: u64,
    pub cached_pages: u64,
    pub ckpt_lsn: u64,
    pub durable_lsn: u64,
    pub wal_blocks: u64,
    pub wal_free: u64,
}

/// Reason an elastic metadata cell could not be reserved and the shard became growth-blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaGrowthFailureReason {
    /// The next metadata image would exceed the format's single-page index limit.
    ImageLimit,
    /// The allocator had fewer free blocks than one metadata cell requires.
    InsufficientFreeBlocks,
    /// Enough free blocks existed, but no contiguous cell-sized run could be reserved.
    NoContiguousRun,
}

/// Immutable inputs captured only when a failed growth attempt sets the shard's blocked state.
///
/// The record remains available after growth is unblocked and is replaced only by a later actual blocking failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaGrowthFailure {
    /// One-based count of actual blocking growth failures for this mounted shard; saturates at `u64::MAX`.
    pub sequence: u64,
    /// Classification of the failure that blocked growth.
    pub reason: MetaGrowthFailureReason,
    /// UTC Unix timestamp, in nanoseconds, sampled when the failure was captured.
    pub unix_time_ns: u64,
    /// Store driver's last `poll(now)` timestamp, in nanoseconds; zero means no poll has run yet.
    pub store_poll_time_ns: u64,
    /// Free meta pages requested by the growth attempt.
    pub requested_free_pages: u64,
    /// Free meta pages observed at the failure.
    pub free_meta_pages: u64,
    /// Actual size of one metadata cell, in 4 KiB store blocks.
    pub cell_blocks: u64,
    /// Tree pages in one metadata cell.
    pub pages_per_cell: u64,
    /// Allocator-free data blocks observed by the growth attempt.
    pub free_data_blocks: u64,
    /// Data blocks held until checkpoint/readers release them.
    pub held_data_blocks: u64,
    /// Allocator-reserved data blocks.
    pub reserved_data_blocks: u64,
    /// Data reserve argument applied to this growth attempt.
    pub reserve_data_blocks: u64,
    /// Current elastic metadata image bytes.
    pub image_bytes: u64,
    /// Bytes reserved for metadata image extension sections.
    pub image_reserve_bytes: u64,
    /// Bytes required by cells pending the active freeze.
    pub deferred_image_bytes: u64,
    /// Projected image size after adding the next cell, including the cell-directory entry.
    pub image_needed_bytes: u64,
    /// Maximum image size indexable by the configured tree page size.
    pub image_limit_bytes: u64,
    /// Number of entirely free allocator windows; an O(1) allocator counter.
    pub free_windows: u64,
}

#[derive(Debug, Clone, Copy)]
struct MetaGrowthFailureContext {
    reason: MetaGrowthFailureReason,
    requested_free_pages: u64,
    free_data_blocks: u64,
    reserve_data_blocks: u64,
    cell_blocks: u64,
    pages_per_cell: u64,
    image_bytes: u64,
    image_reserve_bytes: u64,
    deferred_image_bytes: u64,
    image_needed_bytes: u64,
    image_limit_bytes: u64,
}

#[cfg(test)]
mod statfs_fill_tests {
    use super::Statfs;

    #[test]
    fn partial_reclaim_statfs_preserves_data_bytes_for_each_page_size() {
        for meta_bpp in [1, 2] {
            for elastic in [false, true] {
                let meta_cell_blocks = if elastic { 256 } else { 0 };
                let before = Statfs {
                    data_blocks: 1000,
                    data_used: meta_cell_blocks + 100,
                    meta_cell_blocks,
                    meta_used: 10,
                    meta_bpp,
                    elastic,
                    ..Default::default()
                };
                // Reclaim the final 100 object blocks; metadata pages remain live.
                let after = Statfs {
                    data_used: meta_cell_blocks,
                    ..before
                };
                let expected_meta_bytes = if elastic {
                    10 * meta_bpp * crate::BLK as u64
                } else {
                    0
                };
                for f in [before, after] {
                    assert_eq!(f.meta_in_data_bytes(), expected_meta_bytes);
                }
                let data_bytes =
                    |f: Statfs| f.used_blocks() * crate::BLK as u64 - f.meta_in_data_bytes();
                assert_eq!(data_bytes(before), 100 * crate::BLK as u64);
                assert_eq!(data_bytes(after), 0);
            }
        }
    }

    #[test]
    fn fill_ratio_accounts_for_data_meta_elastic_and_blocked_growth() {
        let base = Statfs {
            data_blocks: 1000,
            data_used: 200,
            meta_pages: 100,
            meta_reserve: 20,
            meta_used: 40,
            dirty_pages: 8,
            run_pages: 4,
            ..Default::default()
        };
        assert_eq!(base.meta_usable_pages(), 70);
        // max(data=20%, meta=(40+8+4)/70)
        assert!((base.fill_ratio() - (52.0 / 70.0)).abs() < f64::EPSILON);

        let elastic = Statfs {
            elastic: true,
            data_used: 300,
            meta_cell_blocks: 100,
            meta_bpp: 2,
            ..base
        };
        // (300 - 100 + (40 + 8 + 4) * 2) / 1000 = 30.4%
        assert!((elastic.fill_ratio() - 0.304).abs() < f64::EPSILON);

        let blocked = Statfs {
            meta_grow_blocked: true,
            ..elastic
        };
        assert!((blocked.fill_ratio() - (52.0 / 70.0)).abs() < f64::EPSILON);
        // real usage ignores the meta-bound clamp: 200 data + 52 pages * 2
        assert_eq!(blocked.used_blocks(), 304);
        assert_eq!(base.used_blocks(), 200);
    }

    /// Effective shard fill (adr 0021 S4): against the shard's capacity plus the pool it can still borrow. Base 25 % of
    /// the device (4 shards: pool = 3 x the bases): a shard at its base reads a quarter of its fill; one that borrowed
    /// half of the pool reads its usage against base + lent + rest; a dry pool or no pool (base 100) = its own fill.
    #[test]
    fn pooled_fill_ratio_counts_the_pool_left() {
        let at_base = Statfs {
            data_blocks: 1000,
            data_used: 900,
            meta_pages: 100,
            ..Default::default()
        };
        let own = at_base.fill_ratio();
        assert!((own - 0.9).abs() < 1e-9);
        #[cfg(feature = "elastic")]
        {
            // 4 shards x 1000 base, pool 12000 free
            let pooled = Statfs {
                data_lendable: 12_000,
                ..at_base
            };
            assert!((pooled.pooled_fill_ratio() - 900.0 / 13_000.0).abs() < 1e-9);
            // borrowed 6000 (capacity 7000, 6900 used), 6000 left in the pool
            let lent = Statfs {
                data_blocks: 7000,
                data_used: 6900,
                data_lendable: 6000,
                ..at_base
            };
            assert!((lent.pooled_fill_ratio() - 6900.0 / 13_000.0).abs() < 1e-9);
            // pool dry: its own fill, the hot shard reads full
            let dry = Statfs {
                data_lendable: 0,
                ..lent
            };
            assert!((dry.pooled_fill_ratio() - dry.fill_ratio()).abs() < 1e-9);
        }
        // plain store (base 100, no pool): its own fill
        assert!((at_base.pooled_fill_ratio() - own).abs() < 1e-9);
    }
}

impl Statfs {
    /// Meta pages available to hold live, dirty, and pending-run tree pages after reserve and COW headroom.
    pub fn meta_usable_pages(&self) -> u64 {
        (self.meta_pages.saturating_sub(self.meta_reserve) * 7 / 8).max(1)
    }

    /// Fraction of this shard's data capacity charged by the existing fullness accounting.
    pub fn fill_ratio(&self) -> f64 {
        let blocks = self.data_blocks.max(1);
        let meta_fill = ((self.meta_used + self.dirty_pages + self.run_pages) as f64
            / self.meta_usable_pages() as f64)
            .min(1.0);
        let native = if self.elastic {
            let used = self.data_used.saturating_sub(self.meta_cell_blocks)
                + (self.meta_used + self.dirty_pages + self.run_pages) * self.meta_bpp;
            let fill = (used as f64 / blocks as f64).min(1.0);
            if self.meta_grow_blocked {
                fill.max(meta_fill)
            } else {
                fill
            }
        } else {
            let data_fill = self.data_used as f64 / blocks as f64;
            data_fill.max(meta_fill).min(1.0)
        };
        #[cfg(any(feature = "rocksdb", feature = "splinterdb"))]
        if let Some((free, total)) = self.external_space {
            return native.max(1.0 - free.min(total) as f64 / total.max(1) as f64);
        }
        native
    }

    /// Blocks the shard really holds: object data plus the tree pages in use (and dirty/run pages not yet written). Free
    /// pages of meta cells, floors and the fullness clamps of [`Self::fill_ratio`] are not in it. A fixed meta region
    /// (non-elastic) lies outside the data blocks: only `data_used` counts.
    pub fn used_blocks(&self) -> u64 {
        if self.elastic {
            self.data_used.saturating_sub(self.meta_cell_blocks)
                + (self.meta_used + self.dirty_pages + self.run_pages) * self.meta_bpp
        } else {
            self.data_used
        }
        .min(self.data_blocks)
    }

    /// Tree-page bytes inside [`Self::used_blocks`]: elastic shards only (their cells lie in the data blocks), a fixed meta
    /// region lies outside them. Object data = `used_blocks` bytes - this.
    pub fn meta_in_data_bytes(&self) -> u64 {
        if self.elastic {
            self.meta_used * self.meta_bpp * BLK as u64
        } else {
            0
        }
    }

    /// [`Self::fill_ratio`] against everything the shard can still get: its capacity plus the free pool blocks it may
    /// borrow (elastic pool, `data_lendable`; 0 when the pool is dry, closed or off: then exactly `fill_ratio`).
    /// Fullness of a pooled store is judged here (adr 0021 S4): one shard at its floor with a dry pool is full even
    /// while the base of idle shards keeps the device sum low.
    pub fn pooled_fill_ratio(&self) -> f64 {
        #[cfg(feature = "elastic")]
        let lendable = self.data_lendable;
        #[cfg(not(feature = "elastic"))]
        let lendable = 0;
        let blocks = self.data_blocks.max(1) as f64;
        let fill = self.fill_ratio() * blocks / (blocks + lendable as f64);
        #[cfg(any(feature = "rocksdb", feature = "splinterdb"))]
        if let Some((free, total)) = self.external_space {
            return fill.max(1.0 - free.min(total) as f64 / total.max(1) as f64);
        }
        fill
    }
}

/// RAM accounting of one shard ([`Shard::mem`]).
#[derive(Debug, Default, Clone, Copy)]
pub struct ShardMem {
    pub tree: crate::tree::TreeMem,
    pub point_entries: u64,
    pub point_bytes: u64,
    pub alloc_bytes: u64,
    /// Allocator chunks present (reserved layer + pool) and pool misses (heap allocations on the write path, adr 0021
    /// am. 24; should stay 0).
    pub alloc_chunks: u64,
    pub alloc_pool_misses: u64,
    pub free_q_extents: u64,
    pub limbo_extents: u64,
    pub ring_units: u64,
    pub pipeline_units: u64,
    pub pipeline_bytes: u64,
    pub read_map: u64,
    /// Page images copied for the checkpoint in flight (transient, up to the dirty pages x page size).
    pub ckpt_bytes: u64,
    /// Omap runs (adr 0476): entries and heap bytes.
    pub run_entries: u64,
    pub run_bytes: u64,
}

/// One shard on one queue handle.
#[derive(Debug)]
pub struct Shard<D: BlockDev> {
    dev: D,
    /// Borrower side of the elastic pool (adr 0021 am. 52).
    #[cfg(feature = "elastic")]
    pub lend: crate::lend::Ctl,
    /// Borrowed chunk being evacuated (adr 0021 am. 57): `(engine block, blocks, fenced runs)`. Blocks released inside it
    /// (checkpoint, reader epochs) are fenced again at once, so no allocation lands there before it is returned.
    #[cfg(feature = "elastic")]
    evac_fence: Option<EvacFence>,
    cfg: ShardCfg,
    dir: ShardDir,
    shard: u32,
    store_id: u32,
    lpb: u64,
    max_xfer_blk: usize,
    state: State,
    /// Acked frees awaiting a checkpoint: `(unit last_lsn, blocks)`, ascending.
    free_q: VecDeque<(u64, Vec<(u64, u32)>)>,
    /// Blocks in `free_q` (adr 0021 am. 33: what the next checkpoint would release).
    free_q_blocks: u64,
    /// Frees passed by a checkpoint, waiting for readers of older epochs: `(epoch tag, blocks)`.
    limbo: VecDeque<(u64, Vec<(u64, u32)>)>,
    /// Deallocate of blocks that became allocatable (adr 0642).
    trim: Trim,
    /// An allocation or meta growth missed while a deallocate held blocks: no command starts before the next allocation or
    /// growth attempt finds none held (the parked request gets the released windows first).
    trim_wait: bool,
    read_epoch: u64,
    readers: VecDeque<(u64, u32)>,
    reads: HashMap<u64, u64, BuildHasherDefault<AddrHasher>>,
    epoch: u32,
    next_lsn: u64,
    durable_lsn: u64,
    ckpt_lsn: u64,
    next_onode_id: u64,
    // checkpoint
    ck: Option<CkJob>,
    ck_requested: bool,
    /// A caller waits on a checkpoint (an admission refused for WAL ring, meta or data space or dirty pages; an explicit
    /// request; the mount after replay): its writes are foreground, outside the device's background checkpoint write
    /// budget with a one-largest-write budget of their own (adr 0021 am. 76). Cleared when a checkpoint ends with no
    /// further one requested.
    ck_fg: bool,
    /// Interval checkpoint deadline (adr 0021 am. 75): `ckpt_interval_ns` after the latest checkpoint start; while the shard has
    /// nothing to persist it is restarted at every poll to `ckpt_phase` ahead.
    ckpt_due: Option<Nanos>,
    /// First interval after a mount or an idle stretch (adr 0021 am. 75, [`ckpt_phase`]): one interval plus an
    /// identity offset, so the interval checkpoints of the shards on one device and of different OSDs do not start together.
    ckpt_phase: Nanos,
    /// Sliced freeze in progress (adr 0021 am. 40): what the checkpoint job needs from its begin.
    fzs: Option<FzStart>,
    /// Sliced freeze: budget handed in for the next `poll` (`Store`), what is left of it in the current one, and since when
    /// / for how many polls a wanted checkpoint has been held back.
    ck_gate: Option<usize>,
    ck_left: usize,
    ck_defer: Option<(Nanos, u32)>,
    /// Sliced checkpoint start in progress (adr 0021 am. 80): `Some` from its first slice to its freeze begin; the
    /// polls it took so far (its window: `ckpt_fz_polls`).
    ck_start: Option<CkStart>,
    ck_start_polls: usize,
    /// When the running checkpoint began (`now` of its freeze begin): checkpoint duration stats.
    ck_t0: Option<Nanos>,
    bm_cur: Option<(u64, u32, u32)>,
    data_reserve: u64,
    /// Migration headroom (adr 0031 am. 4): blocks reserved for PG copies moving into this shard. Raises the user and
    /// system floors (nothing but the copy, which releases it batch by batch, and pure shrinks may use it).
    mig_hold: u64,
    /// Elastic pool: blocks a deferred move needs here; the shard borrows chunks until its room covers them.
    #[cfg(feature = "elastic")]
    mig_want: u64,
    meta_reserve: u32,
    /// Elastic meta space (adr 0021 am. 12): cell size in blocks (0 = legacy fixed region), cells reserved from the
    /// data allocator that the next checkpoint makes durable.
    cell_blocks: u64,
    pending_cells: Vec<u64>,
    /// Unique allocator bitmap chunks touched by pending and freeze-deferred cell extents.
    pending_cell_chunks: Vec<u64>,
    /// Cells reserved while a sliced freeze runs: the freeze writes the image of the cell set at its lsn, so they join
    /// the meta space (and `pending_cells`) when it ends; admission counts their pages at once ([`Shard::meta_free`]).
    fz_cells: Vec<Vec<MetaExtent>>,
    /// Cells given back since the last checkpoint started (moved into its job).
    shrunk: Vec<(u64, u32)>,
    /// Elastic meta growth failed (no contiguous cell-sized run, data full or image at its limit) with this many
    /// free data blocks: the shard is meta-bound until a growth succeeds (statfs, `write_room`).
    meta_blocked: Option<u64>,
    /// Most recent actual meta-growth failure, retained after recovery for later capacity diagnostics.
    last_meta_growth_failure: Option<MetaGrowthFailure>,
    meta_growth_failure_sequence: u64,
    /// The last growth failure was a missing contiguous cell-sized run with enough free blocks (fragmentation): the case a
    /// cell sweep can fix (adr 0021 am. 51).
    meta_no_run: bool,
    /// A checkpoint completed since the failure (held blocks released): growth may be retried.
    meta_retry: bool,
    /// The growth miss behind `meta_blocked` waits for the checkpoint covering this lsn (adr 0021 S13, [`Shard::defer_growth`]):
    /// the acked frees it releases hold at least a cell. Not meta-bound meanwhile (statfs, `write_room`); `meta_blocked`
    /// stays the search gate; [`Shard::finish_ckpt`] of that checkpoint ends the wait.
    meta_wait: Option<u64>,
    /// The checkpoint cycle right after a wait ended: a miss now is a real failure (meta-bound), not a second wait.
    meta_cure: bool,
    /// A completed checkpoint left empty cells that the next one would give back (adr 0021 am. 21): checkpoint again
    /// even without new log records, the cells hold data space (statfs counts only their used pages). Blocks of those
    /// cells; `write_room` counts them as free like held blocks (the alloc path forces the checkpoint).
    reclaim: u64,
    /// Elastic meta (adr 0021 am. 80): the largest meta space (pages) admission or a checkpoint start asked for since the
    /// last checkpoint start, and in the cycle before. The give-back at the next start keeps the larger: the next cycle
    /// asks for about as much again (a fixed slack below that gave cells back and regrew them every checkpoint), also
    /// after a cycle a requested checkpoint cut short. A soft hold: `reclaim` counts the cells it keeps as free data space,
    /// and it yields to data pressure (a failed allocation, a deferred growth: both zero it) and to an idle checkpoint
    /// (nothing logged since the last one: a cycle that asked for nothing).
    meta_peak: usize,
    meta_peak_prev: usize,
    // tree page IO
    page_reads: Vec<Option<Want>>,
    /// Per `page_reads` slot: the page was freed by address while the read was queued or in flight (`reap_gone`): the
    /// image is dropped on completion, never cached.
    page_stale: Vec<bool>,
    gone_buf: Vec<(u64, u32)>,
    deferred: std::collections::VecDeque<Want>,
    /// Scratch of [`Shard::queue_wants`].
    want_buf: Vec<Want>,
    page_dma_wait: bool,
    page_dma_submits: u64,
    wake: bool,
    // WAL ring
    ring: VecDeque<RingUnit>,
    ring_used: u64,
    head_pos: u64,
    head_crc: u32,
    root_seq: u64,
    /// WAL tail of the newest durable root slot (position, crc of the unit before it): an idle checkpoint (nothing
    /// logged since the last one, only lazily freed pages to persist) writes the same tail again.
    tail: (u64, u32, u64),
    // pipeline
    pipeline: VecDeque<Unit>,
    next_unit_seq: u64,
    inflight_units: usize,
    failed: Option<StoreError>,
    failed_reported: bool,
    /// Degraded read-only mount ([`Shard::mount`] `read_only`): the shard never submits a device write, deallocate or
    /// write-zeroes. Txns and pre-writes are refused, no checkpoint starts and no free window is trimmed; the replayed
    /// state stays in memory.
    read_only: bool,
    failed_at: Option<&'static std::panic::Location<'static>>,
    scratch: Enc,
    /// Recycled unit buffers (payload bytes, ack tokens): a unit allocates nothing in steady state.
    pool_payload: Vec<Vec<u8>>,
    pool_tokens: Vec<Vec<u64>>,
    /// Data writes of committed txns waiting for device queue room or for the device window `(blk, buf, unit seq, end
    /// of its range in the device's write stream; None: outside the window)` and why the last drain stopped: a txn may carry more data extents
    /// than the queue holds at once (adr 0066); they go out in waves as completions free slots and the window admits
    /// their range (adr 0643-device-admission-fifo), counted in their unit's `pending_data` from the start (the unit is
    /// acked only once all landed, replay validates their crcs).
    data_backlog: Backlog<D::Buf>,
    /// This shard's side of the device admission window (adr 0643-device-admission-fifo).
    adm: Admit,
    comps: Vec<Completion<D::Buf>>,
    /// Background compaction pacing (adr 0021 am. 33): earliest next step while busy; tree loads when a step last missed
    /// (it waits until something was loaded since).
    bg_next_ns: u64,
    bg_miss_loads: Option<u64>,
    /// Background merges since the last freeze: tree state no WAL record describes, persisted only by a checkpoint
    /// (an idle one when nothing else is logged).
    bg_dirty: bool,
    /// Repair mount (`ShardCfg::repair_fence`): false-free metadata-cell ranges this mount allocated; durable once the
    /// mount returns (its foreground checkpoint). Reported by `Store::repair` ([`Self::take_repaired_meta`]).
    repaired_meta: Vec<(u64, u32)>,
    /// Omap run merge in progress (adr 0476): object, its runs up to this lsn, next slice start.
    mg: Option<(u64, u64, Vec<u8>)>,
    /// Run compactions in progress (adr 0476 step 4), on disjoint windows of runs.
    cps: Vec<crate::runs::Compaction>,
    /// Helper cores with room for a job of this core at this poll (0 = inline only).
    compact_available: usize,
    /// Jobs prepared for helpers, not yet taken (at most `compact_available`).
    compact_ready: Vec<RunCompactionJob>,
    /// Jobs prepared or out on a helper: identity, object, run window (busy for new compactions), reserved bytes.
    compact_remote: Vec<(CompactionId, u64, (u64, u64), usize)>,
    compact_incarnation: u64,
    compact_serial: u64,
    /// Idle merges: time of the last mark (one per checkpoint interval) and `runs.inserted()` at it and at the mark
    /// before: an object without a new run since the previous mark is idle (another object's writes do not keep it).
    mg_mark: (Nanos, u64, u64),
    /// Merge every run (`drain_runs`). `mg_want`: a user txn was refused for meta space while runs held page charges:
    /// one merge (the floor object's runs, the largest charge as a rule). `mg_full`: a merge found no meta space; until
    /// the next checkpoint the object layer stops logging runs.
    mg_drain: bool,
    mg_want: bool,
    mg_full: bool,
    /// A re-log moved the floor: the next one waits for the checkpoint that releases the units it freed.
    rl_wait: bool,
    /// The last merge slice missed tree pages: the next one is built once the page reads completed.
    mg_loads: bool,
    /// The refused slice of the merge in progress (entries, bytes, end key or `None` = to the end): submitted again as is.
    mg_slice: Option<(usize, usize, Option<Vec<u8>>)>,
    /// Core time per merged entry (ps, EWMA 1/8 over submitted slices; 0 = not learned yet): bounds a slice to
    /// [`MERGE_SLICE_NS`]. Measured in thread CPU time (`fastclock::thread_cpu_ns`), never wall time: a preemption inside
    /// a slice is not the slice's cost, and learned as such it shrinks the slices below the writes' pace.
    mg_ps_per_ent: u64,
    /// LAB: every read of `dev_clk` also advances it by this many ns (a core descheduled between any two reads), see
    /// [`Shard::lab_stall_dev_clock`].
    #[cfg(feature = "lab")]
    lab_dev_tick_ns: u64,
    #[cfg(feature = "lab")]
    lab_dev_skew_ns: std::sync::atomic::AtomicU64,
    /// LAB: a merge slice costs this many ps per entry instead of the measured core time (0 = measure), see
    /// [`Shard::lab_fix_merge_cost`].
    #[cfg(feature = "lab")]
    lab_merge_ps: u64,
    /// Pace of the merge in progress ([`Shard::merge_pace`]): `RunSet::admitted` at its start, entries merged since,
    /// `RunSet::admitted` at its latest slice or paced wait.
    mg_pace: (u64, u64, u64),
    /// Txns other than run merges in the pipeline (logged, not yet acked): client and PG-state work the core still owes.
    fg_inflight: u32,
    /// Membership in the run budget (`ShardCfg::run_pool`).
    pool: crate::runs::PoolShare,
    /// Device busy time (adr 0474): start of the current busy period (>= 1 command in flight); `dev_clk` is read only
    /// at the idle/busy edges.
    dev_clk: crate::fastclock::Mono,
    dev_busy_since: Option<u64>,
    /// Background work ns (merges, run compactions, checkpoints, tree compaction) since the last [`Shard::take_bg_ns`],
    /// timed on `dev_clk`: no message of the core caused it, the core keeps it out of its message-cost learning.
    bg_ns: u64,
    /// The device's queue table (adr 0533): this shard publishes its queue edges at its shard id, and
    /// watches the others through `dev_view`.
    dev_idle: std::sync::Arc<crate::devidle::DevIdle>,
    dev_view: crate::devidle::DevView,
    /// Membership in the device's tree page budget (`ShardCfg::page_pool`; `None`: the shard keeps its own share).
    pages: Option<crate::pagepool::PageShare>,
    /// The same table watched for deallocates (adr 0642): every queue of the device, this shard's own included.
    trim_view: crate::devidle::DevView,
    /// Store clock time of the current `poll`.
    poll_now: u64,
    /// Pre-written payload pieces (adr 0477) and a reused buffer of blocks they return.
    pre: crate::pre::PreTab,
    pre_out: Vec<(u64, u32)>,
    /// Omap LSM driver (store with `FEAT_OMAP_LSM`, adr 0610).
    ol: Option<olsm_drv::OlsmDrv>,
    /// Bytes the object layer's data cache and prefetch table hold above their floor ([`Shard::set_data_cache_held`]):
    /// what the run block cache leaves of the lendable tree budget to it.
    dc_held: u64,
    #[cfg(feature = "rocksdb")]
    rocks: Option<rocks_drv::RocksDrv>,
    #[cfg(feature = "splinterdb")]
    splinter: Option<splinter_drv::SplinterDrv>,
    /// An ordinary client data batch waits for read admission; speculative LSM hints yield its slots.
    read_admission_waiting: bool,
    pub stats: ShardStats,
}

// Process-local incarnation prevents a delayed result from matching a newly mounted store's attempt.
static COMPACTION_INCARNATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactionId {
    pub shard: u32,
    incarnation: u64,
    serial: u64,
}

/// Only this immutable-input continuation crosses cores; no Store/Tree/device handle is transferred.
#[derive(Debug)]
pub struct RunCompactionJob {
    id: CompactionId,
    compaction: crate::runs::Compaction,
    _permit: crate::runs::HelperPermit,
}

/// Work that crosses to a helper core and back (adr 0534 lane): an omap run compaction (adr 0476) or a round of an
/// omap LSM flush / merge (adr 0610).
#[derive(Debug)]
pub enum HelperJob {
    Run(Box<RunCompactionJob>),
    Olsm(Box<OlsmJob>),
}

impl HelperJob {
    pub fn id(&self) -> CompactionId {
        match self {
            HelperJob::Run(j) => j.id(),
            HelperJob::Olsm(j) => j.id(),
        }
    }

    /// One bounded slice on the helper (`entries` bounds a run compaction slice; an omap LSM slice is one output
    /// chunk). `true` = send the job back to its owner.
    pub fn step(&mut self, entries: usize) -> bool {
        match self {
            HelperJob::Run(j) => j.step(entries),
            HelperJob::Olsm(j) => j.step(),
        }
    }
}

impl RunCompactionJob {
    pub fn id(&self) -> CompactionId {
        self.id
    }

    /// One bounded merge/Bloom slice. Allocation/final ownership conversion are bounded by the owner's reservation.
    pub fn step(&mut self, entries: usize) -> bool {
        if !self.compaction.step(entries) {
            return false;
        }
        self.compaction.finish_output();
        true
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ShardStats {
    /// Actual device completions; waiting staging retries only after progress, never every core poll.
    pub io_completions: u64,
    /// Bytes the device could not write by reference from their memory ([`Shard::view_buf`] refused: memory not
    /// aligned as the device needs, adr 0061 am. 11) and that were therefore copied into a device buffer (`perf dump`
    /// `view_copy_bytes`; ~0 when senders place payloads, spec msgr2.md 3.1).
    pub view_copy_bytes: u64,
    /// Wall time with >= 1 command in flight on this shard's queue, ns (iostat %util numerator, adr 0474).
    pub dev_busy_ns: u64,
    /// Bytes of successfully completed device reads / writes (WAL, data, checkpoint, page loads; adr 0474).
    pub dev_read_bytes: u64,
    pub dev_write_bytes: u64,
    /// `dev_write_bytes` by write kind (index = completion tag kind, `K_* >> 56`): data, WAL, WAL pad, root slot,
    /// checkpoint pages, pre-written payload (device bytes per op breakdown, doc/perf/store-create-bytes-20261024.md).
    pub dev_write_kind: [u64; 12],
    /// Commit latency of a WAL unit, first txn submit to ack-eligible (WAL and every data write durable), log2 us
    /// buckets (bucket b = [2^(b-1), 2^b) us, 0 = < 1 us, last = open end): whole unit, WAL write alone, last data
    /// write alone (units without data skip the last). `cm_units` units; `cm_ahead` = device commands in flight when
    /// the units were submitted (sum). Units of >= 5 ms: `cm_slow`, and how many had a checkpoint running
    /// (`cm_slow_ckpt`), data held in the backlog (`cm_slow_backlog`), the WAL write completing after the data
    /// (`cm_slow_walfirst` = WAL done first, data last) and the sum of `ahead` (`cm_slow_ahead`).
    pub cm_lat: [u64; 20],
    pub cm_wal: [u64; 20],
    pub cm_data: [u64; 20],
    pub cm_units: u64,
    pub cm_ahead: u64,
    pub cm_slow: u64,
    pub cm_slow_ckpt: u64,
    pub cm_slow_backlog: u64,
    pub cm_slow_walfirst: u64,
    pub cm_slow_ahead: u64,
    /// Commit latency split of the `cm_units` units, ns summed: open (first txn submit -> sealed: group commit wait),
    /// queue (sealed -> WAL write submitted: in-flight unit cap, queue space), device (WAL write submitted -> its
    /// completion reaped; includes the core's time to the next reap), post (last completion reaped -> acked: the shard
    /// poll's remaining work, e.g. a merge slice, plus earlier units still in flight).
    pub cm_open_ns: u64,
    pub cm_queue_ns: u64,
    pub cm_dev_ns: u64,
    pub cm_post_ns: u64,
    /// Units whose WAL write was submitted while a background checkpoint write (of any shard) was in flight on the device, and their
    /// device ns (the `cm_dev_ns` share): WAL commit latency during checkpoint writes (adr 0021 am. 76).
    pub cm_ck_units: u64,
    pub cm_ck_dev_ns: u64,
    pub txns: u64,
    /// Omap run merge slices (adr 0476) and the entries they moved into the tree; slices that waited for
    /// a checkpoint's meta room; merge txns `validate` refused (retried).
    pub run_merges: u64,
    pub run_merged_ents: u64,
    pub run_merge_waits: u64,
    /// Polls a background merge (no limit waits on it) stood at the dirty soft mark (client txns keep the band to the
    /// hard mark).
    pub run_merge_dirty_waits: u64,
    pub run_txn_refused: u64,
    /// Re-logs of the floor unit's runs (ring liveness, adr 0476) and the run entries they wrote again.
    pub run_relogs: u64,
    /// Merge slices refused because their leaves were not resident (built again once the reads completed).
    pub run_merge_miss: u64,
    /// Page reads queued or in flight when those slices were refused (theirs and others').
    pub run_merge_miss_pages: u64,
    /// Tree merges started (adr 0476) by trigger: drain (page charge refusal, explicit), soft size, ring floor, idle.
    pub run_merge_starts: [u64; 4],
    /// Merge steps with runs left that moved nothing, by reason: no merge wanted (no trigger, no idle object), page loads
    /// pending, dirty pages at the hard mark, paced (ahead of the writes).
    pub run_merge_skips: [u64; 4],
    /// Idle marks taken (one per checkpoint interval with the shard polled: [`Shard::idle_mark`]).
    pub run_idle_marks: u64,
    /// Run compactions swapped in, their input runs and output entries; compactions dropped because an input left.
    pub run_compactions: u64,
    pub run_compacted_ents: u64,
    pub run_compact_lost: u64,
    pub run_helper_jobs: u64,
    pub run_helper_done: u64,
    pub run_helper_lost: u64,
    pub units: u64,
    pub pads: u64,
    pub wal_bytes: u64,
    /// Unit header + record bytes of those WAL blocks (the rest is padding to whole blocks).
    pub wal_payload: u64,
    pub data_blocks: u64,
    pub checkpoints: u64,
    pub ckpt_pages: u64,
    /// Elastic meta image pages a checkpoint pointed its root at (part of `ckpt_pages` when the image changed).
    pub ckpt_blob_pages: u64,
    pub forced_ckpts: u64,
    /// High-water mark of WAL ring blocks held by unreleased units (adr 0160 am. 4: ring right-sizing).
    pub wal_hw_blocks: u64,
    /// Data runs placed in a hole of a partly used window to keep whole windows for meta cells (adr 0021 am. 51).
    pub dense_allocs: u64,
    /// Data runs (`alloc_data`, adr 0475) handed out and their blocks (blocks / runs = mean extent of a data write), runs
    /// placed hole-first (`small_dense`), runs cut shorter than asked because no free run was that long (am. 3).
    pub data_runs: u64,
    pub data_run_blocks: u64,
    pub small_dense_allocs: u64,
    pub frag_cuts: u64,
    /// Txns written as multi-part chains (ADR 0028) and the units they used.
    pub multi_txns: u64,
    pub multi_parts: u64,
    /// Elastic meta cells taken from / given back to the data region.
    pub cells_added: u64,
    pub cells_released: u64,
    /// Elastic meta growth misses that waited for the checkpoint releasing the frees (`Shard::defer_growth`), and actual
    /// blocking failures (the shard turned meta-bound: statfs full).
    pub meta_grow_waits: u64,
    pub meta_grow_bound: u64,
    /// Checkpoints with no new WAL record (they only persist the lazy free's progress, adr 0021 am. 18).
    pub idle_ckpts: u64,
    /// Data writes that waited for device queue room (txns with more extents than the queue, adr 0066).
    pub backlog_writes: u64,
    /// Data writes that waited in the backlog for in-flight IO memory of the DMA budget (deferred copies, adr 0175 am. 4).
    pub backlog_dma: u64,
    /// Checkpoint start work done synchronously on the shard's core (begin: delta gc, meta housekeeping, bitmap chunk
    /// flush, freeze begin; then each freeze slice, adr 0021 am. 40): summed, and the longest single piece, ns; largest page
    /// count of one checkpoint.
    /// A long start stalls every op of the core (tail latency, doc/perf/tail-latency-20261015.md).
    pub ckpt_sync_ns: u64,
    pub ckpt_sync_max_ns: u64,
    pub ckpt_max_pages: u64,
    /// Sliced freeze (adr 0021 am. 40): freezes begun, freeze slices, polls a wanted checkpoint was held back, begins
    /// forced past the bound.
    pub ckpt_begins: u64,
    pub ckpt_slices: u64,
    pub ckpt_deferred: u64,
    /// Sliced checkpoint start (adr 0021 am. 80): start slices, incl. the one that begins the freeze.
    pub ckpt_start_slices: u64,
    /// Checkpoint wall time from freeze begin to durable root (sum, longest), ns (adr 0021 am. 43).
    pub ckpt_ns: u64,
    pub ckpt_max_ns: u64,
    /// Checkpoints started by trigger: 0 requested/forced, 1 space, 2 WAL ring, 3 dirty pages, 4 dirty bitmap chunks,
    /// 5 interval.
    pub ckpt_why: [u64; 6],
    /// `validate` refusals by reason (index = `dbg::BUSY` reason: 1 dead list, 2 dirty hard, 3 meta space, 4 data backlog,
    /// 5 device queue, 6 ready units, 7 WAL ring, 8 multi ready, 9 multi ring, 10 omap memtables full (adr 0610)).
    pub busy: [u64; 11],
    /// Meta space refusals (`busy[3]`) of a run page charge (the merge is pressed: `mg_want`).
    pub busy_meta_run: u64,
    /// Meta space refusals that force a checkpoint (or wait for the running one).
    pub busy_meta_ckpt: u64,
    /// Submits that reached the record encoding + path probes of `validate` (vs `txns` committed: the work refusals
    /// redid, adr 0021 am. 62).
    pub prepares: u64,
    /// Runtime deallocate of freed blocks (adr 0642): commands submitted, their ranges and device bytes; device latency
    /// of the completed ones (sum, longest), ns; failed commands; bytes that became allocatable while trims are off;
    /// allocations and meta growths that waited for a command in flight.
    pub trim_cmds: u64,
    pub trim_ranges: u64,
    pub trim_bytes: u64,
    pub trim_lat_ns: u64,
    pub trim_lat_max_ns: u64,
    pub trim_errors: u64,
    pub trim_skipped_bytes: u64,
    pub trim_waits: u64,
}

impl ShardStats {
    /// Add `o` into `self` (the `perf dump` sum over shards): counters and histogram buckets add, the `*_max*` fields and
    /// the WAL high-water mark take the larger value.
    pub fn merge(&mut self, o: &ShardStats) {
        macro_rules! add {
            ($($f:ident),* $(,)?) => { $( self.$f += o.$f; )* };
        }
        macro_rules! add_each {
            ($($f:ident),* $(,)?) => { $( for (a, b) in self.$f.iter_mut().zip(o.$f) { *a += b; } )* };
        }
        macro_rules! max {
            ($($f:ident),* $(,)?) => { $( self.$f = self.$f.max(o.$f); )* };
        }
        add!(
            io_completions,
            view_copy_bytes,
            dev_busy_ns,
            dev_read_bytes,
            dev_write_bytes,
            cm_units,
            cm_ahead,
            cm_slow,
            cm_slow_ckpt,
            cm_slow_backlog,
            cm_slow_walfirst,
            cm_slow_ahead,
            cm_open_ns,
            cm_queue_ns,
            cm_dev_ns,
            cm_post_ns,
            cm_ck_units,
            cm_ck_dev_ns,
            txns,
            run_merges,
            run_merged_ents,
            run_merge_waits,
            run_merge_dirty_waits,
            run_txn_refused,
            run_relogs,
            run_merge_miss,
            run_merge_miss_pages,
            run_idle_marks,
            run_compactions,
            run_compacted_ents,
            run_compact_lost,
            run_helper_jobs,
            run_helper_done,
            run_helper_lost,
            units,
            pads,
            wal_bytes,
            wal_payload,
            data_blocks,
            checkpoints,
            ckpt_pages,
            ckpt_blob_pages,
            forced_ckpts,
            dense_allocs,
            data_runs,
            data_run_blocks,
            small_dense_allocs,
            frag_cuts,
            multi_txns,
            multi_parts,
            cells_added,
            cells_released,
            meta_grow_waits,
            meta_grow_bound,
            idle_ckpts,
            backlog_writes,
            backlog_dma,
            ckpt_sync_ns,
            ckpt_begins,
            ckpt_slices,
            ckpt_deferred,
            ckpt_start_slices,
            ckpt_ns,
            busy_meta_run,
            busy_meta_ckpt,
            prepares,
            trim_cmds,
            trim_ranges,
            trim_bytes,
            trim_lat_ns,
            trim_errors,
            trim_skipped_bytes,
            trim_waits
        );
        add_each!(
            dev_write_kind,
            cm_lat,
            cm_wal,
            cm_data,
            run_merge_starts,
            run_merge_skips,
            ckpt_why,
            busy
        );
        max!(
            ckpt_sync_max_ns,
            ckpt_max_ns,
            ckpt_max_pages,
            wal_hw_blocks,
            trim_lat_max_ns
        );
    }
}

/// See [`Shard::gauges`].
#[derive(Debug, Default, Clone, Copy)]
pub struct ShardGauges {
    pub dirty_pages: u64,
    pub dirty_soft: u64,
    pub dirty_hard: u64,
    /// Pending pages of a running sliced freeze.
    pub freeze_left: u64,
    pub ckpt_running: bool,
    /// WAL ring blocks held by units not yet released by a checkpoint, and the ring size.
    pub wal_used: u64,
    pub wal_blocks: u64,
    /// Runtime deallocate on (adr 0642), blocks the command in flight holds, dirty windows (may hold blocks the device
    /// still maps), candidates (dirty windows that were whole free when marked; a walk drops those in use again, a
    /// command takes at most half of the whole free windows).
    pub trim_on: bool,
    pub trim_held: u64,
    pub trim_dirty_windows: u64,
    pub trim_cand_windows: u64,
}

/// Sliced checkpoint start (adr 0021 am. 80): what the start has done so far, one budget unit = one delta chain folded
/// or one bitmap chunk written into the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CkStart {
    /// Folding the chosen delta chains: the next one, how many were chosen (0 = not chosen yet).
    Fold(usize, usize),
    /// Writing the stale bitmap chunks, oldest first; the slice with room for the rest begins the freeze.
    Chunks,
}

/// Sliced freeze (adr 0021 am. 40): checkpoint facts taken at its begin.
#[derive(Debug)]
struct FzStart {
    lsn: u64,
    used_blocks: u64,
    idle: bool,
    released: Vec<(u64, u32)>,
    floor: u64,
}

/// See `Shard::data_backlog`.
struct Backlog<B>(VecDeque<(u64, Wr<B>, u64, Option<u64>)>, Stop);

/// Memory of a read's buffer ([`Shard::submit_read`], [`Shard::submit_io_read`]).
#[derive(Clone, Copy)]
enum Mem {
    /// May stay in the data cache: ordinary memory when the device reads into it, else deferrable DMA memory.
    Keep,
    /// Deferrable DMA memory (adr 0175 am. 4).
    Defer,
    /// In-flight IO memory (adr 0175 am. 4).
    Io,
}

/// A backlogged data write: its device buffer, or the bytes of a [`CopyRun`] copied into in-flight IO memory at submit.
enum Wr<B> {
    Buf(B),
    Copy(bytes::Bytes),
}

impl<B: IoBuf> Wr<B> {
    fn len(&self) -> usize {
        match self {
            Wr::Buf(b) => b.len(),
            Wr::Copy(s) => s.len(),
        }
    }
}

impl<B> std::fmt::Debug for Backlog<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Backlog({})", self.0.len())
    }
}

impl std::fmt::Debug for Unit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unit#{} {:?} ntxn={}", self.seq, self.st, self.ntxn)
    }
}

impl<D: BlockDev> Shard<D> {
    /// Pages missed by lookups since [`Shard::miss_log_clear`] (wake tokens, adr 0043 am. 9).
    pub fn miss_log(&self) -> &crate::toks::Toks<8> {
        self.state.tree.miss_log()
    }
    pub fn miss_log_clear(&mut self) {
        self.state.tree.miss_log_clear();
    }
    /// Residency lease page pins (adr 0043 am. 18, see [`crate::tree::Tree::pin_log`]).
    pub fn pin_log(&mut self, buf: Option<Vec<u64>>) -> Option<Vec<u64>> {
        self.state.tree.pin_log(buf)
    }
    pub fn pin_page(&mut self, addr: u64) {
        self.state.tree.pin(addr);
    }
    pub fn unpin_page(&mut self, addr: u64) {
        self.state.tree.unpin(addr);
    }
    pub fn pinned_pages(&self) -> usize {
        self.state.tree.pinned()
    }

    /// Mount: pick the newest valid root slot, load the meta bitmap and the data bitmap (`f` chunks), replay the
    /// WAL on top of the checkpointed tree, bump + persist the epoch (replayed state is checkpointed first, so
    /// the WAL is empty again), then serve. Blocking (spins `dev.poll` through `clk`); mount is a cold path.
    /// `read_only` (degraded offline export): load and replay only; no epoch write, no checkpoint, and the shard never
    /// submits a device write, deallocate or write-zeroes afterwards (txns and checkpoints are refused).
    pub fn mount<C: Clock>(
        mut dev: D,
        clk: &mut C,
        sb: &Superblock,
        dir: &ShardDir,
        mut cfg: ShardCfg,
        read_only: bool,
    ) -> Result<(Shard<D>, ReplayStats)> {
        if !(1..=OMAP_SCAN_PREFETCH_MAX_CHUNKS).contains(&cfg.omap_scan_prefetch_chunks) {
            return Err(StoreError::Invalid(
                "omap_scan_prefetch_chunks must be an integer in 1..=16",
            ));
        }
        if !(1..=OMAP_SCAN_PREFETCH_MAX_CHUNKS).contains(&cfg.omap_scan_prefetch_max_chunks) {
            return Err(StoreError::Invalid(
                "omap_scan_prefetch_max_chunks must be an integer in 1..=16",
            ));
        }
        let g = dev.geometry();
        if g.lba_size != sb.lba_size {
            return Err(StoreError::BadGeometry(
                "lba size changed since mkfs".into(),
            ));
        }
        let lpb = crate::dev::lbas_per_blk(&g);
        if u64::from(g.max_xfer_lbas) < lpb {
            return Err(StoreError::BadGeometry(
                "device transfer limit is smaller than a store block".into(),
            ));
        }
        if cfg.max_unit_blocks == 0 {
            return Err(StoreError::Invalid("max_unit_blocks must be nonzero"));
        }
        // A WAL unit is one device write. Keep the physical transfer bound while
        // preserving whole-transaction atomicity through the existing PART/END chain.
        let max_xfer_blk = crate::dev::max_xfer_blks(&g);
        cfg.max_unit_blocks = cfg.max_unit_blocks.min(max_xfer_blk as u32);
        let root = read_root(&mut dev, clk, dir)?;
        let tree_root = root
            .tree_ref()
            .map_err(|m| StoreError::Corrupt(format!("root slot: {m}")))?;
        let store_id = wal_store_id(sb, dir.shard);
        let geom = MetaGeom::new(dir, sb.node_size)?;
        let elastic = sb.features & FEAT_ELASTIC_META != 0;
        let img = read_meta_image_checked(&mut dev, clk, sb, &geom, &root, !cfg.repair_counters)?;
        let bm_cur = img.legacy;
        let bpp = geom.bpp;
        let cell_blocks = geom.cell_blocks(img.meta.ppc())?;
        // omap LSM engine (adr 0610): half of the shard's cache budget goes to its memtables and run block cache (the
        // omap leaves the tree); also during the S7 format upgrade, which fills it from the tree omap (adr 0611)
        let rocks_selected = sb.features & crate::layout::FEAT_OMAP_ROCKSDB != 0;
        if rocks_selected && (!cfg!(feature = "rocksdb") || !crate::upgrade::engine_on(sb)) {
            return Err(StoreError::Invalid("unsupported RocksDB OMAP format"));
        }
        #[cfg(feature = "rocksdb")]
        if rocks_selected && cfg.rocksdb.is_none() {
            return Err(StoreError::Invalid(
                "RocksDB store requires its explicit external database root",
            ));
        }
        #[cfg(feature = "splinterdb")]
        let splinter_mem = cfg.cache_pages / 2 * sb.node_size as usize;
        let splinter_selected = sb.features & crate::layout::FEAT_OMAP_SPLINTERDB != 0;
        if rocks_selected && splinter_selected {
            return Err(StoreError::Invalid(
                "multiple foreign OMAP engines selected",
            ));
        }
        if splinter_selected && (!cfg!(feature = "splinterdb") || !crate::upgrade::engine_on(sb)) {
            return Err(StoreError::Invalid("unsupported SplinterDB OMAP format"));
        }
        let ol = crate::upgrade::engine_on(sb).then(|| {
            let mem = cfg.cache_pages / 2 * sb.node_size as usize;
            cfg.cache_pages -= cfg.cache_pages / 2;
            olsm_drv::OlsmDrv::new(
                if rocks_selected || splinter_selected {
                    mem / 2
                } else {
                    mem
                },
                dir.wal_blocks as usize * BLK,
            )
        });
        #[cfg(feature = "rocksdb")]
        let mut rocks = None;
        #[cfg(feature = "splinterdb")]
        if sb.features & crate::layout::FEAT_OMAP_SPLINTERDB != 0 && cfg.splinterdb.is_none() {
            return Err(StoreError::Invalid(
                "SplinterDB store requires its explicit backing configuration",
            ));
        }
        #[cfg(feature = "splinterdb")]
        let mut splinter = None;
        let tcfg = TreeCfg {
            psz: sb.node_size as usize,
            shard: dir.shard,
            cache_pages: cfg.cache_pages,
            max_walk: cfg.max_walk_pages,
            compact_int: sb.features & crate::layout::FEAT_COMPACT_INT != 0,
            bg_compact: cfg.bg_compact,
        };
        let mut tree = Tree::new(tcfg, geom, img.meta, tree_root);
        // one checkpoint arena chunk = one largest device write
        tree.set_ckpt_chunk((max_xfer_blk / bpp).max(1) as usize);
        if !img.blob_pages.is_empty() {
            tree.set_blob(img.blob_pages, img.blob_crc);
        }
        tree.set_lazy(
            sb.features & crate::layout::FEAT_LAZY_FREE != 0 && elastic,
            img.dead,
        );
        tree.set_delta(
            sb.features & crate::layout::FEAT_LEAF_DELTA != 0 && elastic,
            sb.features & crate::layout::FEAT_DELTA_RELOG != 0,
            cfg.delta_cap_bytes,
            img.segs,
        );
        tree.set_delta_leaf_max(cfg.ckpt_delta_leaves);
        let mut state = State::new(tree, dir.new_alloc());
        if cfg.alloc_pool_chunks > 0 {
            state.alloc.set_pool_target(cfg.alloc_pool_chunks);
        }
        state.lsn = root.ckpt_lsn;
        state.repair_fence = cfg.repair_fence;
        if ol.is_some() {
            state.olsm_replay = Some(Vec::new());
        }
        let mut repaired_meta = Vec::new();
        let out = {
            let mut io = Sio::new(&mut dev, clk);
            // leaf deltas: the chains of the checkpointed state, before anything reads (or replays onto) a leaf - the
            // bitmap chunks live in leaves too
            for sg in state.tree.segdirs() {
                let bpp = state.tree.geom().bpp as u32;
                let reqs: Vec<(u64, u32)> = sg.pages.iter().map(|&(a, _)| (a, bpp)).collect();
                let bufs = io.read(&reqs)?;
                for (&(a, c), b) in sg.pages.iter().zip(&bufs) {
                    state.tree.load_delta_page(a, c, b, sg.seq)?;
                }
            }
            state.load_alloc(&mut io)?;
            // A census that fails (structural damage) fences nothing: the repair refuses on its own census, and the
            // writable repair mount only follows a clean dry pass over the same bytes.
            if cfg.repair_fence
                && let Ok(plan) = crate::fsck::repair_plan_shard(
                    io.dev,
                    io.clk,
                    sb,
                    dir,
                    &crate::obj::onode::fsck_refs,
                )
            {
                // The complete persisted-state census validated the cells, pages and allocator geometry before
                // any allocation or replay. Protect every missing cell block, including partially allocated cells.
                // cell_take dirties the allocator chunks just as metadata growth does. Until the checkpoint root
                // lands, a crash selects the old state and the next repair mount reconstructs this same fence.
                for &(b, n) in &plan.missing_meta {
                    if !state.alloc.reserve_named(b, n) {
                        return Err(StoreError::Corrupt(format!(
                            "repair fence: false-free metadata range {b}+{n} not reservable"
                        )));
                    }
                    state.cell_take(b, n);
                    repaired_meta.push((b, n));
                }
                for &(b, n) in &plan.missing {
                    if !state.alloc.reserve_named(b, n) {
                        return Err(StoreError::Corrupt(format!(
                            "repair fence: false-free range {b}+{n} not reservable"
                        )));
                    }
                }
            }
            #[cfg(feature = "elastic")]
            if !state.alloc.holes_clear() {
                return Err(StoreError::Corrupt(
                    "bitmap bits in a returned (unowned) chunk slot".into(),
                ));
            }
            if state.alloc.n_alloc() != root.used_blocks
                && !cfg.repair_counters
                && repaired_meta.is_empty()
            {
                return Err(StoreError::Corrupt(format!(
                    "bitmap chunks hold {} blocks, root slot says {}",
                    state.alloc.n_alloc(),
                    root.used_blocks
                )));
            }
            // every meta cell must be an allocated extent of the data region and cells must not overlap
            let mut prev_end = 0;
            for (start, blocks) in state.tree.meta.physical_extents(bpp) {
                if start < prev_end || !state.alloc.is_allocated(start, blocks) {
                    return Err(StoreError::Corrupt(format!(
                        "meta cell at block {start} is not an allocated extent"
                    )));
                }
                prev_end = start + u64::from(blocks);
            }
            let out = replay(&mut io, dir, &root, store_id, &mut state, &cfg.replay)?;
            if let Some(d) = &ol {
                #[cfg(feature = "rocksdb")]
                let rocks_ops =
                    rocks_selected.then(|| state.olsm_replay.clone().unwrap_or_default());
                #[cfg(feature = "splinterdb")]
                let replay_ops = splinter_replay_ops(splinter_selected, &state.olsm_replay);
                let engine = olsm_drv::mount_olsm(&mut io, &mut state, d.mt_soft as u64)?;
                #[cfg(feature = "rocksdb")]
                let engine = if let Some(ops) = rocks_ops {
                    let (driver, recovered, buffers) = rocks_drv::mount(
                        cfg.rocksdb.as_ref().expect("validated root"),
                        sb,
                        dir.shard,
                        engine,
                        &ops,
                        out.last_lsn,
                        cfg.cache_pages * sb.node_size as usize / 2,
                    )?;
                    rocks = Some(driver);
                    state.rocks_mem = Some(buffers);
                    recovered
                } else {
                    engine
                };
                #[cfg(feature = "splinterdb")]
                let engine = if let Some(replay_ops) = replay_ops {
                    let mut foreign_cfg = cfg.splinterdb.clone().expect("validated");
                    if foreign_cfg.cpu.is_none() {
                        // Cold path only. Production owner threads are already pinned.
                        let cpu = unsafe { libc::sched_getcpu() };
                        if cpu < 0 {
                            return Err(StoreError::Invalid(
                                "cannot identify SplinterDB owner CPU",
                            ));
                        }
                        foreign_cfg.cpu = Some(cpu as usize);
                    }
                    let (driver, engine, buffers) = splinter_drv::mount(
                        &foreign_cfg,
                        sb,
                        dir.shard,
                        engine,
                        &replay_ops,
                        out.last_lsn,
                        splinter_mem,
                    )?;
                    splinter = Some(driver);
                    state.splinter_mem = Some(buffers);
                    engine
                } else {
                    engine
                };
                state.olsm = Some(engine);
            }
            out
        };
        // no page read is in flight at mount: what the replay freed by address needs no reaping
        state.tree.take_gone(&mut Vec::new());
        let epoch = root.epoch.max(out.max_epoch) + 1;
        let replayed = out.last_lsn > root.ckpt_lsn;
        let ring_used = out.ring.iter().map(|u| u.blocks).sum();
        // user floors = 1.5 x the in-flight window `R`; sys txns stop at R/2 (= floor/3), pure shrinks at 0 (am. 21)
        let data_reserve = dir.data_total() * cfg.data_reserve_pct as u64 / 100 * 3 / 2;
        let meta_reserve = (state.tree.meta.len() / 32).max(12) * 3 / 2;
        let trim = Trim::new(dev.dealloc_limits(), lpb);
        let ckpt_phase = ckpt_phase(&sb.osd_fsid, dir.shard, sb.shards, cfg.ckpt_interval_ns);
        let free_q: VecDeque<(u64, Vec<(u64, u32)>)> = out.frees.into_iter().collect();
        let free_q_blocks = free_q
            .iter()
            .flat_map(|e| e.1.iter())
            .map(|f| u64::from(f.1))
            .sum();
        let mut sh = Shard {
            shard: dir.shard,
            store_id,
            lpb,
            max_xfer_blk: max_xfer_blk as usize,
            free_q,
            free_q_blocks,
            limbo: VecDeque::new(),
            trim,
            trim_wait: false,
            read_epoch: 1,
            readers: VecDeque::new(),
            reads: HashMap::default(),
            epoch,
            next_lsn: out.last_lsn + 1,
            durable_lsn: out.last_lsn,
            ckpt_lsn: root.ckpt_lsn,
            next_onode_id: root.next_onode_id,
            ck: None,
            ck_requested: false,
            ck_fg: false,
            ckpt_due: None,
            ckpt_phase,
            fzs: None,
            ck_gate: None,
            ck_left: 0,
            ck_defer: None,
            ck_start: None,
            ck_start_polls: 0,
            ck_t0: None,
            bm_cur,
            data_reserve,
            mig_hold: 0,
            #[cfg(feature = "elastic")]
            mig_want: 0,
            #[cfg(feature = "elastic")]
            lend: crate::lend::Ctl {
                on: cfg.lend_auto && dir.chunk_blocks != 0,
                chunk: dir.chunk_blocks,
                wm: dir.chunk_blocks * cfg.lend_wm_pct as u64 / 100,
                open: true,
                // until the owner's first `Size` (its first poll after mount): enough to admit while it is on its way
                pool: 2 * dir.chunk_blocks,
                retry_ns: cfg.lend_retry_ms * 1_000_000,
                ..Default::default()
            },
            meta_reserve,
            #[cfg(feature = "elastic")]
            evac_fence: None,
            cell_blocks: if elastic { cell_blocks } else { 0 },
            pending_cells: Vec::new(),
            pending_cell_chunks: Vec::new(),
            fz_cells: Vec::new(),
            shrunk: Vec::new(),
            meta_blocked: None,
            last_meta_growth_failure: None,
            meta_growth_failure_sequence: 0,
            meta_no_run: false,
            meta_retry: false,
            meta_wait: None,
            meta_cure: false,
            reclaim: 0,
            meta_peak: 0,
            meta_peak_prev: 0,
            page_reads: Vec::new(),
            page_stale: Vec::new(),
            gone_buf: Vec::new(),
            deferred: std::collections::VecDeque::new(),
            want_buf: Vec::new(),
            page_dma_wait: false,
            page_dma_submits: 0,
            wake: false,
            ring: out.ring,
            ring_used,
            head_pos: out.head_pos,
            head_crc: out.head_crc,
            root_seq: root.seq,
            tail: (root.wal_tail_pos, root.wal_tail_prev_crc, root.tail_lsn()),
            pipeline: VecDeque::new(),
            next_unit_seq: 1,
            inflight_units: 0,
            failed: None,
            failed_reported: false,
            read_only,
            failed_at: None,
            scratch: Enc::new(),
            pool_payload: Vec::new(),
            pool_tokens: Vec::new(),
            data_backlog: Backlog(VecDeque::new(), Stop::Empty),
            adm: Admit::new(
                sb.shards as usize,
                max_xfer_blk * BLK as u64,
                dev.queue_depth() - wal_floor(cfg.max_inflight_units, dev.queue_depth()),
            ),
            comps: Vec::new(),
            bg_next_ns: 0,
            bg_miss_loads: None,
            // Like background tree work, cell repair changes checkpoint state without advancing the WAL lsn.
            bg_dirty: !repaired_meta.is_empty(),
            repaired_meta,
            mg: None,
            cps: Vec::new(),
            compact_available: 0,
            compact_ready: Vec::new(),
            compact_remote: Vec::new(),
            compact_incarnation: COMPACTION_INCARNATION
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            compact_serial: 0,
            mg_mark: (0, 0, 0),
            mg_drain: false,
            mg_want: false,
            mg_full: false,
            rl_wait: false,
            mg_loads: false,
            mg_slice: None,
            mg_ps_per_ent: 0,
            #[cfg(feature = "lab")]
            lab_dev_tick_ns: 0,
            #[cfg(feature = "lab")]
            lab_dev_skew_ns: std::sync::atomic::AtomicU64::new(0),
            #[cfg(feature = "lab")]
            lab_merge_ps: 0,
            mg_pace: (0, 0, 0),
            fg_inflight: 0,
            pool: crate::runs::PoolShare::join(
                cfg.run_pool.clone().unwrap_or_default(),
                cfg.run_soft_bytes,
            ),
            dev_clk: crate::fastclock::Mono::at(std::time::Instant::now()),
            dev_busy_since: None,
            bg_ns: 0,
            dev_idle: cfg.dev_idle.clone().unwrap_or_default(),
            dev_view: Default::default(),
            pages: cfg.page_pool.clone().and_then(|p| {
                let base = state.tree.cap();
                crate::pagepool::PageShare::join(
                    p,
                    dir.shard as usize,
                    base,
                    crate::obj::MIN_CACHE_PAGES.min(base),
                )
            }),
            trim_view: Default::default(),
            poll_now: 0,
            pre: Default::default(),
            pre_out: Vec::new(),
            ol,
            dc_held: 0,
            #[cfg(feature = "rocksdb")]
            rocks,
            #[cfg(feature = "splinterdb")]
            splinter,
            read_admission_waiting: false,
            stats: ShardStats::default(),
            state,
            dir: dir.clone(),
            cfg,
            dev,
        };
        // a slot left busy by an earlier mount in this process: nothing is in flight now
        sh.dev_idle.edge(dir.shard as usize, false);
        // and its share of the device's checkpoint write budget (adr 0021 am. 76), the deallocate turn (adr 0642) and its
        // share of the admission window (adr 0643-device-admission-fifo); the first shard of the device starts the window
        // (at its upper bound)
        sh.dev_idle.ck_reset(dir.shard as usize);
        sh.dev_idle.trim_give(dir.shard as usize);
        sh.dev_idle.admit.reset(dir.shard as usize);
        sh.dev_idle.admit.start(sh.adm.hi());
        // cells the last checkpoint emptied (crash or shutdown before the next one): give them back at the first poll,
        // nothing else would start a checkpoint on an idle shard (adr 0021 am. 21)
        sh.reclaim = sh.reclaim_blocks();
        sh.ck_requested |= sh.reclaim > 0;
        if read_only {
            // Degraded read-only mount: the replayed state lives in memory only. No epoch/root-slot write, no
            // post-replay checkpoint, no reclaim checkpoint, no trim marks and no chunk lending (nothing may reach the
            // device; `read_only` keeps the shard from submitting any write later). Reads work on the in-memory tree.
            sh.ck_requested = false;
            #[cfg(feature = "elastic")]
            {
                sh.lend.on = false;
            }
            sh.state.alloc.maintain();
            sh.state.alloc.clear_pool_misses();
            return Ok((sh, out.stats));
        }
        // persist the new epoch before anything else is written (`wal.rs` epoch rule): the checkpoint below may seal
        // units (merges, relogs) before its own root lands
        {
            let new_root = RootSlot {
                seq: root.seq + 1,
                epoch,
                ..root.clone()
            };
            let slot = if new_root.seq & 1 == 0 {
                dir.root_a
            } else {
                dir.root_b
            };
            let mut io = Sio::new(&mut sh.dev, clk);
            io.write_one(slot, &new_root.encode())?;
            sh.root_seq = new_root.seq;
        }
        if replayed || !sh.repaired_meta.is_empty() {
            // make the replayed state durable; WAL becomes empty (the mount waits for it: foreground)
            sh.ck_requested = true;
            sh.ck_fg = true;
            let mut ev = Vec::new();
            // No abort on a stall: the checkpoint has no bound of its own (a large replay writes many pages, a slow or
            // recovering device may pause), and failing the mount would only turn a slow start into a down OSD. A
            // stretch without progress is reported every Stall period instead of hanging the start silently; a
            // failed shard or a dead device still ends the wait.
            let mut stall = Stall::new("mount checkpoint");
            loop {
                let ios = sh.stats.io_completions;
                sh.poll(clk.now(), &mut ev);
                // progress, or a reported stall (then the next period starts: report, never abort)
                if !ev.is_empty()
                    || sh.stats.io_completions != ios
                    || stall.expired(format_args!(
                        "shard {}, after WAL replay; still waiting",
                        dir.shard
                    ))
                {
                    stall.progress();
                }
                if let Some(e) = ev.iter().find_map(|e| match e {
                    Event::Failed(e) => Some(e.clone()),
                    _ => None,
                }) {
                    return Err(e);
                }
                if ev.iter().any(|e| matches!(e, Event::Released { .. })) {
                    break;
                }
                ev.clear();
                if sh.dev.is_dead() {
                    return Err(StoreError::Io(IoError::Aborted));
                }
                let h = sh.dev.next_deadline();
                clk.idle(h);
            }
        }
        // the free map is durable, what the device deallocated is not (no format change): every whole free window is
        // trimmed once (after the replay and its checkpoint: what replayed records allocate or free awaits no longer)
        sh.trim.mark_all(&sh.state.alloc);
        // loading and replay are not the write path: count pool misses from here on
        sh.state.alloc.maintain();
        sh.state.alloc.clear_pool_misses();
        Ok((sh, out.stats))
    }

    /// Cache point lookups of the given key tags (first byte); coherent with every applied record.
    pub fn enable_point_cache(&mut self, tags: &[u8]) {
        self.state.pc.enable(tags, self.cfg.point_cache);
    }

    pub fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }

    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    /// LSN the next txn will get.
    pub fn next_lsn(&self) -> u64 {
        self.next_lsn
    }
    /// Highest LSN acked (durable, contiguous).
    pub fn durable_lsn(&self) -> u64 {
        self.durable_lsn
    }
    pub fn ckpt_lsn(&self) -> u64 {
        self.ckpt_lsn
    }
    pub fn dev(&mut self) -> &mut D {
        &mut self.dev
    }
    pub fn dir(&self) -> &ShardDir {
        &self.dir
    }
    pub fn ring_free_blocks(&self) -> u64 {
        self.dir.wal_blocks - self.ring_used
    }
    pub fn is_failed(&self) -> bool {
        self.failed.is_some()
    }
    /// Units not yet acked (open + ready + in flight).
    pub fn pending_units(&self) -> usize {
        self.pipeline.len()
    }
    /// User data floor in blocks (adr 0021 am. 21).
    pub fn data_reserve(&self) -> u64 {
        self.data_reserve
    }
    /// User floor: the data reserve plus the migration headroom held here.
    #[inline]
    fn user_floor(&self) -> u64 {
        self.floors(AllocClass::User).0
    }
    /// Blocks a PG copy could still reserve here: free (held / reclaimable count, the alloc path forces the checkpoint
    /// that releases them) above the user floor and the headroom already held (adr 0031 am. 4).
    pub fn mig_room(&self) -> u64 {
        let a = &self.state.alloc;
        (a.n_free() + a.n_held() + self.reclaim).saturating_sub(self.user_floor())
    }
    /// Reserve `n` blocks of migration headroom; false = no room now.
    pub fn mig_hold(&mut self, n: u64) -> bool {
        if self.failed.is_some() || self.mig_room() < n {
            return false;
        }
        self.mig_hold += n;
        true
    }
    /// Elastic pool: blocks the deferred moves into this shard need (0 = none). The shard borrows chunks until its room
    /// covers them and keeps them from reclaim; the owner of the deferrals sets and clears it.
    #[cfg(feature = "elastic")]
    pub fn set_mig_want(&mut self, n: u64) {
        self.mig_want = n;
    }
    /// A deferred move wants more room than the shard has and the pool may still lend: keep polling (asking).
    #[cfg(feature = "elastic")]
    #[inline]
    fn mig_wanting(&self) -> bool {
        self.mig_want > self.mig_room() && self.lend.may_wait()
    }
    /// Give back `n` blocks of migration headroom (a copy batch is about to use them, or the move ended).
    pub fn mig_unhold(&mut self, n: u64) {
        self.mig_hold = self.mig_hold.saturating_sub(n);
    }
    /// Migration headroom held now (blocks).
    pub fn mig_held(&self) -> u64 {
        self.mig_hold
    }
    /// Elastic meta cell size in blocks (0 = legacy fixed meta region).
    pub fn cell_blocks(&self) -> u64 {
        self.cell_blocks
    }
    /// Elastic meta growth is blocked by fragmentation: enough free blocks in total, but not enough whole-page runs
    /// (adr 0021 am. 12, 47). Not set when the data region or the meta image is full (a sweep cannot help there).
    pub fn meta_growth_blocked(&self) -> bool {
        self.meta_bound() && self.meta_no_run
    }
    /// Elastic meta growth failed and no pending checkpoint can cure it (adr 0021 S13): statfs charges the stricter fill,
    /// `write_room` counts no growable pages. A miss the pending frees can cure only waits (`meta_wait`).
    fn meta_bound(&self) -> bool {
        self.meta_blocked.is_some() && self.meta_wait.is_none()
    }
    /// Most recent actual meta-growth failure, retained after the shard becomes growable again.
    pub fn last_meta_growth_failure(&self) -> Option<MetaGrowthFailure> {
        self.last_meta_growth_failure
    }
    /// Defrag may run cell sweeps (adr 0021 am. 51).
    pub fn defrag_cells(&self) -> bool {
        self.cfg.defrag_cells
    }
    /// Take one elastic meta cell now (end of a cell sweep, adr 0021 am. 51): the window the sweep emptied becomes tree
    /// space before any data allocation can break it again. Durable with the next checkpoint like any grown cell. False
    /// when whole-page extents or image headroom are exhausted. Growth during a freeze is deferred.
    pub fn grow_meta_cell(&mut self) -> bool {
        if self.cell_blocks == 0 || self.failed.is_some() {
            return false;
        }
        // a sweep made the run: the search is worth retrying even though no block was freed
        self.meta_retry = true;
        let want = self.meta_free() + 1;
        self.grow_meta(want, self.data_reserve / 3 + self.mig_hold)
    }
    /// A freeze is running (cells reserved now join the meta space when it ends).
    pub fn freeze_active(&self) -> bool {
        self.state.tree.fz_active()
    }
    /// Background merges wait for a checkpoint (adr 0021 am. 33).
    pub fn bg_dirty(&self) -> bool {
        self.bg_dirty
    }
    pub fn ckpt_active(&self) -> bool {
        self.ck.is_some() || self.fzs.is_some()
    }
    /// A requested checkpoint is in its sliced start: the tree takes the cycle's deltas and bitmap chunks before the
    /// freeze begins (adr 0021 am. 80).
    pub fn ckpt_starting(&self) -> bool {
        self.ck_start.is_some()
    }
    /// Omap run floor (adr 0476): lsn of the oldest live run, `next_lsn` without runs. A checkpoint keeps
    /// the ring units at and above it.
    fn run_floor(&self) -> u64 {
        self.wal_floor().unwrap_or(self.next_lsn)
    }
    /// WAL floor: the oldest record a checkpoint must keep in the ring, of the omap runs (adr 0476) or the omap LSM
    /// memtables (adr 0610); `None` = neither holds one.
    fn wal_floor(&self) -> Option<u64> {
        match (self.state.runs.floor(), self.olsm_floor()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    /// Ring blocks the WAL floor holds (units at or above it); `ring_used` minus these is what a checkpoint can release.
    pub fn floor_blocks(&self) -> u64 {
        self.wal_floor().map_or(0, |f| self.floor_blocks_at(f))
    }
    /// Ring blocks of the units at or above lsn `f`.
    fn floor_blocks_at(&self, f: u64) -> u64 {
        // a PART unit of record r has last_lsn r - 1 and a PAD first_lsn of the unit after it: compare by the later of both
        let i = self
            .ring
            .partition_point(|u| u.last_lsn.max(u.first_lsn) < f);
        match self.ring.get(i) {
            None => 0,
            Some(_) if i == 0 => self.ring_used,
            Some(u) => (self.head_pos + self.dir.wal_blocks - u.pos) % self.dir.wal_blocks,
        }
    }
    /// End of the core loop's pass (receive, cross-core pump, timers; before the thread's device flush): the group
    /// commit for the txns submitted since the store poll of this pass. An idle WAL seals them now (one unit for the
    /// whole pass), a busy one keeps collecting by the group-commit rule (adr 0021 am. 67).
    pub fn end_pass(&mut self) {
        if self
            .pipeline
            .back()
            .is_some_and(|u| u.st == UState::Open && u.ntxn > 0)
        {
            self.group_commit();
        }
        // one doorbell for the pass's commands, the sealed unit included (SPDK; kernel: the thread's flush)
        self.dev.issue();
    }

    /// Group commit (end of the core's poll and of its pass): seal the open unit if a WAL slot is available (and,
    /// with `wal_coalesce`, the WAL is not already busy with enough units unless the unit is full: then it keeps
    /// collecting until a completion), submit ready units.
    fn group_commit(&mut self) {
        if self.failed.is_some() {
            return;
        }
        if self.pipeline.back().is_some_and(|u| {
            u.st == UState::Open
                && u.ntxn > 0
                && (self.cfg.wal_coalesce == 0
                    || self.inflight_units < self.cfg.wal_coalesce
                    || unit_full(u.payload.len(), u.ntxn))
        }) && self.inflight_units < self.cfg.max_inflight_units
            && !self.pipeline.iter().any(|u| u.st == UState::Ready)
        {
            self.close_open();
        }
        self.submit_ready();
        self.dev_note(); // a unit sealed here opens the busy period now (its txns' data writes may have opened it)
    }

    /// A PAD unit (fills the ring end before a wrap): no record, no lsn of its own.
    fn is_pad(u: &RingUnit) -> bool {
        u.last_lsn < u.first_lsn && !u.part
    }
    fn ring_full_by_floor(&self) -> bool {
        self.floor_blocks() * 100 >= self.dir.wal_blocks * self.cfg.ckpt_wal_pct as u64
    }
    /// The object layer may log a run (adr 0476): the ring part above the checkpoint ring threshold holds
    /// the admission headroom of a client txn and of a merge plus a unit of slack, the runs' memory is below twice the
    /// soft size and their logged bytes (about their memory) fit below that threshold, and the last merge found meta room.
    pub fn run_room(&self) -> bool {
        self.run_room_for(0)
    }
    /// [`Shard::run_room`] for a run of `bytes` WAL op bytes: the ring part above the threshold also holds twice the
    /// re-log reserve it may raise (the record and its re-log).
    pub fn run_room_for(&self, bytes: usize) -> bool {
        let pct = self.cfg.ckpt_wal_pct.min(100) as u64;
        if self.cfg.run_soft_bytes == 0
            || self.mg_full
            || self.dir.wal_blocks * (100 - pct) / 100
                < 5 * self.cfg.max_unit_blocks as u64 + 2 * self.relog_blocks(bytes)
        {
            return false;
        }
        let p = self.pool.pool();
        !self.run_ring_full() && p.bytes() < 2 * p.soft()
    }
    /// The runs' memory (about their logged bytes) reached the checkpoint ring threshold: no new run is admitted, so a
    /// merge is pressed ([`Shard::merge_pressed`]).
    fn run_ring_full(&self) -> bool {
        let pct = self.cfg.ckpt_wal_pct.min(100) as u64;
        self.run_mem() >= (self.dir.wal_blocks * BLK as u64 * pct / 100) as usize
    }
    /// Object `id` may log another run: it holds fewer than `run_max` runs above the barrier of a tree merge of it in
    /// progress (adr 0476 step 4): the merge's inputs are being retired and leave at its last slice, so they never hold
    /// back new runs (counted, they left a few slots for the merge's whole duration: every new run waited for a forced
    /// compaction or the merge's end, doc/perf/bfill-rate-20261026.md).
    pub fn run_room_obj(&self, id: u64) -> bool {
        let barrier = self.merge_barrier(id);
        self.state
            .runs
            .obj(id)
            .is_none_or(|o| o.runs.iter().filter(|r| r.lsn > barrier).count() < self.cfg.run_max)
    }
    /// A queued run of `bytes` WAL op bytes of object `id` has to wait for merges: the object holds `run_max` runs, or the
    /// pool has no room while merges are under way. The one admission test of [`Stage::run_admit`], also asked of a
    /// parked txn that waits on it (`Store::resume_queue`): only a change of this answer lets it proceed.
    pub fn run_admit_blocks(&self, id: u64, bytes: usize) -> bool {
        !self.run_room_obj(id) || (!self.run_room_for(bytes) && self.run_drains())
    }
    /// Order lsn up to which a tree merge in progress of object `id` takes its runs (0: none).
    fn merge_barrier(&self, id: u64) -> u64 {
        match &self.mg {
            Some((m, upto, _)) if *m == id => *upto,
            _ => 0,
        }
    }
    /// Lab timeline gauges (`diag::TL_NAMES`): run pool bytes, its soft size, this shard's run memory, live run entries,
    /// a merge in progress.
    pub fn run_gauges(&self) -> [u64; 5] {
        let p = self.pool.pool();
        [
            p.bytes() as u64,
            p.soft() as u64,
            self.run_mem() as u64,
            self.state.runs.entries() as u64,
            u64::from(self.mg.is_some()),
        ]
    }
    /// One line of omap-run / checkpoint state for `tell dump_pgs` (a parked FIFO head that never prepares).
    pub fn run_diag(&self) -> String {
        format!(
            "runs={} run_mem={} room={} mg={:?} cps={} remote={} drain={} want={} full={} rl_wait={} mg_loads={} \
             ckpts={} forced={} merges={} compactions={} busy={:?} dirty={} ring={}/{}",
            self.state.runs.entries(),
            self.run_mem(),
            self.run_room_for(0),
            self.mg.as_ref().map(|m| (m.0, m.1)),
            self.cps.len(),
            self.compact_remote.len(),
            self.mg_drain,
            self.mg_want,
            self.mg_full,
            self.rl_wait,
            self.mg_loads,
            self.stats.checkpoints,
            self.stats.forced_ckpts,
            self.stats.run_merges,
            self.stats.run_compactions,
            self.stats.busy,
            self.state.tree.dirty_pages(),
            self.ring_used,
            self.dir.wal_blocks,
        )
    }

    /// Heap bytes of the runs and of a compaction being built.
    fn run_mem(&self) -> usize {
        self.state.runs.mem()
            + self.cps.iter().map(|c| c.mem()).sum::<usize>()
            + self.compaction_reserved()
    }

    /// Before each poll: `helpers` = helper cores take work (more than one core, not stopping); `credit` = how many of
    /// them have room for a job of this core now. Omap LSM rounds go to helpers whenever there are any (they wait for a
    /// credit); run compactions are prepared for helpers up to the credit (one per free helper core, the rest run
    /// inline). Prepared jobs beyond a shrunk credit return inline.
    pub fn compaction_helpers(&mut self, helpers: bool, credit: usize) {
        self.olsm_helpers(helpers);
        self.compact_available = if helpers && self.cfg.run_helpers {
            credit
        } else {
            0
        };
        if self.compact_ready.len() > self.compact_available {
            while self.compact_ready.len() > self.compact_available {
                let job = self.compact_ready.pop().expect("len checked");
                self.compact_remote.retain(|r| r.0 != job.id);
                self.cps.push(job.compaction);
            }
            self.pool.publish(self.run_mem());
        }
    }

    /// A job for a helper core: a prepared omap LSM flush round (`flush`), else a merge round or a run compaction.
    pub fn take_compaction(&mut self, flush: bool) -> Option<HelperJob> {
        if flush {
            return self.olsm_take(true).map(HelperJob::Olsm);
        }
        if let Some(j) = self.olsm_take(false) {
            return Some(HelperJob::Olsm(j));
        }
        let job = self.compact_ready.pop()?;
        self.stats.run_helper_jobs += 1;
        Some(HelperJob::Run(Box::new(job)))
    }

    /// A job back from a helper. `false` = not this shard's current job (stale mount or attempt: dropped).
    pub fn return_compaction(&mut self, job: HelperJob, publish: bool) -> bool {
        match job {
            HelperJob::Olsm(j) => self.olsm_return(j),
            HelperJob::Run(j) => self.return_run_compaction(j, publish),
        }
    }

    /// A returned immutable continuation; stale incarnation/attempts never replace the current reservation.
    fn return_run_compaction(&mut self, job: Box<RunCompactionJob>, publish: bool) -> bool {
        let Some(i) = self.compact_remote.iter().position(|r| r.0 == job.id) else {
            return false;
        };
        self.compact_remote.swap_remove(i);
        if self.failed.is_some() || !publish {
            self.stats.run_helper_lost += 1;
        } else if !job.compaction.built() {
            // A helper declined work (shutdown/backpressure); retain normal owner progress.
            let mut c = job.compaction;
            c.keep_inline();
            self.cps.push(c);
        } else {
            let (id, nout) = (job.compaction.id(), job.compaction.len() as u64);
            self.stats.run_helper_done += 1;
            if self.state.runs.swap_in(job.compaction) {
                self.stats.run_compactions += 1;
                self.stats.run_compacted_ents += nout;
            } else {
                self.stats.run_compact_lost += 1;
                self.stats.run_helper_lost += 1;
            }
            self.state.runs.add_cand(id);
        }
        self.pool.publish(self.run_mem());
        true
    }

    /// Identity of the next job this shard hands to a helper.
    fn next_compaction_id(&mut self) -> CompactionId {
        self.compact_serial = self
            .compact_serial
            .checked_add(1)
            .expect("compaction attempt exhausted");
        CompactionId {
            shard: self.shard,
            incarnation: self.compact_incarnation,
            serial: self.compact_serial,
        }
    }

    pub fn compaction_reserved(&self) -> usize {
        self.compact_remote.iter().map(|r| r.3).sum()
    }
    pub fn compaction_pool_reserved(&self) -> usize {
        self.pool.pool().helper_bytes()
    }
    /// The runs are over their soft size: the shard's own and the pool's (a shard holding less than its own soft size
    /// leaves the merging to the members over theirs).
    fn run_over(&self) -> bool {
        let p = self.pool.pool();
        self.run_mem() >= self.cfg.run_soft_bytes && p.bytes() >= p.soft()
    }
    /// Merge every run into the tree now (the following polls run the slices) instead of waiting for a trigger.
    pub fn drain_runs(&mut self) {
        if !self.state.runs.is_empty() {
            self.mg_drain = true;
        }
    }
    /// Merges are under way and make run room (a queued txn may wait for them instead of taking the tree path).
    pub fn run_drains(&self) -> bool {
        !self.mg_full && !self.state.runs.is_empty()
    }
    /// Tree pages the runs add once merged: one per 4 KiB of leaf bytes (split leaves stay at least half full). The
    /// copy-on-write pages a merge dirties are transient (the checkpoint frees the old copies): merges size themselves to
    /// the meta room left (`merge_pages`).
    pub fn run_pages(&self) -> usize {
        self.run_pages_with(0)
    }
    fn run_pages_with(&self, bytes: usize) -> usize {
        (self.state.runs.tree_bytes() + bytes).div_ceil(BLK)
    }
    /// Live checkpoint / back-pressure gauges (`perf dump`, adr 0021 am. 43).
    pub fn gauges(&self) -> ShardGauges {
        ShardGauges {
            dirty_pages: self.state.tree.dirty_pages() as u64,
            dirty_soft: self.cfg.dirty_soft_pages as u64,
            dirty_hard: self.cfg.dirty_hard_pages as u64,
            freeze_left: self.state.tree.fz_left() as u64,
            ckpt_running: self.ckpt_active() || self.ckpt_starting(),
            wal_used: self.ring_used,
            wal_blocks: self.dir.wal_blocks,
            trim_on: self.trim.on(),
            trim_held: self.trim.held(),
            trim_dirty_windows: self.trim.dirty_windows(),
            trim_cand_windows: self.trim.cand_windows(),
        }
    }
    pub fn alloc_buf(&mut self, blocks: usize) -> D::Buf {
        self.dev.alloc_buf(blocks * BLK)
    }

    /// Store data buffer of `blocks` the caller overwrites completely (no zeroing): `None` = refused by the device's
    /// DMA budget now ([`BlockDev::try_alloc_buf_uninit`]); the caller holds nothing while it retries.
    pub fn try_alloc_data(&mut self, blocks: usize) -> Option<D::Buf> {
        self.dev.try_alloc_buf_uninit(blocks * BLK)
    }

    /// [`Shard::try_alloc_data`] for store metadata IO whose buffer lives only while the IO is in flight
    /// ([`BlockDev::try_alloc_io_uninit`]).
    pub fn try_alloc_io(&mut self, blocks: usize) -> Option<D::Buf> {
        self.dev.try_alloc_io_uninit(blocks * BLK)
    }
    /// Data write buffer viewing `data` in place (whole blocks), if the device can DMA from it (adr 0061 am. 4).
    /// `None`: the caller copies `data` into a device buffer; the bytes are counted in `stats.view_copy_bytes`.
    pub fn view_buf(&mut self, data: &bytes::Bytes) -> Option<D::Buf> {
        debug_assert!(data.len().is_multiple_of(BLK));
        let v = self.dev.view_buf(data);
        if v.is_none() {
            self.stats.view_copy_bytes += data.len() as u64;
        }
        v
    }
    /// Tree page reads are in flight or waiting for a queue slot.
    pub fn loads_pending(&self) -> bool {
        !self.deferred.is_empty() || self.page_reads.iter().any(Option::is_some)
    }

    /// Tree page reads submitted to the device and not completed yet (tests, readahead depth).
    pub fn page_reads_inflight(&self) -> usize {
        self.page_reads.iter().flatten().count()
    }

    /// Page IO waits for DMA memory, not for the device (adr 0175 am. 4: backpressure, not a stalled request): a
    /// refusal stands and either no device command is outstanding, or a page the tracked FIFO head waits for is still
    /// unsent among the deferred ones, whatever unrelated IO is in flight. Scans the deferred pages: called only once a
    /// deadline has passed.
    pub(crate) fn page_dma_waiting(&self) -> bool {
        let deps = &self.state.tree.dependencies;
        self.page_dma_wait
            && (self.dev.queue_space() == self.dev.queue_depth()
                || self.deferred.iter().any(|w| deps.tracks(w.addr)))
    }

    pub(crate) fn page_dma_submits(&self) -> u64 {
        self.page_dma_submits
    }

    /// Tree page size in bytes.
    pub fn tree_psz(&self) -> usize {
        self.state.tree.psz()
    }

    /// Operator cache drop: evict the clean tree pages ([`crate::tree::Tree::drop_clean`]); `(dropped, kept)`.
    pub fn drop_tree_clean(&mut self) -> (u64, u64) {
        self.state.tree.drop_clean()
    }

    pub fn tree_stats(&self) -> crate::tree::TreeStats {
        self.state.tree.stats
    }

    /// RAM held by this shard (operator memory accounting).
    pub fn mem(&self) -> ShardMem {
        let n =
            |q: &VecDeque<(u64, Vec<(u64, u32)>)>| q.iter().map(|e| e.1.len() as u64).sum::<u64>();
        ShardMem {
            tree: self.state.tree.mem(),
            point_entries: self.state.pc.len() as u64,
            point_bytes: self.state.pc.bytes(),
            alloc_bytes: self.state.alloc.mem_bytes(),
            alloc_chunks: self.state.alloc.live_chunks() + self.state.alloc.pool_len() as u64,
            alloc_pool_misses: self.state.alloc.pool_misses(),
            free_q_extents: n(&self.free_q),
            limbo_extents: n(&self.limbo),
            ring_units: self.ring.len() as u64,
            pipeline_units: self.pipeline.len() as u64,
            pipeline_bytes: self
                .pipeline
                .iter()
                .map(|u| u.payload.capacity() as u64)
                .sum(),
            read_map: self.reads.len() as u64,
            ckpt_bytes: self
                .ck
                .as_ref()
                .map_or(0, |c| (c.fr.arena.bytes() + c.fr.bitmap.capacity()) as u64)
                + self.state.tree.spare_arena_bytes() as u64,
            run_entries: self.state.runs.entries() as u64,
            run_bytes: self.run_mem() as u64,
        }
    }

    /// Elastic meta cells `(start block, blocks)`: extents of the data region holding tree pages.
    pub fn meta_cells(&self) -> Vec<(u64, u64)> {
        self.state
            .tree
            .meta
            .physical_extents(self.state.tree.geom().bpp)
            .into_iter()
            .map(|(s, n)| (s, u64::from(n)))
            .collect()
    }

    pub fn statfs(&self) -> Statfs {
        let a = &self.state.alloc;
        let t = &self.state.tree;
        #[cfg(any(feature = "rocksdb", feature = "splinterdb"))]
        let external_space: Option<(u64, u64)> = None;
        #[cfg(feature = "rocksdb")]
        let external_space = self
            .rocks
            .as_ref()
            .map(|r| r.client.space.sample())
            .or(external_space);
        #[cfg(feature = "splinterdb")]
        let external_space = self
            .splinter
            .as_ref()
            .map(|s| {
                let (_, total) = s.client.space.sample();
                (s.client.available(), total.min(s.client.capacity()))
            })
            .or(external_space);
        Statfs {
            #[cfg(any(feature = "rocksdb", feature = "splinterdb"))]
            external_space,
            data_blocks: a.usable_len(),
            data_used: a.n_alloc(),
            // blocks a deallocate holds are free space (back at its completion)
            data_free: a.n_free() + self.trim.held(),
            data_held: a.n_held() - self.trim.held(),
            data_reclaim: self.reclaim,
            #[cfg(feature = "elastic")]
            data_lendable: self.lend.lendable(),
            data_reserved: a.n_reserved(),
            data_reserve: self.data_reserve,
            mig_hold: self.mig_hold,
            meta_reserve: self.meta_reserve as u64,
            meta_pages: t.meta.len() as u64,
            meta_used: t.meta.used() as u64,
            meta_free: t.meta.free() as u64,
            elastic: self.cell_blocks != 0,
            meta_cells: t.meta.n_cells() as u64,
            // committed cells only (pending ones are still allocator reservations)
            meta_cell_blocks: (t.meta.n_cells() - self.pending_cells.len()) as u64
                * self.cell_blocks,
            meta_cell_used: t.meta.cell_used() as u64,
            meta_base_pages: t.meta.base_pages() as u64,
            meta_bpp: t.geom().bpp,
            meta_grow_blocked: self.meta_bound(),
            dirty_pages: t.dirty_pages() as u64,
            run_pages: self.run_pages() as u64,
            omap_bytes: self.olsm_bytes().unwrap_or(0),
            cached_pages: t.resident_pages() as u64,
            ckpt_lsn: self.ckpt_lsn,
            durable_lsn: self.durable_lsn,
            wal_blocks: self.dir.wal_blocks,
            wal_free: self.dir.wal_blocks - self.ring_used,
        }
    }

    #[track_caller]
    fn fail(&mut self, e: StoreError) {
        // a failed shard reaps nothing more: its share of the device's checkpoint write budget (adr 0021 am. 76), the
        // deallocate turn (adr 0642) and its window bytes, in flight or waiting (adr 0643-device-admission-fifo),
        // go back now
        self.dev_idle.ck_reset(self.dir.shard as usize);
        self.dev_idle.trim_give(self.dir.shard as usize);
        self.dev_idle.admit.reset(self.dir.shard as usize);
        if self.failed.is_none() {
            self.failed = Some(e);
            self.failed_at = Some(std::panic::Location::caller());
        }
    }

    /// Where the shard failed (source location of the failing step; operator log / `diag`).
    pub fn failed_at(&self) -> Option<&'static std::panic::Location<'static>> {
        self.failed_at
    }

    // ---------------------------------------------------------------- allocation (M2.3)

    /// Reserve `n` contiguous data blocks (next-fit); returns the engine block address. The reservation is
    /// consumed by `submit` (data extent) or returned by `unreserve`. Leaves the hard reserve (`data_reserve_pct`)
    /// to `alloc_priv`.
    ///
    /// Errors: `Busy` = no space now but freed blocks are waiting for a checkpoint (one was forced); retry after
    /// `Event::Released`. `NoSpace` = nothing pending, the device is full.
    pub fn alloc(&mut self, n: u32) -> Result<u64> {
        let (r, l) = self.class_floor(AllocClass::User);
        self.alloc_with(n, r, l)
    }

    /// System class (replica applies, admitted writes, maps): stops at a third of the user floor; the last third is
    /// left to `alloc_priv` (pure shrinking txns, adr 0021 am. 21). Never below the migration headroom.
    pub fn alloc_sys(&mut self, n: u32) -> Result<u64> {
        let (r, l) = self.class_floor(AllocClass::Sys);
        self.alloc_with(n, r, l)
    }

    /// System class, longest free run in `min..=max` blocks ([`Alloc::reserve_upto`]): the OLSM lease takes a
    /// [`crate::olsm::CHUNK_MIN`]..=[`crate::olsm::CHUNK_MAX`] piece instead of one fixed 16-block extent
    /// (adr 0610 am. 5). The floors are those of [`Shard::alloc_sys`].
    pub fn alloc_sys_upto(&mut self, min: u32, max: u32) -> Result<(u64, u32)> {
        let (r, l) = self.class_floor(AllocClass::Sys);
        self.alloc_find(min, Some(max), r, l, false)
    }

    /// Like `alloc` but may use the hard reserve (for txns that free space, e.g. removes/trims).
    pub fn alloc_priv(&mut self, n: u32) -> Result<u64> {
        self.alloc_with(n, 0, 0)
    }

    /// Data blocks and meta pages a txn of class `c` leaves free (adr 0021 am. 4/21): user txns the full reserves,
    /// sys txns a third, private ones (pure shrinks) nothing; the migration headroom (adr 0031 am. 4) sits on top of
    /// the user and sys data floors. Allocation (`class_floor`) and the space preflight (`room_view`) use these.
    pub(crate) fn floors(&self, c: AllocClass) -> (u64, u64) {
        let (h, r, m) = (self.mig_hold, self.data_reserve, self.meta_reserve as u64);
        match c {
            AllocClass::User => (r + h, m),
            AllocClass::Sys => (r / 3 + h, m / 3),
            AllocClass::Priv => (0, 0),
        }
    }

    /// Floor and lower borrowing bound of an allocation class (`alloc`, `alloc_sys`, `alloc_priv`): the bound is half
    /// way down to the next class's floor.
    fn class_floor(&self, c: AllocClass) -> (u64, u64) {
        let (h, r) = (self.mig_hold, self.data_reserve);
        let lower = match c {
            AllocClass::User => r * 2 / 3 + h,
            AllocClass::Sys => r / 6 + h,
            AllocClass::Priv => 0,
        };
        (self.floors(c).0, lower)
    }

    /// Space preflight inputs for a txn applied as class `c` (see [`RoomView`]).
    pub(crate) fn room_view(&self, c: AllocClass) -> RoomView {
        let a = &self.state.alloc;
        let t = &self.state.tree;
        let (data_floor, meta_floor) = self.floors(c);
        let runs = if c == AllocClass::User {
            self.run_pages() as u64
        } else {
            0
        };
        let data_free = a.n_free() + a.n_held() + self.reclaim;
        #[cfg(feature = "elastic")]
        let data_free = data_free + self.lend.lendable();
        RoomView {
            data_floor,
            meta_floor: meta_floor + runs,
            data_free,
            data_reclaim: self.reclaim,
            meta_used: t.meta.used() as u64,
            meta_free: t.meta.free() as u64,
            dirty_pages: t.dirty_pages() as u64,
            meta_bpp: t.geom().bpp,
            meta_growable: self.cell_blocks != 0 && !self.meta_bound(),
        }
    }

    /// A data run of at most `n` blocks (`Stage::alloc_upto`, adr 0475): runs of at most `small_dense` blocks fill holes
    /// first; a shard with free blocks but no run of `n` is fragmented, not full: it hands out its longest free run whole
    /// (am. 3, `Alloc::reserve_cut`, counted as a cut) instead of forcing a checkpoint, and never more than the class floor
    /// leaves. `(engine block, blocks)`; the caller writes the rest in further runs.
    pub fn alloc_data(&mut self, n: u32, c: AllocClass) -> Result<(u64, u32)> {
        let (r, l) = self.class_floor(c);
        let x = self.alloc_find(n, None, r, l, true)?;
        self.stats.data_runs += 1;
        self.stats.data_run_blocks += x.1 as u64;
        Ok(x)
    }

    /// The floor `reserve` of a class may be borrowed down to `lower` (half way to the next class) against the blocks the
    /// next checkpoint releases (`free_q_blocks`, adr 0021 am. 33): they are free again within one checkpoint, so the
    /// class floors hold again once it ran, the next class keeps half its margin meanwhile, and an admitted txn does not
    /// wait for that checkpoint inside `queue` (core stall).
    fn alloc_with(&mut self, n: u32, reserve: u64, lower: u64) -> Result<u64> {
        self.alloc_find(n, None, reserve, lower, false).map(|x| x.0)
    }

    /// One allocation request: exactly `n` blocks (`max = None`), the longest free run in `n..=max`, or with `data` a run
    /// of at most `n` blocks (`alloc_data`).
    fn alloc_find(
        &mut self,
        n: u32,
        max: Option<u32>,
        reserve: u64,
        lower: u64,
        data: bool,
    ) -> Result<(u64, u32)> {
        if self.failed.is_some() {
            return Err(StoreError::Failed);
        }
        let reserve = reserve.saturating_sub(self.free_q_blocks).max(lower);
        // a miss that waited for a deallocate: the command completed, its windows are free (adr 0642)
        self.trim_wait &= self.trim.in_flight();
        let a = &mut self.state.alloc;
        // a data run may be cut: never more than the floor leaves
        let n = if data {
            n.min(a.n_free().saturating_sub(reserve).min(u32::MAX as u64) as u32)
        } else {
            n
        };
        if n > 0 && a.n_free() >= n as u64 + reserve {
            // few whole windows left: a short run fills a hole first, so meta growth still finds cells (am. 51). Elastic
            // meta only; short runs only (a long run in a hole leaves a remainder later runs cannot use); not on tiny
            // shards (keeping windows there starves everything else)
            let keep = self.cfg.keep_windows as u64;
            if max.is_none()
                && self.cell_blocks != 0
                && (n as u64) <= crate::alloc::WIN / 8
                && a.n_windows() as u64 >= 4 * keep
                && a.free_windows() <= keep
                && a.free_windows() + self.trim.held_windows() <= keep
                && let Some(b) = a.reserve_dense(n)
            {
                self.stats.dense_allocs += 1;
                return Ok((b, n));
            }
            if data
                && n <= self.cfg.small_dense
                && let Some(b) = a.reserve_dense(n)
            {
                self.stats.small_dense_allocs += 1;
                return Ok((b, n));
            }
            let got = match max {
                None if data => a.reserve_cut(n),
                None => a.reserve(n).map(|b| (b, n)),
                Some(m) => a.reserve_upto(n, m),
            };
            if let Some(x) = got {
                self.stats.frag_cuts += u64::from(x.1 < n);
                return Ok(x);
            }
        }
        // not found: would a checkpoint (or draining readers) release enough?
        if self.reclaim > 0 && self.cfg.auto_ckpt {
            // empty meta cells hold the space: the next checkpoint gives them back, also those the meta peak keeps
            self.meta_peak = 0;
            self.meta_peak_prev = 0;
            self.ck_fg = true;
            if !self.ckpt_active() {
                self.ck_requested = true;
                self.stats.forced_ckpts += 1;
            }
            return Err(StoreError::Busy);
        }
        if a.n_held() > self.trim.held() {
            self.ck_fg = true;
            if self.cfg.auto_ckpt && !self.ckpt_active() && self.next_lsn - 1 > self.ckpt_lsn {
                self.ck_requested = true;
                self.stats.forced_ckpts += 1;
            }
            return Err(StoreError::Busy);
        }
        // a deallocate in flight holds free windows: they are back at its completion (no checkpoint needed)
        if self.trim_miss() {
            return Err(StoreError::Busy);
        }
        // elastic pool (adr 0021 am. 52): no space in the shard is not the device being full while the pool may have a chunk
        // or another shard could give one back (am. 82): ask now (the next `Store::poll` sends it) and park the txn (Busy)
        // until the answer
        #[cfg(feature = "elastic")]
        if self.lend.may_wait() {
            self.lend.want = true;
            return Err(StoreError::Busy);
        }
        Err(StoreError::NoSpace)
    }

    /// Reserved blocks not used go back to the allocator. Every give-back of a reservation and every release of held
    /// blocks goes through here or [`Self::release_held`]: the part inside a chunk under evacuation is fenced again.
    pub fn unreserve(&mut self, blk: u64, n: u32) {
        self.state.alloc.unreserve(blk, n);
        #[cfg(feature = "elastic")]
        self.evac_refence(blk, n);
        self.trim.unbusy(&self.state.alloc, blk, u64::from(n));
    }

    /// Held blocks become free (checkpoint passed, no reader left); fenced again like [`Self::unreserve`]. Their windows
    /// are dirty (adr 0642).
    fn release_held(&mut self, blk: u64, n: u32) {
        self.state.alloc.release_held(blk, n);
        #[cfg(feature = "elastic")]
        self.evac_refence(blk, n);
        if self.trim.on() {
            self.trim.freed(&self.state.alloc, blk, u64::from(n));
        } else {
            self.stats.trim_skipped_bytes += u64::from(n) * BLK as u64;
        }
    }

    /// Give back what a staged txn that will not be submitted holds: its data reservations and its pre-write claims.
    pub fn unreserve_txn(&mut self, txn: &Txn<D::Buf>) {
        for (b, buf) in &txn.data {
            self.unreserve(*b, (buf.len() / BLK) as u32);
        }
        for c in &txn.copies {
            self.unreserve(c.blk, (c.src.len() / BLK) as u32);
        }
        for c in &txn.pre {
            self.pre_unclaim(c.id);
        }
    }

    // ---------------------------------------------------------------- pre-write (adr 0477)

    /// Write `piece` (whole blocks, at most one device transfer, filled receive memory nobody writes again) ahead into
    /// free blocks reserved for it. Nothing refers to those blocks until a txn claims the piece (`Txn::pre`, by the
    /// address of its bytes; memory the device cannot DMA from is copied once). `None` = not written ahead (no
    /// reservation above the user floor or no contiguous run, no queue room above the WAL floor, a data backlog, or
    /// writes waiting for the device window): the txn writes the data itself, as without pre-write. Never forces a
    /// checkpoint or asks the pool.
    pub fn pre_write(&mut self, piece: &bytes::Bytes) -> Option<crate::pre::PreId> {
        let n = piece.len() / BLK;
        if self.failed.is_some()
            || self.read_only
            || n == 0
            || !piece.len().is_multiple_of(BLK)
            || n > self.max_xfer_blk
            || !self.data_backlog.0.is_empty()
            || self.dev.queue_space() <= self.data_floor()
        {
            self.pre.stats.skipped += 1;
            return None;
        }
        // the device window (adr 0643-device-admission-fifo): only when nothing waits for it, a piece written ahead must
        // not pass writes that arrived earlier. Asked before any block is reserved: a reservation given back stays a hole
        // behind the allocator's next-fit cursor, and a refused stream would spread its data over such holes
        let me = self.dir.shard as usize;
        let len = piece.len() as u64;
        let Some(start) = self.adm.take_now(&self.dev_idle.admit, me, len) else {
            self.pre.stats.skipped += 1;
            return None;
        };
        // a device that cannot DMA from the payload memory gets a copy: the one the txn makes otherwise (it takes the
        // piece). Store data IO of the DMA budget: refused = not written ahead (adr 0175 am. 4)
        let (buf, copied) = match self.view_buf(piece) {
            Some(b) => (Some(b), false),
            None => {
                let b = self.dev.try_alloc_buf_uninit(piece.len()).map(|mut b| {
                    b.copy_from_slice(piece);
                    b
                });
                (b, true)
            }
        };
        let Some(buf) = buf else {
            // the ticket will never be submitted: it counts as done
            self.dev_idle.admit.give(me, len);
            self.pre.stats.skipped += 1;
            return None;
        };
        let blk = {
            let (floor, _) = self.class_floor(AllocClass::User);
            let a = &mut self.state.alloc;
            if a.n_free() < n as u64 + floor {
                None
            } else {
                a.reserve(n as u32)
            }
        };
        let Some(blk) = blk else {
            // the ticket will never be submitted: it counts as done
            self.dev_idle.admit.give(me, len);
            self.pre.stats.skipped += 1;
            return None;
        };
        self.pre.stats.copied += u64::from(copied);
        let (id, idx) = self.pre.insert(piece, blk, n as u32);
        let probe = self.adm.submitted(&self.dev_idle.admit, start, len);
        if self
            .dev
            .submit_write(blk * self.lpb, buf, K_PRE | probe | u64::from(idx))
            .is_err()
        {
            self.adm.unsubmitted(&self.dev_idle.admit, me, len, probe);
            self.pre.abort_insert(id);
            self.unreserve(blk, n as u32);
            self.pre.stats.skipped += 1;
            return None;
        }
        self.dev_note();
        Some(id)
    }

    /// Pieces that stopped being open so far (`PreTab::closed`): a ticket holder looks again only when it moved.
    pub fn pre_closed(&self) -> u64 {
        self.pre.closed()
    }

    /// Bytes of one data run (`Stage::write_raw_one`): the pre-write piece that a run claims whole.
    pub fn pre_piece(&self) -> usize {
        self.max_xfer_blk.min(crate::obj::onode::MAX_RUN as usize) * BLK
    }

    /// Piece `id` is still open: neither taken by a txn nor released (a holder of its ticket still has to release it).
    pub fn pre_open(&self, id: crate::pre::PreId) -> bool {
        self.pre.is_open(id)
    }

    /// The piece will not be claimed (its frame is gone): its blocks return to free space (after its write landed).
    pub fn pre_release(&mut self, id: crate::pre::PreId) {
        if let Some((b, n)) = self.pre.release(id) {
            self.unreserve(b, n);
        }
    }

    /// Release every unclaimed piece whose bytes lie in `[lo, hi)` (a staged txn's payload: nothing claims them later).
    pub(crate) fn pre_release_within(&mut self, lo: usize, hi: usize) {
        if !self.pre.has_open() {
            return;
        }
        let mut out = std::mem::take(&mut self.pre_out);
        self.pre.release_within(lo, hi, &mut out);
        for &(b, n) in &out {
            self.unreserve(b, n);
        }
        out.clear();
        self.pre_out = out;
    }

    /// Claim the piece whose bytes start at `ptr` for a staged run of `max` blocks from there: its handle, first block
    /// and the blocks claimed (`<= max`).
    pub(crate) fn pre_claim(
        &mut self,
        ptr: usize,
        max: u32,
    ) -> Option<(crate::pre::PreId, u64, u32)> {
        self.pre.claim(ptr, max)
    }

    /// A claiming txn is discarded before submit: the piece is released.
    pub(crate) fn pre_unclaim(&mut self, id: crate::pre::PreId) {
        if let Some((b, n)) = self.pre.unclaim(id) {
            self.unreserve(b, n);
        }
    }

    /// Pre-write counters.
    pub fn pre_stats(&self) -> crate::pre::PreStats {
        self.pre.stats
    }

    /// Pre-written pieces not finished (claimable, released or committed with the write in flight).
    pub fn pre_live(&self) -> usize {
        self.pre.live()
    }

    /// Defrag destination (adr 0021 am. 33): `n` blocks in a partly used window (`Alloc::reserve_dense`), user floor.
    /// `NoSpace` = no such run now (the move is skipped).
    pub fn alloc_dense(&mut self, n: u32) -> Result<u64> {
        if self.failed.is_some() {
            return Err(StoreError::Failed);
        }
        let floor = self.user_floor();
        let a = &mut self.state.alloc;
        if a.n_free() >= n as u64 + floor
            && let Some(b) = a.reserve_dense(n)
        {
            return Ok(b);
        }
        Err(StoreError::NoSpace)
    }

    /// A chunk granted durably (adr 0021 am. 49) becomes borrowed slot `slot` of this shard (allocator + directory).
    #[cfg(feature = "elastic")]
    pub fn lend_add(&mut self, slot: u32, phys: u64) {
        let k = slot as usize;
        self.state.alloc.lend_add(k, phys);
        // the borrower may never have written it, the lender's frees may not have been trimmed: trim it whole
        self.trim
            .freed(&self.state.alloc, phys, self.dir.chunk_blocks);
        if self.dir.lent.len() <= k {
            self.dir.lent.resize(k + 1, crate::alloc::HOLE);
        }
        self.dir.lent[k] = phys;
    }

    /// Pool space the near-full checkpoint trigger (`space_low`) counts (0 without the elastic pool): only while a request is
    /// on its way, and only the free pool (a chunk another shard still has to evacuate is not near). A shard that does not
    /// wait for a chunk keeps the static cadence: counting the whole pool let held blocks eat the base under heavy churn
    /// (bench rw64k: 5x fewer checkpoints, 1.2 GB held, +19 % cpu/op).
    #[inline]
    fn lend_coming(&self) -> u64 {
        #[cfg(feature = "elastic")]
        return if self.lend.inflight {
            self.lend.pool_hint()
        } else {
            0
        };
        #[cfg(not(feature = "elastic"))]
        0
    }

    /// Should this shard send a pool request now (called from the store poll, never per write)? Marks it in flight.
    /// `Some(short)`: send it; short = the allocation gate failed or a deferred move lacks room (am. 82: with the pool
    /// dry it waits for a chunk given back on demand).
    #[cfg(feature = "elastic")]
    pub fn lend_wants(&mut self, now: Nanos) -> Option<bool> {
        // headroom = whole free windows (1 MiB runs), not free blocks: scattered holes of a churned shard count as free
        // blocks but cannot take a long write (adr 0021 am. 56)
        let free = (self.free_windows() * crate::alloc::WIN)
            .saturating_sub(self.user_floor() + self.mig_want);
        self.lend
            .need(free, now)
            .then(|| self.lend.want || self.mig_want > self.mig_room())
    }

    /// The pool owner answered: a durable grant becomes a borrowed slot, a denial closes the pool for a while.
    #[cfg(feature = "elastic")]
    pub fn lend_answer(&mut self, grant: Option<(u32, u64)>, pool: u64, now: Nanos) {
        if let Some((slot, phys)) = grant {
            self.lend_add(slot, phys);
        }
        self.lend.reply(grant.is_some(), pool, now);
    }

    /// Run memory released by any member of the run pool so far (progress marker of parked txns: run room is the
    /// pool's, [`crate::runs::RunPool::freed`]).
    #[inline]
    pub fn run_freed(&self) -> u64 {
        self.pool.pool().freed()
    }

    /// Pool answers received so far (progress marker of parked txns).
    #[inline]
    pub fn lend_epoch(&self) -> u64 {
        #[cfg(feature = "elastic")]
        return self.lend.epoch;
        #[cfg(not(feature = "elastic"))]
        0
    }

    /// Take borrowed slot `slot` out of use before its return is written (adr 0021 am. 49). False = the chunk holds
    /// allocated, reserved or held blocks (a checkpoint has not passed its last free yet): nothing changed.
    #[cfg(feature = "elastic")]
    pub fn lend_remove(&mut self, slot: u32) -> bool {
        if !self.state.alloc.lend_remove(slot as usize) {
            return false;
        }
        self.dir.lent[slot as usize] = crate::alloc::HOLE;
        true
    }

    /// The pool grew after this shard was denied (adr 0021 am. 57): open again, parked txns retry.
    #[cfg(feature = "elastic")]
    pub fn lend_grew(&mut self, pool: u64) {
        self.lend.grew(pool);
    }

    /// Reclaim runs (adr 0021 am. 57, am. 61): the pool in use and no request of this shard pending (a shard that asks
    /// gives nothing back).
    #[cfg(feature = "elastic")]
    pub fn reclaim_on(&self) -> bool {
        self.lend.on && !self.lend.inflight && !self.lend.want
    }

    /// Could the shard give back an empty chunk holding `whole` blocks in whole free windows (adr 0021 am. 57)? It keeps
    /// `reclaim_keep` in whole free windows without it.
    #[cfg(feature = "elastic")]
    pub fn reclaim_room(&self, whole: u64) -> bool {
        (self.free_windows() * crate::alloc::WIN).saturating_sub(whole) >= self.reclaim_keep()
    }

    /// Blocks in whole free windows a shard keeps when it gives a chunk back (adr 0021 am. 57): measured like the request
    /// watermark (`lend_wants`: whole free windows above the user floor), the watermark plus the hysteresis
    /// (`reclaim_hyst_pct` % of the base): no ping-pong between return and request.
    #[cfg(feature = "elastic")]
    pub fn reclaim_keep(&self) -> u64 {
        let hyst = self.state.alloc.base_blocks() * self.cfg.reclaim_hyst_pct as u64 / 100;
        self.user_floor() + self.mig_want + self.lend.wm + hyst
    }

    /// Borrowed slot `slot`: `(engine block or HOLE, busy blocks)`, blocks the deallocate in flight holds counted free
    /// (adr 0642: back at its completion; `lend_remove` refuses the chunk until then).
    #[cfg(feature = "elastic")]
    pub fn lent_slot(&self, slot: u32) -> (u64, u64) {
        let (p, busy) = self.state.alloc.lent_slot(slot as usize);
        if p == crate::alloc::HOLE || self.trim.held() == 0 {
            return (p, busy);
        }
        let end = p + self.dir.chunk_blocks;
        let trim: u64 = self
            .trim
            .runs()
            .iter()
            .map(|&(b, n)| (b + u64::from(n)).min(end).saturating_sub(b.max(p)))
            .sum();
        (p, busy - trim)
    }

    /// Blocks in whole free windows of borrowed slot `slot` (0 for a hole), deallocate-held blocks counted free.
    #[cfg(feature = "elastic")]
    pub fn slot_whole_free(&self, slot: u32) -> u64 {
        let a = &self.state.alloc;
        let (p, _) = a.lent_slot(slot as usize);
        let Some(w0) = (p != crate::alloc::HOLE).then(|| a.window_of(p)).flatten() else {
            return 0;
        };
        let nw = (self.dir.chunk_blocks / crate::alloc::WIN) as usize;
        (w0..w0 + nw)
            .filter(|&w| a.window_busy(w) == self.trim.held_in(w))
            .count() as u64
            * crate::alloc::WIN
    }

    /// Evacuation move pacing (am. 82: evacuations run only while another shard waits for the chunk): ns per block at
    /// `reclaim_mbps`, client load or not.
    #[cfg(feature = "elastic")]
    pub fn reclaim_ns_per_block(&self) -> u64 {
        BLK as u64 * 1000 / self.cfg.reclaim_mbps.max(1) as u64
    }

    /// Fence borrowed slot `slot` for its evacuation (adr 0021 am. 57): every free block of the chunk is reserved, and stays
    /// so as blocks inside come free. Returns the chunk's window range. None = a hole or a fence is already set.
    #[cfg(feature = "elastic")]
    pub fn evac_fence(&mut self, slot: u32) -> Option<std::ops::Range<usize>> {
        let (p, _) = self.state.alloc.lent_slot(slot as usize);
        if p == crate::alloc::HOLE || self.evac_fence.is_some() {
            return None;
        }
        let a = &mut self.state.alloc;
        let w0 = a.window_of(p)?;
        let ws = w0..w0 + (self.dir.chunk_blocks / crate::alloc::WIN) as usize;
        let mut runs = Vec::new();
        for w in ws.clone() {
            a.fence_window(w, &mut runs);
        }
        self.evac_fence = Some((p, self.dir.chunk_blocks, runs));
        Some(ws)
    }

    /// Give the fence back (end or abort of an evacuation).
    #[cfg(feature = "elastic")]
    pub fn evac_unfence(&mut self) {
        if let Some((_, _, runs)) = self.evac_fence.take() {
            for (b, n) in runs {
                self.state.alloc.unreserve(b, n);
            }
        }
    }

    /// Blocks `[b, b+n)` came free: fence the part inside the chunk under evacuation (one Option check otherwise).
    #[cfg(feature = "elastic")]
    #[inline]
    fn evac_refence(&mut self, b: u64, n: u32) {
        let Some((s, len, runs)) = self.evac_fence.as_mut() else {
            return;
        };
        let (lo, hi) = (b.max(*s), (b + n as u64).min(*s + *len));
        if lo >= hi {
            return;
        }
        let a = &mut self.state.alloc;
        if let (Some(w0), Some(w1)) = (a.window_of(lo), a.window_of(hi - 1)) {
            for w in w0..=w1 {
                a.fence_window(w, runs);
            }
        }
    }

    /// Evacuation destination (adr 0021 am. 57): `n` blocks anywhere but the fenced chunk, above the user floor; a hole
    /// of a partly used window first (`Alloc::reserve_hole`, am. 82: the move keeps the whole free windows the shard
    /// counts as its headroom), a whole free window last. No checkpoint forced, no pool request. `NoSpace` = not now.
    #[cfg(feature = "elastic")]
    pub fn alloc_evac(&mut self, n: u32) -> Result<u64> {
        if self.failed.is_some() {
            return Err(StoreError::Failed);
        }
        let floor = self.user_floor();
        let a = &mut self.state.alloc;
        if a.n_free() >= n as u64 + floor
            && let Some(b) = a.reserve_hole(n).or_else(|| a.reserve(n))
        {
            return Ok(b);
        }
        Err(StoreError::NoSpace)
    }

    /// False-free metadata-cell ranges the repair mount allocated (each range returned once).
    pub fn take_repaired_meta(&mut self) -> Vec<(u64, u32)> {
        std::mem::take(&mut self.repaired_meta)
    }

    /// Degraded read-only mount: the shard never writes to its device.
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Ask for a checkpoint at the next `poll` (no-op if nothing changed since the last one).
    pub fn request_checkpoint(&mut self) {
        #[cfg(feature = "splinterdb")]
        if self.splinter.is_some() {
            self.request_omap_flush();
        }
        self.ck_requested = true;
        self.ck_fg = true;
    }

    // ---------------------------------------------------------------- runtime deallocate (adr 0642)

    /// Blocks the next deallocate may hold: half of what is allocatable above the user floor and one meta cell (the
    /// reserves under every floor are never held by a deallocate), and half of the whole free windows (the headroom of
    /// meta growth, lending and reclaim).
    fn trim_cap(&self) -> u64 {
        let a = &self.state.alloc;
        (a.n_free()
            .saturating_sub(self.user_floor() + self.cell_blocks)
            / 2)
        .min(a.free_windows() / 2 * crate::alloc::WIN)
    }

    /// Free blocks, those the deallocate in flight holds included (back at its completion).
    pub fn free_blocks(&self) -> u64 {
        self.state.alloc.n_free() + self.trim.held()
    }

    /// Whole free windows (1 MiB runs: the headroom of lending, reclaim and meta growth), those the deallocate in flight
    /// holds included (back at its completion).
    pub fn free_windows(&self) -> u64 {
        self.state.alloc.free_windows() + self.trim.held_windows()
    }

    /// Blocks of relative window `w` the deallocate in flight holds (free again at its completion, outside any fence:
    /// defrag leaves such windows alone).
    pub fn trim_held_in(&self, w: usize) -> u64 {
        self.trim.held_in(w)
    }

    /// Free runs of the shard, in no particular order: allocatable blocks and the runs the deallocate in flight holds
    /// (free space the allocator hands out again at its completion).
    pub fn for_each_free(&self, mut f: impl FnMut(u64, u64)) {
        self.state.alloc.for_each_free(&mut f);
        if self.trim.held() > 0 {
            for &(b, n) in self.trim.runs() {
                f(b, u64::from(n));
            }
        }
    }

    /// Store clock (ns) before which this shard starts no deallocate (the pause after its last one); 0 = none due.
    /// Sim fixtures advance their clock to it.
    pub fn trim_due(&self) -> u64 {
        if self.trim.ready() {
            self.trim.pause_until()
        } else {
            0
        }
    }

    /// An allocation or meta growth missed while the deallocate in flight holds free windows: they are back at its
    /// completion (one command, about one device idle gap long); no command starts before the next allocation or growth
    /// attempt finds none held. False = no deallocate holds anything (the miss is real).
    fn trim_miss(&mut self) -> bool {
        if self.trim.held() == 0 {
            return false;
        }
        self.trim_wait = true;
        self.stats.trim_waits += 1;
        true
    }

    /// Send the next deallocate. Called only from a poll of an idle shard (nothing queued, in flight or due: the
    /// quiescent return of [`Self::poll`]), so no client IO of this shard ever waits behind one. One command per device:
    /// the shard takes the device's turn (`DevIdle::trim_take`) once every queue of the device, its own included, was
    /// quiet for `BG_BUSY_GAP_NS`, and keeps it until the pause after the completion ended (as long as the command took,
    /// at least one gap). The command's windows are held (no allocation can name them) until the completion.
    fn trim_step(&mut self, now: Nanos) {
        if self.read_only || !self.trim.on() || self.trim.in_flight() {
            return;
        }
        // every idle poll looks (a queue edge noticed late counts as now: the gap runs from the look)
        let quiet = self.trim.ready()
            && !self.trim_wait
            && self
                .trim_view
                .quiet(&self.dev_idle, usize::MAX, now, BG_BUSY_GAP_NS);
        if now < self.trim.pause_until() {
            return;
        }
        let me = self.dir.shard as usize;
        self.dev_idle.trim_give(me);
        if !quiet {
            return;
        }
        let cap = self.trim_cap();
        if cap < crate::alloc::WIN || !self.dev_idle.trim_take(me) {
            return;
        }
        if !self.trim.build(&self.state.alloc, cap) {
            self.dev_idle.trim_give(me);
            return;
        }
        for &(b, n) in self.trim.runs() {
            self.state.alloc.hold_free(b, n);
        }
        match self.dev.submit_deallocate(self.trim.ranges(), K_TRIM) {
            Ok(()) => {
                self.stats.trim_cmds += 1;
                self.stats.trim_ranges += self.trim.ranges().len() as u64;
                self.stats.trim_bytes += self.trim.range_blocks() * BLK as u64;
                self.trim.submitted(now);
            }
            Err(e) => {
                // not sent: the windows are free again and candidates for the next command
                for (b, n) in self.trim.unbuilt() {
                    self.trim_release(b, n);
                }
                self.dev_idle.trim_give(me);
                match e.err {
                    // a dead device fails the shard through its data and WAL paths
                    SubmitError::QueueFull | SubmitError::Dead => {}
                    SubmitError::Unsupported => {
                        eprintln!(
                            "store: shard {}: the device refused runtime deallocate: trim=off",
                            self.shard
                        );
                        self.trim.turn_off("off(refused at runtime)");
                    }
                    err => {
                        self.stats.trim_errors += 1;
                        self.trim_warn(format_args!("submit refused: {err:?}"));
                    }
                }
            }
        }
    }

    /// The deallocate in flight was reaped at store clock `now` (the shard is polled while it is in flight): its windows
    /// are allocatable again, failed or not (their contents are undefined either way and nothing refers to them); the
    /// next command's size and pause follow from its latency.
    fn trim_done(&mut self, r: std::result::Result<(), IoError>, now: Nanos) {
        let (lat, runs) = self.trim.completed(now, BG_BUSY_GAP_NS);
        self.stats.trim_lat_ns += lat;
        self.stats.trim_lat_max_ns = self.stats.trim_lat_max_ns.max(lat);
        for (b, n) in runs {
            self.trim_release(b, n);
        }
        if let Err(e) = r {
            self.stats.trim_errors += 1;
            self.trim_warn(format_args!("completed with {e:?}"));
        }
    }

    /// Blocks of a deallocate back to the allocator (not dirty: they are trimmed or the command failed).
    fn trim_release(&mut self, b: u64, n: u32) {
        self.state.alloc.release_held(b, n);
        #[cfg(feature = "elastic")]
        self.evac_refence(b, n);
    }

    /// One `WARNING` line per shard for failed deallocates; the rest are counted (`trim_errors`).
    fn trim_warn(&mut self, what: std::fmt::Arguments) {
        if !self.trim.warned {
            self.trim.warned = true;
            eprintln!(
                "WARNING store: shard {}: deallocate {what}; the blocks are in use again untrimmed, further failures only \
                 count in trim_errors",
                self.shard
            );
        }
    }

    // ---------------------------------------------------------------- reader epochs

    /// Pin the current reader epoch: blocks freed from now on stay unreusable until `read_unpin`.
    pub fn read_pin(&mut self) -> u64 {
        let e = self.read_epoch;
        match self.readers.back_mut() {
            Some((le, c)) if *le == e => *c += 1,
            _ => self.readers.push_back((e, 1)),
        }
        e
    }

    pub fn read_unpin(&mut self, e: u64) {
        if let Some(i) = self.readers.iter().position(|(x, _)| *x == e) {
            self.readers[i].1 -= 1;
            if self.readers[i].1 == 0 {
                self.readers.remove(i);
            }
        }
        self.drain_limbo();
    }

    fn drain_limbo(&mut self) {
        let min_active = self.readers.front().map_or(u64::MAX, |r| r.0);
        while self.limbo.front().is_some_and(|(tag, _)| *tag < min_active) {
            let (_, v) = self.limbo.pop_front().unwrap();
            for (b, n) in v {
                self.release_held(b, n);
            }
        }
    }

    // ---------------------------------------------------------------- KV reads

    /// Point lookup in the applied state (includes txns not yet acked). `Miss`: pages queued, retry after `Wake`.
    pub fn get(&mut self, key: &[u8], out: &mut Vec<u8>) -> Result<bool> {
        let r = self.state.get(key, out);
        self.after_tree_op(&r);
        r
    }

    /// Predecessor lookup ([`Tree::get_le`]) in the applied state.
    pub fn get_le(
        &mut self,
        key: &[u8],
        ok: &mut Vec<u8>,
        ov: &mut Vec<u8>,
    ) -> Result<Option<bool>> {
        debug_assert!(
            crate::runs::omap_id(key).is_none_or(|id| !self.state.runs.has_obj(id)),
            "get_le on an omap key of an object with runs (adr 0476)"
        );
        let r = self.state.tree.get_le(key, ok, ov);
        self.after_tree_op(&r);
        r
    }

    /// [`Tree::prefetch_some`] in the applied state.
    pub fn prefetch(&mut self, a: &[u8], b: &[u8]) -> Result<()> {
        let r = self.state.tree.prefetch_some(a, b);
        self.after_tree_op(&r);
        r
    }

    /// Non-blocking probes (`Miss` = reads queued): the pages a `DelRange(a, b)` of a txn visits ([`Tree::probe_range`]),
    /// the path of one key ([`Tree::probe_key`]).
    pub fn probe_range(&mut self, a: &[u8], b: &[u8]) -> Result<()> {
        let r = self.state.tree.probe_range(a, b).map(drop);
        self.after_tree_op(&r);
        r
    }
    pub fn probe_key(&mut self, key: &[u8]) -> Result<()> {
        let r = self.state.tree.probe_key(key);
        self.after_tree_op(&r);
        r
    }

    /// [`Tree::scan_pred`] in the applied state.
    pub fn scan_pred(
        &mut self,
        pivot: &[u8],
        end: &[u8],
        f: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<bool> {
        debug_assert!(
            crate::runs::omap_id(pivot).is_none_or(|id| !self.state.runs.has_obj(id)),
            "scan_pred on an omap key of an object with runs (adr 0476)"
        );
        let r = self.state.tree.scan_pred(pivot, end, f);
        self.after_tree_op(&r);
        r
    }

    /// Lookup with read-your-writes over `txn`'s pending ops.
    pub fn txn_get(&mut self, txn: &Txn<D::Buf>, key: &[u8], out: &mut Vec<u8>) -> Result<bool> {
        for op in txn.ops.iter().rev() {
            match op {
                Op::Put(k, v) if k == key => {
                    out.extend_from_slice(v);
                    return Ok(true);
                }
                Op::Del(k) if k == key => return Ok(false),
                Op::DelRange(a, b) if a.as_slice() <= key && key < b.as_slice() => {
                    return Ok(false);
                }
                Op::RunPut(r) => {
                    if let Some(i) = r.find(key) {
                        let v = r.entry(i).1;
                        if is_tomb(v) {
                            return Ok(false);
                        }
                        out.extend_from_slice(v);
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }
        self.get(key, out)
    }

    /// Range iterator step: emits up to the budget, resumable (`cur` keeps the position). Sees the applied
    /// state, not the txn's pending ops.
    pub fn scan(
        &mut self,
        cur: &mut ScanCursor,
        max_entries: usize,
        max_bytes: usize,
        f: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<ScanStatus> {
        let r = if cur.done
            || self.state.runs.is_empty()
            || !self.state.runs.any_in(&cur.next, &cur.end)
        {
            self.state.tree.scan(cur, max_entries, max_bytes, f)
        } else {
            self.scan_merged(cur, max_entries, max_bytes, f)
        };
        self.after_tree_op(&r);
        if cur.ra_win > 0 && r.is_ok() && self.state.tree.has_wants() {
            self.pump_wants(); // rolling readahead asked for leaves on a hit: submit them now
        }
        r
    }

    /// [`Shard::scan`] over a range omap runs have entries in (adr 0476): the tree step's entries merged on the fly with
    /// the runs' live entries of the same span (a run wins over the tree; a run's removal hides the key), cut to the
    /// budget. No copy per entry: the run entries below each tree key go out before it; tree entries past the budget are
    /// skipped (scanned again by the next step), the key of the last emitted entry is copied once (the resume point).
    fn scan_merged(
        &mut self,
        cur: &mut ScanCursor,
        max_entries: usize,
        max_bytes: usize,
        f: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<ScanStatus> {
        let start = cur.next.clone();
        let end = cur.end.clone();
        let mut ri = self.state.runs.scan(&start, &end).peekable();
        let (mut ne, mut nb) = (0usize, 0usize);
        // `cut`: the budget is full, resume after this key; `more`: an entry past it exists
        let (mut cut, mut more): (Option<Vec<u8>>, bool) = (None, false);
        let mut emit = |k: &[u8], v: &[u8], cut: &mut Option<Vec<u8>>, more: &mut bool| {
            if cut.is_some() {
                *more = true;
                return;
            }
            f(k, v);
            ne += 1;
            nb += k.len() + v.len();
            if ne >= max_entries || nb >= max_bytes {
                *cut = Some(k.to_vec());
            }
        };
        let r = self
            .state
            .tree
            .scan(cur, max_entries, max_bytes, &mut |tk, tv| {
                if more {
                    return;
                }
                while let Some(&(rk, rv)) = ri.peek() {
                    if rk > tk {
                        break;
                    }
                    ri.next();
                    if !is_tomb(rv) {
                        emit(rk, rv, &mut cut, &mut more);
                    }
                    if rk == tk {
                        return; // the run's entry (a value or a removal) replaces the tree's
                    }
                }
                emit(tk, tv, &mut cut, &mut more);
            });
        // every tree key below `hi` was emitted by this step: the run entries below it go out too
        let hi = match r {
            Ok(ScanStatus::Done) => cur.end.clone(),
            Ok(ScanStatus::More) | Err(StoreError::Miss) => cur.next.clone(),
            Err(e) => return Err(e),
        };
        while !more && let Some((rk, rv)) = ri.next_if(|&(rk, _)| rk < hi.as_slice()) {
            if !is_tomb(rv) {
                emit(rk, rv, &mut cut, &mut more);
            }
        }
        if more {
            // budget: resume right after the last emitted key (tree entries past it are scanned again)
            let mut l = cut.expect("a cut precedes more");
            l.push(0);
            cur.done = false;
            cur.next = l;
            return Ok(ScanStatus::More);
        }
        r
    }

    fn after_tree_op<T>(&mut self, r: &Result<T>) {
        if matches!(r, Err(StoreError::Miss)) {
            self.pump_wants();
        }
    }

    /// Issue reads for the pages the tree asked for: the new wants join the deferred ones ([`Shard::queue_wants`]), then
    /// the front of the queue goes to the device while it has room. A pump costs its new wants and its submits, however
    /// many pages wait for a queue slot (a merge slice asks for hundreds at once).
    fn pump_wants(&mut self) {
        let reserve = self.data_floor();
        if self.dev.queue_space() <= reserve && !self.state.tree.has_wants() {
            // busy poll with a full queue: nothing to do (a deep readahead keeps hundreds deferred); nothing was asked
            // for memory, so a refusal of an earlier pump still stands
            return;
        }
        let was_dma_wait = std::mem::replace(&mut self.page_dma_wait, false);
        self.queue_wants();
        let bpp = self.state.tree.geom().bpp as usize;
        // slots below it are taken by this pump's own submits
        let mut slot_from = 0;
        while self.dev.queue_space() > reserve {
            let Some(w) = self.deferred.pop_front() else {
                break;
            };
            if self.state.tree.is_resident(w.addr) {
                // resident without a completion event of ours (a waiter that asked for it got no `Event::Page`): wake all
                self.wake = true;
                if w.dead {
                    self.state.tree.dead_unfly(w.addr);
                }
                continue;
            }
            let Some(buf) = self.dev.try_alloc_io_uninit(bpp * BLK) else {
                // the DMA budget refused a page buffer (adr 0175 am. 4): the rest stays deferred too, asked again next poll
                self.page_dma_wait = true;
                self.deferred.push_front(w);
                break;
            };
            let slot = match self.page_reads[slot_from..]
                .iter()
                .position(Option::is_none)
            {
                Some(i) => slot_from + i,
                None => {
                    self.page_reads.push(None);
                    self.page_stale.push(false);
                    self.page_reads.len() - 1
                }
            };
            match self
                .dev
                .submit_read(w.addr * self.lpb, buf, K_PAGE | slot as u64)
            {
                Ok(()) => {
                    if was_dma_wait {
                        self.page_dma_submits += 1;
                        self.state
                            .tree
                            .dependencies
                            .submitted_after_memory(w.addr, self.poll_now);
                    }
                    self.page_reads[slot] = Some(w);
                    self.page_stale[slot] = false;
                    slot_from = slot + 1;
                }
                Err(r) if r.err == SubmitError::QueueFull => {
                    self.deferred.push_front(w);
                    break;
                }
                Err(_) => self.fail(StoreError::Io(IoError::Aborted)),
            }
        }
    }

    /// Take the tree's new wants into the deferred queue, dropping those whose page is resident, in flight or queued
    /// already (a page asked for again before its read completes). Looks the addresses up in one map built when there
    /// is a new want, not by scanning the reads and the queue per want.
    fn queue_wants(&mut self) {
        if !self.state.tree.has_wants() {
            return;
        }
        let mut fresh = std::mem::take(&mut self.want_buf);
        self.state.tree.take_wants(&mut fresh);
        // address -> a drain read of it is in flight
        let mut asked: crate::fx::FxMap<u64, bool> = crate::fx::FxMap::with_capacity_and_hasher(
            self.page_reads.len() + self.deferred.len() + fresh.len(),
            Default::default(),
        );
        for x in self.page_reads.iter().flatten() {
            *asked.entry(x.addr).or_insert(false) |= x.dead;
        }
        for x in &self.deferred {
            asked.entry(x.addr).or_insert(false);
        }
        for w in fresh.drain(..) {
            let resident = self.state.tree.is_resident(w.addr);
            if resident {
                self.wake = true;
            }
            if resident || asked.contains_key(&w.addr) {
                if w.dead {
                    // lazy free: a read of the page that was asked for before its detach (its image is dropped, see
                    // `reap_gone`) occupies the address: the drain asks again once it is done
                    self.state.tree.dead_unfly(w.addr);
                } else if asked.get(&w.addr) == Some(&true) {
                    // only a page detached after this want was taken shares an address with a drain read: the
                    // waiter descends again and no longer needs it
                    self.wake = true;
                }
                continue;
            }
            asked.insert(w.addr, false);
            self.deferred.push_back(w);
        }
        self.want_buf = fresh;
    }

    /// Pages the tree freed by address (`Tree::take_gone`) whose read is still queued or in flight: such a read was asked for
    /// before the free (nothing references the page since), and its image must never be cached nor mark the address bad
    /// (the address is reused after the next checkpoint). Queued ones are dropped, in-flight ones are marked stale; the
    /// waiters are woken and descend again.
    fn reap_gone(&mut self) {
        if !self.state.tree.has_gone() {
            return;
        }
        let mut g = std::mem::take(&mut self.gone_buf);
        self.state.tree.take_gone(&mut g);
        if self.loads_pending() || self.state.tree.has_wants() {
            self.queue_wants();
            g.sort_unstable();
            let hit = |w: &Want| !w.dead && g.binary_search(&(w.addr, w.crc)).is_ok();
            for (i, r) in self.page_reads.iter().enumerate() {
                if r.as_ref().is_some_and(hit) {
                    self.page_stale[i] = true;
                    self.wake = true;
                }
            }
            let n = self.deferred.len();
            self.deferred.retain(|w| !hit(w));
            if self.deferred.len() != n {
                self.wake = true;
            }
        }
        g.clear();
        self.gone_buf = g;
    }

    /// Blocking full dump of the user keyspace (everything except the engine's `f` keys). Only for quiescent
    /// shards (tests, fsck-style tools): pumps `poll` and discards its events.
    pub fn dump_blocking<C: Clock>(
        &mut self,
        clk: &mut C,
    ) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut out = std::collections::BTreeMap::new();
        let top = vec![0xffu8; self.state.tree.max_key() + 1];
        for (a, b) in [(&b""[..], &b"f"[..]), (&b"g"[..], &top[..])] {
            let mut cur = ScanCursor::new(a, b);
            loop {
                let r = self.scan(&mut cur, 4096, usize::MAX, &mut |k, v| {
                    out.insert(k.to_vec(), v.to_vec());
                });
                match r {
                    Ok(ScanStatus::Done) => break,
                    Ok(ScanStatus::More) => {}
                    Err(StoreError::Miss) => self.wait_wake(clk)?,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(out)
    }

    fn wait_wake<C: Clock>(&mut self, clk: &mut C) -> Result<()> {
        let mut ev = Vec::new();
        for _ in 0..1_000_000 {
            ev.clear();
            self.poll(clk.now(), &mut ev);
            if ev.iter().any(|e| matches!(e, Event::Wake | Event::Page(_))) {
                return Ok(());
            }
            if let Some(Event::Failed(e)) = ev.iter().find(|e| matches!(e, Event::Failed(_))) {
                return Err(e.clone());
            }
            if self.dev.is_dead() {
                return Err(StoreError::Io(IoError::Aborted));
            }
            let h = self.dev.next_deadline();
            clk.idle(h);
        }
        Err(StoreError::Busy)
    }

    // ---------------------------------------------------------------- submit

    /// Submit a txn. On error nothing was changed (beyond queued page reads) and the txn is handed back. `Busy`/`WalFull`: retry after
    /// `poll`; `Miss`: tree pages were queued, retry after `Event::Wake` (reservations stay valid).
    #[allow(clippy::result_large_err)]
    pub fn submit(
        &mut self,
        mut txn: Txn<D::Buf>,
    ) -> std::result::Result<u64, (StoreError, Txn<D::Buf>)> {
        let _s = wprof::span(wprof::S::Tree);
        if self.failed.is_some() {
            return Err((StoreError::Failed, txn));
        }
        if self.read_only {
            return Err((StoreError::Invalid("read-only mount: txn refused"), txn));
        }
        #[cfg(feature = "splinterdb")]
        let foreign_lease = if let Some(r) = &self.splinter {
            let pending = self
                .state
                .splinter_mem
                .as_ref()
                .expect("SplinterDB buffers")
                .bytes();
            match r.client.reserve(&txn.ops, pending) {
                Ok(l) => l,
                Err(e) => return Err((e, txn)),
            }
        } else {
            None
        };
        let mut rec = Record {
            lsn: self.next_lsn,
            ops: std::mem::take(&mut txn.ops),
            data: Vec::new(),
            frees: std::mem::take(&mut txn.frees),
        };
        let mut dt = crate::diag::t0();
        let v = self.validate(&mut txn, &mut rec);
        crate::diag::lap(34, &mut dt);
        let r = match v {
            Ok(()) => self.commit(txn, rec),
            Err(e) => Err((e, txn, rec)),
        };
        crate::diag::lap(35, &mut dt);
        self.dev_note();
        match r {
            Ok(lsn) => {
                #[cfg(feature = "splinterdb")]
                if let Some(lease) = foreign_lease {
                    self.splinter
                        .as_mut()
                        .expect("selected")
                        .client
                        .accepted(lsn, lease);
                }
                self.reap_gone();
                crate::diag::lap(36, &mut dt);
                Ok(lsn)
            }
            Err((e, mut txn, rec)) => {
                self.drop_empty_open();
                txn.ops = rec.ops;
                txn.frees = rec.frees;
                // hand the moved per-extent crcs back (the caller may retry with this txn): data extents first (moved
                // only when the caller supplied them), then the deferred copies and the pre-write claims (always moved),
                // then the omap LSM run extents (drained into the record, adr 0610)
                let nd = txn.data.len();
                let nc = nd + txn.copies.len();
                let np = txn.pre.len();
                let hashed = txn.data_crcs.len() == nd;
                for (i, e) in rec.data.into_iter().enumerate() {
                    if i >= nc + np {
                        if let Some(w) = &mut txn.olsm {
                            w.push(e);
                        }
                    } else if i >= nc {
                        txn.pre[i - nc].crcs = e.crcs;
                    } else if i >= nd {
                        txn.copies[i - nd].crcs = e.crcs;
                    } else if hashed {
                        txn.data_crcs[i] = e.crcs;
                    }
                }
                if e == StoreError::Miss {
                    self.pump_wants();
                }
                Err((e, txn))
            }
        }
    }

    /// Would `txn` pass the hard (size) limits of `submit`: record vs ring (ADR 0028), distinct tree pages vs the
    /// per-txn budget (data extents: no limit, adr 0066)? Same checks as `validate`, no state change except queued page
    /// reads (`Miss`: retry after `Wake`). Returns the distinct tree pages the txn needs resident. Transient
    /// conditions (`Busy`, `WalFull`, space) are not checked.
    pub fn check_fits(&mut self, txn: &mut Txn<D::Buf>) -> Result<usize> {
        if self.failed.is_some() {
            return Err(StoreError::Failed);
        }
        let rec = Record {
            lsn: self.next_lsn,
            ops: std::mem::take(&mut txn.ops),
            data: txn
                .data
                .iter()
                .map(|(b, buf)| Extent {
                    blk: *b,
                    nblk: (buf.len() / BLK) as u32,
                    crcs: vec![0; buf.len() / BLK],
                })
                .collect(),
            frees: std::mem::take(&mut txn.frees),
        };
        let r = self.check_record_fits(&rec);
        txn.ops = rec.ops;
        txn.frees = rec.frees;
        r
    }

    /// Size-only object preflight and prepared txns share the exact record/page checks. Never applies the record.
    pub(crate) fn check_record_fits(&mut self, rec: &Record) -> Result<usize> {
        if rec.data.iter().any(|e| e.nblk as usize > self.max_xfer_blk) {
            return Err(StoreError::TxnTooLarge);
        }
        self.scratch.b.clear();
        encode_record(rec, &mut self.scratch);
        let multi = self.multi_blocks(self.scratch.b.len());
        if multi > 0 && multi + 2 * self.cfg.max_unit_blocks as u64 > self.dir.wal_blocks / 2 {
            return Err(StoreError::TxnTooLarge);
        }
        if let Err(e) = self.state.prepare(rec) {
            if e == StoreError::Miss {
                self.pump_wants();
            }
            return Err(e);
        }
        // no data-extent rule: extents beyond the device queue go out in waves (`data_backlog`, adr 0066)
        Ok(self.state.probe_pages())
    }

    /// Set the LSM range-delete policy for future staging attempts on this owner shard.
    /// Already built transactions retain their selected operations. This changes no cache,
    /// on-disk metadata or in-flight IO and is called only by the shard's owner core.
    pub fn set_omap_delete_range_threshold(&mut self, threshold: u64) {
        self.cfg.omap_delete_range_threshold = threshold;
    }

    /// Current LSM range-delete threshold of this owner shard; zero always selects native ranges.
    pub fn omap_delete_range_threshold(&self) -> u64 {
        self.cfg.omap_delete_range_threshold
    }

    /// Bytes of the WAL ring (a txn record may use about half).
    pub fn ring_bytes(&self) -> u64 {
        self.dir.wal_blocks * BLK as u64
    }

    /// Size-only guard for optional point-range expansion. Unlike `check_fits`, this never reads
    /// tree pages or changes allocator state. Include planned extents for object preflight.
    pub(crate) fn point_ranges_fit(&mut self, txn: &mut Txn<D::Buf>, planned: &[Extent]) -> bool {
        let mut rec = Record {
            lsn: self.next_lsn,
            ops: std::mem::take(&mut txn.ops),
            data: txn
                .data
                .iter()
                .map(|(blk, buf)| {
                    let nblk = buf.len() / BLK;
                    Extent {
                        blk: *blk,
                        nblk: nblk as u32,
                        crcs: vec![0; nblk],
                    }
                })
                .chain(txn.pre.iter().map(|p| Extent {
                    blk: p.blk,
                    nblk: p.nblk,
                    crcs: p.crcs.clone(),
                }))
                .chain(planned.iter().cloned())
                .chain(txn.olsm.iter().flatten().cloned())
                .collect(),
            frees: std::mem::take(&mut txn.frees),
        };
        self.scratch.b.clear();
        encode_record(&rec, &mut self.scratch);
        let multi = self.multi_blocks(self.scratch.b.len());
        let fits =
            multi == 0 || multi + 2 * self.cfg.max_unit_blocks as u64 <= self.dir.wal_blocks / 2;
        txn.ops = std::mem::take(&mut rec.ops);
        txn.frees = std::mem::take(&mut rec.frees);
        fits
    }

    /// Longest tree key (names, omap keys and attrs derive their limits from it).
    pub fn max_key(&self) -> usize {
        self.state.tree.max_key()
    }

    /// Pages one txn may pin at once (see `Tree::txn_page_budget`).
    pub fn txn_page_budget(&self) -> usize {
        self.state.tree.txn_page_budget()
    }

    /// A unit `validate` opened for a txn that `commit` then refused (a single tree mutation that missed) holds no
    /// record: drop it, so `submit` changes nothing on error. Sealed, it would be a record unit without records, which
    /// replay rejects as the end of the log: every txn behind it would be lost.
    fn drop_empty_open(&mut self) {
        if !self
            .pipeline
            .back()
            .is_some_and(|u| u.st == UState::Open && u.ntxn == 0)
        {
            return;
        }
        let u = self.pipeline.pop_back().unwrap();
        debug_assert!(u.tokens.is_empty() && u.frees.is_empty() && u.pending_data == 0);
        if u.seq + 1 == self.next_unit_seq {
            self.next_unit_seq = u.seq;
        }
        if self.pool_payload.len() < 8 && u.payload.capacity() <= 64 * 1024 {
            self.pool_payload.push(u.payload);
        }
        if self.pool_tokens.len() < 8 {
            self.pool_tokens.push(u.tokens);
        }
    }

    /// Validation + admission; no state change except possibly closing the open unit (benign) and queueing
    /// page reads.
    fn validate(&mut self, txn: &mut Txn<D::Buf>, rec: &mut Record) -> Result<()> {
        #[cfg(feature = "rocksdb")]
        if !txn.shrink
            && let Some(r) = &self.rocks
        {
            let bytes: u64 = rec
                .ops
                .iter()
                .filter_map(|op| match op {
                    Op::Omap(crate::olsm::wire::OOp::Put { blob, .. }) => Some(blob.len() as u64),
                    _ => None,
                })
                .sum();
            if bytes != 0 && r.client.space.available() < bytes.saturating_mul(2) {
                return Err(StoreError::NoSpace);
            }
        }
        // backpressure that does not depend on the txn comes first: a txn refused for dirty pages is retried on every store
        // progress (each checkpoint page write), and the record encoding + path probes of a large txn (1024 omap keys:
        // 330 KB, 1024 probes) would be redone per retry (adr 0021 am. 62: they were 58 % of the core in a big-omap
        // populate)
        if self.state.tree.dirty_pages() >= self.cfg.dirty_hard_pages {
            self.force_ckpt();
            self.busy(2);
            return Err(StoreError::Busy);
        }
        let pre = txn.data_crcs.len() == txn.data.len();
        for di in 0..txn.data.len() {
            let (blk, buf) = (&txn.data[di].0, &txn.data[di].1);
            let (s, l) = (buf.as_slice(), buf.len());
            if l == 0 || l % BLK != 0 {
                return Err(StoreError::Invalid("data buffer not a multiple of 4 KiB"));
            }
            if l / BLK > self.max_xfer_blk {
                return Err(StoreError::TxnTooLarge);
            }
            let nblk = (l / BLK) as u32;
            if !self.state.alloc.is_reserved(*blk, nblk) {
                return Err(StoreError::Invalid("data block not reserved via alloc()"));
            }
            let crcs: Vec<u32> = if pre {
                debug_assert!(
                    txn.data_crcs[di].len() == nblk as usize
                        && s.chunks(BLK)
                            .enumerate()
                            .all(|(i, b)| blk_crc(blk + i as u64, b) == txn.data_crcs[di][i])
                );
                std::mem::take(&mut txn.data_crcs[di])
            } else {
                s.chunks(BLK)
                    .enumerate()
                    .map(|(i, b)| blk_crc(blk + i as u64, b))
                    .collect()
            };
            rec.data.push(Extent {
                blk: *blk,
                nblk,
                crcs,
            });
        }
        // deferred copies (adr 0175 am. 4): crcs from the staging, over the same bytes
        for c in &mut txn.copies {
            let l = c.src.len();
            if l == 0 || l % BLK != 0 || c.crcs.len() != l / BLK {
                return Err(StoreError::Invalid(
                    "copy run not whole blocks with their crcs",
                ));
            }
            if l / BLK > self.max_xfer_blk {
                return Err(StoreError::TxnTooLarge);
            }
            let nblk = (l / BLK) as u32;
            if !self.state.alloc.is_reserved(c.blk, nblk) {
                return Err(StoreError::Invalid("data block not reserved via alloc()"));
            }
            debug_assert!(
                c.src
                    .chunks(BLK)
                    .enumerate()
                    .all(|(i, b)| blk_crc(c.blk + i as u64, b) == c.crcs[i])
            );
            rec.data.push(Extent {
                blk: c.blk,
                nblk,
                crcs: std::mem::take(&mut c.crcs),
            });
        }
        // pre-write claims (adr 0477): a prefix of a piece this shard wrote ahead and a staged txn took; the crcs come
        // from the verified payload (the piece's bytes are a slice of it)
        for ci in 0..txn.pre.len() {
            let c = &mut txn.pre[ci];
            let ok = self
                .pre
                .taken(c.id)
                .is_some_and(|(b, n)| b == c.blk && c.nblk > 0 && c.nblk <= n)
                && c.crcs.len() == c.nblk as usize
                && self.state.alloc.is_reserved(c.blk, c.nblk);
            if !ok {
                return Err(StoreError::Invalid("pre-write claim not held"));
            }
            rec.data.push(Extent {
                blk: c.blk,
                nblk: c.nblk,
                crcs: std::mem::take(&mut c.crcs),
            });
        }
        // omap LSM manifest (adr 0610): run extents written and landed before the submit
        if let Some(w) = &mut txn.olsm {
            for x in w.drain(..) {
                if x.nblk == 0
                    || x.nblk as usize > self.max_xfer_blk
                    || x.crcs.len() != x.nblk as usize
                    || !self.state.alloc.is_reserved(x.blk, x.nblk)
                {
                    return Err(StoreError::Invalid("olsm run extent not reserved"));
                }
                rec.data.push(x);
            }
        }
        // frees: no duplicates / overlaps (allocated-ness is checked by State::check)
        rec.frees.sort_unstable_by_key(|&(b, _)| b);
        let mut previous_end = None;
        for &(b, n) in &rec.frees {
            let end = b
                .checked_add(u64::from(n))
                .filter(|_| n > 0)
                .ok_or(StoreError::Invalid("bad or doubly freed block range"))?;
            if previous_end.is_some_and(|e| b < e) {
                return Err(StoreError::Invalid("duplicate free"));
            }
            previous_end = Some(end);
        }
        // record size (before the tree work so oversized txns fail cheaply)
        self.stats.prepares += 1;
        self.scratch.b.clear();
        encode_record(rec, &mut self.scratch);
        let max_payload = self.cfg.max_unit_blocks as usize * BLK - HDR_LEN;
        let multi_blocks = self.multi_blocks(self.scratch.b.len());
        if multi_blocks > 0
            && multi_blocks + 2 * self.cfg.max_unit_blocks as u64 > self.dir.wal_blocks / 2
        {
            // would not fit the ring even when empty (ring sizing: max txn ~ ring / 2, ADR 0028)
            return Err(StoreError::TxnTooLarge);
        }
        // omap memtables full (adr 0610, adr 0175): park until the frozen one is flushed; run set above its space target
        // plus physical pressure: park until the running merge makes room
        if let Some(space) = self.olsm_throttled(rec) {
            self.olsm_note_throttle(space);
            #[cfg(feature = "rocksdb")]
            self.rocks_note_blocked();
            self.busy(10);
            return Err(StoreError::Busy);
        }
        // tree/allocator preconditions + page residency
        let est = self.state.prepare(rec)?;
        // lazy free: a range delete detaches subtrees into the dead list (persisted in the checkpoint image): hold it
        // back while the drain is far behind (bounds the image). The image growth itself is covered like any state a
        // checkpoint finds beyond what admission guaranteed: `meta_housekeeping` grows the meta space before the freeze.
        if self.state.tree.dead_len() >= crate::tree::DEAD_SOFT
            && rec.ops.iter().any(|o| matches!(o, Op::DelRange(..)))
        {
            self.busy(1);
            return Err(StoreError::Busy);
        }
        // backpressure: meta space (dirty pages: at the top)
        let t = &self.state.tree;
        // txns that only delete (and free blocks) may use the meta reserve, so space can always be recovered; a PG delete
        // with its bounded log/info write and the PG-removal marker count as such (`OTxn::frees`, adr 0021 S4)
        // a run re-log (adr 0476) dirties no page: it keeps the ring moving whatever the meta space
        let freeing = txn.shrink
            || rec.data.is_empty()
                && rec
                    .ops
                    .iter()
                    .all(|o| !matches!(o, Op::Put(..) | Op::RunPut(..) | Op::RunMerge { .. }))
            || txn.token == MERGE_TOKEN && matches!(rec.ops.first(), Some(Op::RunPut(..)));
        // run merges (sys) leave the sys part of the reserve to PG-state and replica txns: their room is the page charge
        // user txns keep free for the runs (adr 0476)
        let reserve = if freeing {
            0
        } else if txn.sys && txn.token != MERGE_TOKEN {
            self.meta_reserve as usize / 3
        } else {
            self.meta_reserve as usize
        };
        let data_res = if freeing {
            0
        } else if txn.sys {
            self.data_reserve / 3 + self.mig_hold
        } else {
            self.user_floor()
        };
        let chunk_res = self.state.chunk_reserve(self.state.touched_chunk_count());
        // user txns leave the pages the runs need once merged, their own runs included (adr 0476), like the
        // user reserve; sys txns may take them (unmerged runs stay durable in the ring and merge once space is back)
        let run_res = if freeing || txn.sys {
            0
        } else {
            let b = rec.ops.iter().fold(0, |b, o| match o {
                Op::RunPut(r) => b + r.tree_bytes(),
                _ => b,
            });
            self.run_pages_with(b)
        };
        let mut image_charge = self.meta_image_need();
        let mut need = t.dirty_pages() + est + reserve + chunk_res + image_charge + run_res;
        if self.cell_blocks != 0 {
            // elastic meta: take cells from the data region instead of failing (sys txns may use the hard data
            // reserve, like their data extents)
            let mut cell_charge = self.state.chunk_reserve(self.pending_cell_chunks.len() + 2);
            need += cell_charge;
            // grow while the meta reserve is still free pages, also for sys txns (they do not charge it): a growth
            // failure (no contiguous run left in a fragmented data region) then marks the shard meta-bound (statfs
            // full, `write_room` refuses) while the reserve still absorbs already-admitted txns, like a legacy region; a
            // miss the next checkpoint's frees cure only waits for it (`defer_growth`)
            let growth_reserve = if freeing {
                0
            } else {
                self.meta_reserve as usize - reserve
            };
            while self.meta_free() < need + growth_reserve {
                // Actual fragmented extents may touch more chunks than a contiguous cell. Recompute the
                // admission charge before accepting the txn, without charging the same chunk per segment.
                if !self.grow_meta(need + growth_reserve, data_res) {
                    break;
                }
                let next_charge = self.state.chunk_reserve(self.pending_cell_chunks.len() + 2);
                let next_image_charge = self.meta_image_need();
                need = need - cell_charge + next_charge - image_charge + next_image_charge;
                cell_charge = next_charge;
                image_charge = next_image_charge;
            }
            self.note_meta_need(need + growth_reserve);
        }
        let meta_free = self.meta_free();
        if meta_free < need {
            let held = self.run_pages();
            if run_res > 0 && held > 0 && !self.mg_full && meta_free + held >= need {
                // only the page charge of the runs already logged binds (the txn's own charge is its need like any page
                // estimate): merge (real pages replace the bound), then retry
                self.stats.busy_meta_run += 1;
                self.mg_want = true;
                self.busy(3);
                return Err(StoreError::Busy);
            }
            // growth missed the windows a deallocate holds: they are back at its completion
            if self.trim_miss() {
                self.busy(3);
                return Err(StoreError::Busy);
            }
            return if self.next_lsn - 1 > self.ckpt_lsn || self.ckpt_active() {
                self.force_ckpt();
                self.stats.busy_meta_ckpt += 1;
                self.busy(3);
                Err(StoreError::Busy)
            } else {
                // elastic pool (adr 0021 am. 52): meta cells grow out of the data region, which a chunk extends
                #[cfg(feature = "elastic")]
                if self.lend.may_wait() {
                    self.lend.want = true;
                    return Err(StoreError::Busy);
                }
                Err(StoreError::NoSpace)
            };
        }
        // device queue room: data writes + WAL units/pads/root slot. A txn with more data extents than the queue can
        // hold at once is admitted alone (nothing backlogged) and its data goes out in waves (adr 0066): a txn that
        // fits the primary's store must never be refused by a replica only because its free space is more fragmented.
        // Claimed pre-writes are already on the device (or in flight): only `data` needs slots.
        // A backlog that waits for the device window does not hold the txn back: its ticket is its place in the device's
        // arrival order (adr 0643-device-admission-fifo).
        let writes = txn.data.len() + txn.copies.len();
        if writes > 0 {
            let floor = self.data_floor();
            // a backlog that waits for queue room or for DMA memory (adr 0175 am. 4) takes no more until it drains
            if matches!(self.data_backlog.1, Stop::Queue | Stop::Dma) {
                self.busy(4);
                return Err(StoreError::Busy);
            }
            if writes + floor <= self.dev.queue_depth() && self.dev.queue_space() < writes + floor {
                self.busy(5);
                return Err(StoreError::Busy);
            }
        }
        // omap runs (adr 0476): while runs are live (or this txn logs some), the ring keeps room for the re-log that
        // moves the floor (the floor's record units become releasable; ring liveness) and other txns keep two units more
        // for the merges (the open unit may still fill one, a ring-end PAD takes less than one). Re-logs take that room.
        // a record's runs are its last ops (`State::check`)
        let own_runs: usize = rec
            .ops
            .iter()
            .rev()
            .map_while(|o| match o {
                Op::RunPut(r) => Some(r.wal_bytes()),
                _ => None,
            })
            .sum();
        let wal_res = if self.state.runs.is_empty() && own_runs == 0 {
            0
        } else if txn.token == MERGE_TOKEN {
            if matches!(rec.ops.first(), Some(Op::RunPut(..))) {
                0
            } else {
                self.relog_blocks(0)
            }
        } else {
            2 * self.cfg.max_unit_blocks as u64 + self.relog_blocks(own_runs)
        } + if self.state.olsm.is_some() && txn.olsm.is_none() {
            // the omap LSM manifest txn moves the floor the memtables hold: everything else leaves it room for its own
            // admission (two units: the open unit still to seal and a ring-end PAD come out of what clients leave)
            2 * self.cfg.max_unit_blocks as u64
        } else {
            0
        };
        if multi_blocks > 0 {
            return self.admit_multi(multi_blocks, wal_res);
        }
        // unit room
        let fits = self.pipeline.back().is_some_and(|u| {
            u.st == UState::Open && u.payload.len() + self.scratch.b.len() <= max_payload
        });
        // ring room counts sealed units only: a txn joining the open unit keeps the merge reserve as one opening a unit
        // does (a unit a merge opened next to a full ring must not fill with client records)
        let ring_short =
            |s: &Self| s.dir.wal_blocks - s.ring_used < 2 * s.cfg.max_unit_blocks as u64 + wal_res;
        if fits && wal_res > 0 && ring_short(self) {
            self.busy(7);
            self.force_ckpt();
            self.olsm_ring_pressure();
            return Err(StoreError::WalFull);
        }
        if !fits {
            if self.pipeline.back().is_some_and(|u| u.st == UState::Open) {
                self.close_open();
            }
            if self
                .pipeline
                .iter()
                .filter(|u| u.st == UState::Ready)
                .count()
                >= self.cfg.ready_cap
            {
                self.busy(6);
                return Err(StoreError::Busy);
            }
            if ring_short(self) {
                self.busy(7);
                self.force_ckpt();
                self.olsm_ring_pressure();
                return Err(StoreError::WalFull);
            }
            let seq = self.next_unit_seq;
            self.next_unit_seq += 1;
            self.pipeline.push_back(Unit {
                seq,
                st: UState::Open,
                payload: self
                    .pool_payload
                    .pop()
                    .unwrap_or_else(|| Vec::with_capacity(4096)),
                first_lsn: rec.lsn,
                ntxn: 0,
                flags: 0,
                part_idx: 0,
                tokens: self.pool_tokens.pop().unwrap_or_default(),
                frees: Vec::new(),
                pending_data: 0,
                wal_done: false,
                pad_pending: false,
                pos: 0,
                pad_pos: 0,
                hdr: [0; HDR_LEN],
                pad_hdr: None,
                t_open: 0,
                ahead: 0,
                ckpt: false,
                ck_dev: false,
                backlog: false,
                t_wal: 0,
                t_seal: 0,
                t_sub: 0,
                t_data: 0,
            });
        }
        Ok(())
    }

    /// Ring blocks a record encoding of `len` bytes needs as a multi-part chain; 0 if it fits one unit.
    fn multi_blocks(&self, len: usize) -> u64 {
        let mub = self.cfg.max_unit_blocks as u64;
        let mp = (mub as usize) * BLK - HDR_LEN;
        if len <= mp {
            return 0;
        }
        let k = len.div_ceil(mp) as u64;
        (k - 1) * mub + (HDR_LEN + len - (k as usize - 1) * mp).div_ceil(BLK) as u64
    }

    /// Admission of a multi-part txn (ADR 0028): the whole chain's ring space is required up front (so a chain
    /// can never stall half-written behind a full ring); parts never interleave with other txns. `wal_res`: ring blocks
    /// kept free beyond it (run merges).
    fn admit_multi(&mut self, blocks: u64, wal_res: u64) -> Result<()> {
        if self.pipeline.back().is_some_and(|u| u.st == UState::Open) {
            self.close_open();
        }
        let mub = self.cfg.max_unit_blocks as u64;
        let k = blocks.div_ceil(mub) as usize;
        let ready = self
            .pipeline
            .iter()
            .filter(|u| u.st == UState::Ready)
            .count();
        if ready > 0 && ready + k > self.cfg.ready_cap {
            self.busy(8);
            return Err(StoreError::Busy);
        }
        // + one PAD (< one unit) at the ring end + the usual two-unit slack
        if self.dir.wal_blocks - self.ring_used < blocks + 2 * mub + wal_res {
            self.busy(9);
            self.force_ckpt();
            self.olsm_ring_pressure();
            return Err(StoreError::WalFull);
        }
        Ok(())
    }

    /// Seal a multi-part txn: `scratch` holds the record encoding; one unit per slice, contiguous in the ring.
    /// Returns nothing; the END unit (last in the pipeline) carries the token, frees and the data writes.
    fn seal_parts(&mut self, token: u64, lsn: u64, frees: &[(u64, u32)]) {
        let mp = self.cfg.max_unit_blocks as usize * BLK - HDR_LEN;
        let total = self.scratch.b.len();
        let k = total.div_ceil(mp);
        for i in 0..k {
            let end = i + 1 == k;
            let seq = self.next_unit_seq;
            self.next_unit_seq += 1;
            self.pipeline.push_back(Unit {
                seq,
                st: UState::Open,
                payload: self.scratch.b[i * mp..((i + 1) * mp).min(total)].to_vec(),
                first_lsn: lsn,
                ntxn: end as u32,
                flags: if end { FLAG_END } else { FLAG_PART },
                part_idx: i as u32,
                tokens: if end {
                    self.fg_inflight += u32::from(token != MERGE_TOKEN);
                    vec![token]
                } else {
                    Vec::new()
                },
                frees: if end { frees.to_vec() } else { Vec::new() },
                pending_data: 0,
                wal_done: false,
                pad_pending: false,
                pos: 0,
                pad_pos: 0,
                hdr: [0; HDR_LEN],
                pad_hdr: None,
                t_open: 0,
                ahead: 0,
                ckpt: false,
                ck_dev: false,
                backlog: false,
                t_wal: 0,
                t_seal: 0,
                t_sub: 0,
                t_data: 0,
            });
            self.close_open();
        }
        self.stats.multi_txns += 1;
        self.stats.multi_parts += k as u64;
    }

    /// A `validate` refusal of reason `r` (see `ShardStats::busy`).
    #[inline]
    fn busy(&mut self, r: usize) {
        self.stats.busy[r] += 1;
        crate::dbg::busy(r);
    }

    fn force_ckpt(&mut self) {
        // the refused txn waits on the running checkpoint or the next one
        self.ck_fg = true;
        if self.cfg.auto_ckpt && !self.ckpt_active() && self.next_lsn - 1 > self.ckpt_lsn {
            self.ck_requested = true;
            self.stats.forced_ckpts += 1;
        }
    }

    #[allow(clippy::type_complexity, clippy::result_large_err)]
    fn commit(
        &mut self,
        txn: Txn<D::Buf>,
        rec: Record,
    ) -> std::result::Result<u64, (StoreError, Txn<D::Buf>, Record)> {
        let lsn = rec.lsn;
        // 0. make the new state visible first: a record with a single tree mutation is not probed beforehand
        // and may still miss (without side effects). Tree mutations + allocator: reserved -> allocated, frees
        // -> held.
        if let Err((e, torn)) = self.state.apply(&rec) {
            // a record that changed the state before it failed never reaches the WAL, and a later checkpoint would
            // persist its part: the shard stops here; an untouched state refuses only the txn (`State::apply`)
            if torn {
                self.fail(e.clone());
            }
            return Err((e, txn, rec));
        }
        self.pool.publish(self.run_mem());
        let _w = wprof::span(wprof::S::Wal);
        let multi = self.multi_blocks(self.scratch.b.len()) > 0;
        if multi {
            // 1a. the chain of units (END last); data writes below are attributed to the END unit
            self.seal_parts(txn.token, lsn, &rec.frees);
        }
        let seq = self.pipeline.back().unwrap().seq;
        if self.pipeline.back().unwrap().t_open == 0 {
            let (t, a, c) = (
                self.dev_ns().max(1),
                (self.dev.queue_depth() - self.dev.queue_space()) as u32,
                self.ckpt_active(),
            );
            let u = self.pipeline.back_mut().unwrap();
            (u.t_open, u.ahead, u.ckpt) = (t, a, c);
        }
        // 1. data writes go out now, concurrently with the WAL unit that will carry the record, as far as the device
        //    window admits their ticket (one range of the device's write stream for the txn's data, adr
        //    0643-device-admission-fifo; none when nothing is ahead of it: the uncontended path) and the queue has room
        //    (what waits stays in `data_backlog`, counted as pending in the unit)
        let ext = txn.data.len() + txn.copies.len();
        if ext > 0 {
            let bytes: u64 = txn.data.iter().map(|(_, b)| b.len() as u64).sum::<u64>()
                + txn.copies.iter().map(|c| c.src.len() as u64).sum::<u64>();
            let mut end = if self.adm.free(&self.dev_idle.admit, bytes) {
                self.adm.stats.free += ext as u64;
                None
            } else {
                Some(self.dev_idle.admit.take(self.dir.shard as usize, bytes))
            };
            let runs = txn.data.into_iter().map(|(blk, b)| (blk, Wr::Buf(b)));
            let copies = txn.copies.into_iter().map(|c| (c.blk, Wr::Copy(c.src)));
            for (blk, wr) in runs.chain(copies) {
                self.pipeline.back_mut().unwrap().pending_data += 1;
                self.stats.data_blocks += (wr.len() / BLK) as u64;
                if let Some(e) = &mut end {
                    *e += wr.len() as u64;
                }
                self.data_backlog.0.push_back((blk, wr, seq, end));
            }
            self.drain_backlog();
            let left = self.data_backlog.0.len().min(ext) as u64;
            if left > 0 {
                self.pipeline.back_mut().unwrap().backlog = true;
                match self.data_backlog.1 {
                    Stop::Window => self.adm.stats.waits += left,
                    Stop::Dma => self.stats.backlog_dma += left,
                    _ => self.stats.backlog_writes += left,
                }
            }
        }
        // 1b. claimed pre-writes (adr 0477): the unit waits for a write still in flight like for its own data writes;
        //     the unclaimed rest of a piece is returned once its write landed
        for c in &txn.pre {
            self.stats.data_blocks += u64::from(c.nblk);
            match self.pre.commit(c.id, c.nblk, seq) {
                Ok((b, n)) => {
                    if n > 0 {
                        self.unreserve(b, n);
                    }
                }
                Err(()) => self.pipeline.back_mut().unwrap().pending_data += 1,
            }
        }
        // 2. record into the open unit (scratch holds the encoding from validate)
        if !multi {
            let u = self.pipeline.back_mut().unwrap();
            u.payload.extend_from_slice(&self.scratch.b);
            u.ntxn += 1;
            u.tokens.push(txn.token);
            u.frees.extend_from_slice(&rec.frees);
            self.fg_inflight += u32::from(txn.token != MERGE_TOKEN);
        }
        self.next_lsn = lsn + 1;
        self.stats.txns += 1;
        // Idle WAL (nothing in flight or waiting) on a device that issues at submit: seal and submit the unit NOW, next
        // to the data writes (ADR 0021 am. 8): any later seal is added latency of a lone txn (QD1). A device that issues
        // only at the pass's flush (kernel tier) gets the unit sealed at the end of the pass (`end_pass`): every txn of
        // the pass shares it at no latency cost (adr 0021 am. 67). Under load a unit is in flight: txns group anyway.
        if !multi
            && !self.dev.submits_at_flush()
            && self.inflight_units == 0
            && !self.pipeline.iter().any(|u| u.st == UState::Ready)
        {
            self.close_open();
            self.submit_ready();
        }
        rec.recycle();
        Ok(lsn)
    }

    // ---------------------------------------------------------------- WAL unit lifecycle

    /// Seal the open unit: assign ring position (inserting a PAD at the ring end if needed), write its header. Its
    /// on-disk image is built by `submit_ready`, which submits it when a WAL slot is free: a WAL buffer exists only while
    /// its write is in flight (adr 0175 am. 4).
    fn close_open(&mut self) {
        let n_ring = self.dir.wal_blocks;
        let idx = self.pipeline.len() - 1;
        let epoch = self.epoch;
        let shard = self.shard;
        let (first_lsn, ntxn, uflags, part_idx) = {
            let u = &self.pipeline[idx];
            (u.first_lsn, u.ntxn, u.flags, u.part_idx)
        };
        let payload = &self.pipeline[idx].payload;
        // replay ends at a record unit without records (`wal::parse_unit`)
        debug_assert!(
            uflags != 0 || ntxn > 0,
            "sealing a WAL unit without records"
        );
        let nb = (HDR_LEN + payload.len()).div_ceil(BLK) as u64;
        let payload_len = payload.len();
        let payload_crc = crc(payload);
        let mut pad_hdr = None;
        let mut pad_pos = 0;
        if self.head_pos + nb > n_ring {
            let h = UnitHeader {
                epoch,
                first_lsn,
                ntxn: 0,
                nblocks: 1,
                flags: FLAG_PAD,
                shard,
                payload_len: 0,
                prev_crc: self.head_crc,
                payload_crc: crc(&[]),
                acked_lsn: self.durable_lsn,
                store_id: self.store_id,
            };
            let mut header = [0u8; HDR_LEN];
            let c = h.write(&mut header);
            let blocks = n_ring - self.head_pos;
            pad_pos = self.head_pos;
            self.ring.push_back(RingUnit {
                first_lsn,
                last_lsn: first_lsn - 1,
                pos: self.head_pos,
                blocks,
                crc: c,
                part: false,
            });
            self.ring_used += blocks;
            self.head_pos = 0;
            self.head_crc = c;
            self.stats.pads += 1;
            pad_hdr = Some(header);
        }
        let pos = self.head_pos;
        let h = UnitHeader {
            epoch,
            first_lsn,
            ntxn: if uflags != 0 { part_idx } else { ntxn },
            nblocks: nb as u16,
            flags: uflags,
            shard,
            payload_len: payload_len as u32,
            prev_crc: self.head_crc,
            payload_crc,
            acked_lsn: self.durable_lsn,
            store_id: self.store_id,
        };
        let mut header = [0u8; HDR_LEN];
        let c = h.write(&mut header);
        self.ring.push_back(RingUnit {
            first_lsn,
            last_lsn: first_lsn + ntxn as u64 - 1,
            pos: self.head_pos,
            blocks: nb,
            crc: c,
            part: uflags == FLAG_PART,
        });
        self.ring_used += nb;
        self.stats.wal_hw_blocks = self.stats.wal_hw_blocks.max(self.ring_used);
        self.head_pos = (self.head_pos + nb) % n_ring;
        self.head_crc = c;
        self.stats.units += 1;
        self.stats.wal_bytes += nb * BLK as u64;
        self.stats.wal_payload += (HDR_LEN + payload_len) as u64;
        let t_seal = self.dev_ns();
        let u = &mut self.pipeline[idx];
        u.st = UState::Ready;
        u.t_seal = t_seal;
        u.pad_pending = pad_hdr.is_some();
        u.pad_hdr = pad_hdr;
        u.pad_pos = pad_pos;
        u.pos = pos;
        u.hdr = header;
    }

    /// Submit sealed units in order while WAL slots and queue room exist. Their block images are built here from the
    /// header and payload: store metadata IO of the DMA budget (adr 0175 am. 4); refused = the unit stays sealed and is
    /// submitted at a later call (every shard poll), when IO in flight returned memory.
    fn submit_ready(&mut self) {
        // a failed shard issues no IO (a unit whose write was refused lost its buffer)
        while self.failed.is_none() && self.inflight_units < self.cfg.max_inflight_units {
            let Some(i) = self.pipeline.iter().position(|u| u.st == UState::Ready) else {
                break;
            };
            let (seq, pos, pad_pos) = (
                self.pipeline[i].seq,
                self.pipeline[i].pos,
                self.pipeline[i].pad_pos,
            );
            // A wrap needs PAD + WAL; an ordinary unit needs only WAL. Requiring a spare PAD slot
            // for every unit serializes data and WAL on a depth-two device queue.
            let slots = 1 + usize::from(self.pipeline[i].pad_hdr.is_some());
            if self.dev.queue_space() < slots {
                break;
            }
            let nb = (HDR_LEN + self.pipeline[i].payload.len()).div_ceil(BLK);
            let pad = match self.pipeline[i].pad_hdr {
                Some(h) => match self.dev.try_alloc_io_uninit(BLK) {
                    Some(mut b) => {
                        b.copy_from_slices_zero_tail(&[&h]);
                        Some(b)
                    }
                    None => break,
                },
                None => None,
            };
            let Some(mut buf) = self.dev.try_alloc_io_uninit(nb * BLK) else {
                break;
            };
            let u = &mut self.pipeline[i];
            buf.copy_from_slices_zero_tail(&[&u.hdr, &u.payload]);
            u.pad_hdr = None;
            let mut payload = std::mem::take(&mut u.payload);
            payload.clear();
            if self.pool_payload.len() < 8 && payload.capacity() <= 64 * 1024 {
                self.pool_payload.push(payload);
            }
            if let Some(pb) = pad
                && self
                    .dev
                    .submit_write((self.dir.wal_start + pad_pos) * self.lpb, pb, K_PAD | seq)
                    .is_err()
            {
                self.fail(StoreError::Io(IoError::Aborted));
                return;
            }
            if self
                .dev
                .submit_write((self.dir.wal_start + pos) * self.lpb, buf, K_WAL | seq)
                .is_err()
            {
                self.fail(StoreError::Io(IoError::Aborted));
                return;
            }
            self.pipeline[i].st = UState::InFlight;
            self.pipeline[i].t_sub = self.dev_ns();
            self.pipeline[i].ck_dev = self.dev_idle.ck_busy();
            self.inflight_units += 1;
        }
    }

    /// [`wal_floor`] of this shard's queue.
    fn data_floor(&self) -> usize {
        wal_floor(self.cfg.max_inflight_units, self.dev.queue_depth())
    }

    /// Send backlogged data writes in order while the queue has room above the WAL floor (adr 0066), the device window
    /// admits them (adr 0643-device-admission-fifo) and, for a deferred copy, the DMA budget gives its buffer (in-flight
    /// IO memory, adr 0175 am. 4); notes why it stopped. Called at every poll.
    fn drain_backlog(&mut self) {
        let floor = self.data_floor();
        self.data_backlog.1 = Stop::Empty;
        while self.failed.is_none() {
            let Some(&(_, ref wr, _, end)) = self.data_backlog.0.front() else {
                break;
            };
            let len = wr.len() as u64;
            if self.dev.queue_space() <= floor {
                self.data_backlog.1 = Stop::Queue;
                break;
            }
            if let Some(end) = end
                && !self.adm.admits(&self.dev_idle.admit, end)
            {
                self.data_backlog.1 = Stop::Window;
                break;
            }
            if let Wr::Copy(src) = wr {
                let Some(mut b) = self.dev.try_alloc_io_uninit(src.len()) else {
                    self.data_backlog.1 = Stop::Dma;
                    break;
                };
                b.copy_from_slice(src);
                self.data_backlog.0.front_mut().unwrap().1 = Wr::Buf(b);
            }
            let (blk, wr, seq, _) = self.data_backlog.0.pop_front().unwrap();
            let Wr::Buf(buf) = wr else {
                unreachable!("a copy got its buffer above");
            };
            let tag = match end {
                Some(end) => self.adm.submitted(&self.dev_idle.admit, end - len, len),
                None => ADM_OFF,
            };
            if self
                .dev
                .submit_write(blk * self.lpb, buf, K_DATA | tag | seq)
                .is_err()
            {
                self.fail(StoreError::Io(IoError::Aborted));
            }
        }
    }

    fn unit_mut(&mut self, seq: u64) -> Option<&mut Unit> {
        let front = self.pipeline.front()?.seq;
        self.pipeline.get_mut(seq.checked_sub(front)? as usize)
    }

    /// Submit a block read (completion arrives as `Event::Read`). The read pins the current reader epoch until it
    /// completes, so blocks freed meanwhile are not recycled under it. `keep`: the bytes may stay in the data cache (read
    /// into ordinary memory when the device can, [`BlockDev::alloc_buf_ram_uninit`]). `Busy` when the device queue is
    /// full or its DMA budget has no buffer to spare now (deferrable memory, [`BlockDev::try_alloc_buf_uninit`]): the
    /// caller retries at its next progress step, after polling completions (adr 0175 am. 4).
    pub fn submit_read(&mut self, blk: u64, nblk: u32, token: u64, keep: bool) -> Result<()> {
        self.read_cmd(blk, nblk, token, if keep { Mem::Keep } else { Mem::Defer })
    }

    /// [`Shard::submit_read`] into in-flight IO memory ([`BlockDev::try_alloc_io_uninit`], adr 0175 am. 4): a
    /// synchronous read whose caller waits for the completion and consumes the bytes then (copied, or shared within the
    /// DMA budget's read gate).
    pub fn submit_io_read(&mut self, blk: u64, nblk: u32, token: u64) -> Result<()> {
        self.read_cmd(blk, nblk, token, Mem::Io)
    }

    fn read_cmd(&mut self, blk: u64, nblk: u32, token: u64, mem: Mem) -> Result<()> {
        if self.failed.is_some() {
            return Err(StoreError::Failed);
        }
        assert!(token <= MAX_READ_TOKEN);
        if nblk as usize > self.max_xfer_blk {
            return Err(StoreError::TxnTooLarge);
        }
        let len = nblk as usize * BLK;
        let b = match mem {
            Mem::Keep if self.dev.ram_reads() => Some(self.dev.alloc_buf_ram_uninit(len)),
            Mem::Keep | Mem::Defer => self.dev.try_alloc_buf_uninit(len),
            Mem::Io => self.dev.try_alloc_io_uninit(len),
        }
        .ok_or(StoreError::Busy)?;
        self.dev
            .submit_read(blk * self.lpb, b, K_READ | token)
            .map_err(|r| match r.err {
                SubmitError::QueueFull => StoreError::Busy,
                _ => StoreError::Io(IoError::Aborted),
            })?;
        self.dev_note();
        let e = self.read_pin();
        self.reads.insert(token, e);
        Ok(())
    }

    /// Give the device's unused cache memory back after the data cache evicted ([`BlockDev::trim_ram`]).
    pub fn trim_ram(&mut self) {
        self.dev.trim_ram();
    }

    /// Give parked DMA buffers back when another core ran short ([`BlockDev::release_pooled`]); the store sweep.
    pub fn release_pooled(&mut self) {
        self.dev.release_pooled();
    }

    /// The data cache floor in blocks (`ShardCfg::data_floor_blocks`).
    pub fn data_floor_blocks(&self) -> u64 {
        self.cfg.data_floor_blocks
    }

    /// Bytes of the tree page budget the tree has not allocated and the caches may borrow (adr 0633-data-cache-envelope):
    /// when the device reads into ordinary memory ([`BlockDev::ram_reads`]); 0 when it reads only into a bounded DMA pool.
    /// Shrinks as the tree grows (metadata first).
    pub(crate) fn lendable(&self) -> u64 {
        if self.dev.ram_reads() {
            self.state.tree.unallocated_bytes()
        } else {
            0
        }
    }

    /// The share of [`Shard::lendable`] one cache may hold on top of its own: the other cache's unused part (work
    /// conserving), but at least half, so a busy cache never starves the other of what it brings.
    fn lend_share(lendable: u64, other_borrowed: u64) -> u64 {
        (lendable - lendable / 2).max(lendable.saturating_sub(other_borrowed))
    }

    /// Bytes of this shard's cache share the data cache may hold on top of its floor (adr 0633-data-cache-envelope): the part of the
    /// tree page budget the tree has not allocated yet that the omap run block cache of a store with the omap engine does
    /// not hold beyond its own share (`lend_share`). Shrinks as the tree grows.
    pub fn data_cache_lend(&self) -> u64 {
        let l = self.lendable();
        match &self.ol {
            Some(d) => Self::lend_share(l, d.borrowed()),
            None => l,
        }
    }

    /// The object layer reports the bytes its data cache and prefetch table hold above the floor.
    pub fn set_data_cache_held(&mut self, bytes: u64) {
        self.dc_held = bytes;
    }

    /// Mirror the object layer's ordinary client read admission queue. Hints cannot consume slots
    /// a waiting all-or-nothing read batch needs; demanded reads and WAL keep their existing admission.
    pub(crate) fn set_read_admission_waiting(&mut self, waiting: bool) {
        self.read_admission_waiting = waiting;
    }

    /// Free slots and depth of the device queue (prefetch admission).
    pub fn read_queue(&self) -> (usize, usize) {
        (self.dev.queue_space(), self.dev.queue_depth())
    }

    /// Drop the reader pin a `PF_TOKEN` read kept after its completion (the prefetched data is discarded).
    pub fn read_release(&mut self, token: u64) {
        if let Some(ep) = self.reads.remove(&token) {
            self.read_unpin(ep);
        }
    }

    // ---------------------------------------------------------------- checkpoint

    // ---------------------------------------------------------------- omap run merges (adr 0476)

    /// Merge runs into the tree now: runs over their soft size, ring units held by their floor at the checkpoint ring
    /// threshold, a user txn refused for their page charge (all: the floor object first), or an object without a new run
    /// for a checkpoint interval (idle: that object). The run count of an object is bounded by compactions (`run_max`), not
    /// by tree merges.
    fn merge_wanted(&self) -> bool {
        !self.state.runs.is_empty()
            && (self.mg.is_some() || self.merge_pressed() || self.idle_obj().is_some())
    }

    /// A merge slice can go now: one is wanted and the merge in progress is not ahead of its pace (a paced merge waits
    /// for writes, which wake the shard).
    fn merge_due(&self) -> bool {
        self.merge_wanted() && (self.mg.is_none() || self.merge_pace() > 0)
    }

    /// Most entries the next merge slice moves (0: none now): [`MERGE_ENTS`] for a merge some limit waits on (drain,
    /// page charge, ring, new runs waiting for room: [`Shard::run_room`]); an idle object's merge (nobody waits on it)
    /// moves what fits in [`MERGE_SLICE_NS`] of core time, so it interleaves with the core's messages. A merge of a
    /// written object below those limits is background work paced by the writes (adr 0476 am. 8): it moves one entry
    /// per run entry admitted since it began, in slices of [`MERGE_SLICE_NS`] ([`Shard::merge_time_cap`], like an idle
    /// object's: a whole slice on a cold tree holds the PG core for ms) while it is behind and the pool is over its soft
    /// size ([`Shard::run_over`]: the merge is owed for memory), and none while it is ahead or the pool is back below the
    /// soft size (a mix after a fill: the merge work stays deferred as before the merge began), so the merge work spreads
    /// over the writes (no deficit, no burst near the hard size). Ahead of its pace with no other
    /// txn in the pipeline and no run admitted since its latest slice or paced wait (an idle gap), it takes one such
    /// slice too: a merge whose writes stopped goes on at the idle merge's rate instead of waiting 1-2 checkpoint
    /// intervals for the idle marks while its runs slow every read of the object.
    fn merge_pace(&self) -> usize {
        if self.mg_drain
            || self.mg_want
            || self.ring_full_by_floor()
            || self.run_ring_full()
            || !self.run_room()
        {
            return MERGE_ENTS;
        }
        if !self.run_over() && self.idle_obj().is_some() {
            return self.merge_time_cap();
        }
        let (a0, done, seen) = self.mg_pace;
        let admitted = self.state.runs.admitted();
        if admitted - a0 > done && self.run_over() || self.fg_inflight == 0 && admitted == seen {
            self.merge_time_cap()
        } else {
            0
        }
    }

    /// Most entries a merge slice of [`MERGE_SLICE_NS`] moves at the learned cost per entry ([`MERGE_ENTS`] before the
    /// first slice).
    fn merge_time_cap(&self) -> usize {
        if self.mg_ps_per_ent == 0 {
            return MERGE_ENTS;
        }
        (MERGE_SLICE_NS * 1000 / self.mg_ps_per_ent).clamp(1, MERGE_ENTS as u64) as usize
    }

    /// Core time of the merge slice of `n` entries that began at `t0` (`fastclock::thread_cpu_ns`).
    #[cfg_attr(not(feature = "lab"), allow(unused_variables))]
    fn merge_slice_ns(&self, t0: u64, n: usize) -> u64 {
        #[cfg(feature = "lab")]
        if self.lab_merge_ps != 0 {
            return n as u64 * self.lab_merge_ps / 1000;
        }
        crate::fastclock::thread_cpu_ns().saturating_sub(t0)
    }

    /// Learns the cost per entry from a submitted slice of `n` entries that took `ns`.
    fn merge_learn(&mut self, ns: u64, n: usize) {
        if n == 0 {
            return;
        }
        let ps = (ns * 1000 / n as u64).max(1);
        self.mg_ps_per_ent = if self.mg_ps_per_ent == 0 {
            ps
        } else {
            self.mg_ps_per_ent - self.mg_ps_per_ent / 8 + ps / 8
        };
    }

    fn merge_pressed(&self) -> bool {
        self.mg_drain
            || self.mg_want
            || self.run_over()
            || self.ring_full_by_floor()
            || self.run_ring_full()
    }

    /// An idle object: no new run since the mark before the latest one (one to two checkpoint intervals).
    fn idle_obj(&self) -> Option<u64> {
        self.state.runs.idle_obj(self.mg_mark.2)
    }

    /// Advance the idle marks (once per checkpoint interval). Every poll does this before its quiescence check: a mark
    /// taken only while merging would never make an object idle once nothing else wakes the shard.
    fn idle_mark(&mut self, now: Nanos) {
        if now.saturating_sub(self.mg_mark.0) >= self.cfg.ckpt_interval_ns {
            self.stats.run_idle_marks += 1;
            self.mg_mark = (now, self.state.runs.inserted(), self.mg_mark.1);
        }
    }

    /// Meta pages a merge (sys) txn may dirty now: free pages plus those elastic growth can still add (above the sys data
    /// floor), less the dirty ones and the whole meta reserve (merges leave it to PG-state and replica txns).
    fn merge_pages(&self) -> usize {
        let t = &self.state.tree;
        (t.meta.free() as usize + self.meta_growable())
            .saturating_sub(t.dirty_pages() + self.meta_reserve as usize)
    }

    /// Meta pages elastic growth can still add: free data blocks above the sys data floor, while growth is not blocked
    /// (0 for a fixed meta area).
    fn meta_growable(&self) -> usize {
        if self.cell_blocks != 0 && self.meta_blocked.is_none() {
            let floor = self.data_reserve / 3 + self.mig_hold;
            (self.state.alloc.n_free().saturating_sub(floor) / self.state.tree.geom().bpp.max(1))
                as usize
        } else {
            0
        }
    }

    /// The object a new merge takes: under pressure the one holding the floor (oldest run), else an idle one; all its runs.
    fn merge_target(&self) -> Option<(u64, u64)> {
        let r = &self.state.runs;
        let id = if self.merge_pressed() {
            r.oldest_obj()?
        } else {
            self.idle_obj()?
        };
        Some((id, r.newest(id)?))
    }

    /// Ring blocks a re-log of one record's runs may take: one unit, or the multi-part chain of the largest live run
    /// record (`extra`: WAL op bytes of runs about to be logged by one record).
    fn relog_blocks(&self, extra: usize) -> u64 {
        let b = self.state.runs.max_rec_bytes().max(extra) + REC_HDR_LEN;
        self.multi_blocks(b).max(self.cfg.max_unit_blocks as u64)
    }

    /// Re-log the live runs of the ring unit holding the floor record (a multi-part chain: its record): one record of
    /// re-logs, never more blocks than that unit (same op encoding, a subset of its entries, one record header). The
    /// checkpoint after it releases the unit; the reserve every other txn keeps (`relog_blocks`) guarantees the room.
    fn relog_floor(&mut self) {
        let Some(f) = self.state.runs.floor() else {
            return;
        };
        let mut i = self
            .ring
            .partition_point(|u| u.last_lsn.max(u.first_lsn) < f);
        while self
            .ring
            .get(i)
            .is_some_and(|u| u.part || u.last_lsn < u.first_lsn)
        {
            i += 1;
        }
        let Some(hi) = self.ring.get(i).map(|u| u.last_lsn) else {
            return; // the floor record is not in the ring yet
        };
        let blobs = self.state.runs.relog_range(f, hi);
        let mut t: Txn<D::Buf> = Txn::new(MERGE_TOKEN);
        t.ops = blobs.into_iter().map(Op::RunPut).collect();
        t.sys = true;
        match self.submit(t) {
            Ok(_) => {
                self.stats.run_relogs += 1;
                self.rl_wait = true;
                self.force_ckpt();
            }
            Err((StoreError::Busy | StoreError::WalFull | StoreError::Miss, _)) => {
                self.stats.run_txn_refused += 1;
            }
            Err((e, _)) => self.fail(e),
        }
    }

    /// Run compactions (adr 0476 step 4): the lost ones are dropped ([`Shard::drop_lost_compactions`]), new ones start
    /// for the objects that received runs (on runs above a tree merge in progress of the object and outside the windows
    /// of those under way: a small tier is not held up by a large one), then one [`COMPACT_ENTS`] step budget shared by
    /// the inline jobs; a finished one is swapped in and its object checked again (the merged run may complete the next
    /// tier).
    fn compact_step(&mut self) {
        if self.failed.is_some() {
            return;
        }
        self.drop_lost_compactions();
        let fan = self.cfg.run_fan.clamp(2, 64);
        while let Some(id) = self.state.runs.next_cand() {
            let barrier = self.merge_barrier(id);
            loop {
                let busy: Vec<(u64, u64)> = self
                    .cps
                    .iter()
                    .filter(|c| c.id() == id)
                    .map(|c| c.window())
                    .chain(
                        self.compact_remote
                            .iter()
                            .filter(|r| r.1 == id)
                            .map(|r| r.2),
                    )
                    .collect();
                match self
                    .state
                    .runs
                    .compaction(id, fan, self.cfg.run_max, barrier, &busy)
                {
                    Some(c) => self.cps.push(c),
                    None => break,
                }
            }
        }
        if self.cps.is_empty() {
            return;
        }
        // One prepared job per free helper core; the rest (and any the shared helper budget refuses) step inline.
        while self.compact_ready.len() < self.compact_available
            && let Some(i) = self.cps.iter().rposition(|c| c.helper_allowed())
        {
            let c = self.cps.swap_remove(i);
            let charge = c.reservation();
            let Some(permit) = self.pool.reserve_helper(charge) else {
                self.cps.push(c);
                break;
            };
            let id = self.next_compaction_id();
            self.compact_remote.push((id, c.id(), c.window(), charge));
            self.compact_ready.push(RunCompactionJob {
                id,
                compaction: c,
                _permit: permit,
            });
        }
        // Preserve main's aggregate inline budget; dispatch does not grant each remaining job another slice.
        self.cps.sort_by_key(|c| c.left());
        let mut budget = COMPACT_ENTS;
        let mut done = 0;
        for c in &mut self.cps {
            if budget == 0 {
                break;
            }
            let l = c.left();
            if c.step(budget) {
                done += 1;
            }
            budget = budget.saturating_sub(l - c.left());
        }
        for c in self.cps.drain(..done).collect::<Vec<_>>() {
            let (id, nout) = (c.id(), c.len() as u64);
            if self.state.runs.swap_in(c) {
                self.stats.run_compactions += 1;
                self.stats.run_compacted_ents += nout;
            } else {
                self.stats.run_compact_lost += 1;
            }
            self.state.runs.add_cand(id);
        }
        self.pool.publish(self.run_mem());
    }

    /// Drop the compactions whose input left or was replaced ([`crate::runs::RunSet::holds`]): their result can no longer
    /// be swapped in, so they are not stepped to their end; their output and the inputs only they still hold return now
    /// (removals kill whole runs while a large compaction of them waits behind smaller ones: kept, such compactions pinned
    /// their inputs and outputs unseen by the run memory, doc/perf/omap-hot-object-20261029.md), and their object is
    /// checked again as after a swap-in (its remaining runs are free for the next compaction). A job prepared for a helper
    /// and not taken yet goes with them; one out on a helper is lost when it returns.
    fn drop_lost_compactions(&mut self) {
        let runs = &mut self.state.runs;
        let n = self.cps.len();
        self.cps.retain(|c| {
            let holds = runs.holds(c);
            if !holds {
                runs.add_cand(c.id());
            }
            holds
        });
        let mut lost = n - self.cps.len();
        let remote = &mut self.compact_remote;
        self.compact_ready.retain(|j| {
            let holds = runs.holds(&j.compaction);
            if !holds {
                runs.add_cand(j.compaction.id());
                remote.retain(|r| r.0 != j.id);
                lost += 1;
            }
            holds
        });
        if lost > 0 {
            self.stats.run_compact_lost += lost as u64;
            self.pool.publish(self.run_mem());
        }
    }

    /// One merge slice: the next entries of the merge in progress (key order across the object's runs), as many as the
    /// meta room and the per-txn page budget allow (each may dirty a leaf of its own); the last slice drops the runs.
    fn merge_step(&mut self) {
        if self.state.runs.is_empty() {
            self.mg = None;
            self.mg_drain = false;
            self.mg_want = false;
        }
        if self.failed.is_some() || self.state.runs.is_empty() {
            return;
        }
        if !self.merge_wanted() {
            self.stats.run_merge_skips[0] += 1;
            return;
        }
        if self.mg_loads {
            // queued wants count too: a miss queues them, the poll issues them
            if self.loads_pending() || self.state.tree.has_wants() {
                self.stats.run_merge_skips[1] += 1;
                return;
            }
            self.mg_loads = false;
        }
        // dirty pages at the hard limit: the admission refuses any merge (it checks that first). A merge no limit waits
        // on is background work: it stops at the soft mark (where the dirty checkpoint starts) and leaves the band up to
        // the hard mark to client txns; filling it with an idle object's backlog made client txns hit the hard mark
        // (Busy until the checkpoint ended: 110 ms holds of every op of the PG in b-mix, doc/perf/ckpt-holds-20261025.md, adr 0476 am. 7)
        let dirty = self.state.tree.dirty_pages();
        let mark = if self.merge_pressed() {
            self.cfg.dirty_hard_pages
        } else {
            self.cfg.dirty_soft_pages
        };
        if dirty >= mark {
            self.stats.run_merge_skips[2] += 1;
            if mark == self.cfg.dirty_hard_pages {
                self.force_ckpt();
            } else {
                self.stats.run_merge_dirty_waits += 1;
            }
            return;
        }
        // ring liveness: the floor holds the checkpoint share of the ring (merges do not keep up, or cannot get ring or
        // meta room): re-log the runs of the floor's unit, once per checkpoint
        if !self.rl_wait && self.ring_full_by_floor() {
            self.relog_floor();
        }
        if self
            .mg
            .as_ref()
            .is_some_and(|(id, _, _)| !self.state.runs.has_obj(*id))
        {
            self.mg = None; // the object's runs left (clear / removal)
        }
        if self.mg.is_none() {
            self.mg_slice = None;
            let Some((id, upto)) = self.merge_target() else {
                return;
            };
            let mut a = vec![b'o'];
            a.extend_from_slice(&id.to_be_bytes());
            a.push(crate::obj::keys::S_OMAP);
            self.mg = Some((id, upto, a));
            let ad = self.state.runs.admitted();
            self.mg_pace = (ad, 0, ad);
            let why = if self.mg_drain || self.mg_want {
                0
            } else if self.run_over() {
                1
            } else if self.ring_full_by_floor() || self.run_ring_full() {
                2
            } else {
                3
            };
            self.stats.run_merge_starts[why] += 1;
        }
        let (id, upto, a) = self.mg.clone().unwrap();
        let mut end = vec![b'o'];
        end.extend_from_slice(&id.to_be_bytes());
        end.push(crate::obj::keys::S_OMAP + 1);
        // room: meta pages left and dirty pages before the hard mark, against the admission's own upper bound of the
        // pages a merge record dirties (`State::prepare`: per entry its leaf and a split, the byte splits, one spare
        // page, the shared path twice); the probed leaves stay within half the per-txn page budget (at least one entry:
        // its path alone fits like a single put's)
        let room = self.merge_pages().min(mark - dirty);
        let path = self.state.tree.height() as usize + 2;
        let psz = self.state.tree.psz();
        let pace = self.merge_pace();
        if pace == 0 {
            self.stats.run_merge_skips[3] += 1;
            self.mg_pace.2 = self.state.runs.admitted();
            return;
        }
        let leaves = (self.state.tree.txn_page_budget() / 2)
            .saturating_sub(path)
            .clamp(1, pace);
        let t0 = crate::fastclock::thread_cpu_ns();
        let pages = |n: usize, bytes: usize| {
            let s = n + 1 + 2 * (bytes + 29) / psz + 1;
            (n + 1 + path) + s + s / 8 + path
        };
        // a refused slice is taken again as built while it still fits (its entries can only have become fewer: kills; runs
        // logged since are newer than `upto`)
        let (n, bytes, hi) = match self.mg_slice.take() {
            Some((n, bytes, hi)) if pages(n, bytes) <= room => (n, bytes, hi),
            _ => {
                let (mut n, mut bytes) = (0usize, 0usize);
                let hi = self.state.plan_merge(id, upto, &a, &end, |e| {
                    if n == leaves || pages(n + 1, bytes + e) > room {
                        return false;
                    }
                    n += 1;
                    bytes += e;
                    true
                });
                (n, bytes, hi)
            }
        };
        if n == 0 && hi.is_some() {
            // not even one entry fits: a checkpoint frees the dirty pages, else the meta space is exhausted
            if self.state.tree.dirty_pages() > 0 || self.ckpt_active() {
                self.force_ckpt();
                self.stats.run_merge_waits += 1;
                if mark != self.cfg.dirty_hard_pages {
                    self.stats.run_merge_dirty_waits += 1;
                }
            } else {
                self.mg_full = true;
            }
            return;
        }
        let fin = hi.is_none();
        let slice = (n, bytes, hi.clone());
        let b = hi.unwrap_or(end);
        let mut t: Txn<D::Buf> = Txn::new(MERGE_TOKEN);
        t.ops = vec![Op::RunMerge {
            id,
            upto,
            a,
            b: b.clone(),
            fin,
        }];
        t.sys = true;
        match self.submit(t) {
            Ok(_) => {
                let cost = self.merge_slice_ns(t0, n);
                self.merge_learn(cost, n);
                self.stats.run_merges += 1;
                self.stats.run_merged_ents += n as u64;
                self.mg_pace.1 += n as u64;
                self.mg_pace.2 = self.state.runs.admitted();
                self.mg = if fin { None } else { Some((id, upto, b)) };
                if fin {
                    self.mg_want = false;
                    if self.mg_drain && self.state.runs.is_empty() {
                        self.mg_drain = false;
                    }
                }
            }
            Err((StoreError::Miss, _)) => {
                // its leaves are being read: the slice is submitted again once they are resident, not on every poll
                self.stats.run_txn_refused += 1;
                self.stats.run_merge_miss += 1;
                self.stats.run_merge_miss_pages += (self.state.tree.wants_len()
                    + self.deferred.len()
                    + self.page_reads_inflight())
                    as u64;
                self.mg_loads = true;
                self.mg_slice = Some(slice);
            }
            Err((StoreError::Busy | StoreError::WalFull, _)) => {
                self.stats.run_txn_refused += 1;
                self.mg_slice = Some(slice);
            }
            Err((StoreError::NoSpace, _)) => {
                self.mg_drain = false;
                self.mg_want = false;
                self.mg_full = true;
            }
            Err((e, _)) => self.fail(e),
        }
    }

    fn ckpt_wanted(&self, now: Nanos) -> bool {
        self.ckpt_why(now).is_some()
    }

    /// Why a checkpoint is due now (index into `ShardStats::ckpt_why`: 0 requested/forced, 1 space, 2 WAL ring, 3 dirty
    /// pages, 4 dirty bitmap chunks, 5 interval), or `None`.
    fn ckpt_why(&self, now: Nanos) -> Option<usize> {
        // a read-only mount never checkpoints (the replayed state stays in memory)
        if self.read_only || self.ckpt_clean() {
            return None;
        }
        if self.ck_requested {
            return Some(0);
        }
        if !self.cfg.auto_ckpt {
            return None;
        }
        if self.space_low() {
            Some(1)
        } else if (self.ring_used - self.floor_blocks()) * 100
            >= self.dir.wal_blocks * self.cfg.ckpt_wal_pct as u64
        {
            Some(2)
        } else if self.state.tree.dirty_pages() >= self.cfg.dirty_soft_pages {
            Some(3)
        } else if self.state.dirty_chunks() >= self.cfg.dirty_soft_pages / 2 {
            Some(4)
        } else if self.ckpt_due.is_some_and(|d| now >= d) {
            Some(5)
        } else {
            None
        }
    }

    /// Nothing to persist: nothing logged since the last checkpoint, and none of the state only the lazy free (adr 0021
    /// am. 18) and background merges (am. 33) leave without a record.
    fn ckpt_clean(&self) -> bool {
        self.next_lsn - 1 <= self.ckpt_lsn
            && !self.state.tree.dead_dirty()
            && self.reclaim == 0
            && !self.bg_dirty
            && !self.ring.front().is_some_and(Self::is_pad)
    }

    /// Near full (adr 0021 am. 33): the free data space above the user floor is less than twice what acked frees hold for
    /// the next checkpoint. Start that checkpoint now (it runs while the rest of the headroom is used): otherwise allocations reach the floor first, get `Busy` and the
    /// txn path waits for the forced checkpoint inside `queue` (the core stalls: no network polling for the whole
    /// checkpoint). Bounded: true only while that checkpoint would release blocks.
    fn space_low(&self) -> bool {
        self.free_q_blocks > 0
            && self.state.alloc.n_free() + self.trim.held() + self.lend_coming()
                < self.user_floor() + 2 * self.free_q_blocks
    }

    /// Include physical maps reserved during an active freeze: the current image is frozen, but the
    /// next checkpoint must persist those maps along with the transactions admitted against their pages.
    fn meta_image_need(&self) -> usize {
        let tree = &self.state.tree;
        let deferred: usize = self
            .fz_cells
            .iter()
            .map(|e| tree.meta.added_cell_blob_len(e.len()))
            .sum();
        tree.blob_need() + crate::alloc::blob_pages(tree.blob_len() + deferred, tree.psz())
            - crate::alloc::blob_pages(tree.blob_len(), tree.psz())
    }

    /// Checkpoint headroom includes every distinct bitmap chunk touched by pending physical extents.
    /// `future_chunks` allows for an additional cell not reserved yet.
    fn ckpt_extra_pages(&self, future_chunks: usize) -> usize {
        self.state
            .chunk_reserve(self.pending_cell_chunks.len() + future_chunks)
            + self.meta_image_need()
            + 2
    }

    /// Cache this set only when growing; admission reads its length without allocating.
    fn note_meta_chunks(&mut self, extents: &[MetaExtent]) {
        for e in extents {
            let start = self.state.alloc.rel_of(e.start);
            let end = start + u64::from(e.pages) * self.state.tree.geom().bpp;
            for ci in start / crate::alloc::CHUNK_BLOCKS..=(end - 1) / crate::alloc::CHUNK_BLOCKS {
                if !self.pending_cell_chunks.contains(&ci) {
                    self.pending_cell_chunks.push(ci);
                }
            }
        }
    }

    /// Prefer one contiguous extent, then gather whole tree pages from smaller runs.
    /// A logical cell is published only after the entire reservation succeeds.
    fn reserve_meta_extents(&mut self, blocks: u32, bpp: u32) -> Option<Vec<MetaExtent>> {
        if let Some(start) = self.state.alloc.reserve(blocks) {
            return Some(vec![MetaExtent {
                start,
                pages: blocks / bpp,
            }]);
        }
        let mut remaining = blocks;
        let mut extents: Vec<MetaExtent> = Vec::new();
        while remaining > 0 {
            let Some((start, n)) = self.state.alloc.reserve_upto(bpp, remaining) else {
                for e in extents {
                    self.unreserve(e.start, e.pages * bpp);
                }
                return None;
            };
            let whole = n / bpp * bpp;
            if whole < n {
                self.unreserve(start + u64::from(whole), n - whole);
            }
            extents.push(MetaExtent {
                start,
                pages: whole / bpp,
            });
            remaining -= whole;
        }
        Some(extents)
    }

    /// Delta chains the next checkpoint may fold back into whole leaves (adr 0021 am. 51): each fold dirties a root-to-leaf
    /// path, pages no admission counted. Paid from the free meta pages above the checkpoint's own need plus the cells
    /// whole free windows can still give (`free_windows`: a cell needs one contiguous run).
    fn fold_budget(&self) -> usize {
        let t = &self.state.tree;
        let need = t.dirty_pages() + self.ckpt_extra_pages(2);
        // legacy fixed meta region (cell_blocks 0): nothing growable; nor while growth is blocked (image at its limit,
        // data full, or no run): `grow_meta` would refuse even with whole windows left
        let cells = if self.meta_blocked.is_some() {
            0
        } else {
            (self.free_windows() * crate::alloc::WIN)
                .checked_div(self.cell_blocks)
                .unwrap_or(0)
        };
        let growable = cells as usize * t.meta.ppc() as usize;
        (t.meta.free() as usize + growable).saturating_sub(need) / (t.height() as usize + 1)
    }

    /// Empty cells a checkpoint started now would give back: while enough free pages remain (the headroom the
    /// checkpoint itself and the admission reserve need, plus `meta_slack_cells` cells) and the meta space stays at `hold` pages (the checkpoint start:
    /// the largest size the last two cycles asked for, `meta_peak`, adr 0021 am. 80; 0 = the cells `reclaim` counts).
    /// Also while growth is blocked (adr 0021 am. 21): the surplus above the headroom is never needed back, and keeping
    /// it starves the data region (the shard could never recover from full).
    fn giveable_cells(&self, hold: usize) -> Vec<u64> {
        let ppc = self.state.tree.meta.ppc() as usize;
        let m = &self.state.tree.meta;
        let hold_free = hold.saturating_sub(m.used() as usize);
        let mut release_chunks = self.pending_cell_chunks.clone();
        let mut free = m.free() as usize;
        let mut give = Vec::new();
        let mut empty = m.empty_cells();
        empty.reverse();
        // elastic reclaim (adr 0021 am. 57): an empty cell inside a borrowed chunk pins the chunk; it goes first and
        // without the slack (regrowth takes the base first)
        #[cfg(feature = "elastic")]
        let borrowed = |s: u64| {
            self.lend.on
                && m.cell_extents(s, self.state.tree.geom().bpp)
                    .iter()
                    .any(|&(start, _)| {
                        self.state.alloc.window_of(start).is_some_and(|w| {
                            w as u64 * crate::alloc::WIN >= self.state.alloc.base_blocks()
                        })
                    })
        };
        #[cfg(not(feature = "elastic"))]
        let borrowed = |_: u64| false;
        empty.sort_by_key(|&s| !borrowed(s));
        for start in empty {
            if self.pending_cells.contains(&start) {
                continue;
            }
            let previous = release_chunks.len();
            for (block, blocks) in m.cell_extents(start, self.state.tree.geom().bpp) {
                let first = self.state.alloc.rel_of(block);
                let end = first + u64::from(blocks);
                for ci in
                    first / crate::alloc::CHUNK_BLOCKS..=(end - 1) / crate::alloc::CHUNK_BLOCKS
                {
                    if !release_chunks.contains(&ci) {
                        release_chunks.push(ci);
                    }
                }
            }
            // Giving a fragmented cell back can dirty many allocator chunks. Keep enough metadata
            // to persist all of those frees before removing any of its pages from the logical map.
            let hard = self.state.tree.dirty_pages()
                + self.state.chunk_reserve(release_chunks.len() + 2)
                + self.meta_image_need()
                + 2
                + self.meta_reserve as usize;
            let keep = if borrowed(start) {
                hard
            } else {
                (hard + self.cfg.meta_slack_cells as usize * ppc).max(hold_free)
            };
            if free < keep + ppc {
                release_chunks.truncate(previous);
                continue;
            }
            free -= ppc;
            give.push(start);
        }
        give
    }

    /// Meta space asked for (adr 0021 am. 80): `free` free pages on top of the used ones.
    fn note_meta_need(&mut self, free: usize) {
        let want = self.state.tree.meta.used() as usize + free;
        self.meta_peak = self.meta_peak.max(want);
    }

    /// Data blocks of the empty cells a checkpoint gives back when the meta peak yields (`reclaim`: free data space; per
    /// checkpoint, not on the hot path).
    fn reclaim_blocks(&self) -> u64 {
        if self.cell_blocks == 0 {
            return 0;
        }
        self.giveable_cells(0).len() as u64 * self.cell_blocks
    }

    /// Elastic meta housekeeping at the start of a checkpoint (runs right before the last bitmap chunks are written):
    /// give empty cells back while enough free pages remain (the free headroom the checkpoint itself and the admission
    /// reserve need, and the meta space the last two cycles asked for, `meta_peak`, `giveable_cells`), make sure the
    /// checkpoint has room (replayed state can exceed what admission guaranteed), then commit the cells reserved
    /// since the last one: allocated in the durable bitmap and part of this checkpoint's meta image.
    fn meta_housekeeping(&mut self) -> Result<()> {
        // an idle checkpoint (nothing logged since the last one) asked for nothing: the peak yields
        let hold = if self.next_lsn - 1 == self.ckpt_lsn {
            0
        } else {
            self.meta_peak.max(self.meta_peak_prev)
        };
        let give = self.giveable_cells(hold);
        if !give.is_empty() {
            // the freed cells are growth room again: retry a blocked growth when it is next needed
            self.meta_blocked = None;
            self.meta_wait = None;
            // from here on their blocks are held (free capacity until the checkpoint completes)
            self.reclaim = 0;
        }
        for start in give {
            let extents = self
                .state
                .tree
                .meta
                .cell_extents(start, self.state.tree.geom().bpp);
            self.state.tree.meta.remove_cell(start);
            for (block, blocks) in extents {
                self.state.cell_give(block, blocks);
                self.shrunk.push((block, blocks));
            }
            self.stats.cells_released += 1;
        }
        loop {
            let need = self.state.tree.dirty_pages() + self.ckpt_extra_pages(0);
            self.note_meta_need(need);
            if self.state.tree.meta.free() as usize >= need {
                break;
            }
            if !self.grow_meta(need, 0) {
                // windows a deallocate holds come back at its completion: retry then
                if self.trim_miss() {
                    return Err(StoreError::Busy);
                }
                return Err(StoreError::NoSpace);
            }
        }
        for start in std::mem::take(&mut self.pending_cells) {
            for (block, blocks) in self
                .state
                .tree
                .meta
                .cell_extents(start, self.state.tree.geom().bpp)
            {
                self.state.cell_take(block, blocks);
            }
        }
        self.pending_cell_chunks.clear();
        Ok(())
    }

    /// Elastic meta: reserve cells from the data allocator until `want` pages are free (the cells are part of the
    /// durable state only after the next checkpoint, see `meta_housekeeping`). `reserve`: data blocks that stay free (the
    /// hard reserve for user txns, less for sys, 0 for shrinks). False when the data region cannot provide enough whole pages or the image would outgrow its pages.
    fn grow_meta(&mut self, want: usize, reserve: u64) -> bool {
        let mut dt = crate::diag::t0();
        let r = self.grow_meta_inner(want, reserve);
        crate::diag::lap(37, &mut dt);
        r
    }

    fn grow_meta_inner(&mut self, want: usize, reserve: u64) -> bool {
        if self.cell_blocks == 0 {
            return false;
        }
        // a growth miss that waited for a deallocate: the command completed, its windows are free (adr 0642)
        self.trim_wait &= self.trim.in_flight();
        let cb = self.cell_blocks;
        let psz = self.state.tree.psz();
        let ppc = self.state.tree.meta.ppc() as usize;
        // after a failure the (whole-bitmap) search is retried only once space was freed: a checkpoint released
        // held blocks or a cell's worth of blocks became free since
        if let Some(at) = self.meta_blocked
            && !self.meta_retry
            && self.state.alloc.n_free() < at + cb
        {
            return false;
        }
        while self.meta_free() < want {
            // Budget the cell bitmap and physical extent map, including cells deferred by a sliced freeze.
            let deferred: usize = self
                .fz_cells
                .iter()
                .map(|e| self.state.tree.meta.added_cell_blob_len(e.len()))
                .sum();
            let image_bytes = self.state.tree.meta.blob_len();
            let image_reserve_bytes = self.state.tree.ext_reserve();
            let image_needed_bytes = image_bytes
                + image_reserve_bytes
                + deferred
                + self.state.tree.meta.added_cell_blob_len(1);
            let image_limit_bytes = crate::alloc::blob_max_len(psz);
            let n_free = self.state.alloc.n_free();
            if image_needed_bytes > image_limit_bytes || n_free < cb {
                let reason = if image_needed_bytes > image_limit_bytes {
                    MetaGrowthFailureReason::ImageLimit
                } else {
                    MetaGrowthFailureReason::InsufficientFreeBlocks
                };
                // a deallocate in flight holds free windows (back at its completion): no failure; or a checkpoint cures it
                if reason == MetaGrowthFailureReason::InsufficientFreeBlocks
                    && (self.trim_miss() || self.defer_growth(n_free))
                {
                    return false;
                }
                self.capture_meta_growth_failure(MetaGrowthFailureContext {
                    reason,
                    requested_free_pages: want as u64,
                    free_data_blocks: n_free,
                    reserve_data_blocks: reserve,
                    cell_blocks: cb,
                    pages_per_cell: ppc as u64,
                    image_bytes: image_bytes as u64,
                    image_reserve_bytes: image_reserve_bytes as u64,
                    deferred_image_bytes: deferred as u64,
                    image_needed_bytes: image_needed_bytes as u64,
                    image_limit_bytes: image_limit_bytes as u64,
                });
                self.meta_blocked = Some(n_free);
                self.meta_no_run = false;
                self.meta_retry = false;
                return false;
            }
            if n_free < cb + reserve {
                // only the hard data reserve is left: user class fails, the meta space itself is not exhausted
                return false;
            }
            let bpp = self.state.tree.geom().bpp as u32;
            let extents = self.reserve_meta_extents(cb as u32, bpp);
            let Some(extents) = extents else {
                // Free blocks exist, but they cannot back a complete cell of whole-page extents (a deallocate in flight
                // may hold the run: no failure).
                if self.trim_miss() || self.defer_growth(n_free) {
                    return false;
                }
                self.capture_meta_growth_failure(MetaGrowthFailureContext {
                    reason: MetaGrowthFailureReason::NoContiguousRun,
                    requested_free_pages: want as u64,
                    free_data_blocks: n_free,
                    reserve_data_blocks: reserve,
                    cell_blocks: cb,
                    pages_per_cell: ppc as u64,
                    image_bytes: image_bytes as u64,
                    image_reserve_bytes: image_reserve_bytes as u64,
                    deferred_image_bytes: deferred as u64,
                    image_needed_bytes: image_needed_bytes as u64,
                    image_limit_bytes: image_limit_bytes as u64,
                });
                self.meta_blocked = Some(n_free);
                self.meta_no_run = true;
                self.meta_retry = false;
                return false;
            };
            // Account for the actual extent map before publishing the reservation. A failed map budget
            // returns every segment; no partially allocated logical cell is visible to a checkpoint.
            let actual_image_needed = image_bytes
                + image_reserve_bytes
                + deferred
                + self.state.tree.meta.added_cell_blob_len(extents.len());
            if actual_image_needed > image_limit_bytes {
                for e in &extents {
                    self.unreserve(e.start, e.pages * bpp);
                }
                self.capture_meta_growth_failure(MetaGrowthFailureContext {
                    reason: MetaGrowthFailureReason::ImageLimit,
                    requested_free_pages: want as u64,
                    free_data_blocks: n_free,
                    reserve_data_blocks: reserve,
                    cell_blocks: cb,
                    pages_per_cell: ppc as u64,
                    image_bytes: image_bytes as u64,
                    image_reserve_bytes: image_reserve_bytes as u64,
                    deferred_image_bytes: deferred as u64,
                    image_needed_bytes: actual_image_needed as u64,
                    image_limit_bytes: image_limit_bytes as u64,
                });
                self.meta_blocked = Some(n_free);
                self.meta_no_run = false;
                self.meta_retry = false;
                return false;
            }
            self.note_meta_chunks(&extents);
            let start = extents[0].start;
            // a running sliced freeze writes the image of its own cell set (adr 0021 am. 40, am. 68): the cell joins the meta
            // space when it ends (no page of it is allocated before: only a freeze allocates meta pages)
            if self.state.tree.fz_active() {
                self.fz_cells.push(extents);
            } else {
                self.state.tree.meta.add_cell_extents(extents);
                self.pending_cells.push(start);
            }
            self.stats.cells_added += 1;
        }
        self.meta_blocked = None;
        self.meta_wait = None;
        self.meta_cure = false;
        true
    }

    /// A growth miss the next checkpoint can cure (adr 0021 S13): the acked frees it releases plus the empty cells it gives
    /// back hold at least one cell's blocks, the shard is not meta-bound already, and this is not the cycle right after
    /// such a wait (`meta_cure`). The shard then waits for that checkpoint (requested now) instead of turning meta-bound:
    /// statfs full for a shortage the checkpoint ends anyway is what an OSD near its failsafe ratio answers by dropping
    /// client ops until a map change (doc/perf/fill-stall-20261102.md). Admission still parks what does not fit (Busy) and
    /// keeps the meta reserve. False = a real failure: the caller captures it and the shard is meta-bound.
    fn defer_growth(&mut self, n_free: u64) -> bool {
        if self.meta_cure
            || self.meta_bound()
            || !self.cfg.auto_ckpt
            || self.free_q_blocks + self.reclaim < self.cell_blocks
        {
            return false;
        }
        self.meta_blocked = Some(n_free);
        self.meta_retry = false;
        self.meta_wait = Some(self.next_lsn - 1);
        // the cure counts on `reclaim`: the meta peak yields
        self.meta_peak = 0;
        self.meta_peak_prev = 0;
        if !self.ckpt_active() {
            self.ck_requested = true;
        }
        self.stats.meta_grow_waits += 1;
        true
    }

    /// Record an actual blocking growth failure: the shard turns meta-bound (no wait pending).
    fn capture_meta_growth_failure(&mut self, context: MetaGrowthFailureContext) {
        self.meta_wait = None;
        self.stats.meta_grow_bound += 1;
        let sequence = self.meta_growth_failure_sequence.saturating_add(1);
        self.meta_growth_failure_sequence = sequence;
        let unix_time_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let alloc = &self.state.alloc;
        self.last_meta_growth_failure = Some(MetaGrowthFailure {
            sequence,
            reason: context.reason,
            unix_time_ns,
            store_poll_time_ns: self.poll_now,
            requested_free_pages: context.requested_free_pages,
            free_meta_pages: self.meta_free() as u64,
            cell_blocks: context.cell_blocks,
            pages_per_cell: context.pages_per_cell,
            free_data_blocks: context.free_data_blocks,
            held_data_blocks: alloc.n_held(),
            reserved_data_blocks: alloc.n_reserved(),
            reserve_data_blocks: context.reserve_data_blocks,
            image_bytes: context.image_bytes,
            image_reserve_bytes: context.image_reserve_bytes,
            deferred_image_bytes: context.deferred_image_bytes,
            image_needed_bytes: context.image_needed_bytes,
            image_limit_bytes: context.image_limit_bytes,
            free_windows: self.free_windows(),
        });
    }

    /// Free meta pages for admission: the meta space's free pages plus those of the cells reserved while a freeze runs
    /// (`fz_cells`; only the next freeze allocates meta pages for what is admitted now).
    fn meta_free(&self) -> usize {
        self.state.tree.meta.free() as usize
            + self.fz_cells.len() * self.state.tree.meta.ppc() as usize
    }

    /// One slice of the sliced checkpoint start (adr 0021 am. 80): fold the chosen delta chains, then write the stale
    /// bitmap chunks into the tree, at most `budget` units; the slice with room for the chunks left (`ckpt_may_start`)
    /// does the meta housekeeping, writes them and begins the freeze (`fzs`). Up to the begin the start changes only the
    /// in-RAM tree, as txns do (no device write, the WAL holds every txn): the shard keeps admitting between slices and
    /// a crash in between loses nothing. Returns the units used.
    fn start_slice(&mut self, now: Nanos, budget: usize) -> usize {
        let t = std::time::Instant::now();
        let n = self.start_slice_inner(now, budget);
        let ns = t.elapsed().as_nanos() as u64;
        if n > 0 || self.fzs.is_some() {
            self.stats.ckpt_start_slices += 1;
        }
        self.stats.ckpt_sync_ns += ns;
        self.stats.ckpt_sync_max_ns = self.stats.ckpt_sync_max_ns.max(ns);
        crate::diag::note(1, ns);
        n
    }

    fn start_slice_inner(&mut self, now: Nanos, budget: usize) -> usize {
        let mut dt = crate::diag::t0();
        let mut n = 0;
        // the delta page bound of this checkpoint counts the meta space growth can still add (adr 0021 am. 66)
        let g = self.meta_growable();
        self.state.tree.set_meta_growable(g);
        // leaf deltas over their cap: fold the oldest chains back into whole pages (may need to load leaves: retry);
        // before the housekeeping, which sizes the meta space for the pages this makes dirty. Folding is optional and
        // admission never counted its pages: fold only what the free pages (and cells a whole window can still give)
        // pay for, so a meta-bound fragmented shard never needs a cell it cannot get (am. 51: the first checkpoint
        // after a replay failed the mount). The budget is taken again per slice: earlier folds and admitted txns
        // dirtied pages since
        while let Some(CkStart::Fold(from, _)) = self.ck_start {
            let max = self.fold_budget().min(budget - n);
            if max == 0 && n < budget {
                self.ck_start = Some(CkStart::Chunks);
                break;
            }
            if max == 0 {
                return n;
            }
            match self.state.delta_gc(from, max) {
                Ok((next, total)) => {
                    n += next - from;
                    self.ck_start = Some(if next < total {
                        CkStart::Fold(next, total)
                    } else {
                        CkStart::Chunks
                    });
                }
                Err(StoreError::Miss) => {
                    self.pump_wants();
                    return n;
                }
                Err(e) => {
                    self.fail(e);
                    return n;
                }
            }
        }
        crate::diag::lap(7, &mut dt);
        // bitmap chunks go into the tree before the freeze (their pages may need loading: retry on the next poll); a
        // slice without room for all of them writes the oldest. Txns dirty chunks between slices (a written one again):
        // the budget of the start's last poll is all that is left (`drive_ckpt`), so the begin comes however fast they do
        let room = budget - n;
        if self.state.dirty_chunks() > room {
            if room > 0 {
                match self.state.flush_chunks_upto(room) {
                    Ok(()) => n += room,
                    Err(StoreError::Miss) => self.pump_wants(),
                    Err(e) => self.fail(e),
                }
            }
            crate::diag::lap(9, &mut dt);
            return n;
        }
        // the begin: at most one per core and `Store::poll` (adr 0021 am. 40)
        if !self.ckpt_may_start(now) {
            return n;
        }
        if self.cell_blocks != 0 {
            match self.meta_housekeeping() {
                Ok(()) => {}
                // a deallocate holds the blocks growth needs: next poll (`ck_requested` stays)
                Err(StoreError::Busy) => return n,
                Err(e) => {
                    self.fail(e);
                    return n;
                }
            }
        }
        crate::diag::lap(8, &mut dt);
        n += self.state.dirty_chunks();
        match self.state.flush_chunks() {
            Ok(()) => crate::diag::lap(9, &mut dt),
            Err(StoreError::Miss) => {
                self.pump_wants();
                return n;
            }
            Err(e) => {
                self.fail(e);
                return n;
            }
        }
        self.ck_requested = false;
        self.ckpt_due = Some(now.saturating_add(self.cfg.ckpt_interval_ns));
        // L = newest sealed record; sealing the open unit makes L a unit boundary (replay restarts there)
        if self
            .pipeline
            .back()
            .is_some_and(|u| u.st == UState::Open && u.ntxn > 0)
        {
            if dt.is_some() {
                crate::diag::note(
                    33,
                    self.pipeline.back().map_or(0, |u| u.payload.len() as u64),
                );
            }
            self.close_open();
        }
        crate::diag::lap(29, &mut dt);
        let lsn = self.next_lsn - 1;
        let used_blocks = self.state.alloc.n_alloc();
        if lsn == self.ckpt_lsn {
            self.stats.idle_ckpts += 1;
        }
        self.bg_dirty = false;
        if let Err(e) = self.state.tree.freeze_begin(lsn) {
            self.fail(e);
            return n;
        }
        crate::diag::lap(10, &mut dt);
        // the next cycle of the meta peak starts at what this checkpoint needs
        self.meta_peak_prev = std::mem::take(&mut self.meta_peak);
        self.note_meta_need(self.state.tree.dirty_pages() + self.ckpt_extra_pages(0));
        self.ck_start = None;
        self.stats.ckpt_begins += 1;
        self.ck_t0 = Some(now);
        self.fzs = Some(FzStart {
            lsn,
            used_blocks,
            idle: lsn == self.ckpt_lsn,
            released: std::mem::take(&mut self.shrunk),
            floor: self.run_floor(),
        });
        n
    }

    /// Sliced freeze (adr 0021 am. 40): process up to `budget` pending pages; once none is left, end the freeze and
    /// queue the checkpoint's writes (`self.ck`). Returns the pages processed.
    fn freeze_slice(&mut self, budget: usize) -> usize {
        let t = std::time::Instant::now();
        let (done, n) = self.state.tree.freeze_step(budget);
        if done {
            self.finish_freeze();
        }
        let ns = t.elapsed().as_nanos() as u64;
        self.stats.ckpt_slices += 1;
        self.stats.ckpt_sync_ns += ns;
        self.stats.ckpt_sync_max_ns = self.stats.ckpt_sync_max_ns.max(ns);
        crate::diag::note(6, ns);
        n
    }

    fn finish_freeze(&mut self) {
        let mut dt = crate::diag::t0();
        let st = self.fzs.take().expect("freeze running");
        let (lsn, used_blocks) = (st.lsn, st.used_blocks);
        let fr = self.state.tree.freeze_end();
        // cells reserved during the freeze: meta space from now on, durable with the next checkpoint
        for extents in std::mem::take(&mut self.fz_cells) {
            let start = extents[0].start;
            self.state.tree.meta.add_cell_extents(extents);
            self.pending_cells.push(start);
        }
        let psz = self.state.tree.psz();
        let bpp = self.state.tree.geom().bpp;
        let cp = fr.arena.chunk_pages() as u32;
        let mut jobs: Vec<WJob> = Vec::new();
        // coalesce address-adjacent pages into single IOs (an arena chunk is one largest device write)
        let mut i = 0;
        while i < fr.pages.len() {
            let (addr, ai) = fr.pages[i];
            let mut n = 1u64;
            while i + (n as usize) < fr.pages.len()
                && !(ai + n as u32).is_multiple_of(cp)
                && fr.pages[i + n as usize].0 == addr + n * bpp
                && fr.pages[i + n as usize].1 == ai + n as u32
            {
                n += 1;
            }
            jobs.push(WJob {
                blk: addr,
                bitmap: false,
                off: ai as usize,
                len: n as usize * psz,
                dev: false,
            });
            i += n as usize;
        }
        self.stats.ckpt_pages += fr.pages.len() as u64;
        if let Some((_, _, n)) = fr.blob {
            self.stats.ckpt_blob_pages += u64::from(n);
        }
        self.stats.ckpt_max_pages = self.stats.ckpt_max_pages.max(fr.pages.len() as u64);
        // meta bitmap (only if it changed), alternate A/B
        let geom = self.state.tree.geom().clone();
        let bm = if let Some((a, c, k)) = fr.blob {
            // elastic: the image travels with the tree pages (fr.pages); the root slot points at its first page
            Some((a, k, c))
        } else if !fr.pages.is_empty() || !fr.free_after.is_empty() || self.bm_cur.is_none() {
            let blk = match self.bm_cur {
                Some((a, _, _)) if a == geom.bm_a => geom.bm_b,
                _ => geom.bm_a,
            };
            let c = denc::le::rd_u32(&fr.bitmap, 0);
            let total = fr.bitmap.len();
            let step = self.max_xfer_blk * BLK;
            let mut off = 0;
            while off < total {
                let len = step.min(total - off);
                jobs.push(WJob {
                    blk: blk + (off / BLK) as u64,
                    bitmap: true,
                    off,
                    len,
                    dev: false,
                });
                off += len;
            }
            Some((blk, geom.bm_blocks, c))
        } else {
            self.bm_cur
        };
        crate::diag::lap(11, &mut dt);
        if dt.is_some() {
            crate::diag::note(12, fr.pages.len() as u64 * 1000);
        }
        self.ck = Some(CkJob {
            lsn,
            fr,
            jobs,
            next: 0,
            inflight: 0,
            inflight_bytes: 0,
            root_seq: 0,
            root_sent: false,
            n_units: 0,
            bm,
            used_blocks,
            released: st.released,
            idle: st.idle,
            tail: self.tail,
            floor: st.floor,
        });
    }

    /// Sliced checkpoint start (adr 0021 am. 40): a checkpoint begins only in a poll that did no other checkpoint work of
    /// the core (at most one begin per `Store::poll`), held back at most `DEFER_POLLS` polls / `DEFER_NS`.
    fn ckpt_may_start(&mut self, now: Nanos) -> bool {
        let slice = self.cfg.ckpt_slice;
        if slice == 0 {
            return true;
        }
        let (since, polls) = *self.ck_defer.get_or_insert((now, 0));
        if self.ck_left >= slice || polls >= DEFER_POLLS || now.saturating_sub(since) >= DEFER_NS {
            self.ck_defer = None;
            return true;
        }
        self.ck_defer = Some((since, polls + 1));
        self.stats.ckpt_deferred += 1;
        false
    }

    /// Checkpoint budget for the next `poll` (adr 0021 am. 40): what the shards of this core polled before it left of the
    /// core's `ckpt_slice` (`Store::poll`). Without it every `poll` has the whole slice.
    pub fn set_ckpt_gate(&mut self, left: usize) {
        self.ck_gate = Some(left);
    }

    pub fn park_lookahead(&self) -> usize {
        self.cfg.park_lookahead
    }

    pub fn ckpt_slice(&self) -> usize {
        self.cfg.ckpt_slice
    }

    /// Checkpoint budget left by the last `poll` (for the next shard of the core).
    pub fn ckpt_gate_left(&self) -> usize {
        self.ck_left
    }

    /// Budget units of the next checkpoint slice (adr 0021 am. 40): what the core has left this poll, at least the `left`
    /// units spread over `polls` polls (rounded up: one unit while any is left; at most 512 but all of them in the last
    /// poll), so a backlog ends within that many polls even when the core's budget went to other shards. `ckpt_fz_polls`
    /// 0: the core's budget only; kill switch `ckpt_slice` 0: all.
    fn ckpt_budget(&self, left: usize, polls: usize) -> usize {
        if self.cfg.ckpt_slice == 0 {
            return usize::MAX;
        }
        match (self.cfg.ckpt_fz_polls, polls) {
            (0, _) => self.ck_left,
            (_, 0 | 1) => left,
            (_, p) => self.ck_left.max(left.div_ceil(p).min(512)),
        }
    }

    fn use_ckpt_budget(&mut self, n: usize) {
        if self.cfg.ckpt_slice != 0 {
            self.ck_left -= n.min(self.ck_left);
        }
    }

    fn drive_ckpt(&mut self, now: Nanos) {
        if self.ck.is_none() {
            if self.fzs.is_none() {
                if self.ck_start.is_none() {
                    let Some(why) = self.ckpt_why(now) else {
                        self.ck_defer = None;
                        return;
                    };
                    self.stats.ckpt_why[why] += 1;
                    self.ck_start = Some(CkStart::Fold(0, 0));
                    self.ck_start_polls = 0;
                }
                // the start in slices of the core's budget (kill switch 0: all at once), its units spread over the polls
                // left of a fixed window of `ckpt_fz_polls`: txns dirty bitmap chunks between slices (a written one
                // again) and a window that moved with each poll would let the slices trail them until the dirty hard
                // limit stops admission; the fixed one ends the start within it however fast they do (its last poll
                // writes the rest). The begin is a unit too, so every poll of a start moves it
                let left = match self.ck_start {
                    Some(CkStart::Fold(from, total)) => total - from,
                    _ => 0,
                } + self.state.dirty_chunks()
                    + 1;
                let polls = self.cfg.ckpt_fz_polls.saturating_sub(self.ck_start_polls);
                self.ck_start_polls += 1;
                let budget = self.ckpt_budget(left, polls);
                let n = self.start_slice(now, budget);
                self.use_ckpt_budget(n);
                if self.fzs.is_none() {
                    return; // more slices, pages loading, begin held back or failed
                }
                if self.cfg.ckpt_slice != 0 {
                    // the begin used up the poll (the housekeeping, the open unit's seal and the freeze's page list)
                    self.ck_left = 0;
                    return;
                }
            }
            // the freeze in slices of the core's budget (kill switch 0: all at once)
            let budget = self.ckpt_budget(self.state.tree.fz_left(), self.cfg.ckpt_fz_polls);
            if budget == 0 {
                return;
            }
            let n = self.freeze_slice(budget);
            // a slice that ended the freeze used up the poll (the end writes the delta pages and the image)
            if self.ck.is_some() {
                self.ck_left = 0;
            } else {
                self.use_ckpt_budget(n);
            }
        }
        let Some(mut job) = self.ck.take() else {
            return;
        };
        let wal_reserve = self.data_floor();
        let psz = self.state.tree.psz();
        // in flight: one largest device write of checkpoint bytes (at least one write); background checkpoints share
        // that budget per device, whichever shard (adr 0021 am. 76): a WAL write of any shard queues behind at
        // most one bulk write, never behind the shards' whole checkpoints. A checkpoint a caller waits on is that
        // caller's foreground and keeps a budget of its own: it never waits for another shard's poll (a blocking wait
        // pumps its own shard only)
        let cap = (self.max_xfer_blk * BLK) as u64;
        while job.next < job.jobs.len() && self.dev.queue_space() > wal_reserve {
            let len = job.jobs[job.next].len as u64;
            let dev = !self.ck_fg;
            // store metadata IO of the DMA budget (adr 0175 am. 4): refused = the job waits for the next poll
            let Some(mut b) = self.dev.try_alloc_io_uninit(len as usize) else {
                break;
            };
            if !(if dev {
                self.dev_idle.ck_take(self.dir.shard as usize, len, cap)
            } else {
                job.inflight == 0 || job.inflight_bytes + len <= cap
            }) {
                break;
            }
            let j = &mut job.jobs[job.next];
            j.dev = dev;
            let src = if j.bitmap {
                &job.fr.bitmap[j.off..j.off + j.len]
            } else {
                job.fr.arena.slice(j.off, j.len / psz)
            };
            b.copy_from_slice(src);
            if self
                .dev
                .submit_write(j.blk * self.lpb, b, K_CKPT | job.next as u64)
                .is_err()
            {
                self.fail(StoreError::Io(IoError::Aborted));
                return;
            }
            job.next += 1;
            job.inflight += 1;
            job.inflight_bytes += len;
        }
        if job.next == job.jobs.len()
            && job.inflight == 0
            && !job.root_sent
            && self.durable_lsn >= job.lsn
            && self.dev.queue_space() > 0
        {
            self.send_root(&mut job);
        }
        self.ck = Some(job);
    }

    /// Final step: the A/B root slot referencing the new tree, meta bitmap, and WAL tail. No DMA buffer within the budget
    /// now: not sent, the next poll's [`Shard::drive_ckpt`] tries again.
    fn send_root(&mut self, job: &mut CkJob) {
        let Some(mut b) = self.dev.try_alloc_io_uninit(BLK) else {
            return;
        };
        let l = job.lsn;
        let (mut k, mut tail_pos, mut tail_crc, mut tail_lsn);
        if job.idle {
            // nothing was logged since the last checkpoint: no ring unit to release, same tail (and the same run floor)
            (k, (tail_pos, tail_crc, tail_lsn)) = (0, self.tail);
        } else {
            if !self
                .ring
                .iter()
                .any(|u| u.last_lsn == l && u.last_lsn >= u.first_lsn)
            {
                self.fail(StoreError::Corrupt(format!(
                    "checkpoint lsn {l} is not a ring unit boundary"
                )));
                return;
            }
            // release the units wholly below min(l + 1, floor): the run floor keeps the records of live runs for replay
            // (adr 0476)
            let b = l.min(job.floor - 1);
            let idx = self
                .ring
                .iter()
                .rposition(|u| u.last_lsn <= b && u.last_lsn >= u.first_lsn && !u.part);
            match idx {
                None => (k, (tail_pos, tail_crc, tail_lsn)) = (0, self.tail),
                Some(idx) => {
                    k = idx + 1;
                    let end = self.ring[idx].last_lsn;
                    tail_crc = self.ring[k - 1].crc;
                    tail_pos = self.ring.get(k).map_or(self.head_pos, |u| u.pos);
                    tail_lsn = self.ring.get(k).map_or(end + 1, |u| u.first_lsn);
                }
            }
        }
        // PADs at the released end belong to the released prefix (they hold no record). One can be written after the
        // checkpoint that released the unit before it: it then leads the ring, and a floor unit behind it kept it there
        // for good (ring held: client txns and merges refused `WalFull`, nothing logged, no checkpoint; adr 0021 am. 66)
        while self.ring.get(k).is_some_and(Self::is_pad) {
            k += 1;
            tail_crc = self.ring[k - 1].crc;
            tail_pos = self.ring.get(k).map_or(self.head_pos, |u| u.pos);
            tail_lsn = self
                .ring
                .get(k)
                .map_or(self.ring[k - 1].first_lsn, |u| u.first_lsn);
        }
        job.tail = (tail_pos, tail_crc, tail_lsn);
        let seq = self.root_seq + 1;
        let (ra, rc, rh) = job
            .fr
            .root
            .map_or((0, 0, 0), |(a, c)| (a, c, job.fr.height));
        let (ba, bl, bc) = job.bm.unwrap_or((0, 0, 0));
        let slot = RootSlot {
            shard: self.shard,
            seq,
            epoch: self.epoch,
            ckpt_lsn: l,
            wal_tail_pos: tail_pos,
            wal_tail_prev_crc: tail_crc,
            wal_tail_lsn: tail_lsn,
            run_floor: job.floor,
            tree_root: ra,
            tree_crc: rc,
            tree_height: rh,
            meta_bitmap_addr: ba,
            meta_bitmap_len: bl,
            meta_bitmap_crc: bc,
            next_onode_id: self.next_onode_id,
            used_blocks: job.used_blocks,
            meta_pages_used: job.fr.meta_used as u64,
        };
        b.copy_from_slice(&slot.encode());
        let blk = if seq & 1 == 0 {
            self.dir.root_a
        } else {
            self.dir.root_b
        };
        if self
            .dev
            .submit_write(blk * self.lpb, b, K_ROOT | seq)
            .is_err()
        {
            self.fail(StoreError::Io(IoError::Aborted));
            return;
        }
        job.root_seq = seq;
        job.n_units = k;
        job.root_sent = true;
    }

    fn finish_ckpt(&mut self, now: Nanos, out: &mut Vec<Event<D::Buf>>) {
        let Some(mut job) = self.ck.take() else {
            return;
        };
        // a waiter that asked for one more checkpoint waits on that one too
        self.ck_fg &= self.ck_requested;
        self.state
            .tree
            .arena_return(std::mem::take(&mut job.fr.arena), self.cfg.dirty_soft_pages);
        if let Some(t0) = self.ck_t0.take() {
            let ns = now.saturating_sub(t0);
            self.stats.ckpt_ns += ns;
            self.stats.ckpt_max_ns = self.stats.ckpt_max_ns.max(ns);
        }
        for _ in 0..job.n_units {
            let u = self.ring.pop_front().unwrap();
            self.ring_used -= u.blocks;
        }
        self.root_seq = job.root_seq;
        self.ckpt_lsn = job.lsn;
        self.mg_full = false;
        self.rl_wait = false;
        self.tail = job.tail;
        self.bm_cur = job.bm;
        self.state.tree.ckpt_complete(&job.fr.free_after);
        self.meta_retry = true;
        self.reclaim = self.reclaim_blocks();
        // meta cells given back by this checkpoint are plain data space again (their pages are no longer
        // referenced by the durable root)
        for &(start, blocks) in &job.released {
            self.release_held(start, blocks);
        }
        // frees passed by this checkpoint: usable once no reader of this or an older epoch remains
        while self.free_q.front().is_some_and(|(l, _)| *l <= job.lsn) {
            let (_, fr) = self.free_q.pop_front().unwrap();
            self.free_q_blocks -= fr.iter().map(|f| u64::from(f.1)).sum::<u64>();
            self.limbo.push_back((self.read_epoch, fr));
        }
        self.read_epoch += 1;
        self.drain_limbo();
        // fragmentation block (am. 51): once a cell-sized whole window exists again (a cell sweep emptied one and this
        // checkpoint released its moved blocks; judged after the releases above), meta is growable again; admission and
        // statfs stop treating the shard as meta-bound. A failing retry blocks it again.
        if self.meta_no_run
            && self.meta_bound()
            && self.free_windows() * crate::alloc::WIN >= self.cell_blocks
        {
            self.meta_blocked = None;
            self.meta_no_run = false;
        }
        // a growth wait (adr 0021 S13) ends with the checkpoint that released its frees: the next request searches again,
        // a miss in this cycle is a real failure; a wait on frees logged after this checkpoint's lsn asks for the next one
        self.meta_cure = false;
        if let Some(l) = self.meta_wait {
            if job.lsn >= l {
                self.meta_wait = None;
                self.meta_blocked = None;
                self.meta_cure = true;
            } else {
                self.ck_requested = true;
            }
        }
        self.stats.checkpoints += 1;
        out.push(Event::Released { ckpt_lsn: job.lsn });
    }

    // ---------------------------------------------------------------- poll

    /// Nothing queued, in flight, loading or checkpointing: a `poll` would do nothing (time-driven checkpoints
    /// are the caller's periodic sweep).
    pub fn quiet(&mut self) -> bool {
        #[cfg(feature = "rocksdb")]
        if self.rocks_busy() {
            return false;
        }
        // pool requests are made for active shards only: an idle shard with a deferred move's want keeps asking
        #[cfg(feature = "elastic")]
        if self.mig_wanting() {
            return false;
        }
        // Foreign requests have no native device SQEs. Keep polling their completions and
        // frozen/publication work. A merely buffered batch waits for its age on the sweep,
        // like other time-driven work; it does not busy-spin through its batching interval.
        #[cfg(feature = "splinterdb")]
        if self.splinter_needs_poll() {
            return false;
        }
        self.pipeline.is_empty()
            && !self.ckpt_active()
            && !self.ck_requested
            && self.ck_defer.is_none()
            && self.ck_start.is_none()
            && !self.wake
            && self.failed.is_none()
            && self.deferred.is_empty()
            && self.dev.queue_space() == self.dev.queue_depth()
            && !self.state.tree.has_wants()
            && self.state.tree.dead_len() == 0
            && !self.bg_ready()
            && self.cps.is_empty()
            && !self.state.runs.has_cand()
            && !self.merge_runnable()
    }

    /// A merge slice can go at the next poll: due ([`Shard::merge_due`]) and not held by the meta space. Keeps
    /// the shard active ([`Shard::quiet`]): a merge waits only for its pace (the writes wake it), never for the core's
    /// next wake-up (a paced merge whose last client ack emptied the pipeline went idle until the idle marks).
    fn merge_runnable(&self) -> bool {
        !self.mg_full && self.merge_due()
    }

    /// Room for one background compaction step (adr 0021 am. 33): it dirties at most a leaf path (+ the merged pair) that
    /// no txn admitted, so it runs only while the dirty pages stay under half the soft limit and the meta space still
    /// holds them on top of everything a checkpoint needs plus the user reserve (a freeze never runs out of pages).
    fn bg_room(&self) -> bool {
        let t = &self.state.tree;
        let step = 2 * (t.height() as usize + 1);
        t.dirty_pages() + step <= self.cfg.dirty_soft_pages / 2
            && (t.meta.free() as usize)
                >= t.freeze_need()
                    + step
                    + self.meta_reserve as usize
                    + self.state.chunk_reserve(self.state.touched_chunk_count())
    }

    /// Background work is queued and may run now (not waiting for its reads).
    fn bg_ready(&self) -> bool {
        self.cfg.bg_compact
            && self.state.tree.compact_pending() > 0
            && self.bg_miss_loads.is_none_or(|l| {
                self.state.tree.stats.loads > l || self.page_reads.iter().all(Option::is_none)
            })
            && self.bg_room()
    }

    /// Background compaction of sparse leaves (adr 0021 am. 33). Call between txns only (`Store::poll`, never from inside
    /// a staged op). Paced: up to `BG_STEPS` steps per call while nothing is queued or in flight and the device is quiet
    /// (`dev_quiet`), one step per `BG_BUSY_GAP_NS` under client IO; reads its pages without blocking (a step that misses
    /// waits for a load).
    pub fn background(&mut self, now: Nanos) {
        if self.failed.is_some() {
            return;
        }
        if self.bg_dirty
            && !self.ckpt_active()
            && self.state.tree.compact_pending() > 0
            && !self.bg_room()
        {
            // the merges' own dirty pages used up the budget: persist them, the steps continue after that checkpoint
            self.ck_requested = true;
        }
        if !self.bg_ready() {
            return;
        }
        let busy = !self.pipeline.is_empty() || !self.deferred.is_empty() || !self.dev_quiet(now);
        if busy && now < self.bg_next_ns {
            return;
        }
        self.bg_next_ns = now + BG_BUSY_GAP_NS;
        self.bg_miss_loads = None;
        // the first `BG_PROBE` candidates are worked in turn: one that misses keeps its place and the next is tried, so
        // their page reads overlap
        let (steps, probe) = if busy { (1, 1) } else { (BG_STEPS, BG_PROBE) };
        let (mut i, mut done, mut missed) = (0, 0, false);
        while done < steps && i < probe.min(self.state.tree.compact_pending()) {
            if !self.bg_room() {
                break;
            }
            match self.state.tree.compact_step(i) {
                Ok(m) => {
                    self.bg_dirty |= m;
                    done += 1;
                }
                Err(StoreError::Miss) => {
                    missed = true;
                    i += 1;
                }
                Err(_) => done += 1, // candidate dropped (unreadable page: the op that needs it reports it)
            }
        }
        if missed {
            self.pump_wants();
            if done == 0 {
                self.bg_miss_loads = Some(self.state.tree.stats.loads);
            }
        }
    }

    /// Busy/idle edge of the device queue (adr 0474): opens a busy period when commands are in flight, closes it into
    /// `stats.dev_busy_ns` when none are. Reads the clock only on an edge.
    fn dev_note(&mut self) {
        let busy = self.dev.queue_space() < self.dev.queue_depth();
        match (self.dev_busy_since, busy) {
            (None, true) => {
                self.dev_busy_since = Some(self.dev_ns());
                self.dev_idle.edge(self.dir.shard as usize, true);
            }
            (Some(t), false) => {
                self.stats.dev_busy_ns += self.dev_ns().saturating_sub(t);
                self.dev_busy_since = None;
                self.dev_idle.edge(self.dir.shard as usize, false);
            }
            _ => {}
        }
    }

    /// Device idle signal (adr 0533): no other shard of the device has a command in flight or had one
    /// within `BG_BUSY_GAP_NS` (the pacing period of background work under client IO). Background work treats a busy
    /// device like client IO of its own shard: one step per gap instead of a burst.
    pub fn dev_quiet(&mut self, now: Nanos) -> bool {
        self.dev_view
            .quiet(&self.dev_idle, self.dir.shard as usize, now, BG_BUSY_GAP_NS)
    }

    /// Device idle signal gauges of this shard: slots of its table, edges it published, other shards' edges it noticed.
    pub fn dev_idle_gauges(&self) -> (u64, u64, u64) {
        let me = self.dir.shard as usize;
        (
            self.dev_idle.len() as u64,
            self.dev_idle.edges(me),
            self.dev_view.changes,
        )
    }

    /// One exchange of the tree page budget with the device's other shards ([`crate::pagepool`], adr 0062 am. 3): the
    /// store sweep, between operations. No-op for a shard that keeps its own budget.
    pub fn page_exchange(&mut self, now: Nanos) {
        if let Some(p) = &mut self.pages {
            p.exchange(now, &mut self.state.tree);
        }
    }

    /// Tree page budget of this shard (its cap) and its exchange counters (zero when it keeps its own budget).
    pub fn page_gauges(&self) -> (u64, crate::pagepool::ShareStats) {
        (
            self.state.tree.cap() as u64,
            self.pages
                .as_ref()
                .map_or_else(Default::default, |p| p.stats),
        )
    }

    /// Device admission window (adr 0643-device-admission-fifo): the device's window and ticketed bytes not completed
    /// (all shards), and this shard's counters.
    pub fn admit_gauges(&self) -> (u64, u64, crate::admit::AdmitStats) {
        let a = &self.dev_idle.admit;
        (a.window(), a.outstanding(), self.adm.stats)
    }

    /// Commit-latency probe of an acked unit (`ShardStats::cm_*`); merge units and units without a stamp are skipped.
    fn note_commit(&mut self, u: &Unit, t_ack: u64) {
        if u.t_open == 0 || u.t_wal == 0 {
            return;
        }
        let b = |ns: u64| ((64 - (ns / 1000).leading_zeros()) as usize).min(19);
        let done = u.t_wal.max(u.t_data);
        let lat = done.saturating_sub(u.t_open);
        let st = &mut self.stats;
        st.cm_units += 1;
        st.cm_open_ns += u.t_seal.saturating_sub(u.t_open);
        st.cm_queue_ns += u.t_sub.saturating_sub(u.t_seal);
        st.cm_dev_ns += u.t_wal.saturating_sub(u.t_sub);
        st.cm_post_ns += t_ack.saturating_sub(done);
        if u.ck_dev {
            st.cm_ck_units += 1;
            st.cm_ck_dev_ns += u.t_wal.saturating_sub(u.t_sub);
        }
        st.cm_ahead += u64::from(u.ahead);
        st.cm_lat[b(lat)] += 1;
        st.cm_wal[b(u.t_wal.saturating_sub(u.t_open))] += 1;
        if u.t_data != 0 {
            st.cm_data[b(u.t_data.saturating_sub(u.t_open))] += 1;
        }
        if lat >= 5_000_000 {
            st.cm_slow += 1;
            st.cm_slow_ahead += u64::from(u.ahead);
            st.cm_slow_ckpt += u64::from(u.ckpt);
            st.cm_slow_backlog += u64::from(u.backlog);
            st.cm_slow_walfirst += u64::from(u.t_data > u.t_wal);
        }
    }

    fn dev_ns(&self) -> u64 {
        let ns = self.dev_clk.elapsed().as_nanos() as u64;
        #[cfg(feature = "lab")]
        let ns = ns
            + self
                .lab_dev_skew_ns
                .fetch_add(self.lab_dev_tick_ns, std::sync::atomic::Ordering::Relaxed)
            + self.lab_dev_tick_ns;
        ns
    }

    /// LAB: from now on the wall clock of the background-work account loses `ns` between any two reads, as when the
    /// core is descheduled under load. Core-time measurements (the merge slice cost) must not see it.
    #[cfg(feature = "lab")]
    pub fn lab_stall_dev_clock(&mut self, ns: u64) {
        self.lab_dev_tick_ns = ns;
    }

    /// LAB: from now on a merge slice costs `ps` picoseconds per entry (0: the measured core time). The slice size
    /// follows the learned cost ([`Shard::merge_time_cap`]), so a test that depends on the pace must not depend on how
    /// fast the host runs the debug build (SMT siblings and cache contention under a loaded runner multiply it).
    #[cfg(feature = "lab")]
    pub fn lab_fix_merge_cost(&mut self, ps: u64) {
        self.lab_merge_ps = ps;
    }

    /// Clock of the background-work account (`dev_clk`): the object layer times its own background steps with it.
    pub fn bg_now(&self) -> u64 {
        self.dev_ns()
    }

    /// Background work that ran since `t0` (a [`Shard::bg_now`] value).
    pub fn bg_since(&mut self, t0: u64) {
        self.bg_ns += self.dev_ns().saturating_sub(t0);
    }

    /// Background work ns since the last call (merges, run compactions, checkpoints, tree compaction, and what the
    /// object layer added with [`Shard::bg_since`]).
    pub fn take_bg_ns(&mut self) -> u64 {
        std::mem::take(&mut self.bg_ns)
    }

    /// The device queue has commands in flight (adr 0474 busy period open).
    pub fn queue_busy(&self) -> bool {
        self.dev_busy_since.is_some()
    }

    /// `stats.dev_busy_ns` plus the busy period still open (a saturated queue may never drain).
    pub fn dev_busy_ns(&self) -> u64 {
        let open = self
            .dev_busy_since
            .map_or(0, |t| self.dev_ns().saturating_sub(t));
        self.stats.dev_busy_ns + open
    }

    /// Drive the shard: reap device completions, group-commit the open unit, ack in order, run the checkpoint
    /// state machine, service page loads.
    pub fn poll(&mut self, now: Nanos, out: &mut Vec<Event<D::Buf>>) {
        self.poll_now = now;
        self.state.alloc.maintain();
        self.ck_left = self.ck_gate.take().unwrap_or(self.cfg.ckpt_slice);
        if self.failed.is_some() {
            if !self.failed_reported {
                self.failed_reported = true;
                out.push(Event::Failed(self.failed.clone().unwrap()));
            }
            return;
        }
        // the interval clock runs only with something to persist: the first record after a pause is not itself due (else
        // every shard of every OSD that took the first writes of a load starts a checkpoint in that poll, then all again
        // every interval: one device- and cluster-wide burst, adr 0021 am. 75)
        if self.ckpt_due.is_none() || self.ckpt_clean() {
            self.ckpt_due = Some(now.saturating_add(self.ckpt_phase));
        }
        self.idle_mark(now);
        // quiescent shard (nothing queued, in flight or loading, no checkpoint due): nothing to reap or drive; the time
        // for a deallocate (adr 0642)
        if self.pipeline.is_empty()
            && !self.ckpt_active()
            && self.ck_start.is_none()
            && !self.wake
            && self.deferred.is_empty()
            && self.dev.queue_space() == self.dev.queue_depth()
            && !self.state.tree.has_wants()
            && self.state.tree.dead_len() == 0
            && !self.ckpt_wanted(now)
            && !self.merge_due()
            && self.cps.is_empty()
            && !self.state.runs.has_cand()
            && !self.olsm_busy()
            && {
                #[cfg(feature = "splinterdb")]
                {
                    !self.splinter_busy()
                }
                #[cfg(not(feature = "splinterdb"))]
                {
                    true
                }
            }
        {
            self.trim_step(now);
            return;
        }
        let mut dt = crate::diag::t0();
        let mut comps = std::mem::take(&mut self.comps);
        comps.clear();
        // commands submitted since the last note (checkpoint, page loads, staging retries) open a busy period before
        // the reap can close it
        self.dev_note();
        self.dev.poll(now, &mut comps);
        self.dev_note();
        crate::diag::lap(23, &mut dt);
        self.stats.io_completions += comps.len() as u64;
        let t_reap = if comps.is_empty() { 0 } else { self.dev_ns() };
        for c in comps.drain(..) {
            if c.result.is_ok()
                && let Some(b) = &c.buf
            {
                match c.op {
                    crate::dev::Op::Read => self.stats.dev_read_bytes += b.len() as u64,
                    crate::dev::Op::Write => {
                        self.stats.dev_write_bytes += b.len() as u64;
                        if let Some(k) = self.stats.dev_write_kind.get_mut((c.tag >> 56) as usize) {
                            *k += b.len() as u64;
                        }
                    }
                    _ => {}
                }
            }
            let kind = c.tag & K_MASK;
            let id = c.tag & !K_MASK;
            if kind == K_TRIM {
                self.trim_done(c.result, now);
                continue;
            }
            if let Err(e) = c.result {
                match kind {
                    K_READ => {
                        if id & PF_TOKEN == 0
                            && let Some(ep) = self.reads.remove(&id)
                        {
                            self.read_unpin(ep);
                        }
                        out.push(Event::Read {
                            token: id,
                            result: Err(e),
                        });
                    }
                    K_PAGE => {
                        if let Some(w) = self.page_reads.get_mut(id as usize).and_then(Option::take)
                        {
                            if std::mem::take(&mut self.page_stale[id as usize]) {
                                self.wake = true; // freed while in flight: its waiters descend again
                            } else if w.dead {
                                self.state.tree.dead_failed(w.addr);
                            } else {
                                self.state.tree.mark_bad(w.addr, StoreError::Io(e));
                                self.wake = true;
                            }
                        }
                    }
                    _ => self.fail(StoreError::Io(e)),
                }
                continue;
            }
            let mut ct = crate::diag::t0();
            match kind {
                K_DATA => {
                    if let Some(u) = self.unit_mut(id & !ADM_TAGS) {
                        u.pending_data -= 1;
                        u.t_data = t_reap;
                    }
                    self.adm
                        .completed(c.buf.as_ref().map_or(0, |b| b.len() as u64), id & ADM_TAGS);
                }
                K_PRE => {
                    self.adm
                        .completed(c.buf.as_ref().map_or(0, |b| b.len() as u64), id & ADM_TAGS);
                    match self.pre.landed((id & !ADM_TAGS) as usize) {
                        crate::pre::Landed::Keep => {}
                        crate::pre::Landed::Unreserve(b, n) => self.unreserve(b, n),
                        crate::pre::Landed::Unit { seq, rest } => {
                            if let Some(u) = self.unit_mut(seq) {
                                u.pending_data -= 1;
                            }
                            if rest.1 > 0 {
                                self.unreserve(rest.0, rest.1);
                            }
                        }
                    }
                }
                K_WAL => {
                    if let Some(u) = self.unit_mut(id) {
                        u.wal_done = true;
                        u.t_wal = t_reap;
                    }
                    self.inflight_units -= 1;
                }
                K_PAD => {
                    if let Some(u) = self.unit_mut(id) {
                        u.pad_pending = false;
                    }
                }
                K_ROOT => self.finish_ckpt(now, out),
                K_CKPT => {
                    let t_bg = self.dev_ns();
                    if let Some(job) = self.ck.as_mut() {
                        job.inflight -= 1;
                        let j = &job.jobs[id as usize];
                        job.inflight_bytes -= j.len as u64;
                        if j.dev {
                            self.dev_idle.ck_give(self.dir.shard as usize, j.len as u64);
                        }
                        if !j.bitmap {
                            let bpp = self.state.tree.geom().bpp;
                            let n = (j.len / self.state.tree.psz()) as u64;
                            for k in 0..n {
                                self.state.tree.page_written(j.blk + k * bpp);
                            }
                        }
                        crate::diag::lap(25, &mut ct);
                    }
                    self.bg_since(t_bg);
                }
                K_PAGE => {
                    if let Some(w) = self.page_reads.get_mut(id as usize).and_then(Option::take) {
                        if std::mem::take(&mut self.page_stale[id as usize]) {
                            self.wake = true; // freed while in flight: never cached, its waiters descend again
                            continue;
                        }
                        let r = self
                            .state
                            .tree
                            .install(&w, c.buf.as_ref().unwrap().as_slice());
                        crate::diag::lap(if w.dead { 26 } else { 24 }, &mut ct);
                        if w.dead {
                            // lazy free: nobody waits for it; a damaged detached page leaks its subtree
                            if r.is_err() {
                                self.state.tree.dead_failed(w.addr);
                            }
                        } else {
                            if let Err(e) = r {
                                self.state.tree.mark_bad(w.addr, e);
                            }
                            out.push(Event::Page(w.addr));
                        }
                    }
                }
                K_READ => {
                    if id & PF_TOKEN == 0
                        && let Some(ep) = self.reads.remove(&id)
                    {
                        self.read_unpin(ep);
                    }
                    out.push(Event::Read {
                        token: id,
                        result: Ok(c.buf.unwrap()),
                    });
                }
                K_OLSM => self.olsm_write_done(id),
                K_OREAD => self.olsm_read_done(id, c.buf.unwrap()),
                _ => unreachable!("unknown tag"),
            }
        }
        crate::diag::lap(18, &mut dt);
        self.comps = comps;
        // the window bytes that completed count for the device; a landed probe moves the window
        self.adm
            .reaped(&self.dev_idle.admit, self.dir.shard as usize);
        // data waiting for queue room or the window: next wave into the slots the completions freed, as far as the window
        // moved (here or on other shards of the device)
        self.drain_backlog();
        // drain steps (installs of detached pages) free pages by address too
        self.reap_gone();
        if self.failed.is_some() {
            if !self.failed_reported {
                self.failed_reported = true;
                out.push(Event::Failed(self.failed.clone().unwrap()));
            }
            return;
        }
        self.group_commit();
        // run maintenance after the client txns of this poll are on their way to the device (their WAL write overlaps it);
        // a merge txn joins the next unit
        let mut rt = crate::diag::t0();
        let t_bg = self.dev_ns();
        self.compact_step();
        crate::diag::lap(27, &mut rt);
        self.merge_step();
        self.olsm_step();
        crate::diag::lap(28, &mut rt);
        self.bg_since(t_bg);
        // in-order ack
        let mut t_ack = 0;
        while let Some(u) = self.pipeline.front() {
            if u.st != UState::InFlight || !u.wal_done || u.pad_pending || u.pending_data != 0 {
                break;
            }
            let u = self.pipeline.pop_front().unwrap();
            if t_ack == 0 {
                t_ack = self.dev_ns();
            }
            self.note_commit(&u, t_ack);
            let mut tokens = u.tokens;
            for t in tokens.drain(..) {
                if t != MERGE_TOKEN {
                    self.fg_inflight -= 1;
                    out.push(Event::Acked(t));
                }
            }
            if self.pool_tokens.len() < 8 {
                self.pool_tokens.push(tokens);
            }
            self.durable_lsn = u.first_lsn + u.ntxn as u64 - 1;
            if !u.frees.is_empty() {
                self.free_q_blocks += u.frees.iter().map(|f| u64::from(f.1)).sum::<u64>();
                self.free_q.push_back((self.durable_lsn, u.frees));
            }
        }
        if self.failed.is_none() {
            crate::diag::lap(19, &mut dt);
            let t_bg = self.dev_ns();
            self.drive_ckpt(now);
            self.bg_since(t_bg);
            crate::diag::lap(20, &mut dt);
        }
        if self.failed.is_none() {
            self.submit_ready();
            // lazy free: read detached subtree pages in the background (depth first, a few at a time)
            self.state.tree.dead_kick(DEAD_INFLIGHT);
            crate::diag::lap(21, &mut dt);
            if !self.deferred.is_empty() || self.state.tree.has_wants() {
                self.pump_wants();
            }
            // reads in flight all the time (rolling readahead, adr 0021 am. 26; steady cold client reads): the cache must
            // still shrink, so it does once over budget by 1/32 (small bounded overshoot of the memory target; before, none
            // while any read was in flight = unbounded under steady reads); the newest cache/2 loads, the readahead
            // windows among them, stay protected in `shrink`
            let over = self.state.tree.over_mark();
            if over || (self.deferred.is_empty() && self.page_reads.iter().all(Option::is_none)) {
                self.state.tree.shrink();
            }
            crate::diag::lap(22, &mut dt);
        }
        if self.wake {
            self.wake = false;
            out.push(Event::Wake);
        }
        if self.failed.is_some() && !self.failed_reported {
            self.failed_reported = true;
            out.push(Event::Failed(self.failed.clone().unwrap()));
        }
    }
}

#[cfg(test)]
mod helper_rebase_tests {
    use super::*;
    use crate::dev::{SimClock, SimConfig, SimDev, SimDisk};
    use crate::layout::{MkfsParams, mkfs};
    use crate::obj::keys::omap_key;
    use crate::runs::{Compaction, RunBuilder};

    fn meta_failure_shard() -> (Shard<SimDev>, SimDisk) {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (sb, dirs) = mkfs(
            &mut dev,
            &mut clk,
            &MkfsParams {
                shards: 1,
                wal_blocks: 512,
                align_blocks: 1,
                cell_pages: 128,
                ..Default::default()
            },
        )
        .unwrap();
        let (shard, _) =
            Shard::mount(dev, &mut clk, &sb, &dirs[0], ShardCfg::default(), false).unwrap();
        assert_eq!(shard.cell_blocks(), 256); // the diagnostic reports the actual 1 MiB cell
        (shard, disk)
    }

    #[test]
    fn meta_growth_failure_stamp_survives_cached_suppression_and_recovery() {
        let (mut shard, _disk) = meta_failure_shard();
        let cell = shard.cell_blocks;
        let free = shard.state.alloc.n_free();
        assert!(free > cell);
        let reserve_only_want = shard.meta_free() + 1;
        assert!(!shard.grow_meta_inner(reserve_only_want, free));
        assert!(shard.meta_blocked.is_none());
        assert_eq!(shard.last_meta_growth_failure(), None);

        let reserve_count = (free - cell + 1) as u32;
        let reserved_start = shard.state.alloc.reserve(reserve_count).unwrap();
        let want = shard.meta_free() + 1;
        shard.poll_now = 123;

        assert!(!shard.grow_meta_inner(want, 17));
        let first = shard.last_meta_growth_failure().unwrap();
        assert_eq!(first.sequence, 1);
        assert_eq!(
            first.reason,
            MetaGrowthFailureReason::InsufficientFreeBlocks
        );
        assert_eq!(first.store_poll_time_ns, 123);
        assert!(first.unix_time_ns > 0);
        assert_eq!(first.requested_free_pages, want as u64);
        assert_eq!(first.free_data_blocks, cell - 1);
        assert_eq!(first.reserve_data_blocks, 17);
        assert_eq!(first.reserved_data_blocks, u64::from(reserve_count));
        assert_eq!(first.cell_blocks, 256);
        assert_eq!(first.pages_per_cell, 128);

        // A cached refusal does not represent a new failure or replace its timestamp/counters.
        assert!(!shard.grow_meta_inner(want, 17));
        assert_eq!(shard.last_meta_growth_failure(), Some(first));

        shard.state.alloc.unreserve(reserved_start, reserve_count);
        shard.meta_retry = true;
        assert!(shard.grow_meta_inner(want, 0));
        assert!(shard.meta_blocked.is_none());
        assert_eq!(shard.last_meta_growth_failure(), Some(first));

        let free = shard.state.alloc.n_free();
        let reserve_count = (free - cell + 1) as u32;
        shard.state.alloc.reserve(reserve_count).unwrap();
        let want = shard.meta_free() + 1;
        shard.meta_retry = true;
        assert!(!shard.grow_meta_inner(want, 0));
        assert_eq!(shard.last_meta_growth_failure().unwrap().sequence, 2);
    }

    #[test]
    fn disabled_meta_growth_does_not_stamp_a_failure() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (sb, dirs) = mkfs(
            &mut dev,
            &mut clk,
            &MkfsParams {
                shards: 1,
                wal_blocks: 512,
                align_blocks: 1,
                elastic_meta: false,
                ..Default::default()
            },
        )
        .unwrap();
        let (mut shard, _) =
            Shard::mount(dev, &mut clk, &sb, &dirs[0], ShardCfg::default(), false).unwrap();
        assert_eq!(shard.cell_blocks(), 0);
        assert!(!shard.grow_meta_inner(1, 0));
        assert_eq!(shard.last_meta_growth_failure(), None);
        assert!(shard.meta_blocked.is_none());
    }

    #[test]
    fn image_limit_is_reported_before_simultaneous_data_shortage() {
        let (mut shard, _disk) = meta_failure_shard();
        let cell = shard.cell_blocks;
        let free = shard.state.alloc.n_free();
        let reserve_count = (free - cell + 1) as u32;
        shard.state.alloc.reserve(reserve_count).unwrap();
        let ppc = shard.state.tree.meta.ppc() as usize;
        let limit = crate::alloc::blob_max_len(shard.state.tree.psz());
        let per_cell = shard.state.tree.meta.added_cell_blob_len(1);
        shard.fz_cells.resize(
            limit / per_cell + 1,
            vec![MetaExtent {
                start: 1,
                pages: ppc as u32,
            }],
        );
        let want = shard.meta_free() + 1;

        assert!(!shard.grow_meta_inner(want, 0));
        let failure = shard.last_meta_growth_failure().unwrap();
        assert_eq!(failure.reason, MetaGrowthFailureReason::ImageLimit);
        assert!(failure.image_needed_bytes > failure.image_limit_bytes);
        assert!(failure.free_data_blocks < failure.cell_blocks);
    }

    #[test]
    fn fragmented_cell_growth_falls_back_to_smaller_extents() {
        let (mut shard, _disk) = meta_failure_shard();
        let start = shard.dir.data_start;
        let data_blocks = shard.dir.data_blocks;
        for offset in (0..data_blocks).step_by(crate::alloc::WIN as usize) {
            shard.state.alloc.apply_alloc_replay(start + offset, 1);
        }
        let free = shard.state.alloc.n_free();
        assert!(free >= shard.cell_blocks);
        let want = shard.meta_free() + 1;
        assert!(shard.grow_meta_inner(want, 0));
        assert_eq!(shard.last_meta_growth_failure(), None);
        assert!(!shard.meta_growth_blocked());
        let extents = shard.meta_cells();
        assert!(extents.len() > 1);
        assert_eq!(extents.iter().map(|e| e.1).sum::<u64>(), shard.cell_blocks);
        assert!(
            extents
                .iter()
                .all(|e| e.1 < shard.cell_blocks && e.1.is_multiple_of(2))
        );
    }

    #[test]
    fn fragmented_cell_growth_rolls_back_partial_reservation() {
        let (mut shard, _disk) = meta_failure_shard();
        let start = shard.dir.data_start;
        let data_blocks = shard.dir.data_blocks;
        // Keep exactly one whole page and many isolated blocks: enough blocks in total, but not
        // enough whole pages to back a logical cell. The first page must be returned on failure.
        for offset in (2..data_blocks).step_by(2) {
            shard.state.alloc.apply_alloc_replay(start + offset, 1);
        }
        let free = shard.state.alloc.n_free();
        let reserved = shard.state.alloc.n_reserved();
        let want = shard.meta_free() + 1;
        assert!(!shard.grow_meta_inner(want, 0));
        assert_eq!(shard.state.alloc.n_free(), free);
        assert_eq!(shard.state.alloc.n_reserved(), reserved);
        assert!(shard.meta_cells().is_empty());
        assert!(shard.pending_cell_chunks.is_empty());
        assert_eq!(
            shard.last_meta_growth_failure().unwrap().reason,
            MetaGrowthFailureReason::NoContiguousRun
        );
    }

    #[test]
    fn fragmented_cell_image_budget_failure_returns_all_reservations() {
        let (mut shard, _disk) = meta_failure_shard();
        let start = shard.dir.data_start;
        for offset in (0..shard.dir.data_blocks).step_by(16) {
            shard.state.alloc.apply_alloc_replay(start + offset, 1);
        }
        let m = &shard.state.tree.meta;
        let per_cell = m.added_cell_blob_len(1);
        let limit = crate::alloc::blob_max_len(shard.state.tree.psz());
        let available = limit - m.blob_len() - shard.state.tree.ext_reserve() - per_cell;
        shard.fz_cells.resize(
            available / per_cell,
            vec![MetaExtent {
                start: 1,
                pages: 128,
            }],
        );
        let free = shard.state.alloc.n_free();
        let reserved = shard.state.alloc.n_reserved();
        let want = shard.meta_free() + 1;
        assert!(!shard.grow_meta_inner(want, 0));
        assert_eq!(shard.state.alloc.n_free(), free);
        assert_eq!(shard.state.alloc.n_reserved(), reserved);
        assert!(shard.pending_cells.is_empty());
        assert!(shard.pending_cell_chunks.is_empty());
        let failure = shard.last_meta_growth_failure().unwrap();
        assert_eq!(failure.reason, MetaGrowthFailureReason::ImageLimit);
        assert!(failure.image_needed_bytes > failure.image_limit_bytes);
    }

    /// One prepared job per free helper core (adr 0534 am. 1): three credits take three compactions off the owner; a
    /// shrunk credit returns the extra prepared jobs inline; results returned out of order all swap in.
    #[test]
    fn one_helper_job_per_credit_and_out_of_order_returns() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (sb, dirs) = mkfs(
            &mut dev,
            &mut clk,
            &MkfsParams {
                shards: 1,
                wal_blocks: 512,
                align_blocks: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let cfg = ShardCfg {
            cache_pages: 256,
            run_fan: 16, // only the jobs installed below
            run_max: 64,
            run_helpers: true,
            ..Default::default()
        };
        let (mut shard, _) = Shard::mount(dev, &mut clk, &sb, &dirs[0], cfg, false).unwrap();
        for id in 1..=4u64 {
            for lsn in 1..=2 {
                let mut b = RunBuilder::default();
                for i in 0..3000u32 {
                    b.push(
                        &omap_key(id, &(lsn << 16 | i).to_be_bytes()),
                        &[],
                        &[0],
                        b"v",
                    );
                }
                shard
                    .state
                    .runs
                    .insert(id * 2 + lsn as u64, b.finish(id).unwrap());
            }
            shard
                .cps
                .push(shard.state.runs.compaction(id, 2, 64, 0, &[]).unwrap());
        }
        shard.compaction_helpers(true, 3);
        shard.compact_step();
        assert_eq!(shard.compact_ready.len(), 3);
        assert_eq!(shard.compact_remote.len(), 3);
        assert_eq!(shard.cps.len(), 1);
        // a shrunk credit: two prepared jobs go back inline, their reservations with them
        shard.compaction_helpers(true, 1);
        assert_eq!(shard.compact_ready.len(), 1);
        assert_eq!(shard.compact_remote.len(), 1);
        assert_eq!(shard.cps.len(), 3);
        shard.compaction_helpers(true, 3);
        shard.compact_step();
        let mut jobs: Vec<HelperJob> =
            std::iter::from_fn(|| shard.take_compaction(false)).collect();
        assert_eq!(jobs.len(), 3);
        assert_eq!(shard.compact_remote.len(), 3);
        for j in &mut jobs {
            while !j.step(256) {}
        }
        jobs.swap(0, 2);
        for j in jobs {
            assert!(shard.return_compaction(j, true));
        }
        assert!(shard.compact_remote.is_empty() && shard.compact_ready.is_empty());
        assert_eq!(shard.stats.run_helper_done, 3);
        shard.compaction_helpers(true, 0);
        while !shard.cps.is_empty() {
            shard.compact_step();
        }
        assert_eq!(shard.stats.run_compactions, 4);
        assert_eq!(shard.state.runs.n_runs(), 4);
        assert_eq!(shard.run_mem(), shard.state.runs.mem());
        assert_eq!(shard.pool.pool().bytes(), shard.run_mem());
    }

    #[test]
    fn inline_jobs_share_one_budget_with_and_without_remote_dispatch() {
        for dispatch in [false, true] {
            let disk = SimDisk::new(SimConfig::new(64 << 20));
            let mut dev = disk.queue();
            let mut clk = SimClock::default();
            let (sb, dirs) = mkfs(
                &mut dev,
                &mut clk,
                &MkfsParams {
                    shards: 1,
                    wal_blocks: 512,
                    align_blocks: 1,
                    ..Default::default()
                },
            )
            .unwrap();
            let cfg = ShardCfg {
                cache_pages: 256,
                run_fan: 16, // only step the jobs explicitly installed below
                run_max: 64,
                run_helpers: true,
                ..Default::default()
            };
            let (mut shard, _) = Shard::mount(dev, &mut clk, &sb, &dirs[0], cfg, false).unwrap();
            for id in 1..=3 {
                for lsn in 1..=2 {
                    let mut b = RunBuilder::default();
                    for i in 0..6000u32 {
                        b.push(&omap_key(id, &i.to_be_bytes()), &[], &[0], b"v");
                    }
                    shard.state.runs.insert(id * 2 + lsn, b.finish(id).unwrap());
                }
                shard
                    .cps
                    .push(shard.state.runs.compaction(id, 2, 64, 0, &[]).unwrap());
            }
            let before: usize = shard.cps.iter().map(Compaction::left).sum();
            shard.compact_available = usize::from(dispatch);
            shard.compact_step();
            let remote_left: usize = shard
                .compact_ready
                .iter()
                .map(|j| j.compaction.left())
                .sum();
            assert_eq!(shard.compact_ready.len(), usize::from(dispatch));
            let after: usize = shard.cps.iter().map(Compaction::left).sum::<usize>() + remote_left;
            // Each key consumes two overlapping input entries. Main charges consumed input entries,
            // so its shared budget may finish one call early, never grant every job another slice.
            assert_eq!(before - after, 2 * COMPACT_ENTS);
            assert_eq!(shard.cps.iter().filter(|c| !c.is_empty()).count(), 1);
        }
    }

    /// A compaction whose input left is dropped at the next step, inline or prepared for a helper (not stepped to its
    /// end): the run memory falls back to the runs at once (adr 0476 am. 12).
    #[test]
    fn compactions_whose_input_left_are_dropped_at_the_next_step() {
        for dispatch in [false, true] {
            let disk = SimDisk::new(SimConfig::new(64 << 20));
            let mut dev = disk.queue();
            let mut clk = SimClock::default();
            let (sb, dirs) = mkfs(
                &mut dev,
                &mut clk,
                &MkfsParams {
                    shards: 1,
                    wal_blocks: 512,
                    align_blocks: 1,
                    ..Default::default()
                },
            )
            .unwrap();
            let cfg = ShardCfg {
                cache_pages: 256,
                run_fan: 16, // only the job installed below
                run_max: 64,
                run_helpers: true,
                ..Default::default()
            };
            let (mut shard, _) = Shard::mount(dev, &mut clk, &sb, &dirs[0], cfg, false).unwrap();
            let key = |run: u32, i: u32| omap_key(1, &(run << 16 | i).to_be_bytes());
            for run in 1..=2u32 {
                let mut b = RunBuilder::default();
                for i in 0..6000 {
                    b.push(&key(run, i), &[], &[0], b"v");
                }
                shard.state.runs.insert(run as u64, b.finish(1).unwrap());
            }
            shard
                .cps
                .push(shard.state.runs.compaction(1, 2, 64, 0, &[]).unwrap());
            shard.compact_available = usize::from(dispatch);
            shard.compact_step();
            // 12000 input entries: more than two step budgets
            const { assert!(12000 > 2 * COMPACT_ENTS) };
            assert_eq!(shard.compact_ready.len(), usize::from(dispatch));
            assert_eq!(shard.cps.len(), usize::from(!dispatch));
            let with = shard.run_mem();
            assert!(with > shard.state.runs.mem());
            for i in 0..6000 {
                shard.state.runs.kill(&key(1, i));
            }
            assert_eq!(shard.state.runs.n_runs(), 1);
            shard.compact_available = 0;
            shard.compact_step();
            assert!(shard.cps.is_empty());
            assert!(shard.compact_ready.is_empty() && shard.compact_remote.is_empty());
            assert_eq!(shard.stats.run_compact_lost, 1);
            assert_eq!(shard.run_mem(), shard.state.runs.mem());
            assert_eq!(shard.pool.pool().bytes(), shard.run_mem());
        }
    }

    /// The object of a dropped compaction is checked again: its remaining runs compact without a new run arriving.
    #[test]
    fn a_dropped_compactions_runs_are_compacted_again() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (sb, dirs) = mkfs(
            &mut dev,
            &mut clk,
            &MkfsParams {
                shards: 1,
                wal_blocks: 512,
                align_blocks: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let cfg = ShardCfg {
            cache_pages: 256,
            run_fan: 2,
            run_max: 64,
            ..Default::default()
        };
        let (mut shard, _) = Shard::mount(dev, &mut clk, &sb, &dirs[0], cfg, false).unwrap();
        let key = |run: u32, i: u32| omap_key(1, &(run << 16 | i).to_be_bytes());
        for run in 1..=3u32 {
            let mut b = RunBuilder::default();
            for i in 0..6000 {
                b.push(&key(run, i), &[], &[0], b"v");
            }
            shard.state.runs.insert(run as u64, b.finish(1).unwrap());
        }
        // runs 1 and 2 (one tier, oldest first): more input than one step budget
        shard.compact_step();
        assert_eq!(shard.cps.len(), 1);
        const { assert!(12000 > COMPACT_ENTS) };
        for i in 0..6000 {
            shard.state.runs.kill(&key(1, i));
        }
        assert_eq!(shard.state.runs.n_runs(), 2);
        shard.compact_step();
        assert_eq!(shard.stats.run_compact_lost, 1);
        assert_eq!(shard.cps.len(), 1, "runs 2 and 3 compact without a new run");
        assert!(shard.state.runs.holds(&shard.cps[0]));
    }

    #[test]
    fn merge_slices_are_sized_by_the_learned_cost_per_entry() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (sb, dirs) = mkfs(
            &mut dev,
            &mut clk,
            &MkfsParams {
                shards: 1,
                wal_blocks: 512,
                align_blocks: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let (mut shard, _) =
            Shard::mount(dev, &mut clk, &sb, &dirs[0], ShardCfg::default(), false).unwrap();
        assert_eq!(shard.merge_time_cap(), MERGE_ENTS);
        shard.merge_learn(0, 0); // an empty slice teaches nothing
        assert_eq!(shard.merge_time_cap(), MERGE_ENTS);
        // 100 entries in 3 ms = 30 us per entry: a slice of MERGE_SLICE_NS takes 16
        shard.merge_learn(3_000_000, 100);
        assert_eq!(shard.merge_time_cap(), (MERGE_SLICE_NS / 30_000) as usize);
        // slow entries: at least one entry per slice
        for _ in 0..64 {
            shard.merge_learn(10 * MERGE_SLICE_NS, 1);
        }
        assert_eq!(shard.merge_time_cap(), 1);
        // fast entries: never above MERGE_ENTS
        for _ in 0..128 {
            shard.merge_learn(1, 1);
        }
        assert_eq!(shard.merge_time_cap(), MERGE_ENTS);
    }
}

#[cfg(test)]
mod ckpt_phase_tests {
    use super::*;
    use crate::dev::{SimClock, SimConfig, SimDisk};
    use crate::layout::{MkfsParams, mkfs};

    #[test]
    fn phases_spread_the_shards_of_a_device_one_interval_or_more_out() {
        let i = 5_000_000_000;
        let fsid = [7u8; 16];
        let p: Vec<Nanos> = (0..6).map(|s| ckpt_phase(&fsid, s, 6, i)).collect();
        for (s, &x) in p.iter().enumerate() {
            assert!((i..2 * i).contains(&x), "shard {s}: {x}");
            // evenly spread: shard s is s/6 of the interval after shard 0 (mod the interval)
            assert_eq!((x + i - p[0]) % i, s as u64 * (i / 6) % i);
        }
        assert_ne!(
            ckpt_phase(&[8u8; 16], 0, 6, i),
            p[0],
            "another OSD, another offset"
        );
        assert_eq!(
            ckpt_phase(&[0u8; 16], 0, 6, i),
            i,
            "never sooner than one interval"
        );
        assert_eq!(ckpt_phase(&fsid, 3, 6, 0), 0);
        assert_eq!(ckpt_phase(&[0xff; 16], 5, 6, u64::MAX), u64::MAX);
    }

    /// The first record after an idle stretch does not start an interval checkpoint in its own poll (every shard of every
    /// OSD that took the first writes of a load did so in the same instant); it starts one phase (>= one interval) later.
    #[test]
    fn first_record_after_idle_waits_for_the_phase() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let params = MkfsParams {
            shards: 1,
            wal_blocks: 512,
            align_blocks: 1,
            cell_pages: 128,
            ..Default::default()
        };
        let (sb, dirs) = mkfs(&mut dev, &mut clk, &params).unwrap();
        let cfg = ShardCfg {
            ckpt_interval_ns: 1_000_000,
            ..ShardCfg::default()
        };
        let (mut shard, _) = Shard::mount(dev, &mut clk, &sb, &dirs[0], cfg, false).unwrap();
        let phase = shard.ckpt_phase;
        assert!((1_000_000..2_000_000).contains(&phase));
        let mut out = Vec::new();
        let idle_end = 100 * 1_000_000;
        for t in [0, idle_end / 2, idle_end] {
            shard.poll(t, &mut out);
        }
        let why = shard.stats.ckpt_why[5];
        let mut t: Txn<Vec<u8>> = Txn::new(1);
        t.ops.push(Op::Put(b"k".to_vec(), b"v".to_vec()));
        shard.submit(t).map_err(|(e, _)| e).unwrap();
        shard.poll(idle_end, &mut out);
        assert_eq!(
            shard.stats.ckpt_why[5], why,
            "no interval checkpoint in the poll of the first record"
        );
        shard.poll(idle_end + phase - 1, &mut out);
        assert_eq!(shard.stats.ckpt_why[5], why, "nor before the phase passed");
        shard.poll(idle_end + phase, &mut out);
        assert_eq!(
            shard.stats.ckpt_why[5],
            why + 1,
            "the interval checkpoint one phase later"
        );
    }
}

#[cfg(test)]
mod ckpt_device_budget_tests {
    use super::*;
    use crate::dev::SimDev;
    use crate::dev::{Clock, SimClock, SimConfig, SimDisk};
    use crate::layout::{MkfsParams, mkfs};

    fn put(
        s: &mut Shard<SimDev>,
        clk: &mut SimClock,
        out: &mut Vec<Event<Vec<u8>>>,
        tok: &mut u64,
        k: u64,
    ) {
        *tok += 1;
        let mut t: Txn<Vec<u8>> = Txn::new(*tok);
        t.ops.push(Op::Put(
            format!("key/{k:016x}").into_bytes(),
            vec![k as u8; 200],
        ));
        while let Err((_, back)) = s.submit(t) {
            t = back;
            s.poll(clk.t, out);
            let h = s.dev().next_deadline();
            clk.idle(h);
        }
    }

    /// Two mounted shards of one device, background checkpoints by `dirty_soft_pages` only.
    fn two_shards(
        dirty_soft_pages: usize,
    ) -> (
        SimClock,
        Vec<Shard<SimDev>>,
        std::sync::Arc<crate::devidle::DevIdle>,
    ) {
        let disk = SimDisk::new(SimConfig::new(256 << 20));
        let mut clk = SimClock::default();
        let params = MkfsParams {
            shards: 2,
            wal_blocks: 2048,
            align_blocks: 1,
            cell_pages: 128,
            ..Default::default()
        };
        let (sb, dirs) = mkfs(&mut disk.queue(), &mut clk, &params).unwrap();
        let dev_idle = std::sync::Arc::new(crate::devidle::DevIdle::default());
        assert!(dev_idle.init(2));
        let cfg = ShardCfg {
            ckpt_interval_ns: u64::MAX,
            dirty_soft_pages,
            dev_idle: Some(dev_idle.clone()),
            ..ShardCfg::default()
        };
        let sh = dirs
            .iter()
            .map(|d| {
                Shard::mount(disk.queue(), &mut clk, &sb, d, cfg.clone(), false)
                    .unwrap()
                    .0
            })
            .collect();
        (clk, sh, dev_idle)
    }

    /// Two shards of one device start large background checkpoints at the same poll while clients keep writing
    /// (adr 0021 am. 76): the background checkpoint bytes in flight on the device never exceed one largest device
    /// write, the checkpoints run side by side and both finish.
    #[test]
    fn background_checkpoints_of_a_device_share_one_largest_write() {
        let (mut clk, mut sh, dev_idle) = two_shards(ShardCfg::default().dirty_soft_pages);
        let cap = (sh[0].max_xfer_blk * BLK) as u64;
        let (mut out, mut tok) = (Vec::new(), 0u64);
        // dirty pages on both shards, below the trigger: a client put every 2 us
        for k in 0..20_000u64 {
            let i = (k % 2) as usize;
            put(
                &mut sh[i],
                &mut clk,
                &mut out,
                &mut tok,
                k.wrapping_mul(0x9e37_79b9_7f4a_7c15),
            );
            clk.t += 2_000;
            for s in &mut sh {
                s.poll(clk.t, &mut out);
            }
        }
        let base: Vec<u64> = sh.iter().map(|s| s.stats.checkpoints).collect();
        // both cross the dirty trigger at the same poll: two background checkpoints of many writes each
        for s in &mut sh {
            s.cfg.dirty_soft_pages = 64;
        }
        let (mut both, mut most, mut k) = (0u64, 0u64, 1u64 << 40);
        for _ in 0..2_000_000 {
            for s in &mut sh {
                s.poll(clk.t, &mut out);
            }
            let b = dev_idle.ck_bytes();
            assert!(
                b <= cap,
                "{b} background checkpoint bytes in flight, one largest write is {cap}"
            );
            assert!(
                sh.iter().all(|s| !s.ck_fg),
                "nothing waits on these checkpoints"
            );
            most = most.max(b);
            both += u64::from(
                sh.iter()
                    .all(|s| s.ck.as_ref().is_some_and(|j| j.next < j.jobs.len())),
            );
            if sh.iter().zip(&base).all(|(s, b)| s.stats.checkpoints > *b) {
                break;
            }
            // client writes keep coming on shard 1 while the checkpoints run
            k += 1;
            put(&mut sh[1], &mut clk, &mut out, &mut tok, k);
            let h = sh.iter_mut().filter_map(|s| s.dev().next_deadline()).min();
            clk.idle(h);
        }
        assert!(sh.iter().all(|s| s.failed.is_none()));
        assert!(
            sh.iter().zip(&base).all(|(s, b)| s.stats.checkpoints > *b),
            "both checkpoints finished"
        );
        assert!(both > 0, "the checkpoints ran side by side");
        assert!(most > 0);
        for s in &mut sh {
            s.cfg.dirty_soft_pages = ShardCfg::default().dirty_soft_pages;
        }
        for _ in 0..1_000_000 {
            if sh
                .iter()
                .all(|s| s.ck.is_none() && s.fzs.is_none() && s.ck_start.is_none())
            {
                break;
            }
            for s in &mut sh {
                s.poll(clk.t, &mut out);
            }
            let h = sh.iter_mut().filter_map(|s| s.dev().next_deadline()).min();
            clk.idle(h);
        }
        assert_eq!(dev_idle.ck_bytes(), 0, "budget free after the checkpoints");
    }

    /// A checkpoint a caller waits on is foreground (adr 0021 am. 76): while another shard of the device holds the
    /// background budget and is not polled at all (its core is in a blocking wait of its own), a requested checkpoint
    /// of this shard still finishes, by polling this shard alone. The background one already running is taken over.
    #[test]
    fn waited_checkpoint_never_waits_for_another_shards_poll() {
        let (mut clk, mut sh, dev_idle) = two_shards(64);
        let (mut out, mut tok) = (Vec::new(), 0u64);
        let mut k = 0u64;
        while !dev_idle.ck_busy() {
            k += 1;
            assert!(k < 100_000, "no background checkpoint on shard 0");
            put(&mut sh[0], &mut clk, &mut out, &mut tok, k);
            sh[0].poll(clk.t, &mut out);
        }
        // shard 0 is not polled from here on: its share stays taken
        let (s1, rest) = sh.split_at_mut(1);
        let s = &mut rest[0];
        let mut bg = false;
        for j in 0..20_000u64 {
            put(s, &mut clk, &mut out, &mut tok, 1 << 40 | j);
            s.poll(clk.t, &mut out);
            bg |= s.ck.is_some() && !s.ck_fg;
        }
        assert!(
            bg,
            "shard 1 started a background checkpoint behind shard 0's write"
        );
        s.request_checkpoint();
        let target = s.next_lsn - 1;
        let mut done = false;
        for _ in 0..1_000_000 {
            s.poll(clk.t, &mut out);
            if s.ckpt_lsn >= target && s.ck.is_none() {
                done = true;
                break;
            }
            let h = s.dev().next_deadline();
            clk.idle(h);
        }
        assert!(done, "the requested checkpoint waited for shard 0's poll");
        assert!(dev_idle.ck_busy(), "shard 0's write is still unreaped");
        // shard 0 polls again: its checkpoint finishes and gives the budget back
        let s0 = &mut s1[0];
        for _ in 0..1_000_000 {
            if s0.ck.is_none() && s0.fzs.is_none() && s0.ck_start.is_none() {
                break;
            }
            s0.poll(clk.t, &mut out);
            let h = s0.dev().next_deadline();
            clk.idle(h);
        }
        assert!(s0.ck.is_none() && s0.failed.is_none() && s.failed.is_none());
        assert_eq!(dev_idle.ck_bytes(), 0);
    }
}
