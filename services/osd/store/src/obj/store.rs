// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Multi-shard object store: routing, mount, the public txn/read API.

use super::keys::*;
use super::shardio::{
    BUILD_SESSION, CacheDropped, MEDIA_SESSION, STAGE_SESSION, ShardStore, TREE_MISS,
};
pub use super::stage::ScrubResult;
use super::stage::{Built, Saved, Slot, Stage};
use super::txn::{OTxn, TOp};
use super::{KvList, ObjError, Result};
use crate::BLK;
use crate::dev::{BlockDev, Clock, IoBuf};
use crate::error::StoreError;
use crate::layout::{Superblock, read_super};
use crate::shard::{AllocClass, Shard, ShardCfg, ShardMem, Txn};
use crate::space::{self, Ask, Cost};
use crate::wal::ReplayStats;
use bytes::Bytes;
use denc::types::{CollT, Ghobject};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Queued {
    Submitted(u64),
    Pending(u64),
}

/// Largest pre-write piece ([`Store::pre_write`]): one extent run of `MAX_RUN` blocks. The piece of a store is
/// [`Store::pre_piece`] (a device transfer limit below it shortens the runs).
pub const PRE_PIECE: usize = super::onode::MAX_RUN as usize * BLK;

/// A piece written ahead on one of this store's shards ([`Store::pre_write`], adr 0477).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreTicket {
    si: u32,
    id: crate::pre::PreId,
}

impl PreTicket {
    /// Plain form for layers above the store (shard index, slot id).
    pub fn parts(self) -> (u32, u64) {
        (self.si, self.id.raw())
    }
    /// Back from [`parts`](Self::parts); a forged or stale value only misses (slot generations).
    pub fn from_parts(si: u32, id: u64) -> PreTicket {
        PreTicket {
            si,
            id: crate::pre::PreId::from_raw(id),
        }
    }
}

#[derive(Debug)]
pub struct QueueBuildContext {
    si: usize,
    session: Option<(u64, u64)>,
    reads: (bool, bool),
}

/// Retained input for a cold transaction. Only the FIFO head builds against the current committed view.
/// Returning borrowed payloads avoids a second copy of wire data when staging parks.
/// Builders translate within their assigned shard; they must not recursively drain
/// queues or execute blocking transactions. The selected Splinter barrier rejects
/// such a drain before polling followers; native/Rocks execution policy is unchanged.
pub trait QueueBuilder<D: BlockDev, C: Clock> {
    fn build(&mut self, store: &mut Store<D, C>) -> Result<Option<OTxn<'_>>>;
    fn retained_bytes(&self) -> usize;
    /// Immutable owners of borrowed write bytes; collected only for a parked preparation.
    fn payload_owners(&self) -> Vec<bytes::Bytes> {
        Vec::new()
    }
}

struct Prepared<B> {
    txn: Txn<B>,
    ids: Option<Vec<u64>>,
}

struct Preparation<B> {
    token: u64,
    wanted: bool,
    parts: Saved<B>,
}

struct Parked<D: BlockDev, C: Clock> {
    token: u64,
    /// Park order in its shard (`ParkQ::issue`; kept when a txn is put back at the front).
    seq: u64,
    input: Option<OTxn<'static>>,
    ready: Option<Prepared<D::Buf>>,
    builder: Option<Box<dyn QueueBuilder<D, C>>>,
    objects: Vec<(CollT, Vec<u8>)>,
    /// The objects themselves (lookahead, adr 0021 am. 44).
    oids: Vec<(CollT, Ghobject)>,
    colls: Vec<CollT>,
    bytes: usize,
    tried: Option<(u64, u64, u64)>,
    deadline: u64,
    /// Lookahead loads of its names were submitted while it waited behind the head (adr 0021 am. 44).
    warmed: bool,
    /// [`txn_entries`] of its input.
    entries: u64,
    /// Tries as the FIFO head that ended in `WouldBlock`, and where the last one stopped (`phase`, the shard's
    /// `wb_why`): diagnostics (`Store::diag`).
    blocked: (u64, &'static str, &'static str),
    /// Its last try ended at the omap run admission ([`Shard::run_admit_blocks`], object and WAL op bytes): it is tried
    /// again only once that answer changes, not on every other progress of the store.
    run_wait: Option<(u64, usize)>,
    /// Stall clock of the head: since when it waits without progress, and the progress it saw then
    /// ([`Store::head_progress`]); `None` until its first try as the head.
    stall: Option<(u64, HeadProgress)>,
}

/// What a parked FIFO head's stall clock compares between two of its tries ([`Store::head_progress`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct HeadProgress {
    /// Where the try stopped: phase (build, prepare, submit) and the shard's `WouldBlock` origin.
    at: (&'static str, &'static str),
    /// Device reads of the head admitted or completed; tree pages loaded while it waits for pages; durable LSN; free
    /// blocks; run memory released.
    n: [u64; 5],
}

/// Tree entries a txn sets or removes (space admission while it is parked, adr 0021 am. 45): random keys each may dirty a
/// leaf of their own; data extents and object records count one per op.
fn txn_entries(t: &OTxn) -> u64 {
    t.ops
        .iter()
        .map(|o| match o {
            TOp::OmapSetKeys { pairs, .. } => pairs.len() as u64,
            TOp::OmapSetRun { run, .. } => run.len() as u64,
            TOp::SetAttrs { attrs, .. } => attrs.len() as u64,
            TOp::OmapRmKeys { keys, .. } => keys.len() as u64,
            _ => 1,
        })
        .sum::<u64>()
}

impl<D: BlockDev, C: Clock> Parked<D, C> {
    fn names(&mut self, t: &OTxn) {
        self.objects.clear();
        self.colls.clear();
        self.oids.clear();
        for op in &t.ops {
            for (c, o) in op.objects().into_iter().flatten() {
                self.objects.push((*c, name_key_of(0, o)));
                self.oids.push((*c, o.clone()));
            }
            if op.objects()[0].is_none() {
                self.colls.extend(op.colls().into_iter().flatten().copied());
            }
        }
    }
}

/// Names one collection holds in a shard FIFO: parked txns naming the collection itself, objects of it, and per object key.
#[derive(Default)]
struct CollIdx {
    whole: u32,
    objs: u32,
    keys: std::collections::HashMap<Vec<u8>, u32>,
}

/// Shard FIFO of parked txns with an index of the names they write (adr 0021 am. 44): `parked_on` is O(1) instead of a
/// scan of every parked txn. The index changes only on push / pop (the names of a popped entry may change before it is
/// pushed back).
struct ParkQ<D: BlockDev, C: Clock> {
    q: VecDeque<Parked<D, C>>,
    idx: std::collections::HashMap<CollT, CollIdx>,
    /// Sum of the parked txns' [`Cost::parked`]: the space admission of the shard charges it next to every new txn
    /// (adr 0021 am. 45).
    rsv: Cost,
    /// Last park sequence issued (`Parked::seq`).
    seq: u64,
}

impl<D: BlockDev, C: Clock> ParkQ<D, C> {
    fn new() -> Self {
        ParkQ {
            q: VecDeque::new(),
            idx: std::collections::HashMap::new(),
            rsv: Cost::default(),
            seq: 0,
        }
    }
    /// Park sequence of a txn parked now.
    fn issue(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }
    /// A txn parked at or before `seq` names collection `cid` (as a whole or one of its objects).
    fn names_before(&self, cid: &CollT, seq: u64) -> bool {
        self.q.iter().any(|p| {
            p.seq <= seq && (p.colls.contains(cid) || p.objects.iter().any(|(c, _)| c == cid))
        })
    }
    fn is_empty(&self) -> bool {
        self.q.is_empty()
    }
    fn len(&self) -> usize {
        self.q.len()
    }
    fn front(&self) -> Option<&Parked<D, C>> {
        self.q.front()
    }
    fn iter(&self) -> impl Iterator<Item = &Parked<D, C>> {
        self.q.iter()
    }
    fn index(&mut self, p: &Parked<D, C>, add: bool) {
        let cost = Cost::parked(p.bytes, p.entries);
        if add {
            self.rsv.add(cost);
        } else {
            self.rsv.sub(cost);
            // the held cost closes: an empty FIFO holds nothing (callers pop before they unindex)
            debug_assert!(
                !self.q.is_empty() || self.rsv == Cost::default(),
                "parked cost leaked: {:?}",
                self.rsv
            );
        }
        let step = |n: &mut u32| {
            if add {
                *n += 1;
            } else {
                *n -= 1;
            }
        };
        for c in &p.colls {
            step(&mut self.idx.entry(*c).or_default().whole);
        }
        for (c, k) in &p.objects {
            let e = self.idx.entry(*c).or_default();
            step(&mut e.objs);
            if add {
                *e.keys.entry(k.clone()).or_default() += 1;
            } else if let Some(n) = e.keys.get_mut(k.as_slice()) {
                *n -= 1;
                if *n == 0 {
                    e.keys.remove(k.as_slice());
                }
            }
        }
        if !add {
            for c in p.colls.iter().chain(p.objects.iter().map(|(c, _)| c)) {
                if self.idx.get(c).is_some_and(|e| e.whole == 0 && e.objs == 0) {
                    self.idx.remove(c);
                }
            }
        }
    }
    fn push_back(&mut self, p: Parked<D, C>) {
        self.index(&p, true);
        self.q.push_back(p);
    }
    fn push_front(&mut self, p: Parked<D, C>) {
        self.index(&p, true);
        self.q.push_front(p);
    }
    fn pop_front(&mut self) -> Option<Parked<D, C>> {
        let p = self.q.pop_front()?;
        self.index(&p, false);
        Some(p)
    }
    fn pop_front_if(&mut self, f: impl FnOnce(&mut Parked<D, C>) -> bool) -> Option<Parked<D, C>> {
        let p = self.q.pop_front_if(f)?;
        self.index(&p, false);
        Some(p)
    }
    /// Does a parked txn name `cid` itself, or object `key` of it (`None`: any object of it)?
    fn names(&self, cid: &CollT, key: Option<&[u8]>) -> bool {
        self.idx.get(cid).is_some_and(|e| {
            e.whole > 0
                || match key {
                    None => e.objs > 0,
                    Some(k) => e.keys.contains_key(k),
                }
        })
    }
}

/// Inline-compression counters of a store ([`Store::comp_counters`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompCounters {
    pub ok: u64,
    pub rejected: u64,
    pub sampled_out: u64,
    /// Compressed chunk windows rewritten by the chunk space rule (adr 0059 am. 4).
    pub gc_merged: u64,
    pub decomp: u64,
    pub comp_ns: u64,
    pub decomp_ns: u64,
    /// Data staging counters (adr 0061 am. 4, see `ObjStats`).
    pub staged_bytes: u64,
    pub zc_bytes: u64,
    pub crc_reused_bytes: u64,
    /// Placement bytes covered by a shifted receipt CRC grid.
    pub placement_crc_reblocked_bytes: u64,
    /// Source bytes newly hashed to construct shifted receipt CRCs.
    pub placement_crc_hashed_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct StoreCfg {
    pub shard: ShardCfg,
}

/// Per-shard outcome of a degraded read-only mount ([`Store::mount_shards_read_only`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShardMountState {
    /// Mounted read-only (WAL replayed, nothing written).
    Mounted,
    /// The operator excluded the shard: never opened, never replayed, never checkpointed, never healed.
    Skipped,
    /// Selected but its mount failed (damaged meta region); the store error as text.
    Failed(String),
}

impl Default for StoreCfg {
    fn default() -> Self {
        StoreCfg {
            shard: ShardCfg {
                // 256 KiB WAL records: room for ~60 KiB .. 250 KiB omap batches (units are variable sized)
                max_unit_blocks: 64,
                ..ShardCfg::default()
            },
        }
    }
}

/// Smallest tree page cache of a shard (adr 0062: the txn page budget is half the cache, and a 10 MiB dirfrag batch needs
/// 2-4k pages): [`StoreCfg::for_memory`] sizes no shard below it, a shard of the device's page pool never gives its cache
/// below it ([`crate::pagepool`]).
pub const MIN_CACHE_PAGES: usize = 4096;
/// MiB of tree pages per cache scale unit (16384 pages of 8 KiB).
const CACHE_UNIT_MIB: u64 = 128;
/// Point-cache entries per cache scale unit (~256 B each = 8 MiB).
pub const POINT_PER_UNIT: u64 = 32768;
/// Bytes per cache scale unit: tree pages + the checkpoint arena a checkpoint copies the dirty pages into (up to the soft
/// dirty mark, 1/8 of the pages: the checkpoint trigger; the hard mark 3/8 is a stall level reached only in overload)
/// + point cache + leaf delta chains (16 MiB), adr 0062 am. 1 and am. 2.
pub const CACHE_UNIT_BYTES: u64 = (CACHE_UNIT_MIB + CACHE_UNIT_MIB / 8 + 24) << 20;

/// Largest data cache floor per shard (adr 0633-data-cache-envelope): [`StoreCfg::for_memory`] reserves it in the cache share
/// before the tree pages, but only out of what the share holds above the smallest tree, so it never raises the minimum
/// budget.
pub const DATA_FLOOR_BYTES: u64 = 32 << 20;

/// Omap run soft size (adr 0476) of a shard's cache share: 1/16 of it.
fn run_soft_of_share(share: u64) -> usize {
    (share / 16) as usize
}

/// The omap run soft size [`StoreCfg::for_memory`] gives a shard whose tree cache is `pages` (tools that size a store by
/// its cache pages get the daemon's run budget).
pub fn run_soft_for_pages(pages: usize) -> usize {
    run_soft_of_share(pages as u64 * CACHE_UNIT_BYTES / 16384)
}

/// Omap runs (adr 0476) take their hard size (twice the soft size) out of the shard's cache share: the tree pages and
/// what scales with them (dirty marks, point cache, delta chains) shrink by the same factor. The cache keeps at least the
/// [`MIN_CACHE_PAGES`] of [`StoreCfg::for_memory`]; a share too small for both shrinks the run budget instead.
pub fn carve_runs(s: &mut crate::shard::ShardCfg) {
    let per_page = CACHE_UNIT_BYTES / 16384;
    let want = (2 * s.run_soft_bytes as u64).div_ceil(per_page) as usize;
    let take = want.min(s.cache_pages.saturating_sub(MIN_CACHE_PAGES));
    if take < want {
        s.run_soft_bytes = (take as u64 * per_page / 2) as usize;
    }
    if take == 0 {
        return;
    }
    let (old, new) = (s.cache_pages as u128, (s.cache_pages - take) as u128);
    let f = |x: usize| (x as u128 * new / old) as usize;
    s.dirty_soft_pages = f(s.dirty_soft_pages);
    s.dirty_hard_pages = f(s.dirty_hard_pages);
    s.point_cache = f(s.point_cache).max(1024);
    s.delta_cap_bytes = f(s.delta_cap_bytes).max(1 << 20);
    s.cache_pages -= take;
}

/// Size the tree caches of `s` for a cache share of `share` bytes (adr 0062): pages (at least [`MIN_CACHE_PAGES`]), dirty
/// marks, point cache, delta chains and omap run budget. Returns the bytes they need (`<= share` unless the page minimum
/// applies).
fn size_tree(s: &mut crate::shard::ShardCfg, share: u64) -> u64 {
    // The shard share covers everything that scales with the cache, not only the pages: per 16384 pages (128 MiB)
    // the point cache (32768 entries, ~256 B each = 8 MiB) and the leaf delta chains (16 MiB) come on top.
    // omap runs (adr 0476): soft size 1/16 of the share, pooled over the device's shards; a store formatted with
    // runs takes their hard size out of the cache share at mount (`carve_runs`)
    s.run_soft_bytes = run_soft_of_share(share);
    let pages = (share * 16384 / CACHE_UNIT_BYTES).clamp(MIN_CACHE_PAGES as u64, 1 << 22) as usize;
    let scale = pages as f64 / 16384.0;
    s.cache_pages = pages;
    s.dirty_soft_pages = pages / 8;
    s.dirty_hard_pages = pages * 3 / 8;
    s.point_cache = ((POINT_PER_UNIT as f64 * scale) as usize).max(1024);
    s.delta_cap_bytes = (((16u64 << 20) as f64 * scale) as usize).max(1 << 20);
    (s.cache_pages + s.dirty_soft_pages) as u64 * 8192
        + s.point_cache as u64 * 256
        + s.delta_cap_bytes as u64
}

impl StoreCfg {
    /// Caches sized for a process-wide `budget` bytes over `shards` shards (adr 0062).
    /// Reject budgets below the per-shard working-set minimum (the smallest tree) instead of silently exceeding them.
    pub fn for_memory(budget: u64, shards: u32) -> Result<StoreCfg> {
        let mut c = StoreCfg::default();
        let share = budget / shards.max(1) as u64;
        let min = size_tree(&mut c.shard, 0);
        // the data cache floor comes out of the share first: 1/16 of it like the omap run budget (a small share keeps
        // room for its runs), only out of what it holds above the smallest tree (the minimum budget stays the tree's),
        // at most 32 MiB; the data cache grows beyond it only into tree pages not allocated yet (adr 0633-data-cache-envelope)
        let floor = DATA_FLOOR_BYTES
            .min(share / 16)
            .min(share.saturating_sub(min));
        let required = size_tree(&mut c.shard, share - floor);
        if required > share - floor {
            return Err(ObjError::Invalid(format!(
                "cache budget {budget} bytes across {} shards is below the minimum {} bytes; increase osd_memory_target or reduce shard count",
                shards.max(1),
                min * u64::from(shards.max(1))
            )));
        }
        c.shard.data_floor_blocks = floor / BLK as u64;
        Ok(c)
    }
}

/// PG -> shard (ADR 0021): `(pool + pg_seed) mod S`.
pub fn shard_of_spg(pool: u64, seed: u32, nshards: u32) -> usize {
    (pool.wrapping_add(seed as u64) % nshards as u64) as usize
}

/// Add shard context to a shard mount error so the operator sees which shard failed. [`StoreError::WalLost`] already
/// names its shard; every other mount error is wrapped.
fn shard_err(e: StoreError, shard: u32) -> StoreError {
    if let StoreError::WalLost { .. } = e {
        return e;
    }
    StoreError::Corrupt(format!("shard {shard}: {e}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjStat {
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollStats {
    pub bits: u32,
    /// Objects / bytes excluding pgmeta and temp objects.
    pub nobj: u64,
    pub nbytes: u64,
    /// Compressed extents: physical bytes and the logical bytes they stand for (adr 0059 am. 1).
    pub comp: u64,
    pub comp_orig: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct StoreStatfs {
    pub total_bytes: u64,
    /// Bytes charged as used: the real usage, raised per shard to its binding resource (meta-bound shard reads full).
    pub used_bytes: u64,
    /// Bytes really held (data + tree pages in use, [`crate::shard::Statfs::used_blocks`]): what classic reports as used.
    pub real_used_bytes: u64,
    /// Tree-page bytes inside `real_used_bytes`: the metadata of elastic shards only (their cells lie in the data
    /// blocks); a fixed meta region lies outside the data blocks and is not part of `real_used_bytes`.
    pub real_meta_bytes: u64,
    pub avail_bytes: u64,
    /// Freed but waiting for a checkpoint / readers.
    pub held_bytes: u64,
    pub meta_used_pages: u64,
    /// Bytes of those pages: the page size is the format's `node_size` (`meta_bpp * BLK`), never a constant.
    pub meta_used_bytes: u64,
    pub meta_total_pages: u64,
    /// Omap bytes over all shards: device blocks of the live engine runs plus both memtables; 0 on stores whose omap
    /// lives in the tree (tree omap bytes are part of `used_bytes`).
    pub omap_bytes: u64,
    /// Used percentage of the fullest shard (fullness is judged there, design 2.1), measured against what the shard can
    /// still get: its own capacity plus, on a pooled store, the free pool chunks it may borrow
    /// ([`crate::shard::Statfs::pooled_fill_ratio`]). A pooled shard at its base reads its true fill once the pool is
    /// dry: unused base of other shards is never lent, so it must not hide a full shard behind the device sum.
    pub fullest_shard_pct: f32,
    /// The elastic pool is in use (adr 0021 am. 52): the pool is counted as free capacity by its owner's store only.
    pub pooled: bool,
}

pub struct Store<D: BlockDev, C: Clock> {
    prep: Vec<Option<Preparation<D::Buf>>>,
    prep_yielded: Vec<bool>,
    prep_budget: super::budget::Budget,
    prep_turn: usize,
    helper_served: u64,
    helper_queued: usize,
    helper_capable: bool,
    pub clk: C,
    /// Mounted shards: all for a full mount (`shards[i]` is shard `i`), only the owned ones for a per-core store
    /// ([`Store::mount_shards`]); `slot` maps shard id -> index here.
    pub shards: Vec<ShardStore<D>>,
    nsh: u32,
    slot: Vec<u32>,
    /// PGs whose shard differs from the hash default: split children keep their parent's shard, migrated PGs sit
    /// where they were moved (adr 0031). Rebuilt at mount from where the collections are.
    place: std::collections::HashMap<(u64, u32), u32>,
    pub sb: Superblock,
    next_token: u64,
    /// Shards that may have work (queued txns, I/O, checkpoint, page loads), ascending; `poll` visits only these.
    /// All shards are re-added every `SWEEP_NS` so time-driven work (checkpoint interval) is never missed.
    active: Vec<usize>,
    is_active: Vec<bool>,
    next_sweep: u64,
    woke: bool,
    /// Specific wakes (page loads, prefetch runs) not yet taken by [`Store::take_wake_set`]; `wtoks.overflowed()` = unknown.
    wtoks: crate::toks::Toks<32>,
    /// Read-only calls (`stage`) run non-blocking: a tree miss submits the page read and fails with `WouldBlock`
    /// ([`Store::set_nonblock_reads`]).
    nb_reads: bool,
    /// Residency leases (adr 0043 am. 18): id -> (shard index, collection). `lease_cur` = the lease of the probes that
    /// follow ([`Store::lease_use`], 0 = none).
    leases: crate::fx::FxMap<u64, (usize, CollT)>,
    lease_next: u64,
    lease_cur: u64,
    /// A read hit `WouldBlock` since [`Store::take_blocked`] last looked.
    blocked: bool,
    parked: Vec<ParkQ<D, C>>,
    parked_bytes: Vec<usize>,
    queue_count: usize,
    /// Background work ns of the shards found by the last [`ObjStore::poll`] (see [`ObjStore::bg_ns`]).
    bg_ns: u64,
    queue_bytes: usize,
    queue_errors: Vec<(u64, ObjError)>,
    /// Only the FIFO head's adapter translation may read past its own visibility fence.
    preparing: Option<QueueBuildContext>,
    pub queue_attempts: u64,
    /// Txns parked in a shard FIFO (lifetime), and `parked_on` probes that had to scan a non-empty FIFO (adr 0021 am. 43).
    pub parks: u64,
    pub park_probes: u64,
    /// Blocking queue barriers that found parked txns (`Store::drain_queued`) and the time they held the core.
    pub barriers: u64,
    pub barrier_ns: u64,
    /// Page loads the parked-txn lookahead submitted (adr 0021 am. 44).
    pub lookahead_loads: u64,
    visibility_key: Vec<u8>,
    /// Lending table of a chunked store (adr 0021 am. 49); None for a plain store.
    #[cfg(feature = "elastic")]
    lend: Option<crate::lend::Lending>,
    /// Pool owner only (adr 0021 am. 52): the table writer with its own queue, and what the cores exchange.
    #[cfg(feature = "elastic")]
    pool: Option<crate::lend::Pool<D>>,
    #[cfg(feature = "elastic")]
    lend_out: Vec<crate::lend::LendMsg>,
    #[cfg(feature = "elastic")]
    lend_scratch: Vec<crate::lend::LendMsg>,
    /// Pool owner: free pool blocks and view revision last announced (`pool_announce`; None = not yet since mount),
    /// and per device shard the `(pool, spare, target, prog)` it was told last.
    #[cfg(feature = "elastic")]
    pool_said: Option<(u64, u64)>,
    #[cfg(feature = "elastic")]
    shard_said: Vec<Option<(u64, u64, u64, u64)>>,
    /// Some shard of this store uses the pool (`lend_auto` on a chunked store).
    #[cfg(feature = "elastic")]
    lend_on: bool,
}

const SWEEP_NS: u64 = 1_000_000;
/// A parked FIFO head without progress of its own for this long fails (`resume_queue`).
const STALL_NS: u64 = 30_000_000_000;

impl<D: BlockDev, C: Clock> std::fmt::Debug for Store<D, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Store({} shards)", self.shards.len())
    }
}

/// Data bytes of one txn below which the device queue can never be the limit (extents of <= 256 KiB each).
const MAX_UNCHECKED_DATA: usize = 8 << 20;

/// Stage and submit `t`. `Ok(None)` = a chunk would compress but `FEAT_COMPRESSION` is not durable yet: nothing was
/// applied, the caller sets the bit and runs the txn again.
fn run_txn<D: BlockDev, C: Clock>(
    s: &mut ShardStore<D>,
    clk: &mut C,
    t: &OTxn,
    token: u64,
) -> Result<Option<u64>> {
    run_with(s, clk, token, |st| st.apply(t))
}

/// [`run_txn`] of what `f` stages (the store's own txns, e.g. the format upgrade).
pub(super) fn run_with<'a, D: BlockDev, C: Clock>(
    s: &mut ShardStore<D>,
    clk: &mut C,
    token: u64,
    f: impl FnOnce(&mut Stage<'_, 'a, D, C>) -> Result<()>,
) -> Result<Option<u64>> {
    s.comp_wanted = false;
    let Built {
        mut txn,
        needs_compression,
    } = {
        let mut st = Stage::new(s, clk);
        f(&mut st)?;
        st.finish(token)?
    };
    // the reservations are exactly the staged data extents and the claimed pre-writes
    let unres = |s: &mut ShardStore<D>, txn: &Txn<D::Buf>| s.sh.unreserve_txn(txn);
    if needs_compression {
        unres(s, &txn);
        return Ok(None);
    }
    // freed blocks may hold other data soon: no cached copy may outlive the free
    s.forget_freed(&txn.frees);
    let tails = s.tail_blocks(&txn);
    let mut stall = crate::sio::Stall::new("txn submit wait");
    loop {
        match s.sh.submit(txn) {
            Ok(lsn) => {
                s.cache_tails(tails);
                for k in 0..s.scratch.ids.len() {
                    let id = s.scratch.ids[k];
                    s.note_write(id, lsn);
                }
                s.stats.txns += 1;
                return Ok(Some(lsn));
            }
            Err((e, t)) => {
                txn = t;
                match e {
                    StoreError::Miss => {
                        crate::dbg::miss_tag(0);
                        if let Err(e) = s.miss_wait(clk) {
                            unres(s, &txn);
                            return Err(e);
                        }
                    }
                    StoreError::Busy | StoreError::WalFull => {
                        #[cfg(feature = "lab")]
                        let t0 = std::time::Instant::now();
                        if let Err(e) = s.backpressure_round(clk, &mut stall) {
                            unres(s, &txn);
                            return Err(e);
                        }
                        #[cfg(feature = "lab")]
                        crate::dbg::qwait_done(1, t0);
                    }
                    e => {
                        unres(s, &txn);
                        return Err(e.into());
                    }
                }
            }
        }
    }
}

/// [`Store::check_txn`] on its shard: plan the metadata and extent sizes, then the record fit; a page miss waits
/// ([`ShardStore::miss_wait`]) or, with `s.nonblock`, returns `WouldBlock` with the load submitted.
fn check_record<D: BlockDev, C: Clock>(s: &mut ShardStore<D>, clk: &mut C, t: &OTxn) -> Result<()> {
    let plan = Stage::new(s, clk).plan(t)?;
    let r = loop {
        match s.sh.check_record_fits(&plan) {
            Err(StoreError::Miss) => {
                if let Err(e) = s.miss_wait(clk) {
                    break Err(e);
                }
            }
            Err(e) => break Err(e.into()),
            Ok(pages) => {
                break if pages > s.sh.txn_page_budget() / 2 {
                    Err(ObjError::TooLarge)
                } else {
                    Ok(())
                };
            }
        }
    };
    for e in &plan.data {
        s.sh.unreserve(e.blk, e.nblk);
    }
    r
}

impl<D: BlockDev, C: Clock> Store<D, C> {
    /// Mount all shards of the device. `open` returns one queue handle per call (first for the superblock +
    /// shard 0, then one per further shard).
    pub fn mount(
        open: impl FnMut() -> D,
        clk: C,
        cfg: StoreCfg,
    ) -> Result<(Store<D, C>, Vec<ReplayStats>)> {
        Self::mount_shards(open, clk, cfg, |_| true)
    }

    /// Mount only the shards `owned(shard)` accepts: a per-core store (the core owning shard `i` is the only one that
    /// touches it, adr 0031). Shard ids keep their device-wide meaning (`shard_of`, `nshards`); an operation routed
    /// to a shard this store did not mount fails with `ObjError::NotMounted`. `open` is called once for the
    /// superblock and once per mounted shard (the superblock handle is reused for the first).
    pub fn mount_shards(
        open: impl FnMut() -> D,
        clk: C,
        cfg: StoreCfg,
        owned: impl Fn(u32) -> bool,
    ) -> Result<(Store<D, C>, Vec<ReplayStats>)> {
        Self::mount_with(open, clk, cfg, owned, false, false, None)
    }

    /// Mount a subset of shards read-only for the degraded offline export. Only the shards `owned` accepts are
    /// opened and replayed; **nothing is written**, neither at mount (no superblock heal, feature-bit write,
    /// epoch/root-slot write, post-replay checkpoint, lending-table writer or omap-counter drop) nor later: the shards
    /// refuse txns, pre-writes and checkpoints ([`ShardStore::checkpoint`] fails) and never trim, so reads, scans and
    /// exports submit device reads only; drop writes nothing. The replayed WAL state lives in memory. A store with an
    /// omap engine (LSM/RocksDB) is refused. A selected shard whose mount fails (media error in its meta region) is
    /// recorded as [`ShardMountState::Failed`] and left out; the healthy shards still mount so their PGs stay
    /// exportable. The returned report is indexed by device shard id.
    #[expect(clippy::type_complexity)]
    pub fn mount_shards_read_only(
        open: impl FnMut() -> D,
        clk: C,
        cfg: StoreCfg,
        owned: impl Fn(u32) -> bool,
    ) -> Result<(Store<D, C>, Vec<ReplayStats>, Vec<ShardMountState>)> {
        let mut report = Vec::new();
        let (st, stats) = Self::mount_with(open, clk, cfg, owned, false, true, Some(&mut report))?;
        Ok((st, stats, report))
    }

    /// Mount all shards for an offline format upgrade step (adr 0611, `crate::upgrade`): a store marked upgrading (or
    /// lacking a required bit) mounts; during S7 the omap engine runs beside the tree omap, reads use the tree.
    pub(crate) fn mount_upgrade(
        open: impl FnMut() -> D,
        clk: C,
        cfg: StoreCfg,
    ) -> Result<(Store<D, C>, Vec<ReplayStats>)> {
        Self::mount_with(open, clk, cfg, |_| true, true, false, None)
    }

    fn mount_with(
        mut open: impl FnMut() -> D,
        mut clk: C,
        mut cfg: StoreCfg,
        owned: impl Fn(u32) -> bool,
        upgrade: bool,
        read_only: bool,
        mut report: Option<&mut Vec<ShardMountState>>,
    ) -> Result<(Store<D, C>, Vec<ReplayStats>)> {
        // the shards of one store share their omap run budget unless the caller shares a wider one
        cfg.shard.run_pool.get_or_insert_default();
        let mut d0 = open();
        let (mut sb, dirs) = read_super(&mut d0, &mut clk)?;
        if !upgrade {
            crate::upgrade::mount_check(&sb)?;
            if cfg.shard.require_current {
                crate::layout::check_required(&sb)?;
            }
            // every PG log trim of this build keeps the dup records in the retained log keys (adr 0634): the bit is
            // durable from the first mount on (`heal_super` below), so no PG core ever waits for a superblock write.
            // A read-only mount reads the store as-is and never sets or writes a feature bit.
            if !read_only {
                sb.features |= crate::layout::FEAT_LOG_DUPS;
            }
        }
        // this build keeps no omap counters and logs omap removal runs: durable before the first txn (replay included),
        // so an older build that would trust the stale onode counters or read a removal as a value refuses the store
        // from here on. A read-only mount does not set them (nothing is written).
        if !read_only {
            sb.features |= crate::layout::FEAT_OMAP_UNCOUNTED | crate::layout::FEAT_OMAP_TOMBS;
        }
        let lsm = sb.features & crate::layout::FEAT_OMAP_LSM != 0;
        let engine = crate::upgrade::engine_on(&sb);
        if read_only && engine {
            // the omap engines (LSM, RocksDB) flush and compact on their own; the read-only shard guards cover the tree
            // path only, so a degraded read-only mount refuses them instead of risking a write
            return Err(StoreError::Invalid(
                "degraded read-only mount: stores with an omap engine (LSM/RocksDB) are not supported",
            )
            .into());
        }
        if engine {
            // omap lives in the LSM engine (adr 0610): no tree runs; the engine takes its share at shard mount
            cfg.shard.run_soft_bytes = 0;
        } else if sb.features & crate::layout::FEAT_OMAP_RUNS != 0 {
            carve_runs(&mut cfg.shard);
        }
        // both copies = the one in effect (a crash between the two writes of an expand left the other
        // older; a later fallback to it would drop extents or feature bits the shards rely on). No write when equal.
        // A read-only mount never heals (and never writes the feature bits set above).
        if !read_only {
            crate::layout::heal_super(&mut d0, &mut clk, &sb)?;
        }
        #[cfg(feature = "elastic")]
        // one table writer per device: the store holding shard 0 (per-core stores all keep the default `lend_owner`)
        let lend =
            if sb.features & crate::layout::FEAT_CHUNKED != 0 && cfg.shard.lend_owner && owned(0) {
                Some(crate::lend::Lending::load(
                    &mut crate::sio::Sio::new(&mut d0, &mut clk),
                    &sb,
                    &dirs,
                )?)
            } else {
                None
            };
        let mut first = Some(d0);
        let mut shards = Vec::new();
        let mut stats = Vec::new();
        let nsh = dirs.len();
        if let Some(r) = report.as_deref_mut() {
            r.clear();
            r.resize(nsh, ShardMountState::Skipped);
        }
        // the shards of the device publish their queue state in one table (adr 0533); a table sized for
        // another device (a test mounting two stores with one cfg) is replaced by one of this store's own
        if !cfg.shard.dev_idle.get_or_insert_default().init(nsh) {
            let own = std::sync::Arc::new(crate::devidle::DevIdle::default());
            own.init(nsh);
            cfg.shard.dev_idle = Some(own);
        }
        // and one tree page budget (adr 0062 am. 3), the same way
        if !cfg.shard.page_pool.get_or_insert_default().init(nsh) {
            let own = std::sync::Arc::new(crate::pagepool::PagePool::default());
            own.init(nsh);
            cfg.shard.page_pool = Some(own);
        }
        let mut slot = vec![u32::MAX; nsh];
        for dir in &dirs {
            if !owned(dir.shard) {
                continue;
            }
            let dev = first.take().unwrap_or_else(&mut open);
            let (sh, st) = match Shard::mount(dev, &mut clk, &sb, dir, cfg.shard.clone(), read_only)
            {
                Ok(x) => x,
                Err(e) => {
                    if read_only {
                        // a damaged meta region: record it and keep the healthy shards mountable
                        if let Some(r) = report.as_deref_mut() {
                            r[dir.shard as usize] =
                                ShardMountState::Failed(format!("shard {}: {e}", dir.shard));
                        }
                        continue;
                    }
                    return Err(shard_err(e, dir.shard).into());
                }
            };
            slot[dir.shard as usize] = shards.len() as u32;
            let mut ss = ShardStore::new(sh, dir.shard);
            ss.omap_lsm = lsm;
            // the engine keeps no runs of the tree path
            ss.omap_runs = !lsm
                && sb.features & crate::layout::FEAT_OMAP_RUNS != 0
                && cfg.shard.run_soft_bytes > 0;
            ss.long_names = sb.features & crate::layout::FEAT_LONG_NAME != 0;
            ss.compression = sb.features & crate::layout::FEAT_COMPRESSION != 0;
            ss.shared_ext = sb.features & crate::layout::FEAT_SHARED_EXT != 0;
            ss.dedup = sb.features & crate::layout::FEAT_DEDUP != 0;
            // a store without the bit copies
            ss.share_off = !cfg.shard.shared_clone || !ss.shared_ext;
            ss.pf_retain = cfg.shard.pf_retain;
            ss.defrag = cfg.shard.defrag;
            ss.rc = super::recompact::Rc::new();
            if sb.features & crate::layout::FEAT_INLINE_DATA != 0 {
                // an inline value must stay a short-key sized tree entry (leaf density); never above one block
                ss.inline_max = (cfg.shard.inline_max as usize)
                    .min(BLK)
                    .min(ss.sh.state().tree.soft_entry().saturating_sub(32));
            }
            if sb.features & crate::layout::FEAT_EXT_VALUE != 0 {
                ss.val_ext_min = cfg.shard.val_ext_min as usize;
            }
            if sb.features & crate::layout::FEAT_VAL_COMP != 0 {
                ss.val_comp_min = cfg.shard.val_comp_min as usize;
                ss.val_dict_samples = cfg.shard.val_dict_samples as usize;
                ss.sh.state_mut().vc_min = ss.val_comp_min;
            }
            shards.push(ss);
            stats.push(st);
            if let Some(r) = report.as_deref_mut() {
                r[dir.shard as usize] = ShardMountState::Mounted;
            }
        }
        #[cfg(feature = "elastic")]
        let lend_on = shards.iter().any(|s| s.sh.lend.on);
        // the pool owner writes the table on a queue of its own (completions must not mix with a shard's);
        // a read-only mount never creates the pool writer (the degraded export only reads)
        #[cfg(feature = "elastic")]
        let pool = match &lend {
            Some(l) if lend_on && !read_only => {
                let p = crate::lend::Pool::new(open(), nsh as u32);
                let hint = l.free_chunks() * l.geom.chunk;
                for s in shards.iter_mut() {
                    s.sh.lend.pool = hint;
                }
                Some(p)
            }
            _ => None,
        };
        let mounted = shards.len();
        let mut st = Store {
            prep: (0..mounted).map(|_| None).collect(),
            prep_yielded: vec![false; mounted],
            prep_budget: super::budget::Budget::new(clk.wall_time()),
            prep_turn: 0,
            helper_served: 0,
            helper_queued: 0,
            helper_capable: cfg.shard.run_helpers || engine,
            clk,
            shards,
            nsh: nsh as u32,
            slot,
            place: Default::default(),
            sb,
            next_token: 1 << 62,
            active: Vec::new(),
            is_active: vec![false; mounted],
            next_sweep: 0,
            woke: false,
            wtoks: Default::default(),
            nb_reads: false,
            leases: Default::default(),
            lease_next: 0,
            lease_cur: 0,
            blocked: false,
            parked: (0..mounted).map(|_| ParkQ::new()).collect(),
            parked_bytes: vec![0; mounted],
            queue_count: 128,
            bg_ns: 0,
            queue_bytes: 1 << 30,
            queue_errors: Vec::new(),
            preparing: None,
            queue_attempts: 0,
            parks: 0,
            barriers: 0,
            barrier_ns: 0,
            park_probes: 0,
            lookahead_loads: 0,
            visibility_key: Vec::with_capacity(256),
            #[cfg(feature = "elastic")]
            lend,
            #[cfg(feature = "elastic")]
            pool,
            #[cfg(feature = "elastic")]
            lend_out: Vec::new(),
            #[cfg(feature = "elastic")]
            lend_scratch: Vec::new(),
            #[cfg(feature = "elastic")]
            pool_said: None,
            #[cfg(feature = "elastic")]
            shard_said: Vec::new(),
            #[cfg(feature = "elastic")]
            lend_on,
        };
        st.scan_placement()?;
        if !read_only {
            st.drop_counter_records()?;
        }
        Ok((st, stats))
    }

    /// Remove the omap counter records (`c` keys) an earlier build left (`FEAT_OMAP_UNCOUNTED`): one range removal per
    /// shard that has any. Idempotent: a crash before the removal is durable leaves them to the next mount; nothing
    /// reads them meanwhile.
    fn drop_counter_records(&mut self) -> Result<()> {
        for s in &mut self.shards {
            if Stage::new(s, &mut self.clk).counter_records()? {
                run_with(s, &mut self.clk, 0, |st| {
                    st.drop_counter_records();
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Learn the PGs of the mounted shards that sit off their hash shard.
    fn scan_placement(&mut self) -> Result<()> {
        for i in 0..self.shards.len() {
            let here = self.shards[i].idx;
            let mut st = Stage::new(&mut self.shards[i], &mut self.clk);
            for c in st.scan_colls()? {
                if let CollT::Pg(s) | CollT::PgTemp(s) = c
                    && shard_of_spg(s.pgid.pool, s.pgid.seed, self.nsh) != here as usize
                {
                    self.place.insert((s.pgid.pool, s.pgid.seed), here);
                }
            }
        }
        Ok(())
    }

    /// Apply the LSM range-delete threshold to every shard mounted by this owner core.
    /// Per-core stores update only their owned shards; other stores are unaffected. Future
    /// staging attempts see the new value without restarting, clearing caches or changing
    /// already built transactions. The OSD configuration path fans out to the other cores.
    pub fn set_omap_delete_range_threshold(&mut self, threshold: u64) {
        for shard in &mut self.shards {
            shard.sh.set_omap_delete_range_threshold(threshold);
        }
    }

    /// Declare that PG `(pool, seed)` lives on `shard` (its collections are created / looked up there).
    pub fn set_placement(&mut self, pool: u64, seed: u32, shard: u32) {
        if shard_of_spg(pool, seed, self.nsh) == shard as usize {
            self.place.remove(&(pool, seed));
        } else {
            self.place.insert((pool, seed), shard);
        }
    }

    /// Shard of PG `(pool, seed)`.
    pub fn pg_shard(&self, pool: u64, seed: u32) -> u32 {
        self.place
            .get(&(pool, seed))
            .copied()
            .unwrap_or_else(|| shard_of_spg(pool, seed, self.nsh) as u32)
    }

    /// Superblock feature bits of the mounted store.
    pub fn features(&self) -> u64 {
        self.sb.features
    }

    /// Number of shards of the device (not of this mount).
    pub fn nshards(&self) -> usize {
        self.nsh as usize
    }

    /// Is shard `s` mounted here?
    pub fn has_shard(&self, s: usize) -> bool {
        self.slot.get(s).is_some_and(|x| *x != u32::MAX)
    }

    /// Device-wide shard id of collection `c`.
    pub fn shard_of(&self, c: &CollT) -> usize {
        match c {
            CollT::Meta => 0,
            CollT::Pg(s) | CollT::PgTemp(s) => self.pg_shard(s.pgid.pool, s.pgid.seed) as usize,
        }
    }

    /// Index into `shards` of device shard `s`.
    fn local(&self, s: usize) -> Result<usize> {
        match self.slot.get(s) {
            Some(&i) if i != u32::MAX => Ok(i as usize),
            _ => Err(ObjError::NotMounted(s as u32)),
        }
    }

    /// Local index of the shard the txn touches (None = no collection involved).
    fn route(&self, t: &OTxn) -> Result<Option<usize>> {
        let mut r = None;
        for op in &t.ops {
            let shard = match op {
                TOp::DedupKv { shard, .. } => Some(*shard as usize),
                _ => None,
            };
            for s in op
                .colls()
                .into_iter()
                .flatten()
                .map(|c| self.shard_of(c))
                .chain(shard)
            {
                match r {
                    None => r = Some(s),
                    Some(x) if x != s => return Err(ObjError::CrossShard),
                    _ => {}
                }
            }
        }
        r.map(|s| self.local(s)).transpose()
    }

    // ------------------------------------------------------------------ writes

    /// Write `piece` (whole blocks of a payload still arriving for collection `cid`, filled memory nobody writes again)
    /// ahead on the collection's shard (adr 0477, `Shard::pre_write`). A txn of that shard whose data run starts at the
    /// piece's first byte claims it; `pre_release` returns an unclaimed one. `None` = not written ahead.
    pub fn pre_write(&mut self, cid: &CollT, piece: &Bytes) -> Option<PreTicket> {
        let si = self.local(self.shard_of(cid)).ok()?;
        let id = self.shards[si].sh.pre_write(piece)?;
        self.activate(si);
        Some(PreTicket { si: si as u32, id })
    }

    /// Size of a pre-write piece: one data run (`MAX_RUN` blocks, fewer under the device transfer limit). A txn stages
    /// a block-aligned payload in runs of this size from its first whole block, so pieces cut the same way from the
    /// same start are claimed whole. Every shard of a store sits on the same device kind; the smallest one counts.
    pub fn pre_piece(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.sh.pre_piece())
            .min()
            .unwrap_or(PRE_PIECE)
    }

    /// Pieces of every shard that stopped being open so far: while it stands, every open ticket stays open.
    pub fn pre_closed(&self) -> u64 {
        self.shards.iter().map(|s| s.sh.pre_closed()).sum()
    }

    /// The piece of `t` is still open ([`Shard::pre_open`]): its ticket still matters.
    pub fn pre_open(&self, t: PreTicket) -> bool {
        self.shards
            .get(t.si as usize)
            .is_some_and(|s| s.sh.pre_open(t.id))
    }

    /// The payload of a pre-written piece will not be staged (frame failed or gone): release it if unclaimed.
    pub fn pre_release(&mut self, t: PreTicket) {
        if let Some(s) = self.shards.get_mut(t.si as usize) {
            s.sh.pre_release(t.id);
        }
    }

    /// Nonblocking apply. Pending has no tree/WAL effect; its token completes only through poll/errors.
    pub fn queue(&mut self, t: &OTxn, token: u64) -> Result<Queued> {
        self.enqueue::<fn() -> Box<dyn QueueBuilder<D, C>>>(t, token, None)
    }

    pub fn queue_with_builder<F: FnOnce() -> Box<dyn QueueBuilder<D, C>>>(
        &mut self,
        t: &OTxn,
        token: u64,
        make: F,
    ) -> Result<Queued> {
        self.enqueue(t, token, Some(make))
    }

    /// Adapter-owned input avoids copying borrowed wire payload when staging yields.
    fn enqueue<F: FnOnce() -> Box<dyn QueueBuilder<D, C>>>(
        &mut self,
        t: &OTxn,
        token: u64,
        make: Option<F>,
    ) -> Result<Queued> {
        let t0 = crate::diag::t0();
        let r = self.enqueue_inner(t, token, make);
        if let Some(t0) = t0 {
            crate::diag::note(38, t0.elapsed().as_nanos() as u64);
        }
        r
    }

    fn enqueue_inner<F: FnOnce() -> Box<dyn QueueBuilder<D, C>>>(
        &mut self,
        t: &OTxn,
        token: u64,
        make: Option<F>,
    ) -> Result<Queued> {
        let Some(si) = self.route(t)? else {
            self.shards[0].acked.push(token);
            self.activate(0);
            return Ok(Queued::Submitted(0));
        };
        if t.ops.iter().any(|o| {
            matches!(
                o,
                TOp::MkColl { .. }
                    | TOp::RmColl { .. }
                    | TOp::SetCollBits { .. }
                    | TOp::SetCollDvTrack { .. }
            )
        }) {
            self.drain_queued()?; // cold structural/feature barrier
        }
        self.dedup_gate(si, t)?;
        self.activate(si);

        let large = t
            .ops
            .iter()
            .filter_map(|o| match o {
                TOp::Write { data, .. } => Some(data.len()),
                _ => None,
            })
            .sum::<usize>()
            > 256 << 10;
        if !self.parked[si].is_empty() {
            crate::dbg::park_why(2);
        } else if large {
            crate::dbg::park_why(3);
        }
        let ready = if self.parked[si].is_empty() && !large {
            match self.prepare_txn(si, t, token, &[], false) {
                Ok(p) => Some(p),
                Err(ObjError::WouldBlock) => {
                    crate::dbg::park_why(0);
                    None
                }
                Err(e) => return Err(e),
            }
        } else {
            None
        };
        let ready = match ready {
            Some(p) => match self.submit_prepared(si, p) {
                Ok(lsn) => return Ok(Queued::Submitted(lsn)),
                Err((ObjError::WouldBlock, p)) => {
                    crate::dbg::park_why(1);
                    Some(p)
                }
                Err((e, p)) => {
                    self.unreserve(si, &p.txn);
                    return Err(e);
                }
            },
            None => None,
        };
        let builder = if ready.is_none() {
            make.map(|f| f())
        } else {
            None
        };
        let bytes = if ready.is_some() {
            0
        } else if let Some(b) = &builder {
            b.retained_bytes()
        } else {
            t.retained_bytes()
        };
        if !self.queue_room(si, bytes) {
            if self.parked[si].is_empty() {
                self.drop_preparation(si, token);
            }
            if let Some(p) = ready {
                self.unreserve(si, &p.txn);
            }
            return Err(ObjError::WouldBlock); // not accepted; admission must retain the input
        }
        let mut p = Parked {
            token,
            input: if ready.is_some() || builder.is_some() {
                None
            } else {
                Some(t.owned().shared(&[]))
            },
            ready,
            builder,
            objects: Vec::new(),
            oids: Vec::new(),
            colls: Vec::new(),
            bytes,
            tried: if self.parked[si].is_empty() && !large {
                Some(self.queue_progress(si))
            } else {
                None
            },
            deadline: self.clk.now().saturating_add(30_000_000_000),
            warmed: false,
            entries: 0,
            seq: self.parked[si].issue(),
            blocked: (0, "", ""),
            run_wait: None,
            stall: None,
        };
        p.names(t);
        p.entries = txn_entries(t);
        self.parks += 1;
        self.parked_bytes[si] += bytes;
        self.parked[si].push_back(p);
        Ok(Queued::Pending(token))
    }

    fn queue_room(&self, si: usize, bytes: usize) -> bool {
        self.parked[si].len() < self.queue_count
            && bytes <= self.queue_bytes.saturating_sub(self.parked_bytes[si])
    }

    /// Count/payload cap per shard; one prepared head is separately bounded by the same byte limit.
    pub fn set_queue_limits(&mut self, count: usize, bytes: usize) {
        assert!(self.parked.iter().all(ParkQ::is_empty));
        assert!(count > 0 && bytes > 0);
        self.queue_count = count;
        self.queue_bytes = bytes;
    }

    pub fn admission_ready(&self) -> bool {
        let headroom = self.admit_headroom();
        (0..self.shards.len()).all(|si| self.shard_admission_ready(si, headroom))
    }

    /// Headroom a queued txn is admitted against: a maximum frame plus metadata/continuation room (768 MiB at the
    /// default limit), capped at three quarters of the payload cap.
    fn admit_headroom(&self) -> usize {
        (768 << 20)
            .min(self.queue_bytes - self.queue_bytes / 4)
            .max(1)
    }

    /// Headroom for the collection's physical shard, including persisted placement overrides.
    pub fn admission_ready_for(&self, cid: &CollT) -> bool {
        let headroom = self.admit_headroom();
        self.local(self.shard_of(cid))
            .is_ok_and(|si| self.shard_admission_ready(si, headroom))
    }

    fn shard_admission_ready(&self, si: usize, headroom: usize) -> bool {
        self.parked[si].len() < self.queue_count.saturating_sub(8).max(1)
            && self.queue_room(si, headroom)
    }

    pub fn queued_count(&self) -> usize {
        self.parked.iter().map(ParkQ::len).sum()
    }

    /// Store-local background txn (adr 0593-dedup-deep-scrub-reformat): a reformat rewrite (`TOp::Reformat`, plus the txn's
    /// `comp`) or dedup records (`TOp::DedupKv`). Staged and submitted now or not at all, never parked (a parked txn's
    /// staging error would be fail-stop): `Ok(true)` = submitted (durable later, `token` is reported by `poll` like any
    /// txn); `Ok(false)` = not applied (the shard has parked txns, the object changed since it was read, the new layout
    /// would not be better, or it would wait: a page miss or a full queue/WAL never blocks the PG core, the loads it
    /// started serve the next try). Other errors are returned as they are and leave nothing staged.
    pub fn try_local(&mut self, t: &OTxn, token: u64) -> Result<bool> {
        debug_assert!(
            t.ops
                .iter()
                .all(|o| matches!(o, TOp::Reformat { .. } | TOp::DedupKv { .. }))
        );
        let Some(si) = self.route(t)? else {
            return Ok(false);
        };
        if !self.parked[si].is_empty() {
            return Ok(false);
        }
        self.activate(si);
        let run = |st: &mut Self| {
            let s = &mut st.shards[si];
            let old = std::mem::replace(&mut s.nonblock, true);
            let r = run_txn(s, &mut st.clk, t, token);
            st.shards[si].nonblock = old;
            r
        };
        let mut r = run(self);
        if matches!(r, Ok(None)) {
            // the first compressed chunk of this store: make the bit durable (a blocking store op), then stage again
            self.enable_compression(si);
            r = run(self);
        }
        match r {
            Ok(Some(_)) => Ok(true),
            Ok(None) | Err(ObjError::Stale | ObjError::WouldBlock) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Layout of `[off, off + len)` of an object (adr 0593-dedup-deep-scrub-reformat): see [`super::SpanStats`].
    /// `Ok(None)`: no such object.
    pub fn span_stats(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        off: u64,
        len: u64,
    ) -> Result<Option<super::SpanStats>> {
        let (a, b) = (off / BLK as u64, (off + len).div_ceil(BLK as u64));
        self.stage_object(cid, oid, |st| match st.lookup(cid, oid)? {
            Some(id) => Ok(Some(st.span_stats(id, a, b)?)),
            None => Ok(None),
        })
    }

    pub fn shard_queued(&self, cid: &CollT) -> Result<bool> {
        Ok(!self.parked[self.local(self.shard_of(cid))?].is_empty())
    }

    pub fn queue_builder(
        &mut self,
        colls: &[CollT],
        token: u64,
        builder: Box<dyn QueueBuilder<D, C>>,
        attempted: bool,
    ) -> Result<Queued> {
        let c = colls
            .first()
            .ok_or_else(|| ObjError::Invalid("missing queue collection".into()))?;
        let si = self.local(self.shard_of(c))?;
        if colls
            .iter()
            .any(|c| self.shard_of(c) != self.shards[si].idx as usize)
        {
            return Err(ObjError::CrossShard);
        }
        let bytes = builder.retained_bytes();
        if !self.queue_room(si, bytes) {
            return Err(ObjError::WouldBlock);
        }
        let tried = if attempted {
            Some(self.queue_progress(si))
        } else {
            None
        };
        let deadline = self.clk.now().saturating_add(30_000_000_000);
        self.parks += 1;
        self.parked_bytes[si] += bytes;
        let seq = self.parked[si].issue();
        self.parked[si].push_back(Parked {
            token,
            seq,
            input: None,
            ready: None,
            builder: Some(builder),
            objects: Vec::new(),
            oids: Vec::new(),
            colls: colls.to_vec(),
            bytes,
            tried,
            deadline,
            warmed: false,
            entries: 16,
            blocked: (0, "", ""),
            run_wait: None,
            stall: None,
        });
        self.activate(si);
        Ok(Queued::Pending(token))
    }

    pub fn begin_nonblock(&mut self) -> (bool, bool) {
        let old = (self.nb_reads, self.blocked);
        self.nb_reads = true;
        self.blocked = false;
        old
    }

    pub fn end_nonblock(&mut self, old: (bool, bool)) {
        (self.nb_reads, self.blocked) = old;
    }

    fn begin_build(&mut self, si: usize, token: u64) -> QueueBuildContext {
        let session = self.shards[si].session_context();
        self.shards[si].read_session(Some((BUILD_SESSION, token)), true);
        QueueBuildContext {
            si,
            session,
            reads: self.begin_nonblock(),
        }
    }

    pub fn begin_queue_build(&mut self, cid: &CollT, token: u64) -> Result<QueueBuildContext> {
        let si = self.local(self.shard_of(cid))?;
        Ok(self.begin_build(si, token))
    }

    pub fn end_queue_build(&mut self, old: QueueBuildContext, blocked: bool) {
        self.shards[old.si].read_session(None, blocked);
        self.shards[old.si].restore_session(old.session);
        self.end_nonblock(old.reads);
    }

    pub fn take_queue_errors(&mut self, out: &mut Vec<(u64, ObjError)>) {
        out.append(&mut self.queue_errors);
    }

    /// Before polling: `helpers` = helper cores take work, `credit` = how many have room for a job of this core now
    /// ([`crate::shard::Shard::compaction_helpers`]).
    pub fn compaction_helpers(&mut self, helpers: bool, credit: usize) {
        if !self.helper_capable {
            return;
        }
        for s in &mut self.shards {
            s.sh.compaction_helpers(helpers, credit);
        }
    }

    /// The next job for a helper core: omap LSM flush rounds of every shard first, then merge rounds and run
    /// compactions.
    pub fn take_compaction(&mut self) -> Option<crate::shard::HelperJob> {
        if !self.helper_capable {
            return None;
        }
        self.shards
            .iter_mut()
            .find_map(|s| s.sh.take_compaction(true))
            .or_else(|| {
                self.shards
                    .iter_mut()
                    .find_map(|s| s.sh.take_compaction(false))
            })
    }

    pub fn return_compaction(&mut self, job: crate::shard::HelperJob, publish: bool) -> bool {
        let Some(&si) = self.slot.get(job.id().shard as usize) else {
            return false;
        };
        if si == u32::MAX {
            return false;
        }
        let accepted = self.shards[si as usize].sh.return_compaction(job, publish);
        if accepted {
            self.activate(si as usize);
        }
        accepted
    }

    pub fn helpers_configured(&self) -> bool {
        self.helper_capable
    }

    /// Local helper execution statistics, not mutations of a remote shard's state.
    pub fn compaction_activity(&mut self, queued: usize, completed: bool) {
        self.helper_queued = queued;
        self.helper_served += u64::from(completed);
    }

    fn prepare_txn(
        &mut self,
        si: usize,
        t: &OTxn,
        token: u64,
        owners: &[bytes::Bytes],
        sliced: bool,
    ) -> Result<Prepared<D::Buf>> {
        self.queue_attempts += 1;
        self.prep_yielded[si] = false;
        let saved = self.prep[si].take();
        let s = &mut self.shards[si];
        s.comp_wanted = saved.as_ref().is_some_and(|p| p.wanted);
        s.nonblock = true;
        let old_session = s.session_context();
        s.read_session(Some((STAGE_SESSION, token)), true);
        s.sh.state_mut()
            .tree
            .dependencies
            .begin(token, self.clk.now());
        let r = if let Some(p) = saved {
            assert_eq!(p.token, token, "only the shard FIFO head owns preparation");
            let mut st = Stage::resume(s, &mut self.clk, p.parts);
            let r = st.finish_prepare(token, sliced.then_some(&mut self.prep_budget));
            self.prep_yielded[si] = st.cpu_yield;
            if matches!(r, Err(ObjError::WouldBlock)) {
                let wanted = st.s.comp_wanted;
                self.prep[si] = Some(Preparation {
                    token,
                    wanted,
                    parts: st.into_parts(),
                });
            } else {
                if r.is_err() {
                    st.discard_data();
                }
            }
            r
        } else {
            let mut st = Stage::new(s, &mut self.clk);
            let r = st
                .apply(t)
                .and_then(|()| st.finish_prepare(token, sliced.then_some(&mut self.prep_budget)));
            self.prep_yielded[si] = st.cpu_yield;
            if matches!(r, Err(ObjError::WouldBlock)) && st.discovered() {
                let wanted = st.s.comp_wanted;
                self.prep[si] = Some(Preparation {
                    token,
                    wanted,
                    parts: st.into_parts().retain(owners),
                });
            } else {
                if r.is_err() {
                    st.discard_data();
                }
            }
            r
        };
        s.sh.state_mut()
            .tree
            .dependencies
            .finish(matches!(r, Err(ObjError::WouldBlock)));
        s.nonblock = false;
        s.read_session(None, matches!(r, Err(ObjError::WouldBlock)));
        s.restore_session(old_session);
        let Built {
            txn,
            needs_compression,
        } = r?;
        if needs_compression {
            // The FIFO head is a feature barrier: all earlier entries are applied; later entries stay fenced.
            self.unreserve(si, &txn);
            if !self.shards[si].compression {
                self.enable_compression(si);
            }
            return self.prepare_txn(si, t, token, owners, sliced);
        }
        let bytes: usize = txn.data.iter().map(|(_, b)| b.len()).sum::<usize>()
            + txn.copies.iter().map(|c| c.src.len()).sum::<usize>()
            + txn
                .ops
                .iter()
                .map(|o| match o {
                    crate::state::Op::Put(k, v) => k.len() + v.len(),
                    crate::state::Op::Del(k) => k.len(),
                    crate::state::Op::DelRange(k, v) => k.len() + v.len(),
                    crate::state::Op::RunPut(r) => r.raw().len(),
                    crate::state::Op::RunMerge { a, b, .. } => a.len() + b.len(),
                    crate::state::Op::Omap(o) => o.wal_bytes(),
                })
                .sum::<usize>();
        if bytes > self.queue_bytes {
            self.unreserve(si, &txn);
            return Err(ObjError::NoSpace);
        }
        Ok(Prepared { txn, ids: None })
    }

    fn drop_preparation(&mut self, si: usize, token: u64) {
        self.shards[si]
            .sh
            .state_mut()
            .tree
            .dependencies
            .clear(token);
        // Every path that gives a token's staging up comes here: no later transaction may continue its enumerations.
        self.shards[si].range_memo_release((STAGE_SESSION, token));
        if let Some(p) = self.prep[si].take() {
            assert_eq!(p.token, token);
            for (b, buf) in p.parts.data {
                self.shards[si].sh.unreserve(b, (buf.len() / BLK) as u32);
            }
            for c in p.parts.pre {
                self.shards[si].sh.pre_unclaim(c.id);
            }
        }
    }

    fn unreserve(&mut self, si: usize, t: &Txn<D::Buf>) {
        self.shards[si].sh.unreserve_txn(t);
    }

    #[allow(clippy::result_large_err)]
    fn submit_prepared(
        &mut self,
        si: usize,
        p: Prepared<D::Buf>,
    ) -> std::result::Result<u64, (ObjError, Prepared<D::Buf>)> {
        self.queue_attempts += 1;
        let Prepared { txn, mut ids } = p;
        let s = &mut self.shards[si];
        // Forgetting a cache entry before a rejected submit is harmless; it cannot free/reuse media.
        s.sh.state_mut()
            .tree
            .dependencies
            .begin(txn.token, self.clk.now());
        s.forget_freed(&txn.frees);
        let tails = s.tail_blocks(&txn);
        let submitted = s.sh.submit(txn);
        s.sh.state_mut()
            .tree
            .dependencies
            .finish(matches!(&submitted, Err((StoreError::Miss, _))));
        match submitted {
            Ok(lsn) => {
                s.cache_tails(tails);
                if let Some(ids) = ids {
                    for id in ids {
                        s.note_write(id, lsn);
                    }
                } else {
                    for i in 0..s.scratch.ids.len() {
                        let id = s.scratch.ids[i];
                        s.note_write(id, lsn);
                    }
                }
                s.stats.txns += 1;
                Ok(lsn)
            }
            Err((e, txn)) => {
                if ids.is_none() {
                    ids = Some(s.scratch.ids.clone());
                }
                Err((
                    match e {
                        StoreError::Miss | StoreError::Busy | StoreError::WalFull => {
                            ObjError::WouldBlock
                        }
                        e => e.into(),
                    },
                    Prepared { txn, ids },
                ))
            }
        }
    }

    /// Progress a parked head waits for (it is retried when this changes): IO completions, frees, releases, pool answers,
    /// compactions swapped in, and run memory released anywhere in the device's run pool (run room is the pool's: the
    /// members on other cores free it without any IO of this shard; without it a batch parked on run room waited for
    /// this shard's next timed checkpoint, doc/perf/omap-combo-stall-20261030.md).
    fn queue_progress(&self, si: usize) -> (u64, u64, u64) {
        let s = &self.shards[si];
        (
            s.sh.stats.io_completions,
            s.sh.state().alloc.n_free(),
            s.released + s.sh.lend_epoch() + s.sh.stats.run_compactions + s.sh.run_freed(),
        )
    }

    /// Progress that renews a parked head's stall clock (`resume_queue`): of the head itself (where it stops, its own
    /// device reads, the tree pages it waits for; CPU-sliced preparation is counted by the caller, its tracked page loads
    /// by `Dependencies`) or of store state a head waits for (durable LSN, free blocks, run memory). Reads of other
    /// requests and their releases are not: no head waits for them, and counting them kept the deadline of a head that
    /// waited on them in the future forever.
    fn head_progress(&self, si: usize, phase: &'static str) -> HeadProgress {
        let s = &self.shards[si];
        HeadProgress {
            at: (phase, s.wb_why),
            n: [
                s.head_reads,
                if s.wb_why == TREE_MISS {
                    s.pages_loaded
                } else {
                    0
                },
                s.sh.durable_lsn(),
                s.sh.state().alloc.n_free(),
                s.sh.lend_epoch() + s.sh.stats.run_compactions + s.sh.run_freed(),
            ],
        }
    }

    /// Fail a parked head that is stuck: no progress of its own for `STALL_NS` after it was tried again. Its token
    /// gets the error; nothing of it was applied.
    fn fail_stuck(&mut self, si: usize, p: Parked<D, C>) -> ObjError {
        self.drop_preparation(si, p.token);
        if let Some(ready) = p.ready {
            self.unreserve(si, &ready.txn);
        }
        for namespace in [STAGE_SESSION, BUILD_SESSION] {
            let s = &mut self.shards[si];
            let old = s.session_context();
            s.read_session(Some((namespace, p.token)), true);
            s.read_session(None, false);
            s.restore_session(old);
        }
        self.parked_bytes[si] -= p.bytes;
        eprintln!(
            "WARNING TIMEOUT store parked transaction exceeded {}s (shard {si}, token {}, {} bytes, {} blocked tries, \
             last at {}:{})",
            STALL_NS / 1_000_000_000,
            p.token,
            p.bytes,
            p.blocked.0,
            p.blocked.1,
            p.blocked.2
        );
        let e = ObjError::Eio("parked transaction timed out".into());
        self.queue_errors.push((p.token, e.clone()));
        self.woke = true;
        e
    }

    /// Parked-txn lookahead (adr 0021 am. 44): submit the page loads of the objects (`Stage::warm`) of the txns behind the FIFO head (once each).
    /// Reads only: nothing is staged, the order and the visibility fence stay as they are.
    fn lookahead(&mut self, si: usize) {
        let n = self.shards[si].sh.park_lookahead();
        if n == 0 || self.parked[si].len() < 2 {
            return;
        }
        let s = &mut self.shards[si];
        let old = s.nonblock;
        s.nonblock = true;
        for p in self.parked[si].q.iter_mut().skip(1).take(n) {
            if std::mem::replace(&mut p.warmed, true) {
                continue;
            }
            for (c, o) in &p.oids {
                let r = Stage::new(s, &mut self.clk).warm(c, o, 0, 0);
                if matches!(r, Err(ObjError::WouldBlock)) {
                    self.lookahead_loads += 1;
                    crate::dbg::rq(6);
                }
            }
        }
        s.nonblock = old;
    }

    fn resume_queue(&mut self, si: usize) -> Result<()> {
        let start = self.clk.now();
        crate::dbg::rq(4);
        for round in 0..8 {
            if round == 7 {
                crate::dbg::rq(5);
            }
            if round > 0 && self.clk.now().saturating_sub(start) >= 100_000 {
                break;
            }
            let io = self.queue_progress(si);
            let now = self.clk.now();
            if let Some(p) = self.parked[si].q.front_mut()
                && now >= p.deadline
                && self.shards[si].sh.page_dma_waiting()
                && (p.blocked.2 == TREE_MISS
                    || !matches!(
                        self.shards[si]
                            .sh
                            .state()
                            .tree
                            .dependencies
                            .readiness(p.token),
                        crate::dependencies::Readiness::Untracked
                    ))
            {
                eprintln!(
                    "WARNING TIMEOUT store parked transaction exceeded {}s (shard {si}, token {}, \
                     page DMA memory refused, page unsent; still waiting)",
                    STALL_NS / 1_000_000_000,
                    p.token
                );
                // A page that was never submitted cannot time out as a device request. Keep the
                // immutable input and retry it after memory returns; submitted IO retains its timeout.
                self.shards[si]
                    .sh
                    .state_mut()
                    .tree
                    .dependencies
                    .clear(p.token);
                p.deadline = now.saturating_add(STALL_NS);
                p.stall = None;
                p.tried = None;
            }
            // IO has already been pumped. Only the owning head's exact missing
            // pages gate preparation; unrelated progress cannot renew its stall.
            if let Some(p) = self.parked[si].q.front_mut() {
                match self.shards[si]
                    .sh
                    .state()
                    .tree
                    .dependencies
                    .readiness(p.token)
                {
                    crate::dependencies::Readiness::Untracked => {}
                    crate::dependencies::Readiness::Waiting(deadline) => {
                        p.deadline = deadline;
                        p.tried = Some(io);
                    }
                    crate::dependencies::Readiness::Retry(deadline) => {
                        p.deadline = deadline;
                        p.tried = if now >= deadline
                            && !self.shards[si]
                                .sh
                                .state()
                                .tree
                                .dependencies
                                .final_retry_available()
                        {
                            Some(io)
                        } else {
                            None
                        };
                    }
                }
            }
            // Stuck = `STALL_NS` without progress of the head's own ([`Store::head_progress`], its tracked pages):
            // a head that has not been tried since the last store progress is tried first (below: a try that still
            // finds no progress of its own after the deadline fails it). A process that was stopped (SIGSTOP, a VM
            // pause) finds its IO completed on resume: wall time alone is not a stuck store.
            if let Some(p) =
                self.parked[si].pop_front_if(|p| p.tried == Some(io) && now >= p.deadline)
            {
                return Err(self.fail_stuck(si, p));
            }
            if self.parked[si].front().is_none_or(|p| p.tried == Some(io)) {
                if !self.parked[si].is_empty() {
                    crate::dbg::rq(0);
                }
                break;
            }
            if !self.prep_budget.visit() {
                crate::dbg::rq(5);
                break;
            }
            let mut p = self.parked[si].pop_front().unwrap();
            self.shards[si]
                .sh
                .state_mut()
                .tree
                .dependencies
                .retry_started(p.token, now);
            p.tried = Some(io);
            self.shards[si].wb_why = "";
            self.shards[si].wb_run = None;
            let mut phase = "submit";
            let r = match p.ready.take() {
                Some(ready) => Ok(ready),
                None if !self.shards[si].barrier
                    && p.run_wait.is_some_and(|(id, bytes)| {
                        self.shards[si].sh.run_admit_blocks(id, bytes)
                    }) =>
                {
                    // Still no run room: the try would stop at the same admission after re-preparing the whole batch.
                    // A blocking barrier is the exception: `Stage::run_admit` does not wait for room then (nothing else
                    // runs on the core), so the head is prepared again and takes the tree path.
                    (phase, self.shards[si].wb_why, self.shards[si].wb_run) =
                        (p.blocked.1, p.blocked.2, p.run_wait);
                    Err(ObjError::WouldBlock)
                }
                None => {
                    let mut build_error = None;
                    phase = "prepare";
                    if p.input.is_none() {
                        phase = "build";
                        let mut builder = p
                            .builder
                            .take()
                            .expect("queued input has a builder or immutable plan");
                        let owners = super::budget::payload_owners(builder.payload_owners());
                        let scope = self.begin_build(si, p.token);
                        self.preparing = Some(scope);
                        let built = builder.build(self);
                        let old = self.preparing.take().unwrap();
                        self.end_queue_build(old, matches!(built, Err(ObjError::WouldBlock)));
                        match built {
                            Ok(Some(t)) => {
                                p.names(&t);
                                p.entries = txn_entries(&t);
                                p.input = Some(t.shared(&owners));
                            }
                            Ok(None) => {
                                // A queued no-op still waits behind the durable prefix. Otherwise its
                                // completion could overtake the writes whose visibility it depended on.
                                let sh = &self.shards[si].sh;
                                if sh.durable_lsn() < sh.next_lsn() - 1 {
                                    p.builder = Some(builder);
                                    self.parked[si].push_front(p);
                                    break;
                                }
                                self.shards[si].acked.push(p.token);
                                self.parked_bytes[si] -= p.bytes;
                                self.woke = true;
                                continue;
                            }
                            Err(e) => {
                                build_error = Some(e);
                                p.builder = Some(builder);
                            }
                        }
                    }
                    let r = if let Some(e) = build_error {
                        Err(e)
                    } else {
                        phase = "prepare";
                        let t = p.input.as_ref().unwrap();
                        let owners = if self.prep[si].is_none() {
                            super::budget::payload_owners(t.payload_owners())
                        } else {
                            Vec::new()
                        };
                        self.prepare_txn(si, t, p.token, &owners, true)
                    };
                    if r.is_ok() {
                        p.input = None;
                        self.parked_bytes[si] -= p.bytes;
                        p.bytes = 0;
                    }
                    r
                }
            };
            if matches!(r, Err(ObjError::WouldBlock)) {
                crate::dbg::rq(1);
            }
            if r.is_ok() {
                phase = "submit";
            }
            let r = match r {
                Ok(ready) => match self.submit_prepared(si, ready) {
                    Ok(_) => {
                        crate::dbg::rq(3);
                        Ok(())
                    }
                    Err((e, ready)) => {
                        crate::dbg::rq(2);
                        p.ready = Some(ready);
                        Err(e)
                    }
                },
                Err(e) => Err(e),
            };
            p.tried = if self.prep_yielded[si] {
                self.woke = true;
                None
            } else {
                Some(self.queue_progress(si))
            };
            // The stall clock runs from the head's first blocked try and restarts only on its own progress: unrelated
            // store progress retries it (`tried`) but never postpones its deadline.
            let own = self.head_progress(si, phase);
            if self.prep_yielded[si] || p.stall.is_none_or(|(_, o)| o != own) {
                p.stall = Some((now, own));
            }
            let since = p.stall.map_or(now, |(t, _)| t);
            let untracked = match self.shards[si]
                .sh
                .state()
                .tree
                .dependencies
                .readiness(p.token)
            {
                crate::dependencies::Readiness::Untracked => {
                    p.deadline = since.saturating_add(STALL_NS);
                    true
                }
                crate::dependencies::Readiness::Waiting(d)
                | crate::dependencies::Readiness::Retry(d) => {
                    p.deadline = d;
                    false
                }
            };
            match r {
                Err(ObjError::WouldBlock) => {
                    p.blocked = (p.blocked.0 + 1, phase, self.shards[si].wb_why);
                    p.run_wait = self.shards[si].wb_run.take();
                    if untracked && now >= p.deadline {
                        return Err(self.fail_stuck(si, p));
                    }
                    self.parked[si].push_front(p);
                    break;
                }
                Err(e) => {
                    self.drop_preparation(si, p.token);
                    if let Some(ready) = &p.ready {
                        self.unreserve(si, &ready.txn);
                    }
                    self.queue_errors.push((p.token, e.clone()));
                    self.parked_bytes[si] -= p.bytes;
                    self.woke = true;
                    // Report before applying another queued txn. A caller can poll again to continue;
                    // the PG adapter fail-stops, preserving its already-logged in-memory prefix (ADR 0066).
                    return Err(e);
                }
                Ok(()) => {}
            }
            self.parked_bytes[si] -= p.bytes;
            self.woke = true;
        }
        Ok(())
    }

    /// Offline/cold barriers only. Acks stay on each shard for the next normal poll.
    pub fn drain_queued(&mut self) -> Result<()> {
        if self.queued_count() == 0 {
            return Ok(());
        }
        #[cfg(feature = "splinterdb")]
        if self.shards.iter().any(|s| s.sh.splinter_selected())
            && (self.preparing.is_some() || self.shards.iter().any(|s| s.barrier))
        {
            return Err(ObjError::Invalid(
                "recursive queue drain during preparation".into(),
            ));
        }
        let t0 = self.clk.now();
        for (si, s) in self.shards.iter_mut().enumerate() {
            s.barrier = true;
            #[cfg(feature = "splinterdb")]
            if s.sh.splinter_selected() {
                s.sh.splinter_begin_barrier_read();
                if let Some(head) = self.parked[si].q.front_mut() {
                    // One policy-transition retry, not fake IO/stall progress.
                    // resume_queue still honors every tracked page dependency.
                    head.tried = None;
                }
            }
            #[cfg(not(feature = "splinterdb"))]
            let _ = si;
        }
        let r = self.drain_queued_here();
        for s in &mut self.shards {
            #[cfg(feature = "splinterdb")]
            s.sh.splinter_end_barrier_read();
            s.barrier = false;
        }
        self.barriers += 1;
        self.barrier_ns += self.clk.now().saturating_sub(t0);
        r
    }

    fn drain_queued_here(&mut self) -> Result<()> {
        // 30 s without a queued txn finishing (as the parked head, `resume_queue`: a stopped process is not a stuck store)
        let mut deadline = self.clk.now().saturating_add(30_000_000_000);
        let mut left = self.queued_count();
        let mut dma_submits: u64 = self.shards.iter().map(|s| s.sh.page_dma_submits()).sum();
        while self.queued_count() > 0 {
            let mut acked = Vec::new();
            let result = self.poll(&mut acked);
            // Tokens route to their shard; don't consume them while servicing a barrier.
            self.shards[0].acked.extend(acked);
            if !self.shards[0].acked.is_empty() {
                self.activate(0);
            }
            result?;
            let now = self.clk.now();
            let submitted: u64 = self.shards.iter().map(|s| s.sh.page_dma_submits()).sum();
            if self.queued_count() < left || submitted != dma_submits {
                left = self.queued_count();
                dma_submits = submitted;
                deadline = now.saturating_add(30_000_000_000);
            }
            if now >= deadline {
                eprintln!(
                    "WARNING TIMEOUT store queue barrier exceeded 30s ({} txns still queued)",
                    self.queued_count()
                );
                if self
                    .shards
                    .iter()
                    .enumerate()
                    .all(|(si, s)| self.parked[si].is_empty() || s.sh.page_dma_waiting())
                {
                    deadline = now.saturating_add(STALL_NS);
                } else {
                    return Err(ObjError::Invalid("queue barrier timed out".into()));
                }
            }
            self.idle();
        }
        Ok(())
    }

    /// Stage and submit `t`; returns its LSN. The txn is visible to reads immediately and durable when `token`
    /// shows up in `poll`. Atomic: on error nothing was applied.
    pub fn queue_blocking(&mut self, t: &OTxn, token: u64) -> Result<u64> {
        self.drain_queued()?;
        let _s = wprof::span(wprof::S::StoreStage);
        match self.route(t)? {
            None => {
                self.shards[0].acked.push(token);
                Ok(0)
            }
            Some(si) => {
                self.dedup_gate(si, t)?;
                self.activate(si);
                let r = run_txn(&mut self.shards[si], &mut self.clk, t, token);
                #[cfg(feature = "elastic")]
                let mut r = r;
                // elastic pool (adr 0021 am. 52): the gate wanted a chunk: take it synchronously, ENOSPC only when the pool is dry
                #[cfg(feature = "elastic")]
                while matches!(r, Err(ObjError::NoSpace)) && self.lend_sync(si)? {
                    r = run_txn(&mut self.shards[si], &mut self.clk, t, token);
                }
                if let Some(lsn) = r? {
                    return Ok(lsn);
                }
                self.enable_compression(si);
                run_txn(&mut self.shards[si], &mut self.clk, t, token)?
                    .ok_or_else(|| ObjError::Invalid("feature gate".into()))
            }
        }
    }

    /// Lending table of a chunked store (adr 0021 am. 49).
    #[cfg(feature = "elastic")]
    pub fn lending(&self) -> Option<&crate::lend::Lending> {
        self.lend.as_ref()
    }

    /// Borrowed chunks of mounted shard `shard` by slot: `(engine block or alloc::HOLE, busy blocks)` (blocks a deallocate
    /// holds count free, [`Shard::lent_slot`]).
    #[cfg(feature = "elastic")]
    pub fn lent_chunks(&self, shard: u32) -> Result<Vec<(u64, u64)>> {
        let sh = &self.shards[self.local(shard as usize)?].sh;
        Ok((0..sh.state().alloc.lent_slots() as u32)
            .map(|k| sh.lent_slot(k))
            .collect())
    }

    /// Write one staged lending-table change through the queue of local shard `i` (drained first: the blocking write
    /// must not consume the shard's own completions). Durable on completion (PLP, adr 0008).
    #[cfg(feature = "elastic")]
    fn lend_write(&mut self, i: usize, s: &crate::lend::Staged) -> Result<()> {
        let sh = &mut self.shards[i];
        sh.wait(&mut self.clk, |s| {
            let d = s.sh.dev();
            d.queue_space() == d.queue_depth()
        })?;
        crate::sio::Sio::new(sh.sh.dev(), &mut self.clk).write_one(s.addr, &s.buf)?;
        Ok(())
    }

    /// Grant a pool chunk to mounted shard `shard` (adr 0021 am. 49): pick (grant order), write the table entry, and only
    /// after it is durable add the chunk to the shard's allocator (behind its base: used once the base is full).
    /// `Ok(None)` = the pool is exhausted. Store level, blocking (step 2; the cross-core request path is step 3).
    #[cfg(feature = "elastic")]
    pub fn grant_chunk(&mut self, shard: u32) -> Result<Option<u64>> {
        let i = self.local(shard as usize)?;
        // async table writes first (one writer per table block; a grant in flight for this shard is answered)
        self.pool_drain()?;
        let Some(l) = self.lend.as_mut() else {
            return Err(ObjError::Invalid("not a chunked store".into()));
        };
        let Some(p) = l.pick(shard) else {
            return Ok(None);
        };
        let slot = l.free_slot(shard);
        let st = l.stage(
            p,
            crate::lend::Entry {
                owner: shard as u16,
                slot,
            },
        );
        let r = self.lend_write(i, &st);
        let l = self.lend.as_mut().unwrap();
        match r {
            Ok(()) => {
                l.commit(&st);
                let phys = l.geom.phys(p);
                self.shards[i].sh.lend_add(slot, phys);
                Ok(Some(phys))
            }
            Err(e) => {
                // the device may hold either generation: memory keeps the chunk free and unused by the shard; a later
                // write of the block carries the in-memory entry, a remount takes what is on disk (owned but empty, or free); no
                // grant until then: another block could get the same slot of this shard (`Lending::fail`)
                l.fail(&st);
                Err(e)
            }
        }
    }

    /// Return borrowed chunk `phys` of mounted shard `shard` to the pool (adr 0021 am. 49). Only an unused chunk: no
    /// block allocated, reserved or held (held blocks wait for a checkpoint: `Ok(false)`, retry after one). The shard
    /// stops using it first, then the free entry is written; a crash before that write is durable leaves it owned
    /// (and empty) by the shard.
    #[cfg(feature = "elastic")]
    pub fn return_chunk(&mut self, shard: u32, phys: u64) -> Result<bool> {
        let i = self.local(shard as usize)?;
        self.pool_drain()?;
        let Some(l) = self.lend.as_mut() else {
            return Err(ObjError::Invalid("not a chunked store".into()));
        };
        let p = l
            .geom
            .index_of(phys)
            .ok_or_else(|| ObjError::Invalid(format!("block {phys} is no pool chunk")))?;
        let e = l.entry(p);
        if e.owner as u32 != shard {
            return Err(ObjError::Invalid(format!(
                "chunk {phys} is not lent to shard {shard}"
            )));
        }
        // the queue first: in-flight IO lands before the chunk can change hands (a deallocate holds its blocks, so
        // `lend_remove` would refuse the chunk anyway)
        let sh = &mut self.shards[i];
        sh.wait(&mut self.clk, |s| {
            let d = s.sh.dev();
            d.queue_space() == d.queue_depth()
        })?;
        if !self.shards[i].sh.lend_remove(e.slot) {
            return Ok(false);
        }
        let l = self.lend.as_mut().unwrap();
        let st = l.stage(p, crate::lend::Entry::FREE);
        let r = self.lend_write(i, &st);
        let l = self.lend.as_mut().unwrap();
        match r {
            Ok(()) => {
                l.commit(&st);
                Ok(true)
            }
            Err(e) => {
                // memory keeps it lent to the shard (a hole there, never re-granted until returned again): safe for
                // either generation on disk
                l.fail(&st);
                Err(e)
            }
        }
    }

    /// Pool owner of this store (adr 0021 am. 52)?
    #[cfg(feature = "elastic")]
    pub fn is_pool_owner(&self) -> bool {
        self.pool.is_some()
    }

    /// The elastic pool is in use by the shards of this store (`lend_auto` on a chunked store).
    #[cfg(feature = "elastic")]
    pub fn lend_active(&self) -> bool {
        self.lend_on
    }

    /// Pool requests waiting or table writes in flight (owner).
    #[cfg(feature = "elastic")]
    pub fn lend_busy(&self) -> bool {
        self.pool.as_ref().is_some_and(|p| p.busy())
    }

    /// Messages for other cores (requests to the pool owner, replies to the cores of the borrowing shards).
    #[cfg(feature = "elastic")]
    pub fn take_lend_out(&mut self, out: &mut Vec<crate::lend::LendMsg>) {
        out.append(&mut self.lend_out);
    }

    /// A pool message from another core: a request (owner only) or the owner's answer for a shard of this store.
    #[cfg(feature = "elastic")]
    pub fn lend_in(&mut self, m: crate::lend::LendMsg) {
        use crate::lend::LendMsg as M;
        let now = self.clk.now();
        match m {
            M::Request { shard, short } => match self.pool.as_mut() {
                Some(p) => p.request(shard, short),
                // misrouted (no pool here): an answer, else the borrower waits forever with its txns parked
                None => self.lend_out.push(M::Deny { shard, pool: 0 }),
            },
            M::Return { shard, slot, phys } => {
                // misrouted (no pool here): the chunk stays lent to the shard (a hole there) until the next mount; safe
                if let (Some(l), Some(p)) = (self.lend.as_ref(), self.pool.as_mut()) {
                    p.give_back(l, shard, slot, phys);
                }
            }
            // misrouted (no pool here): dropped, the owner keeps its last view of that shard
            M::Spare {
                shard,
                chunks,
                prog,
            } => {
                if let Some(p) = self.pool.as_mut() {
                    p.spare(shard, chunks, prog);
                }
            }
            M::Size {
                shard,
                pool,
                spare,
                target,
                prog,
            } => {
                let Ok(i) = self.local(shard as usize) else {
                    self.lend_out.push(m);
                    return;
                };
                for s in self.shards.iter_mut() {
                    s.sh.lend.pool = pool;
                }
                self.lend_view(i, spare, target, prog);
            }
            M::Grant { .. } | M::Deny { .. } | M::Grew { .. } => self.lend_answer(m, now),
        }
    }

    /// The owner's view of local shard `i` (am. 82): a raised return target starts its reclaim check at once; more
    /// lendable space wakes writes held for room.
    #[cfg(feature = "elastic")]
    fn lend_view(&mut self, i: usize, spare: u64, target: u64, prog: u64) {
        let before = self.shards[i].sh.lend.lendable();
        if self.shards[i].sh.lend.view(spare, target, prog) {
            self.shards[i].reclaim_kick();
        }
        self.woke |= self.shards[i].sh.lend.lendable() > before;
        self.activate(i);
    }

    /// Pool owner (adr 0021 am. 72): every shard of the device learns the true free pool size, once after mount and
    /// after every change of it (durable grant or return, synchronous or pumped): its own shards here, the others by a
    /// `Size` to their core (O(shards) messages per change, none per op). The hint is what a shard counts as lendable
    /// (`Ctl::lendable`): its fullness (`Statfs::pooled_fill_ratio`) and room checks. Without it a shard that never asked
    /// kept the mount placeholder and read its base as everything it could get (one shard at its base drove the whole
    /// OSD full at a quarter of the device).
    /// Since am. 82 the `Size` also carries the owner's view of each shard (`Pool::view`): spare of the others, return
    /// target, progress for a waiter; sent per shard when its view changed.
    #[cfg(feature = "elastic")]
    fn pool_announce(&mut self) {
        let (Some(l), Some(p)) = (self.lend.as_ref(), self.pool.as_ref()) else {
            return;
        };
        let pool = l.free_chunks() * l.geom.chunk;
        if self.pool_said == Some((pool, p.rev())) {
            return;
        }
        self.pool_said = Some((pool, p.rev()));
        let (chunk, nshards) = (l.geom.chunk, l.geom.data_start.len());
        for s in self.shards.iter_mut() {
            s.sh.lend.pool = pool;
        }
        self.shard_said.resize(nshards, None);
        for shard in 0..nshards {
            let Some(p) = self.pool.as_ref() else {
                return;
            };
            let (spare, target, prog) = p.view(shard as u32, chunk);
            let said = Some((pool, spare, target, prog));
            if self.shard_said[shard] == said {
                continue;
            }
            self.shard_said[shard] = said;
            match self.local(shard) {
                Ok(i) => self.lend_view(i, spare, target, prog),
                Err(_) => self.lend_out.push(crate::lend::LendMsg::Size {
                    shard: shard as u32,
                    pool,
                    spare,
                    target,
                    prog,
                }),
            }
        }
    }

    /// Apply an answer to its shard here, or hand it on (owner answering a shard of another core).
    #[cfg(feature = "elastic")]
    fn lend_answer(&mut self, m: crate::lend::LendMsg, now: u64) {
        use crate::lend::LendMsg as M;
        if let M::Grew { shard, pool } = m {
            let Ok(i) = self.local(shard as usize) else {
                self.lend_out.push(m);
                return;
            };
            self.shards[i].sh.lend_grew(pool);
            for s in self.shards.iter_mut() {
                s.sh.lend.pool = pool;
            }
            self.woke = true;
            self.activate(i);
            return;
        }
        let (shard, grant, pool) = match m {
            M::Grant {
                shard,
                slot,
                phys,
                pool,
            } => (shard, Some((slot, phys)), pool),
            M::Deny { shard, pool } => (shard, None, pool),
            M::Request { .. }
            | M::Return { .. }
            | M::Grew { .. }
            | M::Size { .. }
            | M::Spare { .. } => return,
        };
        let Ok(i) = self.local(shard as usize) else {
            self.lend_out.push(m);
            return;
        };
        self.shards[i].sh.lend_answer(grant, pool, now);
        // every shard of this store learns the pool size, parked txns of this one retry
        for s in self.shards.iter_mut() {
            s.sh.lend.pool = pool;
        }
        self.woke = true;
        self.activate(i);
    }

    /// Pool round of a poll: the owner reaps / starts table writes, shards below their watermark (or stopped at the
    /// allocation gate) ask. Per poll: one flag check when nothing is wanted.
    #[cfg(feature = "elastic")]
    fn lend_poll(&mut self, now: u64) {
        let mut buf = std::mem::take(&mut self.lend_scratch);
        if let (Some(l), Some(p)) = (self.lend.as_mut(), self.pool.as_mut())
            && (p.busy() || p.waiting())
        {
            p.pump(l, now, &mut buf);
        }
        for k in 0..self.active.len() {
            let si = self.active[k];
            if let Some(short) = self.shards[si].sh.lend_wants(now) {
                let shard = self.shards[si].idx;
                match self.pool.as_mut() {
                    Some(p) => p.request(shard, short),
                    None => self
                        .lend_out
                        .push(crate::lend::LendMsg::Request { shard, short }),
                }
            }
        }
        if let (Some(l), Some(p)) = (self.lend.as_mut(), self.pool.as_mut())
            && (p.busy() || p.waiting())
        {
            // requests of the shards above were queued after the first pump: start their writes in the same poll
            p.pump(l, now, &mut buf);
        }
        for m in buf.drain(..) {
            self.lend_answer(m, now);
        }
        self.lend_scratch = buf;
        self.pool_announce();
    }

    /// Reclaim on demand (am. 82): what the shards could give back, and their evacuation progress, go to the pool owner
    /// (here, or as `Spare` to its core) when it changed.
    #[cfg(feature = "elastic")]
    fn spare_out(&mut self, now: u64) {
        for si in 0..self.shards.len() {
            let Some((chunks, prog)) = self.shards[si].spare_report(now) else {
                continue;
            };
            let shard = self.shards[si].idx;
            match self.pool.as_mut() {
                Some(p) => p.spare(shard, chunks, prog),
                None => self.lend_out.push(crate::lend::LendMsg::Spare {
                    shard,
                    chunks,
                    prog,
                }),
            }
        }
    }

    /// Reclaim (adr 0021 am. 57): slots the shards made holes go to the pool owner (here, or as `Return` to its core).
    #[cfg(feature = "elastic")]
    fn reclaim_out(&mut self) {
        for si in 0..self.shards.len() {
            let shard = self.shards[si].idx;
            for (slot, phys) in std::mem::take(&mut self.shards[si].df.returned) {
                match (self.lend.as_ref(), self.pool.as_mut()) {
                    (Some(l), Some(p)) => p.give_back(l, shard, slot, phys),
                    _ => self
                        .lend_out
                        .push(crate::lend::LendMsg::Return { shard, slot, phys }),
                }
            }
        }
    }

    /// Pool owner counters: durable returns, returns dropped as not matching the table.
    #[cfg(feature = "elastic")]
    pub fn pool_returns(&self) -> (u64, u64) {
        self.pool
            .as_ref()
            .map_or((0, 0), |p| (p.returns, p.bad_returns))
    }

    /// Pool owner counter: short requests that waited for a chunk given back on demand (am. 82).
    #[cfg(feature = "elastic")]
    pub fn pool_waits(&self) -> u64 {
        self.pool.as_ref().map_or(0, |p| p.waits)
    }

    /// Blocking: run the pool owner until no request waits and no table write is in flight (answers delivered: applied
    /// here or queued in `lend_out`). Before a synchronous grant/return: the table has one writer per block, and a
    /// grant staged by the pool holds a slot the synchronous one must not reuse.
    #[cfg(feature = "elastic")]
    fn pool_drain(&mut self) -> Result<()> {
        let deadline = self.clk.now().saturating_add(30_000_000_000);
        while self.pool.as_ref().is_some_and(|p| p.busy()) {
            let now = self.clk.now();
            if now >= deadline {
                eprintln!(
                    "WARNING TIMEOUT store elastic pool drain exceeded 30s (pool request still busy)"
                );
                return Err(ObjError::Invalid("pool drain timed out".into()));
            }
            let mut buf = std::mem::take(&mut self.lend_scratch);
            if let (Some(l), Some(p)) = (self.lend.as_mut(), self.pool.as_mut()) {
                p.pump(l, now, &mut buf);
            }
            for m in buf.drain(..) {
                self.lend_answer(m, now);
            }
            self.lend_scratch = buf;
            if self.pool.as_ref().is_some_and(|p| p.busy()) {
                self.idle();
            }
        }
        Ok(())
    }

    /// Blocking path: the txn of local shard `si` hit the allocation gate with the pool open: take a chunk now (step 2
    /// `grant_chunk`; only a store that owns the pool can). True = retry the txn.
    #[cfg(feature = "elastic")]
    fn lend_sync(&mut self, si: usize) -> Result<bool> {
        if self.lend.is_none() || !self.shards[si].sh.lend.want {
            return Ok(false);
        }
        // a request of this shard may be in flight on the pool (a poll sent it): its answer first, then retry the txn
        let e0 = self.shards[si].sh.lend.epoch;
        self.pool_drain()?;
        if self.shards[si].sh.lend.epoch != e0 {
            return Ok(true);
        }
        let shard = self.shards[si].idx;
        let g = self.grant_chunk(shard)?;
        if g.is_none()
            && let Some(p) = self.pool.as_mut()
        {
            p.note_denied(shard);
        }
        let pool = self
            .lend
            .as_ref()
            .map_or(0, |l| l.free_chunks() * l.geom.chunk);
        let now = self.clk.now();
        let s = &mut self.shards[si].sh;
        // grant_chunk already added the chunk to the shard: only the controller state is left
        s.lend.reply(g.is_some(), pool, now);
        Ok(g.is_some())
    }

    /// First compressed chunk of this store (adr 0059 am. 1): make `FEAT_COMPRESSION` durable before a txn that needs it is
    /// submitted. On failure the store keeps writing raw until the next mount.
    fn enable_compression(&mut self, si: usize) {
        if self
            .enable_feature(si, crate::layout::FEAT_COMPRESSION)
            .is_err()
        {
            self.shards[si].comp_off = true;
        }
    }

    /// First data version tracking of this store (adr 0593-dedup-deep-scrub-reformat): `FEAT_DEDUP` is made durable before
    /// the txn that switches tracking on, so no record that needs the bit exists without it.
    fn dedup_gate(&mut self, si: usize, t: &OTxn) -> Result<()> {
        if !self.shards[si].dedup
            && t.ops
                .iter()
                .any(|o| matches!(o, TOp::SetCollDvTrack { on: true, .. }))
        {
            self.enable_feature(si, crate::layout::FEAT_DEDUP)?;
        }
        Ok(())
    }

    /// Make the sticky feature `bit` durable (both superblock copies, copy 0 first, each durable on completion) and switch
    /// it on for every core's shard view. Cold, once per mount and core: the shard's queue is drained first so the blocking
    /// writes see no foreign completions.
    fn enable_feature(&mut self, si: usize, bit: u64) -> Result<()> {
        let mut sb = self.sb.clone();
        sb.features |= bit;
        let s = &mut self.shards[si];
        s.wait(&mut self.clk, |s| {
            let d = s.sh.dev();
            d.queue_space() == d.queue_depth()
        })
        .and_then(|()| Ok(crate::layout::heal_super(s.sh.dev(), &mut self.clk, &sb)?))?;
        self.sb = sb;
        for s in &mut self.shards {
            s.compression |= bit == crate::layout::FEAT_COMPRESSION;
            s.dedup |= bit == crate::layout::FEAT_DEDUP;
        }
        Ok(())
    }

    /// Longest omap key / attribute store key a txn may carry (longer = `NameTooLong`: the txn can never be applied).
    pub fn max_item_key(&self) -> usize {
        self.shards
            .first()
            .map_or(usize::MAX, |s| s.sh.max_key().saturating_sub(15))
    }

    /// Can the store name `oid` (name key within the tree key limit)? `false` = any txn touching it is refused.
    /// Does `oid` need the long-name index (its `N` key exceeds the tree key limit)? Then every replica must store it too.
    pub fn name_is_long(&self, oid: &Ghobject) -> bool {
        self.shards
            .first()
            .is_some_and(|s| name_key_of(0, oid).len() > s.sh.max_key())
    }

    pub fn name_fits(&self, oid: &Ghobject) -> bool {
        let Some(s) = self.shards.first() else {
            return true;
        };
        let mk = s.sh.max_key();
        name_key_of(0, oid).len() <= mk || s.long_names && long_key_of(0, oid).len() <= mk
    }

    /// Wire bytes of a client txn up to which [`Store::check_txn`] cannot refuse it for size (each op is >= 6 wire
    /// bytes and touches at most one tree page; the record is about its wire size).
    pub fn check_wire_floor(&self) -> usize {
        self.shards.first().map_or(0, |s| {
            let pages = s.sh.txn_page_budget() / 2;
            let ring = (s.sh.ring_bytes() / 16) as usize;
            pages.saturating_mul(6).min(ring)
        })
    }

    /// Payload bytes of a client txn up to which [`Store::check_txn`] cannot refuse it for size: payload goes to data
    /// extents (not the record), bounded by the unchecked-data cap and a WAL-ring fraction (tiny rings stay strict).
    pub fn check_data_floor(&self) -> usize {
        self.shards.first().map_or(0, |s| {
            MAX_UNCHECKED_DATA.min((s.sh.ring_bytes() / 16) as usize)
        })
    }

    /// Cheap size estimate of `t`: can it get anywhere near the limits [`Store::check_txn`] judges? `false` = no
    /// (ordinary client writes; no staging needed). Weights: one tree op per omap key / attr / fragment, payload bytes.
    pub fn txn_needs_check(&self, t: &OTxn) -> bool {
        let Ok(Some(si)) = self.route(t) else {
            return false;
        };
        let sh = &self.shards[si].sh;
        let (mut weight, mut rec, mut data) = (0usize, 0usize, 0usize);
        for op in &t.ops {
            match op {
                TOp::Clone { .. } | TOp::CloneRange { .. } => return true,
                TOp::OmapSetKeys { pairs, .. } => {
                    for (k, v) in pairs {
                        weight += 2 + v.len() / 1500;
                        rec += k.len() + v.len() + 8;
                    }
                }
                TOp::OmapSetRun { run, .. } => {
                    for (_, v) in run.view().iter() {
                        weight += 2 + v.len() / 1500;
                    }
                    rec += run.bytes();
                }
                TOp::OmapRmKeys { keys, .. } => {
                    weight += keys.len();
                    rec += keys.iter().map(|k| k.len() + 8).sum::<usize>();
                }
                TOp::SetAttrs { attrs, .. } => {
                    for (k, v) in attrs {
                        weight += 2 + v.len() / 1500;
                        rec += k.len() + v.len() + 8;
                    }
                }
                TOp::Write { data: d, .. } => {
                    weight += 1;
                    data += d.len();
                }
                _ => weight += 1,
            }
        }
        weight * 4 > sh.txn_page_budget()
            || rec as u64 * 8 > sh.ring_bytes()
            || data > MAX_UNCHECKED_DATA
    }

    /// Dry run of `queue`: would `t` be refused for its SIZE (record larger than the WAL ring allows, more distinct
    /// tree pages than half the per-txn budget)? Data extents never count (adr 0066: they go out in waves). `Err(TooLarge)` = yes,
    /// the txn can never be applied (and must not be logged or replicated); `Ok` = it fits (transient `Busy`/space
    /// conditions are not judged). Nothing is applied. Cold tree pages are loaded: blocking, or in non-blocking mode
    /// ([`Store::set_nonblock_reads`], the PG core) the miss submits the load and returns `WouldBlock` (`take_blocked`), the
    /// caller checks again after the wake (adr 0021 S8). The budget is halved so a replica whose tree is shaped differently
    /// still fits. For big txns only: callers gate on size; plans metadata and exact extent sizes without preparing device
    /// buffers.
    pub fn check_txn(&mut self, t: &OTxn) -> Result<()> {
        let Some(si) = self.route(t)? else {
            return Ok(());
        };
        if !self.parked[si].is_empty() {
            if self.nb_reads {
                self.blocked = true;
                self.shards[si].rm_progress = true;
                return Err(ObjError::WouldBlock);
            }
            self.drain_queued()?;
        }
        self.activate(si);
        let s = &mut self.shards[si];
        let old = s.nonblock;
        s.nonblock = old || self.nb_reads;
        let r = check_record(s, &mut self.clk, t);
        self.shards[si].nonblock = old;
        if matches!(r, Err(ObjError::WouldBlock)) {
            self.blocked = true;
        }
        r
    }

    fn activate(&mut self, si: usize) {
        if !self.is_active[si] {
            self.is_active[si] = true;
            let at = self.active.partition_point(|&x| x < si);
            self.active.insert(at, si);
        }
    }

    /// Reap completions of all shards; acked tokens are appended to `acked`.
    pub fn poll(&mut self, acked: &mut Vec<u64>) -> Result<()> {
        let t_all = crate::diag::on().then(std::time::Instant::now);
        let r = self.poll_inner(acked);
        if let Some(t) = t_all {
            crate::diag::note(5, t.elapsed().as_nanos() as u64);
            if crate::diag::tl_on() {
                self.tl_publish();
            }
        }
        self.bg_ns = self.shards.iter_mut().map(|s| s.sh.take_bg_ns()).sum();
        r
    }

    /// Background work ns (merges, run compactions, checkpoints, tree compaction, defragmentation, recompaction) of
    /// the shards since the poll before the last one, as found by the last [`ObjStore::poll`]. The core loop keeps it out
    /// of the learned cost of its message work (`osd::xcore::Slice`): counted in, a merge slice of a few ms in an
    /// iteration that drained a few messages made the next drains hand on only their first message.
    pub fn bg_ns(&self) -> u64 {
        self.bg_ns
    }

    /// Lab timeline values of this core's shards (`diag::TL_NAMES`): counters summed, gauges of the pool from the
    /// first shard, the rest summed.
    fn tl_publish(&self) {
        let mut v = [0u64; crate::diag::TL_N];
        v[3] = self.parks;
        for (i, s) in self.shards.iter().enumerate() {
            let (o, h) = (&s.stats, &s.sh.stats);
            v[0] += h.txns;
            v[1] += o.run_puts;
            v[2] += o.run_waits;
            v[4] += h.run_merges;
            v[5] += h.run_merged_ents;
            v[6] += h.run_compacted_ents;
            v[7] += h.cm_units;
            v[8] += h.cm_open_ns / 1000;
            v[9] += h.cm_queue_ns / 1000;
            v[10] += h.cm_dev_ns / 1000;
            v[11] += h.cm_post_ns / 1000;
            v[12] += h.dev_write_kind[6] >> 10;
            let g = s.sh.run_gauges();
            if i == 0 {
                v[13] = g[0] >> 10;
                v[14] = g[1] >> 10;
            }
            v[15] += g[2] >> 10;
            v[16] += g[3];
            v[17] += g[4];
            v[18] += s.sh.gauges().dirty_pages;
            let r = &s.sh.state().runs;
            v[19] += r.n_runs() as u64;
            v[20] += r.dead_ents() as u64;
        }
        crate::diag::tl_set(v);
    }

    fn poll_inner(&mut self, acked: &mut Vec<u64>) -> Result<()> {
        let diag = crate::diag::on();
        let now = self.clk.now();
        #[cfg(feature = "elastic")]
        if self.lend_on {
            self.lend_poll(now);
        }
        if now >= self.next_sweep {
            self.next_sweep = now + SWEEP_NS;
            self.active.clear();
            self.active.extend(0..self.shards.len());
            self.is_active.fill(true);
            let t = diag.then(std::time::Instant::now);
            for s in &mut self.shards {
                // the tree page budget follows demand across the device's shards (adr 0062 am. 3); before the data
                // cache fits what the tree lends it
                s.sh.page_exchange(now);
                s.pf_expire(now);
                // the run cache's share follows the data cache's held bytes (adr 0633 am. 5), also while the shard is
                // quiescent and its driver pass does not run
                s.sh.olsm_fit_cache();
                // DMA buffers parked on this core go back when another core ran short (adr 0175 am. 4), also while
                // this core allocates nothing
                s.sh.release_pooled();
            }
            if let Some(t) = t {
                crate::diag::note(4, t.elapsed().as_nanos() as u64);
            }
        }
        let mut keep = 0;
        let mut res = Ok(());
        // checkpoint work of this core (adr 0021 am. 40): one budget for all its shards per poll
        let mut ck_left = usize::MAX;
        #[cfg(feature = "elastic")]
        let mut rets = false;
        for i in 0..self.active.len() {
            let si = self.active[i];
            let s = &mut self.shards[si];
            if ck_left == usize::MAX {
                ck_left = s.sh.ckpt_slice();
            }
            s.sh.set_ckpt_gate(ck_left);
            let t = diag.then(std::time::Instant::now);
            let pumped = s.pump_at(now);
            ck_left = s.sh.ckpt_gate_left();
            if let Some(t) = t {
                crate::diag::note(0, t.elapsed().as_nanos() as u64);
            }
            if let Err(e) = pumped {
                // stays active (a failed shard keeps reporting); the first error is returned after the round
                res = res.and(Err(e.clone()));
                while let Some(p) = self.parked[si].pop_front() {
                    self.drop_preparation(si, p.token);
                    if let Some(ready) = p.ready {
                        self.unreserve(si, &ready.txn);
                    }
                    self.parked_bytes[si] -= p.bytes;
                    self.queue_errors.push((p.token, e.clone()));
                }
                self.active[keep] = si;
                keep += 1;
                continue;
            }
            // background compaction (adr 0021 am. 33): here, between txns, never inside a staged op's miss wait
            if self.parked[si].is_empty() {
                let t_bg = s.sh.bg_now();
                let t = diag.then(std::time::Instant::now);
                s.sh.background(now);
                if let Some(t) = t {
                    crate::diag::note(2, t.elapsed().as_nanos() as u64);
                }
                let t = diag.then(std::time::Instant::now);
                s.defrag_step(now);
                if let Some(t) = t {
                    crate::diag::note(3, t.elapsed().as_nanos() as u64);
                }
                // idle recompaction (adr 0533)
                self.rc_step(si, now);
                self.shards[si].sh.bg_since(t_bg);
            }
            let s = &mut self.shards[si];
            #[cfg(feature = "elastic")]
            {
                rets |= !s.df.returned.is_empty();
            }
            self.woke |= std::mem::take(&mut s.woke);
            self.wtoks.merge(&s.wtoks);
            s.wtoks.clear();
            acked.append(&mut s.acked);
            // the idle walk keeps no shard active: a core with nothing else to do may sleep; the walk takes its next unit
            // in the next round (every `SWEEP_NS`) or while its own IO keeps the shard active
            if self.parked[si].is_empty() && s.sh.quiet() && !s.defrag_active() {
                self.is_active[si] = false;
            } else {
                self.active[keep] = si;
                keep += 1;
            }
        }
        self.active.truncate(keep);
        #[cfg(feature = "elastic")]
        if rets {
            self.reclaim_out();
        }
        #[cfg(feature = "elastic")]
        if self.lend_on {
            self.spare_out(now);
        }
        // Mandatory IO completion polling stays above the preparation budget. Only queued CPU work rotates.
        if res.is_ok() && self.active.iter().any(|&si| !self.parked[si].is_empty()) {
            self.prep_budget.reset();
            let start = self.prep_turn;
            for offset in 0..self.shards.len() {
                let si = (start + offset) % self.shards.len();
                if self.parked[si].is_empty() {
                    continue;
                }
                if self.prep_budget.exhausted() {
                    break;
                }
                self.prep_turn = (si + 1) % self.shards.len();
                let queued = self.resume_queue(si);
                if queued.is_ok() {
                    self.lookahead(si);
                }
                acked.append(&mut self.shards[si].acked);
                self.activate(si);
                if let Err(e) = queued {
                    res = Err(e);
                    break;
                }
            }
        }
        res
    }

    /// End of the core loop's pass (after its receive, cross-core pump and timers, before its IO flush): group commit
    /// of the txns submitted since this pass's poll (adr 0021 am. 67). Only active shards can hold an open unit.
    pub fn end_pass(&mut self) {
        for &si in &self.active {
            self.shards[si].sh.end_pass();
        }
    }

    /// Idle core, store not quiet: how long until a device of this core's active shards may complete a command (adr 0004
    /// am. 1, polled devices). `None` = no device estimate (a shard is active without device IO, a queue has none, or
    /// work is queued): the caller keeps its own wait policy. `Some(0)` = a completion is due: poll.
    pub fn wait_hint(&mut self) -> Option<std::time::Duration> {
        #[cfg(feature = "elastic")]
        if self.pool.as_ref().is_some_and(|p| p.busy()) || !self.lend_out.is_empty() {
            return None;
        }
        let mut best: Option<std::time::Duration> = None;
        for &si in &self.active {
            if !self.parked[si].is_empty() {
                return None;
            }
            let h = self.shards[si].sh.dev().wait_hint()?;
            best = Some(best.map_or(h, |b| b.min(h)));
        }
        best
    }

    /// Override the per-poll wall-clock preparation allowance (adr 0093; default 100 us, `None` under virtual time).
    /// Tests: `Some(Duration::ZERO)` forces the most fragmented preparation schedule deterministically.
    pub fn set_prep_allowance(&mut self, allow: Option<std::time::Duration>) {
        self.prep_budget.set_allowance(allow);
    }

    /// Advance virtual/real time while idle (sim clocks jump to the next device completion).
    pub fn idle(&mut self) {
        #[cfg_attr(not(feature = "elastic"), allow(unused_mut))]
        let mut i = self
            .shards
            .iter_mut()
            .filter_map(|s| s.sh.dev().next_deadline())
            .min();
        #[cfg(feature = "elastic")]
        if let Some(p) = self.pool.as_ref() {
            i = i.into_iter().chain(p.tq.next_deadline()).min();
        }
        self.clk.idle(i);
    }

    /// Queue + wait for durability.
    pub fn commit(&mut self, t: &OTxn) -> Result<()> {
        self.next_token += 1;
        let tok = self.next_token;
        let si = self.route(t)?.unwrap_or(0);
        self.drain_queued()?;
        self.queue_blocking(t, tok)?;
        let s = &mut self.shards[si];
        s.wait(&mut self.clk, |s| s.acked.contains(&tok))?;
        s.acked.retain(|t| *t != tok);
        Ok(())
    }

    /// Wait until everything queued is durable.
    pub fn sync(&mut self) -> Result<()> {
        self.drain_queued()?;
        for s in &mut self.shards {
            let target = s.sh.next_lsn() - 1;
            s.wait(&mut self.clk, |s| s.sh.durable_lsn() >= target)?;
        }
        Ok(())
    }

    /// Ask every mounted shard for a checkpoint at its next poll (operator `flush_journal`); does not wait.
    pub fn request_checkpoint(&mut self) {
        // a requested checkpoint is work (`Shard::quiet` is false): the next poll drives it, not the next sweep (a sim
        // clock that only moves with device IO may never reach it)
        for si in 0..self.shards.len() {
            self.shards[si].sh.request_checkpoint();
            self.activate(si);
        }
    }

    /// Inline-compression counters summed over the mounted shards (adr 0059 am. 1).
    pub fn comp_counters(&self) -> CompCounters {
        self.shards.iter().fold(CompCounters::default(), |a, s| {
            let t = &s.stats;
            CompCounters {
                ok: a.ok + t.comp_ok,
                rejected: a.rejected + t.comp_rejected,
                sampled_out: a.sampled_out + t.comp_sampled_out,
                gc_merged: a.gc_merged + t.comp_gc,
                decomp: a.decomp + t.decomp,
                comp_ns: a.comp_ns + t.comp_ns,
                decomp_ns: a.decomp_ns + t.decomp_ns,
                staged_bytes: a.staged_bytes + t.staged_data_bytes,
                zc_bytes: a.zc_bytes + t.zc_data_bytes,
                crc_reused_bytes: a.crc_reused_bytes + t.crc_reused_bytes,
                placement_crc_reblocked_bytes: a.placement_crc_reblocked_bytes
                    + t.placement_crc_reblocked_bytes,
                placement_crc_hashed_bytes: a.placement_crc_hashed_bytes
                    + t.placement_crc_hashed_bytes,
            }
        })
    }

    /// Checkpoint / back-pressure counters of the mounted shards for `perf dump` (adr 0021 am. 43): `(name, gauge, value)`.
    /// Gauges: sums over shards, `_max` = fullest shard. Counters are lifetime values (no perf reset). Runs on every core once
    /// a second (stats for the control core) and per `perf dump`: O(shards), nothing walks a shard's objects or windows (the
    /// fragmentation gauges advance a bounded walk, `Alloc::frag`).
    pub fn perf_counters(&self) -> Vec<(&'static str, bool, u64)> {
        let (mut g, mut st) = (
            crate::shard::ShardGauges::default(),
            crate::shard::ShardStats::default(),
        );
        let mut wal_hw = 0u64;
        // leaf delta state (adr 0021 S6): chain RAM, delta pages and their bound, segments
        let mut dl = [0u64; 4];
        // free blocks, in whole free windows, in windows without a `FRAG_SHORT` run; shortest longest run (adr 0475, bounded walk)
        let mut frag = [0, 0, 0, u64::MAX];
        let (mut dirty_max, mut wal_pct_max, mut running, mut parked_max) = (0, 0, 0, 0);
        let mut helper_reserved = 0;
        let (mut run_live, mut run_merging, mut run_mem) = (0u64, 0u64, 0u64);
        let mut run_vcomp = [0u64; 2];
        let mut helper_pool_reserved = 0;
        // runtime deallocate (adr 0642): shards with trims on, blocks held by commands in flight, dirty windows,
        // candidates (dirty, whole free)
        let mut trim = [0u64; 4];
        for (i, s) in self.shards.iter().enumerate() {
            let x = s.sh.gauges();
            trim[0] += u64::from(x.trim_on);
            trim[1] += x.trim_held;
            trim[2] += x.trim_dirty_windows;
            trim[3] += x.trim_cand_windows;
            g.dirty_pages += x.dirty_pages;
            g.dirty_soft += x.dirty_soft;
            g.dirty_hard += x.dirty_hard;
            g.freeze_left += x.freeze_left;
            g.wal_used += x.wal_used;
            g.wal_blocks += x.wal_blocks;
            dirty_max = dirty_max.max(x.dirty_pages);
            wal_pct_max = wal_pct_max.max(x.wal_used * 100 / x.wal_blocks.max(1));
            running += u64::from(x.ckpt_running);
            parked_max = parked_max.max(self.parked[i].len() as u64);
            let tr = &s.sh.state().tree;
            dl[0] += tr.delta_chain_bytes() as u64;
            dl[1] += tr.delta_pages() as u64;
            dl[2] += tr.delta_max_pages() as u64;
            dl[3] += tr.delta_segments() as u64;
            let t = &s.sh.stats;
            wal_hw = wal_hw.max(t.wal_hw_blocks * 100 / x.wal_blocks.max(1));
            st.merge(t);
            st.dev_busy_ns += s.sh.dev_busy_ns() - t.dev_busy_ns; // plus the busy period still open
            let a = &s.sh.state().alloc;
            let f = a.frag();
            frag[0] += a.n_free();
            frag[1] += f[0];
            frag[2] += f[1];
            frag[3] = frag[3].min(f[2]);
            helper_reserved += s.sh.compaction_reserved() as u64;
            helper_pool_reserved = helper_pool_reserved.max(s.sh.compaction_pool_reserved() as u64);
            let g = s.sh.run_gauges();
            run_mem += g[2];
            run_live += g[3];
            run_merging += g[4];
            let vc = s.sh.state().run_vcomp;
            run_vcomp[0] += vc.1;
            run_vcomp[1] += vc.0;
        }
        #[cfg(feature = "elastic")]
        let (mut lend_req, mut lend_grant, mut lend_deny, mut lend_slots) = (0, 0, 0, 0);
        #[cfg(feature = "elastic")]
        for s in self.shards.iter() {
            lend_req += s.sh.lend.requests;
            lend_grant += s.sh.lend.grants;
            lend_deny += s.sh.lend.denies;
            lend_slots += s.sh.state().alloc.lent_slots() as u64;
        }
        let b = st.busy;
        let tr = self.tree_stats();
        // omap LSM engine (adr 0610), zero on stores without it
        let ol =
            self.shards
                .iter()
                .filter_map(|s| s.sh.olsm_stats())
                .fold([0u64; 42], |mut a, o| {
                    for (x, y) in a.iter_mut().zip([
                        o.flushes,
                        o.merges,
                        o.written_blocks,
                        o.freed_blocks,
                        o.alloc_waits,
                        o.man_retries,
                        o.throttled,
                        o.reads,
                        o.read_blocks,
                        o.helper_rounds,
                        o.inline_rounds,
                        o.gc_merges,
                        o.gc_bytes_reclaimed,
                        o.chunks_lt16,
                        o.space_live_bytes,
                        o.space_used_bytes,
                        o.space_garbage_bytes,
                        o.frag_holes_lt16,
                        o.runs,
                        o.mem_bytes,
                        o.space_throttled,
                        o.pick_visits,
                        o.scan_prefetch.submitted,
                        o.scan_prefetch.useful,
                        o.scan_prefetch.unused,
                        o.scan_prefetch.throttled,
                        o.scan_prefetch.demand_waits,
                        o.scan_prefetch.inflight_bytes,
                        o.scan_prefetch.resident_bytes,
                        o.scan_prefetch_inflight_slots,
                        o.scan_prefetch.late,
                        o.scan_prefetch.late_bytes,
                        o.scan_prefetch.useful_bytes,
                        o.scan_prefetch.unused_bytes,
                        o.scan_prefetch.useful_late_bytes,
                        o.scan_prefetch_fixed,
                        o.scan_prefetch_adaptive,
                        o.scan_prefetch_window,
                        o.scan_prefetch_grows,
                        o.scan_prefetch_shrinks,
                        o.gc_prefixes,
                        o.merges_refused,
                    ]) {
                        *x += y;
                    }
                    a
                });
        // leaves written whole by checkpoints by key space (first key byte = tag, keys.rs)
        let mut wl = [0u64; 8];
        for s in self.shards.iter() {
            for (t, &n) in s.sh.state().tree.fz_whole_tag.iter().enumerate() {
                let i = match t as u8 {
                    T_NAME | T_LNAME => 0,
                    T_ONODE => 1,
                    T_ATTR => 2,
                    T_EXT => 3,
                    T_OMAP | T_HDR | T_FRAG | T_OPEND => 4,
                    T_COLL => 5,
                    b'f' => 6,
                    _ => 7,
                };
                wl[i] += n;
            }
        }
        let mut v = vec![
            ("dirty_pages", true, g.dirty_pages),
            ("dirty_pages_max", true, dirty_max),
            ("dirty_soft", true, g.dirty_soft),
            ("dirty_hard", true, g.dirty_hard),
            ("ckpt_running", true, running),
            ("freeze_left", true, g.freeze_left),
            ("wal_used_blocks", true, g.wal_used),
            ("wal_blocks", true, g.wal_blocks),
            ("wal_used_pct_max", true, wal_pct_max),
            ("wal_hw_pct_max", true, wal_hw),
            ("parked_txns", true, self.queued_count() as u64),
            ("parked_txns_max", true, parked_max),
            ("txns", false, st.txns),
            ("txn_prepares", false, st.prepares),
            ("parks", false, self.parks),
            ("barriers", false, self.barriers),
            ("barrier_ns", false, self.barrier_ns),
            ("park_probes", false, self.park_probes),
            ("lookahead_loads", false, self.lookahead_loads),
            // listings on the PG core (adr 0021 S5, S8): leaves read scan-resistant, passes continued from a scan memo,
            // passes ended by the CPU slice
            (
                "scan_loads",
                false,
                self.shards
                    .iter()
                    .map(|s| s.sh.tree_stats().scan_loads)
                    .sum(),
            ),
            // omap batches staged as runs (removal batches included, also in run_rms), and staging retries that
            // waited for run room
            (
                "run_puts",
                false,
                self.shards.iter().map(|s| s.stats.run_puts).sum(),
            ),
            (
                "run_rms",
                false,
                self.shards.iter().map(|s| s.stats.run_rms).sum(),
            ),
            (
                "run_waits",
                false,
                self.shards.iter().map(|s| s.stats.run_waits).sum(),
            ),
            (
                "scan_resumes",
                false,
                self.shards.iter().map(|s| s.stats.scan_resumes).sum(),
            ),
            (
                "scan_slices",
                false,
                self.shards.iter().map(|s| s.stats.scan_slices).sum(),
            ),
            // omap runs (adr 0476): tree merge slices and entries, compactions and their output entries, compactions dropped
            // because an input left (inline and helper), re-logs; gauges: live entries, run memory (`Shard::run_gauges`)
            ("run_merges", false, st.run_merges),
            ("run_merged_ents", false, st.run_merged_ents),
            ("run_compactions", false, st.run_compactions),
            ("run_helper_jobs", false, st.run_helper_jobs),
            ("run_helper_done", false, st.run_helper_done),
            ("run_helper_lost", false, st.run_helper_lost),
            ("run_compact_lost", false, st.run_compact_lost),
            ("run_helper_reserved", true, helper_reserved),
            ("run_helper_pool_reserved", true, helper_pool_reserved),
            ("run_helper_served", false, self.helper_served),
            ("run_helper_queued", true, self.helper_queued as u64),
            ("run_compacted_ents", false, st.run_compacted_ents),
            ("run_relogs", false, st.run_relogs),
            ("run_merge_drain", false, st.run_merge_starts[0]),
            ("run_merge_soft", false, st.run_merge_starts[1]),
            ("run_merge_floor", false, st.run_merge_starts[2]),
            ("run_merge_idle", false, st.run_merge_starts[3]),
            ("run_merge_dirty_waits", false, st.run_merge_dirty_waits),
            // merge steps with runs left that moved nothing, by reason (`ShardStats::run_merge_skips`); idle marks taken
            ("run_merge_skip_unwanted", false, st.run_merge_skips[0]),
            ("run_merge_skip_loads", false, st.run_merge_skips[1]),
            ("run_merge_skip_dirty", false, st.run_merge_skips[2]),
            ("run_merge_skip_paced", false, st.run_merge_skips[3]),
            ("run_merge_waits", false, st.run_merge_waits),
            ("run_merge_miss", false, st.run_merge_miss),
            ("run_idle_marks", false, st.run_idle_marks),
            ("run_live_ents", true, run_live),
            ("run_mem_bytes", true, run_mem),
            ("run_merging", true, run_merging),
            // merged run values: compressions tried / stored compressed (`State::run_vcomp`)
            ("run_vcomp_tries", false, run_vcomp[0]),
            ("run_vcomp_hits", false, run_vcomp[1]),
            ("ckpt_begins", false, st.ckpt_begins),
            ("ckpt_ends", false, st.checkpoints),
            ("ckpt_forced", false, st.forced_ckpts),
            // elastic meta cells grown / given back; growth misses that waited for the checkpoint releasing the frees, and
            // actual failures (meta-bound: statfs full) (adr 0021 S13)
            ("meta_cells_added", false, st.cells_added),
            ("meta_cells_released", false, st.cells_released),
            ("meta_grow_waits", false, st.meta_grow_waits),
            ("meta_grow_bound", false, st.meta_grow_bound),
            ("ckpt_why_requested", false, st.ckpt_why[0]),
            ("ckpt_why_space", false, st.ckpt_why[1]),
            ("ckpt_why_wal", false, st.ckpt_why[2]),
            ("ckpt_why_dirty", false, st.ckpt_why[3]),
            ("ckpt_why_chunks", false, st.ckpt_why[4]),
            ("ckpt_why_interval", false, st.ckpt_why[5]),
            ("ckpt_pages", false, st.ckpt_pages),
            ("ckpt_slices", false, st.ckpt_slices),
            ("ckpt_deferred", false, st.ckpt_deferred),
            ("ckpt_start_slices", false, st.ckpt_start_slices),
            ("ckpt_ns", false, st.ckpt_ns),
            ("ckpt_max_ns", false, st.ckpt_max_ns),
            ("ckpt_sync_ns", false, st.ckpt_sync_ns),
            ("ckpt_sync_max_ns", false, st.ckpt_sync_max_ns),
            ("delta_chain_bytes", true, dl[0]),
            ("delta_pages", true, dl[1]),
            ("delta_max_pages", true, dl[2]),
            ("delta_segments", true, dl[3]),
            ("ckpt_delta_entries", false, tr.delta_entries),
            ("ckpt_delta_pages", false, tr.delta_pages),
            ("ckpt_delta_declined", false, tr.delta_declined),
            ("ckpt_declined_chain", false, tr.declined_chain),
            ("ckpt_declined_room", false, tr.declined_room),
            ("ckpt_delta_folded", false, tr.delta_folded),
            ("ckpt_delta_relog_chains", false, tr.relog_chains),
            ("ckpt_delta_relog_segs", false, tr.relog_segs),
            ("ckpt_fz_clean", false, tr.fz_clean),
            ("ckpt_fz_whole_leaves", false, tr.fz_whole_leaves),
            ("ckpt_fz_whole_ints", false, tr.fz_whole_ints),
            ("ckpt_wleaf_name", false, wl[0]),
            ("ckpt_wleaf_onode", false, wl[1]),
            ("ckpt_wleaf_attr", false, wl[2]),
            ("ckpt_wleaf_ext", false, wl[3]),
            ("ckpt_wleaf_omap", false, wl[4]),
            ("ckpt_wleaf_coll", false, wl[5]),
            ("ckpt_wleaf_bitmap", false, wl[6]),
            ("ckpt_wleaf_other", false, wl[7]),
            ("busy_dirty_hard", false, b[2]),
            ("busy_meta", false, b[3]),
            ("busy_meta_run", false, st.busy_meta_run),
            ("busy_meta_ckpt", false, st.busy_meta_ckpt),
            ("busy_wal", false, b[6] + b[7] + b[8] + b[9]),
            ("ring_full", false, b[7] + b[9]),
            ("busy_other", false, b[1] + b[4] + b[5]),
            // device queues of this core (adr 0474): %util = delta dev_busy_ns / (delta wall x dev_qpairs)
            ("dev_qpairs", true, self.shards.len() as u64),
            ("dev_busy_ns", false, st.dev_busy_ns),
            ("dev_completions", false, st.io_completions),
            ("view_copy_bytes", false, st.view_copy_bytes),
            ("dev_read_bytes", false, st.dev_read_bytes),
            ("dev_write_bytes", false, st.dev_write_bytes),
            // device write bytes by kind: data extents (+ pre-written payload), WAL units (+ ring-end pads), checkpoint
            // pages, root slots; WAL unit bytes, their header + record share, units; meta image pages per checkpoint
            (
                "dev_wr_data",
                false,
                st.dev_write_kind[1] + st.dev_write_kind[9],
            ),
            (
                "dev_wr_wal",
                false,
                st.dev_write_kind[2] + st.dev_write_kind[3],
            ),
            ("dev_wr_ckpt", false, st.dev_write_kind[6]),
            ("dev_wr_olsm", false, st.dev_write_kind[10]),
            ("olsm_flushes", false, ol[0]),
            ("olsm_merges", false, ol[1]),
            ("olsm_merges_refused", false, ol[41]),
            ("olsm_written_blocks", false, ol[2]),
            ("olsm_freed_blocks", false, ol[3]),
            ("olsm_alloc_waits", false, ol[4]),
            ("olsm_manifest_retries", false, ol[5]),
            ("olsm_throttled", false, ol[6]),
            ("olsm_reads", false, ol[7]),
            ("olsm_read_blocks", false, ol[8]),
            ("olsm_helper_rounds", false, ol[9]),
            ("olsm_inline_rounds", false, ol[10]),
            ("olsm_gc_merges", false, ol[11]),
            ("olsm_gc_prefixes", false, ol[40]),
            ("olsm_gc_bytes_reclaimed", false, ol[12]),
            ("olsm_chunks_lt16", false, ol[13]),
            ("olsm_space_live_bytes", true, ol[14]),
            ("olsm_space_used_bytes", true, ol[15]),
            ("olsm_space_garbage_bytes", true, ol[16]),
            ("olsm_frag_holes_lt16", true, ol[17]),
            ("olsm_runs", true, ol[18]),
            ("olsm_mem_bytes", true, ol[19]),
            ("olsm_space_throttled", false, ol[20]),
            ("olsm_pick_visits", false, ol[21]),
            ("olsm_scan_prefetch_submitted", false, ol[22]),
            ("olsm_scan_prefetch_useful", false, ol[23]),
            ("olsm_scan_prefetch_unused", false, ol[24]),
            ("olsm_scan_prefetch_throttled", false, ol[25]),
            ("olsm_scan_prefetch_demand_waits", false, ol[26]),
            ("olsm_scan_prefetch_inflight_bytes", true, ol[27]),
            ("olsm_scan_prefetch_resident_bytes", true, ol[28]),
            ("olsm_scan_prefetch_inflight_slots", true, ol[29]),
            ("olsm_scan_prefetch_late", false, ol[30]),
            ("olsm_scan_prefetch_late_bytes", false, ol[31]),
            ("olsm_scan_prefetch_useful_bytes", false, ol[32]),
            ("olsm_scan_prefetch_unused_bytes", false, ol[33]),
            ("olsm_scan_prefetch_useful_late_bytes", false, ol[34]),
            ("olsm_scan_prefetch_fixed_shards", true, ol[35]),
            ("olsm_scan_prefetch_adaptive_shards", true, ol[36]),
            ("olsm_scan_prefetch_window_chunks", true, ol[37]),
            ("olsm_scan_prefetch_grows", false, ol[38]),
            ("olsm_scan_prefetch_shrinks", false, ol[39]),
            ("busy_omap_mem", false, b[10]),
            ("dev_wr_root", false, st.dev_write_kind[4]),
            ("wal_unit_bytes", false, st.wal_bytes),
            ("wal_payload_bytes", false, st.wal_payload),
            ("wal_units", false, st.units),
            ("ckpt_blob_pages", false, st.ckpt_blob_pages),
            // commit latency of WAL units (shard stats `cm_*`): log2 us buckets, slow (>= 5 ms) attribution
            ("cm_units", false, st.cm_units),
            ("cm_ahead_cmds", false, st.cm_ahead),
            ("cm_slow", false, st.cm_slow),
            ("cm_slow_ckpt", false, st.cm_slow_ckpt),
            ("cm_slow_backlog", false, st.cm_slow_backlog),
            ("cm_slow_wal_first", false, st.cm_slow_walfirst),
            ("cm_slow_ahead_cmds", false, st.cm_slow_ahead),
            ("cm_open_ns", false, st.cm_open_ns),
            ("cm_queue_ns", false, st.cm_queue_ns),
            ("cm_dev_ns", false, st.cm_dev_ns),
            ("cm_post_ns", false, st.cm_post_ns),
            ("cm_ckpt_units", false, st.cm_ck_units),
            ("cm_ckpt_dev_ns", false, st.cm_ck_dev_ns),
            // allocator (adr 0475): data runs (blocks / runs = mean extent), hole-first runs, cuts on a fragmented shard;
            // free-space shape (fragmented share = free_short_blocks / free_blocks)
            ("alloc_data_runs", false, st.data_runs),
            ("alloc_data_blocks", false, st.data_run_blocks),
            ("alloc_small_dense", false, st.small_dense_allocs),
            ("alloc_frag_cuts", false, st.frag_cuts),
            ("free_blocks", true, frag[0]),
            ("free_whole_win_blocks", true, frag[1]),
            ("free_short_blocks", true, frag[2]),
            ("free_longest_run_min", true, frag[3] % u64::MAX),
            // runtime deallocate of freed blocks (adr 0642); trim_lat_ns / trim_cmds = mean device latency
            ("trim_on", true, trim[0]),
            ("trim_cmds", false, st.trim_cmds),
            ("trim_ranges", false, st.trim_ranges),
            ("trim_bytes", false, st.trim_bytes),
            ("trim_lat_ns", false, st.trim_lat_ns),
            ("trim_lat_max_ns", true, st.trim_lat_max_ns),
            ("trim_errors", false, st.trim_errors),
            ("trim_skipped_bytes", false, st.trim_skipped_bytes),
            ("trim_held_bytes", true, trim[1] * crate::BLK as u64),
            ("trim_dirty_windows", true, trim[2]),
            ("trim_cand_windows", true, trim[3]),
            ("trim_waits", false, st.trim_waits),
        ];
        #[cfg(not(feature = "rocksdb"))]
        let rocks = [0u64; 37];
        #[cfg(feature = "rocksdb")]
        let rocks = self.shards.iter().filter_map(|s| s.sh.rocks_gauges()).fold(
            [0u64; 37],
            |mut total, shard| {
                for i in 0..37 {
                    total[i] = if i == 2 {
                        total[i].max(shard[i])
                    } else {
                        total[i].saturating_add(shard[i])
                    };
                }
                total
            },
        );
        v.extend([
            ("rocks_selected_shards", true, rocks[0]),
            ("rocks_sample_valid_shards", true, rocks[1]),
            ("rocks_sample_age_ns_max", true, rocks[2]),
            ("rocks_active_bytes", true, rocks[3]),
            ("rocks_frozen_bytes", true, rocks[4]),
            ("rocks_pending_reads", true, rocks[5]),
            ("rocks_materializing", true, rocks[6]),
            ("rocks_publication_pending", true, rocks[7]),
            ("rocks_busy_shards", true, rocks[8]),
            ("rocks_sample_errors", false, rocks[9]),
            ("rocks_flush_pending", true, rocks[10]),
            ("rocks_compaction_pending", true, rocks[11]),
            ("rocks_running_flushes", true, rocks[12]),
            ("rocks_running_compactions", true, rocks[13]),
            ("rocks_pending_compaction_bytes", true, rocks[14]),
            ("rocks_write_stopped", true, rocks[15]),
            ("rocks_memtable_bytes", true, rocks[16]),
            ("rocks_block_cache_bytes", true, rocks[17]),
            ("rocks_sst_bytes", true, rocks[18]),
            ("rocks_allocated_bytes", true, rocks[19]),
            ("rocks_db_lsn_sum", true, rocks[20]),
            ("rocks_published_lsn_sum", true, rocks[21]),
            ("rocks_read_only_shards", true, rocks[22]),
            ("rocks_materializations", false, rocks[23]),
            ("rocks_materialization_ns", false, rocks[24]),
            ("rocks_point_requests", false, rocks[25]),
            ("rocks_point_ns", false, rocks[26]),
            ("rocks_page_requests", false, rocks[27]),
            ("rocks_page_ns", false, rocks[28]),
            ("rocks_diagnostic_samples", false, rocks[29]),
            ("rocks_diagnostic_ns", false, rocks[30]),
            ("rocks_materialized_mem_bytes", false, rocks[31]),
            ("rocks_block_cache_capacity_bytes", true, rocks[32]),
            ("rocks_query_attempts", false, rocks[33]),
            ("rocks_read_enqueues", false, rocks[34]),
            ("rocks_pending_query_misses", false, rocks[35]),
            ("rocks_worker_completions", false, rocks[36]),
        ]);
        #[cfg(not(feature = "rocksdb"))]
        let profile = [0u64; 72];
        #[cfg(feature = "rocksdb")]
        let profile = self
            .shards
            .iter()
            .filter_map(|s| s.sh.rocks_profile_gauges())
            .fold([0u64; 72], |mut total, shard| {
                for i in 0..72 {
                    total[i] = if i == 26 {
                        total[i].max(shard[i])
                    } else {
                        total[i].saturating_add(shard[i])
                    };
                }
                total
            });
        v.extend([
            ("rocks_profile_enabled_shards", true, profile[0]),
            ("rocks_profile_valid_shards", true, profile[1]),
            ("rocks_profile_errors", false, profile[2]),
            ("rocks_profile_l0_files", true, profile[3]),
            ("rocks_profile_immutable_memtables", true, profile[4]),
            ("rocks_profile_delayed_rate", true, profile[5]),
            ("rocks_profile_stall_us", false, profile[6]),
            ("rocks_profile_wal_syncs", false, profile[7]),
            ("rocks_profile_wal_bytes", false, profile[8]),
            ("rocks_profile_compact_read_bytes", false, profile[9]),
            ("rocks_profile_compact_write_bytes", false, profile[10]),
            ("rocks_profile_flush_write_bytes", false, profile[11]),
            ("rocks_profile_build_ns", false, profile[12]),
            ("rocks_profile_write_ns", false, profile[13]),
            ("rocks_profile_build_cpu_ns", false, profile[14]),
            ("rocks_profile_write_cpu_ns", false, profile[15]),
            ("rocks_profile_cpu_samples", false, profile[16]),
            ("rocks_profile_cpu_errors", false, profile[17]),
            ("rocks_profile_queue_ns", false, profile[18]),
            ("rocks_profile_completion_ns", false, profile[19]),
            ("rocks_profile_publication_ns", false, profile[20]),
            ("rocks_profile_backpressure_ns", false, profile[21]),
            ("rocks_profile_backpressure_intervals", false, profile[22]),
            ("rocks_profile_point_ops", false, profile[23]),
            ("rocks_profile_range_ops", false, profile[24]),
            ("rocks_profile_batch_bytes", false, profile[25]),
            ("rocks_profile_age_ns_max", true, profile[26]),
            ("rocks_profile_freezes", false, profile[27]),
            ("rocks_profile_freeze_bytes", false, profile[28]),
            ("rocks_profile_freeze_undurable", false, profile[29]),
            ("rocks_profile_freeze_enqueues", false, profile[30]),
            ("rocks_profile_freeze_wait_ns", false, profile[31]),
            ("rocks_profile_freeze_track_errors", false, profile[32]),
            ("rocks_profile_freeze_le4k", false, profile[33]),
            ("rocks_profile_freeze_le64k", false, profile[34]),
            ("rocks_profile_freeze_le1m", false, profile[35]),
            ("rocks_profile_freeze_le8m", false, profile[36]),
            ("rocks_profile_freeze_gt8m", false, profile[37]),
            ("rocks_profile_batch_le4k", false, profile[38]),
            ("rocks_profile_batch_le64k", false, profile[39]),
            ("rocks_profile_batch_le1m", false, profile[40]),
            ("rocks_profile_batch_le8m", false, profile[41]),
            ("rocks_profile_batch_gt8m", false, profile[42]),
            ("rocks_profile_batch_failures", false, profile[43]),
            ("rocks_profile_page_attempts", false, profile[44]),
            ("rocks_profile_page_failures", false, profile[45]),
            ("rocks_profile_page_cpu_samples", false, profile[46]),
            ("rocks_profile_page_cpu_errors", false, profile[47]),
            ("rocks_profile_page_setup_ns", false, profile[48]),
            ("rocks_profile_page_setup_cpu_ns", false, profile[49]),
            ("rocks_profile_page_position_ns", false, profile[50]),
            ("rocks_profile_page_position_cpu_ns", false, profile[51]),
            ("rocks_profile_page_walk_ns", false, profile[52]),
            ("rocks_profile_page_walk_cpu_ns", false, profile[53]),
            ("rocks_profile_page_drop_ns", false, profile[54]),
            ("rocks_profile_page_drop_cpu_ns", false, profile[55]),
            ("rocks_profile_page_handoff_accepted", false, profile[56]),
            ("rocks_profile_page_handoff_dequeued", false, profile[57]),
            ("rocks_profile_page_handoff_ready", false, profile[58]),
            ("rocks_profile_page_handoff_published", false, profile[59]),
            ("rocks_profile_page_handoff_consumed", false, profile[60]),
            ("rocks_profile_page_handoff_success", false, profile[61]),
            ("rocks_profile_page_handoff_refused", false, profile[62]),
            ("rocks_profile_page_handoff_failed", false, profile[63]),
            ("rocks_profile_page_handoff_samples", false, profile[64]),
            ("rocks_profile_page_handoff_errors", false, profile[65]),
            (
                "rocks_profile_page_handoff_full_retries",
                false,
                profile[66],
            ),
            ("rocks_profile_page_handoff_request_ns", false, profile[67]),
            ("rocks_profile_page_handoff_worker_ns", false, profile[68]),
            (
                "rocks_profile_page_handoff_publish_retry_ns",
                false,
                profile[69],
            ),
            (
                "rocks_profile_page_handoff_owner_dequeue_ns",
                false,
                profile[70],
            ),
            ("rocks_profile_page_handoff_total_ns", false, profile[71]),
        ]);
        #[cfg(feature = "splinterdb")]
        {
            let times = self
                .shards
                .iter()
                .filter_map(|s| s.sh.splinter_timing_counters())
                .fold([0u64; crate::splinter_omap::timing::FIELDS], |mut a, b| {
                    for (i, (_, maximum)) in crate::splinter_omap::timing::NAMES.iter().enumerate()
                    {
                        a[i] = if *maximum {
                            a[i].max(b[i])
                        } else {
                            a[i].saturating_add(b[i])
                        };
                    }
                    a
                });
            for ((name, maximum), value) in
                crate::splinter_omap::timing::NAMES.into_iter().zip(times)
            {
                v.push((name, maximum, value));
            }
            let totals = self
                .shards
                .iter()
                .filter_map(|s| s.sh.splinter_gauges())
                .fold([0u64; 10], |mut a, b| {
                    for i in 0..10 {
                        a[i] = a[i].saturating_add(b[i]);
                    }
                    a
                });
            for (name, value) in [
                "splinter_selected_shards",
                "splinter_pages",
                "splinter_points",
                "splinter_flushes",
                "splinter_allocated_bytes",
                "splinter_capacity_bytes",
                "splinter_applied_lsn_sum",
                "splinter_published_lsn_sum",
                "splinter_active_bytes",
                "splinter_frozen_bytes",
            ]
            .into_iter()
            .zip(totals)
            {
                v.push((name, true, value));
            }
            let reads = self
                .shards
                .iter()
                .filter_map(|s| s.sh.splinter_read_gauges())
                .fold([0u64; 29], |mut a, b| {
                    for i in 0..29 {
                        a[i] = if i == 21 {
                            a[i].max(b[i])
                        } else {
                            a[i].saturating_add(b[i])
                        };
                    }
                    a
                });
            for (name, value) in [
                "splinter_scan_window_hits",
                "splinter_scan_retry_hits",
                "splinter_scan_prefetched_pages",
                "splinter_scan_useful_pages",
                "splinter_scan_unused_pages",
                "splinter_scan_useful_bytes",
                "splinter_scan_unused_bytes",
                "splinter_scan_charged_bytes",
                "splinter_scan_window_pages",
                "splinter_worker_scan_seeks",
                "splinter_cache_hits",
                "splinter_cache_misses",
                "splinter_engine_read_bytes",
                "splinter_engine_write_bytes",
                "splinter_engine_prefetch_pages",
                "splinter_direct_io_shards",
                "splinter_cache_capacity_bytes",
                "splinter_prefetch_budget_bytes",
                "splinter_cache_stats_valid_shards",
                "splinter_read_sample_valid_shards",
                "splinter_read_sample_errors",
                "splinter_read_sample_age_ns_max",
                "splinter_point_cache_bytes",
                "splinter_retained_read_bytes",
                "splinter_scan_output_charge_bytes",
                "splinter_logical_readahead_errors",
                "splinter_normal_maintenance_workers",
                "splinter_maintenance_busy_shards",
                "splinter_maintenance_stack_bytes",
            ]
            .into_iter()
            .zip(reads)
            {
                v.push((name, true, value));
            }
        }
        for (i, n) in CM_NAMES.iter().enumerate() {
            v.push((n.0, false, st.cm_lat[i]));
            v.push((n.1, false, st.cm_wal[i]));
            v.push((n.2, false, st.cm_data[i]));
        }
        // receiver-side pre-write (adr 0477): pieces written ahead, claimed by their txn, released unclaimed (wasted
        // device bytes), not written ahead; live = slots not finished
        let mut pre = crate::pre::PreStats::default();
        let mut pre_live = 0u64;
        for s in self.shards.iter() {
            let p = s.sh.pre_stats();
            pre.writes += p.writes;
            pre.bytes += p.bytes;
            pre.claimed += p.claimed;
            pre.claimed_bytes += p.claimed_bytes;
            pre.claimed_landed += p.claimed_landed;
            pre.released += p.released;
            pre.released_bytes += p.released_bytes;
            pre.skipped += p.skipped;
            pre.copied += p.copied;
            pre_live += s.sh.pre_live() as u64;
        }
        v.extend([
            ("pre_writes", false, pre.writes),
            ("pre_bytes", false, pre.bytes),
            ("pre_claimed", false, pre.claimed),
            ("pre_claimed_bytes", false, pre.claimed_bytes),
            ("pre_claimed_landed", false, pre.claimed_landed),
            ("pre_released", false, pre.released),
            ("pre_released_bytes", false, pre.released_bytes),
            ("pre_skipped", false, pre.skipped),
            ("pre_copied", false, pre.copied),
            ("pre_live", true, pre_live),
        ]);
        // elastic pool (adr 0021 am. 52/56): requests, answers, borrowed chunk slots (holes included) of the mounted shards
        #[cfg(feature = "elastic")]
        v.extend([
            ("lend_requests", false, lend_req),
            ("lend_grants", false, lend_grant),
            ("lend_denies", false, lend_deny),
            ("lend_slots", true, lend_slots),
            // pool owner (am. 82): short requests that waited for a chunk given back on demand
            ("lend_waits", false, self.pool_waits()),
        ]);
        // reclaim (adr 0021 am. 57): borrowed chunks held now (holes excluded), returns, evacuations
        #[cfg(feature = "elastic")]
        {
            let mut r = [0u64; 5];
            for s in self.shards.iter() {
                let a = &s.sh.state().alloc;
                r[0] += (0..a.lent_slots())
                    .filter(|&k| a.lent_slot(k).0 != crate::alloc::HOLE)
                    .count() as u64;
                let d = s.defrag_stats();
                r[1] += d.chunks_returned;
                r[2] += d.evacs;
                r[3] += d.evac_blocks;
                r[4] += d.evac_fails;
            }
            v.extend([
                ("lend_lent", true, r[0]),
                ("reclaim_returned", false, r[1]),
                ("reclaim_evacs", false, r[2]),
                ("reclaim_evac_blocks", false, r[3]),
                ("reclaim_evac_fails", false, r[4]),
            ]);
        }
        // background work (adr 0021 am. 33, adr 0533): leaves compacted, defrag sweeps and moves, idle
        // recompaction of cut compressed chunks (blocks the old records held / the new chunks took), extent census of
        // the last complete sweep (`census_seq` = sum of the shards' sweep numbers; `request_census`)
        let df = self.defrag_stats();
        let leaves: u64 = self
            .shards
            .iter()
            .map(|s| s.sh.tree_stats().compacted)
            .sum();
        let rc = self.rc_stats();
        let (cs, cseq) = self.census();
        let mut ig = (0u64, 0u64, 0u64);
        // device admission window (adr 0643-device-admission-fifo): one window per device, counters per shard
        let (mut aw, mut ao, mut ast) = (0u64, 0u64, crate::admit::AdmitStats::default());
        for s in &self.shards {
            let g = s.sh.dev_idle_gauges();
            ig = (ig.0.max(g.0), ig.1 + g.1, ig.2 + g.2);
            let (w, o, st) = s.sh.admit_gauges();
            (aw, ao) = (aw.max(w), ao.max(o));
            ast += st;
        }
        v.extend([
            ("dev_idle_slots", true, ig.0),
            ("dev_idle_edges_published", false, ig.1),
            ("dev_idle_edges_seen", false, ig.2),
            ("adm_window_bytes", true, aw),
            ("adm_outstanding_bytes", true, ao),
            ("adm_waits", false, ast.waits),
            ("adm_free", false, ast.free),
            ("adm_probes", false, ast.probes),
            ("adm_grows", false, ast.grows),
            ("adm_shrinks", false, ast.shrinks),
            ("bg_compacted_leaves", false, leaves),
            ("defrag_sweeps", false, df.sweeps),
            ("defrag_cell_sweeps", false, df.cell_sweeps),
            ("defrag_moved_extents", false, df.moved_extents),
            ("defrag_moved_blocks", false, df.moved_blocks),
            // the drain of a cell sweep / evacuation has no deadline (adr 0021 S6): one that cannot end shows here
            ("defrag_drains_waiting", true, df.drain_waiting),
            ("defrag_drains_on_readers", true, df.drain_readers),
            ("defrag_drain_held_blocks", true, df.drain_held),
            (
                "defrag_drain_wait_max_ms",
                true,
                df.drain_wait_ns / 1_000_000,
            ),
            ("recompact_sweeps", false, rc.sweeps),
            ("recompact_chunks", false, rc.chunks),
            ("recompact_freed_blocks", false, rc.freed_blocks),
            ("recompact_new_blocks", false, rc.new_blocks),
            ("recompact_no_gain", false, rc.no_gain),
            ("recompact_skipped", false, rc.skipped),
            ("recompact_incomplete", false, rc.incomplete),
            ("recompact_overlaps", false, rc.overlaps),
            ("recompact_units", false, rc.units),
            ("recompact_gate_client", false, rc.gate_client),
            ("recompact_gate_gap", false, rc.gate_gap),
            ("recompact_gate_dev", false, rc.gate_dev),
            ("census_seq", true, cseq),
            ("census_objects", true, cs.objects),
            ("census_records", true, cs.records),
            ("census_plain_blocks", true, cs.plain_blocks),
            ("census_chunks", true, cs.chunks),
            ("census_chunk_blocks", true, cs.chunk_blocks),
            ("census_comp_logical_blocks", true, cs.comp_logical),
            ("census_windows", true, cs.windows),
            ("census_cut_chunks", true, cs.cut_chunks),
            ("census_cut_live_blocks", true, cs.cut_live),
            ("census_cut_span_blocks", true, cs.cut_span),
            ("census_unc_objects", true, cs.unc_objects),
            ("census_unc_records", true, cs.unc_records),
            ("census_unc_blocks", true, cs.unc_blocks),
        ]);
        // data cache (adr 0043 "Data cache"): blocks held, capacity, served reads, runs cached / evicted / dropped by frees,
        // moved to / back from the protected list
        let mut d = [0u64; 8];
        for s in &self.shards {
            d[0] += s.dc.blocks();
            d[1] += s.dc.cap();
            d[2] += s.dc.hits;
            d[3] += s.dc.inserts;
            d[4] += s.dc.evictions;
            d[5] += s.dc.forgets;
            d[6] += s.dc.promotions;
            d[7] += s.dc.demotions;
        }
        v.extend([
            ("data_cache_blocks", true, d[0]),
            ("data_cache_cap_blocks", true, d[1]),
            ("data_cache_hits", false, d[2]),
            ("data_cache_inserts", false, d[3]),
            ("data_cache_evictions", false, d[4]),
            ("data_cache_forgets", false, d[5]),
            ("data_cache_promotions", false, d[6]),
            ("data_cache_demotions", false, d[7]),
        ]);
        // tree page budget of the device's page pool (adr 0062 am. 3): pages this store's shards may cache, credits they
        // took from / gave to the pool, pages aged out to give them; CLOCK hand steps (the eviction pace it compares)
        let mut tp = [0u64; 5];
        for s in &self.shards {
            let (cap, st) = s.sh.page_gauges();
            tp[0] += cap;
            tp[1] += st.taken;
            tp[2] += st.given;
            tp[3] += st.aged;
            tp[4] += s.sh.tree_stats().hand_steps;
        }
        v.extend([
            ("tree_cache_cap_pages", true, tp[0]),
            ("tree_cache_taken_pages", false, tp[1]),
            ("tree_cache_given_pages", false, tp[2]),
            ("tree_cache_aged_pages", false, tp[3]),
            ("tree_hand_steps", false, tp[4]),
        ]);
        v
    }

    /// Operator `cache status`: cache counters and gauges `(name, value)` summed over the mounted shards (tree pages,
    /// data cache, decoded chunks, and the totals of the operator cache drops).
    pub fn cache_status(&self) -> Vec<(&'static str, u64)> {
        let mut a = [0u64; 13];
        for s in &self.shards {
            let t = s.sh.tree_stats();
            let m = s.sh.mem().tree;
            let v = [
                t.loads,
                t.evictions,
                t.hint_hits,
                m.pages,
                m.page_bytes,
                m.free_bytes,
                s.dc.blocks() * crate::BLK as u64,
                s.dcache.len() as u64,
                s.drops,
                s.dropped.tree_pages,
                s.dropped.tree_bytes,
                s.dropped.data_bytes,
                s.dropped.decomp_bytes + s.dropped.omap_run_bytes,
            ];
            for (x, y) in a.iter_mut().zip(v) {
                *x += y;
            }
        }
        [
            "tree_page_loads",
            "tree_page_evictions",
            "tree_hint_hits",
            "tree_pages",
            "tree_page_bytes",
            "tree_free_buffer_bytes",
            "data_cache_bytes",
            "decoded_chunks",
            "cache_drops",
            "dropped_tree_pages",
            "dropped_tree_bytes",
            "dropped_data_bytes",
            "dropped_other_bytes",
        ]
        .into_iter()
        .zip(a)
        .collect()
    }

    /// Operator `cache drop`: every mounted shard drops its clean caches ([`ShardStore::drop_caches`]); the sum.
    pub fn drop_caches(&mut self) -> CacheDropped {
        let mut a = CacheDropped::default();
        for s in &mut self.shards {
            let d = s.drop_caches();
            a.add(&d);
            a.tree_kept += d.tree_kept;
        }
        a
    }

    /// Page-load count of the collection's physical shard; unrelated cache misses do not make it cold.
    pub fn shard_page_loads(&self, cid: &CollT) -> Result<u64> {
        let si = self.local(self.shard_of(cid))?;
        Ok(self.shards[si].sh.tree_stats().loads)
    }

    /// Tree counters summed over the mounted shards (lab / bench).
    pub fn tree_stats(&self) -> crate::tree::TreeStats {
        let mut a = crate::tree::TreeStats::default();
        for s in &self.shards {
            let t = s.sh.tree_stats();
            a.loads += t.loads;
            a.scan_loads += t.scan_loads;
            a.scan_evictions += t.scan_evictions;
            a.evictions += t.evictions;
            a.splits += t.splits;
            a.grows += t.grows;
            a.pruned += t.pruned;
            a.locates += t.locates;
            a.descents += t.descents;
            a.hint_hits += t.hint_hits;
            a.dead_detached += t.dead_detached;
            a.dead_freed += t.dead_freed;
            a.dead_lost += t.dead_lost;
            a.delta_pages += t.delta_pages;
            a.delta_entries += t.delta_entries;
            a.delta_declined += t.delta_declined;
            a.declined_chain += t.declined_chain;
            a.declined_room += t.declined_room;
            a.delta_folded += t.delta_folded;
            a.relog_chains += t.relog_chains;
            a.relog_segs += t.relog_segs;
            a.fz_clean += t.fz_clean;
            a.fz_whole_leaves += t.fz_whole_leaves;
            a.fz_whole_ints += t.fz_whole_ints;
            a.merged += t.merged;
        }
        a
    }

    /// RAM accounting summed over the mounted shards.
    pub fn mem(&self) -> ShardMem {
        let mut a = ShardMem::default();
        for s in &self.shards {
            let m = s.sh.mem();
            let (t, u) = (&mut a.tree, &m.tree);
            t.pages += u.pages;
            t.page_bytes += u.page_bytes;
            t.touched_bytes += u.touched_bytes;
            t.touch_pool_bytes += u.touch_pool_bytes;
            t.slab_slots += u.slab_slots;
            t.slab_bytes += u.slab_bytes;
            t.free_slots += u.free_slots;
            t.free_bytes += u.free_bytes;
            t.chains += u.chains;
            t.chain_bytes += u.chain_bytes;
            t.dependency_bytes += u.dependency_bytes;
            t.dead += u.dead;
            t.retired += u.retired;
            a.point_entries += m.point_entries;
            a.point_bytes += m.point_bytes;
            a.alloc_bytes += m.alloc_bytes;
            a.alloc_chunks += m.alloc_chunks;
            a.alloc_pool_misses += m.alloc_pool_misses;
            a.free_q_extents += m.free_q_extents;
            a.limbo_extents += m.limbo_extents;
            a.ring_units += m.ring_units;
            a.pipeline_units += m.pipeline_units;
            a.pipeline_bytes += m.pipeline_bytes;
            a.read_map += m.read_map;
            a.ckpt_bytes += m.ckpt_bytes;
            a.run_entries += m.run_entries;
            a.run_bytes += m.run_bytes;
        }
        a
    }

    /// Unmount, keeping the clock (offline tools continue on the device).
    pub fn into_clock(self) -> C {
        self.clk
    }

    /// Force a checkpoint of every shard and wait (clean shutdown / tests).
    pub fn checkpoint(&mut self) -> Result<()> {
        self.sync()?;
        for s in &mut self.shards {
            s.checkpoint(&mut self.clk)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------ reads

    /// Does a queued (parked) txn of the shard name `cid` / `oid` (not visible yet)? Pure check: no run flag.
    fn parked_on(&mut self, cid: &CollT, oid: Option<&Ghobject>) -> Result<bool> {
        let si = self.local(self.shard_of(cid))?;
        if self.preparing.as_ref().is_some_and(|p| p.si == si) || self.parked[si].is_empty() {
            return Ok(false);
        }
        self.park_probes += 1;
        #[cfg(feature = "lab")]
        {
            use std::sync::atomic::Ordering::Relaxed;
            crate::dbg::PARK_SCANS.fetch_add(1, Relaxed);
            crate::dbg::PARK_ITEMS.fetch_add(1, Relaxed); // index lookup (adr 0021 am. 44)
        }
        self.visibility_key.clear();
        if let Some(o) = oid {
            self.visibility_key.extend_from_slice(&name_prefix(0));
            sort_key_into(&mut self.visibility_key, o);
        }
        let key = oid.map(|_| self.visibility_key.as_slice());
        let hit = self.parked[si].names(cid, key);
        debug_assert_eq!(
            hit,
            self.parked[si].iter().any(|p| {
                p.colls.contains(cid)
                    || p.objects
                        .iter()
                        .any(|(c, k)| c == cid && key.is_none_or(|v| v == k.as_slice()))
            }),
            "park index out of step"
        );
        Ok(hit)
    }

    /// A read behind a parked txn: refused in a nonblocking run (`take_blocked`), else the queue is drained first.
    fn visibility(&mut self, cid: &CollT, oid: Option<&Ghobject>) -> Result<()> {
        if self.parked_on(cid, oid)? {
            let si = self.local(self.shard_of(cid))?;
            if self.nb_reads {
                self.blocked = true;
                self.shards[si].rm_progress = true; // an admission wait must never force a blocking read fallback
                return Err(ObjError::WouldBlock);
            }
            self.drain_queued()?;
        }
        Ok(())
    }

    fn stage_object<R>(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        f: impl FnOnce(&mut Stage<'_, '_, D, C>) -> Result<R>,
    ) -> Result<R> {
        self.visibility(cid, Some(oid))?;
        self.stage(cid, f)
    }

    fn stage<R>(
        &mut self,
        cid: &CollT,
        f: impl FnOnce(&mut Stage<'_, '_, D, C>) -> Result<R>,
    ) -> Result<R> {
        let si = self.local(self.shard_of(cid))?;
        if !self.nb_reads {
            #[cfg(feature = "splinterdb")]
            self.shards[si].sh.splinter_begin_blocking_read();
            let r = f(&mut Stage::new(&mut self.shards[si], &mut self.clk));
            #[cfg(feature = "splinterdb")]
            self.shards[si].sh.splinter_end_blocking_read();
            #[cfg(feature = "splinterdb")]
            if self.shards[si].local_wait && matches!(r, Err(ObjError::WouldBlock)) {
                self.blocked = true;
                self.activate(si); // An IO fallback may encounter a local credit dependency.
            }
            if self.shards[si].sh.olsm_reads_pending() {
                self.activate(si);
            }
            return r;
        }
        self.shards[si].nonblock = true;
        let r = f(&mut Stage::new(&mut self.shards[si], &mut self.clk));
        self.shards[si].nonblock = false;
        if matches!(r, Err(ObjError::WouldBlock)) {
            self.blocked = true;
        }
        if matches!(r, Err(ObjError::WouldBlock)) || self.shards[si].sh.olsm_reads_pending() {
            self.activate(si); // demanded loads and successful listing hints must be polled
        }
        r
    }

    /// Non-blocking mode for every read call (`stat`, `read`, `getattr`, `omap_*`, ...): a tree page miss submits the page
    /// load and returns `WouldBlock` instead of spinning the core (ADR 0021 am. 11). The caller runs a whole op in this
    /// mode, drops its result when [`Store::take_blocked`] says a read was refused, and re-runs it after
    /// [`Store::take_wake`]. Uncached data uses completion-driven rolling submission too.
    pub fn set_nonblock_reads(&mut self, on: bool) {
        self.nb_reads = on;
    }

    /// The current run of an executor request (after [`Store::read_session`]) lists without CPU slice (adr 0021 S8): it
    /// holds later ops of its object, so ending a pass early only delays them (adr 0522). Cold leaves still refuse it.
    pub fn list_whole(&mut self) {
        for s in &mut self.shards {
            s.list_whole = true;
        }
    }

    /// Retain completed ranges across one executor request's retries; release on success/error.
    /// Abandoned requests expire with the prefetch TTL.
    pub fn read_session(&mut self, session: Option<(u64, u64)>, keep: bool) {
        for s in &mut self.shards {
            s.read_session(session, keep);
        }
    }

    /// Tree page loads of any shard are still in flight: a run refused by a cold page is better repeated when they are
    /// all in (one run per batch of parallel loads, not one per completed page).
    pub fn loads_pending(&self) -> bool {
        self.shards.iter().any(|s| s.sh.loads_pending())
    }

    /// Wait until no tree page load of any shard is in flight (after non-blocking probes that queued several: one wait
    /// for all of them). Acks reaped meanwhile stay queued for the next [`Store::poll`].
    pub fn wait_loads(&mut self) -> Result<()> {
        for s in &mut self.shards {
            if s.sh.loads_pending() {
                s.wait(&mut self.clk, |s| !s.sh.loads_pending())?;
            }
        }
        Ok(())
    }

    /// Did a read return `WouldBlock` since the last call?
    pub fn take_blocked(&mut self) -> bool {
        std::mem::take(&mut self.blocked)
    }
    /// The refused OMAP read needs another local request's ownership release.
    pub fn take_local_wait(&mut self) -> bool {
        #[cfg(feature = "splinterdb")]
        {
            self.shards
                .iter_mut()
                .fold(false, |p, s| p | std::mem::take(&mut s.local_wait))
        }
        #[cfg(not(feature = "splinterdb"))]
        {
            false
        }
    }

    pub fn coll_exists(&mut self, cid: &CollT) -> Result<bool> {
        if self
            .parked
            .iter()
            .any(|q| q.iter().any(|p| p.colls.contains(cid)))
        {
            self.list_visibility(cid)?; // a listing request (storeadapt `ov_list`) waits only for its barrier
        }
        self.stage(cid, |st| Ok(st.coll_info(cid)?.is_some()))
    }

    /// Per-collection counters (objects, bytes, compression), O(1): maintained in the collection record by every txn at
    /// staging (adr/0609-pgstats-counters). A snapshot of the staged state: txns still parked are not in it, so no queue barrier is taken
    /// (the periodic PG stats read must never drain the shard FIFO on the PG core); the next read counts them.
    pub fn coll_stats(&mut self, cid: &CollT) -> Result<Option<CollStats>> {
        self.stage(cid, |st| {
            Ok(st.coll_info(cid)?.map(|i| CollStats {
                bits: i.bits,
                nobj: i.nobj.max(0) as u64,
                nbytes: i.nbytes.max(0) as u64,
                comp: i.comp.max(0) as u64,
                comp_orig: i.comp_orig.max(0) as u64,
            }))
        })
    }

    /// Dedup records with keys in `[a, b)` of every shard of this store, merged in key order, at most `max` (adr
    /// 0593-dedup-deep-scrub-reformat). Each entry carries its device shard (prunes go back to it). `nonblock`: a tree
    /// page miss submits the load and returns `WouldBlock` (the shard is activated so the load is polled) instead of
    /// waiting on the core.
    #[expect(clippy::type_complexity)]
    pub fn dedup_scan(
        &mut self,
        a: &[u8],
        b: &[u8],
        max: usize,
        nonblock: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>, u32)>> {
        let mut out = Vec::new();
        for i in 0..self.shards.len() {
            if !self.shards[i].dedup {
                continue;
            }
            let shard = self.shards[i].idx;
            self.shards[i].nonblock = nonblock;
            let r = Stage::new(&mut self.shards[i], &mut self.clk).dedup_scan(a, b, max);
            self.shards[i].nonblock = false;
            if matches!(r, Err(ObjError::WouldBlock)) {
                self.activate(i);
            }
            out.extend(r?.into_iter().map(|(k, v)| (k, v, shard)));
        }
        out.sort_unstable_by(|x, y| x.0.cmp(&y.0));
        out.truncate(max);
        Ok(out)
    }

    /// Device shard ids of this store whose dedup records it may hold (`FEAT_DEDUP` durable).
    pub fn dedup_shards(&self) -> Vec<u32> {
        self.shards
            .iter()
            .filter(|s| s.dedup)
            .map(|s| s.idx)
            .collect()
    }

    pub fn list_colls(&mut self) -> Result<Vec<CollT>> {
        let mut out = Vec::new();
        for i in 0..self.shards.len() {
            let mut st = Stage::new(&mut self.shards[i], &mut self.clk);
            out.extend(st.scan_colls()?);
        }
        Ok(out)
    }

    pub fn stat(&mut self, cid: &CollT, oid: &Ghobject) -> Result<Option<ObjStat>> {
        self.stage_object(cid, oid, |st| {
            Ok(st.lookup(cid, oid)?.map(|id| ObjStat {
                size: st.obj_size(id),
            }))
        })
    }

    /// Data version of an object (adr 0593-dedup-deep-scrub-reformat): onode id, tracking generation of its collection
    /// and the object's data change counter. `Ok(None)`: no such object.
    pub fn data_version(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
    ) -> Result<Option<super::DataVersion>> {
        self.stage_object(cid, oid, |st| match st.lookup(cid, oid)? {
            Some(id) => Ok(Some(st.data_version(cid, id)?)),
            None => Ok(None),
        })
    }

    /// A refused run made progress since the last call: a listing admitted entries or ended its CPU slice, a data read
    /// was admitted (the engine does not charge such a refused run against its try bound and re-runs it on its next
    /// wake).
    pub fn take_rm_progress(&mut self) -> bool {
        self.shards
            .iter_mut()
            .fold(false, |p, s| p | std::mem::take(&mut s.rm_progress))
    }

    /// Non-blocking: are the tree pages a client op on `oid` (range `[off, off+len)`) needs resident? `false` = reads
    /// for the missing pages were submitted; retry after [`Store::take_wake`] says a load finished. Errors count as
    /// ready (the real op reports them). Never waits (thread-per-core, adr 0006).
    pub fn warm(&mut self, cid: &CollT, oid: &Ghobject, off: u64, len: u64) -> Result<bool> {
        if self.parked_on(cid, Some(oid))? {
            // the parked txn's submit wakes (`take_wake`); a probe never latches `blocked` (a later run would read
            // it as its own refusal and wait for a wake that never comes, adr 0043 am. 8)
            return Ok(false);
        }
        let si = self.local(self.shard_of(cid))?;
        Ok(self.nb_probe(si, |st| st.warm(cid, oid, off, len)))
    }

    /// [`Store::warm`] for a removal of `oid` (adr 0021 am. 33): every tree page the remove visits, read in parallel.
    /// `false` = reads submitted, retry after [`Store::take_wake`].
    pub fn warm_rm(&mut self, cid: &CollT, oid: &Ghobject) -> Result<bool> {
        if self.parked_on(cid, Some(oid))? {
            // the parked txn's submit wakes (`take_wake`); a probe never latches `blocked` (a later run would read
            // it as its own refusal and wait for a wake that never comes, adr 0043 am. 8)
            return Ok(false);
        }
        let si = self.local(self.shard_of(cid))?;
        Ok(self.nb_probe(si, |st| st.warm_rm(cid, oid)))
    }

    /// [`Store::warm`] for omap keys of one object (see `Stage::warm_omap`): `false` = reads submitted, retry after
    /// [`Store::take_wake`].
    pub fn warm_omap(&mut self, cid: &CollT, oid: &Ghobject, keys: &[&[u8]]) -> Result<bool> {
        if self.parked_on(cid, Some(oid))? {
            // the parked txn's submit wakes (`take_wake`); a probe never latches `blocked` (a later run would read
            // it as its own refusal and wait for a wake that never comes, adr 0043 am. 8)
            return Ok(false);
        }
        let si = self.local(self.shard_of(cid))?;
        Ok(self.nb_probe(si, |st| st.warm_omap(cid, oid, keys)))
    }

    /// Non-blocking data prefetch for a client read of `[off, off+len)` (call after [`Store::warm`] said ready):
    /// submits the device reads of its committed blocks. `false` = reads in flight, retry after [`Store::take_wake`].
    /// The real [`Store::read`] then finds the data without waiting on the device (ADR 0043).
    pub fn warm_data(&mut self, cid: &CollT, oid: &Ghobject, off: u64, len: u64) -> Result<bool> {
        if self.parked_on(cid, Some(oid))? {
            // the parked txn's submit wakes (`take_wake`); a probe never latches `blocked` (a later run would read
            // it as its own refusal and wait for a wake that never comes, adr 0043 am. 8)
            return Ok(false);
        }
        let si = self.local(self.shard_of(cid))?;
        Ok(self.nb_probe(si, |st| st.warm_data(cid, oid, off, len)))
    }

    /// [`Store::warm_data`] for the source of a `clone_range` of `[off, off+len)` to the same offset (EC stash, adr 0021
    /// am. 38): a range the clone shares needs no data read, only unaligned edges or an ineligible range are prefetched.
    pub fn warm_clone_src(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        off: u64,
        len: u64,
    ) -> Result<bool> {
        if self.parked_on(cid, Some(oid))? {
            // the parked txn's submit wakes (`take_wake`); a probe never latches `blocked` (a later run would read
            // it as its own refusal and wait for a wake that never comes, adr 0043 am. 8)
            return Ok(false);
        }
        let si = self.local(self.shard_of(cid))?;
        Ok(self.nb_probe(si, |st| st.warm_clone_src(cid, oid, off, len)))
    }

    /// Run a non-blocking residency probe on shard `si` (`warm*`): `true` = resident (errors count as resident, the real op
    /// reports them). Under a lease ([`Store::lease_use`]) the pages it missed are pinned and the prefetch runs it found or
    /// submitted are held for the lease.
    fn nb_probe(
        &mut self,
        si: usize,
        f: impl FnOnce(&mut Stage<'_, '_, D, C>) -> Result<()>,
    ) -> bool {
        self.activate(si);
        let lease = self.lease_cur;
        let leased = lease != 0 && self.leases.get(&lease).is_some_and(|l| l.0 == si);
        let sh = &mut self.shards[si];
        sh.nonblock = true;
        if leased {
            sh.lease = lease;
            let buf = std::mem::take(&mut sh.pin_scratch);
            sh.sh.pin_log(Some(buf));
        }
        let r = f(&mut Stage::new(&mut self.shards[si], &mut self.clk));
        let sh = &mut self.shards[si];
        sh.nonblock = false;
        if leased {
            let mut missed = sh.sh.pin_log(None).unwrap_or_default();
            sh.lease_pin_pages(lease, &missed);
            missed.clear();
            sh.pin_scratch = missed;
            sh.lease = 0;
        }
        !matches!(r, Err(ObjError::WouldBlock))
    }

    /// Open a residency lease for an op of collection `cid` that waits for its loads (adr 0043 am. 18): the probes run
    /// under it ([`Store::lease_use`]) pin the tree pages they missed and hold the data prefetch runs they found or
    /// submitted until [`Store::lease_release`], so a completed load cannot be evicted or expire before the op uses it;
    /// a refused prefetch admission keeps its place in the queue and is woken when capacity frees.
    pub fn lease_open(&mut self, cid: &CollT) -> Result<u64> {
        let si = self.local(self.shard_of(cid))?;
        self.lease_next += 1;
        let id = self.lease_next;
        self.leases.insert(id, (si, *cid));
        self.shards[si].lease_open(id);
        Ok(id)
    }

    /// The lease of the `warm*` probes that follow (0 = none).
    pub fn lease_use(&mut self, id: u64) {
        self.lease_cur = id;
    }

    /// Release lease `id` (the op consumed its data or is gone); unknown ids are ignored.
    pub fn lease_release(&mut self, id: u64) {
        if let Some((si, _)) = self.leases.remove(&id) {
            self.shards[si].lease_release(id);
            self.activate(si);
        }
        if self.lease_cur == id {
            self.lease_cur = 0;
        }
    }

    /// Release every lease of collection `cid` (interval change, PG teardown).
    pub fn lease_release_coll(&mut self, cid: &CollT) {
        let ids: Vec<u64> = self
            .leases
            .iter()
            .filter(|(_, (_, c))| c == cid)
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            self.lease_release(id);
        }
    }

    /// Open residency leases (tests, diagnostics).
    pub fn leases_open(&self) -> usize {
        self.leases.len()
    }

    /// Driver wake for work completed off the owner thread (RocksDB OMAP workers): called after each published completion,
    /// from any thread. Install once per core after mount; without it the owner relies on its idle cap.
    pub fn set_owner_wake(&self, w: std::sync::Arc<dyn Fn() + Send + Sync>) {
        #[cfg(feature = "rocksdb")]
        for s in &self.shards {
            s.sh.rocks_set_owner_wake(crate::rocks_omap::OwnerWake(w.clone()));
        }
        #[cfg(feature = "splinterdb")]
        for s in &self.shards {
            s.sh.splinter_set_owner_wake(crate::splinter_omap::OwnerWake(w.clone()));
        }
        #[cfg(not(any(feature = "rocksdb", feature = "splinterdb")))]
        let _ = w;
    }

    /// A completion published by an off-owner worker waits for [`poll`](Self::poll): the driver's idle re-check after it
    /// announced its sleep (pairs with [`set_owner_wake`](Self::set_owner_wake); no lost wake).
    pub fn handed_completion(&self) -> bool {
        let rocks = {
            #[cfg(feature = "rocksdb")]
            {
                self.shards.iter().any(|s| s.sh.rocks_has_completion())
            }
            #[cfg(not(feature = "rocksdb"))]
            {
                false
            }
        };
        let splinter = {
            #[cfg(feature = "splinterdb")]
            {
                self.shards.iter().any(|s| s.sh.splinter_has_completion())
            }
            #[cfg(not(feature = "splinterdb"))]
            {
                false
            }
        };
        rocks || splinter
    }

    /// No shard has work queued, in flight, loading or checkpointing (as of the last [`poll`](Self::poll)); time-driven
    /// work waits for the next sweep (`SWEEP_NS` after the last one), so a caller may sleep up to that long.
    pub fn quiet(&self) -> bool {
        #[cfg(feature = "elastic")]
        if self.pool.as_ref().is_some_and(|p| p.busy()) || !self.lend_out.is_empty() {
            return false;
        }
        self.active.is_empty()
    }

    /// A tree page load, prefetch run or other store progress finished since the last call (ops parked on
    /// [`Store::warm`] may run).
    pub fn take_wake(&mut self) -> bool {
        let t = !self.wtoks.is_empty();
        self.wtoks.clear();
        std::mem::take(&mut self.woke) || t
    }

    /// [`Store::take_wake`] with the specific part: `out` gets the tokens of the page loads and prefetch runs that
    /// completed (wake only the probes that logged them, see [`Store::cause_take`]); `true` in `all` = something else
    /// changed or the token set overflowed: wake every probe. Returns whether anything woke.
    pub fn take_wake_set(&mut self, out: &mut crate::toks::Toks<32>, all: &mut bool) -> bool {
        let t = !self.wtoks.is_empty();
        out.merge(&self.wtoks);
        *all |= std::mem::take(&mut self.woke) || self.wtoks.overflowed();
        self.wtoks.clear();
        t || *all
    }

    /// Start collecting what the next probe (`warm*`, a refused read run) waits on.
    pub fn cause_begin(&mut self) {
        for s in &mut self.shards {
            s.cause_begin();
        }
    }

    /// What the probes since [`Store::cause_begin`] waited on: tree pages missed and prefetch runs in flight.
    /// Empty or overflowed = unknown (the caller must wake the probe on every wake).
    pub fn cause_take(&self, out: &mut crate::toks::Toks<8>) {
        for s in &self.shards {
            s.cause_collect(out);
        }
    }

    /// Wake / prefetch / durability state of every shard (diagnostics).
    pub fn diag(&self) -> String {
        let sh: Vec<String> = self
            .shards
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let head = self.parked[i].front().map(|p| {
                    let deps = s.sh.state().tree.dependencies.readiness(p.token);
                    format!(
                        " head[blocked={} at={}:{} stalled_since={:?} deadline={} deps={deps:?} progress_now={:?}]",
                        p.blocked.0,
                        p.blocked.1,
                        p.blocked.2,
                        p.stall.map(|(t, _)| t),
                        p.deadline,
                        self.queue_progress(i),
                    )
                });
                format!(
                    "s{i}[active={} queued={} prepared={} progress={:?} tried={:?}{} {}]",
                    self.is_active[i],
                    self.parked[i].len(),
                    self.parked[i].front().is_some_and(|p| p.ready.is_some()),
                    self.prep[i].as_ref().map(|p| p.parts.progress()),
                    self.parked[i].front().and_then(|p| p.tried),
                    head.unwrap_or_default(),
                    s.diag()
                )
            })
            .collect();
        format!(
            "store woke={} blocked={} {}",
            self.woke,
            self.blocked,
            sh.join(" ")
        )
    }

    pub fn exists(&mut self, cid: &CollT, oid: &Ghobject) -> Result<bool> {
        Ok(self.stat(cid, oid)?.is_some())
    }

    /// Read `[off, off+len)`, clamped to the object size (checksums verified; mismatch = `Eio`).
    pub fn read(&mut self, cid: &CollT, oid: &Ghobject, off: u64, len: u64) -> Result<Vec<u8>> {
        self.read_crc(cid, oid, off, len).map(|(d, _)| d)
    }

    /// Completion-driven media read for scrub. A private session retains only this slice's
    /// physical snapshot across retries; success/error releases it. Never serve a client cache.
    pub fn read_media_async(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        off: u64,
        len: u64,
        session: u64,
    ) -> Result<Vec<u8>> {
        self.read_media_async_crc(cid, oid, off, len, session)
            .map(|r| r.0)
    }

    /// [`Store::read_media_async`] plus the crc32c (seed `!0`) of the returned bytes when the verified block crcs give it
    /// without another pass ([`Store::read_crc`]): deep scrub joins its data digest from it (adr 0061 am. 4).
    pub fn read_media_async_crc(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        off: u64,
        len: u64,
        session: u64,
    ) -> Result<(Vec<u8>, Option<u32>)> {
        let si = self.local(self.shard_of(cid))?;
        let old_session = self.shards[si].session_context();
        self.shards[si].read_session(Some((MEDIA_SESSION, session)), true);
        let old_media = self.shards[si].media;
        self.shards[si].media = true;
        let old = self.begin_nonblock();
        let result = self.read_crc(cid, oid, off, len);
        self.end_nonblock(old);
        self.shards[si].media = old_media;
        self.shards[si].read_session(None, matches!(result, Err(ObjError::WouldBlock)));
        self.shards[si].restore_session(old_session);
        result
    }

    /// Cancel a scrub snapshot after an object/version change. In-flight commands keep
    /// their own pins and DMA accounting until completion.
    pub fn cancel_media_read(&mut self, cid: &CollT, session: u64) -> Result<()> {
        let si = self.local(self.shard_of(cid))?;
        let old = self.shards[si].session_context();
        self.shards[si].read_session(Some((MEDIA_SESSION, session)), true);
        self.shards[si].read_session(None, false);
        self.shards[si].restore_session(old);
        Ok(())
    }

    /// [`Store::read`] plus the crc32c (seed `!0`, as the msgr2 data segment) of the returned bytes when it is known
    /// without another pass: the range was whole blocks, all read from verified committed blocks.
    pub fn read_crc(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        off: u64,
        len: u64,
    ) -> Result<(Vec<u8>, Option<u32>)> {
        self.stage_object(cid, oid, |st| {
            let id = st.lookup(cid, oid)?.ok_or(ObjError::NoEnt)?;
            let size = st.obj_size(id);
            if off >= size || len == 0 {
                return Ok((Vec::new(), None));
            }
            let len = len.min(size - off);
            st.read_crc = None;
            let d = st.read_eff_bytes(id, off, len)?;
            Ok((d, st.read_crc))
        })
    }

    /// [`Store::read_crc`] as shared pieces in order (the data is their concatenation), each with the crc32c (seed `!0`)
    /// of exactly its bytes when known without a pass. Device / prefetch buffers of plain committed data go by reference
    /// (no copy; checksums verified as on every read, [`Stage::read_eff_shared`]). Empty = nothing to read.
    pub fn read_shared(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        off: u64,
        len: u64,
    ) -> Result<Vec<(bytes::Bytes, Option<u32>)>> {
        self.read_shared_inner(cid, oid, off, len, false)
            .map(|read| read.parts)
    }

    fn read_shared_inner(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        off: u64,
        len: u64,
        verified: bool,
    ) -> Result<super::SharedRead> {
        // Draining a parked mutation can change the LSN and invalidate a previously cached probe.
        self.visibility(cid, Some(oid))?;
        // the probe of this very read found its range in the data cache: no second lookup of the object and its extents
        let hot = match self.local(self.shard_of(cid)) {
            Ok(si) => {
                let s = &mut self.shards[si];
                let lsn = s.sh.next_lsn();
                s.hot.take().filter(|h| h.serves(lsn, cid, oid, off, len))
            }
            Err(_) => None,
        };
        self.stage(cid, |st| {
            if let Some(h) = hot {
                return st.read_eff_shared_hot(h, verified);
            }
            let id = st.lookup(cid, oid)?.ok_or(ObjError::NoEnt)?;
            let size = st.obj_size(id);
            if off >= size || len == 0 {
                return Ok(super::SharedRead {
                    parts: Vec::new(),
                    block_crcs: verified.then(Vec::new),
                });
            }
            if verified {
                st.read_eff_shared_verified(id, off, len.min(size - off))
            } else {
                st.read_eff_shared(id, off, len.min(size - off))
                    .map(|parts| super::SharedRead {
                        parts,
                        block_crcs: None,
                    })
            }
        })
    }

    /// Placement candidate variant of [`Self::read_shared`]. For plain shared
    /// source ranges, aligned reads reuse the exact verified device block CRCs.
    /// Shifted grids derive CRCs from those same blocks and the shorter source
    /// edges; a partial tail
    /// hashes at most one additional block. Payload owners stay shared. Counters
    /// distinguish shifted range bytes from newly hashed bytes. Sources outside
    /// the shared plain path have no sidecar; ordinary SEND callers incur no
    /// sidecar or reblocking.
    pub fn read_shared_verified(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        off: u64,
        len: u64,
    ) -> Result<super::SharedRead> {
        self.read_shared_inner(cid, oid, off, len, true)
    }

    pub fn getattr(&mut self, cid: &CollT, oid: &Ghobject, name: &[u8]) -> Result<Option<Vec<u8>>> {
        self.stage_object(cid, oid, |st| {
            let id = st.lookup(cid, oid)?.ok_or(ObjError::NoEnt)?;
            st.get_val(id, Slot::Attr, name)
        })
    }

    /// Two attributes of one object with a single name lookup (the op executor loads `_` and `snapset` together).
    #[allow(clippy::type_complexity)]
    pub fn getattr_pair(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        a: &[u8],
        b: &[u8],
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        self.stage_object(cid, oid, |st| {
            let id = st.lookup(cid, oid)?.ok_or(ObjError::NoEnt)?;
            let x = st.get_val(id, Slot::Attr, a)?;
            let y = st.get_val(id, Slot::Attr, b)?;
            Ok((x, y))
        })
    }

    pub fn getattrs(&mut self, cid: &CollT, oid: &Ghobject) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        self.stage_object(cid, oid, |st| {
            let id = st.lookup(cid, oid)?.ok_or(ObjError::NoEnt)?;
            Ok(st
                .scan_vals(id, Slot::Attr, b"", usize::MAX - 1)?
                .0
                .into_iter()
                .collect())
        })
    }

    pub fn omap_header(&mut self, cid: &CollT, oid: &Ghobject) -> Result<Vec<u8>> {
        self.stage_object(cid, oid, |st| {
            let id = st.lookup(cid, oid)?.ok_or(ObjError::NoEnt)?;
            Ok(st.get_val(id, Slot::Hdr, b"")?.unwrap_or_default())
        })
    }

    pub fn omap_get(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        keys: &[&[u8]],
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        self.stage_object(cid, oid, |st| {
            let id = st.lookup(cid, oid)?.ok_or(ObjError::NoEnt)?;
            Ok(st.get_vals(id, Slot::Omap, keys)?.into_iter().collect())
        })
    }

    /// Omap entries with key `>= from` (ascending), at most `max`; the flag says more follow.
    pub fn omap_iter(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        from: &[u8],
        max: usize,
    ) -> Result<(KvList, bool)> {
        self.stage_object(cid, oid, |st| {
            let id = st.lookup(cid, oid)?.ok_or(ObjError::NoEnt)?;
            st.scan_vals(id, Slot::Omap, from, max)
        })
    }

    /// Budgeted committed-view scan, inclusive `from`, restricted to `prefix`.
    /// `values = false` emits empty value vectors and budgets serialized keys (4 + key length).
    #[allow(clippy::too_many_arguments)]
    pub fn omap_range(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        from: &[u8],
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        values: bool,
    ) -> Result<(KvList, bool)> {
        self.stage_object(cid, oid, |st| {
            let id = st.lookup(cid, oid)?.ok_or(ObjError::NoEnt)?;
            st.scan_omap_range(id, from, prefix, max, max_bytes, values)
        })
    }

    /// [`Store::omap_range`] encoded for a listing reply in one pass from the tree leaves: `head` reserved zero bytes,
    /// then per entry `le32 key length, key` and, with `values`, `le32 value length, value` (the entries of a denc
    /// `map<string, bufferlist>` / `set<string>`). Returns `(buffer, entries, more)`; the buffer has room for one more
    /// byte.
    #[allow(clippy::too_many_arguments)]
    pub fn omap_list_enc(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        from: &[u8],
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        values: bool,
        head: usize,
    ) -> Result<(Vec<u8>, usize, bool)> {
        self.stage_object(cid, oid, |st| {
            let id = st.lookup(cid, oid)?.ok_or(ObjError::NoEnt)?;
            st.scan_omap_enc(id, from, prefix, max, max_bytes, values, head)
        })
    }

    /// [`Store::omap_range`] as a complete immutable listing reply: `le32` count,
    /// entries encoded as [`Store::omap_list_enc`], then a one-byte `more` flag.
    /// Result bytes survive session cancellation, mutation and Store destruction.
    /// Request-scoped RocksDB retries may share that ownership.
    #[allow(clippy::too_many_arguments)]
    pub fn omap_list_reply(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        from: &[u8],
        prefix: &[u8],
        max: usize,
        max_bytes: usize,
        values: bool,
    ) -> Result<Bytes> {
        self.stage_object(cid, oid, |st| {
            let id = st.lookup(cid, oid)?.ok_or(ObjError::NoEnt)?;
            st.scan_omap_reply(id, from, prefix, max, max_bytes, values)
        })
    }

    /// Recovery's strict byte cutoff and first-oversized-entry rule; `next` is the first
    /// unreturned key (inclusive), without materializing that key's value.
    pub fn omap_recovery_range(
        &mut self,
        cid: &CollT,
        oid: &Ghobject,
        from: &[u8],
        max: usize,
        max_bytes: u64,
    ) -> Result<(KvList, Option<Vec<u8>>)> {
        self.stage_object(cid, oid, |st| {
            let id = st.lookup(cid, oid)?.ok_or(ObjError::NoEnt)?;
            st.scan_omap_recovery(
                id,
                from,
                max,
                usize::try_from(max_bytes).unwrap_or(usize::MAX),
            )
        })
    }

    /// All omap entries (convenience for tests/recovery of small objects).
    pub fn omap_all(&mut self, cid: &CollT, oid: &Ghobject) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        Ok(self
            .omap_iter(cid, oid, b"", usize::MAX - 1)?
            .0
            .into_iter()
            .collect())
    }

    /// Objects of `cid` in Ceph hobject order from `begin` (inclusive) up to `end` (exclusive, `None` = all):
    /// at most `max`, plus the next object to continue from (`None` = exhausted).
    pub fn list(
        &mut self,
        cid: &CollT,
        begin: &Ghobject,
        end: Option<&Ghobject>,
        max: usize,
    ) -> Result<(Vec<Ghobject>, Option<Ghobject>)> {
        self.list_visibility(cid)?;
        self.stage(cid, |st| st.list(cid, begin, end, max))
    }

    /// [`Store::visibility`] of a whole collection for a listing. A non-blocking run of an executor request (adr 0021 S8)
    /// waits only for the txns parked when the request first listed (its barrier, kept for the request): writes that
    /// arrive while it lists are concurrent with it (not acked when it started), and waiting for them could starve a
    /// listing under a steady write stream. Any other caller drains every parked txn of the collection first.
    fn list_visibility(&mut self, cid: &CollT) -> Result<()> {
        let si = self.local(self.shard_of(cid))?;
        let session = self.shards[si].session_context();
        let (true, Some(session)) = (self.nb_reads, session) else {
            return self.visibility(cid, None);
        };
        if self.preparing.as_ref().is_some_and(|p| p.si == si) {
            return Ok(());
        }
        let now = self.parked[si].seq;
        let barrier = self.shards[si].list_barrier(session, now);
        if self.parked[si].names_before(cid, barrier) {
            self.blocked = true;
            self.shards[si].rm_progress = true; // an admission wait must never force a blocking read fallback
            return Err(ObjError::WouldBlock);
        }
        Ok(())
    }

    /// Deep-scrub read path: verifies every block checksum and computes the object digests.
    pub fn scrub(&mut self, cid: &CollT, oid: &Ghobject, seed: u32) -> Result<ScrubResult> {
        self.stage_object(cid, oid, |st| {
            let id = st.lookup(cid, oid)?.ok_or(ObjError::NoEnt)?;
            st.scrub_obj(id, seed)
        })
    }

    /// `(size mkfs recorded, size of the device now)` when the device is smaller than at mkfs: data may lie beyond its
    /// end (classic BLUESTORE_DISK_SIZE_MISMATCH: free list bigger than the device). A grown device is no mismatch.
    pub fn size_mismatch(&self) -> Option<(u64, u64)> {
        let dev = self.shards.iter().map(|s| s.dev_bytes).min()?;
        size_shrunk(self.sb.size_bytes, dev)
    }

    /// Free (allocatable) blocks of the mounted shards: `(first block, blocks)`, ascending, touching runs merged.
    /// Offline use (free-space report): reserved and held blocks count as in use, runs a deallocate holds as free.
    pub fn free_extents(&self) -> Vec<(u64, u64)> {
        let mut v = Vec::new();
        for s in &self.shards {
            s.sh.for_each_free(|b, n| v.push((b, n)));
        }
        crate::report::merge_extents(&mut v);
        v
    }

    /// Data capacity of the mounted shards in blocks (extents of device expansions included).
    pub fn data_blocks(&self) -> u64 {
        self.shards
            .iter()
            .map(|s| s.sh.state().alloc.usable_len())
            .sum()
    }

    /// Capacity as the OSD reports it (full ratios are computed from `total - avail`). Per shard the binding
    /// resource counts: data (`used`; held blocks count as free, an ENOSPC-bound alloc forces the checkpoint that releases them) or meta (tree
    /// pages beyond the reserve and the COW headroom), whichever is fuller; the shard's whole capacity is charged
    /// at that fill, so a metadata-bound shard reads "full" long before its data region is (ADR 0021 amendment 4).
    pub fn statfs(&self) -> StoreStatfs {
        let mut r = StoreStatfs::default();
        for s in &self.shards {
            let f = s.sh.statfs();
            let fill = f.fill_ratio();
            let used = (fill * f.data_blocks as f64) as u64;
            r.total_bytes += f.data_blocks * BLK as u64;
            r.used_bytes += used * BLK as u64;
            r.real_used_bytes += f.used_blocks() * BLK as u64;
            r.real_meta_bytes += f.meta_in_data_bytes();
            r.avail_bytes += (f.data_blocks - used) * BLK as u64;
            r.held_bytes += f.data_held * BLK as u64;
            r.meta_used_pages += f.meta_used;
            r.meta_used_bytes += f.meta_used * f.meta_bpp * BLK as u64;
            r.meta_total_pages += f.meta_pages;
            r.omap_bytes += f.omap_bytes;
            r.fullest_shard_pct = r
                .fullest_shard_pct
                .max(100.0 * f.pooled_fill_ratio() as f32);
        }
        #[cfg(feature = "elastic")]
        if self.lend_on {
            r.pooled = true;
            // free pool chunks are capacity nobody uses yet: the owner counts them once for the device
            if let Some(l) = self.lend.as_ref() {
                let b = l.free_chunks() * l.geom.chunk * BLK as u64;
                r.total_bytes += b;
                r.avail_bytes += b;
            }
        }
        r
    }

    /// Migration headroom (adr 0031 am. 4): reserve `bytes` on device shard `shard` for a PG copy moving in. False = no
    /// room now (or the shard is not mounted here); nothing is held then.
    pub fn mig_hold(&mut self, shard: u32, bytes: u64) -> bool {
        let Ok(i) = self.local(shard as usize) else {
            return false;
        };
        self.shards[i].sh.mig_hold(bytes.div_ceil(BLK as u64))
    }

    /// Elastic pool: `bytes` the deferred moves into device shard `shard` need (0 = none): the shard borrows chunks
    /// until its migration room covers them (adr 0031 am. 4). Set again periodically while deferred: a shard whose
    /// pool request was denied asks again after the retry delay.
    #[cfg(feature = "elastic")]
    pub fn mig_want(&mut self, shard: u32, bytes: u64) {
        if let Ok(i) = self.local(shard as usize) {
            self.shards[i].sh.set_mig_want(bytes.div_ceil(BLK as u64));
            if bytes > 0 {
                self.activate(i);
            }
        }
    }

    /// Give back `bytes` of migration headroom on device shard `shard`.
    pub fn mig_unhold(&mut self, shard: u32, bytes: u64) {
        if let Ok(i) = self.local(shard as usize) {
            self.shards[i].sh.mig_unhold(bytes.div_ceil(BLK as u64));
        }
    }

    /// `(device shard, bytes a PG copy could still reserve)` of every shard mounted here.
    pub fn mig_rooms(&self) -> Vec<(u32, u64)> {
        self.shards
            .iter()
            .map(|s| (s.idx, s.sh.mig_room() * BLK as u64))
            .collect()
    }

    /// Admission preflight for a client txn of about `bytes` payload setting or removing `entries` tree entries (omap keys,
    /// xattrs) in the shard of `c` (ADR 0021 amendment 6, 45):
    /// true iff it fits WITHOUT touching the hard data reserve or the meta reserve (held blocks count as free, the
    /// forced checkpoint on the alloc path releases them). Callers admit with this, then apply the txn as
    /// `OTxn::sys`, so an admitted txn can only fail once the reserves are gone.
    pub fn write_room(&self, c: &CollT, bytes: u64, entries: u64) -> bool {
        self.room(c, bytes, entries, AllocClass::User)
    }

    /// [`Self::write_room`] for a txn this OSD must apply without a client admission of its own (replica write, EC
    /// sub-write, recovery push; adr 0021 S4): true iff it fits above the SYSTEM floors (a third of the reserves) its
    /// `OTxn::sys` apply stops at. False = applying it now would end in NoSpace (fail-stop): the caller holds it,
    /// nothing applied, and asks again after store progress.
    pub fn apply_room(&self, c: &CollT, bytes: u64, entries: u64) -> bool {
        self.room(c, bytes, entries, AllocClass::Sys)
    }

    /// `class`: what the txn is applied as (client admission: `User`; an `OTxn::sys` apply: `Sys`).
    fn room(&self, c: &CollT, bytes: u64, entries: u64, class: AllocClass) -> bool {
        // not mounted here (wrong core): refuse, the caller must route the op to the owning core
        let Ok(i) = self.local(self.shard_of(c)) else {
            return false;
        };
        let v = self.shards[i].sh.room_view(class);
        space::fits(&v, self.parked[i].rsv, Cost::of(Ask { bytes, entries }))
    }
}

/// Counter names of the commit-latency log2 us buckets (`perf_counters`).
const CM_NAMES: [(&str, &str, &str); 20] = [
    ("cm_lat_b00", "cm_wal_b00", "cm_data_b00"),
    ("cm_lat_b01", "cm_wal_b01", "cm_data_b01"),
    ("cm_lat_b02", "cm_wal_b02", "cm_data_b02"),
    ("cm_lat_b03", "cm_wal_b03", "cm_data_b03"),
    ("cm_lat_b04", "cm_wal_b04", "cm_data_b04"),
    ("cm_lat_b05", "cm_wal_b05", "cm_data_b05"),
    ("cm_lat_b06", "cm_wal_b06", "cm_data_b06"),
    ("cm_lat_b07", "cm_wal_b07", "cm_data_b07"),
    ("cm_lat_b08", "cm_wal_b08", "cm_data_b08"),
    ("cm_lat_b09", "cm_wal_b09", "cm_data_b09"),
    ("cm_lat_b10", "cm_wal_b10", "cm_data_b10"),
    ("cm_lat_b11", "cm_wal_b11", "cm_data_b11"),
    ("cm_lat_b12", "cm_wal_b12", "cm_data_b12"),
    ("cm_lat_b13", "cm_wal_b13", "cm_data_b13"),
    ("cm_lat_b14", "cm_wal_b14", "cm_data_b14"),
    ("cm_lat_b15", "cm_wal_b15", "cm_data_b15"),
    ("cm_lat_b16", "cm_wal_b16", "cm_data_b16"),
    ("cm_lat_b17", "cm_wal_b17", "cm_data_b17"),
    ("cm_lat_b18", "cm_wal_b18", "cm_data_b18"),
    ("cm_lat_b19", "cm_wal_b19", "cm_data_b19"),
];

#[cfg(test)]
mod mem_tests {
    use super::*;

    #[test]
    fn for_memory_scales_caches() {
        let d = StoreCfg::default().shard;
        // classic default: 4 GiB target - 768 MiB base over 32 shards: pages + point cache (~256 B/entry) + delta cap
        // fit the shard share (adr 0062 am. 1)
        let share = (4096u64 - 768) << 20;
        let c = StoreCfg::for_memory(share, 32).unwrap().shard;
        let used = (c.cache_pages + c.dirty_soft_pages) as u64 * 8192
            + c.point_cache as u64 * 256
            + c.delta_cap_bytes as u64;
        // the data cache floor (1/16 of a share below 512 MiB) is reserved first (adr 0633-data-cache-envelope)
        let tree_share = share / 32 - share / 32 / 16;
        assert!(
            used <= tree_share && used > tree_share * 95 / 100,
            "{used} vs {tree_share}"
        );
        assert!(c.cache_pages < d.cache_pages);
        assert_eq!(c.dirty_soft_pages, c.cache_pages / 8);
        assert_eq!(c.dirty_hard_pages, c.cache_pages * 3 / 8);
        assert!(StoreCfg::for_memory(1 << 20, 32).is_err());
        // big budget: more cache, more point cache
        let b = StoreCfg::for_memory(64 << 30, 32).unwrap().shard;
        assert!(b.cache_pages > 4 * d.cache_pages && b.point_cache > d.point_cache);
        // a cache sized by pages gets the run budget of the share that yields those pages
        let r = run_soft_for_pages(b.cache_pages);
        assert!(
            r <= b.run_soft_bytes && r > b.run_soft_bytes / 100 * 99,
            "{r} vs {}",
            b.run_soft_bytes
        );
        // other fields untouched
        assert_eq!(c.max_unit_blocks, 64);
        // the shard count divides the budget (no clamp in between), each shard reserves its data cache floor (32 MiB at
        // these shares); 0 shards = 1
        let (s4, s8) = (
            StoreCfg::for_memory(16 << 30, 4).unwrap().shard,
            StoreCfg::for_memory((16 << 30) + 4 * DATA_FLOOR_BYTES, 8)
                .unwrap()
                .shard,
        );
        assert!(s4.cache_pages.abs_diff(2 * s8.cache_pages) <= 2);
        assert_eq!(
            StoreCfg::for_memory(share, 0).unwrap().shard.cache_pages,
            StoreCfg::for_memory(share, 1).unwrap().shard.cache_pages
        );
        assert!(StoreCfg::for_memory(128 << 20, 1).is_ok());
        for n in [4u32, 32, 64] {
            assert!(StoreCfg::for_memory(128 << 20, n).is_err());
        }
    }

    /// The data cache floor never raises the minimum budget: a budget is accepted exactly when its shard share holds the
    /// smallest tree (4096 pages + dirty marks + point cache + delta chains = 42 MiB, the minimum before the floor
    /// existed), and the floor shrinks with the share (1/16, at most what the share holds above the smallest tree;
    /// adr 0633-data-cache-envelope).
    #[test]
    fn the_data_floor_never_raises_the_minimum_budget() {
        const MIN_SHARE: u64 = 42 << 20;
        for n in [1u32, 2, 4, 8, 32] {
            for mib in 0..=(n as u64 * 96) {
                for budget in [mib << 20, (mib << 20) - u64::from(mib > 0)] {
                    let r = StoreCfg::for_memory(budget, n);
                    let share = budget / n as u64;
                    // main's rule before the floor: the share holds the tree sized from all of it
                    let mut m = StoreCfg::default().shard;
                    assert_eq!(
                        size_tree(&mut m, share) <= share,
                        share >= MIN_SHARE,
                        "share {share}"
                    );
                    assert_eq!(r.is_ok(), share >= MIN_SHARE, "budget {budget} shards {n}");
                    if let Ok(c) = r {
                        let s = c.shard;
                        let floor = s.data_floor_blocks * BLK as u64;
                        let want = DATA_FLOOR_BYTES.min(share / 16).min(share - MIN_SHARE);
                        assert_eq!(floor / BLK as u64, want / BLK as u64);
                        let used = (s.cache_pages + s.dirty_soft_pages) as u64 * 8192
                            + s.point_cache as u64 * 256
                            + s.delta_cap_bytes as u64;
                        assert!(
                            used + floor <= share,
                            "budget {budget} shards {n}: {used} + {floor} > {share}"
                        );
                    }
                }
            }
        }
        // the lab docker / churn_rss size: 96 MiB over 2 shards
        assert_eq!(
            StoreCfg::for_memory(96 << 20, 2)
                .unwrap()
                .shard
                .data_floor_blocks,
            (3 << 20) / BLK as u64
        );
        assert_eq!(
            StoreCfg::for_memory(4 << 30, 8)
                .unwrap()
                .shard
                .data_floor_blocks,
            DATA_FLOOR_BYTES / BLK as u64
        );
    }

    #[test]
    fn carve_runs_keeps_the_share() {
        let used = |c: &crate::shard::ShardCfg| {
            (c.cache_pages + c.dirty_soft_pages) as u64 * 8192
                + c.point_cache as u64 * 256
                + c.delta_cap_bytes as u64
        };
        for (budget, n) in [((4096u64 - 768) << 20, 32u32), (64 << 30, 32), (2 << 30, 4)] {
            let share = budget / n as u64;
            let mut c = StoreCfg::for_memory(budget, n).unwrap().shard;
            let soft = c.run_soft_bytes;
            carve_runs(&mut c);
            assert_eq!(
                c.run_soft_bytes, soft,
                "a share above the floor keeps the run budget"
            );
            assert!(
                used(&c) + 2 * c.run_soft_bytes as u64 <= share,
                "cache {} + runs {} over the share {share}",
                used(&c),
                2 * c.run_soft_bytes
            );
            assert!(c.dirty_soft_pages.abs_diff(c.cache_pages / 8) <= 1);
        }
        // at the page floor the run budget gives way
        let mut c = StoreCfg::for_memory(128 << 20, 1).unwrap().shard;
        c.cache_pages = 4096;
        carve_runs(&mut c);
        assert_eq!((c.cache_pages, c.run_soft_bytes), (4096, 0));
    }
}

/// Device `dev` bytes vs `label` bytes recorded at mkfs: `Some` when the device lost at least one block.
pub fn size_shrunk(label: u64, dev: u64) -> Option<(u64, u64)> {
    (dev > 0 && label >= dev + BLK as u64).then_some((label, dev))
}

#[cfg(test)]
mod size_tests {
    use super::size_shrunk;

    #[test]
    fn only_a_shrunk_device_mismatches() {
        let g = 1u64 << 30;
        assert_eq!(size_shrunk(g, g), None);
        assert_eq!(size_shrunk(g, g + (64 << 20)), None, "grown: not an error");
        assert_eq!(size_shrunk(g, g - 4096), Some((g, g - 4096)));
        assert_eq!(size_shrunk(g, g - 1), None, "less than a block of slack");
        assert_eq!(size_shrunk(g, 0), None, "unknown size");
    }
}

#[cfg(all(test, feature = "splinterdb"))]
mod splinter_poll_tests {
    use super::*;
    use crate::dev::{SimClock, SimConfig, SimDev, SimDisk};
    use crate::layout::{MkfsParams, mkfs};
    use std::time::{Duration, Instant};

    struct Temp(std::path::PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn fixture(tag: &str) -> (Temp, Store<SimDev, SimClock>) {
        let root = std::env::temp_dir().join(format!("sdb-store-{tag}-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let temp = Temp(root.clone());
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let (sb, _) = mkfs(
            &mut disk.queue(),
            &mut SimClock::default(),
            &MkfsParams {
                shards: 1,
                wal_blocks: 1024,
                align_blocks: 1,
                omap_splinterdb: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut foreign = crate::splinter_omap::Config::new(root, 128 << 20);
        foreign.allow_non_nvme = true;
        crate::splinter_omap::create(&foreign, &sb, 64 << 20).unwrap();
        let mut cfg = StoreCfg::default();
        cfg.shard.splinterdb = Some(foreign);
        cfg.shard.cache_pages = 32768;
        let (mut st, _) = Store::mount(|| disk.queue(), SimClock::default(), cfg).unwrap();
        st.poll(&mut Vec::new()).unwrap();
        (temp, st)
    }

    fn seed_splinter_wal(st: &mut Store<SimDev, SimClock>, pairs: Vec<(Bytes, Bytes)>) {
        let count = u32::try_from(pairs.len()).unwrap();
        let mut blob = Vec::new();
        for (key, value) in pairs {
            blob.extend_from_slice(&(key.len() as u32).to_le_bytes());
            blob.extend_from_slice(&key);
            blob.extend_from_slice(&(value.len() as u32).to_le_bytes());
            blob.extend_from_slice(&value);
        }
        // Fixture-only raw object ID, but the same WAL/apply/materialization
        // route as a selected-engine write, never the native format upgrader.
        let mut txn = crate::shard::Txn::new(crate::shard::MERGE_TOKEN);
        txn.sys = true;
        txn.ops
            .push(crate::state::Op::Omap(crate::olsm::wire::OOp::Put {
                id: 19,
                n: count,
                blob: Bytes::from(blob),
            }));
        st.shards[0].sh.submit(txn).unwrap();
        st.activate(0);
        let target = st.shards[0].sh.next_lsn() - 1;
        let end = Instant::now() + Duration::from_secs(10);
        while st.shards[0].sh.durable_lsn() < target {
            assert!(
                Instant::now() < end,
                "WARNING TIMEOUT SplinterDB scan fixture WAL seed"
            );
            st.poll(&mut Vec::new()).unwrap();
            st.idle();
            std::thread::yield_now();
        }
        st.checkpoint().unwrap();
    }

    #[test]
    fn splinter_pending_read_stays_active_before_periodic_sweep() {
        let (_temp, mut st) = fixture("readiness");
        assert!(st.quiet());
        let sweep = st.next_sweep;
        // Hold owner consumption, not the C worker. Even an already-published completion must
        // keep this shard scheduled until consumed; timing must not depend on the OS scheduler.
        st.shards[0].sh.splinter_hold_completions(true);
        st.set_nonblock_reads(true);
        let r = st.stage(&CollT::Meta, |s| {
            s.s.sh.olsm_get(None, 19, b"absent").map_err(|e| match e {
                StoreError::Miss => ObjError::WouldBlock,
                e => e.into(),
            })
        });
        assert_eq!(r, Err(ObjError::WouldBlock));
        assert!(!st.quiet());
        for _ in 0..8 {
            st.poll(&mut Vec::new()).unwrap();
            assert_eq!(st.next_sweep, sweep, "no periodic reactivation");
            assert!(!st.quiet(), "foreign completion still needs owner polling");
        }
        st.shards[0].sh.splinter_hold_completions(false);
        let end = Instant::now() + Duration::from_secs(10);
        while !st.quiet() {
            assert!(Instant::now() < end, "WARNING TIMEOUT foreign readiness");
            st.poll(&mut Vec::new()).unwrap();
            std::thread::yield_now();
        }
        assert_eq!(st.next_sweep, sweep);
        assert!(st.take_wake(), "actual completion propagates a wake");
        let r = st.stage(&CollT::Meta, |s| {
            s.s.sh.olsm_get(None, 19, b"absent").map_err(Into::into)
        });
        assert_eq!(r.unwrap(), None);
    }

    #[test]
    fn splinter_request_sized_scan_keeps_owner_slices_and_uses_one_foreign_seek() {
        for count in [0u32, 1024, 1025, 1026] {
            let (_temp, mut st) = fixture(&format!("wide-{count}"));
            let batch: Vec<_> = (0..count)
                .map(|i| {
                    (
                        Bytes::copy_from_slice(&i.to_be_bytes()),
                        Bytes::copy_from_slice(&i.to_le_bytes()),
                    )
                })
                .collect();
            if !batch.is_empty() {
                seed_splinter_wal(&mut st, batch);
            }
            let end = Instant::now() + Duration::from_secs(15);
            while !st.shards[0].sh.olsm_flushed() {
                assert!(
                    Instant::now() < end,
                    "WARNING TIMEOUT wide scan materialization"
                );
                st.poll(&mut Vec::new()).unwrap();
                st.idle();
                std::thread::yield_now();
            }
            st.set_nonblock_reads(true);
            let seeks = st.shards[0].sh.splinter_read_gauges().unwrap()[9];
            let slices = st.shards[0].stats.scan_slices;
            let result = loop {
                st.read_session(Some((7, 1)), false);
                let r = st.stage(&CollT::Meta, |s| {
                    s.scan_omap_range(19, b"", b"", 1024, usize::MAX, true)
                });
                st.read_session(None, matches!(r, Err(ObjError::WouldBlock)));
                match r {
                    Err(ObjError::WouldBlock) => {
                        assert!(Instant::now() < end, "WARNING TIMEOUT sliced wide scan");
                        st.poll(&mut Vec::new()).unwrap();
                        std::thread::yield_now();
                    }
                    r => break r.unwrap(),
                }
            };
            let expected: Vec<_> = (0..count.min(1024))
                .map(|i| (i.to_be_bytes().to_vec(), i.to_le_bytes().to_vec()))
                .collect();
            assert_eq!(result, (expected, count > 1024));
            assert_eq!(
                st.shards[0].sh.splinter_read_gauges().unwrap()[9] - seeks,
                1,
                "one worker seek despite owner yields"
            );
            if count >= 1024 {
                assert!(st.shards[0].stats.scan_slices >= slices + 4);
            }
        }
    }

    #[test]
    fn splinter_request_sized_scan_preserves_value_key_and_recovery_byte_rules() {
        let (_temp, mut st) = fixture("wide-bytes");
        seed_splinter_wal(
            &mut st,
            vec![
                (Bytes::from_static(b"a"), Bytes::from_static(b"1111")),
                (Bytes::from_static(b"b"), Bytes::from_static(b"2222")),
                (Bytes::from_static(b"c"), Bytes::from_static(b"3")),
            ],
        );
        st.set_nonblock_reads(true);
        let end = Instant::now() + Duration::from_secs(15);
        for (i, (max, bytes, values, n)) in [
            (10, 6, true, 2),
            (10, 0, true, 1),
            (10, 5, false, 1),
            (10, 0, false, 0),
            (0, 100, true, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let r = loop {
                st.read_session(Some((8, i as u64)), false);
                let r = st.stage(&CollT::Meta, |s| {
                    s.scan_omap_range(19, b"", b"", max, bytes, values)
                });
                st.read_session(None, matches!(r, Err(ObjError::WouldBlock)));
                match r {
                    Err(ObjError::WouldBlock) => {
                        assert!(Instant::now() < end, "WARNING TIMEOUT wide byte modes");
                        st.poll(&mut Vec::new()).unwrap();
                        std::thread::yield_now();
                    }
                    r => break r.unwrap(),
                }
            };
            assert_eq!(r.0.len(), n);
            assert!(r.1);
            if !values {
                assert!(r.0.iter().all(|(_, v)| v.is_empty()));
            }
        }
        let (pairs, next) = loop {
            st.read_session(Some((8, 99)), false);
            let r = st.stage(&CollT::Meta, |s| s.scan_omap_recovery(19, b"", 10, 10));
            st.read_session(None, matches!(r, Err(ObjError::WouldBlock)));
            match r {
                Err(ObjError::WouldBlock) => {
                    assert!(
                        Instant::now() < end,
                        "WARNING TIMEOUT wide recovery byte modes"
                    );
                    st.poll(&mut Vec::new()).unwrap();
                    std::thread::yield_now();
                }
                r => break r.unwrap(),
            }
        };
        assert_eq!(pairs, vec![(b"a".to_vec(), b"1111".to_vec())]);
        assert_eq!(next, Some(b"b".to_vec()));
    }

    #[test]
    fn splinter_32_competing_scans_yield_credit_even_in_blocking_fallback() {
        let (_temp, mut st) = fixture("competing-scans");
        let batch = (0..32u32)
            .flat_map(|lane| {
                (0..1025u32).map(move |n| {
                    let key = lane * 2048 + n;
                    (
                        Bytes::copy_from_slice(&key.to_be_bytes()),
                        Bytes::copy_from_slice(&key.to_le_bytes()),
                    )
                })
            })
            .collect();
        seed_splinter_wal(&mut st, batch);
        let end = Instant::now() + Duration::from_secs(20);
        while !st.shards[0].sh.olsm_flushed() {
            assert!(
                Instant::now() < end,
                "WARNING TIMEOUT competing scan materialization"
            );
            st.poll(&mut Vec::new()).unwrap();
            st.idle();
            std::thread::yield_now();
        }
        let mut done = [false; 32];
        let mut waits = 0;
        let mut slices = 0;
        while done.iter().any(|&v| !v) {
            assert!(
                Instant::now() < end,
                "WARNING TIMEOUT competing scan completion"
            );
            // Reverse sweep keeps making newer requests contend before the current
            // owner resumes. Four independent tids share each connection.
            for lane in (0..32u32).rev() {
                if done[lane as usize] {
                    continue;
                }
                let session = (1 + u64::from(lane / 4), 1 + u64::from(lane % 4));
                st.cause_begin();
                st.read_session(Some(session), false);
                let credit_wait = st.shards[0].sh.splinter_credit_blocked();
                st.set_nonblock_reads(!credit_wait); // Deliberately select blocking fallback for waiters.
                let t = Instant::now();
                let r = st.stage(&CollT::Meta, |s| {
                    s.scan_omap_range(
                        19,
                        &(lane * 2048).to_be_bytes(),
                        b"",
                        1024,
                        usize::MAX,
                        true,
                    )
                });
                assert!(
                    t.elapsed() < Duration::from_secs(1),
                    "local credit blocked the core"
                );
                let blocked = st.take_blocked();
                let local_wait = st.take_local_wait();
                let progressed = st.take_rm_progress();
                st.read_session(None, blocked);
                match r {
                    Err(ObjError::WouldBlock) => {
                        assert!(blocked);
                        assert_eq!(local_wait, credit_wait);
                        if credit_wait {
                            waits += 1;
                            assert!(!progressed, "admission is not progress");
                        } else {
                            slices += u32::from(progressed);
                        }
                    }
                    Ok((rows, more)) => {
                        assert!(!credit_wait && !blocked && !local_wait);
                        assert!(more);
                        assert_eq!(
                            rows,
                            (0..1024u32)
                                .map(|n| {
                                    let key = lane * 2048 + n;
                                    (key.to_be_bytes().to_vec(), key.to_le_bytes().to_vec())
                                })
                                .collect::<Vec<_>>()
                        );
                        done[lane as usize] = true;
                    }
                    Err(e) => panic!("scan {lane}: {e:?}"),
                }
                // Unrelated native metadata remains runnable between foreign waits.
                st.set_nonblock_reads(false);
                assert!(st.coll_exists(&CollT::Meta).is_ok());
            }
            st.poll(&mut Vec::new()).unwrap();
            std::thread::yield_now();
        }
        assert!(
            waits > 64 && slices > 32,
            "exercise repeated contention and owner slices"
        );
        st.read_session(Some((99, 1)), false);
        assert!(!st.shards[0].sh.splinter_credit_blocked());
        st.read_session(None, false);
    }

    #[test]
    fn splinter_checkpoint_forces_buffered_materialization_and_durable_publication() {
        let (_temp, mut st) = fixture("checkpoint");
        st.shards[0].sh.set_splinter_age_for_test(u64::MAX);
        let mut t = crate::shard::Txn::new(70);
        let mut blob = Vec::new();
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(b"k");
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(b"v");
        t.ops
            .push(crate::state::Op::Omap(crate::olsm::wire::OOp::Put {
                id: 19,
                n: 1,
                blob: Bytes::from(blob),
            }));
        st.shards[0].sh.submit(t).unwrap();
        st.activate(0);
        st.sync().unwrap();
        assert!(
            !st.shards[0].sh.olsm_flushed(),
            "ordinary native sync does not force foreign materialization"
        );
        st.checkpoint().unwrap();
        assert!(st.shards[0].sh.olsm_flushed());
        assert!(st.shards[0].sh.durable_lsn() >= st.shards[0].sh.next_lsn() - 1);
    }
}

#[cfg(test)]
mod scan_prefetch_tests {
    use super::*;
    use crate::dev::{SimClock, SimConfig, SimDisk};
    use crate::layout::{MkfsParams, mkfs};

    /// A successful warm listing can submit hints on an inactive shard. Poll them without another
    /// client request, in both read API modes and device submission styles.
    #[test]
    fn scan_prefetch_success_keeps_its_shard_active_until_completion() {
        for nonblock in [false, true] {
            for submit_at_flush in [false, true] {
                let mut sim = SimConfig::new(64 << 20);
                sim.submit_at_flush = submit_at_flush;
                let disk = SimDisk::new(sim);
                mkfs(
                    &mut disk.queue(),
                    &mut SimClock::default(),
                    &MkfsParams {
                        shards: 1,
                        wal_blocks: 1024,
                        align_blocks: 1,
                        omap_lsm: true,
                        ..Default::default()
                    },
                )
                .unwrap();
                let mut cfg = StoreCfg::default();
                cfg.shard.omap_scan_prefetch = false; // warm only the current chunk first
                let (mut st, _) = Store::mount(|| disk.queue(), SimClock::default(), cfg).unwrap();
                let batch: Vec<_> = (0..256)
                    .map(|i| {
                        (
                            1,
                            Bytes::from(format!("k{i:04}")),
                            Bytes::from(vec![7; 1024]),
                        )
                    })
                    .collect();
                st.shards[0].sh.olsm_upgrade_batch(batch).unwrap();
                st.activate(0);
                for _ in 0..10_000 {
                    st.poll(&mut Vec::new()).unwrap();
                    if st.shards[0].sh.olsm_flushed() {
                        break;
                    }
                    st.idle();
                }
                assert!(st.shards[0].sh.olsm_flushed());
                st.stage(&CollT::Meta, |s| {
                    loop {
                        match s.s.sh.olsm_list(None, 1, b"", false, b"", 1) {
                            Err(StoreError::Miss) => s.s.miss_wait(s.clk)?,
                            r => break r.map_err(Into::into),
                        }
                    }
                })
                .unwrap();
                for _ in 0..10_000 {
                    st.poll(&mut Vec::new()).unwrap();
                    if st.quiet() {
                        break;
                    }
                    st.idle();
                }
                assert!(st.quiet());
                // Enable look-ahead after warming only the current chunk.
                st.shards[0].sh.set_scan_prefetch_for_test(true);
                st.set_nonblock_reads(nonblock);
                let page = st
                    .stage(&CollT::Meta, |s| {
                        s.s.sh
                            .olsm_list(None, 1, b"", false, b"", 1)
                            .map_err(Into::into)
                    })
                    .unwrap();
                assert_eq!(page.0.len(), 1);
                assert!(
                    st.shards[0].sh.olsm_reads_pending(),
                    "successful page submitted a hint"
                );
                assert!(
                    !st.quiet(),
                    "hint completion must be polled: nonblock={nonblock} flush={submit_at_flush}"
                );
                for _ in 0..10_000 {
                    st.poll(&mut Vec::new()).unwrap();
                    if !st.shards[0].sh.olsm_reads_pending() {
                        break;
                    }
                    st.idle();
                }
                assert!(!st.shards[0].sh.olsm_reads_pending());
                let stats = st.shards[0].sh.olsm_stats().unwrap();
                assert!(stats.scan_prefetch.submitted > 0);
                assert_eq!(
                    (
                        stats.scan_prefetch.inflight_bytes,
                        stats.scan_prefetch_inflight_slots
                    ),
                    (0, 0)
                );
            }
        }
    }
}
