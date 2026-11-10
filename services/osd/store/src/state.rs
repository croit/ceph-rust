// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The state machine applied by `submit` and by WAL replay (M2.2): COW B+tree (all KV, including the persisted
//! data bitmap as `f` chunks) plus the in-memory data-block allocator. A WAL `Record` carries the tree
//! mutations (`ops`) and the allocator diff (`data` = allocated, `frees`); chunk updates are derived.

use crate::alloc::{Alloc, CHUNK_BLOCKS, CHUNK_BYTES};
use crate::dev::{BlockDev, Clock};
use crate::error::{Result, StoreError};
use crate::fx::FxMap;
use crate::runs::{Hit, RunBlob, RunSet, is_tomb, omap_id};
use crate::sio::Sio;
use crate::tree::{NO_LEG, PathSet, ScanCursor, ScanStatus, SortedCursor, Tree};

/// KV mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Put(Vec<u8>, Vec<u8>),
    Del(Vec<u8>),
    /// Delete keys in `[a, b)`.
    DelRange(Vec<u8>, Vec<u8>),
    /// One omap batch of one object as a sorted run (adr 0476): into the object's runs, no tree page
    /// touched. Always after the record's tree ops.
    RunPut(RunBlob),
    /// Move the live entries in `[a, b)` of the runs of object `id` with lsn <= `upto` into the tree (newest of those
    /// runs per key); `fin`: the last slice of that merge, those runs leave. A record of merges holds nothing else.
    RunMerge {
        id: u64,
        upto: u64,
        a: Vec<u8>,
        b: Vec<u8>,
        fin: bool,
    },
    /// Omap op of the omap LSM engine (adr 0610, store with `FEAT_OMAP_LSM`): into the shard's memtable, no tree page
    /// touched. Replay inserts it when its lsn is above the manifest's `flushed_lsn`.
    Omap(crate::olsm::wire::OOp),
}

/// New data blocks written by a txn: `nblk` 4 KiB blocks at engine block address `blk`, with per-block crc32c
/// (`codec::blk_crc`, salted with the block address).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extent {
    pub blk: u64,
    pub nblk: u32,
    pub crcs: Vec<u32>,
}

/// One committed transaction as stored in the WAL.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Record {
    pub lsn: u64,
    pub ops: Vec<Op>,
    /// Allocated by this txn (written concurrently with the WAL unit; validated by crc at replay).
    pub data: Vec<Extent>,
    /// Released by this txn (blocks `(blk, nblk)`), reusable only after a checkpoint passed the txn.
    pub frees: Vec<(u64, u32)>,
}

impl Record {
    /// The record is applied and encoded: its key and value vectors go back to the thread's pool ([`crate::vpool`]).
    pub fn recycle(self) {
        for op in self.ops {
            match op {
                Op::Put(k, v) => {
                    crate::vpool::give(k);
                    crate::vpool::give(v);
                }
                Op::Del(k) => crate::vpool::give(k),
                Op::DelRange(a, b) | Op::RunMerge { a, b, .. } => {
                    crate::vpool::give(a);
                    crate::vpool::give(b);
                }
                Op::RunPut(_) | Op::Omap(_) => {}
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bitmap {
    words: Vec<u64>,
    n: u64,
}

impl Bitmap {
    pub fn new(n: u64) -> Bitmap {
        Bitmap {
            words: vec![0; n.div_ceil(64) as usize],
            n,
        }
    }
    /// A bitmap of `n` bits from `words` (bit i = word i / 64, bit i % 64); bits at or above `n` are cleared.
    pub fn from_words(mut words: Vec<u64>, n: u64) -> Bitmap {
        words.resize(n.div_ceil(64) as usize, 0);
        if !n.is_multiple_of(64)
            && let Some(last) = words.last_mut()
        {
            *last &= (1u64 << (n % 64)) - 1;
        }
        Bitmap { words, n }
    }
    pub fn len(&self) -> u64 {
        self.n
    }
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
    pub fn get(&self, i: u64) -> bool {
        self.words[(i / 64) as usize] >> (i % 64) & 1 != 0
    }
    pub fn set(&mut self, i: u64) {
        self.words[(i / 64) as usize] |= 1 << (i % 64);
    }
    pub fn clear(&mut self, i: u64) {
        self.words[(i / 64) as usize] &= !(1 << (i % 64));
    }
    pub fn count(&self) -> u64 {
        self.words.iter().map(|w| w.count_ones() as u64).sum()
    }
}

/// Key of persisted bitmap chunk `ci` (design 2.3 tag `f`); the whole `f` range is reserved for the engine.
pub fn fkey(ci: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = b'f';
    k[1..].copy_from_slice(&ci.to_be_bytes());
    k
}

fn reserved_range(a: &[u8], b: &[u8]) -> bool {
    a < b"g".as_slice() && b > b"f".as_slice()
}

/// A key a tree op names: non-empty and outside the reserved `f` range (persisted bitmap chunks).
fn tree_key_ok(k: &[u8]) -> Result<()> {
    if k.is_empty() || k[0] == b'f' {
        return Err(StoreError::Invalid("empty key or reserved key prefix 'f'"));
    }
    Ok(())
}

/// Value-compression dictionaries of a shard (adr 0021 am. 58): slot `c` = the trained dictionary of value class `c`, installed once by a
/// `Z` + `c` put (immutable afterwards), set here when that put is applied (live commit and replay alike), so the table
/// only ever holds dictionaries that are in the tree. Shared with scans (`Arc`) that read it while the stage is borrowed.
#[derive(Debug)]
pub struct DictTab {
    pub slots: [std::sync::OnceLock<std::sync::Arc<crate::obj::onode::ZDict>>; 64],
}

impl Default for DictTab {
    fn default() -> Self {
        DictTab {
            slots: std::array::from_fn(|_| std::sync::OnceLock::new()),
        }
    }
}

/// Replayed/applied state of one shard.
#[derive(Debug)]
pub struct State {
    pub tree: Tree,
    pub alloc: Alloc,
    pub pc: PointCache,
    pub dicts: std::sync::Arc<DictTab>,
    /// Last applied LSN.
    pub lsn: u64,
    /// Offline repair mount (`ShardCfg::repair_fence`): a record may free a block the repair fenced as a false free
    /// (referenced by the durable tree, absent from its bitmap): the fenced reservation is consumed.
    pub repair_fence: bool,
    chunks: Vec<u64>,
    /// Scratch of `check`: (start, end) of a record's new data extents when they are not ascending (capacity kept).
    exts: Vec<(u64, u64)>,
    /// Scratch of `prepare` (cleared per call, capacity kept).
    ps: PathSet,
    /// Per op of the record `at_lsn` names: the leg of `ps` its probe located (`NO_LEG`: none). `apply` of that record
    /// puts / deletes there without walking the tree again (one walk per key per txn).
    at: Vec<u32>,
    at_lsn: Option<u64>,
    /// Bitmap chunks whose `f` key in the tree is stale (the allocator is authoritative); written into the
    /// tree by `flush_chunks` right before a checkpoint freeze. Dirty list + membership bitset.
    dirty_chunks: Vec<u64>,
    chunk_dirty: Vec<u64>,
    /// Debug builds: (record lsn, dirty pages, estimate) of the last `prepare`; `apply` asserts the estimate was an
    /// upper bound.
    #[cfg(debug_assertions)]
    est_dbg: Option<(u64, usize, usize)>,
    /// Omap runs (adr 0476).
    pub runs: RunSet,
    /// Merge positions of the last `RunMerge` slice (adr 0476): (run, entry) of the object's runs in key order, built
    /// once (slice sizing, `prepare` or `apply`) and reused while `mix_tag` (slice, run set version) matches.
    mix: Vec<(u32, u32)>,
    mix_tag: Option<MixTag>,
    /// Leaf cursor of a merge slice's ascending keys (one descent per leaf).
    mcur: SortedCursor,
    /// Leaf cursor of the probes of a record's ascending stretches of puts and removals (`Tree::probe_sorted`).
    pcur: SortedCursor,
    /// Run merges compress plain values of at least this many bytes with the loaded value dictionaries (adr 0476, as
    /// the stage does on the tree path, adr 0021 am. 58); 0 = off (store without `FEAT_VAL_COMP`).
    pub vc_min: usize,
    /// Merged run values stored compressed / tried (stats).
    pub run_vcomp: (u64, u64),
    /// Compression attempts of merged run values, sampled per value class across merge records (live and replay alike: a
    /// record may store either form of a value), and the coding scratch.
    vc: crate::obj::onode::VcAdapt,
    vc_buf: Vec<u8>,
    /// Omap LSM engine of the shard (store with `FEAT_OMAP_LSM`, adr 0610): applied ops go into its active memtable.
    pub olsm: Option<crate::olsm::Olsm>,
    #[cfg(feature = "rocksdb")]
    pub(crate) rocks_mem: Option<crate::rocks_omap::mem::Buffers>,
    #[cfg(feature = "splinterdb")]
    pub(crate) splinter_mem: Option<crate::foreign_mem::Buffers>,
    /// Mount replay: omap ops of the replayed records, in lsn order (see [`State::olsm_collect`]).
    pub olsm_replay: Option<Vec<(u64, crate::olsm::wire::OOp)>>,
}

/// The merge slice and run set version [`State::mix`] was built for.
#[derive(Debug, PartialEq, Eq)]
pub struct MixTag {
    id: u64,
    upto: u64,
    a: Vec<u8>,
    b: Vec<u8>,
    ver: u64,
}

/// Value compression of one merge record (adr 0476): the tree record a merged run value takes is compressed
/// (`V_CINL`) with the dictionary of its class, else the shared one, when one is loaded, the class is due for an attempt
/// (`VcAdapt`, the stage's sampling) and it saves at least 1/8 (the stage's rule); else the value as logged. A replay may
/// store either form of a value (same value).
struct MergeComp<'a> {
    min: usize,
    dicts: &'a DictTab,
    stats: &'a mut (u64, u64),
    vc: &'a mut crate::obj::onode::VcAdapt,
    cv: &'a mut Vec<u8>,
}

impl MergeComp<'_> {
    fn pack<'v>(&'v mut self, v: &'v [u8]) -> &'v [u8] {
        use crate::obj::onode::{SHARED_CLASS, dict_class, vcomp_pack};
        if self.min == 0 || v.first() != Some(&0) || v.len() - 1 < self.min {
            return v;
        }
        let val = &v[1..];
        let cls = dict_class(val);
        let (id, zd) = match self.dicts.slots[cls].get() {
            Some(z) => (cls, z),
            None => match self.dicts.slots[SHARED_CLASS].get() {
                Some(z) => (SHARED_CLASS, z),
                None => return v,
            },
        };
        if !self.vc.try_now(cls) {
            return v;
        }
        self.stats.1 += 1;
        let n = vcomp_pack(val, zd, id as u8, self.cv);
        if n != usize::MAX && n <= val.len() - (val.len() / 8).max(16) {
            self.vc.hit(cls);
            self.stats.0 += 1;
            &self.cv[..n]
        } else {
            self.vc.miss(cls);
            v
        }
    }
}

/// The entries of a merge slice in key order (merge positions into the object's runs), values packed as merged;
/// a removal keeps its empty value (the tree batch deletes the key).
struct MixSrc<'r, 'c> {
    runs: &'r [crate::runs::Run],
    mix: &'r [(u32, u32)],
    at: usize,
    comp: &'r mut MergeComp<'c>,
}

impl crate::tree::SortedSrc for MixSrc<'_, '_> {
    fn key(&self) -> Option<&[u8]> {
        self.mix
            .get(self.at)
            .map(|&(j, i)| self.runs[j as usize].blob.key(i as usize))
    }
    fn take(&mut self, out: &mut crate::page::Ents) {
        let (j, i) = self.mix[self.at];
        let (k, v) = self.runs[j as usize].blob.entry(i as usize);
        out.push(k, self.comp.pack(v));
        self.at += 1;
    }
}

/// Key of a tree put or removal: its run entries die (the runs are older, adr 0476), values unread.
fn tree_key(op: &Op) -> Option<&[u8]> {
    match op {
        Op::Put(k, _) | Op::Del(k) => Some(k),
        _ => None,
    }
}

/// Run kills of tree op `i` of `ops`: the stretch of tree ops it starts in one batch ([`RunSet::kill_keys`]), nothing
/// for the later ops of a stretch.
fn kill_stretch(runs: &mut RunSet, ops: &[Op], i: usize) {
    if i == 0 || tree_key(&ops[i - 1]).is_none() {
        runs.kill_keys(&ops[i..], tree_key);
    }
}

impl State {
    pub fn new(tree: Tree, alloc: Alloc) -> State {
        State {
            tree,
            alloc,
            pc: PointCache::default(),
            dicts: Default::default(),
            lsn: 0,
            repair_fence: false,
            chunks: Vec::new(),
            exts: Vec::new(),
            ps: PathSet::default(),
            at: Vec::new(),
            at_lsn: None,
            dirty_chunks: Vec::new(),
            chunk_dirty: Vec::new(),
            #[cfg(debug_assertions)]
            est_dbg: None,
            runs: RunSet::default(),
            mix: Vec::new(),
            mix_tag: None,
            mcur: Default::default(),
            pcur: Default::default(),
            vc_min: 0,
            run_vcomp: (0, 0),
            vc: Default::default(),
            vc_buf: Vec::new(),
            olsm: None,
            #[cfg(feature = "rocksdb")]
            rocks_mem: None,
            #[cfg(feature = "splinterdb")]
            splinter_mem: None,
            olsm_replay: None,
        }
    }

    /// Point lookup (appends the value to `out`), served from the [`PointCache`] for its tags.
    pub fn get(&mut self, key: &[u8], out: &mut Vec<u8>) -> Result<bool> {
        if !self.runs.is_empty() {
            match self.runs.get(key) {
                Hit::Live(v) => {
                    out.extend_from_slice(v);
                    return Ok(true);
                }
                Hit::Gone => return Ok(false),
                Hit::Dead | Hit::None => {}
            }
        }
        if !self.pc.wants(key) {
            return self.tree.get(key, out);
        }
        match self.pc.map.get(key) {
            Some(Some(v)) => {
                out.extend_from_slice(v);
                return Ok(true);
            }
            Some(None) => return Ok(false),
            None => {}
        }
        let n0 = out.len();
        let found = self.tree.get(key, out)?;
        self.pc.fill(key, found.then(|| &out[n0..]));
        Ok(found)
    }

    /// Test/debug: every cached entry equals the tree (entries whose pages are not resident are skipped).
    pub fn verify_point_cache(&mut self) -> std::result::Result<usize, String> {
        let mut checked = 0;
        let keys: Vec<Vec<u8>> = self.pc.map.keys().cloned().collect();
        for k in keys {
            let mut v = Vec::new();
            match self.tree.get(&k, &mut v) {
                Ok(f) => {
                    let want = f.then_some(v);
                    if self.pc.map.get(&k) != Some(&want) {
                        return Err(format!("point cache stale for key {k:02x?}"));
                    }
                    checked += 1;
                }
                Err(StoreError::Miss) => {}
                Err(e) => return Err(format!("tree get: {e}")),
            }
        }
        Ok(checked)
    }

    /// Validate `rec` against the current state without touching it (only the `exts` scratch): key limits, reserved
    /// key space, frees allocated, data free of allocation and of overlaps among the record's own new extents.
    pub fn check(&mut self, rec: &Record) -> Result<()> {
        let (mk, me) = (self.tree.max_key(), self.tree.max_entry());
        for op in &rec.ops {
            match op {
                Op::Put(k, v) => {
                    tree_key_ok(k)?;
                    if k.len() > mk || 4 + k.len() + v.len() > me {
                        return Err(StoreError::Invalid(
                            "key or value too large for a tree page",
                        ));
                    }
                }
                Op::Del(k) => tree_key_ok(k)?,
                Op::DelRange(a, b) => {
                    if reserved_range(a, b) {
                        return Err(StoreError::Invalid(
                            "range overlaps reserved key prefix 'f'",
                        ));
                    }
                }
                Op::RunPut(r) => {
                    if (0..r.len()).any(|i| {
                        let (k, v) = r.entry(i);
                        k.len() > mk || 4 + k.len() + v.len() > me
                    }) {
                        return Err(StoreError::Invalid("run entry too large for a tree page"));
                    }
                }
                Op::RunMerge { id, a, b, .. } => {
                    if a >= b || omap_id(a) != Some(*id) {
                        return Err(StoreError::Invalid("bad run merge range"));
                    }
                }
                Op::Omap(o) => {
                    if self.olsm.is_none() && self.olsm_replay.is_none() {
                        return Err(StoreError::Invalid(
                            "omap LSM op on a store without the engine",
                        ));
                    }
                    if o.validate().is_none() {
                        return Err(StoreError::Invalid("malformed omap LSM op"));
                    }
                }
            }
        }
        // runs come after the record's tree ops (the stage emits them last; the tree ops kill run entries as they are
        // before the record); merges are records of their own
        if let Some(i) = rec.ops.iter().position(|o| matches!(o, Op::RunPut(..)))
            && !rec.ops[i..].iter().all(|o| matches!(o, Op::RunPut(..)))
        {
            return Err(StoreError::Invalid("tree op after a run in one record"));
        }
        if rec.ops.iter().any(|o| matches!(o, Op::RunMerge { .. }))
            && !rec.ops.iter().all(|o| matches!(o, Op::RunMerge { .. }))
        {
            return Err(StoreError::Invalid("run merge mixed with other ops"));
        }
        // a record logs at most one new run per object (its order lsn is the record's); re-logs (order lsn of a live run)
        // are records of their own
        let relog = |o: &Op| matches!(o, Op::RunPut(r) if r.ord() != 0);
        if rec.ops.iter().any(relog) {
            if !rec.ops.iter().all(relog) {
                return Err(StoreError::Invalid("run re-log mixed with other ops"));
            }
        } else if rec
            .ops
            .iter()
            .filter(|o| matches!(o, Op::RunPut(..)))
            .nth(1)
            .is_some()
        {
            let mut ids: Vec<u64> = rec
                .ops
                .iter()
                .filter_map(|o| match o {
                    Op::RunPut(r) => Some(r.id()),
                    _ => None,
                })
                .collect();
            let n = ids.len();
            ids.sort_unstable();
            ids.dedup();
            if ids.len() != n {
                return Err(StoreError::Invalid(
                    "two new runs of one object in a record",
                ));
            }
        }
        for &(b, n) in &rec.frees {
            if !self.alloc.in_region(b, n) {
                return Err(StoreError::Invalid("block range outside data region"));
            }
            if !self.alloc.is_allocated(b, n)
                && !(self.repair_fence && self.alloc.is_fenced_or_allocated(b, n))
            {
                return Err(StoreError::Invalid("free of unallocated block"));
            }
        }
        // Every extent is checked against the pre-record bitmap, so two extents of one record sharing blocks would
        // both pass and the unit could ack although only one recorded CRC can match. Ascending extents (the normal
        // case) are proven disjoint by one sweep; any other order sorts a scratch copy: O(n log n), no allocation
        // once the scratch has grown.
        let mut data_end = 0;
        let mut ascending = true;
        for e in &rec.data {
            if e.nblk == 0 || !self.alloc.in_region(e.blk, e.nblk) {
                return Err(StoreError::Invalid("block range outside data region"));
            }
            if !self.alloc.is_unallocated(e.blk, e.nblk) {
                return Err(StoreError::Invalid("allocation of allocated block"));
            }
            if e.blk < data_end {
                ascending = false;
            }
            data_end = data_end.max(e.blk + u64::from(e.nblk)); // in_region checked both ends
        }
        if !ascending {
            self.exts.clear();
            self.exts
                .extend(rec.data.iter().map(|e| (e.blk, e.blk + u64::from(e.nblk))));
            self.exts.sort_unstable();
            if self.exts.windows(2).any(|w| w[1].0 < w[0].1) {
                return Err(StoreError::Invalid("overlapping data extents"));
            }
        }
        Ok(())
    }

    fn touched_chunks(&mut self, rec: &Record) {
        self.chunks.clear();
        let mut add = |b: u64, n: u32| {
            let r = self.alloc.rel_of(b);
            for ci in r / CHUNK_BLOCKS..=(r + n as u64 - 1) / CHUNK_BLOCKS {
                if !self.chunks.contains(&ci) {
                    self.chunks.push(ci);
                }
            }
        };
        rec.frees.iter().for_each(|&(b, n)| add(b, n));
        rec.data.iter().for_each(|e| add(e.blk, e.nblk));
    }

    /// Distinct tree pages of the last `prepare`.
    pub fn probe_pages(&self) -> usize {
        self.ps.resident()
    }

    /// Make every tree page the txn needs resident (`Err(Miss)`: pages queued, retry after they are loaded).
    /// After `Ok`, `apply` cannot miss. Does `check` too. Returns an upper bound of the tree pages the record
    /// dirties (for meta-space admission).
    pub fn prepare(&mut self, rec: &Record) -> Result<usize> {
        let r = self.prepare_ex(rec, true);
        #[cfg(debug_assertions)]
        {
            self.est_dbg = r
                .as_ref()
                .ok()
                .map(|&e| (rec.lsn, self.tree.dirty_pages(), e));
        }
        r
    }

    /// `budgeted = false` (blocking replay: no eviction between load rounds) skips the working-set guard.
    fn prepare_ex(&mut self, rec: &Record, budgeted: bool) -> Result<usize> {
        self.at_lsn = None;
        self.check(rec)?;
        self.touched_chunks(rec);
        let h = self.tree.height() as usize + 2;
        let has_range = rec
            .ops
            .iter()
            .any(|o| matches!(o, Op::DelRange(..) | Op::RunMerge { .. }));
        let alloc_change = !rec.data.is_empty() || !rec.frees.is_empty();
        // a tree op kills the run entries of its key before its walk, which must not miss after that (reads would see
        // the tree's older state meanwhile): a key a run holds live (a value or a removal) takes the probed path
        let hits_runs = |o: &Op| matches!(o, Op::Put(k, _) | Op::Del(k) if !self.runs.is_empty() && matches!(self.runs.get(k), Hit::Live(_) | Hit::Gone));
        if !has_range && !alloc_change && rec.ops.len() <= 1 && !rec.ops.iter().any(hits_runs) {
            // a single tree mutation misses before it changes anything; a put may split every page of its path and
            // grow the root (path + one new page per level + new root); a run touches no page
            let put = matches!(rec.ops.first(), Some(Op::Put(..)));
            let n = rec
                .ops
                .iter()
                .filter(|o| !matches!(o, Op::RunPut(..)))
                .count();
            return Ok(n * if put { 2 * h } else { h });
        }
        let mut miss = false;
        self.ps.reset();
        self.at.clear();
        let mut put_bytes = 0usize;
        self.pcur.reset();
        let mut prev: Option<&[u8]> = None;
        for op in &rec.ops {
            let r = match op {
                Op::Put(k, _) | Op::Del(k) => {
                    // a record holds them in ascending stretches (blind removals, then the stage's sorted map): one
                    // leaf cursor per stretch
                    if prev.is_some_and(|p: &[u8]| p >= k.as_slice()) {
                        self.pcur.reset();
                    }
                    prev = Some(k);
                    let r = self.tree.probe_sorted(&mut self.pcur, k, &mut self.ps);
                    if let Op::Put(_, v) = op {
                        put_bytes += 4 + k.len() + v.len();
                        if r.is_ok() {
                            self.ps.note_put();
                        }
                    }
                    self.at.push(self.ps.leg());
                    r
                }
                Op::DelRange(a, b) => {
                    self.at.push(NO_LEG);
                    self.tree
                        .probe_range(a, b)
                        .map(|_| self.tree.probe_range_paths(a, b, &mut self.ps))
                }
                Op::RunPut(..) | Op::Omap(_) => {
                    self.at.push(NO_LEG);
                    Ok(())
                }
                Op::RunMerge { id, upto, a, b, .. } => {
                    self.at.push(NO_LEG);
                    let mut r = Ok(());
                    self.merge_positions(*id, *upto, a, b);
                    let (tree, ps, cur) = (&mut self.tree, &mut self.ps, &mut self.mcur);
                    cur.reset();
                    let runs = self.runs.obj(*id).map_or(&[][..], |o| &o.runs[..]);
                    for &(j, i) in &self.mix {
                        let (k, v) = runs[j as usize].blob.entry(i as usize);
                        // a removal's leaf is probed too (the merge removes the key there), it never splits
                        match tree.probe_sorted(cur, k, ps) {
                            Ok(()) if !is_tomb(v) => {
                                ps.note_put();
                                put_bytes += 4 + k.len() + v.len();
                            }
                            Ok(()) => {}
                            Err(e) => r = Err(e),
                        }
                    }
                    r
                }
            };
            match r {
                Ok(()) => {}
                Err(StoreError::Miss) => {
                    miss = true;
                    #[cfg(feature = "lab")]
                    crate::dbg::prep_miss(match op {
                        Op::Put(k, _) | Op::Del(k) => k,
                        Op::DelRange(a, _) | Op::RunMerge { a, .. } => a,
                        Op::RunPut(r) => r.first(),
                        Op::Omap(_) => &[],
                    });
                }
                Err(e) => return Err(e),
            }
        }
        if miss {
            // a txn whose distinct page set cannot be held in the cache at once could never complete
            if budgeted && self.ps.resident() + self.tree.wants_len() > self.tree.txn_page_budget()
            {
                return Err(StoreError::TxnTooLarge);
            }
            return Err(StoreError::Miss);
        }
        // Upper bound of meta pages newly dirtied: the clean pages on the probed paths (shared pages once) plus
        // the pages created by splits. A leaf that receives a put splits at most once when first touched and once more per psz/2
        // bytes inserted into it (each split leaves two half-full pages); every split adds one page; parents
        // split far less often (fanout >> 8) and the root may grow. Removals never split (a removal never grows a page,
        // adr 0021 am. 13; range deletes count their surviving boundary pages via `probe_range_paths`).
        let splits = if put_bytes == 0 {
            0
        } else {
            self.ps.put_leaves() + 2 * put_bytes / self.tree.psz() + 1
        };
        self.tree.seal_positions(&mut self.ps);
        self.at_lsn = Some(rec.lsn);
        Ok(self.ps.clean + splits + splits / 8 + self.tree.height() as usize + 2)
    }

    /// Apply a record (after a successful `prepare`, or a single-mutation record that may still `Miss` without
    /// side effects). Allocator: reserved -> allocated, frees -> held.
    /// `Err((e, torn))`: `torn` = the record changed the state before it failed (a later checkpoint would persist a
    /// record that never reaches the WAL); `false` = nothing changed (a `Miss`, or a page error while the first tree
    /// op located its leaf: put / del fail only there). A probed record finds every page its ops read, also after its
    /// earlier ops changed the tree ([`crate::tree::Tree::del_range`]): a `Miss` after a change is an engine bug,
    /// reported as `Corrupt`, never retried.
    pub fn apply(&mut self, rec: &Record) -> std::result::Result<(), (StoreError, bool)> {
        let mut torn = false;
        self.apply_ops(rec, &mut torn).map_err(|e| match e {
            StoreError::Miss if torn => (
                StoreError::Corrupt(format!(
                    "lsn {}: tree page miss after the record changed the state",
                    rec.lsn
                )),
                true,
            ),
            e => (e, torn),
        })
    }

    fn apply_ops(&mut self, rec: &Record, torn: &mut bool) -> Result<()> {
        // the legs the probe of this record located (any other record, or none: walk)
        let carry = self.at_lsn.take() == Some(rec.lsn) && self.at.len() == rec.ops.len();
        for (i, op) in rec.ops.iter().enumerate() {
            let leg = if carry { self.at[i] } else { NO_LEG };
            // a tree op kills the run entries of its keys (the runs are older), once the tree took it
            match op {
                Op::Put(k, v) => {
                    let _k = wprof::kop(wprof::Kop::Put, k, k.len() + v.len());
                    self.tree.put_at(&self.ps, leg, k, v)?;
                    *torn = true;
                    if !self.runs.is_empty() {
                        kill_stretch(&mut self.runs, &rec.ops, i);
                    }
                    self.pc.set(k, Some(v));
                    if k.len() == 2 && k[0] == b'Z' && (k[1] as usize) < 64 {
                        let _ = self.dicts.slots[k[1] as usize].set(std::sync::Arc::new(
                            crate::obj::onode::ZDict::new(v.clone()),
                        ));
                    }
                }
                Op::Del(k) => {
                    let _k = wprof::kop(wprof::Kop::Del, k, k.len());
                    self.tree.del_at(&self.ps, leg, k)?;
                    *torn = true;
                    if !self.runs.is_empty() {
                        kill_stretch(&mut self.runs, &rec.ops, i);
                    }
                    self.pc.set(k, None);
                }
                Op::DelRange(a, b) => {
                    let _k = wprof::kop(wprof::Kop::DelRange, a, a.len() + b.len());
                    // a range removal can fail between subtrees
                    *torn = true;
                    self.runs.kill_range(a, b);
                    self.tree.del_range(a, b)?;
                    self.pc.del_range(a, b);
                }
                Op::RunPut(r) => {
                    *torn = true;
                    self.runs.insert(rec.lsn, r.clone());
                }
                Op::Omap(o) => {
                    if let Some(buf) = &mut self.olsm_replay {
                        buf.push((rec.lsn, o.clone()));
                    } else {
                        #[cfg(feature = "rocksdb")]
                        if let Some(mem) = &mut self.rocks_mem {
                            o.apply_rocks(&mut mem.active, rec.lsn);
                            *torn = true;
                            continue;
                        }
                        #[cfg(feature = "splinterdb")]
                        if let Some(mem) = &mut self.splinter_mem {
                            o.apply_splinter(&mut mem.active, rec.lsn);
                            *torn = true;
                            continue;
                        }
                        let e = self.olsm.as_mut().ok_or(StoreError::Corrupt(
                            "omap LSM op on a store without the engine".into(),
                        ))?;
                        o.apply(&mut e.active, rec.lsn);
                    }
                    *torn = true;
                }
                Op::RunMerge {
                    id,
                    upto,
                    a,
                    b,
                    fin,
                } => {
                    // entries straight from the runs into the tree (disjoint fields: no copy per entry)
                    self.merge_positions(*id, *upto, a, b);
                    let mut comp = MergeComp {
                        min: self.vc_min,
                        dicts: &self.dicts,
                        stats: &mut self.run_vcomp,
                        vc: &mut self.vc,
                        cv: &mut self.vc_buf,
                    };
                    let (tree, pc) = (&mut self.tree, &mut self.pc);
                    let cur = &mut self.mcur;
                    cur.reset();
                    let runs = self.runs.obj(*id).map_or(&[][..], |o| &o.runs[..]);
                    // the batch can fail between entries
                    *torn = true;
                    let mut src = MixSrc {
                        runs,
                        mix: &self.mix,
                        at: 0,
                        comp: &mut comp,
                    };
                    tree.write_sorted_batch(cur, &mut src, |k, v| pc.set(k, v))?;
                    if *fin {
                        self.runs.drop_upto(*id, *upto);
                    } else {
                        self.runs.retire(*id, *upto, a, b);
                    }
                }
            }
        }
        *torn = true;
        if !rec.data.is_empty() || !rec.frees.is_empty() {
            self.touched_chunks(rec);
            for &(b, n) in &rec.frees {
                if self.repair_fence {
                    self.alloc.unreserve_unallocated(b, n);
                }
                self.alloc.apply_free(b, n);
            }
            for e in &rec.data {
                self.alloc.apply_alloc(e.blk, e.nblk);
            }
            for k in 0..self.chunks.len() {
                self.mark_chunk(self.chunks[k]);
            }
        }
        self.tree.finish_txn()?;
        self.lsn = rec.lsn;
        #[cfg(debug_assertions)]
        if let Some((lsn, d0, est)) = self.est_dbg.take()
            && lsn == rec.lsn
        {
            let d1 = self.tree.dirty_pages();
            assert!(
                d1 <= d0 + est,
                "page estimate {est} below the pages dirtied ({d0} -> {d1}): {} ops",
                rec.ops.len()
            );
        }
        Ok(())
    }

    /// Fill [`State::mix`] with the merge positions of the slice `[a, b)` of object `id`'s runs up to order `upto`,
    /// unless it already holds them for the current run set.
    fn merge_positions(&mut self, id: u64, upto: u64, a: &[u8], b: &[u8]) {
        let ver = self.runs.ver();
        if self
            .mix_tag
            .as_ref()
            .is_some_and(|t| t.id == id && t.upto == upto && t.ver == ver && t.a == a && t.b == b)
        {
            return;
        }
        self.mix.clear();
        self.mix.extend(self.runs.merge_ix(id, upto, a, b));
        self.mix_tag = Some(MixTag {
            id,
            upto,
            a: a.to_vec(),
            b: b.to_vec(),
            ver,
        });
    }

    /// Plan a merge slice (the shard's sizing): the positions of `[a, ..)` up to the first that `take` refuses
    /// (`take(entry tree bytes)`, 0 for a removal); returns that position's key (`None`: the slice reaches `end`).
    /// `prepare` and `apply` of the slice `[a, returned key or end)` reuse the positions.
    pub fn plan_merge(
        &mut self,
        id: u64,
        upto: u64,
        a: &[u8],
        end: &[u8],
        mut take: impl FnMut(usize) -> bool,
    ) -> Option<Vec<u8>> {
        self.mix.clear();
        let mut hi = None;
        let runs = self.runs.obj(id).map_or(&[][..], |o| &o.runs[..]);
        for (j, i) in self.runs.merge_ix(id, upto, a, end) {
            let (k, v) = runs[j as usize].blob.entry(i as usize);
            if !take(if is_tomb(v) { 0 } else { 4 + k.len() + v.len() }) {
                hi = Some(k.to_vec());
                break;
            }
            self.mix.push((j, i));
        }
        self.mix_tag = Some(MixTag {
            id,
            upto,
            a: a.to_vec(),
            b: hi.clone().unwrap_or_else(|| end.to_vec()),
            ver: self.runs.ver(),
        });
        hi
    }

    /// Replay of a record the checkpoint already contains (lsn in `[floor, ckpt_lsn]`, adr 0476): only
    /// its effects on the runs (tree, allocator and data are in the checkpoint).
    pub fn apply_runs_only(&mut self, rec: &Record) {
        self.olsm_collect(rec);
        for (i, op) in rec.ops.iter().enumerate() {
            match op {
                Op::Put(..) | Op::Del(_) => kill_stretch(&mut self.runs, &rec.ops, i),
                Op::DelRange(a, b) => self.runs.kill_range(a, b),
                Op::RunPut(r) => self.runs.insert(rec.lsn, r.clone()),
                Op::RunMerge {
                    id,
                    upto,
                    fin,
                    a,
                    b,
                } => {
                    if *fin {
                        self.runs.drop_upto(*id, *upto);
                    } else {
                        self.runs.retire(*id, *upto, a, b);
                    }
                }
                Op::Omap(_) => {}
            }
        }
    }

    /// Mount replay of a store with the omap LSM engine: keep the record's omap ops (the memtable is built once the
    /// replayed manifest says which are flushed).
    fn olsm_collect(&mut self, rec: &Record) {
        if let Some(buf) = &mut self.olsm_replay {
            for op in &rec.ops {
                if let Op::Omap(o) = op {
                    buf.push((rec.lsn, o.clone()));
                }
            }
        }
    }

    fn mark_chunk(&mut self, ci: u64) {
        let (w, b) = ((ci / 64) as usize, ci % 64);
        if w >= self.chunk_dirty.len() {
            self.chunk_dirty.resize(w + 1, 0);
        }
        if self.chunk_dirty[w] >> b & 1 == 0 {
            self.chunk_dirty[w] |= 1 << b;
            self.dirty_chunks.push(ci);
        }
    }

    fn mark_chunks_of(&mut self, blk: u64, n: u32) {
        let r = self.alloc.rel_of(blk);
        for ci in r / CHUNK_BLOCKS..=(r + n as u64 - 1) / CHUNK_BLOCKS {
            self.mark_chunk(ci);
        }
    }

    /// An elastic meta cell leaves the data region (reserved -> allocated). No WAL record: the checkpoint that
    /// carries the cell flushes the touched bitmap chunks and the new meta image together (adr 0021 am. 12).
    pub fn cell_take(&mut self, blk: u64, n: u32) {
        self.alloc.apply_alloc(blk, n);
        self.mark_chunks_of(blk, n);
    }

    /// An empty elastic meta cell returns to the data region (allocated -> held until the checkpoint passes).
    pub fn cell_give(&mut self, blk: u64, n: u32) {
        self.alloc.apply_free(blk, n);
        self.mark_chunks_of(blk, n);
    }

    /// Bitmap chunks not yet written into the tree.
    pub fn dirty_chunks(&self) -> usize {
        self.dirty_chunks.len()
    }

    /// Upper bound of the tree pages a `flush_chunks` dirties (leaf + split + path slack per chunk); `extra`
    /// = chunks a record about to be applied may add.
    pub fn chunk_reserve(&self, extra: usize) -> usize {
        let n = self.dirty_chunks.len() + extra;
        if n == 0 {
            return 0;
        }
        n + n / 2 + n * CHUNK_BYTES * 2 / self.tree.psz() + 2 * self.tree.height() as usize + 4
    }

    /// Chunks the last `prepare` found the record to touch.
    pub fn touched_chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Leaf deltas over their RAM cap (adr 0021 am. 19): mark the leaves of the oldest segment's chains for a whole
    /// rewrite at the next freeze. A window of the sliced checkpoint start (adr 0021 am. 80): the chosen chains
    /// `[from, from + max)` (the caller's slice and meta headroom, adr 0021 am. 51). `Ok((next, chosen))`: the window is done,
    /// `next` = the first chain after it, of `chosen`. `Err(Miss)`: the pages to route to them were queued, retry the window after `Wake`.
    ///
    /// Txns between the windows (and retries) cannot break a fold: the list is chosen once per checkpoint
    /// (`Tree::delta_victims`, dropped at the freeze begin), so every window indexes the same entries, and txns change only
    /// leaves. `Tree::consolidate` folds an entry only while the leaf at its route is still the chain's page (changed but
    /// not split: it is written whole, which is what a fold does) and drops the chain otherwise (split: the halves are
    /// dirty with `F_MOD`, written whole; retired: the page leaves the tree at the next checkpoint). A fold repeated by a
    /// retry only marks a marked leaf again; entries a start does not reach (fold budget spent, trigger gone) keep their
    /// chains for the next checkpoint. Crash runs with one fold per poll and txns between: `delta.rs`
    /// `crash_runs_with_a_sliced_freeze` (no relog).
    pub fn delta_gc(&mut self, from: usize, max: usize) -> Result<(usize, usize)> {
        let (window, total) = self.tree.delta_victims(from, max);
        // the window in one pass: its misses are queued together (parallel loads)
        let (mut miss, mut misses) = (false, 0);
        for (addr, crc, route) in &window {
            match self.tree.consolidate(*addr, *crc, route) {
                Ok(()) => {}
                Err(StoreError::Miss) => {
                    miss = true;
                    misses += 1;
                    if misses >= 64 {
                        break; // a bounded wave of loads; the retry continues
                    }
                }
                Err(e) => return Err(e),
            }
        }
        if miss {
            return Err(StoreError::Miss);
        }
        Ok((from + window.len(), total))
    }

    /// Write the stale bitmap chunks into the tree (before a checkpoint freeze). `Err(Miss)`: the pages they
    /// live on were queued for loading, nothing was changed, retry after `Wake`.
    pub fn flush_chunks(&mut self) -> Result<()> {
        self.flush_chunks_upto(usize::MAX)
    }

    /// Write up to `max` of the stale bitmap chunks into the tree: a slice of the checkpoint start (adr 0021 am. 80),
    /// the oldest stale chunks first; chunks a txn marks meanwhile join the set (a flushed one again), the slice that
    /// begins the freeze writes the rest. `Err(Miss)`: the pages they live on were queued for loading, nothing was
    /// changed, retry after `Wake`.
    pub fn flush_chunks_upto(&mut self, max: usize) -> Result<()> {
        let k = max.min(self.dirty_chunks.len());
        if k == 0 {
            return Ok(());
        }
        let mut paths = PathSet::default();
        let mut miss = false;
        for &ci in &self.dirty_chunks[..k] {
            match self.tree.probe_path(&fkey(ci), &mut paths) {
                Ok(()) => {}
                Err(StoreError::Miss) => miss = true,
                Err(e) => return Err(e),
            }
        }
        if miss {
            return Err(StoreError::Miss);
        }
        self.dirty_chunks[..k].sort_unstable();
        let mut buf = [0u8; CHUNK_BYTES];
        for j in 0..k {
            let ci = self.dirty_chunks[j];
            if self.alloc.chunk_bytes(ci, &mut buf) {
                self.tree.put(&fkey(ci), &buf)?;
            } else {
                self.tree.del(&fkey(ci))?;
            }
            self.chunk_dirty[(ci / 64) as usize] &= !(1 << (ci % 64));
        }
        self.dirty_chunks.drain(..k);
        self.tree.finish_txn()?;
        Ok(())
    }

    /// `prepare` + `apply` with synchronous page loads (mount/replay only).
    pub fn apply_blocking<D: BlockDev, C: Clock>(
        &mut self,
        io: &mut Sio<D, C>,
        rec: &Record,
    ) -> Result<()> {
        loop {
            let r = self
                .prepare_ex(rec, false)
                .and_then(|_| self.apply(rec).map_err(|(e, _)| e));
            match r {
                Err(StoreError::Miss) => fill_blocking(&mut self.tree, io)?,
                Err(StoreError::Invalid(m)) => {
                    return Err(StoreError::Corrupt(format!("lsn {}: {m}", rec.lsn)));
                }
                other => {
                    self.tree.shrink();
                    return other;
                }
            }
        }
    }

    /// Load the persisted data bitmap (`f` chunks) into the allocator.
    pub fn load_alloc<D: BlockDev, C: Clock>(&mut self, io: &mut Sio<D, C>) -> Result<()> {
        // read all bitmap leaves in one parallel round per tree level, then scan from the cache
        loop {
            match self.tree.prefetch_range(b"f", b"g") {
                Ok(()) => break,
                Err(StoreError::Miss) => fill_blocking(&mut self.tree, io)?,
                Err(e) => return Err(e),
            }
        }
        let mut cur = ScanCursor::new(b"f", b"g");
        let mut chunks: Vec<(u64, Vec<u8>)> = Vec::new();
        loop {
            let r = self.tree.scan(&mut cur, 1 << 16, usize::MAX, &mut |k, v| {
                if k.len() == 9 {
                    chunks.push((u64::from_be_bytes(k[1..].try_into().unwrap()), v.to_vec()));
                }
            });
            match r {
                Ok(ScanStatus::Done) => break,
                Ok(ScanStatus::More) => {}
                Err(StoreError::Miss) => fill_blocking(&mut self.tree, io)?,
                Err(e) => return Err(e),
            }
        }
        for (ci, v) in chunks {
            self.alloc
                .load_chunk(ci, &v)
                .map_err(|m| StoreError::Corrupt(format!("bitmap chunk {ci}: {m}")))?;
        }
        self.tree.shrink();
        Ok(())
    }
}

/// Read the pages the tree asked for (blocking).
pub fn fill_blocking<D: BlockDev, C: Clock>(tree: &mut Tree, io: &mut Sio<D, C>) -> Result<()> {
    let mut wants = Vec::new();
    tree.take_wants(&mut wants);
    if wants.is_empty() {
        return Err(StoreError::Corrupt("tree miss without wanted pages".into()));
    }
    let bpp = tree.geom().bpp as u32;
    let reqs: Vec<(u64, u32)> = wants.iter().map(|w| (w.addr, bpp)).collect();
    let bufs = io.read(&reqs)?;
    for (w, b) in wants.iter().zip(&bufs) {
        tree.install(w, b)?;
    }
    Ok(())
}

/// Hot point-key cache (write-through, derived only from the applied record stream): committed values of the
/// key tags the object layer reads on every txn (collection, name, onode records), including negative
/// answers. Coherency is by construction: the only mutation entry point of a shard's tree is `State::apply`
/// (live commit and WAL replay alike), and it updates or drops the cached copy of every key it touches
/// (`DelRange` drops the covered range). Checkpoints do not change logical content. Disabled (`cap == 0`)
/// until a layer enables it, so replay and the raw KV API never populate it.
#[derive(Debug, Default)]
pub struct PointCache {
    tags: [u64; 4],
    cap: usize,
    map: FxMap<Vec<u8>, Option<Vec<u8>>>,
    /// Heap estimate of the entries ([`PointCache::bytes`]), kept current so the accounting never walks the map.
    heap: usize,
}

/// Heap estimate of one entry: key + value with the allocator's per-block overhead (~16 B each).
#[inline]
fn pc_cost(k: &[u8], v: Option<&[u8]>) -> usize {
    k.len() + v.map_or(0, <[u8]>::len) + 32
}

impl PointCache {
    pub fn enable(&mut self, tags: &[u8], cap: usize) {
        self.tags = [0; 4];
        for &t in tags {
            self.tags[(t >> 6) as usize] |= 1 << (t & 63);
        }
        self.cap = cap;
        self.map.clear();
        self.heap = 0;
    }

    #[inline]
    fn wants(&self, k: &[u8]) -> bool {
        self.cap != 0
            && k.first()
                .is_some_and(|&t| self.tags[(t >> 6) as usize] >> (t & 63) & 1 != 0)
    }

    fn fill(&mut self, k: &[u8], v: Option<&[u8]>) {
        if self.map.len() >= self.cap {
            self.map.clear();
            self.heap = 0;
        }
        self.heap += pc_cost(k, v);
        if let Some(old) = self.map.insert(k.to_vec(), v.map(<[u8]>::to_vec)) {
            self.heap -= pc_cost(k, old.as_deref());
        }
    }

    fn set(&mut self, k: &[u8], v: Option<&[u8]>) {
        if !self.wants(k) {
            return;
        }
        match self.map.get_mut(k) {
            Some(e) => {
                self.heap = self.heap + pc_cost(k, v) - pc_cost(k, e.as_deref());
                match (e, v) {
                    (Some(old), Some(new)) => {
                        old.clear();
                        old.extend_from_slice(new);
                    }
                    (e, v) => *e = v.map(<[u8]>::to_vec),
                }
            }
            None => self.fill(k, v),
        }
    }

    /// Drop the entries inside `[a, b)`. An empty bound is the open end of the range (empty `a`: every key below `b`).
    fn del_range(&mut self, a: &[u8], b: &[u8]) {
        if self.map.is_empty() {
            return;
        }
        // may the cache hold a key inside the range at all? Only its tag decides: any tag in `a[0]..=b[0]` (the tags are
        // the first key bytes), and none when `b` is empty (no key is below an empty bound)
        let hit = (0..=255u8).any(|t| {
            self.wants(&[t])
                && a.first().is_none_or(|&x| x <= t)
                && (b.first().is_some_and(|&y| y > t) || b.first() == Some(&t) && b.len() > 1)
        });
        if hit {
            let heap = &mut self.heap;
            self.map.retain(|k, v| {
                let keep = !(a <= k.as_slice() && k.as_slice() < b);
                if !keep {
                    *heap -= pc_cost(k, v.as_deref());
                }
                keep
            });
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    /// RAM held (O(1)): keys + values with the allocator's per-block overhead, plus the table slots (key and value Vec
    /// headers + control byte: kept at their peak after `clear`).
    pub fn bytes(&self) -> u64 {
        debug_assert_eq!(
            self.heap,
            self.map
                .iter()
                .map(|(k, v)| pc_cost(k, v.as_deref()))
                .sum::<usize>()
        );
        (self.heap + self.map.capacity() * 56) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty upper bound is the open end of a range: no key is below it, so nothing is dropped (the tag gate must
    /// not treat the empty bound as "everything").
    #[test]
    fn del_range_with_an_empty_upper_bound_keeps_the_cache() {
        let mut pc = PointCache::default();
        pc.enable(b"C", 8);
        pc.set(b"C1", Some(b"v"));
        pc.del_range(b"", b"");
        assert_eq!(pc.map.get(b"C1".as_slice()), Some(&Some(b"v".to_vec())));
    }

    /// An empty lower bound is the open start of a range: cached keys below the upper bound (`"" .. b"D"`) are
    /// deleted from the tree, so the cache must not keep them.
    #[test]
    fn del_range_with_an_empty_lower_bound_drops_cached_keys() {
        let mut pc = PointCache::default();
        pc.enable(b"CD", 8);
        pc.set(b"C1", Some(b"v"));
        pc.set(b"C2", Some(b"w"));
        pc.set(b"D1", Some(b"x"));
        pc.del_range(b"", b"D");
        assert!(!pc.map.contains_key(b"C1".as_slice()));
        assert!(!pc.map.contains_key(b"C2".as_slice()));
        assert_eq!(pc.map.get(b"D1".as_slice()), Some(&Some(b"x".to_vec())));
    }
}
