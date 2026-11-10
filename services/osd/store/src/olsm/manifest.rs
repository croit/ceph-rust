// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Run set of one shard (adr 0610 (2)-(4), am. 2 partitioned tiers): the tiers, the merge policy and the manifest
//! record of one run.
//!
//! Shape:
//! - Tier 0: flush runs, unpartitioned (each may span the whole keyspace), newest first, LSN-contiguous.
//! - Tier `t >= 1`: disjoint key-range partitions `[lo, hi)`; a partition holds up to [`FAN`] runs (newest first,
//!   each inside the partition's range). Only partitions holding a run exist; a key outside every partition of a
//!   tier (a gap) has no data in that tier.
//! - Age order of the sources of one key: memtables, tier-0 runs, then per tier the runs of the one partition
//!   holding the key. Inside tier 0 and inside a partition the run id orders by age (a higher id is newer).
//!
//! Merges (one policy, no size switches):
//! - Tier 0 holding [`FAN`] runs: its oldest [`FAN`] runs merge into tier 1.
//! - A partition holding [`FAN`] runs: all of them merge into the next tier (push-down). A bottom merge (no
//!   deeper tier holds data in the partition's range) whose output stays below the next size class (`tier(out, n0)
//!   == 0`: mostly shadowed or deleted data) stays in its tier instead (in-place), so overwrite and append+trim
//!   loads do not deepen the structure.
//! - The output is split by the target tier's partitions inside the source range: data inside an existing
//!   partition becomes one new run of it; data in a gap is cut into new partitions of `cut = input bytes / FAN`
//!   (guards = the first key of each piece, chosen from the data), so partitions keep about the size of one
//!   flush. A run moves down once per tier: write amplification as size-tiered (WAL + flush + one rewrite per tier).
//! - Merges in flight lock their source and target `(tier, range)`; a merge that would overlap a lock is not
//!   picked. So arrivals into one partition are installed in pick order and the run id orders them by age.

use super::run::{ChunkRead, RunMeta, load_meta};
use super::{FAN, Gk, Place, RangeT, below};
use crate::StoreError;
use crate::codec::{Dec, Enc};
use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::Arc;

/// Space target of the routine GC arm, `used / live` as `(num, den)` = 1.3 (adr 0610 am. 5). A group (tier 0 or one
/// partition) is merged once its estimated garbage `g` reaches `1 - den/num` of its bytes `b` (`g * num >= b * (num -
/// den)`, here 3/13): every group below that share keeps the shard at `used <= live * num / den` (the sum of the
/// groups' garbage is at most `(num - den) / num` of all run bytes). Rewriting a group at the threshold costs
/// `den / (num - den)` = 3.3 device bytes per reclaimed byte.
pub const GC_AMP: (u64, u64) = (13, 10);
/// Space target of the space-pressure arm (the shard is short of space, see [`Manifest::pick_merge`]): 1.1, the
/// BlueStore space parity target of adr 0610 am. 5 (`used <= 1.1 x live`); at most 10 device bytes per reclaimed
/// byte.
pub const GC_AMP_PRESSURE: (u64, u64) = (11, 10);

/// Defines [`Space`] and its `+=` / `-=` from one field list, so a new field cannot miss either.
macro_rules! space {
    ($(#[$sm:meta])* struct { $($(#[$m:meta])* $f:ident),* $(,)? }) => {
        $(#[$sm])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct Space {
            $($(#[$m])* pub $f: u64,)*
        }

        impl std::ops::AddAssign for Space {
            fn add_assign(&mut self, o: Space) {
                $(self.$f += o.$f;)*
            }
        }

        impl std::ops::SubAssign for Space {
            fn sub_assign(&mut self, o: Space) {
                $(self.$f -= o.$f;)*
            }
        }
    };
}

space! {
    /// The sums of one run or of a run group (tier 0, one partition, the whole shard), maintained as runs are installed
    /// and removed (adr 0610 am. 5): the space gauges and the GC arms read them without a pass over the runs.
    ///
    /// Garbage estimate ([`Manifest::garbage`]), from the run meta only (no IO): a point tombstone is garbage itself and
    /// shadows about one older put of the shard's average put size (`tomb_bytes + tombs x put_bytes / puts` over the
    /// whole shard); a range tombstone shadows the older chunks it covers whole (`shadow`, fixed when the run is
    /// installed). Overwrites (a put shadowing an older put) are not estimated: the size-tiered policy bounds them.
    struct {
        /// Payload bytes.
        bytes,
        /// Device blocks (chunks and metas).
        blocks,
        /// Resident RAM of the run metas.
        ram,
        runs,
        /// Point tombstones and their payload share (a mixed chunk splits its bytes by entry count).
        tombs,
        tomb_bytes,
        /// Puts and their payload share.
        puts,
        put_bytes,
        /// Payload bytes of older chunks wholly covered by the range tombstones.
        shadow,
    }
}

/// Payload bytes of `s`'s chunks wholly covered by the range tombstone `x` (chunks [`super::job::plan`] drops).
fn covered(s: &RunMeta, x: &RangeT) -> u64 {
    let mut b = 0u64;
    for f in &s.fences[s.seek_chunk(x.id, &x.first)..] {
        if f.first_id > x.id
            || f.first_id == x.id && f.first[..] >= x.first[..] && !x.covers(f.first_id, &f.first)
        {
            break;
        }
        if f.first_id == f.last_id && x.covers_span(f.first_id, &f.first, &f.last) {
            b += u64::from(f.len);
        }
    }
    b
}

/// `g / b` reaches `1 - den / num` (see [`GC_AMP`]); `b = 0` with garbage (a run of range tombstones only) does.
fn gc_due(g: u64, b: u64, (num, den): (u64, u64)) -> bool {
    g > 0 && u128::from(g) * u128::from(num) >= u128::from(b) * u128::from(num - den)
}

/// Estimated garbage `g` of `b` payload bytes (a GC candidate), ordered by the share `g / b` (cross-multiplied, no
/// division; `b = 0` orders as one byte).
#[derive(Clone, Copy, Debug)]
struct Share {
    g: u64,
    b: u64,
}

impl Share {
    fn due(self, amp: (u64, u64)) -> bool {
        gc_due(self.g, self.b, amp)
    }
}

impl Ord for Share {
    fn cmp(&self, o: &Share) -> Ordering {
        (u128::from(self.g) * u128::from(o.b.max(1)))
            .cmp(&(u128::from(o.g) * u128::from(self.b.max(1))))
    }
}

impl PartialOrd for Share {
    fn partial_cmp(&self, o: &Share) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

impl PartialEq for Share {
    fn eq(&self, o: &Share) -> bool {
        self.cmp(o) == Ordering::Equal
    }
}

impl Eq for Share {}

/// Manifest record value of one run (tree record `l R <run id be64>`, adr 0610 am. 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunDesc {
    pub id: u64,
    pub lsn_lo: u64,
    pub lsn_hi: u64,
    pub meta_blk: u64,
    pub meta_nblk: u32,
    pub meta_crc: u32,
    pub chunks: u32,
    pub entries: u64,
    pub tombs: u64,
    pub data_bytes: u64,
    pub place: Place,
}

/// Record format version (2: with the run's place).
const DESC_V: u8 = 2;

impl RunDesc {
    pub fn of(m: &RunMeta) -> RunDesc {
        RunDesc {
            id: m.id,
            lsn_lo: m.lsn_lo,
            lsn_hi: m.lsn_hi,
            meta_blk: m.meta_blk,
            meta_nblk: m.meta_nblk,
            meta_crc: m.meta_crc,
            chunks: m.fences.len() as u32,
            entries: m.entries,
            tombs: m.tombs,
            data_bytes: m.data_bytes(),
            place: m.place.clone(),
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u8(DESC_V)
            .u64(self.id)
            .u64(self.lsn_lo)
            .u64(self.lsn_hi)
            .u64(self.meta_blk)
            .u32(self.meta_nblk)
            .u32(self.meta_crc)
            .u32(self.chunks)
            .u64(self.entries)
            .u64(self.tombs)
            .u64(self.data_bytes)
            .u32(self.place.tier);
        let p = &self.place;
        e.u64(p.lo.id).u32(p.lo.key.len() as u32).bytes(&p.lo.key);
        match &p.hi {
            Some(h) => e.u8(1).u64(h.id).u32(h.key.len() as u32).bytes(&h.key),
            None => e.u8(0),
        };
        e.b
    }
    pub fn decode(b: &[u8]) -> Result<RunDesc, StoreError> {
        let bad = || StoreError::Corrupt("olsm: run record".into());
        let mut d = Dec::new(b);
        if d.u8().ok_or_else(bad)? != DESC_V {
            return Err(bad());
        }
        let mut r = RunDesc {
            id: d.u64().ok_or_else(bad)?,
            lsn_lo: d.u64().ok_or_else(bad)?,
            lsn_hi: d.u64().ok_or_else(bad)?,
            meta_blk: d.u64().ok_or_else(bad)?,
            meta_nblk: d.u32().ok_or_else(bad)?,
            meta_crc: d.u32().ok_or_else(bad)?,
            chunks: d.u32().ok_or_else(bad)?,
            entries: d.u64().ok_or_else(bad)?,
            tombs: d.u64().ok_or_else(bad)?,
            data_bytes: d.u64().ok_or_else(bad)?,
            place: Place::default(),
        };
        r.place.tier = d.u32().ok_or_else(bad)?;
        let gk = |d: &mut Dec| -> Result<Gk, StoreError> {
            let id = d.u64().ok_or_else(bad)?;
            let n = d.u32().ok_or_else(bad)? as usize;
            Ok(Gk::new(id, d.bytes(n).ok_or_else(bad)?))
        };
        r.place.lo = gk(&mut d)?;
        r.place.hi = match d.u8().ok_or_else(bad)? {
            0 => None,
            1 => Some(gk(&mut d)?),
            _ => return Err(bad()),
        };
        let ok_range = r.place.hi.as_ref().is_none_or(|h| *h > r.place.lo);
        let ok_top = r.place.tier != 0 || (r.place.lo == Gk::MIN && r.place.hi.is_none());
        if d.left() != 0 || !ok_range || !ok_top {
            return Err(bad());
        }
        Ok(r)
    }
    /// Mount: load the run's resident metadata and check it against this record.
    pub fn load(&self, rd: &mut impl ChunkRead) -> Result<RunMeta, StoreError> {
        let mut m = load_meta(rd, self.meta_blk, self.meta_nblk, self.meta_crc)?;
        m.place = self.place.clone();
        if RunDesc::of(&m) != *self {
            return Err(StoreError::Corrupt(format!(
                "olsm: run {} meta differs from its record",
                self.id
            )));
        }
        Ok(m)
    }
}

/// Size class of `bytes` payload bytes: classes centred on `n0 x FAN^t` (geometric midpoints as bounds). Class 0
/// (below `n0 x sqrt(FAN)`) decides that a bottom partition merge stays in its tier.
pub fn tier(bytes: u64, n0: u64) -> u32 {
    // Smallest t with bytes < n0 x FAN^(t + 1/2), i.e. bytes^2 < n0^2 x FAN^(2t + 1).
    let b2 = bytes as u128 * bytes as u128;
    let mut lim = n0.max(1) as u128 * n0.max(1) as u128 * FAN as u128;
    let mut t = 0;
    while b2 >= lim {
        t += 1;
        lim = lim.saturating_mul((FAN * FAN) as u128);
    }
    t
}

/// One partition of a tier `t >= 1`.
#[derive(Debug, Clone)]
pub struct Part {
    pub lo: Gk,
    pub hi: Option<Gk>,
    /// Newest first; never empty.
    pub runs: Vec<Arc<RunMeta>>,
    /// The sums of each run as installed (parallel to `runs`): a merge of the oldest runs subtracts exactly what
    /// their install added.
    spaces: Vec<Space>,
    /// The sum of the partition's runs.
    sum: Space,
}

impl Part {
    /// The partition holds `(id, key)`.
    pub fn holds(&self, id: u64, key: &[u8]) -> bool {
        self.lo.cmp_at(id, key) != Ordering::Greater && below(self.hi.as_ref(), id, key)
    }
}

/// Index of the partition of `parts` holding `(id, key)`, else `Err(i)` = index of the next partition (gap).
pub fn part_at(parts: &[Part], id: u64, key: &[u8]) -> Result<usize, usize> {
    let i = parts.partition_point(|p| p.lo.cmp_at(id, key) != Ordering::Greater);
    match i.checked_sub(1) {
        Some(j) if below(parts[j].hi.as_ref(), id, key) => Ok(j),
        _ => Err(i),
    }
}

/// `[a_lo, a_hi)` and `[b_lo, b_hi)` intersect.
fn overlaps(a_lo: &Gk, a_hi: Option<&Gk>, b_lo: &Gk, b_hi: Option<&Gk>) -> bool {
    below(a_hi, b_lo.id, &b_lo.key) && below(b_hi, a_lo.id, &a_lo.key)
}

/// One part of a merge's source range: an existing partition of the target tier (`part` = its range: the output
/// there joins it as its newest run) or a gap (new partitions are cut from the output). `lo`/`hi` are clipped to the
/// source range; the regions of a merge cover the source range in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region {
    pub lo: Gk,
    pub hi: Option<Gk>,
    pub part: Option<(Gk, Option<Gk>)>,
}

/// A merge chosen by the policy.
#[derive(Debug, Clone)]
pub struct MergePick {
    /// Newest first: tier 0's oldest [`FAN`] runs or all runs of one partition; a column merge adds, tier by tier,
    /// all runs of every deeper partition of the column (partitions of one tier are disjoint, so the list orders the
    /// sources of every key by age).
    pub inputs: Vec<Arc<RunMeta>>,
    /// No older data than the inputs in the source range: tombstones vanish.
    pub bottom: bool,
    /// Tier of the newest inputs (the picked group).
    pub src_tier: u32,
    /// Tier of the output (`src_tier + 1` for a push-down; the column's deepest tier for a column merge); a bottom
    /// partition merge may stay in `src_tier` instead (see `stay`).
    pub dst_tier: u32,
    pub regions: Vec<Region>,
    /// Piece size of new partitions cut in gaps (payload bytes).
    pub cut: u64,
    /// A bottom partition merge: its output stays in `src_tier` when below size class 1 of `cut` (the smallest
    /// partition, so a partition that holds no more than about one cut stays).
    pub stay: bool,
    /// Run ids `first_id..end_id` reserved for the output runs.
    pub first_id: u64,
    pub end_id: u64,
    /// Picked by a garbage-driven arm (routine GC or space pressure), not by the size-tiered policy.
    pub gc: bool,
}

/// A `(tier, range)` held by a merge in flight (`owner` = the id of its newest input).
#[derive(Debug, Clone)]
struct Lock {
    owner: u64,
    tier: u32,
    lo: Gk,
    hi: Option<Gk>,
}

/// The run set of one shard.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Tier 0, newest first.
    top: Vec<Arc<RunMeta>>,
    /// `tiers[i]` = tier `i + 1`: partitions sorted by `lo`, disjoint.
    pub tiers: Vec<Vec<Part>>,
    /// Every omap op with LSN <= this is in a run (WAL floor input, replay start).
    pub flushed_lsn: u64,
    pub next_run_id: u64,
    /// Flush unit / size class base.
    pub n0: u64,
    locks: Vec<Lock>,
    /// The sums of each tier-0 run (parallel to `top`).
    top_spaces: Vec<Space>,
    /// The sums of all runs.
    total: Space,
    /// The last [`Manifest::pick_merge`] found nothing at this pressure and the run set and locks did not change
    /// since: the next call answers `None` without looking at a candidate.
    idle: Option<bool>,
    /// Partitions holding [`FAN`] runs or more (size-tiered merge due), in pick order (tier, then key).
    full: BTreeSet<(u32, Gk)>,
    /// Partitions that gained a run since the last pick: the next pick re-estimates their columns.
    dirty: Vec<(u32, Gk)>,
    /// GC candidates (adr 0610 am. 6): the column share of every partition whose column reached
    /// [`GC_AMP_PRESSURE`] when it was last estimated, best first from the back; `due_of` keys it by partition.
    due: BTreeSet<(Share, u32, Gk)>,
    due_of: BTreeMap<(u32, Gk), Share>,
    /// Partitions and candidates the merge selection looked at (column walks, candidate checks): the owner's pick
    /// cost (`olsm_pick_visits`).
    visits: Cell<u64>,
    /// Inputs one merge may take ([`Manifest::set_max_inputs`]), so its manifest txn fits the store's per-txn limits.
    max_inputs: usize,
}

impl Manifest {
    pub fn new(n0: u64) -> Manifest {
        Manifest {
            top: Vec::new(),
            tiers: Vec::new(),
            flushed_lsn: 0,
            next_run_id: 1,
            n0,
            locks: Vec::new(),
            top_spaces: Vec::new(),
            total: Space::default(),
            idle: None,
            full: BTreeSet::new(),
            dirty: Vec::new(),
            due: BTreeSet::new(),
            due_of: BTreeMap::new(),
            visits: Cell::new(0),
            max_inputs: usize::MAX,
        }
    }

    /// The input runs one merge may take, so its manifest txn fits the store's per-txn limits: the txn deletes one
    /// descriptor per input (keys spread over the descriptor key range: about one tree leaf each; a GC prefix's
    /// residual descriptors reuse those keys) and puts the outputs under the fresh ids [`Manifest::reserve_ids`]
    /// reserved (consecutive keys no other key lies between: one leaf for all). A size-tiered pick of a larger group
    /// merges its oldest runs; a garbage-driven group or column beyond it is not picked. The store derives it from its
    /// per-txn page budget.
    pub fn set_max_inputs(&mut self, n: usize) {
        if n != self.max_inputs {
            self.max_inputs = n;
            self.idle = None;
        }
    }

    /// Drop a pick whose manifest txn the store refused: its locks go, the run set is unchanged (its outputs were
    /// never published) and the next [`Manifest::pick_merge`] looks again.
    pub fn abort_merge(&mut self, inputs: &[Arc<RunMeta>]) {
        let owner = inputs[0].id;
        self.locks.retain(|l| l.owner != owner);
        self.idle = None;
    }

    /// Mount: rebuild from the manifest records and `flushed_lsn`.
    pub fn mount(
        n0: u64,
        flushed_lsn: u64,
        recs: &[RunDesc],
        rd: &mut impl ChunkRead,
    ) -> Result<Manifest, StoreError> {
        let bad = |w: &str| StoreError::Corrupt(format!("olsm: manifest: {w}"));
        let mut man = Manifest::new(n0);
        man.next_run_id = recs.iter().map(|r| r.id + 1).max().unwrap_or(1);
        man.flushed_lsn = flushed_lsn;
        let mut runs = recs
            .iter()
            .map(|r| r.load(rd).map(Arc::new))
            .collect::<Result<Vec<_>, _>>()?;
        // oldest first, so every insert below is the newest of its place
        runs.sort_by_key(|r| r.id);
        for r in runs {
            if r.place.tier == 0 {
                if man.top.first().is_some_and(|n| n.lsn_hi >= r.lsn_lo) {
                    return Err(bad("tier 0 lsn ranges overlap"));
                }
                man.place(r, Space::default());
                continue;
            }
            let (first, last) = r.span();
            let inside = |p: &Place| {
                first.as_ref().is_none_or(|f| p.lo <= *f)
                    && last
                        .as_ref()
                        .is_none_or(|l| below(p.hi.as_ref(), l.id, &l.key))
            };
            if !inside(&r.place) {
                return Err(bad("run outside its partition"));
            }
            let t = r.place.tier as usize;
            if man.tiers.len() < t {
                man.tiers.resize(t, Vec::new());
            }
            let parts = &man.tiers[t - 1];
            match parts.binary_search_by(|p| p.lo.cmp(&r.place.lo)) {
                Ok(i) if parts[i].hi == r.place.hi => {}
                Ok(_) => return Err(bad("partition bounds differ")),
                Err(i) => {
                    let prev_ok =
                        i == 0 || !below(parts[i - 1].hi.as_ref(), r.place.lo.id, &r.place.lo.key);
                    let next_ok = parts
                        .get(i)
                        .is_none_or(|n| !below(r.place.hi.as_ref(), n.lo.id, &n.lo.key));
                    if !prev_ok || !next_ok {
                        return Err(bad("partitions overlap"));
                    }
                }
            }
            man.place(r, Space::default());
        }
        man.rebuild_sums();
        Ok(man)
    }

    pub fn alloc_run_id(&mut self) -> u64 {
        self.next_run_id += 1;
        self.next_run_id - 1
    }

    /// Install a flushed run (newest of tier 0) and advance `flushed_lsn`.
    pub fn install_flush(&mut self, run: Arc<RunMeta>, flush_lsn: u64) {
        debug_assert!(self.top.first().is_none_or(|r| r.lsn_hi < run.lsn_lo));
        debug_assert_eq!(run.place, Place::default());
        self.insert(run);
        self.flushed_lsn = flush_lsn;
    }

    /// Tier-0 runs, newest first.
    pub fn top(&self) -> &[Arc<RunMeta>] {
        &self.top
    }

    /// Every run (tier 0, then the partitions tier by tier).
    pub fn runs(&self) -> impl Iterator<Item = &Arc<RunMeta>> {
        self.top
            .iter()
            .chain(self.tiers.iter().flatten().flat_map(|p| p.runs.iter()))
    }

    /// See [`Manifest::visits`].
    pub fn pick_visits(&self) -> u64 {
        self.visits.get()
    }

    /// The sums of all runs ([`Manifest::garbage`] of it = the shard's garbage estimate).
    pub fn space(&self) -> Space {
        self.total
    }

    fn locked(&self, tier: u32, lo: &Gk, hi: Option<&Gk>) -> bool {
        self.locks
            .iter()
            .any(|l| l.tier == tier && overlaps(&l.lo, l.hi.as_ref(), lo, hi))
    }

    /// Some tier deeper than `tier` holds data in `[lo, hi)`.
    fn data_below(&self, tier: u32, lo: &Gk, hi: Option<&Gk>) -> bool {
        self.tiers.iter().skip(tier as usize).any(|parts| {
            let i = match part_at(parts, lo.id, &lo.key) {
                Ok(i) | Err(i) => i,
            };
            parts
                .get(i)
                .is_some_and(|p| overlaps(&p.lo, p.hi.as_ref(), lo, hi))
        })
    }

    /// Regions of `[lo, hi)` against the partitions of tier `tier` (gaps and partitions in order).
    fn regions(&self, tier: u32, lo: &Gk, hi: Option<&Gk>) -> Vec<Region> {
        let parts: &[Part] = self.tiers.get(tier as usize - 1).map_or(&[], |v| &v[..]);
        let mut out = Vec::new();
        let mut cur = lo.clone();
        let start = match part_at(parts, lo.id, &lo.key) {
            Ok(i) | Err(i) => i,
        };
        for p in &parts[start..] {
            if !below(hi, p.lo.id, &p.lo.key) {
                break;
            }
            if p.lo > cur {
                out.push(Region {
                    lo: cur,
                    hi: Some(p.lo.clone()),
                    part: None,
                });
                cur = p.lo.clone();
            }
            let end = match (&p.hi, hi) {
                (Some(a), Some(b)) => Some(a.min(b).clone()),
                (Some(a), None) => Some(a.clone()),
                (None, b) => b.cloned(),
            };
            out.push(Region {
                lo: cur,
                hi: end.clone(),
                part: Some((p.lo.clone(), p.hi.clone())),
            });
            match end {
                Some(e) => cur = e,
                None => return out,
            }
        }
        if below(hi, cur.id, &cur.key) {
            out.push(Region {
                lo: cur,
                hi: hi.cloned(),
                part: None,
            });
        }
        out
    }

    /// Piece size of new partitions cut in gaps: one flush unit, at least one chunk (adr 0610 am. 6). A smaller
    /// partition pays a merge's fixed cost (run meta, manifest record, pick) for less data than a flush carries, and
    /// below one chunk its chunks are short and rewritten by every merge; a size-tiered merge of `FAN` flush-sized
    /// runs cuts `FAN` pieces. A cut relative to the input would let garbage merges of small groups cut `FAN` ever
    /// smaller partitions, tier by tier.
    fn cut(&self) -> u64 {
        self.n0.max(super::CHUNK_TARGET as u64)
    }

    /// Reserve the output run ids of a merge of `input` payload bytes into `regions` regions: one per partition
    /// region, per gap at most one piece more than its share of `input / cut` pieces.
    fn reserve_ids(&mut self, input: u64, regions: usize) -> (u64, u64) {
        let first_id = self.next_run_id;
        self.next_run_id += regions as u64 + input.div_ceil(self.cut()) + 1;
        (first_id, self.next_run_id)
    }

    /// A push-down (or in-place bottom merge) of one group (`group`: tier 0's oldest [`FAN`] runs or all runs of a
    /// partition, newest first). A size-tiered pick takes at most [`Manifest::set_max_inputs`] of the group's oldest
    /// runs; a part of a partition always moves down (its output holds older data than the runs staying, so it may not
    /// stay in their tier with a newer id). A garbage-driven pick takes the whole group or nothing (`None`).
    fn pick(&mut self, group: Vec<Arc<RunMeta>>, src: Place, gc: bool) -> Option<MergePick> {
        let dst = src.tier + 1;
        let (lo, hi) = (src.lo, src.hi);
        let k = group.len().min(self.max_inputs);
        if k == 0 || gc && k < group.len() {
            return None;
        }
        let whole = k == group.len();
        let mut inputs = group;
        inputs.drain(..inputs.len() - k);
        let regions = self.regions(dst, &lo, hi.as_ref());
        let bottom = !self.data_below(src.tier, &lo, hi.as_ref());
        let input: u64 = inputs.iter().map(|r| r.data_bytes()).sum();
        let (first_id, end_id) = self.reserve_ids(input, regions.len());
        let owner = inputs[0].id;
        for tier in [src.tier, dst] {
            self.locks.push(Lock {
                owner,
                tier,
                lo: lo.clone(),
                hi: hi.clone(),
            });
        }
        Some(MergePick {
            inputs,
            bottom,
            src_tier: src.tier,
            dst_tier: dst,
            regions,
            cut: self.cut(),
            stay: src.tier > 0 && bottom && whole,
            first_id,
            end_id,
            gc,
        })
    }

    /// A column merge (adr 0610 am. 6): the group `src` and every deeper partition of its column `[lo, hi)` merge
    /// into new partitions of the column's deepest tier `dst` (a bottom merge: tombstones and what they shadow
    /// vanish). The group and the column's range in every tier below it stay locked until the install. `None`: the
    /// column takes more inputs than one manifest txn holds ([`Manifest::set_max_inputs`]); a column is merged whole or
    /// not at all.
    fn pick_col(
        &mut self,
        inputs: Vec<Arc<RunMeta>>,
        src: Place,
        (lo, hi, dst): (Gk, Option<Gk>, u32),
    ) -> Option<MergePick> {
        if inputs.len() > self.max_inputs {
            return None;
        }
        let input: u64 = inputs.iter().map(|r| r.data_bytes()).sum();
        let (first_id, end_id) = self.reserve_ids(input, 1);
        let owner = inputs[0].id;
        self.locks.push(Lock {
            owner,
            tier: src.tier,
            lo: src.lo,
            hi: src.hi,
        });
        for tier in src.tier + 1..=dst {
            self.locks.push(Lock {
                owner,
                tier,
                lo: lo.clone(),
                hi: hi.clone(),
            });
        }
        Some(MergePick {
            inputs,
            bottom: true,
            src_tier: src.tier,
            dst_tier: dst,
            regions: vec![Region { lo, hi, part: None }],
            cut: self.cut(),
            stay: false,
            first_id,
            end_id,
            gc: true,
        })
    }

    /// The next merge by the policy (its inputs and targets stay locked until [`Manifest::install_merge`]), in this
    /// order (adr 0610 am. 5, am. 6):
    /// - `pressure` (the shard is short of space): garbage-driven at [`GC_AMP_PRESSURE`];
    /// - the size-tiered policy ([`Manifest::pick_sized`]): it keeps the run count per group below [`FAN`] (the read
    ///   bound), so garbage-driven merges never starve it;
    /// - routine GC at [`GC_AMP`].
    ///
    /// A garbage-driven merge is a column merge ([`Manifest::pick_col`]): a group with its column, the data its
    /// tombstones can shadow, so the garbage it is chosen for vanishes in this merge (a push-down only carries
    /// tombstones one tier closer and reclaims nothing). It is chosen when the column's garbage share reaches the
    /// arm's target, i.e. when the live bytes it rewrites per reclaimed byte stay within the target's bound: best
    /// share first among the partitions' columns, else the oldest tier-0 runs and their remaining column once the
    /// shard as a whole is at its target. A completed prefix outside those runs' key/range coverage is left alone.
    /// The garbage leaves with the merge; a column is picked again only
    /// after new runs brought new garbage.
    ///
    /// Cost per call: the size-tiered candidates and the GC candidates are kept sorted as runs are installed and
    /// removed (O(log n) per call); a partition's column is re-estimated once after it gained a run (charged to that
    /// install) and once more when it reaches the front.
    pub fn pick_merge(&mut self, pressure: bool) -> Option<MergePick> {
        if self.idle == Some(pressure) {
            return None;
        }
        let p = pressure
            .then(|| self.pick_gc(GC_AMP_PRESSURE))
            .flatten()
            .or_else(|| self.pick_sized())
            .or_else(|| self.pick_gc(GC_AMP));
        if p.is_none() {
            self.idle = Some(pressure);
        }
        p
    }

    /// Index of the partition of tier `t >= 1` starting at `lo`.
    fn find(&self, t: u32, lo: &Gk) -> Option<usize> {
        self.tiers
            .get(t as usize - 1)?
            .binary_search_by(|p| p.lo.cmp(lo))
            .ok()
    }

    /// The size-tiered policy alone: tier 0 holding [`FAN`] runs merges its oldest [`FAN`] runs, a partition holding
    /// [`FAN`] runs merges all of them (tier 0 first, then the partitions tier by tier). The crash matrix picks it to
    /// cut a known merge type.
    pub fn pick_sized(&mut self) -> Option<MergePick> {
        let whole = Place::default();
        if self.top.len() >= FAN
            && !self.locked(0, &whole.lo, None)
            && !self.locked(1, &whole.lo, None)
        {
            let inputs = self.top[self.top.len() - FAN..].to_vec();
            if let Some(p) = self.pick(inputs, whole, false) {
                return Some(p);
            }
        }
        let mut after: Option<(u32, Gk)> = None;
        loop {
            let (t, i) = self
                .full
                .range((
                    after
                        .as_ref()
                        .map_or(Bound::Unbounded, |a| Bound::Excluded(a.clone())),
                    Bound::Unbounded,
                ))
                .find_map(|(t, lo)| {
                    self.visits.set(self.visits.get() + 1);
                    let i = self.find(*t, lo)?;
                    let p = &self.tiers[*t as usize - 1][i];
                    (!self.locked(*t, &p.lo, p.hi.as_ref())
                        && !self.locked(t + 1, &p.lo, p.hi.as_ref()))
                    .then_some((*t, i))
                })?;
            let p = &self.tiers[t as usize - 1][i];
            let src = Place {
                tier: t,
                lo: p.lo.clone(),
                hi: p.hi.clone(),
            };
            after = Some((t, p.lo.clone()));
            let inputs = p.runs.clone();
            if let Some(m) = self.pick(inputs, src, false) {
                return Some(m);
            }
        }
    }

    /// Device bytes of one flush output: `1.05 x n0` (format overhead 5 %, adr 0610 phase 0).
    pub fn flush_out(&self) -> u64 {
        self.n0 * 21 / 20
    }

    /// Space the engine needs free beside its runs (adr 0610 am. 5): one flush output, one merge output and the
    /// inputs a merge freed that stay held until the next checkpoint, one [`Manifest::flush_out`] each. Free space below
    /// it is space pressure.
    pub fn slack(&self) -> u64 {
        3 * self.flush_out()
    }

    /// Accounted run/lease bytes exceed the routine GC target: `GC_AMP x live + slack - 2 x flush_out`, where live
    /// is run payload less estimated garbage. Foreground admission combines this debt with physical pressure and an
    /// active merge; debt alone does not stop writes or guarantee a hard used/live bound while they continue.
    /// The two possible memtable flush outputs retain their allowance within the engine's slack.
    pub fn space_debt(&self, used: u64) -> bool {
        let t = &self.total;
        let live = t.bytes - self.garbage(t).min(t.bytes);
        let (num, den) = GC_AMP;
        let room = self.slack() - 2 * self.flush_out();
        u128::from(used) * u128::from(den)
            > u128::from(live) * u128::from(num) + u128::from(room) * u128::from(den)
    }

    /// Estimated garbage bytes of `s` (see [`Space`]): its tombstones, the puts they shadow at the shard's average put
    /// size, and the chunks its range tombstones cover.
    pub fn garbage(&self, s: &Space) -> u64 {
        let t = &self.total;
        let shadowed = u128::from(s.tombs) * u128::from(t.put_bytes) / u128::from(t.puts.max(1));
        s.tomb_bytes + shadowed as u64 + s.shadow
    }

    /// The column of the range `[lo, hi)` of a group of tier `tier`: every deeper partition overlapping the range,
    /// closed downwards (a partition taken at one tier widens the range the deeper tiers are matched against, so the
    /// column holds every older version of every key it holds). `f(tier, index)` sees each partition taken, tier by
    /// tier in key order. Returns the closed range and the deepest tier taken (`tier` itself: nothing deeper overlaps,
    /// the group is at the bottom). Partitions of one tier above that are not taken hold newer data than the column's
    /// output at its deepest tier, so the age order of every key holds after the install.
    fn column(
        &self,
        tier: u32,
        lo: &Gk,
        hi: Option<&Gk>,
        mut f: impl FnMut(u32, usize),
    ) -> (Gk, Option<Gk>, u32) {
        let (mut lo, mut hi) = (lo.clone(), hi.cloned());
        let mut deepest = tier;
        for (ti, parts) in self.tiers.iter().enumerate().skip(tier as usize) {
            let t = ti as u32 + 1;
            let mut i = match part_at(parts, lo.id, &lo.key) {
                Ok(i) | Err(i) => i,
            };
            while let Some(p) = parts.get(i) {
                if !below(hi.as_ref(), p.lo.id, &p.lo.key) {
                    break;
                }
                if p.lo < lo {
                    lo = p.lo.clone();
                }
                hi = match (hi, &p.hi) {
                    (Some(a), Some(b)) => Some(a.max(b.clone())),
                    _ => None,
                };
                f(t, i);
                self.visits.set(self.visits.get() + 1);
                deepest = t;
                i += 1;
            }
        }
        (lo, hi, deepest)
    }

    /// Garbage share of the column of partition `i` of tier `t`.
    fn col_share(&self, t: u32, i: usize) -> Share {
        let p = &self.tiers[t as usize - 1][i];
        let mut s = p.sum;
        self.column(t, &p.lo, p.hi.as_ref(), |k, j| {
            s += self.tiers[k as usize - 1][j].sum
        });
        Share {
            g: self.garbage(&s),
            b: s.bytes,
        }
    }

    /// Garbage share of the shard's column: tier 0's oldest [`FAN`] runs (the newer ones may not move below them)
    /// and every partition.
    fn shard_share(&self) -> Share {
        let mut s = self.total;
        for x in &self.top_spaces[..self.top.len().saturating_sub(FAN)] {
            s -= *x;
        }
        Share {
            g: self.garbage(&s),
            b: s.bytes,
        }
    }

    /// Record the column share of partition `(t, lo)` as a GC candidate (`None`: not one).
    fn set_due(&mut self, t: u32, lo: &Gk, share: Option<Share>) {
        if let Some(old) = self.due_of.remove(&(t, lo.clone())) {
            self.due.remove(&(old, t, lo.clone()));
        }
        if let Some(sh) = share {
            self.due.insert((sh, t, lo.clone()));
            self.due_of.insert((t, lo.clone()), sh);
        }
    }

    /// Re-estimate the columns of the partitions that gained a run. A partition without garbage of its own is no
    /// candidate: its column adds only its own bytes to the columns of the partitions below it.
    fn refresh_due(&mut self) {
        let mut dirty = std::mem::take(&mut self.dirty);
        dirty.sort();
        dirty.dedup();
        for (t, lo) in dirty {
            let share = self
                .find(t, &lo)
                .filter(|i| self.garbage(&self.tiers[t as usize - 1][*i].sum) > 0)
                .map(|i| self.col_share(t, i))
                .filter(|sh| sh.due(GC_AMP_PRESSURE));
            self.set_due(t, &lo, share);
        }
    }

    /// The column merge of partition `i` of tier `t` (a plain bottom merge when nothing deeper overlaps it); `None`
    /// while a merge holds a part of it.
    fn pick_part_col(&mut self, t: u32, i: usize) -> Option<MergePick> {
        let p = &self.tiers[t as usize - 1][i];
        let src = Place {
            tier: t,
            lo: p.lo.clone(),
            hi: p.hi.clone(),
        };
        let mut taken = Vec::new();
        let col = self.column(t, &src.lo, src.hi.as_ref(), |k, j| taken.push((k, j)));
        if self.locked(t, &src.lo, src.hi.as_ref())
            || (t + 1..=col.2.max(t + 1)).any(|k| self.locked(k, &col.0, col.1.as_ref()))
        {
            return None;
        }
        let mut inputs = p.runs.clone();
        if col.2 == t {
            return self.pick(inputs, src, true);
        }
        for (k, j) in taken {
            inputs.extend(self.tiers[k as usize - 1][j].runs.iter().cloned());
        }
        self.pick_col(inputs, src, col)
    }

    /// The shard's whole column, including tier-only garbage or garbage before tier 0's remaining coverage.
    fn pick_whole_shard_col(&mut self) -> Option<MergePick> {
        let whole = Place::default();
        let deepest = self.tiers.len() as u32;
        if (0..=deepest.max(1)).any(|k| self.locked(k, &whole.lo, None)) {
            return None;
        }
        let mut inputs = self.top[self.top.len().saturating_sub(FAN)..].to_vec();
        if deepest == 0 {
            return (!inputs.is_empty())
                .then(|| self.pick(inputs, whole, true))
                .flatten();
        }
        for p in self.tiers.iter().flatten() {
            inputs.extend(p.runs.iter().cloned());
        }
        self.pick_col(inputs, whole, (Gk::MIN, None, deepest))
    }

    /// The oldest tier-0 runs' remaining column. A prefix already reclaimed by an earlier GC cannot be shadowed by
    /// these inputs once both their entries and range tombstones start later. Excluding that prefix avoids moving
    /// its unchanged runs and rebuilding their metadata again at every subsequent prefix install.
    fn pick_shard_col(&mut self, amp: (u64, u64)) -> Option<MergePick> {
        let start = self.top.len().saturating_sub(FAN);
        let mut inputs = self.top[start..].to_vec();
        let first = inputs
            .iter()
            .flat_map(|r| {
                r.fences
                    .first()
                    .map(|f| Gk {
                        id: f.first_id,
                        key: f.first.clone(),
                    })
                    .into_iter()
                    .chain(r.ranges.first().map(|x| Gk {
                        id: x.id,
                        key: x.first.clone(),
                    }))
            })
            .min();
        let Some(first) = first else {
            return self.pick_whole_shard_col();
        };
        let whole = Place::default();
        if self.locked(0, &whole.lo, None) {
            return None;
        }
        let mut parts = Vec::new();
        let mut col = self.column(0, &first, None, |t, i| parts.push((t, i)));
        let mut sum = Space::default();
        for s in &self.top_spaces[start..] {
            sum += *s;
        }
        for &(t, i) in &parts {
            sum += self.tiers[t as usize - 1][i].sum;
        }
        if !(Share {
            g: self.garbage(&sum),
            b: sum.bytes,
        })
        .due(amp)
        {
            // The coarse shard-wide eligibility may come from garbage outside this coverage. Keep the original
            // whole-column fallback so trimming does not lose that GC work or incorrectly cache the shard as idle.
            return self.pick_whole_shard_col();
        }
        // No deeper partition may overlap these tier-0 keys even when lower tiers contain an earlier clean prefix.
        // Such a bottom merge still writes tier 1, never tier 0 with a non-default place or overlapping LSN ranges.
        col.2 = col.2.max(1);
        if (1..=col.2).any(|t| self.locked(t, &col.0, col.1.as_ref())) {
            return None;
        }
        for (t, i) in parts {
            inputs.extend(self.tiers[t as usize - 1][i].runs.iter().cloned());
        }
        self.pick_col(inputs, whole, col)
    }

    /// Garbage-driven pick at `amp` (see [`Manifest::pick_merge`]): the partition column with the highest share at or
    /// above `amp` that no merge holds, else the shard's column when its share is.
    fn pick_gc(&mut self, amp: (u64, u64)) -> Option<MergePick> {
        self.refresh_due();
        // candidates found held by a merge in this call
        let mut held: Vec<(u32, Gk)> = Vec::new();
        loop {
            let next = self
                .due
                .iter()
                .rev()
                .take_while(|(sh, ..)| sh.due(amp))
                .find(|(_, t, lo)| !held.iter().any(|(ht, hl)| ht == t && hl == lo))
                .map(|(_, t, lo)| (*t, lo.clone()));
            let Some((t, lo)) = next else { break };
            self.visits.set(self.visits.get() + 1);
            let Some(i) = self.find(t, &lo) else {
                self.set_due(t, &lo, None);
                continue;
            };
            // the columns below may have changed since the estimate: the pick uses the current one
            let sh = self.col_share(t, i);
            if !sh.due(amp) {
                self.set_due(t, &lo, sh.due(GC_AMP_PRESSURE).then_some(sh));
                continue;
            }
            match self.pick_part_col(t, i) {
                Some(p) => return Some(p),
                None => held.push((t, lo)),
            }
        }
        if self.shard_share().due(amp) {
            return self.pick_shard_col(amp);
        }
        None
    }

    /// The sums of `run` as a new run of its place: counts from its fences, `shadow` against the runs older than it
    /// (older runs of its group, every deeper tier).
    fn run_space(&self, run: &RunMeta) -> Space {
        let mut s = Space {
            blocks: run.blocks(),
            ram: run.ram() as u64,
            runs: 1,
            ..Space::default()
        };
        for f in &run.fences {
            let (len, n, tombs) = (u64::from(f.len), u64::from(f.n), u64::from(f.tombs));
            let tb = len * tombs / n.max(1);
            s.bytes += len;
            s.tombs += tombs;
            s.tomb_bytes += tb;
            s.puts += n - tombs;
            s.put_bytes += len - tb;
        }
        if run.ranges.is_empty() {
            return s;
        }
        let t = run.place.tier as usize;
        let older: &[Arc<RunMeta>] = if t == 0 {
            &self.top
        } else {
            match self.tiers[t - 1].binary_search_by(|p| p.lo.cmp(&run.place.lo)) {
                Ok(i) => &self.tiers[t - 1][i].runs,
                Err(_) => &[],
            }
        };
        for x in &run.ranges {
            for o in older.iter().filter(|o| o.id < run.id) {
                s.shadow += covered(o, x);
            }
            for parts in self.tiers.iter().skip(t) {
                let i = match part_at(parts, x.id, &x.first) {
                    Ok(i) | Err(i) => i,
                };
                for p in parts[i..].iter().take_while(|p| match &x.end {
                    Some(e) => p.lo.cmp_at(x.id, e) == Ordering::Less,
                    None => p.lo.id <= x.id,
                }) {
                    for o in &p.runs {
                        s.shadow += covered(o, x);
                    }
                }
            }
        }
        s
    }

    /// Insert `run` by age in its place (creating its partition) with its sums. A GC prefix retains the original
    /// IDs of its suffix runs, so they may precede neither concurrent younger flushes nor another newer residual.
    fn insert(&mut self, run: Arc<RunMeta>) {
        let s = self.run_space(&run);
        self.place(run, s);
    }

    fn place(&mut self, run: Arc<RunMeta>, s: Space) {
        self.idle = None;
        self.total += s;
        let t = run.place.tier as usize;
        if t == 0 {
            let i = self.top.partition_point(|r| r.id > run.id);
            debug_assert!(self.top.get(i).is_none_or(|r| r.id != run.id));
            self.top.insert(i, run);
            self.top_spaces.insert(i, s);
            return;
        }
        if self.tiers.len() < t {
            self.tiers.resize(t, Vec::new());
        }
        let parts = &mut self.tiers[t - 1];
        let i = match parts.binary_search_by(|p| p.lo.cmp(&run.place.lo)) {
            Ok(i) => {
                debug_assert_eq!(parts[i].hi, run.place.hi);
                i
            }
            Err(i) => {
                parts.insert(
                    i,
                    Part {
                        lo: run.place.lo.clone(),
                        hi: run.place.hi.clone(),
                        runs: Vec::new(),
                        spaces: Vec::new(),
                        sum: Space::default(),
                    },
                );
                i
            }
        };
        let p = &mut parts[i];
        let at = p.runs.partition_point(|r| r.id > run.id);
        debug_assert!(p.runs.get(at).is_none_or(|r| r.id != run.id));
        p.runs.insert(at, run);
        p.spaces.insert(at, s);
        p.sum += s;
        let (lo, n) = (p.lo.clone(), p.runs.len());
        if n >= FAN {
            self.full.insert((t as u32, lo.clone()));
        }
        self.dirty.push((t as u32, lo));
    }

    /// Mount: the sums of every run against the complete run set (the runs were placed without them).
    fn rebuild_sums(&mut self) {
        let mut total = Space::default();
        let mut top = Space::default();
        let spaces: Vec<Space> = self.top.iter().map(|r| self.run_space(r)).collect();
        for s in &spaces {
            top += *s;
        }
        total += top;
        self.top_spaces = spaces;
        for t in 0..self.tiers.len() {
            for i in 0..self.tiers[t].len() {
                let spaces: Vec<Space> = self.tiers[t][i]
                    .runs
                    .iter()
                    .map(|r| self.run_space(r))
                    .collect();
                let mut sum = Space::default();
                for s in &spaces {
                    sum += *s;
                }
                total += sum;
                self.tiers[t][i].spaces = spaces;
                self.tiers[t][i].sum = sum;
            }
        }
        self.total = total;
    }

    /// Replace the inputs of a finished merge by its output runs and release its locks. The inputs are tier 0's oldest
    /// runs and / or whole partitions (a partition's runs adjacent in the list, see [`MergePick::inputs`]).
    pub fn install_merge(&mut self, inputs: &[Arc<RunMeta>], out: Vec<RunMeta>) {
        self.install_gc_prefix(inputs, out, Vec::new());
    }

    /// Install a completed key prefix and the unconsumed suffixes of its original inputs, releasing the pick's locks.
    /// The record-only manifest transaction must replace all input descriptors, including same-ID suffix descriptors,
    /// atomically before calling this method. The existing descriptor codec stores each suffix's new metadata pointer
    /// and clipped partition bounds; no replay format changes are needed.
    ///
    /// Suffix runs retain input IDs and LSN ranges. Their tier-0 places stay whole; tiered suffix partitions start at
    /// the cut (or their original lower bound if later). Runs flushed since the pick remain younger than every suffix.
    /// `residuals` may be empty, in which case this is an ordinary completed merge.
    pub fn install_gc_prefix(
        &mut self,
        inputs: &[Arc<RunMeta>],
        out: Vec<RunMeta>,
        mut residuals: Vec<RunMeta>,
    ) {
        self.idle = None;
        let owner = inputs[0].id;
        self.locks.retain(|l| l.owner != owner);
        let mut gone = Space::default();
        let ntop = inputs.iter().take_while(|r| r.place.tier == 0).count();
        if ntop > 0 {
            // the inputs are the oldest tier-0 runs; flushes installed since the pick sit in front of them
            let start = self.top.len() - ntop;
            debug_assert!(
                self.top[start..]
                    .iter()
                    .zip(inputs)
                    .all(|(a, b)| a.id == b.id),
                "the merge inputs are the oldest tier-0 runs"
            );
            self.top.truncate(start);
            let mut top = Space::default();
            for s in self.top_spaces.drain(start..) {
                top += s;
            }
            gone += top;
        }
        let mut k = ntop;
        while k < inputs.len() {
            let pl = &inputs[k].place;
            debug_assert!(pl.tier > 0, "tier-0 inputs come first");
            let i = self.find(pl.tier, &pl.lo).expect("merge source partition");
            // the inputs of one partition: its oldest runs (all of them, or the oldest that fit one manifest txn)
            let n = inputs[k..]
                .iter()
                .take_while(|r| r.place.tier == pl.tier && r.place.lo == pl.lo)
                .count();
            let parts = &mut self.tiers[pl.tier as usize - 1];
            let p = &mut parts[i];
            let keep = p.runs.len() - n;
            debug_assert!(
                p.runs[keep..]
                    .iter()
                    .zip(&inputs[k..])
                    .all(|(a, b)| a.id == b.id),
                "a merge takes the oldest runs of a partition"
            );
            k += n;
            let (t, lo) = (pl.tier, p.lo.clone());
            if keep == 0 {
                gone += parts.remove(i).sum;
                self.full.remove(&(t, lo.clone()));
                self.set_due(t, &lo, None);
                continue;
            }
            p.runs.truncate(keep);
            for s in p.spaces.drain(keep..) {
                p.sum -= s;
                gone += s;
            }
            if keep < FAN {
                self.full.remove(&(t, lo.clone()));
            }
            self.dirty.push((t, lo));
        }
        self.total -= gone;
        // Oldest first: range-shadow sums see their older inputs already installed. Placement still sorts by ID,
        // retaining concurrent younger tier-0 flushes in front of the old-ID residuals.
        residuals.sort_unstable_by_key(|r| r.id);
        for r in residuals {
            self.insert(Arc::new(r));
        }
        for r in out {
            self.insert(Arc::new(r));
        }
        while self.tiers.last().is_some_and(|p| p.is_empty()) {
            self.tiers.pop();
        }
    }
}

#[cfg(test)]
mod gc_prefix_tests {
    use super::*;
    use crate::olsm::labdev::MemBlocks;
    use crate::olsm::read::{self, Sources};
    use crate::olsm::run::RunBuilder;

    fn run(
        dev: &mut MemBlocks,
        id: u64,
        lsn: (u64, u64),
        place: Place,
        entries: &[(&[u8], &[u8])],
        ranges: &[(&[u8], Option<&[u8]>)],
    ) -> RunMeta {
        let mut b = RunBuilder::new();
        for (key, value) in entries {
            b.push(dev, 1, key, Some(value)).unwrap();
        }
        for (first, end) in ranges {
            b.add_range(RangeT {
                id: 1,
                first: bytes::Bytes::copy_from_slice(first),
                end: end.map(bytes::Bytes::copy_from_slice),
            });
        }
        let (mut run, _) = b.finish(dev, id, lsn.0, lsn.1).unwrap();
        run.place = place;
        run
    }

    fn place(tier: u32, lo: Gk, hi: Option<Gk>) -> Place {
        Place { tier, lo, hi }
    }

    fn contents(man: &Manifest, dev: &mut MemBlocks) -> Vec<(Vec<u8>, Vec<u8>)> {
        let src = Sources {
            mems: [None; 3],
            top: man.top(),
            tiers: &man.tiers,
        };
        let (rows, more) = read::list(&src, dev, 1, None, b"", usize::MAX).unwrap();
        assert!(!more);
        rows.into_iter()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect()
    }

    fn remount(man: &Manifest, dev: &mut MemBlocks) -> Manifest {
        let descs: Vec<_> = man
            .runs()
            .map(|r| RunDesc::decode(&RunDesc::of(r).encode()).unwrap())
            .collect();
        Manifest::mount(man.n0, man.flushed_lsn, &descs, dev).unwrap()
    }

    fn assert_contents(man: &Manifest, dev: &mut MemBlocks, expect: &[(&[u8], &[u8])]) {
        let expected: Vec<_> = expect
            .iter()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        assert_eq!(contents(man, dev), expected);
        let mounted = remount(man, dev);
        assert_eq!(contents(&mounted, dev), expected);
        assert_eq!(mounted.space(), man.space());
    }

    #[test]
    fn gc_prefix_manifest_keeps_concurrent_flush_and_range_suffix() {
        let mut dev = MemBlocks::new();
        let mut man = Manifest::new(64 << 10);
        man.insert(Arc::new(run(
            &mut dev,
            1,
            (1, 1),
            place(2, Gk::MIN, None),
            &[
                (b"a", b"A"),
                (b"b", b"B"),
                (b"c", b"C"),
                (b"d", b"D"),
                (b"e", b"E"),
                (b"f", b"F"),
            ],
            &[],
        )));
        man.insert(Arc::new(run(
            &mut dev,
            2,
            (2, 2),
            place(1, Gk::MIN, None),
            &[(b"b", b"B1"), (b"e", b"E1")],
            &[],
        )));
        man.install_flush(
            Arc::new(run(
                &mut dev,
                3,
                (3, 3),
                Place::default(),
                &[(b"f", b"F3")],
                &[(b"b", Some(b"e"))],
            )),
            3,
        );
        man.install_flush(
            Arc::new(run(
                &mut dev,
                4,
                (4, 4),
                Place::default(),
                &[(b"c", b"C4")],
                &[],
            )),
            4,
        );
        man.next_run_id = 5;
        let pick = man.pick_whole_shard_col().unwrap();
        let younger = man.alloc_run_id();
        man.install_flush(
            Arc::new(run(
                &mut dev,
                younger,
                (5, 5),
                Place::default(),
                &[(b"a", b"A5"), (b"f", b"F5")],
                &[],
            )),
            5,
        );
        let expected: &[(&[u8], &[u8])] =
            &[(b"a", b"A5"), (b"c", b"C4"), (b"e", b"E1"), (b"f", b"F5")];
        assert_contents(&man, &mut dev, expected);
        let cut = Gk::new(1, b"d");
        let prefix = run(
            &mut dev,
            pick.first_id,
            (1, 4),
            place(2, Gk::MIN, Some(cut.clone())),
            &[(b"a", b"A"), (b"c", b"C4")],
            &[],
        );
        let residuals = vec![
            run(
                &mut dev,
                3,
                (3, 3),
                Place::default(),
                &[(b"f", b"F3")],
                &[(b"d", Some(b"e"))],
            ),
            run(
                &mut dev,
                2,
                (2, 2),
                place(1, cut.clone(), None),
                &[(b"e", b"E1")],
                &[],
            ),
            run(
                &mut dev,
                1,
                (1, 1),
                place(2, cut.clone(), None),
                &[(b"d", b"D"), (b"e", b"E"), (b"f", b"F")],
                &[],
            ),
        ];
        man.install_gc_prefix(&pick.inputs, vec![prefix], residuals);
        assert_contents(&man, &mut dev, expected);
        assert_eq!(
            man.top.iter().map(|r| r.id).collect::<Vec<_>>(),
            [younger, 3]
        );
        assert_eq!((man.top[1].lsn_lo, man.top[1].lsn_hi), (3, 3));
        assert_eq!(man.top[1].ranges[0].first.as_ref(), b"d");
        assert_eq!(man.tiers[1].len(), 2);
        assert_eq!(man.tiers[1][0].hi.as_ref(), Some(&cut));
        assert_eq!(man.tiers[1][1].lo, cut);
        assert!(man.locks.is_empty());
    }

    #[test]
    fn gc_prefix_manifest_preserves_residual_age_inside_a_partition() {
        let mut dev = MemBlocks::new();
        let mut man = Manifest::new(64 << 10);
        for id in [1, 2] {
            let value: &[u8] = if id == 1 { b"old" } else { b"new" };
            man.insert(Arc::new(run(
                &mut dev,
                id,
                (id, id),
                place(1, Gk::MIN, None),
                &[(b"a", value), (b"z", value)],
                &[],
            )));
        }
        man.next_run_id = 3;
        let pick = man.pick_whole_shard_col().unwrap();
        let cut = Gk::new(1, b"m");
        let prefix = run(
            &mut dev,
            pick.first_id,
            (1, 2),
            place(1, Gk::MIN, Some(cut.clone())),
            &[(b"a", b"new")],
            &[],
        );
        // Deliberately newest first: retaining IDs must not depend on the job's result ordering.
        let residuals = vec![
            run(
                &mut dev,
                2,
                (2, 2),
                place(1, cut.clone(), None),
                &[(b"z", b"new")],
                &[],
            ),
            run(
                &mut dev,
                1,
                (1, 1),
                place(1, cut, None),
                &[(b"z", b"old")],
                &[],
            ),
        ];
        man.install_gc_prefix(&pick.inputs, vec![prefix], residuals);
        assert_contents(&man, &mut dev, &[(b"a", b"new"), (b"z", b"new")]);
        assert_eq!(
            man.tiers[0][1]
                .runs
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            [2, 1]
        );
    }

    #[test]
    fn gc_prefix_manifest_accepts_an_empty_reclaimed_prefix() {
        let mut dev = MemBlocks::new();
        let mut man = Manifest::new(64 << 10);
        man.insert(Arc::new(run(
            &mut dev,
            1,
            (1, 1),
            place(1, Gk::MIN, None),
            &[(b"a", b"old"), (b"z", b"live")],
            &[],
        )));
        man.install_flush(
            Arc::new(run(
                &mut dev,
                2,
                (2, 2),
                Place::default(),
                &[],
                &[(b"a", Some(b"m"))],
            )),
            2,
        );
        man.next_run_id = 3;
        let pick = man.pick_whole_shard_col().unwrap();
        let expected: &[(&[u8], &[u8])] = &[(b"z", b"live")];
        assert_contents(&man, &mut dev, expected);
        let suffix = run(
            &mut dev,
            1,
            (1, 1),
            place(1, Gk::new(1, b"m"), None),
            &[(b"z", b"live")],
            &[],
        );
        man.install_gc_prefix(&pick.inputs, Vec::new(), vec![suffix]);
        assert_contents(&man, &mut dev, expected);
        assert!(man.top.is_empty());
        assert!(man.locks.is_empty());
        assert_eq!(man.flushed_lsn, 2);
    }

    fn tomb_run(dev: &mut MemBlocks, id: u64, keys: &[&[u8]]) -> RunMeta {
        let mut b = RunBuilder::new();
        for key in keys {
            b.push(dev, 1, key, None).unwrap();
        }
        b.finish(dev, id, id, id).unwrap().0
    }

    #[test]
    fn gc_prefix_manifest_frontier_excludes_completed_prefixes_after_every_mount() {
        use crate::olsm::job;
        use std::collections::BTreeMap;

        let mut dev = MemBlocks::new();
        let mut man = Manifest::new(crate::olsm::CHUNK_TARGET as u64);
        let value = vec![7; 512];
        let keys: Vec<_> = (0..2048).map(|i| format!("k{i:06}").into_bytes()).collect();
        let mut b = RunBuilder::new();
        for key in &keys {
            b.push(&mut dev, 1, key, Some(&value)).unwrap();
        }
        let mut base = b.finish(&mut dev, 1, 1, 1).unwrap().0;
        base.place = place(1, Gk::MIN, None);
        man.insert(Arc::new(base));
        let dead: Vec<_> = keys.iter().step_by(2).map(Vec::as_slice).collect();
        man.install_flush(Arc::new(tomb_run(&mut dev, 2, &dead)), 2);
        man.next_run_id = 3;
        let expected: Vec<_> = keys
            .iter()
            .skip(1)
            .step_by(2)
            .map(|k| (k.clone(), value.clone()))
            .collect();
        let mut completed = BTreeMap::new();
        let mut frontier = None;
        let mut prefixes = 0;
        for _ in 0..128 {
            if man.top.is_empty() {
                assert!(prefixes > 2);
                return;
            }
            let pick = man
                .pick_shard_col(GC_AMP)
                .expect("dirty suffix still needs GC");
            assert!(
                pick.inputs.iter().all(|r| !completed.contains_key(&r.id)),
                "GC selected a completed clean prefix"
            );
            if let Some(previous) = &frontier {
                assert!(pick.regions[0].lo >= *previous);
            }
            let inputs = pick.inputs.clone();
            let out = job::merge(pick, &mut dev).unwrap();
            if let Some(end) = &out.prefix_end {
                assert!(frontier.as_ref().is_none_or(|p| p < end));
                frontier = Some(end.clone());
                prefixes += 1;
            }
            for r in &out.runs {
                completed.insert(r.id, (r.meta_blk, r.meta_crc));
            }
            let frees = out.freed;
            man.install_gc_prefix(&inputs, out.runs, out.residuals);
            for (blk, nblk) in frees {
                dev.free(blk, nblk);
            }
            assert_eq!(contents(&man, &mut dev), expected);
            man = remount(&man, &mut dev);
            assert_eq!(contents(&man, &mut dev), expected);
            for r in man.runs() {
                if let Some(ptr) = completed.get(&r.id) {
                    assert_eq!(
                        (r.meta_blk, r.meta_crc),
                        *ptr,
                        "an installed prefix changed"
                    );
                }
            }
        }
        panic!("WARNING TIMEOUT GC frontier progress exceeded 128 prefixes");
    }

    #[test]
    fn gc_prefix_manifest_frontier_includes_range_start_before_first_entry() {
        use crate::olsm::job;

        for with_point in [false, true] {
            let mut dev = MemBlocks::new();
            let mut man = Manifest::new(64 << 10);
            let old = vec![1; 512];
            let new = vec![2; 512];
            man.insert(Arc::new(run(
                &mut dev,
                1,
                (1, 1),
                place(1, Gk::MIN, Some(Gk::new(1, b"m"))),
                &[(b"a", &old)],
                &[],
            )));
            man.insert(Arc::new(run(
                &mut dev,
                2,
                (2, 2),
                place(1, Gk::new(1, b"m"), None),
                &[(b"z", &old)],
                &[],
            )));
            let entries: &[(&[u8], &[u8])] = if with_point { &[(b"z", &new)] } else { &[] };
            man.install_flush(
                Arc::new(run(
                    &mut dev,
                    3,
                    (3, 3),
                    Place::default(),
                    entries,
                    &[(b"a", Some(b"b"))],
                )),
                3,
            );
            man.next_run_id = 4;
            let pick = man.pick_shard_col(GC_AMP).unwrap();
            assert!(
                pick.inputs.iter().any(|r| r.id == 1),
                "range-only coverage must include the old prefix"
            );
            let inputs = pick.inputs.clone();
            let newer = man.alloc_run_id();
            man.install_flush(
                Arc::new(run(
                    &mut dev,
                    newer,
                    (4, 4),
                    Place::default(),
                    &[(b"0", b"concurrent")],
                    &[],
                )),
                4,
            );
            let out = job::merge(pick, &mut dev).unwrap();
            man.install_gc_prefix(&inputs, out.runs, out.residuals);
            assert_contents(
                &man,
                &mut dev,
                &[
                    (b"0", b"concurrent"),
                    (b"z", if with_point { &new } else { &old }),
                ],
            );
            assert_eq!(man.top[0].id, newer);
        }
    }

    #[test]
    fn gc_prefix_manifest_frontier_beyond_all_deeper_partitions_still_targets_tier_one() {
        use crate::olsm::job;

        let mut dev = MemBlocks::new();
        let mut man = Manifest::new(64 << 10);
        let value = vec![1; 512];
        man.insert(Arc::new(run(
            &mut dev,
            1,
            (1, 1),
            place(1, Gk::MIN, Some(Gk::new(1, b"m"))),
            &[(b"a", &value)],
            &[],
        )));
        let mut b = RunBuilder::new();
        b.push(&mut dev, 1, b"y", Some(&value)).unwrap();
        b.push(&mut dev, 1, b"z", None).unwrap();
        man.install_flush(Arc::new(b.finish(&mut dev, 2, 2, 2).unwrap().0), 2);
        man.next_run_id = 3;
        let pick = man.pick_shard_col(GC_AMP).unwrap();
        assert_eq!(pick.inputs.len(), 1);
        assert!(pick.bottom && pick.dst_tier == 1);
        assert_eq!(pick.regions[0].lo, Gk::new(1, b"y"));
        let inputs = pick.inputs.clone();
        let out = job::merge(pick, &mut dev).unwrap();
        assert!(out.runs.iter().all(|r| r.place.tier == 1));
        man.install_gc_prefix(&inputs, out.runs, out.residuals);
        assert_contents(&man, &mut dev, &[(b"a", &value), (b"y", &value)]);
    }

    #[test]
    fn gc_prefix_manifest_frontier_expands_downward_without_hiding_newer_upper_prefix() {
        use crate::olsm::job;

        let mut dev = MemBlocks::new();
        let mut man = Manifest::new(64 << 10);
        let old = vec![1; 512];
        let new = vec![2; 512];
        man.insert(Arc::new(run(
            &mut dev,
            1,
            (1, 1),
            place(2, Gk::new(1, b"a"), None),
            &[(b"b", &old), (b"h", &old), (b"k", &old), (b"y", &old)],
            &[],
        )));
        man.insert(Arc::new(run(
            &mut dev,
            2,
            (2, 2),
            place(1, Gk::MIN, Some(Gk::new(1, b"g"))),
            &[(b"b", &new)],
            &[],
        )));
        man.insert(Arc::new(run(
            &mut dev,
            3,
            (3, 3),
            place(1, Gk::new(1, b"g"), None),
            &[(b"h", &new), (b"k", &new), (b"y", &new)],
            &[],
        )));
        man.install_flush(Arc::new(tomb_run(&mut dev, 4, &[b"k", b"y"])), 4);
        man.next_run_id = 5;
        let pick = man.pick_shard_col(GC_AMP).unwrap();
        assert_eq!(pick.regions[0].lo, Gk::new(1, b"a"));
        assert!(
            !pick.inputs.iter().any(|r| r.id == 2),
            "a newer upper prefix remains outside the column"
        );
        let inputs = pick.inputs.clone();
        let out = job::merge(pick, &mut dev).unwrap();
        man.install_gc_prefix(&inputs, out.runs, out.residuals);
        assert_contents(&man, &mut dev, &[(b"b", &new), (b"h", &new)]);
    }

    #[test]
    fn gc_prefix_manifest_frontier_keeps_whole_fallback_for_garbage_before_tier_zero() {
        use crate::olsm::job;

        let mut dev = MemBlocks::new();
        let mut man = Manifest::new(64 << 10);
        let old = vec![1; 512];
        let new = vec![2; 512];
        man.insert(Arc::new(run(
            &mut dev,
            1,
            (1, 1),
            place(1, Gk::MIN, Some(Gk::new(1, b"m"))),
            &[(b"a", &old)],
            &[],
        )));
        let mut tomb = tomb_run(&mut dev, 2, &[b"a"]);
        tomb.place = place(1, Gk::MIN, Some(Gk::new(1, b"m")));
        man.insert(Arc::new(tomb));
        man.insert(Arc::new(run(
            &mut dev,
            3,
            (3, 3),
            place(1, Gk::new(1, b"m"), None),
            &[(b"z", &old)],
            &[],
        )));
        let mut tier_only = remount(&man, &mut dev);
        man.install_flush(
            Arc::new(run(
                &mut dev,
                4,
                (4, 4),
                Place::default(),
                &[(b"z", &new)],
                &[],
            )),
            4,
        );
        man.next_run_id = 5;
        let pick = man.pick_shard_col(GC_AMP).unwrap();
        assert_eq!(pick.regions[0].lo, Gk::MIN);
        assert!(
            pick.inputs.iter().any(|r| r.id == 2),
            "trimmed clean suffix must not hide earlier garbage"
        );
        let inputs = pick.inputs.clone();
        let out = job::merge(pick, &mut dev).unwrap();
        man.install_gc_prefix(&inputs, out.runs, out.residuals);
        assert_contents(&man, &mut dev, &[(b"z", &new)]);
        // No tier-0 data: retain the original coverage for garbage in the tiered runs themselves.
        assert!(tier_only.top.is_empty());
        let pick = tier_only.pick_shard_col(GC_AMP).unwrap();
        assert_eq!(pick.regions[0].lo, Gk::MIN);
        assert!(pick.inputs.iter().any(|r| r.id == 2));
        let inputs = pick.inputs.clone();
        let out = job::merge(pick, &mut dev).unwrap();
        tier_only.install_gc_prefix(&inputs, out.runs, out.residuals);
        assert_contents(&tier_only, &mut dev, &[(b"z", &old)]);
    }

    /// A partition holding more runs than one manifest txn can replace (runs pile up while merges lag foreground
    /// writes, adr 0662) merges at most [`Manifest::set_max_inputs`] of its oldest runs and moves them down; the
    /// newer runs stay in the partition, its sums stay exact and a remount sees the same keys.
    #[test]
    fn oversized_partition_merges_its_oldest_runs_within_the_manifest_limit() {
        let mut dev = MemBlocks::new();
        let mut man = Manifest::new(64 << 10);
        let values: Vec<Vec<u8>> = (1..=12u8).map(|i| vec![b'v', i]).collect();
        let uniques: Vec<Vec<u8>> = (1..=12u8).map(|i| vec![b'u', i]).collect();
        for i in 1..=12u64 {
            let (v, u) = (&values[i as usize - 1], &uniques[i as usize - 1]);
            man.insert(Arc::new(run(
                &mut dev,
                i,
                (i, i),
                place(1, Gk::MIN, None),
                &[(&b"k"[..], &v[..]), (&u[..], &b"U"[..])],
                &[],
            )));
        }
        man.next_run_id = 13;
        let mut expected: Vec<(&[u8], &[u8])> = vec![(&b"k"[..], &values[11][..])];
        expected.extend(uniques.iter().map(|u| (&u[..], &b"U"[..])));
        assert_contents(&man, &mut dev, &expected);
        // unlimited: the whole bottom partition, in place
        let whole = man.clone().pick_sized().unwrap();
        assert_eq!(whole.inputs.len(), 12);
        assert!(whole.stay);
        man.set_max_inputs(5);
        let pick = man.pick_sized().unwrap();
        let ids: Vec<u64> = pick.inputs.iter().map(|r| r.id).collect();
        assert_eq!(ids, [5, 4, 3, 2, 1], "the oldest runs, newest first");
        assert!(
            !pick.stay,
            "older data may not stay beside newer runs with a newer id"
        );
        assert_eq!(pick.dst_tier, 2);
        let inputs = pick.inputs.clone();
        let out = crate::olsm::job::merge(pick, &mut dev).unwrap();
        man.install_gc_prefix(&inputs, out.runs, out.residuals);
        let left: Vec<u64> = man.tiers[0][0].runs.iter().map(|r| r.id).collect();
        assert_eq!(left, [12, 11, 10, 9, 8, 7, 6]);
        assert_eq!(man.tiers.len(), 2);
        assert_contents(&man, &mut dev, &expected);
        assert!(
            man.pick_sized().is_none(),
            "seven runs left: below FAN, no longer due"
        );
    }

    /// A garbage column of more inputs than [`Manifest::set_max_inputs`] is not picked (it is merged whole or not at
    /// all) and leaves no lock behind.
    #[test]
    fn a_column_beyond_the_manifest_limit_is_not_picked() {
        let mut dev = MemBlocks::new();
        let mut man = Manifest::new(64 << 10);
        man.insert(Arc::new(run(
            &mut dev,
            1,
            (1, 1),
            place(1, Gk::MIN, None),
            &[(b"a", b"A"), (b"b", b"B")],
            &[],
        )));
        for i in 2..=3u64 {
            man.install_flush(Arc::new(tomb_run(&mut dev, i, &[b"a"])), i);
        }
        man.next_run_id = 4;
        man.set_max_inputs(2);
        assert!(man.pick_whole_shard_col().is_none());
        man.set_max_inputs(3);
        let pick = man.pick_whole_shard_col().expect("fits now, no lock left");
        assert_eq!(pick.inputs.len(), 3);
    }
}
