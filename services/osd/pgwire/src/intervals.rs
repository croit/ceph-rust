// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PastIntervals (compact rep) and the pure interval-building functions
//! (spec peering.md 2.5, 3.1, 3.3, 3.4).
//!
//! Everything here is sans-IO: map knowledge comes in through [`OsdMapView`] and plain
//! [`Mapping`] values, so the osd crate can plug in `crates/osdmap`.

use denc::types::{Eversion, PgShard, PgT, ShardId};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error, Result};
use std::collections::{BTreeMap, BTreeSet};

/// CRUSH_ITEM_NONE in up/acting vectors.
pub const NONE_OSD: i32 = 0x7fff_ffff;

/// One interval of the compact rep (only `maybe_went_rw` intervals are stored).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompactInterval {
    pub first: u32,
    pub last: u32,
    pub acting: BTreeSet<PgShard>,
}

impl Encode for CompactInterval {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            e.u32(self.first)?;
            e.u32(self.last)?;
            self.acting.encode(e)
        })
    }
}
impl<'a> Decode<'a> for CompactInterval {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| {
            Ok(CompactInterval {
                first: d.u32()?,
                last: d.u32()?,
                acting: BTreeSet::decode(d)?,
            })
        })
    }
}

/// Full interval record (pg_interval_t, v4 c2). NOT sent on the wire by main; input of the
/// compact builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgInterval {
    pub first: u32,
    pub last: u32,
    pub up: Vec<i32>,
    pub acting: Vec<i32>,
    pub maybe_went_rw: bool,
    pub primary: i32,
    pub up_primary: i32,
}
impl Default for PgInterval {
    fn default() -> Self {
        PgInterval {
            first: 0,
            last: 0,
            up: vec![],
            acting: vec![],
            maybe_went_rw: false,
            primary: -1,
            up_primary: -1,
        }
    }
}
impl Encode for PgInterval {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(4, 2, |e| {
            e.u32(self.first)?;
            e.u32(self.last)?;
            self.up.encode(e)?;
            self.acting.encode(e)?;
            e.bool(self.maybe_went_rw)?;
            e.i32(self.primary)?;
            e.i32(self.up_primary)
        })
    }
}
impl<'a> Decode<'a> for PgInterval {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(4, 2, |d, _| {
            Ok(PgInterval {
                first: d.u32()?,
                last: d.u32()?,
                up: Decode::decode(d)?,
                acting: Decode::decode(d)?,
                maybe_went_rw: d.bool()?,
                primary: d.i32()?,
                up_primary: d.i32()?,
            })
        })
    }
}

/// Shards of an OSD vector: replicated = NO_SHARD, EC = index; NONE osds skipped.
pub fn to_shards(osds: &[i32], ec: bool) -> impl Iterator<Item = PgShard> + '_ {
    osds.iter()
        .enumerate()
        .filter(|(_, o)| **o != NONE_OSD && **o >= 0)
        .map(move |(i, o)| PgShard {
            osd: *o,
            shard: if ec {
                ShardId(i as i8)
            } else {
                ShardId::NO_SHARD
            },
        })
}

/// PastIntervals: wire = ENCODE(1,1) | u8 type (0 null, 2 compact) | compact rep.
/// `first`/`last` bound the covered epochs ([first, last] inclusive).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PastIntervals {
    pub first: u32,
    pub last: u32,
    pub all_participants: BTreeSet<PgShard>,
    pub intervals: Vec<CompactInterval>,
}

/// Verdict of the required past-interval bounds check (peering.md 3.8).
///
/// [`Self::EmptyRequired`] is classic's log-only case; the others are implausible and stop the PG on croit-flashstore-osd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundsVerdict {
    /// Nothing required, or the stored range satisfies the required bounds.
    Ok,
    /// Required range empty but a non-empty set is stored (start history-derived): log only.
    EmptyRequired,
    /// Required range not empty but no interval is stored.
    EmptyPast,
    /// Stored intervals start after the required start.
    StartAfter,
    /// Stored intervals end where the current interval does not start.
    EndDiffers,
}

impl BoundsVerdict {
    /// Cases 2-4 of peering.md 3.8: the pair is implausible and the PG is stopped.
    pub fn stops_pg(self) -> bool {
        matches!(
            self,
            BoundsVerdict::EmptyPast | BoundsVerdict::StartAfter | BoundsVerdict::EndDiffers
        )
    }
    /// Operator text for a violation (None for [`BoundsVerdict::Ok`]).
    pub fn reason(self) -> Option<&'static str> {
        match self {
            BoundsVerdict::Ok => None,
            BoundsVerdict::EmptyRequired => {
                Some("required bounds are empty but past intervals is not")
            }
            BoundsVerdict::EmptyPast => Some("past intervals empty but required bounds are not"),
            BoundsVerdict::StartAfter => Some("past intervals start after the required start"),
            BoundsVerdict::EndDiffers => Some("past intervals end differs from the required end"),
        }
    }
}

/// Result of [`PastIntervals::check_required_bounds`]: the required and stored ranges plus the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundsCheck {
    /// Required `[start, end)`.
    pub required: (u32, u32),
    /// Stored `[first, last + 1)`, or `(0, 0)` for an empty set.
    pub past: (u32, u32),
    pub verdict: BoundsVerdict,
}

impl BoundsCheck {
    pub fn is_ok(&self) -> bool {
        self.verdict == BoundsVerdict::Ok
    }
}

impl PastIntervals {
    /// `first > last || (first == 0 && last == 0)`.
    pub fn is_empty(&self) -> bool {
        self.first > self.last || (self.first == 0 && self.last == 0)
    }
    /// Covered epochs `[start, end)`. Only sets that passed [`Self::check_wire`] or [`Self::add_interval`] exist,
    /// so `last < u32::MAX` and `end` never overflows.
    pub fn bounds(&self) -> (u32, u32) {
        (self.first, self.last + 1)
    }
    pub fn clear(&mut self) {
        *self = PastIntervals::default();
    }
    /// Wire acceptance (peering.md 2.5): the covered range ends before `u32::MAX` (its end `last + 1` is compared
    /// as an epoch), stored intervals have `first <= last`, come in non-decreasing `last` order and end within the
    /// covered range; [`Self::intervals_since`] walks them newest to oldest relying on that.
    pub fn check_wire(&self) -> std::result::Result<(), &'static str> {
        if self.last == u32::MAX {
            return Err("past intervals end is not representable");
        }
        let mut prev = 0u32;
        for i in &self.intervals {
            if i.first > i.last {
                return Err("past interval first > last");
            }
            if i.last < prev {
                return Err("past intervals out of order");
            }
            if self.is_empty() || i.last > self.last {
                return Err("past interval outside the covered range");
            }
            prev = i.last;
        }
        Ok(())
    }

    /// Compact dump for the diagnostics of peering.md 3.8: `([first,last] all_participants=[...] intervals=[...])`.
    pub fn dump(&self) -> String {
        fn shards(set: &BTreeSet<PgShard>) -> String {
            set.iter()
                .map(|p| {
                    if p.shard == ShardId::NO_SHARD {
                        p.osd.to_string()
                    } else {
                        format!("{}({})", p.osd, p.shard.0)
                    }
                })
                .collect::<Vec<_>>()
                .join(",")
        }
        let intervals = self
            .intervals
            .iter()
            .map(|i| format!("[{},{}] {}", i.first, i.last, shards(&i.acting)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "([{},{}] all_participants=[{}] intervals=[{}])",
            self.first,
            self.last,
            shards(&self.all_participants),
            intervals
        )
    }

    /// Classic's required-bounds invariant (peering.md 3.8, `check_past_interval_bounds`) for a (history, past
    /// intervals) pair, with `oldest_map` the OSD's `cluster_osdmap_trim_lower_bound`: a non-empty required range
    /// `[max(lec or epoch_pool_created, oldest_map), max(same_interval_since, epoch_pool_created))` must be covered (start
    /// at or before its start, end exactly at its end). The reported past range is `(0, 0)` for an empty set. A
    /// violation is described by [`BoundsVerdict`]; the caller decides between logging and stopping the PG.
    pub fn check_required_bounds(&self, h: &crate::PgHistory, oldest_map: u32) -> BoundsCheck {
        let lec = if h.last_epoch_clean != 0 {
            h.last_epoch_clean
        } else {
            h.epoch_pool_created
        };
        let required = (
            lec.max(oldest_map),
            h.same_interval_since.max(h.epoch_pool_created),
        );
        let past = if self.is_empty() {
            (0, 0)
        } else {
            self.bounds()
        };
        let (rs, re) = required;
        let verdict = if rs >= re {
            // a non-empty set is harmless here unless the start is history-derived (classic logs case 1 only then)
            if !self.is_empty() && rs > oldest_map {
                BoundsVerdict::EmptyRequired
            } else {
                BoundsVerdict::Ok
            }
        } else if self.is_empty() {
            BoundsVerdict::EmptyPast
        } else if past.0 > rs {
            BoundsVerdict::StartAfter
        } else if past.1 != re {
            BoundsVerdict::EndDiffers
        } else {
            BoundsVerdict::Ok
        };
        BoundsCheck {
            required,
            past,
            verdict,
        }
    }

    /// Stored (maybe_went_rw) intervals from newest to oldest while `interval.last >= les`.
    pub fn intervals_since(&self, les: u32) -> impl Iterator<Item = &CompactInterval> {
        self.intervals
            .iter()
            .rev()
            .take_while(move |i| i.last >= les)
    }

    /// Record a closed interval (spec 3.3). `ec` selects shard numbering. Returns false (and
    /// changes nothing) unless the interval extends the covered range: `first <= last`, `last < u32::MAX`
    /// (see [`Self::bounds`]) and `last` grows.
    pub fn add_interval(&mut self, ec: bool, iv: &PgInterval) -> bool {
        if iv.first > iv.last || iv.last == u32::MAX || (!self.is_empty() && iv.last <= self.last) {
            return false;
        }
        if self.is_empty() {
            self.first = iv.first;
        }
        self.last = iv.last;
        let acting: BTreeSet<PgShard> = to_shards(&iv.acting, ec).collect();
        self.all_participants.extend(acting.iter().copied());
        if iv.maybe_went_rw {
            // older intervals whose acting set is a superset of the new one are redundant
            self.intervals
                .retain(|old| !old.acting.is_superset(&acting));
            self.intervals.push(CompactInterval {
                first: iv.first,
                last: iv.last,
                acting,
            });
        }
        true
    }
}

impl Encode for PastIntervals {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            e.u8(2)?;
            e.versioned(1, 1, |e| {
                e.u32(self.first)?;
                e.u32(self.last)?;
                self.all_participants.encode(e)?;
                self.intervals.encode(e)
            })
        })
    }
}
impl<'a> Decode<'a> for PastIntervals {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(1, 1, |d, _| match d.u8()? {
            0 => Ok(PastIntervals::default()),
            2 => d.versioned_min(1, 1, |d, _| {
                let p = PastIntervals {
                    first: d.u32()?,
                    last: d.u32()?,
                    all_participants: BTreeSet::decode(d)?,
                    intervals: Vec::decode(d)?,
                };
                p.check_wire().map_err(Error::BadValue)?;
                Ok(p)
            }),
            _ => Err(Error::BadValue(
                "PastIntervals type (1 = removed pi_simple_rep)",
            )),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Map queries
// ---------------------------------------------------------------------------------------------

/// Up/acting mapping of one PG in one map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Mapping {
    pub up: Vec<i32>,
    pub up_primary: i32,
    pub acting: Vec<i32>,
    pub acting_primary: i32,
}

/// Pool parameters relevant to interval detection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PoolParams {
    pub size: u32,
    pub min_size: u32,
    pub pg_num: u32,
    /// Equals `pg_num` unless a merge is pending.
    pub pg_num_pending: u32,
    pub is_erasure: bool,
    /// EC: data chunks needed for an interval to have been writable.
    pub ec_k: u32,
    /// CRUSH rule of the pool: its take roots define the stretch barrier buckets (stretch.md 2.1).
    pub crush_rule: i32,
    /// Stretch pool fields (stretch.md 1.1); `peering_crush_bucket_count != 0` = stretch pool.
    pub peering_crush_bucket_count: u32,
    pub peering_crush_bucket_target: u32,
    pub peering_crush_bucket_barrier: u32,
    pub peering_crush_mandatory_member: i32,
    pub ec_optimizations: bool,
    /// Erasure pools: what the shard role needs of the pool + profile (adr 0039); `None` = replicated pool.
    pub ec: Option<std::sync::Arc<EcPoolInfo>>,
    /// Facts of the last merge of this pool (`last_pg_merge_meta`); `source_seed == 0` = never merged.
    pub merge_meta: MergeMeta,
    /// Pool flag FULL (cluster/pool full): drives `history.last_epoch_marked_full`.
    pub full: bool,
    /// Cache tiering in any form (`tier_of`, `tiers`, `read_tier`, `write_tier`, `cache_mode`): out of scope (adr 0168),
    /// the pool is fully passive on this OSD like an unsupported EC pool.
    pub tiered: bool,
    /// Pool option `read_lease_interval` (pool_opts key 19) in ns; `None` = the OSD default
    /// (`osd_heartbeat_grace x osd_pool_default_read_lease_ratio`, peering.md 8.2).
    pub read_lease_ns: Option<u64>,
    /// Pool option `scrub_min_interval` (pool_opts key 0, seconds) when > 0, in ns: overrides
    /// `osd_scrub_min_interval` (spec scrub.md 12.1.6).
    pub scrub_min_interval_ns: Option<u64>,
    /// Pool option `deep_scrub_interval` (pool_opts key 2, seconds) when > 0, in ns: overrides
    /// `osd_deep_scrub_interval`.
    pub deep_scrub_interval_ns: Option<u64>,
    /// Pool option `scrub_priority` (pool_opts key 5) when > 0: overrides `osd_scrub_priority` for this PG's scrub ops.
    pub scrub_priority: Option<i32>,
    /// Pool option `recovery_priority` (pool_opts key 3, clamped to -10..10): shifts this PG's recovery/backfill
    /// reservation priorities inside their band (spec replication.md 11.1).
    pub recovery_priority: i32,
    /// Positive pool option 4 overrides WPQ recovery message priority; ignored by mclock.
    pub recovery_op_priority: Option<u16>,
}

impl PoolParams {
    /// Stretch pool (stretch.md 1.1): peering checks site diversity ([`can_peer`]).
    pub fn is_stretch(&self) -> bool {
        self.peering_crush_bucket_count != 0
    }
}

/// `can_peer` (stretch.md 3.1): true for a non-stretch pool; else the barrier buckets of the members of `set` (a NONE
/// hole or an OSD outside the rule's take roots counts as bucket 0) number at least `peering_crush_bucket_count` and
/// include `peering_crush_mandatory_member` unless that is NONE. `map` and `pool` are of the same epoch.
pub fn can_peer(map: &dyn OsdMapView, pool: &PoolParams, set: &[i32]) -> bool {
    if !pool.is_stretch() {
        return true;
    }
    let mut b: Vec<i32> = set
        .iter()
        .map(|o| map.barrier_bucket(*o, pool.peering_crush_bucket_barrier, pool.crush_rule))
        .collect();
    b.sort_unstable();
    b.dedup();
    let m = pool.peering_crush_mandatory_member;
    b.len() as u32 >= pool.peering_crush_bucket_count && (m == NONE_OSD || b.contains(&m))
}

/// Erasure-coded pool facts for the shard role, derived from the pool and its profile by the support gate (crate `ec`).
/// `supported == false`: the pool is fully passive on this OSD and `reason` names the missing feature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcPoolInfo {
    pub k: u32,
    pub m: u32,
    pub stripe_width: u32,
    /// `stripe_width / k` (valid when supported).
    pub chunk_size: u32,
    /// Pool flag `allow_ec_overwrites` (mode L1); false = append-only L0.
    pub overwrites: bool,
    pub supported: bool,
    pub reason: String,
    /// Plugin and technique names of the profile (primary role: selects the code).
    pub plugin: String,
    pub technique: String,
    /// The pool profile map (primary role: builds the code from it).
    pub profile: std::collections::BTreeMap<String, String>,
    /// raw chunk index -> shard (len k+m).
    pub chunk_mapping: Vec<u32>,
    /// Mode O (`allow_ec_optimizations`, adr 0067): optimized backend for this pool.
    pub optimized: bool,
    /// Mode O: shard ids of the nonprimary data shards (raw 1..k-1), ascending; empty otherwise.
    pub nonprimary: Vec<u32>,
    /// Pool flag FLAG_OMAP (omap + cls on this EC pool; mode O only).
    pub omap: bool,
    /// Sub-chunks per chunk (clay S, else 1): shard sub-chunk reads (ec-clay.md 7.1).
    pub sub_chunks: u32,
    /// The primary role may run (false: clay profile served as shard only, ec-clay.md 0.6).
    pub primary_ok: bool,
}

impl Default for EcPoolInfo {
    fn default() -> Self {
        EcPoolInfo {
            k: 0,
            m: 0,
            stripe_width: 0,
            chunk_size: 0,
            overwrites: false,
            supported: false,
            reason: String::new(),
            plugin: String::new(),
            technique: String::new(),
            profile: Default::default(),
            chunk_mapping: Vec::new(),
            optimized: false,
            nonprimary: Vec::new(),
            omap: false,
            sub_chunks: 1,
            primary_ok: true,
        }
    }
}

impl EcPoolInfo {
    /// Mode O nonprimary shard: sparse log, only `_` attr, never leads, ignores own pwlc maintenance.
    pub fn is_nonprimary(&self, shard: u32) -> bool {
        self.optimized && self.nonprimary.binary_search(&shard).is_ok()
    }
}

/// `pg_merge_meta_t` as the PG machinery needs it (split-merge.md 2, 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MergeMeta {
    /// Seed of the merged source PG; 0 = unset (a source always has seed >= 1).
    pub source_seed: u32,
    pub ready_epoch: u32,
    pub last_epoch_started: u32,
    pub last_epoch_clean: u32,
    pub source_version: Eversion,
    pub target_version: Eversion,
}

/// OSDMap flags that start a new interval when they change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MapFlags {
    pub sortbitwise: bool,
    pub recovery_deletes: bool,
}

/// Map queries the interval logic needs. The osd crate implements this over `crates/osdmap`.
pub trait OsdMapView {
    fn epoch(&self) -> u32;
    /// `None` = pool does not exist in this map.
    fn pool(&self, pool: u64) -> Option<PoolParams>;
    fn flags(&self) -> MapFlags;
    fn exists(&self, osd: i32) -> bool;
    fn is_up(&self, osd: i32) -> bool;
    fn up_from(&self, osd: i32) -> u32;
    fn up_thru(&self, osd: i32) -> u32;
    fn lost_at(&self, osd: i32) -> u32;
    /// The OSD said it is dead since its last boot (`osd_xinfo.dead_epoch > up_from`, MOSDMarkMeDead): it serves
    /// nothing under an old read lease any more (peering.md 8.2 prior_readable_down_osds).
    fn is_dead(&self, osd: i32) -> bool;
    /// Stretch barrier bucket of `osd` (also NONE): CRUSH `parent_of_type(osd, barrier, rule)` of this epoch's map
    /// (stretch.md 2.1); 0 = not found.
    fn barrier_bucket(&self, osd: i32, barrier: u32, rule: i32) -> i32;
}

pub use crate::pgmath::{is_split, pg_num_mask, stable_mod};

/// Merge relation of `seed` when pg_num shrinks `from -> to` (`to < from`): source = seed in
/// `[to, from)`; target = lower seed that absorbs a source. Symmetric helper used with both
/// directions of a pending change (`lo`, `hi`).
fn merge_related(seed: u32, lo: u32, hi: u32) -> bool {
    if lo >= hi {
        return false;
    }
    if seed >= lo && seed < hi {
        return true;
    }
    if seed >= lo {
        return false;
    }
    let mask = pg_num_mask(lo);
    (lo..hi).any(|c| stable_mod(c, lo, mask) == seed)
}

/// Interval-change test for one PG between two consecutive maps (spec 3.1). Pool presence is
/// handled by [`is_new_interval_maps`].
pub fn is_new_interval(
    pgid: PgT,
    old: &Mapping,
    new: &Mapping,
    old_pool: &PoolParams,
    new_pool: &PoolParams,
    old_flags: MapFlags,
    new_flags: MapFlags,
) -> bool {
    if old.acting_primary != new.acting_primary
        || old.acting != new.acting
        || old.up_primary != new.up_primary
        || old.up != new.up
        || old_pool.size != new_pool.size
        || old_pool.min_size != new_pool.min_size
        || old_flags.sortbitwise != new_flags.sortbitwise
        || old_flags.recovery_deletes != new_flags.recovery_deletes
        || old_pool.peering_crush_bucket_count != new_pool.peering_crush_bucket_count
        || old_pool.peering_crush_bucket_target != new_pool.peering_crush_bucket_target
        || old_pool.peering_crush_bucket_barrier != new_pool.peering_crush_bucket_barrier
        || old_pool.peering_crush_mandatory_member != new_pool.peering_crush_mandatory_member
        || old_pool.ec_optimizations != new_pool.ec_optimizations
    {
        return true;
    }
    let seed = pgid.seed;
    if is_split(seed, old_pool.pg_num, new_pool.pg_num) {
        return true;
    }
    // merge relations: pending change in either direction, or a pg_num decrease
    let (pa, pb) = (old_pool.pg_num_pending, new_pool.pg_num_pending);
    if merge_related(seed, pa.min(pb), pa.max(pb)) {
        return true;
    }
    merge_related(seed, new_pool.pg_num, old_pool.pg_num)
}

/// [`is_new_interval`] over two maps: pool absent in `lastmap` -> never; absent in `newmap` -> yes.
pub fn is_new_interval_maps(
    pgid: PgT,
    lastmap: &dyn OsdMapView,
    newmap: &dyn OsdMapView,
    old: &Mapping,
    new: &Mapping,
) -> bool {
    let Some(op) = lastmap.pool(pgid.pool) else {
        return false;
    };
    let Some(np) = newmap.pool(pgid.pool) else {
        return true;
    };
    is_new_interval(pgid, old, new, &op, &np, lastmap.flags(), newmap.flags())
}

/// Inputs of [`check_new_interval`].
#[derive(Clone, Copy)]
pub struct IntervalInput<'a> {
    pub pgid: PgT,
    /// `history.same_interval_since` of the interval being closed.
    pub same_interval_since: u32,
    /// `history.last_epoch_clean`.
    pub last_epoch_clean: u32,
    pub old: &'a Mapping,
    pub new: &'a Mapping,
    pub lastmap: &'a dyn OsdMapView,
    pub newmap: &'a dyn OsdMapView,
}

impl std::fmt::Debug for IntervalInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntervalInput")
            .field("pgid", &self.pgid)
            .finish_non_exhaustive()
    }
}

/// Close the old interval into `past` if the maps differ (spec 3.3). Returns the closed
/// [`PgInterval`] when a new interval started (and it was recorded), else `None`.
pub fn check_new_interval(past: &mut PastIntervals, inp: &IntervalInput<'_>) -> Option<PgInterval> {
    if !is_new_interval_maps(inp.pgid, inp.lastmap, inp.newmap, inp.old, inp.new) {
        return None;
    }
    let old_pool = inp.lastmap.pool(inp.pgid.pool)?;
    let first = inp.same_interval_since;
    let last = inp.newmap.epoch().checked_sub(1)?;
    if first > last {
        return None;
    }
    let live = inp
        .old
        .acting
        .iter()
        .filter(|o| **o != NONE_OSD && **o >= 0)
        .count() as u32;
    let primary = inp.old.acting_primary;
    let could_go_active = if old_pool.is_erasure {
        live >= old_pool.ec_k
    } else {
        live > 0
    };
    // stretch.md 6: a stretch pool's interval went rw only if its acting vector passed can_peer under the old pool
    // and the old map's buckets
    let maybe_went_rw = if live == 0
        || primary < 0
        || live < old_pool.min_size
        || !could_go_active
        || !can_peer(inp.lastmap, &old_pool, &inp.old.acting)
    {
        false
    } else if inp.lastmap.up_thru(primary) >= first && inp.lastmap.up_from(primary) <= first {
        true
    } else {
        inp.last_epoch_clean >= first && inp.last_epoch_clean <= last
    };
    let iv = PgInterval {
        first,
        last,
        up: inp.old.up.clone(),
        acting: inp.old.acting.clone(),
        maybe_went_rw,
        primary,
        up_primary: inp.old.up_primary,
    };
    if past.add_interval(old_pool.is_erasure, &iv) {
        Some(iv)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------------------------
// Prior set
// ---------------------------------------------------------------------------------------------

/// Who must be probed during GetInfo (spec 3.4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PriorSet {
    pub probe: BTreeSet<PgShard>,
    /// Existing participants that are not up.
    pub down: BTreeSet<i32>,
    /// osd -> lost_at of the DOWN members blocking peering (only if `pg_down`).
    pub blocked_by: BTreeMap<i32, u32>,
    pub pg_down: bool,
    /// lost_at of every OSD in `down` at build time (for `affected_by_map`).
    down_lost_at: BTreeMap<i32, u32>,
}

impl PriorSet {
    /// `min_present`: replicated 1; EC: k. `up`/`acting`: the PG's current mapping.
    pub fn build(
        past: &PastIntervals,
        ec: bool,
        min_present: usize,
        les: u32,
        up: &[i32],
        acting: &[i32],
        map: &dyn OsdMapView,
    ) -> PriorSet {
        let mut ps = PriorSet::default();
        ps.probe.extend(to_shards(up, ec));
        ps.probe.extend(to_shards(acting, ec));
        for p in &past.all_participants {
            if map.is_up(p.osd) {
                ps.probe.insert(*p);
            } else if map.exists(p.osd) {
                ps.down.insert(p.osd);
                ps.down_lost_at.insert(p.osd, map.lost_at(p.osd));
            }
        }
        for iv in past.intervals_since(les) {
            let mut present = 0usize;
            let mut blockers = BTreeMap::new();
            for m in &iv.acting {
                let o = m.osd;
                if map.is_up(o) {
                    present += 1;
                } else if !map.exists(o) {
                    // DNE: ignored
                } else if map.lost_at(o) > iv.first {
                    present += 1; // declared lost by the admin
                } else {
                    blockers.insert(o, map.lost_at(o));
                }
            }
            if present < min_present && !blockers.is_empty() {
                ps.pg_down = true;
                ps.blocked_by.extend(blockers);
            }
        }
        ps
    }

    /// True if `newmap` invalidates this prior set (restart peering).
    pub fn affected_by_map(&self, newmap: &dyn OsdMapView) -> bool {
        for p in &self.probe {
            if !newmap.is_up(p.osd) && !self.down.contains(&p.osd) {
                return true;
            }
        }
        for (osd, lost) in &self.blocked_by {
            if !newmap.exists(*osd) || newmap.lost_at(*osd) != *lost {
                return true;
            }
        }
        for osd in &self.down {
            if newmap.is_up(*osd)
                || !newmap.exists(*osd)
                || self
                    .down_lost_at
                    .get(osd)
                    .is_some_and(|l| newmap.lost_at(*osd) != *l)
            {
                return true;
            }
        }
        false
    }
}
