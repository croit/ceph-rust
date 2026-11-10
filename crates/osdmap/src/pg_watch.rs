// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Client-side PG interval watch (spec rados-client/22-mutation-retry.md, "interval resend rule"): follows the PGs that
//! have a sent client request through EVERY applied map epoch and keeps the epoch at which each one last started a new
//! interval. A request routed at epoch E must be resent when its PG's interval start is > E (the OSD drops such an op
//! without a reply). Only followed PGs are mapped, once per applied epoch; no map history is kept.

use crate::consts::map_flags;
use crate::hash::stable_mask;
use crate::map::OsdMap;
use crate::mapping::PgMapping;
use crate::pool::{PeeringCrush, flags};
use denc::types::PgT;
use std::collections::HashMap;

/// PG-keyed map with a fast non-cryptographic hasher (foldhash, fixed seed). Keys are (pool, seed) pairs taken from our own
/// map and request routing, never attacker-chosen at a scale that matters (a PG map holds at most pg_num entries per
/// pool), so SipHash's HashDoS resistance buys nothing on the per-op path.
pub type PgHashMap<V> = HashMap<PgT, V, foldhash::fast::FixedState>;

/// Map flags whose change starts a new interval of every PG.
const INTERVAL_FLAGS: u32 = map_flags::SORTBITWISE | map_flags::RECOVERY_DELETES;

/// What decides a PG's interval at one epoch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Snapshot {
    present: bool,
    mapping: PgMapping,
    primary: Option<crate::PrimaryDestination>,
    size: u8,
    min_size: u8,
    pg_num: u32,
    pg_num_pending: u32,
    peering_crush: PeeringCrush,
    ec_optimizations: bool,
    flags: u32,
}

impl Snapshot {
    fn take(&mut self, map: &OsdMap, pg: PgT) {
        self.flags = map.flags & INTERVAL_FLAGS;
        match map.pool(pg.pool as i64) {
            Some(pool) => {
                self.present = true;
                self.size = pool.size;
                self.min_size = pool.min_size;
                self.pg_num = pool.pg_num;
                self.pg_num_pending = pool.pg_num_pending;
                self.peering_crush = pool.peering_crush;
                self.ec_optimizations = pool.has_flag(flags::EC_OPTIMIZATIONS);
                self.mapping = map.pg_to_up_acting(pg);
                self.primary = map.primary_destination(pg, &self.mapping);
            }
            None => *self = Self::default(),
        }
    }
    /// New interval of `seed` from `self` (epoch e-1) to `next` (epoch e)?
    fn new_interval(&self, next: &Self, seed: u32) -> bool {
        self.present != next.present
            || self.mapping != next.mapping
            || self.primary != next.primary
            || self.size != next.size
            || self.min_size != next.min_size
            || self.flags != next.flags
            || self.peering_crush != next.peering_crush
            || self.ec_optimizations != next.ec_optimizations
            || pg_count_change_affects(seed, self.pg_num, next.pg_num)
            || pg_count_change_affects(seed, self.pg_num_pending, next.pg_num_pending)
    }
}

/// A pg count change between `a` and `b` (either direction) touches PG `seed`: it is merged away (seed >= the smaller
/// count) or one of the seeds in [smaller, larger) folds onto it (its split child / merge source).
///
/// `stable_mod(c, lo, mask)` is periodic in `c` with period `mask + 1` and its image on one period is `[0, lo)`:
/// residues `r < lo` map to `r`, residues `r >= lo` map to `r - (mask + 1) / 2`. The answer therefore follows from
/// the residues `[lo, hi)` covers, without scanning them.
pub fn pg_count_change_affects(seed: u32, a: u32, b: u32) -> bool {
    let (lo, hi) = (a.min(b), a.max(b));
    if lo == hi {
        return false;
    }
    if lo == 0 || seed >= lo {
        return true;
    }
    let period = u64::from(stable_mask(lo)) + 1;
    let span = u64::from(hi - lo);
    if span >= period {
        return true; // every residue occurs, i.e. every seed below `lo`
    }
    let half = period / 2;
    let (lo, seed) = (u64::from(lo), u64::from(seed));
    let start = lo % period;
    let end = start + span; // < 2 * period
    // residues [start, min(end, period)) and, if the range wraps, [0, end - period)
    let (mid, wrapped) = (end.min(period), end.max(period) - period);
    let hit = |u: u64, v: u64| -> bool {
        if u >= v {
            return false;
        }
        // r in [u, min(v, lo)) keeps `r`; r in [max(u, lo), v) becomes `r - half`
        (seed >= u && seed < v.min(lo)) || (seed + half >= u.max(lo) && seed + half < v)
    };
    hit(start, mid) || hit(0, wrapped)
}

#[derive(Debug, Default)]
struct Entry {
    pg: PgT,
    refs: u32,
    /// `snap` holds the PG at the watch's current epoch; false = not taken yet (taken from the previous map at the next epoch).
    based: bool,
    snap: Snapshot,
    scratch: Snapshot,
    /// Epoch at which the PG last started a new interval as seen by the watch (0 = none since followed).
    since: u32,
    since_generation: u64,
}

/// Followed PGs, keyed by PG; slots are reused (no allocation in steady state).
#[derive(Debug, Default)]
pub struct PgWatch {
    index: PgHashMap<usize>,
    entries: Vec<Entry>,
    free: Vec<usize>,
    /// Epoch of the last applied map (0 = none yet).
    epoch: u32,
    generation: u64,
}

impl PgWatch {
    /// Epoch of the last map seen by [`Self::observe`].
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    /// Number of followed PGs.
    pub fn len(&self) -> usize {
        self.index.len()
    }
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
    /// Follow `pg` for a request routed at map `epoch`. No mapping work here: the baseline is the map at the watch's
    /// current epoch, taken when the next epoch is applied. A request routed before the watch's epoch has an unknown
    /// history: its PG counts as a new interval at the current epoch.
    pub fn track(&mut self, pg: PgT, epoch: u32) {
        let i = match self.index.get(&pg) {
            Some(&i) => i,
            None => {
                let i = self.free.pop().unwrap_or_else(|| {
                    self.entries.push(Entry::default());
                    self.entries.len() - 1
                });
                let e = &mut self.entries[i];
                e.pg = pg;
                e.refs = 0;
                e.based = false;
                e.since = 0;
                e.since_generation = 0;
                self.index.insert(pg, i);
                i
            }
        };
        let e = &mut self.entries[i];
        e.refs += 1;
        if epoch < self.epoch {
            e.since = e.since.max(self.epoch);
            e.since_generation = self.generation;
        }
    }
    /// Stop following `pg` for one request (the PG is dropped with its last request).
    pub fn untrack(&mut self, pg: PgT) {
        let Some(&i) = self.index.get(&pg) else {
            return;
        };
        let e = &mut self.entries[i];
        e.refs -= 1;
        if e.refs == 0 {
            self.index.remove(&pg);
            self.free.push(i);
        }
    }
    /// Epoch at which followed `pg` last started a new interval (0 = none seen), `None` = not followed.
    pub fn interval_since(&self, pg: PgT) -> Option<u32> {
        self.index.get(&pg).map(|&i| self.entries[i].since)
    }
    /// Install generation of the last observed interval, None if PG is not followed.
    pub fn interval_generation(&self, pg: PgT) -> Option<u64> {
        self.index
            .get(&pg)
            .map(|&i| self.entries[i].since_generation)
    }
    /// Apply one map epoch: `prev` is the map the watch saw last (`None` or a non-adjacent epoch = gap: every followed
    /// PG starts a new interval at `next.epoch`). Each followed PG is mapped once.
    pub fn observe(&mut self, prev: Option<&OsdMap>, next: &OsdMap) {
        // a counter wrap is just another non-advancing install identity (gap), never an abort
        self.observe_generation(prev, next, self.generation.wrapping_add(1));
    }
    /// Observe one installed map using the owner's monotonic install identity.
    /// Same-epoch replacement compares real interval state instead of declaring a gap.
    pub fn observe_generation(&mut self, prev: Option<&OsdMap>, next: &OsdMap, generation: u64) {
        // A non-advancing install identity (repeated or reordered install, re-created owner, counter reset) cannot be
        // compared against the stored intervals: treat it as a gap (fresh baseline at `next.epoch`), never abort.
        let gap = generation <= self.generation
            || prev.is_none_or(|p| {
                p.epoch != next.epoch && p.epoch.checked_add(1) != Some(next.epoch)
            });
        self.epoch = next.epoch;
        self.generation = generation;
        for &i in self.index.values() {
            let e = &mut self.entries[i];
            if gap {
                e.since = next.epoch;
                e.since_generation = generation;
                e.based = false;
                continue;
            }
            if !e.based {
                e.snap
                    .take(prev.expect("adjacent epoch has a previous map"), e.pg);
                e.based = true;
            }
            e.scratch.take(next, e.pg);
            if e.snap.new_interval(&e.scratch, e.pg.seed) {
                e.since = next.epoch;
                e.since_generation = generation;
            }
            std::mem::swap(&mut e.snap, &mut e.scratch);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::stable_mod;

    #[test]
    fn pg_count_change_split_and_merge() {
        // 4 -> 8: seed 1 gets child 5, all of 0..4 split
        assert!((0..4).all(|s| pg_count_change_affects(s, 4, 8)));
        // 4 -> 6: children 4 (of 0) and 5 (of 1); 2 and 3 untouched
        assert!(pg_count_change_affects(0, 4, 6) && pg_count_change_affects(1, 4, 6));
        assert!(!pg_count_change_affects(2, 4, 6) && !pg_count_change_affects(3, 4, 6));
        // merge 6 -> 4: sources 4, 5 and their targets 0, 1
        assert!(pg_count_change_affects(5, 6, 4) && pg_count_change_affects(0, 6, 4));
        assert!(!pg_count_change_affects(3, 6, 4));
        assert!(!pg_count_change_affects(3, 6, 6));
    }

    /// The scan the closed form replaces (spec 4.2 semantics): a child `c` in [lo, hi) folds onto `stable_mod(c, ..)`.
    fn affects_by_scan(seed: u32, a: u32, b: u32) -> bool {
        let (lo, hi) = (a.min(b), a.max(b));
        if lo == hi {
            return false;
        }
        if lo == 0 || seed >= lo {
            return true;
        }
        let mask = stable_mask(lo);
        (lo..hi).any(|c| stable_mod(c, lo, mask) == seed)
    }

    fn assert_same(counts: &[u32]) {
        for &a in counts {
            for &b in counts {
                let top = a.max(b) + 1;
                for seed in 0..=top {
                    assert_eq!(
                        pg_count_change_affects(seed, a, b),
                        affects_by_scan(seed, a, b),
                        "seed {seed}, pg_num {a} -> {b}"
                    );
                }
            }
        }
    }

    #[test]
    fn pg_count_change_affects_matches_the_scan() {
        let small: Vec<u32> = (0..=24).chain([32, 33, 48, 63, 64, 65, 100]).collect();
        assert_same(&small);
        // counts around a period boundary (stable_mask changes between 127, 128, 129)
        assert_same(&[127, 128, 129, 255, 256, 257, 1000, 1024, 1025, 4096]);
    }

    /// Deterministic pseudo-random pairs of larger counts: the scan reference stays affordable because only a few
    /// seeds per pair are sampled.
    #[test]
    fn pg_count_change_affects_random_pairs_match_the_scan() {
        let mut r = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            r ^= r >> 12;
            r ^= r << 25;
            r ^= r >> 27;
            r.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        for _ in 0..40 {
            let a = (next() % 8192) as u32;
            let b = (next() % 8192) as u32;
            for _ in 0..16 {
                let seed = (next() % u64::from(a.max(b).max(1) + 1)) as u32;
                assert_eq!(
                    pg_count_change_affects(seed, a, b),
                    affects_by_scan(seed, a, b),
                    "seed {seed}, pg_num {a} -> {b}"
                );
            }
        }
    }

    #[test]
    fn observe_wraps_the_install_generation_instead_of_aborting() {
        let m = OsdMap::default();
        let mut w = PgWatch {
            generation: u64::MAX,
            ..Default::default()
        };
        w.observe(None, &m);
        assert_eq!(w.generation, 0);
        assert_eq!(w.epoch, 0);
    }
}
