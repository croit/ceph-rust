// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Run block cache of one shard (adr 0610 (5), phase 2): device reads of run pages / chunks as the owner's reads
//! requested them, kept whole (a later read of a sub-range is a slice, no copy), evicted oldest first above the
//! capacity. Reads in flight are tracked so a missing range is requested once; the store answers a miss with
//! [`crate::StoreError::Miss`] and parks the operation like a tree page miss (non-blocking callers re-run it after the
//! wake, blocking callers wait for it).
//!
//! Progress: a read operation (a listing merges one chunk of every run) needs several extents at once and is re-run
//! after a miss: a point read from the start, a listing from the position its refused call returned
//! ([`super::read::ListPos`]), which already holds everything before it. An extent used or loaded since the last
//! completed operation ([`RunCache::op_done`]) is not evicted (speculative reads are excluded), so a re-run finds what
//! its earlier runs loaded even when its working set exceeds the capacity (the cache then holds more than `cap` until
//! an operation completes).
//!
//! Checked pages: an extent remembers which of its first 64 pages passed their crc check in a read
//! ([`RunCache::checked`]); a later read of checked pages ([`RunCache::get_checked`]) skips the check (the bytes are
//! immutable while cached).
//!
//! Foreground listing hints reserve at most a quarter of the cache for speculative resident and outstanding bytes.
//! They reclaim old demand extents outside the current operation, retaining independent hints within their share.
//! A completion that cannot fit is discarded; speculation never uses the demand progress exemption. First demanded
//! use promotes a hint
//! to ordinary protected cache data. Reader epochs are owned by the shard until the actual device completion.
//!
//! Lookup: an extent is found by its first block in a hash map (a point get reads the same page again, a listing the
//! same page-to-chunk-end range); a range starting inside an extent is found through the ordered set of first blocks.
//!
//! Coherence: run extents are immutable while referenced; a merge frees its input extents only through the store's
//! free path (held until a checkpoint passed and every reader epoch older than the free ended), and
//! [`RunCache::forget`] drops cached and in-flight ranges of freed extents at the merge install, so a reused block is
//! never answered from an old read.

use bytes::Bytes;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use crate::BLK;
use crate::fx::FxBuild;

/// A read the cache wants submitted: `(blk, nblk)`.
pub type Want = (u64, u32);

/// One cached extent.
#[derive(Debug)]
struct Ext {
    data: Bytes,
    /// Operation generation of the last use.
    used: u64,
    /// Bit `k`: page `k` of the extent passed its crc check.
    checked: u64,
    /// Speculative data has no operation protection until its first demanded use.
    /// Zero for demanded data; otherwise its key in the separate speculative FIFO.
    spec_seq: u64,
    /// Its first demand arrived before the speculative read completed.
    late: bool,
}

impl Ext {
    fn nblk(&self) -> u64 {
        (self.data.len() / BLK) as u64
    }
}

/// Bits of pages `first..first + n` of an extent; `None` beyond the 64 tracked pages.
fn page_bits(first: u64, n: u32) -> Option<u64> {
    (n > 0 && first + n as u64 <= 64).then(|| (u64::MAX >> (64 - n)) << first)
}

/// Foreground listing read-ahead counters, per shard. Useful/unused resolve once per speculative extent; bytes
/// cover the entire extent on first use or discard, not each requested subrange. Outstanding bytes are unresolved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrefetchStats {
    pub submitted: u64,
    pub useful: u64,
    pub unused: u64,
    pub throttled: u64,
    /// Demand read attempts that wait for an already submitted speculative chunk (retries count again).
    pub demand_waits: u64,
    pub inflight_bytes: u64,
    pub resident_bytes: u64,
    /// Speculative reads first demanded while pending; retries do not count again.
    pub late: u64,
    pub late_bytes: u64,
    pub useful_bytes: u64,
    pub unused_bytes: u64,
    /// Useful bytes whose first demand arrived while pending (a subset of `useful_bytes`).
    pub useful_late_bytes: u64,
}

/// Byte-cohort controller, owned by the shard rather than a reconstructed listing cursor.
/// A cohort needs 256 KiB of resolved bytes. Two cohorts at least 7/8 useful and at least 1/4 late
/// grow one chunk; a cohort at least 1/4 unused halves the window. Pressure halves once per episode.
/// Pending hints never count as waste. All changes stay inside 1..=the configured ceiling.
#[derive(Debug)]
pub(crate) struct AdaptivePrefetch {
    pub window: usize,
    pub grows: u64,
    pub shrinks: u64,
    mark: PrefetchStats,
    good: u8,
    pressure: bool,
}

impl Default for AdaptivePrefetch {
    fn default() -> Self {
        Self {
            window: 1,
            grows: 0,
            shrinks: 0,
            mark: PrefetchStats::default(),
            good: 0,
            pressure: false,
        }
    }
}

impl AdaptivePrefetch {
    pub fn observe(&mut self, stats: PrefetchStats, max: usize, pressure: bool) {
        self.window = self.window.min(max).max(1);
        if pressure {
            if !self.pressure {
                self.shrink();
                self.mark = stats;
            }
            self.good = 0;
        }
        if self.pressure {
            self.mark = stats;
        }
        self.pressure = pressure;
        if pressure {
            return;
        }
        let useful = stats.useful_bytes - self.mark.useful_bytes;
        let unused = stats.unused_bytes - self.mark.unused_bytes;
        let resolved = useful + unused;
        if resolved < 256 * 1024 {
            return;
        }
        let late = stats.useful_late_bytes - self.mark.useful_late_bytes;
        self.mark = stats;
        if unused >= resolved.div_ceil(4) {
            self.shrink();
        } else if useful >= resolved - resolved / 8 && late >= useful.div_ceil(4) {
            self.good += 1;
            if self.good == 2 {
                if self.window < max {
                    self.window += 1;
                    self.grows += 1;
                }
                self.good = 0;
            }
        } else {
            self.good = 0;
        }
    }

    fn shrink(&mut self) {
        self.good = 0;
        if self.window > 1 {
            self.window = (self.window / 2).max(1);
            self.shrinks += 1;
        }
    }
}

#[derive(Debug)]
struct Speculative {
    bytes: usize,
    late: bool,
}

#[derive(Debug, Default)]
pub struct RunCache {
    /// Cached extents by first block; extents may overlap (a page and its chunk).
    ext: HashMap<u64, Ext, FxBuild>,
    /// First blocks of `ext`, ordered.
    starts: BTreeSet<u64>,
    /// Operation generation ([`RunCache::op_done`]).
    generation: u64,
    /// Demanded insertion order (eviction); speculative extents join only on their first use.
    order: VecDeque<u64>,
    /// Speculative insertion order, independently removable on use or eviction.
    spec_order: BTreeMap<u64, u64>,
    next_spec: u64,
    bytes: usize,
    /// Current-generation demanded bytes; speculative extents never contribute.
    protected_bytes: usize,
    cap: usize,
    /// Longest cached extent in blocks (bounds the backward search for a covering extent).
    max_nblk: u64,
    /// Reads in flight: token -> range; a completion of a forgotten range is dropped.
    inflight: HashMap<u64, Want, FxBuild>,
    next_tok: u64,
    /// Token -> reserved bytes; retained through forget until its actual completion.
    speculative: HashMap<u64, Speculative, FxBuild>,
    pub prefetch_stats: PrefetchStats,
}

impl RunCache {
    pub fn new(cap: usize) -> RunCache {
        RunCache {
            cap,
            ..Default::default()
        }
    }

    /// Bytes cached (demanded and speculative extents).
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Capacity in bytes.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Set the capacity (the shard's own share plus what it may borrow from the tree page budget, adr 0633 am. 5); a
    /// smaller one evicts down to it at once, so a cache with no insertion of its own gives its lend back.
    pub fn set_cap(&mut self, cap: usize) {
        self.cap = cap;
        self.evict_to_cap();
    }

    /// First block of the cached extent covering `[blk, blk + nblk)`.
    fn find(&self, blk: u64, nblk: u32) -> Option<u64> {
        let end = blk + nblk as u64;
        if self.ext.get(&blk).is_some_and(|e| blk + e.nblk() >= end) {
            return Some(blk);
        }
        let lo = blk.saturating_sub(self.max_nblk);
        self.starts
            .range(lo..blk)
            .rev()
            .find(|s| **s + self.ext[*s].nblk() >= end)
            .copied()
    }

    /// Cached bytes of `[blk, blk + nblk)` (a slice of one cached extent covering it) and whether all of its pages
    /// were checked ([`RunCache::checked`]).
    pub fn get_checked(&mut self, blk: u64, nblk: u32) -> Option<(Bytes, bool)> {
        let g = self.generation;
        self.find(blk, nblk).map(|s| {
            let e = self.ext.get_mut(&s).expect("found");
            if e.spec_seq != 0 || e.used != g {
                self.protected_bytes += e.data.len();
            }
            e.used = g;
            if e.spec_seq != 0 {
                self.spec_order.remove(&e.spec_seq);
                e.spec_seq = 0;
                self.order.push_back(s);
                self.prefetch_stats.useful += 1;
                self.prefetch_stats.useful_bytes += e.data.len() as u64;
                if e.late {
                    self.prefetch_stats.useful_late_bytes += e.data.len() as u64;
                }
                self.prefetch_stats.resident_bytes -= e.data.len() as u64;
            }
            let off = (blk - s) as usize * BLK;
            let ok = page_bits(blk - s, nblk).is_some_and(|m| e.checked & m == m);
            (e.data.slice(off..off + nblk as usize * BLK), ok)
        })
    }

    /// Cached bytes of `[blk, blk + nblk)` (a slice of one cached extent covering it).
    pub fn get(&mut self, blk: u64, nblk: u32) -> Option<Bytes> {
        self.get_checked(blk, nblk).map(|(b, _)| b)
    }

    /// The pages `[blk, blk + nblk)` passed their crc check: mark them in the cached extent covering them.
    pub fn checked(&mut self, blk: u64, nblk: u32) {
        if let Some(s) = self.find(blk, nblk)
            && let Some(m) = page_bits(blk - s, nblk)
        {
            self.ext.get_mut(&s).expect("found").checked |= m;
        }
    }

    /// The range is already being read.
    pub fn pending(&self, blk: u64, nblk: u32) -> bool {
        let end = blk + nblk as u64;
        self.inflight
            .values()
            .any(|&(b, n)| b <= blk && b + n as u64 >= end)
    }

    /// Whether any cached or in-flight range intersects the hint (including a cached point page). A hint never
    /// duplicates existing bytes; a demanded suffix still uses the ordinary covering-range lookup.
    pub fn overlaps(&self, blk: u64, nblk: u32) -> bool {
        let end = blk + u64::from(nblk);
        let lo = blk.saturating_sub(self.max_nblk);
        self.starts
            .range(lo..end)
            .any(|s| *s + self.ext[s].nblk() > blk)
            || self
                .inflight
                .values()
                .any(|&(b, n)| n > 0 && b < end && blk < b + u64::from(n))
    }

    /// Reserve a hint within a quarter of this shard's cache, including outstanding buffers. Reclaim old,
    /// unprotected demanded data while retaining hints inside their share. Never use the demand operation's
    /// progress exemption.
    pub fn start_prefetch(&mut self, blk: u64, nblk: u32) -> Option<u64> {
        if self.overlaps(blk, nblk) {
            return None;
        }
        let n = nblk as usize * BLK;
        let reserved = self.prefetch_stats.inflight_bytes as usize;
        let need = self
            .bytes
            .saturating_add(reserved + n)
            .saturating_sub(self.cap);
        if n > self.cap / 4
            || reserved + n > self.cap / 4
            || self.bytes - self.protected_bytes < need
        {
            self.prefetch_stats.throttled += 1;
            return None;
        }
        // Replace older hints only when their own share is exhausted, retaining independent next chunks.
        while self.prefetch_stats.resident_bytes as usize + reserved + n > self.cap / 4 {
            let s = *self.spec_order.first_key_value().expect("resident hint").1;
            self.drop_ext(s);
        }
        if !self.prefetch_room(reserved + n) {
            self.prefetch_stats.throttled += 1;
            return None;
        }
        let tok = self.start(blk, nblk);
        self.speculative.insert(
            tok,
            Speculative {
                bytes: n,
                late: false,
            },
        );
        self.prefetch_stats.inflight_bytes += n as u64;
        self.prefetch_stats.submitted += 1;
        Some(tok)
    }

    /// Count a demand miss covered by a speculative read without promoting or pinning it.
    pub fn prefetch_wait(&mut self, blk: u64, nblk: u32) {
        let end = blk + u64::from(nblk);
        for (t, hint) in &mut self.speculative {
            if self
                .inflight
                .get(t)
                .is_some_and(|&(b, n)| n > 0 && b <= blk && b + u64::from(n) >= end)
            {
                self.prefetch_stats.demand_waits += 1;
                if !hint.late {
                    hint.late = true;
                    self.prefetch_stats.late += 1;
                    self.prefetch_stats.late_bytes += hint.bytes as u64;
                }
                break;
            }
        }
    }

    /// Demand's protected working set leaves no room for a target hint, discounting speculative reservations.
    /// Quota exhaustion by speculative buffers alone is ordinary admission, not controller pressure.
    pub(crate) fn demand_pressure(&self, n: usize) -> bool {
        self.protected_bytes.saturating_add(n) > self.cap
    }

    /// Make room without evicting data protected by the current operation. No side effects on failure.
    fn prefetch_room(&mut self, reserve: usize) -> bool {
        let need = self.bytes.saturating_add(reserve).saturating_sub(self.cap);
        if need == 0 {
            return true;
        }
        if self.bytes - self.protected_bytes < need {
            return false;
        }
        // Keep independently useful next chunks inside their share. Reclaim old demanded data first; a full
        // cold cache normally needs just its first FIFO entry, and an all-protected cache was rejected above.
        let mut left = self.order.len();
        while self.bytes.saturating_add(reserve) > self.cap
            && left > 0
            && self.bytes - self.protected_bytes > self.prefetch_stats.resident_bytes as usize
        {
            left -= 1;
            let s = self.order.pop_front().expect("left <= len");
            if self.ext[&s].used != self.generation {
                self.drop_ext(s);
            } else {
                self.order.push_back(s);
            }
        }
        while self.bytes.saturating_add(reserve) > self.cap {
            let s = *self
                .spec_order
                .first_key_value()
                .expect("reclaimable hint")
                .1;
            self.drop_ext(s);
        }
        true
    }

    /// Track a submitted read; returns its token (low bits of the device token).
    pub fn start(&mut self, blk: u64, nblk: u32) -> u64 {
        self.next_tok += 1;
        self.inflight.insert(self.next_tok, (blk, nblk));
        self.next_tok
    }

    /// A read completed: cache its bytes (unless its range was forgotten meanwhile). Returns whether the token was ours.
    pub fn done(&mut self, tok: u64, data: Option<Bytes>) -> bool {
        let Some((blk, nblk)) = self.inflight.remove(&tok) else {
            return false;
        };
        let speculative = self.speculative.remove(&tok);
        if let Some(hint) = &speculative {
            self.prefetch_stats.inflight_bytes -= hint.bytes as u64;
        }
        if let Some(d) = data.filter(|_| nblk > 0) {
            debug_assert_eq!(d.len(), nblk as usize * BLK);
            if speculative.is_none()
                || (!self.overlaps(blk, nblk)
                    && self.prefetch_room(self.prefetch_stats.inflight_bytes as usize + d.len()))
            {
                self.insert(blk, d, speculative.as_ref().map(|h| h.late));
            } else if let Some(hint) = speculative {
                self.prefetch_stats.unused += 1;
                self.prefetch_stats.unused_bytes += hint.bytes as u64;
            }
        } else if let Some(hint) = speculative {
            self.prefetch_stats.unused += 1;
            self.prefetch_stats.unused_bytes += hint.bytes as u64;
        }
        true
    }

    /// A read operation completed (it needs none of its extents any more): extents it used become evictable.
    pub fn op_done(&mut self) {
        self.generation += 1;
        self.protected_bytes = 0;
    }

    fn insert(&mut self, blk: u64, d: Bytes, hint: Option<bool>) {
        let n = d.len();
        let speculative = hint.is_some();
        self.max_nblk = self.max_nblk.max((n / BLK) as u64);
        let spec_seq = if speculative {
            self.next_spec += 1;
            self.next_spec
        } else {
            0
        };
        let e = Ext {
            data: d,
            used: self.generation,
            checked: 0,
            spec_seq,
            late: hint.unwrap_or(false),
        };
        match self.ext.insert(blk, e) {
            // a replaced extent keeps its place in the eviction order
            Some(old) => {
                self.bytes -= old.data.len();
                debug_assert!(!speculative, "hint completion overlapped cached data");
                if old.spec_seq == 0 && old.used == self.generation {
                    self.protected_bytes -= old.data.len();
                }
                if old.spec_seq != 0 {
                    self.spec_order.remove(&old.spec_seq);
                    self.order.push_back(blk);
                    self.prefetch_stats.resident_bytes -= old.data.len() as u64;
                    self.prefetch_stats.unused += 1;
                    self.prefetch_stats.unused_bytes += old.data.len() as u64;
                }
            }
            None => {
                if !speculative {
                    self.order.push_back(blk);
                }
                self.starts.insert(blk);
            }
        }
        self.bytes += n;
        if !speculative {
            self.protected_bytes += n;
        }
        if speculative {
            self.spec_order.insert(spec_seq, blk);
            self.prefetch_stats.resident_bytes += n as u64;
        }
        // Demand inserts reclaim unused hints before any demanded extent, without walking the demand FIFO.
        self.evict_to_cap();
    }

    /// Evict down to [`RunCache::cap`]: unused hints first, then the oldest demanded extents not used by the operation
    /// in progress. O(evicted); one pass over the order at most.
    fn evict_to_cap(&mut self) {
        while self.bytes > self.cap && !self.spec_order.is_empty() {
            let s = *self.spec_order.first_key_value().expect("not empty").1;
            self.drop_ext(s);
        }
        // oldest first, skipping the extents of the operation in progress
        let mut left = self.order.len();
        while self.bytes > self.cap && left > 0 {
            left -= 1;
            let s = self.order.pop_front().expect("left <= len");
            if self.ext.get(&s).is_some_and(|e| e.used == self.generation) {
                self.order.push_back(s);
            } else {
                self.drop_ext(s);
            }
        }
    }

    /// Remove the extent starting at `s` (its `order` entry is the caller's).
    fn drop_ext(&mut self, s: u64) {
        if let Some(b) = self.ext.remove(&s) {
            self.starts.remove(&s);
            self.bytes -= b.data.len();
            if b.spec_seq == 0 && b.used == self.generation {
                self.protected_bytes -= b.data.len();
            }
            if b.spec_seq != 0 {
                self.spec_order.remove(&b.spec_seq);
                self.prefetch_stats.unused += 1;
                self.prefetch_stats.unused_bytes += b.data.len() as u64;
                self.prefetch_stats.resident_bytes -= b.data.len() as u64;
            }
        }
    }

    /// Drop cached and in-flight ranges intersecting freed extents.
    pub fn forget(&mut self, freed: &[(u64, u32)]) {
        let hit = |s: u64, n: u64| {
            freed
                .iter()
                .any(|&(b, fnb)| s < b + fnb as u64 && b < s + n)
        };
        // an extent starting before `b` and reaching into the freed one is at most `max_nblk` blocks long
        let mut gone = Vec::new();
        for &(b, n) in freed {
            let lo = b.saturating_sub(self.max_nblk);
            gone.extend(
                self.starts
                    .range(lo..b + n as u64)
                    .copied()
                    .filter(|s| s + self.ext[s].nblk() > b),
            );
        }
        for s in gone {
            self.drop_ext(s);
        }
        self.order.retain(|s| self.ext.contains_key(s));
        // their completions still arrive (and release their reader pins): only their data is dropped
        for v in self.inflight.values_mut() {
            if hit(v.0, v.1 as u64) {
                v.1 = 0;
            }
        }
    }

    /// Operator cache drop: remove every cached extent; reads in flight complete into the cache as usual. Returns the
    /// bytes dropped.
    pub fn clear(&mut self) -> usize {
        let b = self.bytes;
        self.prefetch_stats.unused += self.spec_order.len() as u64;
        self.prefetch_stats.unused_bytes += self.prefetch_stats.resident_bytes;
        self.prefetch_stats.resident_bytes = 0;
        self.ext.clear();
        self.starts.clear();
        self.order.clear();
        self.spec_order.clear();
        self.bytes = 0;
        self.protected_bytes = 0;
        self.max_nblk = 0;
        b
    }

    /// A completion whose range was forgotten: `nblk` was set to 0 by [`RunCache::forget`].
    pub fn forgotten(&self, tok: u64) -> bool {
        self.inflight.get(&tok).is_some_and(|v| v.1 == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(n: usize, fill: u8) -> Bytes {
        Bytes::from(vec![fill; n * BLK])
    }

    #[test]
    fn sub_range_is_a_slice_and_forget_drops_it() {
        let mut c = RunCache::new(1 << 20);
        let t = c.start(100, 16);
        assert!(c.pending(104, 2));
        assert!(c.get(104, 2).is_none());
        assert!(c.done(t, Some(blocks(16, 7))));
        let s = c.get(104, 2).unwrap();
        assert_eq!(s.len(), 2 * BLK);
        assert!(c.get(115, 2).is_none(), "beyond the extent");
        c.forget(&[(110, 1)]);
        assert!(c.get(104, 2).is_none());
        assert_eq!(c.bytes(), 0);
    }

    #[test]
    fn clear_drops_extents_but_not_reads_in_flight() {
        let mut c = RunCache::new(1 << 20);
        let t = c.start(100, 16);
        c.done(t, Some(blocks(16, 7)));
        let fly = c.start(300, 4);
        assert_eq!(c.clear(), 16 * BLK);
        assert!(c.get(100, 16).is_none());
        assert_eq!(c.bytes(), 0);
        assert!(c.done(fly, Some(blocks(4, 1))));
        assert!(c.get(300, 4).is_some());
    }

    #[test]
    fn eviction_keeps_the_newest_and_forgotten_reads_are_dropped() {
        let mut c = RunCache::new(3 * BLK);
        for i in 0..5u64 {
            let t = c.start(i * 10, 1);
            c.done(t, Some(blocks(1, i as u8)));
            c.op_done();
        }
        assert!(c.bytes() <= 3 * BLK);
        assert!(c.get(40, 1).is_some());
        assert!(c.get(0, 1).is_none());
        let t = c.start(200, 4);
        c.forget(&[(201, 1)]);
        assert!(c.forgotten(t));
        // the caller drops the data of a forgotten completion
        assert!(c.done(t, None));
        assert!(c.get(200, 4).is_none());
    }

    #[test]
    fn set_cap_evicts_down_to_the_new_capacity_at_once() {
        let mut c = RunCache::new(8 * BLK);
        for i in 0..8u64 {
            let t = c.start(i * 10, 1);
            c.done(t, Some(blocks(1, i as u8)));
            c.op_done();
        }
        assert_eq!(c.bytes(), 8 * BLK);
        c.set_cap(3 * BLK);
        assert_eq!(c.bytes(), 3 * BLK, "evicted without an insertion");
        assert!(c.get(70, 1).is_some(), "the newest extents stay");
        assert!(c.get(0, 1).is_none(), "the oldest left");
    }

    #[test]
    fn checked_pages_are_remembered_per_extent_and_dropped_with_it() {
        let mut c = RunCache::new(1 << 20);
        let t = c.start(100, 16);
        c.done(t, Some(blocks(16, 1)));
        assert!(!c.get_checked(103, 1).unwrap().1);
        c.checked(103, 2);
        assert!(c.get_checked(103, 1).unwrap().1);
        assert!(c.get_checked(104, 1).unwrap().1);
        assert!(!c.get_checked(103, 3).unwrap().1, "page 105 unchecked");
        // an extent at the same first block: found directly, its own marks
        let t = c.start(103, 1);
        c.done(t, Some(blocks(1, 2)));
        assert!(!c.get_checked(103, 1).unwrap().1);
        assert!(
            c.get_checked(103, 2).unwrap().1,
            "the longer extent covers two pages"
        );
        c.forget(&[(100, 16)]);
        assert!(c.get_checked(103, 2).is_none());
        let t = c.start(100, 16);
        c.done(t, Some(blocks(16, 3)));
        assert!(
            !c.get_checked(104, 1).unwrap().1,
            "a reloaded extent starts unchecked"
        );
    }

    #[test]
    fn an_operation_in_progress_keeps_its_extents_beyond_the_capacity() {
        let mut c = RunCache::new(2 * BLK);
        for i in 0..4u64 {
            let t = c.start(i * 10, 1);
            c.done(t, Some(blocks(1, i as u8)));
        }
        assert!(
            (0..4u64).all(|i| c.get(i * 10, 1).is_some()),
            "working set kept"
        );
        c.op_done();
        let t = c.start(100, 1);
        c.done(t, Some(blocks(1, 9)));
        assert!(c.bytes() <= 2 * BLK);
    }
    #[test]
    fn prefetch_reclaims_cold_full_cache_but_never_protected_working_set() {
        let mut c = RunCache::new(8 * BLK);
        let t = c.start(100, 8);
        c.done(t, Some(blocks(8, 1)));
        assert!(c.start_prefetch(200, 1).is_none(), "all data protected");
        assert_eq!(c.bytes(), 8 * BLK);
        c.op_done();
        let t = c
            .start_prefetch(200, 1)
            .expect("full cold cache is reclaimable");
        assert!(c.bytes() + c.prefetch_stats.inflight_bytes as usize <= 8 * BLK);
        c.done(t, Some(blocks(1, 2)));
        assert_eq!(c.prefetch_stats.resident_bytes, BLK as u64);
        assert_eq!(c.prefetch_stats.useful, 0);
        assert!(c.get(200, 1).is_some());
        assert_eq!(c.prefetch_stats.useful, 1);
        assert_eq!(c.prefetch_stats.resident_bytes, 0);
        c.get(200, 1);
        assert_eq!(c.prefetch_stats.useful, 1, "first demanded use only");
    }

    #[test]
    fn prefetch_is_bounded_deduplicated_and_not_operation_pinned() {
        let mut c = RunCache::new(8 * BLK);
        assert!(
            RunCache::new(BLK).start_prefetch(1, 1).is_none(),
            "small cache skips"
        );
        let t = c.start_prefetch(100, 2).unwrap();
        assert!(
            c.start_prefetch(101, 2).is_none(),
            "overlapping in-flight hint"
        );
        assert!(
            c.start_prefetch(200, 1).is_none(),
            "outstanding share exhausted"
        );
        c.prefetch_wait(101, 1);
        assert_eq!(c.prefetch_stats.demand_waits, 1);
        c.done(t, Some(blocks(2, 1)));
        assert!(c.start_prefetch(101, 1).is_none(), "cached overlap");
        let t = c.start_prefetch(200, 2).unwrap();
        assert!(
            c.get(100, 1).is_none(),
            "unused hint evicted before demanded cache"
        );
        c.done(t, Some(blocks(2, 2)));
        assert!(
            c.prefetch_stats.resident_bytes + c.prefetch_stats.inflight_bytes <= 2 * BLK as u64
        );
        let t = c.start(300, 8);
        c.done(t, Some(blocks(8, 3)));
        assert!(
            c.get(200, 1).is_none(),
            "unused hint cannot use demand progress protection"
        );
        assert!(c.get(300, 8).is_some());
        assert_eq!(c.bytes(), 8 * BLK);
        assert_eq!(c.prefetch_stats.unused, 2);
    }

    #[test]
    fn prefetch_late_completion_after_free_keeps_reservation_until_landed_and_drops_data() {
        let mut c = RunCache::new(8 * BLK);
        let t = c.start_prefetch(100, 2).unwrap();
        c.forget(&[(101, 1)]);
        assert!(c.forgotten(t));
        assert_eq!(c.prefetch_stats.inflight_bytes, 2 * BLK as u64);
        assert!(
            c.start_prefetch(200, 1).is_none(),
            "forgotten I/O still consumes memory"
        );
        // Defensive even when a caller passes the stale bytes: never resurrect a freed extent.
        c.done(t, Some(blocks(2, 1)));
        assert!(c.get(100, 1).is_none());
        assert_eq!(c.prefetch_stats.inflight_bytes, 0);
        assert_eq!(c.prefetch_stats.unused, 1);
        let t = c.start(100, 1);
        c.done(t, Some(blocks(1, 9)));
        assert_eq!(c.get(100, 1).unwrap()[0], 9);
    }

    #[test]
    fn prefetch_completion_cannot_grow_protected_cache_beyond_cap() {
        let mut c = RunCache::new(8 * BLK);
        let hint = c.start_prefetch(100, 2).unwrap();
        let demand = c.start(200, 8);
        c.done(demand, Some(blocks(8, 1)));
        c.done(hint, Some(blocks(2, 2)));
        assert_eq!(c.bytes(), 8 * BLK);
        assert_eq!(c.prefetch_stats.unused, 1);
        assert!(c.get(200, 8).is_some(), "demand data kept");
        assert!(c.get(100, 2).is_none());
    }

    #[test]
    fn independent_hints_survive_in_full_cold_cache_within_their_share() {
        let mut c = RunCache::new(16 * BLK);
        for i in 100..116 {
            let t = c.start(i, 1);
            c.done(t, Some(blocks(1, 1)));
        }
        c.op_done();
        for i in 200..203 {
            let t = c.start_prefetch(i, 1).unwrap();
            c.done(t, Some(blocks(1, 2)));
            assert_eq!(c.bytes(), 16 * BLK);
        }
        assert_eq!(c.prefetch_stats.resident_bytes, 3 * BLK as u64);
        assert_eq!(
            c.prefetch_stats.unused, 0,
            "independent next chunks retained within share"
        );
        for i in 200..203 {
            assert!(c.get(i, 1).is_some());
        }
        assert_eq!(c.prefetch_stats.useful, 3);
        assert_eq!(c.prefetch_stats.resident_bytes, 0);
        assert!(c.get(100, 1).is_none(), "old demand extents reclaimed");
        assert!(c.get(115, 1).is_some());
        // A promoted hint belongs only to the demand FIFO: a free must not leave a stale hint entry.
        c.forget(&[(200, 1)]);
        assert!(c.get(200, 1).is_none());
        assert!(c.spec_order.is_empty());
    }

    #[test]
    fn hints_replace_each_other_without_disturbing_protected_demand_data() {
        let mut c = RunCache::new(16 * BLK);
        let t = c.start(100, 14);
        c.done(t, Some(blocks(14, 1)));
        for i in 200..203 {
            let t = c.start_prefetch(i, 1).unwrap();
            c.done(t, Some(blocks(1, 2)));
        }
        assert!(c.get(100, 14).is_some());
        assert!(
            c.get(200, 1).is_none(),
            "oldest hint replaced to retain protected data"
        );
        assert!(c.get(201, 1).is_some());
        assert!(c.get(202, 1).is_some());
        assert_eq!(c.bytes(), 16 * BLK);
        assert_eq!(c.prefetch_stats.unused, 1);
    }
    #[test]
    fn adaptive_resolved_byte_cohorts_hysteresis_and_bounds() {
        let mut a = AdaptivePrefetch::default();
        // Pending submissions, including unique late marks, are never resolved waste or evidence to grow.
        let mut stats = PrefetchStats {
            submitted: 1000,
            late_bytes: 1 << 30,
            ..Default::default()
        };
        a.observe(stats, 3, false);
        assert_eq!(a.window, 1);
        // Variable extent sizes accumulate by bytes, not count; two full good cohorts grow once.
        for _ in 0..2 {
            for bytes in [4096, 61440, 196608] {
                stats.useful_bytes += bytes;
                stats.useful_late_bytes += bytes;
                a.observe(stats, 3, false);
            }
        }
        assert_eq!((a.window, a.grows), (2, 1));
        for _ in 0..8 {
            stats.useful_bytes += 256 * 1024;
            stats.useful_late_bytes += 256 * 1024;
            a.observe(stats, 3, false);
        }
        assert_eq!((a.window, a.grows), (3, 2), "non-power-of-two ceiling");
        stats.unused_bytes += 64 * 1024;
        stats.useful_bytes += 192 * 1024;
        a.observe(stats, 3, false);
        assert_eq!(
            (a.window, a.shrinks),
            (1, 1),
            "25% waste halves immediately"
        );
        for _ in 0..4 {
            stats.useful_bytes += 256 * 1024;
            stats.useful_late_bytes += 256 * 1024;
            a.observe(stats, 1, false);
        }
        assert_eq!(a.window, 1);
    }

    #[test]
    fn adaptive_pressure_is_one_decrease_per_continuous_episode() {
        let mut a = AdaptivePrefetch {
            window: 16,
            ..Default::default()
        };
        let mut stats = PrefetchStats::default();
        for _ in 0..100 {
            stats.unused_bytes += 256 * 1024;
            a.observe(stats, 16, true);
        }
        assert_eq!((a.window, a.shrinks), (8, 1));
        // Pressure-period cohorts cannot immediately penalize recovery a second time.
        a.observe(stats, 16, false);
        assert_eq!((a.window, a.shrinks), (8, 1));
        a.observe(stats, 16, true);
        assert_eq!((a.window, a.shrinks), (4, 2));
    }

    #[test]
    fn prefetch_first_late_demand_and_resolution_bytes_survive_lifecycle() {
        let mut c = RunCache::new(64 * BLK);
        let t = c.start_prefetch(100, 4).unwrap();
        for _ in 0..10 {
            c.prefetch_wait(101, 1);
        }
        assert_eq!(c.prefetch_stats.demand_waits, 10);
        assert_eq!(
            (c.prefetch_stats.late, c.prefetch_stats.late_bytes),
            (1, 4 * BLK as u64)
        );
        c.done(t, Some(blocks(4, 1)));
        assert!(c.get(102, 1).is_some());
        assert!(c.get(100, 4).is_some());
        assert_eq!(c.prefetch_stats.useful_bytes, 4 * BLK as u64);
        assert_eq!(c.prefetch_stats.useful_late_bytes, 4 * BLK as u64);
        let forgotten = c.start_prefetch(200, 3).unwrap();
        c.prefetch_wait(200, 1);
        c.forget(&[(200, 1)]);
        c.done(forgotten, Some(blocks(3, 2)));
        assert_eq!(c.prefetch_stats.unused_bytes, 3 * BLK as u64);
        assert_eq!(c.prefetch_stats.useful_late_bytes, 4 * BLK as u64);
        let replacement = c.start_prefetch(300, 2).unwrap();
        c.done(replacement, Some(blocks(2, 3)));
        let demand = c.start(300, 1);
        c.done(demand, Some(blocks(1, 4)));
        let cleared = c.start_prefetch(400, 1).unwrap();
        c.done(cleared, Some(blocks(1, 5)));
        c.clear();
        c.clear();
        assert_eq!(c.prefetch_stats.unused_bytes, 6 * BLK as u64);
        assert_eq!(
            c.prefetch_stats.useful_bytes + c.prefetch_stats.unused_bytes,
            10 * BLK as u64
        );
        assert_eq!(
            c.prefetch_stats.inflight_bytes + c.prefetch_stats.resident_bytes,
            0
        );
    }
    #[test]
    fn adaptive_growth_requires_usefulness_and_lateness_thresholds() {
        for (useful, late, grows) in [
            (229376, 57344, 1),
            (229375, 57344, 0),
            (229376, 57343, 0),
            (262144, 0, 0),
        ] {
            let mut a = AdaptivePrefetch::default();
            let mut stats = PrefetchStats::default();
            for _ in 0..2 {
                stats.useful_bytes += useful;
                stats.unused_bytes += 262144 - useful;
                stats.useful_late_bytes += late;
                a.observe(stats, 16, false);
            }
            assert_eq!(a.grows, grows, "useful={useful} late={late}");
        }
    }
}
