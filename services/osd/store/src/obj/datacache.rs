// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Per-shard cache of committed data blocks that served a read (adr 0043, "Data cache"): a re-read of the same device
//! blocks (a hot object, an EC stash read after the RMW read, a second pass over a working set) is served from memory, no
//! device read, no prefetch round trip, no gate wait.
//!
//! Keyed by device block address. Committed data is never written in place (adr 0021): the bytes at an address change
//! only after the address was freed and allocated again, and every free passes [`DataCache::forget`] when its txn is
//! submitted (the same rule as the decompressed-chunk cache), before the allocator can hand the blocks out again. So an
//! entry holds no reader pin (unlike a prefetch run): it never delays block reuse, and it can stay until evicted.
//!
//! Entries are disjoint runs with their block crcs (computed when the device read completed, adr 0043 am. 14); bytes are
//! shared (`Bytes`): serving one is a reference, the crc check of the reader uses the stored crcs.
//!
//! Eviction is a segmented LRU (adr 0633-data-cache-envelope): a run enters the probation list; a later read of it (a re-read: the read
//! that filled it is the first) moves it to the protected list. Evictions take the oldest probation run; the protected
//! list holds at most half the capacity, its oldest runs over that go back to probation (newest end). A stream read once,
//! however long, only cycles the probation list: runs read twice (up to half the cache) survive it. Every step is O(1)
//! (intrusive lists in a slab): an insert, a hit, an eviction, a demotion; no pass over the entries, no compaction, so a
//! cache of millions of runs never scans on the PG core.
use bytes::Bytes;
use std::collections::BTreeMap;

use crate::BLK;

/// No slot (list end).
const NIL: u32 = u32::MAX;
/// List index: probation (read once), protected (read again since it was cached).
const PROB: usize = 0;
const PROT: usize = 1;

struct Node {
    pba: u64,
    n: u32,
    data: Bytes,
    crcs: Box<[u32]>,
    prev: u32,
    next: u32,
    /// [`PROB`] or [`PROT`].
    seg: u8,
}

/// Doubly linked list over slab slots: `head` = oldest, `tail` = newest.
#[derive(Clone, Copy)]
struct List {
    head: u32,
    tail: u32,
    blocks: u64,
}

impl Default for List {
    fn default() -> Self {
        List {
            head: NIL,
            tail: NIL,
            blocks: 0,
        }
    }
}

/// See the module docs.
#[derive(Default)]
pub(crate) struct DataCache {
    /// First block -> slab slot.
    map: BTreeMap<u64, u32>,
    slab: Vec<Node>,
    /// Free slab slots (their `data` is empty).
    free: Vec<u32>,
    lists: [List; 2],
    /// Capacity in blocks ([`DataCache::set_cap`]); the protected list keeps at most half of it.
    cap: u64,
    pub(crate) hits: u64,
    pub(crate) inserts: u64,
    pub(crate) evictions: u64,
    pub(crate) forgets: u64,
    /// Runs moved to the protected list by a re-read.
    pub(crate) promotions: u64,
    /// Protected runs moved back to probation (the protected list was over half the capacity).
    pub(crate) demotions: u64,
}

impl DataCache {
    /// Blocks held.
    pub(crate) fn blocks(&self) -> u64 {
        self.lists[PROB].blocks + self.lists[PROT].blocks
    }

    /// Capacity in blocks: the owner evicts down to it ([`DataCache::evict_to`]).
    pub(crate) fn cap(&self) -> u64 {
        self.cap
    }

    /// Set the capacity (the shard's share of the memory envelope, adr 0633-data-cache-envelope); a smaller one takes effect at the
    /// next [`DataCache::evict_to`].
    pub(crate) fn set_cap(&mut self, blocks: u64) {
        self.cap = blocks;
    }

    /// Entries held.
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    /// Slot of the entry holding all of `[pba, pba+n)`.
    fn covering(&self, pba: u64, n: u32) -> Option<u32> {
        let (&k, &s) = self.map.range(..=pba).next_back()?;
        (k + u64::from(self.slab[s as usize].n) >= pba + u64::from(n)).then_some(s)
    }

    /// Is all of `[pba, pba+n)` cached?
    pub(crate) fn covers(&self, pba: u64, n: u32) -> bool {
        self.covering(pba, n).is_some()
    }

    /// [`DataCache::covers`] that also moves the entry to the newest end of its list: a probe that counts on the entry
    /// keeps it past an eviction by the admission of the same probe. Not a read: no promotion.
    pub(crate) fn touch(&mut self, pba: u64, n: u32) -> bool {
        let Some(s) = self.covering(pba, n) else {
            return false;
        };
        let seg = self.slab[s as usize].seg as usize;
        self.unlink(s);
        self.push(s, seg);
        true
    }

    /// The bytes of `[pba, pba+n)` (a slice of the cached run, no copy) and their block crcs. A read: the run moves to
    /// the newest end of the protected list.
    pub(crate) fn get(&mut self, pba: u64, n: u32) -> Option<(Bytes, &[u32])> {
        let s = self.covering(pba, n)?;
        self.hits += 1;
        if self.slab[s as usize].seg as usize == PROB {
            self.promotions += 1;
        }
        self.unlink(s);
        self.push(s, PROT);
        // the protected half: its oldest runs go back to probation (each demotion is paid by an earlier promotion)
        while self.lists[PROT].blocks > self.cap / 2 && self.lists[PROT].head != s {
            let h = self.lists[PROT].head;
            self.unlink(h);
            self.push(h, PROB);
            self.demotions += 1;
        }
        let e = &self.slab[s as usize];
        let off = (pba - e.pba) as usize;
        let n = n as usize;
        Some((
            e.data.slice(off * BLK..(off + n) * BLK),
            &e.crcs[off..off + n],
        ))
    }

    /// Cache the run `[pba, pba+n)` (`data` = its bytes, `crcs` = its block crcs) on probation; replaces overlapping
    /// entries. The caller keeps the total within its capacity ([`DataCache::evict_to`]).
    pub(crate) fn put(&mut self, pba: u64, n: u32, data: Bytes, crcs: Vec<u32>) {
        debug_assert_eq!(data.len(), n as usize * BLK);
        debug_assert_eq!(crcs.len(), n as usize);
        self.remove_range(pba, n);
        let node = Node {
            pba,
            n,
            data,
            crcs: crcs.into_boxed_slice(),
            prev: NIL,
            next: NIL,
            seg: PROB as u8,
        };
        let s = match self.free.pop() {
            Some(s) => {
                self.slab[s as usize] = node;
                s
            }
            None => {
                self.slab.push(node);
                (self.slab.len() - 1) as u32
            }
        };
        self.map.insert(pba, s);
        self.push(s, PROB);
        self.inserts += 1;
    }

    /// Evict until at most `max` blocks are held (oldest probation run first). O(1) per evicted run; protected runs over
    /// half a capacity that shrank since go back to probation on the way (O(1) each).
    pub(crate) fn evict_to(&mut self, max: u64) {
        while self.blocks() > max {
            let s = if self.lists[PROT].blocks > self.cap / 2 || self.lists[PROB].head == NIL {
                self.lists[PROT].head
            } else {
                self.lists[PROB].head
            };
            debug_assert_ne!(s, NIL, "blocks held without list entries");
            if s == NIL {
                return;
            }
            if self.slab[s as usize].seg as usize == PROT && self.lists[PROB].head != NIL {
                // over the protected half: the oldest protected run gets one more round on probation
                self.unlink(s);
                self.push(s, PROB);
                self.demotions += 1;
                continue;
            }
            self.evictions += 1;
            self.drop_slot(s);
        }
    }

    /// Operator cache drop: remove every entry (no counter moves except the blocks held). Entries hold no reader pin, so
    /// nothing is waited for. Returns `(runs, blocks)` dropped.
    pub(crate) fn clear(&mut self) -> (u64, u64) {
        let dropped = (self.map.len() as u64, self.blocks());
        let slots: Vec<u32> = self.map.values().copied().collect();
        for s in slots {
            self.drop_slot(s);
        }
        dropped
    }

    /// The blocks of `frees` are freed (their txn is being submitted): no entry may outlive the free.
    pub(crate) fn forget(&mut self, frees: &[(u64, u32)]) {
        if self.map.is_empty() {
            return;
        }
        for &(pba, n) in frees {
            self.remove_range(pba, n);
        }
    }

    /// Drop every entry overlapping `[pba, pba+n)`.
    fn remove_range(&mut self, pba: u64, n: u32) {
        let end = pba + u64::from(n);
        loop {
            // entries are disjoint and sorted: the last one starting before `end` overlaps iff it ends after `pba`
            let Some((&k, &s)) = self.map.range(..end).next_back() else {
                return;
            };
            if k + u64::from(self.slab[s as usize].n) <= pba {
                return;
            }
            self.forgets += 1;
            self.drop_slot(s);
        }
    }

    /// Remove slot `s` from its list, the map and the slab (its bytes go now).
    fn drop_slot(&mut self, s: u32) {
        self.unlink(s);
        let e = &mut self.slab[s as usize];
        self.map.remove(&e.pba);
        e.data = Bytes::new();
        e.crcs = Box::default();
        self.free.push(s);
    }

    fn unlink(&mut self, s: u32) {
        let (prev, next, seg, n) = {
            let e = &self.slab[s as usize];
            (e.prev, e.next, e.seg as usize, e.n)
        };
        match prev {
            NIL => self.lists[seg].head = next,
            p => self.slab[p as usize].next = next,
        }
        match next {
            NIL => self.lists[seg].tail = prev,
            x => self.slab[x as usize].prev = prev,
        }
        self.lists[seg].blocks -= u64::from(n);
    }

    /// Append slot `s` (unlinked) at the newest end of list `seg`.
    fn push(&mut self, s: u32, seg: usize) {
        let tail = self.lists[seg].tail;
        let n = {
            let e = &mut self.slab[s as usize];
            e.prev = tail;
            e.next = NIL;
            e.seg = seg as u8;
            e.n
        };
        match tail {
            NIL => self.lists[seg].head = s,
            t => self.slab[t as usize].next = s,
        }
        self.lists[seg].tail = s;
        self.lists[seg].blocks += u64::from(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(pba: u64, n: u32, fill: u8) -> (Bytes, Vec<u32>) {
        (
            Bytes::from(vec![fill; n as usize * BLK]),
            (0..n).map(|i| pba as u32 + i).collect(),
        )
    }

    fn cache(cap: u64) -> DataCache {
        let mut c = DataCache::default();
        c.set_cap(cap);
        c
    }

    fn put(c: &mut DataCache, pba: u64, n: u32) {
        let (d, k) = run(pba, n, 0);
        c.put(pba, n, d, k);
    }

    /// The lists hold exactly the mapped entries and their block counts.
    fn check(c: &DataCache) {
        let mut seen = 0usize;
        for (seg, l) in c.lists.iter().enumerate() {
            let (mut s, mut prev, mut blocks) = (l.head, NIL, 0u64);
            while s != NIL {
                let e = &c.slab[s as usize];
                assert_eq!(e.seg as usize, seg);
                assert_eq!(e.prev, prev);
                assert_eq!(c.map.get(&e.pba), Some(&s));
                blocks += u64::from(e.n);
                seen += 1;
                (prev, s) = (s, e.next);
            }
            assert_eq!(l.tail, prev);
            assert_eq!(l.blocks, blocks);
        }
        assert_eq!(seen, c.map.len());
        assert_eq!(c.slab.len(), seen + c.free.len());
    }

    #[test]
    fn clear_drops_every_run_and_keeps_the_cache_usable() {
        let mut c = cache(64);
        for i in 0..5 {
            put(&mut c, i * 8, 4);
        }
        assert!(c.get(0, 4).is_some());
        assert_eq!(c.clear(), (5, 20));
        check(&c);
        assert_eq!((c.len(), c.blocks()), (0, 0));
        assert!(!c.covers(0, 4));
        put(&mut c, 0, 4);
        check(&c);
        assert!(c.get(0, 4).is_some());
    }

    #[test]
    fn hit_returns_the_sub_run_and_its_crcs() {
        let mut c = cache(16);
        let (d, k) = run(100, 4, 7);
        c.put(100, 4, d, k);
        assert!(c.covers(101, 2));
        assert!(!c.covers(103, 2));
        let (b, crcs) = c.get(101, 2).unwrap();
        assert_eq!(b.len(), 2 * BLK);
        assert_eq!(crcs, &[101, 102]);
        assert_eq!((c.hits, c.promotions), (1, 1));
        check(&c);
    }

    #[test]
    fn a_free_drops_every_overlapping_entry() {
        let mut c = cache(1 << 20);
        for p in [10u64, 20, 30] {
            put(&mut c, p, 4);
        }
        c.forget(&[(13, 8)]); // touches 10..14 and 20..24, not 30..34
        assert!(!c.covers(10, 1));
        assert!(!c.covers(20, 1));
        assert!(c.covers(30, 4));
        assert_eq!(c.blocks(), 4);
        assert_eq!(c.len(), 1);
        check(&c);
    }

    #[test]
    fn put_replaces_overlapping_runs() {
        let mut c = cache(1 << 20);
        let (d, k) = run(10, 4, 1);
        c.put(10, 4, d, k);
        let (d, k) = run(12, 4, 2);
        c.put(12, 4, d, k);
        assert_eq!(c.blocks(), 4);
        assert!(!c.covers(10, 1));
        assert_eq!(c.get(12, 1).unwrap().0[0], 2);
        check(&c);
    }

    #[test]
    fn eviction_takes_the_oldest_unread_run_first() {
        let mut c = cache(4);
        for p in 0..4u64 {
            put(&mut c, p * 10, 1);
        }
        c.get(0, 1).unwrap(); // the oldest was read again: protected
        c.evict_to(2);
        assert!(c.covers(0, 1));
        assert!(!c.covers(10, 1));
        assert!(!c.covers(20, 1));
        assert!(c.covers(30, 1));
        assert_eq!(c.evictions, 2);
        check(&c);
    }

    #[test]
    fn a_probe_keeps_its_run_past_the_next_eviction() {
        let mut c = cache(3);
        for p in 0..3u64 {
            put(&mut c, p * 10, 1);
        }
        assert!(c.touch(0, 1));
        c.evict_to(2);
        assert!(c.covers(0, 1));
        assert!(!c.covers(10, 1));
        assert_eq!(c.promotions, 0, "a probe is not a read");
        check(&c);
    }

    /// Scan resistance: a hot set (read twice) up to half the capacity survives a stream read once that is many times the
    /// capacity.
    #[test]
    fn a_stream_read_once_does_not_wipe_the_hot_set() {
        let cap = 1024u64;
        let mut c = cache(cap);
        let hot: Vec<u64> = (0..cap / 2 / 4).map(|i| 1_000_000 + i * 4).collect();
        for &p in &hot {
            c.evict_to(cap - 4);
            put(&mut c, p, 4);
            c.get(p, 4).unwrap();
        }
        for i in 0..20 * cap {
            c.evict_to(cap - 1);
            put(&mut c, i, 1);
        }
        assert!(c.blocks() <= cap);
        for &p in &hot {
            assert!(c.covers(p, 4), "hot run {p} evicted by the stream");
        }
        check(&c);
    }

    /// A hot set bigger than the protected half keeps the protected half; the rest competes on probation.
    #[test]
    fn the_protected_list_holds_at_most_half_the_capacity() {
        let cap = 64u64;
        let mut c = cache(cap);
        for p in 0..cap {
            c.evict_to(cap - 1);
            put(&mut c, p, 1);
            c.get(p, 1).unwrap();
        }
        for i in 0..4 * cap {
            c.evict_to(cap - 1);
            put(&mut c, 1000 + i, 1);
        }
        assert!(c.lists[PROT].blocks <= cap / 2);
        // the newest protected half survives
        assert!((cap / 2..cap).all(|p| c.covers(p, 1)));
        check(&c);
    }

    /// A shrinking capacity (the envelope gave memory to the metadata caches) evicts down to it, protected runs too.
    #[test]
    fn shrinking_the_capacity_evicts_down_to_it() {
        let mut c = cache(1 << 20);
        for p in 0..100u64 {
            put(&mut c, p * 2, 2);
            if p % 2 == 0 {
                c.get(p * 2, 2).unwrap();
            }
        }
        assert_eq!(c.blocks(), 200);
        c.set_cap(40);
        c.evict_to(40);
        assert!(c.blocks() <= 40);
        c.set_cap(0);
        c.evict_to(0);
        assert_eq!((c.blocks(), c.len()), (0, 0));
        check(&c);
    }

    /// Eviction cost bound: every list step is O(1) and paid by an operation: a promotion demotes at most the runs its own
    /// blocks push over the protected half, an eviction call on a full cache evicts one run per freed run and demotes
    /// nothing: no pass over the entries, also with 10^5 of them all read twice (the worst case of a CLOCK pass).
    #[test]
    fn eviction_cost_is_constant_per_run() {
        let cap = 100_000u64;
        let mut c = cache(cap);
        for p in 0..cap {
            let d = c.demotions;
            put(&mut c, p, 1);
            c.get(p, 1).unwrap();
            assert!(c.demotions - d <= 1);
            assert!(c.lists[PROT].blocks <= cap / 2);
        }
        assert!(c.demotions <= c.promotions);
        let (e, d) = (c.evictions, c.demotions);
        c.evict_to(cap - 1);
        assert_eq!((c.evictions - e, c.demotions - d), (1, 0));
        // steady state: one insert evicts one run
        for i in 0..cap {
            let (e, d) = (c.evictions, c.demotions);
            put(&mut c, 10 * cap + i, 1);
            c.evict_to(cap - 1);
            assert_eq!((c.evictions - e, c.demotions - d), (1, 0));
        }
        assert_eq!(c.blocks(), cap - 1);
        check(&c);
    }

    #[test]
    fn forgotten_and_recached_keys_reuse_their_slot() {
        let mut c = cache(1 << 20);
        for round in 0..1000u64 {
            let (d, k) = run(5, 1, round as u8);
            c.put(5, 1, d, k);
            c.forget(&[(5, 1)]);
        }
        assert_eq!(c.len(), 0);
        assert_eq!(c.slab.len(), 1);
        put(&mut c, 5, 1);
        c.evict_to(0);
        assert_eq!(c.blocks(), 0);
        check(&c);
    }
}
