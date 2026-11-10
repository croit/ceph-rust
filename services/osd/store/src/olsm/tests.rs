// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Engine tests: property test against a `BTreeMap` reference across flushes and merges (puts, point deletes,
//! range deletes, clears, paging with prefixes; deep enough for partitioned tiers, push-down and in-place merges, so
//! range tombstones and pages cross partition bounds), merge chunk move / drop, and sim-device crash cuts of run
//! writes and manifest commits of flushes, tier-0 merges, partition push-down and in-place merges (torn chunk and
//! torn meta detected by crc). Run: `cargo test -p store --features lab olsm`.

use super::job::{self, Plan};
use super::labdev::{MemBlocks, SimBlocks};
use super::manifest::{MergePick, Region, RunDesc};
use super::*;
use crate::BLK;
use crate::codec::{self, Dec, Enc};
use crate::dev::{CrashPolicy, SimConfig, SimDisk};
use crate::rng::Rng;
use proptest::prelude::*;
use std::collections::BTreeMap;

type Ref = BTreeMap<(u64, Vec<u8>), Vec<u8>>;

/// Engine + reference driven in lockstep.
pub(super) struct H<D: BlockSink + ChunkRead> {
    pub lsm: Olsm,
    pub dev: D,
    pub r: Ref,
    pub lsn: u64,
    pub freed: Vec<(u64, u32)>,
    pub moved: usize,
    pub dropped: usize,
    /// Partition merges that pushed down / stayed in place; deepest tier seen.
    pub pushed: usize,
    pub stayed: usize,
    pub depth: usize,
}

fn b(v: &[u8]) -> Bytes {
    Bytes::copy_from_slice(v)
}

impl<D: BlockSink + ChunkRead> H<D> {
    pub fn new(dev: D, n0: u64) -> Self {
        H {
            lsm: Olsm::new(Manifest::new(n0)),
            dev,
            r: Ref::new(),
            lsn: 0,
            freed: Vec::new(),
            moved: 0,
            dropped: 0,
            pushed: 0,
            stayed: 0,
            depth: 0,
        }
    }
    fn next(&mut self) -> u64 {
        self.lsn += 1;
        self.lsn
    }
    pub fn put(&mut self, id: u64, k: &[u8], v: &[u8]) {
        let l = self.next();
        self.lsm.active.put(l, id, b(k), b(v));
        self.r.insert((id, k.to_vec()), v.to_vec());
    }
    pub fn del(&mut self, id: u64, k: &[u8]) {
        let l = self.next();
        self.lsm.active.del(l, id, b(k));
        self.r.remove(&(id, k.to_vec()));
    }
    pub fn del_range(&mut self, id: u64, first: &[u8], end: Option<&[u8]>) {
        let l = self.next();
        self.lsm.active.del_range(l, id, b(first), end.map(b));
        let dead: Vec<_> = self
            .r
            .range((id, first.to_vec())..)
            .take_while(|((i, k), _)| *i == id && end.is_none_or(|e| &k[..] < e))
            .map(|(k, _)| k.clone())
            .collect();
        for k in dead {
            self.r.remove(&k);
        }
    }
    pub fn flush(&mut self) {
        if self.lsm.freeze().is_none() {
            return;
        }
        let f = self.lsm.frozen.clone().unwrap();
        let id = self.lsm.man.alloc_run_id();
        let (run, _) = job::flush(&f, id, &mut self.dev).unwrap().unwrap();
        self.lsm.flush_done(run);
    }
    /// Run merges until the policy picks none; checks the structure bounds of a point get afterwards.
    pub fn merges(&mut self) {
        self.run_merges(false)
    }
    /// [`Self::merges`] restricted to the size-tiered arm (no garbage-driven merge consumes a tombstone first).
    pub fn merges_sized(&mut self) {
        self.run_merges(true)
    }
    fn run_merges(&mut self, sized: bool) {
        while let Some(p) = if sized {
            self.lsm.man.pick_sized()
        } else {
            self.lsm.man.pick_merge(false)
        } {
            let (inputs, src) = (p.inputs.clone(), p.src_tier);
            let out = job::merge(p, &mut self.dev).unwrap();
            self.moved += out.moved;
            self.dropped += out.dropped;
            if src > 0 {
                if out.runs.iter().any(|r| r.place.tier == src) {
                    self.stayed += 1;
                } else {
                    self.pushed += 1;
                }
            }
            self.lsm
                .man
                .install_gc_prefix(&inputs, out.runs, out.residuals);
            self.freed.extend(out.freed);
        }
        let man = &self.lsm.man;
        self.depth = self.depth.max(man.tiers.len());
        assert!(man.top().len() < FAN);
        // a column merge may empty the tiers between its group and its deepest tier; the deepest tier holds data
        assert!(man.tiers.last().is_none_or(|p| !p.is_empty()));
        for parts in &man.tiers {
            for (i, p) in parts.iter().enumerate() {
                assert!(!p.runs.is_empty() && p.runs.len() < FAN);
                assert!(p.runs.windows(2).all(|w| w[0].id > w[1].id));
                if let Some(n) = parts.get(i + 1) {
                    assert!(
                        p.hi.as_ref().is_some_and(|h| *h <= n.lo),
                        "partitions overlap"
                    );
                }
                for r in &p.runs {
                    let (f, l) = r.span();
                    assert!(f.is_none_or(|f| p.holds(f.id, &f.key)));
                    assert!(l.is_none_or(|l| p.holds(l.id, &l.key)));
                    for x in &r.ranges {
                        assert!(p.holds(x.id, &x.first), "range outside its partition");
                    }
                }
            }
        }
    }
    /// Every object, every way of reading it, matches the reference.
    pub fn check(&mut self, rng: &mut Rng) {
        // Every randomly written object, a sample of the append-only ones, one never written.
        let ids: Vec<u64> = {
            let mut v: Vec<u64> = self.r.keys().map(|(i, _)| *i).collect();
            v.dedup();
            let seqs = v.iter().filter(|i| **i >= 100).count().max(1) as u64;
            v.retain(|i| *i < 100 || rng.below(seqs) < 6);
            v.push(9999);
            v
        };
        for id in ids {
            let want: Vec<(Vec<u8>, Vec<u8>)> = self
                .r
                .range((id, vec![])..)
                .take_while(|((i, _), _)| *i == id)
                .map(|((_, k), v)| (k.clone(), v.clone()))
                .collect();
            // Paging with random page sizes.
            let mut got = Vec::new();
            let mut after: Option<Vec<u8>> = None;
            loop {
                let max = 1 + rng.below(17) as usize;
                let (page, more) = self
                    .lsm
                    .list(&mut self.dev, id, after.as_deref(), b"", max)
                    .unwrap();
                assert!(page.len() <= max);
                got.extend(page.iter().map(|(k, v)| (k.to_vec(), v.to_vec())));
                if !more {
                    break;
                }
                assert_eq!(page.len(), max, "more with a short page");
                after = Some(page.last().unwrap().0.to_vec());
            }
            assert_eq!(got, want, "listing of object {id}");
            // Prefix listing.
            for p in [&b"a/"[..], b"k1", b"zz"] {
                let (page, _) = self
                    .lsm
                    .list(&mut self.dev, id, None, p, usize::MAX)
                    .unwrap();
                let w: Vec<_> = want
                    .iter()
                    .filter(|(k, _)| k.starts_with(p))
                    .cloned()
                    .collect();
                let g: Vec<_> = page.iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect();
                assert_eq!(g, w, "prefix {p:?} of object {id}");
            }
            // Gets of present and absent keys; by_keys.
            for (k, v) in want.iter().step_by(3) {
                assert_eq!(
                    self.lsm.get(&mut self.dev, id, k).unwrap().as_deref(),
                    Some(&v[..])
                );
            }
            for _ in 0..8 {
                let k = key(rng);
                let w = self.r.get(&(id, k.clone()));
                assert_eq!(
                    self.lsm.get(&mut self.dev, id, &k).unwrap().as_deref(),
                    w.map(|v| &v[..])
                );
            }
            let keys: Vec<Bytes> = (0..6).map(|_| b(&key(rng))).collect();
            let got = read::by_keys(&self.lsm.sources(), &mut self.dev, id, &keys).unwrap();
            let w: Vec<_> = keys
                .iter()
                .filter_map(|k| self.r.get(&(id, k.to_vec())).map(|v| (k.clone(), b(v))))
                .collect();
            assert_eq!(got, w);
        }
    }
}

fn key(rng: &mut Rng) -> Vec<u8> {
    let n = rng.below(400);
    match rng.below(4) {
        0 => format!("a/{n:03}").into_bytes(),
        1 => format!("k{n:03}").into_bytes(),
        _ => format!("m{:03}", n).into_bytes(),
    }
}

fn val(rng: &mut Rng) -> Vec<u8> {
    let n = match rng.below(10) {
        0 => rng.below(9000) as usize,
        1..=3 => 0,
        _ => rng.below(300) as usize,
    };
    let mut v = vec![0u8; n];
    rng.fill(&mut v);
    v
}

/// Merge every tier-0 run into tier 1 at once (test stand-in for a policy pick with fewer than `FAN` runs).
pub(super) fn pick_top(man: &mut Manifest, bottom: bool) -> MergePick {
    let inputs = man.top().to_vec();
    let first_id = man.next_run_id;
    man.next_run_id += 2 * FAN as u64 + 2;
    let input: u64 = inputs.iter().map(|r| r.data_bytes()).sum();
    MergePick {
        inputs,
        bottom,
        src_tier: 0,
        dst_tier: 1,
        regions: vec![Region {
            lo: Gk::MIN,
            hi: None,
            part: None,
        }],
        cut: input.div_ceil(FAN as u64).max(1),
        stay: false,
        first_id,
        end_id: man.next_run_id,
        gc: false,
    }
}

/// `mem`: memtable bytes per flush (small = many flushes = deep partitioned tiers).
fn random_run(seed: u64, ops: usize, mem: usize) -> H<MemBlocks> {
    let mut rng = Rng::new(seed);
    let mut h = H::new(MemBlocks::new(), 24 << 10);
    let mut nobj = 2u64;
    let mut seq = 0u64;
    for i in 0..ops {
        if rng.below(200) == 0 {
            nobj += 1;
        }
        let id = rng.below(nobj);
        match rng.below(100) {
            0..=54 => {
                let (k, v) = (key(&mut rng), val(&mut rng));
                h.put(id, &k, &v);
            }
            55..=74 => {
                let k = key(&mut rng);
                h.del(id, &k);
            }
            75..=81 => {
                let (mut a, mut z) = (key(&mut rng), key(&mut rng));
                if a > z {
                    std::mem::swap(&mut a, &mut z);
                }
                let end = (rng.below(5) != 0).then_some(&z[..]);
                h.del_range(id, &a, end);
            }
            82..=83 => h.del_range(id, b"", None),
            _ => {
                // Append-ordered batch into a fresh object (disjoint chunks: move path).
                let id = 100 + nobj + seq / 64;
                for _ in 0..32 {
                    seq += 1;
                    let mut v = vec![0u8; 1500];
                    rng.fill(&mut v);
                    h.put(id, format!("s{seq:08}").as_bytes(), &v);
                }
            }
        }
        if h.lsm.active.bytes() > mem || rng.below(300) == 0 {
            h.flush();
            h.merges();
            if rng.below(8) == 0 {
                h.check(&mut rng);
            }
        }
        if i % 1999 == 0 {
            h.check(&mut rng);
        }
    }
    h.check(&mut rng);
    h.flush();
    h.merges();
    h.check(&mut rng);
    h
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]
    #[test]
    fn olsm_matches_btreemap(seed in any::<u64>(), small in any::<bool>()) {
        random_run(seed, 3000, if small { 4 << 10 } else { 40 << 10 });
    }
}

#[test]
fn olsm_long_run_moves_chunks() {
    let h = random_run(7, 10_000, 40 << 10);
    println!(
        "moved {} dropped {} runs {}",
        h.moved,
        h.dropped,
        h.lsm.man.runs().count()
    );
    assert!(h.moved > 0, "moved {}", h.moved);
}

#[test]
fn olsm_deep_tiers_push_down_and_stay_in_place() {
    let h = random_run(11, 12_000, 3 << 10);
    println!(
        "depth {} pushed {} stayed {} runs {} moved {}",
        h.depth,
        h.pushed,
        h.stayed,
        h.lsm.man.runs().count(),
        h.moved
    );
    assert!(h.depth >= 2, "depth {}", h.depth);
    assert!(
        h.pushed > 0 && h.stayed > 0,
        "pushed {} stayed {}",
        h.pushed,
        h.stayed
    );
}

#[test]
fn range_tombstone_spans_partitions() {
    // n0 = 128 KiB: the tier-0 merge of ~1 MB cuts flush-sized partitions
    let mut h = H::new(MemBlocks::new(), 128 << 10);
    let mut rng = Rng::new(5);
    // Eight overlapping flushes of one object: the tier-0 merge cuts tier 1 into several partitions.
    for r in 0..FAN as u32 {
        for i in 0..400u32 {
            h.put(1, format!("k{:05}", i * 8 + r).as_bytes(), &[r as u8; 300]);
        }
        h.flush();
    }
    h.merges();
    let parts = h.lsm.man.tiers[0].len();
    assert!(parts >= 4, "partitions {parts}");
    // One range over most partitions, a clear of another object, puts after the range in the same flush.
    h.del_range(1, b"k00100", Some(b"k03000"));
    h.put(1, b"k00200", b"new");
    h.put(2, b"x", b"y");
    h.del_range(2, b"", None);
    h.check(&mut rng);
    // size-tiered push-down cuts the range at the partition bounds (a GC merge would apply and drop it at the bottom)
    for _ in 0..FAN {
        h.put(3, b"z", b"z");
        h.flush();
    }
    h.merges_sized();
    let clipped = h.lsm.man.tiers[0]
        .iter()
        .filter(|p| p.runs[0].ranges.iter().any(|x| x.id == 1))
        .count();
    assert!(clipped >= 3, "range clipped into {clipped} partitions");
    h.check(&mut rng);
    assert_eq!(h.lsm.get(&mut h.dev, 1, b"k00150").unwrap(), None);
    assert_eq!(
        h.lsm.get(&mut h.dev, 1, b"k00200").unwrap().as_deref(),
        Some(&b"new"[..])
    );
    let (page, more) = h.lsm.list(&mut h.dev, 1, Some(b"k00099"), b"", 3).unwrap();
    assert!(more);
    let keys: Vec<&[u8]> = page.iter().map(|(k, _)| &k[..]).collect();
    assert_eq!(keys, [&b"k00200"[..], b"k03000", b"k03001"]);
    // the full policy (GC merges apply the shadowed partitions) answers the same
    h.merges();
    h.check(&mut rng);
    assert_eq!(h.lsm.get(&mut h.dev, 1, b"k00150").unwrap(), None);
    let (page, more) = h.lsm.list(&mut h.dev, 1, Some(b"k00099"), b"", 3).unwrap();
    assert!(more);
    let keys: Vec<&[u8]> = page.iter().map(|(k, _)| &k[..]).collect();
    assert_eq!(keys, [&b"k00200"[..], b"k03000", b"k03001"]);
}

#[test]
fn range_tombstones_shadow_older_runs_and_newer_puts_survive() {
    let mut h = H::new(MemBlocks::new(), 1 << 20);
    for i in 0..100u32 {
        h.put(1, format!("k{i:03}").as_bytes(), b"old");
        h.put(2, format!("k{i:03}").as_bytes(), b"two");
    }
    h.flush();
    h.del_range(1, b"k010", Some(b"k020"));
    h.put(1, b"k015", b"new");
    h.flush();
    h.del_range(2, b"", None);
    h.put(2, b"k050", b"after-clear");
    let mut rng = Rng::new(1);
    h.check(&mut rng);
    assert_eq!(h.lsm.get(&mut h.dev, 1, b"k012").unwrap(), None);
    assert_eq!(
        h.lsm.get(&mut h.dev, 1, b"k015").unwrap().as_deref(),
        Some(&b"new"[..])
    );
    h.flush();
    h.check(&mut rng);
    // Merge everything into the bottom: tombstones vanish, results stay.
    let p = pick_top(&mut h.lsm.man, true);
    let inputs = p.inputs.clone();
    let out = job::merge(p, &mut h.dev).unwrap();
    assert!(out.runs.iter().all(|r| r.tombs == 0 && r.ranges.is_empty()));
    assert_eq!(
        out.runs.iter().map(|r| r.entries).sum::<u64>(),
        100 - 10 + 1 + 1
    );
    h.lsm
        .man
        .install_gc_prefix(&inputs, out.runs, out.residuals);
    h.check(&mut rng);
}

#[test]
fn merge_moves_disjoint_chunks_and_drops_cleared_ones() {
    // Eight runs, each a fresh object with ~4 full chunks: all chunks disjoint. `clear`: a ninth run clears object 3.
    let setup = |clear: bool| {
        let mut h = H::new(MemBlocks::new(), 1 << 30);
        let val = vec![7u8; 1000];
        for r in 0..8u64 {
            for i in 0..260u32 {
                h.put(r, format!("k{i:05}").as_bytes(), &val);
            }
            h.flush();
        }
        if clear {
            h.del_range(3, b"", None);
            h.flush();
        }
        h
    };
    let mut h = setup(false);
    let plans = job::plan(h.lsm.man.top(), false, &[]);
    let full = plans.iter().flatten().filter(|p| **p == Plan::Move).count();
    assert!(full >= 8 * 3, "{plans:?}");
    let before = h.dev.written;
    let p = pick_top(&mut h.lsm.man, false);
    let inputs = p.inputs.clone();
    let out = job::merge(p, &mut h.dev).unwrap();
    assert_eq!(out.moved, full);
    assert!(out.runs.len() > 1, "output cut into partitions");
    // Only the short tail chunks and the metas were written.
    assert!(
        h.dev.written - before < (8 * 2 * CHUNK_TARGET) as u64,
        "{}",
        h.dev.written - before
    );
    h.lsm
        .man
        .install_gc_prefix(&inputs, out.runs, out.residuals);
    let mut rng = Rng::new(2);
    h.check(&mut rng);
    // The clearing run is newer: the merge drops object 3's chunks unread.
    let mut h = setup(true);
    let read_before = h.dev.read;
    let p = pick_top(&mut h.lsm.man, true);
    let inputs = p.inputs.clone();
    let out = job::merge(p, &mut h.dev).unwrap();
    assert!(out.dropped >= 3, "{out:?}");
    assert!(h.dev.read - read_before < (2 * CHUNK_TARGET) as u64);
    h.lsm
        .man
        .install_gc_prefix(&inputs, out.runs, out.residuals);
    h.check(&mut rng);
}

#[test]
fn list_page_is_seeked_not_rescanned() {
    let mut h = H::new(MemBlocks::new(), 1 << 30);
    for r in 0..4u32 {
        for i in 0..2000u32 {
            h.put(1, format!("k{:06}", i * 4 + r).as_bytes(), &[1u8; 200]);
        }
        h.flush();
    }
    let before = h.dev.read;
    let (page, more) = h
        .lsm
        .list(&mut h.dev, 1, Some(b"k004000"), b"", 16)
        .unwrap();
    assert!(more);
    assert_eq!(&page[0].0[..], b"k004001");
    // One chunk per run (plus at most one boundary chunk each), not the object.
    assert!(h.dev.read - before <= 4 * 2 * (CHUNK_TARGET as u64 + BLK as u64));
}

/// Object ids are sparse (the object layer allocates `lsn << 12 | seq`): the walk over the ids the runs hold
/// ([`read::next_run_id`], the object-layer check's candidate list) yields exactly the distinct ids of the run entries
/// (values and point tombstones), also where one chunk spans thousands of absent ids, and from every start, in a gap or
/// on an id.
#[test]
fn next_run_id_walks_exactly_the_ids_of_the_runs() {
    let mut h = H::new(MemBlocks::new(), 1 << 30);
    let mut rng = Rng::new(17);
    for round in 0..6u64 {
        for _ in 0..300 {
            let id = (1 + rng.below(400)) << 12 | (1 + rng.below(3));
            let k = key(&mut rng);
            if rng.below(5) == 0 {
                h.del(id, &k);
            } else {
                h.put(id, &k, &[round as u8; 40]);
            }
        }
        h.flush();
        if round % 2 == 1 {
            h.merges();
        }
    }
    let mut want = std::collections::BTreeSet::new();
    let mut wide = false;
    let src = h.lsm.sources();
    for r in src
        .top
        .iter()
        .chain(src.tiers.iter().flatten().flat_map(|p| &p.runs))
    {
        for (i, f) in r.fences.iter().enumerate() {
            wide |= f.last_id - f.first_id > 1 << 12;
            let c = run::load_chunk(&mut h.dev, r, i).unwrap();
            want.extend((0..c.len()).map(|e| c.id(e)));
        }
    }
    assert!(wide, "no chunk spans a gap of absent ids");
    let mut walk = |from| read::next_run_id(&h.lsm.sources(), &mut h.dev, from).unwrap();
    let (mut got, mut from) = (Vec::new(), 0);
    while let Some(id) = walk(from) {
        got.push(id);
        from = id + 1;
    }
    assert_eq!(got, want.iter().copied().collect::<Vec<_>>());
    for _ in 0..300 {
        let from = rng.below(402 << 12);
        assert_eq!(
            walk(from),
            want.range(from..).next().copied(),
            "from {from}"
        );
    }
}

/// Point gets where entries straddle page ends: keys sharing their first 8 bytes (the packed key ties, the get reads
/// the page span), distinct short keys (decided from the packed key), absent keys between them, values up to a few
/// pages. Every present key is found with one read; an absent key never needs more than one.
#[test]
fn point_get_reads_one_span_across_straddling_entries() {
    let mut h = H::new(MemBlocks::new(), 1 << 30);
    let mut rng = Rng::new(9);
    let mut want = Vec::new();
    for i in 0..3000u32 {
        let k = match i % 3 {
            0 => format!("bucket.idx/{i:06}"),
            1 => format!("{i:05}"),
            _ => format!("bucket.idx/{i:06}/long-suffix-to-straddle"),
        };
        let n = match i % 7 {
            0 => 5000 + rng.below(4000) as usize,
            _ => 100 + rng.below(400) as usize,
        };
        let mut v = vec![0u8; n];
        rng.fill(&mut v);
        h.put(1, k.as_bytes(), &v);
        want.push((k, v));
    }
    h.flush();
    let run = h.lsm.man.runs().next().expect("one run").clone();
    for (k, v) in &want {
        let r0 = h.dev.reads;
        let got = read::probe_run(
            &mut h.dev,
            &run,
            1,
            k.as_bytes(),
            bloom::hash(1, k.as_bytes()),
        );
        assert!(
            matches!(got, Ok(mem::Probe::Hit(Some(ref g))) if g[..] == v[..]),
            "{k}"
        );
        assert_eq!(h.dev.reads - r0, 1, "{k}: one read");
    }
    for (k, _) in &want {
        let absent = format!("{k}~");
        let r0 = h.dev.reads;
        assert_eq!(h.lsm.get(&mut h.dev, 1, absent.as_bytes()).unwrap(), None);
        assert!(h.dev.reads - r0 <= 1, "{absent}");
    }
}

#[test]
fn chunk_and_meta_corruption_is_detected() {
    let mut h = H::new(MemBlocks::new(), 1 << 30);
    for i in 0..500u32 {
        h.put(1, format!("k{i:04}").as_bytes(), &[3u8; 300]);
    }
    h.flush();
    let run = h.lsm.man.top()[0].clone();
    // Flip one byte of a page in a copy of the device: chunk loads and point gets of that page fail.
    let mut d = MemBlocks::new();
    for (i, g) in run.fences.iter().enumerate() {
        let mut data = h.dev.read(g.blk, g.nblk).unwrap().to_vec();
        if i == 1 {
            data[BLK + 100] ^= 1;
        }
        d.write(g.blk, data, &[]).unwrap();
    }
    assert!(matches!(
        run::load_chunk(&mut d, &run, 1),
        Err(StoreError::Corrupt(_))
    ));
    let s = run.chunk_starts(1)[1].clone();
    assert!(matches!(
        run::get_in_chunk(&mut d, &run, 1, s.id, &s.key),
        Err(StoreError::Corrupt(_))
    ));
    assert!(run::load_chunk(&mut d, &run, 0).is_ok());
    let meta = h.dev.read(run.meta_blk, run.meta_nblk).unwrap();
    let mut bad = meta.to_vec();
    bad[40] ^= 0x10;
    let mut d = MemBlocks::new();
    let blk = d.alloc(run.meta_nblk).unwrap();
    d.write(blk, bad, &[]).unwrap();
    assert!(matches!(
        run::load_meta(&mut d, blk, run.meta_nblk, run.meta_crc),
        Err(StoreError::Corrupt(_))
    ));
}

// ------------------------------------------------------------------ sim crash cuts

const MAN_BLK: u64 = 0;
/// Blocks reserved for the test manifest; run blocks start after it.
const MAN_BLKS: u32 = 64;
const SIM_BYTES: u64 = 256 << 20;

/// Test stand-in for the manifest txn (atomic as the real record-only txn): two slots of `MAN_BLKS / 2` blocks, each
/// `len u32 | crc u32 | gen u64 | flushed_lsn u64 | n u32 | (len u16 | desc)*`; a write goes to the slot not holding
/// the newest valid copy, a read takes the newest valid one, so a torn write leaves the previous manifest.
const SLOT_BLKS: u32 = MAN_BLKS / 2;

fn manifest_slot(b: &[u8]) -> Option<(u64, Vec<u8>)> {
    let mut d = Dec::new(b);
    let (len, crc) = (d.u32()? as usize, d.u32()?);
    let p = d.bytes(len)?;
    if len < 8 || codec::crc(p) != crc {
        return None;
    }
    Some((Dec::new(p).u64()?, p[8..].to_vec()))
}

fn newest_slot(s: &mut SimBlocks) -> Result<Option<(u32, u64, Vec<u8>)>, StoreError> {
    let mut best = None;
    for i in 0..2 {
        let b = s.read(MAN_BLK + (i * SLOT_BLKS) as u64, SLOT_BLKS)?;
        if let Some((g, p)) = manifest_slot(&b)
            && best.as_ref().is_none_or(|x: &(u32, u64, Vec<u8>)| g > x.1)
        {
            best = Some((i, g, p));
        }
    }
    Ok(best)
}

fn write_manifest(s: &mut SimBlocks, man: &Manifest) -> Result<(), StoreError> {
    let (slot, generation) = newest_slot(s)?.map_or((0, 1), |(i, g, _)| (1 - i, g + 1));
    let mut p = Enc::new();
    p.u64(generation)
        .u64(man.flushed_lsn)
        .u32(man.runs().count() as u32);
    for r in man.runs() {
        let d = RunDesc::of(r).encode();
        p.u16(d.len() as u16).bytes(&d);
    }
    let mut e = Enc::new();
    e.u32(p.b.len() as u32).u32(codec::crc(&p.b)).bytes(&p.b);
    assert!(
        e.b.len() <= SLOT_BLKS as usize * BLK,
        "test manifest slot too small"
    );
    e.pad_to(SLOT_BLKS as usize * BLK);
    s.write(MAN_BLK + (slot * SLOT_BLKS) as u64, e.b, &[])?;
    s.sync()
}

fn read_manifest(s: &mut SimBlocks, n0: u64) -> Option<Manifest> {
    let (_, _, p) = newest_slot(s).unwrap()?;
    let mut d = Dec::new(&p);
    let flushed = d.u64()?;
    let n = d.u32()?;
    let recs: Vec<RunDesc> = (0..n)
        .map(|_| {
            let l = d.u16().unwrap() as usize;
            RunDesc::decode(d.bytes(l).unwrap()).unwrap()
        })
        .collect();
    Some(Manifest::mount(n0, flushed, &recs, s).expect("a committed manifest must mount"))
}

fn contents(
    lsm: &Olsm,
    rd: &mut impl ChunkRead,
    ids: &[u64],
) -> Result<Vec<(u64, Bytes, Bytes)>, StoreError> {
    let mut v = Vec::new();
    for &id in ids {
        for (k, val) in lsm.list(rd, id, None, b"", usize::MAX)?.0 {
            v.push((id, k, val));
        }
    }
    Ok(v)
}

/// Fill `h` with one memtable worth of data per call (deterministic).
fn fill(lsm: &mut Olsm, lsn: &mut u64, round: u64) {
    fill_keys(lsm, lsn, round, 600)
}

/// [`fill`] over `keys` keys per object (a large key space grows the data, so partitions outgrow the stay class).
fn fill_keys(lsm: &mut Olsm, lsn: &mut u64, round: u64, keys: u64) {
    let mut rng = Rng::new(round);
    for i in 0..400u64 {
        *lsn += 1;
        let id = i % 3;
        let mut v = vec![0u8; rng.below(700) as usize];
        rng.fill(&mut v);
        lsm.active.put(
            *lsn,
            id,
            b(format!("k{:04}", rng.below(keys)).as_bytes()),
            Bytes::from(v),
        );
    }
    *lsn += 1;
    lsm.active
        .del_range(*lsn, 2, b(b"k0100"), Some(b(b"k0200")));
}

/// Committed state of a crash phase: `rounds` flushes, tier-0 merges whenever tier 0 is full (`tail`: also after
/// the last flush), manifest written.
fn crash_base(s: &mut SimBlocks, n0: u64, rounds: u64, tail: bool, keys: u64) -> (Olsm, u64) {
    let mut lsm = Olsm::new(Manifest::new(n0));
    let mut lsn = 0;
    for round in 0..rounds {
        fill_keys(&mut lsm, &mut lsn, round, keys);
        lsm.freeze();
        let f = lsm.frozen.clone().unwrap();
        let id = lsm.man.alloc_run_id();
        let (run, _) = job::flush(&f, id, s).unwrap().unwrap();
        lsm.flush_done(run);
        while lsm.man.top().len() >= FAN && (tail || round + 1 < rounds) {
            // the crash matrix below cuts a tier-0 merge, a push-down and an in-place merge at every IO event: it needs
            // that merge type, so it picks the size-tiered arm of the one pick function (a GC pick moves the same data
            // on another path)
            let p = lsm.man.pick_sized().unwrap();
            assert_eq!(p.src_tier, 0);
            let inputs = p.inputs.clone();
            let out = job::merge(p, s).unwrap();
            lsm.man.install_gc_prefix(&inputs, out.runs, out.residuals);
        }
    }
    write_manifest(s, &lsm.man).unwrap();
    (lsm, lsn)
}

/// Phase "column": more flushes over the base (each with point deletes over older data), merges by the policy,
/// until it picks a column merge (inputs from more than one tier, adr 0610 am. 6); the manifest before it committed.
fn column_base(s: &mut SimBlocks, lsm: &mut Olsm, lsn: &mut u64) -> MergePick {
    for round in 200..400 {
        while let Some(p) = lsm.man.pick_merge(false) {
            if p.inputs.iter().any(|r| r.place.tier != p.src_tier) {
                write_manifest(s, &lsm.man).unwrap();
                return p;
            }
            let inputs = p.inputs.clone();
            let out = job::merge(p, s).unwrap();
            lsm.man.install_gc_prefix(&inputs, out.runs, out.residuals);
        }
        fill(lsm, lsn, round);
        // point deletes over older data: tombstones whose shadowed puts sit in deeper tiers
        for i in 0..300u64 {
            *lsn += 1;
            lsm.active.del(*lsn, 1, b(format!("k{i:04}").as_bytes()));
        }
        lsm.freeze();
        let f = lsm.frozen.clone().unwrap();
        let id = lsm.man.alloc_run_id();
        let (run, _) = job::flush(&f, id, s).unwrap().unwrap();
        lsm.flush_done(run);
    }
    panic!("no column merge picked");
}

/// Crash at every IO event of a flush, a tier-0 merge, a partition push-down merge, a partition in-place merge and a
/// column merge, each with its manifest commit: after remount the state is exactly the old or the new committed one and every
/// chunk of every committed run verifies.
#[test]
fn olsm_crash_cuts_of_flush_merge_and_manifest() {
    let ids = [0u64, 1, 2];
    let cfg = SimConfig::new(SIM_BYTES);
    let end = SIM_BYTES / BLK as u64;
    // (phase, n0, flushes before the cut job)
    for (phase, n0, rounds) in [
        ("flush", 1, 8),
        ("merge", 1, 8),
        ("push", 1, 8 * FAN as u64),
        ("stay", 1 << 40, 8 * FAN as u64),
        ("column", 1, 8 * FAN as u64),
    ] {
        let mut k = 1u64;
        loop {
            let disk = SimDisk::new(cfg.clone());
            let mut s = SimBlocks::new(disk.queue(), MAN_BLKS as u64, end);
            // push: 4x the key space, so the partitions grow above the stay class (adr 0610 am. 6)
            let keys = if phase == "push" { 1 << 20 } else { 600 };
            let (mut lsm, mut lsn) = crash_base(&mut s, n0, rounds, phase != "merge", keys);
            let mut col = (phase == "column").then(|| column_base(&mut s, &mut lsm, &mut lsn));
            let old = contents(&lsm, &mut s, &ids).unwrap();
            if phase == "flush" {
                fill(&mut lsm, &mut lsn, 100);
            }
            // New state: the memtable (if any) over the runs; a merge does not change contents.
            let expect_new = contents(&lsm, &mut s, &ids).unwrap();
            let mut new_lsm = lsm;
            disk.arm_crash(disk.events() + k);
            let res = (|| -> Result<(), StoreError> {
                if phase == "flush" {
                    new_lsm.freeze();
                    let f = new_lsm.frozen.clone().unwrap();
                    let id = new_lsm.man.alloc_run_id();
                    let (run, _) = job::flush(&f, id, &mut s)?.unwrap();
                    new_lsm.flush_done(run);
                } else if let Some(p) = col.take() {
                    let (inputs, dst) = (p.inputs.clone(), p.dst_tier);
                    assert!(p.bottom && dst > p.src_tier, "{p:?}");
                    let out = job::merge(p, &mut s)?;
                    assert!(out.runs.iter().all(|r| r.place.tier == dst));
                    new_lsm
                        .man
                        .install_gc_prefix(&inputs, out.runs, out.residuals);
                } else {
                    // same reason as `crash_base`: this cut must be the phase's merge type
                    let p = new_lsm.man.pick_sized().expect("a merge is due");
                    assert_eq!(p.src_tier, (phase != "merge") as u32, "{phase}");
                    let inputs = p.inputs.clone();
                    let out = job::merge(p, &mut s)?;
                    let tier = (phase != "merge") as u32 + (phase != "stay") as u32;
                    assert!(out.runs.iter().all(|r| r.place.tier == tier), "{phase}");
                    new_lsm
                        .man
                        .install_gc_prefix(&inputs, out.runs, out.residuals);
                }
                write_manifest(&mut s, &new_lsm.man)
            })();
            let crashed = disk.crashed();
            assert!(res.is_ok() || crashed, "{res:?}");
            let img = if crashed {
                disk.crash_image(CrashPolicy::MIXED)
            } else {
                disk.image()
            };
            let disk2 = SimDisk::from_image(&img, cfg.clone());
            let mut s2 = SimBlocks::new(disk2.queue(), MAN_BLKS as u64, end);
            let man = read_manifest(&mut s2, n0)
                .unwrap_or_else(|| panic!("{phase} k {k}: a manifest is always committed"));
            let lsm2 = Olsm::new(man);
            let got = contents(&lsm2, &mut s2, &ids).expect("every committed run verifies");
            assert!(
                got == old || got == expect_new,
                "{phase} cut {k}: neither old nor new state"
            );
            if !crashed {
                assert_eq!(got, expect_new);
                break;
            }
            k += 1;
        }
        assert!(k > 3, "{phase}: crash matrix too short ({k})");
    }
}

/// Merge demand of FIFO set/rm on one hot object (the lab cell "ls", adr 0610 am. 6): `clients` key ranges of one
/// object filled to `live` keys, then rounds in which every client puts its 256 next keys or removes its 256 oldest
/// (alternating). A flush at `n0`; after each flush the merges the policy picks run to quiescence (a merge slot that
/// keeps up: the counts are what the policy asks for).
#[derive(Debug, Default)]
pub(super) struct FifoSim {
    pub flushes: u64,
    pub merges: u64,
    pub gc_merges: u64,
    pub max_merges_per_flush: u64,
    /// Partitions and candidates the selection looked at, and its calls.
    pub visits: u64,
    pub picks: u64,
    pub max_parts: usize,
    /// Key + value bytes put / run bytes written in the churn phase.
    pub user_bytes: u64,
    pub written: u64,
    /// Highest run blocks after a flush's merges, and the live key + value bytes at the end.
    pub peak_bytes: u64,
    pub live_bytes: u64,
}

impl FifoSim {
    pub fn per_flush(&self) -> f64 {
        self.merges as f64 / self.flushes as f64
    }
    pub fn wa(&self) -> f64 {
        self.written as f64 / self.user_bytes as f64
    }
    pub fn peak(&self) -> f64 {
        self.peak_bytes as f64 / self.live_bytes as f64
    }
}

pub(super) fn fifo_sim(n0: u64, clients: u64, live: u64, vlen: usize, rounds: u64) -> FifoSim {
    let mut h = H::new(MemBlocks::new(), n0);
    let mut st = FifoSim::default();
    let key = |c: u64, i: u64| format!("c{c:03}-{i:010}").into_bytes();
    let v = vec![7u8; vlen];
    let kv = (key(0, 0).len() + vlen) as u64;
    let flush = |h: &mut H<MemBlocks>, st: &mut FifoSim| {
        h.flush();
        st.flushes += 1;
        let mut n = 0;
        loop {
            let v0 = h.lsm.man.pick_visits();
            let p = h.lsm.man.pick_merge(false);
            st.visits += h.lsm.man.pick_visits() - v0;
            st.picks += 1;
            let Some(p) = p else { break };
            n += 1;
            st.gc_merges += p.gc as u64;
            let inputs = p.inputs.clone();
            let out = job::merge(p, &mut h.dev).unwrap();
            h.lsm
                .man
                .install_gc_prefix(&inputs, out.runs, out.residuals);
            for (b, nb) in out.freed {
                h.dev.free(b, nb);
            }
        }
        st.merges += n;
        st.max_merges_per_flush = st.max_merges_per_flush.max(n);
        st.max_parts = st
            .max_parts
            .max(h.lsm.man.tiers.iter().map(|t| t.len()).sum());
        st.peak_bytes = st.peak_bytes.max(h.dev.live_blocks * BLK as u64);
        // quiescent: the shard's garbage share is below the routine target (adr 0610 am. 5)
        let (sp, (num, den)) = (h.lsm.man.space(), manifest::GC_AMP);
        let g = h.lsm.man.garbage(&sp);
        assert!(
            g * num < sp.bytes * (num - den) || g == 0,
            "garbage {g} of {sp:?}"
        );
    };
    // per client: next key to put, oldest key present
    let mut cl: Vec<(u64, u64)> = vec![(0, 0); clients as usize];
    for i in 0..live {
        let c = &mut cl[(i % clients) as usize];
        h.put(1, &key(i % clients, c.0), &v);
        c.0 += 1;
        if h.lsm.active.bytes() as u64 >= n0 {
            flush(&mut h, &mut st);
        }
    }
    flush(&mut h, &mut st);
    let w0 = h.dev.written;
    st = FifoSim {
        max_parts: st.max_parts,
        peak_bytes: st.peak_bytes,
        ..FifoSim::default()
    };
    for r in 0..rounds {
        for (c, (next, old)) in cl.iter_mut().enumerate() {
            for _ in 0..256 {
                if r % 2 == 0 {
                    h.put(1, &key(c as u64, *next), &v);
                    st.user_bytes += kv;
                    *next += 1;
                } else {
                    h.del(1, &key(c as u64, *old));
                    *old += 1;
                }
            }
            if h.lsm.active.bytes() as u64 >= n0 {
                flush(&mut h, &mut st);
            }
        }
    }
    st.written = h.dev.written - w0;
    st.live_bytes = cl.iter().map(|(n, o)| n - o).sum::<u64>() * kv;
    let mut rng = Rng::new(1);
    h.check(&mut rng);
    st
}

/// The merge storm of the hot-object cell (adr 0610 am. 6): before, every flush's tombstones made its group look
/// mostly garbage, push-downs reclaimed nothing and cut ever smaller partitions (lab: 1000s of merges per flush, pick
/// scans over 100k runs). Now a merge is picked only where it reclaims or bounds the read cost: merges per flush,
/// the selection's work per pick and the partitions stay bounded, and every quiescent point is below the space
/// target. Release numbers: doc/perf/olsm-pick-20261028.md.
#[test]
fn fifo_hot_object_merges_stay_bounded() {
    // 64 clients, 25k keys of 115 B, n0 = 512 KiB (lab shape: live a few n0)
    let st = fifo_sim(512 << 10, 64, 25_000, 100, 64);
    eprintln!(
        "fifo: merges/flush {:.2} (max {}) gc {} visits/pick {:.1} parts {} WA {:.2} peak/live {:.2} {st:?}",
        st.per_flush(),
        st.max_merges_per_flush,
        st.gc_merges,
        st.visits as f64 / st.picks as f64,
        st.max_parts,
        st.wa(),
        st.peak()
    );
    assert!(st.flushes >= 16, "{st:?}");
    assert!(st.per_flush() <= 2.0, "merges per flush {st:?}");
    assert!(
        st.max_parts as u64 <= 4 * st.live_bytes / (512 << 10) + 8,
        "partitions {st:?}"
    );
    assert!(
        st.visits <= 4 * st.picks * st.max_parts as u64,
        "pick work {st:?}"
    );
    assert!(st.wa() <= 7.0, "WA {st:?}");
}

/// An overwrite replaces the key handle too: the old key slice (of an older WAL record) is released, and the RAM
/// charged stays that of one entry.
#[test]
fn memtable_overwrite_releases_old_key_buffer() {
    let mut m = Memtable::new();
    let old = Bytes::from(b"key1-old-record".to_vec());
    m.put(1, 7, old.slice(..4), b(b"v1"));
    let one = m.bytes();
    let new = Bytes::from(b"key1-new-record".to_vec());
    m.put(2, 7, new.slice(..4), b(b"v2"));
    assert_eq!(m.entries(), 1);
    assert_eq!(m.bytes(), one);
    assert!(
        old.is_unique(),
        "the overwritten entry still pins the old key buffer"
    );
    assert_eq!(m.probe(7, b"key1"), mem::Probe::Hit(Some(b(b"v2"))));
}

/// Emptiness is content, not lsn: ops applied at lsn 0 (S7 upgrade batch on a fresh store) make the memtable non-empty.
#[test]
fn memtable_with_ops_at_lsn_zero_is_not_empty() {
    let mut m = Memtable::new();
    assert!(m.is_empty());
    m.put(0, 7, b(b"k"), b(b"v"));
    assert!(!m.is_empty());
    m.put(3, 8, b(b"k"), b(b"v"));
    assert_eq!((m.lsn_lo(), m.lsn_hi()), (0, 3));
    let mut r = Memtable::new();
    r.del_range(0, 7, Bytes::new(), None);
    assert!(!r.is_empty(), "a range tombstone is content");
}

/// An event-driven reader: misses queue each range once; a test round explicitly lands them.
struct ScanReader<'a> {
    dev: &'a mut MemBlocks,
    cache: cache::RunCache,
    wants: Vec<(u64, u64, u32)>,
    hints: Vec<(u64, u32)>,
    enabled: bool,
    chunks: usize,
}

impl<'a> ScanReader<'a> {
    fn new(dev: &'a mut MemBlocks, enabled: bool) -> Self {
        Self {
            dev,
            cache: cache::RunCache::new(1 << 24),
            wants: Vec::new(),
            hints: Vec::new(),
            enabled,
            chunks: 1,
        }
    }
    fn land(&mut self) {
        for (tok, blk, nblk) in self.wants.drain(..) {
            self.cache
                .done(tok, Some(self.dev.read(blk, nblk).unwrap()));
        }
    }
}

impl ChunkRead for ScanReader<'_> {
    fn read(&mut self, blk: u64, nblk: u32) -> Result<Bytes, StoreError> {
        if let Some(b) = self.cache.get(blk, nblk) {
            return Ok(b);
        }
        if !self.cache.pending(blk, nblk) {
            let t = self.cache.start(blk, nblk);
            self.wants.push((t, blk, nblk));
        }
        Err(StoreError::Miss)
    }
    fn scan_prefetch(&self) -> bool {
        self.enabled
    }
    fn scan_prefetch_chunks(&self) -> usize {
        self.chunks
    }
    fn prefetch(&mut self, blk: u64, nblk: u32) {
        self.hints.push((blk, nblk));
    }
}

#[test]
fn scan_batches_every_missing_head_before_merging_and_hints_next_fences_once() {
    let mut h = H::new(MemBlocks::new(), 1 << 30);
    for r in 0..3u32 {
        for i in 0..1500u32 {
            h.put(1, format!("k{:06}", i * 3 + r).as_bytes(), &[r as u8; 200]);
        }
        h.flush();
    }
    let src = h.lsm.sources();
    for (enabled, chunks) in [(false, 1), (true, 1), (true, 4)] {
        let mut rd = ScanReader::new(&mut h.dev, enabled);
        rd.chunks = chunks;
        assert!(matches!(
            read::list(&src, &mut rd, 1, None, b"", 16),
            Err(StoreError::Miss)
        ));
        assert_eq!(rd.wants.len(), if enabled { 3 } else { 1 });
        assert!(
            rd.hints.is_empty(),
            "all demanded heads precede speculation"
        );
        while !rd.wants.is_empty() {
            rd.land();
            match read::list(&src, &mut rd, 1, None, b"", 16) {
                Ok((page, more)) => {
                    assert!(more);
                    assert_eq!(page.len(), 16);
                    assert_eq!(&page[0].0[..], b"k000000");
                    assert_eq!(&page[15].0[..], b"k000015");
                    break;
                }
                Err(StoreError::Miss) => {}
                other => panic!("unexpected listing: {other:?}"),
            }
        }
        let mut expected: Vec<_> = src
            .top
            .iter()
            .flat_map(|r| r.fences.iter().skip(1).take(chunks))
            .map(|f| (f.blk, f.nblk))
            .collect();
        expected.sort_unstable();
        rd.hints.sort_unstable();
        assert_eq!(rd.hints, if enabled { expected } else { vec![] });
    }
}

#[test]
fn scan_batched_paged_prefix_object_boundaries_duplicates_and_range_tombstones() {
    let mut h = H::new(MemBlocks::new(), 128 << 10);
    for round in 0..FAN as u32 {
        for id in 1..=3 {
            for i in 0..500u32 {
                h.put(id, format!("a/{i:06}").as_bytes(), &[round as u8; 200]);
                if i % 7 == 0 {
                    h.put(id, format!("z/{i:06}").as_bytes(), b"other-prefix");
                }
            }
        }
        h.flush();
    }
    h.merges();
    assert!(
        h.lsm.man.tiers[0].len() >= 3,
        "listing crosses partition segments"
    );
    h.del_range(2, b"a/000100", Some(b"a/000400"));
    h.put(2, b"a/000200", b"newer-than-range");
    h.del(2, b"a/000499");
    h.flush();
    for id in [1, 2, 3, 4] {
        for prefix in [b"".as_slice(), b"a/", b"z/", b"none/"] {
            let want: Vec<_> =
                h.r.iter()
                    .filter(|((oid, k), _)| *oid == id && k.starts_with(prefix))
                    .map(|((_, k), v)| (b(k), b(v)))
                    .collect();
            let mut rd = ScanReader::new(&mut h.dev, true);
            rd.chunks = 4;
            let mut got = Vec::new();
            let mut after: Option<Bytes> = None;
            loop {
                let result = loop {
                    match read::list(&h.lsm.sources(), &mut rd, id, after.as_deref(), prefix, 17) {
                        Err(StoreError::Miss) => {
                            assert!(!rd.wants.is_empty());
                            rd.land();
                        }
                        r => break r.unwrap(),
                    }
                };
                let (page, more) = result;
                after = page.last().map(|(k, _)| k.clone());
                got.extend(page);
                rd.cache.op_done();
                if !more {
                    break;
                }
                assert!(after.is_some());
            }
            assert_eq!(got, want, "object={id}, prefix={prefix:?}");
        }
    }
}

/// Drive [`read::list_page`] to the end of the object the way the executor does: a visit-budget stop continues at the
/// returned position, a refused read (`Miss`) lands the chunks and continues at the returned position. Checks the
/// position moves forward only and every call's entries ascend past the earlier ones; returns the entries, the calls
/// that ended on the visit budget and the refused calls.
fn list_all(
    h: &mut H<MemBlocks>,
    id: u64,
    from: &[u8],
    prefix: &[u8],
    page: usize,
    visits: usize,
    prefetch: bool,
) -> (Vec<(Bytes, Bytes)>, usize, usize) {
    let src = h.lsm.sources();
    let mut rd = ScanReader::new(&mut h.dev, prefetch);
    let q = read::ListQuery {
        id,
        prefix,
        max: page,
        max_bytes: usize::MAX,
        visits,
    };
    let (mut all, mut resumes, mut misses) = (Vec::new(), 0, 0);
    let mut after: Option<(Bytes, bool)> = None;
    let mut pos = read::ListPos::new(from, false);
    loop {
        let mut out = Vec::new();
        let more = loop {
            let before = pos.clone();
            match read::list_page(&src, &mut rd, &q, &mut pos, &mut out) {
                Ok(read::ListEnd::Done { more }) => break more,
                Ok(read::ListEnd::Resume) => {
                    resumes += 1;
                    assert!(
                        (&pos.from[..], pos.excl) >= (&before.from[..], before.excl),
                        "the position moves forward"
                    );
                }
                Err(StoreError::Miss) => {
                    misses += 1;
                    assert!(!rd.wants.is_empty());
                    rd.land();
                }
                Err(e) => panic!("{e:?}"),
            }
        };
        rd.cache.op_done();
        if let (Some((last, _)), Some((first, _))) = (&after, out.first()) {
            assert!(first > last, "pages ascend");
        }
        all.extend(out.iter().cloned());
        if !more {
            return (all, resumes, misses);
        }
        let last = out.last().expect("a page with more after it").0.clone();
        after = Some((last.clone(), true));
        pos = read::ListPos {
            from: last,
            excl: true,
        };
    }
}

/// A span of deleted keys costs the listing one call per `visits` entries, never one call over the whole span, and the
/// listing in such steps (also with every cold chunk refused) is exactly the unbounded one: puts, point deletes, range
/// deletes and rewrites across runs and partitions, pages cut at every size, from the start and from a key.
#[test]
fn list_page_bounds_work_over_deleted_keys_and_resumes_exactly() {
    let mut h = H::new(MemBlocks::new(), 128 << 10);
    for round in 0..FAN as u32 {
        for id in 1..=2 {
            for i in 0..1200u32 {
                h.put(id, format!("a/{i:06}").as_bytes(), &[round as u8; 120]);
            }
        }
        h.flush();
    }
    h.merges();
    // The first 1000 of object 1's 1200 keys are point-deleted in a newer run, a range of object 2 by a range tombstone.
    for i in 0..1000u32 {
        h.del(1, format!("a/{i:06}").as_bytes());
    }
    h.del_range(2, b"a/000100", Some(b"a/000900"));
    h.flush();
    h.put(2, b"a/000500", b"rewritten");
    h.del(2, b"a/001100");
    h.flush();
    for id in [1u64, 2, 3] {
        for (from, prefix) in [
            (&b""[..], &b""[..]),
            (b"a/000300", b""),
            (b"", b"a/0005"),
            (b"", b"zz"),
        ] {
            let want: Vec<_> =
                h.r.iter()
                    .filter(|((oid, k), _)| *oid == id && &k[..] >= from && k.starts_with(prefix))
                    .map(|((_, k), v)| (b(k), b(v)))
                    .collect();
            for page in [1usize, 17, 4096] {
                for visits in [1usize, 7, 100, usize::MAX] {
                    // with the scan prefetch off a refusal names only the first missing head: the position it
                    // leaves must still cover everything the page already holds
                    for prefetch in [true, false] {
                        let (got, resumes, misses) =
                            list_all(&mut h, id, from, prefix, page, visits, prefetch);
                        assert!(
                            got == want,
                            "object {id} from {from:?} prefix {prefix:?} page {page} visits {visits} prefetch {prefetch}: {} entries, want {}",
                            got.len(),
                            want.len()
                        );
                        assert!(misses > 0 || want.is_empty(), "cold chunks were refused");
                        if visits == usize::MAX {
                            assert_eq!(resumes, 0);
                        }
                    }
                }
            }
        }
    }
    // The deleted prefix of object 1 (1000 keys): with 100 visits per call the first live key is reached by the tenth
    // call, nine of which stopped on the budget with nothing listed.
    let (got, resumes, _) = list_all(&mut h, 1, b"", b"", 4096, 100, true);
    assert_eq!(got.len(), 200);
    assert_eq!(resumes, 9, "calls over 1000 deleted keys");
}

/// With the scan prefetch off a refusal names only the first missing head, and the listing page keeps the entries it
/// merged before it: the position the call leaves has to be where the merge stands, not where the call began, or the
/// retry lists those entries again. Runs of several chunks each, interleaved keys, newer deletes and rewrites.
#[test]
fn list_page_without_prefetch_continues_where_the_refused_merge_stood() {
    let mut h = H::new(MemBlocks::new(), 1 << 30);
    for r in 0..3u32 {
        for i in 0..1500u32 {
            h.put(1, format!("k{:06}", i * 3 + r).as_bytes(), &[r as u8; 200]);
        }
        h.flush();
    }
    for i in (0..4500u32).step_by(7) {
        h.del(1, format!("k{i:06}").as_bytes());
    }
    for i in (3..4500u32).step_by(11) {
        h.put(1, format!("k{i:06}").as_bytes(), &[9; 150]);
    }
    h.flush();
    let want: Vec<_> =
        h.r.iter()
            .filter(|((oid, _), _)| *oid == 1)
            .map(|((_, k), v)| (b(k), b(v)))
            .collect();
    assert!(want.len() > 3000);
    for page in [100usize, 4096] {
        for visits in [50usize, usize::MAX] {
            let (got, _, misses) = list_all(&mut h, 1, b"", b"", page, visits, false);
            assert!(
                got == want,
                "page {page} visits {visits}: {} entries, want {}",
                got.len(),
                want.len()
            );
            assert!(misses > 10, "the runs span many chunks: {misses} refusals");
        }
    }
}

/// Fence prefix sums count every entry (puts and point tombstones) and are reconstructed identically by decode and
/// chunk moves.
#[test]
fn range_entry_bound_fence_edges_roundtrip_and_moves() {
    let mut dev = MemBlocks::new();
    let mut w = run::RunBuilder::new();
    w.push(&mut dev, 1, b"aaa", Some(b"v")).unwrap();
    w.seal(&mut dev).unwrap();
    w.push(&mut dev, 1, b"zz", Some(b"v")).unwrap();
    w.push(&mut dev, 2, b"00", None).unwrap();
    w.push(&mut dev, 2, b"aa", Some(b"v")).unwrap();
    w.seal(&mut dev).unwrap();
    w.push(&mut dev, 2, b"bb", Some(b"v")).unwrap();
    w.push(&mut dev, 2, b"cc", Some(b"v")).unwrap();
    w.seal(&mut dev).unwrap();
    w.push(&mut dev, 4, b"\0", Some(b"v")).unwrap();
    w.push(&mut dev, 4, b"\xff", None).unwrap();
    let (m, _) = w.finish(&mut dev, 1, 1, 10).unwrap();
    assert_eq!(m.fences.len(), 4);
    let decoded = run::load_meta(&mut dev, m.meta_blk, m.meta_nblk, m.meta_crc).unwrap();
    assert_eq!(m, decoded, "derived counts survive rebuilding at mount");
    let reads = dev.reads;
    for m in [&m, &decoded] {
        // A whole boundary chunk includes object 1's put and object 2's point tombstone: both are visited.
        assert_eq!(m.range_entry_upper_bound(2, b"aa", b"bb", u64::MAX), 3);
        assert_eq!(m.range_entry_upper_bound(2, b"aa", b"cc", u64::MAX), 5);
        assert_eq!(m.range_entry_upper_bound(2, b"aa", b"cc", 4), 4);
        assert_eq!(m.range_entry_upper_bound(2, b"aa", b"cc", 3), 3);
        assert_eq!(m.range_entry_upper_bound(2, b"bb", b"cc", u64::MAX), 2);
        assert_eq!(m.range_entry_upper_bound(2, b"zz", b"zzz", u64::MAX), 0);
        assert_eq!(m.range_entry_upper_bound(3, b"", b"\xff", u64::MAX), 0);
        assert_eq!(m.range_entry_upper_bound(4, b"\0", b"\xff", u64::MAX), 2);
        assert_eq!(
            m.range_entry_upper_bound(4, b"\xff", b"\xff\0", u64::MAX),
            2
        );
        assert_eq!(m.range_entry_upper_bound(2, b"", b"zz", 3), 3);
        assert_eq!(m.range_entry_upper_bound(2, b"", b"zz", 0), 0);
        assert_eq!(m.range_entry_upper_bound(2, b"aa", b"aa", u64::MAX), 0);
        assert_eq!(m.range_entry_upper_bound(2, b"cc", b"aa", u64::MAX), 0);
    }
    assert_eq!(dev.reads, reads, "no reads during estimation");
    let mut moved = run::RunBuilder::new();
    moved.push_moved(&mut dev, &m, 1).unwrap();
    moved.push_moved(&mut dev, &m, 2).unwrap();
    let (moved, _) = moved.finish(&mut dev, 2, 1, 10).unwrap();
    assert_eq!(moved.range_entry_upper_bound(2, b"aa", b"cc", u64::MAX), 5);
}

/// A span holding only point tombstones has no live key but costs a scan: its bound is the tombstone count, so a
/// positive threshold below it keeps the native range tombstone instead of enumerating.
#[test]
fn range_entry_bound_counts_point_tombstone_spans() {
    let mut dev = MemBlocks::new();
    let mut w = run::RunBuilder::new();
    for i in 0..300u32 {
        w.push(&mut dev, 5, format!("k{i:04}").as_bytes(), None)
            .unwrap();
    }
    let (m, _) = w.finish(&mut dev, 1, 1, 10).unwrap();
    assert_eq!(m.range_entry_upper_bound(5, b"k", b"l", u64::MAX), 300);
    assert_eq!(m.range_entry_upper_bound(5, b"k", b"l", 64), 64);
}

#[test]
fn range_entry_bound_counts_memtable_entries_inside_the_range_only() {
    let mut h = H::new(MemBlocks::new(), 1 << 30);
    h.put(1, b"a", b"v");
    h.put(1, b"c", b"v");
    h.put(9, b"b", b"v");
    h.lsm.freeze().unwrap();
    h.put(1, b"b", b"new");
    h.del(1, b"a");
    let mut over = Memtable::new();
    over.put(1, 1, b(b"b"), b(b"newest"));
    over.put(2, 1, b(b"d"), b(b"v"));
    over.del(3, 1, b(b"c"));
    let reads = h.dev.reads;
    let src = h.lsm.sources_over(Some(&over));
    // Only `b` (overlay and active) lies in [b, c); `a`, `c` and `d` elsewhere in the object do not count.
    assert_eq!(src.range_entry_upper_bound(1, b"b", b"c", u64::MAX), 2);
    assert_eq!(src.range_entry_upper_bound(1, b"b", b"c", 1), 1);
    // Point tombstones of the memtables count: [a, d) holds overlay b, c(tomb); active a(tomb), b; frozen a, c.
    assert_eq!(src.range_entry_upper_bound(1, b"a", b"d", u64::MAX), 6);
    assert_eq!(src.range_entry_upper_bound(9, b"a", b"z", u64::MAX), 1);
    assert_eq!(src.range_entry_upper_bound(999, b"a", b"z", u64::MAX), 0);
    assert_eq!(h.dev.reads, reads);
    // The overlay's range hides all older entries, but subtracting them from a bound is unnecessary.
    over.del_range(4, 1, b(b""), None);
    assert_eq!(
        h.lsm
            .sources_over(Some(&over))
            .range_entry_upper_bound(1, b"a", b"z", u64::MAX),
        4
    );
}

#[test]
fn range_entry_bound_covers_sparse_skewed_aged_partitioned_sources() {
    let mut h = H::new(MemBlocks::new(), 512);
    for round in 0..12 {
        for id in [1, 3, 19] {
            for i in 0..96u64 {
                // Arbitrary key bytes: most share a long prefix and numeric spacing is intentionally uneven.
                let mut k = b"shared-long-prefix/".to_vec();
                k.extend_from_slice(&(i * i * 65536).to_be_bytes());
                h.put(id, &k, &[round; 24]);
                if (i + u64::from(round)) % 7 == 0 {
                    h.del(id, &k);
                }
            }
            if round % 3 == 1 {
                let a = [b"shared-long-prefix/".as_slice(), &0u64.to_be_bytes()].concat();
                let z = [
                    b"shared-long-prefix/".as_slice(),
                    &(4096u64 * 65536).to_be_bytes(),
                ]
                .concat();
                h.del_range(id, &a, Some(&z));
            }
        }
        h.flush();
        h.merges_sized();
        let reads = h.dev.reads;
        for id in [0, 1, 2, 3, 19, 20] {
            for (a, z) in [
                (b"".as_slice(), b"\xff".as_slice()),
                (b"shared-long-prefix/", b"shared-long-prefix0"),
            ] {
                let exact =
                    h.r.iter()
                        .filter(|((oid, k), _)| *oid == id && &k[..] >= a && &k[..] < z)
                        .count() as u64;
                for cap in [0, 1, 64, 1_048_576, u64::MAX] {
                    let bound = h.lsm.sources().range_entry_upper_bound(id, a, z, cap);
                    assert!(
                        bound >= exact.min(cap),
                        "round={round}, id={id}, cap={cap}: {bound} < {exact}"
                    );
                    assert!(bound <= cap);
                }
            }
            for (lo, hi) in [(0, 1), (1, 2), (7, 19), (63, 64), (94, 96), (97, 100)] {
                let a = [
                    b"shared-long-prefix/".as_slice(),
                    &(lo * lo * 65536u64).to_be_bytes(),
                ]
                .concat();
                let z = [
                    b"shared-long-prefix/".as_slice(),
                    &(hi * hi * 65536u64).to_be_bytes(),
                ]
                .concat();
                let exact =
                    h.r.iter()
                        .filter(|((oid, k), _)| *oid == id && k >= &a && k < &z)
                        .count() as u64;
                for cap in [1, 64, u64::MAX] {
                    let bound = h.lsm.sources().range_entry_upper_bound(id, &a, &z, cap);
                    assert!(bound >= exact.min(cap), "narrow range: {bound} < {exact}");
                    assert!(bound <= cap);
                }
            }
        }
        assert_eq!(
            h.dev.reads, reads,
            "no data reads for bounds over partitioned tiers"
        );
    }
    assert!(
        h.depth > 0,
        "exercise deeper partitions as well as tier zero"
    );
}

/// Full listing of object `id` at page sizes 1, 2 and unbounded, compared with the reference.
fn assert_listing(h: &mut H<MemBlocks>, id: u64, ctx: &str) {
    let want: Vec<(Vec<u8>, Vec<u8>)> =
        h.r.range((id, vec![])..)
            .take_while(|((i, _), _)| *i == id)
            .map(|((_, k), v)| (k.clone(), v.clone()))
            .collect();
    for max in [1usize, 2, usize::MAX] {
        let mut got = Vec::new();
        let mut after: Option<Vec<u8>> = None;
        loop {
            let (page, more) = h
                .lsm
                .list(&mut h.dev, id, after.as_deref(), b"", max)
                .unwrap();
            got.extend(page.iter().map(|(k, v)| (k.to_vec(), v.to_vec())));
            if !more {
                break;
            }
            after = Some(page.last().unwrap().0.to_vec());
        }
        assert_eq!(got, want, "{ctx}: object {id} in pages of {max}");
    }
}

/// Every assignment of absent / put / point delete to each key in each generation. Every generation but the last is
/// flushed to its own run; the last stays in the memtable. Different assignments give different winners, runner-ups
/// and ties across the sources, so the merge loop's fast path, duplicate skip and runner-up refill all run in turn.
fn point_matrix(keys: &[&[u8]], gens: usize) {
    for code in 0..3usize.pow((keys.len() * gens) as u32) {
        let mut h = H::new(MemBlocks::new(), 24 << 10);
        let mut c = code;
        for g in 0..gens {
            for &k in keys {
                match c % 3 {
                    1 => h.put(1, k, &[b'a' + g as u8, k[1]]),
                    2 => h.del(1, k),
                    _ => {}
                }
                c /= 3;
            }
            if g + 1 < gens {
                h.flush();
            }
        }
        assert_listing(&mut h, 1, &format!("point code {code}"));
    }
}

/// [`point_matrix`] with range tombstones as a fourth state: key `i` is covered by `[key i, key i+1)` (open-ended for
/// the last key), so every range end is exactly the next key, which a reseek lands on.
fn range_matrix(keys: &[&[u8]], gens: usize) {
    for code in 0..4usize.pow((keys.len() * gens) as u32) {
        let mut h = H::new(MemBlocks::new(), 24 << 10);
        let mut c = code;
        for g in 0..gens {
            for (i, &k) in keys.iter().enumerate() {
                match c % 4 {
                    1 => h.put(1, k, &[b'a' + g as u8, k[1]]),
                    2 => h.del(1, k),
                    3 => h.del_range(1, k, keys.get(i + 1).copied()),
                    _ => {}
                }
                c /= 4;
            }
            if g + 1 < gens {
                h.flush();
            }
        }
        assert_listing(&mut h, 1, &format!("range code {code}"));
    }
}

#[test]
fn merge_loop_runner_up_and_tie_matrix_matches_reference() {
    point_matrix(&[b"k0", b"k1", b"k2"], 3);
    point_matrix(&[b"k0", b"k1"], 4);
}

#[test]
fn range_tombstone_end_matrix_matches_reference() {
    range_matrix(&[b"k0", b"k1"], 3);
    range_matrix(&[b"k0", b"k1", b"k2"], 2);
}

/// Reseeks that land exactly on a key of a multi-chunk object: range tombstones of 1, 3 and 17 keys start at every key,
/// so their ends fall on existing keys, on chunk starts and on the object end, and puts sit exactly on range ends.
/// An open-ended range ends object 1 and another ends object 2. Listed before and after merges, with a second object
/// behind the first.
#[test]
fn range_reseek_landing_on_exact_bounds_matches_reference() {
    let n = 300usize;
    let k_at = |i: usize| format!("k{i:04}").into_bytes();
    let mut h = H::new(MemBlocks::new(), 24 << 10);
    for i in 0..n {
        h.put(1, &k_at(i), &[i as u8; 700]);
        h.put(2, &k_at(i), &[7u8; 700]);
    }
    h.flush();
    assert!(
        h.lsm.man.top().iter().any(|r| r.fences.len() > 1),
        "object 1 must span several chunks"
    );
    for d in [1usize, 3, 17] {
        for i in 0..n {
            h.del_range(1, &k_at(i), Some(&k_at((i + d).min(n))[..]));
        }
        h.flush();
    }
    h.del_range(1, &k_at(280), None);
    h.del_range(2, &k_at(250), None);
    h.flush();
    for i in (0..n).step_by(7) {
        h.put(1, &k_at(i), &[0xee; 10]);
    }
    h.flush();
    assert_listing(&mut h, 1, "after ranges");
    assert_listing(&mut h, 2, "after ranges");
    h.merges();
    assert_listing(&mut h, 1, "after merges");
    assert_listing(&mut h, 2, "after merges");
    h.check(&mut Rng::new(7));
}
