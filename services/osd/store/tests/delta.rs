// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Leaf deltas (adr 0021 am. 19): lightly dirty leaves are checkpointed as small delta entries in shared delta pages
//! instead of whole pages. Model tests with cold remounts (fsck applies the chains), crash matrices over delta heavy
//! workloads (deltas folded back by the RAM cap, range deletes, splits), a store that stops writing deltas but still
//! reads them, damaged delta pages, stores without the feature.
mod common;
use common::*;
use std::collections::BTreeMap;
use store::dev::{BlockDev, Clock, CrashPolicy, SimClock, SimDisk, SimImage};
use store::layout::{FEAT_DELTA_RELOG, FEAT_LEAF_DELTA};
use store::rng::Rng;
use store::shard::{Event, ShardCfg, Txn};
use store::state::Op;
use store::{BLK, StoreError};

const POLICIES: [CrashPolicy; 3] = [
    CrashPolicy::DROP_ALL,
    CrashPolicy::PERSIST_ALL,
    CrashPolicy::MIXED,
];

fn key(i: u64) -> Vec<u8> {
    format!("k/{i:08}/{:x<40}", "").into_bytes()
}

fn scfg(cap: usize) -> ShardCfg {
    scfg_slice(cap, ShardCfg::default().ckpt_slice)
}

fn scfg_slice(cap: usize, slice: usize) -> ShardCfg {
    ShardCfg {
        ckpt_slice: slice,
        cache_pages: 400,
        dirty_soft_pages: 40,
        dirty_hard_pages: 600,
        ckpt_interval_ns: 150_000,
        meta_slack_cells: 0,
        delta_cap_bytes: cap,
        ..Default::default()
    }
}

fn env(cap: usize) -> Env {
    env_slice(cap, ShardCfg::default().ckpt_slice)
}

fn env_slice(cap: usize, slice: usize) -> Env {
    make_env_full(64, 512, 1, scfg_slice(cap, slice), 3, 4096, true, 64)
}

/// `env_slice`, `relog` false: a store without segment cleaning (`FEAT_DELTA_RELOG`): only the fold frees old segments.
fn env_relog(cap: usize, slice: usize, relog: bool) -> Env {
    let e = env_slice(cap, slice);
    if relog {
        return e;
    }
    let disk = SimDisk::new(e.sim.clone());
    let p = store::layout::MkfsParams {
        shards: 1,
        wal_blocks: 512,
        align_blocks: 1,
        meta_pct: 3,
        node_size: 4096,
        cell_pages: 64,
        compact_int: COMPACT_INT.get(),
        delta_relog: false,
        ..Default::default()
    };
    let (sb, dirs) = store::layout::mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    assert_eq!(sb.features & FEAT_DELTA_RELOG, 0);
    Env {
        img: disk.image(),
        sb,
        dir: dirs[0].clone(),
        ..e
    }
}

/// `n` keys, checkpointed (the leaves are on disk; deltas start with the first updates).
fn built(env: &Env, n: u64) -> (SimImage, BTreeMap<Vec<u8>, Vec<u8>>) {
    let mut r = Rig::new(env, 1);
    for ch in (0..n).collect::<Vec<_>>().chunks(200) {
        r.apply(
            ch.iter()
                .map(|&i| Op::Put(key(i), format!("v{i}").into_bytes()))
                .collect(),
        );
    }
    r.remount_clean();
    (r.disk.image(), r.model.clone())
}

/// Small random updates all over the keyspace (a few per txn: deltas), now and then a bigger batch into one leaf
/// (too big for a delta), range deletes of every width and inserts of fresh keys (splits).
fn updates(r: &mut Rig, rng: &mut Rng, n: u64, span: u64) {
    for _ in 0..n {
        match rng.below(20) {
            0 => {
                let a = rng.below(span);
                let w = [3u64, 30, 300, 3000][rng.below(4) as usize];
                r.apply(vec![Op::DelRange(key(a), key(a + 1 + rng.below(w)))]);
            }
            1 => {
                // one leaf gets many keys: no delta, maybe a split
                let a = rng.below(span);
                r.apply(
                    (0..rng.range(20, 60))
                        .map(|i| Op::Put(key(a + i * 2), vec![b'b'; rng.below(80) as usize]))
                        .collect(),
                );
            }
            2 => {
                let k = key(rng.below(span));
                r.apply(vec![Op::Del(k)]);
            }
            _ => {
                let ops = (0..rng.range(1, 4))
                    .map(|_| Op::Put(key(rng.below(span)), vec![b'u'; rng.below(70) as usize]))
                    .collect();
                r.apply(ops);
            }
        }
    }
}

fn stats_of(r: &Rig) -> store::tree::TreeStats {
    r.shard.tree_stats()
}

#[test]
fn updates_become_deltas_and_survive_cold_remounts() {
    for (cap, seed, relog) in [
        (4 << 10, 1u64, true),
        (4 << 10, 4, false),
        (1 << 20, 2, true),
        (64 << 20, 3, true),
    ] {
        let e = env_relog(cap, ShardCfg::default().ckpt_slice, relog);
        let (img, base) = built(&e, 12_000);
        let mut r = Rig::new(&Env { img, ..e.clone() }, seed);
        r.model = base;
        let mut rng = Rng::new(seed * 77);
        let (mut entries, mut folded, mut leaves, mut relogged) = (0, 0, 0, 0);
        for round in 0..10 {
            updates(&mut r, &mut rng, 400, 12_000);
            r.checkpoint();
            if round % 2 == 1 {
                let s = stats_of(&r);
                entries += s.delta_entries;
                folded += s.delta_folded;
                relogged += s.relog_chains;
                let rep = r.fsck(&r.disk.image());
                leaves += rep.delta_leaves;
                r.remount_clean(); // cold cache: leaves are re-read through their chains; fsck before and after
                r.verify();
            }
        }
        assert!(entries > 100, "cap {cap}: few delta entries ({entries})");
        assert!(
            leaves > 0,
            "cap {cap}: no leaf with deltas in a durable image"
        );
        // small cap: the page bound is reached; segment cleaning keeps it, else the fold does
        if cap < (1 << 20) && relog {
            assert!(relogged > 0, "cap {cap}: nothing relogged");
        } else if cap < (1 << 20) {
            assert!(
                folded > 0 && relogged == 0,
                "cap {cap}: folded {folded} relogged {relogged}"
            );
        }
    }
}

#[test]
fn a_store_that_stops_writing_deltas_still_reads_and_drains_them() {
    let e = env(8 << 20);
    let (img, base) = built(&e, 10_000);
    let mut r = Rig::new(&Env { img, ..e.clone() }, 5);
    r.model = base;
    let mut rng = Rng::new(9);
    updates(&mut r, &mut rng, 800, 10_000);
    r.checkpoint();
    let img = r.disk.image();
    let rep = r.fsck(&img);
    assert!(rep.delta_leaves > 0, "no deltas to carry over");
    // same store, deltas off (cap 0): content intact, chains are folded away by later updates and checkpoints
    let mut e0 = e.clone();
    e0.scfg.delta_cap_bytes = 0;
    let mut r0 = Rig::new(&Env { img, ..e0 }, 6);
    r0.model = r.model.clone();
    r0.verify();
    updates(&mut r0, &mut rng, 800, 10_000);
    for _ in 0..40 {
        r0.checkpoint();
        r0.put(b"z", b"z");
    }
    assert_eq!(stats_of(&r0).delta_entries, 0, "cap 0 must write no delta");
    r0.remount_clean();
    r0.verify();
    // the old chains have drained: the image carries no deltas any more
    let rep = r0.fsck(&r0.disk.image());
    assert_eq!(rep.delta_pages, 0, "{rep:?}");
}

struct Gen {
    disk: SimDisk,
    clk: SimClock,
    shard: store::shard::Shard<store::dev::SimDev>,
    acked: u64,
    submitted: u64,
    crashed: bool,
    models: Vec<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl Gen {
    fn new(env: &Env, img: &SimImage, seed: u64, base: BTreeMap<Vec<u8>, Vec<u8>>) -> Gen {
        let mut cfg = env.sim.clone();
        cfg.seed = seed;
        let disk = SimDisk::from_image(img, cfg);
        let mut clk = SimClock::default();
        let (shard, _) = mount(env, &disk, &mut clk).unwrap();
        Gen {
            disk,
            clk,
            shard,
            acked: 0,
            submitted: 0,
            crashed: false,
            models: vec![base],
        }
    }

    fn pump(&mut self) {
        let mut ev = Vec::new();
        self.shard.poll(self.clk.t, &mut ev);
        for e in ev {
            match e {
                Event::Acked(_) => self.acked += 1,
                Event::Failed(_) => {
                    assert!(self.disk.crashed(), "shard failed without a crash");
                    self.crashed = true;
                }
                _ => {}
            }
        }
        if self.disk.crashed() {
            self.crashed = true;
        }
        let h = self.shard.dev().next_deadline();
        self.clk.idle(h);
    }

    fn txn(&mut self, ops: Vec<Op>) {
        if self.crashed {
            return;
        }
        let mut m = self.models.last().unwrap().clone();
        for op in &ops {
            match op {
                Op::Put(k, v) => {
                    m.insert(k.clone(), v.clone());
                }
                Op::Del(k) => {
                    m.remove(k);
                }
                Op::DelRange(a, b) => m.retain(|k, _| !(k >= a && k < b)),
                Op::RunPut(r) => {
                    for i in 0..r.len() {
                        let (k, v) = r.entry(i);
                        // an empty value is a removal (FEAT_OMAP_TOMBS)
                        if v.is_empty() {
                            m.remove(k);
                        } else {
                            m.insert(k.to_vec(), v.to_vec());
                        }
                    }
                }
                Op::RunMerge { .. } => {}
                Op::Omap(_) => unreachable!("KV workloads log no omap LSM ops"),
            }
        }
        let mut t: Txn<Vec<u8>> = Txn::new(self.submitted + 1);
        t.ops = ops;
        for _ in 0..5_000_000 {
            if self.crashed {
                return;
            }
            match self.shard.submit(t) {
                Ok(_) => {
                    self.submitted += 1;
                    self.models.push(m);
                    return;
                }
                Err((StoreError::Busy | StoreError::Miss | StoreError::WalFull, back)) => {
                    t = back;
                    self.pump();
                }
                Err((e, _)) => {
                    assert!(self.disk.crashed(), "submit: {e:?}");
                    self.crashed = true;
                    return;
                }
            }
        }
        panic!("txn never admitted");
    }

    fn settle(&mut self) {
        for _ in 0..3_000_000 {
            if self.crashed || (self.acked == self.submitted && !self.shard.ckpt_active()) {
                return;
            }
            self.pump();
        }
        panic!("settle never finished");
    }
}

fn random_txns(g: &mut Gen, rng: &mut Rng, n: u64, span: u64) {
    for i in 0..n {
        let ops = match rng.below(14) {
            0 => {
                let a = rng.below(span);
                vec![Op::DelRange(key(a), key(a + 1 + rng.below(400)))]
            }
            1 => {
                let a = rng.below(span);
                (0..rng.range(15, 50))
                    .map(|j| Op::Put(key(a + j * 2), vec![b'B'; rng.below(80) as usize]))
                    .collect()
            }
            2 => vec![Op::Del(key(rng.below(span)))],
            _ => (0..rng.range(1, 4))
                .map(|_| Op::Put(key(rng.below(span)), vec![b'u'; rng.below(70) as usize]))
                .collect(),
        };
        g.txn(ops);
        if i % 9 == 8 {
            g.shard.request_checkpoint();
        }
    }
}

fn recover(
    env: &Env,
    g: &Gen,
    pol: CrashPolicy,
    label: &str,
) -> (SimImage, BTreeMap<Vec<u8>, Vec<u8>>) {
    let crash_img = g.disk.crash_image(pol);
    {
        let d = SimDisk::from_image(&crash_img, env.sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        store::fsck::fsck(&mut dev, &mut clk, None)
            .unwrap_or_else(|e| panic!("{label}: fsck of the crash image: {e}"));
    }
    let d = SimDisk::from_image(&crash_img, env.sim.clone());
    let mut clk = SimClock::default();
    let (mut sh, stats) =
        mount(env, &d, &mut clk).unwrap_or_else(|e| panic!("{label}: mount: {e:?}"));
    let got = sh.dump_blocking(&mut clk).unwrap();
    let (lo, hi) = (g.acked as usize, g.submitted as usize);
    assert!(
        (lo..=hi).any(|j| g.models[j] == got),
        "{label}: recovered state ({} keys, replayed {} txns) is no prefix between {lo} and {hi}",
        got.len(),
        stats.txns
    );
    (d.image(), got)
}

/// What [`crash_runs`] saw: runs that crashed, wrote deltas, chains folded / relogged, freezes that took more than one
/// slice.
struct Seen {
    crashed: u64,
    with_deltas: u64,
    folded: u64,
    sliced: u64,
    relogged: u64,
}

fn crash_runs(
    cap: usize,
    relog: bool,
    slice: usize,
    seeds: std::ops::Range<u64>,
    max_k: u64,
) -> Seen {
    let e = env_relog(cap, slice, relog);
    let (img, base) = built(&e, 9_000);
    let (mut crashed_runs, mut with_deltas, mut folded, mut sliced, mut relogged) = (0, 0, 0, 0, 0);
    for seed in seeds {
        let pol = POLICIES[(seed % 3) as usize];
        let mut rng = Rng::new(seed ^ 0xDE17A);
        let mut g = Gen::new(&e, &img, seed, base.clone());
        g.disk.arm_crash(g.disk.events() + 3 + rng.below(max_k));
        random_txns(&mut g, &mut rng, 60, 9_000);
        g.settle();
        if g.shard.tree_stats().delta_entries > 0 {
            with_deltas += 1;
        }
        folded += g.shard.tree_stats().delta_folded;
        relogged += g.shard.tree_stats().relog_chains;
        // freezes that took more than one slice
        sliced += g
            .shard
            .stats
            .ckpt_slices
            .saturating_sub(g.shard.stats.ckpt_begins);
        if !g.crashed {
            continue;
        }
        crashed_runs += 1;
        let label = format!("cap {cap} seed {seed} {pol:?}");
        let (img1, got1) = recover(&e, &g, pol, &label);
        // second generation on the recovered store (deltas of the crashed generation are read, extended, folded)
        let mut g2 = Gen::new(&e, &img1, seed + 700, got1);
        g2.disk.arm_crash(g2.disk.events() + rng.below(max_k));
        random_txns(&mut g2, &mut rng, 40, 9_000);
        g2.settle();
        let (img2, got2) = if g2.crashed {
            recover(&e, &g2, pol, &format!("{label} gen1"))
        } else {
            (g2.disk.image(), g2.models.last().unwrap().clone())
        };
        // third: clean run to completion, then a cold remount must show the same content
        let mut g3 = Gen::new(&e, &img2, seed + 900, got2.clone());
        random_txns(&mut g3, &mut rng, 20, 9_000);
        g3.settle();
        assert!(!g3.crashed);
        let want = g3.models.last().unwrap().clone();
        let img3 = g3.disk.image();
        let d = SimDisk::from_image(&img3, e.sim.clone());
        let (mut dev, mut clk) = (d.queue(), SimClock::default());
        store::fsck::fsck(&mut dev, &mut clk, None).unwrap_or_else(|x| panic!("{label}: {x}"));
        let d = SimDisk::from_image(&img3, e.sim.clone());
        let mut clk = SimClock::default();
        let (mut sh, _) = mount(&e, &d, &mut clk).unwrap();
        assert!(
            sh.dump_blocking(&mut clk).unwrap() == want || {
                // unacked txns of gen 3 may be missing at a crash-free image only if never acked: all were settled
                false
            },
            "{label}: content differs after a clean third generation"
        );
    }
    Seen {
        crashed: crashed_runs,
        with_deltas,
        folded,
        sliced,
        relogged,
    }
}

#[test]
fn crash_runs_over_delta_heavy_workloads() {
    // small cap: the RAM cap folds chains while crashes hit checkpoints; big cap: long chains survive crashes
    for (cap, relog) in [
        (2 << 10, true),
        (2 << 10, false),
        (1 << 20, true),
        (64 << 20, true),
    ] {
        let Seen {
            crashed,
            with_deltas,
            folded,
            relogged,
            ..
        } = crash_runs(cap, relog, ShardCfg::default().ckpt_slice, 0..40, 220);
        // small cap: the page bound is reached; segment cleaning (relog) or, without it, the fold keeps it
        if cap < (1 << 20) && relog {
            assert!(relogged > 5, "cap {cap}: little relogged ({relogged})");
        } else if cap < (1 << 20) {
            assert!(folded > 5, "cap {cap}: the fold folded little ({folded})");
        }
        assert!(crashed > 15, "cap {cap}: too few runs crashed ({crashed})");
        assert!(
            with_deltas > 25,
            "cap {cap}: too few runs wrote deltas ({with_deltas})"
        );
    }
}

/// Sliced freeze (adr 0021 am. 40): a few pages per poll, so every freeze spans many polls with txns applied, leaves
/// settled into deltas and then changed, rewritten or removed before the freeze ends, crashes in between; and the kill
/// switch. Same contract: the recovered state is an acked prefix, fsck-clean, every generation. Without relog the small
/// cap folds chains at the checkpoint starts, one per poll at slice 1 (adr 0021 am. 80), crashes later in the run.
#[test]
fn crash_runs_with_a_sliced_freeze() {
    for (cap, slice, relog, max_k) in [
        (2 << 10, 1, true, 220),
        (2 << 10, 1, false, 220),
        (2 << 10, 1, false, 900),
        (64 << 20, 1, true, 220),
        (1 << 20, 3, true, 220),
        (1 << 20, 0, true, 220),
    ] {
        let Seen {
            crashed,
            with_deltas,
            sliced: hits,
            folded,
            ..
        } = crash_runs(cap, relog, slice, 0..30, max_k);
        // the long horizon (crash points up to 900 txns) ends more runs before their crash point
        let min_crashed = if max_k > 220 { 5 } else { 10 };
        if !relog && max_k > 220 {
            assert!(folded > 5, "cap {cap} slice {slice}: {folded} folded");
        }
        assert!(
            crashed > min_crashed,
            "slice {slice}: too few runs crashed ({crashed})"
        );
        assert!(
            with_deltas > 18,
            "slice {slice}: too few runs wrote deltas ({with_deltas})"
        );
        if slice == 0 {
            assert_eq!(hits, 0, "kill switch froze in slices");
        } else {
            assert!(
                hits > 100,
                "cap {cap} slice {slice}: few freezes in slices ({hits})"
            );
        }
    }
}

#[test]
#[ignore = "soak: more seeds and crash points"]
fn crash_runs_over_delta_heavy_workloads_soak() {
    for (cap, relog) in [
        (2 << 10, true),
        (2 << 10, false),
        (1 << 20, true),
        (64 << 20, true),
    ] {
        for slice in [ShardCfg::default().ckpt_slice, 1, 0] {
            crash_runs(cap, relog, slice, 100..700, 600);
        }
    }
}

/// The same leaves go dirty -> delta / whole image (touch log buffer back to the pool) -> dirty again (a pooled buffer,
/// fresh log against the new base) many times, now and then overflowing the log (F_NOTRK, buffer released mid-txn),
/// with checkpoints in flight while they are re-dirtied; crash anywhere: the recovered state is an acked prefix, and a
/// second generation on it (chains read back, extended) stays consistent (adr 0062 am. 1).
fn redirty_runs(cap: usize, seeds: std::ops::Range<u64>, max_k: u64) -> (u64, u64, u64) {
    let e = env(cap);
    let (img, base) = built(&e, 9_000);
    let (mut crashed, mut pooled, mut deltas) = (0, 0, 0);
    // 24 hot leaves (keys 250 apart: one leaf each), each txn updates 3..6 keys of one leaf (log > 128 B)
    let hot = |rng: &mut Rng| -> Vec<Op> {
        let leaf = rng.below(24) * 375;
        let n = if rng.below(8) == 0 {
            60
        } else {
            rng.range(3, 7)
        }; // 60 keys: the log overflows
        (0..n)
            .map(|_| {
                Op::Put(
                    key(leaf + rng.below(30)),
                    vec![b'r'; rng.below(60) as usize],
                )
            })
            .collect()
    };
    for seed in seeds {
        let pol = POLICIES[(seed % 3) as usize];
        let mut rng = Rng::new(seed ^ 0x70C4);
        let mut g = Gen::new(&e, &img, seed, base.clone());
        g.disk.arm_crash(g.disk.events() + 3 + rng.below(max_k));
        for i in 0..80 {
            let ops = hot(&mut rng);
            g.txn(ops);
            if i % 4 == 3 {
                g.shard.request_checkpoint();
            }
            if g.shard.mem().tree.touch_pool_bytes > 0 {
                pooled += 1;
            }
        }
        g.settle();
        deltas += g.shard.tree_stats().delta_entries;
        let label = format!("redirty cap {cap} seed {seed} {pol:?}");
        if !g.crashed {
            let d = SimDisk::from_image(&g.disk.image(), e.sim.clone());
            let mut clk = SimClock::default();
            let (mut sh, _) = mount(&e, &d, &mut clk).unwrap();
            assert!(
                sh.dump_blocking(&mut clk).unwrap() == *g.models.last().unwrap(),
                "{label}: content differs after a cold remount"
            );
            continue;
        }
        crashed += 1;
        let (img1, got1) = recover(&e, &g, pol, &label);
        let mut g2 = Gen::new(&e, &img1, seed + 500, got1);
        g2.disk.arm_crash(g2.disk.events() + rng.below(max_k));
        for i in 0..40 {
            let ops = hot(&mut rng);
            g2.txn(ops);
            if i % 4 == 3 {
                g2.shard.request_checkpoint();
            }
        }
        g2.settle();
        if g2.crashed {
            recover(&e, &g2, pol, &format!("{label} gen1"));
        } else {
            let want = g2.models.last().unwrap().clone();
            let d = SimDisk::from_image(&g2.disk.image(), e.sim.clone());
            let mut clk = SimClock::default();
            let (mut sh, _) = mount(&e, &d, &mut clk).unwrap();
            assert!(
                sh.dump_blocking(&mut clk).unwrap() == want,
                "{label}: content differs after a clean second generation"
            );
        }
    }
    (crashed, pooled, deltas)
}

#[test]
fn redirtied_leaves_with_pooled_touch_logs_survive_crashes() {
    for cap in [2 << 10, 64 << 20] {
        let (crashed, pooled, deltas) = redirty_runs(cap, 0..30, 400);
        assert!(deltas > 50, "cap {cap}: few delta entries ({deltas})");
        assert!(crashed > 10, "cap {cap}: too few runs crashed ({crashed})");
        assert!(pooled > 0, "cap {cap}: touch log buffers never pooled");
    }
}

#[test]
#[ignore = "soak: more seeds and crash points"]
fn redirtied_leaves_with_pooled_touch_logs_survive_crashes_soak() {
    for cap in [2 << 10, 1 << 20, 64 << 20] {
        redirty_runs(cap, 100..700, 1000);
    }
}

#[test]
fn a_damaged_delta_page_is_detected_never_read_as_data() {
    let e = env(64 << 20);
    let (img, base) = built(&e, 8_000);
    let mut r = Rig::new(&Env { img, ..e.clone() }, 8);
    r.model = base;
    let mut rng = Rng::new(3);
    updates(&mut r, &mut rng, 600, 8_000);
    r.checkpoint();
    let img = r.disk.image();
    let rep = r.fsck(&img);
    assert!(rep.delta_pages > 0);
    // find a delta page: every block of the meta region that carries the delta page kind
    let sb = &e.sb;
    let dir = &e.dir;
    let lpb = BLK as u64 / sb.lba_size as u64;
    let mut hit = None;
    for blk in dir.meta_start..dir.data_start + dir.data_blocks {
        let b = img.read_lba(blk * lpb);
        if b.len() >= 8
            && u16::from_le_bytes([b[4], b[5]]) == store::page::MAGIC
            && b[6] == store::page::DELTA
        {
            hit = Some(blk);
            break;
        }
    }
    let blk = hit.expect("a delta page on disk");
    for byte in [100usize, 1000, 3000] {
        let mut bad = img.clone();
        bad.corrupt(blk * lpb, byte, 0x40);
        let d = SimDisk::from_image(&bad, e.sim.clone());
        let (mut dev, mut clk) = (d.queue(), SimClock::default());
        assert!(
            store::fsck::fsck(&mut dev, &mut clk, None).is_err(),
            "fsck accepted a damaged delta page (byte {byte})"
        );
        let d = SimDisk::from_image(&bad, e.sim.clone());
        let mut clk = SimClock::default();
        assert!(
            matches!(mount(&e, &d, &mut clk), Err(StoreError::Corrupt(_))),
            "mount accepted a damaged delta page (byte {byte})"
        );
    }
}

#[test]
fn a_store_without_the_feature_writes_no_deltas() {
    let mut sim = store::dev::SimConfig::new(32 << 20);
    sim.seed = 5;
    let disk = SimDisk::new(sim.clone());
    let p = store::layout::MkfsParams {
        shards: 1,
        wal_blocks: 512,
        align_blocks: 1,
        meta_pct: 4,
        node_size: 4096,
        leaf_delta: false,
        cell_pages: 64,
        ..Default::default()
    };
    let (sb, dirs) = store::layout::mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    assert_eq!(sb.features & FEAT_LEAF_DELTA, 0);
    let env = Env {
        img: disk.image(),
        sim,
        sb,
        dir: dirs[0].clone(),
        scfg: scfg(64 << 20),
        nobj: NOBJ,
        obj_scale: 1,
        big_pct: 3,
        storm_pct: 0,
        spread_pct: 0,
        idle_pct: 0,
    };
    let (img, base) = built(&env, 6_000);
    let mut r = Rig::new(&Env { img, ..env.clone() }, 2);
    r.model = base;
    let mut rng = Rng::new(1);
    updates(&mut r, &mut rng, 500, 6_000);
    r.remount_clean();
    r.verify();
    assert_eq!(stats_of(&r).delta_entries, 0);
    assert_eq!(r.fsck(&r.disk.image()).delta_pages, 0);
}

/// Small puts on random keys of `[lo, hi)`, 1-2 per txn (each dirty leaf changes a little: a delta).
fn small_updates(r: &mut Rig, rng: &mut Rng, lo: u64, hi: u64, n: u64) {
    for _ in 0..n {
        let ops = (0..rng.range(1, 3))
            .map(|_| {
                Op::Put(
                    key(lo + rng.below(hi - lo)),
                    vec![b's'; rng.range(8, 40) as usize],
                )
            })
            .collect();
        r.apply(ops);
    }
}

/// Chains whose leaves went cold never pin the RAM cap (`delta_cap_bytes`). Segment cleaning (relog) keeps the page bound,
/// so nothing else folds them: before the RAM fold, a shard whose chains had all gone cold declined every new delta and
/// wrote each hot leaf whole for good (e9455 osd.0: ~0 delta entries vs 50-70k per shard and minute on its peers, 2.5x
/// checkpoint pages, doc/perf/straggler-1s-20261101.md). The oldest chains are folded for the room the last freeze
/// lacked for hot leaves (dirty in consecutive checkpoints); after the start (one freeze to see a leaf hot, one to fold,
/// one until the folded chains leave) the hot leaves keep their deltas. Content intact through a cold remount.
#[test]
fn cold_chains_at_the_ram_cap_are_folded_and_hot_leaves_keep_their_deltas() {
    let cap = 96 << 10;
    let e = make_env_full(256, 512, 1, scfg(cap), 3, 4096, true, 64);
    let (img, base) = built(&e, 40_000);
    let mut r = Rig::new(&Env { img, ..e.clone() }, 21);
    r.model = base;
    let mut rng = Rng::new(97);
    // cold phase: small updates all over the first 32k keys until their chains hold the cap
    for _ in 0..40 {
        small_updates(&mut r, &mut rng, 0, 32_000, 150);
        r.checkpoint();
        if r.shard.state().tree.delta_chain_bytes() > cap {
            break;
        }
    }
    let t = &r.shard.state().tree;
    assert!(
        t.delta_chain_bytes() > cap,
        "cold phase: chains {} B, cap {cap} B",
        t.delta_chain_bytes()
    );
    // hot phase: only 2k keys (~30 leaves, chains far below the cap)
    let hot = |r: &mut Rig, rng: &mut Rng, steps| {
        for _ in 0..steps {
            small_updates(r, rng, 32_000, 34_000, 60);
            r.checkpoint();
        }
    };
    let s0 = stats_of(&r);
    hot(&mut r, &mut rng, 6);
    let s1 = stats_of(&r);
    hot(&mut r, &mut rng, 10);
    let s2 = stats_of(&r);
    let entries = s2.delta_entries - s1.delta_entries;
    let declined = s2.declined_room - s1.declined_room;
    let folded = s2.delta_folded - s0.delta_folded;
    assert!(
        folded > 0 && entries > 8 * declined,
        "hot phase after the start: delta entries {entries}, declined for room {declined}, folded {folded} (whole phase)"
    );
    r.fsck(&r.disk.image());
    r.remount_clean();
    r.verify();
}

/// The RAM fold serves hot leaves only: for a working set far beyond the cap whose leaves change once in a while, room
/// is folded again before the leaf's next change, so a fold (a leaf load and a whole write) buys nothing. Counting every
/// decline there cost +50 % reads for -6 % writes; only leaves dirty in consecutive checkpoints drive the fold.
#[test]
fn ram_fold_leaves_a_working_set_far_beyond_the_cap_alone() {
    let cap = 96 << 10;
    let e = make_env_full(1024, 512, 1, scfg(cap), 3, 4096, true, 64);
    let (img, base) = built(&e, 200_000);
    let mut r = Rig::new(&Env { img, ..e.clone() }, 21);
    r.model = base;
    let mut rng = Rng::new(97);
    for _ in 0..25 {
        small_updates(&mut r, &mut rng, 0, 200_000, 150);
        r.checkpoint();
    }
    let s0 = stats_of(&r);
    for _ in 0..40 {
        small_updates(&mut r, &mut rng, 0, 200_000, 150);
        r.checkpoint();
    }
    let s1 = stats_of(&r);
    let declined = s1.declined_room - s0.declined_room;
    let folded = s1.delta_folded - s0.delta_folded;
    assert!(
        declined > 1000 && folded * 100 < declined,
        "declined for room {declined}, folded {folded}"
    );
    r.fsck(&r.disk.image());
    r.remount_clean();
    r.verify();
}

/// `ckpt_delta_leaves` bounds the leaves one checkpoint turns into deltas (the synchronous checkpoint start stalls the
/// core ~3 us per delta leaf); the other dirty leaves are written whole. Content intact through cold remounts.
#[test]
fn delta_leaves_per_checkpoint_are_bounded_and_the_rest_is_written_whole() {
    let mut e = env(8 << 20);
    e.scfg.ckpt_delta_leaves = 3;
    let (img, base) = built(&e, 12_000);
    let mut r = Rig::new(&Env { img, ..e.clone() }, 11);
    r.model = base;
    let mut rng = Rng::new(31);
    let (mut ck, mut d) = (0, 0);
    for _ in 0..6 {
        let (c0, d0) = (r.shard.stats.checkpoints, stats_of(&r).delta_entries);
        updates(&mut r, &mut rng, 400, 12_000);
        r.checkpoint();
        ck += r.shard.stats.checkpoints - c0;
        d += stats_of(&r).delta_entries - d0;
        r.fsck(&r.disk.image());
        r.remount_clean();
        r.verify();
    }
    assert!(ck > 0 && d > 0, "checkpoints {ck}, delta entries {d}");
    assert!(
        d <= 3 * ck,
        "{d} delta entries in {ck} checkpoints (bound 3 each)"
    );
}
