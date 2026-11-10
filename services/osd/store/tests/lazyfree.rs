// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Lazy subtree free (adr 0021 am. 18): a range delete detaches covered on-disk subtrees without reading them, a
//! background drain frees their pages, the checkpoint image carries the list. Big-range delete without the per-txn
//! page limit, drain + idle checkpoint, crash matrix over deletes and drain, format checks.
mod common;
use common::*;
use std::collections::BTreeMap;
use store::dev::{BlockDev, Clock, CrashPolicy, SimClock, SimDisk, SimImage};
use store::shard::{Event, ShardCfg, Txn};
use store::state::Op;
use store::{BLK, StoreError};

const POLICIES: [CrashPolicy; 3] = [
    CrashPolicy::DROP_ALL,
    CrashPolicy::PERSIST_ALL,
    CrashPolicy::MIXED,
];

fn key(i: u64) -> Vec<u8> {
    // ~110 B keys: small leaves, but short separators keep interior pages wide; 60k keys = height 3 on 4 KiB pages
    format!("k/{i:08}/{:x<96}", "").into_bytes()
}

fn env() -> Env {
    let cfg = ShardCfg {
        // 1 MiB cache: max_walk = 64 pages, far below what the big deletes below touch without the lazy free
        cache_pages: 256,
        dirty_soft_pages: 48,
        dirty_hard_pages: 400,
        ckpt_interval_ns: 300_000,
        meta_slack_cells: 0,
        ..Default::default()
    };
    make_env_full(64, 512, 1, cfg, 3, 4096, true, 64)
}

/// A store with `n` keys, checkpointed, cold (fresh mount happens in the tests).
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

fn drain(r: &mut Rig) {
    for _ in 0..2_000_000 {
        let t = &r.shard.state().tree;
        if t.dead_len() == 0 && !t.dead_dirty() && !r.shard.ckpt_active() {
            return;
        }
        r.pump();
    }
    panic!("lazy free never drained");
}

#[test]
fn big_range_delete_detaches_drains_and_frees_everything() {
    let e = env();
    let (img, model) = built(&e, 60_000);
    let mut r = Rig::new(
        &Env {
            img: img.clone(),
            ..e.clone()
        },
        2,
    );
    r.model = model;
    let before = r.fsck(&img);
    assert!(before.height >= 3, "tree too small: {before:?}");
    let used0 = r.shard.statfs().meta_used;
    // the keyspace minus a few keys at both ends goes in ONE txn on a cold cache with a 64-page walk limit
    r.delrange(&key(500), &key(59_500));
    let s = r.shard.tree_stats();
    assert!(s.dead_detached > 0, "nothing was detached: {s:?}");
    assert!(r.shard.state().tree.dead_len() > 0);
    drain(&mut r);
    let s = r.shard.tree_stats();
    assert!(s.dead_freed > 0 && s.dead_lost == 0, "{s:?}");
    assert_eq!(r.shard.state().tree.dead_len(), 0);
    r.verify();
    assert_eq!(r.model.len(), 1000);
    // everything the range owned is free again: the durable image has no leak, no dead entry, a small tree
    let img2 = r.disk.image();
    let rep = r.fsck(&img2);
    assert_eq!(rep.dead_pages, 0);
    assert!(
        rep.meta_pages_used * 20 < before.meta_pages_used,
        "{} pages used after, {} before",
        rep.meta_pages_used,
        before.meta_pages_used
    );
    assert!(r.shard.statfs().meta_used * 20 < used0);
    // and the space is reusable: refill, remount, verify
    for ch in (0..40_000u64).collect::<Vec<_>>().chunks(200) {
        r.apply(
            ch.iter()
                .map(|&i| Op::Put(key(10_000 + i), format!("w{i}").into_bytes()))
                .collect(),
        );
    }
    r.remount_clean();
    r.verify();
}

#[test]
fn dead_list_survives_a_remount_and_is_drained_after_it() {
    let e = env();
    let (img, model) = built(&e, 60_000);
    let mut r = Rig::new(&Env { img, ..e.clone() }, 3);
    r.model = model;
    r.delrange(&key(0), &key(40_000));
    // checkpoint right away (before the first poll drains anything): the image lists detached subtrees whose pages are
    // still allocated, and the drain's later progress is persisted by checkpoints without a new WAL record
    r.shard.request_checkpoint();
    while r.shard.ckpt_lsn() < r.shard.next_lsn() - 1 || r.shard.ckpt_active() {
        r.pump();
    }
    let img = r.disk.image();
    let rep = r.fsck(&img);
    // a fresh shard that mounts this image owns the pending drain
    let mut r2 = Rig::new(&Env { img, ..e.clone() }, 4);
    r2.model = r.model.clone();
    assert!(
        rep.dead_pages > 0,
        "no detached subtree in the checkpoint image"
    );
    assert!(r2.shard.state().tree.dead_len() > 0, "dead list not loaded");
    r2.verify();
    drain(&mut r2);
    assert!(
        r2.shard.stats.idle_ckpts > 0,
        "the drain's progress is persisted by checkpoints without new WAL records"
    );
    let img = r2.disk.image();
    assert_eq!(r2.fsck(&img).dead_pages, 0);
    r2.verify();
}

/// One generation of the crash scenario: deterministic steps on a recovered/cold store; returns the content after each
/// submitted txn (index 0 = before the first), how many txns were acked when the run stopped, and whether it crashed.
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

    /// Pump until the lazy free has nothing left (or the disk crashed).
    fn drain(&mut self) {
        for _ in 0..3_000_000 {
            if self.crashed {
                return;
            }
            let t = &self.shard.state().tree;
            if self.acked == self.submitted
                && t.dead_len() == 0
                && !t.dead_dirty()
                && !self.shard.ckpt_active()
            {
                return;
            }
            self.pump();
        }
        panic!("drain never finished");
    }
}

fn steps(g: &mut Gen, round: u64) {
    let k = |i: u64| key(i);
    let put = |i: u64, tag: &str| Op::Put(key(i), format!("{tag}{i}").into_bytes());
    // detach a big middle part, write into the hole, detach a second range overlapping both, tiny puts in between
    g.txn(vec![Op::DelRange(k(8_000 + round), k(30_000))]);
    g.txn((0..5).map(|i| put(10_000 + i * 7, "a")).collect());
    g.txn(vec![Op::DelRange(k(2_000), k(12_000)), put(11_111, "b")]);
    g.shard.request_checkpoint(); // the image lists whatever the drain has not reached yet
    g.txn(vec![
        Op::DelRange(k(29_000), k(58_000)),
        Op::DelRange(k(100), k(300)),
    ]);
    g.txn((0..30).map(|i| put(40_000 + i, "c")).collect());
    g.txn(vec![Op::DelRange(k(0), k(60_000))]);
    g.shard.request_checkpoint();
    g.txn((0..10).map(|i| put(500 + i, "d")).collect());
}

fn check_recovered(
    env: &Env,
    g: &Gen,
    pol: CrashPolicy,
    label: &str,
) -> (SimImage, BTreeMap<Vec<u8>, Vec<u8>>) {
    let crash_img = g.disk.crash_image(pol);
    // durable root of the crash image is consistent by itself
    {
        let d = SimDisk::from_image(&crash_img, env.sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        store::fsck::fsck(&mut dev, &mut clk, None)
            .unwrap_or_else(|e| panic!("{label}: fsck: {e}"));
    }
    let d = SimDisk::from_image(&crash_img, env.sim.clone());
    let mut clk = SimClock::default();
    let (mut sh, stats) =
        mount(env, &d, &mut clk).unwrap_or_else(|e| panic!("{label}: mount: {e:?}"));
    let got = sh.dump_blocking(&mut clk).unwrap();
    // the recovered state is the model after some prefix of the txns: all acked ones, maybe more
    let lo = g.acked as usize;
    let hi = g.submitted as usize;
    let j = (lo..=hi).find(|&j| g.models[j] == got);
    assert!(
        j.is_some(),
        "{label}: recovered state ({} keys, replayed {} txns) is no prefix of the model between {lo} and {hi}",
        got.len(),
        stats.txns
    );
    (d.image(), got)
}

fn scenario(
    env: &Env,
    base_img: &SimImage,
    base: &BTreeMap<Vec<u8>, Vec<u8>>,
    seed: u64,
    k: Option<u64>,
    pol: CrashPolicy,
) -> u64 {
    let mut g = Gen::new(env, base_img, seed, base.clone());
    if let Some(k) = k {
        g.disk.arm_crash(g.disk.events() + k);
    }
    steps(&mut g, 0);
    g.drain();
    let events = g.disk.events();
    if !g.crashed {
        // finished without a crash: the drained store is leak free
        let img = g.disk.image();
        let d = SimDisk::from_image(&img, env.sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        let rep = store::fsck::fsck(&mut dev, &mut clk, None)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(rep.dead_pages, 0);
        return events;
    }
    let label = format!("seed {seed} k {k:?} {pol:?}");
    let (img, got) = check_recovered(env, &g, pol, &label);
    // second generation: the recovered store continues (drain of what the crash left, more deletes), crashing again
    let mut g2 = Gen::new(env, &img, seed + 1, got);
    g2.disk
        .arm_crash(g2.disk.events() + (seed * 7 + k.unwrap_or(0)) % 200);
    steps(&mut g2, 3);
    g2.drain();
    if g2.crashed {
        let (img2, got2) = check_recovered(env, &g2, pol, &format!("{label} gen1"));
        let mut g3 = Gen::new(env, &img2, seed + 2, got2);
        g3.drain();
        assert!(!g3.crashed);
        let img3 = g3.disk.image();
        let d = SimDisk::from_image(&img3, env.sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        let rep = store::fsck::fsck(&mut dev, &mut clk, None)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            rep.dead_pages, 0,
            "{label}: dead list left after a full drain"
        );
    }
    events
}

#[test]
fn crash_matrix_over_big_deletes_and_the_drain() {
    let e = env();
    let (img, base) = built(&e, 30_000);
    let events = scenario(&e, &img, &base, 1, None, CrashPolicy::DROP_ALL);
    assert!(events > 50);
    let mut runs = 0;
    for k in (0..=events).step_by(5) {
        for (pi, pol) in POLICIES.iter().enumerate() {
            scenario(&e, &img, &base, 10 + pi as u64, Some(k), *pol);
            runs += 1;
        }
    }
    println!("{runs} crash runs over {events} IO events");
}

#[test]
#[ignore = "soak: every IO boundary"]
fn crash_matrix_over_big_deletes_and_the_drain_soak() {
    let e = env();
    let (img, base) = built(&e, 30_000);
    let events = scenario(&e, &img, &base, 1, None, CrashPolicy::DROP_ALL);
    for k in 0..=events {
        for (pi, pol) in POLICIES.iter().enumerate() {
            scenario(&e, &img, &base, 100 + k * 3 + pi as u64, Some(k), *pol);
        }
    }
}

/// Random txns: bulk puts, ranges from a handful of keys to most of the keyspace (some pairs inverted or empty).
fn random_steps(g: &mut Gen, rng: &mut store::rng::Rng, n: u64, span: u64) {
    for _ in 0..n {
        match rng.below(10) {
            0..=3 => {
                let a = rng.below(span);
                let w = [3u64, 40, 700, 9_000, 40_000][rng.below(5) as usize];
                g.txn(vec![Op::DelRange(key(a), key(a + rng.below(w)))]);
            }
            4 => {
                // several ranges in one txn, nested / overlapping, with puts between them
                let mut ops = Vec::new();
                for _ in 0..rng.range(2, 6) {
                    let a = rng.below(span);
                    ops.push(Op::DelRange(key(a), key(a + rng.below(25_000))));
                    ops.push(Op::Put(key(rng.below(span)), b"x".to_vec()));
                }
                g.txn(ops);
            }
            _ => {
                let base = rng.below(span);
                let n = rng.range(1, 60);
                g.txn(
                    (0..n)
                        .map(|i| {
                            Op::Put(
                                key((base + i * rng.range(1, 30)) % span),
                                vec![b'p'; rng.below(60) as usize],
                            )
                        })
                        .collect(),
                );
            }
        }
    }
}

#[test]
fn random_big_deletes_vs_model_with_cold_remounts() {
    let e = env();
    let (img, base) = built(&e, 50_000);
    let mut detached = 0;
    for seed in 0..4u64 {
        let mut r = Rig::new(
            &Env {
                img: img.clone(),
                ..e.clone()
            },
            20 + seed,
        );
        r.model = base.clone();
        let mut rng = store::rng::Rng::new(seed ^ 0x77);
        for round in 0..14 {
            for _ in 0..rng.range(2, 6) {
                match rng.below(3) {
                    0 => {
                        let a = rng.below(50_000);
                        let w = [50u64, 3_000, 30_000][rng.below(3) as usize];
                        let b = a + 1 + rng.below(w);
                        r.delrange(&key(a), &key(b));
                    }
                    1 => {
                        let base = rng.below(50_000);
                        let ops: Vec<Op> = (0..rng.range(1, 60))
                            .map(|i| Op::Put(key((base + i * 3) % 50_000), vec![b'q'; 40]))
                            .collect();
                        r.apply(ops);
                    }
                    _ => {
                        let a = rng.below(50_000);
                        r.apply(vec![
                            Op::DelRange(key(a), key(a + rng.below(20_000))),
                            Op::Put(key(a + 1), b"z".to_vec()),
                            Op::DelRange(key(a / 2), key(a / 2 + rng.below(9_000))),
                        ]);
                    }
                }
            }
            if r.model.len() < 25_000 {
                // refill a contiguous block so the next deletes find whole subtrees to detach
                let from = rng.below(40_000);
                for ch in (from..from + 14_000).collect::<Vec<_>>().chunks(200) {
                    r.apply(
                        ch.iter()
                            .map(|&i| Op::Put(key(i), format!("r{i}").into_bytes()))
                            .collect(),
                    );
                }
            }
            if round % 3 == 2 {
                r.sync(); // dump_blocking discards poll events (acks)
                r.verify();
            }
            match rng.below(3) {
                0 => {
                    detached += r.shard.tree_stats().dead_detached;
                    r.remount_clean(); // cold cache, fsck before and after (dead list included)
                }
                1 => drain(&mut r),
                _ => {}
            }
        }
        detached += r.shard.tree_stats().dead_detached;
        drain(&mut r);
        r.verify();
        let img2 = r.disk.image();
        assert_eq!(r.fsck(&img2).dead_pages, 0);
    }
    assert!(detached > 20, "lazy detach barely exercised ({detached})");
}

#[test]
fn crash_random_big_deletes() {
    let e = env();
    let (img, base) = built(&e, 40_000);
    let (mut crashed_runs, mut det) = (0, 0);
    for seed in 0..60u64 {
        let pol = POLICIES[(seed % 3) as usize];
        let mut rng = store::rng::Rng::new(seed ^ 0x1234);
        let mut g = Gen::new(&e, &img, seed, base.clone());
        g.disk.arm_crash(g.disk.events() + 5 + rng.below(160));
        g.txn(vec![Op::DelRange(key(3_000), key(37_000))]);
        random_steps(&mut g, &mut rng, 24, 40_000); // long enough that most armed crash points fall inside the run
        g.drain();
        det += g.shard.tree_stats().dead_detached;
        if !g.crashed {
            continue;
        }
        crashed_runs += 1;
        let label = format!("seed {seed} {pol:?}");
        let (img1, got1) = check_recovered(&e, &g, pol, &label);
        let mut g2 = Gen::new(&e, &img1, seed + 500, got1);
        g2.disk.arm_crash(g2.disk.events() + rng.below(120));
        random_steps(&mut g2, &mut rng, 12, 40_000);
        g2.drain();
        let (img2, got2) = if g2.crashed {
            check_recovered(&e, &g2, pol, &format!("{label} gen1"))
        } else {
            (g2.disk.image(), g2.models.last().unwrap().clone())
        };
        let mut g3 = Gen::new(&e, &img2, seed + 900, got2.clone());
        g3.drain();
        assert!(!g3.crashed);
        let d = SimDisk::from_image(&g3.disk.image(), e.sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        let rep = store::fsck::fsck(&mut dev, &mut clk, None)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            rep.dead_pages, 0,
            "{label}: dead list left after a full drain"
        );
        let d = SimDisk::from_image(&g3.disk.image(), e.sim.clone());
        let mut clk = SimClock::default();
        let (mut sh, _) = mount(&e, &d, &mut clk).unwrap();
        assert!(
            sh.dump_blocking(&mut clk).unwrap() == got2,
            "{label}: content changed by the drain"
        );
    }
    assert!(crashed_runs > 30, "too few runs crashed ({crashed_runs})");
    assert!(det > 60, "lazy detach barely exercised ({det})");
}

#[test]
fn legacy_store_keeps_the_eager_free() {
    // a store formatted without the feature frees by reading, as before
    let mut sim = store::dev::SimConfig::new(32 << 20);
    sim.seed = 5;
    let disk = SimDisk::new(sim.clone());
    let p = store::layout::MkfsParams {
        shards: 1,
        wal_blocks: 512,
        align_blocks: 1,
        meta_pct: 4,
        node_size: 4096,
        lazy_free: false,
        cell_pages: 64,
        ..Default::default()
    };
    let (sb, dirs) = store::layout::mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    assert_eq!(sb.features & store::layout::FEAT_LAZY_FREE, 0);
    let env = Env {
        img: disk.image(),
        sim,
        sb,
        dir: dirs[0].clone(),
        scfg: ShardCfg::default(),
        nobj: NOBJ,
        obj_scale: 1,
        big_pct: 3,
        storm_pct: 0,
        spread_pct: 0,
        idle_pct: 0,
    };
    let mut r = Rig::new(&env, 6);
    for ch in (0..20_000u64).collect::<Vec<_>>().chunks(200) {
        r.apply(
            ch.iter()
                .map(|&i| Op::Put(key(i), format!("v{i}").into_bytes()))
                .collect(),
        );
    }
    r.remount_clean();
    r.delrange(&key(100), &key(19_900));
    r.checkpoint();
    assert_eq!(r.shard.tree_stats().dead_detached, 0);
    assert_eq!(r.shard.state().tree.dead_len(), 0);
    r.verify();
    let img = r.disk.image();
    assert_eq!(r.fsck(&img).dead_pages, 0);
    let _ = BLK;
}

/// Make the pages the delete of `[a, b)` needs resident, start a cold read of `inside` (left in flight), then submit the
/// delete directly: it applies without a page load and so frees what the read is still fetching.
fn race_read_with_delete(r: &mut Rig, inside: u64, a: u64, b: u64) {
    loop {
        match r.shard.state_mut().tree.probe_range(&key(a), &key(b)) {
            Ok(_) => break,
            Err(StoreError::Miss) => {
                r.pump();
                while r.shard.loads_pending() {
                    r.pump();
                }
            }
            Err(e) => panic!("probe: {e:?}"),
        }
    }
    let mut out = Vec::new();
    assert!(
        matches!(r.shard.get(&key(inside), &mut out), Err(StoreError::Miss)),
        "the read inside the range must miss"
    );
    assert!(r.shard.loads_pending(), "the read must be in flight");
    let mut t: Txn<Vec<u8>> = Txn::new(r.submitted + 1);
    t.ops = vec![Op::DelRange(key(a), key(b))];
    match r.shard.submit(t) {
        Ok(_) => r.submitted += 1,
        Err((e, _)) => panic!("the delete needed a load ({e:?}): race not set up"),
    }
    let (ka, kb) = (key(a), key(b));
    r.model.retain(|k, _| !(*k >= ka && *k < kb));
}

#[test]
fn read_in_flight_of_a_leaf_freed_by_address_is_not_cached() {
    // a cold read of a leaf that a range delete frees by address (never read by the delete) completes after the
    // delete: the image must not enter the cache, else a stale copy outlives the free of its address and later
    // shadows or unmaps the page that reuses it
    let e = big_cache_env();
    let (img, model) = built(&e, 60_000);
    let mut r = Rig::new(&Env { img, ..e.clone() }, 11);
    r.model = model;
    race_read_with_delete(&mut r, 30_100, 30_050, 30_150);
    while r.shard.loads_pending() {
        r.pump();
    }
    r.checkpoint();
    r.checkpoint();
    r.shard
        .state()
        .tree
        .check_resident_alloc()
        .unwrap_or_else(|m| panic!("{m}"));
    // reuse the freed pages and evict: content stays exact
    for ch in (0..3000u64).collect::<Vec<_>>().chunks(100) {
        r.apply(
            ch.iter()
                .map(|&i| Op::Put(key(70_000 + i), format!("n{i}").into_bytes()))
                .collect(),
        );
        r.checkpoint();
    }
    r.shard
        .state()
        .tree
        .check_resident_alloc()
        .unwrap_or_else(|m| panic!("{m}"));
    r.verify();
    r.remount_clean();
    r.verify();
}

#[test]
fn detached_subtree_with_a_read_in_flight_still_drains() {
    // a cold read of an interior page is in flight when a range delete detaches that page: the drain's read of the
    // same page must not be lost (a dropped drain read left the entry in flight forever: leak, shard never quiet)
    let e = big_cache_env();
    let (img, model) = built(&e, 60_000);
    let mut r = Rig::new(&Env { img, ..e.clone() }, 11);
    r.model = model;
    race_read_with_delete(&mut r, 30_000, 500, 59_500);
    assert!(r.shard.state().tree.dead_len() > 0, "nothing detached");
    drain(&mut r);
    assert_eq!(r.shard.tree_stats().dead_lost, 0);
    r.checkpoint();
    r.shard
        .state()
        .tree
        .check_resident_alloc()
        .unwrap_or_else(|m| panic!("{m}"));
    r.verify();
    let img = r.disk.image();
    assert_eq!(r.fsck(&img).dead_pages, 0);
}

/// Like `env` with a cache that holds every warmed page (the race tests must not lose them to eviction).
fn big_cache_env() -> Env {
    let mut e = env();
    e.scfg.cache_pages = 8192;
    e
}

#[test]
fn failed_read_of_a_leaf_in_a_removed_range_does_not_outlive_its_address() {
    // a leaf whose read failed (damaged, or a transient error of a pre-scan readahead) is removed by a range delete
    // (freed by address, never read): the failure must go with the address, else the healthy page that reuses it
    // fails with the stale error once evicted and looked up again (until remount)
    let e = env();
    let (img, model) = built(&e, 60_000);
    let mut r = Rig::new(&Env { img, ..e.clone() }, 13);
    r.model = model;
    let (a, b, inside) = (30_000u64, 30_300u64, 30_150u64);
    loop {
        match r.shard.state_mut().tree.probe_range(&key(a), &key(b)) {
            Ok(_) => break,
            Err(StoreError::Miss) => {
                r.pump();
                while r.shard.loads_pending() {
                    r.pump();
                }
            }
            Err(e) => panic!("probe: {e:?}"),
        }
    }
    r.disk.fail_reads(0, u64::MAX / 2);
    let mut out = Vec::new();
    assert!(matches!(
        r.shard.get(&key(inside), &mut out),
        Err(StoreError::Miss)
    ));
    while r.shard.loads_pending() {
        r.pump();
    }
    r.disk.clear_faults();
    let bad: Vec<u64> = r.shard.state().tree.bad_addrs().collect();
    assert_eq!(bad.len(), 1, "one failed leaf read");
    assert!(matches!(
        r.shard.get(&key(inside), &mut out),
        Err(StoreError::Io(_))
    ));
    let mut t: Txn<Vec<u8>> = Txn::new(r.submitted + 1);
    t.ops = vec![Op::DelRange(key(a), key(b))];
    match r.shard.submit(t) {
        Ok(_) => r.submitted += 1,
        Err((e, _)) => panic!("the delete needed a load ({e:?}): the failed leaf is not covered"),
    }
    let (ka, kb) = (key(a), key(b));
    r.model.retain(|k, _| !(*k >= ka && *k < kb));
    assert_eq!(
        r.shard.state().tree.bad_addrs().count(),
        0,
        "freed address still marked bad"
    );
    r.checkpoint();
    r.checkpoint();
    // reuse the freed pages (small cache: they are evicted and read again), then read everything
    let mut reused = false;
    for ch in (0..4000u64).collect::<Vec<_>>().chunks(100) {
        r.apply(
            ch.iter()
                .map(|&i| Op::Put(key(70_000 + i), format!("n{i}").into_bytes()))
                .collect(),
        );
        r.checkpoint();
        let t = &r.shard.state().tree;
        reused |= t.page_idx(bad[0]).is_some_and(|i| t.meta.get(i));
    }
    assert!(
        reused,
        "the freed address was never reused: test not effective"
    );
    r.verify();
    r.remount_clean();
    r.verify();
}

// ---------------------------------------------------------------- underfull leaf merge (adr 0021 am. 29)

/// A sweep of single-key deletes that leaves every 5th key (the leaves thin out one after the other: each merges into
/// its left neighbour while that is still dirty), checkpoints in between, then puts into the holes.
fn sweep_steps(g: &mut Gen, round: u64) {
    for i in 0..4_000u64 {
        if i % 5 != round % 5 {
            g.txn(vec![Op::Del(key(i))]);
        }
        if i % 500 == 499 {
            g.shard.request_checkpoint();
        }
    }
    for i in 0..200u64 {
        g.txn(vec![Op::Put(key(1 + i * 19), format!("m{i}").into_bytes())]);
    }
}

fn sweep_scenario(
    env: &Env,
    img: &SimImage,
    base: &BTreeMap<Vec<u8>, Vec<u8>>,
    seed: u64,
    k: Option<u64>,
    pol: CrashPolicy,
) -> (u64, u64) {
    let mut g = Gen::new(env, img, seed, base.clone());
    if let Some(k) = k {
        g.disk.arm_crash(g.disk.events() + k);
    }
    sweep_steps(&mut g, 0);
    g.drain();
    let (events, merged) = (g.disk.events(), g.shard.tree_stats().merged);
    if !g.crashed {
        // finished: the content is the model, the durable image is consistent
        g.shard.request_checkpoint();
        g.drain();
        let got = g.shard.dump_blocking(&mut g.clk).unwrap();
        assert!(
            got == *g.models.last().unwrap(),
            "content differs from the model"
        );
        return (events, merged);
    }
    let label = format!("sweep seed {seed} k {k:?} {pol:?}");
    let (img, got) = check_recovered(env, &g, pol, &label);
    // the recovered store sweeps again (merging on a replayed tree), crashes again, recovers again
    let mut g2 = Gen::new(env, &img, seed + 1, got);
    g2.disk
        .arm_crash(g2.disk.events() + (seed * 11 + k.unwrap_or(0)) % 300);
    sweep_steps(&mut g2, 1);
    g2.drain();
    if g2.crashed {
        check_recovered(env, &g2, pol, &format!("{label} gen1"));
    }
    (events, merged)
}

#[test]
fn crash_matrix_over_a_merging_sweep() {
    let e = env();
    let (img, base) = built(&e, 4_000);
    let (events, merged) = sweep_scenario(&e, &img, &base, 1, None, CrashPolicy::DROP_ALL);
    assert!(merged > 0, "the sweep merged nothing");
    assert!(events > 100, "{events}");
    for k in (0..=events).step_by((events / 8).max(1) as usize) {
        for (pi, pol) in POLICIES.iter().enumerate() {
            sweep_scenario(&e, &img, &base, 10 + pi as u64, Some(k), *pol);
        }
    }
}

#[test]
#[ignore = "soak: every 3rd IO boundary of the merging sweep"]
fn crash_matrix_over_a_merging_sweep_soak() {
    let e = env();
    let (img, base) = built(&e, 4_000);
    let (events, _) = sweep_scenario(&e, &img, &base, 1, None, CrashPolicy::DROP_ALL);
    for k in (0..=events).step_by(3) {
        for (pi, pol) in POLICIES.iter().enumerate() {
            sweep_scenario(&e, &img, &base, 100 + k * 3 + pi as u64, Some(k), *pol);
        }
    }
}
