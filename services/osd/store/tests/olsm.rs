// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Omap LSM engine in the shard (adr 0610 phase 2a, am. 3 helper jobs): WAL ops into the memtable, flush / merge jobs
//! (inline on the owner, or rounds on a simulated helper core), manifest txn, WAL floor, mount replay. Random omap
//! workloads against a model, clean remounts and crashes at random points (every in-flight write persisted, dropped or
//! torn at random) while flushes and merges run.

use bytes::Bytes;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;
use store::StoreError;
use store::dev::{BlockDev, Clock, CrashPolicy, SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::layout::{MkfsParams, mkfs, read_super};
use store::olsm::wire::{OOp, del_blob, put_blob};
use store::olsm::{
    BlockSink, CHUNK_MAX, CHUNK_MIN, ChunkRead, Manifest, job, labdev::MemBlocks, mem::Memtable,
    run::load_chunk,
};
use store::rng::Rng;
use store::shard::{Event, HelperJob, Shard, ShardCfg, Txn};
use store::state::Op;

/// Model: (object, key) -> value.
type Model = BTreeMap<(u64, Vec<u8>), Vec<u8>>;

const OBJS: u64 = 4;

fn cfg() -> ShardCfg {
    // a small cache: memtables of a few KiB flush often, the run cache misses often
    ShardCfg {
        cache_pages: 96,
        ..ShardCfg::default()
    }
}

fn format(lsm: bool) -> (SimImage, SimConfig) {
    format_wal(lsm, 2048)
}

fn format_wal(lsm: bool, wal_blocks: u64) -> (SimImage, SimConfig) {
    format_sim(lsm, wal_blocks, SimConfig::new(64 << 20))
}

fn format_sim(lsm: bool, wal_blocks: u64, sim: SimConfig) -> (SimImage, SimConfig) {
    let disk = SimDisk::new(sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = MkfsParams {
        shards: 1,
        wal_blocks,
        align_blocks: 1,
        meta_pct: 6,
        omap_lsm: lsm,
        ..Default::default()
    };
    mkfs(&mut dev, &mut clk, &p).unwrap();
    (disk.image(), sim)
}

fn mount(img: &SimImage, sim: &SimConfig, seed: u64) -> (SimDisk, SimClock, Shard<SimDev>) {
    mount_cfg(img, sim, seed, cfg())
}

fn mount_cfg(
    img: &SimImage,
    sim: &SimConfig,
    seed: u64,
    cfg: ShardCfg,
) -> (SimDisk, SimClock, Shard<SimDev>) {
    let mut c = sim.clone();
    c.seed = seed;
    let disk = SimDisk::from_image(img, c);
    let mut clk = SimClock::default();
    let mut dev = disk.queue();
    let (sb, dirs) = read_super(&mut dev, &mut clk).unwrap();
    let (s, _) = Shard::mount(dev, &mut clk, &sb, &dirs[0], cfg, false).unwrap();
    helper_remount();
    (disk, clk, s)
}

/// Simulated helper core (adr 0534 lane, one per test thread): takes the shard's prepared rounds before each poll,
/// steps each a random number of slices per poll (delayed), hands them back in random order, also unfinished (declined
/// / partial rounds). `flip`: helpers stop and start at random (jobs come back, the owner steps them inline meanwhile).
struct Helper {
    jobs: Vec<HelperJob>,
    rng: Rng,
    flip: bool,
    on: bool,
    /// Merge rounds are not taken (a helper slow on merges); flush rounds still are.
    hold_merges: bool,
}

thread_local! {
    static HELPER: RefCell<Option<Helper>> = const { RefCell::new(None) };
}

/// Run the following shard operations of this thread with a simulated helper core.
fn use_helper(seed: u64, flip: bool) {
    HELPER.with(|h| {
        *h.borrow_mut() = Some(Helper {
            jobs: Vec::new(),
            rng: Rng::new(seed),
            flip,
            on: true,
            hold_merges: false,
        })
    });
}

/// Hold (`true`) or release merge rounds in the simulated helper.
fn hold_merges(on: bool) {
    HELPER.with(|h| h.borrow_mut().as_mut().expect("helper in use").hold_merges = on);
}

/// A new mount: jobs of the old one are lost with its process (the shard never sees them again).
fn helper_remount() {
    HELPER.with(|h| {
        if let Some(h) = h.borrow_mut().as_mut() {
            h.jobs.clear();
        }
    });
}

fn helper_pass(s: &mut Shard<SimDev>) {
    HELPER.with(|h| {
        let mut h = h.borrow_mut();
        let Some(h) = h.as_mut() else {
            return;
        };
        if h.flip && h.rng.below(16) == 0 {
            h.on = !h.on;
        }
        s.compaction_helpers(h.on, 1);
        if h.on {
            let merges = !h.hold_merges;
            while let Some(j) = s
                .take_compaction(true)
                .or_else(|| merges.then(|| s.take_compaction(false)).flatten())
            {
                h.jobs.push(j);
            }
        }
        let mut i = 0;
        while i < h.jobs.len() {
            let mut back = !h.on;
            for _ in 0..h.rng.below(6) {
                if h.jobs[i].step(256) {
                    back = true;
                    break;
                }
            }
            if back || h.rng.below(8) == 0 {
                let j = h.jobs.swap_remove(i);
                assert!(s.return_compaction(j, true), "job of this mount");
            } else {
                i += 1;
            }
        }
    });
}

/// One poll (after a helper pass when this thread uses one); returns the acked tokens.
fn poll(s: &mut Shard<SimDev>, clk: &mut SimClock) -> Vec<u64> {
    helper_pass(s);
    let mut ev = Vec::new();
    s.poll(clk.t, &mut ev);
    let mut acked = Vec::new();
    for e in ev {
        match e {
            Event::Acked(t) => acked.push(t),
            Event::Failed(f) => panic!("shard failed: {f:?}"),
            _ => {}
        }
    }
    let h = s.dev().next_deadline();
    clk.idle(h);
    acked
}

/// Submit, polling through backpressure (memtable throttle, ring, pages).
fn submit(s: &mut Shard<SimDev>, clk: &mut SimClock, mut t: Txn<Vec<u8>>, acked: &mut Vec<u64>) {
    for _ in 0..100_000 {
        match s.submit(t) {
            Ok(_) => return,
            Err((StoreError::Busy | StoreError::WalFull | StoreError::Miss, back)) => {
                t = back;
                acked.extend(poll(s, clk));
            }
            Err((e, _)) => panic!("submit: {e:?}"),
        }
    }
    panic!(
        "txn never admitted: busy {:?} {:?} {:?} floor {}",
        s.stats.busy,
        s.olsm_stats(),
        s.gauges(),
        s.floor_blocks()
    );
}

/// Every entry of every object through the engine (paged listings, run block misses polled through).
fn dump(s: &mut Shard<SimDev>, clk: &mut SimClock) -> Model {
    let mut m = Model::new();
    for id in 1..=OBJS {
        let mut from = Vec::new();
        let mut excl = false;
        loop {
            let r = loop {
                match s.olsm_list(None, id, &from, excl, b"", 7) {
                    Err(StoreError::Miss) => {
                        poll(s, clk);
                    }
                    r => break r.unwrap(),
                }
            };
            let (page, more) = r;
            for (k, v) in &page {
                m.insert((id, k.to_vec()), v.to_vec());
            }
            match page.last() {
                Some((k, _)) if more => {
                    from = k.to_vec();
                    excl = true;
                }
                _ => break,
            }
        }
    }
    m
}

fn get(s: &mut Shard<SimDev>, clk: &mut SimClock, id: u64, key: &[u8]) -> Option<Vec<u8>> {
    loop {
        match s.olsm_get(None, id, key) {
            Err(StoreError::Miss) => {
                poll(s, clk);
            }
            r => return r.unwrap().map(|b| b.to_vec()),
        }
    }
}

fn key(i: u64) -> Vec<u8> {
    format!("k{i:05}").into_bytes()
}

/// A random txn of omap ops (applied to `m`).
fn gen_txn(rng: &mut Rng, m: &mut Model, token: u64) -> Txn<Vec<u8>> {
    let mut t = Txn::new(token);
    for _ in 0..1 + rng.below(3) {
        let id = 1 + rng.below(OBJS);
        match rng.below(20) {
            0..=13 => {
                let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..1 + rng.below(12))
                    .map(|_| {
                        let v = vec![rng.below(256) as u8; rng.below(300) as usize];
                        (key(rng.below(400)), v)
                    })
                    .collect();
                let (n, blob) = put_blob(&pairs);
                for (k, v) in &pairs {
                    m.insert((id, k.clone()), v.clone());
                }
                t.ops.push(Op::Omap(OOp::Put { id, n, blob }));
            }
            14..=17 => {
                let keys: Vec<Vec<u8>> =
                    (0..1 + rng.below(6)).map(|_| key(rng.below(400))).collect();
                for k in &keys {
                    m.remove(&(id, k.clone()));
                }
                t.ops.push(Op::Omap(OOp::Del {
                    id,
                    blob: del_blob(&keys),
                }));
            }
            18 => {
                let a = rng.below(400);
                let (first, end) = (key(a), key(a + 1 + rng.below(40)));
                m.retain(|(i, k), _| !(*i == id && *k >= first && *k < end));
                t.ops.push(Op::Omap(OOp::Range {
                    id,
                    first: first.into(),
                    end: Some(end.into()),
                }));
            }
            _ => {
                m.retain(|(i, _), _| *i != id);
                t.ops.push(Op::Omap(OOp::Range {
                    id,
                    first: Default::default(),
                    end: None,
                }));
            }
        }
    }
    t
}

fn settle(s: &mut Shard<SimDev>, clk: &mut SimClock, acked: &mut Vec<u64>, want: u64) {
    for _ in 0..1_000_000 {
        acked.extend(poll(s, clk));
        if acked.len() as u64 >= want {
            return;
        }
    }
    panic!("acks never arrived");
}

#[test]
fn flush_merge_and_reads_match_the_model() {
    model_run();
}

#[test]
fn helper_rounds_match_the_model() {
    use_helper(5, false);
    let st = model_run();
    assert!(st.helper_rounds > 0 && st.inline_rounds == 0, "{st:?}");
}

#[test]
fn helpers_stopping_and_starting_match_the_model() {
    use_helper(9, true);
    let st = model_run();
    assert!(st.helper_rounds > 0 && st.inline_rounds > 0, "{st:?}");
}

fn model_run() -> store::shard::OlsmStats {
    let (img, sim) = format(true);
    let (disk, mut clk, mut s) = mount(&img, &sim, 1);
    let mut rng = Rng::new(7);
    let mut m = Model::new();
    let mut acked = Vec::new();
    let n = 3000;
    for t in 1..=n {
        let txn = gen_txn(&mut rng, &mut m, t);
        submit(&mut s, &mut clk, txn, &mut acked);
        acked.extend(poll(&mut s, &mut clk));
    }
    settle(&mut s, &mut clk, &mut acked, n);
    let st = s.olsm_stats().expect("engine on");
    assert!(st.flushes >= 8 && st.merges >= 1, "jobs ran: {st:?}");
    assert_eq!(dump(&mut s, &mut clk), m);
    for i in (0..400).step_by(37) {
        let k = key(i);
        assert_eq!(
            get(&mut s, &mut clk, 2, &k),
            m.get(&(2, k.clone())).cloned()
        );
    }
    // clean remount: manifest + replay of the memtable ops above flushed_lsn
    let img2 = disk.crash_image(CrashPolicy::PERSIST_ALL);
    drop(s);
    let (_d2, mut clk2, mut s2) = mount(&img2, &sim, 2);
    assert_eq!(dump(&mut s2, &mut clk2), m);
    st
}

#[test]
fn crash_at_random_points_recovers_an_acked_prefix() {
    crash_run(cfg());
}

/// A tree cache of 32 pages: a txn may probe 8 tree pages, a merge takes at most `8 - height - 1` runs (adr 0662
/// am. 1?), so tier 0 and full partitions merge their oldest runs in several picks (partial partition installs) and
/// garbage columns beyond that are not picked. Crashes at random points recover an acked prefix.
#[test]
fn crash_with_partial_merges_recovers_an_acked_prefix() {
    crash_run(ShardCfg {
        cache_pages: 32,
        ..cfg()
    });
}

/// Crashes while rounds are on the helper (delayed, partial, reordered returns; helpers stopping): same recovery.
#[test]
fn crash_with_helper_rounds_recovers_an_acked_prefix() {
    use_helper(13, true);
    crash_run(cfg());
}

fn crash_run(c: ShardCfg) {
    let (img0, sim) = format(true);
    for seed in 0..12u64 {
        let mut img = img0.clone();
        let mut rng = Rng::new(seed * 7919 + 1);
        // state after txn i (global count) for every i a crash may recover to: from the acked ones up
        let mut states: BTreeMap<u64, Model> = BTreeMap::from([(0, Model::new())]);
        for round in 0..4 {
            let (disk, mut clk, mut s) = mount_cfg(&img, &sim, seed * 31 + round, c.clone());
            let got = dump(&mut s, &mut clk);
            let Some(i) = states.iter().find(|(_, m)| **m == got).map(|(i, _)| *i) else {
                panic!(
                    "seed {seed} round {round}: recovered state matches no allowed prefix {:?}",
                    states.keys()
                );
            };
            let mut m = states.remove(&i).expect("found");
            states.clear();
            states.insert(i, m.clone());
            let mut acked = Vec::new();
            let n = 200 + rng.below(600);
            for t in 1..=n {
                let txn = gen_txn(&mut rng, &mut m, t);
                states.insert(i + t, m.clone());
                if rng.below(40) == 0 {
                    // checkpoints at random points: the WAL floor must keep every op only in a memtable
                    s.request_checkpoint();
                }
                submit(&mut s, &mut clk, txn, &mut acked);
                acked.extend(poll(&mut s, &mut clk));
                states.retain(|&k, _| k >= i + acked.len() as u64);
            }
            // crash after a random number of further polls (jobs and checkpoints in flight)
            for _ in 0..rng.below(40) {
                acked.extend(poll(&mut s, &mut clk));
            }
            states.retain(|&k, _| k >= i + acked.len() as u64);
            img = disk.crash_image(CrashPolicy::MIXED);
        }
    }
}

#[test]
fn store_without_the_feature_refuses_omap_lsm_ops() {
    let (img, sim) = format(false);
    let (_d, mut clk, mut s) = mount(&img, &sim, 3);
    assert!(s.olsm_stats().is_none());
    let mut t: Txn<Vec<u8>> = Txn::new(1);
    let (n, blob) = put_blob(&[(b"a".to_vec(), b"b".to_vec())]);
    t.ops.push(Op::Omap(OOp::Put { id: 1, n, blob }));
    assert!(matches!(s.submit(t), Err((StoreError::Invalid(_), _))));
    assert!(matches!(
        s.olsm_get(None, 1, b"a"),
        Err(StoreError::Invalid(_))
    ));
    poll(&mut s, &mut clk);
}

/// Bursts of `burst` txns between polls against a tight device pipeline (`ready_cap` / `max_inflight_units` 1) on a ring of
/// `wal` blocks; every txn is eventually admitted, the engine flushes and the contents match the model.
fn run_bursts(wal: u64, burst: u64, ready_cap: usize) -> store::shard::OlsmStats {
    let (img, sim) = format_wal(true, wal);
    let c = ShardCfg {
        max_inflight_units: 1,
        ready_cap,
        ..cfg()
    };
    let (_disk, mut clk, mut s) = mount_cfg(&img, &sim, 3, c);
    let mut rng = Rng::new(11);
    let mut m = Model::new();
    let mut acked = Vec::new();
    let n = 3000;
    for t in 1..=n {
        let txn = gen_txn(&mut rng, &mut m, t);
        submit(&mut s, &mut clk, txn, &mut acked);
        if t % burst == 0 {
            acked.extend(poll(&mut s, &mut clk));
        }
    }
    settle(&mut s, &mut clk, &mut acked, n);
    assert_eq!(dump(&mut s, &mut clk), m);
    s.olsm_stats().expect("engine on")
}

/// A manifest txn refused for a full WAL pipeline (`ready_cap` 1: client units queue behind the one in flight) gets
/// its run extents back and the resubmit commits them (regression: the hand-back indexed the pre-write claims with the
/// run extents and panicked, lab G1 fill cell 2026-10-27).
#[test]
fn refused_manifest_txns_keep_their_run_extents() {
    let st = run_bursts(768, 20, 1);
    assert!(
        st.flushes >= 8 && st.man_retries >= 1,
        "refusals exercised: {st:?}"
    );
}

/// Small rings (the smallest a txn of these tests fits) never starve the flush: admission leaves the manifest txn the room its own admission needs, and ring
/// pressure freezes the memtable that holds the floor (regressions: a burst left the manifest 31 of 32 blocks and it
/// retried forever; with the ring below the size trigger of the memtables clients were never admitted again).
#[test]
fn small_rings_keep_flushing() {
    for (wal, burst) in [(96, 1), (96, 20), (96, 200), (192, 200)] {
        let st = run_bursts(wal, burst, 32);
        assert!(st.flushes >= 1, "wal {wal} burst {burst}: {st:?}");
    }
}

#[test]
fn small_rings_keep_flushing_with_helpers() {
    use_helper(17, false);
    for (wal, burst) in [(96, 1), (96, 200), (192, 200)] {
        let st = run_bursts(wal, burst, 32);
        assert!(st.flushes >= 1, "wal {wal} burst {burst}: {st:?}");
    }
}

/// Lab cell "ls" shape (G1 2026-10-27: OSDs failed with a parked txn never woken): one hot object pre-filled with
/// `pre` keys, `clients` clients each alternating a 256-key set of new keys and the removal of its own oldest 256
/// keys, all clients' txns submitted between two polls (QD1 each), every txn with PG-meta-like tree puts (log entry,
/// info). Every txn is admitted (`submit` panics after 100k refused polls) and the contents match the model.
fn hot_object_run(
    pre: u64,
    clients: u64,
    rounds: u64,
    wal: u64,
    vlen: usize,
    qd: usize,
    c: ShardCfg,
) -> store::shard::OlsmStats {
    let mut sim = SimConfig::new(1 << 30);
    sim.queue_depth = qd;
    let (img, sim) = format_sim(true, wal, sim);
    let (_disk, mut clk, mut s) = mount_cfg(&img, &sim, 3, c);
    let mut m = Model::new();
    let mut acked = Vec::new();
    let mut tok = 0;
    let val = |i: u64| vec![(i % 251) as u8; vlen];
    let hk = |c: u64, i: u64| format!("c{c:03}-{i:08}").into_bytes();
    for b in 0..pre.div_ceil(256) {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (b * 256..((b + 1) * 256).min(pre))
            .map(|i| (format!("pre-{i:08}").into_bytes(), val(i)))
            .collect();
        for (k, v) in &pairs {
            m.insert((1, k.clone()), v.clone());
        }
        let (n, blob) = put_blob(&pairs);
        tok += 1;
        let mut t = Txn::new(tok);
        t.ops.push(Op::Omap(OOp::Put { id: 1, n, blob }));
        submit(&mut s, &mut clk, t, &mut acked);
        acked.extend(poll(&mut s, &mut clk));
    }
    // per client: next key to insert, oldest key still present
    let mut cl: Vec<(u64, u64)> = vec![(0, 0); clients as usize];
    for r in 0..rounds {
        for c in 0..clients {
            let (next, old) = &mut cl[c as usize];
            let op = if r % 2 == 0 || *old == *next {
                let pairs: Vec<(Vec<u8>, Vec<u8>)> =
                    (*next..*next + 256).map(|i| (hk(c, i), val(i))).collect();
                *next += 256;
                for (k, v) in &pairs {
                    m.insert((1, k.clone()), v.clone());
                }
                let (n, blob) = put_blob(&pairs);
                OOp::Put { id: 1, n, blob }
            } else {
                let keys: Vec<Vec<u8>> = (*old..*old + 256).map(|i| hk(c, i)).collect();
                *old += 256;
                for k in &keys {
                    m.remove(&(1, k.clone()));
                }
                OOp::Del {
                    id: 1,
                    blob: del_blob(&keys),
                }
            };
            tok += 1;
            let mut t = Txn::new(tok);
            t.ops.push(Op::Put(
                format!("pglog-{:012}", tok).into_bytes(),
                vec![7; 180],
            ));
            t.ops
                .push(Op::Put(b"pginfo".to_vec(), tok.to_le_bytes().to_vec()));
            t.ops.push(Op::Omap(op));
            submit(&mut s, &mut clk, t, &mut acked);
        }
        acked.extend(poll(&mut s, &mut clk));
    }
    settle(&mut s, &mut clk, &mut acked, tok);
    assert_eq!(dump(&mut s, &mut clk), m);
    s.olsm_stats().expect("engine on")
}

#[test]
fn hot_object_set_rm_keeps_admitting() {
    let st = hot_object_run(20_000, 64, 200, 2048, 64, 128, cfg());
    assert!(st.flushes >= 8 && st.merges >= 1, "{st:?}");
}

#[test]
fn hot_object_set_rm_keeps_admitting_with_helpers() {
    use_helper(23, false);
    let st = hot_object_run(20_000, 64, 200, 2048, 64, 128, cfg());
    assert!(
        st.flushes >= 8 && st.merges >= 1 && st.helper_rounds > 0,
        "{st:?}"
    );
}

/// Bursts of tree-only txns (no omap op: never throttled by the memtables) beside flushes whose manifest txns span
/// several WAL units (per-block crcs of the output, small units): the manifests are admitted, every txn commits.
#[test]
fn tree_txns_beside_multi_unit_flush_manifests() {
    let c = ShardCfg {
        cache_pages: 131072,
        max_unit_blocks: 2,
        ..cfg()
    };
    let mut sim = SimConfig::new(1 << 30);
    sim.queue_depth = 64;
    let (img, sim) = format_sim(true, 65536, sim);
    let (_disk, mut clk, mut s) = mount_cfg(&img, &sim, 3, c);
    let mut m = Model::new();
    let mut acked = Vec::new();
    let mut tok = 0;
    for b in 0..640u64 {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (b * 256..(b + 1) * 256)
            .map(|i| (format!("k-{i:08}").into_bytes(), vec![(i % 251) as u8; 300]))
            .collect();
        for (k, v) in &pairs {
            m.insert((1, k.clone()), v.clone());
        }
        let (n, blob) = put_blob(&pairs);
        tok += 1;
        let mut t = Txn::new(tok);
        t.ops.push(Op::Omap(OOp::Put { id: 1, n, blob }));
        submit(&mut s, &mut clk, t, &mut acked);
        for i in 0..(if b < 600 { 0 } else { 4000u64 }) {
            tok += 1;
            let mut t = Txn::new(tok);
            t.ops.push(Op::Put(
                format!("t-{:04}", (b * 4000 + i) % 4096).into_bytes(),
                vec![9; 1500],
            ));
            submit(&mut s, &mut clk, t, &mut acked);
        }
        acked.extend(poll(&mut s, &mut clk));
    }
    settle(&mut s, &mut clk, &mut acked, tok);
    assert_eq!(dump(&mut s, &mut clk), m);
    let st = s.olsm_stats().expect("engine on");
    assert!(st.flushes >= 1, "{st:?}");
}

/// Lab cell "ls" (G1 2026-10-27, build 4d37c07c40): with one job slot a long merge blocked the freeze, so the memtable
/// throttle (frozen memtable in flight) never engaged; the active memtable grew until it pinned the whole ring and the
/// manifest txns behind it no longer found ring room: no IO, a parked txn timed out. A merge that stays on a helper
/// core (here: never returned while the clients write) must not stop flushes: every client txn is admitted, the ring
/// floor keeps moving, and the merge's manifest still commits once it returns.
#[test]
fn a_long_merge_never_blocks_flushes() {
    let c = ShardCfg {
        cache_pages: 4096,
        ..cfg()
    };
    let mut sim = SimConfig::new(1 << 30);
    sim.queue_depth = 128;
    let (img, sim) = format_sim(true, 4096, sim);
    let (_disk, mut clk, mut s) = mount_cfg(&img, &sim, 3, c);
    let mut m = Model::new();
    let mut acked = Vec::new();
    let mut held: Option<HelperJob> = None;
    let mut flushes_held = 0;
    let mut tok = 0;
    for b in 0..1500u64 {
        // helper core: flush rounds run to their end at once; the first merge round stays out
        s.compaction_helpers(true, 1);
        while let Some(mut j) = s.take_compaction(true) {
            while !j.step(256) {}
            assert!(s.return_compaction(j, true));
        }
        if held.is_none() {
            held = s.take_compaction(false);
        }
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (b * 64..(b + 1) * 64)
            .map(|i| {
                (
                    format!("k-{:08}", i % 20_000).into_bytes(),
                    vec![(i % 251) as u8; 300],
                )
            })
            .collect();
        for (k, v) in &pairs {
            m.insert((1, k.clone()), v.clone());
        }
        let (n, blob) = put_blob(&pairs);
        tok += 1;
        let mut t = Txn::new(tok);
        t.ops.push(Op::Omap(OOp::Put { id: 1, n, blob }));
        submit(&mut s, &mut clk, t, &mut acked);
        let mut ev = Vec::new();
        s.poll(clk.t, &mut ev);
        clk.t += 10_000;
        for e in ev {
            match e {
                Event::Acked(t) => acked.push(t),
                Event::Failed(f) => panic!("shard failed: {f:?}"),
                _ => {}
            }
        }
        if held.is_some() {
            flushes_held = s.olsm_stats().expect("engine on").flushes;
        }
    }
    let mut j = held.expect("a merge was due");
    while !j.step(256) {}
    assert!(s.return_compaction(j, true));
    use_helper(5, false);
    settle(&mut s, &mut clk, &mut acked, tok);
    assert_eq!(dump(&mut s, &mut clk), m);
    let st = s.olsm_stats().expect("engine on");
    assert!(flushes_held >= 4 && st.merges >= 1, "{st:?}");
}

/// A shallow device queue (`nvme::set_queue_depth`, 2..=4096): the checkpoint writes above the same WAL floor as data
/// writes (at most half the queue), so it still runs and releases the ring.
#[test]
fn shallow_queue_still_checkpoints() {
    for qd in [8, 16, 32] {
        let st = hot_object_run(2_000, 16, 120, 1024, 64, qd, cfg());
        assert!(st.flushes >= 2, "qd {qd}: {st:?}");
    }
}

/// `by_keys` (adr 0610 (5), phase 2b): one engine pass returns exactly the point gets, present keys only and in the
/// requested order, also across flushed runs and the memtable.
#[test]
fn by_keys_batch_reads_match_point_gets() {
    let (img, sim) = format(true);
    let (_d, mut clk, mut s) = mount(&img, &sim, 5);
    let mut rng = Rng::new(11);
    let mut m = Model::new();
    let mut acked = Vec::new();
    for t in 1..=2000 {
        let txn = gen_txn(&mut rng, &mut m, t);
        submit(&mut s, &mut clk, txn, &mut acked);
        acked.extend(poll(&mut s, &mut clk));
    }
    settle(&mut s, &mut clk, &mut acked, 2000);
    assert!(s.olsm_stats().expect("engine on").flushes > 0);
    for id in 1..=OBJS {
        let mut keys: Vec<Vec<u8>> = (0..400).map(key).collect();
        keys.reverse(); // the batch keeps the caller's order
        keys.extend((900..940).map(key)); // absent keys are skipped
        let want: Vec<(Vec<u8>, Vec<u8>)> = keys
            .iter()
            .filter_map(|k| m.get(&(id, k.clone())).map(|v| (k.clone(), v.clone())))
            .collect();
        let kb: Vec<Bytes> = keys.iter().map(|k| Bytes::copy_from_slice(k)).collect();
        let got = loop {
            match s.olsm_by_keys(None, id, &kb) {
                Err(StoreError::Miss) => {
                    poll(&mut s, &mut clk);
                }
                r => break r.unwrap(),
            }
        };
        let got: Vec<(Vec<u8>, Vec<u8>)> = got
            .into_iter()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        assert_eq!(got, want, "by_keys of object {id}");
        for (k, v) in &want {
            assert_eq!(get(&mut s, &mut clk, id, k).as_ref(), Some(v));
        }
    }
}

/// `statfs` omap bytes (adr 0610 (6)) = device blocks of the live runs + both memtables, and 0 without the engine.
#[test]
fn statfs_omap_bytes_are_run_and_memtable_bytes() {
    let (img, sim) = format(true);
    let (_d, mut clk, mut s) = mount(&img, &sim, 6);
    let mut acked = Vec::new();
    // a small batch stays in the memtable: bytes counted, no run yet
    let mut t: Txn<Vec<u8>> = Txn::new(1);
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..10).map(|i| (key(i), vec![7u8; 40])).collect();
    let (n, blob) = put_blob(&pairs);
    t.ops.push(Op::Omap(OOp::Put { id: 1, n, blob }));
    submit(&mut s, &mut clk, t, &mut acked);
    settle(&mut s, &mut clk, &mut acked, 1);
    let st = s.olsm_stats().expect("engine on");
    assert_eq!(st.written_blocks, 0, "nothing flushed yet");
    let f = s.statfs();
    assert_eq!(f.omap_bytes, s.olsm_bytes().expect("engine on"));
    assert!(f.omap_bytes > 0, "the memtable bytes count");
    // a batch over the memtable soft size flushes: the run's device blocks count, the empty memtable adds nothing
    let mut t: Txn<Vec<u8>> = Txn::new(2);
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..5000).map(|i| (key(i), vec![9u8; 100])).collect();
    let (n, blob) = put_blob(&pairs);
    t.ops.push(Op::Omap(OOp::Put { id: 2, n, blob }));
    submit(&mut s, &mut clk, t, &mut acked);
    settle(&mut s, &mut clk, &mut acked, 2);
    for _ in 0..100_000 {
        if s.olsm_stats().expect("engine on").flushes > 0 {
            break;
        }
        acked.extend(poll(&mut s, &mut clk));
    }
    let st = s.olsm_stats().expect("engine on");
    assert!(st.flushes > 0, "the flush ran: {st:?}");
    assert_eq!(st.freed_blocks, 0, "no merge freed a run yet");
    let f = s.statfs();
    assert_eq!(f.omap_bytes, s.olsm_bytes().expect("engine on"));
    assert_eq!(
        f.omap_bytes,
        st.written_blocks * store::BLK as u64,
        "all written run blocks are live, the memtable is empty"
    );
    // a store without the engine reports 0 (tree omap is inside the used bytes)
    let (img, sim) = format(false);
    let (_d, _clk, s) = mount(&img, &sim, 7);
    assert_eq!(s.statfs().omap_bytes, 0);
}

/// Append + trim on one object: a live set of 16 MiB, then 4 x live of churn (each round sets 256 new keys and
/// deletes the oldest 256) with a 2 MiB flush unit. The old keys are tombstoned, so without garbage-driven merges the
/// LSM holds every version ever written (5 x live). Every txn is acked, the model matches, peak used stays
/// `<= 0.85 x region`, device writes per user byte stay `<= 5`, and no lease waits for space. The logical space
/// target drives background GC rather than a foreground ceiling: after bounded background progress, current used
/// reaches `1.3 x live + 3.2 x n0 + 0.05 x live + 64 KiB`; the churn's peak need not meet that logical target.
#[test]
fn append_trim_space_bounded() {
    let device = 256 << 20;
    let n0 = 2 << 20;
    // engine memory = cache_pages / 2 x node_size 8 KiB = 8 MiB -> n0 = mem / 4 = 2 MiB (the 64 MiB ring's
    // wal / 4 term is larger)
    let c = ShardCfg {
        cache_pages: 2048,
        ..ShardCfg::default()
    };
    let sim = SimConfig::new(device);
    let (img, sim) = format_sim(true, 16384, sim);
    let (_disk, mut clk, mut s) = mount_cfg(&img, &sim, 3, c);
    let per = 256u64;
    let vlen = 300usize;
    let mut m = Model::new();
    let mut acked = Vec::new();
    let mut tok = 0u64;
    let mut user_bytes = 0u64;
    let live_keys = ((16 << 20) / vlen) as u64;
    let rounds = 4 * live_keys / per;
    for b in 0..live_keys.div_ceil(per) {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (b * per..((b + 1) * per).min(live_keys))
            .map(|i| (key(i), vec![(i % 251) as u8; vlen]))
            .collect();
        for (k, v) in &pairs {
            m.insert((1, k.clone()), v.clone());
        }
        user_bytes += pairs.len() as u64 * vlen as u64;
        let (n, blob) = put_blob(&pairs);
        tok += 1;
        let mut t = Txn::new(tok);
        t.ops.push(Op::Omap(OOp::Put { id: 1, n, blob }));
        submit(&mut s, &mut clk, t, &mut acked);
        acked.extend(poll(&mut s, &mut clk));
    }
    // the highest `olsm_space_used_bytes` the churn reached (the bound holds throughout, not only at the end)
    let mut peak = 0u64;
    for r in 0..rounds {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..per)
            .map(|i| {
                let k = live_keys + r * per + i;
                (key(k), vec![(k % 251) as u8; vlen])
            })
            .collect();
        for (k, v) in &pairs {
            m.insert((1, k.clone()), v.clone());
        }
        user_bytes += pairs.len() as u64 * vlen as u64;
        let (n, blob) = put_blob(&pairs);
        tok += 1;
        let mut t = Txn::new(tok);
        t.ops.push(Op::Omap(OOp::Put { id: 1, n, blob }));
        submit(&mut s, &mut clk, t, &mut acked);
        let dead: Vec<Vec<u8>> = (r * per..(r + 1) * per).map(key).collect();
        for k in &dead {
            m.remove(&(1, k.clone()));
        }
        tok += 1;
        let mut t = Txn::new(tok);
        t.ops.push(Op::Omap(OOp::Del {
            id: 1,
            blob: del_blob(&dead),
        }));
        submit(&mut s, &mut clk, t, &mut acked);
        acked.extend(poll(&mut s, &mut clk));
        peak = peak.max(s.olsm_stats().expect("engine on").space_used_bytes);
    }
    settle(&mut s, &mut clk, &mut acked, tok);
    assert_eq!(acked.len() as u64, tok, "every txn acked");
    assert_eq!(dump(&mut s, &mut clk), m);
    let live_keys_n = live_keys * vlen as u64;
    // Preserve the former foreground ceiling as an eventual reclamation target. Ack settlement alone does not
    // wait for GC; explicitly allow bounded background progress without admitting any further user writes.
    let bound = live_keys_n * 13 / 10 + n0 * 32 / 10 + live_keys_n / 20 + (64 << 10);
    for _ in 0..100_000 {
        let used = s.olsm_stats().expect("engine on").space_used_bytes;
        peak = peak.max(used);
        if used <= bound {
            break;
        }
        acked.extend(poll(&mut s, &mut clk));
    }
    let st = s.olsm_stats().expect("engine on");
    let live = st.space_live_bytes;
    let used = st.space_used_bytes.max(peak);
    assert!(
        st.space_used_bytes <= bound,
        "background GC did not reach {bound}: current {} (logical live {live_keys_n}, gauge live {live})",
        st.space_used_bytes
    );
    assert!(used * 100 <= device * 85, "used {used} of {device}");
    let wa = s.stats.dev_write_bytes as f64 / user_bytes as f64;
    eprintln!(
        "append_trim: peak used {used} end used {} live {live} logical_live {live_keys_n} peak used/live {:.2} space_throttled {} \
         WA {wa:.2} \
         garbage {} alloc_waits {} flushes {} merges {} gc_merges {} chunks_lt16 {} runs {}",
        st.space_used_bytes,
        used as f64 / live_keys_n as f64,
        st.space_throttled,
        st.space_garbage_bytes,
        st.alloc_waits,
        st.flushes,
        st.merges,
        st.gc_merges,
        st.chunks_lt16,
        st.runs
    );
    assert!(st.gc_merges >= 1, "GC ran: {st:?}");
    assert_eq!(st.alloc_waits, 0, "no lease waited for space: {st:?}");
    assert!(wa <= 5.0, "device writes per user byte {wa:.2}");
}

/// A run set of 4 append runs, then a range tombstone over the oldest half: the tier-0 group holds fewer than `FAN`
/// runs (the size-tiered policy would not merge it), so the pick must be the GC arm, its output at most 0.7 x input,
/// and at least 90 % of the fence-only garbage gone after install. A shard run of the same shape proves the counter
/// path (`olsm_gc_merges`).
#[test]
fn gc_merge_reclaims_tombstones() {
    // Pure run set: 4 runs of one object, increasing keys, 300 B values.
    let mut dev = MemBlocks::new();
    let mut man = Manifest::new(1 << 20);
    let (runs, per) = (4u64, 1000u64);
    let mut lsn = 0u64;
    for r in 0..runs {
        let mut mem = Memtable::new();
        for i in 0..per {
            lsn += 1;
            mem.put(
                lsn,
                1,
                key(r * per + i).into(),
                vec![(i % 251) as u8; 300].into(),
            );
        }
        let id = man.alloc_run_id();
        let (run, _) = job::flush(&mem, id, &mut dev).unwrap().unwrap();
        man.install_flush(Arc::new(run), lsn);
    }
    let input: u64 = man.runs().map(|r| r.data_bytes()).sum();
    // Range tombstone over the oldest half (keys are 5 decimal digits, so the boundary sorts as a key).
    let mut mem = Memtable::new();
    lsn += 1;
    mem.del_range(lsn, 1, key(0).into(), Some(key(runs * per / 2).into()));
    let id = man.alloc_run_id();
    let (run, _) = job::flush(&mem, id, &mut dev).unwrap().unwrap();
    man.install_flush(Arc::new(run), lsn);
    let before = man.garbage(&man.space());
    let p = man.pick_merge(false).expect("a merge is due");
    assert!(p.gc && p.src_tier == 0, "GC pick expected: {p:?}");
    let inputs = p.inputs.clone();
    let out = job::merge(p, &mut dev).unwrap();
    let output: u64 = out.runs.iter().map(|r| r.data_bytes()).sum();
    assert!(output * 10 <= input * 7, "output {output} of input {input}");
    man.install_gc_prefix(&inputs, out.runs, out.residuals);
    let after = man.garbage(&man.space());
    assert!(
        after * 10 <= before,
        "garbage {after} of {before} not reclaimed"
    );

    // Counter path: the same shape on a shard (6 x n0 append runs, a range over the oldest half, then two more flushes)
    // installs at least one garbage-driven merge (`olsm_gc_merges`).
    let c = ShardCfg {
        cache_pages: 2048,
        ..ShardCfg::default()
    };
    let sim = SimConfig::new(64 << 20);
    let (img, sim) = format_sim(true, 2048, sim);
    let (_disk, mut clk, mut s) = mount_cfg(&img, &sim, 3, c);
    let mut acked = Vec::new();
    let mut tok = 0u64;
    let batch = 7000u64;
    let put_batch =
        |s: &mut Shard<SimDev>, clk: &mut SimClock, acked: &mut Vec<u64>, tok: &mut u64, b: u64| {
            let pairs: Vec<(Vec<u8>, Vec<u8>)> = (b * batch..(b + 1) * batch)
                .map(|i| (key(i), vec![(i % 251) as u8; 300]))
                .collect();
            let (n, blob) = put_blob(&pairs);
            *tok += 1;
            let mut t = Txn::new(*tok);
            t.ops.push(Op::Omap(OOp::Put { id: 1, n, blob }));
            submit(s, clk, t, acked);
            acked.extend(poll(s, clk));
        };
    for b in 0..6 {
        put_batch(&mut s, &mut clk, &mut acked, &mut tok, b);
    }
    tok += 1;
    let mut t = Txn::new(tok);
    t.ops.push(Op::Omap(OOp::Range {
        id: 1,
        first: key(0).into(),
        end: Some(key(batch * 3).into()),
    }));
    submit(&mut s, &mut clk, t, &mut acked);
    for b in 6..8 {
        put_batch(&mut s, &mut clk, &mut acked, &mut tok, b);
    }
    settle(&mut s, &mut clk, &mut acked, tok);
    let st = s.olsm_stats().expect("engine on");
    assert!(st.gc_merges >= 1, "garbage-driven merge installed: {st:?}");
}

/// Free lease pieces of 3+1 blocks alternate (the shape a churned region reports after coalescing): the flush must
/// seal 4-block chunks instead of failing the old 16-block request. No allocation wait: the flush completes; every
/// chunk reads back with its entries.
struct FragBlocks {
    data: BTreeMap<u64, bytes::Bytes>,
    free: Vec<(u64, u32)>,
    short: u64,
}

impl BlockSink for FragBlocks {
    fn alloc(&mut self, nblk: u32) -> Result<u64, StoreError> {
        let i = self
            .free
            .iter()
            .position(|x| x.1 >= nblk)
            .ok_or(StoreError::Busy)?;
        let (b, n) = self.free[i];
        if n == nblk {
            self.free.remove(i);
        } else {
            self.free[i] = (b + u64::from(nblk), n - nblk);
        }
        Ok(b)
    }
    fn write(&mut self, blk: u64, data: Vec<u8>, _crcs: &[u32]) -> Result<(), StoreError> {
        assert_eq!(data.len() % 4096, 0);
        self.data.insert(blk, data.into());
        Ok(())
    }
    fn sync(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
    fn room(&self) -> u32 {
        self.free.iter().map(|x| x.1).max().unwrap_or(0)
    }
    fn chunk(&mut self, nblk: u32) {
        if nblk < CHUNK_MAX {
            self.short += 1;
        }
    }
}

impl ChunkRead for FragBlocks {
    fn read(&mut self, blk: u64, nblk: u32) -> Result<bytes::Bytes, StoreError> {
        let data = self
            .data
            .get(&blk)
            .ok_or(StoreError::Invalid("read of an unwritten extent"))?;
        let len = nblk as usize * 4096;
        assert!(len <= data.len(), "read beyond the written extent");
        Ok(data.slice(..len))
    }
}

#[test]
fn chunks_fit_fragmented_space() {
    // 32 pieces of 4 blocks: two alternating free extents of 3 and 1 block that coalesced.
    let free = (0..32u64).map(|i| (i * 8, 4)).collect();
    let mut dev = FragBlocks {
        data: BTreeMap::new(),
        free,
        short: 0,
    };
    let mut mem = Memtable::new();
    for i in 0..300u64 {
        mem.put(i + 1, 1, key(i).into(), vec![(i % 251) as u8; 200].into());
    }
    let (run, _) = job::flush(&mem, 1, &mut dev)
        .unwrap()
        .expect("a non-empty flush completes without an allocation wait");
    assert!(dev.short > 0, "short chunks written");
    assert!(
        run.fences
            .iter()
            .all(|f| f.nblk >= CHUNK_MIN && f.nblk < CHUNK_MAX),
        "chunks fit the pieces: {:?}",
        run.fences.iter().map(|f| f.nblk).collect::<Vec<_>>()
    );
    let mut got = Vec::new();
    for i in 0..run.fences.len() {
        let c = load_chunk(&mut dev, &run, i).unwrap();
        for j in 0..c.len() {
            got.push((
                c.id(j),
                c.key(j).to_vec(),
                c.val_slice(j).map(|v| v.to_vec()),
            ));
        }
    }
    assert_eq!(got.len(), 300, "every entry in a chunk");
    for (i, (id, k, v)) in got.iter().enumerate() {
        assert_eq!(*id, 1);
        assert_eq!(k, &key(i as u64));
        assert_eq!(v.as_deref(), Some(&vec![(i % 251) as u8; 200][..]));
    }
}

/// A garbage-driven merge on the merge slot must not delay flushes: append + trim (live 32768 keys, 10 MB) on a
/// simulated helper; once the trim runs and the merges caught up, the helper stops taking merge rounds (a merge in
/// flight waits) until the flush slot completed two more flushes. Every txn acked, the model matches, a GC merge
/// installed. (The live set leaves the space target room for two flushes of garbage: above the target, admission
/// waits for the running merge, adr 0610 am. 5.)
#[test]
fn gc_merge_never_delays_flushes() {
    let c = ShardCfg {
        cache_pages: 512,
        ..cfg()
    };
    let mut sim = SimConfig::new(64 << 20);
    sim.queue_depth = 64;
    let (img, sim) = format_sim(true, 4096, sim);
    let (_disk, mut clk, mut s) = mount_cfg(&img, &sim, 3, c);
    use_helper(7, false);
    let mut m = Model::new();
    let mut acked = Vec::new();
    let mut tok = 0u64;
    // flushes completed when the merges were held, and while they were
    let mut held_at: Option<u64> = None;
    let mut flushes_held = 0;
    let live = 32768u64;
    for b in 0..1000u64 {
        let st = s.olsm_stats().expect("engine on");
        match held_at {
            None if flushes_held == 0
                && b * 64 >= live
                && st.merges > 0
                && st.space_garbage_bytes * 10 < st.space_live_bytes =>
            {
                hold_merges(true);
                held_at = Some(st.flushes);
            }
            Some(f) if st.flushes >= f + 2 => {
                flushes_held = st.flushes - f;
                hold_merges(false);
                held_at = None;
            }
            _ => {}
        }
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = (b * 64..(b + 1) * 64)
            .map(|k| (key(k), vec![(k % 251) as u8; 300]))
            .collect();
        for (k, v) in &pairs {
            m.insert((1, k.clone()), v.clone());
        }
        let (n, blob) = put_blob(&pairs);
        tok += 1;
        let mut t = Txn::new(tok);
        t.ops.push(Op::Omap(OOp::Put { id: 1, n, blob }));
        if b * 64 >= live {
            let dead: Vec<Vec<u8>> = (b * 64 - live..(b + 1) * 64 - live).map(key).collect();
            for k in &dead {
                m.remove(&(1, k.clone()));
            }
            t.ops.push(Op::Omap(OOp::Del {
                id: 1,
                blob: del_blob(&dead),
            }));
        }
        submit(&mut s, &mut clk, t, &mut acked);
        acked.extend(poll(&mut s, &mut clk));
    }
    assert!(held_at.is_none(), "the merges were released");
    settle(&mut s, &mut clk, &mut acked, tok);
    assert_eq!(dump(&mut s, &mut clk), m);
    let st = s.olsm_stats().expect("engine on");
    assert!(
        flushes_held >= 2 && st.gc_merges >= 1,
        "flushes while the merges were held {flushes_held}, gc {}: {st:?}",
        st.gc_merges
    );
}

/// Real shard cache/device path: speculative completions feed exact pages while another object's point reads run.
#[test]
fn scan_prefetch_pages_match_model_while_point_reads_progress() {
    scan_prefetch_model(false);
}

#[test]
fn scan_prefetch_adaptive_pages_match_model_while_point_reads_progress() {
    scan_prefetch_model(true);
}

fn scan_prefetch_model(adaptive_mode: bool) {
    for (seal_at_flush, chunks, adaptive) in [
        (false, 1, false),
        (true, 1, false),
        (false, 4, false),
        (true, 4, false),
        (false, 4, true),
        (true, 4, true),
    ] {
        if adaptive != adaptive_mode {
            continue;
        }
        let mut sim = SimConfig::new(64 << 20);
        sim.submit_at_flush = seal_at_flush; // shared SPDK/kernel submission behavior
        sim.max_xfer_lbas = 4; // chunks split across several device slots
        // a DMA-pool device lends no tree budget: the run cache is exactly its own quarter of the share (the quota below)
        sim.ram_reads = false;
        let (img, sim) = format_sim(true, 2048, sim);
        let (_disk, mut clk, mut s) = mount_cfg(
            &img,
            &sim,
            23,
            ShardCfg {
                cache_pages: 384,
                omap_scan_prefetch: true,
                omap_scan_prefetch_chunks: chunks,
                omap_scan_prefetch_adaptive: adaptive,
                omap_scan_prefetch_max_chunks: 4,
                ..cfg()
            },
        );
        // Upgrade batches inherit the last committed sequence; zero denotes an empty memtable.
        let mut seed = Txn::new(1);
        seed.ops
            .push(Op::Put(b"scan-seed".to_vec(), b"seed".to_vec()));
        let mut acked = Vec::new();
        submit(&mut s, &mut clk, seed, &mut acked);
        settle(&mut s, &mut clk, &mut acked, 1);
        let mut want = Vec::new();
        for round in 0..3u32 {
            let mut batch: Vec<_> = (0..1200u32)
                .map(|i| {
                    let k = Bytes::from(format!("a/{:06}", i * 3 + round));
                    let v = Bytes::from(vec![round as u8; 200]);
                    want.push((k.clone(), v.clone()));
                    (1, k, v)
                })
                .collect();
            batch.push((
                2,
                Bytes::from_static(b"point"),
                Bytes::from(vec![round as u8; 200]),
            ));
            s.olsm_upgrade_batch(batch).unwrap();
            for _ in 0..100_000 {
                poll(&mut s, &mut clk);
                if s.olsm_flushed() {
                    break;
                }
            }
            assert!(s.olsm_flushed(), "batch flush did not finish");
        }
        want.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        s.olsm_drop_cache();
        let mut from = Bytes::new();
        let mut excl = false;
        let mut got = Vec::new();
        loop {
            let mut result = None;
            for _ in 0..100_000 {
                match s.olsm_list(None, 1, &from, excl, b"a/", 37) {
                    Err(StoreError::Miss) => {
                        poll(&mut s, &mut clk);
                    }
                    r => {
                        result = Some(r.unwrap());
                        break;
                    }
                }
            }
            let (page, more) = result.expect("scan page must make progress beside speculation");
            from = page.last().unwrap().0.clone();
            excl = true;
            got.extend(page);
            // Advance asynchronous speculative completions independently from the next page's demand misses.
            poll(&mut s, &mut clk);
            let mut point = None;
            for _ in 0..100_000 {
                match s.olsm_get(None, 2, b"point") {
                    Err(StoreError::Miss) => {
                        poll(&mut s, &mut clk);
                    }
                    r => {
                        point = Some(r.unwrap());
                        break;
                    }
                }
            }
            assert_eq!(point.flatten().as_deref(), Some(&[2u8; 200][..]));
            let st = s.olsm_stats().unwrap();
            // 384 cache pages / 2 engine / 2 run cache / 4 speculation, at 8 KiB per page.
            assert!(
                st.scan_prefetch.inflight_bytes + st.scan_prefetch.resident_bytes
                    <= 384 * 8192 / 16
            );
            if !more {
                break;
            }
        }
        assert_eq!(got, want);
        let st = s.olsm_stats().unwrap();
        assert!(st.scan_prefetch.submitted > 0, "{st:?}");
        assert!(st.scan_prefetch.useful > 0, "{st:?}");
    }
}
