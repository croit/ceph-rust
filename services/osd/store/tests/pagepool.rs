// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Tree page budget per device (adr 0062 am. 3, `store::pagepool`): one object's omap working set is larger than its
//! shard's even share of the tree page cache but fits the device's budget. On a store of several shards the idle shards
//! give their share over and repeated reads of the set stop missing; on a one-shard store with the same per-shard cache
//! (the even share alone) they keep missing.
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use std::time::Instant;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::txn::Bytes;
use store::obj::{MIN_CACHE_PAGES, OTxn, Store, StoreCfg, TOp, shard_of_spg};
use store::rng::Rng;

type St = Store<SimDev, SimClock>;

/// Tree pages (4 KiB) per shard: above `MIN_CACHE_PAGES`, so an idle shard has pages to give.
const BASE: usize = 2 * MIN_CACHE_PAGES;
const SHARDS: u32 = 4;
/// Omap keys of 1000 B values: ~19k tree pages, between `BASE` and what the device's pool lets one shard hold
/// (`SHARDS x BASE - (SHARDS - 1) x MIN_CACHE_PAGES` = 20480).
const KEYS: u32 = 54_000;
const PER_OP: usize = 64;

fn identity() -> (CollT, Ghobject) {
    (
        CollT::Pg(SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        }),
        Ghobject::new(
            Hobject::new(b"pagepool-hot", SnapId::NOSNAP, 0, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        ),
    )
}

fn key(i: u32) -> Vec<u8> {
    format!("key-{i:08}").into_bytes()
}

fn value(i: u32) -> Vec<u8> {
    let mut v = vec![0; 1000];
    store::rng::Rng::new(u64::from(i) ^ 0x7061_6765).fill(&mut v);
    v
}

fn durable(st: &mut St, t: &OTxn, token: u64) {
    st.queue(t, token).unwrap();
    for _ in 0..200_000 {
        st.clk.t += 10_000;
        let mut done = Vec::new();
        st.poll(&mut done).unwrap();
        let mut errors = Vec::new();
        st.take_queue_errors(&mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        if done.contains(&token) {
            return;
        }
        st.idle();
    }
    panic!("bounded queued transaction did not finish");
}

/// A store of `shards` shards on a SimDisk of `disk` bytes, every shard sized with `base` tree pages; every read and
/// write goes to the tree (no point-key cache, no omap runs). Returns it and the shard of the object's PG.
fn store(shards: u32, base: usize, disk: u64) -> (St, usize) {
    let disk = SimDisk::new(SimConfig::new(disk));
    mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards,
            wal_blocks: 8192,
            align_blocks: 1,
            node_size: 4096,
            ..Default::default()
        },
    )
    .unwrap();
    let mut cfg = StoreCfg::default();
    cfg.shard.cache_pages = base;
    cfg.shard.dirty_soft_pages = base / 8;
    cfg.shard.dirty_hard_pages = base * 3 / 8;
    cfg.shard.point_cache = 0;
    cfg.shard.run_soft_bytes = 0;
    let d = disk.clone();
    let st = Store::mount(move || d.queue(), SimClock::default(), cfg)
        .unwrap()
        .0;
    (st, shard_of_spg(1, 0, shards))
}

/// Create the object and set keys `0..keys`, `PER_OP` per transaction, then checkpoint.
fn fill(st: &mut St, keys: u32) {
    let (cid, oid) = identity();
    let mut init = OTxn::new();
    init.mkcoll(cid);
    init.touch(cid, &oid);
    st.commit(&init).unwrap();
    let ids: Vec<u32> = (0..keys).collect();
    for (n, c) in ids.chunks(PER_OP).enumerate() {
        let mut t = OTxn::new();
        t.push(TOp::OmapSetKeys {
            cid,
            oid: oid.clone(),
            pairs: c
                .iter()
                .map(|&i| (Bytes::Owned(key(i)), Bytes::Owned(value(i))))
                .collect(),
        });
        durable(st, &t, 100 + n as u64);
    }
    st.checkpoint().unwrap();
}

/// Fill the object on a store of `shards` shards, then read every key in random order, `PER_OP` keys per read with a
/// store poll after each (the store sweep exchanges the page budget every `SWEEP_NS` of store time), three passes.
/// Returns the hot shard's tree page loads per key of the last pass, its resident pages, and the budgets of all shards.
fn last_pass(shards: u32) -> (f64, usize, Vec<usize>) {
    let (mut st, hot) = store(shards, BASE, 1 << 30);
    fill(&mut st, KEYS);
    let (cid, oid) = identity();
    let mut order: Vec<u32> = (0..KEYS).collect();
    let mut rng = store::rng::Rng::new(7);
    for i in (1..order.len()).rev() {
        order.swap(i, rng.below(i as u64 + 1) as usize);
    }
    let mut per_key = 0.0;
    for _ in 0..3 {
        let l0 = st.shards[hot].sh.tree_stats().loads;
        for c in order.chunks(PER_OP) {
            let ks: Vec<Vec<u8>> = c.iter().map(|&i| key(i)).collect();
            let refs: Vec<&[u8]> = ks.iter().map(Vec::as_slice).collect();
            let got = st.omap_get(&cid, &oid, &refs).unwrap();
            assert_eq!(got.len(), c.len());
            assert_eq!(got.get(&key(c[0])), Some(&value(c[0])));
            st.clk.t += 100_000;
            st.poll(&mut Vec::new()).unwrap();
        }
        per_key = (st.shards[hot].sh.tree_stats().loads - l0) as f64 / f64::from(KEYS);
    }
    let caps = st
        .shards
        .iter()
        .map(|s| s.sh.page_gauges().0 as usize)
        .collect();
    let resident = st.shards[hot].sh.state().tree.resident_pages();
    println!("shards={shards} resident={resident} last-pass loads/key={per_key:.4} caps={caps:?}");
    (per_key, resident, caps)
}

#[test]
fn a_working_set_above_the_even_share_stops_missing() {
    let (even, _, caps) = last_pass(1);
    assert_eq!(caps, [BASE], "one shard: nothing to exchange");
    assert!(even > 0.2, "the even share alone keeps missing: {even}");
    let (pooled, held, caps) = last_pass(SHARDS);
    assert!(
        held > BASE + BASE / 2,
        "the hot shard holds more than its share: {held}"
    );
    assert!(
        caps.iter().all(|&c| c >= MIN_CACHE_PAGES),
        "no shard below the floor: {caps:?}"
    );
    assert!(
        caps.iter().sum::<usize>() <= SHARDS as usize * BASE,
        "the device budget never grows: {caps:?}"
    );
    assert!(pooled < 0.01, "the pooled budget holds the set: {pooled}");
    assert!(pooled * 20.0 < even, "misses drop: {pooled} vs {even}");
}

/// Eviction cost of the hot shard under random `PER_OP`-key updates of a working set larger than its cache (every op
/// loads leaves and evicts as many): CLOCK hand steps per eviction over the run, and one timed
/// [`store::tree::Tree::age`] pass over the full cache (wall ns and steps per evicted page; the run's wall time is the
/// simulator's, not the eviction's).
struct Cost {
    cap: usize,
    loads_per_op: f64,
    steps_per_eviction: f64,
    age_ns_per_eviction: f64,
    age_steps_per_eviction: f64,
}

fn update_cost(shards: u32, base: usize, keys: u32, ops: u64) -> Cost {
    let (mut st, hot) = store(shards, base, 16 << 30);
    fill(&mut st, keys);
    let (cid, oid) = identity();
    let mut rng = Rng::new(11);
    let mut update = |st: &mut St, n: u64| {
        let pairs = (0..PER_OP)
            .map(|_| {
                let i = rng.below(u64::from(keys)) as u32;
                (
                    Bytes::Owned(key(i)),
                    Bytes::Owned(value(i ^ (n as u32) << 20)),
                )
            })
            .collect();
        let mut t = OTxn::new();
        t.push(TOp::OmapSetKeys {
            cid,
            oid: oid.clone(),
            pairs,
        });
        durable(st, &t, 1_000_000 + n);
    };
    // warm-up: the cache fills and the hot shard's budget settles
    for n in 0..ops / 2 {
        update(&mut st, n);
    }
    let s0 = st.shards[hot].sh.tree_stats();
    for n in ops / 2..ops + ops / 2 {
        update(&mut st, n);
    }
    let s1 = st.shards[hot].sh.tree_stats();
    let tree = &mut st.shards[hot].sh.state_mut().tree;
    let cap = tree.cap();
    let w = Instant::now();
    let aged = tree.age(tree.slots(), cap / 16).max(1) as f64;
    let age_ns = w.elapsed().as_nanos() as f64;
    let s2 = st.shards[hot].sh.tree_stats();
    let c = Cost {
        cap,
        loads_per_op: (s1.loads - s0.loads) as f64 / ops as f64,
        steps_per_eviction: (s1.hand_steps - s0.hand_steps) as f64
            / (s1.evictions - s0.evictions).max(1) as f64,
        age_ns_per_eviction: age_ns / aged,
        age_steps_per_eviction: (s2.hand_steps - s1.hand_steps) as f64 / aged,
    };
    println!(
        "shards={shards} base={base} cap={} keys={keys} loads/op={:.1} steps/eviction={:.2} age: ns/eviction={:.1} \
         steps/eviction={:.2}",
        c.cap,
        c.loads_per_op,
        c.steps_per_eviction,
        c.age_ns_per_eviction,
        c.age_steps_per_eviction
    );
    c
}

/// The cost of an eviction does not grow with the cache: the CLOCK hand takes no more steps per evicted page on the hot
/// shard holding most of the device's budget than on the even share (the protect window and dirty pages it skips stay
/// the share's size while the cache grows), and the misses drop.
#[test]
fn eviction_steps_do_not_grow_with_the_cache() {
    let pooled = SHARDS as usize * BASE - (SHARDS as usize - 1) * MIN_CACHE_PAGES;
    let keys = (pooled * 3 * 3) as u32;
    let even = update_cost(1, BASE, keys, 2_000);
    let big = update_cost(SHARDS, BASE, keys, 2_000);
    assert!(
        big.cap > 2 * even.cap,
        "the hot shard holds most of the budget: {}",
        big.cap
    );
    assert!(
        big.steps_per_eviction <= even.steps_per_eviction,
        "steps per eviction {} (cap {}) vs {} (cap {})",
        big.steps_per_eviction,
        big.cap,
        even.steps_per_eviction,
        even.cap
    );
    assert!(
        big.steps_per_eviction < 4.0,
        "amortized O(1): {}",
        big.steps_per_eviction
    );
    assert!(big.loads_per_op < even.loads_per_op, "misses drop");
}

/// Measurement (release, `--ignored --nocapture`): eviction cost against the cache size at the even share (one shard)
/// and with the device's budget (6 shards, the hot one holds most of it), for two shares; working set ~3x the largest
/// cache. Numbers: doc/perf/tree-cache-demand-20261104.md.
#[test]
#[ignore = "measurement: run with --release --nocapture"]
fn eviction_cost_against_cache_size() {
    for base in [8192usize, 32768] {
        let pooled = 6 * base - 5 * MIN_CACHE_PAGES;
        let keys = (pooled * 3 * 3) as u32;
        update_cost(1, base, keys, 20_000);
        update_cost(6, base, keys, 20_000);
    }
}
