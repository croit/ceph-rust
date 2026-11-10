// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! PG stats source (adr/0609-pgstats-counters): `coll_stats` is an O(1) counter maintained at txn staging (omap totals
//! come from deep scrub, adr 0614). Gates: counters equal a full walk after random ops and a restart; reading them takes
//! no queue barrier while txns are parked; `microbench_stats_vs_walk` (release, ignored) prints the per-tick cost of the
//! counters vs a walk of an object with 1M omap keys.

use bytes::Bytes;
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use store::dev::{SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::layout::{MkfsParams, mkfs};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, Store, StoreCfg, TOp};

type St = Store<SimDev, SimClock>;

fn coll() -> CollT {
    CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    })
}

fn obj(i: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(format!("o{i}").as_bytes(), SnapId::NOSNAP, i, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn image(sim: &SimConfig) -> SimImage {
    let disk = SimDisk::new(sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = MkfsParams {
        shards: 1,
        wal_blocks: 1024,
        align_blocks: 1,
        ..Default::default()
    };
    mkfs(&mut dev, &mut clk, &p).unwrap();
    let (disk, mut st) = open(&disk.image(), sim);
    let mut t = OTxn::new();
    t.mkcoll(coll());
    st.commit(&t).unwrap();
    st.checkpoint().unwrap();
    disk.image()
}

fn open(img: &SimImage, sim: &SimConfig) -> (SimDisk, St) {
    let disk = SimDisk::from_image(img, sim.clone());
    let d2 = disk.clone();
    let (st, _) =
        Store::mount(move || d2.queue(), SimClock::default(), StoreCfg::default()).unwrap();
    (disk, st)
}

/// Full walk over the 24 test objects: (objects, bytes, omap keys, omap bytes) from per-object reads.
fn walk(st: &mut St) -> (u64, u64, u64, u64) {
    let mut a = (0, 0, 0, 0);
    for i in 1..=24 {
        let o = obj(i);
        let Some(s) = st.stat(&coll(), &o).unwrap() else {
            continue;
        };
        a.0 += 1;
        a.1 += s.size;
        let m = st.omap_all(&coll(), &o).unwrap();
        a.2 += m.len() as u64;
        a.3 += m
            .iter()
            .map(|(k, v)| (k.len() + v.len()) as u64)
            .sum::<u64>();
    }
    a
}

fn counters(st: &mut St) -> (u64, u64) {
    let s = st.coll_stats(&coll()).unwrap().unwrap();
    (s.nobj, s.nbytes)
}

#[test]
fn counters_equal_a_full_walk_after_random_ops_and_restart() {
    let mut sim = SimConfig::new(64 << 20);
    sim.seed = 5;
    let (disk, mut st) = open(&image(&sim), &sim);
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut rnd = move |m: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % m
    };
    for round in 0..400u32 {
        let o = obj(rnd(24) as u32 + 1);
        let key = format!("k{}", rnd(40)).into_bytes();
        let data = vec![round as u8; rnd(9000) as usize + 1];
        let off = rnd(5000);
        let mut t = OTxn::new();
        match rnd(6) {
            0 | 1 => {
                t.write(coll(), &o, off, &data);
            }
            2 => {
                t.omap_set(coll(), &o, &key, &data[..data.len().min(50)]);
            }
            3 => {
                t.push(TOp::OmapRmKeys {
                    cid: coll(),
                    oid: o.clone(),
                    keys: vec![TxnBytes::Borrowed(&key)],
                });
            }
            4 => {
                t.remove(coll(), &o);
            }
            _ => {
                t.touch(coll(), &o);
            }
        }
        st.commit(&t).unwrap();
    }
    st.checkpoint().unwrap();
    let w = walk(&mut st);
    assert_eq!(counters(&mut st), (w.0, w.1), "live counters vs walk");
    assert!(w.0 > 0);
    drop(st);
    let (_d, mut st2) = open(&disk.image(), &sim);
    assert_eq!(walk(&mut st2), w, "walk after restart");
    assert_eq!(counters(&mut st2), (w.0, w.1), "counters after restart");
}

#[test]
fn stats_read_takes_no_queue_barrier_while_txns_are_parked() {
    let mut sim = SimConfig::new(64 << 20);
    sim.seed = 6;
    let (_disk, mut st) = open(&image(&sim), &sim);
    st.set_prep_allowance(Some(std::time::Duration::ZERO));
    let big = Bytes::from(vec![7u8; 1 << 20]);
    let mut toks = Vec::new();
    for i in 0..4u32 {
        let mut t = OTxn::new();
        t.push(TOp::Write {
            cid: coll(),
            oid: obj(i + 1),
            off: 0,
            data: TxnBytes::Shared(big.clone()),
        });
        t.payloads.0.push(crc::Payload::owner(big.clone()));
        st.queue(&t, 100 + u64::from(i)).unwrap();
        toks.push(100 + u64::from(i));
    }
    assert!(st.queued_count() > 0, "txns are parked");
    let b0 = st.barriers;
    let _ = counters(&mut st);
    assert_eq!(st.barriers, b0, "coll_stats took a queue barrier");
    assert!(st.queued_count() > 0, "stats read did not drain the FIFO");
    let mut acked = Vec::new();
    for _ in 0..200_000 {
        st.poll(&mut acked).unwrap();
        if toks.iter().all(|t| acked.contains(t)) {
            break;
        }
        st.idle();
    }
    assert_eq!(counters(&mut st), (4, 4 << 20), "next read counts them");
}

/// `cargo test --release -p store --test pg_stats -- --ignored --nocapture`
#[test]
#[ignore = "microbench: run with --release"]
fn microbench_stats_vs_walk() {
    let mut sim = SimConfig::new(1 << 30);
    sim.seed = 7;
    let (_disk, mut st) = open(&image(&sim), &sim);
    let o = obj(1);
    let val = [1u8; 16];
    let keys: Vec<Vec<u8>> = (0..1_000_000u32)
        .map(|i| format!("key{i:08}").into_bytes())
        .collect();
    for chunk in keys.chunks(2000) {
        let mut t = OTxn::new();
        for k in chunk {
            t.omap_set(coll(), &o, k, &val);
        }
        st.commit(&t).unwrap();
    }
    let n = 1000;
    let t0 = std::time::Instant::now();
    for _ in 0..n {
        std::hint::black_box(counters(&mut st));
    }
    let inc = t0.elapsed() / n;
    let t0 = std::time::Instant::now();
    let m = st.omap_all(&coll(), &o).unwrap();
    let bytes: usize = m.iter().map(|(k, v)| k.len() + v.len()).sum();
    println!(
        "incremental tick: {inc:?}; walk of {} keys / {bytes} B: {:?}",
        m.len(),
        t0.elapsed()
    );
}

/// Tick cost vs object count (RBD-like PG: many objects, no omap): `coll_stats` must not depend on it.
#[test]
#[ignore = "microbench: run with --release"]
fn microbench_stats_vs_object_count() {
    let mut sim = SimConfig::new(1 << 30);
    sim.seed = 8;
    let (_disk, mut st) = open(&image(&sim), &sim);
    let mut have = 0u32;
    for target in [1_000u32, 10_000, 100_000] {
        while have < target {
            let mut t = OTxn::new();
            for _ in 0..500 {
                have += 1;
                t.touch(coll(), &obj(have));
            }
            st.commit(&t).unwrap();
        }
        let n = 100_000;
        let t0 = std::time::Instant::now();
        for _ in 0..n {
            std::hint::black_box(counters(&mut st));
        }
        println!("objects {have}: tick {:?}", t0.elapsed() / n);
    }
}
