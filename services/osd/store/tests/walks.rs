// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Tree walks per 4 KiB create (the OSD write shape: state-load warm of the object and the PG log head, then a txn
//! with 4 KiB data + 2 xattrs + a log entry + `_info` on the pgmeta object). Counts `Tree::locate` calls (descents
//! from the root and remembered-leaf hits) per phase from the tree counters, not from a profile.
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{Ghobject, Hobject, ShardId, SnapId};
use objmodel::pgc;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, Store, StoreCfg, TOp};
use store::tree::TreeStats;

type St = Store<SimDev, SimClock>;

fn obj(i: u64) -> Ghobject {
    Ghobject::new(
        Hobject::new(
            format!("rbd_data.1234.{i:016x}").as_bytes(),
            SnapId::NOSNAP,
            (i as u32).wrapping_mul(2654435761),
            1,
            b"",
        ),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

/// PG log length kept: each create past it trims the oldest entry (the OSD's steady state).
const LOG: u64 = 3000;

fn log_key(v: u64) -> Vec<u8> {
    format!("{:010}.{:020}", 5, v).into_bytes()
}

fn store(cap_mib: u64) -> (SimDisk, St) {
    let sim = SimConfig::new(cap_mib << 20);
    let disk = SimDisk::new(sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = MkfsParams {
        shards: 1,
        wal_blocks: 16384,
        align_blocks: 1,
        ..Default::default()
    };
    mkfs(&mut dev, &mut clk, &p).unwrap();
    let d2 = disk.clone();
    let (st, _) =
        Store::mount(move || d2.queue(), SimClock::default(), StoreCfg::default()).unwrap();
    (disk, st)
}

#[derive(Default)]
struct Walks {
    locates: u64,
    descents: u64,
}

impl Walks {
    fn add(&mut self, a: &TreeStats, b: &TreeStats) {
        self.locates += b.locates - a.locates;
        self.descents += b.descents - a.descents;
    }
}

/// Per-create walks of `n` creates after `pre` creates (warm phase, txn phase).
fn creates(pre: u64, n: u64) -> (Walks, Walks, u64) {
    let mut w = (Walks::default(), Walks::default(), 0);
    run(pre, n, &mut |a, b, c, m| {
        w.0.add(a, b);
        w.1.add(b, c);
        w.2 += m;
    });
    w
}

/// `pre + n` creates; `f(before warm, after warm, after the txn's submit, splits)` for each of the last `n`. Returns
/// the wall time of the last `n` (warm + queue + poll, simulated device included).
fn run(pre: u64, n: u64, f: &mut dyn FnMut(&TreeStats, &TreeStats, &TreeStats, u64)) -> f64 {
    let (_disk, mut st) = store(2048);
    let c = pgc(1, 0);
    let pm = Ghobject::pgmeta(1, 0, ShardId::NO_SHARD);
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.touch(c, &pm);
    st.commit(&t).unwrap();
    let page = vec![0xC3u8; 4096];
    let (oi, ss) = (vec![7u8; 260], vec![8u8; 40]);
    let (logv, infov) = (vec![1u8; 180], vec![2u8; 600]);
    let mut acked = Vec::new();
    let mut inflight = 0usize;
    let mut t0 = std::time::Instant::now();
    for i in 0..pre + n {
        if i == pre {
            t0 = std::time::Instant::now();
        }
        let (o, lk) = (obj(i), log_key(i + 1));
        // the state load: pages it misses load in the background (the op retries after the wake)
        let mut s0 = st.tree_stats();
        let mut tries = 0;
        while !(st.warm(&c, &o, 0, 4096).unwrap() & st.warm_omap(&c, &pm, &[&lk]).unwrap()) {
            tries += 1;
            assert!(tries < 1000, "state load of create {i} never ready");
            st.idle();
            acked.clear();
            st.poll(&mut acked).unwrap();
            inflight -= acked.len();
            s0 = st.tree_stats();
        }
        let s1 = st.tree_stats();
        let mut t = OTxn::new();
        t.write(c, &o, 0, &page);
        t.setattr(c, &o, b"_", &oi);
        t.setattr(c, &o, b"snapset", &ss);
        t.omap_set(c, &pm, &lk, &logv);
        t.omap_set(c, &pm, b"_info", &infov);
        if i >= LOG {
            t.push(TOp::OmapRmKeys {
                cid: c,
                oid: pm.clone(),
                keys: vec![log_key(i + 1 - LOG).into()],
            });
        }
        st.queue(&t, i + 1).unwrap();
        inflight += 1;
        acked.clear();
        st.poll(&mut acked).unwrap();
        inflight -= acked.len();
        let s2 = st.tree_stats();
        while inflight > 16 {
            st.idle();
            acked.clear();
            st.poll(&mut acked).unwrap();
            inflight -= acked.len();
        }
        if i >= pre {
            f(&s0, &s1, &s2, s2.splits - s1.splits);
        }
    }
    st.sync().unwrap();
    t0.elapsed().as_secs_f64()
}

/// Prints the walks per create (`--nocapture`) and bounds them: the txn phase locates each of its tree keys at most
/// once (a split re-walks the keys after it).
#[test]
fn create_walks_per_key() {
    let (pre, n) = (20_000, 2_000);
    let (warm, txn, splits) = creates(pre, n);
    let pc = |x: u64| x as f64 / n as f64;
    println!(
        "per create: warm locates {:.2} descents {:.2}; txn locates {:.2} descents {:.2}; splits {:.3}",
        pc(warm.locates),
        pc(warm.descents),
        pc(txn.locates),
        pc(txn.descents),
        pc(splits)
    );
    // at most one locate per tree key of the txn (8: name, 2 xattrs, extent, onode, log entry, `_info`, trimmed log
    // entry); a split voids the located legs of the keys after it (they walk). A key in the leaf of the key before it
    // in an ascending stretch of the record is carried by the leaf cursor (not a locate), so the floor is the leaves
    // the txn must reach: name, xattrs, extent, onode, log head, trimmed log entry (6 key ranges apart)
    assert!(
        pc(txn.locates) <= 8.0 + 8.0 * pc(splits),
        "txn locates per create {:.2} (splits {:.3})",
        pc(txn.locates),
        pc(splits)
    );
    assert!(pc(txn.locates) >= 6.0);
    assert_eq!(warm.locates, 2 * n, "warm: name + log head");
}

/// Store-level CPU per create (release): `cargo test --release -p store --test walks perf -- --ignored --nocapture`;
/// `NCREATE` creates measured after `NPRE`.
#[test]
#[ignore = "microbench"]
fn perf_create() {
    let env = |k: &str, d: u64| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let (pre, n) = (env("NPRE", 20_000), env("NCREATE", 100_000));
    let mut fs = Vec::new();
    for _ in 0..env("NREP", 3) {
        let wall = run(pre, n, &mut |_, _, _, _| {});
        fs.push(wall * 1e9 / n as f64);
    }
    println!("create ns (warm + txn + poll, sim device): {fs:.0?}");
}

fn dkey(i: u64) -> Vec<u8> {
    let mut x = i.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    format!("{:016x}_head", x ^ (x >> 31)).into_bytes()
}

fn dval(i: u64) -> Vec<u8> {
    vec![(i % 251) as u8; 400 + (i % 200) as usize]
}

/// One dirfrag commit (b-dir shape): [set_header, dentries `ins..ins + b` as a run, rm_keys of dentries `del..del + b`].
fn dir_commit(
    c: denc::types::CollT,
    d: &Ghobject,
    h: u64,
    ins: u64,
    del: u64,
    b: u64,
) -> OTxn<'static> {
    let mut kv: Vec<(Vec<u8>, Vec<u8>)> = (ins..ins + b).map(|i| (dkey(i), dval(i))).collect();
    kv.sort();
    let mut enc = Vec::new();
    denc::SortedKv::encode_into(
        &mut enc,
        kv.len(),
        kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
    );
    let mut rm: Vec<Vec<u8>> = (del..del + b).map(dkey).collect();
    rm.sort();
    let mut t = OTxn::new();
    t.push(TOp::OmapSetHeader {
        cid: c,
        oid: d.clone(),
        header: vec![h as u8; 232].into(),
    });
    t.push(TOp::OmapSetRun {
        cid: c,
        oid: d.clone(),
        run: store::obj::KvRunData::from_encoding(enc.into()).unwrap(),
    });
    t.push(TOp::OmapRmKeys {
        cid: c,
        oid: d.clone(),
        keys: rm.into_iter().map(Into::into).collect(),
    });
    t
}

/// Queue `t` (retried after polls while it would block); ns spent in `queue`.
fn queue_one(st: &mut St, t: &OTxn, tok: u64) -> u64 {
    let mut acked = Vec::new();
    let mut ns = 0;
    loop {
        let t0 = std::time::Instant::now();
        let r = st.queue(t, tok);
        ns += t0.elapsed().as_nanos() as u64;
        match r {
            Ok(_) => return ns,
            Err(store::obj::ObjError::WouldBlock) => {
                st.idle();
                acked.clear();
                st.poll(&mut acked).unwrap();
            }
            Err(e) => panic!("commit {tok}: {e}"),
        }
    }
}

/// Poll until `tok` is acked.
fn ack_wait(st: &mut St, tok: u64) {
    let mut acked = Vec::new();
    loop {
        acked.clear();
        st.poll(&mut acked).unwrap();
        if acked.contains(&tok) {
            return;
        }
        st.idle();
    }
}

/// A store with object `d` holding dentries `0..n` in the tree (1000-key tree batches).
fn dir_store(n: u64) -> (SimDisk, St, denc::types::CollT, Ghobject) {
    let (disk, mut st) = store(4096);
    let c = pgc(1, 0);
    let d = obj(7);
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.touch(c, &d);
    st.commit(&t).unwrap();
    for lo in (0..n).step_by(1000) {
        let mut t = OTxn::new();
        t.push(TOp::OmapSetKeys {
            cid: c,
            oid: d.clone(),
            pairs: (lo..(lo + 1000).min(n))
                .map(|i| (dkey(i).into(), dval(i).into()))
                .collect(),
        });
        st.commit(&t).unwrap();
    }
    (disk, st, c, d)
}

/// CephFS dirfrag commits (adr 0476 am. 5 blind removals; OQ 109): [set_header, B new dentries as a run, rm_keys of the B
/// oldest] on an object whose dentries are in a multi-level tree. The probes of the record's ascending blind removals
/// route in the previous leaf's parent instead of descending from the root: descents per removed key stay well below
/// one (the parent route is checked against a full descent in debug builds), and the omap equals the model.
#[test]
fn dirfrag_commit_walks() {
    let (n, b, commits) = (30_000u64, 256u64, 40u64);
    let (_disk, mut st, c, d) = dir_store(n);
    let (mut ins, mut del) = (n, 0u64);
    let (mut walks, mut removed) = (Walks::default(), 0u64);
    for h in 0..commits {
        let t = dir_commit(c, &d, h, ins, del, b);
        let s0 = st.tree_stats();
        queue_one(&mut st, &t, h + 1);
        let s1 = st.tree_stats();
        // the removals of the first commits all hit the tree (no run holds them)
        if del + b <= n {
            walks.add(&s0, &s1);
            removed += b;
        }
        ack_wait(&mut st, h + 1);
        ins += b;
        del += b;
    }
    println!(
        "dirfrag commits b{b}: locates {:.3} descents {:.3} per removed key",
        walks.locates as f64 / removed as f64,
        walks.descents as f64 / removed as f64
    );
    assert!(
        (walks.descents as f64) < 0.3 * removed as f64,
        "descents {} for {removed} removed keys",
        walks.descents
    );
    // the omap is the model's: dentries del..ins
    let mut want: Vec<Vec<u8>> = (del..ins).map(dkey).collect();
    want.sort();
    let mut got = Vec::new();
    let mut from = Vec::new();
    loop {
        let (kv, more) = st.omap_iter(&c, &d, &from, 4096).unwrap();
        for (k, v) in &kv {
            got.push(k.to_vec());
            assert!((400..600).contains(&v.len()), "value length {}", v.len());
        }
        let Some(last) = kv.last() else { break };
        from = last.0.to_vec();
        from.push(0);
        if !more {
            break;
        }
    }
    assert_eq!(got, want);
    assert_eq!(got.len() as u64, ins - del);
}

/// Store CPU of dirfrag commits (OQ 109; release): `NDIR` dentries in the tree, `NCOMMIT` commits of `NB` dentries
/// (`cargo test --release -p store --test walks perf_dirfrag -- --ignored --nocapture`). Prints the time in `queue` per
/// commit (stage + validate + apply: the PG core's share) and per removed + inserted key.
#[test]
#[ignore = "microbench"]
fn perf_dirfrag() {
    let env = |k: &str, d: u64| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let (n, b, commits) = (env("NDIR", 250_000), env("NB", 1024), env("NCOMMIT", 400));
    for _ in 0..env("NREP", 3) {
        let (_disk, mut st, c, d) = dir_store(n);
        let (mut ins, mut del, mut ns) = (n, 0u64, 0u64);
        for h in 0..commits {
            let t = dir_commit(c, &d, h, ins, del, b);
            ns += queue_one(&mut st, &t, h + 1);
            ack_wait(&mut st, h + 1);
            ins += b;
            del += b;
        }
        println!(
            "dirfrag b{b} n{n}: queue {:.1} us/commit, {:.3} us/key op",
            ns as f64 / 1e3 / commits as f64,
            ns as f64 / 1e3 / (commits * 2 * b) as f64
        );
    }
}
