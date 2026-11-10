// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Shared extents (adr 0021 am. 32): clones reference the source's blocks (refcounted), copy-on-write on overwrite,
//! punch and delete, free at owner count 0, first-use feature bit, fsck/check of the counts, crash matrix over a
//! snapshot-shaped workload (clone, overwrite, delete source, delete clone, remount) with a leak check.
#![allow(clippy::too_many_arguments, clippy::collapsible_if)]
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use objmodel::*;
use store::compress::{Alg, CompSpec};
use store::dev::{CrashPolicy, SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::fsck::fsck;
use store::layout::{FEAT_SHARED_EXT, MkfsParams, mkfs, read_super};
use store::obj::onode::fsck_refs;
use store::obj::{OTxn, Store, StoreCfg, TOp};
use store::rng::Rng;
use store::shard::ShardCfg;

type St = Store<SimDev, SimClock>;

fn cfg(share: bool) -> StoreCfg {
    StoreCfg {
        shard: ShardCfg {
            shared_clone: share,
            ckpt_wal_pct: 4,
            ..StoreCfg::default().shard
        },
    }
}

fn image(sim: &SimConfig) -> SimImage {
    image_with(sim, true)
}

fn image_with(sim: &SimConfig, shared_ext: bool) -> SimImage {
    let disk = SimDisk::new(sim.clone());
    let p = MkfsParams {
        shards: 1,
        wal_blocks: 512,
        align_blocks: 1,
        meta_pct: 8,
        node_size: 8192,
        shared_ext,
        ..Default::default()
    };
    mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    disk.image()
}

fn open(img: &SimImage, sim: &SimConfig, c: &StoreCfg) -> (SimDisk, St) {
    let disk = SimDisk::from_image(img, sim.clone());
    let d2 = disk.clone();
    let (st, _) = Store::mount(move || d2.queue(), SimClock::default(), c.clone()).unwrap();
    (disk, st)
}

/// fsck (with the data references: exact bitmap = no leak, refcounts) of an image; data blocks in use.
fn fsck_img(img: &SimImage, sim: &SimConfig) -> Result<u64, String> {
    let d = SimDisk::from_image(img, sim.clone());
    let rep = fsck(&mut d.queue(), &mut SimClock::default(), Some(&fsck_refs))?;
    Ok(rep.iter().map(|r| r.data_blocks_used).sum())
}

fn features(img: &SimImage, sim: &SimConfig) -> u64 {
    let d = SimDisk::from_image(img, sim.clone());
    read_super(&mut d.queue(), &mut SimClock::default())
        .unwrap()
        .0
        .features
}

fn g(oid: &str) -> Ghobject {
    Ghobject::new(
        Hobject::new(oid.as_bytes(), SnapId::NOSNAP, 7, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn c1() -> CollT {
    pgc(1, 0)
}

fn leakv(v: Vec<u8>) -> &'static [u8] {
    Box::leak(v.into_boxed_slice())
}

fn rnd(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng::new(seed);
    (0..n).map(|_| r.below(256) as u8).collect()
}

/// Compressible bytes.
fn cdata(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng::new(seed);
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        let run = r.range(8, 300) as usize;
        let b = r.below(256) as u8;
        v.resize((v.len() + run).min(n), b);
    }
    v
}

fn clone_op(src: &str, dst: &str) -> TOp<'static> {
    TOp::Clone {
        cid: c1(),
        src: g(src),
        dst: g(dst),
    }
}

fn shared_clones(st: &St) -> u64 {
    st.shards.iter().map(|s| s.stats.shared_clones).sum()
}

fn check_clean(st: &mut St) -> u64 {
    let rep = st.check(true).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    rep.shared_runs
}

/// Store + model in lockstep, clean remounts with fsck.
struct Rig {
    sim: SimConfig,
    cfg: StoreCfg,
    disk: SimDisk,
    st: St,
    m: Model,
    gn: Gen,
    vr: Rng,
    /// Sharing clones of earlier mounts.
    shared: u64,
    /// Sharing `clone_range` ops of earlier mounts (am. 38).
    ranges: u64,
}

impl Rig {
    fn new(share: bool) -> Rig {
        Rig::with(share, true)
    }
    fn with(share: bool, shared_ext: bool) -> Rig {
        let mut sim = SimConfig::new(256 << 20);
        sim.seed = 3;
        let img = image_with(&sim, shared_ext);
        let cfg = cfg(share);
        let (disk, mut st) = open(&img, &sim, &cfg);
        let mut t = OTxn::new();
        t.mkcoll(c1());
        st.commit(&t).unwrap();
        let mut m = Model::default();
        m.apply_txn(&t).unwrap();
        let mut gn = Gen::new(1, 1);
        gn.objs = Vec::new();
        Rig {
            sim,
            cfg,
            disk,
            st,
            m,
            gn,
            vr: Rng::new(9),
            shared: 0,
            ranges: 0,
        }
    }
    fn run(&mut self, t: &OTxn) {
        self.st.commit(t).unwrap_or_else(|e| panic!("{e:?}"));
        self.m.apply_txn(t).unwrap();
        for o in t.ops.iter().flat_map(objs_of) {
            if !self.gn.objs.contains(&o) {
                self.gn.objs.push(o);
            }
        }
        verify(&mut self.st, &self.m, &self.gn, &mut self.vr).unwrap();
    }
    fn remount(&mut self) -> u64 {
        self.st.checkpoint().unwrap();
        let img = self.disk.image();
        self.shared += shared_clones(&self.st);
        self.ranges += shared_ranges(&self.st);
        let used = fsck_img(&img, &self.sim).unwrap();
        let (d, s) = open(&img, &self.sim, &self.cfg);
        self.disk = d;
        self.st = s;
        verify(&mut self.st, &self.m, &self.gn, &mut self.vr).unwrap();
        used
    }
}

fn objs_of(op: &TOp) -> Vec<Ghobject> {
    match op {
        TOp::Clone { src, dst, .. } | TOp::CloneRange { src, dst, .. } => {
            vec![src.clone(), dst.clone()]
        }
        TOp::Write { oid, .. }
        | TOp::Touch { oid, .. }
        | TOp::Remove { oid, .. }
        | TOp::Zero { oid, .. }
        | TOp::Truncate { oid, .. } => vec![oid.clone()],
        _ => Vec::new(),
    }
}

#[test]
fn partial_reclaim_zero_and_truncate_release_empty_edge_blocks() {
    for clone in [false, true] {
        for truncate in [false, true] {
            let mut r = Rig::new(true);
            let base = r.remount();
            let mut t = OTxn::new();
            // A sparse object with exactly one allocated block and one live byte.
            t.write(c1(), &g("edge"), store::BLK as u64 + 100, &[0x71]);
            r.run(&t);
            assert_eq!(r.remount(), base + 1);
            if clone {
                let mut t = OTxn::new();
                t.push(clone_op("edge", "snapshot"));
                r.run(&t);
                assert_eq!(r.remount(), base + 1);
            }
            let mut t = OTxn::new();
            if truncate {
                t.truncate(c1(), &g("edge"), store::BLK as u64 + 1);
            } else {
                t.zero(c1(), &g("edge"), store::BLK as u64 + 100, 1);
            }
            r.run(&t);
            // An all-zero RMW edge is a hole, never a new physical allocation.
            // A snapshot retains its original block until the last owner is gone.
            assert_eq!(r.remount(), base + u64::from(clone));
            if clone {
                let mut t = OTxn::new();
                t.remove(c1(), &g("snapshot"));
                r.run(&t);
                assert_eq!(r.remount(), base);
            }
            let stat = r.st.statfs();
            assert_eq!(
                stat.real_used_bytes - stat.real_meta_bytes,
                base * store::BLK as u64
            );
            assert_eq!(check_clean(&mut r.st), 0);
        }
    }
}

#[test]
fn clone_shares_blocks_copy_on_write_and_frees_at_zero() {
    let mut r = Rig::new(true);
    let base = r.remount();
    let a = rnd(1 << 20, 1);
    let mut t = OTxn::new();
    t.write(c1(), &g("a"), 0, &a);
    r.run(&t);
    let after_write = r.remount();
    assert_eq!(after_write - base, 256);
    let mut t = OTxn::new();
    t.push(clone_op("a", "a.s1"));
    r.run(&t);
    assert_eq!(shared_clones(&r.st), 1);
    assert!(check_clean(&mut r.st) > 0);
    // the clone costs no data blocks
    assert_eq!(r.remount(), after_write);
    assert_ne!(features(&r.disk.image(), &r.sim) & FEAT_SHARED_EXT, 0);
    // RBD COW: clone + 4K overwrite of the head in one txn; then more overwrites, a zero, a truncate
    let d = rnd(4096, 2);
    let mut t = OTxn::new();
    t.push(clone_op("a", "a.s2"));
    t.write(c1(), &g("a"), 8192, &d);
    r.run(&t);
    assert_eq!(r.remount(), after_write + 1);
    let mut t = OTxn::new();
    t.write(c1(), &g("a"), 300_000, &d[..100]);
    t.zero(c1(), &g("a"), 500_000, 70_000);
    r.run(&t);
    let mut t = OTxn::new();
    t.truncate(c1(), &g("a.s1"), 700_000);
    r.run(&t);
    r.remount();
    check_clean(&mut r.st);
    // delete the source: the clones keep the data
    let mut t = OTxn::new();
    t.remove(c1(), &g("a"));
    r.run(&t);
    r.remount();
    // clone of a clone, then overwrite it
    let mut t = OTxn::new();
    t.push(clone_op("a.s2", "c"));
    t.write(c1(), &g("c"), 0, &d);
    r.run(&t);
    r.remount();
    for o in ["a.s1", "a.s2", "c"] {
        let mut t = OTxn::new();
        t.remove(c1(), &g(o));
        r.run(&t);
        check_clean(&mut r.st);
    }
    // all owners gone: every block free, no refcount record left
    assert_eq!(r.remount(), base);
    assert_eq!(check_clean(&mut r.st), 0);
}

#[test]
fn same_txn_shapes_and_clone_over_existing() {
    let mut r = Rig::new(true);
    let base = r.remount();
    let mut t = OTxn::new();
    let a = rnd(300_000, 3);
    t.write(c1(), &g("a"), 0, &a);
    r.run(&t);
    // clone and remove the clone in one txn; clone twice; clone a clone in the same txn
    let mut t = OTxn::new();
    t.push(clone_op("a", "x"));
    t.remove(c1(), &g("x"));
    t.push(clone_op("a", "y"));
    t.push(clone_op("y", "z"));
    t.push(clone_op("a", "w"));
    r.run(&t);
    check_clean(&mut r.st);
    r.remount();
    // clone over an existing object (the old one's shared blocks are released), clone onto itself
    let mut t = OTxn::new();
    t.push(clone_op("z", "y"));
    t.push(clone_op("w", "w"));
    r.run(&t);
    // write then clone in one txn (source with staged data: copied), remove source + clone
    let b = rnd(20_000, 4);
    let mut t = OTxn::new();
    t.write(c1(), &g("w"), 4096, &b);
    t.push(clone_op("w", "v"));
    t.remove(c1(), &g("w"));
    r.run(&t);
    r.remount();
    check_clean(&mut r.st);
    for o in ["a", "y", "z", "v"] {
        let mut t = OTxn::new();
        t.remove(c1(), &g(o));
        r.run(&t);
    }
    assert_eq!(r.remount(), base);
    assert_eq!(check_clean(&mut r.st), 0);
}

#[test]
fn compressed_chunks_are_shared_whole() {
    let mut r = Rig::new(true);
    let base = r.remount();
    let cs = Some(CompSpec {
        alg: Alg::Zstd,
        ratio_permille: 875,
        min_bytes: 8192,
        chunk_blks: 16,
    });
    let d = cdata(256 << 10, 5);
    let mut t = OTxn::new();
    t.comp = cs;
    t.write(c1(), &g("a"), 0, &d);
    r.run(&t);
    let used = r.remount();
    let mut t = OTxn::new();
    t.push(clone_op("a", "s"));
    r.run(&t);
    assert_eq!(shared_clones(&r.st), 1);
    assert_eq!(r.remount(), used);
    // 4K overwrite inside a shared compressed chunk: the head pulls the chunk in, the snapshot keeps the old one
    let mut t = OTxn::new();
    t.comp = cs;
    t.write(c1(), &g("a"), 20_480, leakv(rnd(4096, 6)));
    r.run(&t);
    let mut t = OTxn::new();
    t.write(c1(), &g("s"), 100_000, leakv(rnd(9000, 7)));
    r.run(&t);
    r.remount();
    check_clean(&mut r.st);
    for o in ["a", "s"] {
        let mut t = OTxn::new();
        t.remove(c1(), &g(o));
        r.run(&t);
    }
    assert_eq!(r.remount(), base);
    assert_eq!(check_clean(&mut r.st), 0);
}

#[test]
fn feature_bit_only_by_mkfs() {
    // a store without the bit (mkfs variant), sharing on: clones copy and the bit is never set
    let mut r = Rig::with(true, false);
    assert_eq!(features(&r.disk.image(), &r.sim) & FEAT_SHARED_EXT, 0);
    let mut t = OTxn::new();
    t.write(c1(), &g("a"), 0, leakv(rnd(64 << 10, 1)));
    r.run(&t);
    let mut t = OTxn::new();
    t.push(clone_op("a", "b"));
    r.run(&t);
    r.remount();
    assert_eq!(shared_clones(&r.st), 0);
    assert_eq!(r.shared, 0);
    assert_eq!(features(&r.disk.image(), &r.sim) & FEAT_SHARED_EXT, 0);
}

#[test]
fn sharing_off_still_frees_shared_blocks() {
    let mut r = Rig::new(true);
    let mut t = OTxn::new();
    t.write(c1(), &g("a"), 0, leakv(rnd(64 << 10, 1)));
    r.run(&t);
    let mut t = OTxn::new();
    t.push(clone_op("a", "b"));
    r.run(&t);
    assert_eq!(shared_clones(&r.st), 1);
    r.remount();
    // a store with the bit and sharing turned off again still frees shared blocks through the counts
    r.cfg = cfg(false);
    r.remount();
    let mut t = OTxn::new();
    t.write(c1(), &g("a"), 0, leakv(rnd(4096, 3)));
    t.remove(c1(), &g("b"));
    r.run(&t);
    r.remount();
    assert_eq!(check_clean(&mut r.st), 0);
}

#[test]
fn mkfs_sets_the_bit_and_clones_share() {
    let mut r = Rig::new(true);
    assert_ne!(features(&r.disk.image(), &r.sim) & FEAT_SHARED_EXT, 0);
    let mut t = OTxn::new();
    t.write(c1(), &g("a"), 0, leakv(rnd(64 << 10, 1)));
    r.run(&t);
    let mut t = OTxn::new();
    t.push(clone_op("a", "b"));
    r.run(&t);
    assert_eq!(shared_clones(&r.st), 1);
}

#[test]
fn fsck_and_check_catch_bad_refcounts() {
    let mut r = Rig::new(true);
    let mut t = OTxn::new();
    t.write(c1(), &g("a"), 0, leakv(rnd(64 << 10, 1)));
    r.run(&t);
    let mut t = OTxn::new();
    t.push(clone_op("a", "b"));
    r.run(&t);
    r.remount();
    // find the refcount record and damage it through a raw engine txn: owner count 3 instead of 2, then drop it
    let kv = r.st.shards[0].sh.dump_blocking(&mut r.st.clk).unwrap();
    let (rk, rv) = kv
        .iter()
        .find(|(k, _)| k[0] == store::obj::keys::T_REF)
        .map(|(k, v)| (k.clone(), v.clone()))
        .unwrap();
    let (n, c) = store::obj::onode::ref_decode(&rv).unwrap();
    assert_eq!(c, 2);
    for bad in [
        Some(store::obj::onode::ref_encode(n, 3)),
        Some(store::obj::onode::ref_encode(n - 1, 2)),
        None,
    ] {
        let mut t: store::shard::Txn<Vec<u8>> = store::shard::Txn::new(0);
        match &bad {
            Some(v) => t.put(&rk, v),
            None => t.del(&rk),
        };
        r.st.shards[0].sh.submit(t).unwrap();
        let rep = r.st.check(false).unwrap();
        assert!(!rep.errors.is_empty(), "check misses {bad:?}");
        r.st.checkpoint().unwrap();
        assert!(
            fsck_img(&r.disk.image(), &r.sim).is_err(),
            "fsck misses {bad:?}"
        );
    }
}

/// A crc-valid refcount record one run before the end of the block address space (`pba + n` wraps) is reported by both
/// checkers, never panics in the owner sweep ("attempt to add with overflow" in a debug build) and never turns into a
/// verdict about another block range.
#[test]
fn refcount_record_at_the_end_of_the_block_space_is_reported() {
    let mut r = Rig::new(true);
    let mut t = OTxn::new();
    t.write(c1(), &g("a"), 0, leakv(rnd(16 << 10, 1)));
    r.run(&t);
    let mut t = OTxn::new();
    t.push(clone_op("a", "b"));
    r.run(&t);
    r.remount();
    let mut t: store::shard::Txn<Vec<u8>> = store::shard::Txn::new(0);
    t.put(
        &store::obj::keys::ref_key(u64::MAX - 1),
        &store::obj::onode::ref_encode(64, 2),
    );
    r.st.shards[0].sh.submit(t).unwrap();
    let rep = r.st.check(false).unwrap();
    assert!(
        rep.errors.iter().any(|m| m.contains("wraps")),
        "{:?}",
        rep.errors
    );
    r.st.checkpoint().unwrap();
    let err = fsck_img(&r.disk.image(), &r.sim).expect_err("fsck accepts a wrapped record");
    assert!(err.contains("outside the data region"), "{err}");
}

// ------------------------------------------------------------------------------------------- crash matrix
/// Snapshot-shaped workload: write, clone (first one sets the bit), COW overwrite in the clone txn, zero, truncate,
/// delete source, clone of a clone, compressed chunk shared and cut, delete clones.
fn script() -> Vec<OTxn<'static>> {
    let leak = |v: Vec<u8>| -> &'static [u8] { Box::leak(v.into_boxed_slice()) };
    let cs = Some(CompSpec {
        alg: Alg::Lz4,
        ratio_permille: 875,
        min_bytes: 8192,
        chunk_blks: 16,
    });
    let mut v = Vec::new();
    let mut t = OTxn::new();
    t.write(c1(), &g("a"), 0, leak(rnd(256 << 10, 1)));
    t.write(c1(), &g("b"), 0, leak(rnd(64 << 10, 2)));
    v.push(t);
    let mut t = OTxn::new();
    t.comp = cs;
    t.write(c1(), &g("d"), 0, leak(cdata(128 << 10, 3)));
    v.push(t);
    let mut t = OTxn::new();
    t.push(clone_op("a", "a.1"));
    v.push(t);
    let mut t = OTxn::new();
    t.write(c1(), &g("a"), 8192, leak(rnd(4096, 4)));
    v.push(t);
    let mut t = OTxn::new();
    t.push(clone_op("a", "a.2"));
    t.write(c1(), &g("a"), 100_000, leak(rnd(4096, 5)));
    v.push(t);
    let mut t = OTxn::new();
    t.push(clone_op("d", "d.1"));
    t.push(clone_op("b", "b.1"));
    t.remove(c1(), &g("b.1"));
    v.push(t);
    let mut t = OTxn::new();
    t.comp = cs;
    t.write(c1(), &g("d"), 20_480, leak(rnd(4096, 6)));
    t.zero(c1(), &g("a"), 64 << 10, 64 << 10);
    v.push(t);
    let mut t = OTxn::new();
    t.truncate(c1(), &g("a.1"), 200_000);
    v.push(t);
    let mut t = OTxn::new();
    t.remove(c1(), &g("a"));
    v.push(t);
    let mut t = OTxn::new();
    t.push(clone_op("a.2", "c"));
    t.write(c1(), &g("c"), 0, leak(rnd(16 << 10, 7)));
    v.push(t);
    // EC legacy stash shapes (am. 38): stash + overwrite, a second generation, rollback, roll-forward, unaligned range
    let mut t = OTxn::new();
    t.write(c1(), &g("h"), 0, leak(rnd(256 << 10, 9)));
    v.push(t);
    v.push(stash_txn("h", "h.g1", 8192, leak(rnd(4096, 10))));
    v.push(stash_txn("h", "h.g2", 64 << 10, leak(rnd(128 << 10, 11))));
    v.push(rollback_txn("h", "h.g2", 64 << 10, 128 << 10));
    let mut t = OTxn::new();
    t.remove(c1(), &g("h.g1"));
    t.push(crange("h", "b", 1000, 50_000, 4096 + 1000));
    v.push(t);
    for o in ["a.1", "d", "a.2"] {
        let mut t = OTxn::new();
        t.remove(c1(), &g(o));
        v.push(t);
    }
    let mut t = OTxn::new();
    t.push(clone_op("c", "a.2"));
    t.write(c1(), &g("b"), 4096, leak(rnd(8192, 8)));
    v.push(t);
    for o in ["c", "d.1"] {
        let mut t = OTxn::new();
        t.remove(c1(), &g(o));
        v.push(t);
    }
    v
}

fn universe() -> Vec<Ghobject> {
    [
        "a", "a.1", "a.2", "b", "b.1", "c", "d", "d.1", "h", "h.g1", "h.g2",
    ]
    .iter()
    .map(|s| g(s))
    .collect()
}

struct Run {
    disk: SimDisk,
    acked: usize,
    queued: usize,
}

/// Run the script on `img`; crash at device event `crash_at` (None = run to the end).
fn workload(
    img: &SimImage,
    sim: &SimConfig,
    c: &StoreCfg,
    seed: u64,
    crash_at: Option<u64>,
    sc: &[OTxn<'static>],
) -> Run {
    let mut s2 = sim.clone();
    s2.seed = seed;
    let (disk, mut st) = open(img, &s2, c);
    if let Some(k) = crash_at {
        disk.arm_crash(disk.events() + k);
    }
    let mut pr = Rng::new(seed ^ 0xfeed);
    let (mut queued, mut acked) = (0, 0);
    for (i, t) in sc.iter().enumerate() {
        match st.queue(t, i as u64 + 1) {
            Ok(_) => queued += 1,
            Err(_) if disk.crashed() => break,
            Err(e) => panic!("queue: {e:?}"),
        }
        if pr.pct(50) {
            let mut a = Vec::new();
            if st.poll(&mut a).is_err() {
                break;
            }
            acked += a.len();
        }
        if pr.pct(20) {
            st.shards[0].sh.request_checkpoint();
        }
        if pr.pct(10) {
            st.idle();
        }
    }
    if !disk.crashed() {
        let mut a = Vec::new();
        for _ in 0..200 {
            if st.poll(&mut a).is_err() {
                break;
            }
            st.idle();
        }
        acked += a.len();
    }
    drop(st);
    Run {
        disk,
        acked,
        queued,
    }
}

fn prefixes(setup: &Model, sc: &[OTxn<'static>]) -> Vec<Model> {
    let mut m = setup.clone();
    let mut out = vec![m.clone()];
    for t in sc {
        m.apply_txn(t).unwrap();
        out.push(m.clone());
    }
    out
}

fn crash_one(
    img: &SimImage,
    sim: &SimConfig,
    c: &StoreCfg,
    setup: &Model,
    k: Option<u64>,
    pol: CrashPolicy,
    seed: u64,
    sc: &[OTxn<'static>],
    univ: &[Ghobject],
) -> Result<bool, String> {
    let run = workload(img, sim, c, seed, k, sc);
    let crashed = run.disk.crashed();
    run.disk.crash_now();
    let cimg = run.disk.crash_image(pol);
    fsck_img(&cimg, sim).map_err(|e| format!("fsck crash image: {e}"))?;
    let disk = SimDisk::from_image(&cimg, sim.clone());
    let d2 = disk.clone();
    let (mut st, _) = Store::mount(move || d2.queue(), SimClock::default(), c.clone())
        .map_err(|e| format!("mount: {e:?}"))?;
    let mut gn = Gen::new(1, 1);
    gn.objs = univ.to_vec();
    let ps = prefixes(setup, sc);
    let mut vr = Rng::new(seed);
    let j = (run.acked..=run.queued)
        .find(|&j| verify(&mut st, &ps[j], &gn, &mut vr).is_ok())
        .ok_or_else(|| {
            let e = verify(&mut st, &ps[run.acked], &gn, &mut vr).unwrap_err();
            format!(
                "no model prefix in [{}, {}] (vs {}: {e}) crashed={crashed}",
                run.acked, run.queued, run.acked
            )
        })?;
    let rep = st.check(true).map_err(|e| format!("check: {e:?}"))?;
    if !rep.errors.is_empty() {
        return Err(format!("check after recovery: {:?}", rep.errors));
    }
    // second generation: delete everything that survived, remount; no block and no refcount may remain
    let mut t = OTxn::new();
    for o in ps[j].colls[&c1()].keys() {
        t.remove(c1(), o);
    }
    st.commit(&t).map_err(|e| format!("cleanup: {e:?}"))?;
    st.checkpoint().map_err(|e| format!("ckpt: {e:?}"))?;
    let img2 = disk.image();
    let used = fsck_img(&img2, sim).map_err(|e| format!("fsck after cleanup: {e}"))?;
    let base = fsck_img(img, sim).unwrap();
    let (_d, mut st) = open(&img2, sim, c);
    let rep = st
        .check(true)
        .map_err(|e| format!("check after cleanup: {e:?}"))?;
    if !rep.errors.is_empty() || rep.shared_runs != 0 || rep.data_blocks != 0 {
        return Err(format!(
            "after cleanup: errors {:?}, {} refcount records, {} data blocks",
            rep.errors, rep.shared_runs, rep.data_blocks
        ));
    }
    // meta cells may stay allocated (hysteresis); object data must all be back
    let _ = (used, base);
    Ok(crashed)
}

fn matrix(stride: u64, policies: &[CrashPolicy]) -> (u64, u64) {
    matrix_of(stride, policies, &script(), &universe(), "snapshot")
}

fn matrix_of(
    stride: u64,
    policies: &[CrashPolicy],
    sc: &[OTxn<'static>],
    univ: &[Ghobject],
    what: &str,
) -> (u64, u64) {
    let c = cfg(true);
    let mut sim = SimConfig::new(128 << 20);
    sim.seed = 11;
    let img0 = image(&sim);
    // setup (collection) committed before any crash point
    let (d, mut st) = open(&img0, &sim, &c);
    let mut t = OTxn::new();
    t.mkcoll(c1());
    st.commit(&t).unwrap();
    st.checkpoint().unwrap();
    drop(st);
    let img = d.image();
    let mut setup = Model::default();
    setup.apply_txn(&t).unwrap();
    let events = workload(&img, &sim, &c, 1, None, sc).disk.events();
    let (mut n, mut crashed) = (0, 0);
    let mut k = 0;
    while k < events {
        for (pi, pol) in policies.iter().enumerate() {
            match crash_one(
                &img,
                &sim,
                &c,
                &setup,
                Some(k),
                *pol,
                k * 7 + pi as u64 + 1,
                sc,
                univ,
            ) {
                Ok(cr) => {
                    n += 1;
                    crashed += cr as u64;
                }
                Err(e) => panic!("k={k} policy#{pi}: {e}"),
            }
        }
        k += stride;
    }
    eprintln!("{what} crash matrix: {events} events, {n} scenarios, {crashed} crashed");
    (n, crashed)
}

#[test]
fn crash_matrix_snapshot_workload_every_io_boundary() {
    let (n, c) = matrix(
        1,
        &[
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ],
    );
    assert!(n > 100 && c * 2 > n, "scenarios {n}, crashed {c}");
}

// ------------------------------------------------------------------------------------------- random vs model

/// Snapshot-heavy random workload (clones, COW overwrites, punches, deletes, compression) vs the model, with clean
/// remounts (fsck incl. refcounts) and a final delete-all leak check.
fn random_run(seed: u64, ntxn: usize) {
    let mut r = Rig::new(true);
    r.gn.objs = (0..8).map(|i| g(&format!("o{i}"))).collect();
    let base = r.remount();
    let mut rng = Rng::new(seed);
    let objs = r.gn.objs.clone();
    let mut bufs: Vec<&'static [u8]> = Vec::new();
    for i in 0..ntxn {
        let mut t = OTxn::new();
        if rng.pct(20) {
            t.comp = Some(CompSpec {
                alg: Alg::Lz4,
                ratio_permille: 875,
                min_bytes: 8192,
                chunk_blks: 8,
            });
        }
        for _ in 0..rng.range(1, 4) {
            let o = objs[rng.below(objs.len() as u64) as usize].clone();
            let p = objs[rng.below(objs.len() as u64) as usize].clone();
            let off = rng.below(64) * 4096 + if rng.pct(30) { rng.below(4096) } else { 0 };
            match rng.below(100) {
                0..=39 => {
                    let n = if rng.pct(50) {
                        4096
                    } else {
                        rng.range(1, 200_000) as usize
                    };
                    let d: &'static [u8] = Box::leak(
                        if t.comp.is_some() {
                            cdata(n, rng.next_u64())
                        } else {
                            rnd(n, rng.next_u64())
                        }
                        .into_boxed_slice(),
                    );
                    bufs.push(d);
                    t.write(c1(), &o, off, d);
                }
                40..=54 => {
                    t.push(TOp::Clone {
                        cid: c1(),
                        src: o,
                        dst: p,
                    });
                }
                55..=64 => {
                    // EC stash shape (same offset) or any range; aligned or not
                    let len = if rng.pct(50) {
                        rng.range(1, 64) * 4096
                    } else {
                        rng.range(1, 200_000)
                    };
                    let doff = if rng.pct(60) {
                        off
                    } else {
                        rng.below(64) * 4096 + off % 4096 * rng.below(2)
                    };
                    t.push(TOp::CloneRange {
                        cid: c1(),
                        src: o,
                        dst: p,
                        src_off: off,
                        len,
                        dst_off: doff,
                    });
                }
                65..=74 => {
                    t.zero(c1(), &o, off, rng.range(1, 100_000));
                }
                75..=82 => {
                    t.truncate(c1(), &o, rng.below(300_000));
                }
                _ => {
                    t.remove(c1(), &o);
                }
            }
        }
        let mut probe = r.m.clone();
        if probe.apply_txn(&t).is_err() {
            continue;
        }
        r.run(&t);
        if i % 25 == 24 {
            check_clean(&mut r.st);
            r.remount();
        }
    }
    assert!(r.shared + shared_clones(&r.st) > 0);
    assert!(r.ranges + shared_ranges(&r.st) > 0);
    let mut t = OTxn::new();
    for o in r.m.colls[&c1()].keys().cloned().collect::<Vec<_>>() {
        t.remove(c1(), &o);
    }
    r.run(&t);
    let used = r.remount();
    let rep = r.st.check(true).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!((rep.shared_runs, rep.data_blocks), (0, 0), "seed {seed}");
    assert!(used >= base);
}

#[test]
fn random_snapshot_workload_vs_model() {
    for seed in 1..=4 {
        random_run(seed, 150);
    }
}

#[test]
#[ignore = "soak"]
fn random_snapshot_workload_soak() {
    for seed in 100..140 {
        random_run(seed, 400);
    }
}

#[test]
#[ignore = "soak"]
fn crash_matrix_snapshot_workload_soak() {
    matrix(1, &[CrashPolicy::MIXED, CrashPolicy::DROP_ALL]);
}

// ------------------------------------------------------------------------------------------- bench

/// RBD snapshot COW cost: per 4 MiB head object one txn `[clone head -> snap, 4 KiB write to head]` (the first write
/// after a snapshot), QD1. Returns (wall us/op, device-time us/op, KiB written/op, KiB read/op, data MiB in use).
fn snap_cow(share: bool, nobj: usize, frag: bool) -> (f64, f64, f64, f64, f64) {
    let mut sim = SimConfig::new(1 << 30);
    sim.seed = 5;
    let img = image(&sim);
    let c = cfg(share);
    let (disk, mut st) = open(&img, &sim, &c);
    let mut t = OTxn::new();
    t.mkcoll(c1());
    st.commit(&t).unwrap();
    let data = rnd(4 << 20, 1);
    for i in 0..nobj {
        let mut t = OTxn::new();
        t.write(c1(), &g(&format!("rbd_data.{i}")), 0, &data);
        st.commit(&t).unwrap();
    }
    if frag {
        // aged RBD heads: every other 4 KiB block overwritten (1024 extent runs per object)
        let d = rnd(4096, 7);
        for i in 0..nobj {
            for b in (0..1024u64).step_by(2) {
                let mut t = OTxn::new();
                t.write(c1(), &g(&format!("rbd_data.{i}")), b * 4096, &d);
                st.commit(&t).unwrap();
            }
        }
    }
    st.checkpoint().unwrap();
    let blk = rnd(4096, 2);
    let (s0, t0, w0) = (disk.stats(), st.clk.t, std::time::Instant::now());
    let mut r = Rng::new(3);
    for i in 0..nobj {
        let h = g(&format!("rbd_data.{i}"));
        let mut t = OTxn::new();
        t.push(TOp::Clone {
            cid: c1(),
            src: h.clone(),
            dst: g(&format!("rbd_data.{i}.snap1")),
        });
        t.write(c1(), &h, r.below(1024) * 4096, &blk);
        st.commit(&t).unwrap();
    }
    let wall = w0.elapsed().as_secs_f64() * 1e6 / nobj as f64;
    let virt = (st.clk.t - t0) as f64 / 1e3 / nobj as f64;
    let s1 = disk.stats();
    let kib = |l: u64| l as f64 * sim.lba_size as f64 / 1024.0 / nobj as f64;
    st.checkpoint().unwrap();
    let used = fsck_img(&disk.image(), &sim).unwrap() as f64 * 4096.0 / (1 << 20) as f64;
    (
        wall,
        virt,
        kib(s1.write_lbas - s0.write_lbas),
        kib(s1.read_lbas - s0.read_lbas),
        used,
    )
}

#[test]
#[ignore = "measurement: run with --release --nocapture"]
fn bench_rbd_snapshot_clone_plus_4k_overwrite() {
    let n = 64;
    for (share, frag) in [(false, false), (true, false), (false, true), (true, true)] {
        let (w, v, wk, rk, used) = snap_cow(share, n, frag);
        eprintln!(
            "SNAP-COW share={share} frag={frag}: {n} x [clone 4 MiB + 4 KiB write]: wall {w:.1} us/op, device time {v:.1} us/op, written {wk:.1} KiB/op, read {rk:.1} KiB/op, data in use {used:.0} MiB"
        );
    }
}

// ------------------------------------------------------------------------------------------- clone_range (am. 38)

fn crange(src: &str, dst: &str, so: u64, len: u64, dof: u64) -> TOp<'static> {
    TOp::CloneRange {
        cid: c1(),
        src: g(src),
        dst: g(dst),
        src_off: so,
        len,
        dst_off: dof,
    }
}

fn shared_ranges(st: &St) -> u64 {
    st.shards.iter().map(|s| s.stats.shared_ranges).sum()
}

/// EC legacy stash of `[off, off+len)` of `o` into `gen` + overwrite with `d`, one txn (the shard txn shape).
fn stash_txn(o: &str, stash: &str, off: u64, d: &'static [u8]) -> OTxn<'static> {
    let mut t = OTxn::new();
    t.touch(c1(), &g(stash));
    t.push(crange(o, stash, off, d.len() as u64, off));
    t.write(c1(), &g(o), off, d);
    t
}

/// EC rollback of that stash: copy the stashed range back, drop the stash.
fn rollback_txn(o: &str, stash: &str, off: u64, len: u64) -> OTxn<'static> {
    let mut t = OTxn::new();
    t.push(crange(stash, o, off, len, off));
    t.remove(c1(), &g(stash));
    t
}

#[test]
fn clone_range_shares_the_aligned_middle_and_copies_the_edges() {
    let mut r = Rig::new(true);
    let base = r.remount();
    let mut t = OTxn::new();
    t.write(c1(), &g("a"), 0, leakv(rnd(1 << 20, 1)));
    r.run(&t);
    let used = r.remount();
    assert_eq!(used - base, 256);
    // aligned: metadata only
    let mut t = OTxn::new();
    t.touch(c1(), &g("x"));
    t.push(crange("a", "x", 0, 512 << 10, 0));
    r.run(&t);
    assert_eq!(shared_ranges(&r.st), 1);
    assert!(check_clean(&mut r.st) > 0);
    assert_eq!(r.remount(), used);
    // unaligned with the same in-block offset: middle shared, the two edge blocks copied; to another offset
    let mut t = OTxn::new();
    t.push(crange("a", "y", 1000, 300_000, 4096 * 7 + 1000));
    r.run(&t);
    assert_eq!(shared_ranges(&r.st), 1);
    assert_eq!(r.remount(), used + 2);
    // different in-block offsets: copied (75 blocks)
    let mut t = OTxn::new();
    t.push(crange("a", "z", 1000, 300_000, 0));
    r.run(&t);
    assert_eq!(shared_ranges(&r.st), 0);
    assert_eq!(r.remount(), used + 2 + 74);
    // over existing destination data, with staged data of the same txn in the range and around it
    let mut t = OTxn::new();
    t.write(c1(), &g("z"), 4096, leakv(rnd(20_000, 2)));
    t.push(crange("a", "z", 65536, 131072, 0));
    t.write(c1(), &g("z"), 8192, leakv(rnd(100, 3)));
    r.run(&t);
    assert_eq!(shared_ranges(&r.st), 1);
    check_clean(&mut r.st);
    r.remount();
    // a source with staged data of this txn in the range: copied
    let mut t = OTxn::new();
    t.write(c1(), &g("a"), 4096, leakv(rnd(4096, 4)));
    t.push(crange("a", "w", 0, 65536, 0));
    r.run(&t);
    assert_eq!(shared_ranges(&r.st), 0);
    // clone_range of a shared range again, then onto itself
    let mut t = OTxn::new();
    t.push(crange("x", "v", 0, 1 << 20, 0));
    t.push(crange("v", "v", 0, 8192, 8192));
    r.run(&t);
    r.remount();
    check_clean(&mut r.st);
    for o in ["a", "x", "y", "z", "w", "v"] {
        let mut t = OTxn::new();
        t.remove(c1(), &g(o));
        r.run(&t);
        check_clean(&mut r.st);
    }
    assert_eq!(r.remount(), base);
    assert_eq!(check_clean(&mut r.st), 0);
}

/// Commit `t` (then model + verify like `Rig::run`); device bytes (read, written) of the commit alone.
fn run_io(r: &mut Rig, t: &OTxn) -> (u64, u64) {
    let s0 = r.disk.stats();
    r.st.commit(t).unwrap_or_else(|e| panic!("{e:?}"));
    let s1 = r.disk.stats();
    let b = |l: u64| l * r.sim.lba_size as u64;
    let io = (
        b(s1.read_lbas - s0.read_lbas),
        b(s1.write_lbas - s0.write_lbas),
    );
    r.m.apply_txn(t).unwrap();
    for o in t.ops.iter().flat_map(objs_of) {
        if !r.gn.objs.contains(&o) {
            r.gn.objs.push(o);
        }
    }
    verify(&mut r.st, &r.m, &r.gn, &mut r.vr).unwrap();
    io
}

#[test]
fn ec_stash_costs_metadata_only_rollback_restores_and_roll_forward_frees() {
    for share in [true, false] {
        let mut r = Rig::new(true);
        r.cfg.shard.shared_clone = share;
        let base = r.remount();
        let old = rnd(2 << 20, 1);
        let mut t = OTxn::new();
        t.write(c1(), &g("h"), 0, leakv(old.clone()));
        r.run(&t);
        let used = r.remount();
        assert_eq!(used - base, 512);
        // 4K overwrite: the stash keeps the old block (both modes: +1 block), sharing reads and writes no stash data
        let (rd, wr) = run_io(&mut r, &stash_txn("h", "h.g1", 8192, leakv(rnd(4096, 2))));
        assert_eq!(shared_ranges(&r.st), share as u64);
        if share {
            assert!(
                rd == 0 && wr <= 2 * 4096,
                "4K stash read {rd} wrote {wr} (data + WAL)"
            );
        } else {
            assert!(rd >= 4096 && wr >= 3 * 4096, "4K copy read {rd} wrote {wr}");
        }
        assert_eq!(r.remount(), used + 1);
        // roll forward: the stash goes, exactly the old block is freed
        let mut t = OTxn::new();
        t.remove(c1(), &g("h.g1"));
        r.run(&t);
        assert_eq!(r.remount(), used);
        check_clean(&mut r.st);
        // full-chunk (2 MiB) overwrite, then a second stash generation on top, then roll both back (newest first)
        let cur = r.m.colls[&c1()][&g("h")].data.clone();
        let (rd, wr) = run_io(&mut r, &stash_txn("h", "h.g2", 0, leakv(rnd(2 << 20, 3))));
        if share {
            assert!(
                rd < 256 << 10 && wr < (2 << 20) + (256 << 10),
                "2M stash read {rd} wrote {wr}"
            );
        } else {
            assert!(
                rd >= 2 << 20 && wr >= 4 << 20,
                "2M copy read {rd} wrote {wr}"
            );
        }
        r.run(&stash_txn("h", "h.g3", 1 << 20, leakv(rnd(512 << 10, 4))));
        assert_eq!(r.remount(), used + 512 + 128);
        r.run(&rollback_txn("h", "h.g3", 1 << 20, 512 << 10));
        r.run(&rollback_txn("h", "h.g2", 0, 2 << 20));
        assert_eq!(r.m.colls[&c1()][&g("h")].data, cur);
        assert_eq!(r.remount(), used);
        check_clean(&mut r.st);
        let mut t = OTxn::new();
        t.remove(c1(), &g("h"));
        r.run(&t);
        assert_eq!(r.remount(), base);
        assert_eq!(check_clean(&mut r.st), 0);
    }
}

/// NT-ecwrite-02: a copied (not shared) `clone_range` reads and writes only the source's data; its holes stay holes.
/// The EC truncate stash shape: a sparse 32 MiB shard truncated to 8 KiB stashes its whole tail first.
#[test]
fn copied_clone_range_keeps_sparse_holes() {
    const SIZE: u64 = 32 << 20;
    for share in [true, false] {
        let mut r = Rig::new(true);
        r.cfg.shard.shared_clone = share;
        let base = r.remount();
        let mut t = OTxn::new();
        t.write(c1(), &g("s"), 0, leakv(rnd(8192, 1)));
        t.write(c1(), &g("s"), SIZE - 8192, leakv(rnd(8192, 2)));
        r.run(&t);
        let used = r.remount();
        assert_eq!(used - base, 4);
        // stash the tail, truncate, all in one txn; the stash copy is forced by staged data of this txn in the range
        // (a dirty source is never shared) and, without sharing, by the mode
        let mut t = OTxn::new();
        t.write(c1(), &g("s"), SIZE - 4096, leakv(rnd(4096, 3)));
        t.touch(c1(), &g("s.g1"));
        t.push(crange("s", "s.g1", 8192, SIZE - 8192, 8192));
        t.truncate(c1(), &g("s"), 8192);
        let (_, wr) = run_io(&mut r, &t);
        assert_eq!(shared_ranges(&r.st), 0);
        assert!(wr < 1 << 20, "sparse stash wrote {wr} bytes");
        // the head's two tail blocks moved to the stash
        assert_eq!(r.remount(), used);
        // rollback restores the sparse tail, the stash goes
        let mut t = rollback_txn("s", "s.g1", 8192, SIZE - 8192);
        t.truncate(c1(), &g("s"), SIZE);
        let (_, wr) = run_io(&mut r, &t);
        assert!(wr < 1 << 20, "sparse rollback wrote {wr} bytes");
        assert_eq!(r.remount(), used);
        // unaligned (different in-block offsets: never shared) onto the same object, overlapping, over a hole
        let mut t = OTxn::new();
        t.push(crange("s", "s", 100, SIZE - 8192, 4096 + 300));
        let (_, wr) = run_io(&mut r, &t);
        assert!(wr < 1 << 20, "overlapping sparse copy wrote {wr} bytes");
        check_clean(&mut r.st);
        assert!(r.remount() <= used + 6);
        let mut t = OTxn::new();
        t.remove(c1(), &g("s"));
        r.run(&t);
        assert_eq!(r.remount(), base);
        assert_eq!(check_clean(&mut r.st), 0);
    }
}

// ------------------------------------------------------------------------------------------- EC stash generations

/// One EC-shaped step of [`ec_script`]: the txn and, for a rollback, the head and the bytes it must hold afterwards.
struct EcStep {
    t: OTxn<'static>,
    expect: Option<(Ghobject, Vec<u8>)>,
}

/// One stacked stash generation: (gen name, pre-image, stash ranges).
type StashGen = (String, Vec<u8>, Vec<(u64, u64)>);

/// Random EC shard workload over 3 heads (adr 0021 am. 38 shapes): stash txns `[touch gen, clone_range head->gen of
/// every range the txn changes within the old size (pre-op, possibly overlapping, aligned out or exact), then 1-3 of
/// write / append / zero / truncate down or up]`, generations stacked several deep per head, rollback newest first
/// (`[truncate back to the old size if it grew, clone_range gen->head per stash range, remove gen]`, must give the
/// exact pre-image), roll-forward oldest first (remove gen), plain clone_range between heads now and then.
fn ec_script(seed: u64, n: usize) -> (Vec<EcStep>, Vec<Ghobject>) {
    let mut rng = Rng::new(seed);
    let heads: Vec<String> = (0..3).map(|i| format!("h{i}")).collect();
    let mut m = Model::default();
    let mut setup = OTxn::new();
    setup.mkcoll(c1());
    m.apply_txn(&setup).unwrap();
    // per head: stack of (gen name, pre-image, stash ranges)
    let mut stacks: Vec<Vec<StashGen>> = vec![Vec::new(); 3];
    let mut gen_no = 0u64;
    let mut univ: Vec<Ghobject> = heads.iter().map(|h| g(h)).collect();
    let mut out = Vec::new();
    let bytes = |m: &Model, h: &str| -> Vec<u8> {
        m.colls[&c1()]
            .get(&g(h))
            .map(|o| o.data.clone())
            .unwrap_or_default()
    };
    // initial content: heads of different sizes (unaligned ends)
    let mut t = OTxn::new();
    for (i, h) in heads.iter().enumerate() {
        let len = rng.range(1, 300_000) as usize + i * 4096;
        t.write(c1(), &g(h), 0, leakv(rnd(len, rng.next_u64())));
    }
    m.apply_txn(&t).unwrap();
    out.push(EcStep { t, expect: None });
    while out.len() < n {
        let hi = rng.below(3) as usize;
        let h = heads[hi].clone();
        let old = bytes(&m, &h);
        let osz = old.len() as u64;
        let roll = rng.below(100);
        let mut t = OTxn::new();
        let mut expect = None;
        if roll < 25 && !stacks[hi].is_empty() {
            // rollback newest first
            let (gn, pre, ranges) = stacks[hi].pop().unwrap();
            if osz > pre.len() as u64 {
                t.truncate(c1(), &g(&h), pre.len() as u64);
            }
            for &(a, b) in &ranges {
                t.push(crange(&gn, &h, a, b - a, a));
            }
            t.remove(c1(), &g(&gn));
            expect = Some((g(&h), pre));
        } else if roll < 40 && !stacks[hi].is_empty() {
            // roll forward oldest first
            let (gn, _, _) = stacks[hi].remove(0);
            t.remove(c1(), &g(&gn));
        } else if roll < 45 {
            // plain clone_range between heads (the stashes of the destination become unusable: drop them)
            let d = (hi + 1 + rng.below(2) as usize) % 3;
            let so = rng.below(64) * 4096 + if rng.pct(30) { rng.below(4096) } else { 0 };
            let dof = if rng.pct(70) {
                so
            } else {
                rng.below(64) * 4096
            };
            let len = rng.range(1, 200_000);
            for (gn, _, _) in stacks[d].drain(..) {
                t.remove(c1(), &g(&gn));
            }
            t.push(crange(&h, &heads[d], so, len, dof));
        } else {
            gen_no += 1;
            let gn = format!("{h}.g{gen_no}");
            univ.push(g(&gn));
            let align = match rng.below(3) {
                0 => 1,
                1 => 4096,
                _ => 8192,
            };
            let mut muts: Vec<(u8, u64, u64)> = Vec::new();
            let mut ranges: Vec<(u64, u64)> = Vec::new();
            let cover = |a: u64, b: u64, ranges: &mut Vec<(u64, u64)>| {
                let (a, b) = (a / align * align, b.div_ceil(align) * align);
                let b = b.min(osz);
                if a < b {
                    ranges.push((a, b));
                }
            };
            for _ in 0..rng.range(1, 4) {
                let sz = osz.max(1);
                match rng.below(10) {
                    0..=4 => {
                        let off = rng.below(sz + 8192);
                        let off = if rng.pct(50) { off / 4096 * 4096 } else { off };
                        let len = if rng.pct(40) {
                            4096
                        } else {
                            rng.range(1, 150_000)
                        };
                        muts.push((0, off, len));
                        cover(off, off + len, &mut ranges);
                    }
                    5 => {
                        // append
                        let len = rng.range(1, 70_000);
                        muts.push((0, osz, len));
                    }
                    6 | 7 => {
                        let off = rng.below(sz);
                        let len = rng.range(1, 100_000);
                        muts.push((1, off, len));
                        cover(off, off + len, &mut ranges);
                    }
                    _ => {
                        let to = if rng.pct(70) {
                            rng.below(sz)
                        } else {
                            osz + rng.below(50_000)
                        };
                        muts.push((2, to, 0));
                        cover(to, osz, &mut ranges);
                    }
                }
            }
            t.touch(c1(), &g(&gn));
            // the stash: all clones pre-op (overlaps allowed, shuffled order)
            if rng.pct(50) {
                ranges.reverse();
            }
            for &(a, b) in &ranges {
                t.push(crange(&h, &gn, a, b - a, a));
            }
            for (k, a, b) in muts {
                match k {
                    0 => {
                        t.write(c1(), &g(&h), a, leakv(rnd(b as usize, rng.next_u64())));
                    }
                    1 => {
                        t.zero(c1(), &g(&h), a, b);
                    }
                    _ => {
                        t.truncate(c1(), &g(&h), a);
                    }
                }
            }
            stacks[hi].push((gn, old.clone(), ranges));
        }
        if m.apply_txn(&t).is_err() {
            continue;
        }
        if let Some((o, pre)) = &expect {
            assert_eq!(
                &bytes(&m, &String::from_utf8_lossy(&o.hobj.oid)),
                pre,
                "script rollback"
            );
        }
        out.push(EcStep { t, expect });
    }
    (out, univ)
}

fn ec_head_bytes(st: &mut St, o: &Ghobject) -> Vec<u8> {
    let sz = st.stat(&c1(), o).unwrap().map_or(0, |s| s.size);
    st.read(&c1(), o, 0, sz).unwrap()
}

/// EC stash generations vs the model and the exact pre-image after each rollback (sharing on and off), with checkpoints
/// requested between txns, clean remounts (fsck incl. refcounts) and a final delete-all leak check.
fn ec_generations_run(seed: u64, n: usize, share: bool) {
    let mut r = Rig::new(true);
    r.cfg.shard.shared_clone = share;
    let base = r.remount();
    let (steps, _) = ec_script(seed, n);
    let mut rng = Rng::new(seed ^ 0x5eed);
    for (i, s) in steps.iter().enumerate() {
        r.run(&s.t);
        if let Some((o, pre)) = &s.expect {
            let got = ec_head_bytes(&mut r.st, o);
            assert!(
                got == *pre,
                "seed {seed} step {i}: rollback of {o:?} did not restore the pre-image (len {} vs {})",
                got.len(),
                pre.len()
            );
        }
        if rng.pct(15) {
            r.st.shards[0].sh.request_checkpoint();
            r.st.idle();
        }
        if i % 40 == 39 {
            check_clean(&mut r.st);
            r.remount();
        }
    }
    if share {
        assert!(r.ranges + shared_ranges(&r.st) > 0);
    }
    let mut t = OTxn::new();
    for o in r.m.colls[&c1()].keys().cloned().collect::<Vec<_>>() {
        t.remove(c1(), &o);
    }
    r.run(&t);
    let used = r.remount();
    let rep = r.st.check(true).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!((rep.shared_runs, rep.data_blocks), (0, 0), "seed {seed}");
    assert!(used >= base);
}

#[test]
fn ec_stash_generations_rollback_restores_exact_bytes() {
    for seed in 1..=6 {
        ec_generations_run(seed, 160, true);
    }
    ec_generations_run(7, 120, false);
}

#[test]
#[ignore = "soak"]
fn ec_stash_generations_soak() {
    for seed in 100..160 {
        ec_generations_run(seed, 400, true);
    }
}

fn ec_matrix(seed: u64, n: usize, stride: u64) {
    let (steps, univ) = ec_script(seed, n);
    let sc: Vec<OTxn<'static>> = steps.into_iter().map(|s| s.t).collect();
    let pols = [
        CrashPolicy::DROP_ALL,
        CrashPolicy::PERSIST_ALL,
        CrashPolicy::MIXED,
    ];
    let (s, c) = matrix_of(stride, &pols, &sc, &univ, "ec stash");
    assert!(s > 100 && c * 2 > s, "scenarios {s}, crashed {c}");
}

/// Crash at every IO boundary of an EC stash / rollback / roll-forward script (stacked generations, overlapping and
/// unaligned stash ranges, truncates): recovery equals a model prefix (so a rollback is either not applied or gives the
/// exact pre-image), check clean, delete-all leaves no block and no refcount record.
#[test]
fn crash_matrix_ec_stash_generations_every_io_boundary() {
    ec_matrix(1, 40, 1);
}

#[test]
#[ignore = "soak"]
fn crash_matrix_ec_stash_generations_soak() {
    for seed in 2..6 {
        ec_matrix(seed, 80, 1);
    }
}

/// An RBD head after random 4 KiB overwrites has up to one extent run per block (1024 for 4 MiB). Its snapshot COW clone
/// shares too (`SHARE_MAX_EXTENTS` covers a 4 MiB object); at 256 runs it was copied: 4 MiB read + 4 MiB write per first
/// write after a snapshot, the device saturated for seconds (doc/perf/tail-latency-20261015.md, snap cell).
#[test]
fn fragmented_4m_head_clone_shares() {
    let mut r = Rig::new(true);
    let mut t = OTxn::new();
    t.write(c1(), &g("a"), 0, leakv(rnd(4 << 20, 1)));
    r.run(&t);
    let d = leakv(rnd(4096, 2));
    for b in (0..1024u64).step_by(2) {
        let mut t = OTxn::new();
        t.write(c1(), &g("a"), b * 4096, d);
        r.run(&t);
    }
    let used = r.remount();
    let mut t = OTxn::new();
    t.push(clone_op("a", "a.s1"));
    t.write(c1(), &g("a"), 4096, d);
    r.run(&t);
    assert_eq!(
        shared_clones(&r.st),
        1,
        "fragmented head shared, not copied"
    );
    check_clean(&mut r.st);
    assert_eq!(r.remount(), used + 1, "only the overwritten block is new");
}
