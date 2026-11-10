// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! In-place upgrade of a store an earlier build wrote with exact omap counters (adr 0647-omap-blind-removals): onodes
//! of format 2 (`F_OCNT` + counters), `c` counter records in the tree and in the WAL, neither `FEAT_OMAP_UNCOUNTED` nor
//! `FEAT_OMAP_TOMBS` (runs of removals, D1). The first mount of this build makes both bits durable in both superblock
//! copies (one write) before anything else is written, removes
//! the `c` records and reads the onodes without counters: every omap key, value and header reads back the same, the
//! object check and fsck are clean, the store takes omap writes, a second mount finds nothing to remove. The crash matrix
//! cuts the upgrade mount and the checkpoint after it at every device event with each crash policy and mounts again:
//! the same result; a cut before the bit is durable leaves everything but the superblock as the earlier build wrote it.

use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use std::collections::BTreeMap;
use store::dev::{BlockDev, Clock, CrashPolicy, SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::layout::{
    FEAT_OMAP_TOMBS, FEAT_OMAP_UNCOUNTED, FEATURES_KNOWN, FEATURES_STICKY, MkfsParams, mkfs,
    read_super,
};
use store::obj::keys::{T_ONODE, T_OPEND, onode_id_of};
use store::obj::onode::{F_OCNT, F_OMAP, Onode};
use store::obj::txn::Bytes;
use store::obj::{OTxn, Store, StoreCfg, TOp};
use store::shard::{Event, Shard, Txn};
use store::state::Op;

/// Omap contents per object: header, keys in order.
type Model = BTreeMap<(CollT, Ghobject), (Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>)>;

/// The incompat bits of this build an earlier one lacks (both set by the same superblock write).
const BITS: u64 = FEAT_OMAP_UNCOUNTED | FEAT_OMAP_TOMBS;

fn sim() -> SimConfig {
    SimConfig::new(64 << 20)
}

fn coll(seed: u32) -> CollT {
    CollT::Pg(SpgT {
        pgid: PgT::new(1, seed),
        shard: ShardId::NO_SHARD,
    })
}

fn obj(seed: u32, name: &str) -> Ghobject {
    Ghobject::new(
        Hobject::new(name.as_bytes(), SnapId::NOSNAP, seed, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn put(m: &mut Model, t: &mut OTxn, c: CollT, o: &Ghobject, kv: Vec<(Vec<u8>, Vec<u8>)>) {
    let e = m.entry((c, o.clone())).or_default();
    for (k, v) in &kv {
        e.1.insert(k.clone(), v.clone());
    }
    t.push(TOp::OmapSetKeys {
        cid: c,
        oid: o.clone(),
        pairs: kv
            .into_iter()
            .map(|(k, v)| (Bytes::Owned(k), Bytes::Owned(v)))
            .collect(),
    });
}

fn mount(disk: &SimDisk) -> Result<Store<SimDev, SimClock>, store::obj::ObjError> {
    let d = disk.clone();
    Store::mount(move || d.queue(), SimClock::default(), StoreCfg::default()).map(|x| x.0)
}

fn poll(s: &mut Shard<SimDev>, clk: &mut SimClock) -> bool {
    let mut ev = Vec::new();
    s.poll(clk.t, &mut ev);
    let mut acked = false;
    for e in ev {
        match e {
            Event::Acked(_) => acked = true,
            Event::Failed(f) => panic!("shard failed: {f:?}"),
            _ => {}
        }
    }
    let h = s.dev().next_deadline();
    clk.idle(h);
    acked
}

/// Apply raw `ops` to shard `i` (durable on return).
fn raw(st: &mut Store<SimDev, SimClock>, i: usize, ops: Vec<Op>) {
    let clk = &mut st.clk;
    let s = &mut st.shards[i].sh;
    let mut t: Txn<Vec<u8>> = Txn::new(7);
    t.ops = ops;
    let lsn = loop {
        match s.submit(t) {
            Ok(lsn) => break lsn,
            Err((store::StoreError::Busy | store::StoreError::WalFull, back)) => {
                poll(s, clk);
                t = back;
            }
            Err((e, _)) => panic!("submit: {e:?}"),
        }
    };
    for _ in 0..100_000 {
        if poll(s, clk) && s.durable_lsn() >= lsn {
            return;
        }
    }
    panic!("raw txn never acked");
}

/// What an earlier build wrote for the omap objects of shard `i` whose onode id satisfies `pick`: the onode as format 2
/// with (stale) counters, a `c` counter-delta record; one `c` record of object `gone`, which no longer exists. Returns
/// the number of `c` records.
fn age_shard(
    st: &mut Store<SimDev, SimClock>,
    i: usize,
    gone: u64,
    pick: impl Fn(u64) -> bool,
) -> usize {
    let dump = st.shards[i].sh.dump_blocking(&mut st.clk).unwrap();
    let mut ops = Vec::new();
    for (k, v) in &dump {
        if k[0] != T_ONODE || v[0] != 1 {
            continue;
        }
        let on = Onode::decode(v).unwrap();
        let id = onode_id_of(k).unwrap();
        if on.flags & F_OMAP == 0 || !pick(id) {
            continue;
        }
        let mut b = vec![2u8];
        b.extend_from_slice(&on.size.to_le_bytes());
        b.extend_from_slice(&(on.flags | F_OCNT).to_le_bytes());
        b.extend_from_slice(&(1_000_000 + id).to_le_bytes());
        b.extend_from_slice(&(7_000_000 + id).to_le_bytes());
        ops.push(Op::Put(k.clone(), b));
        ops.push(Op::Put(pend_key(id), pend_val(-3, -300)));
    }
    ops.push(Op::Put(pend_key(gone), pend_val(5, 50)));
    let n = ops.len().div_ceil(2);
    raw(st, i, ops);
    n
}

fn pend_key(id: u64) -> Vec<u8> {
    let mut k = vec![T_OPEND];
    k.extend_from_slice(&id.to_be_bytes());
    k
}

fn pend_val(keys: i64, bytes: i64) -> Vec<u8> {
    let mut v = keys.to_le_bytes().to_vec();
    v.extend_from_slice(&bytes.to_le_bytes());
    v
}

/// `c` records and onodes of format 2 (with counters), over all shards.
fn legacy(st: &mut Store<SimDev, SimClock>) -> (usize, usize) {
    let (mut pend, mut f2) = (0, 0);
    for i in 0..st.shards.len() {
        for (k, v) in st.shards[i].sh.dump_blocking(&mut st.clk).unwrap() {
            pend += usize::from(k[0] == T_OPEND);
            f2 += usize::from(k[0] == T_ONODE && v[0] == 2);
        }
    }
    (pend, f2)
}

/// Rewrite both superblock copies without [`BITS`] (what an earlier build wrote): the bits carry no field, so the copy
/// keeps its layout; its crc is recomputed.
fn clear_bit(disk: &SimDisk) {
    let mut d = disk.queue();
    let mut clk = SimClock::default();
    let mut io = store::sio::Sio::new(&mut d, &mut clk);
    let cur = io.read(&[(0, 1), (1, 1)]).unwrap();
    for (blk, mut b) in cur.into_iter().enumerate() {
        let f = u64::from_le_bytes(b[12..20].try_into().unwrap()) & !BITS;
        b[12..20].copy_from_slice(&f.to_le_bytes());
        let z = b.iter().rposition(|&x| x != 0).unwrap() + 1;
        let p = (z.saturating_sub(4)..=z)
            .find(|&p| {
                let mut o = b.clone();
                o[12..20].copy_from_slice(&(f | BITS).to_le_bytes());
                u32::from_le_bytes(o[p..p + 4].try_into().unwrap()) == store::codec::crc(&o[..p])
            })
            .expect("superblock crc");
        let c = store::codec::crc(&b[..p]);
        b[p..p + 4].copy_from_slice(&c.to_le_bytes());
        io.write_one(blk as u64, &b).unwrap();
    }
}

/// [`BITS`] of both superblock copies, as stored: all of them (true) or none (false).
fn copies_have_bit(img: &SimImage) -> [bool; 2] {
    [0, 1].map(|blk| {
        let b = img.read_lba(blk);
        let f = u64::from_le_bytes(b[12..20].try_into().unwrap()) & BITS;
        assert!(
            f == 0 || f == BITS,
            "lba {blk}: the bits go together ({f:#x})"
        );
        f == BITS
    })
}

fn features(img: &SimImage) -> u64 {
    let disk = SimDisk::from_image(img, sim());
    read_super(&mut disk.queue(), &mut SimClock::default())
        .unwrap()
        .0
        .features
}

/// An earlier build's store (2 shards): omap objects with a header on some, a hot object whose batches were staged as
/// runs (adr 0476) with removals, counters on most onodes and `c` records in the tree, more of them only in the WAL
/// (written after the last checkpoint), no run of removals (its removal batches are small), and none of [`BITS`].
fn fixture() -> (SimImage, Model) {
    let disk = SimDisk::new(sim());
    let p = MkfsParams {
        shards: 2,
        wal_blocks: 1024,
        align_blocks: 1,
        meta_pct: 10,
        ..Default::default()
    };
    mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    let mut st = mount(&disk).unwrap();
    let mut m = Model::new();
    let mut i = 0u32;
    for seed in 0..4 {
        let c = coll(seed);
        let mut t = OTxn::new();
        t.push(TOp::MkColl {
            cid: c,
            bits: 0,
            exist_ok: true,
        });
        st.commit(&t).unwrap();
        for n in 0..12 {
            let o = obj(seed, &format!("rbd_header.{seed}.{n}"));
            let mut t = OTxn::new();
            t.push(TOp::Touch {
                cid: c,
                oid: o.clone(),
            });
            let kv = (0..(3 + n * 5))
                .map(|_| {
                    i += 1;
                    (
                        format!("key_{i:06}").into_bytes(),
                        vec![i as u8; 20 + i as usize % 90],
                    )
                })
                .collect();
            put(&mut m, &mut t, c, &o, kv);
            if n % 3 == 0 {
                let h = format!("hdr{n}").into_bytes();
                t.push(TOp::OmapSetHeader {
                    cid: c,
                    oid: o.clone(),
                    header: Bytes::Owned(h.clone()),
                });
                m.get_mut(&(c, o.clone())).unwrap().0 = h;
            }
            st.commit(&t).unwrap();
        }
    }
    let c = coll(1);
    let hot = obj(1, "rbd_directory");
    for b in 0..4u32 {
        let kv: BTreeMap<Vec<u8>, Vec<u8>> = (0..200)
            .map(|j| {
                let k = format!("name_{:05}", (b * 130 + j) % 700).into_bytes();
                (
                    k,
                    format!("v{b}.{j}.{}", "x".repeat((j % 30) as usize)).into_bytes(),
                )
            })
            .collect();
        let mut enc = Vec::new();
        denc::SortedKv::encode_into(
            &mut enc,
            kv.len(),
            kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        );
        let e = m.entry((c, hot.clone())).or_default();
        e.1.extend(kv);
        let mut t = OTxn::new();
        t.push(TOp::OmapSetRun {
            cid: c,
            oid: hot.clone(),
            run: store::obj::KvRunData::from_encoding(enc.into()).unwrap(),
        });
        st.queue(&t, 1 + u64::from(b)).unwrap();
        st.sync().unwrap();
        let rm: Vec<Vec<u8>> = (0..15)
            .map(|j| format!("name_{:05}", (b * 97 + j * 13) % 700).into_bytes())
            .collect();
        for k in &rm {
            e.1.remove(k);
        }
        let mut t = OTxn::new();
        t.push(TOp::OmapRmKeys {
            cid: c,
            oid: hot.clone(),
            keys: rm.into_iter().map(Bytes::Owned).collect(),
        });
        st.commit(&t).unwrap();
    }
    st.sync().unwrap();
    st.checkpoint().unwrap();
    // the earlier build's records: most in the tree (checkpointed), the odd ids of shard 1 only in the WAL
    let gone = u64::MAX / 3;
    let mut pend = age_shard(&mut st, 0, gone, |_| true);
    pend += age_shard(&mut st, 1, gone + 1, |id| id % 2 == 0);
    st.checkpoint().unwrap();
    pend += age_shard(&mut st, 1, gone + 2, |id| id % 2 == 1);
    let (seen, f2) = legacy(&mut st);
    assert!(
        seen == pend && pend > 20 && f2 + 3 == pend,
        "{seen} / {pend} c records, {f2} onodes of format 2"
    );
    drop(st);
    let disk = SimDisk::from_image(&disk.crash_image(CrashPolicy::PERSIST_ALL), sim());
    clear_bit(&disk);
    let img = disk.image();
    assert_eq!(features(&img) & BITS, 0, "an earlier build's store");
    (img, m)
}

/// Mount as this build (the upgrade), then a checkpoint.
fn upgrade(disk: &SimDisk) -> Result<(), store::obj::ObjError> {
    let mut st = mount(disk)?;
    st.checkpoint()?;
    Ok(())
}

/// The upgraded store: the bits in both copies, every omap key / value / header as written, no `c` record left, onodes
/// read without counters, check and fsck clean.
fn verify(disk: &SimDisk, m: &Model, what: &str) {
    let mut st = mount(disk).unwrap_or_else(|e| panic!("{what}: mount: {e}"));
    assert_eq!(
        copies_have_bit(&disk.image()),
        [true, true],
        "{what}: both copies"
    );
    for ((c, o), (h, kv)) in m {
        let (got, more) = st.omap_iter(c, o, b"", usize::MAX - 1).unwrap();
        assert!(!more, "{what}: {o:?}");
        let want: Vec<(Vec<u8>, Vec<u8>)> =
            kv.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        assert!(got == want, "{what}: {o:?} keys/values/order");
        assert_eq!(&st.omap_header(c, o).unwrap(), h, "{what}: {o:?} header");
        let s = st.scrub(c, o, 0).unwrap();
        assert_eq!(s.omap_keys, kv.len() as u64, "{what}: {o:?} recount");
    }
    assert_eq!(legacy(&mut st).0, 0, "{what}: c records left");
    let r = st.check(true).unwrap();
    assert!(r.errors.is_empty(), "{what}: check {:?}", r.errors);
    drop(st);
    store::fsck::fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&store::obj::onode::fsck_refs),
    )
    .unwrap_or_else(|e| panic!("{what}: fsck {e}"));
}

#[test]
fn the_bit_is_known_sticky_and_set_by_mkfs() {
    // an earlier build's `FEATURES_KNOWN` lacks the bits: it refuses a store that carries one in either copy (the mount
    // gate `newer_store_is_refused_untouched` in tests/upgrade.rs); sticky: no superblock write of this build drops them
    assert_eq!(FEATURES_KNOWN & BITS, BITS);
    assert_eq!(FEATURES_STICKY & BITS, BITS);
    let disk = SimDisk::new(sim());
    mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 1,
            wal_blocks: 256,
            align_blocks: 1,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(copies_have_bit(&disk.image()), [true, true]);
}

#[test]
fn upgrade_drops_the_counters_and_keeps_every_entry() {
    let (img, mut m) = fixture();
    let disk = SimDisk::from_image(&img, sim());
    assert_eq!(copies_have_bit(&img), [false, false]);
    upgrade(&disk).unwrap();
    verify(&disk, &m, "upgraded");
    let mut st = mount(&disk).unwrap();
    assert!(
        legacy(&mut st).1 > 0,
        "onodes nothing rewrote keep format 2 (read without counters)"
    );
    // omap writes on upgraded objects: removals (blind and per key), sets, a range removal
    let c = coll(1);
    let hot = obj(1, "rbd_directory");
    let o = obj(2, "rbd_header.2.11");
    let mut t = OTxn::new();
    let e = m.get_mut(&(c, hot.clone())).unwrap();
    let rm: Vec<Vec<u8>> = e.1.keys().step_by(3).cloned().collect();
    for k in &rm {
        e.1.remove(k);
    }
    t.push(TOp::OmapRmKeys {
        cid: c,
        oid: hot.clone(),
        keys: rm.into_iter().map(Bytes::Owned).collect(),
    });
    put(
        &mut m,
        &mut t,
        c,
        &hot,
        vec![(b"name_new".to_vec(), b"v".to_vec())],
    );
    st.commit(&t).unwrap();
    // (another collection: its own txn, the shards may differ)
    let mut t = OTxn::new();
    let e = m.get_mut(&(coll(2), o.clone())).unwrap();
    let first = e.1.keys().nth(5).unwrap().clone();
    let last = e.1.keys().nth(40).unwrap().clone();
    e.1.retain(|k, _| *k < first || *k >= last);
    t.push(TOp::OmapRmKeyRange {
        cid: coll(2),
        oid: o,
        first: Bytes::Owned(first),
        last: Bytes::Owned(last),
    });
    st.commit(&t).unwrap();
    st.checkpoint().unwrap();
    drop(st);
    verify(&disk, &m, "after writes");
    // a later mount finds nothing to remove: it commits no txn
    let lsns = |st: Store<SimDev, SimClock>| -> Vec<u64> {
        st.shards.iter().map(|s| s.sh.durable_lsn()).collect()
    };
    let a = lsns(mount(&disk).unwrap());
    assert_eq!(
        lsns(mount(&disk).unwrap()),
        a,
        "a later mount commits nothing"
    );
}

/// Cut the upgrade at device event `k` with `policy`, mount again, verify.
fn crash_case(img: &SimImage, m: &Model, k: u64, policy: CrashPolicy) -> bool {
    let disk = SimDisk::from_image(img, sim());
    disk.arm_crash(k);
    let r = upgrade(&disk);
    if !disk.crashed() {
        assert!(r.is_ok(), "k={k}: {:?}", r.err());
        return false;
    }
    let after = disk.crash_image(policy);
    if features(&after) & BITS == 0 {
        // nothing but (a torn) superblock copy may differ before the bits are durable: an earlier build still mounts
        // the store as it wrote it
        for lba in 2..after.lba_count {
            assert!(
                after.read_lba(lba) == img.read_lba(lba),
                "k={k} {policy:?}: lba {lba} written before the bit was durable"
            );
        }
    }
    verify(
        &SimDisk::from_image(&after, sim()),
        m,
        &format!("k={k} {policy:?}"),
    );
    true
}

fn matrix(policy: CrashPolicy) {
    let (img, m) = fixture();
    let disk = SimDisk::from_image(&img, sim());
    upgrade(&disk).unwrap();
    let total = disk.events();
    let cases = (0..total)
        .filter(|&k| crash_case(&img, &m, k, policy))
        .count();
    eprintln!("omap upgrade crash matrix {policy:?}: {total} events, {cases} crash cases verified");
    assert!(cases > 0);
}

#[test]
fn crash_matrix_drop_all() {
    matrix(CrashPolicy::DROP_ALL);
}

#[test]
fn crash_matrix_persist_all() {
    matrix(CrashPolicy::PERSIST_ALL);
}

#[test]
fn crash_matrix_mixed() {
    matrix(CrashPolicy::MIXED);
}
