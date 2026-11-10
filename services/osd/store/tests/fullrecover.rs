// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Full device -> mass delete -> space must come back without a restart (ADR 0021 amendment 21), and deletes
//! must keep making progress while the device is full.
#![allow(clippy::too_many_arguments, clippy::collapsible_if)]
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use objmodel::*;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, ObjError, Store, StoreCfg, TOp};

type St = Store<SimDev, SimClock>;

fn g(oid: &[u8], hash: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(oid, SnapId::NOSNAP, hash, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn mk(cap_mib: u64, shards: u32) -> St {
    mk_disk(cap_mib, shards).0
}

fn mount(disk: &SimDisk) -> St {
    let d2 = disk.clone();
    let cfg = StoreCfg::default();
    Store::mount(move || d2.queue(), SimClock::default(), cfg)
        .unwrap()
        .0
}

fn mk_disk(cap_mib: u64, shards: u32) -> (St, SimDisk, SimConfig) {
    let sim = SimConfig::new(cap_mib << 20);
    let disk = SimDisk::new(sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = MkfsParams {
        shards,
        wal_blocks: 2048,
        align_blocks: 1,
        meta_pct: 3,
        node_size: 8192,
        elastic_meta: true,
        ..Default::default()
    };
    mkfs(&mut dev, &mut clk, &p).unwrap();
    let img = disk.image();
    let disk = SimDisk::from_image(&img, sim.clone());
    (mount(&disk), disk, sim)
}

fn obj<'a>(c: CollT, n: u32, keys: &'a [String], data: &'a [u8], val: &'a [u8], t: &mut OTxn<'a>) {
    let name = format!("object-{n:08}");
    let o = g(name.as_bytes(), n);
    t.write(c, &o, 0, data);
    t.setattr(c, &o, b"_", val);
    for k in keys {
        t.omap_set(c, &o, k.as_bytes(), val);
    }
}

/// Fill with `sys` (applied) or user txns until NoSpace, delete everything in `slice`-object txns (as sys, like the
/// PG delete path), then a fresh collection must accept user writes again, no restart.
fn scenario(shards: u32, keys: u32, data_len: usize, slice: u32, range_del: bool, sys_fill: bool) {
    let mut st = mk(64, shards);
    let (c, c2) = (pgc(1, 0), pgc(2, 0));
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    let mut t = OTxn::new();
    t.mkcoll(c2);
    st.commit(&t).unwrap();
    let data = vec![0x5au8; data_len];
    let val = vec![7u8; 200];
    let ks: Vec<String> = (0..keys).map(|k| format!("k{k:05}")).collect();
    let mut n = 0u32;
    loop {
        let mut t = OTxn::new();
        t.sys = sys_fill;
        obj(c, n, &ks, &data, &val, &mut t);
        match st.commit(&t) {
            Ok(()) => n += 1,
            Err(e) => {
                assert_eq!(e, ObjError::NoSpace);
                break;
            }
        }
        assert!(n < 100_000);
    }
    assert!(n > 20);
    // delete everything
    let mut i = 0;
    while i < n {
        let mut t = OTxn::new();
        t.sys = true;
        for j in i..(i + slice).min(n) {
            let name = format!("object-{j:08}");
            let o = g(name.as_bytes(), j);
            if range_del {
                t.push(TOp::OmapRmKeyRange {
                    cid: c,
                    oid: o.clone(),
                    first: TxnBytes::Borrowed(b"k"),
                    last: TxnBytes::Borrowed(b"l"),
                });
            }
            t.remove(c, &o);
        }
        st.commit(&t)
            .unwrap_or_else(|e| panic!("delete slice at {i}/{n} failed: {e:?} {:?}", st.statfs()));
        i += slice;
    }
    let mut t = OTxn::new();
    t.sys = true;
    t.push(TOp::RmColl { cid: c });
    st.commit(&t).unwrap();
    st.checkpoint().unwrap();
    st.idle();
    let s = st.statfs();
    assert!(s.fullest_shard_pct < 20.0, "space not back: {s:?}");
    assert!(st.write_room(&c2, 4 << 20, 0), "write_room closed: {s:?}");
    // the new pool can use (nearly) the whole device again, no restart: empty meta cells must not hold the data space
    let big = vec![0xc3u8; 256 << 10];
    let mut bytes = 0u64;
    let mut k = 0u32;
    while st.write_room(&c2, big.len() as u64, 0) {
        let mut t = OTxn::new();
        t.write(c2, &g(format!("big-{k}").as_bytes(), k), 0, &big);
        st.commit(&t)
            .unwrap_or_else(|e| panic!("write {k} after delete: {e:?} {:?}", st.statfs()));
        bytes += big.len() as u64;
        k += 1;
    }
    let total = st.statfs().total_bytes;
    assert!(
        bytes * 100 * shards as u64 >= total * 70,
        "only {bytes} of {total} usable after the delete"
    );
}

#[test]
fn recover_small_objects_omap() {
    scenario(1, 8, 4096, 16, false, false);
}
#[test]
fn recover_small_objects_omap_sysfill() {
    scenario(1, 8, 4096, 16, false, true);
}
#[test]
fn recover_range_deletes() {
    scenario(1, 64, 4096, 4, true, true);
}
#[test]
fn recover_big_objects() {
    scenario(2, 0, 400_000, 4, false, false);
}
#[test]
fn recover_two_shards_one_per_txn() {
    scenario(2, 8, 4096, 1, false, true);
}
#[test]
fn recover_user_fill_range() {
    scenario(1, 64, 4096, 4, true, false);
}

/// Remount right after the delete (cells emptied by the last checkpoint, not yet given back): the store must give
/// them back by itself (no write must answer NoSpace while the device is mostly empty).
#[test]
fn recover_after_remount_with_empty_cells() {
    let (mut st, disk, sim) = mk_disk(64, 1);
    let (c, c2) = (pgc(1, 0), pgc(2, 0));
    for cid in [c, c2] {
        let mut t = OTxn::new();
        t.mkcoll(cid);
        st.commit(&t).unwrap();
    }
    let data = vec![0x5au8; 4096];
    let val = vec![7u8; 200];
    let ks: Vec<String> = (0..8).map(|k| format!("k{k:05}")).collect();
    let mut n = 0u32;
    loop {
        let mut t = OTxn::new();
        obj(c, n, &ks, &data, &val, &mut t);
        match st.commit(&t) {
            Ok(()) => n += 1,
            Err(e) => {
                assert_eq!(e, ObjError::NoSpace);
                break;
            }
        }
    }
    for i in (0..n).step_by(16) {
        let mut t = OTxn::new();
        t.sys = true;
        for j in i..(i + 16).min(n) {
            t.remove(c, &g(format!("object-{j:08}").as_bytes(), j));
        }
        st.commit(&t).unwrap();
    }
    // one checkpoint: the pages are free afterwards, their cells empty but still present
    st.checkpoint().unwrap();
    drop(st);
    let disk = SimDisk::from_image(&disk.image(), sim);
    let mut st = mount(&disk);
    // statfs and write_room agree right away: the empty cells are free capacity (given back at the first alloc / poll)
    assert!(st.statfs().fullest_shard_pct < 20.0, "{:?}", st.statfs());
    assert!(
        st.write_room(&c2, 4 << 20, 0),
        "write_room closed after remount: {:?}",
        st.shards[0].sh.statfs()
    );
    let big = vec![0xc3u8; 256 << 10];
    let mut bytes = 0u64;
    for k in 0u32.. {
        let mut t = OTxn::new();
        t.write(c2, &g(format!("big-{k}").as_bytes(), k), 0, &big);
        if let Err(e) = st.commit(&t) {
            assert_eq!(e, ObjError::NoSpace);
            break;
        }
        bytes += big.len() as u64;
    }
    let total = st.statfs().total_bytes;
    assert!(
        bytes * 100 >= total * 70,
        "only {bytes} of {total} usable after remount: {:?}",
        st.statfs()
    );
}

/// The pure-shrink class (all reserves) is strict: a txn that removes something but also adds state (omap keys,
/// xattrs, partial-block zeroing of a shared block) is NOT a pure shrink; it must stop at the sys floor and leave the
/// last headroom to deletes, which must still work afterwards.
#[test]
fn shrink_class_cannot_be_abused_to_fill_the_last_space() {
    let mut st = mk(64, 1);
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    let val = vec![7u8; 200];
    let ks: Vec<String> = (0..64).map(|k| format!("k{k:05}")).collect();
    let data = vec![0x5au8; 4096];
    // fill as sys (stops at the sys floor)
    let mut n = 0u32;
    loop {
        let mut t = OTxn::new();
        t.sys = true;
        obj(c, n, &ks, &data, &val, &mut t);
        match st.commit(&t) {
            Ok(()) => n += 1,
            Err(e) => {
                assert_eq!(e, ObjError::NoSpace);
                break;
            }
        }
    }
    assert!(n > 20);
    let before = st.statfs();
    // abuse: remove one small object, add 4x its omap volume to another (each attempt nets growth)
    let big_ks: Vec<String> = (0..256).map(|k| format!("x{k:05}")).collect();
    let mut grown = 0u32;
    for a in 0..n.min(200) {
        let mut t = OTxn::new();
        t.sys = true;
        t.remove(c, &g(format!("object-{a:08}").as_bytes(), a));
        let o = g(format!("abuse-{a}").as_bytes(), 1_000_000 + a);
        for k in &big_ks {
            t.omap_set(c, &o, k.as_bytes(), &val);
        }
        t.setattr(c, &o, b"_", &val);
        match st.commit(&t) {
            Ok(()) => grown += 1,
            Err(e) => {
                assert_eq!(e, ObjError::NoSpace);
                break;
            }
        }
    }
    let after = st.statfs();
    // the growing txns may use what their own removes free (after a checkpoint), never the delete-only headroom
    assert!(
        after.fullest_shard_pct <= before.fullest_shard_pct + 1.0,
        "abuse consumed the delete headroom ({grown} txns): before {before:?} after {after:?}"
    );
    // deletes (pure shrink) still make progress at full
    for i in (0..n).step_by(4) {
        let mut t = OTxn::new();
        t.sys = true;
        for j in i..(i + 4).min(n) {
            let o = g(format!("object-{j:08}").as_bytes(), j);
            if st.stat(&c, &o).ok().flatten().is_some() {
                t.remove(c, &o);
            }
        }
        if !t.is_empty() {
            st.commit(&t)
                .unwrap_or_else(|e| panic!("delete at {i}/{n} failed: {e:?} {:?}", st.statfs()));
        }
    }
}

// ---------------------------------------------------------------------------------------------- crash matrix

/// Base image: a full device (user fill of small objects with omap until NoSpace); returns the image and `n`.
fn full_image(cap_mib: u64) -> (store::dev::SimImage, SimConfig, u32) {
    let (mut st, disk, sim) = mk_disk(cap_mib, 1);
    let (c, c2) = (pgc(1, 0), pgc(2, 0));
    for cid in [c, c2] {
        let mut t = OTxn::new();
        t.mkcoll(cid);
        st.commit(&t).unwrap();
    }
    let data = vec![0x5au8; 4096];
    let val = vec![7u8; 200];
    let ks: Vec<String> = (0..8).map(|k| format!("k{k:05}")).collect();
    let mut n = 0u32;
    loop {
        let mut t = OTxn::new();
        obj(c, n, &ks, &data, &val, &mut t);
        match st.commit(&t) {
            Ok(()) => n += 1,
            Err(e) => {
                assert_eq!(e, ObjError::NoSpace);
                break;
            }
        }
    }
    st.checkpoint().unwrap();
    drop(st);
    (disk.image(), sim, n)
}

#[derive(Default)]
struct Acks {
    deleted: Vec<u32>,
    written: Vec<u32>,
}

/// Delete everything in slices (sys, like PG deletion), drop the collection, let idle checkpoints give the empty
/// cells back, then fill a new collection; stops at the first error (crash or the final NoSpace).
fn phase2(st: &mut St, n: u32, acks: &mut Acks) -> Result<(), ObjError> {
    let (c, c2) = (pgc(1, 0), pgc(2, 0));
    for i in (0..n).step_by(16) {
        let mut t = OTxn::new();
        t.sys = true;
        for j in i..(i + 16).min(n) {
            t.remove(c, &g(format!("object-{j:08}").as_bytes(), j));
        }
        st.commit(&t)?;
        acks.deleted.extend(i..(i + 16).min(n));
    }
    let mut t = OTxn::new();
    t.sys = true;
    t.push(TOp::RmColl { cid: c });
    st.commit(&t)?;
    st.checkpoint()?;
    for _ in 0..4 {
        st.request_checkpoint();
        st.checkpoint()?;
    }
    for k in 0u32.. {
        let big = vec![k as u8 ^ 0x3c; 128 << 10];
        let mut t = OTxn::new();
        t.write(c2, &g(format!("big-{k}").as_bytes(), k), 0, &big);
        st.commit(&t)?;
        acks.written.push(k);
    }
    Ok(())
}

fn crash_point(
    img: &store::dev::SimImage,
    sim: &SimConfig,
    n: u32,
    k: Option<u64>,
    pol: store::dev::CrashPolicy,
) -> Result<u64, String> {
    let disk = SimDisk::from_image(img, sim.clone());
    let mut st = mount(&disk);
    let e0 = disk.events();
    if let Some(k) = k {
        disk.arm_crash(e0 + k);
    }
    let mut acks = Acks::default();
    let r = phase2(&mut st, n, &mut acks);
    let events = disk.events() - e0;
    if k.is_none() {
        if r != Err(ObjError::NoSpace) || (acks.deleted.len() as u32) < n || acks.written.len() < 20
        {
            return Err(format!(
                "dry run ended with {r:?}: {} of {n} deleted, {} written",
                acks.deleted.len(),
                acks.written.len()
            ));
        }
        return Ok(events);
    }
    disk.crash_now();
    let cimg = disk.crash_image(pol);
    drop(st);
    {
        let d = SimDisk::from_image(&cimg, sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        store::fsck::fsck(&mut dev, &mut clk, Some(&store::obj::onode::fsck_refs))
            .map_err(|e| format!("fsck: {e}"))?;
    }
    let disk = SimDisk::from_image(&cimg, sim.clone());
    let mut st = mount(&disk);
    let rep = st.check(true).map_err(|e| format!("check: {e:?}"))?;
    if !rep.errors.is_empty() {
        return Err(format!("check errors: {:?}", rep.errors));
    }
    let (c, c2) = (pgc(1, 0), pgc(2, 0));
    for &j in &acks.deleted {
        let o = g(format!("object-{j:08}").as_bytes(), j);
        if st.coll_exists(&c).map_err(|e| format!("{e:?}"))?
            && st.stat(&c, &o).map_err(|e| format!("{e:?}"))?.is_some()
        {
            return Err(format!("acked delete of {j} lost"));
        }
    }
    for &w in &acks.written {
        let d = st
            .read(&c2, &g(format!("big-{w}").as_bytes(), w), 0, 128 << 10)
            .map_err(|e| format!("read big-{w}: {e:?}"))?;
        if d.len() != 128 << 10 || d.iter().any(|&b| b != w as u8 ^ 0x3c) {
            return Err(format!("acked write big-{w} lost or wrong"));
        }
    }
    // finish the job after the crash: no space may be lost (cells, held blocks)
    let mut acks2 = Acks::default();
    if st.coll_exists(&c).map_err(|e| format!("{e:?}"))? {
        let left: Vec<u32> = (0..n).filter(|j| !acks.deleted.contains(j)).collect();
        for j in left {
            let o = g(format!("object-{j:08}").as_bytes(), j);
            if st.stat(&c, &o).map_err(|e| format!("{e:?}"))?.is_some() {
                let mut t = OTxn::new();
                t.sys = true;
                t.remove(c, &o);
                st.commit(&t)
                    .map_err(|e| format!("delete {j} after crash: {e:?}"))?;
            }
        }
        let mut t = OTxn::new();
        t.sys = true;
        t.push(TOp::RmColl { cid: c });
        st.commit(&t)
            .map_err(|e| format!("rmcoll after crash: {e:?}"))?;
    }
    let base = acks.written.last().map_or(0, |w| w + 1);
    let mut bytes = base as u64 * (128 << 10);
    for k in base.. {
        let big = vec![0x11u8; 128 << 10];
        let mut t = OTxn::new();
        t.write(c2, &g(format!("big-{k}").as_bytes(), k), 0, &big);
        match st.commit(&t) {
            Ok(()) => {
                bytes += big.len() as u64;
                acks2.written.push(k);
            }
            Err(ObjError::NoSpace) => break,
            Err(e) => return Err(format!("refill {k}: {e:?}")),
        }
    }
    let total = st.statfs().total_bytes;
    if bytes * 100 < total * 70 {
        return Err(format!(
            "space lost after crash: {bytes} of {total} {:?}",
            st.statfs()
        ));
    }
    Ok(events)
}

fn crash_matrix(cap_mib: u64, points: u64, pols: &[store::dev::CrashPolicy]) -> u64 {
    let (img, sim, n) = full_image(cap_mib);
    let events = crash_point(&img, &sim, n, None, store::dev::CrashPolicy::DROP_ALL).unwrap();
    let stride = (events / points).max(1);
    let mut scen = 0;
    let mut k = 1;
    while k < events {
        for (pi, &p) in pols.iter().enumerate() {
            crash_point(&img, &sim, n, Some(k), p)
                .unwrap_or_else(|e| panic!("crash at {k}/{events} policy#{pi}: {e}"));
            scen += 1;
        }
        k += stride;
    }
    eprintln!("fullrecover crash matrix: {events} events, {scen} scenarios");
    scen
}

#[test]
fn crash_during_delete_and_give_back() {
    use store::dev::CrashPolicy as P;
    crash_matrix(24, 12, &[P::MIXED, P::DROP_ALL]);
}

#[test]
#[ignore = "soak"]
fn crash_during_delete_and_give_back_soak() {
    use store::dev::CrashPolicy as P;
    crash_matrix(24, 400, &[P::MIXED, P::DROP_ALL, P::PERSIST_ALL]);
}
