// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! ENOSPC at low fill (ADR 0021 amendment 4): churn workloads on small devices must never report NoSpace while
//! the live data is far below capacity; metadata/system txns survive when user writes are rejected.
#![allow(clippy::too_many_arguments, clippy::collapsible_if)]
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use objmodel::*;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, ObjError, Store, StoreCfg};
use store::rng::Rng;

type St = Store<SimDev, SimClock>;

fn g(oid: &[u8], hash: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(oid, SnapId::NOSNAP, hash, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn mk(cap_mib: u64, shards: u32, wal: u64, meta_pct: u32, cfg: StoreCfg) -> St {
    mk_ex(cap_mib, shards, wal, meta_pct, cfg, true)
}

fn mk_ex(cap_mib: u64, shards: u32, wal: u64, meta_pct: u32, cfg: StoreCfg, elastic: bool) -> St {
    mk_disk(cap_mib, shards, wal, meta_pct, cfg, elastic).1
}

fn mk_disk(
    cap_mib: u64,
    shards: u32,
    wal: u64,
    meta_pct: u32,
    cfg: StoreCfg,
    elastic: bool,
) -> (SimDisk, St) {
    let sim = SimConfig::new(cap_mib << 20);
    let disk = SimDisk::new(sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = MkfsParams {
        shards,
        wal_blocks: wal,
        align_blocks: 1,
        meta_pct,
        node_size: 8192,
        elastic_meta: elastic,
        ..Default::default()
    };
    mkfs(&mut dev, &mut clk, &p).unwrap();
    let img = disk.image();
    let disk = SimDisk::from_image(&img, sim);
    let d2 = disk.clone();
    // these tests size values to exhaust space: no value compression
    let mut cfg = cfg;
    cfg.shard.val_comp_min = 0;
    let st = Store::mount(move || d2.queue(), SimClock::default(), cfg)
        .unwrap()
        .0;
    (disk, st)
}

fn mkmeta(st: &mut St) {
    let mut t = OTxn::new();
    t.mkcoll(CollT::Meta);
    st.commit(&t).unwrap();
}

/// osdmap-like system write: replace one object of the meta collection.
fn put_map(st: &mut St, name: &str, data: &[u8]) -> Result<(), ObjError> {
    let o = g(name.as_bytes(), 0);
    let mut t = OTxn::new();
    t.truncate(CollT::Meta, &o, 0);
    t.write(CollT::Meta, &o, 0, data);
    st.commit(&t)
}

/// Random overwrite churn on a fixed working set well below capacity (data held until checkpoints must never
/// surface as NoSpace nor as "full" in statfs).
#[test]
fn overwrite_churn_low_fill_never_nospace() {
    let mut st = mk(64, 1, 2048, 8, StoreCfg::default());
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    let mut rng = Rng::new(7);
    let mut buf = vec![0u8; 48 * 1024];
    rng.fill(&mut buf);
    for i in 0..100u32 {
        let mut t = OTxn::new();
        t.write(c, &g(format!("o{i}").as_bytes(), i), 0, &buf);
        st.commit(&t).unwrap();
    }
    for n in 0..20000u32 {
        let i = rng.below(100) as u32;
        let len = 4096 * (1 + rng.below(12)) as usize;
        let off = 4096 * rng.below((48 * 1024 - len) as u64 / 4096 + 1);
        let nb = n.to_le_bytes();
        let o = g(format!("o{i}").as_bytes(), i);
        let mut t = OTxn::new();
        t.write(c, &o, off, &buf[..len]);
        t.setattr(c, &o, b"v", &nb);
        st.commit(&t).unwrap();
        if n % 1000 == 0 {
            let s = st.statfs();
            assert!(s.fullest_shard_pct < 30.0, "{s:?}");
        }
    }
}

/// Whole-object replace churn at 11% fill: freed blocks wait for checkpoints (82% of the device may be held),
/// that must neither fail an allocation nor make statfs report the OSD full.
#[test]
fn replace_churn_held_blocks_are_not_full() {
    let mut st = mk(128, 1, 2048, 3, StoreCfg::default());
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    let mut rng = Rng::new(11);
    let mut buf = vec![0u8; 1 << 20];
    rng.fill(&mut buf);
    let total = st.statfs().total_bytes;
    let (mut live, mut used, mut next) = (Vec::new(), 0u64, 0u32);
    while used * 100 < total * 11 {
        let len = 4096 * (1 + rng.below(255)) as usize;
        let mut t = OTxn::new();
        t.write(c, &g(format!("o{next}").as_bytes(), next), 0, &buf[..len]);
        st.commit(&t).unwrap();
        live.push(next);
        used += len as u64;
        next += 1;
    }
    let mut max_held = 0;
    for _ in 0..1500 {
        let vid = live.swap_remove(rng.below(live.len() as u64) as usize);
        let len = 4096 * (1 + rng.below(255)) as usize;
        let mut t = OTxn::new();
        t.remove(c, &g(format!("o{vid}").as_bytes(), vid));
        t.write(c, &g(format!("o{next}").as_bytes(), next), 0, &buf[..len]);
        st.commit(&t).unwrap();
        live.push(next);
        next += 1;
        let s = st.statfs();
        max_held = max_held.max(s.held_bytes);
        assert!(s.fullest_shard_pct < 30.0, "{s:?}");
    }
    eprintln!("max held bytes {max_held} of {total}");
}

/// Merge-like bounce between two collections: metadata stays bounded (no leak), nothing fails.
#[test]
fn bounce_between_collections_is_bounded() {
    let mut st = mk(64, 1, 2048, 8, StoreCfg::default());
    let (a, b) = (pgc(1, 0), pgc(1, 32));
    let mut t = OTxn::new();
    t.mkcoll(a);
    t.mkcoll(b);
    st.commit(&t).unwrap();
    let data = vec![3u8; 8192];
    let n = 300u32;
    for i in 0..n {
        let mut t = OTxn::new();
        t.write(a, &g(format!("o{i}").as_bytes(), i), 0, &data);
        st.commit(&t).unwrap();
    }
    let mut peak = 0;
    for round in 0..30 {
        let (from, to) = if round % 2 == 0 { (a, b) } else { (b, a) };
        for i in 0..n {
            let o = g(format!("o{i}").as_bytes(), i);
            let mut t = OTxn::new();
            t.write(to, &o, 0, &data);
            t.setattr(to, &o, b"_", &data[..200]);
            st.commit(&t).unwrap();
            let mut t = OTxn::new();
            t.remove(from, &o);
            st.commit(&t).unwrap();
        }
        peak = peak.max(st.statfs().meta_used_pages);
    }
    assert!(peak < 120, "meta pages grew: {peak}");
}

/// Metadata-bound shard: small objects fill the (3%) meta region at ~5% data fill. statfs must say "full"
/// (so the mon sets the full flags and clients stop) before the hard NoSpace, and system txns still work.
#[test]
fn meta_bound_shard_reports_full_and_sys_txn_survives() {
    meta_bound(false);
}

/// Elastic meta space (am. 12): the same small-object fill is no longer metadata-bound at 5% data fill; meta
/// cells come out of the data region, so it stores several times more objects, "full" is judged on the shared
/// space, and the system/remove paths still work at the end.
#[test]
fn meta_bound_elastic_shares_the_space() {
    let n_legacy = meta_bound(false);
    let n_elastic = meta_bound(true);
    eprintln!(
        "objects stored before ENOSPC on 64 MiB (3% meta): legacy {n_legacy}, elastic {n_elastic}"
    );
    assert!(
        n_elastic > 3 * n_legacy,
        "elastic stored {n_elastic} objects, legacy {n_legacy}"
    );
}

fn meta_bound(elastic: bool) -> u32 {
    let mut st = mk_ex(64, 1, 2048, 3, StoreCfg::default(), elastic);
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    mkmeta(&mut st);
    let data = vec![0x5au8; 4096];
    let val = vec![7u8; 200];
    let keys: Vec<String> = (0..8u32).map(|k| format!("k{k:04}")).collect();
    let mut first_full = None;
    let mut n = 0u32;
    let err = loop {
        let name = format!("object-{n:08}");
        let o = g(name.as_bytes(), n);
        let mut t = OTxn::new();
        t.write(c, &o, 0, &data);
        t.setattr(c, &o, b"_", &val);
        t.setattr(c, &o, b"snapset", &val);
        for k in &keys {
            t.omap_set(c, &o, k.as_bytes(), &val);
        }
        match st.commit(&t) {
            Ok(()) => {
                n += 1;
                if first_full.is_none() && st.statfs().fullest_shard_pct >= 95.0 {
                    first_full = Some(n);
                }
            }
            Err(e) => break e,
        }
        assert!(n < 10_000);
    };
    assert_eq!(err, ObjError::NoSpace);
    let f = st.shards[0].sh.statfs();
    if !elastic {
        assert!(
            f.data_used * 100 < f.data_blocks * 10,
            "data is not the bottleneck: {f:?}"
        );
    } else {
        // the shared space is what ran out: cells hold most of the used blocks
        assert!(
            f.meta_cells > 0 && f.meta_cell_blocks > f.data_blocks / 4,
            "{f:?}"
        );
    }
    let s = st.statfs();
    assert!(s.fullest_shard_pct >= 95.0, "{s:?}");
    assert!(
        s.avail_bytes * 100 <= s.total_bytes * 5,
        "df must show the meta-bound shard as full: {s:?}"
    );
    assert!(first_full.is_some_and(|x| x <= n), "full before ENOSPC");
    // osdmap persistence and trimming (system txns) still succeed from the reserve
    let map = vec![9u8; 40_000];
    for e in 0..10 {
        put_map(&mut st, &format!("osdmap.{}", e % 3), &map).unwrap();
    }
    // removes free metadata, user writes work again
    for i in 0..n / 2 {
        let mut t = OTxn::new();
        let name = format!("object-{i:08}");
        t.remove(c, &g(name.as_bytes(), i));
        st.commit(&t).unwrap();
    }
    let mut t = OTxn::new();
    t.write(c, &g(b"after", 1), 0, &data);
    st.commit(&t).unwrap();
    n
}

/// Data-bound: at the reserve user writes get NoSpace; osdmap writes (meta collection) and removes still work.
#[test]
fn data_full_sys_txn_and_removes_survive() {
    let mut st = mk(48, 1, 256, 8, StoreCfg::default());
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    mkmeta(&mut st);
    let blob = vec![0xA5u8; 200_000];
    let mut n = 0u32;
    loop {
        let mut t = OTxn::new();
        t.write(c, &g(format!("o{n}").as_bytes(), n), 0, &blob);
        match st.commit(&t) {
            Ok(()) => n += 1,
            Err(e) => {
                assert_eq!(e, ObjError::NoSpace);
                break;
            }
        }
        assert!(n < 1000);
    }
    let s = st.statfs();
    assert!(s.fullest_shard_pct >= 95.0, "{s:?}");
    let map = vec![9u8; 300_000];
    for e in 0..5 {
        put_map(&mut st, &format!("osdmap.{}", e % 2), &map).unwrap();
    }
    // a user write is still refused
    let mut t = OTxn::new();
    t.write(c, &g(b"nope", 1), 0, &blob);
    assert_eq!(st.commit(&t), Err(ObjError::NoSpace));
    for i in 0..n / 2 {
        let mut t = OTxn::new();
        t.remove(c, &g(format!("o{i}").as_bytes(), i));
        st.commit(&t).unwrap();
    }
    let mut t = OTxn::new();
    t.write(c, &g(b"after", 1), 0, &blob);
    st.commit(&t).unwrap();
}

/// ADR 0021 amendment 6: client writes are admitted with `write_room`, applied as `sys` txns. After the last
/// admission a burst of already-admitted (replica-style) txns of the same size still fits in the reserves, removes
/// free space, and `write_room` reopens.
#[test]
fn admission_then_sys_apply_never_nospace() {
    let mut st = mk(48, 1, 256, 8, StoreCfg::default());
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    mkmeta(&mut st);
    let blob = vec![0xA5u8; 200_000];
    let mut n = 0u32;
    while st.write_room(&c, blob.len() as u64, 0) {
        let mut t = OTxn::new();
        t.sys = true;
        t.write(c, &g(format!("o{n}").as_bytes(), n), 0, &blob);
        st.commit(&t).expect("admitted txn must not fail");
        n += 1;
        assert!(n < 1000);
    }
    assert!(n > 10);
    // replica-style applies of ops admitted elsewhere: the reserve absorbs a window of them
    for k in 0..4 {
        let mut t = OTxn::new();
        t.sys = true;
        t.write(c, &g(format!("r{k}").as_bytes(), 5000 + k), 0, &blob);
        st.commit(&t).expect("reserve must absorb in-flight txns");
    }
    // user-class (non-sys) writes are refused before sys ones are
    let mut t = OTxn::new();
    t.write(c, &g(b"user", 9), 0, &blob);
    assert_eq!(st.commit(&t), Err(ObjError::NoSpace));
    for i in 0..n / 2 {
        let mut t = OTxn::new();
        t.remove(c, &g(format!("o{i}").as_bytes(), i));
        st.commit(&t).unwrap();
    }
    st.checkpoint().unwrap();
    assert!(st.write_room(&c, blob.len() as u64, 0));
}

/// adr 0021 S4 (review S1): `apply_room` is the replica-side preflight for sys applies. Below the user floor it still
/// admits (the sys band is the replicas' room); every txn it admits applies; once it refuses, the same txn applied
/// anyway would hit NoSpace (fail-stop). Deletes make it admit again.
#[test]
fn apply_room_admits_down_to_the_sys_floor_and_never_lies() {
    let mut st = mk(48, 1, 256, 8, StoreCfg::default());
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    mkmeta(&mut st);
    let blob = vec![0x5Au8; 200_000];
    let sys_write = |n: u32| {
        let mut t = OTxn::new();
        t.sys = true;
        t.write(c, &g(format!("o{n}").as_bytes(), n), 0, &blob);
        t
    };
    let mut n = 0u32;
    let mut below_user = 0;
    while st.apply_room(&c, blob.len() as u64, 0) {
        below_user += u32::from(!st.write_room(&c, blob.len() as u64, 0));
        st.commit(&sys_write(n)).expect("apply_room admitted it");
        n += 1;
        assert!(n < 1000);
    }
    assert!(
        below_user > 0,
        "the sys band below the user floor is usable"
    );
    assert!(!st.write_room(&c, blob.len() as u64, 0));
    // what apply_room refused is really beyond the floor: applying a few anyway ends in NoSpace
    let refused = (0..8).any(|k| st.commit(&sys_write(n + k)) == Err(ObjError::NoSpace));
    assert!(refused, "apply_room refused room the store still had");
    for i in 0..n / 2 {
        let mut t = OTxn::new();
        t.remove(c, &g(format!("o{i}").as_bytes(), i));
        st.commit(&t).unwrap();
    }
    st.checkpoint().unwrap();
    assert!(st.apply_room(&c, blob.len() as u64, 0));
}

/// Migration headroom (adr 0031 am. 4): a hold is refused beyond the room, a granted hold is space nobody but the copy
/// gets (admission and sys txns stop above it), the copy fills it after giving it back, and the room comes back.
#[test]
fn mig_hold_is_space_only_the_copy_gets() {
    let mut st = mk(48, 1, 256, 8, StoreCfg::default());
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    mkmeta(&mut st);
    let room = st.mig_rooms()[0].1;
    assert!(room > 8 << 20, "{room}");
    assert!(!st.mig_hold(0, room + (1 << 20)), "beyond the room");
    assert!(!st.mig_hold(5, 4096), "a shard that is not mounted");
    let hold = room / 2;
    assert!(st.mig_hold(0, hold));
    assert!(st.mig_rooms()[0].1 <= room - hold);
    // admitted writes (sys class) fill up to the user floor above the hold, never into it
    let blob = vec![0xA5u8; 200_000];
    let mut n = 0u32;
    while st.write_room(&c, blob.len() as u64, 0) {
        let mut t = OTxn::new();
        t.sys = true;
        t.write(c, &g(format!("o{n}").as_bytes(), n), 0, &blob);
        st.commit(&t).expect("admitted txn must not fail");
        n += 1;
        assert!(n < 1000);
    }
    // in-flight sys applies stop at the hold
    let mut k = 0;
    loop {
        let mut t = OTxn::new();
        t.sys = true;
        t.write(c, &g(format!("r{k}").as_bytes(), 5000 + k), 0, &blob);
        match st.commit(&t) {
            Ok(()) => k += 1,
            Err(e) => {
                assert_eq!(e, ObjError::NoSpace);
                break;
            }
        }
        assert!(k < 1000);
    }
    // the copy gives back what each batch needs and always fits: the whole hold is usable
    let mut left = hold;
    let mut i = 0u32;
    while left >= blob.len() as u64 + (64 << 10) {
        st.mig_unhold(0, blob.len() as u64);
        left -= blob.len() as u64;
        let mut t = OTxn::new();
        t.sys = true;
        t.write(c, &g(format!("m{i}").as_bytes(), 9000 + i), 0, &blob);
        st.commit(&t).expect("the copy fits its hold");
        i += 1;
    }
    assert!(i as u64 * blob.len() as u64 >= hold / 2, "{i}");
    st.mig_unhold(0, left);
    for j in 0..n {
        let mut t = OTxn::new();
        t.remove(c, &g(format!("o{j}").as_bytes(), j));
        st.commit(&t).unwrap();
    }
    st.checkpoint().unwrap();
    assert!(st.mig_rooms()[0].1 > blob.len() as u64 * n as u64 / 2);
}

/// Elastic meta (am. 12) on a FRAGMENTED data region: cells need a contiguous run, so growth can fail with half the
/// data region free. Admission (`write_room`) and statfs must see that (meta is then bound like a legacy region):
/// an admitted sys txn must never hit NoSpace (fatal in the adapter, am. 6), and the shard must read full first.
#[test]
fn elastic_fragmented_data_region_admission_never_nospace() {
    let mut st = mk_ex(64, 1, 2048, 1, StoreCfg::default(), true);
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    mkmeta(&mut st);
    // fill the data region with 1-block objects, then free every other one: no 2-block run left anywhere
    let blk = vec![0x11u8; 4096];
    let mut n = 0u32;
    while st.write_room(&c, 4096, 0) {
        let mut t = OTxn::new();
        t.sys = true;
        t.write(c, &g(format!("f{n:07}").as_bytes(), n), 0, &blk);
        st.commit(&t).expect("admitted txn must not fail");
        n += 1;
    }
    for i in (0..n).step_by(2) {
        let mut t = OTxn::new();
        t.remove(c, &g(format!("f{i:07}").as_bytes(), i));
        st.commit(&t).unwrap();
    }
    st.checkpoint().unwrap();
    st.checkpoint().unwrap();
    let f = st.shards[0].sh.statfs();
    assert!(f.data_free * 3 > f.data_blocks, "{f:?}");
    // metadata-only growth (omap) admitted like client writes, applied as sys
    let val = vec![7u8; 200];
    let keys: Vec<String> = (0..8u32).map(|k| format!("k{k:04}")).collect();
    let mut m = 0u32;
    while st.write_room(&c, 2048, 0) {
        let o = g(format!("m{m:07}").as_bytes(), m);
        let mut t = OTxn::new();
        t.sys = true;
        for k in &keys {
            t.omap_set(c, &o, k.as_bytes(), &val);
        }
        st.commit(&t).unwrap_or_else(|e| {
            panic!(
                "admitted omap txn {m} failed: {e:?} {:?}",
                st.shards[0].sh.statfs()
            )
        });
        m += 1;
        assert!(m < 200_000);
    }
    assert!(m > 100, "omap objects stored: {m}");
    // a window of already-admitted replica applies still fits (the meta reserve)
    for k in 0..4u32 {
        let o = g(format!("r{k}").as_bytes(), k);
        let mut t = OTxn::new();
        t.sys = true;
        for kk in &keys {
            t.omap_set(c, &o, kk.as_bytes(), &val);
        }
        st.commit(&t).expect("reserve must absorb in-flight txns");
    }
    let s = st.statfs();
    assert!(
        s.fullest_shard_pct >= 95.0,
        "meta-bound shard must read full: {s:?}"
    );
    // osdmap persistence still works
    for e in 0..4 {
        put_map(&mut st, &format!("osdmap.{}", e % 2), &[9u8; 20_000]).unwrap();
    }
}

/// omapbench group A to full (open question 44, adr 0021 am. 45): random-key omap batches into ONE object on a small
/// shard. The store must refuse the txn that does not fit (NoSpace to the caller, nothing applied) and keep serving: a
/// failed shard (`poll` error) is fatal for the OSD and comes back at every restart. `sys` = OSD client-write class
/// behind `write_room`.
fn omap_fill_to_full(sys: bool, cache_pages: usize) {
    let mut cfg = StoreCfg::default();
    cfg.shard.cache_pages = cache_pages;
    cfg.shard.dirty_soft_pages = cache_pages / 8;
    cfg.shard.dirty_hard_pages = cache_pages * 3 / 8;
    let (disk, mut st) = mk_disk(48, 1, 1024, 3, cfg.clone(), true);
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    mkmeta(&mut st);
    let o = g(b"omapbench_A_0", 7);
    let mut t = OTxn::new();
    t.touch(c, &o);
    st.commit(&t).unwrap();
    let mut rng = Rng::new(44);
    let val = vec![0x5au8; 256];
    let (mut keys, mut refused) = (0u64, false);
    for round in 0..100_000u32 {
        if sys && !st.write_room(&c, 256 * 320, 256) {
            refused = true;
            break;
        }
        let mut t = OTxn::new();
        t.sys = sys;
        let ks: Vec<Vec<u8>> = (0..256)
            .map(|_| {
                let mut k = vec![0u8; 64];
                for ch in k.chunks_mut(8) {
                    ch.copy_from_slice(&rng.next_u64().to_le_bytes());
                }
                k
            })
            .collect();
        for k in &ks {
            t.omap_set(c, &o, k, &val);
        }
        match st.commit(&t) {
            Ok(()) => keys += 256,
            Err(ObjError::NoSpace) => {
                refused = true;
                break;
            }
            Err(e) => panic!("round {round}: {e:?}"),
        }
    }
    assert!(refused && keys > 10_000, "keys {keys}");
    let s = st.statfs();
    eprintln!("omap fill sys={sys}: {keys} keys, {s:?}");
    // crash + restart of the full shard (replay, mount checkpoint), then PG-state txns (sys): the lab crash loop
    let img = disk.image();
    drop(st);
    let d = SimDisk::from_image(&img, SimConfig::new(48 << 20));
    let d2 = d.clone();
    let mut st: St = Store::mount(move || d2.queue(), SimClock::default(), cfg)
        .expect("mount of the full shard")
        .0;
    let pgm = g(b"pgmeta", 0);
    for i in 0..50u32 {
        let mut t = OTxn::new();
        t.sys = true;
        let k = format!("pginfo.{}", i % 4);
        t.touch(c, &pgm).omap_set(c, &pgm, k.as_bytes(), &val);
        st.commit(&t).expect("PG state txn at full");
    }
    // the shard still serves: a checkpoint runs, system txns persist, the keys can be removed and space comes back
    st.checkpoint().expect("shard failed at full");
    put_map(&mut st, "osdmap.1", &[9u8; 100_000]).unwrap();
    let mut t = OTxn::new();
    t.push(store::obj::TOp::OmapClear {
        cid: c,
        oid: o.clone(),
    });
    st.commit(&t).unwrap();
    st.checkpoint().unwrap();
    st.checkpoint().unwrap();
    let mut t = OTxn::new();
    t.omap_set(c, &o, b"after", &val);
    st.commit(&t).unwrap();
    assert!(st.check(true).unwrap().errors.is_empty());
}

#[test]
fn omap_fill_to_full_refuses_and_keeps_serving() {
    omap_fill_to_full(false, 2048);
}

#[test]
fn omap_fill_to_full_admitted_sys_never_fails_the_shard() {
    omap_fill_to_full(true, 2048);
}

/// [`omap_fill_to_full`] the way the OSD drives it: admission by `write_room` with the opexec cost (payload + 4 KiB per
/// entry), admitted txns queued as `sys` (a refusal after admission = fatal PG failure), 1024-key batches, 16 in flight, a
/// pg log entry each; then a restart and PG-state txns on the full shard.
#[test]
fn omap_fill_to_full_queued_never_fails_the_shard() {
    use store::obj::Queued;
    let mut cfg = StoreCfg::default();
    cfg.shard.cache_pages = 2048;
    cfg.shard.dirty_soft_pages = 256;
    cfg.shard.dirty_hard_pages = 768;
    let (disk, mut st) = mk_disk(48, 1, 1024, 3, cfg.clone(), true);
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    mkmeta(&mut st);
    let o = g(b"omapbench_A_0", 7);
    let pgm = g(b"pgmeta", 0);
    let mut t = OTxn::new();
    t.touch(c, &o).touch(c, &pgm);
    st.commit(&t).unwrap();
    let mut rng = Rng::new(45);
    let val = vec![0x5au8; 256];
    let (mut tok, mut inflight, mut keys, mut refused) = (0u64, 0usize, 0u64, 0u32);
    let mut acked = Vec::new();
    let mut errs = Vec::new();
    for _ in 0..2_000_000u32 {
        while inflight < 16 && refused == 0 {
            if !st.write_room(&c, 1024 * 320, 1026) {
                refused += 1; // ENOSPC to the client before any log entry
                break;
            }
            let ks: Vec<Vec<u8>> = (0..1024)
                .map(|_| {
                    let mut k = vec![0u8; 64];
                    for ch in k.chunks_mut(8) {
                        ch.copy_from_slice(&rng.next_u64().to_le_bytes());
                    }
                    k
                })
                .collect();
            tok += 1;
            let lk = format!("pglog.{tok:016}");
            let ok = format!("pglog.{:016}", tok.saturating_sub(300));
            let mut t = OTxn::new();
            t.sys = true;
            for k in &ks {
                t.omap_set(c, &o, k, &val);
            }
            t.omap_set(c, &pgm, lk.as_bytes(), &val[..180]);
            t.push(store::obj::TOp::OmapRmKeys {
                cid: c,
                oid: pgm.clone(),
                keys: vec![ok.as_bytes().into()],
            });
            match st.queue(&t, tok) {
                Ok(Queued::Submitted(_) | Queued::Pending(_)) => inflight += 1,
                Err(ObjError::WouldBlock) => {
                    tok -= 1;
                    break;
                }
                Err(e) => panic!("admitted txn refused: {e:?} after {keys} keys"),
            }
        }
        acked.clear();
        let r = st.poll(&mut acked);
        st.take_queue_errors(&mut errs);
        if let Err(e) = r {
            assert!(
                errs.iter().any(|(_, x)| *x == e),
                "shard failed: {e:?} after {keys} keys: {}",
                st.diag()
            );
        }
        inflight -= acked.len() + errs.len();
        keys += 1024 * acked.len() as u64;
        assert!(
            errs.is_empty(),
            "admitted txn refused after {keys} keys: {errs:?}"
        );
        errs.clear();
        if refused > 0 && inflight == 0 {
            break;
        }
        st.idle();
    }
    assert!(refused > 0 && keys > 10_000, "keys {keys}");
    st.checkpoint().expect("shard failed at full");
    // restart from the crash image of the full shard (replay + mount checkpoint), then PG-state txns (sys) must apply
    let img = disk.image();
    drop(st);
    let d = SimDisk::from_image(&img, SimConfig::new(48 << 20));
    let d2 = d.clone();
    let mut st: St = Store::mount(move || d2.queue(), SimClock::default(), cfg)
        .expect("mount of the full shard")
        .0;
    for i in 0..50u32 {
        let mut t = OTxn::new();
        t.sys = true;
        let k = format!("pginfo.{}", i % 4);
        t.omap_set(c, &pgm, k.as_bytes(), &val);
        st.commit(&t).expect("PG state txn at full");
    }
    st.checkpoint().expect("checkpoint after restart");
    eprintln!("queued omap fill: {keys} keys, {:?}", st.statfs());
    let mut t = OTxn::new();
    t.push(store::obj::TOp::OmapClear {
        cid: c,
        oid: o.clone(),
    });
    st.commit(&t).unwrap();
    st.checkpoint().unwrap();
    assert!(st.check(true).unwrap().errors.is_empty());
}

/// adr 0021 am. 45: a data-full shard (meta cannot grow) with a large clean omap tree. Random-key batches admitted by
/// `write_room` must fit: each key may dirty a clean leaf of its own, far more pages than the payload / 4 KiB the old
/// estimate charged (that admitted the batch, the store refused it: fatal for the PG).
fn omap_batch_on_data_full_shard(entries_known: bool) -> Result<u32, ObjError> {
    let mut st = mk(48, 1, 1024, 3, StoreCfg::default());
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    mkmeta(&mut st);
    let o = g(b"omapbench_A_0", 7);
    let mut rng = Rng::new(46);
    let val = vec![0x5au8; 256];
    let key = |rng: &mut Rng| {
        let mut k = vec![0u8; 64];
        for ch in k.chunks_mut(8) {
            ch.copy_from_slice(&rng.next_u64().to_le_bytes());
        }
        k
    };
    for _ in 0..40 {
        let ks: Vec<Vec<u8>> = (0..512).map(|_| key(&mut rng)).collect();
        let mut t = OTxn::new();
        t.touch(c, &o);
        for k in &ks {
            t.omap_set(c, &o, k, &val);
        }
        st.commit(&t).unwrap();
    }
    st.checkpoint().unwrap();
    st.checkpoint().unwrap();
    // fill the data region (client writes, admitted as sys) up to a few MiB
    let blob = vec![0xA5u8; 256 << 10];
    let mut n = 0u32;
    while st.write_room(&c, 3 << 20, 0) {
        let mut t = OTxn::new();
        t.sys = true;
        t.write(c, &g(format!("d{n}").as_bytes(), n), 0, &blob);
        st.commit(&t).unwrap();
        n += 1;
    }
    // random-key batches, admitted like the OSD does
    let mut batches = 0;
    for _ in 0..200 {
        let ks: Vec<Vec<u8>> = (0..1024).map(|_| key(&mut rng)).collect();
        let entries = if entries_known { ks.len() as u64 } else { 0 };
        if !st.write_room(&c, 1024 * 320, entries) {
            break;
        }
        let mut t = OTxn::new();
        t.sys = true;
        for k in &ks {
            t.omap_set(c, &o, k, &val);
        }
        st.commit(&t)?;
        batches += 1;
    }
    Ok(batches)
}

#[test]
fn omap_batch_admission_counts_entries_on_a_data_full_shard() {
    let r = omap_batch_on_data_full_shard(true);
    assert!(r.is_ok(), "admitted batch refused: {r:?}");
    // without the entry count the payload estimate admits a batch the store must refuse (the lab's fatal NoSpace)
    assert_eq!(omap_batch_on_data_full_shard(false), Err(ObjError::NoSpace));
}
