// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Device expand (adr 0021 am. 20): the device grew, `layout::expand` gives every shard one more data extent. Data of
//! the old extents stays readable, the new space is allocatable and fsck-clean, statfs grows, a crash at any IO of the
//! expand leaves a mountable store, repeating the expand converges, the superblock copies end equal.
#![allow(clippy::collapsible_if)]
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use objmodel::*;
use store::BLK;
use store::dev::{CrashPolicy, SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::fsck::fsck;
use store::layout::{EXPAND_UNIT, FEAT_EXPAND, MkfsParams, expand, mkfs, read_super, sizes};
use store::obj::onode::fsck_refs;
use store::obj::{OTxn, Store, StoreCfg};

type St = Store<SimDev, SimClock>;

const SHARDS: u32 = 2;
const PGS: u32 = 16;

fn g(i: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(format!("o{i}").as_bytes(), SnapId::NOSNAP, i, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn pg_of(i: u32) -> CollT {
    pgc(1, i % PGS)
}

fn pattern(i: u32, len: usize) -> Vec<u8> {
    (0..len).map(|k| (k as u32 * 7 + i * 13) as u8).collect()
}

fn formatted(mib: u64) -> SimImage {
    let disk = SimDisk::new(SimConfig::new(mib << 20));
    let p = MkfsParams {
        shards: SHARDS,
        wal_blocks: 1024,
        align_blocks: 1,
        meta_pct: 4,
        ..Default::default()
    };
    mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    disk.image()
}

fn disk_of(img: &SimImage, mib: u64) -> SimDisk {
    SimDisk::from_image_resized(img, SimConfig::new(mib << 20))
}

fn mount(disk: &SimDisk) -> St {
    let d = disk.clone();
    Store::mount(move || d.queue(), SimClock::default(), StoreCfg::default())
        .unwrap()
        .0
}

fn write_objs(st: &mut St, range: std::ops::Range<u32>, len: usize) {
    for i in range {
        let mut t = OTxn::new();
        if i < PGS {
            t.mkcoll(pg_of(i));
        }
        let d = pattern(i, len);
        t.write(pg_of(i), &g(i), 0, &d);
        st.commit(&t)
            .unwrap_or_else(|e| panic!("object {i}: {e:?}"));
    }
}

fn verify(st: &mut St, range: std::ops::Range<u32>, len: usize) {
    for i in range {
        let got = st.read(&pg_of(i), &g(i), 0, len as u64).unwrap();
        assert!(got == pattern(i, len), "object {i} differs");
    }
}

fn check_all(disk: &SimDisk) {
    let (mut dev, mut clk) = (disk.queue(), SimClock::default());
    fsck(&mut dev, &mut clk, Some(&fsck_refs)).unwrap();
}

#[test]
fn expand_grows_capacity_and_keeps_data() {
    let img = formatted(64);
    let disk = disk_of(&img, 64);
    let mut st = mount(&disk);
    let total0 = st.statfs().total_bytes;
    write_objs(&mut st, 0..300, 64 << 10); // ~19 MiB in the original extents
    st.checkpoint().unwrap();
    drop(st);
    let img = disk.image();

    // nothing to do on an unchanged device
    let d = disk_of(&img, 64);
    let s = sizes(&mut d.queue(), &mut SimClock::default()).unwrap();
    assert_eq!((s.expansions, s.expandable_per_shard), (0, 0));
    assert_eq!(
        expand(&mut d.queue(), &mut SimClock::default()).unwrap(),
        None
    );

    // the device grows to 192 MiB
    let d = disk_of(&img, 192);
    let s = sizes(&mut d.queue(), &mut SimClock::default()).unwrap();
    assert_eq!(s.device_bytes, 192 << 20);
    assert!(
        s.store_bytes <= 64 << 20 && s.expandable_per_shard >= 60 << 20,
        "{s:?}"
    );
    let r = expand(&mut d.queue(), &mut SimClock::default())
        .unwrap()
        .expect("device grew");
    assert_eq!(r.generations, 1);
    assert_eq!(r.new_bytes, 192 << 20);
    assert_eq!(r.per_shard_bytes % (EXPAND_UNIT * BLK as u64), 0);
    let (sb, dirs) = read_super(&mut d.queue(), &mut SimClock::default()).unwrap();
    assert!(sb.features & FEAT_EXPAND != 0 && sb.size_bytes == 192 << 20);
    assert!(
        dirs.iter()
            .all(|x| x.ext.len() == 1 && x.ext[0].1 * BLK as u64 == r.per_shard_bytes)
    );
    // both copies equal, second run is a no-op
    assert_eq!(d.image().read_lba(0), d.image().read_lba(1));
    assert_eq!(
        expand(&mut d.queue(), &mut SimClock::default()).unwrap(),
        None
    );
    let s2 = sizes(&mut d.queue(), &mut SimClock::default()).unwrap();
    assert_eq!((s2.expansions, s2.expandable_per_shard), (1, 0));
    check_all(&d);

    // mount: capacity grew by the extents, old data intact, the new space takes data beyond the old capacity
    let mut st = mount(&d);
    let total1 = st.statfs().total_bytes;
    assert_eq!(
        total1 - total0,
        SHARDS as u64 * r.per_shard_bytes,
        "{total0} {total1}"
    );
    verify(&mut st, 0..300, 64 << 10);
    write_objs(&mut st, 300..1500, 64 << 10); // 94 MiB total: more than the old data capacity
    assert!(
        st.statfs().used_bytes > total0,
        "data must live in the new extents"
    );
    st.checkpoint().unwrap();
    let rep = st.check(true).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    verify(&mut st, 0..1500, 64 << 10);
    drop(st);
    let img = d.image();
    check_all(&disk_of(&img, 192));

    // free space report: extents of the new area are free, none inside a used block
    let d = disk_of(&img, 192);
    let mut st = mount(&d);
    let free = st.free_extents();
    let free_blocks: u64 = free.iter().map(|e| e.1).sum();
    let data = st.data_blocks();
    assert!(free_blocks < data && free_blocks > 0);
    verify(&mut st, 0..1500, 64 << 10);
    // remove everything again: the space comes back (also in the new extents)
    for i in 0..1500u32 {
        let mut t = OTxn::new();
        t.remove(pg_of(i), &g(i));
        st.commit(&t).unwrap();
    }
    st.checkpoint().unwrap();
    st.checkpoint().unwrap();
    let rep = st.check(true).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    let free2: u64 = st.free_extents().iter().map(|e| e.1).sum();
    assert!(free2 > free_blocks + 20_000, "{free_blocks} -> {free2}");
}

#[test]
fn second_expand_adds_a_second_generation() {
    let img = formatted(48);
    let d = disk_of(&img, 96);
    let r1 = expand(&mut d.queue(), &mut SimClock::default())
        .unwrap()
        .unwrap();
    let mut st = mount(&d);
    write_objs(&mut st, 0..200, 64 << 10);
    st.checkpoint().unwrap();
    drop(st);
    let img = d.image();
    let d = disk_of(&img, 160);
    let r2 = expand(&mut d.queue(), &mut SimClock::default())
        .unwrap()
        .unwrap();
    assert_eq!(r2.generations, 2);
    assert!(r2.per_shard_bytes >= 28 << 20 && r1.per_shard_bytes >= 16 << 20);
    let (_, dirs) = read_super(&mut d.queue(), &mut SimClock::default()).unwrap();
    assert!(dirs.iter().all(|x| x.ext.len() == 2));
    let mut st = mount(&d);
    verify(&mut st, 0..200, 64 << 10);
    write_objs(&mut st, 200..900, 64 << 10);
    st.checkpoint().unwrap();
    assert!(st.check(true).unwrap().errors.is_empty());
    drop(st);
    check_all(&disk_of(&d.image(), 160));
}

#[test]
fn shrunk_or_too_small_growth_is_refused_or_ignored() {
    let img = formatted(64);
    // a few MiB more: less than one unit per shard
    let d = disk_of(&img, 66);
    let s = sizes(&mut d.queue(), &mut SimClock::default()).unwrap();
    assert_eq!(s.expandable_per_shard, 0);
    assert_eq!(
        expand(&mut d.queue(), &mut SimClock::default()).unwrap(),
        None
    );
    // a device smaller than the store
    let d = disk_of(&img, 32);
    assert!(expand(&mut d.queue(), &mut SimClock::default()).is_err());
}

/// Crash at every IO of the expand (superblock copy 0, copy 1) under every crash policy: the store mounts with its
/// data, either old or expanded; a repeated expand converges and the superblock copies end equal. A mount alone
/// heals a half-written expand.
#[test]
fn crash_during_expand_is_safe_and_converges() {
    let img = formatted(64);
    let d = disk_of(&img, 64);
    let mut st = mount(&d);
    write_objs(&mut st, 0..100, 64 << 10);
    st.checkpoint().unwrap();
    drop(st);
    let img = d.image();
    let mut half = 0;
    for policy in [
        CrashPolicy::DROP_ALL,
        CrashPolicy::PERSIST_ALL,
        CrashPolicy::MIXED,
    ] {
        for k in 0..12u64 {
            let d = disk_of(&img, 160);
            d.arm_crash(k);
            let done = expand(&mut d.queue(), &mut SimClock::default());
            let crashed = d.crashed();
            let ci = d.crash_image(policy);
            if !crashed {
                assert!(done.unwrap().is_some(), "k={k}");
            }
            half += (ci.read_lba(0) != ci.read_lba(1)) as u32;
            // mount alone: data intact; copies healed when the new format is in place
            let m = disk_of(&ci, 160);
            let mut st = mount(&m);
            verify(&mut st, 0..100, 64 << 10);
            drop(st);
            let (sb, _) = read_super(&mut m.queue(), &mut SimClock::default()).unwrap();
            if sb.features & FEAT_EXPAND != 0 {
                assert_eq!(
                    m.image().read_lba(0),
                    m.image().read_lba(1),
                    "k={k} {policy:?}"
                );
            }
            // converge
            let m = disk_of(&m.image(), 160);
            expand(&mut m.queue(), &mut SimClock::default()).unwrap();
            assert_eq!(
                expand(&mut m.queue(), &mut SimClock::default()).unwrap(),
                None
            );
            assert_eq!(
                m.image().read_lba(0),
                m.image().read_lba(1),
                "k={k} {policy:?}"
            );
            let (sb, dirs) = read_super(&mut m.queue(), &mut SimClock::default()).unwrap();
            assert!(sb.features & FEAT_EXPAND != 0 && dirs.iter().all(|x| x.ext.len() == 1));
            let mut st = mount(&m);
            verify(&mut st, 0..100, 64 << 10);
            write_objs(&mut st, 100..200, 64 << 10);
            st.checkpoint().unwrap();
            assert!(st.check(true).unwrap().errors.is_empty());
        }
    }
    assert!(half > 0, "no crash left the two copies different");
}
