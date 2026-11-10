// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `store_shards` (adr 0160): any shard count (not only powers of two), WAL ring sizing, and per-core mounts with a
//! core count different from the one at mkfs (more, fewer, not dividing the shards), incl. replay after a crash and a
//! crash at every IO of mkfs / of the per-core mounts.
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use store::BLK;
use store::dev::{CrashPolicy, SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::layout::{
    MAX_SHARDS, MkfsParams, StoreShards, WAL_RING_MAX, WAL_RING_MIN, mkfs, plan, read_super,
    wal_blocks_for,
};
use store::obj::{OTxn, ObjError, Store, StoreCfg, TOp, shard_of_spg};

type St = Store<SimDev, SimClock>;

const CAP: u64 = 256 << 20;
const PGS: u32 = 24;
const POLICIES: [CrashPolicy; 3] = [
    CrashPolicy::DROP_ALL,
    CrashPolicy::MIXED,
    CrashPolicy::PERSIST_ALL,
];

fn coll(seed: u32) -> CollT {
    CollT::Pg(SpgT {
        pgid: PgT::new(1, seed),
        shard: ShardId::NO_SHARD,
    })
}

fn obj(n: &str, seed: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(n.as_bytes(), SnapId::NOSNAP, seed, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn params(shards: u32) -> MkfsParams {
    MkfsParams {
        shards,
        wal_blocks: 512,
        align_blocks: 1,
        meta_pct: 8,
        ..Default::default()
    }
}

fn sim() -> SimConfig {
    SimConfig::new(CAP)
}

/// Core of PG `seed` with `n` cores: the core owning its shard.
fn core_of(seed: u32, shards: u32, n: usize) -> usize {
    shard_of_spg(1, seed, shards) % n
}

/// Mount core `c` of `n` (shards `s % n == c`).
fn mount_core(disk: &SimDisk, c: usize, n: usize) -> St {
    let d = disk.clone();
    Store::mount_shards(
        move || d.queue(),
        SimClock::default(),
        StoreCfg::default(),
        move |s| s as usize % n == c,
    )
    .unwrap()
    .0
}

fn mount_cores(disk: &SimDisk, n: usize) -> Vec<St> {
    (0..n).map(|c| mount_core(disk, c, n)).collect()
}

fn val(seed: u32, g: u8) -> Vec<u8> {
    vec![seed as u8 ^ g.wrapping_mul(31); 6000]
}

/// Every PG gets its collection and object `a` (generation 1), committed (acked) on its core.
fn populate(cores: &mut [St], shards: u32) {
    let n = cores.len();
    for seed in 0..PGS {
        let v = val(seed, 1);
        let mut t = OTxn::new();
        t.push(TOp::MkColl {
            cid: coll(seed),
            bits: 0,
            exist_ok: true,
        });
        t.write(coll(seed), &obj("a", seed), 0, &v);
        cores[core_of(seed, shards, n)].commit(&t).unwrap();
        // no other core can touch the PG
        let other = (core_of(seed, shards, n) + 1) % n;
        if n > 1 {
            assert!(matches!(
                cores[other].commit(&t),
                Err(ObjError::NotMounted(_))
            ));
        }
    }
}

/// Every PG: `a` holds generation 1; `b` holds generation 2 if its token was acked, else generation 2 or nothing.
fn verify(cores: &mut [St], shards: u32, acked: &[u32]) {
    let n = cores.len();
    for seed in 0..PGS {
        let st = &mut cores[core_of(seed, shards, n)];
        assert_eq!(
            st.read(&coll(seed), &obj("a", seed), 0, 6000).unwrap(),
            val(seed, 1),
            "pg {seed} n {n}"
        );
        match st.read(&coll(seed), &obj("b", seed), 0, 6000) {
            Ok(v) => assert_eq!(v, val(seed, 2), "pg {seed}: torn b"),
            Err(ObjError::NoEnt) => assert!(!acked.contains(&seed), "pg {seed}: acked b lost"),
            Err(e) => panic!("pg {seed}: {e:?}"),
        }
    }
    for st in cores.iter_mut() {
        let r = st.check(true).unwrap();
        assert!(r.errors.is_empty(), "{:?}", r.errors);
    }
}

/// Queue object `b` for every PG on its core and poll a little: some acked, some in flight. Returns the acked seeds.
fn write_b_partly(cores: &mut [St], shards: u32) -> Vec<u32> {
    let n = cores.len();
    for seed in 0..PGS {
        let v = val(seed, 2);
        let mut t = OTxn::new();
        t.write(coll(seed), &obj("b", seed), 0, &v);
        cores[core_of(seed, shards, n)]
            .queue(&t, u64::from(seed) + 1)
            .unwrap();
    }
    let mut acked = Vec::new();
    for st in cores.iter_mut() {
        let mut got = Vec::new();
        st.poll(&mut got).unwrap();
        st.idle();
        st.poll(&mut got).unwrap();
        acked.extend(got.into_iter().map(|t| t as u32 - 1));
    }
    acked
}

// ---------------------------------------------------------------- layout

#[test]
fn any_shard_count_plans_and_mounts() {
    for s in [1u32, 3, 5, 6, 7, 12] {
        let (sb, dirs) = plan(CAP / BLK as u64, &params(s)).unwrap();
        assert_eq!((sb.shards, dirs.len()), (s, s as usize));
        // regions disjoint and in order
        for w in dirs.windows(2) {
            assert!(w[0].region_start + w[0].region_blocks <= w[1].region_start);
        }
        let disk = SimDisk::new(sim());
        mkfs(&mut disk.queue(), &mut SimClock::default(), &params(s)).unwrap();
        let mut cores = mount_cores(&disk, s.min(4) as usize);
        populate(&mut cores, s);
        verify(&mut cores, s, &[]);
    }
    assert!(plan(CAP / BLK as u64, &params(0)).is_err());
    assert!(plan(1 << 40, &params(MAX_SHARDS + 1)).is_err());
}

#[test]
fn store_shards_setting_parses_and_resolves() {
    assert_eq!(StoreShards::parse("auto"), Ok(StoreShards::Auto));
    assert_eq!(StoreShards::parse(" 6 "), Ok(StoreShards::Count(6)));
    for bad in ["0", "-1", "x", "257", ""] {
        assert!(StoreShards::parse(bad).is_err(), "{bad}");
    }
    assert_eq!(StoreShards::Auto.resolve(6), 6);
    assert_eq!(StoreShards::Auto.resolve(0), 1);
    assert_eq!(StoreShards::Auto.resolve(1000), MAX_SHARDS);
    assert_eq!(StoreShards::Count(3).resolve(8), 3);
}

#[test]
fn wal_rings_split_the_device_budget_within_bounds() {
    const G: u64 = 1 << 30;
    let ring = |bytes: u64, s: u32| wal_blocks_for(bytes, s) * BLK as u64;
    // 7.68 TB: 4 GiB total (adr 0160 am. 4); 8 shards = 512 MiB each, 32 shards = 128 MiB, 1 shard = the whole budget
    let big = 7_680_000_000_000;
    assert_eq!(ring(big, 8), G / 2);
    assert_eq!(ring(big, 32), 128 << 20);
    assert_eq!(ring(big, 1), WAL_RING_MAX);
    assert_eq!(ring(big, 4), G);
    assert_eq!(ring(big, 256), WAL_RING_MIN);
    // 1.92 TB: device / 64 = 30 GiB, capped at the 4 GiB budget; 128 GiB: 2 GiB total
    assert_eq!(ring(1_920_000_000_000, 8), G / 2);
    assert_eq!(ring(128 * G, 8), G / 4);
    // lab: floor
    assert_eq!(ring(16 * G, 8), WAL_RING_MIN);
    for s in 1..=MAX_SHARDS {
        let r = ring(big, s);
        assert!(
            (WAL_RING_MIN..=WAL_RING_MAX).contains(&r)
                && r * u64::from(s) <= 4 * G + u64::from(s) * WAL_RING_MIN
        );
    }
    // the sized params fit the device they were made for
    for (bytes, s) in [
        (big, 1),
        (big, 6),
        (big, 8),
        (big, 32),
        (1 << 40, 3),
        (256 * G, 8),
        (16 * G, 8),
        (16 * G, 3),
    ] {
        let p = MkfsParams::for_device(bytes, s);
        let (sb, _) = plan(bytes / BLK as u64, &p).unwrap_or_else(|e| panic!("{bytes} {s}: {e:?}"));
        assert_eq!(sb.shards, s);
    }
}

// ---------------------------------------------------------------- core count != mkfs core count

/// mkfs for 6 cores (6 shards), run with 6, 4, 8 -> 6 (capped by the daemon), 1, 5, back to 6: every PG on the core
/// of its shard, data intact.
#[test]
fn remount_with_any_core_count() {
    let s = 6;
    let disk = SimDisk::new(sim());
    mkfs(&mut disk.queue(), &mut SimClock::default(), &params(s)).unwrap();
    let mut cores = mount_cores(&disk, 6);
    populate(&mut cores, s);
    drop(cores);
    for n in [4usize, 6, 1, 5, 2, 3, 6] {
        let mut cores = mount_cores(&disk, n);
        let owned: usize = cores.iter().map(|c| c.shards.len()).sum();
        assert_eq!(owned, s as usize, "n {n}: every shard mounted exactly once");
        verify(&mut cores, s, &[]);
        // and writable on the new layout
        for seed in 0..PGS {
            let v = val(seed, 1);
            let mut t = OTxn::new();
            t.write(coll(seed), &obj("a", seed), 0, &v);
            cores[core_of(seed, s, n)].commit(&t).unwrap();
        }
    }
}

/// Crash with in-flight txns on 4 cores over 6 shards, replay with 1 / 3 / 5 / 6 cores: acked txns survive, the rest is
/// all-or-nothing, fsck clean; again after a second crash on the new layout.
#[test]
fn replay_after_crash_with_changed_core_count() {
    let s = 6;
    let disk = SimDisk::new(sim());
    mkfs(&mut disk.queue(), &mut SimClock::default(), &params(s)).unwrap();
    let mut cores = mount_cores(&disk, 4);
    populate(&mut cores, s);
    let acked = write_b_partly(&mut cores, s);
    for policy in POLICIES {
        let img = disk.crash_image(policy);
        for n in [1usize, 3, 5, 6] {
            let d = SimDisk::from_image(&img, sim());
            let mut cores = mount_cores(&d, n);
            verify(&mut cores, s, &acked);
            // second generation: crash on the new layout, back to 4 cores
            let acked2: Vec<u32> = {
                let mut more = Vec::new();
                for seed in 0..PGS {
                    let v = val(seed, 2);
                    let mut t = OTxn::new();
                    t.write(coll(seed), &obj("b", seed), 0, &v);
                    cores[core_of(seed, s, n)].commit(&t).unwrap();
                    more.push(seed);
                }
                more
            };
            let img2 = d.crash_image(policy);
            let mut cores = mount_cores(&SimDisk::from_image(&img2, sim()), 4);
            verify(&mut cores, s, &acked2);
        }
    }
}

/// Crash at every IO of the per-core mounts after a core-count change (replay + mount checkpoint), each policy; the next
/// mount (another core count) sees the acked state.
#[test]
fn crash_matrix_mount_with_changed_core_count() {
    let s = 6;
    let disk = SimDisk::new(sim());
    mkfs(&mut disk.queue(), &mut SimClock::default(), &params(s)).unwrap();
    let mut cores = mount_cores(&disk, 4);
    populate(&mut cores, s);
    let acked = write_b_partly(&mut cores, s);
    let base: SimImage = disk.crash_image(CrashPolicy::MIXED);
    drop(cores);
    // IO events of a full 3-core mount
    let probe = SimDisk::from_image(&base, sim());
    let e0 = probe.events();
    drop(mount_cores(&probe, 3));
    let span = probe.events() - e0;
    assert!(span > 0);
    for k in 0..=span {
        for policy in POLICIES {
            let d = SimDisk::from_image(&base, sim());
            d.arm_crash(d.events() + k);
            for c in 0..3 {
                let d2 = d.clone();
                // a crashed device fails the mount: fine, the next one must recover
                let _ = Store::mount_shards(
                    move || d2.queue(),
                    SimClock::default(),
                    StoreCfg::default(),
                    move |x| x as usize % 3 == c,
                );
            }
            let img = if d.crashed() {
                d.crash_image(policy)
            } else {
                d.image()
            };
            let mut cores = mount_cores(&SimDisk::from_image(&img, sim()), 5);
            verify(&mut cores, s, &acked);
        }
    }
}

/// Crash at every IO of mkfs with a non-power-of-two shard count over a used store: superblock gone, the old store,
/// or the new empty one; a second mkfs always yields a mountable store.
#[test]
fn crash_matrix_mkfs_three_shards() {
    let disk = SimDisk::new(sim());
    mkfs(&mut disk.queue(), &mut SimClock::default(), &params(6)).unwrap();
    let mut cores = mount_cores(&disk, 2);
    populate(&mut cores, 6);
    drop(cores);
    let used = disk.image();
    let probe = SimDisk::from_image(&used, sim());
    let e0 = probe.events();
    mkfs(&mut probe.queue(), &mut SimClock::default(), &params(3)).unwrap();
    let span = probe.events() - e0;
    for k in 0..=span {
        for policy in POLICIES {
            let d = SimDisk::from_image(&used, sim());
            d.arm_crash(d.events() + k);
            let r = mkfs(&mut d.queue(), &mut SimClock::default(), &params(3));
            let img = if d.crashed() {
                d.crash_image(policy)
            } else {
                r.map(|_| d.image()).unwrap()
            };
            let ci = SimDisk::from_image(&img, sim());
            match read_super(&mut ci.queue(), &mut SimClock::default()) {
                Ok((sb, _)) if sb.shards == 6 => {
                    // the old store, intact
                    let mut cores = mount_cores(&ci, 2);
                    verify(&mut cores, 6, &[]);
                }
                Ok((sb, _)) => {
                    assert_eq!(sb.shards, 3);
                    let mut cores = mount_cores(&ci, 2);
                    assert!(
                        cores.iter_mut().all(|c| c.list_colls().unwrap().is_empty()),
                        "k={k}"
                    );
                }
                Err(_) => {}
            }
            mkfs(&mut ci.queue(), &mut SimClock::default(), &params(3)).unwrap();
            let mut cores = mount_cores(&ci, 2);
            populate(&mut cores, 3);
            verify(&mut cores, 3, &[]);
        }
    }
}
