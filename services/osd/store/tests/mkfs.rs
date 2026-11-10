// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! mkfs over a used device (adr 0021 am. 36): a fresh store never interprets the old WAL / metadata as its own.
mod common;

use store::dev::{BlockDev, Clock, CrashPolicy, SimClock, SimDisk};
use store::fsck::fsck;
use store::layout::{MkfsParams, mkfs, read_super};
use store::shard::{Event, Shard, ShardCfg, Txn};
use store::sio::Sio;
use store::state::Op;
use store::{BLK, StoreError};

const WAL: u64 = 128;

/// Same fsid, same mkfs_time: the identity of the old and the new store is identical (worst case).
fn params() -> MkfsParams {
    MkfsParams {
        shards: 1,
        wal_blocks: WAL,
        align_blocks: 1,
        meta_pct: 6,
        ..Default::default()
    }
}

#[test]
fn invalid_metadata_geometry_never_erases_an_existing_store() {
    let disk = used_disk(&params(), 1);
    let before = disk.image();
    let mut cases = Vec::new();
    for node_size in [0, 2048, 6144, 65536] {
        cases.push(MkfsParams {
            node_size,
            ..params()
        });
    }
    cases.push(MkfsParams {
        meta_pct: 0,
        ..params()
    });
    for meta_max_blocks in [0, 1, 8] {
        cases.push(MkfsParams {
            meta_max_blocks,
            ..params()
        });
    }
    // 2^29 pages of 32 KiB: one cell would span 2^32 blocks, beyond one allocator extent (mount refuses it).
    cases.push(MkfsParams {
        node_size: 32768,
        cell_pages: 1 << 29,
        ..params()
    });
    for p in cases {
        for elastic_meta in [false, true] {
            if !elastic_meta && (p.meta_max_blocks != u64::MAX || p.cell_pages != 0) {
                continue; // The fixed-meta format uses neither the cap nor cells.
            }
            let p = MkfsParams {
                elastic_meta,
                ..p.clone()
            };
            let writes = disk.stats().writes;
            assert!(
                matches!(
                    mkfs(&mut disk.queue(), &mut SimClock::default(), &p),
                    Err(StoreError::BadGeometry(_))
                ),
                "node_size={} meta_pct={} meta_max_blocks={} cell_pages={} elastic={elastic_meta}",
                p.node_size,
                p.meta_pct,
                p.meta_max_blocks,
                p.cell_pages
            );
            assert_eq!(disk.stats().writes, writes, "invalid mkfs issued writes");
        }
    }
    let after = disk.image();
    for lba in 0..before.lba_count {
        assert_eq!(before.read_lba(lba), after.read_lba(lba));
    }
    let mut clk = SimClock::default();
    let (sb, dirs) = read_super(&mut disk.queue(), &mut clk).unwrap();
    let (s, _) = Shard::mount(disk.queue(), &mut clk, &sb, &dirs[0], cfg(), false).unwrap();
    assert_eq!(s.state().lsn, 1);
}

#[test]
fn every_supported_node_size_formats_a_mountable_store() {
    for node_size in [4096, 8192, 16384, 32768] {
        let p = MkfsParams {
            node_size,
            ..params()
        };
        let disk = SimDisk::new(store::dev::SimConfig::new(16 << 20));
        mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
        mount_empty(&disk, 1);
    }
}

fn cfg() -> ShardCfg {
    ShardCfg {
        auto_ckpt: false,
        ..Default::default()
    }
}

fn put(s: &mut Shard<store::dev::SimDev>, clk: &mut SimClock, token: u64) {
    let mut t = Txn::new(token);
    t.ops.push(Op::Put(
        format!("k{token}").into_bytes(),
        format!("v{token}").into_bytes(),
    ));
    s.submit(t).unwrap();
    for _ in 0..100_000 {
        let mut ev = Vec::new();
        s.poll(clk.t, &mut ev);
        if ev
            .iter()
            .any(|e| matches!(e, Event::Acked(t) if *t == token))
        {
            return;
        }
        let h = s.dev().next_deadline();
        clk.idle(h);
    }
    panic!("no ack");
}

/// Mount `n` times (each bumps the epoch, so stale units of an old store would become "current" one day), expect an
/// empty store and a clean fsck each time.
fn mount_empty(disk: &SimDisk, n: usize) {
    for _ in 0..n {
        let mut clk = SimClock::default();
        let mut dev = disk.queue();
        let (sb, dirs) = read_super(&mut dev, &mut clk).unwrap();
        let (s, _) = Shard::mount(dev, &mut clk, &sb, &dirs[0], cfg(), false).unwrap();
        assert_eq!(s.state().lsn, 0);
        drop(s);
        fsck(&mut disk.queue(), &mut clk, None).unwrap();
    }
}

fn used_disk(p: &MkfsParams, txns: u64) -> SimDisk {
    let disk = SimDisk::new(store::dev::SimConfig::new(16 << 20));
    let mut clk = SimClock::default();
    let mut dev = disk.queue();
    let (sb, dirs) = mkfs(&mut dev, &mut clk, p).unwrap();
    let (mut s, _) = Shard::mount(disk.queue(), &mut clk, &sb, &dirs[0], cfg(), false).unwrap();
    for i in 1..=txns {
        put(&mut s, &mut clk, i);
    }
    drop(s);
    disk
}

#[test]
fn remkfs_over_a_used_store_mounts_empty() {
    let disk = used_disk(&params(), 40);
    let before = disk.image();
    mkfs(&mut disk.queue(), &mut SimClock::default(), &params()).unwrap();
    assert_ne!(before.read_lba(8), disk.image().read_lba(8));
    mount_empty(&disk, 4);
    // and the new store works
    let mut clk = SimClock::default();
    let mut dev = disk.queue();
    let (sb, dirs) = read_super(&mut dev, &mut clk).unwrap();
    let (mut s, _) = Shard::mount(dev, &mut clk, &sb, &dirs[0], cfg(), false).unwrap();
    put(&mut s, &mut clk, 1);
}

#[test]
fn remkfs_over_random_garbage() {
    let disk = SimDisk::new(store::dev::SimConfig::new(16 << 20));
    let mut clk = SimClock::default();
    let mut dev = disk.queue();
    let mut rng = store::rng::Rng::new(77);
    let blocks = (16 << 20) / BLK as u64;
    let mut io = Sio::new(&mut dev, &mut clk);
    for b in (0..blocks).step_by(64) {
        let mut buf = vec![0u8; 64 * BLK];
        rng.fill(&mut buf);
        io.write_one(b, &buf).unwrap();
    }
    mkfs(&mut disk.queue(), &mut SimClock::default(), &params()).unwrap();
    mount_empty(&disk, 3);
}

#[test]
fn remkfs_over_a_store_of_an_older_format() {
    let mut old = params();
    old.elastic_meta = false;
    old.compact_int = false;
    old.inline_data = false;
    old.omap_runs = false;
    old.lazy_free = false;
    old.leaf_delta = false;
    let disk = used_disk(&old, 40);
    mkfs(&mut disk.queue(), &mut SimClock::default(), &params()).unwrap();
    mount_empty(&disk, 3);
    // the other way round: an old format store over a current one
    let disk = used_disk(&params(), 40);
    mkfs(&mut disk.queue(), &mut SimClock::default(), &old).unwrap();
    mount_empty(&disk, 3);
}

#[test]
fn crash_during_mkfs_then_mkfs_again() {
    let used = used_disk(&params(), 40).image();
    for policy in [
        CrashPolicy::DROP_ALL,
        CrashPolicy::PERSIST_ALL,
        CrashPolicy::MIXED,
    ] {
        for k in 0..40u64 {
            let disk = SimDisk::from_image(&used, store::dev::SimConfig::new(16 << 20));
            disk.arm_crash(k);
            let r = mkfs(&mut disk.queue(), &mut SimClock::default(), &params());
            let crashed = disk.crashed();
            let ci = SimDisk::from_image(
                &disk.crash_image(policy),
                store::dev::SimConfig::new(16 << 20),
            );
            if !crashed {
                r.unwrap();
                mount_empty(&ci, 1);
                break;
            }
            // half-way: never a mix of old and new; superblock gone or the new one (then everything is new)
            let mut clk = SimClock::default();
            match read_super(&mut ci.queue(), &mut clk) {
                Err(StoreError::NotFormatted | StoreError::Corrupt(_)) => {}
                Ok((sb, dirs)) => {
                    let (s, _) =
                        Shard::mount(ci.queue(), &mut clk, &sb, &dirs[0], cfg(), false).unwrap();
                    // nothing persisted yet = the old store, intact; otherwise the new empty one
                    let l = s.state().lsn;
                    assert!(l == 0 || l == 40, "k={k} {policy:?}: lsn {l}");
                }
                Err(e) => panic!("k={k}: {e:?}"),
            }
            mkfs(&mut ci.queue(), &mut SimClock::default(), &params()).unwrap();
            mount_empty(&ci, 3);
        }
    }
}

/// Fixed areas of production devices (adr 0021 am. 54): everything but the WAL rings (device budget, adr 0160) stays
/// below 0.35 % of the drive (0.12 % from 1.9 TB up); the data regions cover the rest.
#[test]
fn production_layout_wastes_little_besides_the_wal() {
    for (bytes, shards) in [
        (1_920_000_000_000u64, 1u32),
        (1_920_000_000_000, 8),
        (1_920_000_000_000, 32),
        (7_680_000_000_000, 8),
        (7_680_000_000_000, 32),
        (300_000_000_000, 8),
    ] {
        let blocks = bytes / 4096;
        let p = MkfsParams::for_device(bytes, shards);
        let (_, dirs) = store::layout::plan(blocks, &p).unwrap();
        let wal: u64 = dirs.iter().map(|d| d.wal_blocks).sum();
        let data: u64 = dirs
            .iter()
            .map(|d| d.region_start + d.region_blocks - d.data_start)
            .sum(); // whole data space (a chunked store keeps the pool in the region too)
        let other = blocks - wal - data;
        assert!(
            other as f64 <= blocks as f64 * 0.0035,
            "{bytes} B x {shards} shards: meta base + alignment + roots = {:.3} %",
            other as f64 * 100.0 / blocks as f64
        );
        assert!(
            dirs.iter().all(|d| d.meta_blocks >= 16_384),
            "base >= 64 MiB"
        );
    }
}
