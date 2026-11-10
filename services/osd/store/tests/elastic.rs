// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Elastic meta space (adr 0021 am. 12): tree pages live in cells carved from the data region on demand and
//! returned when empty; the meta image sits in meta pages. Growth/shrink under load, crash matrices over both,
//! image corruption.
mod common;
use common::*;
use store::dev::{CrashPolicy, SimClock, SimDisk};
use store::layout::{FEAT_ELASTIC_META, read_root, read_super};
use store::shard::ShardCfg;
use store::{BLK, StoreError};

const POLICIES: [CrashPolicy; 3] = [
    CrashPolicy::DROP_ALL,
    CrashPolicy::PERSIST_ALL,
    CrashPolicy::MIXED,
];

fn key(i: u64) -> Vec<u8> {
    format!("k/{i:08}").into_bytes()
}

/// Small base area (3% of 16 MiB), tiny cells, frequent checkpoints: the workload must outgrow the base.
fn small_env(storm_pct: u8) -> Env {
    let cfg = ShardCfg {
        dirty_soft_pages: 24,
        dirty_hard_pages: 400,
        ckpt_interval_ns: 200_000,
        meta_slack_cells: 0,
        ..Default::default()
    };
    // 64-page cells (256 KiB): a 16 MiB device sees many grow/shrink steps
    let mut env = make_env_full(16, 128, 1, cfg, 3, 4096, true, 64);
    env.storm_pct = storm_pct;
    env.big_pct = 6;
    env
}

#[test]
fn grows_past_the_base_area_and_gives_cells_back() {
    let env = make_env_ext(
        32,
        256,
        1,
        ShardCfg {
            dirty_soft_pages: 64,
            ..Default::default()
        },
        3,
        4096,
    );
    let mut r = Rig::new(&env, 5);
    let f0 = r.shard.statfs();
    assert!(f0.elastic && f0.meta_cells == 0);
    let base = f0.meta_pages;
    for i in 0..30_000u64 {
        r.put(&key(i), &[0x5a; 90]);
    }
    r.checkpoint();
    let f1 = r.shard.statfs();
    assert!(f1.meta_pages > 2 * base, "{f1:?}");
    assert!(f1.meta_cells > 0 && r.shard.stats.cells_added > 0);
    // cells are data-region blocks: used data grew by the cells, the allocator knows them
    assert_eq!(
        f1.meta_cell_blocks,
        f1.meta_cells * (f1.meta_cell_blocks / f1.meta_cells)
    );
    assert!(f1.data_used >= f1.meta_cell_blocks);
    let img = r.disk.image();
    let rep = r.fsck(&img);
    assert!(rep.meta_pages_used > base);
    r.verify();
    r.remount_clean();
    r.verify();
    assert_eq!(
        r.shard.statfs().meta_cells,
        f1.meta_cells,
        "cell set survives a remount"
    );
    // wipe the keyspace: pages free up, empty cells return to the data region (checkpoints in between: the
    // superseded pages are reusable only after the next root is durable)
    r.delrange(b"k/", b"k0");
    for _ in 0..4 {
        r.put(b"z", b"z");
        r.checkpoint();
    }
    let f2 = r.shard.statfs();
    assert!(f2.meta_cells < f1.meta_cells / 2, "{f2:?} vs {f1:?}");
    assert!(r.shard.stats.cells_released > 0);
    assert!(
        f2.data_free > f1.data_free,
        "returned cells are allocatable data space again"
    );
    let img = r.disk.image();
    r.fsck(&img);
    r.remount_clean();
    r.verify();
    // and they can be taken again
    for i in 0..20_000u64 {
        r.put(&key(i), &[0x33; 1000]);
    }
    r.checkpoint();
    assert!(r.shard.statfs().meta_cells > f2.meta_cells);
    r.remount_clean();
    r.verify();
}

fn exhaustive(
    env: &Env,
    seeds: std::ops::Range<u64>,
    ntxn: u64,
    burst: u64,
    gens: u32,
) -> (u64, (u64, u64)) {
    let (mut runs, mut cells) = (0, (0, 0));
    for seed in seeds {
        let e = count_events(env, seed, ntxn, burst);
        for k in (0..=e).step_by(2) {
            for (pi, pol) in POLICIES.iter().enumerate() {
                let r = one_run(
                    env,
                    seed * 1000 + pi as u64,
                    Some(k),
                    *pol,
                    ntxn,
                    burst,
                    gens,
                )
                .unwrap_or_else(|m| panic!("seed {seed} k {k} policy {pi}: {m}"));
                cells.0 += r.cells.0;
                cells.1 += r.cells.1;
                runs += 1;
            }
        }
    }
    (runs, cells)
}

/// Meta growth while a sliced freeze runs (doc/perf/ckpt-holds-20261025.md): the cell is reserved at once and admits
/// the txn (no Busy until the checkpoint ends), joins the meta space only when the freeze ends (the freeze writes the
/// image of its lsn's cell set), and the store mounts and checks clean after it.
#[test]
fn grows_while_a_freeze_runs() {
    let cfg = ShardCfg {
        dirty_soft_pages: 100_000,
        dirty_hard_pages: 200_000,
        ckpt_interval_ns: u64::MAX / 4,
        ckpt_slice: 1,
        ckpt_fz_polls: 0,
        meta_slack_cells: 0,
        ..Default::default()
    };
    let env = make_env_full(64, 2048, 1, cfg, 3, 4096, true, 64);
    let mut r = Rig::new(&env, 11);
    // new keys of 1000 bytes: meta runs out again and again while sliced freezes (1 page per poll) run
    let mut grown_in_freeze = 0;
    let mut cells_at_growth = 0;
    let mut i = 0u64;
    while grown_in_freeze < 3 {
        let before = (
            r.shard.freeze_active(),
            r.shard.stats.ckpt_begins,
            r.shard.stats.cells_added,
            r.shard.statfs().meta_cells,
        );
        r.put(&key(i), &[0x33; 1000]);
        i += 1;
        assert!(i < 100_000, "no growth while a freeze ran ({i} puts)");
        let in_same_freeze =
            before.0 && r.shard.freeze_active() && r.shard.stats.ckpt_begins == before.1;
        if in_same_freeze && r.shard.stats.cells_added > before.2 {
            grown_in_freeze += 1;
            // reserved, not yet meta space: the freeze's image is the one of its lsn
            assert_eq!(r.shard.statfs().meta_cells, before.3);
            cells_at_growth = before.3;
        }
    }
    r.sync();
    r.checkpoint();
    // the cells reserved during the freeze joined the meta space at its end
    assert!(r.shard.statfs().meta_cells > cells_at_growth);
    let img = r.disk.image();
    r.fsck(&img);
    r.verify();
    r.remount_clean();
    r.verify();
}

#[test]
fn crash_matrix_growth_and_shrink() {
    // storms wipe and refill wide key ranges: cells come and go while crashing at every other IO boundary. A cell goes
    // back once a whole checkpoint cycle asked for less (adr 0021 am. 80): runs long enough for cycles after a wipe
    let env = small_env(35);
    let (runs, cells) = exhaustive(&env, 0..4, 60, 4, 2);
    eprintln!("elastic matrix: {runs} runs, cells added/released {cells:?}");
    assert!(
        cells.0 > 20 && cells.1 > 5,
        "growth/shrink barely exercised: {cells:?}"
    );
}

#[test]
fn crash_random_long_runs_with_cells() {
    let env = small_env(25);
    let mut cells = (0, 0);
    for seed in 0..120u64 {
        let pol = POLICIES[(seed % 3) as usize];
        let r = one_run(&env, 7000 + seed, Some((seed * 41) % 900), pol, 80, 6, 4)
            .unwrap_or_else(|m| panic!("seed {seed}: {m}"));
        cells.0 += r.cells.0;
        cells.1 += r.cells.1;
    }
    eprintln!("elastic long runs: cells added/released {cells:?}");
    assert!(cells.0 > 50);
}

#[test]
fn corrupt_meta_image_is_refused_and_found_by_fsck() {
    let env = small_env(0);
    let mut r = Rig::new(&env, 3);
    for i in 0..8_000u64 {
        r.put(&key(i), &[1; 60]);
    }
    r.checkpoint();
    r.checkpoint();
    let img = r.disk.image();
    r.fsck(&img);
    let (sb, dirs) = {
        let d = SimDisk::from_image(&img, env.sim.clone());
        read_super(&mut d.queue(), &mut SimClock::default()).unwrap()
    };
    let root = {
        let d = SimDisk::from_image(&img, env.sim.clone());
        read_root(&mut d.queue(), &mut SimClock::default(), &dirs[0]).unwrap()
    };
    assert!(root.meta_bitmap_len >= 1 && root.meta_bitmap_addr != 0);
    assert!(sb.features & FEAT_ELASTIC_META != 0);
    for (off, what) in [(2000usize, "payload"), (6, "kind"), (30, "self address")] {
        let mut bad = img.clone();
        bad.corrupt(root.meta_bitmap_addr, off, 0x10);
        let d = SimDisk::from_image(&bad, env.sim.clone());
        let mut clk = SimClock::default();
        let e = store::fsck::fsck(&mut d.queue(), &mut clk, None).unwrap_err();
        assert!(e.contains("meta"), "{what}: {e}");
        let d = SimDisk::from_image(&bad, env.sim.clone());
        match store::shard::Shard::mount(
            d.queue(),
            &mut clk,
            &sb,
            &dirs[0],
            env.scfg.clone(),
            false,
        ) {
            Err(StoreError::Corrupt(m)) => assert!(m.contains("meta"), "{what}: {m}"),
            Err(e) => panic!("{what}: {e:?}"),
            Ok(_) => panic!("{what}: corrupt meta image accepted"),
        }
    }
    // a lost write of the image's first page
    let mut bad = img.clone();
    for b in 0..(BLK as u64) / 8 {
        bad.corrupt(root.meta_bitmap_addr, (b * 8) as usize, 0xff);
    }
    let d = SimDisk::from_image(&bad, env.sim.clone());
    assert!(store::fsck::fsck(&mut d.queue(), &mut SimClock::default(), None).is_err());
}

/// The cell size is part of the format: a store whose superblock lost the feature (or carries another cell size
/// than the image) is not mounted with a misread allocator.
#[test]
fn image_without_the_feature_bit_is_refused() {
    let env = small_env(0);
    let mut r = Rig::new(&env, 9);
    for i in 0..6_000u64 {
        r.put(&key(i), &[1; 60]);
    }
    r.checkpoint();
    let img = r.disk.image();
    let d = SimDisk::from_image(&img, env.sim.clone());
    let mut clk = SimClock::default();
    let (mut sb, dirs) = read_super(&mut d.queue(), &mut clk).unwrap();
    sb.features = 0;
    sb.cell_pages = 0;
    assert!(matches!(
        store::shard::Shard::mount(d.queue(), &mut clk, &sb, &dirs[0], env.scfg.clone(), false),
        Err(StoreError::Corrupt(_))
    ));
    let (mut sb, dirs) = read_super(&mut d.queue(), &mut clk).unwrap();
    sb.cell_pages *= 2;
    assert!(matches!(
        store::shard::Shard::mount(d.queue(), &mut clk, &sb, &dirs[0], env.scfg.clone(), false),
        Err(StoreError::Corrupt(_))
    ));
}
