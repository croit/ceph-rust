// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
mod common;
use common::*;
use store::StoreError;
use store::dev::{CrashPolicy, SimDisk};
use store::shard::ShardCfg;

#[test]
fn smoke_no_crash_remount() {
    let env = make_env(64, 256, 1, ShardCfg::default());
    let mut h = Harness::new(&env, 1);
    assert!(h.run(50, 4));
    assert_eq!(h.acked, 50);
    h.crash_and_remount(CrashPolicy::DROP_ALL, None).unwrap();
    assert_eq!(h.shard.state().lsn, 50);
}

const POLICIES: [CrashPolicy; 3] = [
    CrashPolicy::DROP_ALL,
    CrashPolicy::PERSIST_ALL,
    CrashPolicy::MIXED,
];

/// Crash at every IO boundary (submit or completion event) of seeded workloads, for each crash policy.
fn exhaustive(
    env: &Env,
    seeds: std::ops::Range<u64>,
    ntxn: u64,
    burst: u64,
    gens: u32,
) -> (u64, u64, u64, u64) {
    let (mut runs, mut crashed, mut invalid, mut ckpts, mut dealloc) = (0, 0, 0, 0, 0);
    for seed in seeds {
        let e = count_events(env, seed, ntxn, burst);
        for k in 0..=e {
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
                crashed += r.crashed_in_gen0 as u64;
                invalid += r.stats.data_invalid_units;
                ckpts += r.ckpts;
                dealloc += r.dealloc_crashes;
                runs += 1;
            }
        }
    }
    eprintln!(
        "  checkpoints completed across runs: {ckpts}, crashes with a deallocate in flight: {dealloc}"
    );
    (runs, crashed, invalid, dealloc)
}

#[test]
fn crash_matrix_every_io_boundary() {
    // eager seal (kill switch `wal_coalesce` 0): more units, more boundaries; coalescing: `crash_matrix_wal_coalesce`
    let env = make_env(
        64,
        512,
        1,
        ShardCfg {
            wal_coalesce: 0,
            ..Default::default()
        },
    );
    let (runs, crashed, invalid, _) = exhaustive(&env, 0..6, 24, 4, 1);
    eprintln!(
        "every-boundary matrix: {runs} runs, {crashed} crashed mid-workload, {invalid} replays cut by a data-crc mismatch"
    );
    assert!(runs > 900 && crashed > 800);
    assert!(
        invalid > 20,
        "parallel-commit crc validation path barely exercised"
    );
}

#[test]
fn crash_matrix_every_io_boundary_then_more_generations() {
    // crash points exhaustive in gen 0, then two more random crash/remount cycles (epoch rule, tail reuse)
    let env = make_env(64, 512, 1, ShardCfg::default());
    let (runs, _, _, _) = exhaustive(&env, 100..103, 20, 5, 3);
    eprintln!("multi-gen exhaustive: {runs} runs");
}

#[test]
fn crash_matrix_small_ring_wrap_and_release() {
    // 64-block ring, 4-block units: constant wrap + PAD units + checkpoint-stub releases + WalFull backpressure
    let cfg = ShardCfg {
        max_unit_blocks: 4,
        ..Default::default()
    };
    let env = make_env(64, 64, 1, cfg);
    let (runs, crashed, _, _) = exhaustive(&env, 200..204, 60, 6, 2);
    eprintln!("wrap matrix: {runs} runs, {crashed} crashed");
}

#[test]
fn crash_matrix_atomic_multi_lba_writes() {
    // device with AWUPF = 64 LBAs: multi-block writes are never torn (optimization path must stay correct)
    let env = make_env(64, 512, 64, ShardCfg::default());
    let (runs, _, _, _) = exhaustive(&env, 300..303, 24, 4, 1);
    eprintln!("awupf matrix: {runs} runs");
}

#[test]
fn crash_random_long_runs() {
    let env = make_env(
        64,
        128,
        1,
        ShardCfg {
            max_unit_blocks: 8,
            ..Default::default()
        },
    );
    let mut remounts = 0;
    for seed in 0..400u64 {
        let pol = POLICIES[(seed % 3) as usize];
        let r = one_run(&env, 5000 + seed, Some((seed * 37) % 700), pol, 120, 8, 4)
            .unwrap_or_else(|m| panic!("seed {seed}: {m}"));
        remounts += r.stats.units;
    }
    eprintln!("random long runs ok, replayed units total {remounts}");
}

#[test]
#[ignore = "soak: ~60k scenarios; run with --release --ignored"]
fn crash_soak() {
    let mut total = 0;
    for (wal, unit, awupf) in [(512u64, 16u32, 1u32), (64, 4, 1), (256, 8, 64)] {
        let env = make_env(
            64,
            wal,
            awupf,
            ShardCfg {
                max_unit_blocks: unit,
                ..Default::default()
            },
        );
        let (runs, _, _, _) = exhaustive(&env, 1000..1040, 40, 6, 2);
        total += runs;
        for seed in 0..3000u64 {
            let pol = POLICIES[(seed % 3) as usize];
            one_run(&env, 90_000 + seed, Some((seed * 53) % 900), pol, 150, 8, 4)
                .unwrap_or_else(|m| panic!("soak seed {seed}: {m}"));
            total += 1;
        }
    }
    // checkpoint-heavy configurations: 8 KiB and 4 KiB pages, tiny cache, ring wrap, space pressure
    let mut cfgs: Vec<(Env, u64)> = vec![
        (make_env(64, 256, 1, ckpt_heavy_cfg()), 0),
        (
            make_env_ext(
                64,
                256,
                1,
                ShardCfg {
                    cache_pages: 8,
                    ..ckpt_heavy_cfg()
                },
                8,
                4096,
            ),
            0,
        ),
        (
            make_env_ext(
                64,
                64,
                1,
                ShardCfg {
                    max_unit_blocks: 4,
                    ..ckpt_heavy_cfg()
                },
                6,
                4096,
            ),
            0,
        ),
        (
            make_env_ext(
                64,
                256,
                64,
                ShardCfg {
                    ckpt_interval_ns: 200_000,
                    ..ckpt_heavy_cfg()
                },
                6,
                8192,
            ),
            0,
        ),
    ];
    let mut tight = make_env_ext(
        6,
        128,
        1,
        ShardCfg {
            dirty_soft_pages: 6,
            ..Default::default()
        },
        8,
        4096,
    );
    tight.nobj = 70;
    tight.obj_scale = 6;
    cfgs.push((tight, 0));
    for (env, _) in &cfgs {
        let (runs, _, _, _) = exhaustive(env, 2000..2030, 40, 5, 2);
        total += runs;
        for seed in 0..2500u64 {
            let pol = POLICIES[(seed % 3) as usize];
            one_run(
                env,
                190_000 + seed,
                Some((seed * 41) % 1100),
                pol,
                150,
                7,
                4,
            )
            .unwrap_or_else(|m| panic!("ckpt soak seed {seed}: {m}"));
            total += 1;
        }
    }
    eprintln!("soak: {total} scenarios ok");
}

fn ckpt_heavy_cfg() -> ShardCfg {
    // a checkpoint is (re)started as soon as anything is dirty: crash points land in page writes, bitmap and
    // root slot writes, and in the WAL traffic running alongside
    ShardCfg {
        dirty_soft_pages: 1,
        ckpt_interval_ns: 20_000,
        ..Default::default()
    }
}

#[test]
fn crash_matrix_checkpoint_heavy() {
    let env = make_env(64, 256, 1, ckpt_heavy_cfg());
    let (runs, crashed, _, _) = exhaustive(&env, 400..406, 30, 4, 1);
    eprintln!("ckpt-heavy matrix: {runs} runs, {crashed} crashed");
}

/// Runtime deallocate (adr 0642): checkpoints release whole free windows and the workload has device idle gaps, so
/// deallocates go out between txns. Crash points land inside the commands (persisted, dropped or torn by the policy) and
/// in the writes that reuse their windows after the completion: no block the WAL or the replay still references is
/// ever deallocated, every recovered object reads back.
#[test]
fn crash_matrix_deallocates() {
    let mut env = make_env(64, 256, 1, ckpt_heavy_cfg());
    env.idle_pct = 40;
    env.sim.dealloc_ns = 500_000;
    let (runs, crashed, _, dealloc) = exhaustive(&env, 430..436, 30, 4, 2);
    eprintln!(
        "deallocate matrix: {runs} runs, {crashed} crashed, {dealloc} with a deallocate in flight"
    );
    assert!(
        dealloc > 100,
        "crashes with a deallocate in flight: {dealloc}"
    );
}

/// Sliced freeze (adr 0021 am. 40): one page per slice (and the kill switch), so every checkpoint is frozen over many
/// polls with txns applied in between (write barriers force pending pages, re-dirtied path pages); 4 KiB pages and a tiny
/// cache: splits, merges, root growth and evictions while a freeze runs. Crash at every IO boundary x 3 policies.
#[test]
fn crash_matrix_sliced_freeze() {
    for slice in [1usize, 2, 0] {
        let cfg = ShardCfg {
            cache_pages: 8,
            ckpt_slice: slice,
            ..ckpt_heavy_cfg()
        };
        let mut env = make_env_ext(64, 256, 1, cfg, 8, 4096);
        env.storm_pct = 20;
        let (runs, crashed, _, _) = exhaustive(&env, 420..424, 30, 4, 2);
        eprintln!("sliced-freeze matrix slice {slice}: {runs} runs, {crashed} crashed");
        assert!(
            runs > 300 && crashed > 200,
            "slice {slice}: {runs} runs, {crashed} crashed"
        );
    }
}

/// Sliced checkpoint start and freeze end (adr 0021 am. 80): the start writes the cycle's bitmap chunks (objects spread
/// over the device) one budget unit per poll before the freeze begins, the end steps (fix-up, unalias, relog) run one
/// unit per poll after its pages; txns, page misses and evictions between any two slices. Crash at every IO boundary x 3
/// policies; the matrix lands crash points inside both. Sliced delta folds under crashes: delta.rs
/// (`crash_runs_with_a_sliced_freeze`).
#[test]
fn crash_matrix_sliced_ckpt_steps() {
    for slice in [1usize, 2] {
        let cfg = ShardCfg {
            cache_pages: 8,
            ckpt_slice: slice,
            ..ckpt_heavy_cfg()
        };
        let mut env = make_env_ext(256, 256, 1, cfg, 8, 4096);
        env.storm_pct = 20;
        env.spread_pct = 40;
        let (mut runs, mut crashed, mut starting, mut ending) = (0u64, 0u64, 0u64, 0u64);
        for seed in 430..434 {
            let (ntxn, burst) = (30, 4);
            let e = count_events(&env, seed, ntxn, burst);
            for k in 0..=e {
                for (pi, pol) in POLICIES.iter().enumerate() {
                    let r = one_run(&env, seed * 1000 + pi as u64, Some(k), *pol, ntxn, burst, 2)
                        .unwrap_or_else(|m| {
                            panic!("slice {slice} seed {seed} k {k} policy {pi}: {m}")
                        });
                    runs += 1;
                    crashed += r.crashed_in_gen0 as u64;
                    starting += r.crashed_starting as u64;
                    ending += r.crashed_ending as u64;
                }
            }
        }
        eprintln!(
            "sliced-steps matrix slice {slice}: {runs} runs, {crashed} crashed, {starting} in a start, {ending} in a freeze end"
        );
        assert!(
            runs > 300 && starting > 0 && ending > 0,
            "slice {slice}: {runs} runs, {crashed} crashed, {starting} in a start, {ending} in a freeze end"
        );
    }
}

#[test]
fn crash_matrix_checkpoint_heavy_small_pages_and_cache() {
    // 4 KiB pages (deep tree, many splits) and a tiny page cache (evictions, async page reads, Miss retries)
    let cfg = ShardCfg {
        cache_pages: 6,
        ..ckpt_heavy_cfg()
    };
    let env = make_env_ext(64, 256, 1, cfg, 8, 4096);
    let (runs, crashed, _, _) = exhaustive(&env, 410..414, 40, 4, 2);
    eprintln!("ckpt-heavy small-page matrix: {runs} runs, {crashed} crashed");
}

#[test]
fn crash_matrix_checkpoint_heavy_ring_wrap() {
    let cfg = ShardCfg {
        max_unit_blocks: 4,
        ..ckpt_heavy_cfg()
    };
    let env = make_env_ext(64, 64, 1, cfg, 6, 4096);
    let (runs, crashed, _, _) = exhaustive(&env, 420..424, 50, 5, 2);
    eprintln!("ckpt-heavy wrap matrix: {runs} runs, {crashed} crashed");
}

/// Review 2026-11-03 #3: the newest root slot is lost (bit rot, a lost write), so the mount falls back to the older slot,
/// possibly one of the previous incarnation (`epoch < ` the units written since). Crash at every IO boundary x 3 policies,
/// flip a bit in the newest valid root slot of the crash image, mount: refused, or every acked txn recovered (model prefix,
/// data, allocator). Never a mount with acked txns gone. Returns (refused, recovered, refused by a newer-incarnation unit).
fn lost_newest_root_matrix(
    env: &Env,
    seeds: std::ops::Range<u64>,
    ntxn: u64,
    burst: u64,
) -> (u64, u64, u64) {
    let (mut refused, mut recovered, mut newer) = (0u64, 0u64, 0u64);
    for seed in seeds {
        let e = count_events(env, seed, ntxn, burst);
        for k in 0..=e {
            for (pi, pol) in POLICIES.iter().enumerate() {
                let mut h = Harness::new(env, seed);
                h.disk.arm_crash(h.disk.events() + k);
                h.run(ntxn, burst);
                h.disk.crash_now();
                let mut img = h.disk.crash_image(*pol);
                img.corrupt(newest_root_blk(&env.dir, &img), 12, 0x01);
                let disk = SimDisk::from_image(&img, env.sim.clone());
                match mount(env, &disk, &mut h.clk) {
                    Ok((shard, _)) => {
                        (h.disk, h.shard) = (disk, shard);
                        h.check_recovered().unwrap_or_else(|m| {
                            panic!("seed {seed} k {k} policy {pi}: lost root slot: {m}")
                        });
                        recovered += 1;
                    }
                    Err(StoreError::Corrupt(m)) => {
                        newer += m.contains("newest root slot is lost") as u64;
                        refused += 1;
                    }
                    Err(StoreError::WalLost { .. } | StoreError::NotFormatted) => refused += 1,
                    Err(e) => panic!("seed {seed} k {k} policy {pi}: mount error {e:?}"),
                }
            }
        }
    }
    (refused, recovered, newer)
}

#[test]
fn crash_matrix_lost_newest_root_slot() {
    for (name, env) in [
        ("default", make_env(64, 512, 1, ShardCfg::default())),
        ("ckpt-heavy", make_env(64, 256, 1, ckpt_heavy_cfg())),
    ] {
        let (refused, recovered, newer) = lost_newest_root_matrix(&env, 500..504, 40, 4);
        eprintln!(
            "lost-root matrix {name}: {refused} refused ({newer} by a newer-incarnation unit), {recovered} recovered"
        );
        assert!(newer > 0 && recovered > 0, "{name}: matrix vacuous");
    }
}

#[test]
fn checker_is_not_vacuous_for_tree_pages_lost_writes() {
    // checkpoint-heavy runs with silently lost writes (acked, never persisted): tree pages, bitmap, root slots,
    // WAL and data all get hit; the recovery checks (model prefix, fsck incl. crc/parent-crc/bitmap/extent
    // cross-checks) must flag the large majority
    let env = make_env(64, 256, 1, ckpt_heavy_cfg());
    let mut caught = 0;
    for seed in 0..40u64 {
        let mut h = Harness::new(&env, 900 + seed);
        h.disk.lose_writes(8);
        h.run(60, 4);
        if h.crash_and_remount(CrashPolicy::PERSIST_ALL, None).is_err() {
            caught += 1;
        }
    }
    assert!(caught >= 25, "only {caught}/40 lost-write runs flagged");
}

#[test]
fn checker_detects_bit_rot_in_checkpointed_pages() {
    let env = make_env(64, 256, 1, ckpt_heavy_cfg());
    let mut caught = 0;
    for seed in 0..20u64 {
        let mut h = Harness::new(&env, 950 + seed);
        assert!(h.run(80, 4));
        // wait for a checkpoint so a tree exists on disk
        h.shard.request_checkpoint();
        for _ in 0..20_000 {
            let mut b = 0;
            h.step(&mut b, 0);
            if h.shard.ckpt_lsn() == h.shard.next_lsn() - 1 && !h.shard.ckpt_active() {
                break;
            }
        }
        let geom = store::layout::MetaGeom::new(&env.dir, env.sb.node_size).unwrap();
        // flip a bit in the first live-looking tree page
        h.disk
            .corrupt(geom.pages_start, 500 + (seed as usize % 300), 0x01);
        h.disk.corrupt(geom.pages_start + geom.bpp, 700, 0x10);
        h.disk.corrupt(geom.pages_start + 2 * geom.bpp, 900, 0x20);
        for i in 3..48 {
            h.disk
                .corrupt(geom.pages_start + i * geom.bpp, 300 + 50 * i as usize, 0x40);
        }
        if h.crash_and_remount(CrashPolicy::PERSIST_ALL, None).is_err() {
            caught += 1;
        }
    }
    assert!(caught >= 15, "bit rot flagged in only {caught}/20 runs");
}

#[test]
fn crash_matrix_multi_part_txns() {
    // ADR 0028: 30% of the txns are 50-150 KV puts (> one 4-block unit: 4-11 parts). Crash at every IO boundary
    // (between any two parts, END torn/not landed, data extents of the txn missing) under all persistence
    // policies: all-or-nothing (state == model prefix), acked survive, no stale resurrection on later generations.
    use std::sync::atomic::Ordering::Relaxed;
    let mut env = make_env(
        64,
        512,
        1,
        ShardCfg {
            max_unit_blocks: 4,
            ..Default::default()
        },
    );
    env.big_pct = 30;
    let (s0, r0, d0) = (
        MULTI_SUBMITTED.load(Relaxed),
        MULTI_REPLAYED.load(Relaxed),
        MULTI_DROPPED.load(Relaxed),
    );
    let (runs, crashed, _, _) = exhaustive(&env, 600..604, 14, 3, 2);
    let (s, r, d) = (
        MULTI_SUBMITTED.load(Relaxed) - s0,
        MULTI_REPLAYED.load(Relaxed) - r0,
        MULTI_DROPPED.load(Relaxed) - d0,
    );
    eprintln!(
        "multi-part matrix: {runs} runs, {crashed} crashed; multi txns submitted {s}, replayed {r}, partial chains dropped {d}"
    );
    assert!(
        runs > 500 && s > 100 && r > 50,
        "multi-part path barely exercised"
    );
    assert!(d > 10, "partial chains never dropped at replay");
}

#[test]
fn crash_matrix_multi_part_ring_wrap_checkpoints() {
    // small ring (wrap + PAD inside chains), 3-block units, checkpoint-heavy, 8 KiB pages
    let mut env = make_env(
        64,
        192,
        1,
        ShardCfg {
            max_unit_blocks: 3,
            ..ckpt_heavy_cfg()
        },
    );
    env.big_pct = 25;
    let (runs, _, _, _) = exhaustive(&env, 610..613, 20, 3, 3);
    eprintln!("multi-part wrap/ckpt matrix: {runs} runs");
}

#[test]
fn crash_random_multi_part_long_runs() {
    let mut env = make_env(
        64,
        256,
        1,
        ShardCfg {
            max_unit_blocks: 4,
            ..Default::default()
        },
    );
    env.big_pct = 15;
    for seed in 0..200u64 {
        let pol = POLICIES[(seed % 3) as usize];
        one_run(&env, 7000 + seed, Some((seed * 31) % 900), pol, 100, 6, 4)
            .unwrap_or_else(|m| panic!("seed {seed}: {m}"));
    }
}

#[test]
fn crash_matrix_many_op_storm_txns() {
    // 35% of the txns are many-op KV storms (multi-range deletes with puts between, wide fills, wipes, remove_pg-like
    // prefix drops of 8-32 prefixes in one txn, 60-400 op bursts): every IO boundary x all persistence policies,
    // small pages so the tree is multi-level and ranges prune/empty interior nodes.
    let mut env = make_env_ext(
        64,
        512,
        1,
        ShardCfg {
            max_unit_blocks: 4,
            ..ckpt_heavy_cfg()
        },
        10,
        4096,
    );
    env.storm_pct = 35;
    let (runs, crashed, _, _) = exhaustive(&env, 700..705, 14, 3, 2);
    eprintln!("storm matrix: {runs} runs, {crashed} crashed");
    assert!(runs > 400 && crashed > 300);
}

#[test]
fn crash_matrix_many_op_storm_ring_wrap() {
    let mut env = make_env_ext(
        64,
        192,
        1,
        ShardCfg {
            max_unit_blocks: 3,
            ..ckpt_heavy_cfg()
        },
        10,
        4096,
    );
    env.storm_pct = 30;
    env.big_pct = 10;
    let (runs, _, _, _) = exhaustive(&env, 710..713, 16, 3, 3);
    eprintln!("storm wrap matrix: {runs} runs");
}

#[test]
fn crash_random_many_op_storm_long_runs() {
    let mut env = make_env_ext(
        64,
        256,
        1,
        ShardCfg {
            max_unit_blocks: 4,
            ..ckpt_heavy_cfg()
        },
        10,
        4096,
    );
    env.storm_pct = 30;
    env.big_pct = 8;
    for seed in 0..150u64 {
        let pol = POLICIES[(seed % 3) as usize];
        one_run(&env, 8000 + seed, Some((seed * 41) % 1200), pol, 100, 6, 4)
            .unwrap_or_else(|m| panic!("seed {seed}: {m}"));
    }
}

#[test]
#[ignore = "soak: storm crash matrices; run with --release --ignored"]
fn crash_storm_soak() {
    for (wal, unit, node, ring_seed) in [
        (512u64, 4u32, 4096u32, 0u64),
        (192, 3, 4096, 1),
        (256, 8, 8192, 2),
    ] {
        let mut env = make_env_ext(
            64,
            wal,
            1,
            ShardCfg {
                max_unit_blocks: unit,
                ..ckpt_heavy_cfg()
            },
            10,
            node,
        );
        env.storm_pct = 30 + ring_seed as u8 * 5;
        env.big_pct = 8;
        let (runs, _, _, _) =
            exhaustive(&env, 800 + ring_seed * 20..820 + ring_seed * 20, 24, 4, 3);
        eprintln!("storm soak wal {wal}: {runs} runs");
        for seed in 0..600u64 {
            let pol = POLICIES[(seed % 3) as usize];
            one_run(&env, 9000 + seed, Some((seed * 53) % 2000), pol, 150, 8, 5)
                .unwrap_or_else(|m| panic!("wal {wal} seed {seed}: {m}"));
        }
    }
}

#[test]
fn crash_matrix_wal_coalesce() {
    // group commit (adr 0021 am. 37): bursts behind a busy unit share one; every IO boundary x 3 policies, then more
    // generations (tail reuse), and a small wrapping ring (PADs, releases) with the same policy
    for k in [1usize, 2] {
        let env = make_env(
            64,
            512,
            1,
            ShardCfg {
                wal_coalesce: k,
                ..Default::default()
            },
        );
        // not vacuous: the same workload seals fewer units than without coalescing
        let units = |env: &Env| {
            let mut h = Harness::new(env, 400);
            assert!(h.run(24, 6));
            h.shard.stats.units
        };
        let off = make_env(
            64,
            512,
            1,
            ShardCfg {
                wal_coalesce: 0,
                ..Default::default()
            },
        );
        assert!(
            units(&env) < units(&off),
            "coalesce {k}: {} vs {} units",
            units(&env),
            units(&off)
        );
        let (runs, crashed, invalid, _) = exhaustive(&env, 400..416, 24, 6, 2);
        eprintln!("coalesce {k}: {runs} runs, {crashed} crashed, {invalid} cut by data crc");
        assert!(runs > 700 && crashed > 600 && invalid > 5);
    }
    let env = make_env(
        64,
        64,
        1,
        ShardCfg {
            max_unit_blocks: 4,
            wal_coalesce: 1,
            ..Default::default()
        },
    );
    let (runs, _, _, _) = exhaustive(&env, 410..413, 60, 8, 2);
    eprintln!("coalesce wrap matrix: {runs} runs");
}
