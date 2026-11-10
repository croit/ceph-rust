// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Multi-part (multi-unit) atomic txns (ADR 0028): targeted fates per WAL unit, ack rule, admission.
//! The randomized crash matrix lives in crash.rs (`crash_matrix_multi_part_*`).
mod common;
use common::*;

use store::BLK;
use store::StoreError;
use store::dev::{BlockDev, Clock, CrashPolicy, Persist, SimClock, SimDev, SimDisk};
use store::shard::{Event, Shard, ShardCfg, Txn};
use store::state::Op;

type Sh = Shard<SimDev>;

/// Small units; eager seal (`wal_coalesce` 0): the scenarios need every unit of A, B, C in flight at once.
fn cfg4() -> ShardCfg {
    ShardCfg {
        max_unit_blocks: 4,
        wal_coalesce: 0,
        ..Default::default()
    }
}

fn fresh(env: &Env, seed: u64) -> (SimDisk, SimClock, Sh) {
    let mut cfg = env.sim.clone();
    cfg.seed = seed;
    let disk = SimDisk::from_image(&env.img, cfg);
    let mut clk = SimClock::default();
    let (s, _) = mount(env, &disk, &mut clk).unwrap();
    (disk, clk, s)
}

fn remount(
    env: &Env,
    img: &store::dev::SimImage,
    seed: u64,
) -> (SimDisk, SimClock, Sh, store::wal::ReplayStats) {
    let mut cfg = env.sim.clone();
    cfg.seed = seed;
    let disk = SimDisk::from_image(img, cfg);
    let mut clk = SimClock::default();
    let (s, st) = mount(env, &disk, &mut clk).unwrap();
    (disk, clk, s, st)
}

fn kv(token: u64, k: &str, v: &str) -> Txn<Vec<u8>> {
    let mut t = Txn::new(token);
    t.ops
        .push(Op::Put(k.as_bytes().to_vec(), v.as_bytes().to_vec()));
    t
}

/// `n` puts `big/NNNN` of `len` bytes.
fn big(token: u64, n: usize, len: usize) -> Txn<Vec<u8>> {
    let mut t = Txn::new(token);
    for i in 0..n {
        t.ops.push(Op::Put(
            format!("big/{i:04}").into_bytes(),
            vec![(i % 251) as u8; len],
        ));
    }
    t
}

fn transfer_limited_env(lba_size: u32, max_unit_blocks: u32) -> Env {
    let mut env = make_env(
        32,
        1024,
        1,
        ShardCfg {
            max_unit_blocks,
            wal_coalesce: 0,
            ..Default::default()
        },
    );
    env.sim.lba_size = lba_size;
    env.sim.lba_count = (32 << 20) / u64::from(lba_size);
    env.sim.max_xfer_lbas = (128 << 10) / lba_size;
    let disk = SimDisk::new(env.sim.clone());
    let (sb, dirs) = store::layout::mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &store::layout::MkfsParams {
            shards: 1,
            wal_blocks: 1024,
            align_blocks: 1,
            meta_pct: 6,
            ..Default::default()
        },
    )
    .unwrap();
    env.img = disk.image();
    env.sb = sb;
    env.dir = dirs[0].clone();
    env
}

#[test]
fn wal_units_respect_device_transfer_limit_and_smaller_configuration() {
    for lba_size in [512, 4096] {
        for configured in [64, 4] {
            let env = transfer_limited_env(lba_size, configured);
            let (disk, mut clk, mut s) = fresh(&env, 131);
            // A ~200 KiB metadata record fits the object-store's 256 KiB default,
            // but not this device's 128 KiB transfer limit. It must remain atomic.
            s.submit(big(1, 200, 1000)).unwrap();
            let mut events = Vec::new();
            s.poll(clk.t, &mut events);
            assert!(
                !events.iter().any(|e| matches!(e, Event::Failed(_))),
                "device limit rejection: {events:?}"
            );
            let units = wal_writes(&disk, &env);
            assert!(units.len() >= 2, "large record must be chained: {units:?}");
            let max_lbas = configured.min(32) * BLK as u32 / lba_size;
            assert!(units.iter().all(|&(_, n)| n <= max_lbas), "{units:?}");
            assert_eq!(acks(&mut s, &mut clk, 1), vec![1]);
            assert_eq!(s.stats.multi_txns, 1);
            let img = disk.crash_image(CrashPolicy::DROP_ALL);
            let (_, mut c2, mut s2, _) = remount(&env, &img, 132);
            let actual = dump(&mut s2, &mut c2);
            assert_eq!(has_b(&actual), 200);
            for i in 0..200 {
                assert_eq!(
                    actual[format!("big/{i:04}").as_bytes()],
                    vec![i as u8; 1000]
                );
            }
        }
    }
}

#[test]
fn transfer_limited_wal_chain_torn_at_each_part_never_partially_replays() {
    let env = transfer_limited_env(512, 64);
    let (disk, clk, mut s) = fresh(&env, 141);
    let mut txn = big(1, 200, 1000);
    for op in &mut txn.ops {
        if let Op::Put(_, value) = op {
            value.fill(0xa5);
        }
    }
    s.submit(txn).unwrap();
    s.poll(clk.t, &mut Vec::new());
    let units = wal_writes(&disk, &env);
    assert_eq!(units.len(), 2, "expected two device-sized parts: {units:?}");
    for &(victim, length) in &units {
        for fate in 0..3 {
            let img = disk.crash_image_with(|io, _| {
                if io.lba != victim {
                    return Persist::Full;
                }
                match fate {
                    0 => Persist::Drop,
                    1 => {
                        let mut sectors = vec![false; length as usize];
                        sectors[0] = true;
                        Persist::Tear(sectors)
                    }
                    _ => {
                        let mut sectors = vec![true; length as usize];
                        // Lose actual nonzero payload, not trailing 4 KiB-unit
                        // padding that may already contain the correct zeroes.
                        sectors[length as usize / 2] = false;
                        Persist::Tear(sectors)
                    }
                }
            });
            let (_, mut c2, mut s2, _) = remount(&env, &img, 142);
            assert_eq!(s2.durable_lsn(), 0);
            assert_eq!(has_b(&dump(&mut s2, &mut c2)), 0);
        }
    }
}

#[test]
fn invalid_wal_unit_or_sub_block_transfer_limit_is_refused_at_mount() {
    let env = transfer_limited_env(512, 64);
    let mut sim = env.sim.clone();
    sim.max_xfer_lbas = 7; // Cannot transfer even one 4096-byte store block.
    let disk = SimDisk::from_image(&env.img, sim);
    assert!(matches!(
        Shard::mount(
            disk.queue(),
            &mut SimClock::default(),
            &env.sb,
            &env.dir,
            env.scfg.clone(),
            false,
        ),
        Err(StoreError::BadGeometry(_))
    ));
    let disk = SimDisk::from_image(&env.img, env.sim.clone());
    let mut cfg = env.scfg.clone();
    cfg.max_unit_blocks = 0;
    assert!(matches!(
        Shard::mount(
            disk.queue(),
            &mut SimClock::default(),
            &env.sb,
            &env.dir,
            cfg,
            false,
        ),
        Err(StoreError::Invalid(_))
    ));
}

fn acks(s: &mut Sh, clk: &mut SimClock, n: usize) -> Vec<u64> {
    let mut got = Vec::new();
    for _ in 0..200_000 {
        let mut ev = Vec::new();
        s.poll(clk.t, &mut ev);
        for e in ev {
            if let Event::Acked(t) = e {
                got.push(t);
            }
        }
        if got.len() >= n {
            break;
        }
        let h = s.dev().next_deadline();
        clk.idle(h);
    }
    got
}

fn poll_once(s: &mut Sh, clk: &SimClock) -> Vec<u64> {
    let mut ev = Vec::new();
    s.poll(clk.t, &mut ev);
    ev.into_iter()
        .filter_map(|e| {
            if let Event::Acked(t) = e {
                Some(t)
            } else {
                None
            }
        })
        .collect()
}

fn submit_retry(s: &mut Sh, clk: &mut SimClock, acked: &mut Vec<u64>, mut t: Txn<Vec<u8>>) -> u64 {
    for _ in 0..200_000 {
        match s.submit(t) {
            Ok(l) => return l,
            Err((StoreError::Busy | StoreError::WalFull, x)) => {
                t = x;
                acked.extend(poll_once(s, clk));
                let h = s.dev().next_deadline();
                clk.idle(h);
            }
            Err((e, _)) => panic!("submit: {e:?}"),
        }
    }
    panic!("submit livelock");
}

/// A (lsn 1, small) + B (lsn 2, multi-part with a data extent) + C (lsn 3, small), all in flight at once.
/// Returns the disk plus the WAL unit layout `(lba, nlba)` of the in-flight WAL writes in submit order.
fn scenario(env: &Env, seed: u64) -> (SimDisk, SimClock, Sh, u64) {
    let (disk, clk, mut s) = fresh(env, seed);
    s.submit(kv(1, "a", "1")).unwrap();
    poll_once(&mut s, &clk);
    let blk = s.alloc(2).unwrap();
    let mut buf = s.alloc_buf(2);
    pattern(5, 0, &mut buf[..BLK]);
    pattern(5, 1, &mut buf[BLK..]);
    let mut b = big(2, 40, 1500);
    b.data.push((blk, buf));
    s.submit(b).unwrap();
    poll_once(&mut s, &clk);
    s.submit(kv(3, "c", "3")).unwrap();
    poll_once(&mut s, &clk);
    assert!(
        s.stats.multi_txns == 1 && s.stats.multi_parts >= 4,
        "{:?}",
        s.stats
    );
    (disk, clk, s, blk)
}

fn has_b(kv: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>) -> usize {
    kv.keys().filter(|k| k.starts_with(b"big/")).count()
}

#[test]
fn multi_part_roundtrip_acks_and_replays() {
    let env = make_env(16, 256, 1, cfg4());
    let (disk, mut clk, mut s, _) = scenario(&env, 1);
    assert_eq!(
        acks(&mut s, &mut clk, 3),
        vec![1, 2, 3],
        "acks in lsn order, one per txn"
    );
    assert_eq!(s.durable_lsn(), 3);
    let img = disk.crash_image(CrashPolicy::DROP_ALL);
    let (_d, mut c2, mut s2, st) = remount(&env, &img, 2);
    assert_eq!(s2.state().lsn, 3);
    assert_eq!(st.multi_txns, 1);
    let kvs = dump(&mut s2, &mut c2);
    assert_eq!(has_b(&kvs), 40);
    assert_eq!(kvs[b"big/0007".as_slice()], vec![7u8; 1500]);
}

#[test]
fn ack_only_after_all_parts_and_end_durable() {
    // stop at the first moment txn 2 is acked and power-fail with every unacked in-flight write lost: txn 2
    // (all of its parts, END and data) must be there
    for seed in 0..20u64 {
        let mut env = make_env(16, 256, 1, cfg4());
        env.sim.jitter_ns = 40_000;
        let (disk, mut clk, mut s, _) = scenario(&env, 100 + seed);
        let mut got = Vec::new();
        for _ in 0..100_000 {
            got.extend(poll_once(&mut s, &clk));
            if got.contains(&2) {
                break;
            }
            let h = s.dev().next_deadline();
            clk.idle(h);
        }
        assert!(got.contains(&2));
        let img = disk.crash_image(CrashPolicy::DROP_ALL);
        let (_d, mut c2, mut s2, _) = remount(&env, &img, 7);
        assert!(
            s2.state().lsn >= 2,
            "seed {seed}: acked multi-part txn lost"
        );
        assert_eq!(has_b(&dump(&mut s2, &mut c2)), 40);
    }
}

/// WAL writes in flight (lba, nlba) sorted by lba.
fn wal_writes(disk: &SimDisk, env: &Env) -> Vec<(u64, u32)> {
    let mut v = Vec::new();
    let w0 = env.dir.wal_start * (BLK as u64 / env.sim.lba_size as u64);
    let w1 = (env.dir.wal_start + env.dir.wal_blocks) * (BLK as u64 / env.sim.lba_size as u64);
    disk.crash_image_with(|f, _| {
        if f.lba >= w0 && f.lba < w1 {
            v.push((f.lba, f.nlba));
        }
        Persist::Drop
    });
    v.sort();
    v
}

#[test]
fn every_part_fate_all_or_nothing_and_no_resurrection() {
    let env = make_env(16, 256, 1, cfg4());
    let (disk0, _c, _s, _) = scenario(&env, 3);
    let units = wal_writes(&disk0, &env);
    // A, >= 4 parts of B, C
    assert!(units.len() >= 6, "{units:?}");
    let lpb = BLK as u64 / env.sim.lba_size as u64;
    for victim in 1..units.len() - 1 {
        for how in 0..3 {
            let (disk, _c, s, blk) = scenario(&env, 3);
            drop(s);
            let (vl, vn) = units[victim];
            let is_b_unit = victim < units.len() - 1;
            assert!(is_b_unit);
            let img = disk.crash_image_with(|f, _| {
                if f.lba == vl {
                    match how {
                        0 => Persist::Drop,
                        1 => {
                            // torn: first LBA of the unit lands, the rest does not
                            let mut m = vec![false; vn as usize];
                            m[0] = true;
                            Persist::Tear(m)
                        }
                        _ => {
                            let mut m = vec![true; vn as usize];
                            m[vn as usize - 1] = false;
                            Persist::Tear(m)
                        }
                    }
                } else {
                    Persist::Full
                }
            });
            let _ = (blk, lpb);
            let (d2, mut c2, mut s2, st) = remount(&env, &img, 9);
            let kvs = dump(&mut s2, &mut c2);
            assert_eq!(
                s2.state().lsn,
                1,
                "victim {victim} how {how}: log must end before the broken chain"
            );
            assert_eq!(
                has_b(&kvs),
                0,
                "partial multi-part txn visible (victim {victim} how {how})"
            );
            assert!(
                !kvs.contains_key(b"c".as_slice()),
                "C is behind the broken chain"
            );
            assert_eq!(st.multi_txns, 0);
            // a later incarnation reuses the ring there; the old parts / C must never come back
            s2.submit(kv(10, "gen2", "x")).unwrap();
            assert_eq!(acks(&mut s2, &mut c2, 1), vec![10]);
            let img2 = d2.crash_image(CrashPolicy::PERSIST_ALL);
            let (_d3, mut c3, mut s3, _) = remount(&env, &img2, 10);
            let kvs = dump(&mut s3, &mut c3);
            assert_eq!(has_b(&kvs), 0);
            assert!(!kvs.contains_key(b"c".as_slice()));
            assert!(kvs.contains_key(b"gen2".as_slice()));
        }
    }
}

#[test]
fn all_parts_landed_but_data_extent_missing_drops_the_txn() {
    let env = make_env(16, 256, 1, cfg4());
    let (disk, _c, _s, blk) = scenario(&env, 4);
    let lpb = BLK as u64 / env.sim.lba_size as u64;
    let img = disk.crash_image_with(|f, _| {
        if f.lba == blk * lpb {
            Persist::Drop
        } else {
            Persist::Full
        }
    });
    let (_d, mut c2, mut s2, st) = remount(&env, &img, 11);
    assert_eq!(s2.state().lsn, 1);
    assert_eq!(has_b(&dump(&mut s2, &mut c2)), 0);
    assert_eq!(st.data_invalid_units, 1);
}

#[test]
fn chain_without_end_and_complete_chain_with_everything_landed() {
    let env = make_env(16, 256, 1, cfg4());
    let (disk, _c, _s, _) = scenario(&env, 5);
    let units = wal_writes(&disk, &env);
    // drop only the last part of B (the END unit = highest lba of B = second last unit)
    let end_lba = units[units.len() - 2].0;
    let img = disk.crash_image_with(|f, _| {
        if f.lba == end_lba {
            Persist::Drop
        } else {
            Persist::Full
        }
    });
    let (_d, mut c2, mut s2, st) = remount(&env, &img, 12);
    assert_eq!(s2.state().lsn, 1);
    assert_eq!(has_b(&dump(&mut s2, &mut c2)), 0);
    assert_eq!(st.multi_dropped, 1);
    // everything landed (a crash after the writes, before the acks): applied completely
    let img = disk.crash_image(CrashPolicy::PERSIST_ALL);
    let (_d, mut c3, mut s3, st) = remount(&env, &img, 13);
    assert_eq!(s3.state().lsn, 3);
    assert_eq!(has_b(&dump(&mut s3, &mut c3)), 40);
    assert_eq!(st.multi_dropped, 0);
}

#[test]
fn mixed_big_and_small_txns_stay_in_lsn_order_across_many_units() {
    let env = make_env(64, 1024, 1, cfg4());
    let (disk, mut clk, mut s) = fresh(&env, 6);
    let mut expect = Vec::new();
    let mut got = Vec::new();
    let mut tok = 0;
    for round in 0..30u64 {
        for i in 0..5 {
            tok += 1;
            submit_retry(
                &mut s,
                &mut clk,
                &mut got,
                kv(tok, &format!("s/{round:03}/{i}"), "v"),
            );
            expect.push(tok);
        }
        tok += 1;
        let mut t = Txn::new(tok);
        for i in 0..(30 + round as usize * 3) {
            t.ops.push(Op::Put(
                format!("m/{round:03}/{i:03}").into_bytes(),
                vec![round as u8; 300],
            ));
        }
        submit_retry(&mut s, &mut clk, &mut got, t);
        expect.push(tok);
    }
    got.extend(acks(&mut s, &mut clk, expect.len() - got.len()));
    assert_eq!(got, expect);
    let nmulti = s.stats.multi_txns;
    assert!((15..30).contains(&nmulti), "{nmulti}");
    let img = disk.crash_image(CrashPolicy::DROP_ALL);
    let (_d, mut c2, mut s2, st) = remount(&env, &img, 14);
    assert_eq!(st.multi_txns, nmulti);
    assert_eq!(
        dump(&mut s2, &mut c2).len(),
        150 + (0..30).map(|r| 30 + r * 3).sum::<usize>()
    );
}

#[test]
fn chain_waits_for_ring_space_and_checkpoint_never_deadlocks() {
    // 128-block ring, 4-block units: a ~40-block chain needs 40 + 8 free blocks; the ring is first filled with
    // unreleased units, the chain must be admitted after a forced checkpoint
    let env = make_env(
        64,
        128,
        1,
        ShardCfg {
            ckpt_wal_pct: 100,
            ..cfg4()
        },
    );
    let (disk, mut clk, mut s) = fresh(&env, 7);
    let mut got = Vec::new();
    let mut tok = 0;
    for i in 0..400 {
        tok += 1;
        let mut t = Txn::new(tok);
        t.ops
            .push(Op::Put(format!("q/{i:04}").into_bytes(), vec![1; 1800]));
        submit_retry(&mut s, &mut clk, &mut got, t);
    }
    tok += 1;
    let big_tok = tok;
    submit_retry(&mut s, &mut clk, &mut got, big(big_tok, 100, 1500));
    got.extend(acks(&mut s, &mut clk, tok as usize - got.len()));
    assert_eq!(*got.last().unwrap(), big_tok);
    assert!(s.stats.forced_ckpts > 0 || s.stats.checkpoints > 0);
    let img = disk.crash_image(CrashPolicy::DROP_ALL);
    let (_d, mut c2, mut s2, _) = remount(&env, &img, 15);
    let kvs = dump(&mut s2, &mut c2);
    assert_eq!(has_b(&kvs), 100);
    assert_eq!(kvs.keys().filter(|k| k.starts_with(b"q/")).count(), 400);
}

#[test]
fn chain_larger_than_half_the_ring_is_too_large() {
    let env = make_env(64, 128, 1, cfg4());
    let (_d, _c, mut s) = fresh(&env, 8);
    // ~300 KB = ~75 blocks > 128/2 - 8
    let r = s.submit(big(1, 200, 1500));
    assert!(matches!(r, Err((StoreError::TxnTooLarge, _))));
    assert_eq!(s.next_lsn(), 1);
}

#[test]
fn big_txn_does_not_hit_spurious_nospace_on_small_meta_region() {
    // 8000 sequential keys: the old 5 pages/key estimate (40000 pages) exceeded the whole meta region
    let env = make_env_ext(
        64,
        2048,
        1,
        ShardCfg {
            max_unit_blocks: 64,
            ..Default::default()
        },
        6,
        8192,
    );
    let (disk, mut clk, mut s) = fresh(&env, 9);
    let free0 = s.statfs().meta_free;
    let mut t = Txn::new(1);
    for i in 0..8000u32 {
        t.ops.push(Op::Put(
            format!("log/{i:08}").into_bytes(),
            vec![i as u8; 40],
        ));
    }
    s.submit(t)
        .unwrap_or_else(|(e, _)| panic!("{e:?} (meta free {free0})"));
    assert_eq!(acks(&mut s, &mut clk, 1), vec![1]);
    let img = disk.crash_image(CrashPolicy::DROP_ALL);
    let (_d, mut c2, mut s2, _) = remount(&env, &img, 16);
    assert_eq!(dump(&mut s2, &mut c2).len(), 8000);
}
