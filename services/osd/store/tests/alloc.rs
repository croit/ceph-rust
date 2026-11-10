// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Allocator (M2.3): ENOSPC -> forced checkpoint -> retry -> fail, hard reserve, held-until-checkpoint, reader
//! epochs, statfs accounting, meta-region exhaustion, no-leak / no-double-allocation under crash fuzz.
mod common;
use common::*;
use store::dev::{BlockDev, Clock, CrashPolicy, SimClock};
use store::fsck::fsck;
use store::shard::{Event, Shard, ShardCfg, Txn};
use store::state::Op;
use store::{BLK, StoreError};

type S = Shard<store::dev::SimDev>;

/// Allocate `n` blocks, write a pattern, install `key -> (blk,n,seed)`, free `old` (if any). Retries once on Busy
/// by pumping (the shard forces the checkpoint itself).
fn put_obj(
    r: &mut Rig,
    key: &str,
    n: u32,
    seed: u64,
    old: Option<(u64, u32)>,
) -> Result<(u64, u32), StoreError> {
    let mut busy = 0;
    let blk = loop {
        match r.shard.alloc(n) {
            Ok(b) => break b,
            Err(StoreError::Busy) => {
                busy += 1;
                assert!(
                    busy < 100_000,
                    "alloc stuck in Busy (no checkpoint forced?)"
                );
                r.pump();
            }
            Err(e) => return Err(e),
        }
    };
    let mut buf = r.shard.alloc_buf(n as usize);
    for i in 0..n {
        pattern(seed, i, &mut buf[i as usize * BLK..(i as usize + 1) * BLK]);
    }
    let mut t: Txn<Vec<u8>> = Txn::new(1);
    t.ops
        .push(Op::Put(key.as_bytes().to_vec(), enc_obj(blk, n, seed)));
    t.data.push((blk, buf));
    if let Some(o) = old {
        t.frees.push(o);
    }
    r.model
        .insert(key.as_bytes().to_vec(), enc_obj(blk, n, seed));
    let mut t = Some(t);
    for _ in 0..1_000_000 {
        match r.shard.submit(t.take().unwrap()) {
            Ok(_) => {
                r.submitted += 1;
                return Ok((blk, n));
            }
            Err((StoreError::Busy | StoreError::Miss | StoreError::WalFull, back)) => {
                t = Some(back);
                r.pump();
            }
            Err((e, _)) => panic!("submit {e:?}"),
        }
    }
    panic!("never admitted")
}

fn statfs_sums(s: &S) {
    let f = s.statfs();
    assert_eq!(
        f.data_used + f.data_free + f.data_held + f.data_reserved,
        f.data_blocks,
        "statfs does not add up: {f:?}"
    );
}

fn env_small(meta_pct: u32) -> Env {
    // 8 MiB device: ~1700 data blocks
    make_env_ext(8, 128, 1, ShardCfg::default(), meta_pct, 4096)
}

#[test]
fn overflowing_record_ranges_are_rejected() {
    let env = env_small(10);
    let mut r = Rig::new(&env, 1);
    for rec in [
        store::state::Record {
            frees: vec![(u64::MAX, u32::MAX)],
            ..Default::default()
        },
        store::state::Record {
            data: vec![store::state::Extent {
                blk: u64::MAX,
                nblk: 102,
                crcs: vec![0; 102],
            }],
            ..Default::default()
        },
    ] {
        assert_eq!(
            r.shard.state_mut().check(&rec),
            Err(StoreError::Invalid("block range outside data region"))
        );
    }
}

#[test]
fn enospc_forces_checkpoint_retries_then_fails() {
    let env = env_small(10);
    let mut r = Rig::new(&env, 1);
    let total = r.shard.statfs().data_blocks;
    let live_target = total / 2;
    // phase 1: rewrite a working set of ~50% fill over and over: every rewrite frees the old extent, which stays
    // held until a checkpoint passes it -> alloc hits Busy -> shard forces a checkpoint -> retry succeeds
    let nobj = 20u64;
    let per = (live_target / nobj) as u32;
    let mut cur: Vec<Option<(u64, u32)>> = vec![None; nobj as usize];
    let mut rng = store::rng::Rng::new(9);
    for round in 0..400u64 {
        let i = (round % nobj) as usize;
        let key = format!("obj/{i:02}");
        let n = per.min(60);
        let new = put_obj(&mut r, &key, n, rng.next_u64(), cur[i]).expect("no ENOSPC at 50% fill");
        cur[i] = Some(new);
        statfs_sums(&r.shard);
    }
    r.sync();
    let f = r.shard.statfs();
    assert!(
        r.shard.stats.forced_ckpts > 0,
        "no checkpoint was ever forced by allocation pressure"
    );
    assert!(r.shard.stats.checkpoints > 0);
    eprintln!("phase 1: {:?} {:?}", r.shard.stats, f);
    // phase 2: only grow (no frees) until the device is really full
    let mut grown = 0;
    let err = loop {
        let key = format!("obj/g{grown:04}");
        match put_obj(&mut r, &key, 16, grown as u64, None) {
            Ok(_) => grown += 1,
            Err(e) => break e,
        }
        assert!(grown < 10_000);
    };
    assert_eq!(
        err,
        StoreError::NoSpace,
        "full device must fail with NoSpace after the forced checkpoint"
    );
    // what is left above the floor are runs shorter than 16 blocks (their number depends on the layout, e.g. on runs a
    // deallocate held while phase 1 allocated): single blocks fill them, down to the floor
    loop {
        let key = format!("obj/g{grown:04}");
        match put_obj(&mut r, &key, 1, grown as u64, None) {
            Ok(_) => grown += 1,
            Err(e) => {
                assert_eq!(e, StoreError::NoSpace, "single blocks");
                break;
            }
        }
        assert!(grown < 10_000);
    }
    r.sync();
    let f = r.shard.statfs();
    assert_eq!(f.data_held, 0, "NoSpace only when nothing is pending");
    assert!(!r.shard.ckpt_active());
    // reserve respected: user allocations stop exactly at the hard reserve
    let reserve = total * 3 / 100; // user floor = 1.5 x data_reserve_pct (am. 21)
    assert_eq!(
        f.data_free, reserve,
        "free {} reserve {reserve}",
        f.data_free
    );
    statfs_sums(&r.shard);
    // alloc_priv may dip into the reserve (txns that free space)
    let b = r
        .shard
        .alloc_priv(4)
        .expect("reserve available to privileged alloc");
    r.shard.unreserve(b, 4);
    // freeing (delete objects) makes room again, after a checkpoint
    let mut freed = 0u64;
    for (k, v) in r.model.clone() {
        if k.starts_with(b"obj/g") {
            let (b, n, _) = dec_obj(&v);
            let mut t: Txn<Vec<u8>> = Txn::new(1);
            t.ops.push(Op::Del(k.clone()));
            t.frees.push((b, n));
            r.model.remove(&k);
            loop {
                match r.shard.submit(t) {
                    Ok(_) => break,
                    Err((_, back)) => {
                        t = back;
                        r.pump();
                    }
                }
            }
            r.submitted += 1;
            freed += n as u64;
            if freed >= 160 {
                break;
            }
        }
    }
    // immediately after the deletes the space is still held: Busy (checkpoint forced), then it works
    assert!(matches!(r.shard.alloc(16), Err(StoreError::Busy)));
    let blk = loop {
        match r.shard.alloc(16) {
            Ok(b) => break b,
            Err(StoreError::Busy) => r.pump(),
            Err(e) => panic!("{e:?}"),
        }
    };
    r.shard.unreserve(blk, 16);
    // everything survives a clean remount; fsck cross-checks the bitmap against the referenced extents
    r.checkpoint();
    let img = r.disk.image();
    fsck(
        &mut store::dev::SimDisk::from_image(&img, env.sim.clone()).queue(),
        &mut SimClock::default(),
        Some(&obj_refs),
    )
    .unwrap();
}

#[test]
fn freed_blocks_wait_for_readers_of_older_epochs() {
    let env = env_small(10);
    let mut r = Rig::new(&env, 2);
    let total = r.shard.statfs().data_blocks;
    let a = put_obj(&mut r, "obj/00", 8, 1, None).unwrap();
    r.sync();
    // a reader starts before the free
    let ep = r.shard.read_pin();
    let mut t: Txn<Vec<u8>> = Txn::new(1);
    t.ops.push(Op::Del(b"obj/00".to_vec()));
    t.frees.push(a);
    r.shard.submit(t).unwrap();
    r.submitted += 1;
    r.checkpoint();
    // checkpoint passed the free, but the old reader still pins the blocks
    assert_eq!(r.shard.statfs().data_held, 8);
    let mut got = vec![];
    while let Ok(b) = r.shard.alloc(1) {
        got.push(b);
    }
    assert!(got.len() as u64 <= total - 8);
    assert!(
        got.iter().all(|b| !(a.0..a.0 + 8).contains(b)),
        "block reused under an in-flight reader"
    );
    got.iter().for_each(|&b| r.shard.unreserve(b, 1));
    // reader done -> reusable
    r.shard.read_unpin(ep);
    assert_eq!(r.shard.statfs().data_held, 0);
    assert!(r.shard.alloc(8).is_ok());
    // a reader that starts AFTER the checkpoint never blocks anything
    statfs_sums(&r.shard);
}

#[test]
fn submit_read_pins_blocks_until_completion() {
    let env = env_small(10);
    let mut r = Rig::new(&env, 3);
    let a = put_obj(&mut r, "obj/00", 4, 5, None).unwrap();
    r.sync();
    r.shard.submit_read(a.0, 4, 77, false).unwrap();
    let mut t: Txn<Vec<u8>> = Txn::new(1);
    t.ops.push(Op::Del(b"obj/00".to_vec()));
    t.frees.push(a);
    r.shard.submit(t).unwrap();
    r.submitted += 1;
    // do not poll: the read stays in flight while the checkpoint is requested; drive manually to see order
    let mut ev = Vec::new();
    let mut done_read = false;
    r.shard.request_checkpoint();
    for _ in 0..100_000 {
        ev.clear();
        r.shard.poll(r.clk.t, &mut ev);
        for e in &ev {
            match e {
                Event::Read { token: 77, result } => {
                    assert!(result.is_ok());
                    done_read = true;
                }
                Event::Acked(_) => r.acked += 1,
                _ => {}
            }
        }
        if done_read {
            break;
        }
        let h = r.shard.dev().next_deadline();
        r.clk.idle(h);
    }
    assert!(done_read);
    r.checkpoint();
    assert_eq!(r.shard.statfs().data_held, 0);
}

#[test]
fn meta_exhaustion_is_reported_not_fatal_and_recovers() {
    // ~24 tree pages: fill with keys until the engine refuses, then free and continue
    let env = make_env_ext(16, 128, 1, ShardCfg::default(), 1, 4096);
    let mut r = Rig::new(&env, 4);
    let mut n = 0u64;
    let mut stopped = None;
    for i in 0..100_000u64 {
        let mut t: Txn<Vec<u8>> = Txn::new(1);
        t.put(format!("k/{i:08}").as_bytes(), &[7u8; 200]);
        let mut t = Some(t);
        let mut spins = 0;
        loop {
            match r.shard.submit(t.take().unwrap()) {
                Ok(_) => {
                    r.submitted += 1;
                    r.model
                        .insert(format!("k/{i:08}").into_bytes(), vec![7u8; 200]);
                    n += 1;
                    break;
                }
                Err((StoreError::Busy | StoreError::Miss | StoreError::WalFull, back)) => {
                    t = Some(back);
                    r.pump();
                    spins += 1;
                    assert!(spins < 100_000, "stuck");
                }
                Err((StoreError::NoSpace, _)) => {
                    stopped = Some(i);
                    break;
                }
                Err((e, _)) => panic!("{e:?}"),
            }
        }
        if stopped.is_some() {
            break;
        }
    }
    let stopped = stopped.expect("tree never ran out of meta space");
    assert!(n > 100 && !r.shard.is_failed());
    eprintln!(
        "meta ENOSPC after {n} keys at i={stopped}: {:?}",
        r.shard.statfs()
    );
    // everything admitted is durable and consistent; deleting frees pages, writes work again
    r.verify();
    r.remount_clean();
    r.verify();
    r.delrange(b"k/", b"k0");
    r.checkpoint();
    r.checkpoint();
    assert!(r.shard.statfs().meta_used <= 4, "{:?}", r.shard.statfs());
    for i in 0..50u64 {
        r.put(format!("again/{i}").as_bytes(), b"ok");
    }
    r.remount_clean();
    r.verify();
}

#[test]
fn statfs_tracks_everything() {
    let env = env_small(10);
    let mut r = Rig::new(&env, 5);
    let f0 = r.shard.statfs();
    assert_eq!(
        (f0.data_used, f0.data_held, f0.data_reserved, f0.meta_used),
        (0, 0, 0, 0)
    );
    let b = r.shard.alloc(10).unwrap();
    assert_eq!(r.shard.statfs().data_reserved, 10);
    statfs_sums(&r.shard);
    r.shard.unreserve(b, 10);
    let a = put_obj(&mut r, "obj/00", 10, 1, None).unwrap();
    r.sync();
    let f = r.shard.statfs();
    assert_eq!((f.data_used, f.data_reserved), (10, 0));
    assert!(f.dirty_pages > 0 && f.cached_pages > 0);
    r.checkpoint();
    let f = r.shard.statfs();
    assert_eq!(f.dirty_pages, 0);
    assert!(f.meta_used >= 1 && f.ckpt_lsn == f.durable_lsn);
    // replace: old extent held until the next checkpoint
    let _ = put_obj(&mut r, "obj/00", 10, 2, Some(a)).unwrap();
    r.sync();
    let f = r.shard.statfs();
    assert_eq!((f.data_used, f.data_held), (10, 10));
    statfs_sums(&r.shard);
    r.checkpoint();
    let f = r.shard.statfs();
    assert_eq!((f.data_used, f.data_held), (10, 0));
    // statfs survives a remount (counters come from the persisted bitmap)
    r.remount_clean();
    assert_eq!(r.shard.statfs().data_used, 10);
    statfs_sums(&r.shard);
}

#[test]
fn crash_fuzz_under_space_pressure_no_leak_no_double_allocation() {
    // 6 MiB device, 70 objects of 1-60 blocks rewritten at random: constant ENOSPC/Busy/forced checkpoints,
    // frees, reuse. After every crash: model prefix, allocator == referenced extents (fsck cross-check on the
    // crash image and after mount), data intact.
    let mut env = make_env_ext(
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
    env.nobj = 70;
    env.obj_scale = 6;
    let policies = [
        CrashPolicy::DROP_ALL,
        CrashPolicy::PERSIST_ALL,
        CrashPolicy::MIXED,
    ];
    let (mut enospc, mut runs) = (0, 0);
    for seed in 0..60u64 {
        let mut h = Harness::new(&env, 7000 + seed);
        h.disk.arm_crash(h.disk.events() + (seed * 97) % 1500);
        h.run(400, 6);
        enospc += h.enospc;
        h.crash_and_remount(policies[(seed % 3) as usize], None)
            .unwrap_or_else(|e| panic!("seed {seed}: {e}"));
        // keep going on the recovered shard, crash again
        h.disk.arm_crash(h.disk.events() + 300 + seed);
        h.run(300, 6);
        enospc += h.enospc;
        h.crash_and_remount(policies[((seed + 1) % 3) as usize], None)
            .unwrap_or_else(|e| panic!("seed {seed} gen2: {e}"));
        runs += 1;
    }
    eprintln!("space-pressure fuzz: {runs} runs, {enospc} allocation failures observed");
    assert!(enospc > 50, "workload never hit space pressure");
}

#[test]
fn crash_during_checkpoint_never_loses_or_double_frees_blocks() {
    // continuous checkpoints + rewrites: crash at every IO boundary of a short run; fsck(refs) on each image
    let cfg = ShardCfg {
        dirty_soft_pages: 1,
        ckpt_interval_ns: 10_000,
        ..Default::default()
    };
    let mut env = make_env_ext(4, 64, 1, cfg, 10, 4096);
    env.nobj = 40;
    env.obj_scale = 4;
    let mut runs = 0;
    for seed in 0..3u64 {
        let k_max = count_events(&env, 100 + seed, 40, 3);
        for k in (0..=k_max).step_by(1) {
            one_run(&env, 100 + seed, Some(k), CrashPolicy::MIXED, 40, 3, 1)
                .unwrap_or_else(|e| panic!("seed {seed} k {k}: {e}"));
            runs += 1;
        }
    }
    eprintln!("checkpoint crash points: {runs}");
}
