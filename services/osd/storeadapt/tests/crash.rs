// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Crash matrix at the PG level: random PG transactions (log + info + object ops, PG removal) are submitted
//! through the adapter with a device crash at every IO boundary; after remount the PG state must equal the
//! MemStore state after all acked transactions (or one more: the one in flight may have landed), and fsck
//! must be clean.
#![expect(clippy::too_many_arguments)]
mod common;
use common::*;
use denc::types::*;
use peering::store::{MemStore, PgStoreOps, Queued, StoreOp, StoreTxn};
use pgwire::{LogEntry, LogOp, MissingItem, PgLog};
use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use store::dev::{CrashPolicy, SimClock, SimDisk};
use store::fsck::fsck;
use store::obj::{StoreCfg, onode::fsck_refs};
use store::rng::Rng;
use store::shard::ShardCfg;

fn workload(seed: u64, n: usize) -> (SpgT, Vec<StoreTxn>) {
    let s = spg(1, 0);
    let mut g = PgGen::new(s, seed);
    let mut exist = BTreeSet::new();
    let mut r = Rng::new(seed ^ 9);
    let mut v = Vec::new();
    for _ in 0..n {
        let mut t = StoreTxn::default();
        let e = g.entry(LogOp::MODIFY);
        // lazy PG info (adr 0021 am. 27): most client writes persist the entry only, `_info` / `_loghead` follow with the
        // next info write; reload rebuilds them from the log
        let fast = r.pct(60);
        t.push(if fast {
            StoreOp::LogAppendFast(vec![peering::EncLogEntry::of(&e)])
        } else {
            StoreOp::LogAppend(vec![e.clone()])
        });
        let trim = r.pct(25);
        if trim {
            // the trimmed entries stay as dup records and the oldest dups go in the same txn as the tail move (a crash must
            // keep or drop them together)
            t.push(StoreOp::LogTrim {
                to: Eversion::new(g.epoch, g.ver.saturating_sub(4)),
                dups_from: Some(Eversion::new(g.epoch, g.ver.saturating_sub(4 + r.below(6)))),
                tail_up: false,
            });
        }
        if !fast || trim {
            if fast {
                t.push(StoreOp::LogSetHead(e.version));
            }
            let inf = g.info();
            t.push(StoreOp::PutInfo(Box::new(inf)));
        }
        let d = g.object_txn(&mut exist);
        t.push(StoreOp::ApplyTxn {
            middle: Default::default(),
            data: d.into(),
        });
        v.push(t);
    }
    (s, v)
}

fn quiet() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |i| {
            let m = i
                .payload()
                .downcast_ref::<String>()
                .cloned()
                .unwrap_or_default();
            if !m.contains(": crash:") && !m.contains("crash: ") {
                prev(i)
            }
        }));
    });
}

fn same(mem: &MemStore, ad: &Ad, s: SpgT) -> bool {
    quiet();
    catch_unwind(AssertUnwindSafe(|| {
        assert_same(mem, ad, s, "crash");
        assert_same_objects(mem, ad, s, "crash");
    }))
    .is_ok()
}

fn scenario(
    img: &store::dev::SimImage,
    sim: &store::dev::SimConfig,
    cfg: &StoreCfg,
    s: SpgT,
    txns: &[StoreTxn],
    k: Option<u64>,
    pol: CrashPolicy,
    seed: u64,
) -> Result<(usize, bool), String> {
    let mut s2 = sim.clone();
    s2.seed = seed;
    let (disk, ad) = open(img, &s2, cfg);
    ad.submit_create(s);
    if let Some(k) = k {
        disk.arm_crash(disk.events() + k);
    }
    let mut ok = 0;
    for t in txns {
        match ad.try_submit(s, t) {
            Ok(()) => ok += 1,
            Err(_) if disk.crashed() => break,
            Err(e) => return Err(format!("submit: {e}")),
        }
    }
    let crashed = disk.crashed();
    disk.crash_now();
    let cimg = disk.crash_image(pol);
    drop(ad);
    {
        let d = SimDisk::from_image(&cimg, sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        fsck(&mut dev, &mut clk, Some(&fsck_refs)).map_err(|e| format!("fsck crash image: {e}"))?;
    }
    let (_d2, ad2) = open(&cimg, sim, cfg);
    let rep = ad2
        .with_store(|st| st.check(true))
        .map_err(|e| format!("check: {e}"))?;
    if !rep.errors.is_empty() {
        return Err(format!("object layer check: {:?}", rep.errors));
    }
    let mut mem = MemStore::new();
    mem.submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    for t in &txns[..ok] {
        mem.submit(s, t);
    }
    if same(&mem, &ad2, s) {
        return Ok((ok, crashed));
    }
    if ok < txns.len() {
        mem.submit(s, &txns[ok]);
        if same(&mem, &ad2, s) {
            return Ok((ok + 1, crashed));
        }
    }
    Err(format!(
        "recovered PG state matches neither {ok} nor {} acked-prefix txns (crashed={crashed})",
        ok + 1
    ))
}

fn matrix(seed: u64, n: usize, policies: &[CrashPolicy], stride: u64) -> (u64, u64) {
    let cfg = StoreCfg {
        shard: ShardCfg {
            ckpt_wal_pct: 4,
            ..StoreCfg::default().shard
        },
    };
    let sim = sim_cfg(40, seed);
    let img = fresh_image(&sim, 1, 512);
    let (s, txns) = workload(seed, n);
    // dry run
    let (disk, ad) = open(&img, &sim, &cfg);
    ad.submit_create(s);
    let e0 = disk.events();
    for t in &txns {
        ad.try_submit(s, t).unwrap();
    }
    let events = disk.events() - e0;
    drop(ad);
    let (mut n_s, mut n_c) = (0, 0);
    let mut k = 0;
    while k < events {
        for (pi, pol) in policies.iter().enumerate() {
            match scenario(
                &img,
                &sim,
                &cfg,
                s,
                &txns,
                Some(k),
                *pol,
                k * 5 + pi as u64 + 1,
            ) {
                Ok((_, c)) => {
                    n_s += 1;
                    n_c += c as u64;
                }
                Err(e) => panic!("seed {seed} k={k} policy#{pi}: {e}"),
            }
        }
        k += stride;
    }
    eprintln!(
        "adapter crash matrix seed {seed}: {events} device events, {n_s} scenarios, {n_c} crashed"
    );
    (n_s, n_c)
}

#[test]
fn pg_txns_survive_crash_at_every_io_boundary() {
    let (n, c) = matrix(
        7,
        14,
        &[
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ],
        1,
    );
    assert!(n > 60 && c * 2 > n);
}

#[test]
fn same_version_dups_survive_crash_during_trim_and_rewrite() {
    let sim = sim_cfg(40, 7);
    let cfg = StoreCfg::default();
    let img = fresh_image(&sim, 1, 512);
    let s = spg(1, 0);
    for replace in [false, true] {
        let mut g = PgGen::new(s, 7);
        let mut e = g.entry(LogOp::MODIFY);
        e.reqid.tid = 50;
        e.extra_reqids = (77..80)
            .map(|tid| {
                (
                    OsdReqId {
                        tid,
                        ..Default::default()
                    },
                    tid,
                )
            })
            .collect();
        let newest = g.entry(LogOp::MODIFY);
        let txns = [
            StoreTxn {
                ops: vec![StoreOp::LogAppend(vec![e.clone(), newest.clone()])],
            },
            StoreTxn {
                ops: vec![
                    StoreOp::LogTrim {
                        to: e.version,
                        dups_from: Some(e.version),
                        tail_up: false,
                    },
                    if replace {
                        StoreOp::LogReplace(Box::new(PgLog {
                            head: newest.version,
                            tail: e.version,
                            can_rollback_to: newest.version,
                            rollback_info_trimmed_to: newest.version,
                            log: [newest].into(),
                            dups: e.dups().collect(),
                        }))
                    } else {
                        StoreOp::LogDups(e.dups().collect())
                    },
                ],
            },
        ];
        let (disk, ad) = open(&img, &sim, &cfg);
        ad.submit_create(s);
        let start = disk.events();
        for t in &txns {
            ad.try_submit(s, t).unwrap();
        }
        let events = disk.events() - start;
        drop(ad);
        for k in 0..=events {
            for policy in [
                CrashPolicy::DROP_ALL,
                CrashPolicy::PERSIST_ALL,
                CrashPolicy::MIXED,
            ] {
                scenario(&img, &sim, &cfg, s, &txns, Some(k), policy, 7)
                    .unwrap_or_else(|e| panic!("replace={replace} boundary={k}: {e}"));
            }
        }
    }
}

#[test]
fn pg_txns_survive_crash_more_seeds() {
    for seed in 8..11 {
        matrix(seed, 12, &[CrashPolicy::MIXED, CrashPolicy::DROP_ALL], 2);
    }
}

#[test]
#[ignore = "soak"]
fn pg_crash_soak() {
    for seed in 20..40 {
        matrix(
            seed,
            20,
            &[
                CrashPolicy::MIXED,
                CrashPolicy::DROP_ALL,
                CrashPolicy::PERSIST_ALL,
            ],
            1,
        );
    }
}

#[test]
fn pg_removal_resumes_after_crash() {
    // crash at every boundary of RemovePg on a PG with many objects: afterwards the PG is either complete,
    // gone, or marked as being removed and `resume_removals` finishes it; no object leaks.
    let cfg = StoreCfg {
        shard: ShardCfg {
            ckpt_wal_pct: 4,
            ..StoreCfg::default().shard
        },
    };
    let sim = sim_cfg(40, 5);
    let img = fresh_image(&sim, 1, 512);
    let s = spg(1, 0);
    let (_, txns) = workload(3, 25);
    let (disk, ad) = open(&img, &sim, &cfg);
    ad.submit_create(s);
    for t in &txns {
        ad.try_submit(s, t).unwrap();
    }
    ad.remove_batch.set(3);
    ad.with_store(|st| st.checkpoint().unwrap());
    let base = disk.image();
    drop(ad);
    let rm = StoreTxn {
        ops: vec![StoreOp::RemovePg],
    };
    let (d0, a0) = open(&base, &sim, &cfg);
    a0.remove_batch.set(3);
    let e0 = d0.events();
    a0.try_submit(s, &rm).unwrap();
    a0.finish_removals().unwrap();
    let events = d0.events() - e0;
    assert!(events > 10);
    let mut states = (0, 0, 0);
    for k in 0..events {
        let mut s2 = sim.clone();
        s2.seed = 100 + k;
        let (d, a) = open(&base, &s2, &cfg);
        a.remove_batch.set(3);
        d.arm_crash(d.events() + k);
        let r = a.try_submit(s, &rm);
        let _ = r;
        let _ = a.finish_removals();
        d.crash_now();
        let img = d.crash_image(CrashPolicy::MIXED);
        drop(a);
        let (_d2, mut a2) = open(&img, &sim, &cfg);
        let listed = a2.list_pgs().contains(&s);
        let pending = a2.pending_removals().unwrap().contains(&s);
        match (listed, pending) {
            (true, false) => states.0 += 1,
            (false, true) => states.1 += 1,
            (false, false) => states.2 += 1,
            (true, true) => panic!("both"),
        }
        assert_eq!(a2.resume_removals().unwrap(), pending as usize);
        if listed {
            // not yet started: PG intact, remove it now
            a2.submit(s, &rm);
        }
        a2.finish_removals().unwrap();
        assert!(a2.load_pg(s).is_none() && !a2.list_pgs().contains(&s));
        a2.with_store(|st| {
            assert!(st.list_colls().unwrap().is_empty(), "collections left");
            st.checkpoint().unwrap();
        });
    }
    eprintln!("removal crash states (intact, resumed, gone): {states:?}");
    assert!(states.0 > 0 && states.1 > 0);
}

#[test]
fn queued_pg_removal_never_leaves_a_half_emptied_pg_without_its_marker() {
    // The OSD path: the REMOVE marker and the deletion txns go through the store queue (one deletion txn in flight, none
    // waits for durability). Crash at every I/O boundary: the PG is intact, or marked as being removed (the marker is
    // durable before the first object goes: same shard FIFO), or gone; never partly deleted and unmarked.
    let cfg = StoreCfg {
        shard: ShardCfg {
            ckpt_wal_pct: 4,
            ..StoreCfg::default().shard
        },
    };
    let sim = sim_cfg(44, 5);
    let img = fresh_image(&sim, 1, 512);
    let s = spg(1, 0);
    let (_, txns) = workload(3, 25);
    let (disk, ad) = open(&img, &sim, &cfg);
    ad.submit_create(s);
    for t in &txns {
        ad.try_submit(s, t).unwrap();
    }
    let nobj = ad.object_stats(s).0;
    assert!(nobj > 10, "workload has objects: {nobj}");
    ad.with_store(|st| st.checkpoint().unwrap());
    let base = disk.image();
    drop(ad);
    let rm = StoreTxn {
        ops: vec![StoreOp::RemovePg],
    };
    let (d0, mut a0) = open(&base, &sim, &cfg);
    a0.remove_batch.set(3);
    let e0 = d0.events();
    assert!(matches!(a0.queue(s, &rm, 1), Queued::Pending));
    a0.finish_removals().unwrap();
    let events = d0.events() - e0;
    assert!(events > 10);
    let mut states = (0, 0, 0);
    for k in 0..events {
        let mut s2 = sim.clone();
        s2.seed = 200 + k;
        let (d, mut a) = open(&base, &s2, &cfg);
        a.remove_batch.set(3);
        d.arm_crash(d.events() + k);
        let _ = a.queue(s, &rm, 1);
        let _ = a.finish_removals();
        d.crash_now();
        let img = d.crash_image(CrashPolicy::MIXED);
        drop(a);
        let (_d2, mut a2) = open(&img, &sim, &cfg);
        let listed = a2.list_pgs().contains(&s);
        let pending = a2.pending_removals().unwrap().contains(&s);
        match (listed, pending) {
            (true, false) => {
                states.0 += 1;
                assert_eq!(
                    a2.object_stats(s).0,
                    nobj,
                    "crash at {k}: PG partly deleted without a marker"
                );
            }
            (false, true) => states.1 += 1,
            (false, false) => states.2 += 1,
            (true, true) => panic!("both"),
        }
        assert_eq!(a2.resume_removals().unwrap(), pending as usize);
        a2.finish_removals().unwrap();
        if listed {
            a2.submit(s, &rm);
        }
        assert!(a2.load_pg(s).is_none() && !a2.list_pgs().contains(&s));
        a2.with_store(|st| assert!(st.list_colls().unwrap().is_empty(), "collections left"));
    }
    eprintln!("queued removal crash states (intact, resumed, gone): {states:?}");
    assert!(states.0 > 0 && states.1 > 0);
}

// ---------------------------------------------------------------- multi-record WAL txns (ADR 0028)

fn big_missing(pool: i64, seed: u32, n: usize, epoch: u32) -> Vec<(Hobject, Option<MissingItem>)> {
    (0..n)
        .map(|i| {
            let h = Hobject::new(
                format!("rbd_data.1234.{i:016x}").as_bytes(),
                SnapId::NOSNAP,
                (i as u32).wrapping_mul(0x9e37_79b1) & !0x7 | seed & 7,
                pool,
                b"",
            );
            (
                h,
                Some(MissingItem::new(
                    Eversion::new(epoch, 1000 + i as u64),
                    Eversion::new(epoch, i as u64 % 50),
                    i % 9 == 0,
                )),
            )
        })
        .collect()
}

/// Claim-style whole-log replacement: `entries` log entries + `dups` dups in ONE StoreTxn (with info and,
/// if `missing > 0`, a missing set), framed by small txns.
fn big_workload(seed: u64, entries: usize, dups: usize, missing: usize) -> (SpgT, Vec<StoreTxn>) {
    let s = spg(1, 0);
    let mut g = PgGen::new(s, seed);
    let mut exist = BTreeSet::new();
    let mut v = Vec::new();
    for _ in 0..3 {
        let mut t = StoreTxn::default();
        t.push(StoreOp::LogAppend(vec![g.entry(LogOp::MODIFY)]));
        t.push(StoreOp::PutInfo(Box::new(g.info())));
        v.push(t);
    }
    let all: Vec<LogEntry> = (0..entries + dups)
        .map(|_| g.entry(LogOp::MODIFY))
        .collect();
    let (d, l) = all.split_at(dups);
    let tail = d.last().map_or(Eversion::new(g.epoch, 0), |e| e.version);
    let head = l.last().unwrap().version;
    let mut t = StoreTxn::default();
    t.push(StoreOp::LogReplace(Box::new(PgLog {
        head,
        tail,
        log: l.to_vec().into(),
        can_rollback_to: head,
        rollback_info_trimmed_to: head,
        dups: d.iter().map(|e| g.dup_of(e)).collect(),
    })));
    if missing > 0 {
        t.push(StoreOp::Missing(big_missing(1, 0, missing, g.epoch)));
    }
    t.push(StoreOp::PutInfo(Box::new(g.info())));
    v.push(t);
    for _ in 0..4 {
        let mut t = StoreTxn::default();
        t.push(StoreOp::LogAppend(vec![g.entry(LogOp::MODIFY)]));
        // steady-state trim on the big dup set: drops the oldest keys as a range, nothing is read
        t.push(StoreOp::LogTrim {
            to: Eversion::new(g.epoch, g.ver.saturating_sub(2)),
            dups_from: Some(Eversion::new(g.epoch, g.ver.saturating_sub(40))),
            tail_up: false,
        });
        t.push(StoreOp::PutInfo(Box::new(g.info())));
        t.push(StoreOp::ApplyTxn {
            middle: Default::default(),
            data: g.object_txn(&mut exist).into(),
        });
        v.push(t);
    }
    (s, v)
}

fn multi_total(ad: &Ad) -> u64 {
    ad.with_store(|st| st.shards.iter().map(|s| s.sh.stats.multi_txns).sum())
}

fn big_matrix(
    seed: u64,
    shape: (usize, usize, usize),
    unit_blocks: u32,
    stride: u64,
    policies: &[CrashPolicy],
) -> (u64, u64) {
    let cfg = StoreCfg {
        shard: ShardCfg {
            ckpt_wal_pct: 30,
            max_unit_blocks: unit_blocks,
            ..StoreCfg::default().shard
        },
    };
    let sim = sim_cfg(64, seed);
    let img = fresh_image(&sim, 1, 4096);
    let (s, txns) = big_workload(seed, shape.0, shape.1, shape.2);
    let (disk, ad) = open(&img, &sim, &cfg);
    ad.submit_create(s);
    let e0 = disk.events();
    for t in &txns {
        ad.try_submit(s, t).unwrap();
    }
    let events = disk.events() - e0;
    assert!(
        multi_total(&ad) >= 1,
        "the claim txn must be a multi-part txn"
    );
    drop(ad);
    let (mut n_s, mut n_c) = (0, 0);
    let mut k = 0;
    while k < events {
        for (pi, pol) in policies.iter().enumerate() {
            match scenario(
                &img,
                &sim,
                &cfg,
                s,
                &txns,
                Some(k),
                *pol,
                k * 5 + pi as u64 + 1,
            ) {
                Ok((_, c)) => {
                    n_s += 1;
                    n_c += c as u64;
                }
                Err(e) => panic!("big seed {seed} k={k} policy#{pi}: {e}"),
            }
        }
        k += stride;
    }
    eprintln!(
        "big-txn crash matrix seed {seed}: {events} device events, {n_s} scenarios, {n_c} crashed"
    );
    (n_s, n_c)
}

#[test]
fn big_pg_txn_atomic_at_every_io_boundary() {
    // claim of 400 entries + 200 dups + 300 missing (+info): ~8 KiB units -> many parts; every IO boundary
    let (n, c) = big_matrix(
        21,
        (400, 200, 300),
        2,
        1,
        &[
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ],
    );
    assert!(n > 100 && c * 2 > n);
}

#[test]
fn full_size_claim_5000_entries_3000_dups_crash_every_boundary() {
    let (n, _) = big_matrix(
        22,
        (5000, 3000, 0),
        64,
        1,
        &[CrashPolicy::MIXED, CrashPolicy::DROP_ALL],
    );
    assert!(n > 40);
}

#[test]
fn pg_removal_is_incremental_and_never_blocks_the_caller() {
    // Regression (RGW e2e): deleting a PG of 100k+ objects inside `try_submit` blocked the core for seconds (OSD marked down).
    // Now `RemovePg` only sets the durable marker; `step_removals` does bounded slices; a re-create finishes the old one first.
    let cfg = StoreCfg::default();
    let sim = sim_cfg(40, 5);
    let img = fresh_image(&sim, 1, 512);
    let s = spg(1, 0);
    let (_, txns) = workload(3, 25);
    let (_disk, ad) = open(&img, &sim, &cfg);
    ad.submit_create(s);
    for t in &txns {
        ad.try_submit(s, t).unwrap();
    }
    ad.remove_batch.set(2);
    let rm = StoreTxn {
        ops: vec![StoreOp::RemovePg],
    };
    ad.try_submit(s, &rm).unwrap();
    assert!(
        ad.pending_removals().unwrap().contains(&s),
        "marker set, objects still there"
    );
    // tiny budget: one batch per call, many calls
    let mut calls = 0;
    while ad.step_removals_sync().unwrap() {
        calls += 1;
        assert!(calls < 10_000);
    }
    assert!(calls > 3, "removal was sliced ({calls} calls)");
    assert!(ad.load_pg(s).is_none() && !ad.list_pgs().contains(&s));
    ad.with_store(|st| assert!(st.list_colls().unwrap().is_empty(), "collections left"));
    // re-create while a deletion is queued: the old PG is finished first, the new one starts empty
    ad.submit_create(s);
    for t in &txns {
        ad.try_submit(s, t).unwrap();
    }
    ad.try_submit(s, &rm).unwrap();
    ad.submit_create(s);
    assert!(ad.pending_removals().unwrap().is_empty());
    ad.finish_removals().unwrap();
    assert!(
        ad.list_pgs().contains(&s),
        "the re-created PG survives the queued deletion"
    );
}

fn drain(ad: &mut Ad, n: usize) {
    let mut out = Vec::new();
    for _ in 0..1_000_000 {
        ad.poll_commits(&mut out);
        if out.len() >= n {
            return;
        }
        ad.with_store(|st| st.idle());
    }
    panic!("only {} of {n} txns became durable", out.len());
}

#[test]
fn pg_recreated_through_queue_while_its_deletion_is_queued_keeps_its_data() {
    // Review regression: the OSD persists through `queue` (not `try_submit`). A `CreatePg` there while the old PG's
    // deletion was still queued was a no-op (collection exists): the new PG's acked writes landed in the doomed
    // collection beside the old pgmeta + REMOVE marker; `step_removals` (or the next start) then deleted them.
    let cfg = StoreCfg::default();
    let sim = sim_cfg(40, 5);
    let img = fresh_image(&sim, 1, 512);
    let s = spg(1, 0);
    let (_, old) = workload(3, 25);
    let (_, new) = workload(11, 8);
    let (disk, mut ad) = open(&img, &sim, &cfg);
    ad.submit_create(s);
    for t in &old {
        ad.try_submit(s, t).unwrap();
    }
    ad.remove_batch.set(2);
    let rm = StoreTxn {
        ops: vec![StoreOp::RemovePg],
    };
    assert!(matches!(ad.queue(s, &rm, 1), Queued::Pending));
    assert!(ad.step_removals_sync().unwrap(), "deletion only started");
    // re-create + writes through the OSD path
    let mut mem = MemStore::default();
    let create = StoreTxn {
        ops: vec![StoreOp::CreatePg],
    };
    mem.submit(s, &create);
    let mut n = 0;
    for (i, t) in std::iter::once(&create).chain(&new).enumerate() {
        if i > 0 {
            mem.submit(s, t);
        }
        if matches!(ad.queue(s, t, 10 + i as u64), Queued::Pending) {
            n += 1;
        }
    }
    drain(&mut ad, n);
    ad.finish_removals().unwrap();
    assert!(ad.pending_removals().unwrap().is_empty());
    assert!(
        same(&mem, &ad, s),
        "re-created PG = MemStore after the queued deletion ran"
    );
    ad.with_store(|st| st.checkpoint().unwrap());
    drop(ad);
    let (_d2, a2) = open(&disk.image(), &sim, &cfg);
    assert_eq!(a2.resume_removals().unwrap(), 0);
    assert!(a2.list_pgs().contains(&s));
    assert!(same(&mem, &a2, s), "and after a restart");
}

/// Review 2026-11-03 #10: a late write for a PG whose deletion is queued is an orphan: never applied to the doomed
/// collection and never reported `Durable` (the PG logged it in memory), a local failure instead.
#[test]
fn late_write_to_a_pg_whose_deletion_is_queued_fails_the_store() {
    let cfg = StoreCfg::default();
    let sim = sim_cfg(40, 5);
    let img = fresh_image(&sim, 1, 512);
    let s = spg(1, 0);
    let (_, old) = workload(3, 25);
    let (_, new) = workload(11, 8);
    let (_disk, mut ad) = open(&img, &sim, &cfg);
    ad.submit_create(s);
    for t in &old {
        ad.try_submit(s, t).unwrap();
    }
    ad.remove_batch.set(2);
    let rm = StoreTxn {
        ops: vec![StoreOp::RemovePg],
    };
    assert!(matches!(ad.queue(s, &rm, 1), Queued::Pending));
    assert!(ad.step_removals_sync().unwrap(), "deletion only started");
    let orphans = ad.orphan_writes.get();
    let r = ad.queue(s, &new[0], 2);
    assert!(
        matches!(r, Queued::Failed(_)),
        "late write to a deleted PG: {r:?}"
    );
    assert_eq!(ad.orphan_writes.get(), orphans + 1);
    assert!(ad.failure().is_some());
}

#[test]
fn pg_removal_retries_smaller_on_nospace_and_never_drops_the_deletion() {
    // A deletion slice that hits NoSpace is retried with half the objects (down to 1); if even one object does not fit the
    // PG waits for a retry (note, no store failure) and the deletion is never dropped.
    let cfg = StoreCfg::default();
    let sim = sim_cfg(41, 5);
    let img = fresh_image(&sim, 1, 512);
    let s = spg(1, 0);
    let (_, txns) = workload(3, 25);
    let (_disk, ad) = open(&img, &sim, &cfg);
    ad.submit_create(s);
    for t in &txns {
        ad.try_submit(s, t).unwrap();
    }
    ad.remove_batch.set(16);
    let rm = StoreTxn {
        ops: vec![StoreOp::RemovePg],
    };
    ad.try_submit(s, &rm).unwrap();
    // slices of 4+ objects fail: the slice shrinks 16 -> 8 -> 4 -> 2 and then goes through
    ad.remove_nospace_from.set(4);
    while ad.step_removals_sync().unwrap() {}
    assert!(ad.load_pg(s).is_none() && !ad.list_pgs().contains(&s));
    assert!(ad.failure().is_none(), "{:?}", ad.failure());
    assert!(ad.notes.borrow().is_empty(), "no back-off needed");
    ad.with_store(|st| assert!(st.list_colls().unwrap().is_empty(), "collections left"));

    // even one object does not fit: back off, keep the deletion queued, finish once there is room
    ad.submit_create(s);
    for t in &txns {
        ad.try_submit(s, t).unwrap();
    }
    ad.try_submit(s, &rm).unwrap();
    ad.remove_batch.set(1);
    ad.remove_nospace_from.set(1); // every deletion txn fails
    let mut guard = 0;
    while ad.step_removals_sync().unwrap() && guard < 3 {
        guard += 1;
    }
    assert!(ad.failure().is_none());
    assert!(
        ad.pending_removals().unwrap().contains(&s),
        "deletion still queued"
    );
    assert!(
        ad.notes.borrow().iter().any(|n| n.contains("ENOSPC")),
        "{:?}",
        ad.notes.borrow()
    );
    // room again (after the back-off): it finishes
    ad.remove_nospace_from.set(0);
    let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while ad.step_removals_sync().unwrap() {
        assert!(
            std::time::Instant::now() < end,
            "WARNING TIMEOUT deletion finish exceeded 5s (removal after room again)"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ad.load_pg(s).is_none() && !ad.list_pgs().contains(&s));
}

#[test]
fn nospace_on_deletion_never_fails_the_start_or_the_recreate() {
    // adr 0021 am. 23 / open question 21 (f): a store too full to delete even one object keeps the durable marker and
    // retries in the background (back-off) instead of failing `resume_removals` at mount or a `CreatePg` of a PG whose
    // deletion is still queued; the txns of the re-created PG wait in order and are applied (and acked) afterwards.
    let cfg = StoreCfg::default();
    let sim = sim_cfg(43, 5);
    let img = fresh_image(&sim, 1, 512);
    let s = spg(1, 0);
    let (_, old) = workload(3, 25);
    let (_, new) = workload(11, 8);
    let (disk, mut ad) = open(&img, &sim, &cfg);
    ad.submit_create(s);
    for t in &old {
        ad.try_submit(s, t).unwrap();
    }
    ad.remove_batch.set(2);
    let rm = StoreTxn {
        ops: vec![StoreOp::RemovePg],
    };
    assert!(matches!(ad.queue(s, &rm, 1), Queued::Pending));
    assert!(ad.step_removals_sync().unwrap(), "deletion only started");

    // (a) re-create while the deletion cannot proceed (no room for even a 1-object slice)
    ad.remove_nospace_from.set(1);
    let mut mem = MemStore::default();
    let create = StoreTxn {
        ops: vec![StoreOp::CreatePg],
    };
    mem.submit(s, &create);
    let mut tokens = Vec::new();
    for (i, t) in std::iter::once(&create).chain(&new).enumerate() {
        if i > 0 {
            mem.submit(s, t);
        }
        let tok = 10 + i as u64;
        let q = ad.queue(s, t, tok);
        assert_eq!(q, Queued::Pending, "txn {i} must wait, not fail: {q:?}");
        tokens.push((s, tok));
    }
    assert!(ad.failure().is_none(), "{:?}", ad.failure());
    assert_eq!(ad.rejected.get(), 0);
    assert!(ad.pending_removals().unwrap().contains(&s), "marker kept");
    let mut out = Vec::new();
    ad.poll_commits(&mut out);
    assert!(
        out.iter().all(|t| t.1 == 1),
        "nothing but the deletion marker acked while the PG is still being deleted: {out:?}"
    );
    out.clear();
    assert!(ad.pending() >= tokens.len());
    // room again: the deletion finishes in the background, the waiting txns apply in order and are acked
    ad.remove_nospace_from.set(0);
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while out.len() < tokens.len() {
        assert!(
            std::time::Instant::now() < end,
            "WARNING TIMEOUT deferred txns applied exceeded 10s (acked {})",
            out.len()
        );
        PgStoreOps::step_removals(&ad, u64::MAX);
        ad.poll_commits(&mut out);
        ad.with_store(|st| st.idle());
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    out.sort();
    assert_eq!(out, tokens);
    assert!(ad.failure().is_none(), "{:?}", ad.failure());
    assert!(ad.pending_removals().unwrap().is_empty());
    assert!(
        same(&mem, &ad, s),
        "re-created PG = MemStore, nothing of the old PG"
    );
    ad.with_store(|st| st.checkpoint().unwrap());
    drop(ad);

    // (b) a restart finds a queued deletion and the store is too full to delete: it starts, the PG stays queued
    let (_d2, mut a2) = open(&disk.image(), &sim, &cfg);
    let s2 = s; // the re-created PG of (a)
    a2.remove_batch.set(2);
    assert!(matches!(a2.queue(s2, &rm, 1), Queued::Pending)); // marker queued (durable at the checkpoint), objects not deleted yet
    a2.with_store(|st| st.checkpoint().unwrap());
    let img3 = _d2.image();
    drop(a2);
    let (_d3, a3) = open(&img3, &sim, &cfg);
    a3.remove_nospace_from.set(1);
    assert_eq!(a3.resume_removals().unwrap(), 1, "no error at mount");
    assert!(a3.failure().is_none());
    assert!(a3.pending_removals().unwrap().contains(&s2));
    assert!(
        !a3.list_pgs().contains(&s2),
        "a PG being deleted is not loaded"
    );
    // the first steps (after the start, in the background) hit the full store: the batch halves down to one object, then
    // the back-off note, no failure
    for _ in 0..8 {
        a3.step_removals_sync().unwrap();
        if a3.removal_paused() {
            break;
        }
    }
    assert!(a3.failure().is_none());
    assert!(a3.notes.borrow().iter().any(|n| n.contains("ENOSPC")));
    a3.remove_nospace_from.set(0);
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while a3.step_removals_sync().unwrap() {
        assert!(
            std::time::Instant::now() < end,
            "WARNING TIMEOUT deletion finish exceeded 10s (removal after room again)"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(a3.pending_removals().unwrap().is_empty());
    assert!(!a3.list_pgs().contains(&s2) && a3.load_pg(s2).is_none());
}

/// Lazy PG info only on a store an older build refuses (`FEAT_LAZY_PGINFO`, adr 0021 am. 27): an old-format store keeps
/// eager `_info` writes; after fast appends and a crash-free reopen the reload is rebuilt from the
/// log (head, last_update, last_user_version, last_complete).
#[test]
fn lazy_pg_info_follows_the_store_feature_bit() {
    let sim = sim_cfg(40, 3);
    let img = fresh_image(&sim, 1, 512);
    let (_, ad) = open(&img, &sim, &StoreCfg::default());
    assert!(ad.lazy_info(), "mkfs: all bits");
    drop(ad);
    let disk = SimDisk::new(sim.clone());
    let p = store::layout::MkfsParams {
        shards: 1,
        wal_blocks: 512,
        align_blocks: 1,
        meta_pct: 8,
        lazy_pginfo: false,
        ..Default::default()
    };
    store::layout::mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    let old = disk.image();
    let (_, ad) = open(&old, &sim, &StoreCfg::default());
    assert!(!ad.lazy_info(), "old format: eager");
    drop(ad);
    // fast appends only: `_info` / `_loghead` stay at the create, the reload follows the log
    let (d, ad) = open(&img, &sim, &StoreCfg::default());
    let s = spg(1, 0);
    ad.submit_create(s);
    let mut g = PgGen::new(s, 5);
    let mut last = None;
    for _ in 0..6 {
        let e = g.entry(LogOp::MODIFY);
        last = Some((e.version, e.user_version));
        ad.try_submit(
            s,
            &StoreTxn {
                ops: vec![StoreOp::LogAppendFast(vec![peering::EncLogEntry::of(&e)])],
            },
        )
        .unwrap();
    }
    ad.with_store(|st| st.checkpoint().unwrap());
    let img2 = d.image();
    drop(ad);
    let (_, ad) = open(&img2, &sim, &StoreCfg::default());
    let p = ad.load_pg(s).unwrap();
    let (v, uv) = last.unwrap();
    assert_eq!(
        (
            p.log.head,
            p.info.last_update,
            p.info.last_complete,
            p.info.last_user_version
        ),
        (v, v, v, uv)
    );
    assert_eq!(p.log.log.len(), 6);
}

/// Restart in the middle of a background PG deletion: the resume at mount only queues (no synchronous delete, the OSD
/// serves at once), the slices finish it afterwards, progress is reported, and the objects are gone at the end.
#[test]
fn pg_removal_restart_mid_delete_resumes_in_background() {
    let cfg = StoreCfg::default();
    let sim = sim_cfg(40, 5);
    let img = fresh_image(&sim, 1, 512);
    let s = spg(1, 0);
    let (_, txns) = workload(3, 25);
    let (disk, ad) = open(&img, &sim, &cfg);
    ad.submit_create(s);
    for t in &txns {
        ad.try_submit(s, t).unwrap();
    }
    ad.remove_batch.set(3);
    let nobj = ad.object_stats(s).0;
    assert!(nobj > 10, "workload has objects: {nobj}");
    ad.remove_pg_async(s).unwrap();
    assert_eq!(ad.removal_progress().0, 1);
    assert_eq!(
        ad.removal_progress().2,
        nobj,
        "estimate = objects at queue time"
    );
    // a few tiny slices, then "crash" with the deletion unfinished
    let mut steps = 0;
    while ad.removal_progress().1 == 0 && steps < 1000 {
        ad.step_removals_sync().unwrap();
        steps += 1;
    }
    let (_, done, left) = ad.removal_progress();
    assert!(done > 0 && done < nobj && left < nobj);
    ad.with_store(|st| st.checkpoint().unwrap());
    let image = disk.image();
    drop(ad);

    let (_d2, a2) = open(&image, &sim, &cfg);
    assert!(a2.pending_removals().unwrap().contains(&s));
    assert_eq!(a2.resume_removals().unwrap(), 1);
    // queued, nothing deleted at mount; the PG is hidden from loading while it is being removed
    assert_eq!(a2.removal_progress(), (1, 0, a2.removal_progress().2));
    assert!(a2.removal_progress().2 > 0 && a2.removal_progress().2 <= nobj);
    assert!(a2.pending_removals().unwrap().contains(&s));
    let mut steps = 0;
    while a2.step_removals_sync().unwrap() && steps < 100_000 {
        steps += 1;
    }
    assert!(a2.pending_removals().unwrap().is_empty());
    assert!(!a2.list_pgs().contains(&s));
    a2.with_store(|st| assert!(st.list_colls().unwrap().is_empty(), "collections left"));
    assert_eq!(a2.removal_progress().0, 0);
    assert!(a2.removal_progress().1 > 0);
}

/// A clean shutdown checkpoints the store (review M2): the next mount replays nothing, where a stop without it replays
/// every txn since the last checkpoint (and its first checkpoint then freezes every replayed page).
#[test]
fn clean_exit_checkpoint_leaves_nothing_to_replay() {
    let replayed = |exit: bool| {
        let (disk, ad, sim) = new_adapter(64, 1, 5);
        let s = spg(1, 0);
        ad.submit_create(s);
        let c = CollT::Pg(s);
        ad.with_store(|st| {
            for i in 0..50u32 {
                let o = Ghobject::new(
                    Hobject::new(format!("o{i}").as_bytes(), SnapId::NOSNAP, i, 1, b""),
                    Ghobject::NO_GEN,
                    ShardId::NO_SHARD,
                );
                let mut t = store::obj::OTxn::new();
                t.write(c, &o, 0, &[3u8; 4096]);
                st.commit(&t).unwrap();
            }
        });
        if exit {
            ad.checkpoint_on_exit().unwrap();
        }
        let img = disk.image();
        let d2 = SimDisk::from_image(&img, sim);
        let (_st, stats) =
            store::obj::Store::mount(move || d2.queue(), SimClock::default(), StoreCfg::default())
                .unwrap();
        stats.iter().map(|r| r.txns).sum::<u64>()
    };
    assert!(
        replayed(false) > 0,
        "the stop without the exit checkpoint replays"
    );
    assert_eq!(replayed(true), 0, "a clean exit leaves nothing to replay");
}
