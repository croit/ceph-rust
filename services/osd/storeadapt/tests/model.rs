// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Model-based test: random PG transactions (info/log/missing/object ops) applied to `peering::MemStore`
//! (reference semantics) and to the NVMe store adapter; every observable of `PgStoreOps` must agree.
#![expect(clippy::bool_assert_comparison)]
mod common;
use common::*;
use denc::types::*;
use peering::store::{MemStore, PgStoreOps, StoreOp, StoreTxn};
use pgwire::{LogOp, PgLog};
use std::collections::BTreeSet;
use store::rng::Rng;

fn run(seed: u64, shards: u32, ntxn: usize, remount_every: usize) {
    let (mut disk, mut ad, sim) = new_adapter(128, shards, seed);
    let mut mem = MemStore::new();
    let pgs = [spg(1, 0), spg(1, 1), spg(2, 3)];
    let mut gens: Vec<PgGen> = pgs
        .iter()
        .map(|s| PgGen::new(*s, seed ^ s.pgid.seed as u64))
        .collect();
    let mut exist: Vec<BTreeSet<Hobject>> = vec![BTreeSet::new(); 3];
    let mut r = Rng::new(seed ^ 0xabc);
    for s in pgs {
        let t = StoreTxn {
            ops: vec![StoreOp::CreatePg],
        };
        mem.submit(s, &t);
        ad.submit(s, &t);
    }
    for i in 0..ntxn {
        let pi = r.below(3) as usize;
        let s = pgs[pi];
        let g = &mut gens[pi];
        let mut t = StoreTxn::default();
        match r.below(100) {
            0..=54 => {
                // typical repop: log entry + info + object txn (+ trim)
                let n = r.range(1, 3);
                let es: Vec<_> = (0..n)
                    .map(|_| {
                        g.entry(if r.pct(15) {
                            LogOp::DELETE
                        } else {
                            LogOp::MODIFY
                        })
                    })
                    .collect();
                t.push(StoreOp::LogAppend(es.clone()));
                // a PG trims forward only and keeps dups from at most the trim point
                let p = mem.load_pg(s).unwrap();
                let to = Eversion::new(g.epoch, g.ver.saturating_sub(r.range(2, 12)));
                if r.pct(30) && to > p.log.tail {
                    let from = if r.pct(15) {
                        None
                    } else {
                        Some(Eversion::new(
                            g.epoch,
                            to.version.saturating_sub(r.range(0, 30)),
                        ))
                    };
                    t.push(StoreOp::LogTrim {
                        to,
                        dups_from: from,
                        tail_up: r.pct(50),
                    });
                }
                let inf = g.info();
                t.push(StoreOp::PutInfo(Box::new(inf)));
                if r.pct(30) {
                    t.push(StoreOp::PutEpoch(g.epoch + r.below(3) as u32));
                }
                let d = g.object_txn(&mut exist[pi]);
                t.push(StoreOp::ApplyTxn {
                    middle: Default::default(),
                    data: d.into(),
                });
            }
            55..=64 => {
                let d = g.object_txn(&mut exist[pi]);
                t.push(StoreOp::ApplyTxn {
                    middle: Default::default(),
                    data: d.into(),
                });
            }
            65..=69 => {
                let items = g.missing_items();
                t.push(StoreOp::Missing(items));
            }
            70..=71 => t.push(StoreOp::MissingClear {
                may_include_deletes: r.pct(50),
            }),
            72..=75 => {
                // rewind (its own StoreTxn: no other log ops in the same txn)
                let to = Eversion::new(g.epoch, g.ver.saturating_sub(r.below(6)));
                t.push(StoreOp::LogRewind { to });
            }
            76..=79 => {
                let n = r.range(0, 8);
                let mut l = PgLog::default();
                let tail_v = g.ver;
                for _ in 0..n {
                    l.log.push_back(g.entry(LogOp::MODIFY));
                }
                l.tail = Eversion::new(g.epoch, tail_v);
                l.head = l.log.back().map_or(l.tail, |e| e.version);
                l.can_rollback_to = l.head;
                l.rollback_info_trimmed_to = l.head;
                l.dups = (0..r.below(4))
                    .map(|_| {
                        let e = g.entry(LogOp::MODIFY);
                        g.dup_of(&e)
                    })
                    .collect();
                t.push(StoreOp::LogReplace(Box::new(l)));
            }
            80..=82 => {
                let d = (0..r.below(5))
                    .map(|_| {
                        let e = g.entry(LogOp::MODIFY);
                        g.dup_of(&e)
                    })
                    .collect();
                t.push(StoreOp::LogDups(d));
            }
            83..=85 => {
                let p = g.past();
                t.push(StoreOp::PutPastIntervals(Box::new(p)));
                let inf = g.info();
                t.push(StoreOp::PutInfo(Box::new(inf)));
            }
            86..=90 => {
                let h = g.names[r.below(g.names.len() as u64) as usize].clone();
                exist[pi].remove(&h);
                t.push(StoreOp::RemoveObject(h));
            }
            91..=92 => {
                // delete the PG and recreate it
                t.push(StoreOp::RemovePg);
                exist[pi].clear();
                g.ver = 0;
                mem.submit(s, &t);
                ad.submit(s, &t);
                assert_same(&mem, &ad, s, "after removal");
                assert!(mem.load_pg(s).is_none() && ad.load_pg(s).is_none());
                assert_eq!(ad.list_pgs().contains(&s), false);
                t = StoreTxn {
                    ops: vec![StoreOp::CreatePg],
                };
            }
            _ => {
                // write to a PG that was just deleted? only via the explicit orphan case below
                let inf = g.info();
                t.push(StoreOp::PutInfo(Box::new(inf)));
            }
        }
        mem.submit(s, &t);
        ad.submit(s, &t);
        if i % 7 == 6 || i + 1 == ntxn {
            for (k, p) in pgs.iter().enumerate() {
                assert_same(&mem, &ad, *p, &format!("seed {seed} txn {i} pg {k}"));
                assert_same_objects(&mem, &ad, *p, &format!("seed {seed} txn {i} pg {k}"));
            }
            assert_eq!(mem.list_pgs(), ad.list_pgs());
        }
        if remount_every > 0 && i % remount_every == remount_every - 1 {
            ad.with_store(|st| st.checkpoint().unwrap());
            let img = disk.image();
            drop(ad);
            let (d, a) = open(&img, &sim, &store::obj::StoreCfg::default());
            disk = d;
            ad = a;
            for p in &pgs {
                assert_same(&mem, &ad, *p, "after remount");
                assert_same_objects(&mem, &ad, *p, "after remount");
            }
        }
    }
    assert_eq!(ad.orphan_writes.get(), mem.orphan_writes);
    let rep = ad.with_store(|st| st.check(true)).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}

#[test]
fn adapter_matches_memstore_single_shard() {
    for seed in 1..=3 {
        run(seed, 1, 140, 50);
    }
}

#[test]
fn adapter_matches_memstore_four_shards() {
    for seed in 20..=22 {
        run(seed, 4, 140, 60);
    }
}

/// The same comparison on the omap LSM engine (adr 0610): PG log / info omap, client omap, clones, removals, remounts.
#[test]
fn adapter_matches_memstore_omap_lsm() {
    with_omap_lsm(|| {
        for seed in 40..=42 {
            run(seed, 1, 140, 50);
        }
        run(43, 4, 140, 60);
    });
}

#[test]
#[ignore = "soak"]
fn adapter_matches_memstore_soak() {
    for seed in 100..130 {
        run(seed, if seed % 2 == 0 { 4 } else { 1 }, 500, 120);
    }
}

/// Review 2026-11-03 #10: a mutation of a PG the store does not hold is dropped (counted like `MemStore`) and fails the
/// store: the synchronous form reports it through `failure()`, never as applied.
#[test]
fn orphan_writes_fail_the_store() {
    let s = spg(1, 0);
    let epoch = |e| StoreTxn {
        ops: vec![StoreOp::PutEpoch(e)],
    };
    let (_d, mut ad, _) = new_adapter(32, 1, 1);
    let mut mem = MemStore::new();
    mem.submit(s, &epoch(7));
    ad.submit(s, &epoch(7));
    assert_eq!(ad.orphan_writes.get(), mem.orphan_writes);
    assert!(ad.load_pg(s).is_none());
    assert!(ad.failure().is_some(), "orphan write applied silently");
    // create -> remove -> late write must not resurrect it
    let (_d, mut ad, _) = new_adapter(32, 1, 2);
    for t in [StoreOp::CreatePg, StoreOp::RemovePg] {
        ad.submit(s, &StoreTxn { ops: vec![t] });
    }
    assert!(ad.failure().is_none());
    ad.submit(s, &epoch(9));
    assert!(ad.load_pg(s).is_none());
    assert!(ad.list_pgs().is_empty());
    assert!(ad.failure().is_some(), "late write applied silently");
    // split / merge into a PG that does not exist
    for op in [
        StoreOp::SplitOut {
            parent_bits: 1,
            children: vec![],
        },
        StoreOp::MergeIn {
            sources: vec![],
            bits: 1,
        },
    ] {
        let (_d, ad, _) = new_adapter(32, 1, 3);
        let r = ad.try_submit(s, &StoreTxn { ops: vec![op] });
        assert!(r.is_err(), "structural op on a missing PG: {r:?}");
        assert_eq!(ad.orphan_writes.get(), 1);
    }
}

#[test]
#[should_panic(expected = "epoch")]
fn comparison_is_not_vacuous_meta() {
    let (_d, mut ad, _) = new_adapter(32, 1, 1);
    let mut mem = MemStore::new();
    let s = spg(1, 0);
    let t = StoreTxn {
        ops: vec![StoreOp::CreatePg],
    };
    mem.submit(s, &t);
    ad.submit(s, &t);
    ad.submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::PutEpoch(3)],
        },
    );
    assert_same(&mem, &ad, s, "x");
}

#[test]
fn model_exercises_enough() {
    // a fixed run must end with a populated PG: objects, omap, log entries, missing items
    let (_d, mut ad, _) = new_adapter(64, 1, 5);
    let mut mem = MemStore::new();
    let s = spg(1, 0);
    let mut g = PgGen::new(s, 5);
    let mut exist = BTreeSet::new();
    let t = StoreTxn {
        ops: vec![StoreOp::CreatePg],
    };
    mem.submit(s, &t);
    ad.submit(s, &t);
    for _ in 0..60 {
        let mut t = StoreTxn::default();
        let e = g.entry(LogOp::MODIFY);
        t.push(StoreOp::LogAppend(vec![e]));
        let d = g.object_txn(&mut exist);
        t.push(StoreOp::ApplyTxn {
            middle: Default::default(),
            data: d.into(),
        });
        t.push(StoreOp::Missing(g.missing_items()));
        mem.submit(s, &t);
        ad.submit(s, &t);
    }
    let objs = ad.objects(s);
    assert!(objs.len() >= 5, "{} objects", objs.len());
    assert!(
        objs.values()
            .any(|o| !o.omap.is_empty() && !o.data.is_empty())
    );
    assert!(ad.load_pg(s).unwrap().log.log.len() == 60);
    assert!(!ad.load_pg(s).unwrap().missing.missing.is_empty());
    assert_same(&mem, &ad, s, "end");
    assert_same_objects(&mem, &ad, s, "end");
}
