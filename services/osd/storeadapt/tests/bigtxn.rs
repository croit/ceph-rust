// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Big PG transactions (ADR 0028): whole-log claims, big missing sets and bulk omap are ONE atomic store txn
//! (multi-record WAL chain), never Rejected for size.
mod common;
use common::*;
use denc::types::*;
use peering::store::{MemStore, PgStoreOps, Queued, StoreOp, StoreTxn};
use pgwire::{LogEntry, LogOp, MissingItem, PgLog};
use std::collections::BTreeSet;
use store::obj::StoreCfg;

fn missing(pool: i64, n: usize, epoch: u32) -> Vec<(Hobject, Option<MissingItem>)> {
    (0..n)
        .map(|i| {
            let h = Hobject::new(
                format!("rbd_data.1234.{i:016x}").as_bytes(),
                SnapId::NOSNAP,
                (i as u32).wrapping_mul(0x9e37_79b1) & !0x7,
                pool,
                b"",
            );
            let it = MissingItem::new(
                Eversion::new(epoch, 1000 + i as u64),
                Eversion::new(epoch, i as u64 % 50),
                i % 9 == 0,
            );
            (h, Some(it))
        })
        .collect()
}

fn multi_total(ad: &Ad) -> u64 {
    ad.with_store(|st| st.shards.iter().map(|s| s.sh.stats.multi_txns).sum())
}

fn adapter() -> (
    store::dev::SimDisk,
    Ad,
    store::dev::SimConfig,
    store::dev::SimImage,
) {
    let sim = sim_cfg(256, 5);
    let img = fresh_image(&sim, 1, 8192);
    let (d, a) = open(&img, &sim, &StoreCfg::default());
    (d, a, sim, img)
}

fn drain(ad: &mut Ad, n: usize) -> Vec<(SpgT, u64)> {
    let mut out = Vec::new();
    for _ in 0..1_000_000 {
        ad.poll_commits(&mut out);
        if out.len() >= n {
            break;
        }
        ad.with_store(|st| st.idle());
    }
    out
}

#[test]
fn log_replace_5000_entries_3000_dups_is_one_atomic_txn() {
    let (disk, mut ad, sim, _img) = adapter();
    let s = spg(1, 0);
    ad.submit_create(s);
    let mut mem = MemStore::new();
    mem.submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    let mut g = PgGen::new(s, 77);
    let all: Vec<LogEntry> = (0..8000).map(|_| g.entry(LogOp::MODIFY)).collect();
    let (d, l) = all.split_at(3000);
    let head = l.last().unwrap().version;
    let mut t = StoreTxn::default();
    t.push(StoreOp::LogReplace(Box::new(PgLog {
        head,
        tail: d.last().unwrap().version,
        log: l.iter().cloned().collect(),
        can_rollback_to: head,
        rollback_info_trimmed_to: head,
        dups: d.iter().map(|e| g.dup_of(e)).collect(),
    })));
    t.push(StoreOp::PutInfo(Box::new(g.info())));
    mem.submit(s, &t);
    assert_eq!(ad.queue(s, &t, 42), Queued::Pending);
    assert_eq!(ad.rejected.get(), 0);
    assert_eq!(drain(&mut ad, 1), vec![(s, 42)]);
    assert_eq!(
        multi_total(&ad),
        1,
        "must have been written as a multi-part chain"
    );
    assert_same(&mem, &ad, s, "claim");
    let loaded = ad.load_pg(s).unwrap();
    assert_eq!((loaded.log.log.len(), loaded.log.dups.len()), (5000, 3000));
    // power loss with only acked data: survives
    disk.crash_now();
    let img = disk.crash_image(store::dev::CrashPolicy::DROP_ALL);
    drop(ad);
    let (_d2, ad2) = open(&img, &sim, &StoreCfg::default());
    assert_same(&mem, &ad2, s, "after crash");
    // a second claim replaces it again (old 8000 keys deleted + 8000 new keys in one txn)
    let mut ad2 = ad2;
    let all: Vec<LogEntry> = (0..6000).map(|_| g.entry(LogOp::MODIFY)).collect();
    let (d, l) = all.split_at(1000);
    let head = l.last().unwrap().version;
    let mut t = StoreTxn::default();
    t.push(StoreOp::LogReplace(Box::new(PgLog {
        head,
        tail: d.last().unwrap().version,
        log: l.iter().cloned().collect(),
        can_rollback_to: head,
        rollback_info_trimmed_to: head,
        dups: d.iter().map(|e| g.dup_of(e)).collect(),
    })));
    mem.submit(s, &t);
    assert_eq!(ad2.queue(s, &t, 43), Queued::Pending);
    assert_eq!(drain(&mut ad2, 1), vec![(s, 43)]);
    assert_same(&mem, &ad2, s, "second claim");
    assert_eq!(ad2.rejected.get(), 0);
}

#[test]
fn missing_5000_plus_info_is_one_atomic_txn_and_clear_too() {
    let (_disk, mut ad, _sim, _img) = adapter();
    let s = spg(1, 0);
    ad.submit_create(s);
    let mut mem = MemStore::new();
    mem.submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    let mut g = PgGen::new(s, 78);
    let mut t = StoreTxn::default();
    t.push(StoreOp::Missing(missing(1, 5000, g.epoch)));
    t.push(StoreOp::PutInfo(Box::new(g.info())));
    mem.submit(s, &t);
    assert_eq!(ad.queue(s, &t, 1), Queued::Pending);
    assert_eq!(drain(&mut ad, 1).len(), 1);
    assert_eq!(ad.load_pg(s).unwrap().missing.len(), 5000);
    assert_same(&mem, &ad, s, "missing 5000");
    // clear + re-set in one go
    let mut t = StoreTxn::default();
    t.push(StoreOp::MissingClear {
        may_include_deletes: true,
    });
    t.push(StoreOp::Missing(missing(1, 4000, g.epoch + 1)));
    t.push(StoreOp::PutInfo(Box::new(g.info())));
    mem.submit(s, &t);
    assert_eq!(ad.queue(s, &t, 2), Queued::Pending);
    assert_eq!(drain(&mut ad, 1).len(), 1);
    assert_same(&mem, &ad, s, "missing replaced");
    assert_eq!(ad.rejected.get(), 0);
    assert!(multi_total(&ad) >= 1);
    // objects still fine
    let mut exist = BTreeSet::new();
    let mut t = StoreTxn::default();
    t.push(StoreOp::ApplyTxn {
        middle: Default::default(),
        data: g.object_txn(&mut exist).into(),
    });
    mem.submit(s, &t);
    ad.submit(s, &t);
    assert_same_objects(&mem, &ad, s, "objects");
}

#[test]
fn ops_after_remove_pg_are_refused_not_dropped() {
    // `RemovePg` deletes the whole collection: an op behind it in the same txn would be acknowledged but never applied
    let (_disk, mut ad, _sim, _img) = adapter();
    let s = spg(1, 0);
    ad.submit_create(s);
    let mut t = StoreTxn::default();
    t.push(StoreOp::PutEpoch(7));
    t.push(StoreOp::RemovePg);
    t.push(StoreOp::PutEpoch(9));
    assert!(
        matches!(ad.try_submit(s, &t), Err(store::obj::ObjError::Invalid(_))),
        "a txn with ops after RemovePg must be refused"
    );
    // nothing applied, the PG not deleted
    assert_eq!(ad.load_pg(s).map(|p| p.epoch), Some(0));
    assert!(ad.list_pgs().contains(&s));
    // the asynchronous path refuses it too instead of queueing a partial txn
    assert!(matches!(ad.queue(s, &t, 1), Queued::Rejected(_)));
    assert_eq!(ad.rejected.get(), 1);
    assert_eq!(ad.pending(), 0);
}

#[test]
fn txn_beyond_half_the_ring_is_rejected_not_partially_applied() {
    // ring 2048 blocks = 8 MiB: max chain ~ 4 MiB - 2 units
    let sim = sim_cfg(256, 6);
    let img = fresh_image(&sim, 1, 2048);
    let (_d, mut ad) = open(&img, &sim, &StoreCfg::default());
    let s = spg(1, 0);
    ad.submit_create(s);
    let mut g = PgGen::new(s, 79);
    let all: Vec<LogEntry> = (0..40_000).map(|_| g.entry(LogOp::MODIFY)).collect();
    let head = all.last().unwrap().version;
    let mut t = StoreTxn::default();
    t.push(StoreOp::LogReplace(Box::new(PgLog {
        head,
        tail: all[0].version,
        log: all.into(),
        can_rollback_to: head,
        rollback_info_trimmed_to: head,
        dups: Default::default(),
    })));
    assert!(matches!(ad.queue(s, &t, 1), Queued::Rejected(_)));
    assert_eq!(ad.load_pg(s).unwrap().log.log.len(), 0);
}
