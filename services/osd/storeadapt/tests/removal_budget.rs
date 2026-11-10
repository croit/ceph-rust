// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Deletion batches count user objects, not the retained pgmeta/SnapMapper prefix.
mod common;
use common::*;
use denc::types::*;
use peering::snaps::MapOp;
use peering::store::{PgStoreOps, StoreOp, StoreTxn};
use replwire::txn::{Transaction, TxnOp};
use store::dev::CrashPolicy;
use store::obj::StoreCfg;

fn populated(ad: &Ad, s: SpgT) {
    ad.submit_create(s);
    let h = Hobject::new(b"clone", SnapId(7), s.pgid.seed, s.pgid.pool as i64, b"");
    let oid = Ghobject::new(h.clone(), Ghobject::NO_GEN, s.shard);
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(s));
    let ox = t.obj(&oid);
    t.push(cx, TxnOp::Touch { oid: ox });
    t.push(
        cx,
        TxnOp::Write {
            oid: ox,
            off: 0,
            data: replwire::Data::new(b"value"),
        },
    );
    ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![
                StoreOp::ApplyTxn {
                    middle: Default::default(),
                    data: t.encode_v9().unwrap().into(),
                },
                StoreOp::SnapMap(vec![MapOp::Set {
                    clone: h,
                    snaps: vec![3, 5],
                }]),
            ],
        },
    )
    .unwrap();
    // Exactly the problematic layout: both metadata objects precede the user object.
    let (prefix, next) = ad
        .with_store(|st| st.list(&CollT::Pg(s), &Ghobject::MIN(), None, 2))
        .unwrap();
    assert_eq!(prefix.len(), 2);
    assert!(prefix.iter().all(Ghobject::is_pgmeta));
    assert_eq!(next, Some(oid));
}

#[test]
fn one_object_batches_do_not_mistake_two_metadata_objects_for_an_empty_pg() {
    for shard in [ShardId::NO_SHARD, ShardId(0)] {
        for asynchronous in [false, true] {
            let (disk, ad, sim) = new_adapter(64, 1, 17);
            let mut s = spg(1, 0);
            s.shard = shard;
            populated(&ad, s);
            let keeper = spg(2, 0);
            ad.submit_create(keeper);
            ad.remove_batch.set(1);
            if asynchronous {
                ad.remove_pg_async(s).unwrap();
                assert!(
                    ad.step_removals(1).unwrap(),
                    "first CPU-bounded batch queued"
                );
                let mut complete = false;
                for _ in 0..1000 {
                    if !ad.step_removals_sync().unwrap() {
                        complete = true;
                        break;
                    }
                }
                assert!(complete, "bounded removal driver made no progress");
            } else {
                ad.remove_pg(s).unwrap();
            }
            assert!(!ad.list_pgs().contains(&s));
            assert!(ad.list_pgs().contains(&keeper));
            ad.with_store(|st| {
                assert!(!st.coll_exists(&CollT::Pg(s)).unwrap());
                let report = st.check(true).unwrap();
                assert!(report.errors.is_empty(), "{:?}", report.errors);
            });
            disk.crash_now();
            let image = disk.crash_image(CrashPolicy::DROP_ALL);
            drop(ad);
            let (_reopened_disk, reopened) = open(&image, &sim, &StoreCfg::default());
            assert!(
                !reopened.list_pgs().contains(&s),
                "durable deletion survived replay"
            );
            assert!(reopened.list_pgs().contains(&keeper));
        }
    }
}

#[test]
fn a_queued_deletion_hides_the_persisted_pg_state() {
    // Every peering read answers empty/absent for a PG whose deletion is queued; the persisted state and the objects
    // must not be the one exception.
    let (_disk, ad, _sim) = new_adapter(64, 1, 19);
    let s = spg(1, 0);
    populated(&ad, s);
    assert!(ad.pg_is_complete(s));
    assert!(!ad.objects(s).is_empty());
    ad.remove_pg_async(s).unwrap();
    assert!(
        ad.load_pg(s).is_none(),
        "a PG being deleted has no persisted state"
    );
    assert!(!ad.pg_is_complete(s) && !ad.mig_complete(s));
    assert!(ad.objects(s).is_empty(), "deleted objects must not show up");
    assert!(!ad.list_pgs().contains(&s));
    assert_eq!(ad.object_stats(s), (0, 0));
}

#[test]
fn a_completed_pg_removal_does_not_hide_objects_in_the_next_pg() {
    let (_disk, ad, _) = new_adapter(64, 1, 18);
    let empty = spg(1, 0);
    let next = spg(1, 1);
    ad.submit_create(empty);
    populated(&ad, next);
    ad.remove_pg(empty).unwrap(); // the closing txn sets the next adaptive batch to zero
    ad.remove_pg(next).unwrap(); // clamped to one; both metadata entries still must be skipped
    assert!(ad.list_pgs().is_empty());
    ad.with_store(|st| assert!(st.list_colls().unwrap().is_empty()));
}
