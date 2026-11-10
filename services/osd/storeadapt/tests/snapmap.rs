// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! SnapMapper on the NVMe store (spec snaptrim 4): maintenance ops, same-txn atomicity with the object change
//! (crash at every IO boundary), differential against the in-memory model, migration, PG removal, scrub check.
mod common;
use common::*;
use denc::types::*;
use peering::snaps::MapOp;
use peering::store::{MemStore, PgStoreOps, StoreOp, StoreTxn};
use replwire::txn::*;
use replwire::{ObjectInfo, SnapSet};
use std::collections::BTreeSet;
use store::dev::{CrashPolicy, SimClock, SimDisk};
use store::fsck::fsck;
use store::obj::{StoreCfg, onode::fsck_refs};
use store::rng::Rng;

fn clone_h(name: &str, snap: u64) -> Hobject {
    Hobject::new(name.as_bytes(), SnapId(snap), 0x1234, 1, b"")
}

fn head_h(name: &str) -> Hobject {
    Hobject::new(name.as_bytes(), SnapId::NOSNAP, 0x1234, 1, b"")
}

fn create_clone(s: SpgT, c: &Hobject, snaps: &[u64]) -> StoreTxn {
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(s));
    let g = Ghobject::new(c.clone(), Ghobject::NO_GEN, s.shard);
    let ox = t.obj(&g);
    t.push(cx, TxnOp::Touch { oid: ox });
    t.push(
        cx,
        TxnOp::Write {
            oid: ox,
            off: 0,
            data: replwire::Data::new(b"clone-data"),
        },
    );
    let oi = oi_bytes(c, Eversion::new(2, 3), 10);
    t.push(
        cx,
        TxnOp::SetAttr {
            oid: ox,
            name: b"_",
            value: &oi,
        },
    );
    StoreTxn {
        ops: vec![
            StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            },
            StoreOp::SnapMap(vec![MapOp::Set {
                clone: c.clone(),
                snaps: snaps.to_vec(),
            }]),
        ],
    }
}

/// What a trim step's DELETE entry does to a clone: object gone + mapping gone, in one txn.
fn drop_clone(s: SpgT, c: &Hobject) -> StoreTxn {
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(s));
    let g = Ghobject::new(c.clone(), Ghobject::NO_GEN, s.shard);
    let ox = t.obj(&g);
    t.push(cx, TxnOp::Remove { oid: ox });
    StoreTxn {
        ops: vec![
            StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            },
            StoreOp::SnapMap(vec![MapOp::Remove { clone: c.clone() }]),
        ],
    }
}

fn create_pg(ad: &Ad, s: SpgT) {
    ad.submit_create(s);
}

#[test]
fn maintenance_ops_next_get_update_remove() {
    let (_d, ad, _) = new_adapter(64, 1, 1);
    let s = spg(1, 0);
    create_pg(&ad, s);
    let (a, b) = (clone_h("a", 8), clone_h("b", 8));
    ad.try_submit(s, &create_clone(s, &a, &[5, 7])).unwrap();
    ad.try_submit(s, &create_clone(s, &b, &[7])).unwrap();
    assert_eq!(ad.snapmap_next(s, 7, 10).unwrap().len(), 2);
    assert_eq!(ad.snapmap_next(s, 5, 10).unwrap(), vec![a.clone()]);
    assert_eq!(ad.snapmap_next(s, 7, 1).unwrap().len(), 1, "max honoured");
    assert!(ad.snapmap_next(s, 6, 10).unwrap().is_empty());
    assert_eq!(ad.snapmap_get(s, &a), Some(vec![5, 7]));
    // the forward index walked in pieces: one snap per entry, ascending, resumable from the returned key
    let start = peering::snaps::fwd_prefix(0);
    let (first, more) = ad.snapmap_scan(s, &start, 2).unwrap();
    assert_eq!(first, vec![5, 7]);
    let (rest, end) = ad
        .snapmap_scan(s, &more.expect("one entry left"), 2)
        .unwrap();
    assert_eq!((rest, end), (vec![7], None));
    assert_eq!(
        ad.snapmap_scan(s, &start, 10).unwrap(),
        (vec![5, 7, 7], None)
    );
    // MODIFY entry: shrink to [5]
    ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::SnapMap(vec![MapOp::Set {
                clone: a.clone(),
                snaps: vec![5],
            }])],
        },
    )
    .unwrap();
    assert_eq!(ad.snapmap_next(s, 7, 10).unwrap(), vec![b.clone()]);
    // DELETE entry (object + mapping)
    ad.try_submit(s, &drop_clone(s, &a)).unwrap();
    assert!(ad.snapmap_get(s, &a).is_none() && ad.snapmap_next(s, 5, 10).unwrap().is_empty());
    // removing again / a never-mapped clone is fine (ENOENT tolerated on replicas)
    ad.try_submit(s, &drop_clone(s, &a)).unwrap();
    // RemoveObject (recovery delete, backfill remove, divergent rewind) drops the mapping too
    ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::RemoveObject(b.clone())],
        },
    )
    .unwrap();
    assert!(ad.map_all(s).is_empty());
    // heads never enter the mapper through RemoveObject
    ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::RemoveObject(head_h("a"))],
        },
    )
    .unwrap();
}

#[test]
fn later_ops_of_one_txn_see_earlier_ones() {
    let (_d, ad, _) = new_adapter(64, 1, 2);
    let s = spg(1, 0);
    create_pg(&ad, s);
    let c = clone_h("o", 4);
    let set = |v: &[u64]| MapOp::Set {
        clone: c.clone(),
        snaps: v.to_vec(),
    };
    ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::SnapMap(vec![
                set(&[1, 2]),
                set(&[2, 3]),
                MapOp::Remove { clone: c.clone() },
                set(&[9]),
            ])],
        },
    )
    .unwrap();
    assert_eq!(ad.map_all(s), vec![(c.clone(), vec![9])]);
    for sn in [1, 2, 3] {
        assert!(
            ad.snapmap_next(s, sn, 5).unwrap().is_empty(),
            "stale forward key {sn}"
        );
    }
    assert_eq!(ad.snapmap_next(s, 9, 5).unwrap(), vec![c]);
}

#[test]
fn differential_against_the_memory_model() {
    let (_d, ad, _) = new_adapter(64, 1, 3);
    let s = spg(1, 0);
    let mut mem = MemStore::new();
    mem.submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    create_pg(&ad, s);
    let mut r = Rng::new(77);
    let clones: Vec<Hobject> = (0..12)
        .map(|i| clone_h(&format!("o{}", i % 6), 10 + i))
        .collect();
    for _ in 0..400 {
        let c = clones[(r.next_u64() % clones.len() as u64) as usize].clone();
        let op = match r.next_u64() % 4 {
            0 => MapOp::Remove { clone: c },
            _ => {
                let n = 1 + r.next_u64() % 3;
                let mut v: Vec<u64> = (0..n).map(|_| 1 + r.next_u64() % 9).collect();
                v.sort_unstable();
                v.dedup();
                MapOp::Set { clone: c, snaps: v }
            }
        };
        let t = StoreTxn {
            ops: vec![StoreOp::SnapMap(vec![op])],
        };
        ad.try_submit(s, &t).unwrap();
        mem.submit(s, &t);
    }
    let mut want = mem.pgs[&s].snapmap.all();
    want.sort();
    let mut have = ad.map_all(s);
    have.sort();
    assert_eq!(have, want);
    for sn in 1..10u64 {
        let w: BTreeSet<Hobject> = mem.snapmap_next(s, sn, 100).unwrap().into_iter().collect();
        let h: BTreeSet<Hobject> = ad.snapmap_next(s, sn, 100).unwrap().into_iter().collect();
        assert_eq!(h, w, "snap {sn}");
    }
}

#[test]
fn removing_the_pg_removes_the_mapper() {
    let (_d, ad, _) = new_adapter(64, 1, 4);
    let s = spg(1, 0);
    create_pg(&ad, s);
    for i in 0..20u64 {
        let c = clone_h(&format!("o{i}"), 5);
        ad.try_submit(s, &create_clone(s, &c, &[3, 4])).unwrap();
    }
    ad.remove_pg(s).unwrap();
    assert!(
        !ad.with_store(|st| st.coll_exists(&CollType(s))).unwrap(),
        "collection gone"
    );
    let rep = ad.with_store(|st| st.check(true)).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}

#[expect(non_snake_case)]
fn CollType(s: SpgT) -> CollT {
    CollT::Pg(s)
}

#[test]
fn migration_carries_the_mapper() {
    use storeadapt::migrate::ExportCursor;
    let (_d, src, _) = new_adapter(64, 1, 5);
    let s = spg(1, 0);
    create_pg(&src, s);
    for i in 0..30u64 {
        let c = clone_h(&format!("m{i}"), 6);
        src.try_submit(s, &create_clone(s, &c, &[4, 5])).unwrap();
    }
    let mut cur = ExportCursor::default();
    let mut ops = Vec::new();
    loop {
        let (o, last) = src.export_chunk(s, &mut cur, 1 << 12).unwrap();
        ops.extend(o);
        if last {
            break;
        }
    }
    let (_d2, dst, _) = new_adapter(64, 1, 6);
    dst.import_ops(s, ops).unwrap();
    let (mut a, mut b) = (src.map_all(s), dst.map_all(s));
    a.sort();
    b.sort();
    assert_eq!(a.len(), 30);
    assert_eq!(a, b);
    assert_eq!(dst.snapmap_next(s, 4, 100).unwrap().len(), 30);
}

#[test]
fn scrub_check_finds_missing_and_wrong_entries() {
    let (_d, ad, _) = new_adapter(64, 1, 7);
    let s = spg(1, 0);
    create_pg(&ad, s);
    // head with SnapSet: clones 8 (snaps 7,5) and 12 (snap 10)
    let head = head_h("o");
    let mut ss = SnapSet {
        seq: 12,
        clones: vec![SnapId(8), SnapId(12)],
        ..Default::default()
    };
    ss.clone_snaps.insert(SnapId(8), vec![SnapId(7), SnapId(5)]);
    ss.clone_snaps.insert(SnapId(12), vec![SnapId(10)]);
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(s));
    let g = Ghobject::new(head.clone(), Ghobject::NO_GEN, s.shard);
    let ox = t.obj(&g);
    t.push(cx, TxnOp::Touch { oid: ox });
    let ssb = denc::to_vec(&ss).unwrap();
    let oi = denc::to_vec(&ObjectInfo::new(head.clone())).unwrap();
    t.push(
        cx,
        TxnOp::SetAttr {
            oid: ox,
            name: b"snapset",
            value: &ssb,
        },
    );
    t.push(
        cx,
        TxnOp::SetAttr {
            oid: ox,
            name: b"_",
            value: &oi,
        },
    );
    ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            }],
        },
    )
    .unwrap();
    let (c8, c12) = (clone_h("o", 8), clone_h("o", 12));
    ad.try_submit(s, &create_clone(s, &c8, &[7])).unwrap(); // wrong: expected [5,7]
    ad.try_submit(s, &create_clone(s, &c12, &[10])).unwrap();
    ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::SnapMap(vec![MapOp::Remove { clone: c12.clone() }])],
        },
    )
    .unwrap(); // missing
    let (ops, msgs) = ad.snapmap_check(s, &Hobject::MIN(), &Hobject::MAX());
    assert_eq!(ops.len(), 2, "{msgs:?}");
    assert_eq!(msgs.len(), 2);
    ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::SnapMap(ops)],
        },
    )
    .unwrap();
    assert_eq!(ad.snapmap_get(s, &c8), Some(vec![5, 7]));
    assert_eq!(ad.snapmap_get(s, &c12), Some(vec![10]));
    let (again, _) = ad.snapmap_check(s, &Hobject::MIN(), &Hobject::MAX());
    assert!(again.is_empty());
}

/// Crash at every device event of a create / trim sequence: after remount, a clone object exists iff its mapping
/// does (one txn), and the acked prefix is intact.
#[test]
fn crash_keeps_object_and_mapping_atomic() {
    let sim = sim_cfg(64, 11);
    let img = fresh_image(&sim, 1, 512);
    let s = spg(1, 0);
    let clones: Vec<Hobject> = (0..6).map(|i| clone_h(&format!("c{i}"), 20)).collect();
    let mut txns: Vec<StoreTxn> = clones.iter().map(|c| create_clone(s, c, &[3, 4])).collect();
    for c in clones.iter().step_by(2) {
        txns.push(drop_clone(s, c));
    }
    let cfg = StoreCfg::default();
    let mut k = 1u64;
    let mut crashes = 0;
    loop {
        let (disk, ad) = open(&img, &sim, &cfg);
        ad.submit_create(s);
        disk.arm_crash(disk.events() + k);
        let mut acked = 0;
        for t in &txns {
            match ad.try_submit(s, t) {
                Ok(()) => acked += 1,
                Err(_) if disk.crashed() => break,
                Err(e) => panic!("submit: {e}"),
            }
        }
        let crashed = disk.crashed();
        disk.crash_now();
        let cimg = disk.crash_image(CrashPolicy::MIXED);
        drop(ad);
        {
            let d = SimDisk::from_image(&cimg, sim.clone());
            let mut dev = d.queue();
            let mut clk = SimClock::default();
            fsck(&mut dev, &mut clk, Some(&fsck_refs)).expect("fsck");
        }
        let (_d2, ad2) = open(&cimg, &sim, &cfg);
        if ad2.pg_is_complete(s) {
            let mapped: BTreeSet<Hobject> = ad2.map_all(s).into_iter().map(|(c, _)| c).collect();
            let present: BTreeSet<Hobject> = ad2.all_object_names(s).into_iter().collect();
            assert_eq!(mapped, present, "crash event {k}: object set != mapped set");
            // acked txns are durable: replay on the model
            let mut mem = MemStore::new();
            mem.submit(
                s,
                &StoreTxn {
                    ops: vec![StoreOp::CreatePg],
                },
            );
            for t in &txns[..acked] {
                mem.submit(s, t);
            }
            let want: BTreeSet<Hobject> =
                mem.pgs[&s].snapmap.all().into_iter().map(|x| x.0).collect();
            let more: BTreeSet<Hobject> = if acked < txns.len() {
                mem.submit(s, &txns[acked]);
                mem.pgs[&s].snapmap.all().into_iter().map(|x| x.0).collect()
            } else {
                want.clone()
            };
            assert!(
                mapped == want || mapped == more,
                "crash event {k}: lost an acked txn"
            );
        }
        if !crashed {
            break;
        }
        crashes += 1;
        k += 1;
    }
    assert!(
        crashes > 10,
        "the sequence must have crashed at many points, got {crashes}"
    );
}

/// "Index empty" and "index unreadable" are different answers: an undecodable entry must not read as empty
/// (the trimmer would record the snap purged while a clone still exists).
#[test]
fn snapmap_next_distinguishes_empty_from_damaged() {
    let (_d, ad, _) = new_adapter(64, 1, 1);
    let s = spg(1, 0);
    create_pg(&ad, s);
    let a = clone_h("a", 8);
    ad.try_submit(s, &create_clone(s, &a, &[7])).unwrap();
    assert_eq!(ad.snapmap_next(s, 7, 10).unwrap(), vec![a.clone()]);
    assert!(
        ad.snapmap_next(s, 9, 10).unwrap().is_empty(),
        "no clone: empty"
    );
    // damage the forward entry of snap 7 in place
    let key = {
        let mut k = peering::snaps::fwd_prefix(7);
        k.extend_from_slice(b"zz");
        k
    };
    let mut t = store::obj::OTxn::new();
    t.omap_set(
        CollT::Pg(s),
        &storeadapt::snapmap::mapper_obj(s),
        &key,
        &[0xde, 0xad],
    );
    ad.with_store(|st| st.commit(&t)).unwrap();
    assert!(
        ad.snapmap_next(s, 7, 10).is_err(),
        "undecodable entry must be an error, not skipped"
    );
    assert!(
        ad.snapmap_next(s, 9, 10).unwrap().is_empty(),
        "other snaps unaffected"
    );
}

#[test]
fn rollback_mapping_read_distinguishes_absence_from_corruption() {
    use peering::StoreReadError;
    let (_d, ad, _) = new_adapter(64, 1, 1);
    let s = spg(1, 0);
    create_pg(&ad, s);
    let clone = clone_h("rollback-mapping", 8);
    assert_eq!(ad.snapmap_get_checked(s, &clone), Ok(None));
    ad.try_submit(s, &create_clone(s, &clone, &[7])).unwrap();
    assert_eq!(ad.snapmap_get_checked(s, &clone), Ok(Some(vec![7])));
    for value in [
        vec![0xde, 0xad],
        peering::snaps::enc_rev_val(&clone_h("foreign-clone", 8), &[7]),
    ] {
        let key = peering::snaps::rev_key(&clone);
        let mut t = store::obj::OTxn::new();
        t.omap_set(
            CollT::Pg(s),
            &storeadapt::snapmap::mapper_obj(s),
            &key,
            &value,
        );
        ad.with_store(|st| st.commit(&t)).unwrap();
        assert_eq!(
            ad.snapmap_get_checked(s, &clone),
            Err(StoreReadError::Corrupt)
        );
    }
}
