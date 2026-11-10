// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG migration between stores (adr 0031): a copy is complete only after its last op, the import of a batch is ONE
//! atomic system transaction.
mod common;
use common::*;
use denc::types::*;
use peering::store::{PgStoreOps, StoreOp, StoreTxn};
use pgwire::LogDup;
use storeadapt::migrate::{ExportCursor, MIG_DONE_KEY, MigOp};

fn txns(ad: &Ad) -> u64 {
    ad.with_store(|st| st.shards.iter().map(|s| s.sh.stats.txns).sum())
}

/// A PG whose pgmeta has keys sorting behind `_info` (dups), like a PG with a trimmed log.
fn source(s: SpgT) -> Ad {
    let (_d, mut ad, _) = new_adapter(64, 1, 1);
    let mut g = PgGen::new(s, 7);
    let info = g.info();
    let dups: Vec<LogDup> = (1..=40)
        .map(|v| LogDup {
            version: Eversion::new(5, v),
            ..Default::default()
        })
        .collect();
    ad.submit(
        s,
        &StoreTxn {
            ops: vec![
                StoreOp::CreatePg,
                StoreOp::PutEpoch(5),
                StoreOp::PutInfo(Box::new(info)),
                StoreOp::LogDups(dups),
            ],
        },
    );
    assert!(ad.pg_is_complete(s));
    ad
}

fn export_all(ad: &Ad, s: SpgT) -> Vec<MigOp> {
    let mut cur = ExportCursor::default();
    let mut all = Vec::new();
    loop {
        let (ops, last) = ad.export_chunk(s, &mut cur, 1 << 20).unwrap();
        all.extend(ops);
        if last {
            return all;
        }
    }
}

#[test]
fn sparse_export_bounds_examined_bytes_and_preserves_holes() {
    let s = spg(4, 9);
    let (_d, ad, _) = new_adapter(64, 1, 5);
    let (_dd, dst, _) = new_adapter(64, 1, 6);
    ad.submit_create(s);
    let h = Hobject::new(b"sparse", SnapId::NOSNAP, 1, 4, b"");
    let g = Ghobject::new(h.clone(), Ghobject::NO_GEN, s.shard);
    let c = CollT::Pg(s);
    let size = 16 << 20;
    ad.with_store(|st| {
        let mut t = store::obj::OTxn::new();
        t.touch(c, &g);
        t.truncate(c, &g, size);
        st.commit(&t).unwrap();
    });
    let mut cur = ExportCursor::default();
    let budget = 64 << 10;
    let (ops, last) = ad.export_chunk(s, &mut cur, budget).unwrap();
    assert!(!last, "sparse bytes must consume the export work budget");
    let pos = cur
        .cur
        .as_ref()
        .expect("sparse export must yield mid-object");
    assert_eq!(pos.oid, g);
    assert!(pos.off > 0 && pos.off <= budget as u64);
    dst.import_ops(s, ops).unwrap();
    let mut finished = false;
    for _ in 0..1024 {
        let before = cur.cur.as_ref().map_or(0, |p| p.off);
        let (ops, last) = ad.export_chunk(s, &mut cur, budget).unwrap();
        if let Some(p) = &cur.cur {
            assert!(p.off - before <= budget as u64);
        }
        assert!(
            !ops.iter().any(|op| matches!(op, MigOp::Data { .. })),
            "holes must stay unallocated"
        );
        dst.import_ops(s, ops).unwrap();
        if last {
            finished = true;
            break;
        }
    }
    assert!(
        finished,
        "export did not finish within its byte-derived bound"
    );
    assert_eq!(
        dst.with_store(|st| st.stat(&c, &g).unwrap().unwrap().size),
        size
    );
    assert_eq!(
        dst.with_store(|st| st.read(&c, &g, size - 4096, 4096).unwrap()),
        vec![0; 4096]
    );
}

#[test]
fn empty_objects_consume_export_work_budget() {
    let s = spg(4, 9);
    let (_d, ad, _) = new_adapter(64, 1, 5);
    ad.submit_create(s);
    ad.with_store(|st| {
        let mut t = store::obj::OTxn::new();
        for i in 0..128 {
            let g = Ghobject::new(
                Hobject::new(format!("empty-{i}").as_bytes(), SnapId::NOSNAP, i, 4, b""),
                Ghobject::NO_GEN,
                s.shard,
            );
            t.touch(CollT::Pg(s), &g);
        }
        st.commit(&t).unwrap();
    });
    let budget = std::mem::size_of::<MigOp>();
    let (ops, last) = ad
        .export_chunk(s, &mut ExportCursor::default(), budget)
        .unwrap();
    assert!(!last);
    assert_eq!(
        ops.iter()
            .filter(|op| matches!(op, MigOp::Obj { .. }))
            .count(),
        1
    );
}

#[test]
fn an_export_refuses_a_source_that_shrank_under_the_copy() {
    // The plan's size comes from one stat; a source that shrank since then returns short reads. Skipping them would
    // leave the rest of the planned size as a hole in the copy: the export must refuse instead.
    let s = spg(4, 9);
    let (_d, ad, _) = new_adapter(64, 1, 5);
    ad.submit_create(s);
    let g = Ghobject::new(
        Hobject::new(b"big", SnapId::NOSNAP, 1, 4, b""),
        Ghobject::NO_GEN,
        s.shard,
    );
    let c = CollT::Pg(s);
    ad.with_store(|st| {
        let blk = vec![7u8; 256 << 10];
        let mut t = store::obj::OTxn::new();
        t.touch(c, &g);
        for i in 0..12u64 {
            t.write(c, &g, i * (256 << 10), &blk);
        }
        st.commit(&t).unwrap();
    });
    let mut cur = ExportCursor::default();
    let mut started = false;
    for _ in 0..8 {
        let (ops, last) = ad.export_chunk(s, &mut cur, 1 << 16).unwrap();
        assert!(!last, "the export ended before the first data chunk");
        if ops
            .iter()
            .any(|o| matches!(o, MigOp::Data { data, .. } if !data.is_empty()))
        {
            started = true;
            break;
        }
    }
    assert!(started, "no data chunk exported");
    let copied = cur.cur.as_ref().expect("copy in progress").off;
    ad.with_store(|st| {
        let mut t = store::obj::OTxn::new();
        // End the source at the continuation offset, regardless of the export slice size.
        t.truncate(c, &g, copied);
        st.commit(&t).unwrap();
    });
    match ad.export_chunk(s, &mut cur, 1 << 16) {
        Err(store::obj::ObjError::Eio(_)) => {}
        Err(e) => panic!("a short read must fail the copy with EIO, got {e:?}"),
        Ok(_) => panic!("a short read must fail the copy, not skip the rest of the planned size"),
    }
}

#[test]
fn a_copy_is_complete_only_with_its_last_op() {
    let s = spg(4, 3);
    let src = source(s);
    let ops = export_all(&src, s);
    assert!(
        matches!(ops.last(), Some(MigOp::Omap { kv, .. }) if kv[0].0 == MIG_DONE_KEY),
        "the completion marker is the very last op"
    );
    let (_d, dst, _) = new_adapter(64, 1, 2);
    let n = ops.len();
    for (i, op) in ops.into_iter().enumerate() {
        dst.import_ops(s, vec![op]).unwrap();
        // `_info` is in long before the end: a crash here must not make the half copy look complete
        assert_eq!(dst.pg_is_complete(s), i + 1 == n, "after op {i} of {n}");
    }
    assert!(dst.load_pg(s).is_some());
}

#[test]
fn mig_bytes_sums_engine_omap_and_the_copy_carries_it() {
    let s = spg(4, 21);
    let tree = {
        let (_d, mut ad, _) = new_adapter(64, 1, 41);
        ad.submit(
            s,
            &StoreTxn {
                ops: vec![StoreOp::CreatePg],
            },
        );
        let mut g = PgGen::new(s, 41);
        let mut exist = std::collections::BTreeSet::new();
        for _ in 0..60 {
            let d = g.object_txn(&mut exist);
            ad.submit(
                s,
                &StoreTxn {
                    ops: vec![StoreOp::ApplyTxn {
                        middle: Default::default(),
                        data: d.into(),
                    }],
                },
            );
        }
        ad
    };
    let want = tree.mig_bytes(s).unwrap();
    with_omap_lsm(|| {
        let (_d, mut engine, _) = new_adapter(64, 1, 41);
        engine.submit(
            s,
            &StoreTxn {
                ops: vec![StoreOp::CreatePg],
            },
        );
        let mut g = PgGen::new(s, 41);
        let mut exist = std::collections::BTreeSet::new();
        for _ in 0..60 {
            let d = g.object_txn(&mut exist);
            engine.submit(
                s,
                &StoreTxn {
                    ops: vec![StoreOp::ApplyTxn {
                        middle: Default::default(),
                        data: d.into(),
                    }],
                },
            );
        }
        // the same objects and omap keys on both formats: one exact headroom number
        assert_eq!(engine.mig_bytes(s).unwrap(), want);
        // the copy carries every key: export from the engine store, import into a fresh engine store
        let c = CollT::Pg(s);
        let mut src_omap = 0usize;
        let mut cur = Ghobject::MIN();
        loop {
            let (objs, next) = engine.with_store(|st| st.list(&c, &cur, None, 64).unwrap());
            for o in &objs {
                src_omap += engine
                    .with_store(|st| st.omap_all(&c, o).unwrap())
                    .iter()
                    .map(|(k, v)| k.len() + v.len())
                    .sum::<usize>();
            }
            match next {
                Some(n) => cur = n,
                None => break,
            }
        }
        assert!(src_omap > 0, "the fixture has omap");
        let ops = export_all(&engine, s);
        let (_d2, dst, _) = new_adapter(64, 1, 42);
        dst.import_ops(s, ops).unwrap();
        assert!(dst.pg_is_complete(s));
        let mut cur = Ghobject::MIN();
        loop {
            let (objs, next) = engine.with_store(|st| st.list(&c, &cur, None, 64).unwrap());
            for o in &objs {
                if o.hobj.is_temp() || o.is_pgmeta() {
                    continue; // temps stay at the source, pgmeta gains the migration markers
                }
                let a = engine.with_store(|st| st.omap_all(&c, o).unwrap());
                let b = dst.with_store(|st| st.omap_all(&c, o).unwrap());
                assert_eq!(a, b, "omap of {o:?}");
            }
            match next {
                Some(n) => cur = n,
                None => break,
            }
        }
    });
}

fn mig_obj(i: u8) -> Ghobject {
    Ghobject::new(
        Hobject::new(
            format!("o{i}").as_bytes(),
            SnapId::NOSNAP,
            u32::from(i),
            4,
            b"",
        ),
        0,
        ShardId::NO_SHARD,
    )
}

/// The leftover of a migration a crash interrupted (no pgmeta yet, so indistinguishable from a split child) is dropped
/// when the PG migrates in again: objects deleted at the source in between do not come back with the new copy.
#[test]
fn a_new_migration_drops_an_interrupted_copy() {
    let s = spg(4, 5);
    let (_d, dst, _) = new_adapter(64, 1, 3);
    let obj = |i: u8| MigOp::Obj {
        oid: mig_obj(i),
        attrs: vec![],
        hdr: vec![],
    };
    dst.import_ops(s, vec![MigOp::Coll { bits: 3 }, obj(0), obj(1)])
        .unwrap();
    assert!(!dst.pg_is_complete(s));
    // o0 was deleted at the source meanwhile: the next copy carries o1 only
    dst.import_ops(s, vec![MigOp::Coll { bits: 3 }, obj(1)])
        .unwrap();
    let c = storeadapt::pg_coll(s);
    dst.with_store(|st| {
        assert!(
            !st.exists(&c, &mig_obj(0)).unwrap(),
            "deleted object resurrected"
        );
        assert!(st.exists(&c, &mig_obj(1)).unwrap());
    });
}

#[test]
fn a_batch_imports_as_one_transaction() {
    let s = spg(4, 5);
    let (_d, dst, _) = new_adapter(64, 1, 3);
    let mut ops = vec![MigOp::Coll { bits: 3 }];
    for i in 0..5u8 {
        let oid = Ghobject::new(
            Hobject::new(
                format!("o{i}").as_bytes(),
                SnapId::NOSNAP,
                u32::from(i),
                4,
                b"",
            ),
            0,
            ShardId::NO_SHARD,
        );
        ops.push(MigOp::Obj {
            oid: oid.clone(),
            attrs: vec![(b"a".to_vec(), vec![i])],
            hdr: vec![],
        });
        ops.push(MigOp::Omap {
            oid: oid.clone(),
            kv: vec![(b"k".to_vec(), vec![i])],
        });
        ops.push(MigOp::Data {
            oid: oid.clone(),
            off: 0,
            data: vec![i; 5000],
        });
        ops.push(MigOp::Size { oid, size: 5000 });
    }
    let before = txns(&dst);
    dst.import_ops(s, ops).unwrap();
    assert_eq!(txns(&dst) - before, 1);
}

#[test]
fn import_into_a_full_store_uses_the_reserves() {
    use store::obj::{OTxn, StoreCfg};
    let sim = sim_cfg(48, 11);
    let img = fresh_image(&sim, 1, 1024);
    let (_d, dst) = open(&img, &sim, &StoreCfg::default());
    let s = spg(4, 1);
    let other = CollT::Pg(spg(2, 0));
    let blob = vec![0x5Au8; 100_000];
    dst.with_store(|st| {
        let mut t = OTxn::new();
        t.mkcoll(other);
        st.commit(&t).unwrap();
        let mut n = 0u32;
        while st.write_room(&other, 100_000, 0) {
            let h = Hobject::new(format!("f{n}").as_bytes(), SnapId::NOSNAP, n, 2, b"");
            let mut t = OTxn::new();
            t.write(
                other,
                &Ghobject::new(h, Ghobject::NO_GEN, ShardId::NO_SHARD),
                0,
                &blob,
            );
            t.sys = true;
            st.commit(&t).unwrap();
            n += 1;
        }
    });
    assert!(!dst.write_room(s, 100_000, 0));
    // admitted at the source: the copy must land, the pgmeta marker included
    let src = source(s);
    let mut ops = export_all(&src, s);
    let big = Ghobject::new(
        Hobject::new(b"big", SnapId::NOSNAP, 1, 4, b""),
        0,
        ShardId::NO_SHARD,
    );
    let at = ops.len() - 1;
    ops.splice(
        at..at,
        [
            MigOp::Obj {
                oid: big.clone(),
                attrs: vec![],
                hdr: vec![],
            },
            MigOp::Data {
                oid: big.clone(),
                off: 0,
                data: vec![7; 300_000],
            },
            MigOp::Size {
                oid: big,
                size: 300_000,
            },
        ],
    );
    dst.import_ops(s, ops).unwrap();
    assert!(dst.pg_is_complete(s));
}
