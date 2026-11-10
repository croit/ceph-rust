// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Regression tests for the OSD review fixes.
mod common;
use common::*;
use denc::types::*;
use peering::store::{PgStoreOps, StoreOp, StoreTxn};
use replwire::txn::{Transaction, TxnOp};

fn data_object(ad: &Ad, pg: SpgT, size: usize) -> Hobject {
    let h = Hobject::new(b"data", SnapId::NOSNAP, 3, 1, b"");
    let g = Ghobject::new(h.clone(), Ghobject::NO_GEN, pg.shard);
    let data = vec![8u8; size];
    let oi = oi_bytes(&h, Eversion::new(1, 1), size as u64);
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(pg));
    let o = t.obj(&g);
    t.push(
        c,
        TxnOp::Write {
            oid: o,
            off: 0,
            data: replwire::Data::new(&data),
        },
    );
    t.push(
        c,
        TxnOp::SetAttr {
            oid: o,
            name: b"_",
            value: &oi,
        },
    );
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            }],
        },
    )
    .unwrap();
    h
}

#[test]
fn review_recovery_reads_outside_requested_subset() {
    let (_disk, ad, _sim) = new_adapter(128, 1, 902);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let h = data_object(&ad, pg, 4 << 20);
    let mut ri = ad.recovery_info_checked(pg, &h).unwrap();
    ri.copy_subset = [(3 << 20, 4096)].into_iter().collect();
    let op = ad
        .build_push(pg, &ri, &Default::default(), 1 << 20, 1024)
        .unwrap();
    assert_eq!(op.data.len(), 4096);
    assert_eq!(op.data_included, [(3 << 20, 4096)].into_iter().collect());
    assert_eq!(op.after_progress.data_recovered_to, (3 << 20) + 4096);
    assert!(op.after_progress.data_complete);
}

#[test]
fn review_snapshot_clone_shares_data_blocks() {
    let (_disk, ad, _sim) = new_adapter(128, 1, 903);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let h = data_object(&ad, pg, 4 << 20);
    let src = Ghobject::new(h.clone(), Ghobject::NO_GEN, pg.shard);
    let mut dst = src.clone();
    dst.hobj.snap = SnapId(3);
    let before = ad.with_store(|st| (st.statfs().used_bytes, st.shards[0].stats.read_blocks));
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(pg));
    let s = t.obj(&src);
    let d = t.obj(&dst);
    t.push(
        c,
        TxnOp::Clone {
            oid: s,
            dest_oid: d,
        },
    );
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            }],
        },
    )
    .unwrap();
    let after = ad.with_store(|st| (st.statfs().used_bytes, st.shards[0].stats.read_blocks));
    // OQ 31 fixed (adr 0021 am. 32): the clone references the head's blocks, no data read or written
    assert!(after.0 - before.0 < 64 << 10, "{before:?} -> {after:?}");
    assert_eq!(after.1 - before.1, 0);
    assert_eq!(st_shared(&ad), 1);
}

#[test]
fn review_scrub_swallows_corrupt_name_index_error() {
    let (_disk, ad, _sim) = new_adapter(128, 1, 904);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    data_object(&ad, pg, 4096);
    ad.with_store(|st| {
        let rows = st.shards[0].sh.dump_blocking(&mut st.clk)?;
        let ck = store::obj::keys::coll_key(&CollT::Pg(pg));
        let ci = store::obj::onode::CollInfo::decode(
            rows.iter()
                .find(|(k, _)| k.as_slice() == ck.as_slice())
                .unwrap()
                .1,
        )
        .unwrap();
        let bad = Ghobject::new(
            Hobject::new(b"zzz", SnapId::NOSNAP, 3, 1, b""),
            Ghobject::NO_GEN,
            pg.shard,
        );
        let mut key = store::obj::keys::name_key_of(ci.id, &bad);
        key.pop();
        let mut txn = store::shard::Txn::new(999);
        txn.put(&key, &1u64.to_le_bytes());
        st.shards[0].sh.submit(txn).unwrap();
        assert!(st.list(&CollT::Pg(pg), &Ghobject::MIN(), None, 64).is_err());
        Ok::<(), store::obj::ObjError>(())
    })
    .unwrap();
    let part = ad.build_scrub_map(pg, &Hobject::MIN(), &Hobject::MAX(), true, 64, 1 << 20);
    assert!(part.objects.is_empty());
    assert!(
        part.error
            .as_deref()
            .is_some_and(|e| e.contains("scrub list"))
    );
}

#[test]
fn review_memory_floor_exceeds_process_budget() {
    let budget = 128u64 << 20;
    assert!(store::obj::StoreCfg::for_memory(budget, 32).is_err());
    assert!(store::obj::StoreCfg::for_memory(budget, 1).is_ok());
}

#[test]
#[ignore = "diagnostic simulator timing, not a production throughput benchmark"]
fn review_fragmented_delete_scaling() {
    for n in [1024usize, 2048, 4096, 8192] {
        let (_disk, ad, _sim) = new_adapter(256, 1, 905);
        let pg = spg(1, 0);
        ad.submit_create(pg);
        let g = Ghobject::new(
            Hobject::new(b"fragmented", SnapId::NOSNAP, 3, 1, b""),
            Ghobject::NO_GEN,
            pg.shard,
        );
        let cid = CollT::Pg(pg);
        ad.with_store(|st| {
            let data = vec![8u8; 4096];
            for start in (0..n).step_by(1024) {
                let mut t = store::obj::OTxn::new();
                for i in start..(start + 1024).min(n) {
                    t.write(cid, &g, i as u64 * 4096, &data);
                }
                st.commit(&t).unwrap();
            }
            st.checkpoint().unwrap();
            let exts = st.shards[0]
                .sh
                .dump_blocking(&mut st.clk)
                .unwrap()
                .iter()
                .filter(|(k, _)| k[0] == store::obj::keys::T_EXT)
                .count();
            assert_eq!(exts, n);
            let mut t = store::obj::OTxn::new();
            t.remove(cid, &g);
            let begin = std::time::Instant::now();
            st.commit(&t).unwrap();
            println!(
                "review delete: {n} extents, sorted overlap validation, {:?}",
                begin.elapsed()
            );
        });
    }
}

#[test]
fn review_clone_bypasses_admission_then_exceeds_wal() {
    let (_disk, ad, _sim) = new_adapter(256, 1, 901);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let src = Ghobject::new(
        Hobject::new(b"src", SnapId::NOSNAP, 1, 1, b""),
        Ghobject::NO_GEN,
        pg.shard,
    );
    let dst = Ghobject::new(
        Hobject::new(b"dst", SnapId(3), 1, 1, b""),
        Ghobject::NO_GEN,
        pg.shard,
    );
    // Build an object whose omap is legal in incremental updates, but exceeds half a 4 MiB WAL as one clone.
    for batch in 0..6 {
        let keys: Vec<String> = (0..200).map(|i| format!("{batch}-{i:06}")).collect();
        let val = incompressible(2000, batch as u64);
        let mut t = Transaction::new();
        let c = t.coll(&CollT::Pg(pg));
        let o = t.obj(&src);
        t.push(
            c,
            TxnOp::OmapSetKeys {
                oid: o,
                pairs: keys
                    .iter()
                    .map(|k| (k.as_bytes(), val.as_slice()))
                    .collect(),
            },
        );
        ad.try_submit(
            pg,
            &StoreTxn {
                ops: vec![StoreOp::ApplyTxn {
                    middle: Default::default(),
                    data: t.encode_v9().unwrap().into(),
                }],
            },
        )
        .unwrap();
    }
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(pg));
    let s = t.obj(&src);
    let d = t.obj(&dst);
    t.push(
        c,
        TxnOp::Clone {
            oid: s,
            dest_oid: d,
        },
    );
    let wire: bytes::Bytes = t.encode_v9().unwrap().into();
    assert_eq!(
        ad.check_write(pg, &Default::default(), &wire),
        Err(peering::WriteErr::TooBig(denc::errno::EMSGSIZE))
    );
    let result = ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: wire,
            }],
        },
    );
    assert_eq!(result, Err(store::obj::ObjError::TooLarge));
}

#[test]
fn partial_recovery_crosses_gaps_without_sending_them() {
    let (_disk, ad, _sim) = new_adapter(128, 1, 907);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let h = data_object(&ad, pg, 4 << 20);
    let mut ri = ad.recovery_info_checked(pg, &h).unwrap();
    ri.copy_subset = [(4096, 8192), (2 << 20, 8192)].into_iter().collect();
    let mut progress = replwire::ObjectRecoveryProgress::default();
    let mut received = 0;
    let mut all = Vec::new();
    for (off, len) in [
        (4096, 4096),
        (8192, 4096),
        (2 << 20, 4096),
        ((2 << 20) + 4096, 4096),
    ] {
        let op = ad.build_push(pg, &ri, &progress, 4096, 1024).unwrap();
        assert_eq!(op.data_included, [(off, len)].into_iter().collect());
        all.extend_from_slice(&op.data);
        received += op.data.len();
        progress = op.after_progress;
    }
    assert!(progress.is_complete());
    assert_eq!(received, 16384);
    // one push with a budget over both gaps: their bytes concatenated in interval order (spec 6.2)
    let op = ad
        .build_push(pg, &ri, &Default::default(), 1 << 20, 1024)
        .unwrap();
    assert_eq!(
        op.data_included,
        [(4096, 8192), (2 << 20, 8192)].into_iter().collect()
    );
    assert_eq!(op.data.as_ref(), all.as_slice(), "no gap bytes in `data`");
    ri.copy_subset = [(4 << 20, 4096)].into_iter().collect();
    assert!(
        ad.build_push(pg, &ri, &Default::default(), 4096, 1024)
            .is_err()
    );
}

fn st_shared(ad: &storeadapt::StoreAdapter<store::dev::SimDev, store::dev::SimClock>) -> u64 {
    ad.with_store(|st| st.shards[0].stats.shared_clones)
}
