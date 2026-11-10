// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! ADR 0021 amendment 6: PG txns are applied as system txns. When the store has no admission room left
//! (`write_room` false) already admitted txns (replica applies, PG state, log entries) still go through the reserves
//! and never turn into a fatal NoSpace; the adapter stays healthy. A PG re-created while its old copy's deletion waits
//! for space is deferred, never acknowledged early (OQ 127).
mod common;
use common::*;
use denc::types::*;
use opexec::ObjView;
use peering::store::{PgStoreOps, Queued, StoreOp, StoreTxn};
use replwire::txn::{Data, Transaction, TxnOp};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use store::dev::CrashPolicy;
use store::obj::{OTxn, StoreCfg};

#[test]
fn admitted_pg_txns_survive_no_room() {
    let sim = sim_cfg(48, 11);
    let img = fresh_image(&sim, 1, 1024);
    let (_d, mut ad) = open(&img, &sim, &StoreCfg::default());
    let s = spg(1, 0);
    ad.submit_create(s);
    // fill the (single) shard with user-class data of another collection
    let other = CollT::Pg(spg(2, 0));
    let blob = vec![0x5Au8; 100_000];
    ad.with_store(|st| {
        let mut t = OTxn::new();
        t.mkcoll(other);
        st.commit(&t).unwrap();
        let mut n = 0u32;
        while st.write_room(&other, 1 << 20, 0) {
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
            assert!(n < 1000);
        }
    });
    assert!(!ad.write_room(s, 1 << 20, 0));
    // PG state and object txns of the full OSD still apply (no Failed, no Rejected)
    let mut g = PgGen::new(s, 5);
    let mut exist = BTreeSet::new();
    for tok in 1..=30u64 {
        let mut t = StoreTxn::default();
        t.push(StoreOp::PutInfo(Box::new(g.info())));
        t.push(StoreOp::ApplyTxn {
            middle: Default::default(),
            data: g.object_txn(&mut exist).into(),
        });
        let q = ad.queue(s, &t, tok);
        assert!(matches!(q, Queued::Pending | Queued::Durable), "{q:?}");
    }
    assert!(ad.failure().is_none(), "{:?}", ad.failure());
    assert_eq!(ad.rejected.get(), 0);
}

/// ADR 0021 am. 21: a PG deletion at 100% must finish. A slice of removals bigger than the delete-only headroom gets
/// NoSpace from the store; the adapter halves the slice instead of failing (it would stall until restart, and
/// `resume_removals` at mount would fail again).
#[test]
fn pg_removal_at_full_shrinks_its_slice() {
    let sim = sim_cfg(24, 12);
    let img = fresh_image(&sim, 1, 1024);
    let (_d, ad) = open(&img, &sim, &StoreCfg::default());
    let s = spg(1, 0);
    ad.submit_create(s);
    let c = CollT::Pg(s);
    let val = vec![7u8; 200];
    let data = vec![0x5au8; 4096];
    let keys: Vec<String> = (0..16).map(|k| format!("k{k:04}")).collect();
    let n = ad.with_store(|st| {
        let mut n = 0u32;
        loop {
            let h = Hobject::new(format!("o{n:06}").as_bytes(), SnapId::NOSNAP, n, 1, b"");
            let o = Ghobject::new(h, Ghobject::NO_GEN, ShardId::NO_SHARD);
            let mut t = OTxn::new();
            t.write(c, &o, 0, &data);
            for k in &keys {
                t.omap_set(c, &o, k.as_bytes(), &val);
            }
            if st.commit(&t).is_err() {
                break n;
            }
            n += 1;
            assert!(n < 100_000);
        }
    });
    assert!(n > 100);
    ad.with_store(|st| st.checkpoint().unwrap());
    ad.remove_batch.set(4096);
    ad.remove_pg(s).unwrap();
    assert!(ad.failure().is_none(), "{:?}", ad.failure());
    let pct = ad.with_store(|st| {
        st.checkpoint().unwrap();
        st.request_checkpoint();
        st.checkpoint().unwrap();
        st.statfs().fullest_shard_pct
    });
    assert!(pct < 20.0, "space not back: {pct}");
}

/// Review F3 (adr 0021 S4): a meta-bound shard filled to its SYSTEM floor (replica / PG-state applies) must still free
/// space online: a client delete (object Remove + its PG log entry + info) and the PG-removal marker are freeing txns,
/// not sys txns that hit NoSpace (fail-stop at every restart).
#[test]
fn deletes_with_their_log_entry_free_a_shard_at_its_sys_floor() {
    let sim = sim_cfg(24, 13);
    let img = fresh_image(&sim, 1, 1024);
    let (_d, mut ad) = open(&img, &sim, &StoreCfg::default());
    let s = spg(1, 0);
    ad.submit_create(s);
    let c = CollT::Pg(s);
    let val = vec![7u8; 200];
    let keys: Vec<String> = (0..16).map(|k| format!("k{k:04}")).collect();
    let obj = |n: u32| {
        let h = Hobject::new(format!("o{n:06}").as_bytes(), SnapId::NOSNAP, n, 1, b"");
        Ghobject::new(h, Ghobject::NO_GEN, ShardId::NO_SHARD)
    };
    // omap-heavy sys applies until the store refuses them: meta at the sys floor
    let n = ad.with_store(|st| {
        let mut n = 0u32;
        loop {
            let mut t = OTxn::new();
            t.sys = true;
            t.write(c, &obj(n), 0, &[1u8; 512]);
            for k in &keys {
                t.omap_set(c, &obj(n), k.as_bytes(), &val);
            }
            if st.commit(&t).is_err() {
                break n;
            }
            n += 1;
            assert!(n < 100_000);
        }
    });
    assert!(n > 100);
    // then single small keys until not even those fit: nothing but the floor is left
    ad.with_store(|st| {
        for k in 0..100_000u32 {
            let (o, key) = (obj(n - 1), format!("z{k:06}"));
            let mut t = OTxn::new();
            t.sys = true;
            t.omap_set(c, &o, key.as_bytes(), b"v");
            if st.commit(&t).is_err() {
                return;
            }
        }
        panic!("never reached the sys floor");
    });
    assert!(ad.failure().is_none());
    // client deletes as the PG applies them: Remove + log entry (+ info every few)
    let mut g = PgGen::new(s, 3);
    for (tok, i) in (1..=20u64).zip(0u32..) {
        let o = obj(i);
        let mut tx = replwire::Transaction::new();
        let cid = tx.coll(&c);
        let oid = tx.obj(&o);
        tx.push(cid, replwire::TxnOp::Remove { oid });
        let mut e = g.entry(pgwire::LogOp::DELETE);
        e.soid = o.hobj.clone();
        let mut t = StoreTxn::default();
        t.push(StoreOp::ApplyTxn {
            middle: Default::default(),
            data: tx.encode_v9().unwrap().into(),
        });
        t.push(StoreOp::LogAppendFast(vec![peering::EncLogEntry::of(&e)]));
        // the PG log stays at its bound: a delete adds one entry and trims the oldest, like every PG write
        t.push(StoreOp::LogTrim {
            to: Eversion::new(g.epoch, g.ver.saturating_sub(4)),
            dups_from: None,
            tail_up: false,
        });
        if i % 5 == 0 {
            t.push(StoreOp::PutInfo(Box::new(g.info())));
        }
        let q = ad.queue(s, &t, tok);
        assert!(
            matches!(q, Queued::Pending | Queued::Durable),
            "delete {i}: {q:?} ({:?})",
            ad.failure()
        );
    }
    assert!(ad.failure().is_none(), "{:?}", ad.failure());
    // the PG-removal marker goes through as well; the removal itself is never fatal: done, or deferred (back-off) with
    // a clean NoSpace while the meta space stays at the floor (open: 90-open-questions, removal at the meta floor)
    ad.remove_pg_async(s).expect("marker");
    match ad.remove_pg(s) {
        Ok(()) => {}
        Err(e) => assert_eq!(e, store::obj::ObjError::NoSpace),
    }
    assert!(ad.failure().is_none(), "{:?}", ad.failure());
}

/// OQ 127 (adr 0021 am. 23, adr 0008): a PG re-created while the deletion of its old copy cannot proceed (NoSpace even
/// with a 1-object slice) keeps its txns in `deferred` and answers `Pending`. None of them is acknowledged before the
/// deletion is done and the store holds it durably, the acks keep the PG's order, and from the first ack on the op
/// executor's view (client reads) and the recovery/listing reads see exactly the new copy: the acked object with its
/// bytes, never ENOENT, never the old bytes or an old object. A crash right after the acks keeps them.
#[test]
fn deferred_recreate_is_acked_only_once_durable_and_then_readable() {
    let s = spg(1, 0);
    let g = PgGen::new(s, 9);
    let (a, b) = (g.names[0].clone(), g.names[1].clone());
    let write = |h: &Hobject, data: &[u8], v: Eversion| {
        let oi = oi_bytes(h, v, data.len() as u64);
        let mut t = Transaction::new();
        let c = t.coll(&CollT::Pg(s));
        let o = t.obj(&g.g(h));
        t.push(c, TxnOp::Touch { oid: o });
        t.push(
            c,
            TxnOp::Write {
                oid: o,
                off: 0,
                data: Data::new(data),
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
        StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            }],
        }
    };
    let (old, new) = (vec![0x0au8; 300], vec![0x5bu8; 700]);
    let new_v = Eversion::new(9, 1);
    let (disk, mut ad, sim) = new_adapter(64, 1, 5);
    ad.submit_create(s);
    ad.try_submit(s, &write(&a, &old, Eversion::new(3, 1)))
        .unwrap();
    ad.try_submit(s, &write(&b, &old, Eversion::new(3, 2)))
        .unwrap();
    fn toks(out: &[(SpgT, u64)]) -> Vec<u64> {
        out.iter().map(|x| x.1).collect()
    }
    // the copy is deleted: the OSD re-creates the PG only after the marker is durable (`PgRemoved`); the objects go in
    // background slices, which find no space
    let rm = StoreTxn {
        ops: vec![StoreOp::RemovePg],
    };
    assert_eq!(ad.queue(s, &rm, 1), Queued::Pending);
    let mut out = Vec::new();
    let end = Instant::now() + Duration::from_secs(10);
    while !toks(&out).contains(&1) {
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT removal marker durable exceeded 10s (pg {s})"
        );
        ad.poll_commits(&mut out);
        ad.with_store(|st| st.idle());
        std::thread::sleep(Duration::from_millis(5));
    }
    ad.remove_nospace_from.set(1);
    // re-create, a client write of `a` (new bytes), a later PG-state txn: all wait for the deletion
    let create = StoreTxn {
        ops: vec![StoreOp::CreatePg],
    };
    let state = StoreTxn {
        ops: vec![StoreOp::PutEpoch(9)],
    };
    for (tok, t) in [(10, &create), (11, &write(&a, &new, new_v)), (12, &state)] {
        assert_eq!(ad.queue(s, t, tok), Queued::Pending, "txn {tok} waits");
    }
    // the deletion stays stuck past one back-off retry: nothing of the re-create is acknowledged
    let end = Instant::now() + Duration::from_millis(1300);
    while Instant::now() < end {
        PgStoreOps::step_removals(&ad, u64::MAX);
        ad.poll_commits(&mut out);
        ad.with_store(|st| st.idle());
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(ad.failure().is_none(), "{:?}", ad.failure());
    let early: Vec<u64> = toks(&out).into_iter().filter(|t| *t >= 10).collect();
    assert!(
        early.is_empty(),
        "deferred txns acknowledged before the store holds them: {early:?}"
    );
    // space again: the deletion finishes, the deferred txns apply in order and are acknowledged once durable
    ad.remove_nospace_from.set(0);
    let mut checked = false;
    let end = Instant::now() + Duration::from_secs(10);
    while [10, 11, 12].iter().any(|t| !toks(&out).contains(t)) {
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT deferred re-create acks exceeded 10s (pg {s}, acked {:?}, failure {:?})",
            toks(&out),
            ad.failure()
        );
        PgStoreOps::step_removals(&ad, u64::MAX);
        let n0 = out.len();
        ad.poll_commits(&mut out);
        if !checked && toks(&out[n0..]).contains(&11) {
            // at the ack of the write: every read path sees it, nothing of the old copy
            checked = true;
            assert_eq!(ad.ov_stat(s, &a), Ok(Some(new.len() as u64)));
            assert_eq!(ad.ov_read(s, &a, 0, new.len() as u64), Ok(new.clone()));
            assert_eq!(ad.ov_stat(s, &b), Ok(None), "old object visible");
            assert_eq!(ad.object_version(s, &a), Ok(new_v));
            let l = ad.list_objects(s, &Hobject::MIN(), 0, 100).unwrap();
            assert_eq!(l.objs, vec![(a.clone(), new_v)]);
        }
        ad.with_store(|st| st.idle());
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(checked, "write ack not seen");
    assert!(ad.failure().is_none(), "{:?}", ad.failure());
    let order: Vec<u64> = toks(&out).into_iter().filter(|t| *t >= 10).collect();
    assert_eq!(order, [10, 11, 12], "acks out of PG order");
    // acknowledged = durable: a crash right now keeps the new copy, the old one stays gone
    disk.crash_now();
    let img = disk.crash_image(CrashPolicy::MIXED);
    drop(ad);
    let (_d2, ad2) = open(&img, &sim, &StoreCfg::default());
    assert!(ad2.list_pgs().contains(&s));
    assert!(!ad2.pending_removals().unwrap().contains(&s));
    let objs = ad2.objects(s);
    assert_eq!(objs.keys().collect::<Vec<_>>(), [&a]);
    assert_eq!(objs[&a].data, new);
}
