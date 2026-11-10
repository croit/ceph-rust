// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `list_temps` (adr 0057 am. 1): the temp objects a crash left in a PG are found at load without listing the
//! whole PG (they sort before every regular object), same answer as the reference `MemStore`.
mod common;
use common::*;
use denc::types::*;
use peering::store::{MemStore, PgStoreOps, StoreOp, StoreTxn};
use replwire::txn::*;

fn touch_txn(s: SpgT, objs: &[Hobject]) -> StoreTxn {
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(s));
    for h in objs {
        let ox = t.obj(&Ghobject::new(h.clone(), Ghobject::NO_GEN, s.shard));
        t.push(cx, TxnOp::Touch { oid: ox });
        t.push(
            cx,
            TxnOp::Write {
                oid: ox,
                off: 0,
                data: replwire::Data::new(b"x"),
            },
        );
    }
    StoreTxn {
        ops: vec![StoreOp::ApplyTxn {
            middle: Default::default(),
            data: t.encode_v9().unwrap().into(),
        }],
    }
}

#[test]
fn list_temps_finds_exactly_the_temp_objects() {
    for pool in [0u64, 3] {
        let (_d, mut ad, _sim) = new_adapter(256, 1, 11);
        let mut mem = MemStore::new();
        let s = spg(pool, 0);
        ad.submit_create(s);
        mem.submit(
            s,
            &StoreTxn {
                ops: vec![StoreOp::CreatePg],
            },
        );
        let mut objs: Vec<Hobject> = (0..600u32)
            .map(|i| {
                Hobject::new(
                    format!("obj{i}").as_bytes(),
                    SnapId::NOSNAP,
                    i.wrapping_mul(0x9e37_79b1) & !0x7,
                    pool as i64,
                    if i % 7 == 0 { b"ns".as_slice() } else { b"" },
                )
            })
            .collect();
        let temps: Vec<Hobject> = [0u32, 0xffff_fff8, 0x1234_5678]
            .iter()
            .enumerate()
            .map(|(i, h)| {
                Hobject::new(
                    format!("copy-tmp-5-{i}").as_bytes(),
                    SnapId::NOSNAP,
                    *h,
                    Hobject::temp_pool(pool as i64),
                    b"",
                )
            })
            .collect();
        objs.extend(temps.iter().cloned());
        let t = touch_txn(s, &objs);
        ad.submit(s, &t);
        mem.submit(s, &t);
        let mut want = temps.clone();
        want.sort();
        let mut got = ad.list_temps(s);
        got.sort();
        assert_eq!(got, want, "pool {pool}");
        let mut m = mem.list_temps(s);
        m.sort();
        assert_eq!(m, want, "reference, pool {pool}");
        // a PG without temps: nothing
        let s2 = spg(pool, 1);
        ad.submit_create(s2);
        assert!(ad.list_temps(s2).is_empty());
    }
}
