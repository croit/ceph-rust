// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Physical allocation gates for EC zero-range generation through the store adapter.
mod common;
use common::*;
use denc::types::*;
use ecback::{Backend, OCtx, OldObj};
use peering::store::{StoreOp, StoreTxn};
use replwire::txn::{Data, Transaction, TxnOp};
use std::collections::BTreeMap;
use std::sync::Arc;

fn zero_reclaims(optimized: bool) {
    let be = Arc::new(
        Backend::from_parts(
            "isa",
            "reed_sol_van",
            (2, 1),
            (8192, 4096),
            vec![0, 1, 2],
            true,
        )
        .unwrap(),
    );
    let pg = PgT::new(1, 0);
    let h = Hobject::new(b"reclaim", SnapId::NOSNAP, 0x1234, 1, b"");
    let s = |sh| SpgT {
        pgid: pg,
        shard: ShardId(sh),
    };
    let (_disk, ad, _) = new_adapter(64, 1, 17);
    for sh in 0..3 {
        ad.submit_create(s(sh));
    }
    let payload = incompressible(32768, 18);
    let mut olds = BTreeMap::<Hobject, OldObj>::new();
    let mut original = Vec::new();
    for phase in 0..5 {
        let mut t = Transaction::new();
        let c = t.coll(&CollT::Pg(s(0)));
        let o = t.obj(&storeadapt::gh(s(0), &h));
        t.push(
            c,
            match phase {
                0 => TxnOp::Write {
                    oid: o,
                    off: 0,
                    data: Data::new(&payload),
                },
                1 => TxnOp::Zero {
                    oid: o,
                    off: 0,
                    len: 8192,
                },
                2 => TxnOp::Truncate {
                    oid: o,
                    size: 24576,
                },
                3 => TxnOp::Zero {
                    oid: o,
                    off: 0,
                    len: 24576,
                },
                4 => TxnOp::Truncate {
                    oid: o,
                    size: 32768,
                },
                _ => unreachable!(),
            },
        );
        let txn = t.encode_v9().unwrap();
        let (post, txns) = if optimized {
            let plan = be
                .plan_write_o(
                    pg,
                    &txn,
                    &olds,
                    &BTreeMap::new(),
                    OCtx {
                        members: &[0, 1, 2],
                        first_write: true,
                    },
                )
                .unwrap();
            let post = plan.post();
            let txns = plan.generate(&BTreeMap::new()).unwrap().txns;
            (post, txns)
        } else {
            let plan = be.plan_write(pg, &txn, &olds, &BTreeMap::new()).unwrap();
            let post = plan.post();
            let txns = plan
                .generate(&BTreeMap::new())
                .unwrap()
                .txns
                .into_iter()
                .map(Some)
                .collect();
            (post, txns)
        };
        olds = post.into_iter().map(|(h, p)| (h, p.into())).collect();
        for (sh, txn) in txns.into_iter().enumerate() {
            ad.try_submit(
                s(sh as i8),
                &StoreTxn {
                    ops: vec![StoreOp::ApplyTxn {
                        middle: Default::default(),
                        data: txn.unwrap().into(),
                    }],
                },
            )
            .unwrap();
        }
        for sh in 0..3 {
            let spg = s(sh);
            let g = storeadapt::gh(spg, &h);
            let (size, bytes, allocation) = ad.with_store(|st| {
                let c = CollT::Pg(spg);
                let size = st.stat(&c, &g).unwrap().unwrap().size;
                let bytes = st.read(&c, &g, 0, size).unwrap();
                let allocation = st.span_stats(&c, &g, 0, size).unwrap().unwrap();
                (
                    size,
                    bytes,
                    allocation.allocated + allocation.allocated_compressed,
                )
            });
            assert_eq!(
                size,
                if phase < 2 || phase == 4 {
                    16384
                } else {
                    12288
                },
                "shard size at phase {phase}"
            );
            let expected = [16384, 12288, 8192, 0, 0][phase];
            assert_eq!(
                allocation, expected,
                "optimized={optimized}, shard={sh}, phase={phase}: physical allocation"
            );
            if phase == 0 {
                original.push(bytes);
            } else if phase >= 3 {
                assert!(bytes.iter().all(|b| *b == 0));
            } else {
                assert!(bytes[..4096].iter().all(|b| *b == 0));
                assert_eq!(&bytes[4096..], &original[sh as usize][4096..size as usize]);
            }
        }
    }
}

#[test]
fn legacy_ec_zero_reclaims_allocated_bytes() {
    zero_reclaims(false);
}

#[test]
fn optimized_ec_zero_reclaims_allocated_bytes() {
    zero_reclaims(true);
}
