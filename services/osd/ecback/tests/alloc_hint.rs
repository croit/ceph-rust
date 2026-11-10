// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The client alloc hint reaches every shard transaction of the object (OQ 99, adr 0059 am. 6): flags kept, expected
//! sizes scaled to the shard (`ceil(x / stripe) * chunk`), placed before the data write. Legacy generator.
use denc::types::*;
use ecback::Backend;
use replwire::txn::{Data, Transaction, TxnOp};
use std::collections::BTreeMap;

const COMPRESSIBLE: u32 = 256;
const INCOMPRESSIBLE: u32 = 512;

fn backend() -> Backend {
    // k=4 m=2, chunk 4096 -> stripe 16384
    Backend::from_parts(
        "isa",
        "reed_sol_van",
        (4, 2),
        (16384, 4096),
        (0..6).collect(),
        true,
    )
    .unwrap()
}

fn txn(hints: &[Hint], payload: &[u8]) -> Vec<u8> {
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId(0),
    }));
    let ox = t.obj(&Ghobject::new(
        Hobject::new(b"probe", SnapId::NOSNAP, 0x1234, 1, b""),
        Ghobject::NO_GEN,
        ShardId(0),
    ));
    t.push(cx, TxnOp::Touch { oid: ox });
    for &(oso, wso, flags) in hints {
        t.push(
            cx,
            TxnOp::SetAllocHint {
                oid: ox,
                expected_object_size: oso,
                expected_write_size: wso,
                flags,
            },
        );
    }
    t.push(
        cx,
        TxnOp::Write {
            oid: ox,
            off: 0,
            data: Data::new(payload),
        },
    );
    t.encode_v9().unwrap()
}

type Hint = (u64, u64, u32);

/// Per shard: (hint ops as (oso, wso, flags), index of the first hint op, index of the first write).
fn shard_hints(hints: &[Hint]) -> Vec<(Vec<Hint>, usize, usize)> {
    let be = backend();
    let g = be
        .plan_write(
            PgT::new(1, 0),
            &bytes::Bytes::from(txn(hints, &[7; 20000])),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap()
        .generate(&BTreeMap::new())
        .unwrap();
    assert_eq!(g.txns.len(), 6);
    g.txns
        .iter()
        .map(|b| {
            let t = Transaction::decode(&[], b, 4096).unwrap();
            let mut found = Vec::new();
            let (mut at, mut wr) = (usize::MAX, usize::MAX);
            for (i, op) in t.ops.iter().enumerate() {
                match &op.op {
                    TxnOp::SetAllocHint {
                        expected_object_size,
                        expected_write_size,
                        flags,
                        ..
                    } => {
                        at = at.min(i);
                        found.push((*expected_object_size, *expected_write_size, *flags));
                    }
                    TxnOp::Write { .. } => wr = wr.min(i),
                    _ => {}
                }
            }
            (found, at, wr)
        })
        .collect()
}

#[test]
fn every_shard_carries_the_scaled_hint_before_the_data() {
    // 1 MiB / 64 KiB logical -> per shard ceil(x / 16384) * 4096
    for (found, at, wr) in shard_hints(&[(1 << 20, 65536, COMPRESSIBLE)]) {
        assert_eq!(found, vec![(1 << 18, 16384, COMPRESSIBLE)]);
        assert!(at < wr, "hint before the first write");
    }
}

#[test]
fn flags_are_ored_sizes_of_the_last_hint_win() {
    for (found, ..) in shard_hints(&[(1 << 20, 4096, COMPRESSIBLE), (0, 0, INCOMPRESSIBLE)]) {
        assert_eq!(found, vec![(0, 0, COMPRESSIBLE | INCOMPRESSIBLE)]);
    }
}

#[test]
fn no_hint_op_no_hint_on_the_shards() {
    for (found, ..) in shard_hints(&[]) {
        assert!(found.is_empty());
    }
}
