// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `WriteReq::wire` turns the local skeleton of a client write into the exact plain v9 blob a peer must get.
use bytes::Bytes;
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SpgT};
use peering::WriteReq;
use replwire::{Data, Transaction, TxnOp};

#[test]
fn wire_of_a_skeleton_is_the_plain_blob() {
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i * 13) as u8).collect();
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(SpgT {
        pgid: PgT { pool: 3, seed: 1 },
        shard: ShardId::NO_SHARD,
    }));
    let o = t.obj(&Ghobject::new(
        Hobject {
            oid: b"obj".to_vec(),
            ..Hobject::MIN()
        },
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    ));
    t.push(
        c,
        TxnOp::Write {
            oid: o,
            off: 4096,
            data: Data::new(&payload),
        },
    );
    t.push(
        c,
        TxnOp::SetAttr {
            oid: o,
            name: b"_",
            value: b"oi",
        },
    );
    let plain = t.encode_v9().unwrap();
    let skel = t.encode_v9_split(&|i| i == 0).unwrap();
    let mut w = WriteReq {
        reqid: Default::default(),
        entries: vec![],
        txn_middle: Bytes::new(),
        txn_data: skel.into(),
        txn_refs: vec![Bytes::from(payload)],
        ..Default::default()
    };
    let (m, d) = w.wire().unwrap();
    assert!(m.is_empty());
    assert_eq!(&d[..], &plain[..]);
    let (_, d2, h) = w.wire_crc().unwrap();
    assert_eq!(h.of(&d2), Some(crc::crc32c(!0, &plain)));
    assert_eq!(h.of(&d), None, "hint is bound to the blob it was made for");
    // plain request: passed through as is
    w.txn_refs.clear();
    w.txn_data = Bytes::from(plain.clone());
    let (m, d) = w.wire().unwrap();
    assert!(m.is_empty() && d[..] == plain[..]);
    // a corrupt skeleton is an error, never a panic or a wrong blob
    w.txn_refs = vec![Bytes::from_static(b"short")];
    w.txn_data = Bytes::from(plain);
    assert!(w.wire().is_err());
}
