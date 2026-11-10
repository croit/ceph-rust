// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Local txn skeleton (`encode_v9_split` / `decode_split`): out-of-line write payloads.
mod common;
use bytes::Bytes;
use common::flat;
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SpgT};
use replwire::{Data, Transaction, TxnOp};

fn big(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(7) ^ seed).collect()
}

fn obj(n: u8) -> Ghobject {
    Ghobject::new(
        Hobject {
            oid: vec![n; 3],
            ..Hobject::MIN()
        },
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn txn<'a>(a: &'a [u8], b: &'a [u8]) -> Transaction<'a> {
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(SpgT {
        pgid: PgT { pool: 1, seed: 2 },
        shard: ShardId::NO_SHARD,
    }));
    let (o1, o2) = (t.obj(&obj(1)), t.obj(&obj(2)));
    t.push(c, TxnOp::Touch { oid: o1 });
    t.push(
        c,
        TxnOp::Write {
            oid: o1,
            off: 0,
            data: Data::new(a),
        },
    );
    t.push(
        c,
        TxnOp::SetAttr {
            oid: o1,
            name: b"_",
            value: b"oi",
        },
    );
    t.push(
        c,
        TxnOp::Write {
            oid: o2,
            off: 4096,
            data: Data::new(b),
        },
    );
    t.push(
        c,
        TxnOp::Write {
            oid: o2,
            off: 0,
            data: Data::new(b"small"),
        },
    );
    t
}

#[test]
fn v10_data_beyond_the_declared_streams_is_trailing() {
    let (a, b) = (big(5000, 1), big(9000, 2));
    let t = txn(&a, &b);
    let (p, mut d) = t.encode_v10(replwire::DEFAULT_PAGE).unwrap();
    d.extend_from_slice(&[0xab; 16]);
    let decoded = Transaction::decode(&p, &d, replwire::DEFAULT_PAGE).unwrap();
    assert_eq!(decoded.ops, t.ops);
    assert_eq!(
        decoded.trailing, 16,
        "bytes past len_aligned + len_misaligned are reported, not sliced away"
    );
    // p in DATA (a v10 txn with an empty d part): the d part starts behind the p envelope, so junk there is trailing too
    let (p, d) = Transaction::new()
        .encode_v10(replwire::DEFAULT_PAGE)
        .unwrap();
    assert!(d.is_empty());
    let mut pd = p;
    pd.extend_from_slice(&[0xcd; 5]);
    let decoded = Transaction::decode(&[], &pd, replwire::DEFAULT_PAGE).unwrap();
    assert_eq!(decoded.trailing, 5);
    // v9: the whole transaction is the p envelope, bytes behind it are trailing as well
    let mut v9 = t.encode_v9().unwrap();
    v9.extend_from_slice(&[0xee; 7]);
    let decoded = Transaction::decode(&[], &v9, replwire::DEFAULT_PAGE).unwrap();
    assert_eq!(decoded.ops, t.ops);
    assert_eq!(decoded.trailing, 7);
}

/// The placed form keeps the payload view after the object table outgrew the encoder capacity estimate (a realloc
/// during the encode moves the buffer, so the alignment computed before it no longer holds).
#[test]
fn placed_blob_keeps_the_payload_aligned_for_a_large_object_name() {
    let payload = big(8192, 7);
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(SpgT {
        pgid: PgT { pool: 1, seed: 2 },
        shard: ShardId::NO_SHARD,
    }));
    let name = Ghobject::new(
        Hobject {
            oid: vec![b'o'; 16 * 1024],
            ..Hobject::MIN()
        },
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    );
    let o = t.obj(&name);
    t.push(
        c,
        TxnOp::Write {
            oid: o,
            off: 0,
            data: Data::new(&payload),
        },
    );
    let at = t.payload_at().expect("a write");
    let placed = t.encode_v9_placed().unwrap();
    assert_eq!(placed[..], t.encode_v9().unwrap()[..]);
    let view = &placed[replwire::txn::V9_STREAM_AT + at..];
    assert_eq!(&view[..payload.len()], &payload[..]);
    assert_eq!(
        view.as_ptr() as usize % replwire::txn::PLACE_ALIGN,
        0,
        "first write payload on a PLACE_ALIGN boundary"
    );
}

#[test]
fn split_write_refuses_a_zero_page() {
    assert!(replwire::txn::split_write(0, 4096, 0).is_err());
    assert_eq!(
        replwire::txn::split_write(0x1200, 0x3000, 4096).unwrap(),
        (0xe00, 0x2000, 0x200)
    );
}

#[test]
fn split_roundtrip_equals_the_plain_blob() {
    let (a, b) = (big(300_000, 1), big(70_000, 9));
    let t = txn(&a, &b);
    let full = t.encode_v9().unwrap();
    let is_big = |i: usize| matches!(&t.ops[i].op, TxnOp::Write { data, .. } if data.len() >= replwire::SPLIT_MIN);
    let skel = t.encode_v9_split(&is_big).unwrap();
    assert!(
        skel.len() < 1000,
        "payloads stay out of the skeleton: {}",
        skel.len()
    );
    let refs = [Bytes::from(a.clone()), Bytes::from(b.clone())];
    let d = Transaction::decode_split(&skel, &refs, replwire::DEFAULT_PAGE).unwrap();
    let plain = Transaction::decode(&[], &full, replwire::DEFAULT_PAGE).unwrap();
    assert_eq!(d.ops, plain.ops);
    assert_eq!(d.colls, plain.colls);
    assert_eq!(d.objs, plain.objs);
    // the skeleton re-encodes to exactly the plain v9 blob
    assert_eq!(d.encode_v9().unwrap(), full);
    // payload slices borrow the refs (no copy)
    let TxnOp::Write { data, .. } = &d.ops[1].op else {
        panic!()
    };
    assert_eq!(data.head.as_ptr(), refs[0].as_ptr());
}

#[test]
fn skeleton_is_not_a_valid_plain_blob_and_refs_must_match() {
    let (a, b) = (big(100_000, 3), big(80_000, 4));
    let t = txn(&a, &b);
    let skel = t
        .encode_v9_split(&|i| matches!(&t.ops[i].op, TxnOp::Write { data, .. } if data.len() >= replwire::SPLIT_MIN))
        .unwrap();
    // a peer-side (plain) decode must refuse it, never mis-parse
    assert!(Transaction::decode(&[], &skel, replwire::DEFAULT_PAGE).is_err());
    let ok = [Bytes::from(a.clone()), Bytes::from(b.clone())];
    assert!(Transaction::decode_split(&skel, &ok, replwire::DEFAULT_PAGE).is_ok());
    // too few / too many / wrong length refs
    assert!(Transaction::decode_split(&skel, &ok[..1], replwire::DEFAULT_PAGE).is_err());
    let extra = [ok[0].clone(), ok[1].clone(), Bytes::from_static(b"x")];
    assert!(Transaction::decode_split(&skel, &extra, replwire::DEFAULT_PAGE).is_err());
    let short = [ok[0].slice(..10), ok[1].clone()];
    assert!(Transaction::decode_split(&skel, &short, replwire::DEFAULT_PAGE).is_err());
    // a non-write (or split-shaped) op cannot be taken out of line
    assert!(
        t.encode_v9_split(&|i| i == 0).is_ok(),
        "non-write ops are unaffected"
    );
}

#[test]
fn no_out_of_line_writes_is_the_plain_blob() {
    let (a, b) = (big(10, 3), big(20, 4));
    let t = txn(&a, &b);
    assert_eq!(
        t.encode_v9_split(&|_| false).unwrap(),
        t.encode_v9().unwrap()
    );
    let blob = t.encode_v9().unwrap();
    let d = Transaction::decode_split(&blob, &[], replwire::DEFAULT_PAGE).unwrap();
    assert_eq!(d.ops, t.ops);
}

#[test]
fn blob_crc_fused_with_the_payload_copy_equals_a_plain_pass() {
    for (na, nb) in [
        (0, 0),
        (1, 5),
        (4096, 4096),
        (300_000, 70_000),
        (4 << 20, 4097),
        (1 << 20, 0),
    ] {
        let (a, b) = (big(na, 1), big(nb, 9));
        let t = txn(&a, &b);
        let (blob, crc) = t.encode_v9_crc().unwrap();
        assert_eq!(blob, t.encode_v9().unwrap(), "{na}/{nb} same bytes");
        assert_eq!(crc, crc::crc32c(!0, &blob), "{na}/{nb} crc");
        // rebuilt from a skeleton (the primary's path) too
        let is_big = |i: usize| matches!(&t.ops[i].op, TxnOp::Write { data, .. } if data.len() >= replwire::SPLIT_MIN);
        let skel = t.encode_v9_split(&is_big).unwrap();
        let refs: Vec<Bytes> = [&a, &b]
            .iter()
            .zip([na, nb])
            .filter(|(_, n)| *n >= replwire::SPLIT_MIN)
            .map(|(v, _)| Bytes::from((*v).clone()))
            .collect();
        let d = Transaction::decode_split(&skel, &refs, replwire::DEFAULT_PAGE).unwrap();
        let (b2, c2) = d.encode_v9_crc().unwrap();
        assert_eq!((b2.as_slice(), c2), (blob.as_slice(), crc));
    }
}

#[test]
fn peek_counts_ops_like_decode() {
    let (a, b) = (big(5000, 1), big(9000, 2));
    let mut t = txn(&a, &b);
    let blob = t.encode_v9().unwrap();
    let d = Transaction::decode(&[], &blob, replwire::DEFAULT_PAGE).unwrap();
    assert_eq!(Transaction::peek(&[], &blob).unwrap(), d.ops.len());
    let (p, dd) = t.encode_v10(replwire::DEFAULT_PAGE).unwrap();
    assert_eq!(Transaction::peek(&p, &dd).unwrap(), d.ops.len());
    let c = replwire::Cx(0);
    let o = t.obj(&obj(1));
    t.push(
        c,
        TxnOp::OmapRmKeyRange {
            oid: o,
            first: b"a",
            last: b"b",
        },
    );
    let blob = t.encode_v9().unwrap();
    assert_eq!(Transaction::peek(&[], &blob).unwrap(), d.ops.len() + 1);
    let e = Transaction::new().encode_v9().unwrap();
    assert_eq!(Transaction::peek(&[], &e).unwrap(), 0);
    // an op code decode refuses is refused by peek too (code = first u32 of the first op record)
    let mut bad = Transaction::new();
    let c = bad.coll(&CollT::Pg(SpgT {
        pgid: PgT { pool: 1, seed: 2 },
        shard: ShardId::NO_SHARD,
    }));
    let o = bad.obj(&obj(3));
    bad.push(c, TxnOp::Touch { oid: o });
    let mut blob = bad.encode_v9().unwrap();
    // v9: struct header (6 B), inline data bytes (u32 len + data), op_bl (u32 len + records)
    let l1 = u32::from_le_bytes(blob[6..10].try_into().unwrap()) as usize;
    let at = 10 + l1 + 4;
    assert_eq!(blob[at..at + 4], 9u32.to_le_bytes(), "TOUCH record");
    blob[at..at + 4].copy_from_slice(&18u32.to_le_bytes());
    assert!(Transaction::decode(&[], &blob, replwire::DEFAULT_PAGE).is_err());
    assert!(Transaction::peek(&[], &blob).is_err());
}

#[test]
fn wire_rope_flattens_to_the_plain_blob_and_shares_owned_payloads() {
    let (a, b) = (Bytes::from(big(300_000, 1)), Bytes::from(big(70_000, 9)));
    let t = txn(&a, &b);
    let full = t.encode_v9().unwrap();
    // both owned: both spliced, by reference
    let (inline, zc) = t.encode_v9_rope(&[b.clone(), a.clone()]).unwrap();
    assert_eq!(zc.len(), 2);
    assert!(inline.len() < 1000, "{}", inline.len());
    assert_eq!(zc[0].1.as_ptr(), a.as_ptr());
    assert_eq!(zc[1].1.as_ptr(), b.as_ptr());
    assert_eq!(flat(&inline, &zc), full);
    // only one owned: the other is copied inline
    let (inline, zc) = t.encode_v9_rope(std::slice::from_ref(&b)).unwrap();
    assert_eq!(zc.len(), 1);
    assert_eq!(flat(&inline, &zc), full);
    // no owners / payload not inside an owner: the plain blob
    let (inline, zc) = t.encode_v9_rope(&[]).unwrap();
    assert!(zc.is_empty());
    assert_eq!(inline, full);
    let other = Bytes::from(big(300_000, 1));
    let (inline, zc) = t.encode_v9_rope(&[other]).unwrap();
    assert!(zc.is_empty());
    assert_eq!(inline, full);
    // a payload slice inside a bigger owner is shared as that sub-slice
    let whole = Bytes::from(big(400_000, 5));
    let t2 = txn(&whole[1000..301_000], &b);
    let (inline, zc) = t2.encode_v9_rope(&[whole.clone(), b.clone()]).unwrap();
    assert_eq!(zc[0].1.as_ptr(), whole[1000..].as_ptr());
    assert_eq!(flat(&inline, &zc), t2.encode_v9().unwrap());
}

#[test]
fn local_skeleton_of_the_rope_payloads_decodes_to_the_same_txn() {
    let (a, b) = (Bytes::from(big(300_000, 1)), Bytes::from(big(70_000, 9)));
    let t = txn(&a, &b);
    let full = t.encode_v9().unwrap();
    for owners in [vec![a.clone(), b.clone()], vec![b.clone()], vec![]] {
        let (skel, refs) = t.encode_v9_local(&owners).unwrap();
        assert_eq!(refs.len(), owners.len());
        let d = Transaction::decode_split(&skel, &refs, replwire::DEFAULT_PAGE).unwrap();
        assert_eq!(d.encode_v9().unwrap(), full);
        for r in &refs {
            assert!(
                owners.iter().any(|o| o.as_ptr() == r.as_ptr()),
                "shared, not copied"
            );
        }
    }
}

/// Space preflight (adr 0021 S4): the exact cost counts written bytes, attr / omap values and entries; the wire bound
/// (no decode) is never below it for a txn without clone ops, in both wire forms.
#[test]
fn room_bound_covers_room_cost() {
    let (a, b) = (big(5000, 1), big(9000, 2));
    let mut t = txn(&a, &b);
    let c = replwire::Cx(0);
    let o = t.obj(&obj(1));
    let keys: Vec<(&[u8], &[u8])> = vec![(b"k1", b"v"), (b"k2", b"vv"), (b"k3", b"")];
    t.push(
        c,
        TxnOp::OmapSetKeys {
            oid: o,
            pairs: replwire::OmapKv::Pairs(keys),
        },
    );
    t.push(
        c,
        TxnOp::OmapRmKeys {
            oid: o,
            keys: vec![b"x"],
        },
    );
    assert_eq!(t.room_cost(), (5000 + 2 + 9000 + 5 + 3, 1 + 3 + 1));
    let blob = t.encode_v9().unwrap();
    let (p, d) = t.encode_v10(replwire::DEFAULT_PAGE).unwrap();
    for (mid, data) in [(&[][..], &blob[..]), (&p[..], &d[..])] {
        assert!(!Transaction::expands_objects(mid, data).unwrap());
        let nops = Transaction::peek(mid, data).unwrap();
        let exact = Transaction::decode(mid, data, replwire::DEFAULT_PAGE)
            .unwrap()
            .room_cost();
        let bound = Transaction::room_bound(mid, data, nops);
        assert!(
            bound.0 >= exact.0 && bound.1 >= exact.1,
            "{bound:?} < {exact:?}"
        );
    }
}
