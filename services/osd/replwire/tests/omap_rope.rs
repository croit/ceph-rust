// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Repop blob of omap set / rm / header and data writes: byte-identical to the contiguous v9 encoder of main before the
//! omap run went out of line (`GOLDEN`: length + crc32c of the blob, captured on that encoder), whether the peers get
//! the plain blob or the rope around the client's shared run, and the local skeleton decodes to the same txn.
mod common;
use bytes::Bytes;
use common::flat;
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SpgT};
use replwire::{DEFAULT_PAGE, Data, OmapKv, SPLIT_MIN, Transaction, TxnOp};

fn pat(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
        .collect()
}

fn run(n: usize, vlen: usize) -> (Bytes, usize) {
    let keys: Vec<Vec<u8>> = (0..n).map(|i| format!("key.{i:08}").into_bytes()).collect();
    let val = pat(vlen, 9);
    let mut v = Vec::new();
    denc::SortedKv::encode_into(
        &mut v,
        n,
        keys.iter().map(|k| (k.as_slice(), val.as_slice())),
    );
    (Bytes::from(v).slice(4..), n)
}

fn base<'a>(op: impl FnOnce(replwire::Ox) -> TxnOp<'a>, oi: &'a [u8]) -> Transaction<'a> {
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(SpgT {
        pgid: PgT { pool: 1, seed: 2 },
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
    t.push(c, op(o));
    t.push(
        c,
        TxnOp::SetAttrs {
            oid: o,
            attrs: vec![(b"_".as_slice(), oi)],
        },
    );
    t
}

/// `(name, blob length, crc32c(!0, blob))` of the contiguous v9 blob.
const GOLDEN: &[(&str, usize, u32)] = &[
    ("omap_set_big", 82521, 2814031718),
    ("omap_set_small", 1561, 3247526479),
    ("omap_set_at_threshold", 66137, 2160518499),
    ("omap_rm", 4697, 2733747276),
    ("omap_header", 5601, 738826215),
    ("write", 200601, 2977842739),
];

#[test]
fn omap_and_write_blobs_match_the_old_encoder_and_the_rope() {
    let oi = pat(300, 3);
    let (big, n_big) = run(256, 300); // ~90 KiB: out of line
    let (small, n_small) = run(8, 100); // inline
    let (edge, n_edge) = {
        // exactly SPLIT_MIN entry bytes: 4 + 5 + 4 + vlen per entry
        let (one, _) = run(1, 0);
        let vlen = SPLIT_MIN - one.len();
        run(1, vlen)
    };
    assert_eq!(edge.len(), SPLIT_MIN);
    let keys: Vec<Vec<u8>> = (0..256)
        .map(|i| format!("key.{i:08}").into_bytes())
        .collect();
    let hdr = pat(5000, 7);
    let wr = Bytes::from(pat(200_000, 5));
    type Case<'a> = (&'static str, Transaction<'a>, Vec<Bytes>, usize);
    let cases: Vec<Case> = vec![
        (
            "omap_set_big",
            base(
                |o| TxnOp::OmapSetKeys {
                    oid: o,
                    pairs: OmapKv::Run(denc::SortedKv::trusted(n_big, &big)),
                },
                &oi,
            ),
            vec![big.clone()],
            1,
        ),
        (
            "omap_set_small",
            base(
                |o| TxnOp::OmapSetKeys {
                    oid: o,
                    pairs: OmapKv::Run(denc::SortedKv::trusted(n_small, &small)),
                },
                &oi,
            ),
            vec![small.clone()],
            0,
        ),
        (
            "omap_set_at_threshold",
            base(
                |o| TxnOp::OmapSetKeys {
                    oid: o,
                    pairs: OmapKv::Run(denc::SortedKv::trusted(n_edge, &edge)),
                },
                &oi,
            ),
            vec![edge.clone()],
            1,
        ),
        (
            "omap_rm",
            base(
                |o| TxnOp::OmapRmKeys {
                    oid: o,
                    keys: keys.iter().map(|k| k.as_slice()).collect(),
                },
                &oi,
            ),
            vec![],
            0,
        ),
        (
            "omap_header",
            base(
                |o| TxnOp::OmapSetHeader {
                    oid: o,
                    header: &hdr,
                },
                &oi,
            ),
            vec![],
            0,
        ),
        (
            "write",
            base(
                |o| TxnOp::Write {
                    oid: o,
                    off: 0,
                    data: Data::new(&wr),
                },
                &oi,
            ),
            vec![wr.clone()],
            1,
        ),
    ];
    let mut seen = Vec::new();
    for (name, t, owners, shared) in &cases {
        let plain = t.encode_v9().unwrap();
        seen.push((*name, plain.len(), crc::crc32c(!0, &plain)));
        // rope: the shared run / payload is spliced by reference, flattened it is the plain blob
        let (inline, zc) = t.encode_v9_rope(owners).unwrap();
        assert_eq!(zc.len(), *shared, "{name}");
        assert_eq!(flat(&inline, &zc), plain, "{name} rope");
        for (_, r) in &zc {
            assert!(owners.iter().any(|o| contains(o, r)), "{name}: shared");
        }
        // local skeleton: decodes to the same txn, refs are the owners' bytes (no copy)
        let (skel, refs) = t.encode_v9_local(owners).unwrap();
        assert_eq!(refs.len(), *shared, "{name}");
        if *shared > 0 {
            assert!(skel.len() < 1000, "{name}: payload out of the skeleton");
        }
        let d = Transaction::decode_split(&skel, &refs, DEFAULT_PAGE).unwrap();
        assert_eq!(d.ops, t.ops, "{name} skeleton");
        assert_eq!(d.encode_v9().unwrap(), plain, "{name} skeleton re-encode");
        // the peers' rope made from the decoded skeleton (what the primary does)
        let (inline, zc) = d.encode_v9_rope(&refs).unwrap();
        assert_eq!(flat(&inline, &zc), plain, "{name} rope of skeleton");
    }
    assert_eq!(seen, GOLDEN);
}

fn contains(o: &Bytes, s: &[u8]) -> bool {
    let (a, b) = (o.as_ptr() as usize, s.as_ptr() as usize);
    b >= a && b + s.len() <= a + o.len()
}

#[test]
fn skeleton_with_a_missing_or_unused_omap_ref_is_refused() {
    let oi = pat(10, 1);
    let (big, n) = run(2048, 60);
    let t = base(
        |o| TxnOp::OmapSetKeys {
            oid: o,
            pairs: OmapKv::Run(denc::SortedKv::trusted(n, &big)),
        },
        &oi,
    );
    let (skel, refs) = t.encode_v9_local(std::slice::from_ref(&big)).unwrap();
    assert_eq!(refs.len(), 1);
    assert!(Transaction::decode_split(&skel, &[], DEFAULT_PAGE).is_err());
    let two = [refs[0].clone(), refs[0].clone()];
    assert!(Transaction::decode_split(&skel, &two, DEFAULT_PAGE).is_err());
}
