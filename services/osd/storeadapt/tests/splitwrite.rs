// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Local skeleton writes (`StoreOp::ApplyTxnSplit`, large client payloads out of line): same bytes on the device as the
//! plain blob, same size pre-flight, malformed skeletons refused without applying anything.
mod common;
use bytes::Bytes;
use common::*;
use denc::types::*;
use peering::store::{PgStoreOps, StoreOp, StoreTxn};
use replwire::txn::{Transaction, TxnOp};

fn pat(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(37) ^ seed).collect()
}

fn gh(name: &str) -> Ghobject {
    Ghobject::new(
        Hobject::new(name.as_bytes(), SnapId::NOSNAP, 5, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn parts(pg: SpgT, name: &str, a: &[u8], b: &[u8]) -> (Bytes, Vec<Bytes>, Bytes) {
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(pg));
    let o = t.obj(&gh(name));
    t.push(c, TxnOp::Touch { oid: o });
    t.push(
        c,
        TxnOp::Write {
            oid: o,
            off: 0,
            data: replwire::Data::new(a),
        },
    );
    t.push(
        c,
        TxnOp::SetAttr {
            oid: o,
            name: b"_",
            value: b"info",
        },
    );
    t.push(
        c,
        TxnOp::Write {
            oid: o,
            off: a.len() as u64 + 77,
            data: replwire::Data::new(b),
        },
    );
    let plain = Bytes::from(t.encode_v9().unwrap());
    let skel = Bytes::from(
        t.encode_v9_split(&|i| matches!(&t.ops[i].op, TxnOp::Write { data, .. } if data.len() >= replwire::SPLIT_MIN))
            .unwrap(),
    );
    (
        skel,
        vec![Bytes::copy_from_slice(a), Bytes::copy_from_slice(b)],
        plain,
    )
}

fn read_all(ad: &Ad, pg: SpgT, name: &str, len: u64) -> Vec<u8> {
    ad.with_store(|st| st.read(&CollT::Pg(pg), &gh(name), 0, len))
        .unwrap()
}

#[test]
fn split_and_plain_blobs_store_the_same_bytes() {
    let (_d, ad, _sim) = new_adapter(256, 1, 41);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let (a, b) = (pat(1 << 20, 1), pat(200_000, 2));
    let (skel, refs, _) = parts(pg, "viasplit", &a, &b);
    let empty = Bytes::new();
    assert_eq!(ad.check_write_split(pg, &skel, &refs), Ok(()));
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxnSplit {
                skel,
                refs,
                hints: Vec::new(),
            }],
        },
    )
    .unwrap();
    let (_, _, plain2) = parts(pg, "viaplain", &a, &b);
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: empty,
                data: plain2,
            }],
        },
    )
    .unwrap();
    let total = (a.len() + 77 + b.len()) as u64;
    let (x, y) = (
        read_all(&ad, pg, "viasplit", total),
        read_all(&ad, pg, "viaplain", total),
    );
    assert!(x == y, "split and plain apply differ");
    assert_eq!(&x[..a.len()], &a[..]);
    assert_eq!(&x[a.len() + 77..], &b[..]);
    assert!(ad.failure().is_none());
}

#[test]
fn malformed_skeletons_apply_nothing() {
    let (_d, ad, _sim) = new_adapter(256, 1, 43);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let (a, b) = (pat(100_000, 3), pat(90_000, 4));
    let (skel, refs, _) = parts(pg, "bad", &a, &b);
    // a ref of the wrong length
    let wrong = vec![refs[0].slice(..10), refs[1].clone()];
    let r = ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxnSplit {
                skel: skel.clone(),
                refs: wrong,
                hints: Vec::new(),
            }],
        },
    );
    assert!(r.is_err(), "wrong ref length must be refused");
    // a missing ref
    let r = ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxnSplit {
                skel: skel.clone(),
                refs: refs[..1].to_vec(),
                hints: Vec::new(),
            }],
        },
    );
    assert!(r.is_err(), "missing ref must be refused");
    assert!(
        ad.failure().is_none(),
        "a refused txn is not a store failure"
    );
}

/// adr 0061 am. 4: a split write whose payload carries the receive pass's block crcs is written by reference (the
/// simulated device "views" it) and its block crcs are reused (no crc pass); a payload off the block grid is written by
/// reference with one crc pass; the bytes read back verified either way. The plain blob (replica form) is written by
/// reference too.
#[test]
fn hinted_payloads_are_written_by_reference_with_reused_block_crcs() {
    let (_d, ad, _sim) = new_adapter(256, 1, 47);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let (a, b) = (pat(1 << 20, 5), pat(200_000, 6));
    let (skel, refs, _) = parts(pg, "hinted", &a, &b);
    let blocks: std::sync::Arc<[u32]> = refs[0]
        .as_chunks::<4096>()
        .0
        .iter()
        .map(|c| crc::crc32c(0, c))
        .collect();
    let hints = vec![crc::CrcHint::with_blocks(
        &refs[0],
        crc::crc32c(!0, &refs[0]),
        blocks,
    )];
    let c0 = ad.with_store(|st| st.comp_counters());
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxnSplit { skel, refs, hints }],
        },
    )
    .unwrap();
    let c1 = ad.with_store(|st| st.comp_counters());
    assert_eq!(c1.crc_reused_bytes - c0.crc_reused_bytes, a.len() as u64);
    // a whole + b's aligned middle by reference; only b's two boundary blocks copied
    let zc = c1.zc_bytes - c0.zc_bytes;
    assert!(zc >= a.len() as u64 + 180_000, "zc {zc}");
    assert!(c1.staged_bytes - c0.staged_bytes <= 2 * 4096);
    let total = (a.len() + 77 + b.len()) as u64;
    let x = read_all(&ad, pg, "hinted", total);
    assert_eq!(&x[..a.len()], &a[..]);
    assert_eq!(&x[a.len() + 77..], &b[..]);
    // replica form: the blob is the owner
    let (_, _, plain) = parts(pg, "blob", &a, &b);
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Bytes::new(),
                data: plain,
            }],
        },
    )
    .unwrap();
    let c2 = ad.with_store(|st| st.comp_counters());
    assert!(c2.zc_bytes - c1.zc_bytes >= a.len() as u64);
    assert_eq!(c2.crc_reused_bytes, c1.crc_reused_bytes);
    assert_eq!(read_all(&ad, pg, "blob", total), x);
    assert!(ad.failure().is_none());
}

/// adr 0061 am. 7: a replica's blob received with its block crcs on the grid that starts at the payload (offset 14 of
/// the v9 blob, `StoreOp::TxnHint`): the first write reuses them (no crc pass); a hint whose grid is the blob's own
/// (offset 0) matches no write and costs nothing but the pass.
#[test]
fn replica_blob_with_a_payload_grid_reuses_the_block_crcs() {
    let (_d, ad, _sim) = new_adapter(256, 1, 49);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let (a, b) = (pat(1 << 20, 7), pat(200_000, 8));
    let (_, _, plain) = parts(pg, "grid", &a, &b);
    assert_eq!(&plain[replwire::txn::PAYLOAD_AT..][..a.len()], &a[..]);
    let at = replwire::txn::PAYLOAD_AT;
    let hint = |grid: usize| {
        let blocks: std::sync::Arc<[u32]> = plain[grid..]
            .as_chunks::<4096>()
            .0
            .iter()
            .map(|c| crc::crc32c(0, c))
            .collect();
        crc::CrcHint::with_blocks_at(&plain, crc::crc32c(!0, &plain), blocks, grid)
    };
    let total = (a.len() + 77 + b.len()) as u64;
    let apply = |name: &str, grid: usize| {
        let (_, _, blob) = parts(pg, name, &a, &b);
        // the very same bytes the hint was made for
        let blob = if blob == plain { plain.clone() } else { blob };
        ad.try_submit(
            pg,
            &StoreTxn {
                ops: vec![
                    StoreOp::ApplyTxn {
                        middle: Bytes::new(),
                        data: blob,
                    },
                    StoreOp::TxnHint(hint(grid)),
                ],
            },
        )
        .unwrap();
    };
    let c0 = ad.with_store(|st| st.comp_counters());
    apply("grid", at);
    let c1 = ad.with_store(|st| st.comp_counters());
    assert_eq!(c1.crc_reused_bytes - c0.crc_reused_bytes, a.len() as u64);
    assert!(c1.zc_bytes - c0.zc_bytes >= a.len() as u64);
    let x = read_all(&ad, pg, "grid", total);
    assert_eq!(&x[..a.len()], &a[..]);
    assert_eq!(&x[a.len() + 77..], &b[..]);
    // a hint on the blob's own grid does not line up with the payload: a crc pass, same bytes
    apply("grid", 0); // same blob again
    let c2 = ad.with_store(|st| st.comp_counters());
    assert_eq!(c2.crc_reused_bytes, c1.crc_reused_bytes);
    assert_eq!(read_all(&ad, pg, "grid", total), x);
    assert!(ad.failure().is_none());
}
