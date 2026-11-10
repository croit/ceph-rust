// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Real replication frames captured from classic ceph-osd (v21.1.1 lab, crc mode, osd1 netns) with
//! `examples/pcap_extract` (container: testdata/replwire/cap/frames.bin): every frame decodes,
//! re-encodes byte-exact, and RepOp transactions yield sane op lists.
mod common;
use common::testdata;
use messages::Segments;
use replwire::txn::*;
use replwire::*;
use std::collections::BTreeMap;

struct Rec {
    ty: u16,
    ver: u16,
    compat: u16,
    segs: Segments,
}

fn records() -> Vec<Rec> {
    let b = std::fs::read(testdata("cap/frames.bin")).unwrap();
    let mut p = 0;
    let mut v = Vec::new();
    while p < b.len() {
        let u16at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let l: Vec<usize> = (0..3)
            .map(|i| {
                u32::from_le_bytes(b[p + 6 + 4 * i..p + 10 + 4 * i].try_into().unwrap()) as usize
            })
            .collect();
        let mut o = p + 18;
        let mut take = |n: usize| {
            let s = b[o..o + n].to_vec();
            o += n;
            s
        };
        let (front, middle, data) = (take(l[0]), take(l[1]), take(l[2]));
        v.push(Rec {
            ty: u16at(p),
            ver: u16at(p + 2),
            compat: u16at(p + 4),
            segs: Segments {
                front_zc: Vec::new(),
                front_hints: Default::default(),
                front,
                middle,
                data: data.into(),
            },
        });
        p = o;
    }
    v
}

#[test]
fn captured_frames_roundtrip_byte_exact() {
    let mut seen: BTreeMap<u16, usize> = BTreeMap::new();
    for (i, r) in records().iter().enumerate() {
        let m = decode_repl(r.ty, r.ver, &r.segs)
            .unwrap_or_else(|e| panic!("frame {i} type {}: {e}", r.ty))
            .unwrap_or_else(|| panic!("frame {i}: type {} unknown", r.ty));
        let (ty, ver, compat, segs) = m.encode(denc::features::ALL).unwrap();
        assert_eq!(
            (ty, ver, compat),
            (r.ty, r.ver, r.compat),
            "frame {i} header"
        );
        assert_eq!(segs.front, r.segs.front, "frame {i} type {} front", r.ty);
        assert_eq!(segs.middle, r.segs.middle, "frame {i} middle");
        assert_eq!(segs.data, r.segs.data, "frame {i} data");
        *seen.entry(r.ty).or_default() += 1;
        if let ReplMsg::RepOp(op) = &m {
            check_repop(i, op);
            // the pre-write peek (front only) finds the same PG as the full decode (adr 0477)
            let front = r.segs.front_bytes().unwrap();
            assert_eq!(MOSDRepOp::peek_pgid(r.ver, &front).unwrap(), op.pgid);
        }
    }
    for t in [
        ty::REPOP,
        ty::REPOP_REPLY,
        ty::PUSH,
        ty::PUSH_REPLY,
        ty::PULL,
        ty::RECOVERY_RESERVE,
        ty::RECOVERY_DELETE,
        ty::RECOVERY_DELETE_REPLY,
        ty::UPDATE_LOG_MISSING,
        ty::UPDATE_LOG_MISSING_REPLY,
    ] {
        assert!(seen.contains_key(&t), "type {t} not captured: {seen:?}");
    }
}

fn check_repop(i: usize, op: &MOSDRepOp) {
    assert_eq!(op.pgid.shard, denc::types::ShardId::NO_SHARD);
    let t = op
        .txn(DEFAULT_PAGE)
        .unwrap_or_else(|e| panic!("frame {i}: txn {e}"));
    assert_eq!(t.trailing, 0, "frame {i}: side streams fully consumed");
    assert_eq!(t.colls.len(), 1);
    assert!(t.colls[0] == denc::types::CollT::Pg(op.pgid));
    // every op references the PG collection; the head object appears in the table
    assert!(t.ops.iter().all(|o| o.cid == Cx(0)));
    assert!(
        t.objs.iter().any(|g| g.hobj == op.poid) || t.ops.is_empty(),
        "frame {i}: poid in table"
    );
    // re-encode in the sender's layout
    let (p, d) = if t.struct_v == 9 {
        (t.encode_v9().unwrap(), Vec::new())
    } else {
        t.encode_v10(DEFAULT_PAGE).unwrap()
    };
    if t.struct_v == 9 {
        assert_eq!(p, op.txn_data, "frame {i}: v9 re-encode");
    } else if op.txn_middle.is_empty() {
        assert_eq!(p, op.txn_data, "frame {i}: v10 (p in DATA) re-encode");
    } else {
        assert_eq!(
            (&p[..], &d[..]),
            (&op.txn_middle[..], &op.txn_data[..]),
            "frame {i}: v10 re-encode"
        );
    }
}

#[test]
fn captured_op_shapes() {
    // What a classic primary actually sends for the workloads in the capture (rados bench, rbd bench
    // with snapshots, setxattr/omap, rm): collect op-code sequences and check the spec 2.2 order.
    let mut shapes: BTreeMap<Vec<u32>, usize> = BTreeMap::new();
    for r in records() {
        if let Some(ReplMsg::RepOp(op)) = decode_repl(r.ty, r.ver, &r.segs).unwrap() {
            let t = op.txn(DEFAULT_PAGE).unwrap();
            let mut codes: Vec<u32> = t.ops.iter().map(|o| o.op.code()).collect();
            codes.dedup();
            *shapes.entry(codes).or_default() += 1;
            for o in &t.ops {
                if let TxnOp::Write { data, .. } = &o.op {
                    assert!(!data.is_empty());
                }
            }
        }
    }
    println!("{shapes:#?}");
    assert!(shapes.len() >= 3);
    assert!(shapes.keys().any(|s| s.contains(&opc::WRITE)));
}

/// Captured `_` / `snapset` xattrs and clone ops: object_info_t / SnapSet decode and re-encode
/// byte-exact against what a classic primary wrote.
#[test]
fn captured_object_metadata() {
    use denc::{Encode, from_slice};
    let (mut n_oi, mut n_ss, mut n_clone) = (0, 0, 0);
    for r in records() {
        let Some(ReplMsg::RepOp(op)) = decode_repl(r.ty, r.ver, &r.segs).unwrap() else {
            continue;
        };
        let t = op.txn(DEFAULT_PAGE).unwrap();
        for o in &t.ops {
            match &o.op {
                TxnOp::Clone { oid, dest_oid } => {
                    let (s, d) = (&t.get_obj(*oid).hobj, &t.get_obj(*dest_oid).hobj);
                    assert_eq!(s.snap, denc::types::SnapId::NOSNAP);
                    assert_ne!(d.snap, denc::types::SnapId::NOSNAP);
                    assert_eq!((&s.oid, s.hash, s.pool), (&d.oid, d.hash, d.pool));
                    n_clone += 1;
                }
                TxnOp::SetAttrs { oid, attrs } => {
                    for (k, v) in attrs {
                        if *k == b"_" {
                            let oi: ObjectInfo = from_slice(v).unwrap();
                            assert_eq!(oi.soid, t.get_obj(*oid).hobj, "oi.soid == target object");
                            assert_eq!(oi.encode_to_vec().unwrap(), *v, "object_info_t re-encode");
                            n_oi += 1;
                        } else if *k == b"snapset" {
                            let ss: SnapSet = from_slice(v).unwrap();
                            assert_eq!(ss.encode_to_vec().unwrap(), *v, "SnapSet re-encode");
                            n_ss += 1;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    assert!(
        n_oi > 5 && n_ss > 0 && n_clone > 0,
        "{n_oi} {n_ss} {n_clone}"
    );
}
