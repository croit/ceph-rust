// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Write truncate hint (client-ops s7.2 write step 2): `truncate_size == u64::MAX` is the clients' "no size"
//! sentinel and must never reach the store as a truncate (live bug: ceph-fuse write with truncate_seq 1 /
//! truncate_size u64::MAX on an existing object produced an invalid store op -> OSD exit, re-applied on restart).
mod common;
use common::*;
use opwire::{OsdOp, errno};

fn write_hint(oid: &str, data: &[u8], seq: u32, size: u64) -> opwire::MOSDOp {
    let mut w = OsdOp::write(0, data.to_vec());
    let mut e = w.extent();
    e.truncate_seq = seq;
    e.truncate_size = size;
    w.set_extent(e);
    mkop(oid.as_bytes(), vec![w])
}

fn result(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64, op: opwire::MOSDOp) -> i32 {
    let mut outs = run(pg, eng, 1, tid, client(7), op);
    outs.extend(settle(pg, eng));
    reply_of(&mut outs, 1, tid).expect("reply").result
}

#[test]
fn unset_truncate_size_sentinel_never_truncates() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        result(&mut pg, &mut eng, 1, write_hint("o", b"0123456789", 0, 0)),
        0
    );
    // newer truncate_seq with the "unset" size: data written, object size = written extent, store txn valid
    assert_eq!(
        result(&mut pg, &mut eng, 2, write_hint("o", b"ab", 1, u64::MAX)),
        0
    );
    let objs = pg.store.objects(pg.spg);
    let o = objs.values().next().expect("object");
    assert_eq!(o.data, b"ab23456789");
}

#[test]
fn truncate_size_beyond_object_limit_is_efbig() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        result(&mut pg, &mut eng, 1, write_hint("o", b"xyz", 0, 0)),
        0
    );
    let r = result(&mut pg, &mut eng, 2, write_hint("o", b"q", 1, 1 << 40));
    assert_eq!(r, -errno::EFBIG);
    let objs = pg.store.objects(pg.spg);
    assert_eq!(objs.values().next().expect("object").data, b"xyz");
}

/// TRUNCATE and TRIMTRUNC apply the extent limit to both offset and length, even though the length does not
/// contribute to the resulting object size. Invalid extents must not shrink the object.
#[test]
fn truncate_checks_the_whole_extent() {
    let max = opexec::Limits::default().max_object_size;
    for code in [opwire::op::TRUNCATE, opwire::op::TRIMTRUNC] {
        for len in [max, u64::MAX] {
            let mut pg = TPg::new();
            let mut eng = engine(&pg);
            assert_eq!(
                result(&mut pg, &mut eng, 1, write_hint("o", b"abc", 0, 0)),
                0
            );
            let mut op = OsdOp::new(code);
            op.set_extent(opwire::Extent {
                offset: 1,
                length: len,
                truncate_size: 1,
                truncate_seq: 2,
            });
            assert_eq!(
                result(&mut pg, &mut eng, 2, mkop(b"o", vec![op])),
                -errno::EFBIG,
                "op {code:#x}, length {len}"
            );
            let objs = pg.store.objects(pg.spg);
            assert_eq!(objs.values().next().expect("object").data, b"abc");
            let oi = oi_of(&pg);
            assert_eq!((oi.truncate_seq, oi.truncate_size), (0, 0));
        }
    }
}

#[test]
fn newer_seq_truncate_still_shrinks_and_extends() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        result(&mut pg, &mut eng, 1, write_hint("o", b"0123456789", 0, 0)),
        0
    );
    // seq 1, size 4: truncate to 4 first, then write "ab" at 0
    assert_eq!(
        result(&mut pg, &mut eng, 2, write_hint("o", b"ab", 1, 4)),
        0
    );
    let objs = pg.store.objects(pg.spg);
    assert_eq!(objs.values().next().expect("object").data, b"ab23");
}

/// A write sent before a truncate keeps its immutable receive buffer when clipped to the current EOF.
/// Pointer identity and skeleton size count payload copies without relying on timing noise.
#[test]
fn stale_truncate_write_shares_its_clipped_payload() {
    for ec in [false, true] {
        let mut pg = TPg::new();
        pg.ec = ec;
        let mut eng = engine(&pg);
        let kept = replwire::SPLIT_MIN;
        assert_eq!(
            result(
                &mut pg,
                &mut eng,
                1,
                write_hint("o", &vec![0; kept], 2, kept as u64)
            ),
            0
        );
        let op = write_hint("o", &vec![0x5a; kept * 2], 0, 0);
        let original = op.ops[0].indata.clone();
        pg.hold = true;
        let outs = run(&mut pg, &mut eng, 1, 2, client(7), op);
        assert!(outs.is_empty(), "no reply before durable completion");
        let (tid, _, txn) = pg.held.first().expect("held write");
        let peering::StoreOp::ApplyTxnSplit { skel, refs, .. } = &txn.ops[0] else {
            panic!("clipped payload was copied into the transaction");
        };
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].len(), kept);
        assert_eq!(refs[0].as_ptr(), original.as_ptr());
        assert!(skel.len() < kept, "skeleton contains no payload copy");
        let tid = *tid;
        let mut outs = pg.release(&mut eng, tid, 0);
        assert_eq!(reply_of(&mut outs, 1, 2).expect("durable reply").result, 0);
        let objs = pg.store.objects(pg.spg);
        assert_eq!(objs.values().next().expect("object").data, original[..kept]);
        assert_eq!(original.len(), kept * 2, "request payload remains intact");
        let oi = oi_of(&pg);
        assert_eq!((oi.size, oi.truncate_seq), (kept as u64, 2));
    }
}

fn oi_of(pg: &TPg) -> replwire::ObjectInfo {
    let objs = pg.store.objects(pg.spg);
    let o = objs.values().next().expect("object");
    denc::from_slice(o.xattrs.get(b"_".as_slice()).expect("oi")).expect("oi decodes")
}

fn trimtrunc(oid: &str, seq: u32, size: u64) -> opwire::MOSDOp {
    // like the MDS (`Filer::truncate`): offset 0, the new in-object EOF in truncate_size
    let mut t = OsdOp::new(opwire::consts::op::TRIMTRUNC);
    t.set_extent(opwire::osdop::Extent {
        offset: 0,
        length: 0,
        truncate_size: size,
        truncate_seq: seq,
    });
    mkop(oid.as_bytes(), vec![t])
}

/// trimtrunc truncates to `truncate_size`, not to `extent.offset` (CephFS shrink to a non-object-aligned EOF).
#[test]
fn trimtrunc_truncates_to_truncate_size() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        result(&mut pg, &mut eng, 1, write_hint("o", b"0123456789", 0, 0)),
        0
    );
    assert_eq!(result(&mut pg, &mut eng, 2, trimtrunc("o", 2, 4)), 0);
    let objs = pg.store.objects(pg.spg);
    assert_eq!(objs.values().next().expect("object").data, b"0123");
    let oi = oi_of(&pg);
    assert_eq!((oi.size, oi.truncate_seq, oi.truncate_size), (4, 2, 4));
    // an older seq is a no-op
    assert_eq!(result(&mut pg, &mut eng, 3, trimtrunc("o", 1, 1)), 0);
    let objs = pg.store.objects(pg.spg);
    assert_eq!(objs.values().next().expect("object").data, b"0123");
}

/// The CephFS "never truncated" hint (seq 1, size u64::MAX) is no hint: nothing recorded in the object info, so a
/// later seq-0 write extending the object is not trimmed as an "old write after trimtrunc" (here or on a classic
/// primary that reads the same object info).
#[test]
fn never_truncated_hint_is_no_hint() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        result(&mut pg, &mut eng, 1, write_hint("o", b"0123", 1, u64::MAX)),
        0
    );
    assert_eq!(
        result(
            &mut pg,
            &mut eng,
            2,
            write_hint("o", b"abcdef", 1, u64::MAX)
        ),
        0
    );
    let oi = oi_of(&pg);
    assert_eq!((oi.truncate_seq, oi.truncate_size), (0, 0));
    let mut w = OsdOp::write(4, b"XYZ".to_vec());
    let mut e = w.extent();
    e.truncate_seq = 0;
    w.set_extent(e);
    assert_eq!(result(&mut pg, &mut eng, 3, mkop(b"o", vec![w])), 0);
    let objs = pg.store.objects(pg.spg);
    assert_eq!(objs.values().next().expect("object").data, b"abcdXYZ");
}

/// An object info stored by an earlier croit-flashstore-osd with the "never truncated" hint recorded (seq 1, size u64::MAX) is
/// read as no hint: a seq-0 extending write is not trimmed, and the write stores the repaired object info.
#[test]
fn stored_never_truncated_hint_is_repaired() {
    use denc::types::{CollT, Ghobject};
    use peering::PgStoreOps;
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        result(&mut pg, &mut eng, 1, write_hint("o", b"0123", 0, 0)),
        0
    );
    // rewrite the stored object info as the old code left it
    let (head, mut oi) = {
        let objs = pg.store.objects(pg.spg);
        let (h, _) = objs.iter().next().expect("object");
        (h.clone(), oi_of(&pg))
    };
    oi.truncate_seq = 1;
    oi.truncate_size = u64::MAX;
    let raw = denc::to_vec(&oi).expect("oi encodes");
    let mut t = replwire::Transaction::new();
    let cx = t.coll(&CollT::Pg(pg.spg));
    let ox = t.obj(&Ghobject::head(head, pg.spg.shard));
    t.push(
        cx,
        replwire::TxnOp::SetAttr {
            oid: ox,
            name: b"_",
            value: &raw,
        },
    );
    let (middle, data) = t.encode_v10(4096).expect("txn encodes");
    pg.store.submit(
        pg.spg,
        &peering::StoreTxn {
            ops: vec![peering::StoreOp::ApplyTxn {
                middle: middle.into(),
                data: data.into(),
            }],
        },
    );
    pg.foreign();
    let mut eng = engine(&pg);
    assert_eq!(
        result(
            &mut pg,
            &mut eng,
            2,
            mkop(b"o", vec![OsdOp::write(4, b"XYZ".to_vec())])
        ),
        0
    );
    let objs = pg.store.objects(pg.spg);
    assert_eq!(objs.values().next().expect("object").data, b"0123XYZ");
    let oi = oi_of(&pg);
    assert_eq!((oi.truncate_seq, oi.truncate_size), (0, 0));
}

/// 16.7 (F4): a write carrying a newer truncate hint on a whiteout head (or an absent object) only records the hint;
/// the write alone decides the final size — no store truncate, no `oi.size = truncate_size` before it.
#[test]
fn truncate_hint_on_a_whiteout_head_only_records() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        result(&mut pg, &mut eng, 1, write_hint("o", b"0123456789", 0, 0)),
        0
    );
    // snap 5 then delete: clone + whiteout head
    let mut d = mkop(b"o", vec![OsdOp::delete()]);
    d.snap_seq = 5;
    d.snaps = vec![5];
    assert_eq!(result(&mut pg, &mut eng, 2, d), 0);
    // write at 4 with hint seq 10 / size 2: the whiteout holds no data to truncate
    let mut w = OsdOp::write(4, b"WXYZ".to_vec());
    let mut e = w.extent();
    e.truncate_seq = 10;
    e.truncate_size = 2;
    w.set_extent(e);
    let mut m = mkop(b"o", vec![w]);
    m.snap_seq = 5;
    m.snaps = vec![5];
    assert_eq!(result(&mut pg, &mut eng, 3, m), 0);
    let mut h = denc::types::Hobject::new(
        b"o",
        denc::types::SnapId::NOSNAP,
        0x1234_5678,
        POOL as i64,
        b"",
    );
    h.set_key(b"");
    let objs = pg.store.objects(pg.spg);
    let o = objs.get(&h).expect("head");
    assert_eq!(o.data.len(), 8, "size from the write, not from the hint");
    assert_eq!(&o.data[4..], b"WXYZ");
    let oi: replwire::ObjectInfo =
        denc::from_slice(o.xattrs.get(b"_".as_slice()).expect("oi")).expect("oi");
    assert_eq!(
        (oi.truncate_seq, oi.truncate_size),
        (10, 2),
        "hint recorded"
    );
    assert_eq!(oi.size, 8);
}
