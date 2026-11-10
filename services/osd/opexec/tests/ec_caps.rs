// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! EC pool capabilities in the op layer (client-ops 16.4): the SYNC_READ gate (EC_OPTIMIZATIONS) and the legacy
//! append-only write forms (no EC_OVERWRITES). Errors come before any state change and abort the whole vector.
mod common;
use common::*;
use opexec::{EcCaps, Engine};
use opwire::{OsdOp, errno, op as code};

fn go(pg: &mut TPg, eng: &mut Engine, tid: u64, ops: Vec<OsdOp>) -> opwire::MOSDOpReply {
    let mut outs = run(pg, eng, 1, tid, client(7), mkop(b"o", ops));
    reply_of(&mut outs, 1, tid).expect("reply")
}

fn append_only(pg: &mut TPg) {
    pg.ec = true;
    pg.ec_caps = EcCaps {
        allows_optimizations: false,
        requires_aligned_append: true,
        required_alignment: 4096,
    };
}

fn overwrites(pg: &mut TPg) {
    pg.ec = true;
    pg.ec_caps = EcCaps {
        allows_optimizations: true,
        requires_aligned_append: false,
        required_alignment: 4096,
    };
}

fn head(oid: &str) -> denc::types::Hobject {
    let mut h = denc::types::Hobject::new(
        oid.as_bytes(),
        denc::types::SnapId::NOSNAP,
        0x1234_5678,
        POOL as i64,
        b"",
    );
    h.set_key(b"");
    h
}

#[test]
fn sync_read_needs_ec_optimizations() {
    let mut pg = TPg::new();
    append_only(&mut pg);
    let mut eng = engine(&pg);
    assert_eq!(
        go(&mut pg, &mut eng, 1, vec![OsdOp::write(0, vec![7u8; 8])]).result,
        0
    );
    let mut sync = OsdOp::read(0, 4);
    sync.op = code::SYNC_READ;
    assert_eq!(
        go(&mut pg, &mut eng, 2, vec![sync.clone()]).result,
        -errno::EOPNOTSUPP
    );
    let mut pg = TPg::new();
    overwrites(&mut pg);
    let mut eng = engine(&pg);
    assert_eq!(
        go(&mut pg, &mut eng, 1, vec![OsdOp::write(0, vec![7u8; 8])]).result,
        0
    );
    let r = go(&mut pg, &mut eng, 2, vec![sync]);
    assert_eq!(r.result, 0);
    assert_eq!(r.ops[0].outdata, vec![7u8; 4]);
}

#[test]
fn append_only_write_rules() {
    let mut pg = TPg::new();
    append_only(&mut pg);
    let mut eng = engine(&pg);
    // a new object only at offset 0, on the alignment
    assert_eq!(
        go(&mut pg, &mut eng, 1, vec![OsdOp::write(512, b"x".to_vec())]).result,
        -errno::EOPNOTSUPP
    );
    assert!(!pg.store.objects(pg.spg).contains_key(&head("o")));
    assert_eq!(
        go(&mut pg, &mut eng, 2, vec![OsdOp::write(0, vec![1u8; 4096])]).result,
        0
    );
    // an existing object only at its current size
    assert_eq!(
        go(&mut pg, &mut eng, 3, vec![OsdOp::write(0, vec![2u8; 4096])]).result,
        -errno::EOPNOTSUPP
    );
    assert_eq!(
        go(&mut pg, &mut eng, 4, vec![OsdOp::write(4, b"x".to_vec())]).result,
        -errno::EOPNOTSUPP
    );
    assert_eq!(
        go(
            &mut pg,
            &mut eng,
            5,
            vec![OsdOp::write(4096, vec![3u8; 4096])]
        )
        .result,
        0
    );
    // no zero / truncate / trimtrunc
    assert_eq!(
        go(&mut pg, &mut eng, 6, vec![OsdOp::zero(0, 8)]).result,
        -errno::EOPNOTSUPP
    );
    assert_eq!(
        go(&mut pg, &mut eng, 7, vec![OsdOp::truncate(0)]).result,
        -errno::EOPNOTSUPP
    );
    let mut trim = OsdOp::new(code::TRIMTRUNC);
    let mut e = trim.extent();
    e.offset = 0;
    trim.set_extent(e);
    assert_eq!(
        go(&mut pg, &mut eng, 8, vec![trim]).result,
        -errno::EOPNOTSUPP
    );
    // the failed ops changed nothing: the object still holds exactly the two appended stripes
    let objs = pg.store.objects(pg.spg);
    let o = objs.values().next().expect("object");
    assert_eq!(o.data.len(), 8192);
    assert!(o.data[..4096].iter().all(|b| *b == 1));
    assert!(o.data[4096..].iter().all(|b| *b == 3));
    let oi: replwire::ObjectInfo =
        denc::from_slice(o.xattrs.get(b"_".as_slice()).expect("oi")).unwrap();
    assert_eq!(oi.size, 8192);
}

#[test]
fn ec_pool_with_overwrites_accepts_zero_and_truncate() {
    let mut pg = TPg::new();
    overwrites(&mut pg);
    let mut eng = engine(&pg);
    assert_eq!(
        go(&mut pg, &mut eng, 1, vec![OsdOp::write(0, vec![1u8; 16])]).result,
        0
    );
    assert_eq!(go(&mut pg, &mut eng, 2, vec![OsdOp::zero(0, 8)]).result, 0);
    assert_eq!(go(&mut pg, &mut eng, 3, vec![OsdOp::truncate(4)]).result, 0);
}

/// Sibling check: a replicated pool ignores the EC caps entirely (a large offset / zero / truncate stay valid).
#[test]
fn replicated_pool_is_not_gated() {
    let mut pg = TPg::new();
    pg.ec_caps = EcCaps {
        allows_optimizations: false,
        requires_aligned_append: true,
        required_alignment: 4096,
    };
    let mut eng = engine(&pg);
    assert_eq!(
        go(&mut pg, &mut eng, 1, vec![OsdOp::write(512, b"x".to_vec())]).result,
        0
    );
    assert_eq!(go(&mut pg, &mut eng, 2, vec![OsdOp::zero(0, 1)]).result, 0);
    let mut sync = OsdOp::read(0, 2);
    sync.op = code::SYNC_READ;
    assert_eq!(go(&mut pg, &mut eng, 3, vec![sync]).result, 0);
}

/// Append and writesame are writes (at the current size, at their offset): the append-only rules refuse them like a
/// write, before any state change.
#[test]
fn append_only_rules_cover_append_and_writesame() {
    let mut pg = TPg::new();
    append_only(&mut pg);
    let mut eng = engine(&pg);
    assert_eq!(
        go(&mut pg, &mut eng, 1, vec![OsdOp::append(vec![1u8; 4096])]).result,
        0
    );
    assert_eq!(
        go(&mut pg, &mut eng, 2, vec![OsdOp::append(b"x".to_vec())]).result,
        0
    );
    // the size is off the alignment now: a further append is refused
    assert_eq!(
        go(&mut pg, &mut eng, 3, vec![OsdOp::append(b"y".to_vec())]).result,
        -errno::EOPNOTSUPP
    );
    let mut pg = TPg::new();
    append_only(&mut pg);
    let mut eng = engine(&pg);
    assert_eq!(
        go(&mut pg, &mut eng, 1, vec![OsdOp::write(0, vec![1u8; 4096])]).result,
        0
    );
    assert_eq!(
        go(
            &mut pg,
            &mut eng,
            2,
            vec![OsdOp::writesame(0, 4096, vec![9u8; 512])]
        )
        .result,
        -errno::EOPNOTSUPP
    );
    assert_eq!(
        go(
            &mut pg,
            &mut eng,
            3,
            vec![OsdOp::writesame(4096, 4096, vec![9u8; 512])]
        )
        .result,
        0
    );
    let objs = pg.store.objects(pg.spg);
    let o = objs.values().next().expect("object");
    assert_eq!(o.data.len(), 8192);
    assert!(o.data[..4096].iter().all(|b| *b == 1));
}

/// SYNC_READ uses the same asynchronous decoded-data gate as READ, including length 0 to EOF.
#[test]
fn sync_read_waits_for_decoded_ec_data() {
    for length in [4, 0] {
        let mut pg = TPg::new();
        overwrites(&mut pg);
        let mut eng = engine(&pg);
        assert_eq!(
            go(&mut pg, &mut eng, 1, vec![OsdOp::writefull(vec![7; 8])]).result,
            0
        );
        let mut sync = OsdOp::read(2, length);
        sync.op = code::SYNC_READ;
        let request = mkop(b"o", vec![sync]);
        // Leave the decoded range unavailable until the explicit wake below.
        pg.ec_busy_objs.borrow_mut().insert(b"o".to_vec());
        eng.on_op(
            &mut pg,
            opexec::ClientReq {
                placement_read: None,
                conn: 1,
                caps: None,
                tid: 2,
                op: Box::new(request),
                who: client(7),
                addr: Default::default(),
                peer_addr: Default::default(),
                features: 0,
            },
        );
        assert!(
            settle(&mut pg, &mut eng).is_empty(),
            "must wait for EC data"
        );
        assert!(pg.ec_waits.get() > 0, "decoded range must be requested");
        pg.ec_busy_objs.borrow_mut().clear();
        eng.retry(&mut pg);
        let mut outs = settle(&mut pg, &mut eng);
        let r = reply_of(&mut outs, 1, 2).expect("read after decode");
        assert_eq!(r.result, 0);
        assert_eq!(r.ops[0].outdata, vec![7; if length == 0 { 6 } else { 4 }]);
    }
}

#[test]
fn replicated_sync_read_probes_the_requested_range() {
    for length in [4, 0] {
        let mut pg = TPg::new();
        let mut eng = engine(&pg);
        assert_eq!(
            go(&mut pg, &mut eng, 1, vec![OsdOp::writefull(vec![7; 8])]).result,
            0
        );
        pg.probes.borrow_mut().clear();
        let mut sync = OsdOp::read(2, length);
        sync.op = code::SYNC_READ;
        let r = go(&mut pg, &mut eng, 2, vec![sync]);
        assert_eq!(r.result, 0);
        assert!(
            pg.probes
                .borrow()
                .contains(&(2, if length == 0 { 4 << 20 } else { 4 }))
        );
    }
}
