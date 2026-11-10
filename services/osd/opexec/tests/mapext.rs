// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! MAPEXT (spec client-ops-misc.md 1): `map<u64,u64>` reply, clipping, ENOENT rules, snapshots, EC refusal.
mod common;
use common::*;
use opexec::Engine;
use opwire::{MOSDOpReply, OsdOp, errno};

fn go(
    pg: &mut TPg,
    eng: &mut Engine,
    tid: u64,
    name: &[u8],
    snapid: u64,
    ops: Vec<OsdOp>,
) -> MOSDOpReply {
    let mut m = mkop(name, ops);
    m.snapid = snapid;
    m.flags |= opwire::flag::RETURNVEC;
    let mut out = run(pg, eng, 1, tid, client(7), m);
    reply_of(&mut out, 1, tid).expect("reply")
}
fn map(ext: &[(u64, u64)]) -> Vec<u8> {
    let mut v = (ext.len() as u32).to_le_bytes().to_vec();
    for (o, l) in ext {
        v.extend_from_slice(&o.to_le_bytes());
        v.extend_from_slice(&l.to_le_bytes());
    }
    v
}
const NOSNAP: u64 = opwire::NOSNAP;

#[test]
fn reply_is_one_clipped_extent_or_empty_map() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        go(
            &mut pg,
            &mut eng,
            1,
            b"o",
            NOSNAP,
            vec![OsdOp::write(0, vec![7; 100])]
        )
        .result,
        0
    );
    for (off, len, want) in [
        (0, 100, vec![(0, 100)]),
        (10, 20, vec![(10, 20)]),
        (90, 1000, vec![(90, 10)]),     // clipped to the size
        (10, u64::MAX, vec![(10, 90)]), // offset + length overflow clamps
        (100, 5, vec![]),               // at EOF
        (500, 5, vec![]),               // beyond EOF
        (5, 0, vec![]),                 // length 0
    ] {
        let r = go(
            &mut pg,
            &mut eng,
            2,
            b"o",
            NOSNAP,
            vec![OsdOp::mapext(off, len)],
        );
        assert_eq!((r.result, r.ops[0].rval), (0, 0), "{off} {len}");
        assert_eq!(r.ops[0].outdata.as_ref(), map(&want), "{off} {len}");
    }
    let r = go(
        &mut pg,
        &mut eng,
        3,
        b"o",
        NOSNAP,
        vec![OsdOp::mapext(0, 0)],
    );
    assert_eq!(r.ops[0].outdata.as_ref(), [0, 0, 0, 0]);
    assert_eq!(pg.io.rd, 8);
    // 20 bytes of map = 1 kB; 4 bytes = 1 kB
    assert_eq!(pg.io.rd_kb, 8);
}

#[test]
fn missing_object_enoent_and_write_message_reads_committed_state() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let r = go(
        &mut pg,
        &mut eng,
        1,
        b"x",
        NOSNAP,
        vec![OsdOp::mapext(0, 10)],
    );
    assert_eq!(r.result, -errno::ENOENT);
    // write message on a missing object: -ENOENT from the lookup, nothing created
    let r = go(
        &mut pg,
        &mut eng,
        2,
        b"x",
        NOSNAP,
        vec![OsdOp::mapext(0, 10), OsdOp::write(0, vec![1; 8])],
    );
    assert_eq!(r.result, -errno::ENOENT);
    assert!(pg.store.objects(pg.spg).is_empty());
    // existing object: the pending write of the same message is not visible
    go(
        &mut pg,
        &mut eng,
        3,
        b"x",
        NOSNAP,
        vec![OsdOp::write(0, vec![1; 8])],
    );
    let r = go(
        &mut pg,
        &mut eng,
        4,
        b"x",
        NOSNAP,
        vec![OsdOp::mapext(0, 100), OsdOp::write(0, vec![1; 64])],
    );
    assert_eq!(r.result, 0);
    assert_eq!(r.ops[0].outdata.as_ref(), map(&[(0, 8)]));
}

#[test]
fn snapshot_read_reports_the_clone() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        b"s",
        NOSNAP,
        vec![OsdOp::write(0, vec![1; 8])],
    );
    let mut w = mkop(b"s", vec![OsdOp::write(0, vec![2; 64])]);
    w.snap_seq = 3;
    w.snaps = vec![3];
    let mut out = run(&mut pg, &mut eng, 1, 2, client(7), w);
    assert_eq!(reply_of(&mut out, 1, 2).unwrap().result, 0);
    let r = go(&mut pg, &mut eng, 3, b"s", 3, vec![OsdOp::mapext(0, 100)]);
    assert_eq!(r.ops[0].outdata.as_ref(), map(&[(0, 8)]));
    let r = go(
        &mut pg,
        &mut eng,
        4,
        b"s",
        NOSNAP,
        vec![OsdOp::mapext(0, 100)],
    );
    assert_eq!(r.ops[0].outdata.as_ref(), map(&[(0, 64)]));
    // no covering clone
    let r = go(&mut pg, &mut eng, 5, b"s", 2, vec![OsdOp::mapext(0, 100)]);
    assert_eq!(r.result, -errno::ENOENT);
}

#[test]
fn ec_pool_refuses_first_and_aborts_the_vector() {
    let mut pg = TPg::new();
    pg.ec = true;
    let mut eng = engine(&pg);
    // refused before the existence check: missing object too
    let r = go(
        &mut pg,
        &mut eng,
        1,
        b"e",
        NOSNAP,
        vec![
            OsdOp::write(0, vec![1; 8]),
            OsdOp::mapext(0, 8),
            OsdOp::read(0, 8),
        ],
    );
    assert_eq!(r.result, -errno::EOPNOTSUPP);
    assert_eq!(r.ops[1].rval, -errno::EOPNOTSUPP);
    assert!(r.ops[2].outdata.is_empty());
}
