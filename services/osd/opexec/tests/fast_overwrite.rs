// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The plain-overwrite executor (`fast`) and the general executor produce the same log entries, transactions, replies
//! and object state. Reference: the same message with ORDERSNAP (which the fast path leaves to the general executor
//! and which changes nothing for a snap context at the object's seq).
mod common;
use common::*;
use opwire::{OsdOp, flag};

/// One message on both clusters (plain, forced general); checks everything observable is equal.
fn both(
    a: &mut (TPg, opexec::Engine),
    b: &mut (TPg, opexec::Engine),
    tid: u64,
    op: opwire::MOSDOp,
) {
    let mut forced = op.clone();
    forced.flags |= flag::ORDERSNAP;
    let mut oa = run(&mut a.0, &mut a.1, 1, tid, client(7), op);
    let mut ob = run(&mut b.0, &mut b.1, 1, tid, client(7), forced);
    let (mut ra, mut rb) = (
        reply_of(&mut oa, 1, tid).expect("reply a"),
        reply_of(&mut ob, 1, tid).expect("reply b"),
    );
    // the reply echoes the request flags (ORDERSNAP is the reference's only difference)
    (ra.flags, rb.flags) = (0, 0);
    assert_eq!(format!("{ra:?}"), format!("{rb:?}"), "reply of tid {tid}");
    assert_eq!(a.0.txns, b.0.txns, "transactions after tid {tid}");
    assert_eq!(
        format!("{:?}", a.0.entries),
        format!("{:?}", b.0.entries),
        "log entries after tid {tid}"
    );
}

fn pair(ec: bool) -> ((TPg, opexec::Engine), (TPg, opexec::Engine)) {
    let (mut pa, mut pb) = (TPg::new(), TPg::new());
    (pa.ec, pb.ec) = (ec, ec);
    let (ea, eb) = (engine(&pa), engine(&pb));
    ((pa, ea), (pb, eb))
}

fn pat(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[test]
fn overwrites_match_the_general_executor() {
    overwrites(false);
}

#[test]
fn ec_overwrites_match_the_general_executor() {
    overwrites(true);
}

fn overwrites(ec: bool) {
    let (mut a, mut b) = pair(ec);
    let mut tid = 0;
    let mut go = |a: &mut (TPg, opexec::Engine), b: &mut (TPg, opexec::Engine), op| {
        tid += 1;
        both(a, b, tid, op);
    };
    // create (general on both), then overwrites of every shape
    go(
        &mut a,
        &mut b,
        mkop(b"o", vec![OsdOp::write(0, pat(4096, 1))]),
    );
    go(
        &mut a,
        &mut b,
        mkop(b"o", vec![OsdOp::write(0, pat(4096, 2))]),
    );
    go(
        &mut a,
        &mut b,
        mkop(b"o", vec![OsdOp::write(512, pat(100, 3))]),
    );
    go(
        &mut a,
        &mut b,
        mkop(b"o", vec![OsdOp::write(4000, pat(5000, 4))]),
    ); // grows
    go(
        &mut a,
        &mut b,
        mkop(b"o", vec![OsdOp::write(1 << 20, pat(4096, 5))]),
    ); // gap
    go(
        &mut a,
        &mut b,
        mkop(b"o", vec![OsdOp::write(0, pat(200 << 10, 6))]),
    ); // out-of-line payload
    go(&mut a, &mut b, mkop(b"o", vec![OsdOp::write(7, vec![9])]));
    let mut nomtime = mkop(b"o", vec![OsdOp::write(0, pat(64, 7))]);
    nomtime.mtime = Default::default();
    go(&mut a, &mut b, nomtime);
    // an object with an xattr and one in a namespace
    go(
        &mut a,
        &mut b,
        mkop(
            b"x",
            vec![OsdOp::write(0, pat(10, 8)), OsdOp::setxattr(b"k", b"v")],
        ),
    );
    go(
        &mut a,
        &mut b,
        mkop(b"x", vec![OsdOp::write(3, pat(10, 9))]),
    );
    // not eligible (same on both): snap context newer than the object's, then plain again under it
    let mut snapped = mkop(b"o", vec![OsdOp::write(0, pat(10, 10))]);
    snapped.snap_seq = 5;
    snapped.snaps = vec![5];
    go(&mut a, &mut b, snapped.clone());
    go(&mut a, &mut b, snapped);
    // read back
    for p in [&mut a, &mut b] {
        let mut outs = run(
            &mut p.0,
            &mut p.1,
            1,
            999,
            client(7),
            mkop(b"o", vec![OsdOp::read(0, 4096)]),
        );
        assert_eq!(reply_of(&mut outs, 1, 999).unwrap().result, 0);
    }
    // the plain cluster used the fast path for the plain overwrites, the reference never
    assert!(
        a.1.c.fast_writes >= 8,
        "fast overwrites: {}",
        a.1.c.fast_writes
    );
    assert_eq!(b.1.c.fast_writes, 0);
}

#[test]
fn what_the_fast_path_does_not_know_goes_the_general_way() {
    let (mut a, _) = pair(false);
    let mut tid = 0;
    let mut w = |a: &mut (TPg, opexec::Engine), op: opwire::MOSDOp| {
        tid += 1;
        let mut o = run(&mut a.0, &mut a.1, 1, tid, client(7), op);
        reply_of(&mut o, 1, tid).expect("reply").result
    };
    assert_eq!(w(&mut a, mkop(b"o", vec![OsdOp::write(0, pat(100, 1))])), 0);
    let base = a.1.c.fast_writes;
    // several ops, writefull, append, zero-length write, truncate hint, full pool, no room, pool snaps, RETURNVEC
    assert_eq!(
        w(
            &mut a,
            mkop(
                b"o",
                vec![OsdOp::write(0, pat(10, 2)), OsdOp::write(20, pat(10, 3))]
            )
        ),
        0
    );
    assert_eq!(w(&mut a, mkop(b"o", vec![OsdOp::writefull(pat(10, 4))])), 0);
    assert_eq!(w(&mut a, mkop(b"o", vec![OsdOp::append(pat(10, 5))])), 0);
    assert_eq!(w(&mut a, mkop(b"o", vec![OsdOp::write(0, vec![])])), 0);
    let mut rv = mkop(b"o", vec![OsdOp::write(0, pat(10, 6))]);
    rv.flags |= flag::RETURNVEC;
    assert_eq!(w(&mut a, rv), 0);
    a.0.full = (true, false);
    let r = w(&mut a, mkop(b"o", vec![OsdOp::write(0, pat(10, 7))]));
    assert_eq!(r, 0, "a full pool still admits a write that does not grow");
    // a growing write of a plain client to a full pool is dropped without a reply
    let drop_tid = 9000;
    let mut o = run(
        &mut a.0,
        &mut a.1,
        1,
        drop_tid,
        client(7),
        mkop(b"o", vec![OsdOp::write(1 << 20, pat(10, 8))]),
    );
    assert!(reply_of(&mut o, 1, drop_tid).is_none());
    a.0.full = (false, false);
    a.0.room = false;
    assert!(w(&mut a, mkop(b"o", vec![OsdOp::write(0, pat(10, 9))])) < 0);
    a.0.room = true;
    assert_eq!(
        a.1.c.fast_writes, base,
        "none of those is a plain overwrite"
    );
    assert_eq!(w(&mut a, mkop(b"o", vec![OsdOp::write(0, pat(10, 9))])), 0);
    assert_eq!(a.1.c.fast_writes, base + 1);
}
