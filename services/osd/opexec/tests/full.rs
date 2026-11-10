// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Full-pool admission (G25, client-ops 5.4 #11 / 5.7 step 5 / 5.8): which writes pass a FULL pool.
mod common;
use common::*;
use opwire::{MOSDOpReply, OsdOp, errno, flag as mflag};
use std::collections::BTreeMap;

fn go_as(
    pg: &mut TPg,
    eng: &mut opexec::Engine,
    who: denc::types::EntityName,
    tid: u64,
    op: opwire::MOSDOp,
) -> Option<MOSDOpReply> {
    let mut outs = run(pg, eng, 1, tid, who, op);
    reply_of(&mut outs, 1, tid)
}

fn omap(k: &str) -> OsdOp {
    OsdOp::omap_set_vals(&BTreeMap::from([(k.as_bytes().to_vec(), b"v".to_vec())]))
}

fn flagged(mut op: opwire::MOSDOp, f: u32) -> opwire::MOSDOp {
    op.flags |= f;
    op
}

fn seeded() -> (TPg, opexec::Engine) {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let r = go_as(
        &mut pg,
        &mut eng,
        client(7),
        1,
        mkop(b"a", vec![OsdOp::write(0, b"hello".to_vec())]),
    );
    assert_eq!(r.unwrap().result, 0);
    (pg, eng)
}

#[test]
fn eio_pool_refuses_object_requests_by_client_support() {
    for ec in [false, true] {
        for flags in [0, mflag::FULL_TRY, mflag::FULL_FORCE] {
            for supports in [false, true] {
                let (mut pg, mut eng) = seeded();
                pg.ec = ec;
                pg.pool_eio = true;
                let log_len = pg.entries.len();
                for (i, ops) in [
                    vec![OsdOp::read(0, 5)],
                    vec![OsdOp::writefull(b"changed".to_vec())],
                    vec![OsdOp::delete()],
                ]
                .into_iter()
                .enumerate()
                {
                    let flags = flags | if supports { mflag::SUPPORTSPOOLEIO } else { 0 };
                    let r = go_as(
                        &mut pg,
                        &mut eng,
                        client(7),
                        20 + i as u64,
                        flagged(mkop(b"a", ops), flags),
                    );
                    if supports {
                        assert!(
                            r.is_none(),
                            "map-aware client waits for the pool EIO flag to clear"
                        );
                        assert_eq!(eng.take_dropped().len(), 1);
                    } else {
                        assert_eq!(r.unwrap().result, -errno::EIO);
                    }
                    assert_eq!(
                        pg.entries.len(),
                        log_len,
                        "EIO pool refusal never logs a mutation"
                    );
                }
                pg.pool_eio = false;
                let r = go_as(
                    &mut pg,
                    &mut eng,
                    client(7),
                    30,
                    mkop(b"a", vec![OsdOp::read(0, 5)]),
                )
                .unwrap();
                assert_eq!(r.result, 0);
                assert_eq!(r.ops[0].outdata[..], *b"hello");
            }
        }
    }
}

#[test]
fn full_pool_growing_writes_by_flag() {
    let (mut pg, mut eng) = seeded();
    pg.full = (true, false);
    let grow = |oid: &[u8]| mkop(oid, vec![OsdOp::write(0, b"more data".to_vec())]);
    // plain client: dropped WITHOUT a reply (an -EAGAIN would make the stock client resend at once with its old map);
    // the OSD shares the map through the dropped-op list, nothing applied
    assert!(eng.take_dropped().is_empty());
    let r = go_as(&mut pg, &mut eng, client(7), 2, grow(b"b"));
    assert!(
        r.is_none(),
        "plain growing write to a full pool is not answered"
    );
    assert_eq!(eng.take_dropped().len(), 1);
    assert_eq!(eng.c.full_drops, 1, "counted as a full-pool drop");
    assert_eq!(eng.c.stale, 0, "not reported as a split / primary change");
    // FULL_TRY: -ENOSPC; with a quota flag -EDQUOT
    let r = go_as(
        &mut pg,
        &mut eng,
        client(7),
        3,
        flagged(grow(b"b"), mflag::FULL_TRY),
    )
    .unwrap();
    assert_eq!(r.result, -errno::ENOSPC);
    pg.full = (true, true);
    let r = go_as(
        &mut pg,
        &mut eng,
        client(7),
        4,
        flagged(grow(b"b"), mflag::FULL_TRY),
    )
    .unwrap();
    assert_eq!(r.result, -errno::EDQUOT);
    pg.full = (true, false);
    // FULL_FORCE and MDS sources pass
    let r = go_as(
        &mut pg,
        &mut eng,
        client(7),
        5,
        flagged(grow(b"b"), mflag::FULL_FORCE),
    )
    .unwrap();
    assert_eq!(r.result, 0);
    let r = go_as(
        &mut pg,
        &mut eng,
        denc::types::EntityName {
            ty: denc::types::EntityName::MDS,
            num: 0,
        },
        6,
        grow(b"c"),
    )
    .unwrap();
    assert_eq!(r.result, 0);
    // extending an existing object grows bytes too
    let r = go_as(
        &mut pg,
        &mut eng,
        client(7),
        7,
        flagged(
            mkop(b"a", vec![OsdOp::write(5, b"!!".to_vec())]),
            mflag::FULL_TRY,
        ),
    )
    .unwrap();
    assert_eq!(r.result, -errno::ENOSPC);
}

#[test]
fn full_pool_non_growing_writes_pass() {
    let (mut pg, mut eng) = seeded();
    pg.full = (true, false);
    // overwrite inside the object, omap / xattr on an existing object: no byte or object growth
    for (tid, ops) in [
        (2, vec![OsdOp::write(0, b"HE".to_vec())]),
        (3, vec![omap("k")]),
        (4, vec![OsdOp::setxattr(b"x", b"y")]),
        (5, vec![OsdOp::truncate(2)]),
    ] {
        let r = go_as(&mut pg, &mut eng, client(7), tid, mkop(b"a", ops)).unwrap();
        assert_eq!(r.result, 0, "tid {tid}");
    }
    // deletes always work
    let r = go_as(
        &mut pg,
        &mut eng,
        client(7),
        6,
        mkop(b"a", vec![OsdOp::delete()]),
    )
    .unwrap();
    assert_eq!(r.result, 0);
    // creating a new object (even omap-only) counts as growth
    let r = go_as(
        &mut pg,
        &mut eng,
        client(7),
        7,
        flagged(mkop(b"n", vec![omap("k")]), mflag::FULL_TRY),
    )
    .unwrap();
    assert_eq!(r.result, -errno::ENOSPC);
    // reads are never affected
    let r = go_as(
        &mut pg,
        &mut eng,
        client(7),
        8,
        mkop(b"zz", vec![OsdOp::stat()]),
    )
    .unwrap();
    assert_eq!(r.result, -errno::ENOENT);
}

#[test]
fn ops_sent_before_full_epoch_are_discarded() {
    let (mut pg, mut eng) = seeded();
    pg.full = (true, false);
    pg.marked_full = 12;
    let grow = |oid: &[u8]| mkop(oid, vec![OsdOp::write(0, b"x".to_vec())]); // sent at epoch 10
    // older than the full mark: no reply at all, the client learns the map and resends
    assert!(go_as(&mut pg, &mut eng, client(7), 2, grow(b"b")).is_none());
    assert_eq!(
        eng.take_dropped(),
        vec![opexec::Dropped {
            conn: 1,
            tid: 2,
            epoch: 10
        }]
    );
    assert_eq!(eng.c.full_drops, 1, "counted as a full-pool drop");
    assert_eq!(eng.c.stale, 0, "not reported as a split / primary change");
    // FULL_TRY / FULL_FORCE / MDS are not discarded
    let r = go_as(
        &mut pg,
        &mut eng,
        client(7),
        3,
        flagged(grow(b"b"), mflag::FULL_TRY),
    )
    .unwrap();
    assert_eq!(r.result, -errno::ENOSPC);
    let mds = denc::types::EntityName {
        ty: denc::types::EntityName::MDS,
        num: 0,
    };
    assert_eq!(
        go_as(&mut pg, &mut eng, mds, 4, grow(b"b")).unwrap().result,
        0
    );
    // a delete (rwordered too) from an old epoch is discarded as well (classic does); sent after the mark it works
    assert!(
        go_as(
            &mut pg,
            &mut eng,
            client(7),
            5,
            mkop(b"a", vec![OsdOp::delete()])
        )
        .is_none()
    );
    let mut late = mkop(b"a", vec![OsdOp::delete()]);
    late.osdmap_epoch = 12;
    assert_eq!(
        go_as(&mut pg, &mut eng, client(7), 6, late).unwrap().result,
        0
    );
    // plain reads (not rwordered) are served
    let r = go_as(
        &mut pg,
        &mut eng,
        client(7),
        7,
        mkop(b"b", vec![OsdOp::read(0, 10)]),
    )
    .unwrap();
    assert_eq!(r.result, 0);
    assert_eq!(eng.c.full_drops, 2, "the old-epoch delete is one too");
    assert_eq!(eng.c.stale, 0);
}

#[test]
fn eio_pool_rechecks_waiters_and_keeps_pg_operations_available() {
    for supports in [false, true] {
        let (mut pg, mut eng) = seeded();
        pg.hold = true;
        assert!(
            go_as(
                &mut pg,
                &mut eng,
                client(7),
                40,
                mkop(b"a", vec![OsdOp::writefull(b"durable".to_vec())])
            )
            .is_none()
        );
        let tid = pg.held_tids()[0];
        let read = flagged(
            mkop(b"a", vec![OsdOp::read(0, 7)]),
            if supports { mflag::SUPPORTSPOOLEIO } else { 0 },
        );
        assert!(go_as(&mut pg, &mut eng, client(7), 41, read).is_none());
        pg.pool_eio = true;
        let mut outs = pg.release(&mut eng, tid, 0);
        assert_eq!(
            reply_of(&mut outs, 1, 40).unwrap().result,
            0,
            "write accepted before the EIO map may finish"
        );
        let read = reply_of(&mut outs, 1, 41);
        if supports {
            assert!(read.is_none());
            assert_eq!(eng.take_dropped().len(), 1);
        } else {
            assert_eq!(read.unwrap().result, -errno::EIO);
        }
        let r = go_as(
            &mut pg,
            &mut eng,
            client(7),
            42,
            mkop(b"", vec![OsdOp::new(opwire::op::PG_HITSET_LS)]),
        )
        .unwrap();
        assert_eq!(
            r.result, 0,
            "PG-level queries precede the pool EIO object fence"
        );
    }
}

#[test]
fn eio_pool_error_precedence() {
    let (mut pg, mut eng) = seeded();
    pg.pool_eio = true;
    for supports in [false, true] {
        let mut op = mkop(
            b"a",
            vec![OsdOp::writefull(b"invalid snapshot write".to_vec())],
        );
        op.snapid = 123;
        if supports {
            op.flags |= mflag::SUPPORTSPOOLEIO;
        }
        let r = go_as(&mut pg, &mut eng, client(7), 50, op);
        if supports {
            assert!(r.is_none(), "pool EIO drop precedes invalid snapshot");
            assert_eq!(eng.take_dropped().len(), 1);
        } else {
            assert_eq!(
                r.unwrap().result,
                -errno::EIO,
                "pool EIO precedes invalid snapshot"
            );
        }
    }
}

/// Classic order (PrimaryLogPG::do_op, own words): blocklist, stale-full discard, local failsafe drop of write-ordered
/// non-FULL_TRY ops, pool EIO fence (drop for SUPPORTSPOOLEIO, else EIO), then snapshot/size validation. PG ops precede all.
/// Deviation kept: a pure shrink passes the failsafe, except on an EIO pool (which refuses everything anyway).
#[test]
fn failsafe_precedes_pool_eio_fence_by_classic_order() {
    for eio in [false, true] {
        for supports in [false, true] {
            for full_try in [false, true] {
                for (name, ops, ordered, shrink) in [
                    ("read", vec![OsdOp::read(0, 5)], false, false),
                    ("write", vec![OsdOp::writefull(b"x".to_vec())], true, false),
                    ("delete", vec![OsdOp::delete()], true, true),
                ] {
                    let (mut pg, mut eng) = seeded();
                    pg.pool_eio = eio;
                    pg.failsafe = true;
                    let mut f = 0;
                    if supports {
                        f |= mflag::SUPPORTSPOOLEIO;
                    }
                    if full_try {
                        f |= mflag::FULL_TRY;
                    }
                    let log_len = pg.entries.len();
                    let r = go_as(
                        &mut pg,
                        &mut eng,
                        client(7),
                        60,
                        flagged(mkop(b"a", ops), f),
                    );
                    let dropped = eng.take_dropped().len();
                    let failsafe_drop = ordered && !full_try && (!shrink || eio);
                    let ctx = format!("{name} eio={eio} supports={supports} full_try={full_try}");
                    if failsafe_drop || (eio && supports) {
                        assert!(r.is_none() && dropped == 1, "drop: {ctx}");
                    } else if eio {
                        assert_eq!(r.unwrap().result, -errno::EIO, "{ctx}");
                    } else {
                        assert_eq!(r.unwrap().result, 0, "{ctx}");
                    }
                    if eio || failsafe_drop {
                        assert_eq!(pg.entries.len(), log_len, "no mutation logged: {ctx}");
                    }
                }
            }
        }
    }
}

#[test]
fn failsafe_error_precedence() {
    // validation after the failsafe drop: an invalid snapshot write is dropped, not EINVAL
    let (mut pg, mut eng) = seeded();
    pg.failsafe = true;
    let mut op = mkop(b"a", vec![OsdOp::writefull(b"x".to_vec())]);
    op.snapid = 123;
    assert!(go_as(&mut pg, &mut eng, client(7), 70, op).is_none());
    assert_eq!(eng.take_dropped().len(), 1);
    // checks before it still answer: a blocklisted client gets EBLOCKLISTED, not a silent drop
    let ip = [10, 0, 0, 5];
    pg.blocklist.borrow_mut().push(ip);
    let addr = denc::types::EntityAddr::v4(denc::types::EntityAddr::TYPE_MSGR2, 9, ip, 0);
    eng.on_op(
        &mut pg,
        opexec::ClientReq {
            placement_read: None,
            conn: 1,
            caps: None,
            tid: 71,
            op: Box::new(mkop(b"a", vec![OsdOp::writefull(b"x".to_vec())])),
            who: client(7),
            addr,
            peer_addr: addr,
            features: 0x3f17_ffff_fffd_ffff,
        },
    );
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(
        reply_of(&mut outs, 1, 71).unwrap().result,
        -errno::EBLOCKLISTED
    );
}

/// A write refused by the failsafe at arrival is gone: it never queues behind an object in flight, so once the failsafe
/// clears it cannot reach execution unvalidated (invalid snapid write onto HEAD).
#[test]
fn failsafe_drop_precedes_object_queuing() {
    for eio in [false, true] {
        let (mut pg, mut eng) = seeded();
        pg.hold = true;
        assert!(
            go_as(
                &mut pg,
                &mut eng,
                client(7),
                80,
                mkop(b"a", vec![OsdOp::writefull(b"first".to_vec())])
            )
            .is_none()
        );
        let tid = pg.held_tids()[0];
        // a read waits behind the in-flight write: anything arriving now queues behind it
        assert!(
            go_as(
                &mut pg,
                &mut eng,
                client(7),
                79,
                mkop(b"a", vec![OsdOp::read(0, 5)])
            )
            .is_none()
        );
        pg.failsafe = !eio;
        pg.pool_eio = eio;
        let mut bad = mkop(
            b"a",
            vec![OsdOp::writefull(b"invalid snapshot write".to_vec())],
        );
        bad.snapid = 123;
        bad.flags |= mflag::SUPPORTSPOOLEIO;
        assert!(go_as(&mut pg, &mut eng, client(7), 81, bad).is_none());
        pg.failsafe = false;
        pg.pool_eio = false;
        let mut outs = pg.release(&mut eng, tid, 0);
        assert_eq!(reply_of(&mut outs, 1, 80).unwrap().result, 0);
        assert_eq!(reply_of(&mut outs, 1, 79).unwrap().result, 0);
        assert!(
            reply_of(&mut outs, 1, 81).is_none(),
            "the refused write must not execute after the fence clears (eio={eio})"
        );
        assert_eq!(eng.take_dropped().len(), 1);
        assert_eq!(pg.entries.len(), 2, "seed write + first write only: {eio}");
    }
}
