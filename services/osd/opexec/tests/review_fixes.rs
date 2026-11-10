// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Regression tests from the second opexec review: one classification per message, and a `user_version` at its
//! representable end that must not wrap.

mod common;
use common::*;
use denc::types::{EntityAddr, Hobject, SnapId};
use opexec::{ClientReq, Engine};
use opwire::OsdOp;
use replwire::ObjectInfo;

fn head(oid: &str) -> Hobject {
    let mut h = Hobject::new(
        oid.as_bytes(),
        SnapId::NOSNAP,
        0x1234_5678,
        POOL as i64,
        b"",
    );
    h.set_key(b"");
    h
}

fn creq(tid: u64, op: opwire::MOSDOp) -> ClientReq {
    ClientReq {
        placement_read: None,
        conn: 1,
        caps: None,
        tid,
        op: Box::new(op),
        who: client(7),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    }
}

/// Set the stored `object_info` of `oid` the way a damaged / mixed-version record could carry it.
fn set_oi(pg: &mut TPg, oid: &str, f: impl FnOnce(&mut ObjectInfo)) {
    let o = pg
        .store
        .pgs
        .get_mut(&pg.spg)
        .expect("pg")
        .objects
        .get_mut(&head(oid))
        .expect("object");
    let mut oi: ObjectInfo = denc::from_slice(o.xattrs.get(b"_".as_slice()).expect("oi")).unwrap();
    f(&mut oi);
    o.xattrs
        .insert(b"_".to_vec(), denc::to_vec(&oi).expect("oi encodes"));
    pg.foreign(); // the change is seen on the next load, not from a cached state
}

fn oi(pg: &TPg, oid: &str) -> ObjectInfo {
    denc::from_slice(
        pg.store
            .objects(pg.spg)
            .get(&head(oid))
            .expect("object")
            .xattrs
            .get(b"_".as_slice())
            .expect("oi"),
    )
    .unwrap()
}

fn put(pg: &mut TPg, eng: &mut Engine, oid: &str, data: &[u8]) {
    let mut outs = run(
        pg,
        eng,
        1,
        1,
        client(7),
        mkop(oid.as_bytes(), vec![OsdOp::writefull(data.to_vec())]),
    );
    assert_eq!(reply_of(&mut outs, 1, 1).expect("reply").result, 0);
}

#[test]
fn a_message_is_classified_once_per_run() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    put(&mut pg, &mut eng, "o", b"hello");
    eng.c.classify_calls = 0;
    let mut outs = run(
        &mut pg,
        &mut eng,
        1,
        2,
        client(7),
        mkop(b"o", vec![OsdOp::write(0, b"xy".to_vec())]),
    );
    assert_eq!(reply_of(&mut outs, 1, 2).expect("reply").result, 0);
    assert_eq!(
        eng.c.classify_calls, 1,
        "precheck's classification is reused by the execution"
    );
}

#[test]
fn a_waiter_released_by_a_write_is_classified_once_per_run() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    put(&mut pg, &mut eng, "o", b"hello");
    pg.hold = true;
    eng.on_op(
        &mut pg,
        creq(2, mkop(b"o", vec![OsdOp::write(0, b"xy".to_vec())])),
    );
    assert_eq!(pg.held_tids().len(), 1, "the write is in flight");
    // the read queues behind the in-flight write (its own intake classification is complete)
    eng.on_op(&mut pg, creq(3, mkop(b"o", vec![OsdOp::read(0, 8)])));
    eng.c.classify_calls = 0;
    let tid = pg.held_tids()[0];
    let mut outs = pg.release(&mut eng, tid, 0);
    let reply = reply_of(&mut outs, 1, 3).expect("read reply");
    assert_eq!(reply.result, 0);
    assert_eq!(
        eng.c.classify_calls, 1,
        "the drain classifies the released waiter once and reuses it"
    );
}

#[test]
fn a_write_after_the_max_user_version_does_not_wrap() {
    for general in [false, true] {
        let mut pg = TPg::new();
        let mut eng = engine(&pg);
        let oid = if general { "g" } else { "f" };
        put(&mut pg, &mut eng, oid, b"hello");
        set_oi(&mut pg, oid, |oi| oi.user_version = u64::MAX);
        // fast executor (one plain write) and general executor (write + xattr in one message)
        let mut ops = vec![OsdOp::write(0, b"xy".to_vec())];
        if general {
            ops.push(OsdOp::setxattr(b"k", b"v"));
        }
        let mut outs = run(
            &mut pg,
            &mut eng,
            1,
            2,
            client(7),
            mkop(oid.as_bytes(), ops),
        );
        assert_eq!(
            reply_of(&mut outs, 1, 2).expect("reply").result,
            0,
            "general={general}"
        );
        assert_eq!(
            oi(&pg, oid).user_version,
            u64::MAX,
            "saturates instead of wrapping to 0 (general={general})"
        );
    }
}
