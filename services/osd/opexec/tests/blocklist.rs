// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Client fencing by osdmap blocklist (client-ops 5.2 #10, 10.3): refusal at intake, of parked ops, watch removal.
mod common;
use common::*;
use denc::types::EntityAddr;
use opexec::{ClientReq, Engine};
use opwire::{OsdOp, consts::watch_op, errno};

const IP: [u8; 4] = [10, 0, 0, 5];
const OTHER: [u8; 4] = [10, 0, 0, 6];

fn req(conn: u64, tid: u64, ip: [u8; 4], op: opwire::MOSDOp) -> ClientReq {
    ClientReq {
        placement_read: None,
        conn,
        caps: None,
        tid,
        op: Box::new(op),
        who: client(7),
        addr: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 9, ip, 0),
        peer_addr: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 9, ip, 0),
        features: 0x3f17_ffff_fffd_ffff,
    }
}

fn wr(oid: &str) -> opwire::MOSDOp {
    mkop(oid.as_bytes(), vec![OsdOp::write(0, b"x".to_vec())])
}

fn go(
    pg: &mut TPg,
    eng: &mut Engine,
    c: u64,
    t: u64,
    ip: [u8; 4],
    op: opwire::MOSDOp,
) -> Vec<opexec::Out> {
    eng.on_op(pg, req(c, t, ip, op));
    settle(pg, eng)
}

#[test]
fn intake_refused_all_op_kinds_others_unaffected() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.blocklist.borrow_mut().push(IP);
    eng.on_op(&mut pg, req(1, 1, IP, wr("a")));
    eng.on_op(&mut pg, req(1, 2, IP, mkop(b"a", vec![OsdOp::read(0, 1)])));
    eng.on_op(&mut pg, req(2, 1, OTHER, wr("b")));
    let mut o = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut o, 1, 1).unwrap().result, -errno::EBLOCKLISTED);
    assert_eq!(reply_of(&mut o, 1, 2).unwrap().result, -errno::EBLOCKLISTED);
    assert_eq!(reply_of(&mut o, 2, 1).unwrap().result, 0);
    assert_eq!(pg.entries.len(), 1, "blocklisted write never logged");
}

#[test]
fn parked_ops_refused_when_map_blocklists() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.readable = false; // gated: waits for the read lease
    eng.on_op(&mut pg, req(1, 1, IP, wr("a")));
    eng.on_op(&mut pg, req(2, 1, OTHER, wr("b")));
    assert!(eng.take_out().is_empty());
    // new map blocklists IP while the ops wait
    pg.blocklist.borrow_mut().push(IP);
    eng.check_blocklist(&mut pg);
    let mut o = eng.take_out();
    assert_eq!(reply_of(&mut o, 1, 1).unwrap().result, -errno::EBLOCKLISTED);
    assert!(reply_of(&mut o, 2, 1).is_none(), "innocent op still waits");
    pg.readable = true;
    eng.retry(&mut pg);
    let mut o = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut o, 2, 1).unwrap().result, 0);
    assert_eq!(pg.entries.len(), 1);
}

#[test]
fn parked_on_missing_object_refused() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let mut h = denc::types::Hobject::new(
        b"m",
        denc::types::SnapId::NOSNAP,
        0x1234_5678,
        POOL as i64,
        b"",
    );
    h.set_key(b"");
    pg.missing.insert(h);
    eng.on_op(&mut pg, req(1, 1, IP, wr("m")));
    assert!(eng.take_out().is_empty());
    pg.blocklist.borrow_mut().push(IP);
    pg.missing.clear();
    eng.check_blocklist(&mut pg);
    let mut o = eng.take_out();
    assert_eq!(reply_of(&mut o, 1, 1).unwrap().result, -errno::EBLOCKLISTED);
    assert!(pg.entries.is_empty());
}

#[test]
fn inflight_write_survives_later_ops_refused() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.deferred = true; // submitted, not yet committed
    eng.on_op(&mut pg, req(1, 1, IP, wr("a")));
    pg.blocklist.borrow_mut().push(IP);
    eng.check_blocklist(&mut pg);
    eng.on_op(&mut pg, req(1, 2, IP, wr("a")));
    let mut o = eng.take_out();
    assert_eq!(reply_of(&mut o, 1, 2).unwrap().result, -errno::EBLOCKLISTED);
    assert!(reply_of(&mut o, 1, 1).is_none());
}

#[test]
fn watchers_removed_on_blocklist() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        9,
        1,
        [10, 0, 0, 9],
        mkop(b"h", vec![OsdOp::create(false)]),
    );
    for (c, ip, ck) in [(1, IP, 0xAA), (2, OTHER, 0xBB)] {
        let t = 10 + c; // reqid = (entity, tid): distinct per op
        let op = mkop(b"h", vec![OsdOp::watch_op(ck, watch_op::WATCH, 0)]);
        let mut o = go(&mut pg, &mut eng, c, t, ip, op);
        assert_eq!(reply_of(&mut o, c, t).unwrap().result, 0);
    }
    let mut o = go(
        &mut pg,
        &mut eng,
        9,
        5,
        [10, 0, 0, 9],
        mkop(b"h", vec![OsdOp::list_watchers()]),
    );
    let r = reply_of(&mut o, 9, 5).unwrap();
    let lw: opwire::ObjListWatchResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
    assert_eq!(lw.entries.len(), 2);
    pg.blocklist.borrow_mut().push(IP);
    eng.check_blocklist(&mut pg);
    let _ = settle(&mut pg, &mut eng);
    let mut o = go(
        &mut pg,
        &mut eng,
        9,
        2,
        [10, 0, 0, 9],
        mkop(b"h", vec![OsdOp::list_watchers()]),
    );
    let r = reply_of(&mut o, 9, 2).unwrap();
    let lw: opwire::ObjListWatchResponse = denc::from_slice(&r.ops[0].outdata).unwrap();
    assert_eq!(lw.entries.len(), 1, "only the other watcher stays");
    let op = mkop(b"h", vec![OsdOp::watch_op(0xAA, watch_op::PING, 0)]);
    let mut o = go(&mut pg, &mut eng, 1, 3, IP, op);
    assert_eq!(reply_of(&mut o, 1, 3).unwrap().result, -errno::EBLOCKLISTED);
}

/// Ops queued behind an in-flight write of the same object (per-object waiters) run from the drain, not from intake:
/// a map that blocklists their client in between must refuse them there (classic requeues them through do_op).
#[test]
fn object_waiters_refused_after_blocklist() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.deferred = true;
    eng.on_op(&mut pg, req(1, 1, IP, wr("a")));
    eng.on_op(&mut pg, req(1, 2, IP, mkop(b"a", vec![OsdOp::read(0, 1)]))); // waits for the write
    eng.on_op(&mut pg, req(1, 3, IP, wr("a"))); // waits behind the read
    assert_eq!(pg.done.len(), 1, "only the first write submitted");
    pg.blocklist.borrow_mut().push(IP);
    eng.check_blocklist(&mut pg);
    let mut o = settle(&mut pg, &mut eng);
    assert_eq!(
        reply_of(&mut o, 1, 1).unwrap().result,
        0,
        "accepted before the map"
    );
    assert_eq!(reply_of(&mut o, 1, 2).unwrap().result, -errno::EBLOCKLISTED);
    assert_eq!(reply_of(&mut o, 1, 3).unwrap().result, -errno::EBLOCKLISTED);
    assert!(pg.done.is_empty());
    assert_eq!(pg.tid, 1, "the fenced write was never submitted");
}

/// pg ops (listings) are not fenced, classic order (blocklist check after do_pg_op).
#[test]
fn pg_ops_not_fenced() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.blocklist.borrow_mut().push(IP);
    let op = mkop(b"", vec![OsdOp::pgnls(10, &denc::types::Hobject::MIN())]);
    let mut o = go(&mut pg, &mut eng, 1, 1, IP, op);
    assert_ne!(reply_of(&mut o, 1, 1).unwrap().result, -errno::EBLOCKLISTED);
}
