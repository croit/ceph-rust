// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! RETURNVEC dup-op replay (G24, client-ops 5.6).
mod common;
use common::*;
use denc::types::EntityAddr;
use opexec::{ClientReq, Out};
use opwire::{MOSDOpReply, OsdOp};

fn go(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64, op: opwire::MOSDOp) -> MOSDOpReply {
    let mut outs = run(pg, eng, 1, tid, client(7), op);
    reply_of(&mut outs, 1, tid).expect("reply")
}

fn rv_op(oid: &str) -> opwire::MOSDOp {
    let mut op = mkop(
        oid.as_bytes(),
        vec![OsdOp::write(0, b"XYZ".to_vec()), OsdOp::read(0, 3)],
    );
    op.flags |= opwire::flag::RETURNVEC;
    op
}

#[test]
fn returnvec_dup_replays_rvals_and_outdata() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        mkop(b"rv", vec![OsdOp::write(0, b"abc".to_vec())]),
    );
    let op = rv_op("rv");
    let a = go(&mut pg, &mut eng, 2, op.clone());
    assert_eq!(a.ops[1].outdata, &b"abc"[..]);
    assert_eq!(pg.entries.len(), 2);
    // committed dup: same rvals, outdata, versions; no re-execution
    let b = go(&mut pg, &mut eng, 2, op.clone());
    assert_eq!(pg.entries.len(), 2);
    assert_eq!(b.ops[1].outdata, &b"abc"[..]);
    let rv = |r: &MOSDOpReply| r.ops.iter().map(|o| o.rval).collect::<Vec<_>>();
    assert_eq!(rv(&b), rv(&a));
    assert_eq!(b.replay_version, a.replay_version);
    assert_eq!(b.result, a.result);
    // the log has the results: a resend gets them whatever its flags (classic reply_op_error + set_op_returns)
    let mut plain = op.clone();
    plain.flags &= !opwire::flag::RETURNVEC;
    let c = go(&mut pg, &mut eng, 2, plain);
    assert_eq!(c.ops[1].outdata, &b"abc"[..]);
    // a plain write logs no results: its dup is a bare ack
    let w = mkop(b"rv", vec![OsdOp::write(0, b"q".to_vec())]);
    go(&mut pg, &mut eng, 3, w.clone());
    let d = go(&mut pg, &mut eng, 3, w);
    assert!(d.ops.iter().all(|o| o.rval == 0 && o.outdata.is_empty()));
}

#[test]
fn returnvec_dup_in_flight_replays() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        mkop(b"rw", vec![OsdOp::write(0, b"abc".to_vec())]),
    );
    let op = rv_op("rw");
    let req = |conn| ClientReq {
        placement_read: None,
        conn,
        caps: None,
        tid: 9,
        op: Box::new(op.clone()),
        who: client(9),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    eng.on_op(&mut pg, req(1));
    eng.on_op(&mut pg, req(2));
    let mut outs = settle(&mut pg, &mut eng);
    let a = reply_of(&mut outs, 1, 9).unwrap();
    let b = reply_of(&mut outs, 2, 9).unwrap();
    assert_eq!(a.ops[1].outdata, &b"abc"[..]);
    assert_eq!(b.ops[1].outdata, &b"abc"[..]);
}

/// A failed write logs its per-op results unconditionally (classic `record_write_error` with result < 0), so a resend
/// (or a classic primary after failover reading our log) answers with the same rvals.
#[test]
fn failed_write_logs_and_replays_per_op_rvals() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    go(
        &mut pg,
        &mut eng,
        1,
        mkop(b"fw", vec![OsdOp::write(0, b"abc".to_vec())]),
    );
    let op = mkop(
        b"fw",
        vec![
            OsdOp::write(0, b"zz".to_vec()),
            OsdOp::assert_version(1 << 40),
        ],
    );
    let a = go(&mut pg, &mut eng, 2, op.clone());
    assert!(a.result < 0);
    let e = pg.entries.last().unwrap();
    assert_eq!(e.op, pgwire::LogOp::ERROR);
    let rv = |r: &MOSDOpReply| r.ops.iter().map(|o| o.rval).collect::<Vec<_>>();
    assert_eq!(
        e.op_returns.iter().map(|o| o.rval).collect::<Vec<_>>(),
        rv(&a)
    );
    assert!(rv(&a)[1] < 0);
    let n = pg.entries.len();
    let b = go(&mut pg, &mut eng, 2, op);
    assert_eq!(pg.entries.len(), n);
    assert_eq!(b.result, a.result);
    assert_eq!(rv(&b), rv(&a));
}

/// A resent write whose object is degraded (missing on a peer / backfill) or missing here is answered only once every
/// copy holds the object again (s5.4 rules 15-17): a dup reply first would acknowledge data held by fewer copies.
#[test]
fn dup_of_degraded_or_missing_object_waits_for_recovery() {
    for missing in [false, true] {
        let mut pg = TPg::new();
        let mut eng = engine(&pg);
        let w = mkop(b"dg", vec![OsdOp::write(0, b"abc".to_vec())]);
        let a = go(&mut pg, &mut eng, 5, w.clone());
        assert_eq!(a.result, 0);
        let h = opexec::engine::head_of(&w);
        if missing {
            pg.missing.insert(h.clone());
        } else {
            pg.degraded.insert(h.clone());
        }
        let mut outs = run(&mut pg, &mut eng, 1, 5, client(7), w.clone());
        assert!(
            reply_of(&mut outs, 1, 5).is_none(),
            "dup parked while degraded"
        );
        pg.missing.clear();
        pg.degraded.clear();
        eng.retry(&mut pg);
        let mut outs = settle(&mut pg, &mut eng);
        let b = reply_of(&mut outs, 1, 5).expect("dup answered after recovery");
        assert_eq!((b.result, b.replay_version), (0, a.replay_version));
        assert_eq!(pg.entries.len(), 1, "dup not re-executed");
    }
}

/// A write that fails for good sends its waiting dups back among the gated ops by arrival: ops gated BEFORE the dup arrived
/// run first (they used to be overtaken: the dups went to the very front of the gate).
#[test]
fn failed_write_dups_keep_their_arrival_place_in_the_gate() {
    let mut pg = TPg::new();
    pg.deferred = true;
    let mut eng = engine(&pg);
    let req = |conn: u64, tid: u64, oid: &[u8]| ClientReq {
        placement_read: None,
        conn,
        caps: None,
        tid,
        op: Box::new(mkop(oid, vec![OsdOp::write(0, b"x".to_vec())])),
        who: client(9),
        addr: EntityAddr::default(),
        peer_addr: EntityAddr::default(),
        features: 0,
    };
    eng.on_op(&mut pg, req(1, 1, b"a"));
    let (tid, ver) = std::mem::take(&mut pg.done)[0];
    // an op of another object waits cold in the gate, then the resend of the in-flight write arrives (a dup)
    pg.cold_objs.borrow_mut().push(b"g".to_vec());
    eng.on_op(&mut pg, req(2, 2, b"g"));
    eng.on_op(&mut pg, req(3, 1, b"a"));
    assert_eq!(eng.c.dups, 1);
    eng.on_write_done(&mut pg, tid, ver, -opwire::errno::EIO);
    pg.cold_objs.borrow_mut().clear();
    eng.retry(&mut pg);
    let mut outs = eng.take_out();
    outs.extend(settle(&mut pg, &mut eng));
    let order: Vec<u64> = outs
        .iter()
        .filter_map(|o| match o {
            Out::Reply { conn, .. } => Some(*conn),
            _ => None,
        })
        .collect();
    // conn 1: the failed write's error; conn 2 was gated before the dup (conn 3) arrived
    assert_eq!(order, vec![1, 2, 3], "gated op first");
}
