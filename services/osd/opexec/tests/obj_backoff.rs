// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Object-level backoff for unreadable heads and degraded writes (client-ops 16.6): an unfound head (or a degraded
//! one with `osd_backoff_on_degraded`) gets a BLOCK for exactly that object and the op is dropped, not parked; UNBLOCK
//! when the object is readable again. Parking stays bounded.
mod common;
use common::*;
use denc::types::Hobject;
use opexec::{Engine, Limits, Out};
use opwire::{MOSDBackoff, OsdOp, consts::backoff as bo};

fn head(oid: &str) -> Hobject {
    let mut h = Hobject::new(
        oid.as_bytes(),
        denc::types::SnapId::NOSNAP,
        0x1234_5678,
        POOL as i64,
        b"",
    );
    h.set_key(b"");
    h
}

fn backoffs(outs: &[Out]) -> Vec<(u64, MOSDBackoff)> {
    outs.iter()
        .filter_map(|o| match o {
            Out::Backoff { conn, msg } => Some((*conn, msg.clone())),
            _ => None,
        })
        .collect()
}

fn read_req(oid: &[u8]) -> opwire::MOSDOp {
    mkop(oid, vec![OsdOp::read(0, 4)])
}

#[test]
fn unfound_head_backs_off_instead_of_parking() {
    let mut pg = TPg::new();
    pg.missing.insert(head("o"));
    pg.unfound.insert(head("o"));
    let mut eng = engine(&pg);
    // the op is dropped without a reply; the head gets an object-level BLOCK and recovery is kicked
    let mut outs = run(&mut pg, &mut eng, 1, 1, client(7), read_req(b"o"));
    assert!(reply_of(&mut outs, 1, 1).is_none(), "no reply");
    let bo = backoffs(&outs);
    assert_eq!(bo.len(), 1, "{bo:?}");
    assert_eq!(bo[0].1.op, bo::BLOCK);
    assert_eq!(bo[0].1.begin, head("o"));
    assert_eq!(bo[0].1.end, head("o"), "object-level: begin == end");
    assert_eq!(eng.parked_len(), 0, "nothing retained, the client holds it");
    assert_eq!(pg.kicked, vec![head("o")], "recovery kicked");
    // a resend inside the record is dropped without another BLOCK (s6.5)
    let mut outs = run(&mut pg, &mut eng, 1, 2, client(7), read_req(b"o"));
    assert!(backoffs(&outs).is_empty());
    assert!(reply_of(&mut outs, 1, 2).is_none());
    // another object of the session runs: the record covers exactly one object
    let mut outs = run(
        &mut pg,
        &mut eng,
        1,
        3,
        client(7),
        mkop(b"p", vec![OsdOp::write(0, b"x".to_vec())]),
    );
    assert!(backoffs(&outs).is_empty());
    assert!(reply_of(&mut outs, 1, 3).is_some());
    // object recovered -> UNBLOCK for exactly that object
    pg.missing.remove(&head("o"));
    pg.unfound.remove(&head("o"));
    eng.retry(&mut pg);
    let outs = eng.take_out();
    let bo = backoffs(&outs);
    assert_eq!(bo.len(), 1, "{bo:?}");
    assert_eq!(bo[0].1.op, bo::UNBLOCK);
    assert_eq!(bo[0].1.begin, head("o"));
    assert_eq!(bo[0].1.end, head("o"));
    // DELETING: an op that reaches the OSD after the UNBLOCK but before the ACK was sent before the client saw the
    // BLOCK -> still dropped (the client resends it after the ACK)
    let mut outs = run(&mut pg, &mut eng, 1, 4, client(7), read_req(b"o"));
    assert!(backoffs(&outs).is_empty());
    assert!(reply_of(&mut outs, 1, 4).is_none());
    let mut ack = bo[0].1.clone();
    ack.op = bo::ACK_BLOCK;
    eng.on_backoff_ack(1, &ack);
    // now the op runs again (absent object: the read-only ENOENT guard)
    let mut outs = run(&mut pg, &mut eng, 1, 5, client(7), read_req(b"o"));
    assert!(reply_of(&mut outs, 1, 5).is_some());
}

#[test]
fn degraded_head_parks_unless_backoff_on_degraded() {
    let mut pg = TPg::new();
    // missing here, a peer holds it: degraded, not unfound
    pg.missing.insert(head("d"));
    let mut eng = engine(&pg);
    let mut outs = run(&mut pg, &mut eng, 1, 1, client(7), read_req(b"d"));
    assert!(
        backoffs(&outs).is_empty(),
        "default: no backoff for degraded"
    );
    assert!(reply_of(&mut outs, 1, 1).is_none());
    assert_eq!(eng.parked_len(), 1, "the op waits on the object");

    let mut pg = TPg::new();
    pg.missing.insert(head("d"));
    let mut eng = Engine::new(
        pg.spg,
        Limits {
            backoff_on_degraded: true,
            ..Limits::default()
        },
        opexec::clsx::ClassPolicy::default(),
    );
    let outs = run(&mut pg, &mut eng, 1, 1, client(7), read_req(b"d"));
    let bo = backoffs(&outs);
    assert_eq!(bo.len(), 1, "{bo:?}");
    assert_eq!(bo[0].1.begin, head("d"));
    assert_eq!(bo[0].1.end, head("d"));
    assert_eq!(eng.parked_len(), 0);
}

#[test]
fn degraded_write_parks_unless_backoff_on_degraded() {
    // a write to a head a peer misses (write-ordered path) parks by default and backs off with the option
    let mut pg = TPg::new();
    for (limit, want_backoff) in [(false, false), (true, true)] {
        pg.degraded.insert(head("w"));
        let mut eng = Engine::new(
            pg.spg,
            Limits {
                backoff_on_degraded: limit,
                ..Limits::default()
            },
            opexec::clsx::ClassPolicy::default(),
        );
        let write = mkop(b"w", vec![OsdOp::write(0, b"x".to_vec())]);
        let mut outs = run(&mut pg, &mut eng, 1, 1, client(7), write);
        assert_eq!(!backoffs(&outs).is_empty(), want_backoff);
        assert_eq!(eng.parked_len(), usize::from(!want_backoff));
        assert!(reply_of(&mut outs, 1, 1).is_none());
        pg.degraded.remove(&head("w"));
    }
}

#[test]
fn a_parked_object_lookup_does_not_walk_the_parked_set() {
    // every arriving op asks whether its object is parked: one lookup in the per-object index, never a scan over all
    // parked objects (recovery/scrub already keeps this list full in exactly the degraded case)
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let n = 64u64;
    for i in 0..n {
        let oid = format!("o{i}");
        pg.degraded.insert(head(&oid));
        let mut outs = run(
            &mut pg,
            &mut eng,
            1,
            i + 1,
            client(7),
            mkop(oid.as_bytes(), vec![OsdOp::write(0, b"x".to_vec())]),
        );
        assert!(reply_of(&mut outs, 1, i + 1).is_none());
    }
    assert_eq!(eng.parked_len(), n as usize);
    eng.c.parked_probes = 0;
    let mut outs = run(&mut pg, &mut eng, 1, 100, client(7), read_req(b"fresh"));
    assert!(reply_of(&mut outs, 1, 100).is_some());
    assert_eq!(
        eng.c.parked_probes, 1,
        "one lookup for an object with no parked op, however many objects are parked"
    );
}

#[test]
fn parking_is_bounded() {
    // a client that keeps sending to one degraded object cannot make the OSD retain every message: past the parked
    // bound the object is backed off and further ops are dropped at intake
    let mut pg = TPg::new();
    pg.missing.insert(head("d"));
    let mut eng = engine(&pg);
    let sent = 5000u64;
    let mut block = 0;
    for tid in 1..=sent {
        let outs = run(&mut pg, &mut eng, 1, tid, client(7), read_req(b"d"));
        block += backoffs(&outs)
            .iter()
            .filter(|(_, m)| m.op == bo::BLOCK)
            .count();
    }
    assert_eq!(block, 1, "one object-level BLOCK");
    assert!(eng.parked_len() < sent as usize, "parked set bounded");
    assert_eq!(eng.in_flight(), 0);
}
