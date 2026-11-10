// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! MOSDBackoff (client-ops s6) and OSD caps (osdcaps.md) at the engine.
mod common;
use common::*;
use denc::types::EntityAddr;
use opexec::caps::Caps;
use opexec::{ClientReq, Dropped, Out};
use opwire::{MOSDBackoff, OsdOp, consts::backoff as bo, errno};
use std::sync::Arc;

fn req(conn: u64, tid: u64, op: opwire::MOSDOp, caps: Option<&str>) -> ClientReq {
    ClientReq {
        placement_read: None,
        conn,
        caps: caps.map(|c| Arc::new(Caps::parse(c).unwrap())),
        tid,
        op: Box::new(op),
        who: client(7),
        addr: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [10, 0, 0, 5], 4000),
        peer_addr: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [10, 0, 0, 5], 4000),
        features: 0,
    }
}

fn wr(oid: &str) -> opwire::MOSDOp {
    mkop(oid.as_bytes(), vec![OsdOp::write(0, b"x".to_vec())])
}

fn backoffs(outs: &[Out]) -> Vec<(u64, MOSDBackoff)> {
    outs.iter()
        .filter_map(|o| match o {
            Out::Backoff { conn, msg } => Some((*conn, msg.clone())),
            _ => None,
        })
        .collect()
}

/// `(conn, tid)` of the ops the engine dropped without a reply since the last call.
fn dropped(eng: &mut opexec::Engine) -> Vec<(u64, u64)> {
    eng.take_dropped()
        .into_iter()
        .map(|d: Dropped| (d.conn, d.tid))
        .collect()
}

/// The client's ACK_BLOCK of a BLOCK (same id, range and epoch).
fn ack(block: &MOSDBackoff) -> MOSDBackoff {
    MOSDBackoff {
        op: bo::ACK_BLOCK,
        ..block.clone()
    }
}

#[test]
fn block_ack_unblock_cycle() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.active = false;
    pg.blocked = true;
    eng.on_op(&mut pg, req(1, 1, wr("a"), None));
    let outs = eng.take_out();
    let b = backoffs(&outs);
    assert_eq!(b.len(), 1);
    assert_eq!((b[0].0, b[0].1.op), (1, bo::BLOCK));
    assert_eq!(b[0].1.pgid, pg.spg);
    assert_eq!(b[0].1.begin.hash, 0);
    assert!(b[0].1.end.max); // pg_num 1 in the test env: whole pool
    assert!(eng.has_parked()); // live backoffs need a retry on activation
    // every op dropped without a reply is reported with its tid: the OSD ends its op-tracker record (a linger op the
    // client re-registers under a new tid is never resent, its record would live until the session closes)
    assert_eq!(dropped(&mut eng), vec![(1, 1)]);
    // further ops of the same session are dropped without a message, other sessions get their own BLOCK
    eng.on_op(&mut pg, req(1, 2, wr("b"), None));
    assert!(eng.take_out().is_empty());
    assert_eq!(dropped(&mut eng), vec![(1, 2)]);
    eng.on_op(&mut pg, req(2, 1, wr("a"), None));
    let b2 = backoffs(&eng.take_out());
    assert_eq!(b2[0].0, 2);
    assert_eq!(dropped(&mut eng), vec![(2, 1)]);
    // conn 1 acks
    eng.on_backoff_ack(1, &ack(&b[0].1));
    // still blocked: retry does nothing
    eng.retry(&mut pg);
    assert!(eng.take_out().is_empty());
    // activation: UNBLOCK to both, no op was parked, nothing is executed
    pg.active = true;
    pg.blocked = false;
    eng.retry(&mut pg);
    let mut ub = backoffs(&eng.take_out());
    ub.sort_by_key(|(c, _)| *c);
    assert_eq!(ub.len(), 2);
    assert!(ub.iter().all(|(_, m)| m.op == bo::UNBLOCK));
    assert_eq!(ub[0].1.id, b[0].1.id);
    assert_eq!(ub[1].1.id, b2[0].1.id);
    // client resends after UNBLOCK: executes
    let mut outs = run(&mut pg, &mut eng, 1, 3, client(7), wr("a"));
    assert_eq!(reply_of(&mut outs, 1, 3).unwrap().result, 0);
    assert!(dropped(&mut eng).is_empty(), "an answered op is no drop");
    // nothing further to release
    eng.retry(&mut pg);
    assert!(eng.take_out().is_empty());
}

#[test]
fn peering_parks_without_backoff_and_interval_change_unblocks() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.active = false;
    // plain peering (not blocked): park, no backoff message
    eng.on_op(&mut pg, req(1, 1, wr("a"), None));
    assert!(eng.take_out().is_empty());
    assert!(eng.has_parked());
    pg.active = true;
    eng.retry(&mut pg);
    let mut outs = settle(&mut pg, &mut eng);
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
    // blocked, then new interval before activation: UNBLOCK (late ack of a NEW record is tolerated)
    pg.active = false;
    pg.blocked = true;
    eng.on_op(&mut pg, req(1, 2, wr("a"), None));
    let b = backoffs(&eng.take_out());
    assert_eq!(b.len(), 1);
    eng.reset();
    let ub = backoffs(&eng.take_out());
    assert_eq!(ub.len(), 1);
    assert_eq!(ub[0].1.op, bo::UNBLOCK);
    assert_eq!(ub[0].1.id, b[0].1.id);
    // closed session: records vanish silently
    eng.on_op(&mut pg, req(5, 1, wr("a"), None));
    let _ = eng.take_out();
    eng.conn_closed(5, 0);
    pg.active = true;
    pg.blocked = false;
    eng.retry(&mut pg);
    assert!(eng.take_out().is_empty());
}

/// Regression (client-ops s6.5, classic `Session::have_backoff` ignores the record state): an op the client sent before
/// it saw the BLOCK must stay dropped until the client's ACK arrives, also after the UNBLOCK (record DELETING). The client
/// resends every op of the range on the UNBLOCK; executing the early copy first ran op 2 ahead of op 1 (the client's order)
/// and then again as a resend.
#[test]
fn deleting_backoff_drops_ops_until_the_ack() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.active = false;
    pg.blocked = true;
    eng.on_op(&mut pg, req(1, 1, wr("a"), None)); // op 1: BLOCK, dropped
    let b = backoffs(&eng.take_out());
    assert_eq!(b.len(), 1);
    pg.active = true;
    pg.blocked = false;
    eng.retry(&mut pg); // activation before the ACK: UNBLOCK, record DELETING
    let ub = backoffs(&eng.take_out());
    assert_eq!((ub.len(), ub[0].1.op), (1, bo::UNBLOCK));
    // op 2, sent before the client processed the BLOCK, arrives now: dropped (no reply, no new BLOCK)
    let _ = eng.take_dropped();
    eng.on_op(&mut pg, req(1, 2, wr("a"), None));
    let outs = settle(&mut pg, &mut eng);
    assert!(
        outs.is_empty(),
        "op behind a DELETING backoff must not run: {outs:?}"
    );
    assert_eq!(dropped(&mut eng), vec![(1, 2)], "reported like any drop");
    // the client's ACK of the BLOCK precedes its resends (one ordered session): then ops 1 and 2 run in order
    eng.on_backoff_ack(1, &ack(&b[0].1));
    let mut outs = run(&mut pg, &mut eng, 1, 1, client(7), wr("a"));
    assert_eq!(reply_of(&mut outs, 1, 1).unwrap().result, 0);
    let mut outs = run(&mut pg, &mut eng, 1, 2, client(7), wr("a"));
    assert_eq!(reply_of(&mut outs, 1, 2).unwrap().result, 0);
    // a new interval at the same primary keeps a DELETING record (classic: the session keeps it until the ACK)
    pg.active = false;
    pg.blocked = true;
    eng.on_op(&mut pg, req(1, 3, wr("a"), None));
    let b = backoffs(&eng.take_out());
    eng.reset();
    let ub = backoffs(&eng.take_out());
    assert_eq!((ub.len(), ub[0].1.op), (1, bo::UNBLOCK));
    pg.active = true;
    pg.blocked = false;
    eng.on_op(&mut pg, req(1, 4, wr("a"), None));
    assert!(settle(&mut pg, &mut eng).is_empty());
    eng.on_backoff_ack(1, &ack(&b[0].1));
    let mut outs = run(&mut pg, &mut eng, 1, 3, client(7), wr("a"));
    assert_eq!(reply_of(&mut outs, 1, 3).unwrap().result, 0);
}

fn go_caps(
    pg: &mut TPg,
    eng: &mut opexec::Engine,
    tid: u64,
    op: opwire::MOSDOp,
    caps: &str,
) -> i32 {
    eng.on_op(pg, req(1, tid, op, Some(caps)));
    let mut outs = settle(pg, eng);
    reply_of(&mut outs, 1, tid).expect("reply").result
}

#[test]
fn binary_unknown_method_is_not_a_class_policy_error() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    for (i, class) in [b"rbd".as_slice(), b"hello", b"no_such_class"]
        .iter()
        .enumerate()
    {
        let call = mkop(b"obj", vec![OsdOp::call(class, &[0xff], b"")]);
        let expected = if *class == b"no_such_class" {
            -errno::EPERM
        } else {
            -errno::EOPNOTSUPP
        };
        assert_eq!(
            go_caps(&mut pg, &mut eng, i as u64 + 1, call, "allow *"),
            expected
        );
    }
}

#[test]
fn caps_enforced_per_message() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    // seed an object with an unrestricted session
    assert_eq!(go_caps(&mut pg, &mut eng, 1, wr("obj"), "allow *"), 0);
    let rd = || mkop(b"obj", vec![OsdOp::read(0, 1)]);
    // read-only: write is EPERM, read works
    assert_eq!(
        go_caps(&mut pg, &mut eng, 2, wr("obj"), "allow r"),
        -errno::EPERM
    );
    assert_eq!(go_caps(&mut pg, &mut eng, 3, rd(), "allow r"), 0);
    // EPERM leaves no trace (no log entry, no object change)
    let n = pg.entries.len();
    assert_eq!(
        go_caps(&mut pg, &mut eng, 4, wr("zzz"), "allow r"),
        -errno::EPERM
    );
    assert_eq!(pg.entries.len(), n);
    // pool-restricted
    assert_eq!(
        go_caps(&mut pg, &mut eng, 5, rd(), "allow r pool=other"),
        -errno::EPERM
    );
    assert_eq!(
        go_caps(&mut pg, &mut eng, 6, rd(), "allow r pool=testpool"),
        0
    );
    // namespace, object prefix
    assert_eq!(
        go_caps(&mut pg, &mut eng, 7, rd(), "allow r namespace=n"),
        -errno::EPERM
    );
    assert_eq!(
        go_caps(&mut pg, &mut eng, 8, rd(), "allow r object_prefix ob"),
        0
    );
    assert_eq!(
        go_caps(&mut pg, &mut eng, 9, rd(), "allow r object_prefix xx"),
        -errno::EPERM
    );
    // network
    assert_eq!(
        go_caps(&mut pg, &mut eng, 10, rd(), "allow r network 10.0.0.0/24"),
        0
    );
    assert_eq!(
        go_caps(
            &mut pg,
            &mut eng,
            11,
            rd(),
            "allow r network 192.168.0.0/16"
        ),
        -errno::EPERM
    );
    // profile rbd on an object that is not an rbd one: rwx allowed (grant 5), read fine
    assert_eq!(
        go_caps(
            &mut pg,
            &mut eng,
            12,
            wr("obj"),
            "profile rbd pool=testpool"
        ),
        0
    );
    assert_eq!(
        go_caps(&mut pg, &mut eng, 13, wr("obj"), "profile rbd pool=nope"),
        -errno::EPERM
    );
    assert_eq!(
        go_caps(&mut pg, &mut eng, 14, wr("obj"), "profile read-only"),
        -errno::EPERM
    );
    // pgnls needs r on the whole pool/namespace
    let ls = |tid| {
        let mut m = mkop(b"", vec![OsdOp::pgnls(10, &denc::types::Hobject::MIN())]);
        m.hash = 0;
        let _ = tid;
        m
    };
    assert_eq!(
        go_caps(&mut pg, &mut eng, 15, ls(15), "allow w"),
        -errno::EPERM
    );
    assert_eq!(
        go_caps(&mut pg, &mut eng, 16, ls(16), "allow r object_prefix zz"),
        -errno::EPERM
    );
    // tag grants use the pool's application metadata
    assert_eq!(
        go_caps(&mut pg, &mut eng, 17, rd(), "allow r tag rbd *=*"),
        -errno::EPERM
    );
    pg.apps.insert("rbd".into(), Default::default());
    assert_eq!(
        go_caps(&mut pg, &mut eng, 18, rd(), "allow r tag rbd *=*"),
        0
    );
}

/// PG operations ignore oid/key when choosing their resources. A forged matching
/// name must not turn an object-prefix read grant into namespace-wide access.
#[test]
fn pg_caps_ignore_forged_object_names_and_locator_keys() {
    use denc::types::Hobject;
    use denc::{Encode, Encoder};
    use opwire::op as code;

    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(go_caps(&mut pg, &mut eng, 1, wr("secret"), "allow *"), 0);
    let mut filtered = OsdOp::pgnls(10, &Hobject::MIN());
    filtered.op = code::PGNLS_FILTER;
    let mut e = Encoder::new();
    for s in [&b"pg"[..], b"filter", b"plain", b"", b""] {
        e.bytes(s).unwrap();
    }
    Hobject::MIN().encode(&mut e).unwrap();
    filtered.indata = e.into_vec().into();
    let mut tid = 2;
    for opcode in [
        code::PGNLS,
        code::PGLS,
        code::PGNLS_FILTER,
        code::PGLS_FILTER,
        code::PG_HITSET_LS,
    ] {
        for (oid, key) in [
            (b"allowed-decoy".as_slice(), b"".as_slice()),
            (b"", b"allowed-decoy"),
        ] {
            let mut o = if matches!(opcode, code::PGNLS_FILTER | code::PGLS_FILTER) {
                filtered.clone()
            } else {
                OsdOp::pgnls(10, &Hobject::MIN())
            };
            o.op = opcode;
            let mut m = mkop(oid, vec![o]);
            m.oloc.key = key.to_vec();
            assert_eq!(
                go_caps(
                    &mut pg,
                    &mut eng,
                    tid,
                    m.clone(),
                    "allow r object_prefix allowed-"
                ),
                -errno::EPERM,
                "opcode={opcode:#x} oid={oid:?} key={key:?}"
            );
            tid += 1;
            assert!(
                go_caps(
                    &mut pg,
                    &mut eng,
                    tid,
                    m,
                    "allow r pool=testpool namespace=\"\""
                ) >= 0,
                "namespace-wide grant remains usable"
            );
            tid += 1;
        }
    }
}

#[test]
fn every_pg_opcode_uses_namespace_wide_cap_context() {
    use opwire::op as code;
    let peer = EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [10, 0, 0, 5], 4000);
    for opcode in [
        code::PGLS,
        code::PGLS_FILTER,
        code::PG_HITSET_LS,
        code::PG_HITSET_GET,
        code::PGNLS,
        code::PGNLS_FILTER,
        code::SCRUBLS,
    ] {
        for (oid, key) in [
            (b"allowed-decoy".as_slice(), b"".as_slice()),
            (b"", b"allowed-decoy"),
        ] {
            let mut m = mkop(oid, vec![OsdOp::new(opcode)]);
            m.oloc.key = key.to_vec();
            m.oloc.nspace = b"tenant".to_vec();
            for (text, expected) in [
                ("allow r object_prefix allowed-", false),
                (
                    "allow r pool=testpool namespace=tenant object_prefix allowed-",
                    false,
                ),
                ("profile rbd", true),
                ("allow r pool=testpool namespace=tenant", true),
                ("allow r pool=other namespace=tenant", false),
                ("allow r pool=testpool namespace=other", false),
                ("allow r network 10.0.0.0/24", true),
                ("allow r network 192.168.0.0/24", false),
                (
                    "allow r object_prefix allowed-, allow r pool=testpool namespace=tenant",
                    true,
                ),
                ("allow *", true),
            ] {
                let caps = Caps::parse(text).unwrap();
                assert_eq!(
                    caps.allows_op(&m, &[], &peer, || (b"testpool", None)),
                    expected,
                    "opcode={opcode:#x} oid={oid:?} key={key:?} caps={text}"
                );
            }
        }
    }
}

/// A PG that disappears (merge source) or is no longer ours must not leave a client blocked: teardown UNBLOCKs
/// every live backoff and hands the messages to the caller (found live: engines dropped silently, ops hung).
#[test]
fn teardown_unblocks_live_backoffs() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.active = false;
    pg.blocked = true;
    eng.on_op(&mut pg, req(1, 1, wr("a"), None));
    eng.on_op(&mut pg, req(2, 1, wr("b"), None));
    let _ = eng.take_out(); // the BLOCKs went out
    let mut ub = backoffs(&eng.teardown());
    ub.sort_by_key(|(c, _)| *c);
    assert_eq!(ub.len(), 2);
    assert!(
        ub.iter()
            .all(|(_, m)| m.op == bo::UNBLOCK && m.pgid == pg.spg)
    );
    assert!(!eng.has_parked());
}

/// Ops that die with the PG (merge source) get no reply: the engine names their clients so the OSD can share the
/// map; without it the client sat on its op until its own 10 s tick (found live, 10 s stalls per merge).
#[test]
fn teardown_names_the_clients_of_dropped_ops() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.active = false; // peering: ops park at the gate
    eng.on_op(&mut pg, req(1, 1, wr("a"), None));
    eng.on_op(&mut pg, req(2, 7, wr("b"), None));
    assert!(eng.take_dropped().is_empty());
    let _ = eng.teardown();
    let mut d = dropped(&mut eng);
    d.sort();
    assert_eq!(d, vec![(1, 1), (2, 7)]);
}

/// Review finding 5: a full gate never drops an op silently: the session is BLOCKed, and UNBLOCKed when the PG is
/// active again (the client resends then).
#[test]
fn full_gate_blocks_the_session_instead_of_losing_the_op() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.active = false; // peering, not blocked: ops park at the gate
    for t in 1..=4096u64 {
        eng.on_op(
            &mut pg,
            req(1, t, mkop(b"q", vec![OsdOp::read(0, 1)]), None),
        );
    }
    assert!(
        backoffs(&eng.take_out()).is_empty(),
        "no backoff below the cap"
    );
    // one more from another session: over the cap
    eng.on_op(
        &mut pg,
        req(2, 1, mkop(b"q", vec![OsdOp::read(0, 1)]), None),
    );
    let b = backoffs(&eng.take_out());
    assert_eq!(b.len(), 1, "BLOCK instead of a silent drop");
    assert_eq!((b[0].0, b[0].1.op), (2, bo::BLOCK));
    assert_eq!(dropped(&mut eng), vec![(2, 1)]);
    // the PG becomes active: the gate drains and the session is released
    pg.active = true;
    eng.retry(&mut pg);
    let outs = eng.take_out();
    let ub = backoffs(&outs);
    assert_eq!(ub.len(), 1);
    assert_eq!((ub[0].0, ub[0].1.op), (2, bo::UNBLOCK));
}
