// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! A SESSION_RECONNECT of a stale incarnation of the peer must not wipe a live session.
mod common;
use common::*;
use denc::types::{EntityAddrVec, EntityName};
use msgr2::*;

const OSD: u8 = EntityName::OSD;

/// lab-c (mass restart of the croit-flashstore-osds, classic peers): osd A (our restarted process, new nonce) had dialed classic B and
/// sent 11 frames when B's RECONNECT for its old session with A's previous incarnation arrived (same B addrvec, other
/// client cookie). We replied SESSION_RESET (right) but also wiped the live session (out_seq = 0, cookies cleared) while
/// the connection stayed up: the next frames were numbered from 1 again and B dropped them as "old message 1 <= 11"
/// (PG queries/activations lost, PGs stuck in peering/activating until the next map).
#[test]
fn a_reconnect_of_a_stale_incarnation_leaves_the_live_session_alone() {
    let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut rng = Rng(9);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    for i in 1..=3 {
        c.send_message(msg(i, 42, 10));
    }
    exchange(&mut c, &mut s, t(1), &mut rng, 64);
    assert_eq!(msgs(&events(&mut s)).len(), 3);
    events(&mut c);
    let before = a.table.info(&b.addrs).unwrap();
    assert_eq!(before.out_seq, 3);

    // B's earlier incarnation: same addrvec, its own session with A's earlier incarnation (other nonce)
    let mut b_old = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut a_old = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    let old_addrs = EntityAddrVec::single(addr(1, 6800, 98));
    a_old.addrs = old_addrs.clone();
    a_old.cfg.addrs = old_addrs;
    let mut bc = b_old.dial(&a_old, t(2));
    let mut sa_old = a_old.accept(2, t(2));
    for k in 3..8u64 {
        exchange(&mut bc, &mut sa_old, t(k), &mut rng, 64);
    }
    events(&mut bc);
    // the link drops; B redials A's address (the old incarnation's session is resumed: SESSION_RECONNECT)
    bc.on_closed(t(9));
    bc.send_message(msg(50, 42, 3)); // something to send: the session redials
    events(&mut bc);
    let mut sa = a.accept(2, t(10));
    bc.on_connected(t(10));
    for k in 11..16u64 {
        exchange(&mut bc, &mut sa, t(k), &mut rng, 64);
    }
    // A's live session is untouched and keeps numbering
    let after = a.table.info(&b.addrs).unwrap();
    assert_eq!(
        (after.out_seq, after.client_cookie, after.server_cookie),
        (3, before.client_cookie, before.server_cookie),
        "the live session was wiped by a stale reconnect"
    );
    c.send_message(msg(4, 42, 10));
    exchange(&mut c, &mut s, t(20), &mut rng, 64);
    let evs = events(&mut s);
    let got = msgs(&evs);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].header.seq, 4, "numbering continues");
}

/// A dial for a dead incarnation of this OSD (same ip:port, other nonce) is refused as "target addr is not ours"; the server
/// side keeps who dialled and what it claimed, for the fault log (an accepted link has no other trace of the dialer).
#[test]
fn a_refused_ident_names_the_dialer_and_its_target() {
    let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    let b_old = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut b_new = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    b_new.addrs = EntityAddrVec::single(addr(2, 6800, 100));
    b_new.cfg.addrs = b_new.addrs.clone();
    let mut rng = Rng(3);
    let mut c = a.dial(&b_old, t(0));
    let mut s = b_new.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 64);
    assert!(
        events(&mut s).iter().any(|e| matches!(
            e,
            Event::Fault(FaultReason::Protocol("target addr is not ours"))
        )),
        "refused"
    );
    let (claimed, target) = s.ident_claim().expect("claim kept");
    assert_eq!(*claimed, a.addrs);
    assert_eq!(*target, b_old.addrs.0[0]);
    assert_ne!(*target, b_new.addrs.0[0]);
    assert_eq!(s.target(), addr(1, 40002, 0), "the peer socket");
}

/// Same race on a resetcheck server (SESSION_RESET full=true): answering the stale reconnect keeps the live session and
/// raises no RemoteReset (the driver would take the live peer's link down). The incarnation's following CLIENT_IDENT
/// with its own cookie then legitimately replaces the session: exactly one RemoteReset.
#[test]
fn a_full_reset_answer_to_a_stale_reconnect_raises_no_remote_reset() {
    let srv = PolicyTable {
        default: Policy::stateful_server(0),
        by_type: vec![],
    };
    let cli = PolicyTable {
        default: Policy::lossless_client(0),
        by_type: vec![],
    };
    let mut a = Node::new(OSD, 1, 1, cli.clone());
    let mut b = Node::new(OSD, 2, 2, srv.clone());
    let mut rng = Rng(11);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 64);
    assert_eq!(msgs(&events(&mut s)).len(), 1);
    events(&mut c);
    let before = b.table.info(&a.addrs).unwrap();

    // another incarnation of A (same addrvec) with its own session to an incarnation of B (same addrvec)
    let mut a_old = Node::new(OSD, 1, 1, cli).reseed(77);
    let mut b_old = Node::new(OSD, 2, 2, srv).reseed(78);
    let mut ac = a_old.dial(&b_old, t(2));
    let mut sb_old = b_old.accept(1, t(2));
    for k in 3..8u64 {
        exchange(&mut ac, &mut sb_old, t(k), &mut rng, 64);
    }
    events(&mut ac);
    ac.on_closed(t(9));
    ac.send_message(msg(50, 42, 3));
    events(&mut ac);
    // its reconnect reaches the live B
    let mut sb = b.accept(1, t(10));
    ac.on_connected(t(10));
    let mut seen = Vec::new();
    for k in 11..16u64 {
        exchange(&mut ac, &mut sb, t(k), &mut rng, 64);
        seen.extend(events(&mut sb));
    }
    let resets = seen.iter().filter(|e| **e == Event::RemoteReset).count();
    assert_eq!(resets, 1, "{seen:?}");
    let after = b.table.info(&a.addrs).unwrap();
    assert_ne!(
        after.client_cookie, before.client_cookie,
        "the new incarnation took over"
    );
}
