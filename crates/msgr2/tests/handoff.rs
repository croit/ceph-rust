// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Multi-core placement of peer OSD sessions (open question 15): a connection of OSD `n` that lands on a core which
//! does not own `n`'s sessions is handed to the owner instead of being answered with a session reset.
//! Cores of one OSD = nodes with the same identity and their own session table.
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::*;

const OSD: u8 = EntityName::OSD;

/// Peer OSD 1 (classic: its out queue is dropped by a full reset) and OSD 2 with two cores; osd.1's sessions belong to
/// core 1 (`1 % 2`). `home`: placement on (the fix) or off (what ran before).
fn setup(home: bool) -> (Node, Node, Node) {
    let a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    a.table.set_keep_owed_peers(Default::default());
    let mut b0 = Node::new(OSD, 2, 2, PolicyTable::osd_cluster()).reseed(11);
    let mut b1 = Node::new(OSD, 2, 2, PolicyTable::osd_cluster()).reseed(22);
    if home {
        b0.cfg.home = Home::new(0, 2);
        b1.cfg.home = Home::new(1, 2);
    }
    (a, b0, b1)
}

/// Move the connection that stopped with `Event::Handoff` to `to`.
fn hand_off(mut s: Connection, to: &mut Node, now: std::time::Duration) -> Connection {
    let evs = events(&mut s);
    let Some(Event::Handoff { osd, owner }) = evs.last() else {
        panic!("no handoff: {evs:?}");
    };
    assert_eq!((*osd, *owner), (1, 1));
    let h = s.into_handoff().expect("parked");
    let id = to.id();
    Connection::from_handoff(h, id, to.cfg.clone(), to.table.clone(), now)
}

#[test]
fn handoff_is_send() {
    fn send<T: Send>() {}
    send::<Handoff>();
    send::<Config>();
}

/// The reproducer of the wedge: the peer's reconnect lands on the wrong core.
#[test]
fn reconnect_on_the_wrong_core_resets_the_session_without_placement() {
    let (mut a, mut b0, mut b1) = setup(false);
    let mut rng = Rng(5);
    let mut c = a.dial(&b1, t(0));
    let mut s = b1.accept(1, t(0));
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 50);
    events(&mut c);
    assert_eq!(msgs(&events(&mut s)).len(), 1);
    c.on_closed(t(2));
    events(&mut c);
    c.send_message(msg(2, 42, 10)); // queued while the link is down: classic discards it on a reset
    c.on_connected(t(3));
    let mut wrong = b0.accept(1, t(3));
    exchange(&mut c, &mut wrong, t(4), &mut rng, 17);
    let ec = events(&mut c);
    assert!(ec.contains(&Event::RemoteReset), "{ec:?}");
    assert!(
        msgs(&events(&mut wrong)).is_empty(),
        "the queued frame is gone"
    );
}

#[test]
fn reconnect_on_the_wrong_core_resumes_on_the_owner() {
    let (mut a, mut b0, mut b1) = setup(true);
    let mut rng = Rng(5);
    let mut c = a.dial(&b1, t(0));
    let mut s = b1.accept(1, t(0));
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 50);
    events(&mut c);
    assert_eq!(msgs(&events(&mut s)).len(), 1, "established on the owner");
    // a frame B owes the peer, not yet acked, and two the peer queued while the link was down
    s.send_message(msg(9, 43, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 50);
    events(&mut s);
    c.on_closed(t(2));
    s.on_closed(t(2));
    events(&mut c);
    events(&mut s);
    c.send_message(msg(2, 42, 10));
    c.send_message(msg(3, 42, 10));
    c.on_connected(t(3));
    // lands on core 0: it stops at the ident, the owner takes over
    let mut wrong = b0.accept(1, t(3));
    exchange(&mut c, &mut wrong, t(4), &mut rng, 17);
    assert_eq!(wrong.state(), ConnState::Connecting);
    assert!(
        b0.table.is_empty(),
        "no session was created on the wrong core"
    );
    let mut owner = hand_off(wrong, &mut b1, t(4));
    exchange(&mut c, &mut owner, t(5), &mut rng, 17);
    let (ec, eo) = (events(&mut c), events(&mut owner));
    assert!(!ec.contains(&Event::RemoteReset), "{ec:?}");
    assert!(connected(&ec).unwrap().resumed && connected(&eo).unwrap().resumed);
    let got: Vec<u64> = msgs(&eo).iter().map(|m| m.header.tid).collect();
    assert_eq!(got, vec![2, 3], "nothing lost, nothing twice");
    assert_eq!(b1.table.len(), 1);
    // and the session works in both directions afterwards
    owner.send_message(msg(10, 43, 10));
    c.send_message(msg(4, 42, 10));
    exchange(&mut c, &mut owner, t(6), &mut rng, 1000);
    assert_eq!(
        msgs(&events(&mut owner))
            .iter()
            .map(|m| m.header.tid)
            .collect::<Vec<_>>(),
        vec![4]
    );
    assert_eq!(
        msgs(&events(&mut c))
            .iter()
            .map(|m| m.header.tid)
            .collect::<Vec<_>>(),
        vec![10]
    );
}

#[test]
fn a_new_session_on_the_wrong_core_also_goes_to_the_owner() {
    let (mut a, mut b0, mut b1) = setup(true);
    let mut rng = Rng(6);
    let mut c = a.dial(&b0, t(0));
    let mut wrong = b0.accept(1, t(0));
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut wrong, t(1), &mut rng, 3);
    let mut owner = hand_off(wrong, &mut b1, t(1));
    exchange(&mut c, &mut owner, t(2), &mut rng, 3);
    assert!(connected(&events(&mut c)).is_some());
    assert_eq!(msgs(&events(&mut owner)).len(), 1);
    assert!(b0.table.is_empty() && b1.table.len() == 1);
}

/// A parked connection runs no timer: the deadline of the handshake it stopped and the deadline of the ident frame it
/// stopped at are both spent, and only the resumed connection on the owner core arms its own.
#[test]
fn a_parked_connection_has_no_timer() {
    let (mut a, mut b0, _b1) = setup(true);
    let mut rng = Rng(5);
    let mut c = a.dial(&b0, t(0));
    let mut wrong = b0.accept(1, t(0));
    let deadline = wrong
        .next_timer()
        .expect("the handshake deadline runs while the stream is handshaking");
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut wrong, t(1), &mut rng, 3);
    let evs = events(&mut wrong);
    let Some(Event::Handoff { .. }) = evs.last() else {
        panic!("not parked: {evs:?}");
    };
    assert_eq!(wrong.next_timer(), None, "parked: no timer");
    wrong.on_timer(deadline);
    wrong.on_timer(deadline + t(10_000));
    let evs = events(&mut wrong);
    assert!(
        evs.iter().all(|e| !matches!(e, Event::Fault(_))),
        "a parked connection must not fault itself: {evs:?}"
    );
}

/// The handshake clock of a resumed connection starts on the owning core: a handoff that took longer than
/// `ready_timeout` must not fault the freshly authenticated peer when the owner runs its first timer.
#[test]
fn handoff_rearms_the_handshake_deadline() {
    let (mut a, mut b0, mut b1) = setup(true);
    let mut rng = Rng(9);
    let mut c = a.dial(&b1, t(0));
    let mut s = b1.accept(1, t(0));
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 20);
    events(&mut c);
    assert_eq!(msgs(&events(&mut s)).len(), 1);
    // the link drops: the peer resumes its session
    c.on_closed(t(2));
    s.on_closed(t(2));
    events(&mut c);
    events(&mut s);
    c.send_message(msg(2, 42, 10));
    c.on_connected(t(3));
    let mut wrong = b0.accept(1, t(3));
    exchange(&mut c, &mut wrong, t(4), &mut rng, 17);
    assert_eq!(wrong.state(), ConnState::Connecting);
    // the move stalls on the cross-core queue past the deadline the handshake started with
    let h = wrong.into_handoff().expect("parked");
    let stale = "the owner no longer has the session (SESSION_RESET, spec 10.5 rule 1)";
    let mut owner =
        Connection::from_handoff(h, 99, b1.cfg.clone(), SessionTable::new(77), t(14_001));
    let evs = events(&mut owner);
    assert!(
        evs.iter().all(|e| !matches!(e, Event::Fault(_))),
        "{stale}: {evs:?}"
    );
    owner.on_timer(t(14_001));
    let evs = events(&mut owner);
    assert!(
        evs.iter().all(|e| !matches!(e, Event::Fault(_))),
        "{stale}: {evs:?}"
    );
    assert_eq!(owner.state(), ConnState::Connecting);
    assert!(
        owner.next_timer().is_some_and(|d| d > t(14_001)),
        "{:?}",
        owner.next_timer()
    );
}

#[test]
fn the_owner_core_and_foreign_clients_are_not_handed_off() {
    let (mut a, mut b0, mut b1) = setup(true);
    let mut rng = Rng(7);
    let mut c = a.dial(&b1, t(0));
    let mut s = b1.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 50);
    assert!(
        events(&mut s)
            .iter()
            .all(|e| !matches!(e, Event::Handoff { .. }))
    );
    // a peer that is not an OSD (client policy table) is never placed
    let mut cl = Node::new(EntityName::CLIENT, 4000, 3, PolicyTable::osd_public());
    let mut c2 = cl.dial(&b0, t(2));
    let mut s2 = b0.accept(3, t(2));
    exchange(&mut c2, &mut s2, t(3), &mut rng, 50);
    assert!(connected(&events(&mut s2)).is_some());
}

/// The peer dials while we dial from the owning core: both end up in one session table and decide the race
/// there (A < B: A's dial wins), nothing is lost.
#[test]
fn dial_race_with_the_peers_connection_on_a_foreign_core() {
    for a_first in [true, false] {
        let (mut a, mut b0, mut b1) = setup(true);
        let mut rng = Rng(77);
        let (mut a_c, mut b0_s, mut b1_c, mut a_s);
        if a_first {
            a_c = a.dial(&b0, t(0));
            b0_s = b0.accept(1, t(0));
            b1_c = b1.dial(&a, t(0));
            a_s = a.accept(2, t(0));
        } else {
            b1_c = b1.dial(&a, t(0));
            a_s = a.accept(2, t(0));
            a_c = a.dial(&b0, t(0));
            b0_s = b0.accept(1, t(0));
        }
        a_c.send_message(msg(1, 42, 4));
        b1_c.send_message(msg(2, 43, 4));
        let (mut got_a, mut got_b): (Vec<u64>, Vec<u64>) = (vec![], vec![]);
        let mut owner: Option<Connection> = None;
        for step in 1..60u64 {
            let ts = t(step * 400);
            if let Some(o) = owner.as_mut() {
                exchange(&mut a_c, o, ts, &mut rng, 64);
                got_b.extend(msgs(&events(o)).iter().map(|m| m.header.tid));
            } else {
                exchange(&mut a_c, &mut b0_s, ts, &mut rng, 64);
                if b0_s.state() == ConnState::Connecting
                    && events(&mut b0_s)
                        .iter()
                        .any(|e| matches!(e, Event::Handoff { .. }))
                {
                    let h = std::mem::replace(&mut b0_s, b1.accept(9, ts))
                        .into_handoff()
                        .unwrap();
                    let id = b1.id();
                    owner = Some(Connection::from_handoff(
                        h,
                        id,
                        b1.cfg.clone(),
                        b1.table.clone(),
                        ts,
                    ));
                }
            }
            exchange(&mut b1_c, &mut a_s, ts, &mut rng, 64);
            b1_c.on_timer(ts);
            for e in events(&mut b1_c) {
                match e {
                    Event::Dial { .. } => b1_c.on_connected(ts),
                    Event::Message(m) => got_b.push(m.header.tid),
                    _ => {}
                }
            }
            got_a.extend(msgs(&events(&mut a_s)).iter().map(|m| m.header.tid));
            got_a.extend(msgs(&events(&mut a_c)).iter().map(|m| m.header.tid));
        }
        assert!(owner.is_some(), "the peer's connection was handed off");
        assert!(
            got_a.contains(&2),
            "B's frame reached A: {got_a:?} {a_first}"
        );
        assert!(
            got_b.contains(&1),
            "A's frame reached B: {got_b:?} {a_first}"
        );
        assert!(b0.table.is_empty(), "no session on the foreign core");
        let mut dup = got_a.clone();
        dup.sort();
        dup.dedup();
        assert_eq!(dup.len(), got_a.len(), "duplicates at A: {got_a:?}");
    }
}
