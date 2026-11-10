// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! In-memory pipe tests: our client <-> our server.
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::auth::*;
use msgr2::*;

const OSD: u8 = EntityName::OSD;
const CLI: u8 = EntityName::CLIENT;

fn cluster_pair() -> (Node, Node) {
    (
        Node::new(OSD, 1, 1, PolicyTable::osd_cluster()),
        Node::new(OSD, 2, 2, PolicyTable::osd_cluster()),
    )
}

#[test]
fn timer_notifications_cover_ready_activity_backoff_and_close() {
    let (mut a, mut b) = cluster_pair();
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    let q = EventQueue::default();
    c.set_timer_queue(&q, 10);
    s.set_timer_queue(&q, 20);
    assert_eq!(q.pop(), Some(10));
    assert_eq!(q.pop(), Some(20));
    exchange(&mut c, &mut s, t(1), &mut Rng(17), 4096);
    assert!(connected(&events(&mut c)).is_some());
    for _ in 0..4 {
        if q.pop().is_none() {
            break;
        }
    }
    let old = c.next_timer();
    c.on_bytes(&[], t(2));
    assert_eq!(q.pop(), Some(10));
    assert!(c.next_timer() > old);
    c.send_message(msg(1, 42, 16));
    c.send_keepalive(t(3));
    assert_eq!(q.pop(), Some(10), "mutations coalesce");
    c.on_closed(t(4));
    assert_eq!(q.pop(), Some(10));
    assert!(
        events(&mut c)
            .iter()
            .any(|e| matches!(e, Event::Dial { .. })),
        "ready faults redial immediately"
    );
    c.on_connected(t(5));
    assert_eq!(q.pop(), Some(10));
    c.on_closed(t(6));
    assert_eq!(q.pop(), Some(10));
    let reconnect = c.next_timer().unwrap();
    c.on_timer(reconnect);
    assert_eq!(q.pop(), Some(10));
    assert!(
        events(&mut c)
            .iter()
            .any(|e| matches!(e, Event::Dial { .. }))
    );
    c.close();
    assert_eq!(q.pop(), Some(10));
    assert_eq!(c.next_timer(), None);
    s.on_bytes(&[], t(5));
    drop(s);
    assert_eq!(q.pop(), None, "drop cancels queued registration");
}

#[test]
fn a_ready_send_arms_no_timer_probe() {
    // Queueing on a Ready link moves no deadline (the idle deadline follows `last_activity`, the frame deadline the
    // receive side): the core must not re-index the connection for every message it sends.
    let (mut a, mut b) = cluster_pair();
    let mut rng = Rng(23);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 50);
    events(&mut c);
    let q = EventQueue::default();
    c.set_timer_queue(&q, 10);
    while q.pop().is_some() {}
    assert!(c.send_message(msg(2, 42, 10)));
    assert_eq!(q.pop(), None, "a queued message changes no deadline");
}

#[test]
fn output_notifications_deliver_handshake_messages_and_ack_without_scanning() {
    let (mut a, mut b) = cluster_pair();
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    let q = OutputQueue::default();
    c.set_output_queue(&q, 10);
    s.set_output_queue(&q, 20);
    c.send_message(msg(1, 42, 128));
    for _ in 0..100 {
        let Some(id) = q.pop() else { break };
        match id {
            10 => {
                let bytes = c.poll_output();
                s.on_bytes(&bytes, t(1));
            }
            20 => {
                let bytes = s.poll_output();
                c.on_bytes(&bytes, t(1));
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(
        q.pop(),
        None,
        "notification pump must finish within its bound"
    );
    assert!(connected(&events(&mut c)).is_some());
    assert_eq!(msgs(&events(&mut s)).len(), 1);
    assert_eq!(
        a.table.info(&b.addrs).unwrap().unacked,
        0,
        "ACK notification was delivered"
    );
    s.send_keepalive(t(2));
    assert_eq!(q.pop(), Some(20));
    let bytes = s.poll_output();
    c.on_bytes(&bytes, t(2));
    assert_eq!(
        q.pop(),
        Some(10),
        "keepalive response must wake the transport"
    );
}

#[test]
fn event_notifications_include_existing_dials_and_coalesce_buffered_frames() {
    let (a, mut b) = cluster_pair();
    let mut c = Connection::client(
        55,
        a.cfg.clone(),
        a.table.clone(),
        Box::new(AuthNoneClient {
            name: a.cfg.name,
            global_id: 0,
        }),
        OSD,
        b.addrs.clone(),
        b.addrs.0[0],
    );
    let q = EventQueue::default();
    c.set_event_queue(&q, 55);
    assert_eq!(q.pop(), Some(55));
    assert!(matches!(c.poll_event(), Some(Event::Dial { .. })));
    assert_eq!(q.pop(), None);
    c.on_connected(t(0));
    let mut s = b.accept(1, t(0));
    s.set_event_queue(&q, 66);
    exchange(&mut c, &mut s, t(1), &mut Rng(42), 4096);
    events(&mut c);
    events(&mut s);
    while q.pop().is_some() {}
    c.send_message(msg(1, 42, 100));
    c.send_message(msg(2, 42, 100));
    s.on_bytes(&c.poll_output(), t(2));
    assert_eq!(q.pop(), Some(66));
    assert_eq!(q.pop(), None);
    assert!(matches!(s.poll_event(), Some(Event::Message(_))));
    assert!(s.has_events());
    s.notify_events(); // consumer resumes after a deliberate admission pause, without new bytes
    assert_eq!(q.pop(), Some(66));
    assert!(matches!(s.poll_event(), Some(Event::Message(_))));
    assert!(!s.has_events());
    assert_eq!(q.pop(), None);
}

/// Regression (adr 0074): a reply queued after the request's bytes were processed (store completion, cross-core
/// relay) must wake the transport by itself; before the fix it waited for unrelated input (15 s client stalls).
#[test]
fn reply_queued_outside_on_bytes_wakes_transport() {
    let (mut a, mut b) = cluster_pair();
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    let q = OutputQueue::default();
    c.set_output_queue(&q, 10);
    s.set_output_queue(&q, 20);
    c.send_message(msg(1, 42, 128));
    while let Some(id) = q.pop() {
        if id == 10 {
            let bytes = c.poll_output();
            s.on_bytes(&bytes, t(1));
        } else {
            let bytes = s.poll_output();
            c.on_bytes(&bytes, t(1));
        }
    }
    assert_eq!(msgs(&events(&mut s)).len(), 1);
    assert!(!s.has_output() && !c.has_output(), "idle");
    // the request was consumed and acked; the reply comes later, outside on_bytes
    s.send_message(msg(2, 43, 4096));
    assert_eq!(q.pop(), Some(20), "queued reply must wake the transport");
    assert_eq!(q.pop(), None);
    let bytes = s.poll_output();
    c.on_bytes(&bytes, t(2));
    assert_eq!(msgs(&events(&mut c)).len(), 1);
    assert!(!s.has_output());
}

#[test]
fn handshake_and_messages_lossless_random_chunks() {
    for max_chunk in [1usize, 3, 17, 1000, 1 << 20] {
        let (mut a, mut b) = cluster_pair();
        let mut rng = Rng(0x1234 + max_chunk as u64);
        let mut c = a.dial(&b, t(0));
        let mut s = b.accept(1, t(0));
        for i in 1..=5 {
            c.send_message(msg(i, 42, (i * 70) as usize));
        }
        exchange(&mut c, &mut s, t(1), &mut rng, max_chunk);
        let (ec, es) = (events(&mut c), events(&mut s));
        let pc = connected(&ec).expect("client connected");
        let ps = connected(&es).expect("server connected");
        assert_eq!(pc.name, EntityName::osd(2));
        assert_eq!(ps.name, EntityName::osd(1));
        assert!(!pc.lossy && !ps.lossy && !pc.resumed);
        assert_eq!(pc.addrs, b.addrs);
        assert_eq!(ps.addrs, a.addrs);
        let m = msgs(&es);
        assert_eq!(m.len(), 5);
        for (i, m) in m.iter().enumerate() {
            let i = i as u64 + 1;
            assert_eq!(
                (
                    m.header.seq,
                    m.header.tid,
                    m.header.msg_type,
                    m.header.priority
                ),
                (i, i, 42, 127)
            );
            assert_eq!(m.front, vec![i as u8; (i * 70) as usize]);
            assert_eq!(m.header.compat_version, 1);
        }
        // reply from server; acks flow back and trim the client's sent queue
        s.send_message(msg(100, 43, 5));
        exchange(&mut c, &mut s, t(2), &mut rng, max_chunk);
        assert_eq!(msgs(&events(&mut c)).len(), 1);
        let info = a.table.info(&b.addrs).unwrap();
        assert_eq!(
            (info.state, info.unacked, info.out_seq, info.in_seq),
            (SessState::Ready, 0, 5, 1)
        );
        assert_ne!(info.server_cookie, 0);
        assert_ne!(info.client_cookie, 0);
    }
}

#[test]
fn lossy_client_to_stateless_server() {
    let mut cl = Node::new(CLI, -1, 1, PolicyTable::osd_hb_client());
    let mut osd = Node::new(OSD, 3, 3, PolicyTable::osd_public());
    let mut rng = Rng(5);
    let mut c = cl.dial(&osd, t(0));
    let mut s = osd.accept(1, t(0));
    c.send_message(msg(1, 70, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 64);
    let (ec, es) = (events(&mut c), events(&mut s));
    assert!(connected(&ec).unwrap().lossy && connected(&es).unwrap().lossy);
    // client gid comes from the auth layer (global id 4096)
    assert_eq!(connected(&es).unwrap().name, EntityName::new(CLI, 4096));
    assert_eq!(msgs(&es).len(), 1);
    // lossy never sends ACK frames: only the reply header carries ack_seq
    s.send_message(msg(2, 71, 1));
    exchange(&mut c, &mut s, t(2), &mut rng, 64);
    assert_eq!(msgs(&events(&mut c))[0].header.ack_seq, 1);
    // fault -> Reset + Closed on both sides; sessions removed
    c.on_closed(t(3));
    s.on_closed(t(3));
    let (ec, es) = (events(&mut c), events(&mut s));
    assert!(ec.contains(&Event::Reset) && ec.contains(&Event::Closed));
    assert!(es.contains(&Event::Reset) && es.contains(&Event::Closed));
    assert_eq!(c.state(), ConnState::Closed);
    assert!(cl.table.is_empty() && osd.table.is_empty());
}

/// A second client() to the same addrs on a LOSSY session must not stop the healthy READY connection (spec 10.3
/// supersession is for resumable sessions only); the new connection retires it once it is READY itself.
#[test]
fn second_lossy_dial_keeps_the_ready_connection() {
    let mut cl = Node::new(CLI, -1, 1, PolicyTable::osd_hb_client());
    let mut osd = Node::new(OSD, 3, 3, PolicyTable::osd_public());
    let mut rng = Rng(9);
    let mut c1 = cl.dial(&osd, t(0));
    let mut s1 = osd.accept(1, t(0));
    exchange(&mut c1, &mut s1, t(1), &mut rng, 64);
    assert_eq!(c1.state(), ConnState::Ready);
    let c1_id = c1.id();
    let mut c2 = cl.dial(&osd, t(2));
    assert!(
        !cl.table.take_superseded().contains(&c1_id),
        "second lossy dial superseded the READY connection"
    );
    assert_eq!(c1.state(), ConnState::Ready);
    c1.send_message(msg(1, 70, 10));
    exchange(&mut c1, &mut s1, t(3), &mut rng, 64);
    assert_eq!(msgs(&events(&mut s1)).len(), 1);
    // the new connection takes over once READY
    let mut s2 = osd.accept(2, t(4));
    exchange(&mut c2, &mut s2, t(5), &mut rng, 64);
    assert_eq!(c2.state(), ConnState::Ready);
    assert!(cl.table.take_superseded().contains(&c1_id));
    // the driver closes the retired connection: the session the new one carries stays
    c1.close();
    assert!(
        cl.table.info(&osd.addrs).is_some(),
        "closing the retired connection dropped the live lossy session"
    );
    events(&mut s2);
    c2.send_message(msg(2, 70, 10));
    exchange(&mut c2, &mut s2, t(6), &mut rng, 64);
    assert_eq!(msgs(&events(&mut s2)).len(), 1);
}

#[test]
fn keepalive() {
    let (mut a, mut b) = cluster_pair();
    let mut rng = Rng(9);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 100);
    events(&mut c);
    events(&mut s);
    c.send_keepalive(t(5_000));
    exchange(&mut c, &mut s, t(5_001), &mut rng, 100);
    assert!(events(&mut c).contains(&Event::KeepaliveAck { sec: 5, nsec: 0 }));
    // idle timeout faults the client; lossless_peer = standby when nothing is queued
    assert_eq!(c.next_timer(), Some(t(5_001 + 900_000)));
    c.on_timer(t(5_001 + 900_000));
    assert!(events(&mut c).contains(&Event::Fault(FaultReason::Timeout("idle"))));
    assert_eq!(c.state(), ConnState::Standby);
}

#[test]
fn reconnect_replays_unacked_exactly_once() {
    let (mut a, mut b) = cluster_pair();
    let mut rng = Rng(77);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    for i in 1..=3 {
        c.send_message(msg(i, 42, 10));
    }
    exchange(&mut c, &mut s, t(1), &mut rng, 50);
    events(&mut c);
    assert_eq!(msgs(&events(&mut s)).len(), 3);
    // more messages; the server only sees part of the byte stream, then the link drops
    for i in 4..=6 {
        c.send_message(msg(i, 42, 10));
    }
    let out = c.poll_output();
    let cut = out.len() / 2; // between/inside frames
    let mut sink = Rng(1);
    feed(&mut s, &out[..cut], t(2), &mut sink, 1000);
    let got_before = msgs(&events(&mut s))
        .iter()
        .map(|m| m.header.tid)
        .collect::<Vec<_>>();
    c.on_closed(t(3));
    s.on_closed(t(3));
    let ec = events(&mut c);
    assert!(ec.contains(&Event::Fault(FaultReason::Io)));
    assert!(ec.iter().any(|e| matches!(e, Event::Dial { .. })), "{ec:?}");
    assert!(events(&mut s).contains(&Event::Closed));
    // client reconnects: new stream, new server conn
    let mut s2 = b.accept(1, t(4));
    c.on_connected(t(4));
    c.send_message(msg(7, 42, 10));
    exchange(&mut c, &mut s2, t(5), &mut rng, 7);
    let (ec, es) = (events(&mut c), events(&mut s2));
    let pc = connected(&ec).unwrap();
    assert!(pc.resumed && connected(&es).unwrap().resumed);
    let got_after: Vec<u64> = msgs(&es).iter().map(|m| m.header.tid).collect();
    let mut all = got_before;
    all.extend(got_after);
    assert_eq!(all, vec![4, 5, 6, 7], "exactly once, in order");
    assert_eq!(a.table.info(&b.addrs).unwrap().connect_seq, 1);
    // seqs unchanged by replay
    assert_eq!(a.table.info(&b.addrs).unwrap().out_seq, 7);
}

#[test]
fn server_restart_resets_session_and_resends() {
    // spec 10.3 behaviour (reset drops): the policy without `keep_owed`
    let spec = || PolicyTable::uniform(Policy::lossless_peer(OSD_REQUIRED));
    let mut a = Node::new(OSD, 1, 1, spec());
    let mut b = Node::new(OSD, 2, 2, spec());
    let mut rng = Rng(3);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 50);
    events(&mut c);
    // server "restarts": fresh table; client keeps session with a server cookie
    c.on_closed(t(2));
    events(&mut c);
    let mut b2 = Node::new(OSD, 2, 2, spec());
    let mut s2 = b2.accept(1, t(3));
    c.send_message(msg(2, 42, 10)); // dropped by the full reset (spec 10.3)
    c.on_connected(t(3));
    exchange(&mut c, &mut s2, t(4), &mut rng, 9);
    let ec = events(&mut c);
    assert!(ec.contains(&Event::RemoteReset), "{ec:?}");
    assert!(!connected(&ec).unwrap().resumed);
    assert!(msgs(&events(&mut s2)).is_empty());
    c.send_message(msg(3, 42, 10));
    exchange(&mut c, &mut s2, t(5), &mut rng, 9);
    let es = events(&mut s2);
    let m = msgs(&es);
    assert_eq!((m.len(), m[0].header.tid, m[0].header.seq), (1, 3, 1));
}

#[test]
fn peer_restart_detected_by_cookie() {
    // lossless_peer_reuse has resetcheck=true
    let pol = || PolicyTable::uniform(Policy::lossless_peer_reuse(0));
    let mut a = Node::new(OSD, 1, 1, pol());
    let mut b = Node::new(OSD, 2, 2, pol());
    let mut rng = Rng(4);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 50);
    events(&mut s);
    // A restarts: new table, same addrs -> new client cookie
    let mut a2 = Node::new(OSD, 1, 1, pol()).reseed(424242);
    let mut c2 = a2.dial(&b, t(2));
    let mut s2 = b.accept(1, t(2));
    exchange(&mut c2, &mut s2, t(3), &mut rng, 50);
    let es = events(&mut s2);
    assert!(es.contains(&Event::RemoteReset), "{es:?}");
    assert!(connected(&es).is_some());
    // old transport was superseded
    assert!(events(&mut s).iter().all(|e| *e != Event::Reset));
}

#[test]
fn connection_race_resolves_to_one_transport() {
    // A (ip 1) < B (ip 2): the connection dialled by A must win on both sides.
    let (mut a, mut b) = cluster_pair();
    let mut rng = Rng(11);
    let mut a_c = a.dial(&b, t(0)); // A -> B
    let mut b_s = b.accept(1, t(0));
    let mut b_c = b.dial(&a, t(0)); // B -> A
    let mut a_s = a.accept(2, t(0));
    a_c.send_message(msg(1, 42, 8));
    b_c.send_message(msg(2, 43, 8));
    // interleave: both handshakes progress step by step
    for _ in 0..50 {
        let mut moved = false;
        for (x, y) in [(&mut a_c, &mut b_s), (&mut b_c, &mut a_s)] {
            let out = x.poll_output();
            moved |= feed(y, &out, t(1), &mut rng, 13);
            let out = y.poll_output();
            moved |= feed(x, &out, t(1), &mut rng, 13);
        }
        if !moved {
            break;
        }
    }
    let (e_ac, e_bs, e_bc, e_as) = (
        events(&mut a_c),
        events(&mut b_s),
        events(&mut b_c),
        events(&mut a_s),
    );
    // A's dialled connection is the transport
    assert!(
        connected(&e_ac).is_some() && connected(&e_bs).is_some(),
        "{e_ac:?} {e_bs:?}"
    );
    assert!(
        connected(&e_bc).is_none() && connected(&e_as).is_none(),
        "{e_bc:?} {e_as:?}"
    );
    // B's own dialler lost (superseded at B) or was told to WAIT
    assert!(b.table.take_superseded().contains(&b_c.id()));
    assert!(
        e_bc.iter()
            .any(|e| matches!(e, Event::Fault(FaultReason::Wait)))
            || b_c.state() == ConnState::Closed
    );
    // both messages are delivered over the winning connection
    let mut rng2 = Rng(12);
    b_s.send_message(msg(3, 44, 1));
    exchange(&mut a_c, &mut b_s, t(2), &mut rng2, 100);
    let mut tids: Vec<u64> = msgs(&e_bs).iter().map(|m| m.header.tid).collect();
    tids.extend(msgs(&events(&mut b_s)).iter().map(|m| m.header.tid));
    assert_eq!(tids, vec![1]);
    let ea = events(&mut a_c);
    assert_eq!(
        msgs(&ea).iter().map(|m| m.header.tid).collect::<Vec<_>>(),
        vec![3]
    );
    // B's message 2 sat in the session queue of B's dialler: it moved with the session
    let info = b.table.info(&a.addrs).unwrap();
    assert_eq!(info.state, SessState::Ready);
    assert_eq!(info.active, Some(b_s.id()));
    let _ = (&mut a_s, &mut b_c);
}

#[test]
fn wait_in_reconnect_race_then_peer_wins() {
    // A (ip 1) < B (ip 2). Both reconnect simultaneously with equal connect_seq: at A the existing
    // (own, connecting) session wins -> WAIT for B; at B the incoming wins.
    let (mut a, mut b) = cluster_pair();
    let mut rng = Rng(21);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 100);
    events(&mut c);
    events(&mut s);
    c.on_closed(t(2));
    s.on_closed(t(2));
    events(&mut c);
    events(&mut s);
    c.send_message(msg(1, 42, 4)); // A queues -> wakes from standby
    assert!(
        events(&mut c)
            .iter()
            .any(|e| matches!(e, Event::Dial { .. }))
    );
    c.on_connected(t(3));
    let mut b_c = b.dial(&a, t(3)); // B dials A concurrently (session reused)
    b_c.send_message(msg(2, 43, 4));
    let mut a_s = a.accept(2, t(3));
    let mut b_s = b.accept(1, t(3));
    exchange(&mut b_c, &mut a_s, t(4), &mut rng, 100);
    let e = events(&mut b_c);
    assert!(e.contains(&Event::Fault(FaultReason::Wait)), "{e:?}");
    assert_eq!(b_c.state(), ConnState::Backoff);
    assert_eq!(b_c.next_timer(), Some(t(4 + 15_000)));
    exchange(&mut c, &mut b_s, t(5), &mut rng, 100);
    let (ec, es) = (events(&mut c), events(&mut b_s));
    assert!(
        connected(&ec).unwrap().resumed && connected(&es).unwrap().resumed,
        "{ec:?} {es:?}"
    );
    assert_eq!(msgs(&es).len(), 1);
    assert_eq!(
        msgs(&ec).len(),
        1,
        "B's message queued on its losing dialler moved with the session"
    );
    assert!(b.table.take_superseded().contains(&b_c.id()));
}

fn secure_pair(
    modes_c: Vec<u32>,
    modes_s: Vec<u32>,
    key_c: &[u8],
    key_s: &[u8],
    rounds: u32,
) -> (Node, Node, Connection, Connection) {
    let (mut a, mut b) = cluster_pair();
    let secret: Vec<u8> = (0..64u8).collect();
    let kc = KeyedClient {
        key: key_c.to_vec(),
        secret: secret.clone(),
        modes: modes_c,
        method: AUTH_METHOD_CEPHX,
    };
    let ks = KeyedServer {
        peer_name: None,
        key: key_s.to_vec(),
        secret,
        rounds,
        done: 0,
        methods: vec![AUTH_METHOD_CEPHX],
        modes: modes_s,
    };
    let c = a.dial_with(&b, Box::new(kc), t(0));
    let s = b.accept_with(1, Box::new(ks), t(0));
    (a, b, c, s)
}

#[test]
fn secure_lossy_send_reclaims_unique_payload_after_releasing_its_crc_hint() {
    let mut a = Node::new(OSD, 1, 1, PolicyTable::uniform(Policy::lossy_client(0)));
    let mut b = Node::new(
        OSD,
        2,
        2,
        PolicyTable::uniform(Policy::stateless_registered_server(0)),
    );
    let secret: Vec<u8> = (0..64).collect();
    let mut c = a.dial_with(
        &b,
        Box::new(KeyedClient {
            key: vec![9; 16],
            secret: secret.clone(),
            modes: vec![MODE_SECURE],
            method: AUTH_METHOD_CEPHX,
        }),
        t(0),
    );
    let mut s = b.accept_with(
        1,
        Box::new(KeyedServer {
            peer_name: None,
            key: vec![9; 16],
            secret,
            rounds: 0,
            done: 0,
            methods: vec![AUTH_METHOD_CEPHX],
            modes: vec![MODE_SECURE],
        }),
        t(0),
    );
    exchange(&mut c, &mut s, t(1), &mut Rng(8), 4096);
    assert!(connected(&events(&mut c)).is_some());
    assert!(connected(&events(&mut s)).is_some());
    let data = bytes::Bytes::from(vec![0x6a; 1 << 20]);
    let ptr = data.as_ptr();
    let hint = crc::CrcHint::new(&data, crc::crc32c(!0, &data));
    c.send_message(Message {
        msg_type: 42,
        tid: 1,
        version: 1,
        front: vec![2; 17],
        middle: vec![3; 7],
        data,
        data_crc: hint,
        ..Default::default()
    });
    let runs = c.poll_output_chunks();
    assert!(
        runs.iter().any(|r| r.as_ptr() == ptr && r.len() == 1 << 20),
        "lossy secure send copied a reclaimable payload"
    );
    for run in runs {
        s.on_bytes(&run, t(2));
    }
    let got = events(&mut s);
    let got = msgs(&got);
    assert_eq!(got.len(), 1);
    assert!(got[0].data.iter().all(|&b| b == 0x6a));
    let data = bytes::Bytes::from(vec![0x71; 1 << 20]);
    let ptr = data.as_ptr();
    s.send_message(Message {
        msg_type: 42,
        tid: 2,
        version: 1,
        data,
        ..Default::default()
    });
    let runs = s.poll_output_chunks();
    assert!(runs.iter().any(|r| r.as_ptr() == ptr && r.len() == 1 << 20));
    for run in runs {
        c.on_bytes(&run, t(3));
    }
    let got = events(&mut c);
    let got = msgs(&got);
    assert_eq!(got.len(), 1);
    assert!(got[0].data.iter().all(|&b| b == 0x71));
}

#[test]
fn secure_lossless_replay_preserves_the_large_plaintext_payload() {
    let (a, mut b, mut c, mut s) =
        secure_pair(vec![MODE_SECURE], vec![MODE_SECURE], &[9; 16], &[9; 16], 0);
    exchange(&mut c, &mut s, t(1), &mut Rng(19), 4096);
    events(&mut c);
    events(&mut s);
    let data = bytes::Bytes::from(vec![0x6a; 1 << 20]);
    let ptr = data.as_ptr();
    c.send_message(Message {
        msg_type: 42,
        tid: 77,
        version: 1,
        data,
        ..Default::default()
    });
    let wire = c.poll_output_chunks();
    assert!(!wire.iter().any(|b| b.as_ptr() == ptr));
    assert_eq!(a.table.info(&b.addrs).unwrap().unacked, 1);
    drop(wire); // no bytes or ACK reached the peer
    c.on_closed(t(2));
    s.on_closed(t(2));
    c.on_connected(t(3));
    let secret: Vec<u8> = (0..64).collect();
    let mut s = b.accept_with(
        1,
        Box::new(KeyedServer {
            peer_name: None,
            key: vec![9; 16],
            secret,
            rounds: 0,
            done: 0,
            methods: vec![AUTH_METHOD_CEPHX],
            modes: vec![MODE_SECURE],
        }),
        t(3),
    );
    exchange(&mut c, &mut s, t(4), &mut Rng(20), 4096);
    let got = events(&mut s);
    let got = msgs(&got);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].header.tid, 77);
    assert!(got[0].data.iter().all(|&b| b == 0x6a));
}

#[test]
fn authenticated_frame_retains_ingress_ownership_and_faults_release_it() {
    for mode in [MODE_CRC, MODE_SECURE] {
        for corrupt in [false, true] {
            let (_a, _b, mut client, mut server) =
                secure_pair(vec![mode], vec![mode], &[9; 16], &[9; 16], 0);
            exchange(&mut client, &mut server, t(1), &mut Rng(911), 4096);
            assert!(connected(&events(&mut client)).is_some());
            assert!(connected(&events(&mut server)).is_some());
            client.send_message(msg(77, 42, 1024));
            let mut wire = client.poll_output();
            assert!(!wire.is_empty());
            if corrupt {
                *wire.last_mut().unwrap() ^= 0x80;
            }
            let credits = ingress::IngressCredits::relay();
            let guard = ingress::InputGuard(credits.reserve(0, 64 << 20));
            server.on_bytes_guarded(&wire, t(2), guard);
            let received = events(&mut server);
            if corrupt {
                assert!(
                    received
                        .iter()
                        .any(|event| matches!(event, Event::Fault(_))),
                    "{received:?}"
                );
                assert!(
                    !received
                        .iter()
                        .any(|event| matches!(event, Event::Message(_)))
                );
                assert!(credits.idle());
            } else {
                let frame = received
                    .into_iter()
                    .find_map(|event| match event {
                        Event::Message(frame) => Some(frame),
                        _ => None,
                    })
                    .unwrap();
                assert_eq!(frame.header.tid, 77);
                assert!(!credits.ready(0, 1));
                drop(frame);
                assert!(credits.idle());
            }
        }
    }
}

#[test]
fn secure_mode_with_multi_round_auth() {
    for (rounds, chunk) in [(0, 4096), (1, 13), (3, 1)] {
        let (_a, _b, mut c, mut s) = secure_pair(
            vec![MODE_SECURE, MODE_CRC],
            vec![MODE_CRC, MODE_SECURE],
            &[9u8; 16],
            &[9u8; 16],
            rounds,
        );
        let mut rng = Rng(31 + chunk as u64);
        for i in 1..=4 {
            c.send_message(msg(i, 42, (i * 500) as usize));
        }
        exchange(&mut c, &mut s, t(1), &mut rng, chunk);
        let (ec, es) = (events(&mut c), events(&mut s));
        assert!(connected(&ec).is_some(), "{ec:?}");
        assert_eq!(connected(&es).unwrap().global_id, 5555);
        assert_eq!(c.mode(), MODE_SECURE);
        assert_eq!(msgs(&es).len(), 4);
        s.send_message(msg(9, 1, 3000));
        exchange(&mut c, &mut s, t(2), &mut rng, chunk);
        assert_eq!(msgs(&events(&mut c))[0].data.len(), 9000);
    }
}

#[test]
fn mode_choice_follows_client_preference_among_allowed() {
    // client prefers secure but server allows only crc -> crc
    let (_a, _b, mut c, mut s) =
        secure_pair(vec![MODE_SECURE, MODE_CRC], vec![MODE_CRC], b"k", b"k", 0);
    let mut rng = Rng(1);
    exchange(&mut c, &mut s, t(1), &mut rng, 100);
    assert!(connected(&events(&mut c)).is_some());
    assert_eq!((c.mode(), s.mode()), (MODE_CRC, MODE_CRC));
}

#[test]
fn bad_method_when_no_common_mode() {
    let (_a, _b, mut c, mut s) = secure_pair(vec![MODE_SECURE], vec![MODE_CRC], b"k", b"k", 0);
    let mut rng = Rng(1);
    exchange(&mut c, &mut s, t(1), &mut rng, 100);
    let ec = events(&mut c);
    assert!(connected(&ec).is_none());
    assert!(
        ec.iter()
            .any(|e| matches!(e, Event::Fault(FaultReason::Auth(_)))),
        "{ec:?}"
    );
}

#[test]
fn signature_mismatch_faults() {
    let (_a, _b, mut c, mut s) =
        secure_pair(vec![MODE_CRC], vec![MODE_CRC], b"key-one", b"key-two", 0);
    let mut rng = Rng(1);
    exchange(&mut c, &mut s, t(1), &mut rng, 100);
    let (ec, es) = (events(&mut c), events(&mut s));
    assert!(connected(&ec).is_none() && connected(&es).is_none());
    let sig = |e: &[Event]| {
        e.iter()
            .any(|e| matches!(e, Event::Fault(FaultReason::Protocol(m)) if m.contains("SIGNATURE")))
    };
    assert!(sig(&ec) || sig(&es), "{ec:?} {es:?}");
}

#[test]
fn missing_features_is_reported_and_retried() {
    let (mut a, mut b) = cluster_pair();
    a.cfg.supported_features = 0x1; // lacks PGID64 etc. required by lossless_peer(OSD_REQUIRED)
    let mut c = a.dial(&b, t(0));
    c.send_message(msg(1, 1, 1));
    let mut s = b.accept(1, t(0));
    let mut rng = Rng(8);
    exchange(&mut c, &mut s, t(1), &mut rng, 100);
    let ec = events(&mut c);
    let missing = OSD_REQUIRED & !1 | MSGR2_REQUIRED;
    assert!(
        ec.contains(&Event::Fault(FaultReason::MissingFeatures(missing))),
        "{ec:?}"
    );
    assert_eq!(c.state(), ConnState::Backoff);
    assert_eq!(c.next_timer(), Some(t(1 + 200)));
    c.on_timer(t(201));
    assert!(matches!(events(&mut c)[..], [Event::Dial { .. }]));
}

#[test]
fn backoff_doubles_and_caps() {
    let (mut a, b) = cluster_pair();
    let mut c = a.dial(&b, t(0));
    c.send_message(msg(1, 1, 1));
    let mut now = 0;
    let mut seen = vec![];
    for _ in 0..9 {
        c.on_closed(t(now)); // connect failed / reset
        let at = c.next_timer().unwrap();
        seen.push(at.as_millis() as u64 - now);
        now = at.as_millis() as u64;
        c.on_timer(t(now));
        assert!(matches!(events(&mut c).last(), Some(Event::Dial { .. })));
        c.on_connected(t(now));
    }
    assert_eq!(
        seen,
        vec![200, 400, 800, 1600, 3200, 6400, 12800, 15000, 15000]
    );
}

#[test]
fn ready_timeout_faults() {
    let (mut a, mut b) = cluster_pair();
    let mut c = a.dial(&b, t(0));
    let _s = b.accept(1, t(0));
    assert_eq!(c.next_timer(), Some(t(10_000)));
    c.on_timer(t(10_000));
    assert!(events(&mut c).contains(&Event::Fault(FaultReason::Timeout("ready"))));
}

#[test]
fn garbage_and_msgr1_banners_are_fatal() {
    let (mut a, b) = cluster_pair();
    let mut c = a.dial(&b, t(0));
    c.on_bytes(b"ceph v027 0000000", t(1));
    let ev = events(&mut c);
    assert!(ev.contains(&Event::Fault(FaultReason::Banner(BannerError::Msgr1))));
    assert!(ev.contains(&Event::Closed));
}

#[test]
fn illegal_tag_faults_server() {
    let (_a, mut b) = cluster_pair();
    let mut s = b.accept(1, t(0));
    let mut enc = Encoder::new(Revision::V21);
    let mut v = Vec::new();
    Banner::ours().encode(&mut v);
    enc.encode_control(Tag::Ack as u8, &[0; 8], &mut v).unwrap();
    s.on_bytes(&v, t(1));
    assert!(
        events(&mut s)
            .iter()
            .any(|e| matches!(e, Event::Fault(FaultReason::Protocol(_))))
    );
}

#[test]
fn standby_policy_wakes_on_send() {
    let (mut a, mut b) = cluster_pair();
    let mut rng = Rng(2);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 100); // ready, nothing queued (acked)
    events(&mut c);
    c.on_closed(t(2));
    // lossless_peer = standby: nothing queued -> Standby, no Dial
    assert_eq!(c.state(), ConnState::Standby);
    assert!(
        !events(&mut c)
            .iter()
            .any(|e| matches!(e, Event::Dial { .. }))
    );
    assert!(c.send_message(msg(1, 1, 1)));
    assert!(
        events(&mut c)
            .iter()
            .any(|e| matches!(e, Event::Dial { .. }))
    );
}

#[test]
fn session_table_needs_dial_after_server_side_fault() {
    let (mut a, mut b) = cluster_pair();
    let mut rng = Rng(2);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 100);
    s.on_closed(t(2));
    c.on_closed(t(2));
    // B can queue to A (session known from A's CLIENT_IDENT) and learns it must dial
    assert_eq!(b.table.queue(&a.addrs, msg(1, 1, 1)), Queue::NeedDial);
    assert_eq!(
        b.table.needs_dial(),
        vec![(a.addrs.clone(), EntityName::osd(1))]
    );
    // B dials A: the session (with its cookies) is reused -> RECONNECT, resumed
    let mut b_c = b.dial(&a, t(3));
    let mut a_s = a.accept(2, t(3));
    c.send_message(msg(5, 1, 1)); // A's old client conn is standby/dial; ignore
    exchange(&mut b_c, &mut a_s, t(4), &mut rng, 100);
    let ea = events(&mut a_s);
    assert!(connected(&ea).unwrap().resumed, "{ea:?}");
    assert_eq!(msgs(&ea).len(), 1);
}

#[test]
fn v20_only_peer_interops_crc_and_secure() {
    for secure in [false, true] {
        let (mut a, mut b) = cluster_pair();
        a.cfg.v20_only = true; // old peer: no REVISION_1 in its banner, v2.0 framing
        let modes = if secure {
            vec![MODE_SECURE]
        } else {
            vec![MODE_CRC]
        };
        let secret: Vec<u8> = (100..164u8).collect();
        let kc = KeyedClient {
            key: vec![5; 16],
            secret: secret.clone(),
            modes: modes.clone(),
            method: AUTH_METHOD_CEPHX,
        };
        let ks = KeyedServer {
            peer_name: None,
            key: vec![5; 16],
            secret,
            rounds: 1,
            done: 0,
            methods: vec![AUTH_METHOD_CEPHX],
            modes: vec![MODE_CRC, MODE_SECURE],
        };
        let mut c = a.dial_with(&b, Box::new(kc), t(0));
        let mut s = b.accept_with(1, Box::new(ks), t(0));
        let mut rng = Rng(60);
        for i in 1..=3 {
            c.send_message(msg(i, 42, 300 * i as usize));
        }
        exchange(&mut c, &mut s, t(1), &mut rng, 29);
        s.send_message(msg(9, 1, 1000));
        exchange(&mut c, &mut s, t(2), &mut rng, 29);
        let (ec, es) = (events(&mut c), events(&mut s));
        assert!(connected(&ec).is_some(), "secure={secure} {ec:?}");
        assert_eq!(
            (msgs(&es).len(), msgs(&ec).len()),
            (3, 1),
            "secure={secure}"
        );
        assert_eq!(c.mode(), if secure { MODE_SECURE } else { MODE_CRC });
    }
}

#[test]
fn blank_client_addr_is_learned_from_hello() {
    let mut cl = Node::new(CLI, -1, 1, PolicyTable::osd_hb_client());
    // blank ip, only a nonce (like an rbd/rados client before it knows its address)
    let mut blank = addr(0, 0, 4711);
    blank.family = 0;
    blank.data = [0; 26];
    cl.cfg.addrs = denc::types::EntityAddrVec::single(blank);
    let mut osd = Node::new(OSD, 3, 3, PolicyTable::osd_public());
    let mut rng = Rng(5);
    let mut c = cl.dial(&osd, t(0));
    assert!(c.local_addresses().is_none());
    let mut s = osd.accept(1, t(0)); // peer socket = 10.0.0.1:4xxxx
    exchange(&mut c, &mut s, t(1), &mut rng, 100);
    let es = events(&mut s);
    let pa = connected(&es).unwrap().addrs.0[0];
    assert_eq!(pa.ipv4(), Some([10, 0, 0, 1]));
    assert_eq!((pa.nonce, pa.port(), pa.ty), (4711, 0, 2));
    assert_eq!(c.seen_by_peer().unwrap().ipv4(), Some([10, 0, 0, 1]));
    let view = c.local_addresses().unwrap();
    assert_eq!(view.advertised().collect::<Vec<_>>(), vec![pa]);
    assert_eq!(view.observed_by_peer(), c.seen_by_peer());
    assert_ne!(view.observed_by_peer().unwrap().port(), pa.port());
    c.on_closed(t(2));
    assert!(c.local_addresses().is_none());
    c.close();
    assert!(c.local_addresses().is_none());
}

/// Randomised drops/cuts on a lossless link: every message is delivered exactly once, in order,
/// in both directions (replay + dedup + trim).
#[test]
fn lossless_fuzz_exactly_once_in_order() {
    for seed in 1..=25u64 {
        let (mut a, mut b) = cluster_pair();
        let mut rng = Rng(seed * 0x9E37_79B9 + 1);
        let mut now = 0u64;
        let mut c = a.dial(&b, t(now));
        let mut s = b.accept(1, t(now));
        let (mut sent_a, mut sent_b, mut got_a, mut got_b) = (vec![], vec![], vec![], vec![]);
        let mut next_tid = 1u64;
        let collect =
            |c: &mut Connection, s: &mut Connection, got_a: &mut Vec<u64>, got_b: &mut Vec<u64>| {
                for e in events(c) {
                    if let Event::Message(m) = e {
                        got_a.push(m.header.tid);
                    }
                }
                for e in events(s) {
                    if let Event::Message(m) = e {
                        got_b.push(m.header.tid);
                    }
                }
            };
        for round in 0..150u32 {
            for _ in 0..(rng.next() % 4) {
                let tid = next_tid;
                next_tid += 1;
                let n = (rng.next() % 600) as usize;
                if rng.next().is_multiple_of(2) {
                    sent_a.push(tid);
                    c.send_message(msg(tid, 42, n));
                } else {
                    // no session at B before the first CLIENT_IDENT arrived: nothing to queue to
                    if b.table.queue(&a.addrs, msg(tid, 43, n)) != Queue::NoSession {
                        sent_b.push(tid);
                    }
                }
            }
            // some transfer steps with random cuts (a cut loses bytes: the link must be dropped after)
            let mut cut_happened = false;
            for _ in 0..(2 + rng.next() % 9) {
                now += 1;
                let (oc, os) = (c.poll_output(), s.poll_output());
                let cut = |o: &[u8], r: &mut Rng| {
                    if r.next().is_multiple_of(3) {
                        (r.next() as usize) % (o.len() + 1)
                    } else {
                        o.len()
                    }
                };
                let (kc, ks) = (cut(&oc, &mut rng), cut(&os, &mut rng));
                cut_happened |= kc < oc.len() || ks < os.len();
                feed(&mut s, &oc[..kc], t(now), &mut rng, 200);
                feed(&mut c, &os[..ks], t(now), &mut rng, 200);
                collect(&mut c, &mut s, &mut got_a, &mut got_b);
                if cut_happened {
                    break;
                }
            }
            if cut_happened || round.is_multiple_of(7) || rng.next().is_multiple_of(4) {
                // drop the link
                now += 1;
                c.on_closed(t(now));
                s.on_closed(t(now));
                collect(&mut c, &mut s, &mut got_a, &mut got_b);
                s = b.accept(1, t(now));
                if c.state() == ConnState::Backoff {
                    now = c.next_timer().unwrap().as_millis() as u64;
                    c.on_timer(t(now));
                }
                if c.state() == ConnState::Standby {
                    let tid = next_tid;
                    next_tid += 1;
                    sent_a.push(tid);
                    c.send_message(msg(tid, 42, 5));
                }
                while let Some(e) = c.poll_event() {
                    if let Event::Message(m) = e {
                        got_a.push(m.header.tid);
                    }
                }
                if c.state() == ConnState::WaitSocket {
                    c.on_connected(t(now));
                }
            }
        }
        // final reliable drain
        for _ in 0..20 {
            now += 1;
            exchange(&mut c, &mut s, t(now), &mut rng, 4096);
            collect(&mut c, &mut s, &mut got_a, &mut got_b);
            if c.state() == ConnState::Backoff {
                now = c.next_timer().unwrap().as_millis() as u64;
                c.on_timer(t(now));
            }
            if c.state() == ConnState::WaitSocket {
                c.on_connected(t(now));
            }
        }
        assert_eq!(got_b, sent_a, "seed {seed}: A->B");
        assert_eq!(got_a, sent_b, "seed {seed}: B->A");
    }
}

#[test]
fn large_message_output_chunks_share_the_payload() {
    let (mut a, mut b) = cluster_pair();
    let mut rng = Rng(7);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 1 << 20);
    let _ = (events(&mut c), events(&mut s));
    let data = bytes::Bytes::from(vec![0x5a; 200_000]);
    c.send_message(Message {
        msg_type: 42,
        tid: 1,
        version: 1,
        data: data.clone(),
        ..Default::default()
    });
    let runs = c.poll_output_chunks();
    assert!(
        runs.iter()
            .any(|r| r.as_ptr() == data.as_ptr() && r.len() == data.len()),
        "payload run is the caller's buffer"
    );
    let flat: Vec<u8> = runs.concat();
    for p in flat.chunks(1000) {
        s.on_bytes(p, t(2));
    }
    let ev = events(&mut s);
    let got = msgs(&ev);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].data, data);
}

/// Cluster pair where the server's auth layer reports `auth` as the authenticated identity of the dialer
/// (claimed: osd.1 in HELLO and client_ident).
fn bound_pair(auth: Option<EntityName>) -> (Vec<Event>, Vec<Event>) {
    bound_pair_from(OSD, auth)
}

/// [`bound_pair`] with a dialer of entity type `dialer` (what its HELLO claims).
fn bound_pair_from(dialer: u8, auth: Option<EntityName>) -> (Vec<Event>, Vec<Event>) {
    let (mut a, b) = cluster_pair();
    let mut b = b;
    if dialer != OSD {
        a = Node::new(dialer, 1, 1, PolicyTable::osd_cluster());
    }
    let kc = KeyedClient {
        key: vec![7; 16],
        secret: vec![],
        modes: vec![MODE_CRC],
        method: AUTH_METHOD_CEPHX,
    };
    let ks = KeyedServer {
        peer_name: auth,
        key: vec![7; 16],
        secret: vec![],
        rounds: 0,
        done: 0,
        methods: vec![AUTH_METHOD_CEPHX],
        modes: vec![MODE_CRC],
    };
    let mut c = a.dial_with(&b, Box::new(kc), t(0));
    let mut s = b.accept_with(1, Box::new(ks), t(0));
    exchange(&mut c, &mut s, t(1), &mut Rng(3), 100);
    (events(&mut c), events(&mut s))
}

#[test]
fn authenticated_osd_id_must_match_claimed_gid() {
    // ticket says osd.9, peer claims osd.1 (e.g. a client/OSD with a valid key posing as another OSD)
    let (ec, es) = bound_pair(Some(EntityName::osd(9)));
    assert!(
        connected(&es).is_none() && connected(&ec).is_none(),
        "{es:?}"
    );
    assert!(es.iter().any(
        |e| matches!(e, Event::Fault(FaultReason::Protocol(m)) if m.contains("authenticated"))
    ));
}

#[test]
fn authenticated_entity_type_must_match_hello_type() {
    // ticket is a client, HELLO claims OSD
    let (ec, es) = bound_pair(Some(EntityName::new(CLI, 4096)));
    assert!(
        connected(&es).is_none() && connected(&ec).is_none(),
        "{es:?}"
    );
}

/// A rados client handle that runs inside a daemon (libcephsqlite in the mgr) says CLIENT in HELLO and authenticates with the
/// daemon's key (mgr.x): classic accepts it and the session identity is the authenticated name (mgr devicehealth DB on `.mgr`).
#[test]
fn client_hello_with_a_daemon_ticket_connects() {
    let mgr = EntityName::new(EntityName::MGR, 4285);
    let (ec, es) = bound_pair_from(CLI, Some(mgr));
    assert_eq!(
        connected(&es).expect("accepted").auth_name,
        Some(mgr),
        "{es:?}"
    );
    assert!(connected(&ec).is_some(), "{ec:?}");
    // the reverse stays refused: a daemon-type HELLO needs a ticket of that type
    let (ec, es) = bound_pair_from(EntityName::MGR, Some(EntityName::new(CLI, 4096)));
    assert!(
        connected(&es).is_none() && connected(&ec).is_none(),
        "{es:?}"
    );
}

#[test]
fn matching_authenticated_identity_connects() {
    let (_ec, es) = bound_pair(Some(EntityName::osd(1)));
    assert_eq!(connected(&es).unwrap().name, EntityName::osd(1));
}

#[test]
fn cluster_policy_keeps_queued_frames_across_a_session_reset() {
    // OSD cluster peers (`keep_owed`): the peer lost its session (fresh table), what we still owe it is replayed on the new
    // session instead of being dropped by the full reset; the spec behaviour stays available (test above)
    let (mut a, mut b) = cluster_pair();
    let mut rng = Rng(3);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 50);
    events(&mut c);
    c.on_closed(t(2));
    events(&mut c);
    let mut b2 = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut s2 = b2.accept(1, t(3));
    c.send_message(msg(2, 42, 10)); // queued while the link is down
    c.on_connected(t(3));
    exchange(&mut c, &mut s2, t(4), &mut rng, 9);
    let ec = events(&mut c);
    assert!(ec.contains(&Event::RemoteReset), "{ec:?}");
    let es = events(&mut s2);
    let m = msgs(&es);
    assert_eq!(
        m.iter().map(|m| m.header.tid).collect::<Vec<_>>(),
        vec![2],
        "the frame queued before the reset is delivered on the new session"
    );
    assert_eq!(m[0].header.seq, 1, "renumbered for the new session");
}

#[test]
fn simultaneous_dial_with_the_accept_in_another_session_table_loses_nothing() {
    // OSD A (one core) and OSD B (two cores = two session tables: its link core B1 dials A, the connection A dialed is accepted
    // on core B2). A wins the race (WAIT for B1); B1's frames queued meanwhile and A's frames must all arrive.
    for a_dials_first in [true, false] {
        let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
        let mut b1 = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
        let mut b2 = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
        let mut rng = Rng(77);
        let (mut a_c, mut b2_s, mut b1_c, mut a_s);
        if a_dials_first {
            a_c = a.dial(&b2, t(0)); // A -> B (lands on B's core 2)
            b2_s = b2.accept(1, t(0));
            b1_c = b1.dial(&a, t(0)); // B -> A (B's link core)
            a_s = a.accept(2, t(0));
        } else {
            b1_c = b1.dial(&a, t(0));
            a_s = a.accept(2, t(0));
            a_c = a.dial(&b2, t(0));
            b2_s = b2.accept(1, t(0));
        }
        a_c.send_message(msg(1, 42, 4));
        b1_c.send_message(msg(2, 43, 4));
        // handshakes proceed
        for step in 1..20u64 {
            let ts = t(step);
            exchange(&mut a_c, &mut b2_s, ts, &mut rng, 64);
            exchange(&mut b1_c, &mut a_s, ts, &mut rng, 64);
        }
        let mut got_a: Vec<u64> = Vec::new(); // what A received
        let mut got_b: Vec<u64> = Vec::new(); // what B (either core) received
        got_a.extend(msgs(&events(&mut a_s)).iter().map(|m| m.header.tid));
        got_a.extend(msgs(&events(&mut a_c)).iter().map(|m| m.header.tid));
        got_b.extend(msgs(&events(&mut b2_s)).iter().map(|m| m.header.tid));
        got_b.extend(msgs(&events(&mut b1_c)).iter().map(|m| m.header.tid));
        // B1's dial was told to WAIT (A wins): after the short wait it redials and is adopted
        let mut later = 20u64;
        for _ in 0..40 {
            later += 400; // ms: past a 300 ms wait backoff
            let ts = t(later);
            b1_c.on_timer(ts);
            for e in events(&mut b1_c) {
                if let Event::Dial { .. } = e {
                    b1_c.on_connected(ts);
                }
            }
            exchange(&mut b1_c, &mut a_s, ts, &mut rng, 64);
            got_a.extend(msgs(&events(&mut a_s)).iter().map(|m| m.header.tid));
            got_b.extend(msgs(&events(&mut b1_c)).iter().map(|m| m.header.tid));
        }
        assert!(
            got_a.contains(&2),
            "B1's frame reached A: {got_a:?} (a_first={a_dials_first})"
        );
        assert!(
            got_b.contains(&1),
            "A's frame reached B: {got_b:?} (a_first={a_dials_first})"
        );
    }
}

#[test]
fn keep_owed_is_limited_to_the_listed_peers_and_never_replays_sent_frames() {
    // peer 2 not in the allow-list (classic peer): spec 10.3, the queued frame is dropped by the reset
    let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    a.table.set_keep_owed_peers(Default::default());
    let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut rng = Rng(3);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 50);
    events(&mut c);
    c.on_closed(t(2));
    events(&mut c);
    let mut b2 = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut s2 = b2.accept(1, t(3));
    c.send_message(msg(2, 42, 10));
    c.on_connected(t(3));
    exchange(&mut c, &mut s2, t(4), &mut rng, 9);
    assert!(
        msgs(&events(&mut s2)).is_empty(),
        "peer not listed: dropped as in spec 10.3"
    );
    // listed peer: frames never sent are kept, a frame that was sent (unacked) is NOT replayed after the reset
    let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    a.table.set_keep_owed_peers([2].into());
    let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 50);
    c.send_message(msg(1, 42, 10)); // goes out on the wire, but the link dies before it is acked
    let out = c.poll_output();
    drop(out);
    events(&mut c);
    c.on_closed(t(2));
    events(&mut c);
    let mut b2 = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut s2 = b2.accept(1, t(3));
    c.send_message(msg(2, 42, 10)); // never sent
    c.on_connected(t(3));
    exchange(&mut c, &mut s2, t(4), &mut rng, 9);
    let es = events(&mut s2);
    let got: Vec<u64> = msgs(&es).iter().map(|m| m.header.tid).collect();
    assert_eq!(
        got,
        vec![2],
        "never-sent frame delivered, sent-unacked frame not replayed"
    );
}

#[test]
fn pending_before_reconnect_are_flushed_into_the_resumed_session() {
    // A server-role connection may queue messages before it has a session (`send_message` on a link still in the
    // handshake): they wait in `pending`. A peer that resumes with SESSION_RECONNECT (not CLIENT_IDENT) must get them
    // too: they are the answer to requests of this very peer, and nothing else would ever send them.
    let (mut a, mut b) = cluster_pair();
    let mut rng = Rng(31);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 20);
    assert_eq!(msgs(&events(&mut s)).len(), 1);
    events(&mut c);
    c.on_closed(t(2));
    s.on_closed(t(2));
    events(&mut c);
    events(&mut s);
    // the peer resumes its session; the answer is queued before the reconnect arrived
    let mut s2 = b.accept(1, t(3));
    assert!(s2.send_message(msg(50, 43, 10)));
    c.send_message(msg(2, 42, 10));
    c.on_connected(t(3));
    exchange(&mut c, &mut s2, t(4), &mut rng, 9);
    let ec = events(&mut c);
    assert!(connected(&ec).is_some_and(|p| p.resumed), "{ec:?}");
    let got: Vec<u64> = msgs(&ec).iter().map(|m| m.header.tid).collect();
    assert_eq!(got, vec![50], "the queued answer is sent after READY");
}

#[test]
fn reconnect_of_another_osds_session_is_refused() {
    // osd.1 has a lossless session at B; an entity authenticated as osd.9 sends the SESSION_RECONNECT with osd.1's addrs and
    // cookies (visible in crc mode) and must not take it over
    let (mut a, mut b) = cluster_pair();
    let kc = || {
        Box::new(KeyedClient {
            key: vec![7; 16],
            secret: vec![],
            modes: vec![MODE_CRC],
            method: AUTH_METHOD_CEPHX,
        })
    };
    let ks = |who| {
        Box::new(KeyedServer {
            peer_name: Some(who),
            key: vec![7; 16],
            secret: vec![],
            rounds: 0,
            done: 0,
            methods: vec![AUTH_METHOD_CEPHX],
            modes: vec![MODE_CRC],
        })
    };
    let mut rng = Rng(3);
    let mut c = a.dial_with(&b, kc(), t(0));
    let mut s = b.accept_with(1, ks(EntityName::osd(1)), t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 100);
    assert!(connected(&events(&mut s)).is_some(), "osd.1 connects");
    c.on_closed(t(2));
    s.on_closed(t(2));
    events(&mut c);
    events(&mut s);
    // the reconnect arrives over a connection authenticated as osd.9
    c.send_message(msg(1, 42, 4));
    events(&mut c);
    c.on_connected(t(3));
    let mut s2 = b.accept_with(2, ks(EntityName::osd(9)), t(3));
    exchange(&mut c, &mut s2, t(4), &mut rng, 100);
    let es = events(&mut s2);
    assert!(connected(&es).is_none(), "{es:?}");
    assert!(
        es.iter().any(
            |e| matches!(e, Event::Fault(FaultReason::Protocol(m)) if m.contains("another entity"))
        ),
        "{es:?}"
    );
}

#[test]
fn client_ident_claiming_another_osds_addrs_is_refused() {
    // osd.1 has a lossless session at B; an entity authenticated as osd.9 sends CLIENT_IDENT with osd.1's addrvec: it must
    // neither supersede osd.1's session nor take its owed frames
    let (mut a, mut b) = cluster_pair();
    let kc = || {
        Box::new(KeyedClient {
            key: vec![7; 16],
            secret: vec![],
            modes: vec![MODE_CRC],
            method: AUTH_METHOD_CEPHX,
        })
    };
    let ks = |who| {
        Box::new(KeyedServer {
            peer_name: Some(who),
            key: vec![7; 16],
            secret: vec![],
            rounds: 0,
            done: 0,
            methods: vec![AUTH_METHOD_CEPHX],
            modes: vec![MODE_CRC],
        })
    };
    let mut rng = Rng(5);
    let mut c = a.dial_with(&b, kc(), t(0));
    let mut s = b.accept_with(1, ks(EntityName::osd(1)), t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 100);
    assert!(connected(&events(&mut s)).is_some(), "osd.1 connects");
    // osd.9 claims osd.1's addrvec (same ip, port, nonce)
    let mut x = Node::new(OSD, 9, 1, PolicyTable::osd_cluster());
    let mut cx = x.dial_with(&b, kc(), t(2));
    let mut sx = b.accept_with(2, ks(EntityName::osd(9)), t(2));
    exchange(&mut cx, &mut sx, t(3), &mut rng, 100);
    let es = events(&mut sx);
    assert!(connected(&es).is_none(), "{es:?}");
    assert!(
        es.iter().any(
            |e| matches!(e, Event::Fault(FaultReason::Protocol(m)) if m.contains("another entity"))
        ),
        "{es:?}"
    );
    // osd.1's carrier is untouched
    assert!(
        !events(&mut s)
            .iter()
            .any(|e| matches!(e, Event::Fault(_) | Event::Reset)),
        "osd.1's session was kicked"
    );
}

#[test]
fn pending_ack_piggybacks_after_application_dispatch_and_one_way_still_wakes() {
    let (mut a, mut b) = cluster_pair();
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut Rng(123), 4096);
    events(&mut c);
    events(&mut s);
    c.send_message(msg(1, 42, 128));
    s.on_bytes(&c.poll_output(), t(2));
    assert_eq!(msgs(&events(&mut s)).len(), 1);
    assert!(s.has_output(), "unencoded ACK must count as pending output");
    // Registration after receive must also discover an ACK that has not yet been encoded.
    let q = OutputQueue::default();
    s.set_output_queue(&q, 20);
    assert_eq!(q.pop(), Some(20));
    s.send_message(msg(2, 42, 128));
    let reply = s.poll_output();
    let mut d = Decoder::new(Revision::V21);
    d.feed(&reply);
    let f = d.poll_owned().unwrap().unwrap();
    assert_eq!(f.tag, Tag::Message as u8);
    assert_eq!(
        msgr2::payload::MsgHeader2::from_bytes(&f.segs[0])
            .unwrap()
            .ack_seq,
        1
    );
    assert!(
        d.poll_owned().unwrap().is_none(),
        "standalone ACK preceded reply"
    );
    c.on_bytes(&reply, t(3));
    assert_eq!(a.table.info(&b.addrs).unwrap().unacked, 0);
    // No application response: output readiness alone must deliver the ACK.
    c.send_message(msg(3, 42, 128));
    while q.pop().is_some() {}
    s.on_bytes(&c.poll_output(), t(4));
    assert_eq!(q.pop(), Some(20), "an owed ACK alone wakes the transport");
    let ack = s.poll_output_chunks().concat();
    let mut d = Decoder::new(Revision::V21);
    d.feed(&ack);
    assert_eq!(d.poll_owned().unwrap().unwrap().tag, Tag::Ack as u8);
    assert!(d.poll_owned().unwrap().is_none());
    c.on_bytes(&ack, t(5));
    assert_eq!(a.table.info(&b.addrs).unwrap().unacked, 0);
    assert!(!s.has_output());
}

#[test]
fn secure_pending_ack_piggybacks_without_an_extra_gcm_region() {
    let (a, b, mut c, mut s) =
        secure_pair(vec![MODE_SECURE], vec![MODE_SECURE], &[9; 16], &[9; 16], 0);
    exchange(&mut c, &mut s, t(1), &mut Rng(123), 4096);
    events(&mut c);
    events(&mut s);
    c.send_message(msg(1, 42, 128));
    s.on_bytes(&c.poll_output(), t(2));
    assert_eq!(msgs(&events(&mut s)).len(), 1);
    let response = msg(2, 42, 128);
    let mut reference = Encoder::new(Revision::V21);
    let secret = ConnSecret::new(&(0..64u8).collect::<Vec<_>>()).unwrap();
    reference.set_secure(&secret, Role::Server).unwrap();
    let mut expected = Vec::new();
    reference
        .encode_message(
            &[0; 41],
            &response.front,
            &response.middle,
            &response.data,
            &mut expected,
        )
        .unwrap();
    s.send_message(response);
    let actual = s.poll_output();
    assert_eq!(
        actual.len(),
        expected.len(),
        "standalone secure ACK adds 96 bytes"
    );
    c.on_bytes(&actual, t(3));
    let received = events(&mut c);
    assert_eq!(msgs(&received).len(), 1);
    assert_eq!(msgs(&received)[0].header.ack_seq, 1);
    assert_eq!(a.table.info(&b.addrs).unwrap().unacked, 0);
}

/// A configured idle timeout meaning "never" (`ms_connection_idle_timeout` huge) must not overflow the deadline.
#[test]
fn huge_idle_timeout_never_overflows() {
    let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    a.cfg.idle_timeout = std::time::Duration::MAX;
    let mut rng = Rng(4);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 64);
    assert_eq!(c.state(), ConnState::Ready);
    assert_eq!(c.next_timer(), Some(std::time::Duration::MAX));
    c.on_timer(t(1_000_000));
    assert_eq!(c.state(), ConnState::Ready);
}

/// A message beyond the frame limits is refused when queued: it never takes a seq it cannot put on the wire.
#[test]
fn oversized_message_is_refused_at_queue_time() {
    let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    a.cfg.limits.max_segment = 4096;
    let mut rng = Rng(6);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 64);
    assert!(!c.send_message(msg(1, 42, 8192)));
    assert!(c.send_message(msg(2, 42, 100)));
    exchange(&mut c, &mut s, t(2), &mut rng, 64);
    let evs = events(&mut s);
    let got = msgs(&evs);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].header.tid, got[0].header.seq), (2, 1));
}

/// A message whose front rope is broken cannot be encoded: it is refused at queue time, never queued. Before, the send
/// pump kept it (with its seq) and replayed it on every lossless reconnect, so one bad message blocked the whole peer
/// link forever. The next message flows normally.
#[test]
fn unencodable_message_is_refused_at_queue_time_and_later_messages_flow() {
    let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut rng = Rng(23);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 64);
    let run = || bytes::Bytes::from_static(b"x");
    for zc in [
        vec![(65usize, run())],       // offset beyond the front
        vec![(1, run()), (0, run())], // offsets not ascending
    ] {
        let mut bad = msg(1, 42, 64);
        bad.front_zc = zc;
        assert!(!bad.fits(c.limits()), "refused by the frame check");
        assert!(!c.send_message(bad), "refused at queue time");
        assert_eq!(c.state(), ConnState::Ready, "the link stays up");
    }
    assert!(c.send_message(msg(2, 42, 100)));
    exchange(&mut c, &mut s, t(2), &mut rng, 64);
    let evs = events(&mut s);
    let got = msgs(&evs);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].header.tid, got[0].header.seq), (2, 1));
}

#[test]
fn mds_ident_name_is_rank_or_unranked_in_both_roles() {
    for num in [-1, 0, 7] {
        let mut a = Node::new(EntityName::MDS, -1, 1, PolicyTable::osd_cluster());
        let mut b = Node::new(EntityName::MDS, -1, 2, PolicyTable::osd_cluster());
        let mut c = a.dial(&b, t(0));
        let mut s = b.accept(1, t(0));
        let name = EntityName::new(EntityName::MDS, num);
        c.set_name(name);
        s.set_name(name);
        exchange(&mut c, &mut s, t(1), &mut Rng(17), 4096);
        assert_eq!(connected(&events(&mut c)).unwrap().name, name);
        assert_eq!(connected(&events(&mut s)).unwrap().name, name);
        // Rename a READY carrier without resetting its session or nonce.
        c.set_name(EntityName::new(EntityName::MDS, num + 1));
        assert!(c.send_message(msg(1, 42, 16)));
        exchange(&mut c, &mut s, t(2), &mut Rng(19), 4096);
        assert_eq!(msgs(&events(&mut s))[0].header.tid, 1);
    }
}

/// SERVER_IDENT can turn a locally lossy policy into a lossless session.
/// A replacement must freeze the old receive sequence before announcing it.
#[test]
fn negotiated_lossless_session_freezes_old_carrier_on_replacement() {
    for v20 in [false, true] {
        for mode in [MODE_CRC, MODE_SECURE] {
            let mut a = Node::new(CLI, 7, 1, PolicyTable::uniform(Policy::lossy_client(0)));
            let mut b = Node::new(OSD, 2, 2, PolicyTable::uniform(Policy::stateful_server(0)));
            a.cfg.v20_only = v20;
            b.cfg.v20_only = v20;
            let client_auth = || {
                Box::new(KeyedClient {
                    key: vec![7; 16],
                    secret: vec![9; 64],
                    modes: vec![mode],
                    method: AUTH_METHOD_CEPHX,
                })
            };
            let server_auth = || {
                Box::new(KeyedServer {
                    peer_name: Some(EntityName::client(7)),
                    key: vec![7; 16],
                    secret: vec![9; 64],
                    rounds: 0,
                    done: 0,
                    methods: vec![AUTH_METHOD_CEPHX],
                    modes: vec![mode],
                })
            };
            let mut c = a.dial_with(&b, client_auth(), t(0));
            let mut s = b.accept_with(1, server_auth(), t(0));
            exchange(&mut c, &mut s, t(1), &mut Rng(41), 4096);
            assert!(!connected(&events(&mut c)).unwrap().lossy);
            events(&mut s);
            let mut replacement = a.dial_with(&b, client_auth(), t(2));
            assert!(
                !c.owns_session(),
                "lossless receive sequence must be frozen"
            );
            assert!(replacement.owns_session());
            s.send_message(msg(1, 42, 10));
            c.on_bytes(&s.poll_output(), t(3));
            assert!(msgs(&events(&mut c)).is_empty());
            let mut accepted = b.accept_with(1, server_auth(), t(3));
            exchange(&mut replacement, &mut accepted, t(4), &mut Rng(42), 4096);
            let ev = events(&mut replacement);
            assert!(connected(&ev).unwrap().resumed);
            assert_eq!(
                msgs(&ev).iter().map(|m| m.header.tid).collect::<Vec<_>>(),
                [1]
            );
            accepted.send_message(msg(2, 42, 10));
            exchange(&mut replacement, &mut accepted, t(5), &mut Rng(43), 4096);
            let ev = events(&mut replacement);
            assert_eq!(
                msgs(&ev).iter().map(|m| m.header.tid).collect::<Vec<_>>(),
                [2]
            );
        }
    }
}

#[test]
fn failed_lossy_replacement_preserves_the_live_carrier() {
    for fatal in [false, true] {
        let mut a = Node::new(CLI, 7, 1, PolicyTable::uniform(Policy::lossy_client(0)));
        let mut b = Node::new(OSD, 2, 2, PolicyTable::uniform(Policy::stateless_server(0)));
        let mut c = a.dial(&b, t(0));
        let mut s = b.accept(1, t(0));
        exchange(&mut c, &mut s, t(1), &mut Rng(11), 4096);
        events(&mut c);
        events(&mut s);
        let mut replacement = a.dial(&b, t(2));
        assert!(c.owns_session());
        if fatal {
            replacement.on_bytes(b"invalid banner", t(3));
        } else {
            replacement.close();
        }
        assert!(
            c.owns_session(),
            "failed replacement must not delete the live session"
        );
        c.send_message(msg(1, 42, 10));
        exchange(&mut c, &mut s, t(4), &mut Rng(12), 4096);
        assert_eq!(msgs(&events(&mut s))[0].header.tid, 1);
    }
}

#[test]
fn marked_down_lossless_client_gets_full_reset_on_reconnect() {
    for (client_type, server_type) in [(CLI, EntityName::MDS), (CLI, OSD), (OSD, OSD)] {
        let mut a = Node::new(
            client_type,
            1,
            1,
            PolicyTable::uniform(Policy::lossless_client(0)),
        );
        let mut b = Node::new(
            server_type,
            2,
            2,
            PolicyTable::uniform(Policy::stateful_server(0)),
        );
        let mut rng = Rng(77);
        let mut c = a.dial(&b, t(0));
        let mut s = b.accept(1, t(0));
        exchange(&mut c, &mut s, t(1), &mut rng, 7);
        assert!(connected(&events(&mut c)).is_some());
        assert!(connected(&events(&mut s)).is_some());
        assert!(s.dispose_session());
        assert!(b.table.is_empty());
        c.on_closed(t(2));
        events(&mut c);
        c.on_connected(t(3));
        let mut s2 = b.accept(1, t(3));
        exchange(&mut c, &mut s2, t(4), &mut rng, 7);
        let ec = events(&mut c);
        assert!(ec.contains(&Event::RemoteReset), "{ec:?}");
        assert!(!connected(&ec).unwrap().resumed);
        assert!(!connected(&events(&mut s2)).unwrap().resumed);
    }
}
