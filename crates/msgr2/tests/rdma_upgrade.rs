// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! RDMA upgrade handshake (spec 18): offer / accept / decline after auth, before the session frames. The byte
//! stream continues unchanged across the switch, so the in-memory pipe stands in for both transports.
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::*;

const OSD: u8 = EntityName::OSD;

fn node(num: i64, ip: u8, rdma: bool) -> Node {
    let mut n = Node::new(OSD, num, ip, PolicyTable::osd_cluster());
    n.cfg.rdma = rdma;
    n
}

fn rdma_events(evs: &[Event]) -> Vec<&Event> {
    evs.iter()
        .filter(|e| {
            matches!(
                e,
                Event::RdmaPrepare | Event::RdmaOffer { .. } | Event::RdmaAnswer { .. }
            )
        })
        .collect()
}

/// Run the handshake until the client asks for a QP.
fn to_prepare(c: &mut Connection, s: &mut Connection, rng: &mut Rng) {
    exchange(c, s, t(1), rng, 50);
    assert_eq!(rdma_events(&events(c)), [&Event::RdmaPrepare]);
    assert!(rdma_events(&events(s)).is_empty());
}

fn deliver_both_ways(c: &mut Connection, s: &mut Connection, rng: &mut Rng) -> Vec<Event> {
    c.send_message(msg(1, 42, 300));
    s.send_message(msg(2, 43, 300));
    exchange(c, s, t(5), rng, 1000);
    let (ec, es) = (events(c), events(s));
    assert!(connected(&ec).is_some() && connected(&es).is_some());
    assert_eq!(
        msgs(&es).iter().map(|m| m.header.tid).collect::<Vec<_>>(),
        [1]
    );
    assert_eq!(
        msgs(&ec).iter().map(|m| m.header.tid).collect::<Vec<_>>(),
        [2]
    );
    ec
}

#[test]
fn accepted_upgrade_continues_the_session_on_the_new_transport() {
    let (mut a, mut b) = (node(1, 1, true), node(2, 2, true));
    let mut rng = Rng(3);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    to_prepare(&mut c, &mut s, &mut rng);
    c.rdma_offer(Some(vec![0xC; 32]), t(2));
    exchange(&mut c, &mut s, t(2), &mut rng, 50);
    assert_eq!(
        rdma_events(&events(&mut s)),
        [&Event::RdmaOffer {
            endpoint: vec![0xC; 32]
        }]
    );
    s.rdma_answer(Some(vec![0x5; 32]), t(3));
    exchange(&mut c, &mut s, t(3), &mut rng, 50);
    assert_eq!(
        rdma_events(&events(&mut c)),
        [&Event::RdmaAnswer {
            endpoint: Some(vec![0x5; 32])
        }]
    );
    assert_eq!(c.state(), ConnState::Connecting);
    c.rdma_ready(t(4));
    let _ = deliver_both_ways(&mut c, &mut s, &mut rng);
}

#[test]
fn declined_upgrade_stays_on_tcp() {
    let (mut a, mut b) = (node(1, 1, true), node(2, 2, true));
    let mut rng = Rng(4);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    to_prepare(&mut c, &mut s, &mut rng);
    c.rdma_offer(Some(vec![1; 32]), t(2));
    exchange(&mut c, &mut s, t(2), &mut rng, 50);
    events(&mut s);
    s.rdma_answer(None, t(3));
    let ec = deliver_both_ways(&mut c, &mut s, &mut rng);
    assert!(rdma_events(&ec).contains(&&Event::RdmaAnswer { endpoint: None }));
}

#[test]
fn client_without_a_qp_sends_no_offer() {
    let (mut a, mut b) = (node(1, 1, true), node(2, 2, true));
    let mut rng = Rng(5);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    to_prepare(&mut c, &mut s, &mut rng);
    c.rdma_offer(None, t(2));
    let _ = deliver_both_ways(&mut c, &mut s, &mut rng);
}

/// A classic peer (or croit-flashstore-osd without RDMA) never sees the frame; neither side raises an RDMA event.
#[test]
fn one_sided_feature_is_plain_msgr2() {
    for (ca, cb) in [(true, false), (false, true), (false, false)] {
        let (mut a, mut b) = (node(1, 1, ca), node(2, 2, cb));
        let mut rng = Rng(6);
        let mut c = a.dial(&b, t(0));
        let mut s = b.accept(1, t(0));
        c.send_message(msg(1, 42, 10));
        exchange(&mut c, &mut s, t(1), &mut rng, 50);
        let (ec, es) = (events(&mut c), events(&mut s));
        assert!(rdma_events(&ec).is_empty() && rdma_events(&es).is_empty());
        assert!(connected(&ec).is_some());
        assert_eq!(msgs(&es).len(), 1);
    }
}

/// A connection that will be handed to another core keeps its socket on the landing core: declined, no event.
#[test]
fn connection_for_another_core_is_declined() {
    let mut a = node(1, 1, true);
    let mut b0 = node(2, 2, true);
    b0.cfg.home = Home::new(0, 2); // osd.1 is owned by core 1
    let mut rng = Rng(7);
    let mut c = a.dial(&b0, t(0));
    let mut s = b0.accept(1, t(0));
    to_prepare(&mut c, &mut s, &mut rng);
    c.rdma_offer(Some(vec![1; 32]), t(2));
    exchange(&mut c, &mut s, t(2), &mut rng, 50);
    assert!(rdma_events(&events(&mut c)).contains(&&Event::RdmaAnswer { endpoint: None }));
    let es = events(&mut s);
    assert!(rdma_events(&es).is_empty());
    assert!(matches!(
        es.last(),
        Some(Event::Handoff { osd: 1, owner: 1 })
    ));
}

/// One upgrade per stream: a second offer is a protocol fault.
#[test]
fn second_offer_on_one_stream_faults() {
    let (mut a, mut b) = (node(1, 1, true), node(2, 2, true));
    let mut rng = Rng(8);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    to_prepare(&mut c, &mut s, &mut rng);
    c.rdma_offer(Some(vec![1; 32]), t(2));
    let offer = c.poll_output();
    feed(&mut s, &offer, t(2), &mut rng, 50);
    events(&mut s);
    s.rdma_answer(Some(vec![2; 32]), t(2));
    s.poll_output();
    let mut again = Vec::new();
    let mut e = Encoder::new(Revision::V21);
    e.encode_control(
        Tag::RdmaUpgrade as u8,
        &payload::RdmaUpgrade {
            op: payload::RDMA_OFFER,
            endpoint: vec![1; 32],
        }
        .to_bytes()
        .unwrap(),
        &mut again,
    )
    .unwrap();
    s.on_bytes(&again, t(3));
    assert!(
        events(&mut s)
            .iter()
            .any(|e| matches!(e, Event::Fault(FaultReason::Protocol(_))))
    );
}

/// Trailing bytes behind the offer cannot be split between the two transports.
#[test]
fn bytes_behind_the_offer_fault() {
    let (mut a, mut b) = (node(1, 1, true), node(2, 2, true));
    let mut rng = Rng(9);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    to_prepare(&mut c, &mut s, &mut rng);
    c.rdma_offer(Some(vec![1; 32]), t(2));
    let mut out = c.poll_output();
    out.extend_from_slice(&out.clone());
    s.on_bytes(&out, t(2));
    assert!(
        events(&mut s)
            .iter()
            .any(|e| matches!(e, Event::Fault(FaultReason::Protocol(_))))
    );
}

/// A new stream (reconnect) offers again.
#[test]
fn reconnect_offers_again() {
    let (mut a, mut b) = (node(1, 1, true), node(2, 2, true));
    let mut rng = Rng(10);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    to_prepare(&mut c, &mut s, &mut rng);
    c.rdma_offer(None, t(2));
    let _ = deliver_both_ways(&mut c, &mut s, &mut rng);
    c.on_closed(t(10));
    s.on_closed(t(10));
    events(&mut c);
    c.send_message(msg(3, 42, 10));
    c.on_timer(t(10_000));
    assert!(
        events(&mut c)
            .iter()
            .any(|e| matches!(e, Event::Dial { .. }))
    );
    c.on_connected(t(10_001));
    let mut s = b.accept(1, t(10_001));
    exchange(&mut c, &mut s, t(10_002), &mut rng, 50);
    assert_eq!(rdma_events(&events(&mut c)), [&Event::RdmaPrepare]);
}

/// The optional placement bit is useful only after both peers actually switch to a QP.
#[test]
fn placement_requires_two_banners_and_an_active_ready_qp() {
    for (client_placement, server_placement, accept) in [
        (true, true, true),
        (true, false, true),
        (false, true, true),
        (true, true, false),
    ] {
        let (mut a, mut b) = (node(1, 1, true), node(2, 2, true));
        a.cfg.placement = client_placement;
        b.cfg.placement = server_placement;
        let mut rng = Rng(42);
        let mut c = a.dial(&b, t(0));
        let mut s = b.accept(1, t(0));
        to_prepare(&mut c, &mut s, &mut rng);
        assert!(!c.placement_ready());
        assert!(!s.placement_ready());
        c.rdma_offer(Some(vec![1; 32]), t(2));
        exchange(&mut c, &mut s, t(2), &mut rng, 50);
        events(&mut s);
        s.rdma_answer(accept.then(|| vec![2; 32]), t(3));
        exchange(&mut c, &mut s, t(3), &mut rng, 50);
        if accept {
            events(&mut c);
            assert!(!c.placement_ready(), "QP is not ready yet");
            c.rdma_ready(t(4));
        }
        let _ = deliver_both_ways(&mut c, &mut s, &mut rng);
        let expected = client_placement && server_placement && accept;
        assert_eq!(c.placement_ready(), expected);
        assert_eq!(s.placement_ready(), expected);
        c.on_closed(t(10));
        s.on_closed(t(10));
        assert!(!c.placement_ready(), "fault retires stream state");
        assert!(!s.placement_ready(), "fault retires stream state");
    }
}

#[test]
fn source_pull_requires_both_banners_and_ready_rdma() {
    for (client, server, accept) in [
        (true, true, true),
        (true, false, true),
        (false, true, true),
        (false, false, true),
        (true, true, false),
    ] {
        let (mut a, mut b) = (node(1, 1, true), node(2, 2, true));
        a.cfg.source_pull = client;
        b.cfg.source_pull = server;
        let mut rng = Rng(42);
        let mut c = a.dial(&b, t(0));
        let mut s = b.accept(1, t(0));
        to_prepare(&mut c, &mut s, &mut rng);
        assert!(!c.source_pull_capable() && !s.source_pull_capable());
        c.rdma_offer(Some(vec![1; 32]), t(2));
        exchange(&mut c, &mut s, t(2), &mut rng, 50);
        events(&mut s);
        s.rdma_answer(accept.then(|| vec![2; 32]), t(3));
        exchange(&mut c, &mut s, t(3), &mut rng, 50);
        if accept {
            events(&mut c);
            assert!(!c.source_pull_capable());
            c.rdma_ready(t(4));
        }
        let _ = deliver_both_ways(&mut c, &mut s, &mut rng);
        let expected = client && server && accept;
        assert_eq!(c.source_pull_capable(), expected);
        assert_eq!(s.source_pull_capable(), expected);
        c.on_closed(t(10));
        s.on_closed(t(10));
        assert!(!c.source_pull_capable() && !s.source_pull_capable());
    }
}

#[test]
fn placement_config_without_rdma_does_not_advertise_or_upgrade() {
    let (mut a, mut b) = (node(1, 1, false), node(2, 2, true));
    a.cfg.placement = true;
    b.cfg.placement = true;
    a.cfg.source_pull = true;
    b.cfg.source_pull = true;
    let mut rng = Rng(43);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    let _ = deliver_both_ways(&mut c, &mut s, &mut rng);
    assert!(!c.placement_ready());
    assert!(!s.placement_ready());
    assert!(!c.source_pull_capable());
    assert!(!s.source_pull_capable());
}

fn placement_record(kind: u8) -> [u8; 28] {
    let mut record = [0u8; 28];
    record[0] = 1;
    record[1] = kind;
    record[4..12].copy_from_slice(&7u64.to_le_bytes());
    record[12..20].copy_from_slice(&11u64.to_le_bytes());
    record[20..24].copy_from_slice(&2u32.to_le_bytes());
    record[24..28].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    record
}

fn ready_placement_pair() -> (Connection, Connection, Rng) {
    let (mut a, mut b) = (node(1, 1, true), node(2, 2, true));
    a.cfg.placement = true;
    b.cfg.placement = true;
    let mut rng = Rng(44);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    to_prepare(&mut c, &mut s, &mut rng);
    c.rdma_offer(Some(vec![1; 32]), t(2));
    exchange(&mut c, &mut s, t(2), &mut rng, 50);
    events(&mut s);
    s.rdma_answer(Some(vec![2; 32]), t(3));
    exchange(&mut c, &mut s, t(3), &mut rng, 50);
    events(&mut c);
    c.rdma_ready(t(4));
    let _ = deliver_both_ways(&mut c, &mut s, &mut rng);
    assert!(c.placement_ready() && s.placement_ready());
    (c, s, rng)
}

#[test]
fn placement_control_is_directional_and_cannot_pass_pending_messages() {
    let (mut c, mut s, mut rng) = ready_placement_pair();
    let cancel = placement_record(3);
    let retired = placement_record(4);
    assert!(!c.send_placement_control(retired));
    assert!(!s.send_placement_control(cancel));
    c.send_message(msg(90, 42, 10));
    assert!(
        !c.send_placement_control(cancel),
        "request output precedes cancel"
    );
    exchange(&mut c, &mut s, t(5), &mut rng, 50);
    assert_eq!(msgs(&events(&mut s)).len(), 1);
    assert!(c.send_placement_control(cancel));
    exchange(&mut c, &mut s, t(6), &mut rng, 50);
    assert!(
        events(&mut s)
            .iter()
            .any(|e| matches!(e, Event::PlacementControl(bytes) if bytes == &cancel))
    );
    assert!(s.send_placement_control(retired));
    exchange(&mut c, &mut s, t(7), &mut rng, 50);
    assert!(
        events(&mut c)
            .iter()
            .any(|e| matches!(e, Event::PlacementControl(bytes) if bytes == &retired))
    );
}

#[test]
fn retired_precedes_later_unencoded_server_messages() {
    let (mut client, mut server, mut rng) = ready_placement_pair();
    let retired = placement_record(4);
    assert!(server.placement_begin());
    assert!(server.send_message(msg(90, 42, 10)));
    assert!(server.send_placement_retired(retired));
    server.placement_end();
    exchange(&mut client, &mut server, t(8), &mut rng, 50);
    let received = events(&mut client);
    assert!(matches!(received.first(), Some(Event::PlacementControl(bytes)) if bytes == &retired));
    assert_eq!(msgs(&received).len(), 1);
}

#[test]
fn placed_reply_precedes_later_unencoded_server_messages() {
    let (mut client, mut server, mut rng) = ready_placement_pair();
    assert!(server.placement_begin());
    assert!(server.send_message(msg(90, 42, 10)));
    assert!(server.send_placement_reply(msg(91, 29, 10)));
    server.placement_end();
    exchange(&mut client, &mut server, t(8), &mut rng, 50);
    let received = events(&mut client);
    assert_eq!(
        msgs(&received)
            .iter()
            .map(|m| m.header.tid)
            .collect::<Vec<_>>(),
        [91, 90]
    );
}

#[test]
fn placement_hold_keeps_later_output_behind_the_terminal_reply() {
    let (mut client, mut server, mut rng) = ready_placement_pair();
    assert!(server.send_message(msg(80, 1, 10)));
    assert!(server.placement_begin());
    assert!(server.send_message(msg(90, 2, 10)));
    let prefix = server.poll_output_chunks().concat();
    client.on_bytes(&prefix, t(8));
    assert_eq!(
        msgs(&events(&mut client))
            .iter()
            .map(|m| m.header.tid)
            .collect::<Vec<_>>(),
        [80]
    );
    assert!(server.poll_output_chunks().is_empty());
    assert!(server.send_placement_reply(msg(91, 3, 10)));
    server.placement_end();
    exchange(&mut client, &mut server, t(9), &mut rng, 50);
    assert_eq!(
        msgs(&events(&mut client))
            .iter()
            .map(|m| m.header.tid)
            .collect::<Vec<_>>(),
        [91, 90]
    );
}

#[test]
fn placement_control_bad_direction_faults_the_ready_stream() {
    let (_c, mut s, _rng) = ready_placement_pair();
    let mut encoded = Vec::new();
    Encoder::new(Revision::V21)
        .encode_control(
            Tag::PlacementControl as u8,
            &placement_record(4),
            &mut encoded,
        )
        .unwrap();
    s.on_bytes(&encoded, t(8));
    assert!(events(&mut s).iter().any(|e| matches!(
        e,
        Event::Fault(FaultReason::Protocol("invalid placement control"))
    )));
    assert!(!s.placement_ready());
}

#[test]
fn placement_control_requires_negotiation_and_exact_shape() {
    let (mut c, mut s, mut rng) = ready_placement_pair();
    let mut invalid = placement_record(3);
    invalid[2] = 1;
    assert!(!c.send_placement_control(invalid));
    assert!(!c.has_output());
    let mut encoded = Vec::new();
    Encoder::new(Revision::V21)
        .encode_control(
            Tag::PlacementControl as u8,
            &placement_record(3)[..27],
            &mut encoded,
        )
        .unwrap();
    s.on_bytes(&encoded, t(8));
    assert!(events(&mut s).iter().any(|e| matches!(
        e,
        Event::Fault(FaultReason::Protocol("invalid placement control"))
    )));

    let (mut a, mut b) = (node(1, 1, true), node(2, 2, true));
    a.cfg.placement = true;
    b.cfg.placement = false;
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    to_prepare(&mut c, &mut s, &mut rng);
    c.rdma_offer(Some(vec![1; 32]), t(2));
    exchange(&mut c, &mut s, t(2), &mut rng, 50);
    events(&mut s);
    s.rdma_answer(Some(vec![2; 32]), t(3));
    exchange(&mut c, &mut s, t(3), &mut rng, 50);
    events(&mut c);
    c.rdma_ready(t(4));
    let _ = deliver_both_ways(&mut c, &mut s, &mut rng);
    assert!(!c.send_placement_control(placement_record(3)));
    let mut encoded = Vec::new();
    Encoder::new(Revision::V21)
        .encode_control(
            Tag::PlacementControl as u8,
            &placement_record(3),
            &mut encoded,
        )
        .unwrap();
    s.on_bytes(&encoded, t(8));
    assert!(events(&mut s).iter().any(|e| matches!(
        e,
        Event::Fault(FaultReason::Protocol("invalid placement control"))
    )));
}
