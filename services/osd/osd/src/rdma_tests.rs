// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! RDMA upgrade at the OSD seam (msgr2 spec 18): the OSD turns the messenger's upgrade events into `IoCmd::Rdma*` and takes
//! the transport's answers back; a transport without RDMA declines and the session goes on over TCP.
//! Child of `xcore_tests` (uses its multi-core harness and the placement helpers).
use super::placement::{Peer, accept_none, connected, in_seq, ping, relay};
use super::*;
use crate::auth::PeerAuth;
use crate::osd::{IoCmd, Link, MsgrId, Purpose};
use msgr2::auth::{AuthNoneClient, AuthNoneServer};
use msgr2::{Connection, Event, PolicyTable, SessionTable};

const ENDPOINT: [u8; 32] = [0xC; 32];

fn rdma_mc() -> Mc {
    let mut mc = Mc::new(1);
    mc.osds[0].msgr[MsgrId::Cluster as usize].cfg.rdma = true;
    mc
}

fn rdma_peer(mc: &Mc) -> Peer {
    let mut p = Peer::new(mc);
    p.cfg.rdma = true;
    p
}

/// Drain the driver queue; the RDMA commands (the mon session's dials and closes are not the subject here).
fn io(mc: &mut Mc) -> Vec<IoCmd> {
    std::iter::from_fn(|| mc.osds[0].poll_io())
        .filter(|c| !matches!(c, IoCmd::Dial { .. } | IoCmd::Close { .. }))
        .collect()
}

/// The peer dialled into the OSD, finished the handshake and offered a QP: the OSD's driver sees the accept command.
fn offered(mc: &mut Mc, peer: &mut Peer) -> (Connection, u64) {
    let mut c = peer.dial(mc.t);
    let l = accept_none(mc, 0, 40001);
    let evs = relay(mc, &mut c, 0, l);
    assert!(evs.contains(&Event::RdmaPrepare), "{evs:?}");
    assert!(c.rdma_offer(Some(ENDPOINT.to_vec()), mc.t));
    relay(mc, &mut c, 0, l);
    assert_eq!(
        io(mc),
        [IoCmd::RdmaAccept {
            conn: l,
            endpoint: ENDPOINT.to_vec()
        }]
    );
    (c, l)
}

#[test]
fn an_offer_reaches_the_driver_and_the_session_continues_after_the_accept() {
    let mut mc = rdma_mc();
    let mut peer = rdma_peer(&mc);
    let (mut c, l) = offered(&mut mc, &mut peer);
    assert!(mc.osds[0].rdma_accepted(l, Some(vec![0x5; 32]), mc.t));
    let evs = relay(&mut mc, &mut c, 0, l);
    assert!(
        evs.contains(&Event::RdmaAnswer {
            endpoint: Some(vec![0x5; 32])
        }),
        "{evs:?}"
    );
    // the stream goes on over the new transport (the test pipe stands in for both)
    assert!(c.rdma_ready(mc.t));
    c.send_message(ping(1));
    let evs = relay(&mut mc, &mut c, 0, l);
    assert!(connected(&evs).is_some(), "{evs:?}");
    assert_eq!(in_seq(&mc, 0, &peer), Some(1));
    // the answer was applied once
    assert!(!mc.osds[0].rdma_accepted(l, Some(vec![0x5; 32]), mc.t));
}

/// A transport without RDMA declines through `rdma_decline`: the peer sees the decline, TCP carries the session.
#[test]
fn a_declining_driver_leaves_a_working_tcp_session() {
    let mut mc = rdma_mc();
    let mut peer = rdma_peer(&mc);
    let (mut c, l) = offered(&mut mc, &mut peer);
    mc.osds[0].rdma_decline(
        IoCmd::RdmaAccept {
            conn: l,
            endpoint: ENDPOINT.to_vec(),
        },
        mc.t,
    );
    c.send_message(ping(1));
    let evs = relay(&mut mc, &mut c, 0, l);
    assert!(
        evs.contains(&Event::RdmaAnswer { endpoint: None }),
        "{evs:?}"
    );
    assert!(connected(&evs).is_some(), "{evs:?}");
    assert_eq!(in_seq(&mc, 0, &peer), Some(1));
    assert!(io(&mut mc).is_empty(), "nothing left for the driver");
}

/// `false` = the connection moved on while the transport prepared the QP: surfaced so the transport releases it.
#[test]
fn an_answer_for_a_connection_that_moved_on_returns_false() {
    let mut mc = rdma_mc();
    let mut peer = rdma_peer(&mc);
    let (_c, l) = offered(&mut mc, &mut peer);
    mc.osds[0].on_closed(l, mc.t);
    mc.settle();
    assert!(!mc.osds[0].rdma_accepted(l, Some(vec![1; 32]), mc.t));
    assert!(!mc.osds[0].rdma_accepted(l + 1000, None, mc.t), "unknown");
    assert!(!mc.osds[0].rdma_prepared(l, None, mc.t));
    assert!(!mc.osds[0].rdma_connected(l, mc.t));
}

/// RDMA off (the default): the feature bit is not advertised, no upgrade starts, the driver sees no command.
#[test]
fn messengers_without_rdma_raise_no_rdma_commands() {
    let mut mc = Mc::new(1); // `OsdConfig::rdma` off
    let mut peer = rdma_peer(&mc);
    let mut c = peer.dial(mc.t);
    let l = accept_none(&mut mc, 0, 40001);
    let evs = relay(&mut mc, &mut c, 0, l);
    assert!(!evs.contains(&Event::RdmaPrepare), "{evs:?}");
    assert!(connected(&evs).is_some());
    assert!(io(&mut mc).is_empty());
}

/// Dial the peer from the OSD (client role) over an AuthNone link; returns the link id and the peer's server side.
fn dialled(mc: &mut Mc) -> (u64, Connection) {
    let t = mc.t;
    let target = EntityAddrVec::single(EntityAddr::v4(
        EntityAddr::TYPE_MSGR2,
        556,
        [10, 1, 0, 9],
        6801,
    ));
    let o = &mut mc.osds[0];
    o.set_now(t);
    let id = o.alloc_link_id();
    let ms = &o.msgr[MsgrId::Cluster as usize];
    let mut conn = Connection::client(
        id,
        ms.cfg.clone(),
        ms.table.clone(),
        Box::new(AuthNoneClient {
            name: EntityName::osd(0),
            global_id: 0,
        }),
        EntityName::OSD,
        target.clone(),
        target.0[0],
    );
    conn.set_event_queue(&o.event_ready, id);
    conn.set_timer_queue(&o.timer_ready, id);
    o.conn_timers.get_mut().register(id);
    o.reserve_input_links();
    let caps_peer = opexec::caps::Peer::from_addr(&conn.target());
    o.links.insert(
        id,
        Link {
            pull: None,
            pending_input: None,
            held: Default::default(),
            conn,
            msgr: MsgrId::Cluster,
            purpose: Purpose::Peer(1),
            auth: Rc::new(RefCell::new(PeerAuth::default())),
            peer: None,
            sock: None,
            caps: None,
            caps_peer,
            info: None,
            fwd: 0,
            pre: None,
            placement: Default::default(),
            preauth_charged: 0,
        },
    );
    o.pump();
    mc.osds[0].on_connected(id, t);
    let mut cfg = msgr2::Config::new(EntityName::osd(1), target, PolicyTable::osd_cluster());
    cfg.rdma = true;
    let table = SessionTable::new(7);
    table.set_keep_owed_peers(Default::default());
    let srv = Connection::server(
        1,
        cfg,
        table,
        Box::new(AuthNoneServer::default()),
        EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [10, 1, 0, 4], 40002),
        t,
    );
    (id, srv)
}

/// Move bytes between the OSD's link and the test server until quiet; returns the server's events.
fn shuttle(mc: &mut Mc, l: u64, srv: &mut Connection) -> Vec<Event> {
    let mut evs = Vec::new();
    for _ in 0..500 {
        let t = mc.t;
        mc.settle();
        let out = mc.osds[0].poll_output(l);
        let back = srv.poll_output();
        if out.is_empty() && back.is_empty() {
            break;
        }
        srv.on_bytes(&out, t);
        if !back.is_empty() {
            mc.osds[0].on_bytes(l, &back, t);
        }
        while let Some(e) = srv.poll_event() {
            evs.push(e);
        }
    }
    evs
}

#[test]
fn the_client_role_maps_prepare_connect_and_release() {
    for decline in [false, true] {
        let mut mc = rdma_mc();
        let (l, mut srv) = dialled(&mut mc);
        shuttle(&mut mc, l, &mut srv);
        assert_eq!(io(&mut mc), [IoCmd::RdmaPrepare { conn: l }]);
        assert!(mc.osds[0].rdma_prepared(l, Some(ENDPOINT.to_vec()), mc.t));
        let evs = shuttle(&mut mc, l, &mut srv);
        assert!(
            evs.contains(&Event::RdmaOffer {
                endpoint: ENDPOINT.to_vec()
            }),
            "{evs:?}"
        );
        assert!(srv.rdma_answer((!decline).then(|| vec![0x5; 32]), mc.t));
        let mut done = shuttle(&mut mc, l, &mut srv);
        if decline {
            assert_eq!(io(&mut mc), [IoCmd::RdmaRelease { conn: l }]);
        } else {
            assert_eq!(
                io(&mut mc),
                [IoCmd::RdmaConnect {
                    conn: l,
                    endpoint: vec![0x5; 32]
                }]
            );
            assert!(mc.osds[0].rdma_connected(l, mc.t));
            assert!(!mc.osds[0].rdma_connected(l, mc.t), "applied once");
        }
        // either way the session handshake completes on the stream that continues
        done.extend(shuttle(&mut mc, l, &mut srv));
        assert!(connected(&done).is_some(), "decline={decline}: {done:?}");
    }
}
