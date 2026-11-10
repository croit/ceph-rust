// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Peer OSD connections landing on a core that does not own the peer's sessions (open question 15, pipe.rs), and
//! lossless cluster sessions across socket loss while the OSD holds input (OQ 28 O15).
//! Child of `xcore_tests` (uses its multi-core harness).
use super::*;
use crate::auth::PeerAuth;
use crate::osd::{IoCmd, Link, MsgrId, Purpose};
use bytes::Bytes;
use msgr2::auth::{AuthNoneClient, AuthNoneServer};
use msgr2::{Connection, Event, PolicyTable, SessionTable};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const PEER_IP: [u8; 4] = [10, 1, 0, 9];

#[test]
fn unhandled_op_middle_closes_the_classic_link() {
    let mut mc = Mc::new(1);
    mc.up();
    let mut peer = Peer::new(&mc);
    let mut client = peer.dial(mc.t);
    let link = accept_none(&mut mc, 0, 40040);
    relay(&mut mc, &mut client, 0, link);
    let op = mc.op(1, "placement-guard", vec![OsdOp::read(0, 4)]);
    let (msg_type, version, compat_version, segments) =
        opwire::ClientMsg::Op(op).encode(u64::MAX).unwrap();
    client.send_message(msgr2::Message {
        tid: 71,
        msg_type,
        version,
        compat_version,
        front: segments.front,
        middle: vec![1, 1, 0, 0],
        data: segments.data,
        ..Default::default()
    });
    mc.osds[0].on_bytes(link, &client.poll_output(), mc.t);
    mc.settle();
    assert!(!mc.osds[0].links.contains_key(&link));
    let mut closes = 0;
    while let Some(cmd) = mc.osds[0].poll_io() {
        if cmd == (IoCmd::Close { conn: link }) {
            closes += 1;
        }
    }
    assert_eq!(closes, 1);
}

/// Ceph faults the connection on a message it cannot decode (the client then sees a reset and its Objecter resends);
/// a silent drop leaves the op hanging on a healthy session.
#[test]
fn undecodable_op_faults_the_link_and_is_counted() {
    let mut mc = Mc::new(1);
    mc.up();
    let cl = mc.client(0);
    let op = mc.op(1, "undecodable", vec![OsdOp::read(0, 4)]);
    let (ty, ver, _, mut segs) = opwire::ClientMsg::Op(op).encode(u64::MAX).unwrap();
    assert_eq!(ty, opwire::consts::ty::OSD_OP);
    segs.front.truncate(4);
    mc.osds[0].on_unknown_message(cl, 72, ty, ver, &segs);
    mc.settle();
    assert!(!mc.osds[0].links.contains_key(&cl));
    let mut closes = 0;
    while let Some(cmd) = mc.osds[0].poll_io() {
        if cmd == (IoCmd::Close { conn: cl }) {
            closes += 1;
        }
    }
    assert_eq!(closes, 1);
    assert_eq!(
        mc.osds[0].pg.c.link_events.get("undecodable_client_op"),
        Some(&1)
    );
}

#[derive(Debug, Default)]
struct CountWake(std::sync::atomic::AtomicU32);
impl ingress::Waker for CountWake {
    fn wake(&self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A core that holds input for lack of ingress space is woken by whoever frees it (no sleep cap to wait out).
#[test]
fn releasing_ingress_space_wakes_the_core_that_waits_for_it() {
    let mut mc = Mc::new(2);
    mc.up();
    let w = std::sync::Arc::new(CountWake::default());
    mc.osds[0].set_core_waker(w.clone());
    let credits = mc.osds[0].cl.ingress.clone();
    let held: Vec<_> = (0..128)
        .map(|_| credits.reserve(0, 4096).unwrap())
        .collect();
    assert!(!mc.osds[0].input_room(&credits, 0, 4096, true));
    assert_eq!(w.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(held); // another core's lease drop
    assert_eq!(w.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(mc.osds[0].input_room(&credits, 0, 4096, true));
}

/// Accept a cluster-messenger connection on `core` the way `Osd::on_accept` does, but with the unauthenticated
/// (AuthNone) handshake so a test peer can complete it.
pub(super) fn accept_none(mc: &mut Mc, core: usize, port: u16) -> u64 {
    let t = mc.t;
    let o = &mut mc.osds[core];
    o.set_now(t);
    let id = o.alloc_link_id();
    let ms = &o.msgr[MsgrId::Cluster as usize];
    let mut conn = Connection::server(
        id,
        ms.cfg.clone(),
        ms.table.clone(),
        Box::new(AuthNoneServer::default()),
        EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, PEER_IP, port),
        t,
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
            purpose: Purpose::Accepted,
            auth: Rc::new(RefCell::new(PeerAuth::default())),
            peer: None,
            sock: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(PEER_IP)), port)),
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
    id
}

/// The classic peer osd.1 (its own session table; unsent frames are dropped by a reset, as classic does).
pub(super) struct Peer {
    pub(super) cfg: msgr2::Config,
    pub(super) table: SessionTable,
    pub(super) target: EntityAddrVec,
    next: u64,
}

impl Peer {
    pub(super) fn new(mc: &Mc) -> Peer {
        let addrs = addr(PEER_IP, 6801, 556);
        let table = SessionTable::new(99);
        table.set_keep_owed_peers(Default::default());
        Peer {
            cfg: msgr2::Config::new(EntityName::osd(1), addrs, PolicyTable::osd_cluster()),
            table,
            target: mc.osds[0].cluster_addrs.clone(),
            next: 100,
        }
    }

    pub(super) fn dial(&mut self, t: Duration) -> Connection {
        self.next += 1;
        let mut c = Connection::client(
            self.next,
            self.cfg.clone(),
            self.table.clone(),
            Box::new(AuthNoneClient {
                name: EntityName::osd(1),
                global_id: 0,
            }),
            EntityName::OSD,
            self.target.clone(),
            self.target.0[0],
        );
        while let Some(e) = c.poll_event() {
            assert!(matches!(e, Event::Dial { .. }));
        }
        c.on_connected(t);
        c
    }
}

pub(super) fn ping(tid: u64) -> msgr2::Message {
    msgr2::Message {
        msg_type: 2, // CEPH_MSG_PING: accepted and ignored on a cluster link
        tid,
        version: 1,
        ..Default::default()
    }
}

/// Move bytes between the peer and the OSD core that accepted its socket (`core`, `link` = the driver's id), moving
/// the cores' cross-core messages in between.
pub(super) fn relay(mc: &mut Mc, peer: &mut Connection, core: usize, link: u64) -> Vec<Event> {
    let mut evs = Vec::new();
    for _ in 0..500 {
        let mut moved = false;
        let t = mc.t;
        let out = peer.poll_output();
        if !out.is_empty() {
            // odd chunking on purpose: the handshake must survive being cut anywhere
            for c in out.chunks(37) {
                for _ in 0..500 {
                    if mc.osds[core].input_ready(link) {
                        break;
                    }
                    mc.settle();
                    mc.osds[core].resume_inputs(t);
                }
                assert!(mc.osds[core].input_ready(link), "relay receive timed out");
                mc.osds[core].on_bytes(link, c, t);
            }
            moved = true;
        }
        mc.settle();
        let out = mc.osds[core].poll_output(link);
        if !out.is_empty() {
            peer.on_bytes(&out, t);
            moved = true;
        }
        while let Some(e) = peer.poll_event() {
            evs.push(e);
        }
        if !moved {
            break;
        }
    }
    evs
}

pub(super) fn connected(evs: &[Event]) -> Option<&msgr2::PeerInfo> {
    evs.iter().find_map(|e| match e {
        Event::Connected(p) => Some(p),
        _ => None,
    })
}

pub(super) fn sess(mc: &Mc, core: usize) -> usize {
    mc.osds[core].msgr[MsgrId::Cluster as usize].table.len()
}

pub(super) fn in_seq(mc: &Mc, core: usize, p: &Peer) -> Option<u64> {
    mc.osds[core].msgr[MsgrId::Cluster as usize]
        .table
        .info(&p.cfg.addrs)
        .map(|i| i.in_seq)
}

#[test]
fn peer_reconnect_on_a_foreign_core_resumes_on_the_owner_core() {
    let mut mc = Mc::new(4);
    let owner = mc.osds[0].cl.spec.peer_core(1);
    assert_eq!(owner, 1);
    let mut peer = Peer::new(&mc);

    // first connection lands on the owner: no handoff
    let t = mc.t;
    let mut c = peer.dial(t);
    let l1 = accept_none(&mut mc, owner, 40001);
    c.send_message(ping(1));
    let evs = relay(&mut mc, &mut c, owner, l1);
    assert!(connected(&evs).is_some_and(|p| !p.resumed), "{evs:?}");
    assert_eq!((sess(&mc, owner), in_seq(&mc, owner, &peer)), (1, Some(1)));
    assert_eq!(mc.osds[owner].pipe_counts(), (0, 0));

    // its socket dies; frames queue up at the peer while the link is down
    c.on_closed(mc.t);
    mc.osds[owner].on_closed(l1, mc.t);
    mc.settle();
    while c.poll_event().is_some() {}
    c.send_message(ping(2));
    c.send_message(ping(3));

    // the reconnect lands on core 3
    let landing = 3;
    c.on_connected(mc.t);
    let l2 = accept_none(&mut mc, landing, 40002);
    let evs = relay(&mut mc, &mut c, landing, l2);
    assert!(
        !evs.contains(&Event::RemoteReset),
        "no session reset: {evs:?}"
    );
    assert!(connected(&evs).is_some_and(|p| p.resumed), "{evs:?}");
    assert_eq!(sess(&mc, landing), 0, "no session on the landing core");
    assert_eq!(sess(&mc, owner), 1);
    assert_eq!(
        in_seq(&mc, owner, &peer),
        Some(3),
        "the frames were delivered"
    );
    assert_eq!(mc.osds[landing].pipe_counts(), (1, 0));
    assert_eq!(mc.osds[owner].pipe_counts(), (0, 1));

    // established: traffic keeps flowing through the relay, both ways
    c.send_message(ping(4));
    relay(&mut mc, &mut c, landing, l2);
    assert_eq!(in_seq(&mc, owner, &peer), Some(4));
    assert_eq!(
        peer.table.info(&peer.target).map(|i| i.unacked),
        Some(0),
        "the owner's acks came back"
    );

    // the peer's socket closes: the owner's connection learns it, relay state is gone
    c.on_closed(mc.t);
    mc.osds[landing].on_closed(l2, mc.t);
    mc.settle();
    assert_eq!(mc.osds[owner].pipe_counts().1, 0);
    assert_eq!(mc.osds[landing].pipe_counts().0, 0);

    // and once more, on yet another core: the same session again
    while c.poll_event().is_some() {}
    c.send_message(ping(5));
    c.on_connected(mc.t);
    let l3 = accept_none(&mut mc, 2, 40003);
    let evs = relay(&mut mc, &mut c, 2, l3);
    assert!(connected(&evs).is_some_and(|p| p.resumed), "{evs:?}");
    assert!(!evs.contains(&Event::RemoteReset));
    assert_eq!(in_seq(&mc, owner, &peer), Some(5));
    assert_eq!(sess(&mc, 2) + sess(&mc, landing), 0);
}

#[test]
fn reserved_relay_control_reaches_the_actor_before_a_following_map_barrier() {
    let mut mc = Mc::new(2);
    mc.up();
    let (landing, owner) = (0, 1);
    let native = mc.client_as(owner, EntityName::osd(2));
    mc.osds[owner].links.get_mut(&native).unwrap().msgr = MsgrId::Cluster;
    let pgid = (0..32)
        .map(|seed| PgT::new(1, seed))
        .find(|pgid| mc.owner(1, pgid.seed) == owner)
        .unwrap();
    let spg = SpgT {
        pgid,
        shard: denc::types::ShardId::NO_SHARD,
    };
    let body = peering::Body::Peering(
        pgwire::MOSDPGNotify2 {
            spgid: spg,
            notify: pgwire::PgNotify {
                epoch_sent: mc.epoch + 1,
                query_epoch: mc.epoch + 1,
                info: pgwire::PgInfo::dne(spg),
                ..Default::default()
            },
        }
        .into(),
    );
    let (ty, version, compat_version, segments) = body.encode(u64::MAX).unwrap();
    let held = mc.osds[owner]
        .cl
        .control_ingress
        .reserve(0, 64 << 20)
        .unwrap();
    mc.osds[owner].on_unknown_message(native, 1, ty, version, &segments);
    assert!(!mc.osds[owner].input_ready(native));
    let mut peer = Peer::new(&mc);
    let mut client = peer.dial(mc.t);
    let zid = accept_none(&mut mc, landing, 40006);
    relay(&mut mc, &mut client, landing, zid);
    let hid = *mc.osds[owner].pipes.h.keys().next().unwrap();
    client.send_message(msgr2::Message {
        tid: 2,
        msg_type: ty,
        version,
        compat_version,
        front: segments.front,
        middle: segments.middle,
        data: segments.data,
        ..Default::default()
    });
    mc.osds[landing].on_bytes(zid, &client.poll_output(), mc.t);
    mc.settle();
    assert!(mc.osds[owner].links[&hid].pending_input.is_none());
    assert!(!mc.osds[owner].input_ready(native));
    assert!(mc.osds[owner].xmsg_ready(landing, &XMsg::MonSession));
    drop(held);
    mc.deliver(mc.map(mc.epoch + 1, 10));
    assert!(mc.osds[owner].links[&native].pending_input.is_none());
    assert!(mc.osds[owner].cl.control_ingress.idle());
}

#[test]
fn relay_reservation_pressure_retains_the_received_fragment_before_socket_close() {
    let mut mc = Mc::new(2);
    let mut peer = Peer::new(&mc);
    let mut client = peer.dial(mc.t);
    let (landing, owner) = (0, 1);
    let zid = accept_none(&mut mc, landing, 40007);
    relay(&mut mc, &mut client, landing, zid);
    client.send_message(ping(1));
    let wire = client.poll_output();
    assert!(wire.len() > 1 && wire.len() < 64 << 20);
    let credits = mc.osds[landing].pipes.z[&zid].input.clone();
    let held = credits.reserve(0, (64 << 20) - wire.len() + 1).unwrap();
    assert!(mc.osds[landing].input_ready(zid)); // a one-byte hint fits, but the received fragment does not
    mc.osds[landing].on_bytes(zid, &wire, mc.t);
    assert_eq!(
        mc.osds[landing].pipes.z[&zid]
            .pending_rx
            .as_ref()
            .unwrap()
            .as_ref(),
        wire
    );
    assert!(!mc.osds[landing].input_ready(zid));
    mc.osds[landing].on_closed(zid, mc.t);
    assert!(mc.osds[landing].pipes.z[&zid].socket_closed);
    drop(held);
    assert!(mc.osds[landing].resume_inputs(mc.t));
    mc.settle();
    assert_eq!(in_seq(&mc, owner, &peer), Some(1));
    assert_eq!(mc.osds[landing].pipe_counts(), (0, 0));
    assert_eq!(mc.osds[owner].pipe_counts(), (0, 0));
    assert!(credits.idle());
}

#[test]
fn retained_peer_head_precedes_the_next_decoded_frame_when_capacity_returns() {
    let mut mc = Mc::new(2);
    mc.up();
    let owner = 1;
    let mut peer = Peer::new(&mc);
    let mut client = peer.dial(mc.t);
    let link = accept_none(&mut mc, owner, 40008);
    relay(&mut mc, &mut client, owner, link);
    let spg = mc.op(1, "held-head", vec![]).pgid;
    let body = peering::Body::Peering(
        pgwire::MOSDPGNotify2 {
            spgid: spg,
            notify: pgwire::PgNotify {
                epoch_sent: mc.epoch + 1,
                query_epoch: mc.epoch + 1,
                info: pgwire::PgInfo::dne(spg),
                ..Default::default()
            },
        }
        .into(),
    );
    let (ty, version, compat_version, segments) = body.encode(u64::MAX).unwrap();
    let held = mc.osds[owner]
        .cl
        .control_ingress
        .reserve(0, 64 << 20)
        .unwrap();
    for tid in [71, 72] {
        client.send_message(msgr2::Message {
            tid,
            msg_type: ty,
            version,
            compat_version,
            front: segments.front.clone(),
            middle: segments.middle.clone(),
            data: segments.data.clone(),
            ..Default::default()
        });
    }
    mc.osds[owner].on_bytes(link, &client.poll_output(), mc.t);
    assert!(matches!(
        mc.osds[owner].links[&link].pending_input,
        Some(crate::osd::PendingInput::Peer { tid: 71, .. })
    ));
    assert!(mc.osds[owner].links[&link].conn.has_events());
    drop(held);
    // A store completion calls pump before the transport's next explicit resume pass.
    mc.osds[owner].pump();
    assert!(!mc.osds[owner].input_ready(link));
    assert!(matches!(
        mc.osds[owner].links[&link].pending_input,
        Some(crate::osd::PendingInput::Peer { tid: 71, .. })
    ));
    assert!(mc.osds[owner].links[&link].conn.has_events());
    assert!(mc.osds[owner].resume_inputs(mc.t));
    assert!(mc.osds[owner].links[&link].pending_input.is_none());
    assert!(!mc.osds[owner].links[&link].conn.has_events());
}

#[test]
fn held_relay_fragments_drain_in_order_before_socket_close() {
    let mut mc = Mc::new(2);
    let mut peer = Peer::new(&mc);
    let mut c = peer.dial(mc.t);
    let landing = 0;
    let owner = 1;
    let zid = accept_none(&mut mc, landing, 40009);
    relay(&mut mc, &mut c, landing, zid);
    let hid = *mc.osds[owner].pipes.h.keys().next().unwrap();
    c.send_message(ping(1));
    c.send_message(ping(2));
    let bytes = c.poll_output();
    assert!(bytes.len() > 2);
    let credits = ingress::IngressCredits::relay();
    // The first two fragments were held during actor backpressure. Neither completes a frame.
    for fragment in [&bytes[..1], &bytes[1..2]] {
        let guard = ingress::InputGuard(credits.reserve(0, fragment.len()));
        mc.osds[owner]
            .pipes
            .h
            .get_mut(&hid)
            .unwrap()
            .input
            .push_back((Bytes::copy_from_slice(fragment), guard));
    }
    let guard = ingress::InputGuard(credits.reserve(0, bytes.len() - 2));
    assert!(!mc.osds[owner].on_pipe_in(zid, Bytes::copy_from_slice(&bytes[2..]), guard));
    assert_eq!(mc.osds[owner].pipes.h[&hid].input.len(), 3);
    mc.osds[owner].on_pipe_closed(zid);
    assert!(mc.osds[owner].pipes.h[&hid].closed);
    mc.osds[owner].resume_pipe_input(hid);
    assert_eq!(in_seq(&mc, owner, &peer), Some(2));
    assert!(!mc.osds[owner].pipes.h.contains_key(&hid));
    assert!(credits.idle());
}

#[test]
fn the_owner_closing_closes_the_relayed_socket() {
    let mut mc = Mc::new(2);
    let mut peer = Peer::new(&mc);
    let mut c = peer.dial(mc.t);
    // osd.1 -> core 1 owns it; land on core 0
    let l = accept_none(&mut mc, 0, 40010);
    relay(&mut mc, &mut c, 0, l);
    assert_eq!(mc.osds[0].pipe_counts(), (1, 0));
    let hid = *mc.osds[1].pipes.h.keys().next().unwrap();
    mc.osds[1].close_link(hid);
    while mc.osds[1].poll_io().is_some() {} // the driver of the owner core: its Close becomes a PipeClose
    mc.settle();
    let mut closes = 0;
    while let Some(cmd) = mc.osds[0].poll_io() {
        if cmd == (IoCmd::Close { conn: l }) {
            closes += 1;
        }
    }
    assert_eq!(closes, 1, "the landing core closes the socket");
    // the driver collects the last output, then the relay is dropped
    let _ = mc.osds[0].poll_output(l);
    let _ = mc.osds[0].poll_io();
    assert_eq!(mc.osds[0].pipe_counts().0, 0);
    assert_eq!(mc.osds[1].pipe_counts().1, 0);
}

#[test]
fn the_cephx_result_moves_with_the_connection() {
    let mut mc = Mc::new(2);
    let mut peer = Peer::new(&mc);
    let mut c = peer.dial(mc.t);
    // osd.1 -> core 1 owns it; land on core 0 with what cephx would have recorded
    let l = accept_none(&mut mc, 0, 40020);
    *mc.osds[0].links[&l].auth.borrow_mut() = PeerAuth {
        caps: Some("allow *".into()),
        entity: "osd.1".into(),
    };
    c.send_message(ping(1));
    let evs = relay(&mut mc, &mut c, 0, l);
    assert!(connected(&evs).is_some(), "{evs:?}");
    let hid = *mc.osds[1].pipes.h.keys().next().unwrap();
    assert_eq!(
        mc.osds[1].link_auth(hid),
        Some((Some("allow *".into()), "osd.1".into())),
        "entity and caps of the resumed link"
    );
}

#[test]
fn single_core_osd_has_no_placement() {
    let mc = Mc::new(1);
    assert!(mc.osds[0].msgr[MsgrId::Cluster as usize].cfg.home.is_none());
}

/// Receive-path cost per wire chunk of one bulk connection through `Osd::on_bytes` (single 4 MiB stream, crc mode),
/// without and with 300 idle links on the core:
/// `cargo test --release -p osd --lib bench_rx_chunk -- --ignored --nocapture`.
#[test]
#[ignore = "bench"]
fn bench_rx_chunk() {
    use crate::osd::Listener;
    for idle in [0usize, 300] {
        let mut mc = Mc::new(1);
        let mut peer = Peer::new(&mc);
        let mut c = peer.dial(mc.t);
        let l = accept_none(&mut mc, 0, 40001);
        relay(&mut mc, &mut c, 0, l);
        for i in 0..idle {
            let t = mc.t;
            mc.osds[0].on_accept(
                Listener::Public,
                crate::osd::sock4([10, 9, 0, 1], 30000 + i as u16),
                t,
            );
        }
        for i in 0..32u64 {
            c.send_message(msgr2::Message {
                msg_type: 2,
                tid: i,
                version: 1,
                front: vec![1; 200],
                data: vec![7u8; 4 << 20].into(),
                ..Default::default()
            });
        }
        let wire = c.poll_output_chunks().concat();
        let t = mc.t;
        let mut chunks = 0u64;
        let t0 = std::time::Instant::now();
        for (i, ch) in wire.chunks(1448).enumerate() {
            mc.osds[0].on_bytes(l, ch, t);
            chunks += 1;
            if i % 64 == 63 {
                let _ = mc.osds[0].poll_output(l); // the acks
            }
        }
        let d = t0.elapsed();
        println!(
            "idle links {idle:4}: {chunks} chunks, {:.0} ns/chunk, {:.2} GB/s",
            d.as_nanos() as f64 / chunks as f64,
            wire.len() as f64 / d.as_secs_f64() / 1e9
        );
        // what the driver's `flush_out` costs per driven iteration (all connections, osd side only)
        let t0 = std::time::Instant::now();
        for _ in 0..2000 {
            for id in mc.osds[0].conn_ids() {
                let _ = mc.osds[0].poll_output_chunks(id);
            }
        }
        println!(
            "  flush scan of {} conns: {:.0} ns per iteration",
            mc.osds[0].conn_ids().len(),
            t0.elapsed().as_nanos() as f64 / 2000.0
        );
    }
}

#[test]
fn budgeted_relay_events_hold_ordered_controls_until_actor_acceptance() {
    let mut mc = Mc::new(2);
    let mut peer = Peer::new(&mc);
    let mut client = peer.dial(mc.t);
    let (landing, owner) = (0, 1);
    let zid = accept_none(&mut mc, landing, 40008);
    relay(&mut mc, &mut client, landing, zid);
    let hid = *mc.osds[owner].pipes.h.keys().next().unwrap();
    for tid in 1..=300 {
        client.send_message(ping(tid));
    }
    let wire = client.poll_output();
    mc.osds[owner]
        .links
        .get_mut(&hid)
        .unwrap()
        .conn
        .on_bytes(&wire, mc.t);
    assert!(mc.osds[owner].links[&hid].conn.has_events());
    assert!(!mc.osds[owner].xmsg_ready(landing, &XMsg::MonSession));
    mc.osds[owner].pump();
    assert!(mc.osds[owner].event_pump_pending);
    assert!(mc.osds[owner].links[&hid].conn.has_events());
    assert!(!mc.osds[owner].xmsg_ready(landing, &XMsg::MonSession));
    for _ in 0..1000 {
        if !mc.osds[owner].event_pump_pending {
            break;
        }
        mc.osds[owner].poll_store(mc.t);
    }
    assert!(!mc.osds[owner].links[&hid].conn.has_events());
    assert!(mc.osds[owner].xmsg_ready(landing, &XMsg::MonSession));
}

#[test]
fn yielded_relay_events_resume_raw_tail_and_eof_without_a_typed_pending_head() {
    for closed in [false, true] {
        let mut mc = Mc::new(2);
        let mut peer = Peer::new(&mc);
        let mut client = peer.dial(mc.t);
        let (landing, owner) = (0, 1);
        let zid = accept_none(&mut mc, landing, 40009 + u16::from(closed));
        relay(&mut mc, &mut client, landing, zid);
        let hid = *mc.osds[owner].pipes.h.keys().next().unwrap();
        for tid in 1..=300 {
            client.send_message(ping(tid));
        }
        let wire = client.poll_output();
        mc.osds[owner]
            .links
            .get_mut(&hid)
            .unwrap()
            .conn
            .on_bytes(&wire, mc.t);
        mc.osds[owner].pump();
        assert!(mc.osds[owner].event_pump_pending);
        assert!(!mc.osds[owner].input_ready(hid));
        assert!(mc.osds[owner].links[&hid].pending_input.is_none());
        client.send_message(ping(301));
        let tail = Bytes::from(client.poll_output());
        assert!(!mc.osds[owner].on_pipe_in(zid, tail, ingress::InputGuard::default()));
        assert_eq!(mc.osds[owner].pipes.h[&hid].input.len(), 1);
        assert!(!mc.osds[owner].xmsg_ready(landing, &XMsg::MonSession));
        if closed {
            mc.osds[owner].on_pipe_closed(zid);
            assert!(mc.osds[owner].pipes.h[&hid].closed);
        }
        for _ in 0..1000 {
            mc.osds[owner].poll_store(mc.t);
            if closed {
                if !mc.osds[owner].links.contains_key(&hid) {
                    break;
                }
            } else if in_seq(&mc, owner, &peer) == Some(301)
                && mc.osds[owner].pipes.h[&hid].input.is_empty()
                && !mc.osds[owner].links[&hid].conn.has_events()
            {
                break;
            }
        }
        assert_eq!(in_seq(&mc, owner, &peer), Some(301));
        if closed {
            assert!(!mc.osds[owner].links.contains_key(&hid));
            assert!(!mc.osds[owner].pipes.h_by_z.contains_key(&zid));
        } else {
            assert!(mc.osds[owner].input_ready(hid));
            assert!(mc.osds[owner].pipes.h[&hid].input.is_empty());
        }
        assert!(mc.osds[owner].xmsg_ready(landing, &XMsg::MonSession));
    }
}

/// A transport passes a relayed connection's whole receive batch as one fragment: a 2 MiB frame takes one of the 32
/// relay credits (adr 0084) instead of one per TCP segment, which closed the window long before the frame completed.
#[test]
fn relay_receive_batch_is_one_fragment_of_the_window() {
    let mut mc = Mc::new(2);
    let mut peer = Peer::new(&mc);
    let mut client = peer.dial(mc.t);
    let (landing, owner) = (0, 1);
    let zid = accept_none(&mut mc, landing, 40011);
    relay(&mut mc, &mut client, landing, zid);
    assert!(mc.osds[landing].is_relay(zid));
    assert!(!mc.osds[owner].is_relay(zid));
    let mut m = ping(1);
    m.front = vec![7; 2 << 20];
    client.send_message(m);
    let wire = client.poll_output();
    let credits = mc.osds[landing].pipes.z[&zid].input.clone();
    // segment-sized fragments: the window is exhausted after 32 of them
    let mut seg = 0;
    for c in wire.chunks(1448) {
        if !mc.osds[landing].input_ready(zid) {
            break;
        }
        mc.osds[landing].on_bytes(zid, c, mc.t);
        seg += 1;
    }
    assert_eq!(seg, 32);
    mc.settle();
    assert!(credits.idle());
    // the rest of the frame as one batch: one credit, the frame completes
    let rest = Bytes::copy_from_slice(&wire[32 * 1448..]);
    assert!(mc.osds[landing].input_ready(zid));
    mc.osds[landing].on_relay_bytes(zid, rest, mc.t);
    assert!(mc.osds[landing].input_ready(zid));
    mc.settle();
    assert_eq!(in_seq(&mc, owner, &peer), Some(1));
    assert!(credits.idle());
}

// ---- lossless cluster sessions with the OSD's input backpressure (OQ 28 O15, adr 0071 am. 2)

/// A peer message: the held head (a notify), or a sub-write of a replicated (`ec` false: MOSDRepOp) or EC
/// (MOSDECSubOpWrite) PG.
fn peer_msg(mc: &Mc, tid: u64, kind: u8, ec: bool) -> msgr2::Message {
    let spg = mc.op(1, "o15", vec![]).pgid;
    let e = mc.epoch;
    let txn: bytes::Bytes = replwire::Transaction::new().encode_v9().unwrap().into();
    let body = match kind {
        0 => peering::Body::Peering(
            pgwire::MOSDPGNotify2 {
                spgid: spg,
                notify: pgwire::PgNotify {
                    epoch_sent: e + 1,
                    query_epoch: e + 1,
                    info: pgwire::PgInfo::dne(spg),
                    ..Default::default()
                },
            }
            .into(),
        ),
        _ if ec => peering::Body::Ec(ecwire::EcMsg::Write(ecwire::MOSDECSubOpWrite {
            pgid: SpgT {
                pgid: spg.pgid,
                shard: denc::types::ShardId(1),
            },
            map_epoch: e,
            min_epoch: e,
            op: ecwire::ECSubWrite {
                tid,
                txn_data: txn,
                ..Default::default()
            },
            ..Default::default()
        })),
        _ => peering::Body::Repl(replwire::ReplMsg::RepOp(replwire::msgs::MOSDRepOp {
            map_epoch: e,
            min_epoch: e,
            pgid: spg,
            txn_data: txn,
            pg_stats: vec![1, 1, 0, 0, 0, 0].into(),
            ..Default::default()
        })),
    };
    let (msg_type, version, compat_version, s) = body.encode(u64::MAX).unwrap();
    msgr2::Message {
        tid,
        msg_type,
        version,
        compat_version,
        front: s.front,
        middle: s.middle,
        data: s.data,
        ..Default::default()
    }
}

/// The transport between the peer and link `link` of `core`: bytes go in only while the OSD takes input
/// (`input_ready`), the rest waits in `wait` (the socket buffer).
fn wire(mc: &mut Mc, peer: &mut Connection, core: usize, link: u64, wait: &mut Vec<u8>) {
    for _ in 0..500 {
        let t = mc.t;
        let mut moved = false;
        wait.extend(peer.poll_output());
        while !wait.is_empty()
            && mc.osds[core].links.contains_key(&link)
            && mc.osds[core].input_ready(link)
        {
            let n = wait.len().min(37);
            let chunk: Vec<u8> = wait.drain(..n).collect();
            mc.osds[core].on_bytes(link, &chunk, t);
            moved = true;
        }
        moved |= mc.osds[core].resume_inputs(t);
        mc.settle();
        let out = mc.osds[core].poll_output(link);
        if !out.is_empty() {
            peer.on_bytes(&out, t);
            moved = true;
        }
        while peer.poll_event().is_some() {}
        if !moved {
            return;
        }
    }
    panic!("wire did not settle");
}

/// A peer's cluster connection dies while the OSD holds its input (store / ingress backpressure): the OSD has decoded
/// tids 1..=3 (a held notify, two sub-writes queued behind it), counted them in the session's in_seq and acked them in
/// the reconnect, so the peer never sends them again. `known`: the OSD saw the socket close (faulted link, its events
/// still queued); else the peer's reconnect supersedes the link. The peer sends tid 4 on the new connection. Every
/// tid must reach the PG layer exactly once and in order: the new link takes over the old one's input.
fn reconnect_with_held_input(ec: bool, known: bool) {
    let mut mc = Mc::new(2);
    mc.up();
    let owner = mc.osds[0].cl.spec.peer_core(1);
    let mut peer = Peer::new(&mc);
    let mut c = peer.dial(mc.t);
    let l1 = accept_none(&mut mc, owner, 40020);
    relay(&mut mc, &mut c, owner, l1);
    let held = mc.osds[owner]
        .cl
        .control_ingress
        .reserve(0, 64 << 20)
        .unwrap();
    for (tid, kind) in [(1, 0), (2, 1), (3, 1)] {
        c.send_message(peer_msg(&mc, tid, kind, ec));
    }
    mc.osds[owner].on_bytes(l1, &c.poll_output(), mc.t);
    assert!(matches!(
        mc.osds[owner].links[&l1].pending_input,
        Some(crate::osd::PendingInput::Peer { tid: 1, .. })
    ));
    assert_eq!(in_seq(&mc, owner, &peer), Some(3));
    // the socket dies; the acks of 1..=3 never reached the peer
    if known {
        mc.osds[owner].on_closed(l1, mc.t);
        mc.settle();
    }
    c.on_closed(mc.t);
    while let Some(e) = c.poll_event() {
        assert!(matches!(e, Event::Fault(_) | Event::Dial { .. }), "{e:?}");
    }
    c.on_connected(mc.t);
    c.send_message(peer_msg(&mc, 4, 1, ec));
    let l2 = accept_none(&mut mc, owner, 40021);
    let mut wait = Vec::new();
    wire(&mut mc, &mut c, owner, l2, &mut wait);
    assert!(
        mc.osds[owner].t.peer_in.is_empty(),
        "all held: {:?}",
        mc.osds[owner].t.peer_in
    );
    drop(held);
    for _ in 0..10 {
        wire(&mut mc, &mut c, owner, l2, &mut wait);
    }
    assert_eq!(
        mc.osds[owner].t.peer_in,
        vec![1, 2, 3, 4],
        "ec {ec} known {known}"
    );
    assert_eq!(in_seq(&mc, owner, &peer), Some(4));
    assert!(
        !mc.osds[owner].links.contains_key(&l1),
        "the old link is gone"
    );
    assert_eq!(
        peer.table.info(&peer.target).map(|i| (i.unsent, i.unacked)),
        Some((0, 0)),
        "nothing resent"
    );
}

#[test]
fn rep_sub_writes_held_on_a_superseded_link_reach_the_pg_once_in_order() {
    reconnect_with_held_input(false, false);
}

#[test]
fn ec_sub_writes_held_on_a_superseded_link_reach_the_pg_once_in_order() {
    reconnect_with_held_input(true, false);
}

#[test]
fn rep_sub_writes_held_on_a_faulted_link_go_before_the_reconnect() {
    reconnect_with_held_input(false, true);
}

#[test]
fn ec_sub_writes_held_on_a_faulted_link_go_before_the_reconnect() {
    reconnect_with_held_input(true, true);
}

/// The OSD owes osd.1 a message on the connection osd.1 dialled when that socket dies: osd.1 (classic, nothing to send)
/// stays in standby, so the OSD dials back (spec 10.7 step 7) and the session resumes; before, the reply (a sub-write
/// ack, a push) waited for unrelated traffic.
#[test]
fn an_accepted_session_that_owes_the_peer_is_dialled_back() {
    let mut mc = Mc::new(2);
    mc.up();
    let peer_addrs = addr(PEER_IP, 6801, 556);
    let mut m = mc.map(mc.epoch + 1, 10);
    m.osd_state[1] |= osd_state::UP;
    m.cluster_addrs[1] = peer_addrs.clone();
    mc.deliver(m);
    let owner = mc.osds[0].cl.spec.peer_core(1);
    let mut peer = Peer::new(&mc);
    let mut c = peer.dial(mc.t);
    let l1 = accept_none(&mut mc, owner, 40030);
    relay(&mut mc, &mut c, owner, l1);
    while mc.osds[owner].poll_io().is_some() {}
    let l = mc.osds[owner].links.get_mut(&l1).unwrap();
    assert!(l.conn.send_message(ping(9)));
    mc.osds[owner].on_closed(l1, mc.t);
    c.on_closed(mc.t);
    mc.settle();
    while let Some(e) = c.poll_event() {
        assert!(
            !matches!(e, Event::Dial { .. }),
            "the idle peer does not redial"
        );
    }
    let mut dials = Vec::new();
    while let Some(cmd) = mc.osds[owner].poll_io() {
        if let IoCmd::Dial { conn, target, .. } = cmd {
            dials.push((conn, target));
        }
    }
    assert_eq!(dials.len(), 1, "{dials:?}");
    let (d, target) = dials[0];
    assert_eq!(target, peer_addrs.0[0]);
    assert_eq!(mc.osds[owner].pg.peers.get(&1).map(|p| p.link), Some(d));
    let info = mc.osds[owner].msgr[MsgrId::Cluster as usize]
        .table
        .info(&peer_addrs)
        .unwrap();
    assert_eq!(
        info.unsent + info.unacked,
        1,
        "the owed message waits for the dial"
    );
}

/// The classic peer osd.1 resumed its session on a connection this OSD accepted (msgr2 READY), but its `Connected` event
/// is not processed yet (`peer` unset, as during the 10 ms of lab case 23 between the handoff and the event). A PG frame
/// for osd.1 then goes on that carrier instead of a second dial: a dial takes the session over (spec 10.3) and closes the
/// carrier; before msgr2 stopped the old carrier, the stale msg_seq of that reconnect made classic renumber and one
/// MOSDRepOpReply was dropped as old (pg stuck below pg_committed_to).
#[test]
fn a_frame_for_a_peer_goes_on_its_session_carrier_before_connected_is_seen() {
    let mut mc = Mc::new(2);
    mc.up();
    let peer_addrs = addr(PEER_IP, 6801, 556);
    let mut m = mc.map(mc.epoch + 1, 10);
    m.osd_state[1] |= osd_state::UP;
    m.cluster_addrs[1] = peer_addrs.clone();
    mc.deliver(m);
    let owner = mc.osds[0].cl.spec.peer_core(1);
    let mut peer = Peer::new(&mc);
    let mut c = peer.dial(mc.t);
    let l1 = accept_none(&mut mc, owner, 40031);
    relay(&mut mc, &mut c, owner, l1);
    while mc.osds[owner].poll_io().is_some() {}
    mc.osds[owner].pg.peers.remove(&1);
    mc.osds[owner].links.get_mut(&l1).unwrap().peer = None;
    let up_from = mc.osds[owner].map.as_ref().unwrap().osd_info[1].up_from;
    mc.osds[owner].peer_transmit(
        Some((up_from, peer_addrs.clone())),
        crate::flow::Tx {
            to: 1,
            epoch: mc.epoch,
            tid: 9,
            prio: 0,
            hdr: (2, 1, 1),
            segs: Default::default(),
            data: Default::default(),
        },
    );
    let o = &mut mc.osds[owner];
    let dials: Vec<_> = std::iter::from_fn(|| o.poll_io())
        .filter(|c| matches!(c, IoCmd::Dial { .. }))
        .collect();
    assert!(
        dials.is_empty(),
        "second dial on a carried session: {dials:?}"
    );
    assert_eq!(o.pg.peers.get(&1).map(|p| p.link), Some(l1));
    assert_eq!(o.pg.c.link_events.get("tx_on_carrier").copied(), Some(1));
    relay(&mut mc, &mut c, owner, l1);
    let info = mc.osds[owner].msgr[MsgrId::Cluster as usize]
        .table
        .info(&peer_addrs)
        .unwrap();
    assert_eq!((info.active, info.unsent), (Some(l1), 0), "sent on l1");
}

/// Memory envelope G1 (doc/design/memory-envelope.md): links that wait at a message header for ingress space are retried
/// per pool. A client link parked on the full client pool (writes waiting for their replica acks) must not hold back a
/// peer link parked on the peer pool once that pool has space: the acks it carries are what frees the client pool. One
/// shared FIFO for both pools deadlocked a size-3 RDMA write load (rdma-lossy-20261021: peer pool empty with two
/// waiters, client pool full, every peer link of osd.0 parked behind a client link).
#[test]
fn a_full_client_pool_does_not_hold_back_a_peer_frame_once_the_peer_pool_has_space() {
    let mut mc = Mc::new(1);
    mc.up();
    let gates = mc.osds[0].cl.frame_gates.clone().expect("frame windows");
    // the client link (public messenger) and the peer link (cluster messenger), each with its pool's header gate
    let cp = Peer::new(&mc);
    let mut cc = Connection::client(
        201,
        msgr2::Config::new(
            EntityName::osd(2),
            addr(PEER_IP, 6802, 557),
            PolicyTable::osd_cluster(),
        ),
        SessionTable::new(98),
        Box::new(AuthNoneClient {
            name: EntityName::osd(2),
            global_id: 0,
        }),
        EntityName::OSD,
        cp.target.clone(),
        cp.target.0[0],
    );
    while cc.poll_event().is_some() {}
    cc.on_connected(mc.t);
    let lc = accept_none(&mut mc, 0, 40021);
    relay(&mut mc, &mut cc, 0, lc);
    let mut pc = Peer::new(&mc).dial(mc.t);
    let lp = accept_none(&mut mc, 0, 40022);
    relay(&mut mc, &mut pc, 0, lp);
    for (l, m, g) in [
        (lc, MsgrId::Public, &gates[0]),
        (lp, MsgrId::Cluster, &gates[1]),
    ] {
        let link = mc.osds[0].links.get_mut(&l).unwrap();
        link.msgr = m;
        link.conn.set_frame_gate(Some(g.clone()));
    }
    // both pools full (a soft pool admits while below its limit: one lease of the whole limit fills it)
    let limit = |i: usize| mc.osds[0].cl.ingress.pool_stats()[i].limit as usize;
    let (lim0, lim1) = (limit(0), limit(1));
    let client_full = gates[0]
        .admit(lim0, false, &mut None)
        .expect("client pool lease");
    let peer_full = gates[1]
        .admit(lim1, false, &mut None)
        .expect("peer pool lease");
    // the client frame parks first, the peer frame behind it
    cc.send_message(ping(81));
    mc.osds[0].on_bytes(lc, &cc.poll_output(), mc.t);
    pc.send_message(ping(82));
    mc.osds[0].on_bytes(lp, &pc.poll_output(), mc.t);
    assert!(mc.osds[0].links[&lc].conn.awaiting_credit());
    assert!(mc.osds[0].links[&lp].conn.awaiting_credit());
    // the peer pool drains (local store done), the client pool stays full (its writes wait for the acks)
    drop(peer_full);
    mc.osds[0].resume_inputs(mc.t);
    assert!(
        !mc.osds[0].links[&lp].conn.awaiting_credit(),
        "the peer frame waits behind the client link of the other pool"
    );
    assert!(mc.osds[0].links[&lc].conn.awaiting_credit());
    drop(client_full);
    mc.osds[0].resume_inputs(mc.t);
    assert!(!mc.osds[0].links[&lc].conn.awaiting_credit());
}

// ---- Block 1: the per-connection attempt owner at public ingress (ADR 0471) ----
//
// A real msgr2 client negotiates placement (banner rdma + placement, a lossless
// session so it carries a generation) and completes the RDMA upgrade on the
// public link. The descriptor's `connection` field is then checked against the
// session's server cookie at `Osd::placement_admit`.

const EP: [u8; 32] = [0xC; 32];

/// One-core OSD with placement advertised on the public messenger: `rdma` and
/// `placement` on, and the client policy lossless (a placement session carries
/// its server cookie as the attempt generation; lossy sessions are 0).
fn placement_mc() -> Mc {
    Mc::new_placement(1)
}

/// Accept a public-messenger client link the way `Osd::on_accept` does, but with the
/// unauthenticated (AuthNone) handshake and granted caps so a test client can complete it.
fn placement_link(mc: &mut Mc, port: u16) -> u64 {
    let t = mc.t;
    let o = &mut mc.osds[0];
    o.set_now(t);
    let id = o.alloc_link_id();
    let ms = &o.msgr[MsgrId::Public as usize];
    let mut conn = Connection::server(
        id,
        ms.cfg.clone(),
        ms.table.clone(),
        Box::new(AuthNoneServer::default()),
        EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, PEER_IP, port),
        t,
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
            msgr: MsgrId::Public,
            purpose: Purpose::Accepted,
            auth: Rc::new(RefCell::new(PeerAuth {
                caps: Some("allow *".into()),
                entity: "client.test".into(),
            })),
            peer: None,
            sock: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(PEER_IP)), port)),
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
    id
}

/// A client that negotiates placement: rdma + placement in its banner, a lossless policy.
fn placement_client(mc: &Mc) -> Connection {
    client_with_placement(mc, true)
}

fn client_with_placement(mc: &Mc, placement: bool) -> Connection {
    let t = mc.t;
    let name = denc::types::EntityName::client(4200);
    let target = mc.osds[0].public_addrs.clone();
    let mut cfg = msgr2::Config::new(
        name,
        addr(PEER_IP, 4201, 1),
        PolicyTable::uniform(if placement {
            msgr2::Policy::lossless_client(0)
        } else {
            msgr2::Policy::lossy_client(0)
        }),
    );
    cfg.rdma = placement;
    cfg.placement = placement;
    // The source-pull record is only admitted on a session that negotiated it.
    cfg.source_pull = placement;
    let table = SessionTable::new(42);
    let mut c = Connection::client(
        1,
        cfg,
        table,
        Box::new(AuthNoneClient { name, global_id: 0 }),
        EntityName::OSD,
        target.clone(),
        target.0[0],
    );
    while let Some(e) = c.poll_event() {
        assert!(matches!(e, Event::Dial { .. }), "{e:?}");
    }
    c.on_connected(t);
    c
}

#[test]
fn classic_client_stays_on_tcp_when_server_advertises_placement() {
    let mut mc = placement_mc();
    mc.up();
    let link = placement_link(&mut mc, 40112);
    let mut client = client_with_placement(&mc, false);
    let events = relay(&mut mc, &mut client, 0, link);
    assert!(connected(&events).is_some(), "{events:?}");
    assert!(!events.contains(&Event::RdmaPrepare));
    assert!(!mc.osds[0].links[&link].conn.placement_ready());
    assert!(mc.osds[0].links.contains_key(&link));
}

#[test]
fn placement_client_stays_on_tcp_with_classic_server() {
    let mut mc = Mc::new(1);
    mc.up();
    let link = placement_link(&mut mc, 40113);
    let mut client = placement_client(&mc);
    let events = relay(&mut mc, &mut client, 0, link);
    assert!(connected(&events).is_some(), "{events:?}");
    assert!(!events.contains(&Event::RdmaPrepare));
    assert!(!mc.osds[0].links[&link].conn.placement_ready());
    assert!(mc.osds[0].links.contains_key(&link));

    let write = mc.op(
        1,
        "classic-fallback",
        vec![OsdOp::write(0, b"data".to_vec())],
    );
    assert_eq!(mc.call(0, link, 50, write)[0].1.result, 0);
    let read = mc.op(1, "classic-fallback", vec![OsdOp::read(0, 4)]);
    let (msg_type, version, compat_version, segments) =
        opwire::ClientMsg::Op(read).encode(u64::MAX).unwrap();
    assert!(client.send_message(msgr2::Message {
        tid: 71,
        msg_type,
        version,
        compat_version,
        front: segments.front,
        data: segments.data,
        ..Default::default()
    }));
    let events = relay(&mut mc, &mut client, 0, link);
    let reply = events
        .into_iter()
        .find_map(|event| match event {
            Event::Message(message) if message.header.tid == 71 => Some(message),
            _ => None,
        })
        .expect("classic inline READ reply");
    assert!(reply.middle.is_empty());
    assert_eq!(reply.data.as_ref(), b"data");
    assert_eq!(
        MOSDOpReply::decode_shared(reply.header.version, &reply.front, &reply.data)
            .unwrap()
            .result,
        0
    );
}

/// Finish the handshake and the RDMA upgrade of `c` on `link`; return the session's generation
/// (its server cookie), which a descriptor's `connection` field must carry.
fn placement_ready(mc: &mut Mc, c: &mut Connection, link: u64) -> u64 {
    let evs = relay(mc, c, 0, link);
    assert!(evs.contains(&Event::RdmaPrepare), "{evs:?}");
    assert!(c.rdma_offer(Some(EP.to_vec()), mc.t));
    relay(mc, c, 0, link);
    let mut accept = None;
    while let Some(cmd) = mc.osds[0].poll_io() {
        if let IoCmd::RdmaAccept { .. } = cmd {
            accept = Some(cmd);
        }
    }
    assert!(accept.is_some(), "the driver sees the offered QP");
    assert!(mc.osds[0].rdma_accepted(link, Some(vec![0x5; 32]), mc.t));
    let evs = relay(mc, c, 0, link);
    assert!(
        evs.contains(&Event::RdmaAnswer {
            endpoint: Some(vec![0x5; 32])
        }),
        "{evs:?}"
    );
    assert!(c.rdma_ready(mc.t));
    relay(mc, c, 0, link);
    let generation = mc.osds[0].links[&link].conn.placement_generation();
    assert_ne!(generation, 0, "a placement session carries a generation");
    generation
}

/// `op` encoded for the wire with the placement descriptor (session `generation`, transaction `tid`,
/// `retry`) as its middle segment.
fn op_with_descriptor(op: MOSDOp, generation: u64, tid: u64, retry: u32) -> msgr2::Message {
    let middle = ::rdma::placement::WindowDescriptor {
        attempt: ::rdma::placement::WindowAttempt {
            connection: generation,
            tid,
            retry,
        },
        range: ::rdma::memory::MemoryRange::new(0x1000, 2 << 20).unwrap(),
        rkey: 99,
    }
    .encode()
    .to_vec();
    let (msg_type, version, compat_version, segs) =
        opwire::ClientMsg::Op(op).encode(u64::MAX).unwrap();
    msgr2::Message {
        tid,
        msg_type,
        version,
        compat_version,
        front: segs.front,
        middle,
        data: segs.data,
        ..Default::default()
    }
}

/// A source-pull PUT record (adr 0665) is a different middle record than the
/// placement READ descriptor: the OSD validates it, holds the op and asks the
/// transport for one READ. The transport cannot post it yet, so the held op is
/// admitted with EOPNOTSUPP: no bytes are stored and the link stays up.
#[test]
fn a_source_pull_put_is_held_for_the_read_and_refused_when_it_cannot_be_served() {
    let mut mc = placement_mc();
    mc.up();
    let l = placement_link(&mut mc, 40102);
    let mut c = placement_client(&mc);
    let generation = placement_ready(&mut mc, &mut c, l);
    let payload = vec![9u8; 1 << 20];
    let op = mc.op(1, "source-pull", vec![OsdOp::write(0, Vec::new())]);
    let record = ::rdma::source_pull::Descriptor {
        address: 0x7f00_0000_1000,
        rkey: 0x1234,
        length: payload.len() as u32,
        crc32c: Some(crc::crc32c(0, &payload)),
        transaction: 7,
        attempt: 0,
    };
    let (msg_type, version, compat_version, mut segs) =
        opwire::ClientMsg::Op(op).encode(u64::MAX).unwrap();
    segs.data = bytes::Bytes::new();
    let message = msgr2::Message {
        tid: 81,
        msg_type,
        version,
        compat_version,
        front: segs.front,
        middle: record.encode().to_vec(),
        data: segs.data,
        ..Default::default()
    };
    let _ = generation;
    c.send_message(message);
    relay(&mut mc, &mut c, 0, l);
    let mut declined = false;
    while let Some(cmd) = mc.osds[0].poll_io() {
        if matches!(cmd, IoCmd::SourcePullRead { conn, tid: 81, .. } if conn == l) {
            mc.osds[0].rdma_decline(cmd, mc.t);
            declined = true;
        }
    }
    assert!(declined, "the transport receives the source-pull READ");
    mc.settle();
    let replies = mc.replies(0, l);
    let put = &replies
        .iter()
        .find(|(tid, _)| *tid == 81)
        .expect("refused source-pull reply")
        .1;
    assert_eq!(put.result, -opwire::errno::EOPNOTSUPP);
    assert_eq!(put.ops[0].rval, -opwire::errno::EOPNOTSUPP);
    mc.settle();
    assert!(
        mc.osds[0].links.contains_key(&l),
        "a validated source-pull PUT keeps the link"
    );
    // The write was answered with an error (the READ cannot be served yet) and
    // no object was stored.
    let read = mc.call(
        0,
        l,
        82,
        mc.op(1, "source-pull", vec![OsdOp::read(0, 1 << 20)]),
    );
    assert_eq!(read.len(), 1, "{read:?}");
    assert_ne!(
        read[0].1.result, 0,
        "nothing is stored without the pulled bytes"
    );
}

/// Send one source-pull PUT record for `object` with `crc` over `payload`.
///
/// `relay` drives the frame through the whole OSD/transport loop (the transport
/// then declines the READ, which answers the held op with an error); without it
/// the frame is only decoded by the OSD, so the test can drain the emitted
/// `IoCmd::SourcePullRead` and complete the pull itself.
#[expect(clippy::too_many_arguments)]
fn send_source_pull(
    mc: &mut Mc,
    c: &mut Connection,
    l: u64,
    tid: u64,
    crc: Option<u32>,
    object: &str,
    payload: &[u8],
    relay_it: bool,
) {
    // The op names the write extent; its data segment is replaced by the record.
    let op = mc.op(1, object, vec![OsdOp::write(0, Vec::new())]);
    let record = ::rdma::source_pull::Descriptor {
        address: 0x7f00_0000_1000,
        rkey: 0x1234,
        length: payload.len() as u32,
        crc32c: crc,
        transaction: tid,
        attempt: 0,
    };
    let (msg_type, version, compat_version, mut segs) =
        opwire::ClientMsg::Op(op).encode(u64::MAX).unwrap();
    segs.data = bytes::Bytes::new();
    c.send_message(msgr2::Message {
        tid,
        msg_type,
        version,
        compat_version,
        front: segs.front,
        middle: record.encode().to_vec(),
        data: segs.data,
        ..Default::default()
    });
    if relay_it {
        relay(mc, c, 0, l);
        mc.settle();
    } else {
        let out = c.poll_output();
        assert!(!out.is_empty(), "the PUT frame is encoded");
        assert!(mc.osds[0].input_ready(l), "input ready for the PUT frame");
        mc.osds[0].on_bytes(l, &out, mc.t);
        mc.settle();
    }
}

#[test]
fn a_short_source_pull_reports_eio_without_storing_data() {
    let mut mc = placement_mc();
    mc.up();
    let l = placement_link(&mut mc, 40109);
    let mut c = placement_client(&mc);
    placement_ready(&mut mc, &mut c, l);
    let payload = vec![7u8; 1 << 20];
    send_source_pull(
        &mut mc,
        &mut c,
        l,
        121,
        Some(crc::crc32c(0, &payload)),
        "source-pull-short",
        &payload,
        false,
    );
    while mc.osds[0].poll_io().is_some() {}
    mc.osds[0].source_pull_done(
        l,
        121,
        Ok(Bytes::copy_from_slice(&payload[..payload.len() - 1])),
    );
    mc.settle();
    let replies = mc.call(
        0,
        l,
        122,
        mc.op(1, "source-pull-short", vec![OsdOp::read(0, 0)]),
    );
    let put = replies
        .iter()
        .find(|(tid, _)| *tid == 121)
        .expect("PUT reply");
    assert_eq!(put.1.result, -opwire::errno::EIO);
    assert_eq!(put.1.ops[0].rval, -opwire::errno::EIO);
    let read = replies
        .iter()
        .find(|(tid, _)| *tid == 122)
        .expect("READ reply");
    assert_eq!(read.1.result, -opwire::errno::ENOENT);
}

/// The staging step itself: a completed READ's bytes become the write data, and
/// a crc32c mismatch is refused before the store.
#[test]
fn a_completed_source_pull_stages_the_bytes_and_checks_the_crc() {
    let mut mc = placement_mc();
    mc.up();
    let l = placement_link(&mut mc, 40103);
    let mut c = placement_client(&mc);
    let _generation = placement_ready(&mut mc, &mut c, l);
    let payload: Vec<u8> = (0..(1u32 << 20)).map(|i| (i % 251) as u8).collect();
    send_source_pull(
        &mut mc,
        &mut c,
        l,
        91,
        Some(crc::crc32c(0, &payload)),
        "source-pull-ok",
        &payload,
        false,
    );
    // The OSD asked for the READ; the test plays the transport and completes it.
    let mut asked = None;
    while let Some(cmd) = mc.osds[0].poll_io() {
        if let IoCmd::SourcePullRead {
            conn, tid, length, ..
        } = cmd
        {
            asked = Some((conn, tid, length));
        }
    }
    assert_eq!(asked, Some((l, 91, payload.len() as u32)));
    mc.osds[0].source_pull_done(l, 91, Ok(bytes::Bytes::from(payload.clone())));
    mc.settle();
    let read = mc.call(
        0,
        l,
        92,
        mc.op(
            1,
            "source-pull-ok",
            vec![OsdOp::read(0, payload.len() as u64)],
        ),
    );
    let reply = read
        .iter()
        .find(|(tid, _)| *tid == 92)
        .map(|(_, reply)| reply)
        .unwrap_or_else(|| panic!("no read reply: {read:?}"));
    assert_eq!(reply.result, 0);
    let stored: Vec<u8> = reply
        .ops
        .iter()
        .flat_map(|op| op.outdata.to_vec())
        .collect();
    assert_eq!(stored, payload, "the stored object equals the pulled bytes");

    // A crc mismatch on a second object stores nothing.
    send_source_pull(
        &mut mc,
        &mut c,
        l,
        93,
        Some(0xdead_beef),
        "source-pull-bad",
        &payload,
        false,
    );
    while mc.osds[0].poll_io().is_some() {}
    mc.osds[0].source_pull_done(l, 93, Ok(bytes::Bytes::from(payload.clone())));
    mc.settle();
    let read = mc.call(
        0,
        l,
        94,
        mc.op(1, "source-pull-bad", vec![OsdOp::read(0, 1 << 20)]),
    );
    let reply = read
        .iter()
        .find(|(tid, _)| *tid == 94)
        .map(|(_, reply)| reply)
        .unwrap_or_else(|| panic!("no read reply: {read:?}"));
    assert_ne!(reply.result, 0, "a crc mismatch must not store an object");
    // The PUT itself reports the integrity failure.
    let put = read
        .iter()
        .find(|(tid, _)| *tid == 93)
        .map(|(_, reply)| reply)
        .unwrap_or_else(|| panic!("no PUT reply: {read:?}"));
    assert_eq!(
        put.result,
        -opwire::errno::EIO,
        "a crc mismatch must report failure to the client"
    );

    // A device source carries no crc: the pulled bytes are stored as delivered.
    send_source_pull(
        &mut mc,
        &mut c,
        l,
        95,
        None,
        "source-pull-device",
        &payload,
        false,
    );
    while mc.osds[0].poll_io().is_some() {}
    mc.osds[0].source_pull_done(l, 95, Ok(bytes::Bytes::from(payload.clone())));
    mc.settle();
    let read = mc.call(
        0,
        l,
        96,
        mc.op(
            1,
            "source-pull-device",
            vec![OsdOp::read(0, payload.len() as u64)],
        ),
    );
    let reply = read
        .iter()
        .find(|(tid, _)| *tid == 96)
        .map(|(_, reply)| reply)
        .unwrap_or_else(|| panic!("no read reply: {read:?}"));
    assert_eq!(reply.result, 0);
    let stored: Vec<u8> = reply
        .ops
        .iter()
        .flat_map(|op| op.outdata.to_vec())
        .collect();
    assert_eq!(stored, payload, "a crc-less pull stores the pulled bytes");
}

/// Session ordering (adr 0665, "Ordering"): a source-pull PUT A followed by an
/// inline write B of the same range on the same session applies A first, like two inline writes. B
/// arrives while A's READ is outstanding; it must not overtake A, and the replies keep submission order.
#[test]
fn a_later_inline_write_never_overtakes_a_pending_source_pull() {
    let mut mc = placement_mc();
    mc.up();
    let l = placement_link(&mut mc, 40104);
    let mut c = placement_client(&mc);
    let _generation = placement_ready(&mut mc, &mut c, l);
    let a: Vec<u8> = vec![0xaa; 4096];
    let b: Vec<u8> = vec![0xbb; 4096];
    send_source_pull(
        &mut mc,
        &mut c,
        l,
        101,
        Some(crc::crc32c(0, &a)),
        "source-pull-order",
        &a,
        false,
    );
    while mc.osds[0].poll_io().is_some() {}
    // B: an ordinary inline write of the same range, on the same session, after A.
    let op = mc.op(1, "source-pull-order", vec![OsdOp::write(0, b.clone())]);
    let (msg_type, version, compat_version, segs) =
        opwire::ClientMsg::Op(op).encode(u64::MAX).unwrap();
    c.send_message(msgr2::Message {
        tid: 102,
        msg_type,
        version,
        compat_version,
        front: segs.front,
        middle: Vec::new(),
        data: segs.data,
        ..Default::default()
    });
    let out = c.poll_output();
    assert!(!out.is_empty(), "the inline write is encoded");
    mc.osds[0].on_bytes(l, &out, mc.t);
    mc.settle();
    assert!(
        mc.replies(0, l).iter().all(|(tid, _)| *tid != 102),
        "B is answered before A's READ completed"
    );
    // A's READ completes: A applies, then B.
    mc.osds[0].source_pull_done(l, 101, Ok(bytes::Bytes::from(a.clone())));
    mc.settle();
    for _ in 0..50 {
        mc.osds[0].resume_inputs(mc.t);
        mc.settle();
    }
    let mut replies = mc.replies(0, l);
    let read = mc.call(
        0,
        l,
        103,
        mc.op(1, "source-pull-order", vec![OsdOp::read(0, 4096)]),
    );
    replies.extend(read);
    let order: Vec<u64> = replies.iter().map(|(tid, _)| *tid).collect();
    assert_eq!(order, vec![101, 102, 103], "replies in submission order");
    assert!(replies.iter().all(|(_, r)| r.result == 0), "{replies:?}");
    let stored: Vec<u8> = replies[2]
        .1
        .ops
        .iter()
        .flat_map(|op| op.outdata.to_vec())
        .collect();
    assert_eq!(stored, b, "the later inline write B is the stored content");
}

/// The connection dies while a source-pull READ is outstanding (adr 0665): the transport
/// abandons the READ without a completion, so the OSD aborts the pull itself. The held op and the later message it
/// held back are dropped (never executed, no reply), their ingress credits return, the queued READ command is never
/// handed to the transport, the session is reset and the link's close runs; a later link is unaffected.
#[test]
fn a_connection_lost_during_a_source_pull_drops_the_op_and_frees_the_link() {
    let mut mc = placement_mc();
    mc.up();
    let l = placement_link(&mut mc, 40105);
    let mut c = placement_client(&mc);
    let _generation = placement_ready(&mut mc, &mut c, l);
    // the public pool's header gate, as `on_accept` installs it: frames hold ingress credits from here on
    let gates = mc.osds[0].cl.frame_gates.clone().expect("frame windows");
    let link = mc.osds[0].links.get_mut(&l).unwrap();
    link.msgr = MsgrId::Public;
    link.conn.set_frame_gate(Some(gates[0].clone()));
    let used = |mc: &Mc| -> u64 {
        mc.osds[0]
            .cl
            .ingress
            .pool_stats()
            .iter()
            .map(|p| p.used)
            .sum()
    };
    let idle = used(&mc);
    let a: Vec<u8> = vec![0xaa; 4096];
    send_source_pull(
        &mut mc,
        &mut c,
        l,
        111,
        Some(crc::crc32c(0, &a)),
        "source-pull-lost",
        &a,
        false,
    );
    // B: a later inline write of the same session, decoded while A's READ is outstanding
    let op = mc.op(
        1,
        "source-pull-lost-b",
        vec![OsdOp::write(0, vec![0xbb; 4096])],
    );
    let (msg_type, version, compat_version, segs) =
        opwire::ClientMsg::Op(op).encode(u64::MAX).unwrap();
    c.send_message(msgr2::Message {
        tid: 112,
        msg_type,
        version,
        compat_version,
        front: segs.front,
        middle: Vec::new(),
        data: segs.data,
        ..Default::default()
    });
    let out = c.poll_output();
    mc.osds[0].on_bytes(l, &out, mc.t);
    mc.settle();
    assert!(
        mc.osds[0].links[&l].pull.is_some(),
        "A's READ is outstanding"
    );
    assert!(used(&mc) > idle, "A and B hold ingress credits");
    // The transport reports the socket closed (it abandoned A's READ with the QP, no completion follows).
    mc.osds[0].on_closed(l, mc.t);
    mc.settle();
    assert!(
        !mc.osds[0].links.contains_key(&l),
        "the link's close runs although no source_pull_done came"
    );
    assert_eq!(used(&mc), idle, "the dropped ops' ingress credits returned");
    let mut asked = false;
    while let Some(cmd) = mc.osds[0].poll_io() {
        asked |= matches!(cmd, IoCmd::SourcePullRead { conn, .. } if conn == l);
    }
    assert!(!asked, "no READ is posted for the dead connection");
    assert_eq!(
        mc.osds[0].pg.c.link_events.get("source_pull_aborted"),
        Some(&1)
    );
    // A late completion for the gone link is ignored.
    mc.osds[0].source_pull_done(l, 111, Ok(bytes::Bytes::from(a)));
    mc.settle();
    // A new connection works, and neither A nor B was executed.
    let l2 = placement_link(&mut mc, 40106);
    let mut c2 = placement_client(&mc);
    let _ = placement_ready(&mut mc, &mut c2, l2);
    for (tid, object) in [(113, "source-pull-lost"), (114, "source-pull-lost-b")] {
        let read = mc.call(0, l2, tid, mc.op(1, object, vec![OsdOp::read(0, 4096)]));
        let reply = read
            .iter()
            .find(|(t, _)| *t == tid)
            .map(|(_, reply)| reply)
            .unwrap_or_else(|| panic!("no read reply: {read:?}"));
        assert_ne!(reply.result, 0, "{object} must not be stored");
    }
    let w = mc.op(
        1,
        "source-pull-lost-c",
        vec![OsdOp::write(0, vec![1u8; 4096])],
    );
    assert_eq!(mc.call(0, l2, 115, w)[0].1.result, 0);
}

#[test]
fn a_placement_descriptor_is_admitted_and_the_attempt_vacates_on_the_reply() {
    let mut mc = placement_mc();
    mc.up();
    let l = placement_link(&mut mc, 40101);
    let mut c = placement_client(&mc);
    let generation = placement_ready(&mut mc, &mut c, l);
    // the object exists so the placed read is a hit (a read of a hole is ENOENT)
    let wop = mc.op(
        1,
        "placement-read",
        vec![OsdOp::write(0, vec![7u8; 1 << 20])],
    );
    let wrote = mc.call(0, l, 50, wop);
    assert_eq!(wrote.len(), 1, "{wrote:?}");
    assert_eq!(wrote[0].1.result, 0);
    let op = mc.op(1, "placement-read", vec![OsdOp::read(0, 1 << 20)]);
    c.send_message(op_with_descriptor(op, generation, 71, 0));
    relay(&mut mc, &mut c, 0, l);
    mc.settle();
    // admitted: the link stays open, the op is answered, the pieces are handed to the transport
    assert!(mc.osds[0].links.contains_key(&l), "the link must stay open");
    let mut placed = None;
    while let Some(cmd) = mc.osds[0].poll_io() {
        if let IoCmd::PlaceReadReply { .. } = cmd {
            placed = Some(cmd);
        }
    }
    let (conn, tid, retry, pieces, len) = match placed {
        Some(IoCmd::PlaceReadReply {
            conn,
            tid,
            retry,
            pieces,
            len,
            ..
        }) => (conn, tid, retry, pieces, len),
        _ => panic!("the transport receives the reply's source pieces"),
    };
    assert_eq!(len, 1 << 20, "the placed length is the read length");
    assert_eq!(
        pieces.iter().map(bytes::Bytes::len).sum::<usize>(),
        1 << 20,
        "the pieces cover the read"
    );
    // the transport completes the WRITEs and reports the terminal outcome: the attempt vacates
    mc.osds[0].placement_success(conn, tid, retry, vec![1u8; 44]);
    assert!(
        mc.osds[0].links[&l].placement.is_empty(),
        "the reply vacates the attempt"
    );
    let replies = mc.replies(0, l);
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(replies[0].0, 71);
    assert_eq!(replies[0].1.result, 0);
    // the placed reply carries no inline data: the pieces were written to the client over the QP
    assert_eq!(
        replies[0].1.ops[0].outdata.len(),
        0,
        "a placed reply has an empty data segment"
    );
}

/// No RDMA upgrade on the link: `placement_ready()` is false, so a descriptor middle is a
/// protocol violation and the link is closed (the middle is never a classic payload).
#[test]
fn a_descriptor_without_the_rdma_upgrade_closes_the_link() {
    let mut mc = placement_mc();
    mc.up();
    let l = placement_link(&mut mc, 40102);
    let mut c = placement_client(&mc);
    let evs = relay(&mut mc, &mut c, 0, l);
    assert!(evs.contains(&Event::RdmaPrepare), "{evs:?}");
    assert!(c.rdma_offer(Some(EP.to_vec()), mc.t));
    relay(&mut mc, &mut c, 0, l);
    // the transport declines the upgrade: the session goes on over TCP, not placement-ready
    let mut accept = None;
    while let Some(cmd) = mc.osds[0].poll_io() {
        if let IoCmd::RdmaAccept { .. } = cmd {
            accept = Some(cmd);
        }
    }
    mc.osds[0].rdma_decline(accept.expect("the offered QP"), mc.t);
    relay(&mut mc, &mut c, 0, l);
    assert!(
        !mc.osds[0].links[&l].conn.placement_ready(),
        "TCP session is not placement-ready"
    );
    let op = mc.op(1, "placement-read", vec![OsdOp::read(0, 1 << 20)]);
    c.send_message(op_with_descriptor(op, 0, 71, 0));
    relay(&mut mc, &mut c, 0, l);
    mc.settle();
    assert!(
        !mc.osds[0].links.contains_key(&l),
        "the link must be closed"
    );
}

/// The descriptor claims a session generation the link does not hold: closed.
#[test]
fn a_descriptor_with_the_wrong_session_generation_closes_the_link() {
    let mut mc = placement_mc();
    mc.up();
    let l = placement_link(&mut mc, 40103);
    let mut c = placement_client(&mc);
    let generation = placement_ready(&mut mc, &mut c, l);
    let op = mc.op(1, "placement-read", vec![OsdOp::read(0, 1 << 20)]);
    c.send_message(op_with_descriptor(op, generation.wrapping_add(1), 71, 0));
    relay(&mut mc, &mut c, 0, l);
    mc.settle();
    assert!(
        !mc.osds[0].links.contains_key(&l),
        "the link must be closed"
    );
}

/// The op is not the plain READ shape placement admits: the descriptor is refused, the link closed.
#[test]
fn a_descriptor_on_an_ineligible_op_closes_the_link() {
    let mut mc = placement_mc();
    mc.up();
    let l = placement_link(&mut mc, 40104);
    let mut c = placement_client(&mc);
    let generation = placement_ready(&mut mc, &mut c, l);
    // a 4-byte read is not a single plain READ of at least 1 MiB
    let op = mc.op(1, "placement-read", vec![OsdOp::read(0, 4)]);
    c.send_message(op_with_descriptor(op, generation, 71, 0));
    relay(&mut mc, &mut c, 0, l);
    mc.settle();
    assert!(
        !mc.osds[0].links.contains_key(&l),
        "the link must be closed"
    );
}

#[test]
fn a_descriptor_on_an_ec_direct_read_closes_the_link() {
    let mut mc = placement_mc();
    mc.up();
    let l = placement_link(&mut mc, 40111);
    let mut c = placement_client(&mc);
    let generation = placement_ready(&mut mc, &mut c, l);
    let mut op = mc.op(1, "placement-read", vec![OsdOp::read(0, 1 << 20)]);
    op.flags |= opwire::flag::EC_DIRECT_READ | opwire::flag::FORCE_OSD;
    c.send_message(op_with_descriptor(op, generation, 71, 0));
    relay(&mut mc, &mut c, 0, l);
    mc.settle();
    assert!(!mc.osds[0].links.contains_key(&l));
}

/// Move bytes between the client and `link` until quiet, without settling: a just-admitted
/// attempt stays live (the PG runs on `settle`), so the test can inspect it and queue a control.
fn feed(mc: &mut Mc, c: &mut Connection, l: u64) {
    for _ in 0..50 {
        let mut moved = false;
        let out = c.poll_output();
        if !out.is_empty() {
            assert!(mc.osds[0].input_ready(l), "input ready for the frame");
            mc.osds[0].on_bytes(l, &out, mc.t);
            moved = true;
        }
        let back = mc.osds[0].poll_output(l);
        if !back.is_empty() {
            c.on_bytes(&back, mc.t);
            moved = true;
        }
        while c.poll_event().is_some() {}
        if !moved {
            return;
        }
    }
    panic!("feed did not settle");
}

/// A CANCEL before the PG result prevents a late WRITE handoff or inline reply.
#[test]
fn a_cancel_control_retires_the_live_attempt() {
    let mut mc = placement_mc();
    mc.up();
    let l = placement_link(&mut mc, 40105);
    let mut c = placement_client(&mc);
    let generation = placement_ready(&mut mc, &mut c, l);
    // the object exists so the placed read is a hit
    let wop = mc.op(
        1,
        "placement-read",
        vec![OsdOp::write(0, vec![7u8; 1 << 20])],
    );
    assert_eq!(mc.call(0, l, 50, wop)[0].1.result, 0);
    // admit the placed read and deliver it without settling: the attempt is live
    let op = mc.op(1, "placement-read", vec![OsdOp::read(0, 1 << 20)]);
    c.send_message(op_with_descriptor(op, generation, 71, 0));
    feed(&mut mc, &mut c, l);
    assert!(
        !mc.osds[0].links[&l].placement.is_empty(),
        "the admitted attempt is live"
    );
    // the CANCEL for the same (tid, retry) and grant rkey
    let record = ::rdma::placement::ControlRecord {
        attempt: ::rdma::placement::WindowAttempt {
            connection: generation,
            tid: 71,
            retry: 0,
        },
        rkey: 99,
    }
    .encode(::rdma::placement::ControlRecord::CANCEL);
    assert!(c.send_placement_control(record));
    feed(&mut mc, &mut c, l);
    // The op completes after CANCEL, but its late result cannot start WRITEs.
    mc.settle();
    assert!(mc.osds[0].links.contains_key(&l), "the link must stay open");
    let mut cancel = None;
    while let Some(cmd) = mc.osds[0].poll_io() {
        match cmd {
            IoCmd::PlaceReadCancel { .. } => cancel = Some(cmd),
            IoCmd::PlaceReadReply { .. } => panic!("CANCEL must close WRITE admission"),
            _ => {}
        }
    }
    let (conn, tid, retry) = match cancel {
        Some(IoCmd::PlaceReadCancel {
            conn, tid, retry, ..
        }) => (conn, tid, retry),
        _ => panic!("the transport receives the cancellation"),
    };
    mc.osds[0].placement_cancelled(conn, tid, retry);
    assert!(
        mc.osds[0].links[&l].placement.is_empty(),
        "the retired attempt is vacated"
    );
    assert!(
        mc.replies(0, l).is_empty(),
        "the late PG reply is suppressed"
    );
}

#[test]
fn cancel_wins_over_a_queued_placement_terminal_callback() {
    for success in [false, true] {
        let mut mc = placement_mc();
        mc.up();
        let link = placement_link(&mut mc, 40109);
        let mut client = placement_client(&mc);
        let generation = placement_ready(&mut mc, &mut client, link);
        let write = mc.op(
            1,
            "placement-read",
            vec![OsdOp::write(0, vec![7u8; 1 << 20])],
        );
        assert_eq!(mc.call(0, link, 50, write)[0].1.result, 0);
        let op = mc.op(1, "placement-read", vec![OsdOp::read(0, 1 << 20)]);
        client.send_message(op_with_descriptor(op, generation, 71, 0));
        feed(&mut mc, &mut client, link);
        mc.settle();
        assert!(
            std::iter::from_fn(|| mc.osds[0].poll_io()).any(
                |cmd| matches!(cmd, IoCmd::PlaceReadReply { conn, tid: 71, .. } if conn == link)
            )
        );

        let record = ::rdma::placement::ControlRecord {
            attempt: ::rdma::placement::WindowAttempt {
                connection: generation,
                tid: 71,
                retry: 0,
            },
            rkey: 99,
        }
        .encode(::rdma::placement::ControlRecord::CANCEL);
        assert!(client.send_placement_control(record));
        feed(&mut mc, &mut client, link);
        assert!(mc.osds[0].links[&link].placement.cancelled(71, 0));
        if success {
            mc.osds[0].placement_success(link, 71, 0, vec![1u8; 44]);
        } else {
            mc.osds[0].placement_preflight_refused(link, 71, 0);
        }
        assert!(!mc.osds[0].links[&link].placement.is_empty());
        assert!(mc.replies(0, link).is_empty());
        mc.osds[0].placement_cancelled(link, 71, 0);
        assert!(mc.osds[0].links[&link].placement.is_empty());
        let output = mc.osds[0].poll_output(link);
        client.on_bytes(&output, mc.t);
        let events: Vec<Event> = std::iter::from_fn(|| client.poll_event()).collect();
        assert!(matches!(events.as_slice(), [Event::PlacementControl(_)]));
    }
}

/// Later output stays unencoded until RETIRED has been queued on the placement session.
#[test]
fn retired_control_precedes_later_output_on_the_placement_session() {
    let mut mc = placement_mc();
    mc.up();
    let link = placement_link(&mut mc, 40106);
    let mut client = placement_client(&mc);
    let generation = placement_ready(&mut mc, &mut client, link);
    let write = mc.op(
        1,
        "placement-read",
        vec![OsdOp::write(0, vec![7u8; 1 << 20])],
    );
    assert_eq!(mc.call(0, link, 50, write)[0].1.result, 0);
    let op = mc.op(1, "placement-read", vec![OsdOp::read(0, 1 << 20)]);
    client.send_message(op_with_descriptor(op, generation, 71, 0));
    feed(&mut mc, &mut client, link);
    assert!(!mc.osds[0].links[&link].placement.is_empty());

    let server = &mut mc.osds[0].links.get_mut(&link).unwrap().conn;
    assert!(server.send_message(ping(72)));
    assert!(server.poll_output_chunks_bounded(1).is_empty());
    assert!(server.has_output());
    mc.osds[0].placement_cancelled(link, 71, 0);
    assert!(mc.osds[0].links.contains_key(&link));
    let output = mc.osds[0].poll_output(link);
    client.on_bytes(&output, mc.t);
    let events: Vec<Event> = std::iter::from_fn(|| client.poll_event()).collect();
    assert!(matches!(events.first(), Some(Event::PlacementControl(_))));
    assert!(matches!(events.get(1), Some(Event::Message(message)) if message.header.tid == 72));
}

#[test]
fn placed_reply_precedes_later_output_on_the_same_session() {
    let mut mc = placement_mc();
    mc.up();
    let link = placement_link(&mut mc, 40107);
    let mut client = placement_client(&mc);
    let generation = placement_ready(&mut mc, &mut client, link);
    let write = mc.op(
        1,
        "placement-read",
        vec![OsdOp::write(0, vec![7u8; 1 << 20])],
    );
    assert_eq!(mc.call(0, link, 50, write)[0].1.result, 0);
    let op = mc.op(1, "placement-read", vec![OsdOp::read(0, 1 << 20)]);
    client.send_message(op_with_descriptor(op, generation, 71, 0));
    feed(&mut mc, &mut client, link);
    mc.settle();
    assert!(
        std::iter::from_fn(|| mc.osds[0].poll_io())
            .any(|cmd| matches!(cmd, IoCmd::PlaceReadReply { conn, tid: 71, .. } if conn == link))
    );
    assert!(
        mc.osds[0]
            .links
            .get_mut(&link)
            .unwrap()
            .conn
            .send_message(ping(72))
    );
    mc.osds[0].placement_success(link, 71, 0, vec![1u8; 44]);
    let output = mc.osds[0].poll_output(link);
    client.on_bytes(&output, mc.t);
    let tids: Vec<u64> = std::iter::from_fn(|| client.poll_event())
        .filter_map(|event| match event {
            Event::Message(message) => Some(message.header.tid),
            _ => None,
        })
        .collect();
    assert_eq!(tids, [71, 72]);
}

#[test]
fn failed_placed_read_returns_an_ordered_retired_error() {
    let mut mc = placement_mc();
    mc.up();
    let link = placement_link(&mut mc, 40108);
    let mut client = placement_client(&mc);
    let generation = placement_ready(&mut mc, &mut client, link);
    let op = mc.op(1, "missing-placement-read", vec![OsdOp::read(0, 1 << 20)]);
    client.send_message(op_with_descriptor(op, generation, 71, 0));
    mc.osds[0].on_bytes(link, &client.poll_output(), mc.t);
    mc.settle();
    assert!(mc.osds[0].links[&link].placement.is_empty());
    let output = mc.osds[0].poll_output(link);
    client.on_bytes(&output, mc.t);
    let replies: Vec<_> = std::iter::from_fn(|| client.poll_event())
        .filter_map(|event| match event {
            Event::Message(message) => Some(message),
            _ => None,
        })
        .collect();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].header.tid, 71);
    assert!(replies[0].data.is_empty());
    let (kind, record) = ::rdma::placement::ControlRecord::decode(&replies[0].middle).unwrap();
    assert_eq!(kind, ::rdma::placement::ControlRecord::RETIRED);
    assert_eq!(record.attempt.connection, generation);
    assert_eq!(record.attempt.tid, 71);
    assert_eq!(record.rkey, 99);
    let reply = MOSDOpReply::decode_shared(
        replies[0].header.version,
        &replies[0].front,
        &replies[0].data,
    )
    .unwrap();
    assert!(reply.result < 0);
}

#[test]
fn preflight_refusal_after_admission_retires_without_inline_payload() {
    let mut mc = placement_mc();
    mc.up();
    let link = placement_link(&mut mc, 40110);
    let mut client = placement_client(&mc);
    let generation = placement_ready(&mut mc, &mut client, link);
    let write = mc.op(
        1,
        "placement-read",
        vec![OsdOp::write(0, vec![7u8; 1 << 20])],
    );
    assert_eq!(mc.call(0, link, 50, write)[0].1.result, 0);
    let op = mc.op(1, "placement-read", vec![OsdOp::read(0, 1 << 20)]);
    client.send_message(op_with_descriptor(op, generation, 71, 0));
    feed(&mut mc, &mut client, link);
    mc.settle();
    assert!(
        std::iter::from_fn(|| mc.osds[0].poll_io())
            .any(|cmd| matches!(cmd, IoCmd::PlaceReadReply { conn, tid: 71, .. } if conn == link))
    );
    mc.osds[0].placement_preflight_refused(link, 71, 0);
    let output = mc.osds[0].poll_output(link);
    client.on_bytes(&output, mc.t);
    let message = std::iter::from_fn(|| client.poll_event())
        .find_map(|event| match event {
            Event::Message(message) => Some(message),
            _ => None,
        })
        .expect("terminal error reply");
    assert_eq!(message.header.tid, 71);
    assert!(message.data.is_empty());
    let (kind, record) = ::rdma::placement::ControlRecord::decode(&message.middle).unwrap();
    assert_eq!(kind, ::rdma::placement::ControlRecord::RETIRED);
    assert_eq!(record.attempt.connection, generation);
    assert_eq!(record.rkey, 99);
    let reply =
        MOSDOpReply::decode_shared(message.header.version, &message.front, &message.data).unwrap();
    assert_eq!(reply.result, -opwire::errno::EOPNOTSUPP);
    assert!(mc.osds[0].links[&link].placement.is_empty());
}

/// osd.0's PG layer on `core` sends message `tid` to osd.1, stamped with its map `epoch`.
fn pg_frame(mc: &mut Mc, core: usize, tid: u64, epoch: u32) {
    mc.osds[core].pg_forward(crate::flow::Tx {
        to: 1,
        epoch,
        tid,
        prio: 0,
        hdr: (2, 1, 1),
        segs: Default::default(),
        data: Default::default(),
    });
}

/// `core` dialled the cluster link to osd.1; osd.1 accepts. The link and osd.1's end of the socket.
fn osd_dialled(mc: &mut Mc, peer: &Peer, core: usize) -> (u64, Connection) {
    mc.settle();
    let mut link = None;
    while let Some(cmd) = mc.osds[core].poll_io() {
        if let IoCmd::Dial { conn, .. } = cmd
            && mc.osds[core]
                .links
                .get(&conn)
                .is_some_and(|l| l.msgr == MsgrId::Cluster)
        {
            link = Some(conn);
        }
    }
    let link = link.expect("the link core dials osd.1");
    mc.osds[core].on_connected(link, mc.t);
    let conn = Connection::server(
        900 + link,
        peer.cfg.clone(),
        peer.table.clone(),
        Box::new(AuthNoneServer::default()),
        EntityAddr::from_socket(
            EntityAddr::TYPE_MSGR2,
            0,
            SocketAddr::new(mc.osds[0].cfg.cluster_ips[0], 6801),
        ),
        mc.t,
    );
    (link, conn)
}

fn tids(log: &[Event]) -> Vec<u64> {
    log.iter()
        .filter_map(|e| match e {
            Event::Message(m) => Some(m.header.tid),
            _ => None,
        })
        .collect()
}

/// The map marks osd.0 down while it runs: its cluster identity rebinds and the link to the classic peer osd.1
/// reconnects from the new address; the peer has no session for it and answers RESET, so what osd.0 still owed it is
/// lost. A frame of the old identity (a PG whose core has not taken the map yet, forwarded or local) must not follow on
/// the fresh session: the peer, still in the old interval, would take it behind the lost one.
#[test]
fn after_the_rebind_no_frame_of_the_old_identity_follows_the_reset() {
    let mut mc = Mc::new(3);
    mc.up();
    let peer_addrs = addr(PEER_IP, 6801, 556);
    let mut m = mc.map(mc.epoch + 1, 10);
    m.osd_state[1] |= osd_state::UP;
    m.cluster_addrs[1] = peer_addrs.clone();
    mc.deliver(m);
    for o in &mut mc.osds {
        o.t.dial_auth_none = true;
        o.sync_keep_owed();
    }
    let link = mc.osds[0].cl.spec.peer_core(1);
    let peer = Peer::new(&mc);
    let (old, mut log) = (mc.epoch, Vec::new());
    pg_frame(&mut mc, 0, 1000, old);
    let (l, mut c) = osd_dialled(&mut mc, &peer, link);
    log.extend(relay(&mut mc, &mut c, link, l));
    assert_eq!(tids(&log), [1000]);
    pg_frame(&mut mc, 2, 1001, old);
    mc.settle();
    let mut m = mc.map(mc.epoch + 1, 10);
    m.osd_state[0] = osd_state::EXISTS;
    m.osd_state[1] |= osd_state::UP;
    m.cluster_addrs[1] = peer_addrs.clone();
    mc.deliver(m);
    let down = mc.epoch;
    assert!(
        !mc.osds[link].links.contains_key(&l),
        "the rebind closes the link"
    );
    c.on_closed(mc.t);
    while c.poll_event().is_some() {}
    pg_frame(&mut mc, 2, 1002, down);
    let (l, mut c) = osd_dialled(&mut mc, &peer, link);
    log.extend(relay(&mut mc, &mut c, link, l));
    assert_eq!(tids(&log), [1000], "the peer's RESET dropped 1001 and 1002");
    pg_frame(&mut mc, 2, 1003, old);
    pg_frame(&mut mc, link, 1004, old);
    pg_frame(&mut mc, 2, 1005, down);
    mc.settle();
    log.extend(relay(&mut mc, &mut c, link, l));
    assert_eq!(tids(&log), [1000, 1005], "no frame of the old identity");
}
