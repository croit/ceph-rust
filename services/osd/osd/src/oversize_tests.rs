// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Oversized client messages (spec msgr2.md 8.2, client-ops.md 5.4.1) over a real public link: a write whose data
//! segment is above `osd_max_write_size` is refused before the payload is buffered, answered -EMSGSIZE in classic's
//! reply shape, the link stays open and the next op on it succeeds.
//! Child of `xcore_tests` (uses its multi-core harness).
use super::*;
use crate::auth::PeerAuth;
use crate::config::Level;
use crate::osd::{Link, MsgrId, Purpose};
use messages::Segments;
use msgr2::auth::{AuthNoneClient, AuthNoneServer};
use msgr2::{Connection, Event, PolicyTable, SessionTable};

const CLIENT_IP: [u8; 4] = [10, 2, 0, 7];

/// A public-messenger connection on `core` with the unauthenticated handshake, so a test client can complete it. The
/// link carries what `Osd::on_accept` installs for clients: the frame gate and the data probe.
fn accept_client(mc: &mut Mc, core: usize, port: u16) -> u64 {
    let t = mc.t;
    let o = &mut mc.osds[core];
    o.set_now(t);
    let id = o.alloc_link_id();
    let ms = &o.msgr[MsgrId::Public as usize];
    let mut conn = Connection::server(
        id,
        ms.cfg.clone(),
        ms.table.clone(),
        Box::new(AuthNoneServer::default()),
        EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, CLIENT_IP, port),
        t,
    );
    conn.set_frame_gate(o.cl.frame_gates.as_ref().map(|g| g[0].clone()));
    conn.set_data_probe(o.data_probe(MsgrId::Public));
    conn.set_output_queue(&o.output_ready, id);
    conn.set_event_queue(&o.event_ready, id);
    conn.set_timer_queue(&o.timer_ready, id);
    o.conn_timers.get_mut().register(id);
    o.reserve_input_links();
    let caps_peer = opexec::caps::Peer::from_addr(&conn.target());
    o.links.insert(
        id,
        Link {
            pending_input: None,
            held: Default::default(),
            conn,
            msgr: MsgrId::Public,
            purpose: Purpose::Accepted,
            auth: Rc::new(RefCell::new(PeerAuth {
                caps: Some("allow *".into()),
                entity: "client.oversize".into(),
            })),
            peer: None,
            sock: Some(std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(CLIENT_IP)),
                port,
            )),
            caps: None,
            caps_peer,
            info: None,
            fwd: 0,
            pre: None,
            placement: Default::default(),
            preauth_charged: 0,
            pull: None,
        },
    );
    o.pump();
    id
}

/// A classic client of the public messenger (unauthenticated handshake).
fn dial_client(mc: &Mc, port: u16) -> Connection {
    let name = EntityName::client(4100);
    let mut c = Connection::client(
        1,
        msgr2::Config::new(
            EntityName::client(4100),
            addr(CLIENT_IP, port, 2),
            PolicyTable::osd_public(),
        ),
        SessionTable::new(7),
        Box::new(AuthNoneClient { name, global_id: 0 }),
        EntityName::OSD,
        mc.osds[0].public_addrs().clone(),
        mc.osds[0].public_addrs().0[0],
    );
    while let Some(e) = c.poll_event() {
        assert!(matches!(e, Event::Dial { .. }));
    }
    c.on_connected(mc.t);
    c
}

/// Move bytes between the client and the OSD link (`core`) until both sides are quiet.
fn relay(mc: &mut Mc, client: &mut Connection, core: usize, link: u64) {
    for _ in 0..200 {
        let mut moved = false;
        let t = mc.t;
        let out = client.poll_output();
        if !out.is_empty() {
            mc.osds[core].on_bytes(link, &out, t);
            moved = true;
        }
        let out = mc.osds[core].poll_output(link);
        if !out.is_empty() {
            client.on_bytes(&out, t);
            moved = true;
        }
        mc.settle();
        if !moved && !mc.osds[core].links[&link].conn.has_events() {
            return;
        }
    }
    panic!("client/OSD relay did not settle");
}

/// One MOSDOp frame sent by the client; the OSD's reply on the same link.
fn call(
    mc: &mut Mc,
    client: &mut Connection,
    core: usize,
    link: u64,
    tid: u64,
    op: MOSDOp,
) -> MOSDOpReply {
    let (ty, ver, compat, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
    client.send_message(msgr2::Message {
        tid,
        msg_type: ty,
        version: ver,
        compat_version: compat,
        front: segs.front,
        middle: segs.middle,
        data: segs.data,
        ..Default::default()
    });
    relay(mc, client, core, link);
    let mut reply = None;
    while let Some(e) = client.poll_event() {
        if let Event::Message(m) = e {
            let segs = Segments {
                front_zc: Vec::new(),
                front_hints: Default::default(),
                front: m.front.to_vec(),
                middle: m.middle.to_vec(),
                data: m.data,
            };
            match opwire::decode_client(m.header.msg_type, m.header.version, &segs) {
                Ok(ClientMsg::OpReply(r)) => reply = Some(r),
                other => panic!("unexpected reply {other:?}"),
            }
        }
    }
    reply.expect("the OSD answers the op")
}

/// A write above `osd_max_write_size` is answered -EMSGSIZE before its data segment is buffered: classic's reply
/// shape, no store effect, the link stays open and the next op on it succeeds (spec client-ops.md 5.4.1).
#[test]
fn an_oversized_write_is_refused_unadmitted_and_the_link_keeps_working() {
    const MB: usize = 1 << 20;
    let mut mc = Mc::new(1);
    mc.up();
    mc.osds[0]
        .conf
        .set(Level::Override, "osd_max_write_size", "4")
        .unwrap();
    mc.osds[0].refresh_obs_conf();
    let mut client = dial_client(&mc, 49010);
    let link = accept_client(&mut mc, 0, 49010);
    relay(&mut mc, &mut client, 0, link);
    assert!(mc.osds[0].links.contains_key(&link), "the link is up");

    // a small write over the same link (sanity: the wire path carries the payload)
    let op = mc.op(1, "plain-object", vec![OsdOp::write(0, vec![9; 512])]);
    let r = call(&mut mc, &mut client, 0, link, 90, op);
    assert_eq!(r.result, 0, "plain write first");

    // 5 MiB of payload into a 4 MiB limit: refused, the payload is never buffered
    let op = mc.op(1, "oversize-object", vec![OsdOp::write(0, vec![7; 5 * MB])]);
    let r = call(&mut mc, &mut client, 0, link, 91, op);
    assert_eq!(r.result, -opwire::errno::EMSGSIZE);
    assert_eq!(r.replay_version, denc::types::Eversion::default());
    assert_eq!(r.user_version, 0);
    assert_eq!(
        r.flags & u64::from(opwire::flag::ACK | opwire::flag::ONDISK),
        u64::from(opwire::flag::ACK | opwire::flag::ONDISK)
    );
    assert_eq!(r.ops.len(), 1, "the request ops are echoed");
    assert_eq!(r.ops[0].op, opwire::consts::op::WRITE);
    assert!(r.ops[0].indata.is_empty() && r.ops[0].outdata.is_empty());
    assert_eq!(r.ops[0].rval, 0);

    // nothing of the op happened: the object does not exist
    let stat = mc.op(1, "oversize-object", vec![OsdOp::stat()]);
    let r = call(&mut mc, &mut client, 0, link, 92, stat);
    assert_eq!(r.result, -opwire::errno::ENOENT);

    // the link is still open and the next write on it succeeds
    let op = mc.op(1, "oversize-object", vec![OsdOp::write(0, vec![9; 512])]);
    let r = call(&mut mc, &mut client, 0, link, 93, op);
    assert_eq!(r.result, 0);
    assert!(r.replay_version.version > 0, "the write was applied");
    let stat = mc.op(1, "oversize-object", vec![OsdOp::stat()]);
    let r = call(&mut mc, &mut client, 0, link, 94, stat);
    assert_eq!(r.result, 0);
}

/// A non-write MESSAGE above the link's admission cap is admitted alone and processed normally: no fault, no
/// -EMSGSIZE (spec msgr2.md 8.2). `cmpext` carries its expected bytes in the data segment.
#[test]
fn an_oversize_non_write_message_is_processed() {
    let mut mc = Mc::new(1);
    mc.up();
    mc.osds[0]
        .conf
        .set(Level::Override, "osd_client_message_size_cap", "1024")
        .unwrap();
    mc.osds[0].refresh_obs_conf();
    let mut client = dial_client(&mc, 49011);
    let link = accept_client(&mut mc, 0, 49011);
    relay(&mut mc, &mut client, 0, link);
    let op = mc.op(1, "cap-object", vec![OsdOp::write(0, vec![3; 4096])]);
    let r = call(&mut mc, &mut client, 0, link, 95, op);
    assert_eq!(r.result, 0);
    // 4 KiB of payload on a 1 KiB cap: admitted alone, the comparison runs normally
    let op = mc.op(1, "cap-object", vec![OsdOp::cmpext(0, vec![3; 4096])]);
    let r = call(&mut mc, &mut client, 0, link, 96, op);
    assert_eq!(r.result, 0);
    // the link is still up and keeps working
    let stat = mc.op(1, "cap-object", vec![OsdOp::stat()]);
    let r = call(&mut mc, &mut client, 0, link, 97, stat);
    assert_eq!(r.result, 0);
}
