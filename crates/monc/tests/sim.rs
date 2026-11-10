// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! In-memory simulation: MonClient <-> fake mons (msgr2 server connections, method NONE).
use cephx::none::parse_none_payload;
use denc::types::{EntityAddr, EntityAddrVec, EntityName, Uuid};
use messages::{
    AnyMessage, MConfig, MLogAck, MMonCommandAck, MMonGetVersionReply, MMonMap, MOSDMap,
};
use monc::{Config, IoCmd, MonClient, MonEvent, monmap_from_addrs};
use msgr2::auth::*;
use msgr2::{Connection, Event, Policy, PolicyTable, SessionTable};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

// Match the independently captured OSDMap fixtures used below.
const FSID: Uuid = Uuid([
    0x6d, 0x2f, 0x4f, 0x0e, 0x6e, 0x1a, 0x4a, 0x64, 0x9a, 0x55, 0x6e, 0x76, 0x6d, 0x65, 0x73, 0x6f,
]);
type FrameBytes = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[derive(Debug)]
struct FakeAuth;
impl AuthServerHandler for FakeAuth {
    fn supported_methods(&self, _: u8) -> Vec<u32> {
        vec![AUTH_METHOD_NONE]
    }
    fn supported_modes(&self, _: u8, _: u32) -> Vec<u32> {
        vec![MODE_CRC]
    }
    fn handle_auth_request(
        &mut self,
        _: u8,
        more: bool,
        method: u32,
        mode: u32,
        p: &[u8],
    ) -> AuthServerStep {
        if more || method != AUTH_METHOD_NONE || mode != MODE_CRC {
            return AuthServerStep::Reject(EOPNOTSUPP);
        }
        match parse_none_payload(p) {
            Ok((10, _, _)) => AuthServerStep::Done {
                reply: vec![],
                global_id: 777,
                peer_name: None,
                secrets: AuthSecrets::default(),
            },
            _ => AuthServerStep::Reject(-22),
        }
    }
}

struct Link {
    server: Connection,
    mon: usize,
}

struct Mon {
    up: bool,
    blackhole: bool,
    auto_cmd: bool,
    auto_logack: bool,
    table: SessionTable,
}

struct World {
    mc: MonClient,
    now: Duration,
    mons: Vec<Mon>,
    links: BTreeMap<u64, Link>,
    /// every message the mons received: (mon, tid, message)
    inbox: Vec<(usize, u64, AnyMessage)>,
    events: Vec<MonEvent>,
    dials: Vec<(u64, usize)>,
    next_srv: u64,
    wire_frames: Option<Vec<FrameBytes>>,
}

fn mon_addr(i: usize) -> EntityAddr {
    EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [10, 0, 0, 10 + i as u8], 3300)
}

fn cfg(n: usize) -> Config {
    let mut c = Config::new("osd.1", None);
    c.mon_host = (0..n).map(|i| EntityAddrVec::single(mon_addr(i))).collect();
    c.methods = vec![AUTH_METHOD_NONE];
    c.fsid = FSID;
    c.hostname = "h".into();
    c.seed = 42;
    c
}

impl World {
    fn new(n: usize) -> Self {
        Self::with(cfg(n), n)
    }
    fn with(c: Config, n: usize) -> Self {
        let mc = MonClient::new(c);
        let mons = (0..n)
            .map(|i| Mon {
                up: true,
                blackhole: false,
                auto_cmd: false,
                auto_logack: false,
                table: SessionTable::new(100 + i as u64),
            })
            .collect();
        World {
            mc,
            now: Duration::ZERO,
            mons,
            links: BTreeMap::new(),
            inbox: vec![],
            events: vec![],
            dials: vec![],
            next_srv: 1000,
            wire_frames: None,
        }
    }

    fn start(&mut self) {
        self.mc.start(self.now);
        self.step();
    }

    fn mon_of(target: &EntityAddr) -> usize {
        (target.ipv4().unwrap()[3] - 10) as usize
    }

    fn step(&mut self) {
        for _ in 0..10_000 {
            let mut moved = false;
            while let Some(io) = self.mc.poll_io() {
                moved = true;
                match io {
                    IoCmd::Dial { conn, target } => {
                        let m = Self::mon_of(&target);
                        self.links.remove(&conn);
                        self.dials.push((conn, m));
                        if self.mons[m].up {
                            self.next_srv += 1;
                            let scfg = msgr2::Config::new(
                                EntityName::new(EntityName::MON, m as i64),
                                EntityAddrVec::single(target),
                                PolicyTable::uniform(Policy::stateless_server(0)),
                            );
                            let server = Connection::server(
                                self.next_srv,
                                scfg,
                                self.mons[m].table.clone(),
                                Box::new(FakeAuth),
                                EntityAddr::v4(2, 0, [10, 0, 1, 1], 40000 + conn as u16),
                                self.now,
                            );
                            self.links.insert(conn, Link { server, mon: m });
                            self.mc.on_connected(conn, self.now);
                        } else {
                            self.mc.on_closed(conn, self.now);
                        }
                    }
                    IoCmd::Close { conn } => {
                        self.links.remove(&conn);
                    }
                }
            }
            for id in self.mc.conn_ids() {
                let out = self.mc.poll_output(id);
                if let Some(l) = self.links.get_mut(&id)
                    && !self.mons[l.mon].blackhole
                    && !out.is_empty()
                {
                    moved = true;
                    l.server.on_bytes(&out, self.now);
                }
            }
            let ids: Vec<u64> = self.links.keys().copied().collect();
            for id in ids {
                let (out, evs, mon) = {
                    let l = self.links.get_mut(&id).unwrap();
                    let out = l.server.poll_output();
                    let evs: Vec<Event> = std::iter::from_fn(|| l.server.poll_event()).collect();
                    (out, evs, l.mon)
                };
                if !out.is_empty() && !self.mons[mon].blackhole {
                    moved = true;
                    self.mc.on_bytes(id, &out, self.now);
                }
                for e in evs {
                    moved = true;
                    if let Event::Message(m) = e {
                        if let Some(frames) = &mut self.wire_frames {
                            frames.push((
                                m.header.to_bytes().to_vec(),
                                m.front.to_vec(),
                                m.middle.to_vec(),
                                m.data.to_vec(),
                            ));
                        }
                        let h = &m.header;
                        let msg = messages::decode_any(
                            h.msg_type, h.version, &m.front, &m.middle, &m.data,
                        )
                        .unwrap();
                        self.on_mon_message(mon, id, h.tid, msg);
                    }
                }
            }
            while let Some(e) = self.mc.poll_event() {
                moved = true;
                self.events.push(e);
            }
            if !moved {
                return;
            }
        }
        panic!("no quiescence");
    }

    fn on_mon_message(&mut self, mon: usize, link: u64, tid: u64, msg: AnyMessage) {
        let mut reply: Option<AnyMessage> = None;
        match &msg {
            AnyMessage::MMonGetVersion(g) => {
                reply = Some(
                    MMonGetVersionReply {
                        handle: g.handle,
                        version: 112,
                        oldest_version: 1,
                    }
                    .into(),
                );
            }
            AnyMessage::MMonCommand(_) if self.mons[mon].auto_cmd => {
                reply = Some(
                    MMonCommandAck {
                        version: 0,
                        r: 0,
                        rs: "ok".into(),
                        cmd: vec![],
                        data: b"out".to_vec(),
                    }
                    .into(),
                );
            }
            AnyMessage::MLog(l) if self.mons[mon].auto_logack => {
                reply = Some(
                    MLogAck {
                        fsid: FSID,
                        last: l.entries.last().unwrap().seq,
                        channel: l.entries[0].channel.clone(),
                    }
                    .into(),
                );
            }
            _ => {}
        }
        self.inbox.push((mon, tid, msg));
        if let Some(r) = reply {
            self.push_to(link, r, tid);
        }
    }

    fn push_to(&mut self, link: u64, m: AnyMessage, tid: u64) {
        let (ty, version, compat, segs) = m.encode(u64::MAX).unwrap();
        self.links
            .get_mut(&link)
            .unwrap()
            .server
            .send_message(msgr2::Message {
                msg_type: ty,
                tid,
                version,
                compat_version: compat,
                front: segs.front,
                middle: segs.middle,
                data: segs.data,
                ..Default::default()
            });
    }

    /// Push a message from the mon the client is currently connected to.
    fn push(&mut self, m: impl Into<AnyMessage>) {
        self.push_tid(m, 0);
    }
    fn push_tid(&mut self, m: impl Into<AnyMessage>, tid: u64) {
        let name = self.mc.current_mon().unwrap().to_owned();
        let mon = self.mc.monmap().rank_of(&name).unwrap();
        let link = *self
            .links
            .iter()
            .find(|(_, l)| l.mon == mon)
            .map(|(i, _)| i)
            .unwrap();
        self.push_to(link, m.into(), tid);
        self.step();
    }

    fn advance(&mut self, d: Duration) {
        let target = self.now + d;
        loop {
            let next = self
                .mc
                .next_timer()
                .map_or(target, |t| t.min(target))
                .max(self.now);
            self.now = next;
            self.mc.on_timer(self.now);
            self.step();
            if self.now >= target {
                break;
            }
        }
    }

    fn take_events(&mut self) -> Vec<MonEvent> {
        std::mem::take(&mut self.events)
    }

    fn connected_mon(&self) -> Option<&str> {
        self.mc.current_mon()
    }

    fn msgs<'a, T>(&'a self, mon: usize, f: impl Fn(&'a AnyMessage) -> Option<T>) -> Vec<T> {
        self.inbox
            .iter()
            .filter(|(m, _, _)| *m == mon)
            .filter_map(|(_, _, x)| f(x))
            .collect()
    }
}

fn authenticated(evs: &[MonEvent]) -> Vec<&str> {
    evs.iter()
        .filter_map(|e| {
            if let MonEvent::Authenticated { mon, .. } = e {
                Some(mon.as_str())
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn hunting_parallel_first_to_authenticate_wins() {
    let mut w = World::new(3);
    w.mons[0].up = false;
    w.mons[1].up = false;
    w.start();
    let evs = w.take_events();
    // all three were tried in parallel; only the live one wins; losers' sockets closed
    assert_eq!(w.dials.len(), 3);
    assert_eq!(authenticated(&evs), ["noname-c"]);
    assert_eq!(w.mc.global_id(), 777);
    assert_eq!(w.mc.num_conns(), 1);
    assert!(w.mc.is_connected());
    let id = *w.links.keys().next().unwrap();
    let view = w.mc.local_addresses().unwrap();
    assert_eq!(
        view.observed_by_peer().unwrap(),
        EntityAddr::v4(2, 0, [10, 0, 1, 1], 40000 + id as u16)
    );
    let advertised = view.advertised().next().unwrap();
    assert_eq!(advertised.ipv4(), Some([10, 0, 1, 1]));
    assert_eq!(advertised.port(), 0);
}

#[test]
fn hunting_sequential_with_backoff_until_a_mon_comes_up() {
    let mut c = cfg(3);
    c.hunt_parallel = 1;
    let mut w = World::with(c, 3);
    for m in &mut w.mons {
        m.up = false;
    }
    w.start();
    w.advance(secs(10));
    assert!(!w.mc.is_connected());
    // three distinct ranks tried first (tried set), then it wraps
    let first: BTreeSet<usize> = w
        .dials
        .iter()
        .map(|d| (d.0, d.1))
        .collect::<BTreeMap<_, _>>()
        .values()
        .copied()
        .take(3)
        .collect();
    assert_eq!(first.len(), 3, "{:?}", w.dials);
    w.mons[1].up = true;
    w.advance(secs(40));
    assert!(w.mc.is_connected());
    assert_eq!(w.mc.current_mon(), Some("noname-b"));
}

/// C8: a hunt round that ends without a session is a fired timeout (loud line, counted).
#[test]
fn unanswered_hunt_round_is_a_loud_timeout() {
    let mut c = cfg(1);
    c.hunt_parallel = 1;
    let mut w = World::with(c, 1);
    w.mons[0].blackhole = true;
    w.start();
    w.advance(secs(10));
    assert!(!w.mc.is_connected());
    let hunts = u64::from(w.mc.hunts());
    assert!(hunts >= 3, "hunts {hunts}");
    assert_eq!(w.mc.timeouts(), hunts - 1, "every finished round timed out");
}

#[test]
fn hunt_interval_backoff_is_capped() {
    let mut c = cfg(1);
    c.hunt_parallel = 1;
    let mut w = World::with(c, 1);
    w.mons[0].up = false;
    w.start();
    w.advance(secs(600));
    // intervals 3s * mult (1 -> x1.5 per hunt, but only after having connected once): no growth
    // before the first connect, so hunts ~ 600/3
    let h = w.mc.hunts();
    assert!(h >= 150, "hunts {h}");
    // connect once, drop the mon, now the multiplier grows up to 10x = 30 s
    w.mons[0].up = true;
    w.advance(secs(10));
    assert!(w.mc.is_connected());
    w.mons[0].up = false;
    let cid = *w.links.keys().next().unwrap();
    w.links.clear();
    w.mc.on_closed(cid, w.now);
    w.step();
    let before = w.mc.hunts();
    w.advance(secs(600));
    let n = w.mc.hunts() - before;
    assert!((15..=25).contains(&n), "hunts after reconnect loss {n}");
}

#[test]
fn rehunt_resends_subscriptions_and_commands_and_fails_versions() {
    let mut w = World::new(2);
    w.start();
    let first = w.connected_mon().unwrap().to_owned();
    let fm = w.mc.monmap().rank_of(&first).unwrap();
    w.mc.subscribe("osdmap", 5, 1);
    w.step();
    let t1 = w.mc.send_command(r#"{"prefix":"status"}"#, vec![]);
    let t2 =
        w.mc.send_command(r#"{"prefix":"osd new"}"#, b"secret".to_vec());
    w.step();
    assert_eq!(
        w.msgs(fm, |m| matches!(m, AnyMessage::MMonCommand(_))
            .then_some(()))
            .len(),
        2
    );
    w.mons[fm].blackhole = true; // the version request is never answered
    let h = w.mc.get_version("osdmap").unwrap();
    w.step();
    w.mons[fm].blackhole = false;
    w.take_events();
    let previous_advertisement =
        w.mc.local_addresses()
            .unwrap()
            .advertised()
            .collect::<Vec<_>>();
    // the connected mon dies
    w.mons[fm].up = false;
    let cid = *w.links.keys().next().unwrap();
    w.links.clear();
    w.mc.on_closed(cid, w.now);
    assert!(w.mc.local_addresses().is_none());
    w.step();
    let evs = w.take_events();
    assert!(evs.iter().any(|e| matches!(e, MonEvent::SessionLost(_))));
    assert!(
        evs.iter()
            .any(|e| matches!(e, MonEvent::VersionFailed { handle } if *handle == h))
    );
    assert_eq!(
        w.mc.local_addresses()
            .unwrap()
            .advertised()
            .collect::<Vec<_>>(),
        previous_advertisement
    );
    let other = 1 - fm;
    assert_eq!(authenticated(&evs).len(), 1, "{evs:?}");
    assert_eq!(
        w.mc.monmap().rank_of(w.connected_mon().unwrap()),
        Some(other)
    );
    // new mon got: one MMonSubscribe with everything, and the same two commands with the same tids
    let subs = w.msgs(other, |m| {
        if let AnyMessage::MMonSubscribe(s) = m {
            Some(s)
        } else {
            None
        }
    });
    assert_eq!(subs.len(), 1);
    let keys: Vec<&String> = subs[0].what.keys().collect();
    assert_eq!(keys, ["config", "monmap", "osdmap"]);
    assert_eq!(subs[0].what["osdmap"].start, 5);
    assert_eq!(subs[0].what["osdmap"].flags, 1);
    assert_eq!(subs[0].hostname, "h");
    let cmds: Vec<(u64, String, Vec<u8>)> = w
        .inbox
        .iter()
        .filter(|(m, _, x)| *m == other && matches!(x, AnyMessage::MMonCommand(_)))
        .map(|(_, t, x)| match x {
            AnyMessage::MMonCommand(c) => (*t, c.cmd[0].clone(), c.data.clone()),
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(cmds.len(), 2);
    assert_eq!((cmds[0].0, cmds[1].0), (t1, t2));
    assert_eq!(cmds[1].2, b"secret");
    // reply arrives once, by tid
    w.push_tid(
        MMonCommandAck {
            version: 0,
            r: 0,
            rs: "done".into(),
            cmd: vec![],
            data: b"x".to_vec(),
        },
        t2,
    );
    let evs = w.take_events();
    assert!(evs.iter().any(
        |e| matches!(e, MonEvent::CommandReply { tid, rs, .. } if *tid == t2 && rs == "done")
    ));
    // t1 still outstanding: tid 0 acks the oldest
    w.push_tid(
        MMonCommandAck {
            version: 0,
            r: -2,
            rs: "".into(),
            cmd: vec![],
            data: vec![],
        },
        0,
    );
    let evs = w.take_events();
    assert!(
        evs.iter()
            .any(|e| matches!(e, MonEvent::CommandReply { tid, r, .. } if *tid == t1 && *r == -2))
    );
    // no more outstanding: a stray ack is a diagnostic only
    w.push_tid(MMonCommandAck::default(), 99);
    let evs = w.take_events();
    assert!(
        evs.iter()
            .all(|e| !matches!(e, MonEvent::CommandReply { .. }))
    );
}

#[test]
fn commands_issued_before_session_are_sent_on_open() {
    let mut w = World::new(1);
    w.mons[0].auto_cmd = true;
    let t = w.mc.send_command(r#"{"prefix":"status"}"#, vec![]);
    w.start();
    let evs = w.take_events();
    assert!(evs.iter().any(
        |e| matches!(e, MonEvent::CommandReply { tid, data, .. } if *tid == t && data == b"out")
    ));
}

#[test]
fn oversized_commands_complete_once_without_blocking_the_session_or_replaying() {
    let mut config = cfg(1);
    config.frame_limits.max_segment = 4096;
    let mut w = World::with(config, 1);
    // Check queued-before-connect and already-connected submission.
    let queued = w.mc.send_command(r#"{"prefix":"status"}"#, vec![0; 4097]);
    w.start();
    let connected = w.mc.send_command(r#"{"prefix":"status"}"#, vec![0; 4097]);
    w.step();
    let events = w.take_events();
    for tid in [queued, connected] {
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event,
                    MonEvent::CommandReply { tid: reply_tid, r, .. }
                        if *reply_tid == tid && *r == -denc::errno::EMSGSIZE
                ))
                .count(),
            1,
            "permanent local rejection must complete tid {tid}"
        );
    }
    assert!(w.mc.is_connected());
    assert!(
        w.msgs(0, |message| matches!(message, AnyMessage::MMonCommand(_))
            .then_some(()))
            .is_empty()
    );
    w.mons[0].auto_cmd = true;
    let small = w.mc.send_command(r#"{"prefix":"status"}"#, vec![]);
    w.step();
    assert!(w.take_events().iter().any(|event| matches!(event,
        MonEvent::CommandReply { tid, r: 0, .. } if *tid == small
    )));
    w.mc.rehunt("oversized command replay regression");
    w.step();
    w.advance(secs(10));
    assert!(w.mc.is_connected());
    assert!(!w.take_events().iter().any(|event| matches!(event,
        MonEvent::CommandReply { tid, .. } if [queued, connected].contains(tid)
    )));
    assert!(
        !w.inbox
            .iter()
            .any(|(_, tid, _)| [queued, connected].contains(tid))
    );
}

#[test]
fn command_without_fsid_waits_for_monmap() {
    let mut c = cfg(1);
    c.fsid = Uuid::default();
    let mut w = World::with(c, 1);
    let t = w.mc.send_command(r#"{"prefix":"status"}"#, vec![]);
    w.start();
    assert!(
        w.msgs(0, |m| matches!(m, AnyMessage::MMonCommand(_)).then_some(()))
            .is_empty()
    );
    let mut mm = monmap_from_addrs(&[EntityAddrVec::single(mon_addr(0))]);
    mm.fsid = FSID;
    mm.epoch = 1;
    mm.mon_info.get_mut("noname-a").unwrap().name = "noname-a".into();
    w.push(MMonMap {
        monmap: mm.encode_to().unwrap(),
    });
    let cmds = w.msgs(0, |m| {
        if let AnyMessage::MMonCommand(c) = m {
            Some(c.fsid)
        } else {
            None
        }
    });
    assert_eq!(cmds, [FSID]);
    let _ = t;
}

#[test]
fn keepalive_and_timeout_rehunt() {
    let mut w = World::new(1);
    w.start();
    w.take_events();
    w.advance(secs(25));
    // keepalives flow and are acked while the mon is alive
    assert!(w.mc.keepalive_acks() >= 2, "{}", w.mc.keepalive_acks());
    assert!(w.mc.is_connected());
    // mon goes silent: no ack within ping_timeout (30 s) -> session lost, re-hunt
    w.mons[0].blackhole = true;
    w.advance(secs(35));
    let evs = w.take_events();
    assert!(
        evs.iter()
            .any(|e| matches!(e, MonEvent::SessionLost(s) if s.contains("keepalive"))),
        "{evs:?}"
    );
    assert!(!w.mc.is_connected());
    w.mons[0].blackhole = false;
    w.advance(secs(10));
    assert!(w.mc.is_connected());
}

#[test]
fn delayed_ack_does_not_acknowledge_newer_keepalives() {
    let mut w = World::new(1);
    w.start();
    w.take_events();
    let id = w.mc.conn_ids()[0];
    w.now = secs(10);
    w.mc.on_timer(w.now);
    let ping = w.mc.poll_output(id);
    let link = w.links.get_mut(&id).unwrap();
    link.server.on_bytes(&ping, w.now);
    let delayed_ack = link.server.poll_output();
    assert!(!delayed_ack.is_empty());
    // More probes are sent while the reverse path is blocked. Only the first
    // probe's ACK eventually arrives; it cannot confirm those newer probes.
    w.mons[0].blackhole = true;
    w.advance(secs(25));
    w.mc.on_bytes(id, &delayed_ack, w.now);
    w.advance(secs(5));
    assert!(w.take_events().iter().any(
        |event| matches!(event, MonEvent::SessionLost(reason) if reason.contains("keepalive"))
    ));
}

#[test]
fn delayed_keepalive_acks_advance_liveness_without_false_expiry() {
    let mut w = World::new(1);
    w.start();
    w.take_events();
    let id = w.mc.conn_ids()[0];
    let mut delayed = std::collections::VecDeque::new();
    for second in 1..=65 {
        w.now = secs(second);
        w.mc.on_timer(w.now);
        let ping = w.mc.poll_output(id);
        let link = w.links.get_mut(&id).unwrap();
        if !ping.is_empty() {
            link.server.on_bytes(&ping, w.now);
        }
        let ack = link.server.poll_output();
        if !ack.is_empty() {
            delayed.push_back((w.now + secs(15), ack));
        }
        while delayed.front().is_some_and(|(due, _)| *due <= w.now) {
            let (_, ack) = delayed.pop_front().unwrap();
            w.mc.on_bytes(id, &ack, w.now);
        }
        assert!(w.mc.is_connected(), "session expired at {second}");
    }
    assert!(w.mc.keepalive_acks() >= 5);
}

#[test]
fn driver_stall_longer_than_ping_timeout_is_not_a_lost_session() {
    let mut w = World::new(1);
    w.start();
    w.take_events();
    w.advance(secs(5));
    let acks = w.mc.keepalive_acks();
    // the driver does not run the client for 3x ping_timeout (busy caller): nothing was sent,
    // so no ack can be missing; the first tick afterwards pings and the ack arrives
    w.now += secs(100);
    w.mc.on_timer(w.now);
    w.step();
    w.advance(secs(2));
    let evs = w.take_events();
    assert!(
        !evs.iter().any(|e| matches!(e, MonEvent::SessionLost(_))),
        "{evs:?}"
    );
    assert!(w.mc.is_connected());
    assert!(w.mc.keepalive_acks() > acks);
}

#[test]
fn subscription_renewal_interval_resends_everything() {
    let mut c = cfg(1);
    c.sub_renew_interval = Some(secs(100));
    let mut w = World::with(c, 1);
    w.start();
    w.mc.subscribe("mgrmap", 0, 0);
    w.step();
    let n = |w: &World| {
        w.msgs(0, |m| {
            matches!(m, AnyMessage::MMonSubscribe(_)).then_some(())
        })
        .len()
    };
    assert_eq!(n(&w), 2); // session open + mgrmap
    // identical re-subscribe is a no-op
    w.mc.subscribe("mgrmap", 0, 0);
    w.step();
    assert_eq!(n(&w), 2);
    w.advance(secs(101));
    assert_eq!(n(&w), 3);
    let last = w.msgs(0, |m| {
        if let AnyMessage::MMonSubscribe(s) = m {
            Some(s.what.len())
        } else {
            None
        }
    });
    assert_eq!(*last.last().unwrap(), 3); // config, monmap, mgrmap
}

#[test]
fn stateful_subscription_got_semantics() {
    let mut w = World::new(1);
    w.start();
    // monmap is a standing sub starting at 0 for an unknown map; after a map arrives it moves to epoch+1
    let mut mm = monmap_from_addrs(&[EntityAddrVec::single(mon_addr(0))]);
    mm.fsid = FSID;
    mm.epoch = 3;
    w.push(MMonMap {
        monmap: mm.encode_to().unwrap(),
    });
    let evs = w.take_events();
    assert!(
        evs.iter()
            .any(|e| matches!(e, MonEvent::MonMapUpdated { epoch: 3 }))
    );
    // a session reopen now asks for monmap start 4
    w.mons[0].up = true;
    w.mc.rehunt("test");
    w.step();
    w.advance(secs(1));
    let subs = w.msgs(0, |m| {
        if let AnyMessage::MMonSubscribe(s) = m {
            Some(s.what["monmap"].start)
        } else {
            None
        }
    });
    assert_eq!(subs.last(), Some(&4));
}

#[test]
fn mon_not_in_new_monmap_reopens_session() {
    let mut w = World::new(2);
    w.start();
    w.take_events();
    let cur = w.mc.current_mon().unwrap().to_owned();
    let keep = if cur == "noname-a" { 1 } else { 0 };
    let mut mm = monmap_from_addrs(&[EntityAddrVec::single(mon_addr(keep))]);
    mm.epoch = 5;
    mm.fsid = FSID;
    w.push(MMonMap {
        monmap: mm.encode_to().unwrap(),
    });
    w.advance(secs(1));
    let evs = w.take_events();
    assert!(
        evs.iter()
            .any(|e| matches!(e, MonEvent::MonMapUpdated { epoch: 5 }))
    );
    assert!(evs.iter().any(|e| matches!(e, MonEvent::SessionLost(_))));
    assert!(w.mc.is_connected());
    assert_eq!(w.mc.monmap().num_mons(), 1);
}

#[test]
fn config_replace_semantics_and_filtering() {
    let mut w = World::new(1);
    w.start();
    w.take_events();
    let mk = |kv: &[(&str, &str)]| MConfig {
        config: kv
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    };
    w.push(mk(&[
        ("osd_max_backfills", "3"),
        ("fsid", "x"),
        ("host", "y"),
    ]));
    let evs = w.take_events();
    let got: Vec<&BTreeMap<String, String>> = evs
        .iter()
        .filter_map(|e| {
            if let MonEvent::Config(c) = e {
                Some(c)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].len(), 1);
    // identical set again: no event; replaced set drops the old key
    w.push(mk(&[("osd_max_backfills", "3")]));
    assert!(
        w.take_events()
            .iter()
            .all(|e| !matches!(e, MonEvent::Config(_)))
    );
    w.push(mk(&[("osd_recovery_sleep", "1")]));
    assert_eq!(
        w.mc.config().keys().collect::<Vec<_>>(),
        ["osd_recovery_sleep"]
    );
}

#[test]
fn cluster_log_sent_acked_and_resent_after_rehunt() {
    let mut w = World::new(1);
    w.start();
    w.mc.log(1, "cluster", "one");
    w.mc.log(3, "cluster", "two");
    w.advance(secs(2));
    let logs = |w: &World| {
        w.msgs(0, |m| {
            if let AnyMessage::MLog(l) = m {
                Some(l.entries.iter().map(|e| e.seq).collect::<Vec<_>>())
            } else {
                None
            }
        })
    };
    assert_eq!(logs(&w), [vec![1, 2]]);
    // unacked: after a rehunt it is sent again
    w.mc.rehunt("test");
    w.step();
    w.advance(secs(2));
    assert_eq!(logs(&w), [vec![1, 2], vec![1, 2]]);
    // ack seq 1 only -> a further session only resends seq 2
    w.push(MLogAck {
        fsid: FSID,
        last: 1,
        channel: "cluster".into(),
    });
    w.mc.rehunt("test");
    w.step();
    w.advance(secs(2));
    assert_eq!(*logs(&w).last().unwrap(), vec![2]);
    w.mons[0].auto_logack = true;
    w.mc.log(1, "cluster", "three");
    w.advance(secs(2));
    w.mc.rehunt("test");
    w.step();
    w.advance(secs(2));
    // everything acked -> nothing resent
    assert_eq!(logs(&w).len(), 4);
}

#[test]
fn get_version_roundtrip() {
    let mut w = World::new(1);
    assert!(w.mc.get_version("osdmap").is_none());
    w.start();
    w.take_events();
    let h = w.mc.get_version("osdmap").unwrap();
    w.step();
    let evs = w.take_events();
    assert!(evs.iter().any(
        |e| matches!(e, MonEvent::VersionReply { handle, version: 112, oldest: 1 } if *handle == h)
    ));
}

// ---- osdmap feeding (real reference-cluster maps, epochs 1..91) ----

fn td() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/osdmap")
}
fn blob(kind: &str, e: u32) -> Vec<u8> {
    std::fs::read(td().join(kind).join(format!("{e:04}.bin"))).unwrap()
}
fn mosdmap(incs: &[u32], fulls: &[u32], newest: u32) -> MOSDMap {
    MOSDMap {
        fsid: FSID,
        incremental_maps: incs.iter().map(|e| (*e, blob("inc", *e))).collect(),
        maps: fulls.iter().map(|e| (*e, blob("full", *e))).collect(),
        cluster_osdmap_trim_lower_bound: 1,
        newest_map: newest,
    }
}
fn epoch(w: &World) -> u32 {
    w.mc.osdmap().map_or(0, |m| m.epoch)
}
fn osdmap_subs(w: &World) -> Vec<(u64, u8)> {
    w.msgs(0, |m| match m {
        AnyMessage::MMonSubscribe(s) => s.what.get("osdmap").map(|i| (i.start, i.flags)),
        _ => None,
    })
}

#[test]
fn osdmap_full_incs_gap_and_crc_recovery() {
    let mut w = World::new(1);
    w.start();
    w.mc.subscribe("osdmap", 0, 0);
    w.step();
    w.take_events();
    assert_eq!(osdmap_subs(&w), [(0, 0)]);

    // full 10 (mon says newest is 91): applied, and the client asks to continue from 11
    w.push(mosdmap(&[], &[10], 91));
    assert_eq!(epoch(&w), 10);
    assert_eq!(
        osdmap_subs(&w).last(),
        Some(&(11, 0)),
        "standing flavour kept"
    );
    let evs = w.take_events();
    assert!(
        evs.iter()
            .any(|e| matches!(e, MonEvent::OsdMap { epoch: 10, .. }))
    );

    // incrementals 11..14 chain with crc verification
    w.push(mosdmap(&[11, 12, 13, 14], &[], 91));
    assert_eq!(epoch(&w), 14);
    assert_eq!(
        w.mc.osdmap().unwrap().crc(0).unwrap(),
        osdmap::OsdMap::decode_from(&blob("full", 14))
            .unwrap()
            .crc(0)
            .unwrap()
    );

    // gap: 17,18 without 15,16 -> no progress; the request from 15 is already outstanding
    assert_eq!(osdmap_subs(&w).last(), Some(&(15, 0)));
    let n = osdmap_subs(&w).len();
    w.push(mosdmap(&[17, 18], &[], 91));
    assert_eq!(epoch(&w), 14);
    w.push(mosdmap(&[17, 18], &[], 91));
    assert_eq!(osdmap_subs(&w).len(), n, "duplicate request suppressed");
    w.push(mosdmap(&[15, 16, 17, 18], &[], 91));
    assert_eq!(epoch(&w), 18);

    // corrupted incremental (bad inc crc) -> request that full epoch explicitly
    let mut bad = mosdmap(&[19], &[], 91);
    let b = bad.incremental_maps.get_mut(&19).unwrap();
    let mid = b.len() / 2;
    b[mid] ^= 0xff;
    w.push(bad);
    assert_eq!(epoch(&w), 18);
    let reqs = w.msgs(0, |m| {
        if let AnyMessage::MMonGetOSDMap(g) = m {
            Some((g.full_first, g.full_last))
        } else {
            None
        }
    });
    assert_eq!(reqs, [(19, 19)]);
    let evs = w.take_events();
    assert!(
        evs.iter()
            .any(|e| matches!(e, MonEvent::Diag(s) if s.contains("osdmap inc 19")))
    );
    // the full arrives, then the chain continues
    w.push(mosdmap(&[], &[19], 91));
    assert_eq!(epoch(&w), 19);
    w.push(mosdmap(&[20], &[], 91));
    assert_eq!(epoch(&w), 20);
    // stale duplicates change nothing and emit nothing
    w.take_events();
    w.push(mosdmap(&[19, 20], &[], 91));
    assert_eq!(epoch(&w), 20);
    assert!(
        w.take_events()
            .iter()
            .all(|e| !matches!(e, MonEvent::OsdMap { .. }))
    );
}

#[test]
fn osdmap_from_scratch_via_incrementals_and_onetime_sub_completes() {
    let mut w = World::new(1);
    w.start();
    w.mc.subscribe("osdmap", 1, messages::SubItem::ONETIME);
    w.step();
    let all: Vec<u32> = (1..=40).collect();
    w.push(mosdmap(&all, &[], 40));
    assert_eq!(epoch(&w), 40);
    // newest == epoch and onetime sub satisfied: no further request
    assert_eq!(osdmap_subs(&w), [(1, 1)]);
}

#[test]
fn passthrough_of_other_messages() {
    let mut w = World::new(1);
    w.start();
    w.take_events();
    w.push(AnyMessage::Unknown {
        ty: 0x7ff,
        version: 1,
        compat: 1,
        segments: messages::Segments::front(vec![1, 2, 3]),
    });
    let evs = w.take_events();
    assert!(evs.iter().any(|e| matches!(e, MonEvent::Message { msg, .. } if matches!(**msg, AnyMessage::Unknown { ty: 0x7ff, .. }))));
    assert!(w.mc.is_connected());
}

/// Regression (holes in croit-flashstore-osd's stored map history, PGs removed at boot): two MOSDMaps in one read. The re-subscribe
/// after the first drained the connection and handled the second re-entrantly, so the first event came out SECOND and
/// carried the newer map; the OSD skipped it as old and never stored its epochs. Events: in order, each with its own map.
#[test]
fn osdmap_events_of_one_batch_each_carry_their_own_map() {
    let mut w = World::new(1);
    w.start();
    w.mc.subscribe("osdmap", 0, 0);
    w.step();
    w.push(mosdmap(&[], &[10], 91));
    w.take_events();
    let name = w.mc.current_mon().unwrap().to_owned();
    let mon = w.mc.monmap().rank_of(&name).unwrap();
    let link = *w.links.iter().find(|(_, l)| l.mon == mon).unwrap().0;
    w.push_to(link, mosdmap(&[11, 12], &[], 91).into(), 0);
    w.push_to(link, mosdmap(&[13, 14], &[], 91).into(), 0);
    w.step();
    assert_eq!(epoch(&w), 14);
    let got: Vec<(u32, u32, u32)> = w
        .take_events()
        .into_iter()
        .filter_map(|e| match e {
            MonEvent::OsdMap { epoch, map, .. } => Some((epoch, map.epoch, map.crc(0).unwrap())),
            _ => None,
        })
        .collect();
    let crc = |e: u32| {
        osdmap::OsdMap::decode_from(&blob("full", e))
            .unwrap()
            .crc(0)
            .unwrap()
    };
    assert_eq!(got, [(12, 12, crc(12)), (14, 14, crc(14))]);
}

/// Spec osd-lifecycle 3.5 step 1: a MOSDMap of another cluster is dropped before it touches the held map (the OSD would
/// otherwise persist and act on a foreign map and ask that cluster for further epochs).
#[test]
fn osdmap_from_a_foreign_fsid_is_dropped_without_progress() {
    let mut w = World::new(1);
    w.start();
    w.mc.subscribe("osdmap", 0, 0);
    w.step();
    w.take_events();
    let mut foreign = mosdmap(&[], &[10], 10);
    foreign.fsid = Uuid([9; 16]);
    w.push(foreign);
    assert_eq!(epoch(&w), 0);
    let evs = w.take_events();
    assert!(
        evs.iter().all(|e| !matches!(e, MonEvent::OsdMap { .. })),
        "{evs:?}"
    );
    assert!(
        evs.iter()
            .any(|e| matches!(e, MonEvent::Diag(s) if s.contains("osdmap") && s.contains("fsid"))),
        "{evs:?}"
    );
    // the matching cluster's map is still accepted afterwards
    w.push(mosdmap(&[], &[10], 10));
    assert_eq!(epoch(&w), 10);
}

/// A full map past a gap the mon still has is not taken (the gap is fetched first: a skipped epoch would be a hole in an
/// OSD's stored history); past a gap the mon trimmed it is (classic skip_maps).
#[test]
fn osdmap_full_past_a_gap_only_when_the_mon_trimmed_the_gap() {
    let mut w = World::new(1);
    w.start();
    w.mc.subscribe("osdmap", 0, 0);
    w.step();
    w.push(mosdmap(&[], &[10], 91));
    w.take_events();
    w.push(mosdmap(&[], &[14], 91)); // trim bound 1: 11..13 still at the mon
    assert_eq!(epoch(&w), 10);
    assert_eq!(osdmap_subs(&w).last(), Some(&(11, 0)));
    let mut m = mosdmap(&[], &[14], 91);
    m.cluster_osdmap_trim_lower_bound = 14; // trimmed: 11..13 are gone for good
    w.push(m);
    assert_eq!(epoch(&w), 14);
}

fn full_reqs(w: &World) -> Vec<(u32, u32)> {
    w.msgs(0, |m| match m {
        AnyMessage::MMonGetOSDMap(g) => Some((g.full_first, g.full_last)),
        _ => None,
    })
}

/// Inc with a valid inc_crc but a full_crc no local re-encode reproduces (as a mon with an unknown encoding).
fn poisoned_inc(e: u32) -> Vec<u8> {
    let mut i = osdmap::Incremental::decode_from(&blob("inc", e)).unwrap();
    i.full_crc ^= 1;
    i.encode_inc().unwrap()
}

#[test]
fn osdmap_full_crc_mismatch_stream_never_wedges() {
    let mut w = World::new(1);
    w.start();
    w.mc.subscribe("osdmap", 0, 0);
    w.step();
    w.push(mosdmap(&[], &[10], 20));
    assert_eq!(epoch(&w), 10);

    // every inc of the message mismatches: classic fallback = the full maps of the rest of the message
    let mut m = mosdmap(&[], &[], 20);
    for e in 11..=15 {
        m.incremental_maps.insert(e, poisoned_inc(e));
    }
    w.push(m);
    assert_eq!(epoch(&w), 10);
    assert_eq!(full_reqs(&w), [(11, 15)]);
    assert_eq!(w.mc.osdmap_inc_fallbacks(), 1);

    // never re-sent by time: the mon answers every request of a live session
    w.advance(secs(12));
    assert_eq!(full_reqs(&w), [(11, 15)]);
    // the session resets before the answer: the new session subscribes from 11 again, the incs fail again and ask
    // anew (classic re-requests its full maps on a mon reconnect)
    let n = osdmap_subs(&w).len();
    let cid = *w.links.keys().next().unwrap();
    w.links.clear();
    w.mc.on_closed(cid, w.now);
    w.step();
    w.advance(secs(10));
    assert!(w.mc.is_connected());
    assert_eq!(osdmap_subs(&w)[n..].last().map(|s| s.0), Some(11));
    let mut m = mosdmap(&[], &[], 20);
    for e in 11..=15 {
        m.incremental_maps.insert(e, poisoned_inc(e));
    }
    w.push(m);
    assert_eq!(full_reqs(&w), [(11, 15), (11, 15)]);
    assert_eq!(w.mc.osdmap_inc_fallbacks(), 2);

    // fulls arrive: applied, then the stream continues from 16 (re-subscribe)
    let n = osdmap_subs(&w).len();
    w.push(mosdmap(&[], &[11, 12, 13, 14, 15], 20));
    assert_eq!(epoch(&w), 15);
    assert_eq!(osdmap_subs(&w)[n..].last(), Some(&(16, 0)));

    // a later poisoned inc in the middle of good ones: good prefix applied, full fetch for the rest
    let mut m = mosdmap(&[16, 18], &[], 20);
    m.incremental_maps.insert(17, poisoned_inc(17));
    w.push(m);
    assert_eq!(epoch(&w), 16);
    assert_eq!(full_reqs(&w).last(), Some(&(17, 18)));
    w.push(mosdmap(&[], &[17, 18], 20));
    w.push(mosdmap(&[19, 20], &[], 20));
    assert_eq!(epoch(&w), 20);
    assert_eq!(w.mc.osdmap_inc_fallbacks(), 3);
    // no retry after progress
    let k = full_reqs(&w).len();
    w.advance(secs(12));
    assert_eq!(full_reqs(&w).len(), k);
}

/// A requested full map that does not decode ends the request: it is not asked again from its own answer (the mon
/// returns the same bytes), and the next mon push asks anew instead of being swallowed by the dedup of a request that
/// was already answered.
#[test]
fn osdmap_undecodable_full_ends_the_request_and_the_next_push_asks_again() {
    let mut w = World::new(1);
    w.start();
    w.mc.subscribe("osdmap", 0, 0);
    w.step();
    w.push(mosdmap(&[], &[10], 20));
    assert_eq!(epoch(&w), 10);
    let mut m = mosdmap(&[], &[], 20);
    m.incremental_maps.insert(11, poisoned_inc(11));
    w.push(m);
    assert_eq!(full_reqs(&w), [(11, 11)]);
    w.take_events();

    // the answer's full map is corrupt (crc): loud, no ask from its own answer, nothing by time
    let subs = osdmap_subs(&w).len();
    let mut bad = mosdmap(&[], &[11], 20);
    let b = bad.maps.get_mut(&11).unwrap();
    let mid = b.len() / 2;
    b[mid] ^= 0xff;
    w.push(bad);
    assert_eq!(epoch(&w), 10);
    assert!(
        w.take_events()
            .iter()
            .any(|e| matches!(e, MonEvent::Diag(s) if s.contains("osdmap full 11")))
    );
    // C7: the owner learns that it cannot follow the cluster (the OSD stops)
    assert_eq!(w.mc.undecodable_osdmap().map(|u| u.0), Some(11));
    w.advance(secs(12));
    assert_eq!(full_reqs(&w), [(11, 11)]);
    assert_eq!(osdmap_subs(&w).len(), subs);

    // the mon publishes 12: the gap asks from 11 again, the failing inc asks for the fulls again
    w.push(mosdmap(&[12], &[], 20));
    assert_eq!(osdmap_subs(&w).last(), Some(&(11, 0)));
    assert!(osdmap_subs(&w).len() > subs);
    let mut m = mosdmap(&[12], &[], 20);
    m.incremental_maps.insert(11, poisoned_inc(11));
    w.push(m);
    assert_eq!(full_reqs(&w), [(11, 11), (11, 12)]);
    w.push(mosdmap(&[], &[11, 12], 20));
    assert_eq!(epoch(&w), 12);
    assert!(w.mc.undecodable_osdmap().is_none());
}

#[test]
fn cluster_logs_wait_for_discovered_fsid_and_resume_without_new_logs() {
    let mut c = cfg(1);
    c.fsid = Uuid::default();
    let mut w = World::with(c, 1);
    w.mc.log(1, "cluster", "queued before authentication");
    w.start();
    let logs = w.msgs(0, |m| match m {
        AnyMessage::MLog(l) => Some(l),
        _ => None,
    });
    println!(
        "unknown-fsid clean-main received logs={} fsids={:?}",
        logs.len(),
        logs.iter().map(|l| l.fsid).collect::<Vec<_>>()
    );
    assert!(
        logs.is_empty(),
        "MLog must not carry an unknown cluster FSID"
    );
    assert!(
        !w.msgs(0, |m| matches!(m, AnyMessage::MMonSubscribe(_))
            .then_some(()))
            .is_empty(),
        "FSID discovery subscription must remain live"
    );
    w.mc.log(2, "cluster", "queued while awaiting monmap");
    w.advance(Duration::from_secs(1));
    assert!(
        w.msgs(0, |m| matches!(m, AnyMessage::MLog(_)).then_some(()))
            .is_empty()
    );
    let mut map = monmap_from_addrs(&[EntityAddrVec::single(mon_addr(0))]);
    map.fsid = FSID;
    map.epoch = 1;
    w.push(MMonMap {
        monmap: map.encode_to().unwrap(),
    });
    let logs = w.msgs(0, |m| match m {
        AnyMessage::MLog(l) => Some(l),
        _ => None,
    });
    assert_eq!(
        logs.len(),
        1,
        "discovery must flush retained logs without another log/timer"
    );
    assert_eq!(logs[0].fsid, FSID);
    assert_eq!(
        logs[0]
            .entries
            .iter()
            .map(|e| (e.seq, e.msg.as_str()))
            .collect::<Vec<_>>(),
        [
            (1, "queued before authentication"),
            (2, "queued while awaiting monmap")
        ]
    );
}

#[test]
fn generic_zero_fsid_log_is_rejected_without_blocking_messages_without_fsid() {
    let mut w = World::new(1);
    w.start();
    assert!(w.mc.send_message(messages::MLog::default()).is_none());
    assert_eq!(
        w.mc.get_version("osdmap"),
        Some(3),
        "rejection preserves the existing allocation-of-failed-send TID semantics"
    );
    assert_eq!(
        w.mc.send_message(messages::MMonGetOSDMap::default()),
        Some(4)
    );
    w.step();
    assert!(
        w.msgs(0, |m| matches!(m, AnyMessage::MLog(_)).then_some(()))
            .is_empty()
    );
    assert!(
        !w.msgs(0, |m| matches!(m, AnyMessage::MMonGetVersion(_))
            .then_some(()))
            .is_empty()
    );
    assert!(
        !w.msgs(0, |m| matches!(m, AnyMessage::MMonGetOSDMap(_))
            .then_some(()))
            .is_empty()
    );
}

/// Print a deterministic known-FSID startup transcript for before/after byte
/// comparison; the decoded messages are encoded with the fixture's all-feature
/// peer mask. No connection scheduling or budget code participates.
#[test]
fn known_fsid_startup_transcript_remains_ordered() {
    let mut w = World::new(1);
    w.wire_frames = Some(Vec::new());
    let first = w.mc.send_command(r#"{"prefix":"status","i":1}"#, vec![11]);
    let second = w.mc.send_command(r#"{"prefix":"status","i":2}"#, vec![22]);
    w.mc.log(1, "cluster", "known fsid startup");
    w.start();
    let transcript: Vec<_> = w
        .inbox
        .iter()
        .map(|(_, tid, msg)| {
            let (ty, version, compat, segs) = msg.encode(u64::MAX).unwrap();
            (
                ty,
                *tid,
                version,
                compat,
                segs.front,
                segs.middle,
                segs.data,
            )
        })
        .collect();
    assert_eq!(
        transcript
            .iter()
            .map(|(ty, tid, ..)| (*ty, *tid))
            .collect::<Vec<_>>(),
        [(15, 3), (50, first), (50, second), (52, 4)]
    );
    println!("known-fsid transcript {transcript:?}");
    println!("known-fsid raw frames {:?}", w.wire_frames.unwrap());
}

#[test]
fn zero_fsid_monmap_keeps_logs_held_until_later_valid_map() {
    let mut c = cfg(1);
    c.fsid = Uuid::default();
    let mut w = World::with(c, 1);
    w.mc.log(1, "cluster", "held through an incomplete map");
    w.start();
    let mut map = monmap_from_addrs(&[EntityAddrVec::single(mon_addr(0))]);
    map.epoch = 1;
    assert_eq!(map.fsid, Uuid::default());
    w.push(MMonMap {
        monmap: map.encode_to().unwrap(),
    });
    w.advance(Duration::from_secs(1));
    assert!(
        w.msgs(0, |m| matches!(m, AnyMessage::MLog(_)).then_some(()))
            .is_empty()
    );
    map.fsid = FSID;
    map.epoch = 2;
    w.push(MMonMap {
        monmap: map.encode_to().unwrap(),
    });
    let logs: Vec<_> = w
        .inbox
        .iter()
        .filter_map(|(_, tid, m)| match m {
            AnyMessage::MLog(l) => Some((*tid, l)),
            _ => None,
        })
        .collect();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].0, 2, "holding did not allocate an MLog TID");
    assert_eq!(logs[0].1.fsid, FSID);
    assert_eq!(logs[0].1.entries[0].seq, 1);
    assert_eq!(logs[0].1.entries[0].msg, "held through an incomplete map");
}

#[test]
fn reentrant_ready_monmap_preserves_two_command_passes_then_valid_log() {
    let mut config = cfg(1);
    config.fsid = Uuid::default();
    let mut client = MonClient::new(config);
    for i in 0..20 {
        client.send_command(&format!("{{\"prefix\":\"status\",\"i\":{i}}}"), vec![]);
    }
    client.log(1, "cluster", "before authenticated");
    client.start(Duration::ZERO);
    let IoCmd::Dial { conn, target } = client.poll_io().unwrap() else {
        panic!("expected dial")
    };
    let mut server = Connection::server(
        99,
        msgr2::Config::new(
            EntityName::new(EntityName::MON, 0),
            EntityAddrVec::single(target),
            PolicyTable::uniform(Policy::stateless_server(0)),
        ),
        SessionTable::new(9),
        Box::new(FakeAuth),
        EntityAddr::v4(2, 0, [10, 0, 1, 1], 40000),
        Duration::ZERO,
    );
    client.on_connected(conn, Duration::ZERO);
    let mut final_bytes = None;
    for _ in 0..100 {
        server.on_bytes(&client.poll_output(conn), Duration::ZERO);
        if server.state() == msgr2::ConnState::Ready {
            let mut map = monmap_from_addrs(&[EntityAddrVec::single(mon_addr(0))]);
            map.fsid = FSID;
            map.epoch = 1;
            let msg: AnyMessage = MMonMap {
                monmap: map.encode_to().unwrap(),
            }
            .into();
            let (ty, version, compat, segs) = msg.encode(u64::MAX).unwrap();
            server.send_message(msgr2::Message {
                msg_type: ty,
                version,
                compat_version: compat,
                front: segs.front,
                middle: segs.middle,
                data: segs.data,
                ..Default::default()
            });
            final_bytes = Some(server.poll_output());
            break;
        }
        client.on_bytes(conn, &server.poll_output(), Duration::ZERO);
    }
    client.on_bytes(
        conn,
        &final_bytes.expect("server handshake Ready"),
        Duration::ZERO,
    );
    server.on_bytes(&client.poll_output(conn), Duration::ZERO);
    let mut order = Vec::new();
    let mut raw: Vec<FrameBytes> = Vec::new();
    while let Some(event) = server.poll_event() {
        if let Event::Message(m) = event {
            order.push((m.header.msg_type, m.header.tid));
            assert_eq!(m.header.seq, order.len() as u64);
            if m.header.msg_type == 52 {
                let AnyMessage::MLog(log) = messages::decode_any(
                    m.header.msg_type,
                    m.header.version,
                    &m.front,
                    &m.middle,
                    &m.data,
                )
                .unwrap() else {
                    unreachable!()
                };
                assert_eq!(log.fsid, FSID);
            }
            raw.push((
                m.header.to_bytes().to_vec(),
                m.front.to_vec(),
                m.middle.to_vec(),
                m.data.to_vec(),
            ));
        }
    }
    let mut expected = vec![(15, 21)];
    expected.extend((1..=20).map(|tid| (50, tid)));
    expected.extend((1..=20).map(|tid| (50, tid)));
    expected.push((52, 22));
    assert_eq!(order, expected);
    println!("reentrant valid order count={} {order:?}", order.len());
    println!("reentrant valid raw frames {raw:?}");
}

#[test]
fn zero_fsid_logs_survive_rehunt_until_cluster_discovery() {
    let mut c = cfg(1);
    c.fsid = Uuid::default();
    let mut w = World::with(c, 1);
    w.mc.log(1, "cluster", "held across reconnect");
    w.start();
    let conn = *w.links.keys().next().unwrap();
    w.mc.on_closed(conn, w.now);
    w.step();
    assert!(w.mc.is_connected());
    assert!(
        w.msgs(0, |m| matches!(m, AnyMessage::MLog(_)).then_some(()))
            .is_empty()
    );
    let mut map = monmap_from_addrs(&[EntityAddrVec::single(mon_addr(0))]);
    map.fsid = FSID;
    map.epoch = 1;
    w.push(MMonMap {
        monmap: map.encode_to().unwrap(),
    });
    let logs = w.msgs(0, |m| match m {
        AnyMessage::MLog(l) => Some(l),
        _ => None,
    });
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].fsid, FSID);
    assert_eq!(logs[0].entries[0].seq, 1);
    assert_eq!(logs[0].entries[0].msg, "held across reconnect");
}

#[test]
fn checked_generic_handoff_preserves_pool_reply_identity_and_rejects_stale_transport() {
    use monc::MonSendError;
    let mut w = World::new(1);
    assert_eq!(
        w.mc.try_send_message(messages::MMonGetOSDMap::default()),
        Err(MonSendError::NoSession)
    );
    w.start();
    w.take_events();
    assert_eq!(
        w.mc.try_send_message(messages::MLog::default()),
        Err(MonSendError::Rejected)
    );
    let request = messages::MPoolOp {
        version: 0,
        fsid: FSID,
        pool: 7,
        operation: messages::PoolOperation::AllocateSelfManagedSnap,
        snapid: 0,
        name: vec![],
        crush_rule: 0,
    };
    let tid = w.mc.try_send_message(request.clone()).unwrap();
    w.step();
    assert!(w.inbox.iter().any(
        |(_, wire, msg)| *wire == tid && matches!(msg, AnyMessage::MPoolOp(p) if p == &request)
    ));
    let reply = messages::MPoolOpReply {
        version: 71,
        fsid: FSID,
        result: 0,
        epoch: 19,
        response_data: 23u64.to_le_bytes().to_vec(),
    };
    w.push_tid(reply.clone(), tid);
    assert!(w.take_events().iter().any(|event| matches!(event, MonEvent::Message {tid: wire, msg} if *wire == tid && matches!(msg.as_ref(), AnyMessage::MPoolOpReply(p) if p == &reply))));
    // Keep actual authenticated old-session reply bytes, then deliver them after reset.
    let old = *w.links.keys().next().unwrap();
    w.push_to(old, reply.into(), tid);
    let stale = w.links.get_mut(&old).unwrap().server.poll_output();
    assert!(!stale.is_empty());
    w.mc.rehunt("stale reply fixture");
    w.mc.on_bytes(old, &stale, w.now);
    w.step();
    assert!(
        !w.take_events()
            .iter()
            .any(|event| matches!(event, MonEvent::Message { .. }))
    );
    let next = w.mc.try_send_message(request).unwrap();
    assert!(
        next > tid,
        "rehunt must preserve the monitor identity domain"
    );
}

#[test]
fn cancelled_version_reply_is_ignored_and_a_fresh_handle_still_works() {
    let mut w = World::new(1);
    w.start();
    w.take_events();
    let old = w.mc.try_get_version("osdmap").unwrap();
    assert!(w.mc.cancel_version(old));
    w.step();
    assert!(
        !w.take_events()
            .iter()
            .any(|e| matches!(e,MonEvent::VersionReply {handle,..} if *handle==old))
    );
    let new = w.mc.try_get_version("osdmap").unwrap();
    assert_ne!(old, new);
    w.step();
    assert!(
        w.take_events()
            .iter()
            .any(|e| matches!(e,MonEvent::VersionReply {handle,version:112,..} if *handle==new))
    );
}

#[test]
fn once_command_exact_tid_version_echo_and_data_without_legacy_fallback() {
    let mut w = World::new(1);
    w.start();
    w.take_events();
    let json = r#"{"prefix":"osd blocklist","blocklistop":"add","addr":"v2:10.0.1.1:0/4711","expire":5.0}"#;
    let tid = w.mc.try_send_command_once(json, vec![255, 0]).unwrap();
    w.step();
    assert!(
        w.take_events()
            .iter()
            .all(|e| !matches!(e, MonEvent::CommandOnceReply { .. }))
    );
    // A zero-TID or unrelated acknowledgment must never complete the mutation.
    for wrong in [0, tid + 100] {
        w.push_tid(
            MMonCommandAck {
                version: 99,
                r: 0,
                rs: "wrong".into(),
                cmd: vec![json.into()],
                data: vec![],
            },
            wrong,
        );
    }
    assert!(
        w.take_events()
            .iter()
            .all(|e| !matches!(e, MonEvent::CommandOnceReply { .. }))
    );
    let legacy = w.mc.send_command(r#"{"prefix":"status"}"#, vec![]);
    w.step();
    w.push_tid(MMonCommandAck::default(), 0);
    assert!(
        w.take_events()
            .iter()
            .any(|e| matches!(e,MonEvent::CommandReply{tid:t,..} if *t==legacy))
    );
    w.push_tid(
        MMonCommandAck {
            version: 41,
            r: -13,
            rs: "denied".into(),
            cmd: vec![json.into()],
            data: vec![0, 255, 254],
        },
        tid,
    );
    let events = w.take_events();
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, MonEvent::CommandOnceReply { .. }))
            .count(),
        1
    );
    assert!(events.iter().any(|e|matches!(e,MonEvent::CommandOnceReply{tid:t,version:41,r:-13,rs,cmd,data} if *t==tid && rs=="denied" && cmd==&[json] && data==&[0,255,254])));
    assert!(!w.mc.cancel_command_once(tid));
    w.push_tid(MMonCommandAck::default(), tid);
    assert!(
        w.take_events()
            .iter()
            .all(|e| !matches!(e, MonEvent::CommandOnceReply { .. }))
    );
    let next = w.mc.try_send_command_once(json, vec![]).unwrap();
    assert!(next > tid);
    w.step();
    assert!(w.mc.cancel_command_once(next));
    assert!(!w.mc.cancel_command_once(next));
    w.push_tid(
        MMonCommandAck {
            version: 42,
            r: 0,
            ..Default::default()
        },
        next,
    );
    assert!(
        w.take_events()
            .iter()
            .all(|e| !matches!(e, MonEvent::CommandOnceReply { .. }))
    );
    let success = w.mc.try_send_command_once(json, vec![]).unwrap();
    w.step();
    w.push_tid(
        MMonCommandAck {
            version: 43,
            r: 0,
            rs: "committed".into(),
            cmd: vec![json.into()],
            data: vec![],
        },
        success,
    );
    assert!(
        w.take_events().iter().any(
            |e| matches!(e,MonEvent::CommandOnceReply{tid:t,version:43,r:0,..} if *t==success)
        )
    );
}

#[test]
fn once_command_loss_is_unknown_never_replayed_and_old_session_is_passive() {
    let mut c = cfg(2);
    c.command_timeout = Some(secs(1));
    let mut w = World::with(c, 2);
    w.start();
    w.take_events();
    let first = w.connected_mon().unwrap().to_owned();
    let fm = w.mc.monmap().rank_of(&first).unwrap();
    let json = r#"{"prefix":"osd blocklist","blocklistop":"add","addr":"v2:10.0.1.1:0/4711"}"#;
    let once = w.mc.try_send_command_once(json, vec![]).unwrap();
    w.step();
    w.advance(secs(2)); // Legacy timeout config must not fabricate a once-command reply.
    assert!(w.take_events().iter().all(|e| !matches!(
        e,
        MonEvent::CommandOnceReply { .. } | MonEvent::CommandOnceLost { .. }
    )));
    let legacy = w.mc.send_command(r#"{"prefix":"status"}"#, vec![]);
    w.step();
    let id = *w.links.keys().next().unwrap();
    let mut old_server = w.links.remove(&id).unwrap().server;
    w.mons[fm].up = false;
    w.mc.on_closed(id, w.now);
    w.step();
    let events = w.take_events();
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e,MonEvent::CommandOnceLost{tid} if *tid==once))
            .count(),
        1
    );
    assert!(!w.mc.cancel_command_once(once));
    let other = 1 - fm;
    let received = w
        .inbox
        .iter()
        .filter(|(mon, _, _)| *mon == other)
        .filter_map(|(_, tid, msg)| {
            if let AnyMessage::MMonCommand(command) = msg {
                Some((*tid, command.cmd.clone()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert!(received.iter().any(|(tid, _)| *tid == legacy));
    assert!(
        received
            .iter()
            .all(|(tid, cmd)| *tid != once && cmd != &[json])
    );
    let fresh = w.mc.try_send_command_once(json, vec![]).unwrap();
    assert!(fresh > once);
    w.step();
    w.take_events();
    // Even a matching new TID cannot resolve through the old transport session.
    let (ty, version, compat, segs) = AnyMessage::MMonCommandAck(MMonCommandAck {
        version: 99,
        r: 0,
        cmd: vec![json.into()],
        ..Default::default()
    })
    .encode(u64::MAX)
    .unwrap();
    old_server.send_message(msgr2::Message {
        msg_type: ty,
        tid: fresh,
        version,
        compat_version: compat,
        front: segs.front,
        middle: segs.middle,
        data: segs.data,
        ..Default::default()
    });
    w.mc.on_bytes(id, &old_server.poll_output(), w.now);
    w.step();
    assert!(
        w.take_events()
            .iter()
            .all(|e| !matches!(e, MonEvent::CommandOnceReply { .. }))
    );
    w.push_tid(
        MMonCommandAck {
            version: 100,
            r: 0,
            cmd: vec![json.into()],
            ..Default::default()
        },
        once,
    );
    assert!(
        w.take_events()
            .iter()
            .all(|e| !matches!(e, MonEvent::CommandOnceReply { .. }))
    );
    w.push_tid(
        MMonCommandAck {
            version: 101,
            r: 0,
            cmd: vec![json.into()],
            ..Default::default()
        },
        fresh,
    );
    assert!(
        w.take_events()
            .iter()
            .any(|e| matches!(e,MonEvent::CommandOnceReply{tid,version:101,..} if *tid==fresh))
    );
}

#[test]
fn once_command_not_replayed_when_server_transport_and_command_ack_bytes_are_lost() {
    let mut w = World::new(2);
    w.start();
    w.take_events();
    let name = w.connected_mon().unwrap().to_owned();
    let mon = w.mc.monmap().rank_of(&name).unwrap();
    assert_eq!(w.links.len(), 1);
    let id = *w.links.keys().next().unwrap();
    let json = r#"{"prefix":"osd blocklist","blocklistop":"add","addr":"v2:10.0.1.1:0/4722"}"#;
    let tid = w.mc.try_send_command_once(json, vec![]).unwrap();
    let bytes = w.mc.poll_output(id);
    assert!(!bytes.is_empty());
    let server = &mut w.links.get_mut(&id).unwrap().server;
    server.on_bytes(&bytes, w.now);
    let events: Vec<_> = std::iter::from_fn(|| server.poll_event()).collect();
    let mut received = 0;
    for event in events {
        if let Event::Message(message) = event {
            let h = &message.header;
            let decoded = messages::decode_any(
                h.msg_type,
                h.version,
                &message.front,
                &message.middle,
                &message.data,
            )
            .unwrap();
            if let AnyMessage::MMonCommand(command) = &decoded {
                assert_eq!(h.tid, tid);
                assert_eq!(command.cmd, [json]);
                received += 1;
            }
            w.inbox.push((mon, h.tid, decoded));
        }
    }
    assert_eq!(received, 1);
    w.push_to(
        id,
        MMonCommandAck {
            version: 9,
            r: 0,
            cmd: vec![json.into()],
            ..Default::default()
        }
        .into(),
        tid,
    );
    let lost = w.links.get_mut(&id).unwrap().server.poll_output();
    assert!(!lost.is_empty()); // Never fed to MonClient.
    w.mons[mon].up = false;
    w.mc.on_closed(id, w.now);
    w.step();
    w.advance(secs(5));
    assert!(w.mc.is_connected());
    assert_ne!(w.connected_mon(), Some(name.as_str()));
    let events = w.take_events();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event,MonEvent::CommandOnceLost {tid:t} if *t==tid))
            .count(),
        1
    );
    assert!(
        events
            .iter()
            .all(|event| !matches!(event,MonEvent::CommandOnceReply {tid:t,..} if *t==tid))
    );
    assert_eq!(
        w.inbox
            .iter()
            .filter(|(_, t, message)| *t == tid && matches!(message, AnyMessage::MMonCommand(_)))
            .count(),
        1
    );
    assert_eq!(w.inbox.iter().filter(|(_,_,message)|matches!(message,AnyMessage::MMonCommand(command) if command.cmd==[json])).count(),1);
    assert!(!w.mc.cancel_command_once(tid));
    w.mc.on_bytes(id, &lost, w.now);
    w.step();
    assert!(
        w.take_events()
            .iter()
            .all(|event| !matches!(event, MonEvent::CommandOnceReply { .. }))
    ); // Returning to the original peer must not revive a retained messenger queue either.
    w.mons[mon].up = true;
    w.mons[1 - mon].up = false;
    let ids = w.mc.conn_ids();
    assert_eq!(ids.len(), 1);
    w.mc.on_closed(ids[0], w.now);
    w.step();
    w.advance(secs(5));
    assert_eq!(w.connected_mon(), Some(name.as_str()));
    assert_eq!(w.inbox.iter().filter(|(_,_,message)|matches!(message,AnyMessage::MMonCommand(command) if command.cmd==[json])).count(),1);
    assert!(w.take_events().iter().all(|event| !matches!(
        event,
        MonEvent::CommandOnceReply { .. } | MonEvent::CommandOnceLost { .. }
    )));
}

#[test]
fn once_vector_command_preserves_all_elements_and_raw_input_without_replay() {
    let mut w = World::new(1);
    w.start();
    w.take_events();
    let commands = vec!["first".to_owned(), "".to_owned(), "third".to_owned()];
    let tid =
        w.mc.try_send_commands_once(commands.clone(), vec![0, 255, 7])
            .unwrap();
    w.step();
    // Inspect the actual decoded transport message, not a constructed expectation.
    assert!(
        w.msgs(0, |message| match message {
            AnyMessage::MMonCommand(command)
                if command.cmd == commands && command.data == [0, 255, 7] =>
                Some(()),
            _ => None,
        })
        .len()
            == 1
    );
    w.push_tid(
        MMonCommandAck {
            version: 9,
            r: -22,
            rs: "bad vector".into(),
            cmd: commands.clone(),
            data: vec![255, 0],
        },
        tid,
    );
    assert!(w.take_events().iter().any(|event| matches!(event,MonEvent::CommandOnceReply {tid:t,cmd,data,r:-22,..} if *t==tid && cmd==&commands && data==&[255,0])));
    assert!(!w.mc.cancel_command_once(tid));
}

#[test]
fn cluster_statistics_header_dispatch_delivers_exact_authenticated_tid() {
    let mut w = World::new(1);
    w.start();
    w.take_events();
    let request = messages::MStatfs {
        version: 9,
        fsid: FSID,
        data_pool: None,
    };
    let tid = w.mc.try_send_message(request.clone()).unwrap();
    w.step();
    assert!(
        w.inbox
            .iter()
            .any(|(_, wire, msg)| *wire == tid
                && matches!(msg,AnyMessage::MStatfs(p) if p==&request))
    );
    let reply = messages::MStatfsReply {
        fsid: FSID,
        version: 10,
        statistics: messages::ClusterStatistics {
            kb: 100,
            kb_used: 20,
            kb_avail: 80,
            num_objects: 7,
        },
    };
    w.push_tid(reply.clone(), tid);
    assert!(w.take_events().iter().any(|e|matches!(e,MonEvent::Message {tid:wire,msg} if *wire==tid && matches!(msg.as_ref(),AnyMessage::MStatfsReply(p) if p==&reply))));
}

#[test]
fn pool_statistics_header_dispatch_keeps_raw_flag_names_and_reply_tid() {
    let mut w = World::new(1);
    w.start();
    w.take_events();
    let request = messages::MGetPoolStats {
        version: 9,
        fsid: FSID,
        pools: vec![vec![255, 65]],
    };
    let tid = w.mc.try_send_message(request.clone()).unwrap();
    w.step();
    assert!(
        w.inbox.iter().any(|(_, wire, msg)| *wire == tid
            && matches!(msg,AnyMessage::MGetPoolStats(p) if p==&request))
    );
    let mut raw = messages::RawPoolStatistics::default();
    raw.counters[1] = 7;
    raw.store.allocated = 4096;
    let reply = messages::MGetPoolStatsReply {
        version: 10,
        fsid: FSID,
        pools: [(vec![255, 65], raw)].into_iter().collect(),
        per_pool: true,
    };
    w.push_tid(reply.clone(), tid);
    assert!(w.take_events().iter().any(|e|matches!(e,MonEvent::Message {tid:wire,msg} if *wire==tid && matches!(msg.as_ref(),AnyMessage::MGetPoolStatsReply(p) if p==&reply))));
}

#[test]
fn queued_commands_expire_during_hunt_before_they_can_be_replayed() {
    let mut c = cfg(1);
    c.command_timeout = Some(secs(1));
    let mut w = World::with(c, 1);
    w.mons[0].up = false;
    let tid = w.mc.send_command(r#"{"prefix":"status"}"#, vec![]);
    assert_eq!(w.mc.next_timer(), Some(secs(1)));
    w.start();
    w.advance(secs(1));
    assert!(w.take_events().iter().any(|e| matches!(
        e, MonEvent::CommandReply { tid: t, r, .. }
            if *t == tid && *r == -denc::errno::ETIMEDOUT
    )));
    w.mons[0].up = true;
    w.advance(secs(3));
    assert!(w.mc.is_connected());
    assert!(
        w.msgs(0, |m| match m {
            AnyMessage::MMonCommand(_) => Some(()),
            _ => None,
        })
        .is_empty()
    );
}

#[test]
fn map_blob_epoch_must_match_its_message_key() {
    let mut w = World::new(1);
    w.start();
    w.push(mosdmap(&[], &[10], 10));
    assert_eq!(epoch(&w), 10);
    w.take_events();
    let mut wrong = mosdmap(&[], &[12], 12);
    let payload = wrong.maps.remove(&12).unwrap();
    wrong.maps.insert(11, payload);
    w.push(wrong);
    assert_eq!(epoch(&w), 10);
    assert_eq!(w.mc.undecodable_osdmap().map(|(e, _)| *e), Some(11));
    assert!(
        w.take_events()
            .iter()
            .all(|e| !matches!(e, MonEvent::OsdMap { .. }))
    );
}

#[test]
fn foreign_monmap_cannot_replace_endpoints_or_advance_subscription() {
    let mut w = World::new(1);
    w.start();
    let before = w.mc.monmap().clone();
    let mut foreign = before.clone();
    foreign.epoch = 99;
    foreign.fsid = Uuid([9; 16]);
    w.take_events();
    w.push(MMonMap {
        monmap: foreign.encode_to().unwrap(),
    });
    assert_eq!(w.mc.monmap().epoch, before.epoch);
    assert_eq!(w.mc.monmap().ranks, before.ranks);
    assert!(w.mc.is_connected());
    assert!(
        w.take_events()
            .iter()
            .all(|e| !matches!(e, MonEvent::MonMapUpdated { .. }))
    );
}

#[test]
fn map_blob_fsid_must_match_its_message_envelope() {
    let mut w = World::new(1);
    w.start();
    let mut wrong = mosdmap(&[], &[10], 10);
    let mut map = osdmap::OsdMap::decode_from(&wrong.maps[&10]).unwrap();
    map.fsid = Uuid([9; 16]);
    wrong.maps.insert(10, map.encode_full().unwrap());
    w.push(wrong);
    assert_eq!(epoch(&w), 0);
    assert_eq!(w.mc.undecodable_osdmap().map(|(e, _)| *e), Some(10));
}

#[test]
fn session_open_does_not_send_commands_whose_deadline_already_passed() {
    let mut c = cfg(1);
    c.command_timeout = Some(secs(1));
    let mut w = World::with(c, 1);
    let tid = w.mc.send_command(r#"{"prefix":"status"}"#, vec![]);
    // A delayed driver can deliver authentication before running an overdue timer.
    w.now = secs(2);
    w.start();
    assert!(w.mc.is_connected());
    assert!(
        w.msgs(0, |m| match m {
            AnyMessage::MMonCommand(_) => Some(()),
            _ => None,
        })
        .is_empty()
    );
    assert!(w.take_events().iter().any(|e| matches!(
        e, MonEvent::CommandReply { tid: t, r, .. }
            if *t == tid && *r == -denc::errno::ETIMEDOUT
    )));
}

#[test]
fn incremental_with_wrong_epoch_key_requests_full_without_progress() {
    let mut w = World::new(1);
    w.start();
    w.push(mosdmap(&[], &[10], 10));
    let mut wrong = mosdmap(&[12], &[], 12);
    let payload = wrong.incremental_maps.remove(&12).unwrap();
    wrong.incremental_maps.insert(11, payload);
    w.push(wrong);
    assert_eq!(epoch(&w), 10);
    assert!(
        w.msgs(0, |m| match m {
            AnyMessage::MMonGetOSDMap(request) => Some((request.full_first, request.full_last)),
            _ => None,
        })
        .contains(&(11, 11))
    );
}

#[test]
fn bootstrap_incremental_fsid_must_match_message_envelope() {
    let mut w = World::new(1);
    w.start();
    let mut inc = osdmap::Incremental {
        epoch: 1,
        fsid: Uuid([9; 16]),
        ..Default::default()
    };
    let mut next = osdmap::OsdMap::default();
    next.apply_incremental(&inc).unwrap();
    inc.full_crc = next.crc(inc.encode_features).unwrap();
    let mut wrong = mosdmap(&[], &[], 1);
    wrong.incremental_maps.insert(1, inc.encode_inc().unwrap());
    w.push(wrong);
    assert_eq!(epoch(&w), 0);
    assert!(
        w.msgs(0, |m| match m {
            AnyMessage::MMonGetOSDMap(request) => Some((request.full_first, request.full_last)),
            _ => None,
        })
        .contains(&(1, 1))
    );
}

#[test]
fn zero_keepalive_timeout_disables_expiry_but_keeps_sending_pings() {
    let mut c = cfg(1);
    c.ping_timeout = Duration::ZERO;
    let mut w = World::with(c, 1);
    w.start();
    w.take_events();
    w.advance(secs(25));
    assert!(w.mc.keepalive_acks() >= 2);
    let original_dials = w.dials.len();
    // A live session may wait indefinitely for an ack when expiry is disabled.
    w.mons[0].blackhole = true;
    w.advance(secs(60));
    assert!(w.mc.is_connected());
    assert_eq!(w.mc.timeouts(), 0);
    assert_eq!(w.dials.len(), original_dials);
    assert!(
        !w.take_events()
            .iter()
            .any(|e| matches!(e, MonEvent::SessionLost(_)))
    );
    w.mons[0].blackhole = false;
    w.advance(secs(15));
    assert!(w.mc.keepalive_acks() >= 3);
}

/// Fallback demand is a range: a wider batch sharing its first epoch must not disappear.
#[test]
fn osdmap_full_fallback_widening_and_capped_replies_preserve_suffix() {
    let mut w = World::new(1);
    w.start();
    w.mc.subscribe("osdmap", 0, 0);
    w.step();
    w.push(mosdmap(&[], &[10], 20));
    let mut bad = mosdmap(&[], &[], 20);
    bad.incremental_maps.insert(11, poisoned_inc(11));
    w.push(bad.clone());
    assert_eq!(full_reqs(&w), [(11, 11)]);
    for e in 12..=15 {
        bad.incremental_maps.insert(e, poisoned_inc(e));
    }
    w.push(bad.clone());
    assert_eq!(full_reqs(&w), [(11, 11), (11, 15)]);
    w.push(bad);
    assert_eq!(full_reqs(&w), [(11, 11), (11, 15)]);
    // The monitor's map-count/byte budget returns only a prefix.
    w.push(mosdmap(&[], &[11, 12], 20));
    assert_eq!(epoch(&w), 12);
    assert_eq!(full_reqs(&w).last(), Some(&(13, 15)));
    // An old overlapping response cannot retire the remaining suffix.
    w.push(mosdmap(&[], &[11], 20));
    assert_eq!(full_reqs(&w).last(), Some(&(13, 15)));
    w.push(mosdmap(&[], &[13, 14], 20));
    assert_eq!(full_reqs(&w).last(), Some(&(15, 15)));
    w.push(mosdmap(&[], &[15], 20));
    assert_eq!(epoch(&w), 15);
    let n = full_reqs(&w).len();
    w.push(mosdmap(&[16], &[], 20));
    assert_eq!(full_reqs(&w).len(), n);
}

#[test]
fn missing_key_never_adds_an_unconfigured_none_method() {
    for methods in [vec![AUTH_METHOD_CEPHX], vec![]] {
        let mut c = cfg(1);
        c.methods = methods;
        let mut w = World::with(c, 1);
        w.start();
        assert!(!w.mc.is_connected());
        assert!(authenticated(&w.events).is_empty());
        assert!(
            w.events
                .iter()
                .any(|e| matches!(e, MonEvent::AuthFailed(_)))
        );
    }
    let mut c = cfg(1);
    c.methods = vec![AUTH_METHOD_CEPHX, AUTH_METHOD_NONE];
    let mut w = World::with(c, 1);
    w.start();
    assert!(w.mc.is_connected());
}

/// Trimming permits skipping only the unavailable prefix, not retained intermediate epochs.
#[test]
fn osdmap_trimmed_prefix_does_not_skip_retained_gap() {
    let mut w = World::new(1);
    w.start();
    w.mc.subscribe("osdmap", 0, 0);
    w.step();
    w.push(mosdmap(&[], &[10], 20));
    let mut later = mosdmap(&[], &[14], 20);
    later.cluster_osdmap_trim_lower_bound = 12;
    w.push(later);
    assert_eq!(epoch(&w), 10, "retained epochs 12 and 13 must be recovered");
    assert_eq!(osdmap_subs(&w).last(), Some(&(11, 0)));
    let mut recovered = mosdmap(&[], &[12, 13, 14], 20);
    recovered.cluster_osdmap_trim_lower_bound = 12;
    w.push(recovered);
    assert_eq!(epoch(&w), 14);
}

/// An onetime subscription retires on the prefix, but its unfinished full fallback survives a reset.
#[test]
fn osdmap_onetime_capped_full_fallback_rearms_after_reconnect() {
    let mut w = World::new(1);
    w.start();
    w.mc.subscribe("osdmap", 0, messages::SubItem::ONETIME);
    w.step();
    w.push(mosdmap(&[], &[10], 10));
    let mut bad = mosdmap(&[], &[], 15);
    for e in 11..=15 {
        bad.incremental_maps.insert(e, poisoned_inc(e));
    }
    w.push(bad);
    w.push(mosdmap(&[], &[11, 12], 15));
    assert_eq!(epoch(&w), 12);
    assert_eq!(full_reqs(&w).last(), Some(&(13, 15)));
    let n = osdmap_subs(&w).len();
    let cid = *w.links.keys().next().unwrap();
    w.links.clear();
    w.mc.on_closed(cid, w.now);
    w.step();
    w.advance(secs(10));
    assert!(w.mc.is_connected());
    assert_eq!(osdmap_subs(&w)[n..].last().map(|s| s.0), Some(13));
    w.push(mosdmap(&[13, 14, 15], &[], 15));
    assert_eq!(epoch(&w), 15);
}

/// A running client takes new timers (`MonClient::set_timers`): a ping timeout disabled after the session is up keeps
/// a silent mon's session, as classic re-reads `mon_client_ping_timeout` on every tick.
#[test]
fn runtime_timers_reach_a_running_session() {
    let mut w = World::new(1);
    w.start();
    w.take_events();
    w.advance(secs(5));
    assert!(w.mc.is_connected());
    let mut t = cfg(1).timers();
    t.ping_timeout = Duration::ZERO;
    w.mc.set_timers(t);
    w.mons[0].blackhole = true;
    w.advance(secs(90));
    assert!(w.mc.is_connected());
    assert_eq!(w.mc.timeouts(), 0);
}

/// `mon_client_hunt_parallel` 0 dials every candidate mon in one round (classic), not one.
#[test]
fn zero_hunt_parallel_dials_every_candidate() {
    let mut c = cfg(3);
    c.hunt_parallel = 0;
    let mut w = World::with(c, 3);
    for m in &mut w.mons {
        m.up = false;
    }
    w.start();
    w.step();
    let ranks: BTreeSet<usize> = w.dials.iter().map(|d| d.1).collect();
    assert_eq!(ranks.len(), 3, "{:?}", w.dials);
}

/// A hunt interval x multiple beyond the clock range schedules no next round instead of panicking.
#[test]
fn huge_hunt_interval_does_not_panic() {
    let mut c = cfg(1);
    c.hunt_interval = Duration::MAX;
    c.hunt_backoff = 1e300;
    c.hunt_max_multiple = 1e300;
    let mut w = World::with(c, 1);
    w.mons[0].up = false;
    w.start();
    w.advance(secs(60));
    assert!(!w.mc.is_connected());
}
