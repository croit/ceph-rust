// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! OSD cluster sessions are lossless (spec 10, 11: `lossless_peer`): with both peers up, socket kills at any point, dial
//! races and role swaps (the side that accepted dials back when it has something to send) never lose, duplicate or
//! reorder a message, provided the application drains every connection's events until `Closed`, also of a connection
//! that lost its session to another one (`take_superseded`). OQ 28 O15 / adr 0071 am. 2.
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::auth::*;
use msgr2::*;

struct C {
    node: usize,
    c: Connection,
    /// Index of the other end of the TCP connection, while the socket is up.
    sock: Option<usize>,
}

struct Sim {
    nodes: [Node; 2],
    conns: Vec<Option<C>>,
    /// Per node: the link it sends on (like `Osd::pg.peers`).
    cur: [Option<usize>; 2],
    now: u64,
    rng: Rng,
    sent: [Vec<u64>; 2],
    got: [Vec<u64>; 2],
    next_tid: u64,
    /// The application dials sessions that `needs_dial` once `take_owed` says so (off: the stall without it).
    dial_back: bool,
    /// A connection that reaches READY takes over the undelivered messages of the older ones (off: reordering).
    takeover: bool,
    /// Sometimes the sender does not see an accepted READY link yet (its Connected event is still queued) and dials.
    blind_dial: bool,
}

impl Sim {
    fn new(seed: u64) -> Sim {
        let pol = PolicyTable::osd_cluster;
        Sim {
            nodes: [
                Node::new(EntityName::OSD, 1, 1, pol()),
                Node::new(EntityName::OSD, 2, 2, pol()),
            ],
            conns: Vec::new(),
            cur: [None, None],
            now: 1,
            rng: Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1),
            sent: [vec![], vec![]],
            got: [vec![], vec![]],
            next_tid: 1,
            dial_back: true,
            takeover: true,
            blind_dial: false,
        }
    }

    fn ts(&self) -> std::time::Duration {
        t(self.now)
    }

    fn live(&self, i: usize) -> bool {
        self.conns[i]
            .as_ref()
            .is_some_and(|c| c.c.state() != ConnState::Closed)
    }

    /// Node `x` sends one message to the other node: on its current link, else on an accepted link that carries the
    /// session, else on a new dial (the OSD's `peer_transmit`).
    fn send(&mut self, x: usize) {
        let tid = self.next_tid;
        self.next_tid += 1;
        let n = (self.rng.next() % 300) as usize;
        let m = msg(tid, 42 + x as u16, n);
        let blind = self.blind_dial && self.rng.next().is_multiple_of(4);
        let link = self.cur[x].filter(|&i| self.live(i)).or_else(|| {
            (0..self.conns.len()).filter(|_| !blind).find(|&i| {
                self.conns[i].as_ref().is_some_and(|c| {
                    c.node == x && c.c.role() == Role::Server && c.c.state() == ConnState::Ready
                })
            })
        });
        let i = match link {
            Some(i) => i,
            None => self.dial(x),
        };
        self.cur[x] = Some(i);
        let ok = self.conns[i].as_mut().unwrap().c.send_message(m);
        assert!(ok, "send on a live connection");
        self.sent[x].push(tid);
    }

    fn dial(&mut self, x: usize) -> usize {
        let o = 1 - x;
        let id = self.nodes[x].id();
        let peer = self.nodes[o].addrs.clone();
        let c = Connection::client(
            id,
            self.nodes[x].cfg.clone(),
            self.nodes[x].table.clone(),
            Box::new(AuthNoneClient {
                name: self.nodes[x].cfg.name,
                global_id: 0,
            }),
            EntityName::OSD,
            peer.clone(),
            peer.0[0],
        );
        self.conns.push(Some(C {
            node: x,
            c,
            sock: None,
        }));
        self.conns.len() - 1
    }

    /// A socket closes (or dies): both ends learn it.
    fn kill(&mut self, i: usize) {
        let now = self.ts();
        let Some(o) = self.conns[i].as_mut().and_then(|c| c.sock.take()) else {
            return;
        };
        self.conns[i].as_mut().unwrap().c.on_closed(now);
        if let Some(c) = self.conns[o].as_mut() {
            c.sock = None;
            c.c.on_closed(now);
        }
    }

    /// Drain events; `hold`: some connections keep their input this round (the OSD's store / ingress backpressure).
    fn drain(&mut self, hold: bool) {
        for i in 0..self.conns.len() {
            if hold && self.rng.next().is_multiple_of(3) {
                continue;
            }
            loop {
                let Some(ev) = self.conns[i].as_mut().and_then(|c| c.c.poll_event()) else {
                    break;
                };
                let node = self.conns[i].as_ref().unwrap().node;
                match ev {
                    Event::Message(m) => self.got[node].push(m.header.tid),
                    Event::Connected(_) if self.takeover => {
                        // this connection carries the session now: what older ones decoded goes first (the OSD:
                        // `Osd::take_over_input`)
                        for j in 0..self.conns.len() {
                            if j == i || self.conns[j].as_ref().is_none_or(|c| c.node != node) {
                                continue;
                            }
                            let mut old = self.conns[j].take().unwrap();
                            if self.conns[i]
                                .as_mut()
                                .unwrap()
                                .c
                                .take_over_messages(&mut old.c)
                            {
                                // finished: dropped (the OSD closes the link)
                                self.conns[j] = Some(old);
                                self.kill(j);
                                self.conns[j] = None;
                            } else {
                                self.conns[j] = Some(old);
                            }
                        }
                    }
                    Event::Dial { .. } => {
                        let o = 1 - node;
                        let now = self.ts();
                        let ip = node as u8 + 1;
                        let s = self.nodes[o].accept(ip, now);
                        self.conns.push(Some(C {
                            node: o,
                            c: s,
                            sock: Some(i),
                        }));
                        let si = self.conns.len() - 1;
                        let c = self.conns[i].as_mut().unwrap();
                        c.sock = Some(si);
                        c.c.on_connected(now);
                    }
                    Event::Fault(_) => self.kill(i),
                    Event::Closed => {
                        self.kill(i);
                        self.conns[i] = None;
                        break;
                    }
                    _ => {}
                }
            }
        }
        for x in 0..2 {
            for id in self.nodes[x].table.take_superseded() {
                if let Some(i) = (0..self.conns.len()).find(|&i| {
                    self.conns[i]
                        .as_ref()
                        .is_some_and(|c| c.node == x && c.c.id() == id)
                }) {
                    // the application closes it but still takes the messages it already decoded (Closed comes last,
                    // unless the new carrier took them over first)
                    self.conns[i].as_mut().unwrap().c.close();
                    self.kill(i);
                }
            }
            // spec 10.7 step 7: a session we still owe messages but nobody carries or dials (the accepted side faulted)
            if self.nodes[x].table.take_owed()
                && self.dial_back
                && !self.nodes[x].table.needs_dial().is_empty()
            {
                let i = self.dial(x);
                self.cur[x] = Some(i);
            }
        }
    }

    /// Move bytes over every live socket; `cuts`: sometimes kill a socket after a random prefix.
    fn transfer(&mut self, cuts: bool) -> bool {
        let mut moved = false;
        let now = self.ts();
        for i in 0..self.conns.len() {
            let Some(o) = self.conns[i].as_ref().and_then(|c| c.sock) else {
                continue;
            };
            let out = self.conns[i].as_mut().unwrap().c.poll_output();
            if out.is_empty() {
                continue;
            }
            moved = true;
            let cut = cuts && self.rng.next().is_multiple_of(9);
            let k = if cut {
                (self.rng.next() as usize) % (out.len() + 1)
            } else {
                out.len()
            };
            if let Some(c) = self.conns[o].as_mut() {
                let mut r = Rng(self.rng.next() | 1);
                feed(&mut c.c, &out[..k], now, &mut r, 300);
            }
            if cut {
                self.kill(i);
            }
        }
        moved
    }

    fn timers(&mut self) {
        let now = self.ts();
        for c in self.conns.iter_mut().flatten() {
            if c.c.next_timer().is_some_and(|x| x <= now) {
                c.c.on_timer(now);
            }
        }
    }

    fn next_timer(&self) -> Option<u64> {
        self.conns
            .iter()
            .flatten()
            .filter_map(|c| c.c.next_timer())
            .map(|d| d.as_millis() as u64)
            .min()
    }

    fn run(&mut self, rounds: u32) {
        for _ in 0..rounds {
            for _ in 0..(self.rng.next() % 4) {
                let x = (self.rng.next() % 2) as usize;
                self.send(x);
            }
            // random socket kill (both peers stay up)
            if self.rng.next().is_multiple_of(5) {
                let live: Vec<usize> = (0..self.conns.len())
                    .filter(|&i| self.conns[i].as_ref().is_some_and(|c| c.sock.is_some()))
                    .collect();
                if !live.is_empty() {
                    let i = live[(self.rng.next() as usize) % live.len()];
                    self.kill(i);
                }
            }
            for _ in 0..(1 + self.rng.next() % 6) {
                self.now += 1 + self.rng.next() % 5;
                self.timers();
                self.transfer(true);
                // the application sometimes holds a connection's input back (store backpressure)
                self.drain(true);
            }
        }
        // settle: no more faults, run until both sides got everything
        for _ in 0..20_000 {
            self.drain(false);
            let moved = self.transfer(false);
            self.drain(false);
            if self.got[1].len() == self.sent[0].len() && self.got[0].len() == self.sent[1].len() {
                break;
            }
            if !moved {
                self.now = self
                    .next_timer()
                    .map_or(self.now + 10, |x| x.max(self.now + 1));
                self.timers();
            }
        }
    }
}

#[test]
fn cluster_sessions_lose_nothing_with_kills_races_and_role_swaps() {
    for seed in 1..=1000u64 {
        let mut s = Sim::new(seed);
        s.run(120);
        assert_eq!(s.got[1], s.sent[0], "seed {seed}: osd.1 -> osd.2");
        assert_eq!(s.got[0], s.sent[1], "seed {seed}: osd.2 -> osd.1");
    }
}

#[test]
fn without_dial_back_an_accepted_session_that_owes_messages_stalls() {
    // the reproducer of the gap: some seed ends with frames queued in a session nobody carries
    let stalled = (1..=200u64).any(|seed| {
        let mut s = Sim::new(seed);
        s.dial_back = false;
        s.run(120);
        s.got[1] != s.sent[0] || s.got[0] != s.sent[1]
    });
    assert!(stalled);
}

#[test]
fn without_takeover_a_held_superseded_connection_is_overtaken() {
    // same traffic, the old connection's held messages are taken after the new carrier's: out of session order
    let reordered = (1..=500u64).any(|seed| {
        let mut s = Sim::new(seed);
        s.takeover = false;
        s.run(120);
        let sorted = |v: &[u64]| {
            let mut v = v.to_vec();
            v.sort_unstable();
            v
        };
        assert_eq!(
            sorted(&s.got[1]),
            sorted(&s.sent[0]),
            "seed {seed}: nothing lost"
        );
        assert_eq!(
            sorted(&s.got[0]),
            sorted(&s.sent[1]),
            "seed {seed}: nothing lost"
        );
        s.got[1] != s.sent[0] || s.got[0] != s.sent[1]
    });
    assert!(reordered);
}

#[test]
fn dial_while_accepted_link_ready_loses_nothing() {
    for seed in 1..=1000u64 {
        let mut s = Sim::new(seed);
        s.blind_dial = true;
        s.run(120);
        assert_eq!(s.got[1], s.sent[0], "seed {seed}: osd.1 -> osd.2");
        assert_eq!(s.got[0], s.sent[1], "seed {seed}: osd.2 -> osd.1");
    }
}

/// msg_seq of the SESSION_RECONNECT in a client's output stream (banner first), once it is there.
fn reconnect_msg_seq(stream: &[u8]) -> Option<u64> {
    use msgr2::payload::{Payload, SessionReconnect};
    let (b, n) = Banner::parse(stream).ok()??;
    let mut d = Decoder::new(b.revision());
    d.feed(&stream[n..]);
    while let Ok(Some(f)) = d.poll() {
        if f.tag == Tag::SessionReconnect as u8 {
            return SessionReconnect::from_bytes(f.segments()[0])
                .ok()
                .map(|r| r.msg_seq);
        }
    }
    None
}

/// The application dials a session that an accepted connection still carries (its READY not yet seen: the OSD's
/// `peer_transmit` before `Connected` was processed). While that dial's SESSION_RECONNECT is in flight the peer sends one
/// more message on its old connection. The msg_seq the reconnect announced must still be the session's in_seq when the
/// peer accepts it: a classic peer with nothing to replay restarts its numbering at msg_seq + 1 and every seq up to our
/// real in_seq is dropped here as old (lab case 23: one MOSDRepOpReply lost, pg stuck below pg_committed_to).
#[test]
fn a_dial_on_a_carried_session_freezes_the_announced_in_seq() {
    let pol = PolicyTable::osd_cluster;
    let mut a = Node::new(EntityName::OSD, 1, 1, pol());
    let mut b = Node::new(EntityName::OSD, 2, 2, pol());
    let mut rng = Rng(7);
    let now = t(1);
    // b dials a: the session is a's accepted connection a1
    let mut b1 = b.dial(&a, now);
    let mut a1 = a.accept(2, now);
    exchange(&mut b1, &mut a1, now, &mut rng, 64);
    assert_eq!(a1.state(), ConnState::Ready);
    let mut got: Vec<u64> = Vec::new();
    b1.send_message(msg(1, 42, 10));
    exchange(&mut b1, &mut a1, now, &mut rng, 64);
    got.extend(msgs(&events(&mut a1)).iter().map(|m| m.header.tid));
    // a dials the same session
    let id = a.id();
    let mut a2 = Connection::client(
        id,
        a.cfg.clone(),
        a.table.clone(),
        Box::new(AuthNoneClient {
            name: a.cfg.name,
            global_id: 0,
        }),
        EntityName::OSD,
        b.addrs.clone(),
        b.addrs.0[0],
    );
    assert!(matches!(a2.poll_event(), Some(Event::Dial { .. })));
    a2.on_connected(now);
    let mut b2 = b.accept(1, now);
    // handshake up to (not including) the delivery of a2's SESSION_RECONNECT
    let mut stream = Vec::new();
    let (held, announced) = loop {
        let out = a2.poll_output();
        stream.extend_from_slice(&out);
        if let Some(s) = reconnect_msg_seq(&stream) {
            break (out, s);
        }
        assert!(!out.is_empty(), "a2 stalled before SESSION_RECONNECT");
        feed(&mut b2, &out, now, &mut rng, 64);
        let back = b2.poll_output();
        feed(&mut a2, &back, now, &mut rng, 64);
    };
    // b, unaware, sends tid 2 on its old connection; a1's acks reach b
    b1.send_message(msg(2, 42, 10));
    exchange(&mut b1, &mut a1, now, &mut rng, 64);
    got.extend(msgs(&events(&mut a1)).iter().map(|m| m.header.tid));
    let in_seq = a.table.info(&b.addrs).unwrap().in_seq;
    assert_eq!(
        announced, in_seq,
        "SESSION_RECONNECT announced in_seq {announced}, the session went on to {in_seq} on the old connection"
    );
    // the resume completes; b replays what a has not acknowledged
    feed(&mut b2, &held, now, &mut rng, 64);
    exchange(&mut a2, &mut b2, now, &mut rng, 64);
    assert_eq!(a2.state(), ConnState::Ready);
    got.extend(msgs(&events(&mut a2)).iter().map(|m| m.header.tid));
    b2.send_message(msg(3, 42, 10));
    exchange(&mut a2, &mut b2, now, &mut rng, 64);
    got.extend(msgs(&events(&mut a2)).iter().map(|m| m.header.tid));
    assert_eq!(got, vec![1, 2, 3]);
}
