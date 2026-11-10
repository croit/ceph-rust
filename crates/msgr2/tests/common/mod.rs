// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Shared in-memory pipe harness for session tests.
#![allow(clippy::allow_attributes, dead_code)]
use denc::types::{EntityAddr, EntityAddrVec, EntityName};
use msgr2::auth::*;
use msgr2::*;
use std::time::Duration;

pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

pub fn t(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

pub fn addr(ip: u8, port: u16, nonce: u32) -> EntityAddr {
    EntityAddr::v4(2, nonce, [10, 0, 0, ip], port)
}

pub struct Node {
    pub cfg: Config,
    pub table: SessionTable,
    pub addrs: EntityAddrVec,
    pub next_id: u64,
}

impl Node {
    pub fn new(ty: u8, num: i64, ip: u8, pol: PolicyTable) -> Self {
        let addrs = EntityAddrVec::single(addr(ip, 6800, 99));
        Self {
            cfg: Config::new(EntityName::new(ty, num), addrs.clone(), pol),
            table: SessionTable::new(ip as u64 * 7919),
            addrs,
            next_id: 1,
        }
    }
    pub fn reseed(mut self, seed: u64) -> Self {
        self.table = SessionTable::new(seed);
        self
    }
    pub fn id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
    /// Client conn towards `peer`; drains the initial Dial and connects.
    pub fn dial(&mut self, peer: &Node, now: Duration) -> Connection {
        self.dial_with(
            peer,
            Box::new(AuthNoneClient {
                name: self.cfg.name,
                global_id: 0,
            }),
            now,
        )
    }
    pub fn dial_with(
        &mut self,
        peer: &Node,
        auth: Box<dyn AuthClientHandler>,
        now: Duration,
    ) -> Connection {
        let id = self.id();
        let ty = peer.cfg.name.ty;
        let mut c = Connection::client(
            id,
            self.cfg.clone(),
            self.table.clone(),
            auth,
            ty,
            peer.addrs.clone(),
            peer.addrs.0[0],
        );
        assert!(matches!(c.poll_event(), Some(Event::Dial { .. })));
        c.on_connected(now);
        c
    }
    pub fn accept(&mut self, from_ip: u8, now: Duration) -> Connection {
        self.accept_with(from_ip, Box::new(AuthNoneServer::default()), now)
    }
    pub fn accept_with(
        &mut self,
        from_ip: u8,
        auth: Box<dyn AuthServerHandler>,
        now: Duration,
    ) -> Connection {
        let id = self.id();
        Connection::server(
            id,
            self.cfg.clone(),
            self.table.clone(),
            auth,
            addr(from_ip, 40000 + id as u16, 0),
            now,
        )
    }
}

pub fn events(c: &mut Connection) -> Vec<Event> {
    std::iter::from_fn(|| c.poll_event()).collect()
}

/// Move bytes both ways in random chunks until quiescent.
pub fn exchange(
    a: &mut Connection,
    b: &mut Connection,
    now: Duration,
    rng: &mut Rng,
    max_chunk: usize,
) {
    for _ in 0..100_000 {
        let mut moved = false;
        // a sends through the shared-run output (large payloads by reference), b through the flat one
        let out = a.poll_output_chunks().concat();
        moved |= feed(b, &out, now, rng, max_chunk);
        let out = b.poll_output();
        moved |= feed(a, &out, now, rng, max_chunk);
        if !moved {
            return;
        }
    }
    panic!("no quiescence");
}

pub fn feed(
    to: &mut Connection,
    out: &[u8],
    now: Duration,
    rng: &mut Rng,
    max_chunk: usize,
) -> bool {
    let mut p = 0;
    while p < out.len() {
        let n = 1 + rng.next() as usize % max_chunk;
        let e = (p + n).min(out.len());
        to.on_bytes(&out[p..e], now);
        p = e;
    }
    !out.is_empty()
}

pub fn msg(tid: u64, ty: u16, n: usize) -> Message {
    Message {
        msg_type: ty,
        tid,
        version: 1,
        front: vec![tid as u8; n],
        data: if n > 100 {
            vec![7; n * 3].into()
        } else {
            Default::default()
        },
        ..Default::default()
    }
}

pub fn msgs(evs: &[Event]) -> Vec<&Incoming> {
    evs.iter()
        .filter_map(|e| {
            if let Event::Message(m) = e {
                Some(m)
            } else {
                None
            }
        })
        .collect()
}

pub fn connected(evs: &[Event]) -> Option<&PeerInfo> {
    evs.iter().find_map(|e| {
        if let Event::Connected(p) = e {
            Some(p)
        } else {
            None
        }
    })
}

/// Auth with a session key (and connection secret for secure mode), same on both sides.
#[derive(Debug, Clone)]
pub struct KeyedClient {
    pub key: Vec<u8>,
    pub secret: Vec<u8>,
    pub modes: Vec<u32>,
    pub method: u32,
}
impl AuthClientHandler for KeyedClient {
    fn get_auth_request(&mut self, _: u8) -> Result<AuthRequestOut, AuthError> {
        Ok(AuthRequestOut {
            method: self.method,
            preferred_modes: self.modes.clone(),
            payload: b"hello".to_vec(),
        })
    }
    fn handle_auth_reply_more(&mut self, p: &[u8]) -> Result<Vec<u8>, AuthError> {
        Ok(p.iter().rev().copied().collect())
    }
    fn handle_auth_done(&mut self, _g: u64, _m: u32, _p: &[u8]) -> Result<AuthSecrets, AuthError> {
        Ok(AuthSecrets {
            session_key: self.key.clone(),
            connection_secret: self.secret.clone(),
        })
    }
    fn handle_auth_bad_method(
        &mut self,
        _: u32,
        _: i32,
        _: &[u32],
        _: &[u32],
    ) -> Result<(), AuthError> {
        Err(AuthError("no alternative".into()))
    }
}

#[derive(Debug, Clone)]
pub struct KeyedServer {
    pub peer_name: Option<EntityName>,
    pub key: Vec<u8>,
    pub secret: Vec<u8>,
    pub rounds: u32,
    pub done: u32,
    pub methods: Vec<u32>,
    pub modes: Vec<u32>,
}
impl AuthServerHandler for KeyedServer {
    fn supported_methods(&self, _: u8) -> Vec<u32> {
        self.methods.clone()
    }
    fn supported_modes(&self, _: u8, _: u32) -> Vec<u32> {
        self.modes.clone()
    }
    fn handle_auth_request(
        &mut self,
        _: u8,
        _more: bool,
        _method: u32,
        mode: u32,
        _p: &[u8],
    ) -> AuthServerStep {
        if self.done < self.rounds {
            self.done += 1;
            return AuthServerStep::More(b"challenge".to_vec());
        }
        AuthServerStep::Done {
            reply: b"ok".to_vec(),
            global_id: 5555,
            peer_name: self.peer_name,
            secrets: AuthSecrets {
                session_key: self.key.clone(),
                connection_secret: if mode == MODE_SECURE {
                    self.secret.clone()
                } else {
                    vec![]
                },
            },
        }
    }
}
