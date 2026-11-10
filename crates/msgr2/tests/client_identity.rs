// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Auth-handler contract tests: distinct verified cephx client global ids and
//! signature keys may not exchange lossless sessions using visible addr/cookies.
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::{auth::*, *};
#[derive(Debug)]
struct VerifiedClient {
    inner: KeyedServer,
    global_id: u64,
}
impl AuthServerHandler for VerifiedClient {
    fn supported_methods(&self, peer: u8) -> Vec<u32> {
        self.inner.supported_methods(peer)
    }
    fn supported_modes(&self, peer: u8, method: u32) -> Vec<u32> {
        self.inner.supported_modes(peer, method)
    }
    fn handle_auth_request(
        &mut self,
        peer: u8,
        more: bool,
        method: u32,
        mode: u32,
        payload: &[u8],
    ) -> AuthServerStep {
        match self
            .inner
            .handle_auth_request(peer, more, method, mode, payload)
        {
            AuthServerStep::Done {
                reply,
                peer_name,
                secrets,
                ..
            } => AuthServerStep::Done {
                reply,
                peer_name,
                secrets,
                global_id: self.global_id,
            },
            other => other,
        }
    }
}
fn client(key: u8) -> Box<dyn AuthClientHandler> {
    Box::new(KeyedClient {
        key: vec![key; 16],
        secret: vec![],
        modes: vec![MODE_CRC],
        method: AUTH_METHOD_CEPHX,
    })
}
fn server(global_id: u64, key: u8) -> Box<dyn AuthServerHandler> {
    Box::new(VerifiedClient {
        global_id,
        inner: KeyedServer {
            peer_name: Some(EntityName::client(-1)),
            key: vec![key; 16],
            secret: vec![],
            rounds: 0,
            done: 0,
            methods: vec![AUTH_METHOD_CEPHX],
            modes: vec![MODE_CRC],
        },
    })
}
fn nodes(binding: bool) -> (Node, Node) {
    let (a, mut b) = (
        Node::new(
            EntityName::CLIENT,
            5555,
            1,
            PolicyTable::uniform(Policy::lossless_client(0)),
        ),
        Node::new(
            EntityName::MDS,
            0,
            2,
            PolicyTable::uniform(Policy::stateful_server(0)),
        ),
    );
    assert!(!b.cfg.bind_client_identity);
    b.cfg.bind_client_identity = binding;
    (a, b)
}
#[test]
fn authenticated_client_ident_binds_global_id_before_session_creation() {
    let (mut a, mut b) = nodes(true);
    let mut c = a.dial_with(&b, client(9), t(0));
    let mut s = b.accept_with(1, server(9999, 9), t(0));
    exchange(&mut c, &mut s, t(1), &mut Rng(11), 97);
    let es = events(&mut s);
    assert!(connected(&es).is_none());
    assert!(es.iter().any(|e|matches!(e,Event::Fault(FaultReason::Protocol(m)) if m.contains("authenticated client global id"))));
    assert!(b.table.is_empty());
}
#[test]
fn another_authenticated_client_cannot_adopt_addrvec_or_reconnect_visible_cookie() {
    let (mut a, mut b) = nodes(true);
    let mut c = a.dial_with(&b, client(5), t(0));
    let mut s = b.accept_with(1, server(5555, 5), t(0));
    exchange(&mut c, &mut s, t(1), &mut Rng(7), 97);
    assert!(connected(&events(&mut s)).is_some());
    events(&mut c);
    s.send_message(Message {
        msg_type: 26,
        tid: 91,
        front: b"private victim reply".to_vec(),
        ..Message::default()
    });
    let before = b.table.info(&a.addrs).unwrap();
    assert_eq!(before.unsent, 1);
    let mut attacker = Node::new(
        EntityName::CLIENT,
        9999,
        1,
        PolicyTable::uniform(Policy::lossless_client(0)),
    );
    let mut attack = attacker.dial_with(&b, client(9), t(2));
    let mut accepted = b.accept_with(2, server(9999, 9), t(2));
    exchange(&mut attack, &mut accepted, t(3), &mut Rng(13), 97);
    let es = events(&mut accepted);
    assert!(connected(&es).is_none());
    assert!(es.iter().any(|e|matches!(e,Event::Fault(FaultReason::Protocol(m)) if m.contains("another authenticated client"))));
    assert!(msgs(&events(&mut attack)).is_empty());
    assert_eq!(b.table.info(&a.addrs).unwrap().unsent, 1);
    assert_eq!(b.table.carrier(&a.addrs), Some(s.id()));
    c.on_closed(t(4));
    s.on_closed(t(4));
    events(&mut c);
    events(&mut s);
    // Carry the victim's visible reconnect cookie/sequence in a connection
    // authenticated with another client's independent signature key.
    attacker.table = a.table.clone();
    attacker.next_id = 100;
    let mut attack = attacker.dial_with(&b, client(9), t(5));
    let mut accepted = b.accept_with(3, server(9999, 9), t(5));
    exchange(&mut attack, &mut accepted, t(6), &mut Rng(17), 97);
    let es = events(&mut accepted);
    assert!(connected(&es).is_none());
    assert!(es.iter().any(|e|matches!(e,Event::Fault(FaultReason::Protocol(m)) if m.contains("another authenticated client"))),"{es:?}");
    assert!(msgs(&events(&mut attack)).is_empty());
    assert_eq!(b.table.info(&a.addrs).unwrap().unsent, 1);
    assert!(b.table.carrier(&a.addrs).is_none());
}

#[test]
fn default_allows_client_ident_with_another_global_id() {
    let (mut a, mut b) = nodes(false);
    let mut c = a.dial_with(&b, client(9), t(0));
    let mut s = b.accept_with(1, server(9999, 9), t(0));
    exchange(&mut c, &mut s, t(1), &mut Rng(11), 97);
    assert!(connected(&events(&mut s)).is_some());
}

#[test]
fn default_allows_another_authenticated_client_to_resume_visible_session() {
    let (mut a, mut b) = nodes(false);
    let mut c = a.dial_with(&b, client(5), t(0));
    let mut s = b.accept_with(1, server(5555, 5), t(0));
    exchange(&mut c, &mut s, t(1), &mut Rng(7), 97);
    assert!(connected(&events(&mut s)).is_some());
    events(&mut c);
    c.on_closed(t(2));
    s.on_closed(t(2));
    events(&mut c);
    events(&mut s);
    let mut c = a.dial_with(&b, client(9), t(3));
    let mut s = b.accept_with(2, server(9999, 9), t(3));
    exchange(&mut c, &mut s, t(4), &mut Rng(17), 97);
    assert!(connected(&events(&mut s)).is_some());
}

#[test]
fn default_allows_client_ident_for_another_authenticated_clients_addrvec() {
    let (mut a, mut b) = nodes(false);
    let mut c = a.dial_with(&b, client(5), t(0));
    let mut s = b.accept_with(1, server(5555, 5), t(0));
    exchange(&mut c, &mut s, t(1), &mut Rng(7), 97);
    assert!(connected(&events(&mut s)).is_some());
    events(&mut c);
    let mut attacker = Node::new(
        EntityName::CLIENT,
        9999,
        1,
        PolicyTable::uniform(Policy::lossless_client(0)),
    );
    let mut attack = attacker.dial_with(&b, client(9), t(2));
    let mut accepted = b.accept_with(2, server(9999, 9), t(2));
    exchange(&mut attack, &mut accepted, t(3), &mut Rng(13), 97);
    let es = events(&mut accepted);
    assert!(connected(&es).is_some(), "{es:?}");
}
