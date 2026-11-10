// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! AUTH_NONE on the msgr2 layer (doc/spec/auth-none.md): control-frame vectors, crc-only handshake,
//! AUTH_BAD_METHOD lists.
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::auth::*;
use msgr2::payload::*;
use msgr2::*;
use std::cell::RefCell;
use std::rc::Rc;

const OSD: u8 = EntityName::OSD;

const MON_PAYLOAD: [u8; 18] = [0x0a, 4, 0, 0, 0, 1, 0, 0, 0, b'3', 0, 0, 0, 0, 0, 0, 0, 0];

fn le(v: &[u32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

#[test]
fn control_frame_vectors() {
    // AUTH_REQUEST body for the mon variant
    let mut want = le(&[1, 1, 1, 18]);
    want.extend_from_slice(&MON_PAYLOAD);
    let req = AuthRequest {
        method: AUTH_METHOD_NONE,
        preferred_modes: vec![MODE_CRC],
        auth_payload: MON_PAYLOAD.to_vec(),
    };
    assert_eq!(req.to_bytes().unwrap(), want);
    assert_eq!(AuthRequest::from_bytes(&want).unwrap(), req);

    // AUTH_DONE body (gid 0x1003, crc, empty)
    let mut want = 0x1003u64.to_le_bytes().to_vec();
    want.extend(le(&[1, 0]));
    let done = AuthDone {
        global_id: 0x1003,
        connection_mode: MODE_CRC,
        auth_payload: vec![],
    };
    assert_eq!(done.to_bytes().unwrap(), want);
    assert_eq!(AuthDone::from_bytes(&want).unwrap(), done);

    // AUTH_BAD_METHOD: NONE vs cephx-only OSD
    let want = [le(&[1]), (-95i32).to_le_bytes().to_vec(), le(&[1, 2, 1, 1])].concat();
    let bad = AuthBadMethod {
        method: AUTH_METHOD_NONE,
        result: -95,
        allowed_methods: vec![AUTH_METHOD_CEPHX],
        allowed_modes: vec![MODE_CRC],
    };
    assert_eq!(bad.to_bytes().unwrap(), want);
    assert_eq!(AuthBadMethod::from_bytes(&want).unwrap(), bad);
}

#[test]
fn none_to_none_handshake_is_crc_with_zero_signatures() {
    let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut c = a.dial(&b, t(0));
    c.send_message(msg(1, 42, 16));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut Rng(3), 100);
    let (ec, es) = (events(&mut c), events(&mut s));
    assert!(
        connected(&ec).is_some() && connected(&es).is_some(),
        "{ec:?} {es:?}"
    );
    assert_eq!(msgs(&es).len(), 1);
}

#[derive(Debug, Default)]
struct Seen {
    bad: Vec<(u32, i32, Vec<u32>, Vec<u32>)>,
}

/// Client that offers a fixed method and records the AUTH_BAD_METHOD answer.
#[derive(Debug)]
struct Probe {
    method: u32,
    modes: Vec<u32>,
    seen: Rc<RefCell<Seen>>,
}
impl AuthClientHandler for Probe {
    fn get_auth_request(&mut self, _: u8) -> Result<AuthRequestOut, AuthError> {
        Ok(AuthRequestOut {
            method: self.method,
            preferred_modes: self.modes.clone(),
            payload: MON_PAYLOAD.to_vec(),
        })
    }
    fn handle_auth_reply_more(&mut self, _: &[u8]) -> Result<Vec<u8>, AuthError> {
        Err(AuthError("more".into()))
    }
    fn handle_auth_done(&mut self, _: u64, _: u32, _: &[u8]) -> Result<AuthSecrets, AuthError> {
        Ok(AuthSecrets::default())
    }
    fn handle_auth_bad_method(
        &mut self,
        method: u32,
        result: i32,
        allowed_methods: &[u32],
        allowed_modes: &[u32],
    ) -> Result<(), AuthError> {
        self.seen.borrow_mut().bad.push((
            method,
            result,
            allowed_methods.to_vec(),
            allowed_modes.to_vec(),
        ));
        Err(AuthError("rejected".into()))
    }
}

fn bad_method(
    client: Probe,
    server: Box<dyn AuthServerHandler>,
) -> Vec<(u32, i32, Vec<u32>, Vec<u32>)> {
    let seen = client.seen.clone();
    let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut c = a.dial_with(&b, Box::new(client), t(0));
    let mut s = b.accept_with(1, server, t(0));
    exchange(&mut c, &mut s, t(1), &mut Rng(5), 100);
    assert!(connected(&events(&mut c)).is_none());
    seen.take().bad
}

fn keyed_server(methods: Vec<u32>, modes: Vec<u32>) -> Box<dyn AuthServerHandler> {
    Box::new(KeyedServer {
        peer_name: None,
        key: vec![],
        secret: vec![],
        rounds: 0,
        done: 0,
        methods,
        modes,
    })
}

#[test]
fn none_against_cephx_only_acceptor_gets_crc_filtered_bad_method() {
    let seen = Rc::new(RefCell::new(Seen::default()));
    let got = bad_method(
        Probe {
            method: AUTH_METHOD_NONE,
            modes: vec![MODE_CRC],
            seen,
        },
        keyed_server(vec![AUTH_METHOD_CEPHX], vec![MODE_SECURE, MODE_CRC]),
    );
    assert_eq!(got, [(1, -95, vec![2], vec![1])]);
}

#[test]
fn cephx_against_none_only_acceptor_gets_bad_method() {
    let seen = Rc::new(RefCell::new(Seen::default()));
    let got = bad_method(
        Probe {
            method: AUTH_METHOD_CEPHX,
            modes: vec![MODE_CRC],
            seen,
        },
        Box::new(AuthNoneServer::default()),
    );
    assert_eq!(got, [(2, -95, vec![1], vec![1])]);
}

#[test]
fn none_with_secure_only_modes_is_rejected_with_crc_list() {
    let seen = Rc::new(RefCell::new(Seen::default()));
    let got = bad_method(
        Probe {
            method: AUTH_METHOD_NONE,
            modes: vec![MODE_SECURE],
            seen,
        },
        Box::new(AuthNoneServer::default()),
    );
    assert_eq!(got, [(1, -95, vec![1], vec![1])]);
}
