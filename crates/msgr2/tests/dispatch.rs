// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Client-only admitted input, with the unchanged server as the framing/authentication peer.
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::auth::*;
use msgr2::*;
use std::cell::RefCell;
use std::rc::Rc;

fn domain() -> Rc<RefCell<DispatchBudget>> {
    Rc::new(RefCell::new(DispatchBudget::new(8, 4).unwrap()))
}
fn setup(rev: Revision, secure: bool) -> (Connection, Connection, Rc<RefCell<DispatchBudget>>) {
    let mut a = Node::new(
        EntityName::CLIENT,
        1,
        1,
        PolicyTable::uniform(Policy::lossy_client(0)),
    );
    let mut b = Node::new(
        EntityName::OSD,
        2,
        2,
        PolicyTable::uniform(Policy::stateless_registered_server(0)),
    );
    a.cfg.v20_only = rev == Revision::V20;
    b.cfg.v20_only = rev == Revision::V20;
    let mode = if secure { MODE_SECURE } else { MODE_CRC };
    let secret: Vec<u8> = (0..64).collect();
    let mut c = Connection::client(
        70,
        a.cfg.clone(),
        a.table.clone(),
        Box::new(KeyedClient {
            key: vec![9; 16],
            secret: secret.clone(),
            modes: vec![mode],
            method: AUTH_METHOD_CEPHX,
        }),
        EntityName::OSD,
        b.addrs.clone(),
        b.addrs.0[0],
    );
    let owner = domain();
    c.attach_dispatch(owner.clone()).unwrap();
    assert_eq!(
        c.on_bytes_admitted(&[0; 32], t(0)).consumed,
        0,
        "preconnect accepts nothing"
    );
    c.on_connected(t(0));
    let s = b.accept_with(
        1,
        Box::new(KeyedServer {
            peer_name: None,
            key: vec![9; 16],
            secret,
            rounds: 2,
            done: 0,
            methods: vec![AUTH_METHOD_CEPHX],
            modes: vec![mode],
        }),
        t(0),
    );
    (c, s, owner)
}
fn pump(c: &mut Connection, s: &mut Connection, quantum: usize) {
    for _ in 0..100 {
        let to_server = c.poll_output_chunks().concat();
        for piece in to_server.chunks(quantum) {
            s.on_bytes(piece, t(1));
        }
        let to_client = s.poll_output();
        for piece in to_client.chunks(quantum) {
            c.rx_progress(t(1));
            let accepted = c.on_bytes_admitted(piece, t(1));
            assert_eq!(
                accepted.consumed,
                piece.len(),
                "handshake paused: {accepted:?}"
            );
            assert!(!matches!(
                accepted.state,
                RxFeedState::DispatchBlocked { .. }
            ));
        }
        if to_server.is_empty() && to_client.is_empty() {
            return;
        }
    }
    panic!("in-memory admitted handshake did not quiesce");
}
fn next_message(c: &mut Connection) -> Incoming {
    for _ in 0..32 {
        match c.poll_event() {
            Some(Event::Message(message)) => return message,
            Some(Event::Fault(reason)) => panic!("connection fault {reason:?}"),
            Some(_) => {}
            None => break,
        }
    }
    panic!("missing verified message");
}

#[test]
fn real_auth_mode_changes_coalesced_messages_and_no_edge_resume_all_modes() {
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            for quantum in [1, usize::MAX] {
                let (mut c, mut s, owner) = setup(rev, secure);
                s.send_message(msg(1, 42, 8)); // SERVER_IDENT and first MESSAGE may share one output.
                pump(&mut c, &mut s, quantum);
                assert_eq!(c.state(), ConnState::Ready);
                assert_eq!(s.state(), ConnState::Ready);
                assert_eq!(c.mode(), if secure { MODE_SECURE } else { MODE_CRC });
                assert_eq!(
                    owner.borrow_mut().try_acquire(1),
                    Err(DispatchError::NoCredit)
                );
                let first = next_message(&mut c);
                assert_eq!(first.dispatch.charge(), Some(8));
                assert_eq!(&first.front[..], &[1; 8]);
                assert_eq!(
                    owner.borrow_mut().try_acquire(1),
                    Err(DispatchError::NoCredit),
                    "pop is not dispatch retirement"
                );
                s.send_keepalive(t(2));
                let controls = s.poll_output();
                s.send_message(Message {
                    tid: 2,
                    msg_type: 42,
                    front: vec![2; 2],
                    data: vec![3; 64].into(),
                    ..Default::default()
                });
                let wire = s.poll_output();
                let joined = [controls.as_slice(), wire.as_slice()].concat();
                c.rx_progress(t(3));
                let idle_deadline = c.next_timer();
                let paused = c.on_bytes_admitted(&joined, t(4));
                let RxFeedState::DispatchBlocked { generation } = paused.state else {
                    panic!("{paused:?}");
                };
                let prefix = if secure && rev == Revision::V21 {
                    96
                } else {
                    32
                };
                assert_eq!(paused.consumed, controls.len() + prefix);
                assert_eq!(
                    c.next_timer(),
                    idle_deadline,
                    "parser replay must not manufacture physical activity"
                );
                assert_eq!(owner.borrow_mut().arm(generation), Ok(false));
                assert_eq!(c.on_bytes_admitted(&[], t(5)).consumed, 0);
                assert_eq!(c.next_timer(), idle_deadline);
                let retained_payload = first.front.clone();
                drop(first);
                let resumed = c.on_bytes_admitted(&[], t(6));
                assert_eq!(resumed.consumed, 0);
                assert!(!matches!(
                    resumed.state,
                    RxFeedState::DispatchBlocked { .. }
                ));
                // admitted at the dispatch owner: the client link has no ingress pool, so it carries no frame-completion
                // deadline (spec 4.3), and physical parsing does not move the idle timer
                assert_eq!(c.next_timer(), idle_deadline);
                let done = c.on_bytes_admitted(&joined[paused.consumed..], t(7));
                assert_eq!(done.consumed, joined.len() - paused.consumed);
                assert_eq!(done.state, RxFeedState::FrameReady);
                assert_eq!(c.next_timer(), idle_deadline);
                assert_eq!(&retained_payload[..], &[1; 8]);
                let second = next_message(&mut c);
                assert_eq!(second.dispatch.charge(), Some(66));
                assert_eq!(&second.data[..], &[3; 64]);
            }
        }
    }
}

#[test]
fn queued_or_popped_message_keeps_logical_credit_across_connection_close() {
    for pop_first in [false, true] {
        for secure in [false, true] {
            let (mut c, mut s, owner) = setup(Revision::V21, secure);
            s.send_message(msg(1, 42, 8));
            pump(&mut c, &mut s, usize::MAX);
            let held = pop_first.then(|| next_message(&mut c));
            c.close();
            assert_eq!(c.on_bytes_admitted(&[1; 64], t(9)).consumed, 0);
            assert_eq!(
                owner.borrow_mut().try_acquire(1),
                Err(DispatchError::NoCredit)
            );
            let message = held.unwrap_or_else(|| next_message(&mut c));
            // the payload may outlive the message; the logical credit belongs to the message alone
            let retained = message.front.clone();
            assert_eq!(
                owner.borrow_mut().try_acquire(1),
                Err(DispatchError::NoCredit)
            );
            drop(message);
            let proof = owner.borrow_mut().try_acquire(9).unwrap();
            assert_eq!(&retained[..], &[1; 8]);
            drop(proof);
        }
    }
}

#[test]
fn server_handoff_excludes_local_admission() {
    fn send<T: Send>() {}
    fn send_sync<T: Send + Sync>() {}
    send::<Config>();
    send::<Handoff>();
    send_sync::<Incoming>();
    let (c, mut s, owner) = setup(Revision::V21, false);
    assert_eq!(s.attach_dispatch(owner), Err(Error::Busy));
    assert!(c.into_handoff().is_none());
    let mut a = Node::new(
        EntityName::CLIENT,
        1,
        1,
        PolicyTable::uniform(Policy::lossy_client(0)),
    );
    let mut peer = a.accept(2, t(0));
    assert_eq!(peer.attach_dispatch(domain()), Err(Error::Busy));
}

#[test]
fn legacy_input_faults_gated_client_without_accepting_bytes() {
    for action in [0, 1] {
        let (mut c, _s, owner) = setup(Revision::V21, true);
        match action {
            0 => c.on_bytes(&[1; 64], t(2)),
            _ => c.on_bytes_guarded(&[1; 64], t(2), Default::default()),
        }
        let ev = events(&mut c);
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Fault(FaultReason::Frame(Error::Busy))))
        );
        assert_eq!(c.on_bytes_admitted(&[], t(3)).consumed, 0);
        let proof = owner.borrow_mut().try_acquire(9).unwrap();
        drop(proof);
    }
}
