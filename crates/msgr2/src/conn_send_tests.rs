// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
use super::*;

fn ready() -> Connection {
    let policy = Policy::lossless_client(0);
    let cfg = Config::new(
        EntityName::new(EntityName::CLIENT, 1),
        EntityAddrVec::single(EntityAddr::blank()),
        PolicyTable::uniform(policy),
    );
    let table = SessionTable::new(1);
    let mut session = Session::new(
        SessionKey::Anon(1),
        policy,
        EntityAddrVec::single(EntityAddr::blank()),
    );
    session.active = Some(1);
    session.state = SessState::Ready;
    let sid = table.insert(session);
    let mut c = Connection::base(
        1,
        Role::Client,
        cfg,
        table,
        EntityAddr::blank(),
        EntityName::OSD,
        policy,
    );
    c.sid = Some(sid);
    c.st = St::Ready;
    c
}

fn message(tid: u64, data: usize) -> Message {
    Message {
        tid,
        msg_type: 42,
        front: vec![1; 40],
        data: Bytes::from(vec![7; data]),
        ..Default::default()
    }
}

/// A message the send pump cannot encode is failed alone: it is not kept for replay on a lossless session, where it
/// used to go back to the front of the replay queue on every reconnect and so blocked every later message to the peer.
#[test]
fn a_message_that_fails_to_encode_is_dropped_not_replayed() {
    let mut c = ready();
    assert!(c.send_message(message(1, 8193)), "within cfg.limits");
    // an encoder limit narrower than the connection's stands in for an environmental encode failure
    c.enc.set_limits(Limits {
        max_frame: 4096,
        ..Limits::default()
    });
    c.poll_output();
    let evs: Vec<Event> = std::iter::from_fn(|| c.poll_event()).collect();
    assert!(
        evs.iter()
            .any(|e| matches!(e, Event::Fault(FaultReason::Frame(_)))),
        "{evs:?}"
    );
    // a reconnect moves `sent` back to the front of the send order: the failed message must not be there
    let replayed = c.sess(|s| {
        s.requeue_for_replay();
        s.unsent()
    });
    assert_eq!(replayed, Some(0), "the failed message is not replayed");
    // the link takes later messages again
    assert!(c.send_message(message(2, 100)));
}
