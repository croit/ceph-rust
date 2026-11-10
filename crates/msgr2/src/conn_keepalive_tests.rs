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

/// A KEEPALIVE2 that cannot be encoded must fault the link: swallowing the error would stop the heartbeat silently
/// and the peer would drop the connection on its own idle timeout, with no local trace but the peer's reset.
#[test]
fn a_keepalive_that_cannot_be_encoded_faults() {
    let mut c = ready();
    // no frame fits this encoder: the limit is the only way to reach the send error (a peer never sees it)
    c.enc.set_limits(Limits {
        max_frame: 0,
        ..Limits::default()
    });
    c.send_keepalive(Duration::from_secs(1));
    let ev: Vec<Event> = std::iter::from_fn(|| c.poll_event()).collect();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Fault(FaultReason::Frame(Error::FrameTooLarge(_))))),
        "{ev:?}"
    );
}

fn keepalive_wire(peer: &mut Encoder, sec: u32) -> Vec<u8> {
    let mut wire = Vec::new();
    peer.encode_control(
        Tag::Keepalive2 as u8,
        &Keepalive2 { sec, nsec: 1 }.to_bytes().unwrap(),
        &mut wire,
    )
    .unwrap();
    wire
}

fn acks(replies: &mut Decoder, wire: &[u8]) -> Vec<u32> {
    replies.feed(wire);
    let mut v = Vec::new();
    while let Some(frame) = replies.poll_owned().unwrap() {
        assert_eq!(frame.tag, Tag::Keepalive2Ack as u8);
        let ack = Keepalive2Ack::from_bytes(&frame.segs[0]).unwrap();
        assert_eq!(ack.nsec, 1);
        v.push(ack.sec);
    }
    v
}

/// A peer that sends KEEPALIVE2 without reading the replies owes at most one pending echo, the newest stamp
/// (the receiver records only the echoed stamp); queued output does not grow with the request count. Every
/// framing revision and security mode, unbounded and bounded polls.
#[test]
fn nonreading_peer_keepalive_echoes_coalesce() {
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            let mut c = ready();
            c.install_codec(rev).unwrap();
            let mut peer = Encoder::new(rev);
            let mut replies = Decoder::new(rev);
            if secure {
                let secret = ConnSecret::new(&[7; 64]).unwrap();
                c.enter_mode(MODE_SECURE, &[7; 64]).unwrap();
                peer.set_secure(&secret, Role::Server).unwrap();
                replies.set_secure(&secret, Role::Server).unwrap();
            }
            for stamp in 0..4096 {
                c.on_bytes(&keepalive_wire(&mut peer, stamp), Duration::from_secs(1));
            }
            assert_eq!(c.st, St::Ready);
            assert!(
                c.out.is_empty(),
                "no echo is encoded before output is polled"
            );
            assert!(c.has_output());
            assert_eq!(acks(&mut replies, &c.poll_output()), [4095]);
            assert!(!c.has_output());

            // bounded drain: while earlier output is unconsumed, later requests add no bytes
            c.on_bytes(&keepalive_wire(&mut peer, 5000), Duration::from_secs(1));
            let first = c.poll_output_bounded(1);
            let pending = c.out.len() + c.out_chunks.iter().map(Bytes::len).sum::<usize>();
            for stamp in 5001..6000 {
                c.on_bytes(&keepalive_wire(&mut peer, stamp), Duration::from_secs(1));
                assert!(c.poll_output_bounded(0).is_empty());
            }
            assert_eq!(
                c.out.len() + c.out_chunks.iter().map(Bytes::len).sum::<usize>(),
                pending
            );
            let mut wire = first;
            wire.extend(c.poll_output_bounded(usize::MAX));
            wire.extend(c.poll_output_bounded(usize::MAX));
            assert_eq!(acks(&mut replies, &wire), [5000, 5999]);
            assert!(!c.has_output());
            assert!(!c.has_events());
        }
    }
}

/// `Debug` of a connection (embedded in links and sessions of other crates) must never print the HMAC key.
#[test]
fn connection_debug_hides_the_session_key() {
    let mut c = ready();
    c.session_key = crate::auth::Secret::new(vec![0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A]);
    let text = format!("{c:?}");
    assert!(text.contains("<redacted 8 bytes>"), "{text}");
    for needle in ["171, 205", "AB, CD", "ab, cd", "0xab", "[171"] {
        assert!(!text.contains(needle), "key bytes in Debug: {text}");
    }
}
