// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Frame size ceilings that do not depend on the memory pools: before Ready every frame, and after Ready every
//! non-MESSAGE frame, is held to `MAX_CONTROL_FRAME` (a peer must not make us reserve its declared length).
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::auth::MODE_CRC;
use msgr2::payload::{AuthRequest, Hello};
use msgr2::*;

const OSD: u8 = EntityName::OSD;
const BANNER_LEN: usize = 26;

fn faulted(c: &mut Connection) -> Option<FaultReason> {
    events(c).into_iter().find_map(|e| match e {
        Event::Fault(r) => Some(r),
        _ => None,
    })
}

/// A control frame with `len` payload bytes, encoded by a sender without a control ceiling of its own (what a peer
/// with the compatible wire shape may legally put on the wire; the receiver must bound it).
fn control_frame(tag: Tag, len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = Encoder::new(Revision::V21);
    e.set_limits(Limits::wire_shape());
    e.encode_control(tag as u8, &vec![0u8; len], &mut out)
        .unwrap();
    out
}

fn oversized(tag: Tag) -> Vec<u8> {
    control_frame(tag, MAX_CONTROL_FRAME as usize + 1)
}

fn banner_of_peer() -> Vec<u8> {
    let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    let b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut c = a.dial(&b, t(0));
    c.poll_output()[..BANNER_LEN].to_vec()
}

#[test]
fn oversized_pre_auth_frames_fault_before_any_body_is_taken() {
    for tag in [Tag::Hello, Tag::AuthRequest, Tag::ClientIdent, Tag::Message] {
        let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
        let mut s = b.accept(1, t(0));
        let mut wire = banner_of_peer();
        // only the preamble + a little body: the fault must come without waiting for the declared length
        wire.extend_from_slice(&oversized(tag)[..200]);
        let mut rng = Rng(3);
        feed(&mut s, &wire, t(1), &mut rng, 64);
        let f = faulted(&mut s);
        assert!(
            matches!(
                f,
                Some(FaultReason::Frame(
                    Error::SegmentTooLarge(_) | Error::FrameTooLarge(_)
                ))
            ),
            "{tag:?} {f:?}"
        );
    }
}

#[test]
fn ready_connection_refuses_oversized_control_frames_but_not_messages() {
    for tag in [Tag::Keepalive2, Tag::Ack, Tag::PlacementControl] {
        let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
        let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
        let mut rng = Rng(5);
        let mut c = a.dial(&b, t(0));
        let mut s = b.accept(1, t(0));
        exchange(&mut c, &mut s, t(1), &mut rng, 64);
        events(&mut c);
        events(&mut s);
        // a big message passes
        c.send_message(msg(1, 42, 1 << 20));
        exchange(&mut c, &mut s, t(2), &mut rng, 4096);
        assert_eq!(msgs(&events(&mut s)).len(), 1);
        let wire = oversized(tag);
        feed(&mut s, &wire[..200], t(3), &mut rng, 64);
        let f = faulted(&mut s);
        assert!(
            matches!(f, Some(FaultReason::Frame(Error::FrameTooLarge(_)))),
            "{tag:?} {f:?}"
        );
    }
}

/// The control ceiling is our own resource bound, not a protocol bound: the compat client profile (`Limits::wire_shape`,
/// no control ceiling of its own) takes a pre-READY control frame above `MAX_CONTROL_FRAME` (a cephx AUTH_DONE with
/// service tickets and long caps; classic has no cap either). The server profile keeps the ceiling, so the same
/// declared frame faults there before any body byte is reserved.
#[test]
fn the_compat_client_profile_has_no_pre_ready_control_ceiling() {
    let big = control_frame(Tag::AuthDone, 128 << 10);
    // server profile: fault at the preamble, without waiting for the declared length
    let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut s = b.accept(1, t(0));
    let mut wire = banner_of_peer();
    wire.extend_from_slice(&big[..200]);
    let mut rng = Rng(3);
    feed(&mut s, &wire, t(1), &mut rng, 64);
    let f = faulted(&mut s);
    assert!(
        matches!(
            f,
            Some(FaultReason::Frame(
                Error::SegmentTooLarge(_) | Error::FrameTooLarge(_)
            ))
        ),
        "{f:?}"
    );

    // compat client profile: no ceiling; the link takes the frame and waits for its body
    let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    a.cfg.limits = Limits::wire_shape();
    let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    let peer_banner = s.poll_output();
    feed(&mut c, &peer_banner, t(1), &mut rng, 64);
    assert!(faulted(&mut c).is_none());
    feed(&mut c, &big[..200], t(2), &mut rng, 64);
    assert!(
        faulted(&mut c).is_none(),
        "the client shape has no pre-READY control ceiling"
    );
}

/// spec 9 / `PREAUTH_TRANSCRIPT_MAX`: the handshake transcript is kept for AUTH_SIGNATURE (the session key exists only
/// after AUTH_DONE), so a peer that never authenticates must not grow it past the cap. Before the cap this peer grew
/// the buffer for the whole handshake timeout at line rate (unauthenticated OOM).
#[test]
fn an_unauthenticated_peer_cannot_grow_the_pre_auth_transcript_past_the_cap() {
    let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut s = b.accept(1, t(0));
    let mut rng = Rng(7);
    // the peer's banner and HELLO: the server now waits for AUTH_REQUEST
    let mut wire = banner_of_peer();
    let hello = Hello {
        entity_type: OSD,
        peer_addr: addr(1, 6800, 99),
    }
    .to_bytes()
    .unwrap();
    Encoder::new(Revision::V21)
        .encode_control(Tag::Hello as u8, &hello, &mut wire)
        .unwrap();
    feed(&mut s, &wire, t(1), &mut rng, 64);
    events(&mut s);
    let payload = AuthRequest {
        method: 1, // cephx: the NONE-only server answers AUTH_BAD_METHOD
        preferred_modes: vec![MODE_CRC],
        auth_payload: vec![0u8; MAX_CONTROL_FRAME as usize / 2],
    }
    .to_bytes()
    .unwrap();
    let mut frame = Vec::new();
    Encoder::new(Revision::V21)
        .encode_control(Tag::AuthRequest as u8, &payload, &mut frame)
        .unwrap();
    let mut sent = 0usize;
    let mut now = 1;
    let mut f = None;
    while sent <= PREAUTH_TRANSCRIPT_MAX + frame.len() {
        feed(&mut s, &frame, t(now), &mut rng, 4096);
        sent += frame.len();
        now += 1;
        f = faulted(&mut s);
        if f.is_some() {
            break;
        }
    }
    assert!(
        matches!(
            f,
            Some(FaultReason::Protocol("pre-auth transcript too large"))
        ),
        "no transcript fault after {sent} transcript bytes: {f:?}"
    );
    assert!(
        sent <= PREAUTH_TRANSCRIPT_MAX + frame.len(),
        "the transcript stayed bounded: {sent} bytes"
    );
}

/// The transcript limit must also bound allocations from declared lengths, before
/// an unauthenticated peer sends the body that would trip pre_rx_append.
#[test]
fn pre_auth_declared_frame_cannot_bypass_transcript_budget() {
    let mut failures = Vec::new();
    for (rev, admitted) in [
        (Revision::V20, false),
        (Revision::V21, false),
        (Revision::V20, true),
        (Revision::V21, true),
    ] {
        let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
        a.cfg.limits = Limits::wire_shape();
        let b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
        let mut c = Connection::client(
            77,
            a.cfg.clone(),
            a.table.clone(),
            Box::new(msgr2::auth::AuthNoneClient {
                name: a.cfg.name,
                global_id: 0,
            }),
            OSD,
            b.addrs.clone(),
            b.addrs.0[0],
        );
        if admitted {
            let budget =
                std::rc::Rc::new(std::cell::RefCell::new(DispatchBudget::new(8, 4).unwrap()));
            c.attach_dispatch(budget).unwrap();
        }
        c.on_connected(t(0));
        let mut banner = Vec::new();
        Banner {
            supported: if rev == Revision::V21 {
                FEATURE_REVISION_1
            } else {
                0
            },
            required: 0,
        }
        .encode(&mut banner);
        if admitted {
            c.on_bytes_admitted(&banner, t(1));
        } else {
            c.on_bytes(&banner, t(1));
        }
        let mut encoder = Encoder::new(rev);
        encoder.set_limits(Limits::wire_shape());
        let mut wire = Vec::new();
        encoder
            .encode_control(
                Tag::Hello as u8,
                &vec![0; PREAUTH_TRANSCRIPT_MAX + 1],
                &mut wire,
            )
            .unwrap();
        // The length alone must fault: previously V21 reserved the declared
        // segment with its first byte, and V20 exposed it through recv_buf.
        if admitted {
            c.on_bytes_admitted(&wire[..PREAMBLE_LEN], t(2));
        } else {
            c.on_bytes(&wire[..PREAMBLE_LEN], t(2));
        }
        if !matches!(
            faulted(&mut c),
            Some(FaultReason::Frame(Error::FrameTooLarge(_)))
        ) {
            failures.push((rev, admitted));
        }
    }
    assert!(
        failures.is_empty(),
        "unbounded pre-auth frames: {failures:?}"
    );
}
