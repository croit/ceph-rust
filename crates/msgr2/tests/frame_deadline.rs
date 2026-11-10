// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Frame-completion deadline (spec 4.3): a frame that holds an ingress-pool reservation must complete within
//! `ms_connection_ready_timeout` + its declared size at `FRAME_MIN_RATE`; otherwise the link faults loudly. A peer
//! that declares a large frame and then trickles it used to keep its reservation (and with it the whole pool of its
//! core) for as long as it refreshed the idle timer — one byte every few minutes was enough. A link that does not gate
//! frames through an ingress pool (rustyrados/rados-rt clients, the mon client) carries no such deadline, like classic.
mod common;
use common::*;
use denc::types::EntityName;
use ingress::IngressCredits;
use msgr2::*;

const OSD: u8 = EntityName::OSD;
const MB: usize = 1 << 20;

fn faulted(c: &mut Connection) -> Option<FaultReason> {
    events(c).into_iter().find_map(|e| match e {
        Event::Fault(r) => Some(r),
        _ => None,
    })
}

fn ready() -> (Connection, Connection, Rng) {
    let mut a = Node::new(OSD, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(OSD, 2, 2, PolicyTable::osd_cluster());
    let mut rng = Rng(11);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut rng, 64);
    events(&mut c);
    events(&mut s);
    (c, s, rng)
}

/// Server link with an ingress pool: the accepting side gates MESSAGE frames at their header.
fn ready_gated() -> (Connection, Connection, Rng, IngressCredits) {
    let (c, mut s, rng) = ready();
    let credits = IngressCredits::with_frames(&[(1, 64 * MB as u64)], 64);
    s.set_frame_gate(Some(credits.frame_gate(0)));
    (c, s, rng, credits)
}

/// A MESSAGE frame of `n` data bytes (no `common::msg` tripling).
fn message(tid: u64, n: usize) -> Message {
    Message {
        msg_type: 42,
        tid,
        version: 1,
        front: vec![1; 40],
        data: vec![7; n].into(),
        ..Default::default()
    }
}

#[test]
fn a_stalled_frame_faults_at_its_deadline_and_never_holds_the_pool_forever() {
    let (mut c, mut s, mut rng, _credits) = ready_gated();
    // 4 MiB declared: allowance = ready timeout (10 s) + one second (4 MiB at 8 MiB/s), armed at t = 2 s
    c.send_message(message(1, 4 * MB));
    let wire = c.poll_output();
    feed(&mut s, &wire[..64 * 1024], t(2000), &mut rng, 64);
    assert!(faulted(&mut s).is_none(), "the frame is in progress");
    // no progress at all, and the idle timer is far away: the frame deadline is the next timer
    assert_eq!(s.next_timer(), Some(t(13_000)), "2 s + 10 s + 1 s");
    s.on_timer(t(12_999));
    assert!(faulted(&mut s).is_none(), "inside the allowance");
    s.on_timer(t(13_000));
    let f = faulted(&mut s);
    assert_eq!(f, Some(FaultReason::Timeout("frame")), "{f:?}");
}

/// A link without an ingress pool (`set_frame_gate` never called: rustyrados, the mon client) has no per-frame
/// deadline: a slow frame neither faults nor loses its data, however long it takes.
#[test]
fn a_link_without_an_ingress_pool_has_no_frame_deadline() {
    let (mut c, mut s, mut rng) = ready();
    c.send_message(message(1, 4 * MB));
    let wire = c.poll_output();
    feed(&mut s, &wire[..64 * 1024], t(2000), &mut rng, 64);
    assert_eq!(
        s.next_timer(),
        Some(t(2000 + 900_000)),
        "no frame deadline: only the idle timer"
    );
    s.on_timer(t(2000 + 900_000 - 1));
    assert!(faulted(&mut s).is_none());
    feed(
        &mut s,
        &wire[64 * 1024..],
        t(2000 + 800_000),
        &mut rng,
        4096,
    );
    assert_eq!(msgs(&events(&mut s)).len(), 1, "the slow frame completed");
}

#[test]
fn a_frame_that_completes_in_time_arms_no_deadline() {
    let (mut c, mut s, mut rng, _credits) = ready_gated();
    c.send_message(message(1, 4 * MB));
    let wire = c.poll_output();
    feed(&mut s, &wire, t(2000), &mut rng, 4096);
    assert_eq!(msgs(&events(&mut s)).len(), 1);
    assert_eq!(
        s.next_timer(),
        Some(t(2000 + 900_000)),
        "only the idle timer is left"
    );
    s.on_timer(t(2000 + 900_000 - 1));
    assert!(faulted(&mut s).is_none());
}

/// Our own backpressure (input held for queue room / store admission, `hold_rx`) never faults a link: no deadline runs
/// while the owner does not read, and a resume grants the full allowance again from then.
#[test]
fn a_locally_held_link_keeps_its_frame() {
    let (mut c, mut s, mut rng, _credits) = ready_gated();
    c.send_message(message(1, 4 * MB));
    let wire = c.poll_output();
    feed(&mut s, &wire[..64 * 1024], t(2000), &mut rng, 64);
    assert_eq!(s.next_timer(), Some(t(13_000)));
    s.hold_rx(true, t(2000));
    assert_eq!(
        s.next_timer(),
        Some(t(2000 + 900_000)),
        "held: only the idle timer"
    );
    s.on_timer(t(60_000));
    assert!(
        faulted(&mut s).is_none(),
        "a held link never faults on the frame deadline"
    );
    s.hold_rx(false, t(60_000));
    assert_eq!(
        s.next_timer(),
        Some(t(71_000)),
        "resumed at 60 s: 10 s + 1 s again"
    );
    s.on_timer(t(71_000));
    assert_eq!(faulted(&mut s), Some(FaultReason::Timeout("frame")));
}
