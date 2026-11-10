// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Header-time admission (`Decoder::set_gate`, doc/design/memory-envelope.md G1): a MESSAGE frame whose preamble is
//! parsed reserves its length in the ingress pool before any body byte is consumed; a full pool parks the decoder at
//! the header (nothing assembled, nothing allocated), a retry after space frees assembles the buffered bytes, the
//! reservation rides on the frame until it is dropped.
use ingress::IngressCredits;
use msgr2::*;

fn wire(rev: Revision, seq: u64, data: usize) -> Vec<u8> {
    let h = MsgHeader2 {
        seq,
        tid: seq,
        msg_type: 42,
        ..Default::default()
    }
    .to_bytes();
    let d: Vec<u8> = (0..data)
        .map(|i| (i as u8).wrapping_add(seq as u8))
        .collect();
    let mut out = Vec::new();
    Encoder::new(rev)
        .encode_message(&h, &[1; 40], &[], &d, &mut out)
        .unwrap();
    out
}

fn run(rev: Revision) {
    const MB: usize = 1 << 20;
    // a frame above the pool faults instead of taking it
    // (`a_frame_above_the_pool_capacity_faults_instead_of_taking_the_pool`)
    let w = wire(rev, 1, 2 * MB);
    let credits = IngressCredits::with_frames(&[(1, 3 * MB as u64)], 64);
    let gate = credits.frame_gate(0);
    let mut d = Decoder::new(rev);
    d.set_gate(Some(gate.clone()));
    // the pool is full: a hog holds the whole allowance
    let hog = credits.reserve(0, 3 * MB).unwrap();
    // header + a little body, as one receive chunk
    d.feed(&w[..64 * 1024]);
    assert!(d.poll_owned().unwrap().is_none());
    assert!(d.awaiting_credit());
    assert_eq!(
        d.direct_want(),
        0,
        "no direct receive while parked at the header"
    );
    assert!(d.buffered() <= 64 * 1024, "only the received chunk is held");
    // further chunks the transport may still have in flight stay buffered, nothing is assembled
    d.feed(&w[64 * 1024..128 * 1024]);
    assert!(d.poll_owned().unwrap().is_none());
    assert!(d.awaiting_credit());
    assert!(!d.retry_gate());
    assert_eq!(credits.pool_stats()[0].waiters, 1);
    drop(hog);
    assert!(d.retry_gate());
    assert!(!d.awaiting_credit());
    assert_eq!(credits.pool_stats()[0].waiters, 0);
    for c in w[128 * 1024..].chunks(100 * 1024) {
        d.feed(c);
    }
    let f = d.poll_owned().unwrap().expect("frame");
    assert!(f.credit.0.is_some());
    assert_eq!(f.segs[3].len(), 2 * MB);
    assert!(credits.pool_stats()[0].used >= w.len() as u64);
    // the reservation lives as long as the frame: another input takes the pool over its limit meanwhile
    let top = credits.reserve(0, 3 * MB).unwrap();
    let second = wire(rev, 2, 1000);
    d.feed(&second);
    assert!(
        d.poll_owned().unwrap().is_none(),
        "pool above its limit: the next header waits"
    );
    assert!(d.awaiting_credit());
    drop(top);
    drop(f);
    assert!(d.retry_gate());
    let g = d.poll_owned().unwrap().expect("second frame");
    assert_eq!(g.segs[3].len(), 1000);
    drop(g);
    assert_eq!(credits.pool_stats()[0].used, 0);
    assert!(credits.idle());
}

#[test]
fn a_full_pool_parks_the_decoder_at_the_header_v21() {
    run(Revision::V21);
}

#[test]
fn a_full_pool_parks_the_decoder_at_the_header_v20() {
    run(Revision::V20);
}

#[test]
fn control_frames_and_ungated_decoders_are_not_admitted() {
    let credits = IngressCredits::with_frames(&[(1, 1024)], 8);
    let hog = credits.reserve(0, 1 << 20).unwrap();
    let w = wire(Revision::V21, 1, 100_000);
    let mut plain = Decoder::new(Revision::V21);
    plain.feed(&w);
    assert!(plain.poll_owned().unwrap().is_some());
    drop(hog);
}

/// A MESSAGE frame above its pool's capacity is never faulted for its size: it waits until nothing else of the pool is
/// in flight and is then admitted alone, as classic's byte throttle admits one message above its max (spec 8.2,
/// adr 0175 am. 3).
#[test]
fn a_frame_above_the_pool_capacity_is_admitted_alone() {
    for rev in [Revision::V20, Revision::V21] {
        const MB: usize = 1 << 20;
        let credits = IngressCredits::with_frames(&[(1, MB as u64)], 8);
        let gate = credits.frame_gate(0);
        let mut d = Decoder::new(rev);
        d.set_gate(Some(gate.clone()));
        // 2 MiB declared into a 1 MiB pool: two frames of the pool are in flight, so it waits
        let hog = credits.reserve(0, 4 << 10).unwrap();
        let w = wire(rev, 1, 2 * MB);
        d.feed(&w[..4096]);
        assert!(d.poll_owned().unwrap().is_none(), "{rev:?}");
        assert!(d.awaiting_credit(), "{rev:?}: waits for the empty pool");
        drop(hog);
        assert!(d.retry_gate(), "{rev:?}");
        for c in w[4096..].chunks(64 * 1024) {
            d.feed(c);
        }
        let f = d.poll_owned().unwrap().expect("the frame is processed");
        assert_eq!(f.segs[3].len(), 2 * MB, "{rev:?}");
        assert_eq!(f.data_refused, 0);
        // it held the pool alone while it arrived
        assert!(credits.pool_stats()[0].used >= w.len() as u64);
        drop(f);
        assert!(credits.idle());
        // a frame that fits the pool still passes with others in flight
        let mut d = Decoder::new(rev);
        d.set_gate(Some(credits.frame_gate(0)));
        let ok = wire(rev, 2, MB / 2);
        d.feed(&ok);
        let f = d.poll_owned().unwrap().expect("frame");
        assert_eq!(f.segs[3].len(), MB / 2);
    }
}

/// `osd_client_message_size_cap` (spec 8.2): the size above which a MESSAGE of a link is admitted alone, counted in
/// segment bytes. Above it the frame is neither refused nor faulted.
#[test]
fn a_message_above_the_link_cap_is_admitted_alone() {
    for rev in [Revision::V20, Revision::V21] {
        const MB: usize = 1 << 20;
        let credits = IngressCredits::with_frames(&[(1, 64 * MB as u64)], 8);
        let mut d = Decoder::new(rev);
        d.set_gate(Some(credits.frame_gate(0)));
        d.set_frame_cap(2 * MB as u64);
        // 3 MiB of segments: above the cap, below the pool. With another frame in flight it waits for the pool to be
        // empty; alone it passes.
        let other = credits.reserve(0, 1 << 10).unwrap();
        let over = wire(rev, 1, 3 * MB);
        d.feed(&over[..4096]);
        assert!(d.poll_owned().unwrap().is_none(), "{rev:?}");
        assert!(d.awaiting_credit(), "{rev:?}");
        drop(other);
        assert!(d.retry_gate());
        for c in over[4096..].chunks(64 * 1024) {
            d.feed(c);
        }
        let f = d.poll_owned().unwrap().expect("frame");
        assert_eq!(f.segs[3].len(), 3 * MB);
        drop(f);
        assert!(credits.idle());
        // at the cap: the body (2 MiB data + front) fits; the 41-byte header2 is not counted
        let mut d = Decoder::new(rev);
        d.set_gate(Some(credits.frame_gate(0)));
        d.set_frame_cap(2 * MB as u64 + 64);
        let ok = wire(rev, 2, 2 * MB);
        d.feed(&ok);
        assert_eq!(
            d.poll_owned().unwrap().expect("frame").segs[3].len(),
            2 * MB
        );
    }
}

/// spec 8.2: `osd_client_message_size_cap` counts the segments after the header2 (`sum(seg1..3)`, the bytes Ceph's
/// throttler takes), so a MESSAGE without a body fits even a zero cap and the fixed 41-byte header2 can never be the
/// reason a frame waits alone.
#[test]
fn the_link_cap_counts_segments_after_the_header() {
    let h = MsgHeader2 {
        seq: 1,
        tid: 1,
        msg_type: 42,
        ..Default::default()
    }
    .to_bytes();
    let mut w = Vec::new();
    Encoder::new(Revision::V21)
        .encode_message(&h, &[], &[], &[], &mut w)
        .unwrap();
    let mut d = Decoder::new(Revision::V21);
    d.set_frame_cap(0);
    d.feed(&w);
    let f = d.poll_owned().unwrap().expect("a header-only MESSAGE");
    assert_eq!(f.segs.len(), 1);
    assert_eq!(f.segs[0].len(), h.len());
    // one body byte is above the cap: admitted alone, not refused
    let credits = IngressCredits::with_frames(&[(1, 1 << 20)], 8);
    let mut d = Decoder::new(Revision::V21);
    d.set_gate(Some(credits.frame_gate(0)));
    d.set_frame_cap(0);
    d.feed(&wire(Revision::V21, 1, 1));
    assert_eq!(d.poll_owned().unwrap().expect("frame").segs[3].len(), 1);
}

/// The cap applies to MESSAGE frames of a decoder without a frame gate too (client-role links), and never to control
/// frames (their ceiling is `MAX_CONTROL_FRAME`); above it a frame is processed, never faulted.
#[test]
fn the_link_cap_is_message_only_and_needs_no_gate() {
    const MB: usize = 1 << 20;
    let mut d = Decoder::new(Revision::V21);
    d.set_frame_cap(1024);
    let mut out = Vec::new();
    Encoder::new(Revision::V21)
        .encode_control(Tag::Keepalive2 as u8, &[0u8; 16], &mut out)
        .unwrap();
    d.feed(&out);
    assert!(d.poll_owned().unwrap().is_some(), "control frames pass");
    let over = wire(Revision::V21, 1, MB);
    d.feed(&over);
    let f = d.poll_owned().unwrap().expect("message above the cap");
    assert_eq!(f.segs[3].len(), MB);
}

/// Data probe of the tests: refuses (or keeps) every data segment at or above `from` bytes.
fn probe(from: u64, refuse: bool) -> DataProbe {
    fn refuse_all(_: &[u8], _: &[u8], _: usize, _: usize) -> bool {
        true
    }
    fn keep_all(_: &[u8], _: &[u8], _: usize, _: usize) -> bool {
        false
    }
    DataProbe {
        threshold: from,
        refuse: if refuse { refuse_all } else { keep_all },
    }
}

fn secret() -> ConnSecret {
    ConnSecret::new(&(0..64u8).collect::<Vec<_>>()).unwrap()
}

/// Encoder/decoder pair of one mode; `wire` = one MESSAGE with `data` bytes.
fn message(rev: Revision, secure: bool, seq: u64, data: usize) -> (Encoder, Decoder, Vec<u8>) {
    let mut e = Encoder::new(rev);
    let mut d = Decoder::new(rev);
    if secure {
        e.set_secure(&secret(), Role::Client).unwrap();
        d.set_secure(&secret(), Role::Server).unwrap();
    }
    let w = encode_message(&mut e, seq, data);
    (e, d, w)
}

fn encode_message(e: &mut Encoder, seq: u64, data: usize) -> Vec<u8> {
    let h = MsgHeader2 {
        seq,
        tid: seq,
        msg_type: 42,
        ..Default::default()
    }
    .to_bytes();
    let d: Vec<u8> = (0..data)
        .map(|i| (i as u8).wrapping_add(seq as u8))
        .collect();
    let mut out = Vec::new();
    e.encode_message(&h, &[1; 40], &[], &d, &mut out).unwrap();
    out
}

/// A refused data segment is consumed through the frame's checks and returns its data charge: only segments
/// 0..2 hold the pool, the frame is delivered with `data_refused` set and the stream continues with the next frame
/// (spec 8.2, client-ops 5.4.1). Both CRC and secure mode.
#[test]
fn a_refused_data_segment_is_consumed_and_the_stream_continues() {
    for (rev, secure) in [
        (Revision::V21, false),
        (Revision::V20, false),
        (Revision::V21, true),
        (Revision::V20, true),
    ] {
        const MB: usize = 1 << 20;
        let credits = IngressCredits::with_frames(&[(1, 8 * MB as u64)], 8);
        let (mut e, mut d, w) = message(rev, secure, 1, 2 * MB);
        d.set_gate(Some(credits.frame_gate(0)));
        d.set_data_probe(Some(probe(MB as u64, true)));
        let next = encode_message(&mut e, 2, 4096);
        d.feed(&w);
        let f = d.poll_owned().unwrap().expect("the frame is processed");
        assert_eq!(f.data_refused, 2 * MB as u32, "{rev:?} secure={secure}");
        assert_eq!(f.segs.len(), 4, "{rev:?} secure={secure}");
        assert!(f.segs[3].is_empty(), "{rev:?} secure={secure}");
        assert_eq!(*f.segs[1], [1; 40][..]);
        assert!(f.data_crc.is_none());
        // the refused data charge was returned; only the front stays charged
        assert!(
            credits.pool_stats()[0].used < MB as u64,
            "{rev:?} secure={secure}: {} bytes charged",
            credits.pool_stats()[0].used
        );
        drop(f);
        assert!(credits.idle(), "{rev:?} secure={secure}");
        // the next frame of the same stream decodes normally
        d.feed(&next);
        let g = d
            .poll_owned()
            .unwrap()
            .expect("the next frame of the stream");
        assert_eq!(g.data_refused, 0, "{rev:?} secure={secure}");
        assert_eq!(g.segs[3].len(), 4096, "{rev:?} secure={secure}");
    }
}

/// The probe needs no ingress gate: an ungated decoder still refuses the data segment without buffering it.
#[test]
fn a_refused_data_segment_needs_no_gate() {
    const MB: usize = 1 << 20;
    let (_, mut d, w) = message(Revision::V21, false, 1, 2 * MB);
    d.set_data_probe(Some(probe(MB as u64, true)));
    d.feed(&w);
    let f = d.poll_owned().unwrap().expect("the frame is processed");
    assert_eq!(f.data_refused, 2 * MB as u32);
    assert!(f.segs[3].is_empty());
}

/// A refused data segment still passes its own check: a damaged CRC-mode data segment faults the frame like any other.
#[test]
fn a_damaged_refused_data_segment_still_faults() {
    const MB: usize = 1 << 20;
    let credits = IngressCredits::with_frames(&[(1, 8 * MB as u64)], 8);
    let (_, mut d, mut w) = message(Revision::V21, false, 1, 2 * MB);
    d.set_gate(Some(credits.frame_gate(0)));
    d.set_data_probe(Some(probe(MB as u64, true)));
    let at = w.len() - MB;
    w[at] ^= 0xFF;
    d.feed(&w);
    assert!(matches!(
        d.poll_owned(),
        Err(Error::BadSegmentCrc(3)) | Err(Error::Failed)
    ));
    // the faulted decoder keeps its reservation until the connection drops it (`cancel_gate`)
    d.cancel_gate();
    assert!(credits.idle());
}

/// A split frame reserves its whole declared size at the preamble.
#[test]
fn a_split_frames_data_segment_is_reserved_with_its_front() {
    const MB: usize = 1 << 20;
    let credits = IngressCredits::with_frames(&[(1, 8 * MB as u64)], 8);
    let (_, mut d, w) = message(Revision::V21, false, 1, 2 * MB);
    d.set_gate(Some(credits.frame_gate(0)));
    d.set_data_probe(Some(probe(MB as u64, false)));
    // Charge the data before the probe has seen the front, without allocating it.
    d.feed(&w[..64]);
    assert!(d.poll_owned().unwrap().is_none());
    let front = credits.pool_stats()[0].used;
    assert!(front >= w.len() as u64, "whole frame charged, {front}");
    d.feed(&w[64..]);
    let f = d.poll_owned().unwrap().expect("frame");
    assert_eq!(f.segs[3].len(), 2 * MB);
    let used = credits.pool_stats()[0].used;
    assert_eq!(used, front, "receiving data must not charge it twice");
    assert!(
        used >= w.len() as u64,
        "front and data segment are charged, {used} bytes"
    );
    assert!(
        used < 8 * MB as u64,
        "the pool holds only this frame, {used} bytes"
    );
    drop(f);
    assert_eq!(credits.pool_stats()[0].used, 0);
    assert!(credits.idle());
}

/// Peers may pause after a preamble. Their declared payloads must consume the
/// allowance now, rather than all joining an already overfull pool later.
#[test]
fn split_preambles_cannot_overbook_payload_memory() {
    const MB: usize = 1 << 20;
    for (rev, secure) in [
        (Revision::V21, false),
        (Revision::V20, false),
        (Revision::V21, true),
        (Revision::V20, true),
    ] {
        let credits = IngressCredits::with_frames(&[(1, 3 * MB as u64)], 8);
        // Streaming CRC must stop before the front completes and runs the probe.
        // Secure preambles need their authentication bytes before admission.
        let prefix = if secure { 4096 } else { 64 };
        let mut links = Vec::new();
        for seq in 1..=3 {
            let (_, mut d, w) = message(rev, secure, seq, 2 * MB);
            d.set_gate(Some(credits.frame_gate(0)));
            d.set_data_probe(Some(probe(MB as u64, false)));
            d.feed(&w[..prefix]);
            assert!(d.poll_owned().unwrap().is_none());
            links.push((d, w));
        }
        assert!(links[2].0.awaiting_credit(), "{rev:?} secure={secure}");
        let charged = credits.pool_stats()[0].used;
        assert!(charged >= 4 * MB as u64, "declared data charged: {charged}");
        // Complete the two admitted frames without waiting on another gate.
        for (d, w) in &mut links[..2] {
            d.feed(&w[prefix..]);
            let f = d.poll_owned().unwrap().expect("admitted frame completes");
            assert_eq!(f.segs[3].len(), 2 * MB);
            drop(f);
        }
        assert!(links[2].0.retry_gate());
        let (d, w) = &mut links[2];
        d.feed(&w[prefix..]);
        drop(d.poll_owned().unwrap().expect("waiting frame completes"));
        assert!(credits.idle());
    }
}

/// An alone frame is decided at its preamble from its whole declared size: its front waits for an empty pool, takes
/// the pool alone and keeps it exclusively through its data segment (spec msgr2.md 8.2, adr 0175 am. 3).
#[test]
fn an_alone_frame_is_decided_at_its_preamble() {
    const MB: usize = 1 << 20;
    let credits = IngressCredits::with_frames(&[(1, 2 * MB as u64)], 8);
    let gate = credits.frame_gate(0);
    let (_, mut d, w) = message(Revision::V21, false, 1, 4 * MB);
    d.set_gate(Some(gate.clone()));
    d.set_data_probe(Some(probe(MB as u64, false)));
    // another frame holds half the pool: the 4 MiB frame waits at its front, no byte of it is charged
    let hog = gate.admit(MB, false, &mut None).unwrap();
    d.feed(&w);
    assert!(d.poll_owned().unwrap().is_none());
    assert!(d.awaiting_credit(), "the front waits for the empty pool");
    assert_eq!(credits.pool_stats()[0].used, MB as u64, "front uncharged");
    assert!(!d.retry_gate(), "another frame still holds the pool");
    drop(hog);
    assert!(d.retry_gate(), "alone in the pool after the release");
    assert!(!d.awaiting_credit());
    let front = credits.pool_stats()[0].used;
    assert!(front >= w.len() as u64, "whole frame charged, {front}");
    assert!(!gate.ready(1, false, None), "it keeps the pool exclusively");
    let f = d.poll_owned().unwrap().expect("frame");
    assert_eq!(f.segs[3].len(), 4 * MB);
    let used = credits.pool_stats()[0].used;
    assert!(used >= w.len() as u64, "its data segment joined, {used}");
    let expected: Vec<u8> = (0..4 * MB).map(|i| (i as u8).wrapping_add(1)).collect();
    assert!(f.segs[3][..] == expected[..], "the payload is intact");
    drop(f);
    assert_eq!(credits.pool_stats()[0].used, 0);
    assert!(credits.idle());
}

/// Two links whose split frames are both above the pool: each waits at its own front and they complete in turn, so a
/// front never holds the pool while it waits for its data segment (spec msgr2.md 8.2, adr 0175 am. 3).
#[test]
fn two_split_frames_above_the_pool_complete_in_turn() {
    const MB: usize = 1 << 20;
    let credits = IngressCredits::with_frames(&[(1, 2 * MB as u64)], 8);
    let gate = credits.frame_gate(0);
    let probe = probe(MB as u64, false);
    let (_, mut a, wa) = message(Revision::V21, false, 1, 3 * MB);
    let (_, mut b, wb) = message(Revision::V21, false, 2, 3 * MB);
    for d in [&mut a, &mut b] {
        d.set_gate(Some(gate.clone()));
        d.set_data_probe(Some(probe));
    }
    // A's front is complete but for its last byte while B's whole frame arrives: both are above the pool, so only one
    // of them may hold it — B waits at its front instead of reserving one
    let h = MsgHeader2 {
        seq: 1,
        tid: 1,
        msg_type: 42,
        ..Default::default()
    }
    .to_bytes();
    let front_end = PREAMBLE_LEN + h.len() + 4 + 40;
    a.feed(&wa[..front_end - 1]);
    assert!(a.poll_owned().unwrap().is_none(), "A's front is not done");
    assert!(
        credits.pool_stats()[0].used >= wa.len() as u64,
        "A's declared payload is charged"
    );
    b.feed(&wb);
    assert!(b.awaiting_credit(), "B waits for the pool A holds");
    a.feed(&wa[front_end - 1..]);
    let fa = a.poll_owned().unwrap().expect("A completes");
    assert_eq!(fa.segs[3].len(), 3 * MB);
    assert!(b.awaiting_credit(), "B is still waiting");
    drop(fa);
    assert!(b.retry_gate(), "the pool is B's now");
    let fb = b.poll_owned().unwrap().expect("B completes in turn");
    assert_eq!(fb.segs[3].len(), 3 * MB);
    drop(fb);
    assert!(credits.idle());
}

/// A split frame A holds the pool while an oversized frame B waits for it; A's data segment joins A's reservation at
/// once (no second pool admission behind B's waiter place) and A completes, then B is admitted (spec msgr2.md 8.2,
/// adr 0175 am. 3).
#[test]
fn a_data_segment_does_not_queue_behind_a_waiting_frame() {
    const MB: usize = 1 << 20;
    let credits = IngressCredits::with_frames(&[(1, 2 * MB as u64)], 8);
    let gate = credits.frame_gate(0);
    let probe = probe(MB as u64, false);
    let (_, mut a, wa) = message(Revision::V21, false, 1, MB);
    let (_, mut b, wb) = message(Revision::V21, false, 2, 4 * MB);
    for d in [&mut a, &mut b] {
        d.set_gate(Some(gate.clone()));
        d.set_data_probe(Some(probe));
    }
    // A's front is admitted; B (whole frame above the pool) queues behind the pool
    a.feed(&wa[..64]);
    let front = credits.pool_stats()[0].used;
    assert!(
        front >= wa.len() as u64,
        "A's declared payload is charged, {front} bytes"
    );
    b.feed(&wb);
    assert!(b.awaiting_credit(), "B waits for the empty pool");
    assert_eq!(credits.pool_stats()[0].waiters, 1);
    // A's data joins at once and A completes, although B holds the oldest place
    a.feed(&wa[64..]);
    let fa = a.poll_owned().unwrap().expect("A completes");
    assert_eq!(fa.segs[3].len(), MB);
    let used = credits.pool_stats()[0].used;
    assert!(used >= wa.len() as u64, "A's data segment joined, {used}");
    assert!(b.awaiting_credit(), "B is still waiting");
    drop(fa);
    assert!(b.retry_gate(), "the pool is B's now");
    let fb = b.poll_owned().unwrap().expect("B completes");
    assert_eq!(fb.segs[3].len(), 4 * MB);
    drop(fb);
    assert!(credits.idle());
}

/// A refused data segment is visible to borrowed delivery: `poll` reports the refusal on the frame instead of handing
/// out a silently empty data segment (spec msgr2.md 8.2).
#[test]
fn a_refused_data_segment_is_visible_to_borrowed_delivery() {
    const MB: usize = 1 << 20;
    let credits = IngressCredits::with_frames(&[(1, 8 * MB as u64)], 8);
    let (_, mut d, w) = message(Revision::V21, false, 1, 2 * MB);
    d.set_gate(Some(credits.frame_gate(0)));
    d.set_data_probe(Some(probe(MB as u64, true)));
    d.feed(&w);
    {
        let f = d.poll().unwrap().expect("the frame is delivered");
        assert_eq!(f.data_refused, 2 * MB as u32);
        assert_eq!(f.num_segments, 4);
        assert!(f.segment(3).is_empty());
        assert_eq!(f.segment(1), [1; 40]);
    }
    // the borrowed frame keeps the front charged until the decoder drops it; the refused data never was
    assert!(
        credits.pool_stats()[0].used < MB as u64,
        "the refused data segment is charged to nothing"
    );
    drop(d);
    assert!(credits.idle());
}

/// The secure (buffered) receive path reserves the whole frame at its header like the crc path, and the payload is
/// charged before it is decrypted into the receive buffer: the probe decides after authentication, its plaintext is
/// dropped then (spec msgr2.md 8.2).
#[test]
fn the_secure_path_reserves_the_whole_frame_with_its_data_segment() {
    const MB: usize = 1 << 20;
    let credits = IngressCredits::with_frames(&[(1, 6 * MB as u64)], 8);
    let (_, mut d, w) = message(Revision::V21, true, 1, 4 * MB);
    d.set_gate(Some(credits.frame_gate(0)));
    d.set_data_probe(Some(probe(MB as u64, false)));
    // header2 and the first GCM block only: the preamble decides and the whole frame is charged
    d.feed(&w[..96]);
    assert!(d.poll_owned().unwrap().is_none());
    assert!(!d.awaiting_credit(), "space is free: the frame is admitted");
    let used = credits.pool_stats()[0].used;
    assert!(
        used >= w.len() as u64,
        "the whole frame is charged at its header, {used} bytes"
    );
    d.feed(&w[96..]);
    let f = d.poll_owned().unwrap().expect("frame");
    assert_eq!(f.segs[3].len(), 4 * MB);
    drop(f);
    assert_eq!(credits.pool_stats()[0].used, 0);
    assert!(credits.idle());
}

/// A split frame above the pool is admitted alone at its preamble with its data segment in that one reservation, so
/// it completes instead of waiting for a pool that can never empty (spec msgr2.md 8.2, adr 0175 am. 3).
#[test]
fn a_split_frame_above_the_pool_completes_alone() {
    let credits = IngressCredits::with_frames(&[(1, 100)], 8);
    let (_, mut d, w) = message(Revision::V21, false, 1, 4096);
    d.set_gate(Some(credits.frame_gate(0)));
    d.set_data_probe(Some(probe(1024, false)));
    d.feed(&w);
    let f = d
        .poll_owned()
        .unwrap()
        .expect("the front and its data segment take the pool alone");
    assert_eq!(f.segs[3].len(), 4096);
    assert!(credits.pool_stats()[0].used >= w.len() as u64);
    drop(f);
    assert_eq!(credits.pool_stats()[0].used, 0);
    assert!(credits.idle());
}
