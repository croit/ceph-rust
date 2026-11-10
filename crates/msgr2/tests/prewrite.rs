// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `Decoder::set_prewrite` (adr 0477): a large data segment is readable while it arrives (early headers, views of the
//! received prefix), the frame itself is decoded exactly as without it, and the segment's fate (`SegWatch::gone`) is
//! exact: a frame with a bad data crc or one cut off by a reset never completes and its segment is gone at once; a
//! delivered frame's segment is gone only when its last `Bytes` is dropped.
use msgr2::*;

const TY: u16 = 112;
const HEAD: usize = 14;
const MIN: usize = 256 << 10;

fn mk(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
        .collect()
}

fn wire(ty: u16, data: usize) -> (Vec<u8>, [Vec<u8>; 4]) {
    let h = MsgHeader2 {
        seq: 1,
        tid: 9,
        msg_type: ty,
        // the payload at segment byte HEAD (a replica's v9 blob)
        data_off: 0u16.wrapping_sub(HEAD as u16),
        ..Default::default()
    }
    .to_bytes()
    .to_vec();
    let segs = [h, mk(60, 3), Vec::new(), mk(data, 5)];
    let mut e = Encoder::new(Revision::V21);
    let mut out = Vec::new();
    e.encode_message(&segs[0], &segs[1], &segs[2], &segs[3], &mut out)
        .unwrap();
    (out, segs)
}

fn decoder(head: bool) -> Decoder {
    let mut d = Decoder::new(Revision::V21);
    if head {
        d.set_rx_place(true);
    }
    d.set_prewrite(MIN);
    d
}

/// Start of the data segment on the wire (preamble 32 + header2 + its crc 4 + front, no middle).
fn data_at(segs: &[Vec<u8>; 4]) -> usize {
    32 + segs[0].len() + 4 + segs[1].len()
}

#[test]
fn feed_path_exposes_headers_and_the_received_prefix() {
    for head in [false, true] {
        let (w, segs) = wire(TY, 1 << 20);
        let mut d = decoder(head);
        let at = data_at(&segs);
        d.feed(&w[..at]);
        assert!(d.early().is_none(), "no data byte yet: nothing shared");
        let mut seen = None;
        let mut pos = at;
        for c in w[at..].chunks(100_000) {
            d.feed(c);
            pos += c.len();
            if let Some(e) = d.early() {
                assert_eq!(e.header, &segs[0][..]);
                assert_eq!(e.front, &segs[1][..]);
                assert_eq!(e.len, segs[3].len());
                assert_eq!(e.head, if head { HEAD } else { 0 });
                if head {
                    // the payload (segment byte HEAD) lands 4 KiB-aligned behind the pad
                    let p = e.data.view(e.pad + HEAD, 1).unwrap();
                    assert_eq!(p.as_ptr() as usize % 4096, 0);
                }
                let got = (pos - at).min(segs[3].len());
                assert_eq!(e.data.filled(), e.pad + got, "published = received");
                let v = e.data.view(e.pad, got).unwrap();
                assert_eq!(&v[..], &segs[3][..got], "the prefix as received");
                assert!(e.data.view(e.pad, got + 1).is_none());
                seen = Some((e.data.clone(), e.pad));
            }
        }
        let (watch, pad) = seen.expect("early while the data arrived");
        let early_view = watch.view(pad, 4096).unwrap();
        let f = d.poll_owned().unwrap().expect("frame");
        assert!(d.early().is_none(), "frame done");
        assert_eq!(&f.segs[3][..], &segs[3][..]);
        assert_eq!(f.data_crc, Some(crc::crc32c(!0, &segs[3])));
        assert_eq!(
            f.segs[3].as_ptr(),
            early_view.as_ptr(),
            "the frame's payload is the very memory the views saw"
        );
        assert!(!watch.gone(), "the frame is alive");
        let slice = f.segs[3].slice(4096..8192);
        drop(f);
        assert!(!watch.gone(), "a slice keeps it alive");
        drop(slice);
        assert!(watch.gone());
        assert_eq!(&early_view[..], &segs[3][..4096], "views outlive the frame");
    }
}

#[test]
fn direct_receive_publishes_each_piece() {
    let (w, segs) = wire(TY, 1 << 20);
    let mut d = decoder(true);
    let at = data_at(&segs);
    d.feed(&w[..at]);
    let want = d.direct_want();
    assert_eq!(want, segs[3].len());
    assert!(
        d.direct_take().is_none(),
        "the Vec loan is off with pre-write"
    );
    let (mut v, mut crc) = d.direct_take_seg().unwrap();
    assert!(v.is_shared());
    let e = d.early().expect("shared at the loan");
    let (watch, pad) = (e.data.clone(), e.pad);
    let mut pos = at;
    for _ in 0..4 {
        let n = 256 << 10;
        let l = v.len();
        let spare = &mut v.spare_capacity_mut()[..n];
        for (s, b) in spare.iter_mut().zip(&w[pos..pos + n]) {
            s.write(*b);
        }
        // SAFETY: the n bytes after l were written above.
        unsafe { v.set_len(l + n) };
        crc.update(&v[l..]);
        pos += n;
        let got = pos - at;
        assert_eq!(watch.filled(), pad + got);
        assert_eq!(
            &watch.view(pad + got - n, n).unwrap()[..],
            &segs[3][got - n..got]
        );
    }
    d.direct_put_seg(v, crc);
    d.feed(&w[pos..]);
    let f = d.poll_owned().unwrap().expect("frame");
    assert_eq!(&f.segs[3][..], &segs[3][..]);
    drop(f);
    assert!(watch.gone());
}

#[test]
fn bad_data_crc_never_delivers_and_the_segment_is_gone() {
    let (mut w, segs) = wire(TY, 1 << 20);
    // corrupt one payload byte: the epilogue's data crc no longer matches
    let at = data_at(&segs);
    w[at + 300_000] ^= 0x40;
    let mut d = decoder(false);
    let mut watch = None;
    for c in w.chunks(64 << 10) {
        d.feed(c);
        if let Some(e) = d.early() {
            watch = Some(e.data.clone());
        }
    }
    let watch = watch.unwrap();
    assert!(d.poll_owned().is_err(), "crc failure");
    drop(d);
    assert!(watch.gone(), "nothing will use the pre-written pieces");
}

#[test]
fn reset_mid_frame_marks_the_segment_gone() {
    let (w, segs) = wire(TY, 1 << 20);
    let mut d = decoder(false);
    let at = data_at(&segs);
    d.feed(&w[..at + 500_000]);
    let watch = d.early().unwrap().data.clone();
    let piece = watch.view(0, 256 << 10).unwrap();
    // the connection faults: the decoder is replaced (msgr2 reset_transport)
    drop(d);
    assert!(watch.gone());
    assert_eq!(
        &piece[..],
        &segs[3][..256 << 10],
        "a pre-write in flight still reads valid memory"
    );
}

#[test]
fn lent_buffer_dropped_by_a_dying_transport_marks_the_segment_gone() {
    let (w, segs) = wire(TY, 1 << 20);
    let mut d = decoder(false);
    d.feed(&w[..data_at(&segs)]);
    let (v, _crc) = d.direct_take_seg().unwrap();
    let watch = d.early().unwrap().data.clone();
    drop(v);
    assert!(watch.gone());
}

#[test]
fn small_or_off_frames_stay_plain() {
    for (len, min) in [(MIN - 4096, MIN), (1 << 20, 0)] {
        let (w, segs) = wire(TY, len);
        let mut d = Decoder::new(Revision::V21);
        d.set_prewrite(min);
        for c in w.chunks(50_000) {
            d.feed(c);
            assert!(d.early().is_none());
        }
        let f = d.poll_owned().unwrap().expect("frame");
        assert_eq!(&f.segs[3][..], &segs[3][..]);
    }
}

mod common;
use common::*;
use denc::types::EntityName;

/// A handshaken pair whose acceptor had pre-write set before the banner (the decoder is replaced there).
fn ready_pair() -> (Connection, Connection) {
    let mut a = Node::new(EntityName::OSD, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(EntityName::OSD, 2, 2, PolicyTable::osd_cluster());
    let mut rng = Rng(5);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    s.set_prewrite(MIN);
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 4096);
    assert_eq!(msgs(&events(&mut s)).len(), 1);
    events(&mut c);
    (c, s)
}

/// Drive `s` with `out` like knet: `on_bytes` until a direct receive is offered, then 256 KiB pieces into the lent
/// `SegBuf`. Returns the watch seen while the data arrived. `fault`: the connection faults after the second piece.
fn conn_run(s: &mut Connection, out: &[u8], fault: bool) -> SegWatch {
    let mut pos = 0;
    let mut watch = None;
    while pos < out.len() {
        let want = s.rx_direct_want();
        if want == 0 {
            let n = 1500.min(out.len() - pos);
            s.on_bytes(&out[pos..pos + n], t(5));
            pos += n;
            continue;
        }
        // the front (200 KB) is lent too, plain; the data segment comes shared
        let (mut v, mut crc) = s.rx_direct_take_seg().expect("want > 0");
        let early = s.rx_early().map(|e| e.data.clone());
        assert_eq!(early.is_some(), v.is_shared());
        let end = pos + want;
        let mut pieces = 0;
        while pos < end {
            let n = (256usize << 10).min(end - pos);
            v.extend_from_slice(&out[pos..pos + n]);
            crc.update(&out[pos..pos + n]);
            pos += n;
            pieces += 1;
            if let Some(w) = &early {
                assert_eq!(&w.view(0, v.len()).unwrap()[..], &v[..]);
                if fault && pieces == 2 {
                    s.on_closed(t(6));
                    assert!(s.rx_early().is_none());
                    s.rx_direct_put_seg(v, crc, t(7));
                    return early.unwrap();
                }
            }
        }
        s.rx_direct_put_seg(v, crc, t(6));
        watch = watch.or(early);
    }
    watch.expect("the data segment was shared")
}

#[test]
fn connection_delivers_the_exact_message_from_the_shared_segment() {
    let (mut c, mut s) = ready_pair();
    c.send_message(msg(2, 42, 200_000)); // front 200 KB, data 600 KB
    let out = c.poll_output();
    let watch = conn_run(&mut s, &out, false);
    let evs = events(&mut s);
    let m = msgs(&evs);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].header.tid, 2);
    assert!(m[0].data.iter().all(|&b| b == 7) && m[0].data.len() == 600_000);
    assert!(!watch.gone(), "the delivered message holds the segment");
    drop(evs);
    assert!(watch.gone());
}

#[test]
fn connection_fault_mid_frame_marks_the_segment_gone() {
    let (mut c, mut s) = ready_pair();
    c.send_message(msg(2, 42, 200_000));
    let out = c.poll_output();
    let watch = conn_run(&mut s, &out, true);
    assert!(msgs(&events(&mut s)).is_empty());
    assert!(
        watch.gone(),
        "faulted: the late buffer is dropped, nothing will claim its pieces"
    );
}

/// Pre-write is toggled at runtime on every link: a data segment that started shared (pre-write on) must not be lent
/// as a plain `Vec` after it was switched off (the loan is refused, the frame completes through the ordinary path).
#[test]
fn a_shared_segment_is_not_lent_as_a_vec_after_prewrite_is_switched_off() {
    let (w, segs) = wire(TY, 1 << 20);
    let mut d = decoder(false);
    let at = data_at(&segs);
    d.feed(&w[..at + 4096]);
    d.set_prewrite(0);
    assert!(d.direct_take().is_none());
    d.feed(&w[at + 4096..]);
    let f = d.poll_owned().unwrap().expect("frame");
    assert_eq!(f.segs[3].len(), 1 << 20);
}
