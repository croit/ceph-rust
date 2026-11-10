// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use msgr2::*;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> usize {
        (self.next() % n) as usize
    }
}

fn secret() -> ConnSecret {
    let s: Vec<u8> = (0..64u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    ConnSecret::new(&s).unwrap()
}

fn pair(rev: Revision, secure: bool) -> (Encoder, Decoder) {
    // client encoder -> server decoder
    let mut e = Encoder::new(rev);
    let mut d = Decoder::new(rev);
    if secure {
        e.set_secure(&secret(), Role::Client).unwrap();
        d.set_secure(&secret(), Role::Server).unwrap();
    }
    (e, d)
}

fn mk(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn encode_n(e: &mut Encoder, lens: [usize; 4]) -> Vec<u8> {
    let d: Vec<Vec<u8>> = (0..4).map(|i| mk(lens[i], i as u8 + 1)).collect();
    let mut out = Vec::new();
    e.encode_message(&d[0], &d[1], &d[2], &d[3], &mut out)
        .unwrap();
    out
}

#[test]
fn spec_wire_lengths() {
    let cases: [([usize; 4], usize, usize); 4] = [
        ([0, 0, 0, 0], 32, 96),
        ([20, 0, 0, 0], 56, 96),
        ([0, 70, 0, 0], 115, 0),
        ([20, 70, 0, 350], 489, 560),
    ];
    for (l, crc_len, sec_len) in cases {
        let mut e = Encoder::new(Revision::V21);
        assert_eq!(encode_n(&mut e, l).len(), crc_len, "{l:?}");
        if sec_len > 0 {
            let (mut e, _) = pair(Revision::V21, true);
            assert_eq!(encode_n(&mut e, l).len(), sec_len, "{l:?}");
        }
    }
    let (mut e, _) = pair(Revision::V21, true);
    assert_eq!(encode_n(&mut e, [105, 0, 0, 0]).len(), 176);
    // rev0: crc 32+sum+17; secure 32+sum(P)+32
    let mut e = Encoder::new(Revision::V20);
    assert_eq!(encode_n(&mut e, [20, 70, 0, 350]).len(), 32 + 440 + 17);
    let (mut e, _) = pair(Revision::V20, true);
    assert_eq!(
        encode_n(&mut e, [20, 70, 0, 350]).len(),
        32 + 32 + 80 + 352 + 32
    );
}

#[test]
fn crc_rev1_layout_bytes() {
    // 8-byte control payload: preamble + payload + crc, no epilogue.
    let mut e = Encoder::new(Revision::V21);
    let mut out = Vec::new();
    e.encode_control(
        18,
        &payload::Keepalive2 { sec: 1, nsec: 2 }.to_bytes().unwrap(),
        &mut out,
    )
    .unwrap();
    assert_eq!(out.len(), 32 + 8 + 4);
    assert_eq!(&out[..8], &[18, 1, 8, 0, 0, 0, 8, 0]);
    assert_eq!(&out[8..26], &[0u8; 18]);
    assert_eq!(&out[26..28], &[0, 0]);
    assert_eq!(&out[32..40], &[1, 0, 0, 0, 2, 0, 0, 0]);
    assert_eq!(rd(&out, 28), crc::crc32c(0, &out[..28]));
    assert_eq!(rd(&out, 40), crc::crc32c(!0, &out[32..40]));
    // multi-seg: slots, empty middle = 0xFFFFFFFF, beyond n = 0
    let mut out = Vec::new();
    e.encode_message(&[1; 41], &[], &[7, 7], &[], &mut out)
        .unwrap();
    let n = out.len();
    assert_eq!(out[1], 3);
    assert_eq!(out[n - 13], LATE_COMPLETE);
    assert_eq!(rd(&out, n - 12), 0xFFFF_FFFF);
    assert_eq!(rd(&out, n - 8), crc::crc32c(!0, &[7, 7]));
    assert_eq!(rd(&out, n - 4), 0);
    // alignment slots of dropped segments zero
    assert_eq!(&out[2 + 6 * 3 + 4..2 + 6 * 3 + 6], &[0, 0]);
}

fn rd(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn roundtrip(rev: Revision, secure: bool) {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let (mut e, mut d) = pair(rev, secure);
    let sizes = [0usize, 1, 15, 16, 17, 47, 48, 49, 63, 64, 100, 4096, 5000];
    let mut wire = Vec::new();
    let mut expect: Vec<[Vec<u8>; 4]> = Vec::new();
    for _ in 0..300 {
        let l = [0; 4].map(|_| sizes[rng.below(sizes.len() as u64)]);
        let l = if rng.below(3) == 0 {
            [l[0], 0, 0, 0]
        } else {
            l
        };
        let segs: [Vec<u8>; 4] = [0, 1, 2, 3].map(|i| mk(l[i], rng.below(255) as u8));
        e.encode_message(&segs[0], &segs[1], &segs[2], &segs[3], &mut wire)
            .unwrap();
        expect.push(segs);
    }
    if secure {
        // ciphertext must not contain the first plaintext segment verbatim
        let s0 = &expect[0][0];
        if s0.len() >= 32 {
            assert!(!wire.windows(32).any(|w| w == &s0[..32]));
        }
    }
    // random chunking
    let mut got = 0;
    let mut pos = 0;
    while pos < wire.len() {
        let k = (1 + rng.below(200)).min(wire.len() - pos);
        d.feed(&wire[pos..pos + k]);
        pos += k;
        while let Some(f) = d.poll().unwrap() {
            let ex = &expect[got];
            assert_eq!(f.tag, 17);
            let n = ex.iter().rposition(|s| !s.is_empty()).map_or(1, |i| i + 1);
            assert_eq!(f.num_segments, n);
            for (i, s) in ex.iter().enumerate() {
                assert_eq!(f.segment(i), &s[..], "frame {got} seg {i}");
            }
            got += 1;
        }
    }
    assert_eq!(got, expect.len());
    assert_eq!(d.buffered(), 0);
}

#[test]
fn roundtrip_all_modes() {
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            roundtrip(rev, secure);
        }
    }
}

#[test]
fn byte_by_byte_and_recv_buf() {
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            let (mut e, mut d) = pair(rev, secure);
            let w = encode_n(&mut e, [41, 100, 0, 300]);
            let mut got = 0;
            for &b in &w {
                let buf = d.recv_buf(1);
                buf[0] = b;
                d.commit(1);
                if let Some(f) = d.poll().unwrap() {
                    assert_eq!(f.segment(3), &mk(300, 4)[..]);
                    got += 1;
                }
            }
            assert_eq!(got, 1);
        }
    }
}

#[test]
fn abort_skipped() {
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            let (mut e, mut d) = pair(rev, secure);
            let mut w = Vec::new();
            let s = |x: &'static [u8]| Seg { data: x, align: 8 };
            e.encode_ex(17, 0, true, &[s(b"aaaa"), s(b"bbbb")], &mut w)
                .unwrap();
            e.encode(17, &[s(b"cccc"), s(b"dddd")], &mut w).unwrap();
            d.feed(&w);
            let f = d.poll().unwrap().unwrap();
            assert_eq!(f.segment(0), b"cccc");
            assert!(d.poll().unwrap().is_none());
            assert_eq!(d.aborted_frames(), 1);
        }
    }
    let mut e = Encoder::new(Revision::V21);
    let mut w = Vec::new();
    assert_eq!(
        e.encode_ex(
            1,
            0,
            true,
            &[Seg {
                data: b"x",
                align: 8
            }],
            &mut w
        ),
        Err(Error::CannotAbort)
    );
    assert!(w.is_empty());
}

#[test]
fn mode_switch_mid_stream() {
    for rev in [Revision::V20, Revision::V21] {
        let mut e = Encoder::new(rev);
        let mut d = Decoder::new(rev);
        let mut w = Vec::new();
        e.encode_control(6, b"auth-done", &mut w).unwrap();
        e.set_secure(&secret(), Role::Server).unwrap();
        e.encode_control(7, b"signature", &mut w).unwrap();
        d.feed(&w); // both frames already buffered
        assert_eq!(d.poll().unwrap().unwrap().segment(0), b"auth-done");
        d.set_secure(&secret(), Role::Client).unwrap();
        assert_eq!(d.poll().unwrap().unwrap().segment(0), b"signature");
    }
}

#[test]
fn control_frame_in_place_secure_inline() {
    // seg0 <= 48 bytes: fully inside inline buffer; > 48: split with moved inline
    for len in [0usize, 5, 48, 49, 200] {
        let (mut e, mut d) = pair(Revision::V21, true);
        let p = mk(len, 9);
        let mut w = Vec::new();
        e.encode_control(8, &p, &mut w).unwrap();
        d.feed(&w);
        let f = d.poll().unwrap().unwrap();
        assert_eq!(f.segment(0), &p[..]);
        assert_eq!(f.align[0], 8);
    }
}

#[test]
fn nonce_direction() {
    // server->client uses N_a; a client decoder must not decode client-tx frames.
    let (mut e, _) = pair(Revision::V21, true);
    let mut d = Decoder::new(Revision::V21);
    d.set_secure(&secret(), Role::Client).unwrap();
    let mut w = Vec::new();
    e.encode_control(1, b"x", &mut w).unwrap();
    d.feed(&w);
    assert_eq!(d.poll().unwrap_err(), Error::AuthFailed);
    assert_eq!(d.poll().unwrap_err(), Error::Failed);
}

#[test]
fn errors() {
    let l = Limits::default();
    let _ = l;
    for rev in [Revision::V20, Revision::V21] {
        let mut e = Encoder::new(rev);
        let w = encode_n(&mut e, [41, 10, 0, 20]);
        // flip every single byte: must error (or, for ignored bytes, still not panic)
        let mut errs = 0;
        for i in 0..w.len() {
            let mut x = w.clone();
            x[i] ^= 0x40;
            let mut d = Decoder::new(rev);
            d.feed(&x);
            if d.poll().is_err() {
                errs += 1;
            }
        }
        // only reserved/ignored bytes (flags unknown bits, reserved, high late nibble..) may pass
        assert!(errs >= w.len() - 6, "{rev:?}: {errs}/{}", w.len());
    }
    // empty last segment, bad count
    let mut d = Decoder::new(Revision::V21);
    let mut p = vec![17u8, 2];
    p.extend_from_slice(&[0u8; 24]);
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&crc::crc32c(0, &p).to_le_bytes());
    d.feed(&p);
    assert_eq!(d.poll().unwrap_err(), Error::EmptyLastSegment);
    let mut d = Decoder::new(Revision::V21);
    let mut p = vec![17u8, 5];
    p.extend_from_slice(&[0u8; 24]);
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&crc::crc32c(0, &p).to_le_bytes());
    d.feed(&p);
    assert_eq!(d.poll().unwrap_err(), Error::BadSegmentCount(5));
    // limits
    let mut e = Encoder::new(Revision::V21);
    e.set_limits(Limits {
        max_segment: 10,
        max_frame: 100,
        ..Limits::default()
    });
    let mut out = vec![1u8];
    assert_eq!(
        e.encode_control(1, &[0; 11], &mut out),
        Err(Error::SegmentTooLarge(11))
    );
    assert_eq!(out, vec![1]);
    let mut e2 = Encoder::new(Revision::V21);
    let w = encode_n(&mut e2, [100, 100, 0, 100]);
    let mut d = Decoder::new(Revision::V21);
    d.set_limits(Limits {
        max_segment: 150,
        max_frame: 250,
        ..Limits::default()
    });
    d.feed(&w);
    assert_eq!(d.poll().unwrap_err(), Error::FrameTooLarge(300));
    let mut d = Decoder::new(Revision::V21);
    d.set_limits(Limits {
        max_segment: 50,
        max_frame: 250,
        ..Limits::default()
    });
    d.feed(&w);
    assert_eq!(d.poll().unwrap_err(), Error::SegmentTooLarge(100));
    // late status
    let mut e = Encoder::new(Revision::V21);
    let mut w = encode_n(&mut e, [41, 10, 0, 0]);
    let n = w.len();
    w[n - 13] = 0x05;
    let mut d = Decoder::new(Revision::V21);
    d.feed(&w);
    assert_eq!(d.poll().unwrap_err(), Error::BadLateStatus(5));
    // secret too short
    assert!(ConnSecret::new(&[0; 39]).is_err());
}

#[test]
fn garbage_never_panics() {
    let mut rng = Rng(42);
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            for _ in 0..300 {
                let (_, mut d) = pair(rev, secure);
                let len = rng.below(400);
                let g: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                d.feed(&g);
                let _ = d.poll();
            }
        }
    }
    // valid preamble with huge lengths in crc mode: error, no allocation
    let mut d = Decoder::new(Revision::V21);
    let mut p = vec![17u8, 4];
    for _ in 0..4 {
        p.extend_from_slice(&u32::MAX.to_le_bytes());
        p.extend_from_slice(&[0, 0]);
    }
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&crc::crc32c(0, &p).to_le_bytes());
    d.feed(&p);
    assert!(matches!(d.poll(), Err(Error::SegmentTooLarge(_))));
}

#[test]
fn peek_seg0_early() {
    let mut e = Encoder::new(Revision::V21);
    let w = encode_n(&mut e, [41, 100, 0, 300]);
    let mut d = Decoder::new(Revision::V21);
    d.feed(&w[..32]);
    assert!(d.poll().unwrap().is_none());
    assert!(d.peek_seg0().unwrap().is_none());
    d.feed(&w[32..32 + 41 + 4]);
    assert!(d.poll().unwrap().is_none());
    assert_eq!(d.peek_seg0().unwrap().unwrap(), &mk(41, 1)[..]);
    d.feed(&w[32 + 45..]);
    assert!(d.poll().unwrap().is_some());
}

#[test]
fn ctl_frames_roundtrip_via_codec() {
    for rev in [Revision::V20, Revision::V21] {
        let (mut e, mut d) = pair(rev, false);
        let mut w = Vec::new();
        e.encode_control(
            Tag::Keepalive2 as u8,
            &payload::Keepalive2 {
                sec: 100,
                nsec: 200,
            }
            .to_bytes()
            .unwrap(),
            &mut w,
        )
        .unwrap();
        e.encode_control(
            Tag::Ack as u8,
            &payload::Ack { seq: 77 }.to_bytes().unwrap(),
            &mut w,
        )
        .unwrap();
        d.feed(&w);
        let f = d.poll().unwrap().unwrap();
        assert_eq!(Tag::from_u8(f.tag), Some(Tag::Keepalive2));
        assert_eq!(
            payload::Keepalive2::from_bytes(f.segment(0)),
            Ok(payload::Keepalive2 {
                sec: 100,
                nsec: 200
            })
        );
        let f = d.poll().unwrap().unwrap();
        assert_eq!(
            payload::Ack::from_bytes(f.segment(0)),
            Ok(payload::Ack { seq: 77 })
        );
    }
}

#[test]
fn direct_path_owned_frames_large_chunks_and_corruption() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let mut e = Encoder::new(Revision::V21);
    let lens = [
        [53, 100, 0, 1 << 20],
        [53, 0, 0, 70_000],
        [10, 0, 0, 0],
        [0, 0, 0, 0],
        [53, 7, 9, 3],
    ];
    let mut wire = Vec::new();
    let mut expect = Vec::new();
    for l in lens {
        let segs: [Vec<u8>; 4] = [0, 1, 2, 3].map(|i| mk(l[i], i as u8 + 9));
        e.encode_message(&segs[0], &segs[1], &segs[2], &segs[3], &mut wire)
            .unwrap();
        expect.push(segs);
    }
    for chunk in [1usize << 20, 8948, 1448, 65_536, 37] {
        let mut d = Decoder::new(Revision::V21);
        let mut got = 0;
        let mut pos = 0;
        while pos < wire.len() {
            let k = chunk.min(wire.len() - pos);
            d.feed(&wire[pos..pos + k]);
            pos += k;
            while let Some(f) = d.poll_owned().unwrap() {
                let n = expect[got]
                    .iter()
                    .rposition(|s| !s.is_empty())
                    .map_or(1, |i| i + 1);
                assert_eq!(f.segs.len(), n);
                for (i, s) in f.segs.iter().enumerate() {
                    assert_eq!(s, &expect[got][i], "chunk {chunk} frame {got} seg {i}");
                }
                got += 1;
            }
        }
        assert_eq!((got, d.buffered()), (expect.len(), 0), "chunk {chunk}");
    }
    // a flipped byte in every region is caught (segment data, inline crc, epilogue crc)
    let first = {
        let mut e = Encoder::new(Revision::V21);
        let mut w = Vec::new();
        e.encode_message(&mk(53, 1), &mk(100, 2), &[], &mk(5000, 3), &mut w)
            .unwrap();
        w
    };
    for _ in 0..200 {
        let mut w = first.clone();
        let at = 32 + rng.below(w.len() as u64 - 32);
        w[at] ^= 1 << rng.below(8);
        let mut d = Decoder::new(Revision::V21);
        for c in w.chunks(1 + rng.below(3000)) {
            d.feed(c);
        }
        let mut r = d.poll_owned();
        // flipping the late-status byte may turn the frame into an aborted one (skipped), never into a bad frame
        if let Ok(Some(f)) = &r {
            panic!("corrupt frame accepted at {at}: {:?}", f.segs.len());
        }
        if r.is_ok() {
            assert_eq!(d.aborted_frames(), 1);
            r = Ok(None);
        }
        let _ = r;
    }
    // aborted frames are skipped, the next one is delivered
    let mut w = Vec::new();
    let mut e = Encoder::new(Revision::V21);
    let segs = [mk(53, 1), mk(10, 2), mk(0, 0), mk(30, 3)];
    let sg: Vec<Seg> = segs.iter().map(|s| Seg { data: s, align: 8 }).collect();
    e.encode_ex(17, 0, true, &sg, &mut w).unwrap();
    e.encode_ex(17, 0, false, &sg, &mut w).unwrap();
    let mut d = Decoder::new(Revision::V21);
    d.feed(&w);
    let f = d.poll_owned().unwrap().unwrap();
    assert_eq!((f.segs[3].len(), d.aborted_frames()), (30, 1));
    assert!(d.poll_owned().unwrap().is_none());
}

#[test]
fn zero_copy_encode_is_byte_identical() {
    for n in [0usize, 100, 8191, 8192, 100_000] {
        let data: bytes::Bytes = (0..n).map(|i| (i * 7) as u8).collect::<Vec<u8>>().into();
        let (h, f, m) = ([1u8; 53], [2u8; 40], [3u8; 5]);
        let mut e1 = Encoder::new(Revision::V21);
        let mut plain = Vec::new();
        e1.encode_message(&h, &f, &m, &data, &mut plain).unwrap();
        let mut e2 = Encoder::new(Revision::V21);
        let (mut out, mut chunks) = (Vec::new(), Vec::new());
        e2.encode_message_zc(
            &h,
            &f,
            &m,
            &data,
            &Default::default(),
            &mut out,
            &mut chunks,
        )
        .unwrap();
        let mut flat: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        flat.extend_from_slice(&out);
        assert_eq!(flat, plain, "n={n}");
        // a correct data-crc hint yields the identical frame
        let mut e3 = Encoder::new(Revision::V21);
        let (mut out3, mut chunks3) = (Vec::new(), Vec::new());
        let hint = crc::CrcHint::new(&data, crc::crc32c(!0, &data));
        e3.encode_message_zc(&h, &f, &m, &data, &hint, &mut out3, &mut chunks3)
            .unwrap();
        let mut flat3: Vec<u8> = chunks3.iter().flat_map(|c| c.iter().copied()).collect();
        flat3.extend_from_slice(&out3);
        assert_eq!(flat3, plain, "hinted n={n}");
        // a hint made for other bytes (same length, even same content in another allocation) is ignored: the
        // frame crc is computed from the segment, never taken from a foreign hint
        for other in [
            bytes::Bytes::copy_from_slice(&data),
            data.iter().map(|b| b ^ 0x5A).collect::<Vec<u8>>().into(),
        ] {
            let foreign = crc::CrcHint::new(&other, crc::crc32c(!0, &other));
            let mut e4 = Encoder::new(Revision::V21);
            let (mut out4, mut chunks4) = (Vec::new(), Vec::new());
            e4.encode_message_zc(&h, &f, &m, &data, &foreign, &mut out4, &mut chunks4)
                .unwrap();
            let mut flat4: Vec<u8> = chunks4.iter().flat_map(|c| c.iter().copied()).collect();
            flat4.extend_from_slice(&out4);
            assert_eq!(flat4, plain, "foreign hint n={n}");
        }
        assert_eq!(chunks.is_empty(), n < msgr2::ZC_MIN, "n={n}");
        if n >= msgr2::ZC_MIN {
            assert_eq!(chunks[1].as_ptr(), data.as_ptr(), "data not copied");
        }
        let mut d = Decoder::new(Revision::V21);
        d.feed(&flat);
        let fr = d.poll_owned().unwrap().unwrap();
        assert_eq!(fr.segs.get(3).map_or(0, |s| s.len()), n);
    }
}

/// Front runs spliced by reference (`encode_message_rope`): the wire bytes equal the plain frame of the flattened
/// front, in every mode (crc 2.1 by reference; 2.0 / secure flattened), and decode back to the same segments.
#[test]
fn rope_front_encode_is_byte_identical() {
    let big = |n: usize, s: u8| -> bytes::Bytes { mk(n, s).into() };
    let h = [1u8; 53];
    type Case = (Vec<u8>, Vec<(usize, bytes::Bytes)>, Vec<u8>, bytes::Bytes);
    let cases: Vec<Case> = vec![
        // one big run inside the front, no data
        (
            mk(300, 1),
            vec![(120, big(100_000, 2))],
            vec![],
            bytes::Bytes::new(),
        ),
        // two runs (one below ZC_MIN: copied), middle + big data
        (
            mk(64, 3),
            vec![(0, big(8192, 4)), (10, big(100, 5)), (64, big(20_000, 6))],
            mk(9, 7),
            big(50_000, 8),
        ),
        // only small runs: plain encode
        (mk(10, 9), vec![(5, big(10, 1))], vec![], big(10, 2)),
        // empty inline front, run only; empty middle, big data
        (vec![], vec![(0, big(9000, 3))], vec![], big(9000, 4)),
    ];
    for (rev, secure) in [
        (Revision::V21, false),
        (Revision::V20, false),
        (Revision::V21, true),
        (Revision::V20, true),
    ] {
        for (i, (front, zc, middle, data)) in cases.iter().enumerate() {
            let flat_front = flatten(front, zc).unwrap();
            let (mut e1, _) = pair(rev, secure);
            let mut plain = Vec::new();
            e1.encode_message(&h, &flat_front, middle, data, &mut plain)
                .unwrap();
            let (mut e2, mut d) = pair(rev, secure);
            let (mut out, mut chunks) = (Vec::new(), Vec::new());
            e2.encode_message_rope(
                &h,
                front,
                zc,
                &Default::default(),
                middle,
                data,
                &Default::default(),
                &mut out,
                &mut chunks,
            )
            .unwrap();
            let mut wire: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
            wire.extend_from_slice(&out);
            assert_eq!(wire, plain, "case {i} {rev:?} secure {secure}");
            let by_ref = chunks
                .iter()
                .filter(|c| zc.iter().any(|(_, r)| r.as_ptr() == c.as_ptr()))
                .count();
            let want = if rev == Revision::V21 && !secure {
                zc.iter().filter(|(_, r)| r.len() >= ZC_MIN).count()
            } else {
                0
            };
            assert_eq!(by_ref, want, "case {i} {rev:?} secure {secure}");
            d.feed(&wire);
            let f = d.poll_owned().unwrap().unwrap();
            assert_eq!(&f.segs[1][..], &flat_front[..], "case {i}");
            assert_eq!(f.segs.get(3).map_or(0, |s| s.len()), data.len());
            // the same frame with a crc hint per run (joined, the run bytes not read): byte-identical wire. A hint for
            // other bytes (a copy of the run) is ignored
            let mut hints: Vec<CrcHint> = zc
                .iter()
                .map(|(_, r)| CrcHint::new(r, crc::crc32c(!0, r)))
                .collect();
            hints.push(CrcHint::new(
                &bytes::Bytes::copy_from_slice(&zc[0].1),
                crc::crc32c(!0, &zc[0].1),
            ));
            let (mut e3, _) = pair(rev, secure);
            let (mut out3, mut chunks3) = (Vec::new(), Vec::new());
            e3.encode_message_rope(
                &h,
                front,
                zc,
                &hints.into(),
                middle,
                data,
                &Default::default(),
                &mut out3,
                &mut chunks3,
            )
            .unwrap();
            let mut wire3: Vec<u8> = chunks3.iter().flat_map(|c| c.iter().copied()).collect();
            wire3.extend_from_slice(&out3);
            assert_eq!(wire3, plain, "hinted case {i} {rev:?} secure {secure}");
        }
    }
}

/// Hinted front runs: odd lengths, run boundaries off any 4K grid, runs below ZC_MIN, several runs back to back
/// (empty inline gaps): the joined crc equals the full pass, so the wire frame equals the flattened plain frame.
#[test]
fn rope_front_hints_join_to_the_full_pass() {
    let h = [1u8; 53];
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let mut rnd = |n: usize| -> bytes::Bytes {
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 32) as u8
            })
            .collect::<Vec<u8>>()
            .into()
    };
    let shapes: [&[usize]; 6] = [
        &[ZC_MIN],
        &[ZC_MIN + 1, 4097],
        &[100_001, ZC_MIN, 12_345, 7],
        &[5, 70_000, 0, 65_537],
        &[4095, 4096, 4097],
        &[300_000],
    ];
    for runs in shapes {
        let zc: Vec<(usize, bytes::Bytes)> = {
            let mut at = 0;
            runs.iter()
                .filter(|n| **n > 0)
                .map(|&n| {
                    at += 3;
                    (at, rnd(n))
                })
                .collect()
        };
        let front = rnd(3 * zc.len() + 11).to_vec();
        let flat = flatten(&front, &zc).unwrap();
        let (mut e1, _) = pair(Revision::V21, false);
        let mut plain = Vec::new();
        e1.encode_message(&h, &flat, &[], &bytes::Bytes::new(), &mut plain)
            .unwrap();
        let hints: Vec<CrcHint> = zc
            .iter()
            .map(|(_, r)| CrcHint::new(r, crc::crc32c(!0, r)))
            .collect();
        let (mut e2, _) = pair(Revision::V21, false);
        let (mut out, mut chunks) = (Vec::new(), Vec::new());
        e2.encode_message_rope(
            &h,
            &front,
            &zc,
            &hints.into(),
            &[],
            &bytes::Bytes::new(),
            &Default::default(),
            &mut out,
            &mut chunks,
        )
        .unwrap();
        let mut wire: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        wire.extend_from_slice(&out);
        assert_eq!(wire, plain, "runs {runs:?}");
    }
}

#[test]
fn parts_encode_is_byte_identical_to_the_flat_segment() {
    let mk = |n: usize, s: u8| -> bytes::Bytes {
        (0..n)
            .map(|i| (i * 7) as u8 ^ s)
            .collect::<Vec<u8>>()
            .into()
    };
    let (h, f) = ([1u8; 53], [2u8; 40]);
    // (head, parts) shapes: tiny head + payload + tail, empty head, empty parts, small total (copy path), many parts
    let shapes: [(usize, &[usize]); 6] = [
        (10, &[100_000, 37]),
        (0, &[9000]),
        (6, &[0, 70_000, 0, 5]),
        (3, &[4, 5]),
        (8192, &[]),
        (1, &[4096, 1, 65_536, 2, 3]),
    ];
    for middle in [&[][..], &[3u8; 5][..]] {
        for (hn, parts) in shapes {
            let head = mk(hn, 1);
            let more: Vec<(bytes::Bytes, crc::CrcHint)> = parts
                .iter()
                .enumerate()
                .map(|(i, &n)| (mk(n, i as u8 + 2), Default::default()))
                .collect();
            let flat_data = msgr2::flatten_data(&head, &more);
            let mut e1 = Encoder::new(Revision::V21);
            let mut plain = Vec::new();
            e1.encode_message(&h, &f, middle, &flat_data, &mut plain)
                .unwrap();
            // no hints, correct hints on every part, a foreign hint (ignored)
            for mode in 0..3 {
                let hinted: Vec<(bytes::Bytes, crc::CrcHint)> = more
                    .iter()
                    .map(|(b, _)| {
                        let h = match mode {
                            1 => crc::CrcHint::new(b, crc::crc32c(!0, b)),
                            2 => {
                                let o = bytes::Bytes::copy_from_slice(b);
                                crc::CrcHint::new(&o, crc::crc32c(!0, &o))
                            }
                            _ => Default::default(),
                        };
                        (b.clone(), h)
                    })
                    .collect();
                let hh = if mode == 1 {
                    crc::CrcHint::new(&head, crc::crc32c(!0, &head))
                } else {
                    Default::default()
                };
                let mut e2 = Encoder::new(Revision::V21);
                let (mut out, mut chunks) = (Vec::new(), Vec::new());
                e2.encode_message_parts(&h, &f, middle, &head, &hh, &hinted, &mut out, &mut chunks)
                    .unwrap();
                let mut flat: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
                flat.extend_from_slice(&out);
                assert_eq!(flat, plain, "head {hn} parts {parts:?} mode {mode}");
                // big parts go out by reference
                for (b, _) in &more {
                    if flat_data.len() >= msgr2::ZC_MIN && !b.is_empty() {
                        assert!(
                            chunks.iter().any(|c| c.as_ptr() == b.as_ptr()),
                            "part copied"
                        );
                    }
                }
                let mut d = Decoder::new(Revision::V21);
                d.feed(&flat);
                let fr = d.poll_owned().unwrap().unwrap();
                assert_eq!(fr.segs.get(3).map_or(&[][..], |s| &s[..]), &flat_data[..]);
            }
        }
    }
}

/// Without by-reference frames (secure mode, rev 2.0) the parts are copied into the frame piece by piece (no flattened
/// blob first): the frame is byte-identical to the one of the flattened segment and decodes to it.
#[test]
fn parts_encode_without_zero_copy_matches_the_flat_segment() {
    let (h, f) = ([1u8; 53], [2u8; 40]);
    let shapes: [&[usize]; 4] = [
        &[100_000, 37],
        &[0, 70_000, 0, 5],
        &[4, 5],
        &[1, 4096, 65_536, 2],
    ];
    for (rev, secure) in [
        (Revision::V21, true),
        (Revision::V20, true),
        (Revision::V20, false),
    ] {
        for middle in [&[][..], &[3u8; 5][..]] {
            for (i, parts) in shapes.iter().enumerate() {
                let head: bytes::Bytes = mk(11, 1).into();
                let more: Vec<(bytes::Bytes, crc::CrcHint)> = parts
                    .iter()
                    .enumerate()
                    .map(|(j, &n)| (mk(n, j as u8 + 2).into(), Default::default()))
                    .collect();
                let flat_data = msgr2::flatten_data(&head, &more);
                let (mut e1, _) = pair(rev, secure);
                let mut plain = Vec::new();
                e1.encode_message(&h, &f, middle, &flat_data, &mut plain)
                    .unwrap();
                let (mut e2, mut d) = pair(rev, secure);
                let (mut out, mut chunks) = (Vec::new(), Vec::new());
                e2.encode_message_parts(
                    &h,
                    &f,
                    middle,
                    &head,
                    &Default::default(),
                    &more,
                    &mut out,
                    &mut chunks,
                )
                .unwrap();
                assert!(chunks.is_empty(), "no by-reference chunks");
                assert_eq!(out, plain, "case {i} {rev:?} secure {secure}");
                d.feed(&out);
                let fr = d.poll_owned().unwrap().unwrap();
                assert_eq!(&fr.segs[3][..], &flat_data[..], "case {i}");
            }
        }
    }
}

#[test]
fn owned_frame_reports_the_verified_data_crc() {
    let data: bytes::Bytes = (0..100_000usize)
        .map(|i| (i * 13) as u8)
        .collect::<Vec<u8>>()
        .into();
    let mut e = Encoder::new(Revision::V21);
    let mut w = Vec::new();
    e.encode_message(&[1u8; 53], &[2u8; 40], &[], &data, &mut w)
        .unwrap();
    let mut d = Decoder::new(Revision::V21);
    // fed in pieces: the crc runs over every piece as it is assembled
    for c in w.chunks(1448) {
        d.feed(c);
    }
    let f = d.poll_owned().unwrap().unwrap();
    assert_eq!(f.data_crc, Some(crc::crc32c(!0, &data)));
    assert_eq!(&f.segs[3][..], &data[..]);
}

/// Front-rope offsets are public producer state: a broken rope is an encoder error (`BadFrontRope`), never an
/// out-of-bounds slice in `flatten` or in the by-reference CRC pass (review MSG-07 sibling in this crate).
#[test]
fn broken_front_rope_is_an_error_not_a_panic() {
    use msgr2::Error;
    let run = || bytes::Bytes::from_static(b"x");
    for (front, zc) in [
        (vec![1u8], vec![(5usize, run())]),
        (vec![1u8, 2], vec![(2, run()), (1, run())]),
    ] {
        assert!(matches!(
            msgr2::flatten(&front, &zc),
            Err(Error::BadFrontRope)
        ));
        let mut e = Encoder::new(Revision::V21);
        let (mut out, mut chunks) = (Vec::new(), Vec::new());
        let r = e.encode_message_rope(
            &[1u8; 53],
            &front,
            &zc,
            &crc::CrcHints::default(),
            &[],
            &bytes::Bytes::new(),
            &Default::default(),
            &mut out,
            &mut chunks,
        );
        assert!(matches!(r, Err(Error::BadFrontRope)));
    }
}
