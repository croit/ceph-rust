// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `Decoder::set_rx_place`: the data segment of a MESSAGE frame is received so that its byte 0 lies at in-page offset
//! `data_off mod 4096` (the sender states where its payload lies: `data_off = -HEAD` puts byte `HEAD` on a 4 KiB
//! boundary), for every size, in CRC mode (feed and direct receive), secure mode (out-of-place decrypt) and rev 2.0;
//! block crcs lie on the 4 KiB grid of memory; the segment bytes, the segment crc and everything else are exactly what
//! a plain decode gives.
use msgr2::*;

const TY: u16 = 112;
const HEAD: usize = 14;
/// `data_off` that puts segment byte `HEAD` on a page boundary.
const OFF: u16 = 0u16.wrapping_sub(HEAD as u16);

fn mk(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn header(ty: u16, data_off: u16) -> Vec<u8> {
    MsgHeader2 {
        seq: 1,
        tid: 7,
        msg_type: ty,
        data_off,
        ..Default::default()
    }
    .to_bytes()
    .to_vec()
}

fn wire(data_off: u16, data: usize) -> (Vec<u8>, [Vec<u8>; 4]) {
    wire_rev(Revision::V21, data_off, data)
}

fn wire_rev(rev: Revision, data_off: u16, data: usize) -> (Vec<u8>, [Vec<u8>; 4]) {
    let segs = [header(TY, data_off), mk(40, 2), Vec::new(), mk(data, 4)];
    let mut e = Encoder::new(rev);
    let mut out = Vec::new();
    e.encode_message(&segs[0], &segs[1], &segs[2], &segs[3], &mut out)
        .unwrap();
    (out, segs)
}

fn decoder() -> Decoder {
    let mut d = Decoder::new(Revision::V21);
    d.set_rx_place(true);
    d
}

/// Plain `feed` in `chunk`-sized pieces.
fn feed_all(w: &[u8], chunk: usize) -> OwnedFrame {
    let mut d = decoder();
    for c in w.chunks(chunk) {
        d.feed(c);
    }
    let f = d.poll_owned().unwrap().expect("frame");
    assert!(d.poll_owned().unwrap().is_none());
    f
}

/// `cut` bytes through `feed`, then every direct request served in `chunk`-sized reads (as knet does).
fn direct(w: &[u8], cut: usize, chunk: usize) -> OwnedFrame {
    let mut d = decoder();
    let mut pos = cut.min(w.len());
    d.feed(&w[..pos]);
    loop {
        let want = d.direct_want();
        if want == 0 {
            if pos >= w.len() {
                break;
            }
            let n = chunk.min(w.len() - pos);
            d.feed(&w[pos..pos + n]);
            pos += n;
            continue;
        }
        let (mut v, mut crc) = d.direct_take().expect("want > 0");
        assert!(v.capacity() >= v.len() + want);
        let mut left = want;
        while left > 0 {
            let n = chunk.min(left);
            v.extend_from_slice(&w[pos..pos + n]);
            crc.update(&w[pos..pos + n]);
            pos += n;
            left -= n;
        }
        d.direct_put(v, crc);
    }
    let f = d.poll_owned().unwrap().expect("frame");
    assert!(d.poll_owned().unwrap().is_none());
    f
}

/// Segment bytes exact, segment byte `head` 4 KiB aligned; CRC-mode frames also: crc, grid and block crcs.
fn check(f: &OwnedFrame, segs: &[Vec<u8>; 4], head: usize, crc_mode: bool) {
    for (i, s) in segs.iter().enumerate() {
        assert!(f.segs[i][..] == s[..], "segment {i}");
    }
    let d = &f.segs[3];
    assert_eq!(
        (d.as_ptr() as usize + head) % 4096,
        0,
        "payload not 4 KiB aligned (len {})",
        d.len()
    );
    if d.len() > head {
        assert_eq!(f.data_head, head);
    }
    if !crc_mode {
        return;
    }
    assert_eq!(f.data_crc, Some(crc::crc32c(!0, d)));
    if d.len() >= BLOCKS_MIN {
        let want: Vec<u32> = d[head..]
            .as_chunks::<4096>()
            .0
            .iter()
            .map(|b| crc::crc32c(0, b))
            .collect();
        assert_eq!(f.data_blocks.as_deref(), Some(&want[..]), "block crcs");
    } else {
        assert!(f.data_blocks.is_none());
    }
}

const SIZES: [usize; 8] = [1, 512, 4096, 5000, 65_536, 70_000, 1 << 20, (4 << 20) + 300];

#[test]
fn payload_lands_aligned_with_its_own_block_grid() {
    for data in SIZES {
        for (off, head) in [(OFF, HEAD), (0, 0), (4096 + 512, 4096 - 512)] {
            let (w, segs) = wire(off, data);
            for chunk in [1448usize, 4096, 65_536, 1 << 20] {
                check(&feed_all(&w, chunk), &segs, head, true);
                for cut in [0usize, 5, 40, 100, 300, 5000, w.len() / 2] {
                    check(&direct(&w, cut, chunk), &segs, head, true);
                }
            }
        }
    }
}

#[test]
fn placement_off_leaves_segments_as_allocated() {
    let (w, segs) = wire(OFF, 1 << 20);
    let mut d = Decoder::new(Revision::V21);
    d.feed(&w);
    let f = d.poll_owned().unwrap().expect("frame");
    for (i, s) in segs.iter().enumerate() {
        assert!(f.segs[i][..] == s[..]);
    }
    // grid at segment byte 0, whatever the memory address
    assert_eq!(f.data_head, 0);
    let want: Vec<u32> = f.segs[3]
        .as_chunks::<4096>()
        .0
        .iter()
        .map(|b| crc::crc32c(0, b))
        .collect();
    assert_eq!(f.data_blocks.as_deref(), Some(&want[..]));
}

#[test]
fn a_corrupt_placed_payload_is_still_caught() {
    let (mut w, _) = wire(OFF, 1 << 20);
    let at = w.len() / 2;
    w[at] ^= 0x10;
    let mut d = decoder();
    d.feed(&w);
    assert!(matches!(d.poll_owned(), Err(Error::BadSegmentCrc(_))));
}

#[test]
fn frames_back_to_back_reset_the_pad() {
    let (w1, s1) = wire(OFF, 200_000);
    let (w2, s2) = wire(0, 4096);
    let (w3, s3) = wire(OFF, 100_000);
    let mut d = decoder();
    for (w, s, head) in [(&w1, &s1, HEAD), (&w2, &s2, 0), (&w3, &s3, HEAD)] {
        d.feed(w);
        let f = d.poll_owned().unwrap().expect("frame");
        check(&f, s, head, true);
    }
}

fn secret() -> ConnSecret {
    ConnSecret::new(&(0..64u8).collect::<Vec<_>>()).unwrap()
}

#[test]
fn secure_frames_are_decrypted_into_placed_buffers() {
    for rev in [Revision::V21, Revision::V20] {
        let mut e = Encoder::new(rev);
        e.set_secure(&secret(), Role::Client).unwrap();
        let mut d = Decoder::new(rev);
        d.set_secure(&secret(), Role::Server).unwrap();
        d.set_rx_place(true);
        for data in SIZES {
            for (off, head) in [(OFF, HEAD), (0, 0)] {
                let segs = [header(TY, off), mk(40, 2), mk(9, 3), mk(data, 4)];
                let mut w = Vec::new();
                e.encode_message(&segs[0], &segs[1], &segs[2], &segs[3], &mut w)
                    .unwrap();
                for c in w.chunks(1448) {
                    d.feed(c);
                }
                let f = d.poll_owned().unwrap().expect("frame");
                // rev 2.0 secure: large frames stay views of the rx buffer (in-place decrypt, legacy): bytes only
                if rev == Revision::V21 || w.len() < 8192 {
                    check(&f, &segs, head, false);
                } else {
                    for (i, s) in segs.iter().enumerate() {
                        assert!(f.segs[i][..] == s[..], "segment {i}");
                    }
                }
            }
        }
        // tampered ciphertext fails authentication, nothing is delivered
        let segs = [header(TY, OFF), mk(40, 2), Vec::new(), mk(70_000, 4)];
        let mut w = Vec::new();
        e.encode_message(&segs[0], &segs[1], &segs[2], &segs[3], &mut w)
            .unwrap();
        let at = w.len() - 100;
        w[at] ^= 1;
        d.feed(&w);
        assert!(d.poll_owned().is_err(), "{rev:?}");
    }
}

#[test]
fn rev20_crc_frames_are_placed() {
    let mut d = Decoder::new(Revision::V20);
    d.set_rx_place(true);
    for data in SIZES {
        let (w, segs) = wire_rev(Revision::V20, OFF, data);
        d.feed(&w);
        let f = d.poll_owned().unwrap().expect("frame");
        check(&f, &segs, HEAD, false);
    }
}
