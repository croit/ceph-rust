// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Direct receive: a transport lends the partially filled data-segment buffer (`direct_take`), fills the rest from the
//! socket, computes the running crc and returns it (`direct_put`). The result must be exactly what plain `feed` gives,
//! and corruption must still be caught.
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::*;

fn mk(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn wire(lens: [usize; 4]) -> (Vec<u8>, [Vec<u8>; 4]) {
    let segs: [Vec<u8>; 4] = std::array::from_fn(|i| mk(lens[i], i as u8 + 1));
    let mut e = Encoder::new(Revision::V21);
    let mut out = Vec::new();
    e.encode_message(&segs[0], &segs[1], &segs[2], &segs[3], &mut out)
        .unwrap();
    (out, segs)
}

/// Feed `w` with `cut` bytes through `feed`, then serve every direct request in `chunk`-sized socket reads.
fn run(w: &[u8], cut: usize, chunk: usize) -> Result<Vec<Vec<u8>>, Error> {
    let mut d = Decoder::new(Revision::V21);
    let mut pos = cut.min(w.len());
    d.feed(&w[..pos]);
    let mut direct_used = false;
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
        let from = v.len();
        assert!(v.capacity() >= from + want);
        let mut left = want;
        while left > 0 {
            let n = chunk.min(left);
            v.extend_from_slice(&w[pos..pos + n]);
            crc.update(&w[pos..pos + n]);
            pos += n;
            left -= n;
        }
        d.direct_put(v, crc);
        direct_used = true;
    }
    let f = d.poll_owned()?.expect("frame complete");
    assert!(d.poll_owned()?.is_none());
    check_blocks(&f);
    let _ = direct_used;
    Ok(f.segs.iter().map(|b| b.to_vec()).collect())
}

#[test]
fn direct_fill_equals_plain_decode() {
    for lens in [
        [40, 0, 0, 1 << 20],
        [200, 0, 0, 4 << 20],
        [40, 70_000, 0, 300_000],
        [10, 0, 0, 131_072],
    ] {
        let (w, segs) = wire(lens);
        // cuts: inside the preamble, inside the front, inside / at the start of the big segment, exactly at a boundary
        for cut in [0, 5, 32, 40, 100, 300, 5000, w.len() / 2] {
            for chunk in [4096, 65_536, 1 << 20] {
                let got = run(&w, cut, chunk)
                    .unwrap_or_else(|e| panic!("{lens:?} cut {cut} chunk {chunk}: {e:?}"));
                let n = lens.iter().rposition(|&l| l > 0).unwrap() + 1;
                for i in 0..n {
                    assert!(
                        got[i] == segs[i],
                        "{lens:?} cut {cut} chunk {chunk} seg {i}"
                    );
                }
            }
        }
    }
}

#[test]
fn direct_non_data_segments_reuse_the_running_crc_without_block_tables() {
    for (segment, size) in [
        (0, 1 << 20),
        (1, 1 << 20),
        (2, 1 << 20),
        (3, 1 << 20),
        (3, 4096),
    ] {
        let mut lens = [41, 0, 0, 0];
        lens[segment] = size;
        let (w, segs) = wire(lens);
        let start = PREAMBLE_LEN + if segment > 0 { lens[0] + 4 } else { 0 };
        let cut = start + (size / 2) + 7; // a checksummed run plus an unchecksummed tail
        let mut d = Decoder::new(Revision::V21);
        d.feed(&w[..cut]);
        let (mut buf, mut crcs) = d.direct_take().unwrap();
        let want = d.direct_want();
        assert_eq!(want, 0, "loan owns receive storage");
        if segment != 3 || size < BLOCKS_MIN {
            assert!(
                crcs.blocks().is_empty(),
                "unused block table for segment {segment}"
            );
            assert_eq!(crcs.head(), lens[segment]);
        }
        let end = start + lens[segment];
        buf.extend_from_slice(&w[cut..end]);
        crcs.update(&w[cut..end]);
        d.direct_put(buf, crcs);
        d.feed(&w[end..]);
        let frame = d.poll_owned().unwrap().unwrap();
        assert_eq!(frame.segs[segment].as_ref(), segs[segment]);
        check_blocks(&frame);
    }
}

/// The carried-over running crc must cover exactly the lent segment's prefix (same bytes, same seed): one flipped byte
/// in the checksummed prefix, in a not yet checksummed prefix tail (`crcd < have`), or in the lent remainder fails the
/// segment crc. The prefix is fed whole and in small pieces (the latter leaves a running crc that lags behind `have`).
#[test]
fn direct_running_crc_reuse_detects_one_flipped_byte() {
    for (segment, size) in [(0, 1 << 20), (1, 1 << 20), (2, 1 << 20), (3, 4096)] {
        let mut lens = [41, 0, 0, 0];
        lens[segment] = size;
        let (original, segs) = wire(lens);
        let start = PREAMBLE_LEN + if segment > 0 { lens[0] + 4 } else { 0 };
        let cut = start + size / 2 + 7;
        let end = start + size;
        for pieces in [false, true] {
            for flip in [None, Some(start), Some(cut - 3), Some(cut), Some(end - 1)] {
                let mut w = original.clone();
                if let Some(at) = flip {
                    w[at] ^= 0x01;
                }
                let mut d = Decoder::new(Revision::V21);
                if pieces {
                    // bytes up to the segment, then the prefix in runs shorter than the crc batching threshold
                    d.feed(&w[..start]);
                    for c in w[start..cut].chunks(1000) {
                        d.feed(c);
                    }
                } else {
                    d.feed(&w[..cut]);
                }
                let (mut buf, mut crcs) = d.direct_take().unwrap();
                buf.extend_from_slice(&w[cut..end]);
                crcs.update(&w[cut..end]);
                d.direct_put(buf, crcs);
                d.feed(&w[end..]);
                match (flip, d.poll_owned()) {
                    (None, Ok(Some(f))) => assert_eq!(f.segs[segment].as_ref(), segs[segment]),
                    (Some(_), Err(Error::BadSegmentCrc(s))) => assert_eq!(s, segment),
                    (flip, r) => panic!(
                        "segment {segment} pieces {pieces} flip {flip:?}: {:?}",
                        r.map(|f| f.is_some())
                    ),
                }
            }
        }
    }
}

#[test]
fn direct_fill_still_detects_corruption() {
    let (mut w, _) = wire([40, 0, 0, 1 << 20]);
    let at = w.len() / 2;
    w[at] ^= 0x10;
    assert!(matches!(run(&w, 100, 65_536), Err(Error::BadSegmentCrc(_))));
    // a wrong running crc handed back is caught as well
    let (w, _) = wire([40, 0, 0, 300_000]);
    let mut d = Decoder::new(Revision::V21);
    d.feed(&w[..100]);
    let want = d.direct_want();
    assert!(want > 0);
    let (mut v, crc) = d.direct_take().unwrap();
    v.extend_from_slice(&w[100..100 + want]);
    d.direct_put(v, crc); // crc not advanced
    d.feed(&w[100 + want..]);
    assert!(d.poll_owned().is_err());
}

#[test]
fn direct_is_off_when_it_cannot_apply() {
    let d = Decoder::new(Revision::V20);
    assert_eq!(d.direct_want(), 0);
    let (w, _) = wire([40, 0, 0, 1 << 20]);
    let mut d = Decoder::new(Revision::V21);
    d.feed(&w[..20]); // preamble incomplete
    assert_eq!(d.direct_want(), 0);
    // a size-mismatched buffer is refused
    d.feed(&w[20..100]);
    let want = d.direct_want();
    let (v, crc) = d.direct_take().unwrap();
    assert!(want > 0);
    d.direct_put(v, crc); // not filled: len < segment
    assert!(d.poll_owned().is_err());
}

#[test]
fn bytes_while_the_buffer_is_lent_fail_the_decoder_without_panic() {
    let (w, _) = wire([40, 0, 0, 300_000]);
    let mut d = Decoder::new(Revision::V21);
    d.feed(&w[..50_000]);
    let (_v, _crc) = d.direct_take().expect("want > 0");
    assert_eq!(d.direct_want(), 0, "no second lend");
    assert!(d.direct_take().is_none());
    d.feed(&w[50_000..54_096]); // contract violation by a transport
    assert!(d.poll_owned().is_err());
}

/// Drive `s` with `out`: plain `on_bytes` until a direct receive is offered, then fill it like knet does.
/// `fault_while_lent`: the connection faults while the buffer is out; the late `put` must be ignored.
fn conn_run(s: &mut Connection, out: &[u8], fault_while_lent: bool) -> Vec<Event> {
    let mut pos = 0;
    let mut lent = false;
    while pos < out.len() {
        let want = s.rx_direct_want();
        if want == 0 {
            let n = 1500.min(out.len() - pos);
            s.on_bytes(&out[pos..pos + n], t(5));
            pos += n;
            continue;
        }
        let (mut v, mut crc) = s.rx_direct_take().expect("want > 0");
        lent = true;
        v.extend_from_slice(&out[pos..pos + want]);
        crc.update(&out[pos..pos + want]);
        pos += want;
        if fault_while_lent {
            s.on_closed(t(6));
            s.rx_direct_put(v, crc, t(7));
            assert_eq!(s.rx_direct_want(), 0);
            return events(s);
        }
        s.rx_direct_put(v, crc, t(6));
    }
    assert!(lent, "the big segment went the direct way");
    events(s)
}

fn ready_pair() -> (Connection, Connection) {
    let mut a = Node::new(EntityName::OSD, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(EntityName::OSD, 2, 2, PolicyTable::osd_cluster());
    let mut rng = Rng(5);
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 4096);
    assert_eq!(msgs(&events(&mut s)).len(), 1);
    events(&mut c);
    (c, s)
}

#[test]
fn connection_direct_receive_delivers_the_exact_message() {
    let (mut c, mut s) = ready_pair();
    c.send_message(msg(2, 42, 200_000)); // front 200 KB, data 600 KB
    let out = c.poll_output();
    let evs = conn_run(&mut s, &out, false);
    let m = msgs(&evs);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].header.tid, 2);
    assert!(m[0].front == vec![2u8; 200_000]);
    assert!(m[0].data.iter().all(|&b| b == 7) && m[0].data.len() == 600_000);
}

#[test]
fn connection_fault_while_lent_drops_the_late_buffer() {
    let (mut c, mut s) = ready_pair();
    c.send_message(msg(2, 42, 200_000));
    let out = c.poll_output();
    let evs = conn_run(&mut s, &out, true);
    assert!(
        msgs(&evs).is_empty(),
        "nothing dispatched from a faulted connection"
    );
}

#[test]
fn large_crc_appends_after_short_prefixes_cover_every_byte_and_detect_corruption() {
    let (original, segs) = wire([40, 100_003, 7, 200_007]);
    for corrupt in [false, true] {
        let mut w = original.clone();
        if corrupt {
            w[50_000] ^= 0x80;
        }
        let mut d = Decoder::new(Revision::V21);
        let mut pos = 0;
        for n in [101, 32_768, 19, 65_536, 3, 32_768, 7, 65_536] {
            let end = (pos + n).min(w.len());
            d.feed(&w[pos..end]);
            pos = end;
        }
        d.feed(&w[pos..]);
        if corrupt {
            assert!(matches!(d.poll_owned(), Err(Error::BadSegmentCrc(_))));
        } else {
            let f = d.poll_owned().unwrap().unwrap();
            for (actual, expected) in f.segs.iter().zip(&segs) {
                assert_eq!(actual.as_ref(), expected);
            }
            assert!(d.poll_owned().unwrap().is_none());
        }
    }
}

/// The receive pass's block crcs (adr 0061 am. 4) are exactly the per-4 KiB crcs of the data segment, and the data crc
/// joined from them is the segment's crc.
fn check_blocks(f: &OwnedFrame) {
    let Some(d) = f.segs.get(3) else {
        assert!(f.data_blocks.is_none());
        return;
    };
    assert_eq!(f.data_crc, Some(crc::crc32c(!0, d)));
    if d.len() < msgr2::BLOCKS_MIN {
        assert!(f.data_blocks.is_none(), "small data segment");
        return;
    }
    let want: Vec<u32> = d
        .as_chunks::<4096>()
        .0
        .iter()
        .map(|b| crc::crc32c(0, b))
        .collect();
    assert_eq!(f.data_blocks.as_deref(), Some(&want[..]), "block crcs");
}

#[test]
fn plain_feed_block_crcs_for_every_piece_size() {
    for lens in [
        [40, 0, 0, 65_536],
        [40, 9, 0, 300_001],
        [200, 0, 0, 4 << 20],
        [40, 0, 0, 65_535],
    ] {
        let (w, segs) = wire(lens);
        for piece in [1usize, 1448, 4096, 40_000, 1 << 20] {
            if piece == 1 && w.len() > 400_000 {
                continue;
            }
            let mut d = Decoder::new(Revision::V21);
            let mut got = None;
            for c in w.chunks(piece) {
                d.feed(c);
                if let Some(f) = d.poll_owned().unwrap() {
                    got = Some(f);
                }
            }
            let f = got.or_else(|| d.poll_owned().unwrap()).expect("frame");
            assert_eq!(&f.segs[3][..], &segs[3][..], "{lens:?} piece {piece}");
            check_blocks(&f);
        }
    }
}
