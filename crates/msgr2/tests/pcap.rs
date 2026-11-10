// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Real mon<->osd0 streams captured from the v21.1.1 reference cluster in crc mode
//! (testdata/msgr2/*.bin; client = osd0 172.28.0.20, server = mon 172.28.0.10).
use msgr2::*;
use std::path::PathBuf;

fn load(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/msgr2")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Decode a whole stream: returns (banner, frame tags, re-encoded stream bytes, consumed bytes).
fn run(name: &str, chunk: usize) -> (Banner, Vec<u8>, Vec<u8>, usize, Vec<usize>) {
    let s = load(name);
    let (b, n) = Banner::parse(&s).unwrap().unwrap();
    assert_eq!(n, 26);
    let mut d = Decoder::new(b.revision());
    let mut e = Encoder::new(b.revision());
    let (mut tags, mut re, mut nsegs) = (Vec::new(), Vec::new(), Vec::new());
    let mut consumed = 0;
    for c in s[n..].chunks(chunk) {
        d.feed(c);
        while let Some(f) = d.poll().unwrap() {
            tags.push(f.tag);
            nsegs.push(f.num_segments);
            let segs: Vec<Seg> = (0..f.num_segments)
                .map(|i| Seg {
                    data: f.segment(i),
                    align: f.align[i],
                })
                .collect();
            let before = re.len();
            e.encode_ex(f.tag, f.flags, false, &segs, &mut re).unwrap();
            consumed += re.len() - before;
        }
    }
    assert_eq!(d.buffered() + consumed, s.len() - n);
    (b, tags, re, consumed, nsegs)
}

#[test]
fn banners_and_handshake() {
    for (name, first) in [
        ("osd0-mon-36940-c2s.bin", vec![1u8, 2]),
        ("osd0-mon-36940-s2c.bin", vec![1u8, 4, 6, 7, 22, 9]),
    ] {
        let (b, tags, ..) = run(name, 1 << 20);
        assert_eq!((b.supported, b.required), (3, 0));
        assert_eq!(b.revision(), Revision::V21);
        assert_eq!(&tags[..first.len()], &first[..], "{name}: {tags:?}");
        assert!(tags.iter().all(|&t| Tag::from_u8(t).is_some()));
    }
}

#[test]
fn reencode_is_byte_identical() {
    for name in [
        "osd0-mon-36936-c2s.bin",
        "osd0-mon-36936-s2c.bin",
        "osd0-mon-36940-c2s.bin",
        "osd0-mon-36940-s2c.bin",
    ] {
        let s = load(name);
        let (_, tags, re, consumed, _) = run(name, 1 << 20);
        assert!(tags.len() >= 3, "{name}");
        assert_eq!(&re[..], &s[26..26 + consumed], "{name}");
        // incremental feeding gives the same result
        let (_, tags2, re2, _, _) = run(name, 7);
        assert_eq!((tags, re), (tags2, re2));
    }
}

#[test]
fn long_stream_has_messages_and_keepalives() {
    let (_, tags, _, _, nsegs) = run("osd0-mon-36940-s2c.bin", 4096);
    let msgs = tags.iter().filter(|&&t| t == Tag::Message as u8).count();
    assert!(msgs > 5, "{tags:?}");
    // MESSAGE frames carry a 41-byte header in segment 0
    let (b, ..) = run("osd0-mon-36940-s2c.bin", 4096);
    let _ = b;
    let s = load("osd0-mon-36940-s2c.bin");
    let mut d = Decoder::new(Revision::V21);
    d.feed(&s[26..]);
    let mut seen = 0;
    while let Some(f) = d.poll().unwrap() {
        if f.tag == Tag::Message as u8 {
            assert_eq!(f.segment(0).len(), 41);
            assert_eq!(f.align[0], 8);
            seen += 1;
        }
        if f.tag == Tag::Keepalive2Ack as u8 {
            assert!(payload::Keepalive2Ack::from_bytes(f.segment(0)).is_ok());
        }
    }
    assert_eq!(seen, msgs);
    assert!(nsegs.iter().any(|&n| n == 4 || n == 2 || n == 3));
}

#[test]
fn corrupted_capture_rejected() {
    let s = load("osd0-mon-36940-s2c.bin");
    let mut x = s[26..].to_vec();
    // flip a byte inside the first frame after HELLO (AUTH_DONE payload)
    let mut d = Decoder::new(Revision::V21);
    d.feed(&x);
    let mut off = 0;
    let mut lens = Vec::new();
    while let Some(f) = d.poll().unwrap() {
        let l: usize = 32 + f.segments().iter().map(|s| s.len()).sum::<usize>();
        lens.push(l);
        if lens.len() == 2 {
            break;
        }
    }
    off += lens[0] + 4 + 34; // hello (+seg crc) then 2 bytes into frame 2 payload
    x[off] ^= 1;
    let mut d = Decoder::new(Revision::V21);
    d.feed(&x);
    let mut r = Ok(());
    loop {
        match d.poll() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                r = Err(e);
                break;
            }
        }
    }
    assert!(matches!(r, Err(Error::BadSegmentCrc(0))), "{r:?}");
}
