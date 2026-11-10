// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Real mon<->osd0 MESSAGE frames captured from the v21.1.1 reference cluster
//! (testdata/msgr2/*.bin, crc mode): decode every message, re-encode, require byte equality.
use messages::*;
use msgr2::{Banner, Decoder};
use std::collections::BTreeMap;

fn stream(name: &str) -> Vec<u8> {
    let p = format!("{}/../../testdata/msgr2/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

type Frame = (Header2, Vec<u8>, Vec<u8>, Vec<u8>);

/// All MESSAGE frames of a stream: (header, front, middle, data).
fn frames(name: &str) -> Vec<Frame> {
    let s = stream(name);
    let (b, n) = Banner::parse(&s).unwrap().unwrap();
    let mut d = Decoder::new(b.revision());
    d.feed(&s[n..]);
    let mut out = Vec::new();
    while let Some(f) = d.poll().unwrap() {
        if f.tag != 17 {
            continue;
        }
        let h = Header2::parse(f.segment(0)).unwrap();
        out.push((
            h,
            f.segment(1).to_vec(),
            f.segment(2).to_vec(),
            f.segment(3).to_vec(),
        ));
    }
    out
}

const STREAMS: [&str; 4] = [
    "osd0-mon-36936-c2s.bin",
    "osd0-mon-36936-s2c.bin",
    "osd0-mon-36940-c2s.bin",
    "osd0-mon-36940-s2c.bin",
];

#[test]
fn every_captured_message_roundtrips_byte_exact() {
    let mut seen: BTreeMap<u16, usize> = BTreeMap::new();
    for name in STREAMS {
        for (i, (h, front, mid, data)) in frames(name).into_iter().enumerate() {
            let m = decode_with_header(&h, &front, &mid, &data)
                .unwrap_or_else(|e| panic!("{name}#{i} type {}: {e}", h.ty));
            assert!(
                !matches!(m, AnyMessage::Unknown { .. }),
                "{name}#{i}: type {} unknown",
                h.ty
            );
            let (ty, ver, compat, segs) = m.encode(denc::features::ALL).unwrap();
            assert_eq!(
                (ty, ver, compat),
                (h.ty, h.version, h.compat_version),
                "{name}#{i} header"
            );
            assert_eq!(segs.front, front, "{name}#{i} type {} front\n{m:#?}", h.ty);
            assert_eq!(segs.middle, mid, "{name}#{i} middle");
            assert_eq!(segs.data, data, "{name}#{i} data");
            *seen.entry(h.ty).or_default() += 1;
        }
    }
    // Every message type present in the capture is covered.
    for ty in [
        4u16, 5, 15, 17, 18, 19, 20, 41, 50, 51, 52, 53, 62, 71, 73, 78, 79, 0x704,
    ] {
        assert!(
            seen.contains_key(&ty),
            "type {ty} not in captures: {seen:?}"
        );
    }
}

#[test]
fn captured_boot_has_expected_fields() {
    let (h, front, ..) = frames("osd0-mon-36940-c2s.bin")
        .into_iter()
        .find(|f| f.0.ty == ty::OSD_BOOT)
        .unwrap();
    let AnyMessage::MOSDBoot(b) = decode_any(h.ty, h.version, &front, &[], &[]).unwrap() else {
        panic!()
    };
    assert_eq!(b.sb.whoami, 0);
    assert!(b.metadata.contains_key("hostname") && b.metadata.contains_key("ceph_version_short"));
    assert!(b.sb.mapc.is_empty() || b.sb.current_epoch > 0);
    // Our initial CompatSet matches a real OSD's.
    assert_eq!(b.sb.compat_features, CompatSet::osd_initial());
    println!("{:#?}", b.sb);
}

#[test]
fn captured_mgrmap_prefix() {
    let (h, front, ..) = frames("osd0-mon-36940-s2c.bin")
        .into_iter()
        .find(|f| f.0.ty == ty::MGR_MAP)
        .unwrap();
    let AnyMessage::MMgrMap(m) = decode_any(h.ty, h.version, &front, &[], &[]).unwrap() else {
        panic!()
    };
    println!("{:?}", m.prefix);
    assert!(m.prefix.epoch > 0);
}
