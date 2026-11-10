// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Round-trip every sample and compare with `testdata/messages/ours/<Type>.<name>.msg`; rewrite them when
//! `EMIT_SAMPLES=1` (input for testdata/messages/oracle.sh).
mod common;
use common::*;
use messages::*;

#[test]
fn all_samples_roundtrip() {
    for (t, n, m) in samples() {
        let (ty, ver, compat, segs) = m.encode(denc::features::ALL).unwrap();
        let back = decode_any(ty, ver, &segs.front, &segs.middle, &segs.data).unwrap();
        assert_eq!(back, m, "{t}.{n}");
        let (h, segs2) = m.header(9, denc::features::ALL).unwrap();
        assert_eq!(
            (h.ty, h.version, h.compat_version, h.tid),
            (ty, ver, compat, 9)
        );
        let h = Header2::parse(&h.encode()).unwrap();
        let back2 = decode_with_header(&h, &segs2.front, &segs2.middle, &segs2.data).unwrap();
        assert_eq!(back2, m);
        let wrapped = dencoder_wrapper(ty, ver, compat, &segs);
        let path = testdata(&format!("ours/{t}.{n}.msg"));
        if std::env::var_os("EMIT_SAMPLES").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &wrapped).unwrap();
        } else {
            let stored = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert_eq!(
                stored, wrapped,
                "{t}.{n} differs from stored sample (regen: EMIT_SAMPLES=1)"
            );
        }
    }
}

/// ceph-dencoder's container for Message types (observed black-box, see oracle.sh): legacy msgr1
/// `ceph_msg_header` (53 B) + footer_old (13 B: 3 crc32c + flags) + three length-prefixed segments.
fn dencoder_wrapper(ty: u16, ver: u16, compat: u16, s: &Segments) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0u64.to_le_bytes()); // seq
    b.extend_from_slice(&0u64.to_le_bytes()); // tid
    b.extend_from_slice(&ty.to_le_bytes());
    b.extend_from_slice(&127u16.to_le_bytes()); // priority
    b.extend_from_slice(&ver.to_le_bytes());
    b.extend_from_slice(&(s.front.len() as u32).to_le_bytes());
    b.extend_from_slice(&(s.middle.len() as u32).to_le_bytes());
    b.extend_from_slice(&(s.data.len() as u32).to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes()); // data_off
    b.push(8); // src type client
    b.extend_from_slice(&0i64.to_le_bytes());
    b.extend_from_slice(&compat.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    let hcrc = crc::crc32c(0, &b);
    b.extend_from_slice(&hcrc.to_le_bytes());
    // footer_old: front/middle/data crc, flags = COMPLETE (crcs are then verified)
    b.extend_from_slice(&crc::crc32c(0, &s.front).to_le_bytes());
    b.extend_from_slice(&crc::crc32c(0, &s.middle).to_le_bytes());
    b.extend_from_slice(&crc::crc32c(0, &s.data).to_le_bytes());
    b.push(1);
    for seg in [&s.front[..], &s.middle[..], &s.data[..]] {
        b.extend_from_slice(&(seg.len() as u32).to_le_bytes());
        b.extend_from_slice(seg);
    }
    b
}
