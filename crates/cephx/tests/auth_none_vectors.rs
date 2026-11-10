// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Byte-exact AUTH_NONE vectors (doc/spec/auth-none.md sec 10) and method/mode selection rules.
use cephx::modes::*;
use cephx::none::*;

/// `0a | 04000000 | 01000000 33 | gid 0`
const MON_OSD3_GID0: [u8; 18] = [0x0a, 4, 0, 0, 0, 1, 0, 0, 0, b'3', 0, 0, 0, 0, 0, 0, 0, 0];
/// `01 | 08000000 | 05000000 "admin" | gid 0x1234`
const AUTHORIZER_ADMIN: [u8; 22] = [
    1, 8, 0, 0, 0, 5, 0, 0, 0, b'a', b'd', b'm', b'i', b'n', 0x34, 0x12, 0, 0, 0, 0, 0, 0,
];

#[test]
fn mon_variant_vector_both_directions() {
    let name = EntityName::parse("osd.3").unwrap();
    assert_eq!(mon_auth_payload(&name, 0), MON_OSD3_GID0);
    let (mode, n, gid) = parse_none_payload(&MON_OSD3_GID0).unwrap();
    assert_eq!((mode, n, gid), (AUTH_MODE_MON, name, 0));
}

#[test]
fn authorizer_variant_vector_both_directions() {
    let name = EntityName::parse("client.admin").unwrap();
    assert_eq!(none_authorizer(&name, 0x1234), AUTHORIZER_ADMIN);
    let peer = verify_none(&AUTHORIZER_ADMIN).unwrap();
    assert_eq!((peer.name, peer.global_id), (name, 0x1234));
}

#[test]
fn verifier_ignores_trailing_bytes_and_struct_v_value() {
    let mut p = AUTHORIZER_ADMIN.to_vec();
    p[0] = 9;
    p.extend_from_slice(b"trailing");
    assert_eq!(verify_none(&p).unwrap().global_id, 0x1234);
}

#[test]
fn verifier_never_panics_on_hostile_payloads() {
    assert!(verify_none(&[]).is_err());
    for n in 0..AUTHORIZER_ADMIN.len() {
        assert!(verify_none(&AUTHORIZER_ADMIN[..n]).is_err(), "len {n}");
    }
    for first in [0u8, 10, 19, 20, 255] {
        let mut p = AUTHORIZER_ADMIN.to_vec();
        p[0] = first;
        assert!(verify_none(&p).is_err(), "mode byte {first}");
    }
    // name length larger than the payload
    let mut p = AUTHORIZER_ADMIN.to_vec();
    p[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(verify_none(&p).is_err());
}

#[test]
fn nonzero_gid_is_echoed_without_proof() {
    let name = EntityName::parse("osd.3").unwrap();
    let p = mon_auth_payload(&name, 0xdead_beef);
    let (_, _, gid) = parse_none_payload(&p).unwrap();
    assert_eq!(gid, 0xdead_beef);
}

#[test]
fn none_modes_keep_crc_only() {
    assert_eq!(
        modes_for_method(&[CON_MODE_SECURE, CON_MODE_CRC], AUTH_NONE),
        [CON_MODE_CRC]
    );
    assert!(modes_for_method(&[CON_MODE_SECURE], AUTH_NONE).is_empty());
    assert_eq!(
        modes_for_method(&[CON_MODE_SECURE, CON_MODE_CRC], AUTH_CEPHX),
        [CON_MODE_SECURE, CON_MODE_CRC]
    );
}
