// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use denc::types::Uuid;
use messages::{AnyMessage, MPoolOp, MPoolOpReply, Message, PoolOperation};
fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .flat_map(|part| {
            part.as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        })
        .collect()
}
fn fsid() -> Uuid {
    Uuid::parse("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap()
}
fn request() -> MPoolOp {
    MPoolOp {
        version: 0x0102030405060708,
        fsid: fsid(),
        pool: 0x11223344,
        operation: PoolOperation::AllocateSelfManagedSnap,
        snapid: 0,
        name: vec![],
        crush_rule: 0,
    }
}
#[test]
fn allocation_request_matches_independent_literal_front_and_header() {
    let expected = hex(
        "0807060504030201 ffff 0000000000000000 000102030405060708090a0b0c0d0e0f 44332211 21000000 0000000000000000 0000000000000000 00000000 00 0000",
    );
    let m = request();
    let seg = m.encode(0).unwrap();
    assert_eq!(seg.front, expected);
    assert_eq!(seg.front.len(), 65);
    assert!(seg.middle.is_empty() && seg.data.is_empty());
    assert_eq!(MPoolOp::decode(4, &expected, &[], &[]).unwrap(), m);
    let any: AnyMessage = m.clone().into();
    let (ty, v, c, _) = any.encode(0).unwrap();
    assert_eq!((ty, v, c), (49, 4, 2));
    assert_eq!(
        messages::decode_any(ty, v, &expected, &[], &[]).unwrap(),
        any
    );
}
#[test]
fn successful_snapshot_reply_and_negative_status_match_independent_vectors() {
    let success = hex(
        "0900000000000000 ffff 0000000000000000 000102030405060708090a0b0c0d0e0f 00000000 44332211 01 08000000 efcdab8967452301",
    );
    let m = MPoolOpReply {
        version: 9,
        fsid: fsid(),
        result: 0,
        epoch: 0x11223344,
        response_data: 0x0123456789abcdefu64.to_le_bytes().to_vec(),
    };
    assert_eq!(m.encode(0).unwrap().front, success);
    assert_eq!(MPoolOpReply::decode(1, &success, &[], &[]).unwrap(), m);
    let negative = hex(
        "0900000000000000 ffff 0000000000000000 000102030405060708090a0b0c0d0e0f feffffff 17000000 00",
    );
    let m = MPoolOpReply {
        result: -2,
        epoch: 23,
        response_data: vec![],
        ..m
    };
    assert_eq!(m.encode(0).unwrap().front, negative);
    assert_eq!(MPoolOpReply::decode(1, &negative, &[], &[]).unwrap(), m);
    let any: AnyMessage = m.into();
    let (ty, v, c, _) = any.encode(0).unwrap();
    assert_eq!((ty, v, c), (48, 1, 1));
    assert_eq!(
        messages::decode_any(ty, v, &negative, &[], &[]).unwrap(),
        any
    );
}
#[test]
fn six_typed_operations_preserve_binary_names_ids_and_signed_width() {
    for (op, wire) in [
        (PoolOperation::CreatePool, 0x01),
        (PoolOperation::DeletePool, 0x02),
        (PoolOperation::CreateNamedSnap, 0x11),
        (PoolOperation::RemoveNamedSnap, 0x12),
        (PoolOperation::AllocateSelfManagedSnap, 0x21),
        (PoolOperation::RemoveSelfManagedSnap, 0x22),
    ] {
        let m = MPoolOp {
            operation: op,
            name: vec![0, 255, 65],
            snapid: 0x8877665544332211,
            crush_rule: -7,
            ..request()
        };
        let front = m.encode(0).unwrap().front;
        assert_eq!(&front[38..42], &(wire as u32).to_le_bytes());
        assert_eq!(&front[58..], &hex("03000000 00ff41 00 f9ff"));
        assert_eq!(MPoolOp::decode(4, &front, &[], &[]).unwrap(), m);
    }
    assert!(PoolOperation::try_from(0).is_err());
    assert!(PoolOperation::try_from(3).is_err());
    assert!(PoolOperation::try_from(u32::MAX).is_err());
}
#[test]
fn malformed_lengths_headers_bool_segments_and_trailing_bytes_fail_without_panics() {
    let valid = request().encode(0).unwrap().front;
    for n in 0..valid.len() {
        assert!(MPoolOp::decode(4, &valid[..n], &[], &[]).is_err());
    }
    for v in [0, 1, 2, 3, 5] {
        assert!(MPoolOp::decode(v, &valid, &[], &[]).is_err());
    }
    let mut bad = valid.clone();
    bad[38..42].copy_from_slice(&3u32.to_le_bytes());
    assert!(MPoolOp::decode(4, &bad, &[], &[]).is_err());
    let mut bad = valid.clone();
    bad[58..62].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(MPoolOp::decode(4, &bad, &[], &[]).is_err());
    let mut bad = valid.clone();
    bad.push(0);
    assert!(MPoolOp::decode(4, &bad, &[], &[]).is_err());
    assert!(MPoolOp::decode(4, &valid, &[1], &[]).is_err());
    assert!(MPoolOp::decode(4, &valid, &[], &[1]).is_err());
    let valid = MPoolOpReply {
        version: 1,
        fsid: fsid(),
        result: -13,
        epoch: 2,
        response_data: vec![42],
    }
    .encode(0)
    .unwrap()
    .front;
    for n in 0..valid.len() {
        assert!(MPoolOpReply::decode(1, &valid[..n], &[], &[]).is_err());
    }
    for v in [0, 2] {
        assert!(MPoolOpReply::decode(v, &valid, &[], &[]).is_err());
    }
    let mut bad = valid.clone();
    bad[42] = 2;
    assert!(MPoolOpReply::decode(1, &bad, &[], &[]).is_err());
    let mut bad = valid.clone();
    bad[43..47].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(MPoolOpReply::decode(1, &bad, &[], &[]).is_err());
    let mut bad = valid.clone();
    bad.push(0);
    assert!(MPoolOpReply::decode(1, &bad, &[], &[]).is_err());
    assert!(MPoolOpReply::decode(1, &valid, &[1], &[]).is_err());
    assert!(MPoolOpReply::decode(1, &valid, &[], &[1]).is_err());
}

#[test]
fn snapshot_messages_pass_header_compatibility_dispatch_and_reject_too_new_compat() {
    // Literal wire facts, independent of the registry and codec metadata.
    let vectors = [
        (
            49,
            4,
            2,
            hex(
                "0807060504030201 ffff 0000000000000000 000102030405060708090a0b0c0d0e0f 44332211 21000000 0000000000000000 0000000000000000 00000000 00 0000",
            ),
        ),
        (
            48,
            1,
            0,
            hex(
                "0900000000000000 ffff 0000000000000000 000102030405060708090a0b0c0d0e0f 00000000 44332211 01 08000000 efcdab8967452301",
            ),
        ),
    ];
    for (ty, version, compat_version, front) in vectors {
        let mut header = messages::Header2 {
            ty,
            version,
            compat_version,
            ..Default::default()
        };
        let decoded = messages::decode_with_header(&header, &front, &[], &[]).unwrap();
        assert!(matches!(
            (ty, decoded),
            (49, AnyMessage::MPoolOp(_)) | (48, AnyMessage::MPoolOpReply(_))
        ));
        header.compat_version = version + 1;
        assert!(matches!(
            messages::decode_with_header(&header, &front, &[], &[]),
            Err(denc::Error::CompatTooNew { .. })
        ));
    }
}

#[test]
fn pool_admin_fronts_match_frozen_vectors() {
    for (rule, suffix) in [(-1, "ffff"), (0, "0000"), (255, "ff00")] {
        let m = MPoolOp {
            pool: 0,
            operation: PoolOperation::CreatePool,
            name: b"pool".to_vec(),
            crush_rule: rule,
            ..request()
        };
        let expected = hex(&format!(
            "0807060504030201 ffff 0000000000000000 000102030405060708090a0b0c0d0e0f 00000000 01000000 0000000000000000 0000000000000000 04000000 706f6f6c 00 {suffix}"
        ));
        assert_eq!(m.encode(0).unwrap().front, expected);
        assert_eq!(MPoolOp::decode(4, &expected, &[], &[]).unwrap(), m);
    }
    let m = MPoolOp {
        pool: 7,
        operation: PoolOperation::DeletePool,
        ..request()
    };
    let expected = hex(
        "0807060504030201 ffff 0000000000000000 000102030405060708090a0b0c0d0e0f 07000000 02000000 0000000000000000 0000000000000000 00000000 00 0000",
    );
    assert_eq!(m.encode(0).unwrap().front, expected);
    assert_eq!(MPoolOp::decode(4, &expected, &[], &[]).unwrap(), m);
}
