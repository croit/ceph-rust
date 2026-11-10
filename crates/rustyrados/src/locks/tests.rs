// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::*;
use denc::types::{EntityAddr, UTime};

fn target() -> Target {
    Target {
        pool: 1,
        namespace: vec![],
        locator: vec![],
        object: b"lock-test".to_vec(),
    }
}
fn acquire(kind: LockKind, renew: LockRenew) -> LockOperation {
    LockOperation::Acquire {
        name: b"n".to_vec(),
        kind,
        cookie: b"c".to_vec(),
        tag: vec![0xff, 0],
        description: b"d".to_vec(),
        duration: Duration::new(2, 3),
        renew,
    }
}
#[test]
fn literal_acquire_all_kinds_and_renew_flags() {
    for kind in [
        LockKind::Exclusive,
        LockKind::Shared,
        LockKind::ExclusiveEphemeral,
    ] {
        for renew in [LockRenew::New, LockRenew::May, LockRenew::Must] {
            let operation = acquire(kind, renew);
            let call = operation.build(45).unwrap();
            assert_eq!(call.required_access(), Access::ReadWrite);
            assert_eq!(call.reply_kind(), LockReplyKind::Empty);
            let op = call.into_op();
            let mut literal = b"locklock\x01\x01\x1f\0\0\0\x01\0\0\0n".to_vec();
            literal.push(kind as u8);
            literal
                .extend_from_slice(b"\x01\0\0\0c\x02\0\0\0\xff\0\x01\0\0\0d\x02\0\0\0\x03\0\0\0");
            literal.push(renew as u8);
            assert_eq!(&op.indata[..], literal);
            assert_eq!(op.cls().indata_len, 37);
            assert_eq!(operation.build(44).unwrap_err(), LockBuildError::InputLimit);
            assert_eq!(operation, acquire(kind, renew));
        }
    }
}
#[test]
fn literal_remaining_methods_and_access() {
    use LockOperation::*;
    type Row<'a> = (LockOperation, &'a [u8], &'a [u8], Access, LockReplyKind);
    let rows: Vec<Row<'_>> = vec![
        (
            Unlock {
                name: b"n".to_vec(),
                cookie: b"c".to_vec(),
            },
            b"unlock",
            b"\x01\x01\x0a\0\0\0\x01\0\0\0n\x01\0\0\0c",
            Access::ReadWrite,
            LockReplyKind::Empty,
        ),
        (
            Break {
                name: b"n".to_vec(),
                locker: EntityName::client(-2),
                cookie: b"c".to_vec(),
            },
            b"break_lock",
            b"\x01\x01\x13\0\0\0\x01\0\0\0n\x08\xfe\xff\xff\xff\xff\xff\xff\xff\x01\0\0\0c",
            Access::ReadWrite,
            LockReplyKind::Empty,
        ),
        (
            GetInfo {
                name: vec![0xff, 0],
            },
            b"get_info",
            b"\x01\x01\x06\0\0\0\x02\0\0\0\xff\0",
            Access::Read,
            LockReplyKind::Info,
        ),
        (List, b"list_locks", b"", Access::Read, LockReplyKind::Names),
        (
            Assert {
                name: b"n".to_vec(),
                kind: LockKind::Shared,
                cookie: b"c".to_vec(),
                tag: b"t".to_vec(),
            },
            b"assert_locked",
            b"\x01\x01\x10\0\0\0\x01\0\0\0n\x02\x01\0\0\0c\x01\0\0\0t",
            Access::Read,
            LockReplyKind::Empty,
        ),
        (
            SetCookie {
                name: b"n".to_vec(),
                kind: LockKind::Shared,
                cookie: b"c".to_vec(),
                tag: b"t".to_vec(),
                new_cookie: b"x".to_vec(),
            },
            b"set_cookie",
            b"\x01\x01\x15\0\0\0\x01\0\0\0n\x02\x01\0\0\0c\x01\0\0\0t\x01\0\0\0x",
            Access::ReadWrite,
            LockReplyKind::Empty,
        ),
    ];
    for (operation, method, input, access, reply) in rows {
        let call = operation.build(1024).unwrap();
        assert_eq!(call.required_access(), access);
        assert_eq!(call.reply_kind(), reply);
        let request = call.into_compound(target(), 1024);
        request.validate().unwrap();
        let wire = request.operations[0].cls_call().unwrap();
        assert_eq!(wire.class, b"lock");
        assert_eq!(wire.method, method);
        assert_eq!(wire.input, input);
        let size = request.operations[0].indata.len();
        operation.build(size).unwrap();
        assert_eq!(
            operation.build(size - 1).unwrap_err(),
            LockBuildError::InputLimit
        );
    }
}

#[test]
fn invalid_builder_keeps_original_fields_and_capacities() {
    let mut operation = acquire(LockKind::Exclusive, LockRenew::New);
    if let LockOperation::Acquire { name, .. } = &mut operation {
        name.clear();
        name.reserve(90);
    }
    let saved = operation.clone();
    let (pointer, capacity) = match &operation {
        LockOperation::Acquire { name, .. } => (name.as_ptr(), name.capacity()),
        _ => unreachable!(),
    };
    assert_eq!(
        operation.build(1024).unwrap_err(),
        LockBuildError::EmptyName
    );
    assert_eq!(operation, saved);
    if let LockOperation::Acquire { name, duration, .. } = &mut operation {
        assert_eq!((name.as_ptr(), name.capacity()), (pointer, capacity));
        name.push(b'n');
        *duration = Duration::from_secs(u64::from(u32::MAX) + 1);
    }
    assert_eq!(
        operation.build(1024).unwrap_err(),
        LockBuildError::DurationOverflow
    );
    if let LockOperation::Acquire { duration, .. } = &mut operation {
        *duration = Duration::new(u64::from(u32::MAX), 999_999_999);
    }
    operation.build(1024).unwrap();
    LockOperation::GetInfo { name: vec![] }.build(1024).unwrap();
    LockOperation::Unlock {
        name: vec![],
        cookie: vec![],
    }
    .build(1024)
    .unwrap();
}

#[test]
fn reader_allowlist_is_exact_and_mutators_need_both_access_bits() {
    for class in [b"lock".as_slice(), b"Lock", b"lock\0", b"hello"] {
        for method in [
            b"get_info".as_slice(),
            b"list_locks",
            b"assert_locked",
            b"lock",
            b"unlock",
            b"break_lock",
            b"set_cookie",
            b"GET_INFO",
            b"get_info\0",
            b"unknown",
        ] {
            for access in [Access::Read, Access::Write, Access::ReadWrite] {
                let mut request = LockOperation::List
                    .build(64)
                    .unwrap()
                    .into_compound(target(), 64);
                request.access = access;
                request.operations = vec![OsdOp::call(class, method, b"")];
                let allowed = access == Access::ReadWrite
                    || (access == Access::Read
                        && class == b"lock"
                        && matches!(method, b"get_info" | b"list_locks" | b"assert_locked"));
                assert_eq!(
                    request.validate().is_ok(),
                    allowed,
                    "{class:?}.{method:?} {access:?}"
                );
            }
        }
    }
}

const LIMITS: LockDecodeLimits = LockDecodeLimits {
    bytes: 4096,
    entries: 4,
};
fn decode(kind: LockReplyKind, data: Bytes) -> LockReply {
    LockReply::decode(kind, 0, 0, data, LIMITS).unwrap()
}
fn names() -> Bytes {
    // ENV1 { count2, bytes[00,ff], bytes[ff,00] }
    Bytes::from_static(b"\x01\x01\x10\0\0\0\x02\0\0\0\x02\0\0\0\0\xff\x02\0\0\0\xff\0")
}
fn info() -> Bytes {
    // ENV1: one client.7/cookie[ff,00], sec3/nsec4, ADDR2 legacy IPv4,
    // nonce9, port1234, 127.0.0.1, description[fe,00], raw storedkind9/tag[80,00].
    Bytes::from_static(b"\x01\x01\x57\0\0\0\x01\0\0\0\x01\x01\x0f\0\0\0\x08\x07\0\0\0\0\0\0\0\x02\0\0\0\xff\0\x01\x01\x31\0\0\0\x03\0\0\0\x04\0\0\0\x01\x01\x01\x1c\0\0\0\x01\0\0\0\x09\0\0\0\x10\0\0\0\x02\0\x04\xd2\x7f\0\0\x01\0\0\0\0\0\0\0\0\x02\0\0\0\xfe\0\x09\x02\0\0\0\x80\0")
}
#[test]
fn names_binary_zero_copy_exact_iterator() {
    let bytes = names();
    let pointer = bytes.as_ptr();
    let LockReply::Names(view) = decode(LockReplyKind::Names, bytes) else {
        panic!()
    };
    let mut it = view.entries();
    assert_eq!(it.len(), 2);
    let first = it.next().unwrap();
    assert_eq!(first, b"\0\xff");
    assert_eq!(first.as_ptr(), pointer.wrapping_add(14));
    assert_eq!(it.len(), 1);
    assert_eq!(it.next(), Some(b"\xff\0".as_slice()));
    assert_eq!(it.next(), None);
    assert_eq!(it.next(), None);
}
#[test]
fn info_binary_zero_copy_metadata_and_raw_stored_kind() {
    let bytes = info();
    let pointer = bytes.as_ptr();
    let LockReply::Info(view) = decode(LockReplyKind::Info, bytes) else {
        panic!()
    };
    assert_eq!(view.stored_kind(), 9);
    assert_eq!(view.tag(), b"\x80\0");
    assert_eq!(view.tag().as_ptr(), pointer.wrapping_add(91));
    let mut it = view.entries();
    assert_eq!(it.len(), 1);
    let item = it.next().unwrap();
    assert_eq!(item.locker, EntityName::client(7));
    assert_eq!(item.cookie, b"\xff\0");
    assert_eq!(item.cookie.as_ptr(), pointer.wrapping_add(29));
    assert_eq!(item.expiration, UTime::new(3, 4));
    assert_eq!(
        item.address,
        EntityAddr::v4(EntityAddr::TYPE_LEGACY, 9, [127, 0, 0, 1], 1234)
    );
    assert_eq!(item.description, b"\xfe\0");
    assert_eq!(it.next(), None);
}
#[test]
fn statuses_caps_and_malformed_replies_retain_original_owned_data() {
    for (result, op_result) in [(-1, 0), (0, -16), (-2, -1), (-1, 7)] {
        let data = Bytes::from(vec![0xff, 0]);
        let ptr = data.as_ptr();
        let LockReply::Remote {
            result: got,
            op_result: op,
            data,
        } = LockReply::decode(LockReplyKind::Info, result, op_result, data, LIMITS).unwrap()
        else {
            panic!()
        };
        assert_eq!((got, op), (result, op_result));
        assert_eq!(ptr, data.as_ptr());
    }
    for (kind, result, op_result, data, limits, expected) in [
        (
            LockReplyKind::Names,
            0,
            0,
            names(),
            LockDecodeLimits {
                entries: 1,
                ..LIMITS
            },
            LockDecodeError::EntryLimit,
        ),
        (
            LockReplyKind::Info,
            -1,
            0,
            info(),
            LockDecodeLimits { bytes: 1, ..LIMITS },
            LockDecodeError::ByteLimit,
        ),
        (
            LockReplyKind::Empty,
            1,
            0,
            Bytes::new(),
            LIMITS,
            LockDecodeError::PositiveResult,
        ),
        (
            LockReplyKind::Empty,
            0,
            1,
            Bytes::new(),
            LIMITS,
            LockDecodeError::PositiveResult,
        ),
    ] {
        let ptr = data.as_ptr();
        let err = LockReply::decode(kind, result, op_result, data, limits).unwrap_err();
        assert_eq!(err.reason, expected);
        assert_eq!(err.data.as_ptr(), ptr);
    }
    for valid in [names(), info()] {
        let kind = if valid == names() {
            LockReplyKind::Names
        } else {
            LockReplyKind::Info
        };
        for cut in 0..valid.len() {
            let data = Bytes::copy_from_slice(&valid[..cut]);
            let ptr = data.as_ptr();
            let err = LockReply::decode(kind, 0, 0, data, LIMITS).unwrap_err();
            assert_eq!(err.data.as_ptr(), ptr);
        }
        // Version 2 is accepted (a newer envelope); compat 2 is malformed.
        let mut newer = valid.to_vec();
        newer[0] = 2;
        assert!(LockReply::decode(kind, 0, 0, newer.into(), LIMITS).is_ok());
        let mut incompatible = valid.to_vec();
        incompatible[1] = 2;
        assert!(LockReply::decode(kind, 0, 0, incompatible.into(), LIMITS).is_err());
        // Bytes after the reply are ignored (stock acceptance).
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert!(LockReply::decode(kind, 0, 0, trailing.into(), LIMITS).is_ok());
    }
    assert!(matches!(
        decode(LockReplyKind::Empty, Bytes::new()),
        LockReply::Empty
    ));
    assert!(
        LockReply::decode(LockReplyKind::Empty, 0, 0, Bytes::from_static(b"x"), LIMITS).is_err()
    );
    for (kind, data) in [
        (
            LockReplyKind::Names,
            Bytes::from_static(b"\x01\x01\x04\0\0\0\0\0\0\0"),
        ),
        (
            LockReplyKind::Info,
            Bytes::from_static(b"\x01\x01\x09\0\0\0\0\0\0\0\x02\0\0\0\0"),
        ),
    ] {
        LockReply::decode(
            kind,
            0,
            0,
            data,
            LockDecodeLimits {
                entries: 0,
                ..LIMITS
            },
        )
        .unwrap();
    }
}
#[test]
fn duplicate_and_unsorted_keys_follow_the_stock_rules() {
    // A std::list keeps duplicate names in reply order.
    let mut duplicate = names().to_vec();
    duplicate[20..22].copy_from_slice(b"\0\xff");
    let LockReply::Names(view) = decode(LockReplyKind::Names, duplicate.into()) else {
        panic!()
    };
    assert_eq!(
        view.entries().collect::<Vec<_>>(),
        vec![b"\0\xff".as_slice(), b"\0\xff".as_slice()]
    );
    let mut reversed = names().to_vec();
    reversed[14..16].copy_from_slice(b"\xff\xff");
    let LockReply::Names(view) = decode(LockReplyKind::Names, reversed.into()) else {
        panic!()
    };
    assert_eq!(
        view.entries().collect::<Vec<_>>(),
        vec![b"\xff\xff".as_slice(), b"\xff\0".as_slice()]
    );

    let original = info();
    let mut two = original[..86].to_vec();
    two.extend_from_slice(&original[10..86]);
    two.extend_from_slice(&original[86..]);
    two[2..6].copy_from_slice(&163u32.to_le_bytes());
    two[6..10].copy_from_slice(&2u32.to_le_bytes());
    // The second record repeats the key and carries the later description.
    two[160] = 0xaa;
    let LockReply::Info(view) = decode(LockReplyKind::Info, two.clone().into()) else {
        panic!()
    };
    assert_eq!(view.entries().len(), 1);
    assert_eq!(view.entries().next().unwrap().description, b"\xaa\0");
    // A lower entity number in the second record is accepted and sorts first.
    two[93..101].copy_from_slice(&3i64.to_le_bytes());
    let LockReply::Info(view) = decode(LockReplyKind::Info, two.into()) else {
        panic!()
    };
    assert_eq!(
        view.entries().map(|entry| entry.locker).collect::<Vec<_>>(),
        vec![EntityName::client(3), EntityName::client(7)]
    );
}

#[test]
fn sorted_multiple_holders_validate_and_preserve_each_binary_identity() {
    let original = info();
    let mut two = original[..86].to_vec();
    two.extend_from_slice(&original[10..86]);
    two.extend_from_slice(&original[86..]);
    two[2..6].copy_from_slice(&163u32.to_le_bytes());
    two[6..10].copy_from_slice(&2u32.to_le_bytes());
    // Same entity; cookie ff01 follows ff00.
    two[106] = 1;
    let LockReply::Info(view) = decode(LockReplyKind::Info, two.into()) else {
        panic!()
    };
    assert_eq!(
        view.entries().map(|e| e.cookie).collect::<Vec<_>>(),
        vec![b"\xff\0".as_slice(), b"\xff\x01".as_slice()]
    );
}
#[test]
fn legacy_address_and_enormous_record_counts_remain_bounded() {
    // Same independent holder fields, encoded with the supported legacy address form.
    let modern = info();
    let mut bytes = modern[..45].to_vec();
    // Legacy marker is the low byte of a zero u32; nonce then 128-byte sockaddr.
    bytes.extend_from_slice(&[0, 0, 0, 0, 9, 0, 0, 0]);
    let mut sockaddr = [0u8; 128];
    sockaddr[..8].copy_from_slice(&[0, 2, 4, 0xd2, 127, 0, 0, 1]);
    bytes.extend_from_slice(&sockaddr);
    bytes.extend_from_slice(&modern[80..]);
    let body = (bytes.len() - 6) as u32;
    bytes[2..6].copy_from_slice(&body.to_le_bytes());
    bytes[33..37].copy_from_slice(&150u32.to_le_bytes());
    let LockReply::Info(view) = decode(LockReplyKind::Info, bytes.into()) else {
        panic!()
    };
    assert_eq!(
        view.entries().next().unwrap().address,
        EntityAddr::v4(EntityAddr::TYPE_LEGACY, 9, [127, 0, 0, 1], 1234)
    );
    for kind in [LockReplyKind::Info, LockReplyKind::Names] {
        let data = Bytes::from_static(b"\x01\x01\x04\0\0\0\xff\xff\xff\xff");
        assert_eq!(
            LockReply::decode(kind, 0, 0, data.clone(), LIMITS)
                .unwrap_err()
                .reason,
            LockDecodeError::EntryLimit
        );
        assert!(matches!(
            LockReply::decode(
                kind,
                0,
                0,
                data,
                LockDecodeLimits {
                    entries: u32::MAX,
                    ..LIMITS
                }
            )
            .unwrap_err()
            .reason,
            LockDecodeError::Malformed(_)
        ));
    }
}
