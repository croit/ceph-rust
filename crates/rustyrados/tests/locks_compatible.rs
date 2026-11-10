// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// Authors: Martin Verges, croit GmbH.

use denc::{Decode, types::EntityName};
use rustyrados::{
    Access, CompatibleLockOperation as Compatible, LockBuildError, LockDecodeLimits, LockKind,
    LockOperation, LockRenew, LockReply, LockReplyKind,
};
use std::time::Duration;

fn acquire(seconds: u32, nanoseconds: u32, flags: u8) -> Compatible {
    Compatible::Acquire {
        name: vec![],
        kind: LockKind::Shared,
        cookie: vec![],
        tag: vec![],
        description: vec![],
        seconds,
        nanoseconds,
        flags,
    }
}

#[test]
fn empty_acquire_all_flag_bytes_and_independent_raw_time_words() {
    // Own literal: four empty counted strings, Shared, two raw words and flags.
    for (seconds, nanoseconds) in [(0u32, 0u32), (u32::MAX, u32::MAX), (0, 1_000_000_000)] {
        for flags in 0..=u8::MAX {
            let operation = acquire(seconds, nanoseconds, flags);
            let call = operation.clone().build(40).unwrap();
            assert_eq!(call.required_access(), Access::ReadWrite);
            assert_eq!(call.reply_kind(), LockReplyKind::Empty);
            let op = call.into_op();
            let mut expected =
                b"locklock\x01\x01\x1a\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0".to_vec();
            expected.extend_from_slice(&seconds.to_le_bytes());
            expected.extend_from_slice(&nanoseconds.to_le_bytes());
            expected.push(flags);
            assert_eq!(&op.indata[..], expected);
            assert_eq!(op.cls().indata_len, 32);
            assert_eq!(operation.build(39).unwrap_err(), LockBuildError::InputLimit);
        }
    }
}

#[test]
fn empty_removal_and_info_names_are_not_acquire_validation() {
    for (operation, expected, access, reply) in [
        (
            Compatible::Unlock {
                name: vec![],
                cookie: vec![],
            },
            b"lockunlock\x01\x01\x08\0\0\0\0\0\0\0\0\0\0\0".as_slice(),
            Access::ReadWrite,
            LockReplyKind::Empty,
        ),
        (
            Compatible::Break {
                name: vec![],
                locker: EntityName::client(-1),
                cookie: vec![],
            },
            b"lockbreak_lock\x01\x01\x11\0\0\0\0\0\0\0\x08\xff\xff\xff\xff\xff\xff\xff\xff\0\0\0\0"
                .as_slice(),
            Access::ReadWrite,
            LockReplyKind::Empty,
        ),
        (
            Compatible::GetInfo { name: vec![] },
            b"lockget_info\x01\x01\x04\0\0\0\0\0\0\0".as_slice(),
            Access::Read,
            LockReplyKind::Info,
        ),
    ] {
        let call = operation.clone().build(expected.len()).unwrap();
        assert_eq!(call.required_access(), access);
        assert_eq!(call.reply_kind(), reply);
        assert_eq!(&call.into_op().indata[..], expected);
        assert_eq!(
            operation.build(expected.len() - 1).unwrap_err(),
            LockBuildError::InputLimit
        );
    }
}

#[test]
fn native_validation_and_source_values_are_unchanged() {
    let mut operation = LockOperation::Acquire {
        name: vec![],
        kind: LockKind::Exclusive,
        cookie: vec![],
        tag: vec![],
        description: vec![],
        duration: Duration::ZERO,
        renew: LockRenew::New,
    };
    let before = operation.clone();
    assert_eq!(
        operation.build(usize::MAX).unwrap_err(),
        LockBuildError::EmptyName
    );
    assert_eq!(operation, before);
    if let LockOperation::Acquire { name, duration, .. } = &mut operation {
        *name = b"n".to_vec();
        *duration = Duration::from_secs(u64::from(u32::MAX) + 1);
    }
    let before = operation.clone();
    assert_eq!(
        operation.build(usize::MAX).unwrap_err(),
        LockBuildError::DurationOverflow
    );
    assert_eq!(operation, before);
    for renew in [LockRenew::New, LockRenew::May, LockRenew::Must] {
        if let LockOperation::Acquire {
            duration,
            renew: value,
            ..
        } = &mut operation
        {
            *duration = Duration::new(2, 3);
            *value = renew;
        }
        let compatible = Compatible::Acquire {
            name: b"n".to_vec(),
            kind: LockKind::Exclusive,
            cookie: vec![],
            tag: vec![],
            description: vec![],
            seconds: 2,
            nanoseconds: 3,
            flags: renew as u8,
        };
        assert_eq!(
            operation.build(41).unwrap().into_op(),
            compatible.build(41).unwrap().into_op()
        );
    }
}

#[test]
fn counted_binary_fields_are_borrowed_until_encoding_then_independently_owned() {
    let expected = [
        b"n\0tail".as_slice(),
        b"\0cookie",
        b"\xff\0tag",
        b"\0description",
    ];
    let mut source = expected.map(<[u8]>::to_vec);
    // Bare Compatible still selects Vec<u8> for existing owned callers.
    let owned: Compatible = Compatible::Acquire {
        name: source[0].clone(),
        kind: LockKind::Shared,
        cookie: source[1].clone(),
        tag: source[2].clone(),
        description: source[3].clone(),
        seconds: 0,
        nanoseconds: u32::MAX,
        flags: 255,
    };
    let operation = Compatible::Acquire {
        name: source[0].as_slice(),
        kind: LockKind::Shared,
        cookie: source[1].as_slice(),
        tag: source[2].as_slice(),
        description: source[3].as_slice(),
        seconds: 0,
        nanoseconds: u32::MAX,
        flags: 255,
    };
    let total = 40 + expected.iter().map(|field| field.len()).sum::<usize>();
    assert_eq!(
        operation.clone().build(total - 1).unwrap_err(),
        LockBuildError::InputLimit
    );
    assert_eq!(source, expected.map(<[u8]>::to_vec));
    let op = operation.build(total).unwrap().into_op();
    assert_eq!(op, owned.build(total).unwrap().into_op());
    for field in &mut source {
        field.fill(0xa5);
    }
    drop(source);
    let mut input = denc::Decoder::new(&op.indata[8..]);
    input
        .versioned_min(1, 1, |d, _| {
            assert_eq!(d.bytes()?, expected[0]);
            assert_eq!(d.u8()?, 2);
            for field in &expected[1..] {
                assert_eq!(d.bytes()?, *field);
            }
            assert_eq!(d.u32()?, 0);
            assert_eq!(d.u32()?, u32::MAX);
            assert_eq!(d.u8()?, 255);
            assert!(d.is_empty());
            Ok(())
        })
        .unwrap();
    assert!(input.is_empty());
}

#[test]
fn borrowed_removal_and_info_requests_outlive_binary_caller_storage() {
    let mut name = b"n\0tail".to_vec();
    let mut cookie = b"\xff\0cookie".to_vec();
    let operations = [
        Compatible::Unlock {
            name: name.as_slice(),
            cookie: cookie.as_slice(),
        },
        Compatible::Break {
            name: name.as_slice(),
            locker: EntityName::client(i64::MAX),
            cookie: cookie.as_slice(),
        },
        Compatible::GetInfo {
            name: name.as_slice(),
        },
    ]
    .map(|operation| {
        let encoded = operation.clone().build(128).unwrap().into_op();
        assert_eq!(
            operation.build(encoded.indata.len() - 1).unwrap_err(),
            LockBuildError::InputLimit
        );
        encoded
    });
    name.fill(0xa5);
    cookie.fill(0x5a);
    drop(name);
    drop(cookie);
    for (index, op) in operations.iter().enumerate() {
        let offset = usize::from(op.cls().class_len) + usize::from(op.cls().method_len);
        let mut input = denc::Decoder::new(&op.indata[offset..]);
        input
            .versioned_min(1, 1, |d, _| {
                assert_eq!(d.bytes()?, b"n\0tail");
                if index == 1 {
                    assert_eq!(EntityName::decode(d)?, EntityName::client(i64::MAX));
                }
                if index != 2 {
                    assert_eq!(d.bytes()?, b"\xff\0cookie");
                }
                assert!(d.is_empty());
                Ok(())
            })
            .unwrap();
        assert!(input.is_empty());
    }
}

#[test]
fn server_errors_keep_both_statuses_and_reply_ownership() {
    for kind in [LockReplyKind::Empty, LockReplyKind::Info] {
        for (result, op_result) in [(-22, 0), (0, -2), (-5, -1)] {
            let data = bytes::Bytes::from(vec![255, 0, 17]);
            let pointer = data.as_ptr();
            let reply = LockReply::decode(
                kind,
                result,
                op_result,
                data,
                LockDecodeLimits {
                    bytes: 3,
                    entries: 0,
                },
            )
            .unwrap();
            match reply {
                LockReply::Remote {
                    result: actual,
                    op_result: actual_op,
                    data,
                } => {
                    assert_eq!((actual, actual_op), (result, op_result));
                    assert_eq!(data.as_ptr(), pointer);
                    assert_eq!(&data[..], &[255, 0, 17]);
                }
                _ => panic!("remote error was decoded as success"),
            }
        }
    }
    let data = bytes::Bytes::from_static(b"\x01\x01\x09\0\0\0\0\0\0\0\0\0\0\0\0");
    match LockReply::decode(
        LockReplyKind::Info,
        0,
        0,
        data.clone(),
        LockDecodeLimits {
            bytes: data.len(),
            entries: 0,
        },
    )
    .unwrap()
    {
        LockReply::Info(info) => {
            assert_eq!(info.entries().len(), 0);
            assert_eq!(info.stored_kind(), 0);
            assert!(info.tag().is_empty());
        }
        _ => panic!("empty successful info lost"),
    }
}
