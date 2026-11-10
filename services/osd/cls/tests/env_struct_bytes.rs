// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Byte layout of the structs declared with `env_struct!`: envelope (v, compat, u32 body length)
//! and the fields in declaration order, built here by hand and compared with encode and decode.
//! (LockerInfo / LockInfo / ImageMap: ceph-dencoder vectors in golden.rs.)

use cls::cas::CreateOrGetRefOp;
use cls::otp::OtpCheck;
use cls::rbd::types_group::{GroupImageSpec, GroupImageStatus, GroupSnapshot, ImageSnapshotSpec};
use cls::rgw_gc::UrgentData;
use denc::types::{Hobject, UTime};
use denc::{Decode, Decoder, Encode};
use std::collections::BTreeMap;

fn env(v: u8, c: u8, body: &[u8]) -> Vec<u8> {
    let mut o = vec![v, c];
    o.extend((body.len() as u32).to_le_bytes());
    o.extend(body);
    o
}
fn bytes(b: &[u8]) -> Vec<u8> {
    let mut o = (b.len() as u32).to_le_bytes().to_vec();
    o.extend(b);
    o
}
fn utime(s: u32, ns: u32) -> Vec<u8> {
    [s.to_le_bytes(), ns.to_le_bytes()].concat()
}
fn check<T: Encode + for<'a> Decode<'a> + PartialEq + std::fmt::Debug>(v: &T, want: &[u8]) {
    assert_eq!(v.encode_to_vec().unwrap(), want);
    assert_eq!(&T::decode(&mut Decoder::new(want)).unwrap(), v);
}

#[test]
fn otp_check() {
    let v = OtpCheck {
        token: b"tok".to_vec(),
        timestamp: UTime { sec: 7, nsec: 9 },
        result: 2,
    };
    check(
        &v,
        &env(1, 1, &[bytes(b"tok"), utime(7, 9), vec![2]].concat()),
    );
}

#[test]
fn cas_create_or_get_ref_op() {
    let source = Hobject::default();
    let v = CreateOrGetRefOp {
        source: source.clone(),
        flags: 0x0102_0304_0506_0708,
        data: b"d".to_vec(),
    };
    let body = [
        source.encode_to_vec().unwrap(),
        0x0102_0304_0506_0708u64.to_le_bytes().to_vec(),
        bytes(b"d"),
    ]
    .concat();
    check(&v, &env(1, 1, &body));
}

#[test]
fn rgw_gc_urgent_data() {
    let v = UrgentData {
        urgent_data_map: BTreeMap::from([(b"t".to_vec(), UTime { sec: 1, nsec: 2 })]),
        num_urgent_data_entries: 3,
        num_head_urgent_entries: 4,
        num_xattr_urgent_entries: 5,
    };
    let body = [
        1u32.to_le_bytes().to_vec(),
        bytes(b"t"),
        utime(1, 2),
        3u32.to_le_bytes().to_vec(),
        4u32.to_le_bytes().to_vec(),
        5u32.to_le_bytes().to_vec(),
    ]
    .concat();
    check(&v, &env(1, 1, &body));
}

#[test]
fn rbd_group_types() {
    let spec = GroupImageSpec {
        image_id: b"img".to_vec(),
        pool_id: -3,
    };
    let spec_b = env(
        1,
        1,
        &[bytes(b"img"), (-3i64).to_le_bytes().to_vec()].concat(),
    );
    let st = GroupImageStatus {
        spec: spec.clone(),
        state: 1,
    };
    check(&st, &env(1, 1, &[spec_b.clone(), vec![1]].concat()));

    let snap = ImageSnapshotSpec {
        pool: 5,
        image_id: b"i".to_vec(),
        snap_id: 6,
    };
    let snap_b = env(
        1,
        1,
        &[
            5i64.to_le_bytes().to_vec(),
            bytes(b"i"),
            6u64.to_le_bytes().to_vec(),
        ]
        .concat(),
    );
    check(&snap, &snap_b);

    let g = GroupSnapshot {
        id: b"id".to_vec(),
        name: b"nm".to_vec(),
        state: 1,
        snaps: vec![snap],
    };
    let body = [
        bytes(b"id"),
        bytes(b"nm"),
        vec![1],
        1u32.to_le_bytes().to_vec(),
        snap_b,
    ]
    .concat();
    check(&g, &env(1, 1, &body));
}
