// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Data-object methods (cls_rbd.md C.2) and their header reads (A.5) on MemStore.
mod common;
use cls::ClsCtx;
use cls::errno::*;
use cls::mem::MemStore;
use common::*;

const O: &str = "rbd_data.10abcdef.0000000000000000";
const HDR: &str = "rbd_header.10abcdef";

fn sparsify_input(sparse: u64, remove_empty: bool) -> Vec<u8> {
    [sparse.to_le_bytes().as_slice(), &[u8::from(remove_empty)]].concat()
}

/// Header with the given features, `order` 22, created like librbd does (spec A.5 `create`).
fn header(st: &mut MemStore, features: u64) {
    let create = cat(&[&u64b(4096), &[22], &u64b(features), &e("rbd_data.10abcdef")]);
    ok(st, HDR, "rbd", "create", &create);
}

#[test]
fn sparsify_all_zero_truncates_the_stat_size_not_the_clipped_read() {
    let mut s = MemStore::new();
    // One message: grow the (absent) object to 4096, then sparsify. The committed read is empty
    // (message-start content), the stat size is 4096: spec C.2 truncates on the size.
    let (ret, _) = s.msg(O, |c| {
        c.truncate(4096).unwrap();
        (
            c.call("rbd", "sparsify", &sparsify_input(4096, false)).ret,
            (),
        )
    });
    assert_eq!(ret, 0);
    assert_eq!(
        s.obj(O).unwrap().data.len(),
        0,
        "all-zero object with size > 0 must end up empty"
    );
}

#[test]
fn sparsify_all_zero_committed_object_and_absent_object() {
    let mut s = MemStore::new();
    // absent object: -ENOENT (stat first)
    err(
        &mut s,
        O,
        "rbd",
        "sparsify",
        &sparsify_input(4096, false),
        ENOENT,
    );
    // committed all-zero object: truncated to 0
    s.msg(O, |c| {
        c.write_full(&vec![0u8; 4096]).unwrap();
        (0, ())
    });
    ok(&mut s, O, "rbd", "sparsify", &sparsify_input(4096, false));
    assert_eq!(s.obj(O).unwrap().data.len(), 0);
    // empty object (size 0): nothing to do, and no write is issued
    s.msg(O, |c| {
        c.write_full(b"").unwrap();
        (0, ())
    });
    ok(&mut s, O, "rbd", "sparsify", &sparsify_input(4096, false));
    assert_eq!(s.obj(O).unwrap().data.len(), 0);
    // remove_empty on an all-zero object deletes it
    s.msg(O, |c| {
        c.write_full(&[0u8; 16]).unwrap();
        (0, ())
    });
    ok(&mut s, O, "rbd", "sparsify", &sparsify_input(4096, true));
    assert!(s.obj(O).is_none());
}

#[test]
fn sparsify_keeps_runs_and_drops_trailing_zero_chunks() {
    let mut s = MemStore::new();
    // 3 chunks of 4 bytes: zero, data, zero -> the zero run is replaced at its offset (hole), the
    // trailing zero chunk is dropped, so the object is the leading hole + the data run
    s.msg(O, |c| {
        c.write_full(&[0, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0]).unwrap();
        (0, ())
    });
    ok(&mut s, O, "rbd", "sparsify", &sparsify_input(4, false));
    assert_eq!(s.obj(O).unwrap().data, vec![0, 0, 0, 0, 1, 2, 3, 4]);
    // sparse_size 0 is rejected
    err(
        &mut s,
        O,
        "rbd",
        "sparsify",
        &sparsify_input(0, false),
        EINVAL,
    );
}

#[test]
fn get_stripe_unit_count_missing_order_is_eio() {
    let mut s = MemStore::new();
    header(&mut s, 2); // STRIPINGV2
    // A missing `order` key is -EIO per spec A.5 (only an absent object/key of other getters is ENOENT).
    s.objects
        .get_mut(HDR)
        .unwrap()
        .omap
        .remove(b"order".as_slice());
    err(&mut s, HDR, "rbd", "get_stripe_unit_count", &[], EIO);
}
