// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls_rgw reshard queue (spec/cls_rgw.md s3.6) on MemCtx.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use cls::rgw::types::*;
use common::*;
use denc::types::UTime;

const O: &str = "reshard.0000000000";

fn entry(tenant: &str, bucket: &str, id: &str) -> ReshardEntry {
    ReshardEntry(ReshardEntryBody {
        time: UTime::new(100, 5),
        tenant: tenant.into(),
        bucket_name: bucket.into(),
        bucket_id: id.into(),
        old_num_shards: 11,
        new_num_shards: 23,
        initiator: 2,
    })
}
fn add(s: &mut MemStore, en: ReshardEntry, create_only: bool) -> i32 {
    let op = ReshardAddOp {
        entry: en,
        create_only,
    };
    call(s, O, "rgw", "reshard_add", &e(&op)).ret
}
fn list(s: &mut MemStore, marker: &str, max: u32) -> ReshardListRet {
    let op = ReshardListOp {
        max,
        marker: marker.into(),
    };
    d(&ok(s, O, "rgw", "reshard_list", &e(&op)))
}

#[test]
fn add_get_list_remove() {
    let mut s = MemStore::new();
    assert_eq!(add(&mut s, entry("t", "b1", "id1"), false), 0);
    assert!(
        s.obj(O).unwrap().omap.contains_key(&b"t:b1"[..]),
        "key = tenant:bucket"
    );
    assert_eq!(add(&mut s, entry("", "b0", "id0"), true), 0);
    assert!(
        s.obj(O).unwrap().omap.contains_key(&b":b0"[..]),
        "empty tenant -> ':name'"
    );
    // create_only keeps the existing entry
    assert_eq!(add(&mut s, entry("t", "b1", "other"), true), EEXIST);
    // plain add overwrites
    assert_eq!(add(&mut s, entry("t", "b1", "id2"), false), 0);
    let g: ReshardGetRet = d(&ok(
        &mut s,
        O,
        "rgw",
        "reshard_get",
        &e(&ReshardGetOp {
            entry: entry("t", "b1", ""),
        }),
    ));
    assert_eq!(txt(&g.entry.bucket_id), "id2");
    err(
        &mut s,
        O,
        "rgw",
        "reshard_get",
        &e(&ReshardGetOp {
            entry: entry("t", "nope", ""),
        }),
        ENOENT,
    );
    // list ascending, paging by marker
    let l = list(&mut s, "", 1000);
    assert_eq!(l.entries.len(), 2);
    assert_eq!(txt(&l.entries[0].bucket_name), "b0");
    assert!(!l.is_truncated);
    let l1 = list(&mut s, "", 1);
    assert_eq!((l1.entries.len(), l1.is_truncated), (1, true));
    let l2 = list(&mut s, ":b0", 1);
    assert_eq!(txt(&l2.entries[0].bucket_name), "b1");
    // max 0: nothing decoded (upstream quirk) but still ok
    assert!(list(&mut s, "", 0).entries.is_empty());
    // remove: stale bucket_id leaves the newer entry alone
    let rm = |s: &mut MemStore, t: &str, b: &str, id: &str| {
        call(
            s,
            O,
            "rgw",
            "reshard_remove",
            &e(&ReshardRemoveOp {
                tenant: t.into(),
                bucket_name: b.into(),
                bucket_id: id.into(),
            }),
        )
        .ret
    };
    assert_eq!(rm(&mut s, "t", "b1", "stale"), 0);
    assert_eq!(list(&mut s, "", 100).entries.len(), 2);
    assert_eq!(rm(&mut s, "t", "b1", "id2"), 0);
    assert_eq!(
        rm(&mut s, "", "b0", ""),
        0,
        "empty id removes unconditionally"
    );
    assert!(list(&mut s, "", 100).entries.is_empty());
    assert_eq!(rm(&mut s, "t", "b1", ""), ENOENT);
}

#[test]
fn corrupt_value_is_eio_and_garbage_input_einval() {
    let mut s = MemStore::new();
    s.objects
        .entry(O.into())
        .or_default()
        .omap
        .insert(b"t:x".to_vec(), vec![1]);
    err(
        &mut s,
        O,
        "rgw",
        "reshard_list",
        &e(&ReshardListOp {
            max: 10,
            marker: Vec::new(),
        }),
        EIO,
    );
    for m in [
        "reshard_add",
        "reshard_list",
        "reshard_get",
        "reshard_remove",
    ] {
        err(&mut s, O, "rgw", m, &[0xff], EINVAL);
    }
}
