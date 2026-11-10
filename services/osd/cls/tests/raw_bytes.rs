// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Review point (a): strings classic treats as arbitrary bytes (lc bucket keys, usage owner/bucket/iter, gc tags,
//! log ids/markers, timeindex ext/markers, queue markers) round-trip raw non-UTF-8 bytes; and (b): read methods on an
//! absent object behave like classic (omap reads succeed empty, no ENOENT).
mod common;
use cls::mem::MemStore;
use cls::rgw::gc::{DeferTagOp, RemoveTagsOp};
use cls::rgw::lc::*;
use cls::rgw::usage::*;
use cls::rgw_gc::{
    GcChain, GcObj, GcObjInfo, ListOp as GcListOp, ListRet as GcListRet, SetEntryOp,
};
use cls::{log as lg, queue as q, timeindex as ti};
use common::*;
use denc::types::UTime;

/// Not valid UTF-8 (0xff, 0xfe, lone continuation 0x80).
const RAW: &[u8] = b"b\xff\xfe\x80/x";

fn raw(prefix: &str) -> Vec<u8> {
    [prefix.as_bytes(), RAW].concat()
}
fn omap_keys(s: &MemStore, oid: &str) -> Vec<Vec<u8>> {
    s.obj(oid).unwrap().omap.keys().cloned().collect()
}

#[test]
fn lc_raw_bucket_keys_and_markers() {
    let mut s = MemStore::new();
    let (b1, b2) = (raw("a"), raw("b"));
    for (i, b) in [&b1, &b2].iter().enumerate() {
        let en = LcEntry {
            bucket: (*b).clone(),
            start_time: i as u64,
            status: 1,
        };
        ok(&mut s, "lc.0", "rgw", "lc_set_entry", &e(&LcEntryEnv(en)));
    }
    assert_eq!(omap_keys(&s, "lc.0"), vec![b1.clone(), b2.clone()]);
    let got: LcEntryEnv = d(&ok(
        &mut s,
        "lc.0",
        "rgw",
        "lc_get_entry",
        &e(&LcMarkerOp { marker: b2.clone() }),
    ));
    assert_eq!(got.0.bucket, b2);
    let nxt: LcEntryEnv = d(&ok(
        &mut s,
        "lc.0",
        "rgw",
        "lc_get_next_entry",
        &e(&LcMarkerOp { marker: b1.clone() }),
    ));
    assert_eq!(nxt.0.bucket, b2);
    for v in [3u8, 2, 1] {
        // every echoed form (legacy map<bucket,status> too) carries the raw key
        let l: LcListRet = d(&ok(
            &mut s,
            "lc.0",
            "rgw",
            "lc_list_entries",
            &e(&LcListOp {
                marker: b1.clone(),
                max_entries: 10,
                compat_v: v,
            }),
        ));
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.entries[0].bucket, b2, "compat v{v}");
    }
    let head = LcHead {
        start_date: 7,
        marker: b1.clone(),
        shard_rollover_date: 9,
    };
    ok(
        &mut s,
        "lc.0",
        "rgw",
        "lc_put_head",
        &e(&LcPutHeadOp { head: head.clone() }),
    );
    let h: LcGetHeadRet = d(&ok(&mut s, "lc.0", "rgw", "lc_get_head", &[]));
    assert_eq!(h.head, head);
    ok(
        &mut s,
        "lc.0",
        "rgw",
        "lc_rm_entry",
        &e(&LcEntryEnv(LcEntry {
            bucket: b1.clone(),
            ..Default::default()
        })),
    );
    assert_eq!(omap_keys(&s, "lc.0"), vec![b2]);
}

#[test]
fn usage_raw_owner_bucket_iter() {
    let mut s = MemStore::new();
    let (user, bucket) = (raw("u"), raw("bk"));
    let mut en = UsageEntry {
        owner: user.clone(),
        bucket: bucket.clone(),
        epoch: 1000,
        ..Default::default()
    };
    let dd = UsageData {
        bytes_sent: 1,
        bytes_received: 2,
        ops: 3,
        successful_ops: 3,
    };
    en.usage_map.insert(raw("cat"), dd.clone());
    en.total = dd;
    let add = |s: &mut MemStore, en: &UsageEntry| {
        ok(
            s,
            "usage.0",
            "rgw",
            "user_usage_log_add",
            &e(&UsageAddOp {
                info: UsageInfo {
                    entries: vec![en.clone()],
                },
                user: Vec::new(),
            }),
        );
    };
    add(&mut s, &en);
    en.epoch = 2000;
    add(&mut s, &en);
    let read = |s: &mut MemStore, iter: &[u8], max| -> UsageReadRet {
        d(&ok(
            s,
            "usage.0",
            "rgw",
            "user_usage_log_read",
            &e(&UsageReadOp {
                start_epoch: 0,
                end_epoch: u64::MAX,
                owner: user.clone(),
                bucket: bucket.clone(),
                iter: iter.to_vec(),
                max_entries: max,
            }),
        ))
    };
    let p1 = read(&mut s, b"", 1);
    assert!(p1.truncated && !p1.next_iter.is_empty());
    let (ub, got) = p1.usage.iter().next().unwrap();
    assert_eq!((&ub.user, &ub.bucket), (&user, &bucket));
    assert_eq!(got.usage_map[&raw("cat")].ops, 3);
    let p2 = read(&mut s, &p1.next_iter, 1);
    assert_eq!(p2.usage.len(), 1);
    // an iterator holding raw key bytes is echoed verbatim
    let key = omap_keys(&s, "usage.0").remove(2); // first by-user key
    let p3 = read(&mut s, &key, 1);
    assert!(!p3.usage.is_empty());
    ok(
        &mut s,
        "usage.0",
        "rgw",
        "user_usage_log_trim",
        &e(&UsageTrimOp {
            start_epoch: 0,
            end_epoch: u64::MAX,
            user: user.clone(),
            bucket: bucket.clone(),
        }),
    );
}

fn gc_info(tag: &[u8]) -> GcObjInfo {
    GcObjInfo {
        tag: tag.to_vec(),
        chain: GcChain {
            objs: vec![GcObj {
                pool: "p".into(),
                key: cls::rgw::types::ObjKey::new("o", ""),
                loc: Vec::new(),
            }],
        },
        time: UTime::default(),
    }
}

#[test]
fn legacy_gc_raw_tags_and_markers() {
    let mut s = MemStore::new();
    let (t1, t2) = (raw("t1"), raw("t2"));
    s.env.now = UTime::new(1000, 0);
    for t in [&t1, &t2] {
        s.env.now = UTime::new(s.env.now.sec + 1, 0);
        ok(
            &mut s,
            "gc.0",
            "rgw",
            "gc_set_entry",
            &e(&SetEntryOp {
                expiration_secs: 10,
                info: gc_info(t),
            }),
        );
    }
    ok(
        &mut s,
        "gc.0",
        "rgw",
        "gc_defer_entry",
        &e(&DeferTagOp {
            expiration_secs: 50,
            tag: t1.clone(),
        }),
    );
    let list = |s: &mut MemStore, marker: &[u8], max| -> GcListRet {
        d(&ok(
            s,
            "gc.0",
            "rgw",
            "gc_list",
            &e(&GcListOp {
                marker: marker.to_vec(),
                max,
                expired_only: false,
            }),
        ))
    };
    let p1 = list(&mut s, b"", 1);
    assert!(p1.truncated);
    assert_eq!(p1.entries[0].tag, t2); // t2 expires first (t1 was deferred)
    assert!(p1.next_marker.starts_with(b"1_"));
    let p2 = list(&mut s, &p1.next_marker, 1);
    assert_eq!(p2.entries[0].tag, t1);
    ok(
        &mut s,
        "gc.0",
        "rgw",
        "gc_remove",
        &e(&RemoveTagsOp {
            tags: vec![t1.clone(), t2.clone()],
        }),
    );
    assert!(omap_keys(&s, "gc.0").is_empty());
}

#[test]
fn queue_gc_raw_tags_markers_are_bytes() {
    let mut s = MemStore::new();
    s.objects.entry("q".into()).or_default();
    ok(
        &mut s,
        "q",
        "rgw_gc",
        "rgw_gc_queue_init",
        &e(&cls::rgw_gc::QueueInitOp {
            size: 1 << 20,
            num_deferred_entries: 8,
        }),
    );
    let tag = raw("gt");
    ok(
        &mut s,
        "q",
        "rgw_gc",
        "rgw_gc_queue_enqueue",
        &e(&SetEntryOp {
            expiration_secs: 0,
            info: gc_info(&tag),
        }),
    );
    // garbage / non-UTF-8 start marker: parsed leniently like classic, never an decode error
    let l: GcListRet = d(&ok(
        &mut s,
        "q",
        "rgw_gc",
        "rgw_gc_queue_list_entries",
        &e(&GcListOp {
            marker: RAW.to_vec(),
            max: 10,
            expired_only: false,
        }),
    ));
    assert_eq!(l.entries[0].tag, tag);
    let r = call(
        &mut s,
        "q",
        "queue",
        "queue_list_entries",
        &e(&q::ListOp {
            max: 10,
            start_marker: RAW.to_vec(),
            end_marker: Vec::new(),
        }),
    );
    assert_eq!(r.ret, 0);
}

#[test]
fn log_and_timeindex_raw_ids_markers() {
    let mut s = MemStore::new();
    let id = raw("1_0000000100.000000_");
    let entry = lg::Entry {
        id: id.clone(),
        section: raw("s"),
        name: raw("n"),
        timestamp: UTime::new(100, 0),
        data: vec![1, 2],
    };
    ok(
        &mut s,
        "l",
        "log",
        "add",
        &e(&lg::AddOp {
            entries: vec![entry.clone()],
            monotonic_inc: true,
        }),
    );
    let info: lg::InfoRet = d(&ok(&mut s, "l", "log", "info", &e(&lg::InfoOp {})));
    assert_eq!(info.header.max_marker, id);
    let r: lg::ListRet = d(&ok(
        &mut s,
        "l",
        "log",
        "list",
        &e(&lg::ListOp {
            from_time: UTime::default(),
            marker: Vec::new(),
            to_time: UTime::default(),
            max_entries: 1,
        }),
    ));
    assert_eq!(r.entries, vec![entry]);
    assert_eq!(r.marker, id);
    ok(
        &mut s,
        "l",
        "log",
        "trim",
        &e(&lg::TrimOp {
            from_marker: b"1_".to_vec(),
            to_marker: id.clone(),
            ..Default::default()
        }),
    );

    let ent = ti::Entry {
        key_ts: UTime::new(5, 0),
        key_ext: raw("x"),
        value: vec![9],
    };
    ok(
        &mut s,
        "t",
        "timeindex",
        "add",
        &e(&ti::AddOp {
            entries: vec![ent.clone()],
        }),
    );
    let r: ti::ListRet = d(&ok(
        &mut s,
        "t",
        "timeindex",
        "list",
        &e(&ti::ListOp {
            marker: b"1_".to_vec(),
            from_time: UTime::new(1, 0), // to_time (0) < from_time: no upper bound
            max_entries: 5,
            ..Default::default()
        }),
    ));
    assert_eq!(r.entries, vec![ent]);
}

#[test]
fn reads_on_absent_objects_are_empty_not_enoent() {
    let mut s = MemStore::new();
    let h: LcGetHeadRet = d(&ok(&mut s, "none", "rgw", "lc_get_head", &[]));
    assert_eq!(h.head, LcHead::default());
    let l: LcListRet = d(&ok(
        &mut s,
        "none",
        "rgw",
        "lc_list_entries",
        &e(&LcListOp {
            max_entries: 5,
            ..Default::default()
        }),
    ));
    assert!(l.entries.is_empty() && !l.is_truncated);
    let n: LcEntryEnv = d(&ok(
        &mut s,
        "none",
        "rgw",
        "lc_get_next_entry",
        &e(&LcMarkerOp::default()),
    ));
    assert_eq!(n.0, LcEntry::default());
    err(
        &mut s,
        "none",
        "rgw",
        "lc_get_entry",
        &e(&LcMarkerOp::default()),
        cls::errno::ENOENT,
    );
    let g: GcListRet = d(&ok(
        &mut s,
        "none",
        "rgw",
        "gc_list",
        &e(&GcListOp {
            max: 5,
            ..Default::default()
        }),
    ));
    assert!(g.entries.is_empty() && !g.truncated);
    ok(
        &mut s,
        "none",
        "rgw",
        "user_usage_log_read",
        &e(&UsageReadOp {
            end_epoch: u64::MAX,
            ..Default::default()
        }),
    );
    ok(
        &mut s,
        "none",
        "log",
        "list",
        &e(&lg::ListOp {
            max_entries: 5,
            ..Default::default()
        }),
    );
    ok(
        &mut s,
        "none",
        "timeindex",
        "list",
        &e(&ti::ListOp {
            max_entries: 5,
            ..Default::default()
        }),
    );
    assert!(s.obj("none").is_none(), "RD calls never create the object");
}
