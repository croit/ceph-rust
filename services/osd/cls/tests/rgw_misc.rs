// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls_rgw stage 2: lifecycle (lc_*), legacy omap GC (gc_*), usage log, mp_upload_part_info_update.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use cls::registry::{RD, RW, WR, lookup};
use cls::rgw::gc::{DeferTagOp, RemoveTagsOp};
use cls::rgw::lc::*;
use cls::rgw::mp::*;
use cls::rgw::usage::*;
use cls::rgw_gc::{
    GcChain, GcObj, GcObjInfo, ListOp as GcListOp, ListRet as GcListRet, SetEntryOp,
};
use common::*;
use denc::types::UTime;
use denc::{Encode, Encoder};

#[test]
fn registry_flags() {
    for (m, f) in [
        ("lc_get_entry", RD),
        ("lc_set_entry", RW),
        ("lc_rm_entry", RW),
        ("lc_get_next_entry", RD),
        ("lc_list_entries", RD),
        ("lc_put_head", RW),
        ("lc_get_head", RD),
        ("gc_set_entry", RW),
        ("gc_defer_entry", RW),
        ("gc_list", RD),
        ("gc_remove", RW),
        ("user_usage_log_add", RW),
        ("user_usage_log_read", RD),
        ("user_usage_log_trim", RW),
        ("usage_log_clear", WR),
        ("mp_upload_part_info_update", RW),
    ] {
        assert_eq!(lookup("rgw", m).unwrap().flags, f, "{m}");
    }
}

// ================================================================ lifecycle

const LC: &str = "lc.0";

fn lc_entry(b: &str, start: u64, st: u32) -> LcEntry {
    LcEntry {
        bucket: b.into(),
        start_time: start,
        status: st,
    }
}
fn lc_set(s: &mut MemStore, en: &LcEntry) {
    ok(s, LC, "rgw", "lc_set_entry", &e(&LcEntryEnv(en.clone())));
}
fn marker_op(m: &str) -> Vec<u8> {
    e(&LcMarkerOp { marker: m.into() })
}

#[test]
fn lc_entries_set_get_rm_next() {
    let mut s = MemStore::new();
    for (i, b) in ["b1", "b2", "b3"].iter().enumerate() {
        lc_set(&mut s, &lc_entry(b, 10 + i as u64, i as u32));
    }
    // raw layout: key = bucket, value = enveloped (1,1) entry
    assert_eq!(
        s.omap_get(LC, "b2").unwrap(),
        e(&lc_entry("b2", 11, 1)).as_slice()
    );
    let g: LcEntryEnv = d(&ok(&mut s, LC, "rgw", "lc_get_entry", &marker_op("b2")));
    assert_eq!(g.0, lc_entry("b2", 11, 1));
    err(
        &mut s,
        LC,
        "rgw",
        "lc_get_entry",
        &marker_op("nope"),
        ENOENT,
    );
    // next: first entry strictly after the marker; empty marker = first; past the end = default
    let nx = |s: &mut MemStore, m: &str| -> LcEntry {
        d::<LcEntryEnv>(&ok(s, LC, "rgw", "lc_get_next_entry", &marker_op(m))).0
    };
    assert_eq!(nx(&mut s, "").bucket, b"b1");
    assert_eq!(nx(&mut s, "b1").bucket, b"b2");
    assert_eq!(nx(&mut s, "b3"), LcEntry::default());
    // rm: missing key is fine, key gone afterwards
    ok(
        &mut s,
        LC,
        "rgw",
        "lc_rm_entry",
        &e(&LcEntryEnv(lc_entry("b2", 0, 0))),
    );
    ok(
        &mut s,
        LC,
        "rgw",
        "lc_rm_entry",
        &e(&LcEntryEnv(lc_entry("zz", 0, 0))),
    );
    assert!(s.omap_get(LC, "b2").is_none());
    // corrupt value
    s.objects
        .get_mut(LC)
        .unwrap()
        .omap
        .insert(b"b1".to_vec(), vec![1]);
    err(&mut s, LC, "rgw", "lc_get_entry", &marker_op("b1"), EIO);
    err(&mut s, LC, "rgw", "lc_get_next_entry", &marker_op(""), EIO);
}

#[test]
fn lc_legacy_pair_inputs_and_values() {
    let mut s = MemStore::new();
    // v1 set_entry_op: envelope (1,1){ string bucket, i32 status }
    let mut enc = Encoder::new();
    enc.versioned(1, 1, |e| {
        "old".encode(e)?;
        e.i32(3)
    })
    .unwrap();
    ok(&mut s, LC, "rgw", "lc_set_entry", &enc.into_vec());
    let g: LcEntryEnv = d(&ok(&mut s, LC, "rgw", "lc_get_entry", &marker_op("old")));
    assert_eq!(g.0, lc_entry("old", 0, 3));
    // a pre-1.1 stored value (pair<string,int>) lists as {bucket, 0, status}
    let mut v = Encoder::new();
    "legacy".encode(&mut v).unwrap();
    v.i32(2).unwrap();
    s.objects
        .get_mut(LC)
        .unwrap()
        .omap
        .insert(b"legacy".to_vec(), v.into_vec());
    let l: LcListRet = d(&ok(
        &mut s,
        LC,
        "rgw",
        "lc_list_entries",
        &e(&LcListOp {
            marker: "".into(),
            max_entries: 100,
            compat_v: 0,
        }),
    ));
    assert_eq!(l.entries.len(), 2);
    assert_eq!(l.entries[0], lc_entry("legacy", 0, 2));
}

#[test]
fn lc_list_entries_pages_and_echoes_the_request_version() {
    let mut s = MemStore::new();
    for i in 0..5 {
        lc_set(&mut s, &lc_entry(&format!("b{i}"), i, 1));
    }
    let list = |s: &mut MemStore, marker: &[u8], max| -> LcListRet {
        d(&ok(
            s,
            LC,
            "rgw",
            "lc_list_entries",
            &e(&LcListOp {
                marker: marker.as_ref().to_vec(),
                max_entries: max,
                compat_v: 0,
            }),
        ))
    };
    let p1 = list(&mut s, b"", 2);
    assert!(p1.is_truncated);
    assert_eq!(p1.compat_v, 3);
    assert_eq!(p1.entries.len(), 2);
    let p2 = list(&mut s, &p1.entries[1].bucket, 100);
    assert!(!p2.is_truncated);
    assert_eq!(p2.entries.len(), 3);
    // v2 request -> map<bucket,status> reply with envelope version 2
    let mut raw = Encoder::new();
    raw.versioned(2, 1, |e| {
        "".encode(e)?;
        e.u32(100)
    })
    .unwrap();
    let out = ok(&mut s, LC, "rgw", "lc_list_entries", &raw.into_vec());
    assert_eq!(&out[..2], &[2, 1]);
    let r: LcListRet = d(&out);
    assert_eq!((r.compat_v, r.entries.len()), (2, 5));
    assert!(r.entries.iter().all(|x| x.start_time == 0)); // the map form has no start_time
}

#[test]
fn lc_head() {
    let mut s = MemStore::new();
    let get = |s: &mut MemStore| -> LcHead {
        d::<LcGetHeadRet>(&ok(s, LC, "rgw", "lc_get_head", &[])).head
    };
    assert_eq!(get(&mut s), LcHead::default());
    let h = LcHead {
        start_date: 1_800_000_000,
        marker: "mark".into(),
        shard_rollover_date: 42,
    };
    ok(
        &mut s,
        LC,
        "rgw",
        "lc_put_head",
        &e(&LcPutHeadOp { head: h.clone() }),
    );
    assert_eq!(s.obj(LC).unwrap().omap_header, e(&h));
    assert_eq!(get(&mut s), h);
    s.objects.get_mut(LC).unwrap().omap_header = vec![1, 2];
    err(&mut s, LC, "rgw", "lc_get_head", &[], EINVAL);
}

// ================================================================ legacy omap gc

const GC: &str = "gc.0";

fn gc_info(tag: &str, nobj: usize) -> GcObjInfo {
    GcObjInfo {
        tag: tag.into(),
        chain: GcChain {
            objs: (0..nobj)
                .map(|i| GcObj {
                    pool: "p".into(),
                    key: cls::rgw::types::ObjKey::new(&format!("o{i}"), ""),
                    loc: Vec::new(),
                })
                .collect(),
        },
        time: UTime::default(),
    }
}
fn gc_set(s: &mut MemStore, tag: &str, secs: u32) {
    let op = SetEntryOp {
        expiration_secs: secs,
        info: gc_info(tag, 2),
    };
    ok(s, GC, "rgw", "gc_set_entry", &e(&op));
}
fn time_key(sec: u32, nsec: u32) -> String {
    format!("1_{sec:011}.{nsec:09}")
}
fn gc_list(s: &mut MemStore, marker: impl AsRef<[u8]>, max: u32, expired_only: bool) -> GcListRet {
    let op = GcListOp {
        marker: marker.as_ref().to_vec(),
        max,
        expired_only,
    };
    d(&ok(s, GC, "rgw", "gc_list", &e(&op)))
}
fn keys_of(s: &MemStore) -> Vec<String> {
    s.obj(GC)
        .unwrap()
        .omap
        .keys()
        .map(|k| String::from_utf8_lossy(k).into_owned())
        .collect()
}

#[test]
fn gc_set_entry_writes_name_and_time_index_and_reschedules() {
    let mut s = MemStore::new();
    let now = s.env.now;
    gc_set(&mut s, "tagA", 100);
    let tk = time_key(now.sec + 100, now.nsec);
    assert_eq!(keys_of(&s), vec!["0_tagA".to_string(), tk.clone()]);
    let a = s.omap_get(GC, "0_tagA").unwrap().to_vec();
    assert_eq!(a, s.omap_get(GC, &tk).unwrap());
    let stored: GcObjInfo = d(&a);
    assert_eq!(
        (
            std::str::from_utf8(&stored.tag).unwrap(),
            stored.time,
            stored.chain.objs.len()
        ),
        ("tagA", UTime::new(now.sec + 100, now.nsec), 2)
    );
    // setting again moves the time key
    gc_set(&mut s, "tagA", 500);
    assert_eq!(
        keys_of(&s),
        vec!["0_tagA".to_string(), time_key(now.sec + 500, now.nsec)]
    );
    // defer: unknown tag -> ENOENT; known -> rescheduled with the stored chain
    let df = |tag: &str, secs| {
        e(&DeferTagOp {
            expiration_secs: secs,
            tag: tag.into(),
        })
    };
    err(&mut s, GC, "rgw", "gc_defer_entry", &df("zz", 5), ENOENT);
    ok(&mut s, GC, "rgw", "gc_defer_entry", &df("tagA", 7));
    assert_eq!(
        keys_of(&s),
        vec!["0_tagA".to_string(), time_key(now.sec + 7, now.nsec)]
    );
    assert_eq!(
        d::<GcObjInfo>(s.omap_get(GC, "0_tagA").unwrap())
            .chain
            .objs
            .len(),
        2
    );
}

#[test]
fn gc_list_expiry_paging_and_remove() {
    let mut s = MemStore::new();
    let now = s.env.now;
    for (i, secs) in [10u32, 20, 30, 1000].iter().enumerate() {
        s.env.now = UTime::new(now.sec, i as u32); // distinct nsec: distinct time keys
        gc_set(&mut s, &format!("t{i}"), *secs);
    }
    s.env.now = UTime::new(now.sec + 35, 0);
    // expired only: the first three; the name index ("0_...") is never listed
    let l = gc_list(&mut s, "", 0, true);
    let tags: Vec<&str> = l
        .entries
        .iter()
        .map(|x| std::str::from_utf8(&x.tag).unwrap())
        .collect();
    assert_eq!(tags, ["t0", "t1", "t2"]);
    assert!(!l.truncated && l.next_marker.is_empty());
    // everything
    let all = gc_list(&mut s, "", 0, false);
    assert_eq!(all.entries.len(), 4);
    // paging by next_marker (a full omap key)
    let p1 = gc_list(&mut s, "", 2, false);
    assert!(p1.truncated);
    assert_eq!(p1.entries.len(), 2);
    assert!(p1.next_marker.starts_with(b"1_"));
    let p2 = gc_list(&mut s, &p1.next_marker, 2, false);
    assert_eq!(
        p2.entries
            .iter()
            .map(|x| std::str::from_utf8(&x.tag).unwrap())
            .collect::<Vec<_>>(),
        ["t2", "t3"]
    );
    assert!(!p2.truncated && p2.next_marker.is_empty());
    // remove: unknown tags skipped, both keys gone
    let rm = e(&RemoveTagsOp {
        tags: vec!["t1".into(), "unknown".into(), "t3".into()],
    });
    ok(&mut s, GC, "rgw", "gc_remove", &rm);
    assert_eq!(gc_list(&mut s, "", 0, false).entries.len(), 2);
    assert_eq!(keys_of(&s).len(), 4);
}

#[test]
fn gc_list_corrupt_value_is_eio() {
    let mut s = MemStore::new();
    gc_set(&mut s, "a", 1);
    s.objects
        .get_mut(GC)
        .unwrap()
        .omap
        .insert(time_key(5, 5).into_bytes(), vec![0]);
    let op = GcListOp {
        marker: "".into(),
        max: 10,
        expired_only: false,
    };
    err(&mut s, GC, "rgw", "gc_list", &e(&op), EIO);
}

// ================================================================ usage log

const U: &str = "usage.0";

fn data(sent: u64, recv: u64, ops: u64) -> UsageData {
    UsageData {
        bytes_sent: sent,
        bytes_received: recv,
        ops,
        successful_ops: ops,
    }
}
fn uentry(owner: &str, bucket: &str, epoch: u64, cat: &str, dd: UsageData) -> UsageEntry {
    let mut en = UsageEntry {
        owner: owner.into(),
        bucket: bucket.into(),
        epoch,
        ..Default::default()
    };
    en.usage_map.insert(cat.into(), dd.clone());
    en.total = dd;
    en
}
fn uadd(s: &mut MemStore, entries: Vec<UsageEntry>) {
    let op = UsageAddOp {
        info: UsageInfo { entries },
        user: Vec::new(),
    };
    ok(s, U, "rgw", "user_usage_log_add", &e(&op));
}
fn uread(s: &mut MemStore, op: &UsageReadOp) -> UsageReadRet {
    d(&ok(s, U, "rgw", "user_usage_log_read", &e(op)))
}
fn ukeys(s: &MemStore) -> Vec<String> {
    s.obj(U)
        .map(|o| {
            o.omap
                .keys()
                .map(|k| String::from_utf8_lossy(k).into_owned())
                .collect()
        })
        .unwrap_or_default()
}
fn utrim(s: &mut MemStore, start: u64, end: u64, user: &str, bucket: &str) -> i32 {
    let op = UsageTrimOp {
        start_epoch: start,
        end_epoch: end,
        user: user.into(),
        bucket: bucket.into(),
    };
    call(s, U, "rgw", "user_usage_log_trim", &e(&op)).ret
}

#[test]
fn usage_add_stores_two_copies_and_aggregates_across_calls() {
    let mut s = MemStore::new();
    uadd(
        &mut s,
        vec![uentry("alice", "b1", 3600, "get_obj", data(10, 0, 1))],
    );
    assert_eq!(
        ukeys(&s),
        vec![
            "00000003600_alice_b1".to_string(),
            "alice_00000003600_b1".to_string()
        ]
    );
    assert_eq!(
        s.omap_get(U, "00000003600_alice_b1"),
        s.omap_get(U, "alice_00000003600_b1")
    );
    // second call, same (user, bucket, epoch): categories summed, total follows add_usage
    uadd(
        &mut s,
        vec![{
            let mut x = uentry("alice", "b1", 3600, "get_obj", data(5, 1, 2));
            x.usage_map.insert("put_obj".into(), data(0, 7, 1));
            x
        }],
    );
    let st: UsageEntry = d(s.omap_get(U, "00000003600_alice_b1").unwrap());
    assert_eq!(st.usage_map["get_obj".as_bytes()], data(15, 1, 3));
    assert_eq!(st.usage_map["put_obj".as_bytes()], data(0, 7, 1));
    // payer wins as the filing user
    let mut x = uentry("owner", "b2", 7200, "list_bucket", data(1, 1, 1));
    x.payer = "payer".into();
    uadd(&mut s, vec![x]);
    assert!(ukeys(&s).contains(&"00000007200_payer_b2".to_string()));
    assert!(ukeys(&s).contains(&"payer_00000007200_b2".to_string()));
    // v1 value decodes with usage_map = {"": total}
    let mut v1 = Encoder::new();
    v1.versioned(1, 1, |e| {
        "u".encode(e)?;
        "b".encode(e)?;
        e.u64(1)?;
        for x in [4u64, 3, 2, 1] {
            e.u64(x)?;
        }
        Ok(())
    })
    .unwrap();
    let old: UsageEntry = d(&v1.into_vec());
    assert_eq!(
        old.usage_map["".as_bytes()],
        UsageData {
            bytes_sent: 4,
            bytes_received: 3,
            ops: 2,
            successful_ops: 1
        }
    );
}

#[test]
fn usage_users_starting_with_zero_use_the_tilde_prefix_and_clean_legacy_keys() {
    let mut s = MemStore::new();
    s.objects
        .entry(U.into())
        .or_default()
        .omap
        .insert(b"0bob_00000003600_b1".to_vec(), vec![0]); // legacy by-user key
    uadd(&mut s, vec![uentry("0bob", "b1", 3600, "x", data(1, 1, 1))]);
    let k = ukeys(&s);
    assert!(k.contains(&"~0bob_00000003600_b1".to_string()), "{k:?}");
    assert!(!k.contains(&"0bob_00000003600_b1".to_string()));
    // read by that user finds it (new keys after the legacy pass)
    let r = uread(
        &mut s,
        &UsageReadOp {
            start_epoch: 0,
            end_epoch: u64::MAX,
            owner: "0bob".into(),
            ..Default::default()
        },
    );
    assert_eq!(r.usage.len(), 1);
}

#[test]
fn usage_read_windows_filters_paging_and_aggregation() {
    let mut s = MemStore::new();
    for ep in [1000u64, 2000, 3000, 4000] {
        uadd(
            &mut s,
            vec![uentry("alice", "b1", ep, "get_obj", data(ep, 0, 1))],
        );
    }
    uadd(
        &mut s,
        vec![uentry("alice", "b2", 2000, "get_obj", data(1, 1, 1))],
    );
    uadd(
        &mut s,
        vec![uentry("bob", "b1", 2000, "get_obj", data(9, 9, 9))],
    );
    let read = |s: &mut MemStore, owner: &str, bucket: &str, st, en, iter: &[u8], max| {
        uread(
            s,
            &UsageReadOp {
                start_epoch: st,
                end_epoch: en,
                owner: owner.into(),
                bucket: bucket.into(),
                iter: iter.as_ref().to_vec(),
                max_entries: max,
            },
        )
    };
    // by time, window [2000, 4000): end exclusive; aggregated per (user, bucket) over epochs
    let r = read(&mut s, "", "", 2000, 4000, b"", 0);
    let ub = |u: &str, b: &str| UserBucket {
        user: u.into(),
        bucket: b.into(),
    };
    assert_eq!(r.usage[&ub("alice", "b1")].total, data(5000, 0, 2));
    assert_eq!(
        r.usage[&ub("bob", "b1")].usage_map["get_obj".as_bytes()],
        data(9, 9, 9)
    );
    assert_eq!(r.usage.len(), 3);
    assert!(!r.truncated && r.next_iter.is_empty());
    // bucket filter
    let r = read(&mut s, "", "b2", 0, u64::MAX, b"", 0);
    assert_eq!(r.usage.len(), 1);
    // by user
    let r = read(&mut s, "alice", "", 0, u64::MAX, b"", 0);
    assert_eq!(r.usage.len(), 2);
    assert!(r.usage.keys().all(|k| k.user == b"alice"));
    // a user that is a prefix of another does not bleed (user_ prefix)
    let r = read(&mut s, "ali", "", 0, u64::MAX, b"", 0);
    assert!(r.usage.is_empty());
    // paging with iter
    let mut seen = 0;
    let mut iter = Vec::new();
    for _ in 0..20 {
        let r = read(&mut s, "", "", 0, u64::MAX, &iter, 2);
        seen += r
            .usage
            .values()
            .map(|x| x.usage_map["get_obj".as_bytes()].ops)
            .sum::<u64>();
        if !r.truncated {
            break;
        }
        assert!(!r.next_iter.is_empty());
        iter = r.next_iter;
    }
    assert_eq!(seen, 14); // alice/b1 x4 + alice/b2 x1 + bob/b1 (9 ops)
}

#[test]
fn usage_trim_removes_all_copies_and_signals_end_with_enodata() {
    let mut s = MemStore::new();
    err_absent(&mut s);
    for ep in [1000u64, 2000, 3000] {
        uadd(&mut s, vec![uentry("alice", "b1", ep, "x", data(1, 1, 1))]);
    }
    uadd(&mut s, vec![uentry("bob", "b1", 2000, "x", data(1, 1, 1))]);
    assert_eq!(ukeys(&s).len(), 8);
    // by time window [1500, 2500): alice@2000 and bob@2000 go (both copies each)
    assert_eq!(utrim(&mut s, 1500, 2500, "", ""), 0);
    assert_eq!(ukeys(&s).len(), 4);
    assert_eq!(utrim(&mut s, 1500, 2500, "", ""), ENODATA);
    // by user: only alice's remaining records
    assert_eq!(utrim(&mut s, 0, u64::MAX, "alice", ""), 0);
    assert!(ukeys(&s).is_empty());
    assert_eq!(utrim(&mut s, 0, u64::MAX, "alice", ""), ENODATA);
    // usage_log_clear: drops everything; absent object is fine
    uadd(&mut s, vec![uentry("a", "b", 1, "x", data(1, 1, 1))]);
    ok(&mut s, U, "rgw", "usage_log_clear", &[]);
    assert!(ukeys(&s).is_empty());
    ok(&mut s, "usage.99", "rgw", "usage_log_clear", &[]);
}

fn err_absent(s: &mut MemStore) {
    let op = UsageTrimOp::default();
    err(s, U, "rgw", "user_usage_log_trim", &e(&op), ENOENT);
}

/// The classic trim returns 0 (never ENODATA) when the first page holds no matching record but
/// more records follow, so the client loop never ends. We keep scanning: a match several pages
/// down is trimmed in the same call.
#[test]
fn usage_trim_scans_past_non_matching_pages() {
    let mut s = MemStore::new();
    let o = s.objects.entry(U.into()).or_default();
    let rec = |epoch: u64, bucket: &str| -> Vec<u8> {
        e(&uentry("u", bucket, epoch, "x", data(1, 1, 1)))
    };
    for ep in 1..=2500u64 {
        o.omap
            .insert(format!("{ep:011}_u_other").into_bytes(), rec(ep, "other"));
    }
    o.omap.insert(
        format!("{:011}_u_wanted", 3000).into_bytes(),
        rec(3000, "wanted"),
    );
    assert_eq!(utrim(&mut s, 0, u64::MAX, "", "wanted"), 0);
    assert!(!ukeys(&s).iter().any(|k| k.ends_with("_wanted")));
    assert_eq!(ukeys(&s).len(), 2500);
    // Only exhausting the remaining range reports ENODATA.
    assert_eq!(utrim(&mut s, 0, u64::MAX, "", "wanted"), ENODATA);
}

/// A match beyond the former 256-page cutoff must not be reported as end-of-data.
#[test]
fn usage_trim_scans_entire_filtered_range() {
    let mut s = MemStore::new();
    let o = s.objects.entry(U.into()).or_default();
    let v = e(&uentry("u", "other", 1, "x", data(1, 1, 1)));
    for ep in 1..=270_000u64 {
        o.omap
            .insert(format!("{ep:011}_u_other").into_bytes(), v.clone());
    }
    let before = o.omap.len();
    o.omap.insert(
        b"00000300000_u_wanted".to_vec(),
        e(&uentry("u", "wanted", 300_000, "x", data(1, 1, 1))),
    );
    assert_eq!(utrim(&mut s, 0, u64::MAX, "", "wanted"), 0);
    assert!(
        !s.obj(U)
            .unwrap()
            .omap
            .contains_key(b"00000300000_u_wanted".as_slice())
    );
    assert_eq!(s.obj(U).unwrap().omap.len(), before);
    assert_eq!(utrim(&mut s, 0, u64::MAX, "", "wanted"), ENODATA);
    assert_eq!(s.obj(U).unwrap().omap.len(), before);
}

#[test]
fn usage_user_normalization_round_trips() {
    // owner "t$u" (tenant) and "$ns$id" forms survive decode -> encode through add
    let mut s = MemStore::new();
    uadd(
        &mut s,
        vec![uentry("ten$bob", "b", 100, "x", data(1, 1, 1))],
    );
    assert!(ukeys(&s).contains(&"00000000100_ten$bob_b".to_string()));
    let st: UsageEntry = d(s.omap_get(U, "00000000100_ten$bob_b").unwrap());
    assert_eq!(st.owner, b"ten$bob");
}

// ================================================================ multipart part info

const MP: &str = "up.meta";

/// Hand-built RGWObjManifest (8,6): obj_size, objs{}, explicit=false, rgw_obj env, head_size,
/// max_head_size, prefix, rules{n}, then opaque tail fields.
fn manifest(prefix: &str, rules: u32) -> Vec<u8> {
    let mut m = Encoder::new();
    m.versioned(8, 6, |e| {
        e.u64(1234)?; // obj_size
        e.u32(0)?; // objs
        e.bool(false)?; // explicit_objs
        e.versioned(6, 6, |e| e.raw(b"bucketobj"))?; // rgw_obj (opaque to us)
        e.u64(0)?; // head_size
        e.u64(4096)?; // max_head_size
        prefix.encode(e)?;
        e.u32(rules)?;
        for i in 0..rules {
            e.u64(i as u64)?;
            e.versioned(2, 1, |e| e.raw(&[7; 12]))?; // rule
        }
        e.raw(&[0, 0, 1, 2, 3]) // tail placement etc. (opaque)
    })
    .unwrap();
    m.into_vec()
}
fn part_info(prefix: &str, rules: u32, past: &[&str]) -> PartInfoBytes {
    let mut p = Encoder::new();
    p.versioned(7, 2, |e| {
        e.u32(2)?; // num
        e.u64(1000)?; // size
        "etag".encode(e)?;
        UTime::new(5, 6).encode(e)?;
        e.raw(&manifest(prefix, rules))?;
        e.versioned(2, 1, |e| {
            "none".encode(e)?;
            e.u64(0)?;
            e.u8(0)?;
            e.u32(0)
        })?;
        e.u64(1000)?; // accounted_size
        let set: std::collections::BTreeSet<String> = past.iter().map(|s| s.to_string()).collect();
        set.encode(e)?;
        e.u8(0)?; // cksum absent
        "salt".encode(e)
    })
    .unwrap();
    PartInfoBytes(p.into_vec())
}
struct PartInfoBytes(Vec<u8>);
fn mp_op(key: &str, info: &PartInfoBytes) -> Vec<u8> {
    let mut o = Encoder::new();
    o.versioned(1, 1, |e| {
        key.encode(e)?;
        e.raw(&info.0)
    })
    .unwrap();
    o.into_vec()
}
fn stored(s: &MemStore, key: &str) -> PartInfo {
    d(s.omap_get(MP, key).unwrap())
}

#[test]
fn mp_update_tracks_past_prefixes_and_rejects_reuse() {
    let mut s = MemStore::new();
    let a = part_info("pfxA", 1, &[]);
    ok(
        &mut s,
        MP,
        "rgw",
        "mp_upload_part_info_update",
        &mp_op("part.00000001", &a),
    );
    // canonical v7 input is stored byte-identically
    assert_eq!(s.omap_get(MP, "part.00000001").unwrap(), a.0.as_slice());
    // retry with a new tail prefix: the previous one is remembered
    let b = part_info("pfxB", 1, &[]);
    ok(
        &mut s,
        MP,
        "rgw",
        "mp_upload_part_info_update",
        &mp_op("part.00000001", &b),
    );
    let st = stored(&s, "part.00000001");
    assert_eq!(txt(&st.prefix), "pfxB");
    assert_eq!(st.past_prefixes.iter().collect::<Vec<_>>(), [b"pfxA"]);
    // expected bytes = the input with past_prefixes rewritten
    assert_eq!(
        s.omap_get(MP, "part.00000001").unwrap(),
        part_info("pfxB", 1, &["pfxA"]).0.as_slice()
    );
    // reusing any earlier prefix collides
    for bad in ["pfxA", "pfxB"] {
        let before = s.objects.clone();
        err(
            &mut s,
            MP,
            "rgw",
            "mp_upload_part_info_update",
            &mp_op("part.00000001", &part_info(bad, 1, &[])),
            EEXIST,
        );
        assert_eq!(s.objects, before);
    }
    // the caller's own past_prefixes count too, and merge with the stored ones
    err(
        &mut s,
        MP,
        "rgw",
        "mp_upload_part_info_update",
        &mp_op("part.00000001", &part_info("pfxC", 1, &["pfxC"])),
        EEXIST,
    );
    ok(
        &mut s,
        MP,
        "rgw",
        "mp_upload_part_info_update",
        &mp_op("part.00000001", &part_info("pfxD", 1, &["old"])),
    );
    let st = stored(&s, "part.00000001");
    assert_eq!(
        st.past_prefixes.iter().collect::<Vec<_>>(),
        [b"old".as_slice(), b"pfxA", b"pfxB"]
    );
    // other parts are independent
    ok(
        &mut s,
        MP,
        "rgw",
        "mp_upload_part_info_update",
        &mp_op("part.00000002", &part_info("pfxA", 1, &[])),
    );
}

#[test]
fn mp_update_empty_stored_manifest_adds_no_prefix_and_garbage_is_rejected() {
    let mut s = MemStore::new();
    // a stored record whose manifest has no rules is "empty": its prefix is not remembered
    s.objects
        .entry(MP.into())
        .or_default()
        .omap
        .insert(b"part.00000001".to_vec(), part_info("emptyP", 0, &[]).0);
    ok(
        &mut s,
        MP,
        "rgw",
        "mp_upload_part_info_update",
        &mp_op("part.00000001", &part_info("emptyP", 1, &[])),
    );
    assert!(stored(&s, "part.00000001").past_prefixes.is_empty());
    // undecodable input -> EINVAL, undecodable stored value -> EIO
    err(
        &mut s,
        MP,
        "rgw",
        "mp_upload_part_info_update",
        &[1, 2, 3],
        EINVAL,
    );
    s.objects
        .get_mut(MP)
        .unwrap()
        .omap
        .insert(b"part.00000009".to_vec(), vec![9, 9]);
    err(
        &mut s,
        MP,
        "rgw",
        "mp_upload_part_info_update",
        &mp_op("part.00000009", &part_info("x", 1, &[])),
        EIO,
    );
    // never panics on truncations of a valid input
    let full = mp_op("k", &part_info("p", 1, &[]));
    for n in 0..full.len() {
        let r = call(&mut s, MP, "rgw", "mp_upload_part_info_update", &full[..n]);
        assert!(r.ret < 0);
    }
}

/// List-type methods never return more than the omap page cap (1024) however large the request.
#[test]
fn list_outputs_are_capped_by_the_omap_page() {
    let mut s = MemStore::new();
    let ent = e(&lc_entry("x", 1, 1));
    let u = e(&uentry("u", "b", 1, "x", data(1, 1, 1)));
    let g = e(&gc_info("t", 0));
    let o = s.objects.entry(LC.into()).or_default();
    for i in 0..1500 {
        o.omap.insert(format!("b{i:05}").into_bytes(), ent.clone());
    }
    let l: LcListRet = d(&ok(
        &mut s,
        LC,
        "rgw",
        "lc_list_entries",
        &e(&LcListOp {
            marker: Vec::new(),
            max_entries: u32::MAX,
            compat_v: 0,
        }),
    ));
    assert_eq!(l.entries.len(), 1024);
    assert!(l.is_truncated);

    let o = s.objects.entry(GC.into()).or_default();
    for i in 0..1500u32 {
        o.omap.insert(time_key(i, 0).into_bytes(), g.clone());
    }
    let l = gc_list(&mut s, "", u32::MAX, false);
    assert_eq!(l.entries.len(), 1024);
    assert!(l.truncated && !l.next_marker.is_empty());

    let o = s.objects.entry(U.into()).or_default();
    for i in 1..=1500u64 {
        o.omap
            .insert(format!("{i:011}_u_b").into_bytes(), u.clone());
    }
    let r = uread(
        &mut s,
        &UsageReadOp {
            end_epoch: u64::MAX,
            max_entries: u32::MAX,
            ..Default::default()
        },
    );
    let ops: u64 = r.usage.values().map(|x| x.total.ops).sum();
    assert_eq!(ops, 1024);
    assert!(r.truncated);
}
