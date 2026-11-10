// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls_user scenarios (spec/cls_user.md) on MemCtx + codec vectors.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use cls::user::*;
use common::*;
use denc::types::UTime;
use denc::{Decode, Decoder};

const O: &str = "u1.buckets";
const ACC: &str = "account.roles";

fn s(x: &str) -> Vec<u8> {
    [&(x.len() as u32).to_le_bytes()[..], x.as_bytes()].concat()
}
fn bucket(name: &str) -> UserBucket {
    UserBucket {
        name: name.into(),
        marker: "m".into(),
        bucket_id: format!("id-{name}").into_bytes(),
        ..Default::default()
    }
}
fn bent(name: &str, size: u64, count: u64) -> BucketEntry {
    BucketEntry {
        bucket: bucket(name),
        size,
        size_rounded: size.div_ceil(4096) * 4096,
        count,
        creation_time: UTime::new(1_700_000_000, 123),
        user_stats_sync: false,
    }
}
fn set(st: &mut MemStore, entries: Vec<BucketEntry>, add: bool, t: u32) -> i32 {
    let op = SetBucketsOp {
        entries,
        add,
        time: UTime::new(t, 0),
    };
    call(st, O, "user", "set_buckets_info", &e(&op)).ret
}
fn header(st: &mut MemStore) -> Header {
    let r: GetHeaderRet = d(&ok(st, O, "user", "get_header", &e(&GetHeaderOp {})));
    r.header
}
fn list(st: &mut MemStore, marker: impl Into<Vec<u8>>, max: i32, end: &str) -> ListBucketsRet {
    let op = ListBucketsOp {
        marker: marker.into(),
        max_entries: max,
        end_marker: end.into(),
    };
    d(&ok(st, O, "user", "list_buckets", &e(&op)))
}

#[test]
fn registry_flags() {
    use cls::registry::*;
    assert_eq!(methods("user").len(), 11);
    for m in [
        "list_buckets",
        "get_header",
        "account_resource_get",
        "account_resource_list",
    ] {
        assert_eq!(lookup("user", m).unwrap().flags, RD, "{m}");
    }
    for m in [
        "set_buckets_info",
        "complete_stats_sync",
        "remove_bucket",
        "reset_user_stats",
        "reset_user_stats2",
        "account_resource_add",
        "account_resource_rm",
    ] {
        assert_eq!(lookup("user", m).unwrap().flags, RW, "{m}");
    }
}

#[test]
fn bucket_codec_two_write_forms_and_legacy_decodes() {
    // no placement_id: v7/c3 with explicit-placement pools
    let b = UserBucket {
        name: "b".into(),
        marker: "m".into(),
        bucket_id: "id".into(),
        data_pool: "dp".into(),
        index_pool: "ip".into(),
        data_extra_pool: "xp".into(),
        ..Default::default()
    };
    let body = cat(&[&s("b"), &s("dp"), &s("m"), &s("id"), &s("ip"), &s("xp")]);
    let want = cat(&[&[7, 3], &(body.len() as u32).to_le_bytes(), &body]);
    assert_eq!(e(&b), want);
    assert_eq!(d::<UserBucket>(&want), b);
    // placement_id set: v9/c8 {name, marker, bucket_id, placement_id}
    let b9 = UserBucket {
        placement_id: "pl".into(),
        data_pool: "ignored".into(),
        ..b.clone()
    };
    let body = cat(&[&s("b"), &s("m"), &s("id"), &s("pl")]);
    let want = cat(&[&[9, 8], &(body.len() as u32).to_le_bytes(), &body]);
    assert_eq!(e(&b9), want);
    let back: UserBucket = d(&want);
    assert_eq!((txt(&back.placement_id), txt(&back.data_pool)), ("pl", ""));
    // v3 envelope: bucket_id is a u64 rendered decimal; index_pool = data_pool
    let body = cat(&[&s("b"), &s("dp"), &s("m"), &42u64.to_le_bytes()]);
    let v3 = cat(&[&[3, 3], &(body.len() as u32).to_le_bytes(), &body]);
    let back: UserBucket = d(&v3);
    assert_eq!((txt(&back.bucket_id), txt(&back.index_pool)), ("42", "dp"));
    // v1: no compat byte, no length at all
    let v1 = cat(&[&[1], &s("b"), &s("dp")]);
    let back: UserBucket = d(&v1);
    assert_eq!(
        (txt(&back.name), txt(&back.data_pool), txt(&back.index_pool)),
        ("b", "dp", "dp")
    );
    // v8 with empty placement_id still carries the explicit pools
    let body = cat(&[
        &s("b"),
        &s("m"),
        &s("id"),
        &s(""),
        &s("D"),
        &s("I"),
        &s("X"),
    ]);
    let v8 = cat(&[&[8, 3], &(body.len() as u32).to_le_bytes(), &body]);
    let back: UserBucket = d(&v8);
    assert_eq!(
        (
            txt(&back.data_pool),
            txt(&back.index_pool),
            txt(&back.data_extra_pool)
        ),
        ("D", "I", "X")
    );
    // too new: compat 9 > supported 8
    let body = s("b");
    let bad = cat(&[&[10, 9], &(body.len() as u32).to_le_bytes(), &body]);
    assert!(UserBucket::decode(&mut Decoder::new(&bad)).is_err());
}

#[test]
fn bucket_entry_exact_bytes() {
    let en = BucketEntry {
        bucket: UserBucket {
            name: "b".into(),
            ..Default::default()
        },
        size: 10,
        size_rounded: 4096,
        creation_time: UTime::new(5, 6),
        count: 3,
        user_stats_sync: true,
    };
    let bk = e(&en.bucket);
    let body = cat(&[
        &s(""),
        &10u64.to_le_bytes(),
        &5u32.to_le_bytes(), // time_t
        &3u64.to_le_bytes(),
        &bk,
        &4096u64.to_le_bytes(),
        &[1],
        &5u32.to_le_bytes(),
        &6u32.to_le_bytes(),
    ]);
    let want = cat(&[&[9, 5], &(body.len() as u32).to_le_bytes(), &body]);
    assert_eq!(e(&en), want);
    assert_eq!(d::<BucketEntry>(&want), en);
    // legacy v5 (pre time ns, pre sync flag): creation time derived from the u32
    let body = cat(&[
        &s(""),
        &10u64.to_le_bytes(),
        &77u32.to_le_bytes(),
        &3u64.to_le_bytes(),
        &bk,
        &4096u64.to_le_bytes(),
    ]);
    let v5 = cat(&[&[5, 5], &(body.len() as u32).to_le_bytes(), &body]);
    let back: BucketEntry = d(&v5);
    assert_eq!(
        (back.creation_time, back.user_stats_sync, back.size_rounded),
        (UTime::new(77, 0), false, 4096)
    );
}

#[test]
fn set_buckets_info_add_then_stats_update() {
    let mut st = MemStore::new();
    // stats update for an unknown bucket (add=false): skipped (racing removal), header written
    assert_eq!(set(&mut st, vec![bent("a", 100, 1)], false, 10), 0);
    assert!(list(&mut st, "", 100, "").entries.is_empty());
    // add: new entry, accounted into the header
    assert_eq!(
        set(
            &mut st,
            vec![bent("a", 100, 1), bent("b", 5000, 2)],
            true,
            20
        ),
        0
    );
    let l = list(&mut st, "", 100, "");
    assert_eq!(l.entries.len(), 2);
    assert!(l.entries.iter().all(|x| x.user_stats_sync));
    let h = header(&mut st);
    assert_eq!(
        (
            h.stats.total_entries,
            h.stats.total_bytes,
            h.stats.total_bytes_rounded
        ),
        (3, 5100, 4096 + 8192)
    );
    assert_eq!(h.last_stats_update, UTime::new(20, 0));
    // stats update: old accounting removed, new applied
    assert_eq!(set(&mut st, vec![bent("a", 300, 4)], false, 15), 0);
    let h = header(&mut st);
    assert_eq!((h.stats.total_entries, h.stats.total_bytes), (6, 5300));
    assert_eq!(
        h.last_stats_update,
        UTime::new(20, 0),
        "never moves backwards"
    );
    // re-add of an existing bucket keeps its stats but takes new bucket_id/creation_time
    let mut again = bent("a", 999, 9);
    again.bucket.bucket_id = "new-id".into();
    again.creation_time = UTime::new(1_800_000_000, 0);
    assert_eq!(set(&mut st, vec![again], true, 30), 0);
    let l = list(&mut st, "", 100, "");
    let a = &l.entries[0];
    assert_eq!(
        (a.size, a.count, txt(&a.bucket.bucket_id)),
        (300, 4, "new-id")
    );
    assert_eq!(a.creation_time.sec, 1_800_000_000);
    let h = header(&mut st);
    assert_eq!(
        (h.stats.total_entries, h.stats.total_bytes),
        (6, 5300),
        "stats unchanged by re-add"
    );
    // empty bucket name -> EINVAL
    let bad = BucketEntry::default();
    assert_eq!(set(&mut st, vec![bad], true, 40), EINVAL);
}

#[test]
fn remove_bucket_and_complete_stats_sync() {
    let mut st = MemStore::new();
    set(&mut st, vec![bent("a", 100, 1), bent("b", 200, 2)], true, 5);
    let rm = |st: &mut MemStore, n: &str| {
        ok(
            st,
            O,
            "user",
            "remove_bucket",
            &e(&RemoveBucketOp { bucket: bucket(n) }),
        );
    };
    rm(&mut st, "a");
    let h = header(&mut st);
    assert_eq!((h.stats.total_entries, h.stats.total_bytes), (2, 200));
    rm(&mut st, "a"); // idempotent
    rm(&mut st, "never-existed");
    assert_eq!(list(&mut st, "", 10, "").entries.len(), 1);
    ok(
        &mut st,
        O,
        "user",
        "complete_stats_sync",
        &e(&CompleteStatsSyncOp {
            time: UTime::new(99, 0),
        }),
    );
    assert_eq!(header(&mut st).last_stats_sync, UTime::new(99, 0));
    ok(
        &mut st,
        O,
        "user",
        "complete_stats_sync",
        &e(&CompleteStatsSyncOp {
            time: UTime::new(50, 0),
        }),
    );
    assert_eq!(header(&mut st).last_stats_sync, UTime::new(99, 0));
}

#[test]
fn list_buckets_paging_end_marker_and_garbage_entries() {
    let mut st = MemStore::new();
    let names = ["a", "b", "c", "d", "e"];
    set(
        &mut st,
        names.iter().map(|n| bent(n, 1, 1)).collect(),
        true,
        1,
    );
    let l = list(&mut st, "", 2, "");
    assert_eq!(
        l.entries
            .iter()
            .map(|x| txt(&x.bucket.name))
            .collect::<Vec<_>>(),
        ["a", "b"]
    );
    assert!(l.truncated);
    assert_eq!(txt(&l.marker), "b");
    let l = list(&mut st, "b", 2, "");
    assert_eq!(
        l.entries
            .iter()
            .map(|x| txt(&x.bucket.name))
            .collect::<Vec<_>>(),
        ["c", "d"]
    );
    let l = list(&mut st, "d", 2, "");
    assert!(!l.truncated && l.marker.is_empty());
    // end_marker is exclusive and ends the listing without truncation
    let l = list(&mut st, "", 10, "c");
    assert_eq!(l.entries.len(), 2);
    assert!(!l.truncated);
    // undecodable values are skipped silently
    st.objects
        .get_mut(O)
        .unwrap()
        .omap
        .insert(b"bb".to_vec(), vec![1, 2, 3]);
    let l = list(&mut st, "a", 10, "");
    assert_eq!(l.entries.len(), 4);
    // max_entries 0 returns nothing; negative = capped at 1000
    assert!(list(&mut st, "", 0, "").entries.is_empty());
    assert_eq!(list(&mut st, "", -1, "").entries.len(), 5);
}

#[test]
fn reset_user_stats_variants() {
    let mut st = MemStore::new();
    set(&mut st, vec![bent("a", 100, 1), bent("b", 200, 2)], true, 1);
    // corrupt the header stats, then rebuild
    let mut h = Header::default();
    h.stats.total_entries = 77;
    h.last_stats_sync = UTime::new(5, 0);
    st.objects.get_mut(O).unwrap().omap_header = e(&h);
    ok(
        &mut st,
        O,
        "user",
        "reset_user_stats",
        &e(&ResetStatsOp {
            time: UTime::new(9, 0),
        }),
    );
    let h = header(&mut st);
    assert_eq!((h.stats.total_entries, h.stats.total_bytes), (3, 300));
    assert_eq!(h.last_stats_update, UTime::new(9, 0));
    assert_eq!(
        h.last_stats_sync,
        UTime::default(),
        "legacy reset drops last_stats_sync"
    );
    // reset2: single page, complete result written into a FRESH header (classic does not read the
    // stored one: last_stats_sync is dropped as well)
    let mut h = header(&mut st);
    h.last_stats_sync = UTime::new(5, 0);
    st.objects.get_mut(O).unwrap().omap_header = e(&h);
    let op = ResetStats2Op {
        time: UTime::new(11, 0),
        marker: Vec::new(),
        acc_stats: Stats {
            total_entries: 1000,
            ..Default::default()
        }, // ignored
    };
    let r: ResetStats2Ret = d(&ok(&mut st, O, "user", "reset_user_stats2", &e(&op)));
    assert!(!r.truncated);
    assert_eq!(
        (r.acc_stats.total_entries, r.acc_stats.total_bytes),
        (3, 300)
    );
    let h = header(&mut st);
    assert_eq!(h.last_stats_update, UTime::new(11, 0));
    assert_eq!(
        h.last_stats_sync,
        UTime::default(),
        "reset2 drops last_stats_sync"
    );
    assert_eq!(h.stats.total_entries, 3);
}

#[test]
fn reset_user_stats2_pages_over_1000_entries() {
    let mut st = MemStore::new();
    for i in 0..1500u32 {
        let en = bent(&format!("b{i:05}"), 1, 1);
        st.objects
            .entry(O.into())
            .or_default()
            .omap
            .insert(format!("b{i:05}").into_bytes(), e(&en));
    }
    let op = ResetStats2Op {
        time: UTime::new(1, 0),
        ..Default::default()
    };
    let r1: ResetStats2Ret = d(&ok(&mut st, O, "user", "reset_user_stats2", &e(&op)));
    assert!(r1.truncated);
    assert_eq!(r1.acc_stats.total_entries, 1000);
    assert_eq!(txt(&r1.marker), "b00999");
    assert_eq!(
        header(&mut st).stats.total_entries,
        0,
        "header only written on the last page"
    );
    let op2 = ResetStats2Op {
        time: UTime::new(1, 0),
        marker: r1.marker,
        ..Default::default()
    };
    let r2: ResetStats2Ret = d(&ok(&mut st, O, "user", "reset_user_stats2", &e(&op2)));
    assert!(!r2.truncated);
    assert_eq!(
        r2.acc_stats.total_entries, 500,
        "accumulator is per page; the client sums"
    );
}

// ------------------------------------------------------------------ account resources

fn res(name: &str, path: &str) -> AccountResource {
    AccountResource {
        name: name.into(),
        path: path.into(),
        metadata: vec![1, 2, 3],
    }
}
fn radd(st: &mut MemStore, r: AccountResource, exclusive: bool, limit: u32) -> i32 {
    let op = AccountResourceAddOp {
        entry: r,
        exclusive,
        limit,
    };
    call(st, ACC, "user", "account_resource_add", &e(&op)).ret
}
fn acc_count(st: &MemStore) -> u32 {
    let h: AccountHeader = d(&st.obj(ACC).unwrap().omap_header);
    h.count
}

#[test]
fn account_resources_add_get_rm_limit() {
    let mut st = MemStore::new();
    assert_eq!(radd(&mut st, res("Alice", "/a/"), true, 2), 0);
    // key is the lowercased name
    assert!(st.obj(ACC).unwrap().omap.contains_key(&b"alice"[..]));
    assert_eq!(acc_count(&st), 1);
    // exclusive add of an existing name (case-insensitive) fails
    assert_eq!(radd(&mut st, res("ALICE", "/x/"), true, 2), EEXIST);
    // non-exclusive overwrite: count unchanged, entry replaced
    assert_eq!(radd(&mut st, res("ALICE", "/x/"), false, 2), 0);
    assert_eq!(acc_count(&st), 1);
    assert_eq!(radd(&mut st, res("bob", "/b/"), false, 2), 0);
    assert_eq!(acc_count(&st), 2);
    assert_eq!(
        radd(&mut st, res("carol", "/c/"), false, 2),
        EUSERS,
        "limit reached"
    );
    // get is case-insensitive and returns the stored (overwritten) entry with its original case
    let g: AccountResourceGetRet = d(&ok(
        &mut st,
        ACC,
        "user",
        "account_resource_get",
        &e(&AccountResourceGetOp {
            name: "aLiCe".into(),
        }),
    ));
    assert_eq!((txt(&g.entry.name), txt(&g.entry.path)), ("ALICE", "/x/"));
    err(
        &mut st,
        ACC,
        "user",
        "account_resource_get",
        &e(&AccountResourceGetOp { name: "zed".into() }),
        ENOENT,
    );
    // rm
    let rm = |st: &mut MemStore, n: &str| {
        call(
            st,
            ACC,
            "user",
            "account_resource_rm",
            &e(&AccountResourceRmOp { name: n.into() }),
        )
        .ret
    };
    assert_eq!(rm(&mut st, "ZED"), ENOENT);
    assert_eq!(rm(&mut st, "BOB"), 0);
    assert_eq!(acc_count(&st), 1);
    assert_eq!(rm(&mut st, "alice"), 0);
    assert_eq!(acc_count(&st), 0);
}

#[test]
fn account_resource_list_filters_by_path_and_marks_last_fetched() {
    let mut st = MemStore::new();
    for (n, p) in [
        ("a", "/x/"),
        ("b", "/y/"),
        ("c", "/x/"),
        ("d", "/x/y/"),
        ("e", "/z/"),
    ] {
        radd(&mut st, res(n, p), true, 100);
    }
    let list =
        |st: &mut MemStore, marker: &str, prefix: &str, max: u32| -> AccountResourceListRet {
            d(&ok(
                st,
                ACC,
                "user",
                "account_resource_list",
                &e(&AccountResourceListOp {
                    marker: marker.into(),
                    path_prefix: prefix.into(),
                    max_entries: max,
                }),
            ))
        };
    let l = list(&mut st, "", "/x/", 100);
    assert_eq!(
        l.entries.iter().map(|x| txt(&x.name)).collect::<Vec<_>>(),
        ["a", "c", "d"]
    );
    assert!(!l.truncated);
    assert_eq!(
        txt(&l.marker),
        "e",
        "marker = last fetched key, even if filtered out"
    );
    // a page can come back short: 2 fetched (a, b), only a matches
    let l = list(&mut st, "", "/x/", 2);
    assert_eq!(l.entries.len(), 1);
    assert!(l.truncated);
    assert_eq!(txt(&l.marker), "b");
    let l = list(&mut st, txt(&l.marker), "/x/", 2);
    assert_eq!(
        l.entries.iter().map(|x| txt(&x.name)).collect::<Vec<_>>(),
        ["c", "d"]
    );
}

#[test]
fn methods_reject_garbage() {
    let mut st = MemStore::new();
    for m in [
        "set_buckets_info",
        "complete_stats_sync",
        "remove_bucket",
        "list_buckets",
        "get_header",
        "reset_user_stats",
        "reset_user_stats2",
        "account_resource_add",
        "account_resource_get",
        "account_resource_rm",
        "account_resource_list",
    ] {
        err(&mut st, O, "user", m, &[0xff, 1], EINVAL);
    }
}

#[test]
fn dencoder_fixtures() {
    rt::<UserBucket>("cls_user_bucket");
    rt::<BucketEntry>("cls_user_bucket_entry");
    rt::<Stats>("cls_user_stats");
    rt::<Header>("cls_user_header");
    rt::<SetBucketsOp>("cls_user_set_buckets_op");
    rt::<RemoveBucketOp>("cls_user_remove_bucket_op");
    rt::<ListBucketsOp>("cls_user_list_buckets_op");
    rt::<ListBucketsRet>("cls_user_list_buckets_ret");
    rt::<GetHeaderOp>("cls_user_get_header_op");
    rt::<GetHeaderRet>("cls_user_get_header_ret");
    rt::<CompleteStatsSyncOp>("cls_user_complete_stats_sync_op");
    rt::<AccountHeader>("cls_user_account_header");
    rt::<AccountResource>("cls_user_account_resource");
    rt::<AccountResourceAddOp>("cls_user_account_resource_add_op");
    rt::<AccountResourceGetOp>("cls_user_account_resource_get_op");
    rt::<AccountResourceGetRet>("cls_user_account_resource_get_ret");
    rt::<AccountResourceListOp>("cls_user_account_resource_list_op");
    rt::<AccountResourceListRet>("cls_user_account_resource_list_ret");
    rt::<AccountResourceRmOp>("cls_user_account_resource_rm_op");
}
