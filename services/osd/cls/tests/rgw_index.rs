// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls_rgw bucket-index scenarios (spec/cls_rgw.md) on MemCtx: init, prepare/complete, listing
//! (prefix/delimiter/marker/special namespace/EFBIG), guard/reshard-log, suggest, stats, check.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use cls::rgw::index::ERR_BUSY_RESHARDING;
use cls::rgw::keys;
use cls::rgw::types::*;
use common::*;
use denc::types::UTime;

const O: &str = ".dir.b1.0";

fn meta(size: u64) -> DirEntryMeta {
    DirEntryMeta {
        category: 1,
        size,
        accounted_size: size,
        mtime: UTime::new(7, 9),
        etag: "e".into(),
        ..Default::default()
    }
}
fn init() -> MemStore {
    let mut s = MemStore::new();
    ok(&mut s, O, "rgw", "bucket_init_index", &[]);
    s
}
fn hdr(s: &MemStore) -> DirHeader {
    d(&s.obj(O).unwrap().omap_header)
}
fn entry_at(s: &MemStore, idx: &[u8]) -> Option<DirEntry> {
    s.obj(O)?.omap.get(idx).map(|v| d(v))
}
fn entry(s: &MemStore, name: &str) -> Option<DirEntry> {
    entry_at(s, name.as_bytes())
}
fn prep(s: &mut MemStore, name: &str, tag: &str) -> i32 {
    let op = ObjPrepareOp {
        op: op::ADD,
        tag: tag.into(),
        locator: "loc".into(),
        key: ObjKey::new(name, ""),
        ..Default::default()
    };
    call(s, O, "rgw", "bucket_prepare_op", &e(&op)).ret
}
fn complete_with(s: &mut MemStore, name: &str, tag: &str, o: u8, size: u64, epoch: u64) -> i32 {
    let op = ObjCompleteOp {
        op: o,
        ver: EntryVer { pool: 3, epoch },
        meta: meta(size),
        op_tag: tag.into(),
        key: ObjKey::new(name, ""),
        ..Default::default()
    };
    call(s, O, "rgw", "bucket_complete_op", &e(&op)).ret
}
/// prepare + complete(ADD) like a PUT.
fn put(s: &mut MemStore, name: &str, size: u64) {
    assert_eq!(prep(s, name, "t"), 0);
    assert_eq!(complete_with(s, name, "t", op::ADD, size, 0), 0);
}
fn list_op(n: u32, prefix: &str, delim: &str, start: impl AsRef<[u8]>, versions: bool) -> Vec<u8> {
    e(&ListOp {
        num_entries: n,
        filter_prefix: prefix.into(),
        start_obj: ObjKey::from_bytes(start.as_ref(), b""),
        list_versions: versions,
        delimiter: delim.into(),
    })
}
fn list(s: &mut MemStore, op: &[u8]) -> (i32, ListRet) {
    let r = call(s, O, "rgw", "bucket_list", op);
    (r.ret, d(&r.out))
}
fn names(l: &ListRet) -> Vec<String> {
    l.dir
        .m
        .keys()
        .map(|k| String::from_utf8_lossy(k).into_owned())
        .collect()
}
fn raw_put(s: &mut MemStore, k: &[u8], en: &DirEntry) {
    s.objects
        .entry(O.into())
        .or_default()
        .omap
        .insert(k.to_vec(), e(en));
}
fn plain(name: &str) -> DirEntry {
    DirEntry {
        key: ObjKey::new(name, ""),
        exists: true,
        meta: meta(1),
        ..Default::default()
    }
}

#[test]
fn registry_flags() {
    use cls::registry::*;
    for (m, f) in [
        ("bucket_init_index", RW),
        ("bucket_init_index2", RW),
        ("bucket_set_tag_timeout", RW),
        ("bucket_list", RD),
        ("bucket_check_index", RD),
        ("bucket_rebuild_index", RW),
        ("bucket_update_stats", RW),
        ("bucket_prepare_op", RW),
        ("bucket_complete_op", RW),
        ("obj_remove", RW),
        ("obj_store_pg_ver", WR),
        ("obj_check_attrs_prefix", RD),
        ("obj_check_mtime", RD),
        ("reshard_log_trim", RW),
        ("dir_suggest_changes", RW),
        ("set_bucket_resharding", RW),
        ("clear_bucket_resharding", RW),
        ("guard_bucket_resharding", RD),
        ("get_bucket_resharding", RD),
    ] {
        assert_eq!(lookup("rgw", m).unwrap().flags, f, "{m}");
    }
    assert!(lookup("rgw", "bucket_link_olh").is_some());
    assert!(lookup("rgw", "set_bucket_resharding2").is_none());
}

#[test]
fn init_index_header_bytes() {
    let mut s = MemStore::new();
    ok(&mut s, O, "rgw", "bucket_init_index2", &[]);
    // ENCODE_START(8,2): stats{} tag_timeout ver=1 master_ver max_marker "" new_instance(3,1) sync reshardlog
    let want = cat(&[
        &[8, 2, 52, 0, 0, 0],
        &[0, 0, 0, 0],
        &u64b(0),
        &u64b(1),
        &u64b(0),
        &[0, 0, 0, 0],
        &[3, 1, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
        &[0],
        &[0, 0, 0, 0],
    ]);
    assert_eq!(s.obj(O).unwrap().omap_header, want);
    // second init: already initialised
    err(&mut s, O, "rgw", "bucket_init_index", &[], EINVAL);
    assert_eq!(hdr(&s).ver, 1);
}

#[test]
fn prepare_entry_exact_bytes_and_header_untouched() {
    let mut s = init();
    assert_eq!(prep(&mut s, "obj", "t1"), 0);
    let ts = [&1_800_000_000u32.to_le_bytes()[..], &5000u32.to_le_bytes()].concat();
    let want = cat(&[
        &[8, 3, 146, 0, 0, 0],
        &[3, 0, 0, 0, b'o', b'b', b'j'], // key.name
        &u64b(0),                        // ver.epoch
        &[0],                            // exists
        // meta (8,3) default: 59 byte body
        &[8, 3, 59, 0, 0, 0],
        &[0],
        &u64b(0),
        &[0; 8],
        &[0; 4],
        &[0; 4],
        &[0; 4],
        &[0; 4],
        &u64b(0),
        &[0; 4],
        &[0; 4],
        &[0, 0],
        &[0; 8],
        // pending_map {t1: (state 0, ts, op 0)}
        &[1, 0, 0, 0, 2, 0, 0, 0, b't', b'1'],
        &[2, 2, 10, 0, 0, 0, 0],
        &ts,
        &[0],
        &[3, 0, 0, 0, b'l', b'o', b'c'], // locator "loc"
        &[
            1, 1, 10, 0, 0, 0, 0x88, 255, 255, 255, 255, 255, 255, 255, 255, 0,
        ], // ver {-1,0}
        &[0],                            // index_ver packed 0
        &[0; 4],                         // tag
        &[0; 4],                         // instance
        &[0, 0],                         // flags
        &[0; 8],                         // versioned_epoch
    ]);
    // fix lengths derived by hand: locator adds 3 bytes
    let mut want = want;
    let body = (want.len() - 6) as u32;
    want[2..6].copy_from_slice(&body.to_le_bytes());
    assert_eq!(s.obj(O).unwrap().omap[&b"obj"[..]], want);
    // prepare never writes the header
    assert_eq!(hdr(&s).ver, 1);
    // empty tag is rejected
    assert_eq!(prep(&mut s, "obj", ""), EINVAL);
    // a second prepare with another tag accumulates (entry kept, locator not overwritten)
    assert_eq!(prep(&mut s, "obj", "t0"), 0);
    let en = entry(&s, "obj").unwrap();
    assert_eq!(
        en.pending.iter().map(|p| txt(&p.0)).collect::<Vec<_>>(),
        ["t0", "t1"],
        "multimap sorted by tag"
    );
}

#[test]
fn put_overwrite_delete_stats() {
    let mut s = init();
    put(&mut s, "a", 5000);
    let h = hdr(&s);
    assert_eq!(h.ver, 2, "complete bumps ver once");
    let st = h.stats[&1];
    assert_eq!(
        (
            st.num_entries,
            st.total_size,
            st.total_size_rounded,
            st.actual_size
        ),
        (1, 5000, 8192, 5000)
    );
    let en = entry(&s, "a").unwrap();
    assert!(en.exists && en.pending.is_empty());
    assert_eq!(en.index_ver, 1, "index_ver = header.ver before the bump");
    assert_eq!(txt(&en.tag), "t");
    assert_eq!(en.ver, EntryVer { pool: 3, epoch: 0 });
    // overwrite with another size: old accounting removed
    put(&mut s, "a", 100);
    let st = hdr(&s).stats[&1];
    assert_eq!(
        (st.num_entries, st.total_size, st.total_size_rounded),
        (1, 100, 4096)
    );
    // delete: entry and accounting gone, category slot remains
    assert_eq!(prep(&mut s, "a", "d"), 0);
    assert_eq!(complete_with(&mut s, "a", "d", op::DEL, 0, 0), 0);
    assert!(entry(&s, "a").is_none());
    let st = hdr(&s).stats[&1];
    assert_eq!(
        (
            st.num_entries,
            st.total_size,
            st.total_size_rounded,
            st.actual_size
        ),
        (0, 0, 0, 0)
    );
}

#[test]
fn complete_error_branches_and_cancel() {
    let mut s = init();
    // tag not pending -> EINVAL, nothing changes
    put(&mut s, "a", 10);
    let before = s.obj(O).unwrap().clone();
    assert_eq!(complete_with(&mut s, "a", "nope", op::ADD, 10, 0), EINVAL);
    assert_eq!(s.obj(O).unwrap(), &before);
    // CANCEL of a fresh prepare on a missing object: entry (not exists, no pending) removed again
    assert_eq!(prep(&mut s, "b", "c1"), 0);
    assert!(entry(&s, "b").is_some());
    assert_eq!(complete_with(&mut s, "b", "c1", op::CANCEL, 0, 0), 0);
    assert!(entry(&s, "b").is_none());
    // CANCEL on an existing entry keeps it and drops only the tag
    assert_eq!(prep(&mut s, "a", "c2"), 0);
    assert_eq!(complete_with(&mut s, "a", "c2", op::CANCEL, 0, 0), 0);
    let en = entry(&s, "a").unwrap();
    assert!(en.exists && en.pending.is_empty());
    // untagged CANCEL changes no entry
    let snap = s.obj(O).unwrap().omap.clone();
    assert_eq!(complete_with(&mut s, "a", "", op::CANCEL, 0, 0), 0);
    assert_eq!(s.obj(O).unwrap().omap, snap);
    // old epoch (same pool, epoch <= stored) turns an ADD into a cancel: stats stay
    assert_eq!(prep(&mut s, "e", "t"), 0);
    assert_eq!(complete_with(&mut s, "e", "t", op::ADD, 10, 50), 0);
    assert_eq!(prep(&mut s, "e", "t2"), 0);
    assert_eq!(complete_with(&mut s, "e", "t2", op::ADD, 999, 40), 0);
    assert_eq!(entry(&s, "e").unwrap().meta.size, 10, "older epoch skipped");
    assert_eq!(hdr(&s).stats[&1].num_entries, 2);
}

#[test]
fn delete_with_other_pending_keeps_entry() {
    let mut s = init();
    put(&mut s, "a", 10);
    assert_eq!(prep(&mut s, "a", "t1"), 0);
    assert_eq!(prep(&mut s, "a", "t2"), 0);
    assert_eq!(complete_with(&mut s, "a", "t1", op::DEL, 0, 0), 0);
    let en = entry(&s, "a").unwrap();
    assert!(!en.exists, "pending t2 keeps the entry, marked !exists");
    assert_eq!(en.pending.len(), 1);
    assert_eq!(hdr(&s).stats[&1].num_entries, 0);
}

#[test]
fn complete_remove_objs_ignores_errors() {
    let mut s = init();
    put(&mut s, "p1", 10);
    put(&mut s, "p2", 20);
    assert_eq!(prep(&mut s, "m", "t"), 0);
    let op = ObjCompleteOp {
        op: op::ADD,
        meta: meta(5),
        op_tag: "t".into(),
        key: ObjKey::new("m", ""),
        remove_objs: vec![
            ObjKey::new("p1", ""),
            ObjKey::new("missing", ""),
            ObjKey::new("p2", ""),
        ],
        ..Default::default()
    };
    assert_eq!(call(&mut s, O, "rgw", "bucket_complete_op", &e(&op)).ret, 0);
    assert!(entry(&s, "p1").is_none() && entry(&s, "p2").is_none());
    let st = hdr(&s).stats[&1];
    assert_eq!((st.num_entries, st.total_size), (1, 5));
}

#[test]
fn bilog_written_when_log_op() {
    let mut s = init();
    s.env.version = 412;
    s.env.subop = 1;
    assert_eq!(prep(&mut s, "a", "t"), 0);
    let op = ObjCompleteOp {
        op: op::ADD,
        ver: EntryVer { pool: 3, epoch: 9 },
        meta: meta(5),
        op_tag: "t".into(),
        key: ObjKey::new("a", ""),
        log_op: true,
        bilog_flags: 1,
        zones_trace: ZoneSet(vec!["z1".into()]),
        ..Default::default()
    };
    assert_eq!(call(&mut s, O, "rgw", "bucket_complete_op", &e(&op)).ret, 0);
    // subop = 1 outer op + 3 nested primitives before the log write (header, entry read, write)
    let key = b"\x800_00000000001.412.4".to_vec();
    let v = s.obj(O).unwrap().omap.get(&key).expect("bilog key");
    let b: BiLogEntry = d(v);
    assert_eq!(txt(&b.id), "00000000001.412.4");
    assert_eq!(
        (b.object.as_slice(), b.op, b.state, b.index_ver),
        (&b"a"[..], op::ADD, state::COMPLETE, 1)
    );
    assert_eq!(b.ver, EntryVer { pool: 3, epoch: 9 });
    assert_eq!(txt(&b.tag), "t");
    assert_eq!(b.bilog_flags, 1);
    assert_eq!(b.zones_trace.0, [b"z1"]);
    assert_eq!(b.timestamp, UTime::new(7, 9));
    assert_eq!(txt(&hdr(&s).max_marker), "00000000001.412.4");
    // syncstopped suppresses the log
    let mut h = hdr(&s);
    h.syncstopped = true;
    s.objects.get_mut(O).unwrap().omap_header = e(&h);
    assert_eq!(prep(&mut s, "b", "t"), 0);
    let mut op2 = op.clone();
    op2.key = ObjKey::new("b", "");
    assert_eq!(
        call(&mut s, O, "rgw", "bucket_complete_op", &e(&op2)).ret,
        0
    );
    let n = s
        .obj(O)
        .unwrap()
        .omap
        .keys()
        .filter(|k| k.starts_with(keys::BILOG))
        .count();
    assert_eq!(n, 1);
}

// ------------------------------------------------------------------ listing

#[test]
fn list_basic_paging_and_marker() {
    let mut s = init();
    for i in 0..10 {
        put(&mut s, &format!("k{i}"), i);
    }
    let (r, l) = list(&mut s, &list_op(4, "", "", "", false));
    assert_eq!(r, 0);
    assert_eq!(names(&l), ["k0", "k1", "k2", "k3"]);
    assert!(l.is_truncated);
    assert_eq!(l.marker.name, b"k3");
    assert_eq!(l.dir.header.ver, 11, "header is returned with the page");
    let (_, l2) = list(&mut s, &list_op(4, "", "", &l.marker.name, false));
    assert_eq!(names(&l2), ["k4", "k5", "k6", "k7"]);
    let (_, l3) = list(&mut s, &list_op(4, "", "", "k7", false));
    assert_eq!(names(&l3), ["k8", "k9"]);
    assert!(!l3.is_truncated);
    assert_eq!(l3.marker, ObjKey::default());
    // exact fit is not truncated... but a full page with more behind it is
    let (_, l4) = list(&mut s, &list_op(10, "", "", "", false));
    assert_eq!(names(&l4).len(), 10);
    // num_entries = 0: header only
    let (r, l0) = list(&mut s, &list_op(0, "", "", "", false));
    assert_eq!(r, 0);
    assert!(l0.dir.m.is_empty() && !l0.is_truncated);
    assert_eq!(l0.dir.header.stats[&1].num_entries, 10);
}

#[test]
fn list_prefix_filter() {
    let mut s = init();
    for n in ["a1", "a2", "b1", "b2", "ba"] {
        put(&mut s, n, 1);
    }
    let (_, l) = list(&mut s, &list_op(100, "b", "", "", false));
    assert_eq!(names(&l), ["b1", "b2", "ba"]);
    let (_, l) = list(&mut s, &list_op(100, "zz", "", "", false));
    assert!(names(&l).is_empty() && !l.is_truncated);
}

#[test]
fn list_delimiter_common_prefixes() {
    let mut s = init();
    for n in ["a", "d1/x", "d1/y", "d1/sub/z", "d2/x", "e", "f/"] {
        put(&mut s, n, 1);
    }
    let (r, l) = list(&mut s, &list_op(100, "", "/", "", false));
    assert_eq!(r, 0);
    assert_eq!(names(&l), ["a", "d1/", "d2/", "e", "f/"]);
    let cp = &l.dir.m[&b"d1/"[..]];
    assert_eq!(cp.flags, flag::COMMON_PREFIX);
    assert_eq!(cp.key, ObjKey::new("d1/", ""));
    assert!(!cp.exists);
    // prefix + delimiter descends one level
    let (_, l) = list(&mut s, &list_op(100, "d1/", "/", "", false));
    assert_eq!(names(&l), ["d1/sub/", "d1/x", "d1/y"]);
    // pagination across common prefixes: the marker is the after-delim key
    let (_, l) = list(&mut s, &list_op(2, "", "/", "", false));
    assert_eq!(names(&l), ["a", "d1/"]);
    assert!(l.is_truncated);
    assert_eq!(l.marker.name, b"d1/\xff", "marker = after_delim");
}

#[test]
fn list_delimiter_marker_inside_and_after_prefix() {
    let mut s = init();
    for n in ["a", "d1/x", "d1/y", "d2/x", "e"] {
        put(&mut s, n, 1);
    }
    // client resumes from a returned common prefix "d1/": whole subtree skipped
    let (_, l) = list(&mut s, &list_op(100, "", "/", "d1/", false));
    assert_eq!(names(&l), ["d2/", "e"]);
    // resuming from inside a prefix without delimiter semantic (no skip when not ending with it)
    let (_, l) = list(&mut s, &list_op(100, "", "/", "d1/x", false));
    assert_eq!(
        names(&l),
        ["d1/", "d2/", "e"],
        "a marker inside d1/ still reports the prefix once"
    );
}

#[test]
fn list_skips_special_namespace_and_lists_high_region() {
    let mut s = init();
    put(&mut s, "a", 1);
    put(&mut s, "b", 1);
    // special keys sit between plain-low and plain-high
    raw_put(&mut s, b"\x800_00000000001.1.0", &plain("junk"));
    raw_put(&mut s, b"\x801000_a\0iv", &plain("a"));
    raw_put(&mut s, b"\x802001_a", &plain("a"));
    raw_put(&mut s, "é".as_bytes(), &plain("é"));
    raw_put(&mut s, "日本".as_bytes(), &plain("日本"));
    let (r, l) = list(&mut s, &list_op(100, "", "", "", false));
    assert_eq!(r, 0);
    assert_eq!(names(&l), ["a", "b", "é", "日本"]);
    // a page boundary right before the special area continues into the high region
    let (_, l) = list(&mut s, &list_op(2, "", "", "", false));
    assert_eq!(names(&l), ["a", "b"]);
    assert!(l.is_truncated);
    let (_, l) = list(&mut s, &list_op(2, "", "", "b", false));
    assert_eq!(names(&l), ["é", "日本"]);
    assert!(!l.is_truncated);
}

#[test]
fn list_pending_entries_are_listed() {
    let mut s = init();
    assert_eq!(prep(&mut s, "p", "t"), 0);
    let (_, l) = list(&mut s, &list_op(10, "", "", "", false));
    let en = &l.dir.m[&b"p"[..]];
    assert!(!en.exists);
    assert_eq!(
        en.pending.len(),
        1,
        "RGW decides via check_disk_state/suggest"
    );
}

#[test]
fn list_versions_visibility_and_jump() {
    let mut s = init();
    // name "v": marker placeholder + two list entries (newest first) + instance entries
    let mut cur = plain("v");
    cur.key = ObjKey::new("v", "i2");
    cur.flags = flag::VER | flag::CURRENT;
    cur.versioned_epoch = 20;
    let mut old = cur.clone();
    old.key.instance = "i1".into();
    old.flags = flag::VER;
    old.versioned_epoch = 10;
    let marker = DirEntry {
        key: ObjKey::new("v", ""),
        flags: flag::VER_MARKER,
        ..Default::default()
    };
    raw_put(&mut s, b"v", &marker);
    raw_put(&mut s, &keys::list_key(&cur), &cur);
    raw_put(&mut s, &keys::list_key(&old), &old);
    put(&mut s, "w", 1);
    // unversioned listing: marker skipped, noncurrent skipped, current shown, w shown
    let (_, l) = list(&mut s, &list_op(100, "", "", "", false));
    assert_eq!(l.dir.m.len(), 2);
    let k0 = l.dir.m.keys().next().unwrap().clone();
    assert_eq!(
        k0,
        keys::list_key(&cur),
        "version entries are keyed by their list key"
    );
    assert_eq!(l.dir.m[&k0].key, ObjKey::new("v", "i2"));
    // with versions: both versions, newest first, then w
    let (_, l) = list(&mut s, &list_op(100, "", "", "", true));
    let inst: Vec<String> = l
        .dir
        .m
        .values()
        .map(|e| String::from_utf8_lossy(&e.key.instance).into_owned())
        .collect();
    assert_eq!(inst, ["i2", "i1", ""]);
    // marker with instance resolves through the instance entry, else "name 01"
    raw_put(&mut s, &keys::instance_key(&cur.key, false), &cur);
    let op = e(&ListOp {
        num_entries: 100,
        start_obj: ObjKey::new("v", "i2"),
        list_versions: true,
        ..Default::default()
    });
    let (_, l) = list(&mut s, &op);
    let inst: Vec<String> = l
        .dir
        .m
        .values()
        .map(|e| String::from_utf8_lossy(&e.key.instance).into_owned())
        .collect();
    assert_eq!(inst, ["i1", ""], "resumes after version i2");
    let op = e(&ListOp {
        num_entries: 100,
        start_obj: ObjKey::new("v", "unknown"),
        list_versions: true,
        ..Default::default()
    });
    let (_, l) = list(&mut s, &op);
    assert_eq!(
        names(&l).len(),
        1,
        "unknown instance marker = after all versions of v"
    );
}

#[test]
fn list_efbig_with_output_when_no_progress() {
    let mut s = init();
    // 30 names whose only entries are noncurrent versions: nothing is ever visible
    for i in 0..30 {
        let mut en = plain(&format!("n{i:02}"));
        en.key.instance = "x".into();
        en.flags = flag::VER;
        en.versioned_epoch = 1;
        raw_put(&mut s, &keys::list_key(&en), &en);
    }
    let r = call(
        &mut s,
        O,
        "rgw",
        "bucket_list",
        &list_op(1, "", "", "", false),
    );
    assert_eq!(r.ret, EFBIG, "truncated and empty -> advance-and-retry");
    let out: ListRet = d(&r.out);
    assert!(out.is_truncated && out.dir.m.is_empty());
    assert_eq!(
        out.marker.name, b"n07\x01",
        "8 attempts, marker = after-versions key"
    );
    // the client retries from the marker and keeps advancing
    let r2 = call(
        &mut s,
        O,
        "rgw",
        "bucket_list",
        &list_op(1, "", "", "n07\u{1}", false),
    );
    assert_eq!(r2.ret, EFBIG);
    assert_eq!(d::<ListRet>(&r2.out).marker.name, b"n15\x01");
}

#[test]
fn list_corrupt_value_is_einval_and_bad_key_is_skipped() {
    let mut s = init();
    put(&mut s, "a", 1);
    s.objects
        .get_mut(O)
        .unwrap()
        .omap
        .insert(b"b".to_vec(), vec![1, 2, 3]);
    err(
        &mut s,
        O,
        "rgw",
        "bucket_list",
        &list_op(10, "", "", "", false),
        EINVAL,
    );
    s.objects.get_mut(O).unwrap().omap.remove(&b"b"[..]);
    // malformed list key (NUL without tokens) is skipped, scan continues
    raw_put(&mut s, b"c\0", &plain("c"));
    put(&mut s, "d", 1);
    let (r, l) = list(&mut s, &list_op(10, "", "", "", false));
    assert_eq!(r, 0);
    assert_eq!(names(&l), ["a", "d"]);
}

// ------------------------------------------------------------------ resharding guard + log

fn set_status(s: &mut MemStore, st: u8) {
    let op = SetReshardingOp {
        entry: InstanceEntry { reshard_status: st },
    };
    ok(s, O, "rgw", "set_bucket_resharding", &e(&op));
}

#[test]
fn guard_blocks_writes_with_2300() {
    let mut s = init();
    put(&mut s, "a", 1);
    let guard = |s: &mut MemStore, code: i32| {
        call(
            s,
            O,
            "rgw",
            "guard_bucket_resharding",
            &e(&GuardOp { ret_err: code }),
        )
        .ret
    };
    assert_eq!(guard(&mut s, ERR_BUSY_RESHARDING), 0);
    set_status(&mut s, reshard::IN_PROGRESS);
    assert_eq!(hdr(&s).new_instance.reshard_status, 1);
    assert_eq!(guard(&mut s, ERR_BUSY_RESHARDING), -2300);
    assert_eq!(guard(&mut s, -11), -11, "caller-supplied code");
    assert_eq!(prep(&mut s, "b", "t"), -2300);
    assert_eq!(complete_with(&mut s, "a", "t", op::ADD, 1, 0), -2300);
    assert_eq!(
        call(&mut s, O, "rgw", "dir_suggest_changes", &[]).ret,
        -2300
    );
    err(&mut s, O, "rgw", "bucket_rebuild_index", &[], -2300);
    // get/clear
    let r: GetReshardingRet = d(&ok(
        &mut s,
        O,
        "rgw",
        "get_bucket_resharding",
        &e(&EmptyOp {}),
    ));
    assert_eq!(r.new_instance.reshard_status, 1);
    ok(&mut s, O, "rgw", "clear_bucket_resharding", &e(&EmptyOp {}));
    assert_eq!(hdr(&s).new_instance, InstanceEntry::default());
    assert_eq!(prep(&mut s, "b", "t"), 0);
    // the guard result is delivered for -2300 although it is no errno (passthrough)
    let r = call(
        &mut s,
        O,
        "rgw",
        "guard_bucket_resharding",
        &e(&GuardOp {
            ret_err: ERR_BUSY_RESHARDING,
        }),
    );
    assert_eq!(r.ret, 0);
}

#[test]
fn logrecord_mode_logs_index_mutations_until_threshold() {
    let mut s = init();
    s.env.config.rgw_reshardlog_threshold = 3;
    set_status(&mut s, reshard::IN_LOGRECORD);
    // PUT: prepare logs 1, complete logs 1 (set)
    put(&mut s, "a", 10);
    let h = hdr(&s);
    assert_eq!(
        h.reshardlog_entries, 1,
        "prepare's count is lost: header is not rewritten by it"
    );
    let logk = keys::reshard_log_key(b"a");
    let le: BiEntry = d(s.obj(O).unwrap().omap.get(&logk).expect("reshard log key"));
    assert_eq!((le.ty, le.idx.as_slice()), (bi::INVALID, &b"a"[..]));
    let stored = s.obj(O).unwrap().omap[&b"a"[..]].clone();
    assert_eq!(le.data, stored, "log value = the written bytes");
    // delete: tombstone of type ReshardDeleted
    assert_eq!(prep(&mut s, "a", "d"), 0);
    assert_eq!(complete_with(&mut s, "a", "d", op::DEL, 0, 0), 0);
    let le: BiEntry = d(s.obj(O).unwrap().omap.get(&logk).unwrap());
    assert_eq!(le.ty, bi::RESHARD_DELETED);
    let del: DeletedEntry = d(&le.data);
    assert_eq!(del.key, ObjKey::new("a", ""));
    // count reaches the threshold -> writes blocked
    assert_eq!(hdr(&s).reshardlog_entries, 2);
    put(&mut s, "b", 1);
    assert_eq!(hdr(&s).reshardlog_entries, 3);
    assert_eq!(prep(&mut s, "x", "t"), -2300);
    // trim drops the log, resets the counter, then ENODATA
    ok(&mut s, O, "rgw", "reshard_log_trim", &[]);
    assert_eq!(hdr(&s).reshardlog_entries, 0);
    assert!(
        s.obj(O)
            .unwrap()
            .omap
            .keys()
            .all(|k| !k.starts_with(keys::RESHARD_LOG))
    );
    err(&mut s, O, "rgw", "reshard_log_trim", &[], ENODATA);
    assert_eq!(prep(&mut s, "x", "t"), 0);
}

// ------------------------------------------------------------------ suggest / stats / check

fn suggest(opb: u8, en: &DirEntry) -> Vec<u8> {
    let mut v = vec![opb];
    v.extend(e(en));
    v
}

#[test]
fn suggest_update_remove_and_pending_rules() {
    let mut s = init();
    // 1) unknown key: silently skipped
    let mut ch = plain("ghost");
    assert_eq!(
        call(&mut s, O, "rgw", "dir_suggest_changes", &suggest(b'u', &ch)).ret,
        0
    );
    assert!(entry(&s, "ghost").is_none());
    // 2) entry with a fresh pending op: no change
    assert_eq!(prep(&mut s, "p", "t"), 0);
    ch = plain("p");
    ch.meta = meta(77);
    assert_eq!(
        call(&mut s, O, "rgw", "dir_suggest_changes", &suggest(b'u', &ch)).ret,
        0
    );
    assert!(!entry(&s, "p").unwrap().exists);
    assert_eq!(hdr(&s).ver, 1, "no header write without change");
    // 3) after the tag timeout (default 120 s) the pending op is expired -> update applies
    s.advance(121);
    assert_eq!(
        call(&mut s, O, "rgw", "dir_suggest_changes", &suggest(b'u', &ch)).ret,
        0
    );
    let en = entry(&s, "p").unwrap();
    assert!(
        en.exists && en.pending.is_empty(),
        "suggestion replaces the whole entry"
    );
    assert_eq!(en.index_ver, 1);
    assert_eq!(hdr(&s).stats[&1].total_size, 77);
    assert_eq!(hdr(&s).ver, 2);
    // 4) older suggestion (index_ver < on-disk) is skipped
    let mut stale = plain("p");
    stale.index_ver = 0;
    stale.meta = meta(5);
    put(&mut s, "q", 9);
    let q_ver = entry(&s, "q").unwrap().index_ver;
    let mut older = plain("q");
    older.index_ver = q_ver - 1;
    assert_eq!(
        call(
            &mut s,
            O,
            "rgw",
            "dir_suggest_changes",
            &suggest(b'r', &older)
        )
        .ret,
        0
    );
    assert!(entry(&s, "q").is_some(), "stale removal suggestion ignored");
    // 5) remove: unaccounts + deletes (+ bilog when flagged)
    let mut rm = plain("q");
    rm.index_ver = q_ver;
    s.env.version = 5;
    assert_eq!(
        call(
            &mut s,
            O,
            "rgw",
            "dir_suggest_changes",
            &suggest(b'r' | 0x80, &rm)
        )
        .ret,
        0
    );
    assert!(entry(&s, "q").is_none());
    assert_eq!(hdr(&s).stats[&1].num_entries, 1);
    let nbilog = s
        .obj(O)
        .unwrap()
        .omap
        .keys()
        .filter(|k| k.starts_with(keys::BILOG))
        .count();
    assert_eq!(nbilog, 1);
    // garbage input
    err(
        &mut s,
        O,
        "rgw",
        "dir_suggest_changes",
        &[b'u', 1, 2],
        EINVAL,
    );
}

#[test]
fn tag_timeout_changes_expiry() {
    let mut s = init();
    ok(
        &mut s,
        O,
        "rgw",
        "bucket_set_tag_timeout",
        &e(&TagTimeoutOp { tag_timeout: 10 }),
    );
    assert_eq!((hdr(&s).tag_timeout, hdr(&s).ver), (10, 2));
    assert_eq!(prep(&mut s, "p", "t"), 0);
    s.advance(5);
    let mut ch = plain("p");
    ch.meta = meta(3);
    call(&mut s, O, "rgw", "dir_suggest_changes", &suggest(b'u', &ch));
    assert!(
        !entry(&s, "p").unwrap().exists,
        "not yet expired (5s < 10s)"
    );
    s.advance(6);
    call(&mut s, O, "rgw", "dir_suggest_changes", &suggest(b'u', &ch));
    assert!(entry(&s, "p").unwrap().exists, "expired after 11s > 10s");
}

#[test]
fn update_stats_absolute_incremental_and_dec() {
    let mut s = init();
    let st = |n, sz| CategoryStats {
        total_size: sz,
        total_size_rounded: sz,
        num_entries: n,
        actual_size: sz,
    };
    let mut op = UpdateStatsOp {
        absolute: true,
        ..Default::default()
    };
    op.stats.insert(1, st(5, 50));
    ok(&mut s, O, "rgw", "bucket_update_stats", &e(&op));
    assert_eq!(hdr(&s).stats[&1], st(5, 50));
    op.absolute = false;
    op.stats.insert(1, st(2, 20));
    op.dec_stats.insert(1, st(1, 5));
    op.dec_stats.insert(2, st(1, 1)); // underflows: wrapping, slot created
    ok(&mut s, O, "rgw", "bucket_update_stats", &e(&op));
    assert_eq!(hdr(&s).stats[&1], st(6, 65));
    assert_eq!(hdr(&s).stats[&2].num_entries, u64::MAX);
    // absolute + dec_stats is invalid and persists nothing
    let before = s.obj(O).unwrap().clone();
    op.absolute = true;
    err(&mut s, O, "rgw", "bucket_update_stats", &e(&op), EINVAL);
    assert_eq!(s.obj(O).unwrap(), &before);
}

#[test]
fn check_and_rebuild_index() {
    let mut s = init();
    put(&mut s, "a", 5000);
    put(&mut s, "b", 10);
    raw_put(&mut s, "é".as_bytes(), &plain("é")); // high region plain entry counts too
    // a versioned instance entry counts (exists), its list copy must not be double counted
    let mut vi = plain("v");
    vi.key.instance = "i1".into();
    vi.flags = flag::VER | flag::CURRENT;
    vi.versioned_epoch = 3;
    raw_put(&mut s, &keys::instance_key(&vi.key, false), &vi);
    raw_put(&mut s, &keys::list_key(&vi), &vi);
    let m = DirEntry {
        key: ObjKey::new("v", ""),
        flags: flag::VER_MARKER,
        ..Default::default()
    };
    raw_put(&mut s, b"v", &m);
    // corrupt the header stats to see the difference
    let mut h = hdr(&s);
    h.stats.insert(
        1,
        CategoryStats {
            num_entries: 99,
            ..Default::default()
        },
    );
    h.max_marker = "keepme".into();
    h.tag_timeout = 77;
    s.objects.get_mut(O).unwrap().omap_header = e(&h);
    let ret: CheckIndexRet = d(&ok(&mut s, O, "rgw", "bucket_check_index", &[]));
    assert_eq!(ret.existing_header.stats[&1].num_entries, 99);
    let calc = ret.calculated_header;
    assert_eq!(calc.stats[&1].num_entries, 4);
    assert_eq!(calc.stats[&1].total_size, 5000 + 10 + 1 + 1);
    assert_eq!(calc.stats[&1].total_size_rounded, 8192 + 4096 + 4096 + 4096);
    assert_eq!((calc.tag_timeout, calc.ver), (77, h.ver));
    assert_eq!(calc.max_marker, b"", "max_marker not copied");
    // rebuild writes the calculated header (ver + 1), resets max_marker
    ok(&mut s, O, "rgw", "bucket_rebuild_index", &[]);
    let h2 = hdr(&s);
    assert_eq!(h2.stats[&1].num_entries, 4);
    assert_eq!((h2.ver, txt(&h2.max_marker)), (h.ver + 1, ""));
}

#[test]
fn check_index_scans_beyond_one_chunk() {
    let mut s = init();
    for i in 0..2500u32 {
        raw_put(&mut s, format!("o{i:05}").as_bytes(), &plain("x"));
    }
    let ret: CheckIndexRet = d(&ok(&mut s, O, "rgw", "bucket_check_index", &[]));
    assert_eq!(ret.calculated_header.stats[&1].num_entries, 2500);
}

#[test]
fn list_many_entries_across_omap_pages() {
    let mut s = init();
    for i in 0..3000u32 {
        raw_put(
            &mut s,
            format!("o{i:05}").as_bytes(),
            &plain(&format!("o{i:05}")),
        );
    }
    // ask for more than the 1024 omap page cap: attempts loop fills it (3 pages)
    let (r, l) = list(&mut s, &list_op(2500, "", "", "", false));
    assert_eq!(r, 0);
    assert_eq!(l.dir.m.len(), 2500);
    assert!(l.is_truncated);
    assert_eq!(l.marker.name, b"o02499");
}

#[test]
fn suggest_two_logged_changes_in_one_message_keep_both_bilog_entries() {
    // classic: the bilog id's last part is cls_current_subop_num = ops processed so far in the
    // message INCLUDING nested cls_cxx_* calls, so two log writes of one method never share an id
    // (header.ver is not bumped inside the suggest loop)
    let mut s = init();
    put(&mut s, "a", 1);
    put(&mut s, "b", 2);
    let (mut a, mut b) = (entry(&s, "a").unwrap(), entry(&s, "b").unwrap());
    a.meta = meta(10);
    b.meta = meta(20);
    let mut input = suggest(b'u' | 0x80, &a);
    input.extend(suggest(b'u' | 0x80, &b));
    assert_eq!(call(&mut s, O, "rgw", "dir_suggest_changes", &input).ret, 0);
    let logs: Vec<BiLogEntry> = s
        .obj(O)
        .unwrap()
        .omap
        .iter()
        .filter(|(k, _)| k.starts_with(keys::BILOG))
        .map(|(_, v)| d(v))
        .collect();
    let names: Vec<&[u8]> = logs.iter().map(|l| l.object.as_slice()).collect();
    assert_eq!(names.len(), 2, "both suggestions logged: {names:?}");
    assert!(names.contains(&&b"a"[..]) && names.contains(&&b"b"[..]));
    assert_ne!(logs[0].id, logs[1].id);
}
