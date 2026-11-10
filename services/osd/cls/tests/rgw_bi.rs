// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls_rgw raw index access (G6) and the in-index bilog (G7): bi_get/put/put_entries/list incl.
//! the reshard-log branch, bi_log_list/trim/resync/stop. MemCtx scenarios.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use cls::rgw::index::ERR_BUSY_RESHARDING;
use cls::rgw::keys;
use cls::rgw::types::*;
use common::*;
use denc::types::UTime;

const O: &str = ".dir.bi.0";

fn init() -> MemStore {
    let mut s = MemStore::new();
    ok(&mut s, O, "rgw", "bucket_init_index", &[]);
    s
}
fn meta(size: u64) -> DirEntryMeta {
    DirEntryMeta {
        category: 1,
        size,
        accounted_size: size,
        mtime: UTime::new(100, 0),
        ..Default::default()
    }
}
fn hdr(s: &MemStore) -> DirHeader {
    d(&s.obj(O).unwrap().omap_header)
}
fn raw(s: &mut MemStore, k: &[u8], v: Vec<u8>) {
    s.objects.get_mut(O).unwrap().omap.insert(k.to_vec(), v);
}
fn plain_entry(name: &[u8], size: u64) -> DirEntry {
    DirEntry {
        key: ObjKey::from_bytes(name, b""),
        exists: true,
        meta: meta(size),
        ..Default::default()
    }
}
fn bi_entry(ty: u8, idx: &[u8], en: &DirEntry) -> BiEntry {
    BiEntry {
        ty,
        idx: idx.to_vec(),
        data: e(en),
    }
}

/// Index with plain a, b, versioned v (instances v1, v2 + olh) and a non-ASCII plain name.
fn populated() -> (MemStore, Vec<Vec<u8>>) {
    let mut s = init();
    for n in [&b"a"[..], b"b", "\u{e9}x".as_bytes()] {
        raw(&mut s, n, e(&plain_entry(n, 10)));
    }
    let v1 = DirEntry {
        key: ObjKey::new("v", "v1"),
        exists: true,
        meta: meta(5),
        ..Default::default()
    };
    for i in ["v1", "v2"] {
        let en = DirEntry {
            key: ObjKey::new("v", i),
            ..v1.clone()
        };
        raw(&mut s, &keys::instance_key(&en.key, false), e(&en));
    }
    for i in [("v1", 7u64), ("v2", 8u64)] {
        let en = DirEntry {
            key: ObjKey::new("v", i.0),
            exists: true,
            meta: meta(5),
            flags: flag::VER,
            versioned_epoch: i.1,
            ..Default::default()
        };
        raw(&mut s, &keys::list_key(&en), e(&en));
    }
    raw(
        &mut s,
        b"v",
        e(&DirEntry {
            key: ObjKey::new("v", ""),
            flags: flag::VER_MARKER,
            ..Default::default()
        }),
    );
    let olh = OlhEntry {
        key: ObjKey::new("v", "v2"),
        epoch: 8,
        tag: "t".into(),
        exists: true,
        ..Default::default()
    };
    raw(&mut s, &keys::olh_key(&ObjKey::new("v", "")), e(&olh));
    let expect: Vec<Vec<u8>> = s.obj(O).unwrap().omap.keys().cloned().collect();
    (s, expect)
}
fn bi_list(s: &mut MemStore, max: u32, filter: &str, marker: &[u8], reshardlog: bool) -> BiListRet {
    let op = BiListOp {
        max,
        name_filter: filter.as_bytes().to_vec(),
        marker: marker.to_vec(),
        reshardlog,
    };
    d(&ok(s, O, "rgw", "bi_list", &e(&op)))
}
/// Marker for the next page = last idx (bytes; non-UTF-8 markers are not used by these tests).
fn paged(s: &mut MemStore, max: u32, filter: &str) -> Vec<BiEntry> {
    let mut out = Vec::new();
    let mut marker = Vec::new();
    for _ in 0..100 {
        let r = bi_list(s, max, filter, &marker, false);
        if let Some(l) = r.entries.last() {
            marker = l.idx.clone();
        }
        out.extend(r.entries);
        if !r.is_truncated {
            return out;
        }
    }
    panic!("paging did not terminate");
}

#[test]
fn registry_flags() {
    use cls::registry::*;
    for (m, f) in [
        ("bi_get", RD),
        ("bi_put", RW),
        ("bi_put_entries", RW),
        ("bi_list", RD),
        ("bi_log_list", RD),
        ("bi_log_trim", RW),
        ("bi_log_resync", RW),
        ("bi_log_stop", RW),
    ] {
        assert_eq!(lookup("rgw", m).unwrap().flags, f, "{m}");
    }
}

#[test]
fn bi_get_resolves_key_classes() {
    let (mut s, _) = populated();
    let get = |s: &mut MemStore, ty, name: &str, i: &str| {
        let op = BiGetOp {
            key: ObjKey::new(name, i),
            ty,
        };
        call(s, O, "rgw", "bi_get", &e(&op))
    };
    let r = get(&mut s, bi::PLAIN, "a", "");
    assert_eq!(r.ret, 0);
    let g: BiGetRet = d(&r.out);
    assert_eq!((g.entry.ty, g.entry.idx.as_slice()), (bi::PLAIN, &b"a"[..]));
    assert_eq!(d::<DirEntry>(&g.entry.data).key.name, b"a");
    // instance with an instance id -> the special-area key; empty instance -> the plain key
    let g: BiGetRet = d(&get(&mut s, bi::INSTANCE, "v", "v1").out);
    assert_eq!(
        g.entry.idx,
        keys::instance_key(&ObjKey::new("v", "v1"), false)
    );
    let g: BiGetRet = d(&get(&mut s, bi::INSTANCE, "a", "").out);
    assert_eq!(g.entry.idx, b"a");
    let g: BiGetRet = d(&get(&mut s, bi::OLH, "v", "ignored").out);
    assert_eq!(g.entry.idx, keys::olh_key(&ObjKey::new("v", "")));
    assert_eq!(d::<OlhEntry>(&g.entry.data).epoch, 8);
    assert_eq!(get(&mut s, bi::PLAIN, "nope", "").ret, ENOENT);
    assert_eq!(get(&mut s, bi::RESHARD_DELETED, "a", "").ret, EINVAL);
    assert_eq!(get(&mut s, 99, "a", "").ret, EINVAL);
}

#[test]
fn bi_put_is_raw_and_always_ok() {
    let mut s = init();
    let h0 = hdr(&s);
    let put = |s: &mut MemStore, ty, idx: &[u8], data: &[u8]| {
        let op = BiPutOp {
            entry: BiEntry {
                ty,
                idx: idx.to_vec(),
                data: data.to_vec(),
            },
        };
        ok(s, O, "rgw", "bi_put", &e(&op));
    };
    put(&mut s, bi::PLAIN, b"x", b"garbage"); // no validation, no stats, no header write
    assert_eq!(s.omap_get(O, "x"), Some(&b"garbage"[..]));
    assert_eq!(hdr(&s), h0);
    put(&mut s, bi::RESHARD_DELETED, b"x", b"");
    assert_eq!(s.omap_get(O, "x"), None);
    put(&mut s, bi::RESHARD_DELETED, b"never-existed", b""); // swallowed
    // even the special area is writable (reshard tooling)
    put(&mut s, bi::OLH, b"\x801001_q", b"1");
    assert!(s.obj(O).unwrap().omap.contains_key(&b"\x801001_q"[..]));
}

#[test]
fn bi_put_entries_accounts_stats_and_bumps_the_header() {
    let mut s = init();
    let inst_en = DirEntry {
        key: ObjKey::new("v", "i1"),
        exists: true,
        meta: meta(5),
        ..Default::default()
    };
    let gone = DirEntry {
        exists: false,
        ..inst_en.clone()
    };
    let op = BiPutEntriesOp {
        entries: vec![
            bi_entry(bi::PLAIN, b"a", &plain_entry(b"a", 10)),
            bi_entry(bi::PLAIN, b"b", &plain_entry(b"b", 20)),
            // not accounted: plain with flags, instance not existing, olh
            bi_entry(
                bi::PLAIN,
                b"m",
                &DirEntry {
                    flags: flag::VER_MARKER,
                    ..plain_entry(b"m", 99)
                },
            ),
            bi_entry(bi::INSTANCE, b"\x801000_v\0ig", &gone),
            // accounted instance
            bi_entry(bi::INSTANCE, b"\x801000_v\0ii1", &inst_en),
        ],
        check_existing: false,
    };
    ok(&mut s, O, "rgw", "bi_put_entries", &e(&op));
    let h = hdr(&s);
    let st = h.stats[&1];
    assert_eq!(
        (
            st.num_entries,
            st.total_size,
            st.total_size_rounded,
            st.actual_size
        ),
        (3, 35, 3 * 4096, 35)
    );
    assert_eq!(h.ver, 2);
    assert!(s.omap_get(O, "a").is_some());
    // check_existing: overwritten entries are un-accounted first
    let op = BiPutEntriesOp {
        entries: vec![bi_entry(bi::PLAIN, b"a", &plain_entry(b"a", 1000))],
        check_existing: true,
    };
    ok(&mut s, O, "rgw", "bi_put_entries", &e(&op));
    let st = hdr(&s).stats[&1];
    assert_eq!((st.num_entries, st.total_size), (3, 1025));
    // without check_existing the same overwrite double counts (reshard of a fresh shard only)
    let op = BiPutEntriesOp {
        entries: vec![bi_entry(bi::PLAIN, b"a", &plain_entry(b"a", 1000))],
        check_existing: false,
    };
    ok(&mut s, O, "rgw", "bi_put_entries", &e(&op));
    assert_eq!(hdr(&s).stats[&1].num_entries, 4);
}

#[test]
fn bi_put_entries_deleted_dups_limits_and_guard() {
    let mut s = init();
    raw(&mut s, b"gone", e(&plain_entry(b"gone", 1)));
    let op = BiPutEntriesOp {
        entries: vec![
            BiEntry {
                ty: bi::RESHARD_DELETED,
                idx: b"gone".to_vec(),
                data: Vec::new(),
            },
            bi_entry(bi::PLAIN, b"d", &plain_entry(b"d", 1)),
            bi_entry(bi::PLAIN, b"d", &plain_entry(b"d", 2)), // duplicate: first wins, both counted
        ],
        check_existing: false,
    };
    ok(&mut s, O, "rgw", "bi_put_entries", &e(&op));
    assert!(s.omap_get(O, "gone").is_none());
    assert_eq!(d::<DirEntry>(s.omap_get(O, "d").unwrap()).meta.size, 1);
    assert_eq!(hdr(&s).stats[&1].num_entries, 2);
    assert_eq!(hdr(&s).stats[&1].total_size, 3);
    // limit
    let many = BiPutEntriesOp {
        entries: (0..1025)
            .map(|i| bi_entry(bi::PLAIN, format!("k{i}").as_bytes(), &plain_entry(b"k", 1)))
            .collect(),
        check_existing: false,
    };
    err(&mut s, O, "rgw", "bi_put_entries", &e(&many), E2BIG);
    // undecodable value of an accounted type: refused, nothing written
    let before = s.objects.clone();
    let bad = BiPutEntriesOp {
        entries: vec![
            bi_entry(bi::PLAIN, b"ok", &plain_entry(b"ok", 1)),
            BiEntry {
                ty: bi::PLAIN,
                idx: b"bad".to_vec(),
                data: vec![1, 2, 3],
            },
        ],
        check_existing: false,
    };
    err(&mut s, O, "rgw", "bi_put_entries", &e(&bad), EIO);
    assert_eq!(s.objects, before);
    // guard
    let set = SetReshardingOp {
        entry: InstanceEntry {
            reshard_status: reshard::IN_PROGRESS,
        },
    };
    ok(&mut s, O, "rgw", "set_bucket_resharding", &e(&set));
    let op = BiPutEntriesOp::default();
    err(
        &mut s,
        O,
        "rgw",
        "bi_put_entries",
        &e(&op),
        ERR_BUSY_RESHARDING,
    );
}

#[test]
fn bi_list_walks_all_segments_in_key_order() {
    let (mut s, expect) = populated();
    let all = bi_list(&mut s, 100, "", b"", false);
    assert!(!all.is_truncated);
    let idxs: Vec<Vec<u8>> = all.entries.iter().map(|x| x.idx.clone()).collect();
    assert_eq!(idxs, expect);
    // segment types: plain-low, instance, olh, plain-high
    let tys: Vec<u8> = all.entries.iter().map(|x| x.ty).collect();
    assert_eq!(
        tys,
        vec![
            bi::PLAIN, // a
            bi::PLAIN, // b
            bi::PLAIN, // v (marker)
            bi::PLAIN, // v list entries
            bi::PLAIN,
            bi::INSTANCE,
            bi::INSTANCE,
            bi::OLH,
            bi::PLAIN, // non-ASCII name (high region)
        ]
    );
    // values verbatim
    assert_eq!(all.entries[0].data, e(&plain_entry(b"a", 10)));
    // paging reproduces the same sequence for any page size
    for max in [1, 2, 3, 4, 5, 8, 9, 100] {
        let got: Vec<Vec<u8>> = paged(&mut s, max, "").into_iter().map(|x| x.idx).collect();
        assert_eq!(got, expect, "page size {max}");
    }
    // truncation flag
    let p = bi_list(&mut s, 4, "", b"", false);
    assert!(p.is_truncated);
    assert_eq!(p.entries.len(), 4);
    // max above the cap is clamped (no panic), 0 yields nothing but reports truncation
    assert_eq!(bi_list(&mut s, u32::MAX, "", b"", false).entries.len(), 9);
    let z = bi_list(&mut s, 0, "", b"", false);
    assert!(z.entries.is_empty() && z.is_truncated);
}

#[test]
fn bi_list_name_filter_selects_one_name() {
    let (mut s, _) = populated();
    let got = paged(&mut s, 100, "v");
    let idxs: Vec<String> = got
        .iter()
        .map(|x| {
            String::from_utf8_lossy(&x.idx)
                .replace('\0', "|")
                .replace('\u{80}', "~")
        })
        .collect();
    assert_eq!(got.len(), 6, "{idxs:?}");
    assert_eq!(got[0].idx, b"v");
    assert_eq!(
        got[3].idx,
        keys::instance_key(&ObjKey::new("v", "v1"), false)
    );
    assert_eq!(
        got[4].idx,
        keys::instance_key(&ObjKey::new("v", "v2"), false)
    );
    assert_eq!(got[5].idx, keys::olh_key(&ObjKey::new("v", "")));
    // a name without versions: only its plain entry
    let got = paged(&mut s, 100, "a");
    assert_eq!(got.len(), 1);
    // same result when paged one entry at a time
    let one = paged(&mut s, 1, "v");
    assert_eq!(one.len(), 6);
}

#[test]
fn bi_list_reshardlog_branch() {
    let mut s = init();
    let set = SetReshardingOp {
        entry: InstanceEntry {
            reshard_status: reshard::IN_LOGRECORD,
        },
    };
    ok(&mut s, O, "rgw", "set_bucket_resharding", &e(&set));
    // writes while IN_LOGRECORD leave reshard-log twins (here via update_stats-free paths: raw puts
    // through complete_op)
    for n in ["a", "b"] {
        let p = ObjPrepareOp {
            op: op::ADD,
            tag: "t".into(),
            key: ObjKey::new(n, ""),
            ..Default::default()
        };
        ok(&mut s, O, "rgw", "bucket_prepare_op", &e(&p));
        let c = ObjCompleteOp {
            op_tag: "t".into(),
            key: ObjKey::new(n, ""),
            meta: meta(1),
            ..Default::default()
        };
        ok(&mut s, O, "rgw", "bucket_complete_op", &e(&c));
    }
    // delete 'a': tombstone
    let p = ObjPrepareOp {
        op: op::DEL,
        tag: "t".into(),
        key: ObjKey::new("a", ""),
        ..Default::default()
    };
    ok(&mut s, O, "rgw", "bucket_prepare_op", &e(&p));
    let c = ObjCompleteOp {
        op: op::DEL,
        op_tag: "t".into(),
        key: ObjKey::new("a", ""),
        ..Default::default()
    };
    ok(&mut s, O, "rgw", "bucket_complete_op", &e(&c));
    let all = bi_list(&mut s, 100, "", b"", true);
    assert!(!all.is_truncated);
    assert!(!all.entries.is_empty());
    let last_a = all.entries.iter().rev().find(|x| x.idx == b"a").unwrap();
    assert_eq!(last_a.ty, bi::RESHARD_DELETED); // tombstone keeps its type
    let b = all.entries.iter().find(|x| x.idx == b"b").unwrap();
    assert_eq!(b.ty, bi::PLAIN); // type derived from the original key
    // paging with marker = last idx of the previous page
    let mut seen = Vec::new();
    let mut marker = Vec::new();
    for _ in 0..20 {
        let r = bi_list(&mut s, 1, "", &marker, true);
        if let Some(l) = r.entries.last() {
            marker = l.idx.clone();
            seen.push(l.idx.clone());
        }
        if !r.is_truncated {
            break;
        }
    }
    let want: Vec<Vec<u8>> = all.entries.iter().map(|x| x.idx.clone()).collect();
    assert_eq!(seen, want);
    // the walk stops at the end sentinel: later special keys are not reported
    raw(&mut s, b"\x809999_", vec![0]);
    assert_eq!(
        bi_list(&mut s, 100, "", b"", true).entries.len(),
        want.len()
    );
}

#[test]
fn bi_list_decode_errors_and_non_decodable_segments() {
    let (mut s, _) = populated();
    raw(&mut s, b"zz", vec![1, 2, 3]);
    err(
        &mut s,
        O,
        "rgw",
        "bi_list",
        &e(&BiListOp {
            max: 100,
            ..Default::default()
        }),
        EIO,
    );
}

/// `n` bilog entries through complete_op with log_op.
fn log_puts(s: &mut MemStore, n: usize) {
    for i in 0..n {
        let name = format!("o{i}");
        let p = ObjPrepareOp {
            op: op::ADD,
            tag: "t".into(),
            key: ObjKey::new(&name, ""),
            ..Default::default()
        };
        ok(s, O, "rgw", "bucket_prepare_op", &e(&p));
        let c = ObjCompleteOp {
            op_tag: "t".into(),
            key: ObjKey::new(&name, ""),
            meta: meta(1),
            log_op: true,
            ..Default::default()
        };
        ok(s, O, "rgw", "bucket_complete_op", &e(&c));
    }
}
fn bilog_list(s: &mut MemStore, marker: impl Into<Vec<u8>>, max: u32) -> BiLogListRet {
    let op = BiLogListOp {
        marker: marker.into(),
        max,
    };
    d(&ok(s, O, "rgw", "bi_log_list", &e(&op)))
}
fn bilog_keys(s: &MemStore) -> Vec<Vec<u8>> {
    s.obj(O)
        .unwrap()
        .omap
        .keys()
        .filter(|k| k.starts_with(keys::BILOG))
        .map(|k| k[keys::BILOG.len()..].to_vec())
        .collect()
}
fn trim(s: &mut MemStore, start: &str, end: &str) -> i32 {
    let op = BiLogTrimOp {
        start_marker: start.into(),
        end_marker: end.into(),
    };
    call(s, O, "rgw", "bi_log_trim", &e(&op)).ret
}

#[test]
fn bi_log_list_pages_after_marker() {
    let mut s = init();
    log_puts(&mut s, 5);
    // an instance-namespace key right after the bilog must end the scan
    raw(&mut s, b"\x801000_zzz", vec![0]);
    let all = bilog_list(&mut s, "", 100);
    assert_eq!(all.entries.len(), 5);
    assert!(!all.truncated);
    let ids: Vec<Vec<u8>> = all.entries.iter().map(|x| x.id.clone()).collect();
    assert_eq!(ids, bilog_keys(&s));
    let p1 = bilog_list(&mut s, "", 2);
    assert!(p1.truncated);
    assert_eq!(p1.entries.len(), 2);
    let p2 = bilog_list(&mut s, p1.entries[1].id.clone(), 2);
    assert_eq!(p2.entries[0].id, ids[2]); // strictly after the marker
    let p3 = bilog_list(&mut s, p2.entries[1].id.clone(), 2);
    assert_eq!(p3.entries.len(), 1);
    assert!(!p3.truncated);
    // corrupt value -> EIO
    raw(&mut s, b"\x800_99999999999.1.0", vec![9]);
    err(
        &mut s,
        O,
        "rgw",
        "bi_log_list",
        &e(&BiLogListOp {
            marker: "".into(),
            max: 100,
        }),
        EIO,
    );
}

#[test]
fn bi_log_trim_ranges_and_enodata() {
    let mut s = init();
    log_puts(&mut s, 6);
    let ids = bilog_keys(&s);
    assert_eq!(ids.len(), 6);
    // start marker is exclusive, end marker inclusive
    assert_eq!(trim(&mut s, txt(&ids[0]), txt(&ids[2])), 0);
    assert_eq!(bilog_keys(&s), [&ids[0..1], &ids[3..]].concat());
    // nothing left in the range
    assert_eq!(trim(&mut s, txt(&ids[0]), txt(&ids[2])), ENODATA);
    // empty end marker: through the end of the namespace
    assert_eq!(trim(&mut s, "", ""), 0);
    assert!(bilog_keys(&s).is_empty());
    assert_eq!(trim(&mut s, "", ""), ENODATA);
    // the header is untouched by trim; other namespaces survive
    raw(&mut s, b"\x801000_keep", vec![1]);
    assert_eq!(trim(&mut s, "", ""), ENODATA);
    assert!(s.obj(O).unwrap().omap.contains_key(&b"\x801000_keep"[..]));
}

#[test]
fn bi_log_resync_and_stop() {
    let mut s = init();
    log_puts(&mut s, 1);
    let v = hdr(&s).ver;
    ok(&mut s, O, "rgw", "bi_log_stop", &[]);
    let h = hdr(&s);
    assert!(h.syncstopped);
    assert_eq!(h.ver, v + 1);
    let l = bilog_list(&mut s, "", 100);
    let st = l.entries.last().unwrap();
    assert_eq!((st.op, st.state), (op::SYNCSTOP, state::COMPLETE));
    assert!(st.id.starts_with(format!("{:011}.", v).as_bytes()));
    assert_eq!(st.index_ver, 0); // key uses header.ver, the stored entry keeps 0
    assert_eq!(h.max_marker, st.id);
    // while stopped complete_op writes no bilog
    log_puts(&mut s, 1);
    assert_eq!(bilog_list(&mut s, "", 100).entries.len(), 2);
    ok(&mut s, O, "rgw", "bi_log_resync", &[]);
    let h = hdr(&s);
    assert!(!h.syncstopped);
    let l = bilog_list(&mut s, "", 100);
    assert_eq!(l.entries.last().unwrap().op, op::RESYNC);
    assert_eq!(l.entries.len(), 3);
}
