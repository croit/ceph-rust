// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls_rgw data-pool helpers (obj_remove, obj_store_pg_ver, obj_check_*) and the ClsCtx/G26
//! additions (subop_num, config, unsupported counters).
mod common;
use cls::errno::*;
use cls::mem::{MemStore, Obj};
use cls::rgw::types::*;
use common::*;
use denc::types::UTime;

const O: &str = "head";

fn with_attrs(attrs: &[(&str, &[u8])]) -> MemStore {
    let mut s = MemStore::new();
    let mut o = Obj {
        data: b"payload".to_vec(),
        ..Default::default()
    };
    o.omap.insert(b"k".to_vec(), b"v".to_vec());
    for (k, v) in attrs {
        o.xattrs.insert((*k).into(), v.to_vec());
    }
    o.mtime = UTime::new(1000, 500);
    s.objects.insert(O.into(), o);
    s
}

#[test]
fn obj_remove_plain_and_missing() {
    let mut s = with_attrs(&[("user.rgw.x", b"1")]);
    ok(&mut s, O, "rgw", "obj_remove", &e(&ObjRemoveOp::default()));
    assert!(s.obj(O).is_none());
    err(
        &mut s,
        O,
        "rgw",
        "obj_remove",
        &e(&ObjRemoveOp::default()),
        ENOENT,
    );
}

#[test]
fn obj_remove_keeps_prefixed_attrs_only() {
    let mut s = with_attrs(&[
        ("user.rgw.olh.ver", b"7"),
        ("user.rgw.olh.pending.a", b"p"),
        ("user.rgw.acl", b"acl"),
        ("user.rgw.olh", b"zz"), // shorter than the prefix "user.rgw.olh." -> not kept
    ]);
    let op = ObjRemoveOp {
        keep_attr_prefixes: vec!["user.rgw.olh.".into(), "nonexistent.".into()],
    };
    ok(&mut s, O, "rgw", "obj_remove", &e(&op));
    let o = s.obj(O).expect("recreated");
    assert!(o.data.is_empty() && o.omap.is_empty(), "recreated empty");
    let names: Vec<_> = o.xattrs.keys().cloned().collect();
    assert_eq!(
        names,
        [
            b"user.rgw.olh.pending.a".to_vec(),
            b"user.rgw.olh.ver".to_vec()
        ]
    );
    assert_eq!(o.xattrs["user.rgw.olh.ver".as_bytes()], b"7");
    // nothing matches -> object just gone
    let mut s = with_attrs(&[("user.rgw.acl", b"a")]);
    ok(&mut s, O, "rgw", "obj_remove", &e(&op));
    assert!(s.obj(O).is_none());
}

#[test]
fn obj_remove_preserves_distinct_binary_attribute_names() {
    let mut s = with_attrs(&[]);
    let attrs = &mut s.objects.get_mut(O).unwrap().xattrs;
    attrs.insert(b"user.rgw.\xff".to_vec(), b"first".to_vec());
    attrs.insert(b"user.rgw.\xfe".to_vec(), b"second".to_vec());
    attrs.insert(b"unrelated.\xff".to_vec(), b"discard".to_vec());
    // The sibling prefix check must not mistake invalid UTF-8 for an actual replacement-character name.
    err(
        &mut s,
        O,
        "rgw",
        "obj_check_attrs_prefix",
        &e(&CheckAttrsPrefixOp {
            check_prefix: "user.rgw.\u{fffd}".into(),
            fail_if_exist: true,
        }),
        0,
    );
    let op = ObjRemoveOp {
        keep_attr_prefixes: vec!["user.rgw.".into()],
    };
    ok(&mut s, O, "rgw", "obj_remove", &e(&op));
    let o = s.obj(O).unwrap();
    assert!(o.data.is_empty() && o.omap.is_empty());
    assert_eq!(
        o.xattrs,
        std::collections::BTreeMap::from([
            (b"user.rgw.\xff".to_vec(), b"first".to_vec()),
            (b"user.rgw.\xfe".to_vec(), b"second".to_vec()),
        ])
    );
}

#[test]
fn obj_store_pg_ver_writes_le_u64() {
    let mut s = MemStore::new();
    s.env.version = 0x0102_0304_0506;
    let op = StorePgVerOp {
        attr: "user.rgw.pg_ver".into(),
    };
    ok(&mut s, O, "rgw", "obj_store_pg_ver", &e(&op));
    assert_eq!(
        s.obj(O).unwrap().xattrs["user.rgw.pg_ver".as_bytes()],
        0x0102_0304_0506u64.to_le_bytes()
    );
}

#[test]
fn obj_check_attrs_prefix() {
    let mut s = with_attrs(&[("user.rgw.olh.pending.1", b"x")]);
    let chk = |s: &mut MemStore, p: &str, fail_if_exist: bool, want: i32| {
        let op = CheckAttrsPrefixOp {
            check_prefix: p.into(),
            fail_if_exist,
        };
        err(s, O, "rgw", "obj_check_attrs_prefix", &e(&op), want);
    };
    chk(&mut s, "user.rgw.olh.pending.", true, ECANCELED);
    chk(&mut s, "user.rgw.olh.pending.", false, 0);
    chk(&mut s, "user.rgw.zzz", true, 0);
    chk(&mut s, "user.rgw.zzz", false, ECANCELED);
    chk(&mut s, "", true, EINVAL);
    // absent object behaves like "no attrs"
    let mut s = MemStore::new();
    chk(&mut s, "p", true, 0);
    chk(&mut s, "p", false, ECANCELED);
}

#[test]
fn obj_check_mtime_precision_and_types() {
    let mut s = with_attrs(&[]);
    let chk = |s: &mut MemStore, t: UTime, ty: u8, hp: bool, want: i32| {
        let op = CheckMtimeOp {
            mtime: t,
            ty,
            high_precision_time: hp,
        };
        err(s, O, "rgw", "obj_check_mtime", &e(&op), want);
    };
    let obj = UTime::new(1000, 500);
    // low precision: nanoseconds ignored
    chk(&mut s, UTime::new(1000, 999), 0, false, 0);
    chk(&mut s, UTime::new(1000, 999), 0, true, ECANCELED);
    chk(&mut s, obj, 0, true, 0);
    // LT/LE/GT/GE relative to the object time (obj `type` op)
    chk(&mut s, UTime::new(1001, 0), 1, false, 0);
    chk(&mut s, UTime::new(1000, 0), 1, false, ECANCELED);
    chk(&mut s, UTime::new(1000, 0), 2, false, 0);
    chk(&mut s, UTime::new(999, 0), 3, false, 0);
    chk(&mut s, UTime::new(1000, 0), 3, false, ECANCELED);
    chk(&mut s, UTime::new(1000, 0), 4, false, 0);
    chk(&mut s, UTime::new(1000, 0), 9, false, EINVAL);
    // absent object: mtime epoch 0
    let mut s = MemStore::new();
    chk(&mut s, UTime::new(0, 0), 0, true, 0);
    chk(&mut s, UTime::new(5, 0), 1, true, 0);
}

#[test]
fn methods_reject_garbage() {
    let mut s = with_attrs(&[]);
    for m in [
        "bucket_init_index_x",
        "obj_remove",
        "obj_store_pg_ver",
        "obj_check_attrs_prefix",
        "obj_check_mtime",
        "bucket_list",
        "bucket_prepare_op",
        "bucket_complete_op",
        "bucket_update_stats",
        "bucket_set_tag_timeout",
        "guard_bucket_resharding",
        "set_bucket_resharding",
    ] {
        let r = call(&mut s, O, "rgw", m, &[0xff, 0xff]);
        if m == "bucket_init_index_x" {
            assert_eq!(r.ret, EOPNOTSUPP);
        } else {
            assert_eq!(r.ret, EINVAL, "{m}");
        }
    }
}

#[test]
fn cls_config_defaults_and_lookup() {
    let c = cls::ClsConfig::default();
    assert_eq!(c.get("rgw_reshardlog_threshold"), Some(30000));
    assert_eq!(c.get("rgw_pending_bucket_index_op_expiration"), Some(120));
    assert_eq!(c.get("rgw_usage_log_key_transition"), Some(1));
    assert_eq!(
        c.get("rgw_bucket_index_transaction_instrumentation"),
        Some(0)
    );
    assert_eq!(c.get("osd_max_omap_entries_per_request"), Some(1024));
    assert_eq!(c.get("nope"), None);
}

#[test]
fn unsupported_counters_and_clog_gate() {
    use cls::unsupported::*;
    let before = count("fifo");
    note("fifo");
    note("fifo");
    assert_eq!(count("fifo"), before + 2);
    let other = count("zzz_unknown");
    note("zzz_unknown");
    assert_eq!(
        count("zzz_other_name"),
        other + 1,
        "untracked names share one slot"
    );
    assert!(counts().iter().any(|(c, n)| *c == "fifo" && *n >= 2));
    let mut g = ClogGate::new();
    assert!(g.should_log("fifo", 5, 1000));
    assert!(!g.should_log("fifo", 5, 1000 + 3599));
    assert!(g.should_log("fifo", 6, 1001), "per pool");
    assert!(g.should_log("log", 5, 1001), "per class");
    assert!(g.should_log("fifo", 5, 1000 + 3600));
}

#[test]
fn subop_num_reaches_bilog_id() {
    // subop_num feeds the bilog key; covered end to end in rgw_index::bilog_written_when_log_op.
    use cls::ClsCtx;
    let s = MemStore::new();
    let mut ctx = s.begin(O);
    assert_eq!(ctx.subop_num(), 0);
    ctx.env.subop = 3;
    assert_eq!(ctx.subop_num(), 3);
}
