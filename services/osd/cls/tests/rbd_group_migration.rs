// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Groups, migration, v1-format snapshots, snapshot namespaces and the audit fixes of
//! spec/cls_rbd.md B.9-B.9c on MemStore, with hand-computed expectations.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use cls::rbd::migration::{HEADER_TEXT, MIGRATE_TEXT};
use cls::rbd::types::*;
use cls::rbd::types_group::*;
use common::*;
use std::collections::BTreeMap;

const HDR: &str = "rbd_header.10abcdef";
const GDIR: &str = "rbd_group_directory";
const GH: &str = "rbd_group_header.g1";

fn s(v: &str) -> Vec<u8> {
    e(v)
}
fn args(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}
fn u32b(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}
fn new_image(st: &mut MemStore, features: u64) {
    ok(
        st,
        HDR,
        "rbd",
        "create",
        &args(&[
            u64b(1 << 24),
            vec![22],
            u64b(features),
            s("rbd_data.10abcdef"),
        ]),
    );
}
fn ginput(id: &str, name: &str, state: u8) -> GroupSnapshot {
    GroupSnapshot {
        id: id.into(),
        name: name.into(),
        state,
        snaps: vec![],
    }
}

// ---- group directory ----------------------------------------------------------------------------

#[test]
fn group_directory() {
    let mut st = MemStore::new();
    // list on an absent object: empty map
    let out = ok(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_list",
        &args(&[s(""), u64b(10)]),
    );
    assert_eq!(out, 0u32.to_le_bytes());
    ok(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_add",
        &args(&[s("g-one"), s("abc1")]),
    );
    ok(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_add",
        &args(&[s("g-two"), s("abc2")]),
    );
    err(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_add",
        &args(&[s("g-one"), s("abc9")]),
        EEXIST,
    );
    err(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_add",
        &args(&[s("g-new"), s("abc1")]),
        EBADF,
    );
    err(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_add",
        &args(&[s("g-x"), s("a-b")]),
        EINVAL,
    );
    err(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_add",
        &args(&[s(""), s("abc3")]),
        EINVAL,
    );
    err(&mut st, GDIR, "rbd", "group_dir_add", &s("x"), EINVAL);
    let m: BTreeMap<String, String> = d(&ok(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_list",
        &args(&[s(""), u64b(10)]),
    ));
    assert_eq!(m.len(), 2);
    assert_eq!(m["g-two"], "abc2");
    // paging: start_after is exclusive
    let m: BTreeMap<String, String> = d(&ok(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_list",
        &args(&[s("g-one"), u64b(10)]),
    ));
    assert_eq!(m.keys().collect::<Vec<_>>(), ["g-two"]);
    // rename
    ok(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_rename",
        &args(&[s("g-one"), s("g-1"), s("abc1")]),
    );
    assert!(st.omap_get(GDIR, "name_g-one").is_none());
    assert_eq!(st.omap_get(GDIR, "name_g-1").unwrap(), s("abc1"));
    assert_eq!(st.omap_get(GDIR, "id_abc1").unwrap(), s("g-1"));
    err(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_rename",
        &args(&[s("g-1"), s("g-two"), s("abc1")]),
        EEXIST,
    );
    // remove: stale / missing
    err(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_remove",
        &args(&[s("g-1"), s("abc2")]),
        ESTALE,
    );
    err(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_remove",
        &args(&[s("nope"), s("abc1")]),
        ENOENT,
    );
    ok(
        &mut st,
        GDIR,
        "rbd",
        "group_dir_remove",
        &args(&[s("g-1"), s("abc1")]),
    );
    assert!(st.omap_get(GDIR, "id_abc1").is_none());
}

// ---- group header: images -----------------------------------------------------------------------

fn gi(id: &str, pool: i64) -> GroupImageSpec {
    GroupImageSpec {
        image_id: id.into(),
        pool_id: pool,
    }
}

#[test]
fn group_images() {
    let mut st = MemStore::new();
    for (id, pool, state) in [
        ("imgb", 3, 0u8),
        ("imga", 3, 1),
        ("imgz", 2, 0),
        ("imgn", -2, 1),
    ] {
        let stt = GroupImageStatus {
            spec: gi(id, pool),
            state,
        };
        ok(&mut st, GH, "rbd", "group_image_set", &e(&stt));
    }
    // key layout: 16 hex of the u64 pool, '_' image id; value = plain state byte
    assert_eq!(st.omap_get(GH, "image_0000000000000003_imgb").unwrap(), [0]);
    assert_eq!(st.omap_get(GH, "image_fffffffffffffffe_imgn").unwrap(), [1]);
    // overwrite
    ok(
        &mut st,
        GH,
        "rbd",
        "group_image_set",
        &e(&GroupImageStatus {
            spec: gi("imgb", 3),
            state: 1,
        }),
    );
    assert_eq!(st.omap_get(GH, "image_0000000000000003_imgb").unwrap(), [1]);
    // list in key order: pool 2, pool 3 (a, b), then the "negative" pool
    let list = |st: &mut MemStore, start: &GroupImageSpec, max: u64| -> Vec<GroupImageStatus> {
        d(&ok(
            st,
            GH,
            "rbd",
            "group_image_list",
            &args(&[e(start), u64b(max)]),
        ))
    };
    let all = list(&mut st, &gi("", -1), 100);
    let ids: Vec<_> = all
        .iter()
        .map(|x| (txt(&x.spec.image_id), x.spec.pool_id, x.state))
        .collect();
    assert_eq!(
        ids,
        [
            ("imgz", 2, 0),
            ("imga", 3, 1),
            ("imgb", 3, 1),
            ("imgn", -2, 1)
        ]
    );
    let page = list(&mut st, &gi("", -1), 2);
    assert_eq!(page.len(), 2);
    let next = list(&mut st, &page[1].spec, 10);
    assert_eq!(next.len(), 2);
    assert_eq!(txt(&next[0].spec.image_id), "imgb");
    assert!(list(&mut st, &gi("", -1), 0).is_empty());
    // remove
    ok(&mut st, GH, "rbd", "group_image_remove", &e(&gi("imga", 3)));
    assert!(st.omap_get(GH, "image_0000000000000003_imga").is_none());
    ok(&mut st, GH, "rbd", "group_image_remove", &e(&gi("imga", 3))); // missing key: ok
    err(
        &mut st,
        "rbd_group_header.absent",
        "rbd",
        "group_image_remove",
        &e(&gi("imga", 3)),
        ENOENT,
    );
    // pool -1 quirk: empty key
    ok(
        &mut st,
        GH,
        "rbd",
        "group_image_set",
        &e(&GroupImageStatus {
            spec: gi("x", -1),
            state: 0,
        }),
    );
    assert_eq!(st.omap_get(GH, "").unwrap(), [0]);
    // corrupt value / key
    st.objects
        .get_mut(GH)
        .unwrap()
        .omap
        .insert(b"image_0000000000000009_bad".to_vec(), vec![]);
    err(
        &mut st,
        GH,
        "rbd",
        "group_image_list",
        &args(&[e(&gi("", -1)), u64b(100)]),
        EIO,
    );
    err(&mut st, GH, "rbd", "group_image_list", &[1, 2], EINVAL);
}

#[test]
fn group_image_status_bytes() {
    // GroupImageStatus: env(1,1,len) { env(1,1,len){ string "ab", i64 5 }, u8 1 }
    let b = e(&GroupImageStatus {
        spec: gi("ab", 5),
        state: 1,
    });
    let spec = cat(&[&[1, 1], &u32b(14), &u32b(2), b"ab", &5i64.to_le_bytes()]);
    assert_eq!(
        b,
        cat(&[&[1, 1], &u32b(spec.len() as u32 + 1), &spec, &[1]])
    );
}

// ---- image side of groups -----------------------------------------------------------------------

#[test]
fn image_group_ref() {
    let mut st = MemStore::new();
    new_image(&mut st, 1);
    let g = GroupSpec {
        pool_id: 4,
        group_id: "g1".into(),
    };
    // default when unset
    let got: GroupSpec = d(&ok(&mut st, HDR, "rbd", "image_group_get", &[]));
    assert_eq!((got.pool_id, txt(&got.group_id)), (-1, ""));
    ok(&mut st, HDR, "rbd", "image_group_add", &e(&g));
    assert_eq!(st.omap_u64(HDR, "op_features"), Some(op_feature::GROUP));
    assert_eq!(st.omap_u64(HDR, "features"), Some(1 | feature::OPERATIONS));
    ok(&mut st, HDR, "rbd", "image_group_add", &e(&g)); // same group: no-op
    let other = GroupSpec {
        pool_id: 4,
        group_id: "g2".into(),
    };
    err(&mut st, HDR, "rbd", "image_group_add", &e(&other), EEXIST);
    err(&mut st, HDR, "rbd", "image_group_remove", &e(&other), EBADF);
    assert_eq!(
        d::<GroupSpec>(&ok(&mut st, HDR, "rbd", "image_group_get", &[])),
        g
    );
    ok(&mut st, HDR, "rbd", "image_group_remove", &e(&g));
    assert!(st.omap_get(HDR, "op_features").is_none());
    assert_eq!(st.omap_u64(HDR, "features"), Some(1));
    err(&mut st, HDR, "rbd", "image_group_remove", &e(&g), ENOENT);
    // undecodable stored ref: EINVAL (not EIO)
    st.objects
        .get_mut(HDR)
        .unwrap()
        .omap
        .insert(b"rbd_group_ref".to_vec(), vec![1]);
    err(&mut st, HDR, "rbd", "image_group_get", &[], EINVAL);
    err(&mut st, HDR, "rbd", "image_group_add", &e(&g), EINVAL);
    err(&mut st, HDR, "rbd", "image_group_remove", &e(&g), EINVAL);
}

// ---- group snapshots ----------------------------------------------------------------------------

#[test]
fn group_snapshots() {
    let mut st = MemStore::new();
    let mut a = ginput("sa", "snap-a", 0);
    a.snaps = vec![ImageSnapshotSpec {
        pool: 1,
        image_id: "img".into(),
        snap_id: 7,
    }];
    err(
        &mut st,
        GH,
        "rbd",
        "group_snap_set",
        &e(&ginput("", "n", 0)),
        EINVAL,
    );
    err(
        &mut st,
        GH,
        "rbd",
        "group_snap_set",
        &e(&ginput("i", "", 0)),
        EINVAL,
    );
    ok(&mut st, GH, "rbd", "group_snap_set", &e(&a));
    ok(
        &mut st,
        GH,
        "rbd",
        "group_snap_set",
        &e(&ginput("sb", "snap-b", 0)),
    );
    assert_eq!(st.omap_u64(GH, "snap_max_order"), Some(2));
    assert_eq!(st.omap_u64(GH, "snap_order_sa"), Some(1));
    assert_eq!(st.omap_u64(GH, "snap_order_sb"), Some(2));
    // incomplete again for an existing id / same name under another id
    err(&mut st, GH, "rbd", "group_snap_set", &e(&a), EEXIST);
    err(
        &mut st,
        GH,
        "rbd",
        "group_snap_set",
        &e(&ginput("sc", "snap-a", 0)),
        EEXIST,
    );
    // state -> complete: overwrite, no order change; same name with SAME id is fine
    let mut a2 = a.clone();
    a2.state = 1;
    ok(&mut st, GH, "rbd", "group_snap_set", &e(&a2));
    assert_eq!(st.omap_u64(GH, "snap_max_order"), Some(2));
    let got: GroupSnapshot = d(&ok(&mut st, GH, "rbd", "group_snap_get_by_id", &s("sa")));
    assert_eq!(got, a2);
    err(&mut st, GH, "rbd", "group_snap_get_by_id", &s("zz"), ENOENT);
    // a complete-state first insert gets no order entry
    ok(
        &mut st,
        GH,
        "rbd",
        "group_snap_set",
        &e(&ginput("sd", "snap-d", 1)),
    );
    assert!(st.omap_get(GH, "snap_order_sd").is_none());
    // list + paging
    let l: Vec<GroupSnapshot> = d(&ok(
        &mut st,
        GH,
        "rbd",
        "group_snap_list",
        &args(&[e(&ginput("", "", 0)), u64b(10)]),
    ));
    assert_eq!(
        l.iter().map(|x| txt(&x.id)).collect::<Vec<_>>(),
        ["sa", "sb", "sd"]
    );
    let l: Vec<GroupSnapshot> = d(&ok(
        &mut st,
        GH,
        "rbd",
        "group_snap_list",
        &args(&[e(&ginput("sa", "", 0)), u64b(1)]),
    ));
    assert_eq!(l.len(), 1);
    assert_eq!(txt(&l[0].id), "sb");
    let o: BTreeMap<String, u64> = d(&ok(
        &mut st,
        GH,
        "rbd",
        "group_snap_list_order",
        &args(&[s(""), u64b(10)]),
    ));
    assert_eq!(
        o,
        BTreeMap::from([("sa".to_string(), 1), ("sb".to_string(), 2)])
    );
    let o: BTreeMap<String, u64> = d(&ok(
        &mut st,
        GH,
        "rbd",
        "group_snap_list_order",
        &args(&[s("sa"), u64b(10)]),
    ));
    assert_eq!(o.keys().collect::<Vec<_>>(), ["sb"]);
    // remove drops record and order; max_order stays
    ok(&mut st, GH, "rbd", "group_snap_remove", &s("sa"));
    assert!(st.omap_get(GH, "snapshot_sa").is_none());
    assert!(st.omap_get(GH, "snap_order_sa").is_none());
    assert_eq!(st.omap_u64(GH, "snap_max_order"), Some(2));
    ok(&mut st, GH, "rbd", "group_snap_remove", &s("sd")); // no order key: fine
    ok(
        &mut st,
        GH,
        "rbd",
        "group_snap_set",
        &e(&ginput("se", "snap-a", 0)),
    );
    assert_eq!(st.omap_u64(GH, "snap_order_se"), Some(3));
    // absent object
    err(
        &mut st,
        "rbd_group_header.none",
        "rbd",
        "group_snap_remove",
        &s("x"),
        ENOENT,
    );
    err(
        &mut st,
        "rbd_group_header.none",
        "rbd",
        "group_snap_get_by_id",
        &s("x"),
        ENOENT,
    );
}

// ---- migration ----------------------------------------------------------------------------------

fn mspec(t: u8) -> MigrationSpec {
    MigrationSpec {
        header_type: t,
        pool_id: 3,
        pool_namespace: "ns".into(),
        image_name: "src".into(),
        image_id: "abcd".into(),
        snap_seqs: BTreeMap::from([(4, 9)]),
        overlap: 1 << 20,
        flatten: true,
        mirroring: false,
        state: 1,
        state_description: "x".into(),
        mirror_image_mode: 1,
        source_spec: Vec::new(),
    }
}

#[test]
fn migration_v2_flow() {
    let mut st = MemStore::new();
    new_image(&mut st, 1);
    // not migrating yet
    err(&mut st, HDR, "rbd", "migration_get", &[], EINVAL);
    err(
        &mut st,
        HDR,
        "rbd",
        "migration_set_state",
        &args(&[vec![3], s("run")]),
        EINVAL,
    );
    let sp = mspec(1);
    ok(&mut st, HDR, "rbd", "migration_set", &e(&sp));
    assert_eq!(st.omap_u64(HDR, "features"), Some(1 | feature::MIGRATING));
    err(&mut st, HDR, "rbd", "migration_set", &e(&sp), EEXIST);
    let got: MigrationSpec = d(&ok(&mut st, HDR, "rbd", "migration_get", &[]));
    assert_eq!(got, sp);
    // envelope: v3, compat 1 without source_spec
    let raw = st.omap_get(HDR, "migration").unwrap();
    assert_eq!(&raw[..2], &[3, 1]);
    ok(
        &mut st,
        HDR,
        "rbd",
        "migration_set_state",
        &args(&[vec![3], s("running")]),
    );
    let got: MigrationSpec = d(&ok(&mut st, HDR, "rbd", "migration_get", &[]));
    assert_eq!((got.state, txt(&got.state_description)), (3, "running"));
    // source_spec raises compat to 3
    let mut sp3 = sp.clone();
    sp3.source_spec = "{}".into();
    assert_eq!(e(&sp3)[..2], [3, 3]);
    // remove: clears key + feature, idempotent on the feature
    ok(&mut st, HDR, "rbd", "migration_remove", &[]);
    assert!(st.omap_get(HDR, "migration").is_none());
    assert_eq!(st.omap_u64(HDR, "features"), Some(1));
    ok(&mut st, HDR, "rbd", "migration_remove", &[]);
    err(&mut st, HDR, "rbd", "migration_get", &[], EINVAL);
    // destination image: header_type 2 may be set when MIGRATING is already on (no EEXIST)
    ok(&mut st, HDR, "rbd", "migration_set", &e(&mspec(2)));
    // features already has MIGRATING but key was removed: dst allowed, src refused
    ok(&mut st, HDR, "rbd", "migration_remove", &[]);
    st.objects
        .get_mut(HDR)
        .unwrap()
        .omap
        .insert(b"features".to_vec(), u64b(1 | feature::MIGRATING));
    err(&mut st, HDR, "rbd", "migration_set", &e(&mspec(1)), EEXIST);
    ok(&mut st, HDR, "rbd", "migration_set", &e(&mspec(2)));
    // undecodable stored spec: EIO
    st.objects
        .get_mut(HDR)
        .unwrap()
        .omap
        .insert(b"migration".to_vec(), vec![3]);
    err(&mut st, HDR, "rbd", "migration_get", &[], EIO);
    err(&mut st, HDR, "rbd", "migration_set", &[9], EINVAL);
    // absent object
    // RW methods on an absent object read 0 bytes (v1 probe: wrong length); RD methods are
    // ENOENT before the call (executor rule, cls.md s3)
    err(&mut st, "nohdr", "rbd", "migration_set", &e(&sp), ENXIO);
    err(
        &mut st,
        "nohdr",
        "rbd",
        "migration_set_state",
        &args(&[vec![1], s("")]),
        ENXIO,
    );
    err(&mut st, "nohdr", "rbd", "migration_remove", &[], ENXIO);
}

#[test]
fn migration_v1_header_text() {
    assert_eq!(HEADER_TEXT.len(), 34);
    assert_eq!(MIGRATE_TEXT.len(), 34);
    let mut st = MemStore::new();
    let o = "rbd_old";
    let mut data = HEADER_TEXT.to_vec();
    data.resize(112, 0);
    st.msg(o, |c| {
        use cls::ClsCtx;
        c.write(0, &data).unwrap();
        (0, ())
    });
    err(&mut st, o, "rbd", "migration_get", &[], EINVAL);
    err(&mut st, o, "rbd", "migration_set", &e(&mspec(2)), EINVAL); // v1 only as source
    ok(&mut st, o, "rbd", "migration_set", &e(&mspec(1)));
    assert_eq!(&st.obj(o).unwrap().data[..34], MIGRATE_TEXT);
    assert_eq!(st.obj(o).unwrap().data.len(), 112);
    err(&mut st, o, "rbd", "migration_set", &e(&mspec(1)), EEXIST);
    assert_eq!(
        d::<MigrationSpec>(&ok(&mut st, o, "rbd", "migration_get", &[])),
        mspec(1)
    );
    ok(&mut st, o, "rbd", "migration_remove", &[]);
    assert_eq!(&st.obj(o).unwrap().data[..34], HEADER_TEXT);
    err(&mut st, o, "rbd", "migration_remove", &[], EINVAL);
    // garbage / short header
    st.objects.get_mut(o).unwrap().data[0] = b'X';
    err(&mut st, o, "rbd", "migration_get", &[], ENXIO);
    err(&mut st, o, "rbd", "migration_set", &e(&mspec(1)), ENXIO);
    st.objects.get_mut(o).unwrap().data.truncate(10);
    err(&mut st, o, "rbd", "migration_get", &[], ENXIO);
}

// ---- v1-format snapshot methods -----------------------------------------------------------------

fn v1_header(image_size: u64) -> Vec<u8> {
    let mut h = HEADER_TEXT.to_vec();
    h.resize(40, 0);
    h.extend([0u8; 24]); // block_name
    h.extend(b"RBD\0");
    h.extend(b"001.005");
    h.push(0);
    h.extend([22, 0, 0, 0]); // order, crypt, comp, unused
    h.extend(image_size.to_le_bytes());
    h.extend(0u64.to_le_bytes()); // snap_seq
    h.extend(0u32.to_le_bytes()); // snap_count
    h.extend(0u32.to_le_bytes()); // reserved
    h.extend(0u64.to_le_bytes()); // names_len
    assert_eq!(h.len(), 112);
    h
}

#[test]
fn old_format_snapshots() {
    let mut st = MemStore::new();
    let o = "rbd_old.hdr";
    st.msg(o, |c| {
        use cls::ClsCtx;
        c.write(0, &v1_header(0x4000)).unwrap();
        (0, ())
    });
    let list = |st: &mut MemStore| ok(st, o, "rbd", "snap_list", &[]);
    assert_eq!(list(&mut st), cat(&[&u64b(0), &u32b(0)]));
    ok(&mut st, o, "rbd", "snap_add", &args(&[s("one"), u64b(5)]));
    // image size changes between snapshots: patch the header bytes directly
    st.objects.get_mut(o).unwrap().data[80..88].copy_from_slice(&0x8000u64.to_le_bytes());
    ok(&mut st, o, "rbd", "snap_add", &args(&[s("two"), u64b(6)]));
    ok(&mut st, o, "rbd", "snap_add", &args(&[s("three"), u64b(9)]));
    // newest first
    let expect = cat(&[
        &u64b(9),
        &u32b(3),
        &u64b(9),
        &u64b(0x8000),
        &s("three"),
        &u64b(6),
        &u64b(0x8000),
        &s("two"),
        &u64b(5),
        &u64b(0x4000),
        &s("one"),
    ]);
    assert_eq!(list(&mut st), expect);
    // raw layout: 112 + 3*16 + names("three\0two\0one\0" = 14)
    assert_eq!(st.obj(o).unwrap().data.len(), 112 + 48 + 14);
    assert_eq!(&st.obj(o).unwrap().data[112 + 48..], b"three\0two\0one\0");
    // errors
    err(
        &mut st,
        o,
        "rbd",
        "snap_add",
        &args(&[s("x"), u64b(8)]),
        ESTALE,
    );
    err(
        &mut st,
        o,
        "rbd",
        "snap_add",
        &args(&[s("two"), u64b(10)]),
        EEXIST,
    );
    err(&mut st, o, "rbd", "snap_add", &s("two"), EINVAL);
    st.objects
        .get_mut(o)
        .unwrap()
        .omap
        .insert(b"snap_limit".to_vec(), u64b(3));
    err(
        &mut st,
        o,
        "rbd",
        "snap_add",
        &args(&[s("four"), u64b(10)]),
        EDQUOT,
    );
    // rename
    err(
        &mut st,
        o,
        "rbd",
        "snap_rename",
        &args(&[u64b(6), s("three")]),
        EEXIST,
    );
    err(
        &mut st,
        o,
        "rbd",
        "snap_rename",
        &args(&[u64b(77), s("zzz")]),
        ENOENT,
    );
    ok(
        &mut st,
        o,
        "rbd",
        "snap_rename",
        &args(&[u64b(6), s("second")]),
    );
    assert_eq!(
        &st.obj(o).unwrap().data[112 + 48..],
        b"three\0second\0one\0"
    );
    assert_eq!(le64(&st.obj(o).unwrap().data[104..112]), 17);
    // remove by name
    err(&mut st, o, "rbd", "snap_remove", &s("nope"), ENOENT);
    ok(&mut st, o, "rbd", "snap_remove", &s("second"));
    assert_eq!(&st.obj(o).unwrap().data[112 + 32..], b"three\0one\0");
    let l = list(&mut st);
    assert_eq!(&l[..12], &cat(&[&u64b(9), &u32b(2)])[..]);
    ok(&mut st, o, "rbd", "snap_remove", &s("one"));
    ok(&mut st, o, "rbd", "snap_remove", &s("three"));
    assert_eq!(st.obj(o).unwrap().data.len(), 112);
    assert_eq!(list(&mut st), cat(&[&u64b(9), &u32b(0)]));
    // v2 header (empty data) -> EINVAL, absent -> ENOENT, truncated declared data -> EIO
    new_image(&mut st, 1);
    for m in ["snap_list", "snap_add", "snap_remove", "snap_rename"] {
        err(&mut st, HDR, "rbd", m, &[], EINVAL);
    }
    // absent object: RW methods read 0 bytes (EINVAL); snap_list is ENOENT via the executor rule
    err(&mut st, "absent", "rbd", "snap_add", &[], EINVAL);
    let mut bad = v1_header(1);
    bad[96..100].copy_from_slice(&5u32.to_le_bytes());
    st.objects.get_mut(o).unwrap().data = bad;
    err(&mut st, o, "rbd", "snap_list", &[], EIO);
}

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}

// ---- snapshot namespaces, snapshot_remove / set_size audit, dir state ----------------------------

#[test]
fn snapshot_namespaces() {
    let mut st = MemStore::new();
    new_image(&mut st, 1);
    let grp = SnapNs::Group {
        pool: 4,
        group_id: "g1".into(),
        group_snapshot_id: "gs1".into(),
    };
    ok(
        &mut st,
        HDR,
        "rbd",
        "snapshot_add",
        &args(&[s("gsnap"), u64b(2), e(&grp)]),
    );
    let info: SnapshotInfo = d(&ok(&mut st, HDR, "rbd", "snapshot_get", &u64b(2)));
    assert_eq!(info.ns, grp);
    // group namespace body: i64 pool, string group_id, string group_snapshot_id after u32 type
    let b = e(&grp);
    assert_eq!(&b[..2], &[1, 1]);
    assert_eq!(&b[6..10], &1u32.to_le_bytes());
    assert_eq!(&b[10..18], &4i64.to_le_bytes());
    // same name, different namespace is allowed; same ns+name is a dup
    ok(
        &mut st,
        HDR,
        "rbd",
        "snapshot_add",
        &args(&[s("gsnap"), u64b(3)]),
    );
    err(
        &mut st,
        HDR,
        "rbd",
        "snapshot_add",
        &args(&[s("gsnap"), u64b(4), e(&grp)]),
        EEXIST,
    );
    // group snaps cannot be renamed
    err(
        &mut st,
        HDR,
        "rbd",
        "snapshot_rename",
        &args(&[u64b(2), s("zz")]),
        EINVAL,
    );
    // mirror namespace round-trips
    let mir = SnapNs::Mirror {
        state: 2,
        complete: true,
        peer_uuids: [b"p1".to_vec()].into(),
        primary_mirror_uuid: "u".into(),
        primary_snap_id: 11,
        last_copied_object_number: 5,
        snap_seqs: BTreeMap::from([(1, 2)]),
    };
    ok(
        &mut st,
        HDR,
        "rbd",
        "snapshot_add",
        &args(&[s("m"), u64b(5), e(&mir)]),
    );
    let info: SnapshotInfo = d(&ok(&mut st, HDR, "rbd", "snapshot_get", &u64b(5)));
    assert_eq!(info.ns, mir);
    // unknown namespace type refused
    let unk = cat(&[&[1, 1], &u32b(4), &u32b(99)]);
    err(
        &mut st,
        HDR,
        "rbd",
        "snapshot_add",
        &args(&[s("u"), u64b(6), unk]),
        EINVAL,
    );
    // trash namespace sets SNAP_TRASH; removing the only trash snap clears it
    let tr = SnapNs::Trash {
        original_name: "old".into(),
        original_namespace_type: 0,
    };
    ok(
        &mut st,
        HDR,
        "rbd",
        "snapshot_add",
        &args(&[s("t"), u64b(7), e(&tr)]),
    );
    assert_eq!(
        st.omap_u64(HDR, "op_features"),
        Some(op_feature::SNAP_TRASH)
    );
    ok(&mut st, HDR, "rbd", "snapshot_remove", &u64b(7));
    assert!(st.omap_get(HDR, "op_features").is_none());
    assert_eq!(st.omap_u64(HDR, "features"), Some(1));
    // group snapshot removable (no protection / children)
    ok(&mut st, HDR, "rbd", "snapshot_remove", &u64b(2));
}

fn put_parent(st: &mut MemStore, p: &Parent) {
    st.objects
        .get_mut(HDR)
        .unwrap()
        .omap
        .insert(b"parent".to_vec(), e(p));
}

#[test]
fn snapshot_remove_parent_audit() {
    // A `parent` key that does not "exist" (snap_id == NOSNAP) is neither dropped nor counts as
    // head child; CLONE_CHILD handling follows classic's has_parent logic.
    let mut st = MemStore::new();
    new_image(&mut st, 1);
    let nonexistent = Parent {
        pool_id: 1,
        pool_namespace: Vec::new(),
        image_id: "p".into(),
        snap_id: NOSNAP,
        head_overlap: None,
    };
    put_parent(&mut st, &nonexistent);
    ok(
        &mut st,
        HDR,
        "rbd",
        "snapshot_add",
        &args(&[s("s"), u64b(1)]),
    );
    ok(&mut st, HDR, "rbd", "snapshot_remove", &u64b(1));
    assert!(st.omap_get(HDR, "parent").is_some());
    // real parent with head overlap stays; without head overlap and without child snaps it goes
    let real = Parent {
        pool_id: 1,
        pool_namespace: Vec::new(),
        image_id: "p".into(),
        snap_id: 3,
        head_overlap: Some(1 << 20),
    };
    put_parent(&mut st, &real);
    ok(
        &mut st,
        HDR,
        "rbd",
        "snapshot_add",
        &args(&[s("s2"), u64b(2)]),
    );
    ok(&mut st, HDR, "rbd", "snapshot_remove", &u64b(2));
    assert!(st.omap_get(HDR, "parent").is_some());
    let mut detached = real.clone();
    detached.head_overlap = None;
    put_parent(&mut st, &detached);
    ok(
        &mut st,
        HDR,
        "rbd",
        "snapshot_add",
        &args(&[s("s3"), u64b(3)]),
    );
    // the snapshot (child snap) keeps the parent spec while it exists
    ok(&mut st, HDR, "rbd", "snapshot_remove", &u64b(3));
    assert!(st.omap_get(HDR, "parent").is_none());
}

#[test]
fn set_size_parent_overlap_audit() {
    let mut st = MemStore::new();
    new_image(&mut st, 1);
    let nonexistent = Parent {
        pool_id: 1,
        pool_namespace: Vec::new(),
        image_id: "p".into(),
        snap_id: NOSNAP,
        head_overlap: Some(1 << 20),
    };
    put_parent(&mut st, &nonexistent);
    ok(&mut st, HDR, "rbd", "set_size", &u64b(1 << 10));
    let p: Parent = d(st.omap_get(HDR, "parent").unwrap());
    assert_eq!(p.head_overlap, Some(1 << 20)); // untouched: parent does not exist
    let mut real = nonexistent.clone();
    real.snap_id = 2;
    put_parent(&mut st, &real);
    ok(&mut st, HDR, "rbd", "set_size", &u64b(1 << 9));
    let p: Parent = d(st.omap_get(HDR, "parent").unwrap());
    assert_eq!(p.head_overlap, Some(1 << 9));
}

#[test]
fn dir_state() {
    let mut st = MemStore::new();
    err(
        &mut st,
        "rbd_directory",
        "rbd",
        "dir_state_assert",
        &[0],
        ENOENT,
    );
    // READY may be set on an absent object (creates it)
    ok(&mut st, "rbd_directory", "rbd", "dir_state_set", &[0]);
    ok(&mut st, "rbd_directory", "rbd", "dir_state_assert", &[0]);
    err(
        &mut st,
        "rbd_directory",
        "rbd",
        "dir_state_assert",
        &[1],
        ENOENT,
    );
    err(
        &mut st,
        "rbd_directory",
        "rbd",
        "dir_state_assert",
        &[],
        EINVAL,
    );
    ok(&mut st, "rbd_directory", "rbd", "dir_state_set", &[1]);
    ok(&mut st, "rbd_directory", "rbd", "dir_state_assert", &[1]);
    err(
        &mut st,
        "rbd_directory",
        "rbd",
        "dir_state_set",
        &[2],
        EINVAL,
    );
    // non-empty directory refuses ADD_DISABLED
    ok(&mut st, "rbd_directory", "rbd", "dir_state_set", &[0]);
    ok(
        &mut st,
        "rbd_directory",
        "rbd",
        "dir_add_image",
        &args(&[s("n"), s("i1")]),
    );
    err(
        &mut st,
        "rbd_directory",
        "rbd",
        "dir_state_set",
        &[1],
        EBUSY,
    );
    err(&mut st, "missing_dir", "rbd", "dir_state_set", &[1], ENOENT);
    // empty stored value: EIO
    st.objects
        .get_mut("rbd_directory")
        .unwrap()
        .omap
        .insert(b"state".to_vec(), vec![]);
    err(
        &mut st,
        "rbd_directory",
        "rbd",
        "dir_state_assert",
        &[0],
        EIO,
    );
}

#[test]
fn namespaces() {
    let mut st = MemStore::new();
    let o = "rbd_namespace";
    ok(&mut st, o, "rbd", "namespace_add", &s("b"));
    ok(&mut st, o, "rbd", "namespace_add", &s("a"));
    err(&mut st, o, "rbd", "namespace_add", &s("a"), EEXIST);
    let l: Vec<String> = d(&ok(
        &mut st,
        o,
        "rbd",
        "namespace_list",
        &args(&[s(""), u64b(10)]),
    ));
    assert_eq!(l, ["a", "b"]);
    let l: Vec<String> = d(&ok(
        &mut st,
        o,
        "rbd",
        "namespace_list",
        &args(&[s("a"), u64b(10)]),
    ));
    assert_eq!(l, ["b"]);
    let l: Vec<String> = d(&ok(
        &mut st,
        o,
        "rbd",
        "namespace_list",
        &args(&[s(""), u64b(0)]),
    ));
    assert!(l.is_empty());
    ok(&mut st, o, "rbd", "namespace_remove", &s("a"));
    err(&mut st, o, "rbd", "namespace_remove", &s("a"), ENOENT);
    err(&mut st, o, "rbd", "namespace_add", &[1], EINVAL);
    err(&mut st, o, "rbd", "namespace_list", &s("only-one"), EINVAL);
}

// ---- fuzz-style: random/truncated inputs never panic, failures leave no trace ---------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

const NEW: &[&str] = &[
    "group_dir_add",
    "group_dir_list",
    "group_dir_remove",
    "group_dir_rename",
    "group_image_remove",
    "group_image_list",
    "group_image_set",
    "group_snap_set",
    "group_snap_remove",
    "group_snap_get_by_id",
    "group_snap_list",
    "group_snap_list_order",
    "migration_set",
    "migration_set_state",
    "migration_get",
    "migration_remove",
    "snap_list",
    "snap_add",
    "snap_remove",
    "snap_rename",
    "image_group_add",
    "image_group_remove",
    "image_group_get",
    "dir_state_assert",
    "dir_state_set",
    "namespace_add",
    "namespace_remove",
    "namespace_list",
];

fn populated() -> MemStore {
    let mut st = MemStore::new();
    ok(
        &mut st,
        "o",
        "rbd",
        "create",
        &args(&[u64b(1 << 24), vec![22], u64b(1), s("rbd_data.o")]),
    );
    ok(
        &mut st,
        "o",
        "rbd",
        "group_dir_add",
        &args(&[s("g"), s("id1")]),
    );
    for i in 0..4 {
        let stt = GroupImageStatus {
            spec: gi(&format!("img{i}"), i),
            state: 0,
        };
        ok(&mut st, "o", "rbd", "group_image_set", &e(&stt));
        ok(
            &mut st,
            "o",
            "rbd",
            "group_snap_set",
            &e(&ginput(&format!("s{i}"), &format!("n{i}"), 0)),
        );
    }
    ok(&mut st, "o", "rbd", "migration_set", &e(&mspec(1)));
    ok(&mut st, "o", "rbd", "namespace_add", &s("ns"));
    ok(&mut st, "o", "rbd", "dir_state_set", &[0]);
    ok(
        &mut st,
        "o",
        "rbd",
        "image_group_add",
        &e(&GroupSpec {
            pool_id: 1,
            group_id: "g".into(),
        }),
    );
    st.objects.get_mut("o").unwrap().data = v1_header(77);
    st
}

#[test]
fn fuzz_new_methods_never_panic() {
    let mut rng = Rng(0xfeed_beef_1234_5678);
    // seeds of valid inputs, truncated at every length
    let seeds: Vec<Vec<u8>> = vec![
        e(&mspec(1)),
        e(&GroupImageStatus {
            spec: gi("a", 1),
            state: 1,
        }),
        e(&ginput("x", "y", 0)),
        args(&[e(&gi("a", 1)), u64b(5)]),
        args(&[s("a"), s("b"), s("c")]),
        args(&[s("snap"), u64b(3)]),
        e(&GroupSpec {
            pool_id: 1,
            group_id: "g".into(),
        }),
    ];
    for m in NEW {
        let mut inputs: Vec<Vec<u8>> = vec![vec![]];
        for sd in &seeds {
            for n in 0..sd.len() {
                inputs.push(sd[..n].to_vec());
            }
            inputs.push(sd.clone());
        }
        for round in 0..40 {
            let n = (rng.next() % 96) as usize;
            if round % 2 == 0 {
                let mut v = vec![(rng.next() % 5) as u8, 1];
                v.extend((n as u32).to_le_bytes());
                v.extend(rng.bytes(n));
                inputs.push(v);
            } else {
                inputs.push(rng.bytes(n));
            }
        }
        for input in &inputs {
            for mk in 0..4 {
                let mut st = match mk {
                    0 => MemStore::new(),
                    1 => populated(),
                    2 => {
                        let mut st = populated();
                        for v in st.objects.get_mut("o").unwrap().omap.values_mut() {
                            v.truncate(v.len() / 2);
                        }
                        st
                    }
                    _ => {
                        let mut st = populated();
                        let o = st.objects.get_mut("o").unwrap();
                        let n = (rng.next() % 130) as usize;
                        o.data = rng.bytes(n);
                        if rng.next().is_multiple_of(2) && o.data.len() >= 112 {
                            o.data[96..100]
                                .copy_from_slice(&((rng.next() % 4) as u32).to_le_bytes());
                            o.data[104..112].copy_from_slice(&(rng.next() % 40).to_le_bytes());
                        }
                        st
                    }
                };
                let before = st.objects.clone();
                let r = st.call("o", "rbd", m, input);
                if r.ret < 0 {
                    assert_eq!(st.objects, before, "{m}: failed call changed state");
                }
            }
        }
    }
}

/// snapshot_set_limit on an old-format header counts the v1 header's snapshots (classic), not the omap keys.
#[test]
fn snapshot_set_limit_counts_v1_snapshots() {
    let mut st = MemStore::new();
    let o = "rbd_old2.hdr";
    st.msg(o, |c| {
        use cls::ClsCtx;
        c.write(0, &v1_header(0x4000)).unwrap();
        (0, ())
    });
    ok(&mut st, o, "rbd", "snap_add", &args(&[s("one"), u64b(5)]));
    ok(&mut st, o, "rbd", "snap_add", &args(&[s("two"), u64b(6)]));
    err(&mut st, o, "rbd", "snapshot_set_limit", &u64b(1), ERANGE);
    ok(&mut st, o, "rbd", "snapshot_set_limit", &u64b(2));
}
