// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! librbd call sequences (cls_rbd.md B.10 / C.4 call matrix) replayed on MemStore: create, open,
//! resize, snap create/protect/unprotect/rm, clone v1 + v2, flatten, object-map update under the
//! lock fence, rename, trash. Asserts decoded outputs and the resulting omap/xattr/data state.
mod common;
use cls::ClsCtx;
use cls::errno::*;
use cls::lock::*;
use cls::mem::MemStore;
use cls::rbd::bitvec::{self, ObjMap};
use cls::rbd::types::*;
use common::*;
use denc::Decoder;
use denc::types::{EntityName, UTime};
use std::collections::BTreeMap;

const ID: &str = "10abcdef";
const HDR: &str = "rbd_header.10abcdef";
const OM: &str = "rbd_object_map.10abcdef";
const DIR: &str = "rbd_directory";
const IDOBJ: &str = "rbd_id.img";
const PFX: &str = "rbd_data.10abcdef";
const FEATURES: u64 = 0x3d; // layering exclusive-lock object-map fast-diff deep-flatten
const MB4: u64 = 1 << 22;

#[test]
fn migration_snapc_seq_absent_distinguishes_gt_and_le_without_creating_data() {
    let mut store = MemStore::new();
    let object = "rbd_data.migration.absent";
    for state in [0, 1] {
        for sequence in [0, 1, u64::MAX] {
            let input = [sequence.to_le_bytes().as_slice(), &[state]].concat();
            if state == 0 {
                assert!(ok(&mut store, object, "rbd", "assert_snapc_seq", &input).is_empty());
            } else {
                err(
                    &mut store,
                    object,
                    "rbd",
                    "assert_snapc_seq",
                    &input,
                    ERANGE,
                );
            }
            assert!(!store.objects.contains_key(object));
        }
    }
}

#[test]
fn migration_snapc_seq_existing_boundaries_preserve_data() {
    let object = "rbd_data.migration.present";
    // Pinned raw-class vectors: (stored sequence, comparison, request, status).
    for (stored, state, requested, expected) in [
        (0, 0, 0, ERANGE),
        (0, 1, 0, 0),
        (7, 0, 6, ERANGE),
        (7, 0, 7, ERANGE),
        (7, 0, 8, 0),
        (7, 1, 6, 0),
        (7, 1, 7, 0),
        (7, 1, 8, ERANGE),
        (u64::MAX, 0, u64::MAX, ERANGE),
        (u64::MAX, 1, u64::MAX, 0),
    ] {
        let mut store = MemStore::new();
        let target = store.objects.entry(object.into()).or_default();
        target.snap_seq = stored;
        target.data = b"preserved".to_vec();
        let input = [requested.to_le_bytes().as_slice(), &[state]].concat();
        assert_eq!(
            store.call(object, "rbd", "assert_snapc_seq", &input).ret,
            expected
        );
        let target = store.objects.get(object).unwrap();
        assert_eq!(target.snap_seq, stored);
        assert_eq!(target.data, b"preserved");
    }
}

#[test]
fn migration_snapc_seq_rejects_invalid_input_without_creating_data() {
    let mut store = MemStore::new();
    let object = "rbd_data.migration.invalid";
    err(&mut store, object, "rbd", "assert_snapc_seq", &[0], EINVAL);
    let input = [0u64.to_le_bytes().as_slice(), &[2]].concat();
    err(
        &mut store,
        object,
        "rbd",
        "assert_snapc_seq",
        &input,
        EOPNOTSUPP,
    );
    assert!(!store.objects.contains_key(object));
}

fn s(v: &str) -> Vec<u8> {
    e(v)
}
fn args(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}
/// `rbd create` flow (CreateRequest): id object, directory, header, object map.
fn create_image(st: &mut MemStore, name: &str, id: &str, size: u64, features: u64) {
    let idobj = format!("rbd_id.{name}");
    let hdr = format!("rbd_header.{id}");
    let om = format!("rbd_object_map.{id}");
    // ID: create + set_id in ONE message
    let (ret, _) = st.msg(&idobj, |c| {
        c.create(true).unwrap();
        (c.call("rbd", "set_id", &s(id)).ret, ())
    });
    assert_eq!(ret, 0);
    // D: dir_add_image (creates rbd_directory on first use)
    ok(st, DIR, "rbd", "dir_add_image", &args(&[s(name), s(id)]));
    // header
    let prefix = format!("rbd_data.{id}");
    ok(
        st,
        &hdr,
        "rbd",
        "create",
        &args(&[u64b(size), vec![22], u64b(features), s(&prefix)]),
    );
    if features & 8 != 0 {
        let n = size.div_ceil(MB4);
        ok(
            st,
            &om,
            "rbd",
            "object_map_resize",
            &args(&[u64b(n), vec![0]]),
        );
    }
}

/// (order, size) as returned by get_size.
fn get_size(st: &mut MemStore, hdr: &str, snap: u64) -> (u8, u64) {
    let o = ok(st, hdr, "rbd", "get_size", &u64b(snap));
    (o[0], u64::from_le_bytes(o[1..9].try_into().unwrap()))
}
fn get_features(st: &mut MemStore, hdr: &str) -> u64 {
    let o = ok(st, hdr, "rbd", "get_features", &u64b(0));
    u64::from_le_bytes(o[0..8].try_into().unwrap())
}
fn op_features(st: &mut MemStore, hdr: &str) -> u64 {
    u64::from_le_bytes(
        ok(st, hdr, "rbd", "op_features_get", &[])[..8]
            .try_into()
            .unwrap(),
    )
}
fn snapcontext(st: &mut MemStore, hdr: &str) -> (u64, Vec<u64>) {
    let o = ok(st, hdr, "rbd", "get_snapcontext", &[]);
    let mut d = Decoder::new(&o);
    (
        d.u64().unwrap(),
        <Vec<u64> as denc::Decode>::decode(&mut d).unwrap(),
    )
}
fn snap_info(st: &mut MemStore, hdr: &str, id: u64) -> SnapshotInfo {
    d(&ok(st, hdr, "rbd", "snapshot_get", &u64b(id)))
}
fn snap_add(st: &mut MemStore, hdr: &str, name: &str, id: u64) {
    ok(st, hdr, "rbd", "snapshot_add", &args(&[s(name), u64b(id)]));
}
fn om_load(st: &mut MemStore, om: &str) -> ObjMap {
    ObjMap::decode(&ok(st, om, "rbd", "object_map_load", &[])).unwrap()
}
fn child(pool: i64, id: &str) -> ChildImageSpec {
    ChildImageSpec {
        pool_id: pool,
        pool_namespace: Vec::new(),
        image_id: id.into(),
    }
}
fn pspec(pool: i64, id: &str, snap: u64) -> ParentImageSpec {
    ParentImageSpec {
        pool_id: pool,
        pool_namespace: Vec::new(),
        image_id: id.into(),
        snap_id: snap,
    }
}

fn lock_om(st: &mut MemStore) {
    // librbd/object_map/LockRequest: name rbd_lock, EXCLUSIVE, cookie "", tag "", no duration
    let op = e(&LockOp {
        name: "rbd_lock".into(),
        ty: 1,
        cookie: "".into(),
        tag: "".into(),
        description: "".into(),
        duration: UTime::default(),
        flags: 0,
    });
    ok(st, OM, "lock", "lock", &op);
}
fn assert_om_locked() -> Vec<u8> {
    e(&AssertOp {
        name: "rbd_lock".into(),
        ty: 1,
        cookie: "".into(),
        tag: "".into(),
    })
}
/// `assert_locked + object_map_*` in ONE message on the object-map object.
fn om_msg(st: &mut MemStore, method: &str, input: &[u8]) -> i32 {
    st.msg(OM, |c| {
        let a = c.call("lock", "assert_locked", &assert_om_locked());
        if a.ret < 0 {
            return (a.ret, ());
        }
        (c.call("rbd", method, input).ret, ())
    })
    .0
}
fn upd(start: u64, end: u64, new: u8, cur: Option<u8>) -> Vec<u8> {
    let mut v = args(&[u64b(start), u64b(end), vec![new]]);
    match cur {
        None => v.push(0),
        Some(c) => v.extend([1, c]),
    }
    v
}

#[test]
fn create_open_resize() {
    let mut st = MemStore::new();
    create_image(&mut st, "img", ID, 40 << 20, FEATURES);
    // directory + id object
    assert_eq!(d::<String>(&ok(&mut st, IDOBJ, "rbd", "get_id", &[])), ID);
    assert_eq!(
        d::<String>(&ok(&mut st, DIR, "rbd", "dir_get_id", &s("img"))),
        ID
    );
    assert_eq!(
        d::<String>(&ok(&mut st, DIR, "rbd", "dir_get_name", &s(ID))),
        "img"
    );
    // header omap exactly as spec A.2 (fresh default image)
    let keys: Vec<_> = st
        .obj(HDR)
        .unwrap()
        .omap
        .keys()
        .map(|k| String::from_utf8_lossy(k).into_owned())
        .collect();
    assert_eq!(
        keys,
        [
            "access_timestamp",
            "create_timestamp",
            "features",
            "modify_timestamp",
            "object_prefix",
            "order",
            "size",
            "snap_seq"
        ]
    );
    assert_eq!(st.omap_u64(HDR, "size"), Some(40 << 20));
    assert_eq!(st.omap_u64(HDR, "features"), Some(FEATURES));
    assert_eq!(st.omap_get(HDR, "order"), Some(&[22u8][..]));
    assert_eq!(
        st.omap_get(HDR, "object_prefix").unwrap(),
        s("rbd_data.10abcdef")
    );
    // open sequence
    assert_eq!(get_size(&mut st, HDR, NOSNAP), (22, 40 << 20));
    let o = ok(
        &mut st,
        HDR,
        "rbd",
        "get_features",
        &args(&[u64b(0), vec![1]]),
    );
    assert_eq!(
        u64::from_le_bytes(o[8..16].try_into().unwrap()),
        FEATURES & 0x883,
        "read-only incompatible mask"
    );
    assert_eq!(
        d::<String>(&ok(&mut st, HDR, "rbd", "get_object_prefix", &[])),
        "rbd_data.10abcdef"
    );
    assert_eq!(
        ok(&mut st, HDR, "rbd", "get_data_pool", &[]),
        (-1i64).to_le_bytes()
    );
    assert_eq!(snapcontext(&mut st, HDR), (0, vec![]));
    let ps: ParentImageSpec = d(&ok(&mut st, HDR, "rbd", "parent_get", &[]));
    assert!(!ps.exists());
    assert_eq!(
        ok(&mut st, HDR, "rbd", "parent_overlap_get", &u64b(NOSNAP)),
        [0]
    );
    let g: GroupSpec = d(&ok(&mut st, HDR, "rbd", "image_group_get", &[]));
    assert_eq!(g, GroupSpec::default());
    assert_eq!(
        ok(&mut st, HDR, "rbd", "get_flags", &u64b(NOSNAP)),
        0u64.to_le_bytes()
    );
    let t: UTime = d(&ok(&mut st, HDR, "rbd", "get_create_timestamp", &[]));
    assert_eq!(t, st.env.now);
    assert_eq!(
        ok(&mut st, "rbd_info", "rbd", "get_all_features", &[]),
        0xfffu64.to_le_bytes()
    );
    // metadata_list on a never-written rbd_info: classic returns an empty map in a mixed message
    // object map: all NONEXISTENT
    let m = om_load(&mut st, OM);
    assert_eq!((m.n, m.data.as_slice()), (10, &[0u8, 0, 0][..]));
    // resize 40M -> 100M (header + object map under the fence)
    lock_om(&mut st);
    ok(&mut st, HDR, "rbd", "set_size", &u64b(100 << 20));
    assert_eq!(
        om_msg(&mut st, "object_map_resize", &args(&[u64b(25), vec![0]])),
        0
    );
    assert_eq!(get_size(&mut st, HDR, NOSNAP).1, 100 << 20);
    assert_eq!(om_load(&mut st, OM).n, 25);
    // a different client cannot mutate the map: fence fails, nothing applied
    client(&mut st, 777);
    assert_eq!(
        om_msg(&mut st, "object_map_resize", &args(&[u64b(5), vec![0]])),
        EBUSY
    );
    assert_eq!(om_load(&mut st, OM).n, 25);
    client(&mut st, 4123);
    // shrink with data beyond the new end marked EXISTS -> ESTALE
    assert_eq!(
        om_msg(&mut st, "object_map_update", &upd(20, 21, 1, None)),
        0
    );
    assert_eq!(
        om_msg(&mut st, "object_map_resize", &args(&[u64b(10), vec![0]])),
        ESTALE
    );
    assert_eq!(
        om_msg(&mut st, "object_map_update", &upd(20, 21, 0, Some(1))),
        0
    );
    assert_eq!(
        om_msg(&mut st, "object_map_resize", &args(&[u64b(10), vec![0]])),
        0
    );
    // set_size shrink below parent overlap clamps it (no parent here: untouched)
    ok(&mut st, HDR, "rbd", "set_size", &u64b(40 << 20));
    assert!(st.omap_get(HDR, "parent").is_none());
}

#[test]
fn rename_remove_and_trash() {
    let mut st = MemStore::new();
    create_image(&mut st, "img", ID, 40 << 20, FEATURES);
    // rename: dir_get_name, new id object, dir_rename_image, delete old id object
    st.msg("rbd_id.img2", |c| {
        c.create(true).unwrap();
        (c.call("rbd", "set_id", &s(ID)).ret, ())
    });
    ok(
        &mut st,
        DIR,
        "rbd",
        "dir_rename_image",
        &args(&[s("img"), s("img2"), s(ID)]),
    );
    st.msg(IDOBJ, |c| (c.remove().map_or(-1, |_| 0), ()));
    err(&mut st, DIR, "rbd", "dir_get_id", &s("img"), ENOENT);
    assert_eq!(
        d::<String>(&ok(&mut st, DIR, "rbd", "dir_get_id", &s("img2"))),
        ID
    );
    let l: BTreeMap<String, String> = d(&ok(
        &mut st,
        DIR,
        "rbd",
        "dir_list",
        &args(&[s(""), u64b(100)]),
    ));
    assert_eq!(l, BTreeMap::from([("img2".to_string(), ID.to_string())]));
    // trash mv: trash_add, delete id object, dir_remove_image
    let spec = TrashImageSpec {
        source: 0,
        name: "img2".into(),
        deletion_time: st.env.now,
        deferment_end_time: st.env.now,
        state: 0,
    };
    ok(
        &mut st,
        "rbd_trash",
        "rbd",
        "trash_add",
        &args(&[s(ID), e(&spec)]),
    );
    st.msg("rbd_id.img2", |c| (c.remove().map_or(-1, |_| 0), ()));
    ok(
        &mut st,
        DIR,
        "rbd",
        "dir_remove_image",
        &args(&[s("img2"), s(ID)]),
    );
    assert_eq!(
        d::<TrashImageSpec>(&ok(&mut st, "rbd_trash", "rbd", "trash_get", &s(ID))),
        spec
    );
    let l: BTreeMap<String, TrashImageSpec> = d(&ok(
        &mut st,
        "rbd_trash",
        "rbd",
        "trash_list",
        &args(&[s(""), u64b(10)]),
    ));
    assert_eq!(l.len(), 1);
    // restore: id object, dir_add_image, trash_state_set(restoring), trash_remove
    ok(
        &mut st,
        "rbd_trash",
        "rbd",
        "trash_state_set",
        &args(&[s(ID), vec![3], vec![0]]),
    );
    err(
        &mut st,
        "rbd_trash",
        "rbd",
        "trash_state_set",
        &args(&[s(ID), vec![2], vec![0]]),
        ESTALE,
    );
    ok(
        &mut st,
        DIR,
        "rbd",
        "dir_add_image",
        &args(&[s("img2"), s(ID)]),
    );
    ok(&mut st, "rbd_trash", "rbd", "trash_remove", &s(ID));
    err(&mut st, "rbd_trash", "rbd", "trash_get", &s(ID), ENOENT);
    // rm: dir_remove_image, then a second remove is ENOENT; header ops still fine until deleted
    ok(
        &mut st,
        DIR,
        "rbd",
        "dir_remove_image",
        &args(&[s("img2"), s(ID)]),
    );
    err(
        &mut st,
        DIR,
        "rbd",
        "dir_remove_image",
        &args(&[s("img2"), s(ID)]),
        ENOENT,
    );
    // mirror probes librbd issues on rm / create (mirroring unused)
    st.msg("rbd_mirroring", |c| (c.create(false).map_or(-1, |_| 0), ()));
    err(
        &mut st,
        "rbd_mirroring",
        "rbd",
        "mirror_image_get",
        &s(ID),
        ENOENT,
    );
    err(
        &mut st,
        "rbd_mirroring",
        "rbd",
        "mirror_image_remove",
        &s(ID),
        ENOENT,
    );
    err(
        &mut st,
        "rbd_mirroring",
        "rbd",
        "mirror_mode_get",
        &[],
        ENOENT,
    );
    assert_eq!(
        ok(&mut st, "rbd_mirroring", "rbd", "mirror_peer_list", &[]),
        [0, 0, 0, 0]
    );
}

#[test]
fn snap_create_protect_remove_with_object_map() {
    let mut st = MemStore::new();
    create_image(&mut st, "img", ID, 40 << 20, FEATURES);
    lock_om(&mut st);
    // I/O marks objects 0..3 EXISTS under the fence
    assert_eq!(om_msg(&mut st, "object_map_update", &upd(0, 3, 1, None)), 0);
    let m = om_load(&mut st, OM);
    assert_eq!((m.get(0), m.get(2), m.get(3)), (1, 1, 0));
    // snap create: snapshot_add; head map copied to the snap object; snap_add under the fence
    snap_add(&mut st, HDR, "snap1", 4);
    let blob = st.obj(OM).unwrap().data.clone();
    let som = format!("{OM}.{:016x}", 4u64);
    st.msg(&som, |c| (c.write_full(&blob).map_or(-1, |_| 0), ()));
    assert_eq!(om_msg(&mut st, "object_map_snap_add", &[]), 0);
    let m = om_load(&mut st, OM);
    assert_eq!(
        (m.get(0), m.get(1), m.get(2)),
        (3, 3, 3),
        "EXISTS -> EXISTS_CLEAN"
    );
    assert_eq!(
        ObjMap::decode(&st.obj(&som).unwrap().data).unwrap().get(0),
        1,
        "snap map frozen"
    );
    assert_eq!(snapcontext(&mut st, HDR), (4, vec![4]));
    let si = snap_info(&mut st, HDR, 4);
    assert_eq!(
        (txt(&si.name), si.image_size, si.child_count, si.ns.clone()),
        ("snap1", 40 << 20, 0, SnapNs::User)
    );
    assert_eq!(get_size(&mut st, HDR, 4), (22, 40 << 20));
    // write after the snapshot: object 1 dirtied (CLEAN -> EXISTS via filter EXISTS matches CLEAN)
    assert_eq!(
        om_msg(&mut st, "object_map_update", &upd(1, 2, 1, Some(1))),
        0
    );
    assert_eq!(om_load(&mut st, OM).get(1), 1);
    // protect / unprotect
    ok(
        &mut st,
        HDR,
        "rbd",
        "set_protection_status",
        &args(&[u64b(4), vec![2]]),
    );
    assert_eq!(
        ok(&mut st, HDR, "rbd", "get_protection_status", &u64b(4)),
        [2]
    );
    err(&mut st, HDR, "rbd", "snapshot_remove", &u64b(4), EBUSY);
    ok(
        &mut st,
        HDR,
        "rbd",
        "set_protection_status",
        &args(&[u64b(4), vec![1]]),
    );
    ok(
        &mut st,
        HDR,
        "rbd",
        "set_protection_status",
        &args(&[u64b(4), vec![0]]),
    );
    // snap rm: object_map_load(snap map), snap_remove under the fence, delete snap map, snapshot_remove
    let snap_blob = ok(&mut st, &som, "rbd", "object_map_load", &[]);
    assert_eq!(om_msg(&mut st, "object_map_snap_remove", &snap_blob), 0);
    // objects 0 and 2: CLEAN and EXISTS in the snap map -> back to EXISTS; object 1 already EXISTS
    let m = om_load(&mut st, OM);
    assert_eq!((m.get(0), m.get(1), m.get(2)), (1, 1, 1));
    st.msg(&som, |c| (c.remove().map_or(-1, |_| 0), ()));
    ok(&mut st, HDR, "rbd", "snapshot_remove", &u64b(4));
    assert_eq!(
        snapcontext(&mut st, HDR),
        (4, vec![]),
        "snap_seq is never lowered"
    );
    // snapshot_add with an older id (lost race) is ESTALE; same id as seq is allowed
    err(
        &mut st,
        HDR,
        "rbd",
        "snapshot_add",
        &args(&[s("x"), u64b(3)]),
        ESTALE,
    );
    snap_add(&mut st, HDR, "y", 4);
    // limit, rename, trash
    ok(&mut st, HDR, "rbd", "snapshot_set_limit", &u64b(1));
    err(
        &mut st,
        HDR,
        "rbd",
        "snapshot_add",
        &args(&[s("z"), u64b(5)]),
        EDQUOT,
    );
    ok(&mut st, HDR, "rbd", "snapshot_set_limit", &u64b(u64::MAX));
    ok(
        &mut st,
        HDR,
        "rbd",
        "snapshot_rename",
        &args(&[u64b(4), s("yy")]),
    );
    assert_eq!(txt(&snap_info(&mut st, HDR, 4).name), "yy");
    ok(&mut st, HDR, "rbd", "snapshot_trash_add", &u64b(4));
    assert_eq!(op_features(&mut st, HDR), 8, "SNAP_TRASH");
    assert_eq!(get_features(&mut st, HDR), FEATURES | 0x100, "OPERATIONS");
    let si = snap_info(&mut st, HDR, 4);
    assert!(matches!(&si.ns, SnapNs::Trash { original_name, .. } if original_name == b"yy"));
    assert_eq!(si.name.len(), 36);
    ok(&mut st, HDR, "rbd", "snapshot_remove", &u64b(4));
    assert_eq!(op_features(&mut st, HDR), 0);
    assert_eq!(get_features(&mut st, HDR), FEATURES);
}

#[test]
fn clone_v2_and_flatten() {
    let mut st = MemStore::new();
    const PID: &str = "20parent";
    const CID: &str = "30child";
    let phdr = format!("rbd_header.{PID}");
    let chdr = format!("rbd_header.{CID}");
    create_image(&mut st, "parent", PID, 40 << 20, FEATURES);
    snap_add(&mut st, &phdr, "base", 4);
    ok(
        &mut st,
        &phdr,
        "rbd",
        "set_protection_status",
        &args(&[u64b(4), vec![2]]),
    );
    // clone: child create, op_features_set(CLONE_CHILD), parent_attach, child_attach on the PARENT
    create_image(&mut st, "child", CID, 40 << 20, FEATURES);
    ok(
        &mut st,
        &chdr,
        "rbd",
        "op_features_set",
        &args(&[u64b(2), u64b(2)]),
    );
    assert_eq!(get_features(&mut st, &chdr), FEATURES | 0x100);
    ok(
        &mut st,
        &chdr,
        "rbd",
        "parent_attach",
        &args(&[e(&pspec(1, PID, 4)), u64b(40 << 20)]),
    );
    ok(
        &mut st,
        &phdr,
        "rbd",
        "child_attach",
        &args(&[u64b(4), e(&child(1, CID))]),
    );
    err(
        &mut st,
        &phdr,
        "rbd",
        "child_attach",
        &args(&[u64b(4), e(&child(1, CID))]),
        EEXIST,
    );
    // parent side state
    assert_eq!(op_features(&mut st, &phdr), 1, "CLONE_PARENT");
    assert_eq!(snap_info(&mut st, &phdr, 4).child_count, 1);
    let kids: std::collections::BTreeSet<ChildImageSpec> =
        d(&ok(&mut st, &phdr, "rbd", "children_list", &u64b(4)));
    assert_eq!(kids.into_iter().collect::<Vec<_>>(), vec![child(1, CID)]);
    // unprotect would find the child via child_count; snapshot cannot go
    err(&mut st, &phdr, "rbd", "snapshot_remove", &u64b(4), EBUSY);
    // child open: parent_get / parent_overlap_get / features
    let ps: ParentImageSpec = d(&ok(&mut st, &chdr, "rbd", "parent_get", &[]));
    assert_eq!(ps, pspec(1, PID, 4));
    assert_eq!(
        ok(&mut st, &chdr, "rbd", "parent_overlap_get", &u64b(NOSNAP)),
        args(&[vec![1], u64b(40 << 20)])
    );
    // child snapshot while attached: record carries parent_overlap
    snap_add(&mut st, &chdr, "csnap", 7);
    assert_eq!(
        ok(&mut st, &chdr, "rbd", "parent_overlap_get", &u64b(7)),
        args(&[vec![1], u64b(40 << 20)])
    );
    // shrink the child: head overlap clamps, snapshot overlap stays
    ok(&mut st, &chdr, "rbd", "set_size", &u64b(10 << 20));
    assert_eq!(
        ok(&mut st, &chdr, "rbd", "parent_overlap_get", &u64b(NOSNAP)),
        args(&[vec![1], u64b(10 << 20)])
    );
    assert_eq!(
        ok(&mut st, &chdr, "rbd", "parent_overlap_get", &u64b(7)),
        args(&[vec![1], u64b(40 << 20)])
    );
    // COPY-UP of object 0: first write guarded by stat (ENOENT) -> sparse_copyup + alloc hint + write
    let obj0 = format!("{PFX}.{:016x}", 0);
    let ext = args(&[vec![1, 0, 0, 0], u64b(0), u64b(4), e(&b"data".to_vec())]);
    let (ret, _) = st.msg(&obj0, |c| {
        assert_eq!(c.stat(), Err(ENOENT));
        let a = c.call("rbd", "sparse_copyup", &ext);
        (a.ret, ())
    });
    assert_eq!(ret, 0);
    assert_eq!(st.obj(&obj0).unwrap().data, b"data");
    ok(
        &mut st,
        &obj0,
        "rbd",
        "sparse_copyup",
        &args(&[vec![1, 0, 0, 0], u64b(0), u64b(2), e(&b"XX".to_vec())]),
    );
    assert_eq!(
        st.obj(&obj0).unwrap().data,
        b"data",
        "existing object: copyup is a no-op"
    );
    // flatten: child_detach (parent header), parent_detach (child header)
    ok(
        &mut st,
        &phdr,
        "rbd",
        "child_detach",
        &args(&[u64b(4), e(&child(1, CID))]),
    );
    assert_eq!(op_features(&mut st, &phdr), 0);
    assert_eq!(get_features(&mut st, &phdr), FEATURES);
    err(&mut st, &phdr, "rbd", "children_list", &u64b(4), ENOENT);
    ok(&mut st, &chdr, "rbd", "parent_detach", &[]);
    assert!(
        st.omap_get(&chdr, "parent").is_none(),
        "deep-flatten removes the parent key"
    );
    assert_eq!(op_features(&mut st, &chdr), 0);
    assert_eq!(get_features(&mut st, &chdr), FEATURES);
    assert!(!d::<ParentImageSpec>(&ok(&mut st, &chdr, "rbd", "parent_get", &[])).exists());
    assert_eq!(
        ok(&mut st, &chdr, "rbd", "parent_overlap_get", &u64b(7)),
        [0],
        "snapshot reference cleared"
    );
    err(&mut st, &chdr, "rbd", "parent_detach", &[], ENOENT);
    // now the parent snapshot can be unprotected and removed
    ok(
        &mut st,
        &phdr,
        "rbd",
        "set_protection_status",
        &args(&[u64b(4), vec![0]]),
    );
    ok(&mut st, &phdr, "rbd", "snapshot_remove", &u64b(4));
}

#[test]
fn clone_v1_children_object() {
    let mut st = MemStore::new();
    // probe on a pool without rbd_children: ENOENT (object created first by another pool's clone)
    st.msg("rbd_children", |c| (c.create(false).map_or(-1, |_| 0), ()));
    let key = |pool: u64, p: &str, snap: u64| args(&[u64b(pool), s(p), u64b(snap)]);
    err(
        &mut st,
        "rbd_children",
        "rbd",
        "get_children",
        &key(1, "20parent", 4),
        ENOENT,
    );
    ok(
        &mut st,
        "rbd_children",
        "rbd",
        "add_child",
        &args(&[key(1, "20parent", 4), s("c1")]),
    );
    ok(
        &mut st,
        "rbd_children",
        "rbd",
        "add_child",
        &args(&[key(1, "20parent", 4), s("c0")]),
    );
    err(
        &mut st,
        "rbd_children",
        "rbd",
        "add_child",
        &args(&[key(1, "20parent", 4), s("c1")]),
        EEXIST,
    );
    // binary key layout: u64 pool | string image | u64 snap
    let k = key(1, "20parent", 4);
    assert!(st.obj("rbd_children").unwrap().omap.contains_key(&k));
    let set: std::collections::BTreeSet<String> =
        d(&ok(&mut st, "rbd_children", "rbd", "get_children", &k));
    assert_eq!(set.into_iter().collect::<Vec<_>>(), ["c0", "c1"]);
    ok(
        &mut st,
        "rbd_children",
        "rbd",
        "remove_child",
        &args(&[k.clone(), s("c1")]),
    );
    ok(
        &mut st,
        "rbd_children",
        "rbd",
        "remove_child",
        &args(&[k.clone(), s("c0")]),
    );
    assert!(
        st.obj("rbd_children").unwrap().omap.is_empty(),
        "last child removes the key"
    );
    err(
        &mut st,
        "rbd_children",
        "rbd",
        "remove_child",
        &args(&[k, s("c0")]),
        ENOENT,
    );
}

#[test]
fn flatten_without_deep_flatten_keeps_spec_for_snapshots() {
    let mut st = MemStore::new();
    const CID: &str = "30child";
    let chdr = format!("rbd_header.{CID}");
    create_image(&mut st, "child", CID, 40 << 20, 0x1d); // no deep-flatten
    ok(
        &mut st,
        &chdr,
        "rbd",
        "op_features_set",
        &args(&[u64b(2), u64b(2)]),
    );
    ok(
        &mut st,
        &chdr,
        "rbd",
        "parent_attach",
        &args(&[e(&pspec(1, "20parent", 4)), u64b(40 << 20)]),
    );
    snap_add(&mut st, &chdr, "cs", 7);
    ok(&mut st, &chdr, "rbd", "parent_detach", &[]);
    let p: Parent = d(st.omap_get(&chdr, "parent").unwrap());
    assert_eq!((p.head_overlap, txt(&p.image_id)), (None, "20parent"));
    assert_eq!(
        op_features(&mut st, &chdr),
        2,
        "CLONE_CHILD stays while a snapshot references the parent"
    );
    assert_eq!(
        ok(&mut st, &chdr, "rbd", "parent_overlap_get", &u64b(7)),
        args(&[vec![1], u64b(40 << 20)])
    );
    // removing the last referencing snapshot drops the parent key and CLONE_CHILD
    ok(&mut st, &chdr, "rbd", "snapshot_remove", &u64b(7));
    assert!(st.omap_get(&chdr, "parent").is_none());
    assert_eq!(op_features(&mut st, &chdr), 0);
}

#[test]
fn object_map_rebuild_and_feature_flags() {
    let mut st = MemStore::new();
    create_image(&mut st, "img", ID, 40 << 20, FEATURES);
    // set_flags(OBJECT_MAP_INVALID) head and snapshot
    ok(&mut st, HDR, "rbd", "set_flags", &args(&[u64b(1), u64b(1)]));
    assert_eq!(
        ok(&mut st, HDR, "rbd", "get_flags", &u64b(NOSNAP)),
        1u64.to_le_bytes()
    );
    snap_add(&mut st, HDR, "s", 4);
    assert_eq!(snap_info(&mut st, HDR, 4).image_size, 40 << 20);
    ok(
        &mut st,
        HDR,
        "rbd",
        "set_flags",
        &args(&[u64b(2), u64b(2), u64b(4)]),
    );
    assert_eq!(
        ok(&mut st, HDR, "rbd", "get_flags", &u64b(4)),
        3u64.to_le_bytes(),
        "snapshot inherits the head flags at add"
    );
    // rebuild: object_map_save of a rebuilt map, flags cleared
    lock_om(&mut st);
    let mut m = ObjMap::new(10, 0);
    m.set(3, 1);
    assert_eq!(om_msg(&mut st, "object_map_save", &m.encode_nocrc()), 0);
    assert_eq!(om_load(&mut st, OM), m);
    assert_eq!(
        &st.obj(OM).unwrap().data[18 + 3..],
        &m.encode()[18 + 3..],
        "stored with CRC footer"
    );
    ok(&mut st, HDR, "rbd", "set_flags", &args(&[u64b(0), u64b(1)]));
    assert_eq!(
        ok(&mut st, HDR, "rbd", "get_flags", &u64b(NOSNAP)),
        0u64.to_le_bytes()
    );
    // feature enable/disable
    ok(
        &mut st,
        HDR,
        "rbd",
        "set_features",
        &args(&[u64b(0), u64b(0x20)]),
    ); // disable deep-flatten
    assert_eq!(get_features(&mut st, HDR), FEATURES & !0x20);
    err(
        &mut st,
        HDR,
        "rbd",
        "set_features",
        &args(&[u64b(0x20), u64b(0x20)]),
        EINVAL,
    );
    err(
        &mut st,
        HDR,
        "rbd",
        "set_features",
        &args(&[u64b(0x100), u64b(0x100)]),
        EINVAL,
    );
    ok(
        &mut st,
        HDR,
        "rbd",
        "set_features",
        &args(&[u64b(0x40), u64b(0x40)]),
    ); // journaling
    // object-map CRC slots: update across the 16384-element block boundary rewrites both slots
    let mut st2 = MemStore::new();
    ok(
        &mut st2,
        OM,
        "rbd",
        "object_map_resize",
        &args(&[u64b(40000), vec![0]]),
    );
    ok(
        &mut st2,
        OM,
        "rbd",
        "object_map_update",
        &upd(16380, 16390, 1, None),
    );
    let raw = st2.obj(OM).unwrap().data.clone();
    let m2 = ObjMap::decode(&raw).expect("CRCs valid after partial update");
    assert_eq!(
        (m2.get(16379), m2.get(16380), m2.get(16389), m2.get(16390)),
        (0, 1, 1, 0)
    );
    assert_eq!(raw, m2.encode(), "partial update == full re-encode");
    assert_eq!(bitvec::data_len(40000), 10000);
}

#[test]
fn object_map_bulk_fill_matches_element_reference() {
    // Grow/creation fills whole interior bytes; the result must be exactly the element-wise fill
    // (`object_map_resize` up to MAX_OBJECT_MAP_OBJECT_COUNT = 256M elements).
    fn reference(n: u64, fill: u8) -> Vec<u8> {
        let mut d = vec![0u8; bitvec::data_len(n)];
        for i in 0..n {
            bitvec::set(&mut d, i, fill);
        }
        d
    }
    for fill in [0u8, 1, 2, 3, 7, 255] {
        for n in [0u64, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 1000, 16384, 16385] {
            let m = ObjMap::new(n, fill);
            assert_eq!(m.data, reference(n, fill), "new({n}, {fill})");
            assert_eq!(m.n, n);
            for old in [0u64, 1, 3, 4, 5, 16, 16384, 16385] {
                if old > n {
                    continue;
                }
                let mut m = ObjMap::new(old, 1);
                m.resize(n, fill);
                let mut want = reference(old, 1);
                want.resize(bitvec::data_len(n), 0);
                for i in old..n {
                    bitvec::set(&mut want, i, fill & 3);
                }
                assert_eq!(m.data, want, "resize({old}->{n}, {fill})");
            }
        }
    }
    // shrink keeps the padding bits of the last byte untouched
    let mut m = ObjMap::new(16, 1); // 0b01 per element -> 0x55 per byte
    m.resize(5, 0);
    assert_eq!(
        m.data,
        [0x55, 0x55],
        "shrink truncates; the last byte's padding keeps the old value"
    );
    // a grow inside that byte sets only the new elements; the remaining padding stays untouched
    m.resize(6, 0);
    assert_eq!(
        m.data,
        [0x55, 0x45],
        "grow within the last byte keeps its padding"
    );
    // a grow into fresh bytes zeroes their padding
    m.resize(9, 2);
    assert_eq!(m.data, [0x55, 0x4a, 0x80]);
}

#[test]
fn object_map_snap_add_bulk_bytes_match_element_reference() {
    // 01 -> 11 over whole bytes plus a partial tail byte (padding must stay): compare against the
    // element-wise transform for every element count around byte boundaries.
    let mut x = 0x1234_5678u32;
    for n in [0u64, 1, 2, 3, 4, 5, 7, 8, 9, 13, 16, 16383, 16385] {
        let mut m = ObjMap::new(n, 0);
        for i in 0..n {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            m.set(i, (x & 3) as u8);
        }
        let mut st = MemStore::new();
        st.objects.insert(
            OM.into(),
            cls::mem::Obj {
                data: m.encode(),
                ..Default::default()
            },
        );
        ok(&mut st, OM, "rbd", "object_map_snap_add", &[]);
        let got = ObjMap::decode(&st.obj(OM).unwrap().data).unwrap();
        let mut want = m.clone();
        for i in 0..n {
            if want.get(i) == 1 {
                want.set(i, 3);
            }
        }
        assert_eq!(got, want, "n={n}");
    }
}

#[test]
fn object_map_resize_fills_in_bulk_not_per_element() {
    use std::time::Instant;
    // `object_map_resize` of a 1 PiB image grows to MAX_OBJECT_MAP_OBJECT_COUNT elements; the fill
    // must not be one masked read-modify-write per element. Calibrate the element-wise cost on 4M
    // elements (machine-relative, so the gate does not depend on the build mode or CPU).
    const N: u64 = cls::rbd::objmap::MAX_OBJECT_MAP_OBJECT_COUNT;
    const CAL: u64 = 4_000_000;
    let mut d = vec![0u8; bitvec::data_len(CAL)];
    let t = Instant::now();
    for i in 0..CAL {
        bitvec::set(&mut d, i, 1);
    }
    let per_elem = t.elapsed().as_nanos() as f64 / CAL as f64;
    let mut m = ObjMap::new(1000, 0);
    let t = Instant::now();
    m.resize(N, 1);
    let bulk = t.elapsed().as_nanos() as f64;
    assert_eq!((m.n, m.get(999), m.get(1000), m.get(N - 1)), (N, 0, 1, 1));
    assert!(
        bulk * 4.0 < per_elem * N as f64,
        "resize({N}) took {bulk} ns, {N} element-wise sets extrapolate to {} ns",
        per_elem * N as f64
    );
}

#[test]
fn striping_group_and_metadata() {
    let mut st = MemStore::new();
    create_image(&mut st, "img", ID, 40 << 20, FEATURES | 2);
    ok(
        &mut st,
        HDR,
        "rbd",
        "set_stripe_unit_count",
        &args(&[u64b(65536), u64b(8)]),
    );
    let o = ok(&mut st, HDR, "rbd", "get_stripe_unit_count", &[]);
    assert_eq!(
        (
            u64::from_le_bytes(o[..8].try_into().unwrap()),
            u64::from_le_bytes(o[8..].try_into().unwrap())
        ),
        (65536, 8)
    );
    // config overrides: image-meta set/list/get/remove
    let m: BTreeMap<String, Vec<u8>> = BTreeMap::from([
        ("conf_rbd_cache".into(), b"false".to_vec()),
        ("zz".into(), b"1".to_vec()),
    ]);
    ok(&mut st, HDR, "rbd", "metadata_set", &e(&m));
    let l: BTreeMap<String, Vec<u8>> = d(&ok(
        &mut st,
        HDR,
        "rbd",
        "metadata_list",
        &args(&[s(""), u64b(0)]),
    ));
    assert_eq!(l, m);
    assert_eq!(
        d::<Vec<u8>>(&ok(&mut st, HDR, "rbd", "metadata_get", &s("zz"))),
        b"1"
    );
    ok(&mut st, HDR, "rbd", "metadata_remove", &s("zz"));
    err(&mut st, HDR, "rbd", "metadata_get", &s("zz"), ENOENT);
    // group membership
    let g = GroupSpec {
        pool_id: 1,
        group_id: "g1".into(),
    };
    ok(&mut st, HDR, "rbd", "image_group_add", &e(&g));
    assert_eq!(op_features(&mut st, HDR), 4);
    assert_eq!(
        d::<GroupSpec>(&ok(&mut st, HDR, "rbd", "image_group_get", &[])),
        g
    );
    ok(&mut st, HDR, "rbd", "image_group_remove", &e(&g));
    assert_eq!(op_features(&mut st, HDR), 0);
}

#[test]
fn pagination_beyond_one_page() {
    let mut st = MemStore::new();
    // 1100 directory entries in one message (> 1024 omap cap per call, > 64 class page)
    let (ret, _) = st.msg(DIR, |c| {
        for i in 0..1100 {
            let r = c.call(
                "rbd",
                "dir_add_image",
                &args(&[s(&format!("n{i:05}")), s(&format!("id{i}"))]),
            );
            if r.ret < 0 {
                return (r.ret, ());
            }
        }
        (0, ())
    });
    assert_eq!(ret, 0);
    let l: BTreeMap<String, String> = d(&ok(
        &mut st,
        DIR,
        "rbd",
        "dir_list",
        &args(&[s(""), u64b(5000)]),
    ));
    assert_eq!(l.len(), 1100);
    let l: BTreeMap<String, String> = d(&ok(
        &mut st,
        DIR,
        "rbd",
        "dir_list",
        &args(&[s("n00099"), u64b(3)]),
    ));
    assert_eq!(l.keys().collect::<Vec<_>>(), ["n00100", "n00101", "n00102"]);
    // 200 snapshots: get_snapcontext pages through keys
    create_image(&mut st, "img", ID, 40 << 20, FEATURES);
    for i in 1..=200u64 {
        snap_add(&mut st, HDR, &format!("s{i}"), i);
    }
    let (seq, ids) = snapcontext(&mut st, HDR);
    assert_eq!((seq, ids.len(), ids[0], ids[199]), (200, 200, 200, 1));
    let _ = EntityName::client(0);
}

/// Found by ceph_test_cls_rbd (parents_v1/parents_v2): legacy get_parent on an unknown snapshot answers "no parent" (not
/// ENOENT); legacy get_parent / remove_parent refuse a parent that lives in a pool namespace (EXDEV).
#[test]
fn legacy_parent_methods_unknown_snap_and_namespace_parent() {
    let mut st = MemStore::new();
    const CID: &str = "30child";
    let chdr = format!("rbd_header.{CID}");
    create_image(&mut st, "child", CID, 40 << 20, 0x1d);
    let none = [(-1i64).to_le_bytes().to_vec(), e(""), u64b(NOSNAP), u64b(0)].concat();
    assert_eq!(ok(&mut st, &chdr, "rbd", "get_parent", &u64b(123)), none);
    let mut sp = pspec(1, "20parent", 4);
    sp.pool_namespace = "ns".into();
    ok(
        &mut st,
        &chdr,
        "rbd",
        "op_features_set",
        &args(&[u64b(2), u64b(2)]),
    );
    ok(
        &mut st,
        &chdr,
        "rbd",
        "parent_attach",
        &args(&[e(&sp), u64b(10 << 20)]),
    );
    snap_add(&mut st, &chdr, "cs", 10);
    err(&mut st, &chdr, "rbd", "get_parent", &u64b(NOSNAP), EXDEV);
    err(&mut st, &chdr, "rbd", "get_parent", &u64b(10), EXDEV);
    err(&mut st, &chdr, "rbd", "remove_parent", &[], EXDEV);
    ok(&mut st, &chdr, "rbd", "parent_detach", &[]);
}

#[test]
fn all_registered_methods_reject_garbage_input_without_panicking() {
    // every method, empty / short / garbage input: no panic, never a write on failure
    for class in cls::CLASSES {
        for m in cls::methods(class) {
            for input in [
                &[][..],
                &[1][..],
                &[0xff; 3][..],
                &[0xff; 40][..],
                &[0; 64][..],
            ] {
                let mut st = MemStore::new();
                st.msg("o", |c| (c.create(false).map_or(-1, |_| 0), ()));
                let r = st.call("o", class, m.name, input);
                // `hello` deliberately returns positive values (42, bytes read)
                assert!(
                    r.ret <= 0 || *class == "hello",
                    "{class}.{}: {}",
                    m.name,
                    r.ret
                );
            }
        }
    }
}

/// Review regressions (classic BitVector semantics): a CRC-less stored map stays CRC-less across whole-map rewrites
/// (resize / snap_add / snap_remove re-encode with the decoded setting), `object_map_update` always verifies the CRC
/// slots (a CRC-less map has none: -EINVAL, nothing written), and resize compares `default_state` unmasked.
#[test]
fn object_map_crc_setting_and_resize_state_follow_classic() {
    let put = |st: &mut MemStore, b: Vec<u8>| {
        st.msg(OM, |c| (c.write_full(&b).map_or_else(|e| e, |_| 0), ()));
    };
    let mut st = MemStore::new();
    let mut m = ObjMap::new(8, 0);
    m.set(2, 1);
    put(&mut st, m.encode_nocrc());
    ok(
        &mut st,
        OM,
        "rbd",
        "object_map_resize",
        &args(&[u64b(12), vec![0]]),
    );
    let mut want = m.clone();
    want.resize(12, 0);
    assert_eq!(
        st.obj(OM).unwrap().data,
        want.encode_nocrc(),
        "resize keeps no-CRC"
    );
    ok(&mut st, OM, "rbd", "object_map_snap_add", &[]);
    want.set(2, 3);
    assert_eq!(
        st.obj(OM).unwrap().data,
        want.encode_nocrc(),
        "snap_add keeps no-CRC"
    );
    let snap = ObjMap::new(12, 1).encode();
    ok(&mut st, OM, "rbd", "object_map_snap_remove", &snap);
    want.set(2, 1);
    assert_eq!(
        st.obj(OM).unwrap().data,
        want.encode_nocrc(),
        "snap_remove keeps no-CRC"
    );
    let before = st.obj(OM).unwrap().data.clone();
    err(
        &mut st,
        OM,
        "rbd",
        "object_map_update",
        &upd(0, 4, 1, None),
        EINVAL,
    );
    assert_eq!(st.obj(OM).unwrap().data, before);
    // all-zero CRC-less map: crc32c(0) of zero bytes is 0, still EINVAL (missing slot != 0)
    let mut st0 = MemStore::new();
    put(&mut st0, ObjMap::new(8, 0).encode_nocrc());
    err(
        &mut st0,
        OM,
        "rbd",
        "object_map_update",
        &upd(0, 4, 1, None),
        EINVAL,
    );
    // CRC map: unchanged behaviour, CRCs kept
    let mut st = MemStore::new();
    put(&mut st, ObjMap::new(8, 2).encode());
    ok(&mut st, OM, "rbd", "object_map_snap_add", &[]);
    ok(
        &mut st,
        OM,
        "rbd",
        "object_map_resize",
        &args(&[u64b(16), vec![2]]),
    );
    assert_eq!(st.obj(OM).unwrap().data, ObjMap::new(16, 2).encode());
    // shrink with default_state 6 (& 3 == 2): classic compares the full byte -> ESTALE
    err(
        &mut st,
        OM,
        "rbd",
        "object_map_resize",
        &args(&[u64b(8), vec![6]]),
        ESTALE,
    );
    ok(
        &mut st,
        OM,
        "rbd",
        "object_map_resize",
        &args(&[u64b(8), vec![2]]),
    );
    // truncated footer (CRC slots missing): -EINVAL
    let mut raw = st.obj(OM).unwrap().data.clone();
    raw.truncate(raw.len() - 4);
    put(&mut st, raw);
    err(
        &mut st,
        OM,
        "rbd",
        "object_map_update",
        &upd(0, 4, 1, None),
        EINVAL,
    );
}

/// set_id checks the object before decoding (classic order: ENOENT wins over EINVAL); sparse_copyup applies its
/// extent map in offset order (a map on the wire), consuming the data in that order.
#[test]
fn set_id_order_and_sparse_copyup_extent_order() {
    let mut st = MemStore::new();
    err(&mut st, "rbd_id.x", "rbd", "set_id", &[1, 2], ENOENT);
    let ext = args(&[
        vec![2, 0, 0, 0],
        u64b(8),
        u64b(2),
        u64b(0),
        u64b(3),
        e(&b"abcde".to_vec()),
    ]);
    ok(&mut st, "rbd_data.x.0", "rbd", "sparse_copyup", &ext);
    let d = &st.obj("rbd_data.x.0").unwrap().data;
    assert_eq!(&d[..3], b"abc");
    assert_eq!(&d[8..10], b"de");
}
