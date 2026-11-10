// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Ceph `std::string` fields are byte strings: names, keys, ids and tags that are not valid UTF-8
//! (written by a classic primary or a client) must round-trip through the rbd and rgw classes
//! byte-exactly (no EINVAL on input, no lossy conversion in listings, no collapsed entries).
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use cls::rbd::mirror_types::*;
use cls::rbd::types::*;
use cls::rbd::types_group::GroupSnapshot;
use cls::rgw::types::*;
use common::*;
use denc::types::UTime;
use std::collections::BTreeMap;

type Map = BTreeMap<Vec<u8>, Vec<u8>>;

/// Two names that differ only in invalid bytes (lossy conversion maps both to the same text).
const N1: &[u8] = b"vm-\xff";
const N2: &[u8] = b"vm-\x80";
const N3: &[u8] = b"vm-\xfe\xfd";

fn bs(v: &[u8]) -> Vec<u8> {
    e(&v.to_vec())
}
fn rbd_ok(s: &mut MemStore, oid: &str, m: &str, inp: &[u8]) -> Vec<u8> {
    ok(s, oid, "rbd", m, inp)
}
fn rbd_err(s: &mut MemStore, oid: &str, m: &str, inp: &[u8], errno: i32) {
    err(s, oid, "rbd", m, inp, errno)
}
fn list_input(start: &[u8], max: u64) -> Vec<u8> {
    cat(&[&bs(start), &u64b(max)])
}

#[test]
fn rbd_directory_non_utf8_names() {
    let mut s = MemStore::new();
    let o = "rbd_directory";
    rbd_ok(&mut s, o, "dir_add_image", &cat(&[&bs(N1), &bs(b"10aa")]));
    rbd_ok(&mut s, o, "dir_add_image", &cat(&[&bs(N2), &bs(b"10bb")]));
    rbd_err(
        &mut s,
        o,
        "dir_add_image",
        &cat(&[&bs(N1), &bs(b"10cc")]),
        EEXIST,
    );
    // name -> id and id -> name by the real bytes
    assert_eq!(rbd_ok(&mut s, o, "dir_get_id", &bs(N1)), bs(b"10aa"));
    assert_eq!(rbd_ok(&mut s, o, "dir_get_id", &bs(N2)), bs(b"10bb"));
    assert_eq!(rbd_ok(&mut s, o, "dir_get_name", &bs(b"10aa")), bs(N1));
    rbd_err(&mut s, o, "dir_get_id", &bs(b"vm-\xfc"), ENOENT);
    // listing carries the exact bytes and both entries
    let l: Map = d(&rbd_ok(&mut s, o, "dir_list", &list_input(b"", 10)));
    assert_eq!(
        l,
        Map::from([
            (N2.to_vec(), b"10bb".to_vec()),
            (N1.to_vec(), b"10aa".to_vec())
        ])
    );
    // start marker with invalid bytes pages by bytes
    let l: Map = d(&rbd_ok(&mut s, o, "dir_list", &list_input(N2, 10)));
    assert_eq!(l.len(), 1, "start is exclusive of lesser names only: {l:?}");
    assert!(l.contains_key(N1));
    // rename keeps the bytes
    rbd_ok(
        &mut s,
        o,
        "dir_rename_image",
        &cat(&[&bs(N1), &bs(N3), &bs(b"10aa")]),
    );
    assert_eq!(rbd_ok(&mut s, o, "dir_get_id", &bs(N3)), bs(b"10aa"));
    rbd_err(&mut s, o, "dir_get_id", &bs(N1), ENOENT);
    assert_eq!(rbd_ok(&mut s, o, "dir_get_name", &bs(b"10aa")), bs(N3));
    // remove checks name and id bytes
    rbd_err(
        &mut s,
        o,
        "dir_remove_image",
        &cat(&[&bs(N1), &bs(b"10aa")]),
        ENOENT,
    );
    rbd_err(
        &mut s,
        o,
        "dir_remove_image",
        &cat(&[&bs(N3), &bs(b"10bb")]),
        ESTALE,
    );
    rbd_ok(
        &mut s,
        o,
        "dir_remove_image",
        &cat(&[&bs(N3), &bs(b"10aa")]),
    );
    let l: Map = d(&rbd_ok(&mut s, o, "dir_list", &list_input(b"", 10)));
    assert_eq!(l, Map::from([(N2.to_vec(), b"10bb".to_vec())]));
}

#[test]
fn rbd_metadata_non_utf8_keys() {
    let mut s = MemStore::new();
    let h = "rbd_header.10aa";
    rbd_ok(&mut s, h, "dir_add_image", &cat(&[&bs(b"x"), &bs(b"10aa")])); // creates the object
    let m: Map = Map::from([
        (b"k\xff".to_vec(), b"v1".to_vec()),
        (b"k\x80".to_vec(), b"v2".to_vec()),
        (b"conf_\xfe".to_vec(), b"\xffraw".to_vec()),
    ]);
    rbd_ok(&mut s, h, "metadata_set", &e(&m));
    assert_eq!(rbd_ok(&mut s, h, "metadata_get", &bs(b"k\xff")), bs(b"v1"));
    assert_eq!(rbd_ok(&mut s, h, "metadata_get", &bs(b"k\x80")), bs(b"v2"));
    let l: Map = d(&rbd_ok(&mut s, h, "metadata_list", &list_input(b"", 10)));
    assert_eq!(l, m);
    // start marker is a raw key
    let l: Map = d(&rbd_ok(
        &mut s,
        h,
        "metadata_list",
        &list_input(b"k\x80", 10),
    ));
    assert_eq!(l, Map::from([(b"k\xff".to_vec(), b"v1".to_vec())]));
    rbd_ok(&mut s, h, "metadata_remove", &bs(b"k\xff"));
    rbd_err(&mut s, h, "metadata_get", &bs(b"k\xff"), ENOENT);
    assert_eq!(rbd_ok(&mut s, h, "metadata_get", &bs(b"k\x80")), bs(b"v2"));
}

#[test]
fn rbd_trash_and_namespace_non_utf8() {
    let mut s = MemStore::new();
    let t = "rbd_trash";
    let spec = |name: &[u8]| TrashImageSpec {
        source: 0,
        name: name.to_vec(),
        deletion_time: UTime::new(1, 2),
        deferment_end_time: UTime::new(3, 4),
        state: 0,
    };
    rbd_ok(&mut s, t, "trash_add", &cat(&[&bs(b"10aa"), &e(&spec(N1))]));
    rbd_ok(&mut s, t, "trash_add", &cat(&[&bs(b"10bb"), &e(&spec(N2))]));
    assert_eq!(rbd_ok(&mut s, t, "trash_get", &bs(b"10aa")), e(&spec(N1)));
    let l: BTreeMap<Vec<u8>, TrashImageSpec> =
        d(&rbd_ok(&mut s, t, "trash_list", &list_input(b"", 10)));
    assert_eq!(l.len(), 2);
    assert_eq!(l[b"10aa".as_slice()].name, N1);
    assert_eq!(l[b"10bb".as_slice()].name, N2);

    let ns = "rbd_namespace";
    rbd_ok(&mut s, ns, "namespace_add", &bs(b"ns\xff"));
    rbd_ok(&mut s, ns, "namespace_add", &bs(b"ns\x80"));
    rbd_err(&mut s, ns, "namespace_add", &bs(b"ns\xff"), EEXIST);
    let l: Vec<Vec<u8>> = d(&rbd_ok(&mut s, ns, "namespace_list", &list_input(b"", 10)));
    assert_eq!(l, vec![b"ns\x80".to_vec(), b"ns\xff".to_vec()]);
    rbd_ok(&mut s, ns, "namespace_remove", &bs(b"ns\xff"));
    let l: Vec<Vec<u8>> = d(&rbd_ok(&mut s, ns, "namespace_list", &list_input(b"", 10)));
    assert_eq!(l, vec![b"ns\x80".to_vec()]);
}

#[test]
fn rbd_group_non_utf8() {
    let mut s = MemStore::new();
    let g = "rbd_group_directory";
    rbd_ok(&mut s, g, "group_dir_add", &cat(&[&bs(N1), &bs(b"20aa")]));
    rbd_ok(&mut s, g, "group_dir_add", &cat(&[&bs(N2), &bs(b"20bb")]));
    let l: Map = d(&rbd_ok(&mut s, g, "group_dir_list", &list_input(b"", 10)));
    assert_eq!(
        l,
        Map::from([
            (N2.to_vec(), b"20bb".to_vec()),
            (N1.to_vec(), b"20aa".to_vec())
        ])
    );
    let gh = "rbd_group_header.20aa";
    let snap = |id: &[u8], name: &[u8]| GroupSnapshot {
        id: id.to_vec(),
        name: name.to_vec(),
        state: 0,
        snaps: Vec::new(),
    };
    rbd_ok(&mut s, gh, "group_snap_set", &e(&snap(b"s\xff", b"n\xfe")));
    rbd_ok(&mut s, gh, "group_snap_set", &e(&snap(b"s\x80", b"n\xfd")));
    let got: GroupSnapshot = d(&rbd_ok(&mut s, gh, "group_snap_get_by_id", &bs(b"s\xff")));
    assert_eq!(got, snap(b"s\xff", b"n\xfe"));
    let o: BTreeMap<Vec<u8>, u64> = d(&rbd_ok(
        &mut s,
        gh,
        "group_snap_list_order",
        &list_input(b"", 10),
    ));
    assert_eq!(
        o.keys().cloned().collect::<Vec<_>>(),
        vec![b"s\x80".to_vec(), b"s\xff".to_vec()]
    );
    rbd_ok(&mut s, gh, "group_snap_remove", &bs(b"s\xff"));
    rbd_err(&mut s, gh, "group_snap_get_by_id", &bs(b"s\xff"), ENOENT);
}

#[test]
fn rbd_mirror_non_utf8() {
    let mut s = MemStore::new();
    let p = "rbd_mirroring";
    rbd_ok(&mut s, p, "mirror_uuid_set", &bs(b"pool-uuid-1"));
    rbd_ok(&mut s, p, "mirror_mode_set", &1u32.to_le_bytes());
    let peer = |uuid: &[u8], site: &[u8]| MirrorPeer {
        uuid: uuid.to_vec(),
        direction: DIR_RX_TX,
        site_name: site.to_vec(),
        client_name: b"client.\xff".to_vec(),
        mirror_uuid: b"m\x80".to_vec(),
        last_seen: UTime::default(),
    };
    let p1 = peer(b"u\xff", b"site\xff");
    rbd_ok(&mut s, p, "mirror_peer_add", &e(&p1));
    // another peer whose names differ only in invalid bytes is distinct, not a duplicate
    let mut p2 = peer(b"u\x80", b"site\x80");
    p2.mirror_uuid = b"m\xff".to_vec();
    rbd_ok(&mut s, p, "mirror_peer_add", &e(&p2));
    let l: Vec<MirrorPeer> = d(&rbd_ok(&mut s, p, "mirror_peer_list", &[]));
    assert_eq!(l, vec![p2.clone(), p1.clone()]);

    let img = MirrorImage {
        global_image_id: b"g\xff".to_vec(),
        state: IMG_ENABLED,
        mode: 0,
    };
    rbd_ok(
        &mut s,
        p,
        "mirror_image_set",
        &cat(&[&bs(b"id\xff"), &e(&img)]),
    );
    let img2 = MirrorImage {
        global_image_id: b"g\x80".to_vec(),
        ..img.clone()
    };
    rbd_ok(
        &mut s,
        p,
        "mirror_image_set",
        &cat(&[&bs(b"id\x80"), &e(&img2)]),
    );
    assert_eq!(
        rbd_ok(&mut s, p, "mirror_image_get_image_id", &bs(b"g\xff")),
        bs(b"id\xff")
    );
    let l: Map = d(&rbd_ok(
        &mut s,
        p,
        "mirror_image_list",
        &list_input(b"", 10),
    ));
    assert_eq!(
        l,
        Map::from([
            (b"id\x80".to_vec(), b"g\x80".to_vec()),
            (b"id\xff".to_vec(), b"g\xff".to_vec())
        ])
    );
}

const O: &str = ".dir.b1.0";

#[test]
fn rgw_non_utf8_content_type_through_complete_and_listing() {
    let mut s = MemStore::new();
    ok(&mut s, O, "rgw", "bucket_init_index", &[]);
    let meta = DirEntryMeta {
        category: 1,
        size: 10,
        accounted_size: 10,
        mtime: UTime::new(7, 9),
        etag: b"e\xff".to_vec(),
        owner: b"own\x80".to_vec(),
        owner_display_name: b"disp\xfe".to_vec(),
        content_type: b"text/\xff\x80x".to_vec(),
        storage_class: b"CLS\xfd".to_vec(),
        user_data: b"ud\xff".to_vec(),
        ..Default::default()
    };
    let key = ObjKey::new("obj", "");
    let prep = ObjPrepareOp {
        op: op::ADD,
        tag: b"tag\xff".to_vec(),
        locator: b"loc\x80".to_vec(),
        key: key.clone(),
        ..Default::default()
    };
    assert_eq!(
        call(&mut s, O, "rgw", "bucket_prepare_op", &e(&prep)).ret,
        0
    );
    let comp = ObjCompleteOp {
        op: op::ADD,
        ver: EntryVer { pool: 3, epoch: 0 },
        meta: meta.clone(),
        op_tag: b"tag\xff".to_vec(),
        locator: b"loc\x80".to_vec(),
        key: key.clone(),
        ..Default::default()
    };
    assert_eq!(
        call(&mut s, O, "rgw", "bucket_complete_op", &e(&comp)).ret,
        0
    );
    let list = ListOp {
        num_entries: 10,
        filter_prefix: Vec::new(),
        start_obj: ObjKey::from_bytes(b"", b""),
        list_versions: false,
        delimiter: Vec::new(),
    };
    let r = call(&mut s, O, "rgw", "bucket_list", &e(&list));
    assert_eq!(r.ret, 0);
    let l: ListRet = d(&r.out);
    let en = &l.dir.m[b"obj".as_slice()];
    assert_eq!(en.meta, meta);
    assert_eq!(en.tag, b"tag\xff");
}

#[test]
fn rgw_stored_entry_with_non_utf8_fields_decodes_and_lists() {
    // an entry written by a classic primary: every string field holds arbitrary bytes
    let mut s = MemStore::new();
    ok(&mut s, O, "rgw", "bucket_init_index", &[]);
    let en = DirEntry {
        key: ObjKey::new("classic", ""),
        ver: EntryVer { pool: 3, epoch: 1 },
        exists: true,
        meta: DirEntryMeta {
            category: 1,
            size: 5,
            accounted_size: 5,
            mtime: UTime::new(1, 1),
            etag: b"\xff\xfe".to_vec(),
            owner: b"\x80".to_vec(),
            owner_display_name: b"\x81".to_vec(),
            content_type: b"application/\xfd".to_vec(),
            user_data: b"\xfc".to_vec(),
            storage_class: b"\xfb".to_vec(),
            ..Default::default()
        },
        locator: b"\xfa".to_vec(),
        tag: b"\xf9".to_vec(),
        flags: 0,
        ..Default::default()
    };
    s.objects
        .entry(O.into())
        .or_default()
        .omap
        .insert(b"classic".to_vec(), e(&en));
    let list = ListOp {
        num_entries: 10,
        filter_prefix: Vec::new(),
        start_obj: ObjKey::from_bytes(b"", b""),
        list_versions: false,
        delimiter: Vec::new(),
    };
    let r = call(&mut s, O, "rgw", "bucket_list", &e(&list));
    assert_eq!(
        r.ret, 0,
        "stored entry with non-UTF-8 strings must stay listable"
    );
    let l: ListRet = d(&r.out);
    assert_eq!(l.dir.m[b"classic".as_slice()], en);
    // overwrite through complete_op keeps working on such an entry
    let comp = ObjCompleteOp {
        op: op::ADD,
        ver: EntryVer { pool: 3, epoch: 2 },
        meta: en.meta.clone(),
        key: ObjKey::new("classic", ""),
        ..Default::default()
    };
    assert_eq!(
        call(&mut s, O, "rgw", "bucket_complete_op", &e(&comp)).ret,
        0
    );
}
