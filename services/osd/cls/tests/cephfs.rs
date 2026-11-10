// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cephfs class scenarios (spec/cls_cephfs.md) on MemStore.
mod common;
use cls::cephfs::*;
use cls::errno::*;
use cls::mem::MemStore;
use common::*;

const O: &str = "10000000000.00000000";

fn args(idx: u64, size: u64, mtime: i64) -> Vec<u8> {
    e(&AccumulateArgs {
        obj_xattr_name: "scan_ceiling".into(),
        mtime_xattr_name: "scan_mtime".into(),
        obj_size_xattr_name: "scan_max_size".into(),
        obj_index: idx,
        obj_size: size,
        mtime,
    })
}
fn acc(s: &mut MemStore, idx: u64, size: u64, mtime: i64) -> i32 {
    call(
        s,
        O,
        "cephfs",
        "accumulate_inode_metadata",
        &args(idx, size, mtime),
    )
    .ret
}
fn xa(s: &MemStore, n: &str) -> Vec<u8> {
    s.obj(O).unwrap().xattrs[n.as_bytes()].clone()
}
fn ceiling(s: &MemStore) -> ObjCeiling {
    d(&xa(s, "scan_ceiling"))
}

#[test]
fn registry() {
    use cls::registry::*;
    assert_eq!(methods("cephfs").len(), 1);
    assert_eq!(
        lookup("cephfs", "accumulate_inode_metadata").unwrap().flags,
        RW
    );
    assert!(lookup("cephfs", "inject_inode").is_none());
}

#[test]
fn first_write_creates_object_with_exact_bytes() {
    let mut s = MemStore::new();
    assert_eq!(acc(&mut s, 5, 4096, 1000), 0);
    // ObjCeiling (1,1,len 16) {id, size}; mtime and size are bare 8-byte LE
    assert_eq!(
        xa(&s, "scan_ceiling"),
        cat(&[&[1, 1, 16, 0, 0, 0], &u64b(5), &u64b(4096)])
    );
    assert_eq!(xa(&s, "scan_mtime"), 1000i64.to_le_bytes());
    assert_eq!(xa(&s, "scan_max_size"), u64b(4096));
}

#[test]
fn greater_equal_smaller_per_attribute() {
    let mut s = MemStore::new();
    acc(&mut s, 5, 4096, 1000);
    // lower index (ceiling keeps), newer mtime, bigger size: independent updates
    assert_eq!(acc(&mut s, 3, 8192, 2000), 0);
    assert_eq!(ceiling(&s), ObjCeiling { id: 5, size: 4096 });
    assert_eq!(xa(&s, "scan_mtime"), 2000i64.to_le_bytes());
    assert_eq!(xa(&s, "scan_max_size"), u64b(8192));
    // equal index does not replace the ceiling (size differs but only id counts)
    assert_eq!(acc(&mut s, 5, 1, 2000), 0);
    assert_eq!(ceiling(&s), ObjCeiling { id: 5, size: 4096 });
    assert_eq!(xa(&s, "scan_max_size"), u64b(8192));
    // higher index wins, older mtime and smaller size are ignored
    assert_eq!(acc(&mut s, 9, 100, 1500), 0);
    assert_eq!(ceiling(&s), ObjCeiling { id: 9, size: 100 });
    assert_eq!(xa(&s, "scan_mtime"), 2000i64.to_le_bytes());
    assert_eq!(xa(&s, "scan_max_size"), u64b(8192));
    // negative mtimes compare as signed
    let mut s2 = MemStore::new();
    acc(&mut s2, 1, 1, -5);
    acc(&mut s2, 1, 1, -9);
    assert_eq!(xa(&s2, "scan_mtime"), (-5i64).to_le_bytes());
    acc(&mut s2, 1, 1, 3);
    assert_eq!(xa(&s2, "scan_mtime"), 3i64.to_le_bytes());
}

#[test]
fn unusable_existing_values_are_overwritten() {
    let mut s = MemStore::new();
    acc(&mut s, 5, 4096, 1000);
    let o = s.objects.get_mut(O).unwrap();
    o.xattrs.insert("scan_ceiling".into(), vec![1, 2, 3]); // undecodable
    o.xattrs.insert(
        "scan_mtime".into(),
        [&9999i64.to_le_bytes()[..], b"x"].concat(),
    ); // trailing byte
    o.xattrs.insert("scan_max_size".into(), vec![]); // empty
    assert_eq!(acc(&mut s, 1, 7, 5), 0);
    assert_eq!(ceiling(&s), ObjCeiling { id: 1, size: 7 });
    assert_eq!(xa(&s, "scan_mtime"), 5i64.to_le_bytes());
    assert_eq!(xa(&s, "scan_max_size"), u64b(7));
    // short value
    s.objects
        .get_mut(O)
        .unwrap()
        .xattrs
        .insert("scan_mtime".into(), vec![1, 2, 3]);
    acc(&mut s, 1, 7, 6);
    assert_eq!(xa(&s, "scan_mtime"), 6i64.to_le_bytes());
    // a ceiling envelope with trailing bytes after it is junk
    let mut long = xa(&s, "scan_ceiling");
    long.push(0);
    s.objects
        .get_mut(O)
        .unwrap()
        .xattrs
        .insert("scan_ceiling".into(), long);
    acc(&mut s, 0, 2, 6);
    assert_eq!(ceiling(&s), ObjCeiling { id: 0, size: 2 });
}

#[test]
fn newer_envelope_version_with_extra_fields_still_compares() {
    let mut s = MemStore::new();
    acc(&mut s, 5, 4096, 1000);
    // (v2, compat 1) ceiling with an extra trailing field inside the envelope
    let raw = cat(&[&[2, 1, 24, 0, 0, 0], &u64b(50), &u64b(1), &u64b(0xdead)]);
    s.objects
        .get_mut(O)
        .unwrap()
        .xattrs
        .insert("scan_ceiling".into(), raw);
    acc(&mut s, 10, 2, 0);
    assert_eq!(
        xa(&s, "scan_ceiling").len(),
        30,
        "id 10 < 50: v2 value left untouched"
    );
    assert_eq!(ceiling(&s), ObjCeiling { id: 50, size: 1 });
}

#[test]
fn garbage_input() {
    let mut s = MemStore::new();
    for bad in [
        vec![],
        vec![1],
        vec![1, 1, 200, 0, 0, 0, 1],
        args(1, 1, 1)[..10].to_vec(),
    ] {
        err(
            &mut s,
            O,
            "cephfs",
            "accumulate_inode_metadata",
            &bad,
            EINVAL,
        );
    }
    assert!(s.obj(O).is_none());
}
