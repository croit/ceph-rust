// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Golden vectors from ceph-dencoder (testdata/cls/dencoder, regenerate with testdata/cls/gen.sh):
//! decode every `<n>.bin`, re-encode, require identical bytes. Featured types are also checked in
//! the legacy forms (`.noaddr2.bin`, `.nonautilus.bin`).

use cls::lock::*;
use cls::rbd::bitvec::ObjMap;
use cls::rbd::types::*;
use denc::{Decode, Decoder, Encode};
use std::fs;
use std::path::PathBuf;

const NOADDR2: u64 = !(1u64 << 59);
const NONAUTILUS: u64 = !4u64;

fn dir(t: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/cls/dencoder")
        .join(t)
}

/// Returns number of vectors checked.
fn rt<T>(t: &str, suffix: &str, feat: u64) -> usize
where
    T: for<'a> Decode<'a> + Encode + std::fmt::Debug,
{
    let mut n = 1;
    loop {
        let p = dir(t).join(format!("{n}{suffix}.bin"));
        let Ok(bytes) = fs::read(&p) else { break };
        let mut d = Decoder::new(&bytes);
        let v = T::decode(&mut d).unwrap_or_else(|e| panic!("{t} {n}{suffix}: {e}"));
        assert_eq!(d.remaining(), 0, "{t} {n}{suffix}: trailing bytes");
        let re = v.encode_to_vec_with_features(feat).unwrap();
        assert_eq!(re, bytes, "{t} {n}{suffix} re-encode of {v:?}");
        n += 1;
    }
    assert!(n > 1, "no vectors for {t}{suffix}");
    n - 1
}

fn plain<T: for<'a> Decode<'a> + Encode + std::fmt::Debug>(t: &str) -> usize {
    rt::<T>(t, "", u64::MAX)
}

fn featured<T: for<'a> Decode<'a> + Encode + std::fmt::Debug>(
    t: &str,
    legacy: &[(&str, u64)],
) -> usize {
    let n = rt::<T>(t, "", u64::MAX);
    for (suf, f) in legacy {
        assert_eq!(rt::<T>(t, suf, *f), n, "{t}{suf}");
    }
    n
}

#[test]
fn lock_types() {
    let a2 = [(".noaddr2", NOADDR2)];
    assert_eq!(plain::<LockerId>("locker_id_t"), 2);
    assert_eq!(featured::<LockerInfo>("locker_info_t", &a2), 2);
    assert_eq!(featured::<LockInfo>("lock_info_t", &a2), 2);
    assert_eq!(featured::<GetInfoReply>("cls_lock_get_info_reply", &a2), 2);
    assert_eq!(plain::<LockOp>("cls_lock_lock_op"), 2);
    assert_eq!(plain::<UnlockOp>("cls_lock_unlock_op"), 2);
    assert_eq!(plain::<BreakOp>("cls_lock_break_op"), 2);
    assert_eq!(plain::<GetInfoOp>("cls_lock_get_info_op"), 2);
    assert_eq!(plain::<ListLocksReply>("cls_lock_list_locks_reply"), 2);
    assert_eq!(plain::<AssertOp>("cls_lock_assert_op"), 2);
    assert_eq!(plain::<SetCookieOp>("cls_lock_set_cookie_op"), 2);
}

#[test]
fn rbd_types() {
    let nn = [(".nonautilus", NONAUTILUS)];
    assert_eq!(featured::<Parent>("cls_rbd_parent", &nn), 4);
    assert_eq!(featured::<SnapRec>("cls_rbd_snap", &nn), 4);
    assert_eq!(plain::<ParentImageSpec>("ParentImageSpec"), 3);
    assert_eq!(plain::<ChildImageSpec>("ChildImageSpec"), 3);
    assert_eq!(plain::<SnapNs>("SnapshotNamespace"), 8);
    assert_eq!(plain::<SnapshotInfo>("SnapshotInfo"), 5);
    assert_eq!(plain::<GroupSpec>("GroupSpec"), 2);
    assert_eq!(plain::<MirrorImage>("MirrorImage"), 3);
}

#[test]
fn bitvector_blobs() {
    let mut n = 1;
    while let Ok(b) = fs::read(dir("BitVector2").join(format!("{n}.bin"))) {
        let m = ObjMap::decode(&b).unwrap_or_else(|_| panic!("BitVector2 {n}"));
        assert_eq!(m.encode(), b, "BitVector2 {n}");
        n += 1;
    }
    assert_eq!(n - 1, 2);
}

/// Worked example of spec C.1.4 (derived there; cross-checked here against our encoder and the
/// dencoder-verified CRC rules above).
#[test]
fn bitvector_worked_example() {
    let mut m = ObjMap::new(4, 0);
    m.set(0, 1);
    m.set(2, 2);
    m.set(3, 3);
    assert_eq!(m.data, [0x4b]);
    let blob = m.encode();
    assert_eq!(blob.len(), 35);
    assert_eq!(
        &blob[18..],
        [
            0x4b, 0x0c, 0, 0, 0, 0x3f, 0x38, 0xaa, 0xcb, 1, 0, 0, 0, 0x87, 0xb6, 0xf2, 0xd8
        ]
    );
    assert_eq!(m.encode_nocrc().len(), 18 + 1 + 4);
}

/// Mirroring structs (spec cls_rbd.md C.3.2) vs ceph-dencoder.
#[test]
fn rbd_mirror_types() {
    use cls::rbd::mirror_types::*;
    let a2 = [(".noaddr2", NOADDR2), (".nonautilus", NONAUTILUS)];
    assert_eq!(plain::<MirrorPeer>("MirrorPeer"), 4);
    assert_eq!(plain::<ImageMap>("MirrorImageMap"), 2);
    assert_eq!(plain::<ImageStatus>("MirrorImageStatus"), 3);
    assert_eq!(plain::<SiteStatus>("MirrorImageSiteStatus"), 4);
    assert_eq!(
        featured::<OnDiskStatus>("MirrorImageSiteStatusOnDisk", &a2),
        3
    );
}
