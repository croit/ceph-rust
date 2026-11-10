// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `rados list-inconsistent-obj|snapset` (pg op SCRUBLS 0x1507): the scrub findings of a PG in the classic wire form
//! (`scrub_ls_arg_t` in, `scrub_ls_result_t` of `inconsistent_obj_wrapper` / `inconsistent_snapset_wrapper` out).
//! The error bit numbers of the wire are the rados `err_t` / `obj_err_t` / `inconsistent_snapset_t` values.

use crate::scrubcmp::{ObjReport, err, oerr};
use denc::types::{Hobject, SnapId};
use std::collections::BTreeMap;

// shard_info err_t
const S_MISSING: u64 = 1 << 1;
const S_STAT: u64 = 1 << 2;
const S_READ: u64 = 1 << 3;
const S_DATA_DIGEST: u64 = 1 << 9;
const S_OMAP_DIGEST: u64 = 1 << 10;
const S_SIZE: u64 = 1 << 11;
const S_EC_HASH: u64 = 1 << 12;
const S_EC_SIZE: u64 = 1 << 13;
const S_INFO_MISSING: u64 = 1 << 14;
const S_INFO_CORRUPT: u64 = 1 << 15;
const S_SS_MISSING: u64 = 1 << 16;
const S_SS_CORRUPT: u64 = 1 << 17;
// obj_err_t
const O_INFO: u64 = 1 << 1;
const O_DATA_DIGEST: u64 = 1 << 4;
const O_OMAP_DIGEST: u64 = 1 << 5;
const O_SIZE: u64 = 1 << 6;
const O_ATTR_VALUE: u64 = 1 << 7;
const O_ATTR_NAME: u64 = 1 << 8;
const O_SNAPSET: u64 = 1 << 9;
const O_SIZE_TOO_LARGE: u64 = 1 << 11;
// inconsistent_snapset_t
const SS_CLONE_MISSING: u64 = 1 << 2;
const SS_SNAP_ERROR: u64 = 1 << 3;
const SS_HEADLESS: u64 = 1 << 5;
const SS_SIZE_MISMATCH: u64 = 1 << 6;
const SS_EXTRA_CLONES: u64 = 1 << 9;

/// Decoded `scrub_ls_arg_t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsArg {
    /// 0 = any.
    pub interval: u32,
    pub get_snapsets: bool,
    /// `(name, nspace, snap)` of the last object of the previous page; empty name = from the start.
    pub start_after: (Vec<u8>, Vec<u8>, u64),
    /// 0 = no limit.
    pub max_return: u64,
}

struct Rd<'a>(&'a [u8]);
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = self.0.split_at_checked(n)?;
        self.0 = b;
        Some(a)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn bytes(&mut self) -> Option<Vec<u8>> {
        let n = self.u32()? as usize;
        Some(self.take(n)?.to_vec())
    }
}

/// Decode the op's indata.
pub fn decode_arg(b: &[u8]) -> Option<LsArg> {
    let mut r = Rd(b);
    r.take(2)?; // struct_v, compat
    let len = r.u32()? as usize;
    let mut r = Rd(r.take(len)?);
    Some(LsArg {
        interval: r.u32()?,
        get_snapsets: r.u32()? != 0,
        start_after: (r.bytes()?, r.bytes()?, r.u64()?),
        max_return: r.u64()?,
    })
}

/// Encode an arg (tests, tools).
pub fn encode_arg(a: &LsArg) -> Vec<u8> {
    let mut b = Vec::new();
    let p = start(&mut b, 1, 1);
    b.extend(a.interval.to_le_bytes());
    b.extend(u32::from(a.get_snapsets).to_le_bytes());
    put_bytes(&mut b, &a.start_after.0);
    put_bytes(&mut b, &a.start_after.1);
    b.extend(a.start_after.2.to_le_bytes());
    b.extend(a.max_return.to_le_bytes());
    finish(&mut b, p);
    b
}

fn start(b: &mut Vec<u8>, v: u8, compat: u8) -> usize {
    b.extend([v, compat, 0, 0, 0, 0]);
    b.len()
}
fn finish(b: &mut [u8], p: usize) {
    let n = (b.len() - p) as u32;
    b[p - 4..p].copy_from_slice(&n.to_le_bytes());
}
fn put_bytes(b: &mut Vec<u8>, s: &[u8]) {
    b.extend((s.len() as u32).to_le_bytes());
    b.extend(s);
}

fn put_object_id(b: &mut Vec<u8>, h: &Hobject) {
    let p = start(b, 1, 1);
    put_bytes(b, &h.oid);
    put_bytes(b, &h.nspace);
    put_bytes(b, &h.key);
    b.extend(h.snap.0.to_le_bytes());
    finish(b, p);
}

/// Shard-level `err_t` bits of the local error bits.
fn shard_bits(e: u32) -> u64 {
    let mut o = 0;
    for (l, w) in [
        (err::MISSING, S_MISSING),
        (err::STAT_ERROR, S_STAT),
        (err::READ_ERROR, S_READ),
        (err::INFO_MISSING, S_INFO_MISSING),
        (err::INFO_CORRUPT, S_INFO_CORRUPT),
        (err::SNAPSET_MISSING, S_SS_MISSING),
        (err::SNAPSET_CORRUPT, S_SS_CORRUPT),
        (err::SIZE_INFO_MISMATCH | err::SIZE_MISMATCH, S_SIZE),
        (err::DATA_DIGEST_INFO_MISMATCH, S_DATA_DIGEST),
        (err::OMAP_DIGEST_INFO_MISMATCH, S_OMAP_DIGEST),
        (err::EC_HASH_MISMATCH, S_EC_HASH),
        (err::EC_SIZE_MISMATCH, S_EC_SIZE),
    ] {
        if e & l != 0 {
            o |= w;
        }
    }
    o
}

/// Object-level `obj_err_t` bits: what any shard differs in from the authoritative copy.
fn obj_bits(r: &ObjReport) -> u64 {
    let all = r.shards.values().fold(0, |a, e| a | e);
    let mut o = 0;
    for (l, w) in [
        (err::INFO_MISMATCH, O_INFO),
        (err::SNAPSET_MISMATCH, O_SNAPSET),
        (err::SIZE_MISMATCH, O_SIZE),
        (err::DATA_DIGEST_MISMATCH, O_DATA_DIGEST),
        (err::OMAP_DIGEST_MISMATCH, O_OMAP_DIGEST),
        (err::ATTR_NAME_MISMATCH, O_ATTR_NAME),
        (err::ATTR_VALUE_MISMATCH, O_ATTR_VALUE),
    ] {
        if all & l != 0 {
            o |= w;
        }
    }
    if r.obj_errors & oerr::SIZE_TOO_LARGE != 0 {
        o |= O_SIZE_TOO_LARGE;
    }
    if r.obj_errors & oerr::DATA_DIGESTS != 0 {
        o |= O_DATA_DIGEST;
    }
    o
}

const SNAP_OERR: u32 = oerr::CLONE_MISSING
    | oerr::CLONE_UNEXPECTED
    | oerr::HEADLESS_CLONE
    | oerr::CLONE_SIZE_MISMATCH
    | oerr::SNAPSET_SEQ;

/// One `inconsistent_obj_wrapper` (struct_v 2).
fn encode_obj(r: &ObjReport, primary: i32, who: &dyn Fn(i32) -> (i32, i8)) -> Vec<u8> {
    let mut union = 0u64;
    let mut shards = BTreeMap::new();
    for osd in r.info.keys().chain(r.shards.keys()) {
        let e = shard_bits(r.shards.get(osd).copied().unwrap_or(0));
        union |= e;
        shards.insert(who(*osd), (*osd, e));
    }
    let mut b = Vec::new();
    let p = start(&mut b, 2, 2);
    b.extend(obj_bits(r).to_le_bytes());
    put_object_id(&mut b, &r.soid);
    b.extend(r.user_version.to_le_bytes());
    b.extend((shards.len() as u32).to_le_bytes());
    // classic order: pg_shard_t (osd, shard)
    for ((o, sh), (osd, e)) in &shards {
        let q = start(&mut b, 1, 1);
        b.extend(o.to_le_bytes());
        b.push(*sh as u8); // shard id (-1 = NO_SHARD: replicated)
        finish(&mut b, q);
        let q = start(&mut b, 3, 3);
        b.extend(e.to_le_bytes());
        b.push(u8::from(*osd == primary));
        if e & S_MISSING == 0 {
            let i = r.info.get(osd).copied().unwrap_or_default();
            // attrs: only the selected shard, only `_` (what `rados list-inconsistent-obj` reads; it asserts on a selected shard without)
            if r.auth == Some(*osd) && !r.auth_oi.is_empty() {
                b.extend(1u32.to_le_bytes());
                put_bytes(&mut b, b"_");
                put_bytes(&mut b, &r.auth_oi);
            } else {
                b.extend(0u32.to_le_bytes());
            }
            b.extend(i.size.to_le_bytes());
            b.push(u8::from(i.omap_digest.is_some()));
            b.extend(i.omap_digest.unwrap_or(0).to_le_bytes());
            b.push(u8::from(i.data_digest.is_some()));
            b.extend(i.data_digest.unwrap_or(0).to_le_bytes());
            b.push(u8::from(r.auth == Some(*osd) && !r.auth_oi.is_empty()));
        }
        finish(&mut b, q);
    }
    b.extend(union.to_le_bytes());
    finish(&mut b, p);
    b
}

/// Snapset findings per head object (clone findings fold into their head).
fn snap_records(found: &[ObjReport]) -> Vec<(Hobject, u64, Vec<SnapId>, Vec<SnapId>)> {
    let mut m: BTreeMap<Hobject, (u64, Vec<SnapId>, Vec<SnapId>)> = BTreeMap::new();
    let head = |h: &Hobject| {
        let mut x = h.clone();
        x.snap = SnapId::NOSNAP;
        x
    };
    for r in found.iter().filter(|r| r.obj_errors & SNAP_OERR != 0) {
        let e = m.entry(head(&r.soid)).or_default();
        if r.obj_errors & oerr::HEADLESS_CLONE != 0 {
            e.0 |= SS_HEADLESS;
        }
        if r.obj_errors & oerr::CLONE_MISSING != 0 {
            e.0 |= SS_CLONE_MISSING;
            e.2.extend(&r.missing_clones);
        }
        if r.obj_errors & oerr::CLONE_UNEXPECTED != 0 {
            e.0 |= SS_EXTRA_CLONES;
            e.1.push(r.soid.snap);
        }
        if r.obj_errors & oerr::CLONE_SIZE_MISMATCH != 0 {
            e.0 |= SS_SIZE_MISMATCH;
        }
        if r.obj_errors & oerr::SNAPSET_SEQ != 0 {
            e.0 |= SS_SNAP_ERROR;
        }
    }
    m.into_iter().map(|(h, (e, c, ms))| (h, e, c, ms)).collect()
}

/// One `inconsistent_snapset_wrapper` (struct_v 2).
fn encode_snapset(h: &Hobject, errors: u64, clones: &[SnapId], missing: &[SnapId]) -> Vec<u8> {
    let mut b = Vec::new();
    let p = start(&mut b, 2, 1);
    b.extend(errors.to_le_bytes());
    put_object_id(&mut b, h);
    for v in [clones, missing] {
        b.extend((v.len() as u32).to_le_bytes());
        for s in v {
            b.extend(s.0.to_le_bytes());
        }
    }
    put_bytes(&mut b, &[]); // ss_bl: the head's snapset is not kept
    finish(&mut b, p);
    b
}

/// Page of encoded findings after `arg.start_after`. `None` = the start object is not in the list (stale cursor).
/// Report shard keys are scrub member keys (`primary` is ours); `who` names their `(osd, shard)`.
pub fn ls(
    found: &[ObjReport],
    primary: i32,
    who: &dyn Fn(i32) -> (i32, i8),
    arg: &LsArg,
) -> Option<Vec<Vec<u8>>> {
    let (name, nspace, snap) = &arg.start_after;
    let max = if arg.max_return == 0 {
        usize::MAX
    } else {
        arg.max_return as usize
    };
    let is_start = |h: &Hobject| h.oid[..] == name[..] && h.nspace == *nspace && h.snap.0 == *snap;
    if arg.get_snapsets {
        let recs = snap_records(found);
        let from = if name.is_empty() {
            0
        } else {
            recs.iter().position(|r| is_start(&r.0))? + 1
        };
        Some(
            recs[from..]
                .iter()
                .take(max)
                .map(|(h, e, c, m)| encode_snapset(h, *e, c, m))
                .collect(),
        )
    } else {
        let objs: Vec<&ObjReport> = found
            .iter()
            .filter(|r| !r.shards.is_empty() || obj_bits(r) != 0)
            .collect();
        let from = if name.is_empty() {
            0
        } else {
            objs.iter().position(|r| is_start(&r.soid))? + 1
        };
        Some(
            objs[from..]
                .iter()
                .take(max)
                .map(|r| encode_obj(r, primary, who))
                .collect(),
        )
    }
}

/// `scrub_ls_result_t`.
pub fn encode_result(interval: u32, vals: &[Vec<u8>]) -> Vec<u8> {
    let mut b = Vec::new();
    let p = start(&mut b, 1, 1);
    b.extend(interval.to_le_bytes());
    b.extend((vals.len() as u32).to_le_bytes());
    for v in vals {
        put_bytes(&mut b, v);
    }
    finish(&mut b, p);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrubcmp::ShardInfo;

    fn h(n: &str, snap: SnapId) -> Hobject {
        Hobject::new(n.as_bytes(), snap, 7, 1, b"")
    }

    fn rep(n: &str, shards: &[(i32, u32)], oerrs: u32) -> ObjReport {
        ObjReport {
            soid: h(n, SnapId::NOSNAP),
            auth: Some(0),
            auth_version: Default::default(),
            auth_oi: b"oi".to_vec(),
            obj_errors: oerrs,
            shards: shards.iter().copied().collect(),
            user_version: 9,
            info: [
                (
                    0,
                    ShardInfo {
                        size: 4,
                        data_digest: Some(1),
                        omap_digest: None,
                    },
                ),
                (
                    1,
                    ShardInfo {
                        size: 3,
                        data_digest: Some(2),
                        omap_digest: None,
                    },
                ),
            ]
            .into(),
            missing_clones: vec![],
        }
    }

    fn arg(after: &str, snaps: bool, max: u64) -> LsArg {
        LsArg {
            interval: 0,
            get_snapsets: snaps,
            start_after: (after.as_bytes().to_vec(), vec![], u64::MAX - 1),
            max_return: max,
        }
    }

    #[test]
    fn arg_roundtrip_and_bad_input() {
        let a = arg("foo", true, 10);
        assert_eq!(decode_arg(&encode_arg(&a)), Some(a));
        assert_eq!(decode_arg(&[1, 1, 255, 0, 0, 0]), None);
        assert_eq!(decode_arg(&[]), None);
    }

    #[test]
    fn cross_shard_mismatches_do_not_claim_recorded_digest_damage() {
        for (cross, own, wire) in [
            (
                err::DATA_DIGEST_MISMATCH,
                err::DATA_DIGEST_INFO_MISMATCH,
                S_DATA_DIGEST,
            ),
            (
                err::OMAP_DIGEST_MISMATCH,
                err::OMAP_DIGEST_INFO_MISMATCH,
                S_OMAP_DIGEST,
            ),
        ] {
            assert_eq!(
                shard_bits(cross),
                0,
                "cross-shard comparison is an object error"
            );
            assert_eq!(shard_bits(own), wire);
            assert_eq!(shard_bits(cross | own), wire);
            assert_ne!(obj_bits(&rep("o", &[(1, cross)], 0)), 0);
        }
        assert_eq!(shard_bits(err::EC_HASH_MISMATCH), S_EC_HASH);
        assert_eq!(shard_bits(err::EC_SIZE_MISMATCH), S_EC_SIZE);
    }

    #[test]
    fn object_page_and_bits() {
        let found = vec![
            rep(
                "a",
                &[(1, err::DATA_DIGEST_MISMATCH | err::SIZE_MISMATCH)],
                0,
            ),
            rep("b", &[(1, err::MISSING)], 0),
            rep("c", &[], 0), // nothing to list
        ];
        let all = ls(&found, 0, &|o| (o, -1), &arg("", false, 0)).unwrap();
        assert_eq!(all.len(), 2);
        // first record: obj errors = data digest (1<<4) | size (1<<6)
        let v = &all[0];
        assert_eq!(&v[..2], &[2, 2]);
        assert_eq!(
            u64::from_le_bytes(v[6..14].try_into().unwrap()),
            (1 << 4) | (1 << 6)
        );
        // pagination: after "a" only "b"; unknown cursor = None
        let p = ls(&found, 0, &|o| (o, -1), &arg("a", false, 0)).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0], all[1]);
        assert_eq!(
            ls(&found, 0, &|o| (o, -1), &arg("a", false, 1))
                .unwrap()
                .len(),
            1
        );
        assert!(ls(&found, 0, &|o| (o, -1), &arg("zzz", false, 0)).is_none());
        // max_return
        assert_eq!(
            ls(&found, 0, &|o| (o, -1), &arg("", false, 1))
                .unwrap()
                .len(),
            1
        );
        // result wrapper: interval + count
        let r = encode_result(5, &all);
        assert_eq!(u32::from_le_bytes(r[6..10].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(r[10..14].try_into().unwrap()), 2);
    }

    #[test]
    fn missing_shard_has_no_info_block() {
        let miss = encode_obj(&rep("m", &[(1, err::MISSING)], 0), 0, &|o| (o, -1));
        let ok = encode_obj(&rep("m", &[(1, err::DATA_DIGEST_MISMATCH)], 0), 0, &|o| {
            (o, -1)
        });
        assert!(miss.len() < ok.len());
    }

    #[test]
    fn ec_shard_ids_follow_the_acting_position() {
        let r = rep("m", &[(1, err::DATA_DIGEST_MISMATCH)], 0);
        let enc = |f: &dyn Fn(i32) -> (i32, i8)| encode_obj(&r, 0, f);
        // shard_id_t byte follows the osd id inside the shard-id struct: osd 1 at EC position 3 vs replicated
        let key = |s: u8| [&1i32.to_le_bytes()[..], &[s]].concat();
        let has = |b: &[u8], k: &[u8]| b.windows(k.len()).any(|w| w == k);
        assert!(has(&enc(&|o| (o, 3)), &key(3)));
        assert!(!has(&enc(&|o| (o, 3)), &key(0xff)));
        assert!(has(&enc(&|o| (o, -1)), &key(0xff)));
    }

    #[test]
    fn selected_shard_carries_the_oi_attr() {
        // rados list-inconsistent-obj asserts: a selected shard must hold `_` in its attrs
        let b = encode_obj(&rep("m", &[(1, err::DATA_DIGEST_MISMATCH)], 0), 0, &|o| {
            (o, -1)
        });
        let attr = [
            &1u32.to_le_bytes()[..],
            &1u32.to_le_bytes(),
            b"_",
            &2u32.to_le_bytes(),
            b"oi",
        ]
        .concat();
        assert_eq!(
            b.windows(attr.len())
                .filter(|w| *w == attr.as_slice())
                .count(),
            1
        );
        let mut r = rep("m", &[(1, err::DATA_DIGEST_MISMATCH)], 0);
        r.auth_oi.clear();
        assert!(
            encode_obj(&r, 0, &|o| (o, -1))
                .windows(attr.len())
                .all(|w| w != attr.as_slice())
        );
    }

    #[test]
    fn snapset_records_fold_clones_into_head() {
        let mut head = rep("o", &[], oerr::CLONE_MISSING);
        head.missing_clones = vec![SnapId(4)];
        let mut clone = rep("o", &[], oerr::CLONE_UNEXPECTED | oerr::CLONE_SIZE_MISMATCH);
        clone.soid.snap = SnapId(8);
        let found = vec![head, clone, rep("x", &[(0, err::MISSING)], 0)];
        let recs = snap_records(&found);
        assert_eq!(recs.len(), 1);
        let (hh, e, clones, missing) = &recs[0];
        assert_eq!(hh.snap, SnapId::NOSNAP);
        assert_eq!(*e, SS_CLONE_MISSING | SS_EXTRA_CLONES | SS_SIZE_MISMATCH);
        assert_eq!(
            (clones.clone(), missing.clone()),
            (vec![SnapId(8)], vec![SnapId(4)])
        );
        let page = ls(&found, 0, &|o| (o, -1), &arg("", true, 0)).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(&page[0][..2], &[2, 1]);
        // snapset errors never appear in the object list; the shard error of "x" does
        assert_eq!(
            ls(&found, 0, &|o| (o, -1), &arg("", false, 0))
                .unwrap()
                .len(),
            1
        );
    }
}
