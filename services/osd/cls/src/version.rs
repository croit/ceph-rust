// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `version` (spec/cls_version.md): object version in xattr `ceph.objclass.version`.

use crate::ctx::{ClsCtx, rand_armor};
use crate::env_struct;
use crate::errno::*;
use denc::{Decode, Decoder};

pub const ATTR: &str = "ceph.objclass.version";

env_struct!(
    /// `obj_version`
    ObjVersion (1, 1) { ver: u64, tag: Vec<u8> });
env_struct!(
    /// `obj_version_cond`; `cond` is u32 on the wire.
    VersionCond (1, 1) { ver: ObjVersion, cond: u32 });
env_struct!(SetOp (1, 1) { objv: ObjVersion });
env_struct!(
    /// `cls_version_inc_op` (`objv` is ignored by the server).
    IncOp (1, 1) { objv: ObjVersion, conds: Vec<VersionCond> });
/// Same layout as [`IncOp`].
pub type CheckOp = IncOp;
env_struct!(ReadRet (1, 1) { objv: ObjVersion });

pub const COND_NONE: u32 = 0;
pub const COND_EQ: u32 = 1;
pub const COND_GT: u32 = 2;
pub const COND_GE: u32 = 3;
pub const COND_LT: u32 = 4;
pub const COND_LE: u32 = 5;
pub const COND_TAG_EQ: u32 = 6;
pub const COND_TAG_NE: u32 = 7;

fn set_version<C: ClsCtx>(c: &mut C, v: &ObjVersion) -> Result<(), Errno> {
    c.setxattr(ATTR, &enc(v)?)
}

/// `implicit_create` only for writers (`inc`): absent -> {1, random tag} persisted.
fn read_version<C: ClsCtx>(c: &mut C, implicit_create: bool) -> Result<ObjVersion, Errno> {
    match c.getxattr(ATTR) {
        Err(ENOENT) | Err(ENODATA) => {
            let mut v = ObjVersion::default();
            if implicit_create {
                v.ver = 1;
                v.tag = rand_armor(c, 24);
                set_version(c, &v)?;
            }
            Ok(v)
        }
        Err(e) => Err(e),
        Ok(b) => ObjVersion::decode(&mut Decoder::new(&b)).eio(),
    }
}

/// All conds must hold (empty = pass). NONE and unknown cond values pass.
fn check_conds(conds: &[VersionCond], cur: &ObjVersion) -> bool {
    conds.iter().all(|c| match c.cond {
        COND_EQ => cur == &c.ver,
        COND_GT => cur.ver > c.ver.ver,
        COND_GE => cur.ver >= c.ver.ver,
        COND_LT => cur.ver < c.ver.ver,
        COND_LE => cur.ver <= c.ver.ver,
        COND_TAG_EQ => cur.tag == c.ver.tag,
        COND_TAG_NE => cur.tag != c.ver.tag,
        _ => true,
    })
}

pub fn set<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: SetOp = dec_op(input)?;
    set_version(c, &op.objv)?;
    Ok(())
}

/// `inc` and `inc_conds` (same handler). Fresh object: version becomes 1, then is incremented
/// to 2 (bug-compat).
pub fn inc<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: IncOp = dec_op(input)?;
    let mut v = read_version(c, true)?;
    if !check_conds(&op.conds, &v) {
        return Err(ECANCELED);
    }
    v.ver = v.ver.wrapping_add(1);
    set_version(c, &v)?;
    Ok(())
}

pub fn check_conds_m<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: CheckOp = dec_op(input)?;
    let v = read_version(c, false)?;
    if !check_conds(&op.conds, &v) {
        return Err(ECANCELED);
    }
    Ok(())
}

/// Input is not decoded.
pub fn read<C: ClsCtx>(c: &mut C, _input: &[u8]) -> Result<Vec<u8>, Errno> {
    let objv = read_version(c, false)?;
    enc(&ReadRet { objv })
}
