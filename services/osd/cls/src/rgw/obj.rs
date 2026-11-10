// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `rgw`, data-pool object helpers (spec/cls_rgw.md s9.1): run on RGW head/meta objects,
//! not on index shards.

use super::types::*;
use crate::ctx::ClsCtx;
use crate::errno::*;

/// `obj_remove` (RW): remove the object; with `keep_attr_prefixes` recreate it EMPTY carrying only
/// the xattrs whose name starts with any listed prefix (values as of message start).
pub fn obj_remove<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: ObjRemoveOp = dec_op(input)?;
    if op.keep_attr_prefixes.is_empty() {
        c.remove()?;
        return Ok(Vec::new());
    }
    let attrs = match c.getxattrs_raw() {
        Ok(a) => a,
        Err(ENOENT) => Default::default(),
        Err(e) => return Err(e),
    };
    let keep: Vec<(Vec<u8>, Vec<u8>)> = attrs
        .into_iter()
        .filter(|(n, _)| op.keep_attr_prefixes.iter().any(|p| n.starts_with(p)))
        .collect();
    c.remove()?;
    if keep.is_empty() {
        return Ok(Vec::new());
    }
    c.create(false)?;
    for (n, v) in &keep {
        c.setxattr_raw(n, v)?;
    }
    Ok(Vec::new())
}

/// `obj_store_pg_ver` (WR only): xattr `attr` := le u64 of the PG's last user version.
pub fn obj_store_pg_ver<C: ClsCtx>(c: &mut C, input: &[u8]) -> Result<(), Errno> {
    let op: StorePgVerOp = dec_op(input)?;
    let v = c.current_version();
    c.setxattr_raw(&op.attr, &v.to_le_bytes())?;
    Ok(())
}

/// `obj_check_attrs_prefix` (RD): `-ECANCELED` iff `exists == fail_if_exist`.
pub fn obj_check_attrs_prefix<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: CheckAttrsPrefixOp = dec_op(input)?;
    if op.check_prefix.is_empty() {
        return Err(EINVAL);
    }
    let attrs = match c.getxattrs_raw() {
        Ok(a) => a,
        Err(ENOENT) => Default::default(),
        Err(e) => return Err(e),
    };
    let exist = attrs.keys().any(|n| n.starts_with(&op.check_prefix));
    if exist == op.fail_if_exist {
        return Err(ECANCELED);
    }
    Ok(Vec::new())
}

/// `obj_check_mtime` (RD): compare the object's mtime (nanosecond; absent object = epoch 0).
pub fn obj_check_mtime<C: ClsCtx>(c: &mut C, input: &[u8]) -> R {
    let op: CheckMtimeOp = dec_op(input)?;
    let obj = match c.stat() {
        Ok(s) => s.mtime,
        Err(ENOENT) => Default::default(),
        Err(e) => return Err(e),
    };
    let (mut a, mut b) = (obj, op.mtime);
    if !op.high_precision_time {
        a.nsec = 0;
        b.nsec = 0;
    }
    let ok = match op.ty {
        0 => a == b,
        1 => a < b,
        2 => a <= b,
        3 => a > b,
        4 => a >= b,
        _ => return Err(EINVAL),
    };
    if ok { Ok(Vec::new()) } else { Err(ECANCELED) }
}
