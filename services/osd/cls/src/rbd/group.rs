// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Group methods (cls_rbd.md B.9a): `rbd_group_directory`, `rbd_group_header.<gid>`.
//! `image_group_*` (image side) live in `header.rs`.

use super::header::{dir_add_helper, dir_list, dir_remove_helper};
use super::types_group::*;
use super::*;
use crate::ctx::ClsCtx;
use crate::errno::*;
use std::collections::BTreeMap;

const SNAP_PREFIX: &str = "snapshot_";
const ORDER_PREFIX: &str = "snap_order_";
const MAX_ORDER: &str = "snap_max_order";

// ---- group directory ----------------------------------------------------------------------------

pub fn group_dir_add<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    c.create(false)?;
    let mut d = input(inp);
    let name = Vec::<u8>::decode(&mut d).inval()?;
    let id = Vec::<u8>::decode(&mut d).inval()?;
    dir_add_helper(c, &name, &id, true)?;
    Ok(())
}

pub fn group_dir_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let name = Vec::<u8>::decode(&mut d).inval()?;
    let id = Vec::<u8>::decode(&mut d).inval()?;
    dir_remove_helper(c, &name, &id)?;
    Ok(())
}

pub fn group_dir_rename<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let src = Vec::<u8>::decode(&mut d).inval()?;
    let dest = Vec::<u8>::decode(&mut d).inval()?;
    let id = Vec::<u8>::decode(&mut d).inval()?;
    dir_remove_helper(c, &src, &id)?;
    dir_add_helper(c, &dest, &id, false)?;
    Ok(())
}

pub fn group_dir_list<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    dir_list(c, inp)
}

// ---- group header: images -----------------------------------------------------------------------

pub fn group_image_set<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let st: GroupImageStatus = dec_op(inp)?;
    c.omap_set(&[(st.spec.key().as_slice(), &[st.state])])?;
    Ok(())
}

pub fn group_image_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let spec: GroupImageSpec = dec_op(inp)?;
    c.omap_remove_key(&spec.key())?;
    Ok(())
}

pub fn group_image_list<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let start = GroupImageSpec::decode(&mut d).inval()?;
    let max = d.u64().inval()?;
    let mut out: Vec<GroupImageStatus> = Vec::new();
    for (k, v) in scan(c, "image_", &start.key(), max)? {
        let state = *v.first().ok_or(EIO)?;
        out.push(GroupImageStatus {
            spec: GroupImageSpec::from_key(&k).ok_or(EIO)?,
            state,
        });
    }
    enc(&out)
}

// ---- group header: snapshots --------------------------------------------------------------------

pub fn group_snap_set<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let snap: GroupSnapshot = dec_op(inp)?;
    if snap.name.is_empty() || snap.id.is_empty() {
        return Err(EINVAL);
    }
    for (_, v) in scan(c, SNAP_PREFIX, SNAP_PREFIX.as_bytes(), u64::MAX)? {
        let s: GroupSnapshot = dec_stored(&v)?;
        if s.name == snap.name && s.id != snap.id {
            return Err(EEXIST);
        }
    }
    let skey = key(SNAP_PREFIX, &snap.id);
    if snap.state == 0 {
        if rd_opt_raw(c, &skey)?.is_some() {
            return Err(EEXIST);
        }
        let okey = key(ORDER_PREFIX, &snap.id);
        if rd_opt_raw(c, &okey)?.is_some() {
            return Err(EEXIST);
        }
        let m = rd_opt_u64(c, MAX_ORDER)?.unwrap_or(0).wrapping_add(1);
        wr_u64(c, MAX_ORDER, m)?;
        wr_u64(c, &okey, m)?;
    }
    wr(c, &skey, &enc(&snap)?)?;
    Ok(())
}

pub fn group_snap_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let id = Vec::<u8>::decode(&mut input(inp)).inval()?;
    rm(c, &key(SNAP_PREFIX, &id))?;
    rm(c, &key(ORDER_PREFIX, &id))?;
    Ok(())
}

pub fn group_snap_get_by_id<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let id = Vec::<u8>::decode(&mut input(inp)).inval()?;
    let v = rd(c, &key(SNAP_PREFIX, &id))?;
    let s: GroupSnapshot = dec_stored(&v)?;
    enc(&s)
}

pub fn group_snap_list<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let start = GroupSnapshot::decode(&mut d).inval()?;
    let max = d.u64().inval()?;
    let from = key(SNAP_PREFIX, &start.id);
    let mut out: Vec<GroupSnapshot> = Vec::new();
    for (_, v) in scan(c, SNAP_PREFIX, &from, max)? {
        out.push(dec_stored(&v)?);
    }
    enc(&out)
}

pub fn group_snap_list_order<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let mut d = input(inp);
    let start = Vec::<u8>::decode(&mut d).inval()?;
    let max = d.u64().inval()?;
    let from = key(ORDER_PREFIX, &start);
    let mut out: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
    for (k, v) in scan(c, ORDER_PREFIX, &from, max)? {
        let id = suffix(&k, ORDER_PREFIX.len());
        let order = denc::Decoder::new(&v).u64().eio()?;
        out.insert(id, order);
    }
    enc(&out)
}
