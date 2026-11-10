// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Layering: parent / children methods (cls_rbd.md B.4, B.5).

use super::types::*;
use super::*;
use crate::ctx::ClsCtx;
use crate::errno::*;
use std::collections::BTreeSet;

/// Layering enabled? (`features` missing counts as not enabled.)
fn has_layering<C: ClsCtx>(c: &mut C) -> Result<bool, Errno> {
    Ok(rd_opt_u64(c, "features")?.is_some_and(|f| f & feature::LAYERING != 0))
}

pub fn parent_get<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    check_exists(c)?;
    let mut spec = ParentImageSpec::default();
    if has_layering(c)? {
        match read_parent(c)? {
            Some(p) => {
                spec = ParentImageSpec {
                    pool_id: p.pool_id,
                    pool_namespace: p.pool_namespace,
                    image_id: p.image_id,
                    snap_id: p.snap_id,
                }
            }
            None => {
                for s in snap_iterate(c)? {
                    if s.parent.exists() {
                        spec = ParentImageSpec {
                            pool_id: s.parent.pool_id,
                            pool_namespace: s.parent.pool_namespace,
                            image_id: s.parent.image_id,
                            snap_id: s.parent.snap_id,
                        };
                    }
                }
            }
        }
    }
    enc(&spec)
}

pub fn parent_overlap_get<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let snap = input(inp).u64().inval()?;
    // the exists check result is ignored upstream; a missing layering feature yields "none"
    let none = enc(&Option::<u64>::None)?;
    if !has_layering(c)? {
        return Ok(none);
    }
    let ov = if snap == NOSNAP {
        read_parent(c)?.and_then(|p| p.head_overlap)
    } else {
        let s = read_snap(c, snap)?;
        if s.parent_overlap.is_some() {
            s.parent_overlap
        } else if s.parent.exists() {
            s.parent.head_overlap
        } else {
            None
        }
    };
    enc(&ov)
}

pub fn parent_attach<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let spec = ParentImageSpec::decode(&mut d).inval()?;
    let overlap = d.u64().inval()?;
    let reattach = if d.is_empty() {
        false
    } else {
        d.bool().inval()?
    };
    check_exists(c)?;
    require_feature(c, feature::LAYERING)?;
    if !spec.exists() || overlap == 0 {
        return Err(EINVAL);
    }
    if let Some(p) = read_parent(c)? {
        let same = p.pool_id == spec.pool_id
            && p.pool_namespace == spec.pool_namespace
            && p.image_id == spec.image_id
            && p.snap_id == spec.snap_id;
        if (p.head_overlap.is_some() || !same) && !reattach {
            return Err(EEXIST);
        }
    }
    let size = rd_u64(c, "size")?;
    write_parent(
        c,
        &Parent {
            pool_id: spec.pool_id,
            pool_namespace: spec.pool_namespace,
            image_id: spec.image_id,
            snap_id: spec.snap_id,
            head_overlap: Some(overlap.min(size)),
        },
    )?;
    Ok(())
}

pub fn parent_detach<C: ClsCtx>(c: &mut C, _i: &[u8]) -> Result<(), Errno> {
    detach(c, false)
}

/// `legacy_api`: the pre-namespace remove_parent refuses a parent with a pool namespace (EXDEV).
fn detach<C: ClsCtx>(c: &mut C, legacy_api: bool) -> Result<(), Errno> {
    check_exists(c)?;
    let features = match rd_opt_u64(c, "features")? {
        Some(f) if f & feature::LAYERING != 0 => f,
        _ => return Err(ENOEXEC),
    };
    let Some(parent) = read_parent(c)? else {
        return Err(ENOENT);
    };
    if legacy_api && !parent.pool_namespace.is_empty() {
        return Err(EXDEV);
    }
    if parent.head_overlap.is_none() {
        return Err(ENOENT);
    }
    let deep = features & feature::DEEP_FLATTEN != 0;
    let mut has_child_snaps = false;
    for mut s in snap_iterate(c)? {
        if s.parent_overlap.is_none() && !s.parent.exists() {
            continue;
        }
        if deep {
            s.parent_overlap = None;
            s.parent = Parent::default();
            write_snap(c, s)?;
        } else {
            has_child_snaps = true;
            break;
        }
    }
    if has_child_snaps && c.require_osd_release() >= crate::ctx::release::NAUTILUS {
        let mut p = parent;
        p.head_overlap = None;
        write_parent(c, &p)?;
    } else {
        rm(c, "parent")?;
    }
    if !has_child_snaps {
        set_op_features(c, 0, op_feature::CLONE_CHILD)?;
    }
    Ok(())
}

// ---- legacy single-parent methods ("later") -----------------------------------------------------

pub fn get_parent<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let snap = input(inp).u64().inval()?;
    check_exists(c)?;
    let mut pool = -1i64;
    let mut image = Vec::new();
    let mut psnap = NOSNAP;
    let mut overlap = 0u64;
    if has_layering(c)? {
        let p = read_parent(c)?;
        if p.as_ref().is_some_and(|p| !p.pool_namespace.is_empty()) {
            return Err(EXDEV);
        }
        if snap == NOSNAP {
            if let Some(p) = p {
                pool = p.pool_id;
                image = p.image_id;
                psnap = p.snap_id;
                overlap = p.head_overlap.unwrap_or(0);
            }
        } else {
            // a missing snapshot record counts as "no parent" (classic tolerates ENOENT here)
            let s = match rd_opt_raw(c, &snap_key(snap))? {
                Some(v) => dec_stored::<SnapRec>(&v)?,
                None => SnapRec::default(),
            };
            if s.parent.exists() {
                pool = s.parent.pool_id;
                image = s.parent.image_id;
                psnap = s.parent.snap_id;
                overlap = s.parent.head_overlap.unwrap_or(0);
            } else if let Some(o) = s.parent_overlap {
                // normalized reference: needs the head parent spec
                let p = p.filter(|p| p.exists()).ok_or(EINVAL)?;
                pool = p.pool_id;
                image = p.image_id;
                psnap = p.snap_id;
                overlap = o;
            }
        }
    }
    let mut o = pool.to_le_bytes().to_vec();
    o.extend(enc(&image)?);
    o.extend(enc_u64(psnap));
    o.extend(enc_u64(overlap));
    Ok(o)
}

pub fn set_parent<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let pool = d.i64().inval()?;
    let image = Vec::<u8>::decode(&mut d).inval()?;
    let snap = d.u64().inval()?;
    let overlap = d.u64().inval()?;
    let spec = ParentImageSpec {
        pool_id: pool,
        pool_namespace: Vec::new(),
        image_id: image,
        snap_id: snap,
    };
    let mut o = enc(&spec)?;
    o.extend(enc_u64(overlap));
    parent_attach(c, &o)
}

pub fn remove_parent<C: ClsCtx>(c: &mut C, _i: &[u8]) -> Result<(), Errno> {
    detach(c, true)
}

// ---- children v1 (rbd_children) -----------------------------------------------------------------

fn child_key(pool: u64, image: &[u8], snap: u64) -> Result<Vec<u8>, Errno> {
    let mut k = enc_u64(pool);
    k.extend(enc(image)?);
    k.extend(enc_u64(snap));
    Ok(k)
}

fn dec_child_args(inp: &[u8]) -> Result<(Vec<u8>, Decoder<'_>), Errno> {
    let mut d = input(inp);
    let pool = d.u64().inval()?;
    let image = Vec::<u8>::decode(&mut d).inval()?;
    let snap = d.u64().inval()?;
    Ok((child_key(pool, &image, snap)?, d))
}

fn get_set<C: ClsCtx>(c: &mut C, key: &[u8]) -> Result<Option<BTreeSet<Vec<u8>>>, Errno> {
    rd_opt(c.omap_get_val(key))?
        .map(|v| dec_stored(&v))
        .transpose()
}

pub fn add_child<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let (key, mut d) = dec_child_args(inp)?;
    let child = Vec::<u8>::decode(&mut d).inval()?;
    let mut set = get_set(c, &key)?.unwrap_or_default();
    if !set.insert(child) {
        return Err(EEXIST);
    }
    c.omap_set(&[(&key, &enc(&set)?)])?;
    Ok(())
}

pub fn remove_child<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let (key, mut d) = dec_child_args(inp)?;
    let child = Vec::<u8>::decode(&mut d).inval()?;
    let mut set = get_set(c, &key)?.ok_or(ENOENT)?;
    if !set.remove(&child) {
        return Err(ENOENT);
    }
    if set.is_empty() {
        c.omap_remove_key(&key)?;
    } else {
        c.omap_set(&[(&key, &enc(&set)?)])?;
    }
    Ok(())
}

pub fn get_children<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let (key, _) = dec_child_args(inp)?;
    let set = get_set(c, &key)?.ok_or(ENOENT)?;
    enc(&set)
}

// ---- children v2 (parent header) ----------------------------------------------------------------

type ChildSet = BTreeSet<ChildImageSpec>;

fn read_children<C: ClsCtx>(c: &mut C, snap: u64) -> Result<Option<ChildSet>, Errno> {
    match rd_opt_raw(c, &snap_children_key(snap))? {
        Some(v) => Ok(Some(dec_stored(&v)?)),
        None => Ok(None),
    }
}

pub fn child_attach<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let snap = d.u64().inval()?;
    let child = ChildImageSpec::decode(&mut d).inval()?;
    let mut rec = read_snap(c, snap)?;
    if matches!(rec.ns, SnapNs::Trash { .. }) {
        return Err(ENOENT);
    }
    let mut set = read_children(c, snap)?.unwrap_or_default();
    if !set.insert(child) {
        return Err(EEXIST);
    }
    wr(c, &snap_children_key(snap), &enc(&set)?)?;
    rec.child_count = rec.child_count.wrapping_add(1); // u32 on disk, classic wraps too
    write_snap(c, rec)?;
    set_op_features(c, op_feature::CLONE_PARENT, op_feature::CLONE_PARENT)?;
    Ok(())
}

pub fn child_detach<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let snap = d.u64().inval()?;
    let child = ChildImageSpec::decode(&mut d).inval()?;
    let mut rec = read_snap(c, snap)?;
    let mut set = read_children(c, snap)?.unwrap_or_default();
    if rec.child_count as usize != set.len() {
        return Err(EINVAL);
    }
    if !set.remove(&child) {
        return Err(ENOENT);
    }
    if set.is_empty() {
        rm(c, &snap_children_key(snap))?;
    } else {
        wr(c, &snap_children_key(snap), &enc(&set)?)?;
    }
    rec.child_count -= 1;
    let now_zero = rec.child_count == 0;
    write_snap(c, rec)?;
    if now_zero {
        let mut others = false;
        for s in snap_iterate(c)? {
            if s.id != snap && s.child_count > 0 {
                others = true;
                break;
            }
        }
        if !others {
            set_op_features(c, 0, op_feature::CLONE_PARENT)?;
        }
    }
    Ok(())
}

pub fn children_list<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let snap = input(inp).u64().inval()?;
    read_snap(c, snap)?;
    let set = read_children(c, snap)?.ok_or(ENOENT)?;
    enc(&set)
}
