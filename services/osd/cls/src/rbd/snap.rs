// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Snapshot methods (cls_rbd.md B.3).

use super::types::*;
use super::*;
use crate::ctx::{ClsCtx, omap_scan, rand_uuid_text};
use crate::errno::*;
use std::ops::ControlFlow::Continue;

pub fn snapshot_get<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let id = input(inp).u64().inval()?;
    if id == NOSNAP {
        return Err(EINVAL);
    }
    let s = read_snap(c, id)?;
    enc(&SnapshotInfo {
        id: s.id,
        ns: s.ns,
        name: s.name,
        image_size: s.image_size,
        timestamp: s.timestamp,
        child_count: s.child_count,
    })
}

pub fn get_snapshot_name<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let id = input(inp).u64().inval()?;
    if id == NOSNAP {
        return Err(EINVAL);
    }
    enc(&read_snap(c, id)?.name)
}

pub fn get_snapshot_timestamp<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let id = input(inp).u64().inval()?;
    if id == NOSNAP {
        return Err(EINVAL);
    }
    enc(&read_snap(c, id)?.timestamp)
}

pub fn snapshot_add<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let name = Vec::<u8>::decode(&mut d).inval()?;
    let id = d.u64().inval()?;
    let ns = if d.is_empty() {
        SnapNs::User
    } else {
        SnapNs::decode(&mut d).inval()?
    };
    if matches!(ns, SnapNs::Unknown(_)) {
        return Err(EINVAL);
    }
    if id > MAXSNAP {
        return Err(EINVAL);
    }
    let seq = rd_u64(c, "snap_seq")?;
    if id < seq {
        return Err(ESTALE);
    }
    let size = rd_u64(c, "size")?;
    let flags = rd_opt_u64(c, "flags")?.unwrap_or(0);
    let limit = rd_opt_u64(c, "snap_limit")?.unwrap_or(u64::MAX);
    let ts = c.now();
    let mut count = 0u64;
    for s in snap_iterate(c)? {
        count += 1;
        if count >= limit {
            return Err(EDQUOT);
        }
        if (s.name == name && s.ns.same_for_dup(&ns)) || s.id == id {
            return Err(EEXIST);
        }
    }
    let mut rec = SnapRec {
        id,
        name,
        image_size: size,
        flags,
        ns: ns.clone(),
        timestamp: ts,
        ..Default::default()
    };
    if let Some(p) = read_parent(c)? {
        rec.parent = p;
    }
    if matches!(ns, SnapNs::Trash { .. }) {
        set_op_features(c, op_feature::SNAP_TRASH, op_feature::SNAP_TRASH)?;
    }
    wr_u64(c, "snap_seq", id)?;
    write_snap(c, rec)?;
    Ok(())
}

pub fn snapshot_remove<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let id = input(inp).u64().inval()?;
    let s = read_snap(c, id)?;
    if s.protection_status != PROTECTION_UNPROTECTED || s.child_count > 0 {
        return Err(EBUSY);
    }
    rm(c, &snap_key(id))?;
    // Scan the remaining records. Content reads see the message-start state, so the record just
    // removed is still visible; `exclude` it explicitly.
    let mut has_child_snaps = false;
    let mut has_trash_snaps = false;
    for r in snap_iterate(c)? {
        if r.id == id {
            continue;
        }
        if r.parent_overlap.is_some() || r.parent.pool_id != -1 {
            has_child_snaps = true;
        }
        if matches!(r.ns, SnapNs::Trash { .. }) {
            has_trash_snaps = true;
        }
    }
    let parent = read_parent(c)?.filter(Parent::exists);
    let head_child = parent.as_ref().is_some_and(|p| p.head_overlap.is_some());
    if parent.is_some() && !head_child && !has_child_snaps {
        rm(c, "parent")?;
    }
    let mut mask = 0;
    if !has_child_snaps && !head_child {
        mask |= op_feature::CLONE_CHILD;
    }
    if !has_trash_snaps {
        mask |= op_feature::SNAP_TRASH;
    }
    if mask != 0 {
        set_op_features(c, 0, mask)?;
    }
    Ok(())
}

pub fn snapshot_rename<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let id = d.u64().inval()?;
    let new = Vec::<u8>::decode(&mut d).inval()?;
    for s in snap_iterate(c)? {
        if matches!(s.ns, SnapNs::User) && s.name == new {
            return Err(EEXIST);
        }
    }
    let mut s = read_snap(c, id)?;
    if !matches!(s.ns, SnapNs::User) {
        return Err(EINVAL);
    }
    s.name = new;
    write_snap(c, s)?;
    Ok(())
}

pub fn snapshot_trash_add<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let id = input(inp).u64().inval()?;
    let mut s = read_snap(c, id)?;
    if s.protection_status != PROTECTION_UNPROTECTED {
        return Err(EBUSY);
    }
    if matches!(s.ns, SnapNs::Trash { .. }) {
        return Err(EEXIST);
    }
    set_op_features(c, op_feature::SNAP_TRASH, op_feature::SNAP_TRASH)?;
    s.ns = SnapNs::Trash {
        original_namespace_type: s.ns.type_id(),
        original_name: std::mem::take(&mut s.name),
    };
    s.name = rand_uuid_text(c);
    write_snap(c, s)?;
    Ok(())
}

pub fn snapshot_get_limit<C: ClsCtx>(c: &mut C, _i: &[u8]) -> R {
    Ok(enc_u64(rd_opt_u64(c, "snap_limit")?.unwrap_or(u64::MAX)))
}

pub fn snapshot_set_limit<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let limit = input(inp).u64().inval()?;
    // v1-format probe: header data of at least the v1 header size = old format (count from the v1 header).
    let v1 = c.read(0, 0)?;
    if limit == u64::MAX {
        rm(c, "snap_limit")?;
    } else {
        let mut n = 0u64;
        if let Some(cnt) = oldfmt::v1_snap_count(&v1) {
            n = cnt;
        } else {
            omap_scan(c, b"snapshot_", b"snapshot_", u64::MAX, |_, _, _| {
                n += 1;
                Ok(Continue(()))
            })?;
        }
        if limit < n {
            return Err(ERANGE);
        }
        wr_u64(c, "snap_limit", limit)?;
    }
    Ok(())
}

pub fn set_protection_status<C: ClsCtx>(c: &mut C, inp: &[u8]) -> Result<(), Errno> {
    let mut d = input(inp);
    let id = d.u64().inval()?;
    let status = d.u8().inval()?;
    check_exists(c)?;
    require_feature(c, feature::LAYERING)?;
    if id == NOSNAP || status >= 3 {
        return Err(EINVAL);
    }
    let mut s = read_snap(c, id)?;
    s.protection_status = status;
    write_snap(c, s)?;
    Ok(())
}

pub fn get_protection_status<C: ClsCtx>(c: &mut C, inp: &[u8]) -> R {
    let id = input(inp).u64().inval()?;
    check_exists(c)?;
    if id == NOSNAP {
        return Err(EINVAL);
    }
    let s = read_snap(c, id)?;
    if s.protection_status >= 3 {
        return Err(EIO);
    }
    Ok(vec![s.protection_status])
}
