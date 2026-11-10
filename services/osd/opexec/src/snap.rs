// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Snapshot target resolution (client-ops.md s8.2 find_object_context).

use crate::exec::load_oi;
use crate::types::ObjState;
use crate::view::ObjView;
use denc::types::{Hobject, SnapId, SpgT};
use opwire::{NOSNAP, SNAPDIR, flag as mflag};
use replwire::ObjectInfo;

/// Which object a snapid read/rollback addresses.
#[expect(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Target {
    Head,
    Clone(Hobject, ObjectInfo),
    /// No such snapshot content (-ENOENT for reads).
    None,
    /// The clone the snap maps to has an object_info that cannot be read or decoded (EIO; repair it, adr 0065).
    Damaged(Hobject),
}

pub fn is_removed(removed: &[(u64, u64)], snap: u64) -> bool {
    // `osdmap` intervals are peer data: an interval running past u64::MAX keeps its upper end (never wraps).
    removed
        .iter()
        .any(|(s, l)| snap >= *s && snap < s.saturating_add(*l))
}

/// `Err` = EIO (positive errno).
pub fn resolve_snap<V: ObjView>(
    v: &V,
    spg: SpgT,
    head: &Hobject,
    pre: &ObjState,
    snapid: u64,
    flags: u32,
    removed: &[(u64, u64)],
) -> Result<Target, i32> {
    if snapid == NOSNAP || snapid == SNAPDIR {
        return Ok(Target::Head);
    }
    if pre.oi.is_none() && pre.ss.clones.is_empty() {
        return Ok(Target::None);
    }
    let ss = &pre.ss;
    if flags & mflag::MAP_SNAP_CLONE != 0 {
        if snapid > ss.seq {
            return Ok(Target::Head);
        }
        if !ss.clones.contains(&SnapId(snapid)) {
            return Ok(Target::None);
        }
        return load_clone(v, spg, head, SnapId(snapid));
    }
    if snapid > ss.seq {
        return Ok(Target::Head);
    }
    let Some(c) = ss.clones.iter().find(|c| c.0 >= snapid) else {
        return Ok(Target::None);
    };
    if !ss
        .clone_snaps
        .get(c)
        .is_some_and(|v| v.iter().any(|s| s.0 == snapid))
        || is_removed(removed, snapid)
    {
        return Ok(Target::None);
    }
    load_clone(v, spg, head, *c)
}

fn load_clone<V: ObjView>(v: &V, spg: SpgT, head: &Hobject, c: SnapId) -> Result<Target, i32> {
    let mut coid = head.clone();
    coid.snap = c;
    match load_oi(v, spg, &coid) {
        Ok(Some(oi)) => Ok(Target::Clone(coid, oi)),
        Ok(None) => Ok(Target::None),
        Err(e) if e == opwire::errno::EIO => Ok(Target::Damaged(coid)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::is_removed;

    #[test]
    fn removed_interval_past_the_end_does_not_wrap() {
        // A hostile / corrupt `snap_trim_queue` interval that runs past u64::MAX keeps its upper end (saturating, like
        // `peering::snaps::iv_contains`) instead of wrapping to a low range.
        assert!(!is_removed(&[(u64::MAX - 1, 8)], 5));
        assert!(is_removed(&[(u64::MAX - 1, 8)], u64::MAX - 1));
        // Overflowing length never makes a low snap look removed.
        assert!(!is_removed(&[(u64::MAX, u64::MAX)], 3));
    }
}
