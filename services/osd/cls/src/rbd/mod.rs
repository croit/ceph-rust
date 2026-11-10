// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `rbd` (spec/cls_rbd.md). Handlers are plain generic functions over [`ClsCtx`]; the method
//! table in [`crate::registry`] maps names to them.

pub mod bitvec;
pub mod data;
pub mod group;
pub mod header;
pub mod layering;
pub mod migration;
pub mod mirror;
pub mod mirror_status;
pub mod mirror_types;
pub mod objmap;
pub mod oldfmt;
pub mod snap;
pub mod trash;
pub mod types;
pub mod types_group;

use crate::ctx::{ClsCtx, omap_scan, release};
use crate::errno::*;
use denc::features::SERVER_NAUTILUS;
use denc::{Decode, Decoder};
use std::ops::ControlFlow::Continue;
use types::*;

pub(crate) type KvPair = (Vec<u8>, Vec<u8>);

pub(crate) const MAX_KEYS_READ: u64 = 64;

/// Encode with the feature set implied by `require_osd_release` (always nautilus+ for croit-flashstore-osd).
pub(crate) fn enc_features<C: ClsCtx>(c: &C) -> u64 {
    if c.require_osd_release() >= release::NAUTILUS {
        SERVER_NAUTILUS
    } else {
        0
    }
}

pub(crate) fn enc_u64(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

/// Input decoder (trailing bytes are tolerated like a bufferlist decode).
pub(crate) fn input(b: &[u8]) -> Decoder<'_> {
    Decoder::new(b)
}

// ---- omap key helpers -------------------------------------------------------------------------

/// Omap key `prefix` + raw `name` bytes (Ceph strings are byte strings, never lossy-converted).
pub(crate) fn key(prefix: &str, name: &[u8]) -> Vec<u8> {
    [prefix.as_bytes(), name].concat()
}

pub(crate) fn snap_key(id: u64) -> String {
    format!("snapshot_{id:016x}")
}
pub(crate) fn snap_children_key(id: u64) -> String {
    format!("snap_children_{id:016x}")
}

/// `read_key`: missing key AND missing object are `ENOENT`.
pub(crate) fn rd<C: ClsCtx>(c: &mut C, key: &(impl AsRef<[u8]> + ?Sized)) -> R {
    c.omap_get_val(key.as_ref())
}
pub(crate) fn rd_u64<C: ClsCtx>(
    c: &mut C,
    key: &(impl AsRef<[u8]> + ?Sized),
) -> Result<u64, Errno> {
    let v = rd(c, key)?;
    Decoder::new(&v).u64().eio()
}
/// `Ok(None)` only for ENOENT.
pub(crate) fn rd_opt_u64<C: ClsCtx>(
    c: &mut C,
    key: &(impl AsRef<[u8]> + ?Sized),
) -> Result<Option<u64>, Errno> {
    rd_opt(rd_u64(c, key))
}
pub(crate) fn rd_opt_raw<C: ClsCtx>(
    c: &mut C,
    key: &(impl AsRef<[u8]> + ?Sized),
) -> Result<Option<Vec<u8>>, Errno> {
    rd_opt(rd(c, key))
}
pub(crate) fn wr<C: ClsCtx>(
    c: &mut C,
    key: &(impl AsRef<[u8]> + ?Sized),
    val: &[u8],
) -> Result<(), Errno> {
    c.omap_set(&[(key.as_ref(), val)])
}
pub(crate) fn wr_u64<C: ClsCtx>(
    c: &mut C,
    key: &(impl AsRef<[u8]> + ?Sized),
    v: u64,
) -> Result<(), Errno> {
    wr(c, key, &v.to_le_bytes())
}
pub(crate) fn rm<C: ClsCtx>(c: &mut C, key: &(impl AsRef<[u8]> + ?Sized)) -> Result<(), Errno> {
    c.omap_remove_key(key.as_ref())
}
/// `rm` where an absent object is fine (classic call sites that ignore ENOENT).
pub(crate) fn rm_ok<C: ClsCtx>(c: &mut C, key: &(impl AsRef<[u8]> + ?Sized)) -> Result<(), Errno> {
    match rm(c, key) {
        Err(ENOENT) => Ok(()),
        r => r,
    }
}
pub(crate) fn check_exists<C: ClsCtx>(c: &mut C) -> Result<(), Errno> {
    c.stat().map(|_| ())
}

/// Page through omap entries with `prefix` after `start_after` (full key), at most `max` entries.
pub(crate) fn scan<C: ClsCtx>(
    c: &mut C,
    prefix: &(impl AsRef<[u8]> + ?Sized),
    start_after: &[u8],
    max: u64,
) -> Result<Vec<KvPair>, Errno> {
    let mut out = Vec::new();
    omap_scan(c, start_after, prefix.as_ref(), max, |_, k, v| {
        out.push((k, v));
        Ok(Continue(()))
    })?;
    Ok(out)
}

/// All `snapshot_*` records ascending by id.
pub(crate) fn snap_iterate<C: ClsCtx>(c: &mut C) -> Result<Vec<SnapRec>, Errno> {
    let mut out = Vec::new();
    for (_, v) in scan(c, "snapshot_", b"snapshot_", u64::MAX)? {
        out.push(dec_stored::<SnapRec>(&v)?);
    }
    Ok(out)
}

pub(crate) fn read_snap<C: ClsCtx>(c: &mut C, id: u64) -> Result<SnapRec, Errno> {
    let v = rd(c, &snap_key(id))?;
    dec_stored(&v)
}

/// `image::snapshot::write`: normalize (nautilus layout) and store the record.
pub(crate) fn write_snap<C: ClsCtx>(c: &mut C, mut s: SnapRec) -> Result<(), Errno> {
    if enc_features(c) & SERVER_NAUTILUS != 0 && s.parent.exists() {
        if rd_opt_raw(c, "parent")?.is_none() {
            let mut p = s.parent.clone();
            p.head_overlap = None;
            wr(c, "parent", &enc_f(&p, enc_features(c))?)?;
        }
        s.parent_overlap = s.parent.head_overlap;
        s.parent = Parent::default();
    }
    let key = snap_key(s.id);
    wr(c, &key, &enc_f(&s, enc_features(c))?)
}

pub(crate) fn read_parent<C: ClsCtx>(c: &mut C) -> Result<Option<Parent>, Errno> {
    match rd_opt_raw(c, "parent")? {
        Some(v) => Ok(Some(dec_stored(&v)?)),
        None => Ok(None),
    }
}
pub(crate) fn write_parent<C: ClsCtx>(c: &mut C, p: &Parent) -> Result<(), Errno> {
    wr(c, "parent", &enc_f(p, enc_features(c))?)
}

/// `require_feature`: `features` missing or bit missing -> ENOEXEC. Returns the feature word.
pub(crate) fn require_feature<C: ClsCtx>(c: &mut C, mask: u64) -> Result<u64, Errno> {
    let f = match rd_u64(c, "features") {
        Ok(f) => f,
        Err(ENOENT) => return Err(ENOEXEC),
        Err(e) => return Err(e),
    };
    if f & mask != mask {
        return Err(ENOEXEC);
    }
    Ok(f)
}

/// `image::set_op_features(op, mask)`.
pub(crate) fn set_op_features<C: ClsCtx>(c: &mut C, op: u64, mask: u64) -> Result<(), Errno> {
    let features = rd_u64(c, "features")?;
    let old = rd_opt_u64(c, "op_features")?.unwrap_or(0);
    let new = (old & !mask) | (op & mask);
    if new == old {
        return Ok(());
    }
    let mut nf = features;
    if new == 0 {
        nf &= !feature::OPERATIONS;
        rm(c, "op_features")?;
    } else {
        nf |= feature::OPERATIONS;
        wr_u64(c, "op_features", new)?;
    }
    if nf != features {
        wr_u64(c, "features", nf)?;
    }
    Ok(())
}

/// Key remainder after a `prefix_len` prefix (empty if the key is shorter; never panics).
pub(crate) fn suffix(k: &[u8], prefix_len: usize) -> Vec<u8> {
    k.get(prefix_len..).unwrap_or_default().to_vec()
}

/// Non-empty and ASCII alphanumeric.
pub(crate) fn is_valid_id(id: &[u8]) -> bool {
    !id.is_empty() && id.iter().copied().all(|b| b.is_ascii_alphanumeric())
}
