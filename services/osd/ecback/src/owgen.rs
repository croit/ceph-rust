// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optimized-EC (`allow_ec_optimizations`) write generator, conventional read-modify-write
//! (spec ec-optimized-wgen.md, ec-optimized.md 4; adr 0067).
//!
//! Input = the replicated-shape v9 logical transaction of the op layer (as for the legacy generator). Per object:
//! * plan: per raw shard 4 KiB aligned write extents (data = hull of the touched bytes, parity = their union plus
//!   the boundary stripe of a truncate), the old data-shard bytes the parity needs ([`OWritePlan::reads`]),
//!   `written_shards`, the rollback record (`mod_desc` v3), the rewritten `shard_versions` of the object_info;
//! * generate: compose the new columns from the old bytes and the overlay, encode parity over the written range only,
//!   emit one transaction per member shard that has work (`None` = no sub-write for that shard).
//!
//! Differences from upstream on purpose (byte-identical shard results and records):
//! * every stash `clone_range` is taken from the PRE-op object (upstream clones part of the parity stash after the
//!   truncate, see ec-optimized.md 18 UI-7);
//! * the client alloc hint is carried to every member shard as one `set_alloc_hint` (sizes scaled to the shard, flags
//!   kept; adr 0059 am. 6); the append-part hint of upstream (`SEQUENTIAL_WRITE|APPEND_ONLY`, 0, 0) is not emitted
//!   (spec ec-optimized-wgen.md U-W6). An alloc hint forces all shards written.
//!
//! Raw shard indices (`0..k` data, `k..k+m` parity) are used internally; shard ids appear only in the transactions
//! and the `written_shards` set (via the pool's chunk mapping).

use crate::oext::{Ext, Geo};
use crate::wgen::{Hint, OldObj, Overlay, Post, SharedTxn, contains};
use crate::{Backend, EFBIG, EINVAL, EIO, EOPNOTSUPP, MAX_OBJECT_SIZE, io};
use bytes::Bytes;
use denc::types::{CollT, Eversion, Ghobject, Hobject, PgT, ShardId, SpgT};
use ec::moddesc::{EcOmap, ModDescBuilder, OmapUp};
use pgwire::ObjectModDesc;
use pgwire::log::ShardIdSet;
use replwire::oi::ObjectInfo;
use replwire::txn::{Transaction, TxnOp};
use std::collections::BTreeMap;
use std::sync::Arc;

const LIVE: u64 = Ghobject::NO_GEN;
const OI_KEY: &[u8] = b"_";
const OI_OMAP: u32 = replwire::oi::flag::OMAP;
const HINFO: &[u8] = ec::HINFO_KEY.as_bytes();
const A: u64 = ec::geom::OPT_ALIGN;

fn al(x: u64) -> u64 {
    x.next_multiple_of(A)
}

/// Does the committed object carry omap data (object_info FLAG_OMAP)? Undecodable = treated as yes (keep the object).
fn old_has_omap(old: &OldObj) -> bool {
    old.attrs
        .get(OI_KEY)
        .is_none_or(|b| denc::from_slice::<ObjectInfo>(b).is_ok_and(|oi| oi.flags & OI_OMAP != 0))
}

/// Working object of an omap op: the pool must allow omap; the op creates a missing object like a write.
fn omap_target<'a>(ws: &'a mut Works, ok: bool, soid: &Hobject) -> Result<&'a mut Work, i32> {
    if !ok {
        return Err(EOPNOTSUPP);
    }
    let w = ws.get(soid);
    w.ensure();
    w.dirty = true;
    Ok(w)
}

/// Membership and interval facts of one write.
#[derive(Debug, Clone, Copy)]
pub struct OCtx<'a> {
    /// Shard ids that receive a transaction (members of `acting_recovery_backfill`); others only count for
    /// `written_shards` and the math.
    pub members: &'a [u32],
    /// `first_write_in_interval`: the first object generated is written to all shards (consumed by this plan).
    pub first_write: bool,
}

// ---- logical reduction (same op model as the legacy generator) ----------------------------------------------------

#[derive(Debug, Clone)]
struct Work {
    soid: Hobject,
    old: OldObj,
    exists: bool,
    /// The old object is moved away first (`delete_first`: delete, recreate, truncate-to-0 rewrite).
    deleted: bool,
    /// Created by this transaction.
    fresh: bool,
    clone_of: Option<Hobject>,
    /// Move a committed copy temp into place instead of cloning it.
    move_from: bool,
    /// Index of the Clone op (`usize::MAX`: none); clones run first in transaction order.
    clone_at: usize,
    size: u64,
    /// Old content still valid: `min(old size, truncate points)`.
    b: u64,
    /// A truncate op ran (not the truncate-to-0 rewrite).
    truncated: bool,
    alloc_hint: Option<Hint>,
    overlay: Overlay,
    reclaim: bool,
    attrs: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    dirty: bool,
    /// Omap mutations of this transaction as sequential EC_OMAP records (`OmapAcc`).
    omap: OmapAcc,
}

impl Work {
    fn new(soid: Hobject, old: OldObj) -> Work {
        Work {
            exists: old.exists,
            size: if old.exists { old.size } else { 0 },
            b: if old.exists { old.size } else { 0 },
            soid,
            old,
            deleted: false,
            fresh: false,
            clone_of: None,
            move_from: false,
            clone_at: usize::MAX,
            truncated: false,
            alloc_hint: None,
            overlay: Overlay::default(),
            reclaim: false,
            attrs: BTreeMap::new(),
            dirty: false,
            omap: OmapAcc::default(),
        }
    }
    fn ensure(&mut self) {
        if !self.exists {
            self.exists = true;
            self.fresh = true;
            self.size = 0;
            self.b = 0;
        }
    }
}

/// Omap mutations of one object in one transaction, as sequential EC_OMAP records. A shard applies a record as
/// header, clear, updates (classic order), so a clear starts a fresh record and a header set after a clear gets its
/// own record (ec-optimized.md 18 UI-3: no record may carry clear + header).
#[derive(Debug, Default, Clone)]
struct OmapAcc {
    recs: Vec<EcOmap>,
}

impl OmapAcc {
    fn last(&mut self) -> &mut EcOmap {
        if self.recs.is_empty() {
            self.recs.push(EcOmap::default());
        }
        self.recs.last_mut().unwrap()
    }
    fn clear(&mut self) {
        // everything before is wiped anyway
        self.recs = vec![EcOmap {
            clear: true,
            ..Default::default()
        }];
    }
    fn header(&mut self, h: &[u8]) {
        if self.recs.last().is_some_and(|r| r.clear) {
            self.recs.push(EcOmap::default());
        }
        self.last().header = Some(h.to_vec());
    }
    fn up(&mut self, u: OmapUp) {
        self.last().ups.push(u);
    }
}

struct Works<'a> {
    olds: &'a BTreeMap<Hobject, OldObj>,
    order: Vec<Hobject>,
    map: BTreeMap<Hobject, Work>,
}

impl Works<'_> {
    fn get(&mut self, soid: &Hobject) -> &mut Work {
        if !self.map.contains_key(soid) {
            self.order.push(soid.clone());
            let old = self.olds.get(soid).cloned().unwrap_or_default();
            self.map.insert(soid.clone(), Work::new(soid.clone(), old));
        }
        self.map.get_mut(soid).unwrap()
    }
}

fn reduce(
    t: &Transaction,
    owners: &[Bytes],
    olds: &BTreeMap<Hobject, OldObj>,
    s: u64,
    (ow, omap_ok): (bool, bool),
) -> Result<Vec<Work>, i32> {
    let mut ws = Works {
        olds,
        order: Vec::new(),
        map: BTreeMap::new(),
    };
    let obj = |ox| -> Result<Hobject, i32> {
        let g = t.get_obj(ox);
        if g.generation != LIVE {
            return Err(EINVAL);
        }
        Ok(g.hobj.clone())
    };
    for (i, op) in t.ops.iter().enumerate() {
        match &op.op {
            TxnOp::Nop | TxnOp::CollHint { .. } => {}
            TxnOp::SetAllocHint {
                oid,
                expected_object_size,
                expected_write_size,
                flags,
            } => {
                let w = ws.get(&obj(*oid)?);
                w.ensure();
                w.alloc_hint = Some(Hint::merge(
                    w.alloc_hint,
                    *expected_object_size,
                    *expected_write_size,
                    *flags,
                ));
            }
            TxnOp::Create { oid } | TxnOp::Touch { oid } => {
                ws.get(&obj(*oid)?).ensure();
            }
            TxnOp::Write { oid, off, data } => {
                let w = ws.get(&obj(*oid)?);
                if w.clone_of.is_some() {
                    return Err(EINVAL);
                }
                w.ensure();
                let len = data.len() as u64;
                if !ow && (*off % s != 0 || *off != w.size) {
                    return Err(EOPNOTSUPP);
                }
                if off.checked_add(len).is_none_or(|end| end > MAX_OBJECT_SIZE) {
                    return Err(EFBIG);
                }
                w.dirty = true;
                let bytes = match owners.iter().find(|o| contains(o, data.head)) {
                    Some(o) if data.mid.is_empty() && data.tail.is_empty() => {
                        o.slice_ref(data.head)
                    }
                    _ => Bytes::from(data.to_vec()),
                };
                w.overlay.put(*off, bytes);
                w.size = w.size.max(off + len);
            }
            TxnOp::Zero { oid, off, len } => {
                let w = ws.get(&obj(*oid)?);
                if !ow {
                    return Err(EOPNOTSUPP);
                }
                if w.clone_of.is_some() {
                    return Err(EINVAL);
                }
                if !w.exists {
                    continue;
                }
                // clamped to the object (ec-optimized-wgen.md U-W2)
                let end = off.saturating_add(*len).min(w.size);
                if *off < end {
                    if end > MAX_OBJECT_SIZE {
                        return Err(EFBIG);
                    }
                    w.dirty = true;
                    w.reclaim = true;
                    w.overlay
                        .put(*off, Bytes::from(vec![0u8; (end - off) as usize]));
                }
            }
            TxnOp::Truncate { oid, size } => {
                let w = ws.get(&obj(*oid)?);
                if w.clone_of.is_some() {
                    return Err(EINVAL);
                }
                w.ensure();
                if *size > MAX_OBJECT_SIZE {
                    return Err(EFBIG);
                }
                if *size == w.size {
                    continue;
                }
                w.reclaim = true;
                if *size == 0
                    && w.old.exists
                    && !w.deleted
                    && w.old.size > 0
                    && w.omap.recs.is_empty()
                    && !old_has_omap(&w.old)
                {
                    // truncate to 0 of an existing object = delete_first + create, cached attrs kept (wgen 2.1b)
                    let mut keep: BTreeMap<Vec<u8>, Option<Vec<u8>>> = w
                        .old
                        .attrs
                        .iter()
                        .filter(|(k, _)| k.as_slice() != HINFO)
                        .map(|(k, v)| (k.clone(), Some(v.clone())))
                        .collect();
                    for (k, v) in std::mem::take(&mut w.attrs) {
                        keep.insert(k, v);
                    }
                    keep.retain(|_, v| v.is_some());
                    w.deleted = true;
                    w.fresh = true;
                    w.exists = true;
                    w.size = 0;
                    w.b = 0;
                    w.overlay = Overlay::default();
                    w.attrs = keep;
                    w.dirty = true;
                    continue;
                }
                if !ow {
                    if *size == 0 && w.fresh {
                        w.overlay = Overlay::default();
                        w.size = 0;
                        continue;
                    }
                    return Err(EOPNOTSUPP);
                }
                w.dirty = true;
                w.truncated = true;
                if *size < w.size {
                    w.overlay.cut_range(*size, u64::MAX);
                    w.b = w.b.min(*size);
                }
                w.size = *size;
            }
            TxnOp::Remove { oid } => {
                let w = ws.get(&obj(*oid)?);
                if w.exists {
                    if w.old.exists && !w.deleted {
                        w.deleted = true;
                    }
                    w.exists = false;
                    w.fresh = false;
                    w.size = 0;
                    w.b = 0;
                    w.truncated = false;
                    w.alloc_hint = None;
                    w.overlay = Overlay::default();
                    w.attrs.clear();
                    w.clone_of = None;
                    w.clone_at = usize::MAX;
                    w.omap = OmapAcc::default();
                    w.dirty = true;
                }
            }
            TxnOp::SetAttr { oid, name, value } => {
                let w = ws.get(&obj(*oid)?);
                w.ensure();
                w.attrs.insert(name.to_vec(), Some(value.to_vec()));
            }
            TxnOp::SetAttrs { oid, attrs } => {
                let w = ws.get(&obj(*oid)?);
                w.ensure();
                for (n, v) in attrs {
                    w.attrs.insert(n.to_vec(), Some(v.to_vec()));
                }
            }
            TxnOp::RmAttr { oid, name } => {
                let w = ws.get(&obj(*oid)?);
                w.ensure();
                w.attrs.insert(name.to_vec(), None);
            }
            TxnOp::TryRename { oid, dest_oid } => {
                let sk = obj(*oid)?;
                let dk = obj(*dest_oid)?;
                if !sk.is_temp() || sk.pool != Hobject::temp_pool(dk.pool) || sk.hash != dk.hash {
                    return Err(EOPNOTSUPP);
                }
                let src = ws.get(&sk);
                if !src.exists || src.deleted || src.dirty || src.fresh {
                    return Err(EINVAL);
                }
                let (size, attrs) = (src.size, src.old.attrs.clone());
                src.exists = false;
                // Cleanup also survives a later destination DELETE that reduces away the rename.
                src.deleted = true;
                let dest = ws.get(&dk);
                if dest.exists {
                    return Err(EINVAL);
                }
                dest.exists = true;
                dest.fresh = true;
                dest.size = size;
                dest.b = 0;
                dest.clone_of = Some(sk);
                dest.move_from = true;
                dest.clone_at = i;
                dest.old.attrs = attrs;
            }
            TxnOp::Clone { oid, dest_oid } => {
                let sk = obj(*oid)?;
                let src = ws.get(&sk);
                if !src.exists || src.deleted || src.dirty || src.fresh {
                    return Err(EINVAL);
                }
                let (size, src_attrs) = (src.size, src.old.attrs.clone());
                let d = ws.get(&obj(*dest_oid)?);
                if d.exists {
                    return Err(EINVAL);
                }
                d.exists = true;
                d.fresh = true;
                d.size = size;
                d.b = 0;
                d.clone_of = Some(sk);
                d.clone_at = i;
                d.old.attrs = src_attrs;
            }
            TxnOp::OmapClear { oid } => {
                let w = omap_target(&mut ws, omap_ok, &obj(*oid)?)?;
                w.omap.clear();
            }
            TxnOp::OmapSetHeader { oid, header } => {
                let w = omap_target(&mut ws, omap_ok, &obj(*oid)?)?;
                w.omap.header(header);
            }
            TxnOp::OmapSetKeys { oid, pairs } => {
                let w = omap_target(&mut ws, omap_ok, &obj(*oid)?)?;
                let kv = pairs
                    .iter()
                    .map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .collect();
                w.omap.up(OmapUp::Insert(kv));
            }
            TxnOp::OmapRmKeys { oid, keys } => {
                let w = omap_target(&mut ws, omap_ok, &obj(*oid)?)?;
                w.omap
                    .up(OmapUp::Remove(keys.iter().map(|k| k.to_vec()).collect()));
            }
            TxnOp::OmapRmKeyRange { oid, first, last } => {
                let w = omap_target(&mut ws, omap_ok, &obj(*oid)?)?;
                w.omap
                    .up(OmapUp::RemoveRange(first.to_vec(), last.to_vec()));
            }
            // temp objects, everything else: not on optimized EC pools
            _ => return Err(EOPNOTSUPP),
        }
    }
    let Works { order, mut map, .. } = ws;
    let mut works: Vec<Work> = order.iter().map(|k| map.remove(k).unwrap()).collect();
    // clones copy the committed source: they run first, in transaction order
    works.sort_by_key(|w| w.clone_at);
    Ok(works)
}

// ---- per-object plan -------------------------------------------------------------------------------------------

/// Shard op of one object on one raw shard.
#[derive(Debug, Clone)]
enum SOp {
    Create,
    CloneFrom(Hobject),
    RenameFrom(Hobject),
    /// Unlogged copy temps carry omap directly; live objects keep the EC_OMAP journal.
    TempOmap(EcOmap),
    /// live -> stash generation (delete_first).
    Stash(u64),
    Remove,
    Touch(u64),
    /// Old bytes `[off, off+len)` into stash generation `gen`.
    CloneRange {
        gen_: u64,
        off: u64,
        len: u64,
    },
    Truncate(u64),
    /// Shard bytes `[off, off+len)` from the composed column.
    Write {
        off: u64,
        len: u64,
    },
    SetAttrs(Vec<(Vec<u8>, Vec<u8>)>),
    RmAttr(Vec<u8>),
    /// Client alloc hint, sizes scaled to the shard.
    AllocHint {
        oso: u64,
        wso: u64,
        flags: u32,
    },
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
struct OObj {
    soid: Hobject,
    overlay: Overlay,
    reclaim: bool,
    /// Old bytes below `keep` are valid (logical).
    keep: u64,
    /// Parity write range (shard space): every data column is composed over it.
    par: Ext,
    /// Old shard bytes needed per raw shard (shard space, aligned, inside the old shard size): conventional = data
    /// shards only; after [`OWritePlan::select_pdw`] chose PDW = the written data shards and the member parity shards.
    reads: Vec<Ext>,
    /// Data shard write extents (`will_write` of raw `0..k`).
    wdata: Vec<Ext>,
    /// Old shard bytes the stash `clone_range` of this write reads, per raw shard (`will_write` clipped to the old shard size).
    stash_src: Vec<Ext>,
    /// Parity-delta reads when PDW is allowed for this object (ec-optimized.md 4.1.3; the code has a coding matrix),
    /// raw `0..n`.
    pdw_reads: Option<Vec<Ext>>,
    /// PDW chosen: parity = old parity + M * (old xor new) of the written data columns (4.2).
    pdw: bool,
    /// The extent cache stays valid: no delete / truncate / clone (a create or a size growth is fine).
    cache: bool,
    /// Shard ops per raw shard (members only).
    ops: Vec<Vec<SOp>>,
    written: ShardIdSet,
    md: Option<ObjectModDesc>,
    /// Builder state before `finish` (a clone entry gets the replayed EC_OMAP records of its source at generation).
    mdb: ModDescBuilder,
    clone_src: Option<Hobject>,
    post: Post,
}

/// Planned optimized-EC write: what to read, then [`OWritePlan::generate`].
#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub struct OWritePlan {
    /// Shared, not cloned per write (the backend holds the profile, mapping, codec tables).
    be: Arc<Backend>,
    pgid: PgT,
    objs: Vec<OObj>,
    /// `first_write_in_interval` was consumed (some object was generated).
    pub consumed_first_write: bool,
}

/// Extent cache page: `(raw shard, shard offset, 4 KiB bytes)`.
pub type Page = (usize, u64, Vec<u8>);

/// Output of [`OWritePlan::generate`].
#[derive(Debug)]
pub struct OGenerated<T = Vec<u8>> {
    /// v9 transaction per SHARD id (`T`: blob, or [`SharedTxn`] from [`OWritePlan::generate_shared`]); `None` = nothing
    /// for that shard (no sub-write unless the pipeline forces one).
    pub txns: Vec<Option<T>>,
    /// Extent cache update per object, applied in order: `None` = drop its pages (old content moved / cut away, or the
    /// write changed pages it does not report: whole stripes), `Some` = new content of 4 KiB shard pages `(raw, shard
    /// offset, bytes)` after the write (stripes it covers partly).
    pub pages: Vec<(Hobject, Option<Vec<Page>>)>,
    /// Final `mod_desc` per object (clone entries carry the replayed EC_OMAP records of their source).
    pub mds: BTreeMap<Hobject, ObjectModDesc>,
}

fn set_insert(s: &mut ShardIdSet, shard: u32) {
    s.0[(shard / 64) as usize] |= 1 << (shard % 64);
}

pub fn shard_set_contains(s: &ShardIdSet, shard: u32) -> bool {
    shard < 128 && s.0[(shard / 64) as usize] >> (shard % 64) & 1 == 1
}

fn set_len(s: &ShardIdSet) -> u32 {
    s.0[0].count_ones() + s.0[1].count_ones()
}

fn mask(shards: impl Iterator<Item = u32>) -> [u64; 2] {
    let mut s = ShardIdSet::default();
    for sh in shards {
        set_insert(&mut s, sh);
    }
    s.0
}

impl Backend {
    fn geo(&self) -> Geo {
        Geo {
            k: self.k as u64,
            c: self.c,
        }
    }

    /// Plan an optimized-EC write. `olds` = committed (or projected) state of every object named (missing =
    /// absent), attrs as stored on the primary's (primary-capable) shard incl. `_`; `versions` = entry version of
    /// each object. Errors are positive errno, nothing changed.
    pub fn plan_write_o(
        self: &Arc<Self>,
        pgid: PgT,
        txn: &[u8],
        olds: &BTreeMap<Hobject, OldObj>,
        versions: &BTreeMap<Hobject, u64>,
        ctx: OCtx<'_>,
    ) -> Result<OWritePlan, i32> {
        let t = io(Transaction::decode(&[], txn, 4096))?;
        self.plan_write_o_txn(pgid, &t, &[], olds, versions, ctx)
    }

    /// [`Self::plan_write_o`] from an already decoded transaction; `owners` = buffers its payload slices live in (the
    /// client skeleton's refs or the whole wire blob): retained by reference, else copied.
    pub fn plan_write_o_txn(
        self: &Arc<Self>,
        pgid: PgT,
        t: &Transaction<'_>,
        owners: &[Bytes],
        olds: &BTreeMap<Hobject, OldObj>,
        versions: &BTreeMap<Hobject, u64>,
        ctx: OCtx<'_>,
    ) -> Result<OWritePlan, i32> {
        let works = reduce(t, owners, olds, self.s, (self.overwrites, self.omap))?;
        let n = self.n();
        let mut member = vec![false; n];
        for &sh in ctx.members {
            if let Some(r) = self.raw_of(sh) {
                member[r] = true;
            }
        }
        let mut first = ctx.first_write;
        let consumed = !works.is_empty() && ctx.first_write;
        let mut objs = Vec::with_capacity(works.len());
        for w in works {
            let ver = versions.get(&w.soid).copied();
            objs.push(self.plan_obj_o(w, ver, &member, first)?);
            first = false;
        }
        Ok(OWritePlan {
            be: self.clone(),
            pgid,
            objs,
            consumed_first_write: consumed,
        })
    }

    fn plan_obj_o(
        &self,
        w: Work,
        ver: Option<u64>,
        member: &[bool],
        first_write: bool,
    ) -> Result<OObj, i32> {
        if w.size > MAX_OBJECT_SIZE || (w.old.exists && w.old.size > MAX_OBJECT_SIZE) {
            return Err(EFBIG);
        }
        let g = self.geo();
        let (k, n) = (self.k, self.n());
        let e_of = |x: u64, r: usize| g.shard_size(x, r);
        let del = w.deleted;
        let o = if w.old.exists && !del { w.old.size } else { 0 };
        let p = if w.exists { w.size } else { 0 };
        let trunc = (!del && w.b < o).then_some(w.b);
        let keep = trunc.unwrap_or(o);
        let mut md = ModDescBuilder::new();
        let mut ops: Vec<Vec<SOp>> = vec![Vec::new(); n];
        let mut written = ShardIdSet::default();
        let mut forced =
            first_write || w.alloc_hint.is_some() || del || w.fresh || trunc.is_some() || o != p;
        let push_all = |ops: &mut Vec<Vec<SOp>>, op: SOp| {
            for (r, v) in ops.iter_mut().enumerate() {
                if member[r] {
                    v.push(op.clone());
                }
            }
        };
        // 1. delete_first
        if del {
            match ver {
                Some(v) => {
                    md.delete(v);
                    push_all(&mut ops, SOp::Stash(v));
                }
                None => push_all(&mut ops, SOp::Remove),
            }
        }
        // 2. init
        if w.exists {
            if let Some(src) = &w.clone_of {
                push_all(
                    &mut ops,
                    if w.move_from {
                        SOp::RenameFrom(src.clone())
                    } else {
                        SOp::CloneFrom(src.clone())
                    },
                );
                md.create();
            } else if w.fresh {
                push_all(&mut ops, SOp::Create);
                if !del {
                    md.create();
                }
            }
            if let Some(h) = w.alloc_hint {
                let (oso, wso, flags) = h.shard(g.s(), self.c);
                push_all(&mut ops, SOp::AllocHint { oso, wso, flags });
            }
        }
        // 3. write extents
        let mut ww: Vec<Ext> = vec![Ext::new(); n];
        let mut par = Ext::new();
        let ov_ext = w.overlay.ext();
        if w.exists && w.clone_of.is_none() {
            let mut data = vec![Ext::new(); k];
            for (a, b) in ov_ext.iter() {
                g.ro_to_shards(a, b, &mut data);
            }
            for (r, e) in data.iter().enumerate() {
                par.union(&e.align_out(A));
                ww[r] = e.align_out(A);
            }
            if let Some(t) = trunc {
                let ps = t / self.s * self.s;
                if ps < t {
                    let st = t / self.s;
                    par.insert(st * self.c, st * self.c + self.c.min(al(t) - ps));
                }
            }
            for r in k..n {
                if member[r] {
                    ww[r] = par.clone();
                }
            }
        }
        // 4. reads: old data-column bytes at the parity range not replaced by the overlay
        let mut reads = vec![Ext::new(); k];
        if keep > 0 && !par.is_empty() {
            for (r, rd) in reads.iter_mut().enumerate() {
                for (x, y) in par.iter() {
                    for_segments(&g, r, x, y, |so, lo, len| {
                        let hi = (lo + len).min(keep);
                        if lo < hi {
                            let mut need = Ext::of(lo, hi);
                            need.subtract(&ov_ext);
                            for (a, b) in need.iter() {
                                rd.insert(so + (a - lo), so + (b - lo));
                            }
                        }
                    });
                }
                *rd = rd.align_out(A);
                rd.clip(0, e_of(o, r));
            }
        }
        // 4a. extent cache (wgen spec 1.4 `invalidates_cache`): the post-write pages stay valid unless the old content
        // is moved or cut away (clone/rename, delete_first, truncate); a create or a size growth keeps them
        let cache = w.exists && !del && w.clone_of.is_none() && !w.truncated && trunc.is_none();
        // 4b. PDW alternative (4.1.3): pure overwrite inside the unchanged size that needs conventional reads
        let simple = cache && !w.fresh && o == p;
        // the parity delta needs the GF(2^8) coding matrix (jerasure reed_sol_van w=16/32 = `Code::Wide` has none):
        // without it every overwrite stays conventional (same bytes, no EOPNOTSUPP at generation)
        let pdw_ok = self.codec.matrix().is_some();
        let pdw_reads = (pdw_ok && simple && reads.iter().any(|e| !e.is_empty())).then(|| {
            (0..n)
                .map(|r| {
                    let mut e = match r < k {
                        true => ww[r].clone(),
                        false if member[r] => par.clone(),
                        false => Ext::new(),
                    };
                    e.clip(0, e_of(o, r));
                    e
                })
                .collect::<Vec<Ext>>()
        });
        // 5. stash of overwritten old bytes (pre-op), truncate-down, size fix-ups
        let mut rb_ext: Vec<(u64, u64)> = Vec::new();
        let mut rb_sets: Vec<[u64; 2]> = Vec::new();
        let mut touched = vec![false; n];
        let mut stash_ops: Vec<Vec<SOp>> = vec![Vec::new(); n];
        let cl_max = if del {
            0
        } else {
            match trunc {
                Some(t) if t < al(o) => al(t),
                _ => al(o),
            }
        };
        // truncate-down record first (record order as upstream), its clones after the overwrite stash
        let mut trunc_ops: Vec<Vec<SOp>> = vec![Vec::new(); n];
        if let Some(t) = trunc {
            let mut r_set: Vec<(usize, u64, u64)> = Vec::new();
            for r in 0..n {
                let start = g.shard_data_len(t, r);
                let end = e_of(o, r);
                if start < end {
                    r_set.push((r, start, end));
                }
            }
            if !r_set.is_empty() {
                let cs = r_set.iter().map(|x| x.1 & !(A - 1)).min().unwrap();
                let ce = r_set.iter().map(|x| x.2).max().unwrap();
                for &(r, start, end) in &r_set {
                    if !member[r] {
                        continue;
                    }
                    if let Some(v) = ver {
                        if !touched[r] {
                            touched[r] = true;
                            stash_ops[r].push(SOp::Touch(v));
                        }
                        stash_ops[r].push(SOp::CloneRange {
                            gen_: v,
                            off: cs,
                            len: end - cs,
                        });
                    }
                    trunc_ops[r].push(SOp::Truncate(start));
                    if !start.is_multiple_of(A) {
                        trunc_ops[r].push(SOp::Truncate(al(start)));
                    }
                }
                rb_ext.push((cs, ce - cs));
                rb_sets.push(mask(r_set.iter().map(|x| self.mapping[x.0])));
            }
        }
        // overwrite stash (part 2): X = union of all will_write
        let mut x_set = Ext::new();
        for e in &ww {
            x_set.union(e);
        }
        if !x_set.is_empty() {
            for (r, e) in ww.iter().enumerate() {
                if !e.is_empty() {
                    set_insert(&mut written, self.mapping[r]);
                }
            }
            if let Some(v) = ver {
                for (a, b) in x_set.iter() {
                    let mut to_clone: Vec<usize> = Vec::new();
                    let mut clone_end = 0;
                    for r in 0..n {
                        if ww[r].is_empty() {
                            continue;
                        }
                        let e = e_of(cl_max, r);
                        if e == 0 {
                            continue;
                        }
                        let se = b.min(e);
                        clone_end = clone_end.max(se);
                        if se <= a || !ww[r].intersects(a, b) {
                            continue;
                        }
                        if member[r] {
                            if !touched[r] {
                                touched[r] = true;
                                stash_ops[r].push(SOp::Touch(v));
                            }
                            stash_ops[r].push(SOp::CloneRange {
                                gen_: v,
                                off: a,
                                len: se - a,
                            });
                            to_clone.push(r);
                        }
                    }
                    if !to_clone.is_empty() && clone_end > a {
                        rb_ext.push((a, clone_end - a));
                        rb_sets.push(if to_clone.len() == n {
                            [0, 0]
                        } else {
                            mask(to_clone.iter().map(|r| self.mapping[*r]))
                        });
                    }
                }
            }
        }
        for r in 0..n {
            ops[r].append(&mut stash_ops[r]);
            ops[r].append(&mut trunc_ops[r]);
        }
        // size fix-ups: keep every shard at the formula size (holes stay sparse)
        if w.exists && w.clone_of.is_none() && (del || w.truncated || trunc.is_some() || o < p) {
            for r in 0..n {
                let new = e_of(p, r);
                if new == 0 {
                    continue;
                }
                let old = e_of(cl_max, r);
                if new == old || ww[r].last_end() == Some(new) {
                    continue;
                }
                if member[r] {
                    ops[r].push(SOp::Truncate(new));
                }
                set_insert(&mut written, self.mapping[r]);
            }
        }
        // 6. writes
        for r in 0..n {
            if member[r] {
                for (a, b) in ww[r].iter() {
                    ops[r].push(SOp::Write { off: a, len: b - a });
                }
            }
        }
        // 7. mod_desc data records
        if o < p && !del {
            md.append(al(o));
        }
        if let Some(v) = ver
            && !rb_ext.is_empty()
        {
            md.rollback_extents_v3(v, &rb_ext, al(o), &rb_sets);
        }
        for rec in &w.omap.recs {
            if w.soid.is_temp() && ver.is_none() {
                for r in std::iter::once(0).chain(k..n) {
                    if member[r] {
                        ops[r].push(SOp::TempOmap(rec.clone()));
                    }
                }
            } else {
                md.ec_omap(rec);
            }
        }
        // 8. written_shards
        let old_oi = w
            .old
            .attrs
            .get(OI_KEY)
            .filter(|_| w.old.exists && !del && !w.fresh)
            .map(|b| denc::from_slice::<ObjectInfo>(b).map_err(|_| EIO))
            .transpose()?;
        let mut attrs = w.attrs.clone();
        let mut new_oi = match attrs.get(OI_KEY) {
            Some(Some(b)) => Some(denc::from_slice::<ObjectInfo>(b).map_err(|_| EINVAL)?),
            _ => None,
        };
        if let (Some(a), Some(b)) = (&old_oi, &new_oi)
            && a.is_whiteout()
            && !b.is_whiteout()
        {
            forced = true;
        }
        set_insert(&mut written, self.mapping[0]);
        for r in k..n {
            set_insert(&mut written, self.mapping[r]);
        }
        if forced || set_len(&written) as usize == n {
            written = ShardIdSet::default();
        }
        let all = written.is_empty();
        let is_written = |r: usize| all || shard_set_contains(&written, self.mapping[r]);
        // 9. shard_versions of the new object_info (primary only bookkeeping)
        if let Some(oi) = new_oi.as_mut() {
            let mut sv = old_oi
                .as_ref()
                .map(|x| x.shard_versions.clone())
                .unwrap_or_default();
            if all {
                sv.clear();
            } else {
                for r in 1..k {
                    let s = ShardId(self.mapping[r] as i8);
                    if is_written(r) {
                        sv.remove(&s);
                    } else {
                        sv.entry(s).or_insert(oi.prior_version);
                    }
                }
            }
            if oi.shard_versions != sv {
                oi.shard_versions = sv;
                attrs.insert(OI_KEY.to_vec(), Some(io(denc::to_vec(&*oi))?));
            }
        }
        // 10. attributes: PC shards all, written NP shards only `_`
        if w.exists {
            let sets: Vec<(Vec<u8>, Vec<u8>)> = attrs
                .iter()
                .filter_map(|(k, v)| v.as_ref().map(|v| (k.clone(), v.clone())))
                .collect();
            let oi_only: Vec<(Vec<u8>, Vec<u8>)> =
                sets.iter().filter(|(k, _)| k == OI_KEY).cloned().collect();
            for r in 0..n {
                if !member[r] {
                    continue;
                }
                if r == 0 || r >= k {
                    if !sets.is_empty() {
                        ops[r].push(SOp::SetAttrs(sets.clone()));
                    }
                    for (key, v) in &attrs {
                        if v.is_none() {
                            ops[r].push(SOp::RmAttr(key.clone()));
                        }
                    }
                } else if is_written(r) && !oi_only.is_empty() {
                    ops[r].push(SOp::SetAttrs(oi_only.clone()));
                }
            }
            if !w.fresh {
                let rb: Vec<(Vec<u8>, Option<Vec<u8>>)> = attrs
                    .keys()
                    .map(|key| (key.clone(), w.old.attrs.get(key).cloned()))
                    .collect();
                if !rb.is_empty() {
                    md.set_attrs(&rb);
                }
            }
        }
        // invariant: every member with work is in written_shards (R1)
        for r in 0..n {
            if member[r] && !ops[r].is_empty() && !is_written(r) {
                return Err(EIO);
            }
        }
        // resulting state
        let post = if w.exists {
            let mut pa = if w.clone_of.is_some() || !w.fresh {
                w.old.attrs.clone()
            } else {
                BTreeMap::new()
            };
            for (key, v) in &attrs {
                match v {
                    Some(v) => {
                        pa.insert(key.clone(), v.clone());
                    }
                    None => {
                        pa.remove(key);
                    }
                }
            }
            Post {
                exists: true,
                size: p,
                attrs: pa,
            }
        } else {
            Post::default()
        };
        let stash_src: Vec<Ext> = ww
            .iter()
            .enumerate()
            .map(|(r, e)| {
                let mut e = if ver.is_some() { e.clone() } else { Ext::new() };
                e.clip(0, e_of(cl_max, r));
                e
            })
            .collect();
        let mdb = md.clone();
        let clone_src = w.clone_of.clone();
        let (bl, version, completed) = md.finish();
        let md = ver.map(|_| ObjectModDesc {
            version,
            can_local_rollback: true,
            rollback_info_completed: completed,
            bl,
        });
        Ok(OObj {
            soid: w.soid,
            overlay: w.overlay,
            reclaim: w.reclaim,
            keep,
            par,
            reads,
            wdata: ww[..k].to_vec(),
            stash_src,
            pdw_reads,
            pdw: false,
            cache,
            ops,
            written,
            md,
            mdb,
            clone_src,
            post,
        })
    }
}

/// Visit the chunk segments of shard range `[x, y)` of raw data shard `r`: `f(shard_off, logical_off, len)`.
fn for_segments(g: &Geo, r: usize, x: u64, y: u64, mut f: impl FnMut(u64, u64, u64)) {
    let mut so = x;
    while so < y {
        let row_end = (so / g.c + 1) * g.c;
        let e = row_end.min(y);
        f(so, g.shard_to_ro(r, so), e - so);
        so = e;
    }
}

/// Parity-delta write selection (`ec_pdw`; ec-optimized.md 4.1.3 `ec_pdw_write_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PdwMode {
    /// Conventional RMW only.
    #[default]
    Never,
    /// Fewer shards to read wins (tie: PDW); never when PDW reads >= k shards or needs a decode.
    Auto,
    /// PDW whenever allowed (tests).
    Always,
}

impl PdwMode {
    /// Parse `ec_pdw` (`off`, `auto`, `always`). `None` = unknown value: `PgSet::set_ec_pdw` keeps the current
    /// mode and reports it.
    pub fn parse(s: &str) -> Option<PdwMode> {
        match s {
            "off" => Some(PdwMode::Never),
            "auto" => Some(PdwMode::Auto),
            "always" => Some(PdwMode::Always),
            _ => None,
        }
    }
}

impl OWritePlan {
    /// Choose PDW or conventional RMW per object. `readable(object, shard id)` = the shard can serve a read of the
    /// object without a decode; `cached(object, raw, ext)` = the bytes are in the extent cache (no shard read).
    /// Shard output is byte-identical either way (linearity); only the reads differ. Returns the PDW object count.
    pub fn select_pdw(
        &mut self,
        mode: PdwMode,
        readable: impl Fn(&Hobject, u32) -> bool,
        cached: impl Fn(&Hobject, usize, &Ext) -> bool,
    ) -> usize {
        if mode == PdwMode::Never {
            return 0;
        }
        let (k, map) = (self.be.k, &self.be.mapping);
        let mut chosen = 0;
        for o in &mut self.objs {
            let Some(pr) = o.pdw_reads.as_ref() else {
                continue;
            };
            // (shards read, a read needs a decode)
            let cost = |rs: &[Ext]| {
                let (mut cnt, mut dec) = (0usize, false);
                for (r, e) in rs.iter().enumerate() {
                    if !e.is_empty() && !cached(&o.soid, r, e) {
                        cnt += 1;
                        dec |= !readable(&o.soid, map[r]);
                    }
                }
                (cnt, dec)
            };
            let use_pdw = match mode {
                PdwMode::Always => true,
                _ => {
                    let ((pc, pd), (cc, cd)) = (cost(pr), cost(&o.reads));
                    !(pc >= k || pd) && (cd || pc <= cc)
                }
            };
            if use_pdw {
                o.reads = o.pdw_reads.take().unwrap_or_default();
                o.pdw = true;
                chosen += 1;
            }
        }
        chosen
    }

    /// Old bytes needed: `(object, raw shard, shard-space extents)` (each extent inside the old shard size; raw
    /// `>= k` = old parity of a PDW object).
    pub fn reads(&self) -> Vec<(Hobject, usize, Ext)> {
        let mut v = Vec::new();
        for o in &self.objs {
            for (r, e) in o.reads.iter().enumerate() {
                if !e.is_empty() {
                    v.push((o.soid.clone(), r, e.clone()));
                }
            }
        }
        v
    }

    /// Own-shard bytes the stash of this write reads (`clone_range` sources): `(object, shard offset, length)` of raw
    /// shard `raw`. The primary prefetches them so the local apply never waits on the device.
    pub fn stash_srcs(&self, raw: usize) -> Vec<(Hobject, u64, u64)> {
        let mut v = Vec::new();
        for o in &self.objs {
            if let Some(e) = o.stash_src.get(raw) {
                v.extend(e.iter().map(|(a, b)| (o.soid.clone(), a, b - a)));
            }
        }
        v
    }

    pub fn objects(&self) -> Vec<Hobject> {
        self.objs.iter().map(|o| o.soid.clone()).collect()
    }

    pub fn post(&self) -> BTreeMap<Hobject, Post> {
        self.objs
            .iter()
            .map(|o| (o.soid.clone(), o.post.clone()))
            .collect()
    }

    pub fn mod_descs(&self) -> BTreeMap<Hobject, ObjectModDesc> {
        self.objs
            .iter()
            .filter_map(|o| o.md.clone().map(|m| (o.soid.clone(), m)))
            .collect()
    }

    /// `written_shards` per object (empty = all shards).
    pub fn written(&self) -> BTreeMap<Hobject, ShardIdSet> {
        self.objs
            .iter()
            .map(|o| (o.soid.clone(), o.written))
            .collect()
    }

    /// Shard ids written by any object of the plan (`None` = all).
    pub fn written_union(&self) -> Option<ShardIdSet> {
        let mut u = ShardIdSet::default();
        for o in &self.objs {
            if o.written.is_empty() {
                return None;
            }
            u.0[0] |= o.written.0[0];
            u.0[1] |= o.written.0[1];
        }
        Some(u)
    }

    /// Clone sources whose not-yet-rolled-forward EC_OMAP records [`OWritePlan::generate_omap`] needs.
    pub fn clone_srcs(&self) -> Vec<Hobject> {
        self.objs
            .iter()
            .filter_map(|o| o.clone_src.clone())
            .collect()
    }

    /// [`OWritePlan::generate_omap`] without omap replay.
    pub fn generate(
        self,
        old: &BTreeMap<(Hobject, usize), (u64, Vec<u8>)>,
    ) -> Result<OGenerated, i32> {
        self.generate_omap(old, &BTreeMap::new())
    }

    /// Produce the shard transactions. `old[(object, raw)]` = `(shard offset, bytes)` covering every extent of
    /// [`OWritePlan::reads`] for that shard (bytes past the shard's end may be absent = zeros). `pending[src]` =
    /// EC_OMAP records of `src` not rolled forward yet, in log order, since its object was last created: a clone
    /// copies the stored omap of its source, the replay brings it to the source's current state (spec 12.2).
    pub fn generate_omap(
        self,
        old: &BTreeMap<(Hobject, usize), (u64, Vec<u8>)>,
        pending: &BTreeMap<Hobject, Vec<EcOmap>>,
    ) -> Result<OGenerated, i32> {
        self.generate_with(old, pending, |_, t, _| io(t.encode_v9()))
    }

    /// [`generate_omap`](Self::generate_omap) without copying the shard payloads (byte-identical transactions): per shard
    /// the wire rope and the local skeleton over the same shared column buffers, like the legacy `generate_shared`. `local`:
    /// `Some(shard)` = only that shard's transaction applies locally (it gets just the skeleton, the others just the rope:
    /// one encode per shard); `None` = both forms for every shard (tests).
    pub fn generate_shared(
        self,
        old: &BTreeMap<(Hobject, usize), (u64, Vec<u8>)>,
        pending: &BTreeMap<Hobject, Vec<EcOmap>>,
        local: Option<u32>,
    ) -> Result<OGenerated<SharedTxn>, i32> {
        self.generate_with(old, pending, |sh, t, owners| {
            let (wire, mine) = (local != Some(sh), local.is_none_or(|l| l == sh));
            let (inline, zc) = if wire {
                io(t.encode_v9_rope(owners))?
            } else {
                Default::default()
            };
            let (skel, refs) = if mine {
                io(t.encode_v9_local(owners))?
            } else {
                Default::default()
            };
            Ok(SharedTxn {
                inline,
                zc,
                payload_at: t.payload_at(),
                skel,
                refs,
                hints: Vec::new(),
            })
        })
    }

    /// The shard transactions, each handed to `emit` with the column buffers its payloads live in.
    fn generate_with<T>(
        self,
        old: &BTreeMap<(Hobject, usize), (u64, Vec<u8>)>,
        pending: &BTreeMap<Hobject, Vec<EcOmap>>,
        mut emit: impl FnMut(u32, &Transaction<'_>, &[Bytes]) -> Result<T, i32>,
    ) -> Result<OGenerated<T>, i32> {
        let be = &self.be;
        let g = be.geo();
        let (k, m, n) = (be.k, be.m, be.n());
        let mut txns: Vec<Transaction> = (0..n).map(|_| Transaction::new()).collect();
        let mut used = vec![false; n];
        let colls: Vec<replwire::Cx> = (0..n)
            .map(|r| {
                let sh = be.mapping[r];
                txns[r].coll(&CollT::Pg(SpgT {
                    pgid: self.pgid,
                    shard: ShardId(sh as i8),
                }))
            })
            .collect();
        type Cols = (Vec<(u64, u64)>, Vec<Vec<Bytes>>);
        let mut all: Vec<Cols> = Vec::with_capacity(self.objs.len());
        for o in &self.objs {
            // old shards of this object: one index per object, no key clone per shard lookup
            let olds: Vec<(usize, &(u64, Vec<u8>))> = old
                .range((o.soid.clone(), 0)..)
                .take_while(|((h, _), _)| h == &o.soid)
                .map(|((_, r), v)| (*r, v))
                .collect();
            let old_of = |r: usize| -> Option<&(u64, Vec<u8>)> {
                olds.iter().find(|(raw, _)| *raw == r).map(|(_, v)| *v)
            };
            // compose data columns over the parity range, encode parity
            let pext: Vec<(u64, u64)> = o.par.iter().collect();
            // the plan asked for these old bytes: the caller must deliver a buffer covering them (bytes past the
            // shard's end may be absent = zeros)
            for (r, rd) in o.reads.iter().enumerate() {
                let src = old_of(r);
                for (a, _) in rd.iter() {
                    if !src.is_some_and(|(off, _)| *off <= a) {
                        return Err(EIO);
                    }
                }
            }
            let mut cols: Vec<Vec<Vec<u8>>> = Vec::with_capacity(n);
            // PDW: the old data columns (before the overlay)
            let mut old_cols: Vec<Vec<Vec<u8>>> = Vec::new();
            for r in 0..k {
                let src = old_of(r);
                let mut per = Vec::with_capacity(pext.len());
                let mut old_per = Vec::new();
                for &(x, y) in &pext {
                    let mut buf = vec![0u8; (y - x) as usize];
                    for_segments(&g, r, x, y, |so, lo, len| {
                        let dst = &mut buf[(so - x) as usize..(so - x + len) as usize];
                        // old bytes below keep (absent = zeros)
                        let hi = (lo + len).min(o.keep);
                        if lo < hi
                            && let Some((off, bytes)) = src
                        {
                            // overlap of the shard range [so, so + (hi-lo)) with the delivered buffer
                            let (a, b) =
                                (so.max(*off), (so + (hi - lo)).min(off + bytes.len() as u64));
                            if a < b {
                                dst[(a - so) as usize..(b - so) as usize].copy_from_slice(
                                    &bytes[(a - off) as usize..(b - off) as usize],
                                );
                            }
                        }
                    });
                    if o.pdw && !o.wdata[r].is_empty() {
                        old_per.push(buf.clone());
                    }
                    for_segments(&g, r, x, y, |so, lo, len| {
                        o.overlay.fill(
                            lo,
                            lo + len,
                            &mut buf[(so - x) as usize..(so - x + len) as usize],
                        );
                    });
                    per.push(buf);
                }
                cols.push(per);
                old_cols.push(old_per);
            }
            if o.pdw && !pext.is_empty() {
                // parity-delta (4.2): old parity + sum M[j][r] * (old_r xor new_r) over the written data extents
                for j in 0..m {
                    let src = old_of(k + j);
                    let mut per = Vec::with_capacity(pext.len());
                    for &(x, y) in &pext {
                        let mut buf = vec![0u8; (y - x) as usize];
                        if let Some((off, bytes)) = src {
                            let (a, b) = (x.max(*off), y.min(off + bytes.len() as u64));
                            if a < b {
                                buf[(a - x) as usize..(b - x) as usize].copy_from_slice(
                                    &bytes[(a - off) as usize..(b - off) as usize],
                                );
                            }
                        }
                        per.push(buf);
                    }
                    cols.push(per);
                }
                let mat = be.codec.matrix().ok_or(EOPNOTSUPP)?;
                let mut delta: Vec<u8> = Vec::new();
                for r in 0..k {
                    for (a, b) in o.wdata[r].iter() {
                        let i = pext
                            .iter()
                            .position(|(x, y)| *x <= a && b <= *y)
                            .ok_or(EIO)?;
                        let (lo, hi) = ((a - pext[i].0) as usize, (b - pext[i].0) as usize);
                        delta.clear();
                        delta.extend(
                            old_cols[r][i][lo..hi]
                                .iter()
                                .zip(&cols[r][i][lo..hi])
                                .map(|(p, q)| p ^ q),
                        );
                        for j in 0..m {
                            ec::gf::mul_acc(&mut cols[k + j][i][lo..hi], &delta, mat[j * k + r]);
                        }
                    }
                }
            } else if !pext.is_empty() {
                for _ in 0..m {
                    cols.push(
                        pext.iter()
                            .map(|(x, y)| vec![0u8; (y - x) as usize])
                            .collect(),
                    );
                }
                let (data, parity) = cols.split_at_mut(k);
                for i in 0..pext.len() {
                    let d: Vec<&[u8]> = data.iter().map(|c| &c[i][..]).collect();
                    let mut p: Vec<&mut [u8]> = parity.iter_mut().map(|c| &mut c[i][..]).collect();
                    be.codec.encode(&d, &mut p);
                }
            }
            // composed: freeze (no copy), the shard transactions share the columns
            let cols = cols
                .into_iter()
                .map(|c| c.into_iter().map(Bytes::from).collect())
                .collect();
            all.push((pext, cols));
        }
        // extent cache: post-write pages (data columns over the parity range are complete unless PDW, which composes
        // only the written data extents; parity always complete). Only of the stripes the write covers partly: a later
        // RMW write reads there (the next append, the other half of a stripe); the pages of a stripe written whole are
        // not copied, its older cached pages go with a drop of the object's pages before the put.
        let mut pages = Vec::new();
        for (o, (pext, cols)) in self.objs.iter().zip(&all) {
            if !o.cache {
                pages.push((o.soid.clone(), None));
                continue;
            }
            if pext.is_empty() {
                continue;
            }
            let ov = o.overlay.ext();
            let whole = |off: u64| {
                let s0 = off / be.c * be.s;
                ov.contains_range(s0, s0 + be.s)
            };
            let mut skipped = false;
            let mut v = Vec::new();
            for (r, col) in cols.iter().enumerate() {
                // PDW: a parity shard that is not a member was not read (its column is not the new parity, its older
                // pages go with the drop)
                let ext: Vec<(u64, u64)> = match (o.pdw, r < k) {
                    (true, true) => o.wdata[r].iter().collect(),
                    (true, false) if o.reads[r].is_empty() => {
                        skipped = true;
                        continue;
                    }
                    _ => pext.clone(),
                };
                for (a, b) in ext {
                    let i = pext
                        .iter()
                        .position(|(x, y)| *x <= a && b <= *y)
                        .ok_or(EIO)?;
                    let x = pext[i].0;
                    for off in (a..b).step_by(A as usize) {
                        if whole(off) {
                            skipped = true;
                            continue;
                        }
                        let lo = (off - x) as usize;
                        v.push((r, off, col[i][lo..lo + A as usize].to_vec()));
                    }
                }
            }
            if skipped {
                pages.push((o.soid.clone(), None));
            }
            pages.push((o.soid.clone(), Some(v)));
        }
        // the transactions borrow the columns: built after all objects are composed
        for (o, (pext, cols)) in self.objs.iter().zip(&all) {
            let col_slice = |r: usize, off: u64, len: u64| -> Option<&[u8]> {
                let i = pext
                    .iter()
                    .position(|(x, y)| *x <= off && off + len <= *y)?;
                let x = pext[i].0;
                Some(&cols[r][i][(off - x) as usize..(off - x + len) as usize])
            };
            for r in 0..n {
                if o.ops[r].is_empty() {
                    continue;
                }
                used[r] = true;
                let sh = ShardId(be.mapping[r] as i8);
                let t = &mut txns[r];
                let cx = colls[r];
                let live = Ghobject::new(o.soid.clone(), LIVE, sh);
                for op in &o.ops[r] {
                    match op {
                        SOp::Create => {
                            let ox = t.obj(&live);
                            t.push(cx, TxnOp::Create { oid: ox });
                        }
                        SOp::AllocHint { oso, wso, flags } => {
                            let ox = t.obj(&live);
                            t.push(
                                cx,
                                TxnOp::SetAllocHint {
                                    oid: ox,
                                    expected_object_size: *oso,
                                    expected_write_size: *wso,
                                    flags: *flags,
                                },
                            );
                        }
                        SOp::TempOmap(rec) => {
                            let oid = t.obj(&live);
                            if let Some(header) = &rec.header {
                                t.push(cx, TxnOp::OmapSetHeader { oid, header });
                            }
                            if rec.clear {
                                t.push(cx, TxnOp::OmapClear { oid });
                            }
                            for up in &rec.ups {
                                match up {
                                    OmapUp::Insert(kv) => t.push(
                                        cx,
                                        TxnOp::OmapSetKeys {
                                            oid,
                                            pairs: kv
                                                .iter()
                                                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                                                .collect(),
                                        },
                                    ),
                                    OmapUp::Remove(keys) => t.push(
                                        cx,
                                        TxnOp::OmapRmKeys {
                                            oid,
                                            keys: keys.iter().map(|k| k.as_slice()).collect(),
                                        },
                                    ),
                                    OmapUp::RemoveRange(first, last) => {
                                        t.push(cx, TxnOp::OmapRmKeyRange { oid, first, last })
                                    }
                                }
                            }
                        }
                        SOp::RenameFrom(src) => {
                            let a = t.obj(&Ghobject::new(src.clone(), LIVE, sh));
                            let b = t.obj(&live);
                            t.push(
                                cx,
                                TxnOp::TryRename {
                                    oid: a,
                                    dest_oid: b,
                                },
                            );
                        }
                        SOp::CloneFrom(src) => {
                            let a = t.obj(&Ghobject::new(src.clone(), LIVE, sh));
                            let b = t.obj(&live);
                            t.push(
                                cx,
                                TxnOp::Clone {
                                    oid: a,
                                    dest_oid: b,
                                },
                            );
                        }
                        SOp::Stash(gen_) => {
                            let a = t.obj(&live);
                            let b = t.obj(&Ghobject::new(o.soid.clone(), *gen_, sh));
                            t.push(
                                cx,
                                TxnOp::CollMoveRename {
                                    oid: a,
                                    dest_cid: cx,
                                    dest_oid: b,
                                },
                            );
                        }
                        SOp::Remove => {
                            let ox = t.obj(&live);
                            t.push(cx, TxnOp::Remove { oid: ox });
                        }
                        SOp::Touch(gen_) => {
                            let ox = t.obj(&Ghobject::new(o.soid.clone(), *gen_, sh));
                            t.push(cx, TxnOp::Touch { oid: ox });
                        }
                        SOp::CloneRange { gen_, off, len } => {
                            let a = t.obj(&live);
                            let b = t.obj(&Ghobject::new(o.soid.clone(), *gen_, sh));
                            t.push(
                                cx,
                                TxnOp::CloneRange2 {
                                    oid: a,
                                    dest_oid: b,
                                    src_off: *off,
                                    len: *len,
                                    dest_off: *off,
                                },
                            );
                        }
                        SOp::Truncate(size) => {
                            let ox = t.obj(&live);
                            t.push(
                                cx,
                                TxnOp::Truncate {
                                    oid: ox,
                                    size: *size,
                                },
                            );
                        }
                        SOp::Write { off, len } => {
                            let data = col_slice(r, *off, *len).ok_or(EIO)?;
                            let ox = t.obj(&live);
                            crate::shard_write(t, cx, ox, *off, data, o.reclaim);
                        }
                        SOp::SetAttrs(attrs) => {
                            let ox = t.obj(&live);
                            t.push(
                                cx,
                                TxnOp::SetAttrs {
                                    oid: ox,
                                    attrs: attrs
                                        .iter()
                                        .map(|(k, v)| (k.as_slice(), v.as_slice()))
                                        .collect(),
                                },
                            );
                        }
                        SOp::RmAttr(name) => {
                            let ox = t.obj(&live);
                            t.push(cx, TxnOp::RmAttr { oid: ox, name });
                        }
                    }
                }
            }
        }
        let owners: Vec<Bytes> = all
            .iter()
            .flat_map(|(_, c)| c.iter().flatten().cloned())
            .collect();
        let mut out: Vec<Option<T>> = (0..n).map(|_| None).collect();
        for (r, t) in txns.into_iter().enumerate() {
            if used[r] {
                out[be.mapping[r] as usize] = Some(emit(be.mapping[r], &t, &owners)?);
            }
        }
        let mut mds = BTreeMap::new();
        for o in &self.objs {
            let Some(md) = &o.md else { continue };
            let mut md = md.clone();
            if let Some(recs) = o
                .clone_src
                .as_ref()
                .and_then(|s| pending.get(s))
                .filter(|r| !r.is_empty())
            {
                let mut b = o.mdb.clone();
                for r in recs {
                    b.ec_omap(r);
                }
                (md.bl, md.version, md.rollback_info_completed) = b.finish();
            }
            mds.insert(o.soid.clone(), md);
        }
        Ok(OGenerated {
            txns: out,
            pages,
            mds,
        })
    }
}

/// Version a shard holds per the primary's object_info (`shard_versions` override, else `oi.version`).
pub fn version_for_shard(oi: &ObjectInfo, shard: u32) -> Eversion {
    oi.shard_versions
        .get(&ShardId(shard as i8))
        .copied()
        .unwrap_or(oi.version)
}
