// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Write generator (ec.md 11.2, L0/L1): logical transaction -> per-shard transactions + rollback info.
//!
//! The logical transaction is the replicated-shape v9 transaction of the op layer (ghobjects NO_GEN, ops Create,
//! Write, Zero, Truncate, Remove, SetAttrs, RmAttr, Clone, SetAllocHint). Per object the ops are reduced to
//! (delete_first, truncate point, write overlay, attribute updates), then expressed in whole stripes:
//! `b` = old content kept (old size or the truncate point), overwrite stripes lie below `ceil(b/S)`, append stripes at or
//! above it; every changed old shard range is stashed under generation `V` (the entry version) first.

use crate::oext::Ext;
use crate::{Backend, EFBIG, EINVAL, EIO, EOPNOTSUPP, MAX_OBJECT_SIZE, io};
use bytes::Bytes;
use crc::{BlockCrcs, CrcHint};
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SpgT};
use ec::HashInfo;
use ec::moddesc::ModDescBuilder;
use pgwire::ObjectModDesc;
use replwire::txn::{Transaction, TxnOp};
use std::collections::{BTreeMap, BTreeSet};

const LIVE: u64 = Ghobject::NO_GEN;
const HINFO: &[u8] = ec::HINFO_KEY.as_bytes();

/// Committed state of an object before the transaction (from the primary's own shard).
#[derive(Debug, Clone, Default)]
pub struct OldObj {
    pub exists: bool,
    /// Logical size (object_info size).
    pub size: u64,
    /// All xattrs of the object as stored (incl. `_`, `snapset`, `hinfo_key`).
    pub attrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Disjoint logical byte extents of new data (later writes win). Shared by both write generators.
#[derive(Debug, Default, Clone)]
pub(crate) struct Overlay(BTreeMap<u64, Bytes>);

#[cfg(test)]
thread_local! {
    static OVERLAY_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl Overlay {
    // Disjoint extents: only the predecessor of lo can start before lo and overlap it.
    fn candidates(&self, lo: u64, hi: u64) -> impl Iterator<Item = (&u64, &Bytes)> {
        let start = self
            .0
            .range(..=lo)
            .next_back()
            .map_or(lo, |(o, _)| *o)
            .min(hi);
        self.0.range(start..hi).inspect(|_| {
            #[cfg(test)]
            OVERLAY_VISITS.with(|v| v.set(v.get() + 1));
        })
    }

    pub(crate) fn put(&mut self, off: u64, data: Bytes) {
        if data.is_empty() {
            return;
        }
        let end = off + data.len() as u64;
        self.cut_range(off, end);
        self.0.insert(off, data);
    }
    /// Remove `[lo, hi)`.
    pub(crate) fn cut_range(&mut self, lo: u64, hi: u64) {
        let hits: Vec<u64> = self
            .candidates(lo, hi)
            .filter(|(o, d)| **o + d.len() as u64 > lo)
            .map(|(o, _)| *o)
            .collect();
        for o in hits {
            let d = self.0.remove(&o).unwrap();
            let e = o + d.len() as u64;
            if o < lo {
                self.0.insert(o, d.slice(..(lo - o) as usize));
            }
            if e > hi {
                self.0.insert(hi, d.slice((hi - o) as usize..));
            }
        }
    }
    /// Discard everything at or above `size`.
    fn cut(&mut self, size: u64) {
        self.cut_range(size, u64::MAX);
    }
    fn clear(&mut self) {
        self.0.clear();
    }
    /// A complete run backed by one retained write needs no stripe-composition buffer.
    fn covered_slice(&self, lo: u64, hi: u64) -> Option<&[u8]> {
        let (off, data) = self.0.range(..=lo).next_back()?;
        if hi > *off + data.len() as u64 {
            return None;
        }
        Some(&data[(lo - off) as usize..(hi - off) as usize])
    }
    /// Is every byte of `[lo, hi)` covered?
    fn covers(&self, lo: u64, hi: u64) -> bool {
        let mut pos = lo;
        for (o, d) in self.candidates(lo, hi) {
            let e = *o + d.len() as u64;
            if e <= pos {
                continue;
            }
            if *o > pos {
                return false;
            }
            pos = e;
            if pos >= hi {
                return true;
            }
        }
        pos >= hi
    }
    /// The overlay as shard-space extents (optimized generator).
    pub(crate) fn ext(&self) -> Ext {
        let mut e = Ext::new();
        for (o, d) in &self.0 {
            e.insert(*o, *o + d.len() as u64);
        }
        e
    }
    /// Copy the overlay bytes inside `[lo, hi)` into `dst` (indexed from `lo`).
    pub(crate) fn fill(&self, lo: u64, hi: u64, dst: &mut [u8]) {
        for (o, d) in self.candidates(lo, hi) {
            let e = *o + d.len() as u64;
            if e <= lo {
                continue;
            }
            let (a, b) = ((*o).max(lo), e.min(hi));
            dst[(a - lo) as usize..(b - lo) as usize]
                .copy_from_slice(&d[(a - *o) as usize..(b - *o) as usize]);
        }
    }
}

#[derive(Debug, Clone)]
struct Work {
    soid: Hobject,
    old: OldObj,
    /// Object exists at this point of the transaction.
    exists: bool,
    /// The old object was moved away (delete or truncate-to-0 special case).
    deleted: bool,
    /// Created by this transaction (new, recreated, or cloned).
    fresh: bool,
    /// Content comes from this source object's shard files.
    clone_of: Option<Hobject>,
    /// Move a committed copy temp into place instead of cloning it.
    move_from: bool,
    /// Index of the Clone op that made it (`usize::MAX`: none): shard clones run in transaction order.
    clone_at: usize,
    /// Current logical size.
    size: u64,
    /// Old content still valid: `min(old size, truncate points)`; 0 when deleted / new.
    b: u64,
    overlay: Overlay,
    reclaim: bool,
    attrs: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// Touched by a data op after creation (a clone destination must not be).
    dirty: bool,
    /// Client alloc hint of the transaction (logical sizes, flags ORed); `None` = no hint op.
    hint: Option<Hint>,
}

/// Client `SETALLOCHINT` of one object (logical expected sizes). Every shard transaction of the object carries it
/// with the sizes scaled to the shard (`ceil(x / stripe) * chunk`), so a shard's store sees the same compression
/// decision input as a replicated object (adr 0059 am. 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hint {
    pub(crate) oso: u64,
    pub(crate) wso: u64,
    pub(crate) flags: u32,
}

impl Hint {
    /// Fold a later hint op into the transaction's hint: flags are ORed (the store ORs them per transaction), sizes of the last op win.
    pub(crate) fn merge(old: Option<Hint>, oso: u64, wso: u64, flags: u32) -> Hint {
        Hint {
            oso,
            wso,
            flags: old.map_or(0, |h| h.flags) | flags,
        }
    }

    /// Per-shard sizes for stripe width `s` and chunk size `c`.
    pub(crate) fn shard(self, s: u64, c: u64) -> (u64, u64, u32) {
        let sc = |x: u64| x.div_ceil(s).saturating_mul(c);
        (sc(self.oso), sc(self.wso), self.flags)
    }
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
            overlay: Overlay::default(),
            reclaim: false,
            attrs: BTreeMap::new(),
            dirty: false,
            hint: None,
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

/// Shard operation, identical on every shard unless it names a write run.
#[derive(Debug, Clone)]
enum SOp {
    Create(Hobject),
    /// Touch of a stash generation.
    TouchGen(Hobject, u64),
    Write {
        soid: Hobject,
        off: u64,
        run: usize,
        reclaim: bool,
    },
    CloneRange {
        soid: Hobject,
        gen_: u64,
        off: u64,
        len: u64,
    },
    Truncate(Hobject, u64),
    Remove(Hobject),
    /// live -> generation (stash of a deleted object).
    Stash(Hobject, u64),
    SetAttrs(Hobject, Vec<(Vec<u8>, Vec<u8>)>),
    RmAttr(Hobject, Vec<u8>),
    Clone(Hobject, Hobject),
    Rename(Hobject, Hobject),
    /// Client alloc hint, sizes already scaled to the shard.
    AllocHint {
        soid: Hobject,
        oso: u64,
        wso: u64,
        flags: u32,
    },
}

/// Stripe data written to every shard at one run (`bufs[shard]`), with the crc hint of every shard buffer (the msgr2
/// front crc of the sub-write and the store's block crcs reuse the encode's block crcs).
#[derive(Debug, Clone)]
struct Run {
    bufs: Vec<Bytes>,
    hints: Vec<CrcHint>,
}

/// Shard buffers as shared bytes, each with the hint made from its block crcs.
fn share(bufs: Vec<Vec<u8>>, blocks: Vec<BlockCrcs>) -> (Vec<Bytes>, Vec<CrcHint>) {
    bufs.into_iter()
        .zip(blocks)
        .map(|(b, bc)| {
            let b = Bytes::from(b);
            let h = CrcHint::with_blocks(&b, bc.crc(!0), bc.into_blocks().into());
            (b, h)
        })
        .unzip()
}

/// Object state after a planned write (input `OldObj` of the next write while this one is in flight).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Post {
    pub exists: bool,
    pub size: u64,
    pub attrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl From<Post> for OldObj {
    fn from(p: Post) -> OldObj {
        OldObj {
            exists: p.exists,
            size: p.size,
            attrs: p.attrs,
        }
    }
}

/// One object of a planned write: everything that does not depend on old stripe data is already computed
/// (rollback info, hinfo, the encoded append stripes, the resulting state).
#[derive(Debug, Clone)]
struct ObjPlan {
    w: Work,
    /// Shard ops before any data: stash of the old object, create / clone, attribute changes.
    pre: Vec<SOp>,
    /// Stash of the overwritten shard ranges (`touch` + `clone_range`), then the shard truncate.
    stash: Vec<SOp>,
    /// Overwrite stripes (need the old bytes of the part below `b` that no write covers).
    over: Vec<u64>,
    /// Append stripes, encoded, with the block crcs of every shard buffer.
    append: Vec<(u64, Vec<Vec<u8>>, Vec<BlockCrcs>)>,
    /// hinfo_key (and nothing else) set last.
    post_ops: Vec<SOp>,
    md: Option<ObjectModDesc>,
    post: Post,
}

/// Result of planning: what must be read, then [`WritePlan::generate`].
#[derive(Debug, Clone)]
pub struct WritePlan {
    be: Backend,
    pgid: PgT,
    objs: Vec<ObjPlan>,
    /// Stripes that need old data: `(object, stripe)`.
    need: BTreeSet<(Hobject, u64)>,
}

/// Output of [`WritePlan::generate`].
#[derive(Debug)]
pub struct Generated {
    /// v9 transaction per shard (index = shard id).
    pub txns: Vec<Vec<u8>>,
}

/// One shard transaction of [`WritePlan::generate_shared`], payloads shared with the shard buffers (no copy).
#[derive(Debug)]
pub struct SharedTxn {
    /// Wire v9 rope: inline bytes + `(offset, run)` splices (`ecwire::ECSubWrite::txn_data` / `txn_zc`).
    pub inline: Vec<u8>,
    pub zc: Vec<(usize, Bytes)>,
    /// First write payload in the misaligned stream (`replwire::Transaction::payload_at`, `ECSubWrite::txn_payload_at`).
    pub payload_at: Option<usize>,
    /// Local skeleton + out-of-line payloads (`peering::StoreOp::ApplyTxnSplit`).
    pub skel: Bytes,
    pub refs: Vec<Bytes>,
    /// Crc hints (seed `!0` and per-4K block crcs) of the shard buffers `zc` / `refs` view: the msgr2 front crc of the
    /// sub-write and the store reuse the encode's crcs. Empty when unknown.
    pub hints: Vec<CrcHint>,
}

impl Backend {
    /// Reduce a logical transaction (`txn` = the v9 envelope) and list the old stripes it needs.
    /// `olds` has the committed state of every object the transaction names (missing = absent);
    /// `versions` the version `V` of the log entry of each object (objects without an entry get no rollback info).
    /// Errors are positive errno (EOPNOTSUPP for ops the pool mode refuses, nothing was changed).
    pub fn plan_write(
        &self,
        pgid: PgT,
        txn: &[u8],
        olds: &BTreeMap<Hobject, OldObj>,
        versions: &BTreeMap<Hobject, u64>,
    ) -> Result<WritePlan, i32> {
        self.plan_write_inner(pgid, txn, None, olds, versions)
    }

    /// Retain inline payload spans from an already-owned wire transaction instead of copying them.
    /// The plan may outlive the caller's transaction handle.
    pub fn plan_write_shared(
        &self,
        pgid: PgT,
        txn: &Bytes,
        olds: &BTreeMap<Hobject, OldObj>,
        versions: &BTreeMap<Hobject, u64>,
    ) -> Result<WritePlan, i32> {
        self.plan_write_inner(pgid, txn, Some(txn), olds, versions)
    }

    /// [`Self::plan_write_shared`] for the LOCAL skeleton form of a client write (`skel` + out-of-line payloads `refs`,
    /// `replwire::Transaction::decode_split`): the payloads are retained as slices of `refs`, the contiguous v9 blob is
    /// never built.
    pub fn plan_write_split(
        &self,
        pgid: PgT,
        skel: &Bytes,
        refs: &[Bytes],
        olds: &BTreeMap<Hobject, OldObj>,
        versions: &BTreeMap<Hobject, u64>,
    ) -> Result<WritePlan, i32> {
        let t = io(Transaction::decode_split(skel, refs, 4096))?;
        self.plan_write_txn(pgid, &t, refs, olds, versions)
    }

    fn plan_write_inner(
        &self,
        pgid: PgT,
        txn: &[u8],
        owner: Option<&Bytes>,
        olds: &BTreeMap<Hobject, OldObj>,
        versions: &BTreeMap<Hobject, u64>,
    ) -> Result<WritePlan, i32> {
        let t = io(Transaction::decode(&[], txn, 4096))?;
        self.plan_write_txn(
            pgid,
            &t,
            owner.map(core::slice::from_ref).unwrap_or(&[]),
            olds,
            versions,
        )
    }

    /// `owners`: buffers the payload slices of `t` may live in (retained by reference, else copied).
    fn plan_write_txn(
        &self,
        pgid: PgT,
        t: &Transaction<'_>,
        owners: &[Bytes],
        olds: &BTreeMap<Hobject, OldObj>,
        versions: &BTreeMap<Hobject, u64>,
    ) -> Result<WritePlan, i32> {
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
        let (s, ow) = (self.s, self.overwrites);
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
                    w.hint = Some(Hint::merge(
                        w.hint,
                        *expected_object_size,
                        *expected_write_size,
                        *flags,
                    ));
                }
                TxnOp::Create { oid } | TxnOp::Touch { oid } | TxnOp::TouchTemp { oid, .. } => {
                    let w = ws.get(&obj(*oid)?);
                    w.ensure();
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
                    let end = off.saturating_add(*len).min(w.size);
                    if *off < end {
                        if end > MAX_OBJECT_SIZE {
                            return Err(EFBIG);
                        }
                        w.dirty = true;
                        w.reclaim = true;
                        w.overlay.put(*off, vec![0u8; (end - off) as usize].into());
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
                    if *size == 0 && w.old.exists && !w.deleted && w.old.size > 0 {
                        // truncate to 0 of an existing object = move the old one away, create anew, keep attrs
                        // (the classic special case; allowed on append-only pools: WRITEFULL)
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
                        w.overlay.clear();
                        w.attrs = keep;
                        w.dirty = true;
                        continue;
                    }
                    if !ow {
                        // a truncate of a new / already-moved object to 0 is a no-op; anything else is refused
                        if *size == 0 && w.fresh {
                            w.overlay.clear();
                            w.size = 0;
                            continue;
                        }
                        return Err(EOPNOTSUPP);
                    }
                    w.dirty = true;
                    if *size < w.size {
                        w.overlay.cut(*size);
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
                        w.overlay.clear();
                        w.attrs.clear();
                        w.clone_of = None;
                        w.clone_at = usize::MAX;
                        w.hint = None;
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
                    if !sk.is_temp() || sk.pool != Hobject::temp_pool(dk.pool) || sk.hash != dk.hash
                    {
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
                    // the source must be untouched so far: the shards clone their committed file
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
                // omap and everything else: not on EC pools
                _ => return Err(EOPNOTSUPP),
            }
        }
        let Works { order, mut map, .. } = ws;
        let mut works: Vec<Work> = order.iter().map(|k| map.remove(k).unwrap()).collect();
        // a clone copies the committed source file: clones run first, in transaction order (rollback after a new snap:
        // the head is cloned away before a copy of an older clone replaces it), then the other objects
        works.sort_by_key(|w| w.clone_at);
        let mut objs = Vec::with_capacity(works.len());
        let mut need = BTreeSet::new();
        for w in works {
            let ver = versions.get(&w.soid).copied();
            let p = plan_obj(self, w, ver)?;
            for st in &p.over {
                let (lo, hi) = (st * self.s, ((st + 1) * self.s).min(p.w.b));
                if lo < hi && !p.w.overlay.covers(lo, hi) {
                    need.insert((p.w.soid.clone(), *st));
                }
            }
            objs.push(p);
        }
        Ok(WritePlan {
            be: self.clone(),
            pgid,
            objs,
            need,
        })
    }
}

/// Objects of one transaction in order of first mention.
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

/// Stripe sets of one object.
struct Stripes {
    /// All stripes written, ascending.
    write: Vec<u64>,
    /// First append stripe (`ceil(b/S)`).
    append_from: u64,
}

/// Logical old size still on disk (0 once the old object was moved away).
fn n_old(w: &Work) -> u64 {
    if w.old.exists && !w.deleted {
        w.old.size
    } else {
        0
    }
}

fn stripes(be: &Backend, w: &Work) -> Result<Stripes, i32> {
    let s = be.s;
    let n_str = w.size.div_ceil(s);
    let mut set: BTreeSet<u64> = BTreeSet::new();
    for (o, d) in &w.overlay.0 {
        let (a, e) = (*o / s, (*o + d.len() as u64).div_ceil(s));
        set.extend(a..e);
    }
    let append_from = w.b.div_ceil(s);
    let n_old = n_old(w);
    if !w.b.is_multiple_of(s) && w.b < n_old {
        set.insert(w.b / s);
    }
    if n_str > append_from {
        set.extend(append_from..n_str);
    }
    set.retain(|st| *st < n_str);
    Ok(Stripes {
        write: set.into_iter().collect(),
        append_from,
    })
}

/// Compose stripe `x` of the new object: old bytes below `b` (`old` = whole old stripe), then the overlay.
fn compose(be: &Backend, w: &Work, x: u64, old: Option<&[u8]>, buf: &mut [u8]) {
    let s = be.s;
    debug_assert_eq!(buf.len(), s as usize);
    if let Some(ob) = old {
        let (lo, hi) = (x * s, ((x + 1) * s).min(w.b));
        if lo < hi {
            let m = ((hi - lo) as usize).min(ob.len());
            buf[..m].copy_from_slice(&ob[..m]);
        }
    }
    w.overlay.fill(x * s, (x + 1) * s, buf);
}

/// Reduce one object to its shard ops, rollback info, hinfo and resulting state (no old stripe data needed).
fn plan_obj(be: &Backend, w: Work, ver: Option<u64>) -> Result<ObjPlan, i32> {
    let (s, c, n) = (be.s, be.c, be.n());
    if w.size > MAX_OBJECT_SIZE || (w.old.exists && w.old.size > MAX_OBJECT_SIZE) {
        return Err(EFBIG);
    }
    let o = w.soid.clone();
    let mut md = ModDescBuilder::new();
    let mut pre: Vec<SOp> = Vec::new();
    let mut stash: Vec<SOp> = Vec::new();
    let mut post_ops: Vec<SOp> = Vec::new();
    let mut over: Vec<u64> = Vec::new();
    let mut append: Vec<(u64, Vec<Vec<u8>>, Vec<BlockCrcs>)> = Vec::new();
    // 1. the old object is moved away
    if w.deleted {
        match ver {
            Some(v) => {
                md.delete(v);
                pre.push(SOp::Stash(o.clone(), v));
            }
            None => pre.push(SOp::Remove(o.clone())),
        }
    }
    if !w.exists {
        let md = ver.map(|_| md_wrap(md.finish()));
        return Ok(ObjPlan {
            w,
            pre,
            stash,
            over,
            append,
            post_ops,
            md,
            post: Post::default(),
        });
    }
    // 2. init
    if let Some(src) = &w.clone_of {
        pre.push(if w.move_from {
            SOp::Rename(src.clone(), o.clone())
        } else {
            SOp::Clone(src.clone(), o.clone())
        });
        if ver.is_some() {
            md.create();
        }
    } else if w.fresh {
        pre.push(SOp::Create(o.clone()));
        if ver.is_some() && !w.deleted {
            md.create();
        }
    }
    // 3. attributes (+ rollback of the old values; hinfo_key is always part of it)
    let mut rb: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
    let old_hinfo = w.old.attrs.get(HINFO).cloned();
    if !w.fresh {
        rb.push((
            HINFO.to_vec(),
            Some(
                old_hinfo
                    .clone()
                    .unwrap_or_else(|| HashInfo::new(n).encode()),
            ),
        ));
    }
    let mut sets: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (k, v) in &w.attrs {
        if !w.fresh {
            rb.push((k.clone(), w.old.attrs.get(k).cloned()));
        }
        match v {
            Some(v) => sets.push((k.clone(), v.clone())),
            None => pre.push(SOp::RmAttr(o.clone(), k.clone())),
        }
    }
    if !sets.is_empty() {
        pre.push(SOp::SetAttrs(o.clone(), sets));
    }
    if ver.is_some() && !rb.is_empty() {
        md.set_attrs(&rb);
    }
    // alloc hint after the attributes, before the data (advisory, not rolled back)
    if let Some(h) = w.hint {
        let (oso, wso, flags) = h.shard(s, c);
        pre.push(SOp::AllocHint {
            soid: o.clone(),
            oso,
            wso,
            flags,
        });
    }
    // 4. data
    let mut hinfo = if w.clone_of.is_some() {
        // the cloned shard files carry the source hinfo (`old.attrs` = the source attrs)
        match w.old.attrs.get(HINFO) {
            Some(b) => HashInfo::decode(b).map_err(|_| EIO)?,
            None => HashInfo::new(n),
        }
    } else if w.fresh {
        HashInfo::new(n)
    } else {
        match &old_hinfo {
            Some(b) => HashInfo::decode(b).map_err(|_| EIO)?,
            None if w.old.size == 0 => HashInfo::new(n),
            None => return Err(EIO),
        }
    };
    if w.clone_of.is_none() {
        let st = stripes(be, &w)?;
        let n_old = n_old(&w);
        let old_shard = be.shard_size(n_old)?;
        let append_off = st.append_from * c;
        let mut ext: Vec<(u64, u64)> = Vec::new();
        if n_old > 0 {
            for &x in st.write.iter().filter(|x| **x < st.append_from) {
                push_ext(&mut ext, x * c, c);
            }
            if w.b < n_old && old_shard > append_off {
                push_ext(&mut ext, append_off, old_shard - append_off);
            }
        }
        let extents_nonempty = !ext.is_empty();
        if let (true, Some(v)) = (extents_nonempty, ver) {
            stash.push(SOp::TouchGen(o.clone(), v));
            for (off, len) in &ext {
                stash.push(SOp::CloneRange {
                    soid: o.clone(),
                    gen_: v,
                    off: *off,
                    len: *len,
                });
            }
            md.rollback_extents(v, &ext);
        }
        if w.b < n_old {
            stash.push(SOp::Truncate(o.clone(), append_off));
        }
        over = st
            .write
            .iter()
            .copied()
            .filter(|x| *x < st.append_from)
            .collect();
        // append stripes carry no old bytes: compose and encode now, in runs of consecutive stripes
        let app: Vec<u64> = st
            .write
            .iter()
            .copied()
            .filter(|x| *x >= st.append_from)
            .collect();
        let mut i = 0;
        while i < app.len() {
            let mut j = i;
            while j + 1 < app.len() && app[j + 1] == app[j] + 1 {
                j += 1;
            }
            let lo = app[i] * s;
            let hi = (app[j] + 1) * s;
            // shard crcs fused with the encode (hash-info append below needs no pass over the shard buffers)
            let (bufs, crcs) = if let Some(data) = w.overlay.covered_slice(lo, hi) {
                be.encode_stripes_crc(data)
            } else {
                let mut buf = vec![0; (j - i + 1) * s as usize];
                for (&x, dst) in app[i..=j].iter().zip(buf.chunks_mut(s as usize)) {
                    compose(be, &w, x, None, dst);
                }
                be.encode_stripes_crc(&buf)
            };
            append.push((app[i], bufs, crcs));
            i = j + 1;
        }
        let new_shard = be.shard_size(w.size)?;
        // 5. hinfo
        if extents_nonempty || w.b < n_old {
            hinfo.clear_hashes(new_shard);
        } else {
            if !append.is_empty() {
                if hinfo.total_chunk_size != append_off {
                    return Err(EIO);
                }
                for (_, bufs, blocks) in &append {
                    let len = bufs.first().map_or(0, Vec::len) as u64;
                    if bufs.iter().any(|b| b.len() as u64 != len) {
                        return Err(EIO);
                    }
                    let crcs: Vec<u32> = blocks.iter().map(|b| b.crc(0)).collect();
                    hinfo
                        .append_crcs(hinfo.total_chunk_size, len, &crcs)
                        .map_err(|_| EIO)?;
                }
            }
            if hinfo.total_chunk_size != new_shard {
                if w.fresh || hinfo.total_chunk_size == 0 {
                    hinfo.total_chunk_size = new_shard;
                } else {
                    return Err(EIO);
                }
            }
        }
        if ver.is_some() && !app.is_empty() {
            md.append(w.b);
        }
    }
    let hbytes = hinfo.encode();
    post_ops.push(SOp::SetAttrs(
        o.clone(),
        vec![(HINFO.to_vec(), hbytes.clone())],
    ));
    // resulting state
    let mut attrs = if w.clone_of.is_some() || !w.fresh {
        w.old.attrs.clone()
    } else {
        BTreeMap::new()
    };
    for (k, v) in &w.attrs {
        match v {
            Some(v) => {
                attrs.insert(k.clone(), v.clone());
            }
            None => {
                attrs.remove(k);
            }
        }
    }
    attrs.insert(HINFO.to_vec(), hbytes);
    let post = Post {
        exists: true,
        size: w.size,
        attrs,
    };
    let md = ver.map(|_| md_wrap(md.finish()));
    Ok(ObjPlan {
        w,
        pre,
        stash,
        over,
        append,
        post_ops,
        md,
        post,
    })
}

impl WritePlan {
    /// Old stripes the generator needs (read them with `Backend::plan_read` and hand them to `generate`).
    pub fn reads(&self) -> Vec<(Hobject, u64)> {
        self.need.iter().cloned().collect()
    }

    /// Objects the plan touches (for the pipeline's per-object serialization).
    pub fn objects(&self) -> Vec<Hobject> {
        self.objs.iter().map(|p| p.w.soid.clone()).collect()
    }

    /// Resulting state of every object (`exists == false`: removed) - the `OldObj` of the next write to it.
    pub fn post(&self) -> BTreeMap<Hobject, Post> {
        self.objs
            .iter()
            .map(|p| (p.w.soid.clone(), p.post.clone()))
            .collect()
    }

    /// Rollback info per object with a log entry.
    pub fn mod_descs(&self) -> BTreeMap<Hobject, ObjectModDesc> {
        self.objs
            .iter()
            .filter_map(|p| p.md.clone().map(|m| (p.w.soid.clone(), m)))
            .collect()
    }

    /// Produce the shard transactions. `old` = whole old stripes (`S` bytes, zero padded) for every entry of
    /// [`WritePlan::reads`].
    pub fn generate(self, old: &BTreeMap<(Hobject, u64), Vec<u8>>) -> Result<Generated, i32> {
        let txns = self.generate_with(old, |t, _, _| io(t.encode_v9()))?;
        Ok(Generated { txns })
    }

    /// [`generate`](Self::generate) without copying the shard payloads (byte-identical transactions): per shard the
    /// wire rope (`replwire::Transaction::encode_v9_rope`) and the local skeleton (`encode_v9_local`) over the same
    /// shared shard buffers.
    pub fn generate_shared(
        self,
        old: &BTreeMap<(Hobject, u64), Vec<u8>>,
    ) -> Result<Vec<SharedTxn>, i32> {
        self.generate_with(old, |t, owners, hints| {
            let (inline, zc) = io(t.encode_v9_rope(owners))?;
            let (skel, refs) = io(t.encode_v9_local(owners))?;
            Ok(SharedTxn {
                inline,
                zc,
                payload_at: t.payload_at(),
                skel,
                refs,
                hints: hints.to_vec(),
            })
        })
    }

    /// The shard transactions, each handed to `out` with the shard buffers its payloads live in.
    fn generate_with<T>(
        self,
        old: &BTreeMap<(Hobject, u64), Vec<u8>>,
        mut out: impl FnMut(&Transaction<'_>, &[Bytes], &[CrcHint]) -> Result<T, i32>,
    ) -> Result<Vec<T>, i32> {
        let be = &self.be;
        let n = be.n();
        let mut ops: Vec<SOp> = Vec::new();
        let mut runs: Vec<Run> = Vec::new();
        for p in self.objs {
            ops.extend(p.pre);
            ops.extend(p.stash);
            let soid = &p.w.soid;
            // old stripes of this object, ascending: one lookup index per object, no key clone per stripe
            let olds: Vec<(u64, &Vec<u8>)> = old
                .range((soid.clone(), 0)..)
                .take_while(|((h, _), _)| h == soid)
                .map(|((_, x), v)| (*x, v))
                .collect();
            let old_bytes = |x: u64| -> Option<&[u8]> {
                olds.binary_search_by_key(&x, |(xs, _)| *xs)
                    .ok()
                    .map(|i| &olds[i].1[..])
            };
            // overwrite stripes: compose with the old bytes, encode in runs
            let mut i = 0;
            while i < p.over.len() {
                let mut j = i;
                while j + 1 < p.over.len() && p.over[j + 1] == p.over[j] + 1 {
                    j += 1;
                }
                let lo = p.over[i] * be.s;
                let hi = (p.over[j] + 1) * be.s;
                let (bufs, blocks) = if let Some(data) = p.w.overlay.covered_slice(lo, hi) {
                    be.encode_stripes_crc(data)
                } else {
                    let mut buf = vec![0; (j - i + 1) * be.s as usize];
                    for (&x, dst) in p.over[i..=j].iter().zip(buf.chunks_mut(be.s as usize)) {
                        let (lo, hi) = (x * be.s, ((x + 1) * be.s).min(p.w.b));
                        let ob = old_bytes(x);
                        if lo < hi && ob.is_none() && !p.w.overlay.covers(lo, hi) {
                            return Err(EIO); // the plan asked for it, the caller did not deliver
                        }
                        compose(be, &p.w, x, ob, dst);
                    }
                    be.encode_stripes_crc(&buf)
                };
                let (bufs, hints) = share(bufs, blocks);
                let first = p.over[i];
                ops.push(SOp::Write {
                    soid: soid.clone(),
                    off: first * be.c,
                    run: runs.len(),
                    reclaim: p.w.reclaim,
                });
                runs.push(Run { bufs, hints });
                i = j + 1;
            }
            for (first, bufs, blocks) in p.append {
                let (bufs, hints) = share(bufs, blocks);
                ops.push(SOp::Write {
                    soid: soid.clone(),
                    off: first * be.c,
                    run: runs.len(),
                    reclaim: p.w.reclaim,
                });
                runs.push(Run { bufs, hints });
            }
            ops.extend(p.post_ops);
        }
        // build the per-shard transactions
        let mut txns = Vec::with_capacity(n);
        for sh in 0..n as u32 {
            let mut t = Transaction::new();
            let mut hints: Vec<CrcHint> =
                runs.iter().map(|r| r.hints[sh as usize].clone()).collect();
            let cx = t.coll(&CollT::Pg(SpgT {
                pgid: self.pgid,
                shard: ShardId(sh as i8),
            }));
            let gh = |h: &Hobject, g: u64| Ghobject::new(h.clone(), g, ShardId(sh as i8));
            for op in &ops {
                match op {
                    SOp::Create(h) => {
                        let ox = t.obj(&gh(h, LIVE));
                        t.push(cx, TxnOp::Create { oid: ox });
                    }
                    SOp::TouchGen(h, g) => {
                        let ox = t.obj(&gh(h, *g));
                        t.push(cx, TxnOp::Touch { oid: ox });
                    }
                    SOp::Write {
                        soid,
                        off,
                        run,
                        reclaim,
                    } => {
                        let ox = t.obj(&gh(soid, LIVE));
                        let data = &runs[*run].bufs[sh as usize];
                        let first = t.ops.len();
                        crate::shard_write(&mut t, cx, ox, *off, data, *reclaim);
                        if *reclaim {
                            // The emitting run already owns the checksum grid. Bind hints to its nonzero slices
                            // directly; no search over other objects/runs and no extra whole-payload checksum pass.
                            let parent = &runs[*run].hints[sh as usize];
                            let payload = parent.payload().ok_or(EIO)?;
                            for op in &t.ops[first..] {
                                if let TxnOp::Write { data: part, .. } = &op.op {
                                    let slice = part.head;
                                    if parent.of(slice).is_some() {
                                        continue;
                                    }
                                    let from = slice.as_ptr() as usize - data.as_ptr() as usize;
                                    let blocks =
                                        payload.blocks_at(from, slice.len() / 4096).ok_or(EIO)?;
                                    let mut c =
                                        crc::crc32c_blocks(!0, blocks.iter().map(|c| (*c, 0)));
                                    c = crc::crc32c(c, &slice[blocks.len() * 4096..]);
                                    hints.push(CrcHint::with_blocks(
                                        &data.slice(from..from + slice.len()),
                                        c,
                                        blocks.to_vec().into(),
                                    ));
                                }
                            }
                        }
                    }
                    SOp::CloneRange {
                        soid,
                        gen_,
                        off,
                        len,
                    } => {
                        let a = t.obj(&gh(soid, LIVE));
                        let b = t.obj(&gh(soid, *gen_));
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
                    SOp::Truncate(h, size) => {
                        let ox = t.obj(&gh(h, LIVE));
                        t.push(
                            cx,
                            TxnOp::Truncate {
                                oid: ox,
                                size: *size,
                            },
                        );
                    }
                    SOp::Remove(h) => {
                        let ox = t.obj(&gh(h, LIVE));
                        t.push(cx, TxnOp::Remove { oid: ox });
                    }
                    SOp::Stash(h, g) => {
                        let a = t.obj(&gh(h, LIVE));
                        let b = t.obj(&gh(h, *g));
                        t.push(
                            cx,
                            TxnOp::CollMoveRename {
                                oid: a,
                                dest_cid: cx,
                                dest_oid: b,
                            },
                        );
                    }
                    SOp::SetAttrs(h, attrs) => {
                        let ox = t.obj(&gh(h, LIVE));
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
                    SOp::RmAttr(h, name) => {
                        let ox = t.obj(&gh(h, LIVE));
                        t.push(cx, TxnOp::RmAttr { oid: ox, name });
                    }
                    SOp::Rename(a, b) => {
                        let x = t.obj(&gh(a, LIVE));
                        let y = t.obj(&gh(b, LIVE));
                        t.push(
                            cx,
                            TxnOp::TryRename {
                                oid: x,
                                dest_oid: y,
                            },
                        );
                    }
                    SOp::Clone(a, b) => {
                        let x = t.obj(&gh(a, LIVE));
                        let y = t.obj(&gh(b, LIVE));
                        t.push(
                            cx,
                            TxnOp::Clone {
                                oid: x,
                                dest_oid: y,
                            },
                        );
                    }
                    SOp::AllocHint {
                        soid,
                        oso,
                        wso,
                        flags,
                    } => {
                        let ox = t.obj(&gh(soid, LIVE));
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
                }
            }
            let owners: Vec<Bytes> = runs.iter().map(|r| r.bufs[sh as usize].clone()).collect();
            txns.push(out(&t, &owners, &hints)?);
        }
        Ok(txns)
    }
}

fn push_ext(ext: &mut Vec<(u64, u64)>, off: u64, len: u64) {
    if let Some(last) = ext.last_mut()
        && last.0 + last.1 >= off
    {
        let end = (last.0 + last.1).max(off + len);
        last.1 = end - last.0;
        return;
    }
    ext.push((off, len));
}

fn md_wrap((bl, version, completed): (Vec<u8>, u8, bool)) -> ObjectModDesc {
    ObjectModDesc {
        version,
        can_local_rollback: true,
        rollback_info_completed: completed,
        bl,
    }
}

/// `s` lies inside `o` (then `o.slice_ref(s)` is valid).
pub(crate) fn contains(o: &Bytes, s: &[u8]) -> bool {
    let (a, b) = (o.as_ptr() as usize, s.as_ptr() as usize);
    b >= a && b + s.len() <= a + o.len()
}

#[cfg(test)]
mod overlay_tests {
    use super::*;

    #[test]
    fn sparse_overlay_visits_only_nearby_extents() {
        let n = 4096u64;
        let mut overlay = Overlay::default();
        OVERLAY_VISITS.with(|v| v.set(0));
        for i in 0..n {
            overlay.put(i * 8, Bytes::from_static(b"ab"));
        }
        let insertion = OVERLAY_VISITS.with(|v| v.replace(0));
        for i in 0..n {
            assert!(overlay.covers(i * 8, i * 8 + 2));
            let mut dst = [0; 8];
            overlay.fill(i * 8, i * 8 + 8, &mut dst);
            assert_eq!(&dst, b"ab\0\0\0\0\0\0");
        }
        let composition = OVERLAY_VISITS.with(|v| v.replace(0));
        eprintln!("overlay candidates: insert={insertion}, compose={composition}, extents={n}");
        assert!(insertion <= n as usize);
        assert!(composition <= 2 * n as usize);
    }

    #[test]
    fn overlay_cuts_preserve_boundaries_and_later_writes() {
        let mut overlay = Overlay::default();
        let mut model = [0u8; 64];
        for (lo, hi, byte) in [(3, 20, 1), (30, 40, 2), (10, 35, 3), (5, 12, 4)] {
            overlay.put(lo, vec![byte; (hi - lo) as usize].into());
            model[lo as usize..hi as usize].fill(byte);
        }
        for (lo, hi) in [(11, 18), (0, 4), (38, 64)] {
            overlay.cut_range(lo, hi);
            model[lo as usize..hi as usize].fill(0);
        }
        for lo in 0..64 {
            for hi in lo..=64 {
                let mut dst = vec![0; hi - lo];
                overlay.fill(lo as u64, hi as u64, &mut dst);
                assert_eq!(dst, model[lo..hi]);
                assert_eq!(
                    overlay.covers(lo as u64, hi as u64),
                    model[lo..hi].iter().all(|b| *b != 0)
                );
            }
        }
    }
}
