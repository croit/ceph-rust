// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Moving a whole PG collection between two stores (cores) of one OSD (adr 0031): the source side walks the
//! collection and produces [`MigOp`]s, the destination applies them. Nothing here talks to another thread; the OSD
//! moves the ops over its mesh with a credit window.
//!
//! Crash safety: the destination collection is incomplete until the pgmeta object carries `_mig_done` (pgmeta is the
//! LAST object copied, `_mig_in` generation first; `_mig_done` is the last op of the last batch, and a batch is one
//! atomic txn). `meta::load` treats a collection with `_mig_in` but without `_mig_done` as absent (keys sorting
//! behind `_info` may still be missing), so it is garbage (`gc_orphans`). The source
//! copy is deleted only after the destination acknowledged the complete copy. A crash in between leaves two complete
//! copies; the one with the higher `_mig_in` generation wins ([`StoreAdapter::mig_gen`]).

use crate::{StoreAdapter, key_after, pg_coll, pgmeta};
use denc::types::{Ghobject, PgT, SpgT};
pub use peering::store::{ExportCursor, MigOp, ObjPos, Phase};
use store::dev::{BlockDev, Clock};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, ObjError, TOp};

/// pgmeta omap key: how many times the PG was migrated into this shard (generation).
pub const MIG_KEY: &[u8] = b"_mig_in";
/// pgmeta omap key: written by the last op of the last batch; a migrated copy without it is incomplete.
pub const MIG_DONE_KEY: &[u8] = b"_mig_done";
const CHUNK: u64 = 1 << 20;
const OMAP_BATCH: usize = 512;

impl<D: BlockDev, C: Clock> StoreAdapter<D, C> {
    /// Migration generation of PG `spg` in this store (0 = never migrated here).
    pub fn mig_gen(&self, spg: SpgT) -> u64 {
        let (c, g) = (pg_coll(spg), pgmeta(spg));
        match self.st.borrow_mut().omap_get(&c, &g, &[MIG_KEY]) {
            Ok(mut m) => m
                .remove(MIG_KEY)
                .and_then(|v| v.try_into().ok())
                .map_or(0, u64::from_le_bytes),
            Err(_) => 0,
        }
    }

    /// Migration headroom of a copy of `spg` (adr 0031 am. 4, 5), read from the collection itself: data rounded
    /// up to whole blocks per object plus one metadata block per object, and the EXACT omap bytes of every object
    /// (pgmeta with the PG log included) twice (keys + tree pages), summed by a key-cursor scan of every object (omap is
    /// not counted, adr 0610; the copy reads the same bytes again). Never PG statistics (scrub-updated, may be stale).
    pub fn mig_bytes(&self, spg: SpgT) -> Result<u64, ObjError> {
        let blk = store::BLK as u64;
        let c = pg_coll(spg);
        let stats = self.st.borrow_mut().coll_stats(&c)?;
        let (nobj, nbytes) = stats.map_or((0, 0), |s| (s.nobj, s.nbytes));
        let mut omap = 0u64;
        self.list_pages(&c, 256, |objs| {
            for o in &objs {
                self.omap_pages(&c, o, OMAP_BATCH, |kv| {
                    omap += kv
                        .iter()
                        .map(|(k, v)| (k.len() + v.len()) as u64)
                        .sum::<u64>();
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        // pgmeta + SnapMapper object travel too
        Ok(nbytes + (nobj + 2) * 2 * blk + 2 * omap)
    }

    /// Batch share of the headroom (same rule as [`Self::mig_bytes`]).
    fn batch_bytes(ops: &[MigOp]) -> u64 {
        let blk = store::BLK as u64;
        ops.iter()
            .map(|op| match op {
                MigOp::Data { data, .. } => (data.len() as u64).div_ceil(blk) * blk,
                MigOp::Obj { .. } => 2 * blk,
                MigOp::Omap { kv, .. } => {
                    (2 * kv
                        .iter()
                        .map(|(k, v)| (k.len() + v.len()) as u64)
                        .sum::<u64>())
                    .div_ceil(blk)
                        * blk
                }
                MigOp::Coll { .. } | MigOp::Size { .. } => 0,
            })
            .sum()
    }

    /// Reserve `bytes` of headroom on device shard `shard` for PG `pgid` moving in. False = no room now: nothing held.
    pub fn mig_reserve(&self, pgid: PgT, shard: u32, bytes: u64) -> bool {
        // whole blocks, like the batch shares taken out of it (no rounding drift between PGs of one shard)
        let bytes = bytes.div_ceil(store::BLK as u64) * store::BLK as u64;
        if !self.st.borrow_mut().mig_hold(shard, bytes) {
            return false;
        }
        let mut h = self.mig_holds.borrow_mut();
        let e = h.entry(pgid).or_insert((shard, 0));
        e.1 += bytes;
        true
    }

    /// The moves into this store ended: give back every headroom left.
    pub fn mig_release_all(&self) {
        let holds = std::mem::take(&mut *self.mig_holds.borrow_mut());
        let mut st = self.st.borrow_mut();
        for (shard, left) in holds.into_values() {
            st.mig_unhold(shard, left);
        }
    }

    /// Does the PG exist completely (collection with `_info`, and for a migrated copy `_mig_done`)?
    pub fn pg_is_complete(&self, spg: SpgT) -> bool {
        crate::meta::load(self, spg).is_ok_and(|p| p.is_some())
    }

    /// Next ops of the export of `spg`, about `budget` bytes of work (read data, metadata payload and op storage);
    /// holes consume read work even though they emit no payload. `true` = that was the last batch. The caller
    /// must have made the PG quiet (nothing in flight) and durable first.
    pub fn export_chunk(
        &self,
        spg: SpgT,
        cur: &mut ExportCursor,
        budget: usize,
    ) -> Result<(Vec<MigOp>, bool), ObjError> {
        self.drain_fifo()?;
        let c = pg_coll(spg);
        let pm = pgmeta(spg);
        let mut ops = Vec::new();
        let mut bytes = 0usize;
        loop {
            if bytes >= budget {
                return Ok((ops, false));
            }
            match cur.phase {
                Phase::Start => {
                    let bits = self.st.borrow_mut().coll_stats(&c)?.map_or(0, |s| s.bits);
                    cur.generation = self.mig_gen(spg) + 1;
                    ops.push(MigOp::Coll { bits });
                    cur.phase = Phase::Objects;
                }
                Phase::Objects => {
                    if cur.cur.is_none() {
                        if cur.queue.is_empty() && !cur.listed_all {
                            let (objs, next) =
                                self.st.borrow_mut().list(&c, &cur.list, None, 128)?;
                            cur.queue.extend(
                                objs.into_iter()
                                    .filter(|g| !g.is_pgmeta() && !g.hobj.is_temp()),
                            );
                            match next {
                                Some(n) => cur.list = n,
                                None => {
                                    cur.listed_all = true;
                                    // the SnapMapper object travels like a user object, before pgmeta
                                    let mo = crate::snapmap::mapper_obj(spg);
                                    if self.st.borrow_mut().stat(&c, &mo)?.is_some() {
                                        cur.queue.push_back(mo);
                                    }
                                }
                            }
                        }
                        match cur.queue.pop_front() {
                            Some(oid) => cur.cur = Some(self.obj_pos(&c, oid)?),
                            None if cur.listed_all => cur.phase = Phase::Meta,
                            None => {}
                        }
                        continue;
                    }
                    bytes += self.export_obj(&c, cur, spg, &mut ops, budget - bytes)?;
                }
                Phase::Meta => {
                    if cur.cur.is_none() {
                        cur.cur = Some(self.obj_pos(&c, pm.clone())?);
                    }
                    bytes += self.export_obj(&c, cur, spg, &mut ops, budget - bytes)?;
                    if cur.cur.is_none() {
                        cur.phase = Phase::Done;
                    }
                }
                Phase::Done => {
                    ops.push(MigOp::Omap {
                        oid: pm.clone(),
                        kv: vec![(MIG_DONE_KEY.to_vec(), vec![1])],
                    });
                    return Ok((ops, true));
                }
            }
        }
    }

    fn obj_pos(&self, c: &denc::types::CollT, oid: Ghobject) -> Result<ObjPos, ObjError> {
        let size = self.st.borrow_mut().stat(c, &oid)?.map_or(0, |s| s.size);
        Ok(ObjPos {
            oid,
            size,
            off: 0,
            omap_from: Some(Vec::new()),
            omap_done: false,
            started: false,
        })
    }

    /// Emit (part of) the current object; clears `cur.cur` when it is complete. Returns work bytes consumed,
    /// including examined zeros and op storage so sparse and empty objects cannot bypass the slice budget.
    fn export_obj(
        &self,
        c: &denc::types::CollT,
        cur: &mut ExportCursor,
        spg: SpgT,
        ops: &mut Vec<MigOp>,
        budget: usize,
    ) -> Result<usize, ObjError> {
        let Some(p) = cur.cur.as_mut() else {
            return Ok(0);
        };
        let is_meta = p.oid == pgmeta(spg);
        let mut emitted = 0usize;
        if !p.started {
            let (attrs, hdr) = {
                let mut st = self.st.borrow_mut();
                (st.getattrs(c, &p.oid)?, st.omap_header(c, &p.oid)?)
            };
            let op = MigOp::Obj {
                oid: p.oid.clone(),
                attrs: attrs.into_iter().collect(),
                hdr,
            };
            emitted += op.bytes() + std::mem::size_of::<MigOp>();
            ops.push(op);
            if is_meta {
                // generation first; the completion marker `_mig_done` follows the last batch
                ops.push(MigOp::Omap {
                    oid: p.oid.clone(),
                    kv: vec![(MIG_KEY.to_vec(), cur.generation.to_le_bytes().to_vec())],
                });
            }
            p.started = true;
        }
        while !p.omap_done && emitted < budget.max(1) {
            let from = p.omap_from.clone().unwrap_or_default();
            let (kv, more) = self
                .st
                .borrow_mut()
                .omap_iter(c, &p.oid, &from, OMAP_BATCH)?;
            let last = kv.last().map(|(k, _)| k.clone());
            let kv: Vec<(Vec<u8>, Vec<u8>)> = kv
                .into_iter()
                .filter(|(k, _)| !(is_meta && (k == MIG_KEY || k == MIG_DONE_KEY)))
                .collect();
            if !kv.is_empty() {
                let op = MigOp::Omap {
                    oid: p.oid.clone(),
                    kv,
                };
                emitted += op.bytes() + std::mem::size_of::<MigOp>();
                ops.push(op);
            }
            match (more, last) {
                (true, Some(k)) => p.omap_from = Some(key_after(k)),
                _ => p.omap_done = true,
            }
        }
        if !p.omap_done {
            return Ok(emitted);
        }
        while p.off < p.size && emitted < budget.max(1) {
            let len = CHUNK
                .min(p.size - p.off)
                .min((budget.max(1) - emitted) as u64);
            let data = self.read_copy(c, &p.oid, p.off, len)?;
            emitted += data.len();
            for (o, run) in crate::split::nonzero_runs(&data, p.off) {
                ops.push(MigOp::Data {
                    oid: p.oid.clone(),
                    off: o,
                    data: run.to_vec(),
                });
            }
            p.off += data.len() as u64;
        }
        if p.off >= p.size {
            ops.push(MigOp::Size {
                oid: p.oid.clone(),
                size: p.size,
            });
            cur.cur = None;
        }
        Ok(emitted)
    }

    /// Apply a batch of [`MigOp`]s to this store (the PG must have been `place`d here before) as ONE atomic txn.
    /// Blocks until durable. System class, and the batch first takes its share out of the headroom reserved for the PG
    /// (adr 0031 am. 4: nothing else could use that space, so the copy fits); the WAL cost is per batch, not per op.
    pub fn import_ops(&self, spg: SpgT, ops: Vec<MigOp>) -> Result<(), ObjError> {
        #[cfg(feature = "test-knobs")]
        match self.import_nospace_after.get() {
            Some(0) => {
                self.import_nospace_after.set(None);
                return Err(ObjError::NoSpace);
            }
            Some(k) => self.import_nospace_after.set(Some(k - 1)),
            None => {}
        }
        self.drain_fifo()?;
        self.finish_removal(spg)?; // a PG migrated back in while its old copy is still being deleted here
        // a new copy starts (`Coll` is the first op of an export): a collection here that is not a complete PG is the
        // leftover of an interrupted copy (before its pgmeta, `gc_orphans` cannot tell it from a split child); importing
        // over it would keep its objects deleted at the source since
        if ops.iter().any(|o| matches!(o, MigOp::Coll { .. }))
            && self.st.borrow_mut().coll_exists(&pg_coll(spg))?
            && crate::meta::load(self, spg)?.is_none()
        {
            self.remove_pg(spg)?;
        }
        if let Some(e) = self.mig_holds.borrow_mut().get_mut(&spg.pgid) {
            let take = Self::batch_bytes(&ops).min(e.1);
            e.1 -= take;
            self.st.borrow_mut().mig_unhold(e.0, take);
        }
        let c = pg_coll(spg);
        let mut t = OTxn::new();
        t.sys = true;
        for op in ops {
            match op {
                MigOp::Coll { bits } => {
                    t.push(TOp::MkColl {
                        cid: c,
                        bits,
                        exist_ok: true,
                    });
                }
                MigOp::Obj { oid, attrs, hdr } => {
                    t.push(TOp::Remove {
                        cid: c,
                        oid: oid.clone(),
                    });
                    t.push(TOp::Touch {
                        cid: c,
                        oid: oid.clone(),
                    });
                    if !attrs.is_empty() {
                        t.push(TOp::SetAttrs {
                            cid: c,
                            oid: oid.clone(),
                            attrs: attrs
                                .into_iter()
                                .map(|(k, v)| (TxnBytes::Owned(k), TxnBytes::Owned(v)))
                                .collect(),
                        });
                    }
                    if !hdr.is_empty() {
                        t.push(TOp::OmapSetHeader {
                            cid: c,
                            oid,
                            header: TxnBytes::Owned(hdr),
                        });
                    }
                }
                MigOp::Omap { oid, kv } => {
                    t.push(TOp::OmapSetKeys {
                        cid: c,
                        oid,
                        pairs: kv
                            .into_iter()
                            .map(|(k, v)| (TxnBytes::Owned(k), TxnBytes::Owned(v)))
                            .collect(),
                    });
                }
                MigOp::Data { oid, off, data } => {
                    t.push(TOp::Write {
                        cid: c,
                        oid,
                        off,
                        data: TxnBytes::Owned(data),
                    });
                }
                MigOp::Size { oid, size } => {
                    t.push(TOp::Truncate { cid: c, oid, size });
                }
            }
        }
        if t.is_empty() {
            return Ok(());
        }
        self.commit(&t)
    }
}
