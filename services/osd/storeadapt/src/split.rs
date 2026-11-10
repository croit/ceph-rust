// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG split and merge on the NVMe store (adr 0029, spec split-merge.md 5, 7).
//!
//! Objects keep their onode; a split or merge only re-keys them to the other collection (`MoveRename`, no data
//! copy) when both collections live on the same engine shard, and copies them (data, xattrs, omap) when the
//! shards differ (`(pool + seed) mod S` puts a child on another shard than its parent for small pg_nums).
//!
//! Crash safety without one giant transaction: every step is idempotent and the order makes the durable
//! prefix always redoable from the unchanged parent state (map epoch E-1):
//! 1. children: create the collection, move/copy objects in batches (each batch is one atomic txn);
//! 2. children: write the complete PG state (`_info` ... ) in one txn: from here the child EXISTS;
//! 3. parent: ONE txn with the rewritten log/missing/info/epoch, the new collection bits and (cross-shard only) a
//!    `_splitout` marker naming the children whose objects the parent still holds a copy of;
//! 4. cross-shard: delete the parent's copies (batches), clear the marker. Resumed at mount by
//!    [`StoreAdapter::recover_structural`].
//!
//! A crash before step 3 leaves the parent at E-1: the PG machinery re-advances and repeats the split; a child
//! that exists already keeps its own state, objects already moved are simply not found in the parent again.
//! Merge is the mirror image: move/copy the sources' objects into the target, commit the target's state in one
//! txn, then remove the sources (`_remove` marker, resumed at mount). Collections without PG state that are
//! left over (crash during step 1, parent gone) are removed by [`StoreAdapter::gc_orphans`].

use crate::{StoreAdapter, meta, orphan_write, pg_coll, pgmeta};
use denc::types::{CollT, Ghobject, PgT, SpgT};
use peering::store::{PersistedPg, SplitChild, StoreOp, StoreTxn};
use store::dev::{BlockDev, Clock};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, ObjError, TOp};

/// Objects moved per transaction.
pub const MOVE_BATCH: usize = 256;
/// Bytes copied per transaction when an object has to cross shards.
const COPY_CHUNK: u64 = 4 << 20;
const COPY_OMAP_BATCH: usize = 1024;
/// pgmeta omap key: children (seed, bits) whose objects the parent still has to drop.
pub const SPLITOUT_KEY: &[u8] = b"_splitout";

/// `StoreOp`s that recreate a PG from its persisted state (child of a split).
pub fn state_ops(p: &PersistedPg) -> Vec<StoreOp> {
    let mut v = vec![
        StoreOp::CreatePg,
        StoreOp::LogReplace(Box::new(p.log.clone())),
        StoreOp::MissingClear {
            may_include_deletes: p.missing.may_include_deletes,
        },
    ];
    if !p.missing.missing.is_empty() {
        v.push(StoreOp::Missing(
            p.missing
                .missing
                .iter()
                .map(|(h, it)| (h.clone(), Some(it.clone())))
                .collect(),
        ));
    }
    v.push(StoreOp::PutInfo(Box::new(p.info.clone())));
    v.push(StoreOp::PutPastIntervals(Box::new(
        p.past_intervals.clone(),
    )));
    v.push(StoreOp::PutEpoch(p.epoch));
    v
}

/// Block size for hole detection while copying.
const HOLE_BLOCK: usize = 4096;
static ZEROS: [u8; HOLE_BLOCK] = [0; HOLE_BLOCK];

/// Maximal runs of blocks of `data` (logical offset `base`) that are not all zero.
pub(crate) fn nonzero_runs(data: &[u8], base: u64) -> Vec<(u64, &[u8])> {
    let mut runs: Vec<(u64, &[u8])> = Vec::new();
    let mut start: Option<usize> = None;
    let mut i = 0;
    while i < data.len() {
        let end = (i + HOLE_BLOCK).min(data.len());
        // memcmp against zeros: vectorized, no byte loop
        let zero = data[i..end] == ZEROS[..end - i];
        match (zero, start) {
            (false, None) => start = Some(i),
            (true, Some(s)) => {
                runs.push((base + s as u64, &data[s..i]));
                start = None;
            }
            _ => {}
        }
        i = end;
    }
    if let Some(s) = start {
        runs.push((base + s as u64, &data[s..]));
    }
    runs
}

fn movable(g: &Ghobject) -> bool {
    !g.is_pgmeta() && !g.hobj.is_temp()
}

fn enc_marker(v: &[(u32, u32)]) -> Vec<u8> {
    v.iter()
        .flat_map(|(s, b)| s.to_le_bytes().into_iter().chain(b.to_le_bytes()))
        .collect()
}

fn dec_marker(b: &[u8]) -> Vec<(u32, u32)> {
    b.as_chunks::<8>()
        .0
        .iter()
        .map(|c| {
            (
                u32::from_le_bytes(c[..4].try_into().unwrap()),
                u32::from_le_bytes(c[4..].try_into().unwrap()),
            )
        })
        .collect()
}

impl<D: BlockDev, C: Clock> StoreAdapter<D, C> {
    fn shard_of_pg(&self, s: SpgT) -> usize {
        self.st.borrow().shard_of(&pg_coll(s))
    }

    fn child_spg(parent: SpgT, seed: u32) -> SpgT {
        SpgT {
            pgid: PgT::new(parent.pgid.pool, seed),
            shard: parent.shard,
        }
    }

    /// Does the PG exist completely (collection and `_info`)?
    fn pg_complete(&self, spg: SpgT) -> Result<bool, ObjError> {
        Ok(meta::load(self, spg)?.is_some())
    }

    /// One scan of `cid` (hobject order), handing every movable object to `f` in batches of `MOVE_BATCH`.
    /// `f` may remove or move the objects it gets (the scan continues behind them).
    fn scan_batches(
        &self,
        cid: CollT,
        mut f: impl FnMut(&Self, Vec<Ghobject>) -> Result<(), ObjError>,
    ) -> Result<(), ObjError> {
        let mut batch: Vec<Ghobject> = Vec::new();
        self.list_pages(&cid, 512, |objs| {
            for g in objs {
                if movable(&g) {
                    batch.push(g);
                    if batch.len() >= MOVE_BATCH {
                        f(self, std::mem::take(&mut batch))?;
                    }
                }
            }
            Ok(())
        })?;
        if !batch.is_empty() {
            f(self, batch)?;
        }
        Ok(())
    }

    /// Move `objs` from `from` to `to` (same shard): re-keys the onodes.
    fn move_objects(&self, from: CollT, to: CollT, objs: Vec<Ghobject>) -> Result<(), ObjError> {
        self.sm_moved.set(self.sm_moved.get() + objs.len() as u64);
        let mut t = OTxn::new();
        for g in objs {
            t.push(TOp::MoveRename {
                cid: from,
                oid: g.clone(),
                dcid: to,
                doid: g,
            });
        }
        self.commit(&t)
    }

    /// Copy one object (data, xattrs, omap header + keys) into `to` on another shard. Replaces any partial copy
    /// of an interrupted earlier attempt.
    fn copy_object(&self, from: CollT, to: CollT, g: &Ghobject) -> Result<(), ObjError> {
        let (size, attrs, hdr) = {
            let mut st = self.st.borrow_mut();
            let Some(stat) = st.stat(&from, g)? else {
                return Ok(());
            };
            (stat.size, st.getattrs(&from, g)?, st.omap_header(&from, g)?)
        };
        self.sm_copied.set(self.sm_copied.get() + 1);
        self.sm_copied_bytes.set(self.sm_copied_bytes.get() + size);
        let mut first = OTxn::new();
        first.push(TOp::Remove {
            cid: to,
            oid: g.clone(),
        });
        first.push(TOp::Touch {
            cid: to,
            oid: g.clone(),
        });
        if !attrs.is_empty() {
            first.push(TOp::SetAttrs {
                cid: to,
                oid: g.clone(),
                attrs: attrs
                    .into_iter()
                    .map(|(k, v)| (TxnBytes::Owned(k), TxnBytes::Owned(v)))
                    .collect(),
            });
        }
        if !hdr.is_empty() {
            first.push(TOp::OmapSetHeader {
                cid: to,
                oid: g.clone(),
                header: TxnBytes::Owned(hdr),
            });
        }
        self.commit(&first)?;
        // omap in batches
        self.omap_pages(&from, g, COPY_OMAP_BATCH, |kv| {
            if !kv.is_empty() {
                let mut t = OTxn::new();
                t.push(TOp::OmapSetKeys {
                    cid: to,
                    oid: g.clone(),
                    pairs: kv
                        .into_iter()
                        .map(|(k, v)| (TxnBytes::Owned(k), TxnBytes::Owned(v)))
                        .collect(),
                });
                self.commit(&t)?;
            }
            Ok(())
        })?;
        // data in chunks; all-zero blocks stay holes (a sparse object must not become allocated zeros) and the
        // size is fixed with a truncate, so holes at the end survive too
        let mut off = 0u64;
        while off < size {
            let len = COPY_CHUNK.min(size - off);
            let data = self.read_copy(&from, g, off, len)?;
            let end = off + data.len() as u64;
            let mut t = OTxn::new();
            let runs = nonzero_runs(&data, off);
            let ends_at_size = runs
                .last()
                .is_some_and(|(o, r)| *o + r.len() as u64 == size);
            for (o, run) in runs {
                t.push(TOp::Write {
                    cid: to,
                    oid: g.clone(),
                    off: o,
                    data: TxnBytes::Borrowed(run),
                });
            }
            if end == size && !ends_at_size {
                // trailing hole: only the size is left to set, in the last chunk's transaction
                t.push(TOp::Truncate {
                    cid: to,
                    oid: g.clone(),
                    size,
                });
            }
            if !t.is_empty() {
                self.commit(&t)?;
            }
            off = end;
        }
        Ok(())
    }

    /// Bring the objects of `from` that `pick` selects into `to`: moved on the same shard, copied across shards.
    fn transfer(
        &self,
        from: SpgT,
        to: SpgT,
        pick: impl Fn(&Ghobject) -> bool,
    ) -> Result<(), ObjError> {
        let (fc, tc) = (pg_coll(from), pg_coll(to));
        let same = self.shard_of_pg(from) == self.shard_of_pg(to);
        self.scan_batches(fc, |ad, batch| {
            let objs: Vec<Ghobject> = batch.into_iter().filter(|g| pick(g)).collect();
            if objs.is_empty() {
                return Ok(());
            }
            if same {
                ad.move_objects(fc, tc, objs)
            } else {
                objs.iter().try_for_each(|g| ad.copy_object(fc, tc, g))
            }
        })
    }

    // ---- split -------------------------------------------------------------------------------------------

    /// Steps 1-2 for every child that does not exist yet; returns the children whose objects the parent still
    /// holds copies of (different shard).
    fn split_children(
        &self,
        parent: SpgT,
        children: &[SplitChild],
    ) -> Result<Vec<(u32, u32)>, ObjError> {
        let mut deferred = Vec::new();
        let mut todo: Vec<&SplitChild> = Vec::new();
        for c in children {
            if self.shard_of_pg(c.spg) != self.shard_of_pg(parent) {
                deferred.push((c.spg.pgid.seed, c.bits));
            }
            if self.pg_complete(c.spg)? {
                continue; // redo after a crash: the child keeps its state and its objects
            }
            let mut t = OTxn::new();
            t.push(TOp::MkColl {
                cid: pg_coll(c.spg),
                bits: c.bits,
                exist_ok: true,
            });
            self.commit(&t)?;
            todo.push(c);
        }
        let pc = pg_coll(parent);
        // one scan of the parent for all new children; batches per child
        let mut pend: Vec<Vec<Ghobject>> = vec![Vec::new(); todo.len()];
        self.list_pages(&pc, 512, |objs| {
            for g in objs {
                if !movable(&g) {
                    continue;
                }
                let h = g.hobj.hash;
                if let Some(i) = todo
                    .iter()
                    .position(|c| h & pgwire::pgmath::bits_mask(c.bits) == c.spg.pgid.seed)
                {
                    pend[i].push(g);
                    if pend[i].len() >= MOVE_BATCH {
                        self.flush_child(parent, todo[i].spg, std::mem::take(&mut pend[i]))?;
                    }
                }
            }
            Ok(())
        })?;
        for (i, objs) in pend.into_iter().enumerate() {
            if !objs.is_empty() {
                self.flush_child(parent, todo[i].spg, objs)?;
            }
        }
        // SnapMapper entries follow their clones (idempotent; a cross-shard parent drops its copies at step 4)
        // keys naming no clone hash stay in the parent in every pass: noted once per split
        let mut unplaced = None;
        for c in &todo {
            let same = self.shard_of_pg(c.spg) == self.shard_of_pg(parent);
            let (mask, seed) = (pgwire::pgmath::bits_mask(c.bits), c.spg.pgid.seed);
            let kept = self.map_move(
                parent,
                Some(c.spg),
                &|h| h.is_some_and(|h| h & mask == seed),
                same,
            )?;
            unplaced = unplaced.or(kept);
        }
        if let Some((n, k)) = unplaced {
            self.note_damage(format!(
                "pg {parent}: {n} snap mapper keys unparseable, left in place (first {k:02x?})"
            ));
        }
        // step 2: the child exists from here on
        for c in todo {
            let txn = StoreTxn {
                ops: state_ops(&c.state),
            };
            let mut t = OTxn::new();
            let mut store = self.st.borrow_mut();
            let mut tr = meta::Translator::new(&mut store, c.spg, false);
            for op in &txn.ops {
                tr.op(op, &mut t)?;
            }
            drop(tr);
            drop(store);
            self.commit(&t)?;
        }
        Ok(deferred)
    }

    fn flush_child(&self, parent: SpgT, child: SpgT, objs: Vec<Ghobject>) -> Result<(), ObjError> {
        let (pc, cc) = (pg_coll(parent), pg_coll(child));
        if self.shard_of_pg(parent) == self.shard_of_pg(child) {
            self.move_objects(pc, cc, objs)
        } else {
            objs.iter().try_for_each(|g| self.copy_object(pc, cc, g))
        }
    }

    /// Step 4: drop the parent's copies of objects that live in a child on another shard, clear the marker.
    pub fn finish_split_out(&self, parent: SpgT) -> Result<bool, ObjError> {
        let pc = pg_coll(parent);
        let marker = match self
            .st
            .borrow_mut()
            .omap_get(&pc, &pgmeta(parent), &[SPLITOUT_KEY])
        {
            Ok(mut m) => m.remove(SPLITOUT_KEY),
            Err(ObjError::NoEnt) => None,
            Err(e) => return Err(e),
        };
        let Some(marker) = marker else {
            return Ok(false);
        };
        let kids = dec_marker(&marker);
        self.map_move(
            parent,
            None,
            &|h| {
                h.is_some_and(|h| {
                    kids.iter()
                        .any(|(seed, bits)| h & pgwire::pgmath::bits_mask(*bits) == *seed)
                })
            },
            true,
        )?; // keys without a hash were noted by the split itself
        self.scan_batches(pc, |ad, batch| {
            let mut t = OTxn::new();
            for g in batch {
                let h = g.hobj.hash;
                if kids
                    .iter()
                    .any(|(seed, bits)| h & pgwire::pgmath::bits_mask(*bits) == *seed)
                {
                    t.push(TOp::Remove { cid: pc, oid: g });
                }
            }
            if t.is_empty() { Ok(()) } else { ad.commit(&t) }
        })?;
        let mut t = OTxn::new();
        t.push(TOp::OmapRmKeys {
            cid: pc,
            oid: pgmeta(parent),
            keys: vec![TxnBytes::Borrowed(SPLITOUT_KEY)],
        });
        self.commit(&t)?;
        Ok(true)
    }

    // ---- merge -------------------------------------------------------------------------------------------

    /// Step 1 of a merge: every object of each existing source into the target. Returns the sources to remove.
    fn merge_sources(&self, target: SpgT, sources: &[SpgT]) -> Result<Vec<SpgT>, ObjError> {
        let mut present = Vec::new();
        for &s in sources {
            let c = pg_coll(s);
            // a source whose collection lives on a store shard of another core is not here (never held, or stranded
            // there waiting for room to move, adr 0031 am. 4): the target merges without it, like an absent one
            let mut st = self.st.borrow_mut();
            if s == target || !st.has_shard(st.shard_of(&c)) || !st.coll_exists(&c)? {
                continue;
            }
            drop(st);
            self.transfer(s, target, |_| true)?;
            self.map_move(s, Some(target), &|_| true, false)?; // picks every key: nothing is kept
            present.push(s);
        }
        Ok(present)
    }

    // ---- driver ------------------------------------------------------------------------------------------

    /// Apply a transaction that contains a `SplitOut` or `MergeIn` (executed first): blocks until everything is
    /// durable. `Err` leaves the PG redoable (see the module doc).
    pub(crate) fn submit_structural(&self, spg: SpgT, txn: &StoreTxn) -> Result<(), ObjError> {
        let t0 = std::time::Instant::now();
        let (m0, c0, b0) = (
            self.sm_moved.get(),
            self.sm_copied.get(),
            self.sm_copied_bytes.get(),
        );
        let r = self.submit_structural_inner(spg, txn);
        let ms = t0.elapsed().as_millis();
        if ms >= 200 || self.sm_copied.get() > c0 {
            self.notes.borrow_mut().push(format!(
                "pg {spg}: {} took {ms} ms (moved {} objects, copied {} objects / {} bytes){}",
                if txn
                    .ops
                    .iter()
                    .any(|o| matches!(o, StoreOp::SplitOut { .. }))
                {
                    "split"
                } else {
                    "merge"
                },
                self.sm_moved.get() - m0,
                self.sm_copied.get() - c0,
                self.sm_copied_bytes.get() - b0,
                if r.is_err() { " FAILED" } else { "" }
            ));
        }
        r
    }

    fn submit_structural_inner(&self, spg: SpgT, txn: &StoreTxn) -> Result<(), ObjError> {
        let mut split: Option<(u32, &[SplitChild])> = None;
        let mut merge: Option<(&[SpgT], u32)> = None;
        let mut rest: Vec<&StoreOp> = Vec::new();
        for op in &txn.ops {
            match op {
                StoreOp::SplitOut {
                    parent_bits,
                    children,
                } => split = Some((*parent_bits, children)),
                StoreOp::MergeIn { sources, bits } => merge = Some((sources, *bits)),
                o => rest.push(o),
            }
        }
        let pc = pg_coll(spg);
        if !self.st.borrow_mut().coll_exists(&pc)? {
            return Err(orphan_write(&self.orphan_writes));
        }
        let mut deferred = Vec::new();
        let mut to_remove = Vec::new();
        let mut bits = None;
        if let Some((pb, kids)) = split {
            deferred = self.split_children(spg, kids)?;
            bits = Some(pb);
        }
        if let Some((srcs, b)) = merge {
            to_remove = self.merge_sources(spg, srcs)?;
            bits = Some(b);
        }
        // the parent / target commit: one atomic txn
        let mut t = OTxn::new();
        let mut store = self.st.borrow_mut();
        let mut tr = meta::Translator::new(&mut store, spg, true);
        for op in rest {
            tr.op(op, &mut t)?;
        }
        if let Some(b) = bits {
            t.push(TOp::SetCollBits { cid: pc, bits: b });
        }
        if !deferred.is_empty() {
            t.push(TOp::OmapSetKeys {
                cid: pc,
                oid: pgmeta(spg),
                pairs: vec![(
                    TxnBytes::Borrowed(SPLITOUT_KEY),
                    TxnBytes::Owned(enc_marker(&deferred)),
                )],
            });
        }
        drop(tr);
        drop(store);
        self.commit(&t)?;
        // after the commit
        if !deferred.is_empty() {
            self.finish_split_out(spg)?;
        }
        for s in to_remove {
            self.remove_pg(s)?;
        }
        Ok(())
    }

    // ---- recovery at mount -------------------------------------------------------------------------------

    /// Finish what a crash interrupted after the parent/target commit: cross-shard copies still to be dropped.
    pub fn recover_structural(&self) -> Result<usize, ObjError> {
        let colls = self.st.borrow_mut().list_colls()?;
        let mut n = 0;
        for c in colls {
            if let CollT::Pg(s) = c
                && self.finish_split_out(s)?
            {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Remove PG collections that have no PG state (crash while a split was moving objects and the parent is not
    /// coming back, deleted pool). Skipped while a possible parent (same pool, ancestor seed) is in the store: its
    /// redo would complete the child. Call after the PGs were loaded and advanced.
    pub fn gc_orphans(&self) -> Result<usize, ObjError> {
        let colls = self.st.borrow_mut().list_colls()?;
        let all: Vec<SpgT> = colls
            .iter()
            .filter_map(|c| match c {
                CollT::Pg(s) => Some(*s),
                _ => None,
            })
            .collect();
        let mut n = 0;
        for s in &all {
            if self.pg_complete(*s)? || self.is_removing(*s)? {
                continue;
            }
            let mut anc = s.pgid.seed;
            let mut has_parent = false;
            while anc > 0 {
                anc = pgwire::pgmath::parent(anc);
                let p = Self::child_spg(*s, anc);
                if all.contains(&p) && self.pg_complete(p)? {
                    has_parent = true;
                    break;
                }
            }
            if has_parent {
                continue;
            }
            self.remove_pg(*s)?;
            n += 1;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonzero_runs_skip_holes() {
        let mut d = vec![0u8; 5 * HOLE_BLOCK + 10];
        d[HOLE_BLOCK] = 1; // block 1
        d[2 * HOLE_BLOCK + 5] = 2; // block 2 (adjacent: one run)
        d[5 * HOLE_BLOCK + 3] = 3; // tail block
        let r = nonzero_runs(&d, 100);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].0, 100 + HOLE_BLOCK as u64);
        assert_eq!(r[0].1.len(), 2 * HOLE_BLOCK);
        assert_eq!(r[1].0, 100 + 5 * HOLE_BLOCK as u64);
        assert_eq!(r[1].1.len(), 10);
        assert!(nonzero_runs(&[0u8; 9000], 0).is_empty());
    }
}
