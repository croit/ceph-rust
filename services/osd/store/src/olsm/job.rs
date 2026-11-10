// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Flush and merge jobs (adr 0610 (2), (3)). Pure functions over immutable inputs (a frozen [`Memtable`], resident
//! [`RunMeta`]s), a [`ChunkRead`] for input chunks and a [`BlockSink`] of owner-leased extents: no store handle, so
//! a helper core can run them. The owner installs the result with one record-only manifest txn.
//!
//! Memory: a flush stages one chunk; a merge holds at most one decoded chunk per input plus one output chunk.
//!
//! A merge writes one run per target partition it touches and cuts new partitions in gaps (adr 0610 am. 3, see
//! [`super::manifest`]); input range tombstones are clipped to each output run's partition.

use super::manifest::{MergePick, tier};
use super::run::{Chunk, RunBuilder, load_chunk};
use super::{
    BlockSink, ChunkRead, Gk, Memtable, Place, RangeT, RunMeta, below, cmp_gk, ranges_find,
    ranges_from, ranges_touch,
};
use crate::StoreError;
use bytes::Bytes;
use std::cmp::Ordering;
use std::ops::Bound;
use std::sync::Arc;

/// Write the frozen memtable as one run. `Ok(None)` for an empty memtable.
#[cfg(any(test, feature = "lab"))]
pub fn flush(
    mem: &Memtable,
    run_id: u64,
    sink: &mut impl BlockSink,
) -> Result<Option<(RunMeta, u64)>, StoreError> {
    if mem.is_empty() {
        return Ok(None);
    }
    let mut j = FlushJob::new(mem, run_id);
    loop {
        if let Some(r) = j.step(mem, sink, usize::MAX)? {
            return Ok(Some(r));
        }
    }
}

/// A flush in bounded slices (owner inline, adr 0610 phase 2): a cursor over the frozen memtable in `(id, key)`
/// order. A step that fails (allocation refused) leaves the cursor at the entry it could not push: the next step
/// retries it.
#[derive(Debug)]
pub struct FlushJob {
    ids: Vec<u64>,
    /// Next object (index into `ids`) and the last key pushed of it.
    oi: usize,
    after: Option<Bytes>,
    b: RunBuilder,
    run_id: u64,
    lsn: (u64, u64),
}

impl FlushJob {
    /// `mem` must stay unchanged (frozen) for the job's life and be passed to every step.
    pub fn new(mem: &Memtable, run_id: u64) -> FlushJob {
        FlushJob {
            ids: mem.sorted_ids(),
            oi: 0,
            after: None,
            b: RunBuilder::new(),
            run_id,
            lsn: (mem.lsn_lo(), mem.lsn_hi()),
        }
    }

    /// Push entries until `chunks` chunks were sealed in this step or the memtable is done; then the run is finished
    /// (meta written) and returned with the blocks written.
    pub fn step(
        &mut self,
        mem: &Memtable,
        sink: &mut impl BlockSink,
        chunks: usize,
    ) -> Result<Option<(RunMeta, u64)>, StoreError> {
        let c0 = self.b.chunks();
        while self.oi < self.ids.len() {
            let id = self.ids[self.oi];
            let o = mem.obj(id).expect("id from sorted_ids");
            let lo = match &self.after {
                Some(a) => Bound::Excluded(&a[..]),
                None => Bound::Unbounded,
            };
            for (k, v) in o.map.range::<[u8], _>((lo, Bound::Unbounded)) {
                if self.b.chunks() - c0 >= chunks {
                    return Ok(None);
                }
                self.b.push(sink, id, &k.key, v.as_deref())?;
                self.after = Some(k.key.clone());
            }
            for r in &o.ranges {
                self.b.add_range(r.clone());
            }
            self.oi += 1;
            self.after = None;
        }
        self.b
            .finish(sink, self.run_id, self.lsn.0, self.lsn.1)
            .map(Some)
    }
}

/// What a merge does with one input chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Into the output by reference (no read, no write).
    Move,
    /// Fully covered by a newer input's range tombstone: freed without a read.
    Drop,
    /// Read, merged entry by entry.
    Rewrite,
}

/// Result of a merge.
#[derive(Debug, Default)]
pub struct MergeOut {
    /// Output runs with their places (none: every input entry and range vanished).
    pub runs: Vec<RunMeta>,
    /// Unconsumed suffixes of a GC prefix, keeping their original run ids and LSN bounds.
    /// Installed atomically with `runs`; their chunks remain allocated.
    pub residuals: Vec<RunMeta>,
    /// A GC stopped before this key after consuming its work budget. `None` = complete merge.
    pub prefix_end: Option<Gk>,
    /// Blocks written (chunks + metas).
    pub written_blocks: u64,
    /// Input extents to free once the output is installed and no reader references the inputs.
    pub freed: Vec<(u64, u32)>,
    pub moved: usize,
    pub dropped: usize,
    pub rewritten: usize,
}

/// Plan every chunk of `inputs` (newest first). `bottom`: no older data than the inputs in their range. `bounds`:
/// fixed partition boundaries of the output inside the merged range (a chunk straddling one is rewritten).
pub fn plan(inputs: &[Arc<RunMeta>], bottom: bool, bounds: &[Gk]) -> Vec<Vec<Plan>> {
    plan_for(inputs, bottom, bounds, true)
}

fn plan_for(inputs: &[Arc<RunMeta>], bottom: bool, bounds: &[Gk], repack: bool) -> Vec<Vec<Plan>> {
    inputs
        .iter()
        .enumerate()
        .map(|(i, r)| {
            (0..r.fences.len())
                .map(|ci| plan_chunk(inputs, i, ci, bottom, bounds, repack))
                .collect()
        })
        .collect()
}

/// Plan chunk `ci` of input `i` (see [`plan`]). A merge plans each chunk when its cursor reaches it: a GC prefix
/// visits only the chunks before its end, so its cost follows the prefix, not the size of every input
/// (doc/perf/latency-stall-20261107.md).
fn plan_chunk(
    inputs: &[Arc<RunMeta>],
    i: usize,
    ci: usize,
    bottom: bool,
    bounds: &[Gk],
    repack: bool,
) -> Plan {
    let f = &inputs[i].fences[ci];
    let newer = &inputs[..i];
    let dropped = f.first_id == f.last_id
        && newer.iter().any(|n| {
            ranges_find(&n.ranges, f.first_id, &f.first)
                .is_some_and(|x| x.covers_span(f.first_id, &f.first, &f.last))
        });
    if dropped {
        return Plan::Drop;
    }
    let small = repack && (f.len as usize) < super::CHUNK_TARGET / 2;
    let tomb_gc = bottom && f.tombs > 0;
    let range_hit = newer
        .iter()
        .any(|n| ranges_touch(&n.ranges, f.first_id, &f.first, f.last_id, &f.last));
    let overlap = inputs.iter().enumerate().any(|(j, o)| {
        j != i && {
            let k = o.seek_chunk(f.first_id, &f.first);
            k < o.fences.len()
                && cmp_gk(o.fences[k].first_id, &o.fences[k].first, f.last_id, &f.last)
                    != Ordering::Greater
        }
    });
    // a bound g with first < g <= last
    let k = bounds.partition_point(|g| g.cmp_at(f.first_id, &f.first) != Ordering::Greater);
    let straddle = bounds
        .get(k)
        .is_some_and(|g| g.cmp_at(f.last_id, &f.last) != Ordering::Greater);
    if small || tomb_gc || range_hit || overlap || straddle {
        Plan::Rewrite
    } else {
        Plan::Move
    }
}

/// The fixed inputs of [`plan_chunk`] for one merge.
#[derive(Debug)]
struct Planner {
    bottom: bool,
    bounds: Vec<Gk>,
    repack: bool,
}

impl Planner {
    /// Plan chunk `cur.plan.len()` of input `i` (the cursor's next unplanned chunk).
    fn extend(&self, inputs: &[Arc<RunMeta>], i: usize, cur: &mut Cur) {
        let ci = cur.plan.len();
        cur.plan.push(plan_chunk(
            inputs,
            i,
            ci,
            self.bottom,
            &self.bounds,
            self.repack,
        ));
    }
}

/// What [`Cur::fill`] uses of its job: the inputs and their planner, the output counters and the consumed input
/// (bytes for the GC budget, chunks for the step budget).
struct FillCx<'a> {
    inputs: &'a [Arc<RunMeta>],
    planner: &'a Planner,
    out: &'a mut MergeOut,
    work: &'a mut u64,
    spent: &'a mut usize,
}

#[derive(Debug)]
struct Cur {
    /// Plans of the chunks the cursor (or the read-ahead) reached so far, in chunk order.
    plan: Vec<Plan>,
    /// Cursor position at the previous read-ahead ([`MergeJob::next_reads`]).
    seen: usize,
    ci: usize,
    chunk: Option<Chunk>,
    pos: usize,
}

enum Head<'c> {
    Moved(u64, &'c [u8]),
    Entry(u64, &'c [u8]),
    Done,
}

impl Cur {
    /// Skip dropped chunks, load the next rewrite chunk; afterwards `head` is valid. A failed load leaves the cursor
    /// where it was (retry).
    fn fill(
        &mut self,
        i: usize,
        cx: &mut FillCx<'_>,
        rd: &mut impl ChunkRead,
    ) -> Result<(), StoreError> {
        let run = &cx.inputs[i];
        loop {
            if self.chunk.as_ref().is_some_and(|c| self.pos < c.len())
                || self.ci >= run.fences.len()
            {
                return Ok(());
            }
            if self.chunk.take().is_some() {
                *cx.work = cx.work.saturating_add(u64::from(run.fences[self.ci].len));
                *cx.spent += 1;
                self.ci += 1;
                continue;
            }
            if self.ci == self.plan.len() {
                cx.planner.extend(cx.inputs, i, self);
            }
            match self.plan[self.ci] {
                Plan::Drop => {
                    *cx.work = cx.work.saturating_add(u64::from(run.fences[self.ci].len));
                    *cx.spent += 1;
                    cx.out.dropped += 1;
                    self.ci += 1;
                }
                Plan::Move => return Ok(()),
                Plan::Rewrite => {
                    let c = load_chunk(rd, run, self.ci)?;
                    cx.out.rewritten += 1;
                    self.chunk = Some(c);
                    self.pos = 0;
                }
            }
        }
    }
    fn head<'c>(&'c self, run: &'c RunMeta) -> Head<'c> {
        if let Some(c) = &self.chunk {
            return Head::Entry(c.id(self.pos), c.key(self.pos));
        }
        if self.ci >= run.fences.len() {
            return Head::Done;
        }
        let f = &run.fences[self.ci];
        Head::Moved(f.first_id, &f.first)
    }
}

/// k-way merge of a picked input set (see [`MergeJob`]) in one go. `io` reads the input chunks and writes the output
/// (the helper's own IO queue on owner-leased extents).
#[cfg(any(test, feature = "lab"))]
pub fn merge(
    pick: MergePick,
    io: &mut (impl ChunkRead + BlockSink),
) -> Result<MergeOut, StoreError> {
    let mut j = MergeJob::new(pick);
    loop {
        if let Some(out) = j.step(io, usize::MAX)? {
            return Ok(out);
        }
    }
}

/// The output run being written: one partition (or a piece of a gap) from `lo`.
#[derive(Debug)]
struct Piece {
    lo: Gk,
    b: RunBuilder,
}

/// A GC input's unconsumed suffix. A boundary chunk is rewritten entry by entry; later chunks move by reference.
#[derive(Debug)]
struct Suffix {
    input: usize,
    ci: usize,
    pos: Option<usize>,
    b: RunBuilder,
}

/// Ready source indices in key/age order, and sources whose previous head was consumed. Refills stay pending
/// across misses: the next global minimum is unknown until every advanced source has a valid head again.
#[derive(Debug)]
struct Heads {
    heap: Vec<usize>,
    refill: Vec<usize>,
    /// Sorted source indices holding range tombstones. Point-only inputs need no per-key range probes.
    ranges: Vec<usize>,
}

/// A merge in bounded slices (owner inline, adr 0610 phase 2): k-way merge of `inputs` (newest first, age-adjacent),
/// newest entry wins, entries covered by a newer input's range tombstone vanish, point and range tombstones vanish
/// when `bottom`. The output stream is routed by the pick's regions. A step that fails (chunk read `Miss`,
/// allocation refused) leaves every cursor, the open piece and the region index consistent: the next step
/// continues there.
#[derive(Debug)]
pub struct MergeJob {
    pick: MergePick,
    planner: Planner,
    curs: Vec<Cur>,
    /// Current region and its open output run.
    ri: usize,
    piece: Option<Piece>,
    next_id: u64,
    /// Chunks of the finished output runs.
    sealed: usize,
    out: MergeOut,
    tail: bool,
    /// Consumed rewrite/drop input bytes. Moving a clean prefix does not spend this budget.
    work: u64,
    /// Consumed rewrite/drop input chunks: a step's chunk budget counts them next to its output chunks, so input
    /// that yields no output (entries under a range tombstone, bottom tombstones) cannot run a whole merge in one step.
    spent: usize,
    processed: bool,
    heads: Box<Heads>,
    prefix_closed: bool,
    suffix: Option<Box<Suffix>>,
    suffix_next: usize,
    /// The optional GC work limit is separate from `pick.cut`, which also sets the output partition size.
    prefix_budget: Option<u64>,
}

impl MergeJob {
    pub fn new(pick: MergePick) -> MergeJob {
        let prefix_budget = pick.gc.then_some(pick.cut);
        let bounds: Vec<Gk> = pick.regions.iter().skip(1).map(|r| r.lo.clone()).collect();
        // Reclamation leaves clean chunks alone, including short tails of earlier prefixes. Repacking those
        // tails could consume every prefix's budget before reaching its remaining tombstones.
        let planner = Planner {
            bottom: pick.bottom,
            bounds,
            repack: !pick.gc,
        };
        let curs = pick
            .inputs
            .iter()
            .map(|_| Cur {
                plan: Vec::new(),
                seen: 0,
                ci: 0,
                chunk: None,
                pos: 0,
            })
            .collect();
        let heads = Box::new(Heads {
            heap: Vec::with_capacity(pick.inputs.len()),
            refill: (0..pick.inputs.len()).rev().collect(),
            ranges: pick
                .inputs
                .iter()
                .enumerate()
                .filter(|(_, r)| !r.ranges.is_empty())
                .map(|(i, _)| i)
                .collect(),
        });
        MergeJob {
            next_id: pick.first_id,
            pick,
            planner,
            curs,
            ri: 0,
            piece: None,
            sealed: 0,
            out: MergeOut::default(),
            tail: false,
            work: 0,
            spent: 0,
            processed: false,
            heads,
            prefix_closed: false,
            suffix: None,
            suffix_next: 0,
            prefix_budget,
        }
    }

    /// Retry the original pick as a complete GC when a prefix manifest cannot fit the existing hard WAL limits.
    /// No prefix was installed, so the original inputs, age order, locks and reserved output-ID interval remain valid.
    /// The caller returns every unpublished output reservation before restarting with a new helper job identity.
    pub(crate) fn restart_full(self) -> MergeJob {
        let mut next = MergeJob::new(self.pick);
        next.prefix_budget = None;
        next
    }

    /// The merge's input runs, newest first.
    pub fn inputs(&self) -> &[Arc<RunMeta>] {
        &self.pick.inputs
    }

    fn head_key(&self, input: usize) -> (u64, &[u8]) {
        match self.curs[input].head(&self.pick.inputs[input]) {
            Head::Moved(id, key) | Head::Entry(id, key) => (id, key),
            Head::Done => unreachable!("finished cursor in merge heap"),
        }
    }

    fn head_cmp(&self, a: usize, b: usize) -> Ordering {
        let (ai, ak) = self.head_key(a);
        let (bi, bk) = self.head_key(b);
        // Inputs are newest first. The first source decides among equal keys, including point tombstones.
        cmp_gk(ai, ak, bi, bk).then_with(|| a.cmp(&b))
    }

    fn head_push(&mut self, input: usize) {
        self.heads.heap.push(input);
        let mut i = self.heads.heap.len() - 1;
        while i > 0 {
            let parent = (i - 1) / 2;
            if self.head_cmp(self.heads.heap[parent], input) != Ordering::Greater {
                break;
            }
            self.heads.heap.swap(parent, i);
            i = parent;
        }
    }

    fn head_pop(&mut self) -> usize {
        let first = self.heads.heap[0];
        let last = self.heads.heap.pop().expect("nonempty merge heap");
        if !self.heads.heap.is_empty() {
            self.heads.heap[0] = last;
            let mut i = 0;
            loop {
                let left = 2 * i + 1;
                if left >= self.heads.heap.len() {
                    break;
                }
                let right = left + 1;
                let child = if right < self.heads.heap.len()
                    && self.head_cmp(self.heads.heap[right], self.heads.heap[left])
                        == Ordering::Less
                {
                    right
                } else {
                    left
                };
                if self.head_cmp(last, self.heads.heap[child]) != Ordering::Greater {
                    break;
                }
                self.heads.heap.swap(i, child);
                i = child;
            }
        }
        first
    }

    fn fill_heads(&mut self, io: &mut impl ChunkRead) -> Result<(), StoreError> {
        while let Some(&i) = self.heads.refill.last() {
            let mut cx = FillCx {
                inputs: &self.pick.inputs,
                planner: &self.planner,
                out: &mut self.out,
                work: &mut self.work,
                spent: &mut self.spent,
            };
            self.curs[i].fill(i, &mut cx, io)?;
            self.heads.refill.pop();
            if !matches!(self.curs[i].head(&self.pick.inputs[i]), Head::Done) {
                self.head_push(i);
            }
        }
        Ok(())
    }

    fn chunks(&self) -> usize {
        self.sealed + self.piece.as_ref().map_or(0, |p| p.b.chunks())
    }

    /// Picked by a garbage-driven arm (routine GC or space pressure), not by the size-tiered policy.
    pub fn gc(&self) -> bool {
        self.pick.gc
    }

    /// The extents of the next `ahead` chunks each input reads (rewrites) after its loaded chunk, appended to `out`
    /// (read-ahead of an owner that supplies the chunks, [`super::remote`]). Chunks are planned on demand: per input a
    /// call plans at most `ahead` chunks plus the chunks its cursor consumed since the previous call, so the planned
    /// frontier keeps ahead of the merge and deepens through stretches of moved chunks, while planning stays
    /// proportional to the merge's progress (a GC prefix never plans its inputs to the end).
    pub fn next_reads(&mut self, ahead: usize, out: &mut Vec<(u64, u32)>) {
        if self.out.prefix_end.is_some() {
            return;
        }
        let inputs = &self.pick.inputs;
        for (i, c) in self.curs.iter_mut().enumerate() {
            let run = &inputs[i];
            let from = (c.ci + usize::from(c.chunk.is_some())).min(c.plan.len());
            let rewrite = |p: &Plan| *p == Plan::Rewrite;
            let mut found = c.plan[from..]
                .iter()
                .filter(|p| rewrite(p))
                .take(ahead)
                .count();
            let stop = (c.plan.len() + ahead + from.saturating_sub(c.seen)).min(run.fences.len());
            c.seen = from;
            while found < ahead && c.plan.len() < stop {
                self.planner.extend(inputs, i, c);
                found += usize::from(rewrite(c.plan.last().expect("planned")));
            }
            out.extend(
                (from..c.plan.len())
                    .filter(|&k| rewrite(&c.plan[k]))
                    .take(ahead)
                    .map(|k| (run.fences[k].blk, run.fences[k].nblk)),
            );
        }
    }

    /// Finish the open output run (or an empty one at the region start) at `hi` with the clipped input ranges.
    fn close(&mut self, io: &mut impl BlockSink, hi: Option<Gk>) -> Result<(), StoreError> {
        let reg = &self.pick.regions[self.ri];
        let p = self.piece.get_or_insert_with(|| Piece {
            lo: reg.lo.clone(),
            b: RunBuilder::new(),
        });
        if !self.pick.bottom {
            // re-adding after a failed finish is harmless: ranges coalesce
            for r in self.pick.inputs.iter() {
                for x in clipped(&r.ranges, &p.lo, hi.as_ref()) {
                    p.b.add_range(x);
                }
            }
        }
        if !p.b.is_empty() {
            assert!(self.next_id < self.pick.end_id, "olsm merge: run ids");
            let lo = self.pick.inputs.iter().map(|r| r.lsn_lo).min().unwrap_or(0);
            let hi_lsn = self.pick.inputs.iter().map(|r| r.lsn_hi).max().unwrap_or(0);
            let (mut m, written) = p.b.finish(io, self.next_id, lo, hi_lsn)?;
            self.next_id += 1;
            m.place = match &reg.part {
                Some((plo, phi)) => Place {
                    tier: self.pick.dst_tier,
                    lo: plo.clone(),
                    hi: phi.clone(),
                },
                None => Place {
                    tier: self.pick.dst_tier,
                    lo: p.lo.clone(),
                    hi,
                },
            };
            self.sealed += m.fences.len();
            self.out.written_blocks += written;
            self.out.runs.push(m);
        }
        self.piece = None;
        Ok(())
    }

    /// Before pushing an item at `(id, key)`: close the regions it lies past, cut a new piece in a gap when the open one
    /// reached the cut size.
    fn route(&mut self, io: &mut impl BlockSink, id: u64, key: &[u8]) -> Result<(), StoreError> {
        while !below(self.pick.regions[self.ri].hi.as_ref(), id, key) {
            let hi = self.pick.regions[self.ri].hi.clone();
            self.close(io, hi)?;
            self.ri += 1;
        }
        let reg = &self.pick.regions[self.ri];
        let cut = reg.part.is_none()
            && self.piece.as_ref().is_some_and(|p| {
                p.b.bytes() >= self.pick.cut && p.lo.cmp_at(id, key) == Ordering::Less
            });
        if cut {
            self.close(io, Some(Gk::new(id, key)))?;
            self.piece = Some(Piece {
                lo: Gk::new(id, key),
                b: RunBuilder::new(),
            });
        }
        if self.piece.is_none() {
            self.piece = Some(Piece {
                lo: self.pick.regions[self.ri].lo.clone(),
                b: RunBuilder::new(),
            });
        }
        Ok(())
    }

    /// Rebuild suffix metadata with the original ids: a concurrent flush must remain newer than these inputs.
    fn finish_suffixes(&mut self, io: &mut impl BlockSink, end: &Gk) -> Result<(), StoreError> {
        while self.suffix_next < self.pick.inputs.len() {
            if self.suffix.is_none() {
                let input = self.suffix_next;
                let c = &self.curs[input];
                let run = &self.pick.inputs[input];
                // No entry or chunk was consumed and no range needs clipping. Place is stored in the manifest
                // descriptor, so advancing a deeper partition's lower bound does not rewrite immutable run metadata.
                let keep = c.ci == 0
                    && c.pos == 0
                    && run
                        .ranges
                        .first()
                        .is_none_or(|r| end.cmp_at(r.id, &r.first) != Ordering::Greater);
                if keep {
                    let mut m = (**run).clone();
                    if m.place.tier > 0 {
                        m.place.lo = m.place.lo.max(end.clone());
                    }
                    self.out.residuals.push(m);
                    self.suffix_next += 1;
                    continue;
                }
                let mut ci = c.ci;
                let pos = c.chunk.as_ref().and_then(|chunk| {
                    if c.pos == chunk.len() {
                        ci += 1;
                        None
                    } else {
                        (c.pos > 0).then_some(c.pos)
                    }
                });
                let mut b = RunBuilder::new();
                for x in clipped(&run.ranges, end, run.place.hi.as_ref()) {
                    b.add_range(x);
                }
                self.suffix = Some(Box::new(Suffix { input, ci, pos, b }));
            }
            let s = self.suffix.as_mut().expect("suffix initialized");
            let run = &self.pick.inputs[s.input];
            if let Some(pos) = &mut s.pos {
                let chunk = self.curs[s.input].chunk.as_ref().expect("boundary chunk");
                while *pos < chunk.len() {
                    s.b.push(io, chunk.id(*pos), chunk.key(*pos), chunk.val_slice(*pos))?;
                    *pos += 1;
                }
                s.pos = None;
                s.ci += 1;
            }
            while s.ci < run.fences.len() {
                s.b.push_moved(io, run, s.ci)?;
                s.ci += 1;
            }
            if !s.b.is_empty() {
                let (mut m, written) = s.b.finish(io, run.id, run.lsn_lo, run.lsn_hi)?;
                m.place = run.place.clone();
                if m.place.tier > 0 {
                    m.place.lo = m.place.lo.max(end.clone());
                }
                self.out.written_blocks += written;
                self.out.residuals.push(m);
            }
            self.suffix = None;
            self.suffix_next += 1;
        }
        Ok(())
    }

    /// Only consumed rewrite/drop chunks leave the allocation set. A partial boundary chunk was copied into its
    /// residual, while unread suffix chunks and moved prefix chunks remain referenced by their output metadata.
    fn collect_frees(&mut self) {
        // Suffixes are emitted in input order. Retained original metadata remains owned by its residual;
        // rewritten suffixes have a new extent even though their run id is unchanged.
        let mut residuals = self.out.residuals.iter().peekable();
        for (run, c) in self.pick.inputs.iter().zip(&self.curs) {
            let consumed = if self.out.prefix_end.is_some() {
                c.ci + usize::from(c.chunk.is_some() && c.pos > 0)
            } else {
                run.fences.len()
            };
            debug_assert!(c.plan.len() >= consumed, "consumed chunks are planned");
            self.out.freed.extend(
                run.fences[..consumed]
                    .iter()
                    .zip(&c.plan)
                    .filter(|(_, p)| **p != Plan::Move)
                    .map(|(f, _)| (f.blk, f.nblk)),
            );
            let keep_meta = residuals.peek().is_some_and(|r| r.id == run.id)
                && residuals.next().is_some_and(|r| r.meta_blk == run.meta_blk);
            if !keep_meta {
                self.out.freed.push((run.meta_blk, run.meta_nblk));
            }
        }
    }

    /// Merge until `chunks` chunks were sealed or moved (output) or consumed (rewritten or dropped input) in this step,
    /// or the inputs are done; then the output runs are finished and the result returned.
    pub fn step(
        &mut self,
        io: &mut (impl ChunkRead + BlockSink),
        chunks: usize,
    ) -> Result<Option<MergeOut>, StoreError> {
        let c0 = self.chunks() + self.spent;
        let bottom = self.pick.bottom;
        while !self.tail {
            if self.chunks() + self.spent - c0 >= chunks {
                return Ok(None);
            }
            self.fill_heads(io)?;
            let Some(&w) = self.heads.heap.first() else {
                self.tail = true;
                break;
            };
            if self.prefix_budget.is_some_and(|budget| self.work >= budget) && self.processed {
                let (id, key) = self.head_key(w);
                let end = Gk::new(id, key);
                self.out.prefix_end = Some(end);
                self.tail = true;
                break;
            }
            if matches!(self.curs[w].head(&self.pick.inputs[w]), Head::Moved(..)) {
                let run = self.pick.inputs[w].clone();
                let ci = self.curs[w].ci;
                let f = &run.fences[ci];
                self.route(io, f.first_id, &f.first)?;
                let p = self.piece.as_mut().expect("routed");
                p.b.push_moved(io, &run, ci)?;
                self.out.moved += 1;
                let popped = self.head_pop();
                debug_assert_eq!(popped, w);
                self.curs[w].ci += 1;
                self.heads.refill.push(w);
                self.processed = true;
                continue;
            }
            // Keep the key borrowed from its decoded chunk while the output writer may mutate the job. The
            // removed source is restored before returning any refusal, so retries see the identical winning key.
            let popped = self.head_pop();
            debug_assert_eq!(popped, w);
            let c = self.curs[w].chunk.take().expect("entry head");
            let pos = self.curs[w].pos;
            let id = c.id(pos);
            let key = c.key(pos);
            let tomb = c.is_tomb(pos);
            let covered = self
                .heads
                .ranges
                .iter()
                .take_while(|&&i| i < w)
                .any(|&i| ranges_find(&self.pick.inputs[i].ranges, id, key).is_some());
            let written: Result<(), StoreError> = (|| {
                if !covered && !(bottom && tomb) {
                    self.route(io, id, key)?;
                    let p = self.piece.as_mut().expect("routed");
                    p.b.push(io, id, key, c.val_slice(pos))?;
                }
                Ok(())
            })();
            if let Err(e) = written {
                self.curs[w].chunk = Some(c);
                self.head_push(w);
                return Err(e);
            }
            self.curs[w].pos += 1;
            self.heads.refill.push(w);
            // All versions of this key form consecutive heap roots. Consume the complete group before any
            // refill or prefix cut; lower-priority versions must never survive into a residual suffix.
            while let Some(&i) = self.heads.heap.first() {
                let (next_id, next_key) = self.head_key(i);
                if cmp_gk(id, key, next_id, next_key) != Ordering::Equal {
                    break;
                }
                debug_assert!(matches!(
                    self.curs[i].head(&self.pick.inputs[i]),
                    Head::Entry(..)
                ));
                let popped = self.head_pop();
                debug_assert_eq!(popped, i);
                self.curs[i].pos += 1;
                self.heads.refill.push(i);
            }
            self.curs[w].chunk = Some(c);
            self.processed = true;
        }
        if let Some(end) = self.out.prefix_end.clone() {
            if !self.prefix_closed {
                while self.ri < self.pick.regions.len()
                    && !below(self.pick.regions[self.ri].hi.as_ref(), end.id, &end.key)
                {
                    let hi = self.pick.regions[self.ri].hi.clone();
                    self.close(io, hi)?;
                    self.ri += 1;
                }
                if self.ri < self.pick.regions.len() {
                    self.close(io, Some(end.clone()))?;
                }
                self.prefix_closed = true;
            }
            self.finish_suffixes(io, &end)?;
        } else {
            while self.ri < self.pick.regions.len() {
                let hi = self.pick.regions[self.ri].hi.clone();
                self.close(io, hi)?;
                self.ri += 1;
            }
        }
        self.collect_frees();
        let mut out = std::mem::take(&mut self.out);
        if self.pick.stay {
            let n0 = self.pick.cut;
            let bytes: u64 = out.runs.iter().map(|r| r.data_bytes()).sum();
            if tier(bytes, n0) == 0 {
                for r in &mut out.runs {
                    r.place.tier = self.pick.src_tier;
                }
            }
        }
        Ok(Some(out))
    }
}

/// The ranges of a sorted disjoint list intersecting `[lo, hi)`, clipped to it.
fn clipped<'a>(
    list: &'a [RangeT],
    lo: &'a Gk,
    hi: Option<&'a Gk>,
) -> impl Iterator<Item = RangeT> + 'a {
    // first range ending after lo (ends ascend in a sorted disjoint list)
    list[ranges_from(list, lo.id, &lo.key)..]
        .iter()
        .take_while(move |x| below(hi, x.id, &x.first))
        .filter_map(move |x| x.clip(lo, hi))
}

#[cfg(test)]
mod prefix_tests {
    use super::*;
    use crate::olsm::labdev::MemBlocks;
    use crate::olsm::manifest::{Manifest, Region, RunDesc};
    use crate::olsm::{CHUNK_TARGET, Memtable, Olsm, read};

    fn key(i: usize) -> Bytes {
        Bytes::from(format!("k{i:06}"))
    }

    fn run(dev: &mut MemBlocks, id: u64, mem: &Memtable, tier: u32) -> Arc<RunMeta> {
        let mut r = flush(mem, id, dev).unwrap().unwrap().0;
        r.place.tier = tier;
        Arc::new(r)
    }

    fn pick(inputs: Vec<Arc<RunMeta>>, first_id: u64, gc: bool) -> MergePick {
        MergePick {
            inputs,
            bottom: true,
            src_tier: 0,
            dst_tier: 1,
            regions: vec![Region {
                lo: Gk::MIN,
                hi: None,
                part: None,
            }],
            cut: CHUNK_TARGET as u64,
            stay: false,
            first_id,
            end_id: first_id + 10_000,
            gc,
        }
    }

    fn mounted(dev: &mut MemBlocks, runs: &[Arc<RunMeta>]) -> Olsm {
        let recs: Vec<_> = runs.iter().map(|r| RunDesc::of(r)).collect();
        Olsm::new(Manifest::mount(CHUNK_TARGET as u64, 2, &recs, dev).unwrap())
    }

    fn replace(dev: &mut MemBlocks, out: MergeOut) -> Vec<Arc<RunMeta>> {
        for (b, n) in out.freed {
            dev.free(b, n);
        }
        out.runs
            .into_iter()
            .chain(out.residuals)
            .map(Arc::new)
            .collect()
    }

    #[test]
    fn gc_prefix_keeps_suffix_keys_ids_ranges_and_replay() {
        let mut dev = MemBlocks::new();
        let mut base = Memtable::default();
        let value = Bytes::from(vec![7; 512]);
        for i in 0..2048 {
            base.put(1, 1, key(i), value.clone());
        }
        let base = run(&mut dev, 1, &base, 1);
        let mut newer = Memtable::default();
        newer.del_range(2, 1, key(100), Some(key(1800)));
        // A source's own entry supersedes its range tombstone.
        newer.put(2, 1, key(900), Bytes::from_static(b"new"));
        for i in (0..100).step_by(2) {
            newer.del(2, 1, key(i));
        }
        let newer = run(&mut dev, 2, &newer, 0);
        let out = merge(pick(vec![newer, base], 100, true), &mut dev).unwrap();
        let end = out.prefix_end.clone().expect("bounded prefix");
        assert!(!out.residuals.is_empty());
        assert!(out.residuals.iter().all(|r| r.id <= 2));
        assert!(
            out.residuals
                .iter()
                .all(|r| r.lsn_lo == r.id && r.lsn_hi == r.id)
        );
        assert!(
            out.residuals
                .iter()
                .filter(|r| r.place.tier > 0)
                .all(|r| r.place.lo >= end)
        );
        let runs = replace(&mut dev, out);
        let lsm = mounted(&mut dev, &runs);
        for i in 0..2048 {
            let actual = read::get(&lsm.sources(), &mut dev, 1, &key(i)).unwrap();
            let expect = if i == 900 {
                Some(Bytes::from_static(b"new"))
            } else if (100..1800).contains(&i) || i < 100 && i % 2 == 0 {
                None
            } else {
                Some(value.clone())
            };
            assert_eq!(actual, expect, "key {i}");
        }
        // New writes must stay newer than retained original-id suffixes after a mount.
        let mut last = Memtable::default();
        last.put(3, 1, key(1900), Bytes::from_static(b"latest"));
        let mut runs = runs;
        runs.push(run(&mut dev, 20_000, &last, 0));
        let lsm = mounted(&mut dev, &runs);
        assert_eq!(
            read::get(&lsm.sources(), &mut dev, 1, &key(1900)).unwrap(),
            Some(Bytes::from_static(b"latest"))
        );
    }

    #[test]
    fn gc_prefix_repeated_moved_prefix_reaches_dirty_suffix() {
        let mut dev = MemBlocks::new();
        let mut base = Memtable::default();
        let value = Bytes::from(vec![3; 512]);
        for i in 0..4096 {
            base.put(1, 1, key(i), value.clone());
        }
        let mut newer = Memtable::default();
        for i in (0..4096).step_by(2) {
            newer.del(2, 1, key(i));
        }
        let mut runs = vec![run(&mut dev, 2, &newer, 0), run(&mut dev, 1, &base, 1)];
        let mut frontier = None;
        for round in 0..100 {
            // Rebuild a pick in the same source order a whole-column GC uses.
            runs.sort_by_key(|r| (r.place.tier, r.place.lo.clone(), std::cmp::Reverse(r.id)));
            let out = merge(pick(runs, 100 + round * 10_000, true), &mut dev).unwrap();
            if let Some(end) = &out.prefix_end {
                assert!(
                    frontier.as_ref().is_none_or(|p| p < end),
                    "GC must advance past clean moved output"
                );
                frontier = Some(end.clone());
            }
            let finished = out.prefix_end.is_none();
            runs = replace(&mut dev, out);
            let lsm = mounted(&mut dev, &runs);
            for i in 0..4096 {
                assert_eq!(
                    read::get(&lsm.sources(), &mut dev, 1, &key(i)).unwrap(),
                    (i % 2 == 1).then(|| value.clone()),
                    "round {round} key {i}"
                );
            }
            if finished {
                return;
            }
        }
        panic!("GC prefix failed to finish");
    }

    #[test]
    fn gc_prefix_all_point_tombstones_can_yield_empty_output() {
        let mut dev = MemBlocks::new();
        let mut mem = Memtable::default();
        for i in 0..20_000 {
            mem.del(1, 1, key(i));
        }
        let input = run(&mut dev, 1, &mem, 0);
        let out = merge(pick(vec![input], 100, true), &mut dev).unwrap();
        assert!(out.prefix_end.is_some());
        assert!(out.runs.is_empty());
        assert_eq!(out.residuals.len(), 1);
        let runs = replace(&mut dev, out);
        let lsm = mounted(&mut dev, &runs);
        for i in [0, 10_000, 19_999] {
            assert!(
                read::get(&lsm.sources(), &mut dev, 1, &key(i))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn gc_prefix_non_gc_still_finishes_whole_merge() {
        let mut dev = MemBlocks::new();
        let mut mem = Memtable::default();
        for i in 0..1024 {
            mem.put(1, 1, key(i), Bytes::from(vec![1; 512]));
        }
        let input = run(&mut dev, 1, &mem, 0);
        let out = merge(pick(vec![input], 100, false), &mut dev).unwrap();
        assert!(out.prefix_end.is_none() && out.residuals.is_empty());
        assert_eq!(out.runs.iter().map(|r| r.entries).sum::<u64>(), 1024);
    }

    #[test]
    fn gc_prefix_ring_fallback_restarts_original_pick_without_residuals() {
        use std::collections::BTreeMap;

        let mut dev = MemBlocks::new();
        let mut base = Memtable::default();
        let mut newer = Memtable::default();
        let value = Bytes::from(vec![9; 512]);
        for i in 0..2048 {
            base.put(1, 1, key(i), value.clone());
            if i % 2 == 0 {
                newer.del(2, 1, key(i));
            }
        }
        let inputs = vec![run(&mut dev, 2, &newer, 0), run(&mut dev, 1, &base, 1)];
        let original: BTreeMap<_, _> = inputs
            .iter()
            .flat_map(|r| {
                std::iter::once((r.meta_blk, r.meta_nblk))
                    .chain(r.fences.iter().map(|f| (f.blk, f.nblk)))
            })
            .collect();
        let before = dev.live_blocks;
        let mut job = MergeJob::new(pick(inputs.clone(), 100, true));
        let partial = job.step(&mut dev, usize::MAX).unwrap().unwrap();
        assert!(partial.prefix_end.is_some());
        let unpublished: BTreeMap<_, _> = partial
            .runs
            .iter()
            .chain(&partial.residuals)
            .flat_map(|r| {
                std::iter::once((r.meta_blk, r.meta_nblk))
                    .chain(r.fences.iter().map(|f| (f.blk, f.nblk)))
            })
            .filter(|(b, _)| !original.contains_key(b))
            .collect();
        // A rejected prefix never publishes its frees. Return only newly written output reservations.
        for (b, n) in unpublished {
            dev.free(b, n);
        }
        assert_eq!(dev.live_blocks, before);
        let lsm = mounted(&mut dev, &inputs);
        for i in 0..2048 {
            assert_eq!(
                read::get(&lsm.sources(), &mut dev, 1, &key(i)).unwrap(),
                (i % 2 == 1).then(|| value.clone())
            );
        }
        let mut full = job.restart_full();
        assert!(full.gc());
        assert_eq!(
            full.pick.first_id, 100,
            "the unpublished ID interval is reusable"
        );
        assert_eq!(
            full.pick.cut, CHUNK_TARGET as u64,
            "keep output partition sizing"
        );
        let output = full.step(&mut dev, usize::MAX).unwrap().unwrap();
        assert!(output.prefix_end.is_none() && output.residuals.is_empty());
        let runs = replace(&mut dev, output);
        let lsm = mounted(&mut dev, &runs);
        for i in 0..2048 {
            assert_eq!(
                read::get(&lsm.sources(), &mut dev, 1, &key(i)).unwrap(),
                (i % 2 == 1).then(|| value.clone())
            );
        }
    }

    #[test]
    fn gc_prefix_retains_untouched_future_metadata_but_rewrites_clipped_ranges() {
        for crossing in [false, true] {
            let mut dev = MemBlocks::new();
            let mut base = Memtable::default();
            let value = Bytes::from(vec![7; 512]);
            let mut newer = Memtable::default();
            for i in 0..2048 {
                base.put(1, 1, key(i), value.clone());
                if i % 2 == 0 {
                    newer.del(2, 1, key(i));
                }
            }
            let base = run(&mut dev, 1, &base, 1);
            let newer = run(&mut dev, 2, &newer, 0);
            let mut future = Memtable::default();
            future.del_range(1, 1, key(if crossing { 0 } else { 5000 }), Some(key(7000)));
            future.put(1, 1, key(6000), Bytes::from_static(b"future"));
            let future = run(&mut dev, 3, &future, 2);
            let mut p = pick(vec![newer, base, future.clone()], 100, true);
            p.dst_tier = 2;
            let out = merge(p, &mut dev).unwrap();
            let end = out
                .prefix_end
                .clone()
                .expect("prefix stops before future input");
            assert!(end.cmp_at(1, &key(2048)) == Ordering::Less);
            let residual = out.residuals.iter().find(|r| r.id == future.id).unwrap();
            assert_eq!(residual.place.lo, end);
            if crossing {
                assert_ne!(
                    residual.meta_blk, future.meta_blk,
                    "clipping changes encoded range metadata"
                );
                assert_eq!(residual.ranges[0].first, end.key);
                assert!(out.freed.contains(&(future.meta_blk, future.meta_nblk)));
            } else {
                let mut expected = (*future).clone();
                expected.place.lo = end;
                assert_eq!(*residual, expected, "only descriptor placement changes");
                assert!(
                    residual.shares_body(&future),
                    "an untouched residual references the input's metadata, it does not copy it"
                );
                assert!(!out.freed.contains(&(future.meta_blk, future.meta_nblk)));
                assert_eq!(RunDesc::of(residual).load(&mut dev).unwrap(), expected);
            }
            // Untouched data stays owned in both cases. After all reported frees, retained old metadata and
            // newly written clipped metadata must both remain readable through the mounted descriptors.
            for f in &future.fences {
                assert!(!out.freed.contains(&(f.blk, f.nblk)));
            }
            let runs = replace(&mut dev, out);
            let lsm = mounted(&mut dev, &runs);
            for i in 0..2048 {
                assert_eq!(
                    read::get(&lsm.sources(), &mut dev, 1, &key(i)).unwrap(),
                    (i % 2 == 1).then(|| value.clone()),
                    "crossing={crossing} key {i}"
                );
            }
            assert_eq!(
                read::get(&lsm.sources(), &mut dev, 1, &key(6000)).unwrap(),
                Some(Bytes::from_static(b"future"))
            );
            assert!(
                read::get(&lsm.sources(), &mut dev, 1, &key(6500))
                    .unwrap()
                    .is_none()
            );
        }
    }

    /// A step's budget counts consumed input chunks: input that yields no output (tombstones at the bottom) is still
    /// read and decoded, yet a one-chunk step consumes at most one more input chunk (no whole merge inside a single
    /// core iteration).
    #[test]
    fn step_budget_counts_consumed_inputs_without_output() {
        let mut dev = MemBlocks::new();
        let mut old = Memtable::default();
        let long = |i: usize| Bytes::from(format!("k{i:06}{}", "p".repeat(200)));
        for i in 0..20_000 {
            old.del(1, 1, long(i));
        }
        let old = run(&mut dev, 1, &old, 1);
        let mut new = Memtable::default();
        new.put(2, 1, key(99_999), Bytes::from_static(b"x"));
        let new = run(&mut dev, 2, &new, 0);
        let p = pick(vec![new, old.clone()], 100, false);
        let mut j = MergeJob::new(p);
        let mut steps = 0;
        let out = loop {
            let spent = j.spent;
            let r = j.step(&mut dev, 1).unwrap();
            if r.is_none() {
                assert!(j.spent - spent <= 1, "one input chunk per one-chunk step");
            }
            steps += 1;
            if let Some(out) = r {
                break out;
            }
        };
        assert!(old.fences.len() > 4);
        assert!(
            steps >= old.fences.len(),
            "{steps} steps for {} input chunks",
            old.fences.len()
        );
        assert_eq!(out.rewritten, old.fences.len() + 1);
        assert_eq!(out.runs.iter().map(|r| r.entries).sum::<u64>(), 1);
    }

    /// Lazy per-chunk planning decides every chunk a complete merge visits exactly as planning all chunks up front.
    #[test]
    fn lazy_plan_matches_full_plan() {
        let mut dev = MemBlocks::new();
        let (mut a, mut b, mut c) = (
            Memtable::default(),
            Memtable::default(),
            Memtable::default(),
        );
        for i in 0..3000 {
            a.put(1, 1, key(i), Bytes::from(vec![1; 300]));
            if i % 3 == 0 {
                b.put(2, 1, key(i), Bytes::from(vec![2; 300]));
            }
            if (1000..1500).contains(&i) {
                c.del(3, 1, key(i));
            }
        }
        c.del_range(3, 1, key(2000), Some(key(2600)));
        let inputs = vec![
            run(&mut dev, 3, &c, 0),
            run(&mut dev, 2, &b, 0),
            run(&mut dev, 1, &a, 1),
        ];
        for gc in [false, true] {
            let p = pick(inputs.clone(), 100, gc);
            let full = plan_for(&p.inputs, p.bottom, &[], !gc);
            let mut j = MergeJob::new(p);
            let mut reads = Vec::new();
            while j.step(&mut dev, 1).unwrap().is_none() {
                j.next_reads(4, &mut reads);
            }
            for (cur, want) in j.curs.iter().zip(&full) {
                assert_eq!(cur.plan[..], want[..cur.plan.len()], "gc={gc}");
            }
            if !gc {
                for (cur, want) in j.curs.iter().zip(&full) {
                    assert_eq!(
                        cur.plan.len(),
                        want.len(),
                        "a complete merge plans every chunk"
                    );
                }
            }
        }
    }

    struct RefuseAlloc<'a> {
        dev: &'a mut MemBlocks,
        calls: usize,
        refuse: Option<usize>,
        refused: bool,
    }

    impl BlockSink for RefuseAlloc<'_> {
        fn alloc(&mut self, n: u32) -> Result<u64, StoreError> {
            let call = self.calls;
            self.calls += 1;
            if self.refuse == Some(call) {
                self.refused = true;
                Err(StoreError::Busy)
            } else {
                self.dev.alloc(n)
            }
        }
        fn write(&mut self, b: u64, data: Vec<u8>, crcs: &[u32]) -> Result<(), StoreError> {
            self.dev.write(b, data, crcs)
        }
        fn sync(&mut self) -> Result<(), StoreError> {
            self.dev.sync()
        }
    }

    impl ChunkRead for RefuseAlloc<'_> {
        fn read(&mut self, b: u64, n: u32) -> Result<Bytes, StoreError> {
            self.dev.read(b, n)
        }
    }

    #[test]
    fn gc_prefix_resumes_after_every_output_allocation_refusal() {
        let attempt = |refuse| {
            let mut dev = MemBlocks::new();
            let mut base = Memtable::default();
            let value = Bytes::from(vec![5; 512]);
            let mut newer = Memtable::default();
            for i in 0..1024 {
                base.put(1, 1, key(i), value.clone());
                if i % 2 == 0 {
                    newer.del(2, 1, key(i));
                }
            }
            let inputs = vec![run(&mut dev, 2, &newer, 0), run(&mut dev, 1, &base, 1)];
            let mut job = MergeJob::new(pick(inputs, 100, true));
            let mut io = RefuseAlloc {
                dev: &mut dev,
                calls: 0,
                refuse,
                refused: false,
            };
            let mut out = None;
            for _ in 0..1000 {
                match job.step(&mut io, 1) {
                    Ok(Some(x)) => {
                        out = Some(x);
                        break;
                    }
                    Ok(None) | Err(StoreError::Busy) => {}
                    Err(e) => panic!("{e:?}"),
                }
            }
            let calls = io.calls;
            assert_eq!(io.refused, refuse.is_some());
            let out = out.expect("job must finish after a refused lease");
            assert!(out.prefix_end.is_some());
            let runs = replace(&mut dev, out);
            let lsm = mounted(&mut dev, &runs);
            for i in 0..1024 {
                assert_eq!(
                    read::get(&lsm.sources(), &mut dev, 1, &key(i)).unwrap(),
                    (i % 2 == 1).then(|| value.clone()),
                    "allocation {refuse:?} key {i}"
                );
            }
            calls
        };
        let allocations = attempt(None);
        for i in 0..allocations {
            attempt(Some(i));
        }
    }

    #[test]
    fn cursor_heap_moved_root_survives_every_output_allocation_refusal() {
        let attempt = |refuse| {
            let mut dev = MemBlocks::new();
            let value = Bytes::from(vec![9; 512]);
            let mut inputs = Vec::new();
            for id in 1..=2 {
                let mut mem = Memtable::default();
                for i in 0..512 {
                    mem.put(id, id, key(i), value.clone());
                }
                inputs.insert(0, run(&mut dev, id, &mem, 0));
            }
            // Full disjoint chunks move; each short tail is rewritten. Moving the next object's first chunk
            // must seal the previous object's rewritten tail, exercising both route and push_moved refusals.
            assert!(
                plan(&inputs, true, &[])
                    .iter()
                    .flatten()
                    .any(|p| *p == Plan::Move)
            );
            let mut job = MergeJob::new(pick(inputs, 100, false));
            let mut io = RefuseAlloc {
                dev: &mut dev,
                calls: 0,
                refuse,
                refused: false,
            };
            let mut out = None;
            for _ in 0..1000 {
                match job.step(&mut io, 1) {
                    Ok(Some(x)) => {
                        out = Some(x);
                        break;
                    }
                    Ok(None) | Err(StoreError::Busy) => {}
                    Err(e) => panic!("{e:?}"),
                }
            }
            let calls = io.calls;
            assert_eq!(io.refused, refuse.is_some());
            let out = out.expect("moved root must survive every output refusal");
            assert!(out.moved > 0 && out.prefix_end.is_none());
            let runs = replace(&mut dev, out);
            let lsm = mounted(&mut dev, &runs);
            for id in 1..=2 {
                let (actual, more) =
                    read::list(&lsm.sources(), &mut dev, id, None, b"", 513).unwrap();
                assert!(!more);
                assert_eq!(actual.len(), 512);
                for (i, (k, v)) in actual.iter().enumerate() {
                    assert_eq!(*k, key(i));
                    assert_eq!(*v, value);
                }
            }
            calls
        };
        let allocations = attempt(None);
        for i in 0..allocations {
            attempt(Some(i));
        }
    }

    struct MissFirstRead<'a> {
        dev: &'a mut MemBlocks,
        seen: std::collections::BTreeSet<(u64, u32)>,
        misses: usize,
    }

    impl BlockSink for MissFirstRead<'_> {
        fn alloc(&mut self, n: u32) -> Result<u64, StoreError> {
            self.dev.alloc(n)
        }
        fn write(&mut self, b: u64, data: Vec<u8>, crcs: &[u32]) -> Result<(), StoreError> {
            self.dev.write(b, data, crcs)
        }
        fn sync(&mut self) -> Result<(), StoreError> {
            self.dev.sync()
        }
    }

    impl ChunkRead for MissFirstRead<'_> {
        fn read(&mut self, b: u64, n: u32) -> Result<Bytes, StoreError> {
            if self.seen.insert((b, n)) {
                self.misses += 1;
                Err(StoreError::Miss)
            } else {
                self.dev.read(b, n)
            }
        }
    }

    #[test]
    fn cursor_heap_many_future_inputs_preserves_versions_ranges_and_read_retries() {
        use std::collections::{BTreeMap, BTreeSet};

        for gc in [false, true] {
            let mut dev = MemBlocks::new();
            let mut expected = BTreeMap::new();
            let mut base = Memtable::default();
            let mut mid = Memtable::default();
            let mut newest = Memtable::default();
            for i in 0..1024 {
                let value = Bytes::from(vec![1; 256]);
                base.put(1, 1, key(i), value.clone());
                expected.insert(key(i).to_vec(), value);
                if i % 2 == 0 {
                    mid.del(2, 1, key(i));
                    expected.remove(key(i).as_ref());
                } else {
                    let value = Bytes::from(vec![2; 256]);
                    mid.put(2, 1, key(i), value.clone());
                    expected.insert(key(i).to_vec(), value);
                }
            }
            newest.del_range(3, 1, key(100), Some(key(800)));
            expected.retain(|k, _| {
                k.as_slice() < key(100).as_ref() || k.as_slice() >= key(800).as_ref()
            });
            for i in [0, 200] {
                newest.put(3, 1, key(i), Bytes::from_static(b"newest"));
                expected.insert(key(i).to_vec(), Bytes::from_static(b"newest"));
            }
            newest.del(3, 1, key(901));
            expected.remove(key(901).as_ref());
            let mut base = (*run(&mut dev, 1, &base, 1)).clone();
            base.place.hi = Some(Gk::new(1, &key(10_000)));
            let mut inputs = vec![
                run(&mut dev, 3, &newest, 0),
                run(&mut dev, 2, &mid, 0),
                Arc::new(base),
            ];
            // These disjoint sources all have future heads while the three overlapping sources above merge.
            // They must not affect newest-wins ties, and their pending first-read misses must not hide a minimum.
            for part in 0..64 {
                let lo = 10_000 + part * 1000;
                let mut mem = Memtable::default();
                for i in lo..lo + 128 {
                    let value = Bytes::from(vec![part as u8; 256]);
                    mem.put(1, 1, key(i), value.clone());
                    expected.insert(key(i).to_vec(), value);
                }
                let mut future = (*run(&mut dev, 10 + part as u64, &mem, 1)).clone();
                future.place.lo = Gk::new(1, &key(lo));
                future.place.hi = Some(Gk::new(1, &key(lo + 1000)));
                inputs.push(Arc::new(future));
            }
            let mut job = MergeJob::new(pick(inputs, 1000, gc));
            let mut io = MissFirstRead {
                dev: &mut dev,
                seen: BTreeSet::new(),
                misses: 0,
            };
            let mut out = None;
            for _ in 0..10_000 {
                match job.step(&mut io, 1) {
                    Ok(Some(x)) => {
                        out = Some(x);
                        break;
                    }
                    Ok(None) | Err(StoreError::Miss) => {}
                    Err(e) => panic!("unexpected merge error: {e:?}"),
                }
            }
            assert!(io.misses > 3, "exercise initial and changed-head refills");
            let out = out.expect("heap merge must make progress after read retries");
            assert_eq!(out.prefix_end.is_some(), gc);
            let runs = replace(&mut dev, out);
            let lsm = mounted(&mut dev, &runs);
            let (actual, more) =
                read::list(&lsm.sources(), &mut dev, 1, None, b"", expected.len() + 1).unwrap();
            assert!(!more);
            let actual: BTreeMap<_, _> = actual.into_iter().map(|(k, v)| (k.to_vec(), v)).collect();
            assert_eq!(actual, expected, "gc={gc}");
        }
    }
}
