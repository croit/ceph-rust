// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! A flush or merge as a continuation any core can step (adr 0610 (2), (3), am. 3 helper jobs).
//!
//! A [`Task`] steps against a [`Ctx`] only: blocks from a lease the owner reserved, written blocks collected for the
//! owner to submit, input chunks the owner read for it. No store handle, allocator or device queue inside, so the
//! owner can send the task with its context to a helper core (adr 0534 lane) and step it there, or step it itself
//! (single-core OSD, helpers stopping): one code path.
//!
//! A round ends when the task finished, its lease cannot hold the next block request ([`Ctx::need`]) or it needs an
//! input chunk the owner has not supplied ([`Ctx::missed`]). The owner then queues the written blocks for its
//! device, tops up the lease, reads the missing chunk and the read-ahead ([`Task::next_reads`]) and hands the task out
//! again. A failed allocation or a missing chunk leaves the job where it was (see [`FlushJob`], [`MergeJob`]).
//!
//! Memory while a task is away: its written blocks (at most the lease) and its supplied chunks (at most the
//! read-ahead the owner chose); the frozen memtable and the input runs stay referenced by the owner as well.

use super::job::{FlushJob, MergeJob, MergeOut};
use super::{BlockSink, ChunkRead, Memtable, RunMeta};
use crate::{BLK, StoreError};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;

/// Blocks a task wrote: `(first block, data, per-block crcs)`.
pub type Written = (u64, Vec<u8>, Vec<u32>);

/// The stepping core's view of the owner's resources for one task.
#[derive(Debug, Default)]
pub struct Ctx {
    /// Leased extents not used up yet: `(next block, blocks left)` each.
    pub lease: Vec<(u64, u32)>,
    /// A block request the lease could not hold (0: none); the owner leases at least this much.
    pub need: u32,
    /// Blocks written since the owner last collected them.
    pub out: Vec<Written>,
    /// Input chunks the owner supplied, by extent; a read takes its chunk out.
    pub chunks: HashMap<(u64, u32), Bytes>,
    /// The chunk a read missed (the task cannot continue without it).
    pub missed: Option<(u64, u32)>,
    /// Chunks shorter than [`super::CHUNK_MAX`] blocks this job sealed (counter `olsm_chunks_lt16`).
    pub short_chunks: u64,
}

impl Ctx {
    /// Hand the written blocks to the owner's device queue in pieces of at most `max_blk` blocks (one device transfer):
    /// `f(first block, bytes, per-block crcs)`. No copy: the pieces are slices of the written buffers.
    pub fn drain_out(&mut self, max_blk: usize, mut f: impl FnMut(u64, Bytes, &[u32])) {
        for (blk, data, crcs) in self.out.drain(..) {
            debug_assert_eq!(data.len(), crcs.len() * BLK);
            let data = Bytes::from(data);
            for (i, c) in crcs.chunks(max_blk).enumerate() {
                let off = i * max_blk * BLK;
                f(
                    blk + (i * max_blk) as u64,
                    data.slice(off..off + c.len() * BLK),
                    c,
                );
            }
        }
    }
}

impl BlockSink for Ctx {
    fn alloc(&mut self, nblk: u32) -> Result<u64, StoreError> {
        let Some(i) = self.lease.iter().position(|x| x.1 >= nblk) else {
            self.need = nblk;
            return Err(StoreError::Busy);
        };
        let (b, n) = self.lease[i];
        if n == nblk {
            self.lease.remove(i);
        } else {
            self.lease[i] = (b + nblk as u64, n - nblk);
        }
        Ok(b)
    }
    fn write(&mut self, blk: u64, data: Vec<u8>, crcs: &[u32]) -> Result<(), StoreError> {
        self.out.push((blk, data, crcs.to_vec()));
        Ok(())
    }
    /// The owner submits the blocks and waits for them before the manifest txn.
    fn sync(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
    /// The largest leased piece, never below [`super::CHUNK_MIN`]: a smaller remnant (or an empty lease) is replaced at
    /// the next round boundary by pieces of at least [`super::CHUNK_MIN`] blocks, so a chunk of that size always gets
    /// an extent and a remnant does not cut chunks short.
    fn room(&self) -> u32 {
        self.lease
            .iter()
            .map(|x| x.1)
            .max()
            .unwrap_or(0)
            .max(super::CHUNK_MIN)
    }
    fn chunk(&mut self, nblk: u32) {
        if nblk < super::CHUNK_MAX {
            self.short_chunks += 1;
        }
    }
}

impl ChunkRead for Ctx {
    fn read(&mut self, blk: u64, nblk: u32) -> Result<Bytes, StoreError> {
        match self.chunks.remove(&(blk, nblk)) {
            Some(b) => Ok(b),
            None => {
                self.missed = Some((blk, nblk));
                Err(StoreError::Miss)
            }
        }
    }
}

/// A flush or merge in progress.
#[derive(Debug)]
pub enum Task {
    Flush {
        job: Box<FlushJob>,
        /// The frozen memtable (the owner keeps its own reference for reads).
        mem: Arc<Memtable>,
        out: Option<RunMeta>,
    },
    Merge {
        job: Box<MergeJob>,
        out: Option<MergeOut>,
    },
}

/// Why a round of [`Task::round`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// The task finished (output complete, every block in [`Ctx::out`] or collected).
    Done,
    /// The step budget is used up; the task can continue as it is.
    Budget,
    /// The owner must lease blocks ([`Ctx::need`]) or supply a chunk ([`Ctx::missed`]).
    Owner,
}

impl Task {
    pub fn flush(mem: Arc<Memtable>, run_id: u64) -> Task {
        Task::Flush {
            job: Box::new(FlushJob::new(&mem, run_id)),
            mem,
            out: None,
        }
    }

    pub fn merge(job: MergeJob) -> Task {
        Task::Merge {
            job: Box::new(job),
            out: None,
        }
    }

    pub fn done(&self) -> bool {
        match self {
            Task::Flush { out, .. } => out.is_some(),
            Task::Merge { out, .. } => out.is_some(),
        }
    }

    /// Step until `chunks` output chunks were sealed or moved, the task finished or it needs the owner. A store error
    /// other than a lease or chunk miss (a corrupt input chunk) is returned.
    pub fn round(&mut self, cx: &mut Ctx, chunks: usize) -> Result<Stop, StoreError> {
        if self.done() {
            return Ok(Stop::Done);
        }
        let r = match self {
            Task::Flush { job, mem, out } => job
                .step(mem, cx, chunks)
                .map(|r| r.map(|(m, _)| *out = Some(m)).is_some()),
            Task::Merge { job, out } => job
                .step(cx, chunks)
                .map(|r| r.map(|m| *out = Some(m)).is_some()),
        };
        match r {
            Ok(true) => Ok(Stop::Done),
            Ok(false) => Ok(Stop::Budget),
            Err(StoreError::Busy) if cx.need > 0 => Ok(Stop::Owner),
            Err(StoreError::Miss) if cx.missed.is_some() => Ok(Stop::Owner),
            Err(e) => Err(e),
        }
    }

    /// Input chunks a merge reads next (per input its next `ahead` chunks to rewrite, not loaded yet), appended to
    /// `out`; nothing for a flush.
    pub fn next_reads(&mut self, ahead: usize, out: &mut Vec<(u64, u32)>) {
        if let Task::Merge { job, out: None } = self {
            job.next_reads(ahead, out);
        }
    }
}
