// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Free-space defragmentation (adr 0021 am. 33): keep whole free 1 MiB windows (meta cells, 64-block extents) available
//! on an aged shard by moving the few live blocks out of the sparsest windows.
//!
//! A sweep: (1) trigger (checked every `CHECK_NS`): less than half the free space lies in whole free windows and fewer
//! than `WANT_WINDOWS` of them exist; (2) victims = the sparsest windows (at most `WIN / 8` live blocks, no in-flight
//! write, no meta cell), their free blocks FENCED (reserved, so no allocation lands there meanwhile; bounded to an eighth
//! of the free space); (3) one pass over the extent records (`e` keys) of the shard, non-blocking; an extent lying in
//! victim windows is moved: raw read of its blocks, then in one step (between txns, no yield): the record must still be
//! the one read (else the object changed: skipped), the block crcs must verify at the old address, new blocks are
//! allocated in a partly used window (fills holes; never a whole free window or the fence), and an ordinary txn puts
//! the record with the new address and per-block crcs (salted with the new address) and frees the old blocks; (4) the
//! fence is released: the victims are whole free windows once the next checkpoint released the freed blocks.
//!
//! Crash safety: nothing new on disk. The move is a regular WAL txn (parallel commit: data crcs validated at replay, old
//! blocks held until a checkpoint passed, am. 2); the fence and the sweep live in RAM and are rebuilt by the next sweep.
//! Shared extents (`EXT_SHARED`, am. 32: refcounted, other records own the same blocks) are never moved: one move
//! must rewrite exactly the one record that owns the run.
//! Pacing: only from `Store::poll` (never inside a staged op), `MAX_JOBS` reads in flight; under client IO (own txns in
//! flight, or another queue of the device busy: `Shard::dev_quiet`) one move per `BUSY_GAP_NS`.
//!
//! Cell sweep (adr 0021 am. 51): while elastic meta growth is blocked by fragmentation (free blocks enough, no contiguous
//! cell-sized run), the sweep targets the cheapest group of adjacent windows that can hold one cell, whatever its fill
//! (a uniformly fragmented shard has no window below the `WIN / 8` threshold). A plain extent that finds no contiguous
//! destination is split over smaller holes (one record per piece, logical offsets preserved). The sweep then drains: it
//! re-fences the victims each step (moved-out blocks come back free after the checkpoint that releases them, and must
//! not be refilled), asks for the checkpoint that passes the victims' frees, and once the victims hold no allocated or
//! held block releases the fence and takes the meta cell at once (`Shard::grow_meta_cell`). An allocated block left
//! after the moves pins the victims (frees apply at submit and the fence keeps allocations out: nothing will free it):
//! the sweep gives up at once ([`Drain`]).
//!
//! Retry (am. 79): a victim window a sweep could not empty, and a chunk an evacuation gave up on, keep the allocation
//! bits they had then (`Alloc::alloc_pins`: the blocks that pinned them; the fence kept other allocations out) and are
//! skipped until one of those blocks is freed (checked every `CHECK_NS`). No timer: an idle shard never repeats a pass
//! that achieved nothing, and churn of other blocks does not re-arm it.

use super::keys::{T_EXT, ext_key_arr, onode_id_of};
use super::onode::ExtRaw;
use super::shardio::ShardStore;
use crate::BLK;
use crate::alloc::WIN;
use crate::codec::blk_crc;
use crate::dev::{BlockDev, IoBuf};
use crate::error::StoreError;
use crate::shard::{PF_TOKEN, Txn};
use crate::state::Op;
use crate::tree::{ScanCursor, ScanStatus};
use std::collections::VecDeque;

/// Ack token bit of defrag txns: never reported to the store's caller.
pub(crate) const DF_ACK: u64 = 1 << 63;
pub(crate) const CHECK_NS: u64 = 1_000_000_000;
const BUSY_GAP_NS: u64 = 10_000_000;
/// Whole free windows wanted per shard (cells and large extents); a sweep stops being triggered above it.
const WANT_WINDOWS: u64 = 64;
const MAX_VICTIMS: usize = 32;
const MAX_JOBS: usize = 4;
pub(crate) const SCAN_BATCH: usize = 256;
/// Cell-sized window groups emptied per cell sweep (one cell for the growth, one of slack).
const CELL_GROUPS: usize = 2;

/// Where the drain of a cell sweep or an evacuation stands (all its moves submitted), judged from the victims' state
/// alone: client txns in flight change nothing (their frees applied at submit, the fence keeps their allocations out).
enum Drain {
    /// Allocated blocks are left (shared, straddling or skipped extents): nothing will free them, give up.
    Pinned,
    /// Only held blocks are left: the checkpoint that passes their frees is asked for, then the readers that still pin
    /// them finish.
    Held,
    /// No allocated or held block is left.
    Empty,
}

struct Job<B> {
    key: Vec<u8>,
    val: Vec<u8>,
    pba: u64,
    n: u32,
    /// Read token while the read is in flight; `None` once its data is in `buf`.
    tok: Option<u64>,
    buf: Option<B>,
    verified: bool,
}

pub(crate) struct Defrag<B> {
    /// Sweep in progress: victim windows (sorted), fenced runs, extent cursor, moves.
    active: bool,
    victims: Vec<usize>,
    fence: Vec<(u64, u32)>,
    cur: Option<ScanCursor>,
    jobs: VecDeque<Job<B>>,
    next_ns: u64,
    seq: u64,
    /// Victim windows a sweep could not empty, with their allocated blocks then (`Alloc::alloc_pins`): skipped until one
    /// of those is freed.
    stuck: std::collections::BTreeMap<usize, Vec<(usize, u64)>>,
    /// The running sweep is a cell sweep (am. 51): split moves allowed, drain before the fence is released.
    cells: bool,
    /// Draining (cell sweep or evacuation): the newest lsn that can have freed a victim block, the checkpoint lsn the
    /// drain needs (`None` = not draining).
    drain_lsn: Option<u64>,
    /// When the drain started waiting (its first step that found the victims not empty yet; `None` = no wait).
    drain_since: Option<u64>,
    /// Evacuation of borrowed slot (adr 0021 am. 57; the fence lives in the shard: `Shard::evac_fence`).
    #[cfg(feature = "elastic")]
    evac: Option<u32>,
    /// Slots an evacuation could not empty (shared or unmovable blocks), with their allocated blocks then: skipped until
    /// one of those is freed.
    #[cfg(feature = "elastic")]
    evac_stuck: Vec<(u32, Vec<(usize, u64)>)>,
    /// Slots returned (made holes) whose free entry the pool owner still has to write: `(slot, engine block)`.
    #[cfg(feature = "elastic")]
    pub(crate) returned: Vec<(u32, u64)>,
    /// Reclaim on demand (am. 82): the owner asked for more returns (check at once); borrowed chunks the shard could
    /// give back as of the last check and its free blocks then; evacuation steps taken (progress); the
    /// `(spare, progress)` last reported to the owner and when.
    #[cfg(feature = "elastic")]
    kick: bool,
    #[cfg(feature = "elastic")]
    spare: u64,
    #[cfg(feature = "elastic")]
    spare_free: u64,
    #[cfg(feature = "elastic")]
    evac_prog: u64,
    #[cfg(feature = "elastic")]
    said: (u64, u64),
    #[cfg(feature = "elastic")]
    said_ns: u64,
    pub(crate) stats: DefragStats,
}

impl<B> Default for Defrag<B> {
    fn default() -> Self {
        Self {
            active: false,
            victims: Vec::new(),
            fence: Vec::new(),
            cur: None,
            jobs: VecDeque::new(),
            next_ns: 0,
            seq: 0,
            stuck: Default::default(),
            cells: false,
            drain_lsn: None,
            drain_since: None,
            #[cfg(feature = "elastic")]
            evac: None,
            #[cfg(feature = "elastic")]
            evac_stuck: Vec::new(),
            #[cfg(feature = "elastic")]
            returned: Vec::new(),
            #[cfg(feature = "elastic")]
            kick: false,
            #[cfg(feature = "elastic")]
            spare: 0,
            #[cfg(feature = "elastic")]
            spare_free: 0,
            #[cfg(feature = "elastic")]
            evac_prog: 0,
            #[cfg(feature = "elastic")]
            said: (0, 0),
            #[cfg(feature = "elastic")]
            said_ns: 0,
            stats: Default::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DefragStats {
    pub sweeps: u64,
    pub moved_extents: u64,
    pub moved_blocks: u64,
    /// Extents skipped: record changed meanwhile, crc mismatch at the old address, read error, no space.
    pub skipped: u64,
    /// Cell sweeps started (am. 51), cells taken at their end, sweeps given up (pinned victims, no cell to take).
    pub cell_sweeps: u64,
    pub cells_made: u64,
    pub cell_fails: u64,
    /// Extents moved as several pieces (no contiguous destination; cell sweeps and evacuations).
    pub split_moves: u64,
    /// Elastic reclaim (am. 57): evacuations started, given up, blocks they moved, borrowed chunks returned (empty ones
    /// included).
    pub evacs: u64,
    pub evac_fails: u64,
    pub evac_blocks: u64,
    pub chunks_returned: u64,
    /// The running drain (cell sweep or evacuation) as of its last step; there is no deadline, so these show a drain
    /// that cannot end (`perf dump` `flashstore_store_<core>.defrag_drain*`): 1 while it waits, 1 once the checkpoint that
    /// releases its held blocks has passed (only readers still pin them: a reader pin that never ends shows here with a
    /// wait that only grows), the held victim blocks (0 while a cell sweep waits for a freeze to end), how long it has
    /// waited (ns).
    pub drain_waiting: u64,
    pub drain_readers: u64,
    pub drain_held: u64,
    pub drain_wait_ns: u64,
}

impl DefragStats {
    /// `self` + `o` (shards of a store): counters and drain gauges summed, the drain wait the longer one.
    pub fn merged(mut self, o: &DefragStats) -> DefragStats {
        macro_rules! sum { ($($f:ident),*) => { $(self.$f += o.$f;)* } }
        sum!(
            sweeps,
            moved_extents,
            moved_blocks,
            skipped,
            cell_sweeps,
            cells_made,
            cell_fails,
            split_moves,
            evacs,
            evac_fails,
            evac_blocks,
            chunks_returned,
            drain_waiting,
            drain_readers,
            drain_held
        );
        self.drain_wait_ns = self.drain_wait_ns.max(o.drain_wait_ns);
        self
    }
}

/// Fragmented (adr 0021 am. 33): free space mostly outside whole windows, and too few whole windows.
fn fragmented(free: u64, whole: u64) -> bool {
    free >= 16 * WIN && whole < WANT_WINDOWS && whole * WIN * 2 < free
}

impl<D: BlockDev> ShardStore<D> {
    pub fn defrag_stats(&self) -> DefragStats {
        self.df.stats
    }

    /// A sweep is running (tests, `quiet`).
    pub fn defrag_active(&self) -> bool {
        self.df.active
    }

    /// One defrag step (adr 0021 am. 33). Call between txns only.
    pub fn defrag_step(&mut self, now: u64) {
        if self.sh.is_failed() {
            return;
        }
        if !self.df.active {
            if now < self.df.next_ns {
                // the owner asks for chunks, or the free space moved by a chunk: the reclaim check runs now (am. 82)
                #[cfg(feature = "elastic")]
                if self.reclaim_due() {
                    self.reclaim_check();
                }
                return;
            }
            self.df.next_ns = now + CHECK_NS;
            // what a pass gave up on is a candidate again once a block that pinned it was freed (am. 79)
            let a = &self.sh.state().alloc;
            self.df.stuck.retain(|_, p| !a.pins_freed(p));
            #[cfg(feature = "elastic")]
            self.df.evac_stuck.retain(|(_, p)| !a.pins_freed(p));
            #[cfg(feature = "elastic")]
            if self.reclaim_check() {
                return;
            }
            if self.defrag {
                self.df_start();
            }
            return;
        }
        #[cfg(feature = "elastic")]
        if self.df.evac.is_some() {
            self.evac_step(now);
            return;
        }
        // another queue of the device in use counts as client IO (adr 0533)
        let busy = self.sh.pending_units() > 0 || !self.sh.dev_quiet(now);
        if busy && now < self.df.next_ns {
            return;
        }
        self.df.next_ns = now + BUSY_GAP_NS;
        if self.df.cells {
            self.df_refence();
        }
        self.df_scan();
        self.df_moves(if busy { 1 } else { MAX_JOBS });
        if self.df.cur.is_none() && self.df.jobs.is_empty() {
            if self.df.cells {
                self.df_drain(now);
            } else {
                self.df_give_up_pinned();
                self.df_finish(now);
            }
        }
    }

    fn df_start(&mut self) {
        if self.sh.defrag_cells() && self.sh.meta_growth_blocked() && self.df_start_cells() {
            return;
        }
        let cells = self.sh.meta_cells();
        let a = &self.sh.state().alloc;
        // blocks a deallocate holds are free (adr 0642)
        if !fragmented(
            a.n_free() + self.sh.gauges().trim_held,
            self.sh.free_windows(),
        ) {
            return;
        }
        let mut cand: Vec<(u64, usize)> = (0..a.n_windows())
            .filter_map(|w| {
                // a window the deallocate in flight holds blocks of is not a victim: its completion frees them past the fence
                let b = a.window_busy(w);
                (b > 0
                    && b <= WIN / 8
                    && !a.window_reserved(w)
                    && !self.df.stuck.contains_key(&w)
                    && self.sh.trim_held_in(w) == 0)
                    .then_some((b, w))
            })
            .filter(|&(_, w)| {
                let (s, e) = (a.window_phys(w), a.window_phys(w) + WIN);
                !cells.iter().any(|&(cs, cn)| cs < e && s < cs + cn)
            })
            .collect();
        cand.sort_unstable();
        // the fence takes the victims' free blocks out of the allocator: at most an eighth of the free space,
        // never below twice the user floor while fenced (admission counts only unfenced free blocks)
        let mut budget =
            (a.n_free() / 8).min(a.n_free().saturating_sub(2 * self.sh.data_reserve()));
        let mut victims = Vec::new();
        for (b, w) in cand {
            if victims.len() == MAX_VICTIMS || WIN - b > budget {
                break;
            }
            budget -= WIN - b;
            victims.push(w);
        }
        if victims.is_empty() {
            return;
        }
        victims.sort_unstable();
        let mut fence = Vec::new();
        let a = &mut self.sh.state_mut().alloc;
        for &w in &victims {
            a.fence_window(w, &mut fence);
        }
        self.df_begin(victims, fence, false);
    }

    /// Cell sweep start (am. 51): victims = up to `CELL_GROUPS` cheapest groups of adjacent windows that can each hold
    /// one meta cell, whatever their fill. False = no such group (the plain sweep may still run).
    fn df_start_cells(&mut self) -> bool {
        let cb = self.sh.cell_blocks();
        if cb == 0 {
            return false;
        }
        let k = cb.div_ceil(WIN) as usize;
        // sorted, disjoint: one binary search per window (every window is a candidate here, not only sparse ones)
        let mut cells = self.sh.meta_cells();
        cells.sort_unstable();
        let a = &self.sh.state().alloc;
        let in_cell = |w: usize| {
            let (s, e) = (a.window_phys(w), a.window_phys(w) + WIN);
            let i = cells.partition_point(|&(cs, cn)| cs + cn <= s);
            cells.get(i).is_some_and(|&(cs, _)| cs < e)
        };
        let mut cand: Vec<(u64, usize)> = Vec::new();
        for w in 0..a.n_windows() {
            // whole windows only, physically adjacent (a group never crosses a device-expand segment)
            if (w + k) as u64 * WIN > a.len() {
                break;
            }
            let p0 = a.window_phys(w);
            let mut busy = 0;
            let ok = (w..w + k).all(|x| {
                busy += a.window_busy(x);
                !a.window_reserved(x)
                    && self.sh.trim_held_in(x) == 0
                    && !self.df.stuck.contains_key(&x)
                    && !in_cell(x)
                    && a.window_phys(x) == p0 + (x - w) as u64 * WIN
            });
            if ok && busy > 0 {
                cand.push((busy, w));
            }
        }
        cand.sort_unstable();
        // a group costs a cell's worth of free blocks: its own free blocks fenced plus one destination per live block;
        // twice the user floor stays unfenced
        let span = k as u64 * WIN;
        let mut budget = a.n_free().saturating_sub(2 * self.sh.data_reserve());
        let mut victims: Vec<usize> = Vec::new();
        for (_, w) in cand {
            if victims.len() == CELL_GROUPS * k || span > budget {
                break;
            }
            if (w..w + k).any(|x| victims.contains(&x)) {
                continue;
            }
            budget -= span;
            victims.extend(w..w + k);
        }
        if victims.is_empty() {
            return false;
        }
        victims.sort_unstable();
        let mut fence = Vec::new();
        let a = &mut self.sh.state_mut().alloc;
        for &w in &victims {
            a.fence_window(w, &mut fence);
        }
        self.df_begin(victims, fence, true);
        self.df.stats.cell_sweeps += 1;
        true
    }

    /// Start a sweep over `victims` with their fenced free runs: extent cursor from the first `e` key, `cells` = cell
    /// sweep (drain instead of ending at the last move).
    fn df_begin(&mut self, victims: Vec<usize>, fence: Vec<(u64, u32)>, cells: bool) {
        let (lo, hi) = ([T_EXT], [T_EXT + 1]);
        self.df.victims = victims;
        self.df.fence = fence;
        self.df.cur = Some(ScanCursor::new(&lo, &hi).with_readahead(8));
        self.df.active = true;
        self.df.cells = cells;
    }

    /// End of a cell sweep (am. 51): the moved-out blocks are held until a checkpoint releases them; keep fencing what
    /// comes free (nothing may refill the victims) until the victims hold no allocated or held block, then release the
    /// fence and take the meta cell before any data allocation can break the run. Pinned victims: given up, stuck.
    fn df_drain(&mut self, now: u64) {
        self.df_refence();
        match self.drain_state(now) {
            Drain::Pinned => {
                self.df_give_up_pinned();
                self.df.stats.cell_fails += 1;
                self.df_finish(now);
            }
            Drain::Held => {}
            // cells cannot be added during a freeze: next step
            Drain::Empty if self.sh.freeze_active() => self.df_wait(now, 0, false),
            Drain::Empty => {
                for (b, n) in std::mem::take(&mut self.df.fence) {
                    self.sh.unreserve(b, n);
                }
                if self.sh.grow_meta_cell() {
                    self.df.stats.cells_made += 1;
                } else {
                    self.df.stats.cell_fails += 1;
                }
                self.df_finish(now);
            }
        }
    }

    /// End of the moves: a victim with allocated blocks left (shared, straddling or skipped extents, blocks no extent
    /// record owns) is stuck with those blocks until one is freed (am. 79).
    fn df_give_up_pinned(&mut self) {
        let a = &self.sh.state().alloc;
        for &w in &self.df.victims {
            let p = a.alloc_pins(w..w + 1);
            if !p.is_empty() {
                self.df.stuck.insert(w, p);
            }
        }
    }

    /// Drain state of the victims (cell sweep or evacuation, every move submitted). Held blocks wait for the checkpoint
    /// that passes the newest victim free: every victim free was submitted before the first drain step (no allocated
    /// block is left to free later), so that lsn is fixed then; asked for at once (also under client load) and again
    /// while a checkpoint that started before that lsn was sealed ended short of it.
    fn drain_state(&mut self, now: u64) -> Drain {
        let a = &self.sh.state().alloc;
        let (alloc, live) = self.df.victims.iter().fold((0, 0), |(al, li), &w| {
            (al + a.window_alloc(w), li + a.window_live(w))
        });
        if alloc > 0 {
            return Drain::Pinned;
        }
        if live == 0 {
            return Drain::Empty;
        }
        let need = *self.df.drain_lsn.get_or_insert(self.sh.next_lsn() - 1);
        let passed = self.sh.ckpt_lsn() >= need;
        if !passed && !self.sh.ckpt_active() {
            self.sh.request_checkpoint();
        }
        // past that checkpoint the held blocks wait in limbo for the readers of older epochs
        self.df_wait(now, live, passed);
        Drain::Held
    }

    /// The drain waits: its state and age go to the stats (detection only, no deadline).
    fn df_wait(&mut self, now: u64, held: u64, readers: bool) {
        let since = *self.df.drain_since.get_or_insert(now);
        let s = &mut self.df.stats;
        s.drain_waiting = 1;
        s.drain_readers = u64::from(readers);
        s.drain_held = held;
        s.drain_wait_ns = now.saturating_sub(since);
    }

    /// Cell sweeps: fence what came free in the victims since the last step (blocks a move freed are held until a
    /// checkpoint releases them; released, they must not become the destination of the next move).
    fn df_refence(&mut self) {
        let mut fence = std::mem::take(&mut self.df.fence);
        let a = &mut self.sh.state_mut().alloc;
        for &w in &self.df.victims {
            a.fence_window(w, &mut fence);
        }
        self.df.fence = fence;
    }

    /// Does the run `[pba, pba+n)` lie in victim windows only?
    fn df_victim(&self, pba: u64, n: u32) -> bool {
        let a = &self.sh.state().alloc;
        let (Some(w0), Some(w1)) = (a.window_of(pba), a.window_of(pba + n as u64 - 1)) else {
            return false;
        };
        (w0..=w1).all(|w| self.df.victims.binary_search(&w).is_ok())
    }

    /// Is engine block `blk` in a victim window?
    fn df_in_victim(&self, blk: u64) -> bool {
        self.sh
            .state()
            .alloc
            .window_of(blk)
            .is_some_and(|w| self.df.victims.binary_search(&w).is_ok())
    }

    /// Next batch of extent records: queue the moves (non-blocking; a cold leaf ends the batch, its load is queued).
    fn df_scan(&mut self) {
        if self.df.jobs.len() >= 4 * MAX_JOBS {
            return;
        }
        let Some(mut cur) = self.df.cur.take() else {
            return;
        };
        let mut found: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let r = self.sh.scan(&mut cur, SCAN_BATCH, usize::MAX, &mut |k, v| {
            if k.len() == 14 && ExtRaw::new(v).is_some() {
                found.push((k.to_vec(), v.to_vec()));
            }
        });
        for (k, v) in found {
            let e = ExtRaw::new(&v).expect("validated");
            let (pba, n) = (e.pba(), e.len());
            // a shared run (am. 32) or one reaching past the victims stays: it pins its victims (`df_give_up_pinned`)
            if !e.shared() && self.df_victim(pba, n) {
                self.df.jobs.push_back(Job {
                    key: k,
                    val: v,
                    pba,
                    n,
                    tok: None,
                    buf: None,
                    verified: false,
                });
            }
        }
        self.df.cur = match r {
            Ok(ScanStatus::Done) => None,
            Ok(ScanStatus::More) | Err(StoreError::Miss) => Some(cur),
            Err(_) => None, // unreadable leaf: end the sweep early (the op that needs it reports it)
        };
    }

    /// Start reads for queued moves, complete the ones whose data is in.
    fn df_moves(&mut self, max_done: usize) {
        let inflight = self.df.jobs.iter().filter(|j| j.tok.is_some()).count();
        let mut can_start = MAX_JOBS.saturating_sub(inflight);
        let mut done = 0;
        let mut i = 0;
        while i < self.df.jobs.len() {
            let j = &mut self.df.jobs[i];
            if j.tok.is_none() && j.buf.is_none() {
                if can_start == 0 {
                    i += 1;
                    continue;
                }
                self.tok += 1;
                let t = self.tok & (PF_TOKEN - 1);
                match self.sh.submit_read(j.pba, j.n, t, false) {
                    Ok(()) => {
                        self.df.jobs[i].tok = Some(t);
                        can_start -= 1;
                    }
                    Err(StoreError::Busy) => {} // device queue full or no DMA buffer to spare: next step
                    Err(_) => {
                        self.df.jobs.remove(i);
                        self.df.stats.skipped += 1;
                        continue;
                    }
                }
                i += 1;
                continue;
            }
            if let Some(t) = j.tok {
                match self.reads.remove(&t) {
                    None => {
                        i += 1;
                        continue;
                    }
                    Some(Ok(b)) => {
                        let j = &mut self.df.jobs[i];
                        j.buf = Some(b);
                        j.tok = None;
                    }
                    Some(Err(_)) => {
                        self.df.jobs.remove(i);
                        self.df.stats.skipped += 1;
                        continue;
                    }
                }
            }
            if done == max_done {
                i += 1;
                continue;
            }
            match self.df_commit(i) {
                Ok(true) => {
                    self.df.jobs.remove(i);
                    done += 1;
                }
                Ok(false) => i += 1, // retry later (record page cold, device or WAL busy)
                Err(()) => {
                    self.df.jobs.remove(i);
                    self.df.stats.skipped += 1;
                }
            }
        }
    }

    /// Move job `i` (data in): `Ok(true)` = txn submitted, `Ok(false)` = not now, `Err` = skip it.
    fn df_commit(&mut self, i: usize) -> std::result::Result<bool, ()> {
        let (key, val, pba, n) = {
            let j = &self.df.jobs[i];
            (j.key.clone(), j.val.clone(), j.pba, j.n)
        };
        let mut cur = Vec::new();
        match self.sh.get(&key, &mut cur) {
            Ok(true) if cur == val => {}
            Ok(_) => return Err(()), // removed or rewritten since it was read: nothing to move
            Err(StoreError::Miss) => return Ok(false),
            Err(_) => return Err(()),
        }
        let e = ExtRaw::new(&val).ok_or(())?;
        let data = self.df.jobs[i].buf.as_ref().expect("data in").as_slice();
        if !self.df.jobs[i].verified
            && (0..n).any(|b| {
                blk_crc(
                    pba + b as u64,
                    &data[b as usize * BLK..(b as usize + 1) * BLK],
                ) != e.crc(b)
            })
        {
            return Err(()); // damaged at the old address: leave it for scrub / repair
        }
        self.df.jobs[i].verified = true;
        let plain = e.comp().is_none();
        let new = match self.df_alloc(n) {
            Ok(b) => b,
            Err(StoreError::Busy) => return Ok(false),
            Err(_) if self.df_splits() && plain && n > 1 => {
                return self.df_commit_split(i, &key, &val);
            }
            Err(_) => return Err(()),
        };
        if self.df_in_victim(new) {
            // cannot happen while the fence holds (its blocks are reserved); never move into a victim
            self.sh.unreserve(new, n);
            return Err(());
        }
        let data = self.df.jobs[i].buf.as_ref().expect("data in").as_slice();
        let crcs: Vec<u32> = (0..n)
            .map(|b| {
                blk_crc(
                    new + b as u64,
                    &data[b as usize * BLK..(b as usize + 1) * BLK],
                )
            })
            .collect();
        let mut nv = val.clone();
        nv[2..10].copy_from_slice(&new.to_le_bytes());
        for (b, c) in crcs.iter().enumerate() {
            nv[10 + 4 * b..14 + 4 * b].copy_from_slice(&c.to_le_bytes());
        }
        self.df.seq += 1;
        let mut t: Txn<D::Buf> = Txn::new(DF_ACK | self.df.seq);
        t.ops.push(Op::Put(key.clone(), nv));
        let buf = self.df.jobs[i].buf.take().expect("data in");
        t.data.push((new, buf));
        t.data_crcs.push(crcs);
        t.frees.push((pba, n));
        t.sys = true;
        self.forget_freed(&t.frees);
        match self.sh.submit(t) {
            Ok(lsn) => {
                // reads of the object wait until the new blocks are durable (like after any data write)
                if let Some(id) = onode_id_of(&key) {
                    self.note_write(id, lsn);
                }
                self.df.stats.moved_extents += 1;
                self.df.stats.moved_blocks += n as u64;
                Ok(true)
            }
            Err((StoreError::Busy | StoreError::WalFull | StoreError::Miss, mut txn)) => {
                // Submission did not change state. Retain the original read DMA allocation;
                // CRCs for the next destination are recomputed after its address is allocated.
                self.df.jobs[i].buf = Some(txn.data.pop().expect("rejected move buffer").1);
                self.sh.unreserve(new, n);
                Ok(false)
            }
            Err(_) => {
                self.sh.unreserve(new, n);
                Err(())
            }
        }
    }

    /// Move job `i` (data in, verified, record unchanged) as several pieces (cell sweep, plain extent, no contiguous
    /// destination, am. 51): each piece takes the longest hole run left (halving down to one block) and becomes its own
    /// record at its logical offset (the first one keeps the key), with its own blocks and crcs; the old run is freed whole.
    /// Same contract as the plain move: one parallel-commit txn, reads wait for the new blocks' durability.
    fn df_commit_split(
        &mut self,
        i: usize,
        key: &[u8],
        val: &[u8],
    ) -> std::result::Result<bool, ()> {
        let e = ExtRaw::new(val).ok_or(())?;
        let (pba, n) = (e.pba(), e.len());
        let id = onode_id_of(key).ok_or(())?;
        let lblk = u32::from_be_bytes(key.get(10..14).ok_or(())?.try_into().map_err(|_| ())?);
        let mut pieces: Vec<(u32, u64, u32)> = Vec::new(); // (offset in the run, new block, blocks)
        let (mut off, mut want) = (0u32, n);
        while off < n {
            let len = want.min(n - off);
            match self.df_alloc(len) {
                Ok(b) => {
                    pieces.push((off, b, len));
                    off += len;
                }
                Err(_) if len > 1 => want = len / 2,
                Err(_) => {
                    for &(_, b, l) in &pieces {
                        self.sh.unreserve(b, l);
                    }
                    return Err(());
                }
            }
        }
        let into_victim = pieces.iter().any(|&(_, b, _)| self.df_in_victim(b));
        if into_victim {
            // cannot happen while the fence holds (refenced every step); never move into a victim
            for &(_, b, l) in &pieces {
                self.sh.unreserve(b, l);
            }
            return Err(());
        }
        // the copies are store metadata IO of the DMA budget (adr 0175 am. 4): refused = the job keeps its read buffer
        // and moves at a later step, the pieces go back
        let mut bufs = Vec::with_capacity(pieces.len());
        for &(_, _, l) in &pieces {
            match self.sh.try_alloc_io(l as usize) {
                Some(b) => bufs.push(b),
                None => {
                    for &(_, b, l) in &pieces {
                        self.sh.unreserve(b, l);
                    }
                    return Ok(false);
                }
            }
        }
        self.df.seq += 1;
        let mut t: Txn<D::Buf> = Txn::new(DF_ACK | self.df.seq);
        let data = self.df.jobs[i].buf.as_ref().expect("data in").as_slice();
        for (&(o, b, l), mut buf) in pieces.iter().zip(bufs) {
            let src = &data[o as usize * BLK..(o + l) as usize * BLK];
            let crcs: Vec<u32> = (0..l as usize)
                .map(|x| blk_crc(b + x as u64, &src[x * BLK..(x + 1) * BLK]))
                .collect();
            let mut nv = e.slice_encode(o, l);
            nv[2..10].copy_from_slice(&b.to_le_bytes());
            for (x, c) in crcs.iter().enumerate() {
                nv[10 + 4 * x..14 + 4 * x].copy_from_slice(&c.to_le_bytes());
            }
            t.ops.push(Op::Put(ext_key_arr(id, lblk + o).to_vec(), nv));
            buf.copy_from_slice(src);
            t.data.push((b, buf));
            t.data_crcs.push(crcs);
        }
        t.frees.push((pba, n));
        t.sys = true;
        self.forget_freed(&t.frees);
        match self.sh.submit(t) {
            Ok(lsn) => {
                self.note_write(id, lsn);
                self.df.stats.moved_extents += 1;
                self.df.stats.moved_blocks += n as u64;
                self.df.stats.split_moves += 1;
                Ok(true)
            }
            Err((err, _)) => {
                // nothing changed: the job keeps its read buffer, the pieces go back
                for &(_, b, l) in &pieces {
                    self.sh.unreserve(b, l);
                }
                match err {
                    StoreError::Busy | StoreError::WalFull | StoreError::Miss => Ok(false),
                    _ => Err(()),
                }
            }
        }
    }

    /// End of a sweep: give the fence back (the victims are whole free windows once the freed blocks are released).
    fn df_finish(&mut self, now: u64) {
        for (b, n) in std::mem::take(&mut self.df.fence) {
            self.sh.unreserve(b, n);
        }
        self.df.victims.clear();
        self.df.active = false;
        self.df.cells = false;
        self.df.drain_lsn = None;
        self.df.drain_since = None;
        let s = &mut self.df.stats;
        (
            s.drain_waiting,
            s.drain_readers,
            s.drain_held,
            s.drain_wait_ns,
        ) = (0, 0, 0, 0);
        self.df.stats.sweeps += 1;
        self.df.next_ns = now + CHECK_NS;
    }

    /// Move destination: a hole of a partly used window (defrag), anywhere outside the fenced chunk (evacuation).
    fn df_alloc(&mut self, n: u32) -> crate::error::Result<u64> {
        #[cfg(feature = "elastic")]
        if self.df.evac.is_some() {
            return self.sh.alloc_evac(n);
        }
        self.sh.alloc_dense(n)
    }

    /// May a plain extent without a contiguous destination be split (cell sweeps, evacuations)?
    fn df_splits(&self) -> bool {
        #[cfg(feature = "elastic")]
        if self.df.evac.is_some() {
            return true;
        }
        self.df.cells
    }
}

// ----------------------------------------------------------------------------------------------------------------
// Elastic reclaim (adr 0021 am. 57, step 4; am. 82: live data moves only on demand)
#[cfg(feature = "elastic")]
impl<D: BlockDev> ShardStore<D> {
    /// Reclaim check (every `CHECK_NS` with no sweep running, at once when `reclaim_due`): return every borrowed chunk
    /// that is empty (no allocated, reserved or held block: a durable checkpoint passed its last free) while the shard
    /// keeps its headroom without it (`Shard::reclaim_room`); count the chunks it could give back on demand (`spare`,
    /// `spare_walk`); while the pool owner asks for returns (`reclaim_owed`), start evacuating the cheapest chunk with
    /// live blocks. Live data never moves otherwise. True = a return or an evacuation happened (no defrag sweep this
    /// round).
    fn reclaim_check(&mut self) -> bool {
        self.df.kick = false;
        if !self.sh.reclaim_on() {
            self.df.spare = 0;
            self.df.spare_free = self.sh.free_blocks();
            return false;
        }
        let cb = self.sh.dir().chunk_blocks;
        let cells = self.sh.meta_cells();
        let mut acted = false;
        // (live blocks, blocks in whole free windows, slot)
        let mut cand: Vec<(u64, u64, u32)> = Vec::new();
        for k in 0..self.sh.state().alloc.lent_slots() as u32 {
            let (p, busy) = self.sh.lent_slot(k);
            if p == crate::alloc::HOLE {
                continue;
            }
            let whole = self.sh.slot_whole_free(k);
            if busy == 0 && self.sh.reclaim_room(whole) && self.sh.lend_remove(k) {
                self.df.returned.push((k, p));
                self.df.stats.chunks_returned += 1;
                acted = true;
                continue;
            }
            // a meta cell pins its chunk (tree pages are addressed and sealed by block: no move); it is given back
            // when empty and the chunk returns then
            if self.df.evac_stuck.iter().any(|e| e.0 == k)
                || cells.iter().any(|&(s, n)| s < p + cb && p < s + n)
            {
                continue;
            }
            cand.push((busy, whole, k));
        }
        // cheapest first: the live blocks to move plus the whole free windows the shard gives up with the chunk (an
        // empty chunk that is the shard's headroom comes last)
        cand.sort_unstable_by_key(|&(busy, whole, k)| (busy + whole, busy, k));
        self.df.spare = self.spare_walk(&cand);
        if self.df.spare > 0
            && self.reclaim_owed() > 0
            && let Some(&(_, _, k)) = cand.iter().find(|c| c.0 > 0)
            && let Some(ws) = self.sh.evac_fence(k)
        {
            let (lo, hi) = ([T_EXT], [T_EXT + 1]);
            self.df.victims = ws.collect();
            self.df.cur = Some(ScanCursor::new(&lo, &hi).with_readahead(8));
            self.df.active = true;
            self.df.evac = Some(k);
            self.df.stats.evacs += 1;
            // a write waits for this chunk: the first step runs at once, not a reclaim check interval later
            self.df.next_ns = 0;
            acted = true;
        }
        self.df.spare_free = self.sh.free_blocks();
        acted
    }

    /// Chunks the shard could give back on demand, evacuating `cand` in order (`(live, whole free, slot)`): the live blocks
    /// of a chunk land in holes of partly used windows elsewhere while there are any (`Shard::alloc_evac`), in whole free
    /// windows after; the empty chunk goes back if the shard keeps `Shard::reclaim_keep` in whole free windows without
    /// it, else it stays as that headroom (its windows whole free: a shard whose free space is all holes builds its
    /// headroom first). Stops at the first chunk whose live blocks have nowhere to go.
    fn spare_walk(&self, cand: &[(u64, u64, u32)]) -> u64 {
        let cb = self.sh.dir().chunk_blocks;
        let keep = self.sh.reclaim_keep();
        let mut room = self.sh.free_windows() * WIN;
        let mut holes = self.sh.free_blocks().saturating_sub(room);
        let mut spare = 0;
        for &(busy, whole, _) in cand {
            // the chunk's own holes are fenced with it
            holes = holes.saturating_sub(cb - busy - whole);
            let land = busy.min(holes);
            holes -= land;
            let over = busy - land;
            if room < whole + over {
                break;
            }
            room -= over;
            if room >= keep + whole {
                room -= whole;
                spare += 1;
            } else {
                room += cb - whole;
            }
        }
        spare
    }

    /// Run the reclaim check before its interval: the owner asked for returns, or the free blocks (whole windows and
    /// holes: both decide where live blocks land) moved by a chunk since the last check (the reported spare would be off
    /// by a chunk).
    fn reclaim_due(&self) -> bool {
        self.sh.lend.on
            && (self.df.kick
                || self.sh.free_blocks().abs_diff(self.df.spare_free) >= self.sh.dir().chunk_blocks)
    }

    /// The pool owner asks for more returns (`Size`): check at the next step.
    pub(crate) fn reclaim_kick(&mut self) {
        self.df.kick = true;
    }

    /// Returns the pool owner asked of this shard and it has not made yet.
    fn reclaim_owed(&self) -> u64 {
        self.sh
            .lend
            .target
            .saturating_sub(self.df.stats.chunks_returned)
    }

    /// `(spare chunks, evacuation progress)` to report to the pool owner, if due: the spare changed, or the progress did
    /// and the last report is a reclaim check interval old.
    pub(crate) fn spare_report(&mut self, now: u64) -> Option<(u64, u64)> {
        let cur = (self.df.spare, self.df.evac_prog);
        if cur == self.df.said || (cur.0 == self.df.said.0 && now < self.df.said_ns + CHECK_NS) {
            return None;
        }
        self.df.said = cur;
        self.df.said_ns = now;
        Some(cur)
    }

    /// One evacuation step: paced by bytes moved (`reclaim_mbps`), scan + one move, then drain and return. The shard
    /// asking the pool for space meanwhile, or the owner taking its ask back (no shard waits any more), aborts it (the
    /// chunk stays).
    fn evac_step(&mut self, now: u64) {
        if !self.sh.reclaim_on() || self.reclaim_owed() == 0 {
            // stop, the chunk stays (reads in flight are reaped first)
            if self.df_drop_jobs() {
                self.evac_finish(now, None);
            }
            return;
        }
        if now < self.df.next_ns {
            return;
        }
        self.df.evac_prog += 1;
        let b0 = self.df.stats.moved_blocks;
        self.df_scan();
        self.df_moves(1);
        let moved = self.df.stats.moved_blocks - b0;
        self.df.stats.evac_blocks += moved;
        self.df.next_ns = now + moved * self.sh.reclaim_ns_per_block();
        if self.df.cur.is_none() && self.df.jobs.is_empty() {
            self.evac_drain(now);
        }
    }

    /// After the moves: once no allocated or held block is left in the chunk, return it (the slot becomes a hole here,
    /// the pool owner writes the free entry: `returned`). Pinned blocks: given up, the slot is stuck until one is freed.
    fn evac_drain(&mut self, now: u64) {
        match self.drain_state(now) {
            Drain::Pinned => self.evac_finish(now, Some(false)),
            Drain::Held => {}
            Drain::Empty => self.evac_finish(now, Some(true)),
        }
    }

    /// End of an evacuation: the fence goes back. `Some(true)` = the chunk is empty: return it if the shard still has the
    /// room, else it stays as the shard's headroom (whole free windows, `spare_walk`); `Some(false)` = given up (stuck);
    /// `None` = aborted (the shard wants space, or nobody waits any more).
    fn evac_finish(&mut self, now: u64, ret: Option<bool>) {
        let k = self.df.evac.take().expect("evacuating");
        self.sh.evac_unfence();
        if ret == Some(true)
            && self.sh.reclaim_on()
            && self.sh.reclaim_room(self.sh.slot_whole_free(k))
        {
            let (p, _) = self.sh.state().alloc.lent_slot(k as usize);
            if self.sh.lend_remove(k) {
                self.df.returned.push((k, p));
                self.df.stats.chunks_returned += 1;
            } else {
                self.df.stats.evac_fails += 1;
            }
        } else if ret == Some(false) {
            self.df.stats.evac_fails += 1;
            let p = self.slot_pins(k);
            self.df.evac_stuck.push((k, p));
        }
        self.df.cur = None;
        self.df_finish(now);
        // what the shard can still give changed: count it again at once (and serve a further ask)
        self.df.kick = true;
    }

    /// Allocated blocks of borrowed slot `k` (`Alloc::alloc_pins`; none for a hole).
    fn slot_pins(&self, k: u32) -> Vec<(usize, u64)> {
        let a = &self.sh.state().alloc;
        let (p, _) = a.lent_slot(k as usize);
        let Some(w0) = (p != crate::alloc::HOLE).then(|| a.window_of(p)).flatten() else {
            return Vec::new();
        };
        let nw = (self.sh.dir().chunk_blocks / WIN) as usize;
        a.alloc_pins(w0..w0 + nw)
    }

    /// Drop the queued moves; a read in flight is reaped first (its result must not stay in `reads`). True = none left.
    fn df_drop_jobs(&mut self) -> bool {
        let reads = &mut self.reads;
        self.df
            .jobs
            .retain(|j| j.tok.is_some_and(|t| reads.remove(&t).is_none()));
        self.df.jobs.is_empty()
    }

    /// An evacuation is running (tests).
    pub fn evac_active(&self) -> bool {
        self.df.evac.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::{SimClock, SimConfig, SimDev, SimDisk};
    use crate::layout::{MkfsParams, mkfs};
    use crate::obj::{OTxn, Store, StoreCfg};
    use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};

    #[test]
    fn rejected_move_keeps_original_read_buffer_and_releases_destination() {
        let disk = SimDisk::new(SimConfig::new(32 << 20));
        mkfs(
            &mut disk.queue(),
            &mut SimClock::default(),
            &MkfsParams {
                shards: 1,
                wal_blocks: 1024,
                align_blocks: 1,
                meta_pct: 8,
                ..Default::default()
            },
        )
        .unwrap();
        let (mut st, _) =
            Store::mount(|| disk.queue(), SimClock::default(), StoreCfg::default()).unwrap();
        let c = CollT::Pg(SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        });
        let o = Ghobject::new(
            Hobject::new(b"move-reject", SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        );
        let data = vec![0x63; BLK];
        let mut txn = OTxn::new();
        txn.mkcoll(c);
        txn.write(c, &o, 0, &data);
        st.commit(&txn).unwrap();
        st.checkpoint().unwrap();
        drop(st);
        let mut cfg = StoreCfg::default();
        cfg.shard.dirty_hard_pages = 0; // force submit's Busy after a destination was allocated
        cfg.shard.auto_ckpt = false;
        let (mut st, _) = Store::mount(|| disk.queue(), SimClock::default(), cfg).unwrap();
        let s: &mut ShardStore<SimDev> = &mut st.shards[0];
        let mut cur = ScanCursor::new(&[T_EXT], &[T_EXT + 1]);
        let mut found = None;
        while !cur.done {
            match s.sh.scan(&mut cur, 32, usize::MAX, &mut |k, v| {
                found = Some((k.to_vec(), v.to_vec()));
            }) {
                Ok(_) => {}
                Err(StoreError::Miss) => {
                    s.pump(&mut st.clk).unwrap();
                    s.idle(&mut st.clk);
                }
                Err(e) => panic!("extent scan: {e:?}"),
            }
        }
        let (key, val) = found.unwrap();
        let e = ExtRaw::new(&val).unwrap();
        let (pba, n) = (e.pba(), e.len());
        let base = data.as_ptr();
        s.df.jobs.push_back(Job {
            key,
            val,
            pba,
            n,
            tok: None,
            buf: Some(data),
            verified: false,
        });
        let free = s.sh.state().alloc.n_free();
        for _ in 0..3 {
            assert_eq!(s.df_commit(0), Ok(false));
            let job = &s.df.jobs[0];
            assert!(job.verified);
            assert_eq!(job.buf.as_ref().unwrap().as_ptr(), base);
            assert_eq!(job.buf.as_ref().unwrap(), &vec![0x63; BLK]);
            assert_eq!(s.sh.state().alloc.n_free(), free);
        }
    }
}
