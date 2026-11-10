// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Shard side of the omap LSM engine (adr 0610 phase 2a, am. 3 helper jobs): mount (manifest load, WAL replay into the
//! memtable), the flush / merge driver, run block reads through the [`RunCache`], the manifest txn and the reads the
//! object layer makes.
//!
//! Jobs: one flush and one merge may be in progress at once (slots [`FLUSH`], [`MERGE`]; the flush is started and
//! handed out first). A job is an [`OlsmJob`]: a [`Task`] with its [`Ctx`] (leased blocks, written blocks, supplied input
//! chunks). The owner prepares a round (queues the blocks written so far for its device, leases blocks, reads the
//! chunk the merge missed and the read-ahead), then the round runs on a helper core (multi-core OSD: the job crosses the
//! adr 0534 completion-mesh lane, [`Shard::olsm_take`] / [`Shard::olsm_return`]) or on the owner in bounded steps per
//! poll (single core, helpers stopping). The owner keeps allocation, device IO, the manifest txn and the engine state;
//! the helper does the CPU work (entry encoding, crcs, blooms, page index, k-way merge, chunk checks).
//!
//! Durability: an omap op is durable with its WAL record. The WAL floor ([`Shard::wal_floor`]) stays at the oldest op
//! still only in a memtable, so a checkpoint never releases it. A flush or merge writes its run blocks into reserved
//! extents (nothing references them: a crash leaves free space), waits until every write landed, then submits ONE
//! manifest txn: run records (tree tag [`T_LSM`]), `flushed_lsn`, the written extents (`Txn::olsm`, reserved ->
//! allocated with their block crcs) and the freed merge inputs (`frees`: held until a checkpoint passed them and every
//! reader epoch older than the free ended). The engine state switches at that submit (state is visible from apply):
//! the frozen memtable leaves only once its run is in the manifest record of the same lsn order, so the checkpoint
//! that releases the ring below the new floor always carries the manifest record. Where a round runs changes none of
//! this: the helper never touches the device or the allocator.
//!
//! Memory (adr 0175): the active memtable freezes at `mt_soft` bytes or when the floor it holds pins the checkpoint
//! ring share; while one frozen memtable is in flight and the active one reached `mt_soft`, records with omap ops are
//! refused `Busy` (the caller parks them like any backpressure and retries on store progress; nothing fails or times
//! out). Space debt parks records only while a merge runs and physical headroom is low or a lease has waited
//! since the last GC pick (proposed ADR 0662-omap-physical-pressure-admission). Routine GC still follows its
//! logical space target. The
//! frozen memtable stays in the engine while its flush is away. A job away holds at most its lease of written
//! blocks and its read-ahead of input chunks ([`OlsmDrv::lease_blocks`], [`OlsmDrv::ahead`]).

use super::*;
use crate::olsm::cache::RunCache;
use crate::olsm::job::MergeJob;
use crate::olsm::manifest::RunDesc;
use crate::olsm::remote::{Ctx, Stop, Task};
use crate::olsm::{ChunkRead, Manifest, Olsm};
use bytes::Bytes;
use std::collections::HashSet;

/// Device writes of run blocks (id = job slot).
pub(super) const K_OLSM: u64 = 10 << 56;
/// Device reads of run blocks (id = read part, see [`OlsmDrv::parts`]).
pub(super) const K_OREAD: u64 = 11 << 56;

/// Tree tag of the manifest records: `l R <run id be64>` = [`RunDesc`], `l F` = `flushed_lsn` (le64). Outside the object
/// layer's key space (its tags are listed in `obj::keys`).
pub const T_LSM: u8 = b'l';
const SUB_RUN: u8 = b'R';
const SUB_FLUSHED: u8 = b'F';

/// Key prefix of the run records (`+ run id be64`).
pub const LSM_RUN_PREFIX: [u8; 2] = [T_LSM, SUB_RUN];

fn run_key(id: u64) -> Vec<u8> {
    let mut k = LSM_RUN_PREFIX.to_vec();
    k.extend_from_slice(&id.to_be_bytes());
    k
}

pub(super) const FLUSHED_KEY: [u8; 2] = [T_LSM, SUB_FLUSHED];

/// Job slots.
const FLUSH: usize = 0;
const MERGE: usize = 1;

/// Blocks of one bounded free-space walk per driver pass (`olsm_frag_holes_lt16`; 64 allocator words).
const FRAG_WINDOW: u64 = 4096;

/// A flush or merge of one shard as it crosses cores (adr 0534 lane): no store, allocator or device handle inside.
#[derive(Debug)]
pub struct OlsmJob {
    id: CompactionId,
    slot: u8,
    task: Task,
    cx: Ctx,
    /// A store error of the round (corrupt input chunk); the owner fails the shard with it.
    err: Option<StoreError>,
}

impl OlsmJob {
    fn new(id: CompactionId, slot: u8, task: Task) -> OlsmJob {
        OlsmJob {
            id,
            slot,
            task,
            cx: Ctx::default(),
            err: None,
        }
    }

    pub fn id(&self) -> CompactionId {
        self.id
    }

    /// One bounded slice of the round (at most one output chunk sealed or moved). `true` = the round ended (finished,
    /// or the owner must lease blocks / supply a chunk): send the job back.
    pub fn step(&mut self) -> bool {
        if self.err.is_some() {
            return true;
        }
        match self.task.round(&mut self.cx, 1) {
            Ok(Stop::Budget) => false,
            Ok(Stop::Done | Stop::Owner) => true,
            Err(e) => {
                self.err = Some(e);
                true
            }
        }
    }
}

/// A run block read in flight, in parts of at most the device transfer size.
#[derive(Debug)]
struct Rd {
    blk: u64,
    nblk: u32,
    /// Parts of at most the transfer size; `sent` of them are submitted.
    n: usize,
    sent: usize,
    left: usize,
    /// One part: its buffer, zero-copy. More parts: each is copied into `asm` as it lands and its DMA buffer freed, so
    /// a read never holds more than one transfer of in-flight IO memory while it waits for the next (adr 0175 am. 4).
    one: Option<Bytes>,
    asm: Vec<u8>,
    epoch: u64,
    to: ReadTo,
}

/// Where a completed run block read goes.
#[derive(Clone, Copy, Debug)]
enum ReadTo {
    /// The run cache (object layer reads), with the cache token.
    Cache(u64),
    /// Speculative cache read, retaining the slot accounting until the last part lands.
    Prefetch(u64),
    /// A job's input chunk: the slot, the job and the extent. A completion after the job left the slot is dropped (the
    /// extent may be freed and rewritten by then).
    Job(usize, CompactionId, (u64, u32)),
}

/// Counters (`ShardStats::olsm`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OlsmStats {
    pub flushes: u64,
    pub merges: u64,
    pub written_blocks: u64,
    pub freed_blocks: u64,
    /// Lease attempts that found no space (below the sys floor or held for a checkpoint).
    pub alloc_waits: u64,
    /// Manifest txns refused (Busy / WalFull / Miss) and resubmitted.
    pub man_retries: u64,
    /// Records with omap ops refused while the memtables were full (`busy[10]`).
    pub throttled: u64,
    /// Omap records refused under physical pressure while space debt and a merge were present (`busy[10]`).
    pub space_throttled: u64,
    pub reads: u64,
    pub read_blocks: u64,
    /// Job rounds handed to a helper core / run on the owner.
    pub helper_rounds: u64,
    pub inline_rounds: u64,
    /// Garbage-driven merges installed and the fence-only garbage they rewrote away.
    pub gc_merges: u64,
    /// Garbage-driven jobs that atomically installed a bounded prefix and retained suffix runs.
    pub gc_prefixes: u64,
    /// Finished merges whose manifest txn the store refused as too large: dropped unpublished (run set unchanged),
    /// later merges take at most half its inputs ([`Shard::olsm_refused`]).
    pub merges_refused: u64,
    pub gc_bytes_reclaimed: u64,
    /// Chunks shorter than [`crate::olsm::CHUNK_MAX`] blocks written by flush/merge (the chunk-to-extent path).
    pub chunks_lt16: u64,
    /// Gauges of the last driver pass.
    pub space_live_bytes: u64,
    pub space_used_bytes: u64,
    pub space_garbage_bytes: u64,
    pub frag_holes_lt16: u64,
    pub runs: u64,
    pub mem_bytes: u64,
    /// Partitions and candidates the merge selection looked at (adr 0610 am. 6): the owner's pick cost.
    pub pick_visits: u64,
    pub scan_prefetch: crate::olsm::cache::PrefetchStats,
    pub scan_prefetch_inflight_slots: u64,
    /// Mode gauges (0 or 1 per shard). Store counters sum fixed/adaptive shard counts and logical
    /// future-chunk windows across shards; disabled shards contribute zero. Grow/shrink counts are actual changes.
    pub scan_prefetch_fixed: u64,
    pub scan_prefetch_adaptive: u64,
    pub scan_prefetch_window: u64,
    pub scan_prefetch_grows: u64,
    pub scan_prefetch_shrinks: u64,
}

/// One job slot.
#[derive(Debug, Default)]
struct Slot {
    /// The job while on the owner (`None` while away or when the slot is free).
    job: Option<Box<OlsmJob>>,
    /// The job is on a helper core.
    away: Option<CompactionId>,
    /// The round is prepared (lease and needed chunk present): hand it out or step it.
    ready: bool,
    /// Something changed for the job on the owner (new, returned, a chunk read completed, a lease or read waits for
    /// room, helpers switched): prepare it at the next driver pass.
    wake: bool,
    /// Extents the job wrote (for its manifest txn).
    written: Vec<Extent>,
    /// Writes of the job in the driver queue / in flight.
    queued: usize,
    w_inflight: usize,
    /// Input chunk reads in flight, and completed ones not handed to the job yet.
    reads: HashSet<(u64, u32)>,
    pre: HashMap<(u64, u32), Bytes>,
    /// Blocks the job has leased (gauge `olsm_space_used_bytes`; the helper never allocates, so this stays the value of
    /// the last owner-side prepare).
    lease: u32,
}

impl Slot {
    fn free(&self) -> bool {
        self.job.is_none() && self.away.is_none()
    }
    /// The job in the slot, on the owner or away.
    fn id(&self) -> Option<CompactionId> {
        self.job.as_ref().map(|j| j.id).or(self.away)
    }
    fn landed(&self) -> bool {
        self.queued == 0 && self.w_inflight == 0
    }
}

#[derive(Debug)]
pub(super) struct OlsmDrv {
    slots: [Slot; 2],
    /// Run block writes not submitted yet (each at most the device transfer size), with their slot.
    wq: VecDeque<(u64, Bytes, usize)>,
    cache: RunCache,
    /// The run cache's own share of the shard's cache budget (`mem / 2`); it may borrow more from the tree budget.
    own_cap: usize,
    /// Reads not started yet (no device queue room for all their parts), in order: `(blk, nblk, to, reader pin)`, sent
    /// at a later driver pass ([`Shard::olsm_send`]).
    unsent: VecDeque<(u64, u32, ReadTo, u64)>,
    /// Reads in flight by read id.
    rds: HashMap<u64, Rd>,
    /// The read whose parts are being submitted, one DMA buffer each ([`Shard::olsm_send`]).
    sending: Option<u64>,
    next_rd: u64,
    /// Read part tag -> (read id, part index).
    parts: HashMap<u64, (u64, usize)>,
    next_part: u64,
    prefetch_slots: usize,
    /// Actual outstanding speculative parts; admission retains all parts until the whole chunk lands.
    prefetch_pending_parts: usize,
    adaptive: crate::olsm::cache::AdaptivePrefetch,
    /// Freeze size of the active memtable (bytes, [`Memtable::bytes`]).
    pub(super) mt_soft: usize,
    /// Admission refused a record for ring room while a memtable holds the WAL floor: freeze it at the next driver pass
    /// (one pass: refused records ask again every poll).
    pub(super) want_freeze: bool,
    /// Rounds go to helper cores (set per poll by the OSD: more than one core, not stopping).
    helpers: bool,
    /// `alloc_waits` at the last space-pressure GC pick (`alloc_waits` grew => pressure).
    gc_wait_mark: u64,
    /// Inputs a merge takes at most since a manifest txn was refused as too large (`usize::MAX`: none was;
    /// [`Shard::olsm_refused`]).
    refused_inputs: usize,
    /// Blocks of the largest demand chunk read refused for queue room since the last wake (0: none): its reader waits in
    /// `miss_wait` with no read of its own in flight, so the first driver pass with that room wakes the shard.
    room_wait: u32,
    /// A demand chunk read was started since [`Shard::olsm_take_demand_read`]: a refused engine call that started none
    /// only waits for reads an earlier call issued.
    demand_read: bool,
    /// Cursor and accumulator of the bounded free-run walk behind `olsm_frag_holes_lt16`.
    frag_cursor: u64,
    frag_acc: u64,
    pub(super) stats: OlsmStats,
}

impl OlsmDrv {
    /// Bytes the run cache holds above its own share.
    pub(super) fn borrowed(&self) -> u64 {
        self.cache.bytes().saturating_sub(self.own_cap) as u64
    }

    /// Size the run block cache from `lend` bytes of the tree page budget (adr 0633 am. 5): a smaller share evicts at
    /// once, so an idle read-hot cache gives its borrow back. Returns whether it evicted.
    fn fit_cache(&mut self, lend: u64) -> bool {
        let before = self.cache.bytes();
        self.cache.set_cap(self.own_cap + lend as usize);
        self.cache.bytes() != before
    }

    /// `mem` = bytes for both memtables and the run block cache: each memtable up to a quarter, the cache a half.
    pub(super) fn new(mem: usize, wal_bytes: usize) -> OlsmDrv {
        OlsmDrv {
            slots: Default::default(),
            wq: VecDeque::new(),
            cache: RunCache::new(mem / 2),
            own_cap: mem / 2,
            unsent: VecDeque::new(),
            rds: HashMap::new(),
            sending: None,
            next_rd: 0,
            parts: HashMap::new(),
            next_part: 0,
            prefetch_slots: 0,
            prefetch_pending_parts: 0,
            adaptive: Default::default(),
            // the memtable's ops sit in the ring: a quarter of it leaves room for the frozen one and other records
            mt_soft: (mem / 4).min(wal_bytes / 4).max(1),
            want_freeze: false,
            helpers: false,
            gc_wait_mark: 0,
            refused_inputs: usize::MAX,
            room_wait: 0,
            demand_read: false,
            frag_cursor: 0,
            frag_acc: 0,
            stats: OlsmStats::default(),
        }
    }

    /// Blocks leased to a job per round: the chunks the device queue takes above the WAL floor (what one inline step
    /// wrote at most before), so a round's written blocks go out in about one queue fill; at most one flush unit
    /// (`mt_soft` = n0): the engine's space slack holds about one n0 per job in flight (adr 0610 am. 5), and a
    /// reservation larger than the job's output only takes space from the shard.
    fn lease_blocks<D: BlockDev>(&self, sh: &Shard<D>) -> u32 {
        let chunks = sh.dev.queue_depth().saturating_sub(sh.data_floor()).max(1);
        let queue = chunks * crate::olsm::CHUNK_TARGET / BLK;
        queue
            .min(self.mt_soft.div_ceil(BLK))
            .max(crate::olsm::CHUNK_MAX as usize) as u32
    }

    /// Read-ahead per merge input (chunks): the same queue share split over the inputs.
    fn ahead<D: BlockDev>(sh: &Shard<D>, inputs: usize) -> usize {
        (sh.dev.queue_depth().saturating_sub(sh.data_floor()) / inputs.max(1)).max(1)
    }
}

/// Object layer reads through the run cache (a miss queues the read).
struct Io<'a, D: BlockDev> {
    sh: &'a mut Shard<D>,
    d: &'a mut OlsmDrv,
}

impl<D: BlockDev> ChunkRead for Io<'_, D> {
    fn scan_prefetch(&self) -> bool {
        self.sh.cfg.omap_scan_prefetch
    }
    fn scan_prefetch_chunks(&self) -> usize {
        if self.sh.cfg.omap_scan_prefetch_adaptive {
            self.d.adaptive.window
        } else {
            self.sh.cfg.omap_scan_prefetch_chunks
        }
    }
    fn prefetch(&mut self, blk: u64, nblk: u32) {
        self.adapt();
        if !self.scan_prefetch() || self.d.cache.overlaps(blk, nblk) {
            return;
        }
        if !self.sh.olsm_prefetch_room(self.d, nblk) {
            self.d.cache.prefetch_stats.throttled += 1;
            return;
        }
        if let Some(tok) = self.d.cache.start_prefetch(blk, nblk) {
            self.d.prefetch_slots += nblk.div_ceil(self.sh.max_xfer_blk as u32) as usize;
            self.sh.olsm_read(self.d, blk, nblk, ReadTo::Prefetch(tok));
        }
    }
    fn read(&mut self, blk: u64, nblk: u32) -> Result<Bytes> {
        self.read_checked(blk, nblk).map(|(b, _)| b)
    }
    fn checked(&mut self, blk: u64, nblk: u32) {
        self.d.cache.checked(blk, nblk);
    }
    fn read_checked(&mut self, blk: u64, nblk: u32) -> Result<(Bytes, bool)> {
        if let Some(hit) = self.d.cache.get_checked(blk, nblk) {
            self.adapt();
            return Ok(hit);
        }
        self.d.cache.prefetch_wait(blk, nblk);
        self.adapt();
        if !self.d.cache.pending(blk, nblk) {
            if self.sh.olsm_read_room(nblk) {
                let tok = self.d.cache.start(blk, nblk);
                self.sh.olsm_read(self.d, blk, nblk, ReadTo::Cache(tok));
                self.d.demand_read = true;
            } else {
                self.d.room_wait = self.d.room_wait.max(nblk);
            }
        }
        Err(StoreError::Miss)
    }
}

impl<D: BlockDev> Io<'_, D> {
    fn adapt(&mut self) {
        if !self.sh.cfg.omap_scan_prefetch || !self.sh.cfg.omap_scan_prefetch_adaptive {
            return;
        }
        let demand = crate::olsm::CHUNK_MAX.div_ceil(self.sh.max_xfer_blk as u32) as usize;
        // Discount our outstanding hints: their own half-share exhaustion is admission, not global pressure.
        let io_pressure = self
            .sh
            .dev
            .queue_space()
            .saturating_add(self.d.prefetch_pending_parts)
            < self.sh.data_floor() + demand;
        let memory_pressure = self.d.cache.demand_pressure(crate::olsm::CHUNK_TARGET);
        self.d.adaptive.observe(
            self.d.cache.prefetch_stats,
            self.sh.cfg.omap_scan_prefetch_max_chunks,
            self.sh.read_admission_waiting || io_pressure || memory_pressure,
        );
    }
}

/// Blocking run reads (mount, fsck).
pub(crate) struct SioRead<'a, 'b, D: BlockDev, C: Clock>(pub &'a mut Sio<'b, D, C>);

impl<D: BlockDev, C: Clock> ChunkRead for SioRead<'_, '_, D, C> {
    fn read(&mut self, blk: u64, nblk: u32) -> Result<Bytes> {
        self.0.read_one(blk, nblk).map(Bytes::from)
    }
}

/// Mount: the manifest records of the tree and the engine with the replayed ops above `flushed_lsn`.
pub(super) fn mount_olsm<D: BlockDev, C: Clock>(
    io: &mut Sio<D, C>,
    state: &mut State,
    n0: u64,
) -> Result<Olsm> {
    let ops = state.olsm_replay.take().unwrap_or_default();
    let (lo, hi) = ([T_LSM], [T_LSM + 1]);
    let mut cur = ScanCursor::new(&lo, &hi);
    let (mut descs, mut flushed, mut bad) = (Vec::new(), 0u64, false);
    loop {
        let r = state.tree.scan(
            &mut cur,
            1 << 16,
            usize::MAX,
            &mut |k, v| match (k.get(1), k.len()) {
                (Some(&SUB_RUN), 10) => match RunDesc::decode(v) {
                    Ok(d) if d.id.to_be_bytes() == k[2..] => descs.push(d),
                    _ => bad = true,
                },
                (Some(&SUB_FLUSHED), 2) if v.len() == 8 => {
                    flushed = u64::from_le_bytes(v.try_into().expect("8 bytes"))
                }
                _ => bad = true,
            },
        );
        match r {
            Ok(ScanStatus::Done) => break,
            Ok(ScanStatus::More) => {}
            Err(StoreError::Miss) => crate::state::fill_blocking(&mut state.tree, io)?,
            Err(e) => return Err(e),
        }
    }
    if bad {
        return Err(StoreError::Corrupt(
            "olsm: malformed manifest record".into(),
        ));
    }
    let man = Manifest::mount(n0, flushed, &descs, &mut SioRead(io))?;
    let mut o = Olsm::new(man);
    for (lsn, op) in ops.iter().filter(|(l, _)| *l > flushed) {
        op.apply(&mut o.active, *lsn);
    }
    state.tree.shrink();
    Ok(o)
}

impl<D: BlockDev> Shard<D> {
    /// Lsn of the oldest omap op only in a memtable (`None`: nothing buffered).
    pub(super) fn olsm_floor(&self) -> Option<u64> {
        #[cfg(feature = "splinterdb")]
        if let Some(mem) = &self.state.splinter_mem {
            let floor = mem.floor();
            return if self
                .splinter
                .as_ref()
                .is_some_and(|s| s.client.flushed.is_some())
            {
                let marker = self
                    .state
                    .olsm
                    .as_ref()
                    .expect("SplinterDB manifest")
                    .man
                    .flushed_lsn;
                Some(floor.unwrap_or(u64::MAX).min(marker.saturating_add(1)))
            } else {
                floor
            };
        }
        #[cfg(feature = "rocksdb")]
        if let Some(mem) = &self.state.rocks_mem {
            let floor = mem.floor();
            return if self
                .rocks
                .as_ref()
                .is_some_and(|r| r.client.flushed.is_some())
            {
                let marker = self
                    .state
                    .olsm
                    .as_ref()
                    .expect("RocksDB manifest")
                    .man
                    .flushed_lsn;
                Some(floor.unwrap_or(u64::MAX).min(marker.saturating_add(1)))
            } else {
                floor
            };
        }
        self.state.olsm.as_ref().and_then(olsm_floor_of)
    }

    /// Something to drive: a job on the owner, writes, reads (in flight, waiting for queue room or DMA memory)
    /// or a due freeze.
    pub(super) fn olsm_busy(&self) -> bool {
        #[cfg(feature = "splinterdb")]
        if self.splinter.is_some() {
            return self.splinter_busy();
        }
        #[cfg(feature = "rocksdb")]
        if self.rocks.is_some() {
            return self.rocks_busy();
        }
        let (Some(d), Some(o)) = (&self.ol, &self.state.olsm) else {
            return false;
        };
        d.slots.iter().any(|s| {
            s.wake
                || !s.landed()
                || !s.reads.is_empty()
                || s.job.as_ref().is_some_and(|j| j.task.done())
        }) || !d.rds.is_empty()
            || !d.unsent.is_empty()
            || d.room_wait > 0
            || self.olsm_freeze_due(d, o)
    }

    pub(super) fn olsm_freeze_due(&self, d: &OlsmDrv, o: &Olsm) -> bool {
        o.frozen.is_none()
            && !o.active.is_empty()
            && (o.active.bytes() >= d.mt_soft
                || d.want_freeze
                // `o` is the engine itself: during a driver step it is detached from the state, so `olsm_floor` and
                // `wal_floor` cannot see it
                || olsm_floor_of(o).is_some_and(|f| {
                    self.state.runs.floor().is_none_or(|r| r >= f)
                        && self.floor_blocks_at(f) * 100
                            >= self.dir.wal_blocks * self.cfg.ckpt_wal_pct as u64
                }))
    }

    /// Admission (`validate`): omap records wait for a full active plus frozen memtable, or for a running merge
    /// with logical space debt under physical pressure. `Some(false)` identifies the memory refusal;
    /// `Some(true)` identifies the space refusal. Logical debt alone remains a background-GC trigger.
    pub(super) fn olsm_throttled(&self, rec: &Record) -> Option<bool> {
        let (Some(d), Some(o)) = (&self.ol, &self.state.olsm) else {
            return None;
        };
        if !rec.ops.iter().any(|x| matches!(x, Op::Omap(_))) {
            return None;
        }
        #[cfg(feature = "splinterdb")]
        if let Some(mem) = &self.state.splinter_mem {
            return (mem.frozen.is_some() && mem.active.bytes() >= d.mt_soft).then_some(false);
        }
        #[cfg(feature = "rocksdb")]
        if let Some(mem) = &self.state.rocks_mem {
            return (mem.frozen.is_some() && mem.active.bytes() >= d.mt_soft).then_some(false);
        }
        if o.frozen.is_some() && o.active.bytes() >= d.mt_soft {
            return Some(false);
        }
        // Protect two slack units for foreground admission; the GC urgency arm below uses one. This earlier
        // admission boundary leaves another slack unit for work already admitted and reclamation in flight.
        // A lease wait since the last GC pick also establishes pressure. See the proposed physical-pressure ADR.
        let short = d.stats.alloc_waits > d.gc_wait_mark
            || self.state.alloc.n_free() * (BLK as u64) < 2 * o.man.slack();
        (short && !d.slots[MERGE].free() && o.man.space_debt(d.stats.space_used_bytes))
            .then_some(true)
    }

    /// Ring pressure (`validate`): the memtables hold the floor the ring needs moved, so the holder is flushed (a flush
    /// frees what it waits for: its manifest txn takes the room admission keeps for it).
    pub(super) fn olsm_ring_pressure(&mut self) {
        if self.olsm_floor().is_some()
            && let Some(d) = &mut self.ol
        {
            d.want_freeze = true;
        }
    }

    pub(super) fn olsm_note_throttle(&mut self, space: bool) {
        if let Some(d) = &mut self.ol {
            if space {
                d.stats.space_throttled += 1;
            } else {
                d.stats.throttled += 1;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn set_scan_prefetch_for_test(&mut self, enabled: bool) {
        self.cfg.omap_scan_prefetch = enabled;
    }

    /// Run block cache bytes, its own share and its cap (tests: the borrowed cache envelope, adr 0633 am. 5).
    #[cfg(test)]
    pub(crate) fn run_cache_for_test(&self) -> Option<(usize, usize, usize)> {
        self.ol
            .as_ref()
            .map(|d| (d.cache.bytes(), d.own_cap, d.cache.cap()))
    }

    /// Fill the run block cache with `n` one-block extents (tests: the borrowed cache envelope).
    #[cfg(test)]
    pub(crate) fn fill_run_cache_for_test(&mut self, n: usize) {
        let Some(d) = &mut self.ol else { return };
        for i in 0..n as u64 {
            let t = d.cache.start(i, 1);
            assert!(d.cache.done(t, Some(Bytes::from(vec![0u8; BLK]))));
            d.cache.op_done();
        }
    }

    /// A successful foreground read can leave look-ahead I/O behind; the object store keeps
    /// this shard active until those completions release their buffers and reader epochs. Reads waiting for queue room
    /// ([`OlsmDrv::unsent`]) or DMA memory (adr 0175 am. 4) hold a reader epoch too: they are sent at a later poll.
    pub(crate) fn olsm_reads_pending(&self) -> bool {
        #[cfg(feature = "splinterdb")]
        if self.splinter.is_some() {
            return self.splinter_needs_poll();
        }
        self.ol
            .as_ref()
            .is_some_and(|d| !d.rds.is_empty() || !d.unsent.is_empty())
    }

    /// Operator cache drop: the clean run block cache goes (memtables hold unflushed data and stay). Bytes dropped.
    pub fn olsm_drop_cache(&mut self) -> u64 {
        self.ol.as_mut().map_or(0, |d| d.cache.clear() as u64)
    }

    /// Size the omap run block cache from the lendable tree budget and the data cache's held bytes (adr 0633 am. 5):
    /// a smaller share evicts at once. The store sweep calls it after the data cache's fit, so an idle shard (no driver
    /// pass) keeps no borrow either.
    pub(crate) fn olsm_fit_cache(&mut self) {
        let lend = Self::lend_share(self.lendable(), self.dc_held);
        let Some(d) = &mut self.ol else { return };
        if d.fit_cache(lend) {
            self.trim_ram();
        }
    }

    pub fn olsm_stats(&self) -> Option<OlsmStats> {
        #[cfg(feature = "splinterdb")]
        if self.splinter.is_some() {
            return None;
        }
        #[cfg(feature = "rocksdb")]
        if self.rocks.is_some() {
            return None;
        }
        self.ol.as_ref().map(|d| {
            let mut stats = d.stats;
            stats.scan_prefetch = d.cache.prefetch_stats;
            stats.scan_prefetch_inflight_slots = d.prefetch_slots as u64;
            if self.cfg.omap_scan_prefetch {
                stats.scan_prefetch_adaptive = u64::from(self.cfg.omap_scan_prefetch_adaptive);
                stats.scan_prefetch_fixed = u64::from(!self.cfg.omap_scan_prefetch_adaptive);
                stats.scan_prefetch_window = if self.cfg.omap_scan_prefetch_adaptive {
                    d.adaptive.window
                } else {
                    self.cfg.omap_scan_prefetch_chunks
                } as u64;
            }
            stats.scan_prefetch_grows = d.adaptive.grows;
            stats.scan_prefetch_shrinks = d.adaptive.shrinks;
            stats
        })
    }

    /// Rounds go to helper cores (`true`) or run on this core. Set by the OSD before each poll.
    pub(super) fn olsm_helpers(&mut self, on: bool) {
        if let Some(d) = &mut self.ol
            && d.helpers != on
        {
            d.helpers = on;
            for s in &mut d.slots {
                s.wake |= s.job.is_some();
            }
        }
    }

    /// A prepared round for a helper core: the flush slot (`flush`) or the merge slot.
    pub(super) fn olsm_take(&mut self, flush: bool) -> Option<Box<OlsmJob>> {
        let d = self.ol.as_mut()?;
        let s = &mut d.slots[if flush { FLUSH } else { MERGE }];
        if !d.helpers || !s.ready {
            return None;
        }
        let j = s.job.take()?;
        s.ready = false;
        s.away = Some(j.id);
        d.stats.helper_rounds += 1;
        Some(j)
    }

    /// A round came back from a helper (any state: finished, waiting for the owner, or declined unstepped). `false` = not
    /// this shard's job of this mount (dropped).
    pub(super) fn olsm_return(&mut self, j: Box<OlsmJob>) -> bool {
        let Some(d) = &mut self.ol else {
            return false;
        };
        let s = &mut d.slots[j.slot as usize];
        if s.away != Some(j.id) {
            return false;
        }
        s.away = None;
        s.job = Some(j);
        s.wake = true;
        self.wake = true;
        true
    }

    /// The queue has room for a read of `nblk` blocks above the WAL floor; otherwise the next poll asks again. No wake on
    /// refusal: room frees only on a device completion, and a spurious wake would make `miss_wait` return before `idle`
    /// advances the clock, so the completions that free the queue never land. A refused demand read is recorded in
    /// [`OlsmDrv::room_wait`] instead; the driver pass that sees the room wakes its reader.
    fn olsm_read_room(&mut self, nblk: u32) -> bool {
        let n = nblk.div_ceil(self.max_xfer_blk as u32) as usize;
        self.failed.is_none() && self.dev.queue_space() >= n + self.data_floor()
    }

    /// Speculation takes at most half the queue above the WAL floor and leaves at least one full target chunk
    /// demand read (split by the device transfer limit) free. Queued ordinary data-read batches take
    /// priority: they may need more than one target chunk, so their all-or-nothing admission must
    /// accumulate every freed slot without fresh hints passing them. Shallow queues decline hints.
    fn olsm_prefetch_room(&self, d: &OlsmDrv, nblk: u32) -> bool {
        let n = nblk.div_ceil(self.max_xfer_blk as u32) as usize;
        let demand = crate::olsm::CHUNK_MAX.div_ceil(self.max_xfer_blk as u32) as usize;
        let floor = self.data_floor();
        self.failed.is_none()
            && !self.read_admission_waiting
            && d.prefetch_slots + n <= self.dev.queue_depth().saturating_sub(floor) / 2
            && self.dev.queue_space() >= n + floor + demand
    }

    /// Read `[blk, blk + nblk)` in parts of at most the transfer size (room checked by the caller). The blocks are pinned
    /// now; its parts go out as the DMA budget gives each its buffer (in-flight IO memory, adr 0175 am. 4): at once, or
    /// at later driver passes ([`Shard::olsm_send`]). Its waiter is woken by its completion either way.
    fn olsm_read(&mut self, d: &mut OlsmDrv, blk: u64, nblk: u32, to: ReadTo) {
        let n = nblk.div_ceil(self.max_xfer_blk as u32) as usize;
        if matches!(to, ReadTo::Prefetch(_)) {
            d.prefetch_pending_parts += n;
        }
        let epoch = self.read_pin();
        d.unsent.push_back((blk, nblk, to, epoch));
        self.olsm_send(d);
    }

    /// Submit the reads of [`OlsmDrv::unsent`] in order while the queue has room. Each part takes its own DMA buffer
    /// right before its submit (in-flight IO memory, at most one transfer, adr 0175 am. 4); a refused part waits in
    /// [`OlsmDrv::sending`] for a later pass while the parts already sent complete, so a read longer than D/4 still
    /// completes.
    fn olsm_send(&mut self, d: &mut OlsmDrv) {
        let mx = self.max_xfer_blk as u32;
        loop {
            if let Some(rid) = d.sending {
                let rd = d.rds.get_mut(&rid).expect("sending read");
                if rd.sent == rd.n {
                    d.sending = None;
                    continue;
                }
                if self.failed.is_some() || self.dev.queue_space() <= self.data_floor() {
                    return;
                }
                let i = rd.sent;
                let c = mx.min(rd.nblk - i as u32 * mx);
                // bytes that stay in the run cache of a store whose device reads into ordinary memory are read into it
                // (the cache may grow beyond the bounded in-flight IO memory, like the data cache)
                let buf = if rd.n == 1 && !matches!(rd.to, ReadTo::Job(..)) && self.dev.ram_reads()
                {
                    Some(self.dev.alloc_buf_ram_uninit(c as usize * BLK))
                } else {
                    self.dev.try_alloc_io_uninit(c as usize * BLK)
                };
                let Some(buf) = buf else {
                    return;
                };
                rd.sent += 1;
                let b = rd.blk + (i as u32 * mx) as u64;
                d.next_part = (d.next_part + 1) & !K_MASK;
                d.parts.insert(d.next_part, (rid, i));
                if self
                    .dev
                    .submit_read(b * self.lpb, buf, K_OREAD | d.next_part)
                    .is_err()
                {
                    self.fail(StoreError::Io(IoError::Aborted));
                    return;
                }
                self.dev_note();
                continue;
            }
            let Some(&(blk, nblk, _, _)) = d.unsent.front() else {
                return;
            };
            if !self.olsm_read_room(nblk) {
                return;
            }
            let (_, _, to, epoch) = d.unsent.pop_front().expect("front");
            let n = nblk.div_ceil(mx) as usize;
            d.next_rd += 1;
            let rid = d.next_rd;
            d.rds.insert(
                rid,
                Rd {
                    blk,
                    nblk,
                    n,
                    sent: 0,
                    left: n,
                    one: None,
                    asm: if n > 1 {
                        vec![0; nblk as usize * BLK]
                    } else {
                        Vec::new()
                    },
                    epoch,
                    to,
                },
            );
            d.stats.reads += 1;
            d.stats.read_blocks += nblk as u64;
            d.sending = Some(rid);
        }
    }

    /// Completion of a read part.
    pub(super) fn olsm_read_done(&mut self, part: u64, buf: D::Buf) {
        let Some(mut d) = self.ol.take() else {
            return;
        };
        if let Some((rid, i)) = d.parts.remove(&part)
            && let Some(rd) = d.rds.get_mut(&rid)
        {
            if matches!(rd.to, ReadTo::Prefetch(_)) {
                d.prefetch_pending_parts -= 1;
            }
            if rd.n == 1 {
                rd.one = Some(buf.into_shared());
            } else {
                // a read longer than one transfer (a chunk of one large entry): assembled as its parts land, each DMA
                // buffer freed at once
                let off = i * self.max_xfer_blk * BLK;
                rd.asm[off..off + buf.len()].copy_from_slice(buf.as_slice());
            }
            rd.left -= 1;
            if rd.left == 0 {
                let rd = d.rds.remove(&rid).expect("present");
                let read_parts = rd.n;
                let data = if read_parts == 1 {
                    rd.one
                } else {
                    Some(Bytes::from(rd.asm))
                };
                match rd.to {
                    ReadTo::Cache(tok) | ReadTo::Prefetch(tok) => {
                        if matches!(rd.to, ReadTo::Prefetch(_)) {
                            d.prefetch_slots -= read_parts;
                        }
                        let data = if d.cache.forgotten(tok) { None } else { data };
                        d.cache.done(tok, data);
                        // extents it evicted: their idle cache chunks go back
                        self.dev.trim_ram();
                    }
                    ReadTo::Job(s, id, ext) => {
                        let s = &mut d.slots[s];
                        if s.id() == Some(id)
                            && s.reads.remove(&ext)
                            && let Some(b) = data
                        {
                            s.pre.insert(ext, b);
                            s.wake = true;
                        }
                    }
                }
                self.read_unpin(rd.epoch);
                self.wake = true;
            }
        }
        self.ol = Some(d);
    }

    pub(super) fn olsm_write_done(&mut self, slot: u64) {
        if let Some(d) = &mut self.ol {
            d.slots[slot as usize].w_inflight -= 1;
        }
    }

    /// Queued run writes into the device queue (above the WAL floor, like data writes).
    fn olsm_pump(&mut self, d: &mut OlsmDrv) {
        let floor = self.data_floor();
        while self.failed.is_none() && self.dev.queue_space() > floor {
            let Some((blk, data, s)) = d.wq.pop_front() else {
                break;
            };
            // a copy is store metadata IO of the DMA budget (adr 0175 am. 4): refused = the write waits for the next pass
            let buf = match self.view_buf(&data) {
                Some(b) => b,
                None => match self.dev.try_alloc_io_uninit(data.len()) {
                    Some(mut b) => {
                        b.copy_from_slice(&data);
                        b
                    }
                    None => {
                        d.wq.push_front((blk, data, s));
                        break;
                    }
                },
            };
            if self
                .dev
                .submit_write(blk * self.lpb, buf, K_OLSM | s as u64)
                .is_err()
            {
                self.fail(StoreError::Io(IoError::Aborted));
                return;
            }
            d.slots[s].queued -= 1;
            d.slots[s].w_inflight += 1;
            self.dev_note();
        }
    }

    /// One driver pass (from `poll`): pump writes, start jobs when due, prepare (and on a single core step) their
    /// rounds, submit the manifest txn of a finished job once its writes landed.
    pub(super) fn olsm_step(&mut self) {
        #[cfg(feature = "rocksdb")]
        if self.rocks.is_some() {
            self.rocks_step();
            return;
        }
        #[cfg(feature = "splinterdb")]
        if self.splinter.is_some() {
            self.splinter_step();
            return;
        }
        if self.failed.is_some() {
            return;
        }
        let (Some(mut d), Some(mut o)) = (self.ol.take(), self.state.olsm.take()) else {
            return;
        };
        self.olsm_drive(&mut d, &mut o);
        self.state.olsm = Some(o);
        self.ol = Some(d);
    }

    /// Park `task` in `slot` as a fresh job and wake the slot.
    fn olsm_start(&mut self, d: &mut OlsmDrv, slot: usize, task: Task) {
        d.slots[slot].wake = true;
        d.slots[slot].job = Some(Box::new(OlsmJob::new(
            self.next_compaction_id(),
            slot as u8,
            task,
        )));
    }

    fn olsm_drive(&mut self, d: &mut OlsmDrv, o: &mut Olsm) {
        // the run cache borrows the tree page budget the tree has not allocated, as the data cache does; a smaller
        // share evicts at once and the device's idle cache chunks go back
        if d.fit_cache(Self::lend_share(self.lendable(), self.dc_held)) {
            self.trim_ram();
        }
        self.olsm_pump(d);
        self.olsm_send(d);
        // a demand read refused for queue room: the completions that freed the room woke nobody else
        if d.room_wait > 0 && self.olsm_read_room(d.room_wait) {
            d.room_wait = 0;
            self.wake = true;
        }
        self.olsm_space(d, o);
        let due = self.olsm_freeze_due(d, o);
        d.want_freeze = false;
        if due && d.slots[FLUSH].free() {
            let mem = o.freeze().expect("freeze due");
            let run = o.man.alloc_run_id();
            self.olsm_start(d, FLUSH, Task::flush(mem, run));
        }
        if d.slots[MERGE].free() {
            o.man.set_max_inputs(self.olsm_max_inputs(d));
            // space-pressure arm: a lease found no space since the last GC pick, or the free space no longer holds the
            // engine's own in-flight slack (adr 0610 am. 5)
            let pressure = d.stats.alloc_waits > d.gc_wait_mark
                || self.state.alloc.n_free() * (BLK as u64) < o.man.slack();
            if let Some(p) = o.man.pick_merge(pressure) {
                if p.gc {
                    d.gc_wait_mark = d.stats.alloc_waits;
                }
                self.olsm_start(d, MERGE, Task::merge(MergeJob::new(p)));
            }
        }
        for s in [FLUSH, MERGE] {
            if d.slots[s].job.is_none() || !std::mem::take(&mut d.slots[s].wake) {
                continue;
            }
            self.olsm_prepare(d, s);
            if !d.helpers && d.slots[s].ready {
                // the next pass continues the round
                self.olsm_inline(d, s);
                self.olsm_prepare(d, s);
                d.slots[s].wake = true;
            }
            if self.failed.is_some() {
                return;
            }
        }
        self.olsm_pump(d);
        for s in [FLUSH, MERGE] {
            let sl = &d.slots[s];
            if !(sl.landed() && sl.job.as_ref().is_some_and(|j| j.task.done())) {
                continue;
            }
            match self.olsm_manifest(d, o, s) {
                Ok(()) => {}
                Err(StoreError::Busy | StoreError::WalFull | StoreError::Miss) => {
                    d.stats.man_retries += 1;
                }
                Err(e) => return self.fail(e),
            }
        }
    }

    /// Space gauges of the driver pass: live (manifest + both memtables), used (run blocks + leased blocks), the
    /// fence-only garbage estimate, run count and resident RAM, plus one bounded window of the free-run walk. The
    /// manifest keeps the sums (adr 0610 am. 5): the pass reads them, it does not walk the runs.
    fn olsm_space(&mut self, d: &mut OlsmDrv, o: &Olsm) {
        let space = o.man.space();
        let mem = o.active.bytes() as u64 + o.frozen.as_ref().map_or(0, |f| f.bytes() as u64);
        let leased: u64 = d.slots.iter().map(|s| u64::from(s.lease)).sum();
        d.stats.space_live_bytes = space.bytes + mem;
        d.stats.space_used_bytes = (space.blocks + leased) * BLK as u64;
        d.stats.space_garbage_bytes = o.man.garbage(&space);
        d.stats.runs = space.runs;
        d.stats.mem_bytes = space.ram;
        d.stats.pick_visits = o.man.pick_visits();
        let a = &self.state.alloc;
        let n = a.len();
        if n == 0 {
            return;
        }
        let from = d.frag_cursor.min(n);
        let mut holes = 0u64;
        a.for_each_free_in(from, FRAG_WINDOW, |_, blocks| {
            if blocks < u64::from(crate::olsm::CHUNK_MAX) {
                holes += 1;
            }
        });
        d.frag_acc += holes;
        d.frag_cursor = from + FRAG_WINDOW;
        if d.frag_cursor >= n {
            d.stats.frag_holes_lt16 = d.frag_acc;
            d.frag_acc = 0;
            d.frag_cursor = 0;
        }
    }

    /// Owner side of a round boundary for the job in slot `s`: queue its written blocks, then (unfinished) lease blocks
    /// and supply input chunks; the slot is `ready` when the round can run.
    fn olsm_prepare(&mut self, d: &mut OlsmDrv, s: usize) {
        let mut j = d.slots[s].job.take().expect("job on the owner");
        j.cx.drain_out(self.max_xfer_blk, |blk, data, crcs| {
            d.wq.push_back((blk, data, s));
            d.slots[s].queued += 1;
            d.slots[s].written.push(Extent {
                blk,
                nblk: crcs.len() as u32,
                crcs: crcs.to_vec(),
            });
        });
        let ready = match j.err.take() {
            Some(e) => {
                self.fail(e);
                false
            }
            None if j.task.done() => {
                for (b, n) in std::mem::take(&mut j.cx.lease) {
                    self.unreserve(b, n);
                }
                j.cx.chunks.clear();
                d.slots[s].pre.clear();
                d.slots[s].reads.clear();
                false
            }
            None => self.olsm_lease(d, &mut j.cx) && self.olsm_supply(d, s, &mut j),
        };
        // waiting for space or queue room (not for a read in flight): ask again next pass
        let sl = &mut d.slots[s];
        sl.wake |= !ready
            && !j.task.done()
            && (j.cx.lease.is_empty()
                || j.cx.need > 0
                || j.cx.missed.is_some_and(|m| !sl.reads.contains(&m)));
        sl.ready = ready;
        sl.lease = j.cx.lease.iter().map(|x| x.1).sum();
        sl.job = Some(j);
    }

    /// The job has blocks for its next request. When it ran out (or a request did not fit) the rest of its lease is
    /// given back and it gets a fresh one: [`OlsmDrv::lease_blocks`] in pieces of the longest free run of
    /// [`crate::olsm::CHUNK_MIN`]..=[`crate::olsm::CHUNK_MAX`] blocks (adr 0610 am. 5) plus one exact extent of the
    /// request that did not fit when a minimum piece may not hold it (a run's meta, a large entry). A partial lease is
    /// kept; none at all = wait for space.
    fn olsm_lease(&mut self, d: &mut OlsmDrv, cx: &mut Ctx) -> bool {
        if cx.need == 0 && !cx.lease.is_empty() {
            return true;
        }
        for (b, n) in std::mem::take(&mut cx.lease) {
            self.unreserve(b, n);
        }
        // a request a minimum piece may not hold (a run's meta, a large entry) gets one exact extent
        if cx.need > crate::olsm::CHUNK_MIN {
            match self.alloc_sys(cx.need) {
                Ok(b) => cx.lease.push((b, cx.need)),
                Err(StoreError::Busy | StoreError::NoSpace) => {}
                Err(e) => {
                    self.fail(e);
                    return false;
                }
            }
        }
        let target = d.lease_blocks(self);
        let mut have: u32 = cx.lease.iter().map(|x| x.1).sum();
        // pieces are the longest free run in CHUNK_MIN..=CHUNK_MAX blocks: a fragmented region still leases 16 KiB
        while have < target {
            match self.alloc_sys_upto(crate::olsm::CHUNK_MIN, crate::olsm::CHUNK_MAX) {
                Ok((b, n)) => {
                    cx.lease.push((b, n));
                    have += n;
                }
                Err(StoreError::Busy | StoreError::NoSpace) => break,
                Err(e) => {
                    self.fail(e);
                    return false;
                }
            }
        }
        if cx.lease.iter().all(|x| x.1 < cx.need.max(1)) {
            d.stats.alloc_waits += 1;
            return false;
        }
        cx.need = 0;
        true
    }

    /// Hand the merge its input chunks: the one it missed and the read-ahead, from completed job reads or the run cache,
    /// else read. `true` = the missed chunk (if any) is there.
    fn olsm_supply(&mut self, d: &mut OlsmDrv, s: usize, j: &mut OlsmJob) -> bool {
        let inputs = match &j.task {
            Task::Merge { job, .. } => job.inputs().len(),
            Task::Flush { .. } => return true,
        };
        let mut want: Vec<(u64, u32)> = j.cx.missed.into_iter().collect();
        j.task.next_reads(OlsmDrv::ahead(self, inputs), &mut want);
        for ext in want {
            if j.cx.chunks.contains_key(&ext) {
                continue;
            }
            let b = match d.slots[s].pre.remove(&ext) {
                Some(b) => Some(b),
                None => d.cache.get(ext.0, ext.1),
            };
            match b {
                Some(b) => {
                    j.cx.chunks.insert(ext, b);
                }
                None if !d.slots[s].reads.contains(&ext) && self.olsm_read_room(ext.1) => {
                    d.slots[s].reads.insert(ext);
                    self.olsm_read(d, ext.0, ext.1, ReadTo::Job(s, j.id, ext));
                }
                None => {}
            }
        }
        if j.cx.missed.is_some_and(|m| j.cx.chunks.contains_key(&m)) {
            j.cx.missed = None;
        }
        j.cx.missed.is_none()
    }

    /// Step the prepared round of slot `s` on this core: at most the chunks the device queue takes now above the WAL
    /// floor (a step never queues more writes than that).
    fn olsm_inline(&mut self, d: &mut OlsmDrv, s: usize) {
        let budget = self
            .dev
            .queue_space()
            .saturating_sub(self.data_floor() + d.wq.len());
        if budget == 0 {
            return;
        }
        let j = d.slots[s].job.as_mut().expect("job on the owner");
        d.stats.inline_rounds += 1;
        for _ in 0..budget {
            if j.step() {
                break;
            }
        }
    }

    /// The manifest txn of the finished job in slot `s`; on success the engine switches to the new run set.
    fn olsm_manifest(&mut self, d: &mut OlsmDrv, o: &mut Olsm, s: usize) -> Result<()> {
        let j = d.slots[s].job.as_ref().expect("finished job");
        let mut t: Txn<D::Buf> = Txn::new(MERGE_TOKEN);
        t.sys = true;
        t.olsm = Some(d.slots[s].written.clone());
        match &j.task {
            Task::Flush { out, mem, .. } => {
                let m = out.as_ref().expect("done");
                t.ops.push(Op::Put(run_key(m.id), RunDesc::of(m).encode()));
                t.ops.push(Op::Put(
                    FLUSHED_KEY.to_vec(),
                    mem.lsn_hi().to_le_bytes().to_vec(),
                ));
            }
            Task::Merge { job, out } => {
                let out = out.as_ref().expect("done");
                for r in job.inputs() {
                    t.ops.push(Op::Del(run_key(r.id)));
                }
                for m in out.runs.iter().chain(&out.residuals) {
                    t.ops.push(Op::Put(run_key(m.id), RunDesc::of(m).encode()));
                }
                t.frees = out.freed.clone();
            }
        }
        if let Err((e, _)) = self.submit(t) {
            let merge = match &d.slots[s].job.as_ref().expect("finished job").task {
                Task::Merge { out, .. } => {
                    Some(out.as_ref().is_some_and(|o| o.prefix_end.is_some()))
                }
                Task::Flush { .. } => None,
            };
            match (&e, merge) {
                (StoreError::TxnTooLarge, Some(true)) => self.olsm_restart_full(d, s),
                (StoreError::TxnTooLarge, Some(false)) => self.olsm_refused(d, o, s),
                _ => return Err(e),
            }
            return Ok(());
        }
        let sl = &mut d.slots[s];
        let blocks: u64 = sl.written.drain(..).map(|x| x.nblk as u64).sum();
        d.stats.written_blocks += blocks;
        let j = sl.job.take().expect("finished job");
        sl.ready = false;
        d.stats.chunks_lt16 += j.cx.short_chunks;
        match j.task {
            Task::Flush { out, .. } => {
                o.flush_done(out.expect("done"));
                d.stats.flushes += 1;
            }
            Task::Merge { job, out } => {
                let out = out.expect("done");
                d.cache.forget(&out.freed);
                d.stats.freed_blocks += out.freed.iter().map(|f| f.1 as u64).sum::<u64>();
                if job.gc() {
                    d.stats.gc_merges += 1;
                    let input: u64 = job.inputs().iter().map(|r| r.data_bytes()).sum();
                    let output: u64 = out
                        .runs
                        .iter()
                        .chain(&out.residuals)
                        .map(|r| r.data_bytes())
                        .sum();
                    d.stats.gc_bytes_reclaimed += input.saturating_sub(output);
                }
                if out.prefix_end.is_some() {
                    d.stats.gc_prefixes += 1;
                }
                o.man
                    .install_gc_prefix(job.inputs(), out.runs, out.residuals);
                d.stats.merges += 1;
            }
        }
        Ok(())
    }

    /// A partial manifest exceeded the same hard record/page limits as an ordinary submission. `submit` returned
    /// without applying it and retained its reservations; all writes are already landed. Discard only the new output
    /// extents, leaving the original run set, read epochs and manifest locks unchanged, then retry the original GC.
    fn olsm_restart_full(&mut self, d: &mut OlsmDrv, s: usize) {
        let sl = &mut d.slots[s];
        debug_assert!(sl.landed());
        let old = sl.job.take().expect("finished prefix job");
        debug_assert!(old.cx.lease.is_empty() && old.cx.out.is_empty());
        d.stats.chunks_lt16 += old.cx.short_chunks;
        let Task::Merge { job, .. } = old.task else {
            unreachable!("only a GC prefix can restart as a complete merge")
        };
        for e in sl.written.drain(..) {
            d.stats.written_blocks += u64::from(e.nblk);
            self.unreserve(e.blk, e.nblk);
        }
        sl.pre.clear();
        sl.reads.clear();
        sl.ready = false;
        sl.lease = 0;
        sl.wake = true;
        sl.job = Some(Box::new(OlsmJob::new(
            self.next_compaction_id(),
            s as u8,
            Task::merge(job.restart_full()),
        )));
        d.stats.man_retries += 1;
    }

    /// Inputs one merge may take ([`crate::olsm::Manifest::set_max_inputs`]), from the tree's per-txn page budget (the
    /// distinct pages a txn probes): one leaf per input descriptor, one leaf for all output descriptors, the interior
    /// pages of one shared root-to-leaf path (the descriptor keys are one contiguous key range: `height - 1` pages) and
    /// one page a split of that range may add before the install: `inputs + height + 1` pages. Below that, the ceiling a
    /// refused manifest set ([`Shard::olsm_refused`]).
    fn olsm_max_inputs(&self, d: &OlsmDrv) -> usize {
        let fixed = self.state.tree.height() as usize + 1;
        self.txn_page_budget()
            .saturating_sub(fixed)
            .min(d.refused_inputs)
    }

    /// The finished merge in slot `s` needs a manifest txn larger than the store takes (`TxnTooLarge`: the per-txn
    /// page budget or the WAL record limit). The shard never fails for its own merge: nothing of it is published yet
    /// (`submit` returned without applying it, all writes landed), so its output extents are returned, its pick's locks
    /// released and the run set stays unchanged. Later merges take at most half its inputs, so the next pick of the same
    /// group takes its oldest runs only (a garbage-driven group or column beyond that is not picked).
    fn olsm_refused(&mut self, d: &mut OlsmDrv, o: &mut Olsm, s: usize) {
        let sl = &mut d.slots[s];
        debug_assert!(sl.landed());
        let old = sl.job.take().expect("finished merge job");
        debug_assert!(old.cx.lease.is_empty() && old.cx.out.is_empty());
        d.stats.chunks_lt16 += old.cx.short_chunks;
        let Task::Merge { job, .. } = old.task else {
            unreachable!("only a merge is refused without failing the shard")
        };
        for e in sl.written.drain(..) {
            d.stats.written_blocks += u64::from(e.nblk);
            self.unreserve(e.blk, e.nblk);
        }
        sl.pre.clear();
        sl.reads.clear();
        sl.ready = false;
        sl.lease = 0;
        sl.wake = false;
        o.man.abort_merge(job.inputs());
        d.refused_inputs = d.refused_inputs.min(job.inputs().len() / 2);
        d.stats.merges_refused += 1;
        eprintln!(
            "WARNING olsm: the manifest txn of a merge of {} runs exceeds the per-txn limits: dropped unpublished, \
             merges now take at most {} runs",
            job.inputs().len(),
            d.refused_inputs
        );
    }

    /// Run `f` with the engine and a reader over the run cache (object layer reads). `Miss`: a read was queued (or the
    /// queue was full); the shard wakes the caller when it completes.
    fn olsm_with<T>(&mut self, f: impl FnOnce(&Olsm, &mut Io<'_, D>) -> Result<T>) -> Result<T> {
        let (Some(mut d), Some(o)) = (self.ol.take(), self.state.olsm.take()) else {
            return Err(StoreError::Invalid("store without the omap LSM engine"));
        };
        let r = f(
            &o,
            &mut Io {
                sh: self,
                d: &mut d,
            },
        );
        if !matches!(r, Err(StoreError::Miss)) {
            d.cache.op_done();
        }
        self.state.olsm = Some(o);
        self.ol = Some(d);
        r
    }

    /// Whether an engine call started a demand chunk read since the last call of this (then cleared). The read of a
    /// refused listing pass that started none is still in flight from an earlier pass.
    pub(crate) fn olsm_take_demand_read(&mut self) -> bool {
        self.ol
            .as_mut()
            .is_some_and(|d| std::mem::take(&mut d.demand_read))
    }

    /// The LSN of the newest omap op the engine holds (memtables and runs): unchanged by flushes and merges, which
    /// move data without changing it, so a key-position continuation of an enumeration stays exact while it holds.
    pub(crate) fn olsm_generation(&self) -> u64 {
        self.state.olsm.as_ref().map_or(0, |o| {
            let frozen = o.frozen.as_ref().map_or(0, |f| f.lsn_hi());
            o.active.lsn_hi().max(frozen).max(o.man.flushed_lsn)
        })
    }

    /// Whether metadata alone bounds the entries a point removal of `[first, end)` would visit (puts and point
    /// tombstones, so both its live keys and its enumeration work) below the configured threshold. Zero selects native
    /// range removal without inspecting any sources.
    pub(crate) fn olsm_point_remove_range(
        &self,
        over: Option<&crate::olsm::Memtable>,
        id: u64,
        first: &[u8],
        end: &[u8],
    ) -> Option<usize> {
        #[cfg(feature = "splinterdb")]
        if self.splinter.is_some() {
            return None;
        }
        #[cfg(feature = "rocksdb")]
        if self.rocks.is_some() {
            // Native source metadata cannot bound keys already materialized in
            // the external DB. Preserve RocksDB's logical range operation.
            return None;
        }
        let threshold = self.cfg.omap_delete_range_threshold;
        if threshold == 0 {
            return None;
        }
        let limit = usize::try_from(threshold).ok()?;
        let o = self.state.olsm.as_ref()?;
        (with_over(o, over).range_entry_upper_bound(id, first, end, threshold) < threshold)
            .then_some(limit)
    }

    /// Exact live keys of `[from, end)` (`excl`: strictly after `from`), at most `max`.
    /// Unlike an unrestricted listing, neither demand reads nor prefetch advance past `end`.
    pub(crate) fn olsm_range_keys(
        &mut self,
        over: Option<&crate::olsm::Memtable>,
        id: u64,
        from: &[u8],
        excl: bool,
        end: &[u8],
        max: usize,
    ) -> Result<(Vec<Bytes>, bool)> {
        self.olsm_with(|o, io| {
            crate::olsm::read::list_range_keys(&with_over(o, over), io, id, from, excl, end, max)
        })
    }

    /// Omap value of `key` of object `id`; `over` = newer ops not committed yet (a txn's own ops), read first.
    pub fn olsm_get(
        &mut self,
        over: Option<&crate::olsm::Memtable>,
        id: u64,
        key: &[u8],
    ) -> Result<Option<Bytes>> {
        #[cfg(feature = "splinterdb")]
        if self.splinter.is_some() {
            if over.is_some() {
                return Err(StoreError::Invalid("native overlay on SplinterDB"));
            }
            return self.splinter_get(None, id, key);
        }
        self.olsm_with(|o, io| crate::olsm::read::get(&with_over(o, over), io, id, key))
    }

    /// Up to `max` omap entries of object `id` from `from` (`excl`: after it) whose keys start with `prefix`; `true` =
    /// more follow. `over` as for [`Shard::olsm_get`].
    pub fn olsm_list(
        &mut self,
        over: Option<&crate::olsm::Memtable>,
        id: u64,
        from: &[u8],
        excl: bool,
        prefix: &[u8],
        max: usize,
    ) -> Result<(Vec<(Bytes, Bytes)>, bool)> {
        #[cfg(feature = "splinterdb")]
        if self.splinter.is_some() {
            if over.is_some() {
                return Err(StoreError::Invalid("native overlay on SplinterDB"));
            }
            return self.splinter_list(None, id, from, excl, prefix, max);
        }
        self.olsm_with(|o, io| {
            crate::olsm::read::list_from(&with_over(o, over), io, id, from, excl, prefix, max)
        })
    }

    /// Smallest object id `>= from` with an entry in a run (object-layer check: the walk over the ids the runs hold,
    /// see [`crate::olsm::read::next_run_id`]).
    pub(crate) fn olsm_next_run_id(&mut self, from: u64) -> Result<Option<u64>> {
        self.olsm_with(|o, io| crate::olsm::read::next_run_id(&with_over(o, None), io, from))
    }

    /// One bounded step of an omap listing ([`crate::olsm::read::list_page`]): `pos` and `out` carry the progress, also
    /// across a [`StoreError::Miss`]. `over` as for [`Shard::olsm_get`].
    pub fn olsm_list_page(
        &mut self,
        over: Option<&crate::olsm::Memtable>,
        q: &crate::olsm::read::ListQuery,
        pos: &mut crate::olsm::read::ListPos,
        out: &mut Vec<(Bytes, Bytes)>,
    ) -> Result<crate::olsm::read::ListEnd> {
        self.olsm_with(|o, io| crate::olsm::read::list_page(&with_over(o, over), io, q, pos, out))
    }

    /// Values of `keys` of object `id` (present keys only, in the given order): one engine pass (see
    /// [`crate::olsm::read::by_keys`]). `over` as for [`Shard::olsm_get`].
    pub fn olsm_by_keys(
        &mut self,
        over: Option<&crate::olsm::Memtable>,
        id: u64,
        keys: &[Bytes],
    ) -> Result<Vec<(Bytes, Bytes)>> {
        #[cfg(feature = "splinterdb")]
        if self.splinter.is_some() {
            if over.is_some() {
                return Err(StoreError::Invalid("native overlay on SplinterDB"));
            }
            return self.splinter_by_keys(None, id, keys);
        }
        self.olsm_with(|o, io| crate::olsm::read::by_keys(&with_over(o, over), io, id, keys))
    }

    /// Format upgrade S7 (adr 0611): `batch` (omap entries read from the tree, `(object id, key, value)` in keyspace
    /// order) becomes the active memtable at the shard's last lsn and is frozen at the next driver pass; the normal flush
    /// writes it as one run and its manifest txn installs it. Only while the engine buffers nothing
    /// ([`Shard::olsm_flushed`]): the upgrade waits for the install between batches.
    pub fn olsm_upgrade_batch(&mut self, batch: Vec<(u64, Bytes, Bytes)>) -> Result<()> {
        #[cfg(feature = "splinterdb")]
        if self.splinter.is_some() {
            return Err(StoreError::Invalid(
                "SplinterDB engine conversion is not an LSM format upgrade",
            ));
        }
        #[cfg(feature = "rocksdb")]
        if self.rocks.is_some() {
            return Err(StoreError::Invalid(
                "RocksDB engine conversion is not an LSM format upgrade",
            ));
        }
        let lsn = self.next_lsn - 1;
        let (Some(d), Some(o)) = (&mut self.ol, &mut self.state.olsm) else {
            return Err(StoreError::Invalid("store without the omap LSM engine"));
        };
        if !o.active.is_empty() || o.frozen.is_some() {
            return Err(StoreError::Invalid(
                "upgrade batch while the engine buffers ops",
            ));
        }
        for (id, k, v) in batch {
            o.active.put(lsn, id, k, v);
        }
        d.want_freeze = true;
        self.wake = true;
        Ok(())
    }

    /// Request materialization of the active foreign overlay without changing native sync/ACK semantics.
    #[cfg(feature = "splinterdb")]
    pub(crate) fn request_omap_flush(&mut self) {
        if self
            .state
            .splinter_mem
            .as_ref()
            .is_some_and(|o| !o.active.is_empty())
            && let Some(d) = &mut self.ol
        {
            d.want_freeze = true;
            self.wake = true;
        }
    }

    /// The engine buffers no op: every memtable is flushed and installed (`true` also without the engine).
    pub fn olsm_flushed(&self) -> bool {
        #[cfg(feature = "splinterdb")]
        if let Some(mem) = &self.state.splinter_mem {
            return mem.is_empty();
        }
        #[cfg(feature = "rocksdb")]
        if let Some(mem) = &self.state.rocks_mem {
            return mem.is_empty();
        }
        self.state
            .olsm
            .as_ref()
            .is_none_or(|o| o.active.is_empty() && o.frozen.is_none())
    }

    /// Freeze size of the active memtable (`mt_soft`, bytes): the batch size of the S7 upgrade (adr 0611).
    pub fn olsm_batch_bytes(&self) -> Option<usize> {
        self.ol.as_ref().map(|d| d.mt_soft)
    }

    /// Bytes of the engine's omap on this shard: device blocks of the live runs (chunks and meta, tier 0 and every
    /// partition) plus the keys and values buffered in both memtables. `None` = store without the engine.
    pub fn olsm_bytes(&self) -> Option<u64> {
        #[cfg(feature = "rocksdb")]
        if let Some(r) = &self.rocks {
            let mem = self
                .state
                .rocks_mem
                .as_ref()
                .expect("RocksDB buffers")
                .bytes();
            return Some(r.client.allocated_bytes().saturating_add(mem as u64));
        }
        let o = self.state.olsm.as_ref()?;
        let mem = o.active.bytes() + o.frozen.as_ref().map_or(0, |f| f.bytes());
        #[cfg(feature = "splinterdb")]
        if let Some(r) = &self.splinter {
            let mem = self
                .state
                .splinter_mem
                .as_ref()
                .expect("SplinterDB buffers")
                .bytes();
            return Some(r.client.allocated_bytes().saturating_add(mem as u64));
        }
        Some(o.man.space().blocks * BLK as u64 + mem as u64)
    }
}

/// The engine's sources with `over` as the newest memtable.
fn with_over<'a>(
    o: &'a Olsm,
    over: Option<&'a crate::olsm::Memtable>,
) -> crate::olsm::read::Sources<'a> {
    o.sources_over(over)
}

/// Lsn of the oldest omap op only in a memtable of `o` (`None`: nothing buffered).
fn olsm_floor_of(o: &Olsm) -> Option<u64> {
    match &o.frozen {
        Some(f) => Some(f.lsn_lo()),
        None => (!o.active.is_empty()).then(|| o.active.lsn_lo()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::{SimClock, SimConfig, SimDev, SimDisk};
    use crate::layout::{MkfsParams, mkfs};

    fn mounted() -> Shard<SimDev> {
        mounted_with(false)
    }

    /// The run cache and the data cache share the tree budget the tree has not allocated: each may take the other's
    /// unused part, never less than half.
    #[test]
    fn lend_share_takes_the_unused_part_and_keeps_half() {
        let f = Shard::<SimDev>::lend_share;
        assert_eq!(f(100, 0), 100);
        assert_eq!(f(100, 30), 70);
        assert_eq!(f(100, 50), 50);
        assert_eq!(f(100, 100), 50);
        assert_eq!(f(101, 101), 51);
        assert_eq!(f(0, 7), 0);
    }

    /// A store with the omap engine: the run cache's capacity follows the tree budget the tree has not allocated.
    #[test]
    fn run_cache_borrows_the_unallocated_tree_budget() {
        let mut sh = mounted_with(true);
        let own = sh.ol.as_ref().expect("engine").own_cap;
        sh.olsm_step();
        let lend = sh.lendable() as usize;
        assert!(lend > 0);
        let cap = sh.ol.as_ref().expect("engine").cache.cap();
        assert_eq!(
            cap,
            own + Shard::<SimDev>::lend_share(lend as u64, 0) as usize
        );
        // the data cache reports what it holds above its floor: the run cache keeps at least half
        sh.set_data_cache_held(lend as u64);
        sh.olsm_step();
        let cap = sh.ol.as_ref().expect("engine").cache.cap();
        assert_eq!(cap, own + (lend - lend / 2));
    }

    fn mounted_with(omap_lsm: bool) -> Shard<SimDev> {
        mounted_on(&SimDisk::new(SimConfig::new(64 << 20)), omap_lsm)
    }

    fn mounted_on(disk: &SimDisk, omap_lsm: bool) -> Shard<SimDev> {
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let (sb, dirs) = mkfs(
            &mut dev,
            &mut clk,
            &MkfsParams {
                shards: 1,
                wal_blocks: 512,
                align_blocks: 1,
                cell_pages: 128,
                omap_lsm,
                ..Default::default()
            },
        )
        .unwrap();
        Shard::mount(dev, &mut clk, &sb, &dirs[0], ShardCfg::default(), false)
            .unwrap()
            .0
    }

    fn pressure_poll(sh: &mut Shard<SimDev>, clk: &mut SimClock) {
        let mut events = Vec::new();
        sh.poll(clk.t, &mut events);
        assert!(sh.failed.is_none(), "{:?}", sh.failed);
        clk.idle(sh.dev.next_deadline());
    }

    fn pressure_submit(sh: &mut Shard<SimDev>, clk: &mut SimClock, mut t: Txn<Vec<u8>>) {
        for _ in 0..10_000 {
            match sh.submit(t) {
                Ok(_) => return,
                Err((StoreError::Busy | StoreError::WalFull | StoreError::Miss, back)) => {
                    t = back;
                    pressure_poll(sh, clk);
                }
                Err((e, _)) => panic!("unexpected submit error {e:?}"),
            }
        }
        panic!("admission did not resume");
    }

    fn pressure_put(token: u64, key: &[u8], value: &[u8]) -> Txn<Vec<u8>> {
        use crate::olsm::wire::{OOp, put_blob};
        let (n, blob) = put_blob(&[(key.to_vec(), value.to_vec())]);
        let mut t = Txn::new(token);
        t.ops.push(Op::Omap(OOp::Put { id: 1, n, blob }));
        t
    }

    /// Real WAL puts, flushes and point tombstones create the debt and GC job. Nothing replaces the space
    /// predicate or fabricates its live/used gauges. Stop polling while a real merge owns its input runs.
    fn pressure_debt_fixture() -> (Shard<SimDev>, SimClock) {
        use crate::olsm::wire::{OOp, del_blob, put_blob};
        let mut sh = mounted_with(true);
        let mut clk = SimClock::default();
        sh.ol.as_mut().unwrap().mt_soft = 32 << 10;
        sh.state.olsm.as_mut().unwrap().man = Manifest::new(32 << 10);
        for batch in 0u64..16 {
            let pairs: Vec<_> = (batch * 128..(batch + 1) * 128)
                .map(|i| (i.to_be_bytes().to_vec(), vec![7; 256]))
                .collect();
            let (n, blob) = put_blob(&pairs);
            let mut t = Txn::new(batch + 1);
            t.ops.push(Op::Omap(OOp::Put { id: 1, n, blob }));
            pressure_submit(&mut sh, &mut clk, t);
            for _ in 0..20 {
                pressure_poll(&mut sh, &mut clk);
            }
        }
        sh.ol.as_mut().unwrap().want_freeze = true;
        for _ in 0..2000 {
            pressure_poll(&mut sh, &mut clk);
        }
        let mut t = Txn::new(100);
        t.ops.push(Op::Omap(OOp::Del {
            id: 1,
            blob: del_blob(
                &(0u64..1024)
                    .map(|i| i.to_be_bytes().to_vec())
                    .collect::<Vec<_>>(),
            ),
        }));
        pressure_submit(&mut sh, &mut clk, t);
        sh.ol.as_mut().unwrap().want_freeze = true;
        for _ in 0..10_000 {
            pressure_poll(&mut sh, &mut clk);
            let d = sh.ol.as_ref().unwrap();
            let o = sh.state.olsm.as_ref().unwrap();
            if !d.slots[MERGE].free() && o.man.space_debt(d.stats.space_used_bytes) {
                assert!(sh.state.alloc.n_free() * BLK as u64 >= 2 * o.man.slack());
                assert_eq!(d.stats.alloc_waits, d.gc_wait_mark);
                assert!(o.frozen.is_none());
                return (sh, clk);
            }
        }
        panic!("real flushed deletes did not produce debt with an active merge");
    }

    fn pressure_value(sh: &mut Shard<SimDev>, clk: &mut SimClock, key: &[u8]) -> Option<Bytes> {
        for _ in 0..10_000 {
            match sh.olsm_get(None, 1, key) {
                Ok(value) => return value,
                Err(StoreError::Miss) => pressure_poll(sh, clk),
                Err(e) => panic!("read {e:?}"),
            }
        }
        panic!("read did not complete");
    }

    fn pressure_reserve_to(sh: &mut Shard<SimDev>, remaining: u64) -> Vec<(u64, u32)> {
        let mut held = Vec::new();
        while sh.state.alloc.n_free() > remaining {
            let want = (sh.state.alloc.n_free() - remaining) as u32;
            held.push(
                sh.state
                    .alloc
                    .reserve_upto(1, want)
                    .expect("test free blocks"),
            );
        }
        held
    }

    #[test]
    fn physical_pressure_admission_debt_with_headroom_keeps_real_omap_writable() {
        let (mut sh, mut clk) = pressure_debt_fixture();
        let refused = sh.ol.as_ref().unwrap().stats.space_throttled;
        sh.submit(pressure_put(101, b"foreground", b"accepted during GC"))
            .unwrap();
        assert_eq!(sh.ol.as_ref().unwrap().stats.space_throttled, refused);
        assert_eq!(
            pressure_value(&mut sh, &mut clk, b"foreground"),
            Some(Bytes::from_static(b"accepted during GC"))
        );
        assert_eq!(pressure_value(&mut sh, &mut clk, &0u64.to_be_bytes()), None);
        assert_eq!(
            pressure_value(&mut sh, &mut clk, &2047u64.to_be_bytes()),
            Some(Bytes::from(vec![7; 256]))
        );
    }

    #[test]
    fn physical_pressure_admission_low_free_parks_transaction_until_headroom_returns() {
        let (mut sh, mut clk) = pressure_debt_fixture();
        let threshold = 2 * sh.state.olsm.as_ref().unwrap().man.slack();
        let free_at_boundary = threshold.div_ceil(BLK as u64);
        let held = pressure_reserve_to(&mut sh, free_at_boundary - 1);
        let free = sh.state.alloc.n_free() * BLK as u64;
        assert!(free < threshold);
        assert!(
            free >= sh.state.olsm.as_ref().unwrap().man.slack(),
            "admission must protect two slack units while urgent GC still uses one"
        );
        let lsn = sh.next_lsn;
        let refused = sh.ol.as_ref().unwrap().stats.space_throttled;
        let (error, retry) = sh
            .submit(pressure_put(101, b"parked", b"exactly once"))
            .unwrap_err();
        assert_eq!(error, StoreError::Busy);
        assert_eq!(sh.next_lsn, lsn);
        assert_eq!(sh.ol.as_ref().unwrap().stats.space_throttled, refused + 1);
        assert_eq!(pressure_value(&mut sh, &mut clk, b"parked"), None);
        for (blk, n) in held {
            sh.unreserve(blk, n);
        }
        pressure_submit(&mut sh, &mut clk, retry);
        assert_eq!(
            pressure_value(&mut sh, &mut clk, b"parked"),
            Some(Bytes::from_static(b"exactly once"))
        );
    }

    #[test]
    fn physical_pressure_admission_failed_real_lease_parks_until_gc_progress() {
        let (mut sh, mut clk) = pressure_debt_fixture();
        let held = pressure_reserve_to(&mut sh, 0);
        let mut d = sh.ol.take().unwrap();
        let before = d.stats.alloc_waits;
        assert!(!sh.olsm_lease(&mut d, &mut Ctx::default()));
        assert_eq!(d.stats.alloc_waits, before + 1);
        sh.ol = Some(d);
        for (blk, n) in held {
            sh.unreserve(blk, n);
        }
        // Even after physical room returns, the failed lease remains a pressure signal until a GC pick.
        let (error, retry) = sh
            .submit(pressure_put(101, b"lease-wait", b"resumed"))
            .unwrap_err();
        assert_eq!(error, StoreError::Busy);
        pressure_submit(&mut sh, &mut clk, retry);
        assert_eq!(
            pressure_value(&mut sh, &mut clk, b"lease-wait"),
            Some(Bytes::from_static(b"resumed"))
        );
    }

    #[test]
    fn physical_pressure_admission_full_memtables_still_park_with_headroom() {
        let (mut sh, mut clk) = pressure_debt_fixture();
        let soft = sh.ol.as_ref().unwrap().mt_soft;
        sh.submit(pressure_put(101, b"frozen", &vec![3; soft]))
            .unwrap();
        pressure_poll(&mut sh, &mut clk);
        assert!(sh.state.olsm.as_ref().unwrap().frozen.is_some());
        sh.submit(pressure_put(102, b"active", &vec![4; soft]))
            .unwrap();
        let memory = sh.ol.as_ref().unwrap().stats.throttled;
        let space = sh.ol.as_ref().unwrap().stats.space_throttled;
        let (error, retry) = sh
            .submit(pressure_put(103, b"blocked", b"memory guard"))
            .unwrap_err();
        assert_eq!(error, StoreError::Busy);
        assert_eq!(sh.ol.as_ref().unwrap().stats.throttled, memory + 1);
        assert_eq!(sh.ol.as_ref().unwrap().stats.space_throttled, space);
        pressure_submit(&mut sh, &mut clk, retry);
        assert_eq!(
            pressure_value(&mut sh, &mut clk, b"blocked"),
            Some(Bytes::from_static(b"memory guard"))
        );
        assert_eq!(
            pressure_value(&mut sh, &mut clk, b"frozen"),
            Some(Bytes::from(vec![3; soft]))
        );
        assert_eq!(
            pressure_value(&mut sh, &mut clk, b"active"),
            Some(Bytes::from(vec![4; soft]))
        );
    }

    #[test]
    fn gc_prefix_ring_fallback_returns_only_unpublished_reservations() {
        use crate::olsm::manifest::{MergePick, Region};
        use crate::olsm::remote::Task;
        use crate::olsm::{Gk, Place, RunMeta};
        use std::sync::Arc;

        let mut sh = mounted_with(true);
        let mut sentinel = Txn::new(17);
        sentinel
            .ops
            .push(Op::Put(b"sentinel".to_vec(), b"unchanged".to_vec()));
        sh.submit(sentinel).unwrap();
        let lsn_before = sh.next_lsn;
        let input_block = sh.alloc_sys(1).unwrap();
        let output_block = sh.alloc_sys(1).unwrap();
        let free_before = sh.state.alloc.n_free();
        let mut input = RunMeta::default();
        input.id = 1;
        input.lsn_lo = 1;
        input.lsn_hi = 1;
        input.meta_blk = input_block;
        input.meta_nblk = 1;
        let input = Arc::new(input);
        let pick = MergePick {
            inputs: vec![input.clone()],
            bottom: true,
            src_tier: 0,
            dst_tier: 1,
            regions: vec![Region {
                lo: Gk::MIN,
                hi: None,
                part: None,
            }],
            cut: crate::olsm::CHUNK_TARGET as u64,
            stay: false,
            first_id: 10,
            end_id: 20,
            gc: true,
        };
        let mut d = sh.ol.take().unwrap();
        let mut o = sh.state.olsm.take().unwrap();
        let old_id = sh.next_compaction_id();
        // Force the actual encoded-record/ring guard with an oversized descriptor. No test hook changes the limit.
        let mut oversized = RunMeta::default();
        oversized.id = 1;
        oversized.meta_blk = output_block;
        oversized.meta_nblk = 1;
        oversized.place = Place {
            tier: 1,
            lo: Gk {
                id: 1,
                key: Bytes::from(vec![b'x'; sh.ring_bytes() as usize]),
            },
            hi: None,
        };
        d.slots[MERGE].job = Some(Box::new(OlsmJob::new(
            old_id,
            MERGE as u8,
            Task::Merge {
                job: Box::new(MergeJob::new(pick)),
                out: Some(crate::olsm::job::MergeOut {
                    residuals: vec![oversized],
                    prefix_end: Some(Gk::new(1, b"cut")),
                    freed: vec![(input_block, 1)],
                    ..Default::default()
                }),
            },
        )));
        d.slots[MERGE].written.push(Extent {
            blk: output_block,
            nblk: 1,
            crcs: vec![0],
        });
        sh.olsm_manifest(&mut d, &mut o, MERGE).unwrap();
        assert!(sh.failed.is_none());
        assert_eq!(
            sh.next_lsn, lsn_before,
            "rejected prefix must not apply a record"
        );
        assert_eq!(sh.state.alloc.n_free(), free_before + 1);
        assert!(
            sh.state.alloc.is_reserved(input_block, 1),
            "original input stays held"
        );
        assert!(
            !sh.state.alloc.is_reserved(output_block, 1),
            "new output returned exactly once"
        );
        let slot = &d.slots[MERGE];
        assert!(slot.written.is_empty() && slot.pre.is_empty() && slot.reads.is_empty());
        assert!(slot.wake && !slot.ready);
        let restarted = slot.job.as_ref().unwrap();
        assert_ne!(
            restarted.id(),
            old_id,
            "late reads must not attach to the new job"
        );
        let Task::Merge { job, out } = &restarted.task else {
            panic!("merge restarted as flush")
        };
        assert!(job.gc() && out.is_none());
        assert_eq!(job.inputs()[0].id, input.id);
        assert_eq!(job.inputs()[0].meta_blk, input.meta_blk);
        assert_eq!(d.stats.man_retries, 1);
        let mut actual = Vec::new();
        assert!(sh.get(b"sentinel", &mut actual).unwrap());
        assert_eq!(actual, b"unchanged");
        assert!(
            !sh.get(&run_key(1), &mut Vec::new()).unwrap(),
            "no suffix descriptor was published"
        );
    }

    /// A finished (non-prefix) merge whose manifest txn exceeds the store's per-txn limits never fails the shard: its
    /// unpublished output goes back, its locks go, the run set and the WAL stay unchanged and later picks stay within
    /// half its inputs (before: `olsm_drive` failed the shard and every parked txn returned `TooLarge`).
    #[test]
    fn oversized_merge_manifest_is_dropped_without_failing_the_shard() {
        use crate::olsm::manifest::{MergePick, Region};
        use crate::olsm::remote::Task;
        use crate::olsm::{Gk, Place, RunMeta};
        use std::sync::Arc;

        let mut sh = mounted_with(true);
        let mut sentinel = Txn::new(17);
        sentinel
            .ops
            .push(Op::Put(b"sentinel".to_vec(), b"unchanged".to_vec()));
        sh.submit(sentinel).unwrap();
        let lsn_before = sh.next_lsn;
        let input_block = sh.alloc_sys(1).unwrap();
        let output_block = sh.alloc_sys(1).unwrap();
        let free_before = sh.state.alloc.n_free();
        let mut input = RunMeta::default();
        input.id = 1;
        input.lsn_lo = 1;
        input.lsn_hi = 1;
        input.meta_blk = input_block;
        input.meta_nblk = 1;
        let input = Arc::new(input);
        let pick = MergePick {
            inputs: vec![input.clone()],
            bottom: true,
            src_tier: 0,
            dst_tier: 1,
            regions: vec![Region {
                lo: Gk::MIN,
                hi: None,
                part: None,
            }],
            cut: crate::olsm::CHUNK_TARGET as u64,
            stay: false,
            first_id: 10,
            end_id: 20,
            gc: false,
        };
        let mut d = sh.ol.take().unwrap();
        let mut o = sh.state.olsm.take().unwrap();
        // The real encoded-record/ring guard refuses an oversized output descriptor; no test hook changes the limit.
        let mut oversized = RunMeta::default();
        oversized.id = 10;
        oversized.meta_blk = output_block;
        oversized.meta_nblk = 1;
        oversized.place = Place {
            tier: 1,
            lo: Gk {
                id: 1,
                key: Bytes::from(vec![b'x'; sh.ring_bytes() as usize]),
            },
            hi: None,
        };
        d.slots[MERGE].job = Some(Box::new(OlsmJob::new(
            sh.next_compaction_id(),
            MERGE as u8,
            Task::Merge {
                job: Box::new(MergeJob::new(pick)),
                out: Some(crate::olsm::job::MergeOut {
                    runs: vec![oversized],
                    freed: vec![(input_block, 1)],
                    ..Default::default()
                }),
            },
        )));
        d.slots[MERGE].written.push(Extent {
            blk: output_block,
            nblk: 1,
            crcs: vec![0],
        });
        sh.olsm_manifest(&mut d, &mut o, MERGE).unwrap();
        assert!(sh.failed.is_none());
        assert_eq!(
            sh.next_lsn, lsn_before,
            "refused manifest applies no record"
        );
        assert_eq!(sh.state.alloc.n_free(), free_before + 1);
        assert!(
            sh.state.alloc.is_reserved(input_block, 1),
            "original input stays held"
        );
        assert!(
            !sh.state.alloc.is_reserved(output_block, 1),
            "new output returned exactly once"
        );
        let slot = &d.slots[MERGE];
        assert!(
            slot.free() && slot.written.is_empty() && slot.pre.is_empty() && slot.reads.is_empty()
        );
        assert_eq!(d.stats.merges_refused, 1);
        assert_eq!(d.stats.merges, 0);
        assert_eq!(
            d.refused_inputs, 0,
            "a merge of one run did not fit: none does"
        );
        assert_eq!(sh.olsm_max_inputs(&d), 0);
        let mut actual = Vec::new();
        assert!(sh.get(b"sentinel", &mut actual).unwrap());
        assert_eq!(actual, b"unchanged");
        assert!(
            !sh.get(&run_key(10), &mut Vec::new()).unwrap(),
            "no output descriptor was published"
        );
        sh.state.olsm = Some(o);
        sh.ol = Some(d);
    }

    /// No queue room for a run-chunk read: `olsm_read_room` must refuse without waking the shard. A wake on refusal made
    /// `miss_wait` return before `idle` advanced the clock, so the in-flight ops that free the queue never completed and
    /// the read was retried forever.
    #[test]
    fn olsm_no_room_read_does_not_wake_shard() {
        let mut sh = mounted();
        // fill the device queue with in-flight writes: no room for a read above the data floor
        while sh.dev.queue_space() > 0 {
            assert!(sh.dev.submit_write(0, vec![0; 4096], 0).is_ok());
        }
        assert_eq!(sh.dev.queue_space(), 0);
        assert!(!sh.olsm_read_room(4), "expected no room for the read");
        assert!(!sh.wake, "a refused read must not set the shard wake");
    }

    /// A demand chunk read refused for queue room parks its reader with no read of its own in flight (`miss_wait`): the
    /// refusal does not wake, the first poll whose completions free the room does (before: the reader waited forever
    /// when the IO that held the queue was not an engine read).
    #[test]
    fn olsm_no_room_read_is_woken_when_room_frees() {
        let mut sh = mounted_with(true);
        // queue held by IO that is not an engine read (a pad write of no pipeline unit: its completion wakes nobody)
        while sh.dev.queue_space() > 0 {
            assert!(
                sh.dev
                    .submit_write(0, vec![0; 4096], super::super::K_PAD)
                    .is_ok()
            );
        }
        let mut d = sh.ol.take().expect("engine on");
        let r = Io {
            sh: &mut sh,
            d: &mut d,
        }
        .read_checked(64, 4);
        assert!(matches!(r, Err(StoreError::Miss)));
        assert_eq!(d.room_wait, 4);
        assert!(d.rds.is_empty() && d.unsent.is_empty(), "no read started");
        sh.ol = Some(d);
        assert!(!sh.wake, "a refused read must not set the shard wake");
        assert!(sh.olsm_busy(), "a room waiter keeps the driver polled");
        let mut clk = SimClock::default();
        let mut woke = false;
        for _ in 0..100 {
            let mut ev = Vec::new();
            sh.poll(clk.t, &mut ev);
            if ev.iter().any(|e| matches!(e, Event::Wake)) {
                woke = true;
                break;
            }
            clk.idle(sh.dev.next_deadline());
        }
        assert!(woke, "the reader was never woken");
        assert_eq!(sh.ol.as_ref().unwrap().room_wait, 0);
        assert!(sh.olsm_read_room(4));
    }

    /// A cold omap read whose buffer the DMA budget refused (in-flight IO memory, adr 0175 am. 4) waits in
    /// [`OlsmDrv::sending`] with no part sent, holding its reader pin: the shard counts as busy (else an idle poll would never retry it) and as having reads
    /// pending, a later poll sends it, it lands in the cache and the pin goes.
    #[test]
    fn olsm_read_refused_dma_memory_is_sent_by_a_later_poll() {
        // a device that reads only into its DMA pool (no ordinary-memory cache reads)
        let disk = SimDisk::new(SimConfig {
            ram_reads: false,
            ..SimConfig::new(64 << 20)
        });
        let mut sh = mounted_on(&disk, true);
        let mut d = sh.ol.take().expect("engine on");
        disk.refuse_io_bufs(1);
        let tok = d.cache.start(64, 1);
        sh.olsm_read(&mut d, 64, 1, ReadTo::Cache(tok));
        let rid = d.sending.expect("refused: it waits for memory");
        assert_eq!(d.rds[&rid].sent, 0);
        assert!(d.unsent.is_empty() && d.parts.is_empty());
        assert!(!sh.readers.is_empty(), "the waiting read pins its epoch");
        sh.ol = Some(d);
        assert!(sh.olsm_busy() && sh.olsm_reads_pending());
        let mut clk = SimClock::default();
        for _ in 0..100 {
            sh.poll(clk.t, &mut Vec::new());
            if !sh.olsm_reads_pending() {
                break;
            }
            clk.idle(sh.dev.next_deadline());
        }
        let d = sh.ol.as_mut().unwrap();
        assert!(d.sending.is_none() && d.rds.is_empty(), "never sent");
        assert!(d.cache.get(64, 1).is_some(), "the read landed");
        assert!(sh.readers.is_empty(), "the read kept its reader pin");
        assert_eq!(disk.stats().refused_io_bufs, 1);
    }

    /// A cold read longer than one transfer (a chunk of one large entry) under a DMA budget that admits one part per
    /// poll: each part takes its own buffer right before its submit and lands in the assembly while the next waits, so
    /// the read completes, byte-exact and in order (adr 0175 am. 4). Before, all parts were allocated before the first
    /// submit and a refusal dropped the set: such a read never went out.
    #[test]
    fn olsm_read_longer_than_the_budget_admits_completes_part_by_part() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        let mut sh = mounted_on(&disk, true);
        let mx = sh.max_xfer_blk as u32;
        let (blk, nblk) = (12_000u64, 4 * mx);
        let mut q = disk.queue();
        let mut t = 0;
        let want: Vec<u8> = (0..nblk as usize * BLK)
            .map(|i| (i / BLK) as u8 ^ (i as u8))
            .collect();
        let mut b = q.alloc_buf_uninit(want.len().min(mx as usize * BLK));
        for p in 0..4usize {
            let len = mx as usize * BLK;
            b.copy_from_slice(&want[p * len..(p + 1) * len]);
            assert!(
                q.submit_write((blk + (p * mx as usize) as u64) * sh.lpb, b, 1)
                    .is_ok()
            );
            let mut out = Vec::new();
            while out.is_empty() {
                t = q.next_deadline().unwrap_or(t + 1).max(t);
                q.poll(t, &mut out);
            }
            b = out.pop().unwrap().buf.unwrap();
        }
        let mut d = sh.ol.take().expect("engine on");
        disk.refuse_io_bufs_after(1, 1);
        let tok = d.cache.start(blk, nblk);
        sh.olsm_read(&mut d, blk, nblk, ReadTo::Cache(tok));
        assert!(
            d.unsent.is_empty() && d.sending.is_some(),
            "first part sent, the second waits for memory"
        );
        sh.ol = Some(d);
        let mut clk = SimClock { t };
        for _ in 0..200 {
            // every pass admits one more buffer, then refuses one
            disk.refuse_io_bufs_after(1, 1);
            sh.poll(clk.t, &mut Vec::new());
            if !sh.olsm_reads_pending() {
                break;
            }
            clk.idle(sh.dev.next_deadline());
        }
        disk.clear_faults();
        let d = sh.ol.as_mut().unwrap();
        assert!(d.rds.is_empty() && d.sending.is_none(), "never completed");
        assert_eq!(
            d.cache.get(blk, nblk).as_deref(),
            Some(&want[..]),
            "assembled in order"
        );
        assert!(disk.stats().refused_io_bufs >= 3);
    }

    /// A finished task (stand-in for a merge: only the slot's job identity matters here).
    fn done_task() -> Task {
        let mem = std::sync::Arc::new(crate::olsm::Memtable::new());
        Task::Flush {
            job: Box::new(crate::olsm::job::FlushJob::new(&mem, 1)),
            mem,
            out: Some(crate::olsm::RunMeta::default()),
        }
    }

    /// An input chunk read of a job that finished completes after the next job started in the slot and asked for the same
    /// extent: it must not land in the new job's prefetch (the extent may hold other data by the time the new job wants
    /// it), and the read's reader pin is released; the new job's own read then lands.
    #[test]
    fn olsm_late_job_read_does_not_feed_next_job() {
        let mut sh = mounted_with(true);
        let mut d = sh.ol.take().expect("engine on");
        let ext = (64u64, 1u32);
        let read = |sh: &mut Shard<SimDev>, d: &mut OlsmDrv| {
            let id = d.slots[MERGE].id().expect("job");
            d.slots[MERGE].reads.insert(ext);
            sh.olsm_read(d, ext.0, ext.1, ReadTo::Job(MERGE, id, ext));
            d.next_part
        };
        sh.olsm_start(&mut d, MERGE, done_task());
        let old = read(&mut sh, &mut d);
        // the job finishes (done branch of the prepare) and leaves the slot with its manifest txn
        sh.olsm_prepare(&mut d, MERGE);
        assert!(d.slots[MERGE].reads.is_empty());
        d.slots[MERGE].job = None;
        assert!(d.slots[MERGE].free());
        sh.olsm_start(&mut d, MERGE, done_task());
        let new = read(&mut sh, &mut d);
        sh.ol = Some(d);
        let buf = sh.dev.alloc_buf_uninit(BLK);
        sh.olsm_read_done(old, buf);
        let d = sh.ol.as_ref().unwrap();
        assert!(
            d.slots[MERGE].pre.is_empty(),
            "a finished job's read landed in the next job's prefetch"
        );
        assert!(d.slots[MERGE].reads.contains(&ext));
        let buf = sh.dev.alloc_buf_uninit(BLK);
        sh.olsm_read_done(new, buf);
        let d = sh.ol.as_ref().unwrap();
        assert!(d.slots[MERGE].pre.contains_key(&ext));
        assert!(d.slots[MERGE].reads.is_empty() && d.rds.is_empty());
        assert!(sh.readers.is_empty(), "a read kept its reader pin");
    }

    #[test]
    fn scan_prefetch_defaults_are_adaptive_and_master_disable_wins() {
        let mut sh = mounted_with(true);
        let s = sh.olsm_stats().unwrap();
        assert_eq!(
            (
                s.scan_prefetch_fixed,
                s.scan_prefetch_adaptive,
                s.scan_prefetch_window
            ),
            (0, 1, 1)
        );
        sh.cfg.omap_scan_prefetch = false;
        for adaptive in [true, false] {
            sh.cfg.omap_scan_prefetch_adaptive = adaptive;
            let s = sh.olsm_stats().unwrap();
            assert_eq!(
                (
                    s.scan_prefetch_fixed,
                    s.scan_prefetch_adaptive,
                    s.scan_prefetch_window
                ),
                (0, 0, 0)
            );
            let mut d = sh.ol.take().unwrap();
            Io {
                sh: &mut sh,
                d: &mut d,
            }
            .prefetch(1000, 1);
            assert_eq!(d.cache.prefetch_stats.submitted, 0);
            sh.ol = Some(d);
        }
    }

    #[test]
    fn scan_prefetch_reserves_split_demand_slots_and_releases_forgotten_reader_pins() {
        let mut sh = mounted_with(true);
        sh.cfg.omap_scan_prefetch = true;
        sh.cfg.omap_scan_prefetch_chunks = 4;
        sh.cfg.omap_scan_prefetch_adaptive = false;
        sh.max_xfer_blk = 1; // every block occupies one queue slot
        let mut d = OlsmDrv::new(1 << 20, 1 << 20);
        // A partly full cold cache may be reclaimed, but still cannot enlarge the speculative share.
        let cold = d.cache.start(2000, 120);
        d.cache.done(cold, Some(Bytes::from(vec![0; 120 * BLK])));
        d.cache.op_done();
        {
            let mut io = Io {
                sh: &mut sh,
                d: &mut d,
            };
            io.prefetch(1000, 16);
            io.prefetch(1100, 16);
            io.prefetch(1200, 16); // half-share exhausted, despite enough total queue room
            io.prefetch(1400, 16);
            assert_eq!(io.scan_prefetch_chunks(), 4);
            assert_eq!(io.d.prefetch_slots, 32);
            assert_eq!(io.d.cache.prefetch_stats.submitted, 2);
            assert_eq!(io.d.cache.prefetch_stats.throttled, 2);
            assert!(io.sh.dev.queue_space() >= io.sh.data_floor() + 16);
            assert!(matches!(io.read(1300, 16), Err(StoreError::Miss)));
            assert!(
                io.d.cache.pending(1300, 16),
                "full split demand admitted beside hints"
            );
            io.d.cache.forget(&[(1000, 16), (1100, 16)]);
            assert_eq!(
                io.d.prefetch_slots, 32,
                "pins and slots held until actual I/O completion"
            );
        }
        assert!(!sh.readers.is_empty());
        sh.ol = Some(d);
        // Deliver all but one part of the first split hint: reservation stays conservative, pressure discount follows parts.
        let tags: Vec<_> = sh
            .ol
            .as_ref()
            .unwrap()
            .parts
            .iter()
            .filter_map(|(tag, (rid, _))| (*rid == 1).then_some(*tag))
            .take(15)
            .collect();
        for tag in tags {
            let buf = sh.dev.alloc_buf_uninit(BLK);
            sh.olsm_read_done(tag, buf);
        }
        assert_eq!(sh.ol.as_ref().unwrap().prefetch_slots, 32);
        assert_eq!(sh.ol.as_ref().unwrap().prefetch_pending_parts, 17);
        let mut clk = SimClock::default();
        for _ in 0..100 {
            clk.idle(sh.dev.next_deadline());
            sh.poll(clk.t, &mut Vec::new());
            if sh.ol.as_ref().unwrap().rds.is_empty() {
                break;
            }
        }
        let d = sh.ol.as_mut().unwrap();
        assert!(d.rds.is_empty());
        assert_eq!(d.prefetch_slots, 0);
        assert_eq!(d.cache.prefetch_stats.inflight_bytes, 0);
        assert_eq!(d.cache.prefetch_stats.unused, 2);
        assert!(d.cache.get(1000, 16).is_none());
        assert!(d.cache.get(1300, 16).is_some());
        assert!(
            sh.readers.is_empty(),
            "late speculative completions released all epoch pins"
        );
    }

    #[test]
    fn scan_prefetch_shallow_queue_never_uses_demand_or_wal_floor() {
        let mut sh = mounted_with(true);
        sh.cfg.omap_scan_prefetch = true;
        sh.cfg.omap_scan_prefetch_chunks = 4;
        sh.cfg.omap_scan_prefetch_adaptive = false;
        // Occupy all but the reserved demand share and WAL floor.
        let reserve = sh.data_floor() + 1;
        while sh.dev.queue_space() > reserve {
            sh.dev.submit_write(0, vec![0; BLK], 0).unwrap();
        }
        let mut d = OlsmDrv::new(1 << 20, 1 << 20);
        let mut io = Io {
            sh: &mut sh,
            d: &mut d,
        };
        for blk in 1000..1004 {
            io.prefetch(blk, 1);
        }
        assert_eq!(io.d.prefetch_slots, 0);
        assert_eq!(io.d.cache.prefetch_stats.throttled, 4);
        assert!(matches!(io.read(1000, 1), Err(StoreError::Miss)));
        assert!(io.d.cache.pending(1000, 1));
        assert!(io.sh.dev.queue_space() >= io.sh.data_floor());
    }
    #[test]
    fn scan_prefetch_adaptive_survives_rebuilt_readers_and_ignores_own_admission() {
        let mut sh = mounted_with(true);
        sh.cfg.omap_scan_prefetch = true;
        sh.cfg.omap_scan_prefetch_adaptive = true;
        sh.cfg.omap_scan_prefetch_max_chunks = 3;
        let mut d = OlsmDrv::new(1 << 20, 1 << 20);
        for i in 0..16 {
            let blk = 1000 + i * 16;
            let token = d.cache.start_prefetch(blk, 16).unwrap();
            d.cache.prefetch_wait(blk, 16);
            d.cache.done(token, Some(Bytes::from(vec![0; 16 * BLK])));
            // New Io each time, as on a listing retry; promotion feeds the persistent shard controller.
            let mut io = Io {
                sh: &mut sh,
                d: &mut d,
            };
            assert!(io.read(blk, 16).is_ok());
            io.d.cache.op_done();
        }
        assert_eq!((d.adaptive.window, d.adaptive.grows), (3, 2));
        sh.max_xfer_blk = 1;
        {
            let mut io = Io {
                sh: &mut sh,
                d: &mut d,
            };
            for blk in [2000, 2100, 2200, 2300] {
                io.prefetch(blk, 16);
            }
            assert_eq!(
                io.d.adaptive.shrinks, 0,
                "own speculative half-share is admission only"
            );
        }
        // Demand protection, not our quota, triggers one pressure decrease despite overlap retries.
        let demand = d.cache.start(3000, 128);
        d.cache.done(demand, Some(Bytes::from(vec![0; 128 * BLK])));
        for _ in 0..20 {
            let mut io = Io {
                sh: &mut sh,
                d: &mut d,
            };
            io.prefetch(2000, 16);
        }
        assert_eq!((d.adaptive.window, d.adaptive.shrinks), (1, 1));
        sh.cfg.omap_scan_prefetch_adaptive = false;
        sh.cfg.omap_scan_prefetch_chunks = 4;
        assert_eq!(
            Io {
                sh: &mut sh,
                d: &mut d
            }
            .scan_prefetch_chunks(),
            4
        );
    }
    #[test]
    fn scan_prefetch_adaptive_pressure_discounts_only_uncompleted_parts() {
        let mut sh = mounted_with(true);
        sh.cfg.omap_scan_prefetch = true;
        sh.cfg.omap_scan_prefetch_adaptive = true;
        sh.max_xfer_blk = 1;
        let demand = crate::olsm::CHUNK_MAX as usize;
        // Independent writes leave less than one demand read, even discounting the last speculative part.
        while sh.dev.queue_space() > sh.data_floor() + demand - 2 {
            sh.dev.submit_write(0, vec![0; BLK], 0).unwrap();
        }
        let mut d = OlsmDrv::new(1 << 20, 1 << 20);
        d.adaptive.window = 8;
        d.prefetch_slots = 16; // split read reservation, fifteen parts already completed
        d.prefetch_pending_parts = 1;
        for _ in 0..20 {
            Io {
                sh: &mut sh,
                d: &mut d,
            }
            .adapt();
        }
        assert_eq!((d.adaptive.window, d.adaptive.shrinks), (4, 1));
    }

    /// A queued data read may need more slots than the target-chunk reserve. Until its complete batch
    /// fits, repeated listing retries must yield newly freed slots; admission resumes after it leaves.
    #[test]
    fn scan_prefetch_yields_to_waiting_client_read_batch() {
        use crate::obj::ShardStore;
        let mut ss = ShardStore::new(mounted_with(true), 0);
        ss.sh.cfg.omap_scan_prefetch = true;
        let mut d = OlsmDrv::new(1 << 20, 1 << 20);
        let mut clk = SimClock::default();
        let batch = 80; // larger than the reserved target demand chunk
        let mut token = 0;
        while ss.sh.dev.queue_space() > 24 {
            token += 1;
            ss.sh.submit_read(64, 1, token, false).unwrap();
        }
        ss.pf_admit(64, batch as u64, batch);
        assert_eq!(ss.pf_waiters(), 1);
        assert!(ss.sh.read_admission_waiting);
        for blk in 1000..1016 {
            Io {
                sh: &mut ss.sh,
                d: &mut d,
            }
            .prefetch(blk, 1);
        }
        assert_eq!(d.cache.prefetch_stats.submitted, 0);
        assert_eq!(d.cache.prefetch_stats.throttled, 16);
        for _ in 0..ss.sh.dev.queue_depth() {
            clk.idle(ss.sh.dev.next_deadline());
            ss.pump(&mut clk).unwrap();
            Io {
                sh: &mut ss.sh,
                d: &mut d,
            }
            .prefetch(2000, 1);
            assert_eq!(
                d.cache.prefetch_stats.submitted, 0,
                "waiter owns freed slots"
            );
            if ss.sh.dev.queue_space() == ss.sh.dev.queue_depth() {
                break;
            }
        }
        assert!(
            ss.sh.readers.is_empty(),
            "all queued reads released their epoch pins"
        );
        ss.pf_admit(64, batch as u64, batch);
        assert_eq!(ss.pf_waiters(), 0);
        assert!(!ss.sh.read_admission_waiting);
        // Submit the real admitted batch before another listing can consume the queue.
        for blk in 64..64 + batch as u64 {
            assert!(ss.pf_submit(blk, 1, 64));
        }
        Io {
            sh: &mut ss.sh,
            d: &mut d,
        }
        .prefetch(3000, 1);
        assert_eq!(d.cache.prefetch_stats.submitted, 1);
    }

    #[test]
    fn scan_prefetch_waiter_guard_clears_on_expiry_and_lease_release() {
        use crate::obj::ShardStore;
        let mut ss = ShardStore::new(mounted_with(true), 0);
        let mut token = 0;
        while ss.sh.dev.queue_space() > 24 {
            token += 1;
            ss.sh.submit_read(64, 1, token, false).unwrap();
        }
        ss.pf_admit(64, 80, 80);
        assert_eq!(ss.pf_waiters(), 1);
        assert!(ss.sh.read_admission_waiting);
        ss.pump_at(50_000_001).unwrap(); // abandoned unleased waiter expires
        assert!(!ss.sh.read_admission_waiting);
        assert!(
            ss.sh.readers.is_empty(),
            "expired reads released every epoch pin"
        );
        // Occupy the queue again after reaping the earlier reads.
        while ss.sh.dev.queue_space() > 24 {
            token += 1;
            ss.sh.submit_read(64, 1, token, false).unwrap();
        }
        ss.lease_open(7);
        ss.lease = 7;
        ss.pf_admit(64, 80, 80);
        assert_eq!(ss.pf_waiters(), 1);
        ss.pump_at(100_000_002).unwrap();
        assert!(ss.sh.read_admission_waiting, "leased waiters do not expire");
        assert!(
            ss.sh.readers.is_empty(),
            "leased reads released every epoch pin"
        );
        ss.lease_release(7);
        assert!(!ss.sh.read_admission_waiting);
    }
}
