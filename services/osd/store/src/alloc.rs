// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Allocators (design 2.5, ADR 0021 amendments 1+2, 24).
//!
//! `Alloc`: per-shard data-region bitmap, 1 bit per 4 KiB block, three layers:
//!  * `alloc`    durable-state bits (what the applied tree says is allocated; persisted as `f` chunks in the tree);
//!  * `reserved` overlay: handed out by `reserve`, not yet part of a txn (cleared by `unreserve` or when the txn
//!    commits), so the durable bitmap never contains unlogged state;
//!  * `held`     blocks freed by txns that a checkpoint has not yet passed (amendment 2) plus blocks waiting for
//!    in-flight readers (epoch gate, owned by the shard).
//!
//! A block is allocatable iff none of the three is set (`busy` = union, computed per word on demand, not stored;
//! per-1 MiB-window busy counts). Allocation is next-fit: a lazily maintained tree of free-run summaries over the
//! windows (adr 0475 am. 2) finds the first fit from the cursor in O(log windows) node reads, then a word scan of one
//! window places it; same placement as a word scan from the cursor.
//!
//! RAM (adr 0021 am. 24): `alloc` and `held` are dense word vectors (1 bit per block each: on a used device both are
//! touched everywhere - random overwrites free blocks all over the region between two checkpoints - and a direct word
//! keeps the write path as fast as before). `reserved` lives only around the allocation cursor (in-flight writes):
//! a sparse two-level layer, a table with one slot per 4096-block chunk (512 B of bits) and lazily present chunks;
//! an absent chunk is all zero, a chunk whose last bit clears goes back to a pool. The chunks come from a pre-filled
//! pool (`maintain`, called from the shard poll, tops it up and trims it), so a steady-state set/clear never
//! allocates; only an empty pool (burst) falls back to the heap (`pool_misses`). RAM = 2 bits per block (was 4) +
//! 10 B per chunk + 17 B per window (busy count, run summary, run tree) + 512 B per chunk of reserved bits + the pool.
//! `MetaAlloc`: bitmap of tree pages in the meta region (persisted wholesale per checkpoint, A/B).

use crate::state::Bitmap;

/// Blocks per summary window (1 MiB).
pub const WIN: u64 = 256;
/// Window free-run summary not known (adr 0475): recomputed by the next scan that reads it.
const RUNS_DIRTY: u32 = u32::MAX;
/// Children per run-summary tree node (adr 0475 am. 2): a walk reads at most FAN nodes per level and side.
const LOG_FAN: u32 = 4;
const FAN: usize = 1 << LOG_FAN;
/// A tree node not known (recomputed from its children on read).
const DIRTY: Sum = Sum {
    pre: 0,
    suf: 0,
    max: u64::MAX,
    dmax: 0,
};

/// Free runs of a node of the run-summary tree (blocks; the union of the layers): free at its start, at its end, the
/// longest, the longest inside one partly used window (`reserve_dense`). Runs never join across an extent start, so
/// `pre` = node length iff the node is free and holds no extent start. Full windows (holes) and positions past the
/// region are busy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Sum {
    pre: u64,
    suf: u64,
    max: u64,
    dmax: u64,
}

impl Sum {
    /// `self` (`llen` blocks) followed by `r` (`rlen` blocks); `link` = a run may continue from one into the other.
    #[inline]
    fn join(self, llen: u64, r: Sum, rlen: u64, link: bool) -> Sum {
        Sum {
            pre: if link && self.pre == llen {
                llen + r.pre
            } else {
                self.pre
            },
            suf: if link && r.suf == rlen {
                rlen + self.suf
            } else {
                r.suf
            },
            max: self
                .max
                .max(r.max)
                .max(if link { self.suf + r.pre } else { 0 }),
            dmax: self.dmax.max(r.dmax),
        }
    }
}

/// Free runs shorter than this many blocks (64 KiB) count as fragmented free space ([`Alloc::frag`], adr 0475).
const FRAG_SHORT: u64 = 16;
/// Bits per field of the packed window run summary; a run never exceeds one window ([`WIN`] blocks).
const RUNS_BITS: u32 = 9;
const RUNS_MASK: u32 = (1 << RUNS_BITS) - 1;

/// Packed window run summary -> (free blocks at its start, at its end, longest run).
#[inline]
fn unpack_runs(v: u32) -> (u64, u64, u64) {
    (
        u64::from(v & RUNS_MASK),
        u64::from(v >> RUNS_BITS & RUNS_MASK),
        u64::from(v >> (2 * RUNS_BITS) & RUNS_MASK),
    )
}

/// (free blocks at its start, at its end, longest run) -> packed window run summary.
#[inline]
fn pack_runs(pre: u64, suf: u64, max: u64) -> u32 {
    (pre | suf << RUNS_BITS | max << (2 * RUNS_BITS)) as u32
}

/// Windows one [`Alloc::frag`] call walks (adr 0475 am. 1): the gauges are built on every core once a second (stats for
/// the control core) and by `perf dump`, so one call stays near 0.1 ms whatever the shard size, also when most windows of
/// the step changed since the walk last passed them (`frag_cost` measurement); a shard of n windows refreshes every
/// n / 16384 calls (16 GiB of device per call).
const FRAG_STEP: usize = 16384;
/// Base hysteresis of a chunk-table region (adr 0021 am. 56): closed to new allocations below this free percentage ...
#[cfg(feature = "elastic")]
const BASE_CLOSE_PCT: u64 = 5;
/// ... reopened at this one.
#[cfg(feature = "elastic")]
const BASE_OPEN_PCT: u64 = 10;
/// Blocks per persisted `f` chunk (512 B of bitmap); also the lazy-allocation unit of the reserved layer.
pub const CHUNK_BLOCKS: u64 = 4096;
pub const CHUNK_BYTES: usize = 512;
/// Words per chunk.
const CW: usize = CHUNK_BYTES / 8;
/// Capacity of the pool's free list (never grows on the hot path); chunks returned beyond it are freed.
pub const POOL_CAP: usize = 2048;

fn words_for(n: u64) -> usize {
    n.div_ceil(64) as usize
}

/// Bit mask of `take` bits starting at bit `b` of a word.
fn mask_of(b: u64, take: u64) -> u64 {
    if take == 64 {
        !0
    } else {
        ((1u64 << take) - 1) << b
    }
}

/// Are all bits in `[i, i+n)` equal to `val`? (`word` = word accessor of a layer.)
fn all_bits(word: impl Fn(usize) -> u64, i: u64, n: u64, val: bool) -> bool {
    let (mut pos, end) = (i, i + n);
    while pos < end {
        let w = (pos / 64) as usize;
        let b = pos % 64;
        let take = (64 - b).min(end - pos);
        let m = mask_of(b, take);
        let x = if val { word(w) } else { !word(w) };
        if x & m != m {
            return false;
        }
        pos += take;
    }
    true
}

/// Default pool size for a region of `nchunks` chunks (`ShardCfg::alloc_pool_chunks` = 0): 1/64 of the chunks (a
/// 256 GB shard keeps ~250 chunks = 125 KiB), at least 16, at most `POOL_CAP / 2`, never more than the region has.
pub fn pool_target_for(nchunks: u64) -> usize {
    ((nchunks / 64) as usize)
        .clamp(16, POOL_CAP / 2)
        .min(nchunks.max(1) as usize)
}

/// One lazily present chunk of the reserved layer.
#[derive(Clone, Debug)]
struct Chunk {
    w: [u64; CW],
}

/// Stands in for an absent chunk on reads.
static ZERO: Chunk = Chunk { w: [0; CW] };

/// Pre-filled supply of all-zero chunks.
#[derive(Debug)]
struct Pool {
    /// Boxed on purpose: chunks move between the pool and the layer table as pointers.
    #[allow(clippy::vec_box)]
    free: Vec<Box<Chunk>>,
    target: usize,
    /// Chunks taken from the heap because the pool was empty (hot-path allocations; should stay 0).
    misses: u64,
}

impl Clone for Pool {
    /// Keeps the fixed free-list capacity (a derived clone would shrink it to the length: `put` would reallocate).
    fn clone(&self) -> Pool {
        let mut free = Vec::with_capacity(POOL_CAP);
        free.extend(self.free.iter().cloned());
        Pool {
            free,
            target: self.target,
            misses: self.misses,
        }
    }
}

impl Pool {
    fn new(target: usize) -> Pool {
        let mut p = Pool {
            free: Vec::with_capacity(POOL_CAP),
            target,
            misses: 0,
        };
        p.fill();
        p
    }
    fn fill(&mut self) {
        while self.free.len() < self.target {
            self.free.push(Box::new(Chunk { w: [0; CW] }));
        }
        // trim: keep up to 2x target (returned chunks are reused), free the rest off the hot path
        self.free.truncate(self.target * 2);
    }
    #[inline]
    fn take(&mut self) -> Box<Chunk> {
        self.free.pop().unwrap_or_else(|| {
            self.misses += 1;
            Box::new(Chunk { w: [0; CW] })
        })
    }
    /// Give back an all-zero chunk (no allocation: the list has capacity POOL_CAP).
    #[inline]
    fn put(&mut self, c: Box<Chunk>) {
        debug_assert!(c.w.iter().all(|&w| w == 0));
        if self.free.len() < POOL_CAP {
            self.free.push(c);
        }
    }
}

/// A sparse bit layer: `tab[ci]` = chunk `ci` or None (all zero).
#[derive(Clone, Debug)]
struct Layer {
    tab: Vec<Option<Box<Chunk>>>,
    /// Set bits per chunk (beside the table, not in the chunk: one hot array, no second cache line per chunk).
    pop: Vec<u16>,
    /// Present chunks.
    live: u64,
}

impl Layer {
    fn new(nchunks: usize) -> Layer {
        Layer {
            tab: vec![None; nchunks],
            pop: vec![0; nchunks],
            live: 0,
        }
    }
    #[inline]
    fn word(&self, w: usize) -> u64 {
        self.tab[w / CW].as_deref().unwrap_or(&ZERO).w[w % CW]
    }
    /// Store word `k` of chunk `ci` (was `o`, becomes `x != o`); the chunk enters the layer as it becomes non-empty and
    /// leaves it (back to the pool) when empty. Returns the bit count change.
    #[inline(always)]
    fn put(&mut self, ci: usize, k: usize, o: u64, x: u64, pool: &mut Pool) -> i64 {
        let dp = x.count_ones() as i64 - o.count_ones() as i64;
        let slot = &mut self.tab[ci];
        let pop = &mut self.pop[ci];
        *pop = pop.wrapping_add_signed(dp as i16);
        match slot.as_mut() {
            Some(c) => {
                c.w[k] = x;
                if *pop == 0 {
                    pool.put(slot.take().unwrap());
                    self.live -= 1;
                }
            }
            None => {
                let mut c = pool.take();
                c.w[k] = x;
                *slot = Some(c);
                self.live += 1;
            }
        }
        dp
    }
}

const L_ALLOC: usize = 0;
const L_RESERVED: usize = 1;
const L_HELD: usize = 2;

/// One contiguous device extent of the data region: relative bit index `rel..rel+len` = engine blocks `phys..phys+len`.
#[derive(Clone, Copy, Debug)]
struct Seg {
    rel: u64,
    phys: u64,
    len: u64,
}

#[derive(Clone, Debug)]
pub struct Alloc {
    /// The data region: the original extent first, then the extents added by a device expand (adr 0021 am. 20), in
    /// bit order. A run never crosses a segment boundary (the extents are not adjacent on the device).
    segs: Vec<Seg>,
    n: u64,
    /// Dense layers, interleaved per word: `[alloc, held]` (one cache line for both: a free moves bits between them,
    /// the scan reads both).
    d: Vec<[u64; 2]>,
    /// Reserved layer, sparse.
    res: Layer,
    pool: Pool,
    win_busy: Vec<u16>,
    /// Free runs per window (adr 0475): `pre | suf << RUNS_BITS | max << 2 * RUNS_BITS` (free blocks at its start, at
    /// its end, longest run; union of the layers, split at an extent start inside the window), or `RUNS_DIRTY`. A change
    /// of the union only marks the window (and its tree path); a read recomputes.
    wruns: Vec<std::cell::Cell<u32>>,
    /// Run-summary tree over the windows (adr 0475 am. 2): `tree[k - 1][i]` sums windows `[i * FAN^k, (i + 1) * FAN^k)`,
    /// the last level is one root; `DIRTY` = recomputed from its children on read. A dirty node has dirty ancestors.
    tree: Vec<Vec<std::cell::Cell<Sum>>>,
    /// The fragmentation walk in progress and the last complete one ([`Alloc::frag`]).
    fwalk: std::cell::Cell<FragWalk>,
    cursor: u64,
    /// Set bits per layer: alloc, reserved, held.
    cnt: [u64; 3],
    n_busy: u64,
    /// Word holding the padding bits (`usize::MAX` = none) and those bits (beyond `n`, permanently busy).
    pad_w: usize,
    pad: u64,
    /// Window of the last `reserve_dense` hit (defrag destinations, adr 0021 am. 33).
    dense_cur: usize,
    /// Chunk table (adr 0021 am. 47): log2 blocks of the uniform chunk (0 = plain extents) and chunks sorted by engine block (`(phys, seg index)`).
    #[cfg(feature = "elastic")]
    ck_shift: u32,
    #[cfg(feature = "elastic")]
    by_phys: Vec<(u64, u32)>,
    /// Windows with no busy block (`free_windows`), kept with `win_busy`.
    free_wins: u64,
    /// Lent chunks (adr 0021 am. 49): the base is `[0, base_n)`, borrowed chunks follow in slot order (slot `k` = chunk
    /// `base_n / chunk + k`); `base_n == n` = nothing borrowed. A returned slot is a hole (`Seg::phys == HOLE`, its windows
    /// full in `win_busy`, counted in `n_busy`; never scanned). Allocation (am. 56): next-fit in the base while it
    /// has room (hysteresis `base_open`), else next-fit from `bfirst` in the borrowed space.
    #[cfg(feature = "elastic")]
    base_n: u64,
    #[cfg(feature = "elastic")]
    bfirst: u64,
    /// Next-fit cursor of the base (borrowed allocations do not move it).
    #[cfg(feature = "elastic")]
    base_cur: u64,
    #[cfg(feature = "elastic")]
    holes: u64,
    /// Base hysteresis (adr 0021 am. 56): busy blocks of the base windows (`base_wins`, 0 = no chunk table); whether new
    /// allocations try the base first; the base's free blocks when it was closed.
    #[cfg(feature = "elastic")]
    base_busy: u64,
    #[cfg(feature = "elastic")]
    base_wins: usize,
    #[cfg(feature = "elastic")]
    base_open: bool,
    #[cfg(feature = "elastic")]
    base_closed_free: u64,
}

/// Engine block of a returned borrowed chunk slot (adr 0021 am. 49).
#[cfg(feature = "elastic")]
pub const HOLE: u64 = u64::MAX;

/// Running sums of a fragmentation walk in window order: `[blocks in whole free windows, free blocks in windows without a
/// FRAG_SHORT run, longest free run]` and the free run open at the walk position.
#[derive(Clone, Copy, Debug, Default)]
struct FragSums {
    f: [u64; 3],
    run: u64,
}

/// [`Alloc::frag`] state: the next window of the walk in progress, its sums, the result of the last complete walk.
#[derive(Clone, Copy, Debug, Default)]
struct FragWalk {
    next: usize,
    sums: FragSums,
    last: Option<[u64; 3]>,
}

impl Alloc {
    pub fn new(start: u64, n: u64) -> Alloc {
        Alloc::with_extents(start, n, &[])
    }

    /// The region `start..start+n` plus further extents `(start, blocks)` (device expand).
    pub fn with_extents(start: u64, n0: u64, extra: &[(u64, u64)]) -> Alloc {
        let mut segs = vec![Seg {
            rel: 0,
            phys: start,
            len: n0,
        }];
        let mut n = n0;
        for &(phys, len) in extra {
            segs.push(Seg { rel: n, phys, len });
            n += len;
        }
        let nw = words_for(n);
        let nc = n.div_ceil(CHUNK_BLOCKS);
        let mut a = Alloc {
            segs,
            n,
            d: vec![[0; 2]; nw],
            res: Layer::new(nc as usize),
            pool: Pool::new(pool_target_for(nc)),
            win_busy: vec![0; n.div_ceil(WIN) as usize],
            wruns: vec![std::cell::Cell::new(RUNS_DIRTY); n.div_ceil(WIN) as usize],
            tree: Vec::new(),
            fwalk: std::cell::Cell::new(FragWalk::default()),
            cursor: 0,
            cnt: [0; 3],
            n_busy: 0,
            pad_w: usize::MAX,
            pad: 0,
            dense_cur: 0,
            #[cfg(feature = "elastic")]
            ck_shift: 0,
            #[cfg(feature = "elastic")]
            by_phys: Vec::new(),
            free_wins: n.div_ceil(WIN),
            #[cfg(feature = "elastic")]
            base_n: n,
            #[cfg(feature = "elastic")]
            bfirst: n,
            #[cfg(feature = "elastic")]
            base_cur: 0,
            #[cfg(feature = "elastic")]
            holes: 0,
            #[cfg(feature = "elastic")]
            base_busy: 0,
            #[cfg(feature = "elastic")]
            base_wins: 0,
            #[cfg(feature = "elastic")]
            base_open: true,
            #[cfg(feature = "elastic")]
            base_closed_free: 0,
        };
        a.tree_grow();
        // padding bits of the last word are permanently busy
        if !n.is_multiple_of(64) {
            a.pad_w = nw - 1;
            a.pad = !0u64 << (n % 64);
            a.win_add((nw - 1) / 4, a.pad.count_ones() as i32);
        }
        a
    }

    /// A region of `chunks` uniform chunks of `chunk` blocks (power of two), chunk `i` at engine block `phys[i]`; chunks need not be adjacent.
    /// Translation is O(1) (rel -> phys: table index) or O(log chunks) (phys -> rel), runs never cross a chunk.
    #[cfg(all(test, feature = "elastic"))]
    pub fn with_chunks(phys: &[u64], chunk: u64) -> Alloc {
        Alloc::with_lent(phys, &[], chunk)
    }

    /// A region of the uniform chunks `base` (engine block of each, need not be adjacent) plus borrowed chunks (adr 0021
    /// am. 49): `lent[k]` = engine block of slot `k` or `HOLE`.
    #[cfg(feature = "elastic")]
    pub fn with_lent(base: &[u64], lent: &[u64], chunk: u64) -> Alloc {
        assert!(chunk.is_power_of_two() && chunk >= WIN && !base.is_empty());
        let all: Vec<u64> = base.iter().chain(lent).copied().collect();
        // holes get a placeholder address here (never translated: not in `by_phys`, never scanned)
        let ext: Vec<(u64, u64)> = all[1..].iter().map(|&p| (p, chunk)).collect();
        let mut a = Alloc::with_extents(all[0], chunk, &ext);
        a.ck_shift = chunk.trailing_zeros();
        a.base_n = base.len() as u64 * chunk;
        a.bfirst = a.base_n;
        a.base_wins = (a.base_n / WIN) as usize;
        let mut bp: Vec<(u64, u32)> = all
            .iter()
            .enumerate()
            .filter(|e| *e.1 != HOLE)
            .map(|(i, &p)| (p, i as u32))
            .collect();
        bp.sort_unstable();
        a.by_phys = bp;
        for (k, &p) in lent.iter().enumerate() {
            if p == HOLE {
                a.hole_mark(base.len() + k, true);
            }
        }
        a
    }

    /// Make chunk `i` a hole (`on`) or usable again: its windows read full / empty in the summary, the free count follows.
    /// The chunk's layer bits are all zero either way (callers check).
    #[cfg(feature = "elastic")]
    fn hole_mark(&mut self, i: usize, on: bool) {
        let c = 1u64 << self.ck_shift;
        let (w0, nw) = ((i as u64 * c / WIN) as usize, (c / WIN) as usize);
        for w in w0..w0 + nw {
            // through win_add: keeps `free_wins` exact
            let d = if on {
                WIN as i32 - self.win_busy[w] as i32
            } else {
                -(self.win_busy[w] as i32)
            };
            self.win_add(w, d);
        }
        if on {
            self.n_busy += c;
            self.holes += 1;
            self.segs[i].phys = HOLE;
        } else {
            self.n_busy -= c;
            self.holes -= 1;
        }
    }

    /// Blocks of the region that can hold data (holes of returned chunks excluded).
    #[cfg(feature = "elastic")]
    pub fn usable_len(&self) -> u64 {
        self.n - (self.holes << self.ck_shift)
    }
    #[cfg(not(feature = "elastic"))]
    pub fn usable_len(&self) -> u64 {
        self.n
    }

    /// Base chunks / borrowed slots (holes included) of a chunk-table region (adr 0021 am. 49).
    #[cfg(feature = "elastic")]
    pub fn base_blocks(&self) -> u64 {
        self.base_n
    }
    #[cfg(feature = "elastic")]
    pub fn lent_slots(&self) -> usize {
        if self.ck_shift == 0 {
            0
        } else {
            ((self.n - self.base_n) >> self.ck_shift) as usize
        }
    }

    /// Borrowed slot `k`: `(engine block or HOLE, busy blocks)` (allocated, reserved, held).
    #[cfg(feature = "elastic")]
    pub fn lent_slot(&self, k: usize) -> (u64, u64) {
        let i = (self.base_n >> self.ck_shift) as usize + k;
        let s = self.segs[i];
        if s.phys == HOLE {
            return (HOLE, 0);
        }
        let (w0, nw) = ((s.rel / WIN) as usize, (s.len / WIN) as usize);
        (
            s.phys,
            self.win_busy[w0..w0 + nw].iter().map(|&b| b as u64).sum(),
        )
    }

    /// A chunk granted durably (adr 0021 am. 49) becomes borrowed slot `k`: a hole is filled, or `k` = the next slot
    /// (the region grows by one chunk). Off the hot path (vectors grow).
    #[cfg(feature = "elastic")]
    pub fn lend_add(&mut self, k: usize, phys: u64) {
        let c = 1u64 << self.ck_shift;
        let i = (self.base_n >> self.ck_shift) as usize + k;
        assert!(self.ck_shift != 0 && phys != HOLE);
        assert!(
            self.rel(phys, c).is_none(),
            "chunk {phys} already in the region"
        );
        if i == self.segs.len() {
            self.segs.push(Seg {
                rel: self.n,
                phys,
                len: c,
            });
            self.n += c;
            self.d.resize(words_for(self.n), [0; 2]);
            let nc = self.n.div_ceil(CHUNK_BLOCKS) as usize;
            self.res.tab.resize(nc, None);
            self.res.pop.resize(nc, 0);
            let nw = self.n.div_ceil(WIN) as usize;
            self.free_wins += (nw - self.win_busy.len()) as u64;
            self.win_busy.resize(nw, 0);
            self.wruns.resize(nw, std::cell::Cell::new(RUNS_DIRTY));
            self.tree_grow();
        } else {
            assert_eq!(self.segs[i].phys, HOLE, "slot {k} is in use");
            self.segs[i].phys = phys;
            self.hole_mark(i, false);
        }
        let pos = self.by_phys.partition_point(|e| e.0 < phys);
        self.by_phys.insert(pos, (phys, i as u32));
        self.bfirst = self.segs[i].rel;
    }

    /// Return borrowed slot `k` (adr 0021 am. 49): only when no block of it is allocated, reserved or held (= no record
    /// after the newest durable checkpoint touches it and that checkpoint's bitmap is zero there). The slot becomes a
    /// hole. False (nothing changed) when the chunk is in use.
    #[cfg(feature = "elastic")]
    pub fn lend_remove(&mut self, k: usize) -> bool {
        let i = (self.base_n >> self.ck_shift) as usize + k;
        let s = self.segs[i];
        assert!(s.phys != HOLE, "slot {k} is a hole");
        let (w0, w1) = ((s.rel / 64) as usize, ((s.rel + s.len) / 64) as usize);
        if (w0..w1).any(|w| self.busy_word(w) != 0) {
            return false;
        }
        let pos = self.by_phys.partition_point(|e| e.0 < s.phys);
        self.by_phys.remove(pos);
        self.hole_mark(i, true);
        true
    }

    /// No bit of any layer is set inside a hole (mount / fsck after loading the persisted bitmap).
    #[cfg(feature = "elastic")]
    pub fn holes_clear(&self) -> bool {
        self.segs.iter().filter(|s| s.phys == HOLE).all(|s| {
            let (w0, w1) = ((s.rel / 64) as usize, ((s.rel + s.len) / 64) as usize);
            (w0..w1).all(|w| self.d[w] == [0, 0] && self.res.word(w) == 0)
        })
    }

    /// `find` with borrowed chunks (adr 0021 am. 56). The base first while it has room, borrowed space (next-fit, new
    /// writes append in the newest chunk) when it has none. The base closes below `BASE_CLOSE_PCT` % free or when a scan
    /// finds no run, and reopens at `BASE_OPEN_PCT` % free once it gained `base_n / 50` blocks since: a nearly full base
    /// only has scattered short runs (every long write would be cut into pieces, every miss rescans it), a fresh borrowed
    /// chunk is one long free run. A closed base is still the last resort (never ENOSPC while it has a run).
    #[cfg(feature = "elastic")]
    fn find_lent(&mut self, want: u64) -> Option<u64> {
        let b = self.base_n;
        let free = b - self.base_busy.min(b);
        if self.base_open {
            if free * 100 < b * BASE_CLOSE_PCT {
                self.base_open = false;
                self.base_closed_free = free;
            }
        } else if free * 100 >= b * BASE_OPEN_PCT && free >= self.base_closed_free + b / 50 {
            self.base_open = true;
        }
        if self.base_open {
            self.find_base(want).or_else(|| {
                self.may_fit(want)
                    .then(|| self.find_borrowed(want))
                    .flatten()
            })
        } else {
            self.find_borrowed(want)
                .or_else(|| self.may_fit(want).then(|| self.find_base(want)).flatten())
        }
    }

    /// Base part of `find_lent`: next-fit from `base_cur`, wrapping once. A miss closes the base (see `find_lent`).
    #[cfg(feature = "elastic")]
    fn find_base(&mut self, want: u64) -> Option<u64> {
        let b = self.base_n;
        let from = self.base_cur.min(b);
        let r = self.scan(from, b, want).or_else(|| {
            self.may_fit(want)
                .then(|| self.scan(0, (from + want - 1).min(b), want))
                .flatten()
        });
        match r {
            Some(r) => self.base_cur = r + want,
            None if self.base_open => {
                self.base_open = false;
                self.base_closed_free = b - self.base_busy.min(b);
            }
            None => {}
        }
        r
    }

    /// Borrowed part of `find_lent`: next-fit from the cursor (the newest chunk), wrapping once over the borrowed slots.
    #[cfg(feature = "elastic")]
    fn find_borrowed(&mut self, want: u64) -> Option<u64> {
        let (b, n) = (self.base_n, self.n);
        let from = self.bfirst.clamp(b, n);
        let r = self.scan(from, n, want).or_else(|| {
            self.may_fit(want)
                .then(|| self.scan(b, (from + want - 1).min(n), want))
                .flatten()
        });
        if let Some(r) = r {
            self.bfirst = r + want;
        }
        r
    }

    /// First block of the original extent.
    pub fn start(&self) -> u64 {
        self.segs[0].phys
    }
    /// RAM of the bitmaps: the dense layers, table + popcounts + present chunks of the reserved layer, the chunk pool,
    /// busy windows.
    pub fn mem_bytes(&self) -> u64 {
        let csz = std::mem::size_of::<Chunk>();
        (self.d.capacity() * 16
            + self.res.tab.capacity() * 8
            + self.res.pop.capacity() * 2
            + (self.res.live as usize + self.pool.free.len()) * csz
            + self.pool.free.capacity() * 8
            + self.win_busy.capacity() * 2
            + self.wruns.capacity() * 4
            + self
                .tree
                .iter()
                .map(|l| l.capacity() * std::mem::size_of::<Sum>())
                .sum::<usize>()) as u64
    }
    /// Top up (and trim) the chunk pool; call off the hot path (shard poll). Cheap when nothing changed.
    pub fn maintain(&mut self) {
        let (l, t) = (self.pool.free.len(), self.pool.target);
        if l < t || l > 2 * t {
            self.pool.fill();
        }
    }
    /// Chunks the pool is kept at (0 = no pre-fill: every first set of a chunk allocates); at most `POOL_CAP / 2`.
    pub fn set_pool_target(&mut self, chunks: usize) {
        self.pool.target = chunks.min(POOL_CAP / 2);
        self.pool.fill();
    }
    /// Chunks in the pool now.
    pub fn pool_len(&self) -> usize {
        self.pool.free.len()
    }
    /// Chunks taken from the heap on a set because the pool was empty (since the last `clear_pool_misses`).
    pub fn pool_misses(&self) -> u64 {
        self.pool.misses
    }
    /// Start counting misses afresh (end of mount: loading and replay are not the hot path).
    pub fn clear_pool_misses(&mut self) {
        self.pool.misses = 0;
    }
    /// Present chunks of the reserved layer.
    pub fn live_chunks(&self) -> u64 {
        self.res.live
    }

    pub fn len(&self) -> u64 {
        self.n
    }
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
    pub fn n_alloc(&self) -> u64 {
        self.cnt[L_ALLOC]
    }
    pub fn n_reserved(&self) -> u64 {
        self.cnt[L_RESERVED]
    }
    pub fn n_held(&self) -> u64 {
        self.cnt[L_HELD]
    }
    /// Blocks allocatable right now.
    pub fn n_free(&self) -> u64 {
        self.n - self.n_busy
    }

    /// Relative block index; None if the range is outside the region (or spans two extents).
    fn rel(&self, blk: u64, n: u64) -> Option<u64> {
        if n == 0 {
            return None;
        }
        #[cfg(feature = "elastic")]
        if self.ck_shift != 0 {
            let i = self.by_phys.partition_point(|e| e.0 <= blk);
            let s = &self.segs[self.by_phys.get(i.checked_sub(1)?)?.1 as usize];
            let r = blk - s.phys;
            return r
                .checked_add(n)
                .filter(|&end| end <= s.len)
                .map(|_| s.rel + r);
        }
        self.segs.iter().find_map(|s| {
            let r = blk.checked_sub(s.phys)?;
            r.checked_add(n)
                .filter(|&end| end <= s.len)
                .map(|_| s.rel + r)
        })
    }

    /// Relative index of a block known to be inside the region (callers validated with `in_region`).
    pub fn rel_of(&self, blk: u64) -> u64 {
        self.rel(blk, 1).expect("block inside the data region")
    }

    /// Engine block address of relative index `r`.
    pub fn phys_of(&self, r: u64) -> u64 {
        #[cfg(feature = "elastic")]
        if self.ck_shift != 0 {
            let s = &self.segs[(r >> self.ck_shift) as usize];
            return s.phys + (r - s.rel);
        }
        let s = self
            .segs
            .iter()
            .find(|s| r < s.rel + s.len)
            .expect("index inside the region");
        s.phys + (r - s.rel)
    }

    /// End (exclusive) of the extent holding relative index `r`.
    fn seg_end(&self, r: u64) -> u64 {
        #[cfg(feature = "elastic")]
        if self.ck_shift != 0 {
            return (((r >> self.ck_shift) + 1) << self.ck_shift).min(self.n);
        }
        self.segs
            .iter()
            .find(|s| r < s.rel + s.len)
            .map_or(self.n, |s| s.rel + s.len)
    }

    /// The permanently busy padding bits of word `w` (the last word of a region that is no multiple of 64).
    #[inline]
    fn pad(&self, w: usize) -> u64 {
        if w == self.pad_w { self.pad } else { 0 }
    }

    /// Union of the layers for word `w` (+ padding).
    #[inline]
    fn busy_word(&self, w: usize) -> u64 {
        self.d[w][0] | self.res.word(w) | self.d[w][1] | self.pad(w)
    }

    #[inline(always)]
    fn layer_word(&self, j: usize, w: usize) -> u64 {
        match j {
            L_ALLOC => self.d[w][0],
            L_RESERVED => self.res.word(w),
            _ => self.d[w][1],
        }
    }

    /// Store word `w` of layer `j` (was `o`, becomes `x != o`) and its counter; not the busy summary.
    #[inline(always)]
    fn layer_store(&mut self, j: usize, w: usize, o: u64, x: u64) {
        let dp = match j {
            L_RESERVED => self.res.put(w / CW, w % CW, o, x, &mut self.pool),
            _ => {
                self.d[w][j >> 1] = x;
                x.count_ones() as i64 - o.count_ones() as i64
            }
        };
        self.cnt[j] = self.cnt[j].wrapping_add_signed(dp);
    }

    /// Rewrite word `w` of the layers (alloc, reserved, held) through `f`, keeping the counters and the busy summary
    /// exact.
    #[inline(always)]
    fn update_word(&mut self, w: usize, f: impl Fn(&mut [u64; 3])) {
        let old = [self.d[w][0], self.res.word(w), self.d[w][1]];
        let mut new = old;
        f(&mut new);
        for j in 0..3 {
            if new[j] != old[j] {
                self.layer_store(j, w, old[j], new[j]);
            }
        }
        let pad = self.pad(w);
        let (nu, ou) = (
            new[0] | new[1] | new[2] | pad,
            old[0] | old[1] | old[2] | pad,
        );
        if nu != ou {
            let d = nu.count_ones() as i32 - ou.count_ones() as i32;
            self.win_add(w / 4, d);
            self.n_busy = (self.n_busy as i64 + d as i64) as u64;
        }
    }

    /// Move bits `[i, i+n)` from layer `from` to layer `to` (apply_alloc, apply_free). Where every moved bit is set in
    /// `from` (the normal case) the union cannot change: the third layer is not read. Otherwise the exact path.
    #[inline(always)]
    fn mv(&mut self, i: u64, n: u64, from: usize, to: usize) {
        let (mut pos, end) = (i, i + n);
        while pos < end {
            let w = (pos / 64) as usize;
            let b = pos % 64;
            let take = (64 - b).min(end - pos);
            let m = mask_of(b, take);
            let fx = self.layer_word(from, w);
            if fx & m == m {
                let ty = self.layer_word(to, w);
                self.layer_store(from, w, fx, fx & !m);
                if ty | m != ty {
                    self.layer_store(to, w, ty, ty | m);
                }
            } else {
                self.update_word(w, |x| {
                    x[from] &= !m;
                    x[to] |= m;
                });
            }
            pos += take;
        }
    }

    /// Set or clear bits `[i, i+n)` of layer `which`.
    #[inline(always)]
    fn set(&mut self, which: usize, i: u64, n: u64, val: bool) {
        let (mut pos, end) = (i, i + n);
        while pos < end {
            let w = (pos / 64) as usize;
            let b = pos % 64;
            let take = (64 - b).min(end - pos);
            let m = mask_of(b, take);
            self.update_word(w, |x| {
                x[which] = if val { x[which] | m } else { x[which] & !m }
            });
            pos += take;
        }
    }

    // ---------------------------------------------------------------- queries

    /// True when every bit of `[blk, blk + n)` is `val` in layer `j` (false outside the region).
    #[inline(always)]
    fn layer_all(&self, j: usize, blk: u64, n: u32, val: bool) -> bool {
        self.rel(blk, n as u64)
            .is_some_and(|r| all_bits(|w| self.layer_word(j, w), r, n as u64, val))
    }

    pub fn is_allocated(&self, blk: u64, n: u32) -> bool {
        self.layer_all(L_ALLOC, blk, n, true)
    }
    pub fn is_unallocated(&self, blk: u64, n: u32) -> bool {
        self.layer_all(L_ALLOC, blk, n, false)
    }
    pub fn is_reserved(&self, blk: u64, n: u32) -> bool {
        self.layer_all(L_RESERVED, blk, n, true)
    }
    /// Every block of the range is allocated or reserved (offline repair: a fenced false free counts as owned).
    pub fn is_fenced_or_allocated(&self, blk: u64, n: u32) -> bool {
        (0..u64::from(n)).all(|i| self.is_allocated(blk + i, 1) || self.is_reserved(blk + i, 1))
    }
    #[cfg(test)]
    pub fn is_held(&self, blk: u64, n: u32) -> bool {
        self.rel(blk, n as u64)
            .is_some_and(|r| !all_bits(|w| self.layer_word(L_HELD, w), r, n as u64, false))
    }
    pub fn in_region(&self, blk: u64, n: u32) -> bool {
        self.rel(blk, n as u64).is_some()
    }
    /// Durable-state bitmap as a plain `Bitmap` (tests, fsck).
    pub fn snapshot(&self) -> Bitmap {
        Bitmap::from_words(self.d.iter().map(|w| w[0]).collect(), self.n)
    }

    /// Every maximal run of allocatable blocks as `(engine block, blocks)`, ascending within each extent (free-space
    /// report; reserved and held blocks count as in use). Runs never span two extents.
    pub fn for_each_free(&self, f: impl FnMut(u64, u64)) {
        self.free_runs(0, self.n, f);
    }

    /// Free runs starting in the relative window `[from, from + blocks)`, clipped to it, ascending (bounded free-space
    /// walk for gauges: the caller advances a cursor instead of scanning the whole region per poll).
    pub fn for_each_free_in(&self, from: u64, blocks: u64, f: impl FnMut(u64, u64)) {
        self.free_runs(from, (from + blocks).min(self.n), f);
    }

    fn free_runs(&self, from: u64, to: u64, mut f: impl FnMut(u64, u64)) {
        for s in &self.segs {
            #[cfg(feature = "elastic")]
            if s.phys == HOLE {
                continue;
            }
            let (mut pos, end) = (s.rel.max(from), (s.rel + s.len).min(to));
            let mut cur: Option<u64> = None;
            while pos < end {
                let (w, bit) = ((pos / 64) as usize, pos % 64);
                let avail = (64 - bit).min(end - pos);
                let mask = if avail == 64 { !0 } else { (1u64 << avail) - 1 };
                let free = (!self.busy_word(w) >> bit) & mask;
                if free == mask {
                    cur.get_or_insert(pos);
                } else if free == 0 {
                    if let Some(c) = cur.take() {
                        f(self.phys_of(c), pos - c);
                    }
                } else {
                    for i in 0..avail {
                        if free >> i & 1 == 1 {
                            cur.get_or_insert(pos + i);
                        } else if let Some(c) = cur.take() {
                            f(self.phys_of(c), pos + i - c);
                        }
                    }
                }
                pos += avail;
            }
            if let Some(c) = cur {
                f(self.phys_of(c), end - c);
            }
        }
    }

    // ---------------------------------------------------------------- reservation

    /// Find `want` contiguous allocatable blocks (next-fit from the cursor, wrapping once: the two scans cover every run
    /// of the region). Relative index.
    fn find(&mut self, want: u64) -> Option<u64> {
        if want == 0 || want > self.n - self.n_busy {
            return None;
        }
        #[cfg(feature = "elastic")]
        if self.base_n < self.n {
            return self.find_lent(want);
        }
        let from = self.cursor.min(self.n);
        self.scan(from, self.n, want).or_else(|| {
            self.may_fit(want)
                .then(|| self.scan(0, (from + want - 1).min(self.n), want))
                .flatten()
        })
    }

    /// A run of `want` exists somewhere (the tree root's longest run): a next-fit search that missed from its cursor asks
    /// once before it scans further, so a miss costs one scan and a root read, not every scan of the region.
    #[inline]
    fn may_fit(&self, want: u64) -> bool {
        want <= self.longest_run()
    }

    /// First run of `want` allocatable blocks inside `[from, to)` (lowest start; a run never crosses an extent start, a
    /// hole is busy). The window holding `from` is scanned by words first (the next-fit hit near the cursor reads no
    /// summary), the rest by a tree walk from the root (adr 0475 am. 2): a node inside the range in which no run of
    /// `want` can end is passed in O(1), so a request costs O(FAN * tree height) node reads plus one window of words,
    /// whatever the distance to the fit; same result as a word scan from `from`.
    fn scan(&self, from: u64, to: u64, want: u64) -> Option<u64> {
        if from >= to {
            return None;
        }
        let wi = (from / WIN) as usize;
        let e = ((wi as u64 + 1) * WIN).min(to);
        let mut st = (0, from);
        if (self.win_busy[wi] as u64) < WIN
            && let Some(r) = self.scan_win(wi, from, e, want, &mut st)
        {
            return Some(r);
        }
        if e == to {
            return None;
        }
        self.seek(self.tree.len(), 0, e, to, want, &mut st)
    }

    /// `scan` below node `i` of level `k` (level 0 = windows). `st` = the free run ending at the walk position and its
    /// start. Inner nodes are tested only when inside the range (a node the walk merely crosses is not recomputed: the
    /// next-fit hit near the cursor reads one path); a window is always tested (its summary bounds the clipped part too).
    fn seek(
        &self,
        k: usize,
        i: usize,
        from: u64,
        to: u64,
        want: u64,
        st: &mut (u64, u64),
    ) -> Option<u64> {
        let span = WIN << (LOG_FAN * k as u32);
        let (lo, hi) = (i as u64 * span, (i as u64 + 1) * span);
        if lo >= from && self.brk(lo) {
            st.0 = 0;
        }
        if k == 0 || (lo >= from && hi <= to) {
            let s = self.sum(k, i);
            if st.0 + s.pre < want && s.max < want {
                // no run of `want` ends here: carry the run that reaches the node's end
                if s.pre == span && lo >= from {
                    if st.0 == 0 {
                        st.1 = lo;
                    }
                    st.0 += span;
                } else {
                    st.0 = s.suf.min(hi - lo.max(from));
                    st.1 = hi - st.0;
                }
                return None;
            }
        }
        if k == 0 {
            return self.scan_win(i, lo.max(from), hi.min(to), want, st);
        }
        let cs = span >> LOG_FAN;
        let (j0, j1) = (lo.max(from) / cs, (hi.min(to) - 1) / cs);
        (j0..=j1).find_map(|j| self.seek(k - 1, j as usize, from, to, want, st))
    }

    /// Word scan of `[a, e)` inside window `wi`, continuing the run in `st`: the reserved chunk is looked up once (a
    /// window lies in one), a chunk without reserved bits (the common case) reads the dense words alone. Padding bits
    /// need no mask: `e <= n`.
    fn scan_win(&self, wi: usize, a: u64, e: u64, want: u64, st: &mut (u64, u64)) -> Option<u64> {
        let res = self.res.tab[wi * WIN as usize / CHUNK_BLOCKS as usize].as_deref();
        let mut p = a;
        while p < e {
            let q = self.cut_after(p, e);
            let found = match res {
                None => self.scan_words(st, p, q, want, |w| self.d[w][0] | self.d[w][1]),
                Some(r) => self.scan_words(st, p, q, want, |w| {
                    self.d[w][0] | self.d[w][1] | r.w[w % CW]
                }),
            };
            if found {
                return Some(st.1);
            }
            if q < e {
                st.0 = 0;
            }
            p = q;
        }
        None
    }

    /// Next-fit word scan of `[pos, end)` with busy words from `word`; true = a run of `want` starts at `st.1`.
    #[inline(always)]
    fn scan_words(
        &self,
        st: &mut (u64, u64),
        mut pos: u64,
        end: u64,
        want: u64,
        word: impl Fn(usize) -> u64,
    ) -> bool {
        let (mut run, mut run_start) = *st;
        let mut found = false;
        while pos < end {
            let bit = pos % 64;
            let avail = (64 - bit).min(end - pos);
            let x = word((pos / 64) as usize) >> bit;
            let z = (x.trailing_zeros() as u64).min(avail);
            if z > 0 {
                if run == 0 {
                    run_start = pos;
                }
                run += z;
                if run >= want {
                    found = true;
                    break;
                }
            }
            if z >= avail {
                pos += avail;
                continue;
            }
            // a busy bit at pos+z: skip the whole busy run inside this word
            run = 0;
            let ones = (!(x >> z)).trailing_zeros() as u64;
            pos += z + ones.min(avail - z);
        }
        *st = (run, run_start);
        found
    }

    /// An extent (chunk) starts at relative block `p`: a run cannot continue from `p - 1` into `p`.
    #[inline]
    fn brk(&self, p: u64) -> bool {
        #[cfg(feature = "elastic")]
        if self.ck_shift != 0 {
            return p & ((1u64 << self.ck_shift) - 1) == 0;
        }
        self.segs[1..].iter().any(|s| s.rel == p)
    }

    /// First extent start inside `(p, e)`, else `e`. A chunk is a whole number of windows, so only plain extents
    /// (device expand) can start inside a window.
    #[inline]
    fn cut_after(&self, p: u64, e: u64) -> u64 {
        #[cfg(feature = "elastic")]
        if self.ck_shift != 0 {
            return e;
        }
        self.segs[1..]
            .iter()
            .map(|s| s.rel)
            .filter(|&r| p < r && r < e)
            .min()
            .unwrap_or(e)
    }

    /// Reserve `n` contiguous blocks; returns the engine block address.
    pub fn reserve(&mut self, n: u32) -> Option<u64> {
        let r = self.find(n as u64)?;
        self.take_free(r, n as u64);
        self.cursor = (r + n as u64) % self.n;
        Some(self.phys_of(r))
    }

    /// Offline repair: reserve a census-proven free physical range for an ordinary allocation txn.
    /// Changes only the volatile reservation layer; the txn publishes the allocated bits.
    pub fn reserve_named(&mut self, blk: u64, n: u32) -> bool {
        let Some(r) = self.rel(blk, u64::from(n)) else {
            return false;
        };
        if n == 0 || !(r..r + u64::from(n)).all(|i| self.is_free_rel(i)) {
            return false;
        }
        self.take_free(r, u64::from(n));
        true
    }

    /// A data run that may come out shorter than asked (adr 0475 am. 3): `want` blocks next-fit, else the longest free run
    /// of the region, whole (the tree root names its length, one more walk places it). A shorter run is never a fraction of
    /// a longer one: that would leave the rest of the run to another object and cost one failed walk per fraction.
    /// `(engine block, blocks)`, `blocks < want` = cut; None = no free block.
    pub fn reserve_cut(&mut self, want: u32) -> Option<(u64, u32)> {
        if let Some(b) = self.reserve(want) {
            return Some((b, want));
        }
        let m = self.longest_run().min(want as u64) as u32;
        if m == 0 {
            return None;
        }
        let b = self
            .reserve(m)
            .expect("the root names a free run of this length");
        Some((b, m))
    }

    /// Longest run of allocatable blocks (run-summary tree root, adr 0475 am. 2: runs end at extent starts, holes are busy).
    /// Recomputes the nodes changed since their last read.
    pub fn longest_run(&self) -> u64 {
        self.sum(self.tree.len(), 0).max
    }

    /// Reserve a run of `min..=max` blocks (the longest free run at the first fit, up to `max`).
    pub fn reserve_upto(&mut self, min: u32, max: u32) -> Option<(u64, u32)> {
        let r = self.find(min as u64)?;
        let lo = r + min as u64;
        let lim = self.seg_end(r).min(r + max as u64).max(lo);
        let len = self.free_upto(lo, lim) - r;
        self.take_free(r, len);
        self.cursor = (r + len) % self.n;
        Some((self.phys_of(r), len as u32))
    }

    /// Mark the free run `[i, i+n)` (just found by `find`) reserved: every bit becomes busy, so only the reserved word
    /// is read.
    #[inline(always)]
    fn take_free(&mut self, i: u64, n: u64) {
        let (mut pos, end) = (i, i + n);
        while pos < end {
            let w = (pos / 64) as usize;
            let b = pos % 64;
            let take = (64 - b).min(end - pos);
            let m = mask_of(b, take);
            debug_assert_eq!(self.busy_word(w) & m, 0);
            let o = self.res.word(w);
            self.layer_store(L_RESERVED, w, o, o | m);
            self.win_add(w / 4, take as i32);
            self.n_busy += take;
            pos += take;
        }
    }

    /// Busy blocks of window `wi` change by `d` (or its runs changed, `d` = 0); keeps `free_wins` and marks the window's
    /// run summary.
    #[inline(always)]
    fn win_add(&mut self, wi: usize, d: i32) {
        #[cfg(feature = "elastic")]
        if wi < self.base_wins {
            self.base_busy = (self.base_busy as i64 + d as i64) as u64;
        }
        let o = self.win_busy[wi];
        let v = (o as i32 + d) as u16;
        self.win_busy[wi] = v;
        if o == 0 && v != 0 {
            self.free_wins -= 1;
        } else if o != 0 && v == 0 {
            self.free_wins += 1;
        }
        self.runs_dirty(wi);
    }

    /// Window `wi` changed: its run summary and every tree node above it are recomputed on their next read. Stops at the
    /// first node already dirty (its ancestors are: a node becomes clean only by a read that cleans every node below
    /// it), so a burst of changes in one area costs two steps each. A window summary is no such stop: a full window's
    /// stays dirty under a clean parent (`sum` does not read it).
    #[inline(always)]
    fn runs_dirty(&self, wi: usize) {
        self.wruns[wi].set(RUNS_DIRTY);
        let mut i = wi;
        for lv in &self.tree {
            i >>= LOG_FAN;
            if lv[i].replace(DIRTY).max == DIRTY.max {
                return;
            }
        }
    }

    /// Size the tree for the current window count (construction, `lend_add`): new nodes are dirty, and so is the last
    /// old node of every level (its windows past the old end became real).
    fn tree_grow(&mut self) {
        let mut len = self.win_busy.len();
        let mut k = 0;
        loop {
            len = len.div_ceil(FAN).max(1);
            if k == self.tree.len() {
                self.tree.push(Vec::new());
            }
            let lv = &mut self.tree[k];
            if let Some(last) = lv.last() {
                last.set(DIRTY);
            }
            lv.resize(len, std::cell::Cell::new(DIRTY));
            if len == 1 {
                break;
            }
            k += 1;
        }
    }

    /// Summary of node `i` of level `k` (level 0 = window `i`); positions past the region read as busy.
    fn sum(&self, k: usize, i: usize) -> Sum {
        if k == 0 {
            return match self.win_busy.get(i) {
                Some(&b) if (b as u64) < WIN => {
                    let (pre, suf, max) = self.win_runs(i);
                    Sum {
                        pre,
                        suf,
                        max,
                        dmax: if b > 0 { max } else { 0 },
                    }
                }
                // full (holes included) or past the region
                _ => Sum::default(),
            };
        }
        let Some(c) = self.tree[k - 1].get(i) else {
            return Sum::default();
        };
        let s = c.get();
        if s.max != DIRTY.max {
            return s;
        }
        let cs = WIN << (LOG_FAN * (k as u32 - 1));
        let mut acc = self.sum(k - 1, i * FAN);
        for j in i * FAN + 1..(i + 1) * FAN {
            let r = self.sum(k - 1, j);
            acc = acc.join((j - i * FAN) as u64 * cs, r, cs, !self.brk(j as u64 * cs));
        }
        c.set(acc);
        acc
    }

    /// Free runs of window `wi`: (blocks free at its start, at its end, longest run); recomputed if marked dirty.
    #[inline]
    fn win_runs(&self, wi: usize) -> (u64, u64, u64) {
        let mut v = self.wruns[wi].get();
        if v == RUNS_DIRTY {
            v = self.win_runs_calc(wi);
            self.wruns[wi].set(v);
        }
        unpack_runs(v)
    }

    /// Words beyond the region count as busy; an extent starting inside the window ends the runs before it.
    fn win_runs_calc(&self, wi: usize) -> u32 {
        let (a, e) = (wi as u64 * WIN, (wi as u64 + 1) * WIN);
        let mut p = self.cut_after(a, e);
        let (pre, mut suf, mut max) = self.bit_runs(a, p);
        while p < e {
            let q = self.cut_after(p, e);
            let r = self.bit_runs(p, q);
            (suf, max) = (r.1, max.max(r.2));
            p = q;
        }
        pack_runs(pre, suf, max)
    }

    /// Free runs of the blocks `[p, q)`: (free at the start, at the end, longest).
    fn bit_runs(&self, p: u64, q: u64) -> (u64, u64, u64) {
        let (mut pre, mut cur, mut max, mut closed) = (0u64, 0u64, 0u64, false);
        let mut pos = p;
        while pos < q {
            let w = (pos / 64) as usize;
            let bit = pos % 64;
            let avail = (64 - bit).min(q - pos);
            let x = if w < self.d.len() {
                self.busy_word(w)
            } else {
                !0
            } >> bit;
            let mut b = 0u64;
            while b < avail {
                let z = (((!x) >> b).trailing_ones() as u64).min(avail - b);
                cur += z;
                b += z;
                if b >= avail {
                    break;
                }
                if !closed {
                    (pre, closed) = (cur, true);
                }
                max = max.max(cur);
                cur = 0;
                b += ((x >> b).trailing_ones() as u64).min(avail - b);
            }
            pos += avail;
        }
        max = max.max(cur);
        if !closed {
            pre = cur;
        }
        (pre, cur, max)
    }

    fn is_free_rel(&self, i: u64) -> bool {
        self.busy_word((i / 64) as usize) >> (i % 64) & 1 == 0
    }
    /// End of the free run from relative block `i` within `[i, lim)`: the first busy block, or `lim` (`lim` <= the
    /// region end). Word by word.
    #[inline]
    fn free_upto(&self, mut i: u64, lim: u64) -> u64 {
        while i < lim {
            let b = i % 64;
            let busy = self.busy_word((i / 64) as usize) >> b;
            if busy != 0 {
                return (i + u64::from(busy.trailing_zeros())).min(lim);
            }
            i += 64 - b;
        }
        lim
    }

    pub fn unreserve(&mut self, blk: u64, n: u32) {
        let r = self.rel_of(blk);
        self.set(L_RESERVED, r, n as u64, false);
    }

    // ---------------------------------------------------------------- applied state

    /// Offline repair: drop the reservation of the not yet allocated blocks of a range a record frees.
    pub fn unreserve_unallocated(&mut self, blk: u64, n: u32) {
        for b in blk..blk + u64::from(n) {
            if !self.is_allocated(b, 1) {
                self.unreserve(b, 1);
            }
        }
    }

    /// Txn applied: reserved -> allocated.
    pub fn apply_alloc(&mut self, blk: u64, n: u32) {
        let r = self.rel_of(blk);
        self.mv(r, n as u64, L_RESERVED, L_ALLOC);
    }

    /// Mark allocated without a reservation (fsck's expected map, tests); live apply and WAL replay use [`Self::apply_alloc`].
    pub fn apply_alloc_replay(&mut self, blk: u64, n: u32) {
        self.set(L_ALLOC, self.rel_of(blk), n as u64, true);
    }

    /// Txn applied: allocated -> held (unusable until a checkpoint passes it).
    pub fn apply_free(&mut self, blk: u64, n: u32) {
        let r = self.rel_of(blk);
        self.mv(r, n as u64, L_ALLOC, L_HELD);
    }

    /// Held -> free.
    pub fn release_held(&mut self, blk: u64, n: u32) {
        self.set(L_HELD, self.rel_of(blk), n as u64, false);
    }

    /// Free -> held without a record: a runtime deallocate of `[blk, blk + n)` is in flight (adr 0642); back with
    /// [`Self::release_held`] at its completion. The durable alloc layer is untouched.
    pub fn hold_free(&mut self, blk: u64, n: u32) {
        let r = self.rel_of(blk);
        debug_assert!(
            (r..r + n as u64).all(|i| self.is_free_rel(i)),
            "hold_free of a busy block"
        );
        self.set(L_HELD, r, n as u64, true);
    }

    // ---------------------------------------------------------------- free-space defrag (adr 0021 am. 33)

    /// Summary windows (`WIN` blocks each, relative index order).
    pub fn n_windows(&self) -> usize {
        self.win_busy.len()
    }

    /// Busy blocks (allocated, reserved, held, padding) of window `w`.
    pub fn window_busy(&self, w: usize) -> u64 {
        self.win_busy[w] as u64
    }

    /// Windows without a busy block (each a free 1 MiB run unless it straddles two extents). O(1).
    pub fn free_windows(&self) -> u64 {
        self.free_wins
    }

    /// Free-space shape from the window run summaries (adr 0475): `[blocks in whole free windows, free blocks in windows
    /// whose longest run is shorter than FRAG_SHORT, longest free run]` of the last complete walk over the windows. Each call
    /// walks at most `FRAG_STEP` windows on (the first call walks them all), so the values trail the allocator by up to
    /// `n_windows / FRAG_STEP` calls and a walk spans the changes between its calls. Runs end at extent starts (a free
    /// window holding one is no whole free window).
    pub fn frag(&self) -> [u64; 3] {
        let mut w = self.fwalk.get();
        let Some(last) = w.last else {
            let f = self.frag_full();
            w.last = Some(f);
            self.fwalk.set(w);
            return f;
        };
        let n = self.n_windows();
        let end = (w.next + FRAG_STEP).min(n);
        self.frag_walk(w.next..end, &mut w.sums);
        w.next = end;
        if end >= n {
            w = FragWalk {
                last: Some(w.sums.f),
                ..FragWalk::default()
            };
        }
        self.fwalk.set(w);
        w.last.unwrap_or(last)
    }

    /// [`Self::frag`] of the current state: one walk over every window (O(windows); tests, first call).
    pub fn frag_full(&self) -> [u64; 3] {
        let mut s = FragSums::default();
        self.frag_walk(0..self.n_windows(), &mut s);
        s.f
    }

    fn frag_walk(&self, ws: std::ops::Range<usize>, s: &mut FragSums) {
        for wi in ws {
            let b = self.win_busy[wi] as u64;
            if self.brk(wi as u64 * WIN) {
                s.run = 0;
            }
            if b == WIN {
                s.run = 0;
                continue;
            }
            let (pre, suf, max) = self.win_runs(wi);
            if b == 0 && pre == WIN {
                s.f[0] += WIN;
            }
            if max < FRAG_SHORT {
                s.f[1] += WIN - b;
            }
            s.f[2] = s.f[2].max(max).max(s.run + pre);
            s.run = if pre == WIN { s.run + WIN } else { suf };
        }
    }

    /// Engine block of the first block of window `w`.
    pub fn window_phys(&self, w: usize) -> u64 {
        self.phys_of(w as u64 * WIN)
    }

    /// Window of engine block `blk` (`None` outside the region).
    pub fn window_of(&self, blk: u64) -> Option<usize> {
        self.rel(blk, 1).map(|r| (r / WIN) as usize)
    }

    /// Engine block of window `w` when the window is one free run of `WIN` blocks (no busy block, no extent start
    /// inside it).
    pub fn free_window_phys(&self, w: usize) -> Option<u64> {
        let r = w as u64 * WIN;
        (self.win_busy[w] == 0 && r + WIN <= self.n && self.cut_after(r, r + WIN) == r + WIN)
            .then(|| self.phys_of(r))
    }

    /// Window `w` continues window `w - 1` in engine blocks (no extent starts at its first block).
    pub fn window_joins(&self, w: usize) -> bool {
        w > 0 && !self.brk(w as u64 * WIN)
    }

    /// Allocated or held (freed, waiting for a checkpoint) blocks of window `w`: what still keeps a fenced window from
    /// becoming a whole free run (adr 0021 am. 51).
    pub fn window_live(&self, w: usize) -> u64 {
        (w * 4..(w * 4 + 4).min(self.d.len()))
            .map(|i| (self.d[i][0] | self.d[i][1]).count_ones() as u64)
            .sum()
    }

    /// Allocated blocks of window `w` (held ones excluded: a checkpoint frees those).
    pub fn window_alloc(&self, w: usize) -> u64 {
        (w * 4..(w * 4 + 4).min(self.d.len()))
            .map(|i| self.d[i][0].count_ones() as u64)
            .sum()
    }

    /// Allocated blocks of windows `ws` (held ones excluded) as `(bitmap word, bits)` for the words holding one: what
    /// pins the windows when the data mover gives up on them (adr 0021 am. 79).
    pub fn alloc_pins(&self, ws: std::ops::Range<usize>) -> Vec<(usize, u64)> {
        (ws.start * 4..(ws.end * 4).min(self.d.len()))
            .filter(|&i| self.d[i][0] != 0)
            .map(|i| (i, self.d[i][0]))
            .collect()
    }

    /// Some block of `pins` ([`Self::alloc_pins`]) is no longer allocated: freed since.
    pub fn pins_freed(&self, pins: &[(usize, u64)]) -> bool {
        pins.iter()
            .any(|&(i, b)| self.d.get(i).is_none_or(|d| b & !d[0] != 0))
    }

    /// Any reserved (in-flight write) block in window `w`.
    pub fn window_reserved(&self, w: usize) -> bool {
        (w * 4..(w * 4 + 4).min(self.d.len())).any(|i| self.res.word(i) != 0)
    }

    /// First window in `[lo, hi)` below node `i` of level `k` that is partly used and holds a run of `want` (`Sum::dmax`).
    fn dense_seek(&self, k: usize, i: usize, lo: usize, hi: usize, want: u64) -> Option<usize> {
        let span = 1usize << (LOG_FAN * k as u32);
        let (a, e) = (i * span, (i + 1) * span);
        if (k == 0 || (a >= lo && e <= hi)) && self.sum(k, i).dmax < want {
            return None;
        }
        if k == 0 {
            return Some(i);
        }
        let cs = span >> LOG_FAN;
        (lo.max(a) / cs..=(hi.min(e) - 1) / cs)
            .find_map(|j| self.dense_seek(k - 1, j, lo, hi, want))
    }

    /// Reserve `n` contiguous blocks inside a partly used window (never a whole free one: defrag destinations fill holes
    /// instead of using up the whole windows a sweep makes). Next-fit over windows from the last hit, found through the
    /// run-summary tree (adr 0475 am. 2). Engine block.
    pub fn reserve_dense(&mut self, n: u32) -> Option<u64> {
        // borrowed chunks (adr 0021 am. 49) are never defrag destinations: moves go back to the base
        #[cfg(feature = "elastic")]
        let nw = self.base_n.div_ceil(WIN) as usize;
        #[cfg(not(feature = "elastic"))]
        let nw = self.win_busy.len();
        self.dense_in(n, nw)
    }

    /// `reserve_dense` over every window, borrowed chunks included (evacuation destinations, adr 0021 am. 82: the live
    /// blocks of a chunk given back on demand fill holes, the base's first, and keep the whole free windows).
    #[cfg(feature = "elastic")]
    pub fn reserve_hole(&mut self, n: u32) -> Option<u64> {
        self.dense_in(n, self.win_busy.len())
    }

    /// `reserve_dense` over windows `[0, nw)`.
    fn dense_in(&mut self, n: u32, nw: usize) -> Option<u64> {
        let want = n as u64;
        if want == 0 {
            return None;
        }
        let cur = self.dense_cur.min(nw);
        // the last hit's window, then from it to the end, then wrapping
        for (lo, hi) in [(cur, nw), (0, cur)] {
            if lo >= hi {
                continue;
            }
            let x = if self.sum(0, lo).dmax >= want {
                Some(lo)
            } else {
                self.dense_seek(self.tree.len(), 0, lo, hi, want)
            };
            if let Some(x) = x {
                let (a, e) = (x as u64 * WIN, ((x as u64 + 1) * WIN).min(self.n));
                let r = self
                    .scan_win(x, a, e, want, &mut (0, a))
                    .expect("window summary holds a run of `want`");
                self.take_free(r, want);
                self.dense_cur = x;
                return Some(self.phys_of(r));
            }
        }
        None
    }

    /// Fence window `w`: reserve all its free blocks so no allocation lands there while its live blocks are moved
    /// out. The runs are appended to `out` as `(engine block, blocks)`; `unreserve` gives them back.
    pub fn fence_window(&mut self, w: usize, out: &mut Vec<(u64, u32)>) {
        let (a, b) = (w as u64 * WIN, ((w as u64 + 1) * WIN).min(self.n));
        let mut i = a;
        while i < b {
            if !self.is_free_rel(i) {
                i += 1;
                continue;
            }
            let lim = b.min(self.seg_end(i));
            let e = self.free_upto(i + 1, lim);
            self.take_free(i, e - i);
            out.push((self.phys_of(i), (e - i) as u32));
            i = e;
        }
    }

    // ---------------------------------------------------------------- `f` chunk (de)serialization

    pub fn n_chunks(&self) -> u64 {
        self.n.div_ceil(CHUNK_BLOCKS)
    }

    /// Persistent form of chunk `ci`; returns false if it is all zero (stored as an absent key).
    pub fn chunk_bytes(&self, ci: u64, out: &mut [u8; CHUNK_BYTES]) -> bool {
        let w0 = ci as usize * CW;
        let mut any = 0u64;
        for k in 0..CW {
            let w = self.d.get(w0 + k).map_or(0, |x| x[0]);
            any |= w;
            out[k * 8..k * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        any != 0
    }

    /// Load (or reload: the counters follow the difference) chunk `ci` of the durable layer. Validated before
    /// anything changes: no bit beyond the region.
    pub fn load_chunk(&mut self, ci: u64, bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.len() != CHUNK_BYTES || ci >= self.n_chunks() {
            return Err("bad bitmap chunk");
        }
        let nw = words_for(self.n);
        let w0 = ci as usize * CW;
        let word = |k: usize| denc::le::rd_u64(bytes, k * 8);
        for k in 0..CW {
            let valid = if w0 + k >= nw {
                0
            } else if w0 + k == self.pad_w {
                !self.pad
            } else {
                !0
            };
            if word(k) & !valid != 0 {
                return Err("bitmap bits beyond region");
            }
        }
        for k in 0..CW.min(nw - w0) {
            let x = word(k);
            self.update_word(w0 + k, |l| l[L_ALLOC] = x);
        }
        Ok(())
    }

    /// Words of the durable bitmap (fsck).
    pub fn n_words(&self) -> usize {
        self.d.len()
    }
    /// Word `w` of the durable bitmap (fsck).
    pub fn alloc_word(&self, w: usize) -> u64 {
        self.d[w][0]
    }
}

// ---------------------------------------------------------------------------------------------------------

/// A page-aligned physical part of a logical metadata cell. Extents are in logical page order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetaExtent {
    pub start: u64,
    pub pages: u32,
}

/// One elastic metadata cell: `ppc` tree pages backed by one or more physical extents.
#[derive(Clone, Debug)]
struct Cell {
    /// Engine block address of the first page; 0 = vacant slot.
    start: u64,
    extents: Vec<MetaExtent>,
    /// Exclusive logical page ends, for binary page-to-extent lookup without a scan or allocation.
    page_ends: Vec<u32>,
    bits: Vec<u64>,
    used: u32,
}

/// Bitmap of tree pages. The base area (`n` pages, the fixed meta region of the shard directory) is page indices
/// `0..n`; an ELASTIC store adds cells of `ppc` pages each (index `n + slot * ppc + k`) carved from the data
/// region on demand and returned when empty. Allocation is first-fit by index (low pages first) so high cells
/// empty out and can be released.
#[derive(Clone, Debug)]
pub struct MetaAlloc {
    bits: Vec<u64>,
    n: u32,
    used: u32,
    /// Pages in use inside cells (part of `used`).
    cell_used: u32,
    /// First base word that may hold a free bit.
    low: usize,
    /// Pages per cell (multiple of 64); 0 = not elastic.
    ppc: u32,
    cells: Vec<Cell>,
    /// `(start, slot)` of the present cells, ascending (address -> index lookup).
    order: Vec<(u64, u32)>,
    /// `(physical start, slot, logical page offset, extent pages)`, ascending by physical address.
    extent_order: Vec<(u64, u32, u32, u32)>,
    low_cell: usize,
    /// Bumped by every `add_cell`/`remove_cell`: the persisted image describes the cell set.
    layout_gen: u64,
}

impl MetaAlloc {
    pub fn new(n: u32) -> MetaAlloc {
        MetaAlloc {
            bits: vec![0; words_for(n as u64)],
            n,
            used: 0,
            cell_used: 0,
            low: 0,
            ppc: 0,
            cells: Vec::new(),
            order: Vec::new(),
            extent_order: Vec::new(),
            low_cell: 0,
            layout_gen: 0,
        }
    }
    /// Elastic variant: base `n` pages plus cells of `ppc` pages.
    pub fn new_elastic(n: u32, ppc: u32) -> MetaAlloc {
        assert!(ppc >= 64 && ppc.is_multiple_of(64));
        let mut m = MetaAlloc::new(n);
        m.ppc = ppc;
        m
    }
    pub fn is_elastic(&self) -> bool {
        self.ppc != 0
    }
    pub fn ppc(&self) -> u32 {
        self.ppc
    }
    /// Pages of the base area.
    pub fn base_pages(&self) -> u32 {
        self.n
    }
    pub fn n_cells(&self) -> usize {
        self.order.len()
    }
    /// Total pages (base + present cells).
    pub fn len(&self) -> u32 {
        self.n + self.order.len() as u32 * self.ppc
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn used(&self) -> u32 {
        self.used
    }
    pub fn free(&self) -> u32 {
        self.len() - self.used
    }
    /// Pages in use inside cells (not the base area).
    pub fn cell_used(&self) -> u32 {
        debug_assert_eq!(
            self.cell_used,
            self.cells.iter().map(|c| c.used).sum::<u32>()
        );
        self.cell_used
    }
    pub fn layout_gen(&self) -> u64 {
        self.layout_gen
    }
    /// `(start, used pages)` of the present cells, ascending by start.
    #[cfg(test)]
    pub fn cell_list(&self) -> Vec<(u64, u32)> {
        self.order
            .iter()
            .map(|&(s, sl)| (s, self.cells[sl as usize].used))
            .collect()
    }

    fn cell_of(&self, i: u32) -> (usize, usize) {
        let r = (i - self.n) as usize;
        (r / self.ppc as usize, r % self.ppc as usize)
    }

    pub fn get(&self, i: u32) -> bool {
        if i < self.n {
            return self.bits[(i / 64) as usize] >> (i % 64) & 1 != 0;
        }
        let (s, k) = self.cell_of(i);
        self.cells
            .get(s)
            .is_some_and(|c| c.start != 0 && c.bits[k / 64] >> (k % 64) & 1 != 0)
    }
    pub fn set(&mut self, i: u32) {
        if i < self.n {
            let m = 1u64 << (i % 64);
            let w = &mut self.bits[(i / 64) as usize];
            if *w & m == 0 {
                *w |= m;
                self.used += 1;
            }
            return;
        }
        let (s, k) = self.cell_of(i);
        let c = &mut self.cells[s];
        assert!(c.start != 0, "set in a vacant cell");
        let m = 1u64 << (k % 64);
        if c.bits[k / 64] & m == 0 {
            c.bits[k / 64] |= m;
            c.used += 1;
            self.used += 1;
            self.cell_used += 1;
        }
    }
    pub fn clear(&mut self, i: u32) {
        if i < self.n {
            let m = 1u64 << (i % 64);
            let w = &mut self.bits[(i / 64) as usize];
            if *w & m != 0 {
                *w &= !m;
                self.used -= 1;
                self.low = self.low.min((i / 64) as usize);
            }
            return;
        }
        let (s, k) = self.cell_of(i);
        let c = &mut self.cells[s];
        let m = 1u64 << (k % 64);
        if c.start != 0 && c.bits[k / 64] & m != 0 {
            c.bits[k / 64] &= !m;
            c.used -= 1;
            self.used -= 1;
            self.cell_used -= 1;
            self.low_cell = self.low_cell.min(s);
        }
    }

    /// Lowest free page (first fit).
    pub fn alloc(&mut self) -> Option<u32> {
        let nw = self.bits.len();
        while self.low < nw {
            let mut word = !self.bits[self.low];
            if self.low + 1 == nw && !self.n.is_multiple_of(64) {
                word &= !0u64 >> (64 - self.n % 64);
            }
            if word != 0 {
                let i = self.low as u32 * 64 + word.trailing_zeros();
                self.set(i);
                return Some(i);
            }
            self.low += 1;
        }
        let ppc = self.ppc as usize;
        while self.low_cell < self.cells.len() {
            let s = self.low_cell;
            let c = &self.cells[s];
            if c.start != 0 && (c.used as usize) < ppc {
                let (w, word) = c
                    .bits
                    .iter()
                    .enumerate()
                    .find_map(|(w, b)| (*b != !0).then_some((w, !*b)))
                    .expect("cell with a free page");
                let i = self.n + (s * ppc + w * 64) as u32 + word.trailing_zeros();
                self.set(i);
                return Some(i);
            }
            self.low_cell += 1;
        }
        None
    }

    /// Add a cell at block `start` (> 0); returns its slot.
    #[cfg(test)]
    pub fn add_cell(&mut self, start: u64) -> u32 {
        self.add_cell_extents(vec![MetaExtent {
            start,
            pages: self.ppc,
        }])
    }

    /// Add one logical cell whose physical extents contain exactly `ppc` whole pages. Returns its slot.
    /// The first extent's address is the cell identifier, independent of physical address order.
    pub fn add_cell_extents(&mut self, extents: Vec<MetaExtent>) -> u32 {
        assert!(self.ppc != 0 && !extents.is_empty());
        assert!(extents.iter().all(|e| e.start != 0 && e.pages != 0));
        assert_eq!(
            extents.iter().map(|e| u64::from(e.pages)).sum::<u64>(),
            u64::from(self.ppc)
        );
        let start = extents[0].start;
        let mut offset = 0;
        let page_ends = extents
            .iter()
            .map(|e| {
                offset += e.pages;
                offset
            })
            .collect();
        let cell = Cell {
            start,
            extents,
            page_ends,
            bits: vec![0; self.ppc as usize / 64],
            used: 0,
        };
        let slot = match self.cells.iter().position(|c| c.start == 0) {
            Some(s) => {
                self.cells[s] = cell;
                s
            }
            None => {
                self.cells.push(cell);
                self.cells.len() - 1
            }
        };
        let at = self.order.partition_point(|&(s, _)| s < start);
        self.order.insert(at, (start, slot as u32));
        let mut offset = 0;
        for e in &self.cells[slot].extents {
            let at = self
                .extent_order
                .partition_point(|&(start, _, _, _)| start < e.start);
            self.extent_order
                .insert(at, (e.start, slot as u32, offset, e.pages));
            offset += e.pages;
        }
        self.low_cell = self.low_cell.min(slot);
        self.layout_gen += 1;
        slot as u32
    }

    fn rebuild_extent_order(&mut self) {
        self.extent_order.clear();
        for (slot, cell) in self.cells.iter_mut().enumerate() {
            let mut offset = 0;
            cell.page_ends.clear();
            for e in &cell.extents {
                self.extent_order
                    .push((e.start, slot as u32, offset, e.pages));
                offset += e.pages;
                cell.page_ends.push(offset);
            }
        }
        self.extent_order.sort_unstable();
    }

    /// Physical extents of a logical cell, in logical page order, measured in engine blocks.
    pub fn cell_extents(&self, start: u64, bpp: u64) -> Vec<(u64, u32)> {
        let at = self
            .order
            .binary_search_by_key(&start, |&(s, _)| s)
            .expect("cell_extents: no such cell");
        self.cells[self.order[at].1 as usize]
            .extents
            .iter()
            .map(|e| {
                (
                    e.start,
                    (u64::from(e.pages) * bpp)
                        .try_into()
                        .expect("metadata extent too large"),
                )
            })
            .collect()
    }

    /// Every physical cell extent, sorted by address, measured in engine blocks.
    pub fn physical_extents(&self, bpp: u64) -> Vec<(u64, u32)> {
        self.extent_order
            .iter()
            .map(|&(start, _, _, pages)| {
                (
                    start,
                    (u64::from(pages) * bpp)
                        .try_into()
                        .expect("metadata extent too large"),
                )
            })
            .collect()
    }

    /// Validate the physical extent map for the store's page geometry before mapping or reading any tree page.
    /// The caller additionally checks these ranges belong to its data region and are allocated there.
    pub fn validate_extents(&self, bpp: u64) -> Result<(), &'static str> {
        if !matches!(bpp, 1 | 2 | 4 | 8) {
            return Err("meta extent page geometry");
        }
        let mut previous_end = 0;
        for &(start, _, _, pages) in &self.extent_order {
            let blocks = u64::from(pages)
                .checked_mul(bpp)
                .ok_or("meta extent length overflow")?;
            if start == 0 || pages == 0 || blocks > u64::from(u32::MAX) {
                return Err("meta extent length");
            }
            let end = start
                .checked_add(blocks)
                .ok_or("meta extent address overflow")?;
            if start < previous_end {
                return Err("meta extent overlap");
            }
            previous_end = end;
        }
        Ok(())
    }
    /// Drop an empty cell by its start address.
    pub fn remove_cell(&mut self, start: u64) {
        let at = self
            .order
            .binary_search_by_key(&start, |&(s, _)| s)
            .expect("remove_cell: no such cell");
        let slot = self.order[at].1 as usize;
        assert_eq!(self.cells[slot].used, 0, "remove_cell: cell in use");
        self.order.remove(at);
        self.cells[slot] = Cell {
            start: 0,
            extents: Vec::new(),
            page_ends: Vec::new(),
            bits: Vec::new(),
            used: 0,
        };
        while self.cells.last().is_some_and(|c| c.start == 0) {
            self.cells.pop();
        }
        self.extent_order.retain(|&(_, s, _, _)| s as usize != slot);
        self.layout_gen += 1;
    }
    /// Start addresses of present cells without any used page.
    pub fn empty_cells(&self) -> Vec<u64> {
        self.order
            .iter()
            .filter(|&&(_, s)| self.cells[s as usize].used == 0)
            .map(|&(a, _)| a)
            .collect()
    }

    /// Engine block address of a page in a cell (`bpp` = blocks per page).
    pub fn cell_page_addr(&self, i: u32, bpp: u64) -> u64 {
        let (s, k) = self.cell_of(i);
        let cell = &self.cells[s];
        let extent = cell.page_ends.partition_point(|&end| end <= k as u32);
        let before = if extent == 0 {
            0
        } else {
            cell.page_ends[extent - 1]
        };
        cell.extents[extent].start + (k as u64 - u64::from(before)) * bpp
    }
    /// Page index of an address inside a present cell.
    pub fn cell_page_idx(&self, addr: u64, bpp: u64) -> Option<u32> {
        let at = self
            .extent_order
            .partition_point(|&(s, _, _, _)| s <= addr)
            .checked_sub(1)?;
        let (start, slot, offset, pages) = self.extent_order[at];
        let r = addr - start;
        (r.is_multiple_of(bpp) && r / bpp < u64::from(pages))
            .then(|| self.n + slot * self.ppc + offset + (r / bpp) as u32)
    }

    // ---------------------------------------------------------------- legacy fixed image (no cells)

    /// Serialize: `[u32 crc][u32 magic][u32 n][u32 used]` + bits, padded to whole 4 KiB blocks. Base area only.
    pub fn encode(&self, bytes_len: usize, bits_override: Option<&[u32]>) -> Vec<u8> {
        let mut bits = self.bits.clone();
        if let Some(clr) = bits_override {
            for &i in clr {
                bits[(i / 64) as usize] &= !(1u64 << (i % 64));
            }
        }
        let used: u32 = bits.iter().map(|w| w.count_ones()).sum();
        let mut out = vec![0u8; bytes_len];
        out[4..8].copy_from_slice(&META_BM_MAGIC.to_le_bytes());
        out[8..12].copy_from_slice(&self.n.to_le_bytes());
        out[12..16].copy_from_slice(&used.to_le_bytes());
        for (k, w) in bits.iter().enumerate() {
            out[16 + k * 8..24 + k * 8].copy_from_slice(&w.to_le_bytes());
        }
        let c = crate::codec::crc(&out[4..]);
        out[0..4].copy_from_slice(&c.to_le_bytes());
        out
    }
    pub fn decode(b: &[u8], n: u32) -> Result<MetaAlloc, &'static str> {
        if b.len() < 16 + words_for(n as u64) * 8 {
            return Err("meta bitmap too short");
        }
        if denc::le::rd_u32(b, 0) != crate::codec::crc(&b[4..]) {
            return Err("meta bitmap crc");
        }
        if denc::le::rd_u32(b, 4) != META_BM_MAGIC || denc::le::rd_u32(b, 8) != n {
            return Err("meta bitmap header");
        }
        let nw = words_for(n as u64);
        let bits: Vec<u64> = (0..nw)
            .map(|k| u64::from_le_bytes(b[16 + k * 8..24 + k * 8].try_into().unwrap()))
            .collect();
        let used: u32 = bits.iter().map(|w| w.count_ones()).sum();
        if used != denc::le::rd_u32(b, 12)
            || (!n.is_multiple_of(64) && bits[nw - 1] >> (n % 64) != 0)
        {
            return Err("meta bitmap content");
        }
        let mut m = MetaAlloc::new(n);
        m.bits = bits;
        m.used = used;
        Ok(m)
    }
    pub fn bytes_needed(n: u32) -> usize {
        (16 + words_for(n as u64) * 8).div_ceil(crate::BLK) * crate::BLK
    }

    // ---------------------------------------------------------------- elastic image

    /// Bytes added by a present MBL3 cell in a new slot, including its extent map and page bitmap.
    pub fn added_cell_blob_len(&self, n_extents: usize) -> usize {
        4 + n_extents * 12 + self.ppc as usize / 8
    }

    /// Payload bytes of the elastic image (see `blob_encode`).
    pub fn blob_len(&self) -> usize {
        BLOB_HDR
            + words_for(self.n as u64) * 8
            + self
                .cells
                .iter()
                .map(|c| {
                    if c.start == 0 {
                        4
                    } else {
                        self.added_cell_blob_len(c.extents.len())
                    }
                })
                .sum::<usize>()
    }

    /// MBL3 elastic image: `[magic u32][n u32][ppc u32][nslots u32][used u32]`, base bits, then per slot
    /// `extent_count u32` (0 = vacant), followed by `(start u64, pages u32)` for each extent and the cell's bits.
    /// MBL2 images with one contiguous extent per cell remain readable. Pages in `clear` are written as free (superseded pages
    /// that become reusable when this image's checkpoint is durable).
    pub fn blob_encode(&self, clear: &[u32]) -> Vec<u8> {
        let mut m = self.clone();
        for &i in clear {
            m.clear(i);
        }
        let mut out = Vec::with_capacity(m.blob_len());
        out.extend_from_slice(&BLOB_EXTENTS_MAGIC.to_le_bytes());
        out.extend_from_slice(&m.n.to_le_bytes());
        out.extend_from_slice(&m.ppc.to_le_bytes());
        out.extend_from_slice(&(m.cells.len() as u32).to_le_bytes());
        out.extend_from_slice(&m.used.to_le_bytes());
        for w in &m.bits {
            out.extend_from_slice(&w.to_le_bytes());
        }
        for c in &m.cells {
            out.extend_from_slice(&(c.extents.len() as u32).to_le_bytes());
            if c.start != 0 {
                for e in &c.extents {
                    out.extend_from_slice(&e.start.to_le_bytes());
                    out.extend_from_slice(&e.pages.to_le_bytes());
                }
                for w in &c.bits {
                    out.extend_from_slice(&w.to_le_bytes());
                }
            }
        }
        debug_assert_eq!(out.len(), self.blob_len());
        out
    }

    /// [`MetaAlloc::blob_decode_ext`] of an image without extension sections.
    #[cfg(test)]
    pub fn blob_decode(b: &[u8], n: u32) -> Result<MetaAlloc, &'static str> {
        match Self::blob_decode_ext(b, n)? {
            (m, used) if used == b.len() => Ok(m),
            _ => Err("meta image content"),
        }
    }

    /// Decode a meta image followed by extension sections: also returns the bytes the meta image itself occupies.
    pub fn blob_decode_ext(b: &[u8], n: u32) -> Result<(MetaAlloc, usize), &'static str> {
        let rd32 = |o: usize| denc::le::rd_u32(b, o);
        let rd64 = |o: usize| denc::le::rd_u64(b, o);
        if b.len() < BLOB_HDR || ![BLOB_MAGIC, BLOB_EXTENTS_MAGIC].contains(&rd32(0)) {
            return Err("meta image header");
        }
        let segmented = rd32(0) == BLOB_EXTENTS_MAGIC;
        let (bn, ppc, nslots, used) = (rd32(4), rd32(8), rd32(12) as usize, rd32(16));
        if bn != n || ppc < 64 || !ppc.is_multiple_of(64) {
            return Err("meta image geometry");
        }
        // Logical page indices remain u32 even when vacant slots are present. Bound all allocations by input length.
        if u64::from(n) + nslots as u64 * u64::from(ppc) > u64::from(u32::MAX) {
            return Err("meta image geometry");
        }
        let mut m = MetaAlloc::new_elastic(n, ppc);
        let nw = words_for(n as u64);
        let mut o = BLOB_HDR;
        if b.len() < o + nw * 8 {
            return Err("meta image too short");
        }
        for k in 0..nw {
            m.bits[k] = rd64(o + k * 8);
        }
        o += nw * 8;
        if !n.is_multiple_of(64) && m.bits[nw - 1] >> (n % 64) != 0 {
            return Err("meta image content");
        }
        m.used = m.bits.iter().map(|w| w.count_ones()).sum();
        let cw = ppc as usize / 64;
        for _ in 0..nslots {
            let slot_bytes = if segmented { 4 } else { 8 };
            if b.len() - o < slot_bytes {
                return Err("meta image too short");
            }
            let extents = if segmented {
                let count = rd32(o) as usize;
                o += 4;
                if count > ppc as usize || count > (b.len() - o) / 12 {
                    return Err("meta image extent count");
                }
                let mut extents = Vec::with_capacity(count);
                for _ in 0..count {
                    extents.push(MetaExtent {
                        start: rd64(o),
                        pages: rd32(o + 8),
                    });
                    o += 12;
                }
                extents
            } else {
                let start = rd64(o);
                o += 8;
                if start == 0 {
                    Vec::new()
                } else {
                    vec![MetaExtent { start, pages: ppc }]
                }
            };
            if extents.is_empty() {
                m.cells.push(Cell {
                    start: 0,
                    extents,
                    page_ends: Vec::new(),
                    bits: Vec::new(),
                    used: 0,
                });
                continue;
            }
            if extents.iter().any(|e| {
                e.start == 0 || e.pages == 0 || e.start.checked_add(u64::from(e.pages)).is_none()
            }) || extents.iter().map(|e| u64::from(e.pages)).sum::<u64>() != u64::from(ppc)
            {
                return Err("meta image extent geometry");
            }
            let start = extents[0].start;
            if b.len() < o + cw * 8 {
                return Err("meta image too short");
            }
            let bits: Vec<u64> = (0..cw).map(|k| rd64(o + k * 8)).collect();
            o += cw * 8;
            let u: u32 = bits.iter().map(|w| w.count_ones()).sum();
            m.used = m.used.checked_add(u).ok_or("meta image used overflow")?;
            m.cell_used += u;
            m.order.push((start, m.cells.len() as u32));
            m.cells.push(Cell {
                start,
                extents,
                page_ends: Vec::new(),
                bits,
                used: u,
            });
        }
        if o > b.len() || m.used != used {
            return Err("meta image content");
        }
        m.order.sort_unstable();
        if m.order.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err("meta image duplicate cell");
        }
        m.rebuild_extent_order();
        // A page occupies at least one engine block; the mount geometry checks full physical extents for its bpp.
        if m.extent_order
            .windows(2)
            .any(|w| w[0].0 + u64::from(w[0].3) > w[1].0)
        {
            return Err("meta image overlapping extents");
        }
        Ok((m, o))
    }
}

const META_BM_MAGIC: u32 = 0x4d42_4d50;
const BLOB_MAGIC: u32 = 0x4d42_4c32; // "MBL2"
const BLOB_EXTENTS_MAGIC: u32 = 0x4d42_4c33; // "MBL3"
const BLOB_HDR: usize = 20;

// ---- elastic image packed into meta pages (header page lists the others)

/// Tree pages an elastic image of `len` payload bytes occupies.
pub fn blob_pages(len: usize, psz: usize) -> usize {
    let per = psz - crate::page::HDR;
    let mut k = 1;
    while k * per < len + 8 + 12 * (k - 1) {
        k += 1;
    }
    k
}

/// Largest image the header page can index.
pub fn blob_max_len(psz: usize) -> usize {
    let per = psz - crate::page::HDR;
    let kmax = (per - 8) / 12 + 1;
    kmax * per - 8 - 12 * (kmax - 1)
}

/// Pack `payload` into `addrs.len()` sealed pages (`addrs.len() == blob_pages`). Returns the images back to back
/// and the crc of page 0.
pub fn blob_pack(
    payload: &[u8],
    psz: usize,
    addrs: &[u64],
    shard: u32,
    lsn: u64,
) -> (Vec<u8>, u32) {
    use crate::page::{HDR, init, seal};
    let k = addrs.len();
    debug_assert_eq!(k, blob_pages(payload.len(), psz));
    let per = psz - HDR;
    let mut out = vec![0u8; k * psz];
    let mut stream = Vec::with_capacity(8 + 12 * (k - 1) + payload.len());
    stream.extend_from_slice(&(k as u32).to_le_bytes());
    stream.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    stream.resize(8 + 12 * (k - 1), 0);
    stream.extend_from_slice(payload);
    let fill = |out: &mut [u8], stream: &[u8], p: usize| {
        let pg = &mut out[p * psz..(p + 1) * psz];
        init(pg, crate::page::BLOB, 0, addrs[p], shard);
        let from = p * per;
        if from < stream.len() {
            let to = (from + per).min(stream.len());
            pg[HDR..HDR + (to - from)].copy_from_slice(&stream[from..to]);
        }
    };
    // pages 1.. first: their crcs go into page 0's list (inside the stream prefix)
    for p in 1..k {
        fill(&mut out, &stream, p);
        let c = seal(&mut out[p * psz..(p + 1) * psz], addrs[p], lsn);
        let r = 8 + 12 * (p - 1);
        stream[r..r + 8].copy_from_slice(&addrs[p].to_le_bytes());
        stream[r + 8..r + 12].copy_from_slice(&c.to_le_bytes());
    }
    fill(&mut out, &stream, 0);
    let c0 = seal(&mut out[..psz], addrs[0], lsn);
    (out, c0)
}

/// Parse page 0 of an elastic image: `(pages total, payload length, (addr, crc) of pages 1..)`.
pub fn blob_head(p0: &[u8], psz: usize, addr: u64) -> Result<BlobHead, &'static str> {
    use crate::page::HDR;
    crate::page::validate_blob(p0, psz, addr)?;
    let b = &p0[HDR..];
    let k = denc::le::rd_u32(b, 0) as usize;
    let len = denc::le::rd_u32(b, 4) as usize;
    if len > blob_max_len(psz) || k == 0 || 8 + 12 * (k - 1) > b.len() || k != blob_pages(len, psz)
    {
        return Err("meta image page list");
    }
    let refs = (0..k - 1)
        .map(|i| {
            let o = 8 + 12 * i;
            (
                denc::le::rd_u64(b, o),
                u32::from_le_bytes(b[o + 8..o + 12].try_into().unwrap()),
            )
        })
        .collect();
    Ok((k, len, refs))
}

/// Page 0 of an elastic image: `(pages total, payload length, (addr, crc) of pages 1..)`.
pub type BlobHead = (usize, usize, Vec<(u64, u32)>);

/// Reassemble the payload from page 0 and pages 1.. (in list order; each already read).
pub fn blob_unpack(
    p0: &[u8],
    rest: &[Vec<u8>],
    refs: &[(u64, u32)],
    len: usize,
    psz: usize,
) -> Result<Vec<u8>, &'static str> {
    use crate::page::HDR;
    let per = psz - HDR;
    let mut stream: Vec<u8> = p0[HDR..].to_vec();
    for (i, pg) in rest.iter().enumerate() {
        crate::page::validate_blob(pg, psz, refs[i].0)?;
        if crate::page::stored_crc(pg) != refs[i].1 {
            return Err("meta image page crc vs list");
        }
        stream.extend_from_slice(&pg[HDR..]);
    }
    debug_assert!(stream.len() == (rest.len() + 1) * per);
    let skip = 8 + 12 * refs.len();
    stream
        .get(skip..skip + len)
        .map(<[u8]>::to_vec)
        .ok_or("meta image length")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    #[test]
    fn overflowing_physical_ranges_are_rejected() {
        let a = Alloc::new(100, 256);
        assert!(!a.in_region(u64::MAX, 102));
        assert!(!a.in_region(u64::MAX, 1));
        assert!(!a.in_region(355, 2));
        assert!(a.in_region(100, 256));
        assert!(a.in_region(355, 1));
    }

    #[cfg(feature = "elastic")]
    #[test]
    fn overflowing_chunk_ranges_are_rejected() {
        let a = Alloc::with_chunks(&[1024], 1024);
        assert!(!a.in_region(u64::MAX, 1026));
        assert!(a.in_region(1024, 1024));
        assert!(!a.in_region(2047, 2));
    }

    #[test]
    fn find_runs_and_windows() {
        let mut a = Alloc::new(1000, 10_000);
        let x = a.reserve(300).unwrap();
        assert_eq!(x, 1000);
        let y = a.reserve(5).unwrap();
        assert_eq!(y, 1300);
        a.apply_alloc(x, 300);
        assert_eq!(a.n_alloc(), 300);
        a.unreserve(y, 5);
        a.apply_free(x + 10, 20);
        assert_eq!(a.n_held(), 20);
        assert_eq!(a.n_alloc(), 280);
        // held blocks are not allocatable
        let mut got = vec![];
        while let Some(b) = a.reserve(1) {
            got.push(b);
        }
        assert_eq!(got.len() as u64, 10_000 - 300);
        assert!(got.iter().all(|&b| !(x + 10..x + 30).contains(&b)));
        assert_eq!(a.n_free(), 0);
        a.release_held(x + 10, 20);
        assert_eq!(a.n_free(), 20);
        assert_eq!(a.reserve(20), Some(x + 10));
    }

    /// Borrowed chunks (adr 0021 am. 49, 56): base first until nearly full, borrowed next-fit, back to the base once it reopened,
    /// return only when unused, holes never allocated, holes re-filled by a later grant.
    #[cfg(feature = "elastic")]
    #[test]
    fn lent_chunks_priority_return_and_holes() {
        const C: u64 = 1024;
        let base = [10 * C, 11 * C];
        let mut a = Alloc::with_lent(&base, &[40 * C, HOLE, 30 * C], C);
        assert_eq!((a.len(), a.usable_len(), a.n_free()), (5 * C, 4 * C, 4 * C));
        assert!(a.holes_clear() && a.lent_slots() == 3);
        assert!(!a.in_region(0, 1) && a.in_region(40 * C, C as u32) && a.in_region(30 * C + 5, 1));
        let in_base = |b: u64| (10 * C..12 * C).contains(&b);
        let in_slot = |s: u64, b: u64| (s..s + C).contains(&b);
        // the base fills first until less than 5 % of it is free (closed), then the borrowed space (next-fit, slot 0 before
        // slot 2, slot 1 is a hole)
        let (mut in_b, mut s0, mut s2) = (Vec::new(), Vec::new(), Vec::new());
        loop {
            let b = a.reserve(16).unwrap();
            if in_base(b) {
                assert!(
                    s0.is_empty(),
                    "{b}: the base is closed once slot 0 is in use"
                );
                in_b.push(b);
            } else if in_slot(40 * C, b) {
                s0.push(b);
            } else {
                assert!(in_slot(30 * C, b), "{b}: slot 2 after slot 0");
                s2.push(b);
                break;
            }
        }
        assert_eq!(
            in_b.len() as u64 * 16,
            2 * C - 96,
            "base closed below 5 % free"
        );
        assert_eq!(s0.len() as u64, C / 16, "slot 0 filled before slot 2");
        // frees in the base reopen it at 10 % free (and base_n / 50 more than when it closed): new writes go back
        for &b in &in_b[..16] {
            a.unreserve(b, 16);
        }
        let b = a.reserve(8).unwrap();
        assert!(in_base(b), "{b}: base reopened");
        let nb = a.reserve(8).unwrap();
        assert!(in_base(nb));
        // return: refused while slot 2 holds a block, then a hole; capacity follows, nothing lands there
        assert!(!a.lend_remove(2));
        for &b in &s2 {
            a.unreserve(b, 16);
        }
        assert!(a.lend_remove(2));
        assert_eq!((a.usable_len(), a.lent_slot(2)), (3 * C, (HOLE, 0)));
        assert!(!a.in_region(30 * C, 1) && a.holes_clear());
        let free = a.n_free();
        let mut n = 0;
        while let Some(b) = a.reserve(1) {
            assert!(
                in_base(b) || in_slot(40 * C, b),
                "{b}: holes are never allocated"
            );
            n += 1;
        }
        assert_eq!(
            (n, a.n_free()),
            (free, 0),
            "every free block of base and slot 0, once"
        );
        // a grant fills the lowest hole, a new slot grows the region; allocation continues in the newest chunk
        a.lend_add(1, 50 * C);
        a.lend_add(3, 60 * C);
        assert_eq!((a.len(), a.usable_len()), (6 * C, 5 * C));
        let b = a.reserve(16).unwrap();
        assert!(in_slot(60 * C, b), "newest chunk (slot 3) first");
        assert_eq!(a.rel_of(60 * C + 3), 5 * C + 3);
        assert_eq!(a.phys_of(5 * C + 3), 60 * C + 3);
        // drain completely: every free usable block once (slot 1 whole, slot 3 all but 16)
        assert_eq!(a.n_free(), 2 * C - 16);
        let mut n = 0;
        while a.reserve(1).is_some() {
            n += 1;
        }
        assert_eq!((n, a.n_free()), (2 * C - 16, 0));
    }

    /// A full base with frees interleaved (base dirty windows, base cursor kept across borrowed allocations): a request
    /// succeeds exactly when some chunk has a free run of that length, and base runs win over borrowed ones.
    #[cfg(feature = "elastic")]
    #[test]
    fn lent_full_base_matches_brute_force() {
        const C: u64 = 1024;
        let base = [10 * C, 20 * C, 30 * C];
        let mut a = Alloc::with_lent(&base, &[50 * C, HOLE, 70 * C], C);
        let mut rng = Rng::new(5);
        let mut live: Vec<(u64, u32)> = vec![];
        let chunks = [10 * C, 20 * C, 30 * C, 50 * C, 70 * C];
        let fits = |a: &Alloc, want: u64| {
            chunks.iter().any(|&c| {
                let mut run = 0;
                (0..C).any(|i| {
                    run = if a.is_free_rel(a.rel_of(c + i)) {
                        run + 1
                    } else {
                        0
                    };
                    run >= want
                })
            })
        };
        let (mut misses, mut spill) = (0, 0);
        for step in 0..40_000 {
            // fill phase pushes everything to full, then mostly frees one at a time
            let alloc_pct = if (step / 4000) % 2 == 0 { 80 } else { 45 };
            if rng.pct(alloc_pct) || live.is_empty() {
                let hi = if rng.pct(10) { 200 } else { 12 };
                let n = rng.range(1, hi) as u32;
                let want = fits(&a, n as u64);
                let r = a.reserve(n);
                assert_eq!(r.is_some(), want, "step {step}: reserve({n})");
                if let Some(b) = r {
                    if !(10 * C..11 * C).contains(&b)
                        && !(20 * C..21 * C).contains(&b)
                        && !(30 * C..31 * C).contains(&b)
                    {
                        spill += 1;
                    }
                    live.push((b, n));
                } else {
                    misses += 1;
                }
            } else {
                let (b, n) = live.swap_remove(rng.below(live.len() as u64) as usize);
                a.unreserve(b, n);
            }
        }
        assert!(misses > 100 && spill > 100, "{misses} {spill}");
    }

    #[cfg(feature = "elastic")]
    #[test]
    fn chunk_table_translation_and_runs() {
        // 9 chunks of 1024 blocks, non-adjacent and out of order on the device
        let ph: Vec<u64> = vec![
            50_000, 3_000, 20_480, 7_168, 90_112, 1_024, 40_960, 12_288, 60_000,
        ];
        let mut a = Alloc::with_chunks(&ph, 1024);
        assert_eq!(a.len(), 9 * 1024);
        for (i, &p) in ph.iter().enumerate() {
            let r = i as u64 * 1024;
            assert_eq!(a.phys_of(r), p);
            assert_eq!(a.phys_of(r + 1023), p + 1023);
            assert_eq!(a.rel_of(p + 5), r + 5);
            assert!(a.in_region(p, 1024) && !a.in_region(p, 1025) && !a.in_region(p + 1023, 2));
        }
        assert!(!a.in_region(0, 1) && !a.in_region(2_048, 1));
        let mut rng = Rng::new(11);
        let mut live: Vec<(u64, u32)> = vec![];
        for _ in 0..20_000 {
            if rng.pct(55) || live.is_empty() {
                let n = rng.range(1, 300) as u32;
                if let Some(b) = a.reserve(n) {
                    let c = ph
                        .iter()
                        .find(|&&p| b >= p && b < p + 1024)
                        .expect("inside a chunk");
                    assert!(b + n as u64 <= c + 1024, "run crosses a chunk");
                    live.push((b, n));
                }
            } else {
                let (b, n) = live.swap_remove(rng.below(live.len() as u64) as usize);
                a.unreserve(b, n);
            }
        }
        // same behaviour as plain extents of equal sizes: fill completely with single blocks
        for (b, n) in live.drain(..) {
            a.unreserve(b, n);
        }
        let mut n = 0;
        while a.reserve(1).is_some() {
            n += 1;
        }
        assert_eq!(n, 9 * 1024);
    }

    #[test]
    fn extents_never_span_a_gap_and_report_free_runs() {
        // original extent + two expansion extents, gaps between them on the device
        let segs = [(100u64, 1_001u64), (5_000, 500), (9_000, 333)];
        let mut a = Alloc::with_extents(segs[0].0, segs[0].1, &segs[1..]);
        let total: u64 = segs.iter().map(|s| s.1).sum();
        assert_eq!(a.len(), total);
        let inside = |b: u64, n: u64| segs.iter().any(|s| b >= s.0 && b + n <= s.0 + s.1);
        let used = |b: u64| segs.iter().any(|s| b >= s.0 && b < s.0 + s.1);
        let mut rng = Rng::new(7);
        let mut live: Vec<(u64, u32)> = vec![];
        for _ in 0..20_000 {
            if rng.pct(55) || live.is_empty() {
                let n = rng.range(1, 90) as u32;
                let got = if rng.pct(30) {
                    a.reserve_upto(1, n)
                } else {
                    a.reserve(n).map(|b| (b, n))
                };
                if let Some((b, n)) = got {
                    assert!(inside(b, n as u64), "run {b}+{n} crosses a gap");
                    assert!(a.in_region(b, n));
                    assert_eq!(a.phys_of(a.rel_of(b)), b);
                    live.push((b, n));
                }
            } else {
                let (b, n) = live.swap_remove(rng.below(live.len() as u64) as usize);
                a.unreserve(b, n);
            }
        }
        assert!(!a.in_region(1_101, 1), "gap block");
        assert!(!a.in_region(5_499, 2), "run over the end of an extent");
        let mut free = Vec::new();
        a.for_each_free(|b, n| free.push((b, n)));
        let mut model: Vec<u64> = (0..10_000).filter(|&b| used(b)).collect();
        for &(b, n) in &live {
            model.retain(|x| !(b..b + n as u64).contains(x));
        }
        let flat: Vec<u64> = free.iter().flat_map(|&(b, n)| b..b + n).collect();
        assert_eq!(flat, model);
        assert_eq!(a.n_free(), model.len() as u64);
        // maximal runs inside one extent
        for w in free.windows(2) {
            assert!(w[0].0 + w[0].1 < w[1].0, "runs touch: {w:?}");
        }
        // fill the rest, everything is reachable: no capacity hidden behind a gap
        while a.reserve(1).is_some() {}
        assert_eq!(a.n_free(), 0);
    }

    #[test]
    fn random_ops_never_overlap_and_counters_hold() {
        let mut a = Alloc::new(7, 5_003);
        let mut rng = Rng::new(1);
        let mut live: Vec<(u64, u32)> = vec![];
        let mut model = vec![false; 5_003];
        for _ in 0..20_000 {
            if rng.pct(55) || live.is_empty() {
                let n = rng.range(1, 70) as u32;
                if let Some(b) = a.reserve(n) {
                    for i in 0..n as u64 {
                        assert!(!model[(b - 7 + i) as usize], "overlap");
                        model[(b - 7 + i) as usize] = true;
                    }
                    live.push((b, n));
                }
            } else {
                let (b, n) = live.swap_remove(rng.below(live.len() as u64) as usize);
                if rng.pct(50) {
                    a.unreserve(b, n);
                } else {
                    a.apply_alloc(b, n);
                    a.apply_free(b, n);
                    a.release_held(b, n);
                }
                (0..n as u64).for_each(|i| model[(b - 7 + i) as usize] = false);
            }
            assert_eq!(
                a.n_free(),
                5_003 - model.iter().filter(|x| **x).count() as u64
            );
        }
    }

    /// adr 0021 am. 51: the O(1) whole-window counter equals a recount after every op (reserve, dense reserve, fence,
    /// apply, free, release, unreserve; partial last window, padding), and the dense search never misses a hole
    /// (adr 0475 am. 2): whenever `reserve_dense(n)` says no, no partly used window holds a run of `n`.
    #[test]
    fn free_window_counter_and_dense_search_follow_every_op() {
        let n = 50 * WIN + 77;
        let mut a = Alloc::new(3, n);
        let mut rng = Rng::new(47);
        let mut live: Vec<(u64, u32, bool)> = vec![]; // (block, len, applied)
        let recount = |a: &Alloc| {
            (0..a.n_windows())
                .filter(|&w| a.window_busy(w) == 0)
                .count() as u64
        };
        let dense_exists = |a: &Alloc, want: u64| {
            (0..a.n_windows()).any(|w| {
                let b = a.window_busy(w);
                b > 0
                    && b + want <= WIN
                    && brute_scan(a, w as u64 * WIN, ((w as u64 + 1) * WIN).min(a.n), want)
                        .is_some()
            })
        };
        assert_eq!(a.free_windows(), recount(&a));
        let (mut dense_hits, mut dense_miss) = (0, 0);
        for step in 0..30_000 {
            match rng.below(10) {
                0..=3 => {
                    let k = rng.range(1, 300) as u32;
                    if let Some(b) = a.reserve(k) {
                        live.push((b, k, false));
                    }
                }
                4..=5 => {
                    let k = rng.range(1, 20) as u32;
                    match a.reserve_dense(k) {
                        Some(b) => {
                            dense_hits += 1;
                            let w = a.window_of(b).unwrap();
                            assert!(
                                a.window_busy(w) > k as u64,
                                "dense run in a whole free window"
                            );
                            live.push((b, k, false));
                        }
                        None => {
                            dense_miss += 1;
                            assert!(
                                !dense_exists(&a, k as u64),
                                "dense search missed a hole of {k} at step {step}"
                            );
                        }
                    }
                }
                6 if !live.is_empty() => {
                    let i = rng.below(live.len() as u64) as usize;
                    if !live[i].2 {
                        a.apply_alloc(live[i].0, live[i].1);
                        live[i].2 = true;
                    }
                }
                7..=8 if !live.is_empty() => {
                    let (b, k, applied) = live.swap_remove(rng.below(live.len() as u64) as usize);
                    if applied {
                        a.apply_free(b, k);
                        assert_eq!(a.free_windows(), recount(&a));
                        a.release_held(b, k);
                    } else {
                        a.unreserve(b, k);
                    }
                }
                9 => {
                    let w = rng.below(a.n_windows() as u64) as usize;
                    let mut f = vec![];
                    a.fence_window(w, &mut f);
                    assert!(
                        (w as u64 * WIN..((w as u64 + 1) * WIN).min(n)).all(|i| !a.is_free_rel(i)),
                        "fenced window {w} keeps a free block"
                    );
                    for (b, k) in f {
                        live.push((b, k, false));
                    }
                }
                _ => {}
            }
            assert_eq!(a.free_windows(), recount(&a), "step {step}");
            if step % 64 == 0 {
                runs_fresh(&a);
            }
        }
        assert!(
            dense_hits > 100 && dense_miss > 100,
            "{dense_hits} {dense_miss}"
        );
        for (b, k, applied) in live.drain(..) {
            if applied {
                a.apply_free(b, k);
                a.release_held(b, k);
            } else {
                a.unreserve(b, k);
            }
        }
        assert_eq!(a.n_free(), n);
        // the partial last window keeps its padding bits busy
        assert_eq!(a.free_windows(), n / WIN);
    }

    /// Elastic: grant/return (`lend_add`, `lend_remove`, hole marking) keep the whole-window counter exact and the run
    /// tree current (adr 0021 am. 49/51, adr 0475 am. 2): new free windows can hold a dense run, a hole never counts as
    /// free.
    #[cfg(feature = "elastic")]
    #[test]
    fn free_window_counter_and_dense_search_follow_lend_paths() {
        const C: u64 = 1024;
        let mut a = Alloc::with_lent(&[10 * C, 11 * C], &[40 * C, HOLE, 30 * C], C);
        let recount = |a: &Alloc| {
            (0..a.n_windows())
                .filter(|&w| a.window_busy(w) == 0)
                .count() as u64
        };
        assert_eq!(a.free_windows(), recount(&a));
        assert_eq!(a.free_windows(), 4 * C / WIN, "hole windows are not free");
        // a dense miss; a grant (new empty windows, no block freed) must reach the tree
        let b = a.reserve(8).unwrap();
        assert!(a.reserve_dense(300).is_none() && a.reserve_dense(300).is_none());
        a.lend_remove(2);
        assert_eq!(a.free_windows(), recount(&a));
        a.lend_add(1, 50 * C);
        a.lend_add(3, 60 * C);
        assert_eq!(a.free_windows(), recount(&a));
        assert_eq!(a.free_windows(), 5 * C / WIN - 1);
        assert!(a.reserve_dense(8).is_some(), "grant not in the run tree");
        runs_fresh(&a);
        // return after churn
        a.unreserve(b, 8);
        let mut live = vec![];
        while let Some(x) = a.reserve(64) {
            live.push(x);
        }
        assert_eq!(a.free_windows(), recount(&a));
        for x in live.drain(..) {
            a.unreserve(x, 64);
        }
        assert!(a.lend_remove(3) && a.lend_remove(1));
        assert_eq!(a.free_windows(), recount(&a));
        a.lend_add(1, 70 * C);
        assert_eq!(a.free_windows(), recount(&a));
    }
    #[test]
    fn chunk_roundtrip() {
        let mut a = Alloc::new(0, 10_000);
        a.apply_alloc_replay(5, 3);
        a.apply_alloc_replay(4096 + 17, 100);
        let mut buf = [0u8; CHUNK_BYTES];
        assert!(a.chunk_bytes(0, &mut buf));
        let mut b = Alloc::new(0, 10_000);
        b.load_chunk(0, &buf).unwrap();
        assert!(a.chunk_bytes(1, &mut buf));
        b.load_chunk(1, &buf).unwrap();
        assert!(!a.chunk_bytes(2, &mut buf));
        assert_eq!(b.snapshot(), a.snapshot());
        assert_eq!(b.n_alloc(), 103);
        assert_eq!(b.n_free(), 10_000 - 103);
    }

    // ---- busy derived, reserved sparse (adr 0021 am. 24)

    use crate::alloc_dense::DenseAlloc;

    /// The bounded fragmentation walk (adr 0475 am. 1): the first call walks everything, later calls return the last
    /// complete walk until the one in progress ends, a walk sees the changes made before it passed them, and a free run
    /// across a step boundary is joined like the whole walk joins it.
    #[test]
    fn frag_walk_bounded() {
        let nw = FRAG_STEP as u64 * 5 / 2; // a walk = 3 calls
        let mut a = Alloc::new(0, nw * WIN);
        let b = FRAG_STEP as u64 - 2; // free windows b..b+5 straddle the first step boundary
        for w in 0..nw {
            if w < b || w >= b + 5 {
                a.apply_alloc_replay(w * WIN, WIN as u32);
            }
        }
        let f0 = a.frag();
        assert_eq!(f0, a.frag_full());
        assert_eq!(f0, [5 * WIN, 0, 5 * WIN]);
        // two 8-block holes in a full window far behind the boundary, one block more in the free run
        let h = (nw - 10) * WIN;
        a.apply_free(h + 50, 8);
        a.release_held(h + 50, 8);
        a.apply_free(h + 150, 8);
        a.release_held(h + 150, 8);
        a.apply_free((b + 5) * WIN, 1);
        a.release_held((b + 5) * WIN, 1);
        let f1 = a.frag_full();
        assert_eq!(f1, [5 * WIN, 16 + 1, 5 * WIN + 1]);
        assert_eq!(a.frag(), f0);
        assert_eq!(a.frag(), f0);
        assert_eq!(a.frag(), f1);
        // the next walk starts over: no change, same result on every call
        for _ in 0..4 {
            assert_eq!(a.frag(), f1);
        }
    }

    /// Every known window run summary (adr 0475) and tree node (am. 2) equals a recompute from the bits: no change of
    /// the union missed its dirty mark; a dirty node has a dirty parent.
    fn runs_fresh(a: &Alloc) {
        for wi in 0..a.n_windows() {
            let v = a.wruns[wi].get();
            if v != RUNS_DIRTY {
                assert_eq!(v, a.win_runs_calc(wi), "stale run summary of window {wi}");
            }
        }
        // brute summary of windows [w0, w1): window by window, joined unless an extent starts between them
        let brute = |w0: usize, w1: usize| {
            let mut acc: Option<Sum> = None;
            for w in w0..w1 {
                let leaf = match a.win_busy.get(w) {
                    Some(&b) if (b as u64) < WIN => {
                        let v = a.win_runs_calc(w);
                        let (pre, suf, max) = unpack_runs(v);
                        Sum {
                            pre,
                            suf,
                            max,
                            dmax: if b > 0 { max } else { 0 },
                        }
                    }
                    _ => Sum::default(),
                };
                acc = Some(match acc {
                    None => leaf,
                    Some(l) => l.join((w - w0) as u64 * WIN, leaf, WIN, !a.brk(w as u64 * WIN)),
                });
            }
            acc.unwrap()
        };
        for (k, lv) in a.tree.iter().enumerate() {
            let span = FAN.pow(k as u32 + 1);
            for (i, c) in lv.iter().enumerate() {
                let s = c.get();
                if s == DIRTY {
                    if let Some(up) = a.tree.get(k + 1) {
                        assert_eq!(
                            up[i / FAN].get(),
                            DIRTY,
                            "clean parent of dirty node {k}/{i}"
                        );
                    }
                    continue;
                }
                assert_eq!(
                    s,
                    brute(i * span, (i + 1) * span),
                    "stale tree node {k}/{i}"
                );
            }
        }
    }

    /// Lowest start of a run of `want` allocatable blocks inside `[from, to)` from the bits alone (holes and full windows
    /// busy, no run across an extent start): the oracle of `scan`.
    fn brute_scan(a: &Alloc, from: u64, to: u64, want: u64) -> Option<u64> {
        let free = |i: u64| a.window_busy((i / WIN) as usize) < WIN && a.is_free_rel(i);
        let mut p = from;
        while p + want <= to {
            match (p..p + want).find(|&i| !free(i) || (i > p && a.brk(i))) {
                None => return Some(p),
                Some(i) => p = if free(i) { i } else { i + 1 },
            }
        }
        None
    }

    /// Longest allocatable run from the bits alone (same rules as `brute_scan`): the oracle of `longest_run`.
    fn brute_longest(a: &Alloc) -> u64 {
        let free = |i: u64| a.window_busy((i / WIN) as usize) < WIN && a.is_free_rel(i);
        let (mut best, mut cur) = (0, 0);
        for i in 0..a.n {
            cur = match (free(i), a.brk(i)) {
                (false, _) => 0,
                (true, true) => 1,
                (true, false) => cur + 1,
            };
            best = best.max(cur);
        }
        best
    }

    /// Random ops on `a` (reserve short and long runs, dense reserve, apply, free + release, unreserve; `lend` adds
    /// grants and returns of borrowed slots), checking after each batch that `scan` equals `brute_scan` for random ranges
    /// and lengths, the dense search finds the first partly used window with a run, every clean tree node is current, the
    /// root names the longest run and `reserve_cut` takes `want` or that run whole (adr 0475 am. 3).
    #[cfg_attr(not(feature = "elastic"), allow(unused_variables))]
    fn tree_exercise(a: &mut Alloc, seed: u64, steps: usize, lend: bool) {
        let mut rng = Rng::new(seed);
        let mut live: Vec<(u64, u32, bool)> = vec![];
        let (mut hits, mut misses, mut cuts) = (0u64, 0u64, 0u64);
        #[cfg(feature = "elastic")]
        let mut next_phys = 1u64 << 40;
        for step in 0..steps {
            match rng.below(20) {
                0..=8 => {
                    let k = if rng.pct(10) {
                        rng.range(200, 3000)
                    } else {
                        rng.range(1, 64)
                    } as u32;
                    if let Some(b) = a.reserve(k) {
                        live.push((b, k, false));
                    }
                }
                9..=10 => {
                    let k = rng.range(1, 40) as u32;
                    if let Some(b) = a.reserve_dense(k) {
                        live.push((b, k, false));
                    }
                }
                11..=12 if !live.is_empty() => {
                    let i = rng.below(live.len() as u64) as usize;
                    if !live[i].2 {
                        a.apply_alloc(live[i].0, live[i].1);
                        live[i].2 = true;
                    }
                }
                13..=17 if !live.is_empty() => {
                    let (b, k, applied) = live.swap_remove(rng.below(live.len() as u64) as usize);
                    if applied {
                        a.apply_free(b, k);
                        a.release_held(b, k);
                    } else {
                        a.unreserve(b, k);
                    }
                }
                #[cfg(feature = "elastic")]
                18 if lend && rng.pct(15) => {
                    // fill a hole or append a slot (the region grows: new windows and tree nodes)
                    let k = (0..a.lent_slots())
                        .find(|&k| a.lent_slot(k).0 == HOLE)
                        .unwrap_or(a.lent_slots());
                    a.lend_add(k, next_phys);
                    next_phys += 1 << a.ck_shift;
                }
                #[cfg(feature = "elastic")]
                19 if lend && a.lent_slots() > 0 => {
                    let k = rng.below(a.lent_slots() as u64) as usize;
                    if a.lent_slot(k).0 != HOLE {
                        a.lend_remove(k);
                    }
                }
                _ => {}
            }
            if step % 50 != 0 {
                continue;
            }
            runs_fresh(a);
            for _ in 0..8 {
                let from = rng.below(a.n);
                let to = rng.range(from + 1, a.n);
                let want = match rng.below(3) {
                    0 => rng.range(1, 32),
                    1 => rng.range(32, 600),
                    _ => rng.range(600, 6000),
                };
                let r = a.scan(from, to, want);
                assert_eq!(
                    r,
                    brute_scan(a, from, to, want),
                    "step {step}: scan({from}, {to}, {want})"
                );
                if r.is_some() {
                    hits += 1;
                } else {
                    misses += 1;
                }
                // dense search over windows [lo, hi): the first partly used window holding a run
                let nw = a.n_windows();
                let lo = rng.below(nw as u64) as usize;
                let hi = rng.range(lo as u64 + 1, nw as u64) as usize;
                let dw = (want % 40).max(1);
                let exp = (lo..hi).find(|&w| {
                    a.window_busy(w) > 0
                        && brute_scan(a, w as u64 * WIN, ((w as u64 + 1) * WIN).min(a.n), dw)
                            .is_some()
                });
                assert_eq!(
                    a.dense_seek(a.tree.len(), 0, lo, hi, dw),
                    exp,
                    "step {step}: dense {lo}..{hi} want {dw}"
                );
            }
            runs_fresh(a);
            let longest = brute_longest(a);
            assert_eq!(a.longest_run(), longest, "step {step}: longest run");
            let want = rng.range(1, 2 * longest + 2) as u32;
            match a.reserve_cut(want) {
                Some((b, got)) => {
                    assert_eq!(
                        got as u64,
                        longest.min(want as u64),
                        "step {step}: cut of {want}"
                    );
                    assert!(a.is_reserved(b, got), "step {step}: cut run reserved");
                    cuts += u64::from(got < want);
                    live.push((b, got, false));
                }
                None => assert_eq!(longest, 0, "step {step}: no run with free blocks"),
            }
            runs_fresh(a);
        }
        assert!(hits > 100 && misses > 100, "{hits} {misses}");
        assert!(cuts > 10, "{cuts} cut runs");
    }

    /// The run-summary tree (adr 0475 am. 2) on plain extents: two device-expand extents start inside windows (runs
    /// split there), the last window is partial, the tree has 3 levels.
    #[test]
    fn tree_scan_matches_brute_force() {
        let mut a = Alloc::with_extents(7, 40_037, &[(1_000_000, 20_011), (2_000_000, 16_700)]);
        assert!(a.tree.len() >= 2 && !a.n.is_multiple_of(WIN));
        tree_exercise(&mut a, 3, 6000, false);
    }

    /// Same on a chunk table with holes, grants (growth past a tree level) and returns.
    #[cfg(feature = "elastic")]
    #[test]
    fn tree_scan_matches_brute_force_lent() {
        const C: u64 = 1024;
        let base: Vec<u64> = (0..40).map(|i| (3 * i + 1) * C).collect();
        let lent: Vec<u64> = (0..20)
            .map(|i| if i % 5 == 2 { HOLE } else { (500 + 2 * i) * C })
            .collect();
        let mut a = Alloc::with_lent(&base, &lent, C);
        let levels = a.tree.len();
        // a grant right after a read that cleaned every node: the nodes that gain windows must turn dirty
        a.sum(a.tree.len(), 0);
        a.lend_add(a.lent_slots(), 1 << 39);
        runs_fresh(&a);
        tree_exercise(&mut a, 9, 8000, true);
        assert!(a.tree.len() > levels, "growth added a level");
    }

    /// Same observable state: counters, free-run report, durable bitmap, chunk images.
    fn same(a: &Alloc, d: &DenseAlloc, full: bool) {
        assert_eq!(a.n_alloc(), d.n_alloc());
        assert_eq!(a.n_reserved(), d.n_reserved());
        assert_eq!(a.n_held(), d.n_held());
        assert_eq!(a.n_free(), d.n_free());
        runs_fresh(a);
        if !full {
            return;
        }
        assert_eq!(a.snapshot(), d.snapshot());
        let (mut x, mut y) = (vec![], vec![]);
        a.for_each_free(|b, n| x.push((b, n)));
        d.for_each_free(|b, n| y.push((b, n)));
        assert_eq!(x, y);
        let f = a.frag_full();
        // a free window holding an extent start is no whole free run
        let split = (0..a.n_windows())
            .filter(|&w| {
                a.window_busy(w) == 0
                    && a.cut_after(w as u64 * WIN, (w as u64 + 1) * WIN) < (w as u64 + 1) * WIN
            })
            .count() as u64;
        assert_eq!(f[0], (a.free_windows() - split) * WIN);
        assert_eq!(f[2], x.iter().map(|r| r.1).max().unwrap_or(0));
        let (mut bx, mut by) = ([0u8; CHUNK_BYTES], [0u8; CHUNK_BYTES]);
        for ci in 0..a.n_chunks() {
            assert_eq!(a.chunk_bytes(ci, &mut bx), d.chunk_bytes(ci, &mut by));
            assert_eq!(bx, by);
        }
        for w in 0..a.n_words() {
            assert_eq!(a.alloc_word(w), d.alloc_words()[w]);
        }
    }

    /// Random op sequences (reserve, reserve_upto, unreserve, apply_alloc, apply_free, release_held, replay,
    /// chunk reload, pool maintenance) against the dense implementation: identical results at every step.
    type Runs = Vec<(u64, u32)>;

    fn equiv_run(seed: u64, segs: &[(u64, u64)], ops: usize, pool: usize) -> u64 {
        let mut fails = 0;
        let mut a = Alloc::with_extents(segs[0].0, segs[0].1, &segs[1..]);
        let mut d = DenseAlloc::with_extents(segs[0].0, segs[0].1, &segs[1..]);
        a.set_pool_target(pool);
        let mut rng = Rng::new(seed);
        let (mut res, mut live, mut held): (Runs, Runs, Runs) = (vec![], vec![], vec![]);
        for step in 0..ops {
            let maxn = if rng.pct(5) { 9000 } else { 80 };
            match rng.below(9) {
                0..=2 => {
                    let n = rng.range(1, maxn) as u32;
                    let (x, y) = (a.reserve(n), d.reserve(n));
                    assert_eq!(x, y, "reserve {n} at step {step}");
                    match x {
                        Some(b) => res.push((b, n)),
                        None => fails += 1,
                    }
                }
                3 => {
                    let (lo, hi) = (rng.range(1, 20) as u32, rng.range(20, maxn) as u32);
                    let (x, y) = (a.reserve_upto(lo, hi), d.reserve_upto(lo, hi));
                    assert_eq!(x, y, "reserve_upto at step {step}");
                    if let Some((b, n)) = x {
                        res.push((b, n));
                    }
                }
                4 if !res.is_empty() => {
                    let (b, n) = res.swap_remove(rng.below(res.len() as u64) as usize);
                    a.unreserve(b, n);
                    d.unreserve(b, n);
                }
                5 if !res.is_empty() => {
                    let (b, n) = res.swap_remove(rng.below(res.len() as u64) as usize);
                    a.apply_alloc(b, n);
                    d.apply_alloc(b, n);
                    live.push((b, n));
                }
                6 if !live.is_empty() => {
                    // free a part (or all) of a live run
                    let i = rng.below(live.len() as u64) as usize;
                    let (b, n) = live[i];
                    let k = rng.range(1, n as u64) as u32;
                    let off = rng.below((n - k) as u64 + 1) as u32;
                    live.swap_remove(i);
                    if off > 0 {
                        live.push((b, off));
                    }
                    if off + k < n {
                        live.push((b + (off + k) as u64, n - off - k));
                    }
                    a.apply_free(b + off as u64, k);
                    d.apply_free(b + off as u64, k);
                    held.push((b + off as u64, k));
                }
                7 if !held.is_empty() => {
                    let (b, n) = held.swap_remove(rng.below(held.len() as u64) as usize);
                    a.release_held(b, n);
                    d.release_held(b, n);
                }
                _ => {
                    if rng.pct(30) {
                        a.maintain();
                    }
                }
            }
            if let Some(&(b, n)) = res.last() {
                assert!(a.is_reserved(b, n) && d.is_reserved(b, n));
                assert!(!a.is_allocated(b, n) && !d.is_allocated(b, n));
            }
            if let Some(&(b, n)) = held.last() {
                assert_eq!(a.is_held(b, n), d.is_held(b, n));
                assert!(a.is_unallocated(b, n) || !d.is_unallocated(b, n));
            }
            if let Some(&(b, n)) = live.last() {
                assert!(a.is_allocated(b, n) && d.is_allocated(b, n));
            }
            same(&a, &d, step % 997 == 0);
        }
        same(&a, &d, true);
        // reload through the persistent chunk form (mount) and replay on an untouched region
        let mut a2 = Alloc::with_extents(segs[0].0, segs[0].1, &segs[1..]);
        let mut buf = [0u8; CHUNK_BYTES];
        for ci in 0..a.n_chunks() {
            if a.chunk_bytes(ci, &mut buf) {
                a2.load_chunk(ci, &buf).unwrap();
            }
        }
        assert_eq!(a2.snapshot(), a.snapshot());
        assert_eq!(a2.n_alloc(), a.n_alloc());
        // drain everything: every reserved chunk goes back to the pool
        for (b, n) in res.drain(..) {
            a.unreserve(b, n);
        }
        for (b, n) in live.drain(..) {
            a.apply_free(b, n);
            held.push((b, n));
        }
        for (b, n) in held.drain(..) {
            a.release_held(b, n);
        }
        assert_eq!(a.live_chunks(), 0);
        assert_eq!((a.n_alloc(), a.n_reserved(), a.n_held()), (0, 0, 0));
        assert_eq!(a.n_free(), a.len());
        // an empty region scans like a fresh one: one reserve of everything
        let all = a.len().min(u32::MAX as u64) as u32;
        if a.segs.len() == 1 {
            assert!(a.reserve(all).is_some());
        }
        fails
    }

    /// `reserve_upto` and `fence_window` as they extended a run block by block (`is_free_rel` per block): the
    /// word-wise extension gives the same runs and leaves the same state, on scattered free space with runs crossing
    /// words and segment ends.
    #[test]
    fn run_extension_equals_bit_by_bit() {
        fn upto_ref(a: &mut Alloc, min: u32, max: u32) -> Option<(u64, u32)> {
            let r = a.find(min as u64)?;
            let mut len = min as u64;
            let lim = a.seg_end(r);
            while len < max as u64 && r + len < lim && a.is_free_rel(r + len) {
                len += 1;
            }
            a.take_free(r, len);
            a.cursor = (r + len) % a.n;
            Some((a.phys_of(r), len as u32))
        }
        fn fence_ref(a: &mut Alloc, w: usize, out: &mut Vec<(u64, u32)>) {
            let (s, b) = (w as u64 * WIN, ((w as u64 + 1) * WIN).min(a.n));
            let mut i = s;
            while i < b {
                if !a.is_free_rel(i) {
                    i += 1;
                    continue;
                }
                let lim = b.min(a.seg_end(i));
                let mut e = i + 1;
                while e < lim && a.is_free_rel(e) {
                    e += 1;
                }
                a.take_free(i, e - i);
                out.push((a.phys_of(i), (e - i) as u32));
                i = e;
            }
        }
        for seed in 0..20u64 {
            let mut rng = Rng::new(seed);
            // three segments, ends off word and window boundaries
            let mut a =
                Alloc::with_extents(1000, 3 * WIN + 37, &[(50_000, 2 * WIN + 5), (90_000, 700)]);
            let n = a.len();
            for _ in 0..rng.below(400) {
                let len = 1 + rng.below(40) as u32;
                if let Some(b) = a.reserve(len) {
                    a.apply_alloc(b, len);
                }
            }
            // free scattered runs
            for _ in 0..300 {
                let r = rng.below(n);
                let len = (1 + rng.below(90)).min(a.seg_end(r) - r) as u32;
                let b = a.phys_of(r);
                if a.is_allocated(b, len) {
                    a.apply_free(b, len);
                    a.release_held(b, len);
                }
            }
            let mut d = a.clone();
            for step in 0..300 {
                if rng.below(4) == 0 {
                    let w = rng.below(a.n_windows() as u64) as usize;
                    let (mut x, mut y) = (Vec::new(), Vec::new());
                    a.fence_window(w, &mut x);
                    fence_ref(&mut d, w, &mut y);
                    assert_eq!(x, y, "seed {seed} step {step}: fence_window");
                    for (b, n) in x {
                        a.unreserve(b, n);
                        d.unreserve(b, n);
                    }
                } else {
                    let min = 1 + rng.below(8) as u32;
                    let max = min + rng.below(300) as u32;
                    let (x, y) = (a.reserve_upto(min, max), upto_ref(&mut d, min, max));
                    assert_eq!(x, y, "seed {seed} step {step}: reserve_upto({min}, {max})");
                    if let Some((b, n)) = x
                        && rng.below(3) == 0
                    {
                        a.unreserve(b, n);
                        d.unreserve(b, n);
                    }
                }
                assert_eq!(a.cursor, d.cursor);
                assert_eq!(a.n_free(), d.n_free());
            }
            assert_eq!(a.snapshot(), d.snapshot(), "seed {seed}: final state");
        }
    }

    /// Cost of extending a found run to `max` blocks (`reserve_upto`: the OLSM lease and meta cell growth) and of
    /// fencing a window. Measurement: `cargo test --release -p store --lib alloc::tests::run_extension_cost -- --ignored
    /// --nocapture`.
    #[test]
    #[ignore = "measurement"]
    fn run_extension_cost() {
        let n = 1u64 << 24;
        for max in [64u32, 256, 1024] {
            let mut a = Alloc::new(0, n);
            let mut best = f64::MAX;
            for _ in 0..5 {
                let t = std::time::Instant::now();
                for _ in 0..20_000 {
                    let (b, l) = a.reserve_upto(1, max).unwrap();
                    a.unreserve(b, l);
                }
                best = best.min(t.elapsed().as_nanos() as f64 / 20_000.0);
            }
            eprintln!(
                "run_extension_cost: reserve_upto(1, {max}) + unreserve on free space: {best:.0} ns"
            );
        }
        let mut a = Alloc::new(0, n);
        let mut best = f64::MAX;
        for _ in 0..5 {
            let t = std::time::Instant::now();
            let mut out = Vec::with_capacity(4);
            for w in 0..20_000 {
                out.clear();
                a.fence_window(w, &mut out);
                for &(b, l) in &out {
                    a.unreserve(b, l);
                }
            }
            best = best.min(t.elapsed().as_nanos() as f64 / 20_000.0);
        }
        eprintln!("run_extension_cost: fence_window + unreserve of a free window: {best:.0} ns");
    }

    #[test]
    fn sparse_equals_dense_random_ops() {
        for (seed, pool) in [(1, 0), (2, 4), (3, 256)] {
            equiv_run(seed, &[(1000, 70_001)], 6_000, pool);
        }
        // several extents with gaps, runs crossing chunk edges
        equiv_run(
            9,
            &[(100, 20_001), (50_000, 8_192), (90_000, 4_097)],
            6_000,
            8,
        );
        // tiny region (less than one chunk, padding bits)
        equiv_run(10, &[(7, 1_003)], 3_000, 2);
        // mostly full: failing finds (the failed-run cache) interleaved with frees, two extents
        assert!(equiv_run(11, &[(0, 9_001), (20_000, 3_000)], 20_000, 4) > 500);
        assert!(equiv_run(12, &[(64, 4_096)], 20_000, 1) > 500);
    }

    #[test]
    fn sparse_chunk_load_rejects_bits_beyond_region() {
        let mut a = Alloc::new(0, 4096 + 10);
        let mut buf = [0u8; CHUNK_BYTES];
        buf[0] = 0xff;
        buf[1] = 0x04; // bit 10 of chunk 1: block 4106, outside the region
        assert_eq!(a.load_chunk(1, &buf), Err("bitmap bits beyond region"));
        buf[0] = 0xff;
        buf[1] = 0x03; // 10 bits valid
        a.load_chunk(1, &buf).unwrap();
        assert_eq!(a.n_alloc(), 10);
        assert_eq!(a.n_free(), 4096);
        assert!(a.load_chunk(2, &buf).is_err());
        // a reload is delta-correct (counters follow the difference, not the sum)
        a.load_chunk(1, &buf).unwrap();
        assert_eq!((a.n_alloc(), a.n_free()), (10, 4096));
        buf[0] = 0x01;
        buf[1] = 0;
        a.load_chunk(1, &buf).unwrap();
        assert_eq!((a.n_alloc(), a.n_free()), (1, 4105));
        assert!(a.is_allocated(4096, 1) && a.is_unallocated(4097, 9));
    }

    /// No heap use in steady state: with a topped-up pool, set/clear of scattered blocks (chunks come and go)
    /// never misses the pool.
    #[test]
    fn sparse_steady_state_takes_chunks_from_the_pool() {
        let mut a = Alloc::new(0, 1 << 20);
        let mut rng = Rng::new(5);
        for _ in 0..200 {
            let mut v = vec![];
            for _ in 0..32 {
                if let Some(b) = a.reserve(1 + rng.below(3) as u32) {
                    v.push(b);
                }
            }
            a.maintain();
            for b in v {
                a.apply_alloc(b, 1);
                a.apply_free(b, 1);
            }
            a.maintain();
            let mut w = vec![];
            while let Some(b) = a.reserve(1) {
                w.push(b);
                if w.len() > 64 {
                    break;
                }
            }
            for b in w {
                a.unreserve(b, 1);
            }
            a.maintain();
        }
        assert_eq!(a.pool_misses(), 0);
        // no pool at all: every first set of a chunk is a miss, results stay correct
        let mut b = Alloc::new(0, 1 << 16);
        b.set_pool_target(0);
        b.reserve(10).unwrap();
        assert_eq!(b.pool_misses(), 1);
        assert_eq!(b.n_reserved(), 10);
    }

    /// RAM of a simulated 8 TB device (2^31 blocks): two dense layers (2 x 256 MiB) + tables and windows (~22 MiB) + window
    /// run summaries (32 MiB, adr 0475), about half of the old 4 bits per block; reservations around the cursor add a
    /// few chunks.
    #[test]
    fn memory_of_an_8tb_device() {
        let n = 8u64 << 40 >> 12;
        let mut a = Alloc::new(0, n);
        let empty = a.mem_bytes();
        let dense = 4 * n / 8;
        eprintln!("8 TB: empty {empty} B, dense was {dense} B");
        assert!(empty >= n / 4 && empty < dense * 58 / 100, "empty {empty}");
        // reserves near the cursor: few chunks
        let mut rng = Rng::new(3);
        let mut runs = vec![];
        for _ in 0..50_000 {
            if let Some(b) = a.reserve(1 + rng.below(8) as u32) {
                runs.push(b);
            }
            a.maintain();
        }
        assert_eq!(a.pool_misses(), 0);
        let used = a.mem_bytes();
        eprintln!("8 TB: 50k scattered reserves {used} B");
        assert!(a.live_chunks() <= a.n_reserved() / CHUNK_BLOCKS + 1);
        assert!(used < dense * 58 / 100);
        // functional at the far end
        let last = a.len() - 1;
        a.set(L_ALLOC, last, 1, true);
        assert!(a.is_allocated(a.phys_of(last), 1));
    }

    /// A 64 KiB append stream on a 2.5 TB shard (~2.4M windows, customer drive / 6 shards): at every 1 MiB boundary
    /// `reserve_dense` finds no partly used window with room and must answer in O(set bits + windows / 4096), not by
    /// stepping over every window of the region (qd1 tail, doc/perf/qd1-tail-20261031.md). The median of the failing
    /// calls stays far below the ~ms of a full walk; the allocator state is RAM only (no format involved).
    #[test]
    fn dense_miss_on_huge_empty_shard_is_not_a_region_walk() {
        let n = 2_500_000_000_000u64 / 4096;
        let mut a = Alloc::new(0, n);
        let mut misses = vec![];
        for _ in 0..64 * 16 {
            let t = std::time::Instant::now();
            let got = a.reserve_dense(16);
            let dt = t.elapsed();
            let b = match got {
                Some(b) => b,
                None => {
                    misses.push(dt);
                    a.reserve(16).expect("space")
                }
            };
            a.apply_alloc(b, 16);
        }
        assert_eq!(misses.len(), 64, "one miss per 1 MiB window");
        misses.sort();
        assert!(
            misses[32] < std::time::Duration::from_micros(500),
            "median dense miss {:?} on {} windows",
            misses[32],
            a.n_windows()
        );
    }

    #[test]
    fn meta_cells_first_fit_lookup_and_release() {
        let mut m = MetaAlloc::new_elastic(70, 64);
        assert_eq!(m.len(), 70);
        let base: Vec<u32> = (0..70).map(|_| m.alloc().unwrap()).collect();
        assert_eq!(base, (0..70).collect::<Vec<_>>());
        assert!(m.alloc().is_none());
        // two cells, out of address order
        m.add_cell(5000);
        m.add_cell(1000);
        assert_eq!((m.len(), m.free(), m.n_cells()), (70 + 128, 128, 2));
        // first fit by SLOT index (insertion order), pages of a cell ascending
        let i0 = m.alloc().unwrap();
        assert_eq!(i0, 70);
        assert_eq!(m.cell_page_addr(i0, 2), 5000);
        assert_eq!(m.cell_page_idx(5000 + 2 * 3, 2), Some(70 + 3));
        assert_eq!(m.cell_page_idx(5000 + 3, 2), None, "not page aligned");
        assert_eq!(m.cell_page_idx(5000 + 2 * 64, 2), None, "past the cell");
        assert_eq!(m.cell_page_idx(999, 2), None);
        assert_eq!(m.cell_page_idx(1000 + 2 * 63, 2), Some(70 + 64 + 63));
        for _ in 1..64 {
            m.alloc().unwrap();
        }
        assert_eq!(
            m.alloc(),
            Some(70 + 64),
            "slot 0 full: next page is in slot 1"
        );
        assert_eq!(m.cell_page_addr(70 + 64, 2), 1000);
        assert_eq!(m.empty_cells(), Vec::<u64>::new());
        // free every page of the second cell: it can be removed, its slot is reused
        m.clear(70 + 64);
        assert_eq!(m.empty_cells(), vec![1000]);
        let g = m.layout_gen();
        m.remove_cell(1000);
        assert!(m.layout_gen() > g);
        assert_eq!((m.len(), m.n_cells()), (70 + 64, 1));
        assert_eq!(m.used(), 70 + 64);
        assert_eq!(m.cell_page_idx(1000, 2), None);
        m.add_cell(9000);
        assert_eq!(m.alloc(), Some(70 + 64), "vacant slot reused");
        assert_eq!(m.cell_page_addr(70 + 64, 2), 9000);
        // a freed low page is found again before higher ones
        m.clear(3);
        assert_eq!(m.alloc(), Some(3));
    }

    #[test]
    fn fragmented_meta_cell_mapping_roundtrip_clear_and_slot_reuse() {
        let mut m = MetaAlloc::new_elastic(64, 64);
        let extents = vec![
            MetaExtent {
                start: 9000,
                pages: 16,
            },
            MetaExtent {
                start: 1000,
                pages: 8,
            },
            MetaExtent {
                start: 5000,
                pages: 40,
            },
        ];
        assert_eq!(m.add_cell_extents(extents.clone()), 0);
        m.add_cell(12000);
        assert_eq!(
            m.cell_extents(9000, 2),
            vec![(9000, 32), (1000, 16), (5000, 80)]
        );
        assert_eq!(
            m.physical_extents(2),
            vec![(1000, 16), (5000, 80), (9000, 32), (12000, 128)]
        );
        for k in 0..64 {
            let addr = match k {
                0..16 => 9000 + k * 2,
                16..24 => 1000 + (k - 16) * 2,
                _ => 5000 + (k - 24) * 2,
            };
            assert_eq!(m.cell_page_addr(64 + k, 2), u64::from(addr));
            assert_eq!(m.cell_page_idx(u64::from(addr), 2), Some(64 + k));
            assert_eq!(m.cell_page_idx(u64::from(addr) + 1, 2), None);
            m.set(64 + k);
        }
        assert_eq!(
            m.cell_page_idx(1016, 2),
            None,
            "physical hole is not part of the logical cell"
        );
        let blob = m.blob_encode(&[64 + 16, 64 + 63]);
        assert_eq!(blob.len(), m.blob_len());
        let mut decoded = MetaAlloc::blob_decode(&blob, 64).unwrap();
        assert_eq!(decoded.cell_extents(9000, 2), m.cell_extents(9000, 2));
        assert_eq!(decoded.cell_list(), vec![(9000, 62), (12000, 0)]);
        for k in 0..64 {
            assert_eq!(decoded.get(64 + k), ![16, 63].contains(&k));
            assert_eq!(
                decoded.cell_page_addr(64 + k, 2),
                m.cell_page_addr(64 + k, 2)
            );
            decoded.clear(64 + k);
        }
        decoded.remove_cell(9000);
        assert_eq!(decoded.cell_page_idx(1000, 2), None);
        assert_eq!(decoded.cell_page_idx(5000, 2), None);
        assert_eq!(decoded.cell_page_idx(9000, 2), None);
        let vacant = decoded.blob_encode(&[]);
        decoded = MetaAlloc::blob_decode(&vacant, 64).unwrap();
        assert_eq!(
            decoded.add_cell_extents(extents),
            0,
            "reuse a vacant logical slot"
        );
        assert_eq!(decoded.cell_page_idx(5000, 2), Some(88));
        assert_eq!(
            decoded.cell_page_idx(12000, 2),
            Some(128),
            "other logical indices stay stable"
        );
    }

    #[test]
    fn fragmented_meta_extent_validation_uses_actual_page_geometry() {
        let mut m = MetaAlloc::new_elastic(64, 64);
        m.add_cell_extents(vec![
            MetaExtent {
                start: 100,
                pages: 32,
            },
            MetaExtent {
                start: 140,
                pages: 32,
            },
        ]);
        assert!(m.validate_extents(1).is_ok());
        assert_eq!(m.validate_extents(2), Err("meta extent overlap"));
        assert_eq!(m.validate_extents(0), Err("meta extent page geometry"));
        assert_eq!(m.validate_extents(3), Err("meta extent page geometry"));
        m.extent_order = vec![(100, 0, 0, u32::MAX)];
        assert_eq!(m.validate_extents(8), Err("meta extent length"));
        m.extent_order = vec![(u64::MAX - 5, 0, 0, 4)];
        assert_eq!(m.validate_extents(2), Err("meta extent address overflow"));
    }

    #[test]
    fn fragmented_meta_image_rejects_invalid_extent_maps_and_reads_mbl2() {
        let mut m = MetaAlloc::new_elastic(64, 64);
        m.add_cell_extents(vec![
            MetaExtent {
                start: 9000,
                pages: 32,
            },
            MetaExtent {
                start: 1000,
                pages: 32,
            },
        ]);
        let blob = m.blob_encode(&[]);
        let slot = BLOB_HDR + 8;
        for cut in 0..blob.len() {
            assert!(
                MetaAlloc::blob_decode(&blob[..cut], 64).is_err(),
                "truncated at {cut}"
            );
        }
        for (offset, bytes) in [
            (slot, u32::MAX.to_le_bytes().to_vec()),
            (slot + 12, 0u32.to_le_bytes().to_vec()),
            (slot + 12, 33u32.to_le_bytes().to_vec()),
            (slot + 4, 0u64.to_le_bytes().to_vec()),
            (slot + 4, u64::MAX.to_le_bytes().to_vec()),
            (slot + 16, 9000u64.to_le_bytes().to_vec()),
            (slot + 16, 9010u64.to_le_bytes().to_vec()),
        ] {
            let mut bad = blob.clone();
            bad[offset..offset + bytes.len()].copy_from_slice(&bytes);
            assert!(
                MetaAlloc::blob_decode(&bad, 64).is_err(),
                "bad extent at {offset}"
            );
        }
        let mut legacy = Vec::new();
        for field in [BLOB_MAGIC, 64, 64, 1, 1] {
            legacy.extend_from_slice(&field.to_le_bytes());
        }
        legacy.extend_from_slice(&0u64.to_le_bytes()); // base bitmap
        legacy.extend_from_slice(&1000u64.to_le_bytes());
        legacy.extend_from_slice(&1u64.to_le_bytes()); // cell bitmap
        let decoded = MetaAlloc::blob_decode(&legacy, 64).unwrap();
        assert_eq!(decoded.cell_page_addr(64, 2), 1000);
        assert_eq!(decoded.cell_page_idx(1000 + 126, 2), Some(127));
        assert!(decoded.get(64));
        assert_eq!(decoded.cell_extents(1000, 2), vec![(1000, 128)]);
        let upgraded = decoded.blob_encode(&[]);
        assert_eq!(denc::le::rd_u32(&upgraded, 0), BLOB_EXTENTS_MAGIC);
        assert_eq!(
            MetaAlloc::blob_decode(&upgraded, 64).unwrap().cell_list(),
            decoded.cell_list()
        );
    }

    #[test]
    fn meta_image_roundtrip_corruption_and_packing() {
        let mut m = MetaAlloc::new_elastic(100, 64);
        for _ in 0..100 {
            m.alloc().unwrap();
        }
        for a in [4000u64, 100, 2000, 8000] {
            m.add_cell(a);
        }
        for _ in 0..150 {
            m.alloc().unwrap();
        }
        m.clear(100 + 70);
        m.remove_cell(8000);
        let clear = [3u32, 100 + 5];
        let blob = m.blob_encode(&clear);
        assert_eq!(blob.len(), m.blob_len());
        let d = MetaAlloc::blob_decode(&blob, 100).unwrap();
        assert_eq!((d.len(), d.n_cells(), d.ppc()), (m.len(), m.n_cells(), 64));
        assert_eq!(d.used(), m.used() - 2);
        assert_eq!(
            d.cell_list().iter().map(|c| c.0).collect::<Vec<_>>(),
            vec![100, 2000, 4000]
        );
        for i in 0..d.len() {
            assert_eq!(d.get(i), m.get(i) && !clear.contains(&i), "page {i}");
        }
        // every single-bit corruption of the structure is caught or yields a consistent allocator
        assert!(MetaAlloc::blob_decode(&blob[..blob.len() - 1], 100).is_err());
        assert!(MetaAlloc::blob_decode(&blob, 99).is_err());
        let mut bad = blob.clone();
        bad[16] ^= 1; // used counter
        assert!(MetaAlloc::blob_decode(&bad, 100).is_err());
        // packed into pages of several sizes, reassembled
        for psz in [4096usize, 8192, 16384] {
            let payload = (0..3 * psz + 77)
                .map(|i| (i * 7) as u8)
                .collect::<Vec<u8>>();
            let k = blob_pages(payload.len(), psz);
            assert!(k >= 4);
            let addrs: Vec<u64> = (0..k as u64).map(|i| 100 + 10 * i).collect();
            let (img, c0) = blob_pack(&payload, psz, &addrs, 3, 77);
            assert_eq!(img.len(), k * psz);
            let (hk, hlen, refs) = blob_head(&img[..psz], psz, addrs[0]).unwrap();
            assert_eq!((hk, hlen, refs.len()), (k, payload.len(), k - 1));
            assert_eq!(crate::page::stored_crc(&img[..psz]), c0);
            let rest: Vec<Vec<u8>> = (1..k)
                .map(|p| img[p * psz..(p + 1) * psz].to_vec())
                .collect();
            assert_eq!(refs[0].0, addrs[1]);
            assert_eq!(
                blob_unpack(&img[..psz], &rest, &refs, hlen, psz).unwrap(),
                payload
            );
            // misdirected / flipped continuation page
            assert!(blob_head(&img[..psz], psz, addrs[0] + 1).is_err());
            let mut rest2 = rest.clone();
            rest2[0][100] ^= 1;
            assert!(blob_unpack(&img[..psz], &rest2, &refs, hlen, psz).is_err());
            assert!(blob_max_len(psz) > 1 << 20);
        }
        assert_eq!(blob_pages(1, 4096), 1);
        assert_eq!(blob_pages(4096 - 40 - 8, 4096), 1);
        assert_eq!(blob_pages(4096 - 40 - 7, 4096), 2);
    }

    #[test]
    fn meta_alloc_next_fit_and_roundtrip() {
        let mut m = MetaAlloc::new(130);
        let got: Vec<u32> = (0..130).map(|_| m.alloc().unwrap()).collect();
        assert_eq!(got, (0..130).collect::<Vec<_>>());
        assert!(m.alloc().is_none());
        m.clear(5);
        m.clear(100);
        assert_eq!(m.alloc(), Some(5));
        assert_eq!(m.alloc(), Some(100));
        let bytes = m.encode(MetaAlloc::bytes_needed(130), None);
        let m2 = MetaAlloc::decode(&bytes, 130).unwrap();
        assert_eq!(m2.used(), 130);
        let mut bad = bytes.clone();
        bad[20] ^= 1;
        assert!(MetaAlloc::decode(&bad, 130).is_err());
    }
}

// Measurements (ignored tests, `--release --ignored --nocapture`), kept out of this file.
#[cfg(all(test, feature = "elastic"))]
mod age_cost;
#[cfg(all(test, feature = "elastic"))]
mod borrow_cost;
/// Data-run placement on a filled, aged shard (tsrv2 fill4m sequence, doc/perf/frag4m-20261102.md).
#[cfg(all(test, feature = "elastic"))]
mod frag4m;
#[cfg(test)]
mod frag_cost;
