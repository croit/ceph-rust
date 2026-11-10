// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! In-memory NVMe simulator with fault injection (design 6.2). Deterministic given the seed and call order.
//!
//! Model: a write is applied to the media when its completion is delivered by `poll` (completion == durable,
//! PLP). Until then it is "in flight"; a crash persists an arbitrary subset of in-flight writes (policy
//! driven) and, for multi-LBA writes larger than AWUPF, may tear them at LBA granularity. Completion order
//! follows the latency model (base + bus transfer + jitter), so IOs reorder naturally.
//!
//! Crash control: `SimDisk::arm_crash(k)` freezes the device after k IO events (a submit or a delivered
//! completion is one event): later submits fail with `Dead`, `poll` yields nothing. `crash_image` then gives the
//! post-power-loss media to remount. Several queue handles (`SimDisk::queue`) share one disk.

use super::{BlockDev, Completion, Geometry, IoError, Nanos, Op, Rejected, Submit, SubmitError};
use crate::rng::Rng;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

/// One stored LBA (shared: `SimImage` clones are cheap, `SimConfig::dedup` shares equal blocks).
type Blk = Arc<[u8]>;

/// Shared copy of `c` from `d` (equal content stored once; at most 64k distinct entries, beyond that a private copy).
fn intern(d: &mut HashMap<u32, Blk>, c: &[u8]) -> Blk {
    let k = crc::crc32c(0, c);
    match d.get(&k) {
        Some(b) if **b == *c => b.clone(),
        Some(_) => Arc::from(c),
        None => {
            let b: Blk = Arc::from(c);
            if d.len() < 1 << 16 {
                d.insert(k, b.clone());
            }
            b
        }
    }
}

/// Flip bits of one byte of `lba` (corruption injection; an absent LBA reads as zeros).
fn flip(media: &mut HashMap<u64, Blk>, ls: usize, lba: u64, byte: usize, mask: u8) {
    let mut v = media.get(&lba).map_or_else(|| vec![0; ls], |b| b.to_vec());
    v[byte] ^= mask;
    media.insert(lba, Arc::from(v));
}

#[derive(Clone, Debug)]
pub struct SimConfig {
    pub lba_size: u32,
    pub lba_count: u64,
    pub awupf_lbas: u32,
    pub awun_lbas: u32,
    pub vwc: bool,
    pub max_xfer_lbas: u32,
    pub queue_depth: usize,
    pub write_ns: u64,
    pub read_ns: u64,
    pub dealloc_ns: u64,
    /// Serialized bus time per LBA (bandwidth model, shared by all queues).
    pub xfer_ns_per_lba: u64,
    /// Uniform random extra latency 0..=jitter_ns per IO (drives reordering).
    pub jitter_ns: u64,
    pub seed: u64,
    /// `BlockDev::dealloc_limits` of the queues: a DSM-shaped device by default (every store test runs the trimmer, adr
    /// 0642); `DeallocLimits::off(..)` = a device without runtime deallocate.
    pub dealloc: nvme::DeallocLimits,
    /// Store equal LBA contents once (lab benches that write one pattern: a device far bigger than RAM).
    pub dedup: bool,
    /// `BlockDev::submits_at_flush` of the queues (models the kernel tier's seal point; IO timing is unchanged).
    pub submit_at_flush: bool,
    /// `BlockDev::ram_reads` of the queues: reads may go to ordinary memory (the kernel tier); false models a device
    /// that reads only into a bounded DMA pool (SPDK).
    pub ram_reads: bool,
}

impl SimConfig {
    /// 4 KiB LBA, AWUPF = 1 LBA, PLP, ~3 GB/s, 10 us write / 80 us read.
    pub fn new(capacity_bytes: u64) -> SimConfig {
        SimConfig {
            lba_size: 4096,
            lba_count: capacity_bytes / 4096,
            awupf_lbas: 1,
            awun_lbas: 1,
            vwc: false,
            max_xfer_lbas: 64,
            queue_depth: 128,
            write_ns: 10_000,
            read_ns: 80_000,
            dealloc_ns: 20_000,
            xfer_ns_per_lba: 1_300,
            jitter_ns: 8_000,
            seed: 1,
            dealloc: nvme::DeallocLimits {
                via: "sim",
                ..nvme::DeallocLimits::DSM
            },
            dedup: false,
            submit_at_flush: false,
            ram_reads: true,
        }
    }
}

/// What a crash does to each in-flight write (percentages; remainder is dropped). `tear_pct` only affects
/// writes of more than `awupf_lbas` LBAs (smaller ones are atomic: persist or drop).
#[derive(Clone, Copy, Debug)]
pub struct CrashPolicy {
    pub full_pct: u8,
    pub tear_pct: u8,
}

impl CrashPolicy {
    pub const DROP_ALL: CrashPolicy = CrashPolicy {
        full_pct: 0,
        tear_pct: 0,
    };
    pub const PERSIST_ALL: CrashPolicy = CrashPolicy {
        full_pct: 100,
        tear_pct: 0,
    };
    pub const MIXED: CrashPolicy = CrashPolicy {
        full_pct: 35,
        tear_pct: 35,
    };
}

/// Durable media content (what survives power loss); cheap sparse clone.
#[derive(Clone, Debug)]
pub struct SimImage {
    media: HashMap<u64, Blk>,
    pub lba_size: u32,
    pub lba_count: u64,
}

impl SimImage {
    pub fn read_lba(&self, lba: u64) -> Vec<u8> {
        self.media
            .get(&lba)
            .map_or_else(|| vec![0; self.lba_size as usize], |b| b.to_vec())
    }
    /// Flip bits of one byte in place (silent corruption injection).
    pub fn corrupt(&mut self, lba: u64, byte: usize, mask: u8) {
        let ls = self.lba_size as usize;
        flip(&mut self.media, ls, lba, byte, mask);
    }
    pub fn used_lbas(&self) -> usize {
        self.media.len()
    }
}

#[derive(Debug)]
struct Inflight {
    qid: u32,
    tag: u64,
    op: Op,
    lba: u64,
    /// LBAs (a deallocate: of all its ranges together).
    nlba: u32,
    buf: Option<Vec<u8>>,
    /// Deallocate: its ranges (`lba`/`nlba` = first LBA / total).
    ranges: Vec<(u64, u32)>,
    done_ns: u64,
    seq: u64,
}

/// LBAs of a deallocate's ranges, in order (or `[lba, lba + nlba)` for a single-range op).
/// LBA ranges of an in-flight op (a deallocate may carry several).
fn ranges_of(f: &Inflight) -> Vec<(u64, u32)> {
    if f.ranges.is_empty() {
        vec![(f.lba, f.nlba)]
    } else {
        f.ranges.clone()
    }
}

/// Unmap the LBAs of `ranges`; `mask[j]` false keeps the j-th LBA (in range order) mapped (a torn deallocate).
fn unmap(media: &mut HashMap<u64, Blk>, ranges: &[(u64, u32)], mask: Option<&[bool]>) {
    let mut j = 0;
    for &(l, n) in ranges {
        let n64 = u64::from(n);
        match mask {
            // a range wider than the mapped LBAs: one pass over the map
            None if n64 > media.len() as u64 => media.retain(|&x, _| x < l || x >= l + n64),
            _ => {
                for i in 0..n as usize {
                    if mask.is_none_or(|m| m[j + i]) {
                        media.remove(&(l + i as u64));
                    }
                }
            }
        }
        j += n as usize;
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SimStats {
    pub writes: u64,
    pub reads: u64,
    pub deallocs: u64,
    pub write_lbas: u64,
    pub read_lbas: u64,
    /// Deferrable store buffers refused ([`SimDisk::refuse_bufs`]).
    pub refused_bufs: u64,
    /// In-flight IO buffers refused ([`SimDisk::refuse_io_bufs`]).
    pub refused_io_bufs: u64,
}

#[derive(Debug)]
struct Inner {
    cfg: SimConfig,
    media: HashMap<u64, Blk>,
    inflight: Vec<Inflight>,
    seq: u64,
    now: Nanos,
    bus_free: Nanos,
    rng: Rng,
    events: u64,
    crash_at: Option<u64>,
    crashed: bool,
    read_err: Vec<(u64, u64)>,
    write_err: Vec<(u64, u64)>,
    lose_write_pct: u8,
    /// [`SimDisk::refuse_bufs_after`] / [`SimDisk::refuse_io_bufs_after`]: buffer requests of each kind still to admit
    /// before the refusals, and still to refuse.
    pass_bufs: u64,
    refuse_bufs: u64,
    pass_io_bufs: u64,
    refuse_io_bufs: u64,
    next_qid: u32,
    stats: SimStats,
    /// `SimConfig::dedup`: stored contents by crc32c (bounded).
    dd: HashMap<u32, Blk>,
}

impl Inner {
    fn geometry(&self) -> Geometry {
        let c = &self.cfg;
        Geometry {
            lba_size: c.lba_size,
            lba_count: c.lba_count,
            awupf_lbas: c.awupf_lbas,
            awun_lbas: c.awun_lbas,
            vwc: c.vwc,
            max_xfer_lbas: c.max_xfer_lbas,
            dealloc: true,
            write_zeroes: true,
        }
    }

    /// Account one IO event; false = power failed before it.
    fn event(&mut self) -> bool {
        if self.crashed {
            return false;
        }
        if self.crash_at == Some(self.events) {
            self.crashed = true;
            return false;
        }
        self.events += 1;
        true
    }

    fn persist(
        media: &mut HashMap<u64, Blk>,
        ls: usize,
        lba: u64,
        data: &[u8],
        only: Option<&[bool]>,
        mut dd: Option<&mut HashMap<u32, Blk>>,
    ) {
        for (i, c) in data.chunks(ls).enumerate() {
            if only.is_some_and(|o| !o[i]) {
                continue;
            }
            let l = lba + i as u64;
            if let Some(d) = dd.as_deref_mut() {
                media.insert(l, intern(d, c));
                continue;
            }
            match media.get_mut(&l).and_then(Arc::get_mut) {
                Some(b) => b.copy_from_slice(c),
                None => {
                    media.insert(l, Arc::from(c));
                }
            }
        }
    }

    fn overlaps(list: &[(u64, u64)], lba: u64, n: u64) -> bool {
        list.iter().any(|&(a, l)| lba < a + l && a < lba + n)
    }

    fn finish(&mut self, mut f: Inflight) -> Completion<Vec<u8>> {
        let ls = self.cfg.lba_size as usize;
        let n = f.nlba as u64;
        let mut result = Ok(());
        let mut buf = f.buf.take();
        match f.op {
            Op::Write => {
                self.stats.writes += 1;
                self.stats.write_lbas += n;
                if Self::overlaps(&self.write_err, f.lba, n) {
                    result = Err(IoError::Media);
                } else if !(self.lose_write_pct > 0 && self.rng.pct(self.lose_write_pct)) {
                    Self::persist(
                        &mut self.media,
                        ls,
                        f.lba,
                        buf.as_ref().unwrap(),
                        None,
                        self.cfg.dedup.then_some(&mut self.dd),
                    );
                }
            }
            Op::Read => {
                self.stats.reads += 1;
                self.stats.read_lbas += n;
                if Self::overlaps(&self.read_err, f.lba, n) {
                    result = Err(IoError::Media);
                } else {
                    let b = buf.as_mut().unwrap();
                    for (i, c) in b.chunks_mut(ls).enumerate() {
                        match self.media.get(&(f.lba + i as u64)) {
                            Some(m) => c.copy_from_slice(m),
                            None => c.fill(0),
                        }
                    }
                }
            }
            Op::Deallocate | Op::WriteZeroes => {
                self.stats.deallocs += 1;
                unmap(&mut self.media, &ranges_of(&f), None);
            }
        }
        Completion {
            tag: f.tag,
            op: f.op,
            result,
            buf,
        }
    }
}

/// Shared simulated disk. Single-threaded (Rc/RefCell): the sim is for deterministic tests.
#[derive(Clone, Debug)]
pub struct SimDisk {
    inner: Rc<RefCell<Inner>>,
}

impl SimDisk {
    pub fn new(cfg: SimConfig) -> SimDisk {
        Self::build(cfg, HashMap::new())
    }

    /// Remount after a crash: new disk over the durable image (config geometry must match the image).
    pub fn from_image(img: &SimImage, cfg: SimConfig) -> SimDisk {
        assert_eq!(img.lba_size, cfg.lba_size);
        assert_eq!(img.lba_count, cfg.lba_count);
        Self::build(cfg, img.media.clone())
    }

    /// Like `from_image` for a device whose size changed meanwhile (grown LUN/namespace: `expand` tests; a smaller
    /// `lba_count` models a shrink). Blocks of the image beyond the new size are not readable.
    pub fn from_image_resized(img: &SimImage, cfg: SimConfig) -> SimDisk {
        assert_eq!(img.lba_size, cfg.lba_size);
        Self::build(cfg, img.media.clone())
    }

    fn build(cfg: SimConfig, media: HashMap<u64, Blk>) -> SimDisk {
        let rng = Rng::new(cfg.seed);
        SimDisk {
            inner: Rc::new(RefCell::new(Inner {
                cfg,
                media,
                inflight: Vec::new(),
                seq: 0,
                now: 0,
                bus_free: 0,
                rng,
                events: 0,
                crash_at: None,
                crashed: false,
                read_err: Vec::new(),
                write_err: Vec::new(),
                lose_write_pct: 0,
                pass_bufs: 0,
                refuse_bufs: 0,
                pass_io_bufs: 0,
                refuse_io_bufs: 0,
                next_qid: 0,
                stats: SimStats::default(),
                dd: HashMap::new(),
            })),
        }
    }

    /// New queue handle (one per shard/core).
    pub fn queue(&self) -> SimDev {
        let mut i = self.inner.borrow_mut();
        let qid = i.next_qid;
        i.next_qid += 1;
        let depth = i.cfg.queue_depth;
        drop(i);
        SimDev {
            inner: self.inner.clone(),
            qid,
            depth,
        }
    }

    pub fn config(&self) -> SimConfig {
        self.inner.borrow().cfg.clone()
    }

    /// Freeze the device after `k` more... after a total of `k` IO events since creation.
    pub fn arm_crash(&self, k: u64) {
        self.inner.borrow_mut().crash_at = Some(k);
    }
    pub fn disarm_crash(&self) {
        self.inner.borrow_mut().crash_at = None;
    }
    pub fn events(&self) -> u64 {
        self.inner.borrow().events
    }
    pub fn crashed(&self) -> bool {
        self.inner.borrow().crashed
    }
    /// Power failure right now.
    pub fn crash_now(&self) {
        self.inner.borrow_mut().crashed = true;
    }
    /// Pre-size the media map for `lbas` written blocks (benches: a rehash of a multi-million entry map is a 30-60 ms
    /// stall inside `poll` that the real device does not have).
    pub fn reserve_media(&self, lbas: usize) {
        self.inner.borrow_mut().media.reserve(lbas);
    }

    pub fn stats(&self) -> SimStats {
        self.inner.borrow().stats
    }
    pub fn inflight(&self) -> usize {
        self.inner.borrow().inflight.len()
    }
    /// In-flight deallocates (crash matrices: crash points that hit one).
    pub fn inflight_deallocs(&self) -> usize {
        self.inner
            .borrow()
            .inflight
            .iter()
            .filter(|x| matches!(x.op, Op::Deallocate))
            .count()
    }

    /// Reads overlapping `[lba, lba+n)` fail with a media error.
    pub fn fail_reads(&self, lba: u64, n: u64) {
        self.inner.borrow_mut().read_err.push((lba, n));
    }
    pub fn fail_writes(&self, lba: u64, n: u64) {
        self.inner.borrow_mut().write_err.push((lba, n));
    }
    pub fn clear_faults(&self) {
        let mut i = self.inner.borrow_mut();
        i.read_err.clear();
        i.write_err.clear();
        i.lose_write_pct = 0;
        i.pass_bufs = 0;
        i.refuse_bufs = 0;
        i.pass_io_bufs = 0;
        i.refuse_io_bufs = 0;
    }
    /// The next `n` deferrable store buffer requests ([`BlockDev::try_alloc_buf_uninit`]) are refused, as by a full read gate
    /// of the DMA budget (adr 0175 am. 4); counted in [`SimStats::refused_bufs`].
    pub fn refuse_bufs(&self, n: u64) {
        self.refuse_bufs_after(0, n);
    }
    /// [`SimDisk::refuse_bufs`] after admitting the next `pass` deferrable buffer requests (a refusal in the middle of
    /// a multi-buffer IO).
    pub fn refuse_bufs_after(&self, pass: u64, n: u64) {
        let mut i = self.inner.borrow_mut();
        i.pass_bufs = pass;
        i.refuse_bufs = n;
    }
    /// The next `n` in-flight IO buffer requests ([`BlockDev::try_alloc_io_uninit`]) are refused, as by an exhausted
    /// DMA budget (adr 0175 am. 4); counted in [`SimStats::refused_io_bufs`].
    pub fn refuse_io_bufs(&self, n: u64) {
        self.refuse_io_bufs_after(0, n);
    }
    /// [`SimDisk::refuse_io_bufs`] after admitting the next `pass` in-flight IO buffer requests (a refusal in the middle
    /// of a synchronous read).
    pub fn refuse_io_bufs_after(&self, pass: u64, n: u64) {
        let mut i = self.inner.borrow_mut();
        i.pass_io_bufs = pass;
        i.refuse_io_bufs = n;
    }
    /// Change the bus transfer time per LBA (bandwidth) of a running disk (lab benches: fast fill, slower run).
    pub fn set_xfer_ns(&self, ns: u64) {
        self.inner.borrow_mut().cfg.xfer_ns_per_lba = ns;
    }
    /// Negative-test knob: completed writes are silently not persisted with this probability.
    pub fn lose_writes(&self, pct: u8) {
        self.inner.borrow_mut().lose_write_pct = pct;
    }
    /// Flip bits in durable media.
    pub fn corrupt(&self, lba: u64, byte: usize, mask: u8) {
        let mut i = self.inner.borrow_mut();
        let ls = i.cfg.lba_size as usize;
        flip(&mut i.media, ls, lba, byte, mask);
    }

    /// Durable media as of now, ignoring in-flight IO (= `crash_image(DROP_ALL)`).
    pub fn image(&self) -> SimImage {
        let i = self.inner.borrow();
        SimImage {
            media: i.media.clone(),
            lba_size: i.cfg.lba_size,
            lba_count: i.cfg.lba_count,
        }
    }

    /// Media after power loss: durable media plus, per in-flight write, persisted / dropped / torn per
    /// `policy` (drawn from the disk's seeded RNG). Applied in submit order. Can be called repeatedly (each
    /// call draws new random choices) or at any time, not only after `arm_crash`.
    pub fn crash_image(&self, policy: CrashPolicy) -> SimImage {
        let awupf = self.inner.borrow().cfg.awupf_lbas;
        self.crash_image_with(|f, rng| {
            let roll = rng.below(100) as u8;
            let full = roll < policy.full_pct;
            let tear =
                !full && roll < policy.full_pct.saturating_add(policy.tear_pct) && f.nlba > awupf;
            if full {
                Persist::Full
            } else if tear {
                Persist::Tear((0..f.nlba).map(|_| rng.pct(50)).collect())
            } else {
                Persist::Drop
            }
        })
    }

    /// Like `crash_image` with a caller-chosen fate per in-flight write (targeted tests: e.g. persist the WAL
    /// unit but drop its data). Called in submit order. `Tear` masks must have one entry per LBA.
    pub fn crash_image_with(
        &self,
        mut f: impl FnMut(&InflightInfo, &mut Rng) -> Persist,
    ) -> SimImage {
        let mut i = self.inner.borrow_mut();
        let ls = i.cfg.lba_size as usize;
        let mut media = i.media.clone();
        let mut order: Vec<usize> = (0..i.inflight.len()).collect();
        order.sort_by_key(|&k| i.inflight[k].seq);
        for k in order {
            let (op, lba, n, tag, qid, lbas) = {
                let x = &i.inflight[k];
                (x.op, x.lba, x.nlba, x.tag, x.qid, ranges_of(x))
            };
            let mut rng = std::mem::replace(&mut i.rng, Rng::new(0));
            let fate = f(
                &InflightInfo {
                    op,
                    lba,
                    nlba: n,
                    tag,
                    qid,
                },
                &mut rng,
            );
            i.rng = rng;
            let mask: Option<Vec<bool>> = match fate {
                Persist::Drop => continue,
                Persist::Full => None,
                Persist::Tear(m) => Some(m),
            };
            match op {
                Op::Write => {
                    let data = i.inflight[k].buf.as_ref().unwrap();
                    Inner::persist(&mut media, ls, lba, data, mask.as_deref(), None);
                }
                Op::Deallocate | Op::WriteZeroes => unmap(&mut media, &lbas, mask.as_deref()),
                Op::Read => {}
            }
        }
        SimImage {
            media,
            lba_size: i.cfg.lba_size,
            lba_count: i.cfg.lba_count,
        }
    }
}

/// An in-flight IO as seen by `crash_image_with` (a deallocate: first LBA, LBAs of all ranges; a `Tear` mask covers
/// them in range order).
#[derive(Clone, Copy, Debug)]
pub struct InflightInfo {
    pub op: Op,
    pub lba: u64,
    pub nlba: u32,
    pub tag: u64,
    pub qid: u32,
}

#[derive(Clone, Debug)]
pub enum Persist {
    Drop,
    Full,
    Tear(Vec<bool>),
}

/// Per-core queue handle on a `SimDisk`.
#[derive(Debug)]
pub struct SimDev {
    inner: Rc<RefCell<Inner>>,
    qid: u32,
    depth: usize,
}

impl SimDev {
    fn mine(&self, i: &Inner) -> usize {
        i.inflight.iter().filter(|f| f.qid == self.qid).count()
    }

    fn submit(
        &mut self,
        op: Op,
        lba: u64,
        nlba: u32,
        tag: u64,
        buf: Option<Vec<u8>>,
        ranges: Vec<(u64, u32)>,
    ) -> Submit<Vec<u8>> {
        let _s = wprof::span(wprof::S::Dev);
        let mut i = self.inner.borrow_mut();
        let rej = |err, buf| Err(Rejected { err, buf });
        if i.crashed {
            return rej(SubmitError::Dead, buf);
        }
        if nlba == 0 || nlba > i.cfg.max_xfer_lbas && matches!(op, Op::Write | Op::Read) {
            return rej(SubmitError::Invalid, buf);
        }
        if let Some(b) = &buf
            && b.len() != nlba as usize * i.cfg.lba_size as usize
        {
            return rej(SubmitError::Invalid, buf);
        }
        let end = |l: u64, n: u32| {
            l.checked_add(u64::from(n))
                .is_none_or(|e| e > i.cfg.lba_count)
        };
        if (ranges.is_empty() && end(lba, nlba)) || ranges.iter().any(|&(l, n)| end(l, n)) {
            return rej(SubmitError::OutOfRange, buf);
        }
        if self.mine(&i) >= self.depth {
            return rej(SubmitError::QueueFull, buf);
        }
        if !i.event() {
            return rej(SubmitError::Dead, buf);
        }
        let (base, xfer, jn) = {
            let c = &i.cfg;
            match op {
                Op::Write => (c.write_ns, c.xfer_ns_per_lba * nlba as u64, c.jitter_ns),
                Op::Read => (c.read_ns, c.xfer_ns_per_lba * nlba as u64, c.jitter_ns),
                _ => (c.dealloc_ns, 0, c.jitter_ns),
            }
        };
        let jit = if jn > 0 { i.rng.below(jn + 1) } else { 0 };
        let start = i.bus_free.max(i.now);
        i.bus_free = start + xfer;
        let done_ns = i.bus_free + base + jit;
        let seq = i.seq;
        i.seq += 1;
        i.inflight.push(Inflight {
            qid: self.qid,
            tag,
            op,
            lba,
            nlba,
            buf,
            ranges,
            done_ns,
            seq,
        });
        Ok(())
    }
}

impl BlockDev for SimDev {
    type Buf = Vec<u8>;

    /// The simulated device "views" a payload by copying it at staging time (same bytes; exercises the zero-copy
    /// write path of the store, adr 0061 am. 4).
    fn view_buf(&mut self, data: &bytes::Bytes) -> Option<Vec<u8>> {
        let _s = wprof::span(wprof::S::Dev);
        Some(data.to_vec())
    }

    fn dealloc_limits(&self) -> nvme::DeallocLimits {
        self.inner.borrow().cfg.dealloc
    }
    fn submits_at_flush(&self) -> bool {
        self.inner.borrow().cfg.submit_at_flush
    }
    fn geometry(&self) -> Geometry {
        self.inner.borrow().geometry()
    }
    fn alloc_buf(&mut self, len: usize) -> Vec<u8> {
        let _s = wprof::span(wprof::S::Dev);
        vec![0; len]
    }
    fn try_alloc_buf_uninit(&mut self, len: usize) -> Option<Vec<u8>> {
        {
            let mut i = self.inner.borrow_mut();
            if i.pass_bufs > 0 {
                i.pass_bufs -= 1;
            } else if i.refuse_bufs > 0 {
                i.refuse_bufs -= 1;
                i.stats.refused_bufs += 1;
                return None;
            }
        }
        Some(self.alloc_buf_uninit(len))
    }
    fn try_alloc_io_uninit(&mut self, len: usize) -> Option<Vec<u8>> {
        {
            let mut i = self.inner.borrow_mut();
            if i.pass_io_bufs > 0 {
                i.pass_io_bufs -= 1;
            } else if i.refuse_io_bufs > 0 {
                i.refuse_io_bufs -= 1;
                i.stats.refused_io_bufs += 1;
                return None;
            }
        }
        Some(self.alloc_buf_uninit(len))
    }
    fn ram_reads(&self) -> bool {
        self.inner.borrow().cfg.ram_reads
    }
    fn queue_space(&self) -> usize {
        self.depth.saturating_sub(self.mine(&self.inner.borrow()))
    }
    fn queue_depth(&self) -> usize {
        self.depth
    }
    fn submit_write(&mut self, lba: u64, buf: Vec<u8>, tag: u64) -> Submit<Vec<u8>> {
        let n = buf.len() / self.inner.borrow().cfg.lba_size as usize;
        self.submit(Op::Write, lba, n as u32, tag, Some(buf), Vec::new())
    }
    fn submit_read(&mut self, lba: u64, buf: Vec<u8>, tag: u64) -> Submit<Vec<u8>> {
        let n = buf.len() / self.inner.borrow().cfg.lba_size as usize;
        self.submit(Op::Read, lba, n as u32, tag, Some(buf), Vec::new())
    }
    fn submit_deallocate(&mut self, ranges: &[(u64, u32)], tag: u64) -> Submit<Vec<u8>> {
        if let Err(err) = self.dealloc_limits().check(ranges) {
            return Err(Rejected { err, buf: None });
        }
        let total: u64 = ranges.iter().map(|&(_, n)| u64::from(n)).sum();
        let nlba = u32::try_from(total).unwrap_or(u32::MAX);
        self.submit(
            Op::Deallocate,
            ranges[0].0,
            nlba,
            tag,
            None,
            ranges.to_vec(),
        )
    }
    fn submit_write_zeroes(&mut self, lba: u64, nlba: u32, tag: u64) -> Submit<Vec<u8>> {
        self.submit(Op::WriteZeroes, lba, nlba, tag, None, Vec::new())
    }

    fn poll(&mut self, now: Nanos, out: &mut Vec<Completion<Vec<u8>>>) -> usize {
        let _s = wprof::span(wprof::S::Dev);
        let mut i = self.inner.borrow_mut();
        i.now = i.now.max(now);
        let now = i.now;
        let mut due: Vec<(u64, u64)> = i
            .inflight
            .iter()
            .filter(|f| f.qid == self.qid && f.done_ns <= now)
            .map(|f| (f.done_ns, f.seq))
            .collect();
        due.sort_unstable();
        let mut n = 0;
        for (_, seq) in due {
            if !i.event() {
                break;
            }
            let k = i.inflight.iter().position(|f| f.seq == seq).unwrap();
            let f = i.inflight.swap_remove(k);
            let c = i.finish(f);
            out.push(c);
            n += 1;
        }
        n
    }

    fn next_deadline(&self) -> Option<Nanos> {
        self.inner
            .borrow()
            .inflight
            .iter()
            .filter(|f| f.qid == self.qid)
            .map(|f| f.done_ns)
            .min()
    }

    fn is_dead(&self) -> bool {
        self.inner.borrow().crashed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(d: &mut SimDev, t: &mut u64) -> Vec<Completion<Vec<u8>>> {
        let mut out = Vec::new();
        while out.is_empty() {
            *t = d.next_deadline().unwrap_or(*t + 1).max(*t);
            d.poll(*t, &mut out);
        }
        out
    }

    #[test]
    fn write_read_roundtrip_and_zero_default() {
        let disk = SimDisk::new(SimConfig::new(1 << 20));
        let mut d = disk.queue();
        let mut t = 0;
        let mut b = d.alloc_buf(8192);
        b[..4].copy_from_slice(b"abcd");
        b[4096..4100].copy_from_slice(b"wxyz");
        d.submit_write(3, b, 7).unwrap();
        let c = drain(&mut d, &mut t);
        assert_eq!((c[0].tag, c[0].result), (7, Ok(())));
        let buf = d.alloc_buf(12288);
        d.submit_read(2, buf, 8).unwrap();
        let c = drain(&mut d, &mut t);
        let b = c[0].buf.as_ref().unwrap();
        assert_eq!(&b[..4], &[0; 4]);
        assert_eq!(&b[4096..4100], b"abcd");
        assert_eq!(&b[8192..8196], b"wxyz");
    }

    #[test]
    fn crash_drops_unpolled_writes_and_tears() {
        let mut cfg = SimConfig::new(1 << 22);
        cfg.seed = 5;
        let disk = SimDisk::new(cfg);
        let mut d = disk.queue();
        for k in 0..8u64 {
            let mut b = d.alloc_buf(4096 * 8);
            b.fill(k as u8 + 1);
            d.submit_write(k * 8, b, k).unwrap();
        }
        assert_eq!(disk.image().used_lbas(), 0);
        let img = disk.crash_image(CrashPolicy::DROP_ALL);
        assert_eq!(img.used_lbas(), 0);
        let img = disk.crash_image(CrashPolicy::PERSIST_ALL);
        assert_eq!(img.used_lbas(), 64);
        // torn: some write persists a strict, non-empty subset of its LBAs
        let mut torn = false;
        for _ in 0..20 {
            let img = disk.crash_image(CrashPolicy {
                full_pct: 0,
                tear_pct: 100,
            });
            for k in 0..8u64 {
                let n = (0..8).filter(|j| img.read_lba(k * 8 + j)[0] != 0).count();
                torn |= n > 0 && n < 8;
            }
        }
        assert!(torn);
    }

    #[test]
    fn single_lba_never_torn() {
        let disk = SimDisk::new(SimConfig::new(1 << 20));
        let mut d = disk.queue();
        let mut b = d.alloc_buf(4096);
        b.fill(9);
        d.submit_write(1, b, 0).unwrap();
        for _ in 0..50 {
            let img = disk.crash_image(CrashPolicy {
                full_pct: 50,
                tear_pct: 50,
            });
            let l = img.read_lba(1);
            assert!(l.iter().all(|&x| x == 9) || l.iter().all(|&x| x == 0));
        }
    }

    #[test]
    fn arm_crash_freezes_at_event() {
        let disk = SimDisk::new(SimConfig::new(1 << 20));
        let mut d = disk.queue();
        disk.arm_crash(3);
        let mut t = 0;
        for k in 0..2 {
            d.submit_write(k, vec![1; 4096], k).unwrap();
        }
        let c = drain(&mut d, &mut t); // event 3 = first completion
        assert_eq!(c.len(), 1);
        assert!(!disk.crashed());
        let mut out = Vec::new();
        t += 1_000_000;
        d.poll(t, &mut out);
        assert!(out.is_empty());
        assert!(disk.crashed());
        assert!(matches!(
            d.submit_write(5, vec![0; 4096], 9),
            Err(Rejected {
                err: SubmitError::Dead,
                ..
            })
        ));
    }

    #[test]
    fn completions_reorder_with_jitter() {
        let mut cfg = SimConfig::new(1 << 22);
        cfg.jitter_ns = 50_000;
        cfg.seed = 11;
        let disk = SimDisk::new(cfg);
        let mut d = disk.queue();
        for k in 0..32u64 {
            d.submit_write(k, vec![1; 4096], k).unwrap();
        }
        let mut out = Vec::new();
        d.poll(10_000_000, &mut out);
        let tags: Vec<u64> = out.iter().map(|c| c.tag).collect();
        assert_eq!(tags.len(), 32);
        assert!(
            tags.windows(2).any(|w| w[0] > w[1]),
            "no reordering observed"
        );
    }

    #[test]
    fn read_errors_queue_full_and_range() {
        let mut cfg = SimConfig::new(1 << 20);
        cfg.queue_depth = 2;
        let disk = SimDisk::new(cfg);
        let mut d = disk.queue();
        disk.fail_reads(5, 1);
        d.submit_read(5, vec![0; 4096], 1).unwrap();
        d.submit_read(6, vec![0; 4096], 2).unwrap();
        assert!(matches!(
            d.submit_read(7, vec![0; 4096], 3),
            Err(Rejected {
                err: SubmitError::QueueFull,
                buf: Some(_)
            })
        ));
        assert!(matches!(
            d.submit_read(1 << 30, vec![0; 4096], 3),
            Err(Rejected {
                err: SubmitError::OutOfRange,
                ..
            })
        ));
        let mut t = 0;
        let mut res = drain(&mut d, &mut t);
        let mut out = Vec::new();
        d.poll(t + 10_000_000, &mut out);
        res.append(&mut out);
        res.sort_by_key(|c| c.tag);
        assert_eq!(res[0].result, Err(IoError::Media));
        assert_eq!(res[1].result, Ok(()));
    }

    #[test]
    fn two_queues_share_disk() {
        let disk = SimDisk::new(SimConfig::new(1 << 20));
        let (mut a, mut b) = (disk.queue(), disk.queue());
        a.submit_write(1, vec![7; 4096], 1).unwrap();
        let mut out = Vec::new();
        b.poll(1_000_000, &mut out);
        assert!(out.is_empty());
        a.poll(1_000_000, &mut out);
        assert_eq!(out.len(), 1);
        b.submit_read(1, vec![0; 4096], 2).unwrap();
        out.clear();
        b.poll(2_000_000, &mut out);
        assert_eq!(out[0].buf.as_ref().unwrap()[0], 7);
    }
}
