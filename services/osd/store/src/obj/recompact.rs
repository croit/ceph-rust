// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Idle recompaction of compressed pools and the extent census (adr 0533).
//!
//! A 4 KiB overwrite inside a compressed chunk keeps the rest of the chunk as windows (adr 0059 am. 4): the chunk's
//! blocks stay while the overwrite takes new raw blocks, until the space rule merges the chunk at write time (fewer live
//! blocks than the chunk occupies) into small raw records. While the device is idle the shard walks its compressed
//! collections and rewrites (a) each cut chunk and (b), in a pool that compresses (`Store::set_pool_comp`), each aligned
//! range of small plain records, when the range compresses into fewer blocks than it holds now: one ordinary txn per
//! range (`Stage::recompact`: parallel commit, data crcs validated at replay, old blocks held until a checkpoint passed,
//! refcounts for windows), so crash safety is that of any write. Blocks shared with another object (a clone) are never
//! freed by it (counted as no gain).
//!
//! Sweep: collections (`C`) with non-zero compressed counters or a pool compression (all of them on a census request) ->
//! their names (`N`, `L`) -> per object its extent records (`e`, listing cursors: the walk does not push the working set
//! out of the cache). Per object the census counts records, plain blocks, chunks, windows, cut chunks; candidates are
//! staged right after the object's records are read. Started after mount, when windows were cut since the last sweep
//! began, when a pool's compression is set, or on request (`Store::request_census`); checked every `CHECK_NS`.
//!
//! Scheduling: only while the shard has no client work (a parked or foreign txn in flight, a client read: prefetch run or
//! rolling read of another session, its queue busy while the walk has no IO of its own) for at least `BG_BUSY_GAP_NS`,
//! and every other queue of the device is quiet (`Shard::dev_quiet`). One unit per call (a scan batch or one chunk txn),
//! one chunk txn in flight: a client op waits for at most one unit. The walk keeps no shard active: an otherwise idle core
//! sleeps, the walk takes its next unit in the next store round.
use super::keys::{
    T_COLL, decode_coll_key, decode_long_key, decode_sort_key, id_range, long_end, long_prefix,
    name_end, name_prefix,
};
use super::onode::{CollInfo, ExtRaw};
use super::shardio::{RC_SESSION, ShardStore};
use super::stage::{RcOut, Stage};
use super::{ObjError, Store};
use crate::compress::CompSpec;
use crate::dev::{BlockDev, Clock};
use crate::error::StoreError;
use crate::tree::{ScanCursor, ScanStatus};
use denc::types::{CollT, Ghobject};
use std::collections::VecDeque;

/// Ack token bits of recompaction txns (store-owned like defrag moves: never reported).
const RC_ACK: u64 = super::defrag::DF_ACK | 1 << 62;
/// Same cadence as the defrag and reclaim checks.
const CHECK_NS: u64 = super::defrag::CHECK_NS;
/// Entries per scan step (as defrag's extent scan).
const SCAN_BATCH: usize = super::defrag::SCAN_BATCH;
/// Client work gap before the walk runs: the pacing period of background work under client IO (adr 0021 am. 33).
const GAP_NS: u64 = crate::shard::BG_BUSY_GAP_NS;

/// Extent census as seen by the last complete sweep (state before that sweep's rewrites). Blocks are 4 KiB. The fields
/// up to `cut_span` cover the collections holding compressed data; `unc_*` the other collections, walked only after
/// `Store::request_census`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Census {
    /// Objects with at least one extent record, and their records.
    pub objects: u64,
    pub records: u64,
    /// Blocks of plain (uncompressed) records.
    pub plain_blocks: u64,
    /// Compressed chunks (distinct per object) and their physical blocks.
    pub chunks: u64,
    pub chunk_blocks: u64,
    /// Logical blocks the compressed records stand for.
    pub comp_logical: u64,
    /// Window records (adr 0059 am. 4).
    pub windows: u64,
    /// Chunks with at least one window, the logical blocks still in their windows, their logical span.
    pub cut_chunks: u64,
    pub cut_live: u64,
    pub cut_span: u64,
    /// Collections without compressed data: objects with extent records, their records and blocks.
    pub unc_objects: u64,
    pub unc_records: u64,
    pub unc_blocks: u64,
}

/// Recompaction counters (lifetime).
#[derive(Clone, Copy, Debug, Default)]
pub struct RcStats {
    pub sweeps: u64,
    /// Chunks rewritten, blocks their old records held (freed after the next checkpoint), blocks of the new chunks.
    pub chunks: u64,
    pub freed_blocks: u64,
    pub new_blocks: u64,
    /// Candidates whose rewrite would not save a block, candidates skipped (gone, changed, shared, no contiguous room).
    pub no_gain: u64,
    pub skipped: u64,
    /// Sweeps whose scan failed (not a cold page): their census was partial and is not published; the next change or
    /// census request sweeps again.
    pub incomplete: u64,
    /// Client work seen while the walk's own IO was in flight (the walk overlapped a client op by at most that unit).
    pub overlaps: u64,
    /// Calls of the walk held back: client work of the shard seen now, within the gap after it, another queue of the
    /// device not quiet; calls that ran a unit.
    pub gate_client: u64,
    pub gate_gap: u64,
    pub gate_dev: u64,
    pub units: u64,
}

/// One compressed chunk of the object being read: physical address and blocks, chunk start and span, window records,
/// logical blocks in its records.
struct Chunk {
    pba: u64,
    len: u32,
    cs: u64,
    raw: u32,
    views: u32,
    live: u64,
}

struct ObjWalk {
    oid: Ghobject,
    cur: ScanCursor,
    recs: u64,
    plain: u64,
    /// Plain records `(first logical block, blocks)`, ascending.
    plains: Vec<(u64, u32)>,
    chunks: Vec<Chunk>,
}

/// A range to stage: first block, blocks, the pool's compression for a range of plain records (`None` = a cut chunk,
/// compressed again with its own algorithm).
type Cand = (u64, u32, Option<CompSpec>);

/// Walk state of one shard.
#[derive(Default)]
pub(crate) struct Rc {
    /// A sweep is wanted at the next check (after mount, after a census request).
    want: bool,
    /// The next / running sweep walks every collection (census request).
    all: bool,
    active: bool,
    /// `ObjStats::comp_windows` when the running sweep started.
    wins0: u64,
    next_ns: u64,
    /// Compression of the pools that compress without a client hint (`Store::set_pool_comp`).
    pub(crate) pools: Vec<(u64, CompSpec)>,
    /// Collections of the sweep: (collection, id, holds compressed data, its pool's compression).
    colls: Vec<(CollT, u64, bool, Option<CompSpec>)>,
    ci: usize,
    ccur: Option<ScanCursor>,
    ncur: Option<ScanCursor>,
    long: bool,
    coll: Option<(CollT, bool, Option<CompSpec>)>,
    objs: VecDeque<(Ghobject, u64)>,
    obj: Option<ObjWalk>,
    /// Ranges of `cand_obj` (the object read last) still to stage.
    cands: VecDeque<Cand>,
    cand_obj: Option<(CollT, Ghobject)>,
    cur: Census,
    pub(crate) census: Census,
    pub(crate) census_seq: u64,
    /// Last time the shard had client work.
    busy_ns: u64,
    /// The walk's own IO (page loads, data reads, a chunk txn) may be in flight: a busy queue is not client work.
    io: bool,
    /// A scan of the running sweep failed (not a cold page): its census would be partial, it is not published and the
    /// next change or census request starts a new sweep.
    incomplete: bool,
    /// A refused staging keeps its completed data reads (read session, reader pin) for the next try.
    held: bool,
    /// LSN of the walk's last chunk txn.
    lsn: u64,
    seq: u64,
    pub(crate) stats: RcStats,
}

impl Rc {
    pub(crate) fn new() -> Rc {
        Rc {
            want: true,
            ..Default::default()
        }
    }

    /// Walk every collection in the next sweep (census of uncompressed data too).
    pub(crate) fn request_census(&mut self) {
        self.want = true;
        self.all = true;
    }
}

enum Unit {
    /// More to do at the next call.
    Next,
    /// IO of the walk in flight: wait for it.
    Io,
    Done,
}

/// Ghobject of a name-index key (`N` / `L`), `None` when the key is not one: shorter than the collection prefix or its
/// body does not decode. The walk skips such a key like any other entry that does not decode.
fn decode_name(k: &[u8], long: bool) -> Option<Ghobject> {
    let body = k.get(9..)?;
    if long {
        decode_long_key(body)
    } else {
        decode_sort_key(body)
    }
}

impl<D: BlockDev> ShardStore<D> {
    /// The walk may run now; stamps client work (see the module doc). Client work is seen where it is known for sure: a
    /// parked or foreign txn, a client read (prefetch run, rolling read of another session); the shard's own queue counts
    /// only while the walk has no IO of its own (a busy queue next to the walk's IO cannot tell whose it is, and must
    /// not mask client reads that the read state already shows).
    fn rc_may_run(&mut self, now: u64) -> bool {
        let pending = self.sh.pending_units() > 0;
        let own_txn = pending && self.rc.lsn + 1 == self.sh.next_lsn();
        let queue = self.sh.queue_busy();
        if pending && !own_txn || !self.reads_idle(RC_SESSION) || queue && !self.rc.io {
            self.rc.busy_ns = now;
            self.rc.stats.gate_client += 1;
            if self.rc.io && (pending || queue) {
                self.rc.stats.overlaps += 1;
            }
            if self.rc.held {
                // client work: give the read slot and the reader pin of a refused staging back, it reads again later
                self.rc.held = false;
                let old = self.session_context();
                self.read_session(Some((RC_SESSION, self.idx as u64)), true);
                self.read_session(None, false);
                self.restore_session(old);
            }
            return false;
        }
        if self.rc.io {
            if pending || queue {
                return false;
            }
            self.rc.io = false;
        }
        if now < self.rc.busy_ns.saturating_add(GAP_NS) {
            self.rc.stats.gate_gap += 1;
            return false;
        }
        if !self.sh.dev_quiet(now) {
            self.rc.stats.gate_dev += 1;
            return false;
        }
        true
    }

    fn rc_start(&mut self) {
        let r = &mut self.rc;
        r.active = true;
        r.want = false;
        r.wins0 = self.stats.comp_windows;
        r.colls.clear();
        r.ci = 0;
        r.ccur = Some(ScanCursor::new(&[T_COLL], &[T_COLL + 1]).listing());
        r.ncur = None;
        r.coll = None;
        r.objs.clear();
        r.obj = None;
        r.cands.clear();
        r.cand_obj = None;
        r.cur = Census::default();
        r.incomplete = false;
    }

    fn rc_finish(&mut self) {
        let r = &mut self.rc;
        r.active = false;
        if r.incomplete {
            // a scan failed: the census is partial, publish nothing. No automatic rerun: the tree keeps a failed page
            // bad, a rerun would fail the same way and rescan every healthy object; a new change or census request
            // starts the next sweep
            r.incomplete = false;
            r.stats.incomplete += 1;
            r.want |= self.stats.comp_windows != r.wins0;
            return;
        }
        r.all = false;
        r.census = r.cur;
        r.census_seq += 1;
        r.stats.sweeps += 1;
        // windows cut while the sweep ran (client overwrites): another sweep at the next check
        r.want |= self.stats.comp_windows != r.wins0;
    }

    /// Next scan unit of the walk (collections, names, one object's records).
    fn rc_scan(&mut self) -> Unit {
        if let Some(mut w) = self.rc.obj.take() {
            let mut found: Vec<(u64, Vec<u8>)> = Vec::new();
            let r = self
                .sh
                .scan(&mut w.cur, SCAN_BATCH, usize::MAX, &mut |k, v| {
                    if k.len() == 14 {
                        found.push((
                            u32::from_be_bytes(k[10..14].try_into().unwrap()) as u64,
                            v.to_vec(),
                        ));
                    }
                });
            for (lblk, v) in found {
                let Some(e) = ExtRaw::new(&v) else { continue };
                w.recs += 1;
                match e.comp() {
                    None => {
                        w.plain += e.len() as u64;
                        w.plains.push((lblk, e.len()));
                    }
                    Some(m) => match w.chunks.iter_mut().find(|c| c.pba == e.pba()) {
                        Some(c) => {
                            c.views += u32::from(m.is_view());
                            c.live += m.win as u64;
                        }
                        None => w.chunks.push(Chunk {
                            pba: e.pba(),
                            len: e.len(),
                            cs: lblk - m.skip as u64,
                            raw: m.raw_blks as u32,
                            views: u32::from(m.is_view()),
                            live: m.win as u64,
                        }),
                    },
                }
            }
            return match r {
                Ok(ScanStatus::More) => {
                    self.rc.obj = Some(w);
                    Unit::Next
                }
                Err(StoreError::Miss) => {
                    self.rc.obj = Some(w);
                    Unit::Io
                }
                Ok(ScanStatus::Done) => {
                    self.rc_obj_done(w);
                    Unit::Next
                }
                Err(_) => {
                    // unreadable leaf: the census would be partial
                    self.rc.incomplete = true;
                    Unit::Next
                }
            };
        }
        if let Some((oid, id)) = self.rc.objs.pop_front() {
            let (a, b) = id_range(super::keys::T_EXT, id);
            self.rc.obj = Some(ObjWalk {
                oid,
                cur: ScanCursor::new(&a, &b).listing(),
                recs: 0,
                plain: 0,
                plains: Vec::new(),
                chunks: Vec::new(),
            });
            return Unit::Next;
        }
        if let Some(mut cur) = self.rc.ncur.take() {
            let long = self.rc.long;
            let mut found: Vec<(Ghobject, u64)> = Vec::new();
            let r = self.sh.scan(&mut cur, SCAN_BATCH, usize::MAX, &mut |k, v| {
                if let (Some(g), Ok(id)) = (decode_name(k, long), <[u8; 8]>::try_from(v)) {
                    found.push((g, u64::from_le_bytes(id)));
                }
            });
            self.rc.objs.extend(found);
            match r {
                Ok(ScanStatus::More) => self.rc.ncur = Some(cur),
                Err(StoreError::Miss) => {
                    self.rc.ncur = Some(cur);
                    return Unit::Io;
                }
                r => {
                    if r.is_err() {
                        self.rc.incomplete = true; // unreadable leaf: the census would be partial
                    }
                    if !long {
                        // then the long-name index of the collection
                        let cn = self.rc.colls[self.rc.ci - 1].1;
                        self.rc.long = true;
                        self.rc.ncur =
                            Some(ScanCursor::new(&long_prefix(cn), &long_end(cn)).listing());
                    }
                }
            }
            return Unit::Next;
        }
        if let Some(mut cur) = self.rc.ccur.take() {
            let all = self.rc.all;
            let pools = &self.rc.pools;
            let mut found: Vec<(CollT, u64, bool, Option<CompSpec>)> = Vec::new();
            let r = self.sh.scan(&mut cur, SCAN_BATCH, usize::MAX, &mut |k, v| {
                if let (Some(c), Some(i)) = (decode_coll_key(k), CollInfo::decode(v)) {
                    let spec = match c {
                        CollT::Pg(s) | CollT::PgTemp(s) => {
                            pools.iter().find(|p| p.0 == s.pgid.pool).map(|p| p.1)
                        }
                        CollT::Meta => None,
                    };
                    if c != CollT::Meta && (all || i.comp > 0 || spec.is_some()) {
                        found.push((c, i.id, i.comp > 0 || spec.is_some(), spec));
                    }
                }
            });
            self.rc.colls.extend(found);
            return match r {
                Ok(ScanStatus::More) => {
                    self.rc.ccur = Some(cur);
                    Unit::Next
                }
                Err(StoreError::Miss) => {
                    self.rc.ccur = Some(cur);
                    Unit::Io
                }
                Err(_) => {
                    // unreadable leaf: the census would be partial
                    self.rc.incomplete = true;
                    Unit::Next
                }
                Ok(ScanStatus::Done) => Unit::Next,
            };
        }
        if self.rc.ci < self.rc.colls.len() {
            let (c, cn, comp, spec) = self.rc.colls[self.rc.ci];
            self.rc.ci += 1;
            self.rc.coll = Some((c, comp, spec));
            self.rc.long = false;
            self.rc.ncur = Some(
                ScanCursor::new(&name_prefix(cn), &name_end(cn))
                    .listing()
                    .with_readahead(8),
            );
            return Unit::Next;
        }
        Unit::Done
    }

    /// Census of one object's records. Candidates: its cut chunks that span exactly one aligned chunk, and (pool that
    /// compresses) every aligned chunk range made only of plain records, at least two of them (small overwrites and space
    /// rule merges stored raw; a range written as one plain record was judged by its write).
    fn rc_obj_done(&mut self, w: ObjWalk) {
        let Some((coll, comp, spec)) = self.rc.coll else {
            return;
        };
        if w.recs == 0 {
            return;
        }
        let c = &mut self.rc.cur;
        if !comp && w.chunks.is_empty() {
            c.unc_objects += 1;
            c.unc_records += w.recs;
            c.unc_blocks += w.plain;
            return;
        }
        c.objects += 1;
        c.records += w.recs;
        c.plain_blocks += w.plain;
        for k in &w.chunks {
            c.chunks += 1;
            c.chunk_blocks += k.len as u64;
            c.comp_logical += k.live;
            c.windows += k.views as u64;
            if k.views > 0 {
                c.cut_chunks += 1;
                c.cut_live += k.live;
                c.cut_span += k.raw as u64;
            }
        }
        self.rc.cands.extend(
            w.chunks
                .iter()
                .filter(|k| k.views > 0 && k.cs.is_multiple_of(k.raw as u64))
                .map(|k| (k.cs, k.raw, None)),
        );
        if let Some(sp) = spec
            && let Some(n) = sp.chunk_blocks()
        {
            // aligned ranges: (first block, plain blocks in it, plain records touching it)
            let mut acc: Option<(u64, u64, u32)> = None;
            let mut ranges: Vec<(u64, u64, u32)> = Vec::new();
            for &(s, len) in &w.plains {
                let e = s + len as u64;
                let mut r0 = s - s % n;
                while r0 < e {
                    let blocks = e.min(r0 + n) - s.max(r0);
                    match &mut acc {
                        Some(a) if a.0 == r0 => {
                            a.1 += blocks;
                            a.2 += 1;
                        }
                        _ => {
                            ranges.extend(acc.take());
                            acc = Some((r0, blocks, 1));
                        }
                    }
                    r0 += n;
                }
            }
            ranges.extend(acc);
            let chunked = |r0: u64| {
                w.chunks
                    .iter()
                    .any(|k| k.cs < r0 + n && r0 < k.cs + k.raw as u64)
            };
            self.rc.cands.extend(
                ranges
                    .into_iter()
                    .filter(|&(r0, b, recs)| b == n && recs >= 2 && !chunked(r0))
                    .map(|(r0, _, _)| (r0, n as u32, Some(sp))),
            );
        }
        if !self.rc.cands.is_empty() {
            self.rc.cand_obj = Some((coll, w.oid));
        }
    }
}

impl<D: BlockDev, C: Clock> Store<D, C> {
    /// One step of the idle walk of shard `si` (call between txns, with its parked queue empty).
    pub(crate) fn rc_step(&mut self, si: usize, now: u64) {
        let s = &mut self.shards[si];
        if s.sh.is_failed() || !s.rc_may_run(now) {
            return;
        }
        if !s.rc.active {
            if now < s.rc.next_ns {
                return;
            }
            s.rc.next_ns = now + CHECK_NS;
            if !(s.rc.want || s.stats.comp_windows != s.rc.wins0) {
                return;
            }
            s.rc_start();
        }
        s.rc.stats.units += 1;
        // one unit per call: a scan batch, or one candidate staged
        if s.rc.cands.is_empty() {
            match s.rc_scan() {
                Unit::Next => {}
                Unit::Io => s.rc.io = true,
                Unit::Done => s.rc_finish(),
            }
            return;
        }
        let (cs, raw, spec) = *s.rc.cands.front().expect("non-empty");
        let (c, oid) = s.rc.cand_obj.take().expect("candidates have their object");
        let u = self.rc_chunk(si, &c, &oid, (cs, raw, spec));
        let r = &mut self.shards[si].rc;
        match u {
            Unit::Io => r.io = true,
            Unit::Next | Unit::Done => {
                r.cands.pop_front();
            }
        }
        if !r.cands.is_empty() {
            r.cand_obj = Some((c, oid));
        }
    }

    /// Stage and submit the recompaction of one candidate. `Io` = it waits for a read, a page or device room (staged again
    /// later, from the start); `Done` = submitted or dropped.
    fn rc_chunk(&mut self, si: usize, c: &CollT, oid: &Ghobject, (cs, raw, spec): Cand) -> Unit {
        let s = &mut self.shards[si];
        s.rc.seq += 1;
        let token = RC_ACK | s.rc.seq;
        s.nonblock = true;
        let old = s.session_context();
        s.read_session(Some((RC_SESSION, s.idx as u64)), true);
        let ok0 = s.stats.comp_ok;
        let mut st = Stage::new(s, &mut self.clk);
        let r = match st.recompact(c, oid, cs, raw, spec) {
            Ok(RcOut::Staged { freed, phys }) => st.finish(token).map(|b| Some((b, freed, phys))),
            Ok(o) => {
                drop(st);
                let s = &mut self.shards[si];
                match o {
                    RcOut::NoGain => s.rc.stats.no_gain += 1,
                    _ => s.rc.stats.skipped += 1,
                }
                Ok(None)
            }
            Err(e) => {
                drop(st);
                Err(e)
            }
        };
        let s = &mut self.shards[si];
        s.nonblock = false;
        let blocked = matches!(r, Err(ObjError::WouldBlock));
        // a refused run keeps its completed reads for the next try (same session); anything else releases them
        s.read_session(None, blocked);
        s.restore_session(old);
        s.rc.held = blocked;
        let (b, freed, phys) = match r {
            Ok(Some(x)) => x,
            Ok(None) => return Unit::Done,
            Err(ObjError::WouldBlock) => return Unit::Io,
            Err(_) => {
                s.rc.stats.skipped += 1;
                return Unit::Done;
            }
        };
        let txn = b.txn;
        if s.stats.comp_ok != ok0 + 1 {
            // the chunk found no contiguous room and was staged raw: that would cost more than it saves
            s.sh.unreserve_txn(&txn);
            s.rc.stats.skipped += 1;
            return Unit::Done;
        }
        s.forget_freed(&txn.frees);
        match s.sh.submit(txn) {
            Ok(lsn) => {
                for i in 0..s.scratch.ids.len() {
                    let id = s.scratch.ids[i];
                    s.note_write(id, lsn);
                }
                s.rc.lsn = lsn;
                s.rc.io = true;
                let st = &mut s.rc.stats;
                st.chunks += 1;
                st.freed_blocks += freed;
                st.new_blocks += phys;
                Unit::Done
            }
            Err((StoreError::Busy | StoreError::WalFull | StoreError::Miss, txn)) => {
                s.sh.unreserve_txn(&txn);
                Unit::Io
            }
            Err((_, txn)) => {
                s.sh.unreserve_txn(&txn);
                s.rc.stats.skipped += 1;
                Unit::Done
            }
        }
    }

    /// Compression of `pool` for idle recompaction (adr 0533): `spec` = what a write without client hints
    /// would use (`PoolComp::resolve(0)`; `None` = the pool does not compress then). Ranges of plain records in such a
    /// pool are compressed by the idle walk too. A spec with `chunk_blks == 0` describes no chunk and is refused (the
    /// walk takes the chunk size as the divisor of a logical range).
    pub fn set_pool_comp(&mut self, pool: u64, spec: Option<CompSpec>) {
        let spec = spec.filter(|s| s.chunk_blocks().is_some());
        for s in &mut self.shards {
            let p = &mut s.rc.pools;
            p.retain(|x| x.0 != pool);
            if let Some(sp) = spec {
                p.push((pool, sp));
                s.rc.want = true;
            }
        }
    }

    /// Walk every collection of every mounted shard in the next sweep (extent census, adr 0533); the
    /// result appears in `perf_counters` (`census_*`, `census_seq` + 1 per shard) once the device was idle long enough.
    pub fn request_census(&mut self) {
        for s in &mut self.shards {
            s.rc.request_census();
        }
    }

    /// Defrag counters and drain waits of the mounted shards ([`DefragStats::merged`]).
    pub fn defrag_stats(&self) -> super::DefragStats {
        self.shards
            .iter()
            .fold(super::DefragStats::default(), |a, s| {
                a.merged(&s.defrag_stats())
            })
    }

    /// Census of the last complete sweep summed over the mounted shards, and the sum of their sweep sequence numbers.
    pub fn census(&self) -> (Census, u64) {
        self.shards
            .iter()
            .fold((Census::default(), 0), |(a, n), s| {
                let c = &s.rc.census;
                (
                    Census {
                        objects: a.objects + c.objects,
                        records: a.records + c.records,
                        plain_blocks: a.plain_blocks + c.plain_blocks,
                        chunks: a.chunks + c.chunks,
                        chunk_blocks: a.chunk_blocks + c.chunk_blocks,
                        comp_logical: a.comp_logical + c.comp_logical,
                        windows: a.windows + c.windows,
                        cut_chunks: a.cut_chunks + c.cut_chunks,
                        cut_live: a.cut_live + c.cut_live,
                        cut_span: a.cut_span + c.cut_span,
                        unc_objects: a.unc_objects + c.unc_objects,
                        unc_records: a.unc_records + c.unc_records,
                        unc_blocks: a.unc_blocks + c.unc_blocks,
                    },
                    n + s.rc.census_seq,
                )
            })
    }

    /// Recompaction counters summed over the mounted shards.
    pub fn rc_stats(&self) -> RcStats {
        self.shards.iter().fold(RcStats::default(), |a, s| {
            let t = &s.rc.stats;
            RcStats {
                sweeps: a.sweeps + t.sweeps,
                chunks: a.chunks + t.chunks,
                freed_blocks: a.freed_blocks + t.freed_blocks,
                new_blocks: a.new_blocks + t.new_blocks,
                no_gain: a.no_gain + t.no_gain,
                skipped: a.skipped + t.skipped,
                incomplete: a.incomplete + t.incomplete,
                overlaps: a.overlaps + t.overlaps,
                gate_client: a.gate_client + t.gate_client,
                gate_gap: a.gate_gap + t.gate_gap,
                gate_dev: a.gate_dev + t.gate_dev,
                units: a.units + t.units,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::decode_name;
    use crate::BLK;
    use crate::compress::{Alg, CompSpec};
    use crate::dev::{BlockDev, SimClock, SimConfig, SimDev, SimDisk};
    use crate::devidle::DevIdle;
    use crate::layout::{MkfsParams, mkfs};
    use crate::obj::{OTxn, Store, StoreCfg};
    use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
    use std::sync::Arc;

    fn idle_for(st: &mut Store<SimDev, SimClock>, ns: u64) {
        let end = st.clk.t + ns;
        let mut a = Vec::new();
        while st.clk.t < end {
            st.poll(&mut a).unwrap();
            if st
                .shards
                .iter_mut()
                .any(|s| s.sh.dev().next_deadline().is_some())
            {
                st.idle();
            } else {
                st.clk.t += 100_000;
            }
        }
    }

    /// A name-index key shorter than the collection prefix (a corrupt but crc-valid page can yield one) is skipped, never
    /// a panic inside `Store::poll`.
    #[test]
    fn short_name_key_is_skipped() {
        let g = Ghobject::new(
            Hobject::new(b"obj", SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        );
        let k = crate::obj::keys::name_key_of(1, &g);
        assert_eq!(decode_name(&k, false), Some(g));
        for k in [&b"N"[..], b"abc", b"N\x00\x00\x00\x00\x00\x00\x00"] {
            assert!(decode_name(k, false).is_none(), "{k:?}");
            assert!(decode_name(k, true).is_none(), "{k:?}");
        }
    }

    /// A sweep whose scan failed (not a cold page) must not publish a partial census: the counters drive operator
    /// decisions and `request_census`; no automatic rerun (the failed page stays bad), a new request sweeps again.
    #[test]
    fn failed_scan_does_not_publish_a_partial_census() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
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
            Hobject::new(b"census", SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        );
        let mut t = OTxn::new();
        t.mkcoll(c);
        let data = vec![7u8; 16 * BLK];
        t.write(c, &o, 0, &data);
        st.commit(&t).unwrap();
        st.checkpoint().unwrap();
        st.request_census();
        // every tree page read fails: the sweep cannot see the collection
        assert!(st.shards[0].sh.drop_tree_clean().0 > 0);
        let cfg = disk.config();
        disk.fail_reads(0, cfg.lba_count);
        idle_for(&mut st, 3_000_000_000);
        let (census, seq) = st.census();
        assert_eq!(seq, 0, "a partial census was published: {census:?}");
        assert_eq!(st.rc_stats().sweeps, 0);
        assert!(st.rc_stats().incomplete > 0, "{:?}", st.rc_stats());
        assert!(
            !st.shards[0].rc.want,
            "no automatic rerun over a page the tree keeps bad"
        );
        // the failed page reads stay failed for their addresses (the tree marks them bad); a mount reads again and the
        // sweep publishes a complete census
        disk.clear_faults();
        drop(st);
        let (mut st, _) =
            Store::mount(|| disk.queue(), SimClock::default(), StoreCfg::default()).unwrap();
        st.request_census();
        idle_for(&mut st, 3_000_000_000);
        let (census, seq) = st.census();
        assert_eq!(seq, 1, "{census:?}");
        assert_eq!(census.unc_objects, 1, "{census:?}");
    }

    /// A spec that cannot describe a chunk (`chunk_blks == 0`) is refused: the walk divides a range by the chunk size.
    #[test]
    fn zero_chunk_blocks_spec_is_refused() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
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
            Hobject::new(b"plain", SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        );
        let mut t = OTxn::new();
        t.mkcoll(c);
        let data = vec![3u8; 16 * BLK];
        t.write(c, &o, 0, &data);
        st.commit(&t).unwrap();
        st.set_pool_comp(
            1,
            Some(CompSpec {
                alg: Alg::Lz4,
                ratio_permille: 875,
                min_bytes: 8192,
                chunk_blks: 0,
            }),
        );
        st.request_census();
        idle_for(&mut st, 3_000_000_000);
        assert!(st.rc_stats().sweeps > 0, "{:?}", st.rc_stats());
        assert_eq!(st.rc_stats().chunks, 0, "{:?}", st.rc_stats());
        assert_eq!(st.census().0.unc_objects, 1, "{:?}", st.census().0);
        // the same spec on a write txn (the other consumer of `CompSpec`): stored raw, no panic
        let o2 = Ghobject::new(
            Hobject::new(b"plain2", SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        );
        let data2 = vec![9u8; 8 * BLK];
        let mut t = OTxn::new();
        t.comp = Some(CompSpec {
            alg: Alg::Lz4,
            ratio_permille: 875,
            min_bytes: 8192,
            chunk_blks: 0,
        });
        t.write(c, &o2, 0, &data2);
        st.commit(&t).unwrap();
        assert_eq!(st.read(&c, &o2, 0, data2.len() as u64).unwrap(), data2);
    }

    /// Another shard's busy queue (device idle signal) holds the walk back; once it drained for the gap, the walk runs.
    #[test]
    fn busy_queue_of_another_shard_holds_recompaction() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        mkfs(
            &mut disk.queue(),
            &mut SimClock::default(),
            &MkfsParams {
                shards: 2,
                wal_blocks: 1024,
                align_blocks: 1,
                meta_pct: 8,
                ..Default::default()
            },
        )
        .unwrap();
        let dev = Arc::new(DevIdle::default());
        let mut cfg = StoreCfg::default();
        cfg.shard.dev_idle = Some(dev.clone());
        // a per-core store with shard 0 only: shard 1's slot is written by nobody but this test
        let (mut st, _) =
            Store::mount_shards(|| disk.queue(), SimClock::default(), cfg, |s| s == 0).unwrap();
        let c = CollT::Pg(SpgT {
            pgid: PgT::new(1, 1),
            shard: ShardId::NO_SHARD,
        });
        assert_eq!(st.shard_of(&c), 0);
        let o = Ghobject::new(
            Hobject::new(b"aged", SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        );
        let comp = Some(CompSpec {
            alg: Alg::Lz4,
            ratio_permille: 875,
            min_bytes: 8192,
            chunk_blks: 16,
        });
        let mut t = OTxn::new();
        t.mkcoll(c);
        st.commit(&t).unwrap();
        // two chunks of half random, half zero blocks; one block of each overwritten with the same kind of block
        let mut d = vec![0u8; 128 << 10];
        for (i, b) in d.chunks_mut(4096).enumerate() {
            crate::rng::Rng::new(i as u64 + 1).fill(&mut b[..2048]);
        }
        let mut t = OTxn::new();
        t.comp = comp;
        t.write(c, &o, 0, &d);
        st.commit(&t).unwrap();
        for blk in [2usize, 20] {
            crate::rng::Rng::new(blk as u64 + 99).fill(&mut d[blk * 4096..blk * 4096 + 2048]);
            let x = d[blk * 4096..(blk + 1) * 4096].to_vec();
            let mut t = OTxn::new();
            t.write(c, &o, (blk * 4096) as u64, &x);
            st.commit(&t).unwrap();
        }
        dev.edge(1, true);
        idle_for(&mut st, 3_000_000_000);
        assert_eq!(st.rc_stats().sweeps, 0, "the device is busy: no walk");
        dev.edge(1, false);
        idle_for(&mut st, 3_000_000_000);
        assert_eq!(st.rc_stats().chunks, 2, "{:?}", st.rc_stats());
        assert_eq!(st.read(&c, &o, 0, 128 << 10).unwrap(), d);
        assert!(st.check(true).unwrap().errors.is_empty());
    }

    /// QD1 client reads on one shard (every ms) hold the walk of every shard of the device; it runs once they stop.
    #[test]
    fn qd1_reads_hold_recompaction_on_every_shard() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        mkfs(
            &mut disk.queue(),
            &mut SimClock::default(),
            &MkfsParams {
                shards: 2,
                wal_blocks: 1024,
                align_blocks: 1,
                meta_pct: 8,
                ..Default::default()
            },
        )
        .unwrap();
        let (mut st, _) =
            Store::mount(|| disk.queue(), SimClock::default(), StoreCfg::default()).unwrap();
        let coll = |seed| {
            CollT::Pg(SpgT {
                pgid: PgT::new(1, seed),
                shard: ShardId::NO_SHARD,
            })
        };
        let g = |n: &[u8]| {
            Ghobject::new(
                Hobject::new(n, SnapId::NOSNAP, 1, 1, b""),
                Ghobject::NO_GEN,
                ShardId::NO_SHARD,
            )
        };
        let (c0, c1) = (coll(1), coll(0));
        assert_eq!((st.shard_of(&c0), st.shard_of(&c1)), (0, 1));
        for c in [c0, c1] {
            let mut t = OTxn::new();
            t.mkcoll(c);
            st.commit(&t).unwrap();
        }
        // shard 0: small plain records of a compressing pool (candidates); shard 1: the object the client reads
        let mut d = vec![0u8; 64 << 10];
        for (i, b) in d.chunks_mut(4096).enumerate() {
            crate::rng::Rng::new(i as u64 + 1).fill(&mut b[..1024]);
        }
        for b in 0..16usize {
            let mut t = OTxn::new();
            t.write(
                c0,
                &g(b"aged"),
                (b * 4096) as u64,
                &d[b * 4096..(b + 1) * 4096],
            );
            st.commit(&t).unwrap();
        }
        let mut t = OTxn::new();
        t.write(c1, &g(b"hot"), 0, &d);
        st.commit(&t).unwrap();
        st.set_pool_comp(
            1,
            Some(CompSpec {
                alg: Alg::Lz4,
                ratio_permille: 875,
                min_bytes: 8192,
                chunk_blks: 16,
            }),
        );
        let end = st.clk.t + 3_000_000_000;
        let mut a = Vec::new();
        let mut blk = 0u64;
        while st.clk.t < end {
            blk = (blk + 1) % 16;
            assert_eq!(
                st.read(&c1, &g(b"hot"), blk * 4096, 4096).unwrap().len(),
                4096
            );
            st.poll(&mut a).unwrap();
            st.clk.t += 1_000_000;
        }
        assert_eq!(
            st.rc_stats().chunks,
            0,
            "reads every ms: {:?}",
            st.rc_stats()
        );
        idle_for(&mut st, 3_000_000_000);
        assert_eq!(st.rc_stats().chunks, 1, "{:?}", st.rc_stats());
    }

    /// Daemon layout: one store per core (`mount_shards`) on one shared device table, each with its own clock. QD1 reads
    /// served by the store of shard 1 hold the walk of the store of shard 0; it runs once they stop.
    #[test]
    fn qd1_reads_of_another_per_core_store_hold_recompaction() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        mkfs(
            &mut disk.queue(),
            &mut SimClock::default(),
            &MkfsParams {
                shards: 2,
                wal_blocks: 1024,
                align_blocks: 1,
                meta_pct: 8,
                ..Default::default()
            },
        )
        .unwrap();
        let dev = Arc::new(DevIdle::default());
        let mount = |me: u32| {
            let mut cfg = StoreCfg::default();
            cfg.shard.dev_idle = Some(dev.clone());
            Store::mount_shards(|| disk.queue(), SimClock::default(), cfg, move |s| s == me)
                .unwrap()
                .0
        };
        let (mut walker, mut reader) = (mount(0), mount(1));
        let coll = |seed| {
            CollT::Pg(SpgT {
                pgid: PgT::new(1, seed),
                shard: ShardId::NO_SHARD,
            })
        };
        let g = |n: &[u8]| {
            Ghobject::new(
                Hobject::new(n, SnapId::NOSNAP, 1, 1, b""),
                Ghobject::NO_GEN,
                ShardId::NO_SHARD,
            )
        };
        let (c0, c1) = (coll(1), coll(0));
        assert_eq!((walker.shard_of(&c0), reader.shard_of(&c1)), (0, 1));
        for (st, c) in [(&mut walker, c0), (&mut reader, c1)] {
            let mut t = OTxn::new();
            t.mkcoll(c);
            st.commit(&t).unwrap();
        }
        let mut d = vec![0u8; 64 << 10];
        for (i, b) in d.chunks_mut(4096).enumerate() {
            crate::rng::Rng::new(i as u64 + 1).fill(&mut b[..1024]);
        }
        for b in 0..16usize {
            let mut t = OTxn::new();
            t.write(
                c0,
                &g(b"aged"),
                (b * 4096) as u64,
                &d[b * 4096..(b + 1) * 4096],
            );
            walker.commit(&t).unwrap();
        }
        let mut t = OTxn::new();
        t.write(c1, &g(b"hot"), 0, &d);
        reader.commit(&t).unwrap();
        walker.set_pool_comp(
            1,
            Some(CompSpec {
                alg: Alg::Lz4,
                ratio_permille: 875,
                min_bytes: 8192,
                chunk_blks: 16,
            }),
        );
        let mut a = Vec::new();
        let mut blk = 0u64;
        for _ in 0..3000 {
            blk = (blk + 1) % 16;
            assert_eq!(
                reader
                    .read(&c1, &g(b"hot"), blk * 4096, 4096)
                    .unwrap()
                    .len(),
                4096
            );
            reader.poll(&mut a).unwrap();
            walker.poll(&mut a).unwrap();
            reader.clk.t += 1_000_000;
            walker.clk.t += 1_000_000;
        }
        assert_eq!(
            walker.rc_stats().chunks,
            0,
            "reads every ms on another core's store: {:?}",
            walker.rc_stats()
        );
        assert!(
            walker.rc_stats().gate_dev > 0,
            "the other store's queue edges were seen: {:?}",
            walker.rc_stats()
        );
        idle_for(&mut walker, 3_000_000_000);
        assert_eq!(walker.rc_stats().chunks, 1, "{:?}", walker.rc_stats());
    }
}
