// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Lending table of the shared chunk pool (adr 0021 am. 49, elastic shards step 2; cargo feature `elastic`).
//!
//! The pool = the chunks behind the base of every shard region (`ShardDir::data_blocks` .. whole chunks of the region),
//! `per` chunks per region, pool index `p = region * per + k` (k = 0 adjacent to the base). One entry per pool chunk:
//! free, or `(owner shard, slot)`: borrowed slot `slot` of shard `owner` (its allocator places slot `k` at relative
//! chunk `base + k`, so the persisted bitmap of the shard keeps its meaning across grants and returns).
//!
//! On disk: table blocks right behind the shard directory, two copies per block (`table_blk + 2 * b + copy`), each
//! `magic u32 | block u32 | gen u64 | LEND_EPB x (owner u16 | 0 u16 | slot u32) | crc32c u32` (crc over the bytes
//! before it). A change rewrites ONE block: the copy that does not hold the newest generation gets gen + 1 (A/B like
//! the root slots); mount takes the valid copy with the higher gen per block. A torn or lost write leaves the previous
//! generation: the change did not happen. Grant/return each change one entry = one block write, durable before the
//! shard uses the chunk (grant) or after it proved the chunk unused since its newest durable checkpoint (return).

use crate::BLK;
use crate::alloc::HOLE;
use crate::dev::{BlockDev, Clock, IoBuf};
use crate::error::{Result, StoreError};
use crate::layout::{LEND_EPB, ShardDir, Superblock};
use crate::sio::Sio;

pub const LEND_MAGIC: u32 = 0x444e_454c; // "LEND"
const HDR: usize = 16;
const EPB: usize = LEND_EPB as usize;
const CRC_AT: usize = HDR + EPB * 8;
/// `Entry::owner` of a free chunk.
pub const FREE: u16 = u16::MAX;

/// One pool chunk: free (`owner == FREE`, slot 0) or borrowed slot `slot` of shard `owner`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub owner: u16,
    pub slot: u32,
}

impl Entry {
    pub const FREE: Entry = Entry {
        owner: FREE,
        slot: 0,
    };
    pub fn is_free(&self) -> bool {
        self.owner == FREE
    }
}

/// Where the pool chunks and the table live (derived from the superblock and the directory, nothing extra stored).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Geom {
    pub table_blk: u64,
    pub table_blocks: u64,
    pub chunk: u64,
    /// Base chunks per region (the pool starts behind them).
    pub base: u64,
    /// Pool chunks per region.
    pub per: u64,
    /// `data_start` of each region (shard order).
    pub data_start: Vec<u64>,
}

impl Geom {
    pub fn of(sb: &Superblock, dirs: &[ShardDir]) -> Result<Geom> {
        let bad = |m: &str| Err(StoreError::Corrupt(format!("lending table geometry: {m}")));
        let c = sb.chunk_blocks;
        let d0 = dirs
            .first()
            .ok_or(StoreError::Corrupt("no shards".into()))?;
        let full = |d: &ShardDir| (d.region_start + d.region_blocks - d.data_start) / c;
        let (base, per) = (d0.data_blocks / c, full(d0) - d0.data_blocks / c);
        if dirs
            .iter()
            .any(|d| d.data_blocks / c != base || full(d) - base != per)
        {
            return bad("regions differ");
        }
        let table_blk = sb.dir_blk + sb.dir_blocks as u64;
        let table_blocks = (dirs.len() as u64 * per).div_ceil(LEND_EPB);
        if table_blk + 2 * table_blocks > d0.region_start {
            return bad("table overlaps the first region");
        }
        Ok(Geom {
            table_blk,
            table_blocks,
            chunk: c,
            base,
            per,
            data_start: dirs.iter().map(|d| d.data_start).collect(),
        })
    }

    /// Pool chunks of the device.
    pub fn pool(&self) -> u64 {
        self.data_start.len() as u64 * self.per
    }
    /// Engine block of pool chunk `p`.
    pub fn phys(&self, p: u64) -> u64 {
        self.data_start[(p / self.per) as usize] + (self.base + p % self.per) * self.chunk
    }
    /// Pool chunk starting at engine block `phys`.
    pub fn index_of(&self, phys: u64) -> Option<u64> {
        let r = self
            .data_start
            .partition_point(|&s| s <= phys)
            .checked_sub(1)?;
        let off = phys - self.data_start[r];
        if !off.is_multiple_of(self.chunk) {
            return None;
        }
        let k = (off / self.chunk).checked_sub(self.base)?;
        (k < self.per).then_some(r as u64 * self.per + k)
    }
    /// Block address of copy `c` (0/1) of table block `b`.
    pub fn copy_addr(&self, b: u64, c: u64) -> u64 {
        self.table_blk + 2 * b + c
    }
}

/// Entries of a loaded table: owners are shards, a shard's slots are distinct and below the pool size (a shard can
/// never borrow more chunks than the pool has; `Lending::slots` sizes a vector by the highest slot).
fn check_entries(ent: &[Entry], nshards: u32) -> Result<()> {
    let bad = |m: String| Err(StoreError::Corrupt(format!("lending table: {m}")));
    let mut seen: Vec<std::collections::HashSet<u32>> = vec![Default::default(); nshards as usize];
    for (p, e) in ent.iter().enumerate() {
        if e.is_free() {
            if e.slot != 0 {
                return bad(format!("chunk {p}: free entry with a slot"));
            }
            continue;
        }
        if e.owner as u32 >= nshards {
            return bad(format!("chunk {p}: owner {} is no shard", e.owner));
        }
        if e.slot as usize >= ent.len() {
            return bad(format!(
                "chunk {p}: shard {} slot {} beyond the pool ({} chunks)",
                e.owner,
                e.slot,
                ent.len()
            ));
        }
        if !seen[e.owner as usize].insert(e.slot) {
            return bad(format!(
                "chunk {p}: shard {} slot {} used twice",
                e.owner, e.slot
            ));
        }
    }
    Ok(())
}

pub(crate) fn encode(b: u64, seq: u64, ents: &[Entry]) -> Vec<u8> {
    let mut v = vec![0u8; BLK];
    v[0..4].copy_from_slice(&LEND_MAGIC.to_le_bytes());
    v[4..8].copy_from_slice(&(b as u32).to_le_bytes());
    v[8..16].copy_from_slice(&seq.to_le_bytes());
    for (i, e) in ents.iter().enumerate() {
        let o = HDR + i * 8;
        v[o..o + 2].copy_from_slice(&e.owner.to_le_bytes());
        v[o + 4..o + 8].copy_from_slice(&e.slot.to_le_bytes());
    }
    // entries past the pool (last block) are free
    for i in ents.len()..EPB {
        let o = HDR + i * 8;
        v[o..o + 2].copy_from_slice(&FREE.to_le_bytes());
    }
    let c = crate::codec::crc(&v[..CRC_AT]);
    v[CRC_AT..CRC_AT + 4].copy_from_slice(&c.to_le_bytes());
    v
}

/// `(gen, entries)` of a valid copy of table block `b`.
fn decode(v: &[u8], b: u64) -> Option<(u64, Vec<Entry>)> {
    let u32_at = |o: usize| denc::le::rd_u32(v, o);
    if v.len() < BLK
        || u32_at(0) != LEND_MAGIC
        || u32_at(4) as u64 != b
        || u32_at(CRC_AT) != crate::codec::crc(&v[..CRC_AT])
    {
        return None;
    }
    let seq = denc::le::rd_u64(v, 8);
    let ents = (0..EPB)
        .map(|i| {
            let o = HDR + i * 8;
            Entry {
                owner: denc::le::rd_u16(v, o),
                slot: u32_at(o + 4),
            }
        })
        .collect();
    Some((seq, ents))
}

/// Write a fresh table (mkfs): copy 0 of every block at gen 1, all free; copy 1 zeroed (invalid).
pub fn format<D: BlockDev, C: Clock>(io: &mut Sio<D, C>, g: &Geom) -> Result<()> {
    let zero = vec![0u8; BLK];
    for b in 0..g.table_blocks {
        let n = (g.pool() - b * LEND_EPB).min(LEND_EPB) as usize;
        let v = encode(b, 1, &vec![Entry::FREE; n]);
        io.write(&[(g.copy_addr(b, 0), &v), (g.copy_addr(b, 1), &zero)])?;
    }
    Ok(())
}

/// In-memory table: entries, per block the newest generation and which copy holds it, per region the chunks
/// available for a grant. `busy` marks a chunk whose change is being written (never on disk; step 3: a request in
/// flight on another core).
#[derive(Clone, Debug)]
pub struct Lending {
    pub geom: Geom,
    ent: Vec<Entry>,
    seq: Vec<u64>,
    newest: Vec<u8>,
    busy: Vec<bool>,
    /// Table blocks with a change in flight (one at a time: the block image carries every entry of the block).
    blk_busy: Vec<bool>,
    avail: Vec<u64>,
    nshards: u32,
    /// Staged changes (chunk, new entry): a slot being granted is taken although the table does not hold it yet.
    pend: Vec<(u64, Entry)>,
    /// A table write failed (the device may hold either generation of that block): no grant until a remount reads what
    /// is there (a later grant in another block could hand the same slot of the same shard out a second time).
    failed: bool,
}

/// A staged one-entry change: write `buf` to block `addr`, then `commit` (durable) or `abort` (failed).
#[derive(Debug)]
pub struct Staged {
    pub p: u64,
    pub e: Entry,
    pub addr: u64,
    pub buf: Vec<u8>,
}

impl Lending {
    /// Read and verify the table: a valid copy per block, owners are shards, every shard's slots distinct.
    pub fn load<D: BlockDev, C: Clock>(
        io: &mut Sio<D, C>,
        sb: &Superblock,
        dirs: &[ShardDir],
    ) -> Result<Lending> {
        let geom = Geom::of(sb, dirs)?;
        let bad = |m: String| Err(StoreError::Corrupt(format!("lending table: {m}")));
        let reqs: Vec<(u64, u32)> = (0..geom.table_blocks)
            .flat_map(|b| [(geom.copy_addr(b, 0), 1), (geom.copy_addr(b, 1), 1)])
            .collect();
        let bufs = io.read(&reqs)?;
        let (mut ent, mut seq, mut newest) = (Vec::new(), Vec::new(), Vec::new());
        for b in 0..geom.table_blocks {
            let a = decode(&bufs[2 * b as usize], b);
            let c = decode(&bufs[2 * b as usize + 1], b);
            let (g, e, which) = match (a, c) {
                (Some(a), Some(c)) if c.0 > a.0 => (c.0, c.1, 1),
                (Some(a), _) => (a.0, a.1, 0),
                (None, Some(c)) => (c.0, c.1, 1),
                (None, None) => return bad(format!("block {b}: no valid copy")),
            };
            let n = (geom.pool() - b * LEND_EPB).min(LEND_EPB) as usize;
            if e[n..].iter().any(|x| !x.is_free()) {
                return bad(format!("block {b}: entry beyond the pool in use"));
            }
            ent.extend_from_slice(&e[..n]);
            seq.push(g);
            newest.push(which);
        }
        let nshards = dirs.len() as u32;
        check_entries(&ent, nshards)?;
        let mut l = Lending {
            busy: vec![false; ent.len()],
            blk_busy: vec![false; seq.len()],
            avail: vec![0; nshards as usize],
            geom,
            ent,
            seq,
            newest,
            nshards,
            pend: Vec::new(),
            failed: false,
        };
        for p in 0..l.ent.len() {
            if l.ent[p].is_free() {
                l.avail[(p as u64 / l.geom.per) as usize] += 1;
            }
        }
        Ok(l)
    }

    pub fn entry(&self, p: u64) -> Entry {
        self.ent[p as usize]
    }

    /// Borrowed chunks of `shard` by slot (engine block, `HOLE` for an unused slot below the highest).
    pub fn slots(&self, shard: u32) -> Vec<u64> {
        let mut v = Vec::new();
        for (p, e) in self.ent.iter().enumerate() {
            if e.owner as u32 == shard {
                let k = e.slot as usize;
                if v.len() <= k {
                    v.resize(k + 1, HOLE);
                }
                v[k] = self.geom.phys(p as u64);
            }
        }
        v
    }

    /// Lowest slot of `shard` not in use and not being granted (a hole first: keeps the shard's region compact).
    pub fn free_slot(&self, shard: u32) -> u32 {
        let mut s = self.slots(shard);
        for &(_, e) in self.pend.iter().filter(|x| x.1.owner as u32 == shard) {
            let k = e.slot as usize;
            if s.len() <= k {
                s.resize(k + 1, HOLE);
            }
            s[k] = 0;
        }
        s.iter().position(|&p| p == HOLE).unwrap_or(s.len()) as u32
    }

    fn grantable(&self, p: u64) -> bool {
        self.ent[p as usize].is_free()
            && !self.busy[p as usize]
            && !self.blk_busy[(p / LEND_EPB) as usize]
    }

    /// The chunk to grant to `shard` (adr 0021 am. 49 / plan design input 2): its own region's pool from the base end
    /// up (adjacent to its base), then the region with the most available chunks (lowest index on a tie), from its far
    /// end (highest address first). None = pool exhausted. O(S + per), not a hot path.
    pub fn pick(&self, shard: u32) -> Option<u64> {
        if self.failed {
            return None;
        }
        let per = self.geom.per;
        let own = shard as u64 * per;
        if self.avail[shard as usize] > 0
            && let Some(p) = (own..own + per).find(|&p| self.grantable(p))
        {
            return Some(p);
        }
        // the fullest region first; one whose free chunks all sit in table blocks with a change in flight has none to
        // grant now: the next region does
        let mut others: Vec<usize> = (0..self.nshards as usize)
            .filter(|&r| r != shard as usize && self.avail[r] > 0)
            .collect();
        others.sort_by_key(|&r| (std::cmp::Reverse(self.avail[r]), r));
        others.into_iter().find_map(|r| {
            let r = r as u64;
            (r * per..(r + 1) * per).rev().find(|&p| self.grantable(p))
        })
    }

    /// Stage `p := e` (grant: a free chunk to `(owner, slot)`; return: `Entry::FREE`): the block image with the change at
    /// the next generation, for the copy that does not hold the newest one. The chunk is busy until `commit` / `abort`.
    /// One change per table block may be in flight (the block image carries every entry of the block).
    pub fn stage(&mut self, p: u64, e: Entry) -> Staged {
        let b = p / LEND_EPB;
        let (lo, hi) = (
            (b * LEND_EPB) as usize,
            (((b + 1) * LEND_EPB) as usize).min(self.ent.len()),
        );
        let mut ents = self.ent[lo..hi].to_vec();
        ents[p as usize - lo] = e;
        assert!(
            !self.blk_busy[b as usize],
            "table block {b}: change in flight"
        );
        assert!(!self.busy[p as usize], "chunk {p}: change in flight");
        self.busy[p as usize] = true;
        self.blk_busy[b as usize] = true;
        self.pend.push((p, e));
        if self.ent[p as usize].is_free() {
            self.avail[(p / self.geom.per) as usize] -= 1;
        }
        let other = 1 - self.newest[b as usize] as u64;
        Staged {
            p,
            e,
            addr: self.geom.copy_addr(b, other),
            buf: encode(b, self.seq[b as usize] + 1, &ents),
        }
    }

    /// The staged write completed (durable): the change is in effect.
    pub fn commit(&mut self, s: &Staged) {
        let (p, b) = (s.p as usize, (s.p / LEND_EPB) as usize);
        self.blk_busy[b] = false;
        self.busy[p] = false;
        self.ent[p] = s.e;
        self.pend.retain(|x| x.0 != s.p);
        self.seq[b] += 1;
        self.newest[b] ^= 1;
        if s.e.is_free() {
            self.avail[p / self.geom.per as usize] += 1;
        }
    }

    /// The staged write failed: memory keeps the old entry (the next write of the block carries it; until then the
    /// device may hold either generation, both are consistent: see the callers).
    pub fn abort(&mut self, s: &Staged) {
        let p = s.p as usize;
        self.pend.retain(|x| x.0 != s.p);
        self.blk_busy[(s.p / LEND_EPB) as usize] = false;
        self.busy[p] = false;
        if self.ent[p].is_free() {
            self.avail[p / self.geom.per as usize] += 1;
        }
    }

    /// The staged write completed with an error: like `abort`, and no grant until a remount (`failed`).
    pub fn fail(&mut self, s: &Staged) {
        self.abort(s);
        self.failed = true;
    }

    /// Available (free, not in flight) chunks per region.
    pub fn avail(&self) -> &[u64] {
        &self.avail
    }

    /// A table write failed: no grant until a remount (`fail`).
    pub fn grants_stopped(&self) -> bool {
        self.failed
    }

    /// Free chunks of the pool not in flight (a grant being written is not counted).
    pub fn free_chunks(&self) -> u64 {
        if self.failed {
            0
        } else {
            self.avail.iter().sum()
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Step 3 (adr 0021 am. 52): requests across cores. Everything below is transport free: the store emits and consumes
// `LendMsg` values, the OSD moves them between cores (`XMsg`).
// ---------------------------------------------------------------------------------------------------------------

/// Cross-core pool message. Shards are device-wide ids; the receiving core is `core_of(shard)` for replies and the pool
/// owner core for requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LendMsg {
    /// Borrower -> pool owner: `shard` wants one chunk. `short`: its allocation failed (a txn waits for it): with the
    /// pool dry the request waits for a chunk another shard gives back on demand (am. 82) instead of a `Deny`.
    Request { shard: u32, short: bool },
    /// Owner -> borrower, after the table write is durable: chunk `phys` is slot `slot` of `shard`. `pool` = free pool
    /// blocks left (lendable-space hint for the borrower's checkpoint trigger and admission).
    Grant {
        shard: u32,
        slot: u32,
        phys: u64,
        pool: u64,
    },
    /// Owner -> borrower: the pool has no chunk now (`pool` = 0).
    Deny { shard: u32, pool: u64 },
    /// Borrower -> pool owner (step 4, am. 57): slot `slot` of `shard` (engine block `phys`) is empty since a durable
    /// checkpoint and already a hole in the shard's allocator: write the free entry. No answer (a lost or failed write
    /// leaves the chunk owned and empty: the shard gets it back at the next mount).
    Return { shard: u32, slot: u32, phys: u64 },
    /// Owner -> borrower that was denied: a return made the pool grow (`pool` free blocks): the pool is open again.
    Grew { shard: u32, pool: u64 },
    /// Owner -> core of `shard`: the pool holds `pool` free blocks now (the store of that core takes it as the hint of
    /// all its shards), and the owner's view of `shard` (am. 82): `spare` = blocks the other shards could give back on
    /// demand (lendable while the pool is dry), `target` = returns asked of `shard` since mount, `prog` = progress of
    /// the evacuations a waiting `shard` waits for. Sent after mount and after every change. Only the hints change: a
    /// shard denied stays closed until `Grew` or its retry.
    Size {
        shard: u32,
        pool: u64,
        spare: u64,
        target: u64,
        prog: u64,
    },
    /// Borrower -> pool owner (am. 82): `shard` could give back `chunks` borrowed chunks now (keeping its own headroom);
    /// `prog` = its evacuation progress (steps, cumulative). Sent when either changed (progress at most once per
    /// reclaim check interval).
    Spare { shard: u32, chunks: u64, prog: u64 },
}

/// Borrower side of one shard (kept in the shard; nothing here runs per write): when to ask, what the shard believes
/// about the pool.
#[derive(Clone, Debug, Default)]
pub struct Ctl {
    /// Elastic pool in use for this shard (`ShardCfg::lend_auto` on a chunked store).
    pub on: bool,
    pub chunk: u64,
    /// Ask when the free blocks above the user reserve drop below this.
    pub wm: u64,
    /// The pool may have chunks (false after a `Deny` until `retry_at`).
    pub open: bool,
    /// The allocation gate failed for lack of space: ask now.
    pub want: bool,
    /// A request is on its way.
    pub inflight: bool,
    pub retry_at: u64,
    pub retry_ns: u64,
    /// Free pool blocks as last reported (lendable space).
    pub pool: u64,
    /// Blocks the other shards could give back on demand (am. 82; owner's `Size`): lendable even while the pool is
    /// dry or closed; a short request waits for them.
    pub spare: u64,
    /// Returns the owner asked of this shard since mount (`Size`): the shard owes `target` - its returns.
    pub target: u64,
    /// Progress of the evacuations this shard waits for (`Size`): a change counts as progress of its parked txns.
    pub prog: u64,
    /// Bumped per reply: parked txns re-evaluate their allocation.
    pub epoch: u64,
    pub requests: u64,
    pub grants: u64,
    pub denies: u64,
}

impl Ctl {
    /// Lendable space the shard can count on: the pool as last reported while it is open, plus what the other shards
    /// could give back on demand.
    pub fn lendable(&self) -> u64 {
        if self.on {
            self.pool_hint() + self.spare
        } else {
            0
        }
    }

    /// The free pool as last reported while it is open (0 otherwise).
    pub fn pool_hint(&self) -> u64 {
        if self.on && self.open { self.pool } else { 0 }
    }

    /// A txn that found no space may park for a chunk: the pool is open, or another shard could give one back.
    pub fn may_wait(&self) -> bool {
        self.on && (self.open || self.spare > 0)
    }

    /// The owner's view of this shard (`Size`). True = the owner asks for more returns than before. A changed `prog`
    /// bumps the epoch: parked txns see the evacuation they wait for progress.
    pub fn view(&mut self, spare: u64, target: u64, prog: u64) -> bool {
        self.spare = spare;
        if prog != self.prog {
            self.prog = prog;
            self.epoch += 1;
        }
        let raised = target > self.target;
        self.target = target;
        raised
    }

    /// Should the shard send a request now? `usable_free` = free blocks above the user reserve. Marks it in flight.
    pub fn need(&mut self, usable_free: u64, now: u64) -> bool {
        if !self.on || self.inflight {
            return false;
        }
        if !self.open {
            // a short shard does not wait out its retry while another shard could give a chunk back (am. 82)
            if now < self.retry_at && !(self.want && self.spare > 0) {
                return false;
            }
            self.open = true;
        }
        if !self.want && usable_free >= self.wm {
            return false;
        }
        self.inflight = true;
        self.requests += 1;
        true
    }

    /// The owner answered. `granted`: a chunk was added to the shard by the caller.
    pub fn reply(&mut self, granted: bool, pool: u64, now: u64) {
        self.inflight = false;
        self.want = false;
        self.pool = pool;
        self.epoch += 1;
        if granted {
            self.open = true;
            self.grants += 1;
        } else {
            self.open = false;
            self.retry_at = now + self.retry_ns;
            self.denies += 1;
        }
    }

    /// The owner reports a grown pool (a chunk came back after this shard was denied): open again at once, parked txns
    /// re-evaluate. A request in flight stays in flight (its answer is still coming).
    pub fn grew(&mut self, pool: u64) {
        self.open = true;
        self.retry_at = 0;
        self.pool = pool;
        self.epoch += 1;
    }
}

/// Pool owner: the only writer of the lending table at runtime. Requests are answered in arrival order; each grant is
/// staged (`Lending::stage`), written asynchronously on the owner's own table queue (one change per table block in
/// flight) and answered only after the write completed (durable on PLP, adr 0008): the borrower never uses a chunk
/// the table does not yet hold. Returns (step 4, am. 57) are written the same way, before waiting requests; a completed
/// return sends `Grew` to every shard denied since the last one.
///
/// Reclaim on demand (am. 82): a short request (its allocation failed) that finds the pool dry waits (`wait`, served
/// before all requests) while chunks are on their way back or another shard reported spare chunks (`Spare`); the owner
/// asks as many returns as chunks are missing (`target` per shard, cumulative, sent in `Size`), largest spare first,
/// and takes surplus asks back once returns from elsewhere cover the waiters. A waiter nobody can serve is denied.
pub struct Pool<D: BlockDev> {
    pub tq: D,
    lpb: u64,
    reqs: std::collections::VecDeque<u32>,
    /// A request of the shard is queued or waiting.
    queued: Vec<bool>,
    /// The queued request of the shard is short.
    short: Vec<bool>,
    /// Short requests waiting for a chunk to come back, in arrival order.
    wait: std::collections::VecDeque<u32>,
    waiting: Vec<bool>,
    /// Returns waiting for their table write: (shard, pool chunk, slot).
    rets: std::collections::VecDeque<(u32, u64, u32)>,
    /// Shards answered `Deny` since the pool last grew (they get `Grew`).
    denied: Vec<bool>,
    fly: Vec<(u64, Staged, u32)>,
    next_tag: u64,
    done: Vec<crate::dev::Completion<D::Buf>>,
    /// Per shard: chunks it could give back and its evacuation progress (its last `Spare`); returns asked of it and
    /// returns received from it since mount (any return counts: owed = `target` - `got`).
    spare: Vec<u64>,
    prog: Vec<u64>,
    target: Vec<u64>,
    got: Vec<u64>,
    /// Bumped on every change of the per-shard views (`view`).
    rev: u64,
    /// Durable returns / returns dropped (entry did not match: never expected).
    pub returns: u64,
    pub bad_returns: u64,
    /// Short requests that waited for a return.
    pub waits: u64,
}

impl<D: BlockDev> Pool<D> {
    pub fn new(tq: D, nshards: u32) -> Pool<D> {
        let lpb = crate::dev::lbas_per_blk(&tq.geometry());
        let n = nshards as usize;
        Pool {
            tq,
            lpb,
            reqs: Default::default(),
            queued: vec![false; n],
            short: vec![false; n],
            wait: Default::default(),
            waiting: vec![false; n],
            rets: Default::default(),
            denied: vec![false; n],
            fly: Vec::new(),
            next_tag: 1,
            done: Vec::new(),
            spare: vec![0; n],
            prog: vec![0; n],
            target: vec![0; n],
            got: vec![0; n],
            rev: 0,
            returns: 0,
            bad_returns: 0,
            waits: 0,
        }
    }

    /// Queue a request of `shard` (a second one while the first is pending only marks it short if it is).
    pub fn request(&mut self, shard: u32, short: bool) {
        let s = shard as usize;
        self.short[s] |= short;
        if !std::mem::replace(&mut self.queued[s], true) {
            self.short[s] = short;
            self.reqs.push_back(shard);
        }
    }

    /// `Spare` of `shard`: an ask beyond what it can give now is taken back (`assign` asks another shard).
    pub fn spare(&mut self, shard: u32, chunks: u64, prog: u64) {
        let s = shard as usize;
        self.spare[s] = chunks;
        self.prog[s] = prog;
        if self.owed(s) > chunks {
            self.target[s] = self.got[s] + chunks;
        }
        self.rev += 1;
    }

    /// Returns still owed by shard `s` (asked, not received).
    fn owed(&self, s: usize) -> u64 {
        self.target[s].saturating_sub(self.got[s])
    }

    /// Chunks shard `s` could still give beyond what it owes (0 while it asks itself).
    fn avail(&self, s: usize) -> u64 {
        if self.queued[s] {
            0
        } else {
            self.spare[s].saturating_sub(self.owed(s))
        }
    }

    /// Change counter of the per-shard views.
    pub fn rev(&self) -> u64 {
        self.rev
    }

    /// The owner's view of `shard` for its `Size` (blocks of a chunk: `chunk`): `(spare, target, prog)`. `spare` =
    /// what the other shards could still give, plus the chunk a waiting shard is getting; `prog` = the givers'
    /// progress for a waiting shard (0 otherwise).
    pub fn view(&self, shard: u32, chunk: u64) -> (u64, u64, u64) {
        let s = shard as usize;
        let others: u64 = (0..self.spare.len())
            .filter(|&g| g != s)
            .map(|g| self.avail(g))
            .sum();
        let w = self.waiting[s];
        let prog = if w { self.prog.iter().sum() } else { 0 };
        ((others + w as u64) * chunk, self.target[s], prog)
    }

    /// Short requests waiting for a return.
    pub fn waiting(&self) -> bool {
        !self.wait.is_empty()
    }

    /// Queue the return of slot `slot` of `shard` at engine block `phys` (the shard made the slot a hole). A chunk the
    /// table does not lend to exactly that slot is ignored (counted): the table stays as it is, which is safe. Either
    /// way the return counts against what the shard owes.
    pub fn give_back(&mut self, l: &Lending, shard: u32, slot: u32, phys: u64) {
        self.got[shard as usize] += 1;
        self.rev += 1;
        match l.geom.index_of(phys) {
            Some(p)
                if l.entry(p)
                    == (Entry {
                        owner: shard as u16,
                        slot,
                    })
                    && !self.rets.iter().any(|r| r.1 == p) =>
            {
                self.rets.push_back((shard, p, slot))
            }
            _ => self.bad_returns += 1,
        }
    }

    /// A shard was denied outside `pump` (blocking gate path): it gets `Grew` when a chunk comes back.
    pub fn note_denied(&mut self, shard: u32) {
        self.denied[shard as usize] = true;
    }

    /// Requests or returns waiting or being written.
    pub fn busy(&self) -> bool {
        !self.reqs.is_empty() || !self.rets.is_empty() || !self.fly.is_empty()
    }

    /// Write one table block; `None` = not submitted (queue full, or no buffer within the DMA budget now: store
    /// metadata IO, adr 0175 am. 4), retried at a later round.
    fn submit(&mut self, st: &Staged) -> Option<u64> {
        let mut b = self.tq.try_alloc_io_uninit(BLK)?;
        b.copy_from_slice(&st.buf);
        let tag = self.next_tag;
        self.next_tag += 1;
        self.tq
            .submit_write(st.addr * self.lpb, b, tag)
            .ok()
            .map(|()| tag)
    }

    /// One round: reap table writes (-> `Grant` / `Deny` / `Grew` into `out`), then start the writes of queued returns
    /// and requests in order. A request whose best chunk sits in a table block with a change in flight waits (order kept);
    /// an empty pool answers `Deny`.
    pub fn pump(&mut self, l: &mut Lending, now: u64, out: &mut Vec<LendMsg>) {
        self.done.clear();
        if !self.fly.is_empty() {
            self.tq.poll(now, &mut self.done);
        }
        let mut grew = false;
        for c in self.done.drain(..) {
            let Some(i) = self.fly.iter().position(|f| f.0 == c.tag) else {
                continue;
            };
            let (_, st, shard) = self.fly.swap_remove(i);
            let ret = st.e.is_free();
            if c.result.is_ok() {
                l.commit(&st);
                if ret {
                    self.returns += 1;
                    grew = true;
                } else {
                    self.denied[shard as usize] = false;
                    out.push(LendMsg::Grant {
                        shard,
                        slot: st.e.slot,
                        phys: l.geom.phys(st.p),
                        pool: l.free_chunks() * l.geom.chunk,
                    });
                }
            } else {
                // either generation may be on the device: no more grants until a remount (`Lending::fail`); a failed
                // return stays lent to the shard (a hole there) until then
                l.fail(&st);
                if !ret {
                    self.denied[shard as usize] = true;
                    out.push(LendMsg::Deny {
                        shard,
                        pool: l.free_chunks() * l.geom.chunk,
                    });
                }
            }
        }
        if grew {
            let pool = l.free_chunks() * l.geom.chunk;
            for (s, d) in self.denied.iter_mut().enumerate() {
                if std::mem::take(d) {
                    out.push(LendMsg::Grew {
                        shard: s as u32,
                        pool,
                    });
                }
            }
        }
        // returns first: they grow the pool for the requests behind them
        let mut k = 0;
        while k < self.rets.len() && self.tq.queue_space() > 0 {
            let (_, p, _) = self.rets[k];
            if l.blk_busy[(p / LEND_EPB) as usize] {
                k += 1;
                continue;
            }
            let (shard, p, slot) = self.rets.remove(k).expect("in range");
            let st = l.stage(p, Entry::FREE);
            match self.submit(&st) {
                Some(tag) => self.fly.push((tag, st, shard)),
                None => {
                    l.abort(&st);
                    self.rets.push_front((shard, p, slot));
                    break;
                }
            }
        }
        // waiters next: a chunk that came back goes to a shard whose txn waits for it
        while let Some(&shard) = self.wait.front() {
            if self.tq.queue_space() == 0 {
                break;
            }
            let Some(p) = l.pick(shard) else {
                break;
            };
            if !self.grant(l, p, shard) {
                break;
            }
            self.wait.pop_front();
            self.waiting[shard as usize] = false;
            self.rev += 1;
        }
        while let Some(&shard) = self.reqs.front() {
            if self.tq.queue_space() == 0 {
                break;
            }
            let s = shard as usize;
            // while a shard waits, the chunks coming back are its: no other request gets one first
            let Some(p) = self.wait.is_empty().then(|| l.pick(shard)).flatten() else {
                if self.short[s] {
                    self.reqs.pop_front();
                    self.wait.push_back(shard);
                    self.waiting[s] = true;
                    self.waits += 1;
                    self.rev += 1;
                    continue;
                }
                if !self.wait.is_empty()
                    || (l.free_chunks() == 0
                        && self.rets.is_empty()
                        && !self.fly.iter().any(|f| f.1.e.is_free()))
                {
                    self.reqs.pop_front();
                    self.queued[s] = false;
                    self.denied[s] = true;
                    out.push(LendMsg::Deny { shard, pool: 0 });
                    continue;
                }
                break; // chunks exist (or a return is being written): the next round
            };
            if !self.grant(l, p, shard) {
                break;
            }
            self.reqs.pop_front();
        }
        self.assign(l, out);
    }

    /// Stage and submit the grant of pool chunk `p` to `shard`. False = the queue refused it (nothing changed).
    fn grant(&mut self, l: &mut Lending, p: u64, shard: u32) -> bool {
        let slot = l.free_slot(shard);
        let st = l.stage(
            p,
            Entry {
                owner: shard as u16,
                slot,
            },
        );
        match self.submit(&st) {
            Some(tag) => {
                self.queued[shard as usize] = false;
                self.fly.push((tag, st, shard));
                true
            }
            None => {
                l.abort(&st);
                false
            }
        }
    }

    /// Match the asks to the waiters (am. 82): every waiter not covered by a chunk on its way back (free, being
    /// written, owed) gets one ask, to the shard with the most spare chunks left; asks beyond the waiters are taken back
    /// (a return from elsewhere came first); waiters nobody can serve are denied, newest first.
    fn assign(&mut self, l: &Lending, out: &mut Vec<LendMsg>) {
        let n = self.target.len();
        // chunks on their way to the waiters: free, being written back; none once grants stopped (`Lending::fail`)
        let coming = (!l.grants_stopped()).then(|| {
            l.free_chunks()
                + self.rets.len() as u64
                + self.fly.iter().filter(|f| f.1.e.is_free()).count() as u64
        });
        let need = coming.map_or(0, |c| (self.wait.len() as u64).saturating_sub(c));
        let mut owed: u64 = (0..n).map(|s| self.owed(s)).sum();
        let owed0 = owed;
        for s in (0..n).rev() {
            while owed > need && self.owed(s) > 0 {
                self.target[s] -= 1;
                owed -= 1;
            }
        }
        while owed < need {
            let Some(g) = (0..n)
                .filter(|&g| self.avail(g) > 0)
                .max_by_key(|&g| self.avail(g))
            else {
                break;
            };
            self.target[g] = self.target[g].max(self.got[g]) + 1;
            owed += 1;
        }
        let served = coming.map_or(0, |c| c + owed);
        while self.wait.len() as u64 > served {
            let shard = self.wait.pop_back().expect("more waiters than served");
            let s = shard as usize;
            self.waiting[s] = false;
            self.queued[s] = false;
            self.denied[s] = true;
            out.push(LendMsg::Deny { shard, pool: 0 });
            self.rev += 1;
        }
        if owed != owed0 {
            self.rev += 1;
        }
    }
}

impl<D: BlockDev> std::fmt::Debug for Pool<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("queued", &self.reqs.len())
            .field("in_flight", &self.fly.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_codec_roundtrip_and_corruption() {
        let ents = vec![
            Entry { owner: 3, slot: 7 },
            Entry::FREE,
            Entry { owner: 0, slot: 0 },
        ];
        let mut v = encode(5, 42, &ents);
        let (g, e) = decode(&v, 5).unwrap();
        assert_eq!(g, 42);
        assert_eq!(&e[..3], &ents[..]);
        assert!(e[3..].iter().all(Entry::is_free));
        assert!(decode(&v, 4).is_none(), "block index is checked");
        v[HDR + 9] ^= 1;
        assert!(decode(&v, 5).is_none(), "crc");
        assert!(decode(&vec![0u8; BLK], 5).is_none());
    }

    /// C1: CRC-valid but out-of-range entries are `Corrupt`, never a huge allocation or a panic later.
    #[test]
    fn loaded_entries_are_range_checked() {
        let e = |owner: u16, slot: u32| Entry { owner, slot };
        assert!(check_entries(&[e(0, 0), e(1, 0), e(0, 1), Entry::FREE], 2).is_ok());
        for (ents, what) in [
            (vec![e(0, 0xFFFF_FFFF), Entry::FREE], "beyond the pool"),
            (vec![e(0, 2), Entry::FREE], "beyond the pool"),
            (vec![e(2, 0), Entry::FREE], "is no shard"),
            (vec![e(0, 1), e(0, 1)], "used twice"),
            (
                vec![Entry {
                    owner: FREE,
                    slot: 1,
                }],
                "free entry with a slot",
            ),
        ] {
            match check_entries(&ents, 2) {
                Err(StoreError::Corrupt(m)) => assert!(m.contains(what), "{m}"),
                r => panic!("{ents:?}: {r:?}"),
            }
        }
    }

    fn mem(nshards: u32, per: u64) -> Lending {
        let geom = Geom {
            table_blk: 10,
            table_blocks: (nshards as u64 * per).div_ceil(LEND_EPB),
            chunk: 256,
            base: 4,
            per,
            data_start: (0..nshards as u64)
                .map(|r| 10_000 + r * (4 + per) * 256)
                .collect(),
        };
        let n = geom.pool() as usize;
        Lending {
            busy: vec![false; n],
            blk_busy: vec![false; geom.table_blocks as usize],
            avail: vec![per; nshards as usize],
            seq: vec![1; geom.table_blocks as usize],
            newest: vec![0; geom.table_blocks as usize],
            ent: vec![Entry::FREE; n],
            geom,
            nshards,
            pend: Vec::new(),
            failed: false,
        }
    }

    /// A grant being written holds its slot: a second grant to the same shard (another table block, e.g. the blocking
    /// gate path next to the pool's async write) gets another slot, else the mount refuses "slot used twice".
    #[test]
    fn staged_grant_holds_its_slot() {
        let mut l = mem(2, 400);
        assert_eq!(l.geom.table_blocks, 2);
        let p = l.pick(1).unwrap();
        let a = l.stage(
            p,
            Entry {
                owner: 1,
                slot: l.free_slot(1),
            },
        );
        assert_eq!(a.e.slot, 0);
        let q = l.pick(1).unwrap();
        assert_ne!(q / LEND_EPB, p / LEND_EPB, "the busy block is skipped");
        let b = l.stage(
            q,
            Entry {
                owner: 1,
                slot: l.free_slot(1),
            },
        );
        assert_eq!(b.e.slot, 1, "slot of the staged grant reused");
        l.commit(&b);
        l.abort(&a);
        assert_eq!(l.free_slot(1), 0, "an aborted stage frees its slot");
    }

    /// A failed table write may still have reached the media (that copy then holds the grant): no more grants until a
    /// remount reads the table, the pool reads empty.
    #[test]
    fn failed_table_write_stops_grants() {
        let mut l = mem(2, 400);
        let p = l.pick(1).unwrap();
        let a = l.stage(
            p,
            Entry {
                owner: 1,
                slot: l.free_slot(1),
            },
        );
        let (_, on_media) = decode(&a.buf, p / LEND_EPB).unwrap();
        assert_eq!(
            on_media[(p % LEND_EPB) as usize],
            Entry { owner: 1, slot: 0 }
        );
        l.fail(&a);
        assert!(l.entry(p).is_free());
        assert_eq!((l.pick(1), l.pick(0), l.free_chunks()), (None, None, 0));
    }

    /// The region with the most available chunks may have none to grant (all its free chunks sit in a table block with a
    /// change in flight): the pick goes on to the next region instead of reporting the pool exhausted.
    #[test]
    fn pick_falls_through_to_the_next_region() {
        let mut l = mem(3, 400);
        // shard 2's own region is used up
        for p in 800..1200usize {
            l.ent[p] = Entry {
                owner: 2,
                slot: (p - 800) as u32,
            };
        }
        l.avail[2] = 0;
        // region 1 gives up 100 chunks, so region 0 has the most available
        for p in 400..500usize {
            l.ent[p] = Entry {
                owner: 1,
                slot: (p - 400) as u32,
            };
        }
        l.avail[1] -= 100;
        // table block 0 (every chunk of region 0) has a change in flight
        l.blk_busy[0] = true;
        let p = l.pick(2).expect("region 1 can grant");
        assert!((500..800).contains(&p), "chunk {p} of region 1");
        assert!(l.grantable(p));
    }
}
