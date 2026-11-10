// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Reclaim of borrowed chunks (adr 0021 am. 57, elastic shards step 4): an empty borrowed chunk goes back to the pool
//! once a durable checkpoint passed its last free; a sparse one is evacuated first (fenced, live extents moved by
//! background txns, drained by checkpoints); the pool owner writes the free entry and tells denied shards the pool grew
//! (`Grew`); another shard borrows the chunk again. Single store, per-core stores exchanging `LendMsg` values by hand,
//! and a power-cut matrix over the whole cycle (fill, delete, evacuate, return, re-borrow).
//!
//! Matrix size: `RECLAIM_CRASH_STRIDE` (default 11; every event while a return or a move is pending); soak
//! `crash_matrix_reclaim_every_event` (ignored, stride 1) runs from lab/elastic-crash.sh.
#![cfg(feature = "elastic")]
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use objmodel::*;
use std::collections::BTreeMap;
use store::alloc::HOLE;
use store::dev::{CrashPolicy, Persist, SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::fsck::fsck;
use store::layout::{MkfsParams, mkfs, read_super};
use store::lend::LendMsg;
use store::obj::onode::fsck_refs;
use store::obj::{DefragStats, OTxn, ObjError, Store, StoreCfg, TOp};

type St = Store<SimDev, SimClock>;
const OBJ: usize = 64 << 10;

fn sim(mib: u64, lba: u32) -> SimConfig {
    let mut c = SimConfig::new(mib << 20);
    c.lba_size = lba;
    c.lba_count = (mib << 20) / lba as u64;
    c
}

fn fresh(mib: u64, lba: u32, base_pct: u32) -> SimDisk {
    fresh_chunked(mib, lba, base_pct, 256)
}

fn fresh_chunked(mib: u64, lba: u32, base_pct: u32, chunk_blocks: u64) -> SimDisk {
    let disk = SimDisk::new(sim(mib, lba));
    mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 2,
            wal_blocks: 256,
            align_blocks: 1,
            meta_pct: 10,
            chunked: true,
            chunk_blocks,
            base_pct,
            ..Default::default()
        },
    )
    .unwrap();
    disk
}

/// Pool on (reclaim with it); a denied shard only reopens on `Grew` (retry pause of an hour).
fn cfg(owner: bool) -> StoreCfg {
    let mut c = StoreCfg::default();
    c.shard.lend_auto = true;
    c.shard.lend_owner = owner;
    c.shard.lend_retry_ms = 3_600_000;
    c
}

fn mount_all(disk: &SimDisk) -> St {
    mount_cfg(disk, cfg(true))
}

fn mount_cfg(disk: &SimDisk, c: StoreCfg) -> St {
    let d = disk.clone();
    Store::mount(move || d.queue(), SimClock::default(), c)
        .unwrap()
        .0
}

/// Per-core stores: core 0 = shard 0 + the pool, core 1 = shard 1.
fn mount_cores(disk: &SimDisk) -> Vec<St> {
    (0..2usize)
        .map(|c| {
            let d = disk.clone();
            Store::mount_shards(
                move || d.queue(),
                SimClock::default(),
                cfg(c == 0),
                move |s| s as usize % 2 == c,
            )
            .unwrap()
            .0
        })
        .collect()
}

fn g(i: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(format!("o{i}").as_bytes(), SnapId::NOSNAP, i, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}
fn pattern(seed: u32) -> Vec<u8> {
    (0..OBJ)
        .map(|k| (k as u32 * 31 + seed * 17 + (k >> 9) as u32) as u8)
        .collect()
}

fn coll_of(st: &St, shard: usize) -> CollT {
    (0..256)
        .map(|s| pgc(1, s))
        .find(|c| st.shard_of(c) == shard)
        .unwrap()
}

/// Cores of an OSD in one thread: polls, moves `LendMsg`s (requests / returns to core 0, answers to the core of the
/// shard), advances each clock by `tick` per round (reclaim checks run once a second).
struct Cores {
    st: Vec<St>,
    acked: Vec<Vec<u64>>,
    /// Per core: failed txns (token, error) not yet claimed by `run` / `outcome`.
    errs: Vec<Vec<(u64, ObjError)>>,
    tok: u64,
    log: Vec<LendMsg>,
    tick: u64,
}

impl Cores {
    fn new(st: Vec<St>) -> Self {
        Cores {
            acked: vec![Vec::new(); st.len()],
            errs: vec![Vec::new(); st.len()],
            st,
            tok: 1,
            log: Vec::new(),
            tick: 0,
        }
    }

    fn step(&mut self) -> Result<(), ObjError> {
        let n = self.st.len();
        for c in 0..n {
            let mut a = Vec::new();
            // a txn that waited for space and got none fails with ENOSPC (in `errs`); the store goes on
            match self.st[c].poll(&mut a) {
                Ok(()) | Err(ObjError::NoSpace) => {}
                Err(e) => return Err(e),
            }
            self.acked[c].append(&mut a);
            self.st[c].take_queue_errors(&mut self.errs[c]);
        }
        let mut msgs = Vec::new();
        for s in self.st.iter_mut() {
            s.take_lend_out(&mut msgs);
        }
        for m in msgs {
            self.log.push(m);
            let to = match m {
                LendMsg::Request { .. } | LendMsg::Return { .. } | LendMsg::Spare { .. } => 0,
                LendMsg::Grant { shard, .. }
                | LendMsg::Deny { shard, .. }
                | LendMsg::Grew { shard, .. }
                | LendMsg::Size { shard, .. } => shard as usize % n,
            };
            self.st[to].lend_in(m);
        }
        for s in self.st.iter_mut() {
            s.idle();
            s.clk.t += self.tick;
        }
        Ok(())
    }

    fn run(&mut self, core: usize, t: &OTxn) -> Result<(), ObjError> {
        let tok = self.submit(core, t)?;
        for _ in 0..2_000_000 {
            self.step()?;
            if let Some(r) = self.outcome(core, tok) {
                return r;
            }
        }
        panic!("txn {tok} never completed");
    }

    /// Queue `t` on `core` without waiting for it: its token (`outcome`).
    fn submit(&mut self, core: usize, t: &OTxn) -> Result<u64, ObjError> {
        let tok = self.tok;
        self.tok += 1;
        self.st[core].queue(t, tok)?;
        Ok(tok)
    }

    /// Queue `t` on `core`, running rounds while the queue is full: its token (`outcome`).
    fn submit_waiting(&mut self, core: usize, t: &OTxn) -> u64 {
        for _ in 0..100_000 {
            match self.submit(core, t) {
                Ok(tok) => return tok,
                Err(ObjError::WouldBlock) => self.step().unwrap(),
                Err(e) => panic!("txn refused: {e:?}"),
            }
        }
        panic!("queue of core {core} stays full");
    }

    /// Run rounds of 10 ms until txn `tok` of `core` completes.
    fn finish(&mut self, core: usize, tok: u64) -> Result<(), ObjError> {
        let tick = std::mem::replace(&mut self.tick, 10_000_000);
        for _ in 0..100_000 {
            self.step().unwrap();
            if let Some(r) = self.outcome(core, tok) {
                self.tick = tick;
                return r;
            }
        }
        panic!("txn {tok} never completed");
    }

    /// Txn `tok` of `core` completed (claimed once): Ok = acked, Err = failed; None = still queued or parked.
    fn outcome(&mut self, core: usize, tok: u64) -> Option<Result<(), ObjError>> {
        if let Some(i) = self.acked[core].iter().position(|&x| x == tok) {
            self.acked[core].swap_remove(i);
            return Some(Ok(()));
        }
        let i = self.errs[core].iter().position(|e| e.0 == tok)?;
        Some(Err(self.errs[core].swap_remove(i).1))
    }

    /// Write objects `first..first+limit` into `c` on `core` until ENOSPC; returns the number written.
    fn fill(&mut self, core: usize, c: CollT, first: u32, limit: u32) -> u32 {
        for i in first..first + limit {
            let mut t = OTxn::new();
            t.push(TOp::MkColl {
                cid: c,
                bits: 0,
                exist_ok: true,
            });
            let d = pattern(i);
            t.write(c, &g(i), 0, &d);
            match self.run(core, &t) {
                Ok(()) => {}
                Err(ObjError::NoSpace) => return i - first,
                Err(e) => panic!("object {i}: {e:?}"),
            }
        }
        limit
    }

    fn remove(&mut self, core: usize, c: CollT, ids: impl Iterator<Item = u32>) {
        for i in ids {
            let mut t = OTxn::new();
            t.remove(c, &g(i));
            self.run(core, &t).unwrap();
        }
    }

    /// Rounds of 10 ms under client load on core 0 (adr 0021 am. 70): the txn `load(round)` is queued before each
    /// round, acks and errors not awaited (a full queue adds none that round; failed or refused txns stay in `errs`). Returns the evacuations of shard 0 that started and
    /// ended within `max` rounds, up to the first one `stop` accepts.
    fn run_loaded(
        &mut self,
        max: usize,
        mut load: impl FnMut(usize) -> OTxn<'static>,
        stop: impl Fn(&Evac) -> bool,
    ) -> Vec<Evac> {
        self.tick = 10_000_000;
        let (mut cur, mut res): (Option<Evac>, Vec<Evac>) = (None, Vec::new());
        let mut was = self.st[0].shards[0].evac_active();
        let mut why0 = self.st[0].shards[0].sh.stats.ckpt_why;
        for r in 0..max {
            let tok = self.tok;
            self.tok += 1;
            match self.st[0].queue(&load(r), tok) {
                Ok(_) | Err(ObjError::WouldBlock) => {}
                Err(e) => self.errs[0].push((tok, e)),
            }
            self.step().unwrap();
            let sh = &self.st[0].shards[0];
            let (now, ds, why, act) = (
                self.st[0].clk.t,
                sh.defrag_stats(),
                sh.sh.stats.ckpt_why,
                sh.evac_active(),
            );
            if act && !was {
                cur = Some(Evac {
                    started: now,
                    moved_at: (now, why),
                    ended: 0,
                    why,
                    ds0: ds,
                    ds,
                });
            }
            if let Some(e) = cur.as_mut() {
                if ds.evac_blocks > e.ds.evac_blocks {
                    e.moved_at = (now, why0);
                }
                e.ds = ds;
                if !act {
                    e.ended = now;
                    e.why = why;
                    let e = cur.take().expect("evacuating");
                    let done = stop(&e);
                    res.push(e);
                    if done {
                        break;
                    }
                }
            }
            was = act;
            why0 = why;
        }
        self.tick = 0;
        res
    }

    /// Run background rounds (10 ms of time each) until `done` or `max` rounds.
    fn settle(&mut self, max: usize, mut done: impl FnMut(&Cores) -> bool) -> bool {
        self.tick = 10_000_000;
        let mut ok = false;
        for _ in 0..max {
            self.step().unwrap();
            if done(self) {
                ok = true;
                break;
            }
        }
        self.tick = 0;
        ok
    }
}

/// One evacuation of a loaded run (`Cores::run_loaded`): sim ns of its start, of its last moved block (with the
/// checkpoint reasons before that round, `ShardStats::ckpt_why`), of its end; the checkpoint reasons and defrag stats at
/// its start and end.
#[derive(Debug)]
struct Evac {
    started: u64,
    moved_at: (u64, [u64; 6]),
    ended: u64,
    why: [u64; 6],
    ds0: DefragStats,
    ds: DefragStats,
}

impl Evac {
    /// The chunk went back (else: given up or aborted).
    fn returned(&self) -> bool {
        self.ds.chunks_returned > self.ds0.chunks_returned
    }
    fn given_up(&self) -> bool {
        self.ds.evac_fails > self.ds0.evac_fails
    }
    /// From the last moved block (or the start) to the end.
    fn drain_ns(&self) -> u64 {
        self.ended - self.moved_at.0
    }
    /// Checkpoints started during the drain (from the round of the last move on): on request, automatic.
    fn drain_ckpts(&self) -> (u64, u64) {
        let w0 = self.moved_at.1;
        (
            self.why[0] - w0[0],
            (1..6).map(|i| self.why[i] - w0[i]).sum(),
        )
    }
}

/// Load txn of the reclaim drain tests (single store): even rounds write a new object `LOAD1 + round / 2` into `c1`
/// (shard 1 needs chunks: am. 82), odd rounds rewrite one small omap value of `o` in `c0` (sys, like a replica apply).
fn load_txn(c0: CollT, o: Ghobject, c1: CollT) -> impl FnMut(usize) -> OTxn<'static> {
    static VAL: [u8; 200] = [7; 200];
    let d: &'static [u8] = pattern(LOAD1).leak();
    move |r| {
        let mut t = OTxn::new();
        if r % 2 == 0 {
            t.push(TOp::MkColl {
                cid: c1,
                bits: 0,
                exist_ok: true,
            });
            t.write(c1, &g(LOAD1 + r as u32 / 2), 0, d);
        } else {
            t.sys = true;
            t.omap_set(c0, &o, b"k0000", &VAL);
        }
        t
    }
}

/// First object of the shard-1 writes of `load_txn` (all with the data `pattern(LOAD1)`).
const LOAD1: u32 = 5_000_000;

/// Borrowed (non-hole) chunks of `shard` on the store that mounts it.
fn lent(st: &St, shard: u32) -> Vec<u64> {
    st.lent_chunks(shard)
        .unwrap()
        .iter()
        .map(|e| e.0)
        .filter(|&p| p != HOLE)
        .collect()
}

fn free_pool(st: &St) -> u64 {
    st.lending().unwrap().free_chunks()
}

fn reads_back(st: &mut St, c: CollT, ids: impl Iterator<Item = u32>) {
    for i in ids {
        assert_eq!(
            st.read(&c, &g(i), 0, OBJ as u64).unwrap(),
            pattern(i),
            "object {i}"
        );
    }
}

fn fsck_ok(disk: &SimDisk) {
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .unwrap();
}

/// Shard 0 takes the whole pool, shard 1 is denied; shard 0 deletes everything: its chunks come back one per reclaim
/// check, the first return reopens shard 1 (`Grew`, long before its retry pause), which then borrows them all.
#[test]
fn empty_chunks_return_and_a_denied_shard_reborrows() {
    let disk = fresh(96, 4096, 50);
    let st = mount_all(&disk);
    let pool0 = free_pool(&st);
    let (c0, c1) = (coll_of(&st, 0), coll_of(&st, 1));
    let mut cores = Cores::new(vec![st]);
    let n0 = cores.fill(0, c0, 0, 100_000);
    assert_eq!(free_pool(&cores.st[0]), 0);
    assert_eq!(lent(&cores.st[0], 0).len() as u64, pool0);
    let n1 = cores.fill(0, c1, 1_000_000, 100_000);
    assert!(n1 > 0);
    assert!(!cores.st[0].shards[1].sh.lend.open, "shard 1 was denied");
    cores.remove(0, c0, 0..n0);
    let back = cores.settle(20_000, |c| {
        lent(&c.st[0], 0).is_empty() && !c.st[0].lend_busy()
    });
    let st = &cores.st[0];
    assert!(back, "lent {:?}", lent(st, 0));
    // the reopened shard 1 may already have borrowed some of them again
    assert_eq!(free_pool(st) + lent(st, 1).len() as u64, pool0);
    assert_eq!(st.shards[0].defrag_stats().chunks_returned, pool0);
    assert_eq!(st.pool_returns(), (pool0, 0));
    assert!(st.shards[1].sh.lend.open, "Grew reopened the denied shard");
    // shard 1 now borrows what shard 0 gave back (close to the whole pool; shard 0 keeps nothing)
    let more = cores.fill(0, c1, 2_000_000, 100_000);
    let st = &mut cores.st[0];
    let chunk_objs = 256 * 4096 / OBJ as u64;
    assert!(
        more as u64 >= (pool0 - 1) * chunk_objs * 9 / 10,
        "{more} objects after the return of {pool0} chunks"
    );
    assert_eq!(free_pool(st), 0);
    reads_back(st, c1, (1_000_000..1_000_000 + n1).step_by(5));
    reads_back(st, c1, (2_000_000..2_000_000 + more).step_by(5));
    st.checkpoint().unwrap();
    drop(cores);
    fsck_ok(&disk);
    let mut st = mount_all(&disk);
    assert_eq!(lent(&st, 1).len() as u64, pool0);
    reads_back(&mut st, c1, (2_000_000..2_000_000 + more).step_by(7));
}

/// adr 0021 am. 82: shard 1 (core 1) takes the whole pool, then its base empties and 7 of 8 objects of its borrowed
/// chunks go: they are sparse. No shard needs space: nothing moves for a minute (an empty chunk goes back). Shard 0
/// (core 0, the pool owner's) then fills past its base: its writes wait for chunks (no ENOSPC) while shard 1 evacuates
/// them on demand (shard 1's `Spare` reports and the owner's return target in `Size` cross cores); every chunk shard 1
/// gives back goes to shard 0, until shard 1 keeps none. The kept and the new objects read back before and after a
/// remount, fsck is clean.
#[test]
fn a_short_shard_waits_for_an_evacuation_on_demand() {
    let disk = fresh(96, 4096, 50);
    let st = mount_cores(&disk);
    let geom = st[0].lending().unwrap().geom.clone();
    let pool0 = free_pool(&st[0]);
    let (c0, c1) = (coll_of(&st[0], 0), coll_of(&st[0], 1));
    let mut cores = Cores::new(st);
    let n = cores.fill(1, c1, 0, 100_000);
    assert_eq!(free_pool(&cores.st[0]), 0);
    assert_eq!(lent(&cores.st[1], 1).len() as u64, pool0);
    let nb = (geom.base * geom.chunk * 4096 / OBJ as u64) as u32;
    let kept = |i: &u32| *i >= nb && i.is_multiple_of(8);
    cores.remove(1, c1, (0..n).filter(|i| !kept(i)));
    let ds1 = |c: &Cores| c.st[1].shards[0].defrag_stats();
    cores.settle(6_000, |_| false);
    // (an empty chunk may go back: the first borrowed chunk can hold only base objects)
    let s = ds1(&cores);
    assert_eq!((s.evacs, s.evac_blocks), (0, 0), "idle: {s:?}");
    assert!(
        lent(&cores.st[1], 1).len() as u64 + 1 >= pool0,
        "idle: {s:?}"
    );
    assert!(
        cores
            .log
            .iter()
            .any(|m| matches!(m, LendMsg::Spare { shard: 1, chunks, .. } if *chunks > 0)),
        "shard 1 reported spare chunks"
    );
    // shard 0 fills past its base: its writes wait for the chunks shard 1 evacuates
    cores.tick = 10_000_000;
    let n0 = cores.fill(0, c0, 1_000_000, 100_000);
    cores.tick = 0;
    let s = ds1(&cores);
    let got = lent(&cores.st[0], 0).len() as u64;
    eprintln!(
        "on demand: shard 0 wrote {n0} objects ({nb} fit its base), got {got} chunks, waits {} {s:?}",
        cores.st[0].pool_waits()
    );
    assert!(
        cores.st[0].pool_waits() >= 1 && s.evacs >= 1 && s.evac_blocks > 0,
        "waits {} {s:?}",
        cores.st[0].pool_waits()
    );
    assert!(
        cores
            .log
            .iter()
            .any(|m| matches!(m, LendMsg::Size { shard: 1, target, .. } if *target > 0)),
        "the owner asked shard 1 for returns"
    );
    assert!(
        lent(&cores.st[1], 1).is_empty() && got == pool0 && free_pool(&cores.st[0]) == 0,
        "shard 1 keeps {:?}, shard 0 got {got} of {pool0}, {s:?}",
        lent(&cores.st[1], 1)
    );
    let chunk_objs = (geom.chunk * 4096 / OBJ as u64) as u32;
    assert!(
        n0 >= (nb + pool0 as u32 * chunk_objs) * 9 / 10,
        "shard 0 wrote {n0} objects"
    );
    reads_back(&mut cores.st[1], c1, (0..n).filter(kept));
    reads_back(&mut cores.st[0], c0, (1_000_000..1_000_000 + n0).step_by(7));
    for s in cores.st.iter_mut() {
        s.checkpoint().unwrap();
    }
    drop(cores);
    fsck_ok(&disk);
    let mut st = mount_all(&disk);
    assert!(lent(&st, 1).is_empty());
    reads_back(&mut st, c1, (0..n).filter(kept));
    reads_back(&mut st, c0, (1_000_000..1_000_000 + n0).step_by(5));
}

/// adr 0021 am. 82: the spare a shard reports follows the free blocks it has left, holes included. Shard 1 takes the
/// whole pool, 7 of 8 objects of its chunks go, it reports spare chunks; it then writes new objects into those holes
/// (no clock time passes): the next report already is the one a check interval later gives (within one chunk). Before, it waited for the
/// check interval or for the whole free windows to move, a waiter of another shard counted on spare nobody could give
/// and was denied after its txn had parked (a fatal ENOSPC for the core).
#[test]
fn spare_report_follows_holes_that_writes_fill() {
    let disk = fresh(96, 4096, 50);
    let st = mount_cores(&disk);
    let c1 = coll_of(&st[0], 1);
    let mut cores = Cores::new(st);
    let n = cores.fill(1, c1, 0, 100_000);
    cores.remove(1, c1, (0..n).filter(|i| i % 8 != 0));
    cores.settle(6_000, |_| false);
    let last = |c: &Cores| {
        c.log
            .iter()
            .rev()
            .find_map(|m| match m {
                LendMsg::Spare {
                    shard: 1, chunks, ..
                } => Some(*chunks),
                _ => None,
            })
            .expect("shard 1 reported")
    };
    let before = last(&cores);
    assert!(before > 0, "sparse chunks are spare");
    let refill = (n - n / 8) / 2;
    assert_eq!(cores.fill(1, c1, 5_000_000, refill), refill);
    let after = last(&cores);
    assert!(after < before, "spare {before} -> {after}");
    // the report after the writes is the one a full check interval later gives, give or take the chunk of free blocks a
    // check waits for
    cores.settle(6_000, |_| false);
    let fresh = last(&cores);
    assert!(
        after.abs_diff(fresh) <= 1,
        "spare right after the writes {after}, a check interval later {fresh}"
    );
}

const BIG: usize = 1 << 20;

fn write_txn<'a>(c: CollT, i: u32, d: &'a [u8]) -> OTxn<'a> {
    let mut t = OTxn::new();
    t.push(TOp::MkColl {
        cid: c,
        bits: 0,
        exist_ok: true,
    });
    t.write(c, &g(i), 0, d);
    t
}

fn big(seed: u32) -> Vec<u8> {
    (0..BIG)
        .map(|k| (k as u32 * 13 + seed * 29 + (k >> 12) as u32) as u8)
        .collect()
}

/// adr 0021 am. 82 (lab: after a 4 MiB overwrite burst at 80 % fill, reclaim moved tens of GiB between the shards): two
/// cores fill to 80 % of their space (production base share, 8 MiB chunks of 1 MiB windows, 1 MiB objects), then a
/// pipelined overwrite burst (every fourth object, txns in flight on both cores) borrows the pool dry while its frees wait
/// for a checkpoint: once they are free the borrowed chunks are sparse beside whole free windows. The OSD idles a minute.
/// No shard needs space: nothing moves and no chunk with live data goes back (before: every chunk the shard could spare
/// was evacuated, and the next burst borrowed again).
#[test]
fn an_overwrite_burst_then_idle_moves_nothing() {
    let disk = fresh_chunked(256, 4096, 25, 2048);
    let st = mount_cores(&disk);
    let geom = st[0].lending().unwrap().geom.clone();
    let colls = [coll_of(&st[0], 0), coll_of(&st[0], 1)];
    let mut cores = Cores::new(st);
    let n = ((geom.base + geom.per) * geom.chunk * 4096 / BIG as u64 * 8 / 10) as u32;
    for i in 0..n {
        for (core, &c) in colls.iter().enumerate() {
            cores.run(core, &write_txn(c, i, &big(i))).unwrap();
        }
    }
    let burst = |i: &u32| i.is_multiple_of(4);
    let mut toks = Vec::new();
    for i in (0..n).filter(burst) {
        for (core, &c) in colls.iter().enumerate() {
            let d = big(i + 500_000);
            toks.push((core, cores.submit_waiting(core, &write_txn(c, i, &d))));
        }
    }
    for _ in 0..100_000 {
        if toks.is_empty() {
            break;
        }
        cores.step().unwrap();
        toks.retain(|&(core, tok)| match cores.outcome(core, tok) {
            None => true,
            Some(r) => {
                r.unwrap();
                false
            }
        });
    }
    assert!(toks.is_empty(), "burst txns never completed: {toks:?}");
    let held = |c: &Cores| [lent(&c.st[0], 0).len(), lent(&c.st[1], 1).len()];
    eprintln!(
        "burst: holds {:?}, pool {}",
        held(&cores),
        free_pool(&cores.st[0])
    );
    cores.settle(6_000, |_| false);
    for core in 0..2 {
        let s = cores.st[core].shards[0].defrag_stats();
        eprintln!(
            "burst then idle: core {core} holds {} chunks, {s:?}",
            held(&cores)[core]
        );
        assert_eq!((s.evacs, s.evac_blocks), (0, 0), "core {core}: {s:?}");
    }
    assert_eq!(cores.st[0].pool_waits(), 0);
    for (core, c) in colls.iter().enumerate() {
        for i in 0..n {
            let seed = if burst(&i) { i + 500_000 } else { i };
            let got = cores.st[core].read(c, &g(i), 0, BIG as u64);
            assert!(got.unwrap() == big(seed), "core {core} object {i}");
        }
        cores.st[core].checkpoint().unwrap();
    }
    drop(cores);
    fsck_ok(&disk);
}

/// A reservation taken in a borrowed chunk before its evacuation fence and given back under the fence stays fenced:
/// no later allocation lands in the chunk under evacuation (before: only frees through the reader limbo re-fenced).
#[test]
fn reservation_given_back_under_an_evacuation_fence_stays_fenced() {
    let disk = fresh(96, 4096, 50);
    let st = mount_all(&disk);
    let geom = st.lending().unwrap().geom.clone();
    let c0 = coll_of(&st, 0);
    let mut cores = Cores::new(vec![st]);
    let n = ((geom.base + 1) * geom.chunk * 4096 / OBJ as u64) as u32;
    assert_eq!(cores.fill(0, c0, 0, n), n);
    let st = &mut cores.st[0];
    let slots = st.lent_chunks(0).unwrap();
    let k = slots
        .iter()
        .position(|e| e.0 != HOLE)
        .expect("a borrowed chunk");
    let chunk = slots[k].0..slots[k].0 + geom.chunk;
    let sh = &mut st.shards[0].sh;
    // everything free outside the chunk is taken first, so the next reservation is inside it
    let mut taken = Vec::new();
    let b = loop {
        let b = sh
            .state_mut()
            .alloc
            .reserve(1)
            .expect("a free block in the chunk");
        if chunk.contains(&b) {
            break b;
        }
        taken.push(b);
    };
    assert!(sh.evac_fence(k as u32).is_some());
    sh.unreserve(b, 1);
    while let Some(x) = sh.state_mut().alloc.reserve(1) {
        assert!(
            !chunk.contains(&x),
            "block {x} of the fenced chunk {chunk:?} allocated"
        );
        taken.push(x);
    }
    sh.evac_unfence();
    for x in taken {
        sh.unreserve(x, 1);
    }
}

/// Single store, small pool (base 90 %): shard 0 fills its base and `extra` chunks (objects `0..n`, n returned), shard 1
/// takes the rest of the pool and is denied (shard 0, full, has nothing to spare). The next chunk shard 1 gets is one
/// shard 0 gives back on demand (am. 82).
fn dry_pool(cores: &mut Cores, geom: &store::lend::Geom, c0: CollT, c1: CollT, extra: u64) -> u32 {
    let n = ((geom.base + extra) * geom.chunk * 4096 / OBJ as u64) as u32;
    assert_eq!(cores.fill(0, c0, 0, n), n);
    assert!(lent(&cores.st[0], 0).len() as u64 >= extra);
    assert!(cores.fill(0, c1, 1_000_000, 100_000) > 0);
    assert_eq!(free_pool(&cores.st[0]), 0);
    n
}

/// Removals of shard 0 made durable: their blocks are free (no longer held for a checkpoint), its empty chunks go back,
/// it reports what it could give back.
fn removals_durable(cores: &mut Cores) {
    cores.st[0].checkpoint().unwrap();
    cores.settle(20, |c| !c.st[0].lend_busy());
}

/// Run shard 1 writes (single store, one at a time, time passing) until one waits for an evacuation of shard 0: its
/// token (the write is still parked).
fn write1_until_evac(cores: &mut Cores, c1: CollT, first: u32) -> u64 {
    cores.tick = 10_000_000;
    for i in first..first + 100_000 {
        let d = pattern(i);
        let w = cores.submit(0, &write_txn(c1, i, &d)).unwrap();
        for _ in 0..100_000 {
            cores.step().unwrap();
            if cores.st[0].shards[0].evac_active() {
                cores.tick = 0;
                return w;
            }
            if let Some(r) = cores.outcome(0, w) {
                r.unwrap();
                break;
            }
        }
    }
    panic!("no evacuation started");
}

/// adr 0021 am. 70: evacuations under client load (writes of shard 1 that take the pool dry and then wait for the
/// chunks, am. 82, and small omap txns on shard 0: txns in flight at every step), no interval checkpoint due. The
/// moved-out blocks are held until a checkpoint passes their frees: the drain asks for it as soon as its moves are
/// submitted and the chunk goes back within a few steps (before: it asked only on an idle shard and waited for an
/// automatic checkpoint, or gave the chunk up at a 30 s deadline). No load txn fails.
#[test]
fn evacuation_drain_asks_for_its_checkpoint_under_client_load() {
    let disk = fresh(96, 4096, 90);
    let mut c = cfg(true);
    c.shard.ckpt_interval_ns = 3_600_000_000_000;
    let st = mount_cfg(&disk, c);
    let geom = st.lending().unwrap().geom.clone();
    let (c0, c1) = (coll_of(&st, 0), coll_of(&st, 1));
    let mut cores = Cores::new(vec![st]);
    let n = dry_pool(&mut cores, &geom, c0, c1, 3);
    let nb = (geom.base * geom.chunk * 4096 / OBJ as u64) as u32;
    let kept = |i: &u32| *i >= nb && i.is_multiple_of(8);
    cores.remove(0, c0, (0..n).filter(|i| !kept(i)));
    removals_durable(&mut cores);
    // an evacuation that moved blocks (its drain waits for the frees of its moves) and returned the chunk
    let ev = cores.run_loaded(20_000, load_txn(c0, g(9_000_000), c1), |e| {
        e.returned() && e.ds.evac_blocks > e.ds0.evac_blocks
    });
    assert!(
        cores.errs[0].is_empty(),
        "load txn failed: {:?}",
        cores.errs[0]
    );
    let e = ev.last().expect("no evacuation ended");
    let (asked, auto) = e.drain_ckpts();
    eprintln!(
        "loaded evacuation: {} ns, drain {} ns, drain checkpoints asked {asked} automatic {auto}",
        e.ended - e.started,
        e.drain_ns()
    );
    assert!(
        e.returned() && e.ds.evac_blocks > e.ds0.evac_blocks,
        "{ev:?}"
    );
    assert!(
        asked >= 1 && asked + auto <= 3,
        "checkpoints during the drain: asked {asked}, automatic {auto}, {e:?}"
    );
    assert!(
        e.drain_ns() < 500_000_000,
        "drain took {} ns: {e:?}",
        e.drain_ns()
    );
    let st = &mut cores.st[0];
    reads_back(st, c0, (0..n).filter(kept));
    st.checkpoint().unwrap();
    drop(cores);
    fsck_ok(&disk);
}

/// adr 0021 am. 70: the only sparse borrowed chunk holds an extent shared with a clone (never moved); writes of shard 1
/// take the pool dry and wait for chunks (am. 82). Frees apply at submit and the fence keeps allocations out, so nothing
/// in flight can empty it: its evacuation gives up at its first drain step although client txns are in flight at every
/// step (before: it waited for an idle shard and gave up only at a 30 s deadline with a WARNING TIMEOUT). The chunk
/// stays, both objects read back; with nothing else to give, shard 1's writes fail with ENOSPC (nothing else fails).
#[test]
fn evacuation_gives_up_on_a_shared_extent_at_once_under_client_load() {
    let disk = fresh(96, 4096, 90);
    let st = mount_all(&disk);
    let geom = st.lending().unwrap().geom.clone();
    let (c0, c1) = (coll_of(&st, 0), coll_of(&st, 1));
    let mut cores = Cores::new(vec![st]);
    let n = ((geom.base + 1) * geom.chunk * 4096 / OBJ as u64) as u32;
    assert_eq!(cores.fill(0, c0, 0, n), n);
    let k = n - 1; // written last: in a borrowed chunk
    let mut t = OTxn::new();
    t.push(TOp::Clone {
        cid: c0,
        src: g(k),
        dst: g(8_000_000),
    });
    cores.run(0, &t).unwrap();
    assert!(cores.fill(0, c1, 1_000_000, 100_000) > 0);
    assert_eq!(free_pool(&cores.st[0]), 0);
    cores.remove(0, c0, 0..k);
    removals_durable(&mut cores);
    // chunks emptied by the removals went back already and feed shard 1 first, then the shared extent's chunk is tried
    let ev = cores.run_loaded(2_000, load_txn(c0, g(9_000_000), c1), Evac::given_up);
    let e = ev.last().expect("no evacuation ended within 20 s");
    assert!(
        e.given_up() && e.ds.evac_blocks == e.ds0.evac_blocks,
        "{ev:?} now {:?}",
        cores.st[0].shards[0].defrag_stats()
    );
    assert!(
        e.ended - e.started < 2_000_000_000,
        "given up after {} ns: {e:?}",
        e.ended - e.started
    );
    // nothing left to give: shard 1 writes fail with ENOSPC, nothing else fails
    cores.settle(100, |_| false);
    let errs = &cores.errs[0];
    assert!(errs.iter().all(|e| e.1 == ObjError::NoSpace), "{errs:?}");
    let st = &mut cores.st[0];
    assert!(!lent(st, 0).is_empty(), "the pinned chunk stays");
    for o in [g(k), g(8_000_000)] {
        assert_eq!(st.read(&c0, &o, 0, OBJ as u64).unwrap(), pattern(k));
    }
    st.checkpoint().unwrap();
    drop(cores);
    fsck_ok(&disk);
}

/// adr 0021 am. 79 (am. 82: evacuations on demand): the last 32 objects (in borrowed chunks, 16 objects each) share
/// their extents with clones (never moved). Writes of shard 1 wait for chunks: the evacuations give up on those chunks,
/// the writes fail with ENOSPC; nothing runs while the OSD idles (before: retried every 60 reclaim checks, each retry a
/// whole extent pass). Freeing one pinning extent (object and clone removed) re-arms its chunk: nothing moves until a
/// write of shard 1 waits again, then one more evacuation; freeing all of them empties the chunks: they go back without
/// one, and shard 1 borrows again.
#[test]
fn evacuation_given_up_waits_for_a_freed_pin() {
    let disk = fresh(96, 4096, 90);
    let st = mount_all(&disk);
    let geom = st.lending().unwrap().geom.clone();
    let (c0, c1) = (coll_of(&st, 0), coll_of(&st, 1));
    let mut cores = Cores::new(vec![st]);
    let n = ((geom.base + 1) * geom.chunk * 4096 / OBJ as u64) as u32;
    assert_eq!(cores.fill(0, c0, 0, n), n);
    let pins = n - 32..n; // written last: in borrowed chunks
    for k in pins.clone() {
        let mut t = OTxn::new();
        t.push(TOp::Clone {
            cid: c0,
            src: g(k),
            dst: g(8_000_000 + k),
        });
        cores.run(0, &t).unwrap();
    }
    assert!(cores.fill(0, c1, 1_000_000, 100_000) > 0);
    assert_eq!(free_pool(&cores.st[0]), 0);
    cores.remove(0, c0, 0..pins.start);
    removals_durable(&mut cores);
    let ds = |c: &Cores| c.st[0].shards[0].defrag_stats();
    // shard 1 waits until every pinned chunk was tried
    let mut next = 5_000_000;
    let mut write1 = |cores: &mut Cores| {
        cores.tick = 10_000_000;
        let n = cores.fill(0, c1, next, 100_000);
        cores.tick = 0;
        next += n + 1;
        n
    };
    write1(&mut cores);
    let s0 = ds(&cores);
    assert!(
        s0.evac_fails >= 1 && !lent(&cores.st[0], 0).is_empty(),
        "{s0:?}"
    );
    cores.settle(60_000, |_| false);
    let s1 = ds(&cores);
    assert_eq!(
        (s1.sweeps, s1.evacs, s1.evac_fails),
        (s0.sweeps, s0.evacs, s0.evac_fails),
        "idle retries: {s1:?}"
    );
    let free_pin = |cores: &mut Cores, k: u32| {
        let mut t = OTxn::new();
        t.remove(c0, &g(k));
        t.remove(c0, &g(8_000_000 + k));
        cores.run(0, &t).unwrap();
    };
    free_pin(&mut cores, pins.start + 16);
    cores.settle(1_000, |_| false);
    assert_eq!(ds(&cores).evacs, s1.evacs, "no demand: {:?}", ds(&cores));
    assert_eq!(write1(&mut cores), 0, "nothing to give");
    let s2 = ds(&cores);
    assert_eq!(s2.evacs, s1.evacs + 1, "freed pin re-arms: {s2:?}");
    cores.settle(60_000, |_| false);
    let s3 = ds(&cores);
    assert_eq!(
        (s3.sweeps, s3.evacs),
        (s2.sweeps, s2.evacs),
        "idle retries: {s3:?}"
    );
    for k in pins.clone().filter(|&k| k != pins.start + 16) {
        let st = &mut cores.st[0];
        assert_eq!(st.read(&c0, &g(k), 0, OBJ as u64).unwrap(), pattern(k));
        free_pin(&mut cores, k);
    }
    assert!(
        cores.settle(20_000, |c| lent(&c.st[0], 0).is_empty()
            && !c.st[0].lend_busy()),
        "lent {:?} {:?}",
        lent(&cores.st[0], 0),
        ds(&cores)
    );
    assert_eq!(
        ds(&cores).evacs,
        s3.evacs,
        "empty chunks go back without one"
    );
    assert!(write1(&mut cores) > 0, "shard 1 borrows again");
    cores.st[0].checkpoint().unwrap();
    drop(cores);
    fsck_ok(&disk);
}

/// Per-core stores: a return crosses cores as `Return` (borrower core 1 -> owner core 0), `Grew` crosses to a denied
/// shard on core 1. Every message once: returns == chunks given back, the pool ends where it started.
#[test]
fn returns_and_grew_cross_cores_exactly_once() {
    let disk = fresh(96, 4096, 50);
    let st = mount_cores(&disk);
    let pool0 = free_pool(&st[0]);
    let (c0, c1) = (coll_of(&st[0], 0), coll_of(&st[0], 1));
    let mut cores = Cores::new(st);
    let count = |c: &Cores, f: fn(&LendMsg) -> bool| c.log.iter().filter(|m| f(m)).count();
    // phase A: shard 1 (core 1) takes the pool, shard 0 is denied, shard 1 empties: Return messages to core 0
    let n1 = cores.fill(1, c1, 0, 100_000);
    assert_eq!(lent(&cores.st[1], 1).len() as u64, pool0);
    assert!(cores.fill(0, c0, 1_000_000, 100_000) > 0);
    assert!(!cores.st[0].shards[0].sh.lend.open);
    cores.remove(1, c1, 0..n1);
    assert!(cores.settle(20_000, |c| lent(&c.st[1], 1).is_empty()
        && !c.st[0].lend_busy()));
    let rets = count(&cores, |m| matches!(m, LendMsg::Return { .. }));
    assert_eq!(rets as u64, pool0, "one Return per chunk");
    assert_eq!(cores.st[0].pool_returns(), (pool0, 0));
    assert!(lent(&cores.st[1], 1).is_empty());
    assert!(cores.st[0].shards[0].sh.lend.open, "local Grew");
    // phase B: shard 0 (core 0) takes the pool, shard 1 (core 1) is denied, shard 0 empties: Grew crosses to core 1
    let n0 = cores.fill(0, c0, 2_000_000, 100_000);
    assert_eq!(free_pool(&cores.st[0]), 0);
    assert!(cores.fill(1, c1, 3_000_000, 100_000) > 0);
    assert!(!cores.st[1].shards[0].sh.lend.open);
    let grew0 = count(&cores, |m| matches!(m, LendMsg::Grew { shard: 1, .. }));
    cores.remove(
        0,
        c0,
        (2_000_000..2_000_000 + n0).chain(1_000_000..1_000_100),
    );
    assert!(cores.settle(20_000, |c| lent(&c.st[0], 0).is_empty()
        && !c.st[0].lend_busy()));
    let grew = count(&cores, |m| matches!(m, LendMsg::Grew { shard: 1, .. })) - grew0;
    assert_eq!(grew, 1, "one Grew per denial");
    assert!(cores.st[1].shards[0].sh.lend.open, "Grew reached core 1");
    let more = cores.fill(1, c1, 4_000_000, 100_000);
    assert!(more > 0 && free_pool(&cores.st[0]) == 0);
    reads_back(
        &mut cores.st[1],
        c1,
        (4_000_000..4_000_000 + more).step_by(9),
    );
    for s in cores.st.iter_mut() {
        s.checkpoint().unwrap();
    }
    drop(cores);
    fsck_ok(&disk);
}

/// The shard needs space while one of its chunks is being evacuated for a waiting write of shard 1: the evacuation
/// stops, the fence goes back, the chunk stays; nothing is lost. With nothing left to give, both shards' waiting writes
/// fail with ENOSPC.
#[test]
fn evacuation_stops_when_the_shard_needs_space() {
    let disk = fresh(96, 4096, 90);
    let st = mount_all(&disk);
    let geom = st.lending().unwrap().geom.clone();
    let (c0, c1) = (coll_of(&st, 0), coll_of(&st, 1));
    let mut cores = Cores::new(vec![st]);
    let n = dry_pool(&mut cores, &geom, c0, c1, 2);
    let nb = (geom.base * geom.chunk * 4096 / OBJ as u64) as u32;
    cores.remove(0, c0, (0..n).filter(|i| *i < nb || i % 4 != 0));
    removals_durable(&mut cores);
    let w = write1_until_evac(&mut cores, c1, 5_000_000);
    // the shard fills up (no time passes: the evacuation makes no step): the gate wants a chunk, the evacuation aborts
    let more = cores.fill(0, c0, 1_000_000, 100_000);
    assert!(!cores.st[0].shards[0].evac_active());
    assert!(more > 0);
    let r = cores.finish(0, w);
    assert!(matches!(r, Ok(()) | Err(ObjError::NoSpace)), "{r:?}");
    let st = &mut cores.st[0];
    reads_back(st, c0, (nb..n).filter(|i| i % 4 == 0));
    reads_back(st, c0, (1_000_000..1_000_000 + more).step_by(11));
    st.checkpoint().unwrap();
    drop(cores);
    fsck_ok(&disk);
}

// ------------------------------------------------------------------------------------------------------ crash matrix

#[derive(Default, Debug)]
struct Log {
    /// object -> Some(seed) of every acked write, None once its removal was acked
    acked: BTreeMap<u32, Option<u32>>,
    /// the txn queued and not acked: (object, new state)
    inflight: Option<(u32, Option<u32>)>,
    /// IO event ranges `[a, b)` (from `t0`) while a reclaim step (move, drain, return write) or a write waiting for a
    /// chunk was pending; `open` = start of the current one
    busy: Vec<(u64, u64)>,
    t0: u64,
    open: Option<u64>,
    /// the cycle reached: chunks returned, shard 1 borrowed again
    returned: u64,
    moved: u64,
    reborrowed: bool,
}

fn op(
    cores: &mut Cores,
    disk: &SimDisk,
    log: &mut Log,
    c: CollT,
    i: u32,
    v: Option<u32>,
) -> Result<(), ()> {
    let mut t = OTxn::new();
    let d = v.map(pattern).unwrap_or_default();
    match v {
        Some(_) => {
            t.push(TOp::MkColl {
                cid: c,
                bits: 0,
                exist_ok: true,
            });
            t.write(c, &g(i), 0, &d);
        }
        None => {
            t.remove(c, &g(i));
        }
    }
    log.inflight = Some((i, v));
    let tok = cores.tok;
    cores.tok += 1;
    cores.st[0].queue(&t, tok).map_err(|_| ())?;
    for _ in 0..2_000_000 {
        cores.step().map_err(|_| ())?;
        if disk.crashed() {
            return Err(());
        }
        track(cores, disk, log);
        if let Some(k) = cores.acked[0].iter().position(|&x| x == tok) {
            cores.acked[0].swap_remove(k);
            log.acked.insert(i, v);
            log.inflight = None;
            return Ok(());
        }
        if !cores.errs[0].is_empty() {
            return Err(());
        }
    }
    Err(())
}

/// Reclaim busy: an evacuation of shard 0, a pool table write, or a write of shard 1 waiting for a chunk.
fn reclaim_busy(st: &St) -> bool {
    st.shards[0].evac_active() || st.lend_busy() || st.shards[1].sh.lend.want
}

/// After a round: the busy ranges and how far the cycle got.
fn track(cores: &Cores, disk: &SimDisk, log: &mut Log) {
    let e = disk.events() - log.t0;
    match (reclaim_busy(&cores.st[0]), log.open) {
        (true, None) => log.open = Some(e),
        (false, Some(a)) => {
            log.busy.push((a, e + 1));
            log.open = None;
        }
        _ => {}
    }
    let ds = cores.st[0].shards[0].defrag_stats();
    (log.returned, log.moved) = (ds.chunks_returned, ds.evac_blocks);
}

/// Fill shard 0 two chunks past its base, delete 5 of 6 objects: the chunk emptied goes back on its own, the sparse
/// one stays (no demand). Shard 1 grows past its base: it takes the pool dry, then its write waits while shard 0
/// evacuates the sparse chunk on demand, and borrows it. Stops at the first error (the cut).
fn workload(disk: &SimDisk, st: St, log: &mut Log) -> Result<(), ()> {
    let (c0, c1) = (coll_of(&st, 0), coll_of(&st, 1));
    log.t0 = disk.events();
    let mut cores = Cores::new(vec![st]);
    for i in 0..70 {
        op(&mut cores, disk, log, c0, i, Some(i))?;
    }
    for i in (0..70).filter(|i| *i < 40 || i % 25 != 0) {
        op(&mut cores, disk, log, c0, i, None)?;
    }
    cores.tick = 10_000_000;
    for _ in 0..2_000 {
        cores.step().map_err(|_| ())?;
        if disk.crashed() {
            return Err(());
        }
        track(&cores, disk, log);
        if log.returned >= 1 && log.open.is_none() {
            break;
        }
    }
    // shard 1 grows past its base into the returned chunks, then waits for the evacuated one
    for i in 0..60 {
        op(&mut cores, disk, log, c1, 10_000 + i, Some(10_000 + i))?;
    }
    cores.tick = 0;
    log.reborrowed = !lent(&cores.st[0], 1).is_empty();
    cores.st[0].checkpoint().map_err(|_| ())?;
    Ok(())
}

fn cut_image(disk: &SimDisk, pol: usize, table: (u64, u64)) -> SimImage {
    match pol {
        0 => disk.crash_image(CrashPolicy::DROP_ALL),
        1 => disk.crash_image(CrashPolicy::PERSIST_ALL),
        2 => disk.crash_image(CrashPolicy::MIXED),
        _ => disk.crash_image_with(|f, rng| {
            if f.lba >= table.0 && f.lba < table.1 && f.nlba > 1 {
                Persist::Tear((0..f.nlba).map(|j| j < f.nlba / 2).collect())
            } else if rng.pct(50) {
                Persist::Full
            } else {
                Persist::Drop
            }
        }),
    }
}

fn verify(img: &SimImage, log: &Log) -> Result<(), String> {
    let disk = SimDisk::from_image(img, sim(12, 512));
    let mut st = {
        let d = disk.clone();
        Store::mount(move || d.queue(), SimClock::default(), cfg(true))
            .map_err(|e| format!("mount: {e:?}"))?
            .0
    };
    // fsck: every extent inside the chunks its shard holds in the durable table (a returned chunk is referenced by
    // nobody, a re-granted one only by its new owner), refcounts, crcs
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .map_err(|e| format!("fsck: {e}"))?;
    let (sb, dirs) =
        read_super(&mut disk.queue(), &mut SimClock::default()).map_err(|e| format!("{e:?}"))?;
    let geom = store::lend::Geom::of(&sb, &dirs).map_err(|e| format!("{e:?}"))?;
    let lent_n: usize = dirs
        .iter()
        .map(|d| d.lent.iter().filter(|&&p| p != HOLE).count())
        .sum();
    if lent_n as u64 + st.lending().unwrap().free_chunks() != geom.pool() {
        return Err(format!("pool {} lent {lent_n}: chunks lost", geom.pool()));
    }
    let (c0, c1) = (coll_of(&st, 0), coll_of(&st, 1));
    for (&i, &v) in &log.acked {
        let alt = match log.inflight {
            Some((j, s)) if j == i => Some(s),
            _ => None,
        };
        let c = if i >= 10_000 { c1 } else { c0 };
        let got = st
            .read(&c, &g(i), 0, OBJ as u64)
            .ok()
            .filter(|d| !d.is_empty());
        let ok = |want: Option<u32>| match want {
            Some(s) => got.as_deref() == Some(&pattern(s)[..]),
            None => got.is_none(),
        };
        if !ok(v) && alt.is_none_or(|a| !ok(a)) {
            return Err(format!("object {i}: expected {v:?} (in flight {alt:?})"));
        }
    }
    // keeps working: write past the base again (time passes: an evacuation can serve it), remount, fsck
    let mut cores = Cores::new(vec![st]);
    cores.tick = 10_000_000;
    for i in 0..12u32 {
        let mut t = OTxn::new();
        t.push(TOp::MkColl {
            cid: c0,
            bits: 0,
            exist_ok: true,
        });
        let d = pattern(7000 + i);
        t.write(c0, &g(7000 + i), 0, &d);
        cores
            .run(0, &t)
            .map_err(|e| format!("write after recovery {i}: {e:?}"))?;
    }
    cores.settle(500, |_| false);
    let mut st = cores.st.pop().unwrap();
    st.checkpoint().map_err(|e| format!("{e:?}"))?;
    drop(st);
    let d = disk.clone();
    let mut st = Store::mount(move || d.queue(), SimClock::default(), cfg(true))
        .map_err(|e| format!("remount: {e:?}"))?
        .0;
    for i in 0..12u32 {
        if st.read(&c0, &g(7000 + i), 0, OBJ as u64).ok() != Some(pattern(7000 + i)) {
            return Err(format!("object {} written after recovery lost", 7000 + i));
        }
    }
    drop(st);
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .map(|_| ())
    .map_err(|e| format!("final fsck: {e}"))
}

fn matrix(stride: u64) -> (u64, u64) {
    let fresh12 = || fresh(12, 512, 90);
    let disk = fresh12();
    let (sb, dirs) = read_super(&mut disk.queue(), &mut SimClock::default()).unwrap();
    let geom = store::lend::Geom::of(&sb, &dirs).unwrap();
    let table = (
        geom.table_blk * 8,
        (geom.table_blk + 2 * geom.table_blocks) * 8,
    );
    let mut reference = Log::default();
    let st = mount_all(&disk);
    workload(&disk, st, &mut reference).unwrap();
    let total = disk.events() - reference.t0;
    assert!(
        reference.returned >= 2 && reference.moved > 0 && reference.reborrowed,
        "the workload must return chunks and borrow again: {reference:?}"
    );
    let busy = |k: u64| {
        reference
            .busy
            .iter()
            .any(|&(a, b)| k + 3 >= a && k <= b + 3)
    };
    let (mut runs, mut busy_runs) = (0, 0);
    for k in 0..=total {
        if !(busy(k) || k % stride == 0) {
            continue;
        }
        for pol in 0..4 {
            let disk = fresh12();
            let st = mount_all(&disk);
            disk.arm_crash(disk.events() + k);
            let mut log = Log::default();
            let _ = workload(&disk, st, &mut log);
            disk.crash_now();
            let img = cut_image(&disk, pol, table);
            verify(&img, &log).unwrap_or_else(|m| {
                panic!("cut at event {k}/{total} policy {pol}: {m}\nlog {log:?}")
            });
            runs += 1;
            busy_runs += busy(k) as u64;
        }
    }
    eprintln!(
        "reclaim crash matrix: {total} events, {runs} cuts ({busy_runs} while reclaim was busy), stride {stride}"
    );
    (runs, busy_runs)
}

#[test]
fn crash_matrix_reclaim() {
    let stride = std::env::var("RECLAIM_CRASH_STRIDE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(11);
    let (runs, busy) = matrix(stride);
    assert!(busy >= 4 * 6, "cuts while reclaim was busy: {busy}");
    assert!(runs > busy);
}

#[test]
#[ignore = "soak: every IO event (lab/elastic-crash.sh)"]
fn crash_matrix_reclaim_every_event() {
    matrix(1);
}

// ------------------------------------------------------------------------------- capacity is history-independent

/// Production defaults (`lend_auto` on as the OSD sets it, everything else `StoreCfg::default`).
fn prod_cfg() -> StoreCfg {
    let mut c = StoreCfg::default();
    c.shard.lend_auto = true;
    c
}

fn mount_prod(disk: &SimDisk) -> St {
    let d = disk.clone();
    Store::mount(move || d.queue(), SimClock::default(), prod_cfg())
        .unwrap()
        .0
}

const EC_OBJ: usize = 24 << 10;

/// Refill workload: per store shard a replicated collection (64 KiB objects + an omap entry) and an EC collection (shard
/// id 1; with `ec`, every odd object is a 24 KiB EC chunk with a hinfo-like xattr).
struct Mixed {
    rep: [CollT; 2],
    ec: [CollT; 2],
}

impl Mixed {
    fn new(st: &St) -> Self {
        let ec_of = |shard: usize| {
            (0..256)
                .map(|s| {
                    CollT::Pg(denc::types::SpgT {
                        pgid: denc::types::PgT::new(2, s),
                        shard: ShardId(1),
                    })
                })
                .find(|c| st.shard_of(c) == shard)
                .unwrap()
        };
        Mixed {
            rep: [coll_of(st, 0), coll_of(st, 1)],
            ec: [ec_of(0), ec_of(1)],
        }
    }

    /// (collection, object, payload bytes)
    fn obj(&self, shard: usize, ec: bool, i: u32) -> (CollT, Ghobject, usize) {
        if ec && i % 2 == 1 {
            let h = Hobject::new(format!("e{i}").as_bytes(), SnapId::NOSNAP, i, 2, b"");
            (
                self.ec[shard],
                Ghobject::new(h, Ghobject::NO_GEN, ShardId(1)),
                EC_OBJ,
            )
        } else {
            (self.rep[shard], g(i), OBJ)
        }
    }

    fn txn<'a>(&self, shard: usize, ec: bool, i: u32, d: &'a [u8]) -> OTxn<'a> {
        let (c, o, n) = self.obj(shard, ec, i);
        let mut t = OTxn::new();
        t.push(TOp::MkColl {
            cid: c,
            bits: 0,
            exist_ok: true,
        });
        t.write(c, &o, 0, &d[..n]);
        if n == EC_OBJ {
            t.setattr(c, &o, b"hinfo_key", &d[..48]);
        } else {
            t.omap_set(c, &o, b"k", &d[..96]);
        }
        t
    }

    /// Write objects from `first` until ENOSPC; returns (objects, payload bytes).
    fn fill(&self, cores: &mut Cores, shard: usize, ec: bool, first: u32) -> (u32, u64) {
        let mut bytes = 0;
        for i in first.. {
            let d = pattern(i);
            match cores.run(0, &self.txn(shard, ec, i, &d)) {
                Ok(()) => bytes += self.obj(shard, ec, i).2 as u64,
                Err(ObjError::NoSpace) => return (i - first, bytes),
                Err(e) => panic!("object {i}: {e:?}"),
            }
        }
        unreachable!()
    }

    fn remove(&self, cores: &mut Cores, shard: usize, ec: bool, ids: impl Iterator<Item = u32>) {
        for i in ids {
            let (c, o, _) = self.obj(shard, ec, i);
            let mut t = OTxn::new();
            t.remove(c, &o);
            cores.run(0, &t).unwrap();
        }
    }

    fn reads_back(&self, st: &mut St, shard: usize, ec: bool, ids: impl Iterator<Item = u32>) {
        for i in ids {
            let (c, o, n) = self.obj(shard, ec, i);
            assert_eq!(
                st.read(&c, &o, 0, n as u64).unwrap(),
                pattern(i)[..n],
                "shard {shard} object {i}"
            );
        }
    }
}

/// adr 0021 am. 61 gate (production defaults): shard 0 fills past its base into (nearly) the whole pool, deletes
/// everything (or all but 1 in 16: sparse chunks), restart, background rounds, then shard 1 fills to ENOSPC. Shard 1 must
/// reach what it reaches on a fresh device (only shard 0's base and its reclaim headroom are out of its reach, am. 56 /
/// am. 57); statfs after the delete equals the fresh device's minus the kept data, and drops by what the refill wrote.
/// Empty chunks go back in the background; sparse ones stay until the refill waits for them (am. 82: evacuated on
/// demand, the refill's writes wait instead of failing). Replicated only, and replicated + EC shard objects mixed.
#[test]
fn refill_of_another_shard_is_history_independent() {
    for ec in [false, true] {
        for keep_every in [0u32, 16] {
            refill_case(ec, keep_every);
        }
    }
}

fn refill_case(ec: bool, keep_every: u32) {
    let what = format!("ec {ec} keep 1/{keep_every}");
    // control: shard 1 alone on a fresh device
    let disk = fresh(96, 4096, 25);
    let st = mount_prod(&disk);
    let m = Mixed::new(&st);
    let (total, fresh_avail) = (st.statfs().total_bytes, st.statfs().avail_bytes);
    let mut cores = Cores::new(vec![st]);
    let (_, ctrl) = m.fill(&mut cores, 1, ec, 1_000_000);
    drop(cores);

    // history: shard 0 takes (nearly) the whole pool, then deletes
    let disk = fresh(96, 4096, 25);
    let st = mount_prod(&disk);
    let pool0 = free_pool(&st);
    let mut cores = Cores::new(vec![st]);
    let (n0, _) = m.fill(&mut cores, 0, ec, 0);
    assert!(
        lent(&cores.st[0], 0).len() as u64 + 1 >= pool0,
        "{what}: shard 0 borrowed the pool"
    );
    let kept = |i: &u32| keep_every != 0 && i.is_multiple_of(keep_every);
    m.remove(&mut cores, 0, ec, (0..n0).filter(|i| !kept(i)));
    let kept_bytes: u64 = (0..n0).filter(kept).map(|i| m.obj(0, ec, i).2 as u64).sum();
    let mut st = cores.st.pop().unwrap();
    st.checkpoint().unwrap();
    drop(st);

    // restart; background rounds give the empty chunks back, the sparse ones stay (nobody waits for a chunk)
    let st = mount_prod(&disk);
    let mut cores = Cores::new(vec![st]);
    let back = cores.settle(40_000, |c| {
        let st = &c.st[0];
        (keep_every != 0 || lent(st, 0).is_empty())
            && !st.lend_busy()
            && !st.shards[0].evac_active()
    });
    let st = &cores.st[0];
    let s0 = st.shards[0].defrag_stats();
    assert!(
        back && s0.evac_blocks == 0,
        "{what}: shard 0 keeps {:?} stats {s0:?} cells {:?} statfs {:?}",
        lent(st, 0),
        st.shards[0].sh.meta_cells(),
        st.shards[0].sh.statfs()
    );
    assert_eq!(
        free_pool(st) + lent(st, 0).len() as u64,
        pool0,
        "{what}: every other chunk back"
    );
    // a shard with live data keeps its reclaim headroom (am. 57: user floor + request watermark + `reclaim_hyst_pct` of
    // its base, counted in whole free windows): with the kept objects scattered over every base window that headroom
    // stays in borrowed chunks
    let headroom = |st: &St| {
        let (sf, cfg, chunk) = (st.shards[0].sh.statfs(), prod_cfg().shard, 256);
        let base = sf.data_blocks - lent(st, 0).len() as u64 * chunk;
        let room = sf.data_reserve
            + chunk * cfg.lend_wm_pct as u64 / 100
            + base * cfg.reclaim_hyst_pct as u64 / 100;
        if keep_every == 0 {
            0
        } else {
            room.div_ceil(chunk)
        }
    };
    let sf = cores.st[0].statfs();
    assert_eq!(sf.total_bytes, total, "{what}: total");
    // tree pages and rounding of the kept objects (two chunks), the headroom
    let slack = (2 + headroom(&cores.st[0])) * 256 * 4096;
    assert!(
        sf.avail_bytes + kept_bytes + slack >= fresh_avail && sf.avail_bytes <= fresh_avail,
        "{what}: avail {} fresh {fresh_avail} kept {kept_bytes}",
        sf.avail_bytes
    );

    // refill shard 1 (time passes: its writes wait while shard 0 evacuates)
    cores.tick = 10_000_000;
    let (n1, wrote) = m.fill(&mut cores, 1, ec, 1_000_000);
    cores.tick = 0;
    let st = &cores.st[0];
    let (kept_chunks, s1) = (lent(st, 0).len() as u64, st.shards[0].defrag_stats());
    eprintln!(
        "{what}: refill {wrote} bytes vs {ctrl} fresh, shard 0 keeps {kept_chunks} chunks (headroom {}), waits {} {s1:?}",
        headroom(st),
        st.pool_waits()
    );
    assert!(
        kept_chunks <= headroom(st),
        "{what}: shard 0 keeps {kept_chunks} chunks, headroom {}: {s1:?}",
        headroom(st)
    );
    assert!(
        (wrote + kept_chunks * 256 * 4096) * 100 >= ctrl * 97,
        "{what}: refill {wrote} bytes vs {ctrl} on a fresh device, {kept_chunks} chunks kept"
    );
    let used = sf.avail_bytes - cores.st[0].statfs().avail_bytes;
    assert!(
        used >= wrote && used <= wrote + wrote / 8 + slack,
        "{what}: statfs dropped {used} for {wrote} written"
    );
    let mut st = cores.st.pop().unwrap();
    st.checkpoint().unwrap();
    drop(st);
    fsck_ok(&disk);
    let mut st = mount_prod(&disk);
    m.reads_back(&mut st, 0, ec, (0..n0).filter(kept));
    m.reads_back(&mut st, 1, ec, (1_000_000..1_000_000 + n1).step_by(7));
}
