// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Shared pool with requests (adr 0021 am. 52, elastic shards step 3): a shard that outgrows its base asks the pool owner
//! (in its poll, fallback at the allocation gate), the owner writes the lending table asynchronously, the shard uses the
//! chunk only after the write is durable. Single store (owner and borrower in one), two per-core stores exchanging
//! `LendMsg` values by hand, blocking `commit` path, statfs, and a power-cut matrix with a request in flight.
//!
//! Matrix size: `POOL_CRASH_STRIDE` (default 7; every event inside a pool write); soak `crash_matrix_pool_every_event`
//! (ignored, stride 1) runs from lab/elastic-crash.sh.
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
use store::obj::{OTxn, ObjError, Store, StoreCfg, TOp};

type St = Store<SimDev, SimClock>;
type Hook<'a> = Box<dyn FnMut(&[St], &LendMsg) + 'a>;
const OBJ: usize = 64 << 10;

fn sim(mib: u64, lba: u32) -> SimConfig {
    let mut c = SimConfig::new(mib << 20);
    c.lba_size = lba;
    c.lba_count = (mib << 20) / lba as u64;
    c
}

fn params(base_pct: u32) -> MkfsParams {
    MkfsParams {
        shards: 2,
        wal_blocks: 256,
        align_blocks: 1,
        meta_pct: 4,
        chunked: true,
        chunk_blocks: 256, // 1 MiB
        base_pct,
        ..Default::default()
    }
}

fn fresh(mib: u64, lba: u32, base_pct: u32) -> SimDisk {
    let disk = SimDisk::new(sim(mib, lba));
    mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &params(base_pct),
    )
    .unwrap();
    disk
}

fn cfg(owner: bool) -> StoreCfg {
    let mut c = StoreCfg::default();
    c.shard.lend_auto = true;
    c.shard.lend_owner = owner;
    c
}

/// All shards in one store (owner and borrowers).
fn mount_all(disk: &SimDisk) -> St {
    let d = disk.clone();
    Store::mount(move || d.queue(), SimClock::default(), cfg(true))
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

/// A PG collection that lives on `shard`.
fn coll_of(st: &St, shard: usize) -> CollT {
    (0..256)
        .map(|s| pgc(1, s))
        .find(|c| st.shard_of(c) == shard)
        .unwrap()
}

/// The cores of an OSD in one thread: polls, moves `LendMsg`s (requests to core 0, answers to the core of the shard) and
/// records every message with a check hook.
struct Cores<'a> {
    st: Vec<St>,
    acked: Vec<Vec<u64>>,
    tok: u64,
    log: Vec<LendMsg>,
    /// Called for every answer before it is delivered (core index of the receiver).
    hook: Option<Hook<'a>>,
    /// Drop the owner's `Size` updates to this core (a hint gone stale between two updates).
    mute_size: Option<usize>,
}

impl<'a> Cores<'a> {
    fn new(st: Vec<St>) -> Self {
        Cores {
            acked: vec![Vec::new(); st.len()],
            st,
            tok: 1,
            log: Vec::new(),
            hook: None,
            mute_size: None,
        }
    }

    /// One round: poll every core, deliver the pool messages, let the clock advance.
    fn step(&mut self) -> Result<(), ObjError> {
        let n = self.st.len();
        for c in 0..n {
            let mut a = Vec::new();
            self.st[c].poll(&mut a)?;
            self.acked[c].append(&mut a);
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
            if matches!(m, LendMsg::Size { .. }) && self.mute_size == Some(to) {
                continue;
            }
            if !matches!(m, LendMsg::Request { .. })
                && let Some(h) = self.hook.as_mut()
            {
                h(&self.st, &m);
            }
            self.st[to].lend_in(m);
        }
        for s in self.st.iter_mut() {
            s.idle();
        }
        Ok(())
    }

    /// Queue `t` on `core` and run until it is acked (`Ok`) or fails (`Err`).
    fn run(&mut self, core: usize, t: &OTxn) -> Result<(), ObjError> {
        let tok = self.tok;
        self.tok += 1;
        self.st[core].queue(t, tok)?;
        for _ in 0..2_000_000 {
            self.step()?;
            if let Some(i) = self.acked[core].iter().position(|&x| x == tok) {
                self.acked[core].swap_remove(i);
                return Ok(());
            }
            let mut errs = Vec::new();
            self.st[core].take_queue_errors(&mut errs);
            if let Some((_, e)) = errs.into_iter().find(|e| e.0 == tok) {
                return Err(e);
            }
        }
        panic!("txn {tok} never completed");
    }

    /// Write 64 KiB objects `first..` into PG `c` of `core` until ENOSPC; returns the number written. Any other error
    /// fails the test.
    fn fill(&mut self, core: usize, c: CollT, first: u32, limit: u32) -> u32 {
        for i in first..first + limit {
            let mut t = OTxn::new();
            if first == 0 && i == 0 {
                t.mkcoll(c);
            }
            let d = pattern(i);
            t.write(c, &g(i), 0, &d);
            match self.run(core, &t) {
                Ok(()) => {}
                Err(ObjError::NoSpace) => return i - first,
                Err(e) => panic!("object {i}: {e:?}"),
            }
        }
        panic!("no ENOSPC within {limit} objects");
    }
}

fn free_pool(st: &St) -> u64 {
    st.lending().unwrap().free_chunks()
}

/// Statfs invariants of a store.
fn check_statfs(st: &St) -> store::obj::StoreStatfs {
    let s = st.statfs();
    assert!(s.pooled);
    assert_eq!(s.used_bytes + s.avail_bytes, s.total_bytes, "{s:?}");
    s
}

#[test]
fn one_pg_grows_past_its_base_until_the_pool_is_dry() {
    let disk = fresh(96, 4096, 50);
    let st = mount_all(&disk);
    let geom = st.lending().unwrap().geom.clone();
    let chunk = geom.chunk * store::BLK as u64;
    let base_bytes = geom.base * chunk;
    let pool0 = free_pool(&st);
    assert_eq!(pool0, geom.pool());
    // statfs counts the lendable space: total = bases + pool, nothing used yet, no fullest-shard charge
    let s0 = check_statfs(&st);
    assert_eq!(s0.total_bytes, 2 * base_bytes + pool0 * chunk);
    assert!(s0.avail_bytes * 100 >= s0.total_bytes * 95, "{s0:?}");
    let c = coll_of(&st, 0);
    let mut cores = Cores::new(vec![st]);
    let n = cores.fill(0, c, 0, 100_000);
    let st = &cores.st[0];
    let written = n as u64 * OBJ as u64;
    // far past the base of its shard: ENOSPC only when no chunk was left to lend
    assert!(
        written > base_bytes + base_bytes / 2,
        "written {written} base {base_bytes}"
    );
    assert_eq!(free_pool(st), 0, "ENOSPC while the pool still had chunks");
    assert!(
        written >= base_bytes + (pool0 - 1) * chunk * 9 / 10,
        "written {written}"
    );
    let s = check_statfs(st);
    assert_eq!(
        s.total_bytes,
        2 * base_bytes + pool0 * chunk,
        "the pool is lent, not lost"
    );
    // real usage: close to what was written (meta cells and the reserve on top), the idle shard 1 is free
    assert!(
        s.used_bytes >= written && s.used_bytes < written + written / 8,
        "{s:?} written {written}"
    );
    assert!(
        s.avail_bytes >= base_bytes * 9 / 10,
        "the idle shard's base is free capacity: {s:?}"
    );
    assert!(
        cores.st[0].shards[0].sh.lend.denies >= 1,
        "the dry pool answered"
    );
    // every object reads back; after a remount and with fsck too
    let verify = |st: &mut St, n: u32| {
        let c = coll_of(st, 0);
        for i in (0..n).step_by(3) {
            assert_eq!(
                st.read(&c, &g(i), 0, OBJ as u64).unwrap(),
                pattern(i),
                "object {i}"
            );
        }
    };
    let mut st = cores.st.pop().unwrap();
    verify(&mut st, n);
    st.checkpoint().unwrap();
    drop(st);
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .unwrap();
    let mut st = mount_all(&disk);
    verify(&mut st, n);
    // free space makes the shard writable again (no restart needed), the pool stays as lent
    let c = coll_of(&st, 0);
    let mut cores = Cores::new(vec![st]);
    for i in 0..n / 2 {
        let mut t = OTxn::new();
        t.remove(c, &g(i));
        cores.run(0, &t).unwrap();
    }
    cores.st[0].checkpoint().unwrap();
    cores.st[0].checkpoint().unwrap();
    let more = cores.fill(0, c, 1_000_000, 100_000);
    assert!(more >= n / 2 - 8, "{more} writes after freeing {}", n / 2);
}

/// The fullest shard of a pooled store is judged against its capacity plus the pool it may still borrow (adr 0021 S4):
/// a shard at its base with a big pool is not full; the same shard with the pool dry is full, although the idle shard's
/// unlendable base keeps the device sum far from full (review S1: the sum alone hid it from the full ratios).
#[test]
fn pooled_fullest_shard_counts_the_pool_it_can_still_borrow() {
    let disk = fresh(96, 4096, 50);
    let st = mount_all(&disk);
    let geom = st.lending().unwrap().geom.clone();
    let chunk = geom.chunk * store::BLK as u64;
    let base_bytes = geom.base * chunk;
    let c = coll_of(&st, 0);
    let mut cores = Cores::new(vec![st]);
    // shard 0 at about its base: the pool (as big as both bases) is still free
    let at_base = (base_bytes / OBJ as u64) as u32;
    for i in 0..at_base {
        let mut t = OTxn::new();
        if i == 0 {
            t.mkcoll(c);
        }
        let d = pattern(i);
        t.write(c, &g(i), 0, &d);
        cores.run(0, &t).unwrap();
    }
    let s = check_statfs(&cores.st[0]);
    assert!(free_pool(&cores.st[0]) > 0);
    assert!(
        s.fullest_shard_pct < 70.0,
        "a shard at its base with a free pool is not full: {s:?}"
    );
    // pool dry, shard 0 at its floor: full, whatever the sum says
    cores.fill(0, c, at_base, 100_000);
    let st = &cores.st[0];
    assert_eq!(free_pool(st), 0);
    let s = check_statfs(st);
    assert!(
        s.avail_bytes >= base_bytes * 9 / 10,
        "the idle base keeps the sum low: {s:?}"
    );
    assert!(
        s.fullest_shard_pct >= 90.0,
        "the dry-pool shard reads full: {s:?}"
    );
}

/// Per-core stores (the production layout): a shard on a core without the pool that never asked for a chunk still
/// knows the true pool size from the owner's `Size` updates, so at its base (25 % of the device, the default layout) it
/// is far from full (adr 0021 am. 72: it read its base as everything it could get and drove the OSD full at ~25 %).
#[test]
fn per_core_shard_at_its_base_counts_the_owners_pool() {
    let disk = fresh(96, 4096, 25);
    let st = mount_cores(&disk);
    let geom = st[0].lending().unwrap().geom.clone();
    let chunk = geom.chunk * store::BLK as u64;
    let base_bytes = geom.base * chunk;
    let c1 = coll_of(&st[1], 1);
    let mut cores = Cores::new(st);
    // one chunk below the base: no request yet (the shard asks below a quarter chunk of free space above its floor)
    let n = ((base_bytes - chunk) / OBJ as u64) as u32;
    for i in 0..n {
        let mut t = OTxn::new();
        if i == 0 {
            t.mkcoll(c1);
        }
        let d = pattern(i);
        t.write(c1, &g(i), 0, &d);
        cores.run(1, &t).unwrap();
    }
    assert_eq!(
        cores.st[1].shards[0].sh.lend.grants, 0,
        "no chunk borrowed yet"
    );
    let pool = free_pool(&cores.st[0]) * geom.chunk;
    assert_eq!(pool, geom.pool() * geom.chunk);
    assert!(
        cores
            .log
            .iter()
            .any(|m| matches!(m, LendMsg::Size { shard: 1, pool: p, .. } if *p == pool)),
        "the owner announced the pool to core 1: {:?}",
        cores.log
    );
    assert_eq!(cores.st[1].shards[0].sh.lend.pool, pool);
    let f = cores.st[1].shards[0].sh.statfs();
    assert!(f.fill_ratio() > 0.8, "the shard is near its base: {f:?}");
    let s1 = cores.st[1].statfs();
    let own = f.fill_ratio() * geom.base as f64 / (geom.base + geom.pool()) as f64;
    assert!(
        (f64::from(s1.fullest_shard_pct) / 100.0 - own).abs() < 0.01 && s1.fullest_shard_pct < 30.0,
        "fill against base + pool: {s1:?}"
    );
    // balanced view of the OSD: owner's statfs (its shard + the pool) plus core 1's: real usage, no fullest charge
    let s0 = cores.st[0].statfs();
    let (total, used) = (
        s0.total_bytes + s1.total_bytes,
        s0.used_bytes + s1.used_bytes,
    );
    assert_eq!(
        total,
        geom.data_start.len() as u64 * base_bytes + geom.pool() * chunk
    );
    let device_fill = used as f64 / total as f64;
    assert!(
        f64::from(s1.fullest_shard_pct.max(s0.fullest_shard_pct)) / 100.0 <= device_fill + 0.25,
        "fullest {s0:?} {s1:?} vs device {device_fill}"
    );
    // the shard keeps borrowing until the pool is dry: ENOSPC only then, and only then it reads full
    let more = cores.fill(1, c1, n, 100_000);
    assert_eq!(
        free_pool(&cores.st[0]),
        0,
        "ENOSPC while the pool still had chunks"
    );
    let written = (n + more) as u64 * OBJ as u64;
    assert!(
        written >= base_bytes + (geom.pool() - 1) * chunk * 9 / 10,
        "written {written} base {base_bytes} pool {}",
        geom.pool() * chunk
    );
    assert!(cores.st[1].statfs().fullest_shard_pct >= 90.0);
}

/// A pool hint gone stale (the owner's `Size` updates to core 1 lost while shard 0 drains the pool) never lets shard 1
/// place more than it can get: its request is denied, writes end in a plain ENOSPC (no fail-stop), the store stays
/// consistent and the shard reads full.
#[test]
fn stale_pool_hint_ends_in_enospc_not_failure() {
    let disk = fresh(96, 4096, 25);
    let st = mount_cores(&disk);
    let geom = st[0].lending().unwrap().geom.clone();
    let chunk = geom.chunk * store::BLK as u64;
    let base_bytes = geom.base * chunk;
    let (c0, c1) = (coll_of(&st[0], 0), coll_of(&st[1], 1));
    let mut cores = Cores::new(st);
    // the first announce reaches core 1 (one poll round), later ones are lost
    cores.step().unwrap();
    let pool0 = geom.pool() * geom.chunk;
    assert_eq!(cores.st[1].shards[0].sh.lend.pool, pool0);
    cores.mute_size = Some(1);
    let n0 = cores.fill(0, c0, 0, 100_000);
    assert!(n0 as u64 * OBJ as u64 > base_bytes);
    assert_eq!(free_pool(&cores.st[0]), 0);
    assert_eq!(
        cores.st[1].shards[0].sh.lend.pool, pool0,
        "core 1 still believes the pool is free"
    );
    let n1 = cores.fill(1, c1, 0, 100_000);
    assert!(
        (n1 as u64 * OBJ as u64) < base_bytes,
        "shard 1 placed {} past its base {base_bytes}",
        n1 as u64 * OBJ as u64
    );
    assert!(
        cores.st[1].shards[0].sh.lend.denies >= 1,
        "the owner answered"
    );
    assert!(
        cores.st[1].statfs().fullest_shard_pct >= 90.0,
        "{:?}",
        cores.st[1].statfs()
    );
    // freeing space makes it writable again; everything reads back after fsck and a remount
    for i in 0..n1 / 2 {
        let mut t = OTxn::new();
        t.remove(c1, &g(i));
        cores.run(1, &t).unwrap();
    }
    for st in cores.st.iter_mut() {
        st.checkpoint().unwrap();
    }
    assert!(cores.fill(1, c1, 1_000_000, 100_000) > 0);
    cores.st.clear();
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .unwrap();
    let mut st = mount_cores(&disk);
    for i in (n1 / 2..n1).step_by(5) {
        assert_eq!(st[1].read(&c1, &g(i), 0, OBJ as u64).unwrap(), pattern(i));
    }
    for i in (0..n0).step_by(11) {
        assert_eq!(st[0].read(&c0, &g(i), 0, OBJ as u64).unwrap(), pattern(i));
    }
}

#[test]
fn blocking_commit_takes_chunks_at_the_gate() {
    let disk = fresh(48, 4096, 50);
    let mut st = mount_all(&disk);
    let geom = st.lending().unwrap().geom.clone();
    let pool0 = free_pool(&st);
    let c = coll_of(&st, 1);
    let mut i = 0;
    loop {
        let mut t = OTxn::new();
        if i == 0 {
            t.mkcoll(c);
        }
        let d = pattern(i);
        t.write(c, &g(i), 0, &d);
        match st.commit(&t) {
            Ok(()) => i += 1,
            Err(ObjError::NoSpace) => break,
            Err(e) => panic!("object {i}: {e:?}"),
        }
        assert!(i < 100_000);
    }
    assert_eq!(free_pool(&st), 0, "ENOSPC with pool chunks left");
    let lent = st
        .lent_chunks(1)
        .unwrap()
        .iter()
        .filter(|e| e.0 != HOLE)
        .count() as u64;
    assert_eq!(lent, pool0, "the whole pool went to the one shard");
    assert!(i as u64 * OBJ as u64 > geom.base * geom.chunk * store::BLK as u64);
    let s = check_statfs(&st);
    assert!(s.used_bytes > 0);
    drop(st);
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .unwrap();
}

#[test]
fn both_shards_ask_at_once_one_table_block_one_change_in_flight() {
    let disk = fresh(48, 4096, 50);
    let st = mount_all(&disk);
    let (c0, c1) = (coll_of(&st, 0), coll_of(&st, 1));
    let geom = st.lending().unwrap().geom.clone();
    let mut cores = Cores::new(vec![st]);
    // concurrent txns of both shards so their requests meet in the owner's queue (the whole pool fits one table block:
    // `Lending::stage` asserts a second change of the block is never started while one is in flight)
    let mut want = BTreeMap::new();
    let mut dead = [false; 2];
    let (mut tok0, mut i) = (1u64 << 32, 0u32);
    while !(dead[0] && dead[1]) {
        let mut pend = Vec::new();
        for (sh, c) in [(0usize, c0), (1, c1)] {
            if dead[sh] {
                continue;
            }
            let mut t = OTxn::new();
            if i == 0 {
                t.mkcoll(c);
            }
            let id = i * 2 + sh as u32;
            let d = pattern(id);
            t.write(c, &g(id), 0, &d);
            tok0 += 1;
            match cores.st[0].queue(&t, tok0) {
                Ok(_) => pend.push((tok0, sh, id)),
                Err(ObjError::NoSpace) => dead[sh] = true,
                Err(e) => panic!("{e:?}"),
            }
        }
        for _ in 0..1_000_000 {
            // a txn parked for a chunk the other shard could give back fails with NoSpace once that shard used the
            // room itself: `poll` reports it, `take_queue_errors` names the txn
            match cores.step() {
                Ok(()) | Err(ObjError::NoSpace) => {}
                Err(e) => panic!("{e:?}"),
            }
            let mut errs = Vec::new();
            cores.st[0].take_queue_errors(&mut errs);
            for (tk, e) in errs {
                let &(_, sh, _) = pend.iter().find(|p| p.0 == tk).unwrap();
                assert_eq!(e, ObjError::NoSpace);
                dead[sh] = true;
                pend.retain(|p| p.0 != tk);
            }
            let acked = std::mem::take(&mut cores.acked[0]);
            for tk in acked {
                if let Some(p) = pend.iter().position(|p| p.0 == tk) {
                    let (_, sh, id) = pend.remove(p);
                    want.insert(id, sh);
                }
            }
            if pend.is_empty() {
                break;
            }
        }
        assert!(pend.is_empty(), "txns never finished");
        i += 1;
        assert!(i < 100_000);
    }
    let st = &cores.st[0];
    assert_eq!(free_pool(st), 0);
    let lent = |sh: u32| {
        st.lent_chunks(sh)
            .unwrap()
            .iter()
            .filter(|e| e.0 != HOLE)
            .count() as u64
    };
    assert!(
        lent(0) >= 1 && lent(1) >= 1,
        "both shards borrowed: {} {}",
        lent(0),
        lent(1)
    );
    assert_eq!(lent(0) + lent(1), geom.pool());
    assert!(want.len() > 40);
    check_statfs(st);
    let mut st = cores.st.pop().unwrap();
    for (&id, &sh) in want.iter().step_by(5) {
        let c = if sh == 0 { c0 } else { c1 };
        assert_eq!(st.read(&c, &g(id), 0, OBJ as u64).unwrap(), pattern(id));
    }
    drop(st);
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .unwrap();
    // the table the owner wrote is what a mount sees
    let (_, dirs) = read_super(&mut disk.queue(), &mut SimClock::default()).unwrap();
    assert_eq!(
        dirs.iter()
            .map(|d| d.lent.iter().filter(|&&p| p != HOLE).count() as u64)
            .sum::<u64>(),
        geom.pool()
    );
}

#[test]
fn per_core_stores_request_through_messages_in_grant_order() {
    let disk = fresh(96, 4096, 50);
    let st = mount_cores(&disk);
    assert!(st[0].is_pool_owner() && !st[1].is_pool_owner() && st[1].lending().is_none());
    let geom = st[0].lending().unwrap().geom.clone();
    let c1 = coll_of(&st[1], 1);
    let d = disk.clone();
    let mut cores = Cores::new(st);
    // every answer: the chunk is in the table ON THE DEVICE (power cut now = it is there), and the borrower does not hold it yet
    cores.hook = Some(Box::new(move |st: &[St], m: &LendMsg| {
        if let LendMsg::Grant { shard, phys, .. } = *m {
            assert!(
                st[(shard % 2) as usize]
                    .lent_chunks(shard)
                    .unwrap()
                    .iter()
                    .all(|e| e.0 != phys),
                "borrower already uses chunk {phys} before the answer"
            );
            let img = d.crash_image(CrashPolicy::DROP_ALL);
            let dd = SimDisk::from_image(&img, sim(96, 4096));
            let (_, dirs) = read_super(&mut dd.queue(), &mut SimClock::default()).unwrap();
            assert!(
                dirs[shard as usize].lent.contains(&phys),
                "grant {phys} answered before the table write was durable"
            );
        }
    }));
    let n = cores.fill(1, c1, 0, 100_000);
    assert!(n > 100);
    // owner and borrower agree; the pool is dry; requests really crossed (core 1 never touches the table)
    assert_eq!(free_pool(&cores.st[0]), 0);
    let grants: Vec<u64> = cores
        .log
        .iter()
        .filter_map(|m| match m {
            LendMsg::Grant { shard: 1, phys, .. } => Some(geom.index_of(*phys).unwrap()),
            _ => None,
        })
        .collect();
    assert_eq!(grants.len() as u64, geom.pool());
    // plan order for shard 1: its own region from the base end up (adjacent to its base), then the other region from its
    // far end (highest address first)
    let own = (0..geom.per).map(|k| geom.per + k);
    let other = (0..geom.per).rev();
    assert_eq!(grants, own.chain(other).collect::<Vec<_>>(), "grant order");
    let reqs = cores
        .log
        .iter()
        .filter(|m| matches!(m, LendMsg::Request { shard: 1, .. }))
        .count();
    assert!(
        reqs as u64 >= geom.pool() && reqs < 3 * geom.pool() as usize + 8,
        "requests {reqs}"
    );
    // statfs of the borrower's core: its own capacity (the pool is counted by the owner only), pooled flag set
    let s1 = cores.st[1].statfs();
    let s0 = cores.st[0].statfs();
    assert!(s1.pooled && s0.pooled);
    let chunk = geom.chunk * store::BLK as u64;
    assert_eq!(
        s0.total_bytes,
        geom.base * chunk,
        "dry pool, owner total = its shard"
    );
    assert_eq!(s1.total_bytes, (geom.base + geom.pool()) * chunk);
    assert!(s1.used_bytes >= n as u64 * OBJ as u64);
    cores.st.clear();
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .unwrap();
    let mut st = mount_cores(&disk);
    for i in (0..n).step_by(7) {
        assert_eq!(st[1].read(&c1, &g(i), 0, OBJ as u64).unwrap(), pattern(i));
    }
}

// ------------------------------------------------------------------------------------------------------ crash matrix

#[derive(Default, Debug)]
struct Log {
    /// object -> pattern seed of every acked write
    acked: BTreeMap<u32, u32>,
    /// the object whose write was queued and not acked
    inflight: Option<(u32, u32)>,
    /// borrowed chunks of shard 0 as the store held them (each one was durable before it was added)
    held: Vec<u64>,
    /// IO event ranges `[a, b)` while a pool request / table write was pending (relative to the workload start)
    pool_events: Vec<(u64, u64)>,
}

/// Fill shard 0 past its base (several grants), overwrite a few, checkpoint. Stops at the first error (the cut).
fn workload(disk: &SimDisk, st: St, log: &mut Log) -> Result<(), ()> {
    let c = coll_of(&st, 0);
    let t0 = disk.events();
    let mut cores = Cores::new(vec![st]);
    let mut open: Option<u64> = None;
    let note = |cores: &Cores, log: &mut Log, open: &mut Option<u64>| {
        let st = &cores.st[0];
        let held: Vec<u64> = st
            .lent_chunks(0)
            .unwrap()
            .iter()
            .map(|e| e.0)
            .filter(|&p| p != HOLE)
            .collect();
        if held.len() > log.held.len() {
            log.held = held;
        }
        let e = disk.events() - t0;
        match (st.lend_busy(), *open) {
            (true, None) => *open = Some(e),
            (false, Some(a)) => {
                log.pool_events.push((a, e + 1));
                *open = None;
            }
            _ => {}
        }
    };
    let mut seeds: Vec<(u32, u32)> = (0..70).map(|i| (i, i)).collect();
    // overwrite some of the early objects at the end
    seeds.extend((0..6).map(|i| (i * 3, 500 + i)));
    for (k, &(i, seed)) in seeds.iter().enumerate() {
        let mut t = OTxn::new();
        if k == 0 {
            t.mkcoll(c);
        }
        let d = pattern(seed);
        t.write(c, &g(i), 0, &d);
        log.inflight = Some((i, seed));
        let tok = cores.tok;
        cores.tok += 1;
        if cores.st[0].queue(&t, tok).is_err() {
            return Err(());
        }
        let mut done = false;
        for _ in 0..2_000_000 {
            if cores.step().is_err() {
                return Err(());
            }
            note(&cores, log, &mut open);
            if cores.acked[0].contains(&tok) {
                done = true;
                break;
            }
            let mut errs = Vec::new();
            cores.st[0].take_queue_errors(&mut errs);
            if !errs.is_empty() {
                return Err(());
            }
            if disk.crashed() {
                return Err(());
            }
        }
        if !done {
            return Err(());
        }
        cores.acked[0].retain(|&x| x != tok);
        log.acked.insert(i, seed);
        log.inflight = None;
    }
    // drain pool activity and checkpoint
    for _ in 0..200 {
        cores.step().map_err(|_| ())?;
        note(&cores, log, &mut open);
    }
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
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .map_err(|e| format!("fsck: {e}"))?;
    let (_, dirs) =
        read_super(&mut disk.queue(), &mut SimClock::default()).map_err(|e| format!("{e:?}"))?;
    // every chunk the shard held in memory was durable first; at most the request in flight is durable on top, owned
    // by the shard and unused
    let got: Vec<u64> = dirs[0]
        .lent
        .iter()
        .copied()
        .filter(|&p| p != HOLE)
        .collect();
    if let Some(p) = log.held.iter().find(|p| !got.contains(p)) {
        return Err(format!(
            "chunk {p} was in use by the shard but is not in the durable table {got:?}"
        ));
    }
    if got.len() > log.held.len() + 1 {
        return Err(format!(
            "table lends {got:?}, store held {:?} (one request in flight at most)",
            log.held
        ));
    }
    if dirs[1].lent.iter().any(|&p| p != HOLE) {
        return Err("chunk lent to the idle shard".into());
    }
    // acked objects intact, the one in flight old / new / absent
    if !log.acked.is_empty() || log.inflight.is_some() {
        let c = coll_of(&st, 0);
        for (&i, &seed) in &log.acked {
            let alt = match log.inflight {
                Some((j, s)) if j == i => Some(s),
                _ => None,
            };
            let d = st
                .read(&c, &g(i), 0, OBJ as u64)
                .map_err(|e| format!("read o{i}: {e:?}"))?;
            if d != pattern(seed) && alt.is_none_or(|a| d != pattern(a)) {
                return Err(format!("object {i}: wrong content"));
            }
        }
    }
    // keeps working: borrow more, write, remount, fsck
    let c = coll_of(&st, 0);
    let mut t = OTxn::new();
    t.push(TOp::MkColl {
        cid: c,
        bits: 0,
        exist_ok: true,
    });
    st.commit(&t).map_err(|e| format!("mkcoll: {e:?}"))?;
    for i in 0..12u32 {
        let mut t = OTxn::new();
        let d = pattern(7000 + i);
        t.write(c, &g(7000 + i), 0, &d);
        st.commit(&t).map_err(|e| {
            format!(
                "write after recovery {i}: {e:?} lent {:?} free chunks {} statfs {:?} shard {:?}",
                st.lent_chunks(0),
                st.lending().unwrap().free_chunks(),
                st.statfs(),
                st.shards[0].sh.statfs()
            )
        })?;
    }
    drop(st);
    let d = disk.clone();
    let mut st = Store::mount(move || d.queue(), SimClock::default(), cfg(true))
        .map_err(|e| format!("remount: {e:?}"))?
        .0;
    for i in 0..12u32 {
        if st.read(&c, &g(7000 + i), 0, OBJ as u64).ok() != Some(pattern(7000 + i)) {
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
    let (_, dirs) = read_super(&mut disk.queue(), &mut SimClock::default()).unwrap();
    let geom = store::lend::Geom::of(
        &read_super(&mut disk.queue(), &mut SimClock::default())
            .unwrap()
            .0,
        &dirs,
    )
    .unwrap();
    let table = (
        geom.table_blk * 8,
        (geom.table_blk + 2 * geom.table_blocks) * 8,
    );
    let mut reference = Log::default();
    let st = mount_all(&disk);
    let start = disk.events();
    workload(&disk, st, &mut reference).unwrap();
    let total = disk.events() - start;
    assert!(
        reference.held.len() >= 2,
        "the workload must borrow several chunks: {:?}",
        reference.held
    );
    assert!(!reference.pool_events.is_empty());
    let in_pool = |k: u64| {
        reference
            .pool_events
            .iter()
            .any(|&(a, b)| k + 3 >= a && k <= b + 3)
    };
    let (mut runs, mut pool_runs) = (0, 0);
    for k in 0..=total {
        if !(in_pool(k) || k % stride == 0) {
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
            pool_runs += in_pool(k) as u64;
        }
    }
    eprintln!(
        "pool crash matrix: {total} events, {runs} cuts ({pool_runs} with a request pending), stride {stride}"
    );
    (runs, pool_runs)
}

#[test]
fn crash_matrix_pool() {
    let stride = std::env::var("POOL_CRASH_STRIDE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7);
    let (runs, pool) = matrix(stride);
    assert!(pool >= 4 * 6, "cuts inside pool writes: {pool}");
    assert!(runs > pool);
}

#[test]
#[ignore = "soak: every IO event (lab/elastic-crash.sh)"]
fn crash_matrix_pool_every_event() {
    matrix(1);
}

// ------------------------------------------------------------------- blocking commit vs an async grant in flight

/// Blocking commits into PG `c` of shard `si` until its whole free windows are below the request
/// watermark (the next poll asks the pool), nothing held.
fn commit_below_watermark(st: &mut St, si: usize, c: CollT) -> u32 {
    let big = vec![7u8; 4 << 20];
    let mut i = 0u32;
    loop {
        let f = st.shards[si].sh.statfs();
        let free = f.data_free.saturating_sub(f.data_reserve);
        let wm = st.shards[si].sh.lend.wm;
        // the request fires on whole free windows (adr 0021 am. 56); free blocks below the mark imply it
        let windows = (st.shards[si].sh.state().alloc.free_windows() * store::alloc::WIN)
            .saturating_sub(f.data_reserve);
        if (windows < wm || free < wm) && f.data_held == 0 {
            return i;
        }
        let mut t = OTxn::new();
        if i == 0 {
            t.mkcoll(c);
        }
        // big objects while far from the watermark, then 16 KiB steps
        let n = if free > wm + 4 * 1024 + 256 {
            big.len()
        } else {
            16 << 10
        };
        t.write(c, &g(i), 0, &big[..n]);
        st.commit(&t).unwrap();
        if f.data_held > 0 {
            st.checkpoint().unwrap();
        }
        i += 1;
        assert!(i < 100_000);
    }
}

/// An OSD mixes blocking commits (split, create collection) with polled txns. A poll sent the shard's request and
/// the owner's table write is in flight; a blocking commit then needs a chunk at the gate. It must wait for that
/// grant (or take another one), not answer ENOSPC while the pool has chunks.
#[test]
fn blocking_commit_with_a_pool_grant_in_flight() {
    let disk = fresh(48, 4096, 50);
    let mut st = mount_all(&disk);
    let c = coll_of(&st, 1);
    let n = commit_below_watermark(&mut st, 1, c);
    let mut acked = Vec::new();
    st.poll(&mut acked).unwrap();
    assert!(
        st.lend_busy() && st.shards[1].sh.lend.inflight,
        "the poll sent the request, its table write is in flight"
    );
    let pool = free_pool(&st);
    assert!(pool > 2);
    let d9 = vec![9u8; 512 << 10];
    let mut t = OTxn::new();
    t.write(c, &g(n), 0, &d9);
    st.commit(&t).expect("ENOSPC with chunks in the pool");
    assert_eq!(
        st.read(&c, &g(n), 0, 512 << 10).unwrap(),
        vec![9u8; 512 << 10]
    );
    for _ in 0..1000 {
        st.poll(&mut acked).unwrap();
        st.idle();
    }
    drop(st);
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .unwrap();
    mount_all(&disk);
}

/// Same with a pool of more than one table block: the synchronous grant takes a chunk of the other block while the
/// async one is in flight. Both carry a slot of the same shard: they must differ (one slot per chunk, else the
/// allocator panics on the second and the mount refuses the table: "slot used twice").
#[test]
fn sync_and_async_grants_never_share_a_slot() {
    let disk = fresh(1200, 4096, 50);
    let mut st = mount_all(&disk);
    assert!(
        st.lending().unwrap().geom.table_blocks >= 2,
        "pool spans two table blocks"
    );
    let c = coll_of(&st, 1);
    let n = commit_below_watermark(&mut st, 1, c);
    let mut acked = Vec::new();
    st.poll(&mut acked).unwrap();
    assert!(st.lend_busy() && st.shards[1].sh.lend.inflight);
    let d9 = vec![9u8; 512 << 10];
    let mut t = OTxn::new();
    t.write(c, &g(n), 0, &d9);
    st.commit(&t).unwrap();
    for _ in 0..1000 {
        st.poll(&mut acked).unwrap();
        st.idle();
    }
    assert!(!st.lend_busy());
    let slots: Vec<(u64, u64)> = st.lent_chunks(1).unwrap();
    let mut phys: Vec<u64> = slots.iter().map(|e| e.0).filter(|&p| p != HOLE).collect();
    phys.sort_unstable();
    phys.dedup();
    assert_eq!(phys.len(), slots.iter().filter(|e| e.0 != HOLE).count());
    drop(st);
    let (_, dirs) =
        read_super(&mut disk.queue(), &mut SimClock::default()).expect("table with distinct slots");
    assert!(dirs[1].lent.iter().filter(|&&p| p != HOLE).count() >= 1);
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .unwrap();
}

/// A request that reaches a store without the pool (misrouted by the transport) is answered with a denial: the borrower
/// must not wait forever with its txns parked.
#[test]
fn misrouted_request_is_denied() {
    let disk = fresh(48, 4096, 50);
    let mut st = mount_cores(&disk);
    st[1].lend_in(LendMsg::Request {
        shard: 1,
        short: true,
    });
    let mut out = Vec::new();
    st[1].take_lend_out(&mut out);
    assert_eq!(out, vec![LendMsg::Deny { shard: 1, pool: 0 }]);
}

/// Per-core stores all mounted with the default config (`lend_owner` true): only the store holding shard 0 owns the
/// pool. Two owners would each grant from their own copy of the table: one chunk lent to two shards.
#[test]
fn one_pool_owner_per_device() {
    let disk = fresh(48, 4096, 50);
    let st: Vec<St> = (0..2usize)
        .map(|c| {
            let d = disk.clone();
            Store::mount_shards(
                move || d.queue(),
                SimClock::default(),
                cfg(true),
                move |s| s as usize % 2 == c,
            )
            .unwrap()
            .0
        })
        .collect();
    assert!(st[0].is_pool_owner());
    assert!(!st[1].is_pool_owner() && st[1].lending().is_none());
}

/// Migration headroom on a chunked store (adr 0031 am. 4): a hold refused for lack of room, the deferred move's want
/// makes the (idle) shard borrow chunks from the pool until the copy fits; the retry holds it; the want cleared, the
/// shard goes quiet. A want beyond the pool stops at the denial (no endless asking).
#[test]
fn mig_want_borrows_until_the_copy_fits() {
    let disk = fresh(96, 4096, 50);
    let st = mount_all(&disk);
    let chunk = st.lending().unwrap().geom.chunk * store::BLK as u64;
    let room = |st: &St| st.mig_rooms().iter().find(|r| r.0 == 0).unwrap().1;
    let want = room(&st) + 4 * chunk;
    let mut cores = Cores::new(vec![st]);
    assert!(!cores.st[0].mig_hold(0, want), "beyond the base");
    cores.st[0].mig_want(0, want);
    for _ in 0..100_000 {
        if room(&cores.st[0]) >= want {
            break;
        }
        cores.step().unwrap();
    }
    assert!(
        room(&cores.st[0]) >= want,
        "the shard borrowed for the copy"
    );
    assert!(cores.st[0].mig_hold(0, want), "the retry holds it");
    cores.st[0].mig_want(0, 0);
    cores.st[0].mig_unhold(0, want);
    // more than the whole device: the pool runs dry, the denial ends the asking
    cores.st[0].mig_want(0, 1 << 40);
    for _ in 0..100_000 {
        cores.step().unwrap();
    }
    assert_eq!(free_pool(&cores.st[0]), 0, "lent everything it had");
    assert!(
        cores.st[0].shards[0].sh.lend.denies >= 1,
        "the dry pool answered"
    );
}
