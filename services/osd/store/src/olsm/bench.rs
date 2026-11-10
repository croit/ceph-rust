// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Phase 0 gate microbenchmarks and write-amplification sims (adr 0610, doc/perf/omap-redesign-plan-20261027.md).
//! Release only, numbers printed:
//! `cargo test --release -p store --features lab --lib olsm::bench -- --ignored --nocapture --test-threads 1`.
//!
//! Gates: insert <= 0.3 us/key at `mt_soft` 256 MiB, flush <= 0.3 us/key, merge <= 0.2 us/key, cold point get one
//! 4 KiB page per key, WA <= 3.15 up to 8 x n0 and <= 4 at 64 x n0 (WAL counted as 1 x user bytes).

use super::labdev::MemBlocks;
use super::*;
use crate::BLK;
use crate::rng::Rng;
use std::time::Instant;

const KEY: usize = 32;
const VAL: usize = 100;

fn gate(name: &str, v: f64, lim: f64, unit: &str) {
    let ok = if v <= lim { "PASS" } else { "FAIL" };
    println!("GATE {name:<34} {v:>8.3} {unit:<10} (<= {lim}) {ok}");
}

/// `n` random keys and values as slices of two shared buffers (zero copy, like the WAL / message buffers).
fn kv_pool(rng: &mut Rng, n: usize) -> (Bytes, Bytes) {
    let mut k = vec![0u8; n * KEY];
    rng.fill(&mut k);
    let mut v = vec![0u8; n * VAL];
    rng.fill(&mut v);
    (Bytes::from(k), Bytes::from(v))
}

fn kv(pool: &(Bytes, Bytes), i: usize) -> (Bytes, Bytes) {
    (
        pool.0.slice(i * KEY..(i + 1) * KEY),
        pool.1.slice(i * VAL..(i + 1) * VAL),
    )
}

/// Fill a memtable to `bytes` with sorted 256-key batches of random keys into one object. Batches are built and
/// sorted before the clock starts (an `OPut` batch arrives sorted and validated, adr 0610 (1)); timed = inserts.
fn fill_mem(
    pool: &(Bytes, Bytes),
    first: usize,
    bytes: usize,
    lsn: &mut u64,
) -> (Memtable, usize, f64) {
    let per = bytes / (KEY + VAL + mem::ENTRY_RAM) + 256;
    let batches: Vec<Vec<(Bytes, Bytes)>> = (first..first + per)
        .step_by(256)
        .map(|i| {
            let mut b: Vec<(Bytes, Bytes)> = (i..i + 256).map(|j| kv(pool, j)).collect();
            b.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            b
        })
        .collect();
    let mut m = Memtable::new();
    let mut n = 0;
    let t = Instant::now();
    for b in batches {
        if m.bytes() >= bytes {
            break;
        }
        *lsn += 1;
        n += b.len();
        m.put_batch(*lsn, 1, b);
    }
    (m, n, t.elapsed().as_secs_f64())
}

#[test]
#[ignore = "release microbench"]
fn olsm_bench_insert_flush_merge_get() {
    let mut rng = Rng::new(42);
    let mt_soft = 256usize << 20;
    let per = mt_soft / (KEY + VAL + mem::ENTRY_RAM) + 4096;
    // `fill_mem` callers advance `first` by the keys actually inserted; the pool covers 9 memtables.
    let pool = kv_pool(&mut rng, per * 9);
    let mut lsn = 0;

    // Insert: one memtable to mt_soft (batch sort included: the WAL batch arrives sorted, sorting here is extra).
    let (m, n, secs) = fill_mem(&pool, 0, mt_soft, &mut lsn);
    println!(
        "insert: {n} keys, {} MiB charged, {:.2} s",
        m.bytes() >> 20,
        secs
    );
    gate(
        "insert us/key (256 MiB memtable)",
        secs * 1e6 / n as f64,
        0.3,
        "us/key",
    );
    let mut single = Memtable::new();
    let t = Instant::now();
    for i in 0..n {
        let (k, v) = kv(&pool, i);
        single.put(i as u64 + 1, 1, k, v);
    }
    println!(
        "info  single random puts: {:.3} us/key",
        t.elapsed().as_secs_f64() * 1e6 / n as f64
    );
    drop(single);
    // Keys sharing a 16 byte prefix (inline key prefix does not discriminate): informational.
    let mut kp = pool.0.to_vec();
    for k in kp.chunks_mut(KEY) {
        k[..16].copy_from_slice(b"bucket.idx.0001/");
    }
    let shared = (Bytes::from(kp), pool.1.clone());
    let (m2, n2, secs2) = fill_mem(&shared, 0, mt_soft, &mut lsn);
    println!(
        "info  insert, 16 B shared key prefix: {:.3} us/key",
        secs2 * 1e6 / n2 as f64
    );
    drop(m2);

    // Flush.
    let mut dev = MemBlocks::new();
    let t = Instant::now();
    let (run, _) = job::flush(&m, 1, &mut dev).unwrap().unwrap();
    let fs = t.elapsed().as_secs_f64();
    gate("flush us/key", fs * 1e6 / n as f64, 0.3, "us/key");
    println!(
        "info  flush: {} chunks, {} MiB payload, {} MiB written, resident meta {} KiB ({:.2} B/key)",
        run.fences.len(),
        run.data_bytes() >> 20,
        dev.written >> 20,
        run.ram() >> 10,
        run.ram() as f64 / n as f64
    );
    drop(m);

    // Merge: 8 overlapping runs of 1/8 memtable each (random keys over the same keyspace).
    let mut runs = Vec::new();
    let mut first = n;
    for r in 0..FAN {
        let (m, k, _) = fill_mem(&pool, first, mt_soft / FAN, &mut lsn);
        first += k;
        runs.insert(
            0,
            Arc::new(job::flush(&m, 10 + r as u64, &mut dev).unwrap().unwrap().0),
        );
    }
    let input: u64 = runs.iter().map(|r| r.entries).sum();
    let mut man = Manifest::new(mt_soft as u64);
    for r in runs.iter().rev() {
        man.install_flush(r.clone(), r.lsn_hi);
    }
    man.next_run_id = 100;
    let pick = super::tests::pick_top(&mut man, true);
    let w0 = dev.written;
    let t = Instant::now();
    let out = job::merge(pick, &mut dev).unwrap();
    let ms = t.elapsed().as_secs_f64();
    gate(
        "merge us/key (8 overlapping runs)",
        ms * 1e6 / input as f64,
        0.2,
        "us/key",
    );
    println!(
        "info  merge: {input} keys in, {} MiB written, moved {} rewritten {}",
        (dev.written - w0) >> 20,
        out.moved,
        out.rewritten
    );

    // Cold point gets (no cache): device bytes per key, present and absent keys.
    man.install_gc_prefix(&runs, out.runs, out.residuals);
    println!("info  merge output: {} partitions", man.tiers[0].len());
    for (name, top, tiers) in [
        ("1 merged run", &[][..], &man.tiers[..]),
        ("8 runs", &runs[..], &[][..]),
    ] {
        let s = read::Sources {
            mems: [None; 3],
            top,
            tiers,
        };
        let (b0, r0) = (dev.read, dev.reads);
        let probes = 20_000;
        let t = Instant::now();
        for _ in 0..probes {
            let i = n + rng.below((first - n) as u64) as usize;
            let (k, v) = kv(&pool, i);
            assert_eq!(read::get(&s, &mut dev, 1, &k).unwrap(), Some(v));
        }
        let us = t.elapsed().as_secs_f64() * 1e6 / probes as f64;
        let bpk = (dev.read - b0) as f64 / probes as f64;
        println!(
            "info  cold get present ({name}): {:.0} B/key, {:.3} reads/key, {us:.2} us/key",
            bpk,
            (dev.reads - r0) as f64 / probes as f64
        );
        gate(
            &format!("cold get present B/key ({name})"),
            bpk,
            4096.0 * 1.25,
            "B/key",
        );
        let (b0, r0) = (dev.read, dev.reads);
        for _ in 0..probes {
            let mut k = [0u8; KEY];
            rng.fill(&mut k);
            assert_eq!(read::get(&s, &mut dev, 1, &k).unwrap(), None);
        }
        println!(
            "info  cold get absent ({name}): {:.0} B/key, {:.4} reads/key (bloom false positives)",
            (dev.read - b0) as f64 / probes as f64,
            (dev.reads - r0) as f64 / probes as f64
        );
    }
}

/// Fill `n` keys (random keys over `objs` objects), freeze at `n0` charged bytes, flush, merge by policy; print WA at
/// every power of two of `user bytes / n0`.
/// Returns the max WA up to 8 x n0, the max up to 64 x n0 and the WA when user bytes first reach 64 x n0 (`None`: the
/// sim ends before).
fn wa_sim(n: usize, n0: usize, objs: u64) -> (f64, f64, Option<f64>) {
    let mut rng = Rng::new(n as u64 ^ objs);
    let mut lsm = Olsm::new(Manifest::new(n0 as u64));
    let mut dev = MemBlocks::new();
    let (mut user, mut lsn) = (0u64, 0u64);
    let (mut wa8, mut wa64, mut at64) = (0.0f64, 0.0f64, None);
    let mut next_mark = 1u64;
    let mut kb = [0u8; KEY];
    let mut vb = [0u8; VAL];
    let t = Instant::now();
    for i in 0..n {
        rng.fill(&mut kb);
        rng.fill(&mut vb);
        lsn += 1;
        lsm.active.put(
            lsn,
            rng.below(objs),
            Bytes::copy_from_slice(&kb),
            Bytes::copy_from_slice(&vb),
        );
        user += (KEY + VAL) as u64;
        if lsm.active.bytes() >= n0 || i + 1 == n {
            let f = lsm.freeze().unwrap();
            let id = lsm.man.alloc_run_id();
            let (run, _) = job::flush(&f, id, &mut dev).unwrap().unwrap();
            lsm.flush_done(run);
            merge_all(&mut lsm, &mut dev);
            let ratio = user / n0 as u64;
            let wa = 1.0 + dev.written as f64 / user as f64;
            if ratio >= next_mark || i + 1 == n {
                println!(
                    "info  wa objs {objs:>5} n0 {:>3} MiB: user {:>6} MiB = {ratio:>3} x n0, WA {wa:.2} (store {:.2}), runs {}, tiers {}, live {} MiB",
                    n0 >> 20,
                    user >> 20,
                    wa - 1.0,
                    lsm.man.runs().count(),
                    lsm.man.tiers.len() + 1,
                    (dev.live_blocks * BLK as u64) >> 20
                );
                while next_mark <= ratio {
                    next_mark *= 2;
                }
            }
            if ratio <= 8 {
                wa8 = wa8.max(wa);
            }
            if ratio <= 64 {
                wa64 = wa64.max(wa);
            }
            if ratio >= 64 && at64.is_none() {
                at64 = Some(wa);
            }
        }
    }
    println!("info  wa sim {n} keys: {:.1} s", t.elapsed().as_secs_f64());
    (wa8, wa64, at64)
}

#[test]
#[ignore = "release sim"]
fn olsm_bench_write_amplification() {
    for (n, n0, objs) in [
        (1usize << 20, 16usize << 20, 1u64),
        (1 << 20, 16 << 20, 1024),
        (16 << 20, 64 << 20, 1),
        (8 << 20, 16 << 20, 1),
        (8 << 20, 16 << 20, 1024),
    ] {
        let (wa8, wa64, at64) = wa_sim(n, n0, objs);
        gate(
            &format!("WA max <= 8 x n0 ({n} keys, {objs} objs)"),
            wa8,
            3.15,
            "x",
        );
        println!("info  WA max <= 64 x n0 ({n} keys, {objs} objs): {wa64:.2}");
        if let Some(w) = at64 {
            gate(
                &format!("WA at 64 x n0 ({n} keys, {objs} objs)"),
                w,
                4.0,
                "x",
            );
        }
    }
}

/// Merges by policy until none is due; input extents freed.
fn merge_all(lsm: &mut Olsm, dev: &mut MemBlocks) {
    while let Some(p) = lsm.man.pick_merge(false) {
        let inputs = p.inputs.clone();
        let out = job::merge(p, dev).unwrap();
        lsm.man.install_gc_prefix(&inputs, out.runs, out.residuals);
        for (b, nb) in out.freed {
            dev.free(b, nb);
        }
    }
}

/// Runs a point get of `(id, key)` consults (filter + fence) until a source decides.
fn probes(lsm: &Olsm, dev: &mut MemBlocks, id: u64, key: &[u8]) -> usize {
    read::get_probed(&lsm.sources(), dev, id, key).unwrap().1
}

/// [`MemBlocks`] behind a [`cache::RunCache`] (the shard's read path: a hit is a slice of a cached extent).
struct Cached<'a> {
    dev: &'a mut MemBlocks,
    cache: cache::RunCache,
}

impl ChunkRead for Cached<'_> {
    fn read(&mut self, blk: u64, nblk: u32) -> Result<Bytes, crate::StoreError> {
        self.read_checked(blk, nblk).map(|(b, _)| b)
    }
    fn read_checked(&mut self, blk: u64, nblk: u32) -> Result<(Bytes, bool), crate::StoreError> {
        if let Some(hit) = self.cache.get_checked(blk, nblk) {
            return Ok(hit);
        }
        let b = self.dev.read(blk, nblk)?;
        let t = self.cache.start(blk, nblk);
        self.cache.done(t, Some(b.clone()));
        self.cache.op_done();
        Ok((b, false))
    }
    fn checked(&mut self, blk: u64, nblk: u32) {
        self.cache.checked(blk, nblk);
    }
}

/// Point gets on the current state: present keys (`< inserted` of the pool) cold (every read from the device) and
/// warm (through a run cache holding every page), absent keys, `by_keys` of 16 random present keys.
fn measure_gets(
    lsm: &Olsm,
    dev: &mut MemBlocks,
    pool: &(Bytes, Bytes),
    inserted: usize,
    rng: &mut Rng,
    tag: &str,
) {
    let probes_n = 20_000;
    let keys: Vec<usize> = (0..probes_n)
        .map(|_| rng.below(inserted as u64) as usize)
        .collect();
    let (b0, r0) = (dev.read, dev.reads);
    let t = Instant::now();
    for &i in &keys {
        let (k, v) = kv(pool, i);
        assert_eq!(lsm.get(dev, 1, &k).unwrap(), Some(v));
    }
    let us = t.elapsed().as_secs_f64() * 1e6 / probes_n as f64;
    let (bpk, rpk) = (
        (dev.read - b0) as f64 / probes_n as f64,
        (dev.reads - r0) as f64 / probes_n as f64,
    );
    let pp = keys
        .iter()
        .map(|&i| probes(lsm, dev, 1, &kv(pool, i).0))
        .sum::<usize>() as f64
        / probes_n as f64;
    let absent: Vec<[u8; KEY]> = (0..probes_n)
        .map(|_| {
            let mut k = [0u8; KEY];
            rng.fill(&mut k);
            k
        })
        .collect();
    let (b1, r1) = (dev.read, dev.reads);
    let t = Instant::now();
    for k in &absent {
        assert_eq!(lsm.get(dev, 1, k).unwrap(), None);
    }
    let us_a = t.elapsed().as_secs_f64() * 1e6 / probes_n as f64;
    let ba = (dev.read - b1) as f64 / probes_n as f64;
    let ra = (dev.reads - r1) as f64 / probes_n as f64;
    let pa = absent.iter().map(|k| probes(lsm, dev, 1, k)).sum::<usize>() as f64 / probes_n as f64;
    println!(
        "info  {tag}: runs {} tiers {} partitions {}, present {us:.2} us/get {rpk:.3} reads {bpk:.0} B {pp:.1} probes; absent {us_a:.2} us/get {ra:.4} reads {ba:.0} B {pa:.1} probes",
        lsm.man.runs().count(),
        lsm.man.tiers.len() + 1,
        lsm.man.tiers.iter().map(|t| t.len()).sum::<usize>()
    );
    // Warm: the same keys again through a run cache that holds every page they need.
    let mut c = Cached {
        dev,
        cache: cache::RunCache::new(usize::MAX),
    };
    for &i in &keys {
        lsm.get(&mut c, 1, &kv(pool, i).0).unwrap();
    }
    let t = Instant::now();
    for &i in &keys {
        let (k, v) = kv(pool, i);
        assert_eq!(lsm.get(&mut c, 1, &k).unwrap(), Some(v));
    }
    let us_w = t.elapsed().as_secs_f64() * 1e6 / probes_n as f64;
    let dev = c.dev;
    // by_keys: 16 random present keys per call, cold.
    let sets: Vec<Vec<Bytes>> = (0..probes_n / 16)
        .map(|_| {
            (0..16)
                .map(|_| kv(pool, rng.below(inserted as u64) as usize).0)
                .collect()
        })
        .collect();
    let (b3, r3) = (dev.read, dev.reads);
    let t = Instant::now();
    for ks in &sets {
        assert_eq!(read::by_keys(&lsm.sources(), dev, 1, ks).unwrap().len(), 16);
    }
    let us_b = t.elapsed().as_secs_f64() * 1e6 / (sets.len() * 16) as f64;
    println!(
        "info  {tag}: warm present {us_w:.2} us/get; by_keys 16 cold {us_b:.2} us/key {:.3} reads/key {:.0} B/key",
        (dev.reads - r3) as f64 / (sets.len() * 16) as f64,
        (dev.read - b3) as f64 / (sets.len() * 16) as f64
    );
    // Listing pages of 1024 keys from random start keys (cold, seeked).
    let pages = 200;
    let (b2, t) = (dev.read, Instant::now());
    let mut nk = 0;
    for _ in 0..pages {
        let (k, _) = kv(pool, rng.below(inserted as u64) as usize);
        let (page, _) = lsm.list(dev, 1, Some(&k), b"", 1024).unwrap();
        nk += page.len();
    }
    let s = t.elapsed().as_secs_f64();
    println!(
        "info  {tag}: list {:.0} keys/s ({} keys/page, {:.0} B read/key)",
        nk as f64 / s,
        nk / pages,
        (dev.read - b2) as f64 / nk as f64
    );
    gate(
        &format!("cold get present reads ({tag})"),
        rpk,
        1.1,
        "reads/get",
    );
    gate(
        &format!("cold get absent B/get ({tag})"),
        ba,
        0.1 * BLK as f64,
        "B/get",
    );
}

/// Point reads by LSM depth: random 32 B keys into one object (256-key batches), freeze at `n0`, flush, merges by
/// policy; cold gets measured at 8 x and 64 x n0 user bytes (owner CPU per get must not grow with the run count).
#[test]
#[ignore = "release microbench"]
fn olsm_bench_point_reads_by_depth() {
    let n0 = 8usize << 20;
    let marks = [8usize, 64];
    let total = marks[1] * n0 / (KEY + VAL) + 256;
    let mut rng = Rng::new(7);
    let pool = kv_pool(&mut rng, total);
    let mut lsm = Olsm::new(Manifest::new(n0 as u64));
    let mut dev = MemBlocks::new();
    let (mut lsn, mut i, mut mi) = (0u64, 0usize, 0usize);
    while mi < marks.len() {
        let mut b: Vec<(Bytes, Bytes)> = (i..i + 256).map(|j| kv(&pool, j)).collect();
        b.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        i += 256;
        lsn += 1;
        lsm.active.put_batch(lsn, 1, b);
        if lsm.active.bytes() < n0 && i + 256 < total {
            continue;
        }
        let f = lsm.freeze().unwrap();
        let id = lsm.man.alloc_run_id();
        let (run, _) = job::flush(&f, id, &mut dev).unwrap().unwrap();
        lsm.flush_done(run);
        merge_all(&mut lsm, &mut dev);
        if i * (KEY + VAL) >= marks[mi] * n0 || i + 256 >= total {
            let tag = format!("{} x n0", marks[mi]);
            measure_gets(&lsm, &mut dev, &pool, i, &mut rng, &tag);
            mi += 1;
        }
    }
}

/// Owner work of one task stepped in rounds (adr 0610 am. 3): the owner collects the written blocks into its device
/// queue, leases chunk-sized extents, supplies input chunks (the merge's miss plus `ahead` per input); the helper steps
/// the round. Device writes happen outside both clocks (device time). Returns the finished task and (owner s, helper s,
/// rounds).
fn run_rounds(
    mut task: remote::Task,
    dev: &mut MemBlocks,
    lease: usize,
    ahead: usize,
) -> (remote::Task, f64, f64, u64) {
    let mut cx = remote::Ctx::default();
    let (mut owner, mut helper, mut rounds) = (0f64, 0f64, 0u64);
    let mut queue: Vec<(u64, Bytes, Vec<u32>)> = Vec::new();
    let piece = (CHUNK_TARGET / BLK) as u32;
    loop {
        let t = Instant::now();
        cx.drain_out(32, |b, data, crcs| queue.push((b, data, crcs.to_vec())));
        let done = task.done();
        if !done {
            if cx.need > 0 || cx.lease.is_empty() {
                cx.lease.clear();
                if cx.need > piece {
                    cx.lease.push((dev.alloc(cx.need).unwrap(), cx.need));
                }
                for _ in 0..lease {
                    cx.lease.push((dev.alloc(piece).unwrap(), piece));
                }
                cx.need = 0;
            }
            let mut want: Vec<(u64, u32)> = cx.missed.take().into_iter().collect();
            task.next_reads(ahead, &mut want);
            for e in want {
                if let std::collections::hash_map::Entry::Vacant(v) = cx.chunks.entry(e) {
                    v.insert(dev.read(e.0, e.1).unwrap());
                }
            }
        }
        owner += t.elapsed().as_secs_f64();
        for (b, data, crcs) in queue.drain(..) {
            dev.write(b, data.to_vec(), &crcs).unwrap();
        }
        if done {
            return (task, owner, helper, rounds);
        }
        rounds += 1;
        let t = Instant::now();
        while task.round(&mut cx, 1).unwrap() == remote::Stop::Budget {}
        helper += t.elapsed().as_secs_f64();
    }
}

/// Owner-core work per key, flush + merge inline (phase 2a) vs in helper rounds (am. 3): `FAN` memtables of 64 MiB
/// flushed, their runs merged once (tier 0 -> 1). Inline owner = insert + flush + merge; with helpers the owner keeps
/// insert + round boundaries (queueing written blocks, leases, chunk supply). Lease = 64 chunks per round, read-ahead 8
/// chunks per input (a queue of ~128 slots above the WAL floor).
#[test]
#[ignore = "release microbench"]
fn olsm_bench_owner_work() {
    let mut rng = Rng::new(43);
    let n0 = 64usize << 20;
    let per = n0 / (KEY + VAL + mem::ENTRY_RAM) + 4096;
    let pool = kv_pool(&mut rng, per * FAN);
    let (mut lsn, mut first, mut keys, mut t_ins) = (0, 0, 0, 0f64);
    let mut mems = Vec::new();
    for _ in 0..FAN {
        let (m, k, s) = fill_mem(&pool, first, n0, &mut lsn);
        first += k;
        keys += k;
        t_ins += s;
        mems.push(Arc::new(m));
    }
    let ins = t_ins * 1e6 / keys as f64;
    let merge_once = |runs: Vec<Arc<RunMeta>>| {
        let mut man = Manifest::new(n0 as u64);
        for r in runs.iter().rev() {
            man.install_flush(r.clone(), r.lsn_hi);
        }
        man.next_run_id = 100;
        man.pick_sized().expect("FAN tier-0 runs")
    };

    // inline: the owner steps everything
    let mut dev = MemBlocks::new();
    let t = Instant::now();
    let mut runs = Vec::new();
    for (i, m) in mems.iter().enumerate() {
        runs.insert(
            0,
            Arc::new(job::flush(m, 1 + i as u64, &mut dev).unwrap().unwrap().0),
        );
    }
    let t_flush = t.elapsed().as_secs_f64();
    let pick = merge_once(runs);
    let t = Instant::now();
    job::merge(pick, &mut dev).unwrap();
    let t_merge = t.elapsed().as_secs_f64();
    let inline = ins + (t_flush + t_merge) * 1e6 / keys as f64;
    println!(
        "info  inline: insert {ins:.3} + flush {:.3} + merge {:.3} us/key",
        t_flush * 1e6 / keys as f64,
        t_merge * 1e6 / keys as f64
    );

    // helper rounds
    let mut dev = MemBlocks::new();
    let (mut own, mut help, mut rounds) = (0f64, 0f64, 0u64);
    let mut runs = Vec::new();
    for (i, m) in mems.iter().enumerate() {
        let (t, o, h, r) = run_rounds(
            remote::Task::flush(m.clone(), 1 + i as u64),
            &mut dev,
            64,
            8,
        );
        let remote::Task::Flush { out: Some(run), .. } = t else {
            panic!("flush finished");
        };
        runs.insert(0, Arc::new(run));
        (own, help, rounds) = (own + o, help + h, rounds + r);
    }
    let (fo, fh) = (own, help);
    let pick = merge_once(runs);
    let (_, o, h, r) = run_rounds(
        remote::Task::merge(job::MergeJob::new(pick)),
        &mut dev,
        64,
        8,
    );
    own += o;
    rounds += r;
    let after = ins + own * 1e6 / keys as f64;
    println!(
        "info  helper rounds: {rounds}; owner flush {:.4} merge {:.4} us/key; helper flush {:.3} merge {:.3} us/key",
        fo * 1e6 / keys as f64,
        o * 1e6 / keys as f64,
        fh * 1e6 / keys as f64,
        h * 1e6 / keys as f64
    );
    println!(
        "GATE owner us/key flush+merge inline {inline:.3} -> helpers {after:.3} (insert {ins:.3} + boundaries {:.4})",
        own * 1e6 / keys as f64
    );
    assert!(
        after < ins + 0.1 * (inline - ins),
        "owner keeps < 10 % of the job work"
    );
}

/// Largest run group of the manifest (tier 0 or one partition) and the runs a point get may consult at most (every
/// tier-0 run plus, per tier, the largest partition's runs).
fn groups(man: &Manifest) -> (usize, usize) {
    let mut big = man.top().len();
    let mut reads = man.top().len();
    for parts in &man.tiers {
        let m = parts.iter().map(|p| p.runs.len()).max().unwrap_or(0);
        big = big.max(m);
        reads += m;
    }
    (big, reads)
}

/// Merge-lag sim (adr 0662 am. 1?: merge inputs bounded by the manifest txn limit). Ingest `n` puts over a key space
/// of `n / 2` keys (overwrites leave garbage for the GC arms) with flushes at `n0`; after each flush the merge slot
/// gets `rate x n0` bytes of merge input (a merge slot slower than foreground ingest: runs pile up, as admission no
/// longer waits for merges, adr 0662), then the backlog drains. Arms:
/// - `max_inputs` = input ceiling of every pick (`usize::MAX` = before the fix);
/// - `admit` = option 2 model: foreground (the next flush) waits while a group holds more runs than one merge takes;
///   the merges run meanwhile are foreground stall time.
///
/// Prints WA, merges, the largest pick, the peak largest group, the peak point-get sources and the stalled share.
fn lag_sim(n: usize, n0: usize, rate: u64, max_inputs: usize, admit: bool) {
    let mut rng = Rng::new(n as u64 ^ 0x1a6);
    let mut lsm = Olsm::new(Manifest::new(n0 as u64));
    lsm.man.set_max_inputs(max_inputs);
    let mut dev = MemBlocks::new();
    let (mut user, mut lsn, mut credit) = (0u64, 0u64, 0i64);
    let (mut merges, mut big_pick, mut peak_group, mut peak_reads) = (0u64, 0usize, 0usize, 0usize);
    let (mut merged, mut stalled, mut stall_flushes, mut flushes) = (0u64, 0u64, 0u64, 0u64);
    let mut kb = [0u8; KEY];
    let mut vb = [0u8; VAL];
    let space = (n / 2).max(1) as u64;
    let mut step = |lsm: &mut Olsm, dev: &mut MemBlocks| -> Option<u64> {
        let p = lsm.man.pick_merge(false)?;
        big_pick = big_pick.max(p.inputs.len());
        let inputs = p.inputs.clone();
        let bytes: u64 = inputs.iter().map(|r| r.data_bytes()).sum();
        let out = job::merge(p, dev).unwrap();
        lsm.man.install_gc_prefix(&inputs, out.runs, out.residuals);
        for (b, nb) in out.freed {
            dev.free(b, nb);
        }
        merges += 1;
        Some(bytes.max(1))
    };
    let t = Instant::now();
    for i in 0..n {
        kb[24..].copy_from_slice(&rng.below(space).to_be_bytes());
        rng.fill(&mut vb);
        lsn += 1;
        lsm.active.put(
            lsn,
            1,
            Bytes::copy_from_slice(&kb),
            Bytes::copy_from_slice(&vb),
        );
        user += (KEY + VAL) as u64;
        if lsm.active.bytes() < n0 && i + 1 < n {
            continue;
        }
        if admit {
            let mut waited = false;
            while groups(&lsm.man).0 > max_inputs {
                let Some(b) = step(&mut lsm, &mut dev) else {
                    break;
                };
                stalled += b;
                merged += b;
                waited = true;
            }
            stall_flushes += u64::from(waited);
        }
        let f = lsm.freeze().unwrap();
        let id = lsm.man.alloc_run_id();
        let (run, _) = job::flush(&f, id, &mut dev).unwrap().unwrap();
        lsm.flush_done(run);
        flushes += 1;
        credit += (rate * n0 as u64) as i64;
        while credit > 0 {
            let Some(b) = step(&mut lsm, &mut dev) else {
                credit = 0;
                break;
            };
            credit -= b as i64;
            merged += b;
        }
        let (g, r) = groups(&lsm.man);
        peak_group = peak_group.max(g);
        peak_reads = peak_reads.max(r);
    }
    let ingest_wa = 1.0 + dev.written as f64 / user as f64;
    while let Some(b) = step(&mut lsm, &mut dev) {
        merged += b;
    }
    let (g, r) = groups(&lsm.man);
    let cap = match max_inputs {
        usize::MAX => "inf".to_string(),
        m => m.to_string(),
    };
    println!(
        "info  lag rate {rate} max_inputs {cap:>5} admit {admit:<5}: WA ingest {ingest_wa:.2} drained {:.2}, merges \
         {merges}, largest pick {big_pick} runs, peak group {peak_group} runs, peak get sources {peak_reads}, \
         stalled flushes {stall_flushes}/{flushes} ({:.1} % of merge bytes in foreground stalls), after drain {} runs \
         group {g} sources {r} ({:.1} s)",
        1.0 + dev.written as f64 / user as f64,
        100.0 * stalled as f64 / merged.max(1) as f64,
        lsm.man.runs().count(),
        t.elapsed().as_secs_f64()
    );
}

/// Option 1 (merge inputs bounded by the manifest limit) vs before (unbounded) vs option 2 (foreground waits while a
/// group outgrows one merge), at the hot-object test's limit (24 pages, height 3: 20 inputs), a 64-page budget (60)
/// and the default one (4096 pages, height 4: 4091), merge slot at 1x and 2x the flush rate.
#[test]
#[ignore = "release sim"]
fn olsm_bench_merge_lag() {
    let (n, n0) = (4usize << 20, 4usize << 20);
    for rate in [1u64, 2] {
        for (max_inputs, admit) in [
            (usize::MAX, false),
            (4091, false),
            (60, false),
            (20, false),
            (20, true),
        ] {
            lag_sim(n, n0, rate, max_inputs, admit);
        }
    }
}

/// Thread CPU seconds (the merge-unit bench runs next to other load: wall clocks would count preemption).
fn cpu_now() -> f64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid out pointer, a clock every supported OS provides.
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 * 1e-9
}

/// Longest single unit of owner/helper work on a large LSM (doc/perf/latency-stall-20261107.md): `OLSM_BENCH_KEYS`
/// (default 4 M) random keys of one cold object fill a deep LSM, then pg-log-like churn on a second object (puts plus
/// range-trims) drives the policy's merges and GC prefixes. Each merge is picked, constructed, stepped one chunk at a
/// time, installed and its inputs dropped; every phase is timed separately. A core iteration runs one such unit, so
/// the max of each phase is the stall it adds to the PGs of that core.
#[test]
#[ignore = "release microbench"]
fn olsm_bench_merge_unit_max() {
    let keys: usize = std::env::var("OLSM_BENCH_KEYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4 << 20);
    let n0 = 16usize << 20;
    let mut rng = Rng::new(47);
    let pool = kv_pool(&mut rng, keys + n0 / (KEY + VAL) + 512);
    let mut dev = MemBlocks::new();
    let mut lsm = Olsm::new(Manifest::new(n0 as u64));
    let mut lsn = 0u64;
    let mut first = 0;
    let t = cpu_now();
    while first < keys {
        let (m, k, _) = fill_mem(&pool, first, n0, &mut lsn);
        first += k;
        lsm.active = m;
        lsm.freeze();
        let f = lsm.frozen.clone().unwrap();
        let id = lsm.man.alloc_run_id();
        lsm.flush_done(job::flush(&f, id, &mut dev).unwrap().unwrap().0);
        while let Some(p) = lsm.man.pick_merge(false) {
            let inputs = p.inputs.clone();
            let out = job::merge(p, &mut dev).unwrap();
            lsm.man.install_gc_prefix(&inputs, out.runs, out.residuals);
        }
    }
    let ram: usize = lsm.man.runs().map(|r| r.ram()).sum();
    println!(
        "info  base: {first} keys, {} runs, run metadata {} MiB, tiers {}, {:.1} s",
        lsm.man.runs().count(),
        ram >> 20,
        lsm.man.tiers.len(),
        (cpu_now() - t)
    );

    let mut max = [0f64; 5];
    let mut sum = [0f64; 5];
    let names = ["pick", "job new", "step", "install", "drop inputs"];
    let (mut merges, mut gc, mut prefixes, mut steps) = (0u64, 0u64, 0u64, 0u64);
    let mut seq = 0u64;
    for _ in 0..200 {
        // omap deletes on the cold object (tombstones over deeper data: GC candidates), 1/200 of the keys per round
        for _ in 0..keys / 200 {
            lsn += 1;
            let i = rng.below(first as u64) as usize;
            lsm.active.del(lsn, 1, kv(&pool, i).0);
        }
        // pg-log churn: 20 k entries per round on object 2, trim to the newest 3 k
        for _ in 0..20_000 {
            seq += 1;
            lsn += 1;
            lsm.active.put(
                lsn,
                2,
                Bytes::from(format!("pglog.{seq:020}").into_bytes()),
                Bytes::from(vec![7u8; 180]),
            );
        }
        lsn += 1;
        lsm.active.del_range(
            lsn,
            2,
            Bytes::from_static(b"pglog."),
            Some(Bytes::from(
                format!("pglog.{:020}", seq - 3000).into_bytes(),
            )),
        );
        lsm.freeze();
        let f = lsm.frozen.clone().unwrap();
        let id = lsm.man.alloc_run_id();
        lsm.flush_done(job::flush(&f, id, &mut dev).unwrap().unwrap().0);
        loop {
            let t = cpu_now();
            let Some(p) = lsm.man.pick_merge(false) else {
                break;
            };
            let d = cpu_now() - t;
            max[0] = max[0].max(d);
            sum[0] += d;
            let inputs = p.inputs.clone();
            let t = cpu_now();
            let mut j = job::MergeJob::new(p);
            let d = cpu_now() - t;
            max[1] = max[1].max(d);
            sum[1] += d;
            gc += u64::from(j.gc());
            let out = loop {
                let t = cpu_now();
                let r = j.step(&mut dev, 1).unwrap();
                let d = cpu_now() - t;
                max[2] = max[2].max(d);
                sum[2] += d;
                steps += 1;
                if let Some(out) = r {
                    break out;
                }
            };
            prefixes += u64::from(out.prefix_end.is_some());
            drop(j);
            let t = cpu_now();
            lsm.man.install_gc_prefix(&inputs, out.runs, out.residuals);
            let d = cpu_now() - t;
            max[3] = max[3].max(d);
            sum[3] += d;
            let t = cpu_now();
            drop(inputs);
            let d = cpu_now() - t;
            max[4] = max[4].max(d);
            sum[4] += d;
            merges += 1;
        }
    }
    let ram: usize = lsm.man.runs().map(|r| r.ram()).sum();
    println!(
        "info  churn: {merges} merges ({gc} gc, {prefixes} prefixes), {steps} steps, {} runs, metadata {} MiB",
        lsm.man.runs().count(),
        ram >> 20
    );
    for ((n, v), t) in names.iter().zip(max).zip(sum) {
        println!(
            "max   {n:<12} {:>9.3} ms   total {:>9.1} ms",
            v * 1e3,
            t * 1e3
        );
    }
    println!("total merge work {:.1} ms", sum.iter().sum::<f64>() * 1e3);
}

/// Read-ahead depth on the owner-supplied path (adr 0610 am. 3) for inputs that mix moved and rewritten chunks: one
/// deep run of sequential keys plus newer one-chunk runs, each overwriting one chunk-sized key range of every 16th
/// chunk. Helper rounds end when a chunk is missing (`Stop::Owner`): fewer rounds = the read-ahead covered the next
/// rewrites. Prints rounds, owner and helper seconds, moved and rewritten chunks (doc/perf/latency-stall-20261107.md).
#[test]
#[ignore = "release microbench"]
fn olsm_bench_readahead_moves() {
    let n = 400_000usize;
    let per = 400;
    let val = Bytes::from(vec![5u8; VAL]);
    let k = |i: usize| Bytes::from(format!("k{i:08}").into_bytes());
    let mut dev = MemBlocks::new();
    let mut a = Memtable::new();
    for i in 0..n {
        a.put(1, 1, k(i), val.clone());
    }
    let mut ra = job::flush(&a, 1, &mut dev).unwrap().unwrap().0;
    ra.place.tier = 1;
    let mut inputs = Vec::new();
    for (j, r) in (0..n).step_by(16 * per).enumerate() {
        let mut b = Memtable::new();
        for i in r..(r + per).min(n) {
            b.put(2, 1, k(i), val.clone());
        }
        inputs.insert(
            0,
            Arc::new(job::flush(&b, 2 + j as u64, &mut dev).unwrap().unwrap().0),
        );
    }
    inputs.push(Arc::new(ra));
    let pick = manifest::MergePick {
        inputs,
        bottom: true,
        src_tier: 0,
        dst_tier: 1,
        regions: vec![manifest::Region {
            lo: Gk::MIN,
            hi: None,
            part: None,
        }],
        cut: 1 << 40,
        stay: false,
        first_id: 1000,
        end_id: 2000,
        gc: false,
    };
    let t = Instant::now();
    let (task, owner, helper, rounds) = run_rounds(
        remote::Task::merge(job::MergeJob::new(pick)),
        &mut dev,
        64,
        8,
    );
    let remote::Task::Merge { out: Some(out), .. } = task else {
        panic!("merge finished");
    };
    println!(
        "info  readahead: rounds {rounds}, owner {owner:.3} s, helper {helper:.3} s, total {:.3} s, moved {} rewritten {}",
        t.elapsed().as_secs_f64(),
        out.moved,
        out.rewritten
    );
}
