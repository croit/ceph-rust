// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Crash-test harness: random txn workload (KV + data objects) against a simulated disk, model of every
//! submitted txn, crash/remount, invariant checks (model prefix, allocator, data, fsck of the durable root).
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use store::dev::{BlockDev, Clock, CrashPolicy, SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::fsck::fsck;
use store::layout::{MkfsParams, ShardDir, Superblock, mkfs, read_super};
use store::rng::Rng;
use store::shard::{Event, Shard, ShardCfg, Txn};
use store::sio::Sio;
use store::state::{Bitmap, Extent, Op, Record};
use store::wal::ReplayStats;
use store::{BLK, StoreError};

pub const NOBJ: u64 = 10;

thread_local! {
    /// Interior page format of the stores `make_env_full` formats on this test thread: true = compact (default,
    /// adr 0021 am. 13), false = the original slotted format (old stores).
    pub static COMPACT_INT: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// Coverage counters of the multi-part txn path across `one_run`s (gen 0): submitted, replayed, dropped (partial).
pub static MULTI_SUBMITTED: AtomicU64 = AtomicU64::new(0);
pub static MULTI_REPLAYED: AtomicU64 = AtomicU64::new(0);
pub static MULTI_DROPPED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct Env {
    pub img: SimImage,
    pub sim: SimConfig,
    pub sb: Superblock,
    pub dir: ShardDir,
    pub scfg: ShardCfg,
    /// Number of distinct objects the random workload rewrites, and a block-count multiplier (space pressure).
    pub nobj: u64,
    pub obj_scale: u32,
    /// Percent of txns that are big multi-part KV txns (ADR 0028).
    pub big_pct: u8,
    /// Percent of txns that are many-op KV storms (multi-range deletes, wide fills, wipes, remove_pg-like prefix drops).
    pub storm_pct: u8,
    /// Percent of object writes placed alone in a bitmap chunk (a chunk's worth reserved, the object's blocks kept):
    /// random overwrites on a big full device dirty chunks all over it, the sliced checkpoint start writes many.
    pub spread_pct: u8,
    /// Percent of workload steps that start a device idle gap of 1-8 steps without submissions (adr 0642): once the
    /// device drained the clock passes the pause before the next deallocate, so an idle shard sends one.
    pub idle_pct: u8,
}

pub fn make_env(capacity_mib: u64, wal_blocks: u64, awupf: u32, scfg: ShardCfg) -> Env {
    make_env_ext(capacity_mib, wal_blocks, awupf, scfg, 6, 8192)
}

pub fn make_env_ext(
    capacity_mib: u64,
    wal_blocks: u64,
    awupf: u32,
    scfg: ShardCfg,
    meta_pct: u32,
    node_size: u32,
) -> Env {
    make_env_full(
        capacity_mib,
        wal_blocks,
        awupf,
        scfg,
        meta_pct,
        node_size,
        true,
        0,
    )
}

/// `elastic` false = legacy fixed meta region (format before adr 0021 am. 12).
#[allow(clippy::too_many_arguments)]
pub fn make_env_full(
    capacity_mib: u64,
    wal_blocks: u64,
    awupf: u32,
    scfg: ShardCfg,
    meta_pct: u32,
    node_size: u32,
    elastic: bool,
    cell_pages: u32,
) -> Env {
    let mut sim = SimConfig::new(capacity_mib << 20);
    sim.awupf_lbas = awupf;
    sim.awun_lbas = awupf;
    let disk = SimDisk::new(sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = MkfsParams {
        shards: 1,
        wal_blocks,
        align_blocks: 1,
        meta_pct,
        node_size,
        elastic_meta: elastic,
        cell_pages,
        compact_int: COMPACT_INT.get(),
        ..Default::default()
    };
    let (sb, dirs) = mkfs(&mut dev, &mut clk, &p).unwrap();
    Env {
        img: disk.image(),
        sim,
        sb,
        dir: dirs[0].clone(),
        scfg,
        nobj: NOBJ,
        obj_scale: 1,
        big_pct: 3,
        storm_pct: 0,
        spread_pct: 0,
        idle_pct: 0,
    }
}

pub fn pattern(seed: u64, idx: u32, out: &mut [u8]) {
    Rng::new(seed ^ (idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)).fill(out);
}

pub fn obj_key(id: u64) -> Vec<u8> {
    format!("obj/{id:02}").into_bytes()
}

pub fn enc_obj(blk: u64, nblk: u32, seed: u64) -> Vec<u8> {
    let mut v = blk.to_le_bytes().to_vec();
    v.extend_from_slice(&nblk.to_le_bytes());
    v.extend_from_slice(&seed.to_le_bytes());
    v
}

pub fn dec_obj(v: &[u8]) -> (u64, u32, u64) {
    (
        u64::from_le_bytes(v[0..8].try_into().unwrap()),
        u32::from_le_bytes(v[8..12].try_into().unwrap()),
        u64::from_le_bytes(v[12..20].try_into().unwrap()),
    )
}

/// Engine block of the root slot `read_root` picks (the valid one with the highest seq); 4 KiB LBAs.
pub fn newest_root_blk(dir: &ShardDir, img: &SimImage) -> u64 {
    let seq = |b: u64| store::layout::RootSlot::decode(&img.read_lba(b)).map(|r| r.seq);
    if seq(dir.root_a) > seq(dir.root_b) {
        dir.root_a
    } else {
        dir.root_b
    }
}

/// fsck hook: `obj/NN` values reference data extents.
pub fn obj_refs(k: &[u8], v: &[u8], out: &mut store::fsck::Refs) {
    if k.starts_with(b"obj/") {
        let (b, n, _) = dec_obj(v);
        out.ext.push((b, n));
    }
}

/// Reference model of the applied state (what the old in-memory M2.1 state machine computed).
#[derive(Clone, Debug)]
pub struct Model {
    pub kv: BTreeMap<Vec<u8>, Vec<u8>>,
    pub alloc: Bitmap,
    pub data_start: u64,
    pub lsn: u64,
}

impl Model {
    pub fn new(data_start: u64, n: u64) -> Model {
        Model {
            kv: BTreeMap::new(),
            alloc: Bitmap::new(n),
            data_start,
            lsn: 0,
        }
    }
    pub fn apply(&mut self, rec: &Record) {
        for op in &rec.ops {
            match op {
                Op::Put(k, v) => {
                    self.kv.insert(k.clone(), v.clone());
                }
                Op::Del(k) => {
                    self.kv.remove(k);
                }
                Op::DelRange(a, b) => self.kv.retain(|k, _| !(k >= a && k < b)),
                Op::RunPut(r) => {
                    for i in 0..r.len() {
                        let (k, v) = r.entry(i);
                        // an empty value is a removal (FEAT_OMAP_TOMBS)
                        if v.is_empty() {
                            self.kv.remove(k);
                        } else {
                            self.kv.insert(k.to_vec(), v.to_vec());
                        }
                    }
                }
                Op::RunMerge { .. } => {}
                Op::Omap(_) => unreachable!("KV workloads log no omap LSM ops"),
            }
        }
        for &(b, n) in &rec.frees {
            for i in 0..n as u64 {
                assert!(
                    self.alloc.get(b - self.data_start + i),
                    "model: free of free block"
                );
                self.alloc.clear(b - self.data_start + i);
            }
        }
        for e in &rec.data {
            for i in 0..e.nblk as u64 {
                assert!(
                    !self.alloc.get(e.blk - self.data_start + i),
                    "model: double alloc"
                );
                self.alloc.set(e.blk - self.data_start + i);
            }
        }
        self.lsn = rec.lsn;
        // live objects never share blocks
        let mut ext: Vec<(u64, u32, String)> = self
            .kv
            .range(b"obj/".to_vec()..b"obj0".to_vec())
            .map(|(k, v)| {
                let (b, n, _) = dec_obj(v);
                (b, n, String::from_utf8_lossy(k).to_string())
            })
            .collect();
        ext.sort();
        for w in ext.windows(2) {
            assert!(
                w[0].0 + w[0].1 as u64 <= w[1].0,
                "model: overlapping live extents {:?} {:?} after lsn {} (rec {:?})",
                w[0],
                w[1],
                rec.lsn,
                rec
            );
        }
    }
}

pub struct Harness {
    pub env: Env,
    pub disk: SimDisk,
    pub clk: SimClock,
    pub shard: Shard<SimDev>,
    pub model: Vec<Record>,
    /// Model of everything submitted so far (applied state).
    pub cur: Model,
    /// Highest contiguously acked LSN.
    pub acked: u64,
    pub rng: Rng,
    pub submitted_since_crash: u64,
    pub releases: u64,
    pub wal_full_hits: u64,
    pub remounts: u64,
    pub crashed_mount: u64,
    pub enospc: u64,
    /// Crashes with a deallocate in flight (adr 0642).
    pub dealloc_crashes: u64,
    /// Steps left of the current device idle gap (`Env::idle_pct`).
    pub idle_left: u64,
}

pub type MountRes = Result<(Shard<SimDev>, ReplayStats), StoreError>;

pub fn mount(env: &Env, disk: &SimDisk, clk: &mut SimClock) -> MountRes {
    let mut dev = disk.queue();
    let (sb, dirs) = read_super(&mut dev, clk)?;
    assert_eq!(sb, env.sb);
    Shard::mount(dev, clk, &sb, &dirs[0], env.scfg.clone(), false)
}

impl Harness {
    pub fn new(env: &Env, seed: u64) -> Harness {
        let mut cfg = env.sim.clone();
        cfg.seed = seed ^ 0xD15C;
        let disk = SimDisk::from_image(&env.img, cfg);
        let mut clk = SimClock::default();
        let (shard, _) = mount(env, &disk, &mut clk).unwrap();
        Harness {
            env: env.clone(),
            disk,
            clk,
            shard,
            model: Vec::new(),
            cur: Model::new(env.dir.data_start, env.dir.data_blocks),
            acked: 0,
            rng: Rng::new(seed),
            submitted_since_crash: 0,
            releases: 0,
            wal_full_hits: 0,
            remounts: 0,
            crashed_mount: 0,
            enospc: 0,
            dealloc_crashes: 0,
            idle_left: 0,
        }
    }

    fn cur_obj(&self, id: u64) -> Option<(u64, u32, u64)> {
        self.cur.kv.get(&obj_key(id)).map(|v| dec_obj(v))
    }

    /// Build one random txn; returns the txn plus the model record skeleton (lsn filled by caller).
    fn gen_txn(&mut self) -> Option<(Txn<Vec<u8>>, Record)> {
        let lsn = self.shard.next_lsn();
        let mut t: Txn<Vec<u8>> = Txn::new(lsn);
        let mut rec = Record {
            lsn,
            ..Default::default()
        };
        let kind = if self.env.storm_pct > 0 && self.rng.pct(self.env.storm_pct) {
            200
        } else if self.rng.pct(self.env.big_pct) {
            100
        } else {
            self.rng.below(100)
        };
        let mut ids = vec![];
        if kind < 40 {
            ids.push(self.rng.below(self.env.nobj));
        } else if kind < 55 {
            ids.push(self.rng.below(self.env.nobj));
            ids.push((ids[0] + 1 + self.rng.below(self.env.nobj - 1)) % self.env.nobj);
        } else if kind < 70 {
            // kv only
            for _ in 0..self.rng.range(1, 3) {
                let k = format!("kv/{:03}", self.rng.below(200)).into_bytes();
                let n = if self.rng.pct(5) {
                    (self.env.sb.node_size as u64 / 4 - 64).min(1500)
                } else {
                    self.rng.below(200)
                } as usize;
                let mut v = vec![0; n];
                self.rng.fill(&mut v);
                t.ops.push(Op::Put(k, v));
            }
        } else if kind < 78 {
            let id = self.rng.below(self.env.nobj);
            if let Some((b, n, _)) = self.cur_obj(id) {
                t.ops.push(Op::Del(obj_key(id)));
                t.frees.push((b, n));
            }
        } else if kind < 86 {
            let a = self.rng.below(200);
            let b = a + self.rng.range(1, 60);
            t.ops.push(Op::DelRange(
                format!("kv/{a:03}").into_bytes(),
                format!("kv/{b:03}").into_bytes(),
            ));
        } else if kind < 93 {
            // log trim, like pg log trim
            let upto = lsn.saturating_sub(self.rng.range(1, 12));
            t.ops.push(Op::DelRange(
                b"log/".to_vec(),
                format!("log/{upto:010}").into_bytes(),
            ));
        } else if kind == 200 {
            self.gen_storm(&mut t);
        } else if kind == 100 {
            // multi-part txn (> one WAL unit, ADR 0028): atomic across WAL units; on small rings TxnTooLarge and
            // nothing changes
            let n = self.rng.range(50, 150);
            for i in 0..n {
                let k = format!("kv/big/{:03}", (self.rng.below(40) * 7 + i) % 300).into_bytes();
                let vmax = (self.env.sb.node_size as u64 / 4 - 64).min(1500);
                let mut v = vec![0; self.rng.range(vmax / 2, vmax) as usize];
                self.rng.fill(&mut v);
                t.ops.push(Op::Put(k, v));
            }
        }
        for id in ids {
            let n = if self.rng.pct(10) {
                self.rng.range(5, 24)
            } else {
                self.rng.range(1, 4)
            } as u32;
            let n = (n * self.env.obj_scale).min(60);
            let spread = self.env.spread_pct > 0 && self.rng.pct(self.env.spread_pct);
            let chunk = store::alloc::CHUNK_BLOCKS as u32;
            let got = match spread.then(|| self.shard.alloc(chunk)) {
                Some(Ok(b)) => {
                    self.shard.unreserve(b + n as u64, chunk - n);
                    Ok(b)
                }
                _ => self.shard.alloc(n),
            };
            let Ok(blk) = got else {
                self.enospc += 1;
                for (b, nb) in rec.data.iter().map(|e| (e.blk, e.nblk)) {
                    self.shard.unreserve(b, nb);
                }
                return None;
            };
            let seed = self.rng.next_u64();
            let mut buf = self.shard.alloc_buf(n as usize);
            for i in 0..n {
                pattern(seed, i, &mut buf[i as usize * BLK..(i as usize + 1) * BLK]);
            }
            t.data.push((blk, buf));
            rec.data.push(Extent {
                blk,
                nblk: n,
                crcs: vec![],
            });
            t.ops.push(Op::Put(obj_key(id), enc_obj(blk, n, seed)));
            if let Some((ob, on, _)) = self.cur_obj(id) {
                t.frees.push((ob, on));
            }
        }
        t.ops.push(Op::Put(
            format!("log/{lsn:010}").into_bytes(),
            vec![0xAB; self.rng.below(40) as usize],
        ));
        rec.ops = t.ops.clone();
        rec.frees = t.frees.clone();
        Some((t, rec))
    }

    /// Many-op KV txn (weighted): multi-range deletes with puts in between, wide fills, wipes, remove_pg-like drops of
    /// many key prefixes at once, mixed bursts. Exercises multi-DelRange pruning, big records and multi-part chains.
    fn gen_storm(&mut self, t: &mut Txn<Vec<u8>>) {
        let wide = |r: &mut Rng| format!("kv/w/{:05}", r.below(4000)).into_bytes();
        let val = |r: &mut Rng| {
            let n = if r.pct(4) {
                r.range(200, 900)
            } else {
                r.range(0, 60)
            } as usize;
            let mut v = vec![0; n];
            r.fill(&mut v);
            v
        };
        match self.rng.below(100) {
            0..=17 => {
                // several ranges (nested, overlapping, adjacent) over kv/, kv/w/, log/ with puts after them
                for _ in 0..self.rng.range(2, 12) {
                    let (a, b) = match self.rng.below(3) {
                        0 => {
                            let a = self.rng.below(200);
                            (
                                format!("kv/{a:03}").into_bytes(),
                                format!("kv/{:03}", a + self.rng.range(1, 90)).into_bytes(),
                            )
                        }
                        1 => {
                            let a = self.rng.below(4000);
                            (
                                format!("kv/w/{a:05}").into_bytes(),
                                format!("kv/w/{:05}", a + self.rng.range(1, 700)).into_bytes(),
                            )
                        }
                        _ => {
                            let lsn = t.token;
                            (
                                b"log/".to_vec(),
                                format!("log/{:010}", lsn.saturating_sub(self.rng.below(8)))
                                    .into_bytes(),
                            )
                        }
                    };
                    t.ops.push(Op::DelRange(a, b));
                    if self.rng.pct(40) {
                        let k = wide(&mut self.rng);
                        let v = val(&mut self.rng);
                        t.ops.push(Op::Put(k, v));
                    }
                }
            }
            18..=37 => {
                for _ in 0..self.rng.range(100, 400) {
                    let k = wide(&mut self.rng);
                    let v = val(&mut self.rng);
                    t.ops.push(Op::Put(k, v));
                }
            }
            38..=49 => {
                // wipe the wide space (and sometimes all of kv/) then re-put a few
                t.ops
                    .push(Op::DelRange(b"kv/w/".to_vec(), b"kv/w0".to_vec()));
                if self.rng.pct(50) {
                    t.ops.push(Op::DelRange(b"kv/".to_vec(), b"kv0".to_vec()));
                }
                for _ in 0..self.rng.range(0, 10) {
                    let k = wide(&mut self.rng);
                    let v = val(&mut self.rng);
                    t.ops.push(Op::Put(k, v));
                }
            }
            50..=62 => {
                // fill many "pg" prefixes (kv/p/NN/xxxx) ...
                for pg in 0..self.rng.range(8, 32) {
                    for i in 0..self.rng.range(4, 12) {
                        let v = val(&mut self.rng);
                        t.ops
                            .push(Op::Put(format!("kv/p/{pg:02}/{i:04}").into_bytes(), v));
                    }
                }
            }
            63..=74 => {
                // ... and drop many of them in ONE txn (remove_pg x N), then everything under kv/p/
                let n = self.rng.range(8, 32);
                for pg in 0..n {
                    if self.rng.pct(85) {
                        t.ops.push(Op::DelRange(
                            format!("kv/p/{pg:02}/").into_bytes(),
                            format!("kv/p/{pg:02}0").into_bytes(),
                        ));
                    }
                }
                if self.rng.pct(50) {
                    t.ops
                        .push(Op::DelRange(b"kv/p/".to_vec(), b"kv/p0".to_vec()));
                }
            }
            75..=89 => {
                for _ in 0..self.rng.range(60, 250) {
                    match self.rng.below(10) {
                        0..=5 => {
                            let k = wide(&mut self.rng);
                            let v = val(&mut self.rng);
                            t.ops.push(Op::Put(k, v));
                        }
                        6..=7 => {
                            let k = wide(&mut self.rng);
                            t.ops.push(Op::Del(k));
                        }
                        _ => {
                            let a = self.rng.below(4000);
                            t.ops.push(Op::DelRange(
                                format!("kv/w/{a:05}").into_bytes(),
                                format!("kv/w/{:05}", a + self.rng.range(1, 300)).into_bytes(),
                            ));
                        }
                    }
                }
            }
            _ if self.cur.kv.len() < 150 => {
                // too small to be worth a nuke: grow
                for _ in 0..self.rng.range(200, 450) {
                    let k = wide(&mut self.rng);
                    let v = val(&mut self.rng);
                    t.ops.push(Op::Put(k, v));
                }
            }
            _ => {
                // nuke: free every live object and delete the WHOLE key space (all but the engine's `f` namespace)
                // as N adjacent ranges in random order (+ a final full range); remove_pg of everything in one txn
                let live: Vec<(u64, u32)> = self
                    .cur
                    .kv
                    .range(b"obj/".to_vec()..b"obj0".to_vec())
                    .map(|(_, v)| {
                        let (b, n, _) = dec_obj(v);
                        (b, n)
                    })
                    .collect();
                t.frees.extend(live);
                let mut cand: Vec<Vec<u8>> =
                    vec![b"kv/".to_vec(), b"log/".to_vec(), b"obj/".to_vec()];
                for _ in 0..self.rng.range(4, 30) {
                    cand.push(match self.rng.below(4) {
                        0 => format!("kv/{:03}", self.rng.below(200)).into_bytes(),
                        1 => format!("kv/p/{:02}/", self.rng.below(32)).into_bytes(),
                        2 => format!("kv/w/{:05}", self.rng.below(4000)).into_bytes(),
                        _ => obj_key(self.rng.below(NOBJ)),
                    });
                }
                cand.sort();
                cand.dedup();
                let mut ranges = Vec::new();
                for (lo, hi) in [
                    (b"".to_vec(), b"f".to_vec()),
                    (b"g".to_vec(), vec![0xff; 8]),
                ] {
                    let mut b = vec![lo.clone()];
                    b.extend(cand.iter().filter(|c| **c > lo && **c < hi).cloned());
                    b.push(hi);
                    ranges.extend(b.windows(2).map(|w| (w[0].clone(), w[1].clone())));
                }
                for i in (1..ranges.len()).rev() {
                    ranges.swap(i, self.rng.below(i as u64 + 1) as usize);
                }
                for (a, b) in ranges {
                    t.ops.push(Op::DelRange(a, b));
                }
                if self.rng.pct(50) {
                    t.ops.push(Op::DelRange(b"".to_vec(), b"f".to_vec()));
                    t.ops.push(Op::DelRange(b"g".to_vec(), vec![0xff; 8]));
                }
                if self.rng.pct(30) {
                    for _ in 0..self.rng.range(1, 20) {
                        let k = wide(&mut self.rng);
                        let v = val(&mut self.rng);
                        t.ops.push(Op::Put(k, v));
                    }
                }
            }
        }
    }

    fn mirror_at(&self, lsn: u64) -> Model {
        let mut s = Model::new(self.env.dir.data_start, self.env.dir.data_blocks);
        for r in &self.model[..lsn as usize] {
            s.apply(r);
        }
        s
    }

    /// Ask for a checkpoint now and then (the shard also triggers its own).
    fn maybe_ckpt(&mut self) {
        if self.env.scfg.auto_ckpt && self.rng.pct(4) {
            self.shard.request_checkpoint();
        }
    }

    /// One loop iteration: submit a burst, poll, advance the virtual clock. False once the disk crashed.
    pub fn step(&mut self, submit_budget: &mut u64, max_burst: u64) -> bool {
        if self.disk.crashed() {
            return false;
        }
        if self.idle_left == 0 && self.env.idle_pct > 0 && self.rng.pct(self.env.idle_pct) {
            self.idle_left = self.rng.range(1, 8);
        }
        let burst = if *submit_budget > 0 && self.idle_left == 0 {
            self.rng.below(max_burst + 1).min(*submit_budget)
        } else {
            0
        };
        for _ in 0..burst {
            let Some((t, rec)) = self.gen_txn() else {
                self.shard.request_checkpoint();
                break;
            };
            let blks: Vec<(u64, u32)> = rec.data.iter().map(|e| (e.blk, e.nblk)).collect();
            match self.shard.submit(t) {
                Ok(lsn) => {
                    assert_eq!(lsn, rec.lsn);
                    assert_eq!(lsn, self.model.len() as u64 + 1);
                    self.cur.apply(&rec);
                    self.model.push(rec);
                    *submit_budget -= 1;
                    self.submitted_since_crash += 1;
                }
                Err((e, _t)) => {
                    blks.iter().for_each(|&(b, n)| self.shard.unreserve(b, n));
                    match e {
                        StoreError::Busy | StoreError::Miss => break,
                        StoreError::WalFull => {
                            self.wal_full_hits += 1;
                            self.shard.request_checkpoint();
                            break;
                        }
                        StoreError::TxnTooLarge => {}
                        // a multi-part txn may exceed the meta space of a tiny test device (ENOSPC, nothing applied)
                        StoreError::NoSpace if _t.ops.len() > 40 => {}
                        // a user txn may meet a meta-bound shard (growth failed: fragmented or full data region); it
                        // reports full (statfs, `write_room`), nothing is applied (adr 0021 am. 12/21)
                        StoreError::NoSpace if !_t.sys && self.shard.statfs().meta_grow_blocked => {
                        }
                        StoreError::Failed | StoreError::Io(_) if self.disk.crashed() => {
                            return false;
                        }
                        e => panic!(
                            "unexpected submit error {e:?}: frees {:?} data {:?}",
                            _t.frees,
                            _t.data
                                .iter()
                                .map(|d| (d.0, d.1.len() / BLK))
                                .collect::<Vec<_>>()
                        ),
                    }
                }
            }
        }
        self.maybe_ckpt();
        if self.idle_left > 0 {
            // device idle gap: no submissions; once the device drained the clock passes the deallocate pause
            self.idle_left -= 1;
            let due = self.shard.trim_due();
            if self.shard.dev().next_deadline().is_none() && due > self.clk.t {
                self.clk.idle(Some(due));
            }
        }
        let mut ev = Vec::new();
        self.shard.poll(self.clk.t, &mut ev);
        for e in ev {
            match e {
                Event::Acked(lsn) => {
                    assert_eq!(lsn, self.acked + 1, "acks must be in LSN order");
                    self.acked = lsn;
                }
                Event::Released { .. } => self.releases += 1,
                Event::Failed(f) => {
                    assert!(self.disk.crashed(), "shard failed without crash: {f:?}");
                    return false;
                }
                Event::Read { .. } | Event::Wake | Event::Page(_) => {}
            }
        }
        let hint = self.shard.dev().next_deadline();
        self.clk.idle(hint);
        true
    }

    /// Run until `n` more txns were submitted and everything acked (or crash). False = crashed.
    pub fn run(&mut self, n: u64, max_burst: u64) -> bool {
        let mut budget = n;
        let mut guard = 0u64;
        loop {
            if !self.step(&mut budget, max_burst) {
                return false;
            }
            if budget == 0 && self.acked == self.model.len() as u64 {
                return true;
            }
            guard += 1;
            assert!(
                guard < 5_000_000,
                "livelock: acked {} of {}",
                self.acked,
                self.model.len()
            );
        }
    }

    /// Power loss + remount. `mount_crash`: arm a second power failure k events into the mount itself.
    pub fn crash_and_remount(
        &mut self,
        policy: CrashPolicy,
        mount_crash: Option<u64>,
    ) -> Result<ReplayStats, String> {
        self.dealloc_crashes += u64::from(self.disk.inflight_deallocs() > 0);
        self.disk.crash_now();
        let mut img = self.disk.crash_image(policy);
        // whatever root survived must be a consistent tree
        self.fsck_image(&img, "crash image")?;
        let mut mc = mount_crash;
        loop {
            let mut cfg = self.env.sim.clone();
            cfg.seed = self.rng.next_u64();
            let disk = SimDisk::from_image(&img, cfg);
            if let Some(k) = mc.take() {
                disk.arm_crash(k);
            }
            match mount(&self.env, &disk, &mut self.clk) {
                Ok((shard, stats)) => {
                    disk.disarm_crash();
                    self.disk = disk;
                    self.shard = shard;
                    self.remounts += 1;
                    let last = self.shard.state().lsn;
                    self.check_recovered()?;
                    self.model.truncate(last as usize);
                    self.cur = self.mirror_at(last);
                    self.acked = last;
                    let img2 = self.disk.image();
                    self.fsck_image(&img2, "after mount")?;
                    return Ok(stats);
                }
                Err(StoreError::Io(_)) if disk.crashed() => {
                    self.crashed_mount += 1;
                    img = disk.crash_image(policy);
                    self.fsck_image(&img, "crash image (mount crashed)")?;
                }
                Err(e) => return Err(format!("mount failed: {e:?}")),
            }
        }
    }

    pub fn fsck_image(&mut self, img: &SimImage, what: &str) -> Result<(), String> {
        let d = SimDisk::from_image(img, self.env.sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        fsck(&mut dev, &mut clk, Some(&obj_refs))
            .map(|_| ())
            .map_err(|e| format!("fsck {what}: {e}"))
    }

    /// Invariants on the freshly recovered shard (before the model is truncated):
    /// 1. every acked txn survived; 2. recovered state == model prefix (no phantom/partial txn);
    /// 3. data of every live object is intact (no torn data visible); 4. allocator consistent.
    pub fn check_recovered(&mut self) -> Result<(), String> {
        let last = self.shard.state().lsn;
        if last < self.acked {
            return Err(format!(
                "acked txn lost: acked={} recovered={last}",
                self.acked
            ));
        }
        if last > self.model.len() as u64 {
            return Err(format!(
                "phantom txns: recovered={last} submitted={}",
                self.model.len()
            ));
        }
        let exp = self.mirror_at(last);
        let got = self
            .shard
            .dump_blocking(&mut self.clk)
            .map_err(|e| format!("dump: {e:?}"))?;
        if got != exp.kv {
            let diff = got
                .iter()
                .find(|(k, v)| exp.kv.get(*k) != Some(*v))
                .map(|(k, _)| String::from_utf8_lossy(k).to_string());
            return Err(format!(
                "kv differs from model prefix {last} (first diff {diff:?}; got {} keys, want {})",
                got.len(),
                exp.kv.len()
            ));
        }
        let mut alloc = self.shard.state().alloc.snapshot();
        // elastic meta cells are allocated extents no txn knows about
        for (s, n) in self.shard.meta_cells() {
            for b in s..s + n {
                alloc.clear(b - self.env.dir.data_start);
            }
        }
        if alloc != exp.alloc {
            return Err(format!("allocator bitmap differs from model prefix {last}"));
        }
        // data of live objects
        let mut dev = self.disk.queue();
        let mut clk = SimClock::default();
        let mut io = Sio::new(&mut dev, &mut clk);
        for (k, v) in got.range(b"obj/".to_vec()..b"obj0".to_vec()) {
            let (blk, n, seed) = dec_obj(v);
            let data = io.read_one(blk, n).map_err(|e| format!("read {e:?}"))?;
            for i in 0..n {
                let mut want = vec![0u8; BLK];
                pattern(seed, i, &mut want);
                if data[i as usize * BLK..(i as usize + 1) * BLK] != want[..] {
                    return Err(format!(
                        "torn/stale data visible: {} blk {} (+{i}) lsn<={last}",
                        String::from_utf8_lossy(k),
                        blk
                    ));
                }
            }
            let first = blk - self.env.dir.data_start;
            if !(first..first + n as u64).all(|b| alloc.get(b)) {
                return Err("live object blocks not allocated".into());
            }
        }
        Ok(())
    }
}

/// Dry run: number of device events of a workload (for exhaustive crash points).
pub fn count_events(env: &Env, seed: u64, ntxn: u64, burst: u64) -> u64 {
    let mut h = Harness::new(env, seed);
    let e0 = h.disk.events();
    assert!(h.run(ntxn, burst));
    h.disk.events() - e0
}

pub struct RunInfo {
    pub crashed_in_gen0: bool,
    pub stats: ReplayStats,
    pub acked: u64,
    pub ckpts: u64,
    /// Elastic meta cells added / released over all mounts of the run.
    pub cells: (u64, u64),
    /// Gen 0 crashed in a checkpoint's sliced start / in its freeze end steps (adr 0021 am. 80).
    pub crashed_starting: bool,
    pub crashed_ending: bool,
    /// Crashes of the run that hit an in-flight deallocate.
    pub dealloc_crashes: u64,
}

/// One crash scenario: gen 0 crashes at event `k` (None = after the workload completed, with nothing in
/// flight except what the policy decides); then `gens - 1` further random crash cycles.
pub fn one_run(
    env: &Env,
    seed: u64,
    k: Option<u64>,
    policy: CrashPolicy,
    ntxn: u64,
    burst: u64,
    gens: u32,
) -> Result<RunInfo, String> {
    let mut h = Harness::new(env, seed);
    if let Some(k) = k {
        h.disk.arm_crash(h.disk.events() + k);
    }
    let crashed0 = !h.run(ntxn, burst);
    let crashed_starting = crashed0 && h.shard.ckpt_starting();
    let crashed_ending = crashed0 && h.shard.state().tree.fz_ending();
    let acked = h.acked;
    let mut ckpts = h.releases;
    let mut cells = (h.shard.stats.cells_added, h.shard.stats.cells_released);
    MULTI_SUBMITTED.fetch_add(h.shard.stats.multi_txns, Ordering::Relaxed);
    let mut stats = h
        .crash_and_remount(policy, None)
        .map_err(|e| format!("gen0 seed={seed} k={k:?}: {e}"))?;
    MULTI_REPLAYED.fetch_add(stats.multi_txns, Ordering::Relaxed);
    MULTI_DROPPED.fetch_add(stats.multi_dropped, Ordering::Relaxed);
    for g in 1..gens {
        let kk = h.rng.below(400);
        h.disk.arm_crash(h.disk.events() + kk);
        let n = h.rng.range(5, ntxn.max(6));
        h.run(n, burst);
        let mc = if h.rng.pct(20) {
            Some(h.rng.below(12))
        } else {
            None
        };
        let pol = [
            CrashPolicy::MIXED,
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
        ][h.rng.below(3) as usize];
        ckpts += h.releases;
        cells.0 += h.shard.stats.cells_added;
        cells.1 += h.shard.stats.cells_released;
        stats = h
            .crash_and_remount(pol, mc)
            .map_err(|e| format!("gen{g} seed={seed}: {e}"))?;
    }
    Ok(RunInfo {
        crashed_in_gen0: crashed0,
        stats,
        acked,
        ckpts,
        cells,
        crashed_starting,
        crashed_ending,
        dealloc_crashes: h.dealloc_crashes,
    })
}

#[allow(unused)]
fn _use(_: &dyn Clock) {}

/// Quiescent-shard helpers.
pub fn dump(s: &mut Shard<SimDev>, clk: &mut SimClock) -> BTreeMap<Vec<u8>, Vec<u8>> {
    s.dump_blocking(clk).unwrap()
}

/// Poll until no deallocate is in flight and no candidate is left, or none starts in a device idle gap past its pause
/// (candidates a command never takes: in use again, or above the cap; adr 0642). E.g. the mount trim of the whole free
/// windows: fixtures that count in-flight IO or free blocks start from here. Like a core, it polls an active shard (a
/// sliced checkpoint step needs no IO, adr 0021 am. 80) every pass; only a quiet shard's poll may start a deallocate.
pub fn settle_trims(s: &mut Shard<SimDev>, clk: &mut SimClock) {
    for _ in 0..1_000_000 {
        let g = s.gauges();
        if g.trim_held == 0 && g.trim_cand_windows == 0 {
            return;
        }
        let mut ev = Vec::new();
        s.poll(clk.t, &mut ev);
        assert!(ev.is_empty(), "settle_trims: shard events {ev:?}");
        if let Some(h) = s.dev().next_deadline() {
            clk.idle(Some(h));
            continue;
        }
        if !s.quiet() {
            clk.idle(None);
            continue;
        }
        let cmds = s.stats.trim_cmds;
        clk.idle(Some(s.trim_due().max(clk.t) + store::shard::BG_BUSY_GAP_NS));
        s.poll(clk.t, &mut ev);
        assert!(ev.is_empty(), "settle_trims: shard events {ev:?}");
        if s.stats.trim_cmds == cmds && s.gauges().trim_held == 0 && s.quiet() {
            sync_dev_clock(s.dev(), clk.t);
            return;
        }
    }
    panic!("deallocates never settled");
}

/// A quiescent shard poll skips the device, and the sim device times a submission from its last poll: after an idle
/// gap with nothing in flight, bring the device to `t` so the next command is not timed in the past.
pub fn sync_dev_clock(dev: &mut SimDev, t: u64) {
    let mut c = Vec::new();
    dev.poll(t, &mut c);
    assert!(c.is_empty(), "sync_dev_clock: {} completions", c.len());
}

pub fn has_key(s: &mut Shard<SimDev>, clk: &mut SimClock, key: &[u8]) -> bool {
    dump(s, clk).contains_key(key)
}

/// Poll until a checkpoint released `lsn` (or more); panics after a generous bound.
pub fn run_until_released(s: &mut Shard<SimDev>, clk: &mut SimClock, lsn: u64) -> Vec<u64> {
    let mut acked = vec![];
    for _ in 0..1_000_000 {
        let mut ev = Vec::new();
        s.poll(clk.t, &mut ev);
        for e in ev {
            match e {
                Event::Released { ckpt_lsn } if ckpt_lsn >= lsn => return acked,
                Event::Acked(t) => acked.push(t),
                Event::Failed(f) => panic!("shard failed {f:?}"),
                _ => {}
            }
        }
        let h = s.dev().next_deadline();
        clk.idle(h);
    }
    panic!("checkpoint of lsn {lsn} never completed");
}

pub fn split_reserved(a: &[u8], b: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    if !(a < b"g".as_slice() && b > b"f".as_slice()) {
        return vec![(a.to_vec(), b.to_vec())];
    }
    let mut v = Vec::new();
    if a < b"f".as_slice() {
        v.push((a.to_vec(), b"f".to_vec()));
    }
    if b > b"g".as_slice() {
        v.push((b"g".to_vec(), b.to_vec()));
    }
    v
}

/// Blocking single-shard rig for tree/allocator tests: serial txn submission with retry on
/// Busy/Miss/WalFull, a BTreeMap model, helpers for checkpoint, cold remount and full verification.
pub struct Rig {
    pub env: Env,
    pub disk: SimDisk,
    pub clk: SimClock,
    pub shard: Shard<SimDev>,
    pub model: BTreeMap<Vec<u8>, Vec<u8>>,
    pub submitted: u64,
    pub acked: u64,
    pub released: u64,
    pub rng: Rng,
    /// Tree counters summed over all (re)mounts of this rig, and the largest height seen.
    pub acc: store::tree::TreeStats,
    pub max_height: u8,
}

impl Rig {
    pub fn new(env: &Env, seed: u64) -> Rig {
        let mut cfg = env.sim.clone();
        cfg.seed = seed;
        let disk = SimDisk::from_image(&env.img, cfg);
        let mut clk = SimClock::default();
        let (shard, _) = mount(env, &disk, &mut clk).unwrap();
        Rig {
            env: env.clone(),
            disk,
            clk,
            shard,
            model: BTreeMap::new(),
            submitted: 0,
            acked: 0,
            released: 0,
            rng: Rng::new(seed ^ 0xA5A5),
            acc: Default::default(),
            max_height: 0,
        }
    }

    pub fn pump(&mut self) {
        let mut ev = Vec::new();
        self.shard.poll(self.clk.t, &mut ev);
        for e in ev {
            match e {
                Event::Acked(_) => self.acked += 1,
                Event::Released { .. } => self.released += 1,
                Event::Failed(f) => panic!("shard failed: {f:?}"),
                _ => {}
            }
        }
        let h = self.shard.dev().next_deadline();
        self.clk.idle(h);
    }

    /// Submit (retrying until accepted); the model follows. Returns the lsn.
    pub fn txn(&mut self, ops: Vec<Op>) -> u64 {
        let mut t: Txn<Vec<u8>> = Txn::new(self.submitted + 1);
        t.ops = ops;
        for _ in 0..10_000_000 {
            match self.shard.submit(t) {
                Ok(lsn) => {
                    // read the txn back from the model side: ops were moved into the WAL record
                    self.submitted += 1;
                    return lsn;
                }
                Err((StoreError::Busy | StoreError::Miss | StoreError::WalFull, back)) => {
                    t = back;
                    self.pump();
                }
                Err((e, back)) => panic!(
                    "submit failed: {e:?} ({} ops, {} payload bytes)",
                    back.ops.len(),
                    back.ops
                        .iter()
                        .map(|o| match o {
                            Op::Put(k, v) => k.len() + v.len(),
                            Op::Del(k) => k.len(),
                            Op::DelRange(a, b) => a.len() + b.len(),
                            Op::RunPut(r) => r.raw().len(),
                            Op::RunMerge { a, b, .. } => a.len() + b.len(),
                            Op::Omap(o) => o.wal_bytes(),
                        })
                        .sum::<usize>()
                ),
            }
        }
        panic!("txn never admitted");
    }

    /// Apply to shard and model (ranges overlapping the engine's reserved `f` namespace are split around it).
    pub fn apply(&mut self, ops: Vec<Op>) {
        let mut ops2 = Vec::new();
        for op in ops {
            match op {
                Op::DelRange(a, b) => {
                    if a < b {
                        for (x, y) in split_reserved(&a, &b) {
                            ops2.push(Op::DelRange(x, y));
                        }
                    }
                }
                o => ops2.push(o),
            }
        }
        let ops = ops2;
        for op in &ops {
            match op {
                Op::Put(k, v) => {
                    self.model.insert(k.clone(), v.clone());
                }
                Op::Del(k) => {
                    self.model.remove(k);
                }
                Op::DelRange(a, b) => self.model.retain(|k, _| !(k >= a && k < b)),
                Op::RunPut(r) => {
                    for i in 0..r.len() {
                        let (k, v) = r.entry(i);
                        // an empty value is a removal (FEAT_OMAP_TOMBS)
                        if v.is_empty() {
                            self.model.remove(k);
                        } else {
                            self.model.insert(k.to_vec(), v.to_vec());
                        }
                    }
                }
                Op::RunMerge { .. } => {}
                Op::Omap(_) => unreachable!("KV workloads log no omap LSM ops"),
            }
        }
        self.txn(ops);
    }

    pub fn put(&mut self, k: &[u8], v: &[u8]) {
        self.apply(vec![Op::Put(k.to_vec(), v.to_vec())]);
    }
    pub fn del(&mut self, k: &[u8]) {
        self.apply(vec![Op::Del(k.to_vec())]);
    }
    pub fn delrange(&mut self, a: &[u8], b: &[u8]) {
        self.apply(vec![Op::DelRange(a.to_vec(), b.to_vec())]);
    }

    /// Wait until everything submitted is acked.
    pub fn sync(&mut self) {
        let mut guard = 0u64;
        while self.acked < self.submitted {
            self.pump();
            guard += 1;
            assert!(guard < 10_000_000, "ack livelock");
        }
    }

    /// Checkpoint everything submitted so far and wait for it, and for one requested meanwhile (also in its sliced start).
    pub fn checkpoint(&mut self) {
        self.sync();
        let want = self.shard.next_lsn() - 1;
        let mut guard = 0u64;
        while self.shard.ckpt_lsn() < want || self.shard.ckpt_active() || self.shard.ckpt_starting()
        {
            self.shard.request_checkpoint();
            self.pump();
            guard += 1;
            assert!(guard < 10_000_000, "checkpoint livelock");
        }
    }

    /// Poll until no deallocate is in flight and no candidate is left, or none starts in a device idle gap past its
    /// pause (adr 0642). Fixtures that take blocks directly from the allocator start from here, so no deallocate holds
    /// free windows meanwhile. An active shard is polled every pass, as a core does ([`settle_trims`]).
    pub fn settle_trims(&mut self) {
        for _ in 0..1_000_000 {
            let g = self.shard.gauges();
            if g.trim_held == 0 && g.trim_cand_windows == 0 {
                return;
            }
            self.pump();
            if self.shard.dev().next_deadline().is_some() || !self.shard.quiet() {
                continue;
            }
            let cmds = self.shard.stats.trim_cmds;
            let due = self.shard.trim_due().max(self.clk.t) + store::shard::BG_BUSY_GAP_NS;
            self.clk.idle(Some(due));
            self.pump();
            if self.shard.stats.trim_cmds == cmds
                && self.shard.gauges().trim_held == 0
                && self.shard.quiet()
            {
                sync_dev_clock(self.shard.dev(), self.clk.t);
                return;
            }
        }
        panic!("deallocates never settled");
    }

    /// Poll until no deallocate is in flight (adr 0642); one may start at a later idle poll. Fixtures that take blocks
    /// directly from the allocator while the shard is busy (no deallocate starts then) start from here.
    pub fn drain_trim(&mut self) {
        for _ in 0..1_000_000 {
            if self.shard.gauges().trim_held == 0 {
                return;
            }
            self.pump();
        }
        panic!("deallocate never completed");
    }

    pub fn get(&mut self, k: &[u8]) -> Option<Vec<u8>> {
        for _ in 0..1_000_000 {
            let mut out = Vec::new();
            match self.shard.get(k, &mut out) {
                Ok(true) => return Some(out),
                Ok(false) => return None,
                Err(StoreError::Miss) => self.pump(),
                Err(e) => panic!("get failed: {e:?}"),
            }
        }
        panic!("get never completed");
    }

    /// Bounded scan of `[a, b)` driven to completion with the given budget.
    pub fn scan(&mut self, a: &[u8], b: &[u8], max_entries: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        use store::tree::{ScanCursor, ScanStatus};
        let mut cur = ScanCursor::new(a, b);
        let mut out = Vec::new();
        for _ in 0..10_000_000 {
            let r = self
                .shard
                .scan(&mut cur, max_entries, usize::MAX, &mut |k, v| {
                    out.push((k.to_vec(), v.to_vec()))
                });
            match r {
                Ok(ScanStatus::Done) => return out,
                Ok(ScanStatus::More) => {}
                Err(StoreError::Miss) => self.pump(),
                Err(e) => panic!("scan failed: {e:?}"),
            }
        }
        panic!("scan never completed");
    }

    /// `Shard::scan_pred(pivot, end)` driven through page misses: `Some(entries)` or `None` (predecessor in the
    /// previous leaf: nothing emitted).
    pub fn scan_pred(&mut self, pivot: &[u8], end: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
        for _ in 0..1_000_000 {
            let mut out = Vec::new();
            match self
                .shard
                .scan_pred(pivot, end, &mut |k, v| out.push((k.to_vec(), v.to_vec())))
            {
                Ok(true) => return Some(out),
                Ok(false) => return None,
                Err(StoreError::Miss) => self.pump(),
                Err(e) => panic!("scan_pred failed: {e:?}"),
            }
        }
        panic!("scan_pred never completed");
    }

    pub fn model_range(&self, a: &[u8], b: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        if a >= b {
            return vec![];
        }
        self.model
            .range(a.to_vec()..b.to_vec())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Whole keyspace == model, tree invariants of the cached part hold.
    pub fn verify(&mut self) {
        let got = self.shard.dump_blocking(&mut self.clk).unwrap();
        assert_eq!(got.len(), self.model.len(), "key count");
        assert!(got == self.model, "content differs from model");
    }

    /// Checkpoint, stop, mount again from the durable image (cold cache); fsck before and after.
    pub fn note_stats(&mut self) {
        let s = self.shard.tree_stats();
        self.acc.loads += s.loads;
        self.acc.evictions += s.evictions;
        self.acc.splits += s.splits;
        self.acc.grows += s.grows;
        self.acc.pruned += s.pruned;
        self.acc.merged += s.merged;
        self.max_height = self.max_height.max(self.shard.state().tree.height());
    }

    pub fn remount_clean(&mut self) {
        self.checkpoint();
        self.note_stats();
        let img = self.disk.image();
        self.fsck(&img);
        let mut cfg = self.env.sim.clone();
        cfg.seed = self.rng.next_u64();
        self.disk = SimDisk::from_image(&img, cfg);
        let (shard, stats) = mount(&self.env, &self.disk, &mut self.clk).unwrap();
        assert_eq!(stats.txns, 0, "clean remount must not replay");
        self.shard = shard;
        self.submitted = 0;
        self.acked = 0;
        // model txn tokens restart
    }

    pub fn fsck(&mut self, img: &SimImage) -> store::fsck::FsckReport {
        let d = SimDisk::from_image(img, self.env.sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        let mut r = fsck(&mut dev, &mut clk, None).unwrap_or_else(|e| panic!("fsck: {e}"));
        r.pop().unwrap()
    }
}
