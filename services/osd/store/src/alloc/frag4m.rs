// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Data-run placement on a filled, aged shard (doc/perf/frag4m-20261102.md): the tsrv2 `fill4m-ab.sh` sequence on one
//! shard's allocator. Fill to 96 % of the device with 4 MiB objects (borrowed chunks granted by the lend rule, the pool
//! drained at the end), 3 random 4K overwrites per 256 KiB piece, 4 MiB overwrites (`w4m`), 64K / 32K random overwrites,
//! 4 MiB overwrites again (`w4m.2`). Every write is copy-on-write: new runs first, the old blocks held until the next
//! checkpoint. A 4 MiB write first tries a pre-write of each 256 KiB piece (`Shard::pre_write`), the txn allocates the
//! rest run by run (`Stage::write_raw_one` -> `Shard::alloc_data`). Counts runs (extents) and allocator calls per write
//! and times the calls.

use super::age_cost::env;
use super::*;
use crate::rng::Rng;

/// Blocks of a 4 MiB object and of a pre-write piece (`Shard::pre_piece`: `MAX_RUN` blocks).
const OBJ: u32 = 1024;
const PIECE: u32 = 64;
/// `ShardCfg` defaults of the data path: hole-first runs up to `small_dense` blocks, `keep_windows` whole windows kept
/// for meta cells (adr 0021 am. 51).
const SMALL_DENSE: u32 = 16;
const KEEP: u64 = 8;

#[derive(Clone, Copy, Default)]
struct Tally {
    writes: u64,
    /// Extents written, of them cut shorter than asked; allocator calls and their ns, of them pre-write tries.
    runs: u64,
    cuts: u64,
    calls: u64,
    ns: u128,
    pre_misses: u64,
    pre_ns: u128,
}

struct Sim {
    a: Alloc,
    rng: Rng,
    chunk: u64,
    /// Engine block of every logical block, per object.
    objs: Vec<Vec<u64>>,
    held: Vec<(u64, u32)>,
    held_blocks: u64,
    /// Checkpoint cadence: freed blocks or writes since the last one.
    ckpt_blocks: u64,
    ckpt_ops: u64,
    ops: u64,
    ckpts: u64,
    /// Lend rule (`Shard::lend_wants`): a chunk is granted while the whole free windows hold less than this.
    keep: u64,
    /// Chunks the pool can still lend.
    pool: u64,
    slots: usize,
    next_phys: u64,
    t: Tally,
}

impl Sim {
    fn new(base: u64, total: u64, chunk: u64, seed: u64) -> Sim {
        let phys: Vec<u64> = (0..base).map(|i| i * chunk).collect();
        let n = total * chunk;
        Sim {
            a: Alloc::with_lent(&phys, &[], chunk),
            rng: Rng::new(seed),
            chunk,
            objs: Vec::new(),
            held: Vec::new(),
            held_blocks: 0,
            ckpt_blocks: n / 128,
            ckpt_ops: (n / 20_000).max(64),
            ops: 0,
            ckpts: 0,
            keep: base * chunk * 3 / 100 + chunk / 4,
            pool: total - base,
            slots: 0,
            next_phys: base * chunk,
            t: Tally::default(),
        }
    }

    fn grant(&mut self) {
        assert!(self.pool > 0, "sim device full");
        self.a.lend_add(self.slots, self.next_phys);
        self.slots += 1;
        self.next_phys += self.chunk;
        self.pool -= 1;
    }

    fn ckpt(&mut self) {
        for (b, n) in std::mem::take(&mut self.held) {
            self.a.release_held(b, n);
        }
        self.held_blocks = 0;
        self.ops = 0;
        self.ckpts += 1;
    }

    /// Nothing allocatable: the shard forces a checkpoint while freed blocks are held, else asks the pool.
    fn no_space(&mut self) {
        if self.held_blocks > 0 {
            self.ckpt();
        } else {
            self.grant();
        }
    }

    fn timed<T>(&mut self, pre: bool, f: impl FnOnce(&mut Alloc) -> Option<T>) -> Option<T> {
        let t0 = std::time::Instant::now();
        let r = f(&mut self.a);
        let ns = t0.elapsed().as_nanos();
        let t = &mut self.t;
        t.ns += ns;
        t.calls += 1;
        if pre {
            t.pre_ns += ns;
            t.pre_misses += u64::from(r.is_none());
        }
        r
    }

    /// One `Shard::alloc_data` call (`Shard::alloc_find` with `data`): hole first while few whole windows are left
    /// (keep_windows, adr 0021 am. 51) or for short runs (small_dense, adr 0475), else `Alloc::reserve_cut` (am. 3).
    fn alloc_data(a: &mut Alloc, n: u32) -> Option<(u64, u32)> {
        let keep =
            n as u64 <= WIN / 8 && a.free_windows() <= KEEP && a.n_windows() as u64 >= 4 * KEEP;
        if (keep || n <= SMALL_DENSE)
            && let Some(b) = a.reserve_dense(n)
        {
            return Some((b, n));
        }
        a.reserve_cut(n)
    }

    /// `Stage::alloc_upto`: a run of at most `want` blocks; nothing allocatable -> checkpoint or a granted chunk.
    fn alloc_upto(&mut self, want: u32) -> (u64, u32) {
        loop {
            if let Some((b, got)) = self.timed(false, |a| Sim::alloc_data(a, want)) {
                self.t.runs += 1;
                self.t.cuts += u64::from(got < want);
                return (b, got);
            }
            self.no_space();
        }
    }

    fn free(&mut self, l: &[u64]) {
        let mut i = 0;
        while i < l.len() {
            let mut j = i + 1;
            while j < l.len() && l[j] == l[j - 1] + 1 {
                j += 1;
            }
            self.a.apply_free(l[i], (j - i) as u32);
            self.held.push((l[i], (j - i) as u32));
            self.held_blocks += (j - i) as u64;
            i = j;
        }
    }

    fn done(&mut self, new: &[(u64, u32)]) {
        for &(b, n) in new {
            self.a.apply_alloc(b, n);
        }
        self.t.writes += 1;
        self.ops += 1;
        if self.held_blocks >= self.ckpt_blocks || self.ops >= self.ckpt_ops {
            self.ckpt();
        }
        while self.pool > 0 && self.a.free_windows() * WIN < self.keep {
            self.grant();
        }
    }

    /// Object `i` written whole: pre-write of every piece, the txn allocates the pieces that got none.
    fn write_obj(&mut self, i: usize) {
        let mut runs: Vec<(u64, u32)> = Vec::new();
        let mut pre = [None; (OBJ / PIECE) as usize];
        for p in pre.iter_mut() {
            *p = self.timed(true, |a| a.reserve(PIECE));
            if let Some(b) = *p {
                runs.push((b, PIECE));
            }
        }
        self.t.runs += runs.len() as u64;
        let mut new = vec![0u64; OBJ as usize];
        for (k, p) in pre.iter().enumerate() {
            let l0 = k * PIECE as usize;
            match *p {
                Some(b) => {
                    for (j, x) in new[l0..l0 + PIECE as usize].iter_mut().enumerate() {
                        *x = b + j as u64;
                    }
                }
                None => {
                    let mut l = l0;
                    while l < l0 + PIECE as usize {
                        let (b, got) = self.alloc_upto((l0 + PIECE as usize - l) as u32);
                        for (j, x) in new[l..l + got as usize].iter_mut().enumerate() {
                            *x = b + j as u64;
                        }
                        runs.push((b, got));
                        l += got as usize;
                    }
                }
            }
        }
        let old = std::mem::replace(&mut self.objs[i], new);
        self.free(&old);
        self.done(&runs);
    }

    /// Random `n`-block overwrite at an `n`-aligned offset of a random object.
    fn write_small(&mut self, n: u32) {
        let i = self.rng.below(self.objs.len() as u64) as usize;
        let l0 = (self.rng.below((OBJ / n) as u64) * n as u64) as usize;
        let mut runs = Vec::new();
        let mut l = 0;
        let mut new = vec![0u64; n as usize];
        while l < n as usize {
            let (b, got) = self.alloc_upto(n - l as u32);
            for (j, x) in new[l..l + got as usize].iter_mut().enumerate() {
                *x = b + j as u64;
            }
            runs.push((b, got));
            l += got as usize;
        }
        let old: Vec<u64> = self.objs[i][l0..l0 + n as usize].to_vec();
        self.objs[i][l0..l0 + n as usize].copy_from_slice(&new);
        self.free(&old);
        self.done(&runs);
    }

    fn line(&mut self, what: &str) -> Tally {
        let t = std::mem::take(&mut self.t);
        let w = t.writes.max(1) as f64;
        let [whole, short, longest] = self.a.frag_full();
        let a = &self.a;
        let u = a.usable_len() as f64;
        eprintln!(
            "{what:>10}: {:>7} writes | runs/write {:>6.1} (cut {:>6.1}) | calls/write {:>6.1} (pre-write misses {:>5.1}) | \
             alloc ns/write {:>8.0} (pre-write {:>6.0}) | free {:.2} % (whole windows {:.2} %, short {:.2} %, longest {longest}) \
             | chunks {} + {} lent | ckpts {}",
            t.writes,
            t.runs as f64 / w,
            t.cuts as f64 / w,
            t.calls as f64 / w,
            t.pre_misses as f64 / w,
            t.ns as f64 / w,
            t.pre_ns as f64 / w,
            a.n_free() as f64 * 100.0 / u,
            whole as f64 * 100.0 / u,
            short as f64 * 100.0 / u,
            a.base_n / self.chunk,
            self.slots,
            self.ckpts,
        );
        t
    }
}

/// The phase results: `(name, tally)` per phase.
fn run(base: u64, total: u64, chunk: u64, buckets: u64, seed: u64) -> Vec<(String, Tally)> {
    let mut s = Sim::new(base, total, chunk, seed);
    let objs = (total * chunk * 962 / 1000 / OBJ as u64) as usize;
    let data = objs as u64 * OBJ as u64;
    s.objs = vec![Vec::new(); objs];
    let mut out = Vec::new();
    for i in 0..objs {
        s.write_obj(i);
    }
    while s.pool > 0 {
        s.grant();
    }
    s.ckpt();
    out.push(("fill".to_string(), s.line("fill")));
    for _ in 0..data * 3 / PIECE as u64 {
        s.write_small(1);
    }
    s.ckpt();
    out.push(("4K age".to_string(), s.line("4K age")));
    // volumes as fractions of the data (tsrv2 fill-stall run: w4m 0.60, w64k 0.29, w32k 0.16, w64k.r 0.16, w32k.r 0.10,
    // w4m.2 0.27)
    let phases: [(&str, u32, u64); 6] = [
        ("w4m", OBJ, 600),
        ("w64k", 16, 290),
        ("w32k", 8, 160),
        ("w64k.r", 16, 160),
        ("w32k.r", 8, 100),
        ("w4m.2", OBJ, 270),
    ];
    for (name, n, permille) in phases {
        let ops = data * permille / 1000 / n as u64;
        for k in 0..buckets {
            for _ in 0..ops / buckets {
                if n == OBJ {
                    let i = s.rng.below(objs as u64) as usize;
                    s.write_obj(i);
                } else {
                    s.write_small(n);
                }
            }
            let tag = format!("{name}.{}", k + 1);
            out.push((tag.clone(), s.line(&tag)));
        }
    }
    out
}

/// tsrv2 shard scaled down (FRAG_BASE_CHUNKS, FRAG_CHUNKS, FRAG_CHUNK_BLOCKS, FRAG_BUCKETS, FRAG_SEED). Run:
/// `lab/alloc-frag4m.sh`.
#[test]
#[ignore = "measurement"]
fn tsrv2_frag4m() {
    run(
        env("FRAG_BASE_CHUNKS", 16),
        env("FRAG_CHUNKS", 64),
        env("FRAG_CHUNK_BLOCKS", 65536),
        env("FRAG_BUCKETS", 3),
        env("FRAG_SEED", 7),
    );
}
