// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Allocation search cost on an aged elastic shard, e9455 gate geometry (doc/perf/alloc-scan-20261102.md): base chunks,
//! borrowed chunks granted by the shard's lend rule, filled with 4 MiB objects (16 pre-write pieces of 64 blocks), aged
//! by small random copy-on-write overwrites (hole-first, `small_dense`), then 4 MiB random overwrites. Reports ns per
//! allocator call per phase and bucket. Measurement, run with --release --features elastic --ignored --nocapture.

use super::*;
use crate::rng::Rng;

/// 1 GiB chunks (mkfs default).
const C: u64 = 262_144;
/// A 4 MiB object = 16 pre-write pieces of 256 KiB (`Shard::pre_write` reserves each with `reserve(64)`).
const PIECE: u32 = 64;
const PIECES: usize = 16;

struct Sim {
    a: Alloc,
    rng: Rng,
    /// Live extents per object.
    objs: Vec<Vec<(u64, u32)>>,
    held: Vec<(u64, u32)>,
    held_blocks: u64,
    /// Freed blocks between two checkpoints (held until then).
    ckpt_blocks: u64,
    /// Lend rule (`Shard::lend_wants`): a chunk is granted while the whole free windows hold less than the data
    /// reserve (3 % of the base) plus the watermark (25 % of a chunk).
    keep: u64,
    slots: usize,
    next_phys: u64,
    /// Timed allocator calls since the last [`Sim::take`]: ns, calls, worst call, worst first call after a checkpoint
    /// (it reads the summaries of every window the checkpoint freed blocks in).
    ns: u128,
    calls: u64,
    worst: u128,
    worst_ck: u128,
    after_ck: bool,
}

impl Sim {
    fn new(base: u64, ckpt_blocks: u64, seed: u64) -> Sim {
        let phys: Vec<u64> = (0..base).map(|i| i * C).collect();
        Sim {
            a: Alloc::with_lent(&phys, &[], C),
            rng: Rng::new(seed),
            objs: Vec::new(),
            held: Vec::new(),
            held_blocks: 0,
            ckpt_blocks,
            keep: base * C * 3 / 100 + C / 4,
            slots: 0,
            next_phys: base * C,
            ns: 0,
            calls: 0,
            worst: 0,
            worst_ck: 0,
            after_ck: false,
        }
    }

    fn grant(&mut self) {
        self.a.lend_add(self.slots, self.next_phys);
        self.slots += 1;
        self.next_phys += C;
    }

    fn ckpt(&mut self) {
        for (b, n) in std::mem::take(&mut self.held) {
            self.a.release_held(b, n);
        }
        self.held_blocks = 0;
        self.after_ck = true;
    }

    /// One timed allocation of `n` blocks, hole-first (`small_dense`) or next-fit; nothing fits: checkpoint, then
    /// a granted chunk.
    fn alloc(&mut self, n: u32, dense: bool) -> u64 {
        loop {
            let t = std::time::Instant::now();
            let r = if dense {
                self.a.reserve_dense(n).or_else(|| self.a.reserve(n))
            } else {
                self.a.reserve(n)
            };
            let dt = t.elapsed().as_nanos();
            (self.ns, self.calls) = (self.ns + dt, self.calls + 1);
            if std::mem::take(&mut self.after_ck) {
                self.worst_ck = self.worst_ck.max(dt);
            } else {
                self.worst = self.worst.max(dt);
            }
            if let Some(b) = r {
                self.a.apply_alloc(b, n);
                return b;
            }
            if self.held_blocks > 0 {
                self.ckpt();
            } else {
                self.grant();
            }
        }
    }

    fn free(&mut self, b: u64, n: u32) {
        self.a.apply_free(b, n);
        self.held.push((b, n));
        self.held_blocks += n as u64;
        if self.held_blocks >= self.ckpt_blocks {
            self.ckpt();
        }
    }

    fn lend_check(&mut self) {
        while self.a.free_windows() * WIN < self.keep {
            self.grant();
        }
    }

    /// Write object `i` whole (first write or 4 MiB overwrite): the new pieces, then the old extents are freed.
    fn write_obj(&mut self, i: usize) {
        let new: Vec<(u64, u32)> = (0..PIECES)
            .map(|_| (self.alloc(PIECE, false), PIECE))
            .collect();
        for (b, n) in std::mem::replace(&mut self.objs[i], new) {
            self.free(b, n);
        }
        self.lend_check();
    }

    /// Copy-on-write overwrite of `n` blocks inside one extent of a random object (4K / 64K random write).
    fn write_small(&mut self, n: u32) {
        let (i, j, b, len) = loop {
            let i = self.rng.below(self.objs.len() as u64) as usize;
            let j = self.rng.below(self.objs[i].len() as u64) as usize;
            let (b, len) = self.objs[i][j];
            if len >= n {
                break (i, j, b, len);
            }
        };
        let k = self.rng.below((len - n + 1) as u64) as u32;
        let nb = self.alloc(n, n <= 16);
        let o = &mut self.objs[i];
        o[j] = (nb, n);
        if k > 0 {
            o.push((b, k));
        }
        if k + n < len {
            o.push((b + (k + n) as u64, len - k - n));
        }
        self.free(b + k as u64, n);
        self.lend_check();
    }

    /// (mean ns, worst ns, worst ns after a checkpoint) of the timed calls since the last take.
    fn take(&mut self) -> (f64, f64, f64) {
        let r = (
            self.ns as f64 / self.calls.max(1) as f64,
            self.worst as f64,
            self.worst_ck as f64,
        );
        (self.ns, self.calls, self.worst, self.worst_ck) = (0, 0, 0, 0);
        r
    }

    fn line(&mut self, what: &str) {
        let (mean, worst, worst_ck) = self.take();
        let [whole, short, longest] = self.a.frag_full();
        let a = &self.a;
        eprintln!(
            "{what:>12}: {mean:>9.0} ns/alloc (worst {:>7.3} ms, after ckpt {:>7.3} ms) | chunks {} + {} lent, free {:.2} % \
             (whole windows {:.2} %, short {:.2} %, longest {longest}), held {}, base {} ({:.2} % free)",
            worst / 1e6,
            worst_ck / 1e6,
            a.base_n / C,
            self.slots,
            a.n_free() as f64 * 100.0 / a.usable_len() as f64,
            whole as f64 * 100.0 / a.usable_len() as f64,
            short as f64 * 100.0 / a.usable_len() as f64,
            self.held_blocks,
            if a.base_open { "open" } else { "closed" },
            (a.base_n - a.base_busy.min(a.base_n)) as f64 * 100.0 / a.base_n as f64,
        );
    }
}

/// Measurement parameter `k` from the environment, default `d` (also used by `frag4m`).
pub(super) fn env(k: &str, d: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

/// e9455 gate shard: 595 base chunks, filled to ~1170 chunks at 96.5 %, 4K-aged, then 4 MiB overwrites, then 64K /
/// 32K (EC 2+2 64K per shard) / 4K overwrites (AGE_BASE_CHUNKS, AGE_CHUNKS, AGE_SMALL_OPS, AGE_BUCKETS,
/// AGE_BUCKET_OBJS, AGE_SMALL_BUCKETS, AGE_SMALL_BUCKET_OPS, AGE_CKPT_BLOCKS scale it). Run: `lab/alloc-age-cost.sh`.
#[test]
#[ignore = "measurement"]
fn e9455_overwrite_cost() {
    let base = env("AGE_BASE_CHUNKS", 595);
    let total = env("AGE_CHUNKS", base * 1170 / 595);
    let small = env("AGE_SMALL_OPS", total * C / 150);
    let buckets = env("AGE_BUCKETS", 12);
    let per = env("AGE_BUCKET_OBJS", 1000) as usize;
    let mut s = Sim::new(base, env("AGE_CKPT_BLOCKS", 1 << 20), 11);
    let objs = (total * C * 965 / 1000 / 1024) as usize;
    s.objs = vec![Vec::new(); objs];
    for i in 0..objs {
        s.write_obj(i);
    }
    s.ckpt();
    s.line("fill");
    for _ in 0..small {
        s.write_small(1);
    }
    s.ckpt();
    s.line("4K aging");
    for k in 0..buckets {
        for _ in 0..per {
            let i = s.rng.below(objs as u64) as usize;
            s.write_obj(i);
        }
        s.line(&format!("4M +{}", (k + 1) as usize * per));
    }
    let (sb, sops) = (
        env("AGE_SMALL_BUCKETS", 3),
        env("AGE_SMALL_BUCKET_OPS", 20_000),
    );
    for (name, n) in [("64K", 16u32), ("32K", 8), ("4K", 1)] {
        for k in 0..sb {
            for _ in 0..sops {
                s.write_small(n);
            }
            s.line(&format!("{name} +{}", (k + 1) * sops));
        }
    }
}
