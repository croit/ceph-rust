// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `bench-full`: a store close to full (adr 0021 am. 33), store level on a SIMULATED device (real time).
//!
//!   croit-flashstore-tool bench-full [--dev-mib 4096] [--shards 4] [--pgs 64] [--obj-kib 4096] [--fill 95] [--secs 20]
//!                           [--qd 16] [--mix ow:40,small:20,del:20,new:20] [--cache-pages 4096] [--ckpt-ms 5000]
//!                           [--bg] [--trace] [--no-defrag] [--xfer-ns 1300]
//!
//! Fill phase: new objects (OSD-like txn: data + `_` attr + pg-log omap set/trim) until the fullest shard reaches
//! `--fill` percent. Then `--secs` of mixed load picked at random by weight: `ow` whole-object overwrite, `small` 4 KiB
//! overwrite at a random block (fragments the free space), `del` remove, `new` create (refused like the OSD when
//! `Store::write_room` says no: ENOSPC). Per second: acked ops, MB/s written, ENOSPC, worst single `queue` call (the core
//! is blocked for that long: no network polling), worst op latency, checkpoints / forced, fill, held, free extents.
use crate::bench::{pgc, pgmeta, pgs_arg};
use crate::{arg, flag, mib, num, num_opt};
use denc::types::{Ghobject, Hobject, ShardId, SnapId};
use std::collections::HashMap;
use std::time::Instant;
use store::dev::{MonoClock, SimClock, SimConfig, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, Store, StoreCfg, TOp};
use store::rng::Rng;

type St = Store<store::dev::SimDev, MonoClock>;

pub fn run(a: &[String]) -> i32 {
    match inner(a) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("bench-full: {e}");
            1
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    New,
    Ow,
    Small,
    Del,
}

struct Obj {
    pg: u32,
    o: Ghobject,
}

fn make_obj(i: u64, pgs: u32) -> Obj {
    let h = (i.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 32) as u32;
    let name = format!("benchmark_data_host01_full_object{i}");
    Obj {
        pg: h & (pgs - 1),
        o: Ghobject::new(
            Hobject::new(name.as_bytes(), SnapId(0), h, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        ),
    }
}

fn log_key(n: u64) -> Vec<u8> {
    format!("pglog.0.{n:016}").into_bytes()
}

struct Bench {
    st: St,
    pgs: u32,
    data: Vec<u8>,
    log_seq: Vec<u64>,
    pgm: Vec<Ghobject>,
    live: Vec<Obj>,
    next_id: u64,
    tok: u64,
    /// token -> (start, bytes written)
    inflight: HashMap<u64, (Instant, u64)>,
    acked: Vec<u64>,
    // interval counters
    ops: u64,
    bytes: u64,
    enospc: u64,
    max_queue_ns: u64,
    /// worst queue call per kind (New, Ow, Small, Del)
    kq: [u64; 4],
    max_lat_ns: u64,
    max_poll_ns: u64,
    bg: bool,
}

impl Bench {
    fn fill_pct(&self) -> f32 {
        self.st.statfs().fullest_shard_pct
    }

    /// Queue one op of `kind`; false = refused (ENOSPC / nothing to act on).
    fn issue(&mut self, kind: Kind, rng: &mut Rng) -> Result<bool, String> {
        let size = self.data.len() as u64;
        let (oi, created) = match kind {
            Kind::New => {
                let o = make_obj(self.next_id, self.pgs);
                if !self.st.write_room(&pgc(o.pg), size, 0) {
                    self.enospc += 1;
                    return Ok(false);
                }
                self.next_id += 1;
                self.live.push(o);
                (self.live.len() - 1, true)
            }
            _ => {
                if self.live.is_empty() {
                    return Ok(false);
                }
                (rng.below(self.live.len() as u64) as usize, false)
            }
        };
        let (pg, o) = (self.live[oi].pg, self.live[oi].o.clone());
        let c = pgc(pg);
        let seq = &mut self.log_seq[pg as usize];
        *seq += 1;
        let (kn, ko) = (log_key(*seq), log_key(seq.saturating_sub(500)));
        let lv = &self.data[256..436];
        let mut t = OTxn::new();
        let mut wrote = 0u64;
        match kind {
            Kind::New | Kind::Ow => {
                if !created && !self.st.write_room(&c, size, 0) {
                    self.enospc += 1;
                    return Ok(false);
                }
                t.write(c, &o, 0, &self.data);
                t.setattr(c, &o, b"_", &self.data[..250]);
                wrote = size;
            }
            Kind::Small => {
                if !self.st.write_room(&c, 4096, 0) {
                    self.enospc += 1;
                    return Ok(false);
                }
                let blk = rng.below(size.div_ceil(4096));
                t.write(c, &o, blk * 4096, &self.data[..4096]);
                t.setattr(c, &o, b"_", &self.data[..250]);
                wrote = 4096;
            }
            Kind::Del => {
                t.remove(c, &o);
                self.live.swap_remove(oi);
            }
        }
        t.omap_set(c, &self.pgm[pg as usize], &kn, lv);
        if *seq > 500 {
            t.push(TOp::OmapRmKeys {
                cid: c,
                oid: self.pgm[pg as usize].clone(),
                keys: vec![ko.as_slice().into()],
            });
        }
        t.sys = kind != Kind::Del; // admitted by write_room (the OSD's order), deletes are classed by the store
        self.tok += 1;
        let q0 = Instant::now();
        let r = self.st.queue(&t, self.tok);
        let qns = q0.elapsed().as_nanos() as u64;
        self.max_queue_ns = self.max_queue_ns.max(qns);
        self.kq[kind as usize] = self.kq[kind as usize].max(qns);
        match r {
            Ok(_) => {
                self.inflight.insert(self.tok, (q0, wrote));
                Ok(true)
            }
            Err(store::obj::ObjError::NoSpace) => {
                self.enospc += 1;
                Ok(false)
            }
            Err(e) => Err(format!("queue {kind:?}: {e}")),
        }
    }

    fn poll(&mut self) -> Result<(), String> {
        let p0 = Instant::now();
        self.acked.clear();
        self.st
            .poll(&mut self.acked)
            .map_err(|e| format!("poll: {e}"))?;
        for t in self.acked.drain(..) {
            if let Some((s, b)) = self.inflight.remove(&t) {
                self.ops += 1;
                self.bytes += b;
                self.max_lat_ns = self.max_lat_ns.max(s.elapsed().as_nanos() as u64);
            }
        }
        self.max_poll_ns = self.max_poll_ns.max(p0.elapsed().as_nanos() as u64);
        Ok(())
    }

    fn reset(&mut self) {
        self.ops = 0;
        self.bytes = 0;
        self.enospc = 0;
        self.max_queue_ns = 0;
        self.kq = [0; 4];
        self.max_lat_ns = 0;
        self.max_poll_ns = 0;
    }

    fn line(&mut self, tag: &str, secs: f64, ck0: &mut (u64, u64)) {
        let f = self.st.statfs();
        let ck = self.st.shards.iter().fold((0, 0), |a, s| {
            (a.0 + s.sh.stats.checkpoints, a.1 + s.sh.stats.forced_ckpts)
        });
        let fe = self.st.free_extents();
        let big = fe.iter().map(|e| e.1).max().unwrap_or(0);
        let wins = fe.iter().map(|e| e.1 / 256).sum::<u64>();
        println!(
            "{tag:<6} {:>7.0} ops/s {:>7.1} MB/s enospc {:>5} | queue max {:>7.2} ms poll max {:>6.2} ms lat max {:>7.1} ms | ckpt {:>3} forced {:>4} | fill {:>5.1}% held {:>5.1} MiB | free ext {:>6} max {:>5} blk 1MiB-runs {:>5} | live {} | defrag moved {}",
            self.ops as f64 / secs,
            self.bytes as f64 / secs / 1e6,
            self.enospc,
            self.max_queue_ns as f64 / 1e6,
            self.max_poll_ns as f64 / 1e6,
            self.max_lat_ns as f64 / 1e6,
            ck.0 - ck0.0,
            ck.1 - ck0.1,
            f.fullest_shard_pct,
            f.held_bytes as f64 / (1 << 20) as f64,
            fe.len(),
            big,
            wins,
            self.live.len(),
            self.st
                .shards
                .iter()
                .map(|s| s.defrag_stats().moved_extents)
                .sum::<u64>(),
        );
        let w = |k: usize| {
            (
                store::dbg::QWAIT_CALLS[k].swap(0, std::sync::atomic::Ordering::Relaxed),
                store::dbg::QWAIT_NS[k].swap(0, std::sync::atomic::Ordering::Relaxed) as f64 / 1e6,
            )
        };
        let (a, s) = (w(0), w(1));
        println!(
            "       waits in queue: alloc {} ({:.1} ms) submit {} ({:.1} ms) | queue max new/ow/small/del {:.2} {:.2} {:.2} {:.2} ms",
            a.0,
            a.1,
            s.0,
            s.1,
            self.kq[0] as f64 / 1e6,
            self.kq[1] as f64 / 1e6,
            self.kq[2] as f64 / 1e6,
            self.kq[3] as f64 / 1e6
        );
        let busy: Vec<String> = (1..10)
            .filter_map(|r| {
                let c = store::dbg::BUSY[r].swap(0, std::sync::atomic::Ordering::Relaxed);
                (c > 0).then(|| format!("{r}:{c}"))
            })
            .collect();
        if !busy.is_empty() {
            println!("       submit refusals by reason: {}", busy.join(" "));
        }
        *ck0 = ck;
        self.reset();
    }
}

fn inner(a: &[String]) -> Result<(), String> {
    let dev = mib("--dev-mib", num(a, "--dev-mib", 4096)?)?;
    let shards = num(a, "--shards", 4)? as u32;
    let pgs = pgs_arg(a)?
        .checked_next_power_of_two()
        .ok_or("--pgs: no power of two fits")?;
    let size = (num(a, "--obj-kib", 4096)? as usize * 1024).max(4096);
    let target = num(a, "--fill", 95)? as f32;
    let secs = num(a, "--secs", 20)?;
    let qd = num(a, "--qd", 16)? as usize;
    if qd == 0 {
        return Err(
            "--qd 0: no op is ever in flight (the fill and the load would never end)".into(),
        );
    }
    let mix = arg(a, "--mix").unwrap_or_else(|| "ow:40,small:20,del:20,new:20".into());
    let mut w: Vec<(Kind, u64)> = Vec::new();
    for p in mix.split(',') {
        let (k, v) = p.split_once(':').ok_or("--mix k:w,...")?;
        let kind = match k {
            "ow" => Kind::Ow,
            "small" => Kind::Small,
            "del" => Kind::Del,
            "new" => Kind::New,
            _ => return Err(format!("--mix: unknown {k}")),
        };
        w.push((kind, v.parse().map_err(|_| "--mix weight")?));
    }
    let wsum: u64 = w.iter().map(|x| x.1).sum::<u64>().max(1);
    let mut sim = SimConfig::new(dev);
    sim.jitter_ns = 2000;
    sim.dedup = true;
    let run_xfer = match num_opt(a, "--xfer-ns")? {
        Some(n) => n,
        None => sim.xfer_ns_per_lba,
    };
    let disk = SimDisk::new(sim);
    {
        let mut d = disk.queue();
        let mut clk = SimClock::default();
        let p = MkfsParams {
            shards,
            wal_blocks: 16384,
            align_blocks: 1,
            node_size: 8192,
            ..Default::default()
        };
        mkfs(&mut d, &mut clk, &p).map_err(|e| format!("mkfs: {e:?}"))?;
    }
    let mut cfg = StoreCfg::default();
    cfg.shard.cache_pages = num(a, "--cache-pages", 4096)? as usize;
    cfg.shard.dirty_soft_pages = cfg.shard.cache_pages / 8;
    cfg.shard.dirty_hard_pages = cfg.shard.cache_pages * 3 / 8;
    cfg.shard.ckpt_interval_ns = num(a, "--ckpt-ms", 5000)? * 1_000_000;
    cfg.shard.defrag = !flag(a, "--no-defrag");
    let d2 = disk.clone();
    let (mut st, _) = Store::mount(move || d2.queue(), MonoClock::default(), cfg)
        .map_err(|e| format!("mount: {e:?}"))?;
    for pg in 0..pgs {
        let mut t = OTxn::new();
        t.mkcoll(pgc(pg));
        t.touch(pgc(pg), &pgmeta(pg));
        st.commit(&t).map_err(|e| e.to_string())?;
    }
    let mut data = vec![0u8; size];
    crate::bench::fill_pattern(&mut data, 7);
    let mut b = Bench {
        st,
        pgs,
        data,
        log_seq: vec![0; pgs as usize],
        pgm: (0..pgs).map(pgmeta).collect(),
        live: Vec::new(),
        next_id: 0,
        tok: 0,
        inflight: HashMap::new(),
        acked: Vec::new(),
        ops: 0,
        bytes: 0,
        enospc: 0,
        max_queue_ns: 0,
        kq: [0; 4],
        max_lat_ns: 0,
        max_poll_ns: 0,
        bg: flag(a, "--bg"),
    };
    println!(
        "bench-full: dev {} MiB shards {shards} pgs {pgs} obj {} KiB fill {target}% qd {qd} mix {mix} bg {}",
        dev >> 20,
        size >> 10,
        b.bg
    );
    let mut rng = Rng::new(3);
    let mut ck0 = (0, 0);
    // fill
    let t0 = Instant::now();
    let mut last = Instant::now();
    while b.fill_pct() < target {
        while b.inflight.len() < qd {
            if !b.issue(Kind::New, &mut rng)? {
                break;
            }
        }
        b.poll()?;
        if b.enospc > 0 && b.inflight.is_empty() {
            break; // refused before reaching the target
        }
        if last.elapsed().as_secs_f64() >= 5.0 {
            let s = last.elapsed().as_secs_f64();
            b.line("fill", s, &mut ck0);
            last = Instant::now();
        }
    }
    while !b.inflight.is_empty() {
        b.poll()?;
    }
    b.line("filled", last.elapsed().as_secs_f64(), &mut ck0);
    println!("fill phase {:.1} s", t0.elapsed().as_secs_f64());
    // mixed load
    disk.set_xfer_ns(run_xfer);
    let run0 = Instant::now();
    let mut last = Instant::now();
    let mut sec = 0;
    let (mut tot_ops, mut tot_bytes, mut worst_q) = (0u64, 0u64, 0u64);
    while run0.elapsed().as_secs() < secs {
        while b.inflight.len() < qd {
            let mut r = rng.below(wsum);
            let kind = w
                .iter()
                .find(|x| {
                    if r < x.1 {
                        true
                    } else {
                        r -= x.1;
                        false
                    }
                })
                .unwrap()
                .0;
            if !b.issue(kind, &mut rng)? {
                break;
            }
        }
        b.poll()?;
        if last.elapsed().as_secs_f64() >= 1.0 {
            sec += 1;
            tot_ops += b.ops;
            tot_bytes += b.bytes;
            worst_q = worst_q.max(b.max_queue_ns);
            let s = last.elapsed().as_secs_f64();
            b.line(&format!("t{sec}"), s, &mut ck0);
            last = Instant::now();
        }
    }
    let el = run0.elapsed().as_secs_f64();
    println!(
        "total: {:.0} ops/s {:.1} MB/s worst queue {:.2} ms",
        tot_ops as f64 / el,
        tot_bytes as f64 / el / 1e6,
        worst_q as f64 / 1e6
    );
    if flag(a, "--trace") {
        let m = b.st.mem();
        println!("dead {} chains {}", m.tree.dead, m.tree.chains);
    }
    Ok(())
}
