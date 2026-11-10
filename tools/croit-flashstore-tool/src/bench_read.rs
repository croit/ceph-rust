// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `bench-read`: client-read cost through the store on a SIMULATED device with real-time latency (no hardware).
//!
//!   (`--rmw [--woff 100] [--wlen 64]`: writes of `[woff, woff+wlen)` to cold objects instead of reads, acked on durable;
//!   unaligned head / tail blocks are probed like opexec `Engine::cold` (read-modify-write); `--woff 0 --wlen 4096` = full block)
//!   croit-flashstore-tool bench-read [--size 4096|4194304] [--objs 2000] [--pgs 32] [--qd 16] [--secs 3] [--read-us 80] [--max-xfer LBAS] [--dev-qd N]
//!                           [--no-prefetch] [--crc none|pass|hint] [--clients C] [--jitter-us J] [--gate scan|fifo]|pass|hint]
//!
//! Emulates the OSD core loop for read ops (opexec `cold` gate): per PG a FIFO gate; the front op is probed with
//! `Store::warm` (+ `Store::warm_data` unless `--no-prefetch`), parked while loads are in flight, run on wake.
//! `--clients C` multiplies `--qd` (C clients of QD each, all outstanding at once: many-client load); `--jitter-us`
//! widens the device latency spread (slow tail); `--gate fifo` = old retry (only the front op of a PG gate is probed,
//! one slow op holds the rest), `scan` (default) = opexec `retry` (probe the gate in order, per-object order kept).
//! Without prefetch the data read blocks the core in the device wait (the pre-ADR 0043 behaviour). `--crc` emulates the
//! transport's data crc: `pass` = a crc32c pass over the payload (old), `hint` = the store-derived value (new),
//! `none` = nothing. Reports IOPS, MB/s and busy ns/op (wall time of loop iterations that did work; a blocking
//! read counts as busy = CPU lost).
use crate::bench::{fill_pattern, obj, pgc, pgmeta, pgs_arg};
use crate::{arg, flag, fnum, num, num_opt};
use denc::types::Ghobject;
use std::collections::VecDeque;
use std::time::Instant;
use store::dev::{MonoClock, SimClock, SimConfig, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, Store, StoreCfg, TOp};
use store::rng::Rng;

pub fn run(a: &[String]) -> i32 {
    match inner(a) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("bench-read: {e}");
            1
        }
    }
}

struct Op {
    pg: u32,
    o: Ghobject,
    idx: u64,
    t0: u64,
    cl: usize,
}

fn inner(a: &[String]) -> Result<(), String> {
    let size = num(a, "--size", 4096)? as usize;
    let objs = num(a, "--objs", 2000)?;
    let pgs = pgs_arg(a)?;
    let qd = num(a, "--qd", 16)? as usize;
    if qd == 0 {
        return Err("--qd 0: no read is ever in flight".into());
    }
    let ncl = num(a, "--clients", 1)? as usize;
    if ncl == 0 {
        return Err("--clients 0: no client issues a read".into());
    }
    let per_cl = qd;
    let qd = qd * ncl;
    let scan = arg(a, "--gate").as_deref() != Some("fifo");
    let secs = fnum(a, "--secs", 3.0)?;
    let prefetch = !flag(a, "--no-prefetch");
    let rmw = flag(a, "--rmw");
    let (woff, wlen) = (num(a, "--woff", 100)?, num(a, "--wlen", 64)?.max(1));
    let wbuf = vec![0xABu8; wlen as usize];
    // the boundary blocks a write of [woff, woff+wlen) reads first (opexec `Engine::cold`)
    let wend = woff + wlen;
    let rmw_head = woff % 4096 != 0;
    let rmw_tail = wend % 4096 != 0 && !(rmw_head && (wend - 1) / 4096 == woff / 4096);
    let crc_mode = arg(a, "--crc").unwrap_or_else(|| "pass".into());
    let crc_mode = crc_mode.as_str();
    let mut sim =
        SimConfig::new(((objs * size as u64 * 2) + (512 << 20)).next_multiple_of(1 << 20));
    sim.read_ns = num(a, "--read-us", 80)? * 1000;
    sim.max_xfer_lbas =
        num(a, "--max-xfer", u64::from(sim.max_xfer_lbas))?.min(u64::from(u32::MAX)) as u32;
    sim.queue_depth = num(a, "--dev-qd", sim.queue_depth as u64)? as usize;
    sim.jitter_ns = match num_opt(a, "--jitter-us")? {
        Some(j) => j * 1000,
        None => sim.read_ns / 10,
    };
    let disk = SimDisk::new(sim.clone());
    {
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let p = MkfsParams {
            shards: 4,
            wal_blocks: 4096,
            align_blocks: 1,
            meta_pct: 8,
            node_size: 8192,
            ..Default::default()
        };
        mkfs(&mut dev, &mut clk, &p).map_err(|e| format!("mkfs: {e:?}"))?;
    }
    let d2 = disk.clone();
    let (mut st, _) = Store::mount(
        move || d2.queue(),
        MonoClock::default(),
        StoreCfg::default(),
    )
    .map_err(|e| format!("mount: {e:?}"))?;
    for pg in 0..pgs {
        let mut t = OTxn::new();
        t.push(TOp::MkColl {
            cid: pgc(pg),
            bits: 0,
            exist_ok: true,
        });
        t.touch(pgc(pg), &pgmeta(pg));
        st.commit(&t).map_err(|e| e.to_string())?;
    }
    let mut data = vec![0u8; size];
    fill_pattern(&mut data, 7);
    let name = |i: u64| format!("rbd_data.{:016x}", i.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    for i in 0..objs {
        let pg = (i % pgs as u64) as u32;
        data[..8].copy_from_slice(&i.to_le_bytes());
        let mut t = OTxn::new();
        t.write(pgc(pg), &obj(&name(i), pg), 0, &data);
        st.commit(&t).map_err(|e| e.to_string())?;
    }
    st.checkpoint().map_err(|e| e.to_string())?;

    let mut rng = Rng::new(3);
    let mut gates: Vec<VecDeque<Op>> = (0..pgs).map(|_| VecDeque::new()).collect();
    let (mut inflight, mut done, mut busy) = (0usize, 0u64, 0u64);
    let mut lat: Vec<u32> = Vec::new();
    let mut cl_in = vec![0usize; ncl];
    let mut cl_done = vec![0u64; ncl];
    let mut cl_max = vec![0u32; ncl];
    let mut acked = Vec::new();
    let mut pend: std::collections::HashMap<u64, (usize, u64)> = Default::default();
    let mut next_tok = 1u64;
    let t0 = Instant::now();
    let limit = (secs * 1e9) as u64;
    let mut woke = true;
    loop {
        let it = Instant::now();
        let now = t0.elapsed().as_nanos() as u64;
        let stop = now >= limit;
        let mut work = false;
        if !stop {
            while let Some(cl) = (0..ncl).find(|&c| cl_in[c] < per_cl) {
                cl_in[cl] += 1;
                let idx = rng.below(objs);
                let pg = (idx % pgs as u64) as u32;
                gates[pg as usize].push_back(Op {
                    pg,
                    o: obj(&name(idx), pg),
                    idx,
                    t0: now,
                    cl,
                });
                inflight += 1;
                woke = true;
                work = true;
            }
        }
        if woke {
            woke = false;
            for g in gates.iter_mut() {
                let mut i = 0;
                while i < g.len() && (scan || i == 0) && i < 64 {
                    let f = &g[i];
                    let c = pgc(f.pg);
                    let (poff, plen) = if rmw { (woff, wlen) } else { (0, size as u64) };
                    let mut ready = st.warm(&c, &f.o, poff, plen).map_err(|e| e.to_string())?;
                    if ready && prefetch && !rmw {
                        ready = st
                            .warm_data(&c, &f.o, poff, plen)
                            .map_err(|e| e.to_string())?;
                    } else if ready && prefetch {
                        // both boundary probes in one pass (no short circuit)
                        let h = !rmw_head
                            || st.warm_data(&c, &f.o, woff, 1).map_err(|e| e.to_string())?;
                        let t = !rmw_tail
                            || st
                                .warm_data(&c, &f.o, wend - 1, 1)
                                .map_err(|e| e.to_string())?;
                        ready = h && t;
                    }
                    // scan: a cold op and later ops of the same object stay, the rest runs; fifo: stop at the cold front
                    if !ready || (i > 0 && g.iter().take(i).any(|p| p.idx == f.idx)) {
                        if !scan {
                            break;
                        }
                        i += 1;
                        continue;
                    }
                    let f = g.remove(i).unwrap();
                    if rmw {
                        let mut t = OTxn::new();
                        t.write(pgc(f.pg), &f.o, woff, &wbuf);
                        let tok = next_tok;
                        next_tok += 1;
                        st.queue(&t, tok).map_err(|e| e.to_string())?;
                        pend.insert(tok, (f.cl, f.t0));
                        work = true;
                        continue;
                    }
                    let (r, hint) = st
                        .read_crc(&pgc(f.pg), &f.o, 0, size as u64)
                        .map_err(|e| format!("read: {e}"))?;
                    // what the msgr2 tx does with the payload: its own crc pass, or the store-derived value
                    let tx_crc = match (crc_mode, hint) {
                        ("hint", Some(c)) => c,
                        ("none", _) => 0,
                        _ => crc::crc32c(!0, &r),
                    };
                    std::hint::black_box(tx_crc);
                    if r.len() != size || r[..8] != f.idx.to_le_bytes() {
                        return Err("read content mismatch".into());
                    }
                    let l = ((t0.elapsed().as_nanos() as u64 - f.t0) / 1000) as u32;
                    lat.push(l);
                    cl_in[f.cl] -= 1;
                    cl_done[f.cl] += 1;
                    cl_max[f.cl] = cl_max[f.cl].max(l);
                    done += 1;
                    inflight -= 1;
                    work = true;
                }
            }
        }
        acked.clear();
        st.poll(&mut acked).map_err(|e| e.to_string())?;
        for tok in acked.drain(..) {
            if let Some((cl, ot0)) = pend.remove(&tok) {
                let l = ((t0.elapsed().as_nanos() as u64 - ot0) / 1000) as u32;
                lat.push(l);
                cl_in[cl] -= 1;
                cl_done[cl] += 1;
                cl_max[cl] = cl_max[cl].max(l);
                done += 1;
                inflight -= 1;
                work = true;
            }
        }
        if st.take_wake() {
            woke = true;
            work = true;
        }
        if work {
            busy += it.elapsed().as_nanos() as u64;
        }
        if stop && inflight == 0 {
            break;
        }
    }
    let wall = t0.elapsed().as_secs_f64();
    lat.sort_unstable();
    let p = |q: f64| {
        lat.get(((lat.len() as f64) * q) as usize)
            .copied()
            .unwrap_or(0)
    };
    println!(
        "bench-read {}size={size} qd={qd} pgs={pgs} gate={} read_us={} prefetch={prefetch} tx-crc={crc_mode}: {:.0} IOPS {:.0} MB/s, busy {:.1} us/op ({:.0}% of wall), lat p50 {} p99 {} p999 {} us",
        if rmw { "rmw " } else { "" },
        if scan { "scan" } else { "fifo" },
        sim.read_ns / 1000,
        done as f64 / wall,
        done as f64 * size as f64 / wall / 1e6,
        busy as f64 / done.max(1) as f64 / 1000.0,
        100.0 * busy as f64 / (wall * 1e9),
        p(0.5),
        p(0.99),
        p(0.999),
    );
    let (mn, mx) = (cl_done.iter().min().unwrap(), cl_done.iter().max().unwrap());
    println!(
        "  clients={ncl}: ops/client min {mn} max {mx} (fairness {:.2}), max lat {} us, per-client max lat us {:?}",
        *mn as f64 / (*mx).max(1) as f64,
        lat.last().copied().unwrap_or(0),
        cl_max,
    );
    Ok(())
}
