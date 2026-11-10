// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `bench-purge`: 4k write cost before / after mass deletes (adr 0021 am. 29), store level on a SIMULATED device.
//!
//!   croit-flashstore-tool bench-purge [--objs 500000] [--pgs 128] [--shards 8] [--cycles 3] [--qd 64] [--cache-pages 2048]
//!                            [--del list|rand|pg] [--park] [--park-log] [--no-compact] [--no-defrag] [--nolog] [--prefill N] [--omap] [--omap-tail N] [--dirty-soft P] [--dirty-hard P] [--wal-blocks N] [--ckpt-slice N] [--tail-now] [--keep-pg] [--size 4096] [--log 500] [--keep PCT] [--defrag-wait SECS]
//!
//! Cycle = write N new objects (OSD-like txn: data + `_`/snapset attrs + pg-log omap set/trim on the pgmeta object),
//! checkpoint, delete them all (`--del list` = PG by PG in name-index order like a `rados cleanup` listing, `rand` =
//! random order, `pg` = whole PGs in 64-object txns like `step_removals`), checkpoint, let the lazy free drain.
//! After every phase: ops/s, busy us/op (wall of loop iterations with work), tree page loads/op, blocking miss waits
//! (`dbg::MISS_*`), durable tree shape (fsck: height, leaves, empty leaves, fill), free-space fragmentation, dead list,
//! delta chains. `--keep PCT` leaves PCT percent of the objects of a cycle undeleted (sparse remains).
//! `--park` probes the object with `Store::warm` before queueing (the OSD gate); the pgmeta pages are probed only with
//! `--park-log` (`Store::warm_omap` of the log keys the txn appends and trims, adr 0021 am. 30).
use crate::bench::{pgc, pgmeta, pgs_arg};
use crate::{arg, flag, num, num_opt};
use denc::types::{Ghobject, Hobject, ShardId, SnapId};
use std::collections::VecDeque;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;
use store::dev::{MonoClock, SimClock, SimConfig, SimDisk};
use store::fsck::fsck;
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, Store, StoreCfg};
use store::rng::Rng;

type St = Store<store::dev::SimDev, MonoClock>;

/// Mkfs node size of this bench: also the page size the tree fill percentage is computed with.
const NODE_SIZE: u32 = 8192;

pub fn run(a: &[String]) -> i32 {
    match inner(a) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("bench-purge: {e}");
            1
        }
    }
}

pub(crate) fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

struct Obj {
    pg: u32,
    o: Ghobject,
    hash: u32,
}

fn make_obj(cyc: u64, i: u64, pgs: u32) -> Obj {
    let h = mix(i ^ (cyc << 40)) as u32;
    let name = format!("benchmark_data_host01_{}_object{i}", 1000 + cyc);
    let pg = h & (pgs - 1);
    Obj {
        pg,
        o: Ghobject::new(
            Hobject::new(name.as_bytes(), SnapId(0), h, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        ),
        hash: h,
    }
}

struct Env {
    data: Vec<u8>,
    log_seq: Vec<u64>,
    pgm: Vec<Ghobject>,
    log_len: u64,
    park: bool,
    /// `--park-log`: the gate also probes the pgmeta log keys of the txn (append key + trimmed key).
    park_log: bool,
    /// No pgmeta log ops in the txns (what a deferred pg log would leave: adr 0021 am. 28 review of the pgmeta branch).
    nolog: bool,
    /// `--omap`: the write txn is `rados bench --omap` (one 4 KiB omap value on a new object, no data write).
    omap: bool,
    /// Omap value bytes of an omap txn (`--omap-size`, default `--size`).
    omap_len: usize,
}

fn log_key(n: u64) -> Vec<u8> {
    format!("pglog.0.{n:016}").into_bytes()
}

struct Phase {
    ops: u64,
    wall: f64,
    busy_ns: u64,
    loads: u64,
    miss_calls: u64,
    miss_ns: u64,
    dw: u64,
    dwl: u64,
    dr: u64,
    splits: u64,
    evict: u64,
    dent: u64,
    dpg: u64,
    dfold: u64,
    merged: u64,
    /// Acks per 100 ms of the phase (stop-go detector).
    buckets: Vec<u32>,
    /// Per-job latency (first admission attempt to ack, gate wait included), sorted, ns.
    lat: Vec<u64>,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Write,
    Del,
}

/// Run `ops` (object, kind) at queue depth `qd`; `batch` > 1 packs that many removes of one PG into one txn.
fn drive(
    st: &mut St,
    disk: &SimDisk,
    env: &mut Env,
    ops: &[(usize, Kind)],
    objs: &[Obj],
    qd: usize,
    batch: usize,
) -> Result<Phase, String> {
    let l0 = st.tree_stats().loads;
    let (d0, t0s) = (disk.stats(), st.tree_stats());
    let (mc0, mn0) = (
        store::dbg::MISS_CALLS.load(Relaxed),
        store::dbg::MISS_NS.load(Relaxed),
    );
    let jobs = jobs_of(ops, objs, batch);
    let mut first_ns = vec![0u64; jobs.len()]; // per job: first admission attempt
    let mut tok_job: Vec<u32> = Vec::new(); // token - 1 -> job
    let mut lat: Vec<u64> = Vec::with_capacity(jobs.len());
    let mut gate: VecDeque<usize> = VecDeque::new(); // job indices waiting (cold)
    let mut next = 0usize;
    let (mut inflight, mut done) = (0usize, 0u64);
    let mut acked = Vec::new();
    let mut busy = 0u64;
    let mut woke = true;
    let mut adm_blocked = false;
    let t0 = Instant::now();
    let mut tok = 1u64;
    let mut buckets: Vec<u32> = Vec::new();
    // `NV_TRACE=ms`: a line per interval (acks, dirty pages, checkpoint begins/ends, refusals, parked txns, gate)
    let trace_ns = std::env::var("NV_TRACE")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|ms| ms * 1_000_000);
    let (mut tr_next, mut tr_acks, mut tr0) = (trace_ns.unwrap_or(0), 0u64, trace_snap(st));
    while next < jobs.len() || !gate.is_empty() || inflight > 0 {
        let it = Instant::now();
        let mut work = false;
        // admit: on a store wake every parked job is probed once (arrival order), then new ones
        let mut retry = if woke { gate.len() } else { 0 };
        woke = false;
        while (next < jobs.len() || retry > 0) && inflight < qd {
            let j = if retry > 0 {
                retry -= 1;
                gate.pop_front().unwrap()
            } else if next < jobs.len() && gate.len() < 4 * qd {
                // bounded gate: new jobs wait while it is full (before, one job per poll got in beyond the bound, the
                // gate grew without limit and the pages of thousands of parked jobs evicted each other)
                first_ns[next] = t0.elapsed().as_nanos() as u64;
                next += 1;
                next - 1
            } else {
                break;
            };
            let (idx, end) = jobs[j];
            let (oi, kind) = ops[idx];
            let ob = &objs[oi];
            let c = pgc(ob.pg);
            if env.park {
                let mut ready = if kind == Kind::Write {
                    st.warm(&c, &ob.o, 0, env.data.len() as u64)
                        .map_err(|e| e.to_string())?
                } else {
                    // removal gate (adr 0021 am. 33): every page of every object of the job, probed in one pass
                    let mut r = true;
                    for &(oj, _) in &ops[idx..end] {
                        r &= st
                            .warm_rm(&pgc(objs[oj].pg), &objs[oj].o)
                            .map_err(|e| e.to_string())?;
                    }
                    r
                };
                if env.park_log && !env.nolog {
                    let n = env.log_seq[ob.pg as usize] + 1;
                    let (kn, ko) = (log_key(n), log_key(n.saturating_sub(env.log_len)));
                    let keys: [&[u8]; 2] = [&kn, &ko];
                    ready &= st
                        .warm_omap(&c, &env.pgm[ob.pg as usize], &keys)
                        .map_err(|e| e.to_string())?;
                }
                if !ready {
                    gate.push_back(j);
                    work = true;
                    if gate.len() > 4 * qd {
                        break;
                    }
                    continue;
                }
            }
            if !st.admission_ready_for(&c) {
                // the OSD holds the input while the shard FIFO is full (admission), it does not fail
                adm_blocked = true;
                gate.push_back(j);
                work = true;
                if gate.len() > 4 * qd {
                    break;
                }
                continue;
            }
            let seq = &mut env.log_seq[ob.pg as usize];
            *seq += 1;
            let (kn, ko) = (log_key(*seq), log_key(seq.saturating_sub(env.log_len)));
            let mut t = OTxn::new();
            let attr1 = &env.data[..250];
            let attr2 = &env.data[250..282];
            let lv = &env.data[256..436];
            match kind {
                Kind::Write => {
                    if env.omap {
                        t.touch(c, &ob.o);
                        t.omap_set(c, &ob.o, b"bench-omap-key-0", &env.data[..env.omap_len]);
                    } else {
                        t.write(c, &ob.o, 0, &env.data);
                    }
                    t.setattr(c, &ob.o, b"_", attr1);
                    t.setattr(c, &ob.o, b"snapset", attr2);
                }
                Kind::Del => {
                    for &(oj, _) in &ops[idx..end] {
                        t.remove(c, &objs[oj].o);
                    }
                }
            }
            if !env.nolog {
                t.omap_set(c, &env.pgm[ob.pg as usize], &kn, lv);
            }
            if *seq > env.log_len && !env.nolog {
                t.push(store::obj::TOp::OmapRmKeys {
                    cid: c,
                    oid: env.pgm[ob.pg as usize].clone(),
                    keys: vec![ko.as_slice().into()],
                });
            }
            st.queue(&t, tok).map_err(|e| format!("queue: {e}"))?;
            tok_job.push(j as u32);
            tok += 1;
            inflight += 1;
            done += (end - idx) as u64;
            work = true;
        }
        if let Some(tn) = trace_ns {
            let now = t0.elapsed().as_nanos() as u64;
            if now >= tr_next {
                tr_next = now + tn;
                let s = trace_snap(st);
                println!(
                    "  trace t={:>6}ms acks {:>6} dirty {:>6} (max shard {:>5}) freeze_left {:>5} ckpt b/e +{}/+{} busy +{} parked {} gate {} infl {} rq {:?} busy_why {:?} diag max/avg us: {}",
                    now / 1_000_000,
                    done - tr_acks,
                    s[0],
                    s[1],
                    s[2],
                    s[3] - tr0[3],
                    s[4] - tr0[4],
                    s[5] - tr0[5],
                    s[6],
                    gate.len(),
                    inflight,
                    store::dbg::RQ
                        .iter()
                        .map(|x| x.swap(0, Relaxed))
                        .collect::<Vec<_>>(),
                    store::dbg::BUSY
                        .iter()
                        .map(|x| x.swap(0, Relaxed))
                        .collect::<Vec<_>>(),
                    store::diag::take_all()
                );
                if std::env::var_os("NV_TRACE_DIAG").is_some() {
                    println!("    {}", st.diag());
                }
                tr_acks = done;
                tr0 = s;
            }
        }
        acked.clear();
        st.poll(&mut acked).map_err(|e| format!("poll: {e}"))?;
        if !acked.is_empty() && adm_blocked {
            adm_blocked = false;
            woke = true;
        }
        if !acked.is_empty() {
            let b = (t0.elapsed().as_millis() / 100) as usize;
            if buckets.len() <= b {
                buckets.resize(b + 1, 0);
            }
            buckets[b] += acked.len() as u32;
            let now = t0.elapsed().as_nanos() as u64;
            for t in &acked {
                lat.push(now - first_ns[tok_job[*t as usize - 1] as usize]);
            }
            inflight -= acked.len();
            work = true;
        }
        if st.take_wake() {
            woke = true;
            work = true;
        }
        if inflight == 0 && !gate.is_empty() && !st.loads_pending() {
            woke = true;
        }
        if work {
            busy += it.elapsed().as_nanos() as u64;
        }
    }
    let l1 = st.tree_stats().loads;
    let (d1, t1s) = (disk.stats(), st.tree_stats());
    Ok(Phase {
        ops: done,
        wall: t0.elapsed().as_secs_f64(),
        busy_ns: busy,
        loads: l1 - l0,
        miss_calls: store::dbg::MISS_CALLS.load(Relaxed) - mc0,
        miss_ns: store::dbg::MISS_NS.load(Relaxed) - mn0,
        dw: d1.writes - d0.writes,
        dwl: d1.write_lbas - d0.write_lbas,
        dr: d1.reads - d0.reads,
        splits: t1s.splits - t0s.splits,
        evict: t1s.evictions - t0s.evictions,
        dent: t1s.delta_entries - t0s.delta_entries,
        dpg: t1s.delta_pages - t0s.delta_pages,
        dfold: t1s.delta_folded - t0s.delta_folded,
        merged: t1s.merged - t0s.merged,
        buckets,
        lat: {
            lat.sort_unstable();
            lat
        },
    })
}

/// Upper bound of the lazy-free / compaction drain after a phase (a store that does not drain stays measurable, but the
/// phase numbers are then of a store still freeing pages).
const SETTLE_MAX_S: u64 = 120;

fn settle(st: &mut St) -> Result<(), String> {
    st.checkpoint().map_err(|e| e.to_string())?;
    // lazy free drain and background compaction (adr 0021 am. 33): poll the idle store until both are done (bounded)
    let t0 = Instant::now();
    let mut acked = Vec::new();
    let pending = |st: &St| {
        st.shards
            .iter()
            .map(|s| s.sh.state().tree.compact_pending())
            .sum::<usize>()
    };
    while (st.mem().tree.dead > 0 || pending(st) > 0) && t0.elapsed().as_secs() < SETTLE_MAX_S {
        st.poll(&mut acked).map_err(|e| e.to_string())?;
        st.idle();
    }
    if st.mem().tree.dead > 0 || pending(st) > 0 {
        eprintln!(
            "WARNING TIMEOUT settle exceeded {SETTLE_MAX_S}s (dead {} compact_pending {})",
            st.mem().tree.dead,
            pending(st)
        );
    }
    let c: u64 = st.shards.iter().map(|s| s.sh.tree_stats().compacted).sum();
    if c > 0 {
        println!(
            "                settle: background merges {c} total, {:.1} s",
            t0.elapsed().as_secs_f64()
        );
    }
    st.checkpoint().map_err(|e| e.to_string())
}

fn report(tag: &str, p: &Phase) {
    println!(
        "{tag:<14} {:>9} ops {:>8.0} ops/s  busy {:>6.1} us/op  loads/op {:>5.2}  miss_wait {:>6.3}/op {:>6.2} us/op",
        p.ops,
        p.ops as f64 / p.wall,
        p.busy_ns as f64 / p.ops.max(1) as f64 / 1000.0,
        p.loads as f64 / p.ops.max(1) as f64,
        p.miss_calls as f64 / p.ops.max(1) as f64,
        p.miss_ns as f64 / p.ops.max(1) as f64 / 1000.0,
    );
    if !p.lat.is_empty() {
        let q = |f: f64| p.lat[((p.lat.len() - 1) as f64 * f) as usize] as f64 / 1000.0;
        println!(
            "                latency us: p50 {:.0} p99 {:.0} p99.9 {:.0} p99.99 {:.0} max {:.0}",
            q(0.5),
            q(0.99),
            q(0.999),
            q(0.9999),
            q(1.0)
        );
    }
    {
        let bk = &p.buckets[..p.buckets.len().saturating_sub(1)];
        if bk.len() > 4 {
            let mut s = bk.to_vec();
            s.sort_unstable();
            let med = s[s.len() / 2];
            let slow = bk.iter().filter(|&&x| x * 4 < med).count();
            let (mut run, mut worst) = (0, 0);
            for &x in bk {
                run = if x == 0 { run + 1 } else { 0 };
                worst = worst.max(run);
            }
            println!(
                "                stop-go: acks/100ms median {med} min {} max {}; {slow} of {} buckets < 25% of median; longest zero-ack run {} ms",
                s[0],
                s[s.len() - 1],
                bk.len(),
                worst * 100
            );
        }
    }
    let mut tags = String::new();
    for (t, c) in store::dbg::MISS_TAG.iter().enumerate() {
        let c = c.swap(0, Relaxed);
        if c > 0 {
            tags += &format!(
                " {}:{:.3}",
                if t > 32 {
                    (t as u8 as char).to_string()
                } else {
                    "put".into()
                },
                c as f64 / p.ops.max(1) as f64
            );
        }
    }
    let mut pm = String::new();
    for (t, c) in store::dbg::PREP_MISS.iter().enumerate() {
        let c = c.swap(0, Relaxed);
        if c > 0 {
            pm += &format!(" {}:{:.3}", t as u8 as char, c as f64 / p.ops.max(1) as f64);
        }
    }
    {
        let (sc, it) = (
            store::dbg::PARK_SCANS.swap(0, Relaxed),
            store::dbg::PARK_ITEMS.swap(0, Relaxed),
        );
        println!(
            "                parked_on probes {:.2}/op, avg parked scanned {:.1}",
            sc as f64 / p.ops.max(1) as f64,
            it as f64 / sc.max(1) as f64
        );
    }
    {
        let w: Vec<String> = (0..4)
            .map(|r| {
                format!(
                    "{}:{}",
                    ["prep", "submit", "behind-parked", "large"][r],
                    store::dbg::PARK_WHY[r].swap(0, Relaxed)
                )
            })
            .collect();
        println!("                queue parked-why (counts): {}", w.join(" "));
    }
    {
        let b: Vec<String> = (1..10)
            .filter_map(|r| {
                let c = store::dbg::BUSY[r].swap(0, Relaxed);
                (c > 0).then(|| format!("{r}:{c}"))
            })
            .collect();
        println!(
            "                Shard::validate Busy count by reason (1 dead 2 dirty-hard 3 meta 4 backlog 5 devq 6 ready-units 7 wal-ring): {}",
            b.join(" ")
        );
    }
    println!("                prepare misses/op by key tag:{pm}");
    println!("                miss waits/op by origin:{tags}");
    let o = p.ops.max(1) as f64;
    println!(
        "                dev wr {:.2}/op ({:.2} lba/op) rd {:.2}/op | splits {:.3}/op evict {:.2}/op | delta ent {:.2}/op pg {:.3}/op folded {:.3}/op merged {}",
        p.dw as f64 / o,
        p.dwl as f64 / o,
        p.dr as f64 / o,
        p.splits as f64 / o,
        p.evict as f64 / o,
        p.dent as f64 / o,
        p.dpg as f64 / o,
        p.dfold as f64 / o,
        p.merged
    );
}

fn shape(tag: &str, st: &mut St, disk: &SimDisk) -> Result<(), String> {
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let reps = fsck(&mut dev, &mut clk, None)?;
    let (mut leaves, mut interior, mut empty, mut keys, mut kvb, mut dpg, mut dlv, mut dead) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut h = 0u8;
    for r in &reps {
        leaves += r.leaves;
        interior += r.interior;
        empty += r.empty_leaves;
        keys += r.keys;
        kvb += r.kv_bytes;
        dpg += r.delta_pages;
        dlv += r.delta_leaves;
        dead += r.dead_pages;
        h = h.max(r.height);
    }
    let mut tl: std::collections::BTreeMap<u8, (u64, u64)> = Default::default();
    for r in &reps {
        for (t, v) in &r.tag_leaves {
            let e = tl.entry(*t).or_default();
            e.0 += v.0;
            e.1 += v.1;
        }
    }
    let tls: String = tl
        .iter()
        .map(|(t, v)| format!(" {}:{}lv/{}k", *t as char, v.0, v.1))
        .collect();
    println!("                leaves/keys by tag:{tls}");
    let fe = st.free_extents();
    let fb: u64 = fe.iter().map(|e| e.1).sum();
    let big = fe.iter().map(|e| e.1).max().unwrap_or(0);
    let m = st.mem();
    println!(
        "  {tag:<12} tree: h {h} leaves {leaves} (empty {empty}) int {interior} keys {keys}  fill {:.0}%  keys/leaf {:.1} | delta pg {dpg} leaves {dlv} | dead pg {dead} (ram {}) chains {} | free {} blk in {} extents (max {big}, 1-blk {}, 1 MiB runs {})",
        100.0 * kvb as f64 / (leaves.max(1) * u64::from(NODE_SIZE)) as f64,
        keys as f64 / leaves.max(1) as f64,
        m.tree.dead,
        m.tree.chains,
        fb,
        fe.len(),
        fe.iter().filter(|e| e.1 == 1).count(),
        fe.iter().map(|e| e.1 / 256).sum::<u64>(),
    );
    Ok(())
}

fn inner(a: &[String]) -> Result<(), String> {
    if std::env::var_os("NV_TRACE").is_some() {
        store::diag::enable();
    }
    let n = num(a, "--objs", 500_000)?;
    let pgs = pgs_arg(a)?
        .checked_next_power_of_two()
        .ok_or("--pgs: no power of two fits")?;
    let shards = num(a, "--shards", 8)? as u32;
    let cycles = num(a, "--cycles", 3)?;
    let qd = num(a, "--qd", 64)? as usize;
    if qd == 0 {
        return Err("--qd 0: no op is ever in flight (the phases would never end)".into());
    }
    let size = num(a, "--size", 4096)? as usize;
    let keep = num(a, "--keep", 0)?;
    let defrag_wait = num(a, "--defrag-wait", 0)?;
    let del = arg(a, "--del").unwrap_or_else(|| "list".into());
    let tail_n = num(a, "--omap-tail", 0)?; // the omap tail comes on top of the last fill (cycles free their space)
    let nc = n + tail_n;
    let cap = ((n * size as u64 * 2 + nc * 4096 * 3 + tail_n * 24576)
        + (1 << 30)
        + u64::from(shards) * num(a, "--wal-blocks", 16384)? * 4096)
        .next_multiple_of(1 << 20);
    let mut sim = SimConfig::new(cap);
    sim.jitter_ns = 2000;
    let disk = SimDisk::new(sim.clone());
    disk.reserve_media((cap / 4096) as usize);
    {
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let p = MkfsParams {
            shards,
            wal_blocks: num(a, "--wal-blocks", 16384)?,
            align_blocks: 1,
            meta_pct: if flag(a, "--omap") || num(a, "--omap-tail", 0)? > 0 {
                45
            } else {
                10
            },
            node_size: NODE_SIZE,
            ..Default::default()
        };
        mkfs(&mut dev, &mut clk, &p).map_err(|e| format!("mkfs: {e:?}"))?;
    }
    let mut cfg = StoreCfg::default();
    cfg.shard.cache_pages = num(a, "--cache-pages", 2048)? as usize;
    cfg.shard.dirty_soft_pages = cfg.shard.cache_pages / 8;
    cfg.shard.dirty_hard_pages = cfg.shard.cache_pages * 3 / 8;
    if let Some(v) = num_opt(a, "--dirty-soft")? {
        cfg.shard.dirty_soft_pages = v as usize;
    }
    if let Some(v) = num_opt(a, "--dirty-hard")? {
        cfg.shard.dirty_hard_pages = v as usize;
    }
    if let Some(v) = num_opt(a, "--ckpt-slice")? {
        cfg.shard.ckpt_slice = v as usize;
    }
    if let Some(v) = num_opt(a, "--ckpt-fz-polls")? {
        cfg.shard.ckpt_fz_polls = v as usize;
    }
    if let Some(v) = num_opt(a, "--park-lookahead")? {
        cfg.shard.park_lookahead = v as usize;
    }
    cfg.shard.bg_compact = !flag(a, "--no-compact");
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
    let mut data = vec![0u8; size.max(512)];
    crate::bench::fill_pattern(&mut data, 5);
    data.truncate(size.max(512));
    let mut env = Env {
        data,
        log_seq: vec![0; pgs as usize],
        pgm: (0..pgs).map(pgmeta).collect(),
        log_len: num(a, "--log", 500)?,
        park: flag(a, "--park"),
        park_log: flag(a, "--park-log"),
        nolog: flag(a, "--nolog"),
        omap: flag(a, "--omap"),
        omap_len: (num(a, "--omap-size", size as u64)? as usize).min(size.max(512)),
    };
    // warm-up: fill every PG log, then slide it 2 x log_len single-key set + trim txns (leaf layout of a log that has
    // been sliding for a while, as after hours of load)
    for pg in 0..pgs {
        let lv = vec![7u8; 180];
        for n in 1..=3 * env.log_len {
            let (kn, ko) = (log_key(n), log_key(n.saturating_sub(env.log_len)));
            let mut t = OTxn::new();
            t.omap_set(pgc(pg), &env.pgm[pg as usize], &kn, &lv);
            if n > env.log_len {
                t.push(store::obj::TOp::OmapRmKeys {
                    cid: pgc(pg),
                    oid: env.pgm[pg as usize].clone(),
                    keys: vec![ko.as_slice().into()],
                });
            }
            st.commit(&t).map_err(|e| e.to_string())?;
        }
        env.log_seq[pg as usize] = 3 * env.log_len;
    }
    settle(&mut st)?;
    println!(
        "bench-purge: objs {n} pgs {pgs} shards {shards} qd {qd} cache {} pages/shard del {del} keep {keep}% park {}",
        num(a, "--cache-pages", 2048)?,
        env.park
    );
    let mut rng = Rng::new(11);
    // `--prefill N`: N objects that stay (the live set a purge leaves behind), written densely before cycle 0
    let pre = num(a, "--prefill", 0)?;
    if pre > 0 {
        let objs: Vec<Obj> = (0..pre).map(|i| make_obj(999, i, pgs)).collect();
        let ops: Vec<(usize, Kind)> = (0..objs.len()).map(|i| (i, Kind::Write)).collect();
        let p = drive(&mut st, &disk, &mut env, &ops, &objs, qd, 1)?;
        report("prefill", &p);
        settle(&mut st)?;
    }
    let tail = num(a, "--omap-tail", 0)?;
    for cyc in 0..cycles {
        let objs: Vec<Obj> = (0..n).map(|i| make_obj(cyc, i, pgs)).collect();
        // write in creation order (rados bench names are sequential, hash random)
        let ops: Vec<(usize, Kind)> = (0..objs.len()).map(|i| (i, Kind::Write)).collect();
        let p = drive(&mut st, &disk, &mut env, &ops, &objs, qd, 1)?;
        report(&format!("c{cyc} write"), &p);
        settle(&mut st)?;
        shape(&format!("c{cyc} full"), &mut st, &disk)?;
        // delete order
        let by_pg = flag(a, "--keep-pg");
        let mut idx: Vec<usize> = (0..objs.len())
            .filter(|&i| {
                if by_pg {
                    u64::from(objs[i].pg) * 100 / u64::from(pgs) >= keep
                } else {
                    rng.below(100) >= keep
                }
            })
            .collect();
        let batch = match del.as_str() {
            "rand" => {
                for i in (1..idx.len()).rev() {
                    idx.swap(i, rng.below(i as u64 + 1) as usize);
                }
                1
            }
            "pg" => {
                idx.sort_by_key(|&i| (objs[i].pg, objs[i].hash.reverse_bits()));
                64
            }
            _ => {
                idx.sort_by_key(|&i| (objs[i].pg, objs[i].hash.reverse_bits()));
                1
            }
        };
        let ops: Vec<(usize, Kind)> = idx.into_iter().map(|i| (i, Kind::Del)).collect();
        let p = drive(&mut st, &disk, &mut env, &ops, &objs, qd, batch)?;
        report(&format!("c{cyc} delete"), &p);
        if !flag(a, "--tail-now") {
            settle(&mut st)?;
            shape(&format!("c{cyc} deleted"), &mut st, &disk)?;
        }
        if defrag_wait > 0 {
            // idle store: let the free-space defrag (adr 0021 am. 33) run its sweeps, then report the shape again
            let t0 = Instant::now();
            let mut acked = Vec::new();
            while t0.elapsed().as_secs() < defrag_wait {
                st.poll(&mut acked).map_err(|e| e.to_string())?;
                st.idle();
            }
            settle(&mut st)?;
            let (m, b) = st.shards.iter().fold((0, 0), |a, s| {
                let d = s.defrag_stats();
                (a.0 + d.moved_extents, a.1 + d.sweeps)
            });
            println!("                defrag: {b} sweeps, {m} extents moved");
            shape(&format!("c{cyc} defrag"), &mut st, &disk)?;
        }
    }
    if tail > 0 {
        env.omap = true;
        for c in store::dbg::BUSY.iter().chain(store::dbg::PARK_WHY.iter()) {
            c.store(0, Relaxed);
        }
        store::dbg::PARK_SCANS.store(0, Relaxed);
        store::dbg::PARK_ITEMS.store(0, Relaxed);
        let objs: Vec<Obj> = (0..tail).map(|i| make_obj(77, i, pgs)).collect();
        let ops: Vec<(usize, Kind)> = (0..objs.len()).map(|i| (i, Kind::Write)).collect();
        let p = drive(&mut st, &disk, &mut env, &ops, &objs, qd, 1)?;
        report("tail omap", &p);
    }
    Ok(())
}

/// Jobs = `[start, end)` ranges of `ops`; batched removes group consecutive objects of one PG.
fn jobs_of(ops: &[(usize, Kind)], objs: &[Obj], batch: usize) -> Vec<(usize, usize)> {
    let mut v = Vec::new();
    let mut s = 0;
    while s < ops.len() {
        let mut e = s + 1;
        while e < ops.len() && e - s < batch && objs[ops[e].0].pg == objs[ops[s].0].pg {
            e += 1;
        }
        v.push((s, e));
        s = e;
    }
    v
}

/// `NV_TRACE` snapshot: (dirty sum, dirty max, freeze pages left, ckpt begins, ckpt ends, dirty-hard refusals, parked).
fn trace_snap(st: &St) -> [u64; 7] {
    let mut r = [0, 0, 0, 0, 0, 0, st.queued_count() as u64];
    for s in &st.shards {
        let g = s.sh.gauges();
        let x = &s.sh.stats;
        r[0] += g.dirty_pages;
        r[1] = r[1].max(g.dirty_pages);
        r[2] += g.freeze_left;
        r[3] += x.ckpt_begins;
        r[4] += x.checkpoints;
        r[5] += x.busy.iter().sum::<u64>();
    }
    r
}
