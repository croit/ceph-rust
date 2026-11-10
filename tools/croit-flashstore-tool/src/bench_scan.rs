// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `bench-scan`: cost of long / cold listings on one PG core and what they do to the other ops of that core, through
//! the store on a SIMULATED device with real-time latency (no hardware; adr 0021 S8).
//!
//!   croit-flashstore-tool bench-scan [--keys 1000000] [--objs 1000000] [--hot 1000] [--hot-keys 64] [--val 128] [--page 1024] [--cache-mb 512]
//!                           [--read-us 80] [--rate-us 100] [--solo-ms 500] [--pgls block|park] [--omap vals|keys]
//!                           [--phases LIST]
//!                           [--format plain|json|json-pretty]
//!
//! One shard, one PG: object `omap.big` with `--keys` omap keys (`--val` byte values), `--objs` empty objects (the PGLS
//! set) and `--hot` 4 KiB objects with `--hot-keys` omap keys each (the point-op set). Filled on a zero-latency device, measured on a remount of its
//! image with `--read-us` reads (a fresh mount = cold tree cache). The loop emulates the opexec core loop: point ops
//! (50 % reads = one omap key + 4 KiB data, 50 % 4 KiB writes, of random hot objects) arrive open-loop every `--rate-us`; a refused (cold)
//! op parks until a store wake; the listing runs one client request per step: an omap page (`--page` entries; `--omap
//! vals` = omap_get_vals, `keys` = omap_get_keys; the step includes the reply encoding as opexec builds it) or a PGLS page (`list` in batches of 64 up to `--page` objects, like `ov_list`), re-run after a
//! refusal like the engine (`retry_woken`: once the loads are in or after 8 wakes; blocking after 64 refusals
//! without progress). `--pgls block` = the PGLS page runs blocking (engine before adr 0021 S8 am. 63), `park` = non-blocking,
//! resumed at the first unlisted object.
//! Phases (`--phases`, default `solo,omap-cold,omap-warm,pgls-cold,solo`): `solo` = point ops only for `--solo-ms`;
//! `omap-*` / `pgls-*` = one full listing with the point ops running; `-cold` remounts first (warm = the same
//! listing again on the mount the previous phase left). Per phase: listing entries/s, core ns per entry (time inside
//! listing steps / entries; a blocking step includes its device waits = core lost), refused runs, longest step, and
//! point-op latency p50 / p99 / max with the count of point ops that waited behind a step.
//! Exit: 0 ok, 1 store error / content mismatch, 2 usage.
use crate::bench::{arg, num, obj, pgc, pgmeta};
use denc::types::Ghobject;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::time::Instant;
use store::dev::{MonoClock, SimClock, SimConfig, SimDisk, SimImage};
use store::layout::{MkfsParams, mkfs};
use store::obj::txn::Bytes;
use store::obj::{OTxn, Queued, Store, StoreCfg, TOp};
use store::rng::Rng;

type St = Store<store::dev::SimDev, MonoClock>;

/// Engine constants mirrored by the emulated loop (opexec `MAX_SCAN_TRIES`, `MAX_SCAN_WAKES`).
const MAX_SCAN_TRIES: u32 = 64;
const MAX_SCAN_WAKES: u32 = 8;
/// `ov_list` batch (storeadapt).
const LIST_BATCH: usize = 64;
/// opexec PGLS store call size in non-blocking runs (pgop `LIST_BATCH`).
const PARK_BATCH: usize = 256;
const PG: u32 = 0;
const BLK: usize = 4096;

pub fn run(a: &[String], f: outfmt::Format) -> i32 {
    let cfg = match Cfg::parse(a) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bench-scan: {e}");
            return 2;
        }
    };
    match inner(&cfg) {
        Ok(rows) => {
            if f.is_json() {
                println!("{}", f.doc(&json!({"config": cfg.json(), "phases": rows})));
            } else {
                for r in &rows {
                    println!("{}", plain(r));
                }
            }
            0
        }
        Err(e) => {
            eprintln!("bench-scan: {e}");
            1
        }
    }
}

struct Cfg {
    keys: u64,
    objs: u64,
    hot: u64,
    hot_keys: u64,
    val: usize,
    page: usize,
    cache_pages: usize,
    read_us: u64,
    rate_ns: u64,
    solo_ns: u64,
    pgls_park: bool,
    /// omap pages list values (omap_get_vals) or keys only (omap_get_keys).
    omap_vals: bool,
    phases: Vec<String>,
}

impl Cfg {
    fn parse(a: &[String]) -> Result<Cfg, String> {
        let pgls = arg(a, "--pgls").unwrap_or_else(|| "block".into());
        if pgls != "block" && pgls != "park" {
            return Err(format!("--pgls block|park, got {pgls}"));
        }
        let omap = arg(a, "--omap").unwrap_or_else(|| "vals".into());
        if omap != "vals" && omap != "keys" {
            return Err(format!("--omap vals|keys, got {omap}"));
        }
        let phases: Vec<String> = arg(a, "--phases")
            .unwrap_or_else(|| "solo,omap-cold,omap-warm,pgls-cold,solo".into())
            .split(',')
            .map(str::to_string)
            .collect();
        for p in &phases {
            if !matches!(
                p.as_str(),
                "solo" | "omap-cold" | "omap-warm" | "pgls-cold" | "pgls-warm"
            ) {
                return Err(format!("unknown phase {p}"));
            }
        }
        Ok(Cfg {
            keys: num(a, "--keys", 1_000_000)?,
            objs: num(a, "--objs", 1_000_000)?,
            hot: num(a, "--hot", 1000)?.max(1),
            hot_keys: num(a, "--hot-keys", 64)?.max(1),
            val: num(a, "--val", 128)? as usize,
            page: (num(a, "--page", 1024)? as usize).max(1),
            cache_pages: (num(a, "--cache-mb", 512)? as usize * 128).max(1024),
            read_us: num(a, "--read-us", 80)?,
            rate_ns: num(a, "--rate-us", 100)?.max(1) * 1000,
            solo_ns: num(a, "--solo-ms", 500)? * 1_000_000,
            pgls_park: pgls == "park",
            omap_vals: omap == "vals",
            phases,
        })
    }

    fn json(&self) -> Value {
        json!({"keys": self.keys, "objs": self.objs, "hot": self.hot, "hot_keys": self.hot_keys, "val": self.val, "page": self.page,
               "cache_pages": self.cache_pages, "read_us": self.read_us, "rate_us": self.rate_ns / 1000,
               "pgls": if self.pgls_park { "park" } else { "block" },
               "omap": if self.omap_vals { "vals" } else { "keys" }})
    }
}

fn big() -> Ghobject {
    obj("omap.big", PG)
}
fn hot(i: u64) -> Ghobject {
    obj(&format!("hot.{i:06}"), PG)
}
fn lobj(i: u64) -> Ghobject {
    obj(
        &format!("o.{:016x}", i.wrapping_mul(0x9e37_79b9_7f4a_7c15)),
        PG,
    )
}
fn okey(i: u64) -> Vec<u8> {
    format!("key.{i:010}").into_bytes()
}
/// Incompressible value (the store compresses omap values, adr 0021 S9: a constant would shrink the leaves ~10x).
fn oval(i: u64, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    crate::bench::fill_pattern(&mut v, i);
    v
}

/// Fill on a zero-latency device; returns the durable image.
fn fill(c: &Cfg) -> Result<(SimImage, SimConfig), String> {
    let bytes = (c.keys + c.hot * c.hot_keys) * (c.val as u64 + 64) * 2
        + c.objs * 512
        + c.hot * 3 * BLK as u64;
    let mut sim = SimConfig::new((bytes + (1 << 30)).next_multiple_of(1 << 20));
    let fast = SimConfig {
        read_ns: 0,
        write_ns: 0,
        dealloc_ns: 0,
        xfer_ns_per_lba: 0,
        jitter_ns: 0,
        ..sim.clone()
    };
    let disk = SimDisk::new(fast);
    {
        let mut dev = disk.queue();
        let mut clk = SimClock::default();
        let p = MkfsParams {
            shards: 1,
            wal_blocks: 8192,
            align_blocks: 1,
            meta_pct: 12,
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
    let e = |e: store::obj::ObjError| e.to_string();
    let mut t = OTxn::new();
    t.push(TOp::MkColl {
        cid: pgc(PG),
        bits: 0,
        exist_ok: true,
    });
    t.touch(pgc(PG), &pgmeta(PG));
    t.touch(pgc(PG), &big());
    st.commit(&t).map_err(e)?;
    let mut i = 0;
    while i < c.keys {
        let n = (c.keys - i).min(1000);
        let mut t = OTxn::new();
        t.push(TOp::OmapSetKeys {
            cid: pgc(PG),
            oid: big(),
            pairs: (i..i + n)
                .map(|k| (Bytes::Owned(okey(k)), Bytes::Owned(oval(k, c.val))))
                .collect(),
        });
        st.commit(&t).map_err(e)?;
        i += n;
    }
    let mut i = 0;
    while i < c.objs {
        let n = (c.objs - i).min(1000);
        let mut t = OTxn::new();
        for k in i..i + n {
            t.touch(pgc(PG), &lobj(k));
        }
        st.commit(&t).map_err(e)?;
        i += n;
    }
    let data = vec![0xa5u8; BLK];
    for k in 0..c.hot {
        let mut t = OTxn::new();
        t.write(pgc(PG), &hot(k), 0, &data);
        t.push(TOp::OmapSetKeys {
            cid: pgc(PG),
            oid: hot(k),
            pairs: (0..c.hot_keys)
                .map(|j| {
                    (
                        Bytes::Owned(okey(j)),
                        Bytes::Owned(oval(k * 7919 + j, c.val)),
                    )
                })
                .collect(),
        });
        st.commit(&t).map_err(e)?;
    }
    st.checkpoint().map_err(e)?;
    st.sync().map_err(e)?;
    drop(st);
    sim.read_ns = c.read_us * 1000;
    sim.jitter_ns = sim.read_ns / 10;
    Ok((disk.image(), sim))
}

fn mount(img: &SimImage, sim: &SimConfig, c: &Cfg) -> Result<St, String> {
    let disk = SimDisk::from_image(img, sim.clone());
    let mut cfg = StoreCfg::default();
    cfg.shard.cache_pages = c.cache_pages;
    cfg.shard.dirty_soft_pages = c.cache_pages / 8;
    cfg.shard.dirty_hard_pages = c.cache_pages * 3 / 8;
    let (mut st, _) = Store::mount(move || disk.queue(), MonoClock::default(), cfg)
        .map_err(|e| format!("mount: {e:?}"))?;
    // the point-op working set is hot before a phase starts (blocking reads)
    for k in 0..c.hot {
        st.read(&pgc(PG), &hot(k), 0, BLK as u64)
            .map_err(|e| e.to_string())?;
        st.omap_all(&pgc(PG), &hot(k)).map_err(|e| e.to_string())?;
    }
    Ok(st)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Solo,
    Omap,
    Pgls,
}

struct Point {
    t0: u64,
    idx: u64,
    key: u64,
    write: bool,
    /// Refused (cold) and waiting for a store wake.
    parked: bool,
}

/// The listing in progress (one client request after the other, each re-run until it completes).
struct Listing {
    kind: Kind,
    /// omap: first key of the current page (inclusive); pgls: first unlisted object of the current page.
    from: Vec<u8>,
    cur: Ghobject,
    /// PGLS page entries collected so far (resumed after a refusal in park mode).
    page_n: usize,
    tid: u64,
    done: bool,
    waiting: bool,
    wakes: u32,
    tries: u32,
    entries: u64,
    refusals: u64,
    blocking_runs: u64,
    step_ns: u64,
    step_max_ns: u64,
    steps: u64,
}

impl Listing {
    fn new(kind: Kind) -> Listing {
        Listing {
            kind,
            from: Vec::new(),
            cur: Ghobject::default(),
            page_n: 0,
            tid: 1,
            done: kind == Kind::Solo,
            waiting: false,
            wakes: 0,
            tries: 0,
            entries: 0,
            refusals: 0,
            blocking_runs: 0,
            step_ns: 0,
            step_max_ns: 0,
            steps: 0,
        }
    }
}

fn run_phase(st: &mut St, c: &Cfg, kind: Kind, rng: &mut Rng) -> Result<Value, String> {
    let e = |e: store::obj::ObjError| e.to_string();
    let mut ls = Listing::new(kind);
    let mut pts: VecDeque<Point> = VecDeque::new();
    let mut pend: std::collections::HashMap<u64, u64> = Default::default();
    let (mut next_tok, mut lat, mut behind, mut prefused) = (1u64, Vec::<u32>::new(), 0u64, 0u64);
    let mut ptree = 0u64;
    let (loads0, ev0) = (st.tree_stats().loads, st.tree_stats().evictions);
    let mut acked = Vec::new();
    let wdata = vec![0x3cu8; BLK];
    let t0 = Instant::now();
    let now = || t0.elapsed().as_nanos() as u64;
    let mut next_arrival = 0u64;
    let mut woke = false;
    loop {
        let t = now();
        let listing_live = !ls.done;
        let arrivals_on = if kind == Kind::Solo {
            t < c.solo_ns
        } else {
            listing_live
        };
        while arrivals_on && next_arrival <= t {
            pts.push_back(Point {
                t0: next_arrival,
                idx: rng.below(c.hot),
                key: rng.below(c.hot_keys),
                write: rng.below(2) == 1,
                parked: false,
            });
            next_arrival += c.rate_ns;
        }
        // point ops: everything runnable (a parked one waits for a wake)
        let mut i = 0;
        while i < pts.len() {
            if pts[i].parked && !woke {
                i += 1;
                continue;
            }
            let p = &mut pts[i];
            if p.write {
                let mut tx = OTxn::new();
                tx.write(pgc(PG), &hot(p.idx), 0, &wdata);
                let tok = next_tok;
                next_tok += 1;
                match st.queue(&tx, tok).map_err(e)? {
                    Queued::Submitted(_) | Queued::Pending(_) => {}
                }
                pend.insert(tok, p.t0);
                pts.remove(i);
                continue;
            }
            st.set_nonblock_reads(true);
            st.read_session(Some((2, p.t0)), true);
            let k = okey(p.key);
            let g = st.omap_get(&pgc(PG), &hot(p.idx), &[&k]);
            // a refused omap get = a hot tree page was evicted (the data read refuses on its own: rolling prefetch)
            let tree_cold = st.take_blocked();
            ptree += u64::from(tree_cold);
            let r = st.read_crc(&pgc(PG), &hot(p.idx), 0, BLK as u64);
            st.set_nonblock_reads(false);
            let blocked = st.take_blocked() || tree_cold;
            st.read_session(None, blocked);
            if blocked {
                p.parked = true;
                prefused += 1;
                i += 1;
                continue;
            }
            let (d, _) = r.map_err(e)?;
            if d.len() != BLK || g.map_err(e)?.len() != 1 {
                return Err("hot read: short".into());
            }
            lat.push(((now() - p.t0) / 1000) as u32);
            pts.remove(i);
        }
        woke = false;
        // one listing step (one client request run), as the engine re-runs a refused op
        if !ls.done && !ls.waiting {
            step(st, c, &mut ls)?;
            // point ops that arrived while the step ran waited behind it
            let t2 = now();
            let mut a = next_arrival;
            while a <= t2 && arrivals_on {
                behind += 1;
                a += c.rate_ns;
            }
        }
        acked.clear();
        st.poll(&mut acked).map_err(e)?;
        for tok in acked.drain(..) {
            if let Some(a) = pend.remove(&tok) {
                lat.push(((now() - a) / 1000) as u32);
            }
        }
        if st.take_wake() {
            woke = true;
            if ls.waiting {
                if !st.loads_pending() || ls.wakes >= MAX_SCAN_WAKES {
                    ls.waiting = false;
                    ls.wakes = 0;
                } else {
                    ls.wakes += 1;
                }
            }
        }
        let quiet = pts.is_empty() && pend.is_empty();
        let over = if kind == Kind::Solo {
            now() >= c.solo_ns
        } else {
            ls.done
        };
        if over && quiet {
            break;
        }
    }
    let wall = t0.elapsed().as_secs_f64();
    lat.sort_unstable();
    let q = |x: f64| {
        lat.get(((lat.len() as f64) * x) as usize)
            .copied()
            .unwrap_or(0)
    };
    Ok(json!({
        "entries": ls.entries,
        "secs": wall,
        "entries_per_s": if kind == Kind::Solo { 0.0 } else { ls.entries as f64 / wall },
        "core_ns_per_entry": if ls.entries == 0 { 0.0 } else { ls.step_ns as f64 / ls.entries as f64 },
        "steps": ls.steps,
        "refusals": ls.refusals,
        "blocking_runs": ls.blocking_runs,
        "step_max_us": ls.step_max_ns / 1000,
        "point_ops": lat.len(),
        "point_p50_us": q(0.5),
        "point_p99_us": q(0.99),
        "point_max_us": lat.last().copied().unwrap_or(0),
        "point_behind_step": behind,
        "point_refusals": prefused,
        "point_tree_refusals": ptree,
        "tree_loads": st.tree_stats().loads - loads0,
        "tree_evictions": st.tree_stats().evictions - ev0,
    }))
}

/// One run of the current listing request; `ls.waiting` = refused, re-run after the loads.
fn step(st: &mut St, c: &Cfg, ls: &mut Listing) -> Result<(), String> {
    let park = ls.kind == Kind::Omap || c.pgls_park;
    let nb = park && ls.tries < MAX_SCAN_TRIES;
    ls.blocking_runs += u64::from(!nb);
    let t = Instant::now();
    st.set_nonblock_reads(nb);
    st.read_session(Some((1, ls.tid)), true);
    let mut got = 0usize;
    let mut finished = false;
    let r: Result<(), String> = (|| {
        match ls.kind {
            Kind::Omap => {
                // the reply as opexec builds it (omap_get_vals / omap_get_keys outdata): encoded by the store from
                // the leaves, finished in place
                let (buf, n, more) = st
                    .omap_list_enc(
                        &pgc(PG),
                        &big(),
                        &ls.from,
                        b"",
                        c.page,
                        1 << 30,
                        c.omap_vals,
                        opwire::OMAP_LIST_HEAD,
                    )
                    .map_err(|e| e.to_string())?;
                got = n;
                let reply = opwire::omap_list_out(buf, n as u32, more);
                // the next page starts after the last key (as the client reads it from the reply)
                if let Some(k) = last_key(&reply, n, c.omap_vals)? {
                    ls.from = [k, &[0]].concat();
                }
                finished = !more;
                std::hint::black_box(reply);
            }
            Kind::Pgls => loop {
                // block: `ov_list` batches as the engine ran them before; park: the non-blocking engine's calls (at most
                // a listing slice + the handle)
                let n = if park {
                    (c.page - ls.page_n).clamp(LIST_BATCH, PARK_BATCH) + 1
                } else {
                    LIST_BATCH
                };
                let (objs, next) = st
                    .list(&pgc(PG), &ls.cur, None, n)
                    .map_err(|e| e.to_string())?;
                // park mode resumes at the first unlisted object: everything before it stays listed
                let mut full = false;
                for o in objs {
                    if o.is_pgmeta() {
                        continue;
                    }
                    if ls.page_n >= c.page {
                        ls.cur = o;
                        full = true;
                        break;
                    }
                    ls.page_n += 1;
                    got += 1;
                }
                if full {
                    break;
                }
                match next {
                    Some(n) => ls.cur = n,
                    None => {
                        finished = true;
                        break;
                    }
                }
            },
            Kind::Solo => {}
        }
        Ok(())
    })();
    st.set_nonblock_reads(false);
    let blocked = nb && st.take_blocked();
    st.read_session(None, blocked);
    let dt = t.elapsed().as_nanos() as u64;
    ls.steps += 1;
    ls.step_ns += dt;
    ls.step_max_ns = ls.step_max_ns.max(dt);
    if blocked {
        let progressed = st.take_rm_progress();
        ls.tries += u32::from(!progressed);
        ls.refusals += 1;
        ls.waiting = true;
        ls.wakes = 0;
        if ls.kind == Kind::Pgls {
            ls.entries += got as u64; // kept (cursor advanced past them)
        }
        return Ok(());
    }
    r?;
    ls.entries += got as u64;
    ls.tries = 0;
    ls.tid += 1;
    ls.page_n = 0;
    if finished {
        ls.done = true;
    }
    Ok(())
}

/// Last key of an omap_get_vals (`vals`) / omap_get_keys reply of `n` entries: the store names `n`, a reply that cannot
/// hold that many entries is an error, not a panic.
fn last_key(reply: &[u8], n: usize, vals: bool) -> Result<Option<&[u8]>, String> {
    let mut p = opwire::OMAP_LIST_HEAD;
    let mut take = || -> Result<&[u8], String> {
        let h = reply.get(p..p + 4).ok_or_else(|| {
            format!(
                "omap reply: entry length at {p} is beyond {} B",
                reply.len()
            )
        })?;
        let l = u32::from_le_bytes(h.try_into().expect("4 bytes")) as usize;
        let v = reply.get(p + 4..p + 4 + l).ok_or_else(|| {
            format!(
                "omap reply: entry at {p} ({l} B) is beyond {} B",
                reply.len()
            )
        })?;
        p += 4 + l;
        Ok(v)
    };
    let mut last = None;
    for _ in 0..n {
        last = Some(take()?);
        if vals {
            take()?;
        }
    }
    Ok(last)
}

fn inner(c: &Cfg) -> Result<Vec<Value>, String> {
    let tf = Instant::now();
    let (img, sim) = fill(c)?;
    eprintln!("bench-scan: filled in {:.1} s", tf.elapsed().as_secs_f64());
    let mut rng = Rng::new(11);
    let mut rows = Vec::new();
    let mut st: Option<St> = None;
    for p in &c.phases {
        let (kind, cold) = match p.as_str() {
            "solo" => (Kind::Solo, false),
            "omap-cold" => (Kind::Omap, true),
            "omap-warm" => (Kind::Omap, false),
            "pgls-cold" => (Kind::Pgls, true),
            _ => (Kind::Pgls, false),
        };
        if cold || st.is_none() {
            drop(st.take()); // unmount first: one image per mount
            st = Some(mount(&img, &sim, c)?);
        }
        let s = st.as_mut().expect("mounted");
        let mut r = run_phase(s, c, kind, &mut rng)?;
        let want = match kind {
            Kind::Omap => c.keys,
            Kind::Pgls => c.objs + c.hot + 1,
            Kind::Solo => 0,
        };
        if r["entries"].as_u64() != Some(want) {
            return Err(format!("{p}: listed {} entries, want {want}", r["entries"]));
        }
        r["phase"] = json!(p);
        rows.push(r);
    }
    Ok(rows)
}

fn plain(r: &Value) -> String {
    format!(
        "{:<10} entries {:>8} {:>10.0}/s core {:>7.1} ns/entry steps {:>6} refusals {:>6} blocking {:>4} step_max {:>7} us | point ops {:>7} p50 {:>6} p99 {:>7} max {:>7} us behind_step {} refused {} tree_refused {} | tree loads {} evictions {}",
        r["phase"].as_str().unwrap_or(""),
        r["entries"],
        r["entries_per_s"].as_f64().unwrap_or(0.0),
        r["core_ns_per_entry"].as_f64().unwrap_or(0.0),
        r["steps"],
        r["refusals"],
        r["blocking_runs"],
        r["step_max_us"],
        r["point_ops"],
        r["point_p50_us"],
        r["point_p99_us"],
        r["point_max_us"],
        r["point_behind_step"],
        r["point_refusals"],
        r["point_tree_refusals"],
        r["tree_loads"],
        r["tree_evictions"],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reply length and the entry count come from the store: a reply that cannot hold `n` entries is an error, not
    /// an out-of-bounds slice.
    #[test]
    fn last_key_rejects_a_short_reply() {
        fn enc(vals: bool) -> Vec<u8> {
            let mut r = vec![0u8; opwire::OMAP_LIST_HEAD];
            for k in [b"a".as_slice(), b"bc".as_slice()] {
                r.extend_from_slice(&(k.len() as u32).to_le_bytes());
                r.extend_from_slice(k);
                if vals {
                    r.extend_from_slice(&1u32.to_le_bytes());
                    r.extend_from_slice(b"v");
                }
            }
            r
        }
        let vals = enc(true);
        let keys = enc(false);
        assert_eq!(last_key(&vals, 2, true).unwrap(), Some(b"bc".as_slice()));
        assert_eq!(last_key(&keys, 2, false).unwrap(), Some(b"bc".as_slice()));
        assert_eq!(last_key(&vals, 0, true).unwrap(), None);
        for (r, vals) in [(&vals, true), (&keys, false)] {
            for n in [3usize, 1000] {
                let e = last_key(r, n, vals).unwrap_err();
                assert!(e.contains("beyond"), "{e}");
            }
        }
    }
}
