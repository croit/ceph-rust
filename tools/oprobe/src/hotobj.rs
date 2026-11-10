// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `oprobe hotobj`: one hot omap object under mixed reads and writes (the S3 bucket-index shard pattern), alone and
//! with background omap scans on other objects of the same PG (same OSD core). Measures what per-object ordering costs:
//! a read waits for every write of the object in flight (client-ops 5.5), so ops/s = ops per read/write alternation /
//! alternation time. See `HELP` and doc/perf/hot-object-20261021.md.
//!
//! Phases: populate (hot object + scan objects, 1024-key batches) -> `solo` (hot clients only) -> `scan` (hot clients +
//! scanners) -> `solo2` (hot clients only again: drift check). Workers own one `Probe` each and return per-phase histograms.

use crate::client::{Done, Opts, Probe};
use crate::omapbench::{
    Hist, MAX_CLIENTS, MAX_QD, Rng, flag, key, num, num_max, secs, take, target,
};
use crate::script::ScriptMsg;
use opwire::{KvMap, OsdOp, op as code};
use serde_json::json;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

pub const HELP: &str = "\
hotobj -p POOL [options]   one hot omap object, mixed reads + writes, alone and with omap scans in the same PG
  --prefix S        object name prefix (default hotobj-<time>)
  --keys N          keys of the hot object (100000)          --clients N (8)  --qd N (16)  hot clients x QD
  --write-pct N     share of writes (55)                     --read-keys N (8) keys per read
  write = [omap_get_header, omap_set_header, omap_set_vals(1 key)] (cls read-modify-write shape; --plain-write: no header read)
  read  = [omap_get_header, omap_get_vals_by_keys(N)]
  --scan-objs N     objects in the hot object's PG (4)       --scan-keys N (20000)  keys per scan object
  --scan-clients N  (4)  --scan-qd N (4)                      --scan-n N (16384) keys per omap_get_vals
  --scan-op omap|pgls   scanners list omap keys (default) or walk the hot object's PG with pgnls (--scan-n objects
                    per request, one request in flight per scanner); --pgls-objs N (100000) empty objects created in that PG
  --t-solo S (15)  --t-scan S (15)   phase seconds (phases: solo, scan, solo2); --clients 0: the scanners alone
  --keep            leave the objects    --reuse  objects of an earlier --keep run with the same prefix and sizes: no populate
  --format plain|json|json-pretty
output: one row per phase and class (read, write, scan): ops/s, p50/p99/max us, errors; scan also entries/s (keys or objects
  listed per second, from the replies).
exit: 0 ok, 1 errors counted, 2 usage / setup failure.
";

const VAL_LEN: usize = 256;
const PHASES: [&str; 3] = ["solo", "scan", "solo2"];
const CLASSES: [&str; 3] = ["read", "write", "scan"];

#[derive(Clone, Debug)]
struct Cfg {
    pool: String,
    hot: String,
    scan_objs: Vec<String>,
    keys: u64,
    clients: usize,
    qd: usize,
    write_pct: u64,
    read_keys: usize,
    rmw: bool,
    scan_keys: u64,
    scan_clients: usize,
    scan_qd: usize,
    scan_n: u64,
    t_solo: Duration,
    t_scan: Duration,
    /// Scanners walk the hot object's PG with pgnls instead of listing omap keys.
    pgls: bool,
    pgls_objs: Vec<String>,
    /// The hot object's PG.
    pg_seed: u32,
}

/// Per-phase, per-class histograms (us), error counts and entries listed (scan) of one worker.
type Rec = Vec<[(Hist, u64, u64); 3]>;

fn rec_new() -> Rec {
    (0..PHASES.len())
        .map(|_| std::array::from_fn(|_| (Hist::new(), 0, 0)))
        .collect()
}

fn msg(ops: Vec<OsdOp>) -> ScriptMsg {
    ScriptMsg {
        ops,
        ..Default::default()
    }
}

fn val(rng: &mut Rng) -> Vec<u8> {
    let mut v = Vec::with_capacity(VAL_LEN);
    while v.len() < VAL_LEN {
        v.extend_from_slice(&rng.next_u64().to_le_bytes());
    }
    v.truncate(VAL_LEN);
    v
}

fn connect(o: &Opts, pool: &str) -> Result<(Probe, i64), String> {
    let mut p = Probe::connect(o.clone())?;
    p.idle_sleep = Duration::from_micros(100);
    let id = p
        .osdmap()
        .pool_id_by_name(pool)
        .ok_or_else(|| format!("no pool '{pool}'"))?;
    Ok((p, id))
}

fn failed(d: &Done) -> bool {
    d.reply
        .as_ref()
        .is_none_or(|r| r.result < 0 || r.ops.iter().any(|o| o.rval < 0))
}

/// Fill `name` with keys `0..n` (1024-key batches, QD 4).
fn populate(o: &Opts, pool: &str, name: &str, n: u64, seed: u64) -> Result<(), String> {
    let (mut p, pid) = connect(o, pool)?;
    let mut rng = Rng::new(seed);
    let mut next = 0u64;
    let mut tag = 0u64;
    while next < n || p.in_flight() > 0 {
        while next < n && p.in_flight() < 4 {
            let hi = (next + 1024).min(n);
            let m: KvMap = (next..hi).map(|i| (key(i), val(&mut rng))).collect();
            p.submit(target(pid, name), msg(vec![OsdOp::omap_set_vals(&m)]), tag)?;
            tag += 1;
            next = hi;
        }
        for d in p.poll() {
            if failed(&d) {
                return Err(format!("populate {name}: {}", d.err));
            }
        }
    }
    Ok(())
}

fn hot_worker(
    o: Opts,
    c: Arc<Cfg>,
    id: u64,
    phase: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
) -> Result<Rec, String> {
    let (mut p, pid) = connect(&o, &c.pool)?;
    let mut rng = Rng::new(0x5EED ^ (id << 32));
    let mut rec = rec_new();
    let mut hdr = 0u64;
    // tag = class (0 read, 1 write) | phase at submit << 8
    loop {
        let stopping = stop.load(Relaxed);
        if stopping && p.in_flight() == 0 {
            break;
        }
        while !stopping && p.in_flight() < c.qd {
            let ph = phase.load(Relaxed);
            let write = rng.below(100) < c.write_pct;
            let ops = if write {
                hdr += 1;
                let mut kv = KvMap::new();
                kv.insert(key(rng.below(c.keys)), val(&mut rng));
                let mut v = Vec::with_capacity(3);
                if c.rmw {
                    v.push(OsdOp::omap_get_header());
                }
                v.push(OsdOp::omap_set_header(hdr.to_le_bytes().repeat(8)));
                v.push(OsdOp::omap_set_vals(&kv));
                v
            } else {
                let set: BTreeSet<Vec<u8>> =
                    (0..c.read_keys).map(|_| key(rng.below(c.keys))).collect();
                let mut x = OsdOp::new(code::OMAP_GET_VALS_BY_KEYS);
                x.indata = denc::Encode::encode_to_vec(&set).expect("vec").into();
                vec![OsdOp::omap_get_header(), x]
            };
            p.submit(
                target(pid, &c.hot),
                msg(ops),
                u64::from(write) | (ph as u64) << 8,
            )?;
        }
        for d in p.poll() {
            let (cls, ph) = ((d.tag & 1) as usize, (d.tag >> 8) as usize);
            let r = &mut rec[ph][cls];
            if failed(&d) {
                r.1 += 1;
            } else {
                r.0.rec(d.finished.duration_since(d.submitted).as_micros() as u64);
            }
        }
    }
    Ok(rec)
}

fn scan_worker(
    o: Opts,
    c: Arc<Cfg>,
    id: u64,
    phase: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
) -> Result<Rec, String> {
    let (mut p, pid) = connect(&o, &c.pool)?;
    let mut rng = Rng::new(0x5CA7 ^ (id << 32));
    let mut rec = rec_new();
    loop {
        let stopping = stop.load(Relaxed);
        if stopping && p.in_flight() == 0 {
            break;
        }
        // scanners run in the `scan` phase only
        let ph = phase.load(Relaxed);
        while !stopping && ph == 1 && p.in_flight() < c.scan_qd {
            let name = &c.scan_objs[rng.below(c.scan_objs.len() as u64) as usize];
            let after = key(rng.below(c.scan_keys));
            let op = OsdOp::omap_get_vals(&after, c.scan_n, b"");
            p.submit(target(pid, name), msg(vec![op]), ph as u64)?;
        }
        if ph != 1 && p.in_flight() == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        for d in p.poll() {
            let r = &mut rec[d.tag as usize][2];
            if failed(&d) {
                r.1 += 1;
            } else {
                r.0.rec(d.finished.duration_since(d.submitted).as_micros() as u64);
                // omap_get_vals outdata starts with the entry count
                let out = d.reply.as_ref().and_then(|x| x.ops.first());
                r.2 += out
                    .and_then(|x| x.outdata.get(..4))
                    .map_or(0, |b| u64::from(u32::from_le_bytes(b.try_into().unwrap())));
            }
        }
    }
    Ok(rec)
}

/// pgnls scanner: walks the hot object's PG page by page (one request in flight, as a client listing does), from the
/// start again when the PG is exhausted.
fn pgls_worker(
    o: Opts,
    c: Arc<Cfg>,
    phase: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
) -> Result<Rec, String> {
    let (mut p, pid) = connect(&o, &c.pool)?;
    p.pg_override = Some(c.pg_seed);
    let mut rec = rec_new();
    let mut cursor = denc::types::Hobject::MIN();
    loop {
        let stopping = stop.load(Relaxed);
        if stopping && p.in_flight() == 0 {
            break;
        }
        let ph = phase.load(Relaxed);
        if !stopping && ph == 1 && p.in_flight() == 0 {
            p.submit(
                target(pid, ""),
                msg(vec![OsdOp::pgnls(c.scan_n, &cursor)]),
                ph as u64,
            )?;
        }
        if ph != 1 && p.in_flight() == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        for d in p.poll() {
            let r = &mut rec[d.tag as usize][2];
            if failed(&d) {
                r.1 += 1;
                cursor = denc::types::Hobject::MIN();
                continue;
            }
            r.0.rec(d.finished.duration_since(d.submitted).as_micros() as u64);
            let rep = d.reply.as_ref().expect("not failed");
            let page: Option<opwire::PgNlsResponse> = rep
                .ops
                .first()
                .and_then(|x| denc::from_slice(&x.outdata).ok());
            r.2 += page.as_ref().map_or(0, |pg| pg.entries.len() as u64);
            cursor = match page {
                Some(pg) if rep.result != 1 && !pg.handle.max => pg.handle,
                _ => denc::types::Hobject::MIN(),
            };
        }
    }
    Ok(rec)
}

/// Create `names` (empty objects), pipelined.
fn create_all(o: &Opts, pool: &str, names: &[String]) -> Result<(), String> {
    let (mut p, pid) = connect(o, pool)?;
    let mut next = 0;
    while next < names.len() || p.in_flight() > 0 {
        while next < names.len() && p.in_flight() < 64 {
            p.submit(
                target(pid, &names[next]),
                msg(vec![OsdOp::create(false)]),
                0,
            )?;
            next += 1;
        }
        for d in p.poll() {
            if failed(&d) {
                return Err(format!("create: {}", d.err));
            }
        }
    }
    Ok(())
}

fn remove(o: &Opts, pool: &str, names: &[String]) {
    let Ok((mut p, pid)) = connect(o, pool) else {
        return;
    };
    for n in names {
        let _ = p.exec(&target(pid, n), &msg(vec![OsdOp::delete()]));
    }
}

/// Entry point of `oprobe hotobj ...` (`a` = remaining args, `pool` = the global -p).
pub fn cli(a: Vec<String>, o: Opts, pool: Option<String>) -> Result<ExitCode, String> {
    let (fmt, mut a) = outfmt::extract(&a, false)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let prefix = take(&mut a, "--prefix")?.unwrap_or_else(|| format!("hotobj-{now:x}"));
    let pool = pool.ok_or("hotobj: -p POOL required")?;
    let n_scan: usize = num(&mut a, "--scan-objs", 4)?;
    let mut c = Cfg {
        pool,
        hot: format!("{prefix}-hot"),
        scan_objs: Vec::new(),
        keys: num(&mut a, "--keys", 100_000)?,
        clients: num_max(&mut a, "--clients", MAX_CLIENTS, 8)?,
        qd: num_max(&mut a, "--qd", MAX_QD, 16)?,
        write_pct: num(&mut a, "--write-pct", 55)?,
        read_keys: num(&mut a, "--read-keys", 8)?,
        rmw: !flag(&mut a, "--plain-write"),
        scan_keys: num(&mut a, "--scan-keys", 20_000)?,
        scan_clients: num_max(&mut a, "--scan-clients", MAX_CLIENTS, 4)?,
        scan_qd: num_max(&mut a, "--scan-qd", MAX_QD, 4)?,
        scan_n: num(&mut a, "--scan-n", 16_384)?,
        t_solo: secs(&mut a, "--t-solo", 15.0)?,
        t_scan: secs(&mut a, "--t-scan", 15.0)?,
        pgls: match take(&mut a, "--scan-op")?.as_deref() {
            None | Some("omap") => false,
            Some("pgls") => true,
            Some(x) => return Err(format!("hotobj: --scan-op omap|pgls, got {x}")),
        },
        pgls_objs: Vec::new(),
        pg_seed: 0,
    };
    let n_pgls: usize = num(&mut a, "--pgls-objs", 100_000)?;
    let keep = flag(&mut a, "--keep");
    let reuse = flag(&mut a, "--reuse");
    if let Some(x) = a.first() {
        return Err(format!("hotobj: unknown argument '{x}'"));
    }
    if c.keys == 0
        || c.scan_keys == 0
        || c.clients + c.scan_clients == 0
        || n_scan == 0
        || c.qd == 0
        || c.write_pct > 100
    {
        return Err(
            "hotobj: --keys, --scan-keys, --scan-objs, --clients + --scan-clients, --qd must be > 0, --write-pct <= 100"
                .into(),
        );
    }
    // scan objects: names that map to the hot object's PG (same primary core)
    {
        let (p, pid) = connect(&o, &c.pool)?;
        let pg = p.locate(&target(pid, &c.hot))?.pg;
        c.pg_seed = pg.seed;
        let mut i = 0u64;
        while c.scan_objs.len() < n_scan {
            let n = format!("{prefix}-scan-{i}");
            if p.locate(&target(pid, &n))?.pg == pg {
                c.scan_objs.push(n);
            }
            i += 1;
            if i > 1_000_000 {
                return Err("hotobj: no names map to the hot object's PG".into());
            }
        }
        // pgls scanners: the PG gets `--pgls-objs` more objects to list
        let mut i = 0u64;
        while c.pgls && c.pgls_objs.len() < n_pgls {
            let n = format!("{prefix}-o-{i}");
            if p.locate(&target(pid, &n))?.pg == pg {
                c.pgls_objs.push(n);
            }
            i += 1;
        }
        eprintln!(
            "hotobj: hot {} pg {}.{:x}, {} scan objects in it",
            c.hot,
            pg.pool,
            pg.seed,
            c.scan_objs.len()
        );
    }
    let t0 = Instant::now();
    let mut fills = vec![(c.hot.clone(), c.keys)];
    fills.extend(c.scan_objs.iter().map(|n| (n.clone(), c.scan_keys)));
    let creates = if reuse {
        fills.clear();
        &[][..]
    } else {
        &c.pgls_objs[..]
    };
    let hs: Vec<_> = fills
        .into_iter()
        .enumerate()
        .map(|(i, (n, k))| {
            let (o, pool) = (o.clone(), c.pool.clone());
            std::thread::spawn(move || populate(&o, &pool, &n, k, i as u64))
        })
        .collect();
    let parts = creates.chunks(creates.len().div_ceil(8).max(1));
    let hs2: Vec<_> = parts
        .map(|ch| {
            let (o, pool, ch) = (o.clone(), c.pool.clone(), ch.to_vec());
            std::thread::spawn(move || create_all(&o, &pool, &ch))
        })
        .collect();
    for h in hs.into_iter().chain(hs2) {
        h.join().map_err(|_| "populate thread panicked")??;
    }
    let pop_s = t0.elapsed().as_secs_f64();
    eprintln!("hotobj: populate {pop_s:.1} s");
    let c = Arc::new(c);
    let phase = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let mut hs = Vec::new();
    for i in 0..c.clients as u64 {
        let (o, c, ph, st) = (o.clone(), c.clone(), phase.clone(), stop.clone());
        hs.push(std::thread::spawn(move || hot_worker(o, c, i, ph, st)));
    }
    for i in 0..c.scan_clients as u64 {
        let (o, c, ph, st) = (o.clone(), c.clone(), phase.clone(), stop.clone());
        hs.push(std::thread::spawn(move || {
            if c.pgls {
                pgls_worker(o, c, ph, st)
            } else {
                scan_worker(o, c, i, ph, st)
            }
        }));
    }
    let mut secs = [0f64; 3];
    for (i, t) in [c.t_solo, c.t_scan, c.t_solo].into_iter().enumerate() {
        phase.store(i, Relaxed);
        eprintln!("[{:5.0}s] phase {}", t0.elapsed().as_secs_f64(), PHASES[i]);
        let s = Instant::now();
        std::thread::sleep(t);
        secs[i] = s.elapsed().as_secs_f64();
    }
    stop.store(true, Relaxed);
    let mut tot = rec_new();
    let mut fatal = Vec::new();
    for h in hs {
        match h.join() {
            Ok(Ok(r)) => {
                for (a, b) in tot.iter_mut().zip(&r) {
                    for (x, y) in a.iter_mut().zip(b) {
                        x.0.merge(&y.0);
                        x.1 += y.1;
                        x.2 += y.2;
                    }
                }
            }
            Ok(Err(e)) => fatal.push(e),
            Err(_) => fatal.push("worker panicked".into()),
        }
    }
    if !keep {
        let mut all = vec![c.hot.clone()];
        all.extend(c.scan_objs.iter().cloned());
        all.extend(c.pgls_objs.iter().cloned());
        remove(&o, &c.pool, &all);
    }
    let errs: u64 = tot.iter().flatten().map(|x| x.1).sum();
    print!("{}", render(&c, &tot, &secs, pop_s, &fatal, fmt));
    Ok(if !fatal.is_empty() || errs > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn render(
    c: &Cfg,
    tot: &Rec,
    secs: &[f64; 3],
    pop_s: f64,
    fatal: &[String],
    fmt: outfmt::Format,
) -> String {
    if fmt == outfmt::Format::Plain {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "hotobj: keys {} clients {}x{} write {} % rmw {} | scan {} objs x {} keys, {}x{} x {} keys | populate {pop_s:.1} s",
            c.keys,
            c.clients,
            c.qd,
            c.write_pct,
            c.rmw,
            c.scan_objs.len(),
            c.scan_keys,
            c.scan_clients,
            c.scan_qd,
            c.scan_n
        );
        let _ = writeln!(
            s,
            "phase  class  ops_s  p50_us  p99_us  max_us  errs  entries_s"
        );
        for (pi, ph) in PHASES.iter().enumerate() {
            for (ci, cl) in CLASSES.iter().enumerate() {
                let (h, e, n) = &tot[pi][ci];
                if h.n == 0 && *e == 0 {
                    continue;
                }
                let _ = writeln!(
                    s,
                    "{ph} {cl} {:.0} {} {} {} {e} {:.0}",
                    h.n as f64 / secs[pi].max(1e-9),
                    h.pct(0.5),
                    h.pct(0.99),
                    h.max,
                    *n as f64 / secs[pi].max(1e-9)
                );
            }
        }
        for f in fatal {
            let _ = writeln!(s, "fatal: {f}");
        }
        return s;
    }
    let mut doc = serde_json::Map::new();
    doc.insert("keys".into(), json!(c.keys));
    doc.insert("clients".into(), json!(c.clients));
    doc.insert("qd".into(), json!(c.qd));
    doc.insert("write_pct".into(), json!(c.write_pct));
    doc.insert("rmw".into(), json!(c.rmw));
    doc.insert("scan_objs".into(), json!(c.scan_objs.len()));
    doc.insert("scan_keys".into(), json!(c.scan_keys));
    doc.insert("scan_clients".into(), json!(c.scan_clients));
    doc.insert("scan_qd".into(), json!(c.scan_qd));
    doc.insert("scan_n".into(), json!(c.scan_n));
    doc.insert("populate_s".into(), json!(pop_s));
    let mut phases = Vec::with_capacity(PHASES.len());
    for (pi, ph) in PHASES.iter().enumerate() {
        let mut row = serde_json::Map::new();
        row.insert("phase".into(), json!(ph));
        row.insert("secs".into(), json!(secs[pi]));
        for (ci, cl) in CLASSES.iter().enumerate() {
            let (h, e, n) = &tot[pi][ci];
            row.insert(
                (*cl).into(),
                json!({
                    "ops_s": h.n as f64 / secs[pi].max(1e-9), "n": h.n, "p50_us": h.pct(0.5),
                    "p99_us": h.pct(0.99), "max_us": h.max, "errs": e,
                    "entries": n, "entries_s": *n as f64 / secs[pi].max(1e-9),
                }),
            );
        }
        phases.push(serde_json::Value::Object(row));
    }
    doc.insert("phases".into(), serde_json::Value::Array(phases));
    doc.insert("fatal".into(), json!(fatal));
    let mut s = fmt.doc(&serde_json::Value::Object(doc));
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_render_escapes_fatal_strings() {
        let c = Cfg {
            pool: "p".into(),
            hot: "h".into(),
            scan_objs: Vec::new(),
            keys: 1,
            clients: 1,
            qd: 1,
            write_pct: 0,
            read_keys: 1,
            rmw: true,
            scan_keys: 1,
            scan_clients: 0,
            scan_qd: 1,
            scan_n: 1,
            t_solo: Duration::from_secs(1),
            t_scan: Duration::from_secs(1),
            pgls: false,
            pgls_objs: Vec::new(),
            pg_seed: 0,
        };
        let fatal = ["control \u{7} and DEL \u{7f} and \"quote\"".to_string()];
        let s = render(&c, &rec_new(), &[1.0; 3], 2.5, &fatal, outfmt::Format::Json);
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
        assert_eq!(v["phases"].as_array().map(Vec::len), Some(3));
        assert_eq!(v["fatal"][0], fatal[0]);
        let p = render(
            &c,
            &rec_new(),
            &[1.0; 3],
            2.5,
            &fatal,
            outfmt::Format::JsonPretty,
        );
        assert!(serde_json::from_str::<serde_json::Value>(&p).is_ok());
    }

    fn cli_err(args: &[&str]) -> String {
        let a = args.iter().map(|x| x.to_string()).collect();
        cli(a, Opts::default(), Some("p".into())).unwrap_err()
    }

    #[test]
    fn zero_scan_objs_is_a_usage_error() {
        assert!(cli_err(&["--scan-objs", "0"]).contains("--scan-objs"));
    }

    #[test]
    fn unbounded_clients_and_qd_are_usage_errors() {
        let huge = u64::MAX.to_string();
        for opt in ["--clients", "--scan-clients", "--qd", "--scan-qd"] {
            let e = cli_err(&[opt, &huge]);
            assert!(e.contains(opt) && e.contains("exceeds"), "{opt}: {e}");
        }
        assert!(cli_err(&["--clients", "1025"]).contains("exceeds"));
        assert!(cli_err(&["--qd", "65537"]).contains("exceeds"));
    }
}
