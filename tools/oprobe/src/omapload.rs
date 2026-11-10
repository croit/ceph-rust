// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Count-bounded, partitioned OMAP workloads shared by both OSD implementations.
//!
//! Workers partition keys in every object by default; optional object-first ownership
//! assigns whole objects before splitting their keys among excess workers. A deterministic
//! affine permutation gives repeatable shuffled accesses without replacement.
//! Scans instead schedule complete, independent traversals: queue depth never
//! speculates on an unknown continuation. Raw reply decoding checks wire ordering
//! before any map can hide duplicates. All successful reads validate exact values.
//! Throughput includes construction and validation; RPC latency is submission to
//! completion (not construction/validation). Successful runs drain all requests.
//! Connection setup is excluded. No hidden producer/controller thread.

use crate::client::{Done, Opts, Probe};
use crate::omapbench::{Hist, target, value};
use crate::script::ScriptMsg;
use denc::{Decoder, Encode};
use opwire::{KvMap, OsdOp};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const HELP: &str = "omap-load -p POOL --operation put|get|scan [options]\n\
  --prefix NAME             dataset object-name prefix (required)\n\
  --objects N               objects (default 1)\n\
  --keys N                  keys PER OBJECT (default 1000000)\n\
  --work-keys N             keys touched per object (default --keys; put/get only)\n\
  --threads N               producer threads/process (default 1; includes main)\n\
  --processes N --process-index I  global partition identity (default 1/0)\n\
  --partition keys|objects  split every object's keys, or assign objects first (default keys)\n\
  --qd N                    outstanding RPCs/worker (default 1)\n\
  --batch N                 keys/RPC or scan page cap, 1..1024 (default 1024)\n\
  --value-bytes N            value size, >=8 (default 256); keys are 64 bytes\n\
  --generation N            exact value generation written/expected (default 0)\n\
  --scan-passes N            complete traversals/object across ALL workers (default 8)\n\
  --order shuffled|sequential  point-access order (default shuffled)\n\
  --idle-us N                client idle polling sleep (default 100)\n\
  --max-seconds N            hard worker workload deadline (default 300)\n\
  --gate-dir PATH            write ready-I after setup; wait for PATH/go (30s)\n\
  --format plain|json|json-pretty\n\
Successful put completion uses Probe's durable ONDISK path. Updates use put with\n\
a new generation. Reusing a prefix does NOT empty objects; use fresh prefixes\n\
for population, and quiescent exact get/scan verification after updates.\n";

#[derive(Clone, Debug)]
struct Cfg {
    pool: String,
    operation: String,
    prefix: String,
    objects: u64,
    keys: u64,
    work_keys: u64,
    threads: usize,
    processes: u64,
    process_index: u64,
    qd: usize,
    batch: u64,
    value_bytes: usize,
    generation: u64,
    scan_passes: u64,
    shuffled: bool,
    object_first: bool,
    idle_us: u64,
    max_seconds: u64,
    rpc_timeout: Duration,
    gate: Option<PathBuf>,
}

impl Cfg {
    fn parse(a: Vec<String>) -> Result<Self, String> {
        let mut m = BTreeMap::new();
        let mut it = a.into_iter();
        while let Some(k) = it.next() {
            if !k.starts_with("--") || m.contains_key(&k) {
                return Err(format!("unexpected or duplicate argument {k}"));
            }
            let v = it.next().ok_or_else(|| format!("missing value for {k}"))?;
            if v.starts_with("--") {
                return Err(format!("missing value for {k}"));
            }
            m.insert(k, v);
        }
        let operation = m.remove("--operation").ok_or("--operation required")?;
        if !["put", "get", "scan"].contains(&operation.as_str()) {
            return Err("--operation must be put|get|scan".into());
        }
        let prefix = m.remove("--prefix").ok_or("--prefix required")?;
        if prefix.is_empty() || prefix.len() > 180 {
            return Err("prefix must be 1..180 bytes".into());
        }
        let gate = m.remove("--gate-dir").map(PathBuf::from);
        let shuffled = match m.remove("--order").as_deref().unwrap_or("shuffled") {
            "shuffled" => true,
            "sequential" => false,
            _ => return Err("--order must be shuffled|sequential".into()),
        };
        let object_first = match m.remove("--partition").as_deref().unwrap_or("keys") {
            "keys" => false,
            "objects" => true,
            _ => return Err("--partition must be keys|objects".into()),
        };
        fn num(m: &mut BTreeMap<String, String>, k: &str, d: u64) -> Result<u64, String> {
            m.remove(k)
                .map_or(Ok(d), |v| v.parse().map_err(|_| format!("invalid {k}")))
        }
        let keys = num(&mut m, "--keys", 1_000_000)?;
        let c = Self {
            pool: String::new(),
            operation,
            prefix,
            objects: num(&mut m, "--objects", 1)?,
            keys,
            work_keys: num(&mut m, "--work-keys", keys)?,
            threads: num(&mut m, "--threads", 1)?
                .try_into()
                .map_err(|_| "threads overflow")?,
            processes: num(&mut m, "--processes", 1)?,
            process_index: num(&mut m, "--process-index", 0)?,
            qd: num(&mut m, "--qd", 1)?
                .try_into()
                .map_err(|_| "qd overflow")?,
            batch: num(&mut m, "--batch", 1024)?,
            value_bytes: num(&mut m, "--value-bytes", 256)?
                .try_into()
                .map_err(|_| "value size overflow")?,
            generation: num(&mut m, "--generation", 0)?,
            scan_passes: num(&mut m, "--scan-passes", 8)?,
            shuffled,
            object_first,
            idle_us: num(&mut m, "--idle-us", 100)?,
            max_seconds: num(&mut m, "--max-seconds", 300)?,
            rpc_timeout: Duration::from_secs(5),
            gate,
        };
        if !m.is_empty() {
            return Err(format!("unknown options: {:?}", m.keys()));
        }
        if c.keys == 0
            || c.objects == 0
            || c.objects > 100_000
            || c.work_keys > c.keys
            || c.work_keys == 0
            || c.threads == 0
            || c.threads > 128
            || c.processes == 0
            || c.processes > 128
            || c.process_index >= c.processes
            || c.qd == 0
            || c.qd > 1024
            || !(1..=1024).contains(&c.batch)
            || !(8..=1_048_576).contains(&c.value_bytes)
            || c.scan_passes == 0
            || c.max_seconds == 0
            || c.max_seconds > 3600
            || c.idle_us > 1_000_000
        {
            return Err("invalid workload bounds (see --help)".into());
        }
        c.objects.checked_mul(c.keys).ok_or("dataset overflow")?;
        c.objects
            .checked_mul(c.scan_passes)
            .ok_or("scan task overflow")?;
        c.objects
            .checked_mul(c.scan_passes)
            .and_then(|n| n.checked_mul(c.keys))
            .ok_or("scan key count overflow")?;
        Ok(c)
    }
    fn workers(&self) -> u64 {
        self.processes * self.threads as u64
    }
    fn object(&self, n: u64) -> String {
        format!("{}-o{n:05}", self.prefix)
    }
    /// (rank, number of key owners) for this object. Global workers include all processes and threads.
    fn owners(&self, worker: u64, object: u64) -> Option<(u64, u64)> {
        let workers = self.workers();
        if !self.object_first {
            Some((worker, workers))
        } else if workers <= self.objects {
            (object % workers == worker).then_some((0, 1))
        } else {
            (worker % self.objects == object).then_some((
                worker / self.objects,
                (workers - 1 - object) / self.objects + 1,
            ))
        }
    }
}

fn interval(n: u64, i: u64, workers: u64) -> (u64, u64) {
    (
        ((n as u128 * i as u128) / workers as u128) as u64,
        ((n as u128 * (i + 1) as u128) / workers as u128) as u64,
    )
}

fn key(i: u64) -> Vec<u8> {
    format!("{i:064x}").into_bytes()
}

fn stride(n: u64) -> u64 {
    fn gcd(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            (a, b) = (b, a % b);
        }
        a
    }
    let mut s = 104_729 % n;
    while gcd(s, n) != 1 {
        s += 1;
    }
    s
}

fn index(c: &Cfg, i: u64) -> u64 {
    if c.shuffled {
        ((i as u128 * stride(c.keys) as u128 + 17) % c.keys as u128) as u64
    } else {
        i
    }
}

/// Borrowed raw entries: do not sort/deduplicate before checking wire order.
pub(crate) type RawEntries<'a> = Vec<(&'a [u8], &'a [u8])>;
pub(crate) fn entries(b: &[u8], scan: bool) -> Result<(RawEntries<'_>, bool), String> {
    let mut d = Decoder::new(b);
    let n = d.count().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for _ in 0..n {
        let k = d.bytes().map_err(|e| e.to_string())?;
        let v = d.bytes().map_err(|e| e.to_string())?;
        if out
            .last()
            .is_some_and(|(prev, _): &(&[u8], &[u8])| *prev >= k)
        {
            return Err("duplicate or unordered wire key".into());
        }
        out.push((k, v));
    }
    let more = if scan {
        match d.u8().map_err(|e| e.to_string())? {
            0 => false,
            1 => true,
            _ => return Err("invalid truncated flag".into()),
        }
    } else {
        false
    };
    if !d.is_empty() {
        return Err("trailing reply bytes".into());
    }
    Ok((out, more))
}

fn payload(d: &Done, limit: Duration) -> Result<&[u8], String> {
    let r = d.reply.as_ref().ok_or_else(|| {
        if d.err.to_ascii_lowercase().contains("timeout") {
            format!(
                "WARNING TIMEOUT omap-load RPC exceeded {}s (tag={}, {})",
                limit.as_secs_f64(),
                d.tag,
                d.err
            )
        } else {
            d.err.clone()
        }
    })?;
    if r.result < 0 || r.ops.len() != 1 || r.ops[0].rval < 0 {
        return Err(format!(
            "failed reply result={} ops={:?}",
            r.result,
            r.ops.iter().map(|o| o.rval).collect::<Vec<_>>()
        ));
    }
    Ok(&r.ops[0].outdata)
}

fn check_value(c: &Cfg, k: &[u8], v: &[u8]) -> Result<(), String> {
    if v != value(k, c.generation, c.value_bytes) {
        return Err("wrong value/generation".into());
    }
    Ok(())
}

fn check_get(c: &Cfg, b: &[u8], wanted: &BTreeSet<Vec<u8>>) -> Result<(), String> {
    let (got, _) = entries(b, false)?;
    if got.len() != wanted.len() {
        return Err("missing/extra point keys".into());
    }
    for ((k, v), expected) in got.iter().zip(wanted) {
        if *k != expected {
            return Err("unexpected point key".into());
        }
        check_value(c, k, v)?;
    }
    Ok(())
}

#[derive(Debug)]
enum Request {
    Point {
        object: u64,
        wanted: BTreeSet<Vec<u8>>,
    },
    Scan {
        object: u64,
        seen: u64,
    },
}

impl Request {
    fn object(&self) -> u64 {
        match self {
            Self::Point { object, .. } | Self::Scan { object, .. } => *object,
        }
    }
    fn message(&self, c: &Cfg) -> ScriptMsg {
        let op = match self {
            Self::Scan { seen, .. } => OsdOp::omap_get_vals(
                &if *seen == 0 { vec![] } else { key(seen - 1) },
                c.batch,
                b"",
            ),
            Self::Point { wanted, .. } if c.operation == "put" => {
                let vals: KvMap = wanted
                    .iter()
                    .map(|k| (k.clone(), value(k, c.generation, c.value_bytes)))
                    .collect();
                OsdOp::omap_set_vals(&vals)
            }
            Self::Point { wanted, .. } => {
                let mut op = OsdOp::new(opwire::op::OMAP_GET_VALS_BY_KEYS);
                op.indata = wanted.encode_to_vec().expect("bounded key set").into();
                op
            }
        };
        ScriptMsg {
            ops: vec![op],
            ..Default::default()
        }
    }
}

struct ObjectWork {
    object: u64,
    position: u64,
    end: u64,
    pass: u64,
    pass_stride: u64,
}

struct Source {
    cursor: usize,
    work: Vec<ObjectWork>,
    next_scan: u64,
    workers: u64,
}

impl Source {
    fn new(c: &Cfg, worker: u64) -> Self {
        Self {
            cursor: 0,
            work: (0..c.objects)
                .filter_map(|object| {
                    let (rank, owners) = c.owners(worker, object)?;
                    let (lo, hi) = interval(c.work_keys, rank, owners);
                    Some(ObjectWork {
                        object,
                        position: lo,
                        end: hi,
                        pass: rank,
                        pass_stride: owners,
                    })
                })
                .collect(),
            next_scan: worker,
            workers: c.workers(),
        }
    }
    fn next(&mut self, c: &Cfg) -> Option<Request> {
        if c.operation == "scan" && !c.object_first {
            if self.next_scan >= c.objects * c.scan_passes {
                return None;
            }
            let object = self.next_scan % c.objects;
            self.next_scan += self.workers;
            return Some(Request::Scan { object, seen: 0 });
        }
        for _ in 0..self.work.len() {
            let len = self.work.len();
            let w = &mut self.work[self.cursor];
            self.cursor = (self.cursor + 1) % len;
            if c.operation == "scan" {
                if w.pass >= c.scan_passes {
                    continue;
                }
                w.pass = w.pass.saturating_add(w.pass_stride);
                return Some(Request::Scan {
                    object: w.object,
                    seen: 0,
                });
            }
            if w.position == w.end {
                continue;
            }
            let end = w.position.saturating_add(c.batch).min(w.end);
            let wanted = (w.position..end).map(|i| key(index(c, i))).collect();
            w.position = end;
            return Some(Request::Point {
                object: w.object,
                wanted,
            });
        }
        None
    }
}

fn scan_page(c: &Cfg, b: &[u8], seen: u64) -> Result<(u64, bool), String> {
    let (got, more) = entries(b, true)?;
    if got.len() as u64 > c.batch || (more && got.is_empty()) {
        return Err("invalid scan page size/progress".into());
    }
    let end = seen.checked_add(got.len() as u64).ok_or("scan overflow")?;
    if end > c.keys {
        return Err("scan exceeds dataset".into());
    }
    for ((k, v), i) in got.iter().zip(seen..end) {
        if *k != key(i) {
            return Err(format!("scan key mismatch at {i}"));
        }
        check_value(c, k, v)?;
    }
    if !more && end != c.keys {
        return Err(format!("short scan: {end}/{}", c.keys));
    }
    Ok((end, more))
}

fn unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("epoch")
        .as_nanos() as u64
}

fn connect(o: Opts, c: &Cfg) -> Result<(Probe, i64), String> {
    let mut p = Probe::connect(o)?;
    p.idle_sleep = Duration::from_micros(c.idle_us);
    let pool = p
        .osdmap()
        .pool_id_by_name(&c.pool)
        .ok_or("pool not found")?;
    Ok((p, pool))
}

struct Report {
    doc: Value,
    hist: Hist,
}

fn workload(mut p: Probe, pool: i64, c: &Cfg, worker: u64) -> Result<Report, String> {
    let start_ns = unix_ns();
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(c.max_seconds);
    let mut source = Source::new(c, worker);
    let mut pending = BTreeMap::new();
    let mut next_tag = 0;
    let (mut requests, mut keys, mut scans, mut peak, mut full, mut tails) =
        (0u64, 0u64, 0u64, 0usize, 0u64, 0u64);
    let mut hist = Hist::new();
    let mut object_keys = vec![0u64; c.objects as usize];
    let mut object_requests = vec![0u64; c.objects as usize];
    let mut object_scans = vec![0u64; c.objects as usize];
    loop {
        while pending.len() < c.qd {
            let Some(r) = source.next(c) else { break };
            let msg = r.message(c);
            p.submit(target(pool, &c.object(r.object())), msg, next_tag)?;
            if let Request::Point { wanted, .. } = &r {
                if wanted.len() as u64 == c.batch {
                    full += 1;
                } else {
                    tails += 1;
                }
            }
            pending.insert(next_tag, r);
            next_tag += 1;
            peak = peak.max(pending.len());
        }
        if pending.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "WARNING TIMEOUT omap-load exceeded {}s (worker {worker}, {} pending)",
                c.max_seconds,
                pending.len()
            ));
        }
        for d in p.poll() {
            let r = pending.remove(&d.tag).ok_or("unknown completion tag")?;
            let b = payload(&d, c.rpc_timeout)?;
            hist.rec(d.finished.duration_since(d.submitted).as_micros() as u64);
            requests += 1;
            let oi = r.object() as usize;
            object_requests[oi] += 1;
            match r {
                Request::Point { wanted, .. } => {
                    if c.operation == "get" {
                        check_get(c, b, &wanted)?;
                    }
                    keys += wanted.len() as u64;
                    object_keys[oi] += wanted.len() as u64;
                }
                Request::Scan { object, seen } => {
                    let (end, more) = scan_page(c, b, seen)?;
                    keys += end - seen;
                    object_keys[oi] += end - seen;
                    if more {
                        let r = Request::Scan { object, seen: end };
                        p.submit(target(pool, &c.object(object)), r.message(c), next_tag)?;
                        pending.insert(next_tag, r);
                        next_tag += 1;
                    } else {
                        scans += 1;
                        object_scans[oi] += 1;
                    }
                }
            }
        }
    }
    let elapsed = t0.elapsed().as_secs_f64();
    Ok(Report {
        doc: json!({"worker":worker,"pid":std::process::id(),
        "linux_tid":std::fs::read_link("/proc/thread-self").ok().and_then(|p|p.file_name().map(|n|n.to_string_lossy().to_string())),
        "thread":format!("{:?}",std::thread::current().id()),"start_ns":start_ns,"end_ns":unix_ns(),
        "elapsed_seconds":elapsed,"requests":requests,"keys":keys,"complete_scans":scans,
        "peak_pending":peak,"full_batches":full,"tail_batches":tails,
        "object_work":(0..c.objects as usize).filter(|&i|object_requests[i]!=0).map(|i|
          json!({"object":i,"keys":object_keys[i],"requests":object_requests[i],"complete_scans":object_scans[i]})).collect::<Vec<_>>(),
        "latency_us":{"p50":hist.pct(0.5),"p95":hist.pct(0.95),"p99":hist.pct(0.99),"max":hist.max}}),
        hist,
    })
}

/// Parse and execute one process's share. Any incomplete/invalid run exits nonzero.
pub fn cli(a: Vec<String>, o: Opts, pool: Option<String>) -> Result<ExitCode, String> {
    let (fmt, a) = outfmt::extract(&a, false)?;
    let mut c = Cfg::parse(a)?;
    c.pool = pool.ok_or("omap-load: -p POOL required")?;
    c.rpc_timeout = o.timeout;
    let c = Arc::new(c);
    let barrier = Arc::new(Barrier::new(c.threads));
    let setup_start = Instant::now();
    let setup_error = Mutex::new(None::<String>);
    let run = |tid: usize, o: Opts, c: Arc<Cfg>, barrier: Arc<Barrier>| -> Result<Report, String> {
        let worker = c.process_index * c.threads as u64 + tid as u64;
        let ready: Result<(Probe, i64), String> = (|| {
            let (mut p, pool) = connect(o, &c)?;
            // Empty key lookup warms the OSD connection without modifying the dataset.
            let r = Request::Point {
                object: if c.object_first {
                    worker % c.objects
                } else {
                    0
                },
                wanted: BTreeSet::new(),
            };
            let mut warm_cfg = (*c).clone();
            warm_cfg.operation = "get".into();
            p.submit(target(pool, &c.object(r.object())), r.message(&warm_cfg), 0)?;
            while p.in_flight() != 0 {
                for d in p.poll() {
                    // A not-yet-created population object is expected to return ENOENT.
                    if d.reply.as_ref().is_none_or(|r| r.result != -2) {
                        payload(&d, c.rpc_timeout)?;
                    }
                }
            }
            Ok((p, pool))
        })();
        if let Err(e) = &ready {
            *setup_error.lock().expect("setup lock") = Some(e.clone());
        }
        barrier.wait();
        // Every worker reaches both barriers even on setup failure: no deadlock.
        let setup_ok = setup_error.lock().expect("setup lock").is_none();
        if tid == 0
            && setup_ok
            && let Err(e) = gate(&c)
        {
            *setup_error.lock().expect("setup lock") = Some(e);
        }
        barrier.wait();
        if let Some(e) = setup_error.lock().expect("setup lock").clone() {
            return Err(e);
        }
        let (p, pool) = ready?;
        workload(p, pool, &c, worker)
    };
    let mut reports = Vec::new();
    std::thread::scope(|s| {
        let handles: Vec<_> = (1..c.threads)
            .map(|tid| {
                let (o, c, b) = (o.clone(), c.clone(), barrier.clone());
                let run = &run;
                s.spawn(move || run(tid, o, c, b))
            })
            .collect();
        reports.push(run(0, o, c.clone(), barrier.clone()));
        for h in handles {
            reports.push(h.join().unwrap_or_else(|_| Err("worker panic".into())));
        }
    });
    let mut hist = Hist::new();
    let mut rows = Vec::new();
    let mut errors = Vec::new();
    for r in reports {
        match r {
            Ok(r) => {
                hist.merge(&r.hist);
                rows.push(r.doc);
            }
            Err(e) => {
                eprintln!("omap-load: {e}");
                errors.push(e);
            }
        }
    }
    let doc = json!({"schema":1,"ok":errors.is_empty(),"errors":errors,"operation":c.operation,
        "pool":c.pool,"prefix":c.prefix,"objects":c.objects,"keys_per_object":c.keys,
        "work_keys_per_object":c.work_keys,"dataset_keys":c.keys*c.objects,
        "processes":c.processes,"process_index":c.process_index,"threads":c.threads,
        "qd_per_worker":c.qd,"batch":c.batch,"value_bytes":c.value_bytes,"key_bytes":64,
        "generation":c.generation,"scan_passes":c.scan_passes,"order":if c.shuffled {"shuffled"} else {"sequential"},
        "partition":if c.object_first {"objects"} else {"keys"},
        "idle_us":c.idle_us,"max_seconds":c.max_seconds,
        "rpc_timeout_seconds":c.rpc_timeout.as_secs_f64(),"latency_scope":"RPC submission to completion; throughput includes build/validation",
        "total_seconds_including_setup":setup_start.elapsed().as_secs_f64(),
        "latency_us":{"p50":hist.pct(0.5),"p95":hist.pct(0.95),"p99":hist.pct(0.99),"max":hist.max},
        "workers":rows});
    println!("{}", fmt.doc(&doc));
    Ok(if errors.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn gate(c: &Cfg) -> Result<(), String> {
    let Some(dir) = &c.gate else {
        return Ok(());
    };
    std::fs::write(
        dir.join(format!("ready-{}", c.process_index)),
        format!("{}\n", std::process::id()),
    )
    .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while !dir.join("go").is_file() {
        if Instant::now() >= deadline {
            return Err("WARNING TIMEOUT omap-load gate exceeded 30s".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cfg(extra: &[&str]) -> Cfg {
        let mut a = vec!["--operation", "put", "--prefix", "test", "--keys", "17"];
        a.extend(extra);
        Cfg::parse(a.into_iter().map(String::from).collect()).unwrap()
    }
    fn encoded(rows: &[(Vec<u8>, Vec<u8>)], more: Option<u8>) -> Vec<u8> {
        let mut b = (rows.len() as u32).to_le_bytes().to_vec();
        for (k, v) in rows {
            b.extend_from_slice(&(k.len() as u32).to_le_bytes());
            b.extend_from_slice(k);
            b.extend_from_slice(&(v.len() as u32).to_le_bytes());
            b.extend_from_slice(v);
        }
        if let Some(m) = more {
            b.push(m);
        }
        b
    }
    fn row(i: u64) -> (Vec<u8>, Vec<u8>) {
        let k = key(i);
        let v = value(&k, 0, 256);
        (k, v)
    }

    #[test]
    fn partition_literal_oracle_and_tails() {
        assert_eq!(
            (0..4).map(|i| interval(17, i, 4)).collect::<Vec<_>>(),
            vec![(0, 4), (4, 8), (8, 12), (12, 17)]
        );
        let c = cfg(&["--threads", "4", "--batch", "3"]);
        let mut all = BTreeSet::new();
        let mut batches = 0;
        for w in 0..4 {
            let mut s = Source::new(&c, w);
            while let Some(Request::Point { wanted, .. }) = s.next(&c) {
                batches += 1;
                for k in wanted {
                    assert!(all.insert(k));
                }
            }
        }
        assert_eq!(batches, 8);
        assert_eq!(all.len(), 17);
        assert_eq!(all, (0..17).map(key).collect());
    }
    #[test]
    fn process_and_thread_layouts_have_identical_ownership() {
        let a = cfg(&["--threads", "4", "--objects", "10"]);
        let b = cfg(&["--processes", "4", "--objects", "10"]);
        for w in 0..4 {
            let mut x = Source::new(&a, w);
            let mut y = Source::new(&b, w);
            loop {
                let (x, y) = (x.next(&a), y.next(&b));
                assert_eq!(format!("{x:?}"), format!("{y:?}"));
                if x.is_none() {
                    break;
                }
            }
        }
    }
    #[test]
    fn object_first_owns_whole_objects_in_all_requested_layouts() {
        for (processes, threads) in [(1, 1), (1, 4), (1, 8), (4, 1)] {
            let mut c = cfg(&["--partition", "objects", "--objects", "8", "--batch", "3"]);
            c.processes = processes;
            c.threads = threads;
            let mut all = BTreeSet::new();
            for worker in 0..c.workers() {
                let expected_objects: Vec<u64> = match c.workers() {
                    1 => vec![0, 1, 2, 3, 4, 5, 6, 7],
                    4 => [vec![0, 4], vec![1, 5], vec![2, 6], vec![3, 7]][worker as usize].clone(),
                    8 => vec![worker],
                    _ => unreachable!(),
                };
                let mut got = BTreeMap::<u64, BTreeSet<Vec<u8>>>::new();
                let mut source = Source::new(&c, worker);
                while let Some(Request::Point { object, wanted }) = source.next(&c) {
                    for k in wanted {
                        assert!(all.insert((object, k.clone())), "no duplicate ownership");
                        assert!(got.entry(object).or_default().insert(k));
                    }
                }
                assert_eq!(got.keys().copied().collect::<Vec<_>>(), expected_objects);
                for keys in got.values() {
                    assert_eq!(*keys, (0..17).map(key).collect());
                }
            }
            assert_eq!(all.len(), 8 * 17);
        }
    }

    #[test]
    fn object_first_splits_keys_only_among_excess_workers_for_that_object() {
        let c = cfg(&[
            "--partition",
            "objects",
            "--objects",
            "3",
            "--threads",
            "10",
            "--order",
            "sequential",
        ]);
        // Literal oracle: interleaved worker groups, four owners of object0, three of1/2.
        let expected = [
            (0, 0, 4),
            (1, 0, 5),
            (2, 0, 5),
            (0, 4, 8),
            (1, 5, 11),
            (2, 5, 11),
            (0, 8, 12),
            (1, 11, 17),
            (2, 11, 17),
            (0, 12, 17),
        ];
        let mut all = BTreeSet::new();
        for (worker, (obj, lo, hi)) in expected.into_iter().enumerate() {
            let mut source = Source::new(&c, worker as u64);
            let mut got = BTreeSet::new();
            while let Some(Request::Point { object, wanted }) = source.next(&c) {
                assert_eq!(object, obj);
                for k in wanted {
                    assert!(all.insert((object, k.clone())));
                    got.insert(k);
                }
            }
            assert_eq!(got, (lo..hi).map(key).collect());
        }
        assert_eq!(all.len(), 3 * 17);
    }

    #[test]
    fn object_first_scans_keep_object_owners_and_count_complete_traversals() {
        for (objects, workers, passes) in [(8, 1, 8), (8, 4, 8), (8, 8, 8), (5, 3, 7), (3, 10, 2)] {
            let mut c = cfg(&["--partition", "objects"]);
            c.operation = "scan".into();
            c.objects = objects;
            c.threads = workers;
            c.scan_passes = passes;
            let mut counts = vec![0; objects as usize];
            for worker in 0..workers as u64 {
                let mut source = Source::new(&c, worker);
                while let Some(Request::Scan { object, seen }) = source.next(&c) {
                    assert_eq!(seen, 0);
                    if workers as u64 <= objects {
                        assert_eq!(object % workers as u64, worker);
                    } else {
                        assert_eq!(object, worker % objects);
                    }
                    counts[object as usize] += 1;
                }
            }
            assert_eq!(counts, vec![passes; objects as usize]);
        }
    }

    #[test]
    fn object_first_global_worker_identity_is_process_layout_independent() {
        let a = cfg(&["--partition", "objects", "--objects", "8", "--threads", "8"]);
        let b = cfg(&[
            "--partition",
            "objects",
            "--objects",
            "8",
            "--threads",
            "2",
            "--processes",
            "4",
        ]);
        for worker in 0..8 {
            let mut x = Source::new(&a, worker);
            let mut y = Source::new(&b, worker);
            loop {
                let (x, y) = (x.next(&a), y.next(&b));
                assert_eq!(format!("{x:?}"), format!("{y:?}"));
                if x.is_none() {
                    break;
                }
            }
        }
    }
    #[test]
    fn fewer_keys_than_workers_and_bijections() {
        for n in 1..50 {
            let mut c = cfg(&[]);
            c.keys = n;
            c.work_keys = n;
            c.threads = 8;
            let mut all = BTreeSet::new();
            for w in 0..8 {
                let mut s = Source::new(&c, w);
                while let Some(Request::Point { wanted, .. }) = s.next(&c) {
                    for k in wanted {
                        assert!(all.insert(k));
                    }
                }
            }
            assert_eq!(all, (0..n).map(key).collect());
        }
    }
    #[test]
    fn scan_tasks_partition_across_workers() {
        let mut c = cfg(&["--threads", "8", "--objects", "10", "--scan-passes", "8"]);
        c.operation = "scan".into();
        let mut counts = [0; 10];
        for w in 0..8 {
            let mut s = Source::new(&c, w);
            while let Some(Request::Scan { object, seen }) = s.next(&c) {
                assert_eq!(seen, 0);
                counts[object as usize] += 1;
            }
        }
        assert_eq!(counts, [8; 10]);
    }
    #[test]
    fn raw_map_rejects_duplicates_unordered_trailing_malformed() {
        for rows in [vec![row(0), row(0)], vec![row(1), row(0)]] {
            assert!(entries(&encoded(&rows, None), false).is_err());
        }
        let mut b = encoded(&[row(0)], None);
        b.push(0);
        assert!(entries(&b, false).is_err());
        assert!(entries(&[255, 255, 255, 255], false).is_err());
        let mut b = encoded(&[row(0)], None);
        b.pop();
        assert!(entries(&b, false).is_err());
        assert!(entries(&encoded(&[], Some(2)), true).is_err());
    }
    #[test]
    fn exact_point_keys_and_generation() {
        let c = cfg(&[]);
        let wanted = BTreeSet::from([key(0), key(1)]);
        assert!(check_get(&c, &encoded(&[row(0), row(1)], None), &wanted).is_ok());
        assert!(check_get(&c, &encoded(&[row(0)], None), &wanted).is_err());
        assert!(check_get(&c, &encoded(&[row(0), row(2)], None), &wanted).is_err());
        let mut c = c;
        c.generation = 1;
        assert!(check_get(&c, &encoded(&[row(0), row(1)], None), &wanted).is_err());
    }
    #[test]
    fn scan_short_truncated_page_is_not_eof() {
        let c = cfg(&[]);
        assert_eq!(
            scan_page(&c, &encoded(&[row(0)], Some(1)), 0).unwrap(),
            (1, true)
        );
        assert!(scan_page(&c, &encoded(&[], Some(1)), 0).is_err());
        assert!(scan_page(&c, &encoded(&[row(0)], Some(0)), 0).is_err());
        assert!(scan_page(&c, &encoded(&[row(0)], Some(1)), 1).is_err());
        assert!(scan_page(&c, &encoded(&[row(2)], Some(1)), 1).is_err());
        assert_eq!(
            scan_page(&c, &encoded(&[row(16)], Some(0)), 16).unwrap(),
            (17, false)
        );
        assert!(scan_page(&c, &encoded(&[row(17)], Some(0)), 17).is_err());
    }
    #[test]
    fn cli_rejects_missing_duplicate_zero_and_overflow() {
        for extra in [
            vec!["--qd"],
            vec!["--qd", "0"],
            vec!["--qd", "2", "--qd", "3"],
            vec!["--process-index", "1"],
            vec!["--objects", "18446744073709551615"],
            vec!["--max-seconds", "NaN"],
            vec!["--unknown", "1"],
            vec!["--value-bytes", "7"],
            vec!["--partition", "invalid"],
        ] {
            let mut a: Vec<String> = ["--operation", "get", "--prefix", "t"]
                .into_iter()
                .map(String::from)
                .collect();
            a.extend(extra.into_iter().map(String::from));
            assert!(Cfg::parse(a).is_err());
        }
    }
}
