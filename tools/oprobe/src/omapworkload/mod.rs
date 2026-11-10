// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Configurable cluster-independent OMAP cycles. Counts are RPCs, QD is per client.
//! Known-live FIFO reservations span submission through checked ACK|ONDISK completion.
//! Latency/resource instrumentation is optional; correctness and final exact scans are not.
mod config;
mod metrics;
mod model;
#[cfg(test)]
mod tests;
use crate::client::{Done, Opts, Probe, Target};
use crate::script::ScriptMsg;
use config::{Config, Op};
use metrics::{Sampler, Stats};
use model::{Key, Model, Request, key, value};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

pub const HELP: &str = "omap-workload -p POOL --prefix NAME --output-dir FRESH_DIR [options]\n\
  --objects N --key-bytes N --value-bytes N   defaults 1/48/300\n\
  --prefill N --batch N --clients N --qd N    defaults 250000/256/8/1\n\
  --operations insert,delete                 ordered cyclic RPCs; also update/read\n\
  --ops-per-client N | --seconds N           exactly N requests or timed run (default 60s)\n\
  --metrics throughput,latency,client-cpu,osd-cpu,rss,writes | --all\n\
                 default throughput; --all selects instrumentation, not traffic\n\
  --osd-pid PID --block-stat /sys/.../stat    repeatable explicit local resource targets\n\
  --interval N --max-seconds N --max-live-keys N  defaults 60/3600/10000000\n\
  --plan --format plain|json|json-pretty      plan never connects or creates files\n\
Uses standard connection/namespace/locator options. Creates objects exclusively;\n\
never formats devices, deletes pools, or cleans up existing objects. Full prefill\n\
and final key/value validation outside timing. QD counts outstanding RPCs, not\n\
keys or synchronous lanes. Existing-key ops require QD*batch prefill/owner/object.\n\
Read/update/delete reserve acknowledged FIFO keys; inserts become eligible on ACK.\n\
Timed late completions drain separately. Live-set/key-space exhaustion fails loudly.\n\
Remote resources without local targets are explicitly unavailable, never zero.\n";

trait Transport {
    fn submit(&mut self, object: usize, op: opwire::OsdOp, tag: u64) -> Result<(), String>;
    fn poll(&mut self) -> Vec<Done>;
}
struct Wire {
    probe: Probe,
    pool: i64,
    config: Config,
}
impl Wire {
    fn connect(o: Opts, c: &Config) -> Result<Self, String> {
        let mut probe = Probe::connect(o)?;
        probe.idle_sleep = Duration::ZERO;
        let pool = probe
            .osdmap()
            .pool_id_by_name(&c.pool)
            .ok_or("pool not found")?;
        Ok(Self {
            probe,
            pool,
            config: c.clone(),
        })
    }
    fn target(&self, object: usize) -> Target {
        Target {
            pool: self.pool,
            oid: format!("{}.o{object:08x}", self.config.prefix).into_bytes(),
            nspace: self.config.namespace.as_bytes().to_vec(),
            key: self.config.locator.as_bytes().to_vec(),
            force_osd: None,
        }
    }
    fn one(&mut self, object: usize, op: opwire::OsdOp, timeout: Duration) -> Result<Done, String> {
        let expected = op.op;
        let write = matches!(
            expected,
            opwire::op::CREATE | opwire::op::OMAP_SET_VALS | opwire::op::OMAP_RM_KEYS
        );
        self.submit(object, op, 0)?;
        let deadline = Instant::now() + timeout + Duration::from_secs(15);
        loop {
            let done = self.poll();
            if done.len() > 1 {
                return Err("unexpected setup completions".into());
            }
            if let Some(d) = done.into_iter().next() {
                checked(&d, expected, write)?;
                return Ok(d);
            }
            if Instant::now() >= deadline {
                return Err("WARNING TIMEOUT OMAP setup/verification RPC exceeded deadline".into());
            }
            std::thread::yield_now();
        }
    }
}
impl Transport for Wire {
    fn submit(&mut self, object: usize, op: opwire::OsdOp, tag: u64) -> Result<(), String> {
        self.probe.submit(
            self.target(object),
            ScriptMsg {
                ops: vec![op],
                ..Default::default()
            },
            tag,
        )
    }
    fn poll(&mut self) -> Vec<Done> {
        self.probe.poll()
    }
}
fn checked(d: &Done, opcode: u16, write: bool) -> Result<&[u8], String> {
    let r = d.reply.as_ref().ok_or_else(|| {
        if d.err.to_ascii_lowercase().contains("timeout") {
            format!("WARNING TIMEOUT OMAP RPC: {}", d.err)
        } else {
            format!("missing reply: {}", d.err)
        }
    })?;
    if r.result < 0 || r.ops.len() != 1 || r.ops[0].op != opcode || r.ops[0].rval < 0 {
        return Err(format!(
            "failed OMAP reply: result={} expected opcode={opcode}",
            r.result
        ));
    }
    let durable = opwire::flag::ACK | opwire::flag::ONDISK;
    if write && (r.flags as u32 & durable) != durable {
        return Err("write completion lacks ACK|ONDISK".into());
    }
    Ok(&r.ops[0].outdata)
}
fn check_request(d: &Done, c: &Config, r: &Request) -> Result<(), String> {
    let opcode = match r.op {
        Op::Insert | Op::Update => opwire::op::OMAP_SET_VALS,
        Op::Delete => opwire::op::OMAP_RM_KEYS,
        Op::Read => opwire::op::OMAP_GET_VALS_BY_KEYS,
    };
    let data = checked(d, opcode, r.op != Op::Read)?;
    if r.op == Op::Read {
        let (got, _) = crate::omapload::entries(data, false)?;
        let expected = r
            .keys
            .iter()
            .map(|&k| Ok((key(c, k.id)?, k)))
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        if got.len() != expected.len() {
            return Err("read missing/extra keys".into());
        }
        for ((k, v), (name, expected)) in got.iter().zip(&expected) {
            if *k != name.as_slice() || *v != value(c, *expected) {
                return Err("read key/value mismatch".into());
            }
        }
    }
    Ok(())
}

struct Worker {
    client: usize,
    model: Model,
    stats: BTreeMap<String, Stats>,
    drain: BTreeMap<String, Stats>,
    windows: BTreeMap<u64, BTreeMap<String, Stats>>,
    objects: BTreeMap<usize, BTreeMap<String, u64>>,
    peak: usize,
    starved: u64,
    errors: Vec<String>,
    elapsed: f64,
    accounting: BTreeMap<usize, BTreeMap<String, Counts>>,
    unresolved: Vec<Value>,
    negotiated: Value,
}
#[derive(Default)]
struct Counts {
    prepared: u64,
    admitted: u64,
    not_admitted: u64,
    admission_errors: u64,
    succeeded: u64,
    failed: u64,
    unknown: u64,
}
impl Counts {
    fn doc(&self) -> Value {
        json!({"prepared":self.prepared,"admitted":self.admitted,"prepared_not_admitted":self.not_admitted,"admission_errors_unknown_outcome":self.admission_errors,"succeeded":self.succeeded,"failed_completion":self.failed,"unknown_admitted_outcome":self.unknown})
    }
}
fn counts<'a>(
    map: &'a mut BTreeMap<usize, BTreeMap<String, Counts>>,
    r: &Request,
) -> &'a mut Counts {
    map.entry(r.object)
        .or_default()
        .entry(r.op.name().into())
        .or_default()
}
fn unknown(r: &Request, tag: u64, reason: &str) -> Value {
    json!({"tag":tag,"object":r.object,"operation":r.op.name(),"keys":r.keys.len(),"first_key_id":r.keys.first().map(|k|k.id),"last_key_id":r.keys.last().map(|k|k.id),"reason":reason})
}
fn stat(map: &mut BTreeMap<String, Stats>, op: Op, latency: bool) -> &mut Stats {
    map.entry(op.name().into())
        .or_insert_with(|| Stats::new(latency))
}
fn run_worker(
    wire: &mut impl Transport,
    c: &Config,
    client: usize,
    model: Model,
    start: Instant,
    stop: &AtomicBool,
) -> Worker {
    run_worker_clock(wire, c, client, model, start, stop, Instant::now)
}
fn run_worker_clock(
    wire: &mut impl Transport,
    c: &Config,
    client: usize,
    model: Model,
    start: Instant,
    stop: &AtomicBool,
    mut now: impl FnMut() -> Instant,
) -> Worker {
    let mut w = Worker {
        client,
        model,
        stats: BTreeMap::new(),
        drain: BTreeMap::new(),
        windows: BTreeMap::new(),
        objects: BTreeMap::new(),
        peak: 0,
        starved: 0,
        errors: Vec::new(),
        elapsed: 0.0,
        accounting: BTreeMap::new(),
        unresolved: Vec::new(),
        negotiated: Value::Null,
    };
    let mut pending = BTreeMap::<u64, Request>::new();
    let mut issuance_ended = false;
    let mut run = || -> Result<(), String> {
        loop {
            if now().saturating_duration_since(start).as_secs_f64() > c.max_seconds as f64 {
                return Err("WARNING TIMEOUT OMAP workload exceeded --max-seconds".into());
            }
            let issuing = !issuance_ended
                && !stop.load(Ordering::Acquire)
                && c.requests.map_or_else(
                    || {
                        now().saturating_duration_since(start)
                            < Duration::from_secs(c.seconds.unwrap())
                    },
                    |n| w.model.issued < n,
                );
            if issuing {
                while pending.len() < c.qd
                    && !stop.load(Ordering::Acquire)
                    && c.requests.map_or_else(
                        || {
                            now().saturating_duration_since(start)
                                < Duration::from_secs(c.seconds.unwrap())
                        },
                        |n| w.model.issued < n,
                    )
                {
                    if now().saturating_duration_since(start) >= Duration::from_secs(c.max_seconds)
                    {
                        return Err(
                            "WARNING TIMEOUT OMAP workload exceeded --max-seconds during refill"
                                .into(),
                        );
                    }
                    let Some(r) = w.model.next(c)? else {
                        w.starved += 1;
                        if pending.is_empty() {
                            return Err(
                                "known-live dataset or tracking capacity exhausted; next operation cannot progress"
                                    .into(),
                            );
                        }
                        break;
                    };
                    let tag = w.model.issued;
                    counts(&mut w.accounting, &r).prepared += 1;
                    let encoded = match r.wire(c) {
                        Ok(encoded) => encoded,
                        Err(e) => {
                            counts(&mut w.accounting, &r).not_admitted += 1;
                            w.model.unprepare(r);
                            return Err(e);
                        }
                    };
                    if stop.load(Ordering::Acquire) {
                        counts(&mut w.accounting, &r).not_admitted += 1;
                        w.model.unprepare(r);
                        return Err("cancelled after another client failed before admission".into());
                    }
                    let elapsed = now().saturating_duration_since(start);
                    if elapsed >= Duration::from_secs(c.max_seconds)
                        || c.seconds.is_some_and(|n| elapsed >= Duration::from_secs(n))
                    {
                        counts(&mut w.accounting, &r).not_admitted += 1;
                        w.model.unprepare(r);
                        if elapsed >= Duration::from_secs(c.max_seconds) {
                            return Err("WARNING TIMEOUT OMAP workload exceeded --max-seconds before admission".into());
                        }
                        issuance_ended = true;
                        break;
                    }
                    if let Err(e) = wire.submit(r.object, encoded, tag) {
                        counts(&mut w.accounting, &r).admission_errors += 1;
                        w.unresolved.push(unknown(
                            &r,
                            tag,
                            &format!("transport admission failed; outcome unknown: {e}"),
                        ));
                        return Err(e);
                    }
                    counts(&mut w.accounting, &r).admitted += 1;
                    pending.insert(tag, r);
                    w.peak = w.peak.max(pending.len());
                }
            }
            if pending.is_empty() {
                if stop.load(Ordering::Acquire) {
                    return Err("cancelled after another client failed".into());
                }
                break;
            }
            let done = wire.poll();
            if done.is_empty() {
                std::thread::yield_now();
            }
            for d in done {
                let Some(r) = pending.remove(&d.tag) else {
                    stop.store(true, Ordering::Release);
                    w.errors
                        .push(format!("unknown/duplicate completion tag {}", d.tag));
                    continue;
                };
                let checked_completion = (|| -> Result<(Duration, u64), String> {
                    check_request(&d, c, &r)?;
                    let elapsed = d
                        .finished
                        .checked_duration_since(start)
                        .ok_or("completion precedes start")?;
                    let us = if c.latency() {
                        d.finished
                            .checked_duration_since(d.submitted)
                            .ok_or("invalid RPC clock")?
                            .as_micros()
                            .try_into()
                            .map_err(|_| "latency overflow")?
                    } else {
                        0
                    };
                    Ok((elapsed, us))
                })();
                let (elapsed, us) = match checked_completion {
                    Ok(v) => v,
                    Err(e) => {
                        stop.store(true, Ordering::Release);
                        let a = counts(&mut w.accounting, &r);
                        if d.reply.is_none() {
                            a.unknown += 1;
                        } else {
                            a.failed += 1;
                        }
                        w.unresolved.push(unknown(&r, d.tag, &e));
                        w.errors.push(e);
                        continue;
                    }
                };
                counts(&mut w.accounting, &r).succeeded += 1;
                let late = c.seconds.is_some_and(|n| elapsed >= Duration::from_secs(n));
                let map = if late { &mut w.drain } else { &mut w.stats };
                stat(map, r.op, c.latency()).record(c, r.op, us);
                if !late {
                    stat(
                        w.windows.entry(elapsed.as_secs() / c.interval).or_default(),
                        r.op,
                        c.latency(),
                    )
                    .record(c, r.op, us);
                }
                *w.objects
                    .entry(r.object)
                    .or_default()
                    .entry(r.op.name().into())
                    .or_default() += 1;
                w.model.complete(r);
            }
            if !w.errors.is_empty() {
                return Err("one or more completions failed; outstanding outcomes retained".into());
            }
        }
        Ok(())
    };
    if let Err(e) = run() {
        w.errors.push(e);
        stop.store(true, Ordering::Release);
    }
    for (tag, r) in pending {
        counts(&mut w.accounting, &r).unknown += 1;
        w.unresolved.push(unknown(
            &r,
            tag,
            "request still outstanding when worker stopped",
        ));
    }
    w.elapsed = now().saturating_duration_since(start).as_secs_f64();
    w
}
fn stats_doc(map: &BTreeMap<String, Stats>, seconds: f64, c: &Config) -> Value {
    let mut total = Stats::new(c.latency());
    let mut ops = BTreeMap::new();
    for (k, s) in map {
        total.merge(s);
        ops.insert(k.clone(), s.doc(seconds, c.metrics.contains("throughput")));
    }
    json!({"total":total.doc(seconds,c.metrics.contains("throughput")),"operations":ops})
}
fn aggregate(workers: &[Worker], c: &Config, drain: bool) -> BTreeMap<String, Stats> {
    let mut stats = BTreeMap::new();
    for w in workers {
        for (k, s) in if drain { &w.drain } else { &w.stats } {
            stats
                .entry(k.clone())
                .or_insert_with(|| Stats::new(c.latency()))
                .merge(s);
        }
    }
    stats
}
fn verify_object(
    w: &mut Wire,
    c: &Config,
    object: usize,
    expected: &[Key],
    timeout: Duration,
) -> Result<(), String> {
    verify_pages(c, object, expected, |cursor, limit| {
        w.one(
            object,
            opwire::OsdOp::omap_get_vals(cursor, limit, b""),
            timeout,
        )
    })
}
fn verify_pages(
    c: &Config,
    object: usize,
    expected: &[Key],
    mut page: impl FnMut(&[u8], u64) -> Result<Done, String>,
) -> Result<(), String> {
    let limit = (8 * 1024 * 1024 / (c.key_bytes + c.value_bytes + 16)).clamp(1, 1024);
    let mut cursor = Vec::new();
    let mut seen = 0;
    let deadline = Instant::now() + Duration::from_secs(c.max_seconds);
    for _ in 0..expected.len().saturating_add(1) {
        if Instant::now() >= deadline {
            return Err("WARNING TIMEOUT OMAP full verification exceeded deadline".into());
        }
        let d = page(&cursor, limit as u64)?;
        let (entries, more) =
            crate::omapload::entries(checked(&d, opwire::op::OMAP_GET_VALS, false)?, true)?;
        if entries.len() > limit || (entries.is_empty() && more) {
            return Err("invalid scan page/progress".into());
        }
        for (name, data) in &entries {
            if *name <= cursor.as_slice() {
                return Err("scan order/duplicate key".into());
            }
            let wanted = expected.get(seen).ok_or("extra final key")?;
            if *name != key(c, wanted.id)? || *data != value(c, *wanted) {
                return Err(format!(
                    "object {object} final key/value mismatch at {seen}"
                ));
            }
            seen += 1;
        }
        if let Some((last, _)) = entries.last() {
            cursor = last.to_vec();
        }
        if !more {
            return if seen == expected.len() {
                Ok(())
            } else {
                Err("missing final keys".into())
            };
        }
    }
    Err("scan exceeded progress bound".into())
}
type Start = Arc<(Mutex<Option<Result<Instant, String>>>, Condvar)>;
fn execute(c: &Config, o: Opts) -> Result<Value, String> {
    let mut leader = Wire::connect(o.clone(), c)?;
    for object in 0..c.objects {
        leader.one(object, opwire::OsdOp::create(true), o.timeout)?;
        let mut from = 0;
        while from < c.prefill {
            let end = from.saturating_add(c.batch as u64).min(c.prefill);
            let r = Request {
                op: Op::Insert,
                object,
                keys: (from..end).map(|id| Key { id, version: 0 }).collect(),
                version: 0,
            };
            leader.one(object, r.wire(c)?, o.timeout)?;
            from = end;
        }
        verify_object(
            &mut leader,
            c,
            object,
            &(0..c.prefill)
                .map(|id| Key { id, version: 0 })
                .collect::<Vec<_>>(),
            o.timeout,
        )?;
    }
    let signal: Start = Arc::new((Mutex::new(None), Condvar::new()));
    let stop = AtomicBool::new(false);
    let mut sampler = None;
    let mut common_start = None;
    let (mut workers, controller_errors) = std::thread::scope(
        |scope| -> Result<(Vec<Worker>, Vec<String>), String> {
            let (tx, rx) = mpsc::channel();
            let (finished_tx, finished_rx) = mpsc::channel();
            let mut handles = Vec::new();
            let setup_deadline = Instant::now() + Duration::from_secs(120);
            let mut error = None;
            for client in 0..c.clients {
                let ready = tx.clone();
                let signal = signal.clone();
                let opts = o.clone();
                let stop = &stop;
                let finished = finished_tx.clone();
                let spawn=std::thread::Builder::new().name(format!("omap-client-{client}")).spawn_scoped(scope,move || {
                let result = (|| -> Result<Worker, String> {
                    let mut setup_opts=opts.clone();setup_opts.timeout=setup_opts.timeout.min(Duration::from_secs(120));
                    let setup = Wire::connect(setup_opts, c).and_then(|mut w| {
                        for obj in c.owned(client) {
                            if stop.load(Ordering::Acquire)||Instant::now()>=setup_deadline{return Err("WARNING TIMEOUT OMAP client setup exceeded deadline or cancelled".into());}
                            w.one(obj, opwire::OsdOp::omap_get_vals(b"", 0, b""), opts.timeout.min(Duration::from_secs(120)))?;
                        }
                        w.probe.opts.timeout=opts.timeout;
                        Ok((w, Model::new(c, client)))
                    });
                    let _ = ready.send(setup.as_ref().map(|_| ()).map_err(Clone::clone));
                    let (lock, cv) = &*signal;
                    let state = cv
                        .wait_timeout_while(
                            lock.lock().map_err(|_| "start lock poisoned")?,
                            Duration::from_secs(120),
                            |s| s.is_none(),
                        )
                        .map_err(|_| "start lock poisoned")?
                        .0
                        .clone()
                        .ok_or("WARNING TIMEOUT OMAP common start exceeded 120s")??;
                    let (mut wire, model) = setup?;
                    let mut worker=run_worker(&mut wire,c,client,model,state,stop);
                    worker.negotiated=json!(wire.probe.connection_modes());Ok(worker)
                })();
                let _ = finished.send(result);
            });
                match spawn {
                    Ok(h) => handles.push(h),
                    Err(e) => {
                        error = Some(format!("cannot spawn OMAP client: {e}"));
                        break;
                    }
                }
            }
            drop(tx);
            drop(finished_tx);
            let spawned = handles.len();
            for _ in 0..if error.is_none() { spawned } else { 0 } {
                match rx.recv_timeout(setup_deadline.saturating_duration_since(Instant::now())) {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        error = Some(e);
                        break;
                    }
                    Err(_) => {
                        error = Some("WARNING TIMEOUT OMAP client readiness exceeded 120s".into());
                        break;
                    }
                }
            }
            if error.is_some() {
                stop.store(true, Ordering::Release);
            }
            if error.is_none() {
                match Sampler::new(c) {
                    Ok(s) => sampler = s,
                    Err(e) => error = Some(e),
                }
            }
            let start = Instant::now();
            common_start = Some(start);
            *signal.0.lock().map_err(|_| "start lock poisoned")? =
                Some(error.clone().map_or(Ok(start), Err));
            signal.1.notify_all();
            // The controller waits on bounded intervals and samples outside workers;
            // no resource thread or counter reads exist in throughput-only mode.
            let mut all = Vec::new();
            let mut next_sample = start + Duration::from_secs(c.interval);
            let mut resource_ended = false;
            while all.len() < spawned {
                let now = Instant::now();
                let end = c.seconds.map(|n| start + Duration::from_secs(n));
                if !resource_ended && (now >= next_sample || end.is_some_and(|t| now >= t)) {
                    if let Some(s) = &mut sampler
                        && let Err(e) = s.sample()
                    {
                        error = Some(e);
                        stop.store(true, Ordering::Release);
                        resource_ended = true;
                    }
                    next_sample = now + Duration::from_secs(c.interval);
                    if end.is_some_and(|t| now >= t) {
                        resource_ended = true;
                    }
                }
                let until = if resource_ended {
                    Duration::from_millis(50)
                } else {
                    end.map_or(next_sample, |e| e.min(next_sample))
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(50))
                };
                match finished_rx.recv_timeout(until) {
                    Ok(r) => all.push(r),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => {
                        error = Some("worker result channel closed".into());
                        break;
                    }
                }
            }
            if !resource_ended
                && let Some(s) = &mut sampler
                && let Err(e) = s.sample()
            {
                error = Some(e);
            }
            let mut errors: Vec<_> = error.into_iter().collect();
            for h in handles {
                if h.join().is_err() {
                    errors.push("OMAP worker panicked".into());
                }
            }
            let mut workers = Vec::new();
            for r in all {
                match r {
                    Ok(w) => workers.push(w),
                    Err(e) => errors.push(e),
                }
            }
            Ok((workers, errors))
        },
    )?;
    workers.sort_unstable_by_key(|w| w.client);
    let start = common_start.ok_or("no common start")?;
    let seconds = c
        .seconds
        .map_or_else(
            || workers.iter().map(|w| w.elapsed).fold(0.0, f64::max),
            |n| n as f64,
        )
        .max(f64::MIN_POSITIVE);
    let mut errors: Vec<_> = workers
        .iter()
        .flat_map(|w| w.errors.iter().cloned())
        .collect();
    errors.extend(controller_errors);
    let mut verification =
        json!({"ok":false,"reason":"workload failed; mutation outcomes may be unknown"});
    if errors.is_empty() {
        let verify = (|| -> Result<u64, String> {
            let mut checked_keys = 0u64;
            for object in 0..c.objects {
                let mut expected: Vec<_> = workers
                    .iter()
                    .filter_map(|w| w.model.queues.get(&object))
                    .flatten()
                    .copied()
                    .collect();
                expected.sort_unstable_by_key(|k| k.id);
                if expected.windows(2).any(|p| p[0].id == p[1].id) {
                    return Err("duplicate final ownership".into());
                }
                verify_object(&mut leader, c, object, &expected, o.timeout)?;
                checked_keys += expected.len() as u64;
            }
            Ok(checked_keys)
        })();
        match verify {
            Ok(checked_keys) => {
                verification = json!({"ok":true,"objects":c.objects,"keys_checked":checked_keys,"scope":"full exact live key/value enumeration, including absence of extras"})
            }
            Err(e) => {
                verification = json!({"ok":false,"reason":e});
                errors.push(e);
            }
        }
    }
    finish_report(c, &workers, errors, verification, sampler, start, seconds)
}
fn finish_report(
    c: &Config,
    workers: &[Worker],
    errors: Vec<String>,
    verification: Value,
    sampler: Option<Sampler>,
    start: Instant,
    seconds: f64,
) -> Result<Value, String> {
    let stats = aggregate(workers, c, false);
    let drain = aggregate(workers, c, true);
    let mut windows = BTreeMap::<u64, BTreeMap<String, Stats>>::new();
    for w in workers {
        for (&i, ops) in &w.windows {
            for (k, s) in ops {
                windows
                    .entry(i)
                    .or_default()
                    .entry(k.clone())
                    .or_insert_with(|| Stats::new(c.latency()))
                    .merge(s);
            }
        }
    }
    let mut result = json!({"schema":1,"kind":"omap-workload","ok":errors.is_empty()&&verification["ok"]==true,"config":c.document(),"errors":errors,"elapsed_seconds":seconds,
        "metrics":stats_doc(&stats,seconds,c),"drain":stats_doc(&drain,seconds,c),"verification":verification,
        "windows":windows.iter().map(|(&i,m)|{let end=(((i+1)*c.interval) as f64).min(seconds);json!({"index":i,"start_seconds":i*c.interval,"end_seconds":end,"metrics":stats_doc(m,(end-(i*c.interval) as f64).max(f64::MIN_POSITIVE),c)})}).collect::<Vec<_>>(),
        "notes":["logical byte rates exclude protocol overhead; CPU100% means one core","latency includes submit/transport time, not payload construction or reply validation; throughput includes client overhead","duration drain counts are normalized to foreground seconds, not a drain throughput measurement","requested QD is a cap; data dependencies or short runs may achieve less"],
        "clients":workers.iter().map(|w|json!({"client":w.client,"submitted":w.accounting.values().flat_map(|ops|ops.values()).map(|a|a.admitted).sum::<u64>(),"negotiated_osd_modes":w.negotiated,"accounting":w.accounting.iter().map(|(o,ops)|(o.to_string(),ops.iter().map(|(op,a)|(op,a.doc())).collect::<BTreeMap<_,_>>())).collect::<BTreeMap<_,_>>(),"unresolved":w.unresolved,"peak_pending":w.peak,"data_starvation_events":w.starved,"live_keys":w.model.keys(),"elapsed_seconds_including_drain":w.elapsed,"errors":w.errors,"metrics":stats_doc(&w.stats,seconds,c),"drain":stats_doc(&w.drain,seconds,c),"object_requests":w.objects,"windows":w.windows.iter().map(|(i,m)|{let end=(((i+1)*c.interval) as f64).min(seconds);json!({"index":i,"start_seconds":i*c.interval,"end_seconds":end,"metrics":stats_doc(m,(end-(i*c.interval) as f64).max(f64::MIN_POSITIVE),c)})}).collect::<Vec<_>>()})).collect::<Vec<_>>()});
    if let Some(s) = sampler {
        result["resources"] = s.doc(c, start, seconds);
        if let Err(e) = std::fs::write(
            c.output.join("resources.jsonl"),
            s.samples
                .iter()
                .map(|v| format!("{v}\n"))
                .collect::<String>(),
        ) {
            result["ok"] = json!(false);
            result["errors"]
                .as_array_mut()
                .unwrap()
                .push(json!(format!("resource evidence write failed: {e}")));
            result["resources"]["retained_samples"] = json!(s.samples);
        }
    }
    Ok(result)
}
fn connection(o: &Opts) -> Value {
    json!({"conf":o.conf,"mon":o.mon,"entity":o.entity,"mode_requested":o.mode,"rpc_timeout_seconds":o.timeout.as_secs_f64(),"resend_lost":o.resend_lost,"verbose":o.verbose,"credential_contents":"omitted"})
}
pub fn cli(
    args: Vec<String>,
    o: Opts,
    pool: Option<String>,
    namespace: String,
    locator: String,
    out: Option<String>,
) -> Result<ExitCode, String> {
    let c = Config::parse(args, pool, namespace, locator, out)?;
    if !matches!(o.mode.as_str(), "crc" | "secure" | "auto") {
        return Err("--mode must be crc, secure or auto".into());
    }
    if o.timeout.is_zero()
        || Instant::now()
            .checked_add(o.timeout)
            .and_then(|t| t.checked_add(Duration::from_secs(15)))
            .is_none()
    {
        return Err("invalid RPC timeout".into());
    }
    if o.resend_lost {
        return Err("omap-workload refuses --resend: mutation outcomes must not be guessed".into());
    }
    let mut manifest = c.document();
    manifest["connection"] = connection(&o);
    if c.plan {
        let d = manifest;
        if c.format == "plain" {
            println!(
                "{}",
                serde_json::to_string_pretty(&d).map_err(|e| e.to_string())?
            );
        } else if c.format == "json-pretty" {
            println!("{d:#}");
        } else {
            println!("{d}");
        }
        return Ok(ExitCode::SUCCESS);
    }
    std::fs::create_dir(&c.output).map_err(|e| format!("fresh output directory required: {e}"))?;
    std::fs::write(c.output.join("manifest.json"), format!("{manifest:#}\n"))
        .map_err(|e| e.to_string())?;
    let mut result=execute(&c,o).unwrap_or_else(|e|json!({"schema":1,"kind":"omap-workload","ok":false,"config":c.document(),"errors":[e],"verification":{"ok":false,"reason":"setup/workload/verification failed; unknown mutation outcome"}}));
    if let Some(clients) = result.get("clients") {
        manifest["negotiated_osd_modes_by_client"] = json!(
            clients
                .as_array()
                .unwrap()
                .iter()
                .map(|w| json!({"client":w["client"],"osds":w["negotiated_osd_modes"]}))
                .collect::<Vec<_>>()
        );
    }
    result["config"] = manifest.clone();
    std::fs::write(c.output.join("manifest.json"), format!("{manifest:#}\n"))
        .map_err(|e| e.to_string())?;
    std::fs::write(c.output.join("summary.json"), format!("{result:#}\n"))
        .map_err(|e| e.to_string())?;
    if c.format == "plain" {
        println!(
            "ok={} requests={} elapsed_s={} metrics={} output={}",
            result["ok"],
            result["metrics"]["total"]["requests"],
            result["elapsed_seconds"],
            result["metrics"],
            c.output.display()
        );
    } else if c.format == "json-pretty" {
        println!("{result:#}");
    } else {
        println!("{result}");
    }
    Ok(if result["ok"] == true {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}
