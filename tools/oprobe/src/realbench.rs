// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `oprobe rgwindex` and `oprobe dirfrag`: omap workloads shaped like real users (doc/spec/rgw-osd-surface.md,
//! doc/spec/cls_rgw.md, doc/spec/cephfs-osd-surface.md), not like `omapbench` (64 B keys, 256 B values, one big object).
//!
//! * rgwindex: bucket index shards `.dir.<bucket>.<n>`; a PUT = two messages on the SAME shard object (prepare, complete),
//!   each [stat guard, omap_get_header, omap_set_header, omap_set(1..2 keys)] (plain-op emulation of cls_rgw
//!   bucket_prepare_op / bucket_complete_op, identical against every OSD); LIST = bucket_list paging of 1000 entries.
//! * dirfrag: CephFS directory fragments; commit = ONE message [stat guard, omap_set_header, omap_set(dentries),
//!   omap_rm_keys(dentries)] with one commit in flight per directory; fetch = header + get_vals pages of 1024.
//!
//! Every client thread owns one `Probe` (no shared locks on the hot path); chains of dependent messages (prepare then
//! complete, page after page) run in the slots of a pipelined `drive` loop.

use crate::client::{Done, Opts, Probe};
use crate::omapbench::{
    Hist, MAX_CLIENTS, MAX_QD, ObjState, Rng, flag, num, num_max, secs, splitmix, take, target,
    value,
};
use crate::script::ScriptMsg;
use opwire::{KvMap, OmapValsOut, OsdOp, op as code};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

pub const HELP_RGW: &str = "\
rgwindex -p POOL [options]   RGW bucket-index shape: N buckets x S shard objects, PUT clients (prepare+complete on one shard
  object, each [stat, get_header, set_header, set 1-2 keys]) + LIST clients (bucket_list pages) running concurrently
  --prefix S  object name prefix (default rgwindex-<time>)          --buckets N (1)  --shards N (11)  --entries N (100000 per shard)
  --put-clients N (16)  --put-qd N (2: PUT chains per client)       --put-shards N (all: PUTs hit only the first N shards of every bucket)
  --list-clients N (4)  --list-qd N (1)  --page N (1000)             --val-len N (300)  --header-len N (192)
  --pop-clients N (16)  --pop-qd N (4)  --batch N (1024)             --duration S (60)  --op-timeout S (60)  --del-timeout S (900)
  --map random|own (own: PUT client i always hits object i mod objects)   --spread (object names chosen so every object sits on
  its own PG, primaries balanced; cycles when objects > pg_num)   --pop-from N (populate only keys [N, entries): N = entries
  reuses populated objects; 0 default)   --del-pct N (0: share of PUT chains that are DELETEs of a populated key: prepare +
  complete [stat, get_header, set_header, rm_keys(key), set(bilog)])   --get-clients N (0) --get-qd N (1): point gets
  [omap_get_vals_by_keys(1 populated key)]   --list-pages N (0 = to the end; else pages per listing, then a new random start)
  --rewrite-shards N (0)  --rewrite-entries N (100000)  --rewrite-clients N (8): the reshard copy; DURING the timed phase N new shard
  objects `<prefix>.rewrite.<i>` are filled with --rewrite-entries keys each (batched omap_set like populate, --batch/--pop-qd), row
  `rewrite` + counter `rewrite_keys` (own window = until its keys are written), removed again after the run
  --setup-only (populate, keep, no timed phase)  --skip-setup (objects exist: same --prefix/--buckets/--shards/--entries/--spread; timed
  phase only)  --cleanup-only (remove the objects)  -- a big set is set up once, used by several timed runs (--keep) and removed last
  --seed N  --keep (do not remove the shard objects)  --format plain|json|json-pretty|jsonl (jsonl = one record per op row, then one
  per counter: {counter, n, per_s}; populate and rewrite rates use their own window)
  summary: objects_pgs / objects_primaries = distinct PGs / primary OSDs of the objects; rows: p50/p99/p999/max us.
exit 0 ok, 1 errors counted, 2 usage.
";

pub const HELP_DIR: &str = "\
dirfrag -p POOL [options]   CephFS dirfrag shape: M directory objects x K dentries (`<name>_head` -> ~500 B), commits of
  1/16/256/1024 dentries ([stat, set_header, set(batch), rm_keys(batch)], one commit in flight per dir), then fetch (header + get_vals pages)
  --prefix S  --dirs N (100)  --entries N (5000 per dir)  --active N (32: dirs receiving commits)  --batches 1,16,256,1024
  --commit-clients N (8)   --fetch-clients N (8)  --fetch-qd N (4)  --page N (1024)  --header-len N (232)
  --pop-clients N (16)  --pop-qd N (4)  --batch-pop N (1024)  --phase S (20: seconds per commit batch size and for fetch)
  --spread (dir objects on distinct PGs, primaries balanced)  --pop-from N (populate only dentries [N, entries); N = entries
  reuses populated dirs)  --fetch-clients 0 skips the fetch phase.  More commit clients than active dirs: client i commits to
  dir i mod active (several commits in flight on one dir: the hot-object case, not the MDS's one-commit-per-dirfrag rule)
  --setup-only (populate, keep, no phases)  --skip-setup (dirs exist, same --prefix/--dirs/--entries: phases only)  --cleanup-only
  --op-timeout S (60)  --del-timeout S (900)  --seed N  --keep  --format plain|json|json-pretty|jsonl
exit 0 ok, 1 errors counted, 2 usage.
";

pub const HELP_SCAN: &str = "\
omapscan -p POOL --object NAME [options]   full omap listing of ONE object, sequential pages [omap_get_vals(start_after, N)]
  (the shape of a bucket-index full listing / dirfrag fetch); counts keys and key+value bytes (also the before/after probe)
  --page N (1000)  --max-pages N (0 = to the end)  --op-timeout S (120)  --format plain|json|json-pretty|jsonl
exit 0 ok, 1 errors counted, 2 usage.
";

pub const HELP_RM: &str = "\
omaprm -p POOL --object NAME --by range|keys --begin KEY --end KEY [options]   bulk removal of the keys in [begin, end)
  range: ONE omap_rm_key_range(begin, end) message (single range delete);  keys: list pages [omap_get_vals(after, batch)] and
  remove each page with omap_rm_keys(page) until a key >= end (the paged purge shape of RGW / MDS, one client, sequential)
  --batch N (1000)  --op-timeout S (900)  --format plain|json|json-pretty|jsonl
exit 0 ok, 1 errors counted, 2 usage.
";

pub const HELP_ONE: &str = "\
oneobj -p POOL --scenario S [options]   single-object access: N clients (each its own thread + OSD connections, QD per
  client) on ONE object (--objects 1) or on N objects (--objects N: client i -> object i mod N; --spread = distinct PGs)
  scenarios: read (4 KiB random reads inside a --obj-size object)  write (4 KiB random writes)  append (sequential appends
  of --app-min..--app-max bytes; the objects are truncated to empty before the timed window, and a client truncates its object
  to empty (op roll, own metric, not in all) when its share of the object reached --app-roll bytes, so a cell never hits the
  osd_max_object_size limit (EFBIG stays a counted error, never retried))  mixed (--read-pct reads, rest writes, 4 KiB)  omap-get (point omap_get_vals_by_keys(1) and
  omap_get_vals pages of --page, half each, on --keys keys)  omap-set (omap_set_vals of --batch new keys, every other
  message omap_rm_keys of --batch keys: the client's own oldest inserts (FIFO), random pre-filled keys until enough
  exist; RGW-like keys, --val-len values)  meta (getxattr 40 %, stat 30 %,
  setxattr 15 %, omap_set 1 key 15 %: header / inode / bucket-stats shape)
  --prefix S (oneobj)  --clients N (1)  --qd N (1)  --objects N (1)  --spread  --duration S (15)  --obj-size B (4194304)
  --keys N (1000000: keys of a single omap object)  --spread-keys N (100000: keys of each of N>1 omap objects)
  --batch N (1)  --page N (100)  --val-len N (300)  --read-pct N (70)  --app-min B (4096)  --app-max B (65536)  --app-roll B (67108864)
  --setup-only (create + populate, keep)  --skip-setup (objects exist)  --cleanup-only  --keep  --op-timeout S (60)
  --op-log FILE (one TSV line per op, slowest first: trace_id (16 hex, joins the OSD dump_op_traces), gid, tid (joins classic op descriptions client.GID.0:TID), submit_unix_ns, lat_us, ok)
  --seed N  --format plain|json|json-pretty|jsonl
exit 0 ok, 1 errors counted, 2 usage.
";

// ------------------------------------------------------------------ names, values

/// S3-like object name of index `idx` (30..1100 B, mostly 30..130 B, random sort order).
pub fn s3name(idx: u64) -> Vec<u8> {
    let mut s = idx ^ 0x5333_4e41_4d45;
    let (a, b, c) = (splitmix(&mut s), splitmix(&mut s), splitmix(&mut s));
    let len = match a % 100 {
        0..=79 => 30 + (b % 51) as usize,
        80..=97 => 80 + (b % 121) as usize,
        _ => 200 + (b % 901) as usize,
    };
    let mut k = format!("data/{:04x}/", c >> 48).into_bytes();
    let mut t = c;
    while k.len() < len {
        k.extend_from_slice(format!("{:016x}", splitmix(&mut t)).as_bytes());
    }
    k.truncate(len);
    k
}

/// CephFS dentry key of index `idx`: `<name>_head`, name 10..40 B, random sort order.
pub fn dname(idx: u64) -> Vec<u8> {
    let mut s = idx ^ 0x4445_4e54_5259;
    let (a, b) = (splitmix(&mut s), splitmix(&mut s));
    let len = 10 + (a % 31) as usize;
    let mut k = format!("{:016x}{:016x}", b, splitmix(&mut s)).into_bytes();
    k.truncate(len);
    k.extend_from_slice(b"_head");
    k
}

fn header_bytes(len: usize, g: u64) -> Vec<u8> {
    value(b"header", g, len.max(8))
}

/// Dentry value size 400..600 B, derived from the key.
fn dir_val_len(k: &[u8]) -> usize {
    400 + k.iter().fold(0usize, |h, c| {
        h.wrapping_mul(31).wrapping_add(usize::from(*c))
    }) % 201
}

// ------------------------------------------------------------------ stats

#[derive(Default, Debug)]
pub struct Out {
    stats: BTreeMap<String, (Hist, u64)>,
    /// Counters of static names (`list_entries`, `dentries`): no allocation on the stats path.
    ctr: BTreeMap<&'static str, u64>,
    /// Completed PUT chains per object index (the rgwindex shard rows).
    put_obj: Vec<u64>,
    kinds: BTreeMap<String, u64>,
    /// Own measuring window (seconds) of a label or counter whose work ran outside the timed phase (populate, rewrite);
    /// every other rate uses the report's duration.
    secs: BTreeMap<String, f64>,
    /// Per-op records for `--op-log` (only when `log_on`).
    log: Vec<OpLog>,
    log_on: bool,
    /// Distinct errors (op + object + errno/text) with first occurrence and count; failure path only.
    errs: Errors,
}

/// Key of one distinct error: op name, object name and the errno (`errno N (strerror)`) or error text.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct ErrorKey {
    op: String,
    object: String,
    detail: String,
}

/// First occurrence (Unix ns) and count of one distinct error.
#[derive(Clone, Debug)]
struct ErrorHit {
    first_unix_ns: u64,
    count: u64,
}

/// Aggregates the distinct errors of a run. Only the failure path touches it (no allocation, formatting or locking
/// when an op succeeds).
#[derive(Debug, Default)]
struct Errors {
    hits: BTreeMap<ErrorKey, ErrorHit>,
}

impl Errors {
    /// Record one failure; `Some` when the key is new in this collector (first occurrence).
    fn record(
        &mut self,
        op: &str,
        object: &str,
        kind: &str,
        now_unix_ns: u64,
    ) -> Option<(ErrorKey, ErrorHit)> {
        let key = ErrorKey {
            op: op.into(),
            object: object.into(),
            detail: error_detail(kind),
        };
        match self.hits.entry(key) {
            std::collections::btree_map::Entry::Occupied(mut e) => {
                e.get_mut().count += 1;
                None
            }
            std::collections::btree_map::Entry::Vacant(v) => {
                let key = v.key().clone();
                let hit = ErrorHit {
                    first_unix_ns: now_unix_ns,
                    count: 1,
                };
                v.insert(hit.clone());
                Some((key, hit))
            }
        }
    }
    /// First-occurrence line of one key and the current count.
    fn line(key: &ErrorKey, hit: &ErrorHit) -> String {
        format!(
            "oprobe error: op={} object={} {} first_unix_ns={} count={}",
            key.op,
            if key.object.is_empty() {
                "-"
            } else {
                &key.object
            },
            key.detail,
            hit.first_unix_ns,
            hit.count
        )
    }
    /// One summary line per distinct error with its total count (printed at the end of the run).
    fn summary_lines(&self) -> Vec<String> {
        self.hits
            .iter()
            .map(|(k, h)| format!("{} (run total)", Self::line(k, h)))
            .collect()
    }
    fn merge(&mut self, o: Errors) {
        for (k, h) in o.hits {
            match self.hits.entry(k) {
                std::collections::btree_map::Entry::Occupied(mut e) => {
                    let x = e.get_mut();
                    x.count += h.count;
                    x.first_unix_ns = x.first_unix_ns.min(h.first_unix_ns);
                }
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert(h);
                }
            }
        }
    }
}

/// `errno N (strerror)` for the judge's `errno N` texts; any other error (transport, rados text) stays as it is.
fn error_detail(kind: &str) -> String {
    let Some(n) = kind
        .strip_prefix("errno ")
        .and_then(|s| s.parse::<i32>().ok())
    else {
        return kind.into();
    };
    let text = std::io::Error::from_raw_os_error(n.abs());
    format!("errno {n} ({text})")
}

/// Print the first-occurrence line once per distinct error for the whole process (other threads' `Out` instances
/// report the same key). Failure path only.
fn announce_first(key: &ErrorKey, hit: &ErrorHit) {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<BTreeSet<ErrorKey>>> =
        std::sync::OnceLock::new();
    let mut seen = SEEN
        .get_or_init(|| std::sync::Mutex::new(BTreeSet::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if seen.insert(key.clone()) {
        eprintln!("{}", Errors::line(key, hit));
    }
}

/// One completed op for `--op-log`: its OSD trace id, submit time (ns since the Unix epoch), latency, success.
#[derive(Debug)]
struct OpLog {
    key: u64,
    gid: u64,
    tid: u64,
    submit_unix_ns: u64,
    lat_us: u64,
    ok: bool,
}

/// Trace id the OSD derives from the request id of client `gid` (inc 0) and wire tid `tid`: splitmix64 finalizer over
/// (type, number, tid, inc), the join key of the OSD's `dump_op_traces` (doc/ops/op-trace.md). Never 0.
fn trace_key(gid: u64, tid: u64) -> u64 {
    let mut z = gid ^ (u64::from(denc::types::EntityName::CLIENT) << 56) ^ tid.rotate_left(17);
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    z.max(1)
}

fn unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

impl Out {
    fn ok(&mut self, label: &str, us: u64) {
        // look up by `&str`: only the first occurrence of a label allocates
        if let Some(x) = self.stats.get_mut(label) {
            x.0.rec(us);
        } else {
            self.stats.entry(label.into()).or_default().0.rec(us);
        }
    }
    fn err(&mut self, label: &str, kind: String) {
        self.err_at(label, "", kind);
    }
    /// Failure path: count the op error and, for the first occurrence of a distinct (op, object, errno/text) key,
    /// print one stderr line. `object` is "" when the failure has no object (connect, panic).
    fn err_at(&mut self, label: &str, object: &str, kind: String) {
        if let Some(x) = self.stats.get_mut(label) {
            x.1 += 1;
        } else {
            self.stats.entry(label.into()).or_default().1 += 1;
        }
        *self.kinds.entry(format!("{label}:{kind}")).or_default() += 1;
        if let Some((key, hit)) = self.errs.record(label, object, &kind, unix_ns()) {
            announce_first(&key, &hit);
        }
    }
    fn add(&mut self, c: &'static str, n: u64) {
        *self.ctr.entry(c).or_default() += n;
    }
    fn put_obj(&mut self, obj: usize) {
        if obj >= self.put_obj.len() {
            self.put_obj.resize(obj + 1, 0);
        }
        self.put_obj[obj] += 1;
    }
    fn merge(&mut self, o: Out) {
        for (k, (h, e)) in o.stats {
            let x = self.stats.entry(k).or_default();
            x.0.merge(&h);
            x.1 += e;
        }
        for (k, v) in o.ctr {
            *self.ctr.entry(k).or_default() += v;
        }
        if o.put_obj.len() > self.put_obj.len() {
            self.put_obj.resize(o.put_obj.len(), 0);
        }
        for (a, b) in self.put_obj.iter_mut().zip(o.put_obj) {
            *a += b;
        }
        for (k, v) in o.kinds {
            *self.kinds.entry(k).or_default() += v;
        }
        self.errs.merge(o.errs);
        self.secs.extend(o.secs);
        self.log.extend(o.log);
    }
    fn errors(&self) -> u64 {
        self.stats.values().map(|x| x.1).sum()
    }
}

fn us_between(d: &Done) -> u64 {
    d.finished.duration_since(d.submitted).as_micros() as u64
}

/// Ok(reply) or Err(kind): no reply, result < 0 or any op rval < 0.
fn judge(d: &Done) -> Result<&opwire::MOSDOpReply, String> {
    let Some(r) = &d.reply else {
        return Err(d.err.chars().take(60).collect());
    };
    if r.result < 0 {
        return Err(format!("errno {}", r.result));
    }
    match r.ops.iter().find(|o| o.rval < 0) {
        Some(o) => Err(format!("errno {}", o.rval)),
        None => Ok(r),
    }
}

// ------------------------------------------------------------------ pipelined driver

type Next<J> = Option<(String, ScriptMsg, J)>;

trait Work {
    type Job;
    /// A new chain; None = nothing left.
    fn start(&mut self) -> Next<Self::Job>;
    /// A finished message of a chain; Some = the next message of the chain.
    fn finish(&mut self, job: Self::Job, d: &Done, out: &mut Out) -> Next<Self::Job>;
}

struct Conn {
    p: Probe,
    pool: i64,
}

fn connect(o: &Opts, pool: &str, timeout: Duration) -> Result<Conn, String> {
    let mut o = o.clone();
    o.timeout = timeout;
    let mut p = Probe::connect(o)?;
    p.idle_sleep = Duration::from_micros(100);
    let id = p
        .osdmap()
        .pool_id_by_name(pool)
        .ok_or_else(|| format!("no pool '{pool}'"))?;
    Ok(Conn { p, pool: id })
}

/// Pipelined slots (`qd`) until `deadline` (chains stop at the deadline; in-flight messages drain).
fn drive<W: Work>(c: &mut Conn, qd: usize, deadline: Instant, w: &mut W, out: &mut Out) {
    let pool = c.pool;
    let p = &mut c.p;
    let (gid, base_i, base_u) = (p.client_gid(), Instant::now(), unix_ns());
    let mut jobs: Vec<Option<W::Job>> = (0..qd + 4).map(|_| None).collect();
    let mut free: Vec<usize> = (0..jobs.len()).collect();
    let mut exhausted = false;
    let submit = |p: &mut Probe,
                  jobs: &mut [Option<W::Job>],
                  free: &mut Vec<usize>,
                  n: Next<W::Job>,
                  out: &mut Out| {
        let Some((name, m, j)) = n else { return };
        let Some(slot) = free.pop() else { return };
        match p.submit(target(pool, &name), m, slot as u64) {
            Ok(()) => jobs[slot] = Some(j),
            Err(e) => {
                free.push(slot);
                out.err_at("submit", &name, e.chars().take(60).collect());
            }
        }
    };
    loop {
        let live = Instant::now() < deadline;
        while live && !exhausted && p.in_flight() < qd && !free.is_empty() {
            match w.start() {
                None => exhausted = true,
                n => submit(p, &mut jobs, &mut free, n, out),
            }
        }
        if (exhausted || !live) && p.in_flight() == 0 {
            break;
        }
        for d in p.poll() {
            let slot = d.tag as usize;
            let Some(j) = jobs[slot].take() else { continue };
            free.push(slot);
            let next = w.finish(j, &d, out);
            if out.log_on {
                out.log.push(OpLog {
                    key: trace_key(gid, d.tid),
                    gid,
                    tid: d.tid,
                    submit_unix_ns: base_u
                        + d.submitted.saturating_duration_since(base_i).as_nanos() as u64,
                    lat_us: us_between(&d),
                    ok: judge(&d).is_ok(),
                });
            }
            if live || exhausted {
                submit(p, &mut jobs, &mut free, next, out);
            }
        }
    }
}

fn msg(ops: Vec<OsdOp>) -> ScriptMsg {
    ScriptMsg {
        ops,
        ..Default::default()
    }
}

fn one(k: Vec<u8>, v: Vec<u8>) -> KvMap {
    let mut m = KvMap::new();
    m.insert(k, v);
    m
}

type Handle = std::thread::JoinHandle<Out>;

/// Spawn `n` threads running `f(i)`; each returns an `Out`.
fn run_threads(n: usize, f: impl Fn(usize) -> Out + Send + Sync + 'static) -> Vec<Handle> {
    let f = Arc::new(f);
    (0..n)
        .map(|i| {
            let f = f.clone();
            std::thread::spawn(move || f(i))
        })
        .collect()
}

fn join_all(hs: Vec<Handle>, into: &mut Out) {
    for h in hs {
        match h.join() {
            Ok(o) => into.merge(o),
            Err(_) => into.err("thread", "panic".into()),
        }
    }
}

fn fail_out(what: &str, e: String) -> Out {
    let mut o = Out::default();
    o.err(what, e);
    o
}

// ------------------------------------------------------------------ populate (shared)

/// Populate tasks: (object index, batch index); batches of `batch` keys over objects of `n` keys each.
struct PopWork {
    names: Arc<Vec<String>>,
    tasks: Arc<Vec<(usize, u64)>>,
    next: Arc<AtomicU64>,
    from: u64,
    n: u64,
    batch: u64,
    hdr: usize,
    key: fn(u64) -> Vec<u8>,
    val_len: fn(&[u8], usize) -> usize,
    vlen: usize,
    label: &'static str,
    keys_ctr: &'static str,
}

impl Work for PopWork {
    type Job = (usize, u64);
    fn start(&mut self) -> Next<Self::Job> {
        let t = self.next.fetch_add(1, Relaxed) as usize;
        let &(oi, b) = self.tasks.get(t)?;
        let lo = self.from + b * self.batch;
        let hi = (lo + self.batch).min(self.n);
        let m: KvMap = (lo..hi)
            .map(|i| {
                let k = (self.key)(i);
                let v = value(&k, i, (self.val_len)(&k, self.vlen));
                (k, v)
            })
            .collect();
        let mut ops = vec![OsdOp::omap_set_vals(&m)];
        if lo == 0 {
            ops.push(OsdOp::omap_set_header(header_bytes(self.hdr, 1)));
        }
        Some((self.names[oi].clone(), msg(ops), (oi, hi - lo)))
    }
    fn finish(&mut self, (oi, keys): Self::Job, d: &Done, out: &mut Out) -> Next<Self::Job> {
        match judge(d) {
            Ok(_) => {
                out.ok(self.label, us_between(d));
                out.add(self.keys_ctr, keys);
            }
            Err(k) => out.err_at(self.label, &self.names[oi], k),
        }
        None
    }
}

fn fixed_len(_: &[u8], l: usize) -> usize {
    l
}

struct PopCfg {
    /// First key index to write (keys `[from, n)`); `from >= n` = nothing to populate (objects exist).
    from: u64,
    n: u64,
    batch: u64,
    clients: usize,
    qd: usize,
    hdr: usize,
    key: fn(u64) -> Vec<u8>,
    val_len: fn(&[u8], usize) -> usize,
    vlen: usize,
    op_timeout: Duration,
    /// Stats label of the batches (`populate`, `rewrite`) and the counter of the keys written (`populate_keys`, ...).
    label: &'static str,
    keys_ctr: &'static str,
}

/// Populate every object of `names` with `n` keys; returns (stats, seconds). The label and the key counter of the
/// result use the seconds as their own window.
fn populate(o: &Opts, pool: &str, names: &Arc<Vec<String>>, pc: PopCfg) -> (Out, f64) {
    let tasks: Arc<Vec<(usize, u64)>> = Arc::new(
        (0..names.len())
            .flat_map(|oi| {
                (0..pc.n.saturating_sub(pc.from).div_ceil(pc.batch)).map(move |b| (oi, b))
            })
            .collect(),
    );
    if tasks.is_empty() {
        return (Out::default(), 0.0);
    }
    let next = Arc::new(AtomicU64::new(0));
    let t = Instant::now();
    let (o, pool, names2) = (o.clone(), pool.to_string(), names.clone());
    let hs = run_threads(pc.clients, move |_| {
        let mut out = Out::default();
        let mut c = match connect(&o, &pool, pc.op_timeout.max(Duration::from_secs(120))) {
            Ok(c) => c,
            Err(e) => return fail_out("connect", e),
        };
        let mut w = PopWork {
            names: names2.clone(),
            tasks: tasks.clone(),
            next: next.clone(),
            from: pc.from,
            n: pc.n,
            batch: pc.batch,
            hdr: pc.hdr,
            key: pc.key,
            val_len: pc.val_len,
            vlen: pc.vlen,
            label: pc.label,
            keys_ctr: pc.keys_ctr,
        };
        let far = Instant::now() + Duration::from_secs(86_400);
        drive(&mut c, pc.qd, far, &mut w, &mut out);
        out
    });
    let mut out = Out::default();
    join_all(hs, &mut out);
    let secs = t.elapsed().as_secs_f64();
    out.secs.insert(pc.label.into(), secs);
    out.secs.insert(pc.keys_ctr.into(), secs);
    (out, secs)
}

/// Remove every object (ENOENT ignored); returns the seconds and the stats (label `cleanup`, one sample per object).
fn cleanup(o: &Opts, pool: &str, names: &[String], timeout: Duration) -> (f64, Out) {
    let mut out = Out::default();
    let Ok(mut c) = connect(o, pool, timeout) else {
        for n in names {
            out.err_at("cleanup", n, "connect".into());
        }
        return (0.0, out);
    };
    let t = Instant::now();
    for n in names {
        if let Err(e) = c.p.submit(target(c.pool, n), msg(vec![OsdOp::delete()]), 0) {
            out.err_at("cleanup", n, e.chars().take(60).collect());
            continue;
        }
        loop {
            if let Some(d) = c.p.poll().into_iter().next() {
                match judge(&d) {
                    Ok(_) => out.ok("cleanup", us_between(&d)),
                    Err(k) if k == "errno -2" => out.ok("cleanup", us_between(&d)),
                    Err(k) => {
                        eprintln!("WARNING cleanup {n}: {k}");
                        out.err_at("cleanup", n, k);
                    }
                }
                break;
            }
        }
    }
    (t.elapsed().as_secs_f64(), out)
}

/// Distinct PGs and distinct primary OSDs of `names` under the current map.
fn placement(o: &Opts, pool: &str, names: &[String]) -> Result<(usize, usize), String> {
    let c = connect(o, pool, Duration::from_secs(30))?;
    let (mut pgs, mut prim) = (BTreeSet::new(), BTreeSet::new());
    for n in names {
        let p = c.p.locate(&target(c.pool, n))?;
        pgs.insert(format!("{:?}", p.pg));
        prim.insert(p.primary);
    }
    Ok((pgs.len(), prim.len()))
}

/// `n` names `mk(i, salt)`, salts chosen so every object sits on a PG no other object uses (all PGs used: the next
/// round reuses them) and the primaries stay balanced (least-loaded primary among the first 64 free-PG candidates).
fn spread_names(
    o: &Opts,
    pool: &str,
    n: usize,
    mk: impl Fn(usize, u64) -> String,
) -> Result<Vec<String>, String> {
    let c = connect(o, pool, Duration::from_secs(30))?;
    let mut used: BTreeSet<String> = BTreeSet::new();
    let mut load: BTreeMap<i32, usize> = BTreeMap::new();
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let i = out.len();
        let mut best: Option<(usize, String, String, i32)> = None;
        let mut seen = 0;
        for salt in 0..100_000u64 {
            let name = mk(i, salt);
            let p = c.p.locate(&target(c.pool, &name))?;
            let pg = format!("{:?}", p.pg);
            if used.contains(&pg) {
                continue;
            }
            let l = load.get(&p.primary).copied().unwrap_or(0);
            if best.as_ref().is_none_or(|b| l < b.0) {
                best = Some((l, name, pg, p.primary));
            }
            seen += 1;
            if l == 0 || seen >= 64 {
                break;
            }
        }
        match best {
            Some((_, name, pg, prim)) => {
                used.insert(pg);
                *load.entry(prim).or_default() += 1;
                out.push(name);
            }
            None if !used.is_empty() => used.clear(),
            None => return Err(format!("spread: no placement for object {i}")),
        }
    }
    Ok(out)
}

/// How much of a run executes (`--setup-only`, `--skip-setup`, `--cleanup-only`; default all): a big object set is
/// populated once by a setup run, several timed runs use it, a cleanup run removes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Populate, timed phases, remove the objects (unless `--keep`).
    Full,
    /// Populate and keep the objects; no timed phase.
    SetupOnly,
    /// The objects exist (same names and sizes): timed phases only; removed afterwards unless `--keep`.
    SkipSetup,
    /// Remove the objects only.
    CleanupOnly,
}

impl Mode {
    fn take(a: &mut Vec<String>, tool: &str) -> Result<Mode, String> {
        let on = [
            (flag(a, "--setup-only"), Mode::SetupOnly),
            (flag(a, "--skip-setup"), Mode::SkipSetup),
            (flag(a, "--cleanup-only"), Mode::CleanupOnly),
        ];
        let mut on = on.into_iter().filter(|(f, _)| *f).map(|(_, m)| m);
        let m = on.next().unwrap_or(Mode::Full);
        match on.next() {
            None => Ok(m),
            Some(_) => Err(format!(
                "{tool}: --setup-only, --skip-setup and --cleanup-only exclude each other"
            )),
        }
    }
    fn populates(self) -> bool {
        matches!(self, Mode::Full | Mode::SetupOnly)
    }
    fn timed(self) -> bool {
        matches!(self, Mode::Full | Mode::SkipSetup)
    }
    fn keeps(self) -> bool {
        self == Mode::SetupOnly
    }
}

// ------------------------------------------------------------------ rgwindex

#[derive(Clone)]
struct Rgw {
    mode: Mode,
    rewrite_shards: usize,
    rewrite_entries: u64,
    rewrite_clients: usize,
    pool: String,
    prefix: String,
    buckets: usize,
    shards: usize,
    entries: u64,
    put_clients: usize,
    put_qd: usize,
    put_shards: usize,
    list_clients: usize,
    list_qd: usize,
    page: u64,
    val_len: usize,
    hdr: usize,
    pop_clients: usize,
    pop_qd: usize,
    batch: u64,
    duration: Duration,
    op_timeout: Duration,
    del_timeout: Duration,
    seed: u64,
    keep: bool,
    map_own: bool,
    spread: bool,
    pop_from: u64,
    del_pct: u64,
    get_clients: usize,
    get_qd: usize,
    list_pages: u64,
}

enum RJob {
    Prepare {
        obj: usize,
        key: Vec<u8>,
        t0: Instant,
        del: bool,
    },
    Complete {
        obj: usize,
        t0: Instant,
        del: bool,
    },
    List,
}

struct PutWork {
    c: Rgw,
    names: Arc<Vec<String>>,
    rng: Rng,
    cid: u64,
    seq: u64,
}

impl Work for PutWork {
    type Job = RJob;
    fn start(&mut self) -> Next<RJob> {
        let del = self.c.del_pct > 0 && self.rng.below(100) < self.c.del_pct;
        let idx = if del {
            self.rng.below(self.c.entries)
        } else {
            self.c.entries + (self.cid << 40) + self.seq
        };
        self.seq += 1;
        let key = s3name(idx);
        let obj = if self.c.map_own {
            (self.cid as usize - 1) % self.names.len()
        } else {
            let shard = self.rng.below(self.c.put_shards as u64) as usize;
            let bucket = self.rng.below(self.c.buckets as u64) as usize;
            bucket * self.c.shards + shard
        };
        let v = value(&key, idx, self.c.val_len.min(200));
        let m = msg(vec![
            OsdOp::stat(),
            OsdOp::omap_get_header(),
            OsdOp::omap_set_header(header_bytes(self.c.hdr, idx)),
            OsdOp::omap_set_vals(&one(key.clone(), v)),
        ]);
        Some((
            self.names[obj].clone(),
            m,
            RJob::Prepare {
                obj,
                key,
                t0: Instant::now(),
                del,
            },
        ))
    }
    fn finish(&mut self, job: RJob, d: &Done, out: &mut Out) -> Next<RJob> {
        match job {
            RJob::Prepare { obj, key, t0, del } => {
                match judge(d) {
                    Ok(_) => out.ok("prepare", us_between(d)),
                    Err(k) => {
                        out.err_at("prepare", &self.names[obj], k);
                        return None;
                    }
                }
                let g = self.seq;
                let bl = format!("1_{:016x}", (self.cid << 40) | g).into_bytes();
                let mut ops = vec![
                    OsdOp::stat(),
                    OsdOp::omap_get_header(),
                    OsdOp::omap_set_header(header_bytes(self.c.hdr, g ^ 7)),
                ];
                if del {
                    ops.push(OsdOp::omap_rm_keys(&BTreeSet::from([key])));
                    ops.push(OsdOp::omap_set_vals(&one(bl.clone(), value(&bl, g, 120))));
                } else {
                    let mut kv = one(key.clone(), value(&key, g, self.c.val_len));
                    kv.insert(bl.clone(), value(&bl, g, 120));
                    ops.push(OsdOp::omap_set_vals(&kv));
                }
                Some((
                    self.names[obj].clone(),
                    msg(ops),
                    RJob::Complete { obj, t0, del },
                ))
            }
            RJob::Complete { obj, t0, del } => {
                match judge(d) {
                    Ok(_) => {
                        out.ok("complete", us_between(d));
                        let l = if del { "del" } else { "put" };
                        out.ok(l, d.finished.duration_since(t0).as_micros() as u64);
                        out.put_obj(obj);
                    }
                    Err(k) => out.err_at("complete", &self.names[obj], k),
                }
                None
            }
            RJob::List => None,
        }
    }
}

struct ListWork {
    c: Rgw,
    names: Arc<Vec<String>>,
    rng: Rng,
    cur: usize,
    pages: u64,
}

impl ListWork {
    fn page(&mut self, oi: usize, after: &[u8]) -> Next<RJob> {
        self.cur = oi;
        self.pages += 1;
        let m = msg(vec![
            OsdOp::stat(),
            OsdOp::omap_get_header(),
            OsdOp::omap_get_vals(after, self.c.page, b""),
        ]);
        Some((self.names[oi].clone(), m, RJob::List))
    }
}

impl Work for ListWork {
    type Job = RJob;
    fn start(&mut self) -> Next<RJob> {
        let oi = self.rng.below(self.names.len() as u64) as usize;
        let after = s3name(self.rng.below(self.c.entries.max(1)));
        self.pages = 0;
        self.page(oi, &after)
    }
    fn finish(&mut self, _: RJob, d: &Done, out: &mut Out) -> Next<RJob> {
        let r = match judge(d) {
            Ok(r) => r,
            Err(k) => {
                out.err_at("list_page", &self.names[self.cur], k);
                return self.start();
            }
        };
        out.ok("list_page", us_between(d));
        let got = r
            .ops
            .get(2)
            .and_then(|o| denc::from_slice::<OmapValsOut>(&o.outdata).ok());
        let Some(g) = got else {
            out.err_at(
                "list_page",
                &self.names[self.cur],
                "undecodable reply".into(),
            );
            return self.start();
        };
        out.add("list_entries", g.vals.len() as u64);
        match (g.truncated, g.vals.keys().next_back()) {
            (true, Some(last)) if self.c.list_pages == 0 || self.pages < self.c.list_pages => {
                self.page(self.cur, &last.clone())
            }
            _ => self.start(),
        }
    }
}

/// Point gets: one populated key per message (deleted keys come back empty, still a full lookup).
struct GetWork {
    c: Rgw,
    names: Arc<Vec<String>>,
    rng: Rng,
    cur: usize,
}

impl Work for GetWork {
    type Job = RJob;
    fn start(&mut self) -> Next<RJob> {
        let oi = self.rng.below(self.names.len() as u64) as usize;
        self.cur = oi;
        let keys = BTreeSet::from([s3name(self.rng.below(self.c.entries))]);
        let mut x = OsdOp::new(code::OMAP_GET_VALS_BY_KEYS);
        x.indata = denc::Encode::encode_to_vec(&keys).expect("vec").into();
        Some((self.names[oi].clone(), msg(vec![x]), RJob::List))
    }
    fn finish(&mut self, _: RJob, d: &Done, out: &mut Out) -> Next<RJob> {
        match judge(d) {
            Ok(_) => out.ok("get", us_between(d)),
            Err(k) => out.err_at("get", &self.names[self.cur], k),
        }
        None
    }
}

/// The options of `oprobe rgwindex` (all of `a` is consumed or an error names the rest).
fn parse_rgw(mut a: Vec<String>, pool: Option<String>, now: u64) -> Result<Rgw, String> {
    let a = &mut a;
    let mode = Mode::take(a, "rgwindex")?;
    let shards = num(a, "--shards", 11usize)?.max(1);
    let c = Rgw {
        mode,
        rewrite_shards: num(a, "--rewrite-shards", 0usize)?,
        rewrite_entries: num(a, "--rewrite-entries", 100_000u64)?.max(1),
        rewrite_clients: num_max(a, "--rewrite-clients", MAX_CLIENTS, 8usize)?.max(1),
        pool: pool.ok_or("rgwindex: -p POOL required")?,
        prefix: take(a, "--prefix")?.unwrap_or_else(|| format!("rgwindex-{now:x}")),
        buckets: num(a, "--buckets", 1usize)?.max(1),
        shards,
        entries: num(a, "--entries", 100_000u64)?.max(1),
        put_clients: num_max(a, "--put-clients", MAX_CLIENTS, 16usize)?,
        put_qd: num_max(a, "--put-qd", MAX_QD, 2usize)?.max(1),
        put_shards: num(a, "--put-shards", shards)?.clamp(1, shards),
        list_clients: num_max(a, "--list-clients", MAX_CLIENTS, 4usize)?,
        list_qd: num_max(a, "--list-qd", MAX_QD, 1usize)?.max(1),
        page: num(a, "--page", 1000u64)?.max(1),
        val_len: num(a, "--val-len", 300usize)?,
        hdr: num(a, "--header-len", 192usize)?,
        pop_clients: num_max(a, "--pop-clients", MAX_CLIENTS, 16usize)?.max(1),
        pop_qd: num_max(a, "--pop-qd", MAX_QD, 4usize)?.max(1),
        batch: num(a, "--batch", 1024u64)?.max(1),
        duration: secs(a, "--duration", 60.0)?,
        op_timeout: secs(a, "--op-timeout", 60.0)?,
        del_timeout: secs(a, "--del-timeout", 900.0)?,
        seed: num(a, "--seed", 1u64)?,
        keep: flag(a, "--keep"),
        map_own: match take(a, "--map")?.as_deref() {
            None | Some("random") => false,
            Some("own") => true,
            Some(x) => return Err(format!("rgwindex: --map {x} (random|own)")),
        },
        spread: flag(a, "--spread"),
        pop_from: num(a, "--pop-from", 0u64)?,
        del_pct: num(a, "--del-pct", 0u64)?.min(100),
        get_clients: num_max(a, "--get-clients", MAX_CLIENTS, 0usize)?,
        get_qd: num_max(a, "--get-qd", MAX_QD, 1usize)?.max(1),
        list_pages: num(a, "--list-pages", 0u64)?,
    };
    if let Some(x) = a.first() {
        return Err(format!("rgwindex: unknown argument '{x}'\n{HELP_RGW}"));
    }
    Ok(c.apply_mode())
}

impl Rgw {
    /// A run without a timed phase starts no clients; a run on existing objects populates nothing.
    fn apply_mode(mut self) -> Rgw {
        if !self.mode.populates() {
            self.pop_from = self.entries;
        }
        if !self.mode.timed() {
            self.put_clients = 0;
            self.list_clients = 0;
            self.get_clients = 0;
            self.rewrite_shards = 0;
            self.duration = Duration::ZERO;
        }
        self.keep |= self.mode.keeps();
        self
    }

    /// The shard objects of the reshard copy (`--rewrite-shards`): own names, removed again after the run.
    fn rewrite_names(&self) -> Vec<String> {
        (0..self.rewrite_shards)
            .map(|i| format!("{}.rewrite.{i:04}", self.prefix))
            .collect()
    }
}

/// Entry point of `oprobe rgwindex ...`.
pub fn rgw_cli(a: Vec<String>, o: Opts, pool: Option<String>) -> Result<ExitCode, String> {
    let (fmt, a) = outfmt::extract(&a, true)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let c = parse_rgw(a, pool, now)?;
    let (sh, pre) = (c.shards, c.prefix.clone());
    let names: Arc<Vec<String>> = Arc::new(if c.spread {
        spread_names(&o, &c.pool, c.buckets * sh, |i, salt| {
            format!("{pre}{salt:x}.dir.{:04}.{}", i / sh, i % sh)
        })?
    } else {
        (0..c.buckets * sh)
            .map(|i| format!("{pre}.dir.{:04}.{}", i / sh, i % sh))
            .collect()
    });
    let (obj_pgs, obj_prims) = placement(&o, &c.pool, &names)?;
    let (pop, pop_s) = populate(
        &o,
        &c.pool,
        &names,
        PopCfg {
            from: c.pop_from,
            n: c.entries,
            batch: c.batch,
            clients: c.pop_clients,
            qd: c.pop_qd,
            hdr: c.hdr,
            key: s3name,
            val_len: fixed_len,
            vlen: c.val_len,
            op_timeout: c.op_timeout,
            label: "populate",
            keys_ctr: "populate_keys",
        },
    );
    let keys_total = c.entries * names.len() as u64;
    if c.mode.populates() {
        eprintln!(
            "[rgwindex] populated {keys_total} keys in {pop_s:.1}s ({:.0} keys/s), errors {}",
            keys_total as f64 / pop_s.max(1e-9),
            pop.errors()
        );
    }
    let start = Instant::now();
    let deadline = start + c.duration;
    // the reshard copy: new shard objects filled while the foreground clients run (batched omap_set like populate)
    let rewrite_names = Arc::new(c.rewrite_names());
    let rewrite = (c.rewrite_shards > 0).then(|| {
        let (o4, rn) = (o.clone(), rewrite_names.clone());
        let cfg = PopCfg {
            from: 0,
            n: c.rewrite_entries,
            batch: c.batch,
            clients: c.rewrite_clients,
            qd: c.pop_qd,
            hdr: c.hdr,
            key: s3name,
            val_len: fixed_len,
            vlen: c.val_len,
            op_timeout: c.op_timeout,
            label: "rewrite",
            keys_ctr: "rewrite_keys",
        };
        let pool = c.pool.clone();
        std::thread::spawn(move || populate(&o4, &pool, &rn, cfg).0)
    });
    let (co, nm, o1) = (c.clone(), names.clone(), o.clone());
    let puts = run_threads(c.put_clients, move |i| {
        let mut out = Out::default();
        let mut cn = match connect(&o1, &co.pool, co.op_timeout) {
            Ok(x) => x,
            Err(e) => return fail_out("connect", e),
        };
        let mut w = PutWork {
            c: co.clone(),
            names: nm.clone(),
            rng: Rng::new(co.seed ^ ((i as u64) << 32)),
            cid: i as u64 + 1,
            seq: 0,
        };
        drive(&mut cn, co.put_qd, deadline, &mut w, &mut out);
        out
    });
    let (co, nm, o2) = (c.clone(), names.clone(), o.clone());
    let lists = run_threads(c.list_clients, move |i| {
        let mut out = Out::default();
        let mut cn = match connect(&o2, &co.pool, co.op_timeout) {
            Ok(x) => x,
            Err(e) => return fail_out("connect", e),
        };
        let mut w = ListWork {
            c: co.clone(),
            names: nm.clone(),
            rng: Rng::new(co.seed ^ 0x1157 ^ ((i as u64) << 32)),
            cur: 0,
            pages: 0,
        };
        drive(&mut cn, co.list_qd, deadline, &mut w, &mut out);
        out
    });
    let (co, nm, o3) = (c.clone(), names.clone(), o.clone());
    let gets = run_threads(c.get_clients, move |i| {
        let mut out = Out::default();
        let mut cn = match connect(&o3, &co.pool, co.op_timeout) {
            Ok(x) => x,
            Err(e) => return fail_out("connect", e),
        };
        let mut w = GetWork {
            c: co.clone(),
            names: nm.clone(),
            rng: Rng::new(co.seed ^ 0x6e7 ^ ((i as u64) << 32)),
            cur: 0,
        };
        drive(&mut cn, co.get_qd, deadline, &mut w, &mut out);
        out
    });
    let mut out = Out::default();
    join_all(puts, &mut out);
    join_all(lists, &mut out);
    join_all(gets, &mut out);
    let dur = start.elapsed().as_secs_f64().max(1e-9);
    // the rewrite has its own window: it ends when its keys are written, which may be after the foreground clients stopped
    let mut rewrite_s = 0.0;
    if let Some(h) = rewrite {
        match h.join() {
            Ok(r) => {
                rewrite_s = r.secs.get("rewrite").copied().unwrap_or(0.0);
                out.merge(r);
            }
            Err(_) => out.err("rewrite", "panic".into()),
        }
    }
    let rewrite_keys = out.ctr.get("rewrite_keys").copied().unwrap_or(0);
    let (mut del_s, mut del) = if c.keep {
        (0.0, Out::default())
    } else {
        cleanup(&o, &c.pool, &names, c.del_timeout)
    };
    if !rewrite_names.is_empty() {
        let (s2, d2) = cleanup(&o, &c.pool, &rewrite_names, c.del_timeout);
        del_s += s2;
        del.merge(d2);
    }
    let errs = out.errors() + pop.errors() + del.errors();
    let shard_rows: Vec<Value> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let k = out.put_obj.get(i).copied().unwrap_or(0);
            json!({"object": n, "puts": k, "puts_s": k as f64 / dur})
        })
        .collect();
    let puts_n = out.stats.get("put").map_or(0, |x| x.0.n);
    let dels_n = out.stats.get("del").map_or(0, |x| x.0.n);
    let gets_n = out.stats.get("get").map_or(0, |x| x.0.n);
    let pages = out.stats.get("list_page").map_or(0, |x| x.0.n);
    let summary = json!({
        "mode": "rgwindex", "pool": c.pool, "buckets": c.buckets, "shards": c.shards, "entries_per_shard": c.entries,
        "put_clients": c.put_clients, "put_qd": c.put_qd, "put_shards": c.put_shards, "list_clients": c.list_clients,
        "map": if c.map_own { "own" } else { "random" }, "spread": c.spread, "objects": names.len(),
        "objects_pgs": obj_pgs, "objects_primaries": obj_prims, "pop_from": c.pop_from, "del_pct": c.del_pct,
        "get_clients": c.get_clients, "list_pages_cap": c.list_pages,
        "dels": dels_n, "dels_s": dels_n as f64 / dur, "gets": gets_n, "gets_s": gets_n as f64 / dur,
        "chains_s": (puts_n + dels_n) as f64 / dur,
        "duration_s": dur, "populate_s": pop_s, "populate_keys_s": keys_total as f64 / pop_s.max(1e-9),
        "rewrite_shards": c.rewrite_shards, "rewrite_entries": c.rewrite_entries, "rewrite_s": rewrite_s,
        "rewrite_keys_s": rewrite_keys as f64 / rewrite_s.max(1e-9),
        "puts": puts_n, "puts_s": puts_n as f64 / dur,
        "puts_s_per_hot_shard": puts_n as f64 / dur / (c.put_shards * c.buckets) as f64,
        "list_pages": pages, "list_pages_s": pages as f64 / dur,
        "list_entries_s": out.ctr.get("list_entries").copied().unwrap_or(0) as f64 / dur,
        "cleanup_s": del_s, "errors": errs,
    });
    let mut all = Out::default();
    all.merge(pop);
    all.merge(out);
    all.merge(del);
    report(fmt, &summary, &all, dur, Some(shard_rows), errs)
}

// ------------------------------------------------------------------ dirfrag

#[derive(Clone)]
struct Dir {
    mode: Mode,
    pool: String,
    prefix: String,
    dirs: usize,
    entries: u64,
    active: usize,
    batches: Vec<usize>,
    commit_clients: usize,
    fetch_clients: usize,
    fetch_qd: usize,
    page: u64,
    hdr: usize,
    pop_clients: usize,
    pop_qd: usize,
    batch_pop: u64,
    phase: Duration,
    op_timeout: Duration,
    del_timeout: Duration,
    seed: u64,
    keep: bool,
    spread: bool,
    pop_from: u64,
}

struct CommitWork {
    names: Arc<Vec<String>>,
    st: Arc<Vec<ObjState>>,
    owned: Vec<usize>,
    started: usize,
    batch: usize,
    hdr: usize,
    rng: Rng,
}

impl CommitWork {
    fn commit(&mut self, di: usize) -> Next<usize> {
        let o = &self.st[di];
        let mut sets = KvMap::new();
        let mut rms = BTreeSet::new();
        for _ in 0..self.batch {
            let k = dname(o.next_insert());
            let v = value(&k, self.rng.next_u64(), dir_val_len(&k));
            sets.insert(k, v);
            rms.insert(dname(o.next_delete()));
        }
        let m = msg(vec![
            OsdOp::stat(),
            OsdOp::omap_set_header(header_bytes(self.hdr, self.rng.next_u64())),
            OsdOp::omap_set_vals(&sets),
            OsdOp::omap_rm_keys(&rms),
        ]);
        Some((self.names[di].clone(), m, di))
    }
}

impl Work for CommitWork {
    type Job = usize;
    fn start(&mut self) -> Next<usize> {
        let di = *self.owned.get(self.started)?;
        self.started += 1;
        self.commit(di)
    }
    fn finish(&mut self, di: usize, d: &Done, out: &mut Out) -> Next<usize> {
        match judge(d) {
            Ok(_) => {
                out.ok("commit", us_between(d));
                out.add("dentries", self.batch as u64);
            }
            Err(k) => out.err_at("commit", &self.names[di], k),
        }
        self.commit(di)
    }
}

struct FetchWork {
    names: Arc<Vec<String>>,
    rng: Rng,
    page: u64,
    t0: Instant,
}

impl FetchWork {
    fn page(&mut self, di: usize, after: &[u8]) -> Next<usize> {
        let m = msg(vec![
            OsdOp::omap_get_header(),
            OsdOp::omap_get_vals(after, self.page, b""),
        ]);
        Some((self.names[di].clone(), m, di))
    }
}

impl Work for FetchWork {
    type Job = usize;
    fn start(&mut self) -> Next<usize> {
        let di = self.rng.below(self.names.len() as u64) as usize;
        self.t0 = Instant::now();
        self.page(di, &[])
    }
    fn finish(&mut self, di: usize, d: &Done, out: &mut Out) -> Next<usize> {
        let r = match judge(d) {
            Ok(r) => r,
            Err(k) => {
                out.err_at("fetch_page", &self.names[di], k);
                return self.start();
            }
        };
        out.ok("fetch_page", us_between(d));
        let got = r
            .ops
            .get(1)
            .and_then(|o| denc::from_slice::<OmapValsOut>(&o.outdata).ok());
        let Some(g) = got else {
            out.err_at("fetch_page", &self.names[di], "undecodable reply".into());
            return self.start();
        };
        out.add("dentries", g.vals.len() as u64);
        match (g.truncated, g.vals.keys().next_back()) {
            (true, Some(last)) => self.page(di, &last.clone()),
            _ => {
                out.ok(
                    "fetch_dir",
                    d.finished.duration_since(self.t0).as_micros() as u64,
                );
                self.start()
            }
        }
    }
}

/// One timed commit phase with `b` dentries per commit.
fn commit_phase(
    o: &Opts,
    c: &Dir,
    names: &Arc<Vec<String>>,
    st: &Arc<Vec<ObjState>>,
    b: usize,
) -> Out {
    let deadline = Instant::now() + c.phase;
    let (cc, nm, st2, o2) = (c.clone(), names.clone(), st.clone(), o.clone());
    let hs = run_threads(c.commit_clients, move |i| {
        let mut out = Out::default();
        let owned: Vec<usize> = if cc.commit_clients > cc.active {
            vec![i % cc.active]
        } else {
            (0..cc.active)
                .filter(|d| d % cc.commit_clients == i)
                .collect()
        };
        if owned.is_empty() {
            return out;
        }
        let mut cn = match connect(&o2, &cc.pool, cc.op_timeout) {
            Ok(x) => x,
            Err(e) => return fail_out("connect", e),
        };
        let qd = owned.len();
        let mut w = CommitWork {
            names: nm.clone(),
            st: st2.clone(),
            started: 0,
            batch: b,
            hdr: cc.hdr,
            rng: Rng::new(cc.seed ^ ((i as u64) << 32) ^ b as u64),
            owned,
        };
        drive(&mut cn, qd, deadline, &mut w, &mut out);
        out
    });
    let mut po = Out::default();
    join_all(hs, &mut po);
    po
}

fn fetch_phase(o: &Opts, c: &Dir, names: &Arc<Vec<String>>) -> Out {
    let deadline = Instant::now() + c.phase;
    let (cc, nm, o2) = (c.clone(), names.clone(), o.clone());
    let hs = run_threads(c.fetch_clients, move |i| {
        let mut out = Out::default();
        let mut cn = match connect(&o2, &cc.pool, cc.op_timeout) {
            Ok(x) => x,
            Err(e) => return fail_out("connect", e),
        };
        let mut w = FetchWork {
            names: nm.clone(),
            rng: Rng::new(cc.seed ^ 0xFE7C ^ ((i as u64) << 32)),
            page: cc.page,
            t0: Instant::now(),
        };
        drive(&mut cn, cc.fetch_qd, deadline, &mut w, &mut out);
        out
    });
    let mut po = Out::default();
    join_all(hs, &mut po);
    po
}

/// Entry point of `oprobe dirfrag ...`.
pub fn dir_cli(a: Vec<String>, o: Opts, pool: Option<String>) -> Result<ExitCode, String> {
    let (fmt, mut a) = outfmt::extract(&a, true)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mode = Mode::take(&mut a, "dirfrag")?;
    let dirs = num(&mut a, "--dirs", 100usize)?.max(1);
    let batches = take(&mut a, "--batches")?
        .unwrap_or_else(|| "1,16,256,1024".into())
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<usize>()
                .map_err(|_| format!("bad --batches '{s}'"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut c = Dir {
        mode,
        pool: pool.ok_or("dirfrag: -p POOL required")?,
        prefix: take(&mut a, "--prefix")?.unwrap_or_else(|| format!("dirfrag-{now:x}")),
        dirs,
        entries: num(&mut a, "--entries", 5000u64)?.max(1),
        active: num(&mut a, "--active", 32usize)?.clamp(1, dirs),
        batches,
        commit_clients: num_max(&mut a, "--commit-clients", MAX_CLIENTS, 8usize)?.max(1),
        fetch_clients: num_max(&mut a, "--fetch-clients", MAX_CLIENTS, 8usize)?,
        fetch_qd: num_max(&mut a, "--fetch-qd", MAX_QD, 4usize)?.max(1),
        page: num(&mut a, "--page", 1024u64)?.max(1),
        hdr: num(&mut a, "--header-len", 232usize)?,
        pop_clients: num_max(&mut a, "--pop-clients", MAX_CLIENTS, 16usize)?.max(1),
        pop_qd: num_max(&mut a, "--pop-qd", MAX_QD, 4usize)?.max(1),
        batch_pop: num(&mut a, "--batch-pop", 1024u64)?.max(1),
        phase: secs(&mut a, "--phase", 20.0)?,
        op_timeout: secs(&mut a, "--op-timeout", 60.0)?,
        del_timeout: secs(&mut a, "--del-timeout", 900.0)?,
        seed: num(&mut a, "--seed", 1u64)?,
        keep: flag(&mut a, "--keep"),
        spread: flag(&mut a, "--spread"),
        pop_from: num(&mut a, "--pop-from", 0u64)?,
    };
    if let Some(x) = a.first() {
        return Err(format!("dirfrag: unknown argument '{x}'\n{HELP_DIR}"));
    }
    if !c.mode.populates() {
        c.pop_from = c.entries;
    }
    c.keep |= c.mode.keeps();
    let pre = c.prefix.clone();
    let dname_of = |d: usize, salt: u64| {
        let s = if salt == 0 {
            String::new()
        } else {
            format!("{salt:x}")
        };
        format!("{pre}{s}.{:011x}.00000000", 0x0100_0000_0000_u64 + d as u64)
    };
    let names: Arc<Vec<String>> = Arc::new(if c.spread {
        spread_names(&o, &c.pool, c.dirs, |d, salt| dname_of(d, salt + 1))?
    } else {
        (0..c.dirs).map(|d| dname_of(d, 0)).collect()
    });
    let (obj_pgs, obj_prims) = placement(&o, &c.pool, &names)?;
    let (pop, pop_s) = populate(
        &o,
        &c.pool,
        &names,
        PopCfg {
            from: c.pop_from,
            n: c.entries,
            batch: c.batch_pop,
            clients: c.pop_clients,
            qd: c.pop_qd,
            hdr: c.hdr,
            key: dname,
            val_len: |k, _| dir_val_len(k),
            vlen: 0,
            op_timeout: c.op_timeout,
            label: "populate",
            keys_ctr: "populate_keys",
        },
    );
    let keys_total = c.entries * c.dirs as u64;
    if c.mode.populates() {
        eprintln!(
            "[dirfrag] populated {keys_total} dentries in {pop_s:.1}s ({:.0}/s), errors {}",
            keys_total as f64 / pop_s.max(1e-9),
            pop.errors()
        );
    }
    let st: Arc<Vec<ObjState>> = Arc::new(
        names
            .iter()
            .map(|n| ObjState::new(n.clone(), c.entries))
            .collect(),
    );
    let mut per_phase: Vec<(String, Out)> = Vec::new();
    if c.mode.timed() {
        for &b in &c.batches {
            per_phase.push((format!("commit-b{b}"), commit_phase(&o, &c, &names, &st, b)));
        }
        if c.fetch_clients > 0 {
            per_phase.push(("fetch".into(), fetch_phase(&o, &c, &names)));
        }
    }
    let (del_s, del) = if c.keep {
        (0.0, Out::default())
    } else {
        cleanup(&o, &c.pool, &names, c.del_timeout)
    };
    let mut errs = pop.errors() + del.errors();
    let mut all = Out::default();
    all.merge(pop);
    all.merge(del);
    let mut phase_rows = Vec::new();
    for (ph, po) in per_phase {
        errs += po.errors();
        let dent = po.ctr.get("dentries").copied().unwrap_or(0);
        phase_rows.push(
            json!({"phase": ph, "dentries": dent, "dentries_s": dent as f64 / c.phase.as_secs_f64().max(1e-9)}),
        );
        let mut rl = Out::default();
        for (k, v) in po.stats {
            rl.stats.insert(format!("{ph}/{k}"), v);
        }
        for (k, v) in po.kinds {
            rl.kinds.insert(format!("{ph}/{k}"), v);
        }
        all.merge(rl);
    }
    let summary = json!({
        "mode": "dirfrag", "pool": c.pool, "dirs": c.dirs, "entries_per_dir": c.entries, "active_dirs": c.active,
        "commit_clients": c.commit_clients, "fetch_clients": c.fetch_clients, "phase_s": c.phase.as_secs_f64(),
        "spread": c.spread, "objects_pgs": obj_pgs, "objects_primaries": obj_prims, "pop_from": c.pop_from,
        "populate_s": pop_s, "populate_dentries_s": keys_total as f64 / pop_s.max(1e-9),
        "phases": phase_rows, "cleanup_s": del_s, "errors": errs,
    });
    report(fmt, &summary, &all, c.phase.as_secs_f64(), None, errs)
}

// ------------------------------------------------------------------ oneobj (single-object access)

#[derive(Clone)]
struct One {
    scenario: String,
    names: Arc<Vec<String>>,
    qd: usize,
    obj_size: u64,
    keys: u64,
    spread_keys: u64,
    batch: u64,
    page: u64,
    val_len: usize,
    read_pct: u64,
    app_min: u64,
    app_max: u64,
    app_roll: u64,
    /// clients per object (append roll-over estimates the object size as own bytes * share)
    share: u64,
    seed: u64,
}

impl One {
    fn keys_of(&self) -> u64 {
        if self.names.len() > 1 {
            self.spread_keys
        } else {
            self.keys
        }
        .max(1)
    }
}

/// Insert indices `[rm_seq, rm_seq + batch)` to remove next (FIFO over this client's own inserts `[0, seq)`),
/// or `None` while fewer than `batch` own inserts are still unremoved.
fn fifo_rm_range(rm_seq: u64, seq: u64, batch: u64) -> Option<std::ops::Range<u64>> {
    (seq.saturating_sub(rm_seq) >= batch).then(|| rm_seq..(rm_seq + batch).min(seq))
}

struct OneWork {
    c: One,
    cid: u64,
    rng: Rng,
    seq: u64,
    /// next own insert index to remove (omap-set FIFO)
    rm_seq: u64,
    rm_next: bool,
    /// bytes this client appended since its last roll
    app_bytes: u64,
}

impl OneWork {
    fn data4k(&mut self) -> Vec<u8> {
        value(b"oneobj", self.rng.next_u64(), 4096)
    }
    fn off4k(&mut self) -> u64 {
        self.rng.below((self.c.obj_size / 4096).max(1)) * 4096
    }
}

impl Work for OneWork {
    type Job = &'static str;
    fn start(&mut self) -> Next<&'static str> {
        let n = self.c.names.len();
        let obj = self.c.names[(self.cid as usize) % n].clone();
        let keys = self.c.keys_of();
        let (label, ops): (&'static str, Vec<OsdOp>) = match self.c.scenario.as_str() {
            "read" => ("read", vec![OsdOp::read(self.off4k(), 4096)]),
            "write" => {
                let off = self.off4k();
                ("write", vec![OsdOp::write(off, self.data4k())])
            }
            "append" if self.app_bytes.saturating_mul(self.c.share) >= self.c.app_roll => {
                self.app_bytes = 0;
                ("roll", vec![OsdOp::truncate(0)])
            }
            "append" => {
                let span = self.c.app_max.saturating_sub(self.c.app_min) / 4096 + 1;
                let len = (self.c.app_min / 4096 + self.rng.below(span)) * 4096;
                self.app_bytes += len.max(4096);
                (
                    "append",
                    vec![OsdOp::append(value(
                        b"app",
                        self.rng.next_u64(),
                        len.max(4096) as usize,
                    ))],
                )
            }
            "mixed" => {
                if self.rng.below(100) < self.c.read_pct {
                    ("read", vec![OsdOp::read(self.off4k(), 4096)])
                } else {
                    let off = self.off4k();
                    ("write", vec![OsdOp::write(off, self.data4k())])
                }
            }
            "omap-get" => {
                let k = s3name(self.rng.below(keys));
                if self.rng.below(2) == 0 {
                    let mut x = OsdOp::new(code::OMAP_GET_VALS_BY_KEYS);
                    x.indata = denc::Encode::encode_to_vec(&BTreeSet::from([k]))
                        .expect("vec")
                        .into();
                    ("get_key", vec![x])
                } else {
                    ("get_page", vec![OsdOp::omap_get_vals(&k, self.c.page, b"")])
                }
            }
            "omap-set" => {
                self.rm_next = !self.rm_next;
                if self.rm_next {
                    let rms: BTreeSet<Vec<u8>> =
                        match fifo_rm_range(self.rm_seq, self.seq, self.c.batch) {
                            Some(r) => {
                                self.rm_seq = r.end;
                                r.map(|i| s3name(keys + (self.cid << 40) + i)).collect()
                            }
                            None => (0..self.c.batch)
                                .map(|_| s3name(self.rng.below(keys)))
                                .collect(),
                        };
                    ("omap_rm", vec![OsdOp::omap_rm_keys(&rms)])
                } else {
                    let mut kv = KvMap::new();
                    for _ in 0..self.c.batch {
                        let idx = keys + (self.cid << 40) + self.seq;
                        self.seq += 1;
                        let k = s3name(idx);
                        kv.insert(k.clone(), value(&k, idx, self.c.val_len));
                    }
                    ("omap_set", vec![OsdOp::omap_set_vals(&kv)])
                }
            }
            _ => {
                let r = self.rng.below(100);
                if r < 40 {
                    ("getxattr", vec![OsdOp::getxattr(b"user.meta")])
                } else if r < 70 {
                    ("stat", vec![OsdOp::stat()])
                } else if r < 85 {
                    let v = value(b"x", self.rng.next_u64(), 128);
                    ("setxattr", vec![OsdOp::setxattr(b"user.meta", &v)])
                } else {
                    let k = format!("meta.{}.{}", self.cid, self.rng.below(1024)).into_bytes();
                    let v = value(&k, self.rng.next_u64(), 64);
                    ("omap_set1", vec![OsdOp::omap_set_vals(&one(k, v))])
                }
            }
        };
        Some((obj, msg(ops), label))
    }
    fn finish(&mut self, label: &'static str, d: &Done, out: &mut Out) -> Next<&'static str> {
        match judge(d) {
            Ok(_) => {
                out.ok(label, us_between(d));
                if label != "roll" {
                    out.ok("all", us_between(d));
                }
            }
            Err(k) => out.err(label, k),
        }
        None
    }
}

/// Create the objects of a scenario: data scenarios 4 MiB writefull (+ the xattr of `meta`), omap scenarios populated.
fn one_setup(o: &Opts, pool: &str, c: &One, op_timeout: Duration) -> Result<f64, String> {
    let t = Instant::now();
    if c.scenario.starts_with("omap") {
        let (out, _) = populate(
            o,
            pool,
            &c.names,
            PopCfg {
                from: 0,
                n: c.keys_of(),
                batch: 1024,
                clients: 16,
                qd: 4,
                hdr: 192,
                key: s3name,
                val_len: fixed_len,
                vlen: c.val_len,
                op_timeout,
                label: "populate",
                keys_ctr: "populate_keys",
            },
        );
        if out.errors() > 0 {
            return Err(format!(
                "oneobj setup: {} populate errors {:?}",
                out.errors(),
                out.kinds
            ));
        }
    } else {
        let mut cn = connect(o, pool, op_timeout)?;
        let mut out = Out::default();
        for n in c.names.iter() {
            let data = value(n.as_bytes(), 1, c.obj_size as usize);
            let v = value(b"x", 1, 128);
            one_msg(
                &mut cn,
                n,
                vec![OsdOp::writefull(data), OsdOp::setxattr(b"user.meta", &v)],
                "setup",
                &mut out,
            )?;
        }
    }
    Ok(t.elapsed().as_secs_f64())
}

/// `--op-log`: header comment + one `trace_id gid tid submit_unix_ns lat_us ok` TSV line per op, slowest first.
fn write_op_log(path: &str, log: &mut [OpLog]) -> Result<(), String> {
    log.sort_unstable_by_key(|r| std::cmp::Reverse(r.lat_us));
    let mut s = String::from("# trace_id\tgid\ttid\tsubmit_unix_ns\tlat_us\tok\n");
    for r in log.iter() {
        let _ = writeln!(
            s,
            "{:016x}\t{}\t{}\t{}\t{}\t{}",
            r.key,
            r.gid,
            r.tid,
            r.submit_unix_ns,
            r.lat_us,
            u8::from(r.ok)
        );
    }
    std::fs::write(path, s).map_err(|e| format!("oneobj: --op-log {path}: {e}"))
}

/// Entry point of `oprobe oneobj ...`.
pub fn one_cli(a: Vec<String>, o: Opts, pool: Option<String>) -> Result<ExitCode, String> {
    let (fmt, mut a) = outfmt::extract(&a, true)?;
    let pool = pool.ok_or("oneobj: -p POOL required")?;
    let scenario = take(&mut a, "--scenario")?.ok_or("oneobj: --scenario required")?;
    if ![
        "read", "write", "append", "mixed", "omap-get", "omap-set", "meta",
    ]
    .contains(&scenario.as_str())
    {
        return Err(format!("oneobj: unknown --scenario {scenario}\n{HELP_ONE}"));
    }
    let prefix = take(&mut a, "--prefix")?.unwrap_or_else(|| "oneobj".into());
    let clients = num_max(&mut a, "--clients", MAX_CLIENTS, 1usize)?.max(1);
    let qd = num_max(&mut a, "--qd", MAX_QD, 1usize)?.max(1);
    let nobj = num(&mut a, "--objects", 1usize)?.max(1);
    let spread = flag(&mut a, "--spread");
    let duration = secs(&mut a, "--duration", 15.0)?;
    let setup_only = flag(&mut a, "--setup-only");
    let skip_setup = flag(&mut a, "--skip-setup");
    let cleanup_only = flag(&mut a, "--cleanup-only");
    let keep = flag(&mut a, "--keep");
    let op_timeout = secs(&mut a, "--op-timeout", 60.0)?;
    let op_log = take(&mut a, "--op-log")?;
    let mut c = One {
        scenario: scenario.clone(),
        names: Arc::new(Vec::new()),
        qd,
        obj_size: num(&mut a, "--obj-size", 4_194_304u64)?.max(4096),
        keys: num(&mut a, "--keys", 1_000_000u64)?,
        spread_keys: num(&mut a, "--spread-keys", 100_000u64)?,
        batch: num(&mut a, "--batch", 1u64)?.max(1),
        page: num(&mut a, "--page", 100u64)?.max(1),
        val_len: num(&mut a, "--val-len", 300usize)?,
        read_pct: num(&mut a, "--read-pct", 70u64)?.min(100),
        app_min: num(&mut a, "--app-min", 4096u64)?.max(4096),
        app_max: num(&mut a, "--app-max", 65_536u64)?.max(4096),
        app_roll: num(&mut a, "--app-roll", 67_108_864u64)?.max(4096),
        share: (clients as u64).div_ceil(nobj as u64).max(1),
        seed: num(&mut a, "--seed", 1u64)?,
    };
    if let Some(x) = a.first() {
        return Err(format!("oneobj: unknown argument '{x}'\n{HELP_ONE}"));
    }
    // the object set depends on the scenario family (data / omap / meta) and the object count, never on the client count
    let fam = if scenario.starts_with("omap") {
        "omap"
    } else if scenario == "meta" {
        "meta"
    } else {
        "data"
    };
    let base = format!("{prefix}-{fam}-{nobj}");
    c.names = Arc::new(if spread && nobj > 1 {
        spread_names(&o, &pool, nobj, |i, salt| format!("{base}.{i}.{salt:x}"))?
    } else {
        (0..nobj).map(|i| format!("{base}.{i}")).collect()
    });
    if cleanup_only {
        let (del_s, del) = cleanup(&o, &pool, &c.names, Duration::from_secs(900));
        let errs = del.errors();
        let summary =
            json!({"mode": "oneobj-cleanup", "objects": nobj, "cleanup_s": del_s, "errors": errs});
        return report(fmt, &summary, &Out::default(), 1.0, None, errs);
    }
    let setup_s = if skip_setup {
        0.0
    } else {
        one_setup(&o, &pool, &c, op_timeout)?
    };
    let (obj_pgs, obj_prims) = placement(&o, &pool, &c.names)?;
    if scenario == "append" && !setup_only {
        // every timed append cell starts from empty objects, outside the measurement
        let mut cn = connect(&o, &pool, op_timeout)?;
        let mut rs = Out::default();
        for n in c.names.iter() {
            one_msg(&mut cn, n, vec![OsdOp::truncate(0)], "reset", &mut rs)?;
        }
    }
    let mut summary = json!({"mode": "oneobj", "scenario": scenario, "pool": pool, "clients": clients, "qd": qd,
        "objects": nobj, "spread": spread, "objects_pgs": obj_pgs, "objects_primaries": obj_prims, "setup_s": setup_s,
        "keys_per_object": if fam == "omap" { c.keys_of() } else { 0 }, "batch": c.batch, "page": c.page});
    if setup_only {
        return report(fmt, &summary, &Out::default(), 1.0, None, 0);
    }
    let deadline = Instant::now() + duration;
    let start = Instant::now();
    let (cc, o2, pool2, op_log_on) = (c.clone(), o.clone(), pool.clone(), op_log.is_some());
    let hs = run_threads(clients, move |i| {
        let mut out = Out {
            log_on: op_log_on,
            ..Out::default()
        };
        let mut cn = match connect(&o2, &pool2, op_timeout) {
            Ok(x) => x,
            Err(e) => return fail_out("connect", e),
        };
        let mut w = OneWork {
            c: cc.clone(),
            cid: i as u64,
            rng: Rng::new(cc.seed ^ 0x0e0b ^ ((i as u64) << 32)),
            seq: 0,
            rm_seq: 0,
            rm_next: i % 2 == 1,
            app_bytes: 0,
        };
        drive(&mut cn, cc.qd, deadline, &mut w, &mut out);
        out
    });
    let mut out = Out::default();
    join_all(hs, &mut out);
    let dur = start.elapsed().as_secs_f64().max(1e-9);
    if let Some(path) = &op_log {
        write_op_log(path, &mut out.log)?;
    }
    let all = out.stats.get("all").map_or(0, |x| x.0.n);
    let (del_s, del) = if keep {
        (0.0, Out::default())
    } else {
        cleanup(&o, &pool, &c.names, Duration::from_secs(900))
    };
    let errs = out.errors() + del.errors();
    summary["duration_s"] = json!(dur);
    summary["ops_total"] = json!(all);
    summary["ops_s"] = json!(all as f64 / dur);
    summary["cleanup_s"] = json!(del_s);
    summary["errors"] = json!(errs);
    report(fmt, &summary, &out, dur, None, errs)
}

// ------------------------------------------------------------------ omapscan / omaprm (one object, sequential)

/// One message, waited for; Ok(reply op outdatas) or Err(kind), latency recorded under `label`.
fn one_msg(
    c: &mut Conn,
    name: &str,
    ops: Vec<OsdOp>,
    label: &str,
    out: &mut Out,
) -> Result<Vec<Vec<u8>>, String> {
    c.p.submit(target(c.pool, name), msg(ops), 0)?;
    loop {
        if let Some(d) = c.p.poll().into_iter().next() {
            return match judge(&d) {
                Ok(r) => {
                    out.ok(label, us_between(&d));
                    Ok(r.ops.iter().map(|o| o.outdata.to_vec()).collect())
                }
                Err(k) => {
                    out.err_at(label, name, k.clone());
                    Err(k)
                }
            };
        }
    }
}

fn decode_counted<T: for<'a> denc::Decode<'a>>(
    outdata: Option<&Vec<u8>>,
    out: &mut Out,
    label: &str,
    object: &str,
) -> Result<T, String> {
    outdata
        .and_then(|o| denc::from_slice::<T>(o).ok())
        .ok_or_else(|| {
            let error = "undecodable reply".to_string();
            out.err_at(label, object, error.clone());
            error
        })
}

fn removal_page_ops(after: &[u8], batch: u64, first: bool) -> Result<Vec<OsdOp>, String> {
    let mut ops = Vec::new();
    if first {
        let mut exact = OsdOp::new(code::OMAP_GET_VALS_BY_KEYS);
        exact.indata = denc::to_vec(&BTreeSet::from([after.to_vec()]))
            .map_err(|e| e.to_string())?
            .into();
        ops.push(exact);
    }
    ops.push(OsdOp::omap_get_vals(after, batch, b""));
    Ok(ops)
}

fn removal_page(
    data: &[Vec<u8>],
    first: bool,
    out: &mut Out,
    object: &str,
) -> Result<OmapValsOut, String> {
    let mut page: OmapValsOut = decode_counted(data.last(), out, "list", object)?;
    if first {
        let exact: KvMap = decode_counted(data.first(), out, "list", object)?;
        page.vals.extend(exact);
    }
    Ok(page)
}

/// Entry point of `oprobe omapscan ...`.
pub fn scan_cli(a: Vec<String>, o: Opts, pool: Option<String>) -> Result<ExitCode, String> {
    let (fmt, mut a) = outfmt::extract(&a, true)?;
    let pool = pool.ok_or("omapscan: -p POOL required")?;
    let name = take(&mut a, "--object")?.ok_or("omapscan: --object NAME required")?;
    let page = num(&mut a, "--page", 1000u64)?.max(1);
    let max_pages = num(&mut a, "--max-pages", 0u64)?;
    let tmo = secs(&mut a, "--op-timeout", 120.0)?;
    if let Some(x) = a.first() {
        return Err(format!("omapscan: unknown argument '{x}'\n{HELP_SCAN}"));
    }
    let mut c = connect(&o, &pool, tmo)?;
    let mut out = Out::default();
    let (mut keys, mut bytes, mut pages, mut after) = (0u64, 0u64, 0u64, Vec::new());
    let t = Instant::now();
    loop {
        let r = one_msg(
            &mut c,
            &name,
            vec![OsdOp::omap_get_vals(&after, page, b"")],
            "page",
            &mut out,
        );
        let g = match r
            .and_then(|v| decode_counted::<OmapValsOut>(v.first(), &mut out, "page", &name))
        {
            Ok(g) => g,
            Err(_) => break,
        };
        pages += 1;
        keys += g.vals.len() as u64;
        bytes += g
            .vals
            .iter()
            .map(|(k, v)| (k.len() + v.len()) as u64)
            .sum::<u64>();
        match (g.truncated, g.vals.keys().next_back()) {
            (true, Some(last)) if max_pages == 0 || pages < max_pages => after = last.clone(),
            _ => break,
        }
    }
    let dur = t.elapsed().as_secs_f64().max(1e-9);
    let errs = out.errors();
    let summary = json!({"mode": "omapscan", "pool": pool, "object": name, "page": page, "pages": pages,
        "keys": keys, "bytes": bytes, "duration_s": dur, "keys_s": keys as f64 / dur, "errors": errs});
    report(fmt, &summary, &out, dur, None, errs)
}

/// Entry point of `oprobe omaprm ...`.
pub fn rm_cli(a: Vec<String>, o: Opts, pool: Option<String>) -> Result<ExitCode, String> {
    let (fmt, mut a) = outfmt::extract(&a, true)?;
    let pool = pool.ok_or("omaprm: -p POOL required")?;
    let name = take(&mut a, "--object")?.ok_or("omaprm: --object NAME required")?;
    let mode = take(&mut a, "--by")?.unwrap_or_else(|| "keys".into());
    let begin = take(&mut a, "--begin")?
        .ok_or("omaprm: --begin KEY required")?
        .into_bytes();
    let end = take(&mut a, "--end")?
        .ok_or("omaprm: --end KEY required")?
        .into_bytes();
    let batch = num(&mut a, "--batch", 1000u64)?.max(1);
    let tmo = secs(&mut a, "--op-timeout", 900.0)?;
    if let Some(x) = a.first() {
        return Err(format!("omaprm: unknown argument '{x}'\n{HELP_RM}"));
    }
    if mode != "range" && mode != "keys" {
        return Err(format!("omaprm: --by {mode} (range|keys)"));
    }
    let mut c = connect(&o, &pool, tmo)?;
    let mut out = Out::default();
    let (mut removed, mut batches) = (0u64, 0u64);
    let t = Instant::now();
    if mode == "range" {
        let mut op = OsdOp::new(code::OMAP_RM_KEY_RANGE);
        op.indata = denc::Encode::encode_to_vec(&opwire::OmapRmKeyRangeIn {
            begin: begin.clone(),
            end: end.clone(),
        })
        .map_err(|e| e.to_string())?
        .into();
        let _ = one_msg(&mut c, &name, vec![op], "rm_range", &mut out);
        batches = 1;
    } else {
        // GET_VALS uses an exclusive cursor; include the exact lower bound in the first compound read.
        let mut after = begin.clone();
        let mut first = true;
        loop {
            let r = one_msg(
                &mut c,
                &name,
                removal_page_ops(&after, batch, first)?,
                "list",
                &mut out,
            );
            let Ok(g) = r.and_then(|v| removal_page(&v, first, &mut out, &name)) else {
                break;
            };
            first = false;
            let ks: BTreeSet<Vec<u8>> = g.vals.keys().filter(|k| **k < end).cloned().collect();
            let last = g.vals.keys().next_back().cloned();
            if !ks.is_empty() {
                let n = ks.len() as u64;
                if one_msg(
                    &mut c,
                    &name,
                    vec![OsdOp::omap_rm_keys(&ks)],
                    "rm_keys",
                    &mut out,
                )
                .is_err()
                {
                    break;
                }
                removed += n;
                batches += 1;
            }
            match last {
                Some(l) if g.truncated && l < end => after = l,
                _ => break,
            }
        }
    }
    let dur = t.elapsed().as_secs_f64().max(1e-9);
    let errs = out.errors();
    let summary = json!({"mode": format!("omaprm-{mode}"), "pool": pool, "object": name,
        "begin": String::from_utf8_lossy(&begin), "end": String::from_utf8_lossy(&end), "batch": batch,
        "batches": batches, "removed_keys": removed, "duration_s": dur,
        "keys_s": if removed > 0 { removed as f64 / dur } else { 0.0 }, "errors": errs});
    report(fmt, &summary, &out, dur, None, errs)
}

// ------------------------------------------------------------------ report

/// Rate window of a label or counter: its own (`Out::secs`) or the report's duration.
fn window(all: &Out, k: &str, dur: f64) -> f64 {
    all.secs.get(k).copied().unwrap_or(dur).max(1e-9)
}

/// One record per op label: `op`, `n`, `ops_s`, `errors`, `p50_us`, `p99_us`, `p999_us`, `max_us`.
fn rows(all: &Out, dur: f64) -> Vec<Value> {
    all.stats
        .iter()
        .map(|(k, (h, e))| {
            json!({"op": k, "n": h.n, "ops_s": h.n as f64 / window(all, k, dur), "errors": e,
                   "p50_us": h.pct(0.5), "p99_us": h.pct(0.99), "p999_us": h.pct(0.999), "max_us": h.max})
        })
        .collect()
}

/// One record per counter (keys written or listed, ...): `counter`, `n`, `per_s`.
fn counter_rows(all: &Out, dur: f64) -> Vec<Value> {
    all.ctr
        .iter()
        .map(|(k, n)| json!({"counter": k, "n": n, "per_s": *n as f64 / window(all, k, dur)}))
        .collect()
}

fn report(
    fmt: outfmt::Format,
    summary: &Value,
    all: &Out,
    dur: f64,
    shards: Option<Vec<Value>>,
    errs: u64,
) -> Result<ExitCode, String> {
    let r = rows(all, dur);
    let ctr = counter_rows(all, dur);
    let mut doc = summary.clone();
    doc["ops"] = Value::Array(r.clone());
    doc["counters"] = Value::Array(ctr.clone());
    if let Some(s) = &shards {
        doc["shards"] = Value::Array(s.clone());
    }
    doc["error_kinds"] = json!(all.kinds);
    match fmt {
        outfmt::Format::Plain => {
            let mut s = String::new();
            if let Some(m) = summary.as_object() {
                for (k, v) in m.iter().filter(|(_, v)| !v.is_array()) {
                    let _ = writeln!(s, "{k}: {v}");
                }
            }
            let _ = writeln!(
                s,
                "{:<24} {:>9} {:>10} {:>6} {:>9} {:>9} {:>9} {:>9}",
                "op", "n", "ops/s", "err", "p50_us", "p99_us", "p999_us", "max_us"
            );
            for x in &r {
                let _ = writeln!(
                    s,
                    "{:<24} {:>9} {:>10.1} {:>6} {:>9} {:>9} {:>9} {:>9}",
                    x["op"].as_str().unwrap_or(""),
                    x["n"],
                    x["ops_s"].as_f64().unwrap_or(0.0),
                    x["errors"],
                    x["p50_us"],
                    x["p99_us"],
                    x["p999_us"],
                    x["max_us"]
                );
            }
            for x in &ctr {
                let _ = writeln!(
                    s,
                    "counter {}: {} ({:.0}/s)",
                    x["counter"].as_str().unwrap_or(""),
                    x["n"],
                    x["per_s"].as_f64().unwrap_or(0.0)
                );
            }
            for x in summary["phases"].as_array().into_iter().flatten() {
                let _ = writeln!(
                    s,
                    "phase {}: dentries/s {:.0}",
                    x["phase"].as_str().unwrap_or(""),
                    x["dentries_s"].as_f64().unwrap_or(0.0)
                );
            }
            for x in shards.iter().flatten() {
                let _ = writeln!(
                    s,
                    "shard {}: puts/s {:.1}",
                    x["object"].as_str().unwrap_or(""),
                    x["puts_s"].as_f64().unwrap_or(0.0)
                );
            }
            if !all.kinds.is_empty() {
                let _ = writeln!(s, "error kinds: {:?}", all.kinds);
            }
            print!("{s}");
        }
        // a zero-row stream is zero bytes: an empty line is not a JSON record
        outfmt::Format::Jsonl => {
            let rec: Vec<Value> = r.iter().chain(&ctr).cloned().collect();
            let out = fmt.records(&rec);
            if !out.is_empty() {
                println!("{out}");
            }
        }
        f => println!("{}", f.doc(&doc)),
    }
    for line in all.errs.summary_lines() {
        eprintln!("{line}");
    }
    Ok(if errs > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removal_includes_exact_begin_and_excludes_end() {
        let begin = b"a".to_vec();
        let end = b"c".to_vec();
        let ops = removal_page_ops(&begin, 10, true).unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].op, code::OMAP_GET_VALS_BY_KEYS);
        let exact: BTreeSet<Vec<u8>> = denc::from_slice(&ops[0].indata).unwrap();
        assert_eq!(exact, BTreeSet::from([begin.clone()]));
        let exact = KvMap::from([(begin.clone(), Vec::new())]);
        let next = OmapValsOut {
            vals: KvMap::from([(b"b".to_vec(), Vec::new()), (end.clone(), Vec::new())]),
            truncated: false,
        };
        let data = vec![denc::to_vec(&exact).unwrap(), denc::to_vec(&next).unwrap()];
        let page = removal_page(&data, true, &mut Out::default(), "obj").unwrap();
        let removed: Vec<_> = page.vals.keys().filter(|k| **k < end).cloned().collect();
        assert_eq!(removed, [begin, b"b".to_vec()]);
        assert_eq!(removal_page_ops(b"b", 10, false).unwrap().len(), 1);
    }

    #[test]
    fn malformed_scan_and_removal_pages_are_counted_errors() {
        let mut out = Out::default();
        assert!(decode_counted::<OmapValsOut>(Some(&vec![0]), &mut out, "page", "obj").is_err());
        assert_eq!(out.errors(), 1);
        assert!(removal_page(&[vec![0]], false, &mut out, "obj").is_err());
        assert_eq!(out.errors(), 2);
        let valid_page = denc::to_vec(&OmapValsOut::default()).unwrap();
        assert!(removal_page(&[vec![0], valid_page], true, &mut out, "obj").is_err());
        assert_eq!(out.errors(), 3);
    }

    #[test]
    fn distinct_errors_aggregate_by_op_object_and_errno() {
        let mut e = Errors::default();
        // two identical failures: one distinct entry, count 2
        assert!(
            e.record("prepare", "obj-a", "errno -13", 100).is_some(),
            "first occurrence"
        );
        assert!(
            e.record("prepare", "obj-a", "errno -13", 200).is_none(),
            "same key is not a new entry"
        );
        // a different errno is a second entry
        assert!(e.record("prepare", "obj-a", "errno -2", 300).is_some());
        assert_eq!(e.hits.len(), 2);

        let key = ErrorKey {
            op: "prepare".into(),
            object: "obj-a".into(),
            detail: error_detail("errno -13"),
        };
        assert_eq!(e.hits[&key].count, 2);
        assert_eq!(e.hits[&key].first_unix_ns, 100);
        let line = Errors::line(&key, &e.hits[&key]);
        assert!(line.contains("op=prepare"), "{line}");
        assert!(line.contains("object=obj-a"), "{line}");
        assert!(line.contains("errno -13"), "{line}");
        assert!(line.contains("Permission denied"), "{line}");
        assert!(line.contains("first_unix_ns=100"), "{line}");

        let summary = e.summary_lines();
        assert_eq!(summary.len(), 2);
        assert!(
            summary
                .iter()
                .any(|l| l.contains("errno -13") && l.contains("count=2")),
            "{summary:?}"
        );
        assert!(
            summary
                .iter()
                .any(|l| l.contains("errno -2") && l.contains("count=1")),
            "{summary:?}"
        );
    }

    #[test]
    fn trace_key_matches_the_osd_formula() {
        // vector computed from services/osd/osd/src/trace.rs key_of (client 4242, inc 0, tid 7)
        assert_eq!(trace_key(4242, 7), 0xa96d07a4da491afd);
        assert_ne!(trace_key(4242, 7), trace_key(4242, 8));
    }

    #[test]
    fn s3names_are_deterministic_and_realistic() {
        assert!(s3name(5).starts_with(b"data/"));
        assert_ne!(s3name(5), s3name(6));
        let lens: Vec<usize> = (0..5000).map(|i| s3name(i).len()).collect();
        assert!(lens.iter().all(|l| (30..=1100).contains(l)));
        let mid = lens.iter().filter(|l| **l <= 130).count();
        assert!(mid > 3500 && mid < 4700, "{mid}");
        assert!(lens.iter().any(|l| *l >= 200));
    }

    #[test]
    fn dentry_keys_have_head_suffix_and_size() {
        for i in 0..1000 {
            let k = dname(i);
            assert!(k.ends_with(b"_head"));
            assert!((15..=45).contains(&k.len()), "{}", k.len());
            assert!((400..=600).contains(&dir_val_len(&k)));
        }
    }

    #[test]
    fn out_merges() {
        let mut a = Out::default();
        a.ok("x", 10);
        a.add("c", 2);
        let mut b = Out::default();
        b.ok("x", 20);
        b.err("x", "e".into());
        b.add("c", 3);
        a.merge(b);
        assert_eq!(a.stats["x"].0.n, 2);
        assert_eq!(a.errors(), 1);
        assert_eq!(a.ctr["c"], 5);
    }

    #[test]
    fn commit_message_shape() {
        let st = Arc::new(vec![ObjState::new("d".into(), 100)]);
        let mut w = CommitWork {
            names: Arc::new(vec!["d".into()]),
            st,
            owned: vec![0],
            started: 0,
            batch: 16,
            hdr: 232,
            rng: Rng::new(1),
        };
        let (name, m, _) = w.start().expect("job");
        assert_eq!(name, "d");
        assert_eq!(m.ops.len(), 4);
        assert!(w.start().is_none());
    }

    #[test]
    fn oneobj_scenarios_hit_their_object() {
        for sc in [
            "read", "write", "append", "mixed", "omap-get", "omap-set", "meta",
        ] {
            let c = One {
                scenario: sc.into(),
                names: Arc::new(vec!["a".into(), "b".into()]),
                qd: 1,
                obj_size: 4_194_304,
                keys: 1000,
                spread_keys: 100,
                batch: 16,
                page: 100,
                val_len: 300,
                read_pct: 70,
                app_min: 4096,
                app_max: 65_536,
                app_roll: 67_108_864,
                share: 1,
                seed: 1,
            };
            let mut w = OneWork {
                c,
                cid: 3,
                rng: Rng::new(1),
                seq: 0,
                rm_seq: 0,
                rm_next: false,
                app_bytes: 0,
            };
            for _ in 0..20 {
                let (name, m, _) = w.start().expect("job");
                assert_eq!(name, "b", "{sc}: client 3 of 2 objects -> object 1");
                assert_eq!(m.ops.len(), 1, "{sc}");
            }
        }
    }

    #[test]
    fn fifo_rm_range_removes_own_oldest_inserts_in_order() {
        assert_eq!(fifo_rm_range(0, 15, 16), None, "not enough own inserts yet");
        assert_eq!(fifo_rm_range(0, 16, 16), Some(0..16));
        assert_eq!(fifo_rm_range(16, 40, 16), Some(16..32));
        assert_eq!(fifo_rm_range(32, 40, 16), None, "only 8 unremoved left");
        assert_eq!(fifo_rm_range(0, 0, 1), None);
    }

    #[test]
    fn append_rolls_over_below_object_limit() {
        let c = One {
            scenario: "append".into(),
            names: Arc::new(vec!["a".into()]),
            qd: 1,
            obj_size: 4_194_304,
            keys: 1,
            spread_keys: 1,
            batch: 1,
            page: 1,
            val_len: 1,
            read_pct: 0,
            app_min: 4096,
            app_max: 65_536,
            app_roll: 1 << 20,
            share: 4,
            seed: 1,
        };
        let mut w = OneWork {
            c,
            cid: 0,
            rng: Rng::new(1),
            seq: 0,
            rm_seq: 0,
            rm_next: false,
            app_bytes: 0,
        };
        let (mut rolls, mut peak) = (0, 0u64);
        for _ in 0..2000 {
            let (_, m, l) = w.start().expect("job");
            if l == "roll" {
                rolls += 1;
                assert_eq!(m.ops.len(), 1);
            } else {
                peak = peak.max(w.app_bytes * 4);
            }
        }
        assert!(rolls > 10, "rolls {rolls}");
        assert!(peak < (1 << 20) + 4 * 65_536, "peak {peak}");
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn modes_exclude_each_other_and_default_to_full() {
        let mut a = args(&["--keep"]);
        assert_eq!(Mode::take(&mut a, "t").unwrap(), Mode::Full);
        assert_eq!(a, ["--keep"]);
        let mut a = args(&["--setup-only"]);
        assert_eq!(Mode::take(&mut a, "t").unwrap(), Mode::SetupOnly);
        assert!(a.is_empty());
        let mut a = args(&["--setup-only", "--cleanup-only"]);
        assert!(Mode::take(&mut a, "t").unwrap_err().contains("exclude"));
    }

    #[test]
    fn rgw_modes_shape_the_run() {
        let pool = Some("p".to_string());
        let base = ["--prefix", "x", "--entries", "50", "--rewrite-shards", "3"];
        let full = parse_rgw(args(&base), pool.clone(), 0).unwrap();
        assert_eq!(
            (full.pop_from, full.put_clients, full.rewrite_shards),
            (0, 16, 3)
        );
        assert_eq!(
            full.rewrite_names(),
            ["x.rewrite.0000", "x.rewrite.0001", "x.rewrite.0002"]
        );
        let mut a = args(&base);
        a.push("--setup-only".into());
        let s = parse_rgw(a, pool.clone(), 0).unwrap();
        assert_eq!(
            (s.pop_from, s.put_clients, s.list_clients, s.get_clients),
            (0, 0, 0, 0)
        );
        assert!((s.keep, s.rewrite_shards, s.duration) == (true, 0, Duration::ZERO));
        let mut a = args(&base);
        a.push("--skip-setup".into());
        let k = parse_rgw(a, pool.clone(), 0).unwrap();
        assert_eq!(
            (k.pop_from, k.put_clients, k.keep, k.rewrite_shards),
            (50, 16, false, 3)
        );
        let mut a = args(&base);
        a.push("--cleanup-only".into());
        let c = parse_rgw(a, pool, 0).unwrap();
        assert_eq!(
            (c.pop_from, c.put_clients, c.keep, c.rewrite_names().len()),
            (50, 0, false, 0)
        );
        assert!(parse_rgw(args(&["--nope"]), Some("p".into()), 0).is_err());
    }

    #[test]
    fn own_windows_and_counters_in_the_rows() {
        let mut o = Out::default();
        for _ in 0..10 {
            o.ok("rewrite", 100);
            o.ok("put", 100);
        }
        o.add("rewrite_keys", 5000);
        o.secs.insert("rewrite".into(), 5.0);
        o.secs.insert("rewrite_keys".into(), 5.0);
        let r = rows(&o, 20.0);
        let by = |op: &str| r.iter().find(|x| x["op"] == op).unwrap().clone();
        assert_eq!(by("rewrite")["ops_s"], 2.0);
        assert_eq!(by("put")["ops_s"], 0.5);
        let c = counter_rows(&o, 20.0);
        assert_eq!(
            c,
            [json!({"counter": "rewrite_keys", "n": 5000, "per_s": 1000.0})]
        );
        let mut m = Out::default();
        m.merge(o);
        assert_eq!(m.secs["rewrite"], 5.0);
    }

    #[test]
    fn jsonl_rows_have_the_fields_benchrun_reads() {
        // tools/benchrun/src/cell.rs `evaluate_oprobe` reads exactly these keys
        let mut o = Out::default();
        o.ok("complete", 120);
        o.err("get", "errno -2".into());
        o.add("list_entries", 7);
        let r = rows(&o, 2.0);
        let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
        for x in &r {
            assert_eq!(
                keys(x),
                [
                    "errors", "max_us", "n", "op", "ops_s", "p50_us", "p999_us", "p99_us"
                ]
            );
        }
        assert_eq!(r[1]["errors"], 1);
        assert_eq!(keys(&counter_rows(&o, 2.0)[0]), ["counter", "n", "per_s"]);
    }

    #[test]
    fn report_formats_and_exit_codes() {
        let mut o = Out::default();
        o.ok("put", 100);
        let s = json!({"mode": "t"});
        for f in [
            outfmt::Format::Plain,
            outfmt::Format::Json,
            outfmt::Format::JsonPretty,
            outfmt::Format::Jsonl,
        ] {
            assert!(report(f, &s, &o, 1.0, None, 0).is_ok());
        }
    }
}
