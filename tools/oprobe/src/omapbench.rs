// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `oprobe omapbench`: omap stress test (pipelined, time-phased). See `HELP` and doc/perf/omapbench-*.md.
//!
//! Group A = 1 object with N_A keys, group B = `b_objs` objects with N_B keys each. Keys: 64 B (hex of a
//! splitmix chain over the key index), values 256 B (self-checking: head = generation, body = f(key, gen)).
//! Each object keeps a sliding window of live key indices `[del, n + ins)`: insert adds index `n + ins++`,
//! delete removes index `del++` (constant entry count); read/update/list pick inside the window minus a
//! safety margin so in-flight ops never touch a key being inserted or deleted.
//! Phases: populate -> base (B only) -> ab (A+B) -> drain (A stops) -> delete (remove object A) -> recover.
//! Workers (one thread + one `Probe` each, no shared locks on the hot path) keep per-second histograms
//! and ship them once per second over a channel to the main thread.

use crate::client::{Done, Opts, Probe, Target};
use crate::script::ScriptMsg;
use opwire::{KvMap, OmapValsOut, OsdOp, op as code};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

pub const HELP: &str = "\
omapbench -p POOL [options]   omap stress test, pipelined (N clients x QD), phases populate/base/ab/drain/delete/recover
  --prefix S       object name prefix (default omapbench-<time>)      --outdir DIR result dir (default omapbench-out)
  --scale F        multiply N_A, N_B (default 1)                      --n-a N (2000000)  --n-b N (20000)  --b-objs N (100)
  --clients N      clients per group (8)    --qd N (64)               --pop-clients N (16)  --pop-qd N (4)  --batch N (1024)
  --mix R,L1,L2,U,I,D   percent: read-by-keys,list128,list16384,update,insert,delete (25,10,10,25,15,15)
  --read-keys N    keys per read op (8)     --list-small N (128)  --list-big N (16384)
  --t-base S (120)  --t-ab S (360)  --t-rec S (120)   phase seconds (recover counts from the end of the delete)
  --op-timeout S (60)  --del-timeout S (900)  --stall S (90: abort rc 3 when B completes nothing that long)
  --pop-only       populate group A only (no B objects), no base/ab/delete/recover phases, then cleanup
  --small-objects N  extra fill: N objects with 1 key each (group S, populate only)
  --pop-warm W     probe only (cold-start split): before its first batch each populate client runs one blocking op on object A:
                   none (default, cold), session (stat: OSD session + PG path, object stays absent), object (omap set of key 0:
                   also creates the object and replicates; the batch rewrites the same value). Latency in pop.<client>.tsv `# warm`
  --seed N  --no-verify (skip value checks)  --keep (do not remove the B objects at the end)
output: series.tsv (per second: phase group op ops err p50_us p99_us max_us; op 'point' = read+update+insert+delete),
  summary.txt (also stdout), phases.tsv, pop.<client>.tsv (one line per populate batch: seq batch grp submit_us done_us
  lat_us ok; times from the tool start, `# t0_epoch_us N` header). exit 0 ok, 1 errors counted, 3 stall/abort.
";

pub const NOPS: usize = 7;
const OPN: [&str; NOPS + 1] = [
    "read", "list128", "list16k", "update", "insert", "delete", "populate", "point",
];
const POINT: usize = 7;
const GN: [&str; 3] = ["A", "B", "S"];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Read = 0,
    ListSmall = 1,
    ListBig = 2,
    Update = 3,
    Insert = 4,
    Delete = 5,
    Populate = 6,
}

const MIX_OPS: [Op; 6] = [
    Op::Read,
    Op::ListSmall,
    Op::ListBig,
    Op::Update,
    Op::Insert,
    Op::Delete,
];

// ------------------------------------------------------------------ rng, keys, values

/// splitmix64 step.
pub fn splitmix(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[derive(Debug)]
pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed ^ 0xA076_1D64_78BD_642F)
    }
    pub fn next_u64(&mut self) -> u64 {
        splitmix(&mut self.0)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        ((u128::from(self.next_u64()) * u128::from(n.max(1))) >> 64) as u64
    }
}

pub const KEY_LEN: usize = 64;

/// 64-byte key of index `idx`: 4 x 16 hex chars; sort order is unrelated to `idx`.
pub fn key(idx: u64) -> Vec<u8> {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = idx;
    let mut k = Vec::with_capacity(KEY_LEN);
    for _ in 0..KEY_LEN / 16 {
        let w = splitmix(&mut s);
        for i in (0..16).rev() {
            k.push(H[((w >> (i * 4)) & 15) as usize]);
        }
    }
    k
}

fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, c| {
        (h ^ u64::from(*c)).wrapping_mul(0x100_0000_01b3)
    })
}

/// Self-checking value: 8 bytes generation + pseudo-random body derived from (key, generation).
pub fn value(key: &[u8], generation: u64, len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    v.extend_from_slice(&generation.to_le_bytes());
    let mut s = fnv(key) ^ generation;
    while v.len() < len {
        v.extend_from_slice(&splitmix(&mut s).to_le_bytes());
    }
    v.truncate(len);
    v
}

/// Does `val` belong to `key` (right length, body matches the generation in its head)?
pub fn value_ok(key: &[u8], val: &[u8], len: usize) -> bool {
    val.len() == len && len >= 8 && {
        let g = u64::from_le_bytes(val[..8].try_into().expect("8"));
        value(key, g, len) == val
    }
}

/// Pick an op by percent weights.
pub fn pick(mix: &[u32; 6], r: u64) -> Op {
    let tot: u64 = mix.iter().map(|x| u64::from(*x)).sum::<u64>().max(1);
    let mut x = r % tot;
    for (i, w) in mix.iter().enumerate() {
        if x < u64::from(*w) {
            return MIX_OPS[i];
        }
        x -= u64::from(*w);
    }
    Op::Read
}

pub fn parse_mix(s: &str) -> Result<[u32; 6], String> {
    let v: Vec<u32> = s
        .split(',')
        .map(|x| {
            x.trim()
                .parse::<u32>()
                .map_err(|_| format!("bad --mix '{s}'"))
        })
        .collect::<Result<_, _>>()?;
    let a: [u32; 6] = v
        .try_into()
        .map_err(|_| "--mix needs 6 numbers".to_string())?;
    if a.iter().sum::<u32>() == 0 {
        return Err("--mix all zero".into());
    }
    if a[4] != a[5] {
        eprintln!("omapbench: warning: insert != delete share, entry count will drift");
    }
    Ok(a)
}

// ------------------------------------------------------------------ histogram

const HBUCKETS: usize = 64 * 36;

/// HDR-like log-linear histogram of microseconds (64 sub-buckets per octave, <= 1.6 % error).
#[derive(Clone, Debug)]
pub struct Hist {
    c: Vec<u32>,
    pub n: u64,
    pub max: u64,
}

impl Default for Hist {
    fn default() -> Self {
        Hist::new()
    }
}

fn hidx(v: u64) -> usize {
    if v < 64 {
        return v as usize;
    }
    let e = 63 - v.leading_zeros() as usize;
    let sh = e - 6;
    (sh * 64 + (v >> sh) as usize).min(HBUCKETS - 1)
}

/// Upper edge (inclusive) of bucket `i`.
fn hhigh(i: usize) -> u64 {
    if i < 64 {
        return i as u64;
    }
    let sh = (i >> 6) - 1;
    let m = (i - sh * 64) as u64;
    ((m + 1) << sh) - 1
}

impl Hist {
    pub fn new() -> Hist {
        Hist {
            c: vec![0; HBUCKETS],
            n: 0,
            max: 0,
        }
    }
    pub fn rec(&mut self, v: u64) {
        self.c[hidx(v)] += 1;
        self.n += 1;
        self.max = self.max.max(v);
    }
    pub fn merge(&mut self, o: &Hist) {
        for (a, b) in self.c.iter_mut().zip(&o.c) {
            *a += *b;
        }
        self.n += o.n;
        self.max = self.max.max(o.max);
    }
    /// Non-empty buckets as (inclusive upper edge in us, count): the raw histogram.
    pub fn buckets(&self) -> Vec<(u64, u64)> {
        self.c
            .iter()
            .enumerate()
            .filter(|(_, n)| **n != 0)
            .map(|(i, n)| (hhigh(i), u64::from(*n)))
            .collect()
    }
    /// Value at quantile `q` (0..=1); 0 when empty.
    pub fn pct(&self, q: f64) -> u64 {
        if self.n == 0 {
            return 0;
        }
        let want = ((q * self.n as f64).ceil() as u64).clamp(1, self.n);
        let mut seen = 0u64;
        for (i, c) in self.c.iter().enumerate() {
            seen += u64::from(*c);
            if seen >= want {
                return hhigh(i).min(self.max);
            }
        }
        self.max
    }
}

// ------------------------------------------------------------------ config and groups

#[derive(Clone, Debug)]
pub struct Cfg {
    pub pool: String,
    pub prefix: String,
    pub n_a: u64,
    pub n_b: u64,
    pub b_objs: usize,
    pub clients: usize,
    pub qd: usize,
    pub pop_clients: usize,
    pub pop_qd: usize,
    pub batch: usize,
    pub mix: [u32; 6],
    pub read_keys: usize,
    pub list_small: u64,
    pub list_big: u64,
    pub val_len: usize,
    pub t_base: f64,
    pub t_ab: f64,
    pub t_rec: f64,
    pub op_timeout: f64,
    pub del_timeout: f64,
    pub stall: f64,
    pub seed: u64,
    pub verify: bool,
    pub keep: bool,
    /// Extra populate objects with one key each (group S, fill only).
    pub small_objects: u64,
    /// Populate group A only (no B objects), then clean up: no base/ab/delete/recover phases.
    pub pop_only: bool,
    /// Probe only: one blocking op per populate client before its first batch (`--pop-warm`).
    pub pop_warm: Warm,
    pub out: PathBuf,
}

/// `--pop-warm`: what a populate client does before its first batch (splits the cold start of the first QD).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Warm {
    /// Nothing: the first batches pay session setup and the first op on the object (the gate shape).
    None,
    /// `stat` of object A: session to the primary and the PG op path; the object stays absent.
    Session,
    /// omap set of key 0 on object A: also creates the object and replicates it.
    Object,
}

/// One object and its live-window counters.
#[derive(Debug)]
pub struct ObjState {
    pub name: String,
    pub n: u64,
    ins: AtomicU64,
    del: AtomicU64,
}

impl ObjState {
    pub fn new(name: String, n: u64) -> ObjState {
        ObjState {
            name,
            n,
            ins: AtomicU64::new(0),
            del: AtomicU64::new(0),
        }
    }
    /// Index range `[lo, hi)` safe for read/update/list (live window minus margin; never empty).
    pub fn window(&self) -> (u64, u64) {
        let lo = self.del.load(Relaxed);
        let hi = self.n + self.ins.load(Relaxed);
        let m = (self.n / 8).min(2048);
        if hi > lo + 2 * m + 1 {
            (lo + m, hi - m)
        } else {
            (lo, hi.max(lo + 1))
        }
    }
    pub fn next_insert(&self) -> u64 {
        self.n + self.ins.fetch_add(1, Relaxed)
    }
    pub fn next_delete(&self) -> u64 {
        self.del.fetch_add(1, Relaxed)
    }
    pub fn live(&self) -> u64 {
        (self.n + self.ins.load(Relaxed)).saturating_sub(self.del.load(Relaxed))
    }
}

#[derive(Debug)]
pub struct Group {
    pub id: usize,
    pub objs: Vec<ObjState>,
}

pub fn make_groups(c: &Cfg) -> [Arc<Group>; 2] {
    let a = Group {
        id: 0,
        objs: vec![ObjState::new(format!("{}-A", c.prefix), c.n_a)],
    };
    let b = Group {
        id: 1,
        objs: (0..if c.pop_only { 0 } else { c.b_objs })
            .map(|i| ObjState::new(format!("{}-B-{i:03}", c.prefix), c.n_b))
            .collect(),
    };
    [Arc::new(a), Arc::new(b)]
}

fn kv_one(k: Vec<u8>, v: Vec<u8>) -> KvMap {
    let mut m = KvMap::new();
    m.insert(k, v);
    m
}

fn msg(o: OsdOp) -> ScriptMsg {
    ScriptMsg {
        ops: vec![o],
        ..Default::default()
    }
}

/// Build one mix op against a random object of `g`. Returns (object index, message, keys wanted back).
pub fn build_op(op: Op, g: &Group, rng: &mut Rng, c: &Cfg) -> (usize, ScriptMsg, usize) {
    let oi = rng.below(g.objs.len() as u64) as usize;
    let o = &g.objs[oi];
    let (lo, hi) = o.window();
    let pick_idx = |r: &mut Rng| lo + r.below(hi - lo);
    match op {
        Op::Read => {
            let set: BTreeSet<Vec<u8>> = (0..c.read_keys).map(|_| key(pick_idx(rng))).collect();
            let want = set.len();
            let mut x = OsdOp::new(code::OMAP_GET_VALS_BY_KEYS);
            x.indata = denc::Encode::encode_to_vec(&set).expect("vec").into();
            (oi, msg(x), want)
        }
        Op::ListSmall | Op::ListBig => {
            let n = if op == Op::ListSmall {
                c.list_small
            } else {
                c.list_big
            };
            let k = key(pick_idx(rng));
            (oi, msg(OsdOp::omap_get_vals(&k, n, b"")), 0)
        }
        Op::Update => {
            let k = key(pick_idx(rng));
            let v = value(&k, rng.next_u64(), c.val_len);
            (oi, msg(OsdOp::omap_set_vals(&kv_one(k, v))), 0)
        }
        Op::Insert => {
            let k = key(o.next_insert());
            let v = value(&k, rng.next_u64(), c.val_len);
            (oi, msg(OsdOp::omap_set_vals(&kv_one(k, v))), 0)
        }
        Op::Delete => {
            let mut s = BTreeSet::new();
            s.insert(key(o.next_delete()));
            (oi, msg(OsdOp::omap_rm_keys(&s)), 0)
        }
        Op::Populate => unreachable!("populate has its own builder"),
    }
}

// ------------------------------------------------------------------ worker side

enum Msg {
    Sample {
        sec: u32,
        group: usize,
        op: usize,
        hist: Box<Hist>,
        errs: u64,
    },
    Done {
        kinds: BTreeMap<String, u64>,
        misses: u64,
        bad: u64,
    },
    Delete {
        secs: f64,
        res: Result<(), String>,
    },
    Fatal(String),
}

struct Rec {
    t0: Instant,
    group: usize,
    cur: u32,
    h: Vec<Hist>,
    errs: [u64; NOPS],
    kinds: BTreeMap<String, u64>,
    misses: u64,
    bad: u64,
    tx: Sender<Msg>,
}

impl Rec {
    fn new(t0: Instant, group: usize, tx: Sender<Msg>) -> Rec {
        Rec {
            t0,
            group,
            cur: 0,
            h: (0..NOPS).map(|_| Hist::new()).collect(),
            errs: [0; NOPS],
            kinds: BTreeMap::new(),
            misses: 0,
            bad: 0,
            tx,
        }
    }
    fn flush(&mut self) {
        for op in 0..NOPS {
            if self.h[op].n > 0 || self.errs[op] > 0 {
                let hist = Box::new(std::mem::take(&mut self.h[op]));
                let _ = self.tx.send(Msg::Sample {
                    sec: self.cur,
                    group: self.group,
                    op,
                    hist,
                    errs: self.errs[op],
                });
                self.errs[op] = 0;
            }
        }
    }
    fn at(&mut self, t: Instant) {
        let sec = t.duration_since(self.t0).as_secs() as u32;
        if sec != self.cur {
            self.flush();
            self.cur = sec;
        }
    }
    fn ok(&mut self, op: usize, d: &Done) {
        self.at(d.finished);
        self.h[op].rec(d.finished.duration_since(d.submitted).as_micros() as u64);
    }
    fn err(&mut self, op: usize, d: &Done, kind: String) {
        self.at(d.finished);
        self.errs[op] += 1;
        *self.kinds.entry(format!("{}:{kind}", OPN[op])).or_default() += 1;
    }
    fn finish(mut self) {
        self.flush();
        let _ = self.tx.send(Msg::Done {
            kinds: std::mem::take(&mut self.kinds),
            misses: self.misses,
            bad: self.bad,
        });
    }
}

fn connect(o: &Opts, c: &Cfg, t_secs: f64) -> Result<(Probe, i64), String> {
    let mut o = o.clone();
    o.timeout = Duration::from_secs_f64(t_secs);
    let mut p = Probe::connect(o)?;
    p.idle_sleep = Duration::from_micros(100);
    let id = p
        .osdmap()
        .pool_id_by_name(&c.pool)
        .ok_or_else(|| format!("no pool '{}'", c.pool))?;
    Ok((p, id))
}

pub(crate) fn target(pool: i64, name: &str) -> Target {
    Target {
        pool,
        oid: name.as_bytes().to_vec(),
        nspace: Vec::new(),
        key: Vec::new(),
        force_osd: None,
    }
}

/// Classify a finished op: Ok(()) or Err(kind). Verifies read payloads (counts misses / bad values).
fn judge(d: &Done, op: Op, want: usize, c: &Cfg, rec: &mut Rec) -> Result<(), String> {
    let Some(r) = &d.reply else {
        return Err(d.err.chars().take(60).collect());
    };
    let rv = r.ops.first().map_or(0, |o| o.rval);
    let res = if r.result < 0 { r.result } else { rv };
    if res < 0 {
        return Err(format!("errno {res}"));
    }
    if !c.verify {
        return Ok(());
    }
    let out = r.ops.first().map(|o| &o.outdata);
    let mut check = |m: &KvMap| {
        rec.bad += m.iter().filter(|(k, v)| !value_ok(k, v, c.val_len)).count() as u64;
    };
    match (op, out) {
        (Op::Read, Some(b)) => match denc::from_slice::<KvMap>(b) {
            Ok(m) => {
                rec.misses += want.saturating_sub(m.len()) as u64;
                check(&m);
            }
            Err(_) => return Err("undecodable reply".into()),
        },
        (Op::ListSmall | Op::ListBig, Some(b)) => match denc::from_slice::<OmapValsOut>(b) {
            Ok(m) => check(&m.vals),
            Err(_) => return Err("undecodable reply".into()),
        },
        _ => {}
    }
    Ok(())
}

fn mix_worker(
    o: Opts,
    c: Arc<Cfg>,
    g: Arc<Group>,
    id: u64,
    t0: Instant,
    stop: Arc<AtomicBool>,
    tx: Sender<Msg>,
) {
    let (mut p, pool) = match connect(&o, &c, c.op_timeout) {
        Ok(x) => x,
        Err(e) => {
            let _ = tx.send(Msg::Fatal(format!("{} client {id}: {e}", GN[g.id])));
            return;
        }
    };
    let mut rng = Rng::new(c.seed ^ (id << 32) ^ ((g.id as u64) << 48));
    let mut rec = Rec::new(t0, g.id, tx.clone());
    let mut tags: Vec<Option<(Op, usize)>> = vec![None; c.qd * 2 + 8];
    let mut free: Vec<usize> = (0..tags.len()).collect();
    loop {
        let stopping = stop.load(Relaxed);
        if stopping && p.in_flight() == 0 {
            break;
        }
        let mut submit_failed = false;
        while !stopping && p.in_flight() < c.qd {
            let op = pick(&c.mix, rng.next_u64());
            let (oi, m, want) = build_op(op, &g, &mut rng, &c);
            let Some(slot) = free.pop() else { break };
            tags[slot] = Some((op, want));
            if let Err(e) = p.submit(target(pool, &g.objs[oi].name), m, slot as u64) {
                free.push(slot);
                tags[slot] = None;
                let now = Instant::now();
                let d = Done {
                    tag: 0,
                    tid: 0,
                    reply: None,
                    err: format!("submit: {e}"),
                    submitted: now,
                    finished: now,
                };
                rec.err(op as usize, &d, "submit".into());
                submit_failed = true;
                break;
            }
        }
        if submit_failed {
            std::thread::sleep(Duration::from_millis(20));
        }
        for d in p.poll() {
            let slot = d.tag as usize;
            let Some((op, want)) = tags[slot].take() else {
                continue;
            };
            free.push(slot);
            match judge(&d, op, want, &c, &mut rec) {
                Ok(()) => rec.ok(op as usize, &d),
                Err(k) => rec.err(op as usize, &d, k),
            }
        }
    }
    rec.finish();
}

/// `--pop-warm` op of one populate client (blocking). Returns the `# warm` header line of pop.<client>.tsv ("" = none).
fn pop_warm(p: &mut Probe, pool: i64, name: &str, c: &Cfg) -> Result<String, String> {
    let (kind, m) = match c.pop_warm {
        Warm::None => return Ok(String::new()),
        Warm::Session => ("session", msg(OsdOp::stat())),
        Warm::Object => {
            let k = key(0);
            let v = value(&k, splitmix(&mut { 0 }), c.val_len);
            ("object", msg(OsdOp::omap_set_vals(&kv_one(k, v))))
        }
    };
    let t = Instant::now();
    let r = p.exec(&target(pool, name), &m)?;
    let us = t.elapsed().as_micros();
    let rep = r
        .reply
        .ok_or_else(|| format!("{kind}: no reply ({})", r.note))?;
    let res = if rep.result < 0 {
        rep.result
    } else {
        rep.ops.first().map_or(0, |o| o.rval)
    };
    // stat of the absent object answers ENOENT (-2): the session and the PG path are warm all the same
    if res < 0 && !(c.pop_warm == Warm::Session && res == -2) {
        return Err(format!("{kind}: errno {res}"));
    }
    Ok(format!("# warm {kind} {us}\n"))
}

#[expect(clippy::too_many_arguments)]
fn pop_worker(
    o: Opts,
    c: Arc<Cfg>,
    gs: Arc<[Arc<Group>; 2]>,
    tasks: Arc<Vec<(usize, usize, u64)>>,
    next: Arc<AtomicU64>,
    t0: Instant,
    id: u64,
    tx: Sender<Msg>,
) {
    let (mut p, pool) = match connect(&o, &c, c.op_timeout.max(120.0)) {
        Ok(x) => x,
        Err(e) => {
            let _ = tx.send(Msg::Fatal(format!("populate client {id}: {e}")));
            return;
        }
    };
    let warm = match pop_warm(&mut p, pool, &gs[0].objs[0].name, &c) {
        Ok(w) => w,
        Err(e) => {
            let _ = tx.send(Msg::Fatal(format!("populate client {id} warm: {e}")));
            return;
        }
    };
    let mut recs = [
        Rec::new(t0, 0, tx.clone()),
        Rec::new(t0, 1, tx.clone()),
        Rec::new(t0, 2, tx.clone()),
    ];
    // per batch: (seq, batch, group, submitted, finished, ok) -> pop.<id>.tsv (tail analysis over time)
    let mut slots: Vec<Option<(usize, u64, u64)>> = vec![None; c.pop_qd + 4];
    let mut seq = 0u64;
    let mut trace: Vec<(u64, u64, usize, Instant, Instant, bool)> = Vec::new();
    let mut free: Vec<usize> = (0..slots.len()).collect();
    let mut exhausted = false;
    loop {
        while !exhausted && p.in_flight() < c.pop_qd && !free.is_empty() {
            let t = next.fetch_add(1, Relaxed) as usize;
            let Some(&(gi, oi, b)) = tasks.get(t) else {
                exhausted = true;
                break;
            };
            let small_name;
            let (name, n) = if gi == 2 {
                small_name = format!("{}-S-{oi}", c.prefix);
                (&small_name, 1)
            } else {
                let ob = &gs[gi].objs[oi];
                (&ob.name, ob.n)
            };
            let lo = b * c.batch as u64;
            let hi = (lo + c.batch as u64).min(n);
            let m: KvMap = (lo..hi)
                .map(|i| {
                    let k = key(i);
                    let v = value(&k, splitmix(&mut { i }), c.val_len);
                    (k, v)
                })
                .collect();
            let slot = free.pop().expect("checked");
            slots[slot] = Some((gi, seq, b));
            seq += 1;
            if let Err(e) = p.submit(
                target(pool, name),
                msg(OsdOp::omap_set_vals(&m)),
                slot as u64,
            ) {
                let _ = tx.send(Msg::Fatal(format!("populate submit: {e}")));
                return;
            }
        }
        if exhausted && p.in_flight() == 0 {
            break;
        }
        for d in p.poll() {
            let slot = d.tag as usize;
            let Some((gi, sq, b)) = slots[slot].take() else {
                continue;
            };
            free.push(slot);
            let mut dummy = Rec::new(t0, gi, tx.clone());
            let r = judge(&d, Op::Populate, 0, &c, &mut dummy);
            trace.push((sq, b, gi, d.submitted, d.finished, r.is_ok()));
            match r {
                Ok(()) => recs[gi].ok(Op::Populate as usize, &d),
                Err(k) => recs[gi].err(Op::Populate as usize, &d, k),
            }
        }
    }
    let us = |t: Instant| t.saturating_duration_since(t0).as_micros();
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_micros())
        .saturating_sub(t0.elapsed().as_micros());
    let mut f =
        format!("# t0_epoch_us {epoch}\n{warm}seq\tbatch\tgrp\tsubmit_us\tdone_us\tlat_us\tok\n");
    for (sq, b, gi, s, e, ok) in trace {
        let _ = writeln!(
            f,
            "{sq}\t{b}\t{}\t{}\t{}\t{}\t{}",
            ["A", "B", "S"][gi],
            us(s),
            us(e),
            us(e) - us(s),
            u8::from(ok)
        );
    }
    if let Err(e) = std::fs::write(c.out.join(format!("pop.{id}.tsv")), f) {
        let _ = tx.send(Msg::Fatal(format!("pop.{id}.tsv: {e}")));
    }
    for r in recs {
        r.finish();
    }
}

fn delete_worker(o: Opts, c: Arc<Cfg>, name: String, tx: Sender<Msg>) {
    let (mut p, pool) = match connect(&o, &c, c.del_timeout) {
        Ok(x) => x,
        Err(e) => {
            let _ = tx.send(Msg::Delete {
                secs: 0.0,
                res: Err(format!("connect: {e}")),
            });
            return;
        }
    };
    let t = Instant::now();
    let res = match p.submit(target(pool, &name), msg(OsdOp::delete()), 0) {
        Err(e) => Err(format!("submit: {e}")),
        Ok(()) => loop {
            let ds = p.poll();
            if let Some(d) = ds.into_iter().next() {
                break match d.reply {
                    None => Err(d.err),
                    Some(r) if r.result < 0 => Err(format!("errno {}", r.result)),
                    Some(_) => Ok(()),
                };
            }
        },
    };
    let _ = tx.send(Msg::Delete {
        secs: t.elapsed().as_secs_f64(),
        res,
    });
}

// ------------------------------------------------------------------ aggregation

#[derive(Clone, Debug)]
pub struct Row {
    pub sec: u32,
    pub group: usize,
    pub op: usize,
    pub n: u64,
    pub errs: u64,
    pub p50: u64,
    pub p99: u64,
    pub max: u64,
}

#[derive(Default)]
struct PhaseAgg {
    h: Hist,
    errs: u64,
}

/// First second `s >= from` such that the next `sustain` seconds all have a B point p99 `<= limit`.
/// `series`: (sec, p99) of every second with samples; a missing second counts as bad.
pub fn recovery_secs(
    series: &BTreeMap<u32, u64>,
    from: u32,
    limit: u64,
    sustain: u32,
) -> Option<u32> {
    let last = *series.keys().next_back()?;
    (from..=last).find_map(|s| {
        (s + sustain <= last + 1
            && (s..s + sustain).all(|x| series.get(&x).is_some_and(|p| *p <= limit)))
        .then_some(s - from)
    })
}

struct Agg {
    open: BTreeMap<(u32, usize, usize), (Hist, u64)>,
    rows: Vec<Row>,
    phases: Vec<(String, u32, Instant)>,
    ph: BTreeMap<(usize, usize, usize), PhaseAgg>,
    kinds: BTreeMap<String, u64>,
    misses: u64,
    bad: u64,
    done: usize,
    fatal: Vec<String>,
    del: Option<(f64, Result<(), String>)>,
    last_ok_b: Instant,
    t0_epoch: u64,
}

impl Agg {
    fn phase_idx(&self, sec: u32) -> usize {
        self.phases.iter().rposition(|p| p.1 <= sec).unwrap_or(0)
    }
    fn handle(&mut self, m: Msg) {
        match m {
            Msg::Sample {
                sec,
                group,
                op,
                hist,
                errs,
            } => {
                if group == 1 && hist.n > 0 {
                    self.last_ok_b = Instant::now();
                }
                let e = self
                    .open
                    .entry((sec, group, op))
                    .or_insert_with(|| (Hist::new(), 0));
                e.0.merge(&hist);
                e.1 += errs;
            }
            Msg::Done { kinds, misses, bad } => {
                for (k, v) in kinds {
                    *self.kinds.entry(k).or_default() += v;
                }
                self.misses += misses;
                self.bad += bad;
                self.done += 1;
            }
            Msg::Delete { secs, res } => self.del = Some((secs, res)),
            Msg::Fatal(s) => self.fatal.push(s),
        }
    }
    fn close_upto(&mut self, limit: u32) {
        let keys: Vec<(u32, usize, usize)> =
            self.open.range(..(limit, 0, 0)).map(|(k, _)| *k).collect();
        let mut points: BTreeMap<(u32, usize), (Hist, u64)> = BTreeMap::new();
        for k in keys {
            let (h, errs) = self.open.remove(&k).expect("listed");
            let (sec, g, op) = k;
            if op <= Op::Delete as usize {
                let e = points.entry((sec, g)).or_insert_with(|| (Hist::new(), 0));
                e.0.merge(&h);
                e.1 += errs;
            }
            self.emit(sec, g, op, h, errs);
        }
        for ((sec, g), (h, errs)) in points {
            self.emit(sec, g, POINT, h, errs);
        }
    }
    fn emit(&mut self, sec: u32, g: usize, op: usize, h: Hist, errs: u64) {
        self.rows.push(Row {
            sec,
            group: g,
            op,
            n: h.n,
            errs,
            p50: h.pct(0.5),
            p99: h.pct(0.99),
            max: h.max,
        });
        let pi = self.phase_idx(sec);
        let e = self.ph.entry((pi, g, op)).or_default();
        e.h.merge(&h);
        e.errs += errs;
    }
}

// ------------------------------------------------------------------ controller

enum Pump {
    Ok,
    Timeout,
    Stall,
    Fatal,
}

struct Ctl {
    agg: Agg,
    rx: Receiver<Msg>,
    t0: Instant,
    stall: Duration,
    last_print: Instant,
}

impl Ctl {
    fn sec(&self) -> u32 {
        self.t0.elapsed().as_secs() as u32
    }
    fn mark(&mut self, name: &str) {
        let s = self.sec();
        eprintln!("[{s:5}s] phase {name}");
        self.agg.phases.push((name.to_string(), s, Instant::now()));
    }
    fn progress(&mut self) {
        if self.last_print.elapsed() < Duration::from_secs(10) {
            return;
        }
        self.last_print = Instant::now();
        let ph = self
            .agg
            .phases
            .last()
            .map_or("-", |p| p.0.as_str())
            .to_string();
        let last = self
            .agg
            .rows
            .iter()
            .rev()
            .find(|r| r.op == POINT && r.group == 1)
            .cloned();
        let errs: u64 = self.agg.rows.iter().map(|r| r.errs).sum::<u64>()
            - self
                .agg
                .rows
                .iter()
                .filter(|r| r.op == POINT)
                .map(|r| r.errs)
                .sum::<u64>();
        match last {
            Some(r) => eprintln!(
                "[{:5}s] {ph}: B point sec {} ops {} p99 {} us, errors so far {errs}",
                self.sec(),
                r.sec,
                r.n,
                r.p99
            ),
            None => eprintln!("[{:5}s] {ph}: errors so far {errs}", self.sec()),
        }
    }
    fn pump(
        &mut self,
        max: Duration,
        watch_stall: bool,
        mut cond: impl FnMut(&Agg) -> bool,
    ) -> Pump {
        let end = Instant::now() + max;
        loop {
            match self.rx.recv_timeout(Duration::from_millis(100)) {
                Ok(m) => self.agg.handle(m),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {}
            }
            while let Ok(m) = self.rx.try_recv() {
                self.agg.handle(m);
            }
            let lim = self.sec().saturating_sub(3);
            self.agg.close_upto(lim);
            self.progress();
            if !self.agg.fatal.is_empty() {
                return Pump::Fatal;
            }
            if cond(&self.agg) {
                return Pump::Ok;
            }
            if watch_stall && self.agg.last_ok_b.elapsed() > self.stall {
                eprintln!(
                    "WARNING TIMEOUT omapbench stall exceeded {}s (group B completed nothing)",
                    self.stall.as_secs_f64()
                );
                return Pump::Stall;
            }
            if Instant::now() >= end {
                return Pump::Timeout;
            }
        }
    }
}

fn spawn_mix(
    o: &Opts,
    c: &Arc<Cfg>,
    g: &Arc<Group>,
    t0: Instant,
    stop: &Arc<AtomicBool>,
    tx: &Sender<Msg>,
) -> Vec<std::thread::JoinHandle<()>> {
    (0..c.clients as u64)
        .map(|i| {
            let (o, c, g, stop, tx) = (o.clone(), c.clone(), g.clone(), stop.clone(), tx.clone());
            std::thread::spawn(move || mix_worker(o, c, g, i, t0, stop, tx))
        })
        .collect()
}

/// Take `NAME VALUE` out of `v`: `None` = the option is absent, an option as the last argument is a usage error
/// (never silently dropped, which would fall back to a default).
pub(crate) fn take(v: &mut Vec<String>, name: &str) -> Result<Option<String>, String> {
    let Some(i) = v.iter().position(|x| x == name) else {
        return Ok(None);
    };
    v.remove(i);
    if i >= v.len() {
        return Err(format!("{name} needs a value"));
    }
    Ok(Some(v.remove(i)))
}

pub(crate) fn flag(v: &mut Vec<String>, name: &str) -> bool {
    v.iter()
        .position(|x| x == name)
        .map(|i| v.remove(i))
        .is_some()
}

pub(crate) fn num<T: std::str::FromStr>(
    v: &mut Vec<String>,
    name: &str,
    dflt: T,
) -> Result<T, String> {
    match take(v, name)? {
        None => Ok(dflt),
        Some(s) => s.parse().map_err(|_| format!("bad {name} '{s}'")),
    }
}

/// Upper bound of every `--qd`-like knob: slot vectors are `qd + c` sized and a huge value wraps in release builds.
pub(crate) const MAX_QD: u64 = 65_536;
/// Upper bound of every `--clients`-like knob: each client is an OS thread.
pub(crate) const MAX_CLIENTS: u64 = 1024;

/// `--name N` like `num`, but N must be <= `max` (a usage error otherwise, never a panic or a wrapped size later).
pub(crate) fn num_max<T: TryFrom<u64>>(
    v: &mut Vec<String>,
    name: &str,
    max: u64,
    dflt: T,
) -> Result<T, String> {
    match take(v, name)? {
        None => Ok(dflt),
        Some(s) => match s.parse::<u64>() {
            Ok(n) if n <= max => T::try_from(n).map_err(|_| format!("bad {name} '{s}'")),
            Ok(_) => Err(format!("{name} {s} exceeds the maximum {max}")),
            Err(_) => Err(format!("bad {name} '{s}'")),
        },
    }
}

/// `--name SECONDS` as a `Duration`; non-finite or negative values are usage errors (`Duration::from_secs_f64`
/// panics on them, in the CLI or later inside a worker thread).
pub(crate) fn secs(
    v: &mut Vec<String>,
    name: &str,
    dflt: f64,
) -> Result<std::time::Duration, String> {
    let value = num(v, name, dflt)?;
    std::time::Duration::try_from_secs_f64(value)
        .map_err(|_| format!("bad {name} '{value}' (finite, non-negative seconds)"))
}

/// Entry point of `oprobe omapbench ...` (`a` = remaining args, `pool` = the global -p).
pub fn cli(mut a: Vec<String>, o: Opts, pool: Option<String>) -> Result<ExitCode, String> {
    let scale: f64 = num(&mut a, "--scale", 1.0)?;
    let sc = |n: u64| ((n as f64 * scale).round() as u64).max(1);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mix = match take(&mut a, "--mix")? {
        Some(s) => parse_mix(&s)?,
        None => [25, 10, 10, 25, 15, 15],
    };
    let c = Cfg {
        pool: pool.ok_or("omapbench: -p POOL required")?,
        prefix: take(&mut a, "--prefix")?.unwrap_or_else(|| format!("omapbench-{now:x}")),
        n_a: sc(num(&mut a, "--n-a", 2_000_000u64)?),
        n_b: sc(num(&mut a, "--n-b", 20_000u64)?),
        b_objs: num(&mut a, "--b-objs", 100usize)?.max(1),
        clients: num_max(&mut a, "--clients", MAX_CLIENTS, 8usize)?.max(1),
        qd: num_max(&mut a, "--qd", MAX_QD, 64usize)?.max(1),
        pop_clients: num_max(&mut a, "--pop-clients", MAX_CLIENTS, 16usize)?.max(1),
        pop_qd: num_max(&mut a, "--pop-qd", MAX_QD, 4usize)?.max(1),
        batch: num(&mut a, "--batch", 1024usize)?.max(1),
        mix,
        read_keys: num(&mut a, "--read-keys", 8usize)?.max(1),
        list_small: num(&mut a, "--list-small", 128u64)?,
        list_big: num(&mut a, "--list-big", 16384u64)?,
        val_len: 256,
        t_base: num(&mut a, "--t-base", 120.0)?,
        t_ab: num(&mut a, "--t-ab", 360.0)?,
        t_rec: num(&mut a, "--t-rec", 120.0)?,
        op_timeout: num(&mut a, "--op-timeout", 60.0)?,
        del_timeout: num(&mut a, "--del-timeout", 900.0)?,
        stall: num(&mut a, "--stall", 90.0)?,
        seed: num(&mut a, "--seed", 1u64)?,
        verify: !flag(&mut a, "--no-verify"),
        keep: flag(&mut a, "--keep"),
        small_objects: num(&mut a, "--small-objects", 0u64)?,
        pop_only: flag(&mut a, "--pop-only"),
        pop_warm: match take(&mut a, "--pop-warm")?.as_deref() {
            None | Some("none") => Warm::None,
            Some("session") => Warm::Session,
            Some("object") => Warm::Object,
            Some(x) => {
                return Err(format!(
                    "omapbench: --pop-warm none|session|object, not '{x}'"
                ));
            }
        },
        out: PathBuf::from(take(&mut a, "--outdir")?.unwrap_or_else(|| "omapbench-out".into())),
    };
    if let Some(x) = a.first() {
        return Err(format!("omapbench: unknown argument '{x}'\n{HELP}"));
    }
    run(&o, c)
}

fn run(o: &Opts, c: Cfg) -> Result<ExitCode, String> {
    let c = Arc::new(c);
    std::fs::create_dir_all(&c.out).map_err(|e| format!("{}: {e}", c.out.display()))?;
    let groups = make_groups(&c);
    let t0 = Instant::now();
    let (tx, rx) = channel::<Msg>();
    let mut ctl = Ctl {
        agg: Agg {
            open: BTreeMap::new(),
            rows: Vec::new(),
            phases: vec![("populate".into(), 0, t0)],
            ph: BTreeMap::new(),
            kinds: BTreeMap::new(),
            misses: 0,
            bad: 0,
            done: 0,
            fatal: Vec::new(),
            del: None,
            last_ok_b: Instant::now(),
            t0_epoch: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        },
        rx,
        t0,
        stall: Duration::from_secs_f64(c.stall),
        last_print: Instant::now(),
    };
    eprintln!(
        "omapbench: pool {} prefix {} N_A {} N_B {} x {} objs, {} clients/group x QD {}, mix {:?}",
        c.pool, c.prefix, c.n_a, c.n_b, c.b_objs, c.clients, c.qd, c.mix
    );

    // ---- populate
    let mut tasks: Vec<(usize, usize, u64)> = Vec::new();
    for g in &groups {
        for (oi, ob) in g.objs.iter().enumerate() {
            for b in 0..ob.n.div_ceil(c.batch as u64) {
                tasks.push((g.id, oi, b));
            }
        }
    }
    for i in 0..c.small_objects as usize {
        tasks.push((2, i, 0));
    }
    let mut rng = Rng::new(c.seed);
    for i in (1..tasks.len()).rev() {
        tasks.swap(i, rng.below(i as u64 + 1) as usize);
    }
    let tasks = Arc::new(tasks);
    let next = Arc::new(AtomicU64::new(0));
    let gs = Arc::new(groups.clone());
    let mut handles = Vec::new();
    for i in 0..c.pop_clients as u64 {
        let (o, c, gs, tasks, next, tx) = (
            o.clone(),
            c.clone(),
            gs.clone(),
            tasks.clone(),
            next.clone(),
            tx.clone(),
        );
        handles.push(std::thread::spawn(move || {
            pop_worker(o, c, gs, tasks, next, t0, i, tx)
        }));
    }
    let pop_expect = c.pop_clients * 3;
    let r = ctl.pump(Duration::from_secs(3600), false, |a| a.done >= pop_expect);
    let pop_secs = t0.elapsed().as_secs_f64();
    let mut abort: Option<String> = match r {
        Pump::Ok => None,
        Pump::Fatal => Some(format!("fatal: {}", ctl.agg.fatal.join("; "))),
        _ => {
            eprintln!(
                "WARNING TIMEOUT omapbench populate exceeded 3600s (done {})",
                ctl.agg.done
            );
            Some("populate timeout".into())
        }
    };
    let pop_keys = c.n_a + c.n_b * groups[1].objs.len() as u64 + c.small_objects;
    eprintln!("[{pop_secs:5.0}s] populate done: {pop_keys} keys in {pop_secs:.1} s");

    let stop_a = Arc::new(AtomicBool::new(false));
    let stop_b = Arc::new(AtomicBool::new(false));
    let mut expect = pop_expect;
    let mut del_secs: Option<f64> = None;
    let mut del_res: Result<(), String> = Ok(());
    let dur = |s: f64| Duration::from_secs_f64(s.max(0.0));
    let phase_run = |ctl: &mut Ctl, abort: &mut Option<String>, name: &str, secs: f64| {
        ctl.mark(name);
        match ctl.pump(dur(secs), true, |_| false) {
            Pump::Timeout => {}
            Pump::Stall => {
                *abort = Some(format!(
                    "STALL in phase {name}: group B completed nothing for {} s",
                    c.stall
                ))
            }
            Pump::Fatal => *abort = Some(format!("fatal: {}", ctl.agg.fatal.join("; "))),
            Pump::Ok => {}
        }
    };

    if abort.is_none() && !c.pop_only {
        ctl.agg.last_ok_b = Instant::now();
        handles.extend(spawn_mix(o, &c, &groups[1], t0, &stop_b, &tx));
        expect += c.clients;
        phase_run(&mut ctl, &mut abort, "base", c.t_base);
    }
    if abort.is_none() && !c.pop_only {
        handles.extend(spawn_mix(o, &c, &groups[0], t0, &stop_a, &tx));
        expect += c.clients;
        phase_run(&mut ctl, &mut abort, "ab", c.t_ab);
    }
    if abort.is_none() && !c.pop_only {
        ctl.mark("drain");
        stop_a.store(true, Relaxed);
        let want = expect;
        let r = ctl.pump(dur(c.op_timeout + 60.0), false, |a| {
            a.done >= want - c.clients
        });
        // A done = all but the B workers
        if !matches!(r, Pump::Ok) {
            eprintln!(
                "WARNING TIMEOUT omapbench drain exceeded {}s (group A did not finish)",
                c.op_timeout + 60.0
            );
            abort = Some("drain: group A did not finish".into());
        }
    }
    if abort.is_none() && !c.pop_only {
        ctl.mark("delete");
        let (o2, c2, tx2, name) = (
            o.clone(),
            c.clone(),
            tx.clone(),
            groups[0].objs[0].name.clone(),
        );
        handles.push(std::thread::spawn(move || delete_worker(o2, c2, name, tx2)));
        let r = ctl.pump(dur(c.del_timeout + 60.0), true, |a| a.del.is_some());
        match (&r, ctl.agg.del.take()) {
            (_, Some((s, res))) => {
                del_secs = Some(s);
                del_res = res;
            }
            (Pump::Stall, _) => abort = Some("STALL during delete of object A".into()),
            _ => {
                eprintln!(
                    "WARNING TIMEOUT omapbench delete exceeded {}s (object A)",
                    c.del_timeout + 60.0
                );
                abort = Some("delete did not finish".into())
            }
        }
        eprintln!("delete of A: {:?} s, {:?}", del_secs, del_res);
    }
    if abort.is_none() && !c.pop_only {
        phase_run(&mut ctl, &mut abort, "recover", c.t_rec);
    }
    // ---- stop everything, collect
    stop_a.store(true, Relaxed);
    stop_b.store(true, Relaxed);
    let want = expect;
    let r = ctl.pump(dur(c.op_timeout + 60.0), false, |a| a.done >= want);
    let t_end = Instant::now();
    if !matches!(r, Pump::Ok) {
        eprintln!(
            "WARNING TIMEOUT omapbench worker finish exceeded {}s (expected {want})",
            c.op_timeout + 60.0
        );
    }
    if abort.is_none() && !matches!(r, Pump::Ok) {
        abort = Some("workers did not finish in time".into());
    }
    ctl.agg.close_upto(u32::MAX);
    if matches!(r, Pump::Ok) {
        for h in handles.drain(..) {
            let _ = h.join();
        }
    } else {
        eprintln!("omapbench: workers still running, leaving them behind");
    }

    // ---- cleanup
    let mut cleanup = String::from("skipped (--keep)");
    if !c.keep && abort.is_none() {
        cleanup = cleanup_objects(o, &c, &groups);
    }

    let (text, tsv) = summarize(
        &ctl.agg, &c, pop_secs, pop_keys, del_secs, &del_res, &abort, t_end, &cleanup,
    );
    std::fs::write(c.out.join("summary.txt"), &text).map_err(|e| e.to_string())?;
    std::fs::write(c.out.join("series.tsv"), tsv.0).map_err(|e| e.to_string())?;
    std::fs::write(c.out.join("phases.tsv"), tsv.1).map_err(|e| e.to_string())?;
    print!("{text}");
    let bad = ctl.agg.bad
        + ctl.agg.misses
        + ctl.agg.kinds.values().sum::<u64>()
        + u64::from(del_res.is_err());
    Ok(if abort.is_some() {
        ExitCode::from(3)
    } else if bad > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn cleanup_objects(o: &Opts, c: &Arc<Cfg>, groups: &[Arc<Group>; 2]) -> String {
    let (mut p, pool) = match connect(o, c, 120.0) {
        Ok(x) => x,
        Err(e) => return format!("connect failed: {e}"),
    };
    let mut names: Vec<String> = groups
        .iter()
        .flat_map(|g| g.objs.iter().map(|x| x.name.clone()))
        .collect();
    names.extend((0..c.small_objects).map(|i| format!("{}-S-{i}", c.prefix)));
    let (mut sent, mut fin, mut errs) = (0usize, 0usize, 0usize);
    let end = Instant::now() + Duration::from_secs(600);
    while fin < names.len() && Instant::now() < end {
        while sent < names.len() && p.in_flight() < 16 {
            if p.submit(
                target(pool, &names[sent]),
                msg(OsdOp::delete()),
                sent as u64,
            )
            .is_err()
            {
                errs += 1;
                fin += 1;
            }
            sent += 1;
        }
        for d in p.poll() {
            fin += 1;
            match d.reply {
                Some(r) if r.result >= 0 || r.result == -opwire::errno::ENOENT => {}
                _ => errs += 1,
            }
        }
    }
    format!("{} objects removed, {errs} errors", names.len())
}

fn us(v: u64) -> String {
    if v >= 10_000_000 {
        format!("{:.1}s", v as f64 / 1e6)
    } else if v >= 10_000 {
        format!("{:.1}ms", v as f64 / 1e3)
    } else {
        format!("{v}us")
    }
}

/// Returns (summary text, (series.tsv, phases.tsv)).
#[expect(clippy::too_many_arguments)]
fn summarize(
    a: &Agg,
    c: &Cfg,
    pop_secs: f64,
    pop_keys: u64,
    del_secs: Option<f64>,
    del_res: &Result<(), String>,
    abort: &Option<String>,
    t_end: Instant,
    cleanup: &str,
) -> (String, (String, String)) {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "omapbench summary (pool {}, prefix {})",
        c.pool, c.prefix
    );
    let _ = writeln!(
        s,
        "config: N_A {} N_B {} x {} objs, {} clients/group x QD {}, mix R/L128/L16k/U/I/D {:?}, read-keys {}, key {} B, value {} B, verify {}",
        c.n_a, c.n_b, c.b_objs, c.clients, c.qd, c.mix, c.read_keys, KEY_LEN, c.val_len, c.verify
    );
    if let Some(x) = abort {
        let _ = writeln!(s, "ABORTED: {x}");
    }
    let _ = writeln!(
        s,
        "populate: {pop_keys} keys in {pop_secs:.1} s = {:.0} keys/s ({} clients x QD {}, batch {})",
        pop_keys as f64 / pop_secs.max(0.001),
        c.pop_clients,
        c.pop_qd,
        c.batch
    );
    // phase table
    let np = a.phases.len();
    let pdur = |i: usize| -> f64 {
        let end = a.phases.get(i + 1).map_or(t_end, |p| p.2);
        end.duration_since(a.phases[i].2).as_secs_f64().max(0.001)
    };
    let _ = writeln!(
        s,
        "\nphase    dur_s grp op        ops/s        n   err      p50      p99      max"
    );
    let mut tsv = String::from("sec\tphase\tgroup\top\tops\terr\tp50_us\tp99_us\tmax_us\n");
    #[expect(clippy::needless_range_loop)]
    for pi in 0..np {
        for g in 0..3 {
            for op in 0..=POINT {
                let Some(e) = a.ph.get(&(pi, g, op)) else {
                    continue;
                };
                if e.h.n == 0 && e.errs == 0 {
                    continue;
                }
                let _ = writeln!(
                    s,
                    "{:<8} {:5.0} {:<3} {:<9} {:8.1} {:8} {:5} {:>8} {:>8} {:>8}",
                    a.phases[pi].0,
                    pdur(pi),
                    GN[g],
                    OPN[op],
                    e.h.n as f64 / pdur(pi),
                    e.h.n,
                    e.errs,
                    us(e.h.pct(0.5)),
                    us(e.h.pct(0.99)),
                    us(e.h.max)
                );
            }
        }
    }
    let mut rows = a.rows.clone();
    rows.sort_by_key(|r| (r.sec, r.group, r.op));
    for r in &rows {
        let ph = &a.phases[a.phase_idx(r.sec)].0;
        let _ = writeln!(
            tsv,
            "{}\t{ph}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            r.sec, GN[r.group], OPN[r.op], r.n, r.errs, r.p50, r.p99, r.max
        );
    }
    let mut ptsv = String::from("phase\tstart_sec\tdur_s\tstart_epoch\n");
    for pi in 0..np {
        let _ = writeln!(
            ptsv,
            "{}\t{}\t{:.1}\t{}",
            a.phases[pi].0,
            a.phases[pi].1,
            pdur(pi),
            a.t0_epoch + u64::from(a.phases[pi].1)
        );
    }

    // B point stats per phase
    let pidx = |name: &str| a.phases.iter().position(|p| p.0 == name);
    let bpoint =
        |name: &str| pidx(name).and_then(|i| a.ph.get(&(i, 1, POINT)).map(|e| (e, pdur(i))));
    let _ = writeln!(
        s,
        "\nA -> B impact (B point ops = read+update+insert+delete):"
    );
    if let (Some((b0, d0)), Some((b1, d1))) = (bpoint("base"), bpoint("ab")) {
        let (r0, r1) = (b0.h.n as f64 / d0, b1.h.n as f64 / d1);
        let (p0, p1) = (b0.h.pct(0.99), b1.h.pct(0.99));
        let _ = writeln!(
            s,
            "  B alone: {r0:.1} ops/s p50 {} p99 {} | A+B: {r1:.1} ops/s ({:+.1} %) p50 {} p99 {} (x{:.2})",
            us(b0.h.pct(0.5)),
            us(p0),
            (r1 / r0 - 1.0) * 100.0,
            us(b1.h.pct(0.5)),
            us(p1),
            p1 as f64 / p0.max(1) as f64
        );
    } else {
        let _ = writeln!(s, "  n/a");
    }
    // delete
    let _ = writeln!(s, "\ndelete of object A ({} keys):", c.n_a);
    match del_secs {
        Some(d) => {
            let _ = writeln!(
                s,
                "  duration {d:.2} s, result {}",
                match del_res {
                    Ok(()) => "ok".to_string(),
                    Err(e) => format!("ERROR {e}"),
                }
            );
        }
        None => {
            let _ = writeln!(s, "  not completed");
        }
    }
    let base_p99 = bpoint("base").map_or(0, |(e, _)| e.h.pct(0.99));
    let series: BTreeMap<u32, u64> = rows
        .iter()
        .filter(|r| r.group == 1 && r.op == POINT)
        .map(|r| (r.sec, r.p99))
        .collect();
    if let (Some(di), Some(ri)) = (pidx("delete"), pidx("recover")) {
        let (ds, es) = (a.phases[di].1, a.phases[ri].1);
        let win: Vec<&Row> = rows
            .iter()
            .filter(|r| r.group == 1 && r.op == POINT && r.sec >= ds && r.sec <= es)
            .collect();
        let maxp99 = win.iter().map(|r| r.p99).max().unwrap_or(0);
        let maxlat = win.iter().map(|r| r.max).max().unwrap_or(0);
        let minops = win.iter().map(|r| r.n).min().unwrap_or(0);
        let spikes = win.iter().filter(|r| r.p99 > 2 * base_p99.max(1)).count();
        let _ = writeln!(
            s,
            "  B during delete (secs {ds}..={es}): max p99/s {} (x{:.1} of baseline p99 {}), max latency {}, min ops/s {minops}, seconds with p99 > 2x baseline: {spikes}/{}",
            us(maxp99),
            maxp99 as f64 / base_p99.max(1) as f64,
            us(base_p99),
            us(maxlat),
            win.len()
        );
        let limit = base_p99 * 12 / 10;
        match recovery_secs(&series, es, limit, 5) {
            Some(r) => {
                let _ = writeln!(
                    s,
                    "  B recovery (p99/s <= 1.2 x baseline = {} for 5 s in a row): {r} s after delete end",
                    us(limit)
                );
            }
            None => {
                let _ = writeln!(
                    s,
                    "  B recovery: NOT reached within the recover phase (limit {})",
                    us(limit)
                );
            }
        }
    }
    // errors
    let errs: u64 = a.kinds.values().sum();
    let _ = writeln!(
        s,
        "\nerrors: {errs} (by kind: {:?}); reads with missing keys: {}; bad values: {}",
        a.kinds, a.misses, a.bad
    );
    let _ = writeln!(s, "cleanup: {cleanup}");
    (s, (tsv, ptsv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_options_reject_non_finite_and_negative_values() {
        for v in ["-1", "-0.5", "nan", "inf", "-inf"] {
            let mut a = vec!["--warm".to_string(), v.to_string()];
            assert!(secs(&mut a, "--warm", 3.0).is_err(), "{v}");
        }
        let mut a = vec!["--warm".to_string(), "0.5".to_string()];
        assert_eq!(
            secs(&mut a, "--warm", 3.0).unwrap(),
            Duration::from_millis(500)
        );
        let mut a: Vec<String> = Vec::new();
        assert_eq!(secs(&mut a, "--warm", 3.0).unwrap(), Duration::from_secs(3));
    }

    #[test]
    fn a_trailing_option_is_a_usage_error_not_a_missing_option() {
        let mut v: Vec<String> = ["--mon".to_string()].to_vec();
        assert_eq!(take(&mut v, "--mon").unwrap_err(), "--mon needs a value");
        let mut v: Vec<String> = ["--mon".to_string(), "v2:1.2.3.4:3300".to_string()].to_vec();
        assert_eq!(
            take(&mut v, "--mon").unwrap().as_deref(),
            Some("v2:1.2.3.4:3300")
        );
        assert!(take(&mut v, "--mon").unwrap().is_none());
        let mut v: Vec<String> = ["--clients".to_string()].to_vec();
        assert!(num(&mut v, "--clients", 4usize).is_err());
        assert_eq!(num(&mut v, "--clients", 4usize).unwrap(), 4);
    }

    #[test]
    fn num_max_rejects_values_above_the_bound() {
        let mut v = vec!["--qd".to_string(), "65536".to_string()];
        assert_eq!(num_max(&mut v, "--qd", MAX_QD, 1usize).unwrap(), 65_536);
        let mut v = vec!["--qd".to_string(), "65537".to_string()];
        assert!(
            num_max(&mut v, "--qd", MAX_QD, 1usize)
                .unwrap_err()
                .contains("exceeds")
        );
        let mut v = vec!["--qd".to_string(), "x".to_string()];
        assert!(
            num_max(&mut v, "--qd", MAX_QD, 1usize)
                .unwrap_err()
                .contains("bad")
        );
        assert_eq!(num_max(&mut Vec::new(), "--qd", MAX_QD, 7u64).unwrap(), 7);
    }

    fn cfg() -> Cfg {
        Cfg {
            pool: "p".into(),
            prefix: "t".into(),
            n_a: 1000,
            n_b: 500,
            b_objs: 4,
            clients: 1,
            qd: 1,
            pop_clients: 1,
            pop_qd: 1,
            batch: 100,
            mix: [25, 10, 10, 25, 15, 15],
            read_keys: 4,
            list_small: 128,
            list_big: 16384,
            val_len: 256,
            t_base: 1.0,
            t_ab: 1.0,
            t_rec: 1.0,
            op_timeout: 5.0,
            del_timeout: 5.0,
            stall: 5.0,
            seed: 1,
            verify: true,
            keep: false,
            small_objects: 0,
            pop_only: false,
            pop_warm: Warm::None,
            out: PathBuf::from("x"),
        }
    }

    #[test]
    fn pop_only_has_no_b_objects() {
        let mut c = cfg();
        assert_eq!(make_groups(&c)[1].objs.len(), c.b_objs);
        c.pop_only = true;
        assert!(make_groups(&c)[1].objs.is_empty());
        assert_eq!(make_groups(&c)[0].objs.len(), 1);
    }

    #[test]
    fn keys_are_64b_unique_and_deterministic() {
        let mut seen = BTreeSet::new();
        for i in 0..20_000 {
            let k = key(i);
            assert_eq!(k.len(), 64);
            assert_eq!(k, key(i));
            assert!(k.iter().all(|c| c.is_ascii_hexdigit()));
            assert!(seen.insert(k));
        }
        // sort order is not index order
        let sorted = (0..200u64).is_sorted_by_key(key);
        assert!(!sorted);
    }

    #[test]
    fn values_roundtrip_and_detect_corruption() {
        let k = key(7);
        let v = value(&k, 99, 256);
        assert_eq!(v.len(), 256);
        assert!(value_ok(&k, &v, 256));
        assert_ne!(value(&k, 100, 256), v);
        let mut bad = v.clone();
        bad[200] ^= 1;
        assert!(!value_ok(&k, &bad, 256));
        assert!(!value_ok(&key(8), &v, 256));
        assert!(!value_ok(&k, &v[..255], 256));
    }

    #[test]
    fn mix_follows_weights() {
        let mix = [25, 10, 10, 25, 15, 15];
        let mut r = Rng::new(5);
        let mut n = [0u64; NOPS];
        let total = 200_000u64;
        for _ in 0..total {
            n[pick(&mix, r.next_u64()) as usize] += 1;
        }
        for (i, w) in mix.iter().enumerate() {
            let got = n[i] as f64 / total as f64 * 100.0;
            assert!((got - f64::from(*w)).abs() < 0.6, "op {i}: {got} vs {w}");
        }
        assert_eq!(n[Op::Populate as usize], 0);
        assert_eq!(parse_mix("1,2,3,4,5,5").unwrap(), [1, 2, 3, 4, 5, 5]);
        assert!(parse_mix("1,2,3").is_err());
        assert!(parse_mix("0,0,0,0,0,0").is_err());
    }

    #[test]
    fn hist_percentiles_within_error() {
        let mut h = Hist::new();
        let mut v: Vec<u64> = Vec::new();
        let mut r = Rng::new(3);
        for _ in 0..100_000 {
            let x = 50 + r.below(5_000_000);
            v.push(x);
            h.rec(x);
        }
        v.sort_unstable();
        for q in [0.5, 0.9, 0.99, 0.999] {
            let exact = v[((q * v.len() as f64).ceil() as usize - 1).min(v.len() - 1)] as f64;
            let got = h.pct(q) as f64;
            assert!(
                (got - exact).abs() / exact < 0.02,
                "q {q}: {got} vs {exact}"
            );
        }
        assert_eq!(h.max, *v.last().unwrap());
        assert_eq!(h.pct(1.0), h.max);
        assert_eq!(Hist::new().pct(0.99), 0);
        let mut a = Hist::new();
        a.rec(10);
        let mut b = Hist::new();
        b.rec(1_000_000);
        a.merge(&b);
        assert_eq!(a.n, 2);
        assert_eq!(a.max, 1_000_000);
        assert!(a.pct(0.5) <= 10);
        // bucket edges: monotone, small values exact
        for i in 0..64u64 {
            assert_eq!(hhigh(hidx(i)), i);
        }
        for e in [64u64, 127, 128, 1000, 123_456, 1 << 30] {
            assert!(hhigh(hidx(e)) >= e);
        }
    }

    #[test]
    fn window_keeps_count_constant_and_inside_live_range() {
        let c = cfg();
        let g = make_groups(&c);
        let b = &g[1];
        let mut rng = Rng::new(9);
        let o = &b.objs[0];
        let mut live: BTreeSet<Vec<u8>> = (0..o.n).map(key).collect();
        for step in 0..5000u32 {
            let ins = rng.below(2) == 0;
            if ins {
                live.insert(key(o.next_insert()));
            } else {
                assert!(
                    live.remove(&key(o.next_delete())),
                    "delete of a non-live key"
                );
            }
            // keep balanced like the real mix (insert == delete): pair them
            if step % 2 == 0 {
                if ins {
                    assert!(live.remove(&key(o.next_delete())));
                } else {
                    live.insert(key(o.next_insert()));
                }
            }
            let (lo, hi) = o.window();
            assert!(lo < hi);
            assert!(
                live.contains(&key(lo)) && live.contains(&key(hi - 1)),
                "window edge not live"
            );
        }
        assert_eq!(live.len() as u64, o.live());
        assert!(o.live().abs_diff(o.n) < 64);
    }

    #[test]
    fn build_op_shapes() {
        let c = cfg();
        let g = make_groups(&c);
        let mut r = Rng::new(1);
        for op in MIX_OPS {
            for _ in 0..50 {
                let (oi, m, want) = build_op(op, &g[1], &mut r, &c);
                assert!(oi < c.b_objs);
                assert_eq!(m.ops.len(), 1);
                if op == Op::Read {
                    assert!(want >= 1 && want <= c.read_keys);
                }
            }
        }
        let (oi, m, _) = build_op(Op::Read, &g[0], &mut r, &c);
        assert_eq!(oi, 0);
        assert_eq!(m.ops[0].op, code::OMAP_GET_VALS_BY_KEYS);
        // object names
        assert_eq!(g[0].objs[0].name, "t-A");
        assert_eq!(g[1].objs[3].name, "t-B-003");
    }

    #[test]
    fn recovery_detection() {
        let mut s = BTreeMap::new();
        for sec in 0..30u32 {
            s.insert(sec, if (10..16).contains(&sec) { 5000 } else { 1000 });
        }
        assert_eq!(recovery_secs(&s, 10, 1200, 5), Some(6));
        assert_eq!(recovery_secs(&s, 20, 1200, 5), Some(0));
        assert_eq!(recovery_secs(&s, 10, 500, 5), None);
        s.remove(&22);
        assert_eq!(recovery_secs(&s, 20, 1200, 5), Some(3));
        assert_eq!(recovery_secs(&BTreeMap::new(), 0, 1, 5), None);
    }
}
