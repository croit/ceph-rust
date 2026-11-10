// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Process memory (RSS) against the live heap under the omap FIFO churn of the lab cell
//! `oprobe omap-workload --objects 1 --prefill 250000 --batch 256 --clients 64 --qd 1 --operations insert,delete`
//! (doc/perf/osd-rss-growth-20261029.md). The daemon's allocator (mimalloc) by default, the system allocator with
//! `CHURN_ALLOC=system`. RSS minus the live heap is memory the allocator holds for nothing (the simulated device's
//! media is heap, so it is in both).
//!
//! Wire mode (`CHURN_WIRE=1`, tests `wire_buffers_end_with_*`): every op's bytes live in one 128 KiB wire buffer
//! (the pooled msgr2 receive segment of a ~89 KB insert) and the op is queued with an adapter builder, as the daemon
//! queues `ApplyTxn` input: a parked op is rebuilt from the buffer and staged from views of it
//! (`OTxn::shared(owners)`). A view the store keeps past the op pins the whole buffer; `wire_live` counts the buffers.
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{HashMap, VecDeque};
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{KvRunData, OTxn, ObjError, Store, StoreCfg, TOp};

/// Live heap bytes, and the inner allocator chosen at the first allocation (1 = mimalloc, 2 = system).
static LIVE: AtomicUsize = AtomicUsize::new(0);
static INNER: AtomicU8 = AtomicU8::new(0);

unsafe extern "C" {
    fn getenv(name: *const std::ffi::c_char) -> *const std::ffi::c_char;
}

fn inner() -> u8 {
    match INNER.load(Ordering::Relaxed) {
        0 => {
            // SAFETY: NUL-terminated name; getenv does not allocate (no re-entry into this allocator).
            let v = unsafe { getenv(c"CHURN_ALLOC".as_ptr()) };
            // SAFETY: getenv returns NULL or a NUL-terminated string.
            let system = !v.is_null() && unsafe { std::ffi::CStr::from_ptr(v) } == c"system";
            let pick = if system { 2 } else { 1 };
            match INNER.compare_exchange(0, pick, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => pick,
                Err(won) => won,
            }
        }
        x => x,
    }
}

struct Counted;
unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: forwarded contract.
        let p = unsafe {
            match inner() {
                1 => mimalloc::MiMalloc.alloc(l),
                _ => System.alloc(l),
            }
        };
        if !p.is_null() {
            LIVE.fetch_add(l.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        // SAFETY: forwarded contract.
        let p = unsafe {
            match inner() {
                1 => mimalloc::MiMalloc.alloc_zeroed(l),
                _ => System.alloc_zeroed(l),
            }
        };
        if !p.is_null() {
            LIVE.fetch_add(l.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        // SAFETY: forwarded contract (same inner allocator as the allocation: fixed at the first call).
        unsafe {
            match inner() {
                1 => mimalloc::MiMalloc.dealloc(p, l),
                _ => System.dealloc(p, l),
            }
        }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        // SAFETY: forwarded contract.
        let q = unsafe {
            match inner() {
                1 => mimalloc::MiMalloc.realloc(p, l, n),
                _ => System.realloc(p, l, n),
            }
        };
        if !q.is_null() {
            LIVE.fetch_add(n, Ordering::Relaxed);
            LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        }
        q
    }
}
#[global_allocator]
static ALLOC: Counted = Counted;

type St = Store<SimDev, SimClock>;

const KEY: usize = 48;
const VAL: usize = 300;
const BATCH: u64 = 256;
const CLIENTS: u64 = 64;

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Resident set of this process (Linux; 0 elsewhere).
fn rss() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("VmRSS:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<usize>().ok())
        })
        .map_or(0, |kb| kb << 10)
}

fn coll() -> CollT {
    CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    })
}

fn pgmeta() -> Ghobject {
    Ghobject::pgmeta(1, 0, ShardId::NO_SHARD)
}

fn hot() -> Ghobject {
    Ghobject::new(
        Hobject::new(b"ow-insdel", SnapId::NOSNAP, 0x5eed, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

/// oprobe's key shape: padding, the id big-endian at the end (ids ascend in insert order).
fn key(id: u64) -> Vec<u8> {
    let mut k = vec![b'k'; KEY];
    k[KEY - 8..].copy_from_slice(&id.to_be_bytes());
    k
}

fn run_of(ids: impl Iterator<Item = u64>) -> KvRunData<'static> {
    let mut kv: Vec<(Vec<u8>, Vec<u8>)> =
        ids.map(|i| (key(i), vec![(i % 251) as u8; VAL])).collect();
    kv.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut enc = Vec::new();
    denc::SortedKv::encode_into(
        &mut enc,
        kv.len(),
        kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
    );
    KvRunData::from_encoding(enc.into()).expect("sorted batch")
}

/// Capacity of a wire buffer: the msgr2 receive pool class of a ~89 KB insert (power-of-two classes from 64 KiB).
const WIRE_CAP: usize = 128 << 10;

/// Owner of one wire buffer and the count of live ones it belongs to: live until the last view of it is dropped.
struct Wire(Vec<u8>, Arc<AtomicUsize>);
impl AsRef<[u8]> for Wire {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.1.fetch_sub(1, Ordering::Relaxed);
    }
}

/// One op of a [`WireTxn`]: collection, object and the payload ranges in the wire buffer.
#[derive(Clone)]
enum WOp {
    Run(CollT, Ghobject, usize, Range<usize>),
    RmKeys(CollT, Ghobject, Vec<Range<usize>>),
    Attrs(CollT, Ghobject, Vec<(Range<usize>, Range<usize>)>),
    SetKeys(CollT, Ghobject, Vec<(Range<usize>, Range<usize>)>),
}

/// A churn txn whose payload bytes live in one wire buffer.
#[derive(Clone)]
struct WireTxn {
    buf: bytes::Bytes,
    ops: Vec<WOp>,
}

impl WireTxn {
    /// The payload of the churn txn `t` (its op kinds only) copied into a new wire buffer counted in `live`.
    fn of(t: &OTxn<'_>, live: &Arc<AtomicUsize>) -> WireTxn {
        fn put(v: &mut Vec<u8>, b: &[u8]) -> Range<usize> {
            let s = v.len();
            v.extend_from_slice(b);
            s..v.len()
        }
        let mut v = Vec::with_capacity(WIRE_CAP);
        let mut ops = Vec::new();
        for op in &t.ops {
            ops.push(match op {
                TOp::OmapSetRun { cid, oid, run } => WOp::Run(
                    *cid,
                    oid.clone(),
                    run.len(),
                    put(&mut v, run.view().entries()),
                ),
                TOp::OmapRmKeys { cid, oid, keys } => WOp::RmKeys(
                    *cid,
                    oid.clone(),
                    keys.iter().map(|k| put(&mut v, k)).collect(),
                ),
                TOp::SetAttrs { cid, oid, attrs } => WOp::Attrs(
                    *cid,
                    oid.clone(),
                    attrs
                        .iter()
                        .map(|(k, x)| (put(&mut v, k), put(&mut v, x)))
                        .collect(),
                ),
                TOp::OmapSetKeys { cid, oid, pairs } => WOp::SetKeys(
                    *cid,
                    oid.clone(),
                    pairs
                        .iter()
                        .map(|(k, x)| (put(&mut v, k), put(&mut v, x)))
                        .collect(),
                ),
                _ => unreachable!("not a churn op"),
            });
        }
        assert!(v.len() <= WIRE_CAP, "churn txn larger than a wire buffer");
        live.fetch_add(1, Ordering::Relaxed);
        WireTxn {
            buf: bytes::Bytes::from_owner(Wire(v, live.clone())),
            ops,
        }
    }

    /// The txn as views of the wire buffer (what the adapter decodes from its message).
    fn view(&self) -> OTxn<'_> {
        let b = &self.buf[..];
        let s = |r: &Range<usize>| TxnBytes::Borrowed(&b[r.clone()]);
        let mut t = OTxn::new();
        for op in &self.ops {
            t.push(match op {
                WOp::Run(cid, oid, n, r) => TOp::OmapSetRun {
                    cid: *cid,
                    oid: oid.clone(),
                    run: KvRunData::new(denc::SortedKv::trusted(*n, &b[r.clone()])),
                },
                WOp::RmKeys(cid, oid, keys) => TOp::OmapRmKeys {
                    cid: *cid,
                    oid: oid.clone(),
                    keys: keys.iter().map(s).collect(),
                },
                WOp::Attrs(cid, oid, kv) => TOp::SetAttrs {
                    cid: *cid,
                    oid: oid.clone(),
                    attrs: kv.iter().map(|(k, x)| (s(k), s(x))).collect(),
                },
                WOp::SetKeys(cid, oid, kv) => TOp::OmapSetKeys {
                    cid: *cid,
                    oid: oid.clone(),
                    pairs: kv.iter().map(|(k, x)| (s(k), s(x))).collect(),
                },
            });
        }
        t
    }
}

/// Queued input of a wire op (the adapter's `ApplyTxn` builder): rebuilt from the buffer, which it names as owner.
struct WireInput(WireTxn);
impl store::obj::QueueBuilder<SimDev, SimClock> for WireInput {
    fn build(&mut self, _: &mut St) -> store::obj::Result<Option<OTxn<'_>>> {
        Ok(Some(self.0.view()))
    }
    fn retained_bytes(&self) -> usize {
        self.0.buf.len()
    }
    fn payload_owners(&self) -> Vec<bytes::Bytes> {
        vec![self.0.buf.clone()]
    }
}

struct Churn {
    st: St,
    disk: SimDisk,
    /// Per client: its live key ids, oldest first; the next id it inserts; whether its next op inserts.
    fifo: Vec<VecDeque<u64>>,
    next: Vec<u64>,
    insert: Vec<bool>,
    /// pg log entries written (the OSD logs every client write and trims behind).
    log: u64,
    tok: u64,
    inflight: HashMap<u64, usize>,
    ops: u64,
    /// Wire mode (module doc): the live wire buffers; the most live at once.
    wire: Option<Arc<AtomicUsize>>,
    wire_max: usize,
}

impl Churn {
    /// A store of `shards` shards with `budget` bytes of memory, omap engine LSM or tree (`lsm`), `prefill` keys.
    fn new(budget: u64, shards: u32, prefill: u64, lsm: bool) -> Churn {
        let disk = SimDisk::new(SimConfig::new(32 << 30));
        let mut dev = disk.queue();
        let mut p = MkfsParams::for_device(32 << 30, shards);
        p.omap_lsm = lsm;
        mkfs(&mut dev, &mut SimClock::default(), &p).unwrap();
        let mut cfg = StoreCfg::for_memory(budget, shards).unwrap();
        cfg.shard.run_pool = Some(Default::default());
        let d2 = disk.clone();
        let (mut st, _) = Store::mount(move || d2.queue(), SimClock::default(), cfg).unwrap();
        let mut t = OTxn::new();
        t.push(TOp::MkColl {
            cid: coll(),
            bits: 0,
            exist_ok: true,
        });
        t.touch(coll(), &hot());
        t.touch(coll(), &pgmeta());
        st.commit(&t).unwrap();
        let mut fifo = vec![VecDeque::new(); CLIENTS as usize];
        for first in (0..prefill).step_by(1024) {
            let mut t = OTxn::new();
            t.push(TOp::OmapSetRun {
                cid: coll(),
                oid: hot(),
                run: run_of(first..(first + 1024).min(prefill)),
            });
            st.commit(&t).unwrap();
            for i in first..(first + 1024).min(prefill) {
                fifo[(i % CLIENTS) as usize].push_back(i);
            }
        }
        st.sync().unwrap();
        Churn {
            st,
            disk,
            fifo,
            next: (0..CLIENTS).map(|c| prefill + c).collect(),
            insert: vec![true; CLIENTS as usize],
            log: 0,
            tok: 0,
            inflight: HashMap::new(),
            ops: 0,
            wire: None,
            wire_max: 0,
        }
    }

    fn txn(&mut self, c: usize) -> OTxn<'static> {
        let mut t = OTxn::new();
        if self.insert[c] {
            let first = self.next[c];
            t.push(TOp::OmapSetRun {
                cid: coll(),
                oid: hot(),
                run: run_of((0..BATCH).map(|j| first + j * CLIENTS)),
            });
        } else {
            let mut ks: Vec<Vec<u8>> = self.fifo[c]
                .iter()
                .take(BATCH as usize)
                .map(|&i| key(i))
                .collect();
            ks.sort_unstable();
            t.push(TOp::OmapRmKeys {
                cid: coll(),
                oid: hot(),
                keys: ks.into_iter().map(Into::into).collect(),
            });
        }
        self.log += 1;
        t.push(TOp::SetAttrs {
            cid: coll(),
            oid: hot(),
            attrs: vec![(b"_".to_vec().into(), vec![0x5a; 250].into())],
        });
        t.push(TOp::OmapSetKeys {
            cid: coll(),
            oid: pgmeta(),
            pairs: vec![(
                format!("pglog.0.{:016}", self.log).into_bytes().into(),
                vec![0xa5; 180].into(),
            )],
        });
        t.push(TOp::OmapRmKeys {
            cid: coll(),
            oid: pgmeta(),
            keys: vec![
                format!("pglog.0.{:016}", self.log.saturating_sub(3000))
                    .into_bytes()
                    .into(),
            ],
        });
        t
    }

    fn done(&mut self, c: usize) {
        if self.insert[c] {
            for j in 0..BATCH {
                self.fifo[c].push_back(self.next[c] + j * CLIENTS);
            }
            self.next[c] += BATCH * CLIENTS;
        } else {
            self.fifo[c].drain(..BATCH as usize);
        }
        self.insert[c] = !self.insert[c];
        self.ops += 1;
    }

    /// Run `ops` more client ops (64 in flight, QD1 per client); `each` after every poll.
    fn run(&mut self, ops: u64, mut each: impl FnMut(&mut Churn)) {
        let end = self.ops + ops;
        let mut acked = Vec::new();
        let mut idle: Vec<usize> = (0..CLIENTS as usize)
            .filter(|c| !self.inflight.values().any(|x| x == c))
            .collect();
        let mut stuck = 0u64;
        while self.ops < end {
            let before = idle.len();
            while let Some(&c) = idle.last() {
                let t = self.txn(c);
                self.tok += 1;
                let queued = if let Some(live) = &self.wire {
                    let w = WireTxn::of(&t, live);
                    let v = w.view();
                    self.st
                        .queue_with_builder(&v, self.tok, || Box::new(WireInput(w.clone())))
                } else {
                    self.st.queue(&t, self.tok)
                };
                match queued {
                    Ok(_) => {
                        self.inflight.insert(self.tok, c);
                        idle.pop();
                    }
                    Err(ObjError::WouldBlock) => {
                        self.tok -= 1;
                        self.log -= 1;
                        break;
                    }
                    Err(e) => panic!("queue: {e}"),
                }
            }
            acked.clear();
            self.st.poll(&mut acked).unwrap();
            if acked.is_empty() {
                stuck = if idle.len() == before && self.disk.inflight() == 0 {
                    stuck + 1
                } else {
                    0
                };
                assert!(
                    stuck <= 60_000_000,
                    "WARNING TIMEOUT churn op exceeded 60s (virtual; {} ops in flight, store idle)",
                    self.inflight.len()
                );
                self.st.idle();
            }
            for tok in acked.drain(..) {
                let c = self.inflight.remove(&tok).expect("own token");
                self.done(c);
                idle.push(c);
            }
            self.wire_max = self.wire_max.max(self.wire_live());
            each(self);
        }
    }

    fn counter(&self, name: &str) -> u64 {
        let pc = self.st.perf_counters();
        pc.iter().find(|x| x.0 == name).map_or(0, |x| x.2)
    }

    fn wire_live(&self) -> usize {
        self.wire.as_ref().map_or(0, |l| l.load(Ordering::Relaxed))
    }

    /// Complete every op in flight, then sync the store.
    fn drain(&mut self) {
        let mut acked = Vec::new();
        let mut stuck = 0u64;
        while !self.inflight.is_empty() {
            acked.clear();
            self.st.poll(&mut acked).unwrap();
            if acked.is_empty() {
                stuck = if self.disk.inflight() == 0 {
                    stuck + 1
                } else {
                    0
                };
                assert!(
                    stuck <= 60_000_000,
                    "WARNING TIMEOUT churn drain exceeded 60s (virtual; {} ops in flight, store idle)",
                    self.inflight.len()
                );
                self.st.idle();
            }
            for tok in acked.drain(..) {
                let c = self.inflight.remove(&tok).expect("own token");
                self.done(c);
            }
        }
        self.st.sync().unwrap();
    }

    fn line(&self) -> String {
        let pc = self.st.perf_counters();
        let c = |n: &str| pc.iter().find(|x| x.0 == n).map_or(0, |x| x.2);
        let (r, l) = (rss(), LIVE.load(Ordering::Relaxed));
        format!(
            "ops={} rss={}M live={}M rss-live={}M runs={}M run_compactions={} run_merge_waits={} parks={} dirty_pages={} wire_live={} wire_max={}",
            self.ops,
            r >> 20,
            l >> 20,
            (r.saturating_sub(l)) >> 20,
            self.st.mem().run_bytes >> 20,
            c("run_compactions"),
            c("run_merge_waits"),
            c("parks"),
            c("dirty_pages"),
            self.wire_live(),
            self.wire_max,
        )
    }
}

/// Measurement: RSS and live heap every `CHURN_EVERY` ops (`CHURN_OPS`, `CHURN_BUDGET_MIB`, `CHURN_SHARDS`, `CHURN_WIRE`, `CHURN_LSM`); stops
/// early once RSS exceeds the live heap by `CHURN_STOP_MIB` (the growth is shown, the test host's memory cap stays clear).
#[test]
#[ignore = "measurement: lab/rss-churn.sh"]
fn fifo_churn_rss_trace() {
    let mut ch = Churn::new(
        env("CHURN_BUDGET_MIB", 512) << 20,
        env("CHURN_SHARDS", 4) as u32,
        250_000,
        env("CHURN_LSM", 0) != 0,
    );
    if env("CHURN_WIRE", 0) != 0 {
        ch.wire = Some(Arc::default());
    }
    let alloc = if inner() == 1 { "mimalloc" } else { "system" };
    let t0 = std::time::Instant::now();
    eprintln!("alloc={alloc} prefilled: {}", ch.line());
    let (every, stop) = (env("CHURN_EVERY", 5_000), env("CHURN_STOP_MIB", 3072) << 20);
    let mut last = 0;
    let ops = env("CHURN_OPS", 60_000);
    let mut over = false;
    while ch.ops < ops && !over {
        ch.run(every.min(ops - ch.ops), |c| {
            if c.ops >= last + every {
                last = c.ops;
                eprintln!(
                    "alloc={alloc} t={:.1}s {}",
                    t0.elapsed().as_secs_f64(),
                    c.line()
                );
            }
        });
        over = rss().saturating_sub(LIVE.load(Ordering::Relaxed)) as u64 > stop;
    }
    if over {
        eprintln!(
            "alloc={alloc} stop: rss exceeds the live heap by more than {}M",
            stop >> 20
        );
    }
}

/// Wire churn under a small budget (the store's minimum for 2 shards): input the store parks is rebuilt from views of its
/// 128 KiB buffer (the builder path).
fn wire_churn(lsm: bool) -> Churn {
    let mut ch = Churn::new(96 << 20, 2, 20_000, lsm);
    ch.wire = Some(Arc::default());
    ch.run(env("CHURN_WIRE_OPS", 6_000), |_| {});
    eprintln!("wire churn (lsm={lsm}): {}", ch.line());
    assert!(
        ch.counter("parks") > 0,
        "no op parked (the builder path was not exercised): {}",
        ch.line()
    );
    ch
}

/// Omap tree (default format): the store keeps no view of a wire buffer past its op (a kept view pins the whole 128 KiB
/// buffer outside the budget): at most one buffer per op in flight, none once every op completed.
#[test]
fn wire_buffers_end_with_their_ops_tree() {
    let mut ch = wire_churn(false);
    assert!(
        ch.wire_max <= CLIENTS as usize,
        "wire buffers outlive their ops: {} live at once, {CLIENTS} ops in flight at most ({})",
        ch.wire_max,
        ch.line()
    );
    ch.drain();
    assert_eq!(
        ch.wire_live(),
        0,
        "wire buffers kept after every op completed: {}",
        ch.line()
    );
}

/// Omap LSM: the memtables hold run blobs as slices of the caller's buffers (no copy, adr 0610), so a buffer outlives its
/// op until the memtable holding it is flushed; after that none is left (owned ops drive two more flushes: the active and
/// the frozen memtable).
#[test]
fn wire_buffers_end_with_their_lsm_flush() {
    let mut ch = wire_churn(true);
    ch.drain();
    let live = ch.wire.take();
    let f0 = ch.counter("olsm_flushes");
    for _ in 0..1000 {
        if ch.counter("olsm_flushes") >= f0 + 2 {
            break;
        }
        ch.run(CLIENTS, |_| {});
    }
    ch.drain();
    ch.wire = live;
    assert!(
        ch.counter("olsm_flushes") >= f0 + 2,
        "the omap LSM memtables did not flush within {} owned ops: {}",
        1000 * CLIENTS,
        ch.line()
    );
    assert_eq!(
        ch.wire_live(),
        0,
        "wire buffers kept after their memtables flushed: {}",
        ch.line()
    );
}
