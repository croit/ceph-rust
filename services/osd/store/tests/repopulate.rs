// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Bulk omap populate into a store that already holds more omap than its caches: store-level repro of the lab cells
//! `or-r3-del-populate`, `or-r3-delr-populate`, `or-r5-stray-populate` (benchmark/omap-real: oprobe `rgwindex` / `dirfrag`
//! `--setup-only`, 16 clients x qd 2, `omap_set_vals` batches of 1000 random-order s3-like keys with 300 B values into NEW
//! objects, replicated size 1 so every txn also carries the object_info attr and the pg log keys of the PG).
//!
//! Phases run back to back on one store (virtual time: the simulated device is the only clock, so a phase's rate is what
//! the engine's device waits, parks and merge scheduling allow, not host CPU):
//!   a  many small objects (the first populate of a fresh store: every object fits the caches many times over)
//!   c  a few objects each larger than the shard's tree cache (the later populates)
//! Each phase prints keys per virtual second, op latency p50 / p99 / max, device read blocks per key and the merge
//! counters. `REPOP_*` environment variables size the measurement (`lab/store-repopulate.sh`); the gate test keeps a small
//! fixed shape and fails when the later populate gets slower than a tenth of the first one in virtual time, or a parked
//! head is prepared again on every unrelated device completion (`run_waits` counts the admissions that blocked).
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use std::collections::HashMap;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{KvRunData, OTxn, ObjError, Store, StoreCfg, TOp};

type St = Store<SimDev, SimClock>;

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn splitmix(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// S3-like key of index `idx` (30..1100 B, mostly 30..130 B, random sort order: oprobe `s3name`).
fn s3name(idx: u64) -> Vec<u8> {
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

fn value(idx: u64, len: usize) -> Vec<u8> {
    let mut s = idx;
    let mut v = Vec::with_capacity(len + 8);
    while v.len() < len {
        v.extend_from_slice(&splitmix(&mut s).to_le_bytes());
    }
    v.truncate(len);
    v
}

fn coll(seed: u32) -> CollT {
    CollT::Pg(SpgT {
        pgid: PgT::new(1, seed),
        shard: ShardId::NO_SHARD,
    })
}

fn pgmeta(seed: u32) -> Ghobject {
    Ghobject::pgmeta(1, seed, ShardId::NO_SHARD)
}

fn object(name: &str, pg: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(name.as_bytes(), SnapId::NOSNAP, pg, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

/// One phase's measurements.
#[derive(Debug, Default)]
struct Phase {
    keys: u64,
    ops: u64,
    /// Virtual seconds from the first queue to the last ack.
    secs: f64,
    /// CPU seconds the test thread used (engine and driver; the simulated device has no CPU time of its own).
    cpu: f64,
    p50_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    /// Device blocks read / written during the phase.
    rd_blocks: u64,
    wr_blocks: u64,
    /// Counter deltas of the phase.
    parks: u64,
    run_merges: u64,
    run_merge_miss: u64,
    run_waits: u64,
    busy_dirty_hard: u64,
}

impl Phase {
    fn keys_s(&self) -> f64 {
        self.keys as f64 / self.secs.max(1e-9)
    }
}

struct Rig {
    st: St,
    disk: SimDisk,
    pgs: u32,
    log: Vec<u64>,
    tok: u64,
}

impl Rig {
    fn new(budget: u64, shards: u32, pgs: u32, dev_bytes: u64) -> Rig {
        let mut sc = SimConfig::new(dev_bytes);
        sc.xfer_ns_per_lba = env("REPOP_XFER_NS", sc.xfer_ns_per_lba);
        sc.read_ns = env("REPOP_READ_NS", sc.read_ns);
        sc.write_ns = env("REPOP_WRITE_NS", sc.write_ns);
        let disk = SimDisk::new(sc);
        let mut dev = disk.queue();
        let p = MkfsParams::for_device(dev_bytes, shards);
        mkfs(&mut dev, &mut SimClock::default(), &p).unwrap();
        let mut cfg = StoreCfg::for_memory(budget, shards).unwrap();
        cfg.shard.run_pool = Some(Default::default());
        cfg.shard.page_pool = Some(Default::default());
        let d2 = disk.clone();
        let (mut st, _) = Store::mount(move || d2.queue(), SimClock::default(), cfg).unwrap();
        for pg in 0..pgs {
            let mut t = OTxn::new();
            t.push(TOp::MkColl {
                cid: coll(pg),
                bits: 0,
                exist_ok: true,
            });
            t.touch(coll(pg), &pgmeta(pg));
            st.commit(&t).unwrap();
        }
        st.sync().unwrap();
        Rig {
            st,
            disk,
            pgs,
            log: vec![0; pgs as usize],
            tok: 0,
        }
    }

    fn counter(&self, name: &str) -> u64 {
        self.st
            .perf_counters()
            .iter()
            .find(|x| x.0 == name)
            .map_or(0, |x| x.2)
    }

    /// One client txn: a sorted batch of `keys` keys of key index `[lo, hi)` into `obj`, plus the object_info attr and
    /// the pg log set + trim of its PG (what the OSD adds to every replicated write).
    fn txn(&mut self, name: &str, pg: u32, lo: u64, hi: u64, vlen: usize) -> OTxn<'static> {
        let mut kv: Vec<(Vec<u8>, Vec<u8>)> =
            (lo..hi).map(|i| (s3name(i), value(i, vlen))).collect();
        kv.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        kv.dedup_by(|a, b| a.0 == b.0);
        let mut enc = Vec::new();
        denc::SortedKv::encode_into(
            &mut enc,
            kv.len(),
            kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        );
        let o = object(name, pg);
        let mut t = OTxn::new();
        t.touch(coll(pg), &o);
        t.push(TOp::OmapSetRun {
            cid: coll(pg),
            oid: o.clone(),
            run: KvRunData::from_encoding(enc.into()).expect("sorted batch"),
        });
        t.push(TOp::SetAttrs {
            cid: coll(pg),
            oid: o,
            attrs: vec![(b"_".to_vec().into(), vec![0x5a; 250].into())],
        });
        let l = &mut self.log[pg as usize];
        *l += 1;
        let n = *l;
        t.push(TOp::OmapSetKeys {
            cid: coll(pg),
            oid: pgmeta(pg),
            pairs: vec![(
                format!("pglog.{pg}.{n:016}").into_bytes().into(),
                vec![0xa5; 180].into(),
            )],
        });
        t.push(TOp::OmapRmKeys {
            cid: coll(pg),
            oid: pgmeta(pg),
            keys: vec![
                format!("pglog.{pg}.{:016}", n.saturating_sub(3000))
                    .into_bytes()
                    .into(),
            ],
        });
        t
    }

    /// Populate `objs` new objects (named `<prefix>.<i>`, spread over the PGs) with `keys` keys each in batches of
    /// `batch`, `qd` batches in flight (object-major order like oprobe's task list).
    fn populate(
        &mut self,
        prefix: &str,
        objs: u64,
        keys: u64,
        batch: u64,
        qd: usize,
        vlen: usize,
    ) -> Phase {
        let per = keys.div_ceil(batch);
        let total = objs * per;
        let (mut next, mut inflight): (u64, HashMap<u64, (u64, usize)>) = (0, HashMap::new());
        let mut pending: Option<(u64, u32, OTxn<'static>)> = None;
        let mut lat = Vec::new();
        let c0 = |n: &str, r: &Rig| r.counter(n);
        let before = (
            c0("parks", self),
            c0("run_merges", self),
            c0("run_merge_miss", self),
            c0("run_waits", self),
            c0("busy_dirty_hard", self),
        );
        let s0 = self.disk.stats();
        let t0 = self.st.clk.t;
        let cpu0 = store::fastclock::thread_cpu_ns();
        let mut last_ack = t0;
        let mut acked = Vec::new();
        let mut done = 0u64;
        let mut stuck = 0u64;
        let trace = env("REPOP_TRACE_MS", 0) * 1_000_000;
        let mut next_trace = t0 + trace;
        let mut prev: Vec<u64> = Vec::new();
        while done < total {
            if trace > 0 && self.st.clk.t >= next_trace {
                next_trace = self.st.clk.t + trace;
                let names = [
                    "run_merges",
                    "run_merged_ents",
                    "run_merge_miss",
                    "run_waits",
                    "busy_dirty_hard",
                    "ckpt_begins",
                    "ckpt_ends",
                    "run_merge_skip_loads",
                    "run_merge_skip_dirty",
                    "run_merge_skip_paced",
                    "run_merge_skip_unwanted",
                    "run_merge_waits",
                    "parks",
                ];
                let cur: Vec<u64> = names.iter().map(|n| self.counter(n)).collect();
                let d: Vec<String> = names
                    .iter()
                    .zip(&cur)
                    .enumerate()
                    .map(|(i, (n, c))| format!("{n}={}", c - prev.get(i).copied().unwrap_or(0)))
                    .collect();
                let s = self.disk.stats();
                eprintln!(
                    "  t={:.0}ms done={done}/{total} inflight={} dev_inflight={} rd_lbas={} wr_lbas={} dirty={} dirty_soft={} run_mem={}M run_live={} {}",
                    (self.st.clk.t - t0) as f64 / 1e6,
                    inflight.len(),
                    self.disk.inflight(),
                    s.read_lbas,
                    s.write_lbas,
                    self.counter("dirty_pages"),
                    self.counter("dirty_soft"),
                    self.counter("run_mem_bytes") >> 20,
                    self.counter("run_live_ents"),
                    d.join(" ")
                );
                prev = cur;
            }
            let before_inflight = inflight.len();
            while inflight.len() < qd {
                let (task, pg, t) = match pending.take() {
                    Some(p) => p,
                    None => {
                        if next >= total {
                            break;
                        }
                        next += 1;
                        let task = next - 1;
                        let (oi, b) = (task / per, task % per);
                        let (lo, hi) = (b * batch, ((b + 1) * batch).min(keys));
                        let name = format!("{prefix}.{oi:04}");
                        let pg = (splitmix(&mut (oi ^ 0x7067)) % self.pgs as u64) as u32;
                        (task, pg, self.txn(&name, pg, lo, hi, vlen))
                    }
                };
                self.tok += 1;
                match self.st.queue(&t, self.tok) {
                    Ok(_) => {
                        let b = task % per;
                        let n = (((b + 1) * batch).min(keys) - b * batch) as usize;
                        inflight.insert(self.tok, (self.st.clk.t, n));
                    }
                    Err(ObjError::WouldBlock) => {
                        self.tok -= 1;
                        pending = Some((task, pg, t));
                        break;
                    }
                    Err(e) => panic!("queue: {e}"),
                }
            }
            acked.clear();
            self.st.poll(&mut acked).unwrap();
            if acked.is_empty() {
                stuck = if inflight.len() == before_inflight && self.disk.inflight() == 0 {
                    stuck + 1
                } else {
                    0
                };
                assert!(
                    stuck <= 60_000_000,
                    "WARNING TIMEOUT populate op exceeded 60s (virtual; {} ops in flight, store idle)",
                    inflight.len()
                );
                self.st.idle();
            }
            for tok in acked.drain(..) {
                let (t, _) = inflight.remove(&tok).expect("own token");
                let now = self.st.clk.t;
                lat.push(now - t);
                last_ack = now;
                done += 1;
            }
        }
        let s1 = self.disk.stats();
        lat.sort_unstable();
        let q = |p: f64| lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)] as f64 / 1e6;
        Phase {
            keys: objs * keys,
            ops: total,
            secs: (last_ack - t0) as f64 / 1e9,
            cpu: (store::fastclock::thread_cpu_ns() - cpu0) as f64 / 1e9,
            p50_ms: q(0.5),
            p99_ms: q(0.99),
            max_ms: q(1.0),
            rd_blocks: s1.read_lbas - s0.read_lbas,
            wr_blocks: s1.write_lbas - s0.write_lbas,
            parks: self.counter("parks") - before.0,
            run_merges: self.counter("run_merges") - before.1,
            run_merge_miss: self.counter("run_merge_miss") - before.2,
            run_waits: self.counter("run_waits") - before.3,
            busy_dirty_hard: self.counter("busy_dirty_hard") - before.4,
        }
    }
}

fn show(label: &str, p: &Phase) {
    eprintln!(
        "{label}: {:.0} keys/s virt ({} keys, {} ops, {:.2} s virt, {:.2} s cpu = {:.2} us/key) lat ms p50 {:.1} p99 {:.1} max {:.1} | dev rd {:.3} blk/key wr {:.3} blk/key | parks {} merges {} merge_miss {} run_waits {} busy_dirty_hard {}",
        p.keys_s(),
        p.keys,
        p.ops,
        p.secs,
        p.cpu,
        p.cpu * 1e6 / p.keys as f64,
        p.p50_ms,
        p.p99_ms,
        p.max_ms,
        p.rd_blocks as f64 / p.keys as f64,
        p.wr_blocks as f64 / p.keys as f64,
        p.parks,
        p.run_merges,
        p.run_merge_miss,
        p.run_waits,
        p.busy_dirty_hard
    );
}

/// Measurement (`lab/store-repopulate.sh`): phase `a` (`REPOP_A_OBJS` x `REPOP_A_KEYS`), then `c`
/// (`REPOP_C_OBJS` x `REPOP_C_KEYS`), `REPOP_BUDGET_MIB` store memory over `REPOP_SHARDS` shards.
#[test]
#[ignore = "measurement: lab/store-repopulate.sh"]
fn repopulate_measure() {
    let mut rig = Rig::new(
        env("REPOP_BUDGET_MIB", 128) << 20,
        env("REPOP_SHARDS", 2) as u32,
        env("REPOP_PGS", 8) as u32,
        env("REPOP_DEV_GIB", 32) << 30,
    );
    let (batch, qd, vlen) = (
        env("REPOP_BATCH", 1000),
        env("REPOP_QD", 32) as usize,
        env("REPOP_VLEN", 300) as usize,
    );
    let a = rig.populate(
        "a",
        env("REPOP_A_OBJS", 64),
        env("REPOP_A_KEYS", 20_000),
        batch,
        qd,
        vlen,
    );
    show("first populate (a)", &a);
    let c = rig.populate(
        "c",
        env("REPOP_C_OBJS", 2),
        env("REPOP_C_KEYS", 400_000),
        batch,
        qd,
        vlen,
    );
    show("later populate (c)", &c);
    eprintln!(
        "ratio later/first: keys/s {:.2} p99 {:.1}x",
        c.keys_s() / a.keys_s(),
        c.p99_ms / a.p99_ms
    );
}

/// Gate: small fixed shape (a store of 48 MiB, the smallest one shard mounts; phase c holds twice the omap its caches hold). Virtual-time rates are
/// deterministic. A parked txn that waits for run room is tried again only when the room changes: before the fix its
/// whole batch was prepared again on every device completion (540 blocked admissions per op in the measurement shape).
#[test]
fn repopulate_gate() {
    let mut rig = Rig::new(48 << 20, 1, 4, 4 << 30);
    let a = rig.populate("a", 16, 6_000, 500, 16, 300);
    let c = rig.populate("c", 2, 150_000, 500, 16, 300);
    show("first populate (a)", &a);
    show("later populate (c)", &c);
    assert!(
        a.run_waits <= 8 * a.ops && c.run_waits <= 8 * c.ops,
        "parked heads re-prepared per completion: run_waits a {} / {} ops, c {} / {} ops",
        a.run_waits,
        a.ops,
        c.run_waits,
        c.ops
    );
    assert!(
        c.keys_s() >= 0.1 * a.keys_s(),
        "later populate {:.0} keys/s virt vs first {:.0}",
        c.keys_s(),
        a.keys_s()
    );
}
