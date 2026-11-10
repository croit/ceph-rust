// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Perf counters (spec/ops-observability.md 2): classic `osd.*` names/types/priorities so prometheus, the
//! ceph-mixin dashboards, `ceph osd perf` and ceph-exporter read them unchanged.
//!
//! Hot path = plain integer adds on the owning core ([`OpPerf`], no atomics, no locks, no allocation). Every core ships
//! a cumulative copy with its 1 s stats ([`crate::xcore::CoreStats`]); the admin dumps read these samples off the cores
//! ([`crate::ctrsnap`]).
use crate::backend::Backend;
use crate::ctrsnap::{Catalogue, ControlCounters, CoreCounters, CounterSnap, Ctr};
use crate::osd::Osd;
use messages::{CounterValue, PerfCounterType, pct};
use serde_json::{Value, json};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Sum of nanoseconds + count (a `time_avg` counter).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Avg {
    pub sum_ns: u64,
    pub n: u64,
}

impl Avg {
    #[inline]
    pub fn add(&mut self, ns: u64) {
        self.sum_ns += ns;
        self.n += 1;
    }
    pub(crate) fn merge(&mut self, o: &Avg) {
        self.sum_ns += o.sum_ns;
        self.n += o.n;
    }
}

/// Histogram axes (classic osd): latency log2, min 0, quant 100000 ns; request size log2, min 0, quant 512 B; 32 buckets each.
const HB: usize = 32;
const LAT_QUANT: u64 = 100_000;
const SIZE_QUANT: u64 = 512;

/// Log2 bucket of `v` (classic `PerfHistogramCommon` log2 scale, min 0): 0 = below min (never), 1 = `[0, q)`,
/// i >= 2 = `[q*2^(i-2), q*2^(i-1))`, last = overflow.
#[inline]
fn bucket(v: u64, quant: u64) -> usize {
    let q = v / quant;
    if q == 0 {
        1
    } else {
        (2 + q.ilog2() as usize).min(HB - 1)
    }
}

/// 2-D histogram: latency (rows) x request size (columns).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Hist(pub [[u64; HB]; HB]);

impl Hist {
    #[inline]
    pub fn add(&mut self, lat_ns: u64, bytes: u64) {
        self.0[bucket(lat_ns, LAT_QUANT)][bucket(bytes, SIZE_QUANT)] += 1;
    }
    fn merge(&mut self, o: &Hist) {
        for (a, b) in self.0.iter_mut().flatten().zip(o.0.iter().flatten()) {
            *a += *b;
        }
    }
    fn since(&self, b: &Hist) -> Hist {
        let mut o = *self;
        for (a, b) in o.0.iter_mut().flatten().zip(b.0.iter().flatten()) {
            *a = a.saturating_sub(*b);
        }
        o
    }
}

/// Per-core cumulative op counters (plain integers, owned by the PG core).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OpPerf {
    /// Loop parks with an output notification still queued (adr 0074 am. 4): must stay 0.
    pub wake_parked_ready: u64,
    /// Idle sleeps of the core loop, wall ns slept, sleeps ended by a mesh poke and their summed poke-to-running ns
    /// (the wake cost a cross-core message pays when its target sleeps).
    pub idle_sleeps: u64,
    pub idle_sleep_ns: u64,
    /// Sleeps that ended by their timeout, and their overshoot (ns): one wake latency each.
    pub idle_timeouts: u64,
    pub idle_timeout_over_ns: u64,
    pub mesh_wakes: u64,
    pub mesh_wake_ns: u64,
    /// Core loop iterations that did work / found none (a busy-polling core spins through the latter), and the wall ns
    /// of the working ones: `loop_busy_ns / ops` is the useful cost per op, unlike the cycles of a polling thread.
    pub loop_busy_iters: u64,
    pub loop_idle_iters: u64,
    pub loop_busy_ns: u64,
    /// eventfd writes (wake syscalls) cross-core senders issued to this core.
    pub wake_writes: u64,
    /// Kernel tier ring enters (io_uring_enter) at a poll start / at the end of an iteration / in the idle sleep.
    pub ring_enters_poll: u64,
    pub ring_enters_submit: u64,
    pub ring_enters_sf: u64,
    pub ring_enters_wait: u64,
    /// RDMA transport (`rdmastat.rs`): cumulative counters of this core over its devices, and its upgraded sessions (gauge).
    pub rdma: rdma::status::Counters,
    pub rdma_sessions: u64,
    pub op: u64,
    pub op_in: u64,
    pub op_out: u64,
    pub op_r: u64,
    pub op_r_out: u64,
    pub op_w: u64,
    pub op_w_in: u64,
    pub op_rw: u64,
    pub op_rw_in: u64,
    pub op_rw_out: u64,
    pub lat: Avg,
    pub r_lat: Avg,
    pub w_lat: Avg,
    pub rw_lat: Avg,
    /// Latency x size histograms: reads (by bytes out), writes (in), read-write (in, out).
    pub h_r_out: Hist,
    pub h_w_in: Hist,
    pub h_rw_in: Hist,
    pub h_rw_out: Hist,
    pub subop: u64,
    pub subop_in: u64,
    pub subop_lat: Avg,
    pub subop_w: u64,
    pub subop_w_in: u64,
    pub subop_w_lat: Avg,
    pub subop_push: u64,
    pub subop_push_in: u64,
    pub subop_pull: u64,
    pub pull: u64,
    pub push: u64,
    pub push_out: u64,
    pub recovery_ops: u64,
    pub recovery_bytes: u64,
    /// Gauge: ops in flight on the core (set when the snapshot is taken).
    pub wip: u64,
    /// Gauge: ops older than `osd_op_complaint_time` / age of the oldest in-flight op (s).
    pub slow_n: u64,
    pub oldest_s: u64,
    /// Durable commit latency of store transactions (submit to durable), count = commits.
    pub store_lat: Avg,
    /// Inline compression (adr 0059 am. 1): chunks stored compressed / rejected (ratio, room) / skipped by the sample;
    /// compress latency per chunk attempt (samples included), decompress latency per chunk read.
    pub comp_ok: u64,
    pub comp_rejected: u64,
    pub comp_sampled_out: u64,
    /// Windows of compressed chunks rewritten by the chunk space rule (adr 0059 am. 4; BlueStore `gc_merged`).
    pub comp_gc: u64,
    /// Store data staging (adr 0061 am. 4): bytes copied into device buffers / written by reference / block crcs reused.
    pub store_staged_bytes: u64,
    pub store_zc_bytes: u64,
    pub store_crc_reused_bytes: u64,
    /// Placement range bytes covered by shifted receipt CRC grids.
    pub store_placement_crc_reblocked_bytes: u64,
    /// Actual source bytes hashed for those shifted grids (including edges).
    pub store_placement_crc_hashed_bytes: u64,
    /// Store probes of the op gate refused, by cause (`peering::store::CompPerf`, doc/ops/op-trace.md `pg_gate`).
    pub probe_refused_admission: u64,
    pub probe_refused_obj: u64,
    pub probe_refused_log: u64,
    pub probe_refused_data: u64,
    pub comp_lat: Avg,
    pub decomp_lat: Avg,
    /// Client reads answered with EIO.
    pub read_eio: u64,
    /// EC_DIRECT_READ ops on EC pools: served from our shard / answered EAGAIN (client redrives through the primary).
    pub ec_direct_reads: u64,
    pub ec_direct_eagain: u64,
    /// Client ops that hit a damaged local object and waited for its repair from a peer.
    pub read_repair: u64,
    /// Object-state cache (adr 0160 D5): client ops whose head state came from the cache / from the store.
    pub obj_cache_hit: u64,
    pub obj_cache_miss: u64,
    /// Store wakes at the op gate (adr 0043 am. 9): gated ops probed again / skipped (the wake did not name them) / run
    /// without a second probe (a replicated read whose named cause arrived).
    pub gate_probe: u64,
    pub gate_skip: u64,
    pub gate_direct: u64,
    /// Send-first (adr 0008 am. 2, 3): client writes whose local txn was held back until the repops left / of those, applied by
    /// the driver after it moved them (the rest: applied earlier by another entry point, repops still queued).
    pub late_held: u64,
    pub late_driver: u64,
    /// Listing continuations left for the next loop iteration by the core share (adr 0522).
    pub list_deferred: u64,
    /// Damaged local objects repaired from a peer (summed from the PGs, `num_shards_repaired`).
    pub shards_repaired: u64,
    /// Gauges: slow store commits / EIO reads inside the alert lifetime, payload bytes of the ops in flight.
    pub slow_store_win: u64,
    pub eio_win: u64,
    pub inflight_bytes: u64,
    /// Gauges, repop credits (adr 0084): peer shard lanes with sub-writes waiting for credit; age of the oldest credit
    /// still out (ms, max over the cores). Detection only: a leaked credit shows as an age that only grows.
    pub credit_blocked_lanes: u64,
    pub credit_oldest_ms: u64,
    /// Time in PG states, one sample per visit ([`crate::perfx::RS`]).
    pub rs: [Avg; crate::perfx::RS_N],
    pub scrub: crate::perfx::ScrubPerf,
    /// Closed vulnerability windows / rebuild episodes of the primary PGs (peering.md 9.6), from `PgSet::latch_perf`.
    pub latch: peering::LatchPerf,
}

impl OpPerf {
    /// A successful client op finished: `class` = its counter class from the request's op codes, bytes in (write
    /// data) / out (read data), `lat` in ns. A request without a class is counted nowhere (spec ops-observability 2d).
    #[inline]
    pub fn client_done(&mut self, class: opwire::OpClass, inb: u64, outb: u64, lat: u64) {
        if class.is_empty() {
            return;
        }
        self.op += 1;
        self.op_in += inb;
        self.op_out += outb;
        self.lat.add(lat);
        match (class.read, class.write) {
            (true, true) => {
                self.op_rw += 1;
                self.op_rw_in += inb;
                self.op_rw_out += outb;
                self.rw_lat.add(lat);
                self.h_rw_in.add(lat, inb);
                self.h_rw_out.add(lat, outb);
            }
            (false, true) => {
                self.op_w += 1;
                self.op_w_in += inb;
                self.w_lat.add(lat);
                self.h_w_in.add(lat, inb);
            }
            (true, false) => {
                self.op_r += 1;
                self.op_r_out += outb;
                self.r_lat.add(lat);
                self.h_r_out.add(lat, outb);
            }
            (false, false) => {}
        }
    }

    pub fn merge(&mut self, o: &OpPerf) {
        macro_rules! sum { ($($f:ident),*) => { $(self.$f += o.$f;)* } }
        sum!(
            wake_parked_ready,
            idle_sleeps,
            idle_sleep_ns,
            idle_timeouts,
            idle_timeout_over_ns,
            mesh_wakes,
            mesh_wake_ns,
            loop_busy_iters,
            loop_idle_iters,
            loop_busy_ns,
            wake_writes,
            ring_enters_poll,
            ring_enters_submit,
            ring_enters_sf,
            ring_enters_wait,
            rdma_sessions,
            op,
            op_in,
            op_out,
            op_r,
            op_r_out,
            op_w,
            op_w_in,
            op_rw,
            op_rw_in,
            op_rw_out,
            subop,
            subop_in,
            subop_w,
            subop_w_in,
            subop_push,
            subop_push_in,
            subop_pull,
            pull,
            push,
            push_out,
            recovery_ops,
            recovery_bytes,
            wip,
            slow_n,
            read_eio,
            ec_direct_reads,
            ec_direct_eagain,
            read_repair,
            obj_cache_hit,
            obj_cache_miss,
            gate_probe,
            gate_skip,
            gate_direct,
            late_held,
            late_driver,
            list_deferred,
            shards_repaired,
            comp_ok,
            comp_rejected,
            comp_sampled_out,
            comp_gc,
            store_staged_bytes,
            store_zc_bytes,
            store_crc_reused_bytes,
            store_placement_crc_reblocked_bytes,
            store_placement_crc_hashed_bytes,
            probe_refused_admission,
            probe_refused_obj,
            probe_refused_log,
            probe_refused_data,
            slow_store_win,
            eio_win,
            inflight_bytes,
            credit_blocked_lanes
        );
        self.oldest_s = self.oldest_s.max(o.oldest_s);
        self.credit_oldest_ms = self.credit_oldest_ms.max(o.credit_oldest_ms);
        self.rdma.merge(&o.rdma);
        self.store_lat.merge(&o.store_lat);
        self.comp_lat.merge(&o.comp_lat);
        self.decomp_lat.merge(&o.decomp_lat);
        for (a, b) in self.rs.iter_mut().zip(&o.rs) {
            a.merge(b);
        }
        self.scrub.merge(&o.scrub);
        self.latch.merge(&o.latch);
        for (a, b) in [
            (&mut self.lat, &o.lat),
            (&mut self.r_lat, &o.r_lat),
            (&mut self.w_lat, &o.w_lat),
            (&mut self.rw_lat, &o.rw_lat),
            (&mut self.subop_lat, &o.subop_lat),
            (&mut self.subop_w_lat, &o.subop_w_lat),
        ] {
            a.merge(b);
        }
        self.h_r_out.merge(&o.h_r_out);
        self.h_w_in.merge(&o.h_w_in);
        self.h_rw_in.merge(&o.h_rw_in);
        self.h_rw_out.merge(&o.h_rw_out);
    }
}

/// Event counters (monotonic) of the control core.
#[derive(Debug, Default)]
pub(crate) struct Perf {
    pub util: crate::utilization::Utilization,
    pub map_messages: u64,
    pub map_message_epochs: u64,
    pub heartbeat_to_peers: u64,
    /// This core's op counters.
    pub op: OpPerf,
    /// Control core: its counter sample and the OSD aggregates of its last tick (the admin dumps read these,
    /// [`crate::ctrsnap`]).
    pub own: Arc<CoreCounters>,
    pub ctl: Arc<ControlCounters>,
    /// Control core: every core's sample at the last `perf reset` of each logger (counters report
    /// `current - reset`; gauges are unaffected).
    pub reset: Option<crate::ctrsnap::ResetBaselines>,
    /// Control core: store commit latency totals at the last osd_stat build, and the interval mean it reported
    /// (`ceph osd perf`, spec pg-io-stats.md 4).
    pub last_store: Avg,
    pub last_os_perf: messages::ObjectstorePerfStat,
    /// Replica side: start of every RepOp awaiting its commit, `(pool, seed, client, tid)` -> ns.
    pub sub_start:
        std::collections::HashMap<(u64, u32, i64, u64), u64, foldhash::fast::RandomState>,
    /// Last time slow ops were logged.
    pub last_slow_log: std::time::Duration,
    /// Slow store commits since the last `slow store commit` line, and the worst latency (ns) among them.
    pub slow_commits: u64,
    pub slow_commit_worst_ns: u64,
    /// Last time slow store commits were logged.
    pub last_slow_commit_log: std::time::Duration,
    /// PG state sampler (recoverystate_perf, scrub counters).
    pub obs: crate::perfx::PgObs,
    /// Slow store commits / EIO client reads, for the os_alerts windows.
    pub slow_win: crate::perfx::Window,
    pub eio_win: crate::perfx::Window,
    /// `clear_shards_repaired`: repaired objects already acknowledged (osd_stat shows `total - cleared`).
    pub repaired_cleared: u64,
}

/// Allocation unit of the store (one 4 KiB block).
const ALLOC_UNIT: u64 = 4096;

/// Submit times of store txns awaiting durability (token -> ns on the PG clock). Bounded: a lost token is a missed sample.
#[derive(Debug, Default)]
pub(crate) struct PersistTimes(std::collections::HashMap<u64, u64, foldhash::fast::RandomState>);

impl PersistTimes {
    const CAP: usize = 65_536;

    #[inline]
    pub(crate) fn submit(&mut self, token: u64, now: u64) {
        if self.0.len() >= Self::CAP {
            self.0.clear();
        }
        self.0.insert(token, now);
    }

    /// Durable: ns since the submit, if it was recorded.
    #[inline]
    pub(crate) fn done(&mut self, token: u64, now: u64) -> Option<u64> {
        self.0.remove(&token).map(|t| now.saturating_sub(t))
    }
}

/// `(type, value)` per counter path (`logger.name`), sorted by path: the mgr report's input.
pub(crate) type Map = BTreeMap<String, (PerfCounterType, CounterValue)>;

/// Adds the classic counters of one logger at a time to a [`Catalogue`].
struct Adder<'a> {
    cat: &'a mut Catalogue,
    lg: usize,
}

impl Adder<'_> {
    fn logger(&mut self, name: &'static str) {
        self.lg = self.cat.logger(name);
    }
    #[expect(clippy::too_many_arguments)]
    fn put(
        &mut self,
        name: &'static str,
        ty: u8,
        prio: u8,
        unit: u8,
        nick: &'static str,
        desc: &'static str,
        v: CounterValue,
    ) {
        let c = Ctr {
            name: Cow::Borrowed(name),
            ty,
            prio,
            unit,
            nick,
            desc,
            v,
        };
        self.cat.push(self.lg, c);
    }
    fn gauge(&mut self, name: &'static str, prio: u8, unit: u8, desc: &'static str, v: u64) {
        self.put(name, pct::GAUGE, prio, unit, "", desc, cv(v));
    }
    fn ctr(
        &mut self,
        name: &'static str,
        prio: u8,
        unit: u8,
        nick: &'static str,
        desc: &'static str,
        v: u64,
    ) {
        self.put(name, pct::COUNTER_U64, prio, unit, nick, desc, cv(v));
    }
    fn avg(
        &mut self,
        name: &'static str,
        prio: u8,
        nick: &'static str,
        desc: &'static str,
        a: Avg,
    ) {
        // classic packs (sum ns, count, count) for a time average
        let v = CounterValue {
            value: a.sum_ns,
            avgcount: a.n,
            avgcount2: a.n,
        };
        self.put(name, pct::TIME_AVG, prio, pct::UNIT_NONE, nick, desc, v);
    }
}

fn cv(v: u64) -> CounterValue {
    CounterValue {
        value: v,
        avgcount: 0,
        avgcount2: 0,
    }
}

fn sub(a: u64, b: u64) -> u64 {
    a.saturating_sub(b)
}
pub(crate) fn sub_avg(a: Avg, b: Avg) -> Avg {
    Avg {
        sum_ns: sub(a.sum_ns, b.sum_ns),
        n: sub(a.n, b.n),
    }
}

impl OpPerf {
    /// `self - base` for the monotonic fields (gauges kept).
    pub(crate) fn since(&self, b: &OpPerf) -> OpPerf {
        let mut o = *self;
        macro_rules! d { ($($f:ident),*) => { $(o.$f = sub(self.$f, b.$f);)* } }
        d!(
            wake_parked_ready,
            idle_sleeps,
            idle_sleep_ns,
            idle_timeouts,
            idle_timeout_over_ns,
            mesh_wakes,
            mesh_wake_ns,
            loop_busy_iters,
            loop_idle_iters,
            loop_busy_ns,
            wake_writes,
            ring_enters_poll,
            ring_enters_submit,
            ring_enters_sf,
            ring_enters_wait,
            op,
            op_in,
            op_out,
            op_r,
            op_r_out,
            op_w,
            op_w_in,
            op_rw,
            op_rw_in,
            op_rw_out,
            subop,
            subop_in,
            subop_w,
            subop_w_in,
            subop_push,
            subop_push_in,
            subop_pull,
            pull,
            push,
            push_out,
            recovery_ops,
            recovery_bytes,
            read_eio,
            ec_direct_reads,
            ec_direct_eagain,
            read_repair,
            obj_cache_hit,
            obj_cache_miss,
            gate_probe,
            gate_skip,
            gate_direct,
            late_held,
            late_driver,
            list_deferred,
            shards_repaired,
            comp_ok,
            comp_rejected,
            comp_sampled_out,
            comp_gc,
            store_staged_bytes,
            store_zc_bytes,
            store_crc_reused_bytes,
            store_placement_crc_reblocked_bytes,
            store_placement_crc_hashed_bytes,
            probe_refused_admission,
            probe_refused_obj,
            probe_refused_log,
            probe_refused_data
        );
        o.rdma = self.rdma.since(&b.rdma);
        o.store_lat = sub_avg(self.store_lat, b.store_lat);
        o.comp_lat = sub_avg(self.comp_lat, b.comp_lat);
        o.decomp_lat = sub_avg(self.decomp_lat, b.decomp_lat);
        for (i, a) in o.rs.iter_mut().enumerate() {
            *a = sub_avg(self.rs[i], b.rs[i]);
        }
        o.scrub = self.scrub.since(&b.scrub);
        // perf reset: the time averages restart, the min gauges keep their value (they only move down)
        for (d, b) in [
            (&mut o.latch.vulnerability, b.latch.vulnerability),
            (&mut o.latch.rebuild, b.latch.rebuild),
        ] {
            d.n = d.n.saturating_sub(b.n);
            d.sum_ns = d.sum_ns.saturating_sub(b.sum_ns);
        }
        o.lat = sub_avg(self.lat, b.lat);
        o.r_lat = sub_avg(self.r_lat, b.r_lat);
        o.w_lat = sub_avg(self.w_lat, b.w_lat);
        o.rw_lat = sub_avg(self.rw_lat, b.rw_lat);
        o.subop_lat = sub_avg(self.subop_lat, b.subop_lat);
        o.subop_w_lat = sub_avg(self.subop_w_lat, b.subop_w_lat);
        o.h_r_out = self.h_r_out.since(&b.h_r_out);
        o.h_w_in = self.h_w_in.since(&b.h_w_in);
        o.h_rw_in = self.h_rw_in.since(&b.h_rw_in);
        o.h_rw_out = self.h_rw_out.since(&b.h_rw_out);
        o
    }
}

/// Classic axis description: log2 scale, min 0, 32 buckets; first bucket is below min, last is open-ended.
fn hist_axis(name: &str, quant: u64) -> Value {
    let mut ranges = vec![json!({"max": -1})];
    for i in 1..HB {
        let lo = if i == 1 { 0 } else { quant << (i - 2) };
        if i == HB - 1 {
            ranges.push(json!({"min": lo}));
        } else {
            ranges.push(json!({"min": lo, "max": (quant << (i - 1)) - 1}));
        }
    }
    json!({"name": name, "min": 0, "quant_size": quant, "buckets": HB, "scale_type": "log2", "ranges": ranges})
}

/// 1-minute load average of the host (`getloadavg`), `None` when the system cannot report it.
pub(crate) fn load_average_1m() -> Option<f64> {
    let mut a = [0f64; 1];
    // SAFETY: getloadavg writes at most the requested number of load values into the buffer.
    (unsafe { libc::getloadavg(a.as_mut_ptr(), 1) } == 1).then_some(a[0])
}

/// Online CPUs of the host (`_SC_NPROCESSORS_ONLN`), at least 1.
pub(crate) fn online_cpus() -> usize {
    // SAFETY: sysconf has no preconditions.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    usize::try_from(n).ok().filter(|n| *n > 0).unwrap_or(1)
}

impl<B: Backend> Osd<B> {
    /// Driver hook, right before the core parks: count a park with an output notification still queued (a lost
    /// wake-up: the loop drains the queue on every iteration, adr 0074 am. 4).
    pub fn note_park(&mut self) {
        self.perf.op.wake_parked_ready += u64::from(!self.output_ready.is_empty());
    }
    /// Driver hook after an idle sleep: `slept` wall ns, `wake` = ns from the mesh poke that ended it to running.
    /// Ring enters of the kernel tier loop since the last call: `[poll start, end-of-iteration submit, idle sleep, send-first window closes]`.
    pub fn note_ring_enters(&mut self, d: [u64; 4]) {
        let o = &mut self.perf.op;
        o.ring_enters_poll += d[0];
        o.ring_enters_submit += d[1];
        o.ring_enters_sf += d[3];
        o.ring_enters_wait += d[2];
    }
    /// Driver hook: eventfd writes cross-core senders issued to this core since the last call.
    pub fn note_wake_writes(&mut self, d: u64) {
        self.perf.op.wake_writes += d;
    }
    /// Driver hook: the loop iteration just run found no work.
    pub fn note_idle_iter(&mut self) {
        self.perf.op.loop_idle_iters += 1;
    }
    pub fn note_sleep(&mut self, slept: u64, wake: Option<u64>, timeout_over: Option<u64>) {
        let o = &mut self.perf.op;
        o.idle_sleeps += 1;
        o.idle_sleep_ns += slept;
        if let Some(over) = timeout_over {
            o.idle_timeouts += 1;
            o.idle_timeout_over_ns += over;
        }
        if let Some(w) = wake {
            o.mesh_wakes += 1;
            o.mesh_wake_ns += w;
        }
    }
    /// `(ops older than the complaint time, age of the oldest in ns)`: tracked ops plus the ones waiting for a map,
    /// the OSD being up or their PG, plus replica writes held for their store loads (adr 0021 am. 25).
    pub(crate) fn slow_ops(&self) -> (u64, u64) {
        let now = self.now.as_nanos() as u64;
        let lim = self.tracker.lim.complaint_ns;
        let (n, old) = self.tracker.slow(now);
        let (pn, pold) = self.pg_parked_slow(now, lim);
        let (rn, rold) = self.pg.set.repops_held_slow(self.pg_mono(), lim);
        (n + pn + rn, old.max(pold).max(rold))
    }

    /// This core's counters with the live gauges (ops in flight, slow ops) filled in.
    pub(crate) fn op_perf_local(&self) -> OpPerf {
        let mut p = self.perf.op;
        p.wip = (self.tracker.len() + self.pg_parked_len()) as u64;
        let (n, oldest) = self.slow_ops();
        p.slow_n = n;
        p.oldest_s = oldest / 1_000_000_000;
        p.inflight_bytes = self.tracker.inflight_bytes();
        (p.credit_blocked_lanes, p.credit_oldest_ms) = self.flow_gauges();
        let c = peering::PgStoreOps::comp_perf(&self.pg.store);
        p.comp_ok = c.ok;
        p.comp_rejected = c.rejected;
        p.comp_sampled_out = c.sampled_out;
        p.comp_gc = c.gc_merged;
        p.store_staged_bytes = c.staged_bytes;
        p.store_zc_bytes = c.zc_bytes;
        p.store_crc_reused_bytes = c.crc_reused_bytes;
        p.store_placement_crc_reblocked_bytes = c.placement_crc_reblocked_bytes;
        p.store_placement_crc_hashed_bytes = c.placement_crc_hashed_bytes;
        p.probe_refused_admission = c.probe_refused_admission;
        p.probe_refused_obj = c.probe_refused_obj;
        p.probe_refused_log = c.probe_refused_log;
        p.probe_refused_data = c.probe_refused_data;
        p.comp_lat = Avg {
            sum_ns: c.comp_ns,
            n: c.ok + c.rejected + c.sampled_out,
        };
        p.decomp_lat = Avg {
            sum_ns: c.decomp_ns,
            n: c.decomp,
        };
        p.latch = self.pg.set.latch_perf();
        let now = self.mnow().as_nanos() as u64;
        let life = |k: &str| self.conf.u64(k, 86400).saturating_mul(1_000_000_000);
        p.slow_store_win = self
            .perf
            .slow_win
            .count(now, life("bluestore_slow_ops_warn_lifetime"));
        p.eio_win = self
            .perf
            .eio_win
            .count(now, life("flashstore_read_errors_warn_lifetime"));
        p
    }

    /// Cumulative op counters of the whole OSD (this core + the last report of every other core).
    pub(crate) fn op_perf_all(&self) -> OpPerf {
        let mut t = self.op_perf_local();
        for s in self.cl.stats.iter().flatten() {
            t.merge(&s.counters.perf);
        }
        t
    }

    /// The classic loggers of the last samples (MMgrReport input): `(type, value)` per counter path, sorted by path.
    pub(crate) fn counters(&self) -> Map {
        self.counter_snap().osd_map()
    }
}

impl CounterSnap {
    /// [`Self::osd_counters`] as `(type, value)` per counter path.
    pub(crate) fn osd_map(&self) -> Map {
        let mut cat = Catalogue::default();
        self.osd_counters(&mut cat);
        let mut m = Map::new();
        for (lg, c) in cat.iter() {
            let path = format!("{lg}.{}", c.name);
            let mut t = PerfCounterType::new(&path, c.ty, c.prio, c.unit);
            t.description = c.desc.to_owned();
            t.nick = c.nick.to_owned();
            m.insert(path, (t, c.v));
        }
        m
    }

    /// The classic loggers (spec ops-observability 2): `osd`, `bluestore`, `recoverystate_perf`, `throttle-osd_client_*`.
    pub(crate) fn osd_counters(&self, cat: &mut Catalogue) {
        let s = &self.ctl.statfs;
        let used = s.total.saturating_sub(s.available);
        let (all, o) = self.op_perf();
        let lg = cat.logger("osd");
        let mut a = Adder { cat, lg };
        use pct::*;
        let none = UNIT_NONE;
        let bytes = UNIT_BYTES;
        a.gauge(
            "op_wip",
            PRIO_USEFUL,
            none,
            "Replication operations currently being processed (primary)",
            all.wip,
        );
        a.ctr("op", PRIO_CRITICAL, none, "ops", "Client operations", o.op);
        a.ctr(
            "op_in_bytes",
            PRIO_INTERESTING,
            bytes,
            "wr",
            "Client operations total write size",
            o.op_in,
        );
        a.ctr(
            "op_out_bytes",
            PRIO_INTERESTING,
            bytes,
            "rd",
            "Client operations total read size",
            o.op_out,
        );
        a.avg(
            "op_latency",
            9,
            "l",
            "Latency of client operations (including queue time)",
            o.lat,
        );
        a.avg(
            "op_process_latency",
            PRIO_USEFUL,
            "",
            "Latency of client operations (excluding queue time)",
            o.lat,
        );
        a.ctr(
            "op_r",
            PRIO_USEFUL,
            none,
            "",
            "Client read operations",
            o.op_r,
        );
        a.ctr(
            "op_r_out_bytes",
            PRIO_USEFUL,
            bytes,
            "",
            "Client data read",
            o.op_r_out,
        );
        a.avg(
            "op_r_latency",
            PRIO_USEFUL,
            "",
            "Latency of read operation (including queue time)",
            o.r_lat,
        );
        a.avg(
            "op_r_process_latency",
            PRIO_USEFUL,
            "",
            "Latency of read operation (excluding queue time)",
            o.r_lat,
        );
        a.ctr(
            "op_w",
            PRIO_USEFUL,
            none,
            "",
            "Client write operations",
            o.op_w,
        );
        a.ctr(
            "op_w_in_bytes",
            PRIO_USEFUL,
            none,
            "",
            "Client data written",
            o.op_w_in,
        );
        a.avg(
            "op_w_latency",
            PRIO_USEFUL,
            "",
            "Latency of write operation (including queue time)",
            o.w_lat,
        );
        a.avg(
            "op_w_process_latency",
            PRIO_USEFUL,
            "",
            "Latency of write operation (excluding queue time)",
            o.w_lat,
        );
        a.ctr(
            "op_rw",
            PRIO_USEFUL,
            none,
            "",
            "Client read-modify-write operations",
            o.op_rw,
        );
        a.ctr(
            "op_rw_in_bytes",
            PRIO_USEFUL,
            bytes,
            "",
            "Client read-modify-write operations write in",
            o.op_rw_in,
        );
        a.ctr(
            "op_rw_out_bytes",
            PRIO_USEFUL,
            bytes,
            "",
            "Client read-modify-write operations read out ",
            o.op_rw_out,
        );
        a.avg(
            "op_rw_latency",
            PRIO_USEFUL,
            "",
            "Latency of read-modify-write operation (including queue time)",
            o.rw_lat,
        );
        a.avg(
            "op_rw_process_latency",
            PRIO_USEFUL,
            "",
            "Latency of read-modify-write operation (excluding queue time)",
            o.rw_lat,
        );
        a.ctr("subop", PRIO_DEBUGONLY, none, "", "Suboperations", o.subop);
        a.ctr(
            "subop_in_bytes",
            PRIO_DEBUGONLY,
            bytes,
            "",
            "Suboperations total size",
            o.subop_in,
        );
        a.avg(
            "subop_latency",
            PRIO_DEBUGONLY,
            "",
            "Suboperations latency",
            o.subop_lat,
        );
        a.ctr(
            "subop_w",
            PRIO_DEBUGONLY,
            none,
            "",
            "Replicated writes",
            o.subop_w,
        );
        a.ctr(
            "subop_w_in_bytes",
            PRIO_DEBUGONLY,
            bytes,
            "",
            "Replicated written data size",
            o.subop_w_in,
        );
        a.avg(
            "subop_w_latency",
            PRIO_DEBUGONLY,
            "",
            "Replicated writes latency",
            o.subop_w_lat,
        );
        a.ctr(
            "subop_pull",
            PRIO_DEBUGONLY,
            none,
            "",
            "Suboperations pull requests",
            o.subop_pull,
        );
        a.ctr(
            "subop_push",
            PRIO_DEBUGONLY,
            none,
            "",
            "Suboperations push messages",
            o.subop_push,
        );
        a.ctr(
            "subop_push_in_bytes",
            PRIO_DEBUGONLY,
            bytes,
            "",
            "Suboperations pushed size",
            o.subop_push_in,
        );
        a.ctr(
            "pull",
            PRIO_DEBUGONLY,
            none,
            "",
            "Pull requests sent",
            o.pull,
        );
        a.ctr(
            "push",
            PRIO_DEBUGONLY,
            none,
            "",
            "Push messages sent",
            o.push,
        );
        a.ctr(
            "push_out_bytes",
            PRIO_DEBUGONLY,
            bytes,
            "",
            "Pushed size",
            o.push_out,
        );
        a.ctr(
            "recovery_ops",
            PRIO_INTERESTING,
            none,
            "rop",
            "Started recovery operations",
            o.recovery_ops,
        );
        a.ctr(
            "recovery_bytes",
            PRIO_INTERESTING,
            none,
            "rbt",
            "recovery bytes",
            o.recovery_bytes,
        );
        a.gauge(
            "loadavg",
            PRIO_DEBUGONLY,
            none,
            "CPU load",
            self.ctl.loadavg_x100,
        );
        let (np, npp, npr) = self.ctl.roles;
        a.put(
            "numpg",
            GAUGE,
            PRIO_USEFUL,
            none,
            "pgs",
            "Placement groups",
            cv(np),
        );
        a.gauge(
            "numpg_primary",
            PRIO_DEBUGONLY,
            none,
            "Placement groups for which this osd is primary",
            npp,
        );
        a.gauge(
            "numpg_replica",
            PRIO_DEBUGONLY,
            none,
            "Placement groups for which this osd is replica",
            npr,
        );
        a.gauge(
            "numpg_stray",
            PRIO_DEBUGONLY,
            none,
            "Placement groups ready to be deleted from this osd",
            0,
        );
        let (rpgs, rleft, rdone, rrate) = self.ctl.removal;
        a.put(
            "numpg_removing",
            GAUGE,
            PRIO_USEFUL,
            none,
            "pgsr",
            "Placement groups queued for local deletion",
            cv(rpgs),
        );
        a.gauge(
            "delete_objects_left",
            PRIO_USEFUL,
            none,
            "Objects left in the PGs queued for deletion (estimate)",
            rleft,
        );
        a.ctr(
            "delete_objects",
            PRIO_USEFUL,
            none,
            "",
            "Objects removed by background PG deletion",
            rdone,
        );
        a.gauge(
            "delete_objects_rate",
            PRIO_USEFUL,
            none,
            "Background PG deletion rate (objects per second, last window)",
            rrate,
        );
        a.gauge(
            "heartbeat_to_peers",
            PRIO_DEBUGONLY,
            none,
            "Heartbeat (ping) peers we send to",
            self.ctl.heartbeat_to_peers,
        );
        a.ctr(
            "map_messages",
            PRIO_DEBUGONLY,
            none,
            "",
            "OSD map messages",
            self.ctl.map_messages,
        );
        a.ctr(
            "map_message_epochs",
            PRIO_DEBUGONLY,
            none,
            "",
            "OSD map epochs",
            self.ctl.map_message_epochs,
        );
        a.put(
            "stat_bytes",
            GAUGE,
            PRIO_USEFUL,
            bytes,
            "size",
            "OSD size",
            cv(s.total),
        );
        a.put(
            "stat_bytes_used",
            GAUGE,
            PRIO_USEFUL,
            bytes,
            "used",
            "Used space",
            cv(used),
        );
        a.put(
            "stat_bytes_avail",
            GAUGE,
            PRIO_DEBUGONLY,
            bytes,
            "",
            "Available space",
            cv(s.available),
        );
        self.extra_counters(&mut a, s, &o, &all);
    }

    /// Secondary loggers (spec ops-observability 2c): scrub outcomes in `osd`, `bluestore`, `recoverystate_perf`,
    /// `throttle-osd_client_*`. `o` = counters since the last `perf reset`, `all` = absolute (gauges).
    fn extra_counters(&self, a: &mut Adder, s: &messages::StoreStatfs, o: &OpPerf, all: &OpPerf) {
        use pct::*;
        let none = UNIT_NONE;
        let bytes = UNIT_BYTES;
        a.ctr(
            "knet_wake_parked_ready",
            PRIO_USEFUL,
            none,
            "",
            "Core parks with an output notification still queued (lost wake-up, must stay 0)",
            o.wake_parked_ready,
        );
        a.ctr(
            "knet_idle_sleeps",
            PRIO_USEFUL,
            none,
            "",
            "Idle sleeps of the core loops",
            o.idle_sleeps,
        );
        a.ctr(
            "knet_idle_timeouts",
            PRIO_USEFUL,
            none,
            "",
            "Idle sleeps that ended by their timeout (no completion, no poke)",
            o.idle_timeouts,
        );
        a.ctr(
            "knet_idle_timeout_over_ns",
            PRIO_USEFUL,
            none,
            "",
            "Wall ns those sleeps overshot their timeout (= wake latency, sum)",
            o.idle_timeout_over_ns,
        );
        a.ctr(
            "knet_idle_sleep_ns",
            PRIO_USEFUL,
            none,
            "",
            "Wall ns the core loops slept idle",
            o.idle_sleep_ns,
        );
        for (name, desc, v) in [
            (
                "loop_busy_iters",
                "Core loop iterations that did work",
                o.loop_busy_iters,
            ),
            (
                "loop_idle_iters",
                "Core loop iterations that found no work (spins and idle sleeps)",
                o.loop_idle_iters,
            ),
            (
                "loop_busy_ns",
                "Wall ns of the working core loop iterations (/ client ops = useful ns per op; idle spinning excluded)",
                o.loop_busy_ns,
            ),
            (
                "knet_wake_writes",
                "eventfd writes (wake syscalls) cross-core senders issued to sleeping cores",
                o.wake_writes,
            ),
        ] {
            a.ctr(name, PRIO_USEFUL, none, "", desc, v);
        }
        a.ctr(
            "knet_mesh_wakes",
            PRIO_USEFUL,
            none,
            "",
            "Idle sleeps ended by a cross-core message poke",
            o.mesh_wakes,
        );
        a.ctr(
            "knet_mesh_wake_ns",
            PRIO_USEFUL,
            none,
            "",
            "Summed ns from a cross-core poke to the woken core running (wake cost; / knet_mesh_wakes = mean)",
            o.mesh_wake_ns,
        );
        for (name, desc, v) in [
            (
                "knet_enters_poll",
                "io_uring_enter calls of the net poll (start + re-reap passes: queued requests + socket task work)",
                o.ring_enters_poll,
            ),
            (
                "knet_enters_submit",
                "io_uring_enter calls at the end of a loop iteration (requests queued by it)",
                o.ring_enters_submit,
            ),
            (
                "knet_enters_sf",
                "io_uring_enter calls of send-first window closes (repops of a held-back local txn; adr 0008 am. 3)",
                o.ring_enters_sf,
            ),
            (
                "knet_enters_wait",
                "io_uring_enter calls of idle sleeps",
                o.ring_enters_wait,
            ),
        ] {
            a.ctr(name, PRIO_USEFUL, none, "", desc, v);
        }
        // RDMA transport (only with `flashstore_rdma`): coverage, outcomes and stalls; the session count is a gauge
        if let Some(p) = self.ctl.rdma {
            let r = &o.rdma;
            for (name, desc, v) in [
                (
                    "rdma_upgraded",
                    "Connections that continued over RDMA",
                    r.upgraded,
                ),
                (
                    "rdma_declined",
                    "Upgrades that did not happen (no queue pair, GID mismatch, peer decline): the connection stayed on TCP",
                    r.declined,
                ),
                (
                    "rdma_faulted",
                    "RDMA sessions that ended by a transport fault (they reconnect over TCP)",
                    r.faulted,
                ),
                (
                    "rdma_sessions_capped",
                    "Connections that stayed on TCP because flashstore_rdma_max_sessions or the receive pool was full",
                    r.sessions_capped,
                ),
                (
                    "rdma_credit_stalls",
                    "Sends refused for lack of peer receive credits",
                    r.credit_stalls,
                ),
                (
                    "rdma_queue_stalls",
                    "Sends refused for a full send queue or no free send slot",
                    r.queue_stalls,
                ),
                (
                    "rdma_credit_stall_ns",
                    "Time RDMA sessions spent blocked on peer receive credits (ns, summed over sessions; poll-loop resolution)",
                    r.credit_stall_ns,
                ),
                (
                    "rdma_grants_demand",
                    "Credit lends to credit-blocked RDMA sessions on arrival of their data",
                    r.grants_demand,
                ),
                (
                    "rdma_idle_decays",
                    "RDMA sessions whose credit window fell back to the minimum after idling",
                    r.idle_decays,
                ),
                (
                    "rdma_close_fence_timeouts",
                    "Graceful closes of RDMA sessions that ran into the linger limit",
                    r.close_fence_timeouts,
                ),
                (
                    "rdma_zc_bytes",
                    "Bytes sent over RDMA zero copy from the registered payload heap",
                    r.zc_bytes,
                ),
                (
                    "rdma_zc_misses",
                    "Large output chunks copied because they lie outside the registered payload heap",
                    r.zc_misses,
                ),
                (
                    "rdma_tx_bytes",
                    "Stream bytes sent over RDMA SENDs",
                    r.tx_bytes,
                ),
                (
                    "rdma_tx_sends",
                    "RDMA SEND work requests carrying stream bytes (small chunks are packed into shared SENDs)",
                    r.tx_sends,
                ),
                (
                    "rdma_tx_chunks",
                    "Output chunks completely taken by RDMA SENDs (rdma_tx_sends / rdma_tx_chunks: SENDs per chunk)",
                    r.tx_chunks,
                ),
                (
                    "rdma_tx_doorbells",
                    "ibv_post_send calls on the RDMA send queues (SEND lists, WRITE and local window operations)",
                    r.tx_doorbells,
                ),
                (
                    "rdma_tx_write_wrs",
                    "Accepted RDMA WRITE work requests; excludes SEND and local window operations.",
                    r.tx_write_wrs,
                ),
                (
                    "rdma_tx_write_bytes",
                    "Bytes covered by accepted WRITE requests; excludes rejected posts and SEND bytes.",
                    r.tx_write_bytes,
                ),
                (
                    "rdma_tx_write_doorbells",
                    "WRITE provider post calls, including failed calls; no call is made on SQ admission refusal.",
                    r.tx_write_doorbells,
                ),
                (
                    "rdma_tx_write_sq_stalls",
                    "WRITE admission refusals because the shared SQ is full; counts calls, not stall intervals.",
                    r.tx_write_sq_stalls,
                ),
                (
                    "rdma_rx_doorbells",
                    "ibv_post_srq_recv calls (doorbells) re-posting receive slots, one per list",
                    r.rx_doorbells,
                ),
                (
                    "rdma_wakes",
                    "Completion channel wake-ups of idle RDMA cores",
                    r.wakes,
                ),
                (
                    "rdma_rx_post_failures",
                    "Receive re-posts that lost slots (ibv_post_srq_recv failed): the core's sessions fault; must stay 0",
                    r.rx_post_failures,
                ),
                (
                    "rdma_cq_errors",
                    "ibv_poll_cq errors: the core's sessions fault; must stay 0",
                    r.cq_errors,
                ),
                (
                    "rdma_rx_withheld",
                    "Receive slots withheld at a detach because a lend still covered them (owner bug); must stay 0",
                    r.rx_withheld,
                ),
                (
                    "rdma_rx_held",
                    "RDMA receive slots held (no credit returned) because the OSD could not take input (memory envelope)",
                    r.rx_held,
                ),
                (
                    "rdma_leaked_cores",
                    "Verbs cores left allocated because a retire was not confirmed (process-wide, not reset); must stay 0",
                    p[0],
                ),
                (
                    "rdma_teardown_failures",
                    "CQ / SRQ destroys refused at a core teardown (process-wide, not reset); must stay 0",
                    p[1],
                ),
                (
                    "rdma_qp_drain_timeouts",
                    "QPs without a last-WQE event after their move to ERR, kept with their slots and credits (process-wide, not reset); must stay 0",
                    p[2],
                ),
                (
                    "rdma_quarantined_windows",
                    "Type-2 placement windows whose retirement was uncertain; memory retained (process-wide, not reset); must stay 0",
                    p[3],
                ),
                (
                    "rdma_quarantined_write_sources",
                    "Registered placement WRITE sources with uncertain completion; memory retained (process-wide, not reset); must stay 0",
                    p[4],
                ),
            ] {
                a.ctr(name, PRIO_USEFUL, none, "", desc, v);
            }
            a.gauge(
                "rdma_sessions",
                PRIO_USEFUL,
                none,
                "RDMA sessions carrying connections now",
                all.rdma_sessions,
            );
        }
        // repop credits between croit-flashstore-osd peers (adr 0084): detection only, no expiry
        a.gauge(
            "repop_credit_blocked_lanes",
            PRIO_USEFUL,
            none,
            "Peer shard lanes with sub-writes waiting for repop credit",
            all.credit_blocked_lanes,
        );
        a.gauge(
            "repop_credit_oldest_ms",
            PRIO_USEFUL,
            none,
            "Age of the oldest repop credit still out (ms); grows without bound only if a credit leaked",
            all.credit_oldest_ms,
        );
        // scrub (classic names in the osd logger, replicated pools; shallow + deep together)
        a.ctr(
            "num_scrubs_started_replicated",
            PRIO_DEBUGONLY,
            none,
            "",
            "replicated scrubs attempted count",
            o.scrub.started,
        );
        a.ctr(
            "successful_scrubs_replicated",
            PRIO_DEBUGONLY,
            none,
            "",
            "successful replicated scrubs count",
            o.scrub.ok,
        );
        a.avg(
            "successful_scrubs_replicated_elapsed",
            PRIO_DEBUGONLY,
            "",
            "time to complete a successful replicated scrub",
            o.scrub.ok_elapsed,
        );
        a.ctr(
            "failed_scrubs_replicated",
            PRIO_DEBUGONLY,
            none,
            "",
            "failed replicated scrubs count",
            o.scrub.failed,
        );
        a.avg(
            "failed_scrubs_replicated_elapsed",
            PRIO_DEBUGONLY,
            "",
            "time to scrub failure replicated",
            o.scrub.failed_elapsed,
        );

        a.ctr(
            "read_repair",
            PRIO_DEBUGONLY,
            none,
            "",
            "Client ops that waited for the repair of a damaged local object",
            o.read_repair,
        );
        a.ctr(
            "obj_cache_hit",
            PRIO_DEBUGONLY,
            none,
            "",
            "Client ops whose object state came from the object-state cache",
            o.obj_cache_hit,
        );
        a.ctr(
            "obj_cache_miss",
            PRIO_DEBUGONLY,
            none,
            "",
            "Client ops whose object state was loaded from the store with the object-state cache on",
            o.obj_cache_miss,
        );
        a.ctr(
            "gate_probe",
            PRIO_DEBUGONLY,
            none,
            "",
            "Gated client ops a store wake probed again",
            o.gate_probe,
        );
        a.ctr(
            "gate_skip",
            PRIO_DEBUGONLY,
            none,
            "",
            "Gated client ops a store wake left alone (it did not name their cause)",
            o.gate_skip,
        );
        a.ctr(
            "late_held",
            PRIO_DEBUGONLY,
            none,
            "",
            "Client writes whose local txn was held back until their repops left the core (send-first)",
            o.late_held,
        );
        a.ctr(
            "late_driver",
            PRIO_DEBUGONLY,
            none,
            "",
            "Held-back local txns applied by the driver after it moved the repops (the rest ran earlier, repops queued behind them)",
            o.late_driver,
        );
        a.ctr(
            "gate_direct",
            PRIO_DEBUGONLY,
            none,
            "",
            "Gated replicated reads a store wake ran without probing again (their named cause arrived)",
            o.gate_direct,
        );
        a.ctr(
            "list_deferred",
            PRIO_DEBUGONLY,
            none,
            "",
            "Listing continuations the PG-core share left for the next loop iteration (adr 0522)",
            o.list_deferred,
        );
        a.ctr(
            "shards_repaired",
            PRIO_DEBUGONLY,
            none,
            "",
            "Damaged local objects repaired from a peer",
            o.shards_repaired,
        );

        // bluestore: space + commit/read latencies the dashboards and ceph-exporter read (mapping: spec 2c)
        a.logger(self.store.as_str());
        let o_bs = self.since_for(self.store.as_str());
        let o = &o_bs;
        a.gauge(
            "allocated",
            PRIO_CRITICAL,
            bytes,
            "Sum for allocated bytes",
            s.allocated.max(0) as u64,
        );
        a.gauge(
            "stored",
            PRIO_CRITICAL,
            bytes,
            "Sum for stored bytes (the store keeps no logical-bytes counter: equals allocated)",
            s.data_stored.max(0) as u64,
        );
        a.gauge(
            "omap_bytes",
            PRIO_INTERESTING,
            bytes,
            "Sum of bytes in OMAPs",
            self.ctl.omap_allocated,
        );
        a.gauge(
            "compressed",
            PRIO_USEFUL,
            bytes,
            "Sum for stored compressed bytes",
            s.data_compressed.max(0) as u64,
        );
        a.gauge(
            "compressed_allocated",
            PRIO_USEFUL,
            bytes,
            "Sum for bytes allocated for compressed data",
            s.data_compressed_allocated.max(0) as u64,
        );
        a.gauge(
            "compressed_original",
            PRIO_USEFUL,
            bytes,
            "Sum for original bytes that were compressed",
            s.data_compressed_original.max(0) as u64,
        );
        a.ctr(
            "compress_success_count",
            PRIO_USEFUL,
            none,
            "",
            "Sum for beneficial compress ops",
            o.comp_ok,
        );
        a.ctr(
            "compress_rejected_count",
            PRIO_USEFUL,
            none,
            "",
            "Sum for compress ops rejected due to low net gain of space",
            o.comp_rejected,
        );
        a.ctr(
            "compress_skipped_count",
            PRIO_USEFUL,
            none,
            "",
            "Chunks not compressed: the incompressibility sample ruled them out (croit-flashstore-osd)",
            o.comp_sampled_out,
        );
        a.ctr(
            "gc_merged",
            PRIO_USEFUL,
            none,
            "",
            "Sum for extents that have been merged due to garbage collection",
            o.comp_gc,
        );
        a.ctr(
            "flashstore_staged_bytes",
            PRIO_DEBUGONLY,
            bytes,
            "",
            "Data bytes copied into device buffers by the store (croit-flashstore-osd)",
            o.store_staged_bytes,
        );
        a.ctr(
            "flashstore_zc_bytes",
            PRIO_DEBUGONLY,
            bytes,
            "",
            "Payload bytes written to the device by reference, no copy (croit-flashstore-osd)",
            o.store_zc_bytes,
        );
        a.ctr(
            "flashstore_crc_reused_bytes",
            PRIO_DEBUGONLY,
            bytes,
            "",
            "Data bytes whose block crcs came from the receive pass (croit-flashstore-osd)",
            o.store_crc_reused_bytes,
        );
        a.ctr(
            "flashstore_placement_crc_reblocked_bytes",
            PRIO_DEBUGONLY,
            bytes,
            "",
            "Placement bytes covered by shifted receipt CRC grids (croit-flashstore-osd)",
            o.store_placement_crc_reblocked_bytes,
        );
        a.ctr(
            "flashstore_placement_crc_hashed_bytes",
            PRIO_DEBUGONLY,
            bytes,
            "",
            "Actual source bytes hashed for shifted receipt CRCs, including edges (croit-flashstore-osd)",
            o.store_placement_crc_hashed_bytes,
        );
        a.ctr(
            "flashstore_probe_refused_admission",
            PRIO_DEBUGONLY,
            none,
            "",
            "Op gate store probes refused: the PG store shard had no admission headroom (croit-flashstore-osd)",
            o.probe_refused_admission,
        );
        a.ctr(
            "flashstore_probe_refused_obj",
            PRIO_DEBUGONLY,
            none,
            "",
            "Op gate store probes refused: an object metadata page was loading (croit-flashstore-osd)",
            o.probe_refused_obj,
        );
        a.ctr(
            "flashstore_probe_refused_log",
            PRIO_DEBUGONLY,
            none,
            "",
            "Op gate store probes refused: the PG log page was loading (croit-flashstore-osd)",
            o.probe_refused_log,
        );
        a.ctr(
            "flashstore_probe_refused_data",
            PRIO_DEBUGONLY,
            none,
            "",
            "Op gate store probes refused: a data block was being read (croit-flashstore-osd)",
            o.probe_refused_data,
        );
        a.avg(
            "compress_lat",
            PRIO_USEFUL,
            "cmpl",
            "Average compress latency per chunk (sample included)",
            o.comp_lat,
        );
        a.avg(
            "decompress_lat",
            PRIO_USEFUL,
            "dcpl",
            "Average decompress latency per chunk read",
            o.decomp_lat,
        );
        a.gauge(
            "alloc_unit",
            PRIO_CRITICAL,
            bytes,
            "allocation unit size in bytes",
            ALLOC_UNIT,
        );
        a.avg(
            "txc_commit_lat",
            PRIO_CRITICAL,
            "c_l",
            "Average commit latency (store transaction submit to durable)",
            o.store_lat,
        );
        a.ctr(
            "txc_count",
            PRIO_DEBUGONLY,
            none,
            "",
            "Transactions committed",
            o.store_lat.n,
        );
        a.avg(
            "kv_commit_lat",
            PRIO_USEFUL,
            "kcol",
            "Average commit latency of the WAL write (= txc_commit_lat: no separate KV thread)",
            o.store_lat,
        );
        a.avg(
            "kv_sync_lat",
            PRIO_INTERESTING,
            "kscl",
            "Average durable-sync latency (= txc_commit_lat: one durable step)",
            o.store_lat,
        );
        a.avg(
            "read_lat",
            PRIO_CRITICAL,
            "r_l",
            "Average client read operation latency (the store keeps no separate read timer)",
            o.r_lat,
        );
        a.ctr(
            "read_eio",
            PRIO_DEBUGONLY,
            none,
            "",
            "Read EIO errors propagated to high level callers",
            o.read_eio,
        );
        a.ctr(
            "ec_direct_reads",
            PRIO_DEBUGONLY,
            none,
            "",
            "EC_DIRECT_READ ops served from the local shard",
            o.ec_direct_reads,
        );
        a.ctr(
            "ec_direct_eagain",
            PRIO_DEBUGONLY,
            none,
            "",
            "EC_DIRECT_READ ops answered EAGAIN (client redrives through the primary)",
            o.ec_direct_eagain,
        );

        // recoverystate_perf: time per PG state visit (the states with a state bit)
        a.logger("recoverystate_perf");
        let o_rs = self.since_for("recoverystate_perf");
        let o = &o_rs;
        for (i, (n, _)) in crate::perfx::RS.iter().enumerate() {
            a.avg(
                n,
                PRIO_DEBUGONLY,
                "",
                "Time spent in the recovery state (sampled once a second)",
                o.rs[i],
            );
        }

        // 21.2.0 vulnerability/rebuild duration counters (delta spec B3, peering.md 9.6): one sample per closed window /
        // rebuild episode of a primary PG (rebuild = active Recovering/Backfilling time only); min = smallest non-zero
        // sample over all cores, 0 until the first. The classic per-sample `max` is not served.
        for (n, nmin, d, dmin, v) in [
            (
                "pg_vulnerability_duration",
                "pg_vulnerability_duration_min",
                "Time a PG was vulnerable (degraded, undersized or with degraded/misplaced objects) before it became clean again",
                "Smallest non-zero PG vulnerability duration",
                o.latch.vulnerability,
            ),
            (
                "pg_rebuild_duration",
                "pg_rebuild_duration_min",
                "Active Recovering/Backfilling time of a rebuild episode",
                "Smallest non-zero PG rebuild duration",
                o.latch.rebuild,
            ),
        ] {
            a.avg(
                n,
                PRIO_USEFUL,
                "",
                d,
                Avg {
                    sum_ns: v.sum_ns,
                    n: v.n,
                },
            );
            a.put(
                nmin,
                pct::TIME,
                PRIO_USEFUL,
                pct::UNIT_NONE,
                "",
                dmin,
                cv(v.min_ns),
            );
        }

        // Client op throttles: the ENFORCED numbers (adr 0175: the client ingress pool is the throttle; there is no
        // dispatch queue). `val` = messages in flight (one frame slot each) and their write payload, `max` = the frame
        // slots / byte limit of the client pool. The operator knobs `osd_client_message_cap` / `_size_cap` are per-link
        // admission thresholds (`tell::client_throttle_note`), not this aggregate.
        for (lg, max, val) in [
            (
                "throttle-osd_client_messages",
                self.ctl.client_frames,
                all.wip,
            ),
            (
                "throttle-osd_client_bytes",
                self.ctl.client_pool_bytes,
                all.inflight_bytes,
            ),
        ] {
            let since = self.since_for(lg);
            let o = &since;
            let started = o.op + all.wip;
            let sum = if lg.ends_with("messages") {
                started
            } else {
                o.op_in + all.inflight_bytes
            };
            let (puts, put_sum) = if lg.ends_with("messages") {
                (o.op, o.op)
            } else {
                (o.op, o.op_in)
            };
            a.logger(lg);
            a.gauge(
                "val",
                PRIO_DEBUGONLY,
                none,
                "Messages in flight and their payload (enforced by the client ingress pool)",
                val,
            );
            a.gauge(
                "max",
                PRIO_DEBUGONLY,
                none,
                "Enforced bound: client pool frame slots / bytes",
                max,
            );
            a.ctr(
                "get_started",
                PRIO_DEBUGONLY,
                none,
                "",
                "Number of get calls",
                started,
            );
            a.ctr("get", PRIO_DEBUGONLY, none, "", "Gets", started);
            a.ctr("get_sum", PRIO_DEBUGONLY, none, "", "Got data", sum);
            a.ctr("put", PRIO_DEBUGONLY, none, "", "Puts", puts);
            a.ctr("put_sum", PRIO_DEBUGONLY, none, "", "Put data", put_sum);
        }
    }

    /// `perf histogram dump|schema [logger] [counter]`: the 2-D latency x size histograms of logger `osd`.
    pub(crate) fn histograms(
        &self,
        schema: bool,
        logger: Option<&str>,
        counter: Option<&str>,
    ) -> Value {
        if logger.is_some_and(|l| !l.is_empty() && l != "osd") {
            return json!({});
        }
        let (_, o) = self.op_perf();
        let axes = json!([
            hist_axis("Latency (usec)", LAT_QUANT),
            hist_axis("Request size (bytes)", SIZE_QUANT)
        ]);
        let mut osd = serde_json::Map::new();
        for (name, desc, h) in [
            (
                "op_r_latency_out_bytes_histogram",
                "Histogram of operation latency (including queue time) + data read",
                &o.h_r_out,
            ),
            (
                "op_w_latency_in_bytes_histogram",
                "Histogram of operation latency (including queue time) + data written",
                &o.h_w_in,
            ),
            (
                "op_rw_latency_in_bytes_histogram",
                "Histogram of rw operation latency (including queue time) + data written",
                &o.h_rw_in,
            ),
            (
                "op_rw_latency_out_bytes_histogram",
                "Histogram of rw operation latency (including queue time) + data read",
                &o.h_rw_out,
            ),
        ] {
            if counter.is_some_and(|c| !c.is_empty() && c != name) {
                continue;
            }
            let v = if schema {
                json!({"type": pct::U64 | pct::HISTOGRAM, "metric_type": "gauge", "value_type": "histogram",
                    "description": desc, "nick": "", "priority": 5, "units": "none"})
            } else {
                json!({"axes": axes, "values": h.0})
            };
            osd.insert(name.to_owned(), v);
        }
        json!({ "osd": osd })
    }
}

impl<B: Backend> Osd<B> {
    /// A store txn became durable `el` ns after its submit: commit latency; a slow one feeds the slow-op alert window.
    pub(crate) fn store_commit_done(&mut self, el: u64, now: u64) {
        self.perf.op.store_lat.add(el);
        // No floor below `bluestore_log_op_age`: an operator lowering the threshold below 1 s must still see short
        // stalls. The per-commit `slow store commit` log is already rate-limited (`slow_ops_note`, one line per 10 s),
        // so no log flood follows from counting every sub-second slow commit.
        if el as f64 >= self.conf.f64("bluestore_log_op_age", 5.0) * 1e9 {
            let life = self
                .conf
                .u64("bluestore_slow_ops_warn_lifetime", 86400)
                .saturating_mul(1_000_000_000);
            self.perf.slow_win.push(now, life);
            self.perf.slow_commits += 1;
            self.perf.slow_commit_worst_ns = self.perf.slow_commit_worst_ns.max(el);
        }
    }

    /// A client op got its reply: account it (counters, history). Only a successful reply moves a counter (spec
    /// ops-observability.md 2d); the tracker record still closes and keeps the failed op in the history.
    pub(crate) fn op_done(
        &mut self,
        conn: u64,
        tid: u64,
        class: opwire::OpClass,
        reply: &opwire::MOSDOpReply,
    ) {
        let now = self.now.as_nanos() as u64;
        let outb: u64 = reply.ops.iter().map(|o| o.outdata_len() as u64).sum();
        // Disabling tracking stops admission of new records; a record admitted before the
        // config change must still close when its reply arrives.
        let done = self.tracker.finish(conn, tid, now, outb, reply.result);
        if reply.result >= 0 {
            match &done {
                Some(d) => self.perf.op.client_done(class, d.inb, outb, d.lat),
                // untracked: op and out-bytes only (no in-bytes, class bucket, latency or history without a record)
                None => {
                    self.perf.op.op += 1;
                    self.perf.op.op_out += outb;
                }
            }
        }
        // a failed store read is counted with or without a tracker record: the request's op codes say it read, and a
        // device EIO storm must reach `bluestore.read_eio` / the alert window whatever `osd_enable_op_tracker` says
        if reply.result == -denc::errno::EIO && class.read && store_read_failed(reply) {
            self.perf.op.read_eio += 1;
            let now = self.mnow().as_nanos() as u64;
            let life = self
                .conf
                .u64("flashstore_read_errors_warn_lifetime", 86400)
                .saturating_mul(1_000_000_000);
            self.perf.eio_win.push(now, life);
        }
        if let Some(d) = done
            && self.log_level >= 20
        {
            self.logl(
                20,
                format!(
                    "op {conn}:{tid} done in {} us, result {}",
                    d.lat / 1000,
                    reply.result
                ),
            );
        }
    }

    /// A PG message from a peer arrived on this PG core (sub-op counters).
    pub(crate) fn sub_in(&mut self, body: &peering::Body) {
        use replwire::ReplMsg;
        if let peering::Body::Ec(e) = body {
            // EC shard role: sub-writes count like replicated sub-ops (no per-op latency: replies carry no reqid)
            let p = &mut self.perf;
            p.op.subop += 1;
            if let ecwire::EcMsg::Write(w) = e {
                let n = (w.op.txn_data.len() + w.op.txn_middle.len()) as u64;
                p.op.subop_in += n;
                p.op.subop_w += 1;
                p.op.subop_w_in += n;
            }
            return;
        }
        let peering::Body::Repl(m) = body else { return };
        let now = self.now.as_nanos() as u64;
        let p = &mut self.perf;
        match m {
            ReplMsg::RepOp(r) => {
                let n = (r.txn_data.len() + r.txn_middle.len()) as u64;
                p.op.subop += 1;
                p.op.subop_in += n;
                p.op.subop_w += 1;
                p.op.subop_w_in += n;
                if p.sub_start.len() >= 8192 {
                    p.sub_start.clear(); // replies that never came: bounded
                }
                p.sub_start.insert(
                    (
                        r.pgid.pgid.pool,
                        r.pgid.pgid.seed,
                        r.reqid.name.num,
                        r.reqid.tid,
                    ),
                    now,
                );
            }
            ReplMsg::Push(x) => {
                p.op.subop_push += 1;
                p.op.subop_push_in += x.pushes.iter().map(|o| o.data.len() as u64).sum::<u64>();
            }
            ReplMsg::Pull(_) => p.op.subop_pull += 1,
            _ => {}
        }
    }

    /// A PG message leaves this PG core (sub-op latency, recovery counters).
    pub(crate) fn sub_out(&mut self, body: &peering::Body) {
        use replwire::ReplMsg;
        let peering::Body::Repl(m) = body else { return };
        let now = self.now.as_nanos() as u64;
        let p = &mut self.perf;
        match m {
            ReplMsg::RepOpReply(r) => {
                if let Some(t) = p.sub_start.remove(&(
                    r.pgid.pgid.pool,
                    r.pgid.pgid.seed,
                    r.reqid.name.num,
                    r.reqid.tid,
                )) {
                    let l = now.saturating_sub(t);
                    p.op.subop_lat.add(l);
                    p.op.subop_w_lat.add(l);
                }
            }
            ReplMsg::Push(x) => {
                let n: u64 = x.pushes.iter().map(|o| o.data.len() as u64).sum();
                p.op.push += 1;
                p.op.push_out += n;
                p.op.recovery_ops += x.pushes.len() as u64;
                p.op.recovery_bytes += n;
            }
            ReplMsg::Pull(x) => {
                p.op.pull += 1;
                p.op.recovery_ops += x.pulls.len() as u64;
            }
            _ => {}
        }
    }

    /// Log (every 10 s) while ops are older than `osd_op_complaint_time`, and the slow store commits of the
    /// interval as one line (count, worst latency), so a sustained store slowdown cannot flood the log.
    pub(crate) fn slow_ops_note(&mut self) {
        if self.perf.slow_commits > 0
            && self.now.saturating_sub(self.perf.last_slow_commit_log)
                >= std::time::Duration::from_secs(10)
        {
            self.perf.last_slow_commit_log = self.now;
            let (n, worst) = (
                std::mem::take(&mut self.perf.slow_commits),
                std::mem::take(&mut self.perf.slow_commit_worst_ns),
            );
            self.log(format!(
                "slow store commit: {n} commits slower than bluestore_log_op_age, worst {} ms",
                worst / 1_000_000
            ));
        }
        let (n, oldest) = self.slow_ops();
        if n > 0
            && self.now.saturating_sub(self.perf.last_slow_log)
                >= std::time::Duration::from_secs(10)
        {
            self.perf.last_slow_log = self.now;
            self.log(format!(
                "{n} slow ops on this core, oldest blocked for {} s (osd_op_complaint_time {} s)",
                oldest / 1_000_000_000,
                self.tracker.lim.complaint_ns / 1_000_000_000
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scrub load gate needs the host's 1-minute load average (per online CPU) on every platform the daemon
    /// builds for, not the Linux-only `/proc` file the perf counter used.
    #[test]
    fn host_load_average_and_cpu_count_are_readable() {
        assert!(online_cpus() >= 1);
        assert!(load_average_1m().is_none_or(|l| l >= 0.0));
    }

    #[test]
    fn latch_durations_merge_over_cores_and_reset_keeps_min() {
        let core = |ns: &[u64]| {
            let mut p = OpPerf::default();
            for n in ns {
                p.latch.record(peering::LatchKind::Vulnerability, *n);
            }
            p.latch.record(peering::LatchKind::Rebuild, 7);
            p
        };
        let mut all = core(&[5, 9]);
        all.merge(&core(&[3]));
        all.merge(&OpPerf::default());
        let v = all.latch.vulnerability;
        assert_eq!((v.n, v.sum_ns, v.min_ns), (3, 17, 3));
        assert_eq!((all.latch.rebuild.n, all.latch.rebuild.min_ns), (2, 7));
        let mut later = all;
        later.latch.record(peering::LatchKind::Vulnerability, 4);
        let r = later.since(&all).latch.vulnerability;
        assert_eq!(
            (r.n, r.sum_ns, r.min_ns),
            (1, 4, 3),
            "reset restarts the average, the min gauge stays"
        );
    }

    #[test]
    fn client_done_classifies() {
        use opwire::OpClass;
        let rd = OpClass {
            read: true,
            write: false,
        };
        let wr = OpClass {
            read: false,
            write: true,
        };
        let rw = OpClass {
            read: true,
            write: true,
        };
        let mut p = OpPerf::default();
        p.client_done(wr, 4096, 0, 1_000);
        p.client_done(rd, 0, 512, 2_000);
        p.client_done(rw, 10, 20, 3_000);
        assert_eq!((p.op, p.op_w, p.op_r, p.op_rw), (3, 1, 1, 1));
        assert_eq!((p.op_in, p.op_out), (4106, 532));
        assert_eq!(
            p.lat,
            Avg {
                sum_ns: 6_000,
                n: 3
            }
        );
        assert_eq!(p.w_lat.n, 1);
        // a request without a class is counted nowhere
        p.client_done(OpClass::default(), 1, 1, 1);
        assert_eq!((p.op, p.op_in, p.op_out, p.lat.n), (3, 4106, 532, 3));
        let mut q = OpPerf::default();
        q.merge(&p);
        q.merge(&p);
        assert_eq!(q.op, 6);
        assert_eq!(q.since(&p).op, 3);
    }

    #[test]
    fn histogram_buckets_and_dump_shape() {
        assert_eq!(bucket(0, 100_000), 1);
        assert_eq!(bucket(99_999, 100_000), 1);
        assert_eq!(bucket(100_000, 100_000), 2);
        assert_eq!(bucket(199_999, 100_000), 2);
        assert_eq!(bucket(200_000, 100_000), 3);
        assert_eq!(bucket(u64::MAX, 100_000), 31);
        let mut p = OpPerf::default();
        p.client_done(
            opwire::OpClass {
                read: false,
                write: true,
            },
            4096,
            0,
            250_000,
        );
        assert_eq!(p.h_w_in.0[3][bucket(4096, 512)], 1);
        assert_eq!(p.h_r_out.0.iter().flatten().sum::<u64>(), 0);
        let mut q = OpPerf::default();
        q.merge(&p);
        q.merge(&p);
        assert_eq!(q.since(&p).h_w_in.0[3][bucket(4096, 512)], 1);
        let a = hist_axis("x", 512);
        assert_eq!(a["ranges"][0], json!({"max": -1}));
        assert_eq!(a["ranges"][1], json!({"min": 0, "max": 511}));
        assert_eq!(a["ranges"][2], json!({"min": 512, "max": 1023}));
        assert_eq!(a["ranges"][31], json!({"min": 512u64 << 29}));
        assert_eq!(a["ranges"].as_array().unwrap().len(), 32);
    }
}

/// An EIO reply counts as a store read error unless the op that failed was an object-class call: classes return EIO on their own
/// (corrupt rgw/fifo values, ...), classic `bluestore.read_eio` only counts device/checksum errors.
fn store_read_failed(reply: &opwire::MOSDOpReply) -> bool {
    match reply.ops.iter().find(|o| o.rval < 0) {
        Some(o) => o.op != opwire::op::CALL,
        None => true,
    }
}

#[cfg(test)]
mod eio_tests {
    use super::*;

    fn rep(ops: &[(u16, i32)]) -> opwire::MOSDOpReply {
        let mut r = opwire::MOSDOpReply::default();
        for &(op, rval) in ops {
            r.ops.push(opwire::OsdOp {
                op,
                rval,
                ..Default::default()
            });
        }
        r
    }

    #[test]
    fn class_call_eio_is_no_store_read_error() {
        let e = -denc::errno::EIO;
        assert!(store_read_failed(&rep(&[(opwire::op::READ, e)])));
        assert!(store_read_failed(&rep(&[])));
        assert!(!store_read_failed(&rep(&[(opwire::op::CALL, e)])));
        assert!(store_read_failed(&rep(&[
            (opwire::op::CALL, 0),
            (opwire::op::READ, e)
        ])));
    }
}
