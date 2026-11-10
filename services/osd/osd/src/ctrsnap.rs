// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Admin counter dumps off the cores (adr 0035 am. 3). Every core publishes its counters once a second as an immutable
//! sample ([`CoreCounters`]: workers inside their [`crate::xcore::CoreStats`], the control core at its own tick, which
//! adds the OSD aggregates, [`ControlCounters`]). A `perf dump`, `counter dump`, `perf schema`, `counter schema` or
//! `perf histogram` request costs the control core one [`CounterSnap`]: an `Arc` clone per core, whatever the number of
//! PGs and counters. The catalogue (names, types, descriptions), the per-PG names and the JSON are built from the
//! snapshot by the admin socket thread that answers ([`CounterReq::render`]); nothing walks the store per request.
//!
//! Values are the cores' last samples (at most one tick old, like every other core's values before); `perf reset` and
//! `flush_pg_stats` resample the control core first.
use crate::backend::Backend;
use crate::osd::Osd;
use crate::perf::OpPerf;
use crate::utilization::{HoldWhy, Utilization};
use denc::types::SpgT;
use messages::{CounterValue, pct};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use std::borrow::Cow;
use std::sync::Arc;

/// One core's counters at its last sample.
#[derive(Debug, Default)]
pub struct CoreCounters {
    /// Cumulative op counters + slow-op gauges (perf.rs).
    pub perf: OpPerf,
    pub util: Utilization,
    pub pg_util: Vec<(SpgT, Utilization)>,
    /// Store checkpoint / back-pressure counters of the core's shards (adr 0021 am. 43; `flashstore_store_N`).
    pub store: Vec<(&'static str, bool, u64)>,
}

/// Control core aggregates at its last sample: the gauges of the `osd`, `bluestore` and throttle loggers that are not
/// per core.
#[derive(Debug, Default)]
pub(crate) struct ControlCounters {
    pub statfs: messages::StoreStatfs,
    pub omap_allocated: u64,
    /// `(PGs, primary, replica)`.
    pub roles: (u64, u64, u64),
    /// `(PGs queued for deletion, objects left, objects deleted, objects/s)`.
    pub removal: (u64, u64, u64, u64),
    pub heartbeat_to_peers: u64,
    pub map_messages: u64,
    pub map_message_epochs: u64,
    /// Process-wide RDMA teardown outcomes when `flashstore_rdma` is on: leaked cores, teardown failures, QP drain timeouts,
    /// quarantined windows, quarantined write sources.
    pub rdma: Option<[u64; 5]>,
    /// Enforced client message bound: frame slots of the client ingress pool (one per in-flight client message).
    pub client_frames: u64,
    /// Enforced client byte bound: byte limit of the client ingress pool (`Envelope::pool`, adr 0175).
    pub client_pool_bytes: u64,
    /// Merge moves deferred for lack of headroom, PGs waiting (adr 0031 am. 4).
    pub mig: (u64, u64),
    /// Host 1-minute load average x 100 (`osd` logger `loadavg`).
    pub loadavg_x100: u64,
    /// Process-wide payload and DMA pool counters (`flashstore_payload_pool`, `flashstore_dma_pool`).
    pub pools: [(&'static str, crate::NamedCounters); 2],
}

/// The samples of every core (index = core); `None` = no sample yet.
pub(crate) type CoreSamples = Arc<[Option<Arc<CoreCounters>>]>;

type DiagnosticBaselines =
    std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>>;

/// Input of one counter dump.
#[derive(Clone, Debug)]
pub(crate) struct CounterSnap {
    pub cores: CoreSamples,
    pub ctl: Arc<ControlCounters>,
    /// The samples at the last `perf reset` of each logger: counters report `current - reset` (gauges are unaffected).
    pub reset: Option<ResetBaselines>,
    /// The store name the `bluestore`-identity logger carries (`flashstore_report_objectstore`).
    pub store: crate::storeid::StoreIdentity,
}

/// `perf reset` baselines: one snapshot per logger, so resetting one logger leaves the others running (`all` = a
/// snapshot that applies to every logger not reset on its own since).
#[derive(Clone, Debug, Default)]
pub(crate) struct ResetBaselines {
    all: Option<CoreSamples>,
    per: Vec<(String, CoreSamples)>,
    /// Raw diagnostic counters at each logger's reset. Gauges have no baseline.
    diagnostics: Arc<DiagnosticBaselines>,
}

impl ResetBaselines {
    /// The baseline of `logger` (its own reset, else the last `all`).
    pub(crate) fn for_logger(&self, logger: &str) -> Option<&CoreSamples> {
        self.per
            .iter()
            .find(|(l, _)| l == logger)
            .map(|(_, s)| s)
            .or(self.all.as_ref())
    }

    /// Drop the baselines of loggers that no longer exist: their snapshot can never be subtracted again, so keeping it
    /// would grow without bound (per-PG loggers change name with every interval).
    fn retain_existing(&mut self, cat: &Catalogue) {
        self.per.retain(|(l, _)| cat.has_logger(l));
        Arc::make_mut(&mut self.diagnostics).retain(|l, _| cat.has_logger(l));
    }

    #[cfg(test)]
    /// Test hook: how many per-logger baselines are held.
    pub(crate) fn logger_count(&self) -> usize {
        self.per.len()
    }

    #[cfg(test)]
    /// Test hook: add a baseline for `logger` (a name that may not exist in the catalogue).
    pub(crate) fn insert_for_test(&mut self, logger: &str, s: CoreSamples) {
        self.per.push((logger.to_owned(), s));
    }
}

/// One counter of the catalogue.
#[derive(Clone, Debug)]
pub(crate) struct Ctr {
    pub name: Cow<'static, str>,
    pub ty: u8,
    pub prio: u8,
    pub unit: u8,
    pub nick: &'static str,
    pub desc: &'static str,
    pub v: CounterValue,
}

impl Ctr {
    /// A local diagnostic counter (no description, priority 5).
    fn diag(name: impl Into<Cow<'static, str>>, gauge: bool, v: u64) -> Ctr {
        Ctr {
            name: name.into(),
            ty: if gauge { pct::GAUGE } else { pct::COUNTER_U64 },
            prio: 5,
            unit: pct::UNIT_NONE,
            nick: "",
            desc: "",
            v: CounterValue {
                value: v,
                avgcount: 0,
                avgcount2: 0,
            },
        }
    }
}

/// Loggers in sorted order with their counters in name order, as the classic dump prints them.
pub(crate) type Sorted = Vec<(Cow<'static, str>, Vec<Ctr>)>;

/// Counters by logger, in the order they were added.
#[derive(Debug, Default)]
pub(crate) struct Catalogue {
    loggers: Vec<Cow<'static, str>>,
    ctrs: Vec<(usize, Ctr)>,
}

impl Catalogue {
    /// Start a logger; the counters pushed with the returned index belong to it. A name may come more than once.
    pub(crate) fn logger(&mut self, name: impl Into<Cow<'static, str>>) -> usize {
        self.loggers.push(name.into());
        self.loggers.len() - 1
    }

    pub(crate) fn push(&mut self, lg: usize, c: Ctr) {
        self.ctrs.push((lg, c));
    }

    /// `(logger, counter)` pairs in insertion order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &Ctr)> {
        self.ctrs.iter().map(|(lg, c)| (&*self.loggers[*lg], c))
    }

    /// Whether `name` is one of the loggers (`perf reset <name>` accepts only these).
    pub(crate) fn has_logger(&self, name: &str) -> bool {
        self.loggers.iter().any(|l| &**l == name)
    }

    /// Sorted, filtered by the optional `logger` / `counter` command arguments (empty = all); loggers without a match are
    /// left out. A `logger.name` added twice keeps the last value.
    pub(crate) fn sorted(self, logger: Option<&str>, counter: Option<&str>) -> Sorted {
        let Catalogue { loggers, ctrs } = self;
        let mut v: Vec<(usize, Ctr)> = ctrs
            .into_iter()
            .filter(|(lg, c)| {
                !(logger.is_some_and(|l| !l.is_empty() && l != loggers[*lg])
                    || counter.is_some_and(|n| !n.is_empty() && n != c.name))
            })
            .collect();
        // stable: equal names stay in insertion order, the last one wins below
        v.sort_by(|a, b| {
            loggers[a.0]
                .cmp(&loggers[b.0])
                .then_with(|| a.1.name.cmp(&b.1.name))
        });
        let mut out: Sorted = Vec::new();
        for (lg, c) in v {
            match out.last_mut() {
                Some((l, cs)) if *l == loggers[lg] => match cs.last_mut() {
                    Some(p) if p.name == c.name => *p = c,
                    _ => cs.push(c),
                },
                _ => out.push((loggers[lg].clone(), vec![c])),
            }
        }
        out
    }
}

/// One `flashstore_core_N` counter of a [`Utilization`].
type UtilField = fn(&Utilization) -> u64;
/// One field of the hold statistics of a [`HoldWhy`] (index).
type HoldField = fn(&Utilization, usize) -> u64;

/// `sum.nsec` as the classic dump prints a time value.
pub(crate) fn secs(ns: u64) -> f64 {
    ns as f64 / 1e9
}

/// Classic JSON value of one counter: `{"avgcount", "avgtime", "sum"}` for an average, seconds for a time, else the
/// integer.
struct Val<'a>(&'a Ctr);

impl Serialize for Val<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let (c, v) = (self.0, &self.0.v);
        if c.ty & pct::LONGRUNAVG != 0 {
            let mut m = s.serialize_map(Some(3))?;
            m.serialize_entry("avgcount", &v.avgcount)?;
            m.serialize_entry(
                "avgtime",
                &secs(v.value.checked_div(v.avgcount).unwrap_or(0)),
            )?;
            m.serialize_entry("sum", &secs(v.value))?;
            m.end()
        } else if c.ty & pct::TIME != 0 {
            s.serialize_f64(secs(v.value))
        } else {
            s.serialize_u64(v.value)
        }
    }
}

/// Classic schema entry of one counter (keys in the classic dump's alphabetical order).
struct Schema<'a>(&'a Ctr);

impl Serialize for Schema<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let c = self.0;
        let vt = match (c.ty & pct::LONGRUNAVG != 0, c.ty & pct::TIME != 0) {
            (true, true) => "real-integer-pair",
            (true, false) => "integer-integer-pair",
            (false, true) => "real",
            (false, false) => "integer",
        };
        let mut m = s.serialize_map(Some(7))?;
        m.serialize_entry("description", c.desc)?;
        m.serialize_entry(
            "metric_type",
            if c.ty & pct::COUNTER != 0 {
                "counter"
            } else {
                "gauge"
            },
        )?;
        m.serialize_entry("nick", c.nick)?;
        m.serialize_entry("priority", &c.prio)?;
        m.serialize_entry("type", &c.ty)?;
        m.serialize_entry(
            "units",
            if c.unit == pct::UNIT_BYTES {
                "bytes"
            } else {
                "none"
            },
        )?;
        m.serialize_entry("value_type", vt)?;
        m.end()
    }
}

/// Which counter document a request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Doc {
    /// `perf dump`: `{logger: {name: value}}`.
    PerfDump,
    /// `counter dump`: `{logger: [{"counters": {name: value}, "labels": {}}]}` (ceph-exporter reads this).
    CounterDump,
    /// `perf schema`: `{logger: {name: schema}}`.
    PerfSchema,
    /// `counter schema`: labeled like `counter dump`.
    CounterSchema,
    /// `perf histogram dump`.
    HistDump,
    /// `perf histogram schema`.
    HistSchema,
}

/// The counters of one logger in the document's form.
struct Counters<'a>(&'a [Ctr], Doc);

impl Serialize for Counters<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for c in self.0 {
            match self.1 {
                Doc::PerfSchema | Doc::CounterSchema => m.serialize_entry(&*c.name, &Schema(c))?,
                _ => m.serialize_entry(&*c.name, &Val(c))?,
            }
        }
        m.end()
    }
}

/// `{}`.
struct NoLabels;

impl Serialize for NoLabels {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_map(Some(0))?.end()
    }
}

/// One labeled set: `{"counters": {...}, "labels": {}}`.
struct Labeled<'a>(Counters<'a>);

impl Serialize for Labeled<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(2))?;
        m.serialize_entry("counters", &self.0)?;
        m.serialize_entry("labels", &NoLabels)?;
        m.end()
    }
}

/// A logger in the document's form.
struct Logger<'a>(&'a [Ctr], Doc);

impl Serialize for Logger<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.1 {
            Doc::CounterDump | Doc::CounterSchema => {
                let mut q = s.serialize_seq(Some(1))?;
                q.serialize_element(&Labeled(Counters(self.0, self.1)))?;
                q.end()
            }
            _ => Counters(self.0, self.1).serialize(s),
        }
    }
}

/// The whole document.
struct Document<'a>(&'a Sorted, Doc);

impl Serialize for Document<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (lg, cs) in self.0 {
            m.serialize_entry(&**lg, &Logger(cs, self.1))?;
        }
        m.end()
    }
}

/// Compact JSON, or pretty with a trailing newline (`crate::asok::pretty`).
fn to_bytes(v: &impl Serialize, compact: bool) -> Vec<u8> {
    if compact {
        serde_json::to_vec(v).unwrap_or_default()
    } else {
        let mut b = serde_json::to_vec_pretty(v).unwrap_or_default();
        b.push(b'\n');
        b
    }
}

/// A counter command waiting for its reply body (built off the cores).
#[derive(Clone, Debug)]
pub(crate) struct CounterReq {
    pub snap: CounterSnap,
    pub doc: Doc,
    pub logger: Option<String>,
    pub counter: Option<String>,
}

impl CounterReq {
    /// The reply body: compact JSON for the `json` / `jsonl` formats, pretty otherwise.
    pub(crate) fn render(&self, compact: bool) -> Vec<u8> {
        let (lg, ctr) = (self.logger.as_deref(), self.counter.as_deref());
        match self.doc {
            Doc::HistDump => to_bytes(&self.snap.histograms(false, lg, ctr), compact),
            Doc::HistSchema => to_bytes(&self.snap.histograms(true, None, None), compact),
            doc => to_bytes(
                &Document(&self.snap.catalogue().sorted(lg, ctr), doc),
                compact,
            ),
        }
    }
}

impl CounterSnap {
    /// Cumulative op counters of the whole OSD (core order, as the classic sum).
    fn all_perf(cores: &[Option<Arc<CoreCounters>>]) -> OpPerf {
        let mut it = cores.iter().flatten();
        let mut t = it.next().map(|c| c.perf).unwrap_or_default();
        for c in it {
            t.merge(&c.perf);
        }
        t
    }

    /// `(all, all - reset baseline)`: gauges as they are, monotonic counters since the last `perf reset` of logger
    /// `osd` (the caller's own reset, else the last `all`).
    pub(crate) fn op_perf(&self) -> (OpPerf, OpPerf) {
        (Self::all_perf(&self.cores), self.since_for("osd"))
    }

    /// [`Self::all_perf`] minus the reset baseline of `logger`: the counters whose logger is `logger` restart at its
    /// own reset, the other loggers keep their baselines.
    pub(crate) fn since_for(&self, logger: &str) -> OpPerf {
        let all = Self::all_perf(&self.cores);
        match self.reset.as_ref().and_then(|r| r.for_logger(logger)) {
            Some(r) => all.since(&Self::all_perf(r)),
            None => all,
        }
    }

    /// The full catalogue: the classic loggers ([`Self::osd_counters`]), the local diagnostics per core and PG
    /// (`flashstore_core_N`, `flashstore_pg_*`, `flashstore_store_N`, `flashstore_mig`) and the process-wide pools.
    pub(crate) fn catalogue(&self) -> Catalogue {
        let mut cat = Catalogue::default();
        self.osd_counters(&mut cat);
        self.utilization(&mut cat);
        let mut diagnostics = self.diagnostic_counters();
        if let Some(reset) = &self.reset {
            for (lg, c) in &mut diagnostics.ctrs {
                if c.ty & pct::COUNTER != 0
                    && let Some(base) = reset
                        .diagnostics
                        .get(diagnostics.loggers[*lg].as_ref())
                        .and_then(|cs| cs.get(c.name.as_ref()))
                {
                    c.v.value = c.v.value.saturating_sub(*base);
                }
            }
        }
        let offset = cat.loggers.len();
        cat.loggers.extend(diagnostics.loggers);
        cat.ctrs
            .extend(diagnostics.ctrs.into_iter().map(|(lg, c)| (offset + lg, c)));
        cat
    }

    /// Raw diagnostic values: used both for display and for a reset's baseline.
    fn diagnostic_counters(&self) -> Catalogue {
        let mut cat = Catalogue::default();
        for (core, c) in self.cores.iter().enumerate() {
            let Some(c) = c else { continue };
            let lg = cat.logger(format!("flashstore_store_{core}"));
            for &(n, g, x) in &c.store {
                cat.push(lg, Ctr::diag(n, g, x));
            }
        }
        let lg = cat.logger("flashstore_mig");
        cat.push(lg, Ctr::diag("moves_deferred", false, self.ctl.mig.0));
        cat.push(lg, Ctr::diag("pgs_deferred", true, self.ctl.mig.1));
        for (logger, counters) in &self.ctl.pools {
            let lg = cat.logger(*logger);
            for (name, value) in counters {
                let gauge = matches!(
                    name.as_str(),
                    "used_bytes" | "limit_bytes" | "parked_large_bytes" | "shelf_bytes"
                );
                cat.push(lg, Ctr::diag(name.clone(), gauge, *value));
            }
        }
        cat
    }

    /// Local workload diagnostics per core and PG (utilization.rs). Each lifetime (core: one, PG: its construction ID)
    /// has its own cumulative counters; `perf reset` subtracts the reset sample of the logger that owns the counter.
    fn utilization(&self, cat: &mut Catalogue) {
        for (core, c) in self.cores.iter().enumerate() {
            let Some(c) = c else { continue };
            let lg = cat.logger(format!("flashstore_core_{core}"));
            let name = format!("flashstore_core_{core}");
            let base = self
                .reset
                .as_ref()
                .and_then(|r| r.for_logger(&name))
                .and_then(|r| r.get(core).cloned().flatten());
            let since = |b: Option<&Utilization>, u: &Utilization, f: fn(&Utilization) -> u64| {
                let v = f(u);
                b.filter(|b| b.generation == u.generation)
                    .map_or(v, |b| v.saturating_sub(f(b)))
            };
            let b = base.as_ref().map(|b| &b.util);
            let u = &c.util;
            let fields: [(&'static str, UtilField); 12] = [
                ("busy_ns", |u| u.busy_ns),
                ("ops", |u| u.ops),
                ("bytes", |u| u.bytes),
                ("slice_cuts", |u| u.slice_cuts),
                ("rx_bytes", |u| u.rx_bytes),
                ("rx_pauses", |u| u.rx_pauses),
                ("rx_pause_ms", |u| u.rx_pause_ns / 1_000_000),
                ("rm_free_steps", |u| u.rm_steps[0]),
                ("rm_paced_steps", |u| u.rm_steps[1]),
                ("long_1ms", |u| u.long_iters[0]),
                ("long_10ms", |u| u.long_iters[1]),
                ("long_100ms", |u| u.long_iters[2]),
            ];
            for (n, f) in fields {
                cat.push(lg, Ctr::diag(n, false, since(b, u, f)));
            }
            for why in HoldWhy::ALL {
                let i = why as usize;
                let hold: [(&str, HoldField); 3] = [
                    ("n", |u, i| u.holds[i].n),
                    ("us", |u, i| u.holds[i].ns / 1000),
                    ("max_us", |u, i| u.holds[i].max_ns / 1000),
                ];
                for (suffix, f) in hold {
                    let v = f(u, i);
                    let v = b
                        .filter(|b| b.generation == u.generation)
                        .map_or(v, |b| v.saturating_sub(f(b, i)));
                    cat.push(
                        lg,
                        Ctr::diag(format!("hold_{}_{suffix}", why.name()), false, v),
                    );
                }
            }
            for (spg, u) in &c.pg_util {
                let name = format!(
                    "flashstore_pg_{core}_{}_{:x}_s{}",
                    spg.pgid.pool, spg.pgid.seed, spg.shard.0
                );
                let pg_sample = self
                    .reset
                    .as_ref()
                    .and_then(|r| r.for_logger(&name))
                    .and_then(|r| r.get(core).cloned().flatten());
                let b = pg_sample
                    .as_ref()
                    .and_then(|b| b.pg_util.iter().find(|(s, _)| s == spg))
                    .map(|(_, u)| u);
                let lg = cat.logger(name);
                cat.push(lg, Ctr::diag("busy_ns", false, since(b, u, |u| u.busy_ns)));
                cat.push(lg, Ctr::diag("ops", false, since(b, u, |u| u.ops)));
                cat.push(lg, Ctr::diag("bytes", false, since(b, u, |u| u.bytes)));
            }
        }
    }
}

impl<B: Backend> Osd<B> {
    /// This core's counters now. Cold: once a second per core, O(own PGs + shards); the fragmentation gauges advance
    /// their bounded walk (adr 0475 am. 1).
    pub(crate) fn counter_sample(&self) -> CoreCounters {
        CoreCounters {
            perf: self.op_perf_local(),
            util: self.perf.util,
            pg_util: self.pg_utilization(),
            store: self.store_counters_local(),
        }
    }

    /// Control core, every tick and before `perf reset` / `flush_pg_stats`: its own sample and the OSD aggregates.
    pub(crate) fn sample_counters(&mut self) {
        if !self.is_control() {
            return;
        }
        self.perf.own = Arc::new(self.counter_sample());
        self.perf.ctl = Arc::new(self.control_sample());
    }

    /// The OSD aggregates now (control core; cold, O(cores)).
    fn control_sample(&self) -> ControlCounters {
        let p = &self.rdma.process;
        let rdma = self.cfg.rdma.then_some([
            p.leaked_cores,
            p.teardown_failures,
            p.qp_drain_timeouts,
            p.quarantined_windows,
            p.quarantined_write_sources,
        ]);
        ControlCounters {
            statfs: self.statfs_all(),
            omap_allocated: self.pg_omap_bytes().max(0) as u64,
            roles: self.pg_role_counts(),
            removal: self.pg_removal_totals(),
            heartbeat_to_peers: self.perf.heartbeat_to_peers,
            map_messages: self.perf.map_messages,
            map_message_epochs: self.perf.map_message_epochs,
            rdma,
            client_frames: crate::xcore::FRAME_SLOTS as u64,
            client_pool_bytes: crate::memory::active().pool(),
            mig: (self.cl.mig.deferrals, self.cl.mig.deferred.len() as u64),
            loadavg_x100: crate::perf::load_average_1m().map_or(0, |l| (l * 100.0) as u64),
            pools: [
                ("flashstore_payload_pool", crate::payload_pool_counters()),
                ("flashstore_dma_pool", crate::dma_pool_counters()),
            ],
        }
    }

    /// Input of a counter dump (control core, per request): one `Arc` clone per core, nothing else.
    pub(crate) fn counter_snap(&self) -> CounterSnap {
        let me = self.core_id();
        let cores = (0..self.cores())
            .map(|c| {
                if c == me {
                    Some(self.perf.own.clone())
                } else {
                    self.cl
                        .stats
                        .get(c)
                        .and_then(Option::as_ref)
                        .map(|s| s.counters.clone())
                }
            })
            .collect();
        CounterSnap {
            cores,
            ctl: self.perf.ctl.clone(),
            reset: self.perf.reset.clone(),
            store: self.store_id,
        }
    }

    /// `perf reset <logger>`: that logger's counters restart from now; `all` resets every logger. A plain gauge keeps
    /// its value; other loggers keep their baselines (spec ops-observability 6.1). False = no such logger.
    pub(crate) fn perf_reset(&mut self, logger: &str) -> bool {
        self.sample_counters();
        let snap = self.counter_snap();
        let cat = snap.catalogue();
        if logger != "all" && !cat.has_logger(logger) {
            return false;
        }
        let diagnostics = snap.diagnostic_counters().sorted(None, None);
        let mut b = self.perf.reset.take().unwrap_or_default();
        if logger == "all" {
            b = ResetBaselines {
                all: Some(snap.cores),
                per: Vec::new(),
                diagnostics: Arc::default(),
            };
        } else {
            b.retain_existing(&cat);
            b.per.retain(|(l, _)| l != logger);
            b.per.push((logger.to_owned(), snap.cores));
        }
        // A reset is based on raw values, never on the already-subtracted display.
        for (name, cs) in diagnostics {
            if logger == "all" || name == logger {
                Arc::make_mut(&mut b.diagnostics).insert(
                    name.into_owned(),
                    cs.into_iter()
                        .filter(|c| c.ty & pct::COUNTER != 0)
                        .map(|c| (c.name.into_owned(), c.v.value))
                        .collect(),
                );
            }
        }
        self.perf.reset = Some(b);
        true
    }

    /// A counter command's result: the snapshot; the reply body is built where the reply is sent from.
    pub(crate) fn counter_cmd(
        &self,
        doc: Doc,
        logger: Option<String>,
        counter: Option<String>,
    ) -> crate::tell::Res {
        let req = CounterReq {
            snap: self.counter_snap(),
            doc,
            logger,
            counter,
        };
        (0, String::new(), crate::tell::Out::Counters(Box::new(req)))
    }
}

/// Tests: the documents as JSON values from the control core's values of now (other cores: their last sample).
#[cfg(test)]
impl<B: Backend> Osd<B> {
    pub(crate) fn fresh_counter_snap(&self) -> CounterSnap {
        let mut s = self.counter_snap();
        let mut cores = s.cores.to_vec();
        cores[self.core_id()] = Some(Arc::new(self.counter_sample()));
        s.cores = cores.into();
        s.ctl = Arc::new(self.control_sample());
        s
    }

    fn doc_now(&self, doc: Doc, logger: Option<&str>, counter: Option<&str>) -> serde_json::Value {
        let req = CounterReq {
            snap: self.fresh_counter_snap(),
            doc,
            logger: logger.map(str::to_owned),
            counter: counter.map(str::to_owned),
        };
        serde_json::from_slice(&req.render(true)).unwrap()
    }

    pub(crate) fn perf_dump(
        &self,
        logger: Option<&str>,
        counter: Option<&str>,
    ) -> serde_json::Value {
        self.doc_now(Doc::PerfDump, logger, counter)
    }

    pub(crate) fn counter_dump(
        &self,
        logger: Option<&str>,
        counter: Option<&str>,
    ) -> serde_json::Value {
        self.doc_now(Doc::CounterDump, logger, counter)
    }

    pub(crate) fn perf_schema(&self) -> serde_json::Value {
        self.doc_now(Doc::PerfSchema, None, None)
    }

    pub(crate) fn counter_schema(&self) -> serde_json::Value {
        self.doc_now(Doc::CounterSchema, None, None)
    }

    /// [`Osd::counters`] from the values of now.
    pub(crate) fn counters_now(&self) -> crate::perf::Map {
        self.fresh_counter_snap().osd_map()
    }
}
