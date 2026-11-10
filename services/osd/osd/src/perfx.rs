// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Observers behind the secondary perf loggers (`recoverystate_perf`, scrub counters, `bluestore.*` latencies) and the
//! `os_alerts` of osd_stat (spec ops-observability 2c, 3a). All state is per core; the control core sums the
//! cumulative copies every core ships with its 1 s stats ([`crate::perf::OpPerf`]).
use crate::backend::Backend;
use crate::osd::Osd;
use crate::perf::{Avg, OpPerf};
use denc::types::SpgT;
use pgwire::state as st;
use std::collections::{BTreeMap, VecDeque};

/// Pseudo state bit: this OSD is a replica of the PG and the PG is active there (classic `ReplicaActive`).
const REPLICA_ACTIVE: u64 = 1 << 62;

/// `recoverystate_perf` counters we can derive from PG state bits: classic name, state bit. Time in the state per
/// visit (a PG that leaves the state adds one sample). Primary PGs only, except `replicaactive`. The finer classic
/// states (getinfo, waitremotebackfillreserved, ...) have no bit and are not reported.
pub(crate) const RS: [(&str, u64); 8] = [
    ("peering_latency", st::PEERING),
    ("active_latency", st::ACTIVE),
    ("clean_latency", st::CLEAN),
    ("recovering_latency", st::RECOVERING),
    ("backfilling_latency", st::BACKFILLING),
    ("incomplete_latency", st::INCOMPLETE),
    ("down_latency", st::DOWN),
    ("replicaactive_latency", REPLICA_ACTIVE),
];
pub(crate) const RS_N: usize = RS.len();

/// Scrub outcome counters of one core (primary PGs of replicated pools; the counter names are replicated-only).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScrubPerf {
    pub started: u64,
    pub ok: u64,
    pub failed: u64,
    pub ok_elapsed: Avg,
    pub failed_elapsed: Avg,
}

impl ScrubPerf {
    pub(crate) fn since(&self, b: &ScrubPerf) -> ScrubPerf {
        use crate::perf::sub_avg;
        ScrubPerf {
            started: self.started.saturating_sub(b.started),
            ok: self.ok.saturating_sub(b.ok),
            failed: self.failed.saturating_sub(b.failed),
            ok_elapsed: sub_avg(self.ok_elapsed, b.ok_elapsed),
            failed_elapsed: sub_avg(self.failed_elapsed, b.failed_elapsed),
        }
    }

    pub(crate) fn merge(&mut self, o: &ScrubPerf) {
        self.started += o.started;
        self.ok += o.ok;
        self.failed += o.failed;
        self.ok_elapsed.sum_ns += o.ok_elapsed.sum_ns;
        self.ok_elapsed.n += o.ok_elapsed.n;
        self.failed_elapsed.sum_ns += o.failed_elapsed.sum_ns;
        self.failed_elapsed.n += o.failed_elapsed.n;
    }
}

/// Events inside a sliding window, stored as per-second buckets so the count is exact up to one-second granularity
/// (the alert text is "in the last N s") and memory is bounded by the window lifetime — at most one bucket per
/// populated second — instead of by a fixed event cap. A threshold above any fixed cap can therefore still fire.
#[derive(Debug, Default)]
pub(crate) struct Window {
    /// `(second start ns, events in that second)`, ordered oldest -> newest.
    buckets: VecDeque<(u64, u32)>,
}

impl Window {
    /// One second: the bucket granularity of the window.
    const BUCKET_NS: u64 = 1_000_000_000;

    /// Record an event at `now` (ns) and drop buckets whose whole second fell out of a `life_ns` window ending at
    /// `now`. `life_ns` is the window length current at the time of the event (a later, longer lifetime counts the
    /// remaining buckets; buckets already pruned under a shorter lifetime are gone, as with any expiry window).
    pub(crate) fn push(&mut self, now: u64, life_ns: u64) {
        let sec = now - now % Self::BUCKET_NS;
        match self.buckets.back_mut() {
            Some((s, n)) if *s == sec => *n += 1,
            _ => self.buckets.push_back((sec, 1)),
        }
        self.prune(now, life_ns);
    }

    /// Exact number of events inside the `life_ns` window ending at `now` (second granularity).
    pub(crate) fn count(&self, now: u64, life_ns: u64) -> u64 {
        let cutoff = now.saturating_sub(life_ns);
        self.buckets
            .iter()
            .filter(|(s, _)| s.saturating_add(Self::BUCKET_NS) > cutoff)
            .map(|(_, n)| u64::from(*n))
            .sum()
    }

    /// Drop buckets whose whole second is at or before `now - life_ns` (keeps memory bounded by the lifetime).
    fn prune(&mut self, now: u64, life_ns: u64) {
        let cutoff = now.saturating_sub(life_ns);
        while let Some((s, _)) = self.buckets.front() {
            if s.saturating_add(Self::BUCKET_NS) <= cutoff {
                self.buckets.pop_front();
            } else {
                break;
            }
        }
    }
}

#[derive(Debug, Clone)]
struct PgSeen {
    bits: u64,
    /// When each `RS` state was entered.
    since: [u64; RS_N],
    /// Scrub running: start (ns) and the scrub stamps seen when it started (a finished scrub moves them).
    scrub: Option<(u64, (denc::types::UTime, denc::types::UTime))>,
}

/// Samples PG states once per tick: state durations and scrub outcomes. Granularity = the tick (1 s).
#[derive(Debug, Default)]
pub(crate) struct PgObs {
    seen: BTreeMap<SpgT, PgSeen>,
    /// Last seen `Pg::shards_repaired` per PG (the PG counts since its instance started).
    repaired: BTreeMap<SpgT, u64>,
}

fn rs_end(p: &mut OpPerf, s: &PgSeen, bits: u64, now: u64) {
    for (i, (_, bit)) in RS.iter().enumerate() {
        if s.bits & bit != 0 && bits & bit == 0 {
            p.rs[i].add(now.saturating_sub(s.since[i]));
        }
    }
}

impl PgObs {
    /// Damaged objects a PG repaired since the last sample.
    fn repaired(&mut self, p: &mut OpPerf, spg: SpgT, cum: u64) {
        let last = self.repaired.insert(spg, cum).unwrap_or(0);
        p.shards_repaired += cum.saturating_sub(last);
    }

    /// One PG sampled: `bits` = state bits (+ pseudo bits), `stamps` = (last_scrub, last_deep_scrub) stamps, `lead` =
    /// we are its primary.
    fn sample(
        &mut self,
        p: &mut OpPerf,
        now: u64,
        spg: SpgT,
        bits: u64,
        lead: bool,
        stamps: (denc::types::UTime, denc::types::UTime),
    ) {
        let scrubbing = lead && bits & st::SCRUBBING != 0;
        let Some(s) = self.seen.get_mut(&spg) else {
            if scrubbing {
                p.scrub.started += 1;
            }
            self.seen.insert(
                spg,
                PgSeen {
                    bits,
                    since: [now; RS_N],
                    scrub: scrubbing.then_some((now, stamps)),
                },
            );
            return;
        };
        if s.bits != bits {
            rs_end(p, s, bits, now);
            for (i, (_, bit)) in RS.iter().enumerate() {
                if s.bits & bit == 0 && bits & bit != 0 {
                    s.since[i] = now;
                }
            }
            s.bits = bits;
        }
        match (s.scrub, scrubbing) {
            (None, true) => {
                p.scrub.started += 1;
                s.scrub = Some((now, stamps));
            }
            (Some((t0, at_start)), false) => {
                // a finished scrub moved the stamps; an aborted / failed one did not
                let el = now.saturating_sub(t0);
                if stamps != at_start {
                    p.scrub.ok += 1;
                    p.scrub.ok_elapsed.add(el);
                } else {
                    p.scrub.failed += 1;
                    p.scrub.failed_elapsed.add(el);
                }
                s.scrub = None;
            }
            _ => {}
        }
    }

    /// PGs that vanished since the last sample end all their states.
    fn forget_gone(&mut self, p: &mut OpPerf, now: u64, live: &std::collections::BTreeSet<SpgT>) {
        self.seen.retain(|k, s| {
            if live.contains(k) {
                return true;
            }
            rs_end(p, s, 0, now);
            false
        });
        self.repaired.retain(|k, _| live.contains(k));
    }
}

impl<B: Backend> Osd<B> {
    /// Per tick: feed the PG state observer of this core.
    pub(crate) fn pg_observe(&mut self, states: &[(SpgT, String)]) {
        let now = self.mnow().as_nanos() as u64;
        let mut obs = std::mem::take(&mut self.perf.obs);
        let mut live = std::collections::BTreeSet::new();
        for (spg, s) in states {
            let Some(pg) = self.pg.set.pg(*spg) else {
                continue;
            };
            live.insert(*spg);
            let lead = pg.is_primary();
            let raw = st::parse_state(s).unwrap_or(0);
            // The scrub counters below have replicated-only names. EC PG state durations
            // and repaired-shard counts still belong in the OSD-wide observers.
            let raw = if pg.is_ec_pool() {
                raw & !st::SCRUBBING
            } else {
                raw
            };
            let bits = if lead {
                raw
            } else if raw & st::ACTIVE != 0 {
                REPLICA_ACTIVE
            } else {
                0
            };
            let h = &pg.info().history;
            obs.sample(
                &mut self.perf.op,
                now,
                *spg,
                bits,
                lead,
                (h.last_scrub_stamp, h.last_deep_scrub_stamp),
            );
            obs.repaired(&mut self.perf.op, *spg, pg.shards_repaired());
        }
        obs.forget_gone(&mut self.perf.op, now, &live);
        self.perf.obs = obs;
    }

    /// `os_alerts` of this OSD: code -> text, the keys the mon turns into health checks (`OBJECT_STORE_WARN` family).
    /// Only conditions we can prove; empty = healthy.
    pub(crate) fn os_alerts(&self) -> BTreeMap<String, String> {
        let mut a = BTreeMap::new();
        // classic BLUESTORE_DISK_SIZE_MISMATCH: the device is smaller than what mkfs recorded
        if let Some(m) = self.store.as_ref().and_then(|s| {
            use crate::meta::MetaStore as _;
            s.size_mismatch()
        }) {
            a.insert(
                self.store_id.health_code("DISK_SIZE_MISMATCH"),
                format!(
                    "device size mismatch detected, size at mkfs ({}) > device size ({}), \
                     please stop using this OSD as it might cause data loss",
                    m.0, m.1
                ),
            );
        }
        // own code: erasure pools CRUSH maps onto this OSD that it does not serve (kill switch off, unsupported profile or
        // mode): classic primaries of mixed acting sets stall or run degraded because of it (adr 0039)
        let idle = self.pg_passive_pools();
        if !idle.is_empty() {
            let l: Vec<String> = idle.iter().map(u64::to_string).collect();
            a.insert(
                "FLASHSTORE_EC_POOL_NOT_SERVED".to_owned(),
                format!(
                    "mapped into erasure pool(s) {} that this OSD does not serve (see `ceph tell osd.N status`: ec_pools)",
                    l.join(",")
                ),
            );
        }
        // own code: tracker 74943, classic ISA OSDs older than the fix in acting sets of ISA pools with several k/m shapes
        if !self.pg.isa_alert.is_empty() {
            a.insert(
                "FLASHSTORE_EC_ISA_DECODE_CACHE".to_owned(),
                self.pg.isa_alert.clone(),
            );
        }
        // own code: merge sources that cannot move to their target's core for lack of store room (adr 0031 am. 4), and
        // sources whose merge completed without them (stranded, am. 5: the merged PG is incomplete here and backfilled
        // by its peers; the copy is deleted once that is done)
        let d = &self.cl.mig.deferred;
        if !d.is_empty() {
            let (strand, wait): (Vec<_>, Vec<_>) = d.values().partition(|x| x.stranded);
            let l = |v: &[&crate::mig::Deferred]| {
                v.iter()
                    .map(|x| x.pgid.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let mut msg = Vec::new();
            if !wait.is_empty() {
                msg.push(format!(
                    "{} PG move(s) for merges deferred, no store room at the target's core: {} \
                     (merge waits; free space or add capacity)",
                    wait.len(),
                    l(&wait)
                ));
            }
            if !strand.is_empty() {
                msg.push(format!(
                    "{} merge source(s) stranded on the wrong core: {} (the merged PG backfills from its peers, \
                     the stale copy is deleted after that)",
                    strand.len(),
                    l(&strand)
                ));
            }
            a.insert("FLASHSTORE_PG_MOVE_DEFERRED".to_owned(), msg.join("; "));
        }
        let p = self.op_perf_all();
        // classic BLUESTORE_SLOW_OP_ALERT: durable commits slower than bluestore_log_op_age
        let thr = self.conf.u64("bluestore_slow_ops_warn_threshold", 1);
        if thr > 0 && p.slow_store_win >= thr {
            a.insert(
                self.store_id.health_code("SLOW_OP_ALERT"),
                format!(
                    "observed {} slow store commit(s) (>= {} s) in the last {} s",
                    p.slow_store_win,
                    self.conf.f64("bluestore_log_op_age", 5.0),
                    self.conf.u64("bluestore_slow_ops_warn_lifetime", 86400)
                ),
            );
        }
        // no classic equivalent (classic BLUESTORE_SPURIOUS_READ_ERRORS means "failed once, retry succeeded": we do not
        // retry): client reads failed with EIO
        if self.conf.bool("flashstore_warn_on_read_errors", true) && p.eio_win > 0 {
            a.insert(
                "FLASHSTORE_READ_ERRORS".to_owned(),
                format!(
                    "{} client read(s) failed with EIO in the last {} s (device or checksum error)",
                    p.eio_win,
                    self.conf.u64("flashstore_read_errors_warn_lifetime", 86400)
                ),
            );
        }
        // own code: PGs stopped by the past-interval bounds check (peering.md 3.8). Recomputed per stat report, never
        // sticky: the entry disappears when no PG is stopped any more.
        let mut stopped = self.pg.set.bounds_stopped();
        for s in self.cl.stats.iter().flatten() {
            stopped.extend(s.pg_bounds_stopped.iter().copied());
        }
        stopped.sort_unstable();
        stopped.dedup();
        if let Some(text) = past_interval_alert(&stopped) {
            a.insert("FLASHSTORE_PG_PAST_INTERVALS".to_owned(), text);
        }
        a
    }
}

/// `FLASHSTORE_PG_PAST_INTERVALS` text: every stopped PG of this OSD with its required and stored range (peering.md 3.8).
pub(crate) fn past_interval_alert(stopped: &[peering::BoundsStoppedPg]) -> Option<String> {
    let l: Vec<String> = stopped
        .iter()
        .map(|s| {
            let (rs, re) = s.required;
            let (ps, pe) = s.past;
            format!("{} required [{rs},{re}) past [{ps},{pe})", s.spg)
        })
        .collect();
    (!l.is_empty()).then(|| {
        format!(
            "{} PG(s) stopped, past interval bounds implausible: {}",
            l.len(),
            l.join("; ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::types::UTime;

    fn spg(n: u32) -> SpgT {
        SpgT {
            pgid: denc::types::PgT { pool: 1, seed: n },
            shard: denc::types::ShardId::NO_SHARD,
        }
    }

    #[test]
    fn state_durations_and_scrub_outcomes() {
        let (mut o, mut p) = (PgObs::default(), OpPerf::default());
        let z = (UTime::default(), UTime::default());
        let s = |sec: u64| sec * 1_000_000_000;
        let [peer, act, clean, scrub] = [st::PEERING, st::ACTIVE, st::CLEAN, st::SCRUBBING];
        o.sample(&mut p, s(0), spg(0), peer, true, z);
        o.sample(&mut p, s(3), spg(0), act, true, z);
        // peering lasted 3 s; active + clean entered
        assert_eq!(p.rs[0], Avg { sum_ns: s(3), n: 1 });
        o.sample(&mut p, s(5), spg(0), act | clean, true, z);
        o.sample(&mut p, s(10), spg(0), act | clean | scrub, true, z);
        assert_eq!(p.scrub.started, 1);
        // scrub ends with moved stamps = success, `clean` is still running
        let moved = (UTime::new(10, 0), UTime::default());
        o.sample(&mut p, s(14), spg(0), act | clean, true, moved);
        assert_eq!((p.scrub.ok, p.scrub.failed), (1, 0));
        assert_eq!(p.scrub.ok_elapsed, Avg { sum_ns: s(4), n: 1 });
        // second scrub ends without moved stamps = failed / aborted
        o.sample(&mut p, s(20), spg(0), act | clean | scrub, true, moved);
        o.sample(&mut p, s(21), spg(0), act | clean, true, moved);
        assert_eq!((p.scrub.started, p.scrub.ok, p.scrub.failed), (2, 1, 1));
        // PG gone: every running state ends (active 21 s since s(3)... entered at 3, ended at 30)
        let live = std::collections::BTreeSet::new();
        o.forget_gone(&mut p, s(30), &live);
        assert_eq!(
            p.rs[1],
            Avg {
                sum_ns: s(27),
                n: 1
            }
        );
        assert_eq!(
            p.rs[2],
            Avg {
                sum_ns: s(25),
                n: 1
            }
        );
        assert!(o.seen.is_empty());
    }

    #[test]
    fn replica_active_is_its_own_state() {
        let (mut o, mut p) = (PgObs::default(), OpPerf::default());
        let z = (UTime::default(), UTime::default());
        o.sample(&mut p, 0, spg(1), REPLICA_ACTIVE, false, z);
        o.sample(&mut p, 2_000_000_000, spg(1), 0, false, z);
        assert_eq!(p.rs[7].n, 1);
        assert_eq!(p.rs[1].n, 0, "a replica never reports active_latency");
    }

    #[test]
    fn window_counts_inside_lifetime_and_is_bounded() {
        let mut w = Window::default();
        let s = 1_000_000_000;
        w.push(10, 50 * s);
        w.push(100, 50 * s);
        // both events land in second 0
        assert_eq!(w.count(5 * s, 50 * s), 2);
        assert_eq!(w.count(105 * s, 50 * s), 0, "second 0 aged out");
        assert_eq!(w.count(105 * s, 500 * s), 2);
    }

    /// A threshold above the old fixed cap (256) can fire: the window reports the true count, not a capped one.
    #[test]
    fn window_counts_every_event_without_a_fixed_cap() {
        let mut w = Window::default();
        let s = 1_000_000_000;
        let life = 86_400 * s; // the default lifetime
        // 10_000 slow commits spread over 100 seconds (100/s), far above any threshold an operator might set
        for i in 0..10_000u64 {
            let now = (i / 100) * s + (i % 100) * 10_000_000;
            w.push(now, life);
        }
        assert_eq!(w.count(100 * s, life), 10_000, "no 256 cap");
        // buckets are per second: only the 100 populated seconds exist, not 10_000 entries
        assert_eq!(w.buckets.len(), 100);
    }

    /// Events expire out of the window: the count drops as `now` advances, and the buckets are pruned.
    #[test]
    fn window_expires_events_as_time_advances() {
        let mut w = Window::default();
        let s = 1_000_000_000;
        let life = 60 * s;
        for i in 0..120u64 {
            w.push(i * s, life); // one event per second for two minutes
        }
        assert_eq!(w.count(120 * s, life), 60, "only the last minute is inside");
        // a new event prunes the out-of-window seconds
        w.push(130 * s, life);
        assert_eq!(w.count(130 * s, life), 51);
        assert_eq!(w.buckets.len(), 51, "expired buckets are dropped");
    }
}
