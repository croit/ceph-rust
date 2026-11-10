// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Vulnerability window and active-rebuild span of the acting primary (Ceph 21.2.0, spec peering.md 9.6; history
//! fields 18-23 of pg_history_t, peering.md 2.2).
//!
//! The latches live in `PgHistory` (persisted with the PG info, shared with the replicas). A closed window or rebuild
//! episode yields one duration sample: the PG emits it as [`Action::Latch`], [`crate::PgSet`] sums the samples of its
//! PGs into a [`LatchPerf`] ([`crate::PgSet::latch_perf`]) for the OSD-wide `recoverystate_perf` counters
//! `pg_vulnerability_duration(_min)` and `pg_rebuild_duration(_min)`.

use crate::pg::{ASt, PSt, Pg, St};
use crate::types::Action;
use denc::types::UTime;
use pgwire::state as pgs;
use pgwire::{PgHistory, PgStat};

/// Samples shorter than this are dropped (classic: sub-millisecond windows are noise).
const MIN_SAMPLE_NS: u64 = 1_000_000;

/// Which latch closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatchKind {
    /// A vulnerability window (degraded / undersized / misplaced until clean).
    Vulnerability,
    /// An active-rebuild episode (time in Recovering / Backfilling until Recovered).
    Rebuild,
}

/// Duration counter: classic "time avg with max" plus the smallest sample (a gauge that only moves down, 0 = none yet).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DurStat {
    pub n: u64,
    pub sum_ns: u64,
    pub max_ns: u64,
    pub min_ns: u64,
}

impl DurStat {
    pub fn record(&mut self, ns: u64) {
        self.n += 1;
        self.sum_ns = self.sum_ns.saturating_add(ns);
        self.max_ns = self.max_ns.max(ns);
        if self.min_ns == 0 || ns < self.min_ns {
            self.min_ns = ns;
        }
    }

    /// Sum of two cores' counters (min = smaller non-zero).
    pub fn merge(&mut self, o: &DurStat) {
        self.n += o.n;
        self.sum_ns = self.sum_ns.saturating_add(o.sum_ns);
        self.max_ns = self.max_ns.max(o.max_ns);
        if o.min_ns != 0 && (self.min_ns == 0 || o.min_ns < self.min_ns) {
            self.min_ns = o.min_ns;
        }
    }
}

/// Cumulative latch samples of one core's primary PGs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LatchPerf {
    pub vulnerability: DurStat,
    pub rebuild: DurStat,
}

impl LatchPerf {
    pub fn record(&mut self, kind: LatchKind, ns: u64) {
        match kind {
            LatchKind::Vulnerability => self.vulnerability.record(ns),
            LatchKind::Rebuild => self.rebuild.record(ns),
        }
    }

    pub fn merge(&mut self, o: &LatchPerf) {
        self.vulnerability.merge(&o.vulnerability);
        self.rebuild.merge(&o.rebuild);
    }
}

/// Coarse class of the active substate, for the rebuild-span transitions.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RbPhase {
    /// Anything else (peering, reservation waits, not primary).
    #[default]
    Other,
    /// Recovering / Backfilling.
    Active,
    /// NotRecovering / NotBackfilling (deferred, toofull, unfound).
    Paused,
    /// Recovered / Clean.
    Done,
}

impl RbPhase {
    fn of(st: St) -> RbPhase {
        match st {
            St::Primary(PSt::Active(ASt::Recovering | ASt::Backfilling)) => RbPhase::Active,
            St::Primary(PSt::Active(ASt::NotRecovering | ASt::NotBackfilling)) => RbPhase::Paused,
            St::Primary(PSt::Active(ASt::Recovered | ASt::Clean)) => RbPhase::Done,
            _ => RbPhase::Other,
        }
    }
}

fn ns_between(from: UTime, to: UTime) -> u64 {
    to.as_nanos().saturating_sub(from.as_nanos())
}

fn utime_of(ns: u64) -> UTime {
    UTime::new((ns / 1_000_000_000) as u32, (ns % 1_000_000_000) as u32)
}

/// Close the open vulnerability window at `now`: returns the sample (None below 1 ms).
pub(crate) fn vuln_close(h: &mut PgHistory, now: UTime) -> Option<u64> {
    let ns = ns_between(h.last_degraded, now);
    h.vuln_window_reported = now;
    h.last_clean = now;
    (ns >= MIN_SAMPLE_NS).then_some(ns)
}

/// Entering Recovering / Backfilling: start a span unless one is open. Returns whether the history changed.
pub(crate) fn rebuild_arm(h: &mut PgHistory, now: UTime) -> bool {
    if h.rebuild_open() {
        return false;
    }
    h.last_rebuild_active_start = now;
    true
}

/// Entering NotRecovering / NotBackfilling: bank the open span. Returns whether the history changed.
pub(crate) fn rebuild_pause(h: &mut PgHistory, now: UTime) -> bool {
    if !h.rebuild_open() {
        return false;
    }
    let acc = h.rebuild_active_accum.as_nanos() + ns_between(h.last_rebuild_active_start, now);
    h.rebuild_active_accum = utime_of(acc);
    h.rebuild_span_reported = now;
    true
}

/// Entering Recovered: pause, then end the episode. Returns (history changed, episode ended, sample >= 1 ms).
pub(crate) fn rebuild_close(h: &mut PgHistory, now: UTime) -> (bool, bool, Option<u64>) {
    let paused = rebuild_pause(h, now);
    let acc = h.rebuild_active_accum.as_nanos();
    if acc == 0 {
        return (paused, false, None);
    }
    h.rebuild_active_accum = UTime::default();
    (true, true, (acc >= MIN_SAMPLE_NS).then_some(acc))
}

impl Pg {
    fn latch_sample(&mut self, kind: LatchKind, ns: Option<u64>) {
        if let Some(ns) = ns {
            self.out.push(Action::Latch { kind, ns });
        }
    }

    /// PG creation (becoming primary with history.last_epoch_started == 0): every latch starts at the creation stamp.
    pub(crate) fn latch_created(&mut self) {
        let h = &mut self.info.history;
        let c = h.last_scrub_stamp;
        if (h.last_clean, h.last_degraded, h.vuln_window_reported) != (c, c, c) {
            (h.last_clean, h.last_degraded, h.vuln_window_reported) = (c, c, c);
            self.info_dirty = true;
        }
        self.info.stats.last_degraded = c;
    }

    /// Vulnerability window step of one stats publish (`s` = the stats being published, timestamps refreshed). Mirrors
    /// the window onset into `s.last_degraded`. A publish that opens or closes nothing leaves the history untouched.
    pub(crate) fn latch_publish(&mut self, s: &mut PgStat, now: UTime) {
        if self.refuse.is_none() {
            let vulnerable = self.state & (pgs::DEGRADED | pgs::UNDERSIZED) != 0
                || s.stats.sum.num_objects_degraded > 0
                || s.stats.sum.num_objects_misplaced > 0;
            let h = &mut self.info.history;
            if vulnerable && !h.vuln_open() {
                h.last_degraded = if s.last_change > s.last_clean {
                    s.last_change
                } else {
                    now
                };
                self.info_dirty = true;
            } else if !vulnerable
                && h.vuln_open()
                && self.state & pgs::CLEAN != 0
                && now > h.last_degraded
            {
                let ns = vuln_close(h, now);
                self.info_dirty = true;
                self.prim.latch_unshared = true;
                self.latch_sample(LatchKind::Vulnerability, ns);
            }
        }
        s.last_degraded = self.info.history.last_degraded;
        self.info.stats.last_degraded = s.last_degraded;
    }

    /// Rebuild-span transitions of the acting primary, from the active substate reached by this event.
    pub(crate) fn latch_rebuild_step(&mut self) {
        let phase = if self.refuse.is_none() {
            RbPhase::of(self.st)
        } else {
            RbPhase::Other
        };
        if phase == self.prim.rb_phase {
            return;
        }
        self.prim.rb_phase = phase;
        let now = self.wall();
        let h = &mut self.info.history;
        let changed = match phase {
            RbPhase::Active => rebuild_arm(h, now),
            RbPhase::Paused => rebuild_pause(h, now),
            RbPhase::Done => {
                let (changed, ended, ns) = rebuild_close(h, now);
                if ended {
                    self.prim.latch_unshared = true;
                }
                self.latch_sample(LatchKind::Rebuild, ns);
                changed
            }
            RbPhase::Other => false,
        };
        self.info_dirty |= changed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(sec: u32) -> UTime {
        UTime::new(sec, 0)
    }

    #[test]
    fn rebuild_episode_with_pause() {
        let mut h = PgHistory::default();
        assert!(rebuild_arm(&mut h, t(10)));
        assert!(!rebuild_arm(&mut h, t(11)), "open span: onset kept");
        assert!(rebuild_pause(&mut h, t(15)));
        assert_eq!(
            (h.rebuild_active_accum, h.rebuild_span_reported),
            (t(5), t(15))
        );
        assert!(!rebuild_pause(&mut h, t(16)), "paused twice: nothing");
        assert!(rebuild_arm(&mut h, t(20)));
        let (ch, ended, ns) = rebuild_close(&mut h, t(23));
        assert!(ch && ended);
        assert_eq!(ns, Some(8_000_000_000));
        assert_eq!(h.rebuild_active_accum, UTime::default());
        assert_eq!(h.rebuild_span_reported, t(23));
        assert!(!h.rebuild_open());
        // nothing to record (Activating -> Recovered): no-op
        assert_eq!(rebuild_close(&mut h, t(30)), (false, false, None));
    }

    #[test]
    fn rebuild_close_drops_sub_ms() {
        let mut h = PgHistory::default();
        rebuild_arm(&mut h, UTime::new(10, 0));
        assert_eq!(
            rebuild_close(&mut h, UTime::new(10, 500_000)),
            (true, true, None)
        );
        assert_eq!(h.rebuild_active_accum, UTime::default());
    }

    #[test]
    fn vulnerability_close() {
        let mut h = PgHistory {
            last_degraded: t(10),
            ..Default::default()
        };
        assert!(h.vuln_open());
        assert_eq!(vuln_close(&mut h, t(12)), Some(2_000_000_000));
        assert_eq!((h.vuln_window_reported, h.last_clean), (t(12), t(12)));
        assert!(!h.vuln_open());
    }

    /// Active primary osd.0 of a size-3 replicated PG, members 0..3, stored peer info only for osd.1 (stale history).
    fn primary_pg() -> (Pg, denc::types::PgShard, denc::types::PgShard) {
        use crate::types::Config;
        use denc::types::PgShard;
        use denc::types::{PgT, ShardId, SpgT};
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        };
        let map = crate::map::synth::SynthMap::new(4)
            .with_pool(1, 3, 2, 1)
            .with_osd(0, 1)
            .with_osd(1, 1)
            .with_osd(2, 1)
            .into_handle();
        let mut pg = Pg::blank(
            std::sync::Arc::new(Config::new(0)),
            spg,
            map,
            pgwire::PgInfo::new(spg),
        );
        pg.acting = vec![0, 1, 2];
        pg.up = pg.acting.clone();
        pg.st = St::Primary(PSt::Active(ASt::Clean));
        pg.state = pgs::ACTIVE | pgs::CLEAN;
        let sh = |osd| PgShard {
            osd,
            shard: ShardId::NO_SHARD,
        };
        pg.prim.acting_recovery_backfill = [sh(0), sh(1), sh(2)].into_iter().collect();
        pg.prim.peer_info.insert(sh(1), pgwire::PgInfo::new(spg));
        // own history: a closed window and a finished rebuild episode, les/lis of this interval
        let h = &mut pg.info.history;
        (h.last_degraded, h.vuln_window_reported, h.last_clean) = (t(10), t(20), t(20));
        (h.last_rebuild_active_start, h.rebuild_span_reported) = (t(12), t(19));
        pg.info.last_epoch_started = 7;
        pg.info.last_interval_started = 6;
        (pg, sh(1), sh(2))
    }

    fn info2_sent_to(pg: &Pg) -> Vec<i32> {
        pg.out
            .iter()
            .filter_map(|a| match a {
                Action::Send(s)
                    if matches!(
                        &s.body,
                        crate::types::Body::Peering(pgwire::PeeringMsg::MOSDPGInfo2(_))
                    ) =>
                {
                    Some(s.to)
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn share_refreshes_stored_peer_info_by_merge() {
        let (mut pg, p1, p2) = primary_pg();
        // the peer reported a later deep-scrub and an open window of its own: merge keeps both
        {
            let pi = pg.prim.peer_info.get_mut(&p1).unwrap();
            pi.history.last_deep_scrub_stamp = t(30);
            pi.history.last_degraded = t(25);
            pi.history.vuln_window_reported = t(5);
        }
        pg.prim.latch_unshared = true;
        pg.share_pg_info();
        assert!(!pg.prim.latch_unshared);
        assert_eq!(info2_sent_to(&pg), vec![1, 2]);
        let pi = &pg.prim.peer_info[&p1];
        assert_eq!((pi.last_epoch_started, pi.last_interval_started), (7, 6));
        let h = &pi.history;
        assert_eq!(h.last_deep_scrub_stamp, t(30), "merge, not assign");
        assert_eq!(h.vuln_window_reported, t(20));
        assert_eq!(h.last_clean, t(20));
        assert_eq!(
            h.last_degraded,
            t(25),
            "peer's window still open after max(reported): its onset stays"
        );
        assert_eq!(
            (h.last_rebuild_active_start, h.rebuild_span_reported),
            (t(12), t(19)),
            "newer rebuild_span_reported wins with its onset"
        );
        assert!(
            !pg.prim.peer_info.contains_key(&p2),
            "no stored entry: skipped"
        );
    }

    #[test]
    fn closed_unshared_window_is_shared_on_a_new_map() {
        let (mut pg, p1, _) = primary_pg();
        pg.info.history.last_degraded = t(40);
        pg.info.history.vuln_window_reported = t(20);
        let mut s = PgStat {
            last_change: t(40),
            last_clean: t(20),
            ..Default::default()
        };
        // clean publish closes the window: not shared by the publish itself
        pg.latch_publish(&mut s, t(45));
        assert!(!pg.info.history.vuln_open() && pg.prim.latch_unshared);
        assert!(info2_sent_to(&pg).is_empty());
        assert_eq!(
            pg.prim.peer_info[&p1].history.vuln_window_reported,
            UTime::default()
        );
        // the next map without interval change shares it and refreshes the stored copy
        pg.on_active_advmap();
        assert_eq!(info2_sent_to(&pg), vec![1, 2]);
        assert!(!pg.prim.latch_unshared);
        assert_eq!(pg.prim.peer_info[&p1].history.vuln_window_reported, t(45));
        assert_eq!(pg.prim.peer_info[&p1].history.last_degraded, t(40));
        // nothing unshared: a further map sends nothing
        pg.out.clear();
        pg.on_active_advmap();
        assert!(info2_sent_to(&pg).is_empty());
    }

    #[test]
    fn durstat_min_merge() {
        let mut a = DurStat::default();
        a.record(5);
        a.record(3);
        let mut b = DurStat::default();
        b.merge(&a);
        b.merge(&DurStat::default());
        assert_eq!((b.n, b.sum_ns, b.max_ns, b.min_ns), (2, 8, 5, 3));
    }
}
