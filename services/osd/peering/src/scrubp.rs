// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Primary role of scrub (spec scrub.md 6): scheduling, operator requests, replica reservations, chunked
//! map collection (own map in slices + MOSDRepScrub to every acting peer), comparison ([`crate::scrubcmp`]),
//! result bookkeeping (stamps, error counters, state bits) and repair (the bad copies are entered in the
//! missing sets so the ordinary recovery pushes / pulls the authoritative copy).
//!
//! Client writes to objects of the chunk being scrubbed are refused by [`Pg::submit_write`] with
//! `WriteErr::Degraded`; the op layer parks them and retries (client-ops.md 16, "waiting_for_scrub").
//! Not implemented: write preemption, object_info digest rewrite, persisted scrub store, scrubbing PGs
//! while they recover.

use crate::pg::{ASt, PSt, Pg, St};
use crate::plog::{MissingSet, recompute_last_complete};
use crate::scrub::SLICE_OBJECTS;
use crate::scrubcmp::{EcGeom, ObjReport, compare_chunk, compare_chunk_ec};
use crate::store::PgStoreOps;
use crate::types::*;
use denc::types::{Hobject, PgShard, SpgT, UTime};
use pgwire::state as pgs;
use replwire::scrubmsgs::{MOSDRepScrub, MOSDRepScrubMap, MOSDScrubReserve, ScrubMap};
use std::collections::{BTreeMap, BTreeSet};

/// Scheduler inputs that only the OSD knows (load, windows, flags, recovery); set by `PgSet` before every tick.
#[derive(Debug, Clone, Copy)]
pub struct ScrubGate {
    /// Both time windows (hour of day and weekday) permit the current local time (spec scrub.md 12.1.1).
    pub window: bool,
    /// 1-minute host load average per online CPU strictly below `osd_scrub_load_threshold` (12.1.2).
    pub load: bool,
    /// A local or remote recovery reservation is held (`osd_scrub_during_recovery`, 12.1.3).
    pub recovering: bool,
    /// This tick is skipped for the low urgencies by `osd_scrub_backoff_ratio` (12.1.3).
    pub backoff: bool,
    /// Cluster / pool NOSCRUB.
    pub noscrub: bool,
    /// Cluster / pool NODEEP_SCRUB.
    pub nodeep: bool,
}
impl Default for ScrubGate {
    fn default() -> Self {
        ScrubGate {
            window: true,
            load: true,
            recovering: false,
            backoff: false,
            noscrub: false,
            nodeep: false,
        }
    }
}

/// Start class of a scrub session: which scheduling gates it observes (spec scrub.md 12.1.7 matrix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartClass {
    /// `periodic_regular` / `must_scrub`: every gate; `must_scrub` only drops the randomization (12.1.4).
    Periodic,
    /// `after_repair`: hour / weekday window and recovery only.
    AfterRepair,
    /// `operator_requested` / `must_repair`: no start gate (deliberately limited by `flashstore_scrub_operator_limits`,
    /// adr 0083 am. 2).
    Operator,
}

/// May a scrub of `class` start now? `deep` selects the NOSCRUB / NODEEP_SCRUB flag that applies (spec scrub.md
/// 12.1.7).
fn start_allowed(c: &ScrubCfg, class: StartClass, deep: bool, g: ScrubGate) -> bool {
    match class {
        StartClass::Operator => true,
        StartClass::AfterRepair => g.window && (c.during_recovery || !g.recovering),
        StartClass::Periodic => {
            g.window
                && g.load
                && !g.backoff
                && (!deep || !g.nodeep)
                && (deep || !g.noscrub)
                && (c.during_recovery || !g.recovering)
        }
    }
}

/// Deterministic 64-bit draw source (splitmix64): an explicit seed makes every scheduling draw reproducible.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SplitMix64(u64);
impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> Self {
        SplitMix64(seed)
    }
    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in `[0, 1)`.
    pub(crate) fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }
}

/// An operator (or auto repair) request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrubReq {
    pub deep: bool,
    pub repair: bool,
    /// Follow-up auto repair (not an operator request): stays limited.
    pub auto: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the OSD-wide local slot.
    LocalSlot,
    Reserving,
    Chunks,
}

#[derive(Debug)]
struct Chunk {
    start: Hobject,
    end: Hobject,
    /// Highest pending store token when the requests went out; our own map is built once it committed.
    barrier: u64,
    /// Requests sent (`sp_send_chunk`); until then writes are blocked but nothing is built.
    sent: bool,
    /// A client write hit the range (`osd_scrub_max_preemptions`): writes pass, the outstanding maps are drained and
    /// dropped, the range is scrubbed again with fewer objects.
    preempted: bool,
    built: bool,
    cursor: Hobject,
    local: ScrubMap,
    /// Member keys ([`Pg::sp_members`]) whose map is outstanding / arrived.
    waiting: BTreeSet<i32>,
    maps: BTreeMap<i32, ScrubMap>,
    t0: Mono,
    /// When our own map was complete (0 = not yet); the rest of the chunk waits for the peers' maps.
    t_built: Mono,
}

#[derive(Debug)]
struct Session {
    deep: bool,
    repair: bool,
    /// Replica reservations needed (periodic, or `flashstore_scrub_operator_limits`).
    reserve: bool,
    /// The operator / auto repair request this session serves: kept when the session fails (classic keeps the target
    /// with its urgency and only delays it, scrub.md 6.1).
    req: Option<ScrubReq>,
    /// Which start gates this session observes (NOSCRUB / NODEEP_SCRUB abort a running periodic one).
    class: StartClass,
    /// Chunks preempted by client writes so far (each halves the chunk size).
    preemptions: u32,
    periodic: bool,
    /// Follow-up verification after a repair.
    verify: bool,
    phase: Phase,
    /// Member keys to reserve / being asked (key, nonce, sent) / granted.
    to_reserve: Vec<i32>,
    cur: Option<(i32, u32, Mono)>,
    granted: Vec<i32>,
    next_start: Hobject,
    chunk: Option<Chunk>,
    sleep_until: Mono,
    chunks: u64,
    objects: u64,
    shallow: u64,
    deep_errs: u64,
    fix_shallow: u64,
    fix_deep: u64,
    repaired: u64,
    omap_keys: u64,
    omap_bytes: u64,
    /// Some object lacks authoritative local key lengths; retain the last complete PG totals.
    omap_incomplete: bool,
    large_omap: u64,
    found: Vec<ObjReport>,
    start: Mono,
    /// Deep scrub with dedup listing on: wall start from the dedup record clock, captured before any reads, so a later
    /// re-anchor cannot move the latest-scrub cutoff past records this session already collected.
    start_wall: Option<UTime>,
    /// Stage stamps for the finish note: local slot granted, reservations done; ns spent building our own maps /
    /// waiting for the peers' maps after that; slices of the local build.
    t_slot: Mono,
    t_resv: Mono,
    build_ns: u64,
    wait_ns: u64,
    slices: u64,
}

/// Listing after a shallow scrub: its reports merged with the last deep scrub's by object. Same user version:
/// the deep report with the shallow object/shard errors added and missing shard facts filled in; a newer shallow
/// version replaces the deep report; otherwise the deep report stands.
fn merge_levels(shallow: Vec<ObjReport>, deep: &[ObjReport]) -> Vec<ObjReport> {
    let mut merged: BTreeMap<Hobject, ObjReport> =
        deep.iter().map(|r| (r.soid.clone(), r.clone())).collect();
    for sh in shallow {
        match merged.get_mut(&sh.soid) {
            Some(dp) if sh.user_version == dp.user_version => {
                dp.obj_errors |= sh.obj_errors;
                for (shard, errors) in sh.shards {
                    *dp.shards.entry(shard).or_default() |= errors;
                }
                for (shard, info) in sh.info {
                    dp.info.entry(shard).or_insert(info);
                }
            }
            Some(dp) if sh.user_version < dp.user_version => {}
            _ => {
                merged.insert(sh.soid.clone(), sh);
            }
        }
    }
    merged.into_values().collect()
}

/// Primary scrub state of a PG instance.
#[derive(Debug, Default)]
pub(crate) struct ScrubPrim {
    pub req: Option<ScrubReq>,
    /// A repair queued pushes: verify with a deep scrub once clean again.
    pub verify: bool,
    pub gate: ScrubGate,
    pub retry_at: Mono,
    /// Fresh-draw counters of the two periodic targets: bumped whenever a level reschedules (its scrub finished, or an
    /// interval option changed), so every period draws a new random delay (spec scrub.md 12.1.4).
    shallow_draw: u64,
    deep_draw: u64,
    sess: Option<Session>,
    nonce: u32,
    work: bool,
    /// Inconsistencies of the last finished scrub (not yet repaired ones); after a shallow scrub merged with
    /// `deep_found` ([`merge_levels`]).
    pub found: Vec<ObjReport>,
    /// Reports of the last deep scrub: a shallow scrub cannot clear them (spec scrub.md, ScrubStore levels).
    deep_found: Vec<ObjReport>,
    /// A scrub finished on this PG instance: `found` is meaningful (`list-inconsistent-*` answers ENOENT before).
    pub ls_valid: bool,
    /// Scrubs finished on this PG instance (tests/diagnostics).
    pub done: u64,
    pub aborted: u64,
    /// Chunks preempted by client writes on this PG instance (tests/diagnostics).
    pub preempted: u64,
}

fn in_range(h: &Hobject, start: &Hobject, end: &Hobject) -> bool {
    h >= start && (end.max || h < end)
}

fn same_group(a: &Hobject, b: &Hobject) -> bool {
    a.pool == b.pool && a.hash == b.hash && a.nspace == b.nspace && a.key == b.key && a.oid == b.oid
}

fn ns_of(t: UTime) -> u64 {
    t.sec as u64 * SEC + t.nsec as u64
}
fn utime(ns: u64) -> UTime {
    UTime::new((ns / SEC) as u32, (ns % SEC) as u32)
}

impl Pg {
    /// Diagnostics (`dump_pgs`): primary session (phase, member asked with nonce and age, members left / granted), the
    /// pending operator request, aborts, and the replica reservation of this instance.
    pub fn scrub_debug(&self) -> String {
        let sess = self.sp.sess.as_ref().map(|s| {
            let cur = s
                .cur
                .map(|(k, n, t)| format!("{k}#{n}@{}ms", self.now.saturating_sub(t) / 1_000_000));
            format!(
                "{:?} cur={cur:?} left={:?} granted={:?}",
                s.phase, s.to_reserve, s.granted
            )
        });
        format!(
            "sess={sess:?} req={:?} aborted={} done={} retry_in={}ms replica={}",
            self.sp.req,
            self.sp.aborted,
            self.sp.done,
            self.sp.retry_at.saturating_sub(self.now) / 1_000_000,
            self.scrub_replica_debug()
        )
    }

    // ---- members -----------------------------------------------------------------------------------------

    /// Scrub key of a member instance: its acting position for EC pools (two positions may share one OSD, adr 0049
    /// am. 1), its OSD for replicated ones. Chunk maps, reservations and reports are keyed by it.
    fn sp_key(&self, p: PgShard) -> i32 {
        if self.pool.is_erasure {
            i32::from(p.shard.0)
        } else {
            p.osd
        }
    }

    /// The other members of the acting set as `(key, instance)`. EC: every position but ours, the other instance on
    /// our own OSD included (its requests and maps use local delivery, `PgSet::finish`).
    fn sp_members(&self) -> Vec<(i32, PgShard)> {
        if !self.pool.is_erasure {
            return self
                .peer_osds_acting()
                .into_iter()
                .map(|o| (o, ps(o)))
                .collect();
        }
        (0..self.acting.len())
            .filter(|i| self.acting[*i] >= 0 && self.acting[*i] != pgwire::NONE_OSD)
            .map(|i| PgShard {
                osd: self.acting[i],
                shard: denc::types::ShardId(i as i8),
            })
            .filter(|p| *p != self.me)
            .map(|p| (self.sp_key(p), p))
            .collect()
    }

    fn sp_member(&self, key: i32) -> Option<PgShard> {
        self.sp_members()
            .into_iter()
            .find(|(k, _)| *k == key)
            .map(|(_, p)| p)
    }

    /// `(osd, shard)` of a member key (reports, `list-inconsistent-obj`).
    fn sp_who(&self, key: i32) -> (i32, i8) {
        if key == self.sp_key(self.me) {
            return (self.me.osd, self.me.shard.0);
        }
        self.sp_member(key).map_or(
            if self.pool.is_erasure {
                (pgwire::NONE_OSD, key as i8)
            } else {
                (key, -1)
            },
            |p| (p.osd, p.shard.0),
        )
    }

    // ---- accessors ---------------------------------------------------------------------------------

    /// A primary scrub session is running.
    pub fn scrub_running(&self) -> bool {
        self.sp.sess.is_some()
    }
    /// Scrubs finished / aborted on this PG instance.
    pub fn scrub_counts(&self) -> (u64, u64) {
        (self.sp.done, self.sp.aborted)
    }
    /// Chunks preempted by client writes on this PG instance.
    pub fn scrub_preempted(&self) -> u64 {
        self.sp.preempted
    }
    /// Waiting for a local scrub slot (`osd_max_scrubs`).
    pub fn scrub_waiting_slot(&self) -> bool {
        self.sp
            .sess
            .as_ref()
            .is_some_and(|s| s.phase == Phase::LocalSlot)
    }
    /// Objects of the last scrub that stayed inconsistent (`rados list-inconsistent-obj` source).
    pub fn scrub_inconsistent(&self) -> &[ObjReport] {
        &self.sp.found
    }
    /// `rados list-inconsistent-obj|snapset` (pg op SCRUBLS): `(interval, encoded findings)` or a positive errno
    /// (EAGAIN: the interval changed since the client listed, ENOENT: nothing scrubbed since this PG instance started).
    pub fn scrub_ls(&self, arg: &crate::scrubls::LsArg) -> Result<(u32, Vec<Vec<u8>>), i32> {
        let interval = self.info.history.same_interval_since;
        if arg.interval != 0 && arg.interval != interval {
            return Err(11);
        }
        if !self.sp.ls_valid {
            return Err(2);
        }
        let vals = crate::scrubls::ls(
            &self.sp.found,
            self.sp_key(self.me),
            &|k| self.sp_who(k),
            arg,
        )
        .unwrap_or_default();
        Ok((interval, vals))
    }
    /// `scrub-abort`: drop the pending operator request and stop a running session (replica slots are released).
    /// Returns whether anything was aborted.
    pub fn scrub_abort(&mut self, now: Mono, store: &impl PgStoreOps) -> bool {
        self.now = now;
        let had = self.sp.req.is_some() || self.sp.sess.is_some();
        if self.sp.sess.is_some() {
            self.sp_abort("scrub aborted by operator");
        }
        // nothing of it stays pending
        self.sp.req = None;
        self.sp.verify = false;
        self.after_event(store);
        had
    }
    /// Operator request pending?
    pub fn scrub_requested(&self) -> Option<ScrubReq> {
        self.sp.req
    }
    /// Scheduler inputs (load, window, flags).
    pub fn set_scrub_gate(&mut self, g: ScrubGate) {
        self.sp.gate = g;
    }

    /// Scrub scheduling fields of `pg_stat_t` (`pg ls` SCRUB_SCHEDULING).
    pub(crate) fn sp_fill_stat(&self, s: &mut pgwire::PgStat) {
        s.scrub_is_active = false;
        s.scrub_is_deep = false;
        s.scrub_is_periodic = false;
        s.scrub_sched_status = 1;
        s.scrub_scheduled_at = UTime::default();
        s.objects_scrubbed = 0;
        s.scrub_duration = 0.0;
        if let Some(ss) = &self.sp.sess {
            s.scrub_sched_status = 2;
            s.scrub_is_active = true;
            s.scrub_is_deep = ss.deep;
            s.scrub_is_periodic = ss.periodic;
            s.objects_scrubbed = ss.objects as i64;
            s.scrub_scheduled_at = utime(self.wall_ns());
            s.scrub_duration = self.now.saturating_sub(ss.start) as f64 / SEC as f64;
        } else if let Some(r) = self.sp.req {
            s.scrub_sched_status = 4;
            s.scrub_is_deep = r.deep || r.repair;
            s.scrub_scheduled_at = utime(self.wall_ns());
        } else if self.sp.verify {
            s.scrub_sched_status = 4;
            s.scrub_is_deep = true;
            s.scrub_scheduled_at = utime(self.wall_ns());
        } else if self.is_primary() && matches!(self.st, St::Primary(PSt::Active(_))) {
            // a must_scrub target (invalid stats) is due now; every other target is stamp + a freshly drawn delay
            let (sh, dp) = self.sp_targets();
            let sh = if self.sp_must_scrub() {
                self.wall_ns()
            } else {
                sh
            };
            s.scrub_sched_status = 3;
            s.scrub_is_deep = dp <= sh;
            s.scrub_is_periodic = true;
            s.scrub_scheduled_at = utime(sh.min(dp));
            s.scrub_sched_duration_seconds = 0;
        }
    }

    fn wall_ns(&self) -> u64 {
        self.cfg.wall_base_ns + self.now
    }

    /// `ceph pg scrub|deep-scrub|repair`: MOSDScrub2 for a PG we lead. Silently ignored elsewhere.
    pub fn request_scrub(&mut self, now: Mono, deep: bool, repair: bool, store: &impl PgStoreOps) {
        self.now = now;
        if !self.is_primary() || self.refuse.is_some() {
            self.discard("scrub request at non-primary");
            return;
        }
        let cur = self.sp.req.unwrap_or(ScrubReq {
            deep: false,
            repair: false,
            auto: false,
        });
        self.sp.req = Some(ScrubReq {
            deep: cur.deep || deep || repair,
            repair: cur.repair || repair,
            auto: false,
        });
        self.sp.retry_at = 0;
        self.after_event(store);
    }

    // ---- bookkeeping hooks ---------------------------------------------------------------------------

    /// New interval / leaving the role: forget the session; replicas free their side by their own reset.
    pub(crate) fn sp_reset(&mut self) {
        self.sp_keep_target();
        if self.sp.sess.take().is_some() {
            self.slot_release(SlotPool::ScrubLocal);
            self.sp.aborted += 1;
        }
        self.state &= !(pgs::SCRUBBING | pgs::DEEP | pgs::REPAIR);
        self.sp.work = false;
    }

    /// The OSD-wide limiter granted the local slot.
    pub(crate) fn sp_local_granted(&mut self) {
        // the other instance on our own OSD needs no reservation: the local slot we hold covers this OSD
        let me = self.me.osd;
        // ascending (osd, shard), classic's sorted acting set: every PG takes replica slots in one global OSD order, so
        // sessions cannot hold one slot each while waiting for the other's (EC shard order did: OQ 28 O19)
        let mut members: Vec<(i32, PgShard)> = self
            .sp_members()
            .into_iter()
            .filter(|(_, p)| p.osd != me)
            .collect();
        members.sort_unstable_by_key(|(_, p)| (p.osd, p.shard.0));
        let peers: Vec<i32> = members.into_iter().map(|(k, _)| k).collect();
        let Some(s) = self.sp.sess.as_mut() else {
            self.slot_release(SlotPool::ScrubLocal);
            return;
        };
        if s.phase != Phase::LocalSlot {
            return;
        }
        s.t_slot = self.now;
        s.phase = if s.reserve {
            Phase::Reserving
        } else {
            s.t_resv = self.now;
            Phase::Chunks
        };
        let (deep, repair) = (s.deep, s.repair);
        s.to_reserve = peers;
        self.state |= pgs::SCRUBBING;
        if deep {
            self.state |= pgs::DEEP;
        }
        if repair {
            self.state |= pgs::REPAIR;
        }
        self.sp.work = true;
    }

    pub(crate) fn sp_local_rejected(&mut self) {
        self.sp_keep_target();
        if self.sp.sess.take().is_some() {
            self.sp.retry_at = self.now + self.cfg.scrub.retry;
        }
    }

    /// A scrub is queued, requested or running: the snap trimmer waits.
    pub(crate) fn scrub_pending(&self) -> bool {
        self.sp.sess.is_some() || self.sp.req.is_some() || self.sp.verify
    }

    pub(crate) fn sp_busy(&self) -> bool {
        if self.sp.work {
            return true;
        }
        self.sp
            .sess
            .as_ref()
            .and_then(|s| s.chunk.as_ref())
            .is_some_and(|c| {
                c.sent
                    && !c.built
                    && !c.preempted
                    && self.pending.range(..=c.barrier).next().is_none()
            })
    }

    /// Next time the scheduler needs to look at this PG.
    pub(crate) fn sp_deadline(&self) -> Option<Mono> {
        if !self.is_primary() || !matches!(self.st, St::Primary(PSt::Active(_))) {
            return None;
        }
        let c = &self.cfg.scrub;
        if let Some(s) = &self.sp.sess {
            let mut d = None::<Mono>;
            let mut upd = |t: Mono| d = Some(d.map_or(t, |x| x.min(t)));
            if let Some(ch) = &s.chunk {
                upd(ch.t0 + c.chunk_timeout);
            } else if s.sleep_until > 0 {
                upd(s.sleep_until);
            }
            return d;
        }
        if self.sp.req.is_some() || self.sp.verify {
            return Some(self.sp.retry_at.max(self.now + SEC));
        }
        let (sh, dp) = self.sp_targets();
        let at = if self.sp_must_scrub() {
            self.now
        } else {
            sh.min(dp).saturating_sub(self.cfg.wall_base_ns)
        };
        let at = at.max(self.sp.retry_at);
        Some(if at <= self.now {
            self.now + 5 * SEC
        } else {
            at
        })
    }

    /// The PG's statistics are invalid (`osd_scrub_invalid_stats`): its shallow target is due now and marked must
    /// (spec scrub.md 12.1.4). An EC primary flags its published statistics invalid by design (adr 0049 am. 5, the
    /// logical byte count is approximated), so that marker is no recount request.
    fn sp_must_scrub(&self) -> bool {
        self.cfg.scrub.invalid_stats && !self.pool.is_erasure && self.info.stats.stats_invalid
    }

    /// Interval of the shallow target in seconds: the pool's `scrub_min_interval` (> 0) overrides the OSD option,
    /// the randomization is unchanged (spec scrub.md 12.1.6).
    fn sp_min_interval(&self) -> f64 {
        self.pool
            .scrub_min_interval_ns
            .map_or(self.cfg.scrub.min_interval, |ns| ns as f64 / 1e9)
    }

    /// Interval of the deep target in seconds: the pool's `deep_scrub_interval` (> 0) overrides the OSD option
    /// (spec 12.1.6).
    fn sp_deep_interval(&self) -> f64 {
        self.pool
            .deep_scrub_interval_ns
            .map_or(self.cfg.scrub.deep_interval, |ns| ns as f64 / 1e9)
    }

    /// Draw source of the two periodic targets: the seed names the PG, the level and the level's draw counter, so a
    /// reschedule draws a new value and reading the schedule twice sees the same one.
    fn sp_draw(&self, level: u64) -> SplitMix64 {
        let ctr = if level == 0 {
            self.sp.shallow_draw
        } else {
            self.sp.deep_draw
        };
        let seed = (self.spg.pgid.pool.rotate_left(24))
            ^ u64::from(self.spg.pgid.seed)
            ^ (u64::from(self.spg.shard.0.max(0) as u8) << 48)
            ^ self.cfg.wall_base_ns
            ^ (level << 56)
            ^ ctr.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        SplitMix64::new(seed)
    }

    /// Shallow target delay: `min_interval * (1 + randomize_ratio * r)`, `r` uniform in `[0, 1)` (spec 12.1.4).
    fn sp_shallow_delay(&self) -> u64 {
        let iv = self.sp_min_interval();
        let ratio = self.cfg.scrub.randomize_ratio;
        let r = if ratio > 0.0 {
            self.sp_draw(0).next_f64()
        } else {
            0.0
        };
        (iv * (1.0 + ratio * r) * SEC as f64) as u64
    }

    /// Deep target delay: normal distribution with mean `deep_interval` and sigma `deep_interval * deep_interval_cv`,
    /// clamped to the mean +/- 2 sigma (spec 12.1.4).
    fn sp_deep_delay(&self) -> u64 {
        let iv = self.sp_deep_interval();
        let cv = self.cfg.scrub.deep_interval_cv;
        let z = if cv > 0.0 {
            let mut r = self.sp_draw(1);
            let u1 = r.next_f64().max(f64::MIN_POSITIVE);
            let u2 = r.next_f64();
            // Box-Muller, one normal draw
            ((-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()).clamp(-2.0, 2.0)
        } else {
            0.0
        };
        ((iv * (1.0 + cv * z)).max(0.0) * SEC as f64) as u64
    }

    /// The two periodic targets in wall ns: last stamp plus its freshly drawn delay (spec 12.1.4).
    fn sp_targets(&self) -> (u64, u64) {
        let h = &self.info.history;
        (
            ns_of(h.last_scrub_stamp).saturating_add(self.sp_shallow_delay()),
            ns_of(h.last_deep_scrub_stamp).saturating_add(self.sp_deep_delay()),
        )
    }

    /// An interval option changed: both queued targets reschedule with a fresh random delay (spec 12.1.4).
    pub(crate) fn sp_redraw_targets(&mut self) {
        self.sp.shallow_draw = self.sp.shallow_draw.wrapping_add(1);
        self.sp.deep_draw = self.sp.deep_draw.wrapping_add(1);
    }

    // ---- reservations ---------------------------------------------------------------------------------------

    pub(crate) fn sp_on_reserve_reply(&mut self, from: i32, m: MOSDScrubReserve) {
        let k = self.sp_key(m.from);
        let member = self.sp_member(k);
        let Some(s) = self.sp.sess.as_mut() else {
            self.discard("scrub reserve reply without session");
            return;
        };
        if s.phase != Phase::Reserving {
            self.discard("scrub reserve reply in wrong phase");
            return;
        }
        let Some((key, nonce, _)) = s.cur else {
            self.discard("scrub reserve reply without request");
            return;
        };
        if k != key
            || m.from.osd != from
            || member != Some(m.from)
            || (m.nonce != 0 && m.nonce != nonce)
        {
            self.discard("stale scrub reserve reply");
            return;
        }
        match m.ty {
            MOSDScrubReserve::GRANT => {
                s.granted.push(k);
                s.cur = None;
                self.sp.work = true;
            }
            MOSDScrubReserve::REJECT => {
                self.sp_abort("replica rejected the reservation");
            }
            _ => self.discard("scrub reserve request/release at primary"),
        }
    }

    fn sp_send_reserve(&mut self, key: i32, ty: i32, nonce: u32) {
        let Some(p) = self.sp_member(key) else {
            return;
        };
        let m = MOSDScrubReserve {
            pgid: SpgT {
                pgid: self.spg.pgid,
                shard: p.shard,
            },
            map_epoch: self.map.epoch(),
            ty,
            from: self.me,
            nonce,
            wait_for_resources: true,
        };
        self.send_repl(p.osd, m, 0);
    }

    // ---- abort / finish ---------------------------------------------------------------------------------

    fn sp_release_all(&mut self) {
        let Some(s) = self.sp.sess.take() else { return };
        for o in s.granted.iter().copied().chain(s.cur.map(|c| c.0)) {
            self.sp_send_reserve(o, MOSDScrubReserve::RELEASE, 0);
        }
        self.slot_release(SlotPool::ScrubLocal);
        self.state &= !(pgs::SCRUBBING | pgs::DEEP | pgs::REPAIR);
        self.sp.work = false;
    }

    /// A session ends unfinished: its operator request / repair verification stays pending (merged with one that came
    /// meanwhile) and is retried after the delay, as classic `delay_on_failure` keeps the target's urgency.
    fn sp_keep_target(&mut self) {
        let Some(s) = self.sp.sess.as_ref() else {
            return;
        };
        let (req, verify) = (s.req, s.verify);
        if let Some(r) = req {
            self.sp.req = Some(match self.sp.req {
                Some(c) => ScrubReq {
                    deep: c.deep || r.deep,
                    repair: c.repair || r.repair,
                    auto: c.auto && r.auto,
                },
                None => r,
            });
        }
        self.sp.verify |= verify;
    }

    fn sp_abort(&mut self, why: &'static str) {
        self.error(why);
        self.sp_keep_target();
        self.sp_release_all();
        self.sp.aborted += 1;
        self.sp.retry_at = self.now + self.cfg.scrub.retry;
    }

    fn sp_finish(&mut self) {
        let Some(s) = self.sp.sess.as_ref() else {
            return;
        };
        let (deep, repair, verify, periodic) = (s.deep, s.repair, s.verify, s.periodic);
        let (mut shallow, mut deep_errs) = (s.shallow, s.deep_errs);
        if repair {
            shallow = shallow.saturating_sub(s.fix_shallow);
            deep_errs = deep_errs.saturating_sub(s.fix_deep);
        }
        let (omap_keys, omap_bytes, large, omap_incomplete) =
            (s.omap_keys, s.omap_bytes, s.large_omap, s.omap_incomplete);
        let repaired = s.repaired;
        let mut found: Vec<ObjReport> = if repair {
            s.found
                .iter()
                .filter(|r| r.auth.is_none() || r.obj_errors & !crate::scrubcmp::oerr::NO_AUTH != 0)
                .cloned()
                .collect()
        } else {
            s.found.clone()
        };
        if deep {
            self.sp.deep_found = found.clone();
        } else {
            found = merge_levels(found, &self.sp.deep_found);
        }
        if shallow + deep_errs == 0 {
            self.notes.push(format!(
                "INFO {} {} ok",
                self.spg.pgid,
                if deep { "deep-scrub" } else { "scrub" }
            ));
        }
        if let Some(s) = self.sp.sess.as_ref() {
            let ms = |ns: u64| ns / 1_000_000;
            self.notes.push(format!(
                "pg {}: {} {} in {} ms (slot {} reserve {} build {} peer-wait {} ms, {} chunks {} slices {} objects)",
                self.spg,
                if deep { "deep-scrub" } else { "scrub" },
                if shallow + deep_errs == 0 { "ok" } else { "errors" },
                ms(self.now.saturating_sub(s.start)),
                ms(s.t_slot.saturating_sub(s.start)),
                ms(s.t_resv.saturating_sub(s.t_slot)),
                ms(s.build_ns),
                ms(s.wait_ns),
                s.chunks,
                s.slices,
                s.objects,
            ));
        }
        let wall = self.wall_ns();
        {
            let sum = &mut self.info.stats.stats.sum;
            sum.num_shallow_scrub_errors = shallow as i64;
            if deep {
                sum.num_deep_scrub_errors = deep_errs as i64;
                sum.num_large_omap_objects = large as i64;
                if !omap_incomplete {
                    sum.num_omap_bytes = omap_bytes as i64;
                    sum.num_omap_keys = omap_keys as i64;
                }
            }
            sum.num_scrub_errors = sum.num_shallow_scrub_errors + sum.num_deep_scrub_errors;
        }
        // the scrub result replaces the stats a split left invalid (adr 0029)
        self.info.stats.stats_invalid = false;
        self.info.stats.parent_split_bits = 0;
        if deep {
            self.info.stats.omap_stats_invalid = omap_incomplete;
            if omap_incomplete {
                self.notes.push(format!(
                    "WARN {} deep-scrub: logical OMAP key/value total unavailable from authoritative local metadata; retaining previous complete OMAP totals",
                    self.spg
                ));
            }
        }
        let errs = self.info.stats.stats.sum.num_scrub_errors;
        let dur = self
            .sp
            .sess
            .as_ref()
            .map_or(0, |s| (self.now.saturating_sub(s.start) / SEC) as i32);
        self.info.stats.last_scrub_duration = dur;
        let last = self.info.last_update;
        let start_wall = self.sp.sess.as_ref().and_then(|s| s.start_wall);
        let h = &mut self.info.history;
        h.last_scrub = last;
        h.last_scrub_stamp = utime(wall);
        if deep {
            h.last_deep_scrub = last;
            h.last_deep_scrub_stamp = utime(wall);
            if let Some(t) = start_wall {
                h.last_deep_scrub_start_stamp = t;
            }
        }
        if errs == 0 {
            h.last_clean_scrub_stamp = utime(wall);
        }
        self.info_dirty = true;
        self.sp.found = found;
        self.sp.ls_valid = true;
        self.sp.done += 1;
        // both targets reschedule: a deep scrub advances the shallow stamps too (spec scrub.md 12.1.4), and each
        // reschedule draws a new random delay
        self.sp.shallow_draw = self.sp.shallow_draw.wrapping_add(1);
        if deep {
            self.sp.deep_draw = self.sp.deep_draw.wrapping_add(1);
        }
        self.sp_release_all();
        if errs == 0 {
            self.state &= !(pgs::INCONSISTENT | pgs::FAILED_REPAIR);
        } else if verify {
            self.state |= pgs::FAILED_REPAIR;
        }
        if repaired > 0 {
            self.sp.verify = true;
            self.sp_start_repair_recovery();
        } else if verify {
            self.sp.verify = false;
        }
        if periodic
            && !repair
            && errs > 0
            && errs as u64 <= self.cfg.scrub.auto_repair_num_errors
            && self.cfg.scrub.auto_repair
        {
            self.sp.req = Some(ScrubReq {
                deep: true,
                repair: true,
                auto: true,
            });
        }
        self.share_pg_info();
    }

    /// Entries were added to the missing sets: let the normal recovery machinery push / pull them.
    fn sp_start_repair_recovery(&mut self) {
        recompute_last_complete(&self.log, &mut self.info, &self.missing);
        self.info_dirty = true;
        if !matches!(
            self.st,
            St::Primary(PSt::Active(ASt::Clean | ASt::Recovered))
        ) {
            return; // recovery already running / will notice through the missing sets
        }
        self.state &= !pgs::CLEAN;
        self.state |= pgs::REPAIR;
        self.update_degraded_bits();
        self.start_recovery_reservation();
    }

    // ---- main step ---------------------------------------------------------------------------------------------

    /// Primary part of the scrub machine; runs at the end of every public entry point.
    pub(crate) fn sp_step(&mut self, store: &impl PgStoreOps) {
        self.sp.work = false;
        if !self.is_primary() || self.refuse.is_some() || self.st == St::ToDelete {
            self.sp.req = None;
            self.sp.verify = false;
            return;
        }
        // a PG preparing a merge does not scrub (split-merge.md 6.1)
        let active =
            matches!(self.st, St::Primary(PSt::Active(_))) && self.state & pgs::PREMERGE == 0;
        if !active {
            if self.sp.sess.is_some() {
                self.sp_abort("scrub: pg left active");
            }
            return;
        }
        self.sp_sync_bits();
        // noscrub / nodeep-scrub set while a periodic scrub runs: it is aborted at the next step (spec scrub.md 12.1.6;
        // operator requests and the after-repair verification ignore the flags)
        if let Some(s) = self.sp.sess.as_ref()
            && s.class == StartClass::Periodic
            && ((s.deep && self.sp.gate.nodeep) || (!s.deep && self.sp.gate.noscrub))
        {
            self.sp_abort("scrub: noscrub/nodeep-scrub set");
        }
        if self.sp.sess.is_none() {
            self.sp_maybe_start(|| store.dedup_wall_ns());
        }
        if self.sp.sess.is_some() {
            self.sp_advance(store);
        }
    }

    fn sp_sync_bits(&mut self) {
        let sum = &self.info.stats.stats.sum;
        if sum.num_scrub_errors > 0 {
            self.state |= pgs::INCONSISTENT;
        } else {
            self.state &= !(pgs::INCONSISTENT | pgs::FAILED_REPAIR);
        }
        if self.sp.sess.is_none()
            && self.state & pgs::REPAIR != 0
            && matches!(self.st, St::Primary(PSt::Active(ASt::Clean)))
        {
            self.state &= !pgs::REPAIR;
        }
        // stamps of a brand new PG: now (so a fresh cluster does not scrub everything at once)
        let h = &mut self.info.history;
        if h.last_scrub_stamp == UTime::default() && h.last_deep_scrub_stamp == UTime::default() {
            let t = utime(self.cfg.wall_base_ns + self.now);
            h.last_scrub_stamp = t;
            h.last_deep_scrub_stamp = t;
            h.last_clean_scrub_stamp = t;
            self.info_dirty = true;
        }
    }

    fn sp_maybe_start(&mut self, dedup_wall: impl FnOnce() -> Option<u64>) {
        // A scheduled scrub may start between snaps (SNAPTRIM_WAIT, no trim step in flight) so a long trim queue does
        // not starve the periodic scrub (CS-5566, adr 0037); it never starts while a trim run is active (SNAPTRIM). An
        // operator request keeps classic's deferral under both bits (spec scrub.md 12.1.7, "not bypassed"). The trimmer
        // re-kicks when the scrub ends (`trim_permit` waits on `scrub_pending`).
        let operator = matches!(self.sp.req, Some(r) if !r.auto);
        if self.state & pgs::SNAPTRIM != 0 || (operator && self.state & pgs::SNAPTRIM_WAIT != 0) {
            self.sp.retry_at = self.now + self.cfg.scrub.retry_trimming;
            return;
        }
        if !matches!(self.st, St::Primary(PSt::Active(ASt::Clean)))
            || self.state & pgs::CLEAN == 0
            || !self.missing.is_empty()
        {
            return;
        }
        if self.now < self.sp.retry_at {
            return;
        }
        let c = &self.cfg.scrub;
        let g = self.sp.gate;
        let (deep, repair, class, periodic, verify);
        let mut auto = false;
        let req = self.sp.req.take();
        if let Some(r) = req {
            auto = r.auto;
            (deep, repair) = (r.deep || r.repair, r.repair);
            class = StartClass::Operator;
            (periodic, verify) = (false, false);
        } else if self.sp.verify {
            if !start_allowed(c, StartClass::AfterRepair, true, g) {
                return;
            }
            self.sp.verify = false;
            (deep, repair, class, periodic, verify) =
                (true, false, StartClass::AfterRepair, false, true);
        } else {
            let wall = self.wall_ns();
            let (sh, dp) = self.sp_targets();
            let must = self.sp_must_scrub();
            // the deep scrub wins when both are due; nodeep / noscrub each block one level only
            let deep_due = start_allowed(c, StartClass::Periodic, true, g) && wall >= dp;
            let shallow_due =
                start_allowed(c, StartClass::Periodic, false, g) && (must || wall >= sh);
            if !(deep_due || shallow_due) {
                return;
            }
            (deep, repair, class, periodic, verify) =
                (deep_due, false, StartClass::Periodic, true, false);
        }
        // periodic scrubs reserve and may be refused; operator ones queue for a slot (or bypass the limit, classic);
        // an operator repair never waits (classic force path: no slot limit, no reservations: a replica wait could stall it)
        let forced = class != StartClass::Periodic;
        let reserve = !forced || (self.cfg.scrub.operator_limits && (!repair || auto));
        let start_wall = (deep && self.cfg.scrub.dedup_start_stamp)
            .then(|| utime(dedup_wall().unwrap_or_else(|| self.wall_ns())));
        self.sp.sess = Some(Session {
            deep,
            repair,
            reserve,
            req,
            class,
            preemptions: 0,
            periodic,
            verify,
            phase: Phase::LocalSlot,
            to_reserve: vec![],
            cur: None,
            granted: vec![],
            next_start: Hobject::MIN(),
            chunk: None,
            sleep_until: 0,
            chunks: 0,
            objects: 0,
            shallow: 0,
            deep_errs: 0,
            fix_shallow: 0,
            fix_deep: 0,
            repaired: 0,
            omap_keys: 0,
            omap_bytes: 0,
            omap_incomplete: false,
            large_omap: 0,
            found: vec![],
            start: self.now,
            start_wall,
            t_slot: 0,
            t_resv: 0,
            build_ns: 0,
            wait_ns: 0,
            slices: 0,
        });
        let op = if reserve {
            SlotOp::Request {
                immediate: !forced,
                prio: 0,
            }
        } else {
            SlotOp::Force
        };
        self.slot_ask(SlotPool::ScrubLocal, op);
    }

    fn sp_advance(&mut self, store: &impl PgStoreOps) {
        let now = self.now;
        let cfg = self.cfg.clone();
        let Some(s) = self.sp.sess.as_mut() else {
            return;
        };
        match s.phase {
            Phase::LocalSlot => {}
            Phase::Reserving => {
                // waits for the answer: no timeout (classic has none; requests go out in one global OSD order, so
                // reservations cannot wait on each other in a cycle; an interval change ends the session)
                if s.cur.is_some() {
                    return;
                }
                if s.to_reserve.is_empty() {
                    s.t_resv = now;
                    s.phase = Phase::Chunks;
                    return self.sp_advance(store);
                }
                let osd = s.to_reserve.remove(0);
                self.sp.nonce += 1;
                let nonce = self.sp.nonce;
                if let Some(s) = self.sp.sess.as_mut() {
                    s.cur = Some((osd, nonce, now));
                }
                self.sp_send_reserve(osd, MOSDScrubReserve::REQUEST, nonce);
            }
            Phase::Chunks => {
                let Some(ch) = s.chunk.as_ref() else {
                    if now < s.sleep_until {
                        return;
                    }
                    return self.sp_start_chunk(store);
                };
                if now >= ch.t0 + cfg.scrub.chunk_timeout {
                    eprintln!(
                        "WARNING TIMEOUT scrub chunk exceeded {}s (pg {:?}, aborting scrub)",
                        cfg.scrub.chunk_timeout / SEC,
                        self.spg
                    );
                    self.sp_abort("scrub: chunk timed out");
                    return;
                }
                if ch.preempted {
                    // the maps asked for before the preemption are dropped as they come; then the range again, smaller
                    if ch.waiting.is_empty() {
                        s.chunk = None;
                        self.sp.work = true;
                    }
                    return;
                }
                self.sp_send_chunk();
                self.sp_build_local(store);
                self.sp_try_finish_chunk();
            }
        }
    }

    // ---- chunks -----------------------------------------------------------------------------------------------

    /// End of the chunk starting at `start`: `min..max` objects, a head is never split from its clones.
    /// `None` = the local listing failed (the scrub must abort; a partial chunk would skip objects silently).
    fn sp_select_end(
        &self,
        store: &impl PgStoreOps,
        start: &Hobject,
        deep: bool,
        preemptions: u32,
    ) -> Option<Hobject> {
        let c = &self.cfg.scrub;
        let (min, max) = if deep {
            (c.chunk_min, c.chunk_max)
        } else {
            (c.shallow_chunk_min, c.shallow_chunk_max)
        };
        // every preemption halves the chunk (classic), down to 3 objects (or the configured minimum if smaller)
        let div = 1usize << preemptions.min(16);
        let min = (min / div).max(min.min(3)).max(1);
        let max = (max / div).max(min);
        let l = store.list_objects(self.spg, start, min, max.max(1)).ok()?;
        let Some(last) = l.last() else {
            return Some(Hobject::MAX());
        };
        let mut last = last.clone();
        let mut next = l.next;
        while !next.max && same_group(&next, &last) {
            let more = store.list_objects(self.spg, &next, 1, 1).ok()?;
            match more.last() {
                Some(h) => last = h.clone(),
                None => break,
            }
            next = more.next;
        }
        if !next.max {
            // A peer may hold clones missing from our listing. Start the next range before its whole group,
            // including clones created while that group's head is still outside this chunk's write block.
            next.snap = denc::types::SnapId(0);
        }
        Some(next)
    }

    /// Select the next chunk and block client writes to it; the requests go out once the range is quiet
    /// ([`Self::sp_send_chunk`]).
    fn sp_start_chunk(&mut self, store: &impl PgStoreOps) {
        let Some(s) = self.sp.sess.as_ref() else {
            return;
        };
        let (start, deep, pre) = (s.next_start.clone(), s.deep, s.preemptions);
        let Some(end) = self.sp_select_end(store, &start, deep, pre) else {
            self.sp_abort("scrub: local object listing failed");
            return;
        };
        let peers: Vec<i32> = self.sp_members().into_iter().map(|(k, _)| k).collect();
        let now = self.now;
        store.reset_scrub(self.spg);
        if let Some(s) = self.sp.sess.as_mut() {
            if s.chunks == 0 {
                self.notes.push(format!(
                    "DEBUG {} {} starts",
                    self.spg.pgid,
                    if s.deep { "deep-scrub" } else { "scrub" }
                ));
            }
            s.chunks += 1;
            s.chunk = Some(Chunk {
                cursor: start.clone(),
                start,
                end,
                barrier: 0,
                sent: false,
                preempted: false,
                built: false,
                local: ScrubMap::default(),
                waiting: peers.into_iter().collect(),
                maps: BTreeMap::new(),
                t0: now,
                t_built: 0,
            });
        }
        self.sp_send_chunk();
        self.sp.work = true;
    }

    /// Ask the peers for their maps of the blocked chunk and fix our own barrier, once every write accepted before the
    /// block is committed on all shards ([`Self::sp_write_unacked_in`]). Everything committed before the barrier is in
    /// our map, and every peer has applied each write into the range before it builds its own.
    fn sp_send_chunk(&mut self) {
        let Some(ch) = self.sp.sess.as_ref().and_then(|s| s.chunk.as_ref()) else {
            return;
        };
        if ch.sent || self.sp_write_unacked_in(&ch.start, &ch.end) {
            return;
        }
        let (start, end, deep) = (
            ch.start.clone(),
            ch.end.clone(),
            self.sp.sess.as_ref().unwrap().deep,
        );
        let peers: Vec<PgShard> = ch
            .waiting
            .iter()
            .filter_map(|k| self.sp_member(*k))
            .collect();
        let barrier = self.pending.keys().next_back().copied().unwrap_or(0);
        let epoch = self.map.epoch();
        // priority of the PG's scrub operations: a pool `scrub_priority` (> 0) overrides `osd_scrub_priority`
        let priority = self.pool.scrub_priority.unwrap_or(self.cfg.scrub.priority);
        for p in peers {
            let m = MOSDRepScrub {
                pgid: SpgT {
                    pgid: self.spg.pgid,
                    shard: p.shard,
                },
                map_epoch: epoch,
                chunky: true,
                start: start.clone(),
                end: end.clone(),
                deep,
                seed: 0xFFFF_FFFF,
                min_epoch: self.last_peering_reset,
                priority,
                ..Default::default()
            };
            self.send_repl(p.osd, m, 0);
        }
        if let Some(ch) = self.sp.sess.as_mut().and_then(|s| s.chunk.as_mut()) {
            ch.barrier = barrier;
            ch.sent = true;
        }
    }

    fn sp_build_local(&mut self, store: &impl PgStoreOps) {
        let last_update = self.info.last_update;
        let pending_blocks = |pg: &Pg, b: u64| pg.pending.range(..=b).next().is_some();
        let Some(ch) = self.sp.sess.as_ref().and_then(|s| s.chunk.as_ref()) else {
            return;
        };
        if !ch.sent || ch.built || ch.preempted || pending_blocks(self, ch.barrier) {
            return;
        }
        let deep = self.sp.sess.as_ref().is_some_and(|s| s.deep);
        let spg = self.spg;
        let ecp = self
            .pool
            .ec
            .as_ref()
            .filter(|e| e.supported)
            .map(|e| (crate::ecopt::scrub_mode(e), e.chunk_size));
        if let Some(s) = self.sp.sess.as_mut() {
            s.slices += 1;
        }
        let Some(ch) = self.sp.sess.as_mut().and_then(|s| s.chunk.as_mut()) else {
            return;
        };
        if ch.local.valid_through == Default::default() {
            ch.local.valid_through = last_update;
        }
        let (max_obj, max_bytes) = (
            SLICE_OBJECTS,
            if deep {
                self.cfg.scrub.slice_bytes
            } else {
                u64::MAX
            },
        );
        store.scrub_role(spg, true);
        let part = match ecp {
            Some((mode, chunk)) => store.build_scrub_map_ec(
                spg, &ch.cursor, &ch.end, deep, max_obj, max_bytes, mode, chunk,
            ),
            None => store.build_scrub_map(spg, &ch.cursor, &ch.end, deep, max_obj, max_bytes),
        };
        if let Some(error) = part.error {
            self.notes.push(format!("pg {}: {error}", self.spg));
            self.sp_abort("local scrub enumeration failed");
            return;
        }
        let (kt, bt) = (
            self.cfg.scrub.large_omap_keys,
            self.cfg.scrub.large_omap_bytes,
        );
        ch.local
            .objects
            .extend(part.objects.into_iter().map(|(h, mut o)| {
                o.apply_large_omap(kt, bt);
                (h, o)
            }));
        match part.next {
            Some(n) => {
                ch.cursor = n;
                self.sp.work = true;
            }
            None => {
                ch.built = true;
                ch.t_built = self.now;
                self.sp.work = true;
                let (s, e) = (ch.start.clone(), ch.end.clone());
                self.snapmap_scrub(store, &s, &e, deep);
            }
        }
    }

    pub(crate) fn sp_on_map(&mut self, from: i32, m: MOSDRepScrubMap) {
        let lpr = self.last_peering_reset;
        let key = self.sp_key(m.from);
        let member = self.sp_member(key);
        let Some(ch) = self.sp.sess.as_mut().and_then(|s| s.chunk.as_mut()) else {
            self.discard("scrub map without chunk");
            return;
        };
        if m.map_epoch != lpr
            || m.from.osd != from
            || member != Some(m.from)
            || !ch.waiting.remove(&key)
        {
            self.discard("unexpected scrub map");
            return;
        }
        if ch.preempted {
            // asked for before our own preemption: drained, never compared
            self.sp.work = true;
            return;
        }
        if m.preempted {
            self.sp_abort("replica scrub enumeration failed or was preempted");
            return;
        }
        ch.maps.insert(key, m.map);
        self.sp.work = true;
    }

    fn sp_try_finish_chunk(&mut self) {
        let Some(s) = self.sp.sess.as_ref() else {
            return;
        };
        let Some(ch) = s.chunk.as_ref() else { return };
        if !ch.built || ch.preempted || !ch.waiting.is_empty() {
            return;
        }
        let deep = s.deep;
        let repair = s.repair;
        let me = self.sp_key(self.me);
        let s = self.sp.sess.as_mut().expect("session");
        let ch = s.chunk.take().expect("chunk");
        s.build_ns += ch.t_built.saturating_sub(ch.t0);
        s.wait_ns += self.now.saturating_sub(ch.t_built);
        let mut maps = ch.maps;
        maps.insert(me, ch.local);
        let rep = match self.pool.ec.as_ref().filter(|e| e.supported) {
            Some(e) => compare_chunk_ec(
                &maps,
                me,
                deep,
                self.cfg.scrub.max_object_size,
                EcGeom {
                    stripe_width: u64::from(e.stripe_width),
                    chunk: u64::from(e.chunk_size),
                    k: e.k as usize,
                    // EC member keys are acting positions
                    opt: e.optimized.then(|| {
                        maps.keys()
                            .filter_map(|o| {
                                let raw =
                                    e.chunk_mapping.iter().position(|x| *x as i32 == *o)? as u32;
                                Some((*o, raw))
                            })
                            .collect()
                    }),
                    crc_check: e.optimized
                        && e.plugin == "isa"
                        && (e.technique == "reed_sol_van" || (e.technique == "cauchy" && e.m == 1)),
                },
            ),
            None => compare_chunk(&maps, me, deep, self.cfg.scrub.max_object_size),
        };
        s.objects += rep.num_objects;
        s.shallow += rep.shallow_errors;
        s.deep_errs += rep.deep_errors;
        s.omap_incomplete |= rep.omap_incomplete;
        match s
            .omap_keys
            .checked_add(rep.omap_keys)
            .zip(s.omap_bytes.checked_add(rep.omap_bytes))
        {
            Some((keys, bytes)) if keys <= i64::MAX as u64 && bytes <= i64::MAX as u64 => {
                s.omap_keys = keys;
                s.omap_bytes = bytes;
            }
            _ => s.omap_incomplete = true,
        }
        s.large_omap += rep.large_omap;
        if let Some((o, k, b)) = &rep.large_omap_first {
            // the text the mon's LARGE_OMAP_OBJECTS detail tells operators to search for
            self.notes.push(format!(
                "WARN Large omap object found. Object: {o} PG: {} Key count: {k} Size (bytes): {b}",
                self.spg
            ));
        }
        for o in rep
            .objects
            .iter()
            .filter(|o| o.obj_errors & crate::scrubcmp::oerr::DATA_DIGESTS != 0)
        {
            self.notes.push(format!(
                "ERROR {} {}: data digests are inconsistent",
                self.spg,
                crate::scrubcmp::hobj_str(&o.soid)
            ));
        }
        s.next_start = ch.end.clone();
        let done = ch.end.max;
        let mut repairs: Vec<(Hobject, i32, denc::types::Eversion)> = Vec::new();
        if repair {
            s.fix_shallow += rep.fixable_shallow;
            s.fix_deep += rep.fixable_deep;
            for o in &rep.objects {
                for osd in o.bad_shards() {
                    repairs.push((o.soid.clone(), osd, o.auth_version));
                }
            }
            s.repaired += repairs.len() as u64;
        }
        s.found.extend(rep.objects);
        s.sleep_until = if self.cfg.scrub.sleep > 0 {
            self.now + self.cfg.scrub.sleep
        } else {
            0
        };
        // repair: the bad copies become "missing at the authoritative version"; writes to them park
        // (WriteErr::Degraded) until the recovery fixed them
        for (soid, key, v) in repairs {
            if key == me {
                self.missing
                    .add(soid, v, denc::types::Eversion::default(), false);
            } else if let Some(p) = self.sp_member(key) {
                self.prim
                    .peer_missing
                    .entry(p)
                    .or_insert_with(|| MissingSet::new(true))
                    .add(soid, v, denc::types::Eversion::default(), false);
            }
        }
        if done {
            self.sp_finish();
        } else {
            self.sp.work = true;
        }
    }

    /// A write into `[start, end)` that is not committed on every shard yet: replicated = a log entry newer than
    /// `pg_committed_to` (a replica has not acked its repop), EC = a write queued, being read, or with sub-writes unacked.
    /// The chunk waits for it before any map is asked for or built: a replica that has not applied it would report the
    /// object's previous state, a false inconsistency (and a repair would roll the write back). Writes into the chunk
    /// are blocked meanwhile, so only those accepted before the block drain (one commit round trip). Relying on the
    /// request queueing behind the repops on the same session is not enough: a link replaced mid-chunk carries the
    /// request ahead of a repop still in a faulted carrier's replay.
    pub(crate) fn sp_write_unacked_in(&self, start: &Hobject, end: &Hobject) -> bool {
        if self.pool.is_erasure {
            return self.ec_write_unacked_in(start, end);
        }
        self.log
            .entries()
            .iter()
            .rev()
            .take_while(|e| e.version > self.pg_committed_to)
            .any(|e| in_range(&e.soid, start, end))
    }

    /// Hook of `submit_write`: is `soid` inside the chunk being scrubbed?
    pub(crate) fn scrub_blocks_write(&self, soid: &Hobject) -> bool {
        self.sp
            .sess
            .as_ref()
            .and_then(|s| s.chunk.as_ref())
            .is_some_and(|c| !c.preempted && in_range(soid, &c.start, &c.end))
    }

    /// Hook of `submit_write`, before the checks: a write into the chunk preempts it while the scrub has preemptions
    /// left (`osd_scrub_max_preemptions`, classic): the write passes, the chunk is dropped (maps already asked for are
    /// drained first) and the range is scrubbed again with half the objects. Nothing on the wire changes: the replicas
    /// answer the old request as usual. Afterwards writes wait for the chunk (classic).
    pub(crate) fn sp_preempt<'a>(&mut self, mut soids: impl Iterator<Item = &'a Hobject>) {
        let max = self.cfg.scrub.max_preemptions;
        let Some(s) = self.sp.sess.as_mut() else {
            return;
        };
        let Some(ch) = s.chunk.as_mut() else { return };
        if ch.preempted || s.preemptions >= max || !soids.any(|h| in_range(h, &ch.start, &ch.end)) {
            return;
        }
        s.preemptions += 1;
        self.sp.preempted += 1;
        if ch.sent && !ch.waiting.is_empty() {
            ch.preempted = true;
        } else {
            s.chunk = None;
        }
        self.sp.work = true;
    }
}

/// Cluster and pool scrub flags (osdmap NOSCRUB / NODEEP_SCRUB), set by the OSD on every map.
#[derive(Debug, Clone, Default)]
pub struct ScrubFlags {
    pub noscrub: bool,
    pub nodeep: bool,
    pub pool_noscrub: BTreeSet<u64>,
    pub pool_nodeep: BTreeSet<u64>,
}

/// One cyclic window `[begin, end)` over `period` values: equal ends mean the whole period, `begin > end` wraps.
fn in_window(begin: u32, end: u32, period: u32, v: u32) -> bool {
    if begin == end || begin >= period || end >= period {
        return true;
    }
    if begin < end {
        v >= begin && v < end
    } else {
        v >= begin || v < end
    }
}

/// Both scrub windows permit `t`: hour of day `[begin_hour, end_hour)` AND weekday `[begin_week_day, end_week_day)`
/// (spec scrub.md 12.1.1, 0 = Sunday). The caller passes the OSD's local time.
pub fn in_scrub_window(c: &ScrubCfg, t: LocalTime) -> bool {
    in_window(c.begin_hour, c.end_hour, 24, t.hour)
        && in_window(c.begin_week_day, c.end_week_day, 7, t.weekday)
}

impl Pg {
    /// Range `[start, end)` of the chunk being scrubbed (writes to it are parked).
    pub fn scrub_range(&self) -> Option<(Hobject, Hobject)> {
        self.sp
            .sess
            .as_ref()
            .and_then(|s| s.chunk.as_ref())
            .filter(|c| !c.preempted)
            .map(|c| (c.start.clone(), c.end.clone()))
    }
}

#[cfg(test)]
mod sched_tests {
    use super::*;
    use crate::map::synth::SynthMap;
    use crate::pg::{ASt, PSt, Pg, St};
    use denc::types::{PgT, ShardId};
    use pgwire::PgInfo;
    use std::rc::Rc;
    use std::sync::Arc;

    fn cfg() -> Config {
        let mut c = Config::new(0);
        c.wall_base_ns = 1_700_000_000 * SEC;
        c.scrub.min_interval = 10.0;
        c.scrub.deep_interval = 100.0;
        c.scrub.randomize_ratio = 0.5;
        c
    }

    /// A clean replicated primary with both scrub stamps at `now`.
    fn primary(mut c: Config) -> Pg {
        let map = SynthMap::new(3).with_osd(0, 1).with_pool(1, 3, 2, 1);
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        };
        c.whoami = 0;
        let mut pg = Pg::blank(Arc::new(c), spg, Rc::new(map), PgInfo::new(spg));
        pg.acting = vec![0];
        pg.up = vec![0];
        pg.acting_primary = 0;
        pg.up_primary = 0;
        pg.st = St::Primary(PSt::Active(ASt::Clean));
        pg.state = pgs::CLEAN | pgs::ACTIVE;
        pg.now = 1_000 * SEC;
        let t = utime(pg.wall_ns());
        pg.info.history.last_scrub_stamp = t;
        pg.info.history.last_deep_scrub_stamp = t;
        pg
    }

    fn closed_gate() -> ScrubGate {
        ScrubGate {
            window: false,
            load: false,
            recovering: true,
            backoff: true,
            noscrub: true,
            nodeep: true,
        }
    }

    #[test]
    fn ec_scrub_replies_require_the_mapped_shard_instance() {
        for acting in [vec![0, 1, 2], vec![0, 1, 1]] {
            let mut pg = primary(cfg());
            pg.pool.is_erasure = true;
            pg.me.shard = ShardId(0);
            pg.acting = acting.clone();
            pg.sp.req = Some(ScrubReq {
                deep: true,
                repair: true,
                auto: false,
            });
            pg.sp_maybe_start(|| None);
            pg.sp_start_chunk(&crate::store::MemStore::new());
            let map = |osd, shard| MOSDRepScrubMap {
                pgid: pg.spg,
                map_epoch: pg.last_peering_reset,
                from: PgShard {
                    osd,
                    shard: ShardId(shard),
                },
                preempted: false,
                map: Default::default(),
            };
            let forged = map(99, 1);
            let wrong_member = map(0, 1);
            let valid: Vec<_> = (1..3).map(|s| map(acting[s], s as i8)).collect();
            for m in [forged, wrong_member] {
                pg.sp_on_map(m.from.osd, m);
                let ch = pg.sp.sess.as_ref().unwrap().chunk.as_ref().unwrap();
                assert_eq!(ch.waiting.len(), 2, "forged map consumed a shard");
                assert!(ch.maps.is_empty());
            }
            for m in valid {
                pg.sp_on_map(m.from.osd, m);
            }
            let ch = pg.sp.sess.as_ref().unwrap().chunk.as_ref().unwrap();
            assert!(ch.waiting.is_empty());
            assert_eq!(ch.maps.len(), 2);
        }
    }

    #[test]
    fn ec_scrub_reservations_require_the_mapped_shard_instance() {
        let mut pg = primary(cfg());
        pg.pool.is_erasure = true;
        pg.me.shard = ShardId(0);
        pg.acting = vec![0, 1, 1];
        pg.sp.req = Some(ScrubReq {
            deep: true,
            repair: false,
            auto: false,
        });
        pg.sp_maybe_start(|| None);
        for key in [1, 2] {
            let s = pg.sp.sess.as_mut().unwrap();
            s.phase = Phase::Reserving;
            s.cur = Some((key, 7, pg.now));
            for osd in [99, 0, 1] {
                pg.sp_on_reserve_reply(
                    osd,
                    MOSDScrubReserve {
                        pgid: pg.spg,
                        map_epoch: pg.last_peering_reset,
                        from: PgShard {
                            osd,
                            shard: ShardId(key as i8),
                        },
                        nonce: 7,
                        ty: MOSDScrubReserve::GRANT,
                        wait_for_resources: false,
                    },
                );
                let s = pg.sp.sess.as_ref().unwrap();
                assert_eq!(s.cur.is_none(), osd == 1, "OSD {osd} reservation identity");
            }
        }
        assert_eq!(pg.sp.sess.as_ref().unwrap().granted, vec![1, 2]);
    }

    /// Both windows must permit; hour and weekday wrap; equal ends mean the whole period (spec scrub.md 12.1.1).
    #[test]
    fn windows_require_hour_and_weekday() {
        let mut c = ScrubCfg::default();
        let at = |hour, weekday| LocalTime { hour, weekday };
        // default 0/0: no restriction
        for h in [0, 7, 23] {
            assert!(in_scrub_window(&c, at(h, 3)));
        }
        // 20/6 allows 20:00-05:59 and wraps; 5/6 (Friday) is closed
        c.begin_hour = 20;
        c.end_hour = 6;
        assert!(in_scrub_window(&c, at(20, 3)));
        assert!(in_scrub_window(&c, at(23, 3)));
        assert!(in_scrub_window(&c, at(0, 3)));
        assert!(in_scrub_window(&c, at(5, 3)));
        assert!(!in_scrub_window(&c, at(6, 3)));
        assert!(!in_scrub_window(&c, at(19, 3)));
        // 6/20 (no wrap)
        c.begin_hour = 6;
        c.end_hour = 20;
        assert!(in_scrub_window(&c, at(6, 3)));
        assert!(in_scrub_window(&c, at(19, 3)));
        assert!(!in_scrub_window(&c, at(5, 3)));
        assert!(!in_scrub_window(&c, at(20, 3)));
        // hour 0/0 again, weekdays 5/1 = Friday, Saturday, Sunday (0 = Sunday)
        c.begin_hour = 0;
        c.end_hour = 0;
        c.begin_week_day = 5;
        c.end_week_day = 1;
        for d in [5, 6, 0] {
            assert!(in_scrub_window(&c, at(12, d)), "weekday {d}");
        }
        for d in [1, 2, 3, 4] {
            assert!(!in_scrub_window(&c, at(12, d)), "weekday {d}");
        }
        // 1/5 = Monday..Thursday, no wrap
        c.begin_week_day = 1;
        c.end_week_day = 5;
        for d in [1, 2, 3, 4] {
            assert!(in_scrub_window(&c, at(12, d)), "weekday {d}");
        }
        for d in [0, 5, 6] {
            assert!(!in_scrub_window(&c, at(12, d)), "weekday {d}");
        }
        // both must permit: hour is fine, the weekday is not
        c.begin_week_day = 1;
        c.end_week_day = 2;
        assert!(!in_scrub_window(&c, at(12, 3)));
        // invalid values are treated as "no restriction" instead of gating everything forever
        c.begin_hour = 42;
        assert!(in_scrub_window(&c, at(12, 1)));
        assert!(!in_scrub_window(&c, at(12, 3)));
    }

    /// The urgency matrix (spec scrub.md 12.1.7): what each start class observes.
    #[test]
    fn start_gate_matrix() {
        let c = ScrubCfg::default();
        let ok = ScrubGate::default();
        let closed = closed_gate();
        for deep in [true, false] {
            assert!(start_allowed(&c, StartClass::Periodic, deep, ok));
            assert!(!start_allowed(&c, StartClass::Periodic, deep, closed));
            assert!(start_allowed(&c, StartClass::Operator, deep, closed));
            // after_repair: window and recovery only
            assert!(!start_allowed(&c, StartClass::AfterRepair, deep, closed));
            let mut g = closed;
            g.window = true;
            g.recovering = false;
            assert!(start_allowed(&c, StartClass::AfterRepair, deep, g));
            g.load = true;
            g.backoff = true;
            g.noscrub = true;
            g.nodeep = true;
            assert!(start_allowed(&c, StartClass::AfterRepair, deep, g));
        }
        // load, backoff, flags and recovery each block a periodic start on their own
        for m in [
            |g: &mut ScrubGate| g.load = false,
            |g: &mut ScrubGate| g.backoff = true,
            |g: &mut ScrubGate| g.recovering = true,
            |g: &mut ScrubGate| g.window = false,
        ] {
            let mut g = ok;
            m(&mut g);
            assert!(!start_allowed(&c, StartClass::Periodic, true, g));
        }
        // noscrub blocks shallow only, nodeep blocks deep only (12.1.6)
        let mut g = ok;
        g.noscrub = true;
        assert!(!start_allowed(&c, StartClass::Periodic, false, g));
        assert!(start_allowed(&c, StartClass::Periodic, true, g));
        let mut g = ok;
        g.nodeep = true;
        assert!(start_allowed(&c, StartClass::Periodic, false, g));
        assert!(!start_allowed(&c, StartClass::Periodic, true, g));
        // osd_scrub_during_recovery permits periodic / after_repair starts
        let c = ScrubCfg {
            during_recovery: true,
            ..Default::default()
        };
        let mut g = ok;
        g.recovering = true;
        assert!(start_allowed(&c, StartClass::Periodic, true, g));
        assert!(start_allowed(&c, StartClass::AfterRepair, true, g));
    }

    /// Shallow delay: uniform in `[min_interval, min_interval * (1 + ratio))`, a fresh draw per reschedule.
    #[test]
    fn seeded_shallow_draws_stay_within_bounds() {
        let mut pg = primary(cfg());
        let (iv, ratio) = (10u64, 0.5f64);
        let lo = (iv as f64 * SEC as f64) as u64;
        let hi = (iv as f64 * (1.0 + ratio) * SEC as f64) as u64;
        let mut seen = std::collections::BTreeSet::new();
        for draw in 0..64 {
            pg.sp.shallow_draw = draw;
            let d = pg.sp_shallow_delay();
            assert!(
                (lo..hi).contains(&d),
                "draw {draw}: {d} outside [{lo}, {hi})"
            );
            seen.insert(d);
        }
        assert!(seen.len() > 1, "every reschedule must draw a new delay");
        // no randomization: exactly the interval
        let mut c = cfg();
        c.scrub.randomize_ratio = 0.0;
        let pg = primary(c);
        assert_eq!(pg.sp_shallow_delay(), iv * SEC);
    }

    #[test]
    fn fractional_global_intervals_preserve_subsecond_deadlines() {
        let mut c = cfg();
        c.scrub.min_interval = 0.5;
        c.scrub.deep_interval = 10.75;
        c.scrub.randomize_ratio = 0.0;
        c.scrub.deep_interval_cv = 0.0;
        let pg = primary(c);
        assert_eq!(pg.sp_shallow_delay(), SEC / 2);
        assert_eq!(pg.sp_deep_delay(), 10 * SEC + 3 * SEC / 4);
    }

    #[test]
    fn deep_scrub_start_wall_survives_clock_reanchor() {
        let mut c = cfg();
        c.scrub.dedup_start_stamp = true;
        let mut pg = primary(c);
        let started = utime(pg.wall_ns());
        pg.sp.req = Some(ScrubReq {
            deep: true,
            repair: false,
            auto: false,
        });
        pg.sp_maybe_start(|| None);
        assert!(pg.sp.sess.is_some());

        // A record collected before NTP advances the wall clock must remain
        // newer than the session's start, even after its completion is published.
        pg.now += SEC;
        let record_stamp = utime(pg.wall_ns());
        Arc::make_mut(&mut pg.cfg).wall_base_ns += 3_600 * SEC;
        pg.now += SEC;
        let completed = utime(pg.wall_ns());
        pg.sp_finish();
        let h = &pg.info.history;
        assert_eq!(h.last_deep_scrub_start_stamp, started);
        assert!(h.last_deep_scrub_start_stamp <= record_stamp);
        assert_eq!(h.last_deep_scrub_stamp, completed);
        assert_eq!(pg.info.stats.last_scrub_duration, 2);
    }

    #[test]
    fn deep_scrub_start_uses_record_clock_after_backward_step() {
        let mut c = cfg();
        c.scrub.dedup_start_stamp = true;
        let mut pg = primary(c);
        // The OSD metadata wall stays forward-only; record timestamps follow
        // realtime. A new scrub after a backward step must use the latter too.
        let record_clock = std::cell::Cell::new(pg.wall_ns() - 3_600 * SEC);
        let started = utime(record_clock.get());
        pg.sp.req = Some(ScrubReq {
            deep: true,
            repair: false,
            auto: false,
        });
        pg.sp_maybe_start(|| Some(record_clock.get()));
        assert!(pg.sp.sess.is_some());
        record_clock.set(record_clock.get() + SEC);
        let record_stamp = utime(record_clock.get());
        pg.now += 2 * SEC;
        pg.sp_finish();
        let h = &pg.info.history;
        assert_eq!(h.last_deep_scrub_start_stamp, started);
        assert!(h.last_deep_scrub_start_stamp <= record_stamp);
        assert_eq!(h.last_deep_scrub_stamp, utime(pg.wall_ns()));
    }

    #[test]
    fn dedup_wall_is_only_sampled_for_an_enabled_deep_scrub_start() {
        for (enabled, deep) in [(false, true), (true, false)] {
            let mut c = cfg();
            c.scrub.dedup_start_stamp = enabled;
            let mut pg = primary(c);
            pg.sp.req = Some(ScrubReq {
                deep,
                repair: false,
                auto: false,
            });
            pg.sp_maybe_start(|| panic!("this session needs no dedup clock"));
            assert!(pg.sp.sess.is_some());
        }
        let mut c = cfg();
        c.scrub.dedup_start_stamp = true;
        let mut pg = primary(c);
        pg.sp_maybe_start(|| panic!("no scrub target is due"));
        assert!(pg.sp.sess.is_none());
    }

    /// Deep delay: normal around `deep_interval` with sigma `interval * cv`, clamped to +/- 2 sigma.
    #[test]
    fn seeded_deep_draws_stay_within_two_sigma() {
        let mut pg = primary(cfg());
        let (iv, cv) = (100u64, 0.2f64);
        let lo = ((1.0 - 2.0 * cv) * iv as f64 * SEC as f64) as u64;
        let hi = ((1.0 + 2.0 * cv) * iv as f64 * SEC as f64) as u64;
        let mut seen = std::collections::BTreeSet::new();
        let mut sum = 0.0;
        for draw in 0..512 {
            pg.sp.deep_draw = draw;
            let d = pg.sp_deep_delay();
            assert!(d >= lo && d <= hi, "draw {draw}: {d} outside [{lo}, {hi}]");
            seen.insert(d);
            sum += d as f64 / (iv as f64 * SEC as f64);
        }
        assert!(seen.len() > 100, "the delay must vary across reschedules");
        let mean = sum / 512.0;
        assert!((mean - 1.0).abs() < 0.05, "mean {mean} is not ~1.0");
        // cv 0: exactly the interval
        let mut c = cfg();
        c.scrub.deep_interval_cv = 0.0;
        let pg = primary(c);
        assert_eq!(pg.sp_deep_delay(), iv * SEC);
    }

    /// `osd_scrub_backoff_ratio`: the seeded draw skips the low urgencies about that often, none at 0, all at 1.
    #[test]
    fn seeded_backoff_draw_rate() {
        let mut r = SplitMix64::new(0x5EED);
        let n = 10_000;
        let skipped = (0..n).filter(|_| r.next_f64() < 0.66).count();
        let rate = skipped as f64 / n as f64;
        assert!((0.62..0.70).contains(&rate), "skip rate {rate}");
    }

    /// `must_scrub`: invalid statistics move the shallow target to now, still gated by window / load / flags / backoff
    /// / recovery (spec 12.1.4); an EC primary's permanently invalid marker is no recount request.
    #[test]
    fn must_scrub_from_invalid_stats_obeys_the_gates() {
        // not due: stamps are now and min_interval is 10 s
        let mut pg = primary(cfg());
        pg.sp_maybe_start(|| None);
        assert!(pg.sp.sess.is_none());
        // invalid stats: due at once, no randomization involved
        pg.info.stats.stats_invalid = true;
        pg.sp_maybe_start(|| None);
        assert!(
            pg.sp
                .sess
                .as_ref()
                .is_some_and(|s| !s.deep && s.class == StartClass::Periodic)
        );
        // each gate blocks it
        for g in [
            ScrubGate {
                load: false,
                ..ScrubGate::default()
            },
            ScrubGate {
                window: false,
                ..ScrubGate::default()
            },
            ScrubGate {
                backoff: true,
                ..ScrubGate::default()
            },
            ScrubGate {
                recovering: true,
                ..ScrubGate::default()
            },
            ScrubGate {
                noscrub: true,
                ..ScrubGate::default()
            },
        ] {
            let mut pg = primary(cfg());
            pg.info.stats.stats_invalid = true;
            pg.set_scrub_gate(g);
            pg.sp_maybe_start(|| None);
            assert!(pg.sp.sess.is_none(), "started under {g:?}");
        }
        // osd_scrub_during_recovery permits the recovery case
        let mut c = cfg();
        c.scrub.during_recovery = true;
        let mut pg = primary(c);
        pg.info.stats.stats_invalid = true;
        pg.set_scrub_gate(ScrubGate {
            recovering: true,
            ..ScrubGate::default()
        });
        pg.sp_maybe_start(|| None);
        assert!(pg.sp.sess.is_some());
        // osd_scrub_invalid_stats off: invalid stats schedule nothing
        let mut c = cfg();
        c.scrub.invalid_stats = false;
        let mut pg = primary(c);
        pg.info.stats.stats_invalid = true;
        pg.sp_maybe_start(|| None);
        assert!(pg.sp.sess.is_none());
    }

    /// An operator request starts through every closed gate (spec scrub.md 12.1.7); after_repair still observes the
    /// window and recovery.
    #[test]
    fn operator_and_after_repair_classes() {
        let mut pg = primary(cfg());
        pg.set_scrub_gate(closed_gate());
        pg.sp.req = Some(ScrubReq {
            deep: true,
            repair: false,
            auto: false,
        });
        pg.sp_maybe_start(|| None);
        assert!(
            pg.sp
                .sess
                .as_ref()
                .is_some_and(|s| s.class == StartClass::Operator && s.deep)
        );

        let mut pg = primary(cfg());
        pg.set_scrub_gate(closed_gate());
        pg.sp.verify = true;
        pg.sp_maybe_start(|| None);
        assert!(pg.sp.sess.is_none(), "after_repair observes the window");
        assert!(pg.sp.verify, "a gated verification stays queued");
        pg.set_scrub_gate(ScrubGate::default());
        pg.sp_maybe_start(|| None);
        assert!(
            pg.sp
                .sess
                .as_ref()
                .is_some_and(|s| s.class == StartClass::AfterRepair)
        );
    }

    /// `osd_scrub_max_interval` is not a scheduling input: an overdue PG stays queued while the window is closed.
    #[test]
    fn no_forced_start_beyond_the_max_interval() {
        let mut pg = primary(cfg());
        // 30 days old, way past every interval
        pg.now = 40 * 86_400 * SEC;
        pg.info.history.last_scrub_stamp = utime(pg.now - 30 * 86_400 * SEC);
        pg.info.history.last_deep_scrub_stamp = utime(pg.now - 30 * 86_400 * SEC);
        pg.set_scrub_gate(ScrubGate {
            window: false,
            ..ScrubGate::default()
        });
        pg.sp_maybe_start(|| None);
        assert!(pg.sp.sess.is_none());
        pg.set_scrub_gate(ScrubGate::default());
        pg.sp_maybe_start(|| None);
        assert!(pg.sp.sess.is_some());
    }

    /// CS-5566 (adr 0037): a scrub never starts while a trim run is active (SNAPTRIM), whatever its class.
    #[test]
    fn no_scrub_starts_while_a_trim_run_is_active() {
        for operator in [false, true] {
            let mut pg = primary(cfg());
            pg.info.stats.stats_invalid = true;
            pg.state |= pgs::SNAPTRIM;
            if operator {
                pg.sp.req = Some(ScrubReq {
                    deep: false,
                    repair: false,
                    auto: false,
                });
            }
            pg.sp_maybe_start(|| None);
            assert!(
                pg.sp.sess.is_none(),
                "operator={operator}: a scrub started under SNAPTRIM"
            );
        }
    }

    /// CS-5566 (adr 0037): between snaps (SNAPTRIM_WAIT) a scheduled scrub interleaves, but an operator request keeps
    /// the classic deferral (spec scrub.md 12.1.7, "not bypassed").
    #[test]
    fn operator_scrub_waits_while_a_scheduled_scrub_interleaves() {
        let mut pg = primary(cfg());
        pg.info.stats.stats_invalid = true;
        pg.state |= pgs::SNAPTRIM_WAIT;
        pg.sp_maybe_start(|| None);
        assert!(
            pg.sp.sess.is_some(),
            "a scheduled scrub interleaves between snaps"
        );
        let mut pg = primary(cfg());
        pg.info.stats.stats_invalid = true;
        pg.state |= pgs::SNAPTRIM_WAIT;
        pg.sp.req = Some(ScrubReq {
            deep: false,
            repair: false,
            auto: false,
        });
        pg.sp_maybe_start(|| None);
        assert!(
            pg.sp.sess.is_none(),
            "an operator scrub waits for the queue to drain"
        );
        assert!(pg.sp.req.is_some(), "the operator request stays pending");
    }
}
