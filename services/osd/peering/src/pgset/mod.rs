// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! [`PgSet`]: the per-core container the OSD drives. Owns the PGs, the retained map epochs, the
//! remote reservation limiter, message routing (map waiting, PG creation from create info, DNE
//! replies, parking) and output filtering (peering.md 4, 7.1-7.4).

use crate::map::MapHandle;
use crate::pg::{Pg, St, WriteErr, wait_epoch};
use crate::primary::WriteReq;
use crate::scrubp::{ScrubFlags, ScrubGate, SplitMix64, in_scrub_window};
use crate::split::MergeStatus;
use crate::store::PgStoreOps;
use crate::types::*;
use denc::types::{Eversion, PgT, ShardId, SpgT};
use pgwire::{
    MOSDPGCreate2, MOSDPGLog, MOSDPGNotify2, PastIntervals, PeeringMsg, PgHistory, PgInfo, PgLog,
    PgNotify, QueryType,
};
use replwire::ReplMsg;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A slot this core asked the budget owner for ([`PgSet::slot_open`]).
#[derive(Debug, Clone, Copy)]
struct SlotOpen {
    /// Counter of the latest request ([`SlotReq::seq`]).
    seq: u32,
    /// The owner granted it (a queued request is not yet).
    granted: bool,
    /// Priority of the latest request (a local reservation).
    prio: u32,
}

/// A `scrub_purged_snaps` walk in progress: PGs still to check, the mapper position inside the first one.
struct PurgedScan {
    todo: std::collections::VecDeque<SpgT>,
    cursor: Option<Vec<u8>>,
    total: crate::snaptrim::PurgedScrub,
}

/// Withheld creates handed back by [`PgSet::take_resumable_creates`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ResumeCreates {
    /// Oldest MOSDPGCreate2 epoch of the withheld mon creates: ask the mon for its creates again from there.
    pub mon_from: Option<u32>,
    /// PGs whose create info from a peer was withheld: force a new interval (their primary sends it again).
    pub peer: Vec<PgT>,
}

/// All PGs of one core/OSD.
pub struct PgSet {
    cfg: Arc<Config>,
    /// This OSD's fill ([`PgSet::set_local_full`]): replicas refuse backfill above backfillfull, pushes above failsafe.
    local_full: LocalFull,
    /// Per PG: the EC objects woken since the last [`PgSet::take_ec_wake`] (parked client ops of those objects may run).
    /// One entry per PG; the buffer is reused (no allocation once grown).
    ec_woke: Vec<(SpgT, crate::wake::WakeSet)>,
    /// PGs woken with failed EC client reads since the last [`PgSet::take_ec_wake`].
    ec_err_pgs: Vec<SpgT>,
    /// [`Self::ec_err_pgs`] handed to the op layer with the last wake: their errors are dropped once the parked ops ran
    /// ([`PgSet::ec_read_errors_delivered`]).
    ec_err_due: Vec<SpgT>,
    /// Generation of the next [`PgSet::take_ec_wake`] (stamps the EC read failures it announces).
    ec_wake_gen: u64,
    /// PGs with data-path messages held for the store (`held::Held`, adr 0021 am. 25).
    repop_wait: BTreeSet<SpgT>,
    /// PGs whose last tick ran timers only (persist batch bound, store admission): their events still run.
    tick_defer: BTreeSet<SpgT>,
    /// Some were deferred with store admission open (only the batch bound held them): due at once.
    tick_again: bool,
    maps: BTreeMap<u32, MapHandle>,
    cur: Option<MapHandle>,
    pgs: crate::pgmap::PgMap,
    waiting_map: BTreeMap<u32, Vec<Inbound>>,
    waiting_pg: BTreeMap<SpgT, Vec<Inbound>>,
    /// MOSDPGCreate2 stamped with a map epoch we do not have yet, by that epoch.
    waiting_create: BTreeMap<u32, Vec<MOSDPGCreate2>>,
    /// Per-OSD PG hard limit: `mon_max_pg_per_osd` x `osd_max_pg_per_osd_hard_ratio` (peering.md 7.3 rule 3a); a
    /// create at or above it is withheld ([`PgSet::set_pg_hard_limit`]).
    pg_hard_limit: f64,
    /// This core's PG count when the OSD-wide count ([`Config::num_pgs_hint`]) was last handed in: the OSD-wide
    /// estimate is that count plus this core's change since.
    pgs_at_hint: u64,
    /// Mon creates withheld by the hard limit: PG -> epoch of the MOSDPGCreate2 (re-solicited from the oldest).
    withheld_mon: BTreeMap<SpgT, u32>,
    /// Creates from peer messages withheld by the hard limit: PG -> we are its acting primary.
    withheld_peer: BTreeMap<SpgT, bool>,
    /// Newest `have` sent in an [`Action::RequestMap`]: repeat asks are suppressed until the map advances.
    map_req: u32,
    /// Create-from-message parked because its start epoch is older than the oldest kept map (the maps are being
    /// loaded from the persisted store), by PG. Never replaced by a newer map: a primary that missed an interval with
    /// acked writes could go active without it (open question 13d).
    parked_old: BTreeMap<SpgT, ParkedOld>,
    /// Outstanding [`Action::NeedOldMaps`] `from`s (one request per parked PG and chunk).
    old_out: BTreeSet<u32>,
    /// While creates are parked: the oldest kept map when the first was parked. Nothing from there up is trimmed: the
    /// replay ends there, a gap would hide intervals.
    old_hold: Option<u32>,
    /// Newest epoch `advance_set` may step to (a chunked old-map replay stops at the end of its chunk).
    adv_limit: u32,
    /// The OSD-wide budgets (scrub, backfill / recovery reservations, snap trim): `Some` on the one core that keeps
    /// them (core 0, or the only core), the others reach it by message ([`PgSet::slot_op`]).
    slots: Option<crate::slots::Slots>,
    /// Slot replies for PGs of this core, delivered by the next collect or tick.
    slot_in: Vec<SlotReply>,
    /// OSD-wide recovery-op limit (`osd_recovery_max_active`), kept by the budget owner core ([`crate::recops`]).
    ops_owner: Option<crate::recops::OpsOwner>,
    /// This core's quota of it and its split over the PGs.
    ops_lease: crate::recops::OpsLease,
    /// Answers of the owner not yet applied.
    ops_in: Vec<crate::OpsReply>,
    /// Slots this core asked for and has not released, with the counter of the latest request ([`SlotReq::seq`]).
    slot_open: BTreeMap<(SlotPool, SpgT), SlotOpen>,
    slot_seq: u32,
    /// Closed vulnerability windows / rebuild episodes of this core's primaries (cumulative, [`PgSet::latch_perf`]).
    latch: crate::latch::LatchPerf,
    scrub_flags: ScrubFlags,
    /// 1-minute host load average per online CPU (`osd_scrub_load_threshold` gate).
    scrub_load: f64,
    /// Local wall clock of the OSD host for the scrub windows, refreshed by the OSD on every tick (spec 12.1.1).
    local_time: LocalTime,
    /// Any recovery reservation held as last broadcast by the budget owner (spec 12.1.3); the owner reads its slots.
    recovering: bool,
    /// `osd_scrub_backoff_ratio` decision of the current tick (spec 12.1.3).
    backoff: bool,
    /// Draw source of the backoff decision.
    scrub_rng: SplitMix64,
    parked_scrub_cmds: Vec<replwire::MOSDScrub2>,
    up_thru_emitted: u32,
    up_thru_want: u32,
    /// PGs whose last collect found them stopped by the past-interval bounds check (peering.md 3.8). Empty on a healthy
    /// OSD: the outbound gate of [`Self::finish`] costs one `is_empty` then and resolves the exact PG only when it fires.
    bounds_stopped_pgs: BTreeSet<SpgT>,
    out: Vec<Action>,
    /// PG messages one instance of this OSD sent to another (two EC shards of one PG here, adr 0049 am. 1): delivered
    /// in order by [`Self::finish_at`], never through the cluster messenger. The producer (`None` = a message released
    /// from a queue, not produced here) keeps the past-interval bounds gate per instance.
    loopq: std::collections::VecDeque<(Option<SpgT>, Inbound)>,
    /// Messages that were dropped because no PG exists and none should (reason counters).
    pub dropped: BTreeMap<&'static str, u64>,
    /// PG creates whose (history, past intervals) missed classic's required bounds; logged, created anyway.
    pub create_bounds_mismatch: u64,
    /// Pools (erasure) this OSD is passive for; each is reported once through `notices`.
    passive_seen: BTreeSet<u64>,
    /// Per pool: the support gate verdict + kill switch (`pool_state`) and `pg_num` (`pg_shard`) of the current map.
    pool_cache: std::cell::RefCell<BTreeMap<u64, PoolCached>>,
    /// Decline mode (adr 0039 am. 1): per declined PG the last_complete high-water mark we report; counters by answer.
    declined: BTreeMap<SpgT, Eversion>,
    pub decline_stats: BTreeMap<&'static str, u64>,
    /// Pools this OSD holds (or held) PG data of: stored at boot (all cores, `note_held_pools`), served or forgotten
    /// since. Such a pool is never declined: an empty answer would let classic skip a prior-interval member and
    /// activate from a stale shard (adr 0039 am. 1 point 7); silence keeps classic waiting (`osd lost` / restart).
    held_pools: BTreeSet<u64>,
    notices: Vec<String>,
    /// Peering-state timings of this core's PGs (`dump_pg_recovery_stats`).
    rec_stats: crate::recstats::RecStats,
    /// The running `scrub_purged_snaps` walk of this core.
    purged_scan: Option<PurgedScan>,
    /// Lab (NV_PHASE): note PGs that only the full 1 s tick moved (a missing deadline / lost wake-up).
    tick_diag: bool,
    trace: Vec<String>,
    /// Children created by a split whose peers have not spoken yet (see [`SplitGate`]).
    split_gate: BTreeMap<SpgT, SplitGate>,
    /// Current-map speech for existing PG identities (a gate may be created after its first message arrived).
    /// Cleared on map advance: older gates reopen then and cannot need this evidence again.
    spoke: BTreeMap<(i32, SpgT), u32>,
    /// Peers known to run croit-flashstore-osd.
    flashstore: BTreeSet<i32>,
    /// Shared copy of `croit-flashstore-osd` handed to the PGs (`Pg::nv_peers`).
    nv_arc: std::sync::Arc<BTreeSet<i32>>,
    /// Peers known to accept long object names (adr 0021 am. 30): classic OSDs and croit-flashstore-osd with `FEAT_LONG_NAME`.
    long_peers: BTreeSet<i32>,
    /// Sends held back by `split_gate` (in order).
    held: Vec<Action>,
    /// Merge sources parked at the epoch that removes them, waiting for their target to absorb them.
    parked_src: BTreeMap<(u32, SpgT), Pg>,
    /// Merge readiness of the pending merge of each pool, by source pgid (split-merge.md 6.1).
    merge_reg: BTreeMap<PgT, MergeReg>,
    /// Sources already reported to the mon (`sent_ready_to_merge_source`).
    merge_sent: BTreeSet<PgT>,
    /// Multi-core: PGs off their hash shard (adr 0031); every core keeps the whole table.
    place: BTreeMap<PgT, u32>,
    /// The store's PGs were loaded (`load_pgs` / `note_loaded`): before that a pool switch loads nothing (multi-core
    /// boot: the core's moves still run, its store holds instances that are leaving it).
    loaded: bool,
    /// Multi-core: instances `detach`ed for a move to another core; their collection stays until the destination acked
    /// the copy and must never be loaded here again (a pool switch would revive a stale copy).
    detached: BTreeSet<SpgT>,
    /// Peers whose cluster session was lost (adr 0071), see `peers.rs`.
    peer_links: BTreeMap<i32, peers::PeerLink>,
    pub peer_stats: PeerStats,
}

impl std::fmt::Debug for PgSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgSet")
            .field("osd", &self.cfg.whoami)
            .field("pgs", &self.pgs.len())
            .finish_non_exhaustive()
    }
}

mod decline;
mod gates;
mod load;
mod maps;
mod outbound;
mod peers;
mod route;

use gates::{MergeReg, SplitGate};
use maps::ParkedOld;
pub use outbound::target_spg as body_spg;
use outbound::*;
pub use outbound::{Spgs, body_spgs};
pub use peers::{PEER_BACKOFF_MAX, PEER_BACKOFF_MIN, PeerStats};

/// Loopback deliveries per entry point (adr 0049 am. 1).
const LOOP_MAX: usize = 4096;
/// `MOSDScrub2` commands parked while their map epoch is ahead of ours.
const PARKED_SCRUB_MAX: usize = 64;

/// `PgSet::pool_cache` entry: `(map epoch, is_erasure, served, declined, pg_num)`.
type PoolCached = (u32, bool, bool, bool, u32);

/// Split the owner's replies: those for core `me` into `local`, the others as actions built by `wrap`.
fn route<R>(
    me: u32,
    replies: Vec<(u32, R)>,
    local: &mut Vec<R>,
    out: &mut Vec<Action>,
    wrap: impl Fn(u32, R) -> Action,
) {
    for (core, reply) in replies {
        if core == me {
            local.push(reply);
        } else {
            out.push(wrap(core, reply));
        }
    }
}

impl PgSet {
    pub fn new(cfg: Config) -> Self {
        let (max_bf, max_scrubs, max_trim, max_rec) = (
            cfg.max_backfills,
            cfg.max_scrubs,
            cfg.max_trimming_pgs,
            cfg.recovery_max_active,
        );
        let slots_here = cfg.owner.is_none_or(|o| o.core == 0);
        // independent draws per core; the seed only has to differ between PGs and cores
        let scrub_rng = SplitMix64::new(
            cfg.wall_base_ns
                ^ (cfg.whoami as u64).rotate_left(32)
                ^ u64::from(cfg.owner.map_or(0, |o| o.core)),
        );
        PgSet {
            cfg: Arc::new(cfg),
            maps: BTreeMap::new(),
            cur: None,
            pgs: crate::pgmap::PgMap::new(),
            waiting_map: BTreeMap::new(),
            waiting_pg: BTreeMap::new(),
            waiting_create: BTreeMap::new(),
            pg_hard_limit: Self::PG_HARD_LIMIT_DEFAULT,
            pgs_at_hint: 0,
            withheld_mon: BTreeMap::new(),
            withheld_peer: BTreeMap::new(),
            map_req: 0,
            parked_old: BTreeMap::new(),
            old_out: BTreeSet::new(),
            old_hold: None,
            adv_limit: u32::MAX,
            slots: slots_here.then(|| crate::slots::Slots::new(max_scrubs, max_bf, max_trim)),
            slot_in: Vec::new(),
            ops_owner: slots_here.then(|| crate::recops::OpsOwner::new(max_rec)),
            ops_lease: crate::recops::OpsLease::default(),
            ops_in: Vec::new(),
            slot_open: BTreeMap::new(),
            slot_seq: 0,
            latch: Default::default(),
            scrub_flags: ScrubFlags::default(),
            scrub_load: 0.0,
            local_time: LocalTime::default(),
            recovering: false,
            backoff: false,
            scrub_rng,
            parked_scrub_cmds: Vec::new(),
            up_thru_emitted: 0,
            up_thru_want: 0,
            bounds_stopped_pgs: BTreeSet::new(),
            out: vec![],
            loopq: Default::default(),
            dropped: BTreeMap::new(),
            create_bounds_mismatch: 0,
            passive_seen: BTreeSet::new(),
            ec_woke: Vec::new(),
            ec_err_pgs: Vec::new(),
            ec_err_due: Vec::new(),
            ec_wake_gen: 0,
            tick_diag: false,
            repop_wait: BTreeSet::new(),
            local_full: LocalFull::default(),
            tick_defer: BTreeSet::new(),
            tick_again: false,
            pool_cache: Default::default(),
            declined: BTreeMap::new(),
            decline_stats: BTreeMap::new(),
            held_pools: BTreeSet::new(),
            notices: Vec::new(),
            rec_stats: Default::default(),
            purged_scan: None,
            trace: vec![],
            split_gate: BTreeMap::new(),
            spoke: BTreeMap::new(),
            flashstore: BTreeSet::new(),
            nv_arc: Default::default(),
            long_peers: BTreeSet::new(),
            held: Vec::new(),
            parked_src: BTreeMap::new(),
            merge_reg: BTreeMap::new(),
            merge_sent: BTreeSet::new(),
            place: BTreeMap::new(),
            loaded: false,
            detached: BTreeSet::new(),
            peer_links: BTreeMap::new(),
            peer_stats: PeerStats::default(),
        }
    }

    /// Debug trace lines (PG creation/removal) since the last call.
    pub fn take_trace(&mut self) -> Vec<String> {
        std::mem::take(&mut self.trace)
    }

    pub fn whoami(&self) -> i32 {
        self.cfg.whoami
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// `osd_skip_check_past_interval_bounds` (dev level): disable the required past-interval bounds check. Follow with
    /// [`Self::push_cfg_to_pgs`] and [`Self::recheck_past_bounds`].
    pub fn set_skip_past_bounds_check(&mut self, on: bool) {
        Arc::make_mut(&mut self.cfg).skip_past_bounds_check = on;
    }

    /// Re-run the required past-interval bounds check (peering.md 3.8) on the PGs it stops, after a runtime change of
    /// `osd_skip_check_past_interval_bounds`: a PG the check releases restarts peering through the Reset transition a
    /// new interval start uses (no state poked by hand); one that still fails stays stopped without a second log line.
    /// A PG whose removal is pending (`ToDelete`) is never restarted: its `DeleteStart` keeps the stop, and the removal
    /// is the only thing left to run. Returns the actions of the released PGs.
    pub fn recheck_past_bounds(&mut self, now: Mono, store: &impl PgStoreOps) -> Vec<Action> {
        // the PGs themselves are the authority (not the gate's fast-path set): a stopped PG must never be missed here
        let keys: Vec<SpgT> = self
            .pgs
            .iter()
            .filter(|(_, p)| p.past_bounds_stopped() && !p.is_deleting())
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            let Some(pg) = self.pgs.get_mut(&k) else {
                continue;
            };
            if pg.check_past_interval_bounds() {
                continue;
            }
            // the escape released it (or the pair passes now): peering restarts from Reset, like after a new interval
            pg.enter_reset();
            pg.act_map(now, store);
            self.collect(k, now, store);
        }
        self.finish_at(now, store)
    }

    /// Monotonic superblock `cluster_osdmap_trim_lower_bound` of this OSD: the oldest epoch the cluster can still
    /// provide, and the clamp of the required past-interval bounds (peering.md 3.8).
    pub fn set_cluster_trim(&self, epoch: u32) {
        self.cfg
            .cluster_trim
            .fetch_max(epoch, std::sync::atomic::Ordering::Relaxed);
    }

    pub(super) fn cluster_trim(&self) -> u32 {
        self.cfg
            .cluster_trim
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// PGs stopped by the past-interval bounds check (peering.md 3.8) with their required and stored ranges, for the
    /// `FLASHSTORE_PG_PAST_INTERVALS` health alert.
    pub fn bounds_stopped(&self) -> Vec<BoundsStoppedPg> {
        self.pgs
            .iter()
            .filter_map(|(spg, pg)| {
                pg.past_bounds_stop()
                    .map(|(required, past)| BoundsStoppedPg {
                        spg: *spg,
                        required,
                        past,
                    })
            })
            .collect()
    }

    pub fn current_map(&self) -> Option<&MapHandle> {
        self.cur.as_ref()
    }

    pub fn epoch(&self) -> u32 {
        self.cur.as_ref().map_or(0, |m| m.epoch())
    }

    /// Peering-state timing table of this core (`dump_pg_recovery_stats`).
    pub fn rec_stats(&self) -> &crate::recstats::RecStats {
        &self.rec_stats
    }

    /// `reset_pg_recovery_stats` on this core.
    pub fn reset_rec_stats(&mut self) {
        self.rec_stats.reset();
    }

    /// `scrub_purged_snaps` on this core (spec osd-tell-gaps.md 2): start a walk over every PG of the core. The walk
    /// goes on in steps of one PG and at most `osd_scrub_chunk_max` mapper entries ([`Self::purged_snaps_step`]), so
    /// the core serves everything else in between.
    pub fn purged_snaps_start(&mut self) {
        if self.purged_scan.is_none() {
            self.purged_scan = Some(PurgedScan {
                todo: self.pgs.keys().copied().collect(),
                cursor: None,
                total: Default::default(),
            });
        }
    }

    /// A purged-snaps walk is running on this core.
    pub fn purged_snaps_running(&self) -> bool {
        self.purged_scan.is_some()
    }

    /// One step of the walk. The totals when it just finished; the trim kicks the step queued go out with the actions.
    pub fn purged_snaps_step(
        &mut self,
        now: Mono,
        store: &impl PgStoreOps,
    ) -> (Option<crate::snaptrim::PurgedScrub>, Vec<Action>) {
        let Some(mut scan) = self.purged_scan.take() else {
            return (None, Vec::new());
        };
        let max = self.cfg.scrub.chunk_max.max(1);
        let Some(&k) = scan.todo.front() else {
            return (Some(scan.total), self.finish_at(now, store));
        };
        let mut next = None;
        if let Some(pg) = self.pgs.get_mut(&k) {
            pg.now = now;
            let (f, n) = pg.purged_scan_step(store, scan.cursor.take(), max);
            scan.total.add(&f);
            next = n;
        }
        self.collect(k, now, store);
        if next.is_none() {
            scan.todo.pop_front();
        }
        scan.cursor = next;
        let done = scan.todo.is_empty().then_some(scan.total);
        if done.is_none() {
            self.purged_scan = Some(scan);
        }
        (done, self.finish_at(now, store))
    }

    pub fn pg(&self, spg: SpgT) -> Option<&Pg> {
        self.pgs.get(&spg)
    }

    /// Is an instance (any shard) of PG `pgid` on this core?
    pub fn holds(&self, pgid: PgT) -> bool {
        self.pgs.range(pgid_range(pgid)).next().is_some()
    }

    /// Diagnostics only: does not mark the PG dirty or produce actions.
    pub fn note_work(&mut self, spg: SpgT, ops: u64, bytes: u64) {
        self.pgs.note_work(spg, ops, bytes);
    }

    /// Client io of one message on primary PG `spg` (spec pg-io-stats.md 1): counter-only, the PG is not marked
    /// touched (no engine re-sync); the next stats publish carries it.
    pub fn note_io(&mut self, spg: SpgT, io: &pgwire::IoCount) {
        self.pgs.note_io(spg, io);
    }

    /// Busy ns of one runtime loop iteration, split over the PGs that did work in it.
    pub fn note_busy(&mut self, ns: u64) {
        self.pgs.note_busy(ns);
    }

    pub fn pgs(&self) -> impl Iterator<Item = (&SpgT, &Pg)> {
        self.pgs.iter()
    }

    /// PGs mutably accessed since the last call (a superset of those whose role or interval changed): callers that
    /// mirror per-PG state (op engines) re-sync only these.
    pub fn take_touched(&mut self, out: &mut Vec<SpgT>) -> crate::pgmap::Touched {
        self.pgs.take_touched(out)
    }

    pub fn pg_mut(&mut self, spg: SpgT) -> Option<&mut Pg> {
        let pg = self.pgs.get_mut(&spg)?;
        if !std::sync::Arc::ptr_eq(&pg.nv_peers, &self.nv_arc) {
            pg.nv_peers = self.nv_arc.clone();
        }
        Some(pg)
    }

    /// `(pg, state string)` for every PG.
    pub fn pg_states(&self) -> Vec<(SpgT, String)> {
        self.pgs
            .iter()
            .map(|(k, p)| (*k, p.state_string()))
            .collect()
    }

    /// Oldest map epoch any PG still needs (map trimming bound).
    pub fn min_pg_epoch(&self) -> Option<u32> {
        self.pgs.values().map(|p| p.map_epoch()).min()
    }

    /// Bring one PG to the current map and run its ActMap (messages for a PG that was created from an older
    /// map, or a PG that just got created).
    fn advance_pg(&mut self, spg: SpgT, now: Mono, store: &impl PgStoreOps) {
        let cur = self.epoch();
        if self.pgs.get(&spg).is_some_and(|p| p.map_epoch() < cur) {
            // only this PG and the children it creates on the way: advancing everyone (and ActMap on every PG)
            // for each late PG is quadratic in creation storms
            let known: BTreeSet<SpgT> = self.pgs.keys().copied().collect();
            let only = BTreeSet::from([spg]);
            self.advance_and_act(&only, &known, now, store);
            return;
        }
        if let Some(pg) = self.pgs.get_mut(&spg) {
            pg.act_map(now, store);
        }
        self.collect(spg, now, store);
        self.release_waiting(spg, now, store);
    }

    /// Advance the PGs in `only` plus the ones created on the way (not in `known`) to the current map, then run
    /// their ActMap.
    fn advance_and_act(
        &mut self,
        only: &BTreeSet<SpgT>,
        known: &BTreeSet<SpgT>,
        now: Mono,
        store: &impl PgStoreOps,
    ) {
        self.advance_set(Some((only, known)), now, store);
        let acting: Vec<SpgT> = self
            .pgs
            .keys()
            .filter(|k| only.contains(k) || !known.contains(k))
            .copied()
            .collect();
        for k in acting {
            if let Some(pg) = self.pgs.get_mut(&k) {
                pg.act_map(now, store);
            }
            self.collect(k, now, store);
            self.release_waiting(k, now, store);
        }
    }

    /// Route what waited for `spg` (it exists now). A PG being deleted keeps it: `route` would only park it again, after
    /// re-running the receive side effects for stale messages (`peer_heard` took one as proof that the sender's session
    /// works); `PgRemoved` routes it.
    fn release_waiting(&mut self, spg: SpgT, now: Mono, store: &impl PgStoreOps) {
        if self.pgs.get(&spg).is_some_and(Pg::is_deleting) {
            return;
        }
        if let Some(parked) = self.waiting_pg.remove(&spg) {
            self.route_released(now, parked, store);
        }
    }

    /// AdvMap of every PG through every retained epoch, in lockstep: all PGs that process epoch `e` do so before
    /// any PG processes a later one, so merge sources are parked before their target merges and a split child is
    /// there when its siblings need it (split-merge.md 4, 6.4).
    fn advance_all(&mut self, now: Mono, store: &impl PgStoreOps) {
        self.advance_set(None, now, store);
    }

    /// [`Self::advance_all`] restricted to the PGs in `only` plus every PG that did not exist before (`known`):
    /// the children and merge placeholders created on the way.
    fn advance_set(
        &mut self,
        only: Option<(&BTreeSet<SpgT>, &BTreeSet<SpgT>)>,
        now: Mono,
        store: &impl PgStoreOps,
    ) {
        loop {
            let mut at: Option<u32> = None;
            let mut group: Vec<SpgT> = Vec::new();
            for (k, pg) in self.pgs.iter() {
                if let Some((o, known)) = only
                    && known.contains(k)
                    && !o.contains(k)
                {
                    continue;
                }
                if pg.map_epoch() >= self.adv_limit {
                    continue;
                }
                let Some((&e, _)) = self.maps.range(pg.map_epoch() + 1..=self.adv_limit).next()
                else {
                    continue;
                };
                match at {
                    Some(a) if e > a => {}
                    Some(a) if e == a => group.push(*k),
                    _ => {
                        at = Some(e);
                        group.clear();
                        group.push(*k);
                    }
                }
            }
            let Some(e) = at else { return };
            self.step_epoch(e, group, now, store);
        }
    }

    /// Epoch `e` for the PGs in `group` (all at the epoch before it).
    fn step_epoch(&mut self, e: u32, group: Vec<SpgT>, now: Mono, store: &impl PgStoreOps) {
        let newmap = self.maps[&e].clone();
        // A: merge sources leave first and wait for their target
        let mut rest: Vec<(SpgT, u32, Option<u32>)> = Vec::new();
        for spg in group {
            let Some(pg) = self.pgs.get(&spg) else {
                continue;
            };
            if self.is_passive(spg.pgid.pool) {
                // erasure pools we do not serve are fully passive: no state change, no store write, no message; the
                // PG (which should never have been created) is only forgotten in memory, with every side table entry
                self.forget_pg(spg);
                self.note_passive(spg.pgid.pool);
                continue;
            }
            let old_n = pg.pool_pg_num();
            let new_n = newmap.pool(spg.pgid.pool).map(|p| p.pg_num);
            let source = !pg.is_deleting()
                && new_n.is_some_and(|n| {
                    n < old_n && pgwire::pgmath::is_merge_source(spg.pgid.seed, old_n, n)
                });
            if !source {
                rest.push((spg, old_n, new_n));
                continue;
            }
            if let Some(pg) = self.pgs.get_mut(&spg) {
                pg.quiesce_for_merge(store);
            }
            self.collect(spg, now, store);
            if let Some(pg) = self.pgs.remove(&spg) {
                self.slots_forget(spg);
                self.out.push(Action::PgRemoved { spg });
                self.note_merge(spg);
                self.parked_src.insert((e, spg), pg);
            }
        }
        // B: everything else; targets absorb their sources first, parents split after their AdvMap
        for (spg, old_n, new_n) in rest {
            if !self.pgs.contains_key(&spg) {
                continue;
            }
            let seed = spg.pgid.seed;
            if let Some(n) = new_n
                && n < old_n
                && !self.pgs[&spg].is_deleting()
                && pgwire::pgmath::is_merge_target(seed, old_n, n)
            {
                let srcs: Vec<(u32, Option<Pg>)> = pgwire::pgmath::merge_sources(seed, old_n, n)
                    .into_iter()
                    .map(|s| {
                        let k = (
                            e,
                            SpgT {
                                pgid: PgT::new(spg.pgid.pool, s),
                                // a source merges into the target of the SAME shard (EC: our acting position)
                                shard: spg.shard,
                            },
                        );
                        (s, self.parked_src.remove(&k))
                    })
                    .collect();
                let meta = newmap
                    .pool(spg.pgid.pool)
                    .map(|p| p.merge_meta)
                    .unwrap_or_default();
                self.trace.push(format!(
                    "merge into {spg} at epoch {e}: sources {:?}",
                    srcs.iter()
                        .map(|(s, p)| (*s, p.is_some()))
                        .collect::<Vec<_>>()
                ));
                if let Some(pg) = self.pgs.get_mut(&spg) {
                    pg.merge_from(srcs, &meta, n, false);
                }
            }
            let Some(pg) = self.pgs.get_mut(&spg) else {
                continue;
            };
            // the parent's own previous map (not the global history, which may lack it): who held the parent
            let before = pg.map_handle().pg_mapping(spg.pgid);
            // strays that may hold the parent (past-interval participants) get probed by the child too
            let past: Vec<i32> = pg
                .past_intervals()
                .all_participants
                .iter()
                .map(|p| p.osd)
                .collect();
            let kids = pg.advance_map(now, newmap.clone(), store);
            self.collect(spg, now, store);
            for kid in kids {
                let ks = kid.spg;
                if self.cfg.owner.is_some() {
                    // a child always inherits its parent's shard (and so its core): zero-copy split (adr 0031). A live map
                    // placed it on every core already (`place_split_children`); a split replayed at boot is announced.
                    let sh = self.pg_shard(spg.pgid);
                    self.set_placement(ks.pgid, sh, store);
                    self.out.push(Action::Placement {
                        pgid: ks.pgid,
                        shard: sh,
                    });
                }
                if self.pgs.contains_key(&ks) {
                    // redo after a crash: the child exists already and keeps its own state
                    self.trace
                        .push(format!("split {spg} -> {ks}: child exists"));
                } else {
                    self.trace.push(format!("split {spg} -> {ks} at epoch {e}"));
                    // a child stopped by the bounds check (peering.md 3.8) is silent before its first collect too
                    if kid.past_bounds_stopped() {
                        self.bounds_stopped_pgs.insert(ks);
                    }
                    self.pgs.insert(ks, kid);
                    // Only pairs that talk about the parent have evidence to wait for: the parent's primary and
                    // its members (replicas never talk to each other; gating them would deadlock).
                    let me = self.cfg.whoami;
                    let watch: BTreeSet<i32> = if before.acting_primary == me {
                        before
                            .up
                            .iter()
                            .chain(&before.acting)
                            .chain(&past)
                            .copied()
                            .collect()
                    } else {
                        BTreeSet::from([before.acting_primary])
                    }
                    .into_iter()
                    .filter(|o| *o >= 0 && *o != me)
                    .collect();
                    self.insert_gate(ks, e, watch, &*newmap);
                }
            }
        }
        // Sources whose target was not in this epoch's group: absent locally, or already past the merge epoch.
        // The copy is NEVER dropped (it may be the only one): an absent target is created empty to absorb it
        // (split-merge.md 4 priming, 6.4 step 6: placeholder, incomplete -> backfilled by its peers); a target
        // that is already past the epoch absorbs it late and restarts peering (incomplete too).
        let orphans: Vec<(u32, SpgT)> = self
            .parked_src
            .keys()
            .filter(|k| k.0 == e)
            .copied()
            .collect();
        let mut by_target: BTreeMap<SpgT, Vec<(u32, Option<Pg>)>> = BTreeMap::new();
        for k in orphans {
            let Some(pg) = self.parked_src.remove(&k) else {
                continue;
            };
            let Some(pool) = newmap.pool(k.1.pgid.pool) else {
                // pool deleted: nothing absorbs this copy, deleting the pool deletes it
                self.trace
                    .push(format!("merge source {} of a deleted pool: removed", k.1));
                self.out.push(Action::Persist {
                    spg: k.1,
                    token: u64::MAX,
                    txn: crate::store::StoreTxn {
                        ops: vec![crate::store::StoreOp::RemovePg],
                    },
                });
                continue;
            };
            let t = SpgT {
                pgid: PgT::new(
                    k.1.pgid.pool,
                    pgwire::pgmath::merge_target(k.1.pgid.seed, pool.pg_num),
                ),
                shard: k.1.shard,
            };
            by_target
                .entry(t)
                .or_default()
                .push((k.1.pgid.seed, Some(pg)));
        }
        for (t, srcs) in by_target {
            let Some(pool) = newmap.pool(t.pgid.pool) else {
                continue;
            };
            let n = pool.pg_num;
            let meta = pool.merge_meta;
            if let Some(pg) = self.pgs.get_mut(&t) {
                self.trace.push(format!(
                    "merge into {t} (past epoch {e}): sources {:?}",
                    srcs.iter().map(|(s, _)| *s).collect::<Vec<_>>()
                ));
                pg.merge_from(srcs, &meta, n, true);
                pg.enter_reset();
                pg.act_map(now, store);
                self.collect(t, now, store);
            } else {
                self.trace.push(format!(
                    "merge into {t} at epoch {e}: target absent, placeholder for sources {:?}",
                    srcs.iter().map(|(s, _)| *s).collect::<Vec<_>>()
                ));
                let pg = Pg::merge_placeholder(self.cfg.clone(), t, srcs, &meta, n, now);
                self.pgs.insert(t, pg);
                let kids = self
                    .pgs
                    .get_mut(&t)
                    .map(|p| p.advance_map(now, newmap.clone(), store))
                    .unwrap_or_default();
                self.collect(t, now, store);
                debug_assert!(kids.is_empty());
            }
        }
    }

    /// ActMap for every PG, then release messages parked for PGs that exist now (not for PGs being deleted:
    /// `release_waiting`).
    fn act_all(&mut self, now: Mono, store: &impl PgStoreOps) {
        let keys: Vec<SpgT> = self.pgs.keys().copied().collect();
        for k in keys {
            if let Some(pg) = self.pgs.get_mut(&k) {
                pg.act_map(now, store);
            }
            self.collect(k, now, store);
        }
        let ready: Vec<SpgT> = self
            .waiting_pg
            .keys()
            .filter(|k| self.pgs.contains_key(k))
            .copied()
            .collect();
        for k in ready {
            self.release_waiting(k, now, store);
        }
    }

    /// Drain a PG's actions into the output, serving internal reservation requests.
    fn collect(&mut self, spg: SpgT, now: Mono, store: &impl PgStoreOps) {
        self.collect_pg(spg, now, store);
        self.rec_sync(spg);
    }

    fn collect_pg(&mut self, spg: SpgT, now: Mono, store: &impl PgStoreOps) {
        self.collect_inner(spg, now, store);
        match self.pgs.get(&spg) {
            Some(p) if p.repops_held() != 0 || p.ep.store_wait => {
                self.repop_wait.insert(spg);
            }
            _ => {
                if !self.repop_wait.is_empty() {
                    self.repop_wait.remove(&spg);
                }
            }
        }
        self.note_merge(spg);
    }

    fn collect_inner(&mut self, spg: SpgT, now: Mono, store: &impl PgStoreOps) {
        loop {
            let Some(pg) = self.pgs.get_mut(&spg) else {
                return;
            };
            let notes = pg.take_notes();
            self.notices.extend(notes);
            pg.fold_rec_stats(&mut self.rec_stats);
            let (woke, failed) = pg.ep_take_wake(self.ec_wake_gen);
            if woke.any() {
                match self.ec_woke.iter_mut().find(|e| e.0 == spg) {
                    Some(e) => e.1.merge(&woke),
                    None => self.ec_woke.push((spg, woke)),
                }
            }
            if failed {
                self.ec_err_pgs.push(spg);
            }
            let Some(pg) = self.pgs.get_mut(&spg) else {
                return;
            };
            let mut acts = pg.take_actions();
            // keep the outbound gate of `finish` O(1) on a healthy OSD (peering.md 3.8)
            let stopped = pg.past_bounds_stopped();
            if stopped {
                self.bounds_stopped_pgs.insert(spg);
            } else if !self.bounds_stopped_pgs.is_empty() {
                self.bounds_stopped_pgs.remove(&spg);
            }
            // an EC instance that does not lead (not the acting primary, or may not lead: NP shard, shard-only profile,
            // role switches of its interval) sends only replica-side messages, whatever `ec_enable_primary` says
            if pg.spg.shard != ShardId::NO_SHARD && !pg.ec_leads() {
                let before = acts.len();
                acts.retain(|a| match a {
                    Action::Send(s) => ec_shard_may_send(&s.body, false),
                    _ => true,
                });
                if acts.len() != before {
                    self.drop_msg("primary-side message from an EC instance that does not lead");
                }
            }
            // a stopped instance (peering.md 3.8) emits no outbound message: drop them where they are taken from this
            // PG. Queues that keep an action for later (split gate, loopback) gate it by its producing instance.
            if stopped {
                let mut kept = Vec::with_capacity(acts.len());
                for a in acts {
                    if bounds_gated(&a) {
                        self.drop_msg("outbound message of a bounds-stopped pg");
                    } else {
                        kept.push(a);
                    }
                }
                acts = kept;
            }
            // safety net (after the actions, so it sees the PG's final state and the reserver after this batch): local
            // slots the state no longer justifies (interval change, reset, removal) go back, a lost queue place is
            // requested again
            let had_acts = !acts.is_empty();
            if !had_acts {
                self.local_check(spg);
                if self.slot_in.is_empty() {
                    return;
                }
            }
            for a in acts {
                match a {
                    Action::Resv(ResvAction { pool, spg, op }) => self.resv_action(pool, spg, op),
                    Action::PgRemoved { spg } => {
                        self.forget_pg(spg);
                        // messages that waited for the delete (a new interval mapped the PG here again, `route`):
                        // routed again by `finish_at`, in arrival order; a notify / log creates the PG now
                        if let Some(q) = self.waiting_pg.remove(&spg) {
                            self.loopq.extend(q.into_iter().map(|m| (None, m)));
                        }
                    }
                    Action::NeedUpThru { want } => {
                        self.up_thru_want = self.up_thru_want.max(want);
                        if want > self.up_thru_emitted {
                            self.up_thru_emitted = want;
                            self.out.push(Action::NeedUpThru { want });
                        }
                    }
                    Action::Latch { kind, ns } => self.latch.record(kind, ns),
                    other => self.out.push(other),
                }
            }
            if had_acts {
                self.local_check(spg);
            }
            for t in self.deliver_slots(now) {
                if t != spg {
                    self.collect(t, now, store);
                }
            }
        }
    }

    /// A PG's slot request: a held local slot is granted again, a held or queued remote / trim slot is not asked for
    /// again, everything else goes to the owner.
    fn resv_action(&mut self, pool: SlotPool, spg: SpgT, op: SlotOp) {
        match (pool, op) {
            (
                SlotPool::Resv {
                    local: true,
                    backfill,
                },
                SlotOp::Request { prio, .. },
            ) => {
                self.local_request(spg, prio, backfill);
            }
            (SlotPool::Resv { local: false, .. } | SlotPool::Trim, SlotOp::Request { .. })
                if self.slot_open.contains_key(&(pool, spg)) => {}
            _ => self.slot_op(pool, spg, op),
        }
    }

    /// Ask the budget owner for a slot, or give one back: applied here on the owner core (replies for other cores go
    /// out as actions), sent as an action on the others. A release of a slot never asked for is dropped.
    pub(super) fn slot_op(&mut self, pool: SlotPool, spg: SpgT, op: SlotOp) {
        let seq = if op == SlotOp::Release {
            if self.slot_open.remove(&(pool, spg)).is_none() {
                return;
            }
            0
        } else {
            self.slot_seq = self.slot_seq.wrapping_add(1);
            let seq = self.slot_seq;
            self.slot_open.insert(
                (pool, spg),
                SlotOpen {
                    seq,
                    granted: false,
                    prio: match op {
                        SlotOp::Request { prio, .. } => prio,
                        _ => 0,
                    },
                },
            );
            seq
        };
        let req = SlotReq {
            from: self.core_id(),
            pool,
            spg,
            seq,
            op,
        };
        self.slot_req(req);
    }

    fn slot_req(&mut self, req: SlotReq) {
        let Some(slots) = self.slots.as_mut() else {
            self.out.push(Action::Slot(req));
            return;
        };
        let mut replies = Vec::new();
        slots.apply(req, &mut replies);
        self.route_replies(replies);
    }

    /// Replies of the owner: for this core's PGs into [`Self::slot_in`], for the others as actions.
    fn route_replies(&mut self, replies: Vec<(u32, SlotReply)>) {
        route(
            self.core_id(),
            replies,
            &mut self.slot_in,
            &mut self.out,
            |core, reply| Action::SlotReply { core, reply },
        );
    }

    /// Hand the slot replies to their PGs. A reply of a request since released or replaced is dropped (the owner freed
    /// that slot with the release); a slot its PG no longer exists for or wants is passed on. Returns the PGs that
    /// got an answer (their actions must be collected).
    fn deliver_slots(&mut self, now: Mono) -> BTreeSet<SpgT> {
        let mut got = BTreeSet::new();
        while let Some(r) = self.slot_in.pop() {
            let key = (r.pool, r.spg);
            let Some(open) = self.slot_open.get_mut(&key) else {
                continue;
            };
            if open.seq != r.seq {
                continue;
            }
            let granted = r.answer == SlotAnswer::Granted;
            if r.answer == SlotAnswer::Preempted {
                // the owner already took the slot (and its entry) away: nothing to give back
                self.slot_open.remove(&key);
                let Some(p) = self.pgs.get_mut(&r.spg) else {
                    continue;
                };
                match r.pool {
                    SlotPool::Resv {
                        local: false,
                        backfill,
                    } => p.remote_preempted(now, backfill),
                    SlotPool::Resv {
                        local: true,
                        backfill,
                    } => p.local_preempted(now, backfill),
                    _ => continue,
                }
                got.insert(r.spg);
                continue;
            }
            open.granted = granted;
            let Some(p) = self.pgs.get_mut(&r.spg) else {
                self.slot_op(r.pool, r.spg, SlotOp::Release);
                continue;
            };
            let mut wanted = true;
            match (r.pool, granted) {
                (SlotPool::ScrubLocal, true) => p.sp_local_granted(),
                (SlotPool::ScrubLocal, false) => p.sp_local_rejected(),
                (SlotPool::ScrubReplica, true) => p.scrub_granted(),
                (SlotPool::ScrubReplica, false) => p.scrub_rejected(),
                (
                    SlotPool::Resv {
                        local: false,
                        backfill,
                    },
                    _,
                ) => p.remote_reserved(now, backfill),
                (SlotPool::Trim, _) => p.trim_granted(),
                (
                    SlotPool::Resv {
                        local: true,
                        backfill,
                    },
                    _,
                ) => {
                    if p.local_wait().is_some_and(|w| w.0 == backfill) {
                        p.local_reserved(now, backfill);
                    } else if p.local_resv_needed() == (!backfill, backfill) {
                        // already past the wait, the slot stays
                        continue;
                    } else {
                        // a slot its PG does not want (reset, re-targeted): pass it on
                        wanted = false;
                    }
                }
            }
            if !wanted {
                self.slot_op(r.pool, r.spg, SlotOp::Release);
                continue;
            }
            if !granted {
                self.slot_open.remove(&key);
            }
            got.insert(r.spg);
        }
        got
    }

    /// A slot request of another core (this core keeps the budgets); answers go out as actions.
    pub fn slot_rx_req(&mut self, now: Mono, req: SlotReq, store: &impl PgStoreOps) -> Vec<Action> {
        self.slot_req(req);
        self.slot_flush(now, store)
    }

    /// The owner's answer to a request of this core.
    pub fn slot_rx_reply(
        &mut self,
        now: Mono,
        reply: SlotReply,
        store: &impl PgStoreOps,
    ) -> Vec<Action> {
        self.slot_in.push(reply);
        self.slot_flush(now, store)
    }

    fn slot_flush(&mut self, now: Mono, store: &impl PgStoreOps) -> Vec<Action> {
        for t in self.deliver_slots(now) {
            self.collect(t, now, store);
        }
        self.finish_at(now, store)
    }

    /// Primary-side reservation request of a PG waiting for its local slot. A slot it already holds at that priority is
    /// granted again (a PG that re-enters the wait state keeps it), a queued request or a held one at another priority
    /// goes to the owner with the new priority (classic: update_priority). Only a slot the owner really granted counts as held.
    fn local_request(&mut self, spg: SpgT, prio: u32, backfill: bool) {
        let pool = SlotPool::Resv {
            local: true,
            backfill,
        };
        match self.slot_open.get(&(pool, spg)) {
            Some(o) if o.granted && o.prio == prio => self.slot_in.push(SlotReply {
                pool,
                spg,
                seq: o.seq,
                answer: SlotAnswer::Granted,
            }),
            _ => {
                let op = SlotOp::Request {
                    immediate: false,
                    prio,
                };
                self.slot_op(pool, spg, op);
            }
        }
    }

    /// Safety net for every path that changes a PG without saying so: give back the local slots (or queue places) `spg`
    /// holds although its state does not justify them, and queue again a PG that waits for a local slot it neither holds
    /// nor waits for (a lost queue place would stall it forever).
    fn local_check(&mut self, spg: SpgT) {
        let (need, wait) = self.pgs.get(&spg).map_or(((false, false), None), |p| {
            (p.local_resv_needed(), p.local_wait())
        });
        for (backfill, needed) in [(false, need.0), (true, need.1)] {
            let pool = SlotPool::Resv {
                local: true,
                backfill,
            };
            if !needed && self.slot_open.contains_key(&(pool, spg)) {
                self.slot_op(pool, spg, SlotOp::Release);
            }
        }
        if let Some((backfill, prio)) = wait
            && !self.slot_open.contains_key(&(
                SlotPool::Resv {
                    local: true,
                    backfill,
                },
                spg,
            ))
        {
            self.local_request(spg, prio, backfill);
        }
    }

    /// Give back every slot and queue place of a PG that leaves the set.
    fn slots_forget(&mut self, spg: SpgT) {
        self.ops_lease.forget(spg);
        let held: Vec<SlotPool> = self
            .slot_open
            .keys()
            .filter(|k| k.1 == spg)
            .map(|k| k.0)
            .collect();
        for pool in held {
            self.slot_op(pool, spg, SlotOp::Release);
        }
    }

    // ---- OSD-wide recovery-op budget (`osd_recovery_max_active`, crate::recops) --------------------------------------

    /// A PG's recovery state after an event: its in-flight ops and whether it waits for more go into the lease books, and
    /// it keeps the lease the books allow.
    fn rec_sync(&mut self, spg: SpgT) {
        let Some(pg) = self.pgs.get_mut(&spg) else {
            self.ops_lease.forget(spg);
            return;
        };
        let active = matches!(
            pg.st,
            St::Primary(crate::pg::PSt::Active(
                crate::pg::ASt::Recovering | crate::pg::ASt::Backfilling
            ))
        );
        let inflight = pg.rec_inflight();
        let wants = active && pg.rec.wants;
        pg.rec.cap = self.ops_lease.sync(spg, inflight, pg.rec.cap, wants);
    }

    /// Serve the owner's answers and the waiting PGs: units go to the PGs that stopped at their lease (their recovery pass
    /// runs again), idle units and new wishes go to the owner. Runs at the end of every entry point.
    fn rec_pump(&mut self, now: Mono, store: &impl PgStoreOps) {
        while self.ops_lease.needs_pump() || !self.ops_in.is_empty() {
            for r in std::mem::take(&mut self.ops_in) {
                self.ops_lease.grant(r);
            }
            let (mut grants, mut msgs) = (Vec::new(), Vec::new());
            self.ops_lease.pump(&mut grants, &mut msgs);
            let progressed = !grants.is_empty() || !msgs.is_empty();
            for m in msgs {
                self.ops_send(m);
            }
            for (spg, lease) in grants {
                let Some(pg) = self.pgs.get_mut(&spg) else {
                    self.ops_lease.forget(spg);
                    continue;
                };
                pg.rec.cap = lease;
                pg.rec.wants = false;
                pg.rec_kick(now, store);
                self.collect_pg(spg, now, store);
                self.rec_sync(spg);
            }
            if !progressed && self.ops_in.is_empty() {
                break;
            }
        }
    }

    fn core_id(&self) -> u32 {
        self.cfg.owner.map_or(0, |o| o.core)
    }

    /// Tell the budget owner (applied here on the owner core).
    fn ops_send(&mut self, msg: crate::OpsMsg) {
        let req = crate::OpsReq {
            from: self.core_id(),
            msg,
        };
        let Some(owner) = self.ops_owner.as_mut() else {
            self.out.push(Action::Ops(req));
            return;
        };
        let mut replies = Vec::new();
        owner.apply(req, &mut replies);
        self.ops_route(replies);
    }

    fn ops_route(&mut self, replies: Vec<(u32, crate::OpsReply)>) {
        route(
            self.core_id(),
            replies,
            &mut self.ops_in,
            &mut self.out,
            |core, reply| Action::OpsReply { core, reply },
        );
    }

    /// A request of another core (this core keeps the limit); the answers go out as actions.
    pub fn ops_rx_req(
        &mut self,
        now: Mono,
        req: crate::OpsReq,
        store: &impl PgStoreOps,
    ) -> Vec<Action> {
        if let Some(owner) = self.ops_owner.as_mut() {
            let mut replies = Vec::new();
            owner.apply(req, &mut replies);
            self.ops_route(replies);
        }
        self.finish_at(now, store)
    }

    /// The owner's answer to this core.
    pub fn ops_rx_reply(
        &mut self,
        now: Mono,
        reply: crate::OpsReply,
        store: &impl PgStoreOps,
    ) -> Vec<Action> {
        self.ops_in.push(reply);
        self.finish_at(now, store)
    }

    /// `osd_recovery_max_active` (OSD-wide: only the owner core keeps it; a lower value is reached as ops finish).
    pub fn set_recovery_max_active(&mut self, n: usize) {
        let Some(owner) = self.ops_owner.as_mut() else {
            return;
        };
        let mut replies = Vec::new();
        owner.set_limit(n, &mut replies);
        self.ops_route(replies);
    }

    /// Recovery units this core's PGs hold in the lease books (tests: 0 when idle).
    pub fn rec_held(&self) -> usize {
        self.ops_lease.held_total()
    }

    /// Recovery ops in flight over this core's PGs and the quota this core holds (diagnostics, tests).
    pub fn rec_ops(&self) -> (usize, usize) {
        let ops = self.pgs.values().map(|p| p.rec_inflight()).sum();
        (ops, self.ops_lease.quota())
    }

    /// Highest recovery ops in flight over this core's PGs at once, since start (diagnostics).
    pub fn rec_peak(&self) -> usize {
        self.ops_lease.peak_running()
    }

    /// The budget owner's books: units held by all cores and the limit (None on a core that is not the owner).
    pub fn rec_budget(&self) -> Option<(usize, usize)> {
        self.ops_owner.as_ref().map(|o| o.granted())
    }

    /// Cumulative duration samples of the vulnerability windows and rebuild episodes this core's primary PGs closed
    /// (peering.md 9.6): the source of the `recoverystate_perf` counters `pg_vulnerability_duration(_min)` and
    /// `pg_rebuild_duration(_min)`. Per core; the OSD sums the cores with [`crate::LatchPerf::merge`].
    pub fn latch_perf(&self) -> crate::latch::LatchPerf {
        self.latch
    }

    /// EC primary reads completed / writes moved since the last call: `out` (cleared first) gets, sorted by PG, the
    /// objects each PG woke ([`crate::wake::ec_tok`]); the ops parked on them run again.
    pub fn take_ec_wake(&mut self, out: &mut Vec<(SpgT, crate::wake::WakeSet)>) {
        self.ec_err_due.append(&mut self.ec_err_pgs);
        self.ec_wake_gen += 1;
        out.clear();
        std::mem::swap(out, &mut self.ec_woke);
        out.sort_unstable_by_key(|e| e.0);
    }

    /// The op layer re-ran the ops parked on the EC reads of the last [`PgSet::take_ec_wake`]: the reads that failed
    /// have answered their ops (EIO); a later op asks the shards again (no error hold). Errors of reads that failed
    /// after that wake stay until their own wake was taken and its ops ran.
    pub fn ec_read_errors_delivered(&mut self) {
        // failures stamped before the last take (generation < ec_wake_gen) were announced with it
        let due = self.ec_wake_gen.saturating_sub(1);
        for spg in std::mem::take(&mut self.ec_err_due) {
            if let Some(pg) = self.pgs.get_mut(&spg) {
                pg.ec_read_errors_delivered(due);
            }
        }
    }

    /// Run `f` on PG `spg` and serve what it emitted (reservations, sends, persists): the entry point of drivers
    /// that call PG methods directly (the snap trimmer).
    pub fn with_pg<R>(
        &mut self,
        now: Mono,
        spg: SpgT,
        store: &impl PgStoreOps,
        f: impl FnOnce(&mut Pg) -> R,
    ) -> Option<(R, Vec<Action>)> {
        let pg = self.pgs.get_mut(&spg)?;
        pg.now = now;
        if !std::sync::Arc::ptr_eq(&pg.nv_peers, &self.nv_arc) {
            pg.nv_peers = self.nv_arc.clone();
        }
        let r = f(pg);
        pg.after_event(store);
        self.collect(spg, now, store);
        Some((r, self.finish_at(now, store)))
    }

    /// Is this send from a PG instance stopped by the past-interval bounds check (peering.md 3.8)? Keyed by the
    /// producing instance: one EC pgid can hold a stopped shard next to a healthy one on this OSD (adr 0049 am. 1), and
    /// only the stopped instance must fall silent. The PG-addressed mon actions are filtered where their producer emits
    /// them ([`Self::collect_pg`], [`Self::resend_mon_requests`], merge reports).
    fn bounds_silenced(&self, a: &Action) -> bool {
        match a {
            Action::Send(s) => s
                .producer
                .is_some_and(|p| self.pgs.get(&p).is_some_and(|pg| pg.past_bounds_stopped())),
            _ => false,
        }
    }

    /// Final output filtering: drop sends to peers that are not up since the stamped epoch.
    fn finish(&mut self) -> Vec<Action> {
        // every entry point: gates of children created at an epoch below the current one (PG loaded or advanced late)
        // are reopened without waiting for another map
        self.reopen_gates();
        self.release_held();
        let mut out = std::mem::take(&mut self.out);
        // A PG stopped by the past-interval bounds check sends nothing towards peers or the mon, whatever path produced
        // the action (a tick, a timer, a runtime role switch, a reconnect resend, a send before the stop in this event,
        // one released from a split gate): one gate for every emission path (peering.md 3.8). Persistence, local cleanup
        // and the primary's INCOMPLETE stats stay: the mgr must see the stopped PG.
        if !self.bounds_stopped_pgs.is_empty() {
            self.bounds_stopped_pgs.retain(|s| self.pgs.contains_key(s));
            out.retain(|a| {
                if !self.bounds_silenced(a) {
                    return true;
                }
                self.drop_msg("outbound message of a bounds-stopped pg");
                false
            });
        }
        let Some(cur) = self.cur.clone() else {
            // fail closed: nothing can be validated without a map (prime safety); every other action stays
            out.retain(|a| match a {
                Action::Send(s) => {
                    self.drop_msg("send before the first map");
                    self.notices.push(format!(
                        "dropped outbound message to osd.{}: no map yet",
                        s.to
                    ));
                    false
                }
                _ => true,
            });
            return out;
        };
        // filtered in place (no second vector per call); gated sends move to `held` in order
        if !self.split_gate.is_empty() {
            let gated: Vec<Action> = out
                .extract_if(.., |a| matches!(a, Action::Send(s) if self.gated(s)))
                .collect();
            self.held.extend(gated);
        }
        out.retain(|a| {
            if let Action::Send(s) = a {
                let serves = |p: u64| self.pool_state(p).is_some_and(|(_, serves)| serves);
                let declines = |p: u64| self.declines(p);
                if let Some(why) = spg_violation(
                    &*cur,
                    &serves,
                    &declines,
                    self.cfg.ec_primary,
                    self.cfg.whoami,
                    s.to,
                    &s.body,
                ) {
                    // choke point: never let a malformed/unsupported PG message reach a classic OSD
                    self.drop_msg(why);
                    self.notices
                        .push(format!("dropped outbound message to osd.{}: {why}", s.to));
                    return false;
                }
                if !cur.is_up(s.to) {
                    self.drop_msg("send: peer not up in this core's map");
                    return false;
                }
                if cur.up_from(s.to) > s.epoch {
                    self.drop_msg("send: message epoch older than peer up_from");
                    return false;
                }
                if !self.peer_links.is_empty() && self.peer_holds(s) {
                    self.peer_stats.held_queries += 1;
                    return false;
                }
            }
            true
        });
        if !self.peer_links.is_empty() {
            self.peer_probe_done();
        }
        let me = self.cfg.whoami;
        if out
            .iter()
            .any(|a| matches!(a, Action::Send(s) if s.to == me))
        {
            let own: Vec<Action> = out
                .extract_if(
                    ..,
                    |a| matches!(a, Action::Send(s) if s.to == me && self.loops(s)),
                )
                .collect();
            for a in own {
                if let Action::Send(s) = a {
                    self.loopback(*s);
                }
            }
        }
        out
    }

    /// Is a send to our own OSD delivered here (adr 0049 am. 1)? Only to a PG this core owns (all instances of a pgid
    /// share the core); anything else keeps the messenger path.
    fn loops(&self, s: &Send) -> bool {
        body_spgs(&s.body).iter().all(|spg| self.owns(*spg))
    }

    /// Queue a message to another instance of this OSD as if it had arrived from the wire: encoded and decoded with
    /// every feature, so the receiver sees exactly what a peer would get.
    fn loopback(&mut self, s: Send) {
        let producer = s.producer;
        let body = s
            .body
            .encode(denc::features::ALL)
            .and_then(|(ty, v, _, seg)| Body::decode(ty, v, &seg));
        match body {
            Ok(Some(body)) => self.loopq.push_back((
                producer,
                Inbound {
                    ingress: Default::default(),
                    from: self.cfg.whoami,
                    tid: s.tid,
                    prio: s.prio,
                    body: Box::new(body),
                },
            )),
            _ => {
                self.drop_msg("loopback: message does not round-trip");
                self.notices.push(format!(
                    "dropped loopback message type {}: does not round-trip",
                    s.body.msg_type()
                ));
            }
        }
    }

    /// [`Self::finish`], then deliver what the PGs sent to other instances of this OSD (and what those answer) until
    /// quiet; the bound leaves a ping-pong for the next entry point ([`Self::next_deadline`]).
    fn finish_at(&mut self, now: Mono, store: &impl PgStoreOps) -> Vec<Action> {
        self.rec_pump(now, store);
        let mut out = self.finish();
        if self.loopq.is_empty() {
            return out;
        }
        // Loopback delivery shares the same unapplied-store boundary as released network batches.
        let mut persisted: BTreeSet<SpgT> = out.iter().filter_map(route::persisted_spg).collect();
        let mut n = 0;
        while n < LOOP_MAX
            && let Some((producer, m)) = self.loopq.pop_front()
        {
            // a send a since-stopped instance queued here is not delivered (peering.md 3.8)
            if producer.is_some_and(|p| self.pgs.get(&p).is_some_and(|pg| pg.past_bounds_stopped()))
            {
                self.drop_msg("outbound message of a bounds-stopped pg");
                continue;
            }
            n += 1;
            self.route_ordered(now, m, store, &persisted);
            self.rec_pump(now, store);
            let more = self.finish();
            persisted.extend(more.iter().filter_map(route::persisted_spg));
            out.extend(more);
        }
        out
    }

    // ---- messages -----------------------------------------------------------------------------------
    /// A PG message from a peer OSD.
    /// The driver's judgement of this OSD's fill (fullest store shard against the map ratios), applied to every
    /// later message delivery: a replica rejects / revokes backfill above backfillfull and refuses pushes above
    /// failsafe (classic `try_reserve_recovery_space`, `do_scan`; never apply into NoSpace).
    pub fn set_local_full(&mut self, f: LocalFull) {
        self.local_full = f;
    }

    /// Bytes the backfill reservations this set's replicas hold still expect (classic `get_reserved_num_bytes` summed
    /// over the PGs): the driver adds them to this OSD's fill (backfillfull / full state, MOSDFull).
    pub fn backfill_held(&self, store: &impl PgStoreOps) -> u64 {
        self.pgs.values().map(|p| p.backfill_held(store)).sum()
    }

    pub fn handle_msg(&mut self, now: Mono, m: Inbound, store: &impl PgStoreOps) -> Vec<Action> {
        self.route(now, m, store);
        self.finish_at(now, store)
    }

    /// Does this core own `spg` (always, on a single-core OSD)?
    pub fn owns(&self, spg: SpgT) -> bool {
        self.cfg
            .owner
            .is_none_or(|o| self.core_of(spg.pgid) == o.core as usize)
    }

    /// Store shard of PG `pgid`, where every message and op for it goes (adr 0031): its recorded placement, else the
    /// hash default; a seed beyond this core's map goes to its ancestor's shard. A split child that a peer or client
    /// knows of before this core applied the split thus goes where it is split off, and its route does not change when
    /// the map arrives (`place_split_children`); a merged-away source goes to its target.
    pub fn pg_shard(&self, pgid: PgT) -> u32 {
        if let Some(s) = self.place.get(&pgid) {
            return *s;
        }
        let Some(o) = self.cfg.owner else { return 0 };
        self.beyond_map(pgid).map_or_else(
            || o.default_shard(pgid.pool, pgid.seed),
            |a| self.stored_shard(a),
        )
    }

    /// The ancestor of `pgid` in the current map when its seed lies beyond the pool's `pg_num`.
    fn beyond_map(&self, pgid: PgT) -> Option<PgT> {
        let n = self.pool_pg_num(pgid.pool)?;
        (pgid.seed >= n).then(|| PgT::new(pgid.pool, pgwire::pgmath::ancestor(pgid.seed, n)))
    }

    /// Shard whose store holds the collections of PG `pgid`: its recorded placement, else the hash default. Unlike
    /// [`Self::pg_shard`] without split routing: a merge source that outlived its merge (adr 0031 am. 5) is where it is.
    pub fn stored_shard(&self, pgid: PgT) -> u32 {
        match (self.place.get(&pgid), self.cfg.owner) {
            (Some(s), _) => *s,
            (None, Some(o)) => o.default_shard(pgid.pool, pgid.seed),
            (None, None) => 0,
        }
    }

    /// Core of [`Self::stored_shard`].
    pub fn stored_core(&self, pgid: PgT) -> usize {
        self.cfg
            .owner
            .map_or(0, |o| self.stored_shard(pgid) as usize % o.cores as usize)
    }

    /// Core owning PG `pgid` (shard % cores).
    pub fn core_of(&self, pgid: PgT) -> usize {
        self.cfg
            .owner
            .map_or(0, |o| self.pg_shard(pgid) as usize % o.cores as usize)
    }

    /// Record (and tell the store) that PG `pgid` lives on `shard`.
    pub fn set_placement(&mut self, pgid: PgT, shard: u32, store: &impl PgStoreOps) {
        let Some(o) = self.cfg.owner else { return };
        if o.default_shard(pgid.pool, pgid.seed) == shard {
            self.place.remove(&pgid);
        } else {
            self.place.insert(pgid, shard);
        }
        store.place(pgid, shard);
    }

    /// A map that raises a pool's `pg_num` splits its PGs, and a child lives on its parent's shard (zero-copy split, adr
    /// 0031). Every core records that from the map itself (`before` = each pool's `pg_num` in the previous map), before
    /// a PG advances: no core routes a child by a placement it learns later from the parent's core. (The parent's core
    /// still announces each child, `Action::Placement`: the splits a boot replays.)
    fn place_split_children(&mut self, before: &BTreeMap<u64, u32>, store: &impl PgStoreOps) {
        let (Some(_), Some(cur)) = (self.cfg.owner, self.cur.clone()) else {
            return;
        };
        for (pool, n) in cur.pg_nums() {
            let Some(&old) = before.get(&pool) else {
                continue; // a new pool: its PGs are created where they hash
            };
            for seed in old..n {
                let parent = PgT::new(pool, pgwire::pgmath::ancestor(seed, old));
                let shard = self.pg_shard(parent);
                self.set_placement(PgT::new(pool, seed), shard, store);
            }
        }
    }

    /// The recorded off-default placements.
    pub fn placements(&self) -> impl Iterator<Item = (PgT, u32)> + '_ {
        self.place.iter().map(|(k, v)| (*k, *v))
    }

    /// `(is_erasure, serves)` of a pool in the current map, cached per map epoch (the gate parses the profile; it must
    /// not run per message). `serves` is the one support predicate: no cache tiering (adr 0168) AND, for erasure
    /// pools, the support gate says yes AND the kill switch allows the pool.
    fn pool_state(&self, pool: u64) -> Option<(bool, bool)> {
        self.pool_entry(pool).map(|(a, b, _)| (a, b))
    }

    /// `(is_erasure, serves, declines)`; `declines` = decline mode (adr 0039 am. 1): the support gate REJECTS the pool
    /// and `ec_decline_unsupported` is on. A supported pool disabled by the kill switch is never declined.
    pub(super) fn pool_entry(&self, pool: u64) -> Option<(bool, bool, bool)> {
        self.pool_cached(pool).map(|c| (c.1, c.2, c.3))
    }

    /// `pg_num` of a pool in the current map (cached per epoch: the routing of every message asks).
    fn pool_pg_num(&self, pool: u64) -> Option<u32> {
        self.pool_cached(pool).map(|c| c.4)
    }

    fn pool_cached(&self, pool: u64) -> Option<PoolCached> {
        let m = self.cur.as_ref()?;
        let epoch = m.epoch();
        if let Some(c) = self.pool_cache.borrow().get(&pool)
            && c.0 == epoch
        {
            return Some(*c);
        }
        let p = m.pool(pool)?;
        let name = m.pool_name(pool).unwrap_or_default();
        let serves = self.serves(&p, pool, name.as_ref());
        let declines = self.cfg.ec_decline
            && !p.tiered
            && p.is_erasure
            && p.ec.as_ref().is_some_and(|e| {
                crate::map::ec_declinable(e, &self.cfg.ec_enable_optimized, pool, &name)
            });
        let c = (epoch, p.is_erasure, serves, declines, p.pg_num);
        self.pool_cache.borrow_mut().insert(pool, c);
        Some(c)
    }

    /// The one support predicate: no cache tiering (adr 0168) AND, for erasure pools, the support gate says yes AND
    /// the kill switch allows the pool.
    fn serves(&self, p: &pgwire::intervals::PoolParams, pool: u64, name: &[u8]) -> bool {
        !p.tiered
            && (!p.is_erasure
                || p.ec.as_ref().is_some_and(|e| {
                    crate::map::ec_not_served(
                        e,
                        &self.cfg.ec_enable,
                        &self.cfg.ec_enable_optimized,
                        pool,
                        name,
                    )
                    .is_none()
                }))
    }

    /// The pools of map `m` this OSD serves (the predicate of [`Self::is_passive`] on any map, not only the current
    /// one: the control core places the PGs of a map before it is applied, adr 0639).
    pub fn served_pools(&self, m: &osdmap::OsdMap) -> BTreeSet<u64> {
        m.pools
            .iter()
            .filter(|(id, _)| **id >= 0)
            .filter(|(id, p)| {
                let pool = **id as u64;
                let name = m.pool_name.get(id).cloned().unwrap_or_default();
                self.serves(&crate::map::pool_params(m, p), pool, name.as_ref())
            })
            .map(|(id, _)| *id as u64)
            .collect()
    }

    /// Pools this OSD does not serve (the one support predicate, `pool_entry`): tiered pools (adr 0168) and erasure
    /// pools with an unsupported profile/mode or the kill switch off. Their PGs stay fully passive (no state, no
    /// output).
    pub fn is_passive(&self, pool: u64) -> bool {
        self.pool_state(pool).is_some_and(|(_, serves)| !serves)
    }

    fn note_passive(&mut self, pool: u64) {
        if self.passive_seen.insert(pool) {
            if self
                .cur
                .as_ref()
                .and_then(|m| m.pool(pool))
                .is_some_and(|p| p.tiered)
            {
                self.notices.push(format!(
                    "pool {pool} uses cache tiering (out of scope, adr 0168); PGs are passive on this OSD (no peering, no replies)"
                ));
                return;
            }
            let why = self
                .cur
                .as_ref()
                .and_then(|m| {
                    let e = m.pool(pool)?.ec?;
                    let name = m.pool_name(pool).unwrap_or_default();
                    crate::map::ec_not_served(
                        &e,
                        &self.cfg.ec_enable,
                        &self.cfg.ec_enable_optimized,
                        pool,
                        &name,
                    )
                })
                .unwrap_or_else(|| "unsupported".to_string());
            let what = if self.declines(pool) {
                "PGs are declined on this OSD (answered as an empty shard that refuses backfill, adr 0039 am. 1)"
            } else {
                "PGs are passive on this OSD (no peering, no replies)"
            };
            self.notices
                .push(format!("pool {pool} is erasure-coded: {why}; {what}"));
        }
    }

    /// `ec_enable_primary` (adr 0049): lead supported EC PGs. Applies per PG from its next interval; a PG we lead when
    /// it goes off requests one (`Pg::ec_lead_switch_off`, adr 0067 am. 4.4).
    pub fn set_ec_primary(&mut self, on: bool) {
        if self.cfg.ec_primary != on {
            Arc::make_mut(&mut self.cfg).ec_primary = on;
        }
    }

    /// `ec_decline_unsupported` (adr 0039 am. 1); applies from the next message on.
    pub fn set_ec_decline(&mut self, on: bool) {
        if self.cfg.ec_decline != on {
            Arc::make_mut(&mut self.cfg).ec_decline = on;
            self.pool_cache.borrow_mut().clear();
            self.declined.clear();
        }
    }

    /// `ec_enable_optimized_primary` (adr 0067): lead optimized EC PGs. Applies like [`Self::set_ec_primary`].
    pub fn set_ec_opt_primary(&mut self, on: bool) {
        if self.cfg.ec_opt_primary != on {
            Arc::make_mut(&mut self.cfg).ec_opt_primary = on;
        }
    }

    pub fn set_ec_rf_defer_us(&mut self, us: u64) {
        let ns = us.saturating_mul(1000);
        if self.cfg.ec_rf_defer_ns != ns {
            Arc::make_mut(&mut self.cfg).ec_rf_defer_ns = ns;
        }
    }

    /// `ec_pdw` (off | auto | always): parity-delta writes + extent cache of the mode O primary (plan S5). An
    /// unknown value keeps the current mode and returns `false` (the caller logs it).
    pub fn set_ec_pdw(&mut self, mode: &str) -> bool {
        let Some(m) = ecback::PdwMode::parse(mode) else {
            return false;
        };
        if self.cfg.ec_pdw != m {
            Arc::make_mut(&mut self.cfg).ec_pdw = m;
        }
        true
    }

    /// Does this OSD serve erasure pool `pool` as a shard in the current map (gate + kill switch)?
    pub fn serves_ec_pool(&self, pool: u64) -> bool {
        self.pool_state(pool)
            .is_some_and(|(is_ec, serves)| is_ec && serves)
    }

    /// Change the kill switch at runtime. Pools that become served get their on-disk PGs loaded (they were not in
    /// memory while passive); pools that stop being served are forgotten in memory only (disk untouched).
    pub fn set_ec_enable(
        &mut self,
        now: Mono,
        e: ec::EcEnable,
        store: &impl PgStoreOps,
    ) -> Vec<Action> {
        let opt = self.cfg.ec_enable_optimized.clone();
        self.set_ec_enables(now, e, opt, store)
    }

    /// [`Self::set_ec_enable`] for both kill switches (`ec_enable_pools`, `ec_enable_optimized`).
    pub fn set_ec_enables(
        &mut self,
        now: Mono,
        e: ec::EcEnable,
        opt: ec::EcEnable,
        store: &impl PgStoreOps,
    ) -> Vec<Action> {
        if self.cfg.ec_enable == e && self.cfg.ec_enable_optimized == opt {
            return vec![];
        }
        let c = Arc::make_mut(&mut self.cfg);
        (c.ec_enable, c.ec_enable_optimized) = (e, opt);
        self.pool_cache.borrow_mut().clear();
        self.passive_seen.clear();
        // forget PGs of pools that are passive now
        let drop: Vec<SpgT> = self
            .pgs
            .keys()
            .filter(|k| self.is_passive(k.pgid.pool))
            .copied()
            .collect();
        for k in drop {
            self.forget_pg(k);
            self.note_passive(k.pgid.pool);
        }
        // load PGs of pools that are served now (not before the boot load, never an instance that moved away)
        let list = if self.loaded {
            store.list_pgs()
        } else {
            Vec::new()
        };
        for spg in list {
            if self.pgs.contains_key(&spg)
                || self.detached.contains(&spg)
                || !self.owns(spg)
                || !self
                    .pool_state(spg.pgid.pool)
                    .is_some_and(|(is_ec, serves)| is_ec && serves)
            {
                continue;
            }
            let Some(p) = store.load_pg(spg) else {
                continue;
            };
            let Some(m) = self.start_map(spg, p.epoch) else {
                continue;
            };
            let pg = Pg::load(self.cfg.clone(), spg, p, m, now);
            self.pgs.insert(spg, pg);
        }
        self.advance_all(now, store);
        self.act_all(now, store);
        self.finish_at(now, store)
    }

    /// Operator-visible notices (log once per pool, dropped outbound violations).
    pub fn take_notices(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notices)
    }

    // ---- store / timers ------------------------------------------------------------------------------------
    /// The store committed a `Persist` action.
    pub fn on_commit(
        &mut self,
        now: Mono,
        spg: SpgT,
        token: u64,
        store: &impl PgStoreOps,
    ) -> Vec<Action> {
        if let Some(pg) = self.pgs.get_mut(&spg) {
            pg.on_commit(now, token, store);
        }
        self.collect(spg, now, store);
        self.finish_at(now, store)
    }

    /// `(PGs whose head replica write waits for its store loads longer than complaint_ns, age of the oldest such wait in
    /// ns)`: slow ops of this OSD (the client op is tracked on the primary only; `Pg::repops_held_since`).
    pub fn repops_held_slow(&self, now: Mono, complaint_ns: Mono) -> (u64, u64) {
        self.repop_wait
            .iter()
            .filter_map(|k| self.pgs.get(k)?.repops_held_since())
            .fold((0, 0), |(n, old), t| {
                let age = now.saturating_sub(t);
                (n + u64::from(age >= complaint_ns), old.max(age))
            })
    }

    /// Any PG with messages held for the store?
    pub fn repops_waiting(&self) -> bool {
        !self.repop_wait.is_empty()
    }

    /// A store page load finished: replay the held repops (adr 0021 am. 25).
    pub fn retry_repops(&mut self, now: Mono, store: &impl PgStoreOps) -> Vec<Action> {
        let keys: Vec<SpgT> = self.repop_wait.iter().copied().collect();
        let n = keys.len();
        let mut emitted = 0;
        for (i, k) in keys.into_iter().enumerate() {
            if self
                .pgs
                .get_mut(&k)
                .is_some_and(|pg| pg.retry_repops(now, store))
            {
                self.collect(k, now, store);
            }
            if self.out[emitted..]
                .iter()
                .any(|a| matches!(a, Action::Persist { .. }))
            {
                // the PGs after this one are retried by the next timer pass (`tick_due` takes every PG in `repop_wait`):
                // without it they waited for another store wake, at the end of a load burst the 1 s tick (EC sub-read
                // replies held up to ~1 s, doc/perf/tail-latency-20261015.md)
                if i + 1 < n {
                    self.tick_again = true;
                }
                break;
            }
            emitted = self.out.len();
        }
        self.finish_at(now, store)
    }

    /// Run timers of every PG (lease renewal, WAIT expiry, stats, lease expiry notice, runtime EC role switches; 1 s sweep).
    pub fn tick(&mut self, now: Mono, store: &impl PgStoreOps) -> Vec<Action> {
        self.backoff = self.scrub_draw_backoff();
        let keys: Vec<SpgT> = self.pgs.keys().copied().collect();
        let due = self
            .tick_diag
            .then(|| self.pgs.due(now).into_iter().collect());
        self.tick_pgs(keys, now, store, due)
    }

    /// [`Self::tick`] for the PGs whose deadline is due plus those holding repops or deferred by the previous tick (O(due),
    /// not O(PGs): a PG deadline fires on every core loop iteration it is due, the full sweep stays with the 1 s tick).
    pub fn tick_due(&mut self, now: Mono, store: &impl PgStoreOps) -> Vec<Action> {
        let mut keys = self.pgs.due(now);
        let held: Vec<SpgT> = self
            .repop_wait
            .iter()
            .chain(&self.tick_defer)
            .filter(|k| !keys.contains(k))
            .copied()
            .collect();
        keys.extend(held);
        self.tick_pgs(keys, now, store, None)
    }

    /// `due`: lab diagnostic of the full tick (the PGs whose deadline was due; others that move are noted).
    fn tick_pgs(
        &mut self,
        keys: Vec<SpgT>,
        now: Mono,
        store: &impl PgStoreOps,
        due: Option<BTreeSet<SpgT>>,
    ) -> Vec<Action> {
        let mut noted = 0;
        self.release_held();
        // slot replies that were made without a collect (a changed limit let queued requests through): the PGs that
        // got an answer must be collected here, else e.g. a replica's GRANT waits for the next full 1 s sweep
        for t in self.deliver_slots(now) {
            self.collect(t, now, store);
        }
        self.tick_again = false;
        let mut applying = self.out.iter().any(|a| matches!(a, Action::Persist { .. }));
        // per-tick scheduler inputs (spec scrub.md 12.1): readonly here so the loop below borrows only `self.pgs`
        let window = in_scrub_window(&self.cfg.scrub, self.local_time);
        let load = self.scrub_load < self.cfg.scrub.load_threshold;
        let recovering = self.scrub_recovering();
        let backoff = self.backoff;
        for k in keys {
            let work = store.admission_ready_for(k) && !applying;
            if work || !self.pgs.contains_key(&k) {
                self.tick_defer.remove(&k);
            } else {
                self.tick_defer.insert(k);
                self.tick_again |= store.admission_ready_for(k);
            }
            let emitted = self.out.len();
            if let Some(pg) = self.pgs.get_mut(&k) {
                let pool = k.pgid.pool;
                pg.set_scrub_gate(ScrubGate {
                    window,
                    load,
                    recovering,
                    backoff,
                    noscrub: self.scrub_flags.noscrub
                        || self.scrub_flags.pool_noscrub.contains(&pool),
                    nodeep: self.scrub_flags.nodeep || self.scrub_flags.pool_nodeep.contains(&pool),
                });
                if work {
                    pg.retry_repops(now, store);
                }
                if work {
                    pg.tick(now, store);
                } else {
                    if !store.admission_ready_for(k) {
                        pg.pause_store_replay();
                    }
                    pg.tick_timers(now);
                }
            }
            let woke_before = self.ec_woke.len();
            self.collect(k, now, store);
            if let Some(d) = &due
                && !d.contains(&k)
                && noted < 5
                && (self.out.len() > emitted || self.ec_woke.len() > woke_before)
            {
                noted += 1;
                let kinds: Vec<String> = self.out[emitted..]
                    .iter()
                    .take(4)
                    .map(|a| match a {
                        // message kind: `Repl(EcSubWrite` etc.
                        Action::Send(s) => {
                            let b = format!("{:?}", s.body);
                            b.split(['{', ' ']).next().unwrap_or("").to_string()
                        }
                        _ => {
                            let s = format!("{a:?}");
                            s.split([' ', '{', '(']).next().unwrap_or("").to_string()
                        }
                    })
                    .collect();
                self.notices.push(format!(
                    "tick diag: {k} moved only by the 1 s tick (no deadline due): actions {kinds:?}, ec wake {}",
                    self.ec_woke.len() > woke_before
                ));
            }
            applying |= self.out[emitted..]
                .iter()
                .any(|a| matches!(a, Action::Persist { .. }));
            self.pgs.note_ran(k);
        }
        self.peer_due(now, store);
        self.finish_at(now, store)
    }

    pub fn next_deadline(&self) -> Option<Mono> {
        let again = (self.tick_again || !self.loopq.is_empty()).then_some(1);
        [self.pgs.next_deadline(), self.peer_deadline(), again]
            .into_iter()
            .flatten()
            .min()
    }

    /// Re-emit pending mon requests (new mon session): up_thru and pg_temp.
    pub fn resend_mon_requests(&mut self) -> Vec<Action> {
        self.merge_sent.clear();
        self.emit_merge_reports();
        if let Some(cur) = self.cur.clone()
            && self.up_thru_want > cur.up_thru(self.cfg.whoami)
        {
            self.out.push(Action::NeedUpThru {
                want: self.up_thru_want,
            });
        }
        let reqs: Vec<(PgT, Vec<i32>)> = self
            .pgs
            .values()
            .filter(|p| !p.past_bounds_stopped())
            .filter_map(|p| p.pending_pg_temp().map(|w| (p.pgid(), w)))
            .collect();
        for (pgid, want) in reqs {
            self.out.push(Action::PgTemp { pgid, want });
        }
        self.finish()
    }

    /// Submit a replicated write on the primary PG `spg`.
    pub fn submit_write(
        &mut self,
        now: Mono,
        spg: SpgT,
        w: WriteReq,
        store: &impl PgStoreOps,
    ) -> Result<(u64, Vec<Action>), WriteErr> {
        let pg = self.pgs.get_mut(&spg).ok_or(WriteErr::NotActive)?;
        let tid = pg.submit_write(now, w, store)?;

        self.collect(spg, now, store);
        Ok((tid, self.finish_at(now, store)))
    }

    /// Attach a peer's clock slot at heartbeat peer discovery (adr 0683); samples write only the slot.
    pub fn attach_peer_clock(&mut self, osd: i32, slot: Arc<PeerClockSlot>) {
        self.cfg.peer_clocks.insert(osd, slot);
    }

    // ---- scrub control ---------------------------------------------------------------------------------
    /// Wall clock (unix ns) at monotonic 0. At runtime (forward re-anchor) the loaded PGs follow: they hold their own copy
    /// of the config (stats, scrub stamps and schedule kept the old base).
    pub fn set_wall_base(&mut self, ns: u64) {
        Arc::make_mut(&mut self.cfg).wall_base_ns = ns;
        self.pgs.set_cfg(&self.cfg);
    }

    /// Mutable scrub tunables; call before `load_pgs`, or follow with [`Self::push_cfg_to_pgs`] at runtime.
    pub fn scrub_cfg_mut(&mut self) -> &mut ScrubCfg {
        &mut Arc::make_mut(&mut self.cfg).scrub
    }

    /// Hand the current tunables to the PGs that already exist (runtime `config set`, e.g. the large-omap thresholds).
    pub fn push_cfg_to_pgs(&mut self) {
        self.pgs.set_cfg(&self.cfg);
    }

    /// Snap trimmer tunables: the PG cap `osd_max_trimming_pgs` is OSD-wide (one budget, [`crate::slots::Slots`]).
    pub fn set_snap_trim(&mut self, max_trimming_pgs: usize, concurrent: usize, sleep_ns: u64) {
        let c = Arc::make_mut(&mut self.cfg);
        c.max_trimming_pgs = max_trimming_pgs;
        c.snap_trim_concurrent = concurrent.max(1);
        c.snap_trim_sleep_ns = sleep_ns;
        let m = c.max_trimming_pgs;
        self.with_slots(|s, out| s.set_max_trimming(m, out));
    }

    /// PG log sizing (spec pglog.md 6.3): `osd_min_pg_log_entries`, `osd_max_pg_log_entries`, `osd_pg_log_trim_min`,
    /// `osd_pg_log_trim_max`, `osd_target_pg_log_entries_per_osd`, `osd_pg_log_dups_tracked`. Read at every trim like
    /// classic, so a runtime change applies to the next trim; follow with [`Self::push_cfg_to_pgs`].
    pub fn set_pg_log(&mut self, l: PgLogCfg) {
        let c = Arc::make_mut(&mut self.cfg);
        c.min_pg_log_entries = l.min_entries;
        c.max_pg_log_entries = l.max_entries;
        c.pg_log_trim_min = l.trim_min;
        c.pg_log_trim_max = l.trim_max;
        c.target_pg_log_entries_per_osd = l.target_per_osd;
        c.log_dups_tracked = l.dups_tracked;
    }

    /// PGs on the whole OSD (all cores, primary and replica): the per-PG log target is
    /// `osd_target_pg_log_entries_per_osd / num_pgs` (spec pglog.md 6.3). Follow with [`Self::push_cfg_to_pgs`].
    pub fn set_num_pgs(&mut self, n: u64) -> bool {
        self.pgs_at_hint = self.pgs.len() as u64;
        if self.cfg.num_pgs_hint == n {
            return false;
        }
        Arc::make_mut(&mut self.cfg).num_pgs_hint = n;
        true
    }

    /// Stats re-publish bounds of an unchanged primary PG (`osd_pg_stat_report_interval_max_seconds` / `_epochs`,
    /// spec pg-io-stats.md 5) and the recovery chunk budget (`osd_recovery_max_chunk`). Follow with
    /// [`Self::push_cfg_to_pgs`].
    pub fn set_stats_report(&mut self, interval: Mono, epochs: u32, recovery_max_chunk: u64) {
        let c = Arc::make_mut(&mut self.cfg);
        c.stats_interval = interval;
        c.stats_epochs = epochs;
        c.recovery_max_chunk = recovery_max_chunk.max(1);
    }

    /// `osd_backfill_scan_min` / `osd_backfill_scan_max`: objects per backfill scan; a batch holds at least one object
    /// and the minimum never exceeds the maximum. Follow with [`Self::push_cfg_to_pgs`].
    pub fn set_backfill_scan(&mut self, min: u64, max: u64) {
        let c = Arc::make_mut(&mut self.cfg);
        c.backfill_scan_max = usize::try_from(max.max(1)).unwrap_or(usize::MAX);
        c.backfill_scan_min = usize::try_from(min)
            .unwrap_or(usize::MAX)
            .min(c.backfill_scan_max);
    }

    /// `osd_map_cache_size`: epochs kept in memory below the newest map (applies at the next map).
    pub fn set_map_cache(&mut self, epochs: u32) {
        Arc::make_mut(&mut self.cfg).map_cache = epochs;
    }

    /// `osd_max_push_objects` / `osd_max_push_cost`: objects and accumulated cost per recovery push / delete message
    /// (spec replication.md 6.3, 6.5). Follow with [`Self::push_cfg_to_pgs`].
    pub fn set_push_cfg(&mut self, objects: u64, cost: u64) {
        let c = Arc::make_mut(&mut self.cfg);
        c.max_push_objects = usize::try_from(objects.max(1)).unwrap_or(usize::MAX);
        c.max_push_cost = cost.max(1);
    }

    /// `osd_recovery_retry_interval` and `osd_backfill_retry_interval`: pause after a too-full refusal before the
    /// next attempt (spec peering.md 13.3). Follow with [`Self::push_cfg_to_pgs`].
    pub fn set_retry_intervals(&mut self, recovery: Mono, backfill: Mono) {
        let c = Arc::make_mut(&mut self.cfg);
        c.recovery_retry = recovery;
        c.backfill_retry = backfill;
    }

    /// `osd_recovery_sleep*`: the all-flash non-degraded and degraded pause before a recovery/backfill invocation
    /// (spec peering.md 13.1). Follow with [`Self::push_cfg_to_pgs`].
    pub fn set_recovery_sleep(&mut self, normal: Mono, degraded: Mono) {
        let c = Arc::make_mut(&mut self.cfg);
        c.recovery_sleep = normal;
        c.recovery_sleep_degraded = degraded;
    }

    /// `osd_allow_recovery_below_min_size` (spec peering.md 13.4). Follow with [`Self::push_cfg_to_pgs`].
    pub fn set_allow_recovery_below_min_size(&mut self, v: bool) {
        Arc::make_mut(&mut self.cfg).allow_recovery_below_min_size = v;
    }

    /// `osd_max_backfills` (OSD-wide, not split over the cores): primary-side and replica-side reservations.
    pub fn set_max_backfills(&mut self, n: usize) {
        let c = Arc::make_mut(&mut self.cfg);
        c.max_backfills = n;
        let m = c.max_backfills;
        self.with_slots(|s, out| s.set_max_backfills(m, out));
    }

    /// `osd_min_recovery_priority`: lower priority reservations wait (and lose their slot).
    pub fn set_min_recovery_priority(&mut self, min: u32) {
        self.with_slots(|s, out| s.set_min_recovery_priority(min, out));
    }

    /// Runtime recovery message header priority policy, separate from reservation priority.
    pub fn set_recovery_message_priority(&mut self, mclock: bool, priority: u16) {
        let c = Arc::make_mut(&mut self.cfg);
        c.recovery_mclock = mclock;
        c.recovery_op_priority = priority;
    }

    /// `osd_max_scrubs` (OSD-wide, not split over the cores): local (primary) and replica scrub slots, counted
    /// separately like classic.
    pub fn set_max_scrubs(&mut self, n: usize) {
        let c = Arc::make_mut(&mut self.cfg);
        c.max_scrubs = n;
        let m = c.max_scrubs;
        self.with_slots(|s, out| s.set_max_scrubs(m, out));
    }

    /// Change a limit on the core that keeps the budgets (the others never use it); the queued requests it lets
    /// through are answered at the next collect or tick.
    fn with_slots(&mut self, f: impl FnOnce(&mut crate::slots::Slots, &mut Vec<(u32, SlotReply)>)) {
        let mut replies = Vec::new();
        if let Some(s) = self.slots.as_mut() {
            f(s, &mut replies);
        }
        self.route_replies(replies);
    }

    /// Default read lease length (`osd_heartbeat_grace x osd_pool_default_read_lease_ratio`); a pool's
    /// `read_lease_interval` option overrides it per PG (peering.md 8.2).
    pub fn set_readable_interval(&mut self, ns: u64) {
        Arc::make_mut(&mut self.cfg).readable_interval =
            ns.clamp(1, crate::types::MAX_READABLE_INTERVAL);
    }

    /// Lab (NV_PHASE): note PGs that only the full 1 s tick moved.
    pub fn set_tick_diag(&mut self, on: bool) {
        self.tick_diag = on;
    }

    /// `flashstore_peering_trace_ms` (0 = off): note peerings that take at least this long, with the time per phase.
    pub fn set_peer_trace_ms(&mut self, ms: u64) {
        Arc::make_mut(&mut self.cfg).peer_trace_ns = ms.saturating_mul(1_000_000);
    }

    /// Per-op EC trace (`debug_osd` >= 15, OQ 41). Returns true when it changed (the caller pushes the config).
    pub fn set_ec_trace(&mut self, on: bool) -> bool {
        if self.cfg.ec_trace == on {
            return false;
        }
        Arc::make_mut(&mut self.cfg).ec_trace = on;
        true
    }

    /// Current configuration (read side for drivers).
    pub fn cfg_ref(&self) -> &Config {
        &self.cfg
    }

    /// 1-minute load average of the host divided by its online CPUs (`osd_scrub_load_threshold` gate, spec 12.1.2).
    pub fn set_scrub_load(&mut self, load: f64) {
        self.scrub_load = load;
    }

    /// Local wall clock of the OSD host for the scrub windows (spec 12.1.1); the OSD refreshes it on every 1 s tick.
    pub fn set_local_time(&mut self, t: LocalTime) {
        self.local_time = t;
    }

    /// Any local or remote recovery reservation held OSD-wide (spec 12.1.3), broadcast by the budget owner core.
    /// The owner itself reads its slots ([`Self::scrub_recovering`]).
    pub fn set_scrub_recovering(&mut self, v: bool) {
        self.recovering = v;
    }

    /// Any local or remote recovery reservation held OSD-wide (spec 12.1.3).
    pub fn scrub_recovering(&self) -> bool {
        self.slots
            .as_ref()
            .map_or(self.recovering, |s| s.recovery_active())
    }

    /// `osd_scrub_backoff_ratio`: with this probability a tick skips the low urgencies while a local scrub slot is
    /// free (spec 12.1.3). One draw per tick and core; a skip records no delay and counts nothing. A core without
    /// the budget (`slots` elsewhere) always draws: its start still has to take the OSD-wide slot.
    fn scrub_draw_backoff(&mut self) -> bool {
        let ratio = self.cfg.scrub.backoff_ratio;
        if ratio <= 0.0 {
            return false;
        }
        if ratio >= 1.0 {
            return true;
        }
        if self
            .slots
            .as_ref()
            .is_some_and(|s| s.local_scrubs() >= self.cfg.max_scrubs)
        {
            return false;
        }
        self.scrub_rng.next_f64() < ratio
    }

    /// NOSCRUB / NODEEP_SCRUB of the current map.
    pub fn set_scrub_flags(&mut self, f: ScrubFlags) {
        self.scrub_flags = f;
    }

    /// `dump_recovery_reservations` data of this core: the primary-side LOCAL reserver `(granted (pg, is_backfill), queued
    /// (prio, pg, is_backfill))` and the replica-side limiter.
    pub fn reservations(&self) -> crate::Reservations {
        self.slots
            .as_ref()
            .map(|s| s.dump_resv())
            .unwrap_or_default()
    }

    /// Primary-side local reserver: `(granted, queued)` slots over both pools (diagnostics, tests: all zero when idle).
    pub fn local_slots(&self) -> (usize, usize) {
        self.slots
            .as_ref()
            .map_or((0, 0), |s| s.local_resv_counts())
    }

    /// Diagnostics (`dump_pgs`): messages parked in this core's set `(waiting for a map, waiting for their PG, behind an
    /// old-map replay)`.
    pub fn parked_msgs(&self) -> (usize, usize, usize) {
        (
            self.waiting_map.values().map(Vec::len).sum(),
            self.waiting_pg.values().map(Vec::len).sum(),
            self.parked_old.values().map(|p| p.after.len() + 1).sum(),
        )
    }

    /// `dump_scrub_reservations` part of this core: `(local slots, replica slots granted, replica queue)`. The OSD-wide
    /// lists live on the core that keeps the budget; the others report none (the control core sums the parts).
    pub fn scrub_reservations(&self) -> (Vec<SpgT>, Vec<SpgT>, Vec<SpgT>) {
        self.slots.as_ref().map(|s| s.dump()).unwrap_or_default()
    }

    /// `mark_unfound_lost` for one PG we lead: `None` = no such PG here.
    pub fn mark_unfound_lost(
        &mut self,
        now: Mono,
        spg: SpgT,
        mode: crate::LostMode,
        store: &impl PgStoreOps,
    ) -> (Option<crate::LostReply>, Vec<Action>) {
        let Some(pg) = self.pgs.get_mut(&spg) else {
            return (None, Vec::new());
        };
        let r = pg.mark_unfound_lost(now, mode, store);
        self.collect(spg, now, store);
        (Some(r), self.finish_at(now, store))
    }

    /// `scrub-abort` for one PG we lead: `None` = no such PG here, `Some(aborted)` otherwise.
    pub fn scrub_abort(
        &mut self,
        now: Mono,
        spg: SpgT,
        store: &impl PgStoreOps,
    ) -> (Option<bool>, Vec<Action>) {
        let Some(pg) = self.pgs.get_mut(&spg) else {
            return (None, Vec::new());
        };
        let r = pg.scrub_abort(now, store);
        self.collect(spg, now, store);
        (Some(r), self.finish_at(now, store))
    }

    /// PGs holding a local scrub slot (diagnostics).
    pub fn local_scrubs(&self) -> usize {
        self.slots.as_ref().map_or(0, |s| s.local_scrubs())
    }

    /// PGs holding a trim slot (`osd_max_trimming_pgs`), diagnostics/tests.
    pub fn trimming_pgs(&self) -> usize {
        self.slots.as_ref().map_or(0, |s| s.trimming_pgs())
    }

    /// `ceph pg scrub|deep-scrub|repair` for one PG we lead (admin socket / tests).
    pub fn request_scrub(
        &mut self,
        now: Mono,
        spg: SpgT,
        deep: bool,
        repair: bool,
        store: &impl PgStoreOps,
    ) -> Vec<Action> {
        if let Some(pg) = self.pgs.get_mut(&spg) {
            pg.request_scrub(now, deep, repair, store);
        }
        self.collect(spg, now, store);
        self.finish_at(now, store)
    }

    /// MOSDScrub2 from the mgr (the caller checked the sender is a mon/mgr and the fsid): request the scrub on every
    /// listed PG that is ours and primary; everything else is ignored silently.
    pub fn scrub_command(
        &mut self,
        now: Mono,
        m: replwire::MOSDScrub2,
        store: &impl PgStoreOps,
    ) -> Vec<Action> {
        self.scrub_command_inner(now, m, store);
        self.finish_at(now, store)
    }

    fn scrub_command_inner(&mut self, now: Mono, m: replwire::MOSDScrub2, store: &impl PgStoreOps) {
        if m.epoch > self.epoch() {
            self.request_map();
            if self.parked_scrub_cmds.len() < PARKED_SCRUB_MAX {
                self.parked_scrub_cmds.push(m);
            } else {
                // an operator command must never vanish silently
                self.drop_msg("parked scrub commands: queue full");
                let n = self
                    .dropped
                    .get("parked scrub commands: queue full")
                    .copied()
                    .unwrap_or(0);
                if n.is_power_of_two() {
                    self.notices.push(format!(
                        "WARN MOSDScrub2 epoch {} dropped: {PARKED_SCRUB_MAX} commands already parked for a newer map ({n} dropped)",
                        m.epoch
                    ));
                }
            }
            return;
        }
        // classic: no PG listed = every PG this OSD is primary for (`ceph osd scrub N`, `tell osd.N scrub`)
        let targets: Vec<SpgT> = if m.scrub_pgs.is_empty() {
            self.pgs
                .iter()
                .filter(|(_, p)| p.is_primary())
                .map(|(s, _)| *s)
                .collect()
        } else {
            m.scrub_pgs
        };
        for spg in targets {
            if self.is_passive(spg.pgid.pool) {
                continue;
            }
            if let Some(pg) = self.pgs.get_mut(&spg) {
                pg.request_scrub(now, m.deep, m.repair, store);
            }
            self.collect(spg, now, store);
        }
    }

    /// MOSDForceRecovery from the mgr (the caller checked the sender is a mon/mgr and the fsid): set or cancel the forced
    /// flag on every listed PG that is ours; everything else (replicas, unknown PGs, passive pools) is ignored. No epoch
    /// check (spec force-recovery.md 3).
    pub fn force_command(
        &mut self,
        now: Mono,
        m: replwire::MOSDForceRecovery,
        store: &impl PgStoreOps,
    ) -> Vec<Action> {
        use replwire::MOSDForceRecovery as F;
        // backfill wins when both bits are set; neither bit: nothing
        let backfill = m.options & F::OFR_BACKFILL != 0;
        if backfill || m.options & F::OFR_RECOVERY != 0 {
            for spg in m.forced_pgs {
                if self.is_passive(spg.pgid.pool) {
                    continue;
                }
                if let Some(pg) = self.pgs.get_mut(&spg) {
                    pg.force_recovery(now, backfill, m.options & F::OFR_CANCEL != 0, store);
                }
                self.collect(spg, now, store);
            }
        }
        self.finish_at(now, store)
    }

    /// Minimum `last_epoch_clean` over primary PGs (MOSDBeacon, osd-lifecycle 8.4).
    pub fn min_last_epoch_clean(&self) -> Option<u32> {
        self.pgs
            .values()
            .filter(|p| p.is_primary())
            .map(|p| {
                if p.is_clean() {
                    p.map_epoch()
                } else {
                    p.info().history.last_epoch_clean
                }
            })
            .min()
    }
}

#[cfg(test)]
mod finish_tests {
    use super::*;

    /// Review L1: without a map the outbound choke point cannot validate a PG message: it drops it (fail closed) and
    /// keeps every other action.
    #[test]
    fn finish_without_a_map_drops_sends() {
        let mut set = PgSet::new(Config::new(0));
        let body = Body::Ec(ecwire::EcMsg::from(ecwire::MOSDECSubOpRead::default()));
        set.out.push(Action::Send(Box::new(Send {
            to: 1,
            epoch: 1,
            tid: 0,
            prio: 0,
            body,
            producer: None,
        })));
        set.out.push(Action::PgTemp {
            pgid: denc::types::PgT::new(1, 0),
            want: vec![],
        });
        let out = set.finish();
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(matches!(out[0], Action::PgTemp { .. }));
        assert_eq!(set.dropped.get("send before the first map"), Some(&1));
    }
}

#[cfg(test)]
mod bounds_stop_tests {
    use super::*;
    use crate::map::synth::SynthMap;
    use crate::store::MemStore;
    use denc::types::PgShard;
    use pgwire::{CompactInterval, MOSDPGLease};

    const POOL: u64 = 1;

    fn spg() -> SpgT {
        SpgT {
            pgid: PgT::new(POOL, 0),
            shard: ShardId::NO_SHARD,
        }
    }

    fn map(epoch: u32) -> MapHandle {
        let mut m = SynthMap::new(epoch);
        for o in 0..3 {
            m = m.with_osd(o, 1);
        }
        m = m.with_pool(POOL, 2, 1, 2);
        m.up_override.insert(PgT::new(POOL, 0), vec![0, 1]);
        m.into_handle()
    }

    /// `past(first, last)` covers `[first, last + 1)`; one participant keeps the prior set simple.
    fn past(first: u32, last: u32) -> PastIntervals {
        let acting = BTreeSet::from([PgShard {
            osd: 1,
            shard: ShardId::NO_SHARD,
        }]);
        PastIntervals {
            first,
            last,
            all_participants: acting.clone(),
            intervals: vec![CompactInterval {
                first,
                last,
                acting,
            }],
        }
    }

    fn lease() -> PeeringMsg {
        MOSDPGLease {
            epoch: 6,
            spgid: spg(),
            lease: Default::default(),
        }
        .into()
    }

    fn outbound(acts: &[Action]) -> usize {
        acts.iter()
            .filter(|a| matches!(a, Action::Send(_) | Action::PgTemp { .. }))
            .count()
    }

    /// A primary PG created from an implausible Notify2 (lec 3, sis 6, stored past [3,5)): stopped.
    fn stopped() -> (PgSet, MemStore) {
        let store = MemStore::new();
        let mut set = PgSet::new(Config::new(0));
        for e in 2..=6 {
            let _ = set.handle_map(0, map(e), &store);
        }
        let s = spg();
        let mut info = PgInfo::new(s);
        info.history.epoch_created = 1;
        info.history.epoch_pool_created = 1;
        info.history.last_epoch_started = 3;
        info.history.last_epoch_clean = 3;
        info.history.same_interval_since = 6;
        info.history.same_up_since = 6;
        info.history.same_primary_since = 6;
        let mut n = PgNotify::dne(info, ShardId::NO_SHARD, 6, 6);
        n.past_intervals = past(3, 4);
        let _ = set.handle_msg(
            0,
            Inbound {
                ingress: Default::default(),
                from: 1,
                tid: 0,
                prio: pgwire::msgs::PRIO_DEFAULT,
                body: Box::new(Body::Peering(
                    MOSDPGNotify2 {
                        spgid: s,
                        notify: n,
                    }
                    .into(),
                )),
            },
            &store,
        );
        assert!(set.pg(s).unwrap().past_bounds_stopped());
        set.take_notices();
        (set, store)
    }

    /// The silence of a stopped PG (peering.md 3.8) holds on every outbound path, gated by the producing instance: a
    /// send and a pg_temp request made after the stop (the paths a tick's runtime role switch uses), a send a split gate
    /// held back, and the reconnect resend are all dropped; the primary keeps reporting its INCOMPLETE state to the mgr.
    #[test]
    fn stopped_pg_sends_nothing_on_any_path() {
        let (mut set, store) = stopped();
        let s = spg();
        {
            let pg = set.pgs.get_mut(&s).unwrap();
            pg.send_peering(1, lease());
            pg.request_pg_temp(vec![0, 1]);
        }
        let acts = set.tick(10 * SEC, &store);
        assert_eq!(outbound(&acts), 0, "tick / timers: {acts:?}");
        assert!(
            acts.iter()
                .any(|a| matches!(a, Action::PgStats { spg, .. } if *spg == s)),
            "the primary still reports INCOMPLETE: {acts:?}"
        );
        assert_eq!(
            set.dropped.get("outbound message of a bounds-stopped pg"),
            Some(&2)
        );
        // a send a split gate held back before the stop is released later: still dropped
        set.held.push(Action::Send(Box::new(crate::types::Send {
            to: 1,
            epoch: 6,
            tid: 0,
            prio: 0,
            body: Body::Peering(lease()),
            producer: Some(s),
        })));
        assert_eq!(
            outbound(&set.finish()),
            0,
            "held send released after the stop"
        );
        // a new mon session re-issues pending pg_temp requests from the PG straight into the output
        let acts = set.resend_mon_requests();
        assert_eq!(outbound(&acts), 0, "reconnect resend: {acts:?}");
        assert!(set.pg(s).unwrap().past_bounds_stopped());
    }

    const EC_POOL: u64 = 7;

    fn ec_spg(shard: i8) -> SpgT {
        SpgT {
            pgid: PgT::new(EC_POOL, 0),
            shard: ShardId(shard),
        }
    }

    /// Pool `EC_POOL` (k 2, m 1) placed on `acting`, one PG.
    fn ec_map(epoch: u32, acting: [i32; 3]) -> MapHandle {
        let mut m = SynthMap::new(epoch);
        for o in 0..3 {
            m = m.with_osd(o, 1);
        }
        m = m.with_pool(EC_POOL, 3, 2, 1);
        let p = m.pools.get_mut(&EC_POOL).unwrap();
        p.is_erasure = true;
        p.ec_k = 2;
        p.ec = Some(std::sync::Arc::new(pgwire::EcPoolInfo {
            k: 2,
            m: 1,
            stripe_width: 8192,
            chunk_size: 4096,
            overwrites: true,
            supported: true,
            plugin: "isa".into(),
            technique: "reed_sol_van".into(),
            chunk_mapping: vec![0, 1, 2],
            sub_chunks: 1,
            primary_ok: true,
            ..Default::default()
        }));
        m.up_override.insert(PgT::new(EC_POOL, 0), acting.to_vec());
        m.into_handle()
    }

    /// `past(first, last)` covers `[first, last + 1)`; the participants are the acting shards of `[0,0,1]`.
    fn ec_past(first: u32, last: u32) -> PastIntervals {
        let acting = BTreeSet::from([
            PgShard {
                osd: 0,
                shard: ShardId(0),
            },
            PgShard {
                osd: 0,
                shard: ShardId(1),
            },
            PgShard {
                osd: 1,
                shard: ShardId(2),
            },
        ]);
        PastIntervals {
            first,
            last,
            all_participants: acting.clone(),
            intervals: vec![CompactInterval {
                first,
                last,
                acting,
            }],
        }
    }

    /// Commit every persist of a batch and hand the commit back (the driver's store side); what the commits produce
    /// is returned for inspection.
    fn commit(set: &mut PgSet, store: &mut MemStore, acts: Vec<Action>) -> Vec<Action> {
        let mut out = Vec::new();
        for a in acts {
            if let Action::Persist { spg, token, txn } = a {
                store.submit(spg, &txn);
                out.extend(set.on_commit(0, spg, token, store));
            }
        }
        out
    }

    fn ec_lease() -> PeeringMsg {
        MOSDPGLease {
            epoch: 7,
            spgid: ec_spg(2),
            lease: Default::default(),
        }
        .into()
    }

    fn ec_notify(set: &mut PgSet, store: &MemStore, shard: i8, past: PastIntervals) -> Vec<Action> {
        let s = ec_spg(shard);
        let mut info = PgInfo::new(s);
        info.history.epoch_created = 1;
        info.history.epoch_pool_created = 1;
        info.history.last_epoch_started = 3;
        info.history.last_epoch_clean = 3;
        info.history.same_interval_since = 6;
        info.history.same_up_since = 6;
        info.history.same_primary_since = 6;
        let mut n = PgNotify::dne(info, ShardId(shard), 6, 6);
        n.past_intervals = past;
        set.handle_msg(
            0,
            Inbound {
                ingress: Default::default(),
                from: if shard == 0 { 1 } else { 2 },
                tid: 0,
                prio: pgwire::msgs::PRIO_DEFAULT,
                body: Box::new(Body::Peering(
                    MOSDPGNotify2 {
                        spgid: s,
                        notify: n,
                    }
                    .into(),
                )),
            },
            store,
        )
    }

    /// Local delivery runs before the driver sees returned actions, including an earlier activation persist.
    #[test]
    fn loopback_subread_waits_for_unapplied_persist() {
        let mut store = MemStore::new();
        let mut cfg = Config::new(0);
        cfg.ec_enable = ec::EcEnable::All;
        let mut set = PgSet::new(cfg);
        let _ = set.handle_map(0, ec_map(7, [1, 0, 2]), &store);
        let spg = ec_spg(1);
        let mut info = PgInfo::new(spg);
        info.history = PgHistory {
            epoch_created: 7,
            epoch_pool_created: 7,
            same_interval_since: 7,
            same_up_since: 7,
            same_primary_since: 7,
            ..Default::default()
        };
        let acts = set.handle_msg(
            0,
            Inbound {
                ingress: Default::default(),
                from: 1,
                tid: 0,
                prio: pgwire::msgs::PRIO_DEFAULT,
                body: Box::new(Body::Peering(
                    MOSDPGLog {
                        epoch: 7,
                        info,
                        log: PgLog::default(),
                        missing: Default::default(),
                        query_epoch: 7,
                        past_intervals: PastIntervals::default(),
                        to: ShardId(1),
                        from: ShardId(0),
                        lease: None,
                    }
                    .into(),
                )),
            },
            &store,
        );
        // Model actions awaiting the enclosing finish_at; the driver has applied none yet.
        set.out.extend(acts);
        set.loopq.push_back((
            None,
            Inbound {
                ingress: Default::default(),
                from: 1,
                tid: 11,
                prio: pgwire::msgs::PRIO_DEFAULT,
                body: Box::new(Body::Ec(
                    ecwire::MOSDECSubOpRead {
                        pgid: spg,
                        map_epoch: 7,
                        min_epoch: 7,
                        op: ecwire::ECSubRead {
                            from: PgShard {
                                osd: 1,
                                shard: ShardId(0),
                            },
                            tid: 11,
                            ..Default::default()
                        },
                        trace: [0; 3],
                        cost: 0,
                    }
                    .into(),
                )),
            },
        ));
        let is_read_reply = |a: &Action| matches!(a, Action::Send(s) if matches!(&s.body, Body::Ec(ecwire::EcMsg::ReadReply(_))));
        let acts = set.finish_at(0, &store);
        assert!(
            !acts.iter().any(is_read_reply),
            "read escaped before persist"
        );
        assert_eq!(set.pg(spg).unwrap().repops_held(), 1);
        let after = commit(&mut set, &mut store, acts);
        assert!(
            after.iter().any(is_read_reply),
            "read was not released by commit"
        );
    }

    /// Two instances of one pgid on this OSD (adr 0049 am. 1): stopping the stray shard must not silence the healthy
    /// primary's sends or its removal of the stopped shard, and the stopped shard sends nothing (peering.md 3.8).
    #[test]
    fn stopped_ec_shard_does_not_silence_the_healthy_primary() {
        let mut store = MemStore::new();
        let mut cfg = Config::new(0);
        cfg.ec_enable = ec::EcEnable::All;
        cfg.ec_primary = true;
        let mut set = PgSet::new(cfg);
        for e in 2..=6 {
            let _ = set.handle_map(0, ec_map(e, [0, 0, 1]), &store);
        }
        let acts = ec_notify(&mut set, &store, 0, ec_past(3, 5));
        commit(&mut set, &mut store, acts);
        let acts = ec_notify(&mut set, &store, 1, ec_past(5, 5));
        commit(&mut set, &mut store, acts);
        let (s0, s1) = (ec_spg(0), ec_spg(1));
        assert!(!set.pg(s0).unwrap().past_bounds_stopped());
        assert!(
            !set.pg(s1).unwrap().past_bounds_stopped(),
            "a replica checks at its next interval start"
        );
        set.take_notices();
        // shard 1 leaves the acting set: its closed interval has an implausible pair and it stops; shard 0 stays
        let acts = set.handle_map(0, ec_map(7, [0, 2, 1]), &store);
        commit(&mut set, &mut store, acts);
        assert!(!set.pg(s0).unwrap().past_bounds_stopped());
        assert!(set.pg(s1).unwrap().past_bounds_stopped());
        let sent = |acts: &[Action], from: SpgT| {
            acts.iter()
                .any(|a| matches!(a, Action::Send(s) if s.producer == Some(from)))
        };
        // the healthy primary's messages name the same pgid as the stopped shard, but are its own
        assert!(
            set.pg(s0).unwrap().ec_leads(),
            "the primary leads the EC PG"
        );
        let acts = set
            .with_pg(0, s0, &store, |pg| pg.send_peering(1, ec_lease()))
            .unwrap()
            .1;
        assert!(
            sent(&acts, s0),
            "the healthy primary's sends go out: {acts:?} dropped {:?}",
            set.dropped
        );
        let acts = set
            .with_pg(0, s1, &store, |pg| pg.send_peering(1, ec_lease()))
            .unwrap()
            .1;
        assert!(!sent(&acts, s1), "the stopped shard stays silent: {acts:?}");
        // the primary's removal of the stopped stray goes out and removes it through the local loopback
        let acts = set
            .with_pg(0, s0, &store, |pg| {
                pg.prim.stray_set.insert(PgShard {
                    osd: 0,
                    shard: ShardId(1),
                });
                pg.go_clean();
            })
            .unwrap()
            .1;
        assert!(
            set.pg(s1).unwrap().is_deleting(),
            "the primary's removal reached the stopped stray: {acts:?}"
        );
        assert!(
            acts.iter().any(|a| matches!(
                a,
                Action::Persist { spg, txn, .. }
                    if *spg == s1 && matches!(txn.ops.as_slice(), [crate::store::StoreOp::RemovePg])
            )),
            "only the removal is written for the stray: {acts:?}"
        );
        commit(&mut set, &mut store, acts);
        assert!(set.pg(s1).is_none(), "the removal completed");
        assert!(!set.pg(s0).unwrap().past_bounds_stopped());
    }
}

#[cfg(test)]
mod slot_tests {
    use super::*;
    use crate::store::MemStore;

    #[test]
    fn zero_maintenance_limits_survive_pgset_runtime_updates() {
        let mut s = PgSet::new(Config::new(0));
        s.set_max_scrubs(0);
        s.set_max_backfills(0);
        s.set_snap_trim(0, 1, 0);
        assert_eq!(s.cfg.max_scrubs, 0);
        assert_eq!(s.cfg.max_backfills, 0);
        assert_eq!(s.cfg.max_trimming_pgs, 0);
        s.set_max_scrubs(3);
        s.set_max_backfills(2);
        s.set_snap_trim(4, 1, 0);
        assert_eq!(
            (
                s.cfg.max_scrubs,
                s.cfg.max_backfills,
                s.cfg.max_trimming_pgs
            ),
            (3, 2, 4)
        );
    }

    const CORES: u32 = 8;

    fn spg(n: u32) -> SpgT {
        SpgT {
            pgid: denc::types::PgT::new(1, n),
            shard: denc::types::ShardId::NO_SHARD,
        }
    }

    fn cores() -> Vec<PgSet> {
        (0..CORES)
            .map(|c| {
                let mut cfg = Config::new(0);
                cfg.owner = Some(Owner {
                    core: c,
                    cores: CORES,
                    shards: 1,
                });
                let mut s = PgSet::new(cfg);
                s.set_max_scrubs(1);
                s
            })
            .collect()
    }

    /// Run the cross-core slot traffic of `acts` (from `core`) until it ends.
    fn pump(sets: &mut [PgSet], core: usize, acts: Vec<Action>) {
        let st = MemStore::new();
        let mut q: Vec<(usize, Action)> = acts.into_iter().map(|a| (core, a)).collect();
        while let Some((from, a)) = q.pop() {
            let next = match a {
                Action::Slot(req) => {
                    assert_eq!(req.from as usize, from);
                    sets[0].slot_rx_req(0, req, &st)
                }
                Action::SlotReply { core, reply } => {
                    let c = core as usize;
                    let o = sets[c].slot_rx_reply(0, reply, &st);
                    q.extend(o.into_iter().map(|a| (c, a)));
                    continue;
                }
                _ => continue,
            };
            q.extend(next.into_iter().map(|a| (0, a)));
        }
    }

    fn ask(sets: &mut [PgSet], core: usize, pool: SlotPool, n: u32, op: SlotOp) {
        sets[core].slot_op(pool, spg(n), op);
        let acts = sets[core].finish();
        pump(sets, core, acts);
    }

    /// `osd_max_scrubs` 1 on 8 cores: the budget is OSD-wide, a second core's immediate request is rejected and a
    /// queued one waits for the release (no PG exists here, so each grant is handed straight back: nothing leaks).
    #[test]
    fn budget_is_osd_wide_and_vanished_pgs_free_their_slot() {
        let mut sets = cores();
        for c in 0..CORES as usize {
            ask(
                &mut sets,
                c,
                SlotPool::ScrubLocal,
                c as u32,
                SlotOp::Request {
                    immediate: false,
                    prio: 0,
                },
            );
        }
        assert_eq!(
            sets[0].local_scrubs(),
            0,
            "grants to PGs that are gone come back"
        );
        assert!(sets.iter().all(|s| s.slot_open.is_empty()));
    }

    /// A held local slot is granted again at the same priority; a changed priority (force-recovery set / cancelled)
    /// goes to the owner so its queue can re-order and preempt.
    #[test]
    fn held_local_slot_follows_a_priority_change() {
        let mut sets = cores();
        let pool = SlotPool::Resv {
            local: true,
            backfill: false,
        };
        let key = (pool, spg(1));
        let held = SlotOpen {
            seq: 5,
            granted: true,
            prio: 180,
        };
        sets[0].slot_open.insert(key, held);
        sets[0].local_request(spg(1), 180, false);
        assert_eq!(
            sets[0].slot_open[&key].seq, 5,
            "same priority: no new request"
        );
        assert_eq!(sets[0].slot_in.len(), 1);
        sets[0].local_request(spg(1), 255, false);
        let o = sets[0].slot_open[&key];
        assert_eq!((o.prio, o.granted), (255, false));
        assert_ne!(o.seq, 5, "a new request went to the owner");
    }

    /// Same for the reservation and trim pools: 8 cores ask, no PG exists, so every grant is handed straight back and
    /// nothing leaks (`osd_max_backfills` 1, `osd_max_trimming_pgs` 1).
    #[test]
    fn reservation_and_trim_slots_of_vanished_pgs_are_freed() {
        for pool in [
            SlotPool::Resv {
                local: true,
                backfill: true,
            },
            SlotPool::Resv {
                local: true,
                backfill: false,
            },
            SlotPool::Resv {
                local: false,
                backfill: true,
            },
            SlotPool::Resv {
                local: false,
                backfill: false,
            },
            SlotPool::Trim,
        ] {
            let mut sets = cores();
            for s in sets.iter_mut() {
                s.set_max_backfills(1);
                s.set_snap_trim(1, 1, 0);
            }
            for c in 0..CORES as usize {
                let op = SlotOp::Request {
                    immediate: false,
                    prio: 100,
                };
                ask(&mut sets, c, pool, c as u32, op);
            }
            assert_eq!(sets[0].local_slots(), (0, 0), "{pool:?}");
            assert!(sets[0].reservations().remote.queued.is_empty(), "{pool:?}");
            assert!(sets.iter().all(|s| s.slot_open.is_empty()), "{pool:?}");
        }
    }

    /// A reply of a request since released is ignored: it must not count as the slot of a later request.
    #[test]
    fn stale_reply_is_ignored() {
        let mut sets = cores();
        sets[3].slot_op(
            SlotPool::ScrubReplica,
            spg(1),
            SlotOp::Request {
                immediate: true,
                prio: 0,
            },
        );
        let first = sets[3].slot_seq;
        sets[3].slot_op(SlotPool::ScrubReplica, spg(1), SlotOp::Release);
        sets[3].slot_op(
            SlotPool::ScrubReplica,
            spg(1),
            SlotOp::Request {
                immediate: false,
                prio: 0,
            },
        );
        let sent = sets[3].finish();
        assert_eq!(sent.len(), 3, "request, release, request: {sent:?}");
        let st = MemStore::new();
        let acts = sets[3].slot_rx_reply(
            0,
            SlotReply {
                pool: SlotPool::ScrubReplica,
                spg: spg(1),
                seq: first,
                answer: SlotAnswer::Granted,
            },
            &st,
        );
        assert!(
            acts.is_empty(),
            "a stale grant must not release or take anything: {acts:?}"
        );
        assert_eq!(sets[3].slot_open.len(), 1);
    }
}

#[cfg(test)]
mod ec_cfg_tests {
    use super::*;

    /// `ec_pdw` accepts exactly its documented values: a typo keeps the current mode and is reported to the caller
    /// (the daemon logs it), instead of silently disabling PDW.
    #[test]
    fn ec_pdw_accepts_only_documented_values() {
        let mut set = PgSet::new(Config::new(0));
        assert!(set.set_ec_pdw("auto"));
        assert_eq!(set.cfg.ec_pdw, ecback::PdwMode::Auto);
        assert!(!set.set_ec_pdw("auot"));
        assert_eq!(
            set.cfg.ec_pdw,
            ecback::PdwMode::Auto,
            "unknown value applied"
        );
        assert!(set.set_ec_pdw("always"));
        assert_eq!(set.cfg.ec_pdw, ecback::PdwMode::Always);
        assert!(set.set_ec_pdw("off"));
        assert_eq!(set.cfg.ec_pdw, ecback::PdwMode::Never);
    }
}

#[cfg(test)]
mod scrub_cmd_tests {
    use super::*;
    use crate::map::synth::SynthMap;
    use crate::store::MemStore;

    /// Review R3: a scrub command parked for a map ahead of ours that overflows the queue is a counted drop with an
    /// operator notice, never a silent loss of `ceph pg scrub`.
    #[test]
    fn parked_scrub_commands_report_their_drops() {
        let store = MemStore::new();
        let mut set = PgSet::new(Config::new(0));
        let m = SynthMap::new(100).with_osd(0, 1).with_pool(1, 1, 1, 1);
        let _ = set.handle_map(0, m.into_handle(), &store);
        let cmd = replwire::MOSDScrub2 {
            fsid: [1; 16],
            epoch: 1_000_000,
            scrub_pgs: vec![],
            repair: false,
            deep: true,
        };
        for _ in 0..=PARKED_SCRUB_MAX {
            let _ = set.scrub_command(1, cmd.clone(), &store);
        }
        assert_eq!(set.parked_scrub_cmds.len(), PARKED_SCRUB_MAX);
        assert_eq!(
            set.dropped.get("parked scrub commands: queue full"),
            Some(&1)
        );
        let notes = set.take_notices().join("\n");
        assert!(notes.contains("MOSDScrub2"), "{notes}");
    }
}

#[cfg(test)]
mod pool_lifetime_tests {
    use super::*;
    use crate::map::synth::SynthMap;
    use crate::store::MemStore;

    #[test]
    fn deletion_awaiting_commit_does_not_restore_a_deleted_pool_guard() {
        let mut store = MemStore::new();
        let mut set = PgSet::new(Config::new(0));
        let map = SynthMap::new(1)
            .with_osd(0, 1)
            .with_pool(1, 1, 1, 1)
            .into_handle();
        let _ = set.handle_map(0, map.clone(), &store);
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        };
        let pg = Pg::create(
            set.cfg.clone(),
            spg,
            map,
            Default::default(),
            Default::default(),
            0,
        );
        set.pgs.insert(spg, pg);
        let mut persists = Vec::new();
        for epoch in 2..=3 {
            // Retain all persist completions: the deleting PG remains in memory.
            let map = SynthMap::new(epoch).with_osd(0, 1).into_handle();
            persists.extend(set.handle_map(0, map, &store));
            assert!(set.pgs.get(&spg).unwrap().is_deleting());
            assert!(!set.holds_pool(1));
        }
        // The deletion commits after the pool left the map: forgetting the PG must not restore the guard either.
        let mut q: std::collections::VecDeque<Action> = persists.into();
        while let Some(a) = q.pop_front() {
            if let Action::Persist { spg, token, txn } = a {
                store.submit(spg, &txn);
                q.extend(set.on_commit(0, spg, token, &store));
            }
        }
        assert!(set.pgs.get(&spg).is_none(), "the deletion completed");
        assert!(!set.holds_pool(1));
    }

    #[test]
    fn pool_churn_releases_bookkeeping_without_losing_live_data_guards() {
        let store = MemStore::new();
        let mut set = PgSet::new(Config::new(0));
        // A pool found on disk but not in available maps must keep its guard.
        set.note_held_pools([999]);
        for pool in 2..=33 {
            let map = SynthMap::new((pool * 2) as u32)
                .with_osd(0, 1)
                .with_pool(1, 1, 1, 1)
                .with_pool(pool, 1, 1, 1);
            let _ = set.handle_map(0, map.into_handle(), &store);
            set.note_held_pools([1, pool]);
            assert!(set.pool_entry(pool).is_some());
            set.passive_seen.insert(pool);
            let map = SynthMap::new((pool * 2 + 1) as u32)
                .with_osd(0, 1)
                .with_pool(1, 1, 1, 1);
            let _ = set.handle_map(0, map.into_handle(), &store);
            assert!(!set.pool_cache.borrow().contains_key(&pool));
            assert!(!set.passive_seen.contains(&pool));
            assert!(!set.holds_pool(pool));
            assert!(set.holds_pool(1));
            assert!(set.holds_pool(999));
            assert_eq!(set.held_pools.len(), 2);
        }
    }
}
