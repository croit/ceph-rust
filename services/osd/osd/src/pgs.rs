// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG hosting glue (adr 0023): drives the sans-IO `peering::PgSet` from the OSD core. Map epochs go
//! in one by one, OSD<->OSD PG messages are routed over the cluster messenger (lossless peers with
//! cephx authorizers), actions become sends / store commits / mon requests, and client ops that
//! reach a non-primary (or a primary whose role is disabled in M2) get the spec'd treatment
//! (client-ops.md 5.1-5.4, 5.9, 5.10).
use crate::backend::Backend;
use crate::meta::MetaStore as _;
use crate::osd::{MsgrId, Osd, Purpose, State};
use crate::utilization::HoldWhy;
use crate::xcore::{ConnInfo, XMsg, link_core};
use denc::Encode;
use denc::types::{EntityAddrVec, EntityName, PgT, SpgT};
use messages::{MOSDMap, MOSDPGCreated, MOSDPGTemp, Segments};
use opwire::{ClientMsg, ClsFlags, MOSDOp, MOSDOpReply, OpInfo, errno, flag};
use osdmap::{Incremental, OsdMap};
use peering::{Action, Body, Inbound, MapHandle, PgSet, PgStoreOps, Queued, RealMap};
use pgwire::PeeringMsg;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

/// `pg repeer` mon commands sent per 1 s tick after a runtime change of the EC switches.
const REPEER_PER_TICK: usize = 4;

pub(crate) const MAX_PARKED_OPS: usize = 4096;
/// Payload bound of the waiting client ops of one core (classic bounds them with `osd_client_message_size_cap`).
const MAX_PARKED_BYTES: u64 = 256 << 20;
/// Undecodable PG messages on one link before it is closed.
const BAD_MSGS_CLOSE: u32 = 8;
/// First epoch of a map share toward a peer that knows `known`, we have `ours`: the newest `window` epochs at most
/// (`window` = the smaller of `osd_map_share_max_epochs` and `osd_map_message_max`, at least 1). Classic caps the
/// range at `osd_map_share_max_epochs` and the message at `osd_map_message_max`; we keep the NEWEST epochs of that
/// window, so the peer always reaches our epoch (a gap below it is bridged with the full map).
pub(crate) fn map_share_first(known: u32, ours: u32, window: u32) -> u32 {
    (known + 1).max(ours.saturating_sub(window.max(1) - 1))
}

#[derive(Debug)]
pub(crate) struct PeerConn {
    pub(crate) link: u64,
    pub(crate) up_from: u32,
    pub(crate) addrs: EntityAddrVec,
}

struct Parked {
    epoch: u32,
    link: u64,
    tid: u64,
    op: Box<MOSDOp>,
    /// The map says we are its primary but the PG is not there (yet): waits for it (classic `waiting_for_pg`).
    no_pg: bool,
    /// Arrival order and OSD clock (ns) of the first wait (SLOW_OPS); both kept when it waits again.
    seq: u64,
    since: u64,
    bytes: u64,
}

/// Counters of the client-op fallbacks (diagnostics).
#[derive(Debug, Default, Clone)]
pub(crate) struct PgCounters {
    pub misdirected_dropped: u64,
    /// Client ops dropped silently by reason (the client re-sends after it sees a newer map).
    pub dropped_ops: BTreeMap<&'static str, u64>,
    pub eagain_replies: u64,
    /// Client ops that waited (not up yet / map behind), total.
    pub parked_ops: u64,
    pub peering_msgs_in: u64,
    pub peering_msgs_out: u64,
    pub bad_peer_msgs: u64,
    /// PG transactions refused by the store (the OSD fail-stops on the first, adr 0066).
    pub bad_txns: u64,
    /// PGs loaded from the store at start.
    pub pgs_loaded: u64,
    /// Store polls that reaped durable PG txns, and those txns (`commits / commit_polls` = txns per PG pass).
    pub commit_polls: u64,
    pub commits: u64,
    pub in_by_type: BTreeMap<u16, u64>,
    pub out_by_type: BTreeMap<u16, u64>,
    /// Cluster-link events and silent drops of outbound PG frames by reason (peering diagnostics).
    pub link_events: BTreeMap<&'static str, u64>,
}

impl PgCounters {
    pub(crate) fn link_count(&mut self, what: &'static str) {
        *self.link_events.entry(what).or_default() += 1;
    }
}

/// State changes kept per PG for `dump_pgstate_history`.
const STATE_HIST: usize = 20;

/// Progress reporting of the background PG deletion (a log line every `log_every`; the rate feeds the perf gauges). The
/// deletion itself is scheduled by the store adapter (`StoreAdapter::step_removals`, adr 0524).
#[derive(Debug)]
pub(crate) struct DelProgress {
    pub log_every: Duration,
    /// `(time, objects deleted)` at the last progress sample, and the rate (objects/s) over that window.
    sample: Option<(Duration, u64)>,
    pub rate: u64,
}

impl Default for DelProgress {
    fn default() -> Self {
        DelProgress {
            log_every: Duration::from_secs(10),
            sample: None,
            rate: 0,
        }
    }
}

impl DelProgress {
    /// Progress sample due? Returns the rate window `(seconds, objects)` and restarts it.
    pub fn sample(&mut self, now: Duration, objs_done: u64) -> Option<(f64, u64)> {
        let Some((t, o)) = self.sample else {
            self.sample = Some((now, objs_done));
            return None;
        };
        let dt = now.saturating_sub(t);
        if dt < self.log_every {
            return None;
        }
        self.sample = Some((now, objs_done));
        let n = objs_done.saturating_sub(o);
        self.rate = (n as f64 / dt.as_secs_f64()) as u64;
        Some((dt.as_secs_f64(), n))
    }

    /// A progress window is open (the deletion may have finished since: `Osd::pg_delete_progress` closes it).
    pub fn active(&self) -> bool {
        self.rate > 0 || self.sample.is_some()
    }

    /// Deletion finished or idle: the next run starts a fresh window.
    pub fn reset(&mut self) {
        self.sample = None;
        self.rate = 0;
    }
}

/// Pacing of the queued PG deletion on this core (adr 0524 am. 1): the deletion is background work of the store and follows
/// its rule (adr 0021 am. 33, adr 0533). It runs back to back (one deletion txn in flight) once the core had no client
/// demand for one background gap (`store::shard::BG_BUSY_GAP_NS`); while clients are active it takes one step per gap.
/// Client demand = an op or peer PG message handed to this core's PG work (`Utilization::ops`), sampled every pass. Above
/// the failsafe fill (client writes refused for space) the deletion is what returns the space: back to back.
#[derive(Debug, Default)]
pub(crate) struct RmPace {
    /// `Utilization::ops` at the last look, when it last moved, the earliest next step under client demand.
    ops: u64,
    client_at: Option<Duration>,
    next: Duration,
}

impl RmPace {
    const GAP: Duration = Duration::from_nanos(store::shard::BG_BUSY_GAP_NS);

    /// May a deletion step run now? `ops` = the core's PG work count, `full` = the OSD is above its failsafe fill.
    /// `Some(paced)`: yes (paced = under client demand).
    pub fn due(&mut self, ops: u64, full: bool, now: Duration) -> Option<bool> {
        if ops != self.ops {
            self.ops = ops;
            self.client_at = Some(now);
        }
        match self.client_at {
            _ if full => Some(false),
            Some(t) if now < t + Self::GAP => (now >= self.next).then_some(true),
            _ => Some(false),
        }
    }

    /// The step of `due` queued a deletion txn.
    pub fn stepped(&mut self, paced: bool, now: Duration) {
        if paced {
            self.next = now + Self::GAP;
        }
    }
}

/// Share of the PG core between listing continuations and message work (adr 0522). A listing that continues where its
/// last run stopped (CPU slice, cold leaf with progress; adr 0021 S8) is background work: it hands no units to the drain
/// [`crate::xcore::Slice`], so its time is measured (one clock read before and after each continuation) and kept out of the
/// slice's learned cost per unit (`Osd::note_core_busy`; counted in, every listing slice shrank the next inbox drain until
/// only its first message ran: cross-core ops waited ms in the inbox). While other messages than listing requests flow
/// through local links or the PG core's inbox, the continuations of a loop iteration stop after one drain
/// slice ([`crate::xcore::SLICE_NS`], the bound of the inbox drain itself; the first always runs) and the rest run in the
/// next iteration; otherwise they all run (work-conserving: listings alone keep the whole core, their own requests do
/// not cut them into slices).
#[derive(Debug, Default)]
pub(crate) struct ListShare {
    /// Listing ns of this iteration so far (until the next store poll: the busy report of the iteration reads it first).
    used: u64,
    /// The admitted continuation started here (cleared by [`ListShare::ran`]).
    run: Option<std::time::Instant>,
    /// This iteration accepted non-listing work from local links or the inbox.
    demand: bool,
    /// The last loop iteration had point/control demand from local links or the inbox.
    backlog: bool,
    /// A listing continuation was deferred or a gate probe sweep is unfinished (`Engine::runs_again`): its PG runs
    /// again in the next iteration (no store wake will come for it).
    pub pending: bool,
    /// The PG of the latest listing run that got a turn: the next walk over the PGs with parked ops starts after it
    /// ([`parked_walk`], round robin). Walked from the lowest PG every time, the share went to the first PGs of the order
    /// for as long as their listings kept coming and the last ones starved (omap-load per8.o100 scan: 160 ms on the last
    /// PGs of a core, 4 ms on the first, doc/perf/omap-scan-p99-20261030.md).
    pub last: Option<SpgT>,
    /// Tests set it: messages always wait and one continuation fills the slice (the
    /// simulators' continuations are faster). Production leaves it off.
    pub(crate) one_per_iteration: bool,
}

impl ListShare {
    /// Simulate one full continuation quantum independently of wall-clock speed.
    #[cfg(test)]
    pub(crate) fn exhaust_slice(&mut self) {
        self.used = crate::xcore::SLICE_NS;
    }

    /// May a listing continuation run now? `true` starts its clock. `held`: it holds later ops of its object (adr 0522
    /// am. 1): not background work, it always runs (its time is counted all the same).
    pub fn turn(&mut self, held: bool) -> bool {
        let (backlog, slice) = if self.one_per_iteration {
            (true, 1)
        } else {
            (self.backlog, crate::xcore::SLICE_NS)
        };
        if !held && backlog && self.used >= slice {
            return false;
        }
        self.run = Some(std::time::Instant::now());
        true
    }

    /// The admitted continuation ended.
    pub fn ran(&mut self) {
        if let Some(t) = self.run.take() {
            self.used = self
                .used
                .saturating_add(t.elapsed().as_nanos() as u64)
                .max(1);
        }
    }

    /// Listing ns of the iteration whose busy time is reported now (kept out of the drain slice's learning).
    pub fn listed_ns(&self) -> u64 {
        self.used
    }

    /// Local or forwarded work arrived; `listing`: a client listing request ([`crate::xcore::XMsg::is_listing`]).
    pub fn note_message(&mut self, listing: bool) {
        self.demand |= !listing;
    }

    /// The store poll of a loop iteration starts.
    pub fn next_iteration(&mut self) {
        self.backlog = std::mem::take(&mut self.demand);
        self.used = 0;
        self.run = None;
    }
}

/// The PGs with parked ops in walk order: after `last` (the PG of the latest listing run with a turn,
/// [`ListShare::last`]) to the end of the order, then from its start up to `last` (round robin), each once.
pub(crate) fn parked_walk(parked: &BTreeSet<SpgT>, last: Option<SpgT>, out: &mut Vec<SpgT>) {
    use std::ops::Bound::{Excluded, Unbounded};
    match last {
        Some(l) => out.extend(
            parked
                .range((Excluded(l), Unbounded))
                .chain(parked.range(..=l))
                .copied(),
        ),
        None => out.extend(parked.iter().copied()),
    }
}

/// Everything the OSD keeps for PG hosting.
pub(crate) struct PgHost<P: PgStoreOps> {
    pub set: PgSet,
    pub store: P,
    pub peers: crate::osd::FastMap<i32, PeerConn>,
    /// Latest encoded `pg_stat_t` per primary PG.
    pub stats: BTreeMap<PgT, Vec<u8>>,
    /// Primary PGs forgotten because their EC pool is no longer served: their last stat stays, marked inactive
    /// (INCOMPLETE), so the mgr never keeps showing a frozen PG as active+clean.
    pub orphan_stats: BTreeSet<PgT>,
    /// PGs reported created to the mon (re-sent on a new mon session).
    pub created: BTreeSet<PgT>,
    parked: Vec<Parked>,
    pub(crate) parked_bytes: u64,
    /// `(seq, since)` of the parked op being re-run (a re-park keeps them and is not counted again).
    reparking: Option<(u64, u64)>,
    /// Highest epoch (`have`) a map was asked for: asking again for it or an older one is a no-op, however long ago
    /// (classic `sub_want_increment`); the MonClient keeps the subscription and replays it with a new session.
    last_map_req: Option<u32>,
    /// Per client connection: highest map epoch we believe it has (map sharing, client-ops 5.9).
    proj: crate::osd::FastMap<u64, u32>,
    /// Last cluster-log WARN per EC pool that maps to us and its `(supported, serves)` verdict (once per hour and verdict).
    ec_warned: BTreeMap<u64, (Duration, (bool, bool))>,
    /// EC pools currently mapped to this OSD, refreshed on maps independently of warning rate limits.
    ec_mapped: BTreeSet<u64>,
    /// EC switches (`ec_decline_unsupported`, `ec_enable_pools`, `ec_enable_optimized`) as last applied: a runtime change
    /// makes classic primaries re-peer the PGs whose answer from us changed (they do not re-query on their own).
    ec_cfg_prev: Option<(bool, String, String)>,
    /// `pg repeer` commands still to send (`<pool>.<seed hex>`), paced in [`OsdCore::pg_tick`].
    repeer_q: VecDeque<String>,
    /// Current compression mode and algorithm noted per pool (adr 0059 am. 1).
    compress_noted: BTreeMap<u64, (String, String)>,
    /// Explicit unsupported checksum override last warned per pool.
    checksum_noted: BTreeMap<u64, i64>,
    /// Pool `read_lease_interval` (f64 bits) last warned as capped, per pool.
    lease_noted: BTreeMap<u64, u64>,
    /// Pools whose store options were installed; deleted pools must clear the store's per-pool settings.
    configured_pools: BTreeSet<u64>,
    /// (pool, unknown deep-scrub reformat engine name) already logged.
    reformat_noted: BTreeSet<(u64, String)>,
    last_states: String,
    /// Recent state changes per PG `(wall unix ns, state string)` for `dump_pgstate_history`.
    pub(crate) state_hist: BTreeMap<SpgT, VecDeque<(u64, String)>>,
    primary_logged: BTreeSet<SpgT>,
    /// Test knob: the store refuses the next PG transaction of `pg_exec` (fail-stop path, adr 0066).
    pub(crate) refuse_next: Option<&'static str>,
    bad_by_link: crate::osd::FastMap<u64, u32>,
    /// Local store failure: nothing is served or applied any more.
    pub dead: bool,
    /// Background PG deletion progress reporting.
    pub del: DelProgress,
    /// Pacing of the PG deletion steps by the core's client demand (adr 0524 am. 1).
    pub rm_pace: RmPace,
    /// Core share of listing continuations (adr 0522).
    pub share: ListShare,
    /// Sampled per-op stage tracing of this core (trace.rs).
    pub tr: crate::trace::Tracer,
    /// Store txns awaiting durability (commit latency).
    pub persist_t: crate::perf::PersistTimes,
    /// Local txns of client writes held back until their repops left this core (adr 0008 am. 2), in submit order.
    pub(crate) late: Vec<(SpgT, u64, peering::StoreTxn)>,
    /// Inside a send-first window of the driver (`Osd::on_xmsg_send_first`).
    pub(crate) late_ok: bool,
    /// The driver closes the send-first window after a received chunk ([`Osd::set_local_send_first`]).
    pub(crate) local_sf: bool,
    pub c: PgCounters,
    /// Op engines of primary PGs (opexec).
    pub eng: crate::osd::FastMap<SpgT, opexec::Engine>,
    /// Engines with parked work (`Engine::has_parked`) / with a timer deadline, kept in step by `eng_note`: the
    /// per-op paths visit only these instead of every engine.
    pub eng_parked: BTreeSet<SpgT>,
    /// The members of `eng_parked` that must be visited on every `pg_post` pass, whatever woke: the engine is not
    /// [`opexec::Engine::quiet_without_wake`] (degraded-object parks, live backoffs, deferred listings, copy-from, a gate
    /// that waits for more than store loads). The others wait for a wake token or a PG state change and are visited only
    /// then.
    pub eng_sticky: BTreeSet<SpgT>,
    /// Scratch of `pg_post`: parked PGs to visit besides the sticky ones (touched, EC woke, write done, trim kick).
    pub(crate) post_extra: Vec<SpgT>,
    /// A store load finished since the last `pg_post`: parked engines whose ops wait for the store must probe again.
    pub wake: peering::wake::WakeSet,
    /// Reused buffer of `pg_post`: per PG (sorted), the EC objects whose reads / writes woke ([`peering::wake::ec_tok`]).
    pub ec_wake_buf: Vec<(SpgT, peering::wake::WakeSet)>,
    /// Deadline of every engine that has one, and the same ordered by time (timer queries are O(1), not O(engines)).
    pub eng_due: deadline::Index<SpgT>,
    /// Engines created since the last `pg_engine_sync`: visited by it even if their PG was not touched (an engine made
    /// for a PG that is not primary, e.g. the WriteDone of an aborted interval, must be torn down as before).
    pub eng_new: Vec<SpgT>,
    /// Scratch of `pg_engine_sync` (swapped with the touched list of the `PgSet`).
    pub(crate) touched_buf: Vec<SpgT>,
    /// Engine outputs of one `pg_run`, handed back after sending (capacity reused).
    pub(crate) outs_buf: Vec<opexec::Out>,
    /// Reused list of the parked PGs a store wake visits (`pg_post`): no allocation per wake.
    pub(crate) parked_buf: Vec<SpgT>,
    /// `last_peering_reset` the engine was created in.
    pub eng_reset: crate::osd::FastMap<SpgT, u32>,
    /// Completed writes waiting to be fed to their engine.
    pub done_q: VecDeque<(SpgT, u64, denc::types::Eversion, i32)>,
    pub in_post: bool,
    /// PGs whose snap trimmer was kicked (run in `pg_post`).
    pub trim_kicks: BTreeSet<SpgT>,
    /// Local failsafe full (client-ops 5.4 rule 12), refreshed every tick.
    pub failsafe: bool,
    /// Control: the OSD's adjusted fill (physical + held backfill bytes) is backfillfull or full, refreshed with
    /// `failsafe` (transition log; the cores judge with their `peering::LocalFull`).
    pub backfillfull: bool,
    pub limits: opexec::Limits,
    /// `osd_class_load_list` / `osd_class_default_list` (cls.md 2.1); new PG engines start with it.
    pub classes: opexec::clsx::ClassPolicy,
    /// Object-state cache capacity per PG in heads (0 = off; `flashstore_obj_cache`, size from the cache budget: adr 0160 D5).
    pub obj_cache: usize,
    /// `osd metadata <id>` queries in flight: tid -> (osd, up_from it was asked for).
    pub(crate) peer_meta: BTreeMap<u64, (i32, u32)>,
    #[cfg(test)]
    pub(crate) peer_meta_probes: usize,
    /// Peers whose flavor is known, with the `up_from` it was learned for, and those running croit-flashstore-osd.
    pub(crate) peer_known: BTreeMap<i32, u32>,
    pub(crate) peer_nv: BTreeSet<i32>,
    /// Classic peers' `ceph_version_short` (metadata), by OSD; forgotten with `peer_known` (tracker 74943 check).
    pub(crate) peer_ceph_ver: BTreeMap<i32, String>,
    /// Current FLASHSTORE_EC_ISA_DECODE_CACHE alert text (empty = none): the last one logged is `isa_alert_logged`.
    pub(crate) isa_alert: String,
    pub(crate) isa_alert_logged: String,
    /// Sender-side repop credits towards croit-flashstore-osd peers (flow.rs) and the peer count they were sized for.
    pub(crate) flow: crate::flow::Flow,
    pub(crate) flow_peers: usize,
    /// croit-flashstore-osd peers whose store lacks `FEAT_LONG_NAME` (boot metadata `flashstore_long_names` != 1).
    pub(crate) peer_nolong: BTreeSet<i32>,
    /// Source reads of copy-from in flight (copy.rs).
    pub(crate) cp: crate::copy::Routes,
    /// Lab (NV_PHASE): log when the 1 s re-probe safety net moves parked ops (a lost store wake-up held them).
    pub(crate) wake_diag: bool,
    /// Epochs per map share (`osd_map_share_max_epochs` / `osd_map_message_max`, [`map_share_first`]).
    pub(crate) map_share: u32,
}

impl<P: PgStoreOps> PgHost<P> {
    fn forget_deleted_pools(&mut self, map: &OsdMap) {
        let live = |pool: u64| map.pools.contains_key(&(pool as i64));
        self.configured_pools.retain(|pool| {
            if live(*pool) {
                return true;
            }
            self.store
                .set_pool_compression(*pool, &peering::store::PoolCompOpts::default());
            self.store.set_pool_reformat(*pool, "");
            false
        });
        self.compress_noted.retain(|pool, _| live(*pool));
        self.checksum_noted.retain(|pool, _| live(*pool));
        self.lease_noted.retain(|pool, _| live(*pool));
        self.reformat_noted
            .retain(|(pool, _)| *pool == u64::MAX || live(*pool));
        self.orphan_stats.retain(|pgid| live(pgid.pool));
        self.stats.retain(|pgid, _| live(pgid.pool));
    }

    /// Refresh the parked / deadline membership of the engine of `spg` (call after anything that ran it).
    pub(crate) fn eng_note(&mut self, spg: SpgT) {
        let (parked, sticky, dl) = self.eng.get(&spg).map_or((false, false, None), |e| {
            let parked = e.has_parked();
            (parked, parked && !e.quiet_without_wake(), e.next_deadline())
        });
        // the common op leaves both sets empty: no tree search for it
        if parked {
            self.eng_parked.insert(spg);
        } else if !self.eng_parked.is_empty() {
            self.eng_parked.remove(&spg);
        }
        if sticky {
            self.eng_sticky.insert(spg);
        } else if !self.eng_sticky.is_empty() {
            self.eng_sticky.remove(&spg);
        }
        if self.eng.contains_key(&spg) {
            self.eng_due.register(spg);
            self.eng_due.set(spg, dl);
        } else {
            self.eng_due.unregister(spg);
        }
    }

    pub(crate) fn new(
        whoami: i32,
        store: P,
        map: Option<&Arc<OsdMap>>,
        owner: Option<peering::Owner>,
    ) -> Self {
        let mut cfg = peering::Config::new(whoami);
        cfg.max_backfills = 1;
        cfg.owner = owner;
        let mut set = PgSet::new(cfg);
        if let Some(m) = map {
            set.add_map(handle(m.clone()));
        }
        PgHost {
            set,
            store,
            peers: Default::default(),
            stats: BTreeMap::new(),
            created: BTreeSet::new(),
            parked: Vec::new(),
            parked_bytes: 0,
            reparking: None,
            last_map_req: None,
            proj: Default::default(),
            last_states: String::new(),
            state_hist: BTreeMap::new(),
            ec_warned: BTreeMap::new(),
            ec_mapped: BTreeSet::new(),
            ec_cfg_prev: None,
            repeer_q: VecDeque::new(),
            orphan_stats: BTreeSet::new(),
            compress_noted: BTreeMap::new(),
            checksum_noted: BTreeMap::new(),
            lease_noted: BTreeMap::new(),
            configured_pools: BTreeSet::new(),
            reformat_noted: BTreeSet::new(),
            primary_logged: BTreeSet::new(),
            refuse_next: None,
            bad_by_link: Default::default(),
            dead: false,
            del: DelProgress::default(),
            rm_pace: RmPace::default(),
            share: ListShare::default(),
            tr: Default::default(),
            persist_t: Default::default(),
            late: Vec::new(),
            late_ok: false,
            local_sf: false,
            c: PgCounters::default(),
            eng: Default::default(),
            eng_parked: BTreeSet::new(),
            eng_sticky: BTreeSet::new(),
            post_extra: Vec::new(),
            wake: Default::default(),
            ec_wake_buf: Vec::new(),
            eng_due: Default::default(),
            touched_buf: Vec::new(),
            outs_buf: Vec::new(),
            parked_buf: Vec::new(),
            eng_new: Vec::new(),
            eng_reset: Default::default(),
            done_q: VecDeque::new(),
            in_post: false,
            trim_kicks: BTreeSet::new(),
            failsafe: false,
            backfillfull: false,
            limits: opexec::Limits::default(),
            classes: opexec::clsx::ClassPolicy::default(),
            // until the first config refresh and PG count (adr 0160 D5)
            obj_cache: crate::nvmestore::obj_cache_per_pg(0),
            peer_meta: BTreeMap::new(),
            #[cfg(test)]
            peer_meta_probes: 0,
            peer_known: BTreeMap::new(),
            peer_nv: BTreeSet::new(),
            peer_ceph_ver: BTreeMap::new(),
            isa_alert: String::new(),
            isa_alert_logged: String::new(),
            flow: Default::default(),
            flow_peers: 0,
            peer_nolong: BTreeSet::new(),
            cp: Default::default(),
            wake_diag: std::env::var_os("NV_PHASE").is_some(),
            map_share: 40,
        }
    }
}

fn handle(m: Arc<OsdMap>) -> MapHandle {
    std::rc::Rc::new(RealMap::new(m))
}

/// Up/acting of `pg` in the OSD's current map `map`, for per-op callers: the PG set's handle of that epoch memoizes it
/// ([`RealMap`]); a map the set does not hold yet (boot, before the PGs load) is computed. Scans over every PG of a pool
/// call `pg_to_up_acting` directly (they would fill the memo with PGs nobody asks for again).
pub(crate) fn cur_mapping(set: &PgSet, map: &OsdMap, pg: PgT) -> pgwire::Mapping {
    match set.current_map() {
        Some(h) if h.epoch() == map.epoch => h.pg_mapping(pg),
        _ => peering::map::crush_mapping(map, pg),
    }
}

/// [`cur_mapping`] reduced to `(position of osd in acting, acting_primary)`, without a copy of the mapping when the
/// core's map handle memoizes it (the per-op checks).
pub(crate) fn cur_acting_pos(set: &PgSet, map: &OsdMap, pg: PgT, osd: i32) -> (Option<usize>, i32) {
    match set.current_map() {
        Some(h) if h.epoch() == map.epoch => h.acting_pos(pg, osd),
        _ => {
            let m = peering::map::crush_mapping(map, pg);
            (m.acting.iter().position(|&o| o == osd), m.acting_primary)
        }
    }
}

/// One local `Persist` of a PG batch (a client write on the primary, inline or held back, a repop apply, a commit
/// follow-up): queue it in the store (`refuse` = test knob, taken once: the store answers `Rejected`) and serve the
/// immediate outcome. Durable: the PG's commit actions go behind the batch (`more`, FIFO); Pending: the submit time
/// is recorded, durability arrives through `poll_store`. `Err` = the fail-stop reason (adr 0066), nothing of the
/// batch after it may reach the store: the store refused the txn (counted in `bad_txns`; the PG already logged the
/// entry in memory, diverged from the store: going down is the interval change, peering restores the durable state;
/// a primary validates every client txn before it logs it, so a refusal is a bug, never client input) or failed.
#[expect(clippy::too_many_arguments)]
pub(crate) fn queue_persist<P: PgStoreOps>(
    store: &mut P,
    set: &mut PgSet,
    tr: &mut crate::trace::Tracer,
    persist_t: &mut crate::perf::PersistTimes,
    refuse: &mut Option<&'static str>,
    bad_txns: &mut u64,
    now: u64,
    (spg, token, txn): (SpgT, u64, peering::StoreTxn),
    more: &mut VecDeque<Action>,
) -> Result<(), String> {
    if tr.live_n != 0 {
        tr.on_persist(token);
    }
    let res = match refuse.take() {
        Some(why) => Queued::Rejected(why.into()),
        None => store.queue(spg, &txn, token),
    };
    match res {
        Queued::Durable => {
            more.extend(set.on_commit(now, spg, token, &*store));
            Ok(())
        }
        Queued::Pending => {
            persist_t.submit(token, now);
            Ok(())
        }
        Queued::Rejected(why) => {
            *bad_txns += 1;
            Err(format!(
                "local store failure: pg {spg}: store refused a PG transaction (not applied): {why}"
            ))
        }
        Queued::Failed(why) => Err(format!("local store failure: {why}")),
    }
}

impl<B: Backend> Osd<B> {
    pub(crate) fn pg_mono(&self) -> u64 {
        self.mnow().as_nanos() as u64
    }

    /// EC op whose header names no shard (v7 MOSDOp decode, OSD-internal copy-get): it addresses our own shard, our
    /// position in the current acting set (unchanged when we are not in it).
    pub(crate) fn fill_own_shard(&self, op: &mut MOSDOp) {
        if op.pgid.shard == denc::types::ShardId::NO_SHARD
            && let Some(m) = self.map.as_deref()
            && let (Some(i), _) = cur_acting_pos(&self.pg.set, m, op.pgid.pgid, self.id.whoami)
        {
            op.pgid.shard = denc::types::ShardId(i as i8);
        }
    }

    /// Absolute time of the next PG timer.
    pub(crate) fn pg_next_timer(&self) -> Option<Duration> {
        let a = self.pg.set.next_deadline().map(Duration::from_nanos);
        match (a, self.engines_next_deadline()) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, y) => x.or(y),
        }
    }

    /// Operator notes of the PG machinery: logged; mapper repairs also go to the cluster log (spec snaptrim 8.2).
    pub(crate) fn pg_drain_notices(&mut self) {
        for n in self.pg.set.take_notices() {
            self.log(format!("pg: {n}"));
            if let Some(i) = n.strip_prefix("INFO ") {
                self.clog(messages::clog::INFO, i);
            } else if let Some(d) = n.strip_prefix("DEBUG ") {
                self.clog(messages::clog::DEBUG, d);
            } else if let Some(w) = n.strip_prefix("WARN ") {
                self.clog(messages::clog::WARN, w);
            } else if let Some(e) = n.strip_prefix("ERROR ") {
                self.clog(messages::clog::ERROR, e);
            } else if n.contains("mapper") {
                self.clog(messages::clog::ERROR, &n);
            }
        }
    }

    /// PG and engine timers: the due PGs (core loop), or every PG (`all`, the 1 s tick with its safety nets).
    pub(crate) fn pg_timer(&mut self, all: bool) {
        let now = self.pg_mono();
        let acts = if all {
            self.pg.set.tick(now, &self.pg.store)
        } else {
            self.pg.set.tick_due(now, &self.pg.store)
        };
        self.pg_exec(acts);
        self.engines_tick();
    }

    /// 1 s tick: timers + state summary log on change.
    pub(crate) fn pg_tick(&mut self) {
        // scheduler inputs of this tick (spec scrub.md 12.1.1/12.1.2): the OSD host's local wall clock for the scrub
        // windows and the 1-minute load average per online CPU.
        let wall_ns = self.wall_origin_ns + self.now.as_nanos() as u64;
        self.pg.set.set_local_time(local_scrub_time(wall_ns));
        let load =
            crate::perf::load_average_1m().unwrap_or(0.0) / crate::perf::online_cpus() as f64;
        self.pg.set.set_scrub_load(load);
        self.pg_timer(true);
        self.sync_scrub_recovering();
        self.pg_repeer_drain();
        if self.state == State::Active {
            self.pg_resume_creates();
        }
        // safety net against a lost store wake-up (seen live: an op gated on a prefetch waiter hung for 15 min): ops parked at
        // the gate are re-probed once a second, not only when the store says something finished
        if !self.pg.eng_parked.is_empty() {
            let before: Vec<(SpgT, usize, String)> = if self.pg.wake_diag {
                self.pg
                    .eng_parked
                    .iter()
                    .filter_map(|s| {
                        self.pg
                            .eng
                            .get(s)
                            .map(|e| (*s, e.parked_len(), e.dump_state()))
                    })
                    .collect()
            } else {
                Vec::new()
            };
            self.pg.wake.all = true;
            self.pg_post();
            let (mut moved, mut first) = (0, None);
            for (spg, n, d) in before {
                let now_n = self.pg.eng.get(&spg).map_or(0, |e| e.parked_len());
                if now_n < n {
                    moved += n - now_n;
                    first.get_or_insert((spg, d));
                }
            }
            if let Some((spg, d)) = first {
                self.log(format!(
                    "wake diag: the 1 s re-probe moved {moved} parked ops (lost store wake-up?), e.g. pg {spg}: {d}"
                ));
            }
        }
        let wall_ns = self.wall_origin_ns + self.now.as_nanos() as u64;
        let states = self.pg.set.pg_states();
        self.pg_observe(&states);
        let mut counts: BTreeMap<String, u32> = BTreeMap::new();
        let mut gone: BTreeSet<SpgT> = self.pg.state_hist.keys().copied().collect();
        for (spg, s) in states {
            gone.remove(&spg);
            *counts.entry(s.clone()).or_default() += 1;
            let h = self.pg.state_hist.entry(spg).or_default();
            if h.back().is_none_or(|(_, last)| *last != s) {
                if h.len() >= STATE_HIST {
                    h.pop_front();
                }
                h.push_back((wall_ns, s));
            }
        }
        for g in gone {
            self.pg.state_hist.remove(&g);
        }
        let s = counts
            .iter()
            .map(|(k, v)| format!("{v} {k}"))
            .collect::<Vec<_>>()
            .join(", ");
        if s != self.pg.last_states {
            self.pg.last_states = s.clone();
            self.log(format!("pgs: [{s}]"));
        }
        for t in self.pg.set.take_trace() {
            self.log(format!("pg: {t}"));
        }
        self.pg_drain_notices();
    }

    // ------------------------------------------------------------------ maps

    /// Control (or single) core: every epoch of `(prev, new.epoch]` as a decoded map, oldest first, decoded ONCE here and
    /// shared with the worker cores (a catch-up burst must not cost cores x epochs x map size). Epochs that cannot be
    /// rebuilt are left out.
    pub(crate) fn pg_decode_chain(
        &mut self,
        prev: u32,
        prev_map: Option<Arc<OsdMap>>,
        new: Arc<OsdMap>,
        msg: &MOSDMap,
    ) -> Vec<Arc<OsdMap>> {
        let mut cur: Option<Arc<OsdMap>> = if prev == 0 {
            Some(Arc::new(OsdMap::default()))
        } else {
            prev_map
        };
        let mut skipped = 0u32;
        let mut chain: Vec<Arc<OsdMap>> = Vec::new();
        for e in prev + 1..=new.epoch {
            let m: Option<Arc<OsdMap>> = if e == new.epoch {
                Some(new.clone())
            } else if let (Some(c), Some(b)) = (&cur, msg.incremental_maps.get(&e))
                && c.epoch + 1 == e
            {
                Incremental::decode_from(b)
                    .and_then(|i| c.apply_incremental_checked(&i))
                    .ok()
                    .map(Arc::new)
            } else {
                msg.maps
                    .get(&e)
                    .and_then(|b| OsdMap::decode_from(b).ok())
                    .map(Arc::new)
            };
            match m {
                Some(m) => {
                    // decode CRUSH here, once: a lazily decoded map shared by Arc would make the first worker that
                    // maps a PG decode it while the others wait on its `OnceLock`
                    let _ = m.crush_state();
                    cur = Some(m.clone());
                    chain.push(m);
                }
                None => skipped += 1,
            }
        }
        if skipped > 0 {
            self.log(format!(
                "pg: {skipped} map epochs in ({prev}, {}] unavailable, skipped",
                new.epoch
            ));
        }
        chain
    }

    /// New maps (the chain, oldest first, ending at the newest epoch) arrived: feed them to the PG set.
    pub(crate) fn pg_on_maps(&mut self, chain: Vec<Arc<OsdMap>>) {
        let Some(new) = chain.last().cloned() else {
            return;
        };
        self.pg_forget_restarted_peers(&new);
        let now = self.pg_mono();
        for h in chain.into_iter().map(handle) {
            let acts = self.pg.set.handle_map(now, h, &self.pg.store);
            self.pg_exec(acts);
        }
        // A passive PG has already lost its instance, so deleting its pool or completing its merge emits no
        // further PgRemoved action. Retire its cached inactive report against the current logical PG range.
        let stats = &mut self.pg.stats;
        self.pg.orphan_stats.retain(|pgid| {
            let exists = i64::try_from(pgid.pool)
                .ok()
                .and_then(|id| new.pool(id))
                .is_some_and(|pool| pgid.seed < pool.pg_num);
            if !exists {
                stats.remove(pgid);
            }
            exists
        });
        if self.is_control() {
            self.pg_refresh_peer_flavor(&new);
        }
        self.pg_scrub_flags(&new);
        self.pg_apply_compression(&new);
        if self.is_control() {
            self.pg_warn_ec(&new);
            self.pg_check_isa_cache(&new);
        } else {
            self.pg_drain_notices();
        }
        self.flow_configure();
        self.flow_after_map();
        self.rebucket_input();
        self.pg_retry_parked(true);
        self.engines_after_map();
    }

    /// Which up peers run croit-flashstore-osd (metadata key `flashstore_version`): split children are only exposed to peers that
    /// may be classic after those spoke (peering `SplitGate`). Unknown counts as classic. Knowledge is per
    /// `(osd, up_from)`: an OSD that restarted (maybe as classic) is forgotten BEFORE the maps that show it are
    /// processed ([`Self::pg_forget_restarted_peers`]), and only new or restarted OSDs are asked
    /// (`osd metadata <id>`, one command each), never the whole cluster again.
    fn pg_refresh_peer_flavor(&mut self, map: &OsdMap) {
        // Index once: scanning all outstanding commands for every peer makes discovery quadratic
        // during boot and every map advance until the monitor answers. Each OSD occurs once below,
        // so commands added during this pass need not be added to this snapshot.
        #[cfg(test)]
        {
            self.pg.peer_meta_probes += self.pg.peer_meta.len();
        }
        let pending: BTreeSet<(i32, u32)> = self.pg.peer_meta.values().copied().collect();
        let ups: Vec<(i32, u32)> = (0..map.max_osd)
            .filter(|o| *o != self.id.whoami && map.is_up(*o))
            .map(|o| (o, map.osd_info.get(o as usize).map_or(0, |i| i.up_from)))
            .collect();
        for (o, uf) in ups {
            #[cfg(test)]
            {
                self.pg.peer_meta_probes += 1;
            }
            if self.pg.peer_known.get(&o) == Some(&uf) || pending.contains(&(o, uf)) {
                continue;
            }
            let c = peer_meta_cmd(o);
            if let Some(t) = self.mc.try_send_command(&c, Vec::new()) {
                self.pg.peer_meta.insert(t, (o, uf));
            }
        }
    }

    /// Tracker 74943 (ISA decode-table cache keyed without k/m in classic OSDs before the fix): warn when an acting or
    /// up set of an ISA erasure pool that includes this OSD also holds a classic OSD older than the first fixed
    /// release, while the map has at least two distinct ISA `(k, m)` shapes. croit-flashstore-osd itself is not affected (its decode
    /// plans are keyed by the full code geometry); the risk is wrong shards pushed to us by a classic reconstruction,
    /// which the push check refuses (adr 0039 am. 4). A peer whose version is unknown is not reported.
    fn pg_check_isa_cache(&mut self, map: &OsdMap) {
        let me = self.id.whoami;
        let mut hit: BTreeSet<(u64, i32)> = BTreeSet::new();
        if self.conf.bool("flashstore_warn_isa_decode_cache", true) {
            for (pool_id, _, _) in peering::map::isa_distinct_km_pools(map) {
                let Some(pool) = map.pools.get(&(pool_id as i64)) else {
                    continue;
                };
                for seed in 0..pool.pg_num {
                    let m = map.pg_to_up_acting(PgT::new(pool_id, seed));
                    for set in [&m.up, &m.acting] {
                        if !set.contains(&me) {
                            continue;
                        }
                        for o in set.iter().filter(|o| **o != me && **o >= 0) {
                            if self
                                .pg
                                .peer_ceph_ver
                                .get(o)
                                .is_some_and(|v| isa_cache_bug_version(v))
                            {
                                hit.insert((pool_id, *o));
                            }
                        }
                    }
                }
            }
        }
        let msg = if hit.is_empty() {
            String::new()
        } else {
            let pools: BTreeSet<u64> = hit.iter().map(|(p, _)| *p).collect();
            let osds: BTreeSet<i32> = hit.iter().map(|(_, o)| *o).collect();
            let j = |it: Vec<String>| it.join(",");
            format!(
                "ISA erasure pool(s) {} with several (k, m) shapes share acting sets with classic OSD(s) {} older than ceph 21.1.2: Ceph tracker 74943 (ISA decode-table cache key omits k/m) can reconstruct wrong shards there; upgrade those OSDs to a release with the fix (21.1.2 or later, or a v20 build with the backport). Pushes of reconstructed shards to this OSD are verified against hinfo and refused on mismatch",
                j(pools.iter().map(u64::to_string).collect()),
                j(osds.iter().map(|o| format!("osd.{o}")).collect()),
            )
        };
        self.pg.isa_alert = msg.clone();
        if msg != self.pg.isa_alert_logged {
            if !msg.is_empty() {
                let l = format!("osd.{me}: WARNING {msg}");
                self.log(&l);
                self.clog(messages::clog::WARN, &l);
            }
            self.pg.isa_alert_logged = msg;
        }
    }

    /// Drop what we know about peers that are down or whose `up_from` changed in `map` (not yet fed to the PGs):
    /// the new incarnation may run another flavor, and until answered it is classic (gated).
    fn pg_forget_restarted_peers(&mut self, map: &OsdMap) {
        // Metadata for a vanished incarnation has no consumer. Retire both the
        // local lookup and monitor replay even when no answer ever arrived.
        let obsolete: Vec<u64> = self
            .pg
            .peer_meta
            .iter()
            .filter(|(_, (o, uf))| {
                !map.is_up(*o) || map.osd_info.get(*o as usize).map_or(0, |i| i.up_from) != *uf
            })
            .map(|(tid, _)| *tid)
            .collect();
        for tid in obsolete {
            self.pg.peer_meta.remove(&tid);
            self.mc.cancel_command(tid);
        }
        let stale: Vec<i32> = self
            .pg
            .peer_known
            .iter()
            .filter(|(o, uf)| {
                !map.is_up(**o) || map.osd_info.get(**o as usize).map_or(0, |i| i.up_from) != **uf
            })
            .map(|(o, _)| *o)
            .collect();
        if stale.is_empty() {
            return;
        }
        for o in &stale {
            self.pg.peer_known.remove(o);
            self.pg.peer_nv.remove(o);
            self.pg.peer_ceph_ver.remove(o);
            self.pg.peer_nolong.remove(o);
        }
        self.publish_nv_peers();
        self.sync_long_peers();
        self.sync_keep_owed();
        let acts = self.pg.set.set_flashstore_peers(self.pg.peer_nv.clone());
        self.pg_exec(acts);
    }

    /// Peers that store long object names: known classic OSDs and croit-flashstore-osd with the store bit (unknown = not listed, so
    /// long names wait for the metadata answer). Tells the PG sets of every core (adr 0021 am. 30, OQ 29).
    pub(crate) fn sync_long_peers(&mut self) {
        let ok: BTreeSet<i32> = self
            .pg
            .peer_known
            .keys()
            .filter(|o| !self.pg.peer_nolong.contains(o))
            .copied()
            .collect();
        self.pg.set.set_long_peers(ok.clone());
        if self.multi() && self.is_control() {
            self.xbcast(|| XMsg::LongPeers(ok.clone()));
        }
    }

    /// msgr2 keeps frames that never reached the wire across a session reset only for peers known to be croit-flashstore-osd (classic peers
    /// keep spec 10.3: they must never see frames of an older session replayed).
    pub(crate) fn sync_keep_owed(&mut self) {
        let peers = self.pg.peer_nv.iter().map(|o| i64::from(*o)).collect();
        self.msgr[MsgrId::Cluster as usize]
            .table
            .set_keep_owed_peers(peers);
    }

    /// Reply of an `osd metadata <id>` query; `true` if `tid` was ours.
    pub(crate) fn pg_on_peer_meta(&mut self, tid: u64, r: i32, data: &[u8]) -> bool {
        let Some((o, uf)) = self.pg.peer_meta.remove(&tid) else {
            return false;
        };
        if r != 0 && r != -errno::ENOENT {
            return true; // transient: asked again with the next map
        }
        let cur_uf = self
            .map
            .as_ref()
            .filter(|m| m.is_up(o))
            .map(|m| m.osd_info.get(o as usize).map_or(0, |i| i.up_from));
        if cur_uf != Some(uf) {
            return true; // answer about an incarnation that is gone
        }
        let is_nv = r == 0
            && serde_json::from_slice::<serde_json::Value>(data)
                .is_ok_and(|v| v.get("flashstore_version").is_some());
        self.pg.peer_known.insert(o, uf);
        if r == 0
            && !is_nv
            && let Some(v) = serde_json::from_slice::<serde_json::Value>(data)
                .ok()
                .and_then(|v| v.get("ceph_version_short")?.as_str().map(str::to_owned))
        {
            self.pg.peer_ceph_ver.insert(o, v);
            if let Some(m) = self.map.clone() {
                self.pg_check_isa_cache(&m);
            }
        }
        let nolong = is_nv
            && serde_json::from_slice::<serde_json::Value>(data).is_ok_and(|v| {
                v.get("flashstore_long_names").and_then(|x| x.as_str()) != Some("1")
            });
        if nolong {
            self.pg.peer_nolong.insert(o);
            self.log(format!(
                "osd.{o}: store lacks FEAT_LONG_NAME, object names over ~1.6 KB are refused for PGs it serves (old store: re-mkfs)"
            ));
        }
        self.sync_long_peers();
        if is_nv {
            self.pg.peer_nv.insert(o);
            self.publish_nv_peers();
            self.sync_keep_owed();
            let acts = self.pg.set.set_flashstore_peers(self.pg.peer_nv.clone());
            self.pg_exec(acts);
        }
        true
    }

    /// Hand the pools' `compression_*` options, the deep-scrub reformat engines and the store-wide dedup settings
    /// (`flashstore_dedup_digest` / `flashstore_dedup_zero_objects`) to the store (every core: each applies its own writes),
    /// adr 0059 am. 1. The control core says once per pool and mode in the local log that the pool compresses.
    fn pg_apply_compression(&mut self, map: &OsdMap) {
        self.pg.forget_deleted_pools(map);
        use osdmap::pool::OptVal;
        let s = |o: &osdmap::pool::PoolOpts, k: i32| match o.0.get(&k) {
            Some(OptVal::Str(v)) => v.clone(),
            _ => String::new(),
        };
        let n = |o: &osdmap::pool::PoolOpts, k: i32| match o.0.get(&k) {
            Some(OptVal::Int(v)) => (*v).max(0) as u64,
            _ => 0,
        };
        // store-wide dedup settings (not pool options): applied once per map, also when it holds no pool at all
        let alg = self
            .conf
            .get("flashstore_dedup_digest")
            .unwrap_or("md5")
            .to_owned();
        if !self.pg.store.set_dedup_digest(&alg)
            && self.is_control()
            && self.pg.reformat_noted.insert((u64::MAX, alg.clone()))
        {
            self.log(format!(
                "flashstore_dedup_digest '{alg}' unknown (md5, sha256): kept the previous one"
            ));
        }
        self.pg
            .store
            .set_dedup_zero_objects(self.conf.bool("flashstore_dedup_zero_objects", false));
        for (id, pool) in &map.pools {
            if *id < 0 {
                continue;
            }
            self.pg.configured_pools.insert(*id as u64);
            let o = &pool.opts;
            if self.is_control() {
                match o.0.get(&11) {
                    Some(OptVal::Int(v)) if !matches!(*v, 0 | 4) => {
                        if self.pg.checksum_noted.insert(*id as u64, *v) != Some(*v) {
                            // loud like a no-effect config option (log + cluster log, once per value)
                            let w = format!(
                                "WARNING pool {id}: csum_type {v} unsupported; using fixed crc32c per 4096-byte block"
                            );
                            self.clog(messages::clog::WARN, &w);
                            self.log(w);
                        }
                    }
                    _ => {
                        self.pg.checksum_noted.remove(&(*id as u64));
                    }
                }
            }
            if self.is_control() {
                // admission cap of the pool's read lease (like the daemon-wide value below), once per pool and value
                match o.0.get(&19) {
                    Some(OptVal::Double(v))
                        if peering::types::lease_ns(*v)
                            == peering::types::MAX_READABLE_INTERVAL =>
                    {
                        if self.pg.lease_noted.insert(*id as u64, v.to_bits()) != Some(v.to_bits())
                        {
                            self.logl(
                                0,
                                format!(
                                    "WARNING pool {id}: read_lease_interval {v} s is not representable; using {} s",
                                    peering::types::MAX_READABLE_INTERVAL / peering::types::SEC
                                ),
                            );
                        }
                    }
                    _ => {
                        self.pg.lease_noted.remove(&(*id as u64));
                    }
                }
            }
            // pool option, else the OSD option (classic names and defaults; blob size 0 = the _ssd variant)
            let pick = |p: String, key: &str, d: &str| {
                if p.is_empty() {
                    self.conf
                        .get(key)
                        .filter(|v| !v.is_empty())
                        .unwrap_or(d)
                        .to_owned()
                } else {
                    p
                }
            };
            let blob = |p: u64, key: &str, ssd: u64| {
                if p > 0 {
                    p
                } else {
                    match self.conf.u64(key, 0) {
                        0 => self.conf.u64(&format!("{key}_ssd"), ssd),
                        v => v,
                    }
                }
            };
            let c = peering::store::PoolCompOpts {
                mode: pick(s(o, 6), "bluestore_compression_mode", "none"),
                algorithm: pick(s(o, 7), "bluestore_compression_algorithm", "snappy"),
                required_ratio: match o.0.get(&8) {
                    Some(OptVal::Double(v)) if *v > 0.0 => *v,
                    _ => self.conf.f64("bluestore_compression_required_ratio", 0.875),
                },
                // pool_opts key 9 is the maximum, key 10 the minimum (spec osdmap.md 2.4)
                min_blob: blob(n(o, 10), "bluestore_compression_min_blob_size", 8192),
                max_blob: blob(n(o, 9), "bluestore_compression_max_blob_size", 65536),
            };
            self.pg.store.set_pool_compression(*id as u64, &c);
            // deep-scrub reformat engines: the pool option (key 26, fork `wip-ifed-dedup`), else the OSD fallback list
            let engines = match o.0.get(&POOL_OPT_DEEP_SCRUB_REFORMAT) {
                Some(OptVal::Str(v)) => v.clone(),
                _ => reformat_fallback(
                    self.conf
                        .get("flashstore_deep_scrub_reformat")
                        .unwrap_or(""),
                    *id,
                ),
            };
            let unknown = self.pg.store.set_pool_reformat(*id as u64, &engines);
            if self.is_control() {
                for u in unknown {
                    if self.pg.reformat_noted.insert((*id as u64, u.clone())) {
                        self.log(format!(
                            "pool {id}: ignoring unknown deep scrub reformat engine '{u}'"
                        ));
                    }
                }
            }
            // a policy change is logged with its actual effect; a pool that never compressed stays silent
            let off_mode = c.mode.is_empty() || c.mode == "none";
            let cur = (c.mode.clone(), c.algorithm.clone());
            if self.is_control()
                && match self.pg.compress_noted.insert(*id as u64, cur.clone()) {
                    Some(prev) => prev != cur,
                    None => !off_mode,
                }
            {
                let name = map.pool_name.get(id).cloned().unwrap_or_default();
                let algorithm = if c.algorithm.is_empty() {
                    "snappy"
                } else {
                    &c.algorithm
                };
                let effect = if off_mode || algorithm == "none" {
                    "compression disabled".to_owned()
                } else if store::compress::Alg::parse(algorithm).is_none() {
                    let w = format!(
                        "WARNING pool {id}: compression algorithm '{algorithm}' unsupported; storing uncompressed"
                    );
                    self.clog(messages::clog::WARN, &w);
                    self.log(w);
                    "storing uncompressed".to_owned()
                } else if c.mode.ends_with("_lazy") {
                    "compression deferred to deep-scrub reformat".to_owned()
                } else {
                    format!(
                        "full {}-byte chunks of eligible writes are stored compressed",
                        c.max_blob
                    )
                };
                self.log(format!(
                    "pool {id} ({name}): compression_mode {} algorithm {algorithm}: {effect}",
                    c.mode
                ));
            }
        }
    }

    /// EC pools: if CRUSH maps any PG of one to this OSD and we do not serve it (unsupported profile/mode or the kill
    /// switch is off) say so loudly in the cluster log (at most once per pool per hour); a served pool whose PG is led
    /// by this OSD gets the primary-affinity hint (the primary role is not implemented, adr 0039).
    fn pg_warn_ec(&mut self, map: &OsdMap) {
        self.pg_drain_notices();
        let me = self.id.whoami;
        let now = self.now;
        self.pg
            .ec_warned
            .retain(|p, _| map.pools.contains_key(&(*p as i64)));
        self.pg.ec_mapped.clear();
        let (en, opt) = self.ec_enables();
        for (id, pool) in &map.pools {
            if !pool.is_erasure() || id < &0 {
                continue;
            }
            let pool_id = *id as u64;
            let info = peering::map::ec_pool_info(map, pool).unwrap_or_default();
            let name = map.pool_name.get(id).cloned().unwrap_or_default();
            let why = peering::map::ec_not_served(&info, &en, &opt, pool_id, &name);
            let serves = why.is_none();
            if self.ec_pool_mode(
                &info,
                &en,
                &opt,
                self.conf.bool("ec_decline_unsupported", true),
                pool_id,
                &name,
            ) == "decline"
            {
                self.pg_decline_lead_temps(map, pool_id, pool);
            }
            let (mut mapped, mut leads) = (false, false);
            for seed in 0..pool.pg_num {
                let m = map.pg_to_up_acting(PgT::new(pool_id, seed));
                mapped |= m.up.contains(&me) || m.acting.contains(&me);
                leads |= m.acting_primary == me;
                if mapped && leads {
                    break;
                }
            }
            if mapped {
                self.pg.ec_mapped.insert(pool_id);
            }
            // rate limit per pool AND verdict: a pool created plain and flagged a moment later (allow_ec_optimizations)
            // must get the line of its new mode at once, not an hour later (live, adr 0039 am. 1)
            let verdict = (info.supported, serves);
            if self.pg.ec_warned.get(&pool_id).is_some_and(|(t, v)| {
                *v == verdict && now.saturating_sub(*t) < Duration::from_secs(3600)
            }) {
                continue;
            }
            if mapped && !serves {
                self.pg.ec_warned.insert(pool_id, (now, verdict));
                let why = why.unwrap_or_default();
                let msg = if peering::map::ec_declinable(&info, &opt, pool_id, &name)
                    && self.conf.bool("ec_decline_unsupported", true)
                    && !self.pg.set.holds_pool(pool_id)
                {
                    // adr 0039 am. 1: say what the classic primaries will show and what the operator must do
                    format!(
                        "croit-flashstore-osd osd.{me} mapped into EC pool {pool_id} ({name}): {why}; this OSD declines its shards \
                         (empty shard, backfill refused): those PGs run without it (undersized+degraded+backfill_toofull, \
                         or incomplete/peered below min_size); exclude croit-flashstore-osd OSDs from the pool's CRUSH rule"
                    )
                } else {
                    format!(
                        "croit-flashstore-osd osd.{me} mapped into EC pool {pool_id} ({name}): {why}; PGs will not be served"
                    )
                };
                self.log(&msg);
                self.clog(messages::clog::WARN, &msg);
            } else if serves
                && leads
                && (!self.conf.bool("ec_enable_primary", true)
                    || (info.optimized && !self.conf.bool("ec_enable_optimized_primary", true)))
            {
                self.pg.ec_warned.insert(pool_id, (now, verdict));
                let msg = format!(
                    "croit-flashstore-osd osd.{me} leads PGs of EC pool {pool_id}: the EC primary role is disabled (ec_enable_primary), \
                     those PGs stay inactive; set primary-affinity 0 on croit-flashstore-osd OSDs"
                );
                self.log(&msg);
                self.clog(messages::clog::WARN, &msg);
            }
        }
    }

    /// Ask the mon for the maps after `have` (a worker core asks the control core).
    pub(crate) fn pg_request_map(&mut self, have: u32) {
        if self.pg.last_map_req.is_some_and(|e| e >= have) {
            return;
        }
        self.pg.last_map_req = Some(have);
        if !self.is_control() {
            return self.xsend(0, XMsg::ReqMap { have });
        }
        self.mon_sub("osdmap", u64::from(have) + 1, messages::SubItem::ONETIME);
    }

    /// New mon session: re-send up_thru, pg_temp and pg_created (every core re-sends its own).
    /// The per-core osdmap request latch (`last_map_req`) is not cleared here: the mon client's subscription table still
    /// holds the outstanding osdmap request and `Subs::reopen` (crates/monc) re-sends it on the new session by itself.
    /// Removing that monc re-send would stall map requests: nothing else repeats them.
    pub(crate) fn pg_on_mon_session(&mut self) {
        if self.is_control() {
            self.xbcast(|| XMsg::MonSession);
        }
        let acts = self.pg.set.resend_mon_requests();
        let temps = acts
            .iter()
            .filter(|a| matches!(a, Action::PgTemp { .. }))
            .count();
        if temps > 0 {
            // the only re-send of a pg_temp request (no timer, adr 0023 am. 1); lab case 25 counts these lines
            self.log(format!(
                "new mon session: re-sent {temps} pending pg_temp request(s)"
            ));
        }
        self.pg_exec(acts);
        let created: Vec<PgT> = self.pg.created.iter().copied().collect();
        for pgid in created {
            self.mon_out(MOSDPGCreated { version: 0, pgid }.into());
        }
    }

    // ------------------------------------------------------------------ actions

    /// Driver (adr 0008 am. 2): [`Osd::on_xmsg`] inside a send-first window. A fresh replicated client write leaves
    /// its repops in the outbox and holds its local txn back; the driver moves the outbox to the rings, then calls
    /// [`Osd::apply_late`] (before anything else runs on this core: every other entry point applies first).
    pub fn on_xmsg_send_first(&mut self, from: usize, m: XMsg, now: std::time::Duration) {
        self.pg.share.note_message(m.is_listing());
        self.pg.late_ok = true;
        self.on_xmsg(from, m, now);
        self.pg.late_ok = false;
    }

    /// Driver opt-in (adr 0008 am. 3): after every [`Osd::on_bytes`] it flushes what the op queued (outbox to the rings,
    /// local link output) and calls [`Osd::apply_late`] when [`Osd::late_pending`], so a client write decoded on its own PG
    /// core also sends its repops before its local txn.
    pub fn set_local_send_first(&mut self, on: bool) {
        self.pg.local_sf = on;
    }

    /// Local txns held back by [`Osd::on_xmsg_send_first`] wait for [`Osd::apply_late`].
    pub fn late_pending(&self) -> bool {
        !self.pg.late.is_empty()
    }

    /// Apply the held-back local txns (their repops left), then feed completions back.
    pub fn apply_late(&mut self) {
        if self.late_pending() {
            self.perf.op.late_driver += 1;
            self.settle_late();
            self.pg_post();
        }
    }

    /// Queue the held-back local txns, in submit order, like any PG txn (`pg_exec`). The repops already left: a
    /// refused txn fail-stops (adr 0066), like a classic primary whose local apply asserts; the replicas' copies are
    /// reconciled by peering from the durable state, the client never got an ack.
    pub(crate) fn settle_late(&mut self) {
        if self.pg.late.is_empty() {
            return;
        }
        let acts = std::mem::take(&mut self.pg.late)
            .into_iter()
            .map(|(spg, token, txn)| Action::Persist { spg, token, txn })
            .collect();
        self.pg_exec(acts);
    }

    pub(crate) fn pg_exec(&mut self, acts: Vec<Action>) {
        if self.pg.dead {
            return;
        }
        self.settle_late(); // a held-back txn is never overtaken by a later one

        // The batch runs in place; actions a commit adds go behind it (FIFO), as in one queue.
        let mut it = acts.into_iter();
        let mut q: VecDeque<Action> = VecDeque::new();
        let mut temps: BTreeMap<PgT, Vec<i32>> = BTreeMap::new();
        while let Some(a) = it.next().or_else(|| q.pop_front()) {
            match a {
                Action::Send(s) => self.pg_send(s),
                Action::Persist { spg, token, txn } => {
                    // also every replica apply (a held-back primary txn passes here via `settle_late`)
                    let now = self.pg_mono();
                    let h = &mut self.pg;
                    if let Err(why) = queue_persist(
                        &mut h.store,
                        &mut h.set,
                        &mut h.tr,
                        &mut h.persist_t,
                        &mut h.refuse_next,
                        &mut h.c.bad_txns,
                        now,
                        (spg, token, txn),
                        &mut q,
                    ) {
                        return self.fail_stop(&why);
                    }
                }
                Action::Fatal { spg, why } => {
                    // a protocol violation the PG can never apply, after it diverged in memory (adr 0066)
                    return self.fail_stop(&format!("pg {spg}: {why}"));
                }
                Action::NeedUpThru { want } => {
                    if self.is_control() {
                        self.want_up_thru_inner(want)
                    } else {
                        self.xsend(0, XMsg::UpThru { want });
                    }
                }
                Action::PgTemp { pgid, want } => {
                    temps.insert(pgid, want);
                }
                Action::PgCreated { pgid } => {
                    self.pg.created.insert(pgid);
                    self.mon_out(MOSDPGCreated { version: 0, pgid }.into());
                }
                Action::PgStats { spg, stat } => match stat.encode_to_vec() {
                    Ok(b) => {
                        self.pg.stats.insert(spg.pgid, b);
                        self.pg.orphan_stats.remove(&spg.pgid);
                    }
                    Err(e) => self.log(format!("pg_stat encode {spg}: {e}")),
                },
                Action::RequestMap { have } => self.pg_request_map(have),
                Action::NeedOldMaps { from, to } => {
                    if self.is_control() {
                        // answered in place, its actions queued behind the current ones (no nested pg_exec)
                        let maps = self.pg_old_map_chain(from, to);
                        q.extend(self.pg_old_maps_acts(from, maps));
                    } else {
                        self.xsend(0, XMsg::OldMapsReq { from, to });
                    }
                }
                Action::ReadyToMerge(r) => {
                    let version = u64::from(self.epoch());
                    self.log(format!(
                        "pg {}: merge {} (source v{}, target v{})",
                        r.source,
                        if r.ready { "ready" } else { "not ready" },
                        r.source_version,
                        r.target_version
                    ));
                    self.mon_out(
                        messages::MOSDPGReadyToMerge {
                            version,
                            pgid: r.source,
                            source_version: r.source_version,
                            target_version: r.target_version,
                            last_epoch_started: r.last_epoch_started,
                            last_epoch_clean: r.last_epoch_clean,
                            ready: r.ready,
                        }
                        .into(),
                    );
                }
                Action::PgRemoved { spg } => {
                    // a deferred `mark_unfound_lost` waiting for this instance can never be answered
                    self.lost_abandoned(spg);
                    // EC: a stale instance (old shard position) may go while we lead the PG at another position
                    let other = self
                        .pg
                        .set
                        .pgs()
                        .any(|(s, _)| s.pgid == spg.pgid && *s != spg);
                    if !other {
                        if self.pg.set.is_passive(spg.pgid.pool)
                            && let Some(b) = self.pg.stats.get(&spg.pgid)
                            && let Some(b) = inactive_stat(b)
                        {
                            self.pg.stats.insert(spg.pgid, b);
                            self.pg.orphan_stats.insert(spg.pgid);
                        } else {
                            self.pg.stats.remove(&spg.pgid);
                            self.pg.orphan_stats.remove(&spg.pgid);
                        }
                    }
                    self.pg.created.remove(&spg.pgid);
                    self.pg.primary_logged.remove(&spg);
                }
                Action::WriteDone {
                    spg,
                    tid,
                    version,
                    result,
                } => self.pg.done_q.push_back((spg, tid, version, result)),
                Action::SubWritesAborted { keys, .. } => self.flow_aborted(&keys),
                Action::Placement { pgid, shard } => {
                    self.xbcast(|| XMsg::Placement { pgid, shard });
                }
                Action::SnapTrimKick { spg } => {
                    self.pg.trim_kicks.insert(spg);
                }
                // OSD-wide budgets (scrub, backfill, trim): core 0 keeps it (the owner never emits a request, a reply never targets itself)
                Action::Slot(req) => self.xsend(0, XMsg::Slot(req)),
                Action::SlotReply { core, reply } => {
                    self.xsend(core as usize, XMsg::SlotReply(reply));
                }
                Action::Ops(req) => self.xsend(0, XMsg::Ops(req)),
                Action::OpsReply { core, reply } => {
                    self.xsend(core as usize, XMsg::OpsReply(reply));
                }
                Action::LostMarked(d) => self.lost_marked(*d),
                Action::ReadableChanged { .. } | Action::Resv(_) | Action::Latch { .. } => {}
            }
        }
        for n in self.pg.store.take_notes() {
            self.log(format!("pg: {n}"));
        }
        if !temps.is_empty() {
            self.send_pg_temp(temps);
        }
        // a PG that ops wait for may have been created (classic wakes `waiting_for_pg` on PG creation)
        if self.pg.parked.iter().any(|p| p.no_pg) {
            self.pg_retry_parked(false);
        }
        self.pg_post();
        self.sync_scrub_recovering();
    }

    // ------------------------------------------------------------------ cluster messenger

    /// Features to encode messages for OSD `to` with: what the cluster link negotiated, but only if it was
    /// negotiated with the incarnation the current map names (`up_from`). Otherwise (no link yet, peer restarted,
    /// possibly with another version) the conservative set: everything except the newest wire formats, which every
    /// peer of the cluster decodes.
    pub(crate) fn peer_features(&self, to: i32) -> u64 {
        let up_from = self
            .map
            .as_ref()
            .and_then(|m| m.osd_info.get(to as usize))
            .map(|i| i.up_from);
        match self.cl.peer_feat.get(&to) {
            Some(&(u, f)) if Some(u) == up_from => f,
            _ => denc::features::ALL & !denc::features::TENTACLE_BIT,
        }
    }

    /// Send a PG message to OSD `s.to` (dial on demand, lossless peer connection).
    pub(crate) fn pg_send(&mut self, mut s: Box<peering::Send>) {
        let _s = wprof::span(wprof::S::Send);
        let to = s.to;
        if to < 0 || !self.map.as_ref().is_some_and(|m| m.is_up(to)) {
            self.pg.c.link_count("send_drop_peer_not_up");
            return;
        }
        // encoded here (on the PG's core, where the parallelism is); the peer's link lives on `peer_core(to)`
        let mut feats = self.peer_features(to);
        // a rebuilt transaction blob arrives with the crc computed during its payload copy; msgr2 uses it only if the
        // data segment is exactly that blob
        // a rope (large replicated write) leaves its payload parts out of the encoded DATA segment: they follow it in
        // the msgr2 frame by reference (no copy into a blob)
        let data_crc: crate::xcore::DataX = match &mut s.body {
            // the v9 blob's first write payload sits at a fixed offset: say so, the replica receives it 4 KiB aligned
            Body::Repl(replwire::ReplMsg::RepOp(r)) => crate::xcore::DataX {
                crc: r.txn_data_crc.clone(),
                more: std::mem::take(&mut r.txn_data_more),
                data_off: replwire::REPOP_DATA_OFF,
            },
            // EC sub-read reply: the store-known crc of its one shard buffer (adr 0116); the further store pieces of that
            // buffer follow the DATA segment by reference (adr 0116 am. 4)
            // EC sub-write to a SERVER_TENTACLE peer: struct v5 (what Ceph sends such a peer), transaction data in the
            // DATA segment by reference, its first payload placed 4 KiB aligned at the receiver (spec msgr2.md 3.1)
            Body::Ec(ecwire::EcMsg::Write(w))
                if denc::features::have(feats, denc::features::TENTACLE_BIT) =>
            {
                match ec_write_tentacle(&mut w.op) {
                    Ok(dx) => dx,
                    Err(e) => {
                        // never drop a message the primary waits for: this peer gets struct v4 (every peer decodes it)
                        feats &= !denc::features::TENTACLE_BIT;
                        // once per process: a transaction shape v5 rejects repeats for every such write
                        static WARNED: std::sync::Once = std::sync::Once::new();
                        WARNED.call_once(|| {
                            self.log(format!(
                                "pg: WARNING ec sub-write v5 to osd.{to} failed ({e}); sending struct v4 instead (logged once)"
                            ))
                        });
                        Default::default()
                    }
                }
            }
            Body::Ec(ecwire::EcMsg::ReadReply(r)) => crate::xcore::DataX {
                crc: r.op.data_crc.clone(),
                more: r.op.take_data_more(),
                ..Default::default()
            },
            _ => Default::default(),
        };
        match s.body.encode(feats) {
            Ok((ty, ver, compat, segs)) => {
                let tkey = if self.pg.tr.live_n != 0 {
                    self.trace_peer_out(&s, to)
                } else {
                    None
                };
                self.pg.c.peering_msgs_out += 1;
                self.sub_out(&s.body);
                *self.pg.c.out_by_type.entry(ty).or_default() += 1;
                let spg = peering::body_spg(&s.body);
                let tx = crate::flow::Tx {
                    to,
                    epoch: s.epoch,
                    tid: s.tid,
                    prio: s.prio,
                    hdr: (ty, ver, compat),
                    segs,
                    data: data_crc,
                };
                self.flow_send(&s.body, tx, spg);
                if let Some((k, stage)) = tkey {
                    self.trace_tx_queue(k, stage, self.cl.spec.peer_core(to));
                }
            }
            Err(e) => self.log(format!("pg: encode message {}: {e}", s.body.msg_type())),
        }
    }

    /// Hand an encoded PG message to the core that owns the peer's link (or to the link here).
    pub(crate) fn pg_forward(&mut self, tx: crate::flow::Tx) {
        let pc = self.cl.spec.peer_core(tx.to);
        if pc == self.cl.spec.id {
            self.peer_transmit(None, tx);
        } else {
            let crate::flow::Tx {
                to,
                epoch,
                tid,
                prio,
                hdr,
                segs,
                data,
            } = tx;
            self.cl.fwd_peer_tx += 1;
            // the link core's map may be older than ours (maps reach the cores one by one): the target
            // travels with the frame, it must not be judged by a map that does not know the peer yet
            let target = self.peer_target(to);
            self.xsend(
                pc,
                XMsg::PeerWire {
                    to,
                    epoch,
                    target,
                    tid,
                    prio,
                    hdr,
                    segs,
                    data_crc: data,
                },
            );
        }
    }

    /// Incarnation and cluster addresses of OSD `to` in this core's map.
    pub(crate) fn peer_target(&self, to: i32) -> Option<(u32, EntityAddrVec)> {
        let m = self.map.as_ref()?;
        Some((
            m.osd_info.get(to as usize).map_or(0, |i| i.up_from),
            m.cluster_addrs
                .get(to as usize)
                .cloned()
                .unwrap_or_default(),
        ))
    }

    /// Put an encoded PG message on the cluster link to OSD `to` (dial on demand, lossless peer connection). Runs on
    /// the core that owns that link.
    pub(crate) fn peer_transmit(
        &mut self,
        target: Option<(u32, EntityAddrVec)>,
        tx: crate::flow::Tx,
    ) {
        let crate::flow::Tx {
            to,
            epoch,
            tid,
            prio,
            hdr,
            segs,
            data: data_crc,
        } = tx;
        // a frame of the identity the map marked down: every peer discards it once it has that map (peering spec 2.4
        // step 3); one still behind would take it on the session that reconnected from the new address, behind the
        // frames its RESET dropped (a gap: a primary acks a later write before an earlier one)
        if epoch < self.rebind_epoch {
            self.pg.c.link_count("tx_drop_before_rebind");
            return;
        }
        // `target`: incarnation and addresses as the sending PG core's map names them (frames forwarded from
        // another core); without it this core's own map decides
        let (up_from, addrs) = match target {
            Some(t) => t,
            None => {
                if !self.map.as_ref().is_some_and(|m| m.is_up(to)) {
                    *self
                        .pg
                        .c
                        .link_events
                        .entry("tx_drop_peer_not_up_in_link_core_map")
                        .or_default() += 1;
                    return;
                }
                let Some(t) = self.peer_target(to) else {
                    *self
                        .pg
                        .c
                        .link_events
                        .entry("tx_drop_no_target")
                        .or_default() += 1;
                    return;
                };
                t
            }
        };
        if self.pg.peers.get(&to).is_some_and(|p| p.up_from > up_from) {
            *self
                .pg
                .c
                .link_events
                .entry("tx_drop_old_incarnation")
                .or_default() += 1;
            return; // meant for an incarnation that is gone
        }
        // a link closed for the wire (an accepted one that faulted, a superseded one) may still drain held input: not
        // ours to send on any more, but its session is (a dial or the peer's next accepted connection resumes it)
        if self.pg.peers.get(&to).is_some_and(|p| {
            p.up_from == up_from
                && p.addrs == addrs
                && self
                    .links
                    .get(&p.link)
                    .is_some_and(|l| l.conn.state() == msgr2::ConnState::Closed)
        }) {
            self.pg.peers.remove(&to);
            self.pg.c.link_count("tx_link_closed_for_wire");
        }
        let stale = self.pg.peers.get(&to).is_some_and(|p| {
            p.up_from != up_from || p.addrs != addrs || !self.links.contains_key(&p.link)
        });
        if stale && let Some(p) = self.pg.peers.remove(&to) {
            *self
                .pg
                .c
                .link_events
                .entry("tx_link_replaced_stale")
                .or_default() += 1;
            self.close_link(p.link);
        }
        let id = match self.pg.peers.get(&to) {
            Some(p) => p.link,
            None => {
                // a connection of this incarnation already carries the session (the peer's dial won, or it resumed
                // the session after a socket loss): use it, also before its Connected event was processed here. A
                // second dial takes the session over and stops the carrier (spec 10.3, in_seq freeze): a needless
                // reconnect
                let carrier = self.msgr[MsgrId::Cluster as usize]
                    .table
                    .carrier(&addrs)
                    .filter(|id| {
                        self.links.get(id).is_some_and(|l| {
                            l.msgr == MsgrId::Cluster && l.conn.state() != msgr2::ConnState::Closed
                        })
                    });
                if let Some(id) = carrier {
                    self.pg.c.link_count("tx_on_carrier");
                    self.pg.peers.insert(
                        to,
                        PeerConn {
                            link: id,
                            up_from,
                            addrs,
                        },
                    );
                    self.send_raw_crc(id, tid, prio, hdr, segs, data_crc);
                    return;
                }
                let Some(id) =
                    self.dial(MsgrId::Cluster, Purpose::Peer(to), EntityName::OSD, &addrs)
                else {
                    self.log(format!("pg: no v2 cluster address for osd.{to}"));
                    return;
                };
                self.pg.peers.insert(
                    to,
                    PeerConn {
                        link: id,
                        up_from,
                        addrs,
                    },
                );
                id
            }
        };
        self.send_raw_crc(id, tid, prio, hdr, segs, data_crc);
    }

    /// Sessions of the cluster messenger that owe a peer messages but have no connection (their accepted one faulted;
    /// spec 10.7 step 7): dial them, as the classic accepting side does. The peer, in standby with nothing to send,
    /// would not, and the queued replies / sub-writes / pushes would wait for unrelated traffic (OQ 28 O15). Sessions
    /// of an incarnation the map no longer names stay put (the sweep and the new incarnation's reset settle them).
    pub(crate) fn pg_dial_owed(&mut self) {
        let owed = self.msgr[MsgrId::Cluster as usize].table.needs_dial();
        for (addrs, name) in owed {
            if name.ty != EntityName::OSD || name.num < 0 {
                continue;
            }
            let to = name.num as i32;
            if !self.map.as_ref().is_some_and(|m| m.is_up(to)) {
                continue;
            }
            let Some((up_from, target)) = self.peer_target(to) else {
                continue;
            };
            if target != addrs {
                continue;
            }
            let Some(id) = self.dial(MsgrId::Cluster, Purpose::Peer(to), EntityName::OSD, &addrs)
            else {
                continue;
            };
            self.pg.c.link_count("dial_owed");
            // a previous entry is the faulted accepted link: it drains its input and closes by itself
            self.pg.peers.insert(
                to,
                PeerConn {
                    link: id,
                    up_from,
                    addrs,
                },
            );
        }
    }

    pub(crate) fn pg_peer_link_gone(&mut self, osd: i32, id: u64) {
        if self.pg.peers.get(&osd).is_some_and(|p| p.link == id) {
            self.pg.peers.remove(&osd);
            // what was queued on it is gone
            self.pg_peer_link(osd, false);
        }
    }

    /// A map names a newer incarnation of OSD `o` than the one a cluster link was dialled for: that link targets a dead
    /// address (lossless: it redials the old nonce for ever and the new OSD faults every try with "target addr is not
    /// ours"). Without this sweep the link is only replaced when something is next sent to `o`.
    pub(crate) fn pg_peer_sweep(&mut self) {
        let Some(m) = self.map.as_ref() else { return };
        let dead: Vec<i32> = self
            .pg
            .peers
            .iter()
            .filter(|(o, p)| {
                m.osd_info
                    .get(**o as usize)
                    .is_some_and(|i| i.up_from > p.up_from)
            })
            .map(|(o, _)| *o)
            .collect();
        for o in dead {
            if let Some(p) = self.pg.peers.remove(&o) {
                self.pg.c.link_count("peer_link_swept_new_incarnation");
                self.close_link(p.link);
            }
        }
    }

    /// The cluster session to OSD `osd` was lost (`up` false: fault, reset, closed) or reached READY: peering redrives
    /// what may have been lost, with per-peer back-off (adr 0071). Every core's PGs talk to the peer.
    pub(crate) fn pg_peer_link(&mut self, osd: i32, up: bool) {
        if osd < 0 || osd == self.whoami() {
            return;
        }
        self.pg
            .c
            .link_count(if up { "peer_up" } else { "peer_lost" });
        if self.multi() {
            self.xbcast(|| XMsg::PeerLink { osd, up });
        }
        self.pg_peer_link_local(osd, up);
    }

    pub(crate) fn pg_peer_link_local(&mut self, osd: i32, up: bool) {
        let now = self.pg_mono();
        let acts = if up {
            self.pg.set.peer_connected(osd, now, &self.pg.store)
        } else {
            self.pg.set.peer_fault(osd, now, &self.pg.store)
        };
        self.pg_exec(acts);
    }

    /// A message of a type this OSD handles failed to decode: fault the link, as Ceph does (the peer sees a reset and
    /// resends or surfaces the error; a silent drop would leave the op hanging on a healthy session). The message was
    /// already counted in the session's in_seq, so the reconnect does not replay it. Unknown types stay passive.
    pub(crate) fn fault_undecodable(
        &mut self,
        id: u64,
        counter: &'static str,
        what: &str,
        e: impl std::fmt::Display,
    ) {
        self.pg.c.link_count(counter);
        self.log(format!(
            "link {id}: undecodable {what}: {e}, closing the link"
        ));
        self.close_link(id);
    }

    /// Unknown-to-`messages` type on some link: PG traffic, client op or junk.
    pub(crate) fn on_unknown_message(
        &mut self,
        id: u64,
        tid: u64,
        ty: u16,
        version: u16,
        segs: &Segments,
    ) {
        if ty == opwire::consts::ty::OSD_OP {
            let Some(l) = self.links.get(&id) else { return };
            if l.msgr != MsgrId::Public {
                self.log(format!("link {id}: MOSDOp on non-public messenger dropped"));
                return;
            }
            let dec = {
                let _s = wprof::span(wprof::S::Decode);
                opwire::decode_client(ty, version, segs)
            };
            match dec {
                Ok(ClientMsg::Op(mut op)) => {
                    op.ingress = self
                        .cl
                        .raw_input
                        .as_ref()
                        .filter(|(conn, _)| *conn == id)
                        .map(|(_, guard)| guard.clone())
                        .unwrap_or_default();
                    // an op whose payload is the whole data segment inherits its verified receive crc (a large
                    // replicated write sends it on to the replicas without another pass, adr 0061 am. 1)
                    if self.cl.raw_crc.of(&segs.data).is_some() {
                        for o in op.ops.iter_mut() {
                            if o.indata.as_ptr() == segs.data.as_ptr()
                                && o.indata.len() == segs.data.len()
                            {
                                // the same bytes: the hint (incl. the receive pass's block crcs, adr 0061 am. 4) applies
                                o.indata_crc = self.cl.raw_crc.clone();
                            }
                        }
                    }
                    self.admit_client_op(
                        id,
                        tid,
                        op,
                        segs.front_len() + segs.middle.len() + segs.data.len(),
                    );
                }
                Ok(_) => {}
                Err(e) => self.fault_undecodable(id, "undecodable_client_op", "MOSDOp", e),
            }
            return;
        }
        if ty == opwire::consts::ty::OSD_BACKOFF {
            if self
                .links
                .get(&id)
                .is_some_and(|l| l.msgr == MsgrId::Public)
                && let Ok(ClientMsg::Backoff(b)) = opwire::decode_client(ty, version, segs)
            {
                let pgid = b.pgid.pgid;
                if self.pg.set.core_of(pgid) == self.cl.spec.id && !self.mig_busy(pgid) {
                    self.pg_backoff_ack(id, b);
                } else {
                    self.pg_item(
                        None,
                        XMsg::BackoffAck {
                            conn: id,
                            b: Box::new(b),
                        },
                    );
                }
            }
            return;
        }
        let dec = {
            let _s = wprof::span(wprof::S::Decode);
            Body::decode(ty, version, segs)
        };
        match dec {
            Ok(Some(Body::Repl(replwire::ReplMsg::Scrub2(m)))) => self.pg_on_scrub2(id, m),
            Ok(Some(Body::Repl(replwire::ReplMsg::ForceRecovery(m)))) => {
                self.pg_on_force_recovery(id, m)
            }
            Ok(Some(mut body)) => {
                // a replicated write's blob keeps the receive pass's block crcs (grid at its payload, adr 0061 am. 7):
                // the store writes the payload by reference and reuses them
                if let Body::Repl(replwire::ReplMsg::RepOp(r)) = &mut body
                    && self.cl.raw_crc.of(&r.txn_data).is_some()
                {
                    r.txn_data_crc = self.cl.raw_crc.clone();
                }
                let bytes = segs.front_len() + segs.middle.len() + segs.data.len();
                let ingress = self
                    .cl
                    .raw_input
                    .as_ref()
                    .filter(|(conn, _)| *conn == id)
                    .map(|(_, guard)| guard.clone())
                    .unwrap_or_default();
                let prio = self.cl.raw_prio;
                self.pg_peer_in(id, tid, prio, Box::new(body), bytes, ingress);
            }
            Ok(None) => self.log(format!(
                "link {id}: unhandled message type {ty:#x}, dropped"
            )),
            Err(e) => {
                self.pg.c.bad_peer_msgs += 1;
                self.log(format!("link {id}: undecodable PG message type {ty}: {e}"));
                if is_ec_type(ty) {
                    // an EC sub-op never closes the link (it carries replicated traffic too): the op is just not
                    // answered, as for an EC pool this OSD does not serve (adr 0039 passivity)
                    return;
                }
                // protocol-level garbage: after a few, drop the connection
                let n = self.pg.bad_by_link.entry(id).or_default();
                *n += 1;
                if *n >= BAD_MSGS_CLOSE {
                    self.pg.bad_by_link.remove(&id);
                    self.log(format!(
                        "link {id}: too many undecodable PG messages, closing"
                    ));
                    self.close_link(id);
                }
            }
        }
    }

    /// A public-link MOSDOp whose data segment was refused at intake (`msgr2` data probe): the payload was consumed and
    /// verified but never admitted, so the op is decoded from its front alone and travels the pipeline like any other.
    /// Rule 14 answers it -EMSGSIZE from the declared length; it can never reach the store.
    pub(crate) fn on_refused_op(
        &mut self,
        id: u64,
        purpose: Purpose,
        tid: u64,
        m: &msgr2::Incoming,
    ) {
        let Some(l) = self.links.get(&id) else {
            return;
        };
        if l.msgr != MsgrId::Public || purpose != Purpose::Accepted {
            self.log(format!(
                "link {id}: MOSDOp with a refused data segment on a non-client link dropped"
            ));
            return;
        }
        match opwire::MOSDOp::decode_refused(m.header.version, &m.front, m.data_refused) {
            Ok(mut op) => {
                op.ingress = m.ingress.clone();
                self.admit_client_op(id, tid, op, m.front.len());
            }
            Err(e) => self.fault_undecodable(id, "undecodable_client_op", "MOSDOp", e),
        }
    }

    /// A client op arrived on link `id` (this core): run it here when this core owns the PG, else hand it over.
    pub(crate) fn admit_client_op(&mut self, id: u64, tid: u64, mut op: MOSDOp, bytes: usize) {
        let resumed = self.cl.resuming_conn.take() == Some(id);
        let shard = self.input_shard(op.pgid.pgid);
        let local = self.pg.set.core_of(op.pgid.pgid) == self.cl.spec.id;
        let why = if !resumed && op.ingress.0.is_none() && !self.cl.pending_input[shard].is_empty()
        {
            Some(HoldWhy::Fifo)
        } else if self.cl.out.len() >= crate::xcore::XOUT_MAX || !self.cl.xout_wait.is_empty() {
            Some(HoldWhy::Xout)
        } else if local && !self.pg.store.admission_ready_for(op.pgid) {
            Some(HoldWhy::Store)
        } else {
            None
        };
        if let Some(why) = why {
            self.hold_input(
                id,
                shard,
                why,
                crate::osd::PendingInput::Op { tid, op, bytes },
            );
            return;
        }
        if op.ingress.0.is_none() {
            let Some(lease) = self.cl.ingress.reserve(shard, bytes) else {
                let why = HoldWhy::Ingress;
                self.hold_input(
                    id,
                    shard,
                    why,
                    crate::osd::PendingInput::Op { tid, op, bytes },
                );
                return;
            };
            op.ingress.0 = Some(lease);
        }
        self.route_client_op(id, tid, op);
    }

    pub(crate) fn route_client_op(&mut self, id: u64, tid: u64, op: MOSDOp) {
        if self.cl.xout_wait.is_empty() {
            self.route_client_op_now(id, tid, op);
        } else {
            // older ops wait for cross-core room: arrival order
            self.cl.xout_wait.push_back((id, tid, op));
        }
    }

    fn route_client_op_now(&mut self, id: u64, tid: u64, op: MOSDOp) {
        if self.pg.tr.on() {
            self.trace_ingress(id, tid, &op);
        }
        let pgid = op.pgid.pgid;
        if self.pg.set.core_of(pgid) == self.cl.spec.id && !self.mig_busy(pgid) {
            return self.pg_client_op(id, tid, op);
        }
        // not active: forwarded all the same, the owner core parks it (the state reaches the cores with a delay)
        // the map sharing belongs to the core that holds the connection (one MOSDMap per client, not per PG core)
        if self.state == State::Active && op.osdmap_epoch < self.epoch() {
            self.pg_share_map(id, op.osdmap_epoch);
        }
        if self.cl.out.len() >= crate::xcore::XOUT_MAX {
            // the owner core (or the ring to it) is not keeping up: backpressure like classic. The op waits in arrival
            // order, new input of every link is held behind it (admit_client_op) until the queue drains
            self.cl.xout_wait.push_back((id, tid, op));
            return;
        }
        let Some(info) = self.links.get(&id).and_then(|l| l.info.clone()) else {
            return self.pg_drop_op("no connection info", id, tid, &op);
        };
        self.pg_item(
            None,
            XMsg::Op {
                conn: id,
                tid,
                info,
                op: Box::new(op),
            },
        );
    }

    /// Forward the ops that waited for cross-core queue room, oldest first, while there is room.
    pub(crate) fn drain_xout_wait(&mut self) -> bool {
        let mut work = false;
        while self.cl.out.len() < crate::xcore::XOUT_MAX {
            let Some((id, tid, op)) = self.cl.xout_wait.pop_front() else {
                break;
            };
            work = true;
            // room was checked above and nothing older waits: it cannot be queued again
            self.route_client_op_now(id, tid, op);
        }
        work
    }

    /// PG core: a client acked a backoff.
    pub(crate) fn pg_backoff_ack(&mut self, conn: u64, b: opwire::MOSDBackoff) {
        if self.pg.eng.contains_key(&b.pgid) {
            let spg = b.pgid;
            self.pg_run(spg, move |e, _env| e.on_backoff_ack(conn, &b));
        }
    }

    /// OSD<->OSD PG message on link `id` (this core): validate the sender, route to the core(s) owning the PG(s).
    pub(crate) fn pg_peer_in(
        &mut self,
        id: u64,
        tid: u64,
        prio: u16,
        body: Box<Body>,
        bytes: usize,
        mut ingress: ingress::InputGuard,
    ) {
        let resumed = self.cl.resuming_conn.take() == Some(id);
        if self.pg.tr.on() {
            self.trace_peer_in(&body);
        }
        // while draining for shutdown the replies to our own in-flight writes must still get in (adr 0034 am. 1)
        let draining =
            self.drain_until.is_some() && self.done.is_none() && crate::xcore::pg_progress(&body);
        if (self.state == State::Stopping && !draining) || self.pg.dead {
            return;
        }
        let from = self
            .links
            .get(&id)
            .and_then(|l| l.peer.as_ref().map(|p| (p.name, l.msgr)));
        let Some((name, msgr)) = from else { return };
        if name.ty != EntityName::OSD || msgr != MsgrId::Cluster || name.num < 0 {
            self.pg.c.bad_peer_msgs += 1;
            self.log(format!(
                "link {id}: PG message {} from non-OSD peer {name:?} dropped, closing",
                body.msg_type()
            ));
            self.close_link(id);
            return;
        }
        let from = name.num as i32;
        if let Some(spg) = crate::xcore::data_spg(&body) {
            // own window and lane: never behind client writes, which hold theirs until peers acked (input_credits)
            let lane = self.peer_input_lane(spg.pgid);
            let local = self.pg.set.core_of(spg.pgid) == self.cl.spec.id;
            // credited sub-writes of an croit-flashstore-osd peer (flow.rs): the sender bounds them below our window, so the link never
            // waits for the store or for another link's held input; the PG holds them for the store with their reservation
            let credited = self.flow_peer(from) && crate::flow::is_request(&body);
            let why = if self.cl.out.len() >= crate::xcore::XOUT_MAX {
                Some(HoldWhy::Xout)
            } else if credited {
                None
            } else if !(ingress.0.is_some() || resumed || self.cl.pending_input[lane].is_empty()) {
                Some(HoldWhy::Fifo)
            } else if local && !self.pg.store.admission_ready_for(spg) {
                Some(HoldWhy::Store)
            } else {
                None
            };
            if ingress.0.is_none() && why.is_none() {
                ingress.0 = self.cl.ingress.reserve(lane, bytes);
            }
            if why.is_some() || ingress.0.is_none() {
                self.hold_input(
                    id,
                    lane,
                    why.unwrap_or(HoldWhy::Ingress),
                    crate::osd::PendingInput::Peer {
                        tid,
                        prio,
                        body,
                        bytes,
                        ingress,
                    },
                );
                return;
            }
        } else {
            let reserved = self.control_input_lane();
            // Relay frames already own bounded input. A retained unreserved message on another socket
            // must not stop this frame from reaching its future-map actor before the following Map barrier.
            let ready =
                ingress.0.is_some() || resumed || self.cl.pending_input[reserved].is_empty();
            if ingress.0.is_none() && ready {
                ingress.0 = self.cl.control_ingress.reserve(0, bytes);
            }
            if !ready || ingress.0.is_none() {
                self.hold_input(
                    id,
                    reserved,
                    if ready {
                        HoldWhy::Ingress
                    } else {
                        HoldWhy::Fifo
                    },
                    crate::osd::PendingInput::Peer {
                        tid,
                        prio,
                        body,
                        bytes,
                        ingress,
                    },
                );
                return;
            }
        }
        #[cfg(test)]
        self.t.peer_in.push(tid);
        let me = self.cl.spec.id;
        let spgs = peering::body_spgs(&body);
        if spgs.len() <= 1 || !self.multi() {
            // one PG (the data path) or one core: one owner, no list (no PG address, single core: the PG set drops /
            // handles it)
            match spgs.first() {
                Some(s)
                    if self.multi()
                        && (self.pg.set.core_of(s.pgid) != me || self.mig_busy(s.pgid)) =>
                {
                    self.pg_item(
                        None,
                        XMsg::Pg {
                            ingress,
                            link: id,
                            from,
                            tid,
                            prio,
                            body,
                        },
                    );
                }
                _ => self.pg_deliver_body_with_ingress(id, from, tid, prio, body, ingress),
            }
            return;
        }
        // several PGs (remove, scrub2): every owning core once
        let mut owners: Vec<usize> = Vec::new();
        for s in spgs {
            let c = self.pg.set.core_of(s.pgid);
            if !owners.contains(&c) {
                owners.push(c);
            }
        }
        let last = owners.len() - 1;
        let mut body = Some(body);
        for (i, c) in owners.into_iter().enumerate() {
            let b = if i == last { body.take() } else { body.clone() };
            let Some(b) = b else { break };
            if c == me {
                self.pg_deliver_body_with_ingress(id, from, tid, prio, b, ingress.clone());
            } else {
                self.cl.fwd_pg += 1;
                self.xsend(
                    c,
                    XMsg::Pg {
                        ingress: ingress.clone(),
                        link: id,
                        from,
                        tid,
                        prio,
                        body: b,
                    },
                );
            }
        }
    }

    /// PG core: hand a validated peer message to the PG set.
    pub(crate) fn pg_deliver_body_with_ingress(
        &mut self,
        _link: u64,
        from: i32,
        tid: u64,
        prio: u16,
        body: Box<Body>,
        ingress: ingress::InputGuard,
    ) {
        if self.pg.dead {
            return;
        }
        if let Some(key) = crate::flow::reply_key(&body, from, tid) {
            self.flow_reply(key);
        }
        self.pg.c.peering_msgs_in += 1;
        let spg = peering::body_spg(&body);
        let before = self.perf.op.subop_in + self.perf.op.subop_push_in;
        self.sub_in(&body);
        let bytes = self.perf.op.subop_in + self.perf.op.subop_push_in - before;
        *self.pg.c.in_by_type.entry(body.msg_type()).or_default() += 1;
        let traced =
            (self.pg.tr.on() || self.pg.tr.live_n != 0) && self.trace_peer_pg(&body, from, tid);
        let now = self.pg_mono();
        let acts = {
            let _s = wprof::span(wprof::S::PeerIn);
            self.pg.set.handle_msg(
                now,
                Inbound {
                    ingress,
                    from,
                    tid,
                    prio,
                    body,
                },
                &self.pg.store,
            )
        };
        if let Some(spg) = spg {
            self.note_pg_work(spg, 1, bytes);
        }
        self.pg_exec(acts);
        if traced {
            self.pg.tr.repl_done();
        }
    }

    /// MOSDPGCreate2 from the mon (arrives as an unknown type on the mon session).
    pub(crate) fn pg_on_mon_unknown(&mut self, ty: u16, version: u16, segs: &Segments) -> bool {
        match Body::decode(ty, version, segs) {
            Ok(Some(Body::Peering(PeeringMsg::MOSDPGCreate2(c)))) => {
                self.log(format!(
                    "mon: MOSDPGCreate2 epoch {} with {} pgs",
                    c.epoch,
                    c.pgs.len()
                ));
                if self.multi() {
                    // every core creates the PGs it owns
                    self.xbcast(|| XMsg::Create(Box::new(c.clone())));
                }
                self.pg_create_local(c);
                true
            }
            Ok(Some(_)) => {
                self.log(format!("mon: unexpected PG message type {ty} ignored"));
                true
            }
            _ => false,
        }
    }

    /// MOSDPGCreate2: create the PGs of it this core owns.
    pub(crate) fn pg_create_local(&mut self, c: pgwire::MOSDPGCreate2) {
        let now = self.pg_mono();
        let acts = self.pg.set.handle_create(now, c, &self.pg.store);
        self.pg_exec(acts);
    }

    // ------------------------------------------------------------------ client ops

    /// Client op for a PG this core owns (`id` = connection, possibly on another core): map epoch rules, role
    /// classification (client-ops.md 5.1-5.4/5.10), then the op engine.
    pub(crate) fn pg_client_op(&mut self, id: u64, tid: u64, op: MOSDOp) {
        #[cfg(test)]
        self.t.client_in.push(tid);
        // Not (yet) up in the map / no map: the client may already have connected (it learned of our boot from the mon
        // before we did) and sends nothing again on this connection, so the op waits (`pg_retry_parked` on the map and on
        // the state change) instead of being lost.
        // the map is borrowed, never cloned per op (its `Arc` count is shared by every core)
        let Some(map) = self.map.as_deref().filter(|_| self.state == State::Active) else {
            return self.pg_park_op(id, tid, op, false);
        };
        let epoch = map.epoch;
        if op.osdmap_epoch > epoch {
            // we are behind: park until the epoch is available (client-ops 5.1)
            self.pg_request_map(epoch);
            return self.pg_park_op(id, tid, op, false);
        }
        if op.osdmap_epoch > self.pg.set.epoch() {
            // the core has the epoch, its PG set not yet (several cores: the map waits for the control core's gate
            // decision, mig.rs `drain_held`). The op waits for the PG to reach its epoch (classic waiting_for_map): it
            // never runs against an older interval nor overtakes an op of its client parked before the core map moved.
            return self.pg_park_op(id, tid, op, false);
        }
        let me = self.id.whoami;
        let pgid = op.pg_t();
        let (in_acting, primary) = {
            let (pos, ap) = cur_acting_pos(&self.pg.set, map, pgid, me);
            (pos.is_some(), ap == me)
        };
        if op.osdmap_epoch < epoch && self.link_is_local(id) {
            // (a connection of another core had its maps shared there)
            self.pg_share_map(id, op.osdmap_epoch);
        }
        if !in_acting {
            self.pg.c.misdirected_dropped += 1;
            self.pg_drop_op("not in acting set", id, tid, &op);
            return; // silent drop; the shared map corrects the client
        }
        if self.pg.set.is_passive(pgid.pool) {
            return self.pg_drop_op("passive pg", id, tid, &op);
        }
        // These flags select paths that can bypass the engine's precheck. Enforce
        // its write-order contract before role dispatch (client-ops 16.8).
        if op.flags & flag::DIRECT_READ != 0
            && opexec::engine::classify(&op, &self.pg.classes).is_ok_and(|i| i.rwordered)
        {
            return self.pg_reply_err(id, tid, &op, -errno::EINVAL);
        }
        // EC_DIRECT_READ on an EC PG (primary or shard): the direct-read path, EAGAIN unless `ec_optimized_direct` serves it
        if op.flags & flag::EC_DIRECT_READ != 0
            && let Some(p) = self
                .map
                .as_ref()
                .and_then(|m| m.pool(op.pgid.pgid.pool as i64))
            && p.is_erasure()
        {
            return self.pg_direct_read(id, tid, op);
        }
        if !primary {
            let info = OpInfo::classify(&op.ops, op.flags, &|_, _| {
                Some(opwire::ClsEntry {
                    flags: ClsFlags { rd: true, wr: true },
                    allowed: true,
                })
            });
            // EC_DIRECT_READ on a replicated pool: bounce (EC pools took the direct-read path above);
            // EAGAIN makes the client redrive through the primary (always correct)
            let balanced =
                op.flags & (flag::BALANCE_READS | flag::LOCALIZE_READS | flag::EC_DIRECT_READ) != 0;
            match info {
                Ok(i) if balanced && !i.may_write => {
                    // replica reads (v1: always bounce): EAGAIN. Ceph 21.2.0 has no primary-only rule: watch/notify/pg ops
                    // without a balance flag are misdirected (dropped) like any other op on a non-primary.
                    self.pg_reply_err(id, tid, &op, -errno::EAGAIN);
                    self.pg.c.eagain_replies += 1;
                }
                _ => {
                    self.pg.c.misdirected_dropped += 1; // misdirected: drop silently
                    self.pg_drop_op("not primary", id, tid, &op);
                }
            }
            return;
        }
        self.pg_client_primary(id, tid, op);
    }

    /// Count (and log, rate limited) a client op that is dropped without a reply.
    pub(crate) fn pg_drop_op(&mut self, why: &'static str, id: u64, tid: u64, op: &MOSDOp) {
        let n = self.pg.c.dropped_ops.entry(why).or_default();
        *n += 1;
        if *n <= 5 || n.is_power_of_two() {
            let (e, ours) = (op.osdmap_epoch, self.epoch());
            self.log(format!(
                "pg {}: client op dropped ({why}) op epoch {e} ours {ours} hash {:#x} [{} so far]",
                op.pgid, op.hash, self.pg.c.dropped_ops[why]
            ));
        }
        // a dropped admitted attempt ends without a reply: vacate its terminal owner
        if let Some(retry) = op.placement_read {
            self.placement_done(id, tid, retry);
        }
    }

    /// An admitted placement attempt ended without a reply (drop, EAGAIN): vacate the
    /// link's attempt owner, directly or through the link core.
    pub(crate) fn placement_done(&mut self, id: u64, tid: u64, retry: u32) {
        if self.link_is_local(id) {
            if let Some(l) = self.links.get_mut(&id)
                && l.placement.done(tid, retry)
            {
                self.close_link(id);
            }
        } else {
            self.xsend(
                link_core(id),
                XMsg::PlacementDone {
                    link: id,
                    tid,
                    retry,
                },
            );
        }
    }

    /// Wait for a map / for the OSD to be up / for the PG (`no_pg`); bounded (count and payload bytes), an overflow is a
    /// counted drop (never silent). Order: one FIFO per core, re-run oldest first, so a client's ops on an object never
    /// overtake each other (a new op that cannot run yet queues behind the waiting ones of its kind).
    pub(crate) fn pg_park_op(&mut self, id: u64, tid: u64, op: MOSDOp, no_pg: bool) {
        if self.state == State::Stopping {
            return self.pg_drop_op("osd stopping", id, tid, &op);
        }
        let bytes: u64 = op.ops.iter().map(|o| o.indata.len() as u64).sum();
        if self.pg.parked.len() >= MAX_PARKED_OPS || self.pg.parked_bytes + bytes > MAX_PARKED_BYTES
        {
            return self.pg_drop_op("park list full", id, tid, &op);
        }
        let (seq, since) = match self.pg.reparking {
            Some(k) => k,
            None => {
                self.pg.c.parked_ops += 1;
                let n = self.pg.c.parked_ops;
                if n <= 5 || n.is_power_of_two() {
                    let (state, ours, pgs) = (self.state.name(), self.epoch(), self.pg.set.epoch());
                    let why = if no_pg { ", pg not here yet" } else { "" };
                    self.log(format!(
                        "pg {}: client op parked (osd {state}, op epoch {} ours {ours} pg set {pgs}{why}) [{n} so far]",
                        op.pgid, op.osdmap_epoch
                    ));
                }
                (n, self.now.as_nanos() as u64)
            }
        };
        self.pg.parked_bytes += bytes;
        self.pg.parked.push(Parked {
            epoch: op.osdmap_epoch,
            link: id,
            tid,
            op: Box::new(op),
            no_pg,
            seq,
            since,
            bytes,
        });
    }

    /// Ops waiting (not up yet / map behind the op's epoch / PG not there yet), for status.
    pub(crate) fn pg_parked_len(&self) -> usize {
        self.pg.parked.len()
    }

    /// `(count older than the complaint time, age of the oldest in ns)` of the waiting ops: they are client ops in
    /// flight like the tracked ones (SLOW_OPS, classic tracks ops waiting for a map or a PG too).
    pub(crate) fn pg_parked_slow(&self, now: u64, complaint_ns: u64) -> (u64, u64) {
        self.pg.parked.iter().fold((0, 0), |(n, old), p| {
            let age = now.saturating_sub(p.since);
            (n + u64::from(age >= complaint_ns), old.max(age))
        })
    }

    /// The waiting ops in the `dump_ops_in_flight` shape (`blocked_only`: older than the complaint time), with the reason
    /// as flag point. Unknown connection (peer gone) = ops still listed with a blank client.
    pub(crate) fn pg_parked_dump(
        &self,
        now: u64,
        wall: &dyn Fn(u64) -> String,
        blocked_only: bool,
    ) -> Vec<(u64, serde_json::Value)> {
        let e = self.pg.set.epoch();
        self.pg
            .parked
            .iter()
            .filter(|p| {
                !blocked_only || now.saturating_sub(p.since) >= self.tracker.lim.complaint_ns
            })
            .map(|p| {
                let (who, addr) = self
                    .conn_info(p.link)
                    .map(|i| (i.who, i.addr))
                    .unwrap_or_default();
                let why = if p.epoch > e || self.map.is_none() {
                    "waiting for map"
                } else if self.state != State::Active {
                    "waiting for osd to be active"
                } else {
                    "waiting for pg"
                };
                let rec = crate::optrack::OpRec::new(p.link, p.tid, who, addr, &p.op, p.since);
                (p.since, rec.json_waiting(now, wall, why))
            })
            .collect()
    }

    /// Run the parked ops that can proceed (the OSD is active, its PG set at a map at least as new as the op's; an op
    /// waiting for its PG: the PG is there, or `remap` = the map changed and the op is judged again), oldest first.
    pub(crate) fn pg_retry_parked(&mut self, remap: bool) {
        if self.pg.parked.is_empty() || self.state != State::Active || self.map.is_none() {
            return;
        }
        let e = self.pg.set.epoch();
        let set = &self.pg.set;
        let (ready, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pg.parked)
            .into_iter()
            .partition(|p| p.epoch <= e && (!p.no_pg || remap || set.pg(p.op.pgid).is_some()));
        self.pg.parked_bytes = rest.iter().map(|p| p.bytes).sum();
        self.pg.parked = rest;
        let mut again = false;
        for p in ready {
            if self.conn_alive(p.link) {
                let n = self.pg.parked.len();
                self.pg.reparking = Some((p.seq, p.since));
                // (the map the op waited for may have moved its PG to another core)
                self.reroute_op(p.link, p.tid, *p.op);
                self.pg.reparking = None;
                again |= self.pg.parked.len() > n;
            }
        }
        if again {
            // a re-parked op goes back to its arrival position: never behind a newer op of the same client
            self.pg.parked.sort_by_key(|p| p.seq);
        }
    }

    /// The ops waiting here for PG `pgid` as `(link, tid, op)`, oldest first: the PG leaves this core (adr 0031 am. 8).
    pub(crate) fn pg_take_parked(&mut self, pgid: PgT) -> Vec<(u64, u64, MOSDOp)> {
        if !self.pg.parked.iter().any(|p| p.op.pgid.pgid == pgid) {
            return Vec::new();
        }
        let (take, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pg.parked)
            .into_iter()
            .partition(|p| p.op.pgid.pgid == pgid);
        self.pg.parked_bytes = keep.iter().map(|p| p.bytes).sum();
        self.pg.parked = keep;
        take.into_iter().map(|p| (p.link, p.tid, *p.op)).collect()
    }

    /// Connection `id` is gone: its waiting ops can never be answered.
    fn pg_parked_conn_gone(&mut self, id: u64) {
        if self.pg.parked.iter().any(|p| p.link == id) {
            self.pg.parked.retain(|p| p.link != id);
            self.pg.parked_bytes = self.pg.parked.iter().map(|p| p.bytes).sum();
        }
    }

    /// EC_DIRECT_READ client op (spec ec-optimized.md 7.3, adr 0067 am. 3) at a PG of an EC pool, primary or shard: a read of
    /// our own data shard (and GET_INTERNAL_VERSIONS). Anything else, any doubt, and `ec_optimized_direct` off: EAGAIN,
    /// the client redrives the op through the primary. An op from before the interval / a split is dropped like any.
    pub(crate) fn pg_direct_read(&mut self, id: u64, tid: u64, mut op: MOSDOp) {
        use opwire::op as code;
        let eagain = |s: &mut Self, op: &MOSDOp| {
            s.pg.c.eagain_replies += 1;
            s.perf.op.ec_direct_eagain += 1;
            s.pg_reply_err(id, tid, op, -errno::EAGAIN);
        };
        let plain = !op.ops.is_empty()
            && op.snapid == opwire::NOSNAP
            && op.ops.iter().all(|o| {
                (matches!(o.op, code::READ | code::SPARSE_READ) && o.extent().length > 0)
                    || o.op == code::GET_INTERNAL_VERSIONS
            });
        if !plain || !self.conf.bool("ec_optimized_direct", false) {
            return eagain(self, &op);
        }
        // an op without a shard (v7 decode) addresses our own shard
        self.fill_own_shard(&mut op);
        let spg = op.pgid;
        let Some(pg) = self.pg.set.pg(spg) else {
            return eagain(self, &op);
        };
        if pg.refusal().is_some() {
            return self.pg_drop_op("passive pg", id, tid, &op);
        }
        if pg.past_bounds_stopped() {
            return self.pg_drop_op("past interval bounds stop", id, tid, &op);
        }
        let same_interval = pg.info().history.same_interval_since;
        if self.pg.dead
            || pg.client_op_stale(op.osdmap_epoch)
            || (!pg.is_primary() && op.osdmap_epoch < same_interval)
        {
            return self.pg_drop_op("stale epoch", id, tid, &op);
        }
        let Some(info) = self.conn_info(id) else {
            return self.pg_drop_op("no connection info", id, tid, &op);
        };
        if let Some(c) = &info.caps
            && !c.allows_op(&op, &[], &info.peer_addr, || {
                crate::ops::pool_caps_info(self.map.as_deref(), spg.pgid.pool as i64)
            })
        {
            return self.pg_reply_err(id, tid, &op, -errno::EPERM);
        }
        // fencing (client-ops 5.2 #10): this path bypasses the engine's precheck, so it checks the blocklist itself
        // (position and predicate as there: after the caps, before any object is read)
        if self
            .map
            .as_deref()
            .is_some_and(|m| m.is_blocklisted(&info.addr))
        {
            return self.pg_reply_err(id, tid, &op, -errno::EBLOCKLISTED);
        }
        if self.map.as_deref().is_some_and(|m| {
            m.pool(spg.pgid.pool as i64)
                .is_some_and(|p| p.has_flag(osdmap::pool::flags::EIO))
        }) {
            if op.flags & flag::SUPPORTSPOOLEIO != 0 {
                return self.pg_drop_op("pool EIO", id, tid, &op);
            }
            return self.pg_reply_err(id, tid, &op, -errno::EIO);
        }
        let soid = opexec::head_of(&op);
        let reads: Vec<peering::ecdirect::DirectExtent> = op
            .ops
            .iter()
            .filter(|o| matches!(o.op, code::READ | code::SPARSE_READ))
            .map(|o| {
                let e = o.extent();
                peering::ecdirect::DirectExtent {
                    offset: e.offset,
                    length: e.length,
                    truncate_seq: e.truncate_seq,
                    truncate_size: e.truncate_size,
                    sparse: o.op == code::SPARSE_READ,
                }
            })
            .collect();
        let want_versions = op.ops.iter().any(|o| o.op == code::GET_INTERNAL_VERSIONS);
        let now = self.pg_mono();
        let pg = self.pg.set.pg(spg).expect("checked above");
        let Ok(res) = pg.ec_direct_read(now, &soid, &reads, want_versions, &self.pg.store) else {
            return eagain(self, &op);
        };
        self.perf.op.ec_direct_reads += 1;
        // encoded on the first op that is no read (every such op echoes the versions)
        let mut versions_enc: Option<Option<Vec<u8>>> = None;
        let mut data = res.data.into_iter().zip(res.extents);
        let mut ops = Vec::with_capacity(op.ops.len());
        for o in &op.ops {
            let mut e = o.echo();
            if matches!(o.op, code::READ | code::SPARSE_READ) {
                let (d, ext) = data.next().unwrap_or_default();
                e.outdata = match ext {
                    // map<u64,u64> of logical extents + the bytes (classic direct sparse read, prim spec F.5)
                    Some(x) => denc::to_vec(&opwire::payload::SparseReadOut {
                        extents: x.into_iter().collect(),
                        data: d,
                    })
                    .unwrap_or_default()
                    .into(),
                    None => d.into(),
                };
            } else if let Some(b) = versions_enc.get_or_insert_with(|| {
                let versions: std::collections::BTreeMap<
                    denc::types::ShardId,
                    denc::types::Eversion,
                > = res.versions.iter().copied().collect();
                denc::to_vec(&versions).ok()
            }) {
                e.outdata = b.clone().into();
            }
            ops.push(e);
        }
        let mut rep = MOSDOpReply::for_request_ops(&op, self.epoch(), ops);
        rep.user_version = res.user_version;
        self.send_client_reply(id, tid, rep);
    }

    fn pg_reply_err(&mut self, id: u64, tid: u64, op: &MOSDOp, result: i32) {
        let mut r = MOSDOpReply::for_request(op, self.epoch());
        r.result = result;
        self.send_client_reply(id, tid, r);
        // an error reply is the admitted attempt's terminal proof on this session
        if let Some(retry) = op.placement_read {
            self.placement_done(id, tid, retry);
        }
    }

    /// Send the client the maps it lacks (client-ops 5.9; osd-lifecycle 3.9).
    pub(crate) fn pg_share_map(&mut self, id: u64, client_epoch: u32) {
        if crate::copy::is_copy_conn(id) {
            return;
        }
        if !self.link_is_local(id) {
            // the core holding the connection keeps the per-client projection
            self.xsend(
                link_core(id),
                XMsg::ShareMap {
                    conn: id,
                    epoch: client_epoch,
                },
            );
            return;
        }
        let ours = self.epoch();
        let known = self
            .pg
            .proj
            .get(&id)
            .copied()
            .unwrap_or(0)
            .max(client_epoch);
        if known >= ours {
            return;
        }
        // the stored map blobs are encoded for a current peer (we advertise every feature to the mon): a client without the
        // newest-encoding feature (older release, e.g. squid librados) cannot decode them and aborts in OSDMap::Incremental::decode
        // (bare metal: rados 19.2.6 against Ceph main crashed on a pg_num change). Such clients follow the mon's map stream.
        if self.link_features(id) & denc::features::TENTACLE_BIT == 0 {
            self.pg.proj.insert(id, ours);
            return;
        }
        let first = map_share_first(known, ours, self.pg.map_share);
        let mut m = MOSDMap {
            fsid: self.id.cluster_fsid,
            cluster_osdmap_trim_lower_bound: self.sb.cluster_osdmap_trim_lower_bound,
            newest_map: ours,
            ..Default::default()
        };
        let mut complete = first == known + 1;
        for e in first..=ours {
            match self.map_blob(e, crate::meta::MapKind::Inc) {
                Some(b) => {
                    m.incremental_maps.insert(e, b);
                }
                None => {
                    complete = false;
                    break;
                }
            }
        }
        if !complete {
            m.incremental_maps.clear();
            match self.map_blob(ours, crate::meta::MapKind::Full) {
                Some(b) => {
                    m.maps.insert(ours, b);
                }
                None => return,
            }
        }
        self.pg.proj.insert(id, ours);
        self.send_link(id, m);
    }

    /// A local link closed: forget its per-connection state and tell the cores it forwarded to.
    pub(crate) fn pg_link_closed(&mut self, id: u64, fwd: u64) {
        let me = self.cl.spec.id;
        for c in 0..self.cl.spec.n {
            if c != me && fwd & (1 << c) != 0 {
                self.xsend(c, XMsg::ConnClosed { conn: id });
            }
        }
        self.pg_conn_gone(id);
    }

    /// Per-connection state of `id` (a local link or a connection of another core) is obsolete.
    pub(crate) fn pg_conn_gone(&mut self, id: u64) {
        self.pg_parked_conn_gone(id);
        self.engines_conn_closed(id);
        self.pg.proj.remove(&id);
        self.pg.bad_by_link.remove(&id);
        self.cl.remote.remove(&id);
        self.cl.rlinks.remove(&id);
    }

    /// Is connection `id` (local link, or remote one that sent us ops) still known?
    pub(crate) fn conn_alive(&self, id: u64) -> bool {
        crate::xcore::conn_open(&self.links, &self.cl.remote, self.cl.spec.id, id)
    }

    /// Feature mask of connection `id` (local or remote).
    pub(crate) fn link_features(&self, id: u64) -> u64 {
        if self.link_is_local(id) {
            self.links
                .get(&id)
                .and_then(|l| l.peer.as_ref())
                .map_or(denc::features::ALL, |p| p.features)
        } else {
            self.cl
                .remote
                .get(&id)
                .map_or(denc::features::ALL, |c| c.features)
        }
    }

    /// Connection info for the op engine.
    pub(crate) fn conn_info(&self, id: u64) -> Option<Arc<ConnInfo>> {
        if self.link_is_local(id) {
            self.links.get(&id).and_then(|l| l.info.clone())
        } else {
            self.cl.remote.get(&id).cloned()
        }
    }

    // ------------------------------------------------------------------ stats

    /// `(pg_t, encoded pg_stat_t)` of this core's primary PGs.
    pub(crate) fn pg_stat_list_local(&self) -> Vec<(PgT, Vec<u8>)> {
        // an EC PG led here is a shard instance (`pgid` + our acting position), a replicated one has `NO_SHARD`
        let leading: std::collections::BTreeSet<PgT> = self
            .pg
            .set
            .pgs()
            .filter(|(_, p)| p.is_primary())
            .map(|(s, _)| s.pgid)
            .collect();
        self.pg
            .stats
            .iter()
            .filter(|(pgid, _)| leading.contains(*pgid) || self.pg.orphan_stats.contains(*pgid))
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// `(pg_t, encoded pg_stat_t)` of primary PGs of the whole OSD (MPGStats): this core plus the other cores' last
    /// report (at most a second old).
    pub(crate) fn pg_stat_list(&self) -> Vec<(PgT, Vec<u8>)> {
        let mut v = self.pg_stat_list_local();
        for s in self.cl.stats.iter().flatten() {
            v.extend(s.pg_stats.iter().cloned());
        }
        v
    }

    /// Pools (erasure, unsupported) CRUSH mapped onto this OSD: PGs of these stay passive. Operator signal for `tell status`.
    pub(crate) fn pg_passive_pools(&self) -> Vec<u64> {
        self.pg
            .ec_mapped
            .iter()
            .copied()
            .filter(|p| !self.pg.set.serves_ec_pool(*p))
            .collect()
    }

    /// Decline-mode answers (adr 0039 am. 1) of the whole OSD: this core plus the other cores' last report.
    pub(crate) fn pg_ec_declined(&self) -> BTreeMap<&'static str, u64> {
        let mut m = self.pg.set.decline_stats.clone();
        for s in self.cl.stats.iter().flatten() {
            for (k, v) in &s.ec_declined {
                *m.entry(*k).or_default() += v;
            }
        }
        m
    }

    pub(crate) fn pg_num_pgs(&self) -> u32 {
        self.pg.set.pgs().count() as u32
            + self
                .cl
                .stats
                .iter()
                .flatten()
                .map(|s| s.num_pgs)
                .sum::<u32>()
    }

    /// Control core: hand the OSD-wide PG count (all cores) to every core's PG log target (spec pglog.md 6.3) when it
    /// changed.
    pub(crate) fn pg_sync_num_pgs(&mut self) {
        let n = self.pg_num_pgs();
        if self.pg_set_num_pgs(n) && self.multi() {
            self.xbcast(|| XMsg::NumPgs(n));
        }
    }

    /// This core's copy of the OSD-wide PG count (PG log target, object-state cache size per PG); `true` if it changed.
    pub(crate) fn pg_set_num_pgs(&mut self, n: u32) -> bool {
        let changed = self.pg.set.set_num_pgs(u64::from(n));
        if changed {
            self.pg.set.push_cfg_to_pgs();
            self.obs_memory();
        }
        changed
    }

    /// `min_last_epoch_clean` over primary PGs (all cores) bounded by the current epoch, and the primary PG list.
    pub(crate) fn pg_collect(&self) -> (u32, Vec<PgT>) {
        let e = self.epoch();
        let mut lce = self.pg.set.min_last_epoch_clean().map_or(e, |m| m.min(e));
        let mut pgs: Vec<PgT> = self
            .pg
            .set
            .pgs()
            .filter(|(_, p)| p.is_primary())
            .map(|(s, _)| s.pgid)
            .collect();
        for s in self.cl.stats.iter().flatten() {
            lce = s.lce.map_or(lce, |m| lce.min(m));
            pgs.extend(s.primary_pgs.iter().copied());
        }
        (lce, pgs)
    }
}

impl<B: Backend> Osd<B> {
    /// Rebuild the stored maps `[from, to]` (at or after the newest full map <= `from`), oldest first. Control core.
    pub(crate) fn pg_load_maps(&mut self, from: u32, to: u32) -> Vec<OsdMap> {
        use crate::meta::MapKind;
        let epochs = match self.store.as_ref().map(|s| s.map_epochs(to)) {
            Some(Ok(epochs)) => epochs,
            Some(Err(e)) => {
                self.fatal(&format!("enumerate stored maps: {e}"));
                return Vec::new();
            }
            None => return Vec::new(),
        };
        // Use actual stored epochs, including crash leftovers not yet indexed in the superblock.
        // Probing each absent epoch makes rejoining after a large trimmed gap proportional to downtime.
        let mut base = epochs
            .iter()
            .rev()
            .copied()
            .filter(|e| *e <= from)
            .find(|e| self.meta_map(*e, MapKind::Full).is_some());
        if base.is_none() {
            // nothing at or below: first full above
            base = epochs
                .iter()
                .copied()
                .filter(|e| *e >= from)
                .find(|e| self.meta_map(*e, MapKind::Full).is_some());
        }
        let Some(base) = base else { return Vec::new() };
        let mut out: Vec<OsdMap> = Vec::new();
        let mut remaining = epochs.into_iter().filter(|e| *e >= base).peekable();
        while let Some(e) = remaining.next() {
            let full = self
                .meta_map(e, MapKind::Full)
                .and_then(|b| OsdMap::decode_from(&b).ok());
            let m = match full {
                Some(m) => Some(m),
                None => match (out.last(), self.meta_map(e, MapKind::Inc)) {
                    (Some(p), Some(b)) => Incremental::decode_from(&b)
                        .and_then(|i| p.apply_incremental_checked(&i))
                        .ok(),
                    _ => None,
                },
            };
            match m {
                Some(m) => out.push(m),
                None => {
                    // A hole in the stored history (epochs we never received, e.g. the mon jumped us over them at a
                    // boot): continue at the next stored FULL map instead of stopping. Stopping left the PG set on a
                    // map older than the PGs, and PGs of pools created since looked "deleted" and were removed (data loss).
                    while remaining
                        .peek()
                        .is_some_and(|x| self.meta_map(*x, MapKind::Full).is_none())
                    {
                        remaining.next();
                    }
                    let next = remaining.peek().copied();
                    self.log(format!(
                        "pg: stored map {e} unusable{}",
                        next.map_or(String::new(), |n| format!(", continuing at full map {n}"))
                    ));
                    match next {
                        Some(_) => continue,
                        None => break,
                    }
                }
            }
        }
        out
    }

    /// The persisted maps `[from, to]` for a PG created from a message of epoch `from` (older than the kept maps):
    /// from the newest epoch <= `from` on (the start map and everything after it). Control core. Empty = trimmed.
    fn pg_old_map_chain(&mut self, from: u32, to: u32) -> Vec<Arc<OsdMap>> {
        let maps: Vec<Arc<OsdMap>> = self
            .pg_load_maps(from, to)
            .into_iter()
            .map(Arc::new)
            .collect();
        let start = maps.iter().rposition(|m| m.epoch <= from).unwrap_or(0);
        maps[start..].to_vec()
    }

    /// Control core: a worker asks for old maps (loaded from the meta store, decoded once, shared by Arc).
    pub(crate) fn pg_serve_old_maps(&mut self, core: usize, from: u32, to: u32) {
        let maps = self.pg_old_map_chain(from, to);
        self.xsend(core, XMsg::OldMaps { from, maps });
    }

    /// The old maps arrived (or were found trimmed): the PG set creates the parked PGs.
    pub(crate) fn pg_old_maps_in(&mut self, from: u32, maps: Vec<Arc<OsdMap>>) {
        let acts = self.pg_old_maps_acts(from, maps);
        self.pg_exec(acts);
    }

    fn pg_old_maps_acts(&mut self, from: u32, maps: Vec<Arc<OsdMap>>) -> Vec<Action> {
        let now = self.pg_mono();
        let maps = maps.into_iter().map(handle).collect();
        self.pg.set.old_maps(now, from, maps, &self.pg.store)
    }

    /// Start of the OSD: load PGs persisted in the store (peering resumes from the stored log/info; the maps since
    /// each PG's last epoch are fed first so interval checks work). Workers get their maps from core 0.
    pub(crate) fn pg_boot(&mut self) {
        let spgs = self.pg.store.list_pgs();
        if let Some(f) = self.pg.store.failed() {
            return self.store_failed(&f);
        }
        let cur = self.epoch();
        let loaded: Vec<(SpgT, u32)> = spgs
            .iter()
            .filter_map(|s| self.pg.store.load_pg(*s).map(|p| (*s, p.epoch)))
            .collect();
        let lo = loaded.iter().map(|p| p.1).min().unwrap_or(cur).min(cur);
        if let Some(f) = self.pg.store.failed() {
            return self.store_failed(&f);
        }
        if self.multi() {
            // every core reports the complete PGs its store holds; core 0 resolves copies on two cores and deferrals
            // (mig.rs)
            let pgs: Vec<crate::mig::BootPg> = loaded
                .iter()
                .map(|&(spg, epoch)| crate::mig::BootPg {
                    spg,
                    shard: self.pg.store.shard_of_pg(spg.pgid).unwrap_or(0),
                    generation: self.pg.store.mig_gen(spg),
                    epoch,
                })
                .collect();
            let lo = if pgs.is_empty() { u32::MAX } else { lo };
            if self.is_control() {
                return self.boot_note(0, lo, pgs);
            }
            self.cl.boot_wait = true;
            self.xsend(0, XMsg::MapsReq { lo, pgs });
            return;
        }
        if spgs.is_empty() {
            self.pg.set.note_loaded();
            return;
        }
        let maps: Vec<Arc<OsdMap>> = if cur == 0 {
            Vec::new()
        } else {
            self.pg_load_maps(lo, cur)
                .into_iter()
                .map(Arc::new)
                .collect()
        };
        self.pg_boot_with(maps);
    }

    /// Feed the rebuilt maps (oldest first) to the PG set and load the stored PGs.
    pub(crate) fn pg_boot_with(&mut self, maps: Vec<Arc<OsdMap>>) {
        let spgs = self.pg.store.list_pgs();
        if spgs.is_empty() {
            self.pg.set.note_loaded();
            return;
        }
        if maps.is_empty() {
            self.log(format!(
                "pg: {} PGs in the store but no usable osdmap, not loaded",
                spgs.len()
            ));
            return;
        }
        let n = maps.len();
        let lo = maps.first().map_or(0, |m| m.epoch);
        if let Some(last) = maps.last()
            && last.epoch < self.epoch()
        {
            self.log(format!(
                "pg: ERROR rebuilt maps end at epoch {} but the stored current epoch is {}: PGs stored after it are not loaded",
                last.epoch,
                self.epoch()
            ));
        }
        for m in maps {
            self.pg.set.add_map(handle(m));
        }
        let now = self.pg_mono();
        let acts = self.pg.set.load_pgs(now, &self.pg.store);
        self.pg_drain_notices();
        // before we are booted nobody should hear from us: keep local persistence/bookkeeping only
        let acts: Vec<Action> = acts
            .into_iter()
            .filter(|a| {
                !matches!(
                    a,
                    Action::Send(_)
                        | Action::NeedUpThru { .. }
                        | Action::PgTemp { .. }
                        | Action::RequestMap { .. }
                        | Action::NeedOldMaps { .. }
                )
            })
            .collect();
        self.pg.c.pgs_loaded = self.pg.set.pgs().count() as u64;
        self.log(format!(
            "pg: loaded {} of {} stored PGs ({n} maps rebuilt from epoch {lo})",
            self.pg.c.pgs_loaded,
            spgs.len()
        ));
        self.pg_exec(acts);
        self.pg.store.gc_orphans_after_load();
    }

    /// Driver hook: the store has no IO in flight and nothing queued (see `PgStoreOps::io_quiet`), so the driver need
    /// not poll it before its next timer (the admin socket is polled at least once per deep-idle cap, 1 ms); a running
    /// `bench` keeps the driver polling.
    pub fn store_quiet(&self) -> bool {
        self.cmds.bench.is_none() && self.cl.compact_work.is_empty() && self.pg.store.io_quiet()
    }

    /// Driver hook (idle iteration, store not quiet, no completion wake-up): time until a polled store device may complete
    /// a command (`Some(0)` = due: poll), `None` = no estimate (see `PgStoreOps::io_wait_hint`, adr 0004 am. 1).
    pub fn store_wait_hint(&mut self) -> Option<Duration> {
        if self.cmds.bench.is_some() || !self.cl.compact_work.is_empty() {
            return None;
        }
        self.pg.store.io_wait_hint()
    }

    /// Driver hook (every loop iteration): reap durable PG transactions -> `on_commit`, detect store failure.
    /// Returns true if anything happened (the driver then flushes output).
    pub fn poll_store(&mut self, now: Duration) -> bool {
        if self.cl.compact_configured.is_none() {
            self.cl.compact_configured = Some(B::helpers_configured(&self.pg.store));
        }
        if self.cl.compact_configured == Some(true) {
            let helpers = self.multi() && !self.pg.dead && self.state != State::Stopping;
            B::compaction_helpers(
                &self.pg.store,
                helpers,
                if helpers { self.free_helpers() } else { 0 },
            );
        }
        self.settle_late();
        let queued_events = self.event_pump_pending;
        if queued_events {
            self.set_now(now);
            self.pump();
        }
        let relay_events = self.resume_event_pipes();
        let asok = self.cmds.has_asok() && self.poll_asok(now);
        let bench = self.cmds.bench.is_some() && self.poll_bench();
        let purged = self.pg.set.purged_snaps_running() && self.poll_purged_scan();
        let store = self.poll_store_inner(now);
        let helpers = self.poll_compaction();
        store | helpers | asok | bench | purged | queued_events | relay_events
    }

    /// Driver hook (end of every loop iteration, after receive, cross-core pump and timers, before the IO flush): the
    /// store group-commits the txns this pass submitted (adr 0021 am. 67).
    pub fn end_pass(&mut self) {
        if !self.pg.dead {
            self.pg.store.end_pass();
        }
    }

    fn poll_store_inner(&mut self, now: Duration) -> bool {
        let _s = wprof::span(wprof::S::Poll);
        self.pg.share.next_iteration();
        #[cfg(feature = "lab")]
        if now < self.cmds.stall_until {
            return false; // LAB: completions stay queued in the store
        }
        if self.pg.dead {
            return false;
        }
        self.pre_reap();
        let mut done = Vec::new();
        self.pg.store.poll_commits(&mut done);
        // queued PG deletions (adr 0524): one non-blocking deletion txn at a time through the store queue; it never waits
        // for a page load or for durability, and a step costs the core at most one drain slice (`xcore::SLICE_NS`), like a
        // listing pass (adr 0522): the clients of this core wait at most that long for a deletion. Background work (am. 1):
        // back to back only after a gap without client demand on this core, else one step per gap (`RmPace`).
        let removing = match self
            .pg
            .rm_pace
            .due(self.perf.util.ops, self.pg.failsafe, now)
        {
            Some(paced) => {
                let q = self.pg.store.step_removals(crate::xcore::SLICE_NS);
                if q {
                    self.pg.rm_pace.stepped(paced, now);
                    self.perf.util.rm_steps[usize::from(paced)] += 1;
                }
                q
            }
            None => false,
        };
        if removing || self.pg.del.active() {
            self.pg_delete_progress(now);
        }
        if let Some(f) = self.pg.store.failed() {
            self.set_now(now);
            self.store_failed(&f);
            self.pump();
            return true;
        }
        #[cfg(feature = "elastic")]
        self.pool_forward();
        // a tree page load finished: ops parked at a PG gate (cold object) may run (adr 0021 am. 8)
        let woke = self.pg.store.take_wake_set(&mut self.pg.wake);
        // listing continuations deferred by the core share (adr 0522) run in this iteration: no store wake names them
        let deferred = std::mem::take(&mut self.pg.share.pending);
        if done.is_empty() && !woke && !deferred {
            return removing;
        }
        self.set_now(now);
        let t = self.pg_mono();
        // one PG pass for every txn this poll reaped (group commit makes several durable at once): the PG machinery takes
        // each commit in completion order, their actions run in that order in ONE `pg_exec` (one engine sync, one retry
        // of the parked ops, one reply flush) instead of one per txn
        if !done.is_empty() {
            self.pg.c.commit_polls += 1;
            self.pg.c.commits += done.len() as u64;
            let mut acts = Vec::new();
            for (spg, token) in done {
                if let Some(el) = self.pg.persist_t.done(token, t) {
                    self.store_commit_done(el, t);
                }
                if self.pg.tr.live_n != 0 {
                    self.pg.tr.durable(token);
                }
                acts.extend(self.pg.set.on_commit(t, spg, token, &self.pg.store));
            }
            self.pg_exec(acts);
        }
        if woke && self.pg.set.repops_waiting() {
            // repops held for the store (cold pages, adr 0021 am. 8): the loaded page
            let start = std::time::Instant::now();
            for _ in 0..8 {
                if start.elapsed() >= Duration::from_micros(100) {
                    break;
                }
                let acts = self.pg.set.retry_repops(t, &self.pg.store);
                if acts.is_empty() {
                    break;
                }
                self.pg_exec(acts);
                if self.pg.dead {
                    break;
                }
            }
        }
        if woke || deferred {
            // no commit may follow to run the parked ops (pg_exec ends in pg_post): retry them now, not at the next timer
            self.pg_post();
        }
        self.pump();
        true
    }

    /// Local store failure (EIO / ENOSPC on commit, dead device): stop serving PGs, tell the mon, exit non-zero.
    /// Nothing more is written to the store; what is durable stays consistent.
    pub(crate) fn store_failed(&mut self, why: &str) {
        self.fail_stop(&format!("local store failure: {why}"));
    }

    /// Fail-stop (adr 0066): log FATAL, mark this OSD down and exit (the control core stops the OSD for every core).
    pub(crate) fn fail_stop(&mut self, why: &str) {
        if self.pg.dead {
            return;
        }
        self.pg.dead = true;
        // a name this store cannot hold (no FEAT_LONG_NAME) comes back with every restart (the PG log entry, then the
        // recovery push): exit with "refused" so the unit does not loop, until the store is re-mkfs-ed (adr 0021 am. 30)
        let long_name = why.contains("NameTooLong");
        if long_name {
            self.logl(
                0,
                "FATAL: a replicated object name is too long for this store (no FEAT_LONG_NAME): re-mkfs this OSD; staying down (no restart loop)".to_owned(),
            );
        }
        self.logl(0, format!("FATAL: {why}; marking osd down and exiting"));
        self.fail_code = Some(if long_name {
            crate::release::EXIT_REFUSED
        } else {
            1
        });
        if !self.is_control() {
            // the control core stops the OSD (mark-me-down) and tells every core
            self.xsend(0, XMsg::Fatal(why.to_owned()));
            return;
        }
        self.begin_shutdown(true);
    }

    /// Drop stored maps nobody needs any more: below the mon's trim bound and the oldest map any PG (of any core)
    /// still needs.
    pub(crate) fn trim_stored_maps(&mut self) {
        let _ = self.trim_maps_inner(false);
    }

    /// `force` skips the batching threshold (operator `trim stale osdmaps`). Returns the oldest epoch still stored.
    pub(crate) fn trim_maps_inner(&mut self, force: bool) -> Result<Option<u32>, String> {
        let min_pg = self
            .cl
            .stats
            .iter()
            .flatten()
            .filter_map(|s| s.min_epoch)
            .chain(self.pg.set.min_pg_epoch())
            .min()
            .unwrap_or(u32::MAX);
        let bound = self
            .sb
            .cluster_osdmap_trim_lower_bound
            .min(min_pg)
            .min(self.epoch());
        if !force && bound < self.trimmed_to + 64 {
            return Ok(None);
        }
        let Some(store) = self.store.as_mut() else {
            return Err("no meta store on this core".into());
        };
        match store.trim_maps(bound) {
            Ok(oldest) if oldest > 0 => {
                self.trimmed_to = bound;
                let keep: BTreeMap<u32, u32> = self
                    .sb
                    .mapc
                    .iter()
                    .filter(|(s, l)| **s + **l > oldest)
                    .map(|(s, l)| {
                        let ns = (*s).max(oldest);
                        (ns, *s + *l - ns)
                    })
                    .collect();
                self.sb.mapc = keep;
                Ok(Some(oldest))
            }
            Ok(_) => Ok(None),
            Err(e) => {
                self.log(format!("trim maps: {e}"));
                Err(e.to_string())
            }
        }
    }
}

impl<B: Backend> Osd<B> {
    /// `dump_pgs` tell command (dev diagnostics).
    pub(crate) fn pg_dump(&self) -> serde_json::Value {
        let now = self.pg_mono();
        // the owning core, named in each entry: the merged scatter must not relabel by reply order
        let core = self.core_id();
        let pgs: Vec<serde_json::Value> = self
            .pg
            .set
            .pgs()
            .map(|(s, p)| {
                let objs = self.pg.store.object_stats(*s);
                serde_json::json!({
                    "pgid": s.to_string(),
                    "core": core,
                    "state": p.state_string(),
                    "machine": format!("{:?}", p.machine_state()),
                    "primary": p.is_primary(),
                    "up": p.up(),
                    "acting": p.acting(),
                    "map_epoch": p.map_epoch(),
                    "last_peering_reset": p.last_peering_reset(),
                    "last_update": p.info().last_update.to_string(),
                    "log_head": p.log().head().to_string(),
                    "pg_committed_to": p.pg_committed_to().to_string(),
                    "in_flight_persists": p.in_flight_persists(),
                    "missing": p.missing().len(),
                    "objects": objs.0,
                    "bytes": objs.1,
                    "rep_res": format!("{:?}", p.rep_reservation()),
                    "resv": p.resv_debug(),
                    "scrub": p.scrub_debug(),
                    "repops_held": p.repops_held(),
                    "held_head": p.held_head(now),
                    "readable_until_ms": p.readable_until() / 1_000_000,
                    "lease": p.is_primary().then(|| p.lease_status(now)),
                    "now_ms": now / 1_000_000,
                    "counters": format!("{:?}", p.counters()),
                    "engine": self.pg.eng.get(s).map(|e| e.dump_state()),
                })
            })
            .collect();
        serde_json::json!({
            "pgs": pgs,
            "peers": self.pg.peers.keys().collect::<Vec<_>>(),
            "dropped": self.pg.set.dropped,
            "parked": self.pg.set.parked_msgs(),
            "declined": self.pg.set.decline_stats,
            "counters": format!("{:?}", self.pg.c),
            "store_diag": self.pg.store.diag(),
        })
    }
}

// ------------------------------------------------------------------ scrub control

impl<B: Backend> Osd<B> {
    /// MOSDScrub2 (`ceph pg scrub|deep-scrub|repair`): accepted from a mon or mgr peer of our cluster only.
    fn pg_on_scrub2(&mut self, id: u64, m: replwire::MOSDScrub2) {
        if self.state == State::Stopping || self.pg.dead {
            return;
        }
        let ty = self
            .links
            .get(&id)
            .and_then(|l| l.peer.as_ref().map(|p| p.name.ty));
        if !matches!(ty, Some(EntityName::MON | EntityName::MGR)) {
            self.log(format!(
                "link {id}: MOSDScrub2 from a non mon/mgr peer dropped"
            ));
            return;
        }
        if m.fsid != self.id.cluster_fsid.0 {
            self.log(format!("link {id}: MOSDScrub2 with foreign fsid dropped"));
            return;
        }
        self.log(format!(
            "scrub command: {} pgs deep={} repair={}",
            m.scrub_pgs.len(),
            m.deep,
            m.repair
        ));
        if self.multi() {
            self.xbcast(|| XMsg::Scrub2(Box::new(m.clone())));
        }
        self.pg_scrub2_local(m);
    }

    /// MOSDForceRecovery (`ceph pg force-recovery|force-backfill|cancel-*`): accepted from a mon or mgr peer of our
    /// cluster only (spec force-recovery.md 2).
    fn pg_on_force_recovery(&mut self, id: u64, m: replwire::MOSDForceRecovery) {
        if self.state == State::Stopping || self.pg.dead {
            return;
        }
        let ty = self
            .links
            .get(&id)
            .and_then(|l| l.peer.as_ref().map(|p| p.name.ty));
        if !matches!(ty, Some(EntityName::MON | EntityName::MGR)) {
            self.log(format!(
                "link {id}: MOSDForceRecovery from a non mon/mgr peer dropped"
            ));
            return;
        }
        if m.fsid != self.id.cluster_fsid.0 {
            self.log(format!(
                "link {id}: MOSDForceRecovery with foreign fsid dropped"
            ));
            return;
        }
        if self.multi() {
            self.xbcast(|| XMsg::ForceRecovery(Box::new(m.clone())));
        }
        self.pg_force_recovery_local(m);
    }

    /// Apply the PGs of a (validated) MOSDForceRecovery this core owns.
    pub(crate) fn pg_force_recovery_local(&mut self, m: replwire::MOSDForceRecovery) {
        if self.pg.dead {
            return;
        }
        let now = self.pg_mono();
        let acts = self.pg.set.force_command(now, m, &self.pg.store);
        self.pg_exec(acts);
    }

    /// `ceph tell osd.N scrub|deep-scrub|repair [pgid]`: one PG, or (no pgid) every PG this OSD is primary for.
    pub(crate) fn pg_scrub_tell(
        &mut self,
        deep: bool,
        repair: bool,
        pgid: Option<&str>,
    ) -> (i32, String) {
        let what = if repair {
            "repair"
        } else if deep {
            "deep-scrub"
        } else {
            "scrub"
        };
        let scrub_pgs = match pgid {
            None => Vec::new(),
            Some(s) => match parse_pgid(s) {
                Some(pgid) => vec![SpgT {
                    pgid,
                    shard: denc::types::ShardId::NO_SHARD,
                }],
                None => return (-errno::EINVAL, format!("couldn't parse pgid '{s}'")),
            },
        };
        let m = replwire::MOSDScrub2 {
            fsid: self.id.cluster_fsid.0,
            epoch: self.epoch(),
            scrub_pgs,
            repair,
            deep,
        };
        let msg = match pgid {
            Some(s) => format!("instructing pg {s} on osd.{} to {what}", self.id.whoami),
            None => format!("instructing all pgs on osd.{} to {what}", self.id.whoami),
        };
        if self.multi() {
            self.xbcast(|| XMsg::Scrub2(Box::new(m.clone())));
        }
        self.pg_scrub2_local(m);
        (0, msg)
    }

    /// Scrub the PGs of a (validated) MOSDScrub2 this core owns.
    pub(crate) fn pg_scrub2_local(&mut self, m: replwire::MOSDScrub2) {
        if self.pg.dead {
            return;
        }
        let now = self.pg_mono();
        let acts = self.pg.set.scrub_command(now, m, &self.pg.store);
        self.pg_exec(acts);
    }

    /// Slot request of another core (this core keeps the OSD-wide budgets).
    pub(crate) fn pg_slot_req(&mut self, req: peering::SlotReq) {
        if self.pg.dead {
            return;
        }
        let now = self.pg_mono();
        let acts = self.pg.set.slot_rx_req(now, req, &self.pg.store);
        self.pg_exec(acts);
    }

    /// The budget owner's answer to a slot request of this core.
    pub(crate) fn pg_slot_reply(&mut self, reply: peering::SlotReply) {
        if self.pg.dead {
            return;
        }
        let now = self.pg_mono();
        let acts = self.pg.set.slot_rx_reply(now, reply, &self.pg.store);
        self.pg_exec(acts);
    }

    /// Recovery-op budget request of another core (this core keeps the OSD-wide limit).
    pub(crate) fn pg_ops_req(&mut self, req: peering::OpsReq) {
        if self.pg.dead {
            return;
        }
        let now = self.pg_mono();
        let acts = self.pg.set.ops_rx_req(now, req, &self.pg.store);
        self.pg_exec(acts);
    }

    /// The recovery-op budget owner's answer to this core.
    pub(crate) fn pg_ops_reply(&mut self, reply: peering::OpsReply) {
        if self.pg.dead {
            return;
        }
        let now = self.pg_mono();
        let acts = self.pg.set.ops_rx_reply(now, reply, &self.pg.store);
        self.pg_exec(acts);
    }

    /// NOSCRUB / NODEEP_SCRUB (cluster and pool) of the current map.
    fn pg_scrub_flags(&mut self, map: &OsdMap) {
        use osdmap::consts::map_flags as f;
        use osdmap::pool::flags as pf;
        let mut s = peering::ScrubFlags {
            noscrub: map.flags & f::NOSCRUB != 0,
            nodeep: map.flags & f::NODEEP_SCRUB != 0,
            ..Default::default()
        };
        for (id, p) in &map.pools {
            if p.has_flag(pf::NOSCRUB) {
                s.pool_noscrub.insert(*id as u64);
            }
            if p.has_flag(pf::NODEEP_SCRUB) {
                s.pool_nodeep.insert(*id as u64);
            }
        }
        self.pg.set.set_scrub_flags(s);
    }

    /// Broadcast the OSD-wide recovery reservation state to the other cores (spec scrub.md 12.1.3): only the budget
    /// owner sees its reservers. While reservations are held the state is repeated on every tick, so a core that just
    /// received PGs learns it as well.
    pub(crate) fn sync_scrub_recovering(&mut self) {
        if !self.is_control() || !self.multi() {
            return;
        }
        let v = self.pg.set.scrub_recovering();
        if v == self.scrub_recovering && !v {
            return;
        }
        self.scrub_recovering = v;
        self.xbcast(|| XMsg::ScrubRecovering(v));
    }
}

// ------------------------------------------------------------------ pg query / counts

/// `2026-10-09T18:47:45.485886+0000` (classic `utime_t` JSON form).
pub fn utime_str(t: denc::types::UTime) -> String {
    let (y, m, d, hh, mm, ss) = osddir::civil_from_secs(u64::from(t.sec));
    format!(
        "{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{:06}+0000",
        t.nsec / 1000
    )
}

/// Local wall clock (hour of day, weekday 0 = Sunday) of `wall_ns` in the OSD process's time zone (`TZ`, DST-aware):
/// the base of the scrub windows (spec scrub.md 12.1.1). Unrepresentable times fall back to UTC.
fn local_scrub_time(wall_ns: u64) -> peering::LocalTime {
    let secs = (wall_ns / 1_000_000_000) as libc::time_t;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: localtime_r fills the caller's `tm`; it returns NULL for a time it cannot represent.
    if unsafe { libc::localtime_r(&secs, tm.as_mut_ptr()) }.is_null() {
        let (_, _, _, hour, _, _) = osddir::civil_from_secs(secs.max(0) as u64);
        // 1970-01-01 was a Thursday
        let weekday = (secs.div_euclid(86_400) + 4).rem_euclid(7);
        return peering::LocalTime {
            hour: hour as u32,
            weekday: weekday as u32,
        };
    }
    // SAFETY: localtime_r returned non-NULL, so the whole `tm` is initialized.
    let tm = unsafe { tm.assume_init() };
    peering::LocalTime {
        hour: tm.tm_hour as u32,
        weekday: tm.tm_wday as u32,
    }
}

/// EC sub-op message type (108..=111).
fn is_ec_type(ty: u16) -> bool {
    (ecwire::ty::EC_WRITE..=ecwire::ty::EC_READ_REPLY).contains(&ty)
}

/// LAB ONLY (adr 0024): flip one byte of an object of an EC shard PG straight in the store (scrub / repair tests).
/// `pgid` = `<pool>.<seed hex>s<shard>`.
#[cfg(feature = "lab")]
impl<B: Backend> Osd<B> {
    pub(crate) fn pg_lab_corrupt(
        &mut self,
        pgid: &str,
        oid: &str,
        off: u64,
    ) -> Result<String, String> {
        use peering::PgStoreOps;
        let (p, sh) = pgid.rsplit_once('s').ok_or("pgid needs a shard: 86.5s0")?;
        let spg = denc::types::SpgT {
            pgid: parse_pgid(p).ok_or("bad pgid")?,
            shard: denc::types::ShardId(sh.parse::<i8>().map_err(|_| "bad shard")?),
        };
        let list = self
            .pg
            .store
            .list_objects(spg, &denc::types::Hobject::MIN(), 0, 100_000)
            .map_err(|e| format!("list: {e:?}"))?
            .objs;
        let soid = list
            .into_iter()
            .map(|(h, _)| h)
            .find(|h| h.oid == oid.as_bytes())
            .ok_or("no such object in that pg")?;
        let (cur, _) = self
            .pg
            .store
            .ec_read(spg, &soid, off, 1)
            .map_err(|e| format!("read: {e}"))?;
        let byte = [cur.first().copied().unwrap_or(0) ^ 0xff];
        let mut t = replwire::Transaction::new();
        let c = t.coll(&denc::types::CollT::Pg(spg));
        let o = t.obj(&denc::types::Ghobject::head(soid.clone(), spg.shard));
        t.push(
            c,
            replwire::TxnOp::Write {
                oid: o,
                off,
                data: replwire::Data::new(&byte),
            },
        );
        let data = t.encode_v9().map_err(|e| e.to_string())?;
        self.pg.store.submit(
            spg,
            &peering::StoreTxn {
                ops: vec![peering::StoreOp::ApplyTxn {
                    middle: Default::default(),
                    data: data.into(),
                }],
            },
        );
        Ok(format!("flipped byte {off} of {oid} in {spg}"))
    }
}

pub(crate) fn parse_pgid(s: &str) -> Option<PgT> {
    let (pool, seed) = s.split_once('.')?;
    Some(PgT::new(
        pool.parse().ok()?,
        u32::from_str_radix(seed, 16).ok()?,
    ))
}

/// `interval_set<snapid>` as classic dumps it in JSON: `[{"start":"3","length":"1"}]` (hex strings).
fn ivs_json(s: &std::collections::BTreeMap<u64, u64>) -> serde_json::Value {
    s.iter()
        .map(|(a, l)| serde_json::json!({"start": format!("{a:x}"), "length": format!("{l:x}")}))
        .collect::<Vec<_>>()
        .into()
}

pub fn info_json(i: &pgwire::PgInfo, empty: bool) -> serde_json::Value {
    let h = &i.history;
    serde_json::json!({
        "pgid": i.pgid.to_string(),
        "last_update": i.last_update.to_string(),
        "last_complete": i.last_complete.to_string(),
        "log_tail": i.log_tail.to_string(),
        "last_user_version": i.last_user_version,
        "last_backfill": if i.last_backfill.max { "MAX" } else { "MIN" },
        "purged_snaps": ivs_json(&i.purged_snaps),
        "history": {
            "epoch_created": h.epoch_created,
            "epoch_pool_created": h.epoch_pool_created,
            "last_epoch_started": h.last_epoch_started,
            "last_interval_started": h.last_interval_started,
            "last_epoch_clean": h.last_epoch_clean,
            "last_interval_clean": h.last_interval_clean,
            "last_epoch_split": h.last_epoch_split,
            "last_epoch_marked_full": h.last_epoch_marked_full,
            "same_up_since": h.same_up_since,
            "same_interval_since": h.same_interval_since,
            "same_primary_since": h.same_primary_since,
            "last_scrub": h.last_scrub.to_string(),
            "last_scrub_stamp": utime_str(h.last_scrub_stamp),
            "last_deep_scrub": h.last_deep_scrub.to_string(),
            "last_deep_scrub_stamp": utime_str(h.last_deep_scrub_stamp),
            "last_deep_scrub_start_stamp": utime_str(h.last_deep_scrub_start_stamp),
            "last_clean_scrub_stamp": utime_str(h.last_clean_scrub_stamp),
            // pg_history_t v11 (21.2.0): upstream appends them after prior_readable_until_ub
            "last_degraded": utime_str(h.last_degraded),
            "last_clean": utime_str(h.last_clean),
            "vuln_window_reported": utime_str(h.vuln_window_reported),
            "last_rebuild_active_start": utime_str(h.last_rebuild_active_start),
            "rebuild_span_reported": utime_str(h.rebuild_span_reported),
            "rebuild_active_accum": utime_str(h.rebuild_active_accum),
        },
        "stats": stat_json(&i.stats),
        "empty": i32::from(empty),
        "dne": 0,
        "incomplete": 0,
        "last_epoch_started": i.last_epoch_started,
        "hit_set_history": {"current_last_update": "0'0", "history": []},
    })
}

pub(crate) fn stat_json(s: &pgwire::PgStat) -> serde_json::Value {
    let sum = &s.stats.sum;
    let mut a = serde_json::json!({
        "version": s.version.to_string(),
        "reported_seq": s.reported_seq,
        "reported_epoch": s.reported_epoch,
        "state": pgwire::state::state_string(s.state),
        "last_fresh": utime_str(s.last_fresh),
        "last_change": utime_str(s.last_change),
        "last_active": utime_str(s.last_active),
        "last_peered": utime_str(s.last_peered),
        "last_clean": utime_str(s.last_clean),
        "last_became_active": utime_str(s.last_became_active),
        "last_became_peered": utime_str(s.last_became_peered),
        "last_unstale": utime_str(s.last_unstale),
        "last_undegraded": utime_str(s.last_undegraded),
        "last_fullsized": utime_str(s.last_fullsized),
        "mapping_epoch": s.mapping_epoch,
        "log_start": s.log_start.to_string(),
        "ondisk_log_start": s.ondisk_log_start.to_string(),
        "created": s.created,
        "last_epoch_clean": s.last_epoch_clean,
        "last_scrub": s.last_scrub.to_string(),
        "last_scrub_stamp": utime_str(s.last_scrub_stamp),
        "last_deep_scrub": s.last_deep_scrub.to_string(),
        "last_deep_scrub_stamp": utime_str(s.last_deep_scrub_stamp),
        "last_deep_scrub_start_stamp": utime_str(s.last_deep_scrub_start_stamp),
        "last_clean_scrub_stamp": utime_str(s.last_clean_scrub_stamp),
        "objects_scrubbed": s.objects_scrubbed,
        "log_size": s.log_size,
        "log_dups_size": s.log_dups_size,
        "ondisk_log_size": s.ondisk_log_size,
        "stats_invalid": s.stats_invalid,
        "dirty_stats_invalid": s.dirty_stats_invalid,
        "omap_stats_invalid": s.omap_stats_invalid,
        "hitset_stats_invalid": s.hitset_stats_invalid,
        "hitset_bytes_stats_invalid": s.hitset_bytes_stats_invalid,
        "pin_stats_invalid": s.pin_stats_invalid,
        "manifest_stats_invalid": s.manifest_stats_invalid,
        "snaptrimq_len": s.snaptrimq_len,
        "objects_trimmed": s.objects_trimmed,
        "snaptrim_duration": s.snaptrim_duration,
        "last_scrub_duration": s.last_scrub_duration,
        "scrub_schedule": s.scrub_sched_status,
    });
    let b = serde_json::json!({
        "stat_sum": {
            "num_bytes": sum.num_bytes,
            "num_objects": sum.num_objects,
            "num_object_copies": sum.num_object_copies,
            "num_objects_missing_on_primary": sum.num_objects_missing_on_primary,
            "num_objects_degraded": sum.num_objects_degraded,
            "num_objects_misplaced": sum.num_objects_misplaced,
            "num_objects_unfound": sum.num_objects_unfound,
            "num_omap_bytes": sum.num_omap_bytes,
            "num_omap_keys": sum.num_omap_keys,
            "num_large_omap_objects": sum.num_large_omap_objects,
            "num_scrub_errors": sum.num_scrub_errors,
            "num_shallow_scrub_errors": sum.num_shallow_scrub_errors,
            "num_deep_scrub_errors": sum.num_deep_scrub_errors,
        },
        "up": s.up,
        "acting": s.acting,
        "avail_no_missing": [],
        "object_location_counts": [],
        "blocked_by": s.blocked_by,
        "up_primary": s.up_primary,
        "acting_primary": s.acting_primary,
        "purged_snaps": ivs_json(&s.purged_snaps),
    });
    if let (Some(a), Some(b)) = (a.as_object_mut(), b.as_object()) {
        a.extend(b.clone());
    }
    a
}

impl<B: Backend> Osd<B> {
    /// `pg <pgid> query` (classic JSON shape, what tooling reads: state, epoch, up/acting, info, peer_info,
    /// recovery_state).
    pub(crate) fn pg_query(&self, pgid: &str) -> crate::tell::Res {
        let Some(pg) = parse_pgid(pgid) else {
            return (
                -errno::EINVAL,
                format!("invalid pgid '{pgid}'"),
                Default::default(),
            );
        };
        let Some((_, p)) = self.pg.set.pgs().find(|(s, _)| s.pgid == pg) else {
            return (
                -errno::ENOENT,
                format!("i don't have pgid {pgid}"),
                Default::default(),
            );
        };
        let primary = p.is_primary();
        let peers: Vec<serde_json::Value> = p
            .peer_infos()
            .map(|(osd, i)| {
                let mut j = info_json(i, false);
                if let Some(o) = j.as_object_mut() {
                    o.remove("stats");
                }
                j["peer"] = serde_json::json!(osd.to_string());
                j
            })
            .collect();
        let enter = utime_str(p.info().stats.last_change);
        let mut rs = vec![];
        let machine = format!("{:?}", p.machine_state());
        let name = if !primary {
            "Started/Stray".to_owned()
        } else if p.is_active() {
            "Started/Primary/Active".to_owned()
        } else {
            format!("Started/Primary/Peering ({machine})")
        };
        let mut st = serde_json::json!({"name": name, "enter_time": enter});
        if primary && p.is_active() {
            st["might_have_unfound"] = serde_json::json!([]);
            st["recovery_progress"] = serde_json::json!({
                "backfill_targets": [], "waiting_on_backfill": [],
                "last_backfill_started": "MIN", "backfill_info": {}, "peer_backfill_info": [],
                "backfills_in_flight": [], "recovering": [], "pg_backend": {}});
            st["scrub"] = serde_json::json!({
                "scrubber.epoch_start": "0", "scrubber.active": p.scrub_running(),
                "scrubber.state": if p.scrub_running() { "ACTIVE" } else { "INACTIVE" },
                "scrubber.waiting_on": 0, "scrubber.waiting_on_whom": []});
            if let Some((osd, epoch)) = p.refused_full() {
                st["refused_full"] = serde_json::json!({"osd": osd, "epoch": epoch});
            }
        }
        if p.repops_held() > 0 {
            // replica: messages held behind a repop whose omap range removal is counted ahead (adr 0021 am. 25)
            st["repops_held"] = serde_json::json!(p.repops_held());
        }
        rs.push(st);
        rs.push(serde_json::json!({"name": "Started", "enter_time": enter}));
        let bf: Vec<String> = if primary {
            p.acting().iter().map(|o| o.to_string()).collect()
        } else {
            Vec::new()
        };
        let mut own = info_json(p.info(), p.info().last_update == Default::default());
        let mut s = p.info().stats.clone();
        let h = &p.info().history;
        s.state = p.state_bits();
        (s.last_scrub, s.last_scrub_stamp, s.last_deep_scrub) =
            (h.last_scrub, h.last_scrub_stamp, h.last_deep_scrub);
        (s.last_deep_scrub_stamp, s.last_clean_scrub_stamp) =
            (h.last_deep_scrub_stamp, h.last_clean_scrub_stamp);
        s.last_deep_scrub_start_stamp = h.last_deep_scrub_start_stamp;
        (s.up, s.acting) = (p.up().to_vec(), p.acting().to_vec());
        s.purged_snaps = peering::snaps::iv_head(&p.info().purged_snaps, 512);
        s.snaptrimq_len = u32::try_from(p.snap_trimq_len()).unwrap_or(u32::MAX);
        own["stats"] = stat_json(&s);
        let q = serde_json::json!({
            "snap_trimq": peering::snaps::iv_text(p.snap_trimq()),
            "snap_trimq_len": p.snap_trimq_len(),
            "state": p.state_string(),
            "epoch": p.map_epoch(),
            "up": p.up(),
            "acting": p.acting(),
            "acting_recovery_backfill": bf,
            "info": own,
            "peer_info": peers,
            "recovery_state": rs,
            "agent_state": {},
        });
        Self::ok(q)
    }

    /// Sum of the omap bytes of the hosted PGs as last measured by deep scrub (the store keeps no omap
    /// accounting of its own).
    pub(crate) fn pg_omap_bytes_local(&self) -> i64 {
        self.pg
            .set
            .pgs()
            .map(|(_, p)| p.info().stats.stats.sum.num_omap_bytes.max(0))
            .sum()
    }

    /// `(pool, data bytes, compressed physical bytes, compressed logical bytes)` over this core's PGs.
    /// Data = what this OSD's store holds for the PG (an EC shard holds ~1/k, a backfill target what it has received so
    /// far): the mgr divides the sum over all OSDs by the pool's raw-used rate (size, (k+m)/k). OMAP is reported separately
    /// through primary PG deep-scrub stats: the store has no per-collection OMAP allocation estimator.
    pub(crate) fn pg_pool_bytes_local(&self) -> Vec<PoolBytes> {
        let mut m: std::collections::BTreeMap<i64, [i64; 3]> = Default::default();
        for (s, _) in self.pg.set.pgs() {
            let (_, b) = self.pg.store.object_stats(*s);
            let (cp, co) = self.pg.store.compress_stats(*s);
            let e = m.entry(s.pgid.pool as i64).or_default();
            e[0] += b as i64;
            e[1] += cp as i64;
            e[2] += co as i64;
        }
        m.into_iter().map(|(k, v)| (k, v[0], v[1], v[2])).collect()
    }

    /// Per-pool statfs of the whole OSD (all cores) for MPGStats. Classic semantics (`ceph df`): STORED = (data_stored +
    /// omap_allocated) / rate, USED = allocated + omap_allocated. OMAP allocation is unavailable (zero); the OSD report
    /// disables per-pool OMAP so the mgr falls back to primary PG scrub totals. Data allocation = data_stored.
    pub(crate) fn pg_pool_statfs(&self) -> std::collections::BTreeMap<i64, messages::StoreStatfs> {
        let mut m: std::collections::BTreeMap<i64, [i64; 3]> = Default::default();
        for (k, b, cp, co) in self.pg_pool_bytes_local().into_iter().chain(
            self.cl
                .stats
                .iter()
                .flatten()
                .flat_map(|s| s.pool_bytes.iter().copied()),
        ) {
            let e = m.entry(k).or_default();
            e[0] += b;
            e[1] += cp;
            e[2] += co;
        }
        m.into_iter()
            .map(|(k, [b, cp, co])| (k, pool_statfs(b, cp, co)))
            .collect()
    }

    /// [`Self::pg_omap_bytes_local`] over all cores.
    pub(crate) fn pg_omap_bytes(&self) -> i64 {
        self.pg_omap_bytes_local() + self.cl.stats.iter().flatten().map(|s| s.omap).sum::<i64>()
    }

    /// Background PG deletion over all cores: `(PGs queued, objects left (estimate), objects deleted since start, objects/s)`.
    pub(crate) fn pg_removal_totals(&self) -> (u64, u64, u64, u64) {
        let mut t = (0, 0, 0, 0);
        let own = (self.pg.store.removal_progress(), self.pg.del.rate);
        for (p, rate) in
            std::iter::once(&own).chain(self.cl.stats.iter().flatten().map(|s| &s.removal))
        {
            t.0 += u64::from(p.pgs);
            t.1 += p.objs_left;
            t.2 += p.objs_done;
            t.3 += rate;
        }
        t
    }

    /// `(total, primary, replica)` PG counts (all cores).
    pub(crate) fn pg_role_counts(&self) -> (u64, u64, u64) {
        let (mut n, mut pr) = (0u64, 0u64);
        for (_, p) in self.pg.set.pgs() {
            n += 1;
            pr += u64::from(p.is_primary());
        }
        for s in self.cl.stats.iter().flatten() {
            n += u64::from(s.num_pgs);
            pr += s.primary_pgs.len() as u64;
        }
        (n, pr, n - pr)
    }
}

/// Options the compression observer re-reads: the store-wide dedup settings, the deep-scrub reformat engines and the
/// OSD-wide `bluestore_compression_*` fallbacks of pools without their own (spec osd-lifecycle.md 9.2).
pub(crate) const COMPRESSION_KEYS: &[&str] = &[
    "flashstore_dedup_digest",
    "flashstore_dedup_zero_objects",
    "flashstore_deep_scrub_reformat",
    "bluestore_compression_mode",
    "bluestore_compression_algorithm",
    "bluestore_compression_required_ratio",
    "bluestore_compression_min_blob_size",
    "bluestore_compression_min_blob_size_ssd",
    "bluestore_compression_max_blob_size",
    "bluestore_compression_max_blob_size_ssd",
];

/// Options the scrub observer re-reads: the scrub window, chunking, thresholds, reservations, snap trimming, PG log
/// sizing, stats and recovery pacing (spec scrub.md, peering.md).
pub(crate) const SCRUB_CFG_KEYS: &[&str] = &[
    "osd_scrub_min_interval",
    "osd_deep_scrub_interval",
    "osd_scrub_interval_randomize_ratio",
    "osd_deep_scrub_interval_cv",
    "osd_scrub_load_threshold",
    "osd_scrub_begin_hour",
    "osd_scrub_end_hour",
    "osd_scrub_begin_week_day",
    "osd_scrub_end_week_day",
    "osd_scrub_during_recovery",
    "osd_scrub_backoff_ratio",
    "osd_scrub_invalid_stats",
    "osd_scrub_priority",
    "osd_scrub_chunk_min",
    "osd_scrub_chunk_max",
    "osd_scrub_sleep",
    "flashstore_scrub_slice_bytes",
    "osd_shallow_scrub_chunk_min",
    "osd_shallow_scrub_chunk_max",
    "osd_scrub_max_preemptions",
    "flashstore_scrub_operator_limits",
    "flashstore_dedup_list",
    "osd_scrub_auto_repair",
    "osd_scrub_auto_repair_num_errors",
    "osd_max_object_size",
    "osd_deep_scrub_large_omap_object_key_threshold",
    "osd_deep_scrub_large_omap_object_value_sum_threshold",
    "osd_snap_trim_sleep",
    "osd_snap_trim_sleep_ssd",
    "osd_max_trimming_pgs",
    "osd_pg_max_concurrent_snap_trims",
    "flashstore_delete_log_s",
    "osd_max_backfills",
    "osd_recovery_max_active",
    "osd_recovery_max_active_hdd",
    "osd_recovery_max_active_ssd",
    "osd_min_recovery_priority",
    "osd_max_scrubs",
    "osd_heartbeat_grace",
    "osd_pool_default_read_lease_ratio",
    "osd_min_pg_log_entries",
    "osd_max_pg_log_entries",
    "osd_pg_log_trim_min",
    "osd_pg_log_trim_max",
    "osd_target_pg_log_entries_per_osd",
    "osd_pg_log_dups_tracked",
    "mon_max_pg_per_osd",
    "osd_max_pg_per_osd_hard_ratio",
    "osd_pg_stat_report_interval_max_seconds",
    "osd_pg_stat_report_interval_max_epochs",
    "osd_recovery_max_chunk",
    "osd_backfill_scan_min",
    "osd_backfill_scan_max",
    "osd_deep_scrub_stride",
    "osd_deep_scrub_keys",
    "osd_map_cache_size",
    "osd_map_share_max_epochs",
    "osd_map_message_max",
    "osd_recovery_op_priority",
    "osd_op_queue",
    "osd_max_push_objects",
    "osd_max_push_cost",
    "osd_recovery_retry_interval",
    "osd_backfill_retry_interval",
    "osd_recovery_sleep",
    "osd_recovery_sleep_hdd",
    "osd_recovery_sleep_ssd",
    "osd_recovery_sleep_hybrid",
    "osd_recovery_sleep_degraded",
    "osd_recovery_sleep_degraded_hdd",
    "osd_recovery_sleep_degraded_ssd",
    "osd_recovery_sleep_degraded_hybrid",
    "osd_allow_recovery_below_min_size",
    "flashstore_peering_trace_ms",
];

impl<B: Backend> Osd<B> {
    /// `bluestore_compression_*` changed: hand the pools' effective options to the store again.
    pub(crate) fn pg_reapply_compression(&mut self) {
        if let Some(m) = self.osdmap().cloned() {
            self.pg_apply_compression(&m);
        }
    }

    /// Classic with the mclock scheduler and no `osd_mclock_override_recovery_settings`: a changed recovery option is
    /// removed from the mon config again and the cluster log says it "did not take effect"; the QoS default stays
    /// ([`crate::config::ConfigDb::recovery_limits`]). Runs with every config change; the first call only records.
    pub(crate) fn recovery_qos_guard(&mut self) {
        let now: BTreeMap<String, String> = crate::config::RECOVERY_QOS_KEYS
            .iter()
            .map(|k| ((*k).to_owned(), self.conf.get(k).unwrap_or("").to_owned()))
            .collect();
        let prev = std::mem::replace(&mut self.qos_seen, now.clone());
        if prev.is_empty() || !self.conf.recovery_qos_gated() {
            return;
        }
        for (k, v) in &now {
            let is_default = crate::config::DEFAULTS
                .iter()
                .any(|(dk, dv)| dk == k && dv == v);
            if prev.get(k) == Some(v) || is_default {
                continue;
            }
            for who in ["osd".to_owned(), format!("osd.{}", self.id.whoami)] {
                let c = format!(r#"{{"prefix":"config rm","who":"{who}","name":"{k}"}}"#);
                self.mc.send_command(&c, Vec::new());
            }
            let m = format!(
                "Change to {k} on osd.{} did not take effect. Enable osd_mclock_override_recovery_settings before setting this option.",
                self.id.whoami
            );
            self.clog(messages::clog::WARN, &m);
        }
    }

    pub(crate) fn pg_apply_scrub_cfg(&mut self) {
        let c = &self.conf;
        let s = self.pg.set.scrub_cfg_mut();
        // out-of-range window values are ignored (kept), like classic's option range check (0..=23 / 0..=6)
        let hour = |v: u64, cur: u32| if v < 24 { v as u32 } else { cur };
        let day = |v: u64, cur: u32| if v < 7 { v as u32 } else { cur };
        s.min_interval = c.f64("osd_scrub_min_interval", s.min_interval);
        s.deep_interval = c.f64("osd_deep_scrub_interval", s.deep_interval);
        s.randomize_ratio = c.f64("osd_scrub_interval_randomize_ratio", s.randomize_ratio);
        s.deep_interval_cv = c
            .f64("osd_deep_scrub_interval_cv", s.deep_interval_cv)
            .max(0.0);
        s.load_threshold = c.f64("osd_scrub_load_threshold", s.load_threshold);
        s.begin_hour = hour(
            c.u64("osd_scrub_begin_hour", u64::from(s.begin_hour)),
            s.begin_hour,
        );
        s.end_hour = hour(
            c.u64("osd_scrub_end_hour", u64::from(s.end_hour)),
            s.end_hour,
        );
        s.begin_week_day = day(
            c.u64("osd_scrub_begin_week_day", u64::from(s.begin_week_day)),
            s.begin_week_day,
        );
        s.end_week_day = day(
            c.u64("osd_scrub_end_week_day", u64::from(s.end_week_day)),
            s.end_week_day,
        );
        s.during_recovery = c.bool("osd_scrub_during_recovery", s.during_recovery);
        s.backoff_ratio = c
            .f64("osd_scrub_backoff_ratio", s.backoff_ratio)
            .clamp(0.0, 1.0);
        s.invalid_stats = c.bool("osd_scrub_invalid_stats", s.invalid_stats);
        s.priority = c
            .u64("osd_scrub_priority", s.priority.max(0) as u64)
            .min(i32::MAX as u64) as i32;
        s.chunk_min = c.u64("osd_scrub_chunk_min", s.chunk_min as u64) as usize;
        s.chunk_max = c.u64("osd_scrub_chunk_max", s.chunk_max as u64) as usize;
        s.sleep = (c.f64("osd_scrub_sleep", 0.0).max(0.0) * 1e9) as u64;
        s.slice_bytes = c
            .u64("flashstore_scrub_slice_bytes", s.slice_bytes)
            .max(store::BLK as u64);
        s.shallow_chunk_min =
            c.u64("osd_shallow_scrub_chunk_min", s.shallow_chunk_min as u64) as usize;
        s.shallow_chunk_max =
            c.u64("osd_shallow_scrub_chunk_max", s.shallow_chunk_max as u64) as usize;
        s.max_preemptions = c
            .u64("osd_scrub_max_preemptions", u64::from(s.max_preemptions))
            .min(30) as u32;
        s.operator_limits = c.bool("flashstore_scrub_operator_limits", s.operator_limits);
        s.dedup_start_stamp = c.bool("flashstore_dedup_list", s.dedup_start_stamp);
        s.auto_repair = c.bool("osd_scrub_auto_repair", s.auto_repair);
        s.auto_repair_num_errors =
            c.u64("osd_scrub_auto_repair_num_errors", s.auto_repair_num_errors);
        s.max_object_size = c.u64("osd_max_object_size", s.max_object_size);
        s.large_omap_keys = c.u64(
            "osd_deep_scrub_large_omap_object_key_threshold",
            s.large_omap_keys,
        );
        s.large_omap_bytes = c.u64(
            "osd_deep_scrub_large_omap_object_value_sum_threshold",
            s.large_omap_bytes,
        );
        // snap trimmer: osd_snap_trim_sleep overrides the per-media variant (we are all-flash: the ssd one)
        let sleep = c.f64("osd_snap_trim_sleep", 0.0);
        let sleep = if sleep > 0.0 {
            sleep
        } else {
            c.f64("osd_snap_trim_sleep_ssd", 0.0)
        };
        let (maxp, conc) = (
            c.u64("osd_max_trimming_pgs", 2) as usize,
            c.u64("osd_pg_max_concurrent_snap_trims", 2) as usize,
        );
        self.pg
            .set
            .set_snap_trim(maxp, conc, (sleep.max(0.0) * 1e9) as u64);
        self.pg.del.log_every = Duration::from_secs(c.u64("flashstore_delete_log_s", 10).max(1));
        // replica-side reservation slots: `osd_max_backfills` (was hard-wired to 1; the central/lab value never reached the reserver)
        let lim = c.recovery_limits();
        self.pg.set.set_max_backfills(lim.max_backfills);
        // recovery ops in flight, OSD-wide (the owner core keeps the limit, adr 0031 am. 10) and the reservers' minimum priority
        self.pg.set.set_recovery_max_active(lim.recovery_max_active);
        self.pg.set.set_recovery_message_priority(
            c.get("osd_op_queue") == Some("mclock_scheduler"),
            c.u64("osd_recovery_op_priority", 3)
                .min(u64::from(u16::MAX)) as u16,
        );
        self.pg.set.set_min_recovery_priority(lim.min_priority);
        // local (primary) and replica scrub slots (was hard-wired to 3; the configured value never reached them)
        let ms = c.u64("osd_max_scrubs", 3) as usize;
        self.pg.set.set_max_scrubs(ms);
        // read lease (classic: grace x ratio, recomputed with every map; a pool option overrides it in the PG)
        let lease =
            c.f64("osd_heartbeat_grace", 20.0) * c.f64("osd_pool_default_read_lease_ratio", 0.8);
        let lease_ns = peering::types::lease_ns(lease);
        self.pg.set.set_readable_interval(lease_ns);
        // per-OSD PG hard limit, read at every create like classic (peering.md 7.3 rule 3a)
        self.pg.set.set_pg_hard_limit(
            c.u64("mon_max_pg_per_osd", 500) as f64 * c.f64("osd_max_pg_per_osd_hard_ratio", 3.0),
        );
        // PG log sizing, stats re-publish bounds, recovery chunk: read at use like classic (runtime changes apply)
        let d = peering::PgLogCfg::default();
        self.pg.set.set_pg_log(peering::PgLogCfg {
            min_entries: c.u64("osd_min_pg_log_entries", d.min_entries),
            max_entries: c.u64("osd_max_pg_log_entries", d.max_entries),
            trim_min: c.u64("osd_pg_log_trim_min", d.trim_min),
            trim_max: c.u64("osd_pg_log_trim_max", d.trim_max),
            target_per_osd: c.u64("osd_target_pg_log_entries_per_osd", d.target_per_osd),
            dups_tracked: c.u64("osd_pg_log_dups_tracked", d.dups_tracked),
        });
        let secs = c
            .f64("osd_pg_stat_report_interval_max_seconds", 5.0)
            .max(0.0);
        let epochs = c
            .f64("osd_pg_stat_report_interval_max_epochs", 500.0)
            .max(0.0);
        self.pg.set.set_stats_report(
            (secs * 1e9) as u64,
            epochs.min(f64::from(u32::MAX)) as u32,
            c.u64("osd_recovery_max_chunk", 8 << 20),
        );
        // deep scrub read sizes of this core's store (classic ReplicatedBackend::be_deep_scrub)
        self.pg.store.set_deep_scrub_reads(
            c.u64("osd_deep_scrub_stride", 4 << 20),
            c.u64("osd_deep_scrub_keys", 1024),
        );
        // objects per backfill scan (classic do_scan / scan_range), maps kept in memory, epochs per map share
        self.pg.set.set_backfill_scan(
            c.u64("osd_backfill_scan_min", 64),
            c.u64("osd_backfill_scan_max", 512),
        );
        self.pg
            .set
            .set_map_cache(c.u64("osd_map_cache_size", 50).min(u64::from(u32::MAX)) as u32);
        self.pg.map_share = c
            .u64("osd_map_share_max_epochs", 40)
            .min(c.u64("osd_map_message_max", 40))
            .min(u64::from(u32::MAX)) as u32;
        // objects / cost per recovery push and recovery delete message (spec replication.md 6.3, 6.5)
        self.pg.set.set_push_cfg(
            c.u64("osd_max_push_objects", 10),
            c.u64("osd_max_push_cost", 8 << 20),
        );
        // reservation retry pacing (osd_recovery_retry_interval / osd_backfill_retry_interval) and the recovery/
        // backfill sleep pace (osd_recovery_sleep*, zeroed by mclock in ConfigDb)
        let retry = |k: &str| (c.f64(k, 30.0).max(0.0) * 1e9) as u64;
        self.pg.set.set_retry_intervals(
            retry("osd_recovery_retry_interval"),
            retry("osd_backfill_retry_interval"),
        );
        let (sleep, sleep_deg) = c.recovery_sleep_ns();
        self.pg.set.set_recovery_sleep(sleep, sleep_deg);
        self.pg
            .set
            .set_allow_recovery_below_min_size(c.bool("osd_allow_recovery_below_min_size", true));
        // dev escape: the required past-interval bounds check (peering.md 3.8)
        self.pg
            .set
            .set_skip_past_bounds_check(c.bool("osd_skip_check_past_interval_bounds", false));
        let pt = c.u64("flashstore_peering_trace_ms", 0);
        self.pg.set.set_peer_trace_ms(pt);
        self.pg.set.set_tick_diag(self.pg.wake_diag);
        self.pg.set.push_cfg_to_pgs();
        if lease_ns == peering::types::MAX_READABLE_INTERVAL && self.is_control() {
            self.logl(
                0,
                format!(
                    "WARNING read lease osd_heartbeat_grace x osd_pool_default_read_lease_ratio = {lease} s is not representable; using {} s",
                    peering::types::MAX_READABLE_INTERVAL / peering::types::SEC
                ),
            );
        }
        // a runtime change of the dev escape releases the PGs the bounds check stopped (peering.md 3.8)
        let now = self.pg_mono();
        let acts = self.pg.set.recheck_past_bounds(now, &self.pg.store);
        self.pg_exec(acts);
        self.pg_apply_ec_cfg();
    }

    /// Background PG deletion progress: a log line every `log_every` while it runs (objects left, objects/s).
    fn pg_delete_progress(&mut self, now: Duration) {
        let p = self.pg.store.removal_progress();
        if p.pgs == 0 {
            if self.pg.del.active() {
                self.log(format!(
                    "pg deletion finished: {} objects deleted by this core since start",
                    p.objs_done
                ));
                self.pg.del.reset();
            }
            return;
        }
        if let Some((secs, n)) = self.pg.del.sample(now, p.objs_done) {
            let rate = self.pg.del.rate;
            let eta = p.objs_left.checked_div(rate).unwrap_or(0);
            self.log(format!(
                "pg deletion: {} PGs queued, ~{} objects left, {rate} objects/s ({n} in {secs:.0} s), eta ~{eta} s",
                p.pgs, p.objs_left
            ));
        }
    }

    /// EC shard role (adr 0039): kill switches from the config; a change loads / forgets the PGs of the
    /// pools affected. At start and on every runtime config change (`tell::conf_changed`).
    pub(crate) fn pg_apply_ec_cfg(&mut self) {
        let prim = self.conf.bool("ec_enable_primary", true);
        self.pg.set.set_ec_primary(prim);
        let decl = self.conf.bool("ec_decline_unsupported", true);
        self.pg.set.set_ec_decline(decl);
        // mode O primary (adr 0067 am. 10, plan S2): own switch, default on; needs ec_enable_primary too
        let opt_prim = prim && self.conf.bool("ec_enable_optimized_primary", true);
        self.pg.set.set_ec_opt_primary(opt_prim);
        let pdw = self.conf.get("ec_pdw").unwrap_or("off");
        if !self.pg.set.set_ec_pdw(pdw) {
            self.logl(
                0,
                format!(
                    "WARNING config: invalid ec_pdw value '{pdw}' (off | auto | always); \
                     keeping the current mode"
                ),
            );
        }
        let defer = self.conf.u64("ec_rollforward_defer_us", 20_000);
        self.pg.set.set_ec_rf_defer_us(defer);
        // PGs loaded before this (worker core boot order, runtime change) hold their own cfg copy: push the switches
        self.pg.set.push_cfg_to_pgs();
        let (en, opt) = self.ec_enables();
        let now = self.pg_mono();
        let cur = (
            decl,
            self.conf.get("ec_enable_pools").unwrap_or("off").to_owned(),
            self.conf
                .get("ec_enable_optimized")
                .unwrap_or("all")
                .to_owned(),
        );
        if self.is_control()
            && let Some(prev) = self.pg.ec_cfg_prev.replace(cur.clone())
            && prev != cur
        {
            self.pg_queue_repeers(&prev);
        }
        let acts = self.pg.set.set_ec_enables(now, en, opt, &self.pg.store);
        self.pg_exec(acts);
    }

    /// `tell status` rows of every erasure pool of the map: the support gate verdict, whether this OSD serves it
    /// (verdict + `ec_enable_pools`) and why not.
    pub(crate) fn pg_ec_pools(&self) -> Vec<serde_json::Value> {
        let Some(map) = self.map.as_ref() else {
            return vec![];
        };
        let (en, opt) = self.ec_enables();
        let decline = self.conf.bool("ec_decline_unsupported", true);
        map.pools
            .iter()
            .filter(|(id, p)| **id >= 0 && p.is_erasure())
            .map(|(id, p)| {
                let info = peering::map::ec_pool_info(map, p).unwrap_or_default();
                let name = map.pool_name.get(id).cloned().unwrap_or_default();
                let why = peering::map::ec_not_served(&info, &en, &opt, *id as u64, &name);
                let mode = self.ec_pool_mode(&info, &en, &opt, decline, *id as u64, &name);
                serde_json::json!({
                    "pool": id,
                    "mode": mode,
                    "name": name.to_string(),
                    "profile": p.erasure_code_profile,
                    "supported": info.supported,
                    "ec_mode": if !info.supported {
                        ""
                    } else if info.optimized {
                        "optimized"
                    } else if info.overwrites {
                        "overwrites"
                    } else {
                        "append"
                    },
                    "serves": why.is_none(),
                    "reason": why.unwrap_or_default(),
                })
            })
            .collect()
    }

    /// adr 0039 am. 1: serve = shard role; decline = empty shard that refuses backfill; passive = silent.
    fn ec_pool_mode(
        &self,
        info: &pgwire::EcPoolInfo,
        en: &ec::EcEnable,
        opt: &ec::EcEnable,
        decline: bool,
        id: u64,
        name: impl AsRef<[u8]>,
    ) -> &'static str {
        if peering::map::ec_not_served(info, en, opt, id, name.as_ref()).is_none() {
            "serve"
        } else if decline
            && peering::map::ec_declinable(info, opt, id, name.as_ref())
            && !self.pg.set.holds_pool(id)
        {
            "decline"
        } else {
            "passive"
        }
    }

    /// OQ 30b: PGs of a declined pool that this OSD leads would stay unknown (a classic primary in our place asks for a
    /// pg_temp without its incomplete self). Do the same: pg_temp = acting with our shard position empty, so the next member
    /// leads and treats us as the backfill target we decline. Re-sent on every map while we still lead (the mon may drop it).
    fn pg_decline_lead_temps(&mut self, map: &OsdMap, pool_id: u64, pool: &osdmap::pool::PgPool) {
        let me = self.id.whoami;
        let mut temps: BTreeMap<PgT, Vec<i32>> = BTreeMap::new();
        for seed in 0..pool.pg_num {
            let pg = PgT::new(pool_id, seed);
            let m = map.pg_to_up_acting(pg);
            if m.acting_primary != me || m.acting.len() != pool.size as usize {
                continue;
            }
            let want: Vec<i32> = m
                .acting
                .iter()
                .map(|o| if *o == me { pgwire::NONE_OSD } else { *o })
                .collect();
            if want.iter().any(|o| *o >= 0) {
                temps.insert(pg, want);
            }
        }
        if temps.is_empty() {
            return;
        }
        self.log(format!(
            "declined EC pool {pool_id}: leading {} PG(s) in the acting set, requesting pg_temp without this OSD",
            temps.len()
        ));
        self.send_pg_temp(temps);
    }

    /// Ask the mon for `temps` (empty set = clear). The PSM version is the osdmap epoch like classic: the mon answers
    /// with incrementals from there (version 0 would make it send a whole map).
    pub(crate) fn send_pg_temp(&mut self, temps: BTreeMap<PgT, Vec<i32>>) {
        let map_epoch = self.epoch();
        self.mon_out(
            MOSDPGTemp {
                version: u64::from(map_epoch),
                map_epoch,
                pg_temp: temps,
                forced: false,
            }
            .into(),
        );
    }

    /// A runtime change of the EC switches (`prev` = the values before): a classic primary does not re-query a peer whose
    /// answer changed inside an interval (it waits in GetInfo, or sees a backfill target), so queue `pg repeer` for every PG
    /// of a pool whose mode (serve / decline / passive) flipped that maps to us as a non-primary (adr 0039 am. 3, OQ 30c).
    fn pg_queue_repeers(&mut self, prev: &(bool, String, String)) {
        let Some(map) = self.map.clone() else {
            return;
        };
        let me = self.id.whoami;
        let old = (ec::EcEnable::parse(&prev.1), ec::EcEnable::parse(&prev.2));
        let (en, opt) = self.ec_enables();
        let decline = self.conf.bool("ec_decline_unsupported", true);
        let mut lead_temps: BTreeMap<PgT, Vec<i32>> = BTreeMap::new();
        let mut n = 0;
        for (id, p) in map
            .pools
            .iter()
            .filter(|(id, p)| **id >= 0 && p.is_erasure())
        {
            let info = peering::map::ec_pool_info(&map, p).unwrap_or_default();
            let name = map.pool_name.get(id).cloned().unwrap_or_default();
            let pool = *id as u64;
            if self.ec_pool_mode(&info, &old.0, &old.1, prev.0, pool, &name)
                == self.ec_pool_mode(&info, &en, &opt, decline, pool, &name)
            {
                continue;
            }
            for seed in 0..p.pg_num {
                let pg = PgT::new(pool, seed);
                let m = map.pg_to_up_acting(pg);
                if m.acting_primary == me {
                    // led here: no classic primary will re-query us and a PG we never created gets no notify before a
                    // new interval; ask for one (pg_temp = only us at our shard position, as `Pg::ec_lead_switch_on`)
                    if self.ec_pool_mode(&info, &en, &opt, decline, pool, &name) == "serve"
                        && let Some(want) = lead_only_us(&m.acting, me, p.size as usize)
                    {
                        lead_temps.insert(pg, want);
                    }
                } else if m.up.contains(&me) || m.acting.contains(&me) {
                    self.pg.repeer_q.push_back(pg.to_string());
                    n += 1;
                }
            }
        }
        if !lead_temps.is_empty() {
            self.log(format!(
                "EC switches changed at runtime: leading {} PG(s) of pools that are served now, requesting a new interval (pg_temp)",
                lead_temps.len()
            ));
            self.send_pg_temp(lead_temps);
        }
        if n > 0 {
            self.log(format!(
                "EC switches changed at runtime: {n} PG(s) of pools whose mode flipped get `pg repeer` (classic primaries do not re-query)"
            ));
        }
    }

    /// Creates withheld by the PG hard limit for which there is room again (peering.md 7.3 rule 3a): the mon sends its
    /// creates again, and every PG whose create info came from a peer gets a new interval (a pg_temp that differs from
    /// its acting set; its primary then sends the create info again).
    fn pg_resume_creates(&mut self) {
        let r = self.pg.set.take_resumable_creates();
        if let Some(epoch) = r.mon_from {
            self.log(format!(
                "PG hard limit has room again: asking the mon for its PG creates from epoch {epoch}"
            ));
            self.pg_resolicit_creates(epoch);
        }
        let Some(map) = self.map.clone().filter(|_| !r.peer.is_empty()) else {
            return;
        };
        let temps: BTreeMap<PgT, Vec<i32>> = r
            .peer
            .iter()
            .filter_map(|pg| {
                let p = map.pools.get(&(pg.pool as i64))?;
                let opt_ec_size = (p.is_erasure()
                    && p.has_flag(osdmap::pool::flags::EC_OPTIMIZATIONS))
                .then_some(p.size as usize);
                Some((
                    *pg,
                    new_interval_temp(&map.pg_to_up_acting(*pg).acting, opt_ec_size),
                ))
            })
            .collect();
        self.log(format!(
            "PG hard limit has room again: requesting a new interval (pg_temp) for {} PG(s) whose create was withheld",
            temps.len()
        ));
        self.send_pg_temp(temps);
    }

    /// Ask the mon for its PG creates from `epoch` again (the control core owns the mon subscription).
    pub(crate) fn pg_resolicit_creates(&mut self, epoch: u32) {
        if !self.is_control() {
            return self.xsend(0, XMsg::PgCreatesFrom { epoch });
        }
        #[cfg(test)]
        self.t
            .subs
            .push(("osd_pg_creates".into(), u64::from(epoch), 0));
        self.mc.resubscribe("osd_pg_creates", u64::from(epoch), 0);
    }

    /// Send queued `pg repeer` commands, a few per tick (each one is a mon proposal).
    fn pg_repeer_drain(&mut self) {
        for _ in 0..REPEER_PER_TICK {
            let Some(pg) = self.pg.repeer_q.pop_front() else {
                return;
            };
            let c = format!(r#"{{"prefix":"pg repeer","pgid":"{pg}"}}"#);
            self.mc.send_command(&c, Vec::new());
        }
    }

    /// Kill switches `ec_enable_pools` and `ec_enable_optimized` (adr 0039, 0067).
    pub(crate) fn ec_enables(&self) -> (ec::EcEnable, ec::EcEnable) {
        (
            ec::EcEnable::parse(self.conf.get("ec_enable_pools").unwrap_or("all")),
            ec::EcEnable::parse(self.conf.get("ec_enable_optimized").unwrap_or("all")),
        )
    }
}

/// Last stat of a primary PG we stopped serving, as a still-reported INCOMPLETE one (never active or clean).
pub(crate) fn inactive_stat(enc: &[u8]) -> Option<Vec<u8>> {
    use pgwire::state as st;
    let mut s: pgwire::PgStat = denc::from_slice(enc).ok()?;
    s.state = (s.state & !(st::ACTIVE | st::PEERED | st::CLEAN | st::CREATING)) | st::INCOMPLETE;
    s.reported_seq += 1;
    s.encode_to_vec().ok()
}

/// pg_temp that differs from `acting`, so the mon starts a new interval: its first member alone, or for a set of at most
/// one member that set plus an empty slot. An EC pool with optimizations keeps its size (`opt_ec_size`): empty slots up
/// to it.
pub(crate) fn new_interval_temp(acting: &[i32], opt_ec_size: Option<usize>) -> Vec<i32> {
    let mut t = if acting.len() > 1 {
        vec![acting[0]]
    } else {
        let mut t = acting.to_vec();
        t.push(pgwire::NONE_OSD);
        t
    };
    if let Some(n) = opt_ec_size
        && t.len() < n
    {
        t.resize(n, pgwire::NONE_OSD);
    }
    t
}

/// pg_temp that asks for a new interval of an EC PG we lead: only us, at our shard position, the rest empty.
pub(crate) fn lead_only_us(acting: &[i32], me: i32, size: usize) -> Option<Vec<i32>> {
    let i = acting.iter().position(|o| *o == me)?;
    if acting.len() != size {
        return None;
    }
    let mut want = vec![pgwire::NONE_OSD; size];
    want[i] = me;
    Some(want)
}

/// DATA-segment form of an EC sub-write for a SERVER_TENTACLE peer (struct v5). When the conversion fails the value is
/// left untouched (it encodes as struct v4) and the error is returned: the caller sends v4 without the TENTACLE feature
/// and logs it, a sub-write the primary waits for is never dropped.
fn ec_write_tentacle(op: &mut ecwire::ECSubWrite) -> Result<crate::xcore::DataX, denc::Error> {
    let data_off = op.data_segment()?;
    Ok(crate::xcore::DataX {
        more: std::mem::take(&mut op.txn_data_more),
        data_off,
        ..Default::default()
    })
}

#[cfg(test)]
mod ec_tentacle_fallback_tests {
    use super::*;
    use messages::Message;

    #[test]
    fn rejected_data_segment_falls_back_to_v4_instead_of_dropping() {
        let mut op = ecwire::ECSubWrite {
            // a well-formed envelope (it encodes as v4) that is not a v9 transaction: data_segment rejects it
            txn_data: bytes::Bytes::from_static(&[8, 8, 4, 0, 0, 0, 0, 0, 0, 0]),
            ..Default::default()
        };
        let feats = denc::features::ALL;
        assert!(ec_write_tentacle(&mut op).is_err());
        let f = feats & !denc::features::TENTACLE_BIT;
        // the value is untouched and encodes as v4 for that peer
        assert!(op.txn_middle.is_empty());
        let m = ecwire::MOSDECSubOpWrite {
            pgid: Default::default(),
            map_epoch: 1,
            op,
            min_epoch: 1,
            trace: [0; 3],
        };
        assert!(m.encode(f).is_ok());
    }
}

#[cfg(test)]
mod query_tests {
    use super::*;

    /// `pg query` stamps: classic utime_t text (UTC, microseconds), dates from the one civil-date helper.
    #[test]
    fn utime_str_is_classic_utc_text() {
        use denc::types::UTime;
        assert_eq!(
            utime_str(UTime::new(0, 0)),
            "1970-01-01T00:00:00.000000+0000"
        );
        assert_eq!(
            utime_str(UTime::new(1_709_210_096, 123_456_789)),
            "2024-02-29T12:34:56.123456+0000"
        );
        assert_eq!(
            utime_str(UTime::new(u32::MAX, 0)),
            "2106-02-07T06:28:15.000000+0000"
        );
    }

    #[test]
    fn unserved_pg_stat_turns_inactive() {
        use pgwire::state as st;
        let s = pgwire::PgStat {
            state: st::ACTIVE | st::CLEAN,
            reported_seq: 7,
            ..Default::default()
        };
        let b = inactive_stat(&s.encode_to_vec().unwrap()).unwrap();
        let r: pgwire::PgStat = denc::from_slice(&b).unwrap();
        assert_eq!(r.state & (st::ACTIVE | st::CLEAN), 0);
        assert_ne!(r.state & st::INCOMPLETE, 0);
        assert_eq!(r.reported_seq, 8);
    }

    #[test]
    fn lead_temp_keeps_only_our_shard_position() {
        let n = pgwire::NONE_OSD;
        assert_eq!(lead_only_us(&[5, 3, 7, 8], 3, 4), Some(vec![n, 3, n, n]));
        assert_eq!(lead_only_us(&[3, n, 7, 8], 3, 4), Some(vec![3, n, n, n]));
        assert_eq!(lead_only_us(&[5, 7, 8], 3, 3), None, "not in acting");
        assert_eq!(lead_only_us(&[3, 7], 3, 4), None, "short acting set");
    }

    /// peering.md 7.3 rule 3a: the pg_temp that re-triggers a withheld create differs from the acting set.
    #[test]
    fn new_interval_temp_differs_from_acting() {
        let n = pgwire::NONE_OSD;
        assert_eq!(new_interval_temp(&[4, 1, 2], None), vec![4]);
        assert_eq!(new_interval_temp(&[4], None), vec![4, n]);
        assert_eq!(new_interval_temp(&[], None), vec![n]);
        assert_eq!(
            new_interval_temp(&[4, 1, 2], Some(3)),
            vec![4, n, n],
            "optimized EC keeps its size"
        );
    }

    #[test]
    fn delete_progress_samples_the_rate() {
        let s = Duration::from_secs;
        let mut d = DelProgress::default();
        // progress window: first call arms, a sample every log_every, rate = objects / s
        assert_eq!(d.sample(s(10), 100), None);
        assert_eq!(d.sample(s(15), 600), None);
        let (secs, n) = d.sample(s(20), 1100).unwrap();
        assert_eq!((secs as u64, n, d.rate), (10, 1000, 100));
        d.reset();
        assert_eq!(d.rate, 0);
    }

    #[test]
    fn utime_format_and_pgid() {
        let t = |sec| denc::types::UTime::new(sec, 1500);
        assert_eq!(utime_str(t(0)), "1970-01-01T00:00:00.000001+0000");
        assert_eq!(utime_str(t(951_782_400)), "2000-02-29T00:00:00.000001+0000");
        assert_eq!(
            utime_str(t(1_760_000_000)),
            "2025-10-09T08:53:20.000001+0000"
        );
        assert_eq!(parse_pgid("27.1f"), Some(PgT::new(27, 0x1f)));
        assert_eq!(parse_pgid("x"), None);
    }
}

/// Mon command for one OSD's metadata. `id` MUST be a JSON integer: the mon answers a string with EINVAL
/// ("bad or missing field 'id'"), which made every peer look classic forever (live-found 2026-10-10).
/// `ceph_version_short` of a classic OSD that predates the tracker 74943 fix (first known fixed release 21.1.2, the
/// submodule pin). Unparsable = not reported.
pub(crate) fn isa_cache_bug_version(v: &str) -> bool {
    let mut it = v.split('.').map(|x| x.parse::<u32>());
    match (it.next(), it.next(), it.next()) {
        (Some(Ok(a)), Some(Ok(b)), Some(Ok(c))) => (a, b, c) < (21, 1, 2),
        _ => false,
    }
}

fn peer_meta_cmd(osd: i32) -> String {
    format!(r#"{{"prefix":"osd metadata","id":{osd}}}"#)
}

#[cfg(test)]
mod peer_meta_tests {
    #[test]
    fn isa_cache_bug_versions() {
        use super::isa_cache_bug_version as b;
        assert!(b("20.2.4") && b("19.2.3") && b("21.1.1") && b("21.0.0"));
        assert!(!b("21.1.2") && !b("21.2.0") && !b("22.1.0"));
        assert!(!b("") && !b("dev") && !b("20.2"));
    }

    #[test]
    fn peer_meta_cmd_id_is_integer() {
        let v: serde_json::Value = serde_json::from_str(&super::peer_meta_cmd(7)).unwrap();
        assert_eq!(v["prefix"], "osd metadata");
        assert_eq!(v["id"], serde_json::json!(7));
    }
}

/// One pool's MPGStats `pool_stat` entry from its data and omap bytes on this OSD (see `Osd::pg_pool_statfs`).
/// Per pool: `(pool, data bytes, compressed physical bytes, compressed logical bytes)`.
pub(crate) type PoolBytes = (i64, i64, i64, i64);

/// `comp` / `comp_orig`: physical and logical bytes of the pool's compressed extents (adr 0059 am. 1); allocated = data
/// with the compressed part at its physical size.
pub(crate) fn pool_statfs(data: i64, comp: i64, comp_orig: i64) -> messages::StoreStatfs {
    messages::StoreStatfs {
        allocated: (data - comp_orig + comp).max(0),
        data_stored: data,
        data_compressed: comp,
        data_compressed_allocated: comp,
        data_compressed_original: comp_orig,
        ..Default::default()
    }
}

#[cfg(test)]
mod list_share_tests {
    use super::{ListShare, parked_walk};
    use crate::xcore::SLICE_NS;
    use denc::types::{PgT, SpgT};
    use std::collections::BTreeSet;

    /// The walk over the PGs with parked ops starts after the PG of the latest listing turn, wraps around and visits
    /// each PG once; without a turn yet it keeps the order.
    #[test]
    fn parked_walk_starts_after_the_latest_listing_turn() {
        let pg = |s: u32| SpgT {
            pgid: PgT::new(1, s),
            shard: denc::types::ShardId::NO_SHARD,
        };
        let set: BTreeSet<SpgT> = [1, 4, 9, 12].into_iter().map(pg).collect();
        let walk = |last: Option<SpgT>| {
            let mut v = Vec::new();
            parked_walk(&set, last, &mut v);
            v.into_iter().map(|s| s.pgid.seed).collect::<Vec<_>>()
        };
        assert_eq!(walk(None), [1, 4, 9, 12]);
        assert_eq!(walk(Some(pg(4))), [9, 12, 1, 4]);
        assert_eq!(walk(Some(pg(12))), [1, 4, 9, 12]);
        assert_eq!(
            walk(Some(pg(10))),
            [12, 1, 4, 9],
            "after a PG no longer parked: the next one"
        );
    }

    /// adr 0522: without other messages than listing requests in the last iteration every continuation runs; with
    /// them the continuations of an iteration stop after one drain slice (the first always runs); every store poll
    /// starts over; the listing time of the reported iteration is what the drain slice must not learn from.
    #[test]
    fn share_yields_to_flowing_messages_after_one_slice() {
        let mut s = ListShare::default();
        s.next_iteration();
        assert!(s.turn(false));
        s.ran();
        s.used = 10 * SLICE_NS;
        assert!(s.turn(false), "empty inbox: work-conserving");
        s.ran();
        assert!(s.listed_ns() >= 10 * SLICE_NS);
        // An iteration of listing requests only: still work-conserving.
        s.note_message(true);
        s.next_iteration();
        s.used = 10 * SLICE_NS;
        assert!(s.turn(false));
        s.ran();
        s.note_message(true);
        s.note_message(false);
        s.next_iteration();
        assert_eq!(s.listed_ns(), 0);
        assert!(s.turn(false), "first continuation of an iteration");
        s.ran();
        s.used = SLICE_NS - 1;
        assert!(s.turn(false));
        s.ran();
        s.used = SLICE_NS;
        assert!(!s.turn(false), "messages flow in and the slice is used");
        assert!(
            s.turn(true),
            "a listing that holds later ops of its object always runs"
        );
        s.ran();
        assert!(s.listed_ns() >= SLICE_NS, "its time is counted");
        s.next_iteration(); // no new point demand
        assert!(s.turn(false));
    }
}

/// `pg_pool_t` option key of `deep_scrub_reformat` (fork `wip-ifed-dedup`, dedup-reformat.md 2; string).
const POOL_OPT_DEEP_SCRUB_REFORMAT: i32 = 26;

/// Engine list of `pool` in the OSD fallback option `flashstore_deep_scrub_reformat` (`<pool id>=<engine list>` entries
/// separated by `|`; adr 0593-dedup-deep-scrub-reformat). Empty when the pool has no entry; the last entry of a pool wins.
fn reformat_fallback(conf: &str, pool: i64) -> String {
    let mut out = String::new();
    for ent in conf.split('|') {
        if let Some((id, list)) = ent.split_once('=')
            && id.trim().parse::<i64>() == Ok(pool)
        {
            out = list.to_owned();
        }
    }
    out
}

#[cfg(test)]
mod reformat_conf_tests {
    use super::reformat_fallback;

    #[test]
    fn fallback_entries() {
        let c = "3=collect_csum,recompress| 5 = defragment|3=recompress";
        assert_eq!(reformat_fallback(c, 3), "recompress");
        assert_eq!(reformat_fallback(c, 5), " defragment");
        assert_eq!(reformat_fallback(c, 4), "");
        assert_eq!(reformat_fallback("", 1), "");
        assert_eq!(reformat_fallback("garbage", 1), "");
    }
}

#[cfg(test)]
mod rm_pace_tests {
    use super::RmPace;
    use std::time::Duration;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn free_without_client_demand_paced_with_it() {
        let mut p = RmPace::default();
        // no client op ever: back to back
        assert_eq!(p.due(0, false, MS), Some(false));
        p.stepped(false, MS);
        assert_eq!(p.due(0, false, 2 * MS), Some(false));
        // a client op arrives: one step now, then one per gap
        assert_eq!(p.due(1, false, 3 * MS), Some(true));
        p.stepped(true, 3 * MS);
        assert_eq!(p.due(2, false, 4 * MS), None);
        assert_eq!(p.due(3, false, 12 * MS), None);
        assert_eq!(p.due(4, false, 13 * MS), Some(true));
        // a due step that queued nothing (txn in flight, cold page) keeps its turn
        assert_eq!(p.due(4, false, 14 * MS), Some(true));
        p.stepped(true, 14 * MS);
        // clients quiet for a gap since their last op (13 ms): back to back again
        assert_eq!(p.due(4, false, 22 * MS), None);
        assert_eq!(p.due(4, false, 23 * MS), Some(false));
        // above the failsafe fill: back to back under client demand
        assert_eq!(p.due(5, true, 24 * MS), Some(false));
        assert_eq!(p.due(5, false, 25 * MS), Some(true));
    }
}

#[cfg(test)]
mod pool_lifetime_tests {
    use super::*;
    use store::dev::{SimClock, SimConfig, SimDisk};
    use store::layout::{MkfsParams, mkfs};
    use store::obj::{Store, StoreCfg};

    #[test]
    fn deleted_pool_options_and_orphan_stats_are_released() {
        let disk = SimDisk::new(SimConfig::new(64 << 20));
        mkfs(
            &mut disk.queue(),
            &mut SimClock::default(),
            &MkfsParams {
                shards: 1,
                wal_blocks: 1024,
                align_blocks: 1,
                meta_pct: 8,
                ..Default::default()
            },
        )
        .unwrap();
        let (store, _) =
            Store::mount(|| disk.queue(), SimClock::default(), StoreCfg::default()).unwrap();
        let mut host = PgHost::new(0, storeadapt::StoreAdapter::new(store), None, None);
        let mut map = OsdMap::default();
        map.pools.insert(1, Default::default());
        host.reformat_noted
            .insert((u64::MAX, "unknown global digest".into()));
        for pool in 1..=32 {
            host.configured_pools.insert(pool);
            host.compress_noted
                .insert(pool, ("aggressive".into(), "snappy".into()));
            host.reformat_noted.insert((pool, "unknown engine".into()));
            let pgid = PgT::new(pool, 0);
            host.orphan_stats.insert(pgid);
            host.stats.insert(pgid, vec![0; 1024]);
            host.store.set_pool_compression(
                pool,
                &peering::store::PoolCompOpts {
                    mode: "aggressive".into(),
                    algorithm: "snappy".into(),
                    ..Default::default()
                },
            );
            host.store.set_pool_reformat(pool, "recompress");
            assert!(!host.store.pre_pool(pool));
            assert!(host.store.reformat_engines(pool).any());
            host.forget_deleted_pools(&map);
            assert_eq!(host.configured_pools.len(), 1);
            assert_eq!(host.stats.len(), 1);
            assert_eq!(host.orphan_stats.len(), 1);
            assert_eq!(host.compress_noted.len(), 1);
            assert_eq!(host.reformat_noted.len(), 2);
            assert!(!host.store.pre_pool(1), "live pool options remain");
            assert!(host.store.reformat_engines(1).any());
            if pool != 1 {
                assert!(host.store.pre_pool(pool), "deleted compression released");
                assert!(!host.store.reformat_engines(pool).any());
            }
        }
    }
}

#[cfg(test)]
mod map_share_tests {
    use super::*;

    /// NT-deadcode-04: a map share holds the newest `min(osd_map_share_max_epochs, osd_map_message_max)` epochs (was a
    /// fixed 40), never epochs the peer has, at least the newest one.
    #[test]
    fn map_share_window_follows_the_options() {
        assert_eq!(map_share_first(10, 100, 40), 61, "default window");
        assert_eq!(map_share_first(95, 100, 40), 96, "only what the peer lacks");
        assert_eq!(map_share_first(10, 100, 5), 96);
        assert_eq!(
            map_share_first(10, 100, 0),
            100,
            "at least the newest epoch"
        );
        assert_eq!(map_share_first(0, 3, 40), 1);
    }
}
