// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! One PG's sans-IO state machine: core struct, creation/loading, map advance, interval
//! handling, gating, persistence helpers and the replica/stray role (spec peering.md 3, 5.2, 5.4,
//! 7.3, 8.1, pglog.md 6.1). Primary role: `primary.rs`; recovery data plane: `recovery.rs`.

use crate::held::{Held, HeldMsg, Probe, Step, WaitOn};
use crate::map::MapHandle;
use crate::plog::{
    IndexedLog, MergeError, MissingSet, merge_log, merge_log_ec, recompute_last_complete,
    rewind_divergent_log, rewind_divergent_log_ec,
};
use crate::store::{PersistedPg, PgStoreOps, StoreOp, StoreTxn, with_lease};
use crate::types::*;
use denc::types::{Eversion, Hobject, PgShard, ShardId, SpgT, Timespan};
use pgwire::state as pgs;
use pgwire::{
    IntervalInput, Mapping, PastIntervals, PgHistory, PgInfo, PgLease, PgLeaseAck, PgNotify,
    PoolParams, QueryType, check_new_interval, is_new_interval_maps,
};
use pgwire::{
    MOSDPGInfo2, MOSDPGLease, MOSDPGLeaseAck, MOSDPGLog, MOSDPGNotify2, MOSDPGQuery2, MOSDPGTrim,
    PeeringMsg,
};
use replwire::{
    MOSDPGUpdateLogMissing, MOSDPGUpdateLogMissingReply, MOSDRepOp, MOSDRepOpReply, ReplMsg,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub(crate) use crate::primary::Prim;
pub(crate) use crate::recovery::RecoveryState;

/// Top-level machine state (peering.md 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum St {
    /// Waiting for the map that starts the interval (Initial/Reset).
    Reset,
    Stray,
    ReplicaActive,
    Primary(PSt),
    ToDelete,
}

/// Primary substates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PSt {
    GetInfo,
    GetLog,
    GetMissing,
    WaitUpThru,
    Down,
    Incomplete,
    WaitActingChange,
    Active(ASt),
}

/// Active substates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ASt {
    Activating,
    /// Log-based recovery: waiting for the LOCAL slot (`osd_max_backfills` pool of this OSD).
    WaitLocalRecoveryReserved,
    /// Log-based recovery: waiting for remote reservations.
    WaitRemoteRecoveryReserved,
    Recovering,
    NotRecovering,
    /// Backfill: waiting for the LOCAL slot.
    WaitLocalBackfillReserved,
    WaitRemoteBackfillReserved,
    Backfilling,
    /// Backfill refused/revoked; waits for a retry.
    NotBackfilling,
    Recovered,
    Clean,
}

/// A replica write held this long for its store loads is a slow op (`osd_op_complaint_time` default): it logs
/// `WARNING TIMEOUT` once per period and counts in the slow ops (`Pg::repops_held_since`). Surfacing only: the head keeps
/// waiting for its load completions, it never applies or acks because time passed.
pub const REPOP_HELD_COMPLAINT_NS: Mono = 30_000_000_000;
/// A wait for store loads (a held replica write, an EC own-shard prefetch): since when it waits and how many
/// `REPOP_HELD_COMPLAINT_NS` periods were already reported.
#[derive(Debug, Default)]
pub(crate) struct HeldComplaint {
    since: Option<Mono>,
    warned: u64,
}

impl HeldComplaint {
    /// The wait starts (or goes on).
    pub(crate) fn hold(&mut self, now: Mono) {
        if self.since.is_none() {
            self.since = Some(now);
            self.warned = 0;
        }
    }
    /// Since when it waits (None: no wait).
    pub(crate) fn since(&self) -> Option<Mono> {
        self.since
    }
    /// A wait that entered a new complaint period at `now` is reported once, loudly (`WARNING TIMEOUT <op> exceeded <limit>s
    /// (<ctx>)`); the wait goes on. `ctx` gets the age in seconds.
    pub(crate) fn warn(&mut self, now: Mono, op: &str, ctx: impl FnOnce(u64) -> String) {
        let Some(since) = self.since else {
            return;
        };
        let age = now.saturating_sub(since);
        let periods = age / REPOP_HELD_COMPLAINT_NS;
        if periods > self.warned {
            self.warned = periods;
            eprintln!(
                "WARNING TIMEOUT {op} exceeded {}s ({})",
                REPOP_HELD_COMPLAINT_NS / SEC,
                ctx(age / SEC)
            );
        }
    }
}

/// A PG stopped by the past-interval bounds check (peering.md 3.8): the interval it was decided in and the two ranges
/// the operator log/alert names.
#[derive(Debug, Clone, Copy)]
struct BoundsStop {
    /// `info.history.same_interval_since` at the decision (one log line per interval).
    interval: u32,
    required: (u32, u32),
    past: (u32, u32),
}

/// Replica-side reservation substate (ReplicaActive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepRes {
    NotRecovering,
    WaitRecovery,
    WaitBackfill,
    Recovering { backfill: bool },
}

/// Continuation attached to a store commit.
#[derive(Debug, Clone)]
pub(crate) enum Pending {
    Plain,
    /// Recovery data and the recovered PG info are durable; only now may we purge stray sources.
    RecoveryComplete {
        interval: u32,
        /// `Pg::recovery_writes` when the fence was queued.
        writes: u64,
    },
    /// EC primary: idle roll-forward round (like `Plain`; may leave a lazy `info` behind, adr 0160 am. 2).
    EcRollForward,
    /// Activation durable: ack the primary (replica) / count ourselves (primary).
    Activate {
        interval: u32,
        activation_epoch: u32,
    },
    RepOpReply {
        interval: u32,
        to: i32,
        tid: u64,
        reply: MOSDRepOpReply,
    },
    LogMissingReply {
        interval: u32,
        to: i32,
        tid: u64,
        reply: MOSDPGUpdateLogMissingReply,
    },
    /// EC shard: sub-write durable, ack the primary (ec.md 6.1.2).
    EcWriteReply {
        interval: u32,
        to: i32,
        tid: u64,
        reply: ecwire::MOSDECSubOpWriteReply,
    },
    PushReply {
        interval: u32,
        to: i32,
        tid: u64,
        /// The push's header priority, echoed (spec replication.md 6.1).
        prio: u16,
        reply: replwire::MOSDPGPushReply,
        /// The push completed recovery of an object: `last_complete` right after it was applied (the durable value
        /// once this commits; later appends are not).
        recovered: Option<Eversion>,
    },
    DeleteReply {
        interval: u32,
        to: i32,
        tid: u64,
        /// The delete's header priority, echoed (spec replication.md 6.1).
        prio: u16,
        reply: replwire::MOSDPGRecoveryDeleteReply,
    },
    /// Backfill completion and preceding removals/progress are durable: the target can survive a restart.
    BackfillFinishAck {
        interval: u32,
        to: i32,
        reply: replwire::MOSDPGBackfill,
    },
    /// Primary's own commit of a client write / recovery object.
    LocalWrite {
        interval: u32,
        tid: u64,
    },
    Delete,
}

/// Lease bookkeeping (spec 8).
#[derive(Debug, Clone, Default)]
pub(crate) struct Lease {
    /// Primary: local deadline. Replica: actual grant in the primary clock, converted lazily.
    pub readable_until: Mono,
    pub readable_until_ub: Mono,
    /// Max ub seen from the primary (primary clock), echoed in acks.
    pub ub_from_primary: Mono,
    // primary
    pub ub_sent: Mono,
    pub acks: BTreeMap<i32, Mono>,
    pub next_send: Mono,
    /// Diagnostics (primary): when the last renewal went out, when each peer's ack last advanced its bound, since when
    /// the PG is LAGGY (0 = not) and how often it went LAGGY in this interval (log rate limit).
    pub sent_at: Mono,
    pub acked_at: BTreeMap<i32, Mono>,
    pub laggy_at: Mono,
    pub laggy_n: u32,
    /// Diagnostics (replica): last MOSDPGLease receipt and late-lease episodes in this interval (log rate limit).
    pub rx_at: Mono,
    pub late_n: u32,
    // both: bound on previous intervals' leases
    pub prior_ub: Mono,
    pub wait_until: Mono,
    /// Diagnostics (primary): when WAIT began (0 = not waiting).
    pub wait_from: Mono,
}

/// Wire form of a lease bound. Leases are capped at [`crate::types::MAX_READABLE_INTERVAL`], so bounds fit; a value
/// beyond i32 seconds saturates instead of wrapping negative (a negative bound decodes as "no lease").
pub(crate) fn to_ts(m: Mono) -> Timespan {
    Timespan {
        sec: (m / SEC).min(i32::MAX as u64) as i32,
        nsec: (m % SEC) as i32,
    }
}
pub(crate) fn from_ts(t: Timespan) -> Mono {
    if t.sec < 0 || t.nsec < 0 {
        0
    } else {
        t.sec as u64 * SEC + t.nsec as u64
    }
}

/// Counters for interop debugging (every discard is counted by reason).
#[derive(Debug, Clone, Default)]
pub struct PgCounters {
    /// Process-local counter lifetime, assigned only when constructing a PG. Never encoded or persisted.
    pub work_generation: u64,
    /// Local synchronous PG work; never persisted or encoded in pg_stat_t.
    pub busy_ns: u64,
    pub work_ops: u64,
    pub work_bytes: u64,
    /// Listed in the PG map's per-iteration `ran` list (so the list holds each PG at most once).
    pub(crate) ran: bool,
    pub discards: BTreeMap<&'static str, u64>,
    pub errors: BTreeMap<&'static str, u64>,
    pub intervals: u64,
    /// Peering messages sent again (`redrive_peering`: the peer's cluster session faulted or was reset).
    pub redrives: u64,
}

/// Why a write submission was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteErr {
    NotActive,
    /// Object is missing on a replica or here: recover first.
    Degraded(Hobject),
    /// Refused with this errno (positive) before any log entry exists: the store can never apply the transaction
    /// (size limits), or the object's local state is unreadable (EIO).
    TooBig(i32),
    /// The store's size pre-flight ([`crate::PgStoreOps::check_write`]) needs metadata pages that are loading: nothing was
    /// logged, sent or applied; submit the write again after the store's wake (adr 0021 S8).
    Blocked,
}

/// A PG instance.
pub struct Pg {
    pub(crate) cfg: Arc<Config>,
    pub spg: SpgT,
    pub(crate) me: PgShard,
    // map state
    pub(crate) map: MapHandle,
    pub(crate) lastmap: Option<MapHandle>,
    pub(crate) pool: PoolParams,
    pub(crate) up: Vec<i32>,
    pub(crate) acting: Vec<i32>,
    pub(crate) up_primary: i32,
    pub(crate) acting_primary: i32,
    // durable state
    pub(crate) info: PgInfo,
    pub(crate) log: IndexedLog,
    pub(crate) missing: MissingSet,
    /// Local objects found damaged and waiting for their repair from a peer (module `damage`).
    pub(crate) dmg: BTreeSet<Hobject>,
    /// Damaged objects repaired from a peer.
    pub(crate) shards_repaired: u64,
    pub(crate) past: PastIntervals,
    /// Set while the past-interval bounds check (peering.md 3.8) stops this PG: no peering, no activation, no outbound
    /// message and no client service until a later interval passes the check again.
    bounds_stop: Option<BoundsStop>,
    /// Interval of the last log-only case-1 warning (one line per PG per interval).
    bounds_warned: Option<u32>,
    pub(crate) info_dirty: bool,
    /// Only the log-progress fields of `info` changed (last_update / last_complete / last_user_version / log_tail, by
    /// `append_log` on a PG without missing objects): a client-write txn leaves `_info` alone (one tree put and the pg_info
    /// encode less per write on the primary and every replica); the next txn of another kind, and every log trim, writes it.
    /// `PersistedPg::normalize` rebuilds those fields from the log at load, so a crash before that write loses nothing.
    pub(crate) info_adv: bool,
    /// `_loghead` lags the log since a `LogAppendFast`: written (`LogSetHead`) with the next `info`.
    pub(crate) head_stale: bool,
    pub(crate) past_dirty: bool,
    pub(crate) created_in_store: bool,
    /// Why this PG refuses to peer: an EC pool outside the support gate or an EC role this OSD may not lead.
    pub(crate) refuse: Option<&'static str>,
    /// EC primary role switches (`ec_primary`, `ec_opt_primary`) as they were when this primary interval started: a
    /// runtime change applies from the next interval on (writes of the current one keep flowing, `ec_lead_switch_off`).
    pub(crate) ec_lead_cfg: bool,
    /// Last write tid handed out (unique over the life of this PG instance).
    pub(crate) write_tid: u64,
    pub(crate) persisted_epoch: u32,
    /// A split decided in this advance step still has to add its transaction: `start_peering_interval` must not
    /// flush in between (the interval bookkeeping and the split commit as one txn).
    pub(crate) hold_flush: bool,
    /// Primary of a pending merge: the PG was undersized at activation, the merge cannot proceed.
    pub(crate) merge_not_ready: bool,
    // machine
    pub(crate) st: St,
    /// Transitions of `st` not yet folded into the set's timing table (`dump_pg_recovery_stats`).
    pub(crate) st_track: crate::recstats::StTrack,
    pub(crate) state: u64,
    pub(crate) last_peering_reset: u32,
    pub(crate) send_notify: bool,
    pub(crate) pg_committed_to: Eversion,
    pub(crate) lease: Lease,
    pub(crate) prim: Prim,
    pub(crate) rec: RecoveryState,
    pub(crate) bf: crate::backfill::BackfillState,
    pub(crate) rep_res: RepRes,
    /// Replica: shard bytes the held backfill reservation expects (`Pg::backfill_held`); 0 = none.
    pub(crate) bf_space: u64,
    /// This OSD's fill (`PgSet::set_local_full`), refreshed at every message delivery.
    pub(crate) local_full: LocalFull,
    pub(crate) scrub: crate::scrub::ScrubReplica,
    pub(crate) sp: crate::scrubp::ScrubPrim,
    /// Snap trimmer state (primary).
    pub(crate) trim: crate::snaptrim::Trim,
    /// Peering phase timer (`Config::peer_trace_ns`, lab diagnostic).
    pub(crate) ptrace: PeerTrace,
    /// Operator notes (clog-worthy), drained by the set.
    pub(crate) notes: Vec<String>,
    /// Map epoch of the last EC divergent-entry rollback executed here (0 = none; trace diagnostic).
    pub(crate) ec_rewound_at: u32,
    // output
    pub(crate) out: Vec<Action>,
    pub(crate) txn: Vec<StoreOp>,
    pub(crate) pending: BTreeMap<u64, Pending>,
    next_token: u64,
    /// Object-state generation (adr 0160 D5): changes whenever a txn not produced by the replicated client write path
    /// may change an object of this PG: when it is queued AND when it commits (a state read in between saw the store
    /// before or after the apply). Unique process-wide, so a replaced PG never repeats one. The op engine's decoded
    /// object-state cache is valid only while this stays the same.
    obj_gen: u64,
    /// Tokens of queued txns that change objects and are not the client write path's (see `obj_gen`).
    obj_tokens: Vec<u64>,
    /// Non-client object transactions queued so far (recovery, backfill, repair); see `recovery_fenced`.
    pub(crate) recovery_writes: u64,
    /// Value of `recovery_writes` covered by the latest committed recovery fence.
    pub(crate) recovery_fenced: u64,
    /// Objects recovered here (complete push or pull response, LOST_REVERT stamp, rebuilt EC shard) whose txn has not
    /// committed yet, with the token of the flush that carries it. They are no longer missing, but the store may not
    /// hold them yet: nothing reads them to push them on before that commit, whose event runs recovery again (spec
    /// replication.md 6.6). Not reset with the interval: only commits release entries.
    pub(crate) applying: BTreeMap<Hobject, u64>,
    /// The next `flush` is the replicated client write path's own txn (`submit_write`).
    own_txn: bool,
    barrier: Option<u64>,
    blocked: Vec<Action>,
    pub(crate) temps: BTreeSet<Hobject>,
    /// EC L0 push target: running shard crc of the pushes in flight (adr 0039 am. 4), per object.
    pub(crate) push_verify: BTreeMap<Hobject, crate::recovery::PushVerify>,
    /// EC: run the stash GC after the activation that was just processed (needs the store).
    pub(crate) ec_gc_pending: bool,
    /// EC primary role: geometry + code of the pool (rebuilt when the pool's EC facts change).
    pub(crate) ecb: Option<(Arc<pgwire::EcPoolInfo>, Arc<ecback::Backend>)>,
    /// EC primary role: write pipeline, reads, recovery (module `ecprim`).
    pub(crate) ep: crate::ecprim::EcPrim,
    /// OSDs known to run croit-flashstore-osd (`PgSet::set_flashstore_peers`; refreshed at `PgSet::with_pg`): EC RMW warm reads go only to
    /// them (adr 0043 am. 5). Stale or empty = no warm read (latency only).
    pub(crate) nv_peers: Arc<std::collections::BTreeSet<i32>>,
    /// LAB (wprof on only): first arrival of shard sub-reads (0, tid) / sub-writes (1, tid), for `wprof::lat` slots 6/7.
    pub(crate) lat_in: BTreeMap<(u8, u64), u64>,
    pub(crate) now: Mono,
    /// Replica: epoch of the activation it acked last (sent again with a repeated ack).
    pub(crate) act_epoch: u32,
    /// Map epoch of the last ActMap (the stray notify goes out once per map, adr 0071).
    pub(crate) acted_epoch: u32,
    pub(crate) counters: PgCounters,
    pub(crate) last_stats_pub: Mono,
    /// Map epoch of the last stats publish (`stats_epochs` bound).
    pub(crate) last_stats_epoch: u32,
    pub(crate) stats_seq: u64,
    pub(crate) last_stats_state: u64,
    /// Replica / EC shard: data-path messages (`held_behind`: repop, sub-write, sub-read, log update, pct, scrub, recovery,
    /// info, ...) that wait for the store (admission, space, cold pages; adr 0021 am. 8, 25), in
    /// arrival order, with the state of the head (`held::Held`, adr 0636); bounded (`REPOP_WAIT_*`), replayed by
    /// `retry_repops` and at commits.
    held: Held<Inbound>,
    /// Leases this PG opened and did not release (`release_leases` skips the store when none).
    leases: u32,
    /// Operator-note latch of the space preflight (`space_held`): the last replica write / sub-write verdict was "no room"
    /// (one note per change, not per write). Not op state: the waiting op is the head of `held`.
    space_wait: bool,
    /// `pg_stat_t` of repops: encoded (primary) / decoded (replica) again only when it changed (it does not per write).
    pub(crate) stat_cache: StatCache,
}

impl std::fmt::Debug for Pg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pg")
            .field("spg", &self.spg)
            .field("st", &self.st)
            .field("state", &pgs::state_string(self.state))
            .finish_non_exhaustive()
    }
}

/// Process-wide object-state generations (see `Pg::obj_gen`); bumped only by txns outside the client write path.
fn next_obj_gen() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

impl Pg {
    pub(crate) fn blank(cfg: Arc<Config>, spg: SpgT, map: MapHandle, info: PgInfo) -> Pg {
        // PG construction is cold. One process-wide sequence distinguishes worker lifetimes even when
        // removal and replacement both happen between their one-second diagnostic snapshots.
        static NEXT_WORK_GENERATION: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        let work_generation = NEXT_WORK_GENERATION
            .try_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |n| n.checked_add(1),
            )
            .expect("PG counter lifetime exhausted");
        let me = PgShard {
            osd: cfg.whoami,
            shard: spg.shard,
        };
        let pool = map.pool(spg.pgid.pool).unwrap_or_default();
        let mut pg = Pg {
            cfg,
            spg,
            me,
            map: map.clone(),
            lastmap: None,
            pool,
            up: vec![],
            acting: vec![],
            up_primary: -1,
            acting_primary: -1,
            info,
            log: IndexedLog::default(),
            missing: MissingSet::new(true),
            dmg: BTreeSet::new(),
            shards_repaired: 0,
            past: PastIntervals::default(),
            bounds_stop: None,
            bounds_warned: None,
            info_dirty: false,
            info_adv: false,
            head_stale: false,
            past_dirty: false,
            created_in_store: false,
            refuse: None,
            ec_lead_cfg: false,
            write_tid: 0,
            persisted_epoch: 0,
            hold_flush: false,
            merge_not_ready: false,
            st: St::Reset,
            st_track: Default::default(),
            state: 0,
            last_peering_reset: map.epoch(),
            send_notify: false,
            pg_committed_to: Eversion::default(),
            lease: Lease::default(),
            prim: Prim::default(),
            rec: RecoveryState::default(),
            bf: Default::default(),
            rep_res: RepRes::NotRecovering,
            bf_space: 0,
            local_full: Default::default(),
            scrub: Default::default(),
            sp: Default::default(),
            trim: Default::default(),
            ptrace: Default::default(),
            notes: vec![],
            ec_rewound_at: 0,
            out: vec![],
            txn: vec![],
            pending: BTreeMap::new(),
            next_token: 1,
            obj_gen: next_obj_gen(),
            obj_tokens: Vec::new(),
            recovery_writes: 0,
            recovery_fenced: 0,
            applying: BTreeMap::new(),
            own_txn: false,
            barrier: None,
            blocked: vec![],
            temps: BTreeSet::new(),
            push_verify: BTreeMap::new(),
            ec_gc_pending: false,
            ecb: None,
            ep: Default::default(),
            nv_peers: Default::default(),
            lat_in: BTreeMap::new(),
            now: 0,
            act_epoch: 0,
            acted_epoch: 0,
            counters: PgCounters {
                work_generation,
                ..Default::default()
            },
            last_stats_pub: 0,
            last_stats_epoch: 0,
            stats_seq: 0,
            last_stats_state: 0,
            held: Held::Idle,
            space_wait: false,
            leases: 0,
            stat_cache: StatCache::default(),
        };
        pg.set_mapping(&*map);
        pg.refresh_ecb();
        if pg.pool.is_erasure && !pg.ec_supported() {
            pg.refuse = Some("erasure-coded pool not supported (support gate)");
        }
        pg
    }

    /// Create a brand new PG instance at `map` (mon create, or create info from a peer).
    pub fn create(
        cfg: Arc<Config>,
        spg: SpgT,
        map: MapHandle,
        mut history: PgHistory,
        past: PastIntervals,
        now: Mono,
    ) -> Pg {
        let epoch = map.epoch();
        if history.epoch_created == 0 {
            history.epoch_created = epoch;
        }
        if history.epoch_pool_created == 0 {
            history.epoch_pool_created = history.epoch_created;
        }
        if history.same_interval_since == 0 {
            history.same_interval_since = epoch;
            history.same_up_since = epoch;
            history.same_primary_since = epoch;
        }
        let mut info = PgInfo::new(spg);
        info.history = history;
        let mut pg = Pg::blank(cfg, spg, map, info);
        pg.now = now;
        pg.st_track.push(St::Reset, now);
        pg.past = past;
        pg.last_peering_reset = pg.info.history.same_interval_since.min(epoch);
        pg.info.stats.created = pg.info.history.epoch_created;
        pg.sync_stats_mapping();
        pg.txn.push(StoreOp::CreatePg);
        pg.created_in_store = true;
        pg.info_dirty = true;
        pg.past_dirty = true;
        pg.send_notify = pg.acting_primary >= 0 && !pg.is_primary();
        pg.flush(Pending::Plain);
        pg
    }

    /// Reload a PG from the store; it restarts at `map` (the map of its persisted epoch).
    pub fn load(cfg: Arc<Config>, spg: SpgT, p: PersistedPg, map: MapHandle, now: Mono) -> Pg {
        let mut pg = Pg::blank(cfg, spg, map, p.info);
        pg.now = now;
        pg.st_track.push(St::Reset, now);
        pg.log = IndexedLog::new(p.log);
        pg.missing = MissingSet::from_wire(p.missing);
        if pg.map.flags().recovery_deletes && !pg.missing.may_include_deletes() {
            pg.missing.set_may_include_deletes(true);
        }
        pg.past = p.past_intervals;
        // the persisted map is gone (history hole): the jump to this map stands in for the interval change classic
        // detects while advancing across the trim floor
        if pg.map.epoch() > p.epoch {
            pg.retire_trimmed_past();
        }
        pg.persisted_epoch = p.epoch;
        pg.created_in_store = true;
        pg.send_notify = pg.acting_primary >= 0 && !pg.is_primary();
        pg
    }

    /// Map-gap rule (peering.md 3.2 step 4): a new interval starting at the cluster trim floor with
    /// `last_epoch_clean` below it clears past intervals; the monitor trims maps only below every PG's
    /// clean epoch, so someone was clean after everything recorded here.
    fn retire_trimmed_past(&mut self) {
        let epoch = self.map.epoch();
        if epoch
            == self
                .cfg
                .cluster_trim
                .load(std::sync::atomic::Ordering::Relaxed)
            && self.info.history.last_epoch_clean < epoch
            && !self.past.is_empty()
        {
            self.past.clear();
            self.past_dirty = true;
        }
    }

    // ---- accessors ----------------------------------------------------------------------

    pub fn pgid(&self) -> denc::types::PgT {
        self.spg.pgid
    }
    pub fn info(&self) -> &PgInfo {
        &self.info
    }
    pub fn log(&self) -> &IndexedLog {
        &self.log
    }
    pub fn missing(&self) -> &MissingSet {
        &self.missing
    }
    pub fn past_intervals(&self) -> &PastIntervals {
        &self.past
    }
    pub fn state_bits(&self) -> u64 {
        self.state
    }
    /// Members whose commit the primary still awaits for write `tid` (replicated: the replicas; EC: the shards), or
    /// `None` when the write is not open here or only the local commit is outstanding.
    pub fn write_waiting(&self, tid: u64) -> Option<Vec<PgShard>> {
        let r = self.prim.repops.get(&tid)?;
        (!r.waiting.is_empty()).then(|| r.waiting.iter().copied().collect())
    }
    /// Diagnostics: the primary's writes still open `(tid, local commit done, peers awaited)`.
    pub fn repops_diag(&self) -> String {
        self.prim
            .repops
            .iter()
            .take(3)
            .map(|(t, r)| format!("tid{t}:local={}:wait={:?}", r.local_done, r.waiting))
            .collect::<Vec<_>>()
            .join(" ")
    }
    pub fn state_string(&self) -> String {
        pgs::state_string(self.state)
    }
    /// Move the machine to `to` (no-op when already there) and note the transition for the timing table.
    pub(crate) fn set_st(&mut self, to: St) {
        if self.st != to {
            self.st = to;
            self.st_track.push(to, self.now);
        }
    }
    /// Fold the transitions since the last call into the OSD's recovery-state timing table.
    pub(crate) fn fold_rec_stats(&mut self, rs: &mut crate::recstats::RecStats) {
        self.st_track.fold(rs);
    }
    pub fn machine_state(&self) -> St {
        self.st
    }
    /// The last target OSD (id, map epoch) whose recovery / backfill reservation was refused because it is full
    /// (`backfill_toofull` / `recovery_toofull`); `None` once a reservation succeeds. Operator-facing (`pg query`, the
    /// note).
    pub fn refused_full(&self) -> Option<(i32, u32)> {
        self.rec.refused_by_full
    }
    /// Do we lead this PG INSTANCE? An EC instance leads only when our OSD is the acting primary AT this instance's shard:
    /// after a remap the OSD can hold an old instance (other shard) besides the current one; that one must stay a stray
    /// (its queries would name a shard we no longer hold: classic peers assert on it).
    pub fn is_primary(&self) -> bool {
        self.leads_in(self.acting_primary, &self.acting)
    }

    fn leads_in(&self, acting_primary: i32, acting: &[i32]) -> bool {
        acting_primary == self.me.osd
            && (!self.pool.is_erasure
                || acting
                    .iter()
                    .position(|o| *o == acting_primary)
                    .is_some_and(|i| i as i8 == self.me.shard.0))
    }
    /// Erasure-coded PG with a usable code (this OSD can lead it).
    pub fn is_ec_pool(&self) -> bool {
        self.pool.is_erasure && self.ecb.is_some()
    }
    pub fn ec_stripe_width(&self) -> Option<u64> {
        self.ecb
            .as_ref()
            .map(|(info, _)| u64::from(info.stripe_width))
    }
    pub fn up(&self) -> &[i32] {
        &self.up
    }
    pub fn acting(&self) -> &[i32] {
        &self.acting
    }
    pub fn map_epoch(&self) -> u32 {
        self.map.epoch()
    }
    /// The map this PG last processed.
    pub fn map_handle(&self) -> MapHandle {
        self.map.clone()
    }
    pub fn last_peering_reset(&self) -> u32 {
        self.last_peering_reset
    }
    pub fn pg_committed_to(&self) -> Eversion {
        self.pg_committed_to
    }
    pub fn counters(&self) -> &PgCounters {
        &self.counters
    }
    pub fn is_active(&self) -> bool {
        self.state & pgs::ACTIVE != 0
    }
    pub fn is_clean(&self) -> bool {
        self.state & pgs::CLEAN != 0
    }
    pub fn is_deleting(&self) -> bool {
        self.st == St::ToDelete
    }
    /// Primary only: infos of the peers we peered with (`pg query` peer_info).
    pub fn peer_infos(&self) -> impl Iterator<Item = (i32, &PgInfo)> {
        self.prim.peer_info.iter().map(|(s, i)| (s.osd, i))
    }
    pub fn rep_reservation(&self) -> RepRes {
        self.rep_res
    }

    /// Diagnostics: primary-side reservation progress (recovery and backfill).
    pub fn resv_debug(&self) -> String {
        format!(
            "rec(cur={:?} wait={:?} held={:?}) bf(cur={:?} wait={:?} held={:?})",
            self.rec.reserve_cur,
            self.rec.reserve_wait,
            self.rec.reserved,
            self.bf.reserve_cur,
            self.bf.reserve_wait,
            self.bf.reserved
        )
    }
    pub fn in_flight_persists(&self) -> usize {
        self.pending.len()
    }
    /// Replica read/primary op gate: primary, active, lease valid (spec 8.2).
    pub fn is_readable(&self, now: Mono) -> bool {
        self.is_primary()
            && self.state & pgs::ACTIVE != 0
            && self.state & pgs::WAIT == 0
            && self.lease.readable_until != 0
            && now < self.lease.readable_until
    }
    /// Read lease length of this PG: the pool's `read_lease_interval`, else the OSD default (peering.md 8.2).
    pub(crate) fn readable_interval(&self) -> Mono {
        self.pool
            .read_lease_ns
            .unwrap_or(self.cfg.readable_interval)
    }
    /// Local end of the read lease, 0 = none. Primary: its own deadline. Replica: the primary's grant converted with the
    /// current upper clock bound of the primary's incarnation (adr 0683); no bound = 0.
    pub fn readable_until(&self) -> Mono {
        if self.is_primary() {
            self.lease.readable_until
        } else if self.lease.readable_until == 0 {
            0
        } else {
            self.primary_clock()
                .and_then(|c| c.upper)
                .map_or(0, |delta| {
                    PeerClockBounds::to_local(self.lease.readable_until, delta)
                })
        }
    }
    /// Next version a primary write would get.
    pub fn next_version(&self) -> Eversion {
        if self.pool.is_erasure {
            return self.ec_next_version();
        }
        Eversion::new(self.map.epoch(), self.log.head().version + 1)
    }
    /// Earliest time `tick` has work to do.
    pub fn next_deadline(&self) -> Option<Mono> {
        let mut d: Option<Mono> = None;
        let mut upd = |t: Mono| {
            if t != 0 {
                d = Some(d.map_or(t, |x: Mono| x.min(t)));
            }
        };
        if self.is_primary() && !self.is_deleting() && self.cfg.stats_interval > 0 {
            upd(self.last_stats_pub + self.cfg.stats_interval);
        }
        if self.is_primary() && matches!(self.st, St::Primary(PSt::Active(_))) {
            upd(self.lease.next_send);
            upd(self.lease.wait_until);
            upd(self.rec.retry_at);
            upd(self.rec.sleep_at);
            if let Some(t) = self.ec_recov_next_retry() {
                upd(t);
            }
            if let Some(t) = self.ec_next_deadline() {
                upd(t);
            }
        }
        if self.scrub_busy() || self.held.due() {
            upd(1);
        }
        if let Some(t) = self.sp_deadline() {
            upd(t);
        }
        d
    }
    /// Drain the produced actions.
    pub fn take_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.out)
    }

    pub(crate) fn discard(&mut self, why: &'static str) {
        *self.counters.discards.entry(why).or_default() += 1;
    }
    /// EC per-op trace note (`Config::ec_trace`); the closure runs only when tracing.
    #[inline]
    pub(crate) fn ec_trace(&mut self, f: impl FnOnce() -> String) {
        if self.cfg.ec_trace {
            let s = f();
            self.notes.push(format!("ectrace {}: {s}", self.spg));
        }
    }

    pub(crate) fn error(&mut self, why: &'static str) {
        let n = self.counters.errors.entry(why).or_default();
        *n += 1;
        // operator visibility, rate limited per PG and reason (1, 2, 4, 8, ...)
        if n.is_power_of_two() {
            let n = *n;
            self.notes
                .push(format!("pg {}: error: {why} [{n}x]", self.spg));
        }
    }

    /// Fail-stop this OSD ([`Action::Fatal`]): counted and noted like [`Self::error`], then the driver goes down.
    pub(crate) fn fatal(&mut self, why: &'static str) {
        self.error(why);
        self.out.push(Action::Fatal { spg: self.spg, why });
    }

    // ---- output helpers --------------------------------------------------------------------

    pub(crate) fn emit(&mut self, a: Action) {
        if self.barrier.is_some() && matches!(a, Action::Send(_)) {
            self.blocked.push(a);
        } else {
            self.out.push(a);
        }
    }

    /// Send with the priority classic gives the message: recovery and backfill requests this PG originates use the
    /// recovery message priority, everything else its type's default. Replies that echo a request's priority use
    /// [`Pg::send_prio`] (spec replication.md 6.1).
    pub(crate) fn send(&mut self, to: i32, body: Body, tid: u64) {
        let prio = match &body {
            Body::Repl(
                ReplMsg::Push(_)
                | ReplMsg::Pull(_)
                | ReplMsg::RecoveryDelete(_)
                | ReplMsg::Backfill(_)
                | ReplMsg::BackfillRemove(_),
            ) => self.recovery_message_priority(),
            Body::Repl(ReplMsg::Scan(s)) if s.op == replwire::MOSDPGScan::OP_GET_DIGEST => {
                self.recovery_message_priority()
            }
            _ => body.priority(),
        };
        self.send_prio(to, body, tid, prio);
    }
    pub(crate) fn send_prio(&mut self, to: i32, body: Body, tid: u64, prio: u16) {
        self.emit(Action::Send(Box::new(Send {
            to,
            epoch: self.map.epoch(),
            tid,
            prio,
            body,
            producer: Some(self.spg),
        })));
    }
    pub(crate) fn send_peering(&mut self, to: i32, m: impl Into<PeeringMsg>) {
        self.send(to, Body::Peering(m.into()), 0);
    }
    pub(crate) fn send_repl(&mut self, to: i32, m: impl Into<ReplMsg>, tid: u64) {
        self.send(to, Body::Repl(m.into()), tid);
    }

    /// Queue the pending ops + dirty state into one store transaction with a continuation.
    pub(crate) fn flush(&mut self, kind: Pending) -> Option<u64> {
        let own = std::mem::take(&mut self.own_txn);
        if self.st == St::ToDelete && !matches!(kind, Pending::Delete) {
            // the PG is being removed: nothing may be written for it any more
            self.txn.clear();
            self.info_dirty = false;
            self.info_adv = false;
            self.head_stale = false;
            self.past_dirty = false;
            return None;
        }
        let mut ops = std::mem::take(&mut self.txn);
        self.missing.take_ops(&mut ops);
        let client_write = matches!(
            kind,
            Pending::LocalWrite { .. }
                | Pending::RepOpReply { .. }
                | Pending::EcWriteReply { .. }
                | Pending::EcRollForward
        );
        if self.info_dirty || (self.info_adv && !client_write) {
            // the persisted head lags since a fast append (this txn's or an earlier one's): written with the info unless
            // an op after the last fast append of this txn sets it explicitly
            let head_set = |o: &StoreOp| {
                matches!(
                    o,
                    StoreOp::LogAppend(_)
                        | StoreOp::LogAppendKeep(_)
                        | StoreOp::LogRewind { .. }
                        | StoreOp::LogReplace(_)
                        | StoreOp::LogSetHead(_)
                )
            };
            let fast = ops
                .iter()
                .rposition(|o| matches!(o, StoreOp::LogAppendFast(_)));
            let set = ops.iter().rposition(head_set);
            if (self.head_stale || fast.is_some()) && (set.is_none() || set < fast) {
                ops.push(StoreOp::LogSetHead(self.log.head()));
            }
            ops.push(StoreOp::PutInfo(Box::new(self.info.clone())));
            self.info_dirty = false;
            self.info_adv = false;
            self.head_stale = false;
        } else if ops.iter().any(|o| matches!(o, StoreOp::LogAppendFast(_))) {
            self.head_stale = true;
        }
        if self.past_dirty {
            ops.push(StoreOp::PutPastIntervals(Box::new(self.past.clone())));
            self.past_dirty = false;
        }
        if matches!(kind, Pending::Delete) {
            ops = vec![StoreOp::RemovePg];
        } else if !ops.is_empty() && self.persisted_epoch != self.map.epoch() {
            self.persisted_epoch = self.map.epoch();
            ops.push(StoreOp::PutEpoch(self.persisted_epoch));
        }
        if ops.is_empty() && matches!(kind, Pending::Plain | Pending::EcRollForward) {
            return None;
        }
        let token = self.next_token;
        self.next_token += 1;
        self.pending.insert(token, kind);
        if !client_write && ops.iter().any(StoreOp::touches_objects) {
            self.recovery_writes += 1;
        }
        if !own && ops.iter().any(StoreOp::touches_objects) {
            self.obj_gen = next_obj_gen();
            self.obj_tokens.push(token);
        }
        self.out.push(Action::Persist {
            spg: self.spg,
            token,
            txn: StoreTxn { ops },
        });
        Some(token)
    }

    /// `oid` was recovered here by ops now in `self.txn`: the next flush carries them (see `applying`).
    pub(crate) fn mark_applying(&mut self, oid: &Hobject) {
        self.applying.insert(oid.clone(), self.next_token);
    }

    /// Object-state generation of this PG (adr 0160 D5, see the field).
    pub fn obj_gen(&self) -> u64 {
        self.obj_gen
    }

    /// The next `flush` carries the replicated client write path's own txn: it leaves `obj_gen` as is (the op engine
    /// keeps the post-write state itself). Object ops queued before it by anything else still count.
    pub(crate) fn own_txn_next(&mut self) {
        self.own_txn = !self.txn.iter().any(StoreOp::touches_objects);
    }

    /// Store commit callback.
    pub fn on_commit(&mut self, now: Mono, token: u64, store: &impl PgStoreOps) {
        self.on_commit_inner(now, token);
        if self.held.due() && store.admission_ready_for(self.spg) {
            self.replay(now, store);
        }
        self.after_event(store);
    }

    /// The store admission of this PG is closed: a due held head waits for store progress (`held::Held::pause`).
    pub(crate) fn pause_store_replay(&mut self) {
        self.held.pause();
    }

    fn on_commit_inner(&mut self, now: Mono, token: u64) {
        self.now = now;
        if let Some(i) = self.obj_tokens.iter().position(|t| *t == token) {
            self.obj_tokens.swap_remove(i);
            self.obj_gen = next_obj_gen();
        }
        if !self.applying.is_empty() {
            self.applying.retain(|_, t| *t != token);
        }
        let Some(p) = self.pending.remove(&token) else {
            self.error("commit for unknown token");
            return;
        };
        match p {
            Pending::Plain | Pending::EcRollForward => {}
            Pending::RecoveryComplete { interval, writes } => {
                // commits are ordered: every recovery txn queued before this fence is durable now
                self.recovery_fenced = self.recovery_fenced.max(writes);
                if interval == self.last_peering_reset
                    && self.prim.recovery_complete == Some(token)
                    && self.st == St::Primary(PSt::Active(ASt::Recovered))
                    && !self.needs_recovery()
                    && self.prim.async_recovery_targets.is_empty()
                    && self.prim.backfill_targets.is_empty()
                {
                    self.prim.recovery_complete = None;
                    self.go_clean();
                }
            }
            Pending::Activate {
                interval,
                activation_epoch,
            } => {
                if interval == self.last_peering_reset {
                    self.activate_committed(activation_epoch);
                }
            }
            Pending::RepOpReply {
                interval,
                to,
                tid,
                mut reply,
            } => {
                if interval == self.last_peering_reset {
                    // `last_complete_ondisk` stays the value taken at enqueue: entries appended after this one are
                    // not durable yet (spec replication.md 3.3)
                    reply.map_epoch = self.map.epoch();
                    self.send_repl(to, reply, tid);
                }
            }
            Pending::LogMissingReply {
                interval,
                to,
                tid,
                mut reply,
            } => {
                if interval == self.last_peering_reset {
                    // `last_complete_ondisk` stays the value taken at enqueue: entries appended after this one are
                    // not durable yet (spec replication.md 3.3)
                    reply.map_epoch = self.map.epoch();
                    self.send_repl(to, reply, tid);
                }
            }
            Pending::EcWriteReply {
                interval,
                to,
                tid,
                mut reply,
            } => {
                if let Some(t0) = self.lat_in.remove(&(1, reply.op.tid)) {
                    wprof::lat(7, t0);
                }
                if interval == self.last_peering_reset {
                    reply.map_epoch = self.map.epoch(); // `last_complete`: the enqueue value
                    self.send(to, Body::Ec(reply.into()), tid);
                } else {
                    self.error("ec write reply dropped: interval changed before commit");
                }
            }
            Pending::PushReply {
                interval,
                to,
                tid,
                prio,
                reply,
                recovered,
            } => {
                if interval == self.last_peering_reset {
                    self.send_prio(to, Body::Repl(reply.into()), tid, prio);
                    if let Some(lc) = recovered {
                        self.maybe_report_recovered(lc);
                    }
                }
            }
            Pending::DeleteReply {
                interval,
                to,
                tid,
                prio,
                reply,
            } => {
                if interval == self.last_peering_reset {
                    self.send_prio(to, Body::Repl(reply.into()), tid, prio);
                }
            }
            Pending::BackfillFinishAck {
                interval,
                to,
                reply,
            } => {
                if interval == self.last_peering_reset {
                    self.send_repl(to, reply, 0);
                }
            }
            Pending::LocalWrite { interval, tid } => {
                if interval == self.last_peering_reset {
                    self.local_write_committed(tid);
                }
            }
            Pending::Delete => {
                self.out.push(Action::PgRemoved { spg: self.spg });
            }
        }
        if let Some(b) = self.barrier
            && self.pending.range(..=b).next().is_none()
        {
            self.barrier = None;
            let blocked = std::mem::take(&mut self.blocked);
            self.out.extend(blocked);
        }
    }

    // ---- mapping -------------------------------------------------------------------------

    fn set_mapping(&mut self, map: &dyn crate::map::PgMapView) {
        let m = map.pg_mapping(self.spg.pgid);
        self.up = m.up;
        self.up_primary = m.up_primary;
        self.acting = m.acting;
        self.acting_primary = m.acting_primary;
        self.pool = map.pool(self.spg.pgid.pool).unwrap_or_default();
    }

    fn cur_mapping(&self) -> Mapping {
        Mapping {
            up: self.up.clone(),
            up_primary: self.up_primary,
            acting: self.acting.clone(),
            acting_primary: self.acting_primary,
        }
    }

    pub(crate) fn sync_stats_mapping(&mut self) {
        let s = &mut self.info.stats;
        s.up = self.up.clone();
        s.acting = self.acting.clone();
        s.up_primary = self.up_primary;
        s.acting_primary = self.acting_primary;
        s.mapping_epoch = self.info.history.same_interval_since;
        self.info_dirty = true;
    }

    /// Pool of this PG exists in the current map.
    pub(crate) fn pool_exists(&self) -> bool {
        self.map.pool(self.spg.pgid.pool).is_some()
    }

    /// Members of `acting` that exist (EC vectors keep `NONE` holes).
    pub(crate) fn acting_count(&self) -> u32 {
        self.acting
            .iter()
            .filter(|o| **o != pgwire::NONE_OSD && **o >= 0)
            .count() as u32
    }

    /// The acting set meets `min_size` (recovery / backfill reservation priority).
    pub(crate) fn acting_min_size(&self) -> bool {
        self.acting_count() >= self.pool.min_size
    }

    /// `acting_set_writeable` (stretch.md 3.2): `min_size` AND, for a stretch pool, [`pgwire::can_peer`] of the acting
    /// vector (EC: NONE holes included) on the current map. Gates les/lis advance at activation, the activation
    /// roll-forward and ACTIVE vs PEERED, on primary and replicas alike.
    pub(crate) fn acting_writable(&self) -> bool {
        self.acting_min_size() && pgwire::can_peer(&*self.map, &self.pool, &self.acting)
    }

    /// Required past-interval bounds (peering.md 3.8). On an implausible pair this PG alone stops: INCOMPLETE, no
    /// peering, no activation, no outbound message (the `PgSet` gate of [`crate::PgSet::finish`]) and no client service.
    /// The verdict is recomputed from the durable pair, so a later interval that passes the check resumes normal
    /// peering, as does a runtime `osd_skip_check_past_interval_bounds` change ([`crate::PgSet::recheck_past_bounds`]).
    /// Returns true while the PG is stopped.
    pub(crate) fn check_past_interval_bounds(&mut self) -> bool {
        if self.cfg.skip_past_bounds_check {
            // operator escape (`osd_skip_check_past_interval_bounds`): no log, no stop, no alert
            if self.bounds_stop.take().is_some() {
                self.state &= !pgs::INCOMPLETE;
            }
            return false;
        }
        let chk = self.past.check_required_bounds(
            &self.info.history,
            self.cfg
                .cluster_trim
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        let interval = self.info.history.same_interval_since;
        if chk.verdict.stops_pg() {
            if self
                .bounds_stop
                .as_ref()
                .is_none_or(|s| s.interval != interval)
            {
                let reason = chk.verdict.reason().unwrap_or_default();
                self.notes.push(format!(
                    "ERROR {} past interval bounds implausible: required [{},{}) past [{},{}): {reason}; PG stopped (inactive)",
                    self.spg, chk.required.0, chk.required.1, chk.past.0, chk.past.1
                ));
            }
            self.bounds_stop = Some(BoundsStop {
                interval,
                required: chk.required,
                past: chk.past,
            });
            // enforce on every evaluation: a Reset of the stuck interval must not clear INCOMPLETE
            self.state &=
                !(pgs::ACTIVE | pgs::PEERED | pgs::CLEAN | pgs::PEERING | pgs::ACTIVATING);
            self.state |= pgs::INCOMPLETE;
            if self.is_primary() {
                self.set_st(St::Primary(PSt::Incomplete));
            }
            return true;
        }
        if self.bounds_stop.take().is_some() {
            self.state &= !pgs::INCOMPLETE;
        }
        if chk.verdict == pgwire::BoundsVerdict::EmptyRequired
            && self.bounds_warned != Some(interval)
        {
            self.bounds_warned = Some(interval);
            self.notes.push(format!(
                "WARN {} required past_interval bounds are empty [{},{}) but past_intervals is not: {}",
                self.spg,
                chk.required.0,
                chk.required.1,
                self.past.dump()
            ));
        }
        false
    }

    /// Required and stored past-interval ranges while the bounds check stops this PG (None = not stopped).
    pub fn past_bounds_stop(&self) -> Option<((u32, u32), (u32, u32))> {
        self.bounds_stop.map(|s| (s.required, s.past))
    }

    /// Is this PG stopped by the past-interval bounds check (peering.md 3.8)?
    pub fn past_bounds_stopped(&self) -> bool {
        self.bounds_stop.is_some()
    }

    // ---- map advance -----------------------------------------------------------------------

    /// One map epoch (`AdvMap`). Maps must be delivered in order without gaps that matter. A pg_num increase
    /// that splits this PG returns the new child PGs (split-merge.md 5): they are at this epoch, their
    /// persistence is part of this PG's transaction; the caller registers them and advances them further.
    pub fn advance_map(
        &mut self,
        now: Mono,
        newmap: MapHandle,
        store: &impl PgStoreOps,
    ) -> Vec<Pg> {
        let intervals = self.counters.intervals;
        let kids = self.advance_map_inner(now, newmap);
        if self.counters.intervals != intervals {
            // the ops of the old interval that held store leases are gone (`start_peering_interval`)
            self.release_leases(store);
        }
        self.after_event(store);
        kids
    }

    fn advance_map_inner(&mut self, now: Mono, newmap: MapHandle) -> Vec<Pg> {
        self.now = now;
        let lastmap = self.map.clone();
        if newmap.epoch() <= lastmap.epoch() {
            return vec![];
        }
        if self.st == St::ToDelete {
            self.lastmap = Some(lastmap);
            self.map = newmap;
            return vec![];
        }
        // check_full_transition: a pool newly flagged FULL, or the cluster map FULL flag, discards older write ops
        // (client-ops 5.4 #11)
        let full =
            |m: &MapHandle| m.map_full() || m.pool(self.spg.pgid.pool).is_some_and(|p| p.full);
        if full(&newmap) && !full(&lastmap) {
            self.info.history.last_epoch_marked_full = newmap.epoch();
            self.info_dirty = true;
        }
        let old = self.cur_mapping();
        let new = newmap.pg_mapping(self.spg.pgid);
        let restart = is_new_interval_maps(self.spg.pgid, &*lastmap, &*newmap, &old, &new)
            || (!lastmap.is_up(self.me.osd) && newmap.is_up(self.me.osd));
        let old_pool = self.pool.clone();
        let grown = match (
            lastmap.pool(self.spg.pgid.pool),
            newmap.pool(self.spg.pgid.pool),
        ) {
            // a supported EC shard splits like a replica: its collection is carved by object hash (stash objects too)
            (Some(o), Some(n))
                if n.pg_num > o.pg_num
                    && (!n.is_erasure || n.ec.as_ref().is_some_and(|e| e.supported)) =>
            {
                Some((o.pg_num, n.pg_num))
            }
            _ => None,
        };
        self.lastmap = Some(lastmap);
        self.map = newmap;
        if restart {
            let split = grown.filter(|(o, n)| pgwire::pgmath::is_split(self.spg.pgid.seed, *o, *n));
            self.hold_flush = split.is_some();
            self.start_peering_interval(old, new);
            self.enter_reset();
            // Reset::react(AdvMap) (peering.md 3.8): the closed interval is recorded and sis advanced; a PG with an
            // implausible pair never sends its notify for this interval
            self.check_past_interval_bounds();
            return match split {
                Some((o, n)) => self.split_self(o, n),
                None => vec![],
            };
        }
        self.pool = self.map.pool(self.spg.pgid.pool).unwrap_or_default();
        self.refresh_ecb();
        // no new interval: state specific map handling
        if let St::Primary(p) = self.st {
            let m = self.map.clone();
            match p {
                PSt::GetInfo | PSt::GetLog | PSt::GetMissing | PSt::WaitUpThru => {
                    if self.prim.prior.affected_by_map(&*m) {
                        self.enter_reset();
                        return vec![];
                    }
                    if p == PSt::GetLog
                        && let Some(a) = self.prim.log_src()
                        && !m.is_up(a.osd)
                    {
                        self.enter_reset();
                        return vec![];
                    }
                    if self.prim.need_up_thru
                        && m.up_thru(self.me.osd) >= self.info.history.same_interval_since
                    {
                        self.prim.need_up_thru = false;
                    }
                    self.check_lease_down();
                }
                PSt::Down => {
                    if self.prim.prior.affected_by_map(&*m) {
                        self.enter_reset();
                    }
                }
                PSt::WaitActingChange => {
                    if self
                        .prim
                        .want_acting
                        .iter()
                        .any(|o| *o != pgwire::NONE_OSD && !m.is_up(*o))
                    {
                        self.enter_reset();
                    }
                }
                PSt::Incomplete => {
                    if self.pool.min_size < old_pool.min_size
                        || !self.pool_exists()
                        || self.prim.prior.affected_by_map(&*m)
                    {
                        self.enter_reset();
                    }
                }
                PSt::Active(_) => {
                    self.on_active_advmap();
                    if self.check_lease_down() && self.state & pgs::WAIT != 0 {
                        self.end_wait();
                    }
                }
            }
        }
        if self.st == St::Reset {
            // Reset::react(AdvMap) (peering.md 3.8): every map while the PG waits for its interval start
            self.check_past_interval_bounds();
        }
        vec![]
    }

    /// Reset state: wait for ActMap to restart peering (`Reset` entry sets last_peering_reset).
    pub(crate) fn enter_reset(&mut self) {
        self.on_leave_primary_or_replica();
        self.set_st(St::Reset);
        self.last_peering_reset = self.map.epoch();
        // peering restarts without a new interval: drop peering progress
        // same interval: the replicas keep their slots, owed RELEASEs go out now
        let epoch = self.map.epoch();
        for o in std::mem::take(&mut self.bf.release_owed).into_values() {
            self.send_bf_release(o, epoch);
        }
        self.lost_abort();
        self.prim = Prim::default();
        self.rec = RecoveryState::default();
        self.bf = Default::default();
        self.state &= !(pgs::PEERING | pgs::DOWN | pgs::INCOMPLETE);
    }

    /// Hook when leaving Active/ReplicaActive/primary-specific work (not a new interval).
    pub(crate) fn on_leave_primary_or_replica(&mut self) {
        self.scrub_reset();
        self.trim_reset();
        self.bf_space = 0;
        if self.rep_res != RepRes::NotRecovering {
            self.slot_release_remote();
            self.rep_res = RepRes::NotRecovering;
        }
    }

    /// `start_peering_interval` (spec 3.2).
    fn start_peering_interval(&mut self, old: Mapping, new: Mapping) {
        self.counters.intervals += 1;
        let epoch = self.map.epoch();
        self.last_peering_reset = epoch;
        // repops of the old interval: their primary aborted them; the head's lease goes with `release_leases` (the caller
        // has the store)
        self.held.clear();
        // block outgoing messages until older transactions are durable (spec 3.6)
        self.barrier = self.pending.keys().next_back().copied();
        self.blocked.clear();
        // backend on_change: abort in-flight writes and recoveries of the old interval
        self.abort_interval_work();
        self.on_leave_primary_or_replica();
        self.push_verify.clear();
        for t in std::mem::take(&mut self.temps) {
            self.txn.push(StoreOp::RemoveObject(t));
        }
        // lease: remember the longest promise of the previous interval
        let l = &mut self.lease;
        l.prior_ub = l.prior_ub.max(l.readable_until_ub).max(l.ub_sent);
        l.readable_until = 0;
        l.readable_until_ub = 0;
        l.ub_from_primary = 0;
        l.ub_sent = 0;
        l.acks.clear();
        l.next_send = 0;
        l.sent_at = 0;
        l.acked_at.clear();
        l.laggy_at = 0;
        l.laggy_n = 0;
        l.rx_at = 0;
        l.late_n = 0;
        l.wait_until = 0;
        l.wait_from = 0;

        // swap mapping
        self.up = new.up.clone();
        self.up_primary = new.up_primary;
        self.acting = new.acting.clone();
        self.acting_primary = new.acting_primary;
        let newmap = self.map.clone();
        self.pool = newmap.pool(self.spg.pgid.pool).unwrap_or_default();
        self.refresh_ecb();
        if self.up != self.acting {
            self.state |= pgs::REMAPPED;
        } else {
            self.state &= !pgs::REMAPPED;
        }
        // past intervals / history
        let Some(lastmap) = self.lastmap.clone() else {
            return;
        };
        let inp = IntervalInput {
            pgid: self.spg.pgid,
            same_interval_since: self.info.history.same_interval_since,
            last_epoch_clean: self.info.history.last_epoch_clean,
            old: &old,
            new: &new,
            lastmap: &*lastmap,
            newmap: &*newmap,
        };
        let chk = check_new_interval(&mut self.past, &inp);
        // pg_num / pg_num_pending changes start a new interval even when nothing is recorded in past_intervals
        let (split, pgnum_change) = match (
            lastmap.pool(self.spg.pgid.pool),
            newmap.pool(self.spg.pgid.pool),
        ) {
            (Some(op), Some(np)) => (
                pgwire::is_split(self.spg.pgid.seed, op.pg_num, np.pg_num),
                op.pg_num != np.pg_num || op.pg_num_pending != np.pg_num_pending,
            ),
            _ => (false, false),
        };
        if chk.is_some() {
            self.past_dirty = true;
            self.info.history.same_interval_since = epoch;
            self.retire_trimmed_past();
        } else if pgnum_change || !self.up_acting_equal(&old, &new) {
            // mapping changed but no interval was recorded (pool gone etc.)
            self.info.history.same_interval_since = epoch;
            self.retire_trimmed_past();
        }
        if split {
            self.info.history.last_epoch_split = epoch;
        }
        if old.up != new.up || old.up_primary != new.up_primary {
            self.info.history.same_up_since = epoch;
        }
        if old.acting_primary != new.acting_primary {
            self.info.history.same_primary_since = epoch;
        }
        self.sync_stats_mapping();
        self.leave_backfilling();
        // clear state bits (spec 3.2 step 7)
        let was_primary = self.leads_in(old.acting_primary, &old.acting);
        let primary_changed = was_primary != self.leads_in(new.acting_primary, &new.acting);
        self.state &= !(pgs::ACTIVE
            | pgs::PEERED
            | pgs::PREMERGE
            | pgs::DOWN
            | pgs::RECOVERY_WAIT
            | pgs::RECOVERY_TOOFULL
            | pgs::RECOVERING
            | pgs::PEERING
            | pgs::ACTIVATING
            | pgs::INCOMPLETE
            | pgs::WAIT
            | pgs::LAGGY
            | pgs::BACKFILL_TOOFULL
            | pgs::BACKFILL_WAIT
            | pgs::BACKFILLING
            | pgs::DEGRADED
            | pgs::UNDERSIZED);
        if primary_changed || old.acting != new.acting || !was_primary {
            self.state &= !pgs::CLEAN;
        }
        self.merge_not_ready = false;
        self.prim = Prim::default();
        self.rec = RecoveryState::default();
        self.bf = Default::default();
        self.pg_committed_to = Eversion::default();
        self.send_notify =
            new.acting_primary >= 0 && !self.leads_in(new.acting_primary, &new.acting);
        self.info_dirty = true;
        if new.acting.is_empty() && !new.up.is_empty() && new.up_primary == self.me.osd {
            self.emit(Action::PgTemp {
                pgid: self.spg.pgid,
                want: vec![],
            });
        }
        // persist history/past intervals with every interval change
        if !self.hold_flush {
            self.flush(Pending::Plain);
        }
    }

    fn up_acting_equal(&self, a: &Mapping, b: &Mapping) -> bool {
        a.up == b.up
            && a.acting == b.acting
            && a.up_primary == b.up_primary
            && a.acting_primary == b.acting_primary
    }

    /// `ActMap`: the PG is at the current map; (re)start roles, send notifies.
    pub fn act_map(&mut self, now: Mono, store: &impl PgStoreOps) {
        self.act_map_inner(now, store);
        self.after_event(store);
    }

    fn act_map_inner(&mut self, now: Mono, store: &impl PgStoreOps) {
        self.now = now;
        // classic: one ActMap per map; ours also runs for every message delivered to the PG, the stray notify must not
        // repeat with it (one notify per inbound message flooded an unreachable primary, adr 0071)
        let first = self.acted_epoch < self.map.epoch();
        self.acted_epoch = self.map.epoch();
        if self.bounds_stop.is_some() {
            // stopped PG (peering.md 3.8): no notify, no peering, no activation in this interval. Only the removal a
            // healthy PG takes when it sees its pool gone still runs (ActMap in Reset, not leading: Stray ->
            // DeleteStart), writing only the removal: a stopped copy must stay deletable and a pending one stays down.
            if matches!(self.st, St::Reset) && !self.is_primary() && !self.pool_exists() {
                self.delete_start();
            }
            return;
        }
        match self.st {
            St::Reset => {
                if self.send_notify && self.acting_primary >= 0 {
                    self.send_notify_to_primary();
                }
                // Started -> Start
                if self.is_primary() {
                    self.primary_start();
                } else {
                    self.set_st(St::Stray);
                    if !self.pool_exists() {
                        self.delete_start();
                    }
                }
            }
            St::Stray | St::ReplicaActive => {
                if first && self.send_notify && self.acting_primary >= 0 {
                    self.send_notify_to_primary();
                }
            }
            St::Primary(p) => {
                if p == PSt::WaitUpThru && !self.prim.need_up_thru {
                    self.post_activate();
                }
                self.primary_actmap(store);
            }
            St::ToDelete => {}
        }
        self.update_up_thru_request();
    }

    /// Emit `NeedUpThru` while peering needs it.
    pub(crate) fn update_up_thru_request(&mut self) {
        if let St::Primary(_) = self.st
            && self.prim.need_up_thru
        {
            let want = self.info.history.same_interval_since;
            if self.prim.up_thru_sent < want {
                self.prim.up_thru_sent = want;
                self.out.push(Action::NeedUpThru { want });
            }
        }
    }

    // ---- history / info helpers ------------------------------------------------------------

    /// `update_history`: merge a peer's history.
    pub(crate) fn update_history(&mut self, h: &PgHistory) {
        if h.prior_readable_until_ub != Timespan::default() {
            let rel = from_ts(h.prior_readable_until_ub);
            self.lease.prior_ub = self.lease.prior_ub.max(self.now + rel);
        }
        let mut hh = h.clone();
        hh.prior_readable_until_ub = self.info.history.prior_readable_until_ub;
        if self.info.history.merge(&hh) {
            self.info_dirty = true;
            if self.info.history.last_epoch_clean >= self.info.history.same_interval_since
                && !self.past.is_empty()
            {
                self.past.clear();
                self.past_dirty = true;
            }
        }
    }

    /// Our history for sending: prior lease bound made relative to now.
    pub(crate) fn history_for_send(&self) -> PgHistory {
        let mut h = self.info.history.clone();
        let ub = self
            .lease
            .prior_ub
            .max(self.lease.readable_until_ub)
            .max(self.lease.ub_sent);
        h.prior_readable_until_ub = if ub > self.now {
            to_ts(ub - self.now)
        } else {
            Timespan::default()
        };
        h
    }

    pub(crate) fn info_for_send(&self) -> PgInfo {
        let mut i = self.info.clone();
        i.history = self.history_for_send();
        i
    }

    pub(crate) fn primary_spg(&self) -> SpgT {
        SpgT {
            pgid: self.spg.pgid,
            shard: self.primary_shard(),
        }
    }

    /// Shard of the acting primary: its position in `acting` for EC pools (ec.md 1), `NO_SHARD` for replicated ones
    /// (and for an EC primary we cannot locate: the choke point drops such a message).
    pub(crate) fn primary_shard(&self) -> ShardId {
        if !self.pool.is_erasure {
            return ShardId::NO_SHARD;
        }
        self.acting
            .iter()
            .position(|o| *o == self.acting_primary && *o >= 0)
            .map_or(ShardId::NO_SHARD, |i| ShardId(i as i8))
    }

    fn send_notify_to_primary(&mut self) {
        let to = self.acting_primary;
        let epoch = self.map.epoch();
        let notify = PgNotify {
            query_epoch: epoch,
            epoch_sent: epoch,
            info: self.info_for_send(),
            to: self.primary_shard(),
            from: self.me.shard,
            past_intervals: self.past.clone(),
            pg_features: self.cfg.pg_features,
        };
        self.send_peering(
            to,
            MOSDPGNotify2 {
                spgid: self.primary_spg(),
                notify,
            },
        );
    }

    // ---- inbound dispatch ------------------------------------------------------------------

    /// Handle a peer message (already waited for the map by the caller). Applies the discard
    /// rules of peering.md 7.3 then dispatches by state.
    pub fn handle_msg(&mut self, now: Mono, m: Inbound, store: &impl PgStoreOps) {
        self.handle_msg_inner(now, m, store);
        if std::mem::take(&mut self.ec_gc_pending) {
            self.ec_stash_gc(store);
        }
        self.after_event(store);
    }

    fn handle_msg_inner(&mut self, now: Mono, m: Inbound, store: &impl PgStoreOps) {
        self.now = now;
        let mut held = std::mem::take(&mut self.held);
        held.arrive(m, &mut PgStep::new(self, store));
        self.put_held(held);
    }

    /// Run one message (`held::Step::eval`): the discard rules of peering.md 7.3, then dispatch by state. `Some` = a repop /
    /// sub-write / sub-read waits for `WaitOn` (nothing applied, logged or answered); the caller holds it.
    fn dispatch(
        &mut self,
        m: Inbound,
        store: &impl PgStoreOps,
        probe: &mut Probe,
    ) -> Option<(Inbound, WaitOn)> {
        let (map_epoch, min_epoch, data_path) = gating_of(&m.body);
        let floor = stale_floor(&m.body, map_epoch, min_epoch);
        if self.last_peering_reset > map_epoch || self.last_peering_reset > floor {
            self.discard("old peering message");
            return None;
        }
        if self.bounds_stop.is_some() {
            // stopped PG (peering.md 3.8): no query answer, no peering driven from a peer. A removal runs the same
            // staleness/epoch/interval gate as on a healthy PG (above): a stale one is discarded, it must not delete a
            // copy that rejoined the acting set since.
            if matches!(&*m.body, Body::Peering(PeeringMsg::MOSDPGRemove(_))) {
                self.on_remove(m.from, map_epoch);
            } else {
                self.discard("past interval bounds stop");
            }
            return None;
        }
        if self.refuse.is_some() && matches!(self.st, St::Primary(_)) {
            // a PG led here that this OSD cannot lead (EC primary role): frozen, peers' messages must not drive it
            self.discard("message for a refused primary");
            return None;
        }
        if data_path && (!self.map.is_up(m.from) || self.map.up_from(m.from) > map_epoch) {
            self.discard("sender down or restarted");
            return None;
        }
        let from = m.from;
        let tid = m.tid;
        let prio = m.prio;
        let ingress = m.ingress;
        match *m.body {
            Body::Peering(p) => match p {
                PeeringMsg::MOSDPGNotify2(x) => self.on_notify(from, x),
                PeeringMsg::MOSDPGQuery2(x) => self.on_query(from, x),
                PeeringMsg::MOSDPGInfo2(x) => self.on_info(from, x),
                PeeringMsg::MOSDPGLog(x) => self.on_log(from, x),
                PeeringMsg::MOSDPGLease(x) => self.on_lease(from, x),
                PeeringMsg::MOSDPGLeaseAck(x) => self.on_lease_ack(from, x),
                PeeringMsg::MOSDPGTrim(x) => self.on_trim(from, x),
                PeeringMsg::MOSDPGPCT(x) => self.on_pct(from, x.pg_committed_to),
                PeeringMsg::MOSDPGRemove(x) => self.on_remove(from, x.epoch),
                PeeringMsg::MOSDPGCreate2(_) => self.discard("create2 reached pg"),
                PeeringMsg::MOSDPGRecoveryDelete(x) => {
                    self.on_recovery_delete(from, tid, prio, x.objects.clone(), x.min_epoch)
                }
                PeeringMsg::MOSDPGRecoveryDeleteReply(x) => {
                    self.on_recovery_delete_reply(from, x.from.shard, x.objects.clone())
                }
            },
            Body::Repl(r) => match r {
                ReplMsg::RepOp(x) => {
                    let (x, on) = self.on_repop(from, tid, x, store, probe)?;
                    let body = Box::new(Body::Repl(ReplMsg::RepOp(x)));
                    return Some((
                        Inbound {
                            ingress,
                            from,
                            tid,
                            prio,
                            body,
                        },
                        on,
                    ));
                }
                ReplMsg::RepOpReply(x) => self.on_repop_reply(from, tid, x),
                ReplMsg::UpdateLogMissing(x) => self.on_update_log_missing(from, tid, x),
                ReplMsg::UpdateLogMissingReply(x) => self.on_update_log_missing_reply(from, x),
                ReplMsg::Pct(x) => self.on_pct(from, x.pg_committed_to),
                ReplMsg::Push(x) => self.on_push(from, tid, prio, x, store),
                ReplMsg::PushReply(x) => self.on_push_reply(from, prio, x, store),
                ReplMsg::Pull(x) => self.on_pull(from, tid, prio, x, store),
                ReplMsg::RecoveryDelete(x) => {
                    self.on_recovery_delete(from, tid, prio, x.objects.clone(), x.min_epoch)
                }
                ReplMsg::RecoveryDeleteReply(x) => {
                    self.on_recovery_delete_reply(from, x.from.shard, x.objects.clone())
                }
                ReplMsg::Scan(x) => self.on_scan(from, x, store),
                ReplMsg::Backfill(x) => self.on_backfill(from, x),
                ReplMsg::BackfillRemove(x) => self.on_backfill_remove(from, x),
                ReplMsg::BackfillReserve(x) => self.on_backfill_reserve(from, x, store),
                ReplMsg::RecoveryReserve(x) => self.on_recovery_reserve(from, x),
                ReplMsg::ScrubReserve(x) => self.on_scrub_reserve(from, x),
                ReplMsg::RepScrub(x) => self.on_rep_scrub(from, x),
                ReplMsg::RepScrubMap(x) => self.sp_on_map(from, x),
                ReplMsg::Scrub2(_) => {
                    self.discard("scrub2 reaches pg through PgSet::scrub_command")
                }
                ReplMsg::ForceRecovery(_) => {
                    self.discard("force recovery reaches pg through PgSet::force_command")
                }
            },
            Body::Ec(e) => match e {
                ecwire::EcMsg::Write(x) => {
                    let (x, on) = self.on_ec_write(from, tid, x, store, probe)?;
                    let body = Box::new(Body::Ec(ecwire::EcMsg::Write(x)));
                    return Some((
                        Inbound {
                            ingress,
                            from,
                            tid,
                            prio,
                            body,
                        },
                        on,
                    ));
                }
                ecwire::EcMsg::Read(x) => {
                    let (x, on) = self.on_ec_read(from, x, store, probe)?;
                    let body = Box::new(Body::Ec(ecwire::EcMsg::Read(x)));
                    return Some((
                        Inbound {
                            ingress,
                            from,
                            tid,
                            prio,
                            body,
                        },
                        on,
                    ));
                }
                ecwire::EcMsg::WriteReply(x) => self.on_ec_write_reply(from, x),
                ecwire::EcMsg::ReadReply(x) => self.on_ec_read_reply(from, x, store),
            },
        }
        None
    }

    /// `PgSet` released `m` together with an earlier message of this PG that queued a store transaction in the same call
    /// (map arrival, PG creation): the driver applies it only after the call, a sub-read served now would miss it. Held
    /// until the next commit / timer pass, behind any waiting head (OQ 46 a, adr 0067 am. 9; `held::Held::release`).
    pub(crate) fn hold_released(&mut self, m: Inbound) {
        self.held.release(m);
    }

    /// Put the held queue back after it ran (`dispatch` never touches it: a message waits only through its result).
    fn put_held(&mut self, held: Held<Inbound>) {
        debug_assert!(self.held.is_idle(), "the held queue changed while it ran");
        self.held = held;
    }

    fn is_replica_state(&self) -> bool {
        matches!(self.st, St::Stray | St::ReplicaActive)
    }

    // ---- MQuery (fulfill_query, spec 5.4) ---------------------------------------------------

    fn on_query(&mut self, from: i32, m: MOSDPGQuery2) {
        if !self.is_replica_state() {
            self.discard("query in non-replica state");
            return;
        }
        if from != self.acting_primary {
            self.error("query from non-primary");
            return;
        }
        let q = m.query;
        self.update_history(&q.history);
        let epoch = self.map.epoch();
        match q.ty {
            QueryType::INFO => {
                let notify = PgNotify {
                    query_epoch: q.epoch_sent,
                    epoch_sent: epoch,
                    info: self.info_for_send(),
                    to: q.from,
                    from: self.me.shard,
                    past_intervals: self.past.clone(),
                    pg_features: self.cfg.pg_features,
                };
                self.send_peering(
                    from,
                    MOSDPGNotify2 {
                        spgid: SpgT {
                            pgid: self.spg.pgid,
                            shard: q.from,
                        },
                        notify,
                    },
                );
            }
            QueryType::LOG | QueryType::FULLLOG | QueryType::MISSING => {
                // pglog 6.6: a LOG query below our tail cannot be answered incrementally; the full log goes out, and
                // the sender (which believes it is contiguous with us) is worth a note.
                let below_tail = q.ty == QueryType::LOG
                    && q.since != Eversion::default()
                    && q.since < self.log.tail();
                if below_tail {
                    self.error("log query below tail");
                }
                let full = q.ty != QueryType::LOG || below_tail;
                let log = if full {
                    self.log.copy_after(Eversion::default())
                } else {
                    self.log.copy_after(q.since)
                };
                let msg = MOSDPGLog {
                    epoch,
                    info: self.info_for_send(),
                    log,
                    missing: self.missing.to_wire(),
                    query_epoch: q.epoch_sent,
                    past_intervals: PastIntervals::default(),
                    to: q.from,
                    from: self.me.shard,
                    lease: None,
                };
                self.send_peering(from, msg);
            }
            _ => self.error("unknown query type"),
        }
    }

    // ---- activation messages (Stray / ReplicaActive) ---------------------------------------

    fn on_log(&mut self, from: i32, m: MOSDPGLog) {
        match self.st {
            St::Primary(_) => self.primary_on_log(from, m),
            St::Stray => self.replica_on_log(from, m),
            // The activation log arrives once per interval (a new interval resets to Stray first); a second one in
            // the same interval is a duplicate and would re-merge an older head over newer state.
            St::ReplicaActive => {
                self.discard("duplicate log");
                // our ack may be what was lost (adr 0071): the primary sent its activation again
                if from == self.acting_primary {
                    self.resend_activated_ack();
                }
            }
            _ => self.discard("log in wrong state"),
        }
    }

    fn replica_on_log(&mut self, from: i32, m: MOSDPGLog) {
        if from != self.acting_primary {
            self.error("log from non-primary");
            return;
        }
        self.update_history(&m.info.history);
        let mut ops = Vec::new();
        if m.info.last_backfill == Hobject::MIN() {
            // we are the target of a backfill: adopt info and log wholesale
            let mut info = m.info.clone();
            info.pgid = self.spg;
            let hist = self.info.history.clone();
            info.history = hist;
            info.history.merge(&m.info.history);
            self.info = info;
            self.log = IndexedLog::new(m.log.clone());
            self.log.log.head = m.log.head;
            if self.pool.is_erasure {
                // backfill target: no stash exists for these entries, nothing to roll back or forward
                self.log.log.can_rollback_to = m.log.head;
                self.log.log.rollback_info_trimmed_to = m.log.head;
            }
            self.missing.clear();
            self.missing.set_may_include_deletes(true);
            self.info.last_update = m.log.head;
            self.info.log_tail = m.log.tail;
            ops.push(StoreOp::LogReplace(Box::new(self.log.log.clone())));
            self.info_dirty = true;
        } else {
            // mode O: partial writes that skipped us first raise our last_update (spec 8)
            self.ec_apply_own_pwlc(&m.info);
            let mut info = self.info.clone();
            let merged = match self.ec_ctx() {
                Some(ctx) => merge_log_ec(
                    &mut self.log,
                    &mut info,
                    &mut self.missing,
                    &mut ops,
                    &m.info,
                    &m.log,
                    ctx,
                ),
                None => merge_log(
                    &mut self.log,
                    &mut info,
                    &mut self.missing,
                    &mut ops,
                    &m.info,
                    &m.log,
                ),
            };
            match merged {
                Ok(_) => {
                    self.info = info;
                    self.info_dirty = true;
                }
                Err(MergeError::NoOverlap) => {
                    self.fatal("merge_log: no overlap");
                    return;
                }
            }
        }
        self.ec_note_rewind(&ops);
        self.txn.extend(ops);
        if m.info.last_backfill != Hobject::MIN() {
            self.ec_update_peer_pwlc(m.from, &m.info);
        }
        if let Some(l) = m.lease {
            self.proc_lease(&l);
        }
        if self.log.head() != self.info.last_update {
            self.fatal("log head != last_update after merge");
            return;
        }
        self.set_st(St::ReplicaActive);
        self.begin_activate(m.info.last_epoch_started);
    }

    fn on_info(&mut self, from: i32, m: MOSDPGInfo2) {
        match self.st {
            St::Primary(_) => self.primary_on_info(from, m),
            St::Stray => {
                if from != self.acting_primary {
                    self.error("info from non-primary");
                    return;
                }
                self.update_history(&m.info.history);
                let mut ops = Vec::new();
                if self.info.last_update > m.info.last_update {
                    let mut info = self.info.clone();
                    let rewound = match self.ec_ctx() {
                        Some(ctx) => rewind_divergent_log_ec(
                            &mut self.log,
                            &mut info,
                            &mut self.missing,
                            &mut ops,
                            m.info.last_update,
                            ctx,
                        ),
                        None => rewind_divergent_log(
                            &mut self.log,
                            &mut info,
                            &mut self.missing,
                            &mut ops,
                            m.info.last_update,
                        ),
                    };
                    if rewound.is_err() {
                        self.fatal("rewind below tail");
                        return;
                    }
                    self.info = info;
                    self.ec_note_rewind(&ops);
                    self.txn.extend(ops);
                }
                if self.info.last_update < m.info.last_update {
                    // mode O (spec 8): allowed only for a nonprimary shard whose missing entries are all partial
                    // writes that skipped it: the primary's pwlc for us covers our head and ends at its last_update
                    let ok = self.ec_ctx().is_some_and(|c| c.opt && c.np)
                        && m.info
                            .partial_writes_last_complete
                            .get(&self.me.shard)
                            .is_some_and(|&(from, to)| {
                                self.info.last_update >= from && to == m.info.last_update
                            });
                    if !ok {
                        self.fatal("info activation: replica behind (needs log)");
                        return;
                    }
                }
                let ps = self.primary_shard();
                self.ec_update_peer_pwlc(ps, &m.info);
                if self.info.last_update != m.info.last_update {
                    self.fatal("info activation: replica behind (needs log)");
                    return;
                }
                self.info.stats = m.info.stats.clone();
                self.info.hit_set = m.info.hit_set.clone();
                self.info_dirty = true;
                if let Some(l) = m.lease {
                    self.proc_lease(&l);
                }
                self.set_st(St::ReplicaActive);
                self.begin_activate(m.info.last_epoch_started);
            }
            St::ReplicaActive => {
                if from != self.acting_primary {
                    return;
                }
                // proc_primary_info
                self.update_history(&m.info.history);
                {
                    let s = &mut self.info.stats.stats.sum;
                    if s.num_scrub_errors != 0
                        || s.num_shallow_scrub_errors != 0
                        || s.num_deep_scrub_errors != 0
                    {
                        (
                            s.num_scrub_errors,
                            s.num_shallow_scrub_errors,
                            s.num_deep_scrub_errors,
                        ) = (0, 0, 0);
                        self.info_dirty = true;
                    }
                }
                if self.info.purged_snaps != m.info.purged_snaps {
                    self.info.purged_snaps = m.info.purged_snaps.clone();
                    self.info_dirty = true;
                }
                if let Some(l) = m.lease {
                    self.proc_lease(&l);
                }
                self.flush(Pending::Plain);
                // a lost activation ack is answered by the primary sending its activation again (adr 0071)
                self.resend_activated_ack();
            }
            _ => self.discard("info in wrong state"),
        }
    }

    /// Replica branch of `activate()`; durable ack follows on commit.
    fn begin_activate(&mut self, activation_epoch: u32) {
        self.ec_gc_pending = self.ec_ctx().is_some();
        self.send_notify = false;
        self.state &= !pgs::DOWN;
        let acting_member = self.in_acting(self.me);
        if acting_member && self.info.last_epoch_started < activation_epoch {
            self.info.last_epoch_started = activation_epoch;
            self.info.last_interval_started = self.info.history.same_interval_since;
            self.pg_committed_to = self.info.last_update;
        }
        recompute_last_complete(&self.log, &mut self.info, &self.missing);
        if self.ec_opt() && self.acting_writable() {
            // mode O (spec 6.1): every member of a writable acting set rolls forward to head at activation, so no
            // stash / EC_OMAP debt crosses the interval
            let h = self.log.head();
            self.ec_advance(h, true);
        }
        self.info.log_tail = self.log.tail();
        self.info_dirty = true;
        let interval = self.last_peering_reset;
        self.flush(Pending::Activate {
            interval,
            activation_epoch,
        });
    }

    /// ActivateCommitted (replica and primary self).
    fn activate_committed(&mut self, activation_epoch: u32) {
        let active = self.acting_writable();
        if let St::Primary(_) = self.st {
            self.prim_self_activated();
            return;
        }
        self.state &= !(pgs::ACTIVE | pgs::PEERED | pgs::PREMERGE);
        // Only the acting primary carries PREMERGE (split-merge.md 13.1); a replica stays ACTIVE, or PEERED below
        // min_size, like classic's ReplicaActive. The merge report is primary-only.
        self.state |= if active { pgs::ACTIVE } else { pgs::PEERED };
        self.info.stats.state = self.state;
        self.act_epoch = activation_epoch;
        self.send_activated_ack();
    }

    /// Replica: the activation of this interval is durable: ack it again (the first ack may have been lost).
    fn resend_activated_ack(&mut self) {
        if self.st == St::ReplicaActive && self.state & (pgs::ACTIVE | pgs::PEERED) != 0 {
            self.send_activated_ack();
        }
    }

    fn send_activated_ack(&mut self) {
        let activation_epoch = self.act_epoch;
        let mut info = self.info_for_send();
        info.history.last_epoch_started = info.history.last_epoch_started.max(activation_epoch);
        info.history.last_interval_started = self.info.history.same_interval_since;
        let epoch = self.map.epoch();
        let ack = PgLeaseAck {
            readable_until_ub: to_ts(self.lease.ub_from_primary),
        };
        let to = self.acting_primary;
        if to >= 0 {
            self.send_peering(
                to,
                MOSDPGInfo2 {
                    spgid: self.primary_spg(),
                    epoch_sent: epoch,
                    min_epoch: epoch,
                    info,
                    lease: None,
                    lease_ack: Some(ack),
                },
            );
        }
    }

    // ---- leases (replica side, spec 8.1) -----------------------------------------------------

    /// A bound belongs to exactly the primary process identified by this PG's current map.
    pub(crate) fn primary_clock(&self) -> Option<PeerClockBounds> {
        // Distinct shards can share an OSD. Its cores use one clock; no heartbeat to self is needed.
        if self.acting_primary == self.me.osd {
            return Some(PeerClockBounds {
                up_from: self.map.up_from(self.me.osd),
                lower: Some(0),
                upper: Some(0),
            });
        }
        self.cfg.peer_clocks.get(self.acting_primary).filter(|c| {
            c.valid() && c.up_from != 0 && c.up_from == self.map.up_from(self.acting_primary)
        })
    }

    pub(crate) fn proc_lease(&mut self, l: &PgLease) {
        if self.is_primary() {
            return;
        }
        let ub = from_ts(l.readable_until_ub);
        self.lease.ub_from_primary = self.lease.ub_from_primary.max(ub);
        self.lease.readable_until = from_ts(l.readable_until);
        let clock = self.primary_clock();
        // A possible reader's upper bound needs the opposite bound; receipt + interval is conservative without it.
        let ruub = match clock.and_then(|c| c.lower) {
            Some(delta) => PeerClockBounds::to_local(ub, delta),
            None => self.now.saturating_add(from_ts(l.interval)),
        };
        self.lease.readable_until_ub = self.lease.readable_until_ub.max(ruub);
    }

    fn on_lease(&mut self, from: i32, m: MOSDPGLease) {
        if self.st != St::ReplicaActive && self.st != St::Stray {
            self.discard("lease in wrong state");
            return;
        }
        if from != self.acting_primary {
            self.error("lease from non-primary");
            return;
        }
        // a renewal comes every interval/2: a gap beyond the interval means the primary's lease (and its reads) lapsed
        let gap = self.now.saturating_sub(self.lease.rx_at);
        if self.lease.rx_at != 0 && gap > from_ts(m.lease.interval) {
            self.lease.late_n += 1;
            if self.lease.late_n.is_power_of_two() {
                self.notes.push(format!(
                    "pg {}: lease from osd.{from} {} ms after the previous one (renewal every {} ms) [{}x]",
                    self.spg,
                    gap / 1_000_000,
                    from_ts(m.lease.interval) / 2_000_000,
                    self.lease.late_n
                ));
            }
        }
        self.lease.rx_at = self.now.max(1);
        self.proc_lease(&m.lease);
        let epoch = self.map.epoch();
        let ack = PgLeaseAck {
            readable_until_ub: to_ts(self.lease.ub_from_primary),
        };
        self.send_peering(
            from,
            MOSDPGLeaseAck {
                epoch,
                spgid: self.primary_spg(),
                lease_ack: ack,
            },
        );
    }

    // ---- trim / PCT / log-only updates (replica) ----------------------------------------------

    fn on_trim(&mut self, from: i32, m: MOSDPGTrim) {
        match self.st {
            St::Primary(PSt::Active(_)) => {
                self.prim.peer_lcod.insert(self.pshard(from), m.trim_to);
                self.calc_min_lcod();
            }
            St::ReplicaActive => {
                if from != self.acting_primary {
                    return;
                }
                self.trim_log_to(m.trim_to);
                self.flush(Pending::Plain);
            }
            _ => self.discard("trim in wrong state"),
        }
    }

    pub(crate) fn trim_log_to(&mut self, trim_to: Eversion) {
        if self.ec_ctx().is_some() {
            return self.ec_trim_log_to(trim_to);
        }
        let limit = if self.missing.is_empty() {
            self.log.head()
        } else {
            self.info.last_complete
        };
        let to = trim_to.min(limit);
        if to <= self.log.tail() {
            return;
        }
        let cfg = self.cfg.clone();
        let t = self.log.trim_ex(to, &cfg);
        self.txn.push(StoreOp::LogTrim {
            to,
            dups_from: t.dups_from,
            tail_up: true,
        });
        if t.dups_rewrite {
            self.txn.push(StoreOp::LogDups(
                self.log.log.dups.iter().cloned().collect(),
            ));
        }
        self.info.log_tail = self.log.tail();
        self.info_dirty = true;
    }

    fn on_pct(&mut self, from: i32, pct: Eversion) {
        if self.st != St::ReplicaActive {
            self.discard("pct in wrong state");
            return;
        }
        // like every other replica-side handler: only the acting primary raises our committed point (it gates
        // optimized-EC direct replica reads and scrub / backfill decisions)
        if from != self.acting_primary {
            self.discard("pct from non-primary");
            return;
        }
        self.pg_committed_to = self.pg_committed_to.max(pct);
    }

    /// Bookkeeping of one appended log entry (replicated and EC): info versions, the snap-map op of a clone entry
    /// (`applied`), and the objects we do not have (async recovery / log-only entries) stay missing. `ec` selects the
    /// mode O nonprimary skip rule of the missing set.
    pub(crate) fn note_entry(
        &mut self,
        e: &pgwire::LogEntry,
        applied: bool,
        ec: Option<&crate::ecroll::EcCtx>,
        map_ops: &mut Vec<crate::snaps::MapOp>,
    ) {
        if applied && let Some(op) = crate::snaps::entry_op(e) {
            map_ops.push(op);
        }
        if self.info.last_complete == self.info.last_update {
            self.info.last_complete = e.version;
        }
        self.info.last_update = e.version;
        self.info.last_user_version = self.info.last_user_version.max(e.user_version);
        if e.op != pgwire::LogOp::ERROR
            && e.soid <= self.info.last_backfill
            && (!applied || self.missing.contains(&e.soid))
        {
            crate::ecopt::add_next_event(&mut self.missing, ec, e);
        }
    }

    /// Append log entries (spec pglog 6.1). `applied` = a transaction accompanies the entries. `lazy` = a client write on a
    /// store with lazy PG info (`PgStoreOps::lazy_info`): `_info` / `_loghead` may stay behind when only the log progressed.
    pub(crate) fn append_log(
        &mut self,
        entries: Vec<pgwire::LogEntry>,
        trim_to: Eversion,
        pct: Eversion,
        applied: bool,
        lazy: bool,
    ) {
        self.append_log_enc(entries, Vec::new(), trim_to, pct, applied, lazy)
    }

    /// [`Self::append_log`] with the encodings of the entries at hand (`encs[i]` = `entries[i]`; empty = encoded here
    /// when needed): a client write hands them to the store as they are (`StoreOp::LogAppendFast`), the entries move into
    /// the log.
    pub(crate) fn append_log_enc(
        &mut self,
        entries: Vec<pgwire::LogEntry>,
        encs: Vec<bytes::Bytes>,
        trim_to: Eversion,
        pct: Eversion,
        applied: bool,
        lazy: bool,
    ) {
        if self.ec_ctx().is_some() {
            let mode = if applied {
                crate::ecpg::EcAppend::Applied
            } else {
                crate::ecpg::EcAppend::LogOnly
            };
            return self.ec_append_log(entries, trim_to, pct, mode, lazy);
        }
        // a write must never be remembered without the interval it happened in having gone active: the history change is
        // persisted with it (never lazy)
        let hist = self.info.last_epoch_started != self.info.history.last_epoch_started;
        if hist {
            self.info.history.last_epoch_started = self.info.last_epoch_started;
            self.info.history.last_interval_started = self.info.last_interval_started;
        }
        // likely the fast form (decided below, the entries may add missing objects): the entries go to the store encoded
        let pre_fast = lazy && !hist && self.missing.is_empty();
        let mut appended = Vec::with_capacity(if pre_fast { 0 } else { entries.len() });
        let mut enc_out = Vec::with_capacity(if pre_fast { entries.len() } else { 0 });
        let mut encs = encs.into_iter();
        let mut map_ops = Vec::new();
        for e in entries {
            self.note_entry(&e, applied, None, &mut map_ops);
            if pre_fast {
                enc_out.push(match encs.next() {
                    Some(bl) => crate::store::EncLogEntry {
                        version: e.version,
                        bl,
                    },
                    None => crate::store::EncLogEntry::of(&e),
                });
                self.log.append(e);
            } else {
                self.log.append(e.clone());
                appended.push(e);
            }
        }
        // only the log progressed (nothing missing, history as persisted): `_info` / `_loghead` may stay behind, rebuilt at
        // load by `PersistedPg::normalize`
        let fast = pre_fast && self.missing.is_empty();
        if fast {
            if !enc_out.is_empty() {
                self.txn.push(StoreOp::LogAppendFast(enc_out));
            }
        } else {
            if pre_fast {
                // an entry made an object missing: the full form, with the entries
                appended = enc_out
                    .iter()
                    .map(|x| x.entry().expect("own log entry encoding"))
                    .collect();
            }
            if !appended.is_empty() {
                self.txn.push(StoreOp::LogAppend(appended));
            }
        }
        // SnapMapper follows the object change of the same txn (spec snaptrim 4: not for log-only entries)
        if !map_ops.is_empty() {
            self.txn.push(StoreOp::SnapMap(map_ops));
        }
        recompute_last_complete(&self.log, &mut self.info, &self.missing);
        if trim_to != Eversion::default() {
            self.trim_log_to(trim_to);
        }
        self.info.log_tail = self.log.tail();
        self.pg_committed_to = self.pg_committed_to.max(pct);
        if fast {
            self.info_adv = true;
        } else {
            self.info_dirty = true;
        }
    }

    /// Replay the held messages in order up to the first one that still waits (`held::Held::replay`). Called after a store
    /// wake and by the timer. `true` = something was replayed.
    pub fn retry_repops(&mut self, now: Mono, store: &impl PgStoreOps) -> bool {
        if self.held.is_idle() {
            // the EC primary waits for its own shard's blocks: pump again (`after_event`)
            if !self.ep.store_wait {
                return false;
            }
            self.now = now;
            self.after_event(store);
            return true;
        }
        self.now = now;
        self.held_complaint();
        self.replay(now, store);
        self.after_event(store);
        true
    }

    fn replay(&mut self, now: Mono, store: &impl PgStoreOps) {
        self.now = now;
        let mut held = std::mem::take(&mut self.held);
        held.replay(false, &mut PgStep::new(self, store));
        self.put_held(held);
    }

    /// Are the pgmeta pages the next log entry of this PG lands on resident (`PgStoreOps::warm_log`)?
    pub fn warm_log(&self, store: &impl PgStoreOps) -> bool {
        store.warm_log(self.spg, self.log.head())
    }

    /// Messages held for the store, the waiting head included (adr 0021 am. 25, `held::Held`).
    pub fn repops_held(&self) -> usize {
        self.held.len()
    }

    /// What the held head waits for (`tell dump_pgs`; `-` = nothing held).
    pub fn held_head(&self, now: Mono) -> String {
        self.held.describe(now)
    }

    /// Must the repop wait for cold store pages? It waits until its loads complete (store wakes retry it), never for a
    /// time or retry bound: an apply only hands the txn to the store queue and the reply still waits for its commit. A
    /// held head older than `REPOP_HELD_COMPLAINT_NS` is reported (`held_complaint`).
    /// The caller handled the forced replay (`Probe::force`) and asked `PgStoreOps::probe_cold_for`; the probes run under
    /// `probe.lease`.
    fn repop_must_wait(
        &self,
        t: &replwire::Transaction<'_>,
        store: &impl PgStoreOps,
        probe: &Probe,
    ) -> Option<WaitOn> {
        // Cold tree pages of the objects the txn touches (adr 0021 am. 8, the same probe a client op passes at the gate): park
        // the repop until the loads are in instead of spinning the core on them inside the apply. Every object is probed so
        // the loads overlap; the head waits until they complete.
        let cold = with_lease(store, probe.lease, || {
            let mut cold = false;
            for op in &t.ops {
                let (oid, off, len) = match &op.op {
                    replwire::TxnOp::Write { oid, off, data } => (oid, *off, data.len() as u64),
                    replwire::TxnOp::Zero { oid, off, len } => (oid, *off, *len),
                    replwire::TxnOp::SetAttr { oid, .. }
                    | replwire::TxnOp::SetAttrs { oid, .. }
                    | replwire::TxnOp::RmAttr { oid, .. }
                    | replwire::TxnOp::Truncate { oid, .. }
                    | replwire::TxnOp::Touch { oid }
                    | replwire::TxnOp::Create { oid } => (oid, 0, 0),
                    replwire::TxnOp::Remove { oid } => {
                        let g = t.get_obj(*oid);
                        if !g.is_pgmeta() && g.generation == denc::types::Ghobject::NO_GEN {
                            cold |= !store.warm_rm(self.spg, &g.hobj);
                        }
                        continue;
                    }
                    _ => continue,
                };
                let g = t.get_obj(*oid);
                if g.is_pgmeta() || g.generation != denc::types::Ghobject::NO_GEN {
                    continue;
                }
                cold |= !store.warm(self.spg, &g.hobj, off, len);
            }
            cold |= !store.warm_log(self.spg, self.log.head());
            cold
        });
        cold.then_some(WaitOn::Loads)
    }

    /// Open a residency lease (0 = the store needs none); the PG counts what it holds.
    pub(crate) fn lease_open(&mut self, store: &impl PgStoreOps) -> u64 {
        let lease = store.lease_open(self.spg);
        if lease != 0 {
            self.leases += 1;
        }
        lease
    }

    /// Release a lease opened by [`Pg::lease_open`] (0 = none).
    pub(crate) fn lease_release(&mut self, store: &impl PgStoreOps, lease: u64) {
        if lease != 0 {
            store.lease_release(lease);
            self.leases = self.leases.saturating_sub(1);
        }
    }

    /// Drop every message held for the store (the PG stops serving them: merge quiesce, move to another core).
    pub(crate) fn drop_held(&mut self) {
        self.held.clear();
    }

    /// Release every residency lease of this PG (interval change, merge quiesce): the waiting ops are gone.
    pub(crate) fn release_leases(&mut self, store: &impl PgStoreOps) {
        self.held.forget_lease();
        if std::mem::take(&mut self.leases) != 0 {
            store.lease_release_pg(self.spg);
        }
    }

    /// Since when the head replica write waits for its store loads (None: no such wait); slow-op accounting.
    pub fn repops_held_since(&self) -> Option<Mono> {
        self.held.since()
    }

    /// Loud report of a head held longer than `REPOP_HELD_COMPLAINT_NS` (once per period; the wait goes on).
    fn held_complaint(&mut self) {
        let (now, spg) = (self.now, self.spg);
        self.held.complain(now, |secs, msgs| {
            format!(
                "pg {spg}, held {secs} s, {msgs} msgs held; still waiting, nothing applied or acked"
            )
        });
    }

    /// Space preflight of a replica write (adr 0021 S4): true = its store shard is at its system floor, the repop is held
    /// (no ack, nothing applied) until store progress (checkpoint, deletes, pool chunks) makes room; a held write is
    /// never forced. Cheap bound from the wire sizes first (the object scan only when the bound fits), the decoded txn's
    /// exact cost only when the bound does not fit.
    fn repop_space_held(&mut self, m: &MOSDRepOp, nops: usize, store: &impl PgStoreOps) -> bool {
        use replwire::Transaction as T;
        let (mid, data) = (&m.txn_middle[..], &m.txn_data[..]);
        let (b, e) = T::room_bound(mid, data, nops);
        let fits = (store.apply_room(self.spg, b, e)
            && !T::expands_objects(mid, data).unwrap_or(true))
            || match m.txn(self.cfg.page) {
                Ok(t) => {
                    let (b, e) = t.room_cost();
                    store.apply_room(self.spg, b, e)
                }
                Err(_) => true, // refused by the apply path
            };
        self.space_held(fits)
    }

    /// Record the space verdict of the head replica / sub-write: one operator note per change. True = hold it.
    pub(crate) fn space_held(&mut self, fits: bool) -> bool {
        if fits == self.space_wait {
            self.space_wait = !fits;
            self.notes.push(if fits {
                format!("pg {}: store space is back, held replica writes apply", self.spg)
            } else {
                format!(
                    "pg {}: replica write held: its store shard is at its system floor (full); nothing applied, \
                     retried after store progress",
                    self.spg
                )
            });
        }
        !fits
    }

    /// `Some((m, on))` = the repop must wait for `on` (nothing applied, nothing logged): the caller holds it. Every check
    /// that drops it runs first: a dropped repop never opens a wait (lease, slow-op clock, space note).
    fn on_repop(
        &mut self,
        from: i32,
        tid: u64,
        m: MOSDRepOp,
        store: &impl PgStoreOps,
        probe: &mut Probe,
    ) -> Option<(MOSDRepOp, WaitOn)> {
        if self.st != St::ReplicaActive {
            self.discard("repop in non-active state");
            return None;
        }
        if from != self.acting_primary {
            self.discard("repop from non-primary");
            return None;
        }
        // A repop always ships its log entries (replication.md 3.3; classic asserts a non-empty `logbl`): a replica never
        // applies a transaction without the log that describes it. Fail-stop like a bad entry (adr 0066), nothing
        // applied or acked; an encoded empty vector is accepted like classic does (temp-object writes carry no entry).
        if m.logbl.is_empty() {
            self.fatal("repop: empty logbl");
            return None;
        }
        // with the slice of every entry: the store writes those bytes as they are
        let (entries, encs) = match crate::plog::decode_log_entries(&m.logbl) {
            Ok(e) => e,
            Err(_) => {
                self.fatal("repop: bad log entries");
                return None;
            }
        };
        // A duplicate (every entry already in our log): the original is acked or will be (its RepOpReply waits in
        // `pending` for this interval; a new interval aborts the primary's repops anyway); applying it again would
        // re-run its transaction over newer state. Never ack it a second time: a classic primary asserts
        // `waiting_for_commit.count(from)` on a reply for a still-in-progress tid it already got ours for. After a
        // divergent rewind (new interval only) new entries carry the new epoch, so `version > last_update` holds.
        if entries
            .last()
            .is_some_and(|e| e.version <= self.info.last_update)
        {
            let n = self
                .counters
                .discards
                .get("duplicate repop")
                .copied()
                .unwrap_or(0)
                + 1;
            if n.is_power_of_two() {
                self.notes.push(format!(
                    "pg {}: duplicate repop from osd.{from} tid {tid}: entries {:?}..{:?}, last_update {:?} [{n}x]",
                    self.spg,
                    entries.first().map(|e| e.version),
                    entries.last().map(|e| e.version),
                    self.info.last_update
                ));
            }
            self.discard("duplicate repop");
            return None;
        }
        let mut prev = self.info.last_update;
        for e in &entries {
            if e.version <= prev {
                self.fatal("repop: version not increasing");
                return None;
            }
            prev = e.version;
        }
        // The store apply decodes the txn anyway: the op records (count, codes) suffice here unless the wait probe needs
        // the objects (cold probing).
        let Ok(nops) = replwire::Transaction::peek(&m.txn_middle, &m.txn_data) else {
            self.fatal("repop: bad transaction");
            return None;
        };
        let wait = if !store.admission_ready_for(self.spg) {
            Some(WaitOn::Admission)
        } else if self.repop_space_held(&m, nops, store) {
            Some(WaitOn::Space)
        } else if std::mem::take(&mut probe.force) || !store.probe_cold_for(self.spg) {
            None
        } else {
            match m.txn(self.cfg.page) {
                Ok(t) => self.repop_must_wait(&t, store, probe),
                Err(_) => {
                    self.fatal("repop: bad transaction");
                    return None;
                }
            }
        };
        if let Some(on) = wait {
            return Some((m, on));
        }
        let applied = nops > 0;
        let (middle, data) = (m.txn_middle.clone(), m.txn_data.clone());
        let min = Hobject::MIN();
        if m.new_temp_oid != min {
            self.temps.insert(m.new_temp_oid.clone());
        }
        if m.discard_temp_oid != min {
            self.temps.remove(&m.discard_temp_oid);
            if !applied {
                self.txn
                    .push(StoreOp::RemoveObject(m.discard_temp_oid.clone()));
            }
        }
        if let Some(st) = self.stat_cache.decode(&m.pg_stats)
            && self.info.stats != *st
        {
            self.info.stats = st.clone();
        }
        // classic captures the repop's lcod before its append (spec replication.md 3.3: never above durable)
        let lcod = self.info.last_complete;
        self.append_log_enc(
            entries,
            encs,
            m.pg_trim_to,
            m.pg_committed_to,
            applied,
            store.lazy_info(),
        );
        if applied {
            self.txn.push(StoreOp::ApplyTxn { middle, data });
            if m.txn_data_crc.of(&m.txn_data).is_some() {
                self.txn.push(StoreOp::TxnHint(m.txn_data_crc.clone()));
            }
        }
        let reply = MOSDRepOpReply {
            map_epoch: self.map.epoch(),
            min_epoch: m.min_epoch,
            trace: [0; 3],
            reqid: m.reqid,
            pgid: SpgT {
                pgid: self.spg.pgid,
                shard: m.from.shard,
            },
            ack_type: MOSDRepOp::ACK_ONDISK,
            result: 0,
            last_complete_ondisk: lcod,
            from: self.me,
        };
        let interval = self.last_peering_reset;
        self.flush(Pending::RepOpReply {
            interval,
            to: from,
            tid,
            reply,
        });
        None
    }

    pub(crate) fn on_update_log_missing(&mut self, from: i32, tid: u64, m: MOSDPGUpdateLogMissing) {
        if self.st != St::ReplicaActive || from != self.acting_primary {
            self.discard("update_log_missing in wrong state");
            return;
        }
        let entries: Vec<pgwire::LogEntry> = match denc::from_slice(&m.entries) {
            Ok(e) => e,
            Err(_) => {
                self.fatal("update_log_missing: bad entries");
                return;
            }
        };
        // duplicate: neither append again (log corruption) nor ack twice (classic primary: clog error); see on_repop
        if entries
            .last()
            .is_some_and(|e| e.version <= self.info.last_update)
        {
            self.discard("duplicate update_log_missing");
            return;
        }
        let mut prev = self.info.last_update;
        for e in &entries {
            if e.version <= prev {
                self.fatal("update_log_missing: version not increasing");
                return;
            }
            prev = e.version;
        }
        self.append_log(entries, m.pg_trim_to, m.pg_committed_to, false, false);
        let reply = MOSDPGUpdateLogMissingReply {
            map_epoch: self.map.epoch(),
            pgid: SpgT {
                pgid: self.spg.pgid,
                shard: m.from,
            },
            from: self.me.shard,
            rep_tid: m.rep_tid,
            min_epoch: m.min_epoch,
            last_complete_ondisk: self.info.last_complete,
        };
        let interval = self.last_peering_reset;
        self.flush(Pending::LogMissingReply {
            interval,
            to: from,
            tid,
            reply,
        });
    }

    // ---- delete ------------------------------------------------------------------------------

    /// A peer may purge only a stray copy, as the current acting primary (peering.md 7.5).
    /// Stopped copies remain removable even when mapped here; local pool removal uses `delete_start` directly.
    fn on_remove(&mut self, from: i32, epoch: u32) {
        if from != self.acting_primary || !self.map.is_up(from) || self.map.up_from(from) > epoch {
            self.discard("remove from non-primary or restarted peer");
            return;
        }
        if self.bounds_stop.is_none() && !self.is_stray_shard(self.me) {
            self.discard("remove for a mapped copy");
            return;
        }
        self.delete_start();
    }

    /// `DeleteStart` (peering.md 7.5): the PG leaves through one removal transaction, nothing else. A PG stopped by the
    /// past-interval bounds check (3.8) never peers and is no live member, so a removal (pool deleted, MOSDPGRemove) is
    /// the one transition it still takes; it writes only the removal and never repairs the pair. A PG whose removal is
    /// already pending (`ToDelete`) takes no second one, stopped or not.
    pub(crate) fn delete_start(&mut self) {
        if self.st == St::ToDelete
            || (!matches!(self.st, St::Stray | St::ReplicaActive) && self.bounds_stop.is_none())
        {
            self.discard("delete in wrong state");
            return;
        }
        self.set_st(St::ToDelete);
        self.on_leave_primary_or_replica();
        self.txn.clear();
        self.txn.push(StoreOp::RemovePg);
        self.info_dirty = false;
        self.past_dirty = false;
        self.missing = MissingSet::new(true);
        self.flush(Pending::Delete);
    }

    // ---- misc --------------------------------------------------------------------------------

    /// All acting peers, including other shard positions on our own OSD.
    pub(crate) fn peer_shards_acting(&self) -> Vec<PgShard> {
        self.acting
            .iter()
            .enumerate()
            .filter_map(|(i, &osd)| {
                let p = PgShard {
                    osd,
                    shard: if self.pool.is_erasure {
                        ShardId(i as i8)
                    } else {
                        ShardId::NO_SHARD
                    },
                };
                (osd >= 0 && osd != pgwire::NONE_OSD && p != self.me).then_some(p)
            })
            .collect()
    }

    pub(crate) fn peer_osds_acting(&self) -> Vec<i32> {
        self.acting
            .iter()
            .copied()
            .filter(|o| *o != self.me.osd && *o >= 0 && *o != pgwire::NONE_OSD)
            .collect()
    }
}

/// The PG side of the held queue (`held::Step`): runs messages through `Pg::dispatch`, opens and releases the head's
/// residency lease, and sees the persists emitted since it began.
struct PgStep<'a, S> {
    pg: &'a mut Pg,
    store: &'a S,
    start: usize,
}

impl<'a, S: PgStoreOps> PgStep<'a, S> {
    fn new(pg: &'a mut Pg, store: &'a S) -> Self {
        let start = pg.out.len();
        PgStep { pg, store, start }
    }
}

impl<S: PgStoreOps> Step<Inbound> for PgStep<'_, S> {
    fn eval(&mut self, m: Inbound, probe: &mut Probe) -> Option<(Inbound, WaitOn)> {
        self.pg.dispatch(m, self.store, probe)
    }
    fn persisted(&self) -> bool {
        self.pg.out[self.start..]
            .iter()
            .any(|a| matches!(a, Action::Persist { .. }))
    }
    fn lease_open(&mut self) -> u64 {
        self.pg.lease_open(self.store)
    }
    fn lease_release(&mut self, lease: u64) {
        self.pg.lease_release(self.store, lease);
    }
    fn now(&self) -> Mono {
        self.pg.now
    }
    /// Sub-reads start their block reads while they queue (adr 0636 am. 1); sub-writes and the replicated data path
    /// apply in order and load at their own turn.
    fn kick(&mut self, m: &Inbound) -> bool {
        match &*m.body {
            Body::Ec(ecwire::EcMsg::Read(x)) => self.pg.ec_read_kick(m.from, x, self.store),
            _ => true,
        }
    }
}

impl HeldMsg for Inbound {
    fn held_bytes(&self) -> usize {
        match &*self.body {
            Body::Repl(ReplMsg::RepOp(r)) => r.logbl.len() + r.txn_middle.len() + r.txn_data.len(),
            Body::Ec(ecwire::EcMsg::Write(w)) => w.op.txn_middle.len() + w.op.txn_data.len(),
            _ => 0,
        }
    }
    fn behind(&self) -> bool {
        held_behind(&self.body)
    }
}

/// Does a message queue behind a held repop (adr 0021 am. 25)? Everything of the replica data path whose effect or
/// answer depends on the repops before it: classic applies them in arrival order (repop, log update, pct, scrub chunk
/// request = map of the applied state, backfill scan/progress, push/pull/delete, trim, primary info = purged snaps after
/// the trim repops). Not: peering control of a new interval (notify/query/log/remove: the interval clears the queue)
/// and read leases (time-bound, order-free). EC messages never meet a held repop (replicated pools only).
/// Held messages that only queue a transaction behind the previous ones (the store applies them in order; nothing is
/// read for an answer before that): a replay may run several of them in one call.
pub(crate) fn held_behind(b: &Body) -> bool {
    match b {
        Body::Repl(_) => true,
        Body::Peering(p) => matches!(
            p,
            PeeringMsg::MOSDPGPCT(_)
                | PeeringMsg::MOSDPGTrim(_)
                | PeeringMsg::MOSDPGInfo2(_)
                | PeeringMsg::MOSDPGRecoveryDelete(_)
        ),
        // sub-writes / sub-reads of a shard wait for their blocks in order (`ec_must_wait`); replies are the primary's
        Body::Ec(ecwire::EcMsg::Write(_) | ecwire::EcMsg::Read(_)) => true,
        Body::Ec(_) => false,
    }
}

/// `(map_epoch, min_epoch, data_path)` of any PG message (peering.md 4.1, replication.md 3).
pub fn gating_of(b: &Body) -> (u32, u32, bool) {
    match b {
        Body::Peering(p) => {
            let (a, b) = p.gating();
            let data = matches!(
                p,
                PeeringMsg::MOSDPGPCT(_)
                    | PeeringMsg::MOSDPGRecoveryDelete(_)
                    | PeeringMsg::MOSDPGRecoveryDeleteReply(_)
            );
            (a, b, data)
        }
        Body::Repl(r) => match r {
            ReplMsg::RepOp(m) => (m.map_epoch, m.min_epoch, true),
            ReplMsg::RepOpReply(m) => (m.map_epoch, m.min_epoch, true),
            ReplMsg::UpdateLogMissing(m) => (m.map_epoch, m.min_epoch, true),
            ReplMsg::UpdateLogMissingReply(m) => (m.map_epoch, m.min_epoch, true),
            ReplMsg::Pct(m) => (m.map_epoch, m.min_epoch, true),
            ReplMsg::Push(m) => (m.map_epoch, m.min_epoch, true),
            ReplMsg::PushReply(m) => (m.map_epoch, m.min_epoch, true),
            ReplMsg::Pull(m) => (m.map_epoch, m.min_epoch, true),
            ReplMsg::RecoveryDelete(m) => (m.map_epoch, m.min_epoch, true),
            ReplMsg::RecoveryDeleteReply(m) => (m.map_epoch, m.min_epoch, true),
            ReplMsg::Scan(m) => (m.map_epoch, m.query_epoch, false),
            ReplMsg::Backfill(m) => (m.map_epoch, m.query_epoch, false),
            ReplMsg::BackfillRemove(m) => (m.map_epoch, m.map_epoch, false),
            ReplMsg::BackfillReserve(m) => (m.query_epoch, m.query_epoch, false),
            ReplMsg::RecoveryReserve(m) => (m.query_epoch, m.query_epoch, false),
            ReplMsg::ScrubReserve(m) => (m.map_epoch, m.map_epoch, true),
            ReplMsg::RepScrub(m) => (m.map_epoch, m.min_epoch, true),
            ReplMsg::RepScrubMap(m) => (m.map_epoch, m.map_epoch, true),
            ReplMsg::Scrub2(m) => (m.epoch, m.epoch, false),
            ReplMsg::ForceRecovery(_) => (0, 0, false),
        },
        Body::Ec(m) => {
            let (a, b) = m.gating();
            (a, b, true)
        }
    }
}

/// Staleness floor of PG message `b` (peering.md 7.3): a receiver whose interval started after it discards `b` (as
/// after its `map_epoch`). `min_epoch` for peering messages, scrub chunks (classic checks those against the interval
/// start in the scrubber) and sub-op replies (they echo the request's `min_epoch`: the primary's interval start). `map_epoch` for the requests a replica or stray answers and for recovery data, as
/// classic `can_discard_replica_op` (`old_peering_msg(map_epoch, map_epoch)`): their `min_epoch` is the map the
/// receiver needs, not a floor. A receiver whose reset is newer than the sender's interval start without a new interval
/// (a stray restarted after the primary's interval began) must still answer: a Pull or sub-read dropped there leaves an
/// unfound object unrecovered (storms, seed 4577); a sub-write or log update dropped there stays unanswered while the
/// primary sees no new interval, nothing would end it (no repop timer, adr 0084 am. 5). RecoveryDelete(+Reply) arrive
/// as `Body::Peering` (decoded by pgwire first). `map_epoch` / `min_epoch` are `gating_of(b)`'s.
pub(crate) fn stale_floor(b: &Body, map_epoch: u32, min_epoch: u32) -> u32 {
    let by_map_epoch = matches!(
        b,
        Body::Repl(
            ReplMsg::RepOp(_)
                | ReplMsg::UpdateLogMissing(_)
                | ReplMsg::Push(_)
                | ReplMsg::Pull(_)
                | ReplMsg::PushReply(_)
                | ReplMsg::RecoveryDelete(_)
                | ReplMsg::RecoveryDeleteReply(_)
        ) | Body::Peering(
            PeeringMsg::MOSDPGRecoveryDelete(_) | PeeringMsg::MOSDPGRecoveryDeleteReply(_)
        ) | Body::Ec(ecwire::EcMsg::Write(_) | ecwire::EcMsg::Read(_))
    );
    if by_map_epoch { map_epoch } else { min_epoch }
}

/// Epoch of the message used by `PgSet` to wait for the map.
pub(crate) fn wait_epoch(b: &Body) -> u32 {
    let (a, _, _) = gating_of(b);
    a
}

impl Pg {
    /// The pg_temp we asked the mon for and still await (any primary state: also the clear after recovery).
    pub fn pending_pg_temp(&self) -> Option<Vec<i32>> {
        if matches!(self.st, St::Primary(_)) {
            self.prim.pending_temp.clone()
        } else {
            None
        }
    }
}

impl Pg {
    /// Why this PG refuses to peer, if it does (erasure pools).
    pub fn refusal(&self) -> Option<&'static str> {
        self.refuse
    }

    /// Op-layer gate (peering.md 7.3 point 4): a client op stamped with `op_epoch` is dropped
    /// (client resends) if it predates the current primary/interval or a split.
    pub fn client_op_stale(&self, op_epoch: u32) -> bool {
        op_epoch < self.client_op_floor()
    }

    /// Oldest op epoch [`Pg::client_op_stale`] keeps: the later of the current primary's start and the last split.
    pub fn client_op_floor(&self) -> u32 {
        self.info
            .history
            .same_primary_since
            .max(self.info.history.last_epoch_split)
    }
}

#[cfg(test)]
mod lazy_info_tests {
    //! Lazy PG info (adr 0021 am. 27): which client-write txns may leave `_info` / `_loghead` behind, and that a store
    //! reloading the persisted ops rebuilds exactly the in-memory info.
    use super::*;
    use crate::map::synth::SynthMap;
    use crate::store::{MemStore, PgStoreOps};
    use denc::types::{PgT, SnapId};

    fn spg() -> SpgT {
        SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        }
    }
    fn pg() -> Pg {
        let map: MapHandle = std::rc::Rc::new(SynthMap::new(5).with_pool(1, 3, 2, 1));
        let mut info = PgInfo::new(spg());
        info.history.same_interval_since = 5;
        (info.last_epoch_started, info.history.last_epoch_started) = (5, 5);
        Pg::blank(Arc::new(Config::new(0)), spg(), map, info)
    }
    fn entry(v: u64) -> pgwire::LogEntry {
        let o = Hobject::new(b"o", SnapId::NOSNAP, 7, 1, b"");
        let mut e = pgwire::LogEntry::new(
            pgwire::LogOp::MODIFY,
            o,
            Eversion::new(5, v),
            Eversion::default(),
        );
        e.user_version = v;
        e
    }
    /// Flush as the given kind, apply to `st`, return the ops.
    fn persist(pg: &mut Pg, st: &mut MemStore, write: bool) -> Vec<StoreOp> {
        let kind = if write {
            Pending::LocalWrite {
                interval: 0,
                tid: 1,
            }
        } else {
            Pending::Plain
        };
        pg.flush(kind);
        let mut ops = Vec::new();
        for a in std::mem::take(&mut pg.out) {
            if let Action::Persist { txn, .. } = a {
                st.submit(spg(), &txn);
                ops.extend(txn.ops);
            }
        }
        ops
    }
    fn has_info(ops: &[StoreOp]) -> bool {
        ops.iter().any(|o| matches!(o, StoreOp::PutInfo(_)))
    }
    fn reloaded_matches(pg: &Pg, st: &MemStore) {
        let mut p = st.load_pg(spg()).expect("persisted");
        p.info.stats = pg.info.stats.clone(); // approximate after lazy writes (stats_invalid), see `normalize`
        assert_eq!(p.info, pg.info, "reloaded info");
        assert_eq!(p.log.head, pg.log.head(), "reloaded head");
        assert_eq!(p.log.tail, pg.log.tail(), "reloaded tail");
        assert_eq!(p.log.log, pg.log.log.log, "reloaded entries");
    }

    #[test]
    fn log_progress_is_lazy_history_and_missing_are_not() {
        let mut st = MemStore::new();
        let mut pg = pg();
        pg.txn.push(StoreOp::CreatePg);
        pg.info_dirty = true;
        persist(&mut pg, &mut st, false);
        // plain write: entries only
        pg.append_log(
            vec![entry(1)],
            Eversion::default(),
            Eversion::default(),
            true,
            true,
        );
        let ops = persist(&mut pg, &mut st, true);
        assert!(!has_info(&ops) && ops.iter().any(|o| matches!(o, StoreOp::LogAppendFast(_))));
        reloaded_matches(&pg, &st);
        assert!(
            st.load_pg(spg()).unwrap().info.stats.stats_invalid,
            "stats behind the log are marked approximate"
        );
        // the interval went active since the history was persisted (replica, primary's info not here yet): the write
        // must carry the history (classic: never remember a write without its interval having gone active)
        pg.info.last_epoch_started = 6;
        pg.info.last_interval_started = 6;
        pg.append_log(
            vec![entry(2)],
            Eversion::default(),
            Eversion::default(),
            true,
            true,
        );
        let ops = persist(&mut pg, &mut st, true);
        assert!(
            has_info(&ops),
            "history change persisted with the write: {ops:?}"
        );
        assert_eq!(
            st.load_pg(spg()).unwrap().info.history.last_epoch_started,
            6
        );
        reloaded_matches(&pg, &st);
        // a store without the feature: every write persists info and head
        let mut old = MemStore {
            eager_info: true,
            ..Default::default()
        };
        assert!(!old.lazy_info());
        let mut q = self::pg();
        q.txn.push(StoreOp::CreatePg);
        q.info_dirty = true;
        persist(&mut q, &mut old, false);
        q.append_log(
            vec![entry(1)],
            Eversion::default(),
            Eversion::default(),
            true,
            old.lazy_info(),
        );
        let ops = persist(&mut q, &mut old, true);
        assert!(has_info(&ops) && ops.iter().any(|o| matches!(o, StoreOp::LogAppend(_))));
        assert!(!ops.iter().any(|o| matches!(o, StoreOp::LogAppendFast(_))));
    }

    #[test]
    fn head_follows_info_and_a_log_trimmed_empty_reloads_at_its_tail() {
        let mut st = MemStore::new();
        let mut pg = pg();
        pg.txn.push(StoreOp::CreatePg);
        pg.info_dirty = true;
        persist(&mut pg, &mut st, false);
        for v in 1..=5 {
            pg.append_log(
                vec![entry(v)],
                Eversion::default(),
                Eversion::default(),
                true,
                true,
            );
            persist(&mut pg, &mut st, true);
        }
        assert!(pg.head_stale);
        // a non-write txn writes the info and the stale head with it
        pg.info_dirty = true;
        let ops = persist(&mut pg, &mut st, false);
        assert!(
            ops.iter()
                .any(|o| matches!(o, StoreOp::LogSetHead(h) if *h == Eversion::new(5, 5)))
        );
        assert!(!pg.head_stale);
        for v in 6..=8 {
            pg.append_log(
                vec![entry(v)],
                Eversion::default(),
                Eversion::default(),
                true,
                true,
            );
            persist(&mut pg, &mut st, true);
        }
        // trim everything in its own txn (e.g. MOSDPGTrim): the reloaded head is the tail, never the stale `_loghead`
        pg.trim_log_to(Eversion::new(5, 8));
        persist(&mut pg, &mut st, false);
        assert!(pg.log.is_empty());
        reloaded_matches(&pg, &st);
        st.pgs.get_mut(&spg()).unwrap().p.log.head = Eversion::new(5, 5); // as if the head write were lost
        let p = st.load_pg(spg()).unwrap();
        assert_eq!(
            (p.log.head, p.info.last_update),
            (Eversion::new(5, 8), Eversion::new(5, 8))
        );
    }
}

/// The `pg_stat_t` of a repop is the same bytes for thousands of writes in a row (it changes with the PG state and stat
/// refreshes, not per write), but encoding / decoding it costs ~0.6 us. Primary: the encoding of the last value, kept while
/// `info.stats` compares equal. Replica: the decode of the last bytes, handed out again while the bytes are the same.
#[derive(Default)]
pub(crate) struct StatCache {
    sent: Option<(pgwire::PgStat, bytes::Bytes)>,
    seen: Option<(bytes::Bytes, pgwire::PgStat)>,
}

impl StatCache {
    pub(crate) fn encode(&mut self, s: &pgwire::PgStat) -> bytes::Bytes {
        if let Some((v, b)) = &self.sent
            && v == s
        {
            return b.clone();
        }
        let b: bytes::Bytes = denc::to_vec(s).expect("encode stats").into();
        self.sent = Some((s.clone(), b.clone()));
        b
    }

    pub(crate) fn decode(&mut self, raw: &bytes::Bytes) -> Option<&pgwire::PgStat> {
        if self.seen.as_ref().is_none_or(|(b, _)| b != raw) {
            let v = denc::from_slice::<pgwire::PgStat>(raw).ok()?;
            self.seen = Some((raw.clone(), v));
        }
        self.seen.as_ref().map(|(_, v)| v)
    }
}

#[cfg(test)]
mod stat_cache_tests {
    use super::*;

    #[test]
    fn encode_is_reused_until_the_value_changes() {
        let mut c = StatCache::default();
        let mut s = pgwire::PgStat::default();
        let a = c.encode(&s);
        assert_eq!(a[..], denc::to_vec(&s).unwrap()[..]);
        let b = c.encode(&s);
        assert_eq!(a.as_ptr(), b.as_ptr(), "same value: the cached bytes");
        s.reported_seq += 1;
        let d = c.encode(&s);
        assert_ne!(a[..], d[..]);
        assert_eq!(
            d[..],
            denc::to_vec(&s).unwrap()[..],
            "changed value: fresh encode"
        );
        assert_eq!(c.encode(&s).as_ptr(), d.as_ptr());
    }

    #[test]
    fn decode_is_reused_while_the_bytes_are_the_same() {
        let mut c = StatCache::default();
        let mut s = pgwire::PgStat {
            reported_seq: 7,
            ..Default::default()
        };
        let raw: bytes::Bytes = denc::to_vec(&s).unwrap().into();
        assert_eq!(c.decode(&raw), Some(&s));
        let p = c.seen.as_ref().map(|(_, v)| v as *const _);
        assert_eq!(c.decode(&raw), Some(&s));
        assert_eq!(
            c.seen.as_ref().map(|(_, v)| v as *const _),
            p,
            "no second decode"
        );
        s.reported_seq = 8;
        let raw2: bytes::Bytes = denc::to_vec(&s).unwrap().into();
        assert_eq!(c.decode(&raw2), Some(&s));
        assert_eq!(c.decode(&bytes::Bytes::from_static(b"junk")), None);
    }
}

#[cfg(test)]
mod local_shard_tests {
    use super::*;
    use crate::map::synth::SynthMap;

    fn peer(osd: i32, shard: i8) -> PgShard {
        PgShard {
            osd,
            shard: ShardId(shard),
        }
    }

    fn pg(shard: i8) -> Pg {
        let spg = SpgT {
            pgid: denc::types::PgT::new(1, 0),
            shard: ShardId(shard),
        };
        let map: MapHandle = std::rc::Rc::new(SynthMap::new(5).with_pool(1, 3, 2, 1));
        let mut pg = Pg::blank(Arc::new(Config::new(0)), spg, map, PgInfo::new(spg));
        pg.pool.is_erasure = true;
        pg.acting = vec![0, 1, 2];
        pg.up = vec![0, 1, 0];
        pg.acting_primary = 0;
        pg
    }

    #[test]
    fn local_backfill_is_not_acting_or_degraded_and_local_stray_is_not_authoritative() {
        let mut pg = pg(0);
        let local = peer(0, 2);
        assert!(!pg.in_acting(local));
        assert!(!pg.is_stray_shard(local), "up target is not a stray");
        pg.prim.backfill_targets.insert(local);
        pg.update_degraded_bits();
        assert_eq!(pg.state & pgs::DEGRADED, 0);
        pg.up = pg.acting.clone();
        assert!(pg.is_stray_shard(local));
        let mut stray = PgInfo::new(SpgT {
            pgid: pg.spg.pgid,
            shard: local.shard,
        });
        stray.last_update = Eversion::new(5, 2);
        stray.last_complete = stray.last_update;
        let infos = [(local, &stray)].into_iter().collect();
        assert_eq!(pg.find_best_info(&infos, true, false, false), None);
        assert_eq!(pg.find_best_info(&infos, false, false, false), Some(local));
    }

    #[test]
    fn optimized_local_backfill_log_advances_and_invalidates_pwlc() {
        let mut pg = pg(2);
        pg.pool.ec = Some(Arc::new(pgwire::EcPoolInfo {
            k: 2,
            m: 1,
            stripe_width: 8192,
            chunk_size: 4096,
            supported: true,
            optimized: true,
            chunk_mapping: vec![0, 1, 2],
            ..Default::default()
        }));
        pg.info.partial_writes_last_complete_epoch = 5;
        pg.info
            .partial_writes_last_complete
            .insert(ShardId(2), (Eversion::new(5, 1), Eversion::new(5, 1)));
        let v = Eversion::new(5, 10);
        let entry = pgwire::LogEntry::new(
            pgwire::LogOp::ERROR,
            Hobject::new(b"o", denc::types::SnapId::NOSNAP, 0, 1, b""),
            v,
            Eversion::default(),
        );
        pg.ec_append_log(
            vec![entry],
            Eversion::default(),
            Eversion::default(),
            crate::ecpg::EcAppend::Applied,
            false,
        );
        assert_eq!(pg.log.log.can_rollback_to, v);
        assert_eq!(pg.info.partial_writes_last_complete_epoch, 0);
        assert_eq!(
            pg.info.partial_writes_last_complete[&ShardId(2)],
            (crate::ecopt::PWLC_INVALID, crate::ecopt::PWLC_INVALID)
        );
    }

    #[test]
    fn created_and_reloaded_local_nonprimary_shards_notify() {
        use crate::store::{MemStore, PgStoreOps};
        let pgid = denc::types::PgT::new(1, 0);
        let spg = SpgT {
            pgid,
            shard: ShardId(2),
        };
        let mut m = SynthMap::new(5)
            .with_pool(1, 3, 2, 1)
            .with_osd(0, 1)
            .with_osd(1, 1)
            .with_osd(2, 1);
        m.pools.get_mut(&1).unwrap().is_erasure = true;
        m.up_override.insert(pgid, vec![0, 1, 2]);
        let map: MapHandle = std::rc::Rc::new(m);
        let cfg = Arc::new(Config::new(0));
        let mut pg = Pg::create(
            cfg.clone(),
            spg,
            map.clone(),
            PgHistory::default(),
            PastIntervals::default(),
            0,
        );
        assert!(pg.send_notify);
        let mut store = MemStore::new();
        for a in std::mem::take(&mut pg.out) {
            if let Action::Persist { txn, .. } = a {
                store.submit(spg, &txn);
            }
        }
        let pg = Pg::load(cfg, spg, store.load_pg(spg).unwrap(), map, 0);
        assert!(pg.send_notify);
    }

    #[test]
    fn local_nonacting_activation_preserves_started_history() {
        let mut pg = pg(2);
        pg.info.last_epoch_started = 3;
        pg.info.last_interval_started = 2;
        pg.info.last_update = Eversion::new(4, 10);
        pg.begin_activate(5);
        assert_eq!(pg.info.last_epoch_started, 3);
        assert_eq!(pg.info.last_interval_started, 2);
        assert_eq!(pg.pg_committed_to, Eversion::default());
    }

    #[test]
    fn local_write_reply_advances_the_exact_peer_lcod() {
        let mut pg = pg(0);
        pg.st = St::Primary(PSt::Active(ASt::NotRecovering));
        let local = peer(0, 2);
        let remote = peer(1, 1);
        let v = Eversion::new(5, 10);
        pg.info.last_complete = v;
        pg.prim.acting_recovery_backfill = [pg.me, local, remote].into_iter().collect();
        pg.prim.peer_lcod.insert(remote, v);
        pg.prim.repops.insert(
            7,
            crate::primary::RepOp {
                version: v,
                waiting: [local].into_iter().collect(),
                local_done: false,
                ec_objects: Vec::new(),
                t0: 0,
                t_local: 0,
            },
        );
        let mut reply = ecwire::MOSDECSubOpWriteReply {
            op: ecwire::ECSubWriteReply {
                from: local,
                tid: 7,
                last_complete: v,
                committed: true,
                applied: true,
            },
            ..Default::default()
        };
        pg.on_ec_write_reply(0, reply.clone());
        assert_eq!(pg.prim.peer_lcod.get(&local), Some(&v));
        assert!(!pg.prim.peer_lcod.contains_key(&pg.me));
        assert_eq!(pg.prim.min_lcod, v);
        pg.prim.repops.get_mut(&7).unwrap().waiting.insert(local);
        pg.on_ec_write_reply(1, reply.clone());
        assert!(
            pg.prim.repops[&7].waiting.contains(&local),
            "wrong transport sender"
        );
        reply.op.from = pg.me;
        pg.on_ec_write_reply(0, reply);
        assert!(
            pg.prim.repops[&7].waiting.contains(&local),
            "self reply must not complete a peer"
        );
    }

    #[test]
    fn acting_peers_include_each_other_local_position() {
        let mut pg = pg(0);
        pg.acting = vec![0, 1, 0];
        assert_eq!(pg.peer_shards_acting(), vec![peer(1, 1), peer(0, 2)]);
        pg.acting = vec![0, 0, 0];
        assert_eq!(pg.peer_shards_acting(), vec![peer(0, 1), peer(0, 2)]);
        pg.pool.is_erasure = false;
        pg.me.shard = ShardId::NO_SHARD;
        pg.acting = vec![0, 1, 2];
        assert_eq!(pg.peer_shards_acting(), vec![peer(1, -1), peer(2, -1)]);
    }
}

/// Time a primary spends in each peering phase until it is active again (`Config::peer_trace_ns` > 0: one note per
/// peering that took at least that long; lab diagnostic of the client stall at an OSD out / in, doc/perf/tail-latency).
#[derive(Debug, Default)]
pub(crate) struct PeerTrace {
    /// Peering began (`None` = not peering as primary).
    t0: Option<Mono>,
    /// Current phase index ([`PeerTrace::NAMES`]) and since when.
    cur: (usize, Mono),
    ns: [Mono; 8],
    epoch0: u32,
}

impl PeerTrace {
    const NAMES: [&'static str; 8] = [
        "GetInfo",
        "GetLog",
        "GetMissing",
        "WaitUpThru",
        "Down",
        "Incomplete",
        "WaitActingChange",
        "Activating",
    ];
}

impl Pg {
    /// [`PeerTrace`] step; runs at the end of every event.
    pub(crate) fn peer_trace(&mut self) {
        let min = self.cfg.peer_trace_ns;
        if min == 0 {
            return;
        }
        let k = match self.st {
            St::Primary(PSt::GetInfo) => 0,
            St::Primary(PSt::GetLog) => 1,
            St::Primary(PSt::GetMissing) => 2,
            St::Primary(PSt::WaitUpThru) => 3,
            St::Primary(PSt::Down) => 4,
            St::Primary(PSt::Incomplete) => 5,
            St::Primary(PSt::WaitActingChange) => 6,
            St::Primary(PSt::Active(ASt::Activating)) => 7,
            St::Primary(PSt::Active(_)) => 8,
            _ => {
                self.ptrace.t0 = None;
                return;
            }
        };
        let now = self.now;
        let t = &mut self.ptrace;
        let Some(t0) = t.t0 else {
            if k < 8 {
                *t = PeerTrace {
                    t0: Some(now),
                    cur: (k, now),
                    epoch0: self.map.epoch(),
                    ..Default::default()
                };
            }
            return;
        };
        if k == t.cur.0 {
            return;
        }
        t.ns[t.cur.0] += now.saturating_sub(t.cur.1);
        t.cur = (k, now);
        if k < 8 {
            return;
        }
        t.t0 = None;
        let total = now.saturating_sub(t0);
        if total < min {
            return;
        }
        let parts: Vec<String> = PeerTrace::NAMES
            .iter()
            .zip(t.ns)
            .filter(|(_, ns)| *ns > 0)
            .map(|(n, ns)| format!("{n} {}", ns / 1_000_000))
            .collect();
        let e0 = t.epoch0;
        self.notes.push(format!(
            "{} peering {} ms (e{e0}..e{}, up {:?} acting {:?}): {}",
            self.spg,
            total / 1_000_000,
            self.map.epoch(),
            self.up,
            self.acting,
            parts.join(", ")
        ));
    }
}

#[cfg(test)]
mod obj_gen_tests {
    //! Object-state generation (adr 0160 D5): every txn that may change an object and is not the replicated client
    //! write path's own changes it when queued and when committed; PG metadata and the client path leave it alone.
    use super::*;
    use crate::map::synth::SynthMap;
    use crate::store::MemStore;
    use denc::types::{PgT, SnapId};

    fn spg() -> SpgT {
        SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        }
    }
    fn pg() -> Pg {
        let map: MapHandle = std::rc::Rc::new(SynthMap::new(5).with_pool(1, 3, 2, 1));
        Pg::blank(Arc::new(Config::new(0)), spg(), map, PgInfo::new(spg()))
    }
    fn obj_op() -> StoreOp {
        StoreOp::RemoveObject(Hobject::new(b"o", SnapId::NOSNAP, 7, 1, b""))
    }
    fn write_kind() -> Pending {
        Pending::LocalWrite {
            interval: 0,
            tid: 1,
        }
    }
    /// Flush `ops` as `kind` (client write path's own when `own`): (gen after the flush, its token).
    fn flush(pg: &mut Pg, ops: Vec<StoreOp>, kind: Pending, own: bool) -> (u64, u64) {
        if own {
            pg.own_txn_next();
        }
        pg.txn.extend(ops);
        let token = pg.flush(kind).expect("a txn");
        pg.out.clear();
        (pg.obj_gen(), token)
    }
    fn commit(pg: &mut Pg, token: u64) -> u64 {
        pg.on_commit(0, token, &MemStore::new());
        pg.out.clear();
        pg.obj_gen()
    }

    #[test]
    fn foreign_object_txn_changes_the_generation_when_queued_and_when_committed() {
        let mut pg = pg();
        let g0 = pg.obj_gen();
        let (g1, t) = flush(&mut pg, vec![obj_op()], Pending::Plain, false);
        assert_ne!(g1, g0, "queued");
        let g2 = commit(&mut pg, t);
        assert_ne!(g2, g1, "committed");
        // the same kind as the client path (recovery of a primary object) without the own mark counts too
        let (g3, t) = flush(&mut pg, vec![obj_op()], write_kind(), false);
        assert_ne!(g3, g2);
        assert_ne!(commit(&mut pg, t), g3);
    }

    #[test]
    fn metadata_and_own_client_txns_keep_the_generation() {
        let mut pg = pg();
        let g0 = pg.obj_gen();
        let (g, t) = flush(&mut pg, vec![StoreOp::PutEpoch(5)], Pending::Plain, false);
        assert_eq!(g, g0, "metadata only");
        assert_eq!(commit(&mut pg, t), g0);
        let (g, t) = flush(&mut pg, vec![obj_op()], write_kind(), true);
        assert_eq!(g, g0, "own client write");
        assert_eq!(commit(&mut pg, t), g0);
    }

    #[test]
    fn own_mark_covers_only_the_next_flush_and_not_foreign_ops_queued_before_it() {
        let mut pg = pg();
        let g0 = pg.obj_gen();
        // object ops of something else already queued when the client write starts: they count
        pg.txn.push(obj_op());
        let (g, _) = flush(&mut pg, vec![obj_op()], write_kind(), true);
        assert_ne!(g, g0);
        // a mark consumed by a flush that wrote nothing does not leak into the next txn
        pg.own_txn_next();
        assert!(pg.flush(Pending::Plain).is_none());
        let (g2, _) = flush(&mut pg, vec![obj_op()], Pending::Plain, false);
        assert_ne!(g2, g);
    }

    #[test]
    fn generations_are_unique_across_pgs() {
        let (a, b) = (pg(), pg());
        assert_ne!(
            a.obj_gen(),
            b.obj_gen(),
            "a replaced PG never repeats a generation"
        );
    }
}

#[cfg(test)]
mod stale_floor_tests {
    //! peering.md 7.3: the requests a replica or stray answers and recovery data are stale by `map_epoch` only (classic
    //! `can_discard_replica_op`); peering messages and scrub chunks also by `min_epoch`.
    use super::*;

    /// Sent at map 9 from an interval that started at 5.
    const MAP: u32 = 9;
    const MIN: u32 = 5;

    #[test]
    fn answered_requests_and_recovery_data_are_stale_by_map_epoch() {
        let bodies = [
            Body::Repl(ReplMsg::RepOp(replwire::MOSDRepOp {
                map_epoch: MAP,
                min_epoch: MIN,
                ..Default::default()
            })),
            Body::Repl(ReplMsg::UpdateLogMissing(
                replwire::MOSDPGUpdateLogMissing {
                    map_epoch: MAP,
                    min_epoch: MIN,
                    ..Default::default()
                },
            )),
            Body::Ec(ecwire::EcMsg::Write(ecwire::MOSDECSubOpWrite {
                map_epoch: MAP,
                min_epoch: MIN,
                ..Default::default()
            })),
            Body::Ec(ecwire::EcMsg::Read(ecwire::MOSDECSubOpRead {
                map_epoch: MAP,
                min_epoch: MIN,
                ..Default::default()
            })),
        ];
        for b in &bodies {
            assert_eq!(stale_floor(b, MAP, MIN), MAP, "{}", b.msg_type());
        }
    }

    #[test]
    fn scrub_chunks_and_replies_keep_the_min_epoch_floor() {
        let bodies = [
            Body::Repl(ReplMsg::RepScrub(replwire::MOSDRepScrub {
                map_epoch: MAP,
                min_epoch: MIN,
                ..Default::default()
            })),
            Body::Repl(ReplMsg::RepOpReply(replwire::MOSDRepOpReply {
                map_epoch: MAP,
                min_epoch: MIN,
                ..Default::default()
            })),
            Body::Ec(ecwire::EcMsg::WriteReply(ecwire::MOSDECSubOpWriteReply {
                map_epoch: MAP,
                min_epoch: MIN,
                ..Default::default()
            })),
        ];
        for b in &bodies {
            assert_eq!(stale_floor(b, MAP, MIN), MIN, "{}", b.msg_type());
        }
    }
}
