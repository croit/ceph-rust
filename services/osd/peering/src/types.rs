// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Shared types: config, wire body wrapper, actions (outputs) of the sans-IO PG machinery.

use crate::store::StoreTxn;
use denc::types::{Eversion, PgShard, PgT, ShardId, SpgT};
use messages::Segments;
use pgwire::{PeeringMsg, PgStat};
use replwire::ReplMsg;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64};

/// Monotonic nanoseconds since process start (one clock for leases, spec peering.md 8.3).
pub type Mono = u64;
pub const SEC: Mono = 1_000_000_000;

/// Longest read lease (2^30 s, about 34 years). Lease bounds are monotonic `now + interval` and travel as signed 32-bit
/// wire seconds (`pg_lease_t`), so this cap keeps every bound representable for 34 years of uptime and far from u64
/// overflow. Classic has no bound: its double-to-nanoseconds cast is undefined above about 292 years.
pub const MAX_READABLE_INTERVAL: Mono = (1 << 30) * SEC;

/// Read lease length in ns from configured seconds (`osd_heartbeat_grace x osd_pool_default_read_lease_ratio`, or the
/// pool's `read_lease_interval`). NaN and non-positive values give 0; longer values, `+inf` included, give
/// [`MAX_READABLE_INTERVAL`] (the caller reports the clamp).
pub fn lease_ns(secs: f64) -> Mono {
    if secs.is_nan() || secs <= 0.0 {
        0
    } else if secs >= (MAX_READABLE_INTERVAL / SEC) as f64 {
        MAX_READABLE_INTERVAL
    } else {
        (secs * SEC as f64) as Mono
    }
}

/// Bounds on `peer_mono - local_mono` (ns) for one peer OSD incarnation (`up_from`), from heartbeat stamps (adr 0683,
/// spec osd-lifecycle.md 5.3). A peer timestamp `T` lies in local `[T - upper, T - lower]`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerClockBounds {
    pub up_from: u32,
    pub lower: Option<i64>,
    pub upper: Option<i64>,
}

impl PeerClockBounds {
    /// Peer timestamp minus a delta bound, saturated to the local `Mono` range.
    pub fn to_local(peer: Mono, delta: i64) -> Mono {
        (i128::from(peer) - i128::from(delta)).clamp(0, i128::from(u64::MAX)) as u64
    }

    /// An inverted pair is not a usable observation.
    pub fn valid(self) -> bool {
        match (self.lower, self.upper) {
            (Some(lo), Some(hi)) => lo <= hi,
            _ => true,
        }
    }
}

/// One peer's published bounds: written only by the heartbeat (control) core, read lock-free by every core.
/// Sequence lock: odd version = write in progress; a read that overlaps a write returns `None` (fails closed, no spin).
/// SeqCst on every access keeps version and payload in one total order (also on aarch64).
#[derive(Debug, Default)]
pub struct PeerClockSlot {
    version: AtomicU64,
    incarnation: AtomicU32,
    lower: AtomicI64,
    upper: AtomicI64,
    flags: AtomicU32,
}

impl PeerClockSlot {
    /// Publish (`Some`) or revoke (`None`) one sample; single writer (the heartbeat core).
    pub fn store(&self, bounds: Option<PeerClockBounds>) {
        use std::sync::atomic::Ordering::SeqCst;
        self.version.fetch_add(1, SeqCst);
        let b = bounds.filter(|b| b.valid()).unwrap_or_default();
        self.incarnation.store(b.up_from, SeqCst);
        self.lower.store(b.lower.unwrap_or_default(), SeqCst);
        self.upper.store(b.upper.unwrap_or_default(), SeqCst);
        self.flags.store(
            u32::from(b.lower.is_some()) | (u32::from(b.upper.is_some()) << 1),
            SeqCst,
        );
        self.version.fetch_add(1, SeqCst);
    }

    /// Snapshot in constant time, without allocation, lock or retry; `None` = no sample or a racing write.
    pub fn load(&self) -> Option<PeerClockBounds> {
        use std::sync::atomic::Ordering::SeqCst;
        let v = self.version.load(SeqCst);
        if v & 1 != 0 {
            return None;
        }
        let flags = self.flags.load(SeqCst);
        let b = PeerClockBounds {
            up_from: self.incarnation.load(SeqCst),
            lower: (flags & 1 != 0).then(|| self.lower.load(SeqCst)),
            upper: (flags & 2 != 0).then(|| self.upper.load(SeqCst)),
        };
        (v == self.version.load(SeqCst) && b.up_from != 0).then_some(b)
    }
}

/// Per-core registry peer OSD -> slot, shared by all PGs of the core through [`Config`]. Membership changes only at
/// heartbeat peer discovery, on the owning core; samples write slots, never the registry, a PG or a `Config`.
#[derive(Debug, Default)]
pub struct PeerClocks(arc_swap::ArcSwap<BTreeMap<i32, Arc<PeerClockSlot>>>);

impl PeerClocks {
    /// Attach (or replace) a peer's slot; allocates, control path only.
    pub fn insert(&self, osd: i32, slot: Arc<PeerClockSlot>) {
        let mut peers = (**self.0.load()).clone();
        peers.insert(osd, slot);
        self.0.store(Arc::new(peers));
    }

    /// Current sample of a peer, without lock or allocation.
    pub fn get(&self, osd: i32) -> Option<PeerClockBounds> {
        self.0.load().get(&osd).and_then(|slot| slot.load())
    }
}

/// Tunables (defaults = classic defaults, spec).
#[derive(Debug, Clone)]
pub struct Config {
    pub whoami: i32,
    /// Heartbeat clock bounds of peer OSDs (this core's registry, adr 0683); PGs check the incarnation.
    pub peer_clocks: Arc<PeerClocks>,
    /// PG feature bits advertised in notifies (PCT).
    pub pg_features: u64,
    /// Default lease length (osd_heartbeat_grace x osd_pool_default_read_lease_ratio, 16 s with classic defaults); the
    /// pool option `read_lease_interval` overrides it (`Pg::readable_interval`).
    pub readable_interval: Mono,
    pub min_pg_log_entries: u64,
    pub max_pg_log_entries: u64,
    pub pg_log_trim_min: u64,
    pub pg_log_trim_max: u64,
    pub target_pg_log_entries_per_osd: u64,
    pub log_dups_tracked: u64,
    pub recovery_max_chunk: u64,
    pub recovery_max_omap_entries: usize,
    /// Recovery message header priority policy (spec replication.md 6).
    pub recovery_mclock: bool,
    /// WPQ fallback when pool option `recovery_op_priority` is unset or zero.
    pub recovery_op_priority: u16,
    /// Objects in flight per PG during recovery.
    pub recovery_max_active: usize,
    pub max_push_objects: usize,
    pub max_push_cost: u64,
    /// Objects a backfill scan lists: a replica's digest at least `backfill_scan_min` (if available), every listing at
    /// most `backfill_scan_max` (osd_backfill_scan_min / _max).
    pub backfill_scan_min: usize,
    pub backfill_scan_max: usize,
    /// Epochs kept in memory below the newest map whatever the PGs' epochs are (osd_map_cache_size); older ones are
    /// read back from the store on demand (`Action::NeedOldMaps`).
    pub map_cache: u32,
    /// Remote reservation slots (osd_max_backfills).
    pub max_backfills: usize,
    /// Replica scrub reservation slots (osd_max_scrubs).
    pub max_scrubs: usize,
    /// Epochs per old-map request (a parked create replays the persisted maps in chunks of this many).
    pub old_map_chunk: u32,
    /// PGs trimming snaps at once (osd_max_trimming_pgs).
    pub max_trimming_pgs: usize,
    /// Clones trimmed per round and PG (osd_pg_max_concurrent_snap_trims) and the pause between rounds in ns
    /// (osd_snap_trim_sleep).
    pub snap_trim_concurrent: usize,
    pub snap_trim_sleep_ns: u64,
    pub async_recovery_min_cost: u64,
    pub force_auth_primary_missing_objects: u64,
    pub allow_recovery_below_min_size: bool,
    /// Stats publish interval (osd_pg_stat_report_interval_max_seconds); 0 = no idle re-publish timer (every PG event
    /// publishes).
    pub stats_interval: Mono,
    /// An unchanged primary PG re-publishes once the map moved more than this many epochs past its last report
    /// (osd_pg_stat_report_interval_max_epochs).
    pub stats_epochs: u32,
    /// Retry delay after a backfill reservation was refused as too full (osd_backfill_retry_interval).
    pub backfill_retry: Mono,
    /// Retry delay after recovery was held because a member of the set is full (osd_recovery_retry_interval).
    pub recovery_retry: Mono,
    /// Pause before the next recovery/backfill invocation of a non-degraded PG (`osd_recovery_sleep`, else the
    /// all-flash `_ssd` variant); 0 = no pacing.
    pub recovery_sleep: Mono,
    /// Same for a DEGRADED PG (`osd_recovery_sleep_degraded`, else `_degraded_ssd`).
    pub recovery_sleep_degraded: Mono,
    /// OSD-wide (per core) recovery pace: no invocation starts work before this monotonic time; shared by the PGs
    /// of one `PgSet` (classic `do_recovery` schedule time).
    pub rec_sched: Arc<AtomicU64>,
    /// Superblock `cluster_osdmap_trim_lower_bound` (osd-lifecycle 3.5): epochs below it are gone cluster-wide. Shared
    /// by every PG of the core; the required past-interval bounds clamp their start to it (peering.md 3.8).
    pub cluster_trim: Arc<AtomicU32>,
    /// Transaction page size of peers (v10 txns).
    pub page: usize,
    /// Number of PGs on this OSD (for the log target calc); 0 = unknown.
    pub num_pgs_hint: u64,
    /// Wall clock (unix ns) at monotonic 0; scrub stamps and schedules use it. 0 = unknown (stamps stay monotonic).
    pub wall_base_ns: u64,
    /// Primary-side scrub tunables (osd_scrub_*).
    pub scrub: ScrubCfg,
    /// `flashstore_peering_trace_ms` (lab diagnostic, 0 = off): a primary whose peering took at least this long (ns here)
    /// leaves a note with the time per phase.
    pub peer_trace_ns: u64,
    /// Per-op EC trace (lab diagnostic, OQ 41; `debug_osd` >= 15): client reads, sub-reads, sub-writes, rollbacks and
    /// pushes of EC PGs each leave one note (shard, extents, versions). Off = one bool test per op.
    pub ec_trace: bool,
    /// Multi-core OSD: only PGs this core owns are created / loaded / addressed (None = all, single core).
    pub owner: Option<Owner>,
    /// `ec_enable_pools` kill switch (adr 0039): which supported EC pools this OSD serves as a shard. Default off.
    pub ec_enable: ec::EcEnable,
    /// `ec_enable_primary`: lead supported EC PGs (adr 0049); off = a PG led here stays frozen and silent (adr 0039).
    pub ec_primary: bool,
    /// `ec_decline_unsupported` (adr 0039 am. 1): answer classic primaries of erasure pools the gate rejects as an empty
    /// backfill target that refuses backfill (stateless), instead of silence (which stalls their peering). Default on.
    pub ec_decline: bool,
    /// `ec_enable_optimized` (adr 0067): which optimized EC pools (`allow_ec_optimizations`) this OSD serves as a shard
    /// (in addition to `ec_enable_pools`). Default off = optimized pools stay fully passive.
    pub ec_enable_optimized: ec::EcEnable,
    /// Lead optimized EC PGs (primary role mode O, plan S2; owned by branch ecopt-prim). Off = frozen and silent.
    pub ec_opt_primary: bool,
    /// `ec_pdw` (plan S5): parity-delta writes of the mode O primary (off | auto | always). Default off. The extent cache
    /// of the mode O primary is always on (ecprim `XCache`).
    pub ec_pdw: ecback::PdwMode,
    /// `osd_skip_check_past_interval_bounds` (dev level, default false): skip the required past-interval bounds check
    /// (peering.md 3.8) - no log, no stop, no alert.
    pub skip_past_bounds_check: bool,
    /// `ec_rollforward_defer_us` (adr 0160 am. 3): bound (ns) of the adaptive idle roll-forward deferral of the EC primary:
    /// a PG whose client writes arrive with an average gap <= bound / 2 waits up to 2 gaps for the next write to carry the
    /// roll-forward instead of sending the dummy sub-write round. 0 = always immediate (classic).
    pub ec_rf_defer_ns: u64,
}

impl Config {
    pub fn new(whoami: i32) -> Self {
        let log = PgLogCfg::default();
        Config {
            whoami,
            peer_clocks: Default::default(),
            pg_features: pgwire::pg_features::PCT,
            readable_interval: 16 * SEC,
            min_pg_log_entries: log.min_entries,
            max_pg_log_entries: log.max_entries,
            pg_log_trim_min: log.trim_min,
            pg_log_trim_max: log.trim_max,
            target_pg_log_entries_per_osd: log.target_per_osd,
            log_dups_tracked: log.dups_tracked,
            recovery_max_chunk: 8 << 20,
            recovery_max_omap_entries: 8096,
            recovery_mclock: true,
            recovery_op_priority: 3,
            recovery_max_active: 3,
            max_push_objects: 10,
            max_push_cost: 8 << 20,
            backfill_scan_min: 64,
            backfill_scan_max: 512,
            map_cache: 50,
            max_backfills: 1,
            max_scrubs: 3,
            old_map_chunk: 32,
            max_trimming_pgs: 2,
            snap_trim_concurrent: 2,
            snap_trim_sleep_ns: 0,
            async_recovery_min_cost: 100,
            force_auth_primary_missing_objects: 100,
            allow_recovery_below_min_size: true,
            stats_interval: 5 * SEC,
            stats_epochs: 500,
            backfill_retry: 30 * SEC,
            recovery_retry: 30 * SEC,
            recovery_sleep: 0,
            recovery_sleep_degraded: 0,
            rec_sched: Arc::new(AtomicU64::new(0)),
            cluster_trim: Arc::new(AtomicU32::new(0)),
            page: replwire::DEFAULT_PAGE,
            num_pgs_hint: 0,
            wall_base_ns: 0,
            scrub: ScrubCfg::default(),
            peer_trace_ns: 0,
            ec_trace: false,
            owner: None,
            ec_enable: ec::EcEnable::Off,
            ec_primary: false,
            ec_decline: true,
            ec_enable_optimized: ec::EcEnable::Off,
            ec_opt_primary: false,
            ec_pdw: ecback::PdwMode::Never,
            skip_past_bounds_check: false,
            ec_rf_defer_ns: 20_000_000,
        }
    }
}

/// Hash PG -> core placement of a multi-core OSD (adr 0031): core of PG `(pool, seed)` = `shard % cores`, where `shard`
/// is the hash store shard of the PG (`(pool + seed) % shards`, adr 0021). So a core owns whole store shards (any shard
/// and core count, adr 0160); split children inherit the parent's shard. The default for a PG the control core did not
/// place when it arrived (adr 0639, `crate::place`).
#[inline]
pub fn pg_core(pool: u64, seed: u32, cores: u32, shards: u32) -> usize {
    ((pool.wrapping_add(u64::from(seed)) % u64::from(shards)) as usize) % cores as usize
}

/// Which PGs one core of a multi-core OSD owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    pub core: u32,
    pub cores: u32,
    /// Store shards of the device.
    pub shards: u32,
}

impl Owner {
    /// Hash shard of a PG (the placement of PGs that were never moved).
    pub fn default_shard(&self, pool: u64, seed: u32) -> u32 {
        (pool.wrapping_add(u64::from(seed)) % u64::from(self.shards)) as u32
    }
}

/// One PG stopped by the past-interval bounds check (peering.md 3.8), with both ranges for the operator log and the
/// `FLASHSTORE_PG_PAST_INTERVALS` health alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BoundsStoppedPg {
    pub spg: SpgT,
    /// Required `[start, end)`.
    pub required: (u32, u32),
    /// Stored `[first, last + 1)`.
    pub past: (u32, u32),
}

/// Any PG-addressed OSD<->OSD message of this crate's scope.
// Peering (pg_info_t with the 21.2.0 history) and EC sub-ops are both > 1 KB; outbound bodies travel boxed
// (`Action::Send`), a box per variant would only add an allocation per inbound message (should
// `clippy::large_enum_variant` fire again).
#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    Peering(PeeringMsg),
    Repl(ReplMsg),
    /// Erasure-coded sub-ops (shard role only, adr 0039).
    Ec(ecwire::EcMsg),
}

impl Body {
    pub fn msg_type(&self) -> u16 {
        match self {
            Body::Peering(m) => m.msg_type(),
            Body::Repl(m) => m.msg_type(),
            Body::Ec(m) => m.msg_type(),
        }
    }
    /// `(type, head_version, compat_version, segments)` for a msgr2 header.
    pub fn encode(&self, features: u64) -> denc::Result<(u16, u16, u16, Segments)> {
        match self {
            Body::Peering(m) => m.encode(features),
            Body::Repl(m) => m.encode(features),
            Body::Ec(m) => m.encode(features),
        }
    }
    /// Decode by header type id; `Ok(None)` = not a PG message.
    pub fn decode(ty: u16, version: u16, seg: &Segments) -> denc::Result<Option<Body>> {
        // PCT (136) and RecoveryDelete(+Reply) exist in both crates; they are wire identical, the
        // peering form wins.
        if let Some(r) = pgwire::decode_peering(ty, version, seg) {
            return r.map(|m| Some(Body::Peering(m)));
        }
        if let Some(m) = replwire::decode_repl(ty, version, seg)? {
            return Ok(Some(Body::Repl(m)));
        }
        match ecwire::decode_ec(ty, version, seg) {
            Some(r) => r.map(|m| Some(Body::Ec(m))),
            None => Ok(None),
        }
    }
    /// Messenger priority (peering.md 4, replication.md 3.4). The primary's requests that append to a replica's log
    /// (RepOp, UpdateLogMissing, EC sub-write) share the default priority: a messenger out queue is FIFO only within one
    /// priority, and the replica needs them in version order (a classic replica asserts it; adr 0084 am. 6).
    pub fn priority(&self) -> u16 {
        match self {
            Body::Peering(m) => m.priority(),
            Body::Repl(ReplMsg::RepOpReply(_)) | Body::Repl(ReplMsg::UpdateLogMissingReply(_)) => {
                pgwire::msgs::PRIO_HIGH
            }
            Body::Repl(_) => pgwire::msgs::PRIO_DEFAULT,
            Body::Ec(m) => m.priority(),
        }
    }
}
impl From<PeeringMsg> for Body {
    fn from(m: PeeringMsg) -> Self {
        Body::Peering(m)
    }
}
impl From<ecwire::EcMsg> for Body {
    fn from(m: ecwire::EcMsg) -> Self {
        Body::Ec(m)
    }
}
impl From<ReplMsg> for Body {
    fn from(m: ReplMsg) -> Self {
        Body::Repl(m)
    }
}

/// A received PG message with its sender and msgr header tid.
#[derive(Debug, Clone, PartialEq)]
pub struct Inbound {
    /// Local bounded-input ownership, retained through actor waits and discarded with the input.
    pub ingress: ingress::InputGuard,
    pub from: i32,
    /// Header `tid` (RepOp / UpdateLogMissing reply correlation).
    pub tid: u64,
    /// Header priority: recovery replies echo it (spec replication.md 6.1).
    pub prio: u16,
    pub body: Box<Body>,
}

/// A message to send to a peer OSD over the cluster messenger.
#[derive(Debug, Clone, PartialEq)]
pub struct Send {
    pub to: i32,
    /// Epoch stamped on the message: the driver sends it only if `to` is up in its map and
    /// `up_from(to) <= epoch` (peering.md 4).
    pub epoch: u32,
    /// Header tid to set (echo for replies).
    pub tid: u64,
    pub prio: u16,
    pub body: Body,
    /// PG instance that produced this message (`None` for OSD-level replies). The past-interval bounds gate
    /// (peering.md 3.8) silences exactly this instance, never a healthy shard sibling of the same pgid.
    pub producer: Option<SpgT>,
}

/// Outputs of the machinery. The driver executes them in order.
#[derive(Debug, Clone)]
pub enum Action {
    /// Send a PG message to an OSD. Boxed: actions move through several Vecs per write, an inline 1.4 KB body made
    /// that a memmove per hop (w4k-cpu.md).
    Send(Box<Send>),
    /// Apply a transaction durably to the local store, then call `on_commit(spg, token)`.
    Persist {
        spg: SpgT,
        token: u64,
        txn: StoreTxn,
    },
    /// Raise our wanted up_thru (MOSDAlive want).
    NeedUpThru { want: u32 },
    /// MOSDPGTemp entry (empty vector clears).
    PgTemp { pgid: PgT, want: Vec<i32> },
    /// MOSDPGCreated for a mon-created pool PG that became peered/active.
    PgCreated { pgid: PgT },
    /// Primary PG stats for the mgr (MPGStats).
    PgStats { spg: SpgT, stat: Box<PgStat> },
    /// We need a map newer than `have` (waiting messages).
    RequestMap { have: u32 },
    /// Maps `[from, to]` are needed (a PG is to be created from a message of epoch `from`, older than the kept maps):
    /// the driver loads them from the persisted maps and answers with [`PgSet::old_maps`] (empty = gone).
    NeedOldMaps { from: u32, to: u32 },
    /// A client write submitted with `submit_write` is committed everywhere (result 0) or aborted.
    WriteDone {
        spg: SpgT,
        tid: u64,
        version: Eversion,
        result: i32,
    },
    /// Sub-writes (replicated or EC) the primary aborted before every reply came: a new interval, a merge. `keys` =
    /// `(peer, its shard, tid)` of each one still unanswered; no reply comes for them (the replica discards an older
    /// interval's request), so the driver returns the repop credit they hold (adr 0084).
    SubWritesAborted {
        spg: SpgT,
        keys: Vec<(i32, SpgT, u64)>,
    },
    /// A `mark_unfound_lost` that answered [`crate::LostReply::Later`] finished: every shard committed the marking (the
    /// operator message), or the interval ended before that (`-EAGAIN`, spec ec-unfound-lost.md 6, doc/parity.md).
    LostMarked(Box<crate::lost::LostDone>),
    /// Readable state of a primary PG changed (requeue / park client ops).
    ReadableChanged { spg: SpgT, readable: bool },
    /// The PG is gone locally (deletion committed).
    PgRemoved { spg: SpgT },
    /// Merge report for the mon (MOSDPGReadyToMerge, split-merge.md 6.2); the driver stamps its epoch.
    ReadyToMerge(MergeReport),
    /// Multi-core: PG `pgid` was placed on store `shard` (a split child inherited its parent's): tell the other cores.
    Placement { pgid: PgT, shard: u32 },
    /// Primary: the snap trimmer of `spg` may run (or continue): drive the op engine's trimmer.
    SnapTrimKick { spg: SpgT },
    /// Fail-stop (adr 0066): `spg` got input it can never apply (undecodable or protocol-violating data-path or
    /// activation message from its primary) and has already diverged from it in memory. The driver logs FATAL, marks
    /// the OSD down and exits, like a classic OSD whose decode/apply asserts; the mark-down is the interval change that
    /// lets the primary go on without us, restart + peering bring us back from the durable state. Actions after it in
    /// the same batch must not run.
    Fatal { spg: SpgT, why: &'static str },
    /// Internal to `PgSet` (reservation requests); never reaches the driver.
    #[doc(hidden)]
    Resv(ResvAction),
    /// OSD-wide slot traffic to the core that owns the budget (core 0; never emitted by it, [`SlotReq`]).
    Slot(SlotReq),
    /// Answer of the budget owner to core `core` ([`SlotReply`]).
    SlotReply { core: u32, reply: SlotReply },
    /// Recovery-op budget traffic to the core that owns it (core 0; never emitted by it, [`crate::OpsReq`]).
    Ops(crate::OpsReq),
    /// Answer of the recovery-op budget owner to core `core`.
    OpsReply { core: u32, reply: crate::OpsReply },
    /// Internal to `PgSet`: a primary closed a vulnerability window or rebuild episode lasting `ns` (summed into
    /// [`crate::PgSet::latch_perf`]); never reaches the driver.
    #[doc(hidden)]
    Latch {
        kind: crate::latch::LatchKind,
        ns: u64,
    },
}
// keep `Action` small (see `Action::Send`)
const _: () = assert!(std::mem::size_of::<Action>() <= 96);

/// PG log sizing options ([`crate::PgSet::set_pg_log`]); defaults = classic defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgLogCfg {
    pub min_entries: u64,
    pub max_entries: u64,
    pub trim_min: u64,
    pub trim_max: u64,
    pub target_per_osd: u64,
    pub dups_tracked: u64,
}

impl Default for PgLogCfg {
    fn default() -> Self {
        PgLogCfg {
            min_entries: 250,
            max_entries: 10_000,
            trim_min: 100,
            trim_max: 10_000,
            target_per_osd: 300_000,
            dups_tracked: 3000,
        }
    }
}

/// This OSD's own fill as the driver judges it (statfs aggregate of all cores against the map ratios): what a replica
/// checks before it takes backfill data (classic `OSDService` full state, spec osd-lifecycle.md 4.4).
///
/// Backfill space is judged tentatively like classic: the bytes a replica's granted (or pending) backfill reservation
/// still expects count as used. `used` holds the physical use plus the expected bytes of the OTHER cores of this OSD
/// (driver aggregate); the [`crate::PgSet`] adds its own reservations at judgement time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocalFull {
    /// Capacity in bytes; 0 = unknown (no map or no capacity report yet): nothing is judged backfillfull.
    pub total: u64,
    /// Used bytes: physical use plus the backfill reservations of the other cores.
    pub used: u64,
    /// Use (bytes) above which the OSD is backfillfull: `total x max(backfillfull_ratio, nearfull_ratio)` of the map.
    pub backfill_limit: u64,
    /// Physical fill above `max(osd_failsafe_full_ratio, full_ratio)`: refuse every push (never apply into NoSpace).
    pub failsafe: bool,
}

impl LocalFull {
    /// Backfillfull (or worse) once `extra` more bytes are expected: refuse (REJECT_TOOFULL) / withdraw (REVOKE_TOOFULL)
    /// backfill. Classic: tentative state >= BACKFILLFULL (failsafe is judged on the physical fill).
    pub fn backfillfull_with(&self, extra: u64) -> bool {
        self.failsafe || (self.total > 0 && self.used.saturating_add(extra) > self.backfill_limit)
    }
}

/// Content of a MOSDPGReadyToMerge (pgid = the SOURCE pg).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeReport {
    pub source: denc::types::PgT,
    pub source_version: Eversion,
    pub target_version: Eversion,
    pub last_epoch_started: u32,
    pub last_epoch_clean: u32,
    pub ready: bool,
}

/// The OSD-wide budgets (one counter set per OSD, adr 0031 am. 9). Scrub: `osd_max_scrubs` each for scrubs this OSD
/// leads and reservations it grants to a primary elsewhere, counted separately like classic. Backfill / recovery:
/// `osd_max_backfills` for the primary side (`local`) and the replica side (remote), backfill and recovery in separate
/// pools. Trim: `osd_max_trimming_pgs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlotPool {
    ScrubLocal,
    ScrubReplica,
    Resv { local: bool, backfill: bool },
    Trim,
}

/// What a PG core asks of the budget owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotOp {
    /// Scrub pools: `immediate` answers granted or rejected at once, else queue FIFO. Reservation pools: queue by
    /// `prio` (a held slot is granted again, a queued one takes the new priority); trim: queue FIFO.
    Request { immediate: bool, prio: u32 },
    /// Take a slot regardless of the limit (classic operator scrub with `flashstore_scrub_operator_limits` off).
    Force,
    /// Give the slot or queue place back; idempotent.
    Release,
}

/// Core -> budget owner. Delivered in order per sender (one lane).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotReq {
    /// Requesting core.
    pub from: u32,
    pub pool: SlotPool,
    pub spg: SpgT,
    /// Per-core request counter, echoed by the reply: a reply of an earlier (released) request is ignored.
    pub seq: u32,
    pub op: SlotOp,
}

/// What the budget owner tells a core about one of its slot requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotAnswer {
    Granted,
    /// Immediate request, no slot free.
    Rejected,
    /// A granted reservation was taken away for a higher priority request (the slot is already free).
    Preempted,
}

/// Budget owner -> core: the answer to request `seq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotReply {
    pub pool: SlotPool,
    pub spg: SpgT,
    pub seq: u32,
    pub answer: SlotAnswer,
}

/// A PG's request to the OSD-wide budgets: `op` on `pool` for `spg`. Scrub pools: `Request { immediate }` answers GRANT or
/// REJECT at once, else queues FIFO; `Force` takes the local slot regardless of the limit (classic operator request,
/// `flashstore_scrub_operator_limits` off). Reservation pools: `Request { prio }`, local (primary) before any remote one; a
/// local slot already held is granted again. Trim: granted at once or queued FIFO. A held or queued remote / trim slot
/// is not requested again; `Release` is idempotent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResvAction {
    pub pool: SlotPool,
    pub spg: SpgT,
    pub op: SlotOp,
}

/// Mutation outcome helpers.
pub(crate) fn ps(osd: i32) -> PgShard {
    PgShard {
        osd,
        shard: ShardId::NO_SHARD,
    }
}

/// Local wall clock of the OSD host as the scrub windows see it (spec scrub.md 12.1.1): the process's local time
/// (`TZ`, DST-aware), not UTC.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocalTime {
    /// Hour of day, 0..=23.
    pub hour: u32,
    /// 0 = Sunday .. 6 = Saturday.
    pub weekday: u32,
}

/// Primary-side scrub tunables (defaults = classic v21.2.0; seconds unless noted).
#[derive(Debug, Clone)]
pub struct ScrubCfg {
    /// osd_scrub_min_interval, fractional seconds: shallow target = last scrub + this
    /// (`1 + randomize_ratio * r`, `r` uniform).
    pub min_interval: f64,
    /// osd_deep_scrub_interval: mean of the deep target delay in fractional seconds.
    pub deep_interval: f64,
    /// osd_scrub_interval_randomize_ratio: shallow delay uniform in `[min, min * (1 + ratio))`.
    pub randomize_ratio: f64,
    /// osd_deep_scrub_interval_cv: standard deviation of the deep delay as a fraction of `deep_interval`
    /// (normal distribution, clamped to the mean +/- 2 sigma).
    pub deep_interval_cv: f64,
    /// osd_scrub_load_threshold: a start needs the 1-minute host load average per online CPU strictly below this.
    pub load_threshold: f64,
    /// osd_scrub_begin_hour / end_hour (0..=23); equal = all day, begin > end wraps around midnight.
    pub begin_hour: u32,
    pub end_hour: u32,
    /// osd_scrub_begin_week_day / end_week_day (0 = Sunday .. 6 = Saturday); equal = all week, begin > end wraps.
    pub begin_week_day: u32,
    pub end_week_day: u32,
    /// osd_scrub_during_recovery: periodic / must / after-repair scrubs may start while a recovery reservation is held.
    pub during_recovery: bool,
    /// osd_scrub_backoff_ratio: probability that a tick with a free local slot skips the low urgencies.
    pub backoff_ratio: f64,
    /// osd_scrub_invalid_stats: a PG whose statistics are invalid is due for a shallow scrub (`must_scrub`).
    pub invalid_stats: bool,
    /// osd_scrub_priority: priority of the MOSDRepScrub the primary sends; a pool `scrub_priority` (> 0) overrides it.
    pub priority: i32,
    /// osd_scrub_chunk_min / max (deep) and shallow equivalents, in objects.
    pub chunk_min: usize,
    pub chunk_max: usize,
    pub shallow_chunk_min: usize,
    pub shallow_chunk_max: usize,
    /// Pause between chunks (osd_scrub_sleep), ns.
    pub sleep: Mono,
    /// Deep scrub: data bytes one map slice digests before it yields (`flashstore_scrub_slice_bytes`). A slice runs whole
    /// on the PG core (copy + crc of every byte); all scrubbing PGs of a core may slice in the same loop iteration, so
    /// this bounds the core stall a deep scrub adds to client ops (doc/perf/tail-latency-20261015.md).
    pub slice_bytes: u64,
    /// osd_scrub_max_preemptions: client writes to the chunk being scrubbed abort it (it is retried with half the objects)
    /// this many times per scrub; after that they wait for the chunk (classic). 0 = writes always wait.
    pub max_preemptions: u32,
    /// `flashstore_scrub_operator_limits` (default on): operator / follow-up scrubs wait for a local `osd_max_scrubs` slot and
    /// reserve the replicas like periodic ones. Off = classic: they start at once, unlimited, without replica reservations
    /// (a pool scrub then runs every PG of the pool at once; doc/perf/tail-latency-20261015.md).
    pub operator_limits: bool,
    /// `flashstore_dedup_list` (adr 0593-dedup-deep-scrub-reformat): a successful deep scrub also sets
    /// `last_deep_scrub_start_stamp` (wall time of its session start, before reservations and the first read) for dedup
    /// listing clients (croit fork `wip-ifed-dedup`). Off: the field stays zero and history/stats keep the upstream bytes.
    pub dedup_start_stamp: bool,
    /// Retry delay after an aborted / rejected scrub (osd_scrub_retry_*), ns.
    pub retry: Mono,
    /// Delay before a scrub retries on a PG that is trimming snaps (osd_scrub_retry_trimming), ns.
    pub retry_trimming: Mono,
    /// Give up on a missing chunk map after this long, ns.
    pub chunk_timeout: Mono,
    /// osd_scrub_auto_repair (+ _num_errors): a periodic scrub with <= errors found re-runs as repair.
    pub auto_repair: bool,
    pub auto_repair_num_errors: u64,
    /// osd_max_object_size.
    pub max_object_size: u64,
    /// osd_deep_scrub_large_omap_object_key_threshold / _value_sum_threshold (strictly greater = large).
    pub large_omap_keys: u64,
    pub large_omap_bytes: u64,
}

impl Default for ScrubCfg {
    fn default() -> Self {
        ScrubCfg {
            min_interval: 86_400.0,
            deep_interval: 7.0 * 86_400.0,
            randomize_ratio: 0.5,
            deep_interval_cv: 0.2,
            load_threshold: 10.0,
            begin_hour: 0,
            end_hour: 0,
            begin_week_day: 0,
            end_week_day: 0,
            during_recovery: false,
            backoff_ratio: 0.66,
            invalid_stats: true,
            priority: 5,
            chunk_min: 5,
            chunk_max: 15,
            shallow_chunk_min: 50,
            shallow_chunk_max: 100,
            sleep: 0,
            slice_bytes: crate::scrub::SLICE_BYTES,
            max_preemptions: 5,
            operator_limits: true,
            retry: 30 * SEC,
            retry_trimming: 10 * SEC,
            chunk_timeout: 600 * SEC,
            auto_repair: false,
            auto_repair_num_errors: 5,
            max_object_size: 128 << 20,
            large_omap_keys: 200_000,
            large_omap_bytes: 1 << 30,
            dedup_start_stamp: false,
        }
    }
}

impl ScrubCfg {
    /// Values that define a periodic target: changing one reschedules every queued target with a fresh random delay
    /// (spec scrub.md 12.1.4). Window, load and flag options do not reschedule anything (they are read per tick).
    pub(crate) fn schedule_key(&self) -> (u64, u64, u64, u64) {
        (
            self.min_interval.to_bits(),
            self.deep_interval.to_bits(),
            self.randomize_ratio.to_bits(),
            self.deep_interval_cv.to_bits(),
        )
    }
}

#[cfg(test)]
mod lease_ns_tests {
    use super::*;

    /// NT-clocks-03: a configured lease never overflows deadline arithmetic or the signed wire seconds.
    #[test]
    fn lease_ns_bounds_unrepresentable_settings() {
        assert_eq!(lease_ns(16.0), 16 * SEC);
        assert_eq!(lease_ns(0.25), SEC / 4);
        for v in [0.0, -1.0, f64::NAN, f64::NEG_INFINITY] {
            assert_eq!(lease_ns(v), 0, "{v}");
        }
        // 20 s grace x ratio 1e9 = 2e10 s: the plain cast saturated to u64::MAX
        for v in [20.0 * 1e9, 1e30, f64::INFINITY, (1u64 << 30) as f64] {
            assert_eq!(lease_ns(v), MAX_READABLE_INTERVAL, "{v}");
        }
        // 34 years of uptime plus the longest lease stays inside i32 wire seconds and u64
        let bound = (34 * 365 * 86_400 * SEC)
            .checked_add(MAX_READABLE_INTERVAL)
            .unwrap();
        assert!(bound / SEC <= i32::MAX as u64);
        // a bound past i32 seconds saturates on the wire instead of wrapping negative
        assert_eq!(crate::pg::to_ts(u64::MAX).sec, i32::MAX);
    }
}

#[cfg(test)]
mod priority_tests {
    use super::*;

    /// The primary's log-appending requests to a replica share one messenger priority (Ceph: all default). The msgr2 out
    /// queue sends a higher priority first, so an UpdateLogMissing at HIGH queued behind repops (a reconnect, a busy
    /// socket) went ahead of them: a classic replica asserts on the older repop, an croit-flashstore-osd one discards it as a
    /// duplicate (log hole, the write never completes). Replies stay HIGH.
    #[test]
    fn log_appending_requests_share_one_priority() {
        let requests = [
            Body::Repl(ReplMsg::RepOp(Default::default())),
            Body::Repl(ReplMsg::UpdateLogMissing(Default::default())),
            Body::Ec(ecwire::EcMsg::Write(Default::default())),
        ];
        for b in &requests {
            assert_eq!(b.priority(), pgwire::msgs::PRIO_DEFAULT, "{}", b.msg_type());
        }
        let replies = [
            Body::Repl(ReplMsg::RepOpReply(Default::default())),
            Body::Repl(ReplMsg::UpdateLogMissingReply(Default::default())),
            Body::Ec(ecwire::EcMsg::WriteReply(Default::default())),
        ];
        for b in &replies {
            assert_eq!(b.priority(), pgwire::msgs::PRIO_HIGH, "{}", b.msg_type());
        }
    }
}
