// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Multi-core OSD (adr 0031): one [`Osd`] per core, glued by [`XMsg`] messages.
//!
//! * Core 0 is the *control* core: mon / mgr sessions, boot state machine, heartbeats, osdmap ingestion, tell commands,
//!   osd-wide aggregation. Cores `1..n` are *workers*: same struct, control parts idle.
//! * A PG lives on exactly one core ([`CoreSpec::core_of`] = store shard % cores); that core owns its `PgSet` slice,
//!   op engines and store shards. Connections live on the core their flow lands on (`net` cores, RSS) and never move.
//! * A connection core decodes what arrives and routes the owned message to the PG core ([`XMsg::Op`], [`XMsg::Pg`]);
//!   replies travel back as already-encoded frames ([`XMsg::Wire`]). Link ids carry their core in bits 48..56, so any
//!   code holding a link id sends through [`Osd::send_raw`] without knowing where the link lives.
//! * PG, connection and store state stays on its owner core; the driver moves [`XMsg`] values over SPSC lanes.
//!   Shared bounded input counters retain ownership through actor queues. One core bypasses cross-core routing.
use crate::backend::Backend;
use crate::config::ConfigDb;
use crate::frame_wait::FrameWait;
use crate::mig::{BootInfo, BootPg, MigState};
use crate::osd::{MON_BASE, Osd, State};
use cephx::monclient::MonAuthClient;
use denc::types::{EntityAddr, EntityAddrVec, EntityName, PgT, SpgT};
use ingress::order::{Outbox, Route, Sequencer, Stamped};
use messages::{AnyMessage, MOSDMap, Segments};
use opexec::caps::Caps;
use opwire::{MOSDBackoff, MOSDOp};
use osdmap::OsdMap;
use peering::PgStoreOps as _;
use peering::store::MigOp;
use peering::{Body, Owner, Space};
use replwire::MOSDScrub2;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Store-dependent input. Completions and time-bound leases use reserved ingress capacity.
pub(crate) fn data_spg(body: &Body) -> Option<SpgT> {
    use replwire::ReplMsg;
    let data = match body {
        Body::Peering(_) => false,
        Body::Repl(r) => matches!(
            r,
            ReplMsg::RepOp(_)
                | ReplMsg::UpdateLogMissing(_)
                | ReplMsg::Pct(_)
                | ReplMsg::Push(_)
                | ReplMsg::Pull(_)
                | ReplMsg::RecoveryDelete(_)
                | ReplMsg::Scan(_)
                | ReplMsg::Backfill(_)
                | ReplMsg::BackfillRemove(_)
                | ReplMsg::RepScrub(_)
        ),
        Body::Ec(e) => matches!(e, ecwire::EcMsg::Write(_) | ecwire::EcMsg::Read(_)),
    };
    data.then(|| peering::body_spg(body)).flatten()
}

pub(crate) fn pg_progress(body: &Body) -> bool {
    use pgwire::PeeringMsg;
    use replwire::ReplMsg;
    match body {
        Body::Peering(p) => matches!(
            p,
            PeeringMsg::MOSDPGLease(_)
                | PeeringMsg::MOSDPGLeaseAck(_)
                | PeeringMsg::MOSDPGRecoveryDeleteReply(_)
        ),
        Body::Repl(r) => matches!(
            r,
            ReplMsg::RepOpReply(_)
                | ReplMsg::UpdateLogMissingReply(_)
                | ReplMsg::PushReply(_)
                | ReplMsg::RecoveryDeleteReply(_)
                | ReplMsg::RepScrubMap(_)
                | ReplMsg::Scrub2(_)
        ),
        Body::Ec(e) => matches!(
            e,
            ecwire::EcMsg::WriteReply(_) | ecwire::EcMsg::ReadReply(_)
        ),
    }
}

/// Cores per OSD: the migration round tracks cores in `u64` bit masks.
pub const MAX_CORES: usize = 64;

/// Messages the OSD may hold for other cores (the driver stops draining them when its backlog is full): beyond it a
/// client op stays on its link (`Cl::xout_wait`, arrival order) until the lane has room, so a stalled core cannot make
/// the others grow without bound and no op is answered EAGAIN (classic never answers load with it).
pub const XOUT_MAX: usize = 8 * 1024;

/// Link ids of core `c` are `c << CORE_SHIFT | counter`.
pub const CORE_SHIFT: u32 = 48;

/// Core `id` of `n`, `net` of which own a NIC queue (cores `0..net`; the rest are PG-only cores).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreSpec {
    pub id: usize,
    pub n: usize,
    pub net: usize,
    /// Store shards of the device (adr 0021).
    pub shards: u32,
}

impl CoreSpec {
    /// Validated spec: `1 <= n <= min(shards, MAX_CORES)` (core `c` owns the shards `s % n == c`), `1 <= net <= n`.
    pub fn new(id: usize, n: usize, net: usize, shards: u32) -> Result<CoreSpec, String> {
        if n > MAX_CORES {
            return Err(format!("at most {MAX_CORES} cores per OSD, got {n}"));
        }
        if n == 0 || n as u32 > shards {
            return Err(format!(
                "cores must be between 1 and the store's {shards} shards, got {n}"
            ));
        }
        if net == 0 || net > n || id >= n {
            return Err(format!("bad core spec id {id} n {n} net {net}"));
        }
        Ok(CoreSpec { id, n, net, shards })
    }

    /// Startup warning when the store's shard count does not give every core exactly one shard (= one WAL ring;
    /// adr 0160). Core `c` owns the shards `s % cores == c`; the OSD runs normally either way. `cores` is the count the
    /// OSD runs with (at most `shards`), `asked` the configured one.
    pub fn shard_balance(shards: u32, cores: usize, asked: usize) -> Option<String> {
        if shards as usize == cores && asked == cores {
            return None;
        }
        let fix = format!(
            "for one shard (one WAL ring) per core redeploy this OSD with {asked} cores \
             (croit-flashstore-tool prepare --store-shards auto or {asked}; the cluster backfills it)"
        );
        if asked > cores {
            return Some(format!(
                "WARNING: {asked} cores configured but the store has {shards} shards: running on {cores} cores \
                 (a core owns at least one shard); {fix}"
            ));
        }
        let (lo, hi) = (shards as usize / cores, (shards as usize).div_ceil(cores));
        Some(if lo == hi {
            format!(
                "WARNING: store has {shards} shards on {cores} cores: {lo} WAL rings per core (balanced, but WAL group \
                 commit is split {lo} ways per core); {fix}"
            )
        } else {
            let heavy = shards as usize % cores;
            format!(
                "WARNING: store has {shards} shards on {cores} cores: unbalanced, cores 0..{heavy} own {hi} shards, \
                 the others {lo} (PG load follows shards); {fix}"
            )
        })
    }

    /// Ownership filter handed to the PG machinery (None on a single core).
    pub fn owner(&self) -> Option<Owner> {
        (self.n > 1).then_some(Owner {
            core: self.id as u32,
            cores: self.n as u32,
            shards: self.shards,
        })
    }

    /// Core holding the cluster-messenger link to peer OSD `osd` (one link per peer: msgr2 lossless peer sessions
    /// are keyed by address, two dials from one entity would replace each other).
    #[inline]
    pub fn peer_core(&self, osd: i32) -> usize {
        osd.max(0) as usize % self.net
    }
}

/// Does `core` own `link` (mon connection ids belong to every core)?
#[inline]
fn link_on_core(link: u64, core: usize) -> bool {
    link & MON_BASE != 0 || link_core(link) == core
}

/// Is connection `id` (a link of `core`, or a remote one that sent its ops) still known?
pub(crate) fn conn_open<L, R>(
    links: &HashMap<u64, L, impl std::hash::BuildHasher>,
    remote: &HashMap<u64, R, impl std::hash::BuildHasher>,
    core: usize,
    id: u64,
) -> bool {
    if link_on_core(id, core) {
        links.contains_key(&id)
    } else {
        remote.contains_key(&id)
    }
}

/// Core that owns link `id` (not for mon connection ids).
pub fn link_core(id: u64) -> usize {
    debug_assert!(id & MON_BASE == 0);
    ((id >> CORE_SHIFT) & 0xff) as usize
}

/// Everything the PG side needs to know about a client connection that lives on another core.
#[derive(Debug)]
pub struct ConnInfo {
    pub who: EntityName,
    pub features: u64,
    /// Client-advertised identity (blocklist/watch semantics).
    pub addr: EntityAddr,
    /// Source of the accepted transport, used only for authorization.
    pub peer_addr: EntityAddr,
    pub caps: Option<Arc<Caps>>,
}

/// What the control core needs to know about a link of another core to handle a forwarded message.
#[derive(Debug, Clone)]
pub struct LinkCtx {
    pub(crate) caps: Option<String>,
    pub(crate) entity: String,
}

/// osdmap epochs ingested by the control core, for the workers.
#[derive(Debug)]
pub struct MapUpdate {
    /// Epoch the workers held before (0 = none).
    pub prev: u32,
    /// The map at `prev` when more than one epoch is new or it is the direct predecessor.
    pub prev_map: Option<Arc<OsdMap>>,
    pub new: Arc<OsdMap>,
    /// Every epoch of `(prev, new.epoch]`, decoded once on the control core and shared by all cores, oldest first.
    pub chain: Vec<Arc<OsdMap>>,
    /// Encoded maps for map sharing (workers keep only these of recent updates, not the decoded maps).
    pub blobs: Arc<MapBlobs>,
}

/// Encoded epochs of one [`MapUpdate`].
#[derive(Debug)]
pub struct MapBlobs {
    /// Epoch of `MapUpdate::new`.
    pub epoch: u32,
    /// The mon message (incrementals / fulls).
    pub msg: MOSDMap,
    /// Encoded full map of `epoch` (when `msg` has none).
    pub full: Option<Vec<u8>>,
}

/// Inputs and result of one capacity aggregation. Retain the local observation so transition
/// diagnostics use the same capacity input as the failsafe decision.
pub(crate) struct SpaceSnapshot {
    pub aggregate: messages::StoreStatfs,
    pub local: Space,
    pub local_store: Option<Space>,
    pub available_before_clamp: u64,
    /// Core whose ceiling (fullest shard, plain core: also its sum) bounds the aggregate's fill.
    pub fullest_core: Option<usize>,
}

/// Per-core numbers the control core aggregates (sent every second).
#[derive(Debug, Default, Clone)]
pub struct CoreStats {
    /// Monotonic sample time in the driver-shared clock; includes cross-core queue delay in report age.
    pub sampled_at: Duration,
    /// Per-shard capacity detail sampled alongside `space` (empty for stores without this diagnostic).
    pub space_shards: Vec<peering::store::ShardSpace>,
    /// Op counters, utilization and store counters for the admin dumps (built here, read off the cores,
    /// [`crate::ctrsnap`]).
    pub counters: std::sync::Arc<crate::ctrsnap::CoreCounters>,
    /// `(pgid, encoded pg_stat_t)` of primary PGs.
    pub pg_stats: Vec<(PgT, Vec<u8>)>,
    pub num_pgs: u32,
    /// Creates of PGs this core leads withheld by the PG hard limit (`PENDING_CREATING_PGS`).
    pub pending_creating: u64,
    /// Primary PGs of the core.
    pub primary_pgs: Vec<PgT>,
    /// Other OSDs in the up or acting set of the core's PGs (heartbeat PG peers, osd-lifecycle 5.2), sorted.
    pub pg_osds: Vec<i32>,
    /// Min last_epoch_clean over primary PGs.
    pub lce: Option<u32>,
    /// Oldest map epoch any PG of the core still needs.
    pub min_epoch: Option<u32>,
    pub omap: i64,
    /// Local data and compression usage by pool (MPGStats `pool_stat`); OMAP uses primary PG scrub stats.
    pub pool_bytes: Vec<crate::pgs::PoolBytes>,
    pub space: Option<Space>,
    /// Decline-mode answers by kind (adr 0039 am. 1).
    pub ec_declined: Vec<(&'static str, u64)>,
    /// PGs stopped by the past-interval bounds check, with required and stored ranges (peering.md 3.8,
    /// `FLASHSTORE_PG_PAST_INTERVALS`).
    pub pg_bounds_stopped: Vec<peering::BoundsStoppedPg>,
    /// Background PG deletion of the core: (progress, objects/s).
    pub removal: (peering::store::RemovalProgress, u64),
    /// `(store shard, bytes a PG copy could still reserve)` of the core's shards (adr 0031 am. 4: deferred moves retry
    /// when their destination has room).
    pub mig_rooms: Vec<(u32, u64)>,
    /// Bytes the core's held backfill reservations still expect (`PgSet::backfill_held`): the control core adds them
    /// to the OSD's fill for FULL / BACKFILLFULL and the other cores' reservation judgement (osd-lifecycle 4.4).
    pub bf_held: u64,
}

/// Data-segment extras of an encoded frame: the crc hint of `segs.data` and further parts sent by reference after it
/// (`msgr2::Message::{data_crc, data_more}`; a replicated large write's payload, adr 0061 am. 1).
#[derive(Clone, Default, Debug)]
pub struct DataX {
    pub crc: msgr2::CrcHint,
    pub more: msgr2::DataMore,
    /// msgr2 header `data_off`: where the sender's payload lies in the segment (receivers place by it,
    /// `msgr2::Decoder::set_rx_place`, spec msgr2.md 3.1); 0 = no statement.
    pub data_off: u16,
}

impl From<msgr2::CrcHint> for DataX {
    fn from(crc: msgr2::CrcHint) -> Self {
        DataX {
            crc,
            ..Default::default()
        }
    }
}

/// Cross-core message. Large payloads are boxed: ring slots stay small.
pub enum XMsg {
    // ---- connection core -> PG core
    /// Client op for a PG of the receiver.
    Op {
        conn: u64,
        tid: u64,
        info: Arc<ConnInfo>,
        op: Box<MOSDOp>,
    },
    /// Source read `tid` of a copy-from for OSD `osd`: put it on the client link to it (receiver = `peer_core(osd)`).
    CopyOut {
        osd: i32,
        tid: u64,
        op: Box<MOSDOp>,
    },
    /// Origin expired or rerouted a copy source read: release the link owner's retained request.
    CopyCancel {
        osd: i32,
        tid: u64,
    },
    /// A source read of a copy-from (pseudo connection `conn`, see copy.rs) for a PG of the receiver.
    CopyRead {
        conn: u64,
        op: Box<MOSDOp>,
    },
    /// Client acked a backoff.
    BackoffAck {
        conn: u64,
        b: Box<MOSDBackoff>,
    },
    /// Pieces of a large write still arriving for PG `spg` of the receiver (whole pieces from a piece start): write
    /// them ahead (prewrite.rs, adr 0477). Same lane as the op of its frame, which follows them. `wake`: the first
    /// message of its frame wakes the PG core; the later ones ride on its next drain ([`XMsg::wakes`]).
    PrePiece {
        spg: SpgT,
        watch: msgr2::SegWatch,
        pieces: bytes::Bytes,
        wake: bool,
        /// `trace::now()` when the connection core cut the pieces (the PG core's lag: `pre_rx_lag_ns`).
        at: u64,
    },
    /// OSD<->OSD PG message (validated sender) for a PG of the receiver. `link` = where it came from.
    Pg {
        ingress: ingress::InputGuard,
        link: u64,
        from: i32,
        tid: u64,
        /// Header priority (recovery replies echo it, spec replication.md 6.1).
        prio: u16,
        body: Box<Body>,
    },
    /// MOSDScrub2 (validated), to every core.
    Scrub2(Box<MOSDScrub2>),
    /// MOSDForceRecovery (validated), to every core.
    ForceRecovery(Box<replwire::MOSDForceRecovery>),
    /// OSD-wide slot request (scrub, backfill, trim), to the core that keeps the budget (core 0). Same lane as its replies.
    Slot(peering::SlotReq),
    /// Answer to a [`XMsg::Slot`], to the requesting core.
    SlotReply(peering::SlotReply),
    /// Recovery-op budget (`osd_recovery_max_active`) traffic to core 0, which keeps the OSD-wide limit.
    Ops(peering::OpsReq),
    /// Answer to a [`XMsg::Ops`], to the requesting core.
    OpsReply(peering::OpsReply),
    /// A connection closed: drop per-connection state (engines, backoffs, map projection).
    ConnClosed {
        conn: u64,
    },
    // ---- PG core -> connection core
    /// Answer of a source read of a copy-from, to the core of the destination PG (`Err` = errno, re-sent there).
    CopyReply {
        id: u64,
        r: Result<Box<opwire::MOSDOpReply>, i32>,
    },
    /// Frame for link `link`.
    Wire {
        link: u64,
        tid: u64,
        prio: u16,
        hdr: (u16, u16, u16),
        segs: Segments,
        /// Known crc of `segs.data` (owner-bound hint) and further data parts, see `msgr2::Message::data_crc`.
        data_crc: DataX,
    },
    /// An admitted READ's unencoded reply, including error replies and original
    /// source owners, delivered to the connection core for attempt handling.
    ClientReply {
        link: u64,
        tid: u64,
        /// The admitted attempt's retry number (its terminal proof).
        retry: u32,
        reply: Box<opwire::MOSDOpReply>,
    },
    /// An admitted placement attempt ended without a reply (dropped op, EAGAIN):
    /// the connection core vacates its attempt owner.
    PlacementDone {
        link: u64,
        tid: u64,
        retry: u32,
    },
    /// A frame of sampled op `key` is queued on this (the link) core: stamp `stage` (`trace::TX`, `R_TX`) at the next tx step.
    TraceTx {
        key: u64,
        stage: u8,
    },
    /// Message to encode on the link's core (cold paths: tell replies, map sharing).
    Msg {
        link: u64,
        tid: Option<u64>,
        msg: Box<AnyMessage>,
    },
    /// Frame for the cluster link to OSD `to` (receiver = `peer_core(to)`).
    PeerWire {
        to: i32,
        /// Map epoch of the sending PG (`flow::Tx::epoch`).
        epoch: u32,
        target: Option<(u32, EntityAddrVec)>,
        tid: u64,
        prio: u16,
        hdr: (u16, u16, u16),
        segs: Segments,
        data_crc: DataX,
    },
    /// Close a link (malformed traffic).
    CloseLink {
        link: u64,
    },
    /// Send the map delta a client lacks.
    ShareMap {
        conn: u64,
        epoch: u32,
    },
    /// Negotiated features of the cluster link to `osd` incarnation `up_from` (all cores encode with them).
    PeerFeat {
        osd: i32,
        up_from: u32,
        features: u64,
    },
    // ---- any core -> control core
    /// Control-plane message (tell, mon command) received on a link of the sender.
    Ctl {
        link: u64,
        ctx: LinkCtx,
        tid: u64,
        msg: Box<AnyMessage>,
    },
    /// Message for the mon session.
    Mon(Box<AnyMessage>),
    /// Peering wants `up_thru >= want`.
    UpThru {
        want: u32,
    },
    /// Peering needs maps after `have`.
    ReqMap {
        have: u32,
    },
    /// Withheld mon creates have room again: ask the mon for its PG creates from `epoch` (peering.md 7.3 rule 3a).
    PgCreatesFrom {
        epoch: u32,
    },
    /// Local store failure: stop the OSD.
    Fatal(String),
    /// Periodic per-core numbers.
    Stats(Box<CoreStats>),
    /// Answer to [`XMsg::Query`] (`id` of the scatter, per-core result).
    QueryReply {
        id: u64,
        r: i32,
        out: Box<serde_json::Value>,
    },
    /// Owning core -> control: the part of scatter `id` that answered [`crate::tell::DEFERRED`] finished with `(r, rs)`
    /// (`mark_unfound_lost` once every shard committed). Ordered after that part's [`XMsg::QueryReply`].
    CmdDone {
        id: u64,
        r: i32,
        rs: String,
    },
    /// A core booted: its oldest PG's epoch `lo` and the PGs in its store; core 0 answers once every core reported.
    MapsReq {
        lo: u32,
        pgs: Vec<BootPg>,
    },
    /// Worker -> control: maps `[from, to]` from the persisted store (a PG is created from a message older than the
    /// kept maps, open question 13d).
    OldMapsReq {
        from: u32,
        to: u32,
    },
    /// Control -> worker: answer to [`XMsg::OldMapsReq`] (shared decoded maps; empty = trimmed from the store).
    OldMaps {
        from: u32,
        maps: Vec<Arc<OsdMap>>,
    },
    /// PG `spg` (destination shard `shard`) moves to the receiver: ops of the copy (`last` = final batch) of move
    /// attempt `seq`.
    MigData {
        spg: SpgT,
        shard: u32,
        ops: Vec<MigOp>,
        last: bool,
        seq: u64,
    },
    /// The receiver applied one [`XMsg::MigData`] (flow control).
    MigCredit {
        spg: SpgT,
    },
    /// The receiver holds a complete, durable copy: the sender may delete its own.
    MigAck {
        spg: SpgT,
    },
    /// Source -> destination core: reserve `bytes` of headroom on store shard `shard` for PG `pgid` before it moves
    /// (adr 0031 am. 4); the source moves `n` instances in attempt `seq`.
    MigReserve {
        pgid: PgT,
        shard: u32,
        bytes: u64,
        seq: u64,
        n: usize,
    },
    /// Destination -> source: no room for the copy of `pgid` after all (`imported` payload bytes were applied): the
    /// import is undone, the source serves its copy again and defers the move (adr 0031 am. 5).
    MigAbort {
        pgid: PgT,
        imported: u64,
    },
    /// Worker -> control: the stranded merge source `pgid` is obsolete (the PG covering it is complete here).
    MigObsolete {
        pgid: PgT,
    },
    /// Destination -> source: the headroom for `pgid` is held (`ok`) or there is no room (the move is deferred).
    MigGrant {
        pgid: PgT,
        ok: bool,
    },
    /// The sender started round `round` (its count of rounds): it holds what it routes for the round's PGs, everything it
    /// routed before is delivered (ordered barrier, adr 0031 am. 8). To every source core of the round.
    MigHold {
        round: u64,
    },
    /// Source -> destination: PG `pgid` is handed over; the PG messages sent before this one came from the source's
    /// queues (adr 0031 am. 8).
    MigHandoff {
        pgid: PgT,
    },
    /// This core finished its part of the PG moves of map epoch `epoch` (to the control core); `deferred` = its moves
    /// that did not start for lack of headroom at the destination, `stay` = its placements of arriving PGs that found
    /// an instance here (adr 0639: placed PGs never carry data).
    MigDone {
        epoch: u32,
        deferred: Vec<crate::mig::Deferred>,
        stay: Vec<PgT>,
    },
    /// PG `pgid` lives on store shard `shard` (a split child inherits its parent's; all cores keep the table).
    Placement {
        pgid: PgT,
        shard: u32,
    },
    // ---- control core -> workers
    /// The PG moves the round of map `epoch` consists of (empty = none): the control core decides, everybody follows.
    Gate {
        epoch: u32,
        moves: Vec<crate::mig::Move>,
    },
    /// Retry of deferred moves (room appeared at their destinations): a round at the applied map `epoch`, run after
    /// the maps this core received before it (adr 0031 am. 4).
    MigRetry {
        epoch: u32,
        moves: Vec<crate::mig::Move>,
    },
    /// The deferred moves of the OSD changed outside a round (a merge was cancelled, a stranded source became
    /// obsolete): destinations borrow for exactly theirs, holders delete stranded copies no longer listed.
    MigDeferred {
        list: Vec<crate::mig::Deferred>,
    },
    /// Every core finished the round of `epoch`: switch the placements (except of the `deferred` and `stay` PGs, which
    /// stay), apply the held map.
    Release {
        epoch: u32,
        deferred: Vec<crate::mig::Deferred>,
        stay: Vec<PgT>,
    },
    /// Reply to [`XMsg::MapsReq`]: maps, placement table, duplicates to drop, moves to run before loading.
    Boot(Box<BootInfo>),
    /// New osdmap epochs.
    Map(Arc<MapUpdate>),
    /// OSD state changed.
    State(State, u32),
    /// cephx keys changed.
    Keys(Box<MonAuthClient>),
    /// The mon session's NONE authorizer payload (`None` = the session runs cephx).
    NoneAuthorizer(Option<Vec<u8>>),
    /// Layered config changed.
    Conf(Box<ConfigDb>),
    /// MOSDPGCreate2 from the mon (every core creates the PGs it owns).
    Create(Box<pgwire::MOSDPGCreate2>),
    /// Peers known to run croit-flashstore-osd.
    NvPeers(BTreeSet<i32>),
    /// Peers that store long object names (adr 0021 am. 30).
    LongPeers(BTreeSet<i32>),
    /// Attach a peer OSD's heartbeat clock slot to this core's registry (adr 0683); once per peer discovery, never per
    /// sample.
    PeerClock {
        osd: i32,
        slot: Arc<peering::PeerClockSlot>,
    },
    /// The cluster session to a peer OSD was lost (`up` false) or reached READY (adr 0071).
    PeerLink {
        osd: i32,
        up: bool,
    },
    /// This core's fill view changed (control core computes it from the aggregated statfs and every core's held
    /// backfill bytes, `used` without the receiver's own).
    LocalFull(peering::LocalFull),
    /// PGs on the whole OSD changed (control core): the per-PG log target follows it.
    NumPgs(u32),
    /// Any recovery reservation is held OSD-wide (control core reads its budget): `osd_scrub_during_recovery`.
    ScrubRecovering(bool),
    /// New mon session: re-send mon-bound state.
    MonSession,
    /// Run the per-core part of a scattered command (JSON command text); the answer is an [`XMsg::QueryReply`].
    Query {
        id: u64,
        cmd: String,
    },
    /// LAB: hold back store completions for the given milliseconds.
    #[cfg(feature = "lab")]
    LabStall(u64),
    // ---- peer connection placement (pipe.rs): landing core <-> the core owning the peer's sessions
    /// Landing -> owner: resume this connection (its socket is `zid` on the sender).
    Handoff {
        ingress: ingress::InputGuard,
        zid: u64,
        sock: Option<SocketAddr>,
        h: msgr2::Handoff,
        /// What cephx told the landing core about the peer (entity, caps).
        auth: crate::auth::PeerAuth,
    },
    /// Landing -> owner: bytes read from the socket.
    PipeIn {
        zid: u64,
        data: bytes::Bytes,
        ingress: ingress::InputGuard,
    },
    /// Landing -> owner: the socket closed.
    PipeClosed {
        zid: u64,
    },
    /// Owner -> landing: bytes for the socket.
    PipeOut {
        zid: u64,
        runs: Vec<bytes::Bytes>,
    },
    /// Owner -> landing: close the socket after the queued output.
    PipeClose {
        zid: u64,
    },
    /// Helper work / result (run compaction, omap LSM flush / merge round); the original owner alone reconciles and
    /// publishes.
    CompactWork(store::shard::HelperJob),
    CompactDone(store::shard::HelperJob),
    /// Elastic pool (adr 0021 am. 53): store pool message between cores (request to core 0, the owner; answer to the core of the
    /// borrowing shard). Own FIFO lane, delivered exactly once.
    #[cfg(feature = "elastic")]
    Pool(peering::PoolMsg),
    /// Wrongly marked down in map `epoch`: the cluster + heartbeat identity of the OSD takes this nonce (spec 7.4); PG
    /// frames stamped before `epoch` belong to the old identity (`Osd::rebind_epoch`).
    Rebind {
        nonce: u32,
        epoch: u32,
    },
    /// Graceful shutdown.
    Shutdown,
}

/// Time slice of one drain (adr 0006 am. 4): the link-event pump and, per source core, the PG-core inbox (`rt::xport`, am. 6)
/// stop after the message whose work fills ~100 us (or at their count cap; the first message always runs).
pub const SLICE_NS: u64 = 100_000;

/// Learned cost of message work on this core: no clock read inside a loop iteration. Work units ([`XMsg::slice_work`],
/// link events alike) handed on in a loop iteration are summed; the runtime reports the iteration's busy ns from its one
/// clock read (`Osd::note_core_busy`), which updates ps per unit (EWMA 1/8). The slice is [`SLICE_NS`] / that rate. Until the
/// first report (and in the simulators, which report none) the rate is 1 ns per unit (128 KiB of payload ~ one slice).
/// Biased towards smaller slices: the iteration also polls the NIC, the store and sends. Work no message caused is kept
/// out (`Osd::note_core_busy`): listing continuations (adr 0522) and store background work (merges, compactions,
/// checkpoints, compaction helper steps; counted in, a few-ms merge slice in an iteration that drained a few messages cut the
/// next drains to their first message, and the core's message rate collapsed to one per iteration while the merge backlog
/// lasted). Fair share with that background work: a drain may take as long as the background work of the previous
/// iteration took, at least [`SLICE_NS`]. Under contention messages and maintenance get half of the core each; before, a
/// backlog of 3-5 ms merge slices ran against 100 us drains and messages waited 50-100 ms in the inbox.
///
/// Own links vs inbox (adr 0006 am. 6): the link-event pump runs once per received chunk, each run with a fresh slice, so
/// the own links hand on all their input of an iteration; the inbox drains once per iteration. Each source core's share of
/// a drain is one slice, at least the work the own links handed on since the previous drain ([`Slice::start_drain`]): a
/// client whose op is forwarded to the PG core waits no longer than one on the PG core's own links. With one slice for the
/// whole inbox, a hot object's PG core (~290 us per 256-key omap batch, a ~20 KiB slice) ran ~5 own-link ops and 1
/// forwarded op per iteration; forwarded ops waited ~15x longer (doc/perf/omap-hot-object-20261029.md).
#[derive(Debug)]
pub struct Slice {
    units: u64,
    ps_per_unit: u64,
    bg_ns: u64,
    linked: usize,
}

impl Default for Slice {
    fn default() -> Self {
        Slice {
            units: 0,
            ps_per_unit: 1000,
            bg_ns: 0,
            linked: 0,
        }
    }
}

impl Slice {
    /// Work units of one drain.
    pub fn budget(&self) -> usize {
        (SLICE_NS.max(self.bg_ns) * 1000 / self.ps_per_unit.max(1)) as usize
    }

    /// An inbox drain starts: the work units each source core may hand on in it, one slice, at least what the own links
    /// handed on since the previous drain (their count starts over).
    pub fn start_drain(&mut self) -> usize {
        self.budget().max(std::mem::take(&mut self.linked))
    }

    /// Work the own links' events handed on (link-event pump).
    pub fn add_link(&mut self, units: usize) {
        self.add(units);
        self.linked += units;
    }

    /// Busy ns of the previous iteration that went to background work: the next drains may take as long.
    pub fn share(&mut self, bg_ns: u64) {
        self.bg_ns = bg_ns;
    }

    /// Work handed on in this iteration.
    pub fn add(&mut self, units: usize) {
        self.units += units as u64;
    }

    /// Busy ns of the iteration that handed on the work added since the last call.
    pub fn learn(&mut self, ns: u64) {
        if let Some(sample) = ns.saturating_mul(1000).checked_div(self.units) {
            self.ps_per_unit = (self.ps_per_unit * 7 + sample) / 8;
            self.units = 0;
        }
    }
}

/// Work of a message without payload (acks, small reads, control): one block, the store I/O unit.
pub const SLICE_MIN: usize = 4096;

/// Bytes an op moves: write data in, read extents out.
fn op_work(op: &MOSDOp) -> usize {
    op.ops
        .iter()
        .map(|o| {
            if opwire::reads(o.op) {
                o.extent().length as usize
            } else {
                o.indata.len()
            }
        })
        .sum()
}

impl XMsg {
    /// The sender wakes a sleeping receiver for this message. Every message does but the later pieces of a pre-write
    /// frame: the PG core drains them with whatever wakes it next (the store completion of the frame's earlier pieces,
    /// other input, at the latest the op of the frame, which follows on the same lane).
    pub fn wakes(&self) -> bool {
        !matches!(self, XMsg::PrePiece { wake: false, .. })
    }

    /// A client listing request (omap_get_vals / omap_get_keys, PGLS / PGNLS): background work of the PG core, whose
    /// arrival does not make listing continuations yield (adr 0522, `pgs::ListShare`).
    pub fn is_listing(&self) -> bool {
        matches!(self, XMsg::Op { op, .. } if opexec::engine::is_listing(op))
    }

    /// Work units of this message in a drain [`Slice`]: its payload bytes, at least [`SLICE_MIN`].
    pub fn slice_work(&self) -> usize {
        use replwire::ReplMsg;
        let n = match self {
            XMsg::Op { op, .. } | XMsg::CopyRead { op, .. } => op_work(op),
            XMsg::Pg { body, .. } => match &**body {
                Body::Repl(ReplMsg::RepOp(m)) => m.txn_data.len(),
                Body::Repl(ReplMsg::Push(m)) => m.pushes.iter().map(|p| p.data.len()).sum(),
                Body::Ec(ecwire::EcMsg::Write(m)) => m.op.txn_data.len(),
                _ => 0,
            },
            XMsg::Wire { segs, data_crc, .. } | XMsg::PeerWire { segs, data_crc, .. } => {
                segs.data.len() + data_crc.more.iter().map(|(b, _)| b.len()).sum::<usize>()
            }
            XMsg::ClientReply { reply, .. } => {
                reply.ops.iter().map(opwire::OsdOp::outdata_len).sum()
            }
            _ => 0,
        };
        n.max(SLICE_MIN)
    }
}

impl std::fmt::Debug for XMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            XMsg::Op { .. } => "Op",
            XMsg::CopyRead { .. } => "CopyRead",
            XMsg::CopyReply { .. } => "CopyReply",
            XMsg::CopyOut { .. } => "CopyOut",
            XMsg::CopyCancel { .. } => "CopyCancel",
            XMsg::BackoffAck { .. } => "BackoffAck",
            XMsg::PrePiece { .. } => "PrePiece",
            XMsg::Pg { .. } => "Pg",
            XMsg::Scrub2(_) => "Scrub2",
            XMsg::ForceRecovery(_) => "ForceRecovery",
            XMsg::Slot(_) => "Slot",
            XMsg::SlotReply(_) => "SlotReply",
            XMsg::Ops(_) => "Ops",
            XMsg::OpsReply(_) => "OpsReply",
            XMsg::ConnClosed { .. } => "ConnClosed",
            XMsg::Wire { .. } => "Wire",
            XMsg::ClientReply { .. } => "ClientReply",
            XMsg::PlacementDone { .. } => "PlacementDone",
            XMsg::Msg { .. } => "Msg",
            XMsg::PeerWire { .. } => "PeerWire",
            XMsg::CloseLink { .. } => "CloseLink",
            XMsg::ShareMap { .. } => "ShareMap",
            XMsg::PeerFeat { .. } => "PeerFeat",
            XMsg::Ctl { .. } => "Ctl",
            XMsg::Mon(_) => "Mon",
            XMsg::UpThru { .. } => "UpThru",
            XMsg::ReqMap { .. } => "ReqMap",
            XMsg::PgCreatesFrom { .. } => "PgCreatesFrom",
            XMsg::Fatal(_) => "Fatal",
            XMsg::Stats(_) => "Stats",
            XMsg::QueryReply { .. } => "QueryReply",
            XMsg::Query { .. } => "Query",
            XMsg::CmdDone { .. } => "CmdDone",
            XMsg::MapsReq { .. } => "MapsReq",
            XMsg::OldMapsReq { .. } => "OldMapsReq",
            XMsg::OldMaps { .. } => "OldMaps",
            XMsg::Boot(_) => "Boot",
            XMsg::MigData { .. } => "MigData",
            XMsg::MigCredit { .. } => "MigCredit",
            XMsg::MigAck { .. } => "MigAck",
            XMsg::MigReserve { .. } => "MigReserve",
            XMsg::MigGrant { .. } => "MigGrant",
            XMsg::MigAbort { .. } => "MigAbort",
            XMsg::MigObsolete { .. } => "MigObsolete",
            XMsg::MigHold { .. } => "MigHold",
            XMsg::MigHandoff { .. } => "MigHandoff",
            XMsg::MigDone { .. } => "MigDone",
            XMsg::Placement { .. } => "Placement",
            XMsg::Gate { .. } => "Gate",
            XMsg::MigRetry { .. } => "MigRetry",
            XMsg::MigDeferred { .. } => "MigDeferred",
            XMsg::Release { .. } => "Release",
            XMsg::Map(_) => "Map",
            XMsg::State(..) => "State",
            XMsg::Keys(_) => "Keys",
            XMsg::NoneAuthorizer(_) => "NoneAuthorizer",
            XMsg::Conf(_) => "Conf",
            XMsg::TraceTx { .. } => "TraceTx",
            XMsg::Create(_) => "Create",
            XMsg::NvPeers(_) => "NvPeers",
            XMsg::LongPeers(_) => "LongPeers",
            XMsg::PeerLink { .. } => "PeerLink",
            XMsg::PeerClock { .. } => "PeerClock",
            XMsg::LocalFull(_) => "LocalFull",
            XMsg::NumPgs(_) => "NumPgs",
            XMsg::ScrubRecovering(_) => "ScrubRecovering",
            XMsg::MonSession => "MonSession",
            XMsg::Handoff { .. } => "Handoff",
            XMsg::PipeIn { .. } => "PipeIn",
            XMsg::PipeClosed { .. } => "PipeClosed",
            XMsg::PipeOut { .. } => "PipeOut",
            XMsg::PipeClose { .. } => "PipeClose",
            XMsg::CompactWork(_) => "CompactWork",
            XMsg::CompactDone(_) => "CompactDone",
            #[cfg(feature = "elastic")]
            XMsg::Pool(_) => "Pool",
            XMsg::Rebind { .. } => "Rebind",
            XMsg::Shutdown => "Shutdown",
            #[cfg(feature = "lab")]
            XMsg::LabStall(_) => "LabStall",
        })
    }
}

/// Encoded-input windows of one OSD (adr 0084 am. 2): client data of physical shard `s` uses window `s`, peer data
/// window `shards + s`. Client writes keep their reservation until the replicas acked; peer data only waits for the local
/// store. One shared window let client writes starve the peer repop at the head of a link whose following acks they
/// waited for (rented PG hang). The two classes are separate byte pools of the memory envelope (`memory::Envelope`): the
/// bytes reserved by all client windows (and by all peer windows) never exceed `Envelope::pool`, the input pauses
/// (backpressure to the transport) instead of growing the process.
pub fn input_credits(shards: u32) -> ingress::IngressCredits {
    let pool = crate::memory::active().pool();
    ingress::IngressCredits::with_frames(
        &[(shards as usize, pool), (shards as usize, pool)],
        FRAME_SLOTS,
    )
}

/// Message frames in flight per ingress pool (frames being received, held, or owned by a running op): the slots of
/// the frame window. 16384 cover thousands of connections with deep queues; running out is backpressure like a full pool.
pub(crate) const FRAME_SLOTS: usize = 16384;

/// Header-time frame admission per ingress pool (client, peer) of `credits`; none without frame windows.
fn frame_gates_of(credits: &ingress::IngressCredits) -> Option<[ingress::FrameGate; 2]> {
    credits
        .has_frames()
        .then(|| [credits.frame_gate(0), credits.frame_gate(1)])
}

/// Newest map updates a worker keeps for map sharing with clients.
const RECENT_UPDATES: usize = 64;

/// Multi-core state of one [`Osd`].
#[derive(Debug)]
pub(crate) struct Cl {
    pub spec: CoreSpec,
    /// Outgoing messages `(destination core, message)`.
    pub out: Outbox<XMsg>,
    pub sequence: Sequencer,
    pub ingress: ingress::IngressCredits,
    pub control_ingress: ingress::IngressCredits,
    /// Header-time frame admission per pool: client (public links), peer (cluster links); none without frame windows.
    pub frame_gates: Option<[ingress::FrameGate; 2]>,
    /// Bytes this core buffers for unauthenticated handshakes, one budget per messenger (index `MsgrId as usize`):
    /// charged as a transcript grows, released at authentication or close. Separate budgets, so handshakes on the
    /// public listener can never use the cluster or heartbeat allowance.
    pub preauth_used: [u64; crate::osd::MsgrId::COUNT],
    /// Bytes this core may buffer for unauthenticated handshake transcripts per messenger (`Cl::preauth_used`,
    /// `PREAUTH_TRANSCRIPT_MAX` per link): `Envelope::pool() / MsgrId::COUNT` each, so the budgets of all messengers
    /// together stay inside one ingress pool share and one listener's handshakes can never use another's. Idle links
    /// buffer nothing (they are closed by `ms_connection_ready_timeout`); a transcript beyond its messenger's budget
    /// closes the link loudly, the peer retries.
    pub preauth_limit: u64,
    /// Links whose message header waits for pool space, one queue per pool of `frame_gates` (client, peer); the pool
    /// decides the admission order across cores (`Osd::resume_frames`), a full pool never delays the other one.
    pub frame_wait: [FrameWait; 2],
    /// This core's wake handle: whoever frees ingress space wakes it while it holds input or frames for lack of space.
    pub waker: Option<Arc<ingress::Parker>>,
    pub pending_input: Vec<VecDeque<u64>>,
    pub pending_count: usize,
    /// Client ops admitted here whose owner core is not reachable (cross-core queue full): the head of every link's
    /// input until the queue drains, in arrival order (no EAGAIN: classic never answers load with it).
    pub xout_wait: VecDeque<(u64, u64, MOSDOp)>,
    pub resuming_input: bool,
    pub resuming_conn: Option<u64>,
    pub raw_input: Option<(u64, ingress::InputGuard)>,
    /// Verified data-segment crc of the message being handled (`msgr2::Incoming::data_crc`), with `raw_input`.
    pub raw_crc: msgr2::CrcHint,
    /// Header priority of the message being handled (the default outside a received frame), with `raw_input`.
    pub raw_prio: u16,
    /// PG core: connections of other cores that sent us ops.
    pub remote: HashMap<u64, Arc<ConnInfo>, foldhash::fast::RandomState>,
    /// Negotiated features per peer OSD, valid for the incarnation `up_from` only (see `Osd::peer_features`).
    pub peer_feat: HashMap<i32, (u32, u64), foldhash::fast::RandomState>,
    /// Control: link contexts of forwarded control messages.
    pub rlinks: HashMap<u64, LinkCtx, foldhash::fast::RandomState>,
    /// Control: state last announced to the workers.
    pub last_state: Option<(State, u32)>,
    /// Control: latest numbers per core (index = core; own slot unused).
    pub stats: Vec<Option<CoreStats>>,
    /// Control: last logged actual blocking-growth failure sequence per store shard.
    pub meta_growth_seen: HashMap<u32, u64>,
    /// Control: `LocalFull` last sent per core (index = core; own slot unused).
    pub local_full_sent: Vec<Option<peering::LocalFull>>,
    /// Workers: recent map updates (map sharing source).
    pub recent: VecDeque<Arc<MapBlobs>>,
    /// Worker: waiting for the control core's maps before loading PGs.
    pub boot_wait: bool,
    /// PG migration between cores (adr 0031).
    pub mig: MigState,
    /// Client ops forwarded to another core / PG messages forwarded / PG messages sent via another core (counters).
    pub fwd_ops: u64,
    pub fwd_pg: u64,
    pub fwd_peer_tx: u64,
    /// One dispatch credit per helper core (index = core), held through work and the result's return trip: at most one
    /// job of this core on each other core.
    pub compact_inflight: Vec<Option<store::shard::CompactionId>>,
    pub compact_configured: Option<bool>,
    pub compact_next: usize,
    pub compact_work: VecDeque<(usize, store::shard::HelperJob)>,
    /// Ns this iteration's compaction helper steps took (background work of the drain slice, [`Slice`]).
    pub helper_ns: u64,
}

impl Cl {
    pub(crate) fn new(spec: CoreSpec) -> Cl {
        let ingress = input_credits(spec.shards);
        let frame_gates = frame_gates_of(&ingress);
        Cl {
            spec,
            out: Outbox::sparse(spec.n, spec.shards as usize + 4, spec.id),
            sequence: Sequencer::new(spec.n, spec.shards as usize + 4),
            ingress,
            control_ingress: ingress::IngressCredits::with_count(1, 32),
            frame_gates,
            preauth_used: [0; crate::osd::MsgrId::COUNT],
            preauth_limit: (crate::memory::active().pool() / crate::osd::MsgrId::COUNT as u64)
                .max(1),
            frame_wait: [FrameWait::new(), FrameWait::new()],
            waker: None,
            pending_input: (0..=2 * spec.shards).map(|_| VecDeque::new()).collect(),
            pending_count: 0,
            xout_wait: VecDeque::new(),
            resuming_input: false,
            resuming_conn: None,
            raw_input: None,
            raw_crc: Default::default(),
            raw_prio: pgwire::msgs::PRIO_DEFAULT,
            remote: HashMap::default(),
            peer_feat: HashMap::default(),
            rlinks: HashMap::default(),
            last_state: None,
            stats: (0..spec.n).map(|_| None).collect(),
            meta_growth_seen: HashMap::new(),
            local_full_sent: vec![None; spec.n],
            recent: VecDeque::new(),
            boot_wait: false,
            mig: MigState::new(spec.n),
            fwd_ops: 0,
            fwd_pg: 0,
            fwd_peer_tx: 0,
            compact_inflight: vec![None; spec.n],
            compact_configured: None,
            compact_next: (spec.id + 1) % spec.n,
            compact_work: VecDeque::with_capacity(spec.n.saturating_sub(1)),
            helper_ns: 0,
        }
    }
}

impl<B: Backend> Osd<B> {
    /// One aggregate maintenance quantum per core poll, not one quantum per peer/job.
    pub(crate) fn poll_compaction(&mut self) -> bool {
        self.cl.helper_ns = 0;
        if self.cl.compact_configured != Some(true) && self.cl.compact_work.is_empty() {
            return false;
        }
        let accepting = self.multi() && !self.pg.dead && self.state != State::Stopping;
        let mut progress = false;
        while accepting
            && let Some(to) = self.free_helper()
            && let Some(job) = B::take_compaction(&self.pg.store)
        {
            self.cl.compact_next = (to + 1) % self.cores();
            self.cl.compact_inflight[to] = Some(job.id());
            self.xsend(to, XMsg::CompactWork(job));
            progress = true;
        }
        if self.cl.compact_work.is_empty() {
            return progress;
        }
        let start = std::time::Instant::now();
        for _ in 0..8 {
            let Some((owner, mut job)) = self.cl.compact_work.pop_front() else {
                break;
            };
            let completed = accepting && job.step(256);
            if !accepting || completed {
                self.xsend(owner, XMsg::CompactDone(job));
                B::compaction_activity(&self.pg.store, self.cl.compact_work.len(), completed);
            } else {
                self.cl.compact_work.push_back((owner, job));
            }
            progress = true;
            if start.elapsed().as_nanos() >= SLICE_NS as u128 {
                break;
            }
        }
        B::compaction_activity(&self.pg.store, self.cl.compact_work.len(), false);
        self.cl.helper_ns = start.elapsed().as_nanos() as u64;
        progress
    }

    /// The next core (round robin from `compact_next`, not this one) holding no job of this core.
    pub(crate) fn free_helper(&self) -> Option<usize> {
        let n = self.cores();
        (0..n)
            .map(|i| (self.cl.compact_next + i) % n)
            .find(|&c| c != self.core_id() && self.cl.compact_inflight[c].is_none())
    }

    /// Other cores holding no job of this core: the run compactions this core may hand out now (adr 0534 am. 1).
    pub(crate) fn free_helpers(&self) -> usize {
        let me = self.core_id();
        (0..self.cores())
            .filter(|&c| c != me && self.cl.compact_inflight[c].is_none())
            .count()
    }

    /// Install the shared, preallocated ingress windows before starting this core.
    pub fn set_ingress_credits(&mut self, credits: ingress::IngressCredits) {
        assert!(self.cl.ingress.idle() && self.cl.pending_count == 0);
        assert_eq!(credits.windows(), 2 * self.cl.spec.shards as usize);
        self.cl.frame_gates = frame_gates_of(&credits);
        self.cl.ingress = credits;
        if let Some(p) = self.cl.waker.clone() {
            self.install_parker(p);
        }
    }

    /// Install this core's wake handle before starting it: a release of ingress space by any core wakes it while it
    /// holds input or a message header for lack of that space, an admin socket worker after queueing a command (no
    /// polling, no sleep cap to wait out), and the store's off-owner workers after a published completion (RocksDB OMAP).
    pub fn set_core_waker(&mut self, w: Arc<dyn ingress::Waker>) {
        self.set_cmd_waker(w.clone());
        let store_wake = w.clone();
        self.pg
            .store
            .set_owner_wake(Arc::new(move || store_wake.wake()));
        self.install_parker(ingress::Parker::new(w));
    }

    fn install_parker(&mut self, p: Arc<ingress::Parker>) {
        if let Some(gates) = self.cl.frame_gates.take() {
            self.cl.frame_gates = Some(gates.map(|g| g.with_parker(p.clone())));
        }
        self.cl.waker = Some(p);
    }

    /// [`IngressCredits::ready`](ingress::IngressCredits::ready); with `park` (retry paths, never the idle re-check)
    /// this core is registered for the next release when not ready (see [`ingress::Parker`]).
    pub(crate) fn input_room(
        &self,
        credits: &ingress::IngressCredits,
        window: usize,
        bytes: usize,
        park: bool,
    ) -> bool {
        match &self.cl.waker {
            Some(p) if park => credits.ready_or_park(window, bytes, p),
            _ => credits.ready(window, bytes),
        }
    }

    /// Input shard of PG `pgid`: its window and mesh data lane. Multi-core: the map of the destination
    /// ([`PgSet::core_of`](peering::PgSet::core_of)), so the lane's owner core is the receiving core; a split child goes
    /// to its parent's shard, a store placement the PG set has not loaded (detached, unloadable, temp-only) does not count.
    /// One core (no PG set placement, no cross-core lanes): the store's shard of the PG.
    pub(crate) fn input_shard(&self, pgid: PgT) -> usize {
        use peering::PgStoreOps;
        (match self.cl.spec.owner() {
            Some(_) => self.pg.set.pg_shard(pgid),
            None => self.pg.store.shard_of_pg(pgid).unwrap_or(0),
        }) as usize
    }

    /// Input window and retained-input lane of peer data for `pgid` (see [`input_credits`]).
    pub(crate) fn peer_input_lane(&self, pgid: PgT) -> usize {
        self.cl.spec.shards as usize + self.input_shard(pgid)
    }

    /// Retained-input lane of peer controls (their window is `control_ingress`).
    pub(crate) fn control_input_lane(&self) -> usize {
        2 * self.cl.spec.shards as usize
    }

    /// This core's index.
    pub fn core_id(&self) -> usize {
        self.cl.spec.id
    }

    /// Number of cores of the OSD.
    pub fn cores(&self) -> usize {
        self.cl.spec.n
    }

    /// Core 0: owns the control plane.
    pub(crate) fn is_control(&self) -> bool {
        self.cl.spec.id == 0
    }

    pub(crate) fn multi(&self) -> bool {
        self.cl.spec.n > 1
    }

    pub(crate) fn xsend(&mut self, dst: usize, m: XMsg) {
        debug_assert!(dst != self.cl.spec.id);
        let m = if matches!(m, XMsg::Stats(_)) {
            match self.cl.out.replace_tail(dst, 1, m) {
                Ok(()) => return,
                Err(m) => m,
            }
        } else {
            m
        };
        let route = self.xroute(&m);
        let message = self.cl.sequence.stamp(dst, route, m);
        self.cl.out.push(dst, message);
    }

    pub(crate) fn xroute(&self, message: &XMsg) -> Route {
        match message {
            XMsg::Op { op, .. } | XMsg::CopyRead { op, .. } => {
                Route::Data(self.input_shard(op.pgid.pgid))
            }
            // a PG message lands on the lane of the op (client) or repop (peer) its frame becomes, else on the progress
            // FIFO (separate from data and raw relay input; fenced by ordered controls, so completion messages cannot
            // cross an interval change)
            XMsg::Pg { body, .. } => match data_spg(body) {
                Some(spg) => Route::Data(self.input_shard(spg.pgid)),
                None if pg_progress(body) => Route::Data(self.cl.spec.shards as usize + 1),
                None => Route::Ordered,
            },
            // the lane of the op/repop its frame becomes: the pieces come first, the op follows
            XMsg::PrePiece { spg, .. } => Route::Data(self.input_shard(spg.pgid)),
            XMsg::PipeIn { .. } => Route::Data(self.cl.spec.shards as usize),
            XMsg::BackoffAck { .. }
            | XMsg::CopyReply { .. }
            | XMsg::CopyOut { .. }
            | XMsg::CopyCancel { .. }
            | XMsg::Wire { .. }
            | XMsg::ClientReply { .. }
            | XMsg::PlacementDone { .. }
            | XMsg::PeerWire { .. }
            | XMsg::TraceTx { .. }
            | XMsg::PipeOut { .. }
            | XMsg::MigCredit { .. }
            | XMsg::MigAck { .. }
            | XMsg::MigReserve { .. }
            | XMsg::MigGrant { .. }
            | XMsg::MigAbort { .. }
            | XMsg::MigDone { .. } => Route::Data(self.cl.spec.shards as usize + 1),
            XMsg::CompactWork(_) | XMsg::CompactDone(_) => {
                Route::Data(self.cl.spec.shards as usize + 1)
            }
            #[cfg(feature = "elastic")]
            XMsg::Pool(_) => Route::Data(self.cl.spec.shards as usize + 1),
            // Samples replace an earlier sample; they do not mutate PG, connection or placement state.
            XMsg::Stats(_) => Route::Progress,
            _ => Route::Ordered,
        }
    }

    /// Destination gate for a lane-aware port. Reserved ownership already bounds actor-retained data.
    pub fn xmsg_ready(&self, from: usize, message: &XMsg) -> bool {
        use peering::PgStoreOps;
        if self.xroute(message) == Route::Ordered
            && self.pipes.h.iter().any(|(&id, pipe)| {
                pipe.core == from
                    && (!pipe.input.is_empty()
                        || self
                            .links
                            .get(&id)
                            .is_some_and(|l| l.pending_input.is_some() || l.conn.has_events()))
            })
        {
            return false;
        }
        match message {
            XMsg::Op { op, .. } | XMsg::CopyRead { op, .. } => {
                op.ingress.0.is_some() || self.pg.store.admission_ready_for(op.pgid)
            }
            XMsg::Pg { ingress, body, .. } => {
                ingress.0.is_some()
                    || data_spg(body).is_none_or(|spg| self.pg.store.admission_ready_for(spg))
            }
            _ => true,
        }
    }

    /// Elastic pool (adr 0021 am. 53): forward the store's pool messages. A request goes to core 0 (the store mounting shard 0 owns
    /// the pool), an answer to the core mounting the borrowing shard (`shard % cores`, as `mount_dev_core`). Each message is
    /// taken out of the store once and handed to exactly one lane push: no loss, no duplicate by construction.
    #[cfg(feature = "elastic")]
    pub(crate) fn pool_forward(&mut self) {
        use peering::{PgStoreOps as _, PoolMsg};
        let mut out = Vec::new();
        self.pg.store.pool_take(&mut out);
        let n = self.cl.spec.n;
        for m in out {
            let dst = match m {
                PoolMsg::Request { .. } | PoolMsg::Return { .. } | PoolMsg::Spare { .. } => 0,
                PoolMsg::Grant { shard, .. }
                | PoolMsg::Deny { shard, .. }
                | PoolMsg::Grew { shard, .. }
                | PoolMsg::Size { shard, .. } => shard as usize % n,
            };
            if dst == self.cl.spec.id {
                self.pg.store.pool_in(m);
            } else {
                self.xsend(dst, XMsg::Pool(m));
            }
        }
    }

    /// Send to every other core.
    pub(crate) fn xbcast(&mut self, mk: impl Fn() -> XMsg) {
        for d in 0..self.cl.spec.n {
            if d != self.cl.spec.id {
                self.xsend(d, mk());
            }
        }
    }

    /// Next message for another core. The driver moves it over its mesh (and keeps it when the ring is full).
    pub fn poll_xmsg(&mut self) -> Option<(usize, XMsg)> {
        self.prepare_xmsg();
        self.cl
            .out
            .pop_fifo()
            .map(|(dst, message)| (dst, message.value))
    }

    /// Drain eligible lane heads without losing their insertion-time barrier dependencies.
    pub fn poll_xmsg_ready(
        &mut self,
        ready: impl FnMut(usize, usize, &XMsg) -> bool,
    ) -> Option<(usize, Stamped<XMsg>)> {
        self.prepare_xmsg();
        self.cl.out.pop_ready(ready)
    }

    fn prepare_xmsg(&mut self) {
        self.flush_pipes();
        let now_state = (self.state, self.up_epoch);
        if self.is_control() && self.multi() && self.cl.last_state != Some(now_state) {
            self.cl.last_state = Some(now_state);
            self.xbcast(|| XMsg::State(now_state.0, now_state.1));
        }
    }

    /// A message from core `from`.
    pub fn on_xmsg(&mut self, from: usize, m: XMsg, now: Duration) {
        self.set_now(now);
        self.settle_late(); // a driver without `apply_late` (adr 0008 am. 2): nothing runs before it
        match m {
            // the sender routed by its own placement table; a PG in a move or whose owner changed is taken care of
            // (adr 0031 am. 8)
            m @ (XMsg::Op { .. }
            | XMsg::CopyRead { .. }
            | XMsg::BackoffAck { .. }
            | XMsg::PrePiece { .. }
            | XMsg::Pg { .. }) => self.pg_item(Some(from), m),
            XMsg::CopyOut { osd, tid, op } => self.copy_out(osd, tid, *op),
            XMsg::CopyCancel { osd, tid } => self.copy_cancel_out(osd, tid),
            XMsg::CopyReply { id, r } => self.copy_back(id, r.map(|b| *b)),
            XMsg::Scrub2(m) => self.pg_scrub2_local(*m),
            XMsg::ForceRecovery(m) => self.pg_force_recovery_local(*m),
            XMsg::Slot(r) => self.pg_slot_req(r),
            XMsg::SlotReply(r) => self.pg_slot_reply(r),
            XMsg::Ops(r) => self.pg_ops_req(r),
            XMsg::OpsReply(r) => self.pg_ops_reply(r),
            XMsg::ConnClosed { conn } => self.pg_conn_gone(conn),
            XMsg::Wire {
                link,
                tid,
                prio,
                hdr,
                segs,
                data_crc,
            } => {
                self.send_raw_crc(link, tid, prio, hdr, segs, data_crc);
            }
            XMsg::ClientReply {
                link,
                tid,
                retry,
                reply,
            } => {
                self.deliver_placement_reply(link, tid, retry, reply);
            }
            XMsg::PlacementDone { link, tid, retry } => {
                if let Some(l) = self.links.get_mut(&link)
                    && l.placement.done(tid, retry)
                {
                    self.close_link(link);
                }
            }
            XMsg::Msg { link, tid, msg } => {
                match tid {
                    Some(t) => self.send_link_tid(link, t, *msg),
                    None => self.send_link(link, *msg),
                };
            }
            XMsg::PeerWire {
                to,
                epoch,
                target,
                tid,
                prio,
                hdr,
                segs,
                data_crc,
            } => {
                let tx = crate::flow::Tx {
                    to,
                    epoch,
                    tid,
                    prio,
                    hdr,
                    segs,
                    data: data_crc,
                };
                self.peer_transmit(target, tx)
            }
            XMsg::CloseLink { link } => self.close_link(link),
            XMsg::ShareMap { conn, epoch } => self.pg_share_map(conn, epoch),
            XMsg::PeerFeat {
                osd,
                up_from,
                features,
            } => {
                self.cl.peer_feat.insert(osd, (up_from, features));
            }
            XMsg::Ctl {
                link,
                ctx,
                tid,
                msg,
            } => {
                self.cl.rlinks.insert(link, ctx);
                self.on_ctl_message(link, tid, *msg);
            }
            XMsg::Mon(m) => {
                self.send_mon(*m);
            }
            XMsg::UpThru { want } => self.want_up_thru_inner(want),
            XMsg::ReqMap { have } => self.pg_request_map(have),
            XMsg::PgCreatesFrom { epoch } => self.pg_resolicit_creates(epoch),
            XMsg::Fatal(why) => self.fail_stop(&why),
            XMsg::Stats(s) => {
                if from < self.cl.stats.len() {
                    self.report_meta_growth_failures(from, s.sampled_at, &s.space_shards);
                    self.cl.stats[from] = Some(*s);
                }
                self.mig_retry_check();
            }
            XMsg::QueryReply { id, r, out } => self.on_query_reply(from, id, r, *out),
            XMsg::Query { id, cmd } => self.on_query(from, id, &cmd),
            XMsg::CmdDone { id, r, rs } => self.on_cmd_done(from, id, r, rs),
            XMsg::MapsReq { lo, pgs } => self.boot_note(from, lo, pgs),
            XMsg::OldMapsReq { from: lo, to } => self.pg_serve_old_maps(from, lo, to),
            XMsg::OldMaps { from: lo, maps } => self.pg_old_maps_in(lo, maps),
            XMsg::Boot(b) => self.worker_boot(*b),
            XMsg::MigData {
                spg,
                shard,
                ops,
                last,
                seq,
            } => self.on_mig_data(from, spg, shard, ops, last, seq),
            XMsg::MigCredit { spg } => self.on_mig_credit(spg),
            XMsg::MigAck { spg } => self.on_mig_ack(spg),
            XMsg::MigReserve {
                pgid,
                shard,
                bytes,
                seq,
                n,
            } => self.on_mig_reserve(from, pgid, shard, bytes, seq, n),
            XMsg::MigAbort { pgid, imported } => self.on_mig_abort(pgid, imported),
            XMsg::MigObsolete { pgid } => self.on_mig_obsolete(pgid),
            XMsg::MigGrant { pgid, ok } => self.on_mig_grant(pgid, ok),
            XMsg::MigHold { round } => self.on_mig_hold(round),
            XMsg::MigHandoff { pgid } => self.on_mig_handoff(pgid),
            XMsg::MigDone {
                epoch,
                deferred,
                stay,
            } => self.on_mig_done(from, epoch, deferred, stay),
            XMsg::Placement { pgid, shard } => self.set_input_placement(pgid, shard),
            XMsg::Gate { epoch, moves } => self.on_mig_gate(epoch, moves),
            XMsg::MigRetry { epoch, moves } => self.on_mig_retry(epoch, moves),
            XMsg::MigDeferred { list } => self.on_mig_deferred(list),
            XMsg::Release {
                epoch,
                deferred,
                stay,
            } => self.on_mig_release(epoch, deferred, stay),
            XMsg::Map(u) => self.worker_map(u),
            XMsg::State(s, up) => {
                self.state = s;
                self.up_epoch = up;
                self.pg_retry_parked(false);
            }
            XMsg::LocalFull(f) => {
                self.pg.failsafe = f.failsafe;
                self.pg.set.set_local_full(f);
            }
            XMsg::NumPgs(n) => {
                self.pg_set_num_pgs(n);
            }
            XMsg::ScrubRecovering(v) => {
                self.scrub_recovering = v;
                self.pg.set.set_scrub_recovering(v);
            }
            XMsg::TraceTx { key, stage } => self.pg.tr.await_tx(key, stage),
            XMsg::Keys(k) => self.keys.set(*k),
            XMsg::NoneAuthorizer(p) => self.keys.set_none_authorizer(p),
            XMsg::Conf(c) => {
                self.conf = *c;
                self.refresh_obs_conf();
                self.pg_apply_scrub_cfg();
                self.pg_reapply_compression();
            }
            XMsg::Create(c) => self.pg_create_local(*c),
            XMsg::LongPeers(p) => self.pg.set.set_long_peers(p),
            XMsg::PeerLink { osd, up } => self.pg_peer_link_local(osd, up),
            XMsg::PeerClock { osd, slot } => self.pg.set.attach_peer_clock(osd, slot),
            XMsg::NvPeers(p) => {
                self.pg.peer_nv = p.clone();
                self.sync_keep_owed();
                let acts = self.pg.set.set_flashstore_peers(p);
                self.pg_exec(acts);
            }
            XMsg::MonSession => self.pg_on_mon_session(),
            #[cfg(feature = "lab")]
            XMsg::LabStall(ms) => self.cmds.stall_until = self.now + Duration::from_millis(ms),
            XMsg::Handoff {
                zid,
                sock,
                h,
                auth,
                ingress,
            } => self.on_handoff(from, zid, sock, h, auth, ingress),
            // hot path: input that completes nothing (middle of a frame, acks) needs no pump (as `Osd::on_bytes`)
            XMsg::PipeIn { zid, data, ingress } => {
                if !self.on_pipe_in(zid, data, ingress) {
                    self.cl.raw_input = None;
                    return;
                }
            }
            XMsg::PipeClosed { zid } => self.on_pipe_closed(zid),
            XMsg::PipeOut { zid, runs } => self.on_pipe_out(zid, runs),
            XMsg::PipeClose { zid } => self.on_pipe_close(zid),
            #[cfg(feature = "elastic")]
            XMsg::Pool(m) => {
                use peering::PgStoreOps as _;
                self.pg.store.pool_in(m);
            }
            XMsg::Rebind { nonce, epoch } => {
                self.rebind_epoch = self.rebind_epoch.max(epoch);
                self.set_nonce(nonce)
            }
            XMsg::CompactWork(job) => {
                if from == self.core_id() || from >= self.cores() {
                    return;
                }
                if self.pg.dead
                    || self.state == State::Stopping
                    || self.cl.compact_work.len() >= self.cores().saturating_sub(1)
                    || self.cl.compact_work.iter().any(|(owner, _)| *owner == from)
                {
                    self.xsend(from, XMsg::CompactDone(job));
                } else {
                    self.cl.compact_work.push_back((from, job));
                    B::compaction_activity(&self.pg.store, self.cl.compact_work.len(), false);
                }
            }
            XMsg::CompactDone(job) => {
                if self.cl.compact_inflight.get(from) == Some(&Some(job.id())) {
                    self.cl.compact_inflight[from] = None;
                    B::return_compaction(
                        &self.pg.store,
                        job,
                        !self.pg.dead && self.state != State::Stopping,
                    );
                }
            }
            XMsg::Shutdown => {
                self.state = State::Stopping;
                if self.done.is_none() && self.drain_until.is_none() {
                    self.drain_begin();
                }
            }
        }
        self.pump();
        self.cl.raw_input = None;
    }

    // ------------------------------------------------------------ control -> workers

    /// Worker: new epochs from the control core.
    fn worker_map(&mut self, u: Arc<MapUpdate>) {
        self.sb.cluster_osdmap_trim_lower_bound = self
            .sb
            .cluster_osdmap_trim_lower_bound
            .max(u.blobs.msg.cluster_osdmap_trim_lower_bound);
        self.pg
            .set
            .set_cluster_trim(self.sb.cluster_osdmap_trim_lower_bound);
        let prev = self.epoch();
        if u.new.epoch <= prev {
            return;
        }
        self.map = Some(u.new.clone());
        // blobs only: decoded maps pinned here would outlive the PG set map cache (64 updates x epochs each)
        self.cl.recent.push_back(u.blobs.clone());
        while self.cl.recent.len() > RECENT_UPDATES {
            self.cl.recent.pop_front();
        }
        // the PGs advance from what this core held, not from what the control core held
        let prev_map = if prev == u.prev {
            u.prev_map.clone()
        } else {
            None
        };
        // shared decoded epochs; an epoch this core already has (boot loaded newer maps) is not fed again
        let chain: Vec<Arc<OsdMap>> = u.chain.iter().filter(|m| m.epoch > prev).cloned().collect();
        self.pg_maps(prev_map, chain);
    }

    /// Control core: publish freshly ingested epochs.
    pub(crate) fn publish_map(
        &mut self,
        prev: u32,
        prev_map: Option<Arc<OsdMap>>,
        msg: &MOSDMap,
        full: Option<Vec<u8>>,
        chain: &[Arc<OsdMap>],
    ) {
        if !self.multi() {
            return;
        }
        let Some(new) = self.map.clone() else { return };
        let new_epoch = new.epoch;
        let u = Arc::new(MapUpdate {
            prev,
            prev_map,
            new,
            chain: chain.to_vec(),
            blobs: Arc::new(MapBlobs {
                epoch: new_epoch,
                msg: msg.clone(),
                full,
            }),
        });
        self.xbcast(|| XMsg::Map(u.clone()));
    }

    /// Control core: tell the workers the cephx keys changed.
    pub(crate) fn publish_keys(&mut self) {
        if self.multi() && self.is_control() {
            let k = self.mc.with_cephx(Clone::clone);
            if let Some(k) = k {
                self.xbcast(|| XMsg::Keys(Box::new(k.clone())));
            }
        }
    }

    /// Control core: tell the workers whether the mon session runs NONE (and the authorizer to present).
    pub(crate) fn publish_none_authorizer(&mut self, p: Option<Vec<u8>>) {
        if self.multi() && self.is_control() {
            self.xbcast(|| XMsg::NoneAuthorizer(p.clone()));
        }
    }

    pub(crate) fn publish_conf(&mut self) {
        if self.multi() && self.is_control() {
            let c = self.conf.clone();
            self.xbcast(|| XMsg::Conf(Box::new(c.clone())));
        }
    }

    pub(crate) fn publish_nv_peers(&mut self) {
        if self.multi() && self.is_control() {
            let p = self.pg.peer_nv.clone();
            self.xbcast(|| XMsg::NvPeers(p.clone()));
        }
    }

    // ------------------------------------------------------------ worker -> control

    /// Per-core numbers (see [`CoreStats`]).
    pub(crate) fn local_stats(&self) -> CoreStats {
        let me = self.id.whoami;
        let (mut primary_pgs, mut pg_osds, mut num_pgs) = (Vec::new(), BTreeSet::new(), 0u32);
        for (s, p) in self.pg.set.pgs() {
            num_pgs += 1;
            if p.is_primary() {
                primary_pgs.push(s.pgid);
            }
            pg_osds.extend(crate::hb::pg_peer_osds(p, me));
        }
        CoreStats {
            sampled_at: self.now,
            counters: std::sync::Arc::new(self.counter_sample()),
            pg_stats: self.pg_stat_list_local(),
            primary_pgs,
            pg_osds: pg_osds.into_iter().collect(),
            num_pgs,
            pending_creating: self.pg.set.pending_creating_pgs(),
            lce: self.pg.set.min_last_epoch_clean(),
            min_epoch: self.pg.set.min_pg_epoch(),
            omap: self.pg_omap_bytes_local(),
            pool_bytes: self.pg_pool_bytes_local(),
            space: peering::PgStoreOps::space(&self.pg.store),
            space_shards: peering::PgStoreOps::space_shards(&self.pg.store),
            removal: (
                peering::PgStoreOps::removal_progress(&self.pg.store),
                self.pg.del.rate,
            ),
            mig_rooms: peering::PgStoreOps::mig_rooms(&self.pg.store),
            bf_held: self.pg.set.backfill_held(&self.pg.store),
            ec_declined: self
                .pg
                .set
                .decline_stats
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            pg_bounds_stopped: self.pg.set.bounds_stopped(),
        }
    }

    /// Log the newest actual blocking-growth failure from each shard, even without a failsafe
    /// transition. Reports may coalesce several attempts: the sequence delta explicitly counts
    /// them; the payload is the latest attempt, captured at failure time. Repeated or older
    /// samples are silent. Cached retry suppression and reserve-only refusal are not attempts.
    pub(crate) fn report_meta_growth_failures(
        &mut self,
        core: usize,
        sampled_at: Duration,
        shards: &[peering::store::ShardSpace],
    ) {
        if !self.is_control() {
            return;
        }
        for shard in shards {
            let Some(failure) = shard.meta_growth_failure.as_ref() else {
                continue;
            };
            let seen = self.cl.meta_growth_seen.entry(shard.shard).or_default();
            if failure.sequence <= *seen {
                continue;
            }
            let attempts = failure.sequence - *seen;
            *seen = failure.sequence;
            let record = serde_json::json!({
                "version": 1, "event": "metadata_growth_blocked",
                "osd": self.id.whoami, "core": core, "shard": shard.shard,
                "reported_at_ns": self.now.as_nanos(), "report_sampled_at_ns": sampled_at.as_nanos(),
                "report_age_ms": self.now.saturating_sub(sampled_at).as_millis(),
                "currently_blocked": shard.meta_grow_blocked,
                "failed_attempts_since_previous_log": attempts,
                "failure": crate::osd::meta_growth_failure_json(failure),
            });
            self.logl(0, format!("metadata growth blocked {record}"));
        }
    }

    /// Worker: send the numbers to the control core.
    pub(crate) fn push_stats(&mut self) {
        if self.is_control() || !self.multi() {
            return;
        }
        let s = Box::new(self.local_stats());
        self.xsend(0, XMsg::Stats(s));
    }

    /// Control core: has every worker reported at least once (capacity known)?
    pub(crate) fn workers_reported(&self) -> bool {
        self.cl.stats.iter().skip(1).all(Option::is_some)
    }

    /// Worker: start of the core (PG boot; the control core drives everything else).
    pub(crate) fn worker_start(&mut self) {
        self.init = crate::osd::Init::Done;
        self.pg_boot();
    }

    /// Capacity of the whole OSD: the meta store's (core 0's shards) plus the other cores' last report.
    pub(crate) fn statfs_all(&self) -> messages::StoreStatfs {
        self.statfs_snapshot().aggregate
    }

    pub(crate) fn statfs_snapshot(&self) -> SpaceSnapshot {
        use crate::meta::MetaStore as _;
        let mut s = self.store.as_ref().map(|m| m.statfs()).unwrap_or_default();
        // ceiling of one core (adr 0021 S4): its fullest shard against what that shard can still get (`Space::fullest`);
        // a plain core also its own sum (a pooled core's sum misses the pool its shards may still borrow)
        let ceiling = |sp: &Space| {
            let own = if sp.pooled {
                0.0
            } else {
                // a shard set without capacity counts as empty
                crate::osd::fill(sp.total, sp.available).unwrap_or(0.0)
            };
            own.max(sp.fullest)
        };
        let local_store = peering::PgStoreOps::space(&self.pg.store);
        let local = Space {
            total: s.total,
            available: s.available,
            allocated: s.allocated.max(0) as u64,
            internal_metadata: s.internal_metadata.max(0) as u64,
            pooled: local_store.is_some_and(|p| p.pooled),
            fullest: local_store.map_or(0.0, |p| p.fullest),
        };
        let mut fullest = ceiling(&local);
        let mut fullest_core = (s.total > 0).then_some(self.cl.spec.id);
        for (core, sp) in self
            .cl
            .stats
            .iter()
            .enumerate()
            .filter_map(|(core, c)| c.as_ref().and_then(|c| c.space).map(|sp| (core, sp)))
        {
            let ratio = ceiling(&sp);
            if ratio > fullest || fullest_core.is_none() {
                fullest_core = Some(core);
            }
            fullest = fullest.max(ratio);
            s.total += sp.total;
            s.available += sp.available;
            s.allocated += sp.allocated as i64;
            // the store keeps no logical-bytes counter: allocated stands in for data_stored, exactly as the meta store
            // of core 0 reports it (`NvmeMeta::statfs`)
            s.data_stored += sp.allocated as i64;
            s.internal_metadata += sp.internal_metadata as i64;
        }
        // compressed extents (adr 0059 am. 1): summed over the PGs of every core, physical / logical bytes
        for (_, _, cp, co) in self.pg_pool_bytes_local().into_iter().chain(
            self.cl
                .stats
                .iter()
                .flatten()
                .flat_map(|c| c.pool_bytes.iter().copied()),
        ) {
            s.data_compressed += cp;
            s.data_compressed_allocated += cp;
            s.data_compressed_original += co;
        }
        // adr 0021 am. 5: report at least the fullest core's fill, a hot core must not hide behind the sum
        let used = (s.total as f64 * fullest) as u64;
        let available_before_clamp = s.available;
        s.available = s.available.min(s.total.saturating_sub(used));
        // everything charged beyond what the cores really hold is withheld capacity (`internally_reserved`): DATA / META
        // stay the real usage; total - available (full ratios, RAW USE, %USE) keeps the fullness charge
        s.internally_reserved = crate::meta::internally_reserved(
            s.total,
            s.available,
            (s.allocated + s.internal_metadata).max(0) as u64,
        );
        SpaceSnapshot {
            aggregate: s,
            local,
            local_store,
            available_before_clamp,
            fullest_core,
        }
    }

    /// Stored map blob from the meta store (control core).
    pub(crate) fn meta_map(&self, epoch: u32, kind: crate::meta::MapKind) -> Option<Vec<u8>> {
        use crate::meta::MetaStore as _;
        self.store.as_ref()?.get_map(epoch, kind).ok().flatten()
    }

    /// Map blob for sharing with clients: the meta store on core 0, the recent updates on workers.
    pub(crate) fn map_blob(&self, epoch: u32, kind: crate::meta::MapKind) -> Option<Vec<u8>> {
        use crate::meta::MapKind;
        if self.store.is_some() {
            return self.meta_map(epoch, kind);
        }
        for u in self.cl.recent.iter().rev() {
            match kind {
                MapKind::Inc => {
                    if let Some(b) = u.msg.incremental_maps.get(&epoch) {
                        return Some(b.clone());
                    }
                }
                MapKind::Full => {
                    if let Some(b) = u.msg.maps.get(&epoch) {
                        return Some(b.clone());
                    }
                    if u.epoch == epoch
                        && let Some(b) = &u.full
                    {
                        return Some(b.clone());
                    }
                }
            }
        }
        None
    }

    // ------------------------------------------------------------ routing helpers

    /// Where does `link` live?
    pub(crate) fn link_is_local(&self, link: u64) -> bool {
        link_on_core(link, self.cl.spec.id)
    }

    /// Message for the mon session (from any core).
    pub(crate) fn mon_out(&mut self, m: AnyMessage) -> Option<u64> {
        if self.is_control() {
            self.send_mon(m)
        } else {
            self.xsend(0, XMsg::Mon(Box::new(m)));
            Some(0)
        }
    }

    /// A forwarded control message (tell / mon command) of a link of another core.
    fn on_ctl_message(&mut self, link: u64, tid: u64, msg: AnyMessage) {
        match msg {
            AnyMessage::MCommand(c) => self.on_tell(link, tid, c),
            AnyMessage::MMonCommand(c) => self.on_legacy_mon_command(link, tid, c),
            AnyMessage::MOSDDedupList(m) => self.dedup_list_scatter(link, tid, &m),
            other => self.log(format!(
                "link {link}: unexpected forwarded message type {:#x}, dropped",
                other.msg_type()
            )),
        }
    }

    /// Worker: a control message arrived on a local link; the control core handles it.
    pub(crate) fn forward_ctl(&mut self, id: u64, tid: u64, msg: AnyMessage) {
        let Some(l) = self.links.get_mut(&id) else {
            return;
        };
        l.fwd |= 1; // core 0 remembers the link context until it hears of the close
        let ctx = LinkCtx {
            caps: l.auth.borrow().caps.clone(),
            entity: l.auth.borrow().entity.clone(),
        };
        self.xsend(
            0,
            XMsg::Ctl {
                link: id,
                ctx,
                tid,
                msg: Box::new(msg),
            },
        );
    }

    /// `(auth caps text, entity)` of a link, local or forwarded.
    pub(crate) fn link_auth(&self, link: u64) -> Option<(Option<String>, String)> {
        if let Some(l) = self.links.get(&link) {
            let a = l.auth.borrow();
            return Some((a.caps.clone(), a.entity.clone()));
        }
        self.cl
            .rlinks
            .get(&link)
            .map(|c| (c.caps.clone(), c.entity.clone()))
    }
}
