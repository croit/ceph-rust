// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The [`Osd`] state machine: plumbing (links, driver API, dispatch), startup sequence, map
//! ingestion and the boot / wrongly-marked-down state machine (spec 3, 7).
use crate::auth::{DaemonAuthClient, DaemonAuthServer, KeyStore, PeerAuth};
use crate::backend::Backend;
use crate::config::{ConfigDb, Level};
use crate::hb::Hb;
use crate::meta::{Identity, MapKind, MetaStore};
use crate::mgrc::MgrState;
use crate::perf::Perf;
use crate::pgs::PgHost;
use crate::xcore::{Cl, ConnInfo, CoreSpec, XMsg, link_core};
use bytes::Bytes;
use cephx::CryptoKey;
use cephx::none::ENTITY_OSD as ENTITY_OSD_BIT;
use denc::types::{EntityAddr, EntityAddrVec, EntityName, UTime, Uuid};
use messages::Message;
use messages::{AnyMessage, Header2, MOSDMap, OsdSuperblock};
use monc::{MonClient, MonEvent};
use msgr2::{Connection, Event, PolicyTable, SessionTable};
use opwire::MOSDOpReply;
use osdmap::OsdMap;
use osdmap::consts::{map_flags, osd_state, release};
use peering::PgStoreOps;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};

/// Local-id keyed maps (conn ids are ours, not attacker-chosen): seeded foldhash, not SipHash.
pub(crate) type FastMap<K, V> = HashMap<K, V, foldhash::fast::RandomState>;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

/// Connection ids of the embedded MonClient are `MON_BASE | id`.
pub(crate) const MON_BASE: u64 = 1 << 62;
const TICK: Duration = Duration::from_secs(1);
/// The 1 s tick moves the wall anchor FORWARD when the system clock is ahead of our wall clock by more than this.
const REANCHOR_NS: u64 = 100_000_000;
/// Log lines kept for the driver when it polls slower than they are produced (the oldest are dropped).
const LOG_KEEP: usize = 10_000;

/// The generic message dispatcher preserves these service-owned types as `Unknown`.
/// Enforce the header compatibility contract before their payload decoders run.
fn check_wire_compat(ty: u16, version: u16, compat: u16) -> denc::Result<()> {
    const CLIENT_EC: &[(u16, u16)] = &[
        (opwire::MOSDOp::MSG_TYPE, opwire::MOSDOp::HEAD_VERSION),
        (
            opwire::MOSDOpReply::MSG_TYPE,
            opwire::MOSDOpReply::HEAD_VERSION,
        ),
        (
            opwire::MOSDBackoff::MSG_TYPE,
            opwire::MOSDBackoff::HEAD_VERSION,
        ),
        (
            opwire::MWatchNotify::MSG_TYPE,
            opwire::MWatchNotify::HEAD_VERSION,
        ),
        (
            ecwire::MOSDECSubOpWrite::MSG_TYPE,
            ecwire::MOSDECSubOpWrite::HEAD_VERSION,
        ),
        (
            ecwire::MOSDECSubOpWriteReply::MSG_TYPE,
            ecwire::MOSDECSubOpWriteReply::HEAD_VERSION,
        ),
        (
            ecwire::MOSDECSubOpRead::MSG_TYPE,
            ecwire::MOSDECSubOpRead::HEAD_VERSION,
        ),
        (
            ecwire::MOSDECSubOpReadReply::MSG_TYPE,
            ecwire::MOSDECSubOpReadReply::HEAD_VERSION,
        ),
    ];
    let supported = CLIENT_EC
        .iter()
        .chain(pgwire::PeeringMsg::HEAD_BY_TYPE)
        .chain(replwire::ReplMsg::HEAD_BY_TYPE)
        .find_map(|&(t, v)| (t == ty).then_some(v));
    let compat = if compat == 0 { version } else { compat };
    if let Some(supported) = supported
        && compat > supported
    {
        return Err(denc::Error::CompatTooNew {
            compat: compat.min(u8::MAX as u16) as u8,
            supported: supported.min(u8::MAX as u16) as u8,
        });
    }
    Ok(())
}

/// System clock, unix ns (injectable in tests).
fn system_unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// New wall origin (unix ns at monotonic 0): forward only. A system clock ahead of `origin + mono` by more than `thr`
/// (NTP step after an early start, a VM resume) pulls the origin up; a clock that is behind never moves it, so wall stamps
/// stay monotonic.
pub(crate) fn reanchored_origin(origin_ns: u64, mono_ns: u64, sys_ns: u64, thr: u64) -> u64 {
    if sys_ns > origin_ns + mono_ns + thr {
        sys_ns - mono_ns
    } else {
        origin_ns
    }
}

/// Failure-time inputs, captured before returning from the failed allocator attempt. Unix time
/// identifies the attempt in client logs; store poll time is the last injected store-clock sample.
pub(crate) fn meta_growth_failure_json(f: &peering::store::MetaGrowthFailure) -> serde_json::Value {
    serde_json::json!({
        "sequence": f.sequence, "reason": f.reason, "unix_time_ns": f.unix_time_ns,
        "store_poll_time_ns": f.store_poll_time_ns,
        "requested_free_pages": f.requested_free_pages, "free_meta_pages": f.free_meta_pages,
        "block_size_bytes": store::BLK, "cell_blocks": f.cell_blocks,
        "cell_bytes": f.cell_blocks * store::BLK as u64, "pages_per_cell": f.pages_per_cell,
        "free_data_blocks": f.free_data_blocks, "held_data_blocks": f.held_data_blocks,
        "reserved_data_blocks": f.reserved_data_blocks, "reserve_data_blocks": f.reserve_data_blocks,
        "image_bytes": f.image_bytes, "image_reserve_bytes": f.image_reserve_bytes,
        "deferred_image_bytes": f.deferred_image_bytes,
        "image_needed_bytes": f.image_needed_bytes, "image_limit_bytes": f.image_limit_bytes,
        "free_windows": f.free_windows,
    })
}

/// One log line as the OSD emits it: `prio` is the level (`debug_osd` scale: 0 = always, higher = chattier), `text`
/// the message body. Derefs to the text so callers that only print it stay simple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub prio: u8,
    pub text: String,
}

impl std::ops::Deref for LogLine {
    type Target = str;
    fn deref(&self) -> &str {
        &self.text
    }
}

impl std::fmt::Display for LogLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// Static configuration given by the driver.
#[derive(Clone, Debug)]
pub struct OsdConfig {
    /// Short hostname (crush `host=`, metadata).
    pub hostname: String,
    /// Public addresses, one per enabled family, in advertised (addrvec) order (`ms_bind_prefer_ipv4`, spec 2.4).
    pub public_ips: Vec<IpAddr>,
    /// Cluster addresses, one per enabled family, in advertised order.
    pub cluster_ips: Vec<IpAddr>,
    /// Public port (both families of a kind share it: listeners are bound explicitly, spec 3).
    pub public_port: u16,
    /// Cluster port.
    pub cluster_port: u16,
    /// Heartbeat front port (on the public IP).
    pub hb_front_port: u16,
    /// Heartbeat back port (on the cluster IP).
    pub hb_back_port: u16,
    /// Initial mons.
    pub mon_host: Vec<EntityAddrVec>,
    /// Unix seconds at `now == 0`.
    pub wall_origin_unix: u64,
    /// Drivers: `Osd::start` re-anchors the wall clock to the system clock (the unix seconds above are truncated and taken before the
    /// monotonic origin, which made every wall stamp lag by up to seconds). Tests: false, the fixed origin stays.
    pub wall_from_clock: bool,
    /// Entropy for ids/jitter (use OS randomness).
    pub seed: u64,
    /// Process-unique nonce (classic: pid).
    pub nonce: u32,
    /// Extra metadata (see [`crate::sysinfo::collect`]).
    pub sys_metadata: BTreeMap<String, String>,
    /// The daemon's startup settings (conf file, environment, command line; the last setting of a key wins).
    pub local_config: Vec<(String, String)>,
    /// The source level of each [`Self::local_config`] entry (`config diff`, mgr `config show`).
    pub local_sources: crate::config::LocalSources,
    /// Data path shown in metadata.
    pub data_path: String,
    /// Offer the RDMA upgrade (msgr2 spec 18) on the public and cluster messengers; never on heartbeat or mon links.
    /// The driver must execute the RDMA [`IoCmd`]s; one that cannot declines them.
    pub rdma: bool,
    /// Negotiate registered READ placement on public client sessions. Requires
    /// RDMA; production drivers leave this off until the in-stack gates pass.
    pub placement: bool,
    /// Advertise the object source-pull extension (adr 0665) on public client
    /// sessions. Requires RDMA and READ-capable QPs (`rdma setup reads`); the
    /// OSD then answers a source-pull PUT by reading the client's READ-only
    /// memory window instead of receiving the bytes inline.
    pub source_pull: bool,
}

/// The four listeners the driver binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Listener {
    /// Clients, mon, mgr.
    Public,
    /// OSD peers.
    Cluster,
    /// Heartbeat front.
    HbFront,
    /// Heartbeat back.
    HbBack,
}

pub use daemon_io::IoCmd;

/// Text of the always-logged line announcing the OSD is up in the map (drivers turn it into `READY=1`).
pub const ACTIVE_MARKER: &str = "is now active";

/// OSD states (spec 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Startup sequence running.
    Initializing,
    /// Learning maps, waiting for permission to boot.
    Preboot,
    /// MOSDBoot sent.
    Booting,
    /// Up in the map.
    Active,
    /// Marked down; waiting for healthy heartbeats.
    WaitingForHealthy,
    /// Shutting down.
    Stopping,
}

impl State {
    /// Name as in `status`.
    pub fn name(self) -> &'static str {
        match self {
            State::Initializing => "initializing",
            State::Preboot => "preboot",
            State::Booting => "booting",
            State::Active => "active",
            State::WaitingForHealthy => "waiting_for_healthy",
            State::Stopping => "stopping",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum MsgrId {
    Public = 0,
    Cluster = 1,
    HbFrontSrv = 2,
    HbBackSrv = 3,
    HbFrontCli = 4,
    HbBackCli = 5,
}

impl MsgrId {
    /// Number of messengers (`HbBackCli` is the last), one pre-auth budget each ([`Cl::preauth_used`]).
    pub(crate) const COUNT: usize = Self::HbBackCli as usize + 1;
}

pub(crate) struct Msgr {
    pub cfg: msgr2::Config,
    pub table: SessionTable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Purpose {
    Accepted,
    Mgr,
    Hb(i32),
    /// Outgoing cluster-messenger link to a peer OSD (PG traffic).
    Peer(i32),
    /// Outgoing public-messenger client link to OSD `i32` (source reads of copy-from, copy.rs).
    Copy(i32),
}

impl Purpose {
    /// The OSD id a dialled link serves (`None`: the mgr, an accepted link).
    fn osd(self) -> Option<i32> {
        match self {
            Purpose::Hb(o) | Purpose::Peer(o) | Purpose::Copy(o) => Some(o),
            Purpose::Accepted | Purpose::Mgr => None,
        }
    }
}

/// One dial problem already logged (`Osd::dial_warned`): per peer, family and direction, so a reconnect loop logs each
/// once while an operator still sees every broken peer (the old purpose-only key hid all peers behind the first one), a
/// one-NIC flap is deduplicated per heartbeat direction (front vs back, CS-5247 / CS-5002), and an entry leaves when the
/// peer answers or leaves the map. The set is bounded by the peers of the map, not by address incarnations (a restarting
/// peer gets a new nonce, not a new entry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DialWarn {
    /// A dial of this purpose through this messenger failed in address family 4 / 6 (0: the target carries no parsed
    /// family).
    Failed(Purpose, u8, MsgrId),
    /// The purpose's advertised addresses hold none of a family we bind (it is retried every round).
    Unreachable(Purpose, MsgrId),
}

impl DialWarn {
    fn purpose(self) -> Purpose {
        match self {
            Self::Failed(p, _, _) | Self::Unreachable(p, _) => p,
        }
    }

    /// The link of `p` reached READY, authenticated as OSD `peer_osd` (if an OSD): the peer answers, so its warnings
    /// re-arm (the same link, the same peer OSD on another messenger, or that OSD dialling in).
    fn answered_by(self, p: Purpose, peer_osd: Option<i32>) -> bool {
        let mine = self.purpose();
        mine == p
            || mine
                .osd()
                .is_some_and(|o| p.osd() == Some(o) || peer_osd == Some(o))
    }
}

pub(crate) struct Link {
    pub pending_input: Option<PendingInput>,
    /// When and why `pending_input` was retained (hold statistics).
    pub held: (Duration, crate::utilization::HoldWhy),
    pub conn: Connection,
    pub msgr: MsgrId,
    pub purpose: Purpose,
    pub auth: Rc<RefCell<PeerAuth>>,
    pub peer: Option<msgr2::PeerInfo>,
    /// Accepted links: the peer socket address.
    pub sock: Option<SocketAddr>,
    /// Public-messenger sessions: parsed OSD caps of the authenticated entity (osdcaps.md s1).
    pub caps: Option<Arc<opexec::caps::Caps>>,
    /// The peer's address as the caps check reads it (osdcaps network caps). The connection's target is fixed for the
    /// link's life, so it is built once here, not per received frame (prewrite.rs).
    pub caps_peer: opexec::caps::Peer,
    /// Public-messenger sessions: what PG cores need to know about the client (set when the session is ready).
    pub info: Option<Arc<ConnInfo>>,
    /// Cores this link forwarded messages to (bit per core): told when the link closes.
    pub fwd: u64,
    /// The frame being received shares its data segment (pre-write, prewrite.rs).
    pub pre: Option<crate::prewrite::PreRx>,
    /// Accepted placement attempts of this session (attempt.rs); dropped with the link.
    pub placement: crate::attempt::Attempts,
    /// Pre-auth handshake transcript bytes this link holds in its messenger's budget (`Cl::preauth_used`): charged as
    /// the transcript grows, released at authentication (READY) or when the link leaves the table.
    pub preauth_charged: u64,
    /// The source-pull PUT (adr 0665) whose RDMA READ is outstanding. Its READ is the
    /// op's data arriving: like an inline op whose data segment is still on the wire, it holds the link's ordered
    /// input, so no later message of this session is taken before it (`actor_input_ready`).
    pub pull: Option<PendingPull>,
}

/// One source-pull PUT held between admission and the completed RDMA READ.
pub(crate) struct PendingPull {
    pub tid: u64,
    pub op: opwire::MOSDOp,
    pub bytes: usize,
    pub descriptor: rdma::source_pull::Descriptor,
}

// Keep client ops inline in the bounded input queue instead of allocating a box per admitted op.
#[expect(clippy::large_enum_variant)]
pub(crate) enum PendingInput {
    Op {
        tid: u64,
        op: opwire::MOSDOp,
        bytes: usize,
    },
    Peer {
        tid: u64,
        prio: u16,
        body: Box<peering::Body>,
        bytes: usize,
        ingress: ingress::InputGuard,
    },
}

/// Startup sub-state (spec 3.1 steps 3-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Init {
    WaitAuth,
    WaitKeys { since: Duration, attempts: u32 },
    WaitConfig { since: Duration },
    CrushClass,
    CrushLoc,
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitCmd {
    Class,
    Loc,
    Create,
}

impl InitCmd {
    /// The mon command prefix the init state is waiting on, for the loud progress line.
    fn name(self) -> &'static str {
        match self {
            InitCmd::Class => "osd crush set-device-class",
            InitCmd::Loc => "osd crush create-or-move",
            InitCmd::Create => "osd create",
        }
    }
}

/// The OSD core. See the crate docs for the driver contract.
pub struct Osd<B: Backend> {
    pub(crate) cfg: OsdConfig,
    pub(crate) conf: ConfigDb,
    /// Store name reported toward mon/mgr/CLI, fixed at start (`flashstore_report_objectstore`).
    pub(crate) store_id: crate::storeid::StoreIdentity,
    /// CRUSH location for `osd crush create-or-move`, fixed at start ([`crate::crushloc`]); control core only.
    pub(crate) crush_loc: crate::crushloc::Location,
    /// Meta store (identity, superblock, osdmaps): the control core only.
    pub(crate) store: Option<B::Meta>,
    /// Exit code to report once shutdown completes (local store failure).
    pub(crate) fail_code: Option<i32>,
    /// Epoch below which stored maps were last trimmed.
    pub(crate) trimmed_to: u32,
    pub(crate) id: Identity,
    pub(crate) sb: OsdSuperblock,
    /// Driver time: one process-wide origin shared by every core, so PG lease stamps of all cores and the heartbeat
    /// mono stamps are one clock (adr 0683).
    pub(crate) now: Duration,
    /// Unix nanoseconds at `now == 0`.
    pub(crate) wall_origin_ns: u64,
    /// System clock source (tests inject).
    pub(crate) sys_clock: fn() -> u64,
    pub(crate) rng: u64,
    pub(crate) mc: MonClient,
    pub(crate) keys: KeyStore,
    /// Notes about the stored state and the auth method lists (unusable stored map, bad syntax) that must reach the
    /// log: logged once at `start`, the constructor has no logger yet.
    startup_warnings: Vec<String>,
    pub(crate) msgr: [Msgr; 6],
    pub(crate) links: FastMap<u64, Link>,
    pub(crate) output_ready: msgr2::OutputQueue,
    pub(crate) event_ready: msgr2::EventQueue,
    pub(crate) event_pump_pending: bool,
    /// Learned work slice of the drains on this core (adr 0006 am. 4).
    pub(crate) slice: crate::xcore::Slice,
    pub(crate) timer_ready: msgr2::EventQueue,
    pub(crate) conn_timers: RefCell<deadline::Index<u64, Duration>>,
    pub(crate) next_link: u64,
    pub(crate) public_addrs: EntityAddrVec,
    pub(crate) cluster_addrs: EntityAddrVec,
    pub(crate) hb_front_addrs: EntityAddrVec,
    pub(crate) hb_back_addrs: EntityAddrVec,
    pub(crate) state: State,
    pub(crate) init: Init,
    pub(crate) init_cmd: Option<(u64, InitCmd)>,
    /// Send time and next `WARNING TIMEOUT` deadline of the outstanding init CRUSH command (NT-cs-restart-02).
    pub(crate) init_cmd_wait: Option<(Duration, Duration)>,
    pub(crate) map: Option<Arc<OsdMap>>,
    pub(crate) boot_epoch: u32,
    pub(crate) up_epoch: u32,
    pub(crate) bind_epoch: u32,
    /// Epoch of the map that last marked this OSD down while it ran (its cluster identity rebound, spec 7.4); 0 = never.
    /// A PG frame stamped before it is of the old identity: this core never sends it (`peer_transmit`). Every peer
    /// discards such a frame once it has that map (peering spec 2.4 step 3); a peer still behind would take it on the
    /// session that reconnected from the new address, behind the frames its RESET dropped. Set on the control core before
    /// the rebind is broadcast and on every other core before it takes the new nonce ([`XMsg::Rebind`]): a session resets
    /// that way only on a core that has the epoch. A link move does not bring such a session to a core without it: a
    /// move committed before the rebind leaves the old core only frames routed before the commit, stamped before the
    /// rebind (dropped there, no reconnect); the session reaches the new core under the old address and resumes there.
    pub(crate) rebind_epoch: u32,
    pub(crate) do_restart: bool,
    pub(crate) want_up_thru: u32,
    pub(crate) markdown_log: Vec<Duration>,
    /// Dial problems already logged ([`DialWarn`]): each once per peer and family, never silently forever.
    pub(crate) dial_warned: BTreeSet<DialWarn>,
    pub(crate) hb: Hb,
    pub(crate) mgr: MgrState,
    pub(crate) perf: Perf,
    /// RDMA transport status (`rdmastat.rs`).
    pub(crate) rdma: crate::rdmastat::RdmaState,
    /// Op tracker of this core (optrack.rs).
    pub(crate) tracker: crate::optrack::OpTracker,
    /// Command plumbing: admin socket, scattered commands (tell.rs).
    pub(crate) cmds: crate::tell::CmdState,
    /// `debug_osd` log level (first number), refreshed every tick and on config changes.
    pub(crate) log_level: u8,
    pub(crate) tick_at: Duration,
    pub(crate) last_beacon: Option<Duration>,
    pub(crate) last_mon_report: Duration,
    pub(crate) last_lonely: Duration,
    pub(crate) pending_version: Option<u64>,
    /// Preboot decided to wait: its mon version probe was answered, the onetime osdmap subscription is armed, and the
    /// next map (or a new mon session) re-runs it. Without this the 1 s tick probed the mon again every second.
    pub(crate) preboot_parked: bool,
    pub(crate) last_collect_epoch: u32,
    pub(crate) last_collect_pgs: Vec<denc::types::PgT>,
    pub(crate) shutdown_deadline: Option<Duration>,
    /// Shutdown drain (adr 0034 am. 1): in-flight client ops may finish until this instant, then the core is done.
    pub(crate) drain_until: Option<Duration>,
    /// `osd_shutdown_drain_timeout` as accepted by `drain_begin` (the drain window, for the timeout context).
    pub(crate) drain_limit: Duration,
    pub(crate) shutdown_notify: bool,
    pub(crate) drain_logged: bool,
    pub(crate) done: Option<i32>,
    pub(crate) io: VecDeque<IoCmd>,
    pub(crate) logs: VecDeque<LogLine>,
    pub(crate) tid: u64,
    pub(crate) stat_seq: u64,
    pub(crate) last_full_sent: Option<u32>,
    pub(crate) cfg_seen: bool,
    /// `osd_memory_target` of the last "applies at the next start" note, 0 = none ([`crate::memory::restart_note`]).
    pub(crate) mem_noted: u64,
    /// `(osd_client_message_size_cap, osd_max_write_size)` of the last note about what croit-flashstore-osd enforces of the client
    /// throttles, `None` until the first config.
    pub(crate) msg_cap_noted: Option<(u64, usize)>,
    /// `ms_crc_data` of the last loud note about msgr2 frame integrity, `None` until the first config.
    pub(crate) crc_data_noted: Option<bool>,
    /// Last values of the recovery QoS options ([`Osd::recovery_qos_guard`]); empty until the first config.
    pub(crate) qos_seen: std::collections::BTreeMap<String, String>,
    /// Last values of the no-effect options ([`crate::config::NO_EFFECT`], [`Osd::no_effect_guard`]).
    pub(crate) no_effect_seen: std::collections::BTreeMap<String, String>,
    /// Any recovery reservation held OSD-wide as last broadcast to the other cores (spec scrub.md 12.1.3).
    pub(crate) scrub_recovering: bool,
    pub(crate) last_boot: Duration,
    pub(crate) pg: PgHost<B::Pg>,
    /// Multi-core state (adr 0031).
    pub(crate) cl: Cl,
    /// Relays of peer connections owned by another core (pipe.rs).
    pub(crate) pipes: crate::pipe::Pipes,
    /// Receiver-side pre-write (prewrite.rs, adr 0477).
    pub(crate) pre: crate::prewrite::Pre,
    /// Core liveness shared with the daemon's checker thread (liveness.rs); `None` = not supervised (tests, tools).
    pub(crate) live: Option<&'static crate::liveness::Liveness>,
    #[cfg(test)]
    pub(crate) t: TestHooks,
}

/// A frame queued on a local link: `(link, tid, header (type, version, compat), segments)`.
#[cfg(test)]
pub(crate) type TestFrame = (u64, u64, (u16, u16, u16), messages::Segments);

/// What the unit tests observe (messages "sent" to the mon without a session).
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestHooks {
    pub timer_probes: std::cell::Cell<u64>,
    pub event_visits: u64,
    pub sent: Vec<AnyMessage>,
    /// Model the production send refusal while the monitor has no active session.
    pub mon_send_unavailable: bool,
    /// `MMonGetVersion` probes issued (`mon_get_version`).
    pub version_requests: u32,
    pub subs: Vec<(String, u64, u8)>,
    /// Frames queued on local links: `(link, tid, header (type, version, compat), segments)`.
    pub out: Vec<TestFrame>,
    /// Tids of the peer messages taken by `pg_peer_in` (past input backpressure), in order.
    pub peer_in: Vec<u64>,
    /// Tids of the client ops taken by `pg_client_op`, in order.
    pub client_in: Vec<u64>,
    /// Dialled links authenticate with AuthNone (a test peer has no cephx keys).
    pub dial_auth_none: bool,
}

impl<B: Backend> std::fmt::Debug for Osd<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Osd")
            .field("whoami", &self.id.whoami)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

pub(crate) fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Compare addrvecs as classic `legacy_equals`: ip + port + nonce of the primary address.
pub(crate) fn legacy_eq(a: &EntityAddrVec, b: &EntityAddrVec) -> bool {
    let p = |v: &EntityAddrVec| v.v2().or_else(|| v.0.first()).copied();
    match (p(a), p(b)) {
        (Some(x), Some(y)) => {
            x.ipv4() == y.ipv4()
                && x.ipv6() == y.ipv6()
                && x.port() == y.port()
                && x.nonce == y.nonce
        }
        _ => false,
    }
}

/// `[v2:ip:port/nonce]` text (single address without brackets, as in `osd metadata`).
pub(crate) fn addrs_str(v: &EntityAddrVec) -> String {
    let parts: Vec<String> = v.0.iter().map(ToString::to_string).collect();
    if parts.len() == 1 {
        parts[0].clone()
    } else {
        format!("[{}]", parts.join(","))
    }
}

/// Test-only peer socket of an accepted IPv4 connection.
#[cfg(test)]
pub(crate) fn sock4(ip: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::from(ip)), port)
}

/// Same address family (`IpAddr` has no portable family comparison).
fn same_family(a: IpAddr, b: IpAddr) -> bool {
    a.is_ipv4() == b.is_ipv4()
}

/// Operator-facing family name.
fn family_name(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() { "IPv4" } else { "IPv6" }
}

/// Address family code of a dial target for a [`DialWarn`] key: 4 / 6, 0 = the target carries no parsed family.
fn family_code(ip: Option<IpAddr>) -> u8 {
    match ip {
        Some(ip) if ip.is_ipv4() => 4,
        Some(_) => 6,
        None => 0,
    }
}

/// One msgr2 addrvec entry per own address, in the configured (spec 2.4) order.
fn mk_addr(ips: &[IpAddr], port: u16, nonce: u32) -> EntityAddrVec {
    EntityAddrVec(
        ips.iter()
            .map(|ip| {
                EntityAddr::from_socket(EntityAddr::TYPE_MSGR2, nonce, SocketAddr::new(*ip, port))
            })
            .collect(),
    )
}

/// Fill ratio `(total - available) / total` of a statfs; `None` without capacity.
pub(crate) fn fill(total: u64, available: u64) -> Option<f64> {
    (total > 0).then(|| total.saturating_sub(available) as f64 / total as f64)
}

#[cfg(any(feature = "lab", test))]
impl Osd<crate::backend::LabDir> {
    /// Legacy dev mode: directory meta store + in-memory PGs.
    pub fn new(cfg: OsdConfig, store: crate::meta::FileMetaStore) -> Result<Self, String> {
        Self::with_pg_store(cfg, store, crate::devstore::DevMemStore::new())
    }
}

/// The OSD's receive probe of public-link MESSAGE data segments (spec msgr2.md 8.2, client-ops 5.4.1): an
/// uncompressed MOSDOp whose front alone classifies as a write — rule 14 is answerable without the payload — and whose
/// declarations the decoder put at or above the threshold is refused before its data segment is admitted.
///
/// The decoder already compared the data length with the threshold; a `call` op (its class method decides WR, and it
/// lives in the payload) and every non-write message keep their payload.
fn write_probe_refuse(header: &[u8], front: &[u8], middle: usize, _data: usize) -> bool {
    if middle != 0 {
        return false;
    }
    let Ok(h) = msgr2::MsgHeader2::from_bytes(header) else {
        return false;
    };
    h.msg_type == opwire::consts::ty::OSD_OP
        && opwire::MOSDOp::front_may_write(h.version, front).unwrap_or(false)
}

impl<B: Backend> Osd<B> {
    /// Open the OSD with an explicit PG store (the persistent NVMe store: PGs found in it are loaded at `start`).
    pub fn with_pg_store(cfg: OsdConfig, store: B::Meta, pg_store: B::Pg) -> Result<Self, String> {
        // One core: the mounted store's shard count is the OSD's lane and input-window count (`input_shard`,
        // `pending_input`); a spec diverging from the store indexes past both.
        let spec = CoreSpec::new(0, 1, 1, pg_store.shards())?;
        Self::control(cfg, store, pg_store, spec)
    }

    /// Core 0 of a (possibly single-core) OSD: owns the meta store and the control plane.
    pub fn control(
        cfg: OsdConfig,
        store: B::Meta,
        pg_store: B::Pg,
        spec: CoreSpec,
    ) -> Result<Self, String> {
        let id = store
            .load_identity()
            .map_err(|e| e.to_string())?
            .ok_or("store has no identity (run mkfs)")?;
        let mut sb = store
            .load_superblock()
            .map_err(|e| e.to_string())?
            .ok_or("store has no superblock (run mkfs)")?;
        if sb.whoami != id.whoami || sb.cluster_fsid != id.cluster_fsid {
            return Err("superblock does not match identity".into());
        }
        // Superblock compat check (lifecycle spec 3.1, like classic): every feature bit the disk carries in any of
        // the three sets must be known to this build; a subset of ours is fine. Bit 0 is the always-set marker.
        let supported = messages::CompatSet::osd_initial();
        let unknown = |disk: u64, ours: u64| disk & !ours & !1;
        let (cf, sf) = (&sb.compat_features, &supported);
        let compat = unknown(cf.compat.mask, sf.compat.mask);
        let ro_compat = unknown(cf.ro_compat.mask, sf.ro_compat.mask);
        let incompat = unknown(cf.incompat.mask, sf.incompat.mask);
        if compat | ro_compat | incompat != 0 {
            return Err(format!(
                "superblock uses features unsupported by this build: compat={compat:#x}, ro_compat={ro_compat:#x}, \
                 incompat={incompat:#x}"
            ));
        }
        // newest stored map seeds the MonClient; one that is there but cannot be used is named loudly (store
        // corruption must not look like a cold start) and refetched from the mon
        let mut map = None;
        let mut startup_notes = Vec::new();
        if sb.current_epoch > 0 {
            let epoch = sb.current_epoch;
            match store.get_map(epoch, MapKind::Full) {
                Ok(Some(b)) => match OsdMap::decode_from(&b) {
                    Ok(m) => map = Some(m),
                    Err(e) => startup_notes.push(format!(
                        "stored osdmap epoch {epoch} unusable ({e}), refetching from the mon"
                    )),
                },
                Ok(None) => startup_notes.push(format!(
                    "stored osdmap epoch {epoch} missing, refetching from the mon"
                )),
                Err(e) => startup_notes.push(format!(
                    "stored osdmap epoch {epoch} unreadable ({e}), refetching from the mon"
                )),
            }
            if map.is_none() {
                sb.current_epoch = 0;
                sb.mapc.clear();
            }
        }
        // fixed once at start, before any mon traffic (spec osd-lifecycle.md 1.4): a bad location refuses the start
        let crush_loc = crate::crushloc::resolve(
            |k| {
                crate::config::local_get(&cfg.local_config, k)
                    .map(str::to_owned)
                    .or_else(|| crate::monboot::boot().get(k).cloned())
            },
            &cfg.hostname,
            id.whoami,
        )?;
        let mut o = Self::build(cfg, Some(store), id, sb, map, pg_store, spec)?;
        o.crush_loc = crush_loc;
        o.startup_warnings.extend(startup_notes);
        Ok(o)
    }

    /// A worker core (`spec.id > 0`): PGs and links only; identity and superblock come from core 0
    /// ([`Osd::identity`], [`Osd::superblock`]); maps arrive from core 0 at start.
    pub fn worker(
        cfg: OsdConfig,
        id: Identity,
        sb: OsdSuperblock,
        pg_store: B::Pg,
        spec: CoreSpec,
    ) -> Result<Self, String> {
        if spec.id == 0 {
            return Err("core 0 is the control core".into());
        }
        Self::build(cfg, None, id, sb, None, pg_store, spec)
    }

    fn build(
        cfg: OsdConfig,
        store: Option<B::Meta>,
        id: Identity,
        sb: OsdSuperblock,
        map: Option<OsdMap>,
        pg_store: B::Pg,
        spec: CoreSpec,
    ) -> Result<Self, String> {
        if cfg.placement && !cfg.rdma {
            return Err("placement requires RDMA".into());
        }
        // the trace clock is read with sampling off as well (pre-write lag, `prewrite::pre_send`): calibrate it before the
        // core takes traffic, never on the first op that reads it (doc/perf/omap-cold-start-20261024.md)
        crate::trace::init();
        let mut conf = ConfigDb::default();
        // the store identity is read once here: the mon config fetched at boot counts (`ceph config set osd ...`),
        // the local file wins over it like for every option
        if let Some(v) = crate::monboot::boot().get(crate::storeid::OPTION)
            && let Err(e) = conf.set(Level::Mon, crate::storeid::OPTION, v)
        {
            eprintln!("WARNING {e}; the option keeps its default");
        }
        for (i, (k, v)) in cfg.local_config.iter().enumerate() {
            if let Err(e) = conf.set(cfg.local_sources.level(i), k, v) {
                eprintln!("WARNING {e}; the option keeps its default");
            }
        }
        let store_id = crate::storeid::StoreIdentity::from_conf(&conf)?;
        conf.set_default_unchecked("osd_objectstore", store_id.as_str());
        // `ms_crc_data` (spec msgr2.md 4.3): read when a connection is created, so a runtime change reaches only
        // connections made afterwards (refreshed in `refresh_obs_conf`)
        let crc_data = conf.bool("ms_crc_data", true);
        let map = map.map(Arc::new);
        // own secret: `key` > `keyfile` > `keyring` search list (default `$osd_data/keyring`), else the key mkfs
        // recorded on the device; none at all = an OSD without a key: cephx is unusable, see `AuthLists::without_cephx`
        let key =
            match crate::keysrc::resolve(&cfg.local_config, i64::from(id.whoami), &cfg.hostname)
                .map_err(|e| format!("osd.{} key: {e}", id.whoami))?
            {
                Some(f) => {
                    if spec.id == 0 {
                        eprintln!("osd.{}: cephx key from {}", id.whoami, f.source);
                    }
                    Some(f.key)
                }
                None if id.key.is_empty() => None,
                None => {
                    if spec.id == 0 {
                        eprintln!(
                            "osd.{}: cephx key from the device identity (mkfs)",
                            id.whoami
                        );
                    }
                    Some(
                        CryptoKey::from_base64(&id.key)
                            .map_err(|e| format!("osd key on the device: {e:?}"))?,
                    )
                }
            };
        let mut rng =
            cfg.seed ^ 0xD6E8_FEB8_6659_FD93 ^ (spec.id as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let wall_origin_ns = cfg.wall_origin_unix * 1_000_000_000;
        let nonce = cfg.nonce;
        let public_addrs = mk_addr(&cfg.public_ips, cfg.public_port, nonce);
        let cluster_addrs = mk_addr(&cfg.cluster_ips, cfg.cluster_port, nonce);
        let hb_front_addrs = mk_addr(&cfg.public_ips, cfg.hb_front_port, nonce);
        let hb_back_addrs = mk_addr(&cfg.cluster_ips, cfg.hb_back_port, nonce);
        let mut mcfg = monc::Config::new(&format!("osd.{}", id.whoami), key.clone());
        mcfg.mon_host = cfg.mon_host.clone();
        mcfg.wall_origin = Duration::from_nanos(wall_origin_ns);
        mcfg.seed = splitmix(&mut rng);
        mcfg.hostname = cfg.hostname.clone();
        mcfg.fsid = id.cluster_fsid;
        mcfg.crc_data = crc_data;
        // `mon_client_*` (file over the mon config fetched at boot); later changes: `Osd::obs_monc`
        crate::monboot::apply_mon_client(&mut mcfg, |k| {
            conf.get(k)
                .or_else(|| crate::monboot::boot().get(k).map(String::as_str))
        });
        let (mut auth_lists, mut auth_warnings) =
            crate::auth::AuthLists::from_local(&cfg.local_config);
        if let Some(m) = crate::auth::mon_session_modes(&cfg.local_config) {
            auth_warnings.extend(
                m.unknown
                    .into_iter()
                    .map(|w| crate::auth::mode_warning("ms_mon_cluster_mode", &w)),
            );
            mcfg.modes = m.modes;
        }
        // the method lists from the local config until the layered config exists (refreshed on every config change,
        // `refresh_obs_conf`): toward the mon an OSD offers `auth_cluster_required`
        if key.is_none() {
            auth_lists = auth_lists.without_cephx(id.whoami, &mut auth_warnings)?;
        }
        mcfg.methods = auth_lists.cluster.clone();
        mcfg.my_addrs = Some(public_addrs.clone());
        let mut mc = MonClient::new(mcfg);
        let output_ready = msgr2::OutputQueue::default();
        mc.set_output_queue(&output_ready, MON_BASE);
        if let Some(m) = &map {
            mc.set_osdmap(OsdMap::clone(m));
        }
        let name = EntityName::osd(i64::from(id.whoami));
        // `ms_connection_idle_timeout` (seconds, local config like `ms_mon_cluster_mode`): fixed at start, as in classic
        let idle_timeout =
            crate::config::local_get(&cfg.local_config, "ms_connection_idle_timeout")
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|s| *s > 0)
                .map(std::time::Duration::from_secs);
        let mk =
            |a: &EntityAddrVec, p: PolicyTable, rdma: bool, placement: bool, rng: &mut u64| Msgr {
                cfg: msgr2::Config {
                    // connections of one peer can be accepted on another core (own session table): do not idle 15 s for them
                    wait_backoff: std::time::Duration::from_millis(300),
                    idle_timeout: idle_timeout.unwrap_or(msgr2::Config::DEFAULT_IDLE_TIMEOUT),
                    rdma,
                    placement,
                    crc_data,
                    // Advertised only where the OSD can serve it: RDMA is up and
                    // every usable device runs READ-capable QPs. The per-peer
                    // READ depths are still negotiated on top of that.
                    // Source-pull needs READ-capable QPs and the operator opt-in,
                    // not the placement READ path: the transport serves the pull.
                    source_pull: cfg.rdma && cfg.source_pull,
                    ..msgr2::Config::new(name, a.clone(), p)
                },
                table: SessionTable::new(splitmix(rng)),
            };
        let rdma = cfg.rdma;
        let mut public_policy = PolicyTable::osd_public();
        if cfg.placement {
            public_policy
                .by_type
                .push((EntityName::CLIENT, msgr2::Policy::stateful_server(0)));
        }
        let mut msgr = [
            mk(&public_addrs, public_policy, rdma, cfg.placement, &mut rng),
            mk(
                &cluster_addrs,
                PolicyTable::osd_cluster(),
                rdma,
                false,
                &mut rng,
            ),
            mk(
                &hb_front_addrs,
                PolicyTable::osd_hb_server(),
                false,
                false,
                &mut rng,
            ),
            mk(
                &hb_back_addrs,
                PolicyTable::osd_hb_server(),
                false,
                false,
                &mut rng,
            ),
            mk(
                &hb_front_addrs,
                PolicyTable::osd_hb_client(),
                false,
                false,
                &mut rng,
            ),
            mk(
                &hb_back_addrs,
                PolicyTable::osd_hb_client(),
                false,
                false,
                &mut rng,
            ),
        ];
        // peer OSD sessions live on `peer_core(osd)`: connections landing elsewhere are handed over (pipe.rs)
        if spec.net > 1 {
            msgr[MsgrId::Cluster as usize].cfg.home = msgr2::Home::new(spec.id, spec.net);
        }
        let keys = KeyStore::default();
        keys.set_have_key(key.is_some());
        keys.set_lists(auth_lists);
        let pg = PgHost::new(id.whoami, pg_store, map.as_ref(), spec.owner());
        pg.set.set_cluster_trim(sb.cluster_osdmap_trim_lower_bound);
        Ok(Self {
            cfg,
            conf,
            store_id,
            crush_loc: Vec::new(),
            store,
            fail_code: None,
            trimmed_to: 0,
            id,
            sb,
            now: Duration::ZERO,
            wall_origin_ns,
            sys_clock: system_unix_ns,
            rng,
            mc,
            keys,
            startup_warnings: auth_warnings,
            msgr,
            links: FastMap::default(),
            output_ready,
            event_ready: Default::default(),
            event_pump_pending: false,
            slice: Default::default(),
            timer_ready: Default::default(),
            conn_timers: Default::default(),
            next_link: 1,
            public_addrs,
            cluster_addrs,
            hb_front_addrs,
            hb_back_addrs,
            state: State::Initializing,
            init: if spec.id == 0 {
                Init::WaitAuth
            } else {
                Init::Done
            },
            init_cmd: None,
            init_cmd_wait: None,
            map,
            boot_epoch: 0,
            up_epoch: 0,
            bind_epoch: 0,
            rebind_epoch: 0,
            do_restart: false,
            want_up_thru: 0,
            markdown_log: Vec::new(),
            dial_warned: BTreeSet::new(),
            hb: Hb::default(),
            mgr: MgrState::new(),
            perf: Perf::default(),
            rdma: Default::default(),
            tracker: Default::default(),
            cmds: Default::default(),
            log_level: 1,
            tick_at: Duration::ZERO,
            last_beacon: None,
            last_mon_report: Duration::ZERO,
            last_lonely: Duration::ZERO,
            pending_version: None,
            preboot_parked: false,
            last_collect_epoch: 0,
            last_collect_pgs: Vec::new(),
            shutdown_deadline: None,
            drain_until: None,
            drain_limit: Duration::from_secs_f64(DRAIN_TIMEOUT_SECS),
            shutdown_notify: false,
            drain_logged: false,
            done: None,
            io: VecDeque::new(),
            logs: VecDeque::new(),
            tid: 1,
            stat_seq: 0,
            last_full_sent: None,
            cfg_seen: false,
            mem_noted: 0,
            msg_cap_noted: None,
            crc_data_noted: None,
            qos_seen: std::collections::BTreeMap::new(),
            no_effect_seen: std::collections::BTreeMap::new(),
            scrub_recovering: false,
            last_boot: Duration::ZERO,
            pg,
            cl: Cl::new(spec),
            pipes: Default::default(),
            pre: Default::default(),
            live: None,
            #[cfg(test)]
            t: TestHooks::default(),
        })
    }

    // ---------------------------------------------------------------- accessors

    /// Osd id.
    pub fn whoami(&self) -> i32 {
        self.id.whoami
    }
    /// Current state.
    pub fn state(&self) -> State {
        self.state
    }
    /// Held OSDMap epoch (0 = none).
    pub fn epoch(&self) -> u32 {
        self.map.as_ref().map_or(0, |m| m.epoch)
    }
    /// Held OSDMap.
    pub fn osdmap(&self) -> Option<&OsdMap> {
        self.map.as_deref()
    }
    /// Identity (worker cores are built from core 0's).
    pub fn identity(&self) -> &Identity {
        &self.id
    }
    /// Superblock.
    pub fn superblock(&self) -> &OsdSuperblock {
        &self.sb
    }
    /// Layered config.
    pub fn hostname(&self) -> &str {
        &self.cfg.hostname
    }

    pub fn config(&self) -> &ConfigDb {
        &self.conf
    }
    /// Lab diagnostics: ops answered after >100 ms / >1 s / >5 s on this core and the longest op (ms).
    pub fn dbg_op_lat(&self) -> ([u64; 3], u64) {
        (self.tracker.lat_over, self.tracker.lat_max / 1_000_000)
    }

    /// Exit code once the OSD wants the process to end (`Some(0)` clean).
    pub fn exit_code(&self) -> Option<i32> {
        self.done
    }
    /// Our public addresses.
    pub fn public_addrs(&self) -> &EntityAddrVec {
        &self.public_addrs
    }
    /// Mon session open?
    pub fn mon_connected(&self) -> bool {
        self.mc.is_connected()
    }
    /// Ids of current heartbeat peers.
    pub fn hb_peer_ids(&self) -> Vec<i32> {
        self.hb.peers.keys().copied().collect()
    }
    /// Whether a mgr session is open.
    pub fn mgr_connected(&self) -> bool {
        self.mgr.link.is_some_and(|l| {
            self.links
                .get(&l)
                .is_some_and(|k| matches!(k.conn.state(), msgr2::ConnState::Ready))
        })
    }

    /// Log at level 1 (always shown at the default `debug_osd = 1/5`).
    pub(crate) fn log(&mut self, s: impl Into<String>) {
        self.logl(1, s);
    }

    /// Log at `level` (0 = always, higher = chattier); dropped when `debug_osd` is lower.
    pub(crate) fn logl(&mut self, level: u8, s: impl Into<String>) {
        if level > self.log_level {
            return;
        }
        let mut text = s.into();
        if self.cl.spec.id > 0 {
            text = format!("[core {}] {text}", self.cl.spec.id);
        }
        self.logs.push_back(LogLine { prio: level, text });
        if self.logs.len() > LOG_KEEP {
            self.logs.pop_front();
        }
    }

    /// Next log line (the driver prints it).
    pub fn poll_log(&mut self) -> Option<LogLine> {
        self.logs.pop_front()
    }

    pub(crate) fn clog(&mut self, prio: u16, msg: &str) {
        self.mc.log(prio, "cluster", msg);
    }

    pub(crate) fn alloc_tid(&mut self) -> u64 {
        self.tid += 1;
        self.tid
    }

    pub(crate) fn wall(&self) -> UTime {
        let t = self.wall_origin_ns + self.now.as_nanos() as u64;
        UTime::new((t / 1_000_000_000) as u32, (t % 1_000_000_000) as u32)
    }

    pub(crate) fn mnow(&self) -> Duration {
        self.now
    }

    pub(crate) fn rand(&mut self) -> u64 {
        splitmix(&mut self.rng)
    }

    pub(crate) fn set_now(&mut self, now: Duration) {
        if now > self.now {
            self.now = now;
        }
    }

    pub(crate) fn fatal(&mut self, why: &str) {
        self.logl(0, format!("FATAL: {why}"));
        if self.done.is_none() {
            self.done = Some(1);
        }
    }

    // ---------------------------------------------------------------- driver API

    /// Begin startup. `now` uses the driver's process-wide origin, shared by every core.
    pub fn start(&mut self, now: Duration) {
        if self.cfg.wall_from_clock
            && let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        {
            self.wall_origin_ns = (d.as_nanos() as u64).saturating_sub(now.as_nanos() as u64);
        }
        self.set_now(now);
        self.pg.set.set_wall_base(self.wall_origin_ns);
        self.pg_apply_scrub_cfg();
        self.tick_at = now + TICK;
        self.last_mon_report = now;
        if !self.is_control() {
            return self.worker_start();
        }
        // scratch objects of a bench the last run did not finish (crash)
        if let Some(s) = self.store.as_mut() {
            use crate::meta::MetaStore as _;
            if let Err(e) = s.bench_cleanup(crate::meta::BENCH_SLOTS) {
                self.logl(0, format!("WARNING bench scratch cleanup failed: {e}"));
            }
        }
        for w in std::mem::take(&mut self.startup_warnings) {
            self.logl(0, w);
        }
        self.log(format!(
            "osd.{} starting: public {} cluster {} hb_front {} hb_back {}",
            self.id.whoami,
            addrs_str(&self.public_addrs),
            addrs_str(&self.cluster_addrs),
            addrs_str(&self.hb_front_addrs),
            addrs_str(&self.hb_back_addrs)
        ));
        if let Some(e) = self
            .map
            .as_ref()
            .and_then(|m| crate::release::check_map(m).err())
        {
            return self.refuse(&e);
        }
        self.client_throttle_note();
        self.pg_boot();
        self.mc.start(now);
        self.pump();
    }

    /// A socket was accepted on `l` from `peer`. Returns the connection id to use afterwards.
    pub fn on_accept(&mut self, l: Listener, peer: SocketAddr, now: Duration) -> u64 {
        self.set_now(now);
        let m = match l {
            Listener::Public => MsgrId::Public,
            Listener::Cluster => MsgrId::Cluster,
            Listener::HbFront => MsgrId::HbFrontSrv,
            Listener::HbBack => MsgrId::HbBackSrv,
        };
        let id = self.alloc_link_id();
        let auth = Rc::new(RefCell::new(PeerAuth::default()));
        let h = DaemonAuthServer::new(self.keys.clone(), ENTITY_OSD_BIT, auth.clone());
        let ms = &self.msgr[m as usize];
        let target = EntityAddr::from_socket(EntityAddr::TYPE_MSGR2, 0, peer);
        let mut conn = Connection::server(
            id,
            ms.cfg.clone(),
            ms.table.clone(),
            Box::new(h),
            target,
            now,
        );
        conn.set_frame_gate(self.frame_gate(m));
        conn.set_data_probe(self.data_probe(m));
        conn.set_prewrite(self.pre.min);
        conn.set_rx_place(true);
        conn.set_output_queue(&self.output_ready, id);
        conn.set_event_queue(&self.event_ready, id);
        conn.set_timer_queue(&self.timer_ready, id);
        self.conn_timers.get_mut().register(id);
        self.reserve_input_links();
        self.links.insert(
            id,
            Link {
                pending_input: None,
                held: Default::default(),
                conn,
                msgr: m,
                purpose: Purpose::Accepted,
                auth,
                peer: None,
                sock: Some(peer),
                caps: None,
                caps_peer: opexec::caps::Peer::from_addr(&target),
                info: None,
                fwd: 0,
                pre: None,
                placement: Default::default(),
                preauth_charged: 0,
                pull: None,
            },
        );
        // the server banner is the transcript's first bytes: charged at once, not at the first received byte
        self.sync_preauth(id);
        self.pump();
        id
    }

    /// A link left this core's table: its pre-auth transcript bytes leave their messenger's budget.
    pub(crate) fn link_left(&mut self, l: &Link) {
        if l.preauth_charged != 0 {
            let used = &mut self.cl.preauth_used[l.msgr as usize];
            debug_assert!(*used >= l.preauth_charged, "pre-auth budget underflow");
            *used = used.saturating_sub(l.preauth_charged);
        }
    }

    /// Charge the pre-auth transcript bytes `conn` holds now to its messenger's budget (releasing what it no longer
    /// holds: authentication, a reset transport). `Some((held, limit))`: the transcript exceeded the budget of its
    /// messenger; the caller closes the link loudly (the peer retries), so an unauthenticated peer can never pin more
    /// than one share, let alone starve the accepts of another listener.
    fn charge_preauth(&mut self, conn: u64) -> Option<(u64, u64)> {
        let limit = self.cl.preauth_limit;
        let l = self.links.get_mut(&conn)?;
        let held = l.conn.preauth_bytes() as u64;
        let used = &mut self.cl.preauth_used[l.msgr as usize];
        if held >= l.preauth_charged {
            *used += held - l.preauth_charged;
        } else {
            debug_assert!(
                *used >= l.preauth_charged - held,
                "pre-auth budget underflow"
            );
            *used = used.saturating_sub(l.preauth_charged - held);
        }
        l.preauth_charged = held;
        (*used > limit).then_some((held, limit))
    }

    /// Reconcile the pre-auth charge of `id` with the transcript its connection holds now (it grows with the banner at
    /// creation, with every handshake frame, and drops to zero at a transport reset): called after every connection
    /// state change. True = the transcript exceeded its messenger's budget and the link was closed loudly (the peer
    /// retries). An authenticated link holds nothing and costs one branch.
    fn sync_preauth(&mut self, id: u64) -> bool {
        let Some(l) = self.links.get(&id) else {
            return false;
        };
        if l.preauth_charged == 0 && l.conn.preauth_bytes() == 0 {
            return false;
        }
        let Some((held, limit)) = self.charge_preauth(id) else {
            return false;
        };
        let m = self.links.get(&id).map(|l| l.msgr);
        if let Some(m) = m {
            self.log(format!(
                "link {id} closed: pre-auth handshake buffer of {held} B exceeds the {limit} B budget of {m:?}"
            ));
        }
        self.close_link(id);
        true
    }

    /// A link authenticated (READY): its handshake transcript is gone, so its budget share is free again.
    fn release_preauth(&mut self, id: u64) {
        let Some(l) = self.links.get_mut(&id) else {
            return;
        };
        if l.preauth_charged != 0 {
            let used = &mut self.cl.preauth_used[l.msgr as usize];
            debug_assert!(*used >= l.preauth_charged, "pre-auth budget underflow");
            *used = used.saturating_sub(l.preauth_charged);
            l.preauth_charged = 0;
        }
    }

    /// Next socket operation.
    pub fn poll_io(&mut self) -> Option<IoCmd> {
        loop {
            let Some(c) = self.io.pop_front() else {
                if !self.pipes.z.is_empty() {
                    self.pipe_sweep();
                }
                return None;
            };
            // the socket of a resumed peer connection is on another core
            if let IoCmd::Close { conn } = c
                && !self.pipes.h.is_empty()
                && self.pipes.h.contains_key(&conn)
            {
                self.pipe_close_cmd(conn);
                continue;
            }
            return Some(c);
        }
    }

    /// The socket for `conn` is connected.
    pub fn on_connected(&mut self, conn: u64, now: Duration) {
        self.set_now(now);
        if conn & MON_BASE != 0 {
            self.mc.on_connected(conn & !MON_BASE, now);
        } else if let Some(l) = self.links.get_mut(&conn) {
            l.conn.on_connected(now);
            self.sync_preauth(conn);
        }
        self.pump();
    }

    /// A dial failed (`refused` = connection refused, i.e. nobody listens there).
    pub fn on_dial_failed(&mut self, conn: u64, refused: bool, now: Duration) {
        self.set_now(now);
        if conn & MON_BASE != 0 {
            self.mc.on_closed(conn & !MON_BASE, now);
        } else if let Some(l) = self.links.get_mut(&conn) {
            // loud, once per peer + family + direction: a dial that cannot succeed must never retry silently
            let target = l.conn.target();
            let family = target.ip().map(family_name);
            let p = l.purpose;
            let msgr = l.msgr;
            let warn = self
                .dial_warned
                .insert(DialWarn::Failed(p, family_code(target.ip()), msgr));
            l.conn.on_closed(now);
            if warn {
                let dir = self.dial_direction(msgr);
                self.logl(
                    0,
                    format!(
                        "osd.{}: dial {target} failed ({}, {}){}",
                        self.id.whoami,
                        if refused {
                            "connection refused"
                        } else {
                            "unreachable"
                        },
                        family.unwrap_or("no address family"),
                        dir
                    ),
                );
            }
            self.sync_preauth(conn);
            if refused && let Purpose::Hb(o) = p {
                self.on_hb_refused(o, msgr == MsgrId::HbBackCli);
            }
        }
        self.pump();
    }

    /// Answer to [`IoCmd::RdmaPrepare`]: `Some(endpoint)` = the prepared QP's endpoint (offered to the server), `None` = no
    /// QP, the connection goes on over TCP. False: the connection moved on (closed, faulted); release the QP.
    pub fn rdma_prepared(&mut self, conn: u64, endpoint: Option<Vec<u8>>, now: Duration) -> bool {
        self.rdma_step(conn, now, |c| c.rdma_offer(endpoint, now))
    }

    /// Answer to [`IoCmd::RdmaAccept`]: `Some(endpoint)` = our QP, connected to the peer's endpoint (RTR); `None` declines.
    /// False: the connection moved on; release the QP and do not switch the transport.
    pub fn rdma_accepted(&mut self, conn: u64, endpoint: Option<Vec<u8>>, now: Duration) -> bool {
        self.rdma_step(conn, now, |c| c.rdma_answer(endpoint, now))
    }

    /// Answer to [`IoCmd::RdmaConnect`]: the QP is connected (RTS), the socket is liveness only. False: the connection moved on;
    /// release the QP.
    pub fn rdma_connected(&mut self, conn: u64, now: Duration) -> bool {
        self.rdma_step(conn, now, |c| c.rdma_ready(now))
    }

    /// Decline an RDMA command: transports without RDMA call this for every [`IoCmd`] they cannot execute. The connection
    /// stays on TCP; a command that can only follow an accepted offer (never offered, so never reached) closes it.
    pub fn rdma_decline(&mut self, cmd: IoCmd, now: Duration) {
        match cmd {
            IoCmd::RdmaPrepare { conn } => {
                self.rdma_prepared(conn, None, now);
            }
            IoCmd::RdmaAccept { conn, .. } => {
                self.rdma_accepted(conn, None, now);
            }
            IoCmd::RdmaConnect { conn, .. } => self.on_closed(conn, now),
            IoCmd::RdmaRelease { .. } | IoCmd::Dial { .. } | IoCmd::Close { .. } => {}
            IoCmd::SourcePullRead { conn, tid, .. } => {
                // No READ direction on this transport/connection: the held op
                // is admitted with the error so the client gets a normal reply.
                self.source_pull_done(conn, tid, Err(-opwire::errno::EOPNOTSUPP));
            }
            IoCmd::PlaceReadReply {
                conn, tid, retry, ..
            } => {
                // The transport cannot place: retire the admitted grant with an error reply.
                self.placement_preflight_refused(conn, tid, retry);
            }
            IoCmd::PlaceReadCancel { conn, tid, retry } => {
                // The transport cannot process the CANCEL (no RDMA / not upgraded): the link
                // sends the RETIRED and vacates the attempt.
                self.placement_cancelled(conn, tid, retry);
            }
        }
    }

    /// The transport refused the placement preflight before any WRITE was posted.
    /// The ordered error reply carries RETIRED for the exact admitted grant;
    /// its source pieces are dropped without an inline payload copy.
    pub fn placement_preflight_refused(&mut self, conn: u64, tid: u64, retry: u32) {
        let Some(l) = self.links.get_mut(&conn) else {
            return;
        };
        if l.placement.cancelled(tid, retry) {
            // The queued CANCEL still owns retirement. An error reply here
            // could overtake RETIRED and race a retry of the same transaction.
            return;
        }
        let Some(grant) = l.placement.grant(tid, retry) else {
            return;
        };
        let Some(reply) = l.placement.take_reply(tid, retry) else {
            return;
        };
        l.placement.done(tid, retry);
        let feats = self.link_features(conn);
        let retired = rdma::placement::ControlRecord {
            attempt: grant.attempt,
            rkey: grant.rkey,
        }
        .encode(rdma::placement::ControlRecord::RETIRED);
        let wire = reply.encode_placed_error(feats, retired, opwire::errno::EOPNOTSUPP);
        self.queue_placement_reply(conn, tid, "placement retirement error", wire);
    }

    /// The transport completed (or refused) a source-pull READ (`Err` = negative errno). The held op is
    /// admitted with the pulled bytes as its data segment, or with the error so
    /// the client gets a normal reply. A crc32c mismatch is an integrity failure,
    /// never a stored object. A record without a crc (device source) stores what the
    /// READ delivered: its transfer was checked by the RoCE ICRC.
    pub fn source_pull_done(&mut self, conn: u64, tid: u64, result: Result<Bytes, i32>) {
        let Some(l) = self.links.get_mut(&conn) else {
            // The link closed while its READ was outstanding: the lossy client session resends on its new
            // connection; nothing waits for this completion.
            return;
        };
        let Some(mut pull) = l.pull.take_if(|p| p.tid == tid) else {
            eprintln!("source-pull: completion for unknown tid {tid} on link {conn:#x}");
            return;
        };
        l.conn.hold_rx(false, self.now);
        let bytes = match result {
            Ok(bytes) => {
                if bytes.len() as u32 != pull.descriptor.length {
                    Err(-opwire::errno::EIO)
                } else if pull
                    .descriptor
                    .crc32c
                    .is_some_and(|crc| crc::crc32c(0, &bytes) != crc)
                {
                    self.log(format!(
                        "link {conn:#x}: source-pull PUT {tid}: crc32c mismatch"
                    ));
                    Err(-opwire::errno::EIO)
                } else {
                    Ok(bytes)
                }
            }
            Err(errno) => Err(errno),
        };
        match bytes {
            Ok(bytes) => {
                pull.op.ops[0].indata = bytes;
                pull.op.source_pull_error = None;
            }
            Err(errno) => pull.op.source_pull_error = Some(errno),
        }
        // The pull held the link's input, so nothing else of this link is held now.
        self.admit_client_op(conn, tid, pull.op, pull.bytes);
        // The session's later messages follow in order (the input pause ends unless the op itself is held).
        if let Some(link) = self.links.get(&conn)
            && link.pending_input.is_none()
        {
            link.conn.notify_events();
        }
        self.pump();
        self.resume_pipe_input(conn);
    }

    /// The transport completed the placement WRITEs and retired their sources: encode the
    /// placed reply (receipt in the middle, empty data segment) on the same QP and vacate
    /// the attempt. The pieces were written to the client and are taken out of the reply.
    pub fn placement_success(&mut self, conn: u64, tid: u64, retry: u32, receipt: Vec<u8>) {
        let Some(l) = self.links.get_mut(&conn) else {
            return;
        };
        if l.placement.cancelled(tid, retry) {
            // A CANCEL was accepted before this callback. The transport must
            // process its queued cancellation and report retirement instead.
            return;
        }
        let Some(mut reply) = l.placement.take_reply(tid, retry) else {
            return;
        };
        l.placement.done(tid, retry);
        let Some(payload) = reply.take_placed_read_payload() else {
            self.log(format!(
                "link {conn:#x}: placed reply lost its source pieces"
            ));
            self.close_link(conn);
            return;
        };
        let len = payload.len;
        let feats = self.link_features(conn);
        let wire = reply.encode_placed_read(feats, receipt, len);
        self.queue_placement_reply(conn, tid, "placed MOSDOpReply", wire);
    }

    /// Queue an encoded placement reply (`what` names it in the diagnostics) on `conn` and finish the attempt's
    /// session state: an unsent reply closes the link, the last attempt of a session releases its RDMA order.
    fn queue_placement_reply<E: std::fmt::Display>(
        &mut self,
        conn: u64,
        tid: u64,
        what: &str,
        wire: Result<messages::Segments, E>,
    ) {
        let sent = match wire {
            Ok(segs) => {
                let hdr = (
                    MOSDOpReply::MSG_TYPE,
                    MOSDOpReply::HEAD_VERSION,
                    MOSDOpReply::COMPAT_VERSION,
                );
                #[cfg(test)]
                self.t.out.push((conn, tid, hdr, segs.clone()));
                self.links.get_mut(&conn).is_some_and(|l| {
                    l.conn.send_placement_reply(msgr2::Message {
                        msg_type: hdr.0,
                        tid,
                        version: hdr.1,
                        compat_version: hdr.2,
                        front: segs.front,
                        front_zc: segs.front_zc,
                        front_hints: segs.front_hints,
                        middle: segs.middle,
                        data: segs.data,
                        ..Default::default()
                    })
                })
            }
            Err(e) => {
                self.log(format!("link {conn:#x}: encode {what}: {e}"));
                false
            }
        };
        self.placement_outcome(conn, what, sent);
    }

    fn placement_outcome(&mut self, conn: u64, what: &str, sent: bool) {
        if sent {
            if let Some(l) = self.links.get_mut(&conn)
                && l.placement.is_empty()
            {
                l.conn.placement_end();
            }
        } else {
            self.log(format!(
                "link {conn:#x}: {what} not queued; closing the placement session"
            ));
            self.close_link(conn);
        }
    }

    /// The transport processed a matching CANCEL (WRITE admission closed, accepted WRITE CQEs
    /// drained): send the RETIRED as a placement control frame (the spec's retirement path)
    /// and vacate the attempt.
    pub fn placement_cancelled(&mut self, conn: u64, tid: u64, retry: u32) {
        let Some(l) = self.links.get_mut(&conn) else {
            return;
        };
        // Construct the RETIRED record from the link's grant and send it as a
        // placement control frame (msgr2 tag PlacementControl, direction-checked).
        let Some(grant) = l.placement.grant(tid, retry) else {
            return;
        };
        let record = rdma::placement::ControlRecord {
            attempt: grant.attempt,
            rkey: grant.rkey,
        };
        let sent = l
            .conn
            .send_placement_retired(record.encode(rdma::placement::ControlRecord::RETIRED));
        l.placement.done(tid, retry);
        self.placement_outcome(conn, "RETIRED", sent);
    }

    /// The transport lost the QP (a failed or missing CQE, QP loss): no success or RETIRED can
    /// be produced, the connection faults and the client retains its window. Vacate the attempt.
    pub fn placement_fault(&mut self, conn: u64, tid: u64, retry: u32) {
        if let Some(l) = self.links.get_mut(&conn) {
            l.placement.done(tid, retry);
        }
        self.close_link(conn);
    }

    fn rdma_step(
        &mut self,
        conn: u64,
        now: Duration,
        f: impl FnOnce(&mut Connection) -> bool,
    ) -> bool {
        self.set_now(now);
        let Some(l) = self.links.get_mut(&conn) else {
            return false;
        };
        let applied = f(&mut l.conn);
        self.pump();
        applied
    }

    /// The socket of `conn` was closed / failed.
    pub fn on_closed(&mut self, conn: u64, now: Duration) {
        self.set_now(now);
        if conn & MON_BASE != 0 {
            self.mc.on_closed(conn & !MON_BASE, now);
        } else if let Some(l) = self.links.get_mut(&conn) {
            l.conn.on_closed(now);
            // a reset transport drops its transcript: its charge leaves the budget now, not at the next byte
            self.sync_preauth(conn);
            self.abort_pull(conn);
        } else {
            self.pipe_socket_closed(conn);
        }
        self.pump();
    }

    /// The physical connection of link `id` is gone (the transport reported it closed, or this OSD closed its wire):
    /// a source-pull READ of it can no longer deliver, and the transport keeps an abandoned READ's destination with
    /// the QP until the QP is destroyed, without a completion. The held op is dropped like an op whose inline data
    /// never fully arrived, together with the later messages of the session it held back (they must not run without
    /// it). The session is reset with them (`Connection::discard_messages`): the client resends all of them on its new
    /// session with the same reqids, so no reply goes to the dead link. Dropping them releases their ingress credits
    /// and lets the link's lifecycle events (fault, closed) run.
    fn abort_pull(&mut self, id: u64) {
        let Some(l) = self.links.get_mut(&id) else {
            return;
        };
        let Some(pull) = l.pull.take() else {
            return;
        };
        let (later, carrier) = l.conn.discard_messages();
        // the pull held the link's input: its lifecycle events go on now (the pump consumed their readiness)
        l.conn.notify_events();
        // a READ the transport has not taken yet is never posted for the dead connection
        self.io
            .retain(|c| !matches!(c, IoCmd::SourcePullRead { conn, .. } if *conn == id));
        self.pg.c.link_count("source_pull_aborted");
        self.log(format!(
            "link {id:#x}: connection lost during source-pull PUT {}: op and {later} later message(s) dropped, session reset (client resends)",
            pull.tid
        ));
        // a connection that resumed the session already carries a sequence that skips the dropped messages
        if let Some(other) = carrier {
            self.close_link(other);
        }
    }

    /// Header-time admission of a link's message frames: client frames on the public messenger, peer frames on the
    /// cluster messenger (the two pools of the memory envelope); heartbeats and the rest carry no bulk data.
    fn frame_gate(&self, m: MsgrId) -> Option<ingress::FrameGate> {
        let g = self.cl.frame_gates.as_ref()?;
        Self::frame_pool(m).map(|i| g[i].clone())
    }

    /// Receive probe of a public link's MESSAGE data segments (spec msgr2.md 8.2, client-ops 5.4.1): a write whose data
    /// segment alone is above `osd_max_write_size` is consumed unadmitted and the pipeline answers it -EMSGSIZE from
    /// its front. Only client links write; peer messages have no size rule.
    pub(crate) fn data_probe(&self, m: MsgrId) -> Option<msgr2::DataProbe> {
        // the limit rule 14 enforces on this core: the front decides, so both must agree exactly
        (m == MsgrId::Public)
            .then_some(self.pg.limits.max_write_size as u64)
            .filter(|limit| *limit != 0)
            .map(|limit| msgr2::DataProbe {
                threshold: limit.saturating_add(1),
                refuse: write_probe_refuse,
            })
    }

    /// Index of the pool (`Cl::frame_gates`, `Cl::frame_wait`) whose frame window gates messenger `m`'s links.
    fn frame_pool(m: MsgrId) -> Option<usize> {
        match m {
            MsgrId::Public => Some(0),
            MsgrId::Cluster => Some(1),
            _ => None,
        }
    }

    /// The link waits at a message header for ingress pool space (see `rt::knet::Driver::rx_parked`).
    pub fn rx_parked(&self, conn: u64) -> bool {
        self.links
            .get(&conn)
            .is_some_and(|l| l.conn.awaiting_credit())
    }

    /// Every entry that can run the decoder (`on_bytes`, the direct and secure receive returns) calls this afterwards: a
    /// link that now waits at a message header is queued for [`resume_frames`](Self::resume_frames) (a parked link
    /// that nobody retries would stay unread forever).
    fn note_frame_wait(&mut self, conn: u64) {
        let Some(pool) = self
            .links
            .get(&conn)
            .filter(|l| l.conn.awaiting_credit())
            .and_then(|l| Self::frame_pool(l.msgr))
        else {
            return;
        };
        self.cl.frame_wait[pool].insert(conn);
    }

    /// Retry the message headers that wait for pool space. The order is the pool's (`ingress::FrameGate`: the oldest
    /// waiter across all cores goes first, newcomers queue behind), not this core's queue order, so every waiting link
    /// may be the one at its turn. One refused retry per pool and pass registers this core for the pool's next release;
    /// after it only the links that can go now (`credit_ready`: at their turn, space free) are retried, so a core with
    /// many parked links pays one registration per pass, as with one. The pools are retried independently: a client
    /// pool full of writes that wait for replica acks must not hold back the acks, which wait for the peer pool (one
    /// shared queue did: every peer link of a core parked behind a client link, rdma-lossy-20261021). True when a
    /// connection went on.
    fn resume_frames(&mut self, now: Duration) -> bool {
        let mut work = false;
        let links = &mut self.links;
        for q in &mut self.cl.frame_wait {
            let mut parked = false;
            q.retain(|id| {
                let Some(l) = links.get_mut(id).filter(|l| l.conn.awaiting_credit()) else {
                    return false;
                };
                if parked && !l.conn.credit_ready() {
                    return true;
                }
                // admitted: its messages may be complete even when the next frame of the link waits again
                let admitted = l.conn.retry_credit(now);
                work |= admitted;
                parked |= !admitted;
                l.conn.awaiting_credit()
            });
        }
        if work {
            self.pump();
        }
        work
    }

    /// Bytes received on `conn`.
    pub fn on_bytes(&mut self, conn: u64, data: &[u8], now: Duration) {
        self.set_now(now);
        if conn & MON_BASE != 0 {
            self.mc.on_bytes(conn & !MON_BASE, data, now);
        } else {
            let Some(l) = self.links.get_mut(&conn) else {
                self.pipe_rx(conn, data);
                return;
            };
            l.conn.on_bytes(data, now);
            if self.sync_preauth(conn) {
                self.pump();
                return;
            }
            let Some(l) = self.links.get(&conn) else {
                return;
            };
            if l.pre_due() {
                self.pre_scan(conn);
            }
            self.note_frame_wait(conn);
            let Some(l) = self.links.get(&conn) else {
                return;
            };
            // hot path (one call per received chunk): bytes that complete nothing (the middle of a large frame, acks)
            // Partial input changed no state elsewhere. Dispatch only when a message, handshake step or fault
            // is ready; superseded sessions also come with an event.
            if !l.conn.has_events() {
                return;
            }
        }
        // send-first (adr 0008 am. 2, 5?): a client write on its own PG core leaves its repops before its local txn
        // when the driver closes the window (`set_local_send_first`)
        self.pg.late_ok = self.pg.local_sf;
        self.pump();
        self.pg.late_ok = false;
    }

    /// For a dial of cluster peer link `conn`: the core (NIC queue) of the peer that owns our session there
    /// (`peer_core(whoami)` with the peer's net cores assumed equal to ours). The transport picks a source port the
    /// peer's RSS steers to that core, so the peer needs no relay (adr 0054 am. 1). `None`: any port.
    pub fn dial_remote_core(&self, conn: u64) -> Option<usize> {
        let l = self.links.get(&conn)?;
        (matches!(l.purpose, Purpose::Peer(_)) && l.msgr == MsgrId::Cluster && self.cl.spec.net > 1)
            .then(|| self.cl.spec.peer_core(self.whoami()))
    }

    /// Is `conn` a relayed connection (socket on this core, session on another, adr 0054)?
    pub fn is_relay(&self, conn: u64) -> bool {
        self.pipes.z.contains_key(&conn)
    }

    /// Socket input of a relayed connection as one owned buffer. Transports pass a whole receive batch: the relay window
    /// (adr 0084, 32 fragments) then bounds batches, not TCP segments (32 x 1448 B starved 2 MiB EC sub-writes).
    pub fn on_relay_bytes(&mut self, conn: u64, data: bytes::Bytes, now: Duration) {
        self.set_now(now);
        self.pipe_rx_owned(conn, data);
    }

    /// Core admission headroom for pending store transactions.
    pub fn admission_ready(&self) -> bool {
        self.pg.store.admission_ready()
    }

    /// Transport input pauses behind decoded events until their actor has accepted them.
    /// The actor pump uses its separate pending-input gate, so paused transport
    /// cannot prevent already decoded events or monitor progress from resuming.
    pub fn input_ready(&self, conn: u64) -> bool {
        if conn & MON_BASE != 0 {
            return !self.event_pump_pending;
        }
        self.actor_input_ready(conn)
            && self
                .links
                .get(&conn)
                .is_none_or(|l| !l.conn.has_events() && !l.conn.awaiting_credit())
    }

    fn actor_input_ready(&self, conn: u64) -> bool {
        if let Some(pipe) = self.pipes.z.get(&conn) {
            return pipe.closing.is_none()
                && !pipe.socket_closed
                && pipe.pending_rx.is_none()
                && self.input_room(&pipe.input, 0, 1, true);
        }
        self.links
            .get(&conn)
            .is_none_or(|link| link.pending_input.is_none() && link.pull.is_none())
    }

    /// Held input, a pipe source or a message header that waits for ingress space could go on now. The idle core's
    /// re-check after it announced its sleep, pure (no parking): the retry paths parked every refused input since the
    /// last [`ingress::Parker::arm`]; a release before the announcement is seen here, one after it pokes the core
    /// (`set_core_waker`), and a release that drained a registration in between disarmed the parker.
    pub fn input_resumable(&self) -> bool {
        self.cl.waker.as_ref().is_some_and(|p| !p.armed())
            || self.pipes.rx_pending.iter().any(|c| {
                self.pipes.z.get(c).is_some_and(|p| {
                    p.pending_rx
                        .as_ref()
                        .is_some_and(|d| p.input.ready(0, d.len()))
                })
            })
            || (!self.cl.xout_wait.is_empty() && self.cl.out.len() < crate::xcore::XOUT_MAX)
            || (self.cl.pending_count > 0
                && self.cl.pending_input.iter().any(|q| {
                    q.front()
                        .is_some_and(|&id| self.input_can_resume(id, false))
                }))
            || self.cl.frame_wait.iter().flatten().any(|id| {
                self.links
                    .get(id)
                    .is_some_and(|l| l.conn.awaiting_credit() && l.conn.credit_ready())
            })
    }

    /// Only resume_inputs may remove a retained head; the transport cannot expose the next event first. `park`: see
    /// [`input_room`](Self::input_room).
    fn input_can_resume(&self, conn: u64, park: bool) -> bool {
        let Some(input) = self.links.get(&conn).and_then(|l| l.pending_input.as_ref()) else {
            return true;
        };
        let (spg, window, bytes, guarded) = match input {
            PendingInput::Op { op, bytes, .. } => (
                op.pgid,
                self.input_shard(op.pgid.pgid),
                *bytes,
                op.ingress.0.is_some(),
            ),
            PendingInput::Peer {
                body,
                bytes,
                ingress,
                ..
            } => {
                let Some(spg) = crate::xcore::data_spg(body) else {
                    return ingress.0.is_some()
                        || self.input_room(&self.cl.control_ingress, 0, *bytes, park);
                };
                (
                    spg,
                    self.peer_input_lane(spg.pgid),
                    *bytes,
                    ingress.0.is_some(),
                )
            }
        };
        let credited = match input {
            PendingInput::Peer { body, .. } => {
                crate::flow::is_request(body)
                    && self
                        .links
                        .get(&conn)
                        .and_then(|l| l.peer.as_ref())
                        .is_some_and(|p| self.flow_peer(p.name.num as i32))
            }
            PendingInput::Op { .. } => false,
        };
        (guarded || self.input_room(&self.cl.ingress, window, bytes, park))
            && (credited
                || self.pg.set.core_of(spg.pgid) != self.cl.spec.id
                || self.pg.store.admission_ready_for(spg))
            && self.cl.out.len() < crate::xcore::XOUT_MAX
            && self.cl.xout_wait.is_empty()
    }

    pub(crate) fn hold_input(
        &mut self,
        conn: u64,
        shard: usize,
        why: crate::utilization::HoldWhy,
        input: PendingInput,
    ) {
        let now = self.now;
        // not parked: the idle re-check must not sleep before resume_inputs retried (and parked) it
        if let Some(p) = &self.cl.waker {
            p.disarm();
        }
        if let Some(link) = self.links.get_mut(&conn) {
            debug_assert!(link.pending_input.is_none());
            link.pending_input = Some(input);
            link.held = (now, why);
            // we stop reading this link: its frame deadline (msgr2 spec 4.3) measures the peer, not our backpressure
            link.conn.hold_rx(true, now);
            self.cl.pending_input[shard].push_back(conn);
            self.cl.pending_count += 1;
        }
    }

    pub(crate) fn reserve_input_links(&mut self) {
        let connections = self.links.len() + 1;
        for queue in &mut self.cl.pending_input {
            queue.reserve(connections.saturating_sub(queue.len()));
        }
    }

    pub(crate) fn forget_input(&mut self, id: u64) {
        if self.cl.pending_count == 0 {
            return;
        }
        for queue in &mut self.cl.pending_input {
            let before = queue.len();
            queue.retain(|&conn| conn != id);
            self.cl.pending_count -= before - queue.len();
        }
    }

    /// Placement is a cold barrier: rebuild only the retained input routing, keeping every old lane's FIFO.
    pub(crate) fn set_input_placement(&mut self, pgid: denc::types::PgT, shard: u32) {
        self.pg.set.set_placement(pgid, shard, &self.pg.store);
        self.rebucket_input();
    }

    pub(crate) fn rebucket_input(&mut self) {
        if self.cl.pending_count == 0 {
            return;
        }
        let mut held = Vec::with_capacity(self.cl.pending_count);
        for queue in &mut self.cl.pending_input {
            held.extend(queue.drain(..));
        }
        self.cl.pending_count = 0;
        for id in held {
            let lane = match self.links.get(&id).and_then(|l| l.pending_input.as_ref()) {
                Some(PendingInput::Op { op, .. }) => self.input_shard(op.pgid.pgid),
                Some(PendingInput::Peer { body, .. }) => crate::xcore::data_spg(body)
                    .map_or(self.control_input_lane(), |spg| {
                        self.peer_input_lane(spg.pgid)
                    }),
                None => continue,
            };
            self.cl.pending_input[lane].push_back(id);
            self.cl.pending_count += 1;
        }
    }

    /// Retry one retained head per physical destination. A closed shard costs one probe, regardless of its links.
    pub fn resume_inputs(&mut self, now: Duration) -> bool {
        if self.cl.resuming_input {
            return false;
        }
        if let Some(p) = &self.cl.waker {
            p.arm();
        }
        let mut work = self.resume_pipe_sources();
        if !self.cl.xout_wait.is_empty() {
            self.set_now(now);
            work |= self.drain_xout_wait();
        }
        if self.cl.frame_wait.iter().any(|q| !q.is_empty()) {
            self.set_now(now);
            work |= self.resume_frames(now);
        }
        if self.cl.pending_count == 0 {
            return work;
        }
        self.set_now(now);
        self.cl.resuming_input = true;
        for shard in 0..self.cl.pending_input.len() {
            let Some(id) = self.cl.pending_input[shard].front().copied() else {
                continue;
            };
            if !self.input_can_resume(id, true) {
                continue;
            }
            self.cl.pending_input[shard].pop_front();
            self.cl.pending_count -= 1;
            let Some((Some(input), (at, why))) = self.links.get_mut(&id).map(|l| {
                l.conn.hold_rx(false, self.now);
                (l.pending_input.take(), l.held)
            }) else {
                continue;
            };
            self.note_hold(why, self.now.saturating_sub(at));
            self.cl.resuming_conn = Some(id);
            match input {
                PendingInput::Op { tid, op, bytes } => self.admit_client_op(id, tid, op, bytes),
                PendingInput::Peer {
                    tid,
                    prio,
                    body,
                    bytes,
                    ingress,
                } => self.pg_peer_in(id, tid, prio, body, bytes, ingress),
            }
            work = true;
            self.cl.resuming_conn = None;
            if let Some(link) = self.links.get(&id)
                && link.pending_input.is_none()
            {
                link.conn.notify_events();
            }
            self.pump();
            self.resume_pipe_input(id);
        }
        self.cl.resuming_input = false;
        self.cl.resuming_conn = None;
        work
    }

    /// Transport hint for a dial of `conn`: our OSD id when the target is a peer OSD (not a mon), so a kernel driver can
    /// pick a source port that lands the connection on the peer's owner core of our sessions (adr 0054).
    pub fn dial_owner(&self, conn: u64) -> Option<u32> {
        (conn & MON_BASE == 0).then(|| self.id.whoami.max(0) as u32)
    }

    /// Bytes of a data segment still to come on `conn` that the transport may receive straight into the segment buffer
    /// (see `msgr2::Connection::rx_direct_want`); 0 = no (relayed / other-core / handshake connections, small segments).
    pub fn rx_direct_want(&self, conn: u64) -> usize {
        if conn & MON_BASE != 0 {
            return 0;
        }
        self.links.get(&conn).map_or(0, |l| l.conn.rx_direct_want())
    }

    /// Lend the segment buffer of `conn` to the transport; it comes back through [`Osd::rx_direct_put`].
    pub fn rx_direct_take(&mut self, conn: u64) -> Option<(msgr2::SegBuf, msgr2::BlockCrcs)> {
        self.links.get_mut(&conn)?.conn.rx_direct_take_seg()
    }

    /// The transport filled the lent buffer (`crcs` = its block crcs over all of it, adr 0061 am. 4).
    pub fn rx_direct_put(
        &mut self,
        conn: u64,
        v: msgr2::SegBuf,
        crcs: msgr2::BlockCrcs,
        now: Duration,
    ) {
        self.set_now(now);
        let Some(l) = self.links.get_mut(&conn) else {
            return; // the link is gone: the buffer is dropped
        };
        l.conn.rx_direct_put_seg(v, crcs, now);
        if l.pre_due() {
            self.pre_scan(conn);
        }
        self.note_frame_wait(conn);
        let Some(l) = self.links.get(&conn) else {
            return;
        };
        if !l.conn.has_events() {
            return;
        }
        self.pump();
    }

    /// Positive socket receive progress while the transport owns a frame buffer.
    /// Authentication and actor delivery still wait for the complete frame.
    pub fn rx_progress(&mut self, conn: u64, now: Duration) {
        self.set_now(now);
        if let Some(link) = self.links.get_mut(&conn) {
            link.conn.rx_progress(now);
            // A superseded session may fault instead of refreshing activity.
            self.event_pump_pending |= link.conn.has_events();
            if link.pre_due() {
                self.pre_scan(conn);
            }
        }
    }

    /// Remaining bytes of a known secure frame eligible for decoder-buffer receive.
    pub fn rx_secure_want(&self, conn: u64) -> usize {
        if conn & MON_BASE != 0 {
            return 0;
        }
        self.links.get(&conn).map_or(0, |l| l.conn.rx_secure_want())
    }

    /// Lend initialized decoder ciphertext storage; authentication still happens on return.
    pub fn rx_secure_take(&mut self, conn: u64) -> Option<msgr2::SecureRxBuffer> {
        self.links.get_mut(&conn)?.conn.rx_secure_take()
    }

    /// Complete ciphertext receive. Stale/closed sessions reject the loan in msgr2.
    pub fn rx_secure_put(&mut self, conn: u64, buffer: msgr2::SecureRxBuffer, now: Duration) {
        self.set_now(now);
        let Some(l) = self.links.get_mut(&conn) else {
            return;
        };
        l.conn.rx_secure_put(buffer, now);
        self.note_frame_wait(conn);
        if self.links.get(&conn).is_some_and(|l| l.conn.has_events()) {
            self.pump();
        }
    }

    /// Bytes to write to `conn`.
    pub fn poll_output(&mut self, conn: u64) -> Vec<u8> {
        if conn & MON_BASE != 0 {
            self.mc.poll_output(conn & !MON_BASE)
        } else if let Some(runs) = self.pipe_tx(conn) {
            runs.concat()
        } else {
            self.links
                .get_mut(&conn)
                .map(|l| l.conn.poll_output())
                .unwrap_or_default()
        }
    }

    /// Like [`poll_output`](Self::poll_output) as an ordered list of shared runs: large message payloads are not
    /// copied into the output (the driver sends each run by reference).
    pub fn poll_output_chunks(&mut self, conn: u64) -> Vec<bytes::Bytes> {
        if conn & MON_BASE != 0 {
            let v = self.mc.poll_output(conn & !MON_BASE);
            if v.is_empty() {
                Vec::new()
            } else {
                vec![v.into()]
            }
        } else if let Some(runs) = self.pipe_tx(conn) {
            runs
        } else {
            self.links
                .get_mut(&conn)
                .map(|l| l.conn.poll_output_chunks())
                .unwrap_or_default()
        }
    }

    /// Ids of live connections (a driver may poll them all for output).
    pub fn conn_ids(&self) -> Vec<u64> {
        self.mc
            .conn_ids()
            .into_iter()
            .map(|i| i | MON_BASE)
            .chain(
                self.links
                    .keys()
                    .copied()
                    .filter(|i| !self.pipes.h.contains_key(i)) // their socket is on another core
                    .chain(self.pipes.z.keys().copied()),
            )
            .collect()
    }

    /// Next connection with output, without enumerating idle connections. Socket backpressure consumes
    /// the notification; the transport retries that connection on writability/send completion.
    pub fn poll_output_ready(&mut self) -> Option<u64> {
        self.output_ready.pop()
    }

    /// Earliest absolute time something is due.
    pub fn next_timer(&self) -> Option<Duration> {
        self.refresh_connection_timers();
        let mut t = Some(self.tick_at);
        let mut add = |d: Option<Duration>| {
            if let Some(d) = d {
                t = Some(t.map_or(d, |c| c.min(d)));
            }
        };
        add(self.mc.next_timer());
        add(self.conn_timers.borrow().first().map(|(d, _)| d));
        add(self.hb.next_round);
        add(self.mgr.next_report);
        add(self.mgr.retry_at);
        add(self.shutdown_deadline);
        if self.drain_until.is_some() && self.done.is_none() && self.shutdown_deadline.is_none() {
            add(Some(self.now + Duration::from_millis(1)));
        }
        add(self.pg_next_timer());
        add(self.scatter_deadline());
        t
    }

    /// Run due timers.
    pub fn on_timer(&mut self, now: Duration) {
        self.set_now(now);
        self.settle_late();
        let now = self.now;
        if self.mc.next_timer().is_some_and(|d| d <= now) {
            self.mc.on_timer(now);
        }
        self.refresh_connection_timers();
        let due = self.conn_timers.borrow_mut().due(now);
        for i in due {
            if let Some(l) = self.links.get_mut(&i) {
                l.conn.on_timer(now);
                // a handshake timeout resets the transcript
                self.sync_preauth(i);
            }
        }
        if self.hb.next_round.is_some_and(|d| d <= now) {
            self.hb_round();
        }
        if self.mgr.next_report.is_some_and(|d| d <= now) {
            self.mgr_report_tick();
        }
        if self.mgr.retry_at.is_some_and(|d| d <= now) {
            self.mgr.retry_at = None;
            self.mgr_connect();
        }
        if self.pg_next_timer().is_some_and(|d| d <= now) {
            self.pg_timer(false);
        }
        self.scatter_expire();
        if self.shutdown_deadline.is_some_and(|d| d <= now) {
            let limit = self.conf.f64("osd_mon_shutdown_timeout", 5.0);
            self.logl(
                0,
                format!(
                    "WARNING TIMEOUT shutdown mon ack exceeded {limit}s (osd_mon_shutdown_timeout, MOSDMarkMeDown unacked, exiting)"
                ),
            );
            self.finish_shutdown();
        }
        self.drain_poll();
        if now >= self.tick_at {
            self.tick_at = now + TICK;
            self.tick();
        }
        self.pump();
    }

    // ---------------------------------------------------------------- link plumbing

    fn refresh_connection_timers(&self) {
        let mut timers = self.conn_timers.borrow_mut();
        while let Some(id) = self.timer_ready.pop() {
            if let Some(l) = self.links.get(&id) {
                #[cfg(test)]
                self.t.timer_probes.set(self.t.timer_probes.get() + 1);
                let d = l.conn.next_timer();
                timers.set(id, d);
            } else {
                timers.unregister(id);
            }
        }
    }

    pub(crate) fn alloc_link_id(&mut self) -> u64 {
        let i = self.next_link | ((self.cl.spec.id as u64) << crate::xcore::CORE_SHIFT);
        self.next_link += 1;
        i
    }

    /// Encode + queue `m` on local link `id` with `tid`. False if the link is gone or encoding failed.
    fn send_local(&mut self, id: u64, tid: u64, m: AnyMessage) -> bool {
        let feats = self
            .links
            .get(&id)
            .and_then(|l| l.peer.as_ref())
            .map_or(denc::features::ALL, |p| p.features);
        let (ty, version, compat, segs) = match m.encode(feats) {
            Ok(x) => x,
            Err(e) => {
                self.log(format!("encode message {}: {e}", m.msg_type()));
                return false;
            }
        };
        #[cfg(test)]
        self.t
            .out
            .push((id, tid, (ty, version, compat), segs.clone()));
        let Some(l) = self.links.get_mut(&id) else {
            return false;
        };
        l.conn.send_message(msgr2::Message {
            msg_type: ty,
            tid,
            version,
            compat_version: compat,
            front: segs.front,
            front_zc: segs.front_zc,
            front_hints: segs.front_hints,
            middle: segs.middle,
            data: segs.data,
            ..Default::default()
        })
    }

    /// Encode + queue `m` on link `id`. False if the link is gone or encoding failed.
    pub(crate) fn send_link(&mut self, id: u64, m: impl Into<AnyMessage>) -> bool {
        let m: AnyMessage = m.into();
        if !self.link_is_local(id) {
            self.xsend(
                link_core(id),
                XMsg::Msg {
                    link: id,
                    tid: None,
                    msg: Box::new(m),
                },
            );
            return true;
        }
        let tid = self.alloc_tid();
        self.send_local(id, tid, m)
    }

    /// Send a reply that echoes `tid`.
    pub(crate) fn send_link_tid(&mut self, id: u64, tid: u64, m: impl Into<AnyMessage>) -> bool {
        let m: AnyMessage = m.into();
        if !self.link_is_local(id) {
            self.xsend(
                link_core(id),
                XMsg::Msg {
                    link: id,
                    tid: Some(tid),
                    msg: Box::new(m),
                },
            );
            return true;
        }
        self.send_local(id, tid, m)
    }

    /// Queue an already encoded message on link `id`.
    pub(crate) fn send_raw(
        &mut self,
        id: u64,
        tid: u64,
        priority: u16,
        hdr: (u16, u16, u16),
        segs: messages::Segments,
    ) -> bool {
        self.send_raw_crc(id, tid, priority, hdr, segs, Default::default())
    }

    /// [`Self::send_raw`] with the known crc32c (seed `!0`) of the data segment.
    pub(crate) fn send_raw_crc(
        &mut self,
        id: u64,
        tid: u64,
        priority: u16,
        (ty, version, compat): (u16, u16, u16),
        segs: messages::Segments,
        data_crc: crate::xcore::DataX,
    ) -> bool {
        if !self.link_is_local(id) {
            self.xsend(
                link_core(id),
                XMsg::Wire {
                    link: id,
                    tid,
                    prio: priority,
                    hdr: (ty, version, compat),
                    segs,
                    data_crc,
                },
            );
            return true;
        }
        #[cfg(test)]
        self.t.out.push((
            id,
            tid,
            (ty, version, compat),
            messages::Segments {
                data: msgr2::flatten_data(&segs.data, &data_crc.more),
                ..segs.clone()
            },
        ));
        let Some(l) = self.links.get_mut(&id) else {
            return false;
        };
        l.conn.send_message(msgr2::Message {
            msg_type: ty,
            tid,
            priority,
            version,
            compat_version: compat,
            front: segs.front,
            front_zc: segs.front_zc,
            front_hints: segs.front_hints,
            middle: segs.middle,
            data: segs.data,
            data_crc: data_crc.crc,
            data_more: data_crc.more,
            data_off: data_crc.data_off,
        })
    }

    /// Dial a peer through messenger `m`.
    pub(crate) fn dial(
        &mut self,
        m: MsgrId,
        purpose: Purpose,
        peer_type: u8,
        peer_addrs: &EntityAddrVec,
    ) -> Option<u64> {
        let Some(target) = self.pick_target(m, peer_addrs) else {
            self.warn_unreachable(purpose, m, peer_addrs);
            return None;
        };
        let id = self.alloc_link_id();
        let h: Box<dyn msgr2::auth::AuthClientHandler> =
            Box::new(DaemonAuthClient::new(self.keys.clone()));
        #[cfg(test)]
        let h: Box<dyn msgr2::auth::AuthClientHandler> = if self.t.dial_auth_none {
            Box::new(msgr2::auth::AuthNoneClient {
                name: EntityName::osd(i64::from(self.id.whoami)),
                global_id: 0,
            })
        } else {
            h
        };
        let ms = &self.msgr[m as usize];
        let mut conn = Connection::client(
            id,
            ms.cfg.clone(),
            ms.table.clone(),
            h,
            peer_type,
            peer_addrs.clone(),
            target,
        );
        conn.set_frame_gate(self.frame_gate(m));
        conn.set_data_probe(self.data_probe(m));
        conn.set_prewrite(self.pre.min);
        conn.set_rx_place(true);
        conn.set_output_queue(&self.output_ready, id);
        conn.set_event_queue(&self.event_ready, id);
        conn.set_timer_queue(&self.timer_ready, id);
        self.conn_timers.get_mut().register(id);
        self.reserve_input_links();
        self.links.insert(
            id,
            Link {
                pending_input: None,
                held: Default::default(),
                conn,
                msgr: m,
                purpose,
                auth: Rc::new(RefCell::new(PeerAuth::default())),
                peer: None,
                sock: None,
                caps: None,
                caps_peer: opexec::caps::Peer::from_addr(&target),
                info: None,
                fwd: 0,
                pre: None,
                placement: Default::default(),
                preauth_charged: 0,
                pull: None,
            },
        );
        if self.sync_preauth(id) {
            return None;
        }
        Some(id)
    }

    /// The OSD's own addresses of messenger `m` (cluster and heartbeat back: cluster, the rest: public; spec 3.4).
    fn own_ips(&self, m: MsgrId) -> &[IpAddr] {
        match m {
            MsgrId::Cluster | MsgrId::HbBackCli | MsgrId::HbBackSrv => &self.cfg.cluster_ips,
            _ => &self.cfg.public_ips,
        }
    }

    /// Our address of the target's family for the source bind (adr 0171, `ms_bind_before_connect`); None = we bind
    /// no address of that family, the socket stays unbound (never a cross-family bind, spec 8).
    fn src_for(ips: &[IpAddr], target: IpAddr) -> Option<IpAddr> {
        ips.iter().copied().find(|ip| same_family(*ip, target))
    }

    /// Bind address of a dialled link: the link messenger's own address of the target's family.
    fn dial_src(&self, id: u64, target: IpAddr) -> Option<IpAddr> {
        let m = self.links.get(&id).map(|l| l.msgr);
        Self::src_for(
            m.map_or(&self.cfg.public_ips[..], |m| self.own_ips(m)),
            target,
        )
    }

    /// Dial target of a peer addrvec (spec 4): the first msgr2 entry; if that is of a family we hold no address of, the
    /// first msgr2 entry of a family we do hold (dual-stack peers list both). `None` when no advertised entry is
    /// reachable for us: no dial at all, so a peer is never reported failed for a family we cannot speak (spec 8).
    /// An unspecified address (`0.0.0.0`, `::`: a classic daemon's wildcard entry for a family it has no address of) is
    /// never a target: dialling it reaches this host, not the peer.
    fn pick_target(&self, m: MsgrId, peer_addrs: &EntityAddrVec) -> Option<EntityAddr> {
        let own = self.own_ips(m);
        let reachable = |a: &EntityAddr| {
            a.ip()
                .is_some_and(|ip| !ip.is_unspecified() && Self::src_for(own, ip).is_some())
        };
        let mut v2 = peer_addrs
            .0
            .iter()
            .filter(|a| a.ty == EntityAddr::TYPE_MSGR2);
        let first = v2.next()?;
        if reachable(first) {
            return Some(*first);
        }
        v2.find(|a| reachable(a)).copied()
    }

    /// The direction suffix of a failed heartbeat dial: ` on back path (local <ip[,ip]> on <iface>)`, empty for a
    /// non-heartbeat messenger (the peer address is already the dial `target` in the line).
    fn dial_direction(&self, msgr: MsgrId) -> String {
        let back = match msgr {
            MsgrId::HbBackCli => true,
            MsgrId::HbFrontCli => false,
            _ => return String::new(),
        };
        let ips = if back {
            &self.cfg.cluster_ips
        } else {
            &self.cfg.public_ips
        };
        let iface_key = if back { "back_iface" } else { "front_iface" };
        let local = ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let iface = self
            .cfg
            .sys_metadata
            .get(iface_key)
            .map(String::as_str)
            .unwrap_or("");
        let dir = if back { "back" } else { "front" };
        if iface.is_empty() {
            format!(" on {dir} path (local {local})")
        } else {
            format!(" on {dir} path (local {local} on {iface})")
        }
    }

    /// A peer none of whose advertised families we bind: loud, once per peer (it is retried every round).
    fn warn_unreachable(&mut self, purpose: Purpose, msgr: MsgrId, peer_addrs: &EntityAddrVec) {
        if !self
            .dial_warned
            .insert(DialWarn::Unreachable(purpose, msgr))
        {
            return;
        }
        let key = addrs_str(peer_addrs);
        self.logl(
            0,
            format!(
                "osd.{}: cannot reach {key}: no advertised address of a family we bind (ours: {}); not dialling",
                self.id.whoami,
                self.cfg
                    .public_ips
                    .iter()
                    .chain(self.cfg.cluster_ips.iter())
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        );
    }

    pub(crate) fn close_link(&mut self, id: u64) {
        if !self.link_is_local(id) {
            self.xsend(link_core(id), XMsg::CloseLink { link: id });
            return;
        }
        if let Some(mut l) = self.links.remove(&id) {
            self.link_left(&l);
            self.conn_timers.get_mut().unregister(id);
            self.forget_input(id);
            l.conn.close();
            self.io.push_back(IoCmd::Close { conn: id });
            self.link_gone(id, l.purpose, l.fwd);
        }
    }

    /// A connection lost its lossless session to a newer one (`take_superseded`). The messages it decoded but this OSD
    /// has not taken yet (held input, queued events) are counted in the session's in_seq: the peer never resends them.
    /// Without any, the link closes now; else it is closed for the wire but its input still drains, or the new carrier
    /// takes it over at READY (`take_over_input`). Its `Closed` event comes last and removes it (OQ 28 O15).
    fn retire_link(&mut self, id: u64) {
        let Some(l) = self.links.get_mut(&id) else {
            return;
        };
        if l.pending_input.is_none() && l.pull.is_none() && !l.conn.has_events() {
            self.close_link(id);
            return;
        }
        l.conn.close();
        self.io.push_back(IoCmd::Close { conn: id });
        // the wire closes: a pending source-pull READ ends with it (`abort_pull`)
        self.abort_pull(id);
        self.pg.c.link_count("superseded_input_drains");
    }

    /// Cluster link `id` reached READY for OSD peer `name`: older links of the same peer whose session it now carries
    /// hand over what they decoded but this OSD has not taken (held input first, then queued messages), so the
    /// session's messages arrive once and in order; the finished links close (OQ 28 O15, `take_over_messages`).
    fn take_over_input(&mut self, id: u64, name: EntityName) {
        let mut older: Vec<u64> = self
            .links
            .iter()
            .filter(|(o, l)| {
                **o != id
                    && l.msgr == MsgrId::Cluster
                    && l.peer.as_ref().is_some_and(|p| p.name == name)
            })
            .map(|(o, _)| *o)
            .collect();
        older.sort_unstable();
        for o in older {
            let Some(mut old) = self.links.remove(&o) else {
                continue;
            };
            let Some(new) = self.links.get_mut(&id) else {
                self.links.insert(o, old);
                return;
            };
            // READY is the new connection's first event: nothing of its own is held yet
            if new.pending_input.is_some() || !new.conn.take_over_messages(&mut old.conn) {
                self.links.insert(o, old);
                continue;
            }
            if let Some(input) = old.pending_input.take() {
                new.pending_input = Some(input);
                new.held = old.held;
                new.conn.hold_rx(true, self.now);
                for queue in &mut self.cl.pending_input {
                    for c in queue.iter_mut().filter(|c| **c == o) {
                        *c = id;
                    }
                }
            }
            self.links.insert(o, old);
            self.pg.c.link_count("input_taken_over");
            self.close_link(o);
        }
    }

    fn link_gone(&mut self, id: u64, p: Purpose, fwd: u64) {
        match p {
            Purpose::Mgr => self.mgr_link_lost(id),
            Purpose::Hb(o) => self.hb_link_lost(o, id),
            Purpose::Peer(o) => self.pg_peer_link_gone(o, id),
            Purpose::Copy(o) => self.copy_link_gone(o, id),
            Purpose::Accepted => self.pg_link_closed(id, fwd),
        }
    }

    // ---------------------------------------------------------------- pump

    /// Drain every component until quiet.
    pub(crate) fn pump(&mut self) {
        // inside the send-first window the driver applies the held-back txn after it moved the repops; every PG entry
        // point below settles it before it touches the store (`pg_run`, `pg_exec`, `poll_store`, ...)
        if !self.pg.late_ok {
            self.settle_late();
        }
        self.event_pump_pending = false;
        let mut events = 0usize;
        // work slice (adr 0006 am. 4): learned like the PG-core inbox, no clock read per event; what the events hand on is
        // each source core's minimum share of the next inbox drain (am. 6)
        let budget = self.slice.budget();
        let mut slice = 0usize;
        for _ in 0..1000 {
            let mut progress = false;
            while let Some(c) = self.mc.poll_io() {
                progress = true;
                match c {
                    monc::IoCmd::Dial { conn, target } => self.io.push_back(IoCmd::Dial {
                        conn: conn | MON_BASE,
                        target,
                        src: target
                            .ip()
                            .and_then(|ip| Self::src_for(&self.cfg.public_ips, ip)),
                    }),
                    monc::IoCmd::Close { conn } => self.io.push_back(IoCmd::Close {
                        conn: conn | MON_BASE,
                    }),
                }
            }
            while let Some(ev) = self.mc.poll_event() {
                progress = true;
                self.on_mon_event(ev);
                events += 1;
                slice += crate::xcore::SLICE_MIN;
                self.slice.add_link(crate::xcore::SLICE_MIN);
                if events >= 128 || slice >= budget {
                    if slice >= budget {
                        self.note_slice_cut();
                    }
                    self.event_pump_pending = true;
                    return;
                }
            }
            while let Some(id) = self.event_ready.pop() {
                if !self.actor_input_ready(id)
                    || !self.links.get(&id).is_some_and(|l| l.conn.has_events())
                {
                    continue;
                }
                #[cfg(test)]
                {
                    self.t.event_visits += 1;
                }
                let mut connection_events = 0;
                loop {
                    if !self.actor_input_ready(id) {
                        break;
                    }
                    let ev = match self.links.get_mut(&id) {
                        Some(l) => l.conn.poll_event(),
                        None => None,
                    };
                    let Some(ev) = ev else { break };
                    progress = true;
                    let w = match &ev {
                        Event::Message(m) => m.front.len() + m.middle.len() + m.data.len(),
                        _ => 0,
                    }
                    .max(crate::xcore::SLICE_MIN);
                    slice += w;
                    self.slice.add_link(w);
                    self.on_link_event(id, ev);
                    events += 1;
                    connection_events += 1;
                    if events >= 128 || slice >= budget {
                        if slice >= budget {
                            self.note_slice_cut();
                        }
                        // The readiness token was consumed. Retained events must
                        // resume without another network packet or timer.
                        if let Some(l) = self.links.get(&id) {
                            l.conn.notify_events();
                        }
                        self.event_pump_pending = true;
                        return;
                    }
                    if connection_events >= 16 {
                        if let Some(l) = self.links.get(&id) {
                            l.conn.notify_events();
                        }
                        break;
                    }
                }
            }
            for s in self
                .msgr
                .iter()
                .flat_map(|m| m.table.take_superseded())
                .collect::<Vec<_>>()
            {
                if s & MON_BASE == 0 && self.links.contains_key(&s) {
                    progress = true;
                    self.retire_link(s);
                }
            }
            // spec 10.7 step 7: an accepted cluster connection faulted while its session owed the peer messages
            if self.msgr[MsgrId::Cluster as usize].table.take_owed() {
                progress = true;
                self.pg_dial_owed();
            }
            if !progress {
                return;
            }
        }
        self.event_pump_pending = true;
    }

    pub(crate) fn on_link_event(&mut self, id: u64, ev: Event) {
        let purpose = match self.links.get(&id) {
            Some(l) => l.purpose,
            None => return,
        };
        match ev {
            Event::Dial { target } => {
                let src = target.ip().and_then(|ip| self.dial_src(id, ip));
                self.io.push_back(IoCmd::Dial {
                    conn: id,
                    target,
                    src,
                });
            }
            Event::Connected(p) => {
                let name = p.name;
                if matches!(purpose, Purpose::Peer(_))
                    || self
                        .links
                        .get(&id)
                        .is_some_and(|l| l.msgr == MsgrId::Cluster)
                {
                    self.pg.c.link_count("connected");
                    self.log(format!(
                        "cluster link {id} ({purpose:?}) connected to {:?}",
                        p.name
                    ));
                }
                if let Some(l) = self.links.get_mut(&id) {
                    l.peer = Some(p);
                }
                // authenticated: the handshake transcript is gone, its budget share is free again
                self.release_preauth(id);
                // the peer answers (also inbound, by its authenticated OSD name): its dial warnings re-arm
                let peer_osd = self
                    .links
                    .get(&id)
                    .and_then(|l| l.peer.as_ref())
                    .filter(|p| p.name.ty == EntityName::OSD)
                    .map(|p| p.name.num as i32);
                self.dial_warned
                    .retain(|w| !w.answered_by(purpose, peer_osd));
                // cluster and heartbeat listeners serve OSDs only; the name is the authenticated identity (msgr2 binds it)
                if purpose == Purpose::Accepted
                    && self.links.get(&id).is_some_and(|l| {
                        l.msgr != MsgrId::Public
                            && l.peer
                                .as_ref()
                                .is_some_and(|p| p.name.ty != EntityName::OSD)
                    })
                {
                    self.log(format!(
                        "link {id}: non-OSD entity on a cluster-side listener refused"
                    ));
                    self.close_link(id);
                    return;
                }
                if purpose == Purpose::Accepted && !self.session_caps(id) {
                    self.close_link(id);
                    return;
                }
                self.link_ready_info(id, purpose);
                self.on_link_ready(id, purpose);
                if let Some(o) = self.cluster_peer_osd(id) {
                    self.take_over_input(id, name);
                    self.pg_peer_link(o, true);
                }
            }
            Event::Message(m) => {
                // Refused payloads and placement middles bypass on_link_message.
                if m.header.msg_type == opwire::MOSDOp::MSG_TYPE
                    && let Err(e) = check_wire_compat(
                        m.header.msg_type,
                        m.header.version,
                        m.header.compat_version,
                    )
                {
                    self.fault_undecodable(id, "undecodable_message", "MOSDOp header", e);
                    return;
                }
                // A public-link MOSDOp whose data segment the receive probe refused (spec msgr2.md 8.2, client-ops
                // 5.4.1): the payload was never admitted, the op is answered from its front.
                if m.header.msg_type == opwire::consts::ty::OSD_OP && m.data_refused > 0 {
                    let tid = m.header.tid;
                    self.on_refused_op(id, purpose, tid, &m);
                    return;
                }
                // Classic MOSDOp/MOSDOpReply leave middle empty (client-ops spec s1).
                // Only the authenticated attempt owner may admit a descriptor middle;
                // anything else is a protocol violation, never a classic payload.
                if m.header.msg_type == opwire::consts::ty::OSD_OP && !m.middle.is_empty() {
                    let tid = m.header.tid;
                    // A source-pull PUT record (adr 0665) names a client READ-only
                    // source instead of inline data. It is validated here, before
                    // any op reaches a PG core; the op is held until the transport's
                    // RDMA READ filled its data (`source_pull_done`).
                    if rdma::source_pull::is_record(&m.middle) {
                        match self.source_pull_admit(id, purpose, &m) {
                            Ok((op, descriptor, bytes)) => {
                                if let Some(l) = self.links.get_mut(&id) {
                                    // the session's input pauses until the READ delivered the data; the frame
                                    // deadline (msgr2 spec 4.3) measures the peer, not this wait
                                    l.conn.hold_rx(true, self.now);
                                    l.pull = Some(PendingPull {
                                        tid,
                                        op,
                                        bytes,
                                        descriptor,
                                    });
                                }
                                self.io.push_back(IoCmd::SourcePullRead {
                                    conn: id,
                                    tid,
                                    source: descriptor.address,
                                    rkey: descriptor.rkey,
                                    length: descriptor.length,
                                    crc32c: descriptor.crc32c,
                                });
                                return;
                            }
                            Err(e) => {
                                self.log(format!("link {id}: source-pull record refused ({e:?})"));
                                self.close_link(id);
                                return;
                            }
                        }
                    }
                    match self.placement_admit(id, purpose, tid, &m) {
                        Ok(op) => {
                            self.admit_client_op(
                                id,
                                tid,
                                op,
                                m.front.len() + m.middle.len() + m.data.len(),
                            );
                            return;
                        }
                        Err(e) => {
                            self.log(format!("link {id}: op middle refused ({e:?})"));
                            self.close_link(id);
                            return;
                        }
                    }
                }
                if m.header.msg_type == opwire::consts::ty::OSD_OPREPLY && !m.middle.is_empty() {
                    self.log(format!(
                        "link {id}: op reply middle before placement attempt handler"
                    ));
                    self.close_link(id);
                    return;
                }
                let previous = self.cl.raw_input.take();
                self.cl.raw_input = Some((id, m.ingress));
                let previous_crc = std::mem::replace(&mut self.cl.raw_crc, m.data_crc);
                let previous_prio = std::mem::replace(&mut self.cl.raw_prio, m.header.priority);
                let h = Header2 {
                    seq: m.header.seq,
                    tid: m.header.tid,
                    ty: m.header.msg_type,
                    priority: m.header.priority,
                    version: m.header.version,
                    data_pre_padding_len: m.header.data_pre_padding_len,
                    data_off: m.header.data_off,
                    ack_seq: m.header.ack_seq,
                    flags: m.header.flags,
                    compat_version: m.header.compat_version,
                    reserved: m.header.reserved,
                };
                match messages::decode_with_header_owned(&h, &m.front, &m.middle, &m.data) {
                    Ok(msg) => self.on_link_message(id, purpose, h.tid, msg),
                    Err(e) => self.fault_undecodable(
                        id,
                        "undecodable_message",
                        &format!("message type {}", h.ty),
                        e,
                    ),
                }
                self.cl.raw_input = previous;
                self.cl.raw_crc = previous_crc;
                self.cl.raw_prio = previous_prio;
            }
            Event::KeepaliveAck { .. } => {}
            Event::Handoff { owner, .. } => self.handoff_link(id, owner),
            Event::RdmaPrepare => self.io.push_back(IoCmd::RdmaPrepare { conn: id }),
            Event::RdmaOffer { endpoint } => {
                self.io.push_back(IoCmd::RdmaAccept { conn: id, endpoint })
            }
            Event::RdmaAnswer {
                endpoint: Some(endpoint),
            } => self.io.push_back(IoCmd::RdmaConnect { conn: id, endpoint }),
            Event::RdmaAnswer { endpoint: None } => {
                self.io.push_back(IoCmd::RdmaRelease { conn: id })
            }
            Event::PlacementControl(record) => {
                // msgr2 admitted the frame only on a negotiated READY placement
                // session (direction-checked: this is the client's CANCEL).
                let Some(l) = self.links.get_mut(&id) else {
                    return;
                };
                if let Some((tid, retry)) =
                    l.placement.cancel(l.conn.placement_generation(), &record)
                {
                    self.log(format!("link {id}: placement attempt retired by CANCEL"));
                    // tell the transport to close WRITE admission and send RETIRED on the same SQ
                    self.io.push_back(IoCmd::PlaceReadCancel {
                        conn: id,
                        tid,
                        retry,
                    });
                } else {
                    self.log(format!(
                        "link {id}: placement CANCEL without a live attempt"
                    ));
                }
            }
            Event::Reset | Event::RemoteReset => {
                if self
                    .links
                    .get(&id)
                    .is_some_and(|l| l.msgr == MsgrId::Cluster)
                {
                    self.pg.c.link_count(if matches!(ev, Event::Reset) {
                        "reset"
                    } else {
                        "remote_reset"
                    });
                    self.log(format!("cluster link {id} ({purpose:?}) session {ev:?}"));
                }
                if let Some(o) = self.cluster_peer_osd(id) {
                    self.pg_peer_link(o, false);
                }
                if purpose == Purpose::Mgr {
                    self.close_link(id);
                }
            }
            Event::Fault(r) => {
                if self
                    .links
                    .get(&id)
                    .is_some_and(|l| l.msgr == MsgrId::Cluster)
                {
                    self.pg.c.link_count("fault");
                    let from = self.links.get(&id).map_or_else(String::new, |l| {
                        let t = addrs_str(&EntityAddrVec::single(l.conn.target()));
                        match l.conn.ident_claim() {
                            Some((a, d)) if purpose == Purpose::Accepted => format!(
                                " from {t} claims {} dialled {} we are {}",
                                addrs_str(a),
                                addrs_str(&EntityAddrVec::single(*d)),
                                addrs_str(&self.cluster_addrs)
                            ),
                            _ if purpose == Purpose::Accepted => format!(" from {t}"),
                            _ => format!(" to {t}"),
                        }
                    });
                    self.log(format!(
                        "cluster link {id} ({purpose:?}{from}) fault: {r:?}"
                    ));
                }
                if let Some(o) = self.cluster_peer_osd(id) {
                    self.pg_peer_link(o, false);
                }
                self.io.push_back(IoCmd::Close { conn: id });
                if matches!(purpose, Purpose::Mgr | Purpose::Hb(_)) {
                    self.log(format!("link {id} ({purpose:?}) fault: {r:?}"));
                }
            }
            Event::Closed => {
                if self
                    .links
                    .get(&id)
                    .is_some_and(|l| l.msgr == MsgrId::Cluster)
                {
                    self.pg.c.link_count("closed");
                }
                self.io.push_back(IoCmd::Close { conn: id });
                if let Some(l) = self.links.remove(&id) {
                    self.link_left(&l);
                    self.conn_timers.get_mut().unregister(id);
                    self.forget_input(id);
                    self.link_gone(id, purpose, l.fwd);
                }
            }
        }
    }

    /// The peer OSD of a cluster-messenger link (dialled or accepted), if known.
    fn cluster_peer_osd(&self, id: u64) -> Option<i32> {
        let l = self.links.get(&id)?;
        if l.msgr != MsgrId::Cluster {
            return None;
        }
        match l.purpose {
            Purpose::Peer(o) => Some(o),
            Purpose::Accepted => l
                .peer
                .as_ref()
                .filter(|p| p.name.ty == EntityName::OSD)
                .map(|p| p.name.num as i32),
            _ => None,
        }
    }

    /// Parse the caps of a newly authenticated public-messenger client. `false` = refuse the connection.
    fn session_caps(&mut self, id: u64) -> bool {
        let Some(l) = self.links.get_mut(&id) else {
            return true;
        };
        if l.msgr != MsgrId::Public {
            return true;
        }
        let text = l.auth.borrow().caps.clone();
        let who = l.auth.borrow().entity.clone();
        let parsed = match text.as_deref() {
            None | Some("") => Err("empty caps".to_owned()),
            Some(t) => opexec::caps::Caps::parse(t),
        };
        match parsed {
            Ok(c) => {
                l.caps = Some(Arc::new(c));
                true
            }
            Err(e) => {
                self.log(format!("link {id}: refusing {who}: osd caps {text:?}: {e}"));
                false
            }
        }
    }

    /// Ingress of a placement descriptor (`Event::Message` with a nonempty MOSDOp middle):
    /// the link must be a negotiated READY placement session, the op the plain READ shape,
    /// and the descriptor must match the session generation and the frame's transaction
    /// with a fresh retry identity. On success the checked grant is recorded on the link's
    /// attempt owner, the op is marked with the attempt's retry number and the middle is
    /// consumed (it was never a classic payload).
    fn placement_admit(
        &mut self,
        id: u64,
        purpose: Purpose,
        tid: u64,
        m: &msgr2::Incoming,
    ) -> Result<opwire::MOSDOp, crate::attempt::Reject> {
        use crate::attempt::Reject;
        let Some(l) = self.links.get_mut(&id) else {
            return Err(Reject::Session);
        };
        if l.msgr != MsgrId::Public
            || purpose != Purpose::Accepted
            || !l.conn.placement_ready()
            || l.conn.mode() != msgr2::auth::MODE_CRC
        {
            return Err(Reject::Session);
        }
        let mut op = opwire::MOSDOp::decode_shared(m.header.version, &m.front, &m.data)
            .map_err(|_| Reject::Shape)?;
        if !op.placement_read_eligible() {
            return Err(Reject::Shape);
        }
        let retry = l
            .placement
            .admit(l.conn.placement_generation(), tid, &m.middle)?;
        if !l.conn.placement_begin() {
            l.placement.done(tid, retry);
            return Err(Reject::Session);
        }
        op.placement_read = Some(retry);
        op.ingress = m.ingress.clone();
        Ok(op)
    }

    /// Admit a source-pull PUT record (adr 0665): a plain write whose data
    /// segment is replaced by a validated descriptor naming a client READ-only
    /// source. The record is checked against the session and the op shape; the
    /// caller holds the op until the transport's RDMA READ answered
    /// ([`Self::source_pull_done`]).
    fn source_pull_admit(
        &mut self,
        id: u64,
        purpose: Purpose,
        m: &msgr2::Incoming,
    ) -> Result<(opwire::MOSDOp, rdma::source_pull::Descriptor, usize), crate::attempt::Reject>
    {
        use crate::attempt::Reject;
        let Some(l) = self.links.get_mut(&id) else {
            eprintln!(
                "source-pull: link {id:#x} not on this core ({} links here, purpose={purpose:?})",
                self.links.len()
            );
            return Err(Reject::Session);
        };
        // A READY CRC-mode public session with the extension negotiated is all the
        // pull needs; the placement READ path is not involved
        // (`source_pull_capable` below already implies READY and an RDMA carrier).
        if l.msgr != MsgrId::Public
            || purpose != Purpose::Accepted
            || l.conn.mode() != msgr2::auth::MODE_CRC
        {
            eprintln!(
                "source-pull: link {id:#x} refused (msgr={:?} purpose={purpose:?} mode={:?})",
                l.msgr,
                l.conn.mode()
            );
            return Err(Reject::Session);
        }
        let mut op = opwire::MOSDOp::decode_shared(m.header.version, &m.front, &m.data)
            .map_err(|_| Reject::Shape)?;
        if op.ops.len() != 1 || op.ops[0].op != opwire::op::WRITE {
            return Err(Reject::Shape);
        }
        let descriptor =
            rdma::source_pull::Descriptor::decode(&m.middle).map_err(|_| Reject::Shape)?;
        // The record carries the write length: the op names the offset only (its
        // data segment is the descriptor, so it has no inline bytes).
        let mut extent = op.ops[0].extent();
        extent.length = u64::from(descriptor.length);
        op.ops[0].set_extent(extent);
        if !l.conn.source_pull_capable() {
            eprintln!(
                "link {id:#x}: source-pull record refused (no negotiated source-pull capability)"
            );
            return Err(Reject::Session);
        }
        op.source_pull = Some(m.middle.to_vec());
        op.ingress = m.ingress.clone();
        Ok((
            op,
            descriptor,
            m.front.len() + m.middle.len() + m.data.len(),
        ))
    }

    /// A session became ready: public clients get the [`ConnInfo`] PG cores work with; peer links announce their
    /// negotiated features to every core (they encode cluster messages for it).
    pub(super) fn link_ready_info(&mut self, id: u64, purpose: Purpose) {
        let Some(l) = self.links.get_mut(&id) else {
            return;
        };
        let Some(p) = l.peer.as_ref() else { return };
        if l.msgr == MsgrId::Public && purpose == Purpose::Accepted {
            let addr = client_src_addr(&p.addrs);
            l.info = Some(Arc::new(ConnInfo {
                who: p.name,
                features: p.features,
                addr,
                peer_addr: l.conn.target(),
                caps: l.caps.clone(),
            }));
            return;
        }
        let (features, addrs) = (p.features, p.addrs.clone());
        if let Some(o) = self.cluster_peer_osd(id) {
            // the peer's incarnation: a dialed link names the one it was dialed for (a link no longer in `pg.peers`,
            // replaced, says nothing); an accepted one (the peer's dial won the race, spec 10.3; `pg_send` then sends
            // on it as the carrier) the map's incarnation at the address the peer identified with. Ceph encodes for
            // the connection's features whichever side dialed (ECSubWrite v5 vs v4, spec ec.md 6.1.1).
            let up_from = match purpose {
                Purpose::Peer(_) => self
                    .pg
                    .peers
                    .get(&o)
                    .filter(|c| c.link == id)
                    .map(|c| c.up_from),
                _ => self
                    .peer_target(o)
                    .filter(|(_, target)| *target == addrs)
                    .map(|(u, _)| u),
            };
            let Some(up_from) = up_from else {
                return;
            };
            self.cl.peer_feat.insert(o, (up_from, features));
            self.xbcast(|| XMsg::PeerFeat {
                osd: o,
                up_from,
                features,
            });
        }
    }

    fn on_link_ready(&mut self, id: u64, purpose: Purpose) {
        if purpose == Purpose::Mgr {
            self.mgr_ready(id);
        } else if let Purpose::Copy(o) = purpose {
            self.copy_link_ready(o, id);
        }
    }

    pub(crate) fn on_link_message(&mut self, id: u64, purpose: Purpose, tid: u64, msg: AnyMessage) {
        if let AnyMessage::Unknown {
            ty,
            version,
            compat,
            ..
        } = &msg
            && let Err(e) = check_wire_compat(*ty, *version, *compat)
        {
            self.fault_undecodable(id, "undecodable_message", "service message header", e);
            return;
        }
        match (&msg, purpose) {
            // CEPH_MSG_PING: classic drops it (debug log only), no reply
            (AnyMessage::MPing(_), _) => {}
            (
                AnyMessage::Unknown {
                    ty,
                    version,
                    segments,
                    ..
                },
                Purpose::Copy(o),
            ) => self.copy_link_message(id, o, tid, *ty, *version, segments),
            (_, Purpose::Copy(_)) => {} // maps and the like a classic OSD sends its clients: not needed
            (AnyMessage::MOSDPing(p), _) => self.on_ping(id, p.clone()),
            (
                AnyMessage::Unknown {
                    ty,
                    version,
                    segments,
                    ..
                },
                _,
            ) if purpose != Purpose::Mgr => {
                self.on_unknown_message(id, tid, *ty, *version, segments)
            }
            (
                AnyMessage::Unknown {
                    ty,
                    version,
                    segments,
                    ..
                },
                Purpose::Mgr,
            ) if matches!(
                *ty,
                replwire::scrubmsgs::ty::SCRUB2 | replwire::ty::FORCE_RECOVERY
            ) =>
            {
                self.on_unknown_message(id, tid, *ty, *version, segments)
            }
            (_, Purpose::Mgr) => self.on_mgr_message(msg),
            (AnyMessage::MCommand(_) | AnyMessage::MMonCommand(_), _) if !self.is_control() => {
                self.forward_ctl(id, tid, msg)
            }
            (AnyMessage::MCommand(c), _) => self.on_tell(id, tid, c.clone()),
            (AnyMessage::MOSDDedupList(m), _) => self.on_dedup_list(id, tid, m.clone()),
            (AnyMessage::MMonCommand(c), _) => self.on_legacy_mon_command(id, tid, c.clone()),
            (AnyMessage::MOSDMap(m), _) => {
                self.log(format!(
                    "link {id}: MOSDMap from peer ({} inc, {} full, newest {}) ignored (mon is our map source)",
                    m.incremental_maps.len(),
                    m.maps.len(),
                    m.newest_map
                ));
            }
            (other, _) => self.log(format!(
                "link {id}: unhandled message type {:#x}, dropped",
                other.msg_type()
            )),
        }
    }

    // ---------------------------------------------------------------- mon events

    fn on_mon_event(&mut self, ev: MonEvent) {
        match ev {
            MonEvent::Authenticated {
                global_id,
                mon,
                method,
                ..
            } => {
                self.log(format!("mon session open: {mon} gid {global_id}"));
                self.set_session_method(method, global_id);
                self.refresh_keys();
                self.on_mon_session();
            }
            MonEvent::SessionLost(w) => {
                self.log(format!("mon session lost: {w}"));
                self.pending_version = None;
            }
            MonEvent::AuthFailed(w) => self.log(format!("mon auth failed: {w}")),
            MonEvent::MonMapUpdated { epoch } => self.log(format!("monmap epoch {epoch}")),
            MonEvent::OsdMap { map, msg, .. } => self.on_osdmap_event(map, &msg),
            MonEvent::Config(c) => {
                for e in self.conf.apply_mon(&c) {
                    self.logl(0, format!("WARNING mon config: {e}; ignored"));
                }
                self.publish_conf();
                self.conf_changed();
                self.cfg_seen = true;
                self.log(format!("mon config: {} options", c.len()));
                self.init_advance();
            }
            MonEvent::CommandReply { tid, r, rs, data } => self.on_mon_cmd_reply(tid, r, rs, data),
            // This daemon owns legacy commands; send-once client events cannot
            // complete or advance an OSD initialization command.
            MonEvent::CommandOnceReply { .. } | MonEvent::CommandOnceLost { .. } => {}

            MonEvent::VersionReply {
                handle,
                version,
                oldest,
            } => {
                if self.pending_version == Some(handle) {
                    self.pending_version = None;
                    if self.state == State::Preboot {
                        self.preboot(oldest as u32, version as u32);
                    }
                }
            }
            MonEvent::VersionFailed { handle } => {
                if self.pending_version == Some(handle) {
                    self.pending_version = None;
                }
            }
            MonEvent::KeysUpdated => {
                self.refresh_keys();
                self.init_advance();
            }
            MonEvent::Message { msg, .. } => self.on_mon_message(*msg),
            MonEvent::Diag(s) => self.log(format!("monc: {s}")),
        }
    }

    /// Send to the mon session (dropped when there is none; spec 2.2).
    pub(crate) fn send_mon(&mut self, m: impl Into<AnyMessage>) -> Option<u64> {
        #[cfg(test)]
        {
            if self.t.mon_send_unavailable {
                return None;
            }
            let m: AnyMessage = m.into();
            self.t.sent.push(m);
            Some(0)
        }
        #[cfg(not(test))]
        self.mc.send_message(m)
    }

    pub(crate) fn mon_up(&self) -> bool {
        #[cfg(test)]
        {
            true
        }
        #[cfg(not(test))]
        self.mc.is_connected()
    }

    pub(crate) fn mon_get_version(&mut self, what: &str) -> Option<u64> {
        #[cfg(test)]
        {
            let _ = what;
            self.t.version_requests += 1;
            Some(77)
        }
        #[cfg(not(test))]
        self.mc.get_version(what)
    }

    /// Subscribe at the mon. While ACTIVE the osdmap sub is standing (adr 0022): a one-shot request (map gap, PG
    /// waiting for an epoch, YOU_DIED, `get_latest_osdmap`) asks from `start` but keeps it standing, else the
    /// one-shot would replace the standing sub in the table and at the mon, and after its answer this OSD would get
    /// new epochs only through a random mon push or a heartbeat YOU_DIED (seconds; a primary marked down while
    /// alive then sends MOSDMarkMeDead late and the new primary waits for its read lease that long).
    pub(crate) fn mon_sub(&mut self, what: &str, start: u64, flags: u8) {
        let flags = if what == "osdmap" && self.state == State::Active {
            flags & !messages::SubItem::ONETIME
        } else {
            flags
        };
        #[cfg(test)]
        self.t.subs.push((what.to_owned(), start, flags));
        self.mc.subscribe(what, start, flags);
    }

    /// The mon session negotiated `method`: after NONE every authorizer of this daemon is a NONE authorizer with the gid
    /// the mon returned, and no rotating keys exist (auth-none spec 5.1).
    fn set_session_method(&mut self, method: u32, global_id: u64) {
        let payload = (method == cephx::modes::AUTH_NONE).then(|| {
            let name = cephx::none::EntityName {
                ty: ENTITY_OSD_BIT,
                id: self.id.whoami.to_string(),
            };
            cephx::none::none_authorizer(&name, global_id)
        });
        self.keys.set_none_authorizer(payload.clone());
        self.publish_none_authorizer(payload);
    }

    pub(crate) fn refresh_keys(&mut self) {
        if let Some(c) = self.mc.with_cephx(Clone::clone) {
            self.keys.set(c);
            self.publish_keys();
        }
    }

    /// Session (re)established: re-send state-bearing messages (spec 3.7).
    fn on_mon_session(&mut self) {
        match self.init {
            Init::WaitAuth => {
                self.init = Init::WaitKeys {
                    since: self.now,
                    attempts: 1,
                };
                self.init_advance();
                return;
            }
            Init::Done => {}
            _ => {
                self.init_advance();
                return;
            }
        }
        match self.state {
            State::Preboot => self.start_boot(),
            State::Booting => self.send_boot(),
            State::Active | State::WaitingForHealthy => {
                self.last_mon_report = self.now;
                self.send_alive_if_needed();
                self.hb_requeue_failures();
                self.pg_on_mon_session();
                self.send_beacon();
            }
            _ => {}
        }
        // map requests need nothing here: the MonClient replays the subscriptions on the new session
    }

    fn on_mon_message(&mut self, msg: AnyMessage) {
        if let AnyMessage::Unknown {
            ty,
            version,
            compat,
            ..
        } = &msg
            && let Err(e) = check_wire_compat(*ty, *version, *compat)
        {
            self.log(format!(
                "mon: incompatible service message type {ty}: {e}, dropped"
            ));
            return;
        }
        match msg {
            AnyMessage::MMgrMap(m) => self.on_mgrmap(&m),
            AnyMessage::MMonGetPurgedSnapsReply(r) => self.on_purged_snaps(r),
            AnyMessage::MOSDMarkMeDown(m) => {
                if !m.request_ack && self.state == State::Stopping {
                    self.log("mon acked mark-me-down");
                    self.finish_shutdown();
                }
            }
            AnyMessage::MMonSubscribeAck(_) | AnyMessage::MLogAck(_) => {}
            AnyMessage::Unknown {
                ty,
                version,
                segments,
                ..
            } if self.pg_on_mon_unknown(ty, version, &segments) => {}
            other => self.log(format!(
                "mon: unhandled message type {:#x}, dropped",
                other.msg_type()
            )),
        }
    }

    // ---------------------------------------------------------------- startup sequence (3.1)

    fn rotating_timeout(&self) -> (Duration, u32) {
        (
            Duration::from_secs(self.conf.u64("rotating_keys_bootstrap_timeout", 30)),
            self.conf.u64("max_rotating_auth_attempts", 10) as u32,
        )
    }

    pub(crate) fn init_advance(&mut self) {
        loop {
            match self.init {
                Init::WaitAuth | Init::Done => return,
                Init::WaitKeys { since, attempts } => {
                    if self.keys.have_rotating() {
                        self.log(if self.keys.none_authorizer().is_some() {
                            "auth none: no rotating keys needed"
                        } else {
                            "rotating keys ready"
                        });
                        self.init = Init::WaitConfig { since: self.now };
                        continue;
                    }
                    let (to, max) = self.rotating_timeout();
                    if self.now.saturating_sub(since) >= to {
                        self.logl(
                            0,
                            format!(
                                "WARNING TIMEOUT rotating service keys exceeded {:.3}s (attempt {}/{max})",
                                to.as_secs_f64(),
                                attempts + 1
                            ),
                        );
                        if attempts >= max {
                            self.fatal("unable to obtain rotating service keys (clock skew?)");
                            return;
                        }
                        self.init = Init::WaitKeys {
                            since: self.now,
                            attempts: attempts + 1,
                        };
                    }
                    return;
                }
                Init::WaitConfig { since } => {
                    // the first MConfig always arrives right after auth; do not wait forever
                    let waited = self.now.saturating_sub(since) >= Duration::from_secs(10);
                    if !self.cfg_seen && waited {
                        self.logl(
                            0,
                            "WARNING TIMEOUT first MConfig exceeded 10s (continuing without it)",
                        );
                    }
                    if self.cfg_seen || waited {
                        self.init = Init::CrushClass;
                        continue;
                    }
                    return;
                }
                Init::CrushClass => {
                    let class = self.id.crush_device_class.clone();
                    if !self.conf.bool("osd_class_update_on_start", true) || class.is_empty() {
                        self.init = Init::CrushLoc;
                        continue;
                    }
                    if self.init_cmd.is_none() {
                        let c = format!(
                            r#"{{"prefix":"osd crush set-device-class","class":{},"ids":["{}"]}}"#,
                            js(&class),
                            self.id.whoami
                        );
                        self.send_init_cmd(&c, InitCmd::Class);
                    }
                    self.warn_init_cmd();
                    return;
                }
                Init::CrushLoc => {
                    // The shard reports are the capacity of every core, needed by the boot either way:
                    // with the start-time CRUSH update they feed its weight, without it they still gate
                    // the boot (finishing init early left the OSD in the map as nothing the mon accepts).
                    if !self.workers_reported() {
                        return; // the crush weight is the capacity of ALL cores' shards: wait for their reports
                    }
                    if !self.conf.bool("osd_crush_update_on_start", true) {
                        self.init_finish();
                        continue;
                    }
                    if self.init_cmd.is_none() {
                        let c = self.crush_create_or_move_cmd();
                        self.log(format!("crush: {c}"));
                        self.send_init_cmd(&c, InitCmd::Loc);
                    }
                    self.warn_init_cmd();
                    return;
                }
            }
        }
    }

    /// First loud progress line for an init CRUSH command, then the repeat interval (NT-cs-restart-02).
    const CRUSH_WAIT_FIRST_WARN: Duration = Duration::from_secs(30);
    const CRUSH_WAIT_WARN_EVERY: Duration = Duration::from_secs(60);

    /// Send an init CRUSH command and record when, so a slow mon is visible (a `WARNING TIMEOUT` line,
    /// NT-cs-restart-02). The monc resends outstanding commands across a reconnect on its own, so this only
    /// times the wait, it never re-sends.
    fn send_init_cmd(&mut self, cmd: &str, kind: InitCmd) {
        let t = self.mc.send_command(cmd, Vec::new());
        self.init_cmd = Some((t, kind));
        self.init_cmd_wait = Some((self.now, self.now + Self::CRUSH_WAIT_FIRST_WARN));
    }

    /// One loud line after [`Self::CRUSH_WAIT_FIRST_WARN`], then every [`Self::CRUSH_WAIT_WARN_EVERY`], while the
    /// outstanding init command waits for the mon (`WARNING TIMEOUT <cmd> exceeded <n>s (still waiting for the mon)`).
    fn warn_init_cmd(&mut self) {
        let Some((_, kind)) = self.init_cmd else {
            return;
        };
        let Some((since, next_warn)) = self.init_cmd_wait else {
            return;
        };
        if self.now < next_warn {
            return;
        }
        let waited = self.now.saturating_sub(since).as_secs();
        self.logl(
            0,
            format!(
                "WARNING TIMEOUT {} exceeded {}s (still waiting for the mon)",
                kind.name(),
                waited
            ),
        );
        self.init_cmd_wait = Some((since, self.now + Self::CRUSH_WAIT_WARN_EVERY));
    }

    fn crush_create_or_move_cmd(&self) -> String {
        let w = self.conf.f64("osd_crush_initial_weight", -1.0);
        let weight = if w >= 0.0 {
            w
        } else {
            let tib = self.statfs_all().total as f64 / (1u64 << 40) as f64;
            tib.max(0.00001)
        };
        let args: Vec<String> = self
            .crush_loc
            .iter()
            .map(|(t, n)| js(&format!("{t}={n}")))
            .collect();
        format!(
            r#"{{"prefix":"osd crush create-or-move","id":{},"weight":{:.4},"args":[{}]}}"#,
            self.id.whoami,
            weight,
            args.join(",")
        )
    }

    fn on_mon_cmd_reply(&mut self, tid: u64, r: i32, rs: String, data: Vec<u8>) {
        if self.pg_on_peer_meta(tid, r, &data) {
            return;
        }
        let Some((t, kind)) = self.init_cmd else {
            return;
        };
        if t != tid {
            return;
        }
        self.init_cmd = None;
        self.init_cmd_wait = None;
        // errno of the mon's command reply, negated (osd-lifecycle 1.4): -EBUSY = "already has a class",
        // -ENOENT = this OSD is not in the map yet, `osd create` makes it
        const EBUSY: i32 = -opwire::errno::EBUSY;
        const ENOENT: i32 = -opwire::errno::ENOENT;
        match (kind, r) {
            (InitCmd::Class, 0) | (InitCmd::Class, EBUSY) => {
                self.log(format!("device class set ({r}: {rs})"));
                self.init = Init::CrushLoc;
                self.init_advance();
            }
            (InitCmd::Loc, 0) => {
                self.log(format!("crush location set ({rs})"));
                self.init_finish();
            }
            (InitCmd::Class | InitCmd::Loc, ENOENT) => {
                let c = format!(
                    r#"{{"prefix":"osd create","id":{},"uuid":"{}"}}"#,
                    self.id.whoami, self.id.osd_fsid
                );
                self.send_init_cmd(&c, InitCmd::Create);
            }
            (InitCmd::Create, 0) => self.init_advance(),
            (k, r) => self.fatal(&format!("mon command {k:?} failed: {r} {rs}")),
        }
    }

    fn init_finish(&mut self) {
        self.init = Init::Done;
        self.mon_sub("osd_pg_creates", 0, 0);
        self.mon_sub("mgrmap", 0, 0);
        self.bind_epoch = self.epoch();
        self.hb.next_round = Some(self.now + Duration::from_secs(1));
        self.log(format!("init done; bind_epoch {}", self.bind_epoch));
        self.start_boot();
    }

    // ---------------------------------------------------------------- 1 s tick

    /// Forward-only wall re-anchor (adr 0064 am.): see [`reanchored_origin`].
    pub(crate) fn reanchor_wall(&mut self) {
        if !self.cfg.wall_from_clock {
            return;
        }
        // The mon session's cephx clock (ticket renewal, rotating-key refresh) follows the system clock in both
        // directions, as the classic one does; only the OSD's own object/stat stamps are forward-only. Outbound
        // authorizers need no clock: cached tickets stay usable until the peer drops the sealing key.
        let sys_ns = (self.sys_clock)();
        if self.is_control() {
            self.mc
                .set_wall_origin(Duration::from_nanos(sys_ns).saturating_sub(self.now));
        }
        let o = reanchored_origin(
            self.wall_origin_ns,
            self.now.as_nanos() as u64,
            sys_ns,
            REANCHOR_NS,
        );
        if o != self.wall_origin_ns {
            self.logl(
                1,
                format!(
                    "wall clock re-anchored forward by {} ms",
                    (o - self.wall_origin_ns) / 1_000_000
                ),
            );
            self.wall_origin_ns = o;
            self.pg.set.set_wall_base(o);
        }
    }

    /// LAB ONLY: this core's wprof stage sums since the last tick (ms/spans/allocs), one log line when any span ran.
    #[cfg(all(feature = "wprof-on", not(feature = "kernel-probe")))]
    fn wprof_log(&mut self) {
        let a = wprof::take();
        if a.iter().any(|s| s.1 > 0) {
            let v: Vec<String> = a
                .iter()
                .zip(wprof::NAMES)
                .filter(|(s, _)| s.1 > 0)
                .map(|(s, n)| format!("{n}={:.1}ms/{}/{}", s.0 / 1e6, s.1, s.2))
                .collect();
            self.log(format!("wprof 1s: {}", v.join(" ")));
        }
        let l = wprof::take_lat();
        if l.iter().any(|s| s.1 > 0) {
            let v: Vec<String> = l
                .iter()
                .zip(wprof::LNAMES)
                .filter(|(s, _)| s.1 > 0)
                .map(|(s, n)| format!("{n}={:.2}ms/{}", s.0 as f64 / 1e6 / s.1 as f64, s.1))
                .collect();
            self.log(format!("wprof lat 1s: {}", v.join(" ")));
        }
    }

    /// A full map the mon sent does not decode: asking again returns the same bytes, and up at a stale epoch the OSD
    /// would hold its PGs (classic aborts). Mark down and exit 1 so the PGs move and the operator sees the failure.
    fn stop_on_undecodable_osdmap(&mut self, (e, err): (u32, String)) {
        self.logl(
            0,
            format!("FATAL: osdmap {e} from the mon does not decode ({err}); marking osd down and exiting"),
        );
        self.fail_code = Some(1);
        self.begin_shutdown(true);
    }

    fn tick(&mut self) {
        let now = self.now;
        if let Some(l) = self.live {
            l.beat(self.cl.spec.id);
            if self.is_control() {
                l.set_limits(
                    self.conf.f64("osd_op_thread_timeout", 15.0),
                    self.conf.f64("osd_op_thread_suicide_timeout", 150.0),
                );
            }
        }
        #[cfg(all(feature = "wprof-on", not(feature = "kernel-probe")))]
        self.wprof_log();
        self.reanchor_wall();
        self.refresh_obs_conf();
        self.slow_ops_note();
        self.mig_tick();
        self.rdma_notice_tick();
        // control core: its counter sample for the admin dumps (workers ship theirs with the stats below)
        self.sample_counters();
        if !self.is_control() {
            // worker core: its PGs and its numbers for core 0
            self.pg_tick();
            self.push_stats();
            return;
        }
        if self.init != Init::Done {
            self.init_advance();
            return;
        }
        if let Some(u) = self.mc.undecodable_osdmap().cloned()
            && self.state != State::Stopping
        {
            self.stop_on_undecodable_osdmap(u);
            return;
        }
        self.markdown_log.retain(|t| {
            now.saturating_sub(*t)
                < Duration::from_secs(self.conf.u64("osd_max_markdown_period", 600))
        });
        self.pg_tick();
        match self.state {
            State::Active | State::WaitingForHealthy => {
                self.heartbeat_check();
                let report_due = now.saturating_sub(self.last_mon_report)
                    >= Duration::from_secs(self.conf.u64("osd_mon_report_interval", 5));
                // every tick, not only every report interval: a fast writer crosses nearfull -> hard NoSpace in
                // seconds, and a new fullness state must reach the mon at once (resends stay on the report interval)
                self.update_local_failsafe();
                self.pg_sync_num_pgs();
                self.check_fullness(report_due);
                // the mon ignores failure reports from an OSD that is down (osd-lifecycle 7.2): report only while up
                if report_due {
                    self.last_mon_report = now;
                    if self.state == State::Active {
                        self.flush_failures();
                    }
                }
            }
            _ => {}
        }
        match self.state {
            State::Active => {
                let iv = Duration::from_secs(self.conf.u64("osd_beacon_report_interval", 300));
                if self.last_beacon.is_none_or(|t| now.saturating_sub(t) > iv) {
                    self.send_beacon();
                }
                self.purged_snaps_scrub_tick();
                if self.hb.peers.is_empty()
                    && now.saturating_sub(self.last_lonely)
                        >= Duration::from_secs(self.conf.u64("osd_mon_heartbeat_interval", 30))
                {
                    self.last_lonely = now;
                    let e = u64::from(self.epoch()) + 1;
                    self.mon_sub("osdmap", e, 0);
                }
            }
            State::WaitingForHealthy if self.is_healthy() => self.start_boot(),
            State::Booting
                if now.saturating_sub(self.last_boot)
                    >= Duration::from_secs(self.conf.u64("osd_mon_heartbeat_interval", 30)) =>
            {
                // no answer to MOSDBoot: a duplicate is answered with maps only (spec 3.3)
                self.send_boot();
            }
            State::Preboot
                if self.pending_version.is_none() && !self.preboot_parked && self.mon_up() =>
            {
                // the probe was refused while the session was up: ask again (a parked preboot waits for its map)
                self.start_boot()
            }
            _ => {}
        }
    }

    pub(crate) fn is_healthy(&self) -> bool {
        if self.live.is_some_and(|l| l.unhealthy()) {
            return false;
        }
        if self.markdown_log.is_empty() {
            return true;
        }
        let total = self.hb.peers.len();
        if total == 0 {
            return true;
        }
        let ok = self
            .hb
            .peers
            .values()
            .filter(|p| p.is_healthy(self.now))
            .count();
        ok as f64 >= self.conf.f64("osd_heartbeat_min_healthy_ratio", 0.33) * total as f64
    }

    // ---------------------------------------------------------------- boot state machine (3.2)

    pub(crate) fn start_boot(&mut self) {
        if self.state == State::Stopping || self.init != Init::Done {
            return;
        }
        if !self.is_healthy() {
            self.state = State::WaitingForHealthy;
            let e = u64::from(self.epoch()) + 1;
            self.mon_sub("osdmap", e, messages::SubItem::ONETIME);
            return;
        }
        self.state = State::Preboot;
        self.preboot_parked = false;
        // no mon session (None): `on_mon_session` runs start_boot again
        self.pending_version = self.mon_get_version("osdmap");
    }

    pub(crate) fn preboot(&mut self, oldest: u32, newest: u32) {
        let epoch = self.epoch();
        let mut why = "";
        let mut boot = false;
        'chk: {
            let Some(map) = self.map.as_ref() else {
                why = "waiting for initial osdmap";
                break 'chk;
            };
            let st = map.raw_state(self.id.whoami);
            if st & osd_state::DESTROYED != 0 {
                if epoch > newest.saturating_sub(1) {
                    self.log("osd is destroyed in the newest map, exiting");
                    self.done = Some(0);
                    return;
                }
                why = "osd destroyed, fetching newest map";
                break 'chk;
            }
            // global, per-OSD, or `osd set-group noup` on a CRUSH bucket of our location / our device class
            if map.is_noup(self.id.whoami) {
                why = "noup set";
                break 'chk;
            }
            if map.flags & map_flags::SORTBITWISE == 0 {
                why = "sortbitwise not set";
                break 'chk;
            }
            if self.fullness_differs() {
                self.send_full();
                why = "fullness update sent";
                break 'chk;
            }
            if map.require_osd_release >= release::OCTOPUS
                && self.sb.purged_snaps_last < self.sb.current_epoch
            {
                self.request_purged_snaps();
                why = "purged snaps catch-up";
                break 'chk;
            }
            let max_msg = self.conf.u64("osd_map_message_max", 40) as u32;
            if epoch >= oldest.saturating_sub(1) && epoch + max_msg > newest {
                boot = true;
            } else {
                why = "catching up on maps";
            }
        }
        if boot {
            self.send_boot();
            return;
        }
        self.preboot_parked = true;
        self.log(format!(
            "preboot: {why} (have {epoch}, mon {oldest}..{newest})"
        ));
        if epoch + 1 >= oldest {
            self.mon_sub("osdmap", u64::from(epoch) + 1, messages::SubItem::ONETIME);
        } else {
            self.mon_sub("osdmap", u64::from(oldest) - 1, messages::SubItem::ONETIME);
        }
    }

    fn request_purged_snaps(&mut self) {
        let m = messages::MMonGetPurgedSnaps {
            version: 0,
            start: self.sb.purged_snaps_last + 1,
            last: self.sb.current_epoch + 1,
        };
        self.send_mon(m);
    }

    fn on_purged_snaps(&mut self, r: messages::MMonGetPurgedSnapsReply) {
        if self.state != State::Preboot || r.last < self.sb.purged_snaps_last {
            return;
        }
        self.sb.purged_snaps_last = r.last;
        if let Err(e) = self
            .store
            .as_mut()
            .map_or(Ok(()), |s| s.store_superblock(&self.sb))
        {
            return self.fatal(&format!("store superblock: {e}"));
        }
        if r.last < self.sb.current_epoch {
            self.request_purged_snaps();
        } else {
            self.start_boot();
        }
    }

    pub(crate) fn send_boot(&mut self) {
        let Some(map) = self.map.as_ref() else {
            return;
        };
        let admission = crate::release::boot_admission_warning(map.require_osd_release);
        let m = messages::MOSDBoot {
            version: u64::from(map.epoch),
            sb: self.sb.clone(),
            hb_back_addrs: self.hb_back_addrs.clone(),
            cluster_addrs: self.cluster_addrs.clone(),
            boot_epoch: self.boot_epoch,
            hb_front_addrs: self.hb_front_addrs.clone(),
            metadata: self.boot_metadata(),
            // the dedup listing request (croit fork, adr 0593-dedup-deep-scrub-reformat): advertised only when served
            osd_features: crate::release::CLAIMED_FEATURES
                | if self.conf.bool("flashstore_dedup_list", false) {
                    messages::FEATUREMASK_OSD_DEDUP_LIST
                } else {
                    0
                },
        };
        if let Some(w) = admission {
            self.logl(0, w);
        }
        if self.send_mon(m).is_some() {
            self.log(format!(
                "sent MOSDBoot (map {}, boot_epoch {})",
                self.epoch(),
                self.boot_epoch
            ));
        }
        self.last_boot = self.now;
        self.state = State::Booting;
    }

    // ---------------------------------------------------------------- map ingestion (3.5)

    /// `new` = the map at the event's epoch (NOT the MonClient's newest: several MOSDMaps may have been handled before
    /// their events are drained; persisting the newest under an older event's epoch, and then skipping the later events
    /// as old, left holes in the stored history = PGs removed at the next boot).
    pub(crate) fn on_osdmap_event(&mut self, new: Arc<OsdMap>, msg: &MOSDMap) {
        if msg.fsid != self.id.cluster_fsid {
            self.log("MOSDMap with foreign fsid ignored");
            return;
        }
        let epoch = new.epoch;
        let prev_epoch = self.epoch();
        if epoch <= prev_epoch {
            return;
        }
        // fail closed before persisting or acting on a map from a release we do not implement
        if let Err(e) = crate::release::check_map(&new) {
            return self.refuse(&e);
        }
        self.perf.map_messages += 1;
        self.perf.map_message_epochs += u64::from(epoch - prev_epoch);
        // persist before acting (spec 3.5 step 6)
        let mut blobs: Vec<(u32, MapKind, Vec<u8>)> = Vec::new();
        let mut stored: Vec<u32> = Vec::new();
        for (e, b) in &msg.incremental_maps {
            if *e > prev_epoch && *e <= epoch {
                blobs.push((*e, MapKind::Inc, b.clone()));
                stored.push(*e);
            }
        }
        for (e, b) in &msg.maps {
            if *e > prev_epoch && *e <= epoch {
                blobs.push((*e, MapKind::Full, b.clone()));
                stored.push(*e);
            }
        }
        // a gap is only legitimate when the mon trimmed those epochs (classic skip_maps); loud either way: PG loading
        // must then work across it (`pg_load_maps`, peering `start_map`)
        if prev_epoch > 0
            && let Some(gap) = (prev_epoch + 1..epoch)
                .find(|e| !msg.incremental_maps.contains_key(e) && !msg.maps.contains_key(e))
        {
            self.logl(
                0,
                format!(
                    "osdmap: epochs from {gap} to before {epoch} not received (had {prev_epoch}, mon trim bound {}): \
                     the stored map history has a gap",
                    msg.cluster_osdmap_trim_lower_bound
                ),
            );
        }
        let mut full_blob: Option<Vec<u8>> = None;
        if !msg.maps.contains_key(&epoch) {
            match new.encode_full() {
                Ok(b) => {
                    if self.multi() {
                        full_blob = Some(b.clone());
                    }
                    blobs.push((epoch, MapKind::Full, b))
                }
                Err(e) => return self.fatal(&format!("re-encode osdmap {epoch}: {e}")),
            }
        }
        let first_new = stored.iter().copied().min().unwrap_or(epoch);
        for e in stored {
            add_epoch(&mut self.sb.mapc, e);
        }
        add_epoch(&mut self.sb.mapc, epoch);
        self.sb.current_epoch = epoch;
        self.sb.cluster_osdmap_trim_lower_bound = self
            .sb
            .cluster_osdmap_trim_lower_bound
            .max(msg.cluster_osdmap_trim_lower_bound);
        // required past-interval bounds use the mon's trim floor (peering.md 3.8)
        self.pg
            .set
            .set_cluster_trim(self.sb.cluster_osdmap_trim_lower_bound);
        if self.sb.purged_snaps_last == first_new.saturating_sub(1) {
            self.sb.purged_snaps_last = epoch;
        }
        if self.boot_epoch != 0 && self.boot_epoch >= self.sb.mounted {
            self.sb.mounted = self.boot_epoch;
            self.sb.clean_thru = epoch;
        }
        if let Err(e) = self
            .store
            .as_mut()
            .map_or(Ok(()), |s| s.commit_maps(&blobs, &self.sb))
        {
            return self.fatal(&format!("persist maps: {e}"));
        }
        self.trim_stored_maps();
        self.mc.subscription_got("osdmap", u64::from(epoch));
        // the map at `prev_epoch`, which the PG side needs for the incremental chain: the one we replace here
        let old = self.map.replace(new.clone());
        self.after_map(old.clone(), msg);
        let chain = self.pg_decode_chain(prev_epoch, old.clone(), new, msg);
        self.publish_map(prev_epoch, old.clone(), msg, full_blob, &chain);
        self.pg_maps(old, chain);
    }

    fn after_map(&mut self, old: Option<Arc<OsdMap>>, msg: &MOSDMap) {
        let Some(map) = self.map.clone() else { return };
        // a peer that left the map takes its dial warnings with it: the set stays bounded by the peers of the map
        self.dial_warned
            .retain(|w| w.purpose().osd().is_none_or(|o| map.exists(o)));
        let me = self.id.whoami;
        let epoch = map.epoch;
        if let Some(old) = &old {
            for o in 0..old.max_osd {
                if o != me && old.is_up(o) && !map.is_up(o) {
                    self.hb_peer_down(o);
                }
            }
        }
        if self.state != State::Stopping
            && (self.state == State::Active || epoch >= msg.newest_map)
            && let Some(why) = self.identity_gone(&map)
        {
            let m = format!("osd.{me}: {why}, exiting");
            self.logl(0, &m);
            self.clog(messages::clog::WARN, &m);
            return self.begin_shutdown(false);
        }
        let st = map.raw_state(me);
        let up = map.is_up(me);
        let addrs_ok = up && self.all_addrs_match(&map);
        let up_from = map.osd_info.get(me as usize).map_or(0, |i| i.up_from);
        if self.up_epoch == 0 && up && legacy_eq(&map.client_addrs[me as usize], &self.public_addrs)
        {
            self.up_epoch = up_from;
            if self.boot_epoch == 0 {
                self.boot_epoch = up_from;
            }
        }
        // noup changed (any source, either direction) while our boot is in flight: the mon may have dropped the boot
        // (sent while noup was being set), so boot again (classic)
        if self.state == State::Booting
            && old
                .as_ref()
                .is_some_and(|o| o.is_noup(me) != map.is_noup(me))
        {
            self.do_restart = true;
        }
        if self.state == State::Booting && addrs_ok && self.bind_epoch < up_from {
            self.state = State::Active;
            self.do_restart = false;
            // level 0: the unit manager (sd_notify READY=1) keys on this line, `debug_osd` must not filter it
            self.logl(
                0,
                format!("osd.{me} {ACTIVE_MARKER} (up_from {up_from}, map {epoch})"),
            );
            if self.boot_epoch != 0 && self.boot_epoch >= self.sb.mounted {
                self.sb.mounted = self.boot_epoch;
                self.sb.clean_thru = epoch;
                if let Err(e) = self
                    .store
                    .as_mut()
                    .map_or(Ok(()), |s| s.store_superblock(&self.sb))
                {
                    return self.fatal(&format!("store superblock: {e}"));
                }
            }
            self.hb_cancel_all_failures();
            // standing osdmap subscription for robustness (spec 2.4 / U3)
            self.mon_sub("osdmap", u64::from(epoch) + 1, 0);
            self.send_beacon();
            self.send_alive_if_needed();
        } else if self.state == State::Active {
            if st & osd_state::STOP != 0 {
                self.log("stop flag set in the map, shutting down");
                return self.begin_shutdown(false);
            }
            if !up || !addrs_ok {
                return self.wrongly_marked_down(&map, up);
            }
        } else if st & osd_state::STOP != 0 {
            return self.begin_shutdown(false);
        }
        if self.state == State::Stopping && !up {
            self.finish_shutdown();
            return;
        }
        if self.state == State::Active || self.state == State::WaitingForHealthy {
            self.hb_update_peers();
            self.send_alive_if_needed();
        }
        if msg.newest_map > epoch {
            // MonClient already re-armed the subscription
        } else if self.state == State::Preboot {
            self.preboot(
                msg.cluster_osdmap_trim_lower_bound,
                msg.newest_map.max(epoch),
            );
        } else if self.do_restart {
            self.do_restart = false;
            self.start_boot();
        }
    }

    /// Purged / re-created id (classic: "map says i do not exist", plus the uuid of `osd new`): this daemon is no
    /// longer the OSD of that id. Zero map uuid = slot without a claim, ignored. Exit is clean (code 0, no restart).
    fn identity_gone(&self, map: &OsdMap) -> Option<String> {
        let me = self.id.whoami;
        if !map.exists(me) {
            return Some("map says i do not exist (purged)".into());
        }
        let u = map.osd_uuid.get(me as usize).copied().unwrap_or_default();
        if u != Uuid::default() && u != self.id.osd_fsid {
            return Some(format!(
                "map uuid {u} for my id differs from mine {} (id re-created)",
                self.id.osd_fsid
            ));
        }
        None
    }

    /// Release/feature policy violated: log loudly, exit with `EXIT_REFUSED` (unit: no restart).
    fn refuse(&mut self, why: &str) {
        self.logl(0, format!("FATAL: {why}"));
        self.fail_code = Some(crate::release::EXIT_REFUSED);
        self.begin_shutdown(false);
    }

    fn all_addrs_match(&self, map: &OsdMap) -> bool {
        let me = self.id.whoami as usize;
        let get = |v: &Vec<EntityAddrVec>| v.get(me).cloned().unwrap_or_default();
        legacy_eq(&get(&map.client_addrs), &self.public_addrs)
            && legacy_eq(&get(&map.cluster_addrs), &self.cluster_addrs)
            && legacy_eq(&get(&map.hb_front_addrs), &self.hb_front_addrs)
            && legacy_eq(&get(&map.hb_back_addrs), &self.hb_back_addrs)
    }

    /// The addr kinds the map disagrees with us on, each with the map's and our addrvec (spec 7.4: log which one).
    fn addr_mismatch(&self, map: &OsdMap) -> String {
        let me = self.id.whoami as usize;
        let get = |v: &Vec<EntityAddrVec>| v.get(me).cloned().unwrap_or_default();
        let mut out: Vec<String> = Vec::new();
        for (kind, map_addrs, mine) in [
            ("public", get(&map.client_addrs), &self.public_addrs),
            ("cluster", get(&map.cluster_addrs), &self.cluster_addrs),
            ("hb_front", get(&map.hb_front_addrs), &self.hb_front_addrs),
            ("hb_back", get(&map.hb_back_addrs), &self.hb_back_addrs),
        ] {
            if !legacy_eq(&map_addrs, mine) {
                out.push(format!(
                    "{kind}: map {} mine {}",
                    addrs_str(&map_addrs),
                    addrs_str(mine)
                ));
            }
        }
        out.join(", ")
    }

    // ---------------------------------------------------------------- wrongly marked down (7.4)

    fn wrongly_marked_down(&mut self, map: &OsdMap, up: bool) {
        let me = self.id.whoami;
        let diff = self.addr_mismatch(map);
        let msg = if !up {
            format!("Monitor daemon marked osd.{me} down, but it is still running")
        } else {
            format!("osd.{me}: map shows different addresses, restarting boot ({diff})")
        };
        self.log(&msg);
        self.clog(messages::clog::WARN, &msg);
        if !up && !diff.is_empty() {
            self.log(format!("osd.{me}: map addresses differ ({diff})"));
        }
        if map.require_osd_release >= release::OCTOPUS && !up {
            let m = messages::MOSDMarkMeDead {
                version: u64::from(map.epoch),
                fsid: self.id.cluster_fsid,
                target_osd: me,
                epoch: map.epoch,
            };
            self.send_mon(m);
        }
        self.up_epoch = 0;
        self.bind_epoch = map.epoch;
        self.markdown_log.push(self.now);
        if self.markdown_log.len() as u64 > self.conf.u64("osd_max_markdown_count", 5) {
            self.log("marked down too often, shutting down");
            return self.begin_shutdown(false);
        }
        self.state = State::WaitingForHealthy;
        self.hb_drop_all();
        self.rebind();
        // fresh peers (no PG peers): the health gate waits until enough of them answer on back and front
        self.hb_update_peers();
        self.start_boot();
        self.mon_sub(
            "osdmap",
            u64::from(map.epoch) + 1,
            messages::SubItem::ONETIME,
        );
    }

    /// New nonce for the cluster + heartbeat messengers (and hence new addresses). The public
    /// messenger keeps its identity (spec 7.4). Every core takes the new identity: a peer connection lands on any core,
    /// which checks the address the peer dialled against its own (a stale worker refused the new nonce for ever).
    fn rebind(&mut self) {
        let nonce = (self.rand() as u32) | 1;
        let epoch = self.bind_epoch;
        self.rebind_epoch = self.rebind_epoch.max(epoch);
        if self.multi() {
            self.xbcast(|| XMsg::Rebind { nonce, epoch });
        }
        self.set_nonce(nonce);
        self.log(format!(
            "rebound cluster/hb with new nonce {nonce}: cluster {}",
            addrs_str(&self.cluster_addrs)
        ));
    }

    /// Cluster + heartbeat identity with `nonce`; links of the old identity are closed.
    pub(crate) fn set_nonce(&mut self, nonce: u32) {
        self.cluster_addrs = mk_addr(&self.cfg.cluster_ips, self.cfg.cluster_port, nonce);
        self.hb_front_addrs = mk_addr(&self.cfg.public_ips, self.cfg.hb_front_port, nonce);
        self.hb_back_addrs = mk_addr(&self.cfg.cluster_ips, self.cfg.hb_back_port, nonce);
        self.msgr[MsgrId::Cluster as usize].cfg.addrs = self.cluster_addrs.clone();
        for (m, a) in [
            (MsgrId::HbFrontSrv, &self.hb_front_addrs),
            (MsgrId::HbFrontCli, &self.hb_front_addrs),
            (MsgrId::HbBackSrv, &self.hb_back_addrs),
            (MsgrId::HbBackCli, &self.hb_back_addrs),
        ] {
            self.msgr[m as usize].cfg.addrs = a.clone();
        }
        // existing accepted hb/cluster links are stale now
        let stale: Vec<u64> = self
            .links
            .iter()
            .filter(|(_, l)| l.msgr != MsgrId::Public)
            .map(|(i, _)| *i)
            .collect();
        for i in stale {
            self.close_link(i);
        }
    }

    // ---------------------------------------------------------------- up_thru / beacon / full

    /// PG peering asks for `up_thru >= epoch` (spec 4.2).
    pub fn queue_want_up_thru(&mut self, epoch: u32) {
        self.want_up_thru_inner(epoch);
        self.pump();
    }

    pub(crate) fn want_up_thru_inner(&mut self, epoch: u32) {
        if epoch > self.want_up_thru {
            self.want_up_thru = epoch;
        }
        self.send_alive_if_needed();
    }

    pub(crate) fn send_alive_if_needed(&mut self) {
        let Some(map) = &self.map else { return };
        if self.state != State::Active || self.want_up_thru == 0 {
            return;
        }
        let cur = map
            .osd_info
            .get(self.id.whoami as usize)
            .map_or(0, |i| i.up_thru);
        if cur >= self.want_up_thru {
            return;
        }
        let m = messages::MOSDAlive {
            // ALWAYS our map epoch (classic, osd-lifecycle 4.2): the mon parks a PaxosServiceMessage whose version is
            // above its committed epoch (`is_readable` -> `wait_for_readable`) and sets up_thru = version. A want above
            // our epoch (split gate nudge) is fine: up_thru < want makes the mon propose a map.
            version: u64::from(map.epoch),
            want: self.want_up_thru,
        };
        self.send_mon(m);
    }

    pub(crate) fn send_beacon(&mut self) {
        if self.state != State::Active {
            return;
        }
        if self.multi() && !self.workers_reported() {
            return; // the worker cores own PGs we know nothing about yet: their epochs bound the trim
        }
        // classic: the values are the ones of the latest collection; ours collects right now (a mon without mgr
        // would otherwise never trim)
        let (lce, pgs) = self.pg_collect();
        self.last_collect_epoch = lce;
        self.last_collect_pgs = pgs;
        let epoch = self.epoch();
        let m = messages::MOSDBeacon {
            version: u64::from(epoch),
            pgs: self.last_collect_pgs.clone(),
            min_last_epoch_clean: self.last_collect_epoch,
            last_purged_snaps_scrub: self.sb.last_purged_snaps_scrub,
            osd_beacon_report_interval: self.conf.u64("osd_beacon_report_interval", 300) as i32,
        };
        if self.send_mon(m).is_some() {
            self.last_beacon = Some(self.now);
            self.log(format!("sent MOSDBeacon (epoch {epoch})"));
        }
    }

    /// `osd_failsafe_full_ratio`, also in the percent spelling (`97` = 0.97, spec osd-lifecycle 4.4): one helper for
    /// the map thresholds and the local failsafe gate, which must agree on the fill they call full.
    fn failsafe_full_ratio(&self) -> f64 {
        crate::config::ratio_or_percent(self.conf.f64("osd_failsafe_full_ratio", 0.97))
    }

    /// The map's (nearfull, backfillfull, full) ratios, each raised to at least the previous one; a map with any of
    /// them unset (<= 0) puts all three on the failsafe ratio (osd-lifecycle 4.4). `None` without a map.
    fn full_thresholds(&self) -> Option<(f64, f64, f64)> {
        let map = self.map.as_ref()?;
        let nf = f64::from(map.nearfull_ratio);
        let bf = f64::from(map.backfillfull_ratio).max(nf);
        let fl = f64::from(map.full_ratio).max(bf);
        if nf <= 0.0 || bf <= 0.0 || fl <= 0.0 {
            let fs = self.failsafe_full_ratio().max(fl);
            return Some((fs, fs, fs));
        }
        Some((nf, bf, fl))
    }

    /// Bytes the held backfill reservations still expect, per core (index = core; this core's sampled live, the
    /// others' from their last report).
    fn backfill_held_cores(&self) -> Vec<u64> {
        let me = self.cl.spec.id;
        (0..self.cl.spec.n)
            .map(|c| {
                if c == me {
                    self.pg.set.backfill_held(&self.pg.store)
                } else {
                    self.cl.stats[c].as_ref().map_or(0, |s| s.bf_held)
                }
            })
            .collect()
    }

    /// Fullness bits we compute vs the ones in the map: FULL / BACKFILLFULL on the fill adjusted by the held backfill
    /// reservations, NEARFULL on the physical fill (osd-lifecycle 4.4).
    fn local_fullness(&self) -> u32 {
        let Some((nf, bf, fl)) = self.full_thresholds() else {
            return 0;
        };
        let s = self.statfs_all();
        let Some(pratio) = fill(s.total, s.available) else {
            return 0;
        };
        let held: u64 = self.backfill_held_cores().iter().sum();
        let ratio = pratio + held as f64 / s.total as f64;
        if ratio > fl {
            osd_state::FULL
        } else if ratio > bf {
            osd_state::BACKFILLFULL
        } else if pratio > nf {
            osd_state::NEARFULL
        } else {
            0
        }
    }

    /// Physical fill above `max(osd_failsafe_full_ratio, full_ratio)` (osd-lifecycle 4.4): client writes are refused
    /// locally (client-ops 5.4 rule 12), not reported as a map flag.
    ///
    /// Each state change emits `local failsafe full transition {JSON}` at log level 0. The versioned
    /// record contains the exact aggregate/local inputs used for admission, pre-clamp availability,
    /// thresholds, fullest core, and every core's last sample (including missing reports).
    /// `sample_age_ms` includes time in the cross-core queue; worker clocks share the driver's
    /// monotonic origin. `cores[].shards` carries actual store-shard ids and capacity/metadata
    /// pressure, rather than attributing a core aggregate to each owned shard. Worker detail is
    /// cached with its capacity sample; local detail is read synchronously on the transition.
    /// The failsafe transition JSON is constructed only on a state change. Shard snapshots and
    /// growth-failure reporting use the periodic core reports.
    pub(crate) fn update_local_failsafe(&mut self) {
        let snapshot = self.statfs_snapshot();
        let local_shards = self.pg.store.space_shards();
        self.report_meta_growth_failures(self.cl.spec.id, self.now, &local_shards);
        let ratio = fill(snapshot.aggregate.total, snapshot.aggregate.available);
        // classic also takes the percent spelling (`97` = 0.97)
        let configured = self.failsafe_full_ratio();
        let map_full = self.map.as_ref().map(|m| f64::from(m.full_ratio));
        let threshold = map_full.map(|f| configured.max(f));
        let fs = ratio.zip(threshold).is_some_and(|(r, t)| r > t);
        // backfillfull (or full): replicas refuse / withdraw backfill (classic `try_reserve_recovery_space`, `do_scan`)
        let bf = self.local_fullness() & (osd_state::BACKFILLFULL | osd_state::FULL) != 0;
        self.push_local_full(&snapshot.aggregate, fs);
        if bf != self.pg.backfillfull {
            self.pg.backfillfull = bf;
            self.logl(
                0,
                format!("local backfillfull transition: {bf} (fill ratio {ratio:?}), replicas refuse backfill while true"),
            );
        }
        if fs != self.pg.failsafe {
            self.pg.failsafe = fs;
            let diagnostic = self.failsafe_diagnostic(
                &snapshot,
                &local_shards,
                fs,
                configured,
                map_full,
                threshold,
            );
            self.logl(0, format!("local failsafe full transition {diagnostic}"));
        }
    }

    /// Hand every core its fill view for backfill reservation / scan judgement: `used` = physical use plus the held
    /// backfill bytes of the OTHER cores (each core adds its own live sum, `PgSet::backfill_held`); workers get it only
    /// on change.
    fn push_local_full(&mut self, a: &messages::StoreStatfs, failsafe: bool) {
        let held = self.backfill_held_cores();
        let all: u64 = held.iter().sum();
        let (total, backfill_limit) = match self.full_thresholds() {
            Some((_, bf, _)) => (a.total, (a.total as f64 * bf) as u64),
            None => (0, 0),
        };
        let physical = a.total.saturating_sub(a.available);
        let me = self.cl.spec.id;
        for (core, own) in held.into_iter().enumerate() {
            let lf = peering::LocalFull {
                total,
                used: physical.saturating_add(all - own),
                backfill_limit,
                failsafe,
            };
            if core == me {
                self.pg.set.set_local_full(lf);
            } else if self.cl.local_full_sent[core] != Some(lf) {
                self.cl.local_full_sent[core] = Some(lf);
                self.xsend(core, XMsg::LocalFull(lf));
            }
        }
    }

    fn failsafe_diagnostic(
        &self,
        snapshot: &crate::xcore::SpaceSnapshot,
        local_shards: &[peering::store::ShardSpace],
        enabled: bool,
        configured: f64,
        map_full: Option<f64>,
        threshold: Option<f64>,
    ) -> serde_json::Value {
        use peering::Space;
        use serde_json::{Value, json};
        fn space(s: Space) -> Value {
            json!({
                "total_bytes": s.total, "available_bytes": s.available,
                "allocated_bytes": s.allocated, "internal_metadata_bytes": s.internal_metadata,
                "pooled": s.pooled, "fullest_shard_fill_ratio": s.fullest,
                "fill_ratio": fill(s.total, s.available),
            })
        }
        fn shards(shards: &[peering::store::ShardSpace]) -> Vec<Value> {
            shards.iter().map(|s| json!({
                "shard": s.shard, "space": space(s.space),
                "data_used_bytes": s.data_used_bytes, "data_held_bytes": s.data_held_bytes,
                "data_reserved_bytes": s.data_reserved_bytes, "data_reserve_bytes": s.data_reserve_bytes,
                "meta_used_pages": s.meta_used_pages, "meta_dirty_pages": s.meta_dirty_pages,
                "meta_run_pages": s.meta_run_pages, "meta_usable_pages": s.meta_usable_pages,
                "meta_cell_used_pages": s.meta_cell_used_pages, "meta_base_pages": s.meta_base_pages,
                "meta_cell_blocks": s.meta_cell_blocks, "meta_blocks_per_page": s.meta_blocks_per_page,
                "meta_grow_blocked": s.meta_grow_blocked, "elastic": s.elastic,
                "meta_growth_failure": s.meta_growth_failure.as_ref().map(meta_growth_failure_json),
            })).collect()
        }
        let cores: Vec<_> = (0..self.cl.spec.n).map(|core| {
            if core == self.cl.spec.id {
                json!({
                    "core": core, "reported": self.store.is_some(),
                    "sampled_at_ns": self.now.as_nanos(), "sample_age_ms": 0,
                    "space": space(snapshot.local),
                    "store_space": snapshot.local_store.map(space),
                    "shards": shards(local_shards),
                })
            } else {
                let stats = self.cl.stats[core].as_ref();
                json!({
                    "core": core, "reported": stats.is_some(),
                    "sampled_at_ns": stats.map(|s| s.sampled_at.as_nanos()),
                    "sample_age_ms": stats.map(|s| self.now.saturating_sub(s.sampled_at).as_millis()),
                    "space": stats.and_then(|s| s.space).map(space),
                    "shards": stats.map(|s| shards(&s.space_shards)).unwrap_or_default(),
                })
            }
        }).collect();
        let s = &snapshot.aggregate;
        json!({
            "version": 2, "event": "local_failsafe_full", "enabled": enabled,
            "osd": self.id.whoami, "map_epoch": self.epoch(),
            "sampled_at_ns": self.now.as_nanos(),
            "configured_ratio": configured, "map_full_ratio": map_full, "threshold_ratio": threshold,
            "aggregate": {
                "total_bytes": s.total, "available_bytes": s.available,
                "available_before_clamp_bytes": snapshot.available_before_clamp,
                "fill_ratio": fill(s.total, s.available),
            },
            "fullest_core": snapshot.fullest_core,
            "cores": cores,
        })
    }

    /// Fullness bits of this OSD in the map differ from `local`.
    fn fullness_differs_from(&self, local: u32) -> bool {
        let Some(map) = &self.map else { return false };
        let mask = osd_state::FULL | osd_state::BACKFILLFULL | osd_state::NEARFULL;
        map.raw_state(self.id.whoami) & mask != local
    }

    fn fullness_differs(&self) -> bool {
        self.fullness_differs_from(self.local_fullness())
    }

    pub(crate) fn send_full(&mut self) {
        let st = self.local_fullness();
        let epoch = self.epoch();
        // PSM version = osdmap epoch (classic): the mon replies with incrementals, not a full map
        let m = messages::MOSDFull {
            version: u64::from(epoch),
            map_epoch: epoch,
            state: st,
        };
        self.send_mon(m);
        self.last_full_sent = Some(st);
    }

    /// `resend`: the report interval is due, so the same state is sent again (osd-lifecycle 4.4).
    fn check_fullness(&mut self, resend: bool) {
        let st = self.local_fullness(); // one statfs sample per tick, not one per question
        if self.fullness_differs_from(st) && (resend || self.last_full_sent != Some(st)) {
            self.send_full();
        }
    }

    // ---------------------------------------------------------------- shutdown (7.5)

    /// Start a graceful shutdown (SIGINT/SIGTERM): tell the mon we go down, wait for the ack.
    /// Supervise this core's progress (liveness.rs): beat every tick; core 0 publishes the limits and drops heartbeat
    /// pings while any core is unhealthy.
    pub fn set_liveness(&mut self, l: &'static crate::liveness::Liveness) {
        self.live = Some(l);
    }

    pub fn shutdown(&mut self, now: Duration) {
        self.set_now(now);
        if !self.is_control() {
            // workers follow core 0 (it tells the mon); stop right away when asked directly
            self.state = State::Stopping;
            if self.done.is_none() {
                self.done = Some(self.fail_code.unwrap_or(0));
                self.checkpoint_on_exit();
            }
            return;
        }
        self.begin_shutdown(true);
        self.pump();
    }

    /// Shutdown order (adr 0034 am. 1): refuse new ops (state Stopping) -> drain the running ones (bounded) -> MOSDMarkMeDown
    /// with ack -> exit. Draining BEFORE the mark-down keeps the PG intervals alive while ops finish (the new map would cancel
    /// them); clients resend whatever was never acked.
    pub(crate) fn begin_shutdown(&mut self, notify: bool) {
        if self.state == State::Stopping || self.done.is_some() {
            return;
        }
        let was_up = self.map.as_ref().is_some_and(|m| m.is_up(self.id.whoami));
        let was_state = self.state;
        self.state = State::Stopping;
        self.shutdown_notify = notify
            && was_up
            && self.mon_up()
            && matches!(was_state, State::Active | State::Booting)
            && self.shutdown_tells_mon();
        // Notification policy does not govern completion of work already accepted while up.
        if was_up && matches!(was_state, State::Active | State::Booting) {
            if self.multi() {
                self.xbcast(|| XMsg::Shutdown);
            }
            self.drain_begin();
        } else {
            self.finish_shutdown();
        }
    }

    /// Classic: `osd_fast_shutdown_notify_mon` decides only for the fast shutdown (the default); with
    /// `osd_fast_shutdown = false` the OSD always tells the mon (`prepare_to_stop`). Both run the same drain -> mark
    /// down -> checkpoint sequence here (adr 0034 am. 1); there is no separate slow teardown.
    fn shutdown_tells_mon(&self) -> bool {
        !self.conf.bool("osd_fast_shutdown", true)
            || self.conf.bool("osd_fast_shutdown_notify_mon", true)
    }

    fn send_mark_me_down(&mut self) -> bool {
        let m = self.map.as_ref().map(|m| messages::MOSDMarkMeDown {
            version: u64::from(m.epoch),
            fsid: self.id.cluster_fsid,
            target_osd: self.id.whoami,
            target_addrs: m.client_addrs[self.id.whoami as usize].clone(),
            epoch: m.epoch,
            request_ack: true,
            down_and_dead: true,
        });
        let Some(m) = m else { return false };
        self.send_mon(m);
        // a float option (classic): 2.5 means 2.5 s; a negative / non-finite value falls back to the default
        let limit = Duration::try_from_secs_f64(self.conf.f64("osd_mon_shutdown_timeout", 5.0))
            .unwrap_or(Duration::from_secs(5));
        self.shutdown_deadline = Some(self.now.saturating_add(limit));
        self.log("shutdown: sent MOSDMarkMeDown, waiting for ack");
        true
    }

    pub(crate) fn finish_shutdown(&mut self) {
        self.state = State::Stopping;
        self.shutdown_deadline = None;
        self.bench_abort();
        if self.done.is_none() {
            self.done = Some(self.fail_code.unwrap_or(0));
            if self.multi() {
                self.xbcast(|| XMsg::Shutdown);
            }
            self.checkpoint_on_exit();
        }
        self.log("shutdown complete");
    }

    /// A clean exit checkpoints this core's store (review M2): the next start replays nothing.
    fn checkpoint_on_exit(&mut self) {
        if self.done != Some(0) {
            return;
        }
        match self.pg.store.checkpoint_on_exit() {
            Ok(()) => self.log("shutdown: store checkpointed"),
            Err(e) => self.logl(
                0,
                format!("shutdown: store checkpoint skipped: {e} (next start replays the WAL)"),
            ),
        }
    }

    /// Start the drain window (`osd_shutdown_drain_timeout`, default 5 s, 0 = none). Workers only publish their ops left.
    /// The option has no schema, so a mon can set any text: a negative, non-finite or out-of-range value falls back to
    /// the default (like `osd_mon_shutdown_timeout`) instead of aborting the shutdown in `Duration::from_secs_f64`.
    pub(crate) fn drain_begin(&mut self) {
        let v = self
            .conf
            .f64("osd_shutdown_drain_timeout", DRAIN_TIMEOUT_SECS);
        self.drain_limit = match Duration::try_from_secs_f64(v) {
            Ok(d) => d,
            Err(_) => {
                let raw = self.conf.get("osd_shutdown_drain_timeout").unwrap_or("");
                let fallback = Duration::from_secs_f64(DRAIN_TIMEOUT_SECS);
                self.logl(
                    0,
                    format!(
                        "WARNING osd_shutdown_drain_timeout {raw}: not a usable duration, using the {}s default",
                        fallback.as_secs_f64()
                    ),
                );
                fallback
            }
        };
        self.drain_until = Some(self.now.saturating_add(self.drain_limit));
        self.log("shutdown: draining in-flight ops");
        self.drain_poll();
    }

    /// Log the oldest unfinished ops of this core and the state of their PGs (drain window over).
    fn drain_diag(&mut self) {
        let now = self.now.as_nanos() as u64;
        let spgs: Vec<_> = self.tracker.live_spgs().into_iter().take(2).collect();
        for s in spgs {
            if let Some(p) = self.pg.set.pg(s) {
                self.log(format!(
                    "shutdown: pg {}.{} {} {}",
                    s.pgid.pool,
                    s.pgid.seed,
                    p.repops_diag(),
                    p.state_string()
                ));
            }
        }
        for (_, j) in self
            .tracker
            .dump_live(now, &|n| n.to_string(), false)
            .iter()
            .take(2)
        {
            let d = j["description"]
                .as_str()
                .unwrap_or("")
                .trim_start_matches("osd_op(")
                .to_owned();
            self.log(format!("shutdown: unfinished {d}"));
        }
    }

    /// Drain check. Multi-core: every core publishes its ops left in `DRAIN_LEFT`; the control core waits for all of them,
    /// then (window over or nothing left) sends the mark-down. Workers run until the control core's exit stops them. A
    /// core still on the sentinel has not reported yet: that is unknown, never an op count to add up.
    pub(crate) fn drain_poll(&mut self) {
        use std::sync::atomic::Ordering::Relaxed;
        let Some(until) = self.drain_until else {
            return;
        };
        if self.done.is_some() || self.shutdown_deadline.is_some() {
            return;
        }
        let mut left = self.tracker.len();
        let mut unreported = 0usize;
        let me = self.cl.spec.id.min(DRAIN_LEFT.len() - 1);
        if self.multi() {
            DRAIN_LEFT[me].store(left, Relaxed);
            if !self.is_control() {
                if self.now >= until && left > 0 && !self.drain_logged {
                    self.drain_logged = true;
                    self.drain_diag();
                }
                return;
            }
            for (i, s) in DRAIN_LEFT.iter().enumerate().take(self.cl.spec.n) {
                if i == me {
                    continue;
                }
                match s.load(Relaxed) {
                    usize::MAX => unreported += 1,
                    n => left = left.saturating_add(n),
                }
            }
        }
        if (left == 0 && unreported == 0) || self.now >= until {
            if left > 0 || unreported > 0 {
                let limit = self.drain_limit.as_secs_f64();
                let mut ctx = format!("{left} op(s) unfinished");
                if unreported > 0 {
                    ctx.push_str(&format!(", {unreported} core(s) did not report"));
                }
                self.logl(
                    0,
                    format!(
                        "WARNING TIMEOUT shutdown drain exceeded {limit}s (osd_shutdown_drain_timeout, {ctx}, never acked)"
                    ),
                );
                self.drain_diag();
            }
            if !self.shutdown_notify || !self.send_mark_me_down() {
                self.finish_shutdown();
            }
        }
    }
}

/// `osd_shutdown_drain_timeout` default in seconds (adr 0034 am. 1).
const DRAIN_TIMEOUT_SECS: f64 = 5.0;

/// Shutdown drain slots (ops left per core, `usize::MAX` = has not reported yet), see `Osd::drain_poll`.
pub(crate) static DRAIN_LEFT: [std::sync::atomic::AtomicUsize; 64] =
    [const { std::sync::atomic::AtomicUsize::new(usize::MAX) }; 64];

fn add_epoch(s: &mut BTreeMap<u32, u32>, e: u32) {
    // interval_set<epoch> as start -> length
    let mut start = e;
    let mut len = 1u32;
    if let Some((&ps, &pl)) = s.range(..=e).next_back() {
        if ps + pl > e {
            return;
        }
        if ps + pl == e {
            start = ps;
            len += pl;
            s.remove(&ps);
        }
    }
    if let Some(&nl) = s.get(&(e + 1)) {
        s.remove(&(e + 1));
        len += nl;
    }
    s.insert(start, len);
}

/// Source address of a client op (blocklist match, watcher / lock origin), classic `Message::get_source_addr`: the
/// first address the peer advertised in its msgr2 ident, verbatim (librados `any:ip:0/nonce`, a bound daemon such as
/// an MDS `v2:ip:port/nonce`); `OsdMap::is_blocklisted` normalises the type. Never the socket's ip:port (msgr2
/// refuses an empty / blank first address).
pub(crate) fn client_src_addr(adv: &EntityAddrVec) -> EntityAddr {
    adv.0.first().copied().unwrap_or_default()
}

/// JSON string literal.
pub(crate) fn js(s: &str) -> String {
    serde_json::Value::String(s.to_owned()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a blocklist entry made by the mon matches (OSDMonitor stores type ANY): librados advertises a single
    /// `any:ip:0/nonce` (no msgr2-typed entry at all), an MDS / bound daemon `v2:` + `v1:` with its port, IPv6 alike.
    #[test]
    fn client_source_addr_is_what_blocklist_stores() {
        let any = |n, ip, port| EntityAddr::v4(EntityAddr::TYPE_ANY, n, ip, port);
        let mut m = OsdMap::default();
        m.require_osd_release = release::NAUTILUS + 10;
        let fenced = |m: &OsdMap, v: &[EntityAddr]| {
            m.is_blocklisted(&client_src_addr(&EntityAddrVec(v.to_vec())))
        };
        // librados client 10.1.2.3 nonce 77 (rbd exclusive-lock break: `blocklist add 10.1.2.3:0/77`)
        let rados = [any(77, [10, 1, 2, 3], 0)];
        let other = [any(78, [10, 1, 2, 3], 0)];
        assert_eq!(client_src_addr(&EntityAddrVec(rados.to_vec())), rados[0]);
        assert!(!fenced(&m, &rados));
        m.blocklist
            .insert(any(77, [10, 1, 2, 3], 0), UTime::default());
        assert!(fenced(&m, &rados));
        assert!(!fenced(&m, &other), "same host, other instance");
        // failed MDS: both its addrs blocklisted (port + nonce)
        let mds = [
            EntityAddr::v4(EntityAddr::TYPE_MSGR2, 5, [10, 1, 2, 4], 6800),
            EntityAddr::v4(EntityAddr::TYPE_LEGACY, 5, [10, 1, 2, 4], 6801),
        ];
        assert!(!fenced(&m, &mds));
        m.blocklist
            .insert(any(5, [10, 1, 2, 4], 6800), UTime::default());
        m.blocklist
            .insert(any(5, [10, 1, 2, 4], 6801), UTime::default());
        assert!(fenced(&m, &mds));
        // IPv6 librados client
        let ip6 = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let v6 = [EntityAddr::v6(EntityAddr::TYPE_ANY, 9, ip6, 0, 0)];
        assert!(!fenced(&m, &v6));
        m.blocklist.insert(v6[0], UTime::default());
        assert!(fenced(&m, &v6));
        // whole host
        m.blocklist
            .insert(any(0, [10, 1, 2, 3], 0), UTime::default());
        assert!(fenced(&m, &other));
    }

    #[test]
    fn service_header_compatibility_matches_decoder_support() {
        for &(ty, head) in pgwire::PeeringMsg::HEAD_BY_TYPE
            .iter()
            .chain(replwire::ReplMsg::HEAD_BY_TYPE)
            .chain(&[
                (opwire::MOSDOp::MSG_TYPE, opwire::MOSDOp::HEAD_VERSION),
                (
                    opwire::MOSDOpReply::MSG_TYPE,
                    opwire::MOSDOpReply::HEAD_VERSION,
                ),
                (
                    opwire::MOSDBackoff::MSG_TYPE,
                    opwire::MOSDBackoff::HEAD_VERSION,
                ),
                (
                    opwire::MWatchNotify::MSG_TYPE,
                    opwire::MWatchNotify::HEAD_VERSION,
                ),
                (
                    ecwire::MOSDECSubOpWrite::MSG_TYPE,
                    ecwire::MOSDECSubOpWrite::HEAD_VERSION,
                ),
                (
                    ecwire::MOSDECSubOpWriteReply::MSG_TYPE,
                    ecwire::MOSDECSubOpWriteReply::HEAD_VERSION,
                ),
                (
                    ecwire::MOSDECSubOpRead::MSG_TYPE,
                    ecwire::MOSDECSubOpRead::HEAD_VERSION,
                ),
                (
                    ecwire::MOSDECSubOpReadReply::MSG_TYPE,
                    ecwire::MOSDECSubOpReadReply::HEAD_VERSION,
                ),
            ])
        {
            assert!(check_wire_compat(ty, head, head + 1).is_err(), "type {ty}");
            assert!(check_wire_compat(ty, head + 1, 0).is_err(), "type {ty}");
            assert!(check_wire_compat(ty, head + 1, head).is_ok(), "type {ty}");
            assert!(check_wire_compat(ty, head, 0).is_ok(), "type {ty}");
        }
        assert!(check_wire_compat(u16::MAX, u16::MAX, u16::MAX).is_ok());
    }

    #[test]
    fn interval_add() {
        let mut s = BTreeMap::new();
        for e in [5, 3, 4, 10, 1, 2, 9] {
            add_epoch(&mut s, e);
        }
        assert_eq!(s.into_iter().collect::<Vec<_>>(), vec![(1, 5), (9, 2)]);
    }
}

#[cfg(test)]
mod core_tests;
