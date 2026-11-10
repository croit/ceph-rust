// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Sans-IO MonClient (spec osd-lifecycle.md section 2).
//!
//! Driver contract (like msgr2): drain [`MonClient::poll_io`] (open / close sockets), report
//! sockets with [`on_connected`](MonClient::on_connected) / [`on_closed`](MonClient::on_closed),
//! feed bytes with [`on_bytes`](MonClient::on_bytes), write [`poll_output`](MonClient::poll_output)
//! per connection id, drain [`poll_event`](MonClient::poll_event), and call
//! [`on_timer`](MonClient::on_timer) at [`next_timer`](MonClient::next_timer). `now` is a monotonic
//! [`Duration`] since an arbitrary origin; `Config::wall_origin` maps it to unix time (cephx).
#[path = "directed.rs"]
mod directed;
#[cfg(feature = "lab")]
#[path = "osdmap_dump.rs"]
mod osdmap_dump;
use crate::auth::{AuthShared, MonAuthHandler};
use crate::config::{Config, monmap_from_addrs};
use crate::subs::Subs;
use cephx::CryptoKey;
use cephx::modes::AUTH_CEPHX;
#[cfg(test)]
use cephx::modes::AUTH_NONE;
use cephx::monclient::{MonAuthClient, MonReply};
use denc::types::{EntityAddr, EntityAddrVec, EntityName, UTime, Uuid};
pub use directed::{MonitorTarget, MonitorTargetError, MonitorTargetSeed};
use messages::{
    AnyMessage, Header2, MAuth, MMonCommand, MMonGetOSDMap, MMonGetVersion, MMonSubscribe, MOSDMap,
    SubItem,
};
use msgr2::{Connection, Event, Policy, PolicyTable, SessionTable};
use osdmap::{Incremental, MonMap, OsdMap};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

const TICK: Duration = Duration::from_secs(1);
const AUTH_REQ_TIMEOUT: Duration = Duration::from_secs(10);
const ETIMEDOUT: i32 = -denc::errno::ETIMEDOUT;

/// Socket operations for the driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IoCmd {
    /// Open a TCP connection for connection `conn`, then call `on_connected` (or `on_closed`).
    Dial {
        /// Connection id.
        conn: u64,
        /// Target address.
        target: EntityAddr,
    },
    /// Close the socket of `conn` (idempotent; connection ids are never reused).
    Close {
        /// Connection id.
        conn: u64,
    },
}

/// A generic message was not handed to the active monitor messenger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonSendError {
    NoSession,
    IdentityExhausted,
    Rejected,
}

/// Events for the owner.
#[derive(Debug, Clone)]
pub enum MonEvent {
    /// A mon session is authenticated and open (subscriptions/commands are being resent).
    Authenticated {
        /// Global id assigned by the mon.
        global_id: u64,
        /// Mon name (synthetic `noname-x` until a monmap arrives).
        mon: String,
        /// Mon address dialled.
        addr: EntityAddr,
        /// Negotiated connection mode (`msgr2::auth::MODE_CRC` / `MODE_SECURE`).
        mode: u32,
        /// Auth method used.
        method: u32,
    },
    /// The session was lost (re-hunting started). In-flight state-bearing messages must be resent
    /// by the owner (commands and subscriptions are handled here).
    SessionLost(String),
    /// Authentication failed on a hunting connection (the client keeps hunting).
    AuthFailed(String),
    /// A newer monmap was adopted ([`MonClient::monmap`]).
    MonMapUpdated {
        /// New epoch.
        epoch: u32,
    },
    /// The held OSDMap advanced to `epoch`. `msg` is the verbatim message (store/forward its map blobs). `map` is the
    /// map AT `epoch`: several MOSDMaps can be handled before the events are drained, so [`MonClient::osdmap`] may
    /// already be newer (persisting that one under this event's epoch left holes in the stored history).
    OsdMap {
        /// New epoch.
        epoch: u32,
        /// The map at `epoch` (shared with the client's held map, no copy).
        map: Arc<OsdMap>,
        /// The MOSDMap that carried the maps.
        msg: Box<MOSDMap>,
    },
    /// Centralized config set changed (complete MON-level set, [`MonClient::config`]).
    Config(BTreeMap<String, String>),
    /// Reply to [`MonClient::send_command`].
    CommandReply {
        /// Tid returned by `send_command`.
        tid: u64,
        /// Result code (negative errno).
        r: i32,
        /// Status string.
        rs: String,
        /// Output blob.
        data: Vec<u8>,
    },
    /// Exact reply to a send-once command. Consumer validates the echoed command.
    CommandOnceReply {
        tid: u64,
        version: u64,
        r: i32,
        rs: String,
        cmd: Vec<String>,
        data: Vec<u8>,
    },
    /// Session lost after handoff; remote outcome is unknown. Never automatically replayed.
    CommandOnceLost { tid: u64 },
    /// Reply to [`MonClient::get_version`].
    VersionReply {
        /// Handle returned by `get_version`.
        handle: u64,
        /// Newest epoch.
        version: u64,
        /// Oldest epoch.
        oldest: u64,
    },
    /// A pending `get_version` was dropped by a session reset; re-issue it.
    VersionFailed {
        /// Handle.
        handle: u64,
    },
    /// cephx tickets / rotating keys were refreshed.
    KeysUpdated,
    /// Any other message from the mon (MOSDBoot replies arrive as `OsdMap`; MgrMap etc. here).
    Message {
        /// Header tid.
        tid: u64,
        /// Decoded message.
        msg: Box<AnyMessage>,
    },
    /// Diagnostic line (log + continue).
    Diag(String),
}

#[derive(Debug)]
struct MonEntry {
    /// Monmap rank of this mon (the dial list drops ranks without a v2 address, so it is not the list index).
    rank: usize,
    name: String,
    addrs: EntityAddrVec,
    target: EntityAddr,
    priority: u16,
    weight: u16,
}

struct Slot {
    conn: Connection,
    shared: Rc<AuthShared<Vec<u8>>>,
    mon: usize,
}

#[derive(Debug)]
struct Cmd {
    cmd: Vec<String>,
    data: Vec<u8>,
    deadline: Option<Duration>,
}

#[derive(Debug)]
struct LogQ {
    e: messages::ByteLogEntry,
    sent: bool,
}

/// The MonClient. See the module docs.
pub struct MonClient {
    pinned: Option<String>,
    cfg: Config<Vec<u8>>,
    now: Duration,
    clock: Rc<Cell<Duration>>,
    table: SessionTable,
    msgr_cfg: msgr2::Config,
    rng: u64,
    // monmap / hunting
    monmap: MonMap,
    mons: Vec<MonEntry>,
    tried: BTreeSet<usize>,
    slots: HashMap<u64, Slot, foldhash::fast::RandomState>,
    output_queue: Option<(msgr2::OutputQueue, u64)>,
    next_conn: u64,
    active: Option<u64>,
    active_mon: Option<usize>,
    active_addr: Option<EntityAddr>,
    features: u64,
    auth: Rc<AuthShared<Vec<u8>>>,
    methods: Vec<u32>,
    next_hunt: Option<Duration>,
    reopen_mult: f64,
    hunts: u32,
    /// Interval of the running hunt round (for its timeout line).
    hunt_round: Duration,
    timeouts: u64,
    ever_connected: bool,
    // session timers
    tick_at: Duration,
    last_ping: Duration,
    /// Expiry baseline while probes remain outstanding: initially the first probe's send
    /// time, advanced by echoed ACK timestamps. An old ACK cannot acknowledge newer probes.
    /// No pending probe means no expiry, including after a driver stall before sending.
    ping_unacked: Option<Duration>,
    acks: u64,
    /// Connection events handled so far: only these change client state (`events_drained`).
    events_drained: u64,
    last_log: Duration,
    last_sub_flush: Duration,
    auth_req_at: Option<Duration>,
    // state
    subs: Subs,
    next_tid: u64,
    cmds: BTreeMap<u64, Cmd>,
    commands_once: BTreeSet<u64>,
    versions: BTreeSet<u64>,
    osdmap: Option<Arc<OsdMap>>,
    /// PGs of sent client requests, followed through every applied map epoch (interval resend rule).
    pg_watch: osdmap::PgWatch,
    /// Bumped by every map install; lets readers hold per-map derived caches that die with the map.
    osdmap_generation: u64,
    map_req: Option<u32>,
    /// Outstanding inclusive full-map range; retain its suffix across short replies.
    full_req: Option<(u32, u32)>,
    /// Incrementals that failed to apply (crc mismatch, decode error) and were replaced by full maps.
    inc_fallbacks: u64,
    /// The mon's full map for this epoch did not decode (error text); cleared when the held map moves past it.
    undecodable: Option<(u32, String)>,
    config: BTreeMap<String, String>,
    have_config: bool,
    logq: VecDeque<LogQ>,
    #[cfg(test)]
    log_flush_visits: usize,
    log_seq: u64,
    log_waiting_fsid: bool,
    ready_resend: bool,
    my_addrs: EntityAddrVec,
    // outputs
    events: VecDeque<MonEvent>,
    io: VecDeque<IoCmd>,
}

impl std::fmt::Debug for MonClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonClient")
            .field("entity", &self.cfg.entity)
            .field("active", &self.active)
            .field("slots", &self.slots.len())
            .finish_non_exhaustive()
    }
}

impl MonClient {
    /// Replace the auth method list (`auth_cluster_required` of a daemon after a config change): the next mon
    /// connection (reconnect or hunt) offers it; the established session is kept.
    pub fn set_methods(&mut self, methods: &[u32]) {
        self.cfg.methods = methods.to_vec();
        self.methods = usable_methods(methods, self.cfg.key.is_some());
    }

    /// Connection mode preference of monitor connections created from now on; existing connections, including
    /// attempts already hunting, keep the list their handshake started with.
    pub fn set_modes(&mut self, modes: &[u32]) {
        if self.cfg.modes != modes {
            self.cfg.modes = modes.to_vec();
        }
    }

    /// `ms_crc_data` of monitor connections created from now on (spec msgr2.md 4.3: read at connection creation);
    /// existing connections keep their codec.
    pub fn set_crc_data(&mut self, crc_data: bool) {
        self.cfg.crc_data = crc_data;
        self.msgr_cfg.crc_data = crc_data;
    }

    /// New `mon_client_*` timers ([`crate::Timers`]); deadlines already scheduled stay, the next ones use the new set.
    pub fn set_timers(&mut self, t: crate::Timers) {
        self.cfg.set_timers(t);
    }

    /// The `mon_client_*` timers in effect.
    pub fn timers(&self) -> crate::Timers {
        self.cfg.timers()
    }

    /// `rotate-key`: replace the own cephx secret in memory (cephx spec sec 2.2). `false` = no cephx key is loaded
    /// (cephx not in use), nothing changed.
    pub fn rotate_key(&mut self, key: CryptoKey) -> bool {
        match self.auth.cephx.borrow_mut().as_mut() {
            Some(c) => c.set_key(key.clone()),
            None => return false,
        }
        // Hunt attempts own independent credential snapshots. A winner replaces
        // `self.auth`, so every pending attempt must take the replacement too.
        for slot in self.slots.values() {
            if !Rc::ptr_eq(&slot.shared, &self.auth)
                && let Some(c) = slot.shared.cephx.borrow_mut().as_mut()
            {
                c.set_key(key.clone());
            }
        }
        self.cfg.key = Some(key);
        true
    }

    /// `wipe-rotating-secrets` (also on a monmap `auth_epoch` bump): drop rotating secrets, invalidate every ticket and
    /// re-authenticate / re-fetch at once. Emits [`MonEvent::KeysUpdated`] so service-side copies drop the wiped keys.
    pub fn wipe_secrets_and_tickets(&mut self) {
        match self.auth.cephx.borrow_mut().as_mut() {
            Some(c) => c.wipe_secrets_and_tickets(),
            None => return,
        }
        for slot in self.slots.values() {
            if !Rc::ptr_eq(&slot.shared, &self.auth)
                && let Some(c) = slot.shared.cephx.borrow_mut().as_mut()
            {
                c.wipe_secrets_and_tickets();
            }
        }
        self.events.push_back(MonEvent::KeysUpdated);
        self.auth_poll();
        if let Some(id) = self.active {
            self.drain(id);
        }
    }

    /// `auth_service_ticket_ttl` (runtime option, seconds).
    pub fn set_service_ticket_ttl(&mut self, secs: u32) {
        self.cfg.service_ticket_ttl = secs;
        if let Some(c) = self.auth.cephx.borrow_mut().as_mut() {
            c.set_service_ticket_ttl(secs);
        }
        for slot in self.slots.values() {
            if !Rc::ptr_eq(&slot.shared, &self.auth)
                && let Some(c) = slot.shared.cephx.borrow_mut().as_mut()
            {
                c.set_service_ticket_ttl(secs);
            }
        }
    }

    /// Selected hard frame policy of this monitor owner, including directed overrides.
    pub fn frame_limits(&self) -> msgr2::Limits {
        self.msgr_cfg.limits
    }

    /// New client; call [`start`](Self::start) to begin hunting.
    pub fn new(cfg: Config) -> Self {
        Self::new_bytes(cfg.into_bytes())
    }
    /// Owned byte principal; messenger role remains independently configured.
    pub fn new_bytes(cfg: Config<Vec<u8>>) -> Self {
        let clock = Rc::new(Cell::new(cfg.wall_origin));
        let monmap = cfg
            .initial_monmap
            .clone()
            .unwrap_or_else(|| monmap_from_addrs(&cfg.mon_host));
        let methods = usable_methods(&cfg.methods, cfg.key.is_some());
        let cephx = cfg
            .key
            .clone()
            .map(|k| MonAuthClient::new_bytes(cfg.auth_cfg(k)));
        let auth = AuthShared::new_bytes(cephx, cfg.auth_name(), 0, clock.clone());
        let mut rng = cfg.seed ^ 0xA076_1D64_78BD_642F;
        // Nonzero: a zero nonce reads as a nonce-less (whole-host) address in blocklist matching.
        let nonce = splitmix(&mut rng) as u32 | 1;
        let my_addrs = cfg.my_addrs.clone().unwrap_or_else(|| {
            let mut a = EntityAddr::blank();
            a.ty = EntityAddr::TYPE_MSGR2;
            a.nonce = nonce;
            EntityAddrVec::single(a)
        });
        let mut msgr_cfg = msgr2::Config::new(
            cfg.msgr_name(),
            my_addrs.clone(),
            PolicyTable::uniform(Policy::lossy_client(cfg.mon_required_features)),
        );
        msgr_cfg.supported_features = cfg.supported_features;
        msgr_cfg.compression = cfg.compression;
        msgr_cfg.limits = cfg.frame_limits;
        msgr_cfg.crc_data = cfg.crc_data;
        let table = SessionTable::new(splitmix(&mut rng));
        let mut s = Self {
            pinned: None,
            cfg,
            now: Duration::ZERO,
            clock,
            table,
            msgr_cfg,
            rng,
            monmap: MonMap::default(),
            mons: Vec::new(),
            tried: BTreeSet::new(),
            slots: HashMap::default(),
            output_queue: None,
            next_conn: 1,
            active: None,
            active_mon: None,
            active_addr: None,
            features: 0,
            auth,
            methods,
            next_hunt: None,
            reopen_mult: 1.0,
            hunts: 0,
            hunt_round: Duration::ZERO,
            timeouts: 0,
            ever_connected: false,
            tick_at: Duration::ZERO,
            last_ping: Duration::ZERO,
            ping_unacked: None,
            acks: 0,
            events_drained: 0,
            last_log: Duration::ZERO,
            last_sub_flush: Duration::ZERO,
            auth_req_at: None,
            subs: Subs::default(),
            next_tid: 1,
            cmds: BTreeMap::new(),
            commands_once: BTreeSet::new(),
            versions: BTreeSet::new(),
            osdmap: None,
            pg_watch: osdmap::PgWatch::default(),
            osdmap_generation: 0,
            map_req: None,
            full_req: None,
            inc_fallbacks: 0,
            undecodable: None,
            config: BTreeMap::new(),
            have_config: false,
            logq: VecDeque::new(),
            #[cfg(test)]
            log_flush_visits: 0,
            log_seq: 0,
            log_waiting_fsid: false,
            ready_resend: false,
            my_addrs,
            events: VecDeque::new(),
            io: VecDeque::new(),
        };
        if s.cfg.fsid == Uuid::default() {
            s.cfg.fsid = monmap.fsid;
        }
        s.set_monmap(monmap);
        if s.cfg.default_subs {
            let start = if s.monmap.epoch == 0 {
                0
            } else {
                u64::from(s.monmap.epoch) + 1
            };
            s.subs.want("monmap", start, 0);
            s.subs.want("config", 0, 0);
        }
        s
    }

    // ---------------------------------------------------------------- accessors

    /// Current monmap (synthetic, epoch 0, until a real one arrives).
    pub fn monmap(&self) -> &MonMap {
        &self.monmap
    }
    /// Held OSDMap (fed from MOSDMap), if any.
    pub fn osdmap(&self) -> Option<&OsdMap> {
        self.osdmap.as_deref()
    }
    /// `(epoch, error)` of a full map from the mon that does not decode while the held map is still older: asking
    /// again returns the same bytes, so the owner cannot follow the cluster (the OSD stops, as classic aborts).
    pub fn undecodable_osdmap(&self) -> Option<&(u32, String)> {
        self.undecodable.as_ref()
    }
    /// Shared handle on the held map (identity changes with every install); for publishing to other owners.
    pub fn osdmap_arc(&self) -> Option<&Arc<OsdMap>> {
        self.osdmap.as_ref()
    }
    /// Incrementals that failed to apply and were replaced by full maps since start.
    pub fn osdmap_inc_fallbacks(&self) -> u64 {
        self.inc_fallbacks
    }
    /// Number of map installs so far: changes whenever [`Self::osdmap`] may return different content.
    pub fn osdmap_generation(&self) -> u64 {
        self.osdmap_generation
    }
    /// Seed the held OSDMap (e.g. the newest stored map at OSD start) so only newer epochs are
    /// requested/applied.
    pub fn set_osdmap(&mut self, m: OsdMap) {
        self.install_osdmap(m);
    }
    /// Make `m` the held map; the PG watch sees every installed epoch (a skipped epoch is a gap).
    fn install_osdmap(&mut self, m: OsdMap) {
        let generation = self
            .osdmap_generation
            .checked_add(1)
            .expect("OSD map generation exhausted");
        self.pg_watch
            .observe_generation(self.osdmap.as_deref(), &m, generation);
        self.osdmap = Some(Arc::new(m));
        self.osdmap_generation = generation;
    }
    /// Follow `pg` of a request sent with map `epoch` through every map epoch applied from now on.
    pub fn track_pg(&mut self, pg: denc::types::PgT, epoch: u32) {
        self.pg_watch.track(pg, epoch);
    }
    /// Stop following `pg` for one request.
    pub fn untrack_pg(&mut self, pg: denc::types::PgT) {
        self.pg_watch.untrack(pg);
    }
    /// Epoch at which followed `pg` last started a new interval (0 = none seen; `None` = not followed).
    pub fn pg_interval_since(&self, pg: denc::types::PgT) -> Option<u32> {
        self.pg_watch.interval_since(pg)
    }
    /// Install generation of the last observed interval for a followed PG.
    pub fn pg_interval_generation(&self, pg: denc::types::PgT) -> Option<u64> {
        self.pg_watch.interval_generation(pg)
    }
    /// Newest centralized config set from the mon.
    pub fn config(&self) -> &BTreeMap<String, String> {
        &self.config
    }
    /// Authenticated session open?
    pub fn is_connected(&self) -> bool {
        self.active.is_some()
    }
    /// Count of connection events handled so far. Handing output alone changes no client state, so a driver that
    /// re-derives its own state from the client after `poll_output*` needs to do so only when this count moved.
    pub fn events_drained(&self) -> u64 {
        self.events_drained
    }
    /// Nonce of this client instance's advertised address. Classic messengers use one nonce for every
    /// connection of a client instance, so OSD/manager sessions advertise this value too (fencing: a
    /// blocklist of the `rados_getaddrs` address must match every session).
    pub fn address_nonce(&self) -> Option<u32> {
        self.my_addrs.0.first().map(|a| a.nonce)
    }
    /// Ready active monitor's local advertised identity; never a hunt-loser fallback.
    pub fn local_addresses(&self) -> Option<msgr2::LocalAddresses<'_>> {
        self.active
            .and_then(|id| self.slots.get(&id))
            .and_then(|slot| slot.conn.local_addresses())
    }
    /// Global id (0 until authenticated).
    pub fn global_id(&self) -> u64 {
        self.auth.global_id()
    }
    /// Name of the mon we are connected to.
    pub fn current_mon(&self) -> Option<&str> {
        self.active_mon.map(|i| self.mons[i].name.as_str())
    }
    /// Negotiated connection mode of the active session (0 = none).
    pub fn mode(&self) -> u32 {
        if self.active.is_some() {
            self.auth.mode.get()
        } else {
            0
        }
    }
    /// Run `f` on the cephx state (tickets, rotating keys, authorizers).
    pub fn with_cephx<R>(&self, f: impl FnOnce(&MonAuthClient) -> R) -> Option<R> {
        self.auth.cephx.borrow().as_ref().map(f)
    }
    /// Cluster fsid (zero until known).
    pub fn fsid(&self) -> Uuid {
        self.cfg.fsid
    }
    /// Number of live connection objects (hunting + active), diagnostics.
    pub fn num_conns(&self) -> usize {
        self.slots.len()
    }
    /// Keepalive acks received (all sessions).
    pub fn keepalive_acks(&self) -> u64 {
        self.acks
    }
    /// Hunt rounds started so far.
    pub fn hunts(&self) -> u32 {
        self.hunts
    }

    /// Timeouts that fired (each printed a `WARNING TIMEOUT` line).
    pub fn timeouts(&self) -> u64 {
        self.timeouts
    }

    // ---------------------------------------------------------------- driver API

    /// Begin hunting for a mon. With no usable auth method (cephx-only list and no key, or an empty list) no
    /// connection is attempted: [`MonEvent::AuthFailed`] is queued at once, like classic `MonClient::init`, which
    /// fails with `-ENOENT` ("No supported authentication method found! Is the keyring missing?").
    pub fn start(&mut self, now: Duration) {
        self.set_now(now);
        if self.methods.is_empty() {
            self.events
                .push_back(MonEvent::AuthFailed(NO_AUTH_METHOD.into()));
            return;
        }
        if self.active.is_none() && self.slots.is_empty() {
            self.start_hunt();
        }
    }

    /// Next socket operation.
    pub fn poll_io(&mut self) -> Option<IoCmd> {
        self.io.pop_front()
    }
    /// Work already queued for the outer owner; network/timer waits are separate.
    pub fn has_pending_work(&self) -> bool {
        self.has_pending_work_with_blocked_output(&|_| false)
    }
    /// Only exact transport-blocked messenger output may wait; queued events/IO cannot.
    pub fn has_pending_work_with_blocked_output(&self, blocked: &impl Fn(u64) -> bool) -> bool {
        !self.io.is_empty()
            || !self.events.is_empty()
            || self
                .slots
                .iter()
                .any(|(&id, s)| s.conn.has_events() || (s.conn.has_output() && !blocked(id)))
    }

    /// Next event for the owner.
    pub fn poll_event(&mut self) -> Option<MonEvent> {
        self.events.pop_front()
    }

    /// Socket for `conn` is connected.
    pub fn on_connected(&mut self, conn: u64, now: Duration) {
        self.set_now(now);
        if let Some(s) = self.slots.get_mut(&conn) {
            s.conn.on_connected(now);
            self.drain(conn);
        }
    }

    /// Socket for `conn` failed / was closed by the peer (also: a dial failed).
    pub fn on_closed(&mut self, conn: u64, now: Duration) {
        self.set_now(now);
        if let Some(s) = self.slots.get_mut(&conn) {
            s.conn.on_closed(now);
            self.drain(conn);
        }
    }

    /// Bytes received on `conn`.
    pub fn on_bytes(&mut self, conn: u64, data: &[u8], now: Duration) {
        self.set_now(now);
        if let Some(s) = self.slots.get_mut(&conn) {
            s.conn.on_bytes(data, now);
            self.drain(conn);
        }
    }

    /// Bytes to write to the socket of `conn`.
    pub fn poll_output(&mut self, conn: u64) -> Vec<u8> {
        match self.slots.get_mut(&conn) {
            Some(s) => {
                let o = s.conn.poll_output();
                self.drain(conn);
                o
            }
            None => Vec::new(),
        }
    }

    /// Ordered wire prefix; zero budget leaves output and events untouched.
    pub fn poll_output_bounded(&mut self, conn: u64, maximum: usize) -> Vec<u8> {
        if maximum == 0 {
            return Vec::new();
        }
        match self.slots.get_mut(&conn) {
            Some(s) => {
                let out = s.conn.poll_output_bounded(maximum);
                self.drain(conn);
                out
            }
            None => Vec::new(),
        }
    }

    /// Ids of live connections (a driver may poll them all).
    pub fn conn_ids(&self) -> Vec<u64> {
        self.slots.keys().copied().collect()
    }

    /// Register monitor output with the embedding core's queue (ids tagged by `base`).
    pub fn set_output_queue(&mut self, q: &msgr2::OutputQueue, base: u64) {
        for (&id, s) in &mut self.slots {
            s.conn.set_output_queue(q, id | base);
        }
        self.output_queue = Some((q.clone(), base));
    }

    /// Earliest absolute time something is due.
    pub fn next_timer(&self) -> Option<Duration> {
        let mut t: Option<Duration> = None;
        let mut add = |d: Duration| t = Some(t.map_or(d, |c| c.min(d)));
        for command in self.cmds.values() {
            if let Some(deadline) = command.deadline {
                add(deadline);
            }
        }
        for s in self.slots.values() {
            if let Some(d) = s.conn.next_timer() {
                add(d);
            }
        }
        if self.active.is_none() {
            if let Some(d) = self.next_hunt {
                add(d);
            }
        } else {
            add(self.tick_at);
        }
        t
    }

    /// Run due timers.
    pub fn on_timer(&mut self, now: Duration) {
        self.set_now(now);
        self.expire_commands();
        let due: Vec<u64> = self
            .slots
            .iter()
            .filter(|(_, s)| s.conn.next_timer().is_some_and(|d| d <= now))
            .map(|(i, _)| *i)
            .collect();
        for id in due {
            if let Some(s) = self.slots.get_mut(&id) {
                s.conn.on_timer(now);
            }
            self.drain(id);
        }
        if self.active.is_none() {
            if self.next_hunt.is_some_and(|d| d <= now) {
                if !self.slots.is_empty() {
                    let n = self.slots.len();
                    self.warn_timeout(
                        "mon hunt round",
                        self.hunt_round,
                        &format!("no session from {n} dialed mon(s), next round"),
                    );
                }
                self.start_hunt();
            }
        } else if now >= self.tick_at {
            self.tick();
        }
    }

    // ---------------------------------------------------------------- public operations

    /// Subscribe (`what`, first wanted epoch, flags; `SubItem::ONETIME` = 1). No-op if identical.
    pub fn subscribe(&mut self, what: &str, start: u64, flags: u8) {
        if self.subs.want(what, start, flags) {
            self.flush_subs();
        }
    }

    /// Send the subscription to `what` from `start` again even when it is unchanged (the mon then sends what it has from
    /// `start` once more, e.g. `osd_pg_creates` after creates were withheld).
    pub fn resubscribe(&mut self, what: &str, start: u64, flags: u8) {
        self.subs.force(what, start, flags);
        self.flush_subs();
    }

    /// Remove local subscription bookkeeping; no unsubscribe message exists.
    pub fn unsubscribe(&mut self, what: &str) {
        self.subs.unwant(what);
    }

    /// The owner has everything up to `have` for `what` (after it stored/consumed it itself).
    pub fn subscription_got(&mut self, what: &str, have: u64) {
        self.subs.got(what, have);
    }

    /// Send a mon command (`json` = one JSON object string) with optional input blob. Returns the
    /// tid; the reply is [`MonEvent::CommandReply`]. Outstanding commands are resent after rehunt.
    /// Returns reserved zero without admission when request identities are exhausted.
    /// Prefer `try_send_command` when handling admission explicitly.
    pub fn send_command(&mut self, json: &str, inbl: Vec<u8>) -> u64 {
        self.try_send_command(json, inbl).unwrap_or(0)
    }

    /// Checked command admission. `None` means identity exhaustion; nothing was queued.
    pub fn try_send_command(&mut self, json: &str, inbl: Vec<u8>) -> Option<u64> {
        let tid = self.alloc_tid()?;
        let deadline = self.cfg.command_timeout.map(|t| self.now + t);
        self.cmds.insert(
            tid,
            Cmd {
                cmd: vec![json.to_owned()],
                data: inbl,
                deadline,
            },
        );
        self.send_cmd(tid);
        Some(tid)
    }

    /// Abandon command correlation and reconnect replay. Already handed-off bytes
    /// cannot be retracted, and cancellation does not undo remote effects.
    pub fn cancel_command(&mut self, tid: u64) -> bool {
        self.cmds.remove(&tid).is_some()
    }

    /// One handoff only; no monitor-hunt replay or implicit deadline. Caller bounds
    /// requests and cancels abandoned correlation. Acceptance is not remote commit.
    pub fn try_send_command_once(
        &mut self,
        json: &str,
        input: Vec<u8>,
    ) -> Result<u64, MonSendError> {
        self.try_send_commands_once(vec![json.to_owned()], input)
    }
    /// Exact command-vector send-once; caller supplies bounded owned inputs.
    pub fn try_send_commands_once(
        &mut self,
        commands: Vec<String>,
        input: Vec<u8>,
    ) -> Result<u64, MonSendError> {
        let id = self.active.ok_or(MonSendError::NoSession)?;
        if self
            .slots
            .get(&id)
            .is_none_or(|slot| slot.conn.state() != msgr2::ConnState::Ready)
        {
            return Err(MonSendError::NoSession);
        }
        if self.cfg.fsid == Uuid::default() {
            return Err(MonSendError::Rejected);
        }
        let tid = self.alloc_tid().ok_or(MonSendError::IdentityExhausted)?;
        let command = MMonCommand {
            version: 0,
            fsid: self.cfg.fsid,
            cmd: commands,
            data: input,
        };
        self.commands_once.insert(tid); // drain can synchronously report loss
        if !self.send_any(&command.into(), tid) {
            self.commands_once.remove(&tid);
            return Err(MonSendError::Rejected);
        }
        Ok(tid)
    }
    /// Correlation removal only. Already handed-off bytes and mutations are not retracted.
    pub fn cancel_command_once(&mut self, tid: u64) -> bool {
        self.commands_once.remove(&tid)
    }

    /// Ask for the newest/oldest epoch of `what` (`osdmap`, `monmap`, ...). `None` if not connected,
    /// identities are exhausted, or the messenger refused the request (pending requests are failed on
    /// session reset).
    pub fn get_version(&mut self, what: &str) -> Option<u64> {
        self.try_get_version(what).ok()
    }

    /// Checked read-only map-version request; no session or identity exhaustion is explicit, and a messenger refusal
    /// is reported instead of a handle that can never be answered.
    pub fn try_get_version(&mut self, what: &str) -> Result<u64, MonSendError> {
        let session = self.active.ok_or(MonSendError::NoSession)?;
        let handle = self.alloc_tid().ok_or(MonSendError::IdentityExhausted)?;
        let m = MMonGetVersion {
            handle,
            what: what.to_owned(),
        };
        // Register only after a confirmed handoff: a loss during the send fails every registered handle, and a
        // refused one must not leave a request that no reply can ever match.
        if !self.send_any(&m.into(), handle) || self.active != Some(session) {
            return Err(MonSendError::Rejected);
        }
        self.versions.insert(handle);
        Ok(handle)
    }

    /// Remove local version correlation; already handed-off bytes cannot be retracted.
    pub fn cancel_version(&mut self, handle: u64) -> bool {
        self.versions.remove(&handle)
    }

    /// Re-arm existing OSDMap delivery when the held map has not reached `target`.
    pub fn request_osdmap_epoch(&mut self, target: u32) {
        let current = self.osdmap.as_ref().map_or(0, |m| m.epoch);
        if current < target {
            self.request_maps(current + 1);
        }
    }

    /// Send a message to the current mon. `None` if no session (messages are never queued across
    /// sessions, spec 2.2), identities are exhausted, or an MLog lacks its FSID; otherwise the header tid used.
    pub fn send_message(&mut self, m: impl Into<AnyMessage>) -> Option<u64> {
        self.try_send_message(m).ok()
    }

    /// Checked generic handoff; messages are not replayed across sessions.
    pub fn try_send_message(&mut self, m: impl Into<AnyMessage>) -> Result<u64, MonSendError> {
        self.active.ok_or(MonSendError::NoSession)?;
        let tid = self.alloc_tid().ok_or(MonSendError::IdentityExhausted)?;
        self.send_any(&m.into(), tid)
            .then_some(tid)
            .ok_or(MonSendError::Rejected)
    }

    /// Handoff a service-owned codec without extending the shared message enum.
    /// Preserves its header compatibility version; never replayed after session loss.
    pub fn try_send_service_message<M: messages::Message>(
        &mut self,
        message: &M,
        priority: u16,
    ) -> Result<u64, MonSendError> {
        self.active.ok_or(MonSendError::NoSession)?;
        let tid = self.alloc_tid().ok_or(MonSendError::IdentityExhausted)?;
        self.send_encoded_priority(M::MSG_TYPE, tid, priority, |features| {
            Ok((
                M::HEAD_VERSION,
                M::COMPAT_VERSION,
                message.encode(features)?,
            ))
        })
        .then_some(tid)
        .ok_or(MonSendError::Rejected)
    }

    /// Queue a cluster-log entry (sent every `mon_client_log_interval`, resent until acked).
    pub fn log(&mut self, prio: u16, channel: &str, msg: &str) {
        let n = self.cfg.auth_name();
        self.log_seq += 1;
        let e = messages::ByteLogEntry {
            name: messages::ByteCephEntityName { ty: n.ty, id: n.id },
            rank: self.cfg.msgr_name(),
            addrs: self.my_addrs.clone(),
            stamp: UTime::new(self.unix_now() as u32, 0),
            seq: self.log_seq,
            prio,
            msg: msg.to_owned(),
            channel: channel.to_owned(),
        };
        self.logq.push_back(LogQ { e, sent: false });
    }

    /// Force a re-hunt (drop the session and look for a mon again).
    pub fn rehunt(&mut self, why: &str) {
        self.session_lost(why);
    }

    /// Re-anchor the unix clock: `origin` = unix wall time at monotonic 0 (system clock minus the driver's monotonic
    /// now, sub-second like [`wall_now`](Self::wall_now)). The driver calls it every tick with the real system clock, in both directions: cephx rotating-key refresh
    /// and ticket expiry compare against the mon's wall clock, so a clock step must take effect here at once (a stale
    /// forward-only origin refreshed rotating keys late after a forward step, and once per second after a backward one).
    pub fn set_wall_origin(&mut self, origin: Duration) {
        if origin != self.cfg.wall_origin {
            self.cfg.wall_origin = origin;
            self.clock.set(self.wall_now());
        }
    }

    // ---------------------------------------------------------------- internals: misc

    fn set_now(&mut self, now: Duration) {
        self.now = now;
        self.clock.set(self.wall_now());
    }

    /// Unix seconds as this client sees them (cluster-log stamps, rotating-key checks).
    pub fn unix_now(&self) -> u64 {
        self.wall_now().as_secs()
    }

    /// Unix wall time with the monotonic clock's subsecond precision (cephx ticket expiry and renewal).
    pub fn wall_now(&self) -> Duration {
        self.cfg.wall_origin + self.now
    }

    fn alloc_tid(&mut self) -> Option<u64> {
        let t = self.next_tid;
        if t == 0 {
            return None;
        }
        self.next_tid = t.checked_add(1).unwrap_or(0);
        Some(t)
    }

    /// Loud timeout line (`WARNING TIMEOUT <op> exceeded <limit>s (<context>)`) on stderr, counted.
    fn warn_timeout(&mut self, op: &str, limit: Duration, ctx: &str) {
        self.timeouts += 1;
        diag::diag!("{}", deadline::timeout_line(op, limit, ctx));
    }

    fn diag(&mut self, s: impl Into<String>) {
        self.events.push_back(MonEvent::Diag(s.into()));
    }

    fn rand(&mut self) -> u64 {
        splitmix(&mut self.rng)
    }

    fn set_monmap(&mut self, m: MonMap) {
        self.mons = m
            .ranks
            .iter()
            .enumerate()
            .filter_map(|(rank, n)| {
                let i = m.mon_info.get(n)?;
                let target = mon_target(&i.public_addrs, &self.my_addrs)?;
                Some(MonEntry {
                    rank,
                    name: n.clone(),
                    addrs: i.public_addrs.clone(),
                    target,
                    priority: i.priority,
                    weight: i.weight,
                })
            })
            .collect();
        self.monmap = m;
        self.tried.clear();
    }

    // ---------------------------------------------------------------- hunting

    fn start_hunt(&mut self) {
        self.hunts += 1;
        if self.ever_connected && self.hunts > 1 {
            self.reopen_mult =
                (self.reopen_mult * self.cfg.hunt_backoff).min(self.cfg.hunt_max_multiple);
        }
        // abandon the previous round
        let old: Vec<u64> = self.slots.keys().copied().collect();
        for id in old {
            self.drop_slot(id);
        }
        let n = self.mons.len();
        let mut cand: Vec<usize> = if let Some(name) = &self.pinned {
            self.mons
                .iter()
                .position(|m| &m.name == name)
                .into_iter()
                .collect()
        } else {
            match self.cfg.target_rank {
                Some(r) => self
                    .mons
                    .iter()
                    .position(|m| m.rank == r)
                    .into_iter()
                    .collect(),
                None => (0..n).collect(),
            }
        };
        if cand.is_empty() {
            self.diag("hunt: no dialable (v2) mon in monmap");
        }
        let mut avail: Vec<usize> = cand
            .iter()
            .copied()
            .filter(|i| !self.tried.contains(i))
            .collect();
        if avail.is_empty() {
            self.tried.clear();
            avail = std::mem::take(&mut cand);
        }
        if let Some(p) = avail.iter().map(|i| self.mons[*i].priority).min() {
            avail.retain(|i| self.mons[*i].priority == p);
        }
        // weighted shuffle (Efraimidis-Spirakis); all-zero weights = uniform
        let any_w = avail.iter().any(|i| self.mons[*i].weight != 0);
        let mut keyed: Vec<(f64, usize)> = avail
            .iter()
            .map(|i| {
                let w = if any_w {
                    f64::from(self.mons[*i].weight).max(1e-6)
                } else {
                    1.0
                };
                let u = ((self.rand() >> 11) as f64 + 1.0) / ((1u64 << 53) as f64 + 1.0);
                (u.ln() / w, *i)
            })
            .collect();
        keyed.sort_by(|a, b| b.0.total_cmp(&a.0));
        // `mon_client_hunt_parallel` 0 = every candidate at once
        let parallel = match self.cfg.hunt_parallel {
            0 => usize::MAX,
            n => n,
        };
        for (_, i) in keyed.into_iter().take(parallel) {
            self.tried.insert(i);
            self.spawn(i);
        }
        // configured values: an interval x multiple beyond the clock range means "never" rather than a panic
        let iv =
            Duration::try_from_secs_f64(self.cfg.hunt_interval.as_secs_f64() * self.reopen_mult)
                .unwrap_or(Duration::MAX);
        self.hunt_round = iv;
        self.next_hunt = Some(self.now.saturating_add(iv));
    }

    fn spawn(&mut self, mon: usize) {
        let id = self.next_conn;
        self.next_conn += 1;
        let me = &self.mons[mon];
        // fresh auth state per attempt, cloned from the long-lived one (keeps gid + AUTH ticket)
        let cephx = self.auth.cephx.borrow().clone();
        let shared = AuthShared::new_bytes(
            cephx,
            self.cfg.auth_name(),
            self.auth.global_id(),
            self.clock.clone(),
        );
        let handler =
            MonAuthHandler::new(shared.clone(), self.methods.clone(), self.cfg.modes.clone());
        let mut conn = Connection::client(
            id,
            self.msgr_cfg.clone(),
            self.table.clone(),
            Box::new(handler),
            EntityName::MON,
            me.addrs.clone(),
            me.target,
        );
        if let Some((q, base)) = &self.output_queue {
            conn.set_output_queue(q, id | base);
        }
        self.slots.insert(id, Slot { conn, shared, mon });
        self.drain(id);
    }

    fn drop_slot(&mut self, id: u64) {
        if let Some(mut s) = self.slots.remove(&id) {
            s.conn.close();
            self.io.push_back(IoCmd::Close { conn: id });
        }
    }

    fn session_lost(&mut self, why: &str) {
        let Some(id) = self.active.take() else {
            return;
        };
        self.drop_slot(id);
        self.active_mon = None;
        self.active_addr = None;
        self.auth_req_at = None;
        self.events.push_back(MonEvent::SessionLost(why.to_owned()));
        for h in std::mem::take(&mut self.versions) {
            self.events.push_back(MonEvent::VersionFailed { handle: h });
        }
        for tid in std::mem::take(&mut self.commands_once) {
            self.events.push_back(MonEvent::CommandOnceLost { tid });
        }
        // An onetime subscription may already have retired after a capped full-map prefix.
        // Preserve its unfinished fallback demand before dropping this session's wire request.
        if self
            .full_req
            .is_some_and(|(_, end)| end > self.osdmap.as_ref().map_or(0, |map| map.epoch))
        {
            let next = self.osdmap.as_ref().map_or(1, |map| map.epoch + 1);
            let flags = self
                .subs
                .get("osdmap")
                .map_or(SubItem::ONETIME, |sub| sub.flags);
            self.subs.force("osdmap", u64::from(next), flags);
        }
        self.subs.reopen();
        self.map_req = None;
        self.full_req = None;
        for l in &mut self.logq {
            l.sent = false;
        }
        self.start_hunt();
    }

    fn pinned_peer_matches(&self, name: EntityName) -> bool {
        let Some(selected) = &self.pinned else {
            return true;
        };
        name.ty == EntityName::MON
            && (self.monmap.epoch == 0
                || self
                    .monmap
                    .rank_of(selected)
                    .is_some_and(|rank| name.num == rank as i64))
    }
    fn on_ready(&mut self, id: u64, peer: msgr2::PeerInfo) {
        if !self.pinned_peer_matches(peer.name) {
            self.drop_slot(id);
            self.next_hunt = Some(self.now.saturating_add(self.cfg.hunt_interval));
            self.diag("directed monitor peer identity mismatch");
            return;
        }

        if self.active.is_some() {
            self.drop_slot(id); // lost the race
            return;
        }
        let Some(s) = self.slots.get(&id) else { return };
        self.auth = s.shared.clone();
        let mon = s.mon;
        self.active = Some(id);
        self.active_mon = Some(mon);
        self.active_addr = Some(self.mons[mon].target);
        self.features = peer.features;
        let others: Vec<u64> = self.slots.keys().copied().filter(|i| *i != id).collect();
        for o in others {
            self.drop_slot(o);
        }
        self.next_hunt = None;
        self.reopen_mult =
            (self.reopen_mult / self.cfg.hunt_backoff).max(self.cfg.hunt_min_multiple);
        self.ever_connected = true;
        self.ping_unacked = None;
        self.last_ping = self.now;
        self.last_log = self.now;
        self.last_sub_flush = self.now;
        self.tick_at = self.now + TICK;
        let ev = MonEvent::Authenticated {
            global_id: self.auth.global_id(),
            mon: self.mons[mon].name.clone(),
            addr: self.mons[mon].target,
            mode: self.auth.mode.get(),
            method: self.auth.method.get(),
        };
        self.events.push_back(ev);
        // resend state (spec 2.2): subscriptions, commands, log
        self.ready_resend = true;
        self.subs.reopen();
        self.expire_commands();
        self.flush_subs();
        let tids: Vec<u64> = self.cmds.keys().copied().collect();
        for t in tids {
            self.send_cmd(t);
        }
        self.ready_resend = false;
        self.flush_log();
        self.auth_poll();
    }

    // ---------------------------------------------------------------- connection events

    fn drain(&mut self, id: u64) {
        while let Some(ev) = self.slots.get_mut(&id).and_then(|s| s.conn.poll_event()) {
            self.events_drained += 1;
            let is_active = self.active == Some(id);
            match ev {
                Event::Dial { target } => self.io.push_back(IoCmd::Dial { conn: id, target }),
                Event::Connected(p) => self.on_ready(id, p),
                Event::Message(m) => {
                    if is_active {
                        self.on_message(m);
                    }
                }
                // clients have no placement config and never enable the RDMA upgrade
                Event::Handoff { .. }
                | Event::RdmaPrepare
                | Event::RdmaOffer { .. }
                | Event::RdmaAnswer { .. } => {}
                Event::PlacementControl(_) => {
                    self.io.push_back(IoCmd::Close { conn: id });
                    if is_active {
                        self.session_lost("unexpected placement control");
                    }
                }
                Event::KeepaliveAck { sec, nsec } => {
                    if is_active {
                        let acknowledged = Duration::new(u64::from(sec), nsec);
                        if acknowledged >= self.last_ping {
                            self.ping_unacked = None;
                        } else if let Some(baseline) = &mut self.ping_unacked {
                            *baseline = (*baseline).max(acknowledged);
                        }
                        self.acks += 1;
                    }
                }
                Event::Reset | Event::RemoteReset => {
                    if is_active {
                        self.session_lost("connection reset");
                    }
                }
                Event::Fault(r) => {
                    self.io.push_back(IoCmd::Close { conn: id });
                    if let msgr2::FaultReason::Auth(s) = &r {
                        self.events.push_back(MonEvent::AuthFailed(s.clone()));
                    }
                    if is_active {
                        self.session_lost(&format!("fault: {r:?}"));
                    } else {
                        self.diag(format!("conn {id}: fault {r:?}"));
                    }
                }
                Event::Closed => {
                    self.slots.remove(&id);
                    self.io.push_back(IoCmd::Close { conn: id });
                    if is_active {
                        self.session_lost("connection closed");
                    }
                }
            }
        }
    }

    fn on_message(&mut self, m: msgr2::Incoming) {
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
        let msg = match messages::decode_with_header(&h, &m.front, &m.middle, &m.data) {
            Ok(x) => x,
            Err(e) => {
                self.diag(format!("dropping message type {}: {e}", h.ty));
                return;
            }
        };
        match msg {
            AnyMessage::MAuthReply(r) => self.on_auth_reply(r),
            AnyMessage::MMonMap(r) => self.on_monmap(&r.monmap),
            AnyMessage::MMonSubscribeAck(_) => {}
            AnyMessage::MConfig(c) => self.on_config(c.config),
            AnyMessage::MOSDMap(o) => self.on_osdmap(o),
            AnyMessage::MMonCommandAck(a) => {
                if h.tid != 0 && self.commands_once.remove(&h.tid) {
                    self.events.push_back(MonEvent::CommandOnceReply {
                        tid: h.tid,
                        version: a.version,
                        r: a.r,
                        rs: a.rs,
                        cmd: a.cmd,
                        data: a.data,
                    });
                    return;
                }

                let tid = if h.tid == 0 {
                    self.cmds.keys().next().copied()
                } else {
                    Some(h.tid)
                };
                if let Some(t) = tid.filter(|t| self.cmds.remove(t).is_some()) {
                    self.events.push_back(MonEvent::CommandReply {
                        tid: t,
                        r: a.r,
                        rs: a.rs,
                        data: a.data,
                    });
                } else {
                    self.diag(format!("command ack for unknown tid {}", h.tid));
                }
            }
            AnyMessage::MMonGetVersionReply(v) => {
                if self.versions.remove(&v.handle) {
                    self.events.push_back(MonEvent::VersionReply {
                        handle: v.handle,
                        version: v.version,
                        oldest: v.oldest_version,
                    });
                }
            }
            AnyMessage::MLogAck(a) => {
                self.logq.retain(|l| {
                    !(l.e.seq <= a.last && (a.channel.is_empty() || l.e.channel == a.channel))
                });
            }
            AnyMessage::Unknown { ty: 2, .. } => {} // CEPH_MSG_PING
            other => self.events.push_back(MonEvent::Message {
                tid: h.tid,
                msg: Box::new(other),
            }),
        }
    }

    // ---------------------------------------------------------------- sending

    fn send_any(&mut self, m: &AnyMessage, tid: u64) -> bool {
        // Caller-provided logs must identify their cluster too. Do not invent
        // an FSID for messages whose payload does not contain one.
        if matches!(m, AnyMessage::MLog(l) if l.fsid == Uuid::default()) {
            return false;
        }
        self.send_encoded(m.msg_type(), tid, |features| {
            m.encode(features)
                .map(|(_, version, compat, segs)| (version, compat, segs))
        })
    }
    fn send_log(&mut self, m: &messages::ByteMLog, tid: u64) -> bool {
        use messages::Message;
        if m.fsid == Uuid::default() {
            return false;
        }
        self.send_encoded(messages::ByteMLog::MSG_TYPE, tid, |features| {
            Ok((
                messages::ByteMLog::HEAD_VERSION,
                messages::ByteMLog::COMPAT_VERSION,
                m.encode(features)?,
            ))
        })
    }
    fn send_encoded(
        &mut self,
        ty: u16,
        tid: u64,
        encode: impl FnOnce(u64) -> messages::Result<(u16, u16, messages::Segments)>,
    ) -> bool {
        self.send_encoded_priority(ty, tid, 0, encode)
    }
    fn send_encoded_priority(
        &mut self,
        ty: u16,
        tid: u64,
        priority: u16,
        encode: impl FnOnce(u64) -> messages::Result<(u16, u16, messages::Segments)>,
    ) -> bool {
        let Some(id) = self.active else { return false };
        let (version, compat, segs) = match encode(self.features) {
            Ok(x) => x,
            Err(e) => {
                self.diag(format!("encode message {ty}: {e}"));
                return false;
            }
        };
        let message = msgr2::Message {
            msg_type: ty,
            priority,
            tid,
            version,
            compat_version: compat,
            front: segs.front,
            front_zc: segs.front_zc,
            front_hints: segs.front_hints,
            middle: segs.middle,
            data: segs.data,
            ..Default::default()
        };
        // A permanent local frame refusal cannot be repaired by monitor failover.
        // Retire owned legacy commands now, including those queued before connect;
        // a missing session above still preserves them for normal replay.
        if ty == <MMonCommand as messages::Message>::MSG_TYPE
            && self.cmds.contains_key(&tid)
            && !message.fits(&self.msgr_cfg.limits)
        {
            self.cmds.remove(&tid);
            self.events.push_back(MonEvent::CommandReply {
                tid,
                r: -denc::errno::EMSGSIZE,
                rs: "command exceeds local messenger frame limits".into(),
                data: Vec::new(),
            });
            return false;
        }
        let Some(s) = self.slots.get_mut(&id) else {
            return false;
        };
        let accepted = s.conn.send_message(message);
        self.drain(id);
        accepted
    }

    fn send_cmd(&mut self, tid: u64) {
        let Some(c) = self.cmds.get(&tid) else { return };
        if self.cfg.fsid == Uuid::default() {
            return; // the mon rejects a zero fsid; sent once the monmap told us (on_monmap)
        }
        let m = MMonCommand {
            version: 0,
            fsid: self.cfg.fsid,
            cmd: c.cmd.clone(),
            data: c.data.clone(),
        };
        self.send_any(&m.into(), tid);
    }

    /// Send the pending subscription set. Returns true when it was handed to the messenger (or nothing was pending);
    /// a refusal leaves it pending so the next flush resends it.
    fn flush_subs(&mut self) -> bool {
        if self.active.is_none() {
            return false;
        }
        if !self.subs.has_new() {
            return true;
        }
        let Some(tid) = self.alloc_tid() else {
            return false;
        };
        let what = self.subs.take_new();
        let session = self.active;
        let m = MMonSubscribe {
            what: what.clone(),
            hostname: self.cfg.hostname.clone(),
        };
        if !self.send_any(&m.into(), tid) || self.active != session {
            self.subs.unsend(what);
            return false;
        }
        self.last_sub_flush = self.now;
        true
    }

    fn flush_log(&mut self) {
        if self.active.is_none() {
            return;
        }
        if self.cfg.fsid == Uuid::default() {
            self.log_waiting_fsid |= !self.logq.is_empty();
            return;
        }
        self.log_waiting_fsid = false;
        let max = self.cfg.max_log_entries.max(1);
        loop {
            // Sent entries always precede unsent ones: appends add unsent entries,
            // ACKs only remove entries, and session loss resets the entire queue.
            let first = self.logq.partition_point(|l| {
                #[cfg(test)]
                {
                    self.log_flush_visits += 1;
                }
                l.sent
            });
            let entries: Vec<messages::ByteLogEntry> = self
                .logq
                .iter()
                .skip(first)
                .take(max)
                .map(|l| {
                    #[cfg(test)]
                    {
                        self.log_flush_visits += 1;
                    }
                    l.e.clone()
                })
                .collect();
            if entries.is_empty() {
                break;
            }
            let Some(tid) = self.alloc_tid() else { return };
            let from = entries[0].seq;
            let upto = entries.last().map_or(0, |e| e.seq);
            let m = messages::ByteMLog {
                version: 0,
                fsid: self.cfg.fsid,
                entries,
            };
            let session = self.active;
            if !self.send_log(&m, tid) {
                return;
            }
            // Handoff drains messenger events; a concurrent loss resets ownership
            // for the next connection and must not be overwritten here.
            if self.active != session {
                return;
            }
            // ACK handling during handoff can remove entries, so recover the
            // batch's position by sequence instead of retaining its old index.
            let first = self.logq.partition_point(|l| {
                #[cfg(test)]
                {
                    self.log_flush_visits += 1;
                }
                l.e.seq < from
            });
            for l in self
                .logq
                .iter_mut()
                .skip(first)
                .take_while(|l| l.e.seq <= upto)
            {
                #[cfg(test)]
                {
                    self.log_flush_visits += 1;
                }
                l.sent = true;
            }
        }
    }

    // ---------------------------------------------------------------- tick

    fn tick(&mut self) {
        let now = self.now;
        self.tick_at = now + TICK;
        if !self.cfg.ping_timeout.is_zero()
            && self
                .ping_unacked
                .is_some_and(|sent| now.saturating_sub(sent) >= self.cfg.ping_timeout)
        {
            self.warn_timeout(
                "mon keepalive",
                self.cfg.ping_timeout,
                "no ack from active mon, session lost",
            );
            self.session_lost("keepalive timeout");
            return;
        }
        if now.saturating_sub(self.last_ping) >= self.cfg.ping_interval {
            self.last_ping = now;
            if let Some(s) = self.active.and_then(|i| self.slots.get_mut(&i)) {
                s.conn.send_keepalive(now);
                self.ping_unacked.get_or_insert(now);
            }
        }
        self.reopen_mult =
            (self.reopen_mult / self.cfg.hunt_backoff).max(self.cfg.hunt_min_multiple);
        if now.saturating_sub(self.last_log) >= self.cfg.log_interval {
            self.last_log = now;
            self.flush_log();
        }
        if let Some(iv) = self.cfg.sub_renew_interval
            && now.saturating_sub(self.last_sub_flush) >= iv
        {
            self.subs.reopen();
            self.flush_subs();
        }
        if self
            .auth_req_at
            .is_some_and(|t| now.saturating_sub(t) >= AUTH_REQ_TIMEOUT)
        {
            // an established session that leaves a cephx request unanswered is broken: a new session starts the
            // auth state over, so no retired request can shadow the answers to later ones
            self.warn_timeout(
                "mon auth request",
                AUTH_REQ_TIMEOUT,
                "re-hunting the mon session",
            );
            self.rehunt("mon auth request timed out");
        }
        self.auth_poll();
        // flush anything the above queued
        if let Some(id) = self.active {
            self.drain(id);
        }
    }

    /// Command deadlines belong to the request, including time spent without a session.
    fn expire_commands(&mut self) {
        let now = self.now;
        let expired: Vec<u64> = self
            .cmds
            .iter()
            .filter(|(_, c)| c.deadline.is_some_and(|d| d <= now))
            .map(|(t, _)| *t)
            .collect();
        for t in expired {
            self.cmds.remove(&t);
            if let Some(limit) = self.cfg.command_timeout {
                self.warn_timeout("mon command", limit, &format!("tid {t}"));
            }
            self.events.push_back(MonEvent::CommandReply {
                tid: t,
                r: ETIMEDOUT,
                rs: "timed out".into(),
                data: Vec::new(),
            });
        }
    }

    fn auth_poll(&mut self) {
        // Reconnect retains credentials for reclaim, but NONE owns no renewal work.
        if self.active.is_none() || self.auth.method.get() != AUTH_CEPHX || self.next_tid == 0 {
            return;
        }
        let wall = self.wall_now();
        let (req, skew) = match self.auth.cephx.borrow_mut().as_mut() {
            Some(c) => (c.poll(wall), c.rotating_clock_skew(wall)),
            None => return,
        };
        match req {
            Ok(Some(r)) => {
                if skew && r.request_type == cephx::types::CEPHX_GET_ROTATING_KEY {
                    self.diag(format!(
                        "WARNING possible clock skew: rotating keys expired way too early (more than auth_service_ticket_ttl={}s before now)",
                        self.cfg.service_ticket_ttl
                    ));
                }
                let Some(tid) = self.alloc_tid() else { return };
                self.auth_req_at = Some(self.now);
                let m = MAuth {
                    version: 0,
                    protocol: u32::from(AUTH_CEPHX as u16),
                    auth_payload: r.payload,
                    monmap_epoch: 0,
                };
                self.send_any(&m.into(), tid);
            }
            Ok(None) => {}
            Err(e) => self.diag(format!("cephx poll: {e:?}")),
        }
    }

    fn on_auth_reply(&mut self, r: messages::MAuthReply) {
        let wall = self.wall_now();
        let res = match self.auth.cephx.borrow_mut().as_mut() {
            Some(c) => c.on_response(r.result, r.global_id, &r.result_bl, wall),
            None => return,
        };
        match res {
            Ok(MonReply::Installed) => {
                self.auth_req_at = None;
                self.events.push_back(MonEvent::KeysUpdated);
                self.auth_poll();
            }
            Ok(MonReply::Ignored) => {
                // late or stale reply (timed out request, pre-wipe request): keep the session and whatever request
                // is still in flight
                let n = self
                    .auth
                    .cephx
                    .borrow()
                    .as_ref()
                    .map_or(0, |c| c.ignored_replies());
                self.diag(format!(
                    "ignoring MAuthReply that answers no current request ({n} ignored so far)"
                ));
                self.auth_poll();
            }
            Err(e) => {
                self.auth_req_at = None;
                self.events.push_back(MonEvent::AuthFailed(format!(
                    "MAuthReply: {e:?} ({})",
                    r.result_msg
                )));
                self.session_lost("auth renewal failed");
            }
        }
    }

    // ---------------------------------------------------------------- monmap / config / osdmap

    fn on_monmap(&mut self, blob: &[u8]) {
        let m = match MonMap::decode_from(blob) {
            Ok(m) => m,
            Err(e) => return self.diag(format!("bad MMonMap: {e}")),
        };
        if self.cfg.fsid != Uuid::default() && m.fsid != self.cfg.fsid {
            self.diag(format!(
                "dropping monmap from fsid {} (ours {})",
                m.fsid, self.cfg.fsid
            ));
            return;
        }
        let epoch = m.epoch;
        self.subs.got("monmap", u64::from(epoch));
        if epoch == self.monmap.epoch && self.monmap.epoch != 0 {
            return;
        }
        if epoch < self.monmap.epoch {
            return;
        }
        let fsid_learned = self.cfg.fsid == Uuid::default();
        if fsid_learned {
            self.cfg.fsid = m.fsid;
        }
        let cur = self.active_addr;
        let auth_bump = m.auth_epoch > self.monmap.auth_epoch && self.monmap.epoch != 0;
        self.set_monmap(m);
        if auth_bump {
            self.diag("auth epoch changed: wiping rotating secrets and tickets");
            self.wipe_secrets_and_tickets();
        }
        if fsid_learned {
            self.expire_commands();
            let tids: Vec<u64> = self.cmds.keys().copied().collect();
            for t in tids {
                self.send_cmd(t);
            }
            // Entries held before discovery are still unsent; do not wait for
            // another log entry or the periodic flush to publish them.
            if self.log_waiting_fsid && !self.ready_resend {
                self.flush_log();
            }
        }
        self.events.push_back(MonEvent::MonMapUpdated { epoch });
        // re-resolve our mon; vanished (or only v1 now) -> reopen the session
        match cur.and_then(|a| {
            self.mons.iter().position(|e| {
                e.target.ipv4() == a.ipv4()
                    && e.target.ipv6() == a.ipv6()
                    && e.target.port() == a.port()
            })
        }) {
            Some(i) => self.active_mon = Some(i),
            None if self.active.is_some() => self.session_lost("mon not in new monmap"),
            None => {}
        }
    }

    /// Subscribe to complete config maps without the daemon identity-key filter.
    /// Call before start when the initial raw snapshot is required.
    pub fn subscribe_full_config(&mut self) {
        self.cfg.filter_config_identity = false;
        self.subscribe("config", 0, 0);
    }

    fn on_config(&mut self, mut c: BTreeMap<String, String>) {
        if self.cfg.filter_config_identity {
            c.remove("fsid");
            c.remove("host");
        }
        if !self.have_config || c != self.config {
            self.have_config = true;
            self.config = c.clone();
            self.events.push_back(MonEvent::Config(c));
        }
    }

    /// Re-arm the osdmap subscription from `from` (keeps standing/onetime flavour). No-op while an identical
    /// request is outstanding or when the held map already reached `from` (a re-entrant `on_osdmap` may have
    /// moved it past the request).
    fn request_maps(&mut self, from: u32) {
        if self.map_req == Some(from) || from <= self.osdmap.as_ref().map_or(0, |m| m.epoch) {
            return;
        }
        let flags = self
            .subs
            .get("osdmap")
            .map_or(SubItem::ONETIME, |s| s.flags);
        self.subs.force("osdmap", u64::from(from), flags);
        // A send drains the messenger and can handle a newer buffered map re-entrantly; keep a newer request it
        // recorded instead of overwriting it with this (older) epoch.
        if self.flush_subs() && self.map_req.is_none_or(|r| r <= from) {
            self.map_req = Some(from);
        }
    }

    /// Fetch full maps `e..=last` (classic: after a failed incremental, the full maps of the rest of that message).
    /// Deduplicated by range coverage while outstanding, never re-sent by time: the mon answers every request of a live
    /// session; a session reset clears it and the new session's subscription from the next epoch (re-armed by
    /// `session_lost` when unfinished full-map demand outlived a onetime subscription) brings the failing incrementals
    /// again, which ask anew (classic re-requests its full maps on a mon reconnect). An answer whose full
    /// map does not decode ends the request too (`on_osdmap`).
    fn request_full(&mut self, e: u32, last: u32) {
        let last = last.max(e);
        if self
            .full_req
            .is_some_and(|(first, end)| first <= e && last <= end)
            || e <= self.osdmap.as_ref().map_or(0, |m| m.epoch)
        {
            return;
        }
        // An expanded fallback must retain the earlier unanswered prefix too.
        let (e, last) = self
            .full_req
            .map_or((e, last), |(first, end)| (e.min(first), last.max(end)));
        let m = MMonGetOSDMap {
            version: 0,
            full_first: e,
            full_last: last,
            inc_first: 0,
            inc_last: 0,
        };
        // Handoff drains buffered events: reserve before sending so nested map requests see it, and let
        // map progress or session loss clear/replace it without a stale post-send write restoring it.
        let session = self.active;
        let previous = self.full_req;
        self.full_req = Some((e, last));
        if self.send_message(m).is_none()
            && self.active == session
            && self.full_req == Some((e, last))
        {
            self.full_req = previous;
        }
    }

    fn on_osdmap(&mut self, m: MOSDMap) {
        if self.cfg.fsid != Uuid::default() && m.fsid != self.cfg.fsid {
            self.diag(format!(
                "dropping osdmap message from fsid {} (ours {})",
                m.fsid, self.cfg.fsid
            ));
            return;
        }
        let start = self.osdmap.as_ref().map_or(0, |o| o.epoch);
        let mut cur = start;
        let epochs: BTreeSet<u32> = m
            .incremental_maps
            .keys()
            .chain(m.maps.keys())
            .copied()
            .collect();
        let last_in_msg = epochs.last().copied().unwrap_or(0);
        let mut want_full = None;
        let mut gap = false;
        let mut undecodable = false;
        for e in epochs {
            if e <= cur {
                continue;
            }
            let mut done = false;
            if e == cur + 1
                && let Some(blob) = m.incremental_maps.get(&e)
            {
                let base = match &self.osdmap {
                    Some(b) => Some(Arc::clone(b)),
                    None if cur == 0 => Some(Arc::new(OsdMap::default())),
                    None => None,
                };
                if let Some(base) = base {
                    match Incremental::decode_from(blob)
                        .and_then(|i| {
                            if i.epoch != e || i.fsid != m.fsid {
                                return Err(osdmap::Error::Invalid(
                                    "incremental identity differs from message",
                                ));
                            }
                            base.apply_incremental_checked(&i)
                        })
                        .and_then(|map| checked_message_map(map, e, m.fsid))
                    {
                        Ok(nm) => {
                            self.install_osdmap(nm);
                            cur = e;
                            done = true;
                        }
                        Err(err) => {
                            self.inc_fallbacks += 1;
                            #[cfg(feature = "lab")]
                            osdmap_dump::capture(&base, e, blob, self.inc_fallbacks);
                            self.diag(format!(
                                "osdmap inc {e}: {err} (falling back to full maps {e}..={last_in_msg}, {} so far)",
                                self.inc_fallbacks
                            ))
                        }
                    }
                }
            }
            if !done {
                // a full map past a gap is taken only when the sender no longer has the gap (it trimmed it: classic
                // skip_maps); else the gap is fetched first (osd-lifecycle 3.5 step 4), a skipped epoch is a hole in
                // an OSD's stored map history
                let skip_ok = cur == 0
                    || e == cur + 1
                    || (m.cluster_osdmap_trim_lower_bound > cur + 1
                        && e == m.cluster_osdmap_trim_lower_bound);
                if let Some(blob) = m.maps.get(&e).filter(|_| skip_ok) {
                    match OsdMap::decode_from(blob)
                        .and_then(|map| checked_message_map(map, e, m.fsid))
                    {
                        Ok(nm) => {
                            self.install_osdmap(nm);
                            cur = e;
                        }
                        Err(err) => {
                            // the mon's own full map: asking for it again returns the same bytes
                            diag::diag!(
                                "ERROR osdmap full {e} does not decode: {err} (held map stays at epoch {cur}; the \
                                 next map push, subscription renewal or session asks again)"
                            );
                            self.diag(format!("osdmap full {e}: {err}"));
                            self.undecodable = Some((e, err.to_string()));
                            undecodable = true;
                            break;
                        }
                    }
                } else if m.incremental_maps.contains_key(&e) && e == cur + 1 {
                    // inc failed to apply and no full in this message
                    want_full = Some(e);
                    break;
                } else {
                    gap = true;
                    break;
                }
            }
        }
        let progress = cur > start;
        let newest = m.newest_map;
        // Queue the event BEFORE anything that sends: a send drains the connection and can run `on_osdmap` for the
        // next buffered MOSDMap re-entrantly. Queued after it, this event came out behind the newer one and carried
        // the newer map (the OSD then skipped it as old and never stored its epochs: holes in its map history).
        if self.undecodable.as_ref().is_some_and(|(e, _)| *e <= cur) {
            self.undecodable = None;
        }
        // A monitor caps full-map replies by epoch count and bytes. Map progress
        // completes only the received prefix, not the entire requested range.
        let remaining_full = if progress {
            self.full_req
                .take()
                .and_then(|(_, last)| (cur < last).then_some(last))
        } else {
            None
        };
        if progress && let Some(map) = self.osdmap.clone() {
            self.map_req = None;
            self.events.push_back(MonEvent::OsdMap {
                epoch: cur,
                map,
                msg: Box::new(m),
            });
        }
        if cur > 0 {
            self.subs.got("osdmap", u64::from(cur));
        }
        if undecodable {
            // nothing is outstanding any more (the dedup would swallow every later ask for this epoch); the next
            // mon push, subscription renewal or session asks again
            self.map_req = None;
            self.full_req = None;
        } else if let Some(e) = want_full {
            self.request_full(e, last_in_msg.max(remaining_full.unwrap_or(0)));
        } else if let Some(last) = remaining_full {
            self.request_full(cur + 1, last);
        } else if gap {
            // hole in what the mon sent: ask again from the epoch we need next
            self.request_maps(cur + 1);
        } else if newest > cur {
            self.request_maps(cur + 1);
        }
    }
}

/// A valid CRC does not bind a map to its enclosing message's identity.
fn checked_message_map(map: OsdMap, epoch: u32, fsid: Uuid) -> osdmap::Result<OsdMap> {
    if map.epoch != epoch {
        return Err(osdmap::Error::Invalid("map epoch differs from message key"));
    }
    if map.fsid != fsid {
        return Err(osdmap::Error::FsidMismatch);
    }
    Ok(map)
}

/// Reason of the immediate [`MonEvent::AuthFailed`] of [`MonClient::start`] without a usable auth method.
pub const NO_AUTH_METHOD: &str = "no supported authentication method found (cephx configured but no keyring/key, or an empty auth method list)";

/// The methods a session offers: `configured` without cephx when there is no key.
fn usable_methods(configured: &[u32], have_key: bool) -> Vec<u32> {
    let mut methods = configured.to_vec();
    if !have_key {
        methods.retain(|m| *m != AUTH_CEPHX);
    }
    methods
}

fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn log_catchup_does_not_rescan_sent_prefix_per_batch() {
        let mut cfg = Config::new("client.test", None);
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300").unwrap();
        cfg.fsid = Uuid([7; 16]);
        cfg.max_log_entries = 1;
        let mut c = MonClient::new(cfg);
        c.spawn(0);
        c.active = Some(c.conn_ids()[0]);
        let count = 1024usize;
        for _ in 0..count {
            c.log(1, "cluster", "catch-up");
        }
        c.flush_log();
        assert!(c.logq.iter().all(|entry| entry.sent));
        // Two binary searches per batch, one clone and one state update.
        // Include the final empty probe.
        let bound = (count + 1) * 2 * (count.ilog2() as usize + 1) + 2 * count;
        diag::diag!("{count} log entries: {} queue visits", c.log_flush_visits);
        assert!(
            c.log_flush_visits <= bound,
            "{} queue visits exceed {bound}",
            c.log_flush_visits
        );
        c.log_flush_visits = 0;
        c.flush_log();
        assert!(c.log_flush_visits <= count.ilog2() as usize + 1);
    }

    #[test]
    fn full_config_snapshot_identity_filter_is_explicit_native_policy() {
        let snapshot: BTreeMap<_, _> = [
            ("fsid".into(), "raw-fsid".into()),
            ("host".into(), "raw-host".into()),
            ("rbd_cache".into(), "false".into()),
        ]
        .into();
        let mut strict = MonClient::new(Config::new_client("client.test", None));
        strict.on_config(snapshot.clone());
        assert_eq!(strict.config().len(), 1);
        let mut cfg = Config::new_client("client.test", None);
        cfg.filter_config_identity = false;
        let mut raw = MonClient::new(cfg);
        raw.on_config(snapshot.clone());
        assert_eq!(raw.config(), &snapshot);
    }
    #[test]
    fn frame_policy_is_explicit_and_independent_of_client_identity() {
        for entity in ["client.test", "osd.3", "mgr.name with spaces"] {
            let strict = MonClient::new(Config::new_client(entity, None));
            assert_eq!(strict.frame_limits(), msgr2::Limits::default());
            let mut cfg = Config::new_client(entity, None);
            cfg.frame_limits = msgr2::Limits::wire_shape();
            let compatible = MonClient::new(cfg);
            assert_eq!(compatible.frame_limits(), msgr2::Limits::wire_shape());
            assert_eq!(compatible.msgr_cfg.name, strict.msgr_cfg.name);
            assert_eq!(compatible.cfg.auth_name(), strict.cfg.auth_name());
        }
        let mut cfg = Config::new_client("client.test", None);
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300").unwrap();
        let seed = |cfg| {
            crate::MonitorTargetSeed::from_config(cfg, crate::MonitorTarget::Rank(0)).unwrap()
        };
        assert_eq!(
            seed(cfg.clone())
                .into_client_limits(msgr2::Limits::wire_shape())
                .frame_limits(),
            msgr2::Limits::wire_shape()
        );
        assert_eq!(seed(cfg).into_client().frame_limits().max_segment, 33 << 20);
    }

    #[test]
    fn address_view_never_falls_back_to_configured_or_missing_active_slot() {
        let mut c = MonClient::new(Config::new("client.test", None));
        assert!(c.local_addresses().is_none());
        c.active = Some(99);
        assert!(c.local_addresses().is_none());
    }
    /// `mon_client_target_rank` names a monmap rank; ranks without a v2 address are filtered from the dial list, so the
    /// option must not be used as an index into that filtered list.
    #[test]
    fn target_rank_selects_the_monmap_rank_not_the_filtered_index() {
        let mut map = MonMap {
            fsid: Uuid([7; 16]),
            epoch: 1,
            ..Default::default()
        };
        let addrs = [
            EntityAddr::v4(EntityAddr::TYPE_LEGACY, 0, [10, 0, 0, 1], 6789),
            EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [10, 0, 0, 2], 3300),
            EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [10, 0, 0, 3], 3300),
        ];
        for (rank, a) in addrs.into_iter().enumerate() {
            let name = format!("mon{rank}");
            map.ranks.push(name.clone());
            map.mon_info.insert(
                name.clone(),
                osdmap::MonInfo {
                    name,
                    public_addrs: EntityAddrVec::single(a),
                    ..Default::default()
                },
            );
        }
        let mut cfg = Config::new("osd.1", None);
        cfg.methods = vec![AUTH_NONE];
        cfg.initial_monmap = Some(map);
        cfg.target_rank = Some(1);
        cfg.hunt_parallel = 1;
        let mut c = MonClient::new(cfg);
        c.start(Duration::ZERO);
        match c.poll_io() {
            Some(IoCmd::Dial { target, .. }) => assert_eq!(target.ipv4(), Some([10, 0, 0, 2])),
            other => panic!("unexpected first IO {other:?}"),
        }
    }
    #[test]
    fn last_identity_is_issued_once_and_rehunt_never_reopens_domain() {
        let mut c = MonClient::new(Config::new("client.test", None));
        c.next_tid = u64::MAX - 1;
        assert_eq!(c.alloc_tid(), Some(u64::MAX - 1));
        assert_eq!(c.try_send_command("{}", vec![]), Some(u64::MAX));
        assert_eq!(c.cmds.len(), 1);
        assert_eq!(c.alloc_tid(), None);
        assert_eq!(c.try_send_command("{}", vec![]), None);
        assert_eq!(c.send_command("{}", vec![]), 0);
        assert_eq!(c.cmds.len(), 1);
        // Exercise the real session-loss path, not an allocator-only reset.
        c.active = Some(99);
        c.rehunt("identity boundary fixture");
        assert_eq!(c.alloc_tid(), None);
        assert!(c.cmds.contains_key(&u64::MAX));
    }

    #[test]
    fn abandoned_command_releases_payload_and_reconnect_replay() {
        let mut c = MonClient::new(Config::new("client.test", None));
        let retired = c
            .try_send_command("{\"prefix\":\"old\"}", vec![7; 8192])
            .unwrap();
        let live = c.try_send_command("{\"prefix\":\"live\"}", vec![]).unwrap();
        assert!(c.cancel_command(retired));
        assert!(!c.cancel_command(retired));
        c.active = Some(99);
        c.rehunt("command cancellation fixture");
        assert_eq!(c.cmds.len(), 1);
        assert!(c.cmds.contains_key(&live));
        assert!(!c.cmds.contains_key(&retired));
    }

    #[test]
    fn exhausted_consumers_preserve_pending_state_and_do_not_generate_requests() {
        let mut cfg = Config::new("client.test", None);
        cfg.fsid = Uuid([7; 16]);
        let mut c = MonClient::new(cfg);
        c.next_tid = 0;
        c.active = Some(99);
        assert_eq!(c.get_version("osdmap"), None);
        assert!(c.versions.is_empty());
        assert_eq!(
            c.try_send_message(MMonGetOSDMap::default()),
            Err(MonSendError::IdentityExhausted)
        );
        assert_eq!(c.send_message(MMonGetOSDMap::default()), None);
        assert_eq!(c.try_send_command("{}", vec![]), None);
        assert!(c.cmds.is_empty());
        c.subscribe("fixture", 17, 0);
        assert!(c.subs.has_new());
        c.log(0, "test", "retained at identity exhaustion");
        c.flush_log();
        assert_eq!(c.logq.len(), 1);
        assert!(!c.logq[0].sent);
        c.auth_poll();
        assert_eq!(c.auth_req_at, None);
        assert!(c.io.is_empty());
        c.active = None;
        assert_eq!(
            c.try_send_message(MMonGetOSDMap::default()),
            Err(MonSendError::NoSession)
        );
    }
}

#[cfg(test)]
mod method_tests {
    use super::*;

    /// The wall origin keeps its fraction: monc's clock equals the OSD's nanosecond peer-authorizer clock.
    #[test]
    fn wall_origin_is_sub_second() {
        let mut c = MonClient::new(Config::new("osd.1", None));
        let origin = Duration::new(1_700_000_000, 123_456_789);
        c.set_wall_origin(origin);
        c.set_now(Duration::from_millis(1_500));
        assert_eq!(c.wall_now(), origin + Duration::from_millis(1_500));
        assert_eq!(c.unix_now(), 1_700_000_001);
    }

    /// A changed method list applies to the next connection; without a key cephx never enters it.
    #[test]
    fn set_methods_filters_cephx_without_a_key() {
        let mut c = MonClient::new(Config::new("osd.1", None));
        c.set_methods(&[AUTH_CEPHX, AUTH_NONE]);
        assert_eq!(c.methods, [AUTH_NONE]);
        c.set_methods(&[AUTH_CEPHX]);
        assert!(c.methods.is_empty());
        c.set_methods(&[]);
        assert!(c.methods.is_empty());
        // no usable method: start refuses at once (no dial), AuthFailed is queued
        c.start(Duration::ZERO);
        assert!(c.poll_io().is_none());
        assert!(matches!(c.poll_event(), Some(MonEvent::AuthFailed(w)) if w == NO_AUTH_METHOD));
        let key = cephx::CryptoKey::generate(cephx::KeyType::Aes, cephx::UTime::new(1, 0)).unwrap();
        let mut c = MonClient::new(Config::new("osd.1", Some(key)));
        c.set_methods(&[AUTH_NONE, AUTH_CEPHX]);
        assert_eq!(c.methods, [AUTH_NONE, AUTH_CEPHX]);
    }

    /// `rotate-key` needs a loaded cephx key; it replaces the key the next authentication uses.
    #[test]
    fn rotate_key_needs_cephx() {
        let k =
            |s| cephx::CryptoKey::generate(cephx::KeyType::Aes, cephx::UTime::new(s, 0)).unwrap();
        let mut c = MonClient::new(Config::new("osd.1", None));
        assert!(!c.rotate_key(k(1)));
        assert!(c.cfg.key.is_none());
        let mut c = MonClient::new(Config::new("osd.1", Some(k(1))));
        let kn = k(2);
        assert!(c.rotate_key(kn.clone()));
        assert_eq!(c.cfg.key.as_ref(), Some(&kn));
    }

    /// A monmap with a higher `auth_epoch` wipes rotating secrets and tickets and tells the owner (KeysUpdated); the
    /// first monmap and an unchanged auth epoch do not.
    #[test]
    fn auth_epoch_bump_wipes_secrets() {
        let key = cephx::CryptoKey::generate(cephx::KeyType::Aes, cephx::UTime::new(1, 0)).unwrap();
        let mut c = MonClient::new(Config::new("osd.1", Some(key)));
        let wiped = |c: &mut MonClient| {
            std::iter::from_fn(|| c.poll_event()).any(|e| matches!(e, MonEvent::KeysUpdated))
        };
        let map = |epoch, auth_epoch| {
            MonMap {
                epoch,
                auth_epoch,
                ..MonMap::default()
            }
            .encode_to()
            .unwrap()
        };
        c.on_monmap(&map(1, 3));
        assert!(!wiped(&mut c));
        c.on_monmap(&map(2, 3));
        assert!(!wiped(&mut c));
        c.on_monmap(&map(3, 4));
        assert!(wiped(&mut c));
    }
}

#[cfg(test)]
mod handoff_tests {
    use super::*;
    #[test]
    fn once_admission_requires_ready_known_fsid_and_unused_identity() {
        // Auth-none in-memory fixture only; no native CephX policy change.
        #[derive(Debug)]
        struct Accept;
        impl msgr2::auth::AuthServerHandler for Accept {
            fn supported_methods(&self, _: u8) -> Vec<u32> {
                vec![msgr2::auth::AUTH_METHOD_NONE]
            }
            fn supported_modes(&self, _: u8, _: u32) -> Vec<u32> {
                vec![msgr2::auth::MODE_CRC]
            }
            fn handle_auth_request(
                &mut self,
                _: u8,
                _: bool,
                _: u32,
                _: u32,
                _: &[u8],
            ) -> msgr2::auth::AuthServerStep {
                msgr2::auth::AuthServerStep::Done {
                    reply: vec![],
                    global_id: 7,
                    peer_name: None,
                    secrets: Default::default(),
                }
            }
        }
        let mut cfg = Config::new("client.test", None);
        cfg.fsid = Uuid([7; 16]);
        cfg.methods = vec![AUTH_NONE];
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300").unwrap();
        let mut c = MonClient::new(cfg);
        let before = c.next_tid;
        assert_eq!(
            c.try_send_command_once("{}", vec![]),
            Err(MonSendError::NoSession)
        );
        assert_eq!(c.next_tid, before);
        c.spawn(0);
        let id = c.conn_ids()[0];
        c.active = Some(id);
        assert_eq!(
            c.try_send_command_once("{}", vec![]),
            Err(MonSendError::NoSession)
        );
        c.active = None;
        let address = c.mons[0].target;
        let scfg = msgr2::Config::new(
            EntityName::new(EntityName::MON, 0),
            EntityAddrVec::single(address),
            PolicyTable::uniform(Policy::stateless_server(0)),
        );
        let mut server = Connection::server(
            999,
            scfg,
            SessionTable::new(2),
            Box::new(Accept),
            EntityAddr::v4(2, 0, [127, 0, 0, 2], 40000),
            Duration::ZERO,
        );
        c.on_connected(id, Duration::ZERO);
        for _ in 0..32 {
            let out = c.poll_output(id);
            if !out.is_empty() {
                server.on_bytes(&out, Duration::ZERO);
            }
            let out = server.poll_output();
            if !out.is_empty() {
                c.on_bytes(id, &out, Duration::ZERO);
            }
        }
        assert!(c.is_connected());
        assert_eq!(c.slots[&id].conn.state(), msgr2::ConnState::Ready);
        c.cfg.fsid = Uuid::default();
        let before = c.next_tid;
        assert_eq!(
            c.try_send_command_once("{}", vec![]),
            Err(MonSendError::Rejected)
        );
        assert_eq!(c.next_tid, before);
        c.cfg.fsid = Uuid([7; 16]);
        c.next_tid = u64::MAX;
        assert_eq!(c.try_send_command_once("{}", vec![]), Ok(u64::MAX));
        assert_eq!(
            c.try_send_command_once("{}", vec![]),
            Err(MonSendError::IdentityExhausted)
        );
        assert!(c.cancel_command_once(u64::MAX));
        assert_eq!(c.next_tid, 0);
        assert!(c.commands_once.is_empty());
        c.slots.get_mut(&id).unwrap().conn.close();
        assert_eq!(
            c.try_send_command_once("{}", vec![]),
            Err(MonSendError::NoSession)
        );
        assert!(c.commands_once.is_empty());
        assert!(c.cmds.is_empty());
    }
    #[test]
    fn encoded_service_and_existing_messages_preserve_wire_bytes_and_shared_front() {
        #[derive(Debug)]
        struct Accept;
        impl msgr2::auth::AuthServerHandler for Accept {
            fn supported_methods(&self, _: u8) -> Vec<u32> {
                vec![AUTH_NONE]
            }
            fn supported_modes(&self, _: u8, _: u32) -> Vec<u32> {
                vec![msgr2::auth::MODE_CRC]
            }
            fn handle_auth_request(
                &mut self,
                _: u8,
                _: bool,
                _: u32,
                _: u32,
                _: &[u8],
            ) -> msgr2::auth::AuthServerStep {
                msgr2::auth::AuthServerStep::Done {
                    reply: vec![],
                    global_id: 7,
                    peer_name: None,
                    secrets: Default::default(),
                }
            }
        }
        fn exchange(c: &mut MonClient, server: &mut Connection, id: u64) -> Vec<msgr2::Incoming> {
            let mut received = Vec::new();
            for _ in 0..32 {
                let out = c.poll_output(id);
                server.on_bytes(&out, Duration::ZERO);
                let out = server.poll_output();
                c.on_bytes(id, &out, Duration::ZERO);
                while let Some(event) = server.poll_event() {
                    match event {
                        Event::Message(message) => received.push(message),
                        Event::Fault(e) => panic!("wire regression: {e:?}"),
                        _ => {}
                    }
                }
            }
            received
        }
        let mut cfg = Config::new("client.test", None);
        cfg.fsid = Uuid([7; 16]);
        cfg.methods = vec![AUTH_NONE];
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300").unwrap();
        let mut c = MonClient::new(cfg);
        c.start(Duration::ZERO);
        let id = c.conn_ids()[0];
        let target = c.mons[0].target;
        let mut server = Connection::server(
            999,
            msgr2::Config::new(
                EntityName::new(EntityName::MON, 0),
                EntityAddrVec::single(target),
                PolicyTable::uniform(Policy::stateless_server(0)),
            ),
            SessionTable::new(2),
            Box::new(Accept),
            EntityAddr::v4(2, 0, [127, 0, 0, 2], 40000),
            Duration::ZERO,
        );
        c.on_connected(id, Duration::ZERO);
        exchange(&mut c, &mut server, id);
        assert!(c.is_connected());
        // These existing mon/OSD/client messages retain the exact previous payloads.
        let messages: Vec<AnyMessage> = vec![
            messages::MMonSubscribe::default().into(),
            messages::MMonGetVersion::default().into(),
            MMonGetOSDMap::default().into(),
            messages::MMonCommand {
                fsid: Uuid([7; 16]),
                cmd: vec!["{}".into()],
                data: vec![1, 2, 3],
                ..Default::default()
            }
            .into(),
            messages::MOSDBoot::default().into(),
        ];
        for (index, message) in messages.iter().enumerate() {
            let (_, version, compat, expected) = message.encode(c.features).unwrap();
            assert!(expected.front_zc.is_empty());
            assert!(expected.front_hints.is_empty());
            let tid = 100 + index as u64;
            assert!(c.send_any(message, tid));
            let received = exchange(&mut c, &mut server, id);
            let received = received.iter().find(|m| m.header.tid == tid).unwrap();
            assert_eq!(
                (
                    received.header.msg_type,
                    received.header.version,
                    received.header.compat_version
                ),
                (message.msg_type(), version, compat)
            );
            assert_eq!(
                &received.front[..],
                expected.front_bytes().unwrap().as_ref()
            );
            assert_eq!(&received.middle[..], &expected.middle);
            assert_eq!(received.data, expected.data);
        }
        let mut segments = messages::Segments::front(b"headtail".to_vec());
        segments.front_zc.push((4, vec![0x5a; 8192].into()));
        let shared = &segments.front_zc[0].1;
        // Independent CRC32C, seed !0, no final xor (msgr2 spec).
        let mut checksum = !0u32;
        for byte in shared {
            checksum ^= u32::from(*byte);
            for _ in 0..8 {
                checksum = (checksum >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(checksum & 1));
            }
        }
        segments.front_hints = vec![msgr2::CrcHint::new(shared, checksum)].into();
        assert_eq!(segments.front_hints.of(shared), Some(checksum));
        segments.middle = b"middle".to_vec();
        segments.data = b"data".to_vec().into();
        let expected = segments.front_bytes().unwrap().into_owned();
        assert!(c.send_encoded_priority(60000, 200, 196, |_| Ok((8, 6, segments))));
        let received = exchange(&mut c, &mut server, id);
        let received = received.iter().find(|m| m.header.tid == 200).unwrap();
        assert_eq!(
            (
                received.header.version,
                received.header.compat_version,
                received.header.priority
            ),
            (8, 6, 196)
        );
        assert_eq!(&received.front[..], &expected);
        assert_eq!(&received.middle[..], b"middle");
        assert_eq!(&received.data[..], b"data");
        c.slots.get_mut(&id).unwrap().conn.close();
        assert_eq!(
            c.try_send_service_message(&messages::MMonGetVersion::default(), 196),
            Err(MonSendError::Rejected)
        );
    }
    #[test]
    fn closed_messenger_cannot_report_accepted_generic_handoff() {
        let mut cfg = Config::new("client.test", None);
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300").unwrap();
        let mut c = MonClient::new(cfg);
        c.spawn(0);
        let id = c.conn_ids()[0];
        c.active = Some(id);
        c.slots.get_mut(&id).unwrap().conn.close();
        assert_eq!(
            c.try_send_message(MMonGetOSDMap::default()),
            Err(MonSendError::Rejected)
        );
        assert_ne!(
            c.next_tid, 1,
            "a rejected handoff may consume an ID but never reuse it"
        );
    }
    /// A refused version request must not report the handle as queued: the caller gets `Rejected` and no handle stays
    /// pending (the session loss triggered by the refused handoff fails it in the same call).
    #[test]
    fn refused_version_request_reports_rejection_instead_of_ok() {
        let mut cfg = Config::new("client.test", None);
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300").unwrap();
        let mut c = MonClient::new(cfg);
        c.spawn(0);
        let id = c.conn_ids()[0];
        c.active = Some(id);
        c.slots.get_mut(&id).unwrap().conn.close();
        assert_eq!(c.try_get_version("osdmap"), Err(MonSendError::Rejected));
        assert!(c.versions.is_empty());
    }
    /// A refused subscribe/request handoff must not be recorded as sent: the subscription stays pending and the map
    /// request is not marked outstanding, so the next flush resends it instead of waiting for a session reset or the
    /// 1-day renewal.
    #[test]
    fn refused_subscription_handoff_stays_pending_and_keeps_map_request_rearmable() {
        let mut c = MonClient::new(Config::new("client.test", None));
        c.active = Some(1); // active session without a slot: the messenger refuses the frame
        c.subscribe("osdmap", 5, 0);
        assert!(c.subs.has_new(), "refused subscribe must stay pending");
        assert_eq!(c.subs.get("osdmap").map(|s| s.start), Some(5));
        c.request_maps(6);
        assert_eq!(
            c.map_req, None,
            "no outstanding map request after a refusal"
        );
        assert_eq!(c.subs.get("osdmap").map(|s| s.start), Some(6));
    }
    #[test]
    fn byte_client_log_queue_owns_principal_and_preserves_text_message_surfaces() {
        let mut input = b"mgr.\xff spaces.more".to_vec();
        let cfg = Config::new_client_bytes(&input, None);
        let mut client = MonClient::new_bytes(cfg);
        client.log(1, "cluster", "message \u{e4}");
        input.fill(b'x');
        client.cfg.entity = b"client.changed".to_vec();
        assert_eq!(client.logq.len(), 1);
        assert_eq!(client.log_seq, 1);
        assert_eq!(client.logq[0].e.name.ty, cephx::none::ENTITY_MGR);
        assert_eq!(client.logq[0].e.name.id, b"\xff spaces.more");
        assert_eq!(client.logq[0].e.msg, "message \u{e4}");
        assert_eq!(client.logq[0].e.channel, "cluster");
        let entry = client.logq[0].e.clone();
        drop(client);
        assert_eq!(entry.name.id, b"\xff spaces.more");
        let mut native = MonClient::new(Config::new_client("client.text", None));
        native.log(1, "cluster", "message");
        assert_eq!(native.logq[0].e.name.id, b"text");
    }
    #[test]
    fn byte_logs_use_messenger_and_preserve_fsid_ack_resend_and_rejected_handoff_ownership() {
        use messages::Message;
        #[derive(Debug)]
        struct Accept;
        impl msgr2::auth::AuthServerHandler for Accept {
            fn supported_methods(&self, _: u8) -> Vec<u32> {
                vec![AUTH_NONE]
            }
            fn supported_modes(&self, _: u8, _: u32) -> Vec<u32> {
                vec![cephx::modes::CON_MODE_CRC]
            }
            fn handle_auth_request(
                &mut self,
                peer: u8,
                more: bool,
                method: u32,
                _: u32,
                payload: &[u8],
            ) -> msgr2::auth::AuthServerStep {
                assert_eq!(peer, EntityName::CLIENT);
                assert!(!more);
                assert_eq!(method, AUTH_NONE);
                let mut d = denc::Decoder::new(payload);
                assert_eq!(d.u8().unwrap(), cephx::none::AUTH_MODE_MON);
                let name = <cephx::none::ByteEntityName as denc::Decode>::decode(&mut d).unwrap();
                assert_eq!(name.ty, cephx::none::ENTITY_MGR);
                assert_eq!(name.id, b"\xff spaces.more");
                msgr2::auth::AuthServerStep::Done {
                    reply: vec![],
                    global_id: 7,
                    peer_name: None,
                    secrets: Default::default(),
                }
            }
        }
        fn server(target: EntityAddr) -> Connection {
            Connection::server(
                999,
                msgr2::Config::new(
                    EntityName::new(EntityName::MON, 0),
                    EntityAddrVec::single(target),
                    PolicyTable::uniform(Policy::stateless_server(0)),
                ),
                SessionTable::new(2),
                Box::new(Accept),
                EntityAddr::v4(2, 0, [127, 0, 0, 1], 40000),
                Duration::ZERO,
            )
        }
        fn exchange(
            c: &mut MonClient,
            server: &mut Connection,
            id: u64,
        ) -> Vec<messages::ByteMLog> {
            let mut logs = Vec::new();
            for _ in 0..64 {
                let out = c.poll_output(id);
                if !out.is_empty() {
                    server.on_bytes(&out, Duration::ZERO);
                }
                let incoming = server.poll_output();
                if !incoming.is_empty() {
                    c.on_bytes(id, &incoming, Duration::ZERO);
                }
                while let Some(event) = server.poll_event() {
                    match event {
                        Event::Message(m) if m.header.msg_type == messages::ByteMLog::MSG_TYPE => {
                            logs.push(
                                messages::ByteMLog::decode(
                                    m.header.version,
                                    &m.front,
                                    &m.middle,
                                    &m.data,
                                )
                                .unwrap(),
                            );
                        }
                        Event::Fault(error) => panic!("in-memory log exchange: {error:?}"),
                        _ => {}
                    }
                }
                if out.is_empty() && incoming.is_empty() {
                    return logs;
                }
            }
            panic!("in-memory log exchange did not quiesce");
        }
        fn ack(server: &mut Connection, channel: &str) {
            let message = messages::MLogAck {
                fsid: Uuid([7; 16]),
                last: 2,
                channel: channel.into(),
            };
            let segments = message.encode(u64::MAX).unwrap();
            assert!(server.send_message(msgr2::Message {
                msg_type: messages::MLogAck::MSG_TYPE,
                version: messages::MLogAck::HEAD_VERSION,
                compat_version: messages::MLogAck::COMPAT_VERSION,
                front: segments.front,
                middle: segments.middle,
                data: segments.data,
                ..Default::default()
            }));
        }
        let mut input = b"mgr.\xff spaces.more".to_vec();
        let mut cfg = Config::new_client_bytes(&input, None);
        cfg.methods = vec![AUTH_NONE];
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300").unwrap();
        cfg.default_subs = false;
        cfg.max_log_entries = 1;
        let mut c = MonClient::new_bytes(cfg);
        c.log(1, "alpha", "first");
        c.log(2, "beta", "second");
        input.fill(b'x');
        c.spawn(0);
        let id = c.conn_ids()[0];
        let target = c.mons[0].target;
        let mut peer = server(target);
        c.on_connected(id, Duration::ZERO);
        assert!(exchange(&mut c, &mut peer, id).is_empty());
        assert!(c.is_connected());
        assert!(c.log_waiting_fsid);
        assert!(c.logq.iter().all(|entry| !entry.sent));
        assert!(!c.send_log(&messages::ByteMLog::default(), 17));
        assert!(!c.send_any(&messages::MLog::default().into(), 18));
        let mut map = c.monmap.clone();
        map.fsid = Uuid([7; 16]);
        map.epoch = 1;
        c.on_monmap(&map.encode_to().unwrap());
        let logs = exchange(&mut c, &mut peer, id);
        assert_eq!(logs.len(), 2);
        assert!(c.logq.iter().all(|entry| entry.sent));
        for (index, log) in logs.iter().enumerate() {
            assert_eq!(log.fsid, Uuid([7; 16]));
            assert_eq!(log.entries.len(), 1);
            let expected = &c.logq[index].e;
            let actual = &log.entries[0];
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.rank, expected.rank);
            assert_eq!(actual.stamp, expected.stamp);
            assert_eq!(actual.seq, expected.seq);
            assert_eq!(actual.prio, expected.prio);
            assert_eq!(actual.msg, expected.msg);
            assert_eq!(actual.channel, expected.channel);
            assert_eq!(log.entries[0].name.id, b"\xff spaces.more");
            assert_eq!(log.entries[0].rank.ty, EntityName::CLIENT);
        }
        ack(&mut peer, "alpha");
        assert!(exchange(&mut c, &mut peer, id).is_empty());
        assert_eq!(c.logq.len(), 1);
        assert_eq!(c.logq[0].e.channel, "beta");
        c.rehunt("log ownership fixture");
        assert!(!c.logq[0].sent);
        let next = c.conn_ids()[0];
        let mut next_peer = server(target);
        c.on_connected(next, Duration::ZERO);
        let resent = exchange(&mut c, &mut next_peer, next);
        assert_eq!(resent, vec![logs[1].clone()]);
        ack(&mut next_peer, "beta");
        assert!(exchange(&mut c, &mut next_peer, next).is_empty());
        assert!(c.logq.is_empty());
        c.log(1, "cluster", "retained on rejected handoff");
        c.slots.get_mut(&next).unwrap().conn.close();
        c.flush_log();
        assert_eq!(c.logq.len(), 1);
        assert!(!c.logq[0].sent);
        let retained = c.logq[0].e.clone();
        drop(c);
        assert_eq!(retained.name.id, b"\xff spaces.more");
    }
}

#[cfg(test)]
mod version_control_tests {
    use super::*;
    #[test]
    fn checked_version_admission_cancel_and_identity_exhaustion() {
        let mut cfg = Config::new("client.test", None);
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300").unwrap();
        let mut c = MonClient::new(cfg);
        assert_eq!(c.try_get_version("osdmap"), Err(MonSendError::NoSession));
        assert!(c.versions.is_empty());
        c.spawn(0);
        let id = c.conn_ids()[0];
        c.active = Some(id);
        c.next_tid = u64::MAX;
        assert_eq!(c.try_get_version("osdmap"), Ok(u64::MAX));
        assert!(c.cancel_version(u64::MAX));
        assert!(!c.cancel_version(u64::MAX));
        assert!(c.versions.is_empty());
        assert_eq!(
            c.try_get_version("osdmap"),
            Err(MonSendError::IdentityExhausted)
        );
        assert_eq!(c.get_version("osdmap"), None);
        assert!(c.versions.is_empty());
    }
    #[test]
    fn explicit_epoch_delivery_is_deduplicated_and_does_not_overflow() {
        let mut cfg = Config::new("client.test", None);
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300").unwrap();
        let mut c = MonClient::new(cfg);
        c.spawn(0);
        let id = c.conn_ids()[0];
        c.active = Some(id);
        let mut map = OsdMap::default();
        map.epoch = u32::MAX;
        c.set_osdmap(map);
        c.request_osdmap_epoch(u32::MAX);
        assert_eq!(c.map_req, None);
        let mut map = OsdMap::default();
        map.epoch = 4;
        c.set_osdmap(map);
        c.request_osdmap_epoch(8);
        assert_eq!(c.map_req, Some(5));
        c.request_osdmap_epoch(9);
        assert_eq!(c.map_req, Some(5));
    }
}

#[cfg(test)]
mod blocked_output_tests {
    use super::*;
    #[test]
    fn blanket_output_exception_never_masks_owned_events_or_io() {
        let mut c = MonClient::new(Config::new("client.test", None));
        assert!(!c.has_pending_work_with_blocked_output(&|_| true));
        c.events
            .push_back(MonEvent::AuthFailed("test rejection".into()));
        assert!(c.has_pending_work_with_blocked_output(&|_| true));
        c.poll_event().unwrap();
        c.io.push_back(IoCmd::Close { conn: 9 });
        assert!(c.has_pending_work_with_blocked_output(&|_| true));
        c.poll_io().unwrap();
        assert!(!c.has_pending_work_with_blocked_output(&|_| true));
    }
}

#[cfg(test)]
mod pg_watch_tests {
    use super::*;
    use denc::types::PgT;

    fn fixture() -> OsdMap {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/osdmap/full/0091.bin");
        OsdMap::decode_from(&std::fs::read(p).unwrap()).unwrap()
    }
    /// Encoded incremental `prev -> prev.epoch + 1` with `f` applied, and the resulting map.
    fn inc(prev: &OsdMap, f: impl FnOnce(&mut Incremental)) -> (Vec<u8>, OsdMap) {
        let mut i = Incremental {
            fsid: prev.fsid,
            epoch: prev.epoch + 1,
            ..Default::default()
        };
        f(&mut i);
        let mut next = prev.clone();
        next.apply_incremental(&i).unwrap();
        i.full_crc = next.crc(0).unwrap();
        (i.encode_inc().unwrap(), next)
    }

    /// One MOSDMap carries a primary move and its return: the watch sees both epochs although the client handles the
    /// message (and the object client checks routes) once. Without the per-epoch watch the newest map shows the old
    /// primary and the request is never resent.
    #[test]
    fn primary_away_and_back_inside_one_message_is_seen() {
        let m1 = fixture();
        let (pg, a, b) = m1
            .pools
            .iter()
            .filter(|(_, p)| p.is_replicated() && p.size >= 2)
            .flat_map(|(&id, p)| (0..p.pg_num).map(move |s| PgT::new(id as u64, s)))
            .find_map(|pg| {
                let m = m1.pg_to_up_acting(pg);
                (m.acting.len() >= 2).then(|| (pg, m.acting[0], m.acting[1]))
            })
            .unwrap();
        let mut c = MonClient::new(Config::new("client.test", None));
        c.set_osdmap(m1.clone());
        c.track_pg(pg, m1.epoch);
        let (i2, m2) = inc(&m1, |i| {
            i.new_pg_temp.insert(pg, vec![b, a]);
        });
        let (i3, m3) = inc(&m2, |i| {
            i.new_pg_temp.insert(pg, vec![]);
        });
        assert_eq!(m2.pg_to_up_acting(pg).acting_primary, b);
        c.on_osdmap(MOSDMap {
            fsid: m1.fsid,
            incremental_maps: [(m2.epoch, i2), (m3.epoch, i3)].into_iter().collect(),
            maps: BTreeMap::new(),
            cluster_osdmap_trim_lower_bound: 1,
            newest_map: m3.epoch,
        });
        assert_eq!(c.osdmap().unwrap().epoch, m3.epoch);
        assert_eq!(c.osdmap().unwrap().pg_to_up_acting(pg).acting_primary, a);
        assert_eq!(c.pg_interval_since(pg), Some(m3.epoch));
        c.untrack_pg(pg);
        assert_eq!(c.pg_interval_since(pg), None);
    }

    /// A full map past a gap (the sender trimmed the missing epoch): every followed PG starts a new interval.
    #[test]
    fn full_map_past_a_gap_is_a_new_interval() {
        let m1 = fixture();
        let pg = PgT::new(*m1.pools.keys().next().unwrap() as u64, 0);
        let mut c = MonClient::new(Config::new("client.test", None));
        c.set_osdmap(m1.clone());
        c.track_pg(pg, m1.epoch);
        let mut m3 = m1.clone();
        m3.epoch += 2;
        c.on_osdmap(MOSDMap {
            fsid: m1.fsid,
            incremental_maps: BTreeMap::new(),
            maps: [(m3.epoch, m3.encode_full().unwrap())]
                .into_iter()
                .collect(),
            cluster_osdmap_trim_lower_bound: m3.epoch,
            newest_map: m3.epoch,
        });
        assert_eq!(c.osdmap().unwrap().epoch, m3.epoch);
        assert_eq!(c.pg_interval_since(pg), Some(m3.epoch));
    }
    #[test]
    fn every_map_install_bumps_the_generation() {
        let mut c = MonClient::new(Config::new("client.test", None));
        assert_eq!(c.osdmap_generation(), 0);
        let mut map = OsdMap::default();
        map.epoch = 4;
        c.set_osdmap(map.clone());
        assert_eq!(c.osdmap_generation(), 1);
        // a replacement at the same epoch may differ in content: still a new generation
        c.set_osdmap(map);
        assert_eq!(c.osdmap_generation(), 2);
    }

    #[test]
    fn same_epoch_acting_change_retains_the_selected_replica_but_changes_interval() {
        let map = fixture();
        let (pg, acting) = map
            .pools
            .iter()
            .filter(|(_, pool)| pool.is_replicated() && pool.size >= 2)
            .flat_map(|(&id, pool)| (0..pool.pg_num).map(move |seed| PgT::new(id as u64, seed)))
            .find_map(|pg| {
                let acting = map.pg_to_up_acting(pg).acting;
                (acting.len() >= 2).then_some((pg, acting))
            })
            .unwrap();
        let replica = acting[1];
        let mut c = MonClient::new(Config::new("client.test", None));
        c.set_osdmap(map.clone());
        c.track_pg(pg, map.epoch);
        let sent_generation = c.osdmap_generation();
        c.set_osdmap(map.clone());
        assert_eq!(c.pg_interval_generation(pg), Some(0));
        let mut changed = map.clone();
        let mut rotated = acting;
        rotated.rotate_left(1);
        changed.pg_temp.insert(pg, rotated);
        c.set_osdmap(changed);
        assert!(
            c.osdmap()
                .unwrap()
                .pg_to_up_acting(pg)
                .acting
                .contains(&replica)
        );
        assert!(c.pg_interval_generation(pg).unwrap() > sent_generation);
        assert_eq!(c.pg_interval_since(pg), Some(map.epoch));
        c.untrack_pg(pg);
        assert_eq!(c.pg_interval_generation(pg), None);
    }
}

/// Dial target of a mon entry (spec ip-addressing 4): the first v2 entry; if the client holds no address of that
/// family, the first v2 entry of a family it does hold (dual-stack mons list both). A client without any own IP (blank
/// messenger address, the classic client case) takes the first entry and lets the kernel pick the route's family.
pub(crate) fn mon_target(addrs: &EntityAddrVec, my: &EntityAddrVec) -> Option<EntityAddr> {
    let mut v2 = addrs.0.iter().filter(|a| a.ty == EntityAddr::TYPE_MSGR2);
    let first = v2.next()?;
    let own: Vec<bool> =
        my.0.iter()
            .filter_map(|a| a.ip().map(|ip| ip.is_ipv4()))
            .collect();
    if own.is_empty() {
        return Some(*first);
    }
    let reachable = |a: &&EntityAddr| a.ip().is_some_and(|ip| own.contains(&ip.is_ipv4()));
    if reachable(&first) {
        return Some(*first);
    }
    v2.find(reachable).copied()
}

#[cfg(test)]
mod auth_transition_tests {
    use super::*;
    use cephx::modes::CON_MODE_CRC;
    use cephx::none::ENTITY_AUTH;
    use cephx::ticket::{TicketEntry, encode_ticket_reply};
    use cephx::types::{CEPHX_GET_AUTH_SESSION_KEY, ResponseHeader, ServerChallenge, TicketBlob};
    use denc::{Encode, Encoder};
    use msgr2::auth::AuthClientHandler;

    fn hunting_client() -> MonClient {
        let key = CryptoKey::new(cephx::KeyType::Aes, UTime::default(), &[7; 16]);
        let mut cfg = Config::new_client("client.rotation", Some(key));
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300,v2:127.0.0.2:3300").unwrap();
        cfg.hunt_parallel = 0;
        let mut client = MonClient::new(cfg);
        client.start(Duration::ZERO);
        assert_eq!(client.slots.len(), 2);
        client
    }

    #[test]
    fn rotate_key_reaches_every_pending_monitor_attempt() {
        use cephx::challenge::compute_key;
        use cephx::types::{Authenticate, RequestHeader};
        use denc::{Decode, Decoder};

        let mut client = hunting_client();
        let key = CryptoKey::new(cephx::KeyType::Aes, UTime::default(), &[9; 16]);
        assert!(client.rotate_key(key.clone()));
        // A hunt winner becomes the long-lived state. Verify its actual next
        // authentication proof, as well as the source used by later hunt rounds.
        for shared in std::iter::once(&client.auth).chain(client.slots.values().map(|s| &s.shared))
        {
            let mut auth = shared.cephx.borrow().as_ref().unwrap().clone();
            auth.start();
            let proof = auth
                .on_reply_more(
                    &ServerChallenge {
                        server_challenge: 41,
                    }
                    .encode_to_vec()
                    .unwrap(),
                    Duration::ZERO,
                )
                .unwrap();
            let mut decoder = Decoder::new(&proof);
            assert_eq!(
                RequestHeader::decode(&mut decoder).unwrap().request_type,
                CEPHX_GET_AUTH_SESSION_KEY
            );
            let request = Authenticate::decode(&mut decoder).unwrap();
            assert_eq!(
                request.key,
                compute_key(&key, 41, request.client_challenge).unwrap()
            );
        }
    }

    #[test]
    fn service_ticket_ttl_reaches_every_pending_monitor_attempt() {
        let mut client = hunting_client();
        client.set_service_ticket_ttl(120);
        for shared in std::iter::once(&client.auth).chain(client.slots.values().map(|s| &s.shared))
        {
            assert_eq!(
                shared.cephx.borrow().as_ref().unwrap().service_ticket_ttl(),
                120
            );
        }
    }

    #[test]
    fn wipe_reaches_pending_attempts_and_retires_their_inflight_replies() {
        use cephx::envelope::seal_wrapped_t;
        use cephx::key::Usage;
        use cephx::monclient::MonReply;
        use cephx::types::{CEPHX_GET_ROTATING_KEY, ExpiringCryptoKey, RotatingSecrets};

        let mut client = hunting_client();
        let key = client.cfg.key.clone().unwrap();
        let mut reply = Encoder::new();
        ResponseHeader {
            request_type: CEPHX_GET_AUTH_SESSION_KEY,
            status: 0,
        }
        .encode(&mut reply)
        .unwrap();
        reply
            .raw(
                &encode_ticket_reply(
                    &[TicketEntry {
                        service_id: ENTITY_AUTH,
                        session_key: key.clone(),
                        validity: UTime::new(100, 0),
                        blob: TicketBlob {
                            secret_id: 1,
                            blob: vec![1],
                        },
                    }],
                    &key,
                    None,
                )
                .unwrap(),
            )
            .unwrap();
        // Request and cache rotating material before cloning the hunt attempts.
        // Only AUTH is wanted so the first post-handshake request is rotating.
        let mut cfg = client.cfg.auth_cfg(key.clone());
        cfg.want = ENTITY_AUTH;
        cfg.want_rotating = true;
        let mut seeded = MonAuthClient::new_bytes(cfg);
        seeded.start();
        seeded
            .on_reply_more(
                &ServerChallenge {
                    server_challenge: 41,
                }
                .encode_to_vec()
                .unwrap(),
                Duration::ZERO,
            )
            .unwrap();
        seeded
            .on_done(17, CON_MODE_CRC, reply.buf(), Duration::ZERO)
            .unwrap();
        assert_eq!(
            seeded.poll(Duration::ZERO).unwrap().unwrap().request_type,
            CEPHX_GET_ROTATING_KEY
        );
        let mut rotating_reply = Encoder::new();
        ResponseHeader {
            request_type: CEPHX_GET_ROTATING_KEY,
            status: 0,
        }
        .encode(&mut rotating_reply)
        .unwrap();
        let rotating = RotatingSecrets {
            secrets: BTreeMap::from([(
                1,
                ExpiringCryptoKey {
                    key: key.clone(),
                    expiration: UTime::new(1000, 0),
                },
            )]),
            max_ver: 1,
        };
        rotating_reply
            .raw(&seal_wrapped_t(&key, Usage::RotatingSecret, &rotating).unwrap())
            .unwrap();
        seeded
            .on_response(0, 17, rotating_reply.buf(), Duration::ZERO)
            .unwrap();
        *client.auth.cephx.borrow_mut() = Some(seeded);
        client.start_hunt();
        for shared in std::iter::once(&client.auth).chain(client.slots.values().map(|s| &s.shared))
        {
            let mut state = shared.cephx.borrow_mut();
            let state = state.as_mut().unwrap();
            assert_eq!(state.rotating().secrets.len(), 1);
            assert_eq!(
                state
                    .poll(Duration::from_secs(80))
                    .unwrap()
                    .unwrap()
                    .request_type,
                CEPHX_GET_AUTH_SESSION_KEY
            );
        }
        client.wipe_secrets_and_tickets();
        for shared in std::iter::once(&client.auth).chain(client.slots.values().map(|s| &s.shared))
        {
            let mut state = shared.cephx.borrow_mut();
            let state = state.as_mut().unwrap();
            assert!(state.rotating().secrets.is_empty());
            assert!(!state.ticket(ENTITY_AUTH).unwrap().have_key(Duration::ZERO));
            assert_eq!(
                state
                    .on_response(0, 17, reply.buf(), Duration::from_secs(80))
                    .unwrap(),
                MonReply::Ignored
            );
            assert!(
                !state
                    .ticket(ENTITY_AUTH)
                    .unwrap()
                    .have_key(Duration::from_secs(80))
            );
        }
    }

    #[test]
    fn none_reconnect_never_renews_retained_cephx_tickets_or_rotating_keys() {
        for now in [Duration::ZERO, Duration::from_secs(100)] {
            let key = CryptoKey::new(cephx::KeyType::Aes, UTime::default(), &[7; 16]);
            let mut cfg = Config::new_client("client.transition", Some(key.clone()));
            cfg.want = ENTITY_AUTH;
            cfg.want_rotating = true;
            let mut old = MonAuthClient::new_bytes(cfg.auth_cfg(key.clone()));
            old.start();
            old.on_reply_more(
                &ServerChallenge {
                    server_challenge: 41,
                }
                .encode_to_vec()
                .unwrap(),
                Duration::ZERO,
            )
            .unwrap();
            let mut reply = Encoder::new();
            ResponseHeader {
                request_type: CEPHX_GET_AUTH_SESSION_KEY,
                status: 0,
            }
            .encode(&mut reply)
            .unwrap();
            reply
                .raw(
                    &encode_ticket_reply(
                        &[TicketEntry {
                            service_id: ENTITY_AUTH,
                            session_key: key.clone(),
                            validity: UTime::new(100, 0),
                            blob: TicketBlob {
                                secret_id: 1,
                                blob: vec![1],
                            },
                        }],
                        &key,
                        None,
                    )
                    .unwrap(),
                )
                .unwrap();
            old.on_done(17, CON_MODE_CRC, reply.buf(), Duration::ZERO)
                .unwrap();
            // A real successful CEPHX handshake leaves renewal work available.
            assert!(old.clone().poll(now).unwrap().is_some());
            let mut client = MonClient::new(cfg);
            // spawn() retains the previous credentials in the new attempt.
            let shared =
                AuthShared::new_bytes(Some(old), client.cfg.auth_name(), 17, client.clock.clone());
            let mut handler =
                MonAuthHandler::new(shared.clone(), vec![AUTH_NONE], vec![CON_MODE_CRC]);
            assert_eq!(
                handler.get_auth_request(EntityName::MON).unwrap().method,
                AUTH_NONE
            );
            handler.handle_auth_done(17, CON_MODE_CRC, &[]).unwrap();
            client.auth = shared;
            client.active = Some(1);
            client.set_now(now);
            client.auth_poll();
            assert_eq!(
                client.auth_req_at, None,
                "NONE must not start a CEPHX deadline"
            );
            assert!(
                client
                    .auth
                    .cephx
                    .borrow_mut()
                    .as_mut()
                    .unwrap()
                    .poll(now)
                    .unwrap()
                    .is_some(),
                "NONE must not consume retained CEPHX renewal work"
            );
        }
    }
}

#[cfg(test)]
mod family_tests {
    use super::*;

    fn v6_first() -> EntityAddrVec {
        let v6 = "fd00:77::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
        EntityAddrVec(vec![
            EntityAddr::v6(EntityAddr::TYPE_MSGR2, 0, v6, 3300, 0),
            EntityAddr::v6(EntityAddr::TYPE_LEGACY, 0, v6, 6789, 0),
            EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [10, 78, 0, 1], 3300),
            EntityAddr::v4(EntityAddr::TYPE_LEGACY, 0, [10, 78, 0, 1], 6789),
        ])
    }

    /// A v4-only daemon dials the mon's v4 v2 entry although the mon lists IPv6 first (spec 4/8).
    #[test]
    fn target_follows_the_families_the_client_holds() {
        let mon = v6_first();
        let me4 =
            EntityAddrVec::single(EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [10, 78, 0, 9], 0));
        let t = mon_target(&mon, &me4).unwrap();
        assert_eq!(t.ipv4(), Some([10, 78, 0, 1]));
        // a v6-only daemon takes the v6 entry
        let me6 = EntityAddrVec::single(EntityAddr::v6(
            EntityAddr::TYPE_MSGR2,
            0,
            "fd00:77::9".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            0,
            0,
        ));
        let t = mon_target(&mon, &me6).unwrap();
        assert_eq!(t.family, denc::types::entity::AF_INET6);
        // a blank client address (no IP yet) keeps Ceph's first-entry rule
        let blank = EntityAddrVec::single(EntityAddr::blank());
        assert_eq!(mon_target(&mon, &blank), Some(mon.0[0]));
        // a mon of a family we cannot speak: no target
        let only6 = EntityAddrVec(vec![EntityAddr::v6(
            EntityAddr::TYPE_MSGR2,
            0,
            "fd00:77::1".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            3300,
            0,
        )]);
        assert!(mon_target(&only6, &me4).is_none());
    }
}

#[cfg(test)]
mod full_request_handoff_tests {
    use super::*;
    use messages::Message;

    #[derive(Debug)]
    struct Accept;
    impl msgr2::auth::AuthServerHandler for Accept {
        fn supported_methods(&self, _: u8) -> Vec<u32> {
            vec![AUTH_NONE]
        }
        fn supported_modes(&self, _: u8, _: u32) -> Vec<u32> {
            vec![msgr2::auth::MODE_CRC]
        }
        fn handle_auth_request(
            &mut self,
            _: u8,
            _: bool,
            _: u32,
            _: u32,
            _: &[u8],
        ) -> msgr2::auth::AuthServerStep {
            msgr2::auth::AuthServerStep::Done {
                reply: vec![],
                global_id: 7,
                peer_name: None,
                secrets: Default::default(),
            }
        }
    }
    fn connect(c: &mut MonClient) -> (u64, Connection) {
        let id = c.conn_ids()[0];
        let target = c.mons[0].target;
        let mut peer = Connection::server(
            999,
            msgr2::Config::new(
                EntityName::new(EntityName::MON, 0),
                EntityAddrVec::single(target),
                PolicyTable::uniform(Policy::stateless_server(0)),
            ),
            SessionTable::new(2),
            Box::new(Accept),
            EntityAddr::v4(2, 0, [127, 0, 0, 2], 40000),
            Duration::ZERO,
        );
        c.on_connected(id, Duration::ZERO);
        for _ in 0..32 {
            peer.on_bytes(&c.poll_output(id), Duration::ZERO);
            c.on_bytes(id, &peer.poll_output(), Duration::ZERO);
            while peer.poll_event().is_some() {}
        }
        assert!(c.is_connected());
        (id, peer)
    }
    fn fixture() -> (MonClient, u64, Connection) {
        let mut cfg = Config::new("client.test", None);
        cfg.fsid = Uuid([7; 16]);
        cfg.default_subs = false;
        cfg.methods = vec![AUTH_NONE];
        cfg.mon_host = crate::parse_mon_host("v2:127.0.0.1:3300").unwrap();
        let mut c = MonClient::new(cfg);
        let mut map = OsdMap::default();
        map.fsid = Uuid([7; 16]);
        map.epoch = 10;
        c.set_osdmap(map);
        c.start(Duration::ZERO);
        let (id, peer) = connect(&mut c);
        (c, id, peer)
    }
    fn buffer(c: &mut MonClient, id: u64, peer: &mut Connection, message: impl Into<AnyMessage>) {
        let message = message.into();
        let (msg_type, version, compat_version, segments) = message.encode(u64::MAX).unwrap();
        assert!(peer.send_message(msgr2::Message {
            msg_type,
            version,
            compat_version,
            front: segments.front,
            middle: segments.middle,
            data: segments.data,
            ..Default::default()
        }));
        // Leave the decoded message queued for the request's re-entrant send drain.
        c.slots
            .get_mut(&id)
            .unwrap()
            .conn
            .on_bytes(&peer.poll_output(), Duration::ZERO);
    }
    fn requests(c: &mut MonClient, id: u64, peer: &mut Connection) -> Vec<(u32, u32)> {
        peer.on_bytes(&c.poll_output(id), Duration::ZERO);
        std::iter::from_fn(|| peer.poll_event())
            .filter_map(|event| {
                let Event::Message(message) = event else {
                    return None;
                };
                if message.header.msg_type != MMonGetOSDMap::MSG_TYPE {
                    return None;
                }
                let request = MMonGetOSDMap::decode(
                    message.header.version,
                    &message.front,
                    &message.middle,
                    &message.data,
                )
                .unwrap();
                Some((request.full_first, request.full_last))
            })
            .collect()
    }
    #[test]
    fn full_request_expansion_preserves_the_unanswered_range() {
        let (mut c, id, mut peer) = fixture();
        c.request_full(11, 12);
        assert_eq!(requests(&mut c, id, &mut peer), [(11, 12)]);
        c.request_full(11, 14);
        assert_eq!(
            requests(&mut c, id, &mut peer),
            [(11, 14)],
            "a wider fallback is not a duplicate"
        );
        c.request_full(12, 13);
        assert!(
            requests(&mut c, id, &mut peer).is_empty(),
            "covered range is already outstanding"
        );
    }
    #[test]
    fn full_request_short_reply_preserves_the_unanswered_suffix() {
        let (mut c, id, mut peer) = fixture();
        c.request_full(11, 14);
        assert_eq!(requests(&mut c, id, &mut peer), [(11, 14)]);
        let mut map = c.osdmap().unwrap().clone();
        map.epoch = 11;
        c.on_osdmap(MOSDMap {
            fsid: map.fsid,
            maps: [(11, map.encode_full().unwrap())].into(),
            newest_map: 14,
            ..Default::default()
        });
        assert_eq!(
            requests(&mut c, id, &mut peer),
            [(12, 14)],
            "short full reply must request remaining full maps directly"
        );
    }
    #[test]
    fn rejected_expansion_preserves_the_accepted_range() {
        let (mut c, id, mut peer) = fixture();
        c.request_full(11, 12);
        assert_eq!(requests(&mut c, id, &mut peer), [(11, 12)]);
        c.next_tid = 0;
        c.request_full(11, 14);
        assert_eq!(c.full_req, Some((11, 12)));
        assert!(requests(&mut c, id, &mut peer).is_empty());
    }
    #[test]
    fn session_loss_during_full_request_handoff_keeps_reconnect_rearmable() {
        let (mut c, id, mut peer) = fixture();
        let original = c.monmap.clone();
        let moved = MonMap {
            fsid: Uuid([7; 16]),
            epoch: 1,
            ..Default::default()
        };
        buffer(
            &mut c,
            id,
            &mut peer,
            messages::MMonMap {
                monmap: moved.encode_to().unwrap(),
            },
        );
        c.request_full(11, 11);
        assert!(c.active.is_none());
        assert_eq!(c.full_req, None, "lost session owns no outstanding request");
        c.set_monmap(original);
        c.start_hunt();
        let (id, mut peer) = connect(&mut c);
        c.request_full(11, 11);
        assert_eq!(c.full_req, Some((11, 11)));
        peer.on_bytes(&c.poll_output(id), Duration::ZERO);
        assert!(std::iter::from_fn(|| peer.poll_event()).any(|event| {
            matches!(event, Event::Message(message)
                if message.header.msg_type == MMonGetOSDMap::MSG_TYPE)
        }));
    }
    #[test]
    fn full_progress_and_newer_request_during_handoff_keep_the_new_owner() {
        let (mut c, id, mut peer) = fixture();
        let mut map = c.osdmap().unwrap().clone();
        map.epoch = 11;
        buffer(
            &mut c,
            id,
            &mut peer,
            MOSDMap {
                fsid: map.fsid,
                maps: [(11, map.encode_full().unwrap())].into_iter().collect(),
                newest_map: 11,
                ..Default::default()
            },
        );
        let inc = Incremental {
            fsid: map.fsid,
            epoch: 12,
            full_crc: map.crc(0).unwrap() ^ 1,
            ..Default::default()
        };
        buffer(
            &mut c,
            id,
            &mut peer,
            MOSDMap {
                fsid: map.fsid,
                incremental_maps: [(12, inc.encode_inc().unwrap())].into_iter().collect(),
                newest_map: 12,
                ..Default::default()
            },
        );
        c.request_full(11, 11);
        assert_eq!(c.osdmap().unwrap().epoch, 11);
        assert_eq!(
            c.full_req,
            Some((12, 12)),
            "newer fallback owns the outstanding request"
        );
    }
}
