// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
#[path = "bootstrap_configuration.rs"]
mod configuration;
use configuration::ConfigurationControl;
pub use configuration::MonitorConfigError;
#[path = "bootstrap_log.rs"]
mod log;
#[path = "bootstrap_map_barriers.rs"]
mod map_barriers;
#[path = "bootstrap_metadata.rs"]
mod metadata;
#[path = "bootstrap_monitor_commands.rs"]
mod monitor_commands;
#[path = "bootstrap_statistics.rs"]
mod statistics;
pub use log::{MonitorLogEntry, MonitorLogError};
pub use statistics::{
    ClusterStatistics, PoolStatistics, PoolStatisticsBatchCompletion, PoolStatisticsCompletion,
    StatisticsCompletion, StatisticsError, StatisticsToken,
};
#[path = "bootstrap_snapshots.rs"]
mod snapshots;

#[path = "bootstrap_blocklist.rs"]
mod blocklists;
pub use blocklists::BlocklistControlLimits;
#[cfg(feature = "lab")]
pub use blocklists::LabBlocklistStats;

use cephx::{
    CryptoKey,
    modes::{AUTH_CEPHX, AUTH_NONE, CON_MODE_CRC, CON_MODE_SECURE},
};
use denc::types::{EntityAddrVec, Uuid};
use monc::{IoCmd, MonClient, MonEvent};
use osdmap::OsdMap;
use std::{collections::VecDeque, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessengerMode {
    Crc,
    Secure,
    PreferSecure,
    PreferCrc,
}
impl MessengerMode {
    pub(crate) fn modes(self) -> Vec<u32> {
        match self {
            Self::Crc => vec![CON_MODE_CRC],
            Self::Secure => vec![CON_MODE_SECURE],
            Self::PreferSecure => vec![CON_MODE_SECURE, CON_MODE_CRC],
            Self::PreferCrc => vec![CON_MODE_CRC, CON_MODE_SECURE],
        }
    }
    pub(crate) fn accepts(self, mode: u32) -> bool {
        match self {
            Self::Crc => mode == CON_MODE_CRC,
            Self::Secure => mode == CON_MODE_SECURE,
            Self::PreferSecure | Self::PreferCrc => matches!(mode, CON_MODE_CRC | CON_MODE_SECURE),
        }
    }
}

/// Typed cold-path configuration; secrets are never rendered by Debug.
pub struct BootstrapConfig<A = CryptoKey, E = String> {
    pub entity: E,
    pub key: A,
    pub monitors: Vec<EntityAddrVec>,
    pub expected_fsid: Option<Uuid>,
    pub mode: MessengerMode,
    pub startup_timeout: Duration,
    pub wall_origin_unix: u64,
}
impl<A, E: std::fmt::Debug> std::fmt::Debug for BootstrapConfig<A, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapConfig")
            .field("entity", &self.entity)
            .field("monitors", &self.monitors)
            .field("expected_fsid", &self.expected_fsid)
            .field("mode", &self.mode)
            .field("startup_timeout", &self.startup_timeout)
            .finish_non_exhaustive()
    }
}
/// Native owned full entity bytes; C adapters must copy only through the first NUL.
pub type ByteBootstrapConfig<A = CryptoKey> = BootstrapConfig<A, Vec<u8>>;
impl<A> BootstrapConfig<A> {
    pub fn into_bytes(self) -> ByteBootstrapConfig<A> {
        BootstrapConfig {
            entity: self.entity.into_bytes(),
            key: self.key,
            monitors: self.monitors,
            expected_fsid: self.expected_fsid,
            mode: self.mode,
            startup_timeout: self.startup_timeout,
            wall_origin_unix: self.wall_origin_unix,
        }
    }
}

/// Ordered monitor methods and real optional credentials. Debug never exposes keys.
pub struct ClientAuth {
    methods: Vec<u32>,
    key: Option<CryptoKey>,
}
impl ClientAuth {
    pub fn new(methods: Vec<u32>, key: Option<CryptoKey>) -> Result<Self, BootstrapError> {
        if methods.is_empty()
            || methods
                .iter()
                .any(|m| !matches!(*m, AUTH_CEPHX | AUTH_NONE))
        {
            return Err(BootstrapError::AuthRejected);
        }
        if methods.contains(&AUTH_CEPHX) {
            let key = key.as_ref().ok_or(BootstrapError::InvalidKey)?;
            let valid = match key.key_type() {
                cephx::key::KeyType::Aes => key.secret().len() == 16,
                cephx::key::KeyType::Aes256Krb5 => key.secret().len() == 32,
                _ => false,
            };
            if !valid {
                return Err(BootstrapError::InvalidKey);
            }
        }
        Ok(Self {
            key: key.filter(|_| methods.contains(&AUTH_CEPHX)),
            methods,
        })
    }
    pub fn methods(&self) -> &[u32] {
        &self.methods
    }
    /// Move the ordered methods and optional key into a native monitor configuration.
    pub fn into_parts(self) -> (Vec<u32>, Option<CryptoKey>) {
        (self.methods, self.key)
    }
}
impl From<CryptoKey> for ClientAuth {
    fn from(key: CryptoKey) -> Self {
        Self {
            methods: vec![AUTH_CEPHX],
            key: Some(key),
        }
    }
}
impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuth")
            .field("methods", &self.methods)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapError {
    InvalidEntity,
    AlreadyStarted,
    InvalidKey,
    InvalidMonitors,
    InvalidTimeout,
    InvalidFsid,
    InvalidClock,
    Randomness,
    StartupTimeout,
    ClockRegression,
    IdentityLost,
    FsidMismatch,
    AuthRejected,
    ModeRejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapState {
    New,
    Hunting,
    AwaitingMaps,
    Ready,
    Failed(BootstrapError),
    Closed,
}

/// Single-owner monitor/control-plane bootstrap. Driver owns all transport IO.
/// This is cold control-path composition, not an allocation-free reactor.
pub struct Bootstrap {
    monitor: Option<MonClient>,
    daemon_monitor: bool,
    snapshots: Option<snapshots::SnapshotControl>,
    map_barriers: Option<map_barriers::MapBarrierControl>,
    pool_checks: Option<map_barriers::MapBarrierControl>,
    blocklists: Option<blocklists::BlocklistControl>,
    commands: Option<monitor_commands::MonitorCommandControl>,
    statistics: Option<statistics::StatisticsControl>,
    logs: Option<log::Logs>,
    configuration: Option<ConfigurationControl>,
    manager_enabled: bool,
    manager_map: Option<messages::MgrMapPrefix>,
    #[cfg(feature = "lab")]
    blocklist_observer_loss: bool,
    #[cfg(feature = "lab")]
    blocklist_wait_for_loss: bool,
    #[cfg(feature = "lab")]
    blocklist_withhold_ack: bool,
    closes: VecDeque<IoCmd>,
    state: BootstrapState,
    identity: Option<u64>,
    entity: cephx::none::ByteEntityName,
    methods: Vec<u32>,
    method: Option<u32>,
    /// Last authenticated service method; monitor loss does not revoke cached credentials.
    service_method: Option<u32>,
    fsid: Option<Uuid>,
    mode: MessengerMode,
    timeout: Duration,
    deadline: Option<Duration>,
    /// Reached Ready once: later monitor authentication failures are hunt faults, not connect failures.
    was_ready: bool,
    last_now: Duration,
    wall_origin_unix: u64,
    /// Leader: cell the held map, OSD ticket and identity are published to.
    view_out: Option<std::sync::Arc<crate::ViewCell>>,
    /// Follower: no monitor session; map, ticket and identity come from the leader's published view.
    follower: Option<Follower>,
}
/// State of a view-driven bootstrap (adr 0467 am. 4, step 1).
struct Follower {
    cell: std::sync::Arc<crate::ViewCell>,
    /// Last installed view generation.
    seen: u64,
    map: Option<std::sync::Arc<OsdMap>>,
    /// Local install counter (never reused): keys the per-map caches of the owner.
    map_generation: u64,
    pg_watch: osdmap::PgWatch,
    osd_ticket: Option<cephx::ticket::TicketHandler>,
}
impl std::fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bootstrap")
            .field("state", &self.state)
            .field("identity", &self.identity)
            .field("fsid", &self.fsid)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}
impl Bootstrap {
    /// Replace the unstarted monitor with a daemon-role session. The caller
    /// drains observed events after every transport step; bootstrap still
    /// handles its own authentication, map and request-control events.
    pub fn configure_daemon_monitor(&mut self, config: monc::Config) -> Result<(), BootstrapError> {
        if self.state != BootstrapState::New || self.follower.is_some() {
            return Err(BootstrapError::AlreadyStarted);
        }
        if cephx::none::ByteEntityName::parse_bytes(config.entity.as_bytes())
            .is_none_or(|n| n.ty != self.entity.ty || n.id != self.entity.id)
        {
            return Err(BootstrapError::InvalidEntity);
        }
        self.monitor = Some(MonClient::new(config));
        self.daemon_monitor = true;
        Ok(())
    }
    /// Exclusive access to the shared session; never drive a second monitor
    /// transport alongside bootstrap. Drain daemon events between driver steps.
    pub fn daemon_monitor_mut(&mut self) -> Option<&mut MonClient> {
        if !self.daemon_monitor {
            return None;
        }
        self.monitor.as_mut()
    }
    /// Pull one caller-visible monitor event after applying bootstrap state.
    /// Replies owned by internal queues are consumed here; daemon-owned
    /// command replies and losses are returned unchanged. Daemon callers provide
    /// backpressure by stopping pulls; there is no second event queue.
    pub fn next_event(&mut self) -> Option<MonEvent> {
        loop {
            let event = self.monitor.as_mut()?.poll_event()?;
            let event = self.monitor_event(event);
            // Daemon event handling can drain buffered monitor input after the
            // transport's progress pass. Reconcile readiness, epoch waiters and
            // follower publication before handing control back to that caller.
            // Ordinary clients already reconcile around their internal drain.
            if self.daemon_monitor {
                self.advance();
            }
            if let Some(event) = event {
                return Some(event);
            }
        }
    }
    pub fn monitor_target_seed(
        &self,
        target: monc::MonitorTarget,
    ) -> Result<monc::MonitorTargetSeed, monc::MonitorTargetError> {
        self.monitor
            .as_ref()
            .ok_or(monc::MonitorTargetError::NoAddress)?
            .target_seed(target)
    }
    pub fn new<A: Into<ClientAuth>>(config: BootstrapConfig<A>) -> Result<Self, BootstrapError> {
        Self::new_bytes(config.into_bytes())
    }
    pub fn new_bytes<A: Into<ClientAuth>>(
        config: ByteBootstrapConfig<A>,
    ) -> Result<Self, BootstrapError> {
        Self::new_services(config, false, msgr2::Limits::default(), None, false)
    }
    /// Opt-in manager ticket and continuous manager map subscription.
    pub fn new_with_manager<A: Into<ClientAuth>>(
        config: BootstrapConfig<A>,
    ) -> Result<Self, BootstrapError> {
        Self::new_with_manager_bytes(config.into_bytes())
    }
    pub fn new_with_manager_bytes<A: Into<ClientAuth>>(
        config: ByteBootstrapConfig<A>,
    ) -> Result<Self, BootstrapError> {
        Self::new_services(config, true, msgr2::Limits::default(), None, false)
    }
    /// Explicit compatible monitor framing, with optional manager subscription.
    /// Authentication principal and messenger identity retain their independent roles.
    pub fn new_compatible<A: Into<ClientAuth>>(
        config: BootstrapConfig<A>,
        manager: bool,
    ) -> Result<Self, BootstrapError> {
        Self::new_compatible_bytes(config.into_bytes(), manager)
    }
    pub fn new_compatible_bytes<A: Into<ClientAuth>>(
        config: ByteBootstrapConfig<A>,
        manager: bool,
    ) -> Result<Self, BootstrapError> {
        Self::new_services(config, manager, msgr2::Limits::wire_shape(), None, true)
    }
    fn new_services<A: Into<ClientAuth>>(
        config: ByteBootstrapConfig<A>,
        manager: bool,
        frame_limits: msgr2::Limits,
        configuration: Option<ConfigurationControl>,
        allow_unbounded_auth: bool,
    ) -> Result<Self, BootstrapError> {
        if config.entity.contains(&0) {
            return Err(BootstrapError::InvalidEntity);
        }
        let auth = config.key.into();
        let auth = ClientAuth::new(auth.methods, auth.key)?;
        let entity = cephx::none::ByteEntityName::parse_bytes(&config.entity)
            .ok_or(BootstrapError::InvalidEntity)?;
        // a mon without a usable v2 entry is a legacy (msgr1) mon: the msgr2-only client skips it and fails only when
        // nothing else is left (spec ip-addressing 5)
        let monitors: Vec<_> = config.monitors.into_iter().filter(has_v2).collect();
        if monitors.is_empty() {
            return Err(BootstrapError::InvalidMonitors);
        }
        if config.startup_timeout.is_zero() && !allow_unbounded_auth {
            return Err(BootstrapError::InvalidTimeout);
        }
        if config.expected_fsid == Some(Uuid::default()) {
            return Err(BootstrapError::InvalidFsid);
        }
        if config.wall_origin_unix > u64::from(u32::MAX) {
            return Err(BootstrapError::InvalidClock);
        }
        let methods = auth.methods;
        let mut cfg = monc::Config::new_client_bytes(&config.entity, auth.key);
        cfg.frame_limits = frame_limits;
        cfg.filter_config_identity = configuration.is_none();
        let configuration_only = configuration
            .as_ref()
            .is_some_and(ConfigurationControl::only);
        if configuration_only {
            cfg.want = cephx::none::ENTITY_AUTH;
        }
        cfg.seed = cephx::challenge::random_u64().map_err(|_| BootstrapError::Randomness)?;
        cfg.mon_host = monitors;
        cfg.methods = methods.clone();
        cfg.modes = config.mode.modes();
        cfg.default_subs = false;
        cfg.wall_origin = Duration::from_secs(config.wall_origin_unix);
        // Learn actual FSID before accepting it; an expected value is policy, not evidence.
        cfg.fsid = Uuid::default();
        let mut monitor = MonClient::new_bytes(cfg);
        monitor.subscribe("monmap", 0, 0);
        if configuration.is_some() {
            monitor.subscribe("config", 0, 0);
        }
        if !configuration_only {
            monitor.subscribe("osdmap", 0, 0);
        }
        if manager {
            monitor.subscribe("mgrmap", 0, 0);
        }
        Ok(Self {
            monitor: Some(monitor),
            daemon_monitor: false,
            snapshots: None,
            map_barriers: None,
            pool_checks: None,
            blocklists: None,
            commands: None,
            statistics: None,
            logs: None,
            configuration,
            manager_enabled: manager,
            manager_map: None,
            #[cfg(feature = "lab")]
            blocklist_observer_loss: false,
            #[cfg(feature = "lab")]
            blocklist_wait_for_loss: false,
            #[cfg(feature = "lab")]
            blocklist_withhold_ack: false,
            closes: VecDeque::new(),
            state: BootstrapState::New,
            identity: None,
            entity,
            methods,
            method: None,
            service_method: None,
            fsid: config.expected_fsid,
            mode: config.mode,
            timeout: config.startup_timeout,
            deadline: None,
            was_ready: false,
            last_now: Duration::ZERO,
            wall_origin_unix: config.wall_origin_unix,
            view_out: None,
            follower: None,
        })
    }
    /// Data-only bootstrap that follows the view published by a leader: no monitor session, no control plane.
    /// `New` until [`Self::start`]; `Ready` as soon as the view carries identity, a map and (cephx) an OSD ticket.
    pub fn new_follower(
        cell: std::sync::Arc<crate::ViewCell>,
        mode: MessengerMode,
        wall_origin_unix: u64,
    ) -> Result<Self, BootstrapError> {
        if wall_origin_unix > u64::from(u32::MAX) {
            return Err(BootstrapError::InvalidClock);
        }
        Ok(Self {
            monitor: None,
            daemon_monitor: false,
            snapshots: None,
            map_barriers: None,
            pool_checks: None,
            blocklists: None,
            commands: None,
            statistics: None,
            logs: None,
            configuration: None,
            manager_enabled: false,
            manager_map: None,
            #[cfg(feature = "lab")]
            blocklist_observer_loss: false,
            #[cfg(feature = "lab")]
            blocklist_wait_for_loss: false,
            #[cfg(feature = "lab")]
            blocklist_withhold_ack: false,
            closes: VecDeque::new(),
            state: BootstrapState::New,
            identity: None,
            entity: cephx::none::ByteEntityName {
                ty: 0,
                id: Vec::new(),
            },
            methods: Vec::new(),
            method: None,
            service_method: None,
            fsid: None,
            mode,
            timeout: Duration::ZERO,
            deadline: None,
            was_ready: false,
            last_now: Duration::ZERO,
            wall_origin_unix,
            view_out: None,
            follower: Some(Follower {
                cell,
                seen: 0,
                map: None,
                map_generation: 0,
                pg_watch: osdmap::PgWatch::default(),
                osd_ticket: None,
            }),
        })
    }
    /// Leader: publish the held map, OSD ticket and identity to `cell` whenever they change. Publishes the current
    /// state at once and again at the end of every monitor-driven step.
    pub fn publish_view_to(&mut self, cell: std::sync::Arc<crate::ViewCell>) {
        self.view_out = Some(cell);
        self.publish_view();
    }
    fn publish_view(&self) {
        let (Some(cell), Some(m), Some(identity), Some(method)) = (
            self.view_out.as_ref(),
            self.monitor.as_ref(),
            self.identity,
            self.method,
        ) else {
            return;
        };
        // The ticket is compared in place: an unchanged view allocates nothing.
        fn publish(
            cell: &crate::ViewCell,
            this: &Bootstrap,
            m: &monc::MonClient,
            identity: u64,
            method: u32,
            osd_ticket: Option<&cephx::ticket::TicketHandler>,
        ) -> bool {
            cell.publish(crate::ViewInput {
                map: m.osdmap_arc(),
                osd_ticket,
                identity,
                entity: &this.entity,
                method,
                fsid: this.fsid,
            })
        }
        if m.with_cephx(|c| {
            publish(
                cell,
                self,
                m,
                identity,
                method,
                c.ticket(cephx::none::ENTITY_OSD),
            )
        })
        .is_none()
        {
            publish(cell, self, m, identity, method, None);
        }
    }
    /// Follower: install the newest published view (one atomic load when nothing changed).
    fn sync_view(&mut self) {
        let Some(f) = self.follower.as_mut() else {
            return;
        };
        if f.cell.generation() == f.seen {
            return;
        }
        let Some(view) = f.cell.load() else {
            return;
        };
        f.seen = view.generation;
        if let Some(map) = &view.map
            && !f
                .map
                .as_ref()
                .is_some_and(|m| std::sync::Arc::ptr_eq(m, map))
        {
            f.map_generation += 1;
            f.pg_watch
                .observe_generation(f.map.as_deref(), map, f.map_generation);
            f.map = Some(map.clone());
        }
        f.osd_ticket = view.osd_ticket.clone();
        self.identity = Some(view.identity);
        self.entity = view.entity.clone();
        self.method = Some(view.method);
        self.service_method = Some(view.method);
        self.fsid = view.fsid;
        let ticket_ok = match view.method {
            AUTH_CEPHX => f
                .osd_ticket
                .as_ref()
                .is_some_and(|t| t.session_key().is_some()),
            _ => true,
        };
        if self.state == BootstrapState::Hunting
            && f.map.as_ref().is_some_and(|m| m.epoch > 0)
            && ticket_ok
        {
            self.state = BootstrapState::Ready;
            self.was_ready = true;
        }
    }
    /// Lab qualifier only: consume the initial map subscription once, then request catch-up explicitly.
    #[cfg(feature = "lab")]
    pub fn lab_onetime_osdmap(&mut self) -> bool {
        if self.state != BootstrapState::New {
            return false;
        }
        let Some(monitor) = self.monitor.as_mut() else {
            return false;
        };
        monitor.subscribe("osdmap", 0, messages::SubItem::ONETIME);
        true
    }
    pub fn state(&self) -> BootstrapState {
        self.state
    }
    /// Initial bootstrap completed and the data plane can use its held map and service credentials.
    /// Monitor hunting does not interrupt established OSD sessions; missing credentials gate only new dials.
    pub fn data_ready(&self) -> bool {
        self.was_ready
            && !matches!(
                self.state,
                BootstrapState::Failed(_) | BootstrapState::Closed
            )
    }
    /// Whether this owner runs a monitor session. A data follower
    /// ([`Self::new_follower`]) follows a published view and has none (adr 0467
    /// am. 4: one monitor session per client instance).
    pub fn has_monitor_session(&self) -> bool {
        self.monitor.is_some()
    }
    pub fn identity(&self) -> Option<u64> {
        self.identity
    }
    /// Configured authentication principal, independent of messenger CLIENT role.
    pub fn auth_entity(&self) -> &cephx::none::ByteEntityName {
        &self.entity
    }
    pub fn fsid(&self) -> Option<Uuid> {
        self.fsid
    }
    pub fn osdmap(&self) -> Option<&OsdMap> {
        if let Some(f) = &self.follower {
            return f.map.as_deref();
        }
        self.monitor.as_ref()?.osdmap()
    }
    /// Map install counter of the monitor client or, for a follower, of its own installs (0 before any).
    pub fn osdmap_generation(&self) -> u64 {
        if let Some(f) = &self.follower {
            return f.map_generation;
        }
        self.monitor.as_ref().map_or(0, |m| m.osdmap_generation())
    }
    /// Follow `pg` of a request sent with map `epoch` through every applied map epoch (interval resend rule).
    pub fn track_pg(&mut self, pg: denc::types::PgT, epoch: u32) {
        if let Some(f) = self.follower.as_mut() {
            f.pg_watch.track(pg, epoch);
        }
        if let Some(m) = self.monitor.as_mut() {
            m.track_pg(pg, epoch);
        }
    }
    /// Stop following `pg` for one request.
    pub fn untrack_pg(&mut self, pg: denc::types::PgT) {
        if let Some(f) = self.follower.as_mut() {
            f.pg_watch.untrack(pg);
        }
        if let Some(m) = self.monitor.as_mut() {
            m.untrack_pg(pg);
        }
    }
    /// Epoch at which followed `pg` last started a new interval (0 = none seen; `None` = not followed or no monitor).
    pub fn pg_interval_since(&self, pg: denc::types::PgT) -> Option<u32> {
        if let Some(f) = &self.follower {
            return f.pg_watch.interval_since(pg);
        }
        self.monitor.as_ref()?.pg_interval_since(pg)
    }
    pub fn pg_interval_generation(&self, pg: denc::types::PgT) -> Option<u64> {
        if let Some(f) = &self.follower {
            return f.pg_watch.interval_generation(pg);
        }
        self.monitor.as_ref()?.pg_interval_generation(pg)
    }
    pub fn manager_enabled(&self) -> bool {
        self.manager_enabled
    }
    pub fn manager_map(&self) -> Option<&messages::MgrMapPrefix> {
        self.manager_map.as_ref()
    }
    pub fn with_cephx<R>(
        &self,
        f: impl FnOnce(&cephx::monclient::MonAuthClient) -> R,
    ) -> Option<R> {
        self.monitor.as_ref()?.with_cephx(f)
    }
    /// Whether service authentication has cached key material. Like classic Ceph, the peer's rotating key set
    /// decides admission; local ticket expiry schedules renewal and does not discard usable credentials.
    pub fn service_ticket_available(&self, service: u32) -> bool {
        match self.service_method {
            Some(AUTH_NONE) => true,
            Some(AUTH_CEPHX) => match &self.follower {
                Some(f) => {
                    service == cephx::none::ENTITY_OSD
                        && f.osd_ticket
                            .as_ref()
                            .is_some_and(|ticket| ticket.session_key().is_some())
                }
                None => self
                    .with_cephx(|c| {
                        c.ticket(service)
                            .is_some_and(|ticket| ticket.session_key().is_some())
                    })
                    .unwrap_or(false),
            },
            _ => false,
        }
    }
    /// Snapshot service authentication from the method that actually completed monitor auth.
    pub fn service_auth(
        &self,
        service: u32,
        mode: MessengerMode,
    ) -> Result<Box<dyn msgr2::auth::AuthClientHandler>, crate::OsdAuthError> {
        use crate::{NoneServiceAuth, OsdAuth, OsdAuthError};
        let gid = self.identity.ok_or(OsdAuthError::Identity)?;
        match self.service_method {
            Some(AUTH_NONE) => Ok(Box::new(NoneServiceAuth::new_bytes(
                self.entity.clone(),
                gid,
                service,
                mode,
            )?)),
            Some(AUTH_CEPHX) => {
                let ticket = match &self.follower {
                    Some(f) if service == cephx::none::ENTITY_OSD => f.osd_ticket.clone(),
                    Some(_) => None,
                    None => self.with_cephx(|c| c.ticket(service).cloned()).flatten(),
                }
                .ok_or(OsdAuthError::Ticket)?;
                let auth = match service {
                    cephx::none::ENTITY_OSD => OsdAuth::new(gid, ticket, mode)?,
                    cephx::none::ENTITY_MGR => OsdAuth::new_manager(gid, ticket, mode)?,
                    _ => return Err(OsdAuthError::Service),
                };
                Ok(Box::new(auth))
            }
            _ => Err(OsdAuthError::Phase),
        }
    }
    pub fn start(&mut self, now: Duration) -> Result<(), BootstrapError> {
        if self.state != BootstrapState::New {
            return Ok(());
        }
        if self.follower.is_some() {
            self.follower_time(now)?;
            self.state = BootstrapState::Hunting;
            self.sync_view();
            return Ok(());
        }
        let deadline = match self.authentication_deadline(now) {
            Ok(deadline) => deadline,
            Err(error) => {
                self.fail(error);
                return Err(error);
            }
        };
        if !self.valid_clock(now) {
            self.fail(BootstrapError::InvalidClock);
            return Err(BootstrapError::InvalidClock);
        }
        self.last_now = now;
        self.deadline = deadline;
        self.state = BootstrapState::Hunting;
        self.monitor.as_mut().unwrap().start(now);
        self.advance();
        Ok(())
    }
    fn time(&mut self, now: Duration) -> bool {
        if self.monitor.is_none() || self.state == BootstrapState::New {
            return false;
        }
        if now < self.last_now {
            self.fail(BootstrapError::ClockRegression);
            return false;
        }
        if !self.valid_clock(now) {
            self.fail(BootstrapError::InvalidClock);
            return false;
        }
        self.last_now = now;
        if self.deadline.is_some_and(|d| now >= d) {
            match self.configuration_expired(now) {
                Ok(true) => {}
                Ok(false) => {
                    self.fail(BootstrapError::StartupTimeout);
                    return false;
                }
                Err(error) => {
                    self.fail(error);
                    return false;
                }
            }
        }
        true
    }
    fn valid_clock(&self, now: Duration) -> bool {
        self.wall_origin_unix
            .checked_add(now.as_secs())
            .is_some_and(|unix| unix <= u64::from(u32::MAX))
    }
    /// Follower time step: no monitor timer, but the same monotonic, wire-representable clock domain the control
    /// queues compute with. A terminal owner keeps its cause, like the leader path that drops its monitor.
    fn follower_time(&mut self, now: Duration) -> Result<(), BootstrapError> {
        if matches!(
            self.state,
            BootstrapState::Failed(_) | BootstrapState::Closed
        ) {
            return Ok(());
        }
        if now < self.last_now {
            self.fail(BootstrapError::ClockRegression);
            return Err(BootstrapError::ClockRegression);
        }
        if !self.valid_clock(now) {
            self.fail(BootstrapError::InvalidClock);
            return Err(BootstrapError::InvalidClock);
        }
        self.last_now = now;
        Ok(())
    }
    /// Monotonic bootstrap time in microseconds for the bounded control queues.
    fn control_now(&self) -> u64 {
        crate::time::clock_us(self.last_now)
            .expect("bootstrap time is validated against the narrower Unix wire clock")
    }
    pub fn on_connected(&mut self, conn: u64, now: Duration) {
        if self.time(now) {
            self.monitor.as_mut().unwrap().on_connected(conn, now);
            self.advance();
        }
    }
    pub fn on_closed(&mut self, conn: u64, now: Duration) {
        if self.time(now) {
            self.monitor.as_mut().unwrap().on_closed(conn, now);
            self.advance();
        }
    }
    pub fn on_bytes(&mut self, conn: u64, bytes: &[u8], now: Duration) {
        if self.time(now) {
            self.monitor.as_mut().unwrap().on_bytes(conn, bytes, now);
            self.advance();
        }
    }
    pub fn on_timer(&mut self, now: Duration) {
        if self.time(now) {
            self.monitor.as_mut().unwrap().on_timer(now);
            self.advance();
        }
    }
    /// Drive bounded control work even when no socket or monitor timer fired.
    pub fn progress(&mut self, now: Duration) -> Result<(), BootstrapError> {
        if self.follower.is_some() {
            self.follower_time(now)?;
            self.sync_view();
            return match self.state {
                BootstrapState::Failed(error) => Err(error),
                _ => Ok(()),
            };
        }
        // `advance` runs when the sleep proof fails (control or monitor work is runnable) or a deadline is due: with
        // the proof holding and no deadline due it has nothing to do, and every input that could change that (monitor
        // bytes, connection events, timers) runs it itself.
        if self.time(now) && (!self.can_sleep() || self.next_timer().is_some_and(|t| t <= now)) {
            self.advance();
        }
        match self.state {
            BootstrapState::Failed(error) => Err(error),
            _ => Ok(()),
        }
    }
    pub fn next_timer(&self) -> Option<Duration> {
        [
            self.deadline,
            self.statistics
                .as_ref()
                .and_then(|c| c.deadline())
                .map(Duration::from_micros),
            self.map_barriers
                .as_ref()
                .and_then(|c| c.queue.next_deadline_us())
                .map(Duration::from_micros),
            self.pool_checks
                .as_ref()
                .and_then(|c| c.queue.next_deadline_us())
                .map(Duration::from_micros),
            self.blocklists
                .as_ref()
                .and_then(|c| c.queue.next_deadline_us())
                .map(Duration::from_micros),
            self.commands
                .as_ref()
                .and_then(|control| control.queue.next_deadline_us())
                .map(Duration::from_micros),
            self.monitor.as_ref().and_then(MonClient::next_timer),
            self.snapshots
                .as_ref()
                .and_then(|s| s.queue.next_deadline())
                .map(Duration::from_micros),
        ]
        .into_iter()
        .flatten()
        .min()
    }
    /// A monitor connection has output to hand over or events to drain: the transport polls its stream only then.
    pub fn monitor_pending(&self) -> bool {
        self.monitor
            .as_ref()
            .is_some_and(|m| m.has_pending_work_with_blocked_output(&|_| false))
    }
    pub fn poll_io(&mut self) -> Option<IoCmd> {
        self.closes
            .pop_front()
            .or_else(|| self.monitor.as_mut()?.poll_io())
    }
    /// No locally runnable control, monitor output/event or retained result work.
    pub fn can_sleep(&self) -> bool {
        self.can_sleep_with_blocked_output(&|_| false)
    }
    /// Preserve all ready-work guards except exact transport-blocked messenger output.
    pub fn can_sleep_with_blocked_output(&self, blocked: &impl Fn(u64) -> bool) -> bool {
        if self
            .logs
            .as_ref()
            .is_some_and(|logs| !logs.entries.is_empty() || logs.error.is_some())
        {
            return false;
        }
        if self
            .configuration
            .as_ref()
            .is_some_and(|control| !control.can_wait())
        {
            return false;
        }
        if !self.closes.is_empty()
            || self
                .monitor
                .as_ref()
                .is_some_and(|m| m.has_pending_work_with_blocked_output(blocked))
        {
            return false;
        }
        if self
            .commands
            .as_ref()
            .is_some_and(|control| !control.queue.can_wait())
        {
            return false;
        }
        if self
            .statistics
            .as_ref()
            .is_some_and(|c| !c.can_wait(self.state == BootstrapState::Ready))
        {
            return false;
        }
        if self.snapshots.is_none()
            && self.map_barriers.is_none()
            && self.pool_checks.is_none()
            && self.blocklists.is_none()
        {
            return true;
        }
        let Some(map) = self.osdmap() else {
            return false;
        };
        if self.fsid != Some(map.fsid)
            || self
                .monitor
                .as_ref()
                .is_none_or(|m| Some(m.monmap().fsid) != self.fsid)
        {
            return false;
        }
        let Ok(now) = u64::try_from(self.last_now.as_micros()) else {
            return false;
        };
        self.snapshots
            .as_ref()
            .is_none_or(|s| s.queue.can_wait(now, map.epoch))
            && [self.map_barriers.as_ref(), self.pool_checks.as_ref()]
                .into_iter()
                .flatten()
                .all(|s| {
                    s.queue.can_wait(
                        now,
                        map.fsid,
                        map.epoch,
                        self.state == BootstrapState::Ready,
                    )
                })
            && self
                .blocklists
                .as_ref()
                .is_none_or(|s| s.can_wait(now, map))
    }
    pub fn connection_ids(&self) -> Vec<u64> {
        self.monitor
            .as_ref()
            .map_or_else(Vec::new, MonClient::conn_ids)
    }
    pub fn poll_output(&mut self, conn: u64) -> Vec<u8> {
        self.poll_monitor_output(|m| m.poll_output(conn))
    }
    /// Ordered wire prefix for a bounded transport handoff.
    pub fn poll_output_bounded(&mut self, conn: u64, maximum: usize) -> Vec<u8> {
        if maximum == 0 {
            return Vec::new();
        }
        self.poll_monitor_output(|m| m.poll_output_bounded(conn, maximum))
    }
    /// Monitor output handoff. Control state follows only the connection events drained with it: the transport asks
    /// every pump, so an output poll that drained none skips `advance` (the per-turn `progress` still runs it).
    fn poll_monitor_output(&mut self, poll: impl FnOnce(&mut MonClient) -> Vec<u8>) -> Vec<u8> {
        let Some(m) = self.monitor.as_mut() else {
            self.advance();
            return Vec::new();
        };
        let drained = m.events_drained();
        let out = poll(m);
        if m.events_drained() != drained {
            self.advance();
        }
        if self.monitor.is_some() {
            out
        } else {
            Vec::new()
        }
    }
    fn accept_fsid(&mut self, fsid: Uuid) -> bool {
        if fsid == Uuid::default() {
            return false;
        }
        if self.fsid.is_some_and(|old| old != fsid) {
            self.fail(BootstrapError::FsidMismatch);
            return false;
        }
        self.fsid = Some(fsid);
        true
    }
    fn authenticated(&mut self, gid: u64, mode: u32, method: u32) {
        if !self.methods.contains(&method) {
            self.fail(BootstrapError::AuthRejected);
        } else if !self.mode.accepts(mode) || (method == AUTH_NONE && mode != CON_MODE_CRC) {
            self.fail(BootstrapError::ModeRejected);
        } else if gid == 0 || self.identity.is_some_and(|old| old != gid) {
            self.fail(BootstrapError::IdentityLost);
        } else {
            self.identity = Some(gid);
            self.method = Some(method);
            self.service_method = Some(method);
            self.state = BootstrapState::AwaitingMaps;
            self.configuration_authenticated();
        }
    }
    fn drain_monitor_events(&mut self) {
        if !self.daemon_monitor {
            while self.next_event().is_some() {}
        }
    }
    fn monitor_event(&mut self, event: MonEvent) -> Option<MonEvent> {
        if !self.daemon_monitor {
            self.monitor_event_owned(event);
            return None;
        }
        match &event {
            MonEvent::CommandOnceReply { tid, .. } | MonEvent::CommandOnceLost { tid }
                if !self
                    .commands
                    .as_ref()
                    .is_some_and(|c| c.queue.owns_tid(*tid))
                    && !self
                        .blocklists
                        .as_ref()
                        .is_some_and(|c| c.queue.owns_tid(*tid)) =>
            {
                return Some(event);
            }
            MonEvent::Authenticated {
                global_id,
                mode,
                method,
                ..
            } => {
                self.authenticated(*global_id, *mode, *method);
            }
            MonEvent::SessionLost(_) => {
                self.monitor_event_owned(MonEvent::SessionLost(String::new()));
            }
            MonEvent::Config(snapshot) => {
                if self.configuration.is_some() {
                    self.configuration_snapshot(snapshot.clone());
                }
            }
            MonEvent::OsdMap { map, .. } => {
                self.accept_fsid(map.fsid);
            }
            MonEvent::MonMapUpdated { .. } => {
                self.accept_fsid(self.monitor.as_ref().unwrap().monmap().fsid);
            }
            MonEvent::Message { msg, .. }
                if matches!(
                    msg.as_ref(),
                    messages::AnyMessage::MLog(_)
                        | messages::AnyMessage::MStatfsReply(_)
                        | messages::AnyMessage::MGetPoolStatsReply(_)
                        | messages::AnyMessage::MMgrMap(_)
                        | messages::AnyMessage::MPoolOpReply(_)
                ) =>
            {
                self.monitor_event_owned(event);
                return None;
            }
            MonEvent::VersionReply { .. }
            | MonEvent::VersionFailed { .. }
            | MonEvent::CommandOnceReply { .. }
            | MonEvent::CommandOnceLost { .. }
            | MonEvent::AuthFailed(_) => {
                self.monitor_event_owned(event);
                return None;
            }
            _ => {}
        }
        Some(event)
    }
    fn monitor_event_owned(&mut self, event: MonEvent) {
        match event {
            MonEvent::Authenticated {
                global_id,
                mode,
                method,
                ..
            } => self.authenticated(global_id, mode, method),
            MonEvent::Config(snapshot) => self.configuration_snapshot(snapshot),
            MonEvent::SessionLost(_) => {
                self.configuration_monitor_lost();
                self.method = None;
                self.state = BootstrapState::Hunting;
                self.snapshot_progress(0);
                self.map_barrier_progress(0, 0);
                self.blocklist_monitor_lost();
                self.monitor_commands_lost();
                self.statistics_lost();
                for c in [self.map_barriers.as_mut(), self.pool_checks.as_mut()]
                    .into_iter()
                    .flatten()
                {
                    c.queue.monitor_lost();
                }
                if let Some(s) = &mut self.snapshots {
                    s.queue.monitor_lost();
                }
            }
            MonEvent::VersionReply {
                handle,
                version,
                oldest,
            } => {
                self.map_barrier_version(handle, version, oldest);
                self.blocklist_version(handle, version, oldest);
            }
            MonEvent::VersionFailed { .. } => {}
            MonEvent::CommandOnceReply {
                tid,
                version,
                r,
                rs,
                cmd,
                data,
            } => {
                if self
                    .commands
                    .as_ref()
                    .is_some_and(|control| control.queue.owns_tid(tid))
                {
                    self.monitor_command_reply(
                        tid,
                        cmd,
                        crate::MonitorCommandReply {
                            version,
                            result: r,
                            status: rs,
                            data,
                        },
                    );
                } else {
                    self.blocklist_reply(crate::BlocklistReply {
                        tid,
                        ack: crate::BlocklistAck {
                            version,
                            result: r,
                            status: rs,
                            data,
                        },
                        command: cmd,
                    });
                }
            }
            MonEvent::CommandOnceLost { tid } => {
                if !self.monitor_command_lost(tid) {
                    self.blocklist_lost(tid);
                }
            }

            // Before the first Ready an authentication failure ends the connect attempt. After it, MonClient keeps
            // hunting (a failed ticket renewal or a rejecting monitor is a session fault), so the client stays up and
            // OSD work continues on its held tickets and map.
            MonEvent::AuthFailed(reason) => {
                if self.was_ready {
                    diag::diag!(
                        "rustyrados: monitor authentication failed, hunting continues: {reason}"
                    );
                } else {
                    self.fail(BootstrapError::AuthRejected)
                }
            }
            MonEvent::OsdMap { map, .. } => {
                self.accept_fsid(map.fsid);
            }
            MonEvent::MonMapUpdated { .. } => {
                let fsid = self.monitor.as_ref().unwrap().monmap().fsid;
                self.accept_fsid(fsid);
            }
            MonEvent::Message { tid, msg } => {
                if let messages::AnyMessage::MLog(message) = *msg {
                    self.monitor_log_message(message);
                } else if let messages::AnyMessage::MStatfsReply(reply) = *msg {
                    self.statistics_reply(tid, reply);
                } else if let messages::AnyMessage::MGetPoolStatsReply(reply) = *msg {
                    self.pool_statistics_reply(tid, reply);
                } else if let messages::AnyMessage::MMgrMap(map) = *msg {
                    if self
                        .manager_map
                        .as_ref()
                        .is_none_or(|old| map.prefix.epoch > old.epoch)
                        && map.prefix.active_name.len() <= 4096
                    {
                        if let Some(m) = self.monitor.as_mut() {
                            m.subscription_got("mgrmap", u64::from(map.prefix.epoch));
                        }
                        self.manager_map = Some(map.prefix);
                    }
                } else if let messages::AnyMessage::MPoolOpReply(reply) = *msg {
                    self.snapshot_reply(tid, reply);
                }
            }
            _ => {}
        }
    }
    fn advance(&mut self) {
        if !self.snapshot_validate_maps() {
            return;
        }
        self.map_barrier_progress(0, 0);
        self.blocklist_progress(0);
        self.drain_monitor_events();
        if self
            .configuration
            .as_ref()
            .is_some_and(ConfigurationControl::only)
        {
            self.advance_configuration();
            return;
        }
        let Some(m) = self.monitor.as_ref() else {
            return;
        };
        let mon_fsid = m.monmap().fsid;
        let map = m.osdmap().map(|m| (m.fsid, m.epoch));
        let connected = m.is_connected();
        let osd_ticket = m
            .with_cephx(|c| {
                c.ticket(cephx::none::ENTITY_OSD)
                    .is_some_and(|ticket| ticket.session_key().is_some())
            })
            .unwrap_or(false);
        self.advance_readiness(connected, mon_fsid, map, osd_ticket);
        if self.monitor.is_none() {
            return;
        }
        let work = self.snapshots.as_ref().map_or(0, |s| s.work);
        self.snapshot_progress(work);
        self.snapshot_dispatch(work);
        let map_work = self.map_barriers.as_ref().map_or(0, |c| c.work);
        let pool_work = self.pool_checks.as_ref().map_or(0, |c| c.work);
        self.map_barrier_progress(map_work, pool_work);
        self.map_barrier_dispatch();
        let block_work = self.blocklists.as_ref().map_or(0, |c| c.work);
        self.blocklist_progress(block_work);
        self.blocklist_dispatch();
        let command_work = self.commands.as_ref().map_or(0, |control| control.work);
        self.monitor_commands_progress(command_work);
        self.monitor_commands_dispatch(command_work);
        self.statistics_dispatch();
        self.publish_view();
    }
    fn advance_readiness(
        &mut self,
        connected: bool,
        mon_fsid: Uuid,
        map: Option<(Uuid, u32)>,
        osd_ticket: bool,
    ) {
        let mon_known = self.accept_fsid(mon_fsid);
        if self.monitor.is_none() {
            return;
        }
        let map_ready = map.is_some_and(|(fsid, epoch)| self.accept_fsid(fsid) && epoch > 0);
        let service_ready = match self.method {
            Some(AUTH_NONE) => true,
            Some(AUTH_CEPHX) => osd_ticket,
            _ => false,
        };
        if self.monitor.is_some()
            && connected
            && self.identity.is_some()
            && mon_known
            && map_ready
            && service_ready
        {
            self.state = BootstrapState::Ready;
            self.deadline = None;
            self.was_ready = true;
        }
    }
    fn drop_monitor(&mut self) {
        self.configuration_stop();
        self.method = None;
        if let Some(mut monitor) = self.monitor.take() {
            let mut ids = monitor.conn_ids();
            // Closed/hunt-loser slots may already be removed while their Close is
            // still queued. Preserve those exact sockets too; discard unsent Dial.
            while let Some(io) = monitor.poll_io() {
                if let IoCmd::Close { conn } = io {
                    ids.push(conn);
                }
            }
            ids.sort_unstable();
            ids.dedup();
            for conn in ids {
                self.closes.push_back(IoCmd::Close { conn });
            }
        }
        self.deadline = None;
    }
    fn fail(&mut self, error: BootstrapError) {
        if error == BootstrapError::StartupTimeout {
            diag::diag!(
                "WARNING TIMEOUT {} bootstrap exceeded {}s (monitor authentication/maps)",
                cephx::none::type_name(self.entity.ty).unwrap_or("?"),
                self.timeout.as_secs_f64()
            );
        }
        self.logs = None;
        self.blocklist_stop(crate::BlocklistError::Bootstrap(error));
        self.monitor_commands_stop(crate::MonitorCommandError::Bootstrap(error));
        self.statistics_stop(StatisticsError::Bootstrap(error));
        for c in [self.map_barriers.as_mut(), self.pool_checks.as_mut()]
            .into_iter()
            .flatten()
        {
            c.queue.abort(crate::MapBarrierError::Bootstrap(error));
        }
        if let Some(s) = &mut self.snapshots {
            s.queue.abort(crate::SnapshotQueueError::Bootstrap(error));
        }
        self.drop_monitor();
        self.state = BootstrapState::Failed(error);
    }
    pub fn close(&mut self) {
        self.logs = None;
        self.blocklist_stop(crate::BlocklistError::Closed);
        self.monitor_commands_stop(crate::MonitorCommandError::Closed);
        self.statistics_stop(StatisticsError::Closed);
        for c in [self.map_barriers.as_mut(), self.pool_checks.as_mut()]
            .into_iter()
            .flatten()
        {
            c.queue.close();
        }
        if let Some(s) = &mut self.snapshots {
            s.queue.close();
        }
        self.drop_monitor();
        // Closing after a failure keeps its cause: the driver closes a terminal owner, and the caller still has to
        // tell a rejected login from an expired startup window.
        if !matches!(self.state, BootstrapState::Failed(_)) {
            self.state = BootstrapState::Closed;
        }
    }
}

impl Bootstrap {
    /// Current authenticated scalar listing profile; no map clone or implicit wait.
    pub fn list_layout(&self, pool: i64) -> Result<crate::ListLayout, crate::ListScanError> {
        let mon = self
            .monitor
            .as_ref()
            .ok_or(crate::ListScanError::NotReady)?;
        let map = mon.osdmap().ok_or(crate::ListScanError::NotReady)?;
        if self.identity.is_none() || map.epoch == 0 {
            return Err(crate::ListScanError::NotReady);
        }
        if self.fsid != Some(map.fsid) || self.fsid != Some(mon.monmap().fsid) {
            return Err(crate::ListScanError::Identity);
        }
        crate::ListLayout::from_map(map, pool)
    }
}

/// A mon we can dial: its addrvec has a v2 entry with an IP and a port (spec ip-addressing 4).
fn has_v2(a: &EntityAddrVec) -> bool {
    a.v2()
        .is_some_and(|x| !x.is_blank() && x.port() != 0 && x.ip().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn daemon_events_remain_in_monitor_until_pulled() {
        let mut b = Bootstrap::new(config()).unwrap();
        let mut native = monc::Config::new("client.native", None);
        native.methods = vec![cephx::modes::AUTH_NONE];
        b.configure_daemon_monitor(native).unwrap();
        b.monitor.as_mut().unwrap().start(Duration::ZERO);
        b.drain_monitor_events();
        assert!(b.next_event().is_some());
        assert!(b.next_event().is_none());
    }

    #[test]
    fn daemon_command_replies_and_losses_return_to_their_owner() {
        let mut b = Bootstrap::new(config()).unwrap();
        b.daemon_monitor = true;
        let event = MonEvent::CommandOnceReply {
            tid: 77,
            version: 148,
            r: 0,
            rs: "finished".into(),
            cmd: vec!["daemon-owned blocklist".into()],
            data: vec![1, 2, 3],
        };
        let MonEvent::CommandOnceReply {
            tid,
            version,
            r,
            rs,
            cmd,
            data,
        } = b
            .monitor_event(event)
            .expect("daemon must receive its command reply")
        else {
            panic!("command reply")
        };
        assert_eq!((tid, version, r), (77, 148, 0));
        assert_eq!(rs, "finished");
        assert_eq!(cmd, ["daemon-owned blocklist"]);
        assert_eq!(data, [1, 2, 3]);
        assert!(matches!(
            b.monitor_event(MonEvent::CommandOnceLost { tid: 78 }),
            Some(MonEvent::CommandOnceLost { tid: 78 })
        ));
        b.daemon_monitor = false;
        assert!(
            b.monitor_event(MonEvent::CommandOnceLost { tid: 79 })
                .is_none()
        );
    }

    #[test]
    fn events_move_once_and_internal_events_are_consumed() {
        let mut b = Bootstrap::new(config()).unwrap();
        b.daemon_monitor = true;
        let line = String::from("owned daemon diagnostic");
        let pointer = line.as_ptr();
        let MonEvent::Diag(moved) = b.monitor_event(MonEvent::Diag(line)).unwrap() else {
            panic!("diagnostic")
        };
        assert_eq!(moved.as_ptr(), pointer);
        assert!(
            b.monitor_event(MonEvent::VersionFailed { handle: 1 })
                .is_none()
        );
        assert!(matches!(
            b.monitor_event(MonEvent::KeysUpdated),
            Some(MonEvent::KeysUpdated)
        ));
    }

    #[test]
    fn daemon_messages_are_moved_without_a_type_whitelist() {
        let mut b = Bootstrap::new(config()).unwrap();
        b.daemon_monitor = true;
        for ty in [21, 45, 100, 999] {
            let msg = Box::new(messages::AnyMessage::Unknown {
                ty,
                version: 1,
                compat: 1,
                segments: messages::Segments::front(vec![1, 2, 3]),
            });
            let pointer = msg.as_ref() as *const messages::AnyMessage;
            let MonEvent::Message { tid, msg: moved } =
                b.monitor_event(MonEvent::Message { tid: 7, msg }).unwrap()
            else {
                panic!("message")
            };
            assert_eq!(tid, 7);
            assert_eq!(moved.as_ref() as *const messages::AnyMessage, pointer);
        }
        assert!(b.next_event().is_none());
    }

    #[test]
    fn startup_timeout_logs_entity_types_in_client_and_daemon_modes() {
        const CHILD: &str = "RUSTYRADOS_TIMEOUT_ENTITY_TEST";
        if std::env::var_os(CHILD).is_some() {
            for entity in ["client.timeout", "mds.timeout"] {
                for daemon in [false, true] {
                    let mut cfg = config();
                    cfg.entity = entity.into();
                    let mut b = Bootstrap::new(cfg).unwrap();
                    b.daemon_monitor = daemon;
                    b.start(Duration::ZERO).unwrap();
                    assert!(!b.time(Duration::from_millis(10)));
                    assert_eq!(
                        b.state(),
                        BootstrapState::Failed(BootstrapError::StartupTimeout)
                    );
                }
            }
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "bootstrap::tests::startup_timeout_logs_entity_types_in_client_and_daemon_modes",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        for role in ["client", "mds"] {
            assert_eq!(stderr.matches(&format!("WARNING TIMEOUT {role} bootstrap exceeded 0.01s (monitor authentication/maps)")).count(), 2, "{stderr}");
        }
    }

    #[test]
    fn compatible_constructor_selects_monitor_wire_shape_without_widening_strict() {
        for manager in [false, true] {
            let strict = if manager {
                Bootstrap::new_with_manager(config())
            } else {
                Bootstrap::new(config())
            }
            .unwrap();
            let compatible = Bootstrap::new_compatible(config(), manager).unwrap();
            assert_eq!(
                strict.monitor.as_ref().unwrap().frame_limits(),
                msgr2::Limits::default()
            );
            assert_eq!(
                compatible.monitor.as_ref().unwrap().frame_limits(),
                msgr2::Limits::wire_shape()
            );
            assert_eq!(strict.entity, compatible.entity);
            assert_eq!(strict.manager_enabled(), compatible.manager_enabled());
        }
    }

    fn policy_config(auth: ClientAuth) -> BootstrapConfig<ClientAuth> {
        BootstrapConfig {
            entity: "client.native".into(),
            key: auth,
            monitors: monc::parse_mon_host("v2:127.0.0.1:3300").unwrap(),
            expected_fsid: None,
            mode: MessengerMode::PreferSecure,
            startup_timeout: Duration::from_millis(10),
            wall_origin_unix: 100,
        }
    }
    #[test]
    fn typed_auth_preserves_order_and_cephx_key_validation() {
        for methods in [vec![AUTH_CEPHX, AUTH_NONE], vec![AUTH_NONE, AUTH_CEPHX]] {
            let auth = ClientAuth::new(methods.clone(), Some(config().key)).unwrap();
            assert_eq!(auth.methods(), methods);
            let b = Bootstrap::new(policy_config(auth)).unwrap();
            assert_eq!(b.methods, methods);
            assert_eq!(b.method, None);
        }
        assert_eq!(
            ClientAuth::new(vec![], None).unwrap_err(),
            BootstrapError::AuthRejected
        );
        assert_eq!(
            ClientAuth::new(vec![4], None).unwrap_err(),
            BootstrapError::AuthRejected
        );
        assert_eq!(
            ClientAuth::new(vec![AUTH_CEPHX], None).unwrap_err(),
            BootstrapError::InvalidKey
        );
        let bad = CryptoKey::new(cephx::key::KeyType::None, Default::default(), &[]);
        assert_eq!(
            Bootstrap::new(policy_config(bad.into())).unwrap_err(),
            BootstrapError::InvalidKey
        );
        let auth = ClientAuth::new(vec![AUTH_NONE], None).unwrap();
        assert!(auth.into_parts().1.is_none());
    }
    #[test]
    fn none_bootstrap_readiness_requires_identity_fsid_and_initial_map_not_tickets() {
        let mut b = Bootstrap::new(policy_config(
            ClientAuth::new(vec![AUTH_NONE], None).unwrap(),
        ))
        .unwrap();
        let fsid = Uuid([7; 16]);
        b.advance_readiness(true, fsid, Some((fsid, 1)), false);
        assert_ne!(b.state(), BootstrapState::Ready);
        b.authenticated(77, CON_MODE_CRC, AUTH_NONE);
        assert_eq!(b.state(), BootstrapState::AwaitingMaps);
        assert!(b.with_cephx(|_| ()).is_none());
        b.advance_readiness(false, fsid, Some((fsid, 1)), false);
        assert_ne!(b.state(), BootstrapState::Ready);
        b.advance_readiness(true, fsid, None, false);
        assert_ne!(b.state(), BootstrapState::Ready);
        b.advance_readiness(true, fsid, Some((fsid, 0)), false);
        assert_ne!(b.state(), BootstrapState::Ready);
        b.advance_readiness(true, fsid, Some((fsid, 1)), false);
        assert_eq!(b.state(), BootstrapState::Ready);
        assert_eq!(b.identity(), Some(77));
        b.advance_readiness(true, fsid, Some((Uuid([8; 16]), 1)), false);
        assert_eq!(
            b.state(),
            BootstrapState::Failed(BootstrapError::FsidMismatch)
        );
        let mut b = Bootstrap::new(policy_config(
            ClientAuth::new(vec![AUTH_NONE], None).unwrap(),
        ))
        .unwrap();
        b.authenticated(77, CON_MODE_CRC, AUTH_NONE);
        b.advance_readiness(true, Uuid::default(), None, false);
        assert_eq!(b.state(), BootstrapState::AwaitingMaps);
    }
    #[test]
    fn monitor_loss_retains_service_authentication_after_ready() {
        let mut b = Bootstrap::new(policy_config(
            ClientAuth::new(vec![AUTH_NONE], None).unwrap(),
        ))
        .unwrap();
        let fsid = Uuid([7; 16]);
        b.authenticated(77, CON_MODE_CRC, AUTH_NONE);
        b.advance_readiness(true, fsid, Some((fsid, 1)), false);
        assert_eq!(b.state(), BootstrapState::Ready);
        b.monitor_event(MonEvent::SessionLost("renewal unavailable".into()));
        assert_eq!(b.state(), BootstrapState::Hunting);
        assert!(b.service_ticket_available(cephx::none::ENTITY_OSD));
        assert!(
            b.service_auth(cephx::none::ENTITY_OSD, MessengerMode::Crc)
                .is_ok()
        );
        assert_eq!(b.identity(), Some(77));
    }
    #[test]
    fn monitor_auth_failure_ends_connect_but_only_rehunts_after_ready() {
        let none = || policy_config(ClientAuth::new(vec![AUTH_NONE], None).unwrap());
        let fsid = Uuid([7; 16]);
        let mut b = Bootstrap::new(none()).unwrap();
        b.authenticated(77, CON_MODE_CRC, AUTH_NONE);
        b.monitor_event(MonEvent::AuthFailed("before ready".into()));
        assert_eq!(
            b.state(),
            BootstrapState::Failed(BootstrapError::AuthRejected)
        );
        let mut b = Bootstrap::new(none()).unwrap();
        b.authenticated(77, CON_MODE_CRC, AUTH_NONE);
        b.advance_readiness(true, fsid, Some((fsid, 1)), false);
        assert_eq!(b.state(), BootstrapState::Ready);
        b.monitor_event(MonEvent::SessionLost("hunt".into()));
        b.monitor_event(MonEvent::AuthFailed("renewal rejected".into()));
        assert!(!matches!(b.state(), BootstrapState::Failed(_)));
        assert_eq!(b.identity(), Some(77));
        b.authenticated(77, CON_MODE_CRC, AUTH_NONE);
        b.advance_readiness(true, fsid, Some((fsid, 2)), false);
        assert_eq!(b.state(), BootstrapState::Ready);
    }
    #[test]
    fn mixed_policy_service_auth_uses_completed_method_and_cephx_readiness_keeps_ticket_gate() {
        let auth = ClientAuth::new(vec![AUTH_CEPHX, AUTH_NONE], Some(config().key)).unwrap();
        let mut b = Bootstrap::new(policy_config(auth)).unwrap();
        assert!(
            b.service_auth(cephx::none::ENTITY_OSD, MessengerMode::Crc)
                .is_err()
        );
        b.authenticated(77, CON_MODE_SECURE, AUTH_CEPHX);
        for service in [cephx::none::ENTITY_OSD, cephx::none::ENTITY_MGR] {
            assert!(!b.service_ticket_available(service));
        }
        b.advance_readiness(true, Uuid([7; 16]), Some((Uuid([7; 16]), 1)), false);
        assert_eq!(b.state(), BootstrapState::AwaitingMaps);
        // Offered NONE must not replace a missing cephx service ticket.
        assert!(
            b.service_auth(cephx::none::ENTITY_OSD, MessengerMode::Crc)
                .is_err()
        );
        b.advance_readiness(true, Uuid([7; 16]), Some((Uuid([7; 16]), 1)), true);
        assert_eq!(b.state(), BootstrapState::Ready);
        b.monitor_event(MonEvent::SessionLost("test".into()));
        assert_eq!(b.method, None);
        assert!(
            b.service_auth(cephx::none::ENTITY_OSD, MessengerMode::Crc)
                .is_err()
        );
        b.authenticated(77, CON_MODE_CRC, AUTH_NONE);
        for service in [cephx::none::ENTITY_OSD, cephx::none::ENTITY_MGR] {
            assert!(b.service_ticket_available(service));
            let mut auth = b
                .service_auth(service, MessengerMode::PreferSecure)
                .unwrap();
            assert_eq!(
                auth.get_auth_request(service as u8).unwrap().method,
                AUTH_NONE
            );
        }
        b.authenticated(78, CON_MODE_CRC, AUTH_NONE);
        assert_eq!(
            b.state(),
            BootstrapState::Failed(BootstrapError::IdentityLost)
        );
    }
    #[test]
    fn none_bootstrap_rejects_zero_identity_and_secure_completion() {
        for (gid, mode, error) in [
            (0, CON_MODE_CRC, BootstrapError::IdentityLost),
            (77, CON_MODE_SECURE, BootstrapError::ModeRejected),
        ] {
            let mut b = Bootstrap::new(policy_config(
                ClientAuth::new(vec![AUTH_NONE], None).unwrap(),
            ))
            .unwrap();
            b.authenticated(gid, mode, AUTH_NONE);
            assert_eq!(b.state(), BootstrapState::Failed(error));
            assert_eq!(b.identity(), None);
            assert_eq!(b.method, None);
        }
    }
    #[test]
    fn keyless_bootstrap_and_crc_fallback_advance_epoch_waiters() {
        use msgr2::auth::{AuthSecrets, AuthServerHandler, AuthServerStep};
        #[derive(Debug)]
        struct MonitorAuth(Vec<u8>);
        impl AuthServerHandler for MonitorAuth {
            fn supported_methods(&self, _: u8) -> Vec<u32> {
                vec![AUTH_NONE]
            }
            fn supported_modes(&self, _: u8, _: u32) -> Vec<u32> {
                vec![CON_MODE_CRC]
            }
            fn handle_auth_request(
                &mut self,
                peer: u8,
                more: bool,
                method: u32,
                mode: u32,
                payload: &[u8],
            ) -> AuthServerStep {
                assert_eq!(u32::from(peer), cephx::none::ENTITY_CLIENT);
                assert!(!more);
                assert_eq!((method, mode), (AUTH_NONE, CON_MODE_CRC));
                let mut decoder = denc::Decoder::new(payload);
                let phase = decoder.u8().unwrap();
                let name =
                    <cephx::none::ByteEntityName as denc::Decode>::decode(&mut decoder).unwrap();
                let gid = decoder.u64().unwrap();
                assert_eq!(phase, cephx::none::AUTH_MODE_MON);
                assert_eq!(
                    name,
                    cephx::none::ByteEntityName::parse_bytes(&self.0).unwrap()
                );
                assert_eq!(gid, 0);
                AuthServerStep::Done {
                    reply: vec![],
                    global_id: 77,
                    peer_name: None,
                    secrets: AuthSecrets::default(),
                }
            }
        }
        fn exchange(b: &mut Bootstrap, server: &mut msgr2::Connection, conn: u64) {
            for _ in 0..1000 {
                let client_bytes = b.poll_output(conn);
                if !client_bytes.is_empty() {
                    server.on_bytes(&client_bytes, Duration::ZERO);
                }
                let server_bytes = server.poll_output();
                if !server_bytes.is_empty() {
                    b.on_bytes(conn, &server_bytes, Duration::ZERO);
                }
                while let Some(event) = server.poll_event() {
                    assert!(!matches!(event, msgr2::Event::Fault(_)), "{event:?}");
                }
                if client_bytes.is_empty() && server_bytes.is_empty() {
                    return;
                }
            }
            panic!("in-memory auth exchange did not quiesce");
        }
        for entity in [
            b"client.native".as_slice(),
            b"osd.3",
            b"mgr.",
            b"auth.name with spaces",
            b"client.\xff nested.id",
            b"osd.\x80",
            b"mon.\xff",
            b"mds.. \x81",
            b"mgr.\xfe",
            b"auth.\xff id",
        ] {
            let config = policy_config(ClientAuth::new(vec![AUTH_NONE], None).unwrap());
            let mut b = if let Ok(entity) = std::str::from_utf8(entity) {
                let mut config = config;
                config.entity = entity.into();
                Bootstrap::new(config).unwrap()
            } else {
                let mut config = config.into_bytes();
                config.entity = entity.to_vec();
                Bootstrap::new_bytes(config).unwrap()
            };
            b.start(Duration::ZERO).unwrap();
            let Some(IoCmd::Dial { conn, target }) = b.poll_io() else {
                panic!("monitor dial")
            };
            let cfg = msgr2::Config::new(
                denc::types::EntityName::new(denc::types::EntityName::MON, 0),
                EntityAddrVec::single(target),
                msgr2::PolicyTable::uniform(msgr2::Policy::stateless_server(0)),
            );
            let mut server = msgr2::Connection::server(
                999,
                cfg,
                msgr2::SessionTable::new(1),
                Box::new(MonitorAuth(entity.to_vec())),
                denc::types::EntityAddr::v4(2, 0, [127, 0, 0, 1], 40000),
                Duration::ZERO,
            );
            b.on_connected(conn, Duration::ZERO);
            exchange(&mut b, &mut server, conn);
            assert_eq!(b.identity(), Some(77));
            assert_eq!(b.method, Some(AUTH_NONE));
            assert_eq!(b.state(), BootstrapState::AwaitingMaps);
            assert!(b.with_cephx(|_| ()).is_none());
            let fsid = Uuid([7; 16]);
            let mut monmap = b.monitor.as_ref().unwrap().monmap().clone();
            monmap.fsid = fsid;
            monmap.epoch = 1;
            let message: messages::AnyMessage = messages::MMonMap {
                monmap: monmap.encode_to().unwrap(),
            }
            .into();
            let (msg_type, version, compat_version, segments) = message.encode(u64::MAX).unwrap();
            server.send_message(msgr2::Message {
                msg_type,
                version,
                compat_version,
                front: segments.front,
                middle: segments.middle,
                data: segments.data,
                ..Default::default()
            });
            exchange(&mut b, &mut server, conn);
            assert_eq!(b.fsid(), Some(fsid));
            assert_eq!(b.state(), BootstrapState::AwaitingMaps);
            let mut map = OsdMap::default();
            map.fsid = fsid;
            map.epoch = 1;
            // A map reaches the client through `on_bytes` (which advances); this fixture installs it directly.
            b.monitor.as_mut().unwrap().set_osdmap(map);
            b.advance();
            assert_eq!(b.state(), BootstrapState::Ready);

            // Daemon callers pull monitor events themselves, as the MDS does.
            b.daemon_monitor = true;
            // A CRC failure must leave the base installed, then a full-map
            // answer must publish the new epoch to existing barrier waiters.
            b.enable_map_barriers(
                crate::MapBarrierLimits {
                    slots: 1,
                    query_attempts: 1,
                },
                1,
            )
            .unwrap();
            let waiter = b
                .submit_map_barrier(crate::MapBarrierRequest::Epoch(2), 10_000)
                .unwrap();
            let base = b.osdmap().unwrap().clone();
            let mut inc = osdmap::Incremental {
                fsid,
                epoch: 2,
                ..Default::default()
            };
            let mut next = base.clone();
            next.apply_incremental(&inc).unwrap();
            inc.full_crc = next.crc(inc.encode_features).unwrap() ^ 1;
            let send = |server: &mut msgr2::Connection, message: messages::MOSDMap| {
                let message: messages::AnyMessage = message.into();
                let (msg_type, version, compat_version, segments) =
                    message.encode(u64::MAX).unwrap();
                assert!(server.send_message(msgr2::Message {
                    msg_type,
                    version,
                    compat_version,
                    front: segments.front,
                    middle: segments.middle,
                    data: segments.data,
                    ..Default::default()
                }));
            };
            send(
                &mut server,
                messages::MOSDMap {
                    fsid,
                    incremental_maps: [(2, inc.encode_inc().unwrap())].into(),
                    newest_map: 2,
                    ..Default::default()
                },
            );
            exchange(&mut b, &mut server, conn);
            assert_eq!(b.osdmap().unwrap().epoch, 1);
            assert_eq!(b.monitor.as_ref().unwrap().osdmap_inc_fallbacks(), 1);
            assert_eq!(b.poll_map_barriers_into(&mut [None]), 0);
            let generation = b.osdmap_generation();
            send(
                &mut server,
                messages::MOSDMap {
                    fsid,
                    maps: [(2, next.encode_full().unwrap())].into(),
                    newest_map: 2,
                    ..Default::default()
                },
            );
            exchange(&mut b, &mut server, conn);
            assert_eq!(b.osdmap().unwrap().epoch, 2);
            assert!(b.osdmap_generation() > generation);
            assert!(std::iter::from_fn(|| b.next_event()).any(|event| {
                matches!(event, MonEvent::OsdMap { epoch: 2, map, .. } if map.epoch == 2)
            }));
            let mut completions = [None];
            assert_eq!(b.poll_map_barriers_into(&mut completions), 1);
            let completion = completions[0].take().unwrap();
            assert_eq!(completion.token, waiter);
            assert!(matches!(
                completion.outcome,
                crate::MapBarrierOutcome::Reached {
                    target_epoch: 2,
                    ..
                }
            ));

            // The daemon can receive queued maps while handling monitor events
            // after the driver's last progress pass. Event delivery itself must
            // reconcile the barrier and FE follower view before the caller waits.
            let cell = crate::ViewCell::new(1);
            b.publish_view_to(cell.clone());
            let waiter = b
                .submit_map_barrier(crate::MapBarrierRequest::Epoch(3), 10_000)
                .unwrap();
            let mut inc = osdmap::Incremental {
                fsid,
                epoch: 3,
                ..Default::default()
            };
            let mut next = b.osdmap().unwrap().clone();
            next.apply_incremental(&inc).unwrap();
            inc.full_crc = next.crc(inc.encode_features).unwrap() ^ 1;
            send(
                &mut server,
                messages::MOSDMap {
                    fsid,
                    incremental_maps: [(3, inc.encode_inc().unwrap())].into(),
                    newest_map: 3,
                    ..Default::default()
                },
            );
            b.daemon_monitor_mut()
                .unwrap()
                .on_bytes(conn, &server.poll_output(), Duration::ZERO);
            while b.next_event().is_some() {}
            assert_eq!(b.osdmap().unwrap().epoch, 2);
            assert_eq!(b.monitor.as_ref().unwrap().osdmap_inc_fallbacks(), 2);
            assert_eq!(b.poll_map_barriers_into(&mut [None]), 0);
            send(
                &mut server,
                messages::MOSDMap {
                    fsid,
                    maps: [(3, next.encode_full().unwrap())].into(),
                    newest_map: 3,
                    ..Default::default()
                },
            );
            b.daemon_monitor_mut()
                .unwrap()
                .on_bytes(conn, &server.poll_output(), Duration::ZERO);
            assert!(
                std::iter::from_fn(|| b.next_event())
                    .any(|event| { matches!(event, MonEvent::OsdMap { epoch: 3, .. }) })
            );
            assert_eq!(b.state(), BootstrapState::Ready);
            assert_eq!(
                cell.load().unwrap().map.as_ref().unwrap().epoch,
                3,
                "late daemon map delivery publishes the FE view without another driver step"
            );
            let mut completions = [None];
            assert_eq!(b.poll_map_barriers_into(&mut completions), 1);
            assert_eq!(completions[0].as_ref().unwrap().token, waiter);
            assert!(matches!(
                completions[0].as_ref().unwrap().outcome,
                crate::MapBarrierOutcome::Reached {
                    target_epoch: 3,
                    ..
                }
            ));
        }
    }
    fn config() -> BootstrapConfig {
        BootstrapConfig {
            entity: "client.native".into(),
            key: CryptoKey::new(
                cephx::key::KeyType::Aes,
                Default::default(),
                b"1234567890abcdef",
            ),
            monitors: monc::parse_mon_host("v2:127.0.0.1:3300").unwrap(),
            expected_fsid: None,
            mode: MessengerMode::Secure,
            startup_timeout: Duration::from_millis(10),
            wall_origin_unix: 100,
        }
    }
    #[test]
    fn configured_identity_accepts_generic_roles_and_preserves_id() {
        for role in ["auth", "mon", "osd", "mds", "mgr", "client"] {
            for id in ["", "name with spaces", "nested.id"] {
                let mut cfg = config();
                cfg.entity = format!("{role}.{id}");
                let expected = cephx::none::EntityName::parse(&cfg.entity).unwrap();
                let bootstrap = Bootstrap::new(cfg).unwrap();
                assert_eq!(bootstrap.entity, expected);
            }
        }
    }
    #[test]
    fn byte_bootstrap_none_service_authorizers_outlive_config_and_coordinator() {
        for role in ["auth", "mon", "osd", "mds", "mgr", "client"] {
            for service in [cephx::none::ENTITY_OSD, cephx::none::ENTITY_MGR] {
                let mut config =
                    policy_config(ClientAuth::new(vec![AUTH_NONE], None).unwrap()).into_bytes();
                let mut input = format!("{role}.").into_bytes();
                input.extend_from_slice(b"\xff\x80 spaces.extra.dot");
                config.entity = input.clone();
                let expected_name = cephx::none::ByteEntityName::parse_bytes(&input).unwrap();
                let mut bootstrap = Bootstrap::new_with_manager_bytes(config).unwrap();
                input.fill(b'x');
                assert_eq!(bootstrap.auth_entity(), &expected_name);
                bootstrap.authenticated(77, CON_MODE_CRC, AUTH_NONE);
                let mut auth = bootstrap.service_auth(service, MessengerMode::Crc).unwrap();
                drop(bootstrap);
                let request = auth.get_auth_request(service as u8).unwrap();
                let mut wanted = vec![1];
                wanted.extend_from_slice(&expected_name.ty.to_le_bytes());
                wanted.extend_from_slice(&(expected_name.id.len() as u32).to_le_bytes());
                wanted.extend_from_slice(&expected_name.id);
                wanted.extend_from_slice(&77u64.to_le_bytes());
                assert_eq!(request.method, AUTH_NONE);
                assert_eq!(request.payload, wanted);
                assert_eq!(
                    auth.get_auth_request(service as u8).unwrap().payload,
                    wanted
                );
            }
        }
    }
    #[test]
    fn byte_bootstrap_direct_secret_reaches_cephx_monitor_request_without_text_identity() {
        let mut cfg = config().into_bytes();
        cfg.entity = b"mds.\xff spaces.extra.dot".to_vec();
        let bootstrap = Bootstrap::new_bytes(cfg).unwrap();
        let mut auth = bootstrap.with_cephx(Clone::clone).unwrap();
        drop(bootstrap);
        let id = b"\xff spaces.extra.dot";
        let mut wanted = vec![10, 2, 0, 0, 0];
        wanted.extend_from_slice(&(id.len() as u32).to_le_bytes());
        wanted.extend_from_slice(id);
        wanted.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(auth.start(), wanted);
        let native = Bootstrap::new(config()).unwrap();
        let byte_adapter = Bootstrap::new_bytes(config().into_bytes()).unwrap();
        assert_eq!(
            native.with_cephx(|auth| auth.clone().start()),
            byte_adapter.with_cephx(|auth| auth.clone().start())
        );
    }
    #[test]
    fn native_byte_configuration_rejects_nul_but_cstr_adapter_stops_at_first_nul() {
        let mut config = config().into_bytes();
        config.entity = b"client.\xff\0ignored".to_vec();
        assert_eq!(
            Bootstrap::new_bytes(config).unwrap_err(),
            BootstrapError::InvalidEntity
        );
        // Models only the future C boundary; no length-bearing C API is introduced.
        let input = std::ffi::CStr::from_bytes_until_nul(b"client.\xff\0ignored").unwrap();
        let mut config = self::config().into_bytes();
        config.entity = input.to_bytes().to_vec();
        assert_eq!(
            Bootstrap::new_bytes(config).unwrap().auth_entity().id,
            [255]
        );
    }
    #[test]
    fn invalid_configuration_rejected_before_constructing_any_monitor() {
        for entity in ["unknown.3", "client", "", "client.bad\0name"] {
            let mut cfg = config();
            cfg.entity = entity.into();
            assert_eq!(
                Bootstrap::new(cfg).unwrap_err(),
                BootstrapError::InvalidEntity
            );
        }
        let mut cfg = config();
        cfg.key = CryptoKey::new(cephx::key::KeyType::None, Default::default(), b"not a key");
        assert_eq!(Bootstrap::new(cfg).unwrap_err(), BootstrapError::InvalidKey);
        let mut cfg = config();
        cfg.monitors.clear();
        assert_eq!(
            Bootstrap::new(cfg).unwrap_err(),
            BootstrapError::InvalidMonitors
        );
        let mut cfg = config();
        cfg.monitors = monc::parse_mon_host("v1:127.0.0.1:6789").unwrap();
        assert_eq!(
            Bootstrap::new(cfg).unwrap_err(),
            BootstrapError::InvalidMonitors
        );
        let mut cfg = config();
        cfg.startup_timeout = Duration::ZERO;
        assert_eq!(
            Bootstrap::new(cfg).unwrap_err(),
            BootstrapError::InvalidTimeout
        );
        let mut cfg = config();
        cfg.expected_fsid = Some(Uuid::default());
        assert_eq!(
            Bootstrap::new(cfg).unwrap_err(),
            BootstrapError::InvalidFsid
        );
    }
    #[test]
    fn startup_hunts_do_not_extend_deadline_and_expiry_closes_owned_connections() {
        let mut b = Bootstrap::new(config()).unwrap();
        b.start(Duration::from_millis(5)).unwrap();
        let ids = b.connection_ids();
        assert!(!ids.is_empty());
        assert_eq!(b.next_timer(), Some(Duration::from_millis(15)));
        b.on_closed(ids[0], Duration::from_millis(6));
        b.on_timer(Duration::from_millis(15));
        assert_eq!(
            b.state(),
            BootstrapState::Failed(BootstrapError::StartupTimeout)
        );
        assert_eq!(b.next_timer(), None);
        assert!(b.connection_ids().is_empty());
        let mut closes = vec![];
        while let Some(io) = b.poll_io() {
            match io {
                IoCmd::Close { conn } => closes.push(conn),
                _ => panic!("dial after failure"),
            }
        }
        assert!(closes.contains(&ids[0]));
        assert!(b.poll_output(ids[0]).is_empty());
    }
    #[test]
    fn clock_regression_and_overflow_fail_closed() {
        let mut b = Bootstrap::new(config()).unwrap();
        assert_eq!(b.start(Duration::MAX), Err(BootstrapError::InvalidTimeout));
        assert_eq!(b.poll_io(), None);
        let mut b = Bootstrap::new(config()).unwrap();
        b.start(Duration::from_millis(5)).unwrap();
        b.on_bytes(999, &[], Duration::from_millis(4));
        assert_eq!(
            b.state(),
            BootstrapState::Failed(BootstrapError::ClockRegression)
        );
    }
    #[test]
    fn explicit_close_drains_exact_ids_and_is_idempotent() {
        let mut b = Bootstrap::new(config()).unwrap();
        b.start(Duration::ZERO).unwrap();
        let ids = b.connection_ids();
        b.close();
        b.close();
        let mut closes = vec![];
        while let Some(io) = b.poll_io() {
            match io {
                IoCmd::Close { conn } => closes.push(conn),
                _ => panic!("dial after close"),
            }
        }
        closes.sort_unstable();
        let mut ids = ids;
        ids.sort_unstable();
        assert_eq!(closes, ids);
        b.on_connected(1, Duration::from_secs(1));
        assert_eq!(b.state(), BootstrapState::Closed);
    }
    #[test]
    fn invalid_wall_clock_and_late_overflow_never_enter_monc() {
        let mut cfg = config();
        cfg.wall_origin_unix = u64::MAX;
        assert_eq!(
            Bootstrap::new(cfg).unwrap_err(),
            BootstrapError::InvalidClock
        );
        let mut cfg = config();
        cfg.wall_origin_unix = u64::from(u32::MAX);
        let mut b = Bootstrap::new(cfg).unwrap();
        b.start(Duration::ZERO).unwrap();
        b.on_timer(Duration::from_secs(1));
        assert_eq!(
            b.state(),
            BootstrapState::Failed(BootstrapError::InvalidClock)
        );
        let mut b = Bootstrap::new(config()).unwrap();
        assert_eq!(
            b.start(Duration::from_secs(u64::MAX - 1)),
            Err(BootstrapError::InvalidClock)
        );
    }
    #[test]
    fn fsid_is_inferred_once_and_mismatches_are_terminal() {
        let mut b = Bootstrap::new(config()).unwrap();
        assert!(!b.accept_fsid(Uuid::default()));
        assert_eq!(b.fsid(), None);
        assert!(b.accept_fsid(Uuid([7; 16])));
        assert!(b.accept_fsid(Uuid([7; 16])));
        assert!(!b.accept_fsid(Uuid([8; 16])));
        assert_eq!(
            b.state(),
            BootstrapState::Failed(BootstrapError::FsidMismatch)
        );
        let mut cfg = config();
        cfg.expected_fsid = Some(Uuid([9; 16]));
        let mut b = Bootstrap::new(cfg).unwrap();
        assert!(!b.accept_fsid(Uuid([7; 16])));
    }
    #[test]
    fn identity_and_mode_policy_never_fall_back_or_retag() {
        let mut b = Bootstrap::new(config()).unwrap();
        b.authenticated(7, CON_MODE_SECURE, AUTH_CEPHX);
        assert_eq!(b.state(), BootstrapState::AwaitingMaps);
        b.authenticated(7, CON_MODE_SECURE, AUTH_CEPHX);
        b.authenticated(8, CON_MODE_SECURE, AUTH_CEPHX);
        assert_eq!(
            b.state(),
            BootstrapState::Failed(BootstrapError::IdentityLost)
        );
        assert_eq!(b.identity(), Some(7));
        let mut b = Bootstrap::new(config()).unwrap();
        b.authenticated(7, CON_MODE_CRC, AUTH_CEPHX);
        assert_eq!(
            b.state(),
            BootstrapState::Failed(BootstrapError::ModeRejected)
        );
        let mut b = Bootstrap::new(config()).unwrap();
        b.authenticated(7, CON_MODE_SECURE, cephx::modes::AUTH_NONE);
        assert_eq!(
            b.state(),
            BootstrapState::Failed(BootstrapError::AuthRejected)
        );
    }
    #[test]
    fn ipv6_v2_and_secret_free_debug() {
        let mut cfg = config();
        cfg.monitors = monc::parse_mon_host("v2:[::1]:3300").unwrap();
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("1234567890abcdef"));
        assert!(!rendered.contains(&cfg.key.to_base64().unwrap()));
        assert_eq!(Bootstrap::new(cfg).unwrap().state(), BootstrapState::New);
    }
    /// A mon_host list may hold legacy (msgr1 only) entries next to v2 ones: the msgr2 client skips the legacy ones
    /// instead of rejecting the whole list (spec ip-addressing 5).
    #[test]
    fn legacy_mon_entries_are_skipped_in_a_mixed_list() {
        let mut cfg = config();
        cfg.monitors =
            monc::parse_mon_host("v1:127.0.0.1:6789,[fd00::1]:3300,v1:[fd00::2]:6789").unwrap();
        assert_eq!(Bootstrap::new(cfg).unwrap().state(), BootstrapState::New);
        let mut cfg = config();
        cfg.monitors = monc::parse_mon_host("v1:127.0.0.1:6789,v1:[fd00::2]:6789").unwrap();
        assert_eq!(
            Bootstrap::new(cfg).unwrap_err(),
            BootstrapError::InvalidMonitors,
            "nothing left to dial"
        );
    }

    #[test]
    fn typed_unknown_address_family_and_zero_port_are_rejected() {
        let mut cfg = config();
        cfg.monitors[0].0[0].family = 0;
        assert_eq!(
            Bootstrap::new(cfg).unwrap_err(),
            BootstrapError::InvalidMonitors
        );
        let mut cfg = config();
        cfg.monitors[0].0[0].data[0] = 0;
        cfg.monitors[0].0[0].data[1] = 0;
        assert_eq!(
            Bootstrap::new(cfg).unwrap_err(),
            BootstrapError::InvalidMonitors
        );
    }
    fn aes(byte: u8) -> CryptoKey {
        CryptoKey::new(cephx::key::KeyType::Aes, Default::default(), &[byte; 16])
    }
    fn osd_ticket(secret_id: u64, validity: u32, now: u64) -> cephx::ticket::TicketHandler {
        let mut t = cephx::ticket::TicketHandler::new(cephx::none::ENTITY_OSD);
        t.install(
            cephx::ticket::TicketEntry {
                service_id: cephx::none::ENTITY_OSD,
                session_key: aes(secret_id as u8),
                validity: denc::types::UTime {
                    sec: validity,
                    nsec: 0,
                },
                blob: cephx::types::TicketBlob {
                    secret_id,
                    blob: vec![1, 2, 3],
                },
            },
            Duration::from_secs(now),
        );
        t
    }
    fn map_at(epoch: u32) -> std::sync::Arc<OsdMap> {
        let mut m = OsdMap::default();
        m.epoch = epoch;
        std::sync::Arc::new(m)
    }
    fn entity() -> cephx::none::ByteEntityName {
        cephx::none::ByteEntityName {
            ty: cephx::none::ENTITY_CLIENT,
            id: b"native".to_vec(),
        }
    }
    fn input<'a>(
        map: Option<&'a std::sync::Arc<OsdMap>>,
        ticket: Option<&'a cephx::ticket::TicketHandler>,
        entity: &'a cephx::none::ByteEntityName,
        method: u32,
    ) -> crate::ViewInput<'a> {
        crate::ViewInput {
            map,
            osd_ticket: ticket,
            identity: 77,
            entity,
            method,
            fsid: None,
        }
    }
    fn follower(cell: &std::sync::Arc<crate::ViewCell>) -> Bootstrap {
        let mut f = Bootstrap::new_follower(cell.clone(), MessengerMode::Crc, 100).unwrap();
        assert_eq!(f.state(), BootstrapState::New);
        f.start(Duration::ZERO).unwrap();
        f
    }
    #[test]
    fn view_is_shared_types() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<crate::ViewCell>();
        assert_send_sync::<crate::ClusterView>();
    }
    #[test]
    fn view_publication_is_versioned_deduplicated_and_epoch_monotonic() {
        let cell = crate::ViewCell::new(5);
        let e = entity();
        assert_eq!(cell.generation(), 0);
        assert!(cell.load().is_none());
        let (m5, m6, m4) = (map_at(5), map_at(6), map_at(4));
        assert!(cell.publish(input(Some(&m5), None, &e, AUTH_NONE)));
        assert_eq!(cell.generation(), 1);
        // Same content: no new snapshot, readers see no news.
        assert!(!cell.publish(input(Some(&m5), None, &e, AUTH_NONE)));
        assert_eq!(cell.generation(), 1);
        assert!(cell.publish(input(Some(&m6), None, &e, AUTH_NONE)));
        assert_eq!(cell.load().unwrap().map.as_ref().unwrap().epoch, 6);
        // A lower epoch never replaces the published map; the snapshot is unchanged, so nothing is published.
        assert!(!cell.publish(input(Some(&m4), None, &e, AUTH_NONE)));
        assert_eq!(cell.load().unwrap().map.as_ref().unwrap().epoch, 6);
        assert_eq!(cell.generation(), 2);
        // A temporarily missing map keeps the old one.
        assert!(!cell.publish(input(None, None, &e, AUTH_NONE)));
        assert_eq!(cell.load().unwrap().map.as_ref().unwrap().epoch, 6);
        // Same epoch, new identity of the map object: published (a re-install is a new generation).
        let m6b = map_at(6);
        assert!(cell.publish(input(Some(&m6b), None, &e, AUTH_NONE)));
        assert_eq!(cell.generation(), 3);
    }
    #[test]
    fn view_ticket_renewal_is_published_and_visible_to_a_follower() {
        let cell = crate::ViewCell::new(5);
        let e = entity();
        let m = map_at(3);
        let t1 = osd_ticket(1, 3600, 100);
        assert!(cell.publish(input(Some(&m), Some(&t1), &e, AUTH_CEPHX)));
        let mut f = follower(&cell);
        assert_eq!(f.state(), BootstrapState::Ready);
        assert_eq!(f.identity(), Some(77));
        assert_eq!(f.osdmap().unwrap().epoch, 3);
        assert!(
            f.service_auth(cephx::none::ENTITY_OSD, MessengerMode::Crc)
                .is_ok()
        );
        assert_eq!(
            f.follower
                .as_ref()
                .unwrap()
                .osd_ticket
                .as_ref()
                .unwrap()
                .blob()
                .secret_id,
            1
        );
        // Renewal: same map, new ticket -> new snapshot; the follower's next connect uses it.
        let t2 = osd_ticket(2, 3600, 200);
        assert!(cell.publish(input(Some(&m), Some(&t2), &e, AUTH_CEPHX)));
        f.progress(Duration::from_secs(1)).unwrap();
        assert_eq!(
            f.follower
                .as_ref()
                .unwrap()
                .osd_ticket
                .as_ref()
                .unwrap()
                .blob()
                .secret_id,
            2
        );
        assert_eq!(
            f.osdmap_generation(),
            1,
            "a ticket renewal is not a map install"
        );
        assert!(
            f.service_auth(cephx::none::ENTITY_OSD, MessengerMode::Crc)
                .is_ok()
        );
        // Service other than OSD is not served from the view.
        assert!(
            f.service_auth(cephx::none::ENTITY_MGR, MessengerMode::Crc)
                .is_err()
        );
    }
    #[test]
    fn view_follower_waits_for_identity_map_and_cephx_ticket() {
        let cell = crate::ViewCell::new(5);
        let e = entity();
        let mut f = follower(&cell);
        assert_eq!(f.state(), BootstrapState::Hunting);
        assert!(f.osdmap().is_none());
        let m = map_at(2);
        cell.publish(input(Some(&m), None, &e, AUTH_CEPHX));
        f.progress(Duration::ZERO).unwrap();
        assert_eq!(f.state(), BootstrapState::Hunting, "cephx needs a ticket");
        let expired = osd_ticket(1, 10, 0);
        cell.publish(input(Some(&m), Some(&expired), &e, AUTH_CEPHX));
        f.progress(Duration::from_secs(1000)).unwrap();
        assert_eq!(
            f.state(),
            BootstrapState::Ready,
            "cached expired ticket remains usable"
        );
        let ok = osd_ticket(2, 3600, 1000);
        cell.publish(input(Some(&m), Some(&ok), &e, AUTH_CEPHX));
        f.progress(Duration::from_secs(1000)).unwrap();
        assert_eq!(f.state(), BootstrapState::Ready);
        f.close();
        assert_eq!(f.state(), BootstrapState::Closed);
    }
    #[test]
    fn view_follower_map_epochs_are_monotonic_and_gaps_count_as_interval_change() {
        let cell = crate::ViewCell::new(5);
        let e = entity();
        let mut f = follower(&cell);
        let pg = denc::types::PgT { pool: 1, seed: 0 };
        let m1 = map_at(1);
        cell.publish(input(Some(&m1), None, &e, AUTH_NONE));
        f.progress(Duration::ZERO).unwrap();
        assert_eq!(f.state(), BootstrapState::Ready);
        f.track_pg(pg, 1);
        // Followers may skip epochs: the gap is a conservative interval change at the new epoch.
        let m4 = map_at(4);
        cell.publish(input(Some(&m4), None, &e, AUTH_NONE));
        f.progress(Duration::ZERO).unwrap();
        assert_eq!(f.osdmap().unwrap().epoch, 4);
        assert_eq!(f.pg_interval_since(pg), Some(4));
        let g = f.osdmap_generation();
        // An older map is never installed.
        cell.publish(input(Some(&map_at(2)), None, &e, AUTH_NONE));
        f.progress(Duration::ZERO).unwrap();
        assert_eq!(f.osdmap().unwrap().epoch, 4);
        assert_eq!(f.osdmap_generation(), g);
        f.untrack_pg(pg);
        assert_eq!(f.pg_interval_since(pg), None);
    }
    #[test]
    fn view_leader_publishes_map_identity_and_ticket_when_it_changes() {
        let cell = crate::ViewCell::new(9);
        let mut b = Bootstrap::new(policy_config(
            ClientAuth::new(vec![AUTH_NONE], None).unwrap(),
        ))
        .unwrap();
        // Nothing to publish before authentication.
        b.publish_view_to(cell.clone());
        assert_eq!(cell.generation(), 0);
        b.authenticated(77, CON_MODE_CRC, AUTH_NONE);
        b.monitor.as_mut().unwrap().set_osdmap({
            let mut m = OsdMap::default();
            m.epoch = 7;
            m
        });
        b.publish_view();
        let v = cell.load().unwrap();
        assert_eq!(
            (v.identity, v.method, v.map.as_ref().unwrap().epoch),
            (77, AUTH_NONE, 7)
        );
        assert!(std::sync::Arc::ptr_eq(
            v.map.as_ref().unwrap(),
            b.monitor.as_ref().unwrap().osdmap_arc().unwrap()
        ));
        b.publish_view();
        assert_eq!(cell.generation(), 1, "unchanged state is not republished");
        b.monitor.as_mut().unwrap().set_osdmap({
            let mut m = OsdMap::default();
            m.epoch = 8;
            m
        });
        b.publish_view();
        assert_eq!(cell.generation(), 2);
        assert_eq!(follower(&cell).osdmap().unwrap().epoch, 8);
    }
    #[test]
    fn view_follower_clock_is_validated_before_control_queues_trust_it() {
        let cell = crate::ViewCell::new(5);
        let e = entity();
        let m = map_at(2);
        cell.publish(input(Some(&m), None, &e, AUTH_NONE));
        let mut f = Bootstrap::new_follower(cell.clone(), MessengerMode::Crc, 100).unwrap();
        assert_eq!(
            f.start(Duration::MAX),
            Err(BootstrapError::InvalidClock),
            "the wire clock domain is narrower than Duration::MAX"
        );
        assert_eq!(
            f.state(),
            BootstrapState::Failed(BootstrapError::InvalidClock)
        );
        assert_eq!(
            f.enable_monitor_commands(
                crate::MonitorCommandLimits {
                    slots: 1,
                    bytes: 1024,
                    request_bytes: 64,
                    reply_bytes: 64,
                },
                1,
            ),
            Err(crate::MonitorCommandError::NotReady)
        );
        assert_eq!(
            f.enable_snapshots(
                crate::SnapshotLimits {
                    slots: 1,
                    bytes: 64,
                    response_bytes: 16,
                },
                1,
            ),
            Err(crate::SnapshotQueueError::NotReady)
        );
        let mut f = follower(&cell);
        assert_eq!(f.state(), BootstrapState::Ready);
        assert_eq!(f.progress(Duration::from_secs(1)), Ok(()));
        assert_eq!(
            f.progress(Duration::ZERO),
            Err(BootstrapError::ClockRegression)
        );
        assert_eq!(
            f.state(),
            BootstrapState::Failed(BootstrapError::ClockRegression)
        );
    }
    #[cfg(feature = "lab")]
    #[test]
    fn lab_onetime_osdmap_only_qualifies_a_live_monitor() {
        let cell = crate::ViewCell::new(5);
        let mut f = Bootstrap::new_follower(cell, MessengerMode::Crc, 100).unwrap();
        assert_eq!(f.state(), BootstrapState::New);
        assert!(!f.lab_onetime_osdmap(), "a follower has no monitor session");
        assert_eq!(f.state(), BootstrapState::New);
        let mut b = Bootstrap::new(policy_config(
            ClientAuth::new(vec![AUTH_NONE], None).unwrap(),
        ))
        .unwrap();
        assert!(
            b.lab_onetime_osdmap(),
            "a live monitor accepts the qualifier"
        );
    }
}
