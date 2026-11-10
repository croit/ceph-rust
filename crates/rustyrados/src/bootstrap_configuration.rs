// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Configuration-only bootstrap and ordered runtime monitor snapshots.
use super::*;
use std::collections::{BTreeMap, VecDeque};

/// MON persistent feature `MONMAP_MIMIC`: from mimic on the monitor also sends the configuration snapshot
/// during bootstrap, so readiness waits for it.
const MONMAP_MIMIC: u64 = 1 << 2;
/// Undrained runtime snapshots retain at most this many complete config maps.
const MAX_RETAINED_SNAPSHOTS: usize = 64;
/// Undrained runtime snapshots retain at most this many bytes; the newest snapshot is always kept, so one larger
/// snapshot alone may exceed the bound.
const MAX_RETAINED_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;

/// Runtime snapshot retention outcome; a driver that stops draining is told that it lost older snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonitorConfigError {
    /// Older undrained snapshots were dropped; the retained ones are the newest, in receive order.
    Dropped,
}

pub(super) struct ConfigurationControl {
    only: bool,
    received: bool,
    waiting: bool,
    interval: Duration,
    attempt: u8,
    snapshots: VecDeque<BTreeMap<String, String>>,
    bytes: usize,
    error: Option<MonitorConfigError>,
}

/// Approximate retained heap bytes of one complete config map: entry strings by capacity, excluding map node overhead.
fn snapshot_charge(snapshot: &BTreeMap<String, String>) -> usize {
    snapshot.iter().fold(0usize, |total, (key, value)| {
        total
            .saturating_add(std::mem::size_of::<(String, String)>())
            .saturating_add(key.capacity())
            .saturating_add(value.capacity())
    })
}
impl ConfigurationControl {
    pub(super) fn runtime() -> Self {
        Self {
            only: false,
            received: false,
            waiting: false,
            interval: Duration::ZERO,
            attempt: 0,
            snapshots: VecDeque::new(),
            bytes: 0,
            error: None,
        }
    }
    fn bootstrap(interval: Duration) -> Self {
        Self {
            only: true,
            interval,
            attempt: 1,
            ..Self::runtime()
        }
    }
    pub(super) fn only(&self) -> bool {
        self.only
    }
    /// No retained result work: neither a snapshot nor an unreported drop.
    pub(super) fn can_wait(&self) -> bool {
        self.snapshots.is_empty() && self.error.is_none()
    }
    fn clear(&mut self) {
        self.snapshots.clear();
        self.bytes = 0;
        self.error = None;
    }
    /// Retain `snapshot` as the newest one; drop the oldest while either bound would be exceeded.
    fn retain(&mut self, snapshot: BTreeMap<String, String>) {
        let charge = snapshot_charge(&snapshot);
        while !self.snapshots.is_empty()
            && (self.snapshots.len() >= MAX_RETAINED_SNAPSHOTS
                || self
                    .bytes
                    .checked_add(charge)
                    .is_none_or(|total| total > MAX_RETAINED_SNAPSHOT_BYTES))
        {
            let oldest = self.snapshots.pop_front().expect("nonempty snapshot queue");
            self.bytes -= snapshot_charge(&oldest);
            self.error = Some(MonitorConfigError::Dropped);
        }
        self.bytes += charge;
        self.snapshots.push_back(snapshot);
    }
}
impl Bootstrap {
    /// Temporary monitor bootstrap; no OSD map or service-ticket dependency.
    pub fn new_configuration<A: Into<ClientAuth>>(
        config: BootstrapConfig<A>,
        interval: Duration,
    ) -> Result<Self, BootstrapError> {
        Self::new_configuration_bytes(config.into_bytes(), interval)
    }
    pub fn new_configuration_bytes<A: Into<ClientAuth>>(
        config: super::ByteBootstrapConfig<A>,
        interval: Duration,
    ) -> Result<Self, BootstrapError> {
        Self::new_services(
            config,
            false,
            msgr2::Limits::wire_shape(),
            Some(ConfigurationControl::bootstrap(interval)),
            true,
        )
    }
    /// Opt in before starting to ordered raw MON snapshots; readiness is unchanged.
    pub fn enable_monitor_configuration(&mut self) -> Result<(), BootstrapError> {
        if self.state != BootstrapState::New || self.configuration.is_some() {
            return Err(BootstrapError::AlreadyStarted);
        }
        self.configuration = Some(ConfigurationControl::runtime());
        self.monitor.as_mut().unwrap().subscribe_full_config();
        Ok(())
    }
    /// Complete MON snapshots in receive order. Taking one transfers ownership.
    pub fn take_monitor_config(&mut self) -> Option<BTreeMap<String, String>> {
        let control = self.configuration.as_mut()?;
        let snapshot = control.snapshots.pop_front()?;
        control.bytes -= snapshot_charge(&snapshot);
        Some(snapshot)
    }
    /// Reports (and clears) runtime snapshot loss: a driver that stops draining keeps only the newest snapshots.
    pub fn take_monitor_config_error(&mut self) -> Option<MonitorConfigError> {
        self.configuration.as_mut()?.error.take()
    }
    pub(super) fn authentication_deadline(
        &self,
        now: Duration,
    ) -> Result<Option<Duration>, BootstrapError> {
        if self.timeout.is_zero() {
            return Ok(None);
        }
        now.checked_add(self.timeout)
            .map(Some)
            .ok_or(BootstrapError::InvalidTimeout)
    }
    pub(super) fn configuration_snapshot(&mut self, snapshot: BTreeMap<String, String>) {
        if let Some(control) = &mut self.configuration {
            if control.only {
                control.clear();
            }
            control.received = true;
            control.retain(snapshot);
        }
    }
    pub(super) fn configuration_authenticated(&mut self) {
        if let Some(control) = &mut self.configuration
            && control.only
            && !control.waiting
        {
            control.waiting = true;
            match self.last_now.checked_add(control.interval) {
                Some(deadline) => self.deadline = Some(deadline),
                None => self.fail(BootstrapError::InvalidTimeout),
            }
        }
    }
    pub(super) fn configuration_stop(&mut self) {
        if let Some(control) = &mut self.configuration {
            control.clear();
            control.received = false;
        }
    }
    pub(super) fn configuration_monitor_lost(&mut self) {
        if let Some(control) = &mut self.configuration
            && control.only
        {
            control.received = false;
            control.clear();
        }
    }
    /// True means the source-derived configuration wait retry owns the expiry.
    pub(super) fn configuration_expired(&mut self, now: Duration) -> Result<bool, BootstrapError> {
        let Some(control) = self.configuration.as_mut().filter(|c| c.only && c.waiting) else {
            diag::diag!(
                "WARNING TIMEOUT client authentication exceeded {}s (state={:?})",
                self.timeout.as_secs_f64(),
                self.state
            );
            return Ok(false);
        };
        diag::diag!(
            "WARNING TIMEOUT monitor configuration exceeded {}s (attempt={} fsid={:?})",
            control.interval.as_secs_f64(),
            control.attempt,
            self.fsid
        );
        // Both pinned get_monmap_and_config contracts allow ten authenticated waits.
        if control.attempt == 10 {
            return Ok(false);
        }
        control.attempt += 1;
        control.waiting = false;
        control.received = false;
        control.clear();
        self.deadline = self.authentication_deadline(now)?;
        self.identity = None;
        self.method = None;
        self.state = BootstrapState::Hunting;
        if let Some(monitor) = &mut self.monitor {
            monitor.rehunt("configuration wait deadline");
        }
        Ok(true)
    }
    pub(super) fn advance_configuration(&mut self) {
        let Some(control) = self.configuration.as_ref().filter(|c| c.only) else {
            return;
        };
        let Some(monitor) = self.monitor.as_ref() else {
            return;
        };
        let map = monitor.monmap();
        let ready = monitor.is_connected()
            && self.identity.is_some()
            && self.method.is_some()
            && map.epoch != 0
            && (map.persistent_features & MONMAP_MIMIC == 0 || control.received);
        let fsid = map.fsid;
        if ready && self.accept_fsid(fsid) {
            self.state = BootstrapState::Ready;
            self.deadline = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cephx::modes::{AUTH_NONE, CON_MODE_CRC};
    use denc::types::{EntityAddr, EntityAddrVec, EntityName};
    fn config(timeout: Duration) -> BootstrapConfig<ClientAuth> {
        BootstrapConfig {
            entity: "client.config-bootstrap".into(),
            key: ClientAuth::new(vec![AUTH_NONE], None).unwrap(),
            monitors: monc::parse_mon_host("v2:127.0.0.1:3300").unwrap(),
            expected_fsid: None,
            mode: MessengerMode::Crc,
            startup_timeout: timeout,
            wall_origin_unix: 100,
        }
    }
    #[test]
    fn configuration_only_byte_entrypoint_keeps_original_principal() {
        let mut cfg = config(Duration::ZERO).into_bytes();
        cfg.entity = b"mon.\xff spaces.more".to_vec();
        let mut bootstrap =
            Bootstrap::new_configuration_bytes(cfg, Duration::from_secs(5)).unwrap();
        assert_eq!(bootstrap.auth_entity().ty, cephx::none::ENTITY_MON);
        assert_eq!(bootstrap.auth_entity().id, b"\xff spaces.more");
        bootstrap.start(Duration::ZERO).unwrap();
        assert_eq!(bootstrap.state(), BootstrapState::Hunting);
    }
    fn exchange(b: &mut Bootstrap, server: &mut msgr2::Connection, conn: u64) {
        for _ in 0..1000 {
            let client_bytes = b.poll_output(conn);
            if !client_bytes.is_empty() {
                server.on_bytes(&client_bytes, b.last_now);
            }
            let server_bytes = server.poll_output();
            if !server_bytes.is_empty() {
                b.on_bytes(conn, &server_bytes, b.last_now);
            }
            while let Some(event) = server.poll_event() {
                assert!(!matches!(event, msgr2::Event::Fault(_)), "{event:?}");
            }
            if client_bytes.is_empty() && server_bytes.is_empty() {
                return;
            }
        }
        panic!("configuration test exchange failed to quiesce");
    }
    #[derive(Debug)]
    struct MonitorNone;
    impl msgr2::auth::AuthServerHandler for MonitorNone {
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
        ) -> msgr2::auth::AuthServerStep {
            assert_eq!(peer, EntityName::CLIENT);
            assert!(!more);
            assert_eq!((method, mode), (AUTH_NONE, CON_MODE_CRC));
            let (phase, name, gid) = cephx::none::parse_none_payload(payload).unwrap();
            assert_eq!(phase, cephx::none::AUTH_MODE_MON);
            assert_eq!(name.to_string(), "client.config-bootstrap");
            assert_eq!(gid, 0);
            msgr2::auth::AuthServerStep::Done {
                reply: vec![],
                global_id: 77,
                peer_name: None,
                secrets: msgr2::auth::AuthSecrets::default(),
            }
        }
    }
    fn authenticated() -> (Bootstrap, msgr2::Connection, u64) {
        let mut b =
            Bootstrap::new_configuration(config(Duration::from_secs(10)), Duration::from_secs(2))
                .unwrap();
        b.start(Duration::ZERO).unwrap();
        let Some(IoCmd::Dial { conn, target }) = b.poll_io() else {
            panic!("monitor dial")
        };
        let mut server = msgr2::Connection::server(
            999,
            msgr2::Config::new(
                EntityName::new(EntityName::MON, 0),
                EntityAddrVec::single(target),
                msgr2::PolicyTable::uniform(msgr2::Policy::stateless_server(0)),
            ),
            msgr2::SessionTable::new(1),
            Box::new(MonitorNone),
            EntityAddr::v4(2, 0, [127, 0, 0, 1], 40000),
            Duration::ZERO,
        );
        b.on_connected(conn, Duration::ZERO);
        exchange(&mut b, &mut server, conn);
        assert_eq!(b.identity(), Some(77));
        assert_eq!(b.state(), BootstrapState::AwaitingMaps);
        (b, server, conn)
    }
    fn send(
        b: &mut Bootstrap,
        server: &mut msgr2::Connection,
        conn: u64,
        message: messages::AnyMessage,
    ) {
        let (msg_type, version, compat_version, segments) = message.encode(u64::MAX).unwrap();
        assert!(server.send_message(msgr2::Message {
            msg_type,
            version,
            compat_version,
            front: segments.front,
            middle: segments.middle,
            data: segments.data,
            ..Default::default()
        }));
        exchange(b, server, conn);
    }
    fn map(b: &Bootstrap, mimic: bool) -> messages::AnyMessage {
        let mut map = b.monitor.as_ref().unwrap().monmap().clone();
        map.fsid = Uuid([7; 16]);
        map.epoch = 1;
        map.persistent_features = if mimic { MONMAP_MIMIC } else { 0 };
        messages::MMonMap {
            monmap: map.encode_to().unwrap(),
        }
        .into()
    }
    #[test]
    fn configuration_readiness_requires_mimic_snapshot_not_osd_map_or_ticket() {
        for config_first in [false, true] {
            let (mut b, mut server, conn) = authenticated();
            let snapshot: BTreeMap<_, _> = [
                ("rbd_cache".into(), "false".into()),
                ("fsid".into(), "ignored-by-value-policy".into()),
            ]
            .into();
            let monmap = map(&b, true);
            let message = messages::MConfig {
                config: snapshot.clone(),
            }
            .into();
            if config_first {
                send(&mut b, &mut server, conn, message);
                assert_eq!(b.state(), BootstrapState::AwaitingMaps);
                send(&mut b, &mut server, conn, monmap);
            } else {
                send(&mut b, &mut server, conn, monmap);
                assert_eq!(b.state(), BootstrapState::AwaitingMaps);
                send(&mut b, &mut server, conn, message);
            }
            assert_eq!(b.state(), BootstrapState::Ready);
            assert_eq!(b.fsid(), Some(Uuid([7; 16])));
            assert!(b.monitor.as_ref().unwrap().osdmap().is_none());
            assert!(b.with_cephx(|_| ()).is_none());
            assert_eq!(b.take_monitor_config(), Some(snapshot));
            assert_eq!(b.take_monitor_config(), None);
            assert_eq!(b.deadline, None);
        }
    }
    #[test]
    fn premimic_configuration_skips_snapshot_and_auth_timeout_zero_is_unbounded() {
        let (mut b, mut server, conn) = authenticated();
        let monmap = map(&b, false);
        send(&mut b, &mut server, conn, monmap);
        assert_eq!(b.state(), BootstrapState::Ready);
        assert_eq!(b.take_monitor_config(), None);
        let mut unbounded =
            Bootstrap::new_configuration(config(Duration::ZERO), Duration::from_secs(2)).unwrap();
        unbounded.start(Duration::ZERO).unwrap();
        assert_eq!(unbounded.deadline, None);
        assert!(matches!(
            Bootstrap::new(config(Duration::ZERO)),
            Err(BootstrapError::InvalidTimeout)
        ));
    }
    #[test]
    fn configuration_wait_retries_only_its_ten_attempt_budget() {
        let mut b =
            Bootstrap::new_configuration(config(Duration::from_secs(1)), Duration::from_secs(2))
                .unwrap();
        b.start(Duration::ZERO).unwrap();
        for attempt in 1..=10 {
            b.authenticated(77, CON_MODE_CRC, AUTH_NONE);
            let now = Duration::from_secs(attempt * 2);
            assert_eq!(b.deadline, Some(now));
            let result = b.progress(now);
            if attempt < 10 {
                assert_eq!(result, Ok(()));
                assert_eq!(
                    b.configuration.as_ref().unwrap().attempt,
                    (attempt + 1) as u8
                );
                assert_eq!(b.deadline, Some(now + Duration::from_secs(1)));
                assert_eq!(b.state(), BootstrapState::Hunting);
            } else {
                assert_eq!(result, Err(BootstrapError::StartupTimeout));
            }
        }
        let mut auth =
            Bootstrap::new_configuration(config(Duration::from_secs(1)), Duration::from_secs(2))
                .unwrap();
        auth.start(Duration::ZERO).unwrap();
        assert_eq!(
            auth.progress(Duration::from_secs(1)),
            Err(BootstrapError::StartupTimeout)
        );
        assert_eq!(auth.configuration.as_ref().unwrap().attempt, 1);
    }
    #[test]
    fn runtime_snapshot_ownership_is_ordered_and_strict_constructor_ignores_it() {
        let first: BTreeMap<_, _> = [("rbd_cache".into(), "false".into())].into();
        let second: BTreeMap<_, _> = [("rbd_cache".into(), "true".into())].into();
        let mut strict = Bootstrap::new(config(Duration::from_secs(1))).unwrap();
        strict.monitor_event(MonEvent::Config(first.clone()));
        assert_eq!(strict.take_monitor_config(), None);
        let mut compatible =
            Bootstrap::new_compatible(config(Duration::from_secs(1)), false).unwrap();
        compatible.enable_monitor_configuration().unwrap();
        compatible.monitor_event(MonEvent::Config(first.clone()));
        compatible.monitor_event(MonEvent::Config(second.clone()));
        assert_eq!(compatible.take_monitor_config(), Some(first));
        assert_eq!(compatible.take_monitor_config(), Some(second));
        assert_eq!(compatible.take_monitor_config(), None);
        compatible.monitor_event(MonEvent::Config(BTreeMap::new()));
        compatible.close();
        assert_eq!(compatible.take_monitor_config(), None);
    }
    fn runtime() -> Bootstrap {
        let mut b = Bootstrap::new_compatible(config(Duration::from_secs(1)), false).unwrap();
        b.enable_monitor_configuration().unwrap();
        b
    }
    fn distinct(i: usize) -> BTreeMap<String, String> {
        [("client_identifier".into(), i.to_string())].into()
    }
    #[test]
    fn undrained_runtime_snapshots_keep_only_the_newest_counted_ones() {
        let mut b = runtime();
        let received = MAX_RETAINED_SNAPSHOTS + 3;
        for i in 0..received {
            b.monitor_event(MonEvent::Config(distinct(i)));
        }
        let retained: Vec<_> = std::iter::from_fn(|| b.take_monitor_config()).collect();
        assert_eq!(retained.len(), MAX_RETAINED_SNAPSHOTS);
        assert_eq!(
            retained.first().unwrap()["client_identifier"],
            (received - MAX_RETAINED_SNAPSHOTS).to_string()
        );
        assert_eq!(
            retained.last().unwrap()["client_identifier"],
            (received - 1).to_string()
        );
        assert_eq!(
            b.take_monitor_config_error(),
            Some(MonitorConfigError::Dropped)
        );
        assert_eq!(b.take_monitor_config_error(), None, "reported once");
    }
    #[test]
    fn undrained_runtime_snapshots_keep_only_the_newest_byte_budget() {
        let mut b = runtime();
        let per_snapshot = 1024 * 1024;
        let retained_snapshots = MAX_RETAINED_SNAPSHOT_BYTES / per_snapshot;
        let large = |i: usize| -> BTreeMap<String, String> {
            let mut value = String::with_capacity(per_snapshot);
            value.push_str(&i.to_string());
            [("value".to_string(), value)].into()
        };
        for i in 0..retained_snapshots + 2 {
            b.monitor_event(MonEvent::Config(large(i)));
        }
        let retained: Vec<_> = std::iter::from_fn(|| b.take_monitor_config()).collect();
        assert!(retained.len() <= retained_snapshots, "{retained:?}");
        assert!(retained.len() > 1);
        assert_eq!(
            retained.last().unwrap()["value"],
            (retained_snapshots + 1).to_string()
        );
        assert_eq!(
            b.take_monitor_config_error(),
            Some(MonitorConfigError::Dropped)
        );
        // A snapshot larger than the whole budget is still retained as the newest complete state.
        let oversized = |i: usize| -> BTreeMap<String, String> {
            let mut value = String::with_capacity(MAX_RETAINED_SNAPSHOT_BYTES);
            value.push_str(&i.to_string());
            [("value".to_string(), value)].into()
        };
        b.monitor_event(MonEvent::Config(oversized(1)));
        b.monitor_event(MonEvent::Config(oversized(2)));
        assert_eq!(b.take_monitor_config().unwrap()["value"], "2".to_string());
        assert_eq!(
            b.take_monitor_config_error(),
            Some(MonitorConfigError::Dropped)
        );
    }
    #[test]
    fn pending_runtime_snapshot_and_its_loss_keep_the_driver_awake() {
        let mut b = runtime();
        assert!(b.can_sleep());
        b.monitor_event(MonEvent::Config(distinct(0)));
        assert!(!b.can_sleep(), "a retained snapshot is undelivered work");
        assert!(!b.can_sleep_with_blocked_output(&|_| true));
        assert_eq!(b.take_monitor_config().unwrap()["client_identifier"], "0");
        assert!(b.can_sleep());
        assert!(b.can_sleep_with_blocked_output(&|_| true));
        for i in 0..MAX_RETAINED_SNAPSHOTS {
            b.monitor_event(MonEvent::Config(distinct(i)));
        }
        b.monitor_event(MonEvent::Config(distinct(0)));
        while b.take_monitor_config().is_some() {}
        assert!(
            !b.can_sleep(),
            "an unreported drop is result work like a log error"
        );
        assert_eq!(
            b.take_monitor_config_error(),
            Some(MonitorConfigError::Dropped)
        );
        assert!(b.can_sleep());
    }
    #[test]
    fn stopped_runtime_control_releases_retained_snapshots_and_their_loss() {
        let mut b = runtime();
        for i in 0..MAX_RETAINED_SNAPSHOTS + 1 {
            b.monitor_event(MonEvent::Config(distinct(i)));
        }
        b.close();
        assert_eq!(b.take_monitor_config(), None);
        assert_eq!(b.take_monitor_config_error(), None);
        assert!(b.can_sleep());
    }
}
