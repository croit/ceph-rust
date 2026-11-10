// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Opt-in monitor log ownership, ADR0302/RC188.
use super::*;
pub use messages::LogEntry as MonitorLogEntry;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonitorLogError {
    InvalidLevel,
    NotReady,
    TooLarge,
    Closed,
}
#[derive(Default)]
pub(super) struct Logs {
    watch: Option<&'static str>,
    version: u64,
    pub(super) entries: VecDeque<(MonitorLogEntry, usize)>,
    bytes: usize,
    pub(super) error: Option<MonitorLogError>,
}
fn watch(level: &str) -> Result<&'static str, MonitorLogError> {
    Ok(match level {
        "debug" => "log-debug",
        "info" => "log-info",
        "warn" | "warning" => "log-warn",
        "err" | "error" => "log-error",
        "sec" => "log-sec",
        _ => return Err(MonitorLogError::InvalidLevel),
    })
}
impl Logs {
    fn accept(
        &mut self,
        message: messages::MLog,
        fsid: Option<Uuid>,
    ) -> Result<Option<(&'static str, u64)>, MonitorLogError> {
        if fsid != Some(message.fsid) || message.version <= self.version {
            return Ok(None);
        }
        let Some(watch) = self.watch else {
            // The monitor may retain its standing subscription after local
            // stop. Consume the cursor without invoking a stopped callback.
            self.version = message.version;
            return Ok(None);
        };
        let charge = message.entries.iter().try_fold(0usize, |n, e| {
            n.checked_add(std::mem::size_of::<MonitorLogEntry>())?
                .checked_add(e.name.id.capacity())?
                .checked_add(e.msg.capacity())?
                .checked_add(e.channel.capacity())?
                .checked_add(
                    e.addrs
                        .0
                        .capacity()
                        .checked_mul(std::mem::size_of::<denc::types::EntityAddr>())?,
                )
        });
        if message.entries.len() > 4096usize.saturating_sub(self.entries.len())
            || charge.is_none_or(|n| n > (64 * 1024 * 1024usize).saturating_sub(self.bytes))
        {
            self.entries.clear();
            self.bytes = 0;
            self.watch = None;
            self.error = Some(MonitorLogError::TooLarge);
            return Err(MonitorLogError::TooLarge);
        }
        self.version = message.version;
        for entry in message.entries {
            let n = std::mem::size_of::<MonitorLogEntry>()
                + entry.name.id.capacity()
                + entry.msg.capacity()
                + entry.channel.capacity()
                + entry.addrs.0.capacity() * std::mem::size_of::<denc::types::EntityAddr>();
            self.bytes += n;
            self.entries.push_back((entry, n));
        }
        Ok(Some((watch, self.version)))
    }
}
impl Bootstrap {
    pub fn configure_monitor_log(&mut self, level: Option<&str>) -> Result<(), MonitorLogError> {
        if matches!(
            self.state,
            BootstrapState::Closed | BootstrapState::Failed(_)
        ) {
            return Err(MonitorLogError::Closed);
        }
        if self.identity.is_none() {
            return Err(MonitorLogError::NotReady);
        }
        let next = level.map(watch).transpose()?;
        let logs = self.logs.get_or_insert_with(Default::default);
        if next.is_some()
            && let Some(error) = logs.error.take()
        {
            return Err(error);
        }
        if let Some(old) = logs.watch.take() {
            self.monitor.as_mut().unwrap().unsubscribe(old);
        }
        logs.entries.clear();
        logs.bytes = 0;
        logs.error = None;
        logs.watch = next;
        if let Some(next) = next {
            let monitor = self.monitor.as_mut().unwrap();
            monitor.subscribe(next, 0, 0);
            if logs.version != 0 {
                monitor.subscription_got(next, logs.version);
            }
        }
        Ok(())
    }
    pub fn poll_monitor_log(&mut self) -> Result<Option<MonitorLogEntry>, MonitorLogError> {
        let Some(logs) = &mut self.logs else {
            return Ok(None);
        };
        if let Some(error) = logs.error.take() {
            return Err(error);
        }
        Ok(logs.entries.pop_front().map(|(entry, n)| {
            logs.bytes -= n;
            entry
        }))
    }
    pub(super) fn monitor_log_message(&mut self, message: messages::MLog) {
        let Some(logs) = &mut self.logs else {
            return;
        };
        let old_watch = logs.watch;
        match logs.accept(message, self.fsid) {
            Ok(Some((watch, version))) => {
                if let Some(m) = &mut self.monitor {
                    m.subscription_got(watch, version);
                }
            }
            Err(_) => {
                if let (Some(m), Some(watch)) = (&mut self.monitor, old_watch) {
                    m.unsubscribe(watch);
                }
            }
            _ => {}
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_stop_restart_and_invalid_preserve_version_and_pending_state() {
        let mut b = Bootstrap::new(BootstrapConfig {
            entity: "client.logs".into(),
            key: cephx::CryptoKey::new(cephx::KeyType::Aes, Default::default(), &[7; 16]),
            monitors: monc::parse_mon_host("v2:10.0.0.2:3300").unwrap(),
            expected_fsid: None,
            mode: MessengerMode::Crc,
            startup_timeout: Duration::from_secs(5),
            wall_origin_unix: 1000,
        })
        .unwrap();
        assert_eq!(
            b.configure_monitor_log(None),
            Err(MonitorLogError::NotReady)
        );
        b.identity = Some(77);
        b.fsid = Some(Uuid([3; 16]));
        b.state = BootstrapState::Hunting;
        b.configure_monitor_log(Some("info")).unwrap();
        let message = |version| messages::MLog {
            version,
            fsid: Uuid([3; 16]),
            entries: vec![MonitorLogEntry {
                seq: version,
                ..Default::default()
            }],
        };
        b.monitor_log_message(message(1));
        assert!(!b.can_sleep());
        assert_eq!(
            b.configure_monitor_log(Some("invalid")),
            Err(MonitorLogError::InvalidLevel)
        );
        assert_eq!(b.poll_monitor_log().unwrap().unwrap().seq, 1);
        b.monitor_log_message(message(2));
        b.configure_monitor_log(None).unwrap();
        assert!(b.poll_monitor_log().unwrap().is_none());
        b.monitor_log_message(message(3)); // stopped: cursor advances without delivery
        b.configure_monitor_log(Some("warning")).unwrap();
        b.monitor_log_message(message(2)); // duplicate across replacement is ignored
        assert!(b.poll_monitor_log().unwrap().is_none());
        b.monitor_log_message(message(3));
        assert!(b.poll_monitor_log().unwrap().is_none());
        b.monitor_log_message(message(4));
        assert_eq!(b.poll_monitor_log().unwrap().unwrap().seq, 4);
        b.close();
        assert!(b.poll_monitor_log().unwrap().is_none());
        assert_eq!(b.configure_monitor_log(None), Err(MonitorLogError::Closed));
    }
    #[test]
    fn aliases_and_atomic_versions_fsid_pressure() {
        for (level, expected) in [
            ("warn", "log-warn"),
            ("warning", "log-warn"),
            ("err", "log-error"),
            ("error", "log-error"),
            ("sec", "log-sec"),
        ] {
            assert_eq!(watch(level), Ok(expected));
        }
        assert_eq!(watch("INFO"), Err(MonitorLogError::InvalidLevel));
        let mut logs = Logs {
            watch: Some("log-info"),
            ..Default::default()
        };
        let fsid = Uuid([3; 16]);
        let msg = messages::MLog {
            version: 1,
            fsid,
            entries: vec![
                MonitorLogEntry {
                    seq: 7,
                    ..Default::default()
                },
                MonitorLogEntry {
                    seq: 8,
                    ..Default::default()
                },
            ],
        };
        assert_eq!(logs.accept(msg.clone(), Some(Uuid([4; 16]))), Ok(None));
        assert_eq!(
            logs.accept(msg.clone(), Some(fsid)),
            Ok(Some(("log-info", 1)))
        );
        assert_eq!(logs.accept(msg, Some(fsid)), Ok(None));
        assert_eq!(logs.entries.len(), 2);
        assert_eq!(logs.entries[0].0.seq, 7);
        assert_eq!(logs.entries[1].0.seq, 8);
        let oversize = messages::MLog {
            version: 2,
            fsid,
            entries: vec![MonitorLogEntry::default(); 4097],
        };
        assert_eq!(
            logs.accept(oversize, Some(fsid)),
            Err(MonitorLogError::TooLarge)
        );
        assert!(logs.entries.is_empty() && logs.bytes == 0 && logs.watch.is_none());
        assert_eq!(logs.version, 1);
        assert_eq!(logs.error, Some(MonitorLogError::TooLarge));
    }
}
