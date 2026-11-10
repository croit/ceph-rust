// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optional bounded cluster statistics controls, ADR0294/RC179.
use super::{Bootstrap, BootstrapError, BootstrapState};
use crate::time;
pub use messages::{ClusterStatistics, PoolStatistics};
use messages::{MGetPoolStats, MGetPoolStatsReply, MStatfs, MStatfsReply};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatisticsError {
    Overflow,
    Disabled,
    AlreadyEnabled,
    Limits,
    NotReady,
    NoCredit,
    NoMemory,
    NoPool,
    RequestTooLarge,
    Protocol,
    Identity,
    Deadline,
    Cancelled,
    Stale,
    AlreadyComplete,
    Transport,
    MonitorLost,
    Closed,
    Bootstrap(BootstrapError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatisticsToken {
    owner: u64,
    sequence: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatisticsCompletion {
    pub token: StatisticsToken,
    pub result: Result<ClusterStatistics, StatisticsError>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolStatisticsCompletion {
    pub token: StatisticsToken,
    pub result: Result<PoolStatistics, StatisticsError>,
}
/// One completion for an entire compatible name batch. Only names actually
/// returned by the monitor occur here; no missing-name defaults or poolmap filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolStatisticsBatchCompletion {
    pub token: StatisticsToken,
    pub result: Result<BTreeMap<Vec<u8>, PoolStatistics>, StatisticsError>,
}
enum Query {
    Cluster,
    Pool { id: i64, name: Vec<u8> },
    Pools { names: Vec<Vec<u8>> },
}
enum Value {
    Cluster(ClusterStatistics),
    Pool(PoolStatistics),
    Pools(BTreeMap<Vec<u8>, PoolStatistics>),
}
fn copy_names(names: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, StatisticsError> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(names.len())
        .map_err(|_| StatisticsError::NoMemory)?;
    for name in names {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(name.len())
            .map_err(|_| StatisticsError::NoMemory)?;
        bytes.extend_from_slice(name);
        copied.push(bytes);
    }
    Ok(copied)
}
struct Entry {
    token: StatisticsToken,
    deadline: u64,
    started: u64,
    tid: Option<u64>,
    query: Query,
    result: Option<Result<Value, StatisticsError>>,
}
pub(super) struct StatisticsControl {
    owner: u64,
    sequence: u64,
    version: u64,
    work: usize,
    entries: Vec<Option<Entry>>,
    occupied: usize,
    error: Option<StatisticsError>,
}
impl StatisticsControl {
    pub(super) fn deadline(&self) -> Option<u64> {
        if self.occupied == 0 {
            return None;
        }
        self.entries
            .iter()
            .flatten()
            .filter(|e| e.result.is_none())
            .filter_map(|e| time::timer(e.deadline))
            .min()
    }
    pub(super) fn can_wait(&self, monitor_ready: bool) -> bool {
        if self.occupied == 0 {
            return true;
        }
        self.entries
            .iter()
            .flatten()
            .all(|e| e.result.is_none() && (e.tid.is_some() || !monitor_ready))
    }
    fn fail(&mut self, error: StatisticsError) {
        if self.occupied == 0 {
            return;
        }
        for e in self
            .entries
            .iter_mut()
            .flatten()
            .filter(|e| e.result.is_none())
        {
            e.result = Some(Err(error));
        }
    }
    /// Move completed entries of one query family, in slot order, into `out`.
    fn drain<T>(
        &mut self,
        out: &mut [Option<T>],
        selected: impl Fn(&Query) -> bool,
        publish: impl Fn(StatisticsToken, Result<Value, StatisticsError>) -> T,
    ) -> usize {
        if self.occupied == 0 {
            return 0;
        }
        let mut count = 0;
        for slot in &mut self.entries {
            if count == out.len() || out[count].is_some() {
                break;
            }
            if slot
                .as_ref()
                .is_some_and(|e| e.result.is_some() && selected(&e.query))
            {
                let entry = slot.take().unwrap();
                self.occupied -= 1;
                out[count] = Some(publish(entry.token, entry.result.unwrap()));
                count += 1;
            }
        }
        count
    }
}
impl Bootstrap {
    pub fn enable_statistics(&mut self, slots: usize, work: usize) -> Result<(), StatisticsError> {
        if self.statistics.is_some() {
            return Err(StatisticsError::AlreadyEnabled);
        }
        if !(1..=4096).contains(&slots) || !(1..=4096).contains(&work) {
            return Err(StatisticsError::Limits);
        }
        if self.state != BootstrapState::Ready {
            return Err(StatisticsError::NotReady);
        }
        let owner = NEXT_OWNER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| StatisticsError::Identity)?;
        self.statistics = Some(StatisticsControl {
            owner,
            sequence: 0,
            version: 0,
            work,
            entries: (0..slots).map(|_| None).collect(),
            occupied: 0,
            error: None,
        });
        Ok(())
    }
    pub fn submit_cluster_statistics(
        &mut self,
        deadline: u64,
    ) -> Result<StatisticsToken, StatisticsError> {
        self.submit_statistics(Query::Cluster, deadline)
    }
    pub fn submit_pool_statistics(
        &mut self,
        pool: i64,
        deadline: u64,
    ) -> Result<StatisticsToken, StatisticsError> {
        let control = self.statistics.as_ref().ok_or(StatisticsError::Disabled)?;
        if let Some(error) = control.error {
            return Err(error);
        }
        if self.state != BootstrapState::Ready {
            return Err(StatisticsError::NotReady);
        }
        let map = self.osdmap().ok_or(StatisticsError::NotReady)?;
        if map.pool(pool).is_none() {
            return Err(StatisticsError::NoPool);
        }
        let name = map
            .pool_name
            .get(&pool)
            .ok_or(StatisticsError::NoPool)?
            .as_bytes();
        if name.len() > 4096 {
            return Err(StatisticsError::RequestTooLarge);
        }
        MGetPoolStats::front_len(1, [name.len()]).map_err(|_| StatisticsError::RequestTooLarge)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(name.len())
            .map_err(|_| StatisticsError::NoMemory)?;
        owned.extend_from_slice(name);
        self.submit_statistics(
            Query::Pool {
                id: pool,
                name: owned,
            },
            deadline,
        )
    }
    /// Submit one compatible MGetPoolStats query, retaining the exact order and
    /// duplicate occurrences. An empty vector queries no names, not all pools.
    /// No local poolmap membership/name policy is applied. Loss resubmits the
    /// same logical batch under its original token/deadline after authentication.
    /// Strict single-pool admission through `submit_pool_statistics` is unchanged.
    pub fn submit_pool_statistics_batch_compatible(
        &mut self,
        names: Vec<Vec<u8>>,
        deadline: u64,
    ) -> Result<StatisticsToken, StatisticsError> {
        MGetPoolStats::front_len(names.len(), names.iter().map(Vec::len))
            .map_err(|_| StatisticsError::RequestTooLarge)?;
        self.submit_statistics(Query::Pools { names }, deadline)
    }
    fn submit_statistics(
        &mut self,
        query: Query,
        deadline: u64,
    ) -> Result<StatisticsToken, StatisticsError> {
        let now = self.last_now.as_micros();
        let started = time::clock_us(self.last_now).map_err(|_| StatisticsError::Overflow)?;
        let control = self.statistics.as_mut().ok_or(StatisticsError::Disabled)?;

        if let Some(error) = control.error {
            return Err(error);
        }
        if self.state != BootstrapState::Ready || self.fsid.is_none() {
            return Err(StatisticsError::NotReady);
        }
        if time::validate_deadline(deadline).is_err() {
            return Err(StatisticsError::Overflow);
        }
        if time::timer(deadline).is_some_and(|deadline| u128::from(deadline) <= now) {
            diag::diag!(
                "WARNING TIMEOUT pool statistics request exceeded {}s (admission, deadline_us={deadline})",
                time::budget_seconds(deadline.saturating_sub(started))
            );
            return Err(StatisticsError::Deadline);
        }
        let entry = control
            .entries
            .iter_mut()
            .find(|e| e.is_none())
            .ok_or(StatisticsError::NoCredit)?;
        control.sequence = control
            .sequence
            .checked_add(1)
            .ok_or(StatisticsError::Identity)?;
        let token = StatisticsToken {
            owner: control.owner,
            sequence: control.sequence,
        };
        *entry = Some(Entry {
            token,
            deadline,
            started,
            tid: None,
            query,
            result: None,
        });
        control.occupied += 1;
        Ok(token)
    }
    pub fn cancel_statistics(&mut self, token: StatisticsToken) -> Result<(), StatisticsError> {
        let control = self.statistics.as_mut().ok_or(StatisticsError::Disabled)?;
        let entry = control
            .entries
            .iter_mut()
            .flatten()
            .find(|e| e.token == token)
            .ok_or(StatisticsError::Stale)?;
        if entry.result.is_some() {
            return Err(StatisticsError::AlreadyComplete);
        }
        entry.result = Some(Err(StatisticsError::Cancelled));
        Ok(())
    }
    pub fn poll_statistics_into(&mut self, out: &mut [Option<StatisticsCompletion>]) -> usize {
        self.statistics.as_mut().map_or(0, |control| {
            control.drain(
                out,
                |query| matches!(query, Query::Cluster),
                |token, result| StatisticsCompletion {
                    token,
                    result: result.and_then(|value| match value {
                        Value::Cluster(value) => Ok(value),
                        _ => Err(StatisticsError::Protocol),
                    }),
                },
            )
        })
    }
    pub fn poll_pool_statistics_into(
        &mut self,
        out: &mut [Option<PoolStatisticsCompletion>],
    ) -> usize {
        self.statistics.as_mut().map_or(0, |control| {
            control.drain(
                out,
                |query| matches!(query, Query::Pool { .. }),
                |token, result| PoolStatisticsCompletion {
                    token,
                    result: result.and_then(|value| match value {
                        Value::Pool(value) => Ok(value),
                        _ => Err(StatisticsError::Protocol),
                    }),
                },
            )
        })
    }
    /// Drain complete batches without consuming cluster/single-pool work or an
    /// occupied output slot. Credit remains held until this completion is taken.
    pub fn poll_pool_statistics_batch_into(
        &mut self,
        out: &mut [Option<PoolStatisticsBatchCompletion>],
    ) -> usize {
        self.statistics.as_mut().map_or(0, |control| {
            control.drain(
                out,
                |query| matches!(query, Query::Pools { .. }),
                |token, result| PoolStatisticsBatchCompletion {
                    token,
                    result: result.and_then(|value| match value {
                        Value::Pools(map) => Ok(map),
                        _ => Err(StatisticsError::Protocol),
                    }),
                },
            )
        })
    }
    pub(super) fn statistics_progress(&mut self) {
        let Some(control) = &mut self.statistics else {
            return;
        };
        if control.occupied == 0 {
            return;
        }
        for e in control
            .entries
            .iter_mut()
            .flatten()
            .filter(|e| e.result.is_none())
        {
            if time::timer(e.deadline)
                .is_some_and(|deadline| self.last_now.as_micros() >= u128::from(deadline))
            {
                diag::diag!(
                    "WARNING TIMEOUT pool statistics request exceeded {}s (deadline_us={})",
                    time::budget_seconds(e.deadline.saturating_sub(e.started)),
                    e.deadline
                );
                e.result = Some(Err(StatisticsError::Deadline));
            }
        }
    }
    pub(super) fn statistics_dispatch(&mut self) {
        if self.statistics.as_ref().is_none_or(|c| c.occupied == 0) {
            return;
        }
        self.statistics_progress();
        if self.state != BootstrapState::Ready {
            return;
        }
        let Some(fsid) = self.fsid else { return };
        let work = self.statistics.as_ref().map_or(0, |c| c.work);
        for _ in 0..work {
            let c = self.statistics.as_mut().unwrap();
            let Some(e) = c
                .entries
                .iter_mut()
                .flatten()
                .find(|e| e.result.is_none() && e.tid.is_none())
            else {
                break;
            };
            let request: messages::AnyMessage = match &e.query {
                Query::Cluster => MStatfs {
                    fsid,
                    version: c.version,
                    data_pool: None,
                }
                .into(),
                Query::Pool { id, name } => {
                    let valid = self
                        .monitor
                        .as_ref()
                        .and_then(|m| m.osdmap())
                        .is_some_and(|map| {
                            map.pool(*id).is_some()
                                && map.pool_name.get(id).is_some_and(|n| n.as_bytes() == name)
                        });
                    if !valid {
                        e.result = Some(Err(StatisticsError::NoPool));
                        continue;
                    }
                    MGetPoolStats {
                        fsid,
                        version: c.version,
                        pools: vec![name.clone()],
                    }
                    .into()
                }
                Query::Pools { names } => match copy_names(names) {
                    Ok(pools) => MGetPoolStats {
                        fsid,
                        version: c.version,
                        pools,
                    }
                    .into(),
                    Err(error) => {
                        e.result = Some(Err(error));
                        continue;
                    }
                },
            };
            let token = e.token;
            let batch = matches!(e.query, Query::Pools { .. });
            let mut session_error = None;
            match self
                .monitor
                .as_mut()
                .map_or(Err(monc::MonSendError::NoSession), |mon| {
                    mon.try_send_message(request)
                }) {
                Ok(tid) => e.tid = Some(tid),
                Err(error @ (monc::MonSendError::NoSession | monc::MonSendError::Rejected))
                    if batch =>
                {
                    session_error = Some(error);
                }
                Err(error) => {
                    e.result = Some(Err(match error {
                        monc::MonSendError::NoSession => StatisticsError::NotReady,
                        monc::MonSendError::IdentityExhausted => StatisticsError::Identity,
                        monc::MonSendError::Rejected => StatisticsError::Transport,
                    }))
                }
            }
            // Record handoff before processing a synchronously queued session loss.
            self.drain_monitor_events();
            // Only a real session-loss event permits resubmission. A rejection
            // with an otherwise ready session is terminal, never a retry policy.
            if self.state == BootstrapState::Ready
                && let Some(error) = session_error
                && let Some(entry) = self.statistics.as_mut().and_then(|c| {
                    c.entries
                        .iter_mut()
                        .flatten()
                        .find(|e| e.token == token && e.result.is_none())
                })
            {
                entry.result = Some(Err(match error {
                    monc::MonSendError::NoSession => StatisticsError::NotReady,
                    _ => StatisticsError::Transport,
                }));
            }
            if self.state != BootstrapState::Ready {
                break;
            }
        }
    }
    pub(super) fn statistics_reply(&mut self, tid: u64, reply: MStatfsReply) {
        self.statistics_progress();
        let Some(c) = &mut self.statistics else {
            return;
        };
        let Some(e) = c.entries.iter_mut().flatten().find(|e| {
            e.result.is_none() && e.tid == Some(tid) && matches!(e.query, Query::Cluster)
        }) else {
            return;
        };
        if self.fsid != Some(reply.fsid) {
            self.fail(BootstrapError::FsidMismatch);
            return;
        }
        c.version = c.version.max(reply.version);
        e.result = Some(Ok(Value::Cluster(reply.statistics)));
    }
    pub(super) fn pool_statistics_reply(&mut self, tid: u64, reply: MGetPoolStatsReply) {
        self.statistics_progress();
        let Some(c) = &mut self.statistics else {
            return;
        };
        let Some(e) = c.entries.iter_mut().flatten().find(|e| {
            e.result.is_none()
                && e.tid == Some(tid)
                && matches!(e.query, Query::Pool { .. } | Query::Pools { .. })
        }) else {
            return;
        };
        if self.fsid != Some(reply.fsid) {
            self.fail(BootstrapError::FsidMismatch);
            return;
        }
        c.version = c.version.max(reply.version);
        e.result = Some(Ok(match &e.query {
            Query::Pool { name, .. } => Value::Pool(
                reply
                    .pools
                    .get(name)
                    .map_or_else(PoolStatistics::default, |raw| raw.public(reply.per_pool)),
            ),
            Query::Pools { .. } => Value::Pools(
                reply
                    .pools
                    .into_iter()
                    .map(|(name, raw)| (name, raw.public(reply.per_pool)))
                    .collect(),
            ),
            Query::Cluster => unreachable!("matched pool statistics query"),
        }));
    }
    pub(super) fn statistics_lost(&mut self) {
        self.statistics_progress();
        if let Some(c) = &mut self.statistics {
            for entry in c
                .entries
                .iter_mut()
                .flatten()
                .filter(|e| e.result.is_none())
            {
                if matches!(entry.query, Query::Pools { .. }) {
                    entry.tid = None;
                } else {
                    entry.result = Some(Err(StatisticsError::MonitorLost));
                }
            }
        }
    }
    pub(super) fn statistics_stop(&mut self, error: StatisticsError) {
        if let Some(c) = &mut self.statistics {
            c.fail(error);
            c.error = Some(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wide_statistics_budget_expires_once_unlimited_survives_loss_without_a_timer() {
        let mut b = fixture();
        b.statistics.as_mut().unwrap().entries.push(None);
        assert_eq!(
            b.submit_cluster_statistics(time::MAX_TIME_US + 1),
            Err(StatisticsError::Overflow)
        );
        let end = time::deadline_after(0, 1u64 << 32).unwrap();
        let finite = b.submit_cluster_statistics(end).unwrap();
        let unlimited = b
            .submit_pool_statistics_batch_compatible(vec![b"retained".to_vec()], time::NO_DEADLINE)
            .unwrap();
        b.last_now = Duration::from_micros(end - 1);
        b.statistics_progress();
        assert_eq!(b.poll_statistics_into(&mut [None]), 0);
        assert_eq!(b.statistics.as_ref().unwrap().deadline(), Some(end));
        b.last_now = Duration::from_micros(end);
        b.statistics_lost();
        let done = take(&mut b);
        assert_eq!(
            (done.token, done.result),
            (finite, Err(StatisticsError::Deadline))
        );
        assert_eq!(b.statistics.as_ref().unwrap().deadline(), None);
        let entry = b
            .statistics
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .flatten()
            .next()
            .unwrap();
        assert_eq!(
            (entry.token, entry.deadline),
            (unlimited, time::NO_DEADLINE)
        );
        b.last_now = Duration::from_micros(time::MAX_TIME_US);
        b.statistics_progress();
        assert_eq!(b.poll_pool_statistics_batch_into(&mut [None]), 0);
        b.cancel_statistics(unlimited).unwrap();
        assert_eq!(take_batch(&mut b).result, Err(StatisticsError::Cancelled));
        assert_eq!(b.poll_pool_statistics_batch_into(&mut [None]), 0);
    }
    use crate::{BootstrapConfig, MessengerMode};
    use denc::types::Uuid;
    use std::time::Duration;
    const FSID: Uuid = Uuid([7; 16]);
    #[derive(Debug)]
    struct StatisticsMonitorAuth;
    impl msgr2::auth::AuthServerHandler for StatisticsMonitorAuth {
        fn supported_methods(&self, _: u8) -> Vec<u32> {
            vec![cephx::modes::AUTH_NONE]
        }
        fn supported_modes(&self, _: u8, _: u32) -> Vec<u32> {
            vec![cephx::modes::CON_MODE_CRC]
        }
        fn handle_auth_request(
            &mut self,
            _: u8,
            _: bool,
            method: u32,
            mode: u32,
            payload: &[u8],
        ) -> msgr2::auth::AuthServerStep {
            assert_eq!(
                (method, mode),
                (cephx::modes::AUTH_NONE, cephx::modes::CON_MODE_CRC)
            );
            let (_, name, gid) = cephx::none::parse_none_payload(payload).unwrap();
            assert_eq!(name.to_string(), "client.statistics");
            assert!(gid == 0 || gid == 77);
            msgr2::auth::AuthServerStep::Done {
                reply: vec![],
                global_id: 77,
                peer_name: None,
                secrets: Default::default(),
            }
        }
    }
    fn exchange(
        b: &mut Bootstrap,
        server: &mut msgr2::Connection,
        conn: u64,
    ) -> Vec<(u64, MGetPoolStats)> {
        use messages::Message;
        let mut requests = Vec::new();
        for _ in 0..1000 {
            // Pump the real owner just as the client reactor does: submission
            // itself admits work; progress performs the monitor handoff.
            b.progress(b.last_now).unwrap();
            let from_client = b.poll_output(conn);
            if !from_client.is_empty() {
                server.on_bytes(&from_client, b.last_now);
            }
            let from_server = server.poll_output();
            if !from_server.is_empty() {
                b.on_bytes(conn, &from_server, b.last_now);
            }
            while let Some(event) = server.poll_event() {
                match event {
                    msgr2::Event::Message(m) if m.header.msg_type == 58 => {
                        requests.push((
                            m.header.tid,
                            MGetPoolStats::decode(m.header.version, &m.front, &m.middle, &m.data)
                                .unwrap(),
                        ));
                    }
                    msgr2::Event::Fault(error) => panic!("statistics monitor fault: {error:?}"),
                    _ => {}
                }
            }
            if from_client.is_empty() && from_server.is_empty() {
                return requests;
            }
        }
        panic!("statistics byte exchange did not quiesce");
    }
    fn connect_monitor(b: &mut Bootstrap) -> (msgr2::Connection, u64, Vec<(u64, MGetPoolStats)>) {
        let (conn, target) = loop {
            match b.poll_io().expect("monitor dial queued") {
                monc::IoCmd::Dial { conn, target } => break (conn, target),
                monc::IoCmd::Close { .. } => {}
            }
        };
        let config = msgr2::Config::new(
            denc::types::EntityName::new(denc::types::EntityName::MON, 0),
            denc::types::EntityAddrVec::single(target),
            msgr2::PolicyTable::uniform(msgr2::Policy::stateless_server(0)),
        );
        let mut server = msgr2::Connection::server(
            999,
            config,
            msgr2::SessionTable::new(1),
            Box::new(StatisticsMonitorAuth),
            denc::types::EntityAddr::v4(2, 0, [127, 0, 0, 1], 40000),
            b.last_now,
        );
        b.on_connected(conn, b.last_now);
        let sent = exchange(b, &mut server, conn);
        (server, conn, sent)
    }
    fn send_monitor(
        server: &mut msgr2::Connection,
        tid: u64,
        message: impl Into<messages::AnyMessage>,
    ) {
        let (msg_type, version, compat_version, segments) =
            message.into().encode(u64::MAX).unwrap();
        assert!(server.send_message(msgr2::Message {
            tid,
            msg_type,
            version,
            compat_version,
            front: segments.front,
            middle: segments.middle,
            data: segments.data,
            ..Default::default()
        }));
    }
    fn wire_fixture() -> (Bootstrap, msgr2::Connection, u64) {
        let mut b = Bootstrap::new(BootstrapConfig {
            entity: "client.statistics".into(),
            key: crate::ClientAuth::new(vec![cephx::modes::AUTH_NONE], None).unwrap(),
            monitors: monc::parse_mon_host("v2:127.0.0.1:3300").unwrap(),
            expected_fsid: Some(FSID),
            mode: MessengerMode::Crc,
            startup_timeout: Duration::from_secs(10),
            wall_origin_unix: 100,
        })
        .unwrap();
        b.start(Duration::ZERO).unwrap();
        let (mut server, conn, sent) = connect_monitor(&mut b);
        assert!(sent.is_empty());
        let mut monmap = b.monitor.as_ref().unwrap().monmap().clone();
        monmap.fsid = FSID;
        monmap.epoch = 1;
        send_monitor(
            &mut server,
            0,
            messages::MMonMap {
                monmap: monmap.encode_to().unwrap(),
            },
        );
        assert!(exchange(&mut b, &mut server, conn).is_empty());
        let mut map = osdmap::OsdMap::default();
        map.fsid = FSID;
        map.epoch = 1;
        // No pools at all: compatible batches must not require membership.
        b.monitor.as_mut().unwrap().set_osdmap(map);
        // A map reaches the client through `on_bytes` (which advances); this fixture installs it directly.
        b.advance();
        assert_eq!(b.state, BootstrapState::Ready);
        b.enable_statistics(3, 3).unwrap();
        (b, server, conn)
    }
    #[test]
    fn batch_is_one_real_wire_message_and_empty_is_an_actual_empty_query() {
        let (mut b, mut server, conn) = wire_fixture();
        let mut large = vec![b"returned".to_vec(); 4097];
        large.extend([b"unknown".to_vec(), vec![255; 4097], vec![]]);
        for names in [large, vec![]] {
            let token = b
                .submit_pool_statistics_batch_compatible(names.clone(), 5_000_000)
                .unwrap();
            let sent = exchange(&mut b, &mut server, conn);
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].1.pools, names);
            assert_eq!(sent[0].1.fsid, FSID);
            assert_eq!(b.statistics.as_ref().unwrap().occupied, 1);
            let pools = if names.is_empty() {
                BTreeMap::new()
            } else {
                BTreeMap::from([(b"returned".to_vec(), messages::RawPoolStatistics::default())])
            };
            send_monitor(
                &mut server,
                sent[0].0,
                MGetPoolStatsReply {
                    version: 11,
                    fsid: FSID,
                    pools,
                    per_pool: false,
                },
            );
            assert!(exchange(&mut b, &mut server, conn).is_empty());
            let done = take_batch(&mut b);
            assert_eq!(done.token, token);
            assert_eq!(done.result.unwrap().len(), usize::from(!names.is_empty()));
        }
    }
    #[test]
    fn real_monitor_reconnect_resends_one_original_batch_not_a_new_logical_query() {
        let (mut b, mut old_server, conn) = wire_fixture();
        let deadline = time::deadline_after(0, 1u64 << 32).unwrap();
        let names = vec![
            b"returned".to_vec(),
            b"unknown".to_vec(),
            b"returned".to_vec(),
            vec![],
        ];
        let token = b
            .submit_pool_statistics_batch_compatible(names.clone(), deadline)
            .unwrap();
        let old = exchange(&mut b, &mut old_server, conn);
        assert_eq!(old.len(), 1);
        b.monitor
            .as_mut()
            .unwrap()
            .rehunt("statistics reconnect test");
        b.drain_monitor_events();
        assert_eq!(b.state, BootstrapState::Hunting);
        assert_eq!(b.poll_pool_statistics_batch_into(&mut [None]), 0);
        let (mut server, next_conn, resent) = connect_monitor(&mut b);
        assert_eq!(resent.len(), 1);
        assert_eq!(resent[0].1.pools, names);
        assert_ne!(resent[0].0, old[0].0);
        let entry = b.statistics.as_ref().unwrap().entries[0].as_ref().unwrap();
        assert_eq!((entry.token, entry.deadline), (token, deadline));
        batch_reply(&mut b, old[0].0, true);
        assert_eq!(b.poll_pool_statistics_batch_into(&mut [None]), 0);
        send_monitor(
            &mut server,
            resent[0].0,
            MGetPoolStatsReply {
                version: 21,
                fsid: FSID,
                pools: BTreeMap::new(),
                per_pool: true,
            },
        );
        assert!(exchange(&mut b, &mut server, next_conn).is_empty());
        let done = take_batch(&mut b);
        assert_eq!(done.token, token);
        assert!(done.result.unwrap().is_empty());
        assert_eq!(b.statistics.as_ref().unwrap().sequence, 1);
    }
    #[test]
    fn singleton_name_batch_survives_real_credit_wait_map_changes_and_monitor_reconnect() {
        let (mut b, mut old_server, conn) = wire_fixture();
        let mut original = vec![b'p', 0, 255];
        original.extend(vec![b'n'; 8193]);
        let mut map = b.osdmap().unwrap().clone();
        map.epoch += 1;
        map.pools.insert(7, osdmap::PgPool::default());
        map.pool_name.insert(7, original.clone().into());
        map.pools.insert(9, osdmap::PgPool::default());
        map.pool_name.insert(9, "strict".into());
        b.monitor.as_mut().unwrap().set_osdmap(map.clone());
        // The FFI retains this owned name before attempting native admission.
        let captured = vec![b.osdmap().unwrap().pool_name[&7].as_bytes().to_vec()];
        let cluster = b.submit_cluster_statistics(5_000_000).unwrap();
        let strict = b.submit_pool_statistics(9, 5_000_000).unwrap();
        let blocker = b.submit_cluster_statistics(5_000_000).unwrap();
        for change in 0..3 {
            match change {
                0 => {
                    map.pool_name.insert(7, "renamed".into());
                }
                1 => {
                    map.pools.remove(&7);
                    map.pool_name.remove(&7);
                }
                _ => {
                    map.pools.insert(8, osdmap::PgPool::default());
                    map.pool_name.insert(8, original.clone().into());
                }
            }
            map.epoch += 1;
            b.monitor.as_mut().unwrap().set_osdmap(map.clone());
            assert_eq!(
                b.submit_pool_statistics_batch_compatible(captured.clone(), 5_000_000),
                Err(StatisticsError::NoCredit)
            );
        }
        b.cancel_statistics(blocker).unwrap();
        let done = take(&mut b);
        assert_eq!(
            (done.token, done.result),
            (blocker, Err(StatisticsError::Cancelled))
        );
        let token = b
            .submit_pool_statistics_batch_compatible(captured.clone(), 5_000_000)
            .unwrap();
        let sent = exchange(&mut b, &mut old_server, conn);
        assert_eq!(sent.len(), 2); // strict native query plus compatible singleton
        let old_tid = sent
            .iter()
            .find(|(_, request)| request.pools == captured)
            .unwrap()
            .0;
        assert!(
            sent.iter()
                .any(|(_, request)| request.pools == [b"strict".to_vec()])
        );
        b.monitor
            .as_mut()
            .unwrap()
            .rehunt("singleton statistics reconnect test");
        b.drain_monitor_events();
        let done = take(&mut b);
        assert_eq!(
            (done.token, done.result),
            (cluster, Err(StatisticsError::MonitorLost))
        );
        let done = take_pool(&mut b);
        assert_eq!(
            (done.token, done.result),
            (strict, Err(StatisticsError::MonitorLost))
        );
        assert_eq!(b.poll_pool_statistics_batch_into(&mut [None]), 0);
        // Delete even the replacement ID before resend: the retained name,
        // not a held-map binding, remains the complete request identity.
        map.pools.remove(&8);
        map.pool_name.remove(&8);
        map.epoch += 1;
        b.monitor.as_mut().unwrap().set_osdmap(map);
        let (mut server, next_conn, resent) = connect_monitor(&mut b);
        assert_eq!(resent.len(), 1);
        assert_eq!(resent[0].1.pools, captured);
        let entry = b
            .statistics
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .flatten()
            .next()
            .unwrap();
        assert_eq!((entry.token, entry.deadline), (token, 5_000_000));
        batch_reply(&mut b, old_tid, true);
        assert_eq!(b.poll_pool_statistics_batch_into(&mut [None]), 0);
        send_monitor(
            &mut server,
            resent[0].0,
            MGetPoolStatsReply {
                version: 21,
                fsid: FSID,
                pools: BTreeMap::new(),
                per_pool: true,
            },
        );
        assert!(exchange(&mut b, &mut server, next_conn).is_empty());
        let done = take_batch(&mut b);
        assert_eq!(done.token, token);
        assert!(done.result.unwrap().is_empty()); // C delivery alone maps omission to zero
        batch_reply(&mut b, resent[0].0, true);
        assert_eq!(b.poll_pool_statistics_batch_into(&mut [None]), 0);
        assert_eq!(b.cancel_statistics(token), Err(StatisticsError::Stale));
        assert_eq!(b.statistics.as_ref().unwrap().occupied, 0);
    }
    fn take_batch(b: &mut Bootstrap) -> PoolStatisticsBatchCompletion {
        let mut out = [None];
        assert_eq!(b.poll_pool_statistics_batch_into(&mut out), 1);
        out[0].take().unwrap()
    }
    fn batch_reply(b: &mut Bootstrap, tid: u64, per_pool: bool) {
        let mut raw = messages::RawPoolStatistics::default();
        raw.counters[0] = 111;
        raw.counters[1] = 7;
        raw.store.allocated = 999;
        b.pool_statistics_reply(
            tid,
            MGetPoolStatsReply {
                version: 17,
                fsid: FSID,
                pools: BTreeMap::from([(b"returned".to_vec(), raw)]),
                per_pool,
            },
        );
    }
    #[test]
    fn batch_owns_names_without_poolmap_filter_and_keeps_other_consumers_separate() {
        let mut b = fixture();
        b.statistics.as_mut().unwrap().entries.extend([None, None]);
        let mut names = vec![b"unknown".to_vec(); 4097];
        names.extend([vec![], vec![255; 4097]]);
        let owner = names.as_ptr();
        let batch = b
            .submit_pool_statistics_batch_compatible(names, 100)
            .unwrap();
        let entry = b.statistics.as_ref().unwrap().entries[0].as_ref().unwrap();
        let Query::Pools { names } = &entry.query else {
            panic!("batch")
        };
        assert_eq!(names.as_ptr(), owner);
        assert_eq!(names.len(), 4099);
        assert_eq!(names[4097], b"");
        assert_eq!(names[4098].len(), 4097);
        assert!(b.osdmap().is_none());
        b.statistics.as_mut().unwrap().entries[0]
            .as_mut()
            .unwrap()
            .tid = Some(31);
        let cluster = b.submit_cluster_statistics(100).unwrap();
        b.statistics.as_mut().unwrap().entries[1]
            .as_mut()
            .unwrap()
            .tid = Some(32);
        // Neither a cluster reply to the batch TID nor an unrelated pool reply
        // completes anything. The full returned map is one typed result.
        reply(&mut b, 31, FSID, 10);
        batch_reply(&mut b, 30, true);
        assert_eq!(b.poll_pool_statistics_batch_into(&mut [None]), 0);
        batch_reply(&mut b, 31, true);
        assert_eq!(b.poll_statistics_into(&mut [None]), 0);
        assert_eq!(b.poll_pool_statistics_into(&mut [None]), 0);
        let mut occupied = [Some(PoolStatisticsBatchCompletion {
            token: batch,
            result: Err(StatisticsError::Cancelled),
        })];
        assert_eq!(b.poll_pool_statistics_batch_into(&mut occupied), 0);
        let done = take_batch(&mut b);
        assert_eq!(done.token, batch);
        let map = done.result.unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map[b"returned".as_slice()].num_bytes, 999);
        assert!(!map.contains_key(b"unknown".as_slice()));
        reply(&mut b, 32, FSID, 18);
        assert_eq!(take(&mut b).token, cluster);
        assert_eq!(b.statistics.as_ref().unwrap().occupied, 0);
    }
    #[test]
    fn batch_loss_keeps_logical_identity_names_and_deadline_but_strict_loss_stays_terminal() {
        let mut b = pool_fixture();
        let batch = b
            .submit_pool_statistics_batch_compatible(
                vec![b"unknown".to_vec(), vec![], b"unknown".to_vec()],
                100,
            )
            .unwrap();
        let strict = b.submit_pool_statistics(7, 100).unwrap();
        b.statistics.as_mut().unwrap().entries[0]
            .as_mut()
            .unwrap()
            .tid = Some(41);
        b.statistics.as_mut().unwrap().entries[1]
            .as_mut()
            .unwrap()
            .tid = Some(42);
        b.monitor_event(monc::MonEvent::SessionLost("batch test".into()));
        let entry = b.statistics.as_ref().unwrap().entries[0].as_ref().unwrap();
        assert_eq!(entry.token, batch);
        assert_eq!(entry.deadline, 100);
        assert_eq!(entry.tid, None);
        assert!(entry.result.is_none());
        let Query::Pools { names } = &entry.query else {
            panic!("batch")
        };
        assert_eq!(names, &[b"unknown".to_vec(), vec![], b"unknown".to_vec()]);
        let done = take_pool(&mut b);
        assert_eq!(done.token, strict);
        assert_eq!(done.result, Err(StatisticsError::MonitorLost));
        assert!(b.statistics.as_ref().unwrap().can_wait(false));
        assert!(!b.statistics.as_ref().unwrap().can_wait(true));
        assert_eq!(b.statistics.as_ref().unwrap().deadline(), Some(100));
        batch_reply(&mut b, 41, false); // stale pre-reconnect reply
        assert_eq!(b.poll_pool_statistics_batch_into(&mut [None]), 0);
        b.state = BootstrapState::Ready;
        b.statistics.as_mut().unwrap().entries[0]
            .as_mut()
            .unwrap()
            .tid = Some(43);
        batch_reply(&mut b, 43, false);
        let done = take_batch(&mut b);
        assert_eq!(done.token, batch);
        assert_eq!(done.result.unwrap()[b"returned".as_slice()].num_bytes, 111);
        assert_eq!(b.statistics.as_ref().unwrap().version, 17);
    }
    #[test]
    fn batch_deadline_cancel_close_and_fsid_follow_existing_terminal_contracts() {
        for action in 0..4 {
            let mut b = fixture();
            let token = b
                .submit_pool_statistics_batch_compatible(vec![], 100)
                .unwrap();
            b.statistics.as_mut().unwrap().entries[0]
                .as_mut()
                .unwrap()
                .tid = Some(51);
            let expected = match action {
                0 => {
                    b.last_now = Duration::from_micros(100);
                    b.statistics_lost();
                    batch_reply(&mut b, 51, true);
                    StatisticsError::Deadline
                }
                1 => {
                    let foreign = fixture()
                        .submit_pool_statistics_batch_compatible(vec![], 100)
                        .unwrap();
                    assert_eq!(b.cancel_statistics(foreign), Err(StatisticsError::Stale));
                    b.cancel_statistics(token).unwrap();
                    StatisticsError::Cancelled
                }
                2 => {
                    b.close();
                    StatisticsError::Closed
                }
                _ => {
                    b.pool_statistics_reply(
                        51,
                        MGetPoolStatsReply {
                            version: 19,
                            fsid: Uuid([8; 16]),
                            pools: BTreeMap::new(),
                            per_pool: true,
                        },
                    );
                    StatisticsError::Bootstrap(BootstrapError::FsidMismatch)
                }
            };
            assert_eq!(b.poll_statistics_into(&mut [None]), 0);
            assert_eq!(b.poll_pool_statistics_into(&mut [None]), 0);
            let done = take_batch(&mut b);
            assert_eq!(done.token, token);
            assert_eq!(done.result, Err(expected));
            assert_eq!(b.poll_pool_statistics_batch_into(&mut [None]), 0);
        }
    }
    #[test]
    fn concurrent_batches_match_their_own_tid_and_cancel_does_not_publish_a_prefix() {
        let mut b = pool_fixture();
        b.statistics.as_mut().unwrap().entries.push(None);
        let first = b
            .submit_pool_statistics_batch_compatible(vec![b"a".to_vec(), b"b".to_vec()], 100)
            .unwrap();
        let second = b
            .submit_pool_statistics_batch_compatible(vec![b"c".to_vec()], 101)
            .unwrap();
        let single = b.submit_pool_statistics(7, 102).unwrap();
        for (slot, tid) in b
            .statistics
            .as_mut()
            .unwrap()
            .entries
            .iter_mut()
            .zip([61, 62, 63])
        {
            slot.as_mut().unwrap().tid = Some(tid);
        }
        batch_reply(&mut b, 62, true);
        pool_reply(&mut b, 63, false);
        let complete = take_batch(&mut b);
        assert_eq!(complete.token, second);
        assert_eq!(complete.result.unwrap().len(), 1);
        let complete = take_pool(&mut b);
        assert_eq!(complete.token, single);
        assert_eq!(complete.result, Ok(PoolStatistics::default()));
        b.cancel_statistics(first).unwrap();
        batch_reply(&mut b, 61, true);
        let complete = take_batch(&mut b);
        assert_eq!(complete.token, first);
        assert_eq!(complete.result, Err(StatisticsError::Cancelled));
        assert_eq!(b.statistics.as_ref().unwrap().occupied, 0);
    }
    #[test]
    fn strict_single_pool_name_policy_is_not_relaxed_by_compatible_batch_codec() {
        let mut b = pool_fixture();
        let mut map = b.osdmap().unwrap().clone();
        map.pool_name.insert(7, vec![b'n'; 4097].into());
        b.monitor.as_mut().unwrap().set_osdmap(map);
        assert_eq!(
            b.submit_pool_statistics(7, 100),
            Err(StatisticsError::RequestTooLarge)
        );
        assert!(
            b.submit_pool_statistics_batch_compatible(vec![vec![b'n'; 4097]], 100)
                .is_ok()
        );
    }
    fn fixture() -> Bootstrap {
        let mut b = Bootstrap::new(BootstrapConfig {
            entity: "client.statistics".into(),
            key: cephx::CryptoKey::new(
                cephx::key::KeyType::Aes,
                Default::default(),
                b"1234567890abcdef",
            ),
            monitors: monc::parse_mon_host("v2:127.0.0.1:3300").unwrap(),
            expected_fsid: Some(FSID),
            mode: MessengerMode::Crc,
            startup_timeout: Duration::from_secs(10),
            wall_origin_unix: 100,
        })
        .unwrap();
        // Owner composition only, not an authentication test.
        b.state = BootstrapState::Ready;
        b.fsid = Some(FSID);
        b.deadline = None;
        b.enable_statistics(1, 1).unwrap();
        b
    }
    fn flight(b: &mut Bootstrap, deadline: u64) -> StatisticsToken {
        let token = b.submit_cluster_statistics(deadline).unwrap();
        b.statistics.as_mut().unwrap().entries[0]
            .as_mut()
            .unwrap()
            .tid = Some(19);
        token
    }
    fn reply(b: &mut Bootstrap, tid: u64, fsid: Uuid, version: u64) {
        b.monitor_event(monc::MonEvent::Message {
            tid,
            msg: Box::new(
                MStatfsReply {
                    fsid,
                    version,
                    statistics: ClusterStatistics {
                        kb: 100,
                        kb_used: 20,
                        kb_avail: 80,
                        num_objects: 7,
                    },
                }
                .into(),
            ),
        });
    }
    fn take(b: &mut Bootstrap) -> StatisticsCompletion {
        let mut out = [None];
        assert_eq!(b.poll_statistics_into(&mut out), 1);
        out[0].take().unwrap()
    }
    #[test]
    fn slots_keep_credit_through_exact_reply_and_dequeue() {
        let mut b = fixture();
        let token = flight(&mut b, 100);
        reply(&mut b, 18, FSID, 90);
        assert_eq!(b.poll_statistics_into(&mut [None]), 0);
        assert_eq!(
            b.submit_cluster_statistics(101),
            Err(StatisticsError::NoCredit)
        );
        reply(&mut b, 19, FSID, 10);
        reply(&mut b, 19, FSID, 11);
        assert_eq!(
            b.submit_cluster_statistics(101),
            Err(StatisticsError::NoCredit)
        );
        assert_eq!(b.statistics.as_ref().unwrap().version, 10);
        assert_eq!(
            take(&mut b),
            StatisticsCompletion {
                token,
                result: Ok(ClusterStatistics {
                    kb: 100,
                    kb_used: 20,
                    kb_avail: 80,
                    num_objects: 7
                })
            }
        );
        let next = flight(&mut b, 101);
        assert_ne!(next, token);
        reply(&mut b, 19, FSID, 5);
        take(&mut b);
        assert_eq!(b.statistics.as_ref().unwrap().version, 10);
    }
    #[test]
    fn occupied_output_keeps_prior_completion_and_new_slot_credit() {
        let mut b = fixture();
        let first = flight(&mut b, 100);
        reply(&mut b, 19, FSID, 10);
        let mut out = [None];
        assert_eq!(b.poll_statistics_into(&mut out), 1);
        let second = flight(&mut b, 100);
        reply(&mut b, 19, FSID, 11);
        assert_eq!(b.poll_statistics_into(&mut out), 0);
        assert_eq!(out[0].unwrap().token, first);
        assert_eq!(
            b.submit_cluster_statistics(101),
            Err(StatisticsError::NoCredit)
        );
        out[0] = None;
        assert_eq!(b.poll_statistics_into(&mut out), 1);
        assert_eq!(out[0].unwrap().token, second);
        assert!(b.submit_cluster_statistics(101).is_ok());
    }
    #[test]
    fn queued_and_completed_work_remain_runnable_but_inflight_sleeps() {
        let mut b = fixture();
        assert!(b.can_sleep());
        let token = b.submit_cluster_statistics(100).unwrap();
        assert!(!b.can_sleep());
        assert_eq!(b.next_timer(), Some(Duration::from_micros(100)));
        b.statistics.as_mut().unwrap().entries[0]
            .as_mut()
            .unwrap()
            .tid = Some(19);
        assert!(b.can_sleep());
        assert!(b.can_sleep_with_blocked_output(&|_| true));
        b.cancel_statistics(token).unwrap();
        assert!(!b.can_sleep());
        assert_eq!(b.next_timer(), None);
        assert_eq!(
            b.cancel_statistics(token),
            Err(StatisticsError::AlreadyComplete)
        );
        take(&mut b);
        assert!(b.can_sleep());
        assert_eq!(b.cancel_statistics(token), Err(StatisticsError::Stale));
    }
    #[test]
    fn deadline_wins_over_reply_or_loss_and_cancel_is_owner_scoped() {
        let mut b = fixture();
        flight(&mut b, 100);
        b.last_now = Duration::from_micros(100);
        reply(&mut b, 19, FSID, 10);
        assert_eq!(take(&mut b).result, Err(StatisticsError::Deadline));
        let other = flight(&mut fixture(), 100);
        let token = b.submit_cluster_statistics(101).unwrap();
        assert_eq!(b.cancel_statistics(other), Err(StatisticsError::Stale));
        b.last_now = Duration::from_micros(101);
        b.statistics_lost();
        assert_eq!(take(&mut b).token, token);
        assert_eq!(b.statistics.as_ref().unwrap().version, 0);
    }
    #[test]
    fn loss_and_close_terminalize_once_and_no_session_has_no_success() {
        let mut b = fixture();
        flight(&mut b, 100);
        b.statistics_lost();
        reply(&mut b, 19, FSID, 10);
        assert_eq!(take(&mut b).result, Err(StatisticsError::MonitorLost));
        b.submit_cluster_statistics(100).unwrap();
        b.statistics_dispatch();
        assert_eq!(take(&mut b).result, Err(StatisticsError::NotReady));
        b.submit_cluster_statistics(100).unwrap();
        b.close();
        assert_eq!(take(&mut b).result, Err(StatisticsError::Closed));
        assert_eq!(
            b.submit_cluster_statistics(100),
            Err(StatisticsError::Closed)
        );
        b.close();
        assert_eq!(b.poll_statistics_into(&mut [None]), 0);
    }
    #[test]
    fn active_wrong_fsid_fails_bootstrap_and_preserves_terminal_result() {
        let mut b = fixture();
        flight(&mut b, 100);
        reply(&mut b, 18, Uuid([8; 16]), 10);
        assert_eq!(b.state, BootstrapState::Ready);
        reply(&mut b, 19, Uuid([8; 16]), 10);
        assert_eq!(
            b.state,
            BootstrapState::Failed(BootstrapError::FsidMismatch)
        );
        assert_eq!(
            take(&mut b).result,
            Err(StatisticsError::Bootstrap(BootstrapError::FsidMismatch))
        );
    }
    fn pool_fixture() -> Bootstrap {
        let mut b = fixture();
        b.statistics.as_mut().unwrap().entries.push(None);
        let mut cfg = monc::Config::new("client.statistics", None);
        let mut monmap =
            monc::monmap_from_addrs(&monc::parse_mon_host("v2:127.0.0.1:3300").unwrap());
        monmap.fsid = FSID;
        cfg.initial_monmap = Some(monmap);
        let mut mon = monc::MonClient::new(cfg);
        let mut map = osdmap::OsdMap::default();
        map.fsid = FSID;
        map.epoch = 4;
        map.pools.insert(
            7,
            osdmap::PgPool {
                ptype: 3,
                ..Default::default()
            },
        );
        map.pool_name.insert(7, vec![255, 65].into());
        mon.set_osdmap(map);
        b.monitor = Some(mon);
        b
    }
    fn pool_reply(b: &mut Bootstrap, tid: u64, found: bool) {
        let mut pools = std::collections::BTreeMap::new();
        if found {
            let mut raw = messages::RawPoolStatistics::default();
            raw.counters[1] = 7;
            pools.insert(vec![255, 65], raw);
        }
        b.monitor_event(monc::MonEvent::Message {
            tid,
            msg: Box::new(
                messages::MGetPoolStatsReply {
                    fsid: FSID,
                    version: 11,
                    pools,
                    per_pool: true,
                }
                .into(),
            ),
        });
    }
    fn take_pool(b: &mut Bootstrap) -> PoolStatisticsCompletion {
        let mut out = [None];
        assert_eq!(b.poll_pool_statistics_into(&mut out), 1);
        out[0].take().unwrap()
    }
    #[test]
    fn cluster_and_pool_families_share_credit_without_cross_consumption() {
        let mut b = pool_fixture();
        assert_eq!(b.statistics.as_ref().unwrap().occupied, 0);
        let cluster = flight(&mut b, 100);
        let pool = b.submit_pool_statistics(7, 100).unwrap();
        assert_eq!(b.statistics.as_ref().unwrap().occupied, 2);
        b.statistics.as_mut().unwrap().entries[1]
            .as_mut()
            .unwrap()
            .tid = Some(20);
        pool_reply(&mut b, 19, true);
        reply(&mut b, 20, FSID, 10);
        assert_eq!(b.poll_statistics_into(&mut [None]), 0);
        assert_eq!(b.poll_pool_statistics_into(&mut [None]), 0);
        pool_reply(&mut b, 20, true);
        assert_eq!(b.poll_statistics_into(&mut [None]), 0);
        assert_eq!(
            b.submit_cluster_statistics(101),
            Err(StatisticsError::NoCredit)
        );
        let done = take_pool(&mut b);
        assert_eq!(done.token, pool);
        assert_eq!(done.result.unwrap().num_objects, 7);
        assert_eq!(b.statistics.as_ref().unwrap().occupied, 1);
        reply(&mut b, 19, FSID, 10);
        assert_eq!(take(&mut b).token, cluster);
        assert_eq!(b.statistics.as_ref().unwrap().version, 11);
        assert_eq!(b.statistics.as_ref().unwrap().occupied, 0);
        assert!(b.statistics.as_ref().unwrap().can_wait(true));
        assert_eq!(b.statistics.as_ref().unwrap().deadline(), None);
        assert!(b.submit_cluster_statistics(101).is_ok());
    }
    #[test]
    fn cancelled_statistics_keep_credit_until_matching_consumer_drains() {
        let mut b = fixture();
        let token = b.submit_cluster_statistics(100).unwrap();
        b.cancel_statistics(token).unwrap();
        assert_eq!(b.statistics.as_ref().unwrap().occupied, 1);
        assert!(!b.statistics.as_ref().unwrap().can_wait(true));
        assert_eq!(b.poll_pool_statistics_into(&mut [None]), 0);
        assert_eq!(
            b.submit_cluster_statistics(101),
            Err(StatisticsError::NoCredit)
        );
        assert_eq!(take(&mut b).result, Err(StatisticsError::Cancelled));
        assert_eq!(b.statistics.as_ref().unwrap().occupied, 0);
        assert!(b.statistics.as_ref().unwrap().can_wait(true));
        b.statistics_progress();
        b.statistics_dispatch();
        assert_eq!(b.poll_statistics_into(&mut [None]), 0);
    }
    #[test]
    fn pool_result_preserves_occupied_output_and_missing_report_is_zero() {
        let mut b = pool_fixture();
        let token = b.submit_pool_statistics(7, 100).unwrap();
        b.statistics.as_mut().unwrap().entries[0]
            .as_mut()
            .unwrap()
            .tid = Some(19);
        pool_reply(&mut b, 19, false);
        let held = PoolStatisticsCompletion {
            token,
            result: Err(StatisticsError::Cancelled),
        };
        let mut out = [Some(held)];
        assert_eq!(b.poll_pool_statistics_into(&mut out), 0);
        assert_eq!(out[0], Some(held));
        out[0] = None;
        assert_eq!(b.poll_pool_statistics_into(&mut out), 1);
        assert_eq!(out[0].unwrap().result, Ok(PoolStatistics::default()));
    }
    #[test]
    fn pool_name_delete_and_rename_revalidated_before_handoff() {
        let mut b = pool_fixture();
        assert_eq!(
            b.submit_pool_statistics(8, 100),
            Err(StatisticsError::NoPool)
        );
        b.submit_pool_statistics(7, 100).unwrap();
        let mut map = b.osdmap().unwrap().clone();
        map.pool_name.insert(7, "renamed".into());
        b.monitor.as_mut().unwrap().set_osdmap(map);
        b.statistics_dispatch();
        assert_eq!(take_pool(&mut b).result, Err(StatisticsError::NoPool));
        b.submit_pool_statistics(7, 100).unwrap();
        let mut map = b.osdmap().unwrap().clone();
        map.pools.remove(&7);
        b.monitor.as_mut().unwrap().set_osdmap(map);
        b.statistics_dispatch();
        assert_eq!(take_pool(&mut b).result, Err(StatisticsError::NoPool));
    }
    #[test]
    fn pool_cancel_loss_and_close_drain_only_through_pool_api() {
        let mut b = pool_fixture();
        let token = b.submit_pool_statistics(7, 100).unwrap();
        b.cancel_statistics(token).unwrap();
        assert_eq!(b.poll_statistics_into(&mut [None]), 0);
        assert_eq!(take_pool(&mut b).result, Err(StatisticsError::Cancelled));
        b.submit_pool_statistics(7, 100).unwrap();
        b.statistics_lost();
        assert_eq!(take_pool(&mut b).result, Err(StatisticsError::MonitorLost));
        b.submit_pool_statistics(7, 100).unwrap();
        b.close();
        assert_eq!(take_pool(&mut b).result, Err(StatisticsError::Closed));
        assert_eq!(
            b.submit_pool_statistics(7, 100),
            Err(StatisticsError::Closed)
        );
    }
}
