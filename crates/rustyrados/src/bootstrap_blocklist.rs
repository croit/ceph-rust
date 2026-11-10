// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::{Bootstrap, BootstrapState};
use crate::{
    BlocklistCompletion, BlocklistError as E, BlocklistLimits, BlocklistQueue, BlocklistReply,
    BlocklistRequest, BlocklistToken, MapBarrierError as M, MapBarrierLimits, MapBarrierOutcome,
    MapBarrierQueue, MapBarrierRequest, MapBarrierToken, RejectedBlocklist,
};
use monc::MonSendError;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlocklistControlLimits {
    pub queue: BlocklistLimits,
    pub query_attempts: u32,
    pub work: usize,
}
/// Lab diagnostics only; accepted handoffs do not imply wire delivery.
#[cfg(feature = "lab")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LabBlocklistStats {
    pub mutations: u64,
    pub queries: u64,
    pub observer_losses: u64,
    pub lagged_queries: u64,
    pub monitor_losses: u64,
    pub observer_waiting: bool,
    pub withheld_acks: u64,
}
pub(super) struct BlocklistControl {
    pub(super) queue: BlocklistQueue,
    maps: MapBarrierQueue,
    cohort: Vec<Option<BlocklistToken>>,
    flight: Option<MapBarrierToken>,
    pub(super) work: usize,
    #[cfg(feature = "lab")]
    stats: LabBlocklistStats,
    #[cfg(feature = "lab")]
    withhold_tid: Option<u64>,
}
fn map_error(error: M) -> E {
    match error {
        M::Overflow => E::Overflow,
        M::Deadline => E::Deadline,
        M::Cancelled => E::Cancelled,
        M::Closed => E::Closed,
        M::MonitorLost => E::MonitorLost,
        M::Clock => E::Clock,
        M::Fsid => E::Fsid,
        M::MapRegression => E::MapRegression,
        M::Identity => E::Identity,
        M::Bootstrap(e) => E::Bootstrap(e),
        _ => E::Protocol,
    }
}
impl BlocklistControl {
    pub(super) fn can_wait(&self, now: u64, map: &osdmap::OsdMap) -> bool {
        if !self.queue.can_wait(now, map)
            || !self.maps.can_wait(now, map.fsid, map.epoch, true)
            || (self.maps.error().is_some() && self.queue.error().is_none())
        {
            return false;
        }
        match self.flight {
            Some(_) => {
                self.maps.outstanding() == 1
                    && self
                        .cohort
                        .iter()
                        .flatten()
                        .any(|&token| self.queue.observation_pending(token))
            }
            None => {
                self.maps.outstanding() == 0
                    && self.cohort.iter().all(Option::is_none)
                    && !(0..self.cohort.len()).any(|i| self.queue.observation_at(i).is_some())
            }
        }
    }
    fn synchronize(&mut self) {
        if let Some(flight) = self.flight
            && !self
                .cohort
                .iter()
                .flatten()
                .any(|&token| self.queue.observation_pending(token))
        {
            let _ = self.maps.cancel(flight);
        }
        let mut out = [None];
        if self.maps.poll_into(&mut out) == 1 {
            let done = out[0].take().unwrap();
            if self.flight == Some(done.token) {
                for member in &mut self.cohort {
                    if let Some(token) = member.take() {
                        if !self.queue.observation_pending(token) {
                            continue;
                        }
                        match done.outcome {
                            MapBarrierOutcome::Reached { target_epoch, .. } => {
                                let _ = self.queue.confirm_observation(token, target_epoch);
                            }
                            MapBarrierOutcome::Failed { error, .. } => {
                                self.queue.fail_observation(token, map_error(error))
                            }
                        }
                    }
                }
                self.flight = None;
            } else {
                self.queue.abort(E::Protocol);
            }
        }
    }
    fn start_cohort(&mut self) {
        if self.flight.is_some() || self.queue.error().is_some() {
            return;
        }
        let mut deadline = 0;
        for (slot, member) in self.cohort.iter_mut().enumerate() {
            *member = self.queue.observation_at(slot).map(|(token, until)| {
                deadline = deadline.max(until);
                token
            });
        }
        if deadline == 0 {
            return;
        }
        match self.maps.submit(MapBarrierRequest::Latest, deadline) {
            Ok(token) => self.flight = Some(token),
            Err(error) => {
                self.cohort.fill(None);
                self.queue.abort(map_error(error.reason));
            }
        }
    }
}
impl Bootstrap {
    /// Inject one EOF after the first accepted observer query, before output drain.
    #[cfg(feature = "lab")]
    pub fn lab_blocklist_observer_loss(&mut self) -> bool {
        if self.state != BootstrapState::New {
            return false;
        }
        self.blocklist_observer_loss = true;
        true
    }
    #[cfg(feature = "lab")]
    pub fn lab_blocklist_stats(&self) -> Option<LabBlocklistStats> {
        self.blocklists.as_ref().map(|c| LabBlocklistStats {
            lagged_queries: c.maps.lab_lagged_queries(),
            observer_waiting: c.maps.needs_query(),
            ..c.stats
        })
    }

    /// Lab-only query gate; real monitor loss releases it after a committed cohort exists.
    #[cfg(feature = "lab")]
    pub fn lab_blocklist_wait_for_monitor_loss(&mut self) -> bool {
        if self.state != BootstrapState::New {
            return false;
        }
        self.blocklist_wait_for_loss = true;
        true
    }
    /// Lab qualifier: lose one authenticated command reply before core publication.
    #[cfg(feature = "lab")]
    pub fn lab_blocklist_withhold_ack(&mut self) -> bool {
        if self.state != BootstrapState::New {
            return false;
        }
        self.blocklist_withhold_ack = true;
        true
    }
    pub fn enable_blocklist(&mut self, limits: BlocklistControlLimits) -> Result<(), E> {
        if self.blocklists.is_some() {
            return Err(E::AlreadyEnabled);
        }
        if !(1..=4096).contains(&limits.work) || !(1..=65535).contains(&limits.query_attempts) {
            return Err(E::Limits);
        }
        if self.state != BootstrapState::Ready {
            return Err(E::NotReady);
        }
        let map = self.blocklist_map()?;
        let now = self.control_now();
        let mut queue = BlocklistQueue::new(map.fsid, limits.queue)?;
        queue.progress(now, map, 0)?;
        let mut maps = MapBarrierQueue::new(
            map.fsid,
            MapBarrierLimits {
                slots: 1,
                query_attempts: limits.query_attempts,
            },
        )
        .map_err(map_error)?;
        maps.progress(now, map.fsid, map.epoch, 0)
            .map_err(map_error)?;
        self.blocklists = Some(BlocklistControl {
            queue,
            maps,
            cohort: vec![None; limits.queue.slots],
            flight: None,
            work: limits.work,
            #[cfg(feature = "lab")]
            stats: LabBlocklistStats::default(),
            #[cfg(feature = "lab")]
            withhold_tid: None,
        });
        Ok(())
    }
    pub fn submit_blocklist(
        &mut self,
        request: BlocklistRequest,
        deadline_us: u64,
    ) -> Result<BlocklistToken, RejectedBlocklist> {
        let reject = |reason| RejectedBlocklist { reason, request };
        if self.blocklists.is_none() {
            return Err(reject(E::Disabled));
        }
        if self.state != BootstrapState::Ready {
            return Err(reject(E::NotReady));
        }
        self.blocklist_map().map_err(reject)?;
        self.blocklist_progress(0);
        let q = &mut self.blocklists.as_mut().unwrap().queue;
        let token = q.submit(request, deadline_us)?;
        q.defer_observation(token).map_err(reject)?;
        Ok(token)
    }
    pub fn cancel_blocklist(&mut self, token: BlocklistToken) -> Result<(), E> {
        self.blocklists
            .as_mut()
            .ok_or(E::Disabled)?
            .queue
            .cancel(token)?;
        let work = self.blocklists.as_ref().unwrap().work;
        self.blocklist_detach(work);
        Ok(())
    }
    pub fn poll_blocklist_into(&mut self, out: &mut [Option<BlocklistCompletion>]) -> usize {
        let work = self.blocklists.as_ref().map_or(0, |c| c.work);
        self.blocklist_detach(work);
        self.blocklists
            .as_mut()
            .map_or(0, |c| c.queue.poll_into(out))
    }
    pub fn blocklist_error(&self) -> Option<E> {
        self.blocklists.as_ref().and_then(|c| c.queue.error())
    }
    fn blocklist_map(&self) -> Result<&osdmap::OsdMap, E> {
        let mon = self.monitor.as_ref().ok_or(E::NotReady)?;
        let map = mon.osdmap().ok_or(E::NotReady)?;
        if self.identity.is_none_or(|id| id == 0) || map.epoch == 0 {
            return Err(E::NotReady);
        }
        if self.fsid != Some(map.fsid)
            || self.fsid != Some(mon.monmap().fsid)
            || map.fsid == denc::types::Uuid::default()
        {
            return Err(E::Fsid);
        }
        Ok(map)
    }
    pub(super) fn blocklist_detach(&mut self, work: usize) {
        let Some(c) = &mut self.blocklists else {
            return;
        };
        c.synchronize();
        if let Some(handle) = c.maps.take_abandoned_query()
            && let Some(mon) = &mut self.monitor
        {
            mon.cancel_version(handle);
        }
        for _ in 0..work.min(c.cohort.len()) {
            let Some(tid) = c.queue.take_abandoned_command() else {
                break;
            };
            if let Some(mon) = &mut self.monitor {
                mon.cancel_command_once(tid);
            }
        }
    }
    pub(super) fn blocklist_stop(&mut self, error: E) {
        if let Some(c) = &mut self.blocklists {
            c.queue.abort(error);
            c.maps.abort(M::Closed);
        }
        let slots = self.blocklists.as_ref().map_or(0, |c| c.cohort.len());
        self.blocklist_detach(slots);
    }
    pub(super) fn blocklist_progress(&mut self, work: usize) {
        if self.blocklists.is_none() || self.monitor.is_none() {
            return;
        }
        if let Err(error) = self.blocklist_map() {
            if error == E::Fsid {
                self.fail(super::BootstrapError::FsidMismatch);
            } else {
                self.blocklist_stop(error);
            }
            return;
        }
        let now = self.control_now();
        let map = self.monitor.as_ref().unwrap().osdmap().unwrap();
        let c = self.blocklists.as_mut().unwrap();
        let _ = c.queue.progress(now, map, work);
        let _ = c
            .maps
            .progress(now, map.fsid, map.epoch, usize::from(work > 0));
        if let Some(error) = c.maps.error() {
            c.queue.abort(map_error(error));
        }
        if c.queue.error().is_some() {
            c.maps.abort(M::Closed);
        }
        c.synchronize();
        let _ = c.queue.progress(now, map, work);
        if work > 0 {
            c.start_cohort();
        }
        self.blocklist_detach(work);
    }
    pub(super) fn blocklist_reply(&mut self, reply: BlocklistReply) {
        self.blocklist_progress(0);
        let now = self.control_now();
        if let Some(c) = &mut self.blocklists {
            #[cfg(feature = "lab")]
            if c.withhold_tid == Some(reply.tid) {
                c.withhold_tid = None;
                c.stats.withheld_acks = c.stats.withheld_acks.saturating_add(1);
                return;
            }
            let _ = c.queue.on_reply(now, reply);
        }
    }
    pub(super) fn blocklist_lost(&mut self, tid: u64) {
        self.blocklist_progress(0);
        if let Some(c) = &mut self.blocklists {
            c.queue.lost(tid);
        }
    }
    pub(super) fn blocklist_monitor_lost(&mut self) {
        self.blocklist_progress(0);
        if let Some(c) = &mut self.blocklists {
            #[cfg(feature = "lab")]
            {
                c.stats.monitor_losses = c.stats.monitor_losses.saturating_add(1);
                if c.flight.is_some() {
                    self.blocklist_wait_for_loss = false;
                }
            }
            c.queue.monitor_lost();
            c.maps.monitor_lost();
        }
        let work = self.blocklists.as_ref().map_or(0, |c| c.work);
        self.blocklist_detach(work);
    }
    pub(super) fn blocklist_version(&mut self, handle: u64, newest: u64, oldest: u64) {
        self.blocklist_progress(0);
        if let Some(c) = &mut self.blocklists {
            let _ = c.maps.on_version(handle, newest, oldest);
        }
        let work = self.blocklists.as_ref().map_or(0, |c| c.work);
        self.blocklist_detach(work);
    }
    pub(super) fn blocklist_dispatch(&mut self) {
        let work = self.blocklists.as_ref().map_or(0, |c| c.work);
        self.blocklist_detach(work);
        if self.state != BootstrapState::Ready {
            return;
        }
        let Some(c) = &mut self.blocklists else {
            return;
        };
        if let Some(dispatch) = c.queue.next_command(work) {
            let token = dispatch.token;
            match self
                .monitor
                .as_mut()
                .unwrap()
                .try_send_command_once(dispatch.command, vec![])
            {
                Ok(tid) => {
                    #[cfg(feature = "lab")]
                    {
                        c.stats.mutations = c.stats.mutations.saturating_add(1);
                    }
                    if let Err(error) = c.queue.mark_handed(token, tid) {
                        self.monitor.as_mut().unwrap().cancel_command_once(tid);
                        c.queue.abort(error);
                    } else {
                        #[cfg(feature = "lab")]
                        if self.blocklist_withhold_ack {
                            c.withhold_tid = Some(tid);
                            self.blocklist_withhold_ack = false;
                        }
                    }
                }
                Err(MonSendError::NoSession) => {}
                Err(MonSendError::Rejected) => {
                    let _ = c.queue.reject_handoff(token);
                }
                Err(MonSendError::IdentityExhausted) => c.queue.abort(E::Identity),
            }
        }
        self.drain_monitor_events();
        if self.state != BootstrapState::Ready {
            return;
        }
        let Some(c) = &mut self.blocklists else {
            return;
        };
        if let Some(epoch) = c
            .queue
            .waiting_epoch()
            .into_iter()
            .chain(c.maps.wanted_epoch())
            .min()
        {
            self.monitor.as_mut().unwrap().request_osdmap_epoch(epoch);
        }
        #[cfg(feature = "lab")]
        let mut inject_loss = false;
        let query_ready = c.maps.needs_query();
        #[cfg(feature = "lab")]
        let query_ready = query_ready && !self.blocklist_wait_for_loss;
        if query_ready {
            match self.monitor.as_mut().unwrap().try_get_version("osdmap") {
                Ok(handle) => {
                    #[cfg(feature = "lab")]
                    {
                        c.stats.queries = c.stats.queries.saturating_add(1);
                    }
                    if let Err(error) = c.maps.mark_query(handle) {
                        self.monitor.as_mut().unwrap().cancel_version(handle);
                        c.queue.abort(map_error(error));
                    } else {
                        #[cfg(feature = "lab")]
                        {
                            inject_loss = self.blocklist_observer_loss;
                            self.blocklist_observer_loss = false;
                        }
                    }
                }
                Err(MonSendError::NoSession) => {}
                Err(MonSendError::IdentityExhausted) => c.queue.abort(E::Identity),
                Err(MonSendError::Rejected) => c.queue.abort(E::Protocol),
            }
            #[cfg(feature = "lab")]
            if inject_loss {
                let c = self.blocklists.as_mut().unwrap();
                c.stats.observer_losses = c.stats.observer_losses.saturating_add(1);
                let mon = self.monitor.as_mut().unwrap();
                for id in mon.conn_ids() {
                    mon.on_closed(id, self.last_now);
                }
            }
            self.drain_monitor_events();
        }
        self.blocklist_detach(work);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlocklistCertainty, BlocklistOutcome, BootstrapConfig, BootstrapError, MessengerMode,
    };
    use denc::types::{EntityAddr, UTime, Uuid};
    use monc::MonEvent;
    use std::time::Duration;
    const FSID: Uuid = Uuid([7; 16]);
    fn fixture() -> Bootstrap {
        let mut b = Bootstrap::new(BootstrapConfig {
            entity: "client.blocklist".into(),
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
        let mut cfg = monc::Config::new("client.blocklist", None);
        let mut mm = monc::monmap_from_addrs(&monc::parse_mon_host("v2:127.0.0.1:3300").unwrap());
        mm.fsid = FSID;
        cfg.initial_monmap = Some(mm);
        let mut mon = monc::MonClient::new(cfg);
        let mut map = osdmap::OsdMap::default();
        map.fsid = FSID;
        map.epoch = 5;
        map.require_osd_release = 21;
        mon.set_osdmap(map);
        b.monitor = Some(mon);
        b.identity = Some(9);
        b.state = BootstrapState::Ready;
        b // Composition fixture, not CephX qualification.
    }
    fn limits() -> BlocklistControlLimits {
        BlocklistControlLimits {
            queue: BlocklistLimits {
                slots: 4,
                reply_bytes: 256,
            },
            query_attempts: 2,
            work: 4,
        }
    }
    fn req(nonce: u32) -> BlocklistRequest {
        BlocklistRequest {
            address: EntityAddr::v4(2, nonce, [10, 0, 0, 1], 0),
            expire_seconds: 60,
        }
    }
    fn handed(b: &mut Bootstrap, nonce: u32, tid: u64, deadline: u64) -> BlocklistToken {
        let t = b.submit_blocklist(req(nonce), deadline).unwrap();
        b.blocklists
            .as_mut()
            .unwrap()
            .queue
            .mark_handed(t, tid)
            .unwrap();
        t
    }
    fn ack(b: &mut Bootstrap, tid: u64, version: u64, result: i32) {
        let command = b
            .blocklists
            .as_mut()
            .unwrap()
            .queue
            .next_command(4)
            .map(|d| d.command.to_owned());
        assert!(
            command.is_none(),
            "fixture marks every submitted mutation handed before ack"
        );
        let nonce = tid as u32;
        let json = format!(
            "{{\"prefix\":\"osd blocklist\",\"blocklistop\":\"add\",\"addr\":\"{}\",\"expire\":60.0}}",
            req(nonce).address
        );
        b.monitor_event(MonEvent::CommandOnceReply {
            tid,
            version,
            r: result,
            rs: "status".into(),
            cmd: vec![json],
            data: vec![0, 255],
        });
    }
    fn epoch(b: &mut Bootstrap, epoch: u32, nonces: &[u32]) {
        let mut m = b.osdmap().unwrap().clone();
        m.epoch = epoch;
        for &n in nonces {
            let mut a = req(n).address;
            a.ty = 3;
            m.blocklist.insert(a, UTime::new(999, 1));
        }
        b.monitor.as_mut().unwrap().set_osdmap(m);
    }
    fn version(b: &mut Bootstrap, handle: u64, newest: u64) {
        b.monitor_event(MonEvent::VersionReply {
            handle,
            version: newest,
            oldest: 1,
        });
    }
    fn query(b: &mut Bootstrap, handle: u64) {
        b.blocklists
            .as_mut()
            .unwrap()
            .maps
            .mark_query(handle)
            .unwrap();
    }
    fn take(b: &mut Bootstrap) -> BlocklistCompletion {
        let mut out = [None];
        assert_eq!(b.poll_blocklist_into(&mut out), 1);
        out[0].take().unwrap()
    }
    #[test]
    fn daemon_command_routing_keeps_internal_blocklist_replies_and_losses() {
        let mut b = fixture();
        b.enable_blocklist(limits()).unwrap();
        b.daemon_monitor = true;
        let token = handed(&mut b, 8, 8, 100);
        assert!(matches!(
            b.monitor_event(MonEvent::CommandOnceLost { tid: 7 }),
            Some(MonEvent::CommandOnceLost { tid: 7 })
        ));
        let event = |tid| MonEvent::CommandOnceReply {
            tid,
            version: 4,
            r: -13,
            rs: "denied".into(),
            cmd: vec![format!(
                "{{\"prefix\":\"osd blocklist\",\"blocklistop\":\"add\",\"addr\":\"{}\",\"expire\":60.0}}",
                req(8).address
            )],
            data: vec![],
        };
        assert!(matches!(
            b.monitor_event(event(7)),
            Some(MonEvent::CommandOnceReply { tid: 7, .. })
        ));
        assert!(b.monitor_event(event(8)).is_none());
        let done = take(&mut b);
        assert_eq!(done.token, token);
        assert!(matches!(
            done.outcome,
            BlocklistOutcome::Failed {
                error: E::Remote(-13),
                ..
            }
        ));
        let token = handed(&mut b, 9, 9, 100);
        assert!(
            b.monitor_event(MonEvent::CommandOnceLost { tid: 9 })
                .is_none()
        );
        assert_eq!(take(&mut b).token, token);
    }

    #[test]
    fn fresh_after_ack_not_cached_map_and_later_ack_needs_later_cohort() {
        let mut b = fixture();
        b.enable_blocklist(limits()).unwrap();
        assert!(b.can_sleep());
        let a = handed(&mut b, 1, 1, 1000);
        assert!(b.can_sleep());
        epoch(&mut b, 6, &[1]);
        b.blocklist_progress(4);
        assert!(b.blocklists.as_ref().unwrap().flight.is_none());
        ack(&mut b, 1, 6, 0);
        assert!(!b.can_sleep()); // Fresh observer needed even with cached committed map.
        b.blocklist_progress(4);
        assert!(!b.can_sleep());
        assert!(b.blocklists.as_ref().unwrap().maps.needs_query());
        assert_eq!(b.poll_blocklist_into(&mut [None]), 0);
        query(&mut b, 100);
        assert!(b.can_sleep());
        let c = handed(&mut b, 2, 2, 1000);
        ack(&mut b, 2, 7, 0);
        assert!(b.can_sleep()); // Later committed member waits behind old cohort.
        version(&mut b, 100, 6);
        assert!(!b.can_sleep());
        b.blocklist_progress(4);
        let done = take(&mut b);
        assert_eq!(done.token, a);
        assert!(matches!(
            done.outcome,
            BlocklistOutcome::Observed {
                committed_epoch: 6,
                target_epoch: 6,
                observed_epoch: 6,
                ..
            }
        ));
        assert_eq!(b.poll_blocklist_into(&mut [None]), 0);
        assert!(b.blocklists.as_ref().unwrap().maps.needs_query());
        assert!(!b.can_sleep());
        query(&mut b, 101);
        assert!(b.can_sleep());
        version(&mut b, 101, 8);
        assert!(b.can_sleep());
        epoch(&mut b, 8, &[2]);
        assert!(!b.can_sleep());
        b.blocklist_progress(4);
        assert!(!b.can_sleep());
        let done = take(&mut b);
        assert_eq!(done.token, c);
        assert!(matches!(
            done.outcome,
            BlocklistOutcome::Observed {
                committed_epoch: 7,
                target_epoch: 8,
                observed_epoch: 8,
                ..
            }
        ));
        assert!(b.can_sleep());
    }
    #[test]
    fn readiness_preserves_observer_cleanup_and_internal_error_propagation() {
        let mut b = fixture();
        b.enable_blocklist(limits()).unwrap();
        let token = handed(&mut b, 1, 1, 1000);
        ack(&mut b, 1, 6, 0);
        b.blocklist_progress(4);
        query(&mut b, 100);
        assert!(b.can_sleep());
        assert!(b.can_sleep_with_blocked_output(&|_| true));
        b.cancel_blocklist(token).unwrap();
        assert!(!b.can_sleep());
        assert!(!b.can_sleep_with_blocked_output(&|_| true));
        assert_eq!(take(&mut b).token, token);
        assert!(b.can_sleep());
        assert!(b.can_sleep_with_blocked_output(&|_| true));
        let token = handed(&mut b, 2, 2, 1000);
        b.blocklists.as_mut().unwrap().maps.abort(M::Protocol);
        assert!(!b.can_sleep());
        assert!(!b.can_sleep_with_blocked_output(&|_| true));
        b.blocklist_progress(4);
        assert!(!b.can_sleep());
        assert!(!b.can_sleep_with_blocked_output(&|_| true));
        let done = take(&mut b);
        assert_eq!(done.token, token);
        assert!(matches!(
            done.outcome,
            BlocklistOutcome::Failed {
                certainty: BlocklistCertainty::Unknown,
                ..
            }
        ));
        assert!(b.can_sleep());
        assert!(b.can_sleep_with_blocked_output(&|_| true));
    }
    #[test]
    fn one_cohort_multiple_acks_member_expiry_does_not_cancel_other_member() {
        let mut b = fixture();
        b.enable_blocklist(limits()).unwrap();
        let a = handed(&mut b, 1, 1, 100);
        let c = handed(&mut b, 2, 2, 200);
        ack(&mut b, 1, 6, 0);
        ack(&mut b, 2, 6, 0);
        b.blocklist_progress(4);
        query(&mut b, 100);
        assert_eq!(
            b.blocklists
                .as_ref()
                .unwrap()
                .cohort
                .iter()
                .flatten()
                .count(),
            2
        );
        b.last_now = Duration::from_micros(100);
        b.blocklist_progress(4);
        assert!(b.blocklists.as_ref().unwrap().flight.is_some());
        let done = take(&mut b);
        assert_eq!(done.token, a);
        assert!(matches!(
            done.outcome,
            BlocklistOutcome::Failed {
                error: E::Deadline,
                certainty: BlocklistCertainty::Committed,
                ..
            }
        ));
        version(&mut b, 100, 6);
        epoch(&mut b, 6, &[2]);
        b.blocklist_progress(4);
        assert_eq!(take(&mut b).token, c);
    }
    #[test]
    fn last_cancel_releases_observer_and_stale_cohort_cannot_retarget_reused_slot() {
        let mut b = fixture();
        let mut l = limits();
        l.queue.slots = 1;
        b.enable_blocklist(l).unwrap();
        let a = handed(&mut b, 1, 1, 1000);
        ack(&mut b, 1, 6, 0);
        b.blocklist_progress(1);
        query(&mut b, 100);
        b.cancel_blocklist(a).unwrap();
        assert!(b.blocklists.as_ref().unwrap().flight.is_none());
        assert_eq!(b.blocklists.as_ref().unwrap().maps.outstanding(), 0);
        take(&mut b);
        let c = handed(&mut b, 2, 2, 1000);
        ack(&mut b, 2, 7, 0);
        b.blocklist_progress(1);
        query(&mut b, 101);
        version(&mut b, 100, 99);
        assert_eq!(b.poll_blocklist_into(&mut [None]), 0);
        version(&mut b, 101, 7);
        epoch(&mut b, 7, &[2]);
        b.blocklist_progress(1);
        assert_eq!(take(&mut b).token, c);
    }
    #[test]
    fn commit_higher_than_sample_still_waits_for_commit_and_exact_entry() {
        let mut b = fixture();
        b.enable_blocklist(limits()).unwrap();
        handed(&mut b, 1, 1, 1000);
        ack(&mut b, 1, 9, 0);
        b.blocklist_progress(4);
        query(&mut b, 100);
        version(&mut b, 100, 5);
        b.blocklist_progress(4);
        assert_eq!(
            b.blocklists.as_ref().unwrap().queue.waiting_epoch(),
            Some(9)
        );
        assert_eq!(b.poll_blocklist_into(&mut [None]), 0);
        epoch(&mut b, 9, &[1]);
        b.blocklist_progress(4);
        assert!(matches!(
            take(&mut b).outcome,
            BlocklistOutcome::Observed {
                committed_epoch: 9,
                target_epoch: 9,
                observed_epoch: 9,
                ..
            }
        ));
    }
    #[test]
    fn permission_error_skips_query_and_unhanded_rejected_dispatch_is_not_unknown() {
        let mut b = fixture();
        b.enable_blocklist(limits()).unwrap();
        let a = handed(&mut b, 1, 1, 1000);
        ack(&mut b, 1, 0, -13);
        let done = take(&mut b);
        assert_eq!(done.token, a);
        assert!(matches!(
            done.outcome,
            BlocklistOutcome::Failed {
                error: E::Remote(-13),
                certainty: BlocklistCertainty::Rejected(-13),
                ..
            }
        ));
        assert_eq!(b.blocklists.as_ref().unwrap().maps.outstanding(), 0);
        let queued = b.submit_blocklist(req(2), 1000).unwrap();
        b.blocklist_dispatch(); // fake-ready monc has no active connection: no handoff
        b.cancel_blocklist(queued).unwrap();
        assert!(matches!(
            take(&mut b).outcome,
            BlocklistOutcome::Failed {
                error: E::Cancelled,
                certainty: BlocklistCertainty::NotHanded,
                ..
            }
        ));
    }
    #[test]
    fn loss_retries_only_readonly_query_and_known_commit_survives_close_or_auth_failure() {
        let mut b = fixture();
        b.enable_blocklist(limits()).unwrap();
        let a = handed(&mut b, 1, 1, 1000);
        ack(&mut b, 1, 6, 0);
        b.blocklist_progress(4);
        query(&mut b, 100);
        b.monitor_event(MonEvent::SessionLost("fixture".into()));
        assert_eq!(b.state, BootstrapState::Hunting);
        assert!(b.blocklists.as_ref().unwrap().maps.needs_query());
        assert_eq!(b.poll_blocklist_into(&mut [None]), 0);
        b.state = BootstrapState::Ready;
        query(&mut b, 101);
        version(&mut b, 100, 99);
        version(&mut b, 101, 6);
        epoch(&mut b, 6, &[1]);
        b.blocklist_progress(4);
        assert_eq!(take(&mut b).token, a);
        let t = handed(&mut b, 2, 2, 1000);
        ack(&mut b, 2, 7, 0);
        b.close();
        let done = take(&mut b);
        assert_eq!(done.token, t);
        assert!(matches!(
            done.outcome,
            BlocklistOutcome::Failed {
                error: E::Closed,
                certainty: BlocklistCertainty::Committed,
                committed_epoch: Some(7)
            }
        ));
        let mut b = fixture();
        b.enable_blocklist(limits()).unwrap();
        handed(&mut b, 1, 1, 1000);
        b.monitor_event(MonEvent::AuthFailed("fixture".into()));
        assert!(matches!(
            take(&mut b).outcome,
            BlocklistOutcome::Failed {
                error: E::Bootstrap(BootstrapError::AuthRejected),
                certainty: BlocklistCertainty::Unknown,
                ..
            }
        ));
    }
    #[test]
    fn enable_limits_identity_fsid_clock_and_timer_boundaries() {
        let mut b = fixture();
        assert_eq!(
            b.submit_blocklist(req(1), 100).unwrap_err().reason,
            E::Disabled
        );
        b.state = BootstrapState::Hunting;
        assert_eq!(b.enable_blocklist(limits()), Err(E::NotReady));
        b.state = BootstrapState::Ready;
        let mut l = limits();
        l.query_attempts = 0;
        assert_eq!(b.enable_blocklist(l), Err(E::Limits));
        l = limits();
        l.work = 0;
        assert_eq!(b.enable_blocklist(l), Err(E::Limits));
        b.enable_blocklist(limits()).unwrap();
        assert_eq!(b.enable_blocklist(limits()), Err(E::AlreadyEnabled));
        b.submit_blocklist(req(1), 100).unwrap();
        assert_eq!(b.next_timer(), Some(Duration::from_micros(100)));
        b.progress(Duration::from_micros(100)).unwrap();
        assert!(matches!(
            take(&mut b).outcome,
            BlocklistOutcome::Failed {
                error: E::Deadline,
                certainty: BlocklistCertainty::NotHanded,
                ..
            }
        ));
        let t = handed(&mut b, 2, 2, 200);
        let mut m = b.osdmap().unwrap().clone();
        m.fsid = Uuid([8; 16]);
        b.monitor.as_mut().unwrap().set_osdmap(m);
        b.blocklist_progress(4);
        assert_eq!(
            b.state,
            BootstrapState::Failed(BootstrapError::FsidMismatch)
        );
        assert_eq!(take(&mut b).token, t);
    }
    #[test]
    fn public_latest_snapshot_and_internal_observer_keep_separate_credits_and_ids() {
        let mut b = fixture();
        let mut map = b.osdmap().unwrap().clone();
        map.pools.insert(
            7,
            osdmap::PgPool {
                ptype: 1,
                size: 3,
                ..Default::default()
            },
        );
        b.monitor.as_mut().unwrap().set_osdmap(map);
        b.enable_blocklist(limits()).unwrap();
        b.enable_map_barriers(
            MapBarrierLimits {
                slots: 1,
                query_attempts: 2,
            },
            1,
        )
        .unwrap();
        b.enable_snapshots(
            crate::SnapshotLimits {
                slots: 1,
                bytes: 64,
                response_bytes: 16,
            },
            1,
        )
        .unwrap();
        let public = b
            .submit_map_barrier(MapBarrierRequest::Latest, 1000)
            .unwrap();
        let snapshot = b
            .submit_snapshot(
                crate::SnapshotRequest {
                    pool: 7,
                    operation: crate::SnapshotOperation::Allocate,
                },
                1000,
            )
            .unwrap();
        b.map_barriers
            .as_mut()
            .unwrap()
            .queue
            .mark_query(99)
            .unwrap();
        let block = handed(&mut b, 1, 1, 1000);
        ack(&mut b, 1, 6, 0);
        b.blocklist_progress(4);
        query(&mut b, 100);
        version(&mut b, 99, 5);
        b.map_barrier_progress(1, 0);
        let mut out = [None];
        assert_eq!(b.poll_map_barriers_into(&mut out), 1);
        assert_eq!(out[0].take().unwrap().token, public);
        assert_eq!(b.poll_blocklist_into(&mut [None]), 0);
        assert_eq!(b.poll_snapshots_into(&mut [None]), 0);
        version(&mut b, 100, 6);
        epoch(&mut b, 6, &[1]);
        b.blocklist_progress(4);
        let done = take(&mut b);
        assert_eq!(done.token, block);
        b.monitor_event(MonEvent::AuthFailed("fixture".into()));
        let mut out = [None];
        assert_eq!(b.poll_snapshots_into(&mut out), 1);
        assert_eq!(out[0].take().unwrap().token, snapshot);
        assert!(matches!(done.outcome, BlocklistOutcome::Observed { .. }));
        assert_eq!(b.poll_blocklist_into(&mut [None]), 0);
    }
    #[test]
    fn committed_observer_deadline_and_regressing_map_fail_without_success() {
        let mut b = fixture();
        b.enable_blocklist(limits()).unwrap();
        handed(&mut b, 1, 1, 100);
        ack(&mut b, 1, 6, 0);
        b.blocklist_progress(4);
        query(&mut b, 100);
        b.last_now = Duration::from_micros(100);
        b.blocklist_progress(4);
        assert!(b.blocklists.as_ref().unwrap().flight.is_none());
        assert!(matches!(
            take(&mut b).outcome,
            BlocklistOutcome::Failed {
                error: E::Deadline,
                certainty: BlocklistCertainty::Committed,
                ..
            }
        ));
        let mut b = fixture();
        b.enable_blocklist(limits()).unwrap();
        handed(&mut b, 1, 1, 100);
        ack(&mut b, 1, 6, 0);
        b.blocklist_progress(4);
        query(&mut b, 100);
        epoch(&mut b, 4, &[1]);
        b.blocklist_progress(4);
        assert_eq!(b.blocklist_error(), Some(E::MapRegression));
        assert!(matches!(
            take(&mut b).outcome,
            BlocklistOutcome::Failed {
                error: E::MapRegression,
                certainty: BlocklistCertainty::Committed,
                ..
            }
        ));
    }
    #[cfg(feature = "lab")]
    #[test]
    fn lab_arm_prestart_only_and_no_session_cannot_consume_arm_or_count_handoff() {
        let mut b = fixture();
        assert!(!b.lab_blocklist_observer_loss());
        assert_eq!(b.lab_blocklist_stats(), None);
        b.state = BootstrapState::New;
        assert!(b.lab_blocklist_observer_loss());
        b.state = BootstrapState::Ready;
        b.enable_blocklist(limits()).unwrap();
        assert_eq!(b.lab_blocklist_stats(), Some(LabBlocklistStats::default()));
        let token = b.submit_blocklist(req(1), 1000).unwrap();
        b.blocklist_dispatch();
        assert!(b.blocklist_observer_loss);
        assert_eq!(b.lab_blocklist_stats(), Some(LabBlocklistStats::default()));
        // NoSession does not consume a query attempt or the armed EOF, either.
        b.blocklists
            .as_mut()
            .unwrap()
            .queue
            .mark_handed(token, 1)
            .unwrap();
        ack(&mut b, 1, 6, 0);
        b.blocklist_progress(4);
        b.blocklist_dispatch();
        assert!(b.blocklist_observer_loss);
        assert_eq!(
            b.lab_blocklist_stats(),
            Some(LabBlocklistStats {
                observer_waiting: true,
                ..Default::default()
            })
        );
        query(&mut b, 100);
        version(&mut b, 100, 6);
        assert_eq!(b.lab_blocklist_stats().unwrap().lagged_queries, 1);
    }
    #[cfg(feature = "lab")]
    #[test]
    fn process_gate_requires_prestart_and_committed_cohort_then_retains_request_on_loss() {
        let mut b = fixture();
        assert!(!b.lab_blocklist_wait_for_monitor_loss());
        b.state = BootstrapState::New;
        assert!(b.lab_blocklist_wait_for_monitor_loss());
        b.state = BootstrapState::Ready;
        b.enable_blocklist(limits()).unwrap();
        b.monitor_event(MonEvent::SessionLost("idle".into()));
        assert!(b.blocklist_wait_for_loss);
        b.state = BootstrapState::Ready;
        let token = handed(&mut b, 1, 1, 1000);
        ack(&mut b, 1, 6, 0);
        b.blocklist_progress(4);
        b.blocklist_dispatch();
        assert!(b.blocklist_wait_for_loss);
        assert!(b.lab_blocklist_stats().unwrap().observer_waiting);
        assert_eq!(b.poll_blocklist_into(&mut [None]), 0);
        b.monitor_event(MonEvent::SessionLost("committed cohort".into()));
        assert!(!b.blocklist_wait_for_loss);
        assert_eq!(b.lab_blocklist_stats().unwrap().monitor_losses, 2);
        assert_eq!(b.poll_blocklist_into(&mut [None]), 0);
        b.state = BootstrapState::Ready;
        query(&mut b, 100);
        version(&mut b, 100, 6);
        epoch(&mut b, 6, &[1]);
        b.blocklist_progress(4);
        let done = take(&mut b);
        assert_eq!(done.token, token);
        assert!(matches!(
            done.outcome,
            BlocklistOutcome::Observed {
                committed_epoch: 6,
                ..
            }
        ));
    }
    #[cfg(feature = "lab")]
    #[test]
    fn withheld_ack_does_not_infer_commit_from_map_or_replay_after_loss() {
        let mut b = fixture();
        assert!(!b.lab_blocklist_withhold_ack());
        b.state = BootstrapState::New;
        assert!(b.lab_blocklist_withhold_ack());
        b.state = BootstrapState::Ready;
        b.enable_blocklist(limits()).unwrap();
        let token = b.submit_blocklist(req(1), 1000).unwrap();
        b.blocklist_dispatch();
        assert!(b.blocklist_withhold_ack);
        assert_eq!(b.lab_blocklist_stats().unwrap().mutations, 0);
        // Composition fixture primes accepted correlation; real handoff qualified by live probe.
        let c = b.blocklists.as_mut().unwrap();
        c.queue.mark_handed(token, 1).unwrap();
        c.withhold_tid = Some(1);
        b.blocklist_withhold_ack = false;
        ack(&mut b, 99, 6, 0);
        assert_eq!(b.lab_blocklist_stats().unwrap().withheld_acks, 0);
        ack(&mut b, 1, 6, 0);
        assert_eq!(b.lab_blocklist_stats().unwrap().withheld_acks, 1);
        epoch(&mut b, 6, &[1]);
        b.blocklist_progress(4);
        assert_eq!(b.poll_blocklist_into(&mut [None]), 0);
        assert!(!b.lab_blocklist_stats().unwrap().observer_waiting);
        b.monitor_event(MonEvent::SessionLost("fixture actual-typed loss".into()));
        let done = take(&mut b);
        assert_eq!(done.token, token);
        assert!(done.ack.is_none());
        assert!(matches!(
            done.outcome,
            BlocklistOutcome::Failed {
                error: E::MonitorLost,
                certainty: BlocklistCertainty::Unknown,
                committed_epoch: None
            }
        ));
        ack(&mut b, 1, 6, 0);
        assert_eq!(b.poll_blocklist_into(&mut [None]), 0);
        b.state = BootstrapState::Ready;
        let next = handed(&mut b, 2, 2, 1000);
        ack(&mut b, 2, 7, 0);
        b.blocklist_progress(4);
        query(&mut b, 100);
        version(&mut b, 100, 7);
        epoch(&mut b, 7, &[2]);
        b.blocklist_progress(4);
        let good = take(&mut b);
        assert_eq!(good.token, next);
        assert!(matches!(
            good.outcome,
            BlocklistOutcome::Observed {
                committed_epoch: 7,
                ..
            }
        ));
        assert_eq!(b.lab_blocklist_stats().unwrap().withheld_acks, 1);
    }
}
