// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::{Bootstrap, BootstrapState};
use crate::{
    MapBarrierCompletion, MapBarrierError, MapBarrierLimits, MapBarrierQueue, MapBarrierRequest,
    MapBarrierToken, RejectedMapBarrier,
};
use monc::MonSendError;
pub(super) struct MapBarrierControl {
    pub(super) queue: MapBarrierQueue,
    pub(super) work: usize,
}
impl Bootstrap {
    pub fn enable_map_barriers(
        &mut self,
        limits: MapBarrierLimits,
        work: usize,
    ) -> Result<(), MapBarrierError> {
        self.enable_map_barrier_queue(work, |fsid| MapBarrierQueue::new(fsid, limits))
    }
    pub fn enable_compatible_map_barriers(
        &mut self,
        slots: usize,
        work: usize,
    ) -> Result<(), MapBarrierError> {
        self.enable_map_barrier_queue(work, |fsid| MapBarrierQueue::new_compatible(fsid, slots))
    }
    fn enable_map_barrier_queue(
        &mut self,
        work: usize,
        make: impl FnOnce(denc::types::Uuid) -> Result<MapBarrierQueue, MapBarrierError>,
    ) -> Result<(), MapBarrierError> {
        if self.map_barriers.is_some() {
            return Err(MapBarrierError::AlreadyEnabled);
        }
        if !(1..=4096).contains(&work) {
            return Err(MapBarrierError::Limits);
        }
        if self.state != BootstrapState::Ready {
            return Err(MapBarrierError::NotReady);
        }
        let (fsid, epoch) = self.map_barrier_map()?;
        let mut queue = make(fsid)?;
        queue.progress(self.control_now(), fsid, epoch, 0)?;
        self.map_barriers = Some(MapBarrierControl { queue, work });
        Ok(())
    }
    pub fn submit_map_barrier(
        &mut self,
        request: MapBarrierRequest,
        deadline_us: u64,
    ) -> Result<MapBarrierToken, RejectedMapBarrier> {
        let reject = |reason| RejectedMapBarrier { reason, request };
        if self.map_barriers.is_none() {
            return Err(reject(MapBarrierError::Disabled));
        }
        if self.state != BootstrapState::Ready {
            return Err(reject(MapBarrierError::NotReady));
        }
        let (fsid, epoch) = self.map_barrier_map().map_err(reject)?;
        let now = self.control_now();
        let q = &mut self.map_barriers.as_mut().unwrap().queue;
        q.progress(now, fsid, epoch, 0).map_err(reject)?;
        q.submit(request, deadline_us)
    }
    pub fn cancel_map_barrier(&mut self, token: MapBarrierToken) -> Result<(), MapBarrierError> {
        self.map_barriers
            .as_mut()
            .ok_or(MapBarrierError::Disabled)?
            .queue
            .cancel(token)?;
        self.map_barrier_detach();
        Ok(())
    }
    pub fn poll_map_barriers_into(&mut self, out: &mut [Option<MapBarrierCompletion>]) -> usize {
        self.map_barriers
            .as_mut()
            .map_or(0, |c| c.queue.poll_into(out))
    }
    #[cfg(feature = "lab")]
    pub fn lab_map_barrier_lagged_queries(&self) -> Option<u64> {
        self.map_barriers
            .as_ref()
            .map(|c| c.queue.lab_lagged_queries())
    }
    pub fn map_barrier_error(&self) -> Option<MapBarrierError> {
        self.map_barriers.as_ref().and_then(|c| c.queue.error())
    }
    pub(super) fn map_barrier_map(&self) -> Result<(denc::types::Uuid, u32), MapBarrierError> {
        let m = self.monitor.as_ref().ok_or(MapBarrierError::NotReady)?;
        let map = m.osdmap().ok_or(MapBarrierError::NotReady)?;
        if self.identity.is_none() || map.epoch == 0 {
            return Err(MapBarrierError::NotReady);
        }
        // An address-only bootstrap MonMap has a zero FSID. Map delivery can
        // precede both its replacement and the inference pass in advance().
        // Only two learned, nonzero identities can contradict one another.
        let zero = denc::types::Uuid::default();
        let mon_fsid = m.monmap().fsid;
        let known = self.fsid.filter(|fsid| *fsid != zero);
        if (map.fsid != zero && mon_fsid != zero && map.fsid != mon_fsid)
            || known.is_some_and(|fsid| {
                (map.fsid != zero && fsid != map.fsid) || (mon_fsid != zero && fsid != mon_fsid)
            })
        {
            return Err(MapBarrierError::Fsid);
        }
        if known.is_none() || mon_fsid == zero || map.fsid == zero {
            return Err(MapBarrierError::NotReady);
        }
        Ok((map.fsid, map.epoch))
    }
    /// Private freshness ownership for ordinary operations; public map waiters remain separate.
    pub fn submit_pool_check(
        &mut self,
        deadline_us: u64,
    ) -> Result<MapBarrierToken, MapBarrierError> {
        let (fsid, epoch) = self.map_barrier_map()?;
        let now = self.control_now();
        if self.pool_checks.is_none() {
            self.pool_checks = Some(MapBarrierControl {
                queue: MapBarrierQueue::new_compatible(fsid, 64)?,
                work: 16,
            });
        }
        let queue = &mut self.pool_checks.as_mut().unwrap().queue;
        queue.progress(now, fsid, epoch, 0)?;
        queue
            .submit(MapBarrierRequest::Latest, deadline_us)
            .map_err(|r| r.reason)
    }
    pub fn poll_pool_check(
        &mut self,
        token: MapBarrierToken,
    ) -> Result<Option<MapBarrierCompletion>, MapBarrierError> {
        let result = self
            .pool_checks
            .as_mut()
            .ok_or(MapBarrierError::Disabled)?
            .queue
            .poll_token(token);
        self.map_barrier_detach();
        result
    }
    pub fn cancel_pool_check(&mut self, token: MapBarrierToken) {
        if let Some(control) = &mut self.pool_checks {
            let _ = control.queue.cancel(token);
            let _ = control.queue.poll_token(token);
        }
        self.map_barrier_detach();
    }
    pub fn pool_check_waiting(&self, token: Option<MapBarrierToken>) -> bool {
        self.pool_checks
            .as_ref()
            .is_some_and(|control| match token {
                Some(token) => control.queue.token_waiting(token),
                None => control.queue.is_full(),
            })
    }
    pub(super) fn map_barrier_detach(&mut self) {
        for control in [self.map_barriers.as_mut(), self.pool_checks.as_mut()]
            .into_iter()
            .flatten()
        {
            if let Some(handle) = control.queue.take_abandoned_query()
                && let Some(mon) = &mut self.monitor
            {
                mon.cancel_version(handle);
            }
        }
    }
    pub(super) fn map_barrier_progress(&mut self, work: usize, pool_work: usize) {
        if self.monitor.is_none() {
            return;
        }
        let map = self.map_barrier_map();
        if map == Err(MapBarrierError::Fsid) {
            self.fail(super::BootstrapError::FsidMismatch);
            return;
        }
        if self.map_barriers.is_none() && self.pool_checks.is_none() {
            return;
        }
        let now = self.control_now();
        for (control, work) in [
            (self.map_barriers.as_mut(), work),
            (self.pool_checks.as_mut(), pool_work),
        ] {
            if let Some(control) = control {
                match map {
                    Ok((fsid, epoch)) => {
                        let _ = control.queue.progress(now, fsid, epoch, work);
                    }
                    Err(error) => control.queue.abort(error),
                }
            }
        }
        self.map_barrier_detach();
    }
    pub(super) fn map_barrier_version(&mut self, handle: u64, newest: u64, oldest: u64) {
        self.map_barrier_progress(0, 0);
        for control in [self.map_barriers.as_mut(), self.pool_checks.as_mut()]
            .into_iter()
            .flatten()
        {
            let _ = control.queue.on_version(handle, newest, oldest);
        }
        self.map_barrier_detach();
    }
    pub(super) fn map_barrier_dispatch(&mut self) {
        self.map_barrier_detach();
        if self.state != BootstrapState::Ready {
            return;
        }
        if let Some(epoch) = [self.map_barriers.as_ref(), self.pool_checks.as_ref()]
            .into_iter()
            .flatten()
            .filter_map(|c| c.queue.wanted_epoch())
            .min()
        {
            self.monitor.as_mut().unwrap().request_osdmap_epoch(epoch);
        }
        for c in [self.map_barriers.as_mut(), self.pool_checks.as_mut()]
            .into_iter()
            .flatten()
        {
            // A send can synchronously enqueue session loss. Mark before draining those events.
            if !c.queue.needs_query() {
                continue;
            }
            match self.monitor.as_mut().unwrap().try_get_version("osdmap") {
                Ok(handle) => {
                    if let Err(error) = c.queue.mark_query(handle) {
                        self.monitor.as_mut().unwrap().cancel_version(handle);
                        c.queue.abort(error);
                    }
                }
                Err(MonSendError::NoSession) => break,
                Err(error) => c.queue.abort(if error == MonSendError::IdentityExhausted {
                    MapBarrierError::Identity
                } else {
                    MapBarrierError::Protocol
                }),
            }
        }
        self.drain_monitor_events();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BootstrapConfig, MapBarrierOutcome, MessengerMode};
    use denc::types::Uuid;
    use std::time::Duration;
    const FSID: Uuid = Uuid([7; 16]);
    fn fixture() -> Bootstrap {
        let mut b = Bootstrap::new(BootstrapConfig {
            entity: "client.barrier".into(),
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
        let mut cfg = monc::Config::new("client.barrier", None);
        let mut map = monc::monmap_from_addrs(&monc::parse_mon_host("v2:127.0.0.1:3300").unwrap());
        map.fsid = FSID;
        cfg.initial_monmap = Some(map);
        let mut m = monc::MonClient::new(cfg);
        let mut map = osdmap::OsdMap::default();
        map.fsid = FSID;
        map.epoch = 4;
        m.set_osdmap(map);
        b.monitor = Some(m);
        // Owner composition fixture only; authentication itself is not exercised here.
        b.identity = Some(9);
        b.state = BootstrapState::Ready;
        b
    }
    fn enable(b: &mut Bootstrap) {
        b.enable_map_barriers(
            MapBarrierLimits {
                slots: 4,
                query_attempts: 2,
            },
            4,
        )
        .unwrap();
    }
    fn take(b: &mut Bootstrap) -> MapBarrierCompletion {
        let mut out = [None];
        assert_eq!(b.poll_map_barriers_into(&mut out), 1);
        out[0].take().unwrap()
    }
    fn epoch(b: &mut Bootstrap, n: u32) {
        let mut map = b.osdmap().unwrap().clone();
        map.epoch = n;
        b.monitor.as_mut().unwrap().set_osdmap(map);
    }
    #[test]
    fn initial_osdmap_before_fsid_inference_is_not_a_mismatch() {
        for mon_known in [false, true] {
            for expected in [None, Some(FSID)] {
                let mut b = fixture();
                b.state = BootstrapState::AwaitingMaps;
                b.fsid = expected;
                if !mon_known {
                    let mut m = monc::MonClient::new(monc::Config::new("client.barrier", None));
                    m.set_osdmap(b.osdmap().unwrap().clone());
                    b.monitor = Some(m);
                }
                // advance() checks map controls before draining the event that
                // learns the cluster identity. No map controls need be enabled.
                b.map_barrier_progress(0, 0);
                assert_eq!(b.state, BootstrapState::AwaitingMaps);
                assert_eq!(
                    b.map_barrier_map(),
                    if mon_known && expected.is_some() {
                        Ok((FSID, 4))
                    } else {
                        Err(MapBarrierError::NotReady)
                    }
                );
                b.monitor_event_owned(monc::MonEvent::OsdMap {
                    epoch: 4,
                    map: std::sync::Arc::new(b.osdmap().unwrap().clone()),
                    msg: Box::new(messages::MOSDMap::default()),
                });
                assert_eq!(b.fsid, Some(FSID));
                b.map_barrier_progress(0, 0);
                assert_eq!(b.state, BootstrapState::AwaitingMaps);
                if mon_known {
                    b.method = Some(cephx::modes::AUTH_NONE);
                    b.advance_readiness(true, FSID, Some((FSID, 4)), false);
                    assert_eq!(b.state, BootstrapState::Ready);
                }
            }
        }
    }
    #[test]
    fn learned_map_identities_disagree_even_before_inference() {
        let mut b = fixture();
        b.fsid = None;
        let mut map = b.osdmap().unwrap().clone();
        map.fsid = Uuid([8; 16]);
        b.monitor.as_mut().unwrap().set_osdmap(map);
        b.map_barrier_progress(0, 0);
        assert_eq!(
            b.state,
            BootstrapState::Failed(crate::BootstrapError::FsidMismatch)
        );
    }

    #[test]
    fn compatible_bootstrap_enable_and_loss_events_preserve_correlation_and_timer() {
        let mut b = fixture();
        b.enable_compatible_map_barriers(4, 4).unwrap();
        let token = b
            .submit_map_barrier(MapBarrierRequest::Latest, 100)
            .unwrap();
        for handle in 1..=5 {
            b.map_barriers
                .as_mut()
                .unwrap()
                .queue
                .mark_query(handle)
                .unwrap();
            b.monitor_event(monc::MonEvent::SessionLost("fixture".into()));
            assert_eq!(b.state, BootstrapState::Hunting);
            assert!(b.can_sleep());
            assert_eq!(b.next_timer(), Some(Duration::from_micros(100)));
            assert_eq!(b.poll_map_barriers_into(&mut [None]), 0);
            b.state = BootstrapState::Ready;
            assert!(!b.can_sleep());
        }
        b.map_barriers
            .as_mut()
            .unwrap()
            .queue
            .mark_query(6)
            .unwrap();
        b.monitor_event(monc::MonEvent::VersionReply {
            handle: 1,
            version: 99,
            oldest: 1,
        });
        b.monitor_event(monc::MonEvent::VersionReply {
            handle: 6,
            version: 6,
            oldest: 1,
        });
        assert_eq!(b.poll_map_barriers_into(&mut [None]), 0);
        epoch(&mut b, 6);
        b.map_barrier_progress(4, 0);
        let done = take(&mut b);
        assert_eq!(done.token, token);
        assert!(matches!(
            done.outcome,
            MapBarrierOutcome::Reached {
                target_epoch: 6,
                ..
            }
        ));
    }

    #[test]
    fn private_pool_checks_preserve_public_completions_and_recover_independently() {
        let mut b = fixture();
        enable(&mut b);
        let public = b
            .submit_map_barrier(MapBarrierRequest::Latest, 100)
            .unwrap();
        let private = b.submit_pool_check(90).unwrap();
        b.map_barriers
            .as_mut()
            .unwrap()
            .queue
            .mark_query(1)
            .unwrap();
        b.pool_checks.as_mut().unwrap().queue.mark_query(2).unwrap();
        b.monitor_event(monc::MonEvent::SessionLost("fixture".into()));
        assert!(b.can_sleep());
        assert_eq!(b.next_timer(), Some(Duration::from_micros(90)));
        assert!(b.pool_check_waiting(Some(private)));
        b.state = BootstrapState::Ready;
        b.map_barriers
            .as_mut()
            .unwrap()
            .queue
            .mark_query(3)
            .unwrap();
        b.pool_checks.as_mut().unwrap().queue.mark_query(4).unwrap();
        b.map_barrier_version(2, 99, 1);
        b.map_barrier_version(3, 5, 1);
        b.map_barrier_version(4, 6, 1);
        epoch(&mut b, 5);
        b.map_barrier_progress(4, 64);
        assert_eq!(take(&mut b).token, public);
        assert_eq!(b.poll_pool_check(private), Ok(None));
        assert_eq!(b.poll_map_barriers_into(&mut [None]), 0);
        epoch(&mut b, 6);
        b.map_barrier_progress(4, 64);
        assert_eq!(b.poll_pool_check(private).unwrap().unwrap().token, private);
        assert!(!b.pool_check_waiting(Some(private)));
        assert_eq!(b.next_timer(), None);
        b.cancel_pool_check(private);
    }
    #[test]
    fn private_pool_checks_do_not_enable_or_require_the_public_queue() {
        let mut b = fixture();
        let token = b.submit_pool_check(100).unwrap();
        assert!(b.map_barriers.is_none());
        assert_eq!(b.poll_map_barriers_into(&mut [None]), 0);
        b.cancel_pool_check(token);
        assert_eq!(b.pool_checks.as_ref().unwrap().queue.outstanding(), 0);
        assert_eq!(b.next_timer(), None);
        b.enable_compatible_map_barriers(1, 1).unwrap();
        let token = b.submit_pool_check(100).unwrap();
        b.close();
        assert!(matches!(
            b.poll_pool_check(token).unwrap().unwrap().outcome,
            MapBarrierOutcome::Failed {
                error: MapBarrierError::Closed,
                ..
            }
        ));
    }
    #[test]
    fn opt_in_timer_reply_and_verified_map_observation() {
        let mut b = fixture();
        assert_eq!(
            b.submit_map_barrier(MapBarrierRequest::Latest, 100)
                .unwrap_err()
                .reason,
            MapBarrierError::Disabled
        );
        enable(&mut b);
        assert!(b.can_sleep());
        assert_eq!(
            b.enable_map_barriers(
                MapBarrierLimits {
                    slots: 4,
                    query_attempts: 2
                },
                4
            ),
            Err(MapBarrierError::AlreadyEnabled)
        );
        let token = b
            .submit_map_barrier(MapBarrierRequest::Latest, 100)
            .unwrap();
        assert!(!b.can_sleep());
        assert_eq!(b.next_timer(), Some(Duration::from_micros(100)));
        b.map_barriers
            .as_mut()
            .unwrap()
            .queue
            .mark_query(1)
            .unwrap();
        assert!(b.can_sleep());
        b.monitor_event(monc::MonEvent::VersionReply {
            handle: 1,
            version: 6,
            oldest: 1,
        });
        assert_eq!(b.poll_map_barriers_into(&mut [None]), 0);
        assert!(b.can_sleep());
        epoch(&mut b, 6);
        assert!(!b.can_sleep());
        b.map_barrier_progress(4, 0);
        assert!(!b.can_sleep());
        let done = take(&mut b);
        assert_eq!(done.token, token);
        assert_eq!(
            done.outcome,
            MapBarrierOutcome::Reached {
                fsid: FSID,
                target_epoch: 6,
                observed_epoch: 6
            }
        );
        assert_eq!(b.next_timer(), None);
        assert!(b.can_sleep());
    }
    #[test]
    fn session_loss_and_old_failure_do_not_poison_new_query_or_extend_deadline() {
        let mut b = fixture();
        enable(&mut b);
        b.submit_map_barrier(MapBarrierRequest::Latest, 100)
            .unwrap();
        b.map_barriers
            .as_mut()
            .unwrap()
            .queue
            .mark_query(1)
            .unwrap();
        b.monitor_event(monc::MonEvent::SessionLost("fixture".into()));
        assert_eq!(b.state, BootstrapState::Hunting);
        b.state = BootstrapState::Ready;
        b.map_barriers
            .as_mut()
            .unwrap()
            .queue
            .mark_query(2)
            .unwrap();
        b.monitor_event(monc::MonEvent::VersionFailed { handle: 1 });
        b.monitor_event(monc::MonEvent::VersionReply {
            handle: 1,
            version: 9,
            oldest: 1,
        });
        assert_eq!(b.poll_map_barriers_into(&mut [None]), 0);
        assert_eq!(b.next_timer(), Some(Duration::from_micros(100)));
        b.monitor_event(monc::MonEvent::VersionReply {
            handle: 2,
            version: 4,
            oldest: 1,
        });
        assert!(matches!(
            take(&mut b).outcome,
            MapBarrierOutcome::Reached {
                target_epoch: 4,
                ..
            }
        ));
    }
    #[test]
    fn fsid_identity_and_close_fail_pending_but_preserve_completed_results() {
        for mode in 0..3 {
            let mut b = fixture();
            enable(&mut b);
            let ready = b
                .submit_map_barrier(MapBarrierRequest::Epoch(4), 100)
                .unwrap();
            b.submit_map_barrier(MapBarrierRequest::Latest, 100)
                .unwrap();
            match mode {
                0 => {
                    let mut map = b.osdmap().unwrap().clone();
                    map.fsid = Uuid([8; 16]);
                    b.monitor.as_mut().unwrap().set_osdmap(map);
                    b.map_barrier_progress(4, 0);
                    assert_eq!(
                        b.state,
                        BootstrapState::Failed(crate::BootstrapError::FsidMismatch)
                    );
                }
                1 => b.authenticated(10, cephx::modes::CON_MODE_CRC, cephx::modes::AUTH_CEPHX),
                _ => b.close(),
            }
            let done = take(&mut b);
            assert_eq!(done.token, ready);
            assert!(matches!(done.outcome, MapBarrierOutcome::Reached { .. }));
            assert!(matches!(
                take(&mut b).outcome,
                MapBarrierOutcome::Failed { .. }
            ));
        }
    }
    #[test]
    fn deadline_equality_precedes_map_and_reply_and_cancel_is_final() {
        let mut b = fixture();
        enable(&mut b);
        let token = b.submit_map_barrier(MapBarrierRequest::Latest, 10).unwrap();
        b.map_barriers
            .as_mut()
            .unwrap()
            .queue
            .mark_query(1)
            .unwrap();
        b.last_now = Duration::from_micros(10);
        b.monitor_event(monc::MonEvent::VersionReply {
            handle: 1,
            version: 4,
            oldest: 1,
        });
        b.map_barrier_progress(4, 0);
        assert!(matches!(
            take(&mut b).outcome,
            MapBarrierOutcome::Failed {
                error: MapBarrierError::Deadline,
                ..
            }
        ));
        assert_eq!(b.cancel_map_barrier(token), Err(MapBarrierError::Stale));
        let token = b
            .submit_map_barrier(MapBarrierRequest::Latest, 100)
            .unwrap();
        b.map_barriers
            .as_mut()
            .unwrap()
            .queue
            .mark_query(2)
            .unwrap();
        b.cancel_map_barrier(token).unwrap();
        b.monitor_event(monc::MonEvent::VersionReply {
            handle: 2,
            version: 4,
            oldest: 1,
        });
        assert!(matches!(
            take(&mut b).outcome,
            MapBarrierOutcome::Failed {
                error: MapBarrierError::Cancelled,
                ..
            }
        ));
    }
    #[test]
    fn bootstrap_rejection_aborts_both_control_owners_without_replacing_results() {
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
        enable(&mut b);
        b.enable_snapshots(
            crate::SnapshotLimits {
                slots: 1,
                bytes: 64,
                response_bytes: 16,
            },
            1,
        )
        .unwrap();
        let barrier = b
            .submit_map_barrier(MapBarrierRequest::Latest, 100)
            .unwrap();
        let snapshot = b
            .submit_snapshot(
                crate::SnapshotRequest {
                    pool: 7,
                    operation: crate::SnapshotOperation::Allocate,
                },
                100,
            )
            .unwrap();
        b.monitor_event(monc::MonEvent::AuthFailed("fixture rejection".into()));
        assert_eq!(
            b.state,
            BootstrapState::Failed(crate::BootstrapError::AuthRejected)
        );
        assert_eq!(
            take(&mut b),
            MapBarrierCompletion {
                token: barrier,
                request: MapBarrierRequest::Latest,
                outcome: MapBarrierOutcome::Failed {
                    error: MapBarrierError::Bootstrap(crate::BootstrapError::AuthRejected),
                    target_epoch: None
                }
            }
        );
        let mut out = [None];
        assert_eq!(b.poll_snapshots_into(&mut out), 1);
        let done = out[0].take().unwrap();
        assert_eq!(done.token, snapshot);
        assert!(matches!(
            done.outcome,
            crate::SnapshotOutcome::Failed {
                error: crate::SnapshotQueueError::Bootstrap(crate::BootstrapError::AuthRejected),
                possibly_sent: false,
                ..
            }
        ));
    }
}
