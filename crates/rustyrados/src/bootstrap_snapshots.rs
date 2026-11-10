// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::{Bootstrap, BootstrapError, BootstrapState};
use crate::{
    RejectedSnapshot, SnapshotCompletion, SnapshotLimits, SnapshotQueue, SnapshotQueueError,
    SnapshotRequest, SnapshotToken,
};
use monc::MonSendError;

pub(super) struct SnapshotControl {
    pub(super) queue: SnapshotQueue,
    pub(super) work: usize,
}
impl Bootstrap {
    /// Opt in once after authenticated readiness; completion-held credit is never replaced.
    pub fn enable_snapshots(
        &mut self,
        limits: SnapshotLimits,
        work: usize,
    ) -> Result<(), SnapshotQueueError> {
        self.enable_snapshot_queue(limits, work, SnapshotQueue::new)
    }
    /// Like `enable_snapshots`, but `limits.bytes` is a target: a sole oversized request is admitted.
    pub fn enable_compatible_snapshots(
        &mut self,
        limits: SnapshotLimits,
        work: usize,
    ) -> Result<(), SnapshotQueueError> {
        self.enable_snapshot_queue(limits, work, SnapshotQueue::new_compatible)
    }
    fn enable_snapshot_queue(
        &mut self,
        limits: SnapshotLimits,
        work: usize,
        build: fn(denc::types::Uuid, SnapshotLimits) -> Result<SnapshotQueue, SnapshotQueueError>,
    ) -> Result<(), SnapshotQueueError> {
        if self.snapshots.is_some() {
            return Err(SnapshotQueueError::AlreadyEnabled);
        }
        if work == 0 || work > 4096 {
            return Err(SnapshotQueueError::Limits);
        }
        if self.state != BootstrapState::Ready {
            return Err(SnapshotQueueError::NotReady);
        }
        let mut queue = build(self.fsid.ok_or(SnapshotQueueError::NotReady)?, limits)?;
        queue.progress(self.control_now(), self.snapshot_epoch(), 0)?;
        self.snapshots = Some(SnapshotControl { queue, work });
        Ok(())
    }
    /// Admit self-managed control work; the reactor performs its single monitor handoff.
    pub fn submit_snapshot(
        &mut self,
        request: SnapshotRequest,
        deadline_us: u64,
    ) -> Result<SnapshotToken, RejectedSnapshot> {
        let reject = |reason| RejectedSnapshot { reason, request };
        self.snapshot_admission(request.pool).map_err(reject)?;
        let now = self.control_now();
        let epoch = self.snapshot_epoch();
        let queue = &mut self.snapshots.as_mut().unwrap().queue;
        queue.progress(now, epoch, 0).map_err(reject)?;
        queue.submit(request, deadline_us)
    }
    pub fn submit_named_snapshot(
        &mut self,
        request: crate::NamedSnapshotRequest,
        deadline_us: u64,
    ) -> Result<SnapshotToken, crate::RejectedNamedSnapshot> {
        if let Err(reason) = self.snapshot_admission(request.pool) {
            return Err(crate::RejectedNamedSnapshot { reason, request });
        }
        let now = self.control_now();
        let epoch = self.snapshot_epoch();
        let queue = &mut self.snapshots.as_mut().unwrap().queue;
        if let Err(reason) = queue.progress(now, epoch, 0) {
            return Err(crate::RejectedNamedSnapshot { reason, request });
        }
        queue.submit_named(request, deadline_us)
    }
    /// Admit pool administration on the existing single-handoff pool-operation owner.
    pub fn submit_pool_admin(
        &mut self,
        request: crate::PoolAdminRequest,
        deadline_us: u64,
    ) -> Result<SnapshotToken, crate::RejectedPoolAdmin> {
        let validation = (|| {
            if self.snapshots.is_none() {
                return Err(SnapshotQueueError::Disabled);
            }
            if self.state != BootstrapState::Ready {
                return Err(SnapshotQueueError::NotReady);
            }
            let map = self.osdmap().ok_or(SnapshotQueueError::NotReady)?;
            match &request {
                crate::PoolAdminRequest::Create { name, .. } => {
                    if map.pool_id_by_name_bytes(name).is_some() {
                        return Err(SnapshotQueueError::PoolExists);
                    }
                }
                crate::PoolAdminRequest::Delete { pool } => {
                    if *pool < 0 || *pool > u32::MAX as i64 {
                        return Err(SnapshotQueueError::InvalidRequest);
                    }
                    if map.pool(*pool).is_none() {
                        return Err(SnapshotQueueError::NoPool);
                    }
                }
            }
            Ok(())
        })();
        if let Err(reason) = validation {
            return Err(crate::RejectedPoolAdmin { reason, request });
        }
        let now = self.control_now();
        let epoch = self.snapshot_epoch();
        let queue = &mut self.snapshots.as_mut().unwrap().queue;
        if let Err(reason) = queue.progress(now, epoch, 0) {
            return Err(crate::RejectedPoolAdmin { reason, request });
        }
        queue.submit_pool_admin(request, deadline_us)
    }
    /// Current validated map; no implicit freshness wait or write capability required.
    pub fn named_snapshots(
        &self,
        pool: i64,
    ) -> Result<crate::NamedSnapshots<'_>, SnapshotQueueError> {
        let mon = self.monitor.as_ref().ok_or(SnapshotQueueError::NotReady)?;
        let map = mon.osdmap().ok_or(SnapshotQueueError::NotReady)?;
        if self.identity.is_none() || map.epoch == 0 {
            return Err(SnapshotQueueError::NotReady);
        }
        if self.fsid != Some(map.fsid) || self.fsid != Some(mon.monmap().fsid) {
            return Err(SnapshotQueueError::Fsid);
        }
        self.snapshot_pool(pool)?;
        crate::NamedSnapshots::from_pool(pool, map.epoch, &map.pool(pool).unwrap().snaps)
    }
    fn snapshot_admission(&self, pool: i64) -> Result<(), SnapshotQueueError> {
        if self.snapshots.is_none() {
            return Err(SnapshotQueueError::Disabled);
        }
        if self.state != BootstrapState::Ready {
            return Err(SnapshotQueueError::NotReady);
        }
        if pool < 0 || pool > u32::MAX as i64 {
            return Err(SnapshotQueueError::InvalidRequest);
        }
        self.snapshot_pool(pool)
    }
    pub fn snapshot_error(&self) -> Option<SnapshotQueueError> {
        self.snapshots.as_ref().and_then(|s| s.queue.error())
    }
    pub fn cancel_snapshot(&mut self, token: SnapshotToken) -> Result<(), SnapshotQueueError> {
        self.snapshots
            .as_mut()
            .ok_or(SnapshotQueueError::Disabled)?
            .queue
            .cancel(token)
    }
    pub fn poll_snapshots_into(&mut self, out: &mut [Option<SnapshotCompletion>]) -> usize {
        self.snapshots
            .as_mut()
            .map_or(0, |s| s.queue.poll_into(out))
    }
    fn snapshot_pool(&self, pool: i64) -> Result<(), SnapshotQueueError> {
        self.osdmap()
            .and_then(|map| map.pool(pool))
            .ok_or(SnapshotQueueError::NoPool)
            .map(|_| ())
    }
    fn snapshot_epoch(&self) -> u32 {
        self.osdmap().map_or(0, |map| map.epoch)
    }
    pub(super) fn snapshot_validate_maps(&mut self) -> bool {
        if self.snapshots.is_none() || self.monitor.is_none() {
            return true;
        }
        if self.map_barrier_map() == Err(crate::MapBarrierError::Fsid) {
            self.fail(BootstrapError::FsidMismatch);
            return false;
        }
        true
    }
    pub(super) fn snapshot_progress(&mut self, work: usize) {
        if self.monitor.is_none() {
            return;
        }
        let now = self.control_now();
        let epoch = self.snapshot_epoch();
        if let Some(s) = &mut self.snapshots {
            let _ = s.queue.progress(now, epoch, work);
        }
    }
    pub(super) fn snapshot_reply(&mut self, tid: u64, reply: messages::MPoolOpReply) {
        let now = self.control_now();
        let epoch = self.snapshot_epoch();
        if let Some(s) = &mut self.snapshots
            && s.queue.on_reply(tid, reply, now, epoch) == Err(SnapshotQueueError::Fsid)
        {
            self.fail(BootstrapError::FsidMismatch);
        }
    }
    pub(super) fn snapshot_dispatch(&mut self, work: usize) {
        if self
            .snapshots
            .as_ref()
            .is_none_or(|s| s.queue.outstanding() == 0)
        {
            return;
        }
        for _ in 0..work {
            if self.state != BootstrapState::Ready {
                break;
            }
            let Some(s) = &mut self.snapshots else { break };
            let Some(token) = s.queue.next_unsent() else {
                continue;
            };
            let Ok(message) = s.queue.prepare(token) else {
                continue;
            };
            let validation = match message.operation {
                messages::PoolOperation::CreatePool => {
                    if self
                        .osdmap()
                        .is_some_and(|map| map.pool_id_by_name_bytes(&message.name).is_some())
                    {
                        Err(SnapshotQueueError::PoolExists)
                    } else {
                        Ok(())
                    }
                }
                messages::PoolOperation::DeletePool => {
                    if self
                        .osdmap()
                        .and_then(|map| map.pool(i64::from(message.pool)))
                        .is_some()
                    {
                        Ok(())
                    } else {
                        Err(SnapshotQueueError::NoPool)
                    }
                }
                _ => self.snapshot_pool(i64::from(message.pool)),
            };
            if let Err(error) = validation {
                let _ = self
                    .snapshots
                    .as_mut()
                    .unwrap()
                    .queue
                    .reject_unsent(token, error);
                continue;
            }
            let s = self.snapshots.as_mut().unwrap();
            let result = self
                .monitor
                .as_mut()
                .map_or(Err(MonSendError::NoSession), |mon| {
                    mon.try_send_message(message)
                });
            match result {
                Ok(tid) => {
                    let _ = s.queue.mark_sent(token, tid);
                }
                Err(MonSendError::NoSession) => break,
                Err(error) => {
                    s.queue.abort(if error == MonSendError::IdentityExhausted {
                        SnapshotQueueError::Identity
                    } else {
                        SnapshotQueueError::Transport
                    });
                    break;
                }
            }
            // monc may enqueue a loss while handing to msgr2. Mark before observing it.
            self.drain_monitor_events();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BootstrapConfig, MessengerMode, SnapshotOperation, SnapshotOutcome, SnapshotReply,
    };
    use denc::types::Uuid;
    use monc::{MonClient, MonEvent};
    use osdmap::{OsdMap, PgPool};
    use std::{sync::Arc, time::Duration};
    const FSID: Uuid = Uuid([7; 16]);
    #[test]
    fn pool_admin_does_not_require_pool_zero_and_ec_delete_is_not_snapshot_work() {
        let mut b = enabled();
        let created = b
            .submit_pool_admin(
                crate::PoolAdminRequest::Create {
                    name: b"new".to_vec(),
                    crush_rule: 255,
                },
                100,
            )
            .unwrap();
        assert_eq!(
            b.snapshots
                .as_mut()
                .unwrap()
                .queue
                .prepare(created)
                .unwrap()
                .pool,
            0
        );
        let mut map = b.osdmap().unwrap().clone();
        map.pools.get_mut(&7).unwrap().ptype = 3;
        b.monitor.as_mut().unwrap().set_osdmap(map);
        let snapshot = b.submit_snapshot(request(), 100).unwrap();
        b.cancel_snapshot(snapshot).unwrap();
        assert_eq!(take(&mut b).token, snapshot);
        assert!(
            b.submit_pool_admin(crate::PoolAdminRequest::Delete { pool: 7 }, 100)
                .is_ok()
        );
        assert_eq!(
            b.submit_pool_admin(crate::PoolAdminRequest::Delete { pool: 8 }, 100)
                .unwrap_err()
                .reason,
            SnapshotQueueError::NoPool
        );
    }
    #[test]
    fn pool_delete_is_revalidated_before_single_monitor_handoff() {
        let mut b = enabled();
        let token = b
            .submit_pool_admin(crate::PoolAdminRequest::Delete { pool: 7 }, 100)
            .unwrap();
        let mut map = b.osdmap().unwrap().clone();
        map.pools.remove(&7);
        map.epoch += 1;
        b.monitor.as_mut().unwrap().set_osdmap(map);
        b.snapshot_dispatch(1);
        let done = take(&mut b);
        assert_eq!(done.token, token);
        assert!(matches!(
            done.outcome,
            SnapshotOutcome::Failed {
                error: SnapshotQueueError::NoPool,
                possibly_sent: false,
                ..
            }
        ));
    }
    fn limits() -> SnapshotLimits {
        SnapshotLimits {
            slots: 4,
            bytes: 64,
            response_bytes: 16,
        }
    }
    fn request() -> SnapshotRequest {
        SnapshotRequest {
            pool: 7,
            operation: SnapshotOperation::Allocate,
        }
    }
    fn fixture() -> Bootstrap {
        let mut b = Bootstrap::new(BootstrapConfig {
            entity: "client.snapshot".into(),
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
        let mut cfg = monc::Config::new("client.snapshot", None);
        let mut monmap =
            monc::monmap_from_addrs(&monc::parse_mon_host("v2:127.0.0.1:3300").unwrap());
        monmap.fsid = FSID;
        cfg.initial_monmap = Some(monmap);
        let mut mon = MonClient::new(cfg);
        let mut map = OsdMap::default();
        map.fsid = FSID;
        map.epoch = 4;
        map.pools.insert(
            7,
            PgPool {
                ptype: 1,
                size: 3,
                ..Default::default()
            },
        );
        mon.set_osdmap(map);
        b.monitor = Some(mon);
        // Composition fixture only: no claim of exercising CephX authentication here.
        b.state = BootstrapState::Ready;
        b.identity = Some(9);
        b
    }
    fn enabled() -> Bootstrap {
        let mut b = fixture();
        b.enable_snapshots(limits(), 1).unwrap();
        b
    }
    fn set_epoch(b: &mut Bootstrap, epoch: u32) {
        let mut map = b.osdmap().unwrap().clone();
        map.epoch = epoch;
        b.monitor.as_mut().unwrap().set_osdmap(map);
    }
    fn handed_off(b: &mut Bootstrap, tid: u64, deadline: u64) -> SnapshotToken {
        let token = b.submit_snapshot(request(), deadline).unwrap();
        b.snapshots
            .as_mut()
            .unwrap()
            .queue
            .mark_sent(token, tid)
            .unwrap();
        token
    }
    fn reply(b: &mut Bootstrap, tid: u64, id: u64, epoch: u32) {
        b.monitor_event(MonEvent::Message {
            tid,
            msg: Box::new(
                messages::MPoolOpReply {
                    version: 91,
                    fsid: FSID,
                    result: 0,
                    epoch,
                    response_data: id.to_le_bytes().to_vec(),
                }
                .into(),
            ),
        });
    }
    fn take(b: &mut Bootstrap) -> crate::SnapshotCompletion {
        let mut out = [None];
        assert_eq!(b.poll_snapshots_into(&mut out), 1);
        out[0].take().unwrap()
    }
    #[test]
    fn all_control_owners_can_idle_without_hiding_snapshot_handoff_map_or_result_work() {
        let mut b = enabled();
        b.enable_map_barriers(
            crate::MapBarrierLimits {
                slots: 2,
                query_attempts: 2,
            },
            1,
        )
        .unwrap();
        b.enable_blocklist(crate::BlocklistControlLimits {
            queue: crate::BlocklistLimits {
                slots: 2,
                reply_bytes: 64,
            },
            query_attempts: 2,
            work: 1,
        })
        .unwrap();
        assert!(b.can_sleep());
        assert!(b.can_sleep_with_blocked_output(&|_| true));
        let token = b.submit_snapshot(request(), 100).unwrap();
        assert!(!b.can_sleep());
        assert!(!b.can_sleep_with_blocked_output(&|_| true));
        b.snapshots
            .as_mut()
            .unwrap()
            .queue
            .mark_sent(token, 1)
            .unwrap();
        assert!(b.can_sleep());
        assert!(b.can_sleep_with_blocked_output(&|_| true));
        reply(&mut b, 1, 9, 6);
        assert!(b.can_sleep());
        assert!(b.can_sleep_with_blocked_output(&|_| true));
        set_epoch(&mut b, 6);
        assert!(!b.can_sleep());
        assert!(!b.can_sleep_with_blocked_output(&|_| true));
        b.snapshot_progress(0);
        assert!(!b.can_sleep());
        assert!(!b.can_sleep_with_blocked_output(&|_| true));
        b.snapshot_progress(1);
        assert!(!b.can_sleep());
        assert!(!b.can_sleep_with_blocked_output(&|_| true));
        assert_eq!(take(&mut b).token, token);
        assert!(b.can_sleep());
        assert!(b.can_sleep_with_blocked_output(&|_| true));
        let mut invalid = b.osdmap().unwrap().clone();
        invalid.fsid = Uuid([8; 16]);
        b.monitor.as_mut().unwrap().set_osdmap(invalid);
        assert!(!b.can_sleep());
        assert!(!b.can_sleep_with_blocked_output(&|_| true));
    }
    #[test]
    fn compatible_enable_admits_sole_oversize_named_request_but_strict_rejects() {
        let named = |compatible: bool| {
            let mut b = fixture();
            if compatible {
                b.enable_compatible_snapshots(limits(), 1).unwrap();
            } else {
                b.enable_snapshots(limits(), 1).unwrap();
            }
            let mut name = Vec::with_capacity(128);
            name.extend_from_slice(b"snap");
            let request = crate::NamedSnapshotRequest {
                pool: 7,
                operation: crate::NamedSnapshotOperation::Create,
                name,
            };
            (b, request)
        };
        let (mut strict, named_request) = named(false);
        let rejected = strict
            .submit_named_snapshot(named_request, 100)
            .unwrap_err();
        assert_eq!(rejected.reason, SnapshotQueueError::NoCredit);
        assert_eq!(rejected.request.name.capacity(), 128);
        let (mut b, named_request) = named(true);
        let token = b.submit_named_snapshot(named_request, 100).unwrap();
        let second = b.submit_snapshot(request(), 100).unwrap_err();
        assert_eq!(second.reason, SnapshotQueueError::NoCredit);
        b.cancel_snapshot(token).unwrap();
        assert_eq!(
            b.enable_compatible_snapshots(limits(), 1),
            Err(SnapshotQueueError::AlreadyEnabled)
        );
        assert_eq!(take(&mut b).token, token);
        b.submit_snapshot(request(), 100).unwrap();
    }
    #[test]
    fn opt_in_is_bounded_once_and_does_not_replace_held_completions() {
        let mut b = fixture();
        assert_eq!(
            b.submit_snapshot(request(), 100).unwrap_err().reason,
            SnapshotQueueError::Disabled
        );
        assert_eq!(
            b.enable_snapshots(limits(), 0),
            Err(SnapshotQueueError::Limits)
        );
        assert_eq!(
            b.enable_snapshots(limits(), 4097),
            Err(SnapshotQueueError::Limits)
        );
        b.state = BootstrapState::Hunting;
        assert_eq!(
            b.enable_snapshots(limits(), 1),
            Err(SnapshotQueueError::NotReady)
        );
        b.state = BootstrapState::Ready;
        b.enable_snapshots(limits(), 1).unwrap();
        let token = b.submit_snapshot(request(), 100).unwrap();
        b.cancel_snapshot(token).unwrap();
        assert_eq!(
            b.enable_snapshots(limits(), 1),
            Err(SnapshotQueueError::AlreadyEnabled)
        );
        assert_eq!(take(&mut b).token, token);
    }
    #[test]
    fn admission_accepts_ec_and_tier_metadata_and_rejects_missing_pools() {
        let mut b = enabled();
        for kind in 0..6 {
            let mut map = b.osdmap().unwrap().clone();
            let pool = map.pools.get_mut(&7).unwrap();
            match kind {
                0 => pool.ptype = 3,
                1 => pool.tier_of = 8,
                2 => {
                    pool.tiers.insert(8);
                }
                3 => pool.cache_mode = 1,
                4 => pool.read_tier = 8,
                _ => pool.write_tier = 8,
            }
            b.monitor.as_mut().unwrap().set_osdmap(map);
            let token = b.submit_snapshot(request(), 100).unwrap();
            assert_eq!(
                b.snapshots
                    .as_mut()
                    .unwrap()
                    .queue
                    .prepare(token)
                    .unwrap()
                    .pool,
                7
            );
            b.cancel_snapshot(token).unwrap();
            assert_eq!(take(&mut b).token, token);
            let mut map = b.osdmap().unwrap().clone();
            map.pools.insert(
                7,
                PgPool {
                    ptype: 1,
                    ..Default::default()
                },
            );
            b.monitor.as_mut().unwrap().set_osdmap(map);
        }
        assert_eq!(
            b.submit_snapshot(
                SnapshotRequest {
                    pool: 9,
                    ..request()
                },
                100
            )
            .unwrap_err()
            .reason,
            SnapshotQueueError::NoPool
        );
        assert_eq!(
            b.submit_snapshot(
                SnapshotRequest {
                    pool: i64::MAX,
                    ..request()
                },
                100
            )
            .unwrap_err()
            .reason,
            SnapshotQueueError::InvalidRequest
        );
        assert_eq!(b.snapshots.as_ref().unwrap().queue.outstanding(), 0);
    }
    #[test]
    fn latest_held_map_wins_over_historical_map_event_and_unknown_reply_is_passive() {
        let mut b = enabled();
        let token = handed_off(&mut b, 19, 100);
        b.monitor_event(MonEvent::Message {
            tid: 0,
            msg: Box::new(
                messages::MPoolOpReply {
                    version: u64::MAX,
                    fsid: Uuid([8; 16]),
                    result: 0,
                    epoch: 99,
                    response_data: vec![0; 99],
                }
                .into(),
            ),
        });
        assert_eq!(b.snapshot_error(), None);
        reply(&mut b, 19, 42, 5);
        assert_eq!(b.poll_snapshots_into(&mut [None]), 0);
        set_epoch(&mut b, 6);
        let mut old = OsdMap::default();
        old.fsid = FSID;
        old.epoch = 3;
        b.monitor_event(MonEvent::OsdMap {
            epoch: 3,
            map: Arc::new(old),
            msg: Box::new(messages::MOSDMap::default()),
        });
        b.advance();
        let done = take(&mut b);
        assert_eq!(done.token, token);
        assert!(matches!(
            done.outcome,
            SnapshotOutcome::Completed(SnapshotReply {
                snapshot_id: Some(42),
                epoch: 5,
                ..
            })
        ));
        assert_eq!(b.snapshot_error(), None);
    }
    #[test]
    fn loss_retains_verified_id_and_never_replays_handed_off_unknown_allocation() {
        let mut b = enabled();
        let known = handed_off(&mut b, 11, 100);
        reply(&mut b, 11, 42, 5);
        let unknown = handed_off(&mut b, 12, 100);
        let unsent = b.submit_snapshot(request(), 100).unwrap();
        b.last_now = Duration::from_micros(2);
        b.monitor_event(MonEvent::SessionLost("fixture".into()));
        let done = take(&mut b);
        assert_eq!(done.token, unknown);
        assert!(matches!(
            done.outcome,
            SnapshotOutcome::Failed {
                error: SnapshotQueueError::MonitorLost,
                possibly_sent: true,
                reply: None
            }
        ));
        assert_eq!(
            b.snapshots
                .as_mut()
                .unwrap()
                .queue
                .prepare(known)
                .unwrap_err(),
            SnapshotQueueError::AlreadySent
        );
        assert!(b.snapshots.as_mut().unwrap().queue.prepare(unsent).is_ok());
        assert_eq!(b.next_timer(), Some(Duration::from_micros(100)));
        set_epoch(&mut b, 5);
        b.snapshot_progress(4);
        assert_eq!(take(&mut b).token, known);
    }
    #[test]
    fn deadline_precedes_reply_at_equality_and_known_id_survives_clock_failure() {
        let mut b = enabled();
        let token = handed_off(&mut b, 11, 10);
        reply(&mut b, 11, 42, 5);
        b.last_now = Duration::from_micros(10);
        set_epoch(&mut b, 5);
        b.snapshot_progress(4);
        assert!(matches!(
            take(&mut b).outcome,
            SnapshotOutcome::Deadline {
                possibly_sent: true,
                reply: Some(SnapshotReply {
                    snapshot_id: Some(42),
                    ..
                })
            }
        ));
        assert_eq!(b.cancel_snapshot(token), Err(SnapshotQueueError::Stale));
        let token = handed_off(&mut b, 12, 100);
        reply(&mut b, 12, 43, 6);
        b.on_bytes(999, &[], Duration::from_micros(9));
        let done = take(&mut b);
        assert_eq!(done.token, token);
        assert!(matches!(
            done.outcome,
            SnapshotOutcome::Failed {
                error: SnapshotQueueError::Bootstrap(BootstrapError::ClockRegression),
                reply: Some(SnapshotReply {
                    snapshot_id: Some(43),
                    ..
                }),
                ..
            }
        ));
        assert_eq!(b.next_timer(), None);
    }
    #[test]
    fn close_and_identity_rejection_preserve_known_id_and_drain_after_monitor_drop() {
        for close in [true, false] {
            let mut b = enabled();
            let token = handed_off(&mut b, 11, 100);
            reply(&mut b, 11, 42, 5);
            if close {
                b.close();
            } else {
                b.authenticated(10, cephx::modes::CON_MODE_CRC, cephx::modes::AUTH_CEPHX);
            }
            assert!(b.monitor.is_none());
            let done = take(&mut b);
            assert_eq!(done.token, token);
            match done.outcome {
                SnapshotOutcome::Canceled {
                    reply: Some(r),
                    possibly_sent: true,
                } if close => assert_eq!(r.snapshot_id, Some(42)),
                SnapshotOutcome::Failed {
                    error: SnapshotQueueError::Bootstrap(BootstrapError::IdentityLost),
                    reply: Some(r),
                    possibly_sent: true,
                } if !close => assert_eq!(r.snapshot_id, Some(42)),
                other => panic!("unexpected outcome {other:?}"),
            }
        }
    }
    #[test]
    fn wrong_held_cluster_fails_before_map_can_complete_known_id() {
        let mut b = enabled();
        handed_off(&mut b, 11, 100);
        reply(&mut b, 11, 42, 5);
        let mut map = b.osdmap().unwrap().clone();
        map.fsid = Uuid([8; 16]);
        map.epoch = 5;
        b.monitor.as_mut().unwrap().set_osdmap(map);
        b.advance();
        assert_eq!(
            b.state,
            BootstrapState::Failed(BootstrapError::FsidMismatch)
        );
        assert!(matches!(
            take(&mut b).outcome,
            SnapshotOutcome::Failed {
                error: SnapshotQueueError::Bootstrap(BootstrapError::FsidMismatch),
                reply: Some(SnapshotReply {
                    snapshot_id: Some(42),
                    ..
                }),
                ..
            }
        ));
    }
    #[test]
    fn queued_work_is_revalidated_before_handoff_after_pool_change() {
        let mut b = enabled();
        let token = b.submit_snapshot(request(), 100).unwrap();
        let mut map = b.osdmap().unwrap().clone();
        map.pools.remove(&7);
        b.monitor.as_mut().unwrap().set_osdmap(map);
        b.snapshot_dispatch(1);
        let done = take(&mut b);
        assert_eq!(done.token, token);
        assert!(matches!(
            done.outcome,
            SnapshotOutcome::Failed {
                error: SnapshotQueueError::NoPool,
                possibly_sent: false,
                reply: None
            }
        ));
        assert_eq!(b.snapshot_error(), None);
    }
    #[test]
    fn no_session_leaves_work_unsent_and_progress_obeys_slot_budget() {
        let mut b = enabled();
        let tokens: Vec<_> = (0..4)
            .map(|_| b.submit_snapshot(request(), 10).unwrap())
            .collect();
        b.snapshot_dispatch(1);
        assert!(
            b.snapshots
                .as_mut()
                .unwrap()
                .queue
                .prepare(tokens[0])
                .is_ok()
        );
        b.last_now = Duration::from_micros(10);
        b.snapshot_progress(1);
        assert!(matches!(
            take(&mut b).outcome,
            SnapshotOutcome::Deadline {
                possibly_sent: false,
                ..
            }
        ));
        assert_eq!(b.poll_snapshots_into(&mut [None]), 0);
        assert_eq!(b.next_timer(), Some(Duration::from_micros(10)));
        b.snapshot_progress(3);
        let mut out = [None, None, None];
        assert_eq!(b.poll_snapshots_into(&mut out), 3);
        assert_eq!(b.next_timer(), None);
    }
    #[test]
    fn ec_snapshot_controls_preserve_remote_results_ids_and_epoch_barriers() {
        use crate::{NamedSnapshotOperation, NamedSnapshotRequest};
        for operation in 0..4 {
            for result in [0, -1, -22, -95] {
                let mut b = enabled();
                let mut map = b.osdmap().unwrap().clone();
                map.pools.get_mut(&7).unwrap().ptype = osdmap::pool::TYPE_ERASURE;
                b.monitor.as_mut().unwrap().set_osdmap(map);
                let token = match operation {
                    0 => b.submit_snapshot(request(), 100).unwrap(),
                    1 => b
                        .submit_snapshot(
                            SnapshotRequest {
                                pool: 7,
                                operation: SnapshotOperation::Remove { snapid: 42 },
                            },
                            100,
                        )
                        .unwrap(),
                    _ => b
                        .submit_named_snapshot(
                            NamedSnapshotRequest {
                                pool: 7,
                                operation: if operation == 2 {
                                    NamedSnapshotOperation::Create
                                } else {
                                    NamedSnapshotOperation::Remove
                                },
                                name: b"ec-snapshot".to_vec(),
                            },
                            100,
                        )
                        .unwrap(),
                };
                let queue = &mut b.snapshots.as_mut().unwrap().queue;
                let wire = queue.prepare(token).unwrap();
                assert_eq!(wire.pool, 7);
                queue.mark_sent(token, 11).unwrap();
                b.monitor_event(MonEvent::Message {
                    tid: 11,
                    msg: Box::new(
                        messages::MPoolOpReply {
                            version: 91,
                            fsid: FSID,
                            result,
                            epoch: 5,
                            response_data: if result == 0 && operation == 0 {
                                42u64.to_le_bytes().to_vec()
                            } else {
                                vec![]
                            },
                        }
                        .into(),
                    ),
                });
                assert_eq!(b.poll_snapshots_into(&mut [None]), 0);
                set_epoch(&mut b, 5);
                b.snapshot_progress(4);
                let done = take(&mut b);
                assert_eq!(done.token, token);
                let SnapshotOutcome::Completed(reply) = done.outcome else {
                    panic!("expected monitor completion")
                };
                assert_eq!(reply.result, result);
                assert_eq!(
                    reply.snapshot_id,
                    if result == 0 && operation == 0 {
                        Some(42)
                    } else {
                        None
                    }
                );
                assert_eq!(b.snapshot_error(), None);
            }
        }
    }
    #[test]
    fn named_metadata_is_available_without_opt_in_and_named_admission_keeps_owned_names() {
        use crate::{NamedSnapshotOperation, NamedSnapshotRequest};
        let mut b = fixture();
        let mut map = b.osdmap().unwrap().clone();
        map.pools.get_mut(&7).unwrap().ptype = osdmap::pool::TYPE_ERASURE;
        map.pools.get_mut(&7).unwrap().snaps.insert(
            9,
            osdmap::pool::PoolSnapInfo {
                snapid: 9,
                name: vec![255, 65],
                stamp: denc::types::UTime::new(123, 456),
            },
        );
        b.monitor.as_mut().unwrap().set_osdmap(map);
        let view = b.named_snapshots(7).unwrap();
        assert_eq!(view.map_epoch, 4);
        assert_eq!(view.by_name(&[255, 65]).unwrap().id, 9);
        assert!(matches!(
            b.named_snapshots(8),
            Err(SnapshotQueueError::NoPool)
        ));
        let mut name = Vec::with_capacity(8);
        name.extend_from_slice(&[255, 65]);
        let ptr = name.as_ptr();
        let request = NamedSnapshotRequest {
            pool: 7,
            operation: NamedSnapshotOperation::Create,
            name,
        };
        let rejected = b.submit_named_snapshot(request, 100).unwrap_err();
        assert_eq!(rejected.reason, SnapshotQueueError::Disabled);
        assert_eq!(rejected.request.name.as_ptr(), ptr);
        b.enable_snapshots(limits(), 1).unwrap();
        let token = b.submit_named_snapshot(rejected.request, 100).unwrap();
        let queue = &mut b.snapshots.as_mut().unwrap().queue;
        assert_eq!(queue.prepare(token).unwrap().name, [255, 65]);
        queue.mark_sent(token, 11).unwrap();
        b.monitor_event(MonEvent::Message {
            tid: 11,
            msg: Box::new(
                messages::MPoolOpReply {
                    version: 91,
                    fsid: FSID,
                    result: 0,
                    epoch: 4,
                    response_data: vec![],
                }
                .into(),
            ),
        });
        assert!(matches!(
            take(&mut b).outcome,
            SnapshotOutcome::Completed(SnapshotReply {
                snapshot_id: None,
                ..
            })
        ));
        b.state = BootstrapState::Hunting;
        assert_eq!(
            b.named_snapshots(7).unwrap().by_id(9).unwrap().name,
            [255, 65]
        );
        b.close();
        assert!(matches!(
            b.named_snapshots(7),
            Err(SnapshotQueueError::NotReady)
        ));
    }
    #[test]
    fn metadata_never_publishes_unverified_identity_or_foreign_cluster() {
        let mut b = fixture();
        b.identity = None;
        assert!(matches!(
            b.named_snapshots(7),
            Err(SnapshotQueueError::NotReady)
        ));
        b.identity = Some(9);
        let mut map = b.osdmap().unwrap().clone();
        map.fsid = Uuid([8; 16]);
        b.monitor.as_mut().unwrap().set_osdmap(map);
        assert!(matches!(
            b.named_snapshots(7),
            Err(SnapshotQueueError::Fsid)
        ));
    }
}
