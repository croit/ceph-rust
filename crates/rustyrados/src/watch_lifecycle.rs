// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Transport-neutral managed-watch coordinator. Runtime composition remains required.
use crate::{ControlOperation, WatchHandle};

use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_DOMAIN: AtomicU64 = AtomicU64::new(1);

use crate::time::{self, MAX_TIME_US as MAX_TIME, NO_DEADLINE};

#[derive(Clone, Copy, Debug)]
pub struct WatchTiming {
    /// Zero selects the OSD default; its lease length is unknown locally.
    pub server_timeout_seconds: u32,
    pub ping_interval_us: u64,
    /// Per-operation budget of each WATCH/RECONNECT (`rados_osd_op_timeout`), armed when the operation is
    /// created for a routable target; `time::NO_DEADLINE` enrolls unlimited work. PINGs have no deadline and
    /// there is no total-outage limit (watch-timing-config-contract s1/s4): an established watch ends only on
    /// an OSD error reply, a server disconnect or an expired RECONNECT operation.
    pub operation_timeout_us: u64,
}
impl Default for WatchTiming {
    fn default() -> Self {
        Self {
            server_timeout_seconds: 30,
            ping_interval_us: 5_000_000,
            operation_timeout_us: 10_000_000,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchLifecycleError {
    Overflow,
    Local(crate::LocalRequestError),
    Limits,
    Clock,
    Deadline,
    Disconnected,
    Remote(i32),
    Protocol,
    IdentityExhausted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchLifecycleState {
    Registering,
    Connected,
    Reconnecting,
    Failed(WatchLifecycleError),
    Stopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchActionKind {
    Register,
    Reconnect,
    Ping,
}
/// Unique local intent, not a request TID or proof that the control reached the OSD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchAction {
    domain: u64,
    deadline: u64,
    handle: WatchHandle,
    id: u64,
    generation: u32,
    kind: WatchActionKind,
    timeout_seconds: u32,
}
impl WatchAction {
    pub fn deadline_us(self) -> u64 {
        self.deadline
    }
    pub fn id(self) -> u64 {
        self.id
    }
    pub fn handle(self) -> WatchHandle {
        self.handle
    }
    pub fn generation(self) -> u32 {
        self.generation
    }
    pub fn kind(self) -> WatchActionKind {
        self.kind
    }
    pub fn operation(self) -> ControlOperation {
        let cookie = self.handle.cookie();
        match self.kind {
            WatchActionKind::Register => ControlOperation::Register {
                cookie,
                timeout_seconds: self.timeout_seconds,
            },
            WatchActionKind::Reconnect => ControlOperation::Reconnect {
                cookie,
                generation: self.generation,
            },
            WatchActionKind::Ping => ControlOperation::Ping {
                cookie,
                generation: self.generation,
            },
        }
    }
}
#[derive(Clone, Copy, Debug)]
struct Pending {
    action: WatchAction,
    sent: Option<u64>,
    granted_us: u64,
}
/// Constant-space lifecycle only. Does not drive a socket, registry or request queue.
#[derive(Debug)]
pub struct WatchLifecycle {
    domain: u64,
    handle: WatchHandle,
    timing: WatchTiming,
    now: u64,
    state: WatchLifecycleState,
    generation: u32,
    sequence: u64,
    pending: Option<Pending>,
    setup_deadline: Option<u64>,
    /// The owner can address the target now; while false (homeless/map wait) no control operation is created.
    routable: bool,
    valid_through: Option<u64>,
    next_ping: u64,
    paused: bool,
}
impl WatchLifecycle {
    pub fn new(
        handle: WatchHandle,
        timing: WatchTiming,
        now: u64,
    ) -> Result<Self, WatchLifecycleError> {
        let server = u64::from(timing.server_timeout_seconds) * 1_000_000;
        time::validate_deadline(timing.operation_timeout_us)
            .map_err(|_| WatchLifecycleError::Overflow)?;
        time::validate_clock(timing.ping_interval_us).map_err(|_| WatchLifecycleError::Overflow)?;
        if timing.ping_interval_us == 0
            || (server != 0 && timing.ping_interval_us >= server)
            || timing.operation_timeout_us == 0
        {
            return Err(WatchLifecycleError::Limits);
        }
        let deadline = time::operation_deadline(now, timing.operation_timeout_us)
            .map_err(|_| WatchLifecycleError::Overflow)?;
        let domain = NEXT_DOMAIN
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| WatchLifecycleError::IdentityExhausted)?;
        Ok(Self {
            domain,
            handle,
            timing,
            now,
            state: WatchLifecycleState::Registering,
            generation: 0,
            sequence: 0,
            pending: None,
            setup_deadline: time::timer(deadline),
            routable: true,
            valid_through: None,
            next_ping: now,
            paused: false,
        })
    }
    pub fn state(&self) -> WatchLifecycleState {
        self.state
    }
    pub fn generation(&self) -> u32 {
        self.generation
    }
    /// First handoff time of last acknowledged control; excludes caller event processing.
    pub fn valid_through(&self) -> Option<u64> {
        self.valid_through
    }
    pub fn pending_action(&self) -> Option<WatchAction> {
        self.pending.map(|p| p.action)
    }
    /// Owner's current route state for the target. A classic linger sends no WATCH/RECONNECT/PING to a
    /// homeless target, so while unroutable no action (and no per-operation deadline) starts; already armed
    /// deadlines keep running.
    pub fn set_routable(&mut self, routable: bool) {
        self.routable = routable;
    }
    /// No lifecycle action/expiry is runnable at this clock and current pause.
    /// A pending action still needs an owner-side admitted, waiting control.
    pub fn can_wait(&self, now: u64, paused: bool) -> bool {
        if now < self.now
            || now > MAX_TIME
            || matches!(
                self.state,
                WatchLifecycleState::Failed(_) | WatchLifecycleState::Stopped
            )
            || self.setup_deadline.is_some_and(|t| t <= now)
            || self
                .pending
                .is_some_and(|p| time::is_due(p.action.deadline, now))
        {
            return false;
        }
        self.pending.is_some()
            || !self.routable
            || (self.state == WatchLifecycleState::Connected && (paused || now < self.next_ping))
    }
    pub fn next_timer(&self) -> Option<u64> {
        self.next_timer_for(self.paused)
    }
    /// Query against the owner's current map pause, even before a bounded visit.
    pub fn next_timer_for(&self, paused: bool) -> Option<u64> {
        if matches!(
            self.state,
            WatchLifecycleState::Failed(_) | WatchLifecycleState::Stopped
        ) {
            return None;
        }
        (self.pending.is_none()
            && self.routable
            && matches!(
                self.state,
                WatchLifecycleState::Registering | WatchLifecycleState::Reconnecting
            ))
        .then_some(self.now)
        .into_iter()
        .chain(self.setup_deadline)
        .chain(self.pending.and_then(|p| time::timer(p.action.deadline)))
        .chain(
            (self.state == WatchLifecycleState::Connected
                && self.pending.is_none()
                && self.routable
                && !paused)
                .then_some(self.next_ping),
        )
        .min()
    }
    fn fail(&mut self, error: WatchLifecycleError) {
        if !matches!(
            self.state,
            WatchLifecycleState::Failed(_) | WatchLifecycleState::Stopped
        ) {
            self.state = WatchLifecycleState::Failed(error);
            self.pending = None;
        }
    }
    /// A fired deadline reports the budget it enforced before failing.
    fn fail_deadline(&mut self, limit_us: u64) {
        diag::diag!(
            "WARNING TIMEOUT watch lifecycle exceeded {}s (state={:?} setup_deadline={:?} pending={:?})",
            time::budget_seconds(limit_us),
            self.state,
            self.setup_deadline,
            self.pending.map(|p| p.action.kind)
        );
        self.fail(WatchLifecycleError::Deadline);
    }
    /// Terminal map policy is distinct from a transport outage/reconnect.
    pub fn reject_local(&mut self, error: crate::LocalRequestError) {
        self.fail(WatchLifecycleError::Local(error));
    }
    fn advance(&mut self, now: u64) -> bool {
        if matches!(
            self.state,
            WatchLifecycleState::Failed(_) | WatchLifecycleState::Stopped
        ) {
            return false;
        }
        if now < self.now || now > MAX_TIME {
            self.fail(WatchLifecycleError::Clock);
            return false;
        }
        self.now = now;
        let limit_us = if self.setup_deadline.is_some_and(|t| t <= now) {
            Some(self.timing.operation_timeout_us)
        } else {
            self.pending
                .filter(|p| time::is_due(p.action.deadline, now))
                .map(|p| p.granted_us)
        };
        if let Some(limit_us) = limit_us {
            self.fail_deadline(limit_us);
            return false;
        }
        true
    }
    pub fn poll_action(&mut self, now: u64, paused: bool) -> Option<WatchAction> {
        if !self.advance(now) {
            return None;
        }
        self.paused = paused;
        if self.pending.is_some() || !self.routable {
            return None;
        }
        let kind = match self.state {
            WatchLifecycleState::Registering => WatchActionKind::Register,
            WatchLifecycleState::Reconnecting => WatchActionKind::Reconnect,
            WatchLifecycleState::Connected if !paused && now >= self.next_ping => {
                WatchActionKind::Ping
            }
            _ => return None,
        };
        let Some(id) = self.sequence.checked_add(1) else {
            self.fail(WatchLifecycleError::IdentityExhausted);
            return None;
        };
        let generation = if kind == WatchActionKind::Reconnect {
            let Some(g) = self.generation.checked_add(1) else {
                self.fail(WatchLifecycleError::IdentityExhausted);
                return None;
            };
            g
        } else {
            self.generation
        };
        // A captured setup deadline already bounds this action. Do not
        // recompute a later end (or fail its addition) when that earlier bound wins.
        // PING arms no deadline: a missing reply only ages the watch.
        let cap = self.setup_deadline.unwrap_or(NO_DEADLINE);
        let interval = if kind == WatchActionKind::Ping {
            NO_DEADLINE
        } else if cap != NO_DEADLINE {
            self.timing.operation_timeout_us.min(cap - now)
        } else {
            self.timing.operation_timeout_us
        };
        let deadline = match time::operation_deadline(now, interval) {
            Ok(deadline) => deadline,
            Err(_) => {
                self.fail(WatchLifecycleError::Overflow);
                return None;
            }
        }
        .min(cap);
        let action = WatchAction {
            domain: self.domain,
            deadline,
            handle: self.handle,
            id,
            generation,
            kind,
            timeout_seconds: self.timing.server_timeout_seconds,
        };
        self.sequence = id;
        self.generation = generation;
        self.pending = Some(Pending {
            action,
            sent: None,
            granted_us: interval,
        });
        Some(action)
    }
    /// Record first actual transport acceptance, rather than local request admission.
    pub fn sent(&mut self, action: WatchAction, now: u64) -> bool {
        if !self.advance(now) {
            return false;
        }
        let Some(p) = self.pending.as_mut().filter(|p| p.action == action) else {
            return false;
        };
        p.sent.get_or_insert(now);
        true
    }
    /// Return whether an exact current action was consumed. Late/stale results are passive.
    pub fn complete(&mut self, action: WatchAction, result: i32, now: u64) -> bool {
        if !self.advance(now) {
            return false;
        }
        let Some(p) = self.pending.filter(|p| p.action == action) else {
            return false;
        };
        let Some(sent) = p.sent else {
            self.fail(WatchLifecycleError::Protocol);
            return true;
        };
        if result != 0 {
            self.fail(if matches!(result, -2 | -107) {
                WatchLifecycleError::Disconnected
            } else {
                WatchLifecycleError::Remote(result)
            });
            return true;
        }
        let Ok(next) = time::add_us(sent, self.timing.ping_interval_us) else {
            self.fail(WatchLifecycleError::Overflow);
            return true;
        };
        self.pending = None;
        self.state = WatchLifecycleState::Connected;
        self.setup_deadline = None;
        self.valid_through = Some(sent);
        self.next_ping = next;
        true
    }
    /// Called after old-route ingress and control have been revoked by the owner.
    pub fn transport_lost(&mut self, now: u64) {
        if !self.advance(now) {
            return;
        }
        if self.state == WatchLifecycleState::Connected {
            self.state = WatchLifecycleState::Reconnecting;
        }
        self.pending = None;
    }
    pub fn disconnected(&mut self, now: u64) {
        if self.advance(now) {
            self.fail(WatchLifecycleError::Disconnected);
        }
    }
    pub fn stop(&mut self) {
        if !matches!(self.state, WatchLifecycleState::Failed(_)) {
            self.state = WatchLifecycleState::Stopped;
        }
        self.pending = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn outage_reconnects_without_a_local_limit_and_unroutable_targets_get_no_action() {
        let mut registry = crate::WatchRegistry::new(1, 1, 1024).unwrap();
        let handle = registry
            .reserve_unbound_watch(crate::Target {
                pool: 7,
                object: b"outage".to_vec(),
                namespace: vec![],
                locator: vec![],
            })
            .unwrap();
        // Default timing (10 s operation budget, as the live outage cell's rados_osd_op_timeout=10).
        let mut lifecycle = WatchLifecycle::new(handle, WatchTiming::default(), 0).unwrap();
        let action = lifecycle.poll_action(1, false).unwrap();
        assert!(lifecycle.sent(action, 1));
        assert!(lifecycle.complete(action, 0, 2));
        lifecycle.transport_lost(3);
        // Primary down: the target is homeless for 45 s; before the fix a RECONNECT was created anyway and
        // its 10 s deadline (or the 25 s outage limit) failed the watch.
        lifecycle.set_routable(false);
        for now in [4, 10_000_000, 25_000_004, 45_000_000] {
            assert!(lifecycle.poll_action(now, false).is_none());
            assert_eq!(lifecycle.state(), WatchLifecycleState::Reconnecting);
            assert_eq!(lifecycle.next_timer(), None);
        }
        lifecycle.set_routable(true);
        let reconnect = lifecycle.poll_action(45_000_001, false).unwrap();
        assert_eq!(reconnect.kind(), WatchActionKind::Reconnect);
        assert_eq!(reconnect.deadline_us(), 55_000_001);
        assert!(lifecycle.sent(reconnect, 45_000_002));
        assert!(lifecycle.complete(reconnect, 0, 45_000_003));
        assert_eq!(lifecycle.state(), WatchLifecycleState::Connected);
    }
    #[test]
    fn wide_and_unlimited_setup_keep_original_bounds_without_timer_sentinels() {
        let mut registry = crate::WatchRegistry::new(1, 1, 1024).unwrap();
        let handle = registry
            .reserve_unbound_watch(crate::Target {
                pool: 7,
                object: b"wide".to_vec(),
                namespace: vec![],
                locator: vec![],
            })
            .unwrap();
        for budget in [(1u64 << 32) * 1_000_000, NO_DEADLINE] {
            let mut lifecycle = WatchLifecycle::new(
                handle,
                WatchTiming {
                    operation_timeout_us: budget,
                    ..Default::default()
                },
                5,
            )
            .unwrap();
            let action = lifecycle.poll_action(6, false).unwrap();
            assert_eq!(
                action.deadline_us(),
                time::operation_deadline(5, budget).unwrap()
            );
            if budget == NO_DEADLINE {
                assert_eq!(lifecycle.next_timer(), None);
                assert!(lifecycle.can_wait(MAX_TIME, false));
                assert!(lifecycle.sent(action, MAX_TIME));
                assert_eq!(lifecycle.state(), WatchLifecycleState::Registering);
            } else {
                assert_eq!(lifecycle.next_timer(), Some(5 + budget));
                assert!(lifecycle.sent(action, 4 + budget));
                assert!(!lifecycle.sent(action, 5 + budget));
                assert_eq!(
                    lifecycle.state(),
                    WatchLifecycleState::Failed(WatchLifecycleError::Deadline)
                );
            }
        }
        assert!(matches!(
            WatchLifecycle::new(handle, Default::default(), MAX_TIME),
            Err(WatchLifecycleError::Overflow)
        ));
    }
    #[test]
    fn local_identity_exhaustion_never_wraps_or_emits_an_action() {
        for exhaust_generation in [false, true] {
            let mut registry = crate::WatchRegistry::new(1, 1, 100).unwrap();
            let handle = registry
                .reserve(
                    crate::Target {
                        pool: 1,
                        object: vec![1],
                        namespace: vec![],
                        locator: vec![],
                    },
                    crate::ReadRoute {
                        direct_read: false,
                        base_pool: 1,
                        osd: 1,
                        session: 1,
                        pg: Default::default(),
                        hash: 0,
                        epoch: 1,
                        features: 0,
                        generation: 1,
                        pool: crate::PoolRoute::Replicated,
                    },
                    crate::WatchKind::Watch,
                )
                .unwrap();
            let mut l = WatchLifecycle::new(handle, Default::default(), 0).unwrap();
            if exhaust_generation {
                l.state = WatchLifecycleState::Reconnecting;
                l.generation = u32::MAX;
            } else {
                l.sequence = u64::MAX;
            }
            assert!(l.poll_action(0, false).is_none());
            assert_eq!(
                l.state(),
                WatchLifecycleState::Failed(WatchLifecycleError::IdentityExhausted)
            );
            assert!(l.pending.is_none());
        }
    }
}
