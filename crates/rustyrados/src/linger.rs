// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Public-compatible watch/linger scheduling state machine.
//!
//! Transport-neutral entry state for one public watch or linger registration.
//! A coordinator supplies global ticks, route replacements, disconnects, exact
//! action results and cancellation. ObjectClient/FFI public integration remains
//! a separate required step; this native component expresses the protocol policy
//! that the strict native [`crate::WatchLifecycle`] deliberately excludes:
//! overlapping independently identified pending pings, per-reconnect
//! operation budgets, a wrapping u32 wire registration generation, tick-time
//! pre-send confirmation stamps and recoverable first-error history, with no
//! total-outage expiry.
//!
//! The ping cadence is the source's client global tick, owned by the
//! coordinator: it decides when `tick` is called. This entry keeps no
//! interval, due time or schedule state.
//!
//! Contract: `doc/spec/rados-client/public-linger-scheduling-contract.md`.

use crate::time::{self, NO_DEADLINE};
use crate::{ControlOperation, WatchHandle};
use denc::errno;
use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DOMAIN: AtomicU64 = AtomicU64::new(1);

/// Profile captured from current client configuration at entry creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LingerProfile {
    /// Initial WATCH lease seconds; zero selects the OSD default.
    pub server_timeout_seconds: u32,
    /// Relative registration/reconnect budget; `time::NO_DEADLINE` is
    /// unlimited (the generic zero-seconds timeout enrollment).
    pub operation_timeout_us: u64,
}
impl Default for LingerProfile {
    fn default() -> Self {
        Self {
            server_timeout_seconds: 0,
            operation_timeout_us: NO_DEADLINE,
        }
    }
}

/// Local protocol, clock and identity outcomes plus recoverable pressure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LingerError {
    /// Monotonic clock regression.
    Clock,
    /// Clock/deadline outside the checked finite representation.
    Overflow,
    /// Terminal: the per-entry u64 local action identity space is exhausted.
    Identity,
    /// Recoverable: ping-slot or error-event-slot reservation failed; state
    /// and identity are preserved and the coordinator re-drives.
    Memory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LingerState {
    /// Initial registration owed or in flight; its result stays the setup
    /// result and never queues a watch error callback.
    Registering,
    /// Registered; pings renew the confirmation stamp only.
    Established,
    /// A replacement RECONNECT is owed after a route/session/interval change.
    Reconnecting,
    /// The last RECONNECT failed; no automatic retry. The next route,
    /// session or interval change owes a new reconnect.
    ReconnectFailed,
    /// Terminal: the initial registration failed with its original errno.
    SetupFailed(i32),
    /// Terminal local protocol/clock/identity error.
    Failed(LingerError),
    /// Terminal: the coordinator stopped this entry; late results are passive.
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LingerActionKind {
    Register,
    Reconnect,
    Ping,
}

/// One exact local scheduling intent; the identity is local, not a wire TID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LingerAction {
    domain: u64,
    id: u64,
    handle: WatchHandle,
    generation: u32,
    kind: LingerActionKind,
    deadline: u64,
    timeout_seconds: u32,
    /// Completion storage only; never encoded or used as a dispatch cursor.
    ping_slot: Option<NonZeroUsize>,
}
impl LingerAction {
    pub fn id(self) -> u64 {
        self.id
    }
    pub fn handle(self) -> WatchHandle {
        self.handle
    }
    /// Wire registration generation; wraps modulo 2^32 by source.
    pub fn generation(self) -> u32 {
        self.generation
    }
    pub fn kind(self) -> LingerActionKind {
        self.kind
    }
    /// Finite deadline or `time::NO_DEADLINE`; pings are always unlimited.
    pub fn deadline_us(self) -> u64 {
        self.deadline
    }
    pub fn operation(self) -> ControlOperation {
        let cookie = self.handle.cookie();
        match self.kind {
            LingerActionKind::Register => ControlOperation::Register {
                cookie,
                timeout_seconds: self.timeout_seconds,
            },
            LingerActionKind::Reconnect => ControlOperation::Reconnect {
                cookie,
                generation: self.generation,
            },
            LingerActionKind::Ping => ControlOperation::Ping {
                cookie,
                generation: self.generation,
            },
        }
    }
}

/// Captured remote error with its queue time; survives later last-error
/// changes, including a reconnect clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LingerErrorEvent {
    errno: i32,
    queued_at: u64,
}
impl LingerErrorEvent {
    pub fn errno(self) -> i32 {
        self.errno
    }
    pub fn queued_at_us(self) -> u64 {
        self.queued_at
    }
}

#[derive(Debug)]
struct PendingPing {
    action: LingerAction,
    /// Sampled before queue/backoff/socket work when this tick intent is created.
    sampled_at: u64,
}

/// One public-compatible watch/linger entry under shared coordinator
/// ownership. Health reads allocate nothing.
#[derive(Debug)]
pub struct Linger {
    domain: u64,
    handle: WatchHandle,
    profile: LingerProfile,
    now: u64,
    state: LingerState,
    last_error: Option<i32>,
    generation: u32,
    sequence: u64,
    registration: Option<LingerAction>,
    pings: Vec<Option<PendingPing>>,
    ping_free: Vec<usize>,
    errors: VecDeque<LingerErrorEvent>,
    /// Confirmation baseline: the creation stamp, refreshed only by ping
    /// success to that ping's pre-send sample.
    confirmation: u64,
    /// Original initial registration result; never rewritten by later state.
    setup_result: Option<i32>,
    /// Setup version captured from the first validated commit reply,
    /// including negative results and version 0; published at most once.
    setup_version: Option<u64>,
    /// Local subscription cutoff; a pending initial setup keeps its ownership.
    canceled: bool,
}
impl Linger {
    pub fn new(profile: LingerProfile, handle: WatchHandle, now: u64) -> Result<Self, LingerError> {
        time::validate_clock(now).map_err(|_| LingerError::Overflow)?;
        time::validate_deadline(profile.operation_timeout_us).map_err(|_| LingerError::Overflow)?;
        let domain = NEXT_DOMAIN
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| LingerError::Identity)?;
        Ok(Self {
            domain,
            handle,
            profile,
            now,
            state: LingerState::Registering,
            last_error: None,
            generation: 0,
            sequence: 0,
            registration: None,
            pings: Vec::new(),
            ping_free: Vec::new(),
            errors: VecDeque::new(),
            confirmation: now,
            setup_result: None,
            setup_version: None,
            canceled: false,
        })
    }
    pub fn state(&self) -> LingerState {
        self.state
    }
    pub fn handle(&self) -> WatchHandle {
        self.handle
    }
    pub fn generation(&self) -> u32 {
        self.generation
    }
    pub fn confirmation_stamp_us(&self) -> u64 {
        self.confirmation
    }
    pub fn last_error(&self) -> Option<i32> {
        self.last_error
    }
    pub fn setup_result(&self) -> Option<i32> {
        self.setup_result
    }
    pub fn setup_version(&self) -> Option<u64> {
        self.setup_version
    }
    pub fn is_canceled(&self) -> bool {
        self.canceled
    }
    pub fn pending_registration(&self) -> Option<LingerAction> {
        self.registration
    }
    /// Overlapping independently identified pings; no fixed count cap.
    pub fn pending_pings(&self) -> usize {
        self.pings.len() - self.ping_free.len()
    }
    /// Queue time of the oldest retained error event, if any.
    pub fn front_queue_time_us(&self) -> Option<u64> {
        self.errors.front().map(|e| e.queued_at)
    }
    /// Checked age from the older of the confirmation stamp and the queued
    /// front time; the coordinator folds in notification front times.
    pub fn age_us(&self, now: u64) -> Result<u64, LingerError> {
        time::validate_clock(now).map_err(|_| LingerError::Overflow)?;
        if now < self.now {
            return Err(LingerError::Clock);
        }
        let base = self
            .confirmation
            .min(self.front_queue_time_us().unwrap_or(u64::MAX));
        now.checked_sub(base).ok_or(LingerError::Clock)
    }
    /// FIFO drain of retained captured errors for coordinator dispatch.
    pub fn poll_error_event(&mut self) -> Option<LingerErrorEvent> {
        self.errors.pop_front()
    }
    /// A pending registration, ping or error event still needs an owner.
    pub fn has_pending_work(&self) -> bool {
        self.registration.is_some() || self.pending_pings() != 0 || !self.errors.is_empty()
    }

    /// Next owed registration/reconnect intent; None while one is pending,
    /// after cancellation, in `ReconnectFailed` (no automatic retry) or in a
    /// terminal state. The budget is captured at this time; armed actions
    /// keep their captured deadline.
    pub fn poll_action(&mut self, now: u64) -> Option<LingerAction> {
        if !self.advance(now) || self.canceled || self.registration.is_some() {
            return None;
        }
        let kind = match self.state {
            LingerState::Registering => LingerActionKind::Register,
            LingerState::Reconnecting => LingerActionKind::Reconnect,
            _ => return None,
        };
        let Some(id) = self.sequence.checked_add(1) else {
            self.fail(LingerError::Identity);
            return None;
        };
        let generation = if kind == LingerActionKind::Reconnect {
            self.generation = self.generation.wrapping_add(1);
            self.generation
        } else {
            self.generation
        };
        let deadline = match time::operation_deadline(now, self.profile.operation_timeout_us) {
            Ok(deadline) => deadline,
            Err(_) => {
                self.fail(LingerError::Overflow);
                return None;
            }
        };
        let action = LingerAction {
            domain: self.domain,
            id,
            handle: self.handle,
            generation,
            kind,
            deadline,
            ping_slot: None,
            timeout_seconds: if kind == LingerActionKind::Register {
                self.profile.server_timeout_seconds
            } else {
                0
            },
        };
        self.sequence = id;
        self.registration = Some(action);
        Some(action)
    }

    /// Externally driven client tick. Every tick for an established, live,
    /// clear-error, non-paused entry creates one more independently
    /// identified ping, including ticks at the same timestamp. The tick
    /// timestamp is the ping's fixed pre-send sample.
    pub fn tick(&mut self, now: u64, paused: bool) -> Result<Option<LingerAction>, LingerError> {
        if !self.advance(now) {
            return if let LingerState::Failed(error) = self.state {
                Err(error)
            } else {
                Ok(None)
            };
        }
        if self.canceled || paused {
            return Ok(None);
        }
        // Registration remains established while a replacement reconnect is
        // pending. Its current-generation pings do not wait for that reply.
        if !self.setup_result.is_some_and(|result| result >= 0) || self.last_error.is_some() {
            return Ok(None);
        }
        let Some(id) = self.sequence.checked_add(1) else {
            self.fail(LingerError::Identity);
            return Err(LingerError::Identity);
        };
        let slot = match self.ping_free.pop() {
            Some(slot) => slot,
            None => {
                let slot = self.pings.len();
                let total = slot.checked_add(1).ok_or(LingerError::Memory)?;
                if self.pings.try_reserve(1).is_err()
                    || self
                        .ping_free
                        .try_reserve(total - self.ping_free.len())
                        .is_err()
                {
                    // Preserve the pending intent/identity under recoverable pressure.
                    return Err(LingerError::Memory);
                }
                self.pings.push(None);
                slot
            }
        };
        let action = LingerAction {
            domain: self.domain,
            id,
            handle: self.handle,
            generation: self.generation,
            kind: LingerActionKind::Ping,
            deadline: NO_DEADLINE,
            timeout_seconds: 0,
            ping_slot: Some(NonZeroUsize::new(slot + 1).expect("reserved vector slot")),
        };
        self.sequence = id;
        self.pings[slot] = Some(PendingPing {
            action,
            sampled_at: now,
        });
        Ok(Some(action))
    }

    /// Apply an explicit result to an exact action. Late, revoked or foreign
    /// actions are passive. A negative result that must queue an event
    /// reserves that slot first: on pressure the pending action is not
    /// consumed, nothing is recorded, and no mandatory event is dropped.
    /// Local timeout or route/owner loss can complete an action before any
    /// send; such negative local results require no pre-send sample.
    pub fn complete(
        &mut self,
        action: LingerAction,
        result: i32,
        version: Option<u64>,
        now: u64,
    ) -> Result<bool, LingerError> {
        let registration = self.registration == Some(action);
        let ping = action.ping_slot.map(|slot| slot.get() - 1).filter(|&slot| {
            self.pings
                .get(slot)
                .and_then(Option::as_ref)
                .is_some_and(|pending| pending.action == action)
        });
        if (!registration && ping.is_none()) || !self.advance(now) {
            return Ok(false);
        }
        if result < 0
            && !self.canceled
            && action.kind != LingerActionKind::Register
            && self.last_error.is_none()
            && self.errors.try_reserve(1).is_err()
        {
            return Err(LingerError::Memory);
        }
        if registration {
            self.registration = None;
            self.complete_registration(action, result, version, now);
            return Ok(true);
        }
        let slot = ping.expect("matched ping");
        let pending = self.pings[slot].take().expect("located ping");
        self.ping_free.push(slot);
        self.complete_ping(pending, result, now);
        Ok(true)
    }

    /// Server DISCONNECT: sets the first error and nothing else. No state
    /// change, no ping revocation, no reconnect trigger. Its error is
    /// independent of whether initial setup completion has been delivered.
    pub fn disconnected(&mut self, now: u64) -> Result<(), LingerError> {
        if !self.advance(now) || self.canceled {
            return Ok(());
        }
        if self.last_error.is_none() && self.errors.try_reserve(1).is_err() {
            // Nothing recorded; the coordinator retains and re-drives the
            // disconnect event rather than dropping its first error.
            return Err(LingerError::Memory);
        }
        self.record_error(-errno::ENOTCONN, now, false);
        Ok(())
    }

    /// Map/route replacement: outstanding pings are revoked without replay
    /// and the pending registration is replaced; returns the exact revoked
    /// registration action, if any, whose late result is now passive. For an
    /// active entry with an unfinished initial registration the same poll
    /// guard issues a fresh initial Register. A locally canceled entry
    /// revokes nothing and re-registers nothing: its original pending setup
    /// keeps its ownership.
    pub fn route_changed(&mut self, now: u64) -> Option<LingerAction> {
        if !self.advance(now) || self.canceled {
            return None;
        }
        self.clear_pings();
        let revoked = self.registration.take();
        if self.state != LingerState::Registering {
            self.state = LingerState::Reconnecting;
        }
        revoked
    }

    /// Local subscription cutoff: stops new intents, revokes outstanding
    /// pings and suppresses queued error dispatch. The pending initial setup
    /// keeps its ownership and still publishes its result/version.
    pub fn cancel_local(&mut self, now: u64) {
        self.advance(now);
        self.canceled = true;
        self.clear_pings();
        self.errors.clear();
    }

    /// Terminal stop: every pending action and queued event is revoked; all
    /// late results are passive.
    pub fn stop(&mut self, now: u64) {
        self.advance(now);
        self.state = LingerState::Stopped;
        self.canceled = true;
        self.registration = None;
        self.clear_pings();
        self.errors.clear();
    }

    /// Current operation budget for future registration/reconnect actions;
    /// already armed actions keep their captured deadline.
    pub fn set_operation_budget(&mut self, budget_us: u64) -> Result<(), LingerError> {
        time::validate_deadline(budget_us).map_err(|_| LingerError::Overflow)?;
        self.profile.operation_timeout_us = budget_us;
        Ok(())
    }

    fn clear_pings(&mut self) {
        self.pings.clear();
        self.ping_free.clear();
    }

    fn advance(&mut self, now: u64) -> bool {
        if matches!(
            self.state,
            LingerState::SetupFailed(_) | LingerState::Failed(_) | LingerState::Stopped
        ) {
            return false;
        }
        if now < self.now {
            self.fail(LingerError::Clock);
            return false;
        }
        if time::validate_clock(now).is_err() {
            self.fail(LingerError::Overflow);
            return false;
        }
        self.now = now;
        true
    }

    fn fail(&mut self, error: LingerError) {
        if !matches!(
            self.state,
            LingerState::SetupFailed(_) | LingerState::Failed(_) | LingerState::Stopped
        ) {
            self.state = LingerState::Failed(error);
            self.registration = None;
            self.clear_pings();
            self.errors.clear();
        }
    }

    fn complete_registration(
        &mut self,
        pending: LingerAction,
        result: i32,
        version: Option<u64>,
        now: u64,
    ) {
        // No pre-send sample is required: local timeout or route loss can
        // complete a registration/reconnect before any send.
        if self.setup_result.is_none() {
            self.setup_result = Some(result);
            self.setup_version = version;
        }
        if result < 0 {
            if pending.kind == LingerActionKind::Register {
                // Original, unnormalized result; no error callback, no retry.
                self.state = LingerState::SetupFailed(result);
            } else {
                self.record_error(Self::normalize(result), now, true);
                self.state = LingerState::ReconnectFailed;
            }
            return;
        }
        if pending.kind == LingerActionKind::Reconnect {
            self.last_error = None;
        }
        self.state = LingerState::Established;
    }

    fn complete_ping(&mut self, pending: PendingPing, result: i32, now: u64) {
        if result < 0 {
            // Failure needs no pre-send sample.
            self.record_error(Self::normalize(result), now, false);
            return;
        }

        // Same-generation success records its pre-send sample, including an
        // older out-of-order confirmation; success never clears last_error.
        self.confirmation = pending.sampled_at;
    }

    /// assign overwrites (reconnect failure); first-error-wins otherwise
    /// (ping, disconnect). A queued event is emitted only when the last
    /// error was previously clear and the captured errno is nonzero.
    fn record_error(&mut self, errno: i32, now: u64, assign: bool) {
        let fresh = self.last_error.is_none();
        if assign || fresh {
            self.last_error = Some(errno);
        }
        if fresh && errno != 0 && !self.canceled {
            self.errors.push_back(LingerErrorEvent {
                errno,
                queued_at: now,
            });
        }
    }

    fn normalize(result: i32) -> i32 {
        if result == -errno::ENOENT {
            -errno::ENOTCONN
        } else {
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::MAX_TIME_US;

    fn handle() -> WatchHandle {
        let mut registry = crate::WatchRegistry::new(1, 1, 1024).unwrap();
        registry
            .reserve_unbound_watch(crate::Target {
                pool: 1,
                object: vec![1],
                namespace: vec![],
                locator: vec![],
            })
            .unwrap()
    }

    fn entry(budget: u64) -> Linger {
        Linger::new(
            LingerProfile {
                server_timeout_seconds: 30,
                operation_timeout_us: budget,
            },
            handle(),
            0,
        )
        .unwrap()
    }

    fn establish(l: &mut Linger, at: u64) {
        let reg = l.poll_action(at).unwrap();
        assert!(l.complete(reg, 0, Some(5), at).unwrap());
        assert_eq!(l.state(), LingerState::Established);
    }

    fn ping(l: &mut Linger, at: u64) -> LingerAction {
        let action = l.tick(at, false).unwrap().unwrap();
        assert_eq!(action.kind(), LingerActionKind::Ping);
        action
    }

    #[test]
    fn every_global_tick_creates_an_independent_ping_even_at_same_timestamp() {
        let mut l = entry(NO_DEADLINE);
        establish(&mut l, 0);
        let p1 = ping(&mut l, 10);
        let p2 = ping(&mut l, 10);
        let p3 = ping(&mut l, 10);
        assert_eq!(l.pending_pings(), 3);
        assert_ne!(p1.id(), p2.id());
        assert_ne!(p2.id(), p3.id());
        assert_eq!(p1.generation(), p2.generation());
        // Out-of-order same-generation replies confirm from their samples.
        assert!(l.complete(p3, 0, None, 11).unwrap());
        assert!(l.complete(p1, 0, None, 12).unwrap());
        assert_eq!(l.confirmation_stamp_us(), 10);
        assert!(l.complete(p2, 0, None, 13).unwrap());
        assert_eq!(l.confirmation_stamp_us(), 10);
        assert_eq!(l.last_error(), None);
    }

    #[test]
    fn total_outage_has_no_client_expiry_with_unlimited_budget() {
        let mut l = entry(NO_DEADLINE);
        establish(&mut l, 0);
        assert_eq!(l.disconnected(10_000_000), Ok(()));
        assert_eq!(l.state(), LingerState::Established);
        assert_eq!(l.last_error(), Some(-107));
        // No automatic reconnect: only a route change owes one.
        assert!(l.poll_action(35_000_000).is_none());
        l.route_changed(35_000_000);
        let r1 = l.poll_action(35_000_000).unwrap();
        assert_eq!(r1.deadline_us(), NO_DEADLINE);
        assert!(l.complete(r1, -110, None, 60_000_000).unwrap());
        assert_eq!(l.state(), LingerState::ReconnectFailed);
        assert_eq!(l.last_error(), Some(-110));
        // No auto retry; the next route change triggers it.
        assert!(l.poll_action(120_000_000).is_none());
        l.route_changed(120_000_000);
        let r2 = l.poll_action(120_000_000).unwrap();
        assert!(l.complete(r2, 0, None, 150_000_000).unwrap());
        assert_eq!(l.state(), LingerState::Established);
        assert_eq!(l.last_error(), None);
        // Reconnect success never refreshes the confirmation baseline.
        assert_eq!(l.confirmation_stamp_us(), 0);
        // The disconnect error event survived the reconnect clear.
        assert_eq!(l.front_queue_time_us(), Some(10_000_000));
    }

    #[test]
    fn reconnect_recaptures_current_budget_and_armed_deadline_is_unchanged() {
        let mut l = entry(10_000);
        let reg = l.poll_action(0).unwrap();
        assert_eq!(reg.deadline_us(), 10_000);
        l.set_operation_budget(100_000).unwrap();
        assert_eq!(l.pending_registration().unwrap().deadline_us(), 10_000);
        assert!(l.complete(reg, 0, Some(3), 5_000).unwrap());
        assert_eq!(l.route_changed(6_000), None);
        let r = l.poll_action(6_000).unwrap();
        assert_eq!(r.kind(), LingerActionKind::Reconnect);
        assert_eq!(r.deadline_us(), 106_000);
        assert_eq!(l.setup_version(), Some(3));
    }

    #[test]
    fn late_ping_from_revoked_route_is_passive() {
        let mut l = entry(NO_DEADLINE);
        establish(&mut l, 0);
        let p = ping(&mut l, 1);
        assert_eq!(l.route_changed(2), None);
        assert_eq!(l.pending_pings(), 0);
        assert_eq!(l.complete(p, 0, None, 3), Ok(false));
        assert_eq!(l.confirmation_stamp_us(), 0);
        let r = l.poll_action(3).unwrap();
        assert_eq!(r.generation(), 1);
        assert!(l.complete(r, 0, None, 4).unwrap());
        assert_eq!(l.generation(), 1);
    }

    #[test]
    fn wire_generation_wraps_modulo_u32_without_exhaustion_error() {
        let mut l = entry(NO_DEADLINE);
        establish(&mut l, 0);
        l.generation = u32::MAX - 1;
        l.route_changed(1);
        let r1 = l.poll_action(1).unwrap();
        assert_eq!(r1.generation(), u32::MAX);
        assert!(l.complete(r1, 0, None, 2).unwrap());
        l.route_changed(3);
        let r2 = l.poll_action(3).unwrap();
        assert_eq!(r2.generation(), 0);
    }

    #[test]
    fn failed_initial_registration_keeps_original_result_and_version() {
        let mut l = entry(NO_DEADLINE);
        let reg = l.poll_action(0).unwrap();
        assert!(l.complete(reg, -2, Some(42), 5).unwrap());
        assert_eq!(l.state(), LingerState::SetupFailed(-2));
        assert_eq!(l.setup_result(), Some(-2));
        assert_eq!(l.setup_version(), Some(42));
        assert_eq!(l.last_error(), None);
        assert_eq!(l.front_queue_time_us(), None);
        assert_eq!(l.pending_registration(), None);
        // No retry, no ping, no further publication.
        assert!(l.poll_action(6).is_none());
        assert_eq!(l.tick(7, false), Ok(None));
        assert_eq!(l.complete(reg, 0, None, 8), Ok(false));
    }

    #[test]
    fn setup_version_is_captured_from_validated_replies_including_zero() {
        let mut l = entry(NO_DEADLINE);
        let reg = l.poll_action(0).unwrap();
        assert!(l.complete(reg, 0, Some(0), 1).unwrap());
        assert_eq!(l.setup_version(), Some(0));
        let mut f = entry(NO_DEADLINE);
        let freg = f.poll_action(0).unwrap();
        assert!(f.complete(freg, -5, Some(0), 2).unwrap());
        assert_eq!(f.setup_version(), Some(0));
        assert_eq!(f.setup_result(), Some(-5));
        // No reply version means no fabricated version.
        let mut n = entry(NO_DEADLINE);
        let nreg = n.poll_action(0).unwrap();
        assert!(n.complete(nreg, -5, None, 3).unwrap());
        assert_eq!(n.setup_version(), None);
    }

    #[test]
    fn canceled_entry_still_publishes_late_initial_setup_result() {
        let mut l = entry(NO_DEADLINE);
        let reg = l.poll_action(0).unwrap();
        l.cancel_local(1);
        assert!(l.is_canceled());
        assert_eq!(l.pending_registration(), Some(reg));
        assert_eq!(l.tick(2, false), Ok(None));
        assert!(l.poll_action(2).is_none());
        assert_eq!(l.route_changed(2), None);
        assert!(l.complete(reg, 0, Some(9), 3).unwrap());
        assert_eq!(l.setup_result(), Some(0));
        assert_eq!(l.setup_version(), Some(9));
        assert_eq!(l.state(), LingerState::Established);
        assert!(l.is_canceled());
    }

    #[test]
    fn first_error_wins_for_pings_and_reconnect_clears_without_dropping_queued() {
        let mut l = entry(NO_DEADLINE);
        establish(&mut l, 0);
        let p1 = ping(&mut l, 10);
        assert!(l.complete(p1, -5, None, 11).unwrap());
        assert_eq!(l.last_error(), Some(-5));
        assert_eq!(l.front_queue_time_us(), Some(11));
        // Pings stop while last_error is set.
        assert_eq!(l.tick(12, false), Ok(None));
        // ENOENT normalizes; reconnect assigns over the first error; no
        // second event because the last error was not clear.
        l.route_changed(13);
        let r1 = l.poll_action(13).unwrap();
        assert!(l.complete(r1, -2, None, 14).unwrap());
        assert_eq!(l.last_error(), Some(-107));
        assert_eq!(l.front_queue_time_us(), Some(11));
        assert_eq!(l.errors.len(), 1);
        // A failed reconnect does not auto-retry; route change re-owes it.
        assert_eq!(l.state(), LingerState::ReconnectFailed);
        assert!(l.poll_action(15).is_none());
        l.route_changed(15);
        let r2 = l.poll_action(15).unwrap();
        assert!(l.complete(r2, 0, None, 16).unwrap());
        assert_eq!(l.last_error(), None);
        assert_eq!(l.state(), LingerState::Established);
        let queued = l.poll_error_event().unwrap();
        assert_eq!(queued.errno(), -5);
        assert_eq!(queued.queued_at_us(), 11);
        assert!(l.poll_error_event().is_none());
    }

    #[test]
    fn stopped_entry_is_passive_to_late_results_and_events() {
        let mut l = entry(NO_DEADLINE);
        establish(&mut l, 0);
        let p = ping(&mut l, 1);
        l.stop(2);
        assert_eq!(l.state(), LingerState::Stopped);
        assert_eq!(l.complete(p, 0, None, 3), Ok(false));
        assert_eq!(l.confirmation_stamp_us(), 0);
        assert_eq!(l.pending_pings(), 0);
        assert!(l.poll_error_event().is_none());
        assert_eq!(l.disconnected(4), Ok(()));
        assert_eq!(l.state(), LingerState::Stopped);
    }

    #[test]
    fn regression_and_out_of_domain_clocks_are_terminal() {
        let mut l = entry(NO_DEADLINE);
        establish(&mut l, 100);
        let p = ping(&mut l, 110);
        assert_eq!(l.complete(p, 0, None, 105), Ok(false));
        assert_eq!(l.state(), LingerState::Failed(LingerError::Clock));
        assert_eq!(l.pending_pings(), 0);
        let mut l2 = entry(NO_DEADLINE);
        establish(&mut l2, 0);
        assert_eq!(l2.tick(MAX_TIME_US + 1, false), Err(LingerError::Overflow));
        assert_eq!(l2.state(), LingerState::Failed(LingerError::Overflow));
    }

    #[test]
    fn finite_zero_budget_is_due_now_while_zero_seconds_stays_unlimited() {
        let mut l = entry(0);
        let reg = l.poll_action(0).unwrap();
        assert_eq!(reg.deadline_us(), 0);
        assert!(time::is_due(reg.deadline_us(), 0));
        let mut u = entry(NO_DEADLINE);
        let ureg = u.poll_action(0).unwrap();
        assert_eq!(ureg.deadline_us(), NO_DEADLINE);
        assert!(!time::is_due(ureg.deadline_us(), MAX_TIME_US));
    }

    #[test]
    fn identity_exhaustion_is_terminal_and_emits_nothing() {
        let mut l = entry(NO_DEADLINE);
        establish(&mut l, 0);
        l.sequence = u64::MAX;
        assert_eq!(l.tick(1, false), Err(LingerError::Identity));
        assert_eq!(l.state(), LingerState::Failed(LingerError::Identity));
        let mut r = entry(NO_DEADLINE);
        r.sequence = u64::MAX;
        assert!(r.poll_action(0).is_none());
        assert_eq!(r.state(), LingerState::Failed(LingerError::Identity));
    }

    #[test]
    fn local_timeout_before_send_is_not_a_protocol_error() {
        // A negative local result (timeout/route/owner loss) can complete a
        // registration/reconnect before any send; no sample is required.
        let mut l = entry(NO_DEADLINE);
        establish(&mut l, 0);
        l.route_changed(1);
        let r = l.poll_action(1).unwrap();
        assert!(l.complete(r, -110, None, 2).unwrap());
        assert_eq!(l.state(), LingerState::ReconnectFailed);
        assert_eq!(l.last_error(), Some(-110));
        // A ping failure likewise needs no pre-send sample.
        let mut p = entry(NO_DEADLINE);
        establish(&mut p, 0);
        let ping = ping(&mut p, 5);
        assert!(p.complete(ping, -110, None, 6).unwrap());
        assert_eq!(p.last_error(), Some(-110));
    }

    #[test]
    fn disconnect_only_sets_first_error_without_reconnect_or_state_change() {
        let mut l = entry(NO_DEADLINE);
        establish(&mut l, 0);
        let p = ping(&mut l, 5);
        assert_eq!(l.disconnected(10), Ok(()));
        assert_eq!(l.state(), LingerState::Established);
        assert_eq!(l.last_error(), Some(-107));
        assert_eq!(l.front_queue_time_us(), Some(10));
        assert_eq!(l.pending_pings(), 1);
        // No automatic reconnect; pings are suppressed by the last error.
        assert!(l.poll_action(11).is_none());
        assert_eq!(l.tick(12, false), Ok(None));
        // A second disconnect queues no second event.
        assert_eq!(l.disconnected(13), Ok(()));
        assert_eq!(l.errors.len(), 1);
        // The outstanding same-generation ping is still honored.
        assert!(l.complete(p, 0, None, 14).unwrap());
        assert_eq!(l.confirmation_stamp_us(), 5);
        l.route_changed(15);
        let r = l.poll_action(15).unwrap();
        assert!(l.complete(r, 0, None, 16).unwrap());
        assert_eq!(l.state(), LingerState::Established);
        assert_eq!(l.last_error(), None);
    }

    #[test]
    fn route_change_replaces_unfinished_setup_with_exactly_revoked_action() {
        let mut l = entry(NO_DEADLINE);
        let reg = l.poll_action(0).unwrap();
        let revoked = l.route_changed(1);
        assert_eq!(revoked, Some(reg));
        assert_eq!(l.state(), LingerState::Registering);
        assert_eq!(l.pending_registration(), None);
        // The new route owes a fresh initial register under the same guard.
        let reg2 = l.poll_action(2).unwrap();
        assert_eq!(reg2.kind(), LingerActionKind::Register);
        assert_ne!(reg2.id(), reg.id());
        // The old action's late result is passive.
        assert_eq!(l.complete(reg, 0, None, 3), Ok(false));
        assert!(l.complete(reg2, 0, Some(1), 4).unwrap());
        assert_eq!(l.state(), LingerState::Established);
    }

    #[test]
    fn route_change_on_canceled_entry_keeps_original_setup_owned() {
        let mut l = entry(NO_DEADLINE);
        let reg = l.poll_action(0).unwrap();
        l.cancel_local(1);
        assert_eq!(l.route_changed(2), None);
        assert_eq!(l.pending_registration(), Some(reg));
        assert_eq!(l.state(), LingerState::Registering);
        // The coordinator reports the original reply or an explicit loss.
        assert!(l.complete(reg, -5, Some(7), 3).unwrap());
        assert_eq!(l.setup_result(), Some(-5));
        assert_eq!(l.setup_version(), Some(7));
        assert_eq!(l.state(), LingerState::SetupFailed(-5));
    }

    #[test]
    fn age_uses_older_of_confirmation_and_queued_front() {
        let mut l = entry(NO_DEADLINE);
        establish(&mut l, 0);
        assert_eq!(l.age_us(100), Ok(100));
        let p1 = ping(&mut l, 4);
        assert!(l.complete(p1, -5, None, 5).unwrap());
        l.route_changed(6);
        let r = l.poll_action(6).unwrap();
        assert!(l.complete(r, 0, None, 7).unwrap());
        let p2 = ping(&mut l, 10);
        assert!(l.complete(p2, 0, None, 11).unwrap());
        assert_eq!(l.confirmation_stamp_us(), 10);
        // The queued outage event (older than the new confirmation) keeps
        // age high until the coordinator drains it.
        assert_eq!(l.age_us(100), Ok(95));
        l.poll_error_event();
        assert_eq!(l.age_us(100), Ok(90));
        let mut late = Linger::new(LingerProfile::default(), handle(), 50).unwrap();
        let reg = late.poll_action(50).unwrap();
        assert!(late.complete(reg, 0, None, 50).unwrap());
        assert_eq!(late.age_us(40), Err(LingerError::Clock));
        assert_eq!(late.age_us(60), Ok(10));
    }

    #[test]
    fn disconnect_before_setup_delivery_keeps_both_original_setup_and_error() {
        let mut linger = entry(NO_DEADLINE);
        let registration = linger.poll_action(0).unwrap();
        linger.disconnected(1).unwrap();
        assert_eq!(linger.last_error(), Some(-errno::ENOTCONN));
        assert_eq!(linger.pending_registration(), Some(registration));
        assert_eq!(linger.poll_error_event().unwrap().errno(), -errno::ENOTCONN);
        assert!(linger.complete(registration, 0, Some(17), 2).unwrap());
        assert_eq!(linger.setup_result(), Some(0));
        assert_eq!(linger.setup_version(), Some(17));
        assert_eq!(linger.last_error(), Some(-errno::ENOTCONN));
        assert_eq!(linger.confirmation_stamp_us(), 0);
    }

    #[test]
    fn registered_watch_can_ping_before_pending_reconnect_completes() {
        let mut linger = entry(NO_DEADLINE);
        establish(&mut linger, 0);
        linger.route_changed(1);
        let reconnect = linger.poll_action(1).unwrap();
        let renewal = linger.tick(2, false).unwrap().unwrap();
        assert_eq!(renewal.generation(), reconnect.generation());
        assert!(linger.complete(renewal, -errno::ENOENT, None, 3).unwrap());
        assert_eq!(linger.last_error(), Some(-errno::ENOTCONN));
        assert!(linger.complete(reconnect, 0, Some(19), 4).unwrap());
        assert_eq!(linger.last_error(), None);
        assert_eq!(linger.setup_version(), Some(5));
        assert_eq!(linger.confirmation_stamp_us(), 0);
        let error = linger.poll_error_event().unwrap();
        assert_eq!((error.errno(), error.queued_at_us()), (-errno::ENOTCONN, 3));
    }

    #[test]
    fn canceled_reconnect_completion_does_not_restore_callback_work() {
        let mut linger = entry(NO_DEADLINE);
        establish(&mut linger, 0);
        linger.route_changed(1);
        let reconnect = linger.poll_action(1).unwrap();
        linger.cancel_local(2);
        assert!(linger.complete(reconnect, -errno::ENOENT, None, 3).unwrap());
        assert!(linger.is_canceled());
        assert!(linger.poll_error_event().is_none());
        assert!(!linger.has_pending_work());
        assert_eq!(linger.tick(4, false), Ok(None));
    }

    #[test]
    fn stale_action_is_passive_and_health_rejects_regression_after_confirmation() {
        let mut linger = entry(NO_DEADLINE);
        establish(&mut linger, 0);
        let old = ping(&mut linger, 4);
        linger.route_changed(5);
        let reconnect = linger.poll_action(5).unwrap();
        assert!(linger.complete(reconnect, 0, None, 6).unwrap());
        let current = ping(&mut linger, 7);
        assert!(linger.complete(current, 0, None, 10).unwrap());
        assert_eq!(linger.age_us(9), Err(LingerError::Clock));
        assert_eq!(linger.complete(old, -5, None, 3), Ok(false));
        assert_eq!(linger.state(), LingerState::Established);
        assert_eq!(linger.last_error(), None);
        assert_eq!(linger.confirmation_stamp_us(), 7);
    }
    #[test]
    fn reused_ping_slot_keeps_stale_actions_passive_and_honors_older_confirmation() {
        let mut linger = entry(NO_DEADLINE);
        establish(&mut linger, 0);
        let first = ping(&mut linger, 1);
        let older = ping(&mut linger, 2);
        assert!(linger.complete(first, 0, None, 3).unwrap());
        let replacement = ping(&mut linger, 4);
        assert_eq!(first.ping_slot, replacement.ping_slot);
        assert_ne!(first.id(), replacement.id());
        assert_eq!(linger.complete(first, -5, None, 0), Ok(false));
        assert_eq!(linger.last_error(), None);
        assert!(linger.complete(replacement, 0, None, 5).unwrap());
        assert_eq!(linger.confirmation_stamp_us(), 4);
        assert!(linger.complete(older, 0, None, 6).unwrap());
        assert_eq!(linger.confirmation_stamp_us(), 2);
        assert_eq!(linger.pending_pings(), 0);
        let revoked = ping(&mut linger, 7);
        linger.route_changed(8);
        assert_eq!(linger.pending_pings(), 0);
        let reconnect = linger.poll_action(8).unwrap();
        assert!(linger.complete(reconnect, 0, None, 9).unwrap());
        let current = ping(&mut linger, 10);
        assert_eq!(linger.complete(revoked, -5, None, 0), Ok(false));
        assert!(linger.complete(current, 0, None, 11).unwrap());
        assert_eq!(linger.pending_pings(), 0);
        assert!(!linger.has_pending_work());
    }

    #[test]
    fn repeated_reverse_drains_reuse_storage_and_preallocate_completion_free_slots() {
        let mut linger = entry(NO_DEADLINE);
        establish(&mut linger, 0);
        let mut now = 1;
        let mut capacities = None;
        for _ in 0..16 {
            let actions: Vec<_> = (0..9).map(|_| ping(&mut linger, now)).collect();
            assert!(linger.ping_free.capacity() >= linger.pings.len());
            for action in actions.into_iter().rev() {
                now += 1;
                assert!(linger.complete(action, 0, None, now).unwrap());
            }
            assert_eq!(linger.pending_pings(), 0);
            assert_eq!(linger.pings.len(), 9);
            let actual = (linger.pings.capacity(), linger.ping_free.capacity());
            if let Some(expected) = capacities {
                assert_eq!(actual, expected);
            } else {
                capacities = Some(actual);
            }
        }
    }

    /// Explicit debug-profile measurement; excluded from ordinary correctness runs.
    /// Setup and final ownership checks are outside the timed completion drain.
    #[test]
    #[ignore = "run scripts/test-rustyrados-gaps.sh linger-drain on the build host"]
    fn measure_ping_completion_drains() {
        for depth in [256usize, 1024] {
            for reverse in [false, true] {
                let mut samples = Vec::with_capacity(32);
                for _ in 0..32 {
                    let mut linger = entry(NO_DEADLINE);
                    establish(&mut linger, 0);
                    let mut actions: Vec<_> =
                        (1..=depth).map(|at| ping(&mut linger, at as u64)).collect();
                    if reverse {
                        actions.reverse();
                    }
                    assert_eq!(linger.pending_pings(), depth);
                    let started = std::time::Instant::now();
                    for (ordinal, action) in actions.into_iter().enumerate() {
                        assert!(
                            std::hint::black_box(&mut linger)
                                .complete(
                                    std::hint::black_box(action),
                                    0,
                                    None,
                                    (depth + ordinal + 1) as u64
                                )
                                .unwrap()
                        );
                    }
                    samples.push(started.elapsed().as_nanos());
                    assert_eq!(linger.pending_pings(), 0);
                    assert_eq!(linger.last_error(), None);
                    assert_eq!(
                        linger.confirmation_stamp_us(),
                        if reverse { 1 } else { depth as u64 }
                    );
                    assert!(!linger.has_pending_work());
                }
                samples.sort_unstable();
                let total = samples[samples.len() / 2];
                let order = if reverse { "reverse" } else { "fifo" };
                println!(
                    "{{\"measurement\":\"public_linger_ping_drain\",\"profile\":\"debug\",\"depth\":{depth},\"order\":\"{order}\",\"samples\":32,\"median_total_ns\":{total},\"median_ns_per_op\":{}}}",
                    total / depth as u128
                );
            }
        }
    }
}
