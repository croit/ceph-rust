// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::{AdmissionError, ReadRoute, Target};
use bytes::Bytes;
use opwire::consts::{notify, watch_op};
use opwire::{MWatchNotify, OsdOp};
use std::{
    collections::VecDeque,
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Debug)]
pub enum ControlOperation {
    Register {
        cookie: u64,
        timeout_seconds: u32,
    },
    Reconnect {
        cookie: u64,
        generation: u32,
    },
    Ping {
        cookie: u64,
        generation: u32,
    },
    Unwatch {
        cookie: u64,
    },
    Notify {
        cookie: u64,
        timeout_seconds: u32,
        payload: Bytes,
    },
    NotifyAck {
        cookie: u64,
        notify_id: u64,
        response: Bytes,
    },
}

#[derive(Debug)]
pub struct ControlRequest {
    pub target: Target,
    pub operation: ControlOperation,
}
#[derive(Debug)]
pub struct RejectedControl {
    pub reason: AdmissionError,
    pub request: ControlRequest,
}

/// One typed control with immutable ioctx-compatible request metadata.
#[derive(Debug)]
pub struct ContextualControlRequest {
    pub request: ControlRequest,
    pub context: crate::RequestContext,
}
impl std::ops::Deref for ContextualControlRequest {
    type Target = ControlRequest;
    fn deref(&self) -> &Self::Target {
        &self.request
    }
}
#[derive(Debug)]
pub struct RejectedContextualControl {
    pub reason: AdmissionError,
    pub request: ControlRequest,
    pub context: crate::RequestContext,
}
impl ContextualControlRequest {
    pub(crate) fn charge(&self) -> Option<u64> {
        self.operation
            .charge()?
            .checked_add((self.context.snapshots.capacity() as u64).checked_mul(8)?)
    }
    pub fn validate(&self) -> Result<(), AdmissionError> {
        self.operation.validate()?;
        let c = &self.context;
        if c.legacy_reply || c.read_op.is_some() || c.write_op.is_some() {
            return Err(AdmissionError::InvalidOperation);
        }
        if (self.operation.writes() && c.snapid != opwire::NOSNAP)
            || (!self.operation.writes() && (c.snap_sequence != 0 || !c.snapshots.is_empty()))
            || c.snapshots.first().is_some_and(|&id| id > c.snap_sequence)
            || c.snapshots.windows(2).any(|ids| ids[0] <= ids[1])
            || c.snap_sequence >= opwire::NOSNAP
            || c.snapshots.iter().any(|&id| id >= opwire::NOSNAP)
        {
            return Err(AdmissionError::InvalidSnapshot);
        }
        Ok(())
    }
}
impl ControlOperation {
    pub fn cookie(&self) -> u64 {
        match self {
            Self::Register { cookie, .. }
            | Self::Reconnect { cookie, .. }
            | Self::Ping { cookie, .. }
            | Self::Unwatch { cookie }
            | Self::Notify { cookie, .. }
            | Self::NotifyAck { cookie, .. } => *cookie,
        }
    }
    pub(crate) fn writes(&self) -> bool {
        matches!(
            self,
            Self::Register { .. } | Self::Reconnect { .. } | Self::Unwatch { .. }
        )
    }
    pub(crate) fn max_output(&self) -> u64 {
        if matches!(self, Self::Notify { .. }) {
            8
        } else {
            0
        }
    }
    pub(crate) fn charge(&self) -> Option<u64> {
        Some(
            self.max_output()
                + match self {
                    Self::Notify { payload, .. } => payload.len() as u64,
                    Self::NotifyAck { response, .. } => response.len() as u64,
                    _ => 0,
                },
        )
    }
    pub(crate) fn validate(&self) -> Result<(), AdmissionError> {
        if self.cookie() == 0 && !matches!(self, Self::NotifyAck { .. }) {
            return Err(AdmissionError::InvalidOperation);
        }
        match self {
            Self::Notify { payload, .. } if payload.len() > u32::MAX as usize - 12 => {
                return Err(AdmissionError::InvalidOperation);
            }
            Self::NotifyAck { response, .. } if response.len() > u32::MAX as usize - 20 => {
                return Err(AdmissionError::InvalidOperation);
            }
            _ => {}
        }
        Ok(())
    }
    pub(crate) fn wire_op(&self) -> OsdOp {
        match self {
            Self::Register {
                cookie,
                timeout_seconds,
            } => OsdOp::watch_op(*cookie, watch_op::WATCH, *timeout_seconds),
            Self::Reconnect { cookie, generation } | Self::Ping { cookie, generation } => {
                let mut o = OsdOp::watch_op(
                    *cookie,
                    if matches!(self, Self::Ping { .. }) {
                        watch_op::PING
                    } else {
                        watch_op::RECONNECT
                    },
                    0,
                );
                let mut w = o.watch();
                w.gen_ = *generation;
                o.set_watch(w);
                o
            }
            Self::Unwatch { cookie } => OsdOp::watch_op(*cookie, watch_op::UNWATCH, 0),
            Self::Notify {
                cookie,
                timeout_seconds,
                payload,
            } => OsdOp::notify_op(*cookie, *timeout_seconds, payload),
            Self::NotifyAck {
                cookie,
                notify_id,
                response,
            } => OsdOp::notify_ack(*notify_id, *cookie, response),
        }
    }
}

#[derive(Debug)]
struct IdentitySource(AtomicU64);
impl IdentitySource {
    const fn new(last_allocated: u64) -> Self {
        Self(AtomicU64::new(last_allocated))
    }
    fn allocate(&self) -> Result<u64, WatchError> {
        self.0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                last.checked_add(1)
            })
            .map(|last| last + 1)
            .map_err(|_| WatchError::IdentityExhausted)
    }
}
static NEXT_DOMAIN: IdentitySource = IdentitySource::new(0);
static NEXT_COOKIE: IdentitySource = IdentitySource::new(0);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchHandle {
    domain: u64,
    slot: usize,
    cookie: u64,
}
impl WatchHandle {
    pub fn cookie(self) -> u64 {
        self.cookie
    }
}
/// Captured prefix of local payload delivery; not remote ACK or application processing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchEventWatermark {
    domain: u64,
    sequence: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchKind {
    Watch,
    Notify,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchError {
    Local(crate::LocalRequestError),
    /// Authenticated watch-control rejection, including client blocklisting.
    Remote(i32),
    Clock,
    Stale,
    NoCredit,
    InvalidEvent,
    Disconnected,
    IdentityExhausted,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WatchEvent {
    Notification {
        cookie: u64,
        notify_id: u64,
        notifier_gid: u64,
        version: u64,
        payload: Vec<u8>,
    },
    NotifyComplete {
        cookie: u64,
        notify_id: u64,
        result: i32,
        data: Vec<u8>,
    },
}
impl WatchEvent {
    fn cookie(&self) -> u64 {
        match self {
            Self::Notification { cookie, .. } | Self::NotifyComplete { cookie, .. } => *cookie,
        }
    }
    fn charge(&self) -> u64 {
        match self {
            Self::Notification { payload, .. } => payload.capacity() as u64,
            Self::NotifyComplete { data, .. } => data.capacity() as u64,
        }
    }
}
#[derive(Debug)]
struct Entry {
    handle: WatchHandle,
    target: Target,
    route: Option<ReadRoute>,
    kind: WatchKind,
    generation: u32,
    connected: bool,
    suspended: bool,
    removing: bool,
    faulted: bool,
    error: Option<WatchError>,
    notify_id: Option<u64>,
    final_seen: bool,
    charge: u64,
}

/// Single-owner event broker. No callbacks or automatic ACKs; errors reserve one bit
/// per live cookie independently of event FIFO capacity. Caller must terminate failed delivery on overflow.
#[derive(Debug)]
pub struct WatchRegistry {
    domain: u64,
    slots: Vec<Option<Entry>>,
    /// Occupied `slots`: the idle checks an owner runs every turn are O(1) without watches.
    occupied: usize,
    /// Entries holding an untaken `error`: the error poll and the pending check an owner runs every turn are O(1)
    /// until a watch faults (the slots are scanned only while one is set).
    errors: usize,
    events: VecDeque<(u64, Option<u64>, WatchEvent)>,
    event_clock: u64,
    event_sequence: u64,
    event_limit: usize,
    byte_limit: u64,
    charged: u64,
    event_bytes: u64,
    max_event_capacity: Option<u64>,
    elastic_registrations: bool,
    elastic_events: bool,
    _owner: PhantomData<Rc<()>>,
}
impl WatchRegistry {
    pub fn new(capacity: usize, event_limit: usize, byte_limit: u64) -> Option<Self> {
        Self::new_inner(capacity, event_limit, byte_limit, None)
    }
    /// Explicit compatible payload admission; metadata remains strictly bounded.
    /// Zero-byte events remain holders. The hard bound applies to retained capacity.
    pub fn with_compatible_events(
        capacity: usize,
        event_limit: usize,
        byte_target: u64,
        max_event_capacity: u64,
    ) -> Option<Self> {
        if byte_target == 0
            || max_event_capacity == 0
            || usize::try_from(max_event_capacity).is_err()
        {
            return None;
        }
        Self::new_inner(capacity, event_limit, byte_target, Some(max_event_capacity))
    }
    /// Application-compatible registration population; event limits stay independent.
    pub fn with_compatible_registrations(
        capacity: usize,
        event_limit: usize,
        byte_target: u64,
        max_event_capacity: u64,
    ) -> Option<Self> {
        let mut registry =
            Self::with_compatible_events(capacity, event_limit, byte_target, max_event_capacity)?;
        registry.elastic_registrations = true;
        Some(registry)
    }
    /// Full-compatibility delivery: registrations and queued event count/aggregate
    /// bytes grow with actual work. `capacity`, `event_initial` and `byte_target`
    /// are allocation/metadata hints; `max_event_capacity` stays the per-event bound.
    /// Only a real allocation failure or checked-arithmetic overflow refuses an event.
    pub fn with_compatible_delivery(
        capacity: usize,
        event_initial: usize,
        byte_target: u64,
        max_event_capacity: u64,
    ) -> Option<Self> {
        let mut registry =
            Self::with_compatible_registrations(capacity, 1, byte_target, max_event_capacity)?;
        let mut events = VecDeque::new();
        events.try_reserve_exact(event_initial).ok()?;
        registry.events = events;
        registry.elastic_events = true;
        Some(registry)
    }
    fn new_inner(
        capacity: usize,
        event_limit: usize,
        byte_limit: u64,
        max_event_capacity: Option<u64>,
    ) -> Option<Self> {
        if capacity == 0 || event_limit == 0 {
            return None;
        }
        let domain = NEXT_DOMAIN.allocate().ok()?;
        Some(Self {
            domain,
            slots: (0..capacity).map(|_| None).collect(),
            occupied: 0,
            errors: 0,
            events: VecDeque::with_capacity(event_limit),
            event_sequence: 0,
            event_clock: 0,
            event_limit,
            byte_limit,
            charged: 0,
            event_bytes: 0,
            max_event_capacity,
            elastic_registrations: false,
            elastic_events: false,
            _owner: PhantomData,
        })
    }
    pub fn event_watermark(&self) -> WatchEventWatermark {
        WatchEventWatermark {
            domain: self.domain,
            sequence: self.event_sequence,
        }
    }
    /// True when the captured prefix has been polled or explicitly discarded.
    /// Events already transferred to caller ownership need no further acknowledgment.
    pub fn events_drained(&self, mark: WatchEventWatermark) -> Result<bool, WatchError> {
        if mark.domain != self.domain {
            return Err(WatchError::Stale);
        }
        Ok(self
            .events
            .front()
            .is_none_or(|(seq, _, _)| *seq > mark.sequence))
    }
    pub fn charged_bytes(&self) -> u64 {
        self.charged
    }
    /// No watch/notify handles, pending errors or retained deliveries.
    pub fn is_empty(&self) -> bool {
        self.occupied == 0 && self.events.is_empty()
    }
    /// Allocated watch/notify handles, including faulted or removing entries.
    pub fn len(&self) -> usize {
        self.occupied
    }
    /// Caller-visible deliveries or reserved errors remain to be consumed.
    pub fn has_pending_events(&self) -> bool {
        !self.events.is_empty() || self.errors > 0
    }
    pub fn reserve(
        &mut self,
        target: Target,
        route: ReadRoute,
        kind: WatchKind,
    ) -> Result<WatchHandle, (WatchError, Target)> {
        self.reserve_inner(target, Some(route), kind)
    }
    /// Allocate a managed watch identity before a route exists. No ingress is
    /// accepted until bind_managed supplies a real route.
    pub fn reserve_unbound_watch(
        &mut self,
        target: Target,
    ) -> Result<WatchHandle, (WatchError, Target)> {
        self.reserve_inner(target, None, WatchKind::Watch)
    }
    fn reserve_inner(
        &mut self,
        target: Target,
        route: Option<ReadRoute>,
        kind: WatchKind,
    ) -> Result<WatchHandle, (WatchError, Target)> {
        let charge = (target.object.capacity() as u64)
            .checked_add(target.namespace.capacity() as u64)
            .and_then(|n| n.checked_add(target.locator.capacity() as u64));
        let slot = match self.slots.iter().position(Option::is_none) {
            Some(slot) => slot,
            None if self.elastic_registrations && self.slots.try_reserve(1).is_ok() => {
                let slot = self.slots.len();
                self.slots.push(None);
                slot
            }
            None => return Err((WatchError::NoCredit, target)),
        };
        let metadata_used = if self.max_event_capacity.is_some() {
            self.charged - self.event_bytes
        } else {
            self.charged
        };
        if charge.is_none_or(|n| {
            (!self.elastic_registrations && n > self.byte_limit.saturating_sub(metadata_used))
                || self.charged.checked_add(n).is_none()
        }) {
            return Err((WatchError::NoCredit, target));
        }
        let cookie = match NEXT_COOKIE.allocate() {
            Ok(cookie) => cookie,
            Err(error) => return Err((error, target)),
        };
        let handle = WatchHandle {
            domain: self.domain,
            slot,
            cookie,
        };
        let charge = charge.unwrap();
        self.charged += charge;
        self.occupied += 1;
        self.slots[slot] = Some(Entry {
            handle,
            target,
            route,
            kind,
            generation: 0,
            connected: false,
            suspended: false,
            removing: false,
            faulted: false,
            error: None,
            notify_id: None,
            final_seen: false,
            charge,
        });
        Ok(handle)
    }
    fn entry(&mut self, handle: WatchHandle) -> Result<&mut Entry, WatchError> {
        self.slots
            .get_mut(handle.slot)
            .and_then(Option::as_mut)
            .filter(|e| e.handle == handle)
            .ok_or(WatchError::Stale)
    }
    pub fn target(&self, handle: WatchHandle) -> Option<&Target> {
        self.slots
            .get(handle.slot)
            .and_then(Option::as_ref)
            .filter(|e| e.handle == handle)
            .map(|e| &e.target)
    }
    pub fn handle_for_cookie(&self, cookie: u64) -> Option<WatchHandle> {
        self.slots
            .iter()
            .flatten()
            .find(|e| e.handle.cookie == cookie)
            .map(|e| e.handle)
    }
    pub fn route(&self, handle: WatchHandle) -> Option<ReadRoute> {
        self.slots
            .get(handle.slot)?
            .as_ref()
            .filter(|e| e.handle == handle)
            .and_then(|e| e.route)
    }
    pub fn kind(&self, handle: WatchHandle) -> Option<WatchKind> {
        self.slots
            .get(handle.slot)?
            .as_ref()
            .filter(|e| e.handle == handle)
            .map(|e| e.kind)
    }
    pub fn generation(&self, handle: WatchHandle) -> Option<u32> {
        self.slots
            .get(handle.slot)?
            .as_ref()
            .filter(|e| e.handle == handle)
            .map(|e| e.generation)
    }
    pub fn live(&self, handle: WatchHandle) -> bool {
        self.slots
            .get(handle.slot)
            .and_then(Option::as_ref)
            .is_some_and(|e| e.handle == handle && !e.faulted && !e.removing)
    }
    pub fn fault_all(&mut self, reason: WatchError) {
        for e in self.slots.iter_mut().flatten().filter(|e| !e.faulted) {
            e.connected = false;
            e.faulted = true;
            self.errors += usize::from(e.error.replace(reason).is_none());
        }
        for (_, _, event) in self.events.drain(..) {
            self.charged -= event.charge();
            self.event_bytes -= event.charge();
        }
    }
    pub fn fault(&mut self, handle: WatchHandle, reason: WatchError) -> Result<(), WatchError> {
        let e = self.entry(handle)?;
        if !e.faulted {
            e.connected = false;
            e.faulted = true;
            let first = e.error.replace(reason).is_none();
            self.errors += usize::from(first);
        }
        Ok(())
    }
    pub fn activate(&mut self, handle: WatchHandle, generation: u32) -> Result<(), WatchError> {
        let e = self.entry(handle)?;
        if e.kind != WatchKind::Watch || e.generation != generation || e.faulted || e.removing {
            return Err(WatchError::Stale);
        }
        e.connected = true;
        Ok(())
    }
    /// Driver-only transition after consuming an authenticated redirect or EAGAIN reply.
    /// Retains the cookie, generation, activation and notification ownership.
    pub fn reroute_control(
        &mut self,
        handle: WatchHandle,
        route: ReadRoute,
    ) -> Result<(), WatchError> {
        let e = self.entry(handle)?;
        if e.faulted
            || e.removing
            || route.base_pool != e.target.pool
            || !route.pool.valid()
            || route.osd < 0
            || route.session == 0
            || route.epoch == 0
            || (e.kind == WatchKind::Notify && e.notify_id.is_some())
        {
            return Err(WatchError::Stale);
        }
        e.route = Some(route);
        Ok(())
    }
    pub fn rebind(&mut self, handle: WatchHandle, route: ReadRoute) -> Result<u32, WatchError> {
        let e = self.entry(handle)?;
        if e.kind != WatchKind::Watch || e.removing {
            return Err(WatchError::Stale);
        }
        let generation = e
            .generation
            .checked_add(1)
            .ok_or(WatchError::IdentityExhausted)?;
        e.route = Some(route);
        e.suspended = false;
        e.generation = generation;
        e.connected = false;
        e.faulted = false;
        let cleared = e.error.take().is_some();
        self.errors -= usize::from(cleared);
        Ok(generation)
    }
    /// Revoke ingress during a managed transport outage without inventing a server error.
    pub fn suspend(&mut self, handle: WatchHandle) -> Result<(), WatchError> {
        let e = self.entry(handle)?;
        if e.kind != WatchKind::Watch || e.faulted || e.removing {
            return Err(WatchError::Stale);
        }
        e.connected = false;
        e.suspended = true;
        Ok(())
    }
    pub fn bind_managed(
        &mut self,
        handle: WatchHandle,
        route: ReadRoute,
        generation: u32,
    ) -> Result<(), WatchError> {
        let e = self.entry(handle)?;
        if e.kind != WatchKind::Watch || e.faulted || e.removing || generation < e.generation {
            return Err(WatchError::Stale);
        }
        e.route = Some(route);
        e.generation = generation;
        e.suspended = false;
        Ok(())
    }
    pub fn fault_unsuspended_route(&mut self, osd: i32, session: u64, reason: WatchError) {
        for e in self.slots.iter_mut().flatten().filter(|e| {
            e.route
                .is_some_and(|r| r.osd == osd && r.session == session)
                && !e.faulted
                && !e.suspended
        }) {
            e.connected = false;
            e.faulted = true;
            self.errors += usize::from(e.error.replace(reason).is_none());
        }
    }
    /// Local ingress cutoff after UNWATCH admission, preserving payloads and first error.
    pub fn mark_removing(&mut self, handle: WatchHandle) -> Result<(), WatchError> {
        let e = self.entry(handle)?;
        if e.kind != WatchKind::Watch {
            return Err(WatchError::Stale);
        }
        e.removing = true;
        e.suspended = true;
        e.connected = false;
        Ok(())
    }
    /// Route binding for UNWATCH only; cannot revive delivery, generation or health.
    pub fn bind_cleanup(
        &mut self,
        handle: WatchHandle,
        route: ReadRoute,
    ) -> Result<(), WatchError> {
        let e = self.entry(handle)?;
        if e.kind != WatchKind::Watch || !e.removing {
            return Err(WatchError::Stale);
        }
        e.route = Some(route);
        Ok(())
    }
    pub fn initial_notify_id(&mut self, handle: WatchHandle, id: u64) -> Result<(), WatchError> {
        let e = self.entry(handle)?;
        if e.kind != WatchKind::Notify || id == 0 || e.notify_id.is_some_and(|old| old != id) {
            return Err(WatchError::InvalidEvent);
        }
        e.notify_id = Some(id);
        Ok(())
    }
    pub fn oldest_event_us(&self, handle: WatchHandle) -> Result<Option<u64>, WatchError> {
        if self.target(handle).is_none() {
            return Err(WatchError::Stale);
        }
        let mut oldest = None;
        for (_, time, event) in &self.events {
            if event.cookie() == handle.cookie() {
                let time = time.ok_or(WatchError::InvalidEvent)?;
                oldest = Some(oldest.map_or(time, |old: u64| old.min(time)));
            }
        }
        Ok(oldest)
    }
    pub fn on_event_at(
        &mut self,
        osd: i32,
        session: u64,
        msg: MWatchNotify,
        now_us: u64,
    ) -> Result<bool, WatchError> {
        if now_us < self.event_clock || crate::time::validate_clock(now_us).is_err() {
            return Err(WatchError::Clock);
        }
        self.event_clock = now_us;
        self.ingest(osd, session, msg, Some(now_us))
    }
    /// true = event accepted; false = stale/unknown/duplicate final ignored.
    pub fn on_event(
        &mut self,
        osd: i32,
        session: u64,
        msg: MWatchNotify,
    ) -> Result<bool, WatchError> {
        self.ingest(osd, session, msg, None)
    }
    fn ingest(
        &mut self,
        osd: i32,
        session: u64,
        msg: MWatchNotify,
        time: Option<u64>,
    ) -> Result<bool, WatchError> {
        let Some(slot) = self
            .slots
            .iter()
            .position(|e| e.as_ref().is_some_and(|e| e.handle.cookie == msg.cookie))
        else {
            return Ok(false);
        };
        let e = self.slots[slot].as_mut().unwrap();
        if e.route.is_none_or(|r| r.osd != osd || r.session != session) || e.faulted || e.suspended
        {
            return Ok(false);
        }
        if msg.msg_ver != 1 {
            return Err(WatchError::InvalidEvent);
        }
        let event = match msg.opcode {
            notify::DISCONNECT if e.kind == WatchKind::Watch => {
                e.connected = false;
                e.faulted = true;
                let first = e.error.replace(WatchError::Disconnected).is_none();
                self.errors += usize::from(first);
                return Ok(true);
            }
            notify::NOTIFY
                if e.kind == WatchKind::Watch && msg.notify_id != 0 && msg.data.is_empty() =>
            {
                WatchEvent::Notification {
                    cookie: msg.cookie,
                    notify_id: msg.notify_id,
                    notifier_gid: msg.notifier_gid,
                    version: msg.ver,
                    payload: msg.bl,
                }
            }
            notify::NOTIFY_COMPLETE
                if e.kind == WatchKind::Notify && msg.notify_id != 0 && msg.bl.is_empty() =>
            {
                if e.notify_id.is_some_and(|id| id != msg.notify_id) || e.final_seen {
                    return Ok(false);
                }
                WatchEvent::NotifyComplete {
                    cookie: msg.cookie,
                    notify_id: msg.notify_id,
                    result: msg.return_code,
                    data: msg.data,
                }
            }
            _ => return Err(WatchError::InvalidEvent),
        };
        let charge = event.charge();
        if self.elastic_events {
            // Population and aggregate bytes follow actual owned work; only the
            // per-event bound, checked totals and real allocation can refuse.
            if self
                .max_event_capacity
                .is_none_or(|maximum| charge > maximum)
                || self.charged.checked_add(charge).is_none()
                || self.event_bytes.checked_add(charge).is_none()
                || self.events.try_reserve(1).is_err()
            {
                return Err(WatchError::NoCredit);
            }
        } else {
            let fits = if let Some(maximum) = self.max_event_capacity {
                charge <= maximum
                    && crate::ByteAdmission::compatible(self.byte_limit)
                        .admit(self.event_bytes, self.events.len(), charge)
                        .is_ok()
            } else {
                charge <= self.byte_limit - self.charged
            };
            if self.events.len() >= self.event_limit
                || !fits
                || self.charged.checked_add(charge).is_none()
            {
                return Err(WatchError::NoCredit);
            }
        }
        let sequence = self
            .event_sequence
            .checked_add(1)
            .ok_or(WatchError::IdentityExhausted)?;
        if e.kind == WatchKind::Notify {
            e.notify_id = Some(msg.notify_id);
            e.final_seen = true;
        }
        self.charged += charge;
        self.event_bytes += charge;
        self.event_sequence = sequence;
        self.events.push_back((sequence, time, event));
        Ok(true)
    }
    pub fn fault_route(&mut self, osd: i32, session: u64, reason: WatchError) {
        for e in self.slots.iter_mut().flatten().filter(|e| {
            e.route
                .is_some_and(|r| r.osd == osd && r.session == session)
                && !e.faulted
        }) {
            e.connected = false;
            e.faulted = true;
            self.errors += usize::from(e.error.replace(reason).is_none());
        }
    }
    pub fn poll_error(&mut self) -> Option<(WatchHandle, WatchError)> {
        if self.errors == 0 {
            return None;
        }
        let taken = self
            .slots
            .iter_mut()
            .flatten()
            .find_map(|e| e.error.take().map(|error| (e.handle, error)));
        self.errors -= usize::from(taken.is_some());
        taken
    }
    pub fn poll(&mut self) -> Option<WatchEvent> {
        let (_, _, event) = self.events.pop_front()?;
        self.charged -= event.charge();
        self.event_bytes -= event.charge();
        Some(event)
    }
    pub fn remove(&mut self, handle: WatchHandle) -> Result<(), WatchError> {
        self.entry(handle)?;
        self.events.retain(|(_, _, event)| {
            if event.cookie() != handle.cookie {
                true
            } else {
                self.charged -= event.charge();
                self.event_bytes -= event.charge();
                false
            }
        });
        let entry = self.slots[handle.slot].take().unwrap();
        self.occupied -= 1;
        self.errors -= usize::from(entry.error.is_some());
        self.charged -= entry.charge;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_clock_crosses_old_horizon_without_accepting_regression_or_infinity() {
        let mut registry = WatchRegistry::new(1, 1, 1024).unwrap();
        let handle = registry
            .reserve(
                Target {
                    pool: 1,
                    object: vec![1],
                    namespace: vec![],
                    locator: vec![],
                },
                ReadRoute {
                    direct_read: false,
                    base_pool: 1,
                    osd: 2,
                    session: 3,
                    pg: Default::default(),
                    hash: 0,
                    epoch: 1,
                    features: 0,
                    generation: 1,
                    pool: crate::PoolRoute::Replicated,
                },
                WatchKind::Watch,
            )
            .unwrap();
        let message = || MWatchNotify {
            msg_ver: 1,
            opcode: notify::NOTIFY,
            cookie: handle.cookie(),
            notify_id: 1,
            ..Default::default()
        };
        let now = (1u64 << 32) * 1_000_000;
        assert_eq!(registry.on_event_at(2, 3, message(), now), Ok(true));
        let mark = registry.event_watermark();
        assert_eq!(
            registry.on_event_at(2, 3, message(), now - 1),
            Err(WatchError::Clock)
        );
        assert_eq!(
            registry.on_event_at(2, 3, message(), crate::time::NO_DEADLINE),
            Err(WatchError::Clock)
        );
        assert_eq!(registry.event_watermark(), mark);
        assert!(registry.poll().is_some());
        assert!(registry.poll().is_none());
    }
    #[test]
    fn error_count_tracks_set_taken_and_removed_errors() {
        let mut r = WatchRegistry::new(3, 1, 4096).unwrap();
        let route = ReadRoute {
            direct_read: false,
            base_pool: 1,
            osd: 2,
            session: 3,
            pg: Default::default(),
            hash: 0,
            epoch: 1,
            features: 0,
            generation: 1,
            pool: crate::PoolRoute::Replicated,
        };
        let target = |object: u8| Target {
            pool: 1,
            object: vec![object],
            namespace: vec![],
            locator: vec![],
        };
        let a = r.reserve(target(1), route, WatchKind::Watch).unwrap();
        let b = r.reserve(target(2), route, WatchKind::Watch).unwrap();
        let c = r.reserve(target(3), route, WatchKind::Watch).unwrap();
        assert!(!r.has_pending_events());
        assert_eq!(r.poll_error(), None);
        // A second fault of a faulted entry neither replaces its error nor counts twice.
        r.fault(a, WatchError::Disconnected).unwrap();
        r.fault(a, WatchError::Stale).unwrap();
        assert!(r.has_pending_events());
        assert_eq!(r.poll_error(), Some((a, WatchError::Disconnected)));
        assert!(!r.has_pending_events());
        assert_eq!(r.poll_error(), None);
        // A removed entry takes its untaken error with it.
        r.fault(b, WatchError::Disconnected).unwrap();
        r.remove(b).unwrap();
        assert!(!r.has_pending_events());
        assert_eq!(r.poll_error(), None);
        // One route fault reaches every unfaulted entry on it, each error polled once.
        r.fault_all(WatchError::Disconnected);
        assert_eq!(r.poll_error(), Some((c, WatchError::Disconnected)));
        assert_eq!(r.poll_error(), None);
        assert!(!r.has_pending_events());
    }
    #[test]
    fn notify_ack_preserves_zero_identifiers_for_abi_callers() {
        let operation = ControlOperation::NotifyAck {
            cookie: 0,
            notify_id: 0,
            response: Bytes::new(),
        };
        assert_eq!(operation.validate(), Ok(()));
        let wire = operation.wire_op();
        assert_eq!(wire.op, opwire::op::NOTIFY_ACK);
        assert_eq!(&wire.indata[..16], &[0; 16]);
    }
    #[test]
    fn event_sequence_exhaustion_preserves_notify_state_and_credit() {
        let mut r = WatchRegistry::new(1, 1, 1024).unwrap();
        let route = ReadRoute {
            direct_read: false,
            base_pool: 1,
            osd: 2,
            session: 3,
            pg: Default::default(),
            hash: 0,
            epoch: 1,
            features: 0,
            generation: 1,
            pool: crate::PoolRoute::Replicated,
        };
        let h = r
            .reserve(
                Target {
                    pool: 1,
                    object: vec![1],
                    namespace: vec![],
                    locator: vec![],
                },
                route,
                WatchKind::Notify,
            )
            .unwrap();
        r.event_sequence = u64::MAX;
        let mark = r.event_watermark();
        let credit = r.charged_bytes();
        let m = MWatchNotify {
            msg_ver: 1,
            opcode: notify::NOTIFY_COMPLETE,
            cookie: h.cookie(),
            notify_id: 99,
            data: vec![1],
            ..Default::default()
        };
        assert_eq!(r.on_event(2, 3, m), Err(WatchError::IdentityExhausted));
        assert_eq!(r.event_watermark(), mark);
        assert_eq!(r.charged_bytes(), credit);
        assert!(r.poll().is_none());
        let e = r.entry(h).unwrap();
        assert_eq!(e.notify_id, None);
        assert!(!e.final_seen);
        assert!(!e.faulted);
    }
}

#[cfg(test)]
mod compatible_resource_tests {
    use super::*;

    #[test]
    fn identities_cross_the_old_partition_and_preserve_full_wire_cookies() {
        let source = IdentitySource::new(u64::from(u32::MAX) - 1);
        for expected in [
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            u64::from(u32::MAX) + 2,
        ] {
            let cookie = source.allocate().unwrap();
            assert_eq!(cookie, expected);
            let operation = ControlOperation::Register {
                cookie,
                timeout_seconds: 30,
            };
            operation.validate().unwrap();
            assert_eq!(operation.wire_op().watch().cookie, expected);
        }
        let source = IdentitySource::new(u64::MAX - 1);
        assert_eq!(source.allocate(), Ok(u64::MAX));
        assert_eq!(source.allocate(), Err(WatchError::IdentityExhausted));
        assert_eq!(source.allocate(), Err(WatchError::IdentityExhausted));
        assert_eq!(source.0.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn reused_watch_and_notify_slots_never_alias_a_stale_or_foreign_cookie() {
        for kind in [WatchKind::Watch, WatchKind::Notify] {
            let mut registry = WatchRegistry::new(1, 1, 4096).unwrap();
            let old = registry.reserve(target(), route(), kind).unwrap();
            registry.remove(old).unwrap();
            let current = registry.reserve(target(), route(), kind).unwrap();
            assert_ne!(old.cookie(), current.cookie());
            assert_ne!(current.cookie(), 0);
            assert!(registry.target(old).is_none());
            assert!(registry.handle_for_cookie(old.cookie()).is_none());
            assert_eq!(registry.handle_for_cookie(current.cookie()), Some(current));
            let before = registry.charged_bytes();
            assert_eq!(
                registry.on_event(2, 3, notification(old, 1, vec![7])),
                Ok(false)
            );
            assert_eq!(registry.charged_bytes(), before);
            let mut other = WatchRegistry::new(1, 1, 4096).unwrap();
            let foreign = other.reserve(target(), route(), kind).unwrap();
            assert_ne!(foreign.cookie(), current.cookie());
            assert!(registry.target(foreign).is_none());
            assert!(registry.handle_for_cookie(foreign.cookie()).is_none());
            assert!(other.target(current).is_none());
            assert!(registry.handle_for_cookie(0).is_none());
        }
    }
    fn route() -> ReadRoute {
        ReadRoute {
            direct_read: false,
            base_pool: 1,
            osd: 2,
            session: 3,
            pg: Default::default(),
            hash: 0,
            epoch: 1,
            features: 0,
            generation: 1,
            pool: crate::PoolRoute::Replicated,
        }
    }
    fn target() -> Target {
        Target {
            pool: 1,
            object: vec![1; 4],
            namespace: vec![],
            locator: vec![],
        }
    }
    fn message(h: WatchHandle, data: Vec<u8>) -> MWatchNotify {
        MWatchNotify {
            msg_ver: 1,
            opcode: notify::NOTIFY_COMPLETE,
            cookie: h.cookie(),
            notify_id: 9,
            data,
            ..Default::default()
        }
    }
    #[test]
    fn compatible_event_oversize_is_independent_of_metadata_and_strict_remains_strict() {
        let mut strict = WatchRegistry::new(2, 2, 8).unwrap();
        let h = strict
            .reserve(target(), route(), WatchKind::Notify)
            .unwrap();
        assert_eq!(
            strict.on_event(2, 3, message(h, vec![1; 12])),
            Err(WatchError::NoCredit)
        );
        let mut r = WatchRegistry::with_compatible_events(2, 2, 8, 32).unwrap();
        let h = r.reserve(target(), route(), WatchKind::Notify).unwrap();
        assert_eq!(r.on_event(2, 3, message(h, vec![1; 12])), Ok(true));
        // Metadata reserve must not subtract oversized payload occupancy from its target.
        let second = r.reserve(target(), route(), WatchKind::Notify).unwrap();
        assert_eq!(r.charged_bytes(), 20);
        assert_eq!(
            r.on_event(2, 3, message(second, vec![])),
            Err(WatchError::NoCredit)
        );
        assert_eq!(r.entry(second).unwrap().notify_id, None);
        assert!(r.poll().is_some());
        assert_eq!(r.charged_bytes(), 8);
        assert_eq!(r.on_event(2, 3, message(second, vec![2; 12])), Ok(true));
        r.remove(second).unwrap();
        assert_eq!(r.charged_bytes(), 4);
        assert_eq!(r.event_bytes, 0);
        r.remove(h).unwrap();
        assert_eq!(r.charged_bytes(), 0);
    }
    #[test]
    fn zero_byte_holders_and_spare_capacity_preserve_admission_and_final_identity() {
        let mut r = WatchRegistry::with_compatible_events(2, 2, 8, 32).unwrap();
        let a = r.reserve(target(), route(), WatchKind::Notify).unwrap();
        let b = r.reserve(target(), route(), WatchKind::Notify).unwrap();
        assert_eq!(r.on_event(2, 3, message(a, vec![])), Ok(true));
        assert_eq!(
            r.on_event(2, 3, message(b, vec![1; 12])),
            Err(WatchError::NoCredit)
        );
        assert!(r.poll().is_some());
        let mut slack = Vec::with_capacity(33);
        slack.push(1);
        let watermark = r.event_watermark();
        assert_eq!(
            r.on_event(2, 3, message(b, slack)),
            Err(WatchError::NoCredit)
        );
        assert_eq!(r.event_watermark(), watermark);
        assert_eq!(r.entry(b).unwrap().notify_id, None);
        assert_eq!(r.on_event(2, 3, message(b, vec![1; 12])), Ok(true));
        r.fault_all(WatchError::Disconnected);
        assert_eq!(r.event_bytes, 0);
        assert_eq!(r.charged_bytes(), 8);
        assert!(r.poll().is_none());
        r.remove(a).unwrap();
        r.remove(b).unwrap();
        assert_eq!(r.charged_bytes(), 0);
    }
    fn notification(h: WatchHandle, id: u64, payload: Vec<u8>) -> MWatchNotify {
        MWatchNotify {
            msg_ver: 1,
            opcode: notify::NOTIFY,
            cookie: h.cookie(),
            notify_id: id,
            bl: payload,
            ..Default::default()
        }
    }
    fn exact(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        v.resize(n, 7);
        v
    }
    #[test]
    fn delivery_burst_beyond_initial_and_target_keeps_fifo_and_exact_charges() {
        let mut r = WatchRegistry::with_compatible_delivery(1, 2, 8, 64).unwrap();
        let h = r.reserve(target(), route(), WatchKind::Watch).unwrap();
        let metadata = r.charged_bytes();
        let mut expected = 0;
        for id in 1..=40u64 {
            assert_eq!(r.on_event(2, 3, notification(h, id, exact(16))), Ok(true));
            expected += 16;
            assert_eq!(r.charged_bytes(), metadata + expected);
        }
        assert!(r.event_bytes > 8 && r.events.len() > 2);
        for id in 1..=40u64 {
            match r.poll().unwrap() {
                WatchEvent::Notification {
                    notify_id, payload, ..
                } => {
                    assert_eq!(notify_id, id);
                    assert_eq!(payload.capacity() as u64, 16);
                }
                other => panic!("{other:?}"),
            }
            expected -= 16;
            assert_eq!(r.charged_bytes(), metadata + expected);
        }
        assert!(r.poll().is_none());
        assert_eq!(r.event_bytes, 0);
        r.remove(h).unwrap();
        assert_eq!(r.charged_bytes(), 0);
    }
    #[test]
    fn delivery_keeps_per_event_maximum_and_registration_growth() {
        let mut r = WatchRegistry::with_compatible_delivery(1, 1, 4, 16).unwrap();
        let a = r.reserve(target(), route(), WatchKind::Watch).unwrap();
        let b = r.reserve(target(), route(), WatchKind::Watch).unwrap();
        let watermark = r.event_watermark();
        assert_eq!(
            r.on_event(2, 3, notification(a, 1, exact(17))),
            Err(WatchError::NoCredit)
        );
        assert_eq!(r.event_watermark(), watermark);
        assert_eq!(r.event_bytes, 0);
        assert_eq!(r.on_event(2, 3, notification(b, 2, exact(16))), Ok(true));
        assert_eq!(r.on_event(2, 3, notification(a, 3, exact(16))), Ok(true));
        assert_eq!(r.event_bytes, 32);
    }
    #[test]
    fn delivery_removal_close_and_stale_cookie_release_exact_charges() {
        let mut r = WatchRegistry::with_compatible_delivery(2, 1, 4, 64).unwrap();
        let a = r.reserve(target(), route(), WatchKind::Watch).unwrap();
        let b = r.reserve(target(), route(), WatchKind::Watch).unwrap();
        let metadata = r.charged_bytes();
        for id in 1..=6u64 {
            let h = if id % 2 == 0 { a } else { b };
            assert_eq!(r.on_event(2, 3, notification(h, id, exact(10))), Ok(true));
        }
        assert_eq!(r.event_bytes, 60);
        r.remove(a).unwrap();
        assert_eq!(r.event_bytes, 30);
        assert_eq!(r.charged_bytes(), metadata - target_charge() + 30);
        // Old cookie after removal is harmless: ignored, nothing charged.
        let watermark = r.event_watermark();
        assert_eq!(r.on_event(2, 3, notification(a, 9, exact(10))), Ok(false));
        assert_eq!(r.event_watermark(), watermark);
        assert_eq!(r.event_bytes, 30);
        // Wrong session is harmless as well.
        assert_eq!(r.on_event(2, 4, notification(b, 9, exact(10))), Ok(false));
        assert_eq!(r.event_bytes, 30);
        // Transfer to the caller releases exactly that event.
        let first = r.poll().unwrap();
        assert_eq!(first.charge(), 10);
        assert_eq!(r.event_bytes, 20);
        drop(first);
        r.fault_all(WatchError::Disconnected);
        assert_eq!(r.event_bytes, 0);
        assert_eq!(r.charged_bytes(), target_charge());
        r.remove(b).unwrap();
        assert_eq!(r.charged_bytes(), 0);
        assert!(r.is_empty());
    }
    fn target_charge() -> u64 {
        let t = target();
        (t.object.capacity() + t.namespace.capacity() + t.locator.capacity()) as u64
    }
    #[test]
    fn delivery_invalid_profile_and_overflow_do_not_publish() {
        assert!(WatchRegistry::with_compatible_delivery(0, 1, 8, 8).is_none());
        assert!(WatchRegistry::with_compatible_delivery(1, 1, 0, 8).is_none());
        assert!(WatchRegistry::with_compatible_delivery(1, 1, 8, 0).is_none());
        let mut r = WatchRegistry::with_compatible_delivery(1, 0, 8, 8).unwrap();
        let h = r.reserve(target(), route(), WatchKind::Watch).unwrap();
        r.charged = u64::MAX;
        assert_eq!(
            r.on_event(2, 3, notification(h, 1, exact(1))),
            Err(WatchError::NoCredit)
        );
        assert!(r.poll().is_none());
    }
    #[test]
    fn bounded_constructors_remain_bounded_beside_delivery() {
        let mut strict = WatchRegistry::new(1, 1, 1024).unwrap();
        let h = strict.reserve(target(), route(), WatchKind::Watch).unwrap();
        assert_eq!(strict.on_event(2, 3, notification(h, 1, vec![])), Ok(true));
        assert_eq!(
            strict.on_event(2, 3, notification(h, 2, vec![])),
            Err(WatchError::NoCredit)
        );
        let mut compat = WatchRegistry::with_compatible_registrations(1, 1, 1024, 64).unwrap();
        let h = compat.reserve(target(), route(), WatchKind::Watch).unwrap();
        assert_eq!(compat.on_event(2, 3, notification(h, 1, vec![])), Ok(true));
        assert_eq!(
            compat.on_event(2, 3, notification(h, 2, vec![])),
            Err(WatchError::NoCredit)
        );
        let mut events = WatchRegistry::with_compatible_events(1, 1, 1024, 64).unwrap();
        let h = events.reserve(target(), route(), WatchKind::Watch).unwrap();
        assert_eq!(events.on_event(2, 3, notification(h, 1, vec![])), Ok(true));
        assert_eq!(
            events.on_event(2, 3, notification(h, 2, vec![])),
            Err(WatchError::NoCredit)
        );
        assert!(events.reserve(target(), route(), WatchKind::Watch).is_err());
    }
    #[test]
    fn compatible_invalid_profile_and_total_overflow_do_not_publish() {
        assert!(WatchRegistry::with_compatible_events(1, 1, 0, 8).is_none());
        assert!(WatchRegistry::with_compatible_events(1, 1, 8, 0).is_none());
        let mut r = WatchRegistry::with_compatible_events(1, 1, u64::MAX, 8).unwrap();
        let h = r.reserve(target(), route(), WatchKind::Notify).unwrap();
        r.charged = u64::MAX;
        assert_eq!(
            r.on_event(2, 3, message(h, vec![1])),
            Err(WatchError::NoCredit)
        );
        assert_eq!(r.entry(h).unwrap().notify_id, None);
        assert_eq!(r.event_bytes, 0);
        assert!(r.poll().is_none());
    }
}
