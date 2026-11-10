// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Fixed-slot map observation waits. Driver supplies authenticated maps/version replies.
use crate::BootstrapError;
use crate::time::{self, MAX_TIME_US as MAX_TIME};
use denc::types::Uuid;
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapBarrierRequest {
    Epoch(u32),
    Latest,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapBarrierLimits {
    pub slots: usize,
    pub query_attempts: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapBarrierError {
    Overflow,
    Limits,
    Disabled,
    AlreadyEnabled,
    NotReady,
    InvalidEpoch,
    NoCredit,
    Identity,
    Stale,
    AlreadyComplete,
    Clock,
    MapRegression,
    Fsid,
    Protocol,
    MonitorLost,
    Deadline,
    Cancelled,
    Closed,
    Bootstrap(BootstrapError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapBarrierToken {
    owner: u64,
    sequence: u64,
    slot: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RejectedMapBarrier {
    pub reason: MapBarrierError,
    pub request: MapBarrierRequest,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapBarrierOutcome {
    Reached {
        fsid: Uuid,
        target_epoch: u32,
        observed_epoch: u32,
    },
    Failed {
        error: MapBarrierError,
        target_epoch: Option<u32>,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapBarrierCompletion {
    pub token: MapBarrierToken,
    pub request: MapBarrierRequest,
    pub outcome: MapBarrierOutcome,
}
#[derive(Debug)]
struct Entry {
    token: MapBarrierToken,
    request: MapBarrierRequest,
    deadline: u64,
    started: u64,
    target: Option<u32>,
    query: Option<u64>,
    attempts: u32,
    outcome: Option<MapBarrierOutcome>,
}
#[derive(Debug)]
pub struct MapBarrierQueue {
    owner: u64,
    sequence: u64,
    fsid: Uuid,
    epoch: u32,
    now: u64,
    attempts: Option<u32>,
    entries: Vec<Option<Entry>>,
    cursor: usize,
    occupied: usize,
    #[cfg(feature = "lab")]
    lagged_queries: u64,
    query: Option<u64>,
    error: Option<MapBarrierError>,
    _owner: PhantomData<Rc<()>>,
}
impl MapBarrierQueue {
    pub fn new(fsid: Uuid, limits: MapBarrierLimits) -> Result<Self, MapBarrierError> {
        Self::with_attempt_policy(fsid, limits.slots, Some(limits.query_attempts))
    }
    /// Read-only librados version waits recover session resets until their original
    /// deadline. Slots remain native staging, independent of accepted FFI population.
    pub fn new_compatible(fsid: Uuid, slots: usize) -> Result<Self, MapBarrierError> {
        Self::with_attempt_policy(fsid, slots, None)
    }
    fn with_attempt_policy(
        fsid: Uuid,
        slots: usize,
        attempts: Option<u32>,
    ) -> Result<Self, MapBarrierError> {
        if fsid == Uuid::default() {
            return Err(MapBarrierError::Fsid);
        }
        if !(1..=4096).contains(&slots)
            || attempts.is_some_and(|limit| !(1..=65535).contains(&limit))
        {
            return Err(MapBarrierError::Limits);
        }
        let owner = NEXT_OWNER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| MapBarrierError::Identity)?;
        Ok(Self {
            owner,
            sequence: 0,
            fsid,
            epoch: 0,
            now: 0,
            attempts,
            entries: (0..slots).map(|_| None).collect(),
            cursor: 0,
            occupied: 0,
            #[cfg(feature = "lab")]
            lagged_queries: 0,
            query: None,
            error: None,
            _owner: PhantomData,
        })
    }
    #[cfg(feature = "lab")]
    pub fn lab_lagged_queries(&self) -> u64 {
        self.lagged_queries
    }
    pub fn error(&self) -> Option<MapBarrierError> {
        self.error
    }
    pub fn outstanding(&self) -> usize {
        self.occupied
    }
    pub(crate) fn can_wait(&self, now: u64, fsid: Uuid, epoch: u32, monitor_ready: bool) -> bool {
        if now < self.now || now > MAX_TIME || fsid != self.fsid || epoch < self.epoch {
            return false;
        }
        if self.occupied == 0 {
            return self.query.is_none();
        }
        if let Some(handle) = self.query
            && !self
                .entries
                .iter()
                .flatten()
                .any(|e| e.outcome.is_none() && e.query == Some(handle) && e.deadline > now)
        {
            return false;
        }
        self.entries.iter().flatten().all(|e| {
            e.outcome.is_none()
                && e.deadline > now
                && match e.target {
                    Some(target) => target > epoch,
                    None => self.query.is_some() || !monitor_ready,
                }
        })
    }
    pub fn next_deadline_us(&self) -> Option<u64> {
        if self.occupied == 0 {
            return None;
        }
        self.entries
            .iter()
            .flatten()
            .filter(|e| e.outcome.is_none())
            .filter_map(|e| time::timer(e.deadline))
            .min()
    }
    pub fn wanted_epoch(&self) -> Option<u32> {
        if self.occupied == 0 {
            return None;
        }
        self.entries
            .iter()
            .flatten()
            .filter(|e| e.outcome.is_none())
            .filter_map(|e| e.target)
            .filter(|&t| t > self.epoch)
            .min()
    }
    pub fn submit(
        &mut self,
        request: MapBarrierRequest,
        deadline_us: u64,
    ) -> Result<MapBarrierToken, RejectedMapBarrier> {
        let reject = |reason| RejectedMapBarrier { reason, request };
        if let Some(error) = self.error {
            return Err(reject(error));
        }
        if request == MapBarrierRequest::Epoch(0) {
            return Err(reject(MapBarrierError::InvalidEpoch));
        }
        if time::validate_deadline(deadline_us).is_err() {
            return Err(reject(MapBarrierError::Overflow));
        }
        if time::is_due(deadline_us, self.now) {
            diag::diag!(
                "WARNING TIMEOUT map-version wait exceeded 0s (unadmitted request={request:?})"
            );
            return Err(reject(MapBarrierError::Deadline));
        }
        let slot = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| reject(MapBarrierError::NoCredit))?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| reject(MapBarrierError::Identity))?;
        let token = MapBarrierToken {
            owner: self.owner,
            sequence: self.sequence,
            slot,
        };
        let target = match request {
            MapBarrierRequest::Epoch(e) => Some(e),
            MapBarrierRequest::Latest => None,
        };
        let mut entry = Entry {
            token,
            request,
            deadline: deadline_us,
            started: self.now,
            target,
            query: None,
            attempts: 0,
            outcome: None,
        };
        Self::advance_entry(&mut entry, self.now, self.epoch, self.fsid);
        self.entries[slot] = Some(entry);
        self.occupied += 1;
        Ok(token)
    }
    fn advance_entry(entry: &mut Entry, now: u64, epoch: u32, fsid: Uuid) {
        if entry.outcome.is_some() {
            return;
        }
        if time::is_due(entry.deadline, now) {
            Self::fail_entry(entry, MapBarrierError::Deadline);
        } else if let Some(target) = entry.target.filter(|&target| epoch >= target) {
            entry.outcome = Some(MapBarrierOutcome::Reached {
                fsid,
                target_epoch: target,
                observed_epoch: epoch,
            });
        }
    }
    fn fail_entry(entry: &mut Entry, error: MapBarrierError) {
        if entry.outcome.is_none() {
            if error == MapBarrierError::Deadline {
                let limit =
                    std::time::Duration::from_micros(entry.deadline - entry.started).as_secs_f64();
                diag::diag!(
                    "WARNING TIMEOUT map-version wait exceeded {limit}s (request={:?}, sequence={})",
                    entry.request,
                    entry.token.sequence
                );
            }
            entry.outcome = Some(MapBarrierOutcome::Failed {
                error,
                target_epoch: entry.target,
            });
        }
    }
    pub fn abort(&mut self, error: MapBarrierError) {
        self.error.get_or_insert(error);
        for entry in self.entries.iter_mut().flatten() {
            Self::fail_entry(entry, error);
        }
    }
    pub fn close(&mut self) {
        self.abort(MapBarrierError::Closed);
    }
    /// Observe a verified held map, then visit at most `work` slots, rotating fairly.
    pub fn progress(
        &mut self,
        now: u64,
        fsid: Uuid,
        epoch: u32,
        work: usize,
    ) -> Result<(), MapBarrierError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let invalid = if fsid != self.fsid {
            Some(MapBarrierError::Fsid)
        } else if now < self.now || now > MAX_TIME {
            Some(MapBarrierError::Clock)
        } else if epoch < self.epoch {
            Some(MapBarrierError::MapRegression)
        } else {
            None
        };
        if let Some(error) = invalid {
            self.abort(error);
            return Err(error);
        }
        self.now = now;
        self.epoch = epoch;
        if self.occupied == 0 {
            return Ok(());
        }
        for _ in 0..work.min(self.entries.len()) {
            if let Some(entry) = &mut self.entries[self.cursor] {
                Self::advance_entry(entry, now, epoch, fsid);
            }
            self.cursor = (self.cursor + 1) % self.entries.len();
        }
        Ok(())
    }
    pub fn needs_query(&self) -> bool {
        self.occupied != 0
            && self.error.is_none()
            && self.query.is_none()
            && self.entries.iter().flatten().any(|e| {
                e.outcome.is_none()
                    && e.target.is_none()
                    && e.query.is_none()
                    && e.deadline > self.now
            })
    }
    /// Capture only current eligible latest waiters at the actual monitor handoff boundary.
    pub fn mark_query(&mut self, handle: u64) -> Result<(), MapBarrierError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if handle == 0 || !self.needs_query() {
            return Err(MapBarrierError::Protocol);
        }
        for e in self.entries.iter_mut().flatten().filter(|e| {
            e.outcome.is_none() && e.target.is_none() && e.query.is_none() && e.deadline > self.now
        }) {
            e.query = Some(handle);
            if self.attempts.is_some() {
                e.attempts += 1;
            }
        }
        self.query = Some(handle);
        Ok(())
    }
    /// Detach correlation when no live participants remain; driver removes it from monc.
    pub fn take_abandoned_query(&mut self) -> Option<u64> {
        let handle = self.query?;
        if self
            .entries
            .iter()
            .flatten()
            .any(|e| e.outcome.is_none() && e.query == Some(handle) && e.deadline > self.now)
        {
            return None;
        }
        self.query.take()
    }
    pub fn on_version(
        &mut self,
        handle: u64,
        newest: u64,
        oldest: u64,
    ) -> Result<bool, MapBarrierError> {
        if self.query != Some(handle) {
            return Ok(false);
        }
        if let Some(error) = self.error {
            return Err(error);
        }
        self.query = None;
        for e in self
            .entries
            .iter_mut()
            .flatten()
            .filter(|e| e.query == Some(handle))
        {
            if time::is_due(e.deadline, self.now) {
                Self::fail_entry(e, MapBarrierError::Deadline);
            }
        }
        if !self
            .entries
            .iter()
            .flatten()
            .any(|e| e.query == Some(handle) && e.outcome.is_none())
        {
            return Ok(true);
        }
        if newest == 0 || newest > u64::from(u32::MAX) || oldest > newest {
            self.abort(MapBarrierError::Protocol);
            return Err(MapBarrierError::Protocol);
        }
        #[cfg(feature = "lab")]
        if u64::from(self.epoch) < newest {
            self.lagged_queries = self.lagged_queries.saturating_add(1);
        }
        for e in self
            .entries
            .iter_mut()
            .flatten()
            .filter(|e| e.query == Some(handle))
        {
            e.query = None;
            if e.outcome.is_none() {
                // Deadline precedence also applies before publishing a newly learned target.
                if time::is_due(e.deadline, self.now) {
                    Self::fail_entry(e, MapBarrierError::Deadline);
                } else {
                    e.target = Some(newest as u32);
                    Self::advance_entry(e, self.now, self.epoch, self.fsid);
                }
            }
        }
        Ok(true)
    }
    pub fn monitor_lost(&mut self) {
        let Some(handle) = self.query.take() else {
            return;
        };
        for e in self
            .entries
            .iter_mut()
            .flatten()
            .filter(|e| e.query == Some(handle))
        {
            e.query = None;
            if time::is_due(e.deadline, self.now) {
                Self::fail_entry(e, MapBarrierError::Deadline);
            } else if self.attempts.is_some_and(|limit| e.attempts >= limit) {
                Self::fail_entry(e, MapBarrierError::MonitorLost);
            }
        }
    }
    fn entry_mut(&mut self, token: MapBarrierToken) -> Result<&mut Entry, MapBarrierError> {
        if token.owner != self.owner {
            return Err(MapBarrierError::Stale);
        }
        self.entries
            .get_mut(token.slot)
            .and_then(Option::as_mut)
            .filter(|e| e.token == token)
            .ok_or(MapBarrierError::Stale)
    }
    pub fn cancel(&mut self, token: MapBarrierToken) -> Result<(), MapBarrierError> {
        let now = self.now;
        let e = self.entry_mut(token)?;
        if e.outcome.is_some() {
            return Err(MapBarrierError::AlreadyComplete);
        }
        Self::fail_entry(
            e,
            if time::is_due(e.deadline, now) {
                MapBarrierError::Deadline
            } else {
                MapBarrierError::Cancelled
            },
        );
        Ok(())
    }
    pub fn poll_token(
        &mut self,
        token: MapBarrierToken,
    ) -> Result<Option<MapBarrierCompletion>, MapBarrierError> {
        if self.entry_mut(token)?.outcome.is_none() {
            return Ok(None);
        }
        let entry = self.entries[token.slot].take().unwrap();
        self.occupied -= 1;
        Ok(Some(MapBarrierCompletion {
            token,
            request: entry.request,
            outcome: entry.outcome.unwrap(),
        }))
    }
    pub fn token_waiting(&self, token: MapBarrierToken) -> bool {
        token.owner == self.owner
            && self
                .entries
                .get(token.slot)
                .and_then(Option::as_ref)
                .is_some_and(|entry| entry.token == token && entry.outcome.is_none())
    }
    pub fn is_full(&self) -> bool {
        self.occupied == self.entries.len()
    }
    pub fn poll_into(&mut self, out: &mut [Option<MapBarrierCompletion>]) -> usize {
        if self.occupied == 0 {
            return 0;
        }
        let mut n = 0;
        for destination in out.iter_mut().filter(|o| o.is_none()) {
            if self.occupied == 0 {
                break;
            }
            let Some(slot) = self
                .entries
                .iter()
                .position(|e| e.as_ref().is_some_and(|e| e.outcome.is_some()))
            else {
                break;
            };
            let e = self.entries[slot].take().unwrap();
            self.occupied -= 1;
            *destination = Some(MapBarrierCompletion {
                token: e.token,
                request: e.request,
                outcome: e.outcome.unwrap(),
            });
            n += 1;
        }
        n
    }
}

#[cfg(test)]
mod tests;
