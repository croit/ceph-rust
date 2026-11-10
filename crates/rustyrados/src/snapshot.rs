// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Bounded snapshot and pool-administration control state; native composition is opt-in through Bootstrap.
use crate::time::{self, MAX_TIME_US as MAX_TIME};
use denc::types::Uuid;
use messages::{MPoolOp, MPoolOpReply, PoolOperation};
use std::{
    collections::VecDeque,
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_QUEUE: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotOperation {
    Allocate,
    Remove { snapid: u64 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotRequest {
    pub pool: i64,
    pub operation: SnapshotOperation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamedSnapshotOperation {
    Create,
    Remove,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedSnapshotRequest {
    pub pool: i64,
    pub operation: NamedSnapshotOperation,
    pub name: Vec<u8>,
}
#[derive(Debug)]
pub struct RejectedNamedSnapshot {
    pub reason: SnapshotQueueError,
    pub request: NamedSnapshotRequest,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolAdminRequest {
    Create { name: Vec<u8>, crush_rule: i16 },
    Delete { pool: i64 },
}
#[derive(Debug)]
pub struct RejectedPoolAdmin {
    pub reason: SnapshotQueueError,
    pub request: PoolAdminRequest,
}
enum ControlRequest {
    PoolAdmin(PoolAdminRequest),
    SelfManaged(SnapshotRequest),
    Named(NamedSnapshotRequest),
}

/// A named snapshot travels in the pool-operation front, so its name must fit that u32 frame, not only the wire's own
/// length prefix. Admission and encoding therefore share one rule.
fn named_name_fits(len: usize) -> bool {
    MPoolOp::front_len(len).is_ok()
}
#[derive(Clone, Copy, Debug)]
pub struct SnapshotLimits {
    pub slots: usize,
    pub bytes: u64,
    pub response_bytes: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotQueueError {
    Overflow,
    Limits,
    Disabled,
    AlreadyEnabled,
    NotReady,
    NoPool,
    PoolExists,
    Transport,
    Bootstrap(crate::BootstrapError),
    Closed,
    Clock,
    MapRegression,
    Identity,
    InvalidRequest,
    NoCredit,
    Stale,
    AlreadySent,
    Protocol,
    Fsid,
    MonitorLost,
    Deadline,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotToken {
    queue: u64,
    slot: usize,
    sequence: u64,
}
impl SnapshotToken {
    pub fn sequence(self) -> u64 {
        self.sequence
    }
}
#[derive(Debug)]
pub struct RejectedSnapshot {
    pub reason: SnapshotQueueError,
    pub request: SnapshotRequest,
}
#[derive(Debug, PartialEq, Eq)]
pub struct SnapshotReply {
    pub result: i32,
    pub epoch: u32,
    pub snapshot_id: Option<u64>,
    pub data: Vec<u8>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum SnapshotOutcome {
    Completed(SnapshotReply),
    Deadline {
        possibly_sent: bool,
        reply: Option<SnapshotReply>,
    },
    Canceled {
        possibly_sent: bool,
        reply: Option<SnapshotReply>,
    },
    Failed {
        error: SnapshotQueueError,
        possibly_sent: bool,
        reply: Option<SnapshotReply>,
    },
}
#[derive(Debug, PartialEq, Eq)]
pub struct SnapshotCompletion {
    pub token: SnapshotToken,
    pub outcome: SnapshotOutcome,
}
struct Pending {
    token: SnapshotToken,
    request: ControlRequest,
    deadline: u64,
    started: u64,
    charge: u64,
    wire_tid: Option<u64>,
    handed_off: bool,
    reply: Option<SnapshotReply>,
    terminal: bool,
}
#[derive(Clone, Copy)]
enum End {
    Reply,
    Deadline,
    Cancel,
    Failure(SnapshotQueueError),
}
pub struct SnapshotQueue {
    id: u64,
    fsid: Uuid,
    limits: SnapshotLimits,
    slots: Vec<Option<Pending>>,
    free: Vec<usize>,
    completions: VecDeque<SnapshotCompletion>,
    sequence: u64,
    last_wire_tid: u64,
    service_version: u64,
    now: u64,
    epoch: u32,
    cursor: usize,
    dispatch_cursor: usize,
    charged: u64,
    compatible: bool,
    closed: bool,
    error: Option<SnapshotQueueError>,
    _owner: PhantomData<Rc<()>>,
}
impl std::fmt::Debug for SnapshotQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotQueue")
            .field("closed", &self.closed)
            .field("error", &self.error)
            .field("outstanding", &self.outstanding())
            .finish_non_exhaustive()
    }
}
impl SnapshotQueue {
    /// Hard byte budget: a request never enters above `limits.bytes`.
    pub fn new(fsid: Uuid, limits: SnapshotLimits) -> Result<Self, SnapshotQueueError> {
        Self::with_admission(fsid, limits, false)
    }
    /// `limits.bytes` is a target: a sole request above it enters only into an empty queue,
    /// and later work waits until completed charges are consumed. Slots stay finite.
    pub fn new_compatible(fsid: Uuid, limits: SnapshotLimits) -> Result<Self, SnapshotQueueError> {
        Self::with_admission(fsid, limits, true)
    }
    fn with_admission(
        fsid: Uuid,
        limits: SnapshotLimits,
        compatible: bool,
    ) -> Result<Self, SnapshotQueueError> {
        if fsid == Uuid::default() {
            return Err(SnapshotQueueError::Fsid);
        }
        if limits.slots == 0
            || limits.slots > 65536
            || limits.response_bytes < 8
            || limits.response_bytes > u32::MAX as usize
            || limits.bytes == 0
            || (!compatible && limits.bytes < limits.response_bytes as u64)
        {
            return Err(SnapshotQueueError::Limits);
        }
        let id = NEXT_QUEUE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| SnapshotQueueError::Identity)?;
        Ok(Self {
            id,
            fsid,
            limits,
            slots: (0..limits.slots).map(|_| None).collect(),
            free: (0..limits.slots).rev().collect(),
            completions: VecDeque::with_capacity(limits.slots),
            sequence: 1,
            last_wire_tid: 0,
            service_version: 0,
            now: 0,
            epoch: 0,
            cursor: 0,
            dispatch_cursor: 0,
            charged: 0,
            compatible,
            closed: false,
            error: None,
            _owner: PhantomData,
        })
    }
    pub(crate) fn next_unsent(&mut self) -> Option<SnapshotToken> {
        if self.closed {
            return None;
        }
        let i = self.dispatch_cursor;
        self.dispatch_cursor = (i + 1) % self.slots.len();
        self.slots[i]
            .as_ref()
            .filter(|p| !p.terminal && !p.handed_off)
            .map(|p| p.token)
    }
    pub(crate) fn reject_unsent(
        &mut self,
        token: SnapshotToken,
        error: SnapshotQueueError,
    ) -> Result<(), SnapshotQueueError> {
        if self.live(token)?.handed_off {
            return Err(SnapshotQueueError::AlreadySent);
        }
        self.finish(token.slot, End::Failure(error));
        Ok(())
    }
    pub(crate) fn abort(&mut self, error: SnapshotQueueError) {
        let _: Result<(), _> = self.fail(error);
    }
    pub fn outstanding(&self) -> usize {
        self.slots.len() - self.free.len()
    }
    pub(crate) fn can_wait(&self, now: u64, epoch: u32) -> bool {
        now >= self.now
            && now <= MAX_TIME
            && epoch >= self.epoch
            && self.completions.is_empty()
            && (self.outstanding() == 0
                || self.slots.iter().flatten().all(|p| {
                    !p.terminal
                        && p.deadline > now
                        && p.handed_off
                        && match &p.reply {
                            Some(reply) => reply.epoch > epoch,
                            None => p.wire_tid.is_some(),
                        }
                }))
    }
    pub fn charged_bytes(&self) -> u64 {
        self.charged
    }
    pub fn error(&self) -> Option<SnapshotQueueError> {
        self.error
    }
    pub fn observed_service_version(&self) -> u64 {
        self.service_version
    }
    fn has_credit(&self, charge: Option<u64>) -> bool {
        let Some(charge) = charge else {
            return false;
        };
        !self.free.is_empty()
            && (self
                .charged
                .checked_add(charge)
                .is_some_and(|total| total <= self.limits.bytes)
                || (self.compatible && self.charged == 0))
    }
    fn rejection(
        &self,
        pool: i64,
        valid: bool,
        deadline: u64,
        charge: Option<u64>,
    ) -> Option<SnapshotQueueError> {
        if self.closed {
            Some(SnapshotQueueError::Closed)
        } else if pool < 0 || pool > u32::MAX as i64 || !valid {
            Some(SnapshotQueueError::InvalidRequest)
        } else if time::validate_deadline(deadline).is_err() {
            Some(SnapshotQueueError::Overflow)
        } else if time::is_due(deadline, self.now) {
            diag::diag!(
                "WARNING TIMEOUT pool snapshot request exceeded {}s (admission, deadline_us={deadline})",
                time::budget_seconds(deadline.saturating_sub(self.now))
            );
            Some(SnapshotQueueError::Deadline)
        } else if self.sequence == u64::MAX {
            Some(SnapshotQueueError::Identity)
        } else if !self.has_credit(charge) {
            Some(SnapshotQueueError::NoCredit)
        } else {
            None
        }
    }
    pub fn submit(
        &mut self,
        request: SnapshotRequest,
        deadline: u64,
    ) -> Result<SnapshotToken, RejectedSnapshot> {
        let valid = !matches!(request.operation,SnapshotOperation::Remove {snapid} if snapid==0 || snapid>=opwire::NOSNAP);
        let charge = self.limits.response_bytes as u64;
        if let Some(reason) = self.rejection(request.pool, valid, deadline, Some(charge)) {
            return Err(RejectedSnapshot { reason, request });
        }
        Ok(self.insert(ControlRequest::SelfManaged(request), deadline, charge))
    }
    pub fn submit_named(
        &mut self,
        request: NamedSnapshotRequest,
        deadline: u64,
    ) -> Result<SnapshotToken, RejectedNamedSnapshot> {
        let valid = named_name_fits(request.name.len()) && !request.name.contains(&0);
        let charge =
            (self.limits.response_bytes as u64).checked_add(request.name.capacity() as u64);
        if let Some(reason) = self.rejection(request.pool, valid, deadline, charge) {
            return Err(RejectedNamedSnapshot { reason, request });
        }
        Ok(self.insert(
            ControlRequest::Named(request),
            deadline,
            charge.expect("validated charge"),
        ))
    }
    pub fn submit_pool_admin(
        &mut self,
        request: PoolAdminRequest,
        deadline: u64,
    ) -> Result<SnapshotToken, RejectedPoolAdmin> {
        let (pool, valid, capacity) = match &request {
            PoolAdminRequest::Create { name, .. } => (
                0,
                if self.compatible {
                    MPoolOp::front_len(name.len()).is_ok()
                } else {
                    !name.is_empty() && name.len() <= 1024 * 1024 && !name.contains(&0)
                },
                name.capacity() as u64,
            ),
            PoolAdminRequest::Delete { pool } => (*pool, true, 0),
        };
        let charge = capacity.checked_add(self.limits.response_bytes as u64);
        if let Some(reason) = self.rejection(pool, valid, deadline, charge) {
            return Err(RejectedPoolAdmin { reason, request });
        }
        Ok(self.insert(
            ControlRequest::PoolAdmin(request),
            deadline,
            charge.unwrap(),
        ))
    }
    fn insert(&mut self, request: ControlRequest, deadline: u64, charge: u64) -> SnapshotToken {
        let slot = self.free.pop().expect("validated slot");
        let token = SnapshotToken {
            queue: self.id,
            slot,
            sequence: self.sequence,
        };
        self.sequence += 1;
        self.slots[slot] = Some(Pending {
            token,
            request,
            deadline,
            started: self.now,
            charge,
            wire_tid: None,
            handed_off: false,
            reply: None,
            terminal: false,
        });
        self.charged = self.charged.checked_add(charge).expect("validated charge");
        token
    }
    fn live(&self, token: SnapshotToken) -> Result<&Pending, SnapshotQueueError> {
        self.slots
            .get(token.slot)
            .and_then(Option::as_ref)
            .filter(|p| p.token == token && !p.terminal)
            .ok_or(SnapshotQueueError::Stale)
    }
    pub fn prepare(&mut self, token: SnapshotToken) -> Result<MPoolOp, SnapshotQueueError> {
        if self.closed {
            return Err(SnapshotQueueError::Closed);
        }
        let p = self.live(token)?;
        if p.handed_off {
            return Err(SnapshotQueueError::AlreadySent);
        }
        if time::is_due(p.deadline, self.now) {
            self.finish(token.slot, End::Deadline);
            return Err(SnapshotQueueError::Deadline);
        }
        let (pool, operation, snapid, name, crush_rule) = match &p.request {
            ControlRequest::PoolAdmin(PoolAdminRequest::Create { name, crush_rule }) => {
                (0, PoolOperation::CreatePool, 0, name.clone(), *crush_rule)
            }
            ControlRequest::PoolAdmin(PoolAdminRequest::Delete { pool }) => {
                (*pool, PoolOperation::DeletePool, 0, Vec::new(), 0)
            }
            ControlRequest::SelfManaged(request) => {
                let (operation, snapid) = match request.operation {
                    SnapshotOperation::Allocate => (PoolOperation::AllocateSelfManagedSnap, 0),
                    SnapshotOperation::Remove { snapid } => {
                        (PoolOperation::RemoveSelfManagedSnap, snapid)
                    }
                };
                (request.pool, operation, snapid, Vec::new(), 0)
            }
            ControlRequest::Named(request) => (
                request.pool,
                match request.operation {
                    NamedSnapshotOperation::Create => PoolOperation::CreateNamedSnap,
                    NamedSnapshotOperation::Remove => PoolOperation::RemoveNamedSnap,
                },
                0,
                request.name.clone(),
                0,
            ),
        };
        Ok(MPoolOp {
            version: self.service_version,
            fsid: self.fsid,
            pool: pool as u32,
            operation,
            snapid,
            name,
            crush_rule,
        })
    }
    pub fn mark_sent(
        &mut self,
        token: SnapshotToken,
        wire_tid: u64,
    ) -> Result<(), SnapshotQueueError> {
        let p = self.live(token)?;
        if p.handed_off {
            return Err(SnapshotQueueError::AlreadySent);
        }
        self.slots[token.slot].as_mut().unwrap().handed_off = true;
        if wire_tid == 0 || wire_tid <= self.last_wire_tid {
            return self.fail(SnapshotQueueError::Identity);
        }
        self.last_wire_tid = wire_tid;
        self.slots[token.slot].as_mut().unwrap().wire_tid = Some(wire_tid);
        Ok(())
    }
    fn clock(&mut self, now: u64, epoch: u32) -> Result<(), SnapshotQueueError> {
        if self.closed {
            return Err(self.error.unwrap_or(SnapshotQueueError::Closed));
        }
        if now < self.now || now > MAX_TIME {
            return self.fail(SnapshotQueueError::Clock);
        }
        if epoch < self.epoch {
            return self.fail(SnapshotQueueError::MapRegression);
        }
        self.now = now;
        self.epoch = epoch;
        Ok(())
    }
    pub fn on_reply(
        &mut self,
        wire_tid: u64,
        reply: MPoolOpReply,
        now: u64,
        epoch: u32,
    ) -> Result<bool, SnapshotQueueError> {
        self.clock(now, epoch)?;
        if self.outstanding() == 0 {
            return Ok(false);
        }
        let Some(i) = self.slots.iter().position(|p| {
            p.as_ref()
                .is_some_and(|p| !p.terminal && p.wire_tid == Some(wire_tid))
        }) else {
            return Ok(false);
        };
        let p = self.slots[i].as_ref().unwrap();
        if time::is_due(p.deadline, self.now) {
            self.finish(i, End::Deadline);
            return Ok(false);
        }
        if p.reply.is_some() {
            return Ok(false);
        }
        if reply.fsid != self.fsid {
            return self.fail(SnapshotQueueError::Fsid);
        }
        if reply.response_data.capacity() > self.limits.response_bytes {
            return self.fail(SnapshotQueueError::Protocol);
        }
        let snapshot_id = if reply.result == 0 {
            match &p.request {
                ControlRequest::SelfManaged(SnapshotRequest {
                    operation: SnapshotOperation::Allocate,
                    ..
                }) => {
                    let Ok(bytes) = <&[u8; 8]>::try_from(reply.response_data.as_slice()) else {
                        return self.fail(SnapshotQueueError::Protocol);
                    };
                    let id = u64::from_le_bytes(*bytes);
                    if id == 0 || id >= opwire::NOSNAP {
                        return self.fail(SnapshotQueueError::Protocol);
                    }
                    Some(id)
                }
                _ => {
                    if !reply.response_data.is_empty() {
                        return self.fail(SnapshotQueueError::Protocol);
                    }
                    None
                }
            }
        } else {
            None
        };
        let converged = reply.epoch <= self.epoch;
        self.service_version = self.service_version.max(reply.version);
        self.slots[i].as_mut().unwrap().reply = Some(SnapshotReply {
            result: reply.result,
            epoch: reply.epoch,
            snapshot_id,
            data: reply.response_data,
        });
        if converged {
            self.finish(i, End::Reply);
        }
        Ok(true)
    }
    pub fn progress(
        &mut self,
        now: u64,
        epoch: u32,
        budget: usize,
    ) -> Result<usize, SnapshotQueueError> {
        self.clock(now, epoch)?;
        if self.outstanding() == 0 {
            return Ok(0);
        }
        let count = budget.min(self.slots.len());
        let mut finished = 0;
        for offset in 0..count {
            let i = (self.cursor + offset) % self.slots.len();
            let Some(p) = self.slots[i].as_ref().filter(|p| !p.terminal) else {
                continue;
            };
            if time::is_due(p.deadline, self.now) {
                self.finish(i, End::Deadline);
                finished += 1;
            } else if p.reply.as_ref().is_some_and(|r| r.epoch <= self.epoch) {
                self.finish(i, End::Reply);
                finished += 1;
            }
        }
        self.cursor = (self.cursor + count) % self.slots.len();
        Ok(finished)
    }
    pub fn monitor_lost(&mut self) {
        for i in 0..self.slots.len() {
            if let Some(p) = self.slots[i].as_ref().filter(|p| !p.terminal) {
                if time::is_due(p.deadline, self.now) {
                    self.finish(i, End::Deadline);
                } else if p.handed_off && p.reply.is_none() {
                    self.finish(i, End::Failure(SnapshotQueueError::MonitorLost));
                }
            }
        }
    }
    pub fn cancel(&mut self, token: SnapshotToken) -> Result<(), SnapshotQueueError> {
        self.live(token)?;
        self.finish(token.slot, End::Cancel);
        Ok(())
    }
    pub fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            for i in 0..self.slots.len() {
                self.finish(i, End::Cancel);
            }
        }
    }
    fn fail<T>(&mut self, error: SnapshotQueueError) -> Result<T, SnapshotQueueError> {
        let error = *self.error.get_or_insert(error);
        self.closed = true;
        for i in 0..self.slots.len() {
            self.finish(i, End::Failure(error));
        }
        Err(error)
    }
    fn finish(&mut self, i: usize, end: End) {
        let Some(p) = self.slots[i].as_mut().filter(|p| !p.terminal) else {
            return;
        };
        p.terminal = true;
        if matches!(end, End::Deadline) {
            diag::diag!(
                "WARNING TIMEOUT pool snapshot request exceeded {}s (deadline_us={} handed_off={})",
                time::budget_seconds(p.deadline.saturating_sub(p.started)),
                p.deadline,
                p.handed_off
            );
        }
        let reply = p.reply.take();
        let possibly_sent = p.handed_off;
        let outcome = match end {
            End::Reply => SnapshotOutcome::Completed(reply.expect("verified map-barrier reply")),
            End::Deadline => SnapshotOutcome::Deadline {
                possibly_sent,
                reply,
            },
            End::Cancel => SnapshotOutcome::Canceled {
                possibly_sent,
                reply,
            },
            End::Failure(error) => SnapshotOutcome::Failed {
                error,
                possibly_sent,
                reply,
            },
        };
        self.completions.push_back(SnapshotCompletion {
            token: p.token,
            outcome,
        });
    }
    pub fn next_deadline(&self) -> Option<u64> {
        if self.outstanding() == 0 {
            return None;
        }
        self.slots
            .iter()
            .flatten()
            .filter(|p| !p.terminal)
            .filter_map(|p| time::timer(p.deadline))
            .min()
    }
    pub fn poll_into(&mut self, out: &mut [Option<SnapshotCompletion>]) -> usize {
        let mut count = 0;
        for dst in out {
            if dst.is_some() {
                break;
            }
            let Some(done) = self.completions.pop_front() else {
                break;
            };
            let pending = self.slots[done.token.slot]
                .take()
                .expect("completion owns slot");
            self.free.push(done.token.slot);
            self.charged -= pending.charge;
            *dst = Some(done);
            count += 1;
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wide_deadline_expires_once_and_unlimited_has_no_timer() {
        let end = time::deadline_after(5, 1u64 << 32).unwrap();
        let mut q = admin_queue();
        q.progress(5, 4, 2).unwrap();
        let request = SnapshotRequest {
            pool: 7,
            operation: SnapshotOperation::Allocate,
        };
        let finite = q.submit(request, end).unwrap();
        let unlimited = q.submit(request, time::NO_DEADLINE).unwrap();
        assert_eq!(q.next_deadline(), Some(end));
        q.progress(end - 1, 4, 2).unwrap();
        assert_eq!(q.poll_into(&mut [None]), 0);
        q.progress(end, 4, 2).unwrap();
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        assert_eq!(out[0].as_ref().unwrap().token, finite);
        assert!(matches!(
            out[0].as_ref().unwrap().outcome,
            SnapshotOutcome::Deadline { .. }
        ));
        assert_eq!(q.next_deadline(), None);
        q.progress(MAX_TIME, 4, 2).unwrap();
        assert_eq!(q.poll_into(&mut [None]), 0);
        assert!(q.prepare(unlimited).is_ok());
        q.cancel(unlimited).unwrap();
        assert_eq!(q.poll_into(&mut [None]), 1);
        assert_eq!(q.poll_into(&mut [None]), 0);
    }
    fn admin_queue() -> SnapshotQueue {
        SnapshotQueue::new(
            queue().fsid,
            SnapshotLimits {
                slots: 2,
                bytes: 128,
                response_bytes: 16,
            },
        )
        .unwrap()
    }
    #[test]
    fn pool_create_waits_for_reply_epoch_and_retains_credit_until_consumed() {
        let mut q = admin_queue();
        q.progress(1, 4, 0).unwrap();
        let mut name = Vec::with_capacity(32);
        name.extend_from_slice(b"new-pool");
        let token = q
            .submit_pool_admin(
                PoolAdminRequest::Create {
                    name,
                    crush_rule: -1,
                },
                100,
            )
            .unwrap();
        assert_eq!(q.charged_bytes(), 48);
        let message = q.prepare(token).unwrap();
        assert_eq!(
            (
                message.pool,
                message.operation,
                message.snapid,
                message.crush_rule
            ),
            (0, PoolOperation::CreatePool, 0, -1)
        );
        assert_eq!(message.name, b"new-pool");
        q.mark_sent(token, 9).unwrap();
        assert_eq!(q.prepare(token), Err(SnapshotQueueError::AlreadySent));
        q.on_reply(
            9,
            MPoolOpReply {
                version: 1,
                fsid: q.fsid,
                result: 0,
                epoch: 6,
                response_data: vec![],
            },
            2,
            4,
        )
        .unwrap();
        assert_eq!(q.poll_into(&mut [None]), 0);
        q.progress(3, 6, 2).unwrap();
        assert_eq!(q.charged_bytes(), 48);
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        assert!(matches!(
            &out[0].as_ref().unwrap().outcome,
            SnapshotOutcome::Completed(SnapshotReply {
                snapshot_id: None,
                epoch: 6,
                ..
            })
        ));
        assert_eq!(q.charged_bytes(), 0);
    }
    #[test]
    fn pool_delete_targets_id_with_empty_name_and_never_replays_after_loss() {
        let mut q = admin_queue();
        let token = q
            .submit_pool_admin(PoolAdminRequest::Delete { pool: 7 }, 100)
            .unwrap();
        let m = q.prepare(token).unwrap();
        assert_eq!(
            (m.pool, m.operation, m.snapid, m.crush_rule),
            (7, PoolOperation::DeletePool, 0, 0)
        );
        assert!(m.name.is_empty());
        q.mark_sent(token, 1).unwrap();
        q.monitor_lost();
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        assert!(matches!(
            &out[0].as_ref().unwrap().outcome,
            SnapshotOutcome::Failed {
                error: SnapshotQueueError::MonitorLost,
                possibly_sent: true,
                ..
            }
        ));
        assert!(q.next_unsent().is_none());
    }
    #[test]
    fn compatible_pool_names_reach_binary_handoff_and_keep_remote_errors() {
        for (mut name, result) in [(vec![], -22), (vec![b'n'; 1024 * 1024 + 1], -36)] {
            if !name.is_empty() {
                name[0] = 255;
            }
            let mut strict = compat_queue(1, false);
            assert_eq!(
                strict
                    .submit_pool_admin(
                        PoolAdminRequest::Create {
                            name: name.clone(),
                            crush_rule: 255,
                        },
                        100
                    )
                    .unwrap_err()
                    .reason,
                SnapshotQueueError::InvalidRequest
            );
            let mut queue = compat_queue(1, true);
            queue.progress(1, 4, 0).unwrap();
            let token = queue
                .submit_pool_admin(
                    PoolAdminRequest::Create {
                        name: name.clone(),
                        crush_rule: 255,
                    },
                    100,
                )
                .unwrap();
            let message = queue.prepare(token).unwrap();
            assert_eq!(message.name, name);
            assert_eq!(message.crush_rule, 255);
            queue.mark_sent(token, 9).unwrap();
            queue
                .on_reply(
                    9,
                    MPoolOpReply {
                        version: 1,
                        fsid: queue.fsid,
                        result,
                        epoch: 4,
                        response_data: vec![],
                    },
                    2,
                    4,
                )
                .unwrap();
            let mut output = [None];
            assert_eq!(queue.poll_into(&mut output), 1);
            assert!(matches!(&output[0].as_ref().unwrap().outcome,
                SnapshotOutcome::Completed(reply) if reply.result == result));
            assert_eq!(queue.charged_bytes(), 0);
        }
    }

    #[test]
    fn pool_admin_rejections_preserve_owned_request_and_deadline_handoff_state() {
        let mut q = admin_queue();
        for name in [vec![], vec![b'a', 0]] {
            let request = PoolAdminRequest::Create {
                name,
                crush_rule: 0,
            };
            assert_eq!(
                q.submit_pool_admin(request, 100).unwrap_err().reason,
                SnapshotQueueError::InvalidRequest
            );
        }
        for pool in [-1, u32::MAX as i64 + 1] {
            assert_eq!(
                q.submit_pool_admin(PoolAdminRequest::Delete { pool }, 100)
                    .unwrap_err()
                    .reason,
                SnapshotQueueError::InvalidRequest
            );
        }
        let mut name = Vec::with_capacity(128);
        name.extend_from_slice(b"kept");
        let rejected = q
            .submit_pool_admin(
                PoolAdminRequest::Create {
                    name,
                    crush_rule: 255,
                },
                100,
            )
            .unwrap_err();
        assert_eq!(rejected.reason, SnapshotQueueError::NoCredit);
        assert!(
            matches!(rejected.request, PoolAdminRequest::Create {name, crush_rule:255} if name == b"kept" && name.capacity() == 128)
        );
        assert_eq!(q.charged_bytes(), 0);
        for sent in [false, true] {
            let mut q = admin_queue();
            let token = q
                .submit_pool_admin(PoolAdminRequest::Delete { pool: 7 }, 10)
                .unwrap();
            if sent {
                q.mark_sent(token, 1).unwrap();
            }
            q.progress(10, 0, 2).unwrap();
            let mut out = [None];
            assert_eq!(q.poll_into(&mut out), 1);
            assert!(
                matches!(&out[0].as_ref().unwrap().outcome, SnapshotOutcome::Deadline {possibly_sent,..} if *possibly_sent == sent)
            );
        }
    }
    fn queue() -> SnapshotQueue {
        SnapshotQueue::new(
            Uuid::parse("01020304-0506-0708-090a-0b0c0d0e0f10").unwrap(),
            SnapshotLimits {
                slots: 1,
                bytes: 16,
                response_bytes: 16,
            },
        )
        .unwrap()
    }
    #[test]
    fn named_snapshot_name_is_bounded_by_the_pool_operation_front() {
        // The front is `name + 65` in a u32; derive the boundary instead of repeating the overhead here.
        let boundary = u32::MAX as usize - MPoolOp::front_len(0).unwrap();
        assert!(named_name_fits(boundary));
        assert!(!named_name_fits(boundary + 1));
        let mut q = SnapshotQueue::new_compatible(
            queue().fsid,
            SnapshotLimits {
                slots: 1,
                bytes: 16,
                response_bytes: 16,
            },
        )
        .unwrap();
        // A sole oversize request is admitted by the compatible profile, so admission alone must bound the name.
        let token = q
            .submit_named(
                NamedSnapshotRequest {
                    pool: 7,
                    operation: NamedSnapshotOperation::Create,
                    name: b"snap".to_vec(),
                },
                100,
            )
            .unwrap();
        assert_eq!(q.prepare(token).unwrap().name, b"snap");
    }
    #[test]
    fn wait_hint_distinguishes_handoff_future_map_and_unvisited_or_retained_result() {
        let mut q = queue();
        q.progress(1, 4, 0).unwrap();
        assert!(q.can_wait(1, 4));
        let token = q
            .submit(
                SnapshotRequest {
                    pool: 7,
                    operation: SnapshotOperation::Allocate,
                },
                100,
            )
            .unwrap();
        assert!(!q.can_wait(1, 4));
        q.mark_sent(token, 1).unwrap();
        assert!(q.can_wait(1, 4));
        assert!(!q.can_wait(100, 4));
        q.on_reply(
            1,
            MPoolOpReply {
                version: 1,
                fsid: q.fsid,
                result: 0,
                epoch: 6,
                response_data: 9u64.to_le_bytes().to_vec(),
            },
            2,
            4,
        )
        .unwrap();
        assert!(q.can_wait(2, 4));
        assert!(!q.can_wait(3, 6));
        q.progress(3, 6, 0).unwrap();
        assert!(!q.can_wait(3, 6));
        q.progress(3, 6, 1).unwrap();
        assert!(!q.can_wait(3, 6));
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        assert_eq!(out[0].as_ref().unwrap().token, token);
        assert!(q.can_wait(3, 6));
        assert!(!q.can_wait(2, 6));
        assert!(!q.can_wait(3, 5));
        assert!(!q.can_wait(MAX_TIME + 1, 6));
        let next = q
            .submit(
                SnapshotRequest {
                    pool: 7,
                    operation: SnapshotOperation::Allocate,
                },
                100,
            )
            .unwrap();
        q.cancel(next).unwrap();
        assert!(!q.can_wait(3, 6));
        assert_eq!(q.poll_into(&mut [None]), 1);
        assert!(q.can_wait(3, 6));
    }
    #[test]
    fn token_exhaustion_rejects_before_credit_and_invalid_accepted_wire_id_is_possibly_sent() {
        let mut q = queue();
        q.sequence = u64::MAX;
        let request = SnapshotRequest {
            pool: 7,
            operation: SnapshotOperation::Allocate,
        };
        assert_eq!(
            q.submit(request, 10).unwrap_err().reason,
            SnapshotQueueError::Identity
        );
        assert_eq!(q.outstanding(), 0);
        assert_eq!(q.charged_bytes(), 0);
        let mut q = queue();
        let token = q.submit(request, 10).unwrap();
        assert_eq!(q.mark_sent(token, 0), Err(SnapshotQueueError::Identity));
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        assert!(matches!(
            out[0].as_ref().unwrap().outcome,
            SnapshotOutcome::Failed {
                possibly_sent: true,
                error: SnapshotQueueError::Identity,
                ..
            }
        ));
    }
    #[test]
    fn limits_and_time_bounds_reject_without_unbounded_allocation() {
        let fsid = queue().fsid;
        for limits in [
            SnapshotLimits {
                slots: 0,
                bytes: 16,
                response_bytes: 16,
            },
            SnapshotLimits {
                slots: 65537,
                bytes: 16,
                response_bytes: 16,
            },
            SnapshotLimits {
                slots: 1,
                bytes: 7,
                response_bytes: 8,
            },
            SnapshotLimits {
                slots: 1,
                bytes: 16,
                response_bytes: 7,
            },
        ] {
            assert!(SnapshotQueue::new(fsid, limits).is_err());
        }
        assert!(
            SnapshotQueue::new(
                Uuid::default(),
                SnapshotLimits {
                    slots: 1,
                    bytes: 16,
                    response_bytes: 16
                }
            )
            .is_err()
        );
        let mut q = queue();
        let request = SnapshotRequest {
            pool: 7,
            operation: SnapshotOperation::Allocate,
        };
        assert_eq!(
            q.submit(request, MAX_TIME + 1).unwrap_err().reason,
            SnapshotQueueError::Overflow
        );
        assert_eq!(
            q.progress(MAX_TIME + 1, 0, 0),
            Err(SnapshotQueueError::Clock)
        );
        assert_eq!(q.error(), Some(SnapshotQueueError::Clock));
    }
    fn compat_queue(slots: usize, compatible: bool) -> SnapshotQueue {
        let limits = SnapshotLimits {
            slots,
            bytes: 32,
            response_bytes: 16,
        };
        let fsid = queue().fsid;
        if compatible {
            SnapshotQueue::new_compatible(fsid, limits)
        } else {
            SnapshotQueue::new(fsid, limits)
        }
        .unwrap()
    }
    fn named(capacity: usize) -> NamedSnapshotRequest {
        let mut name = Vec::with_capacity(capacity);
        name.extend_from_slice(b"snap");
        NamedSnapshotRequest {
            pool: 7,
            operation: NamedSnapshotOperation::Create,
            name,
        }
    }
    fn allocate() -> SnapshotRequest {
        SnapshotRequest {
            pool: 7,
            operation: SnapshotOperation::Allocate,
        }
    }
    #[test]
    fn strict_rejects_oversize_named_request_while_compatible_admits_sole_one() {
        let mut strict = compat_queue(2, false);
        let rejected = strict.submit_named(named(64), 100).unwrap_err();
        assert_eq!(rejected.reason, SnapshotQueueError::NoCredit);
        assert_eq!(rejected.request.name.capacity(), 64);
        assert_eq!((strict.outstanding(), strict.charged_bytes()), (0, 0));
        let mut q = compat_queue(2, true);
        let token = q.submit_named(named(64), 100).unwrap();
        assert_eq!((q.outstanding(), q.charged_bytes()), (1, 80));
        assert_eq!(q.prepare(token).unwrap().name, b"snap");
    }
    #[test]
    fn compatible_occupied_queue_returns_unchanged_input_and_readmits_after_consumption() {
        let mut q = compat_queue(3, true);
        let first = q.submit_named(named(64), 100).unwrap();
        let sequence = q.sequence;
        let second = named(48);
        let pointer = second.name.as_ptr();
        let rejected = q.submit_named(second, 100).unwrap_err();
        assert_eq!(rejected.reason, SnapshotQueueError::NoCredit);
        assert_eq!(rejected.request.name.as_ptr(), pointer);
        assert_eq!(rejected.request.name.capacity(), 48);
        assert_eq!(
            q.submit(allocate(), 100).unwrap_err().reason,
            SnapshotQueueError::NoCredit
        );
        assert_eq!(
            (q.sequence, q.charged_bytes(), q.outstanding()),
            (sequence, 80, 1)
        );
        q.cancel(first).unwrap();
        assert_eq!(q.charged_bytes(), 80);
        let rejected = q.submit_named(rejected.request, 100).unwrap_err();
        assert_eq!(rejected.reason, SnapshotQueueError::NoCredit);
        assert_eq!(rejected.request.name.as_ptr(), pointer);
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        assert_eq!(q.charged_bytes(), 0);
        q.submit_named(rejected.request, 100).unwrap();
        assert_eq!(q.charged_bytes(), 64);
    }
    #[test]
    fn compatible_target_can_be_below_single_response_reservation() {
        let mut q = SnapshotQueue::new_compatible(
            queue().fsid,
            SnapshotLimits {
                slots: 2,
                bytes: 1,
                response_bytes: 8,
            },
        )
        .unwrap();
        let first = q.submit(allocate(), 100).unwrap();
        assert_eq!(q.charged_bytes(), 8);
        assert_eq!(
            q.submit(allocate(), 100).unwrap_err().reason,
            SnapshotQueueError::NoCredit
        );
        q.cancel(first).unwrap();
        q.poll_into(&mut [None]);
        q.submit(allocate(), 100).unwrap();
    }
    #[test]
    fn compatible_within_target_shares_credit_and_exact_slots_stay_finite() {
        let mut q = compat_queue(2, true);
        q.submit(allocate(), 100).unwrap();
        q.submit(allocate(), 100).unwrap();
        assert_eq!(q.charged_bytes(), 32);
        assert_eq!(
            q.submit(allocate(), 100).unwrap_err().reason,
            SnapshotQueueError::NoCredit
        );
        let mut roomy = SnapshotQueue::new_compatible(
            q.fsid,
            SnapshotLimits {
                slots: 2,
                bytes: 1 << 20,
                response_bytes: 16,
            },
        )
        .unwrap();
        roomy.submit(allocate(), 100).unwrap();
        roomy.submit(allocate(), 100).unwrap();
        assert_eq!(
            roomy.submit(allocate(), 100).unwrap_err().reason,
            SnapshotQueueError::NoCredit
        );
        assert_eq!(roomy.outstanding(), 2);
    }
    #[test]
    fn charge_overflow_rejects_without_changing_counter_or_identity() {
        for compatible in [false, true] {
            let mut q = compat_queue(2, compatible);
            q.charged = u64::MAX - 1;
            let sequence = q.sequence;
            let request = named(4);
            let pointer = request.name.as_ptr();
            let rejected = q.submit_named(request, 100).unwrap_err();
            assert_eq!(rejected.reason, SnapshotQueueError::NoCredit);
            assert_eq!(rejected.request.name.as_ptr(), pointer);
            assert_eq!(
                (q.charged_bytes(), q.sequence, q.outstanding()),
                (u64::MAX - 1, sequence, 0)
            );
        }
    }
}
