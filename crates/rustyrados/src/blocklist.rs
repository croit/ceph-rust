// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Fixed-slot blocklist-add state, RC-BLOCK62. Driver supplies verified maps/once replies.
use crate::time::{self, MAX_TIME_US as MAX_TIME};
use denc::types::{EntityAddr, UTime, Uuid};
use osdmap::{OsdMap, consts::release};
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlocklistRequest {
    pub address: EntityAddr,
    pub expire_seconds: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlocklistLimits {
    pub slots: usize,
    pub reply_bytes: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlocklistError {
    Overflow,
    Limits,
    Disabled,
    AlreadyEnabled,
    NotReady,
    InvalidAddress,
    NoCredit,
    Identity,
    Stale,
    AlreadyComplete,
    Clock,
    Fsid,
    MapRegression,
    Protocol,
    ReplyLimit,
    EntryAbsent,
    Deadline,
    Cancelled,
    Closed,
    MonitorLost,
    Transport,
    Remote(i32),
    Bootstrap(crate::BootstrapError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlocklistCertainty {
    NotHanded,
    Unknown,
    Rejected(i32),
    Committed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlocklistToken {
    owner: u64,
    sequence: u64,
    slot: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RejectedBlocklist {
    pub reason: BlocklistError,
    pub request: BlocklistRequest,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlocklistOutcome {
    Observed {
        fsid: Uuid,
        committed_epoch: u32,
        target_epoch: u32,
        observed_epoch: u32,
        expires: UTime,
    },
    Failed {
        error: BlocklistError,
        certainty: BlocklistCertainty,
        committed_epoch: Option<u32>,
    },
}
#[derive(Debug, PartialEq, Eq)]
pub struct BlocklistAck {
    pub version: u64,
    pub result: i32,
    pub status: String,
    pub data: Vec<u8>,
}
#[derive(Debug)]
pub struct BlocklistReply {
    pub tid: u64,
    pub ack: BlocklistAck,
    pub command: Vec<String>,
}
#[derive(Debug)]
pub struct BlocklistCompletion {
    pub token: BlocklistToken,
    pub request: BlocklistRequest,
    pub outcome: BlocklistOutcome,
    pub ack: Option<BlocklistAck>,
}
#[derive(Debug)]
pub struct BlocklistDispatch<'a> {
    pub token: BlocklistToken,
    pub command: &'a str,
}
#[derive(Debug)]
struct Entry {
    token: BlocklistToken,
    request: BlocklistRequest,
    command: String,
    deadline: u64,
    started: u64,
    handed: bool,
    tid: Option<u64>,
    committed: Option<u32>,
    deferred: bool,
    target: Option<u32>,
    rejected: Option<i32>,
    ack: Option<BlocklistAck>,
    outcome: Option<BlocklistOutcome>,
}
impl Entry {
    fn fail(&mut self, error: BlocklistError) {
        if self.outcome.is_some() {
            return;
        }
        if matches!(error, BlocklistError::Deadline) {
            diag::diag!(
                "WARNING TIMEOUT blocklist request exceeded {}s (deadline_us={} handed={})",
                time::budget_seconds(self.deadline.saturating_sub(self.started)),
                self.deadline,
                self.handed
            );
        }
        let certainty = if self.committed.is_some() {
            BlocklistCertainty::Committed
        } else if let Some(result) = self.rejected {
            BlocklistCertainty::Rejected(result)
        } else if self.handed {
            BlocklistCertainty::Unknown
        } else {
            BlocklistCertainty::NotHanded
        };
        self.outcome = Some(BlocklistOutcome::Failed {
            error,
            certainty,
            committed_epoch: self.committed,
        });
    }
}
#[derive(Debug)]
pub struct BlocklistQueue {
    owner: u64,
    sequence: u64,
    last_tid: u64,
    fsid: Uuid,
    epoch: u32,
    now: u64,
    reply_bytes: usize,
    entries: Vec<Option<Entry>>,
    occupied: usize,
    progress_cursor: usize,
    dispatch_cursor: usize,
    detach_cursor: usize,
    poll_cursor: usize,
    error: Option<BlocklistError>,
    _owner: PhantomData<Rc<()>>,
}
impl BlocklistQueue {
    pub fn new(fsid: Uuid, limits: BlocklistLimits) -> Result<Self, BlocklistError> {
        if fsid == Uuid::default() {
            return Err(BlocklistError::Fsid);
        }
        if !(1..=4096).contains(&limits.slots) || !(1..=65536).contains(&limits.reply_bytes) {
            return Err(BlocklistError::Limits);
        }
        let owner = NEXT_OWNER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| BlocklistError::Identity)?;
        Ok(Self {
            owner,
            sequence: 1,
            last_tid: 0,
            fsid,
            epoch: 0,
            now: 0,
            reply_bytes: limits.reply_bytes,
            entries: (0..limits.slots).map(|_| None).collect(),
            occupied: 0,
            progress_cursor: 0,
            dispatch_cursor: 0,
            detach_cursor: 0,
            poll_cursor: 0,
            error: None,
            _owner: PhantomData,
        })
    }
    pub fn error(&self) -> Option<BlocklistError> {
        self.error
    }
    pub fn outstanding(&self) -> usize {
        self.occupied
    }
    /// Correlation still owned by this queue, including a late terminal reply.
    pub(crate) fn owns_tid(&self, tid: u64) -> bool {
        tid != 0
            && self
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.tid == Some(tid))
    }
    /// Deferred observers additionally require the Bootstrap cohort/query guard.
    pub(crate) fn can_wait(&self, now: u64, map: &OsdMap) -> bool {
        now >= self.now
            && now <= MAX_TIME
            && map.fsid == self.fsid
            && map.epoch > 0
            && map.epoch >= self.epoch
            && (self.occupied == 0
                || self.entries.iter().flatten().all(|e| {
                    e.outcome.is_none()
                        && e.deadline > now
                        && e.handed
                        && match e.committed {
                            None => e.tid.is_some(),
                            Some(_) => e.target.map_or(e.deferred, |target| target > map.epoch),
                        }
                }))
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
    pub fn waiting_epoch(&self) -> Option<u32> {
        if self.occupied == 0 {
            return None;
        }
        self.entries
            .iter()
            .flatten()
            .filter(|e| e.outcome.is_none())
            .filter_map(|e| e.target)
            .filter(|&epoch| epoch > self.epoch)
            .min()
    }
    fn clock(&mut self, now: u64) -> Result<(), BlocklistError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        if now < self.now || now > MAX_TIME {
            self.abort(BlocklistError::Clock);
            return Err(BlocklistError::Clock);
        }
        self.now = now;
        Ok(())
    }
    pub fn submit(
        &mut self,
        request: BlocklistRequest,
        deadline_us: u64,
    ) -> Result<BlocklistToken, RejectedBlocklist> {
        let reject = |reason| RejectedBlocklist { reason, request };
        if let Some(error) = self.error {
            return Err(reject(error));
        }
        if self.epoch == 0 {
            return Err(reject(BlocklistError::NotReady));
        }
        if !canonical(request.address) {
            return Err(reject(BlocklistError::InvalidAddress));
        }
        if time::validate_deadline(deadline_us).is_err() {
            return Err(reject(BlocklistError::Overflow));
        }
        if time::is_due(deadline_us, self.now) {
            diag::diag!(
                "WARNING TIMEOUT blocklist request exceeded {}s (admission, deadline_us={deadline_us})",
                time::budget_seconds(deadline_us.saturating_sub(self.now))
            );
            return Err(reject(BlocklistError::Deadline));
        }
        let slot = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| reject(BlocklistError::NoCredit))?;
        if self.sequence == 0 {
            return Err(reject(BlocklistError::Identity));
        }
        let sequence = self.sequence;
        self.sequence = sequence.checked_add(1).unwrap_or(0);
        let token = BlocklistToken {
            owner: self.owner,
            sequence,
            slot,
        };
        use std::fmt::Write;
        let mut command = String::with_capacity(512);
        write!(
            command,
            "{{\"prefix\":\"osd blocklist\",\"blocklistop\":\"add\",\"addr\":\"{}\"",
            request.address
        )
        .unwrap();
        if request.expire_seconds != 0 {
            write!(command, ",\"expire\":{}.0", request.expire_seconds).unwrap();
        }
        command.push('}');
        debug_assert!(command.len() <= 512);
        self.entries[slot] = Some(Entry {
            token,
            request,
            command,
            deadline: deadline_us,
            started: self.now,
            handed: false,
            tid: None,
            committed: None,
            deferred: false,
            target: None,
            rejected: None,
            ack: None,
            outcome: None,
        });
        self.occupied += 1;
        Ok(token)
    }
    fn entry_mut(&mut self, token: BlocklistToken) -> Result<&mut Entry, BlocklistError> {
        if token.owner != self.owner {
            return Err(BlocklistError::Identity);
        }
        self.entries
            .get_mut(token.slot)
            .and_then(Option::as_mut)
            .filter(|e| e.token == token)
            .ok_or(BlocklistError::Stale)
    }
    pub(crate) fn defer_observation(
        &mut self,
        token: BlocklistToken,
    ) -> Result<(), BlocklistError> {
        let e = self.entry_mut(token)?;
        if e.outcome.is_some() || e.handed {
            return Err(BlocklistError::Protocol);
        }
        e.deferred = true;
        e.target = None;
        Ok(())
    }
    pub(crate) fn observation_at(&self, slot: usize) -> Option<(BlocklistToken, u64)> {
        let e = self.entries.get(slot)?.as_ref()?;
        (e.outcome.is_none()
            && e.deadline > self.now
            && e.deferred
            && e.committed.is_some()
            && e.target.is_none())
        .then_some((e.token, e.deadline))
    }
    pub(crate) fn observation_pending(&self, token: BlocklistToken) -> bool {
        self.observation_at(token.slot)
            .is_some_and(|(t, _)| t == token)
    }
    pub(crate) fn confirm_observation(
        &mut self,
        token: BlocklistToken,
        target: u32,
    ) -> Result<(), BlocklistError> {
        let e = self.entry_mut(token)?;
        if e.outcome.is_some() {
            return Err(BlocklistError::AlreadyComplete);
        }
        let commit = e.committed.ok_or(BlocklistError::Protocol)?;
        if !e.deferred || target == 0 {
            return Err(BlocklistError::Protocol);
        }
        e.target = Some(commit.max(target));
        Ok(())
    }
    pub(crate) fn fail_observation(&mut self, token: BlocklistToken, error: BlocklistError) {
        if let Ok(e) = self.entry_mut(token) {
            e.fail(error);
        }
    }
    pub fn next_command(&mut self, work: usize) -> Option<BlocklistDispatch<'_>> {
        if self.error.is_some() || self.occupied == 0 {
            return None;
        }
        let mut found = None;
        for _ in 0..work.min(self.entries.len()) {
            let i = self.dispatch_cursor;
            self.dispatch_cursor = (i + 1) % self.entries.len();
            if let Some(e) = &mut self.entries[i] {
                if e.outcome.is_some() || e.handed {
                    continue;
                }
                if time::is_due(e.deadline, self.now) {
                    e.fail(BlocklistError::Deadline);
                    continue;
                }
                found = Some(i);
                break;
            }
        }
        let e = self.entries[found?].as_ref().unwrap();
        Some(BlocklistDispatch {
            token: e.token,
            command: &e.command,
        })
    }
    pub fn mark_handed(&mut self, token: BlocklistToken, tid: u64) -> Result<(), BlocklistError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let now = self.now;
        let e = self.entry_mut(token)?;
        if e.outcome.is_some() {
            return Err(BlocklistError::AlreadyComplete);
        }
        if e.handed {
            return Err(BlocklistError::Protocol);
        }
        e.handed = true;
        if tid == 0 || tid <= self.last_tid {
            self.abort(BlocklistError::Protocol);
            return Err(BlocklistError::Protocol);
        }
        self.last_tid = tid;
        let e = self.entry_mut(token)?;
        e.tid = Some(tid);
        if time::is_due(e.deadline, now) {
            e.fail(BlocklistError::Deadline);
        }
        Ok(())
    }
    pub fn reject_handoff(&mut self, token: BlocklistToken) -> Result<(), BlocklistError> {
        let e = self.entry_mut(token)?;
        if e.outcome.is_some() {
            return Err(BlocklistError::AlreadyComplete);
        }
        if e.handed {
            return Err(BlocklistError::Protocol);
        }
        e.fail(BlocklistError::Transport);
        Ok(())
    }
    pub fn on_reply(&mut self, now: u64, reply: BlocklistReply) -> Result<bool, BlocklistError> {
        self.clock(now)?;
        let Some(e) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|e| e.tid == Some(reply.tid) && e.outcome.is_none())
        else {
            return Ok(false);
        };
        e.tid = None; // monc consumed this correlation before emitting the reply
        let deadline = time::is_due(e.deadline, now);
        if reply.command.len() != 1 || reply.command[0] != e.command {
            e.fail(if deadline {
                BlocklistError::Deadline
            } else {
                BlocklistError::Protocol
            });
            return Ok(true);
        }
        let ack = reply.ack;
        let valid_commit = ack.result == 0 && ack.version > 0 && ack.version <= u32::MAX as u64;
        if valid_commit {
            e.committed = Some(ack.version as u32);
            if !e.deferred {
                e.target = e.committed;
            }
        }
        if ack.result < 0 {
            e.rejected = Some(ack.result);
        }
        if ack
            .status
            .len()
            .checked_add(ack.data.len())
            .is_none_or(|size| size > self.reply_bytes)
        {
            e.fail(if deadline {
                BlocklistError::Deadline
            } else {
                BlocklistError::ReplyLimit
            });
            return Ok(true);
        }
        let result = ack.result;
        e.ack = Some(ack);
        if deadline {
            e.fail(BlocklistError::Deadline);
        } else if result < 0 {
            e.fail(BlocklistError::Remote(result));
        } else if !valid_commit {
            e.fail(BlocklistError::Protocol);
        }
        Ok(true)
    }
    pub fn lost(&mut self, tid: u64) {
        if let Some(e) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|e| e.tid == Some(tid) && e.outcome.is_none())
        {
            e.tid = None;
            e.fail(if time::is_due(e.deadline, self.now) {
                BlocklistError::Deadline
            } else {
                BlocklistError::MonitorLost
            });
        }
    }
    pub fn monitor_lost(&mut self) {
        for e in self
            .entries
            .iter_mut()
            .flatten()
            .filter(|e| e.outcome.is_none() && e.handed && e.committed.is_none())
        {
            e.tid = None;
            e.fail(if time::is_due(e.deadline, self.now) {
                BlocklistError::Deadline
            } else {
                BlocklistError::MonitorLost
            });
        }
    }
    pub fn progress(&mut self, now: u64, map: &OsdMap, work: usize) -> Result<(), BlocklistError> {
        self.clock(now)?;
        let bad = if map.fsid != self.fsid {
            Some(BlocklistError::Fsid)
        } else if map.epoch == 0 {
            Some(BlocklistError::Protocol)
        } else if map.epoch < self.epoch {
            Some(BlocklistError::MapRegression)
        } else {
            None
        };
        if let Some(error) = bad {
            self.abort(error);
            return Err(error);
        }
        self.epoch = map.epoch;
        if self.occupied == 0 {
            return Ok(());
        }
        for _ in 0..work.min(self.entries.len()) {
            let i = self.progress_cursor;
            self.progress_cursor = (i + 1) % self.entries.len();
            let Some(e) = &mut self.entries[i] else {
                continue;
            };
            if e.outcome.is_some() {
                continue;
            }
            if time::is_due(e.deadline, now) {
                e.fail(BlocklistError::Deadline);
                continue;
            }
            let Some(target_epoch) = e.target.filter(|&epoch| epoch <= map.epoch) else {
                continue;
            };
            let Some(committed_epoch) = e.committed else {
                continue;
            };
            let mut key = e.request.address;
            key.ty = if map.require_osd_release >= release::NAUTILUS {
                EntityAddr::TYPE_ANY
            } else {
                EntityAddr::TYPE_LEGACY
            };
            match map.blocklist.get(&key) {
                Some(expires) if expires.nsec < 1_000_000_000 => {
                    e.outcome = Some(BlocklistOutcome::Observed {
                        fsid: self.fsid,
                        committed_epoch,
                        target_epoch,
                        observed_epoch: map.epoch,
                        expires: *expires,
                    })
                }
                Some(_) => e.fail(BlocklistError::Protocol),
                None => e.fail(BlocklistError::EntryAbsent),
            }
        }
        Ok(())
    }
    pub fn cancel(&mut self, token: BlocklistToken) -> Result<(), BlocklistError> {
        let now = self.now;
        let e = self.entry_mut(token)?;
        if e.outcome.is_some() {
            return Err(BlocklistError::AlreadyComplete);
        }
        e.fail(if time::is_due(e.deadline, now) {
            BlocklistError::Deadline
        } else {
            BlocklistError::Cancelled
        });
        Ok(())
    }
    pub fn abort(&mut self, error: BlocklistError) {
        let error = *self.error.get_or_insert(error);
        for e in self.entries.iter_mut().flatten() {
            e.fail(error);
        }
    }
    pub fn close(&mut self) {
        self.abort(BlocklistError::Closed);
    }
    /// Driver immediately cancels this monc correlation; no wire rollback.
    pub fn take_abandoned_command(&mut self) -> Option<u64> {
        if self.occupied == 0 {
            return None;
        }
        for _ in 0..self.entries.len() {
            let i = self.detach_cursor;
            self.detach_cursor = (i + 1) % self.entries.len();
            if let Some(e) = &mut self.entries[i]
                && e.outcome.is_some()
                && let Some(tid) = e.tid.take()
            {
                return Some(tid);
            }
        }
        None
    }
    pub fn poll_into(&mut self, out: &mut [Option<BlocklistCompletion>]) -> usize {
        if self.occupied == 0 {
            return 0;
        }
        let mut scanned = 0;
        let mut n = 0;
        for cell in out.iter_mut().take(self.entries.len()) {
            if cell.is_some() {
                continue;
            }
            while scanned < self.entries.len() {
                let i = self.poll_cursor;
                self.poll_cursor = (i + 1) % self.entries.len();
                scanned += 1;
                if self.entries[i]
                    .as_ref()
                    .is_some_and(|e| e.outcome.is_some() && e.tid.is_none())
                {
                    let e = self.entries[i].take().unwrap();
                    self.occupied -= 1;
                    *cell = Some(BlocklistCompletion {
                        token: e.token,
                        request: e.request,
                        outcome: e.outcome.unwrap(),
                        ack: e.ack,
                    });
                    n += 1;
                    break;
                }
            }
            if scanned == self.entries.len() {
                break;
            }
        }
        n
    }
}
fn canonical(a: EntityAddr) -> bool {
    if !matches!(
        a.ty,
        EntityAddr::TYPE_LEGACY | EntityAddr::TYPE_MSGR2 | EntityAddr::TYPE_ANY
    ) {
        return false;
    }
    if let Some(ip) = a.ipv4() {
        a == EntityAddr::v4(a.ty, a.nonce, ip, a.port())
    } else if let Some(ip) = a.ipv6() {
        a == EntityAddr::v6(a.ty, a.nonce, ip, a.port(), 0)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wide_and_unlimited_waits_keep_wire_expiry_separate() {
        let mut q = queue(2, 1024);
        let end = time::deadline_after(100, 1u64 << 32).unwrap();
        let finite = q.submit(request(1), end).unwrap();
        let unlimited = q.submit(request(2), time::NO_DEADLINE).unwrap();
        q.progress(end - 1, &map(10), 2).unwrap();
        assert_eq!(q.next_deadline_us(), Some(end));
        assert_eq!(q.poll_into(&mut [None]), 0);
        q.progress(end, &map(10), 2).unwrap();
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        let done = out[0].take().unwrap();
        assert_eq!(done.token, finite);
        assert!(matches!(
            done.outcome,
            BlocklistOutcome::Failed {
                error: BlocklistError::Deadline,
                ..
            }
        ));
        assert_eq!(q.next_deadline_us(), None);
        q.progress(MAX_TIME, &map(10), 2).unwrap();
        assert_eq!(q.poll_into(&mut out), 0);
        assert_eq!(
            q.entries[unlimited.slot]
                .as_ref()
                .unwrap()
                .request
                .expire_seconds,
            60
        );
    }
    fn map(epoch: u32) -> OsdMap {
        let mut m = OsdMap::default();
        m.fsid = Uuid([7; 16]);
        m.epoch = epoch;
        m.require_osd_release = 21;
        m
    }
    fn request(nonce: u32) -> BlocklistRequest {
        BlocklistRequest {
            address: EntityAddr::v4(2, nonce, [10, 1, 2, 3], 0),
            expire_seconds: 60,
        }
    }
    fn queue(slots: usize, reply_bytes: usize) -> BlocklistQueue {
        let mut q =
            BlocklistQueue::new(Uuid([7; 16]), BlocklistLimits { slots, reply_bytes }).unwrap();
        q.progress(100, &map(10), 0).unwrap();
        q
    }
    fn reply(
        q: &BlocklistQueue,
        t: BlocklistToken,
        tid: u64,
        version: u64,
        result: i32,
    ) -> BlocklistReply {
        BlocklistReply {
            tid,
            ack: BlocklistAck {
                version,
                result,
                status: "ok\0status".into(),
                data: vec![0, 255],
            },
            command: vec![q.entries[t.slot].as_ref().unwrap().command.clone()],
        }
    }
    fn take(q: &mut BlocklistQueue) -> BlocklistCompletion {
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        out[0].take().unwrap()
    }
    fn failed(
        c: &BlocklistCompletion,
        error: BlocklistError,
        certainty: BlocklistCertainty,
        epoch: Option<u32>,
    ) {
        assert_eq!(
            c.outcome,
            BlocklistOutcome::Failed {
                error,
                certainty,
                committed_epoch: epoch
            }
        );
    }
    fn insert(m: &mut OsdMap, r: BlocklistRequest, expires: UTime) {
        let mut a = r.address;
        a.ty = if m.require_osd_release >= 14 { 3 } else { 1 };
        m.blocklist.insert(a, expires);
    }
    #[test]
    fn queue_wait_hint_preserves_deadline_map_and_retained_outcome() {
        let mut q = queue(1, 64);
        assert!(q.can_wait(100, &map(10)));
        let r = request(1);
        let token = q.submit(r, 300).unwrap();
        assert!(!q.can_wait(100, &map(10)));
        q.mark_handed(token, 1).unwrap();
        assert!(q.can_wait(100, &map(10)));
        assert!(!q.can_wait(300, &map(10)));
        let ack = reply(&q, token, 1, 11, 0);
        q.on_reply(101, ack).unwrap();
        assert!(q.can_wait(101, &map(10)));
        let mut newer = map(11);
        insert(&mut newer, r, UTime::new(999, 0));
        assert!(!q.can_wait(102, &newer));
        q.progress(102, &newer, 0).unwrap();
        assert!(!q.can_wait(102, &newer));
        q.progress(102, &newer, 1).unwrap();
        assert!(!q.can_wait(102, &newer));
        assert_eq!(take(&mut q).token, token);
        assert!(q.can_wait(102, &newer));
        assert!(!q.can_wait(101, &newer));
        assert!(!q.can_wait(102, &map(10)));
        newer.fsid = Uuid([8; 16]);
        assert!(!q.can_wait(102, &newer));
        assert!(!q.can_wait(MAX_TIME + 1, &map(11)));
    }
    #[test]
    fn canonical_typed_json_default_ttl_and_nonrepresentable_identity_rejection() {
        assert!(
            BlocklistQueue::new(
                Uuid::default(),
                BlocklistLimits {
                    slots: 1,
                    reply_bytes: 1
                }
            )
            .is_err()
        );
        for (slots, reply_bytes) in [(0, 1), (4097, 1), (1, 0), (1, 65537)] {
            assert_eq!(
                BlocklistQueue::new(Uuid([7; 16]), BlocklistLimits { slots, reply_bytes })
                    .unwrap_err(),
                BlocklistError::Limits
            );
        }
        let mut q = BlocklistQueue::new(
            Uuid([7; 16]),
            BlocklistLimits {
                slots: 8,
                reply_bytes: 64,
            },
        )
        .unwrap();
        assert_eq!(
            q.submit(request(7), 200).unwrap_err().reason,
            BlocklistError::NotReady
        );
        q.progress(100, &map(10), 0).unwrap();
        let r = request(7);
        let t = q.submit(r, 200).unwrap();
        assert_eq!(
            q.entries[t.slot].as_ref().unwrap().command,
            r#"{"prefix":"osd blocklist","blocklistop":"add","addr":"v2:10.1.2.3:0/7","expire":60.0}"#
        );
        let r = BlocklistRequest {
            address: EntityAddr::v4(3, 0, [0; 4], 0),
            expire_seconds: 0,
        };
        let t = q.submit(r, 200).unwrap();
        assert_eq!(
            q.entries[t.slot].as_ref().unwrap().command,
            r#"{"prefix":"osd blocklist","blocklistop":"add","addr":"0.0.0.0:0/0"}"#
        );
        let r = BlocklistRequest {
            address: EntityAddr::v6(1, u32::MAX, [255; 16], u16::MAX, 0),
            expire_seconds: u32::MAX,
        };
        let t = q.submit(r, 200).unwrap();
        let command = &q.entries[t.slot].as_ref().unwrap().command;
        assert!(command.contains("v1:[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535/4294967295"));
        assert!(command.ends_with(",\"expire\":4294967295.0}"));
        assert!(command.len() <= 512);
        let mut padding = request(1).address;
        padding.data[25] = 1;
        for address in [
            EntityAddr::blank(),
            EntityAddr::v4(4, 24, [1; 4], 0),
            padding,
            EntityAddr::v6(2, 1, [1; 16], 0, 2),
        ] {
            assert_eq!(
                q.submit(
                    BlocklistRequest {
                        address,
                        expire_seconds: 1
                    },
                    200
                )
                .unwrap_err()
                .reason,
                BlocklistError::InvalidAddress
            );
        }
        assert_eq!(
            q.submit(request(9), 100).unwrap_err().reason,
            BlocklistError::Deadline
        );
        assert_eq!(
            q.submit(request(9), MAX_TIME + 1).unwrap_err().reason,
            BlocklistError::Overflow
        );
    }
    #[test]
    fn ack_commit_target_exact_entry_then_observation_and_held_credit() {
        let mut q = queue(1, 64);
        let r = request(7);
        let t = q.submit(r, 300).unwrap();
        let dispatch = q.next_command(1).unwrap();
        assert_eq!(dispatch.token, t);
        q.mark_handed(t, 9).unwrap();
        let mut m = map(10);
        insert(&mut m, r, UTime::new(1, 2));
        q.progress(101, &m, 1).unwrap();
        assert_eq!(q.poll_into(&mut [None]), 0);
        let ack = reply(&q, t, 9, 12, 0);
        assert!(q.on_reply(102, ack).unwrap());
        assert_eq!(q.waiting_epoch(), Some(12));
        q.progress(103, &m, 1).unwrap();
        assert_eq!(q.poll_into(&mut [None]), 0);
        m.epoch = 12;
        q.progress(104, &m, 1).unwrap();
        assert_eq!(
            q.submit(r, 300).unwrap_err().reason,
            BlocklistError::NoCredit
        );
        let done = take(&mut q);
        assert_eq!(done.token, t);
        assert_eq!(done.request, r);
        assert_eq!(
            done.outcome,
            BlocklistOutcome::Observed {
                fsid: m.fsid,
                committed_epoch: 12,
                target_epoch: 12,
                observed_epoch: 12,
                expires: UTime::new(1, 2)
            }
        );
        assert_eq!(done.ack.unwrap().data, [0, 255]);
        assert_eq!(q.outstanding(), 0);
        assert_eq!(q.next_deadline_us(), None);
        assert_eq!(q.waiting_epoch(), None);
        let fresh = q.submit(r, 300).unwrap();
        assert_ne!(fresh, t);
        assert_eq!(q.cancel(t), Err(BlocklistError::Stale));
    }
    #[test]
    fn cancelled_handoff_requires_detachment_before_drain_and_late_ack_is_immutable() {
        let mut q = queue(1, 64);
        let t = q.submit(request(1), 300).unwrap();
        q.mark_handed(t, 1).unwrap();
        let late = reply(&q, t, 1, 11, 0);
        q.cancel(t).unwrap();
        assert_eq!(q.poll_into(&mut [None]), 0);
        assert_eq!(q.take_abandoned_command(), Some(1));
        assert_eq!(q.take_abandoned_command(), None);
        assert!(!q.on_reply(101, late).unwrap());
        let done = take(&mut q);
        failed(
            &done,
            BlocklistError::Cancelled,
            BlocklistCertainty::Unknown,
            None,
        );
        assert!(done.ack.is_none());
        assert_eq!(q.cancel(t), Err(BlocklistError::Stale));
    }
    #[test]
    fn echo_status_version_and_reply_bounds_preserve_trustworthy_facts() {
        for (version, result, expected, certainty, epoch) in [
            (
                0,
                0,
                BlocklistError::Protocol,
                BlocklistCertainty::Unknown,
                None,
            ),
            (
                u32::MAX as u64 + 1,
                0,
                BlocklistError::Protocol,
                BlocklistCertainty::Unknown,
                None,
            ),
            (
                11,
                1,
                BlocklistError::Protocol,
                BlocklistCertainty::Unknown,
                None,
            ),
            (
                0,
                -13,
                BlocklistError::Remote(-13),
                BlocklistCertainty::Rejected(-13),
                None,
            ),
        ] {
            let mut q = queue(1, 64);
            let t = q.submit(request(1), 300).unwrap();
            q.mark_handed(t, 1).unwrap();
            let a = reply(&q, t, 1, version, result);
            q.on_reply(101, a).unwrap();
            let c = take(&mut q);
            failed(&c, expected, certainty, epoch);
            assert_eq!(c.ack.unwrap().result, result);
        }
        for (result, certainty, epoch) in [
            (0, BlocklistCertainty::Committed, Some(11)),
            (-13, BlocklistCertainty::Rejected(-13), None),
        ] {
            let mut q = queue(1, 1);
            let t = q.submit(request(1), 300).unwrap();
            q.mark_handed(t, 1).unwrap();
            let a = reply(&q, t, 1, 11, result);
            q.on_reply(101, a).unwrap();
            let c = take(&mut q);
            failed(&c, BlocklistError::ReplyLimit, certainty, epoch);
            assert!(c.ack.is_none());
        }
        let mut q = queue(1, 64);
        let t = q.submit(request(1), 300).unwrap();
        q.mark_handed(t, 1).unwrap();
        let mut a = reply(&q, t, 1, 11, 0);
        a.command = vec!["{}".into()];
        q.on_reply(101, a).unwrap();
        let c = take(&mut q);
        failed(
            &c,
            BlocklistError::Protocol,
            BlocklistCertainty::Unknown,
            None,
        );
        assert!(c.ack.is_none());
    }
    #[test]
    fn deadline_wins_but_does_not_erase_acknowledged_commit_or_rejection() {
        for (result, certainty, epoch) in [
            (0, BlocklistCertainty::Committed, Some(11)),
            (-13, BlocklistCertainty::Rejected(-13), None),
        ] {
            let mut q = queue(1, 64);
            let t = q.submit(request(1), 200).unwrap();
            q.mark_handed(t, 1).unwrap();
            let a = reply(&q, t, 1, 11, result);
            q.on_reply(200, a).unwrap();
            let c = take(&mut q);
            failed(&c, BlocklistError::Deadline, certainty, epoch);
            assert_eq!(c.ack.unwrap().result, result);
        }
        let mut q = queue(1, 64);
        let t = q.submit(request(1), 200).unwrap();
        q.mark_handed(t, 1).unwrap();
        let a = reply(&q, t, 1, 11, 0);
        q.on_reply(199, a).unwrap();
        let mut m = map(11);
        insert(&mut m, request(1), UTime::new(9, 0));
        q.progress(200, &m, 1).unwrap();
        failed(
            &take(&mut q),
            BlocklistError::Deadline,
            BlocklistCertainty::Committed,
            Some(11),
        );
    }
    #[test]
    fn monitor_loss_does_not_replay_handed_commands_or_erase_committed_waits() {
        let mut q = queue(3, 64);
        let queued = q.submit(request(1), 300).unwrap();
        let lost = q.submit(request(2), 300).unwrap();
        let committed = q.submit(request(3), 300).unwrap();
        q.mark_handed(lost, 10).unwrap();
        q.mark_handed(committed, 11).unwrap();
        let a = reply(&q, committed, 11, 12, 0);
        q.on_reply(101, a).unwrap();
        q.monitor_lost();
        assert_eq!(q.next_command(3).unwrap().token, queued);
        assert_eq!(q.waiting_epoch(), Some(12));
        let c = take(&mut q);
        assert_eq!(c.token, lost);
        failed(
            &c,
            BlocklistError::MonitorLost,
            BlocklistCertainty::Unknown,
            None,
        );
        let mut m = map(12);
        insert(&mut m, request(3), UTime::new(1, 0));
        q.progress(102, &m, 3).unwrap();
        assert_eq!(take(&mut q).token, committed);
        q.mark_handed(queued, 12).unwrap();
        q.lost(12);
        failed(
            &take(&mut q),
            BlocklistError::MonitorLost,
            BlocklistCertainty::Unknown,
            None,
        );
    }
    #[test]
    fn wildcard_and_range_do_not_substitute_for_exact_committed_entry() {
        let mut q = queue(1, 64);
        let r = request(9);
        let t = q.submit(r, 300).unwrap();
        q.mark_handed(t, 1).unwrap();
        let a = reply(&q, t, 1, 11, 0);
        q.on_reply(101, a).unwrap();
        let mut m = map(11);
        let mut wildcard = r.address;
        wildcard.ty = 3;
        wildcard.nonce = 0;
        m.blocklist.insert(wildcard, UTime::new(999, 0));
        m.insert_range_blocklist(EntityAddr::v4(4, 24, [10, 1, 2, 0], 0), UTime::new(999, 0));
        assert!(m.is_blocklisted(&r.address));
        q.progress(102, &m, 1).unwrap();
        failed(
            &take(&mut q),
            BlocklistError::EntryAbsent,
            BlocklistCertainty::Committed,
            Some(11),
        );
        for release in [0, 10, 14, 21] {
            let mut q = queue(1, 64);
            let t = q.submit(r, 300).unwrap();
            q.mark_handed(t, 1).unwrap();
            let a = reply(&q, t, 1, 11, 0);
            q.on_reply(101, a).unwrap();
            let mut m = map(11);
            m.require_osd_release = release;
            insert(&mut m, r, UTime::default());
            q.progress(102, &m, 1).unwrap();
            assert!(matches!(
                take(&mut q).outcome,
                BlocklistOutcome::Observed {
                    expires: UTime { sec: 0, nsec: 0 },
                    ..
                }
            ));
        }
    }
    #[test]
    fn sticky_map_and_clock_failures_preserve_certainty_and_detach_correlations() {
        for error in [
            BlocklistError::Fsid,
            BlocklistError::MapRegression,
            BlocklistError::Clock,
        ] {
            let mut q = queue(3, 64);
            let handed = q.submit(request(1), 300).unwrap();
            let committed = q.submit(request(2), 300).unwrap();
            let queued = q.submit(request(3), 300).unwrap();
            q.mark_handed(handed, 1).unwrap();
            q.mark_handed(committed, 2).unwrap();
            let a = reply(&q, committed, 2, 11, 0);
            q.on_reply(101, a).unwrap();
            let mut m = map(10);
            let now = if error == BlocklistError::Clock {
                100
            } else {
                102
            };
            if error == BlocklistError::Fsid {
                m.fsid = Uuid([8; 16]);
            }
            if error == BlocklistError::MapRegression {
                m.epoch = 9;
            }
            assert_eq!(q.progress(now, &m, 3), Err(error));
            assert_eq!(q.error(), Some(error));
            assert_eq!(q.take_abandoned_command(), Some(1));
            let mut out = [None, None, None];
            assert_eq!(q.poll_into(&mut out), 3);
            for c in out.into_iter().flatten() {
                let certainty = if c.token == handed {
                    BlocklistCertainty::Unknown
                } else if c.token == committed {
                    BlocklistCertainty::Committed
                } else {
                    assert_eq!(c.token, queued);
                    BlocklistCertainty::NotHanded
                };
                failed(
                    &c,
                    error,
                    certainty,
                    if c.token == committed { Some(11) } else { None },
                );
            }
            assert_eq!(q.submit(request(4), 300).unwrap_err().reason, error);
        }
    }
    #[test]
    fn budgets_token_ownership_output_ownership_close_and_sequence_exhaustion() {
        let mut q = queue(3, 64);
        let a = q.submit(request(1), 200).unwrap();
        let b = q.submit(request(2), 200).unwrap();
        let c = q.submit(request(3), 200).unwrap();
        q.progress(200, &map(10), 1).unwrap();
        q.cancel(c).unwrap();
        q.progress(200, &map(10), 1).unwrap();
        let first = take(&mut q);
        assert_eq!(first.token, a);
        failed(
            &first,
            BlocklistError::Deadline,
            BlocklistCertainty::NotHanded,
            None,
        );
        let mut out = [Some(first), None, None];
        assert_eq!(q.poll_into(&mut out), 2);
        assert_eq!(out[0].as_ref().unwrap().token, a);
        assert!(out.iter().flatten().any(|done| done.token == b));
        assert_eq!(q.next_deadline_us(), None);
        let mut other = queue(1, 64);
        let foreign = other.submit(request(1), 300).unwrap();
        assert_eq!(q.cancel(foreign), Err(BlocklistError::Identity));
        assert_eq!(q.error(), None);
        q.sequence = u64::MAX;
        let last = q.submit(request(5), 300).unwrap();
        q.reject_handoff(last).unwrap();
        failed(
            &take(&mut q),
            BlocklistError::Transport,
            BlocklistCertainty::NotHanded,
            None,
        );
        assert_eq!(
            q.submit(request(6), 300).unwrap_err().reason,
            BlocklistError::Identity
        );
        other.close();
        failed(
            &take(&mut other),
            BlocklistError::Closed,
            BlocklistCertainty::NotHanded,
            None,
        );
    }
    #[test]
    fn malformed_map_expiration_close_and_handling_at_deadline_preserve_facts() {
        let mut q = queue(1, 64);
        let r = request(1);
        let t = q.submit(r, 300).unwrap();
        q.mark_handed(t, 1).unwrap();
        let a = reply(&q, t, 1, 11, 0);
        q.on_reply(101, a).unwrap();
        let mut m = map(11);
        insert(&mut m, r, UTime::new(99, 1_000_000_000));
        q.progress(102, &m, 1).unwrap();
        failed(
            &take(&mut q),
            BlocklistError::Protocol,
            BlocklistCertainty::Committed,
            Some(11),
        );
        let mut q = queue(3, 64);
        let a = q.submit(request(1), 300).unwrap();
        let b = q.submit(request(2), 300).unwrap();
        let c = q.submit(request(3), 300).unwrap();
        q.mark_handed(a, 1).unwrap();
        q.mark_handed(b, 2).unwrap();
        let ack = reply(&q, b, 2, 11, 0);
        q.on_reply(101, ack).unwrap();
        q.close();
        assert_eq!(q.take_abandoned_command(), Some(1));
        let mut out = [None, None, None];
        assert_eq!(q.poll_into(&mut out), 3);
        for done in out.into_iter().flatten() {
            let (certainty, epoch) = if done.token == a {
                (BlocklistCertainty::Unknown, None)
            } else if done.token == b {
                (BlocklistCertainty::Committed, Some(11))
            } else {
                assert_eq!(done.token, c);
                (BlocklistCertainty::NotHanded, None)
            };
            failed(&done, BlocklistError::Closed, certainty, epoch);
        }
        let mut q = queue(1, 64);
        let t = q.submit(r, 200).unwrap();
        q.progress(200, &map(10), 0).unwrap();
        q.mark_handed(t, 9).unwrap();
        assert_eq!(q.take_abandoned_command(), Some(9));
        failed(
            &take(&mut q),
            BlocklistError::Deadline,
            BlocklistCertainty::Unknown,
            None,
        );
    }
    #[test]
    fn completed_observation_is_immutable_and_invalid_monitor_ids_do_not_claim_not_handed() {
        let mut q = queue(1, 64);
        let r = request(1);
        let t = q.submit(r, 300).unwrap();
        q.mark_handed(t, u64::MAX).unwrap();
        let a = reply(&q, t, u64::MAX, 11, 0);
        q.on_reply(101, a).unwrap();
        let mut m = map(11);
        insert(&mut m, r, UTime::new(1, 0));
        q.progress(102, &m, 1).unwrap();
        q.close();
        assert!(matches!(
            take(&mut q).outcome,
            BlocklistOutcome::Observed { .. }
        ));
        for tid in [0, 1] {
            let mut q = queue(2, 64);
            let a = q.submit(r, 300).unwrap();
            let b = q.submit(request(2), 300).unwrap();
            q.mark_handed(a, 1).unwrap();
            assert_eq!(q.mark_handed(b, tid), Err(BlocklistError::Protocol));
            assert_eq!(q.take_abandoned_command(), Some(1));
            let mut out = [None, None];
            assert_eq!(q.poll_into(&mut out), 2);
            for c in out.into_iter().flatten() {
                failed(
                    &c,
                    BlocklistError::Protocol,
                    BlocklistCertainty::Unknown,
                    None,
                );
            }
        }
    }
}
