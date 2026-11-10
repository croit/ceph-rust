// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optional bounded send-once monitor commands, ADR0278/spec163.
use crate::BootstrapError;
use crate::time::{self, MAX_TIME_US as MAX_TIME};
use std::{
    fmt,
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
pub struct MonitorCommandRequest {
    pub commands: Vec<String>,
    pub input: Vec<u8>,
}
impl fmt::Debug for MonitorCommandRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MonitorCommandRequest")
            .field("commands", &self.commands.len())
            .field("input_bytes", &self.input.len())
            .finish_non_exhaustive()
    }
}
pub struct MonitorCommandReply {
    pub version: u64,
    pub result: i32,
    pub status: String,
    pub data: Vec<u8>,
}
impl fmt::Debug for MonitorCommandReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MonitorCommandReply")
            .field("version", &self.version)
            .field("result", &self.result)
            .field("status_bytes", &self.status.len())
            .field("data_bytes", &self.data.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonitorCommandLimits {
    pub slots: usize,
    pub bytes: u64,
    pub request_bytes: u32,
    pub reply_bytes: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonitorCommandError {
    Overflow,
    Limits,
    Disabled,
    AlreadyEnabled,
    NotReady,
    NoCredit,
    Identity,
    Stale,
    AlreadyComplete,
    Clock,
    RequestTooLarge,
    ReplyTooLarge,
    Protocol,
    Transport,
    MonitorLost,
    Deadline,
    Cancelled,
    Closed,
    Bootstrap(BootstrapError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonitorCommandToken {
    owner: u64,
    slot: usize,
    sequence: u64,
}
#[derive(Debug)]
pub struct RejectedMonitorCommand {
    pub reason: MonitorCommandError,
    pub request: MonitorCommandRequest,
}
#[derive(Debug)]
pub enum MonitorCommandOutcome {
    Reply(MonitorCommandReply),
    Failed {
        error: MonitorCommandError,
        possibly_sent: bool,
    },
}
#[derive(Debug)]
pub struct MonitorCommandCompletion {
    pub token: MonitorCommandToken,
    pub outcome: MonitorCommandOutcome,
}
pub struct MonitorCommandDispatch {
    pub token: MonitorCommandToken,
    pub commands: Vec<String>,
    pub input: Vec<u8>,
}
impl fmt::Debug for MonitorCommandDispatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MonitorCommandDispatch")
            .field("token", &self.token)
            .field("commands", &self.commands.len())
            .field("input_bytes", &self.input.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Queued,
    Dispatching,
    InFlight(u64),
    Done,
}
struct Entry {
    token: MonitorCommandToken,
    request: MonitorCommandRequest,
    deadline: u64,
    started: u64,
    charge: u64,
    stage: Stage,
    possibly_sent: bool,
    abandoned: Option<u64>,
    outcome: Option<MonitorCommandOutcome>,
}
pub struct MonitorCommandQueue {
    owner: u64,
    sequence: u64,
    now: u64,
    limits: Option<MonitorCommandLimits>,
    compatible: Option<crate::CommandCompatibleProfile>,
    entries: Vec<Option<Entry>>,
    occupied: usize,
    cursor: usize,
    dispatch_cursor: usize,
    charged: u64,
    error: Option<MonitorCommandError>,
    _owner: PhantomData<Rc<()>>,
}
impl fmt::Debug for MonitorCommandQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MonitorCommandQueue")
            .field("outstanding", &self.outstanding())
            .field("charged_bytes", &self.charged)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl MonitorCommandQueue {
    pub fn new(limits: MonitorCommandLimits) -> Result<Self, MonitorCommandError> {
        if !(1..=4096).contains(&limits.slots)
            || limits.request_bytes == 0
            || limits.reply_bytes == 0
            || limits.bytes
                < u64::from(limits.reply_bytes)
                    + std::mem::size_of::<MonitorCommandRequest>() as u64
        {
            return Err(MonitorCommandError::Limits);
        }
        Self::create(limits.slots, Some(limits), None)
    }
    fn create(
        slots: usize,
        limits: Option<MonitorCommandLimits>,
        compatible: Option<crate::CommandCompatibleProfile>,
    ) -> Result<Self, MonitorCommandError> {
        let owner = NEXT_OWNER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| MonitorCommandError::Identity)?;
        Ok(Self {
            owner,
            sequence: 0,
            now: 0,
            limits,
            compatible,
            entries: (0..slots).map(|_| None).collect(),
            occupied: 0,
            cursor: 0,
            dispatch_cursor: 0,
            charged: 0,
            error: None,
            _owner: PhantomData,
        })
    }
    pub fn new_compatible(
        profile: crate::CommandCompatibleProfile,
    ) -> Result<Self, MonitorCommandError> {
        profile.check_counter_bound(size_of::<Entry>())?;
        Self::create(profile.slots(), None, Some(profile))
    }
    pub fn request_size(request: &MonitorCommandRequest) -> Option<u64> {
        request.commands.iter().try_fold(
            std::mem::size_of::<MonitorCommandRequest>() as u64 + request.input.len() as u64,
            |n, command| {
                n.checked_add(std::mem::size_of::<String>() as u64)?
                    .checked_add(command.len() as u64)
            },
        )
    }
    fn retained_size(request: &MonitorCommandRequest) -> Option<u64> {
        let initial = (std::mem::size_of::<MonitorCommandRequest>() as u64)
            .checked_add(request.input.capacity() as u64)?
            .checked_add(
                (request.commands.capacity() as u64)
                    .checked_mul(std::mem::size_of::<String>() as u64)?,
            )?;
        request.commands.iter().try_fold(initial, |n, command| {
            n.checked_add(command.capacity() as u64)
        })
    }
    pub fn submit(
        &mut self,
        mut request: MonitorCommandRequest,
        deadline: u64,
    ) -> Result<MonitorCommandToken, RejectedMonitorCommand> {
        let reason = self.error.or({
            if time::validate_deadline(deadline).is_err() {
                Some(MonitorCommandError::Overflow)
            } else if time::is_due(deadline, self.now) {
                diag::diag!(
                    "WARNING TIMEOUT monitor command exceeded {}s (admission, deadline_us={deadline})",
                    time::budget_seconds(deadline.saturating_sub(self.now))
                );
                Some(MonitorCommandError::Deadline)
            } else {
                None
            }
        });
        let size = Self::request_size(&request);
        let charge = match self.compatible {
            Some(profile) => profile.request_charge(&request, size_of::<Entry>()),
            None => Self::retained_size(&request)
                .and_then(|n| n.checked_add(u64::from(self.limits.unwrap().reply_bytes))),
        };
        let reason = reason.or_else(|| {
            if self.compatible.map_or_else(
                || {
                    request.commands.len() > u32::MAX as usize
                        || size
                            .is_none_or(|size| size > u64::from(self.limits.unwrap().request_bytes))
                },
                |profile| profile.check_request(&request, true).is_err(),
            ) {
                Some(MonitorCommandError::RequestTooLarge)
            } else {
                None
            }
        });
        let slot = self.entries.iter().position(Option::is_none);
        let reason = reason.or_else(|| {
            if slot.is_none()
                || charge.is_none_or(|n| match self.compatible {
                    Some(profile) => profile
                        .admission()
                        .admit(self.charged, self.occupied, n)
                        .is_err(),
                    None => n > self.limits.unwrap().bytes - self.charged,
                })
            {
                Some(MonitorCommandError::NoCredit)
            } else if self.sequence == u64::MAX {
                Some(MonitorCommandError::Identity)
            } else {
                None
            }
        });
        if let Some(reason) = reason {
            return Err(RejectedMonitorCommand { reason, request });
        }
        let slot = slot.unwrap();
        if let Some(profile) = self.compatible {
            profile.normalize_request(&mut request);
        }
        self.sequence += 1;
        let token = MonitorCommandToken {
            owner: self.owner,
            slot,
            sequence: self.sequence,
        };
        let charge = charge.unwrap();
        self.charged += charge;
        self.entries[slot] = Some(Entry {
            token,
            request,
            deadline,
            started: self.now,
            charge,
            stage: Stage::Queued,
            possibly_sent: false,
            abandoned: None,
            outcome: None,
        });
        self.occupied += 1;
        Ok(token)
    }
    fn entry(&mut self, token: MonitorCommandToken) -> Result<&mut Entry, MonitorCommandError> {
        if token.owner != self.owner {
            return Err(MonitorCommandError::Stale);
        }
        self.entries
            .get_mut(token.slot)
            .and_then(Option::as_mut)
            .filter(|entry| entry.token == token)
            .ok_or(MonitorCommandError::Stale)
    }
    fn fail(entry: &mut Entry, error: MonitorCommandError) {
        if entry.stage == Stage::Done {
            return;
        }
        if matches!(error, MonitorCommandError::Deadline) {
            diag::diag!(
                "WARNING TIMEOUT monitor command exceeded {}s (deadline_us={} possibly_sent={})",
                time::budget_seconds(entry.deadline.saturating_sub(entry.started)),
                entry.deadline,
                entry.possibly_sent
            );
        }
        if let Stage::InFlight(tid) = entry.stage {
            entry.abandoned = Some(tid);
        }
        entry.stage = Stage::Done;
        entry.outcome = Some(MonitorCommandOutcome::Failed {
            error,
            possibly_sent: entry.possibly_sent,
        });
    }
    pub fn progress(&mut self, now: u64, work: usize) -> Result<(), MonitorCommandError> {
        if now < self.now || now > MAX_TIME {
            return Err(MonitorCommandError::Clock);
        }
        self.now = now;
        if self.occupied == 0 {
            return Ok(());
        }
        for _ in 0..work.min(self.entries.len()) {
            let index = self.cursor;
            self.cursor = (self.cursor + 1) % self.entries.len();
            if let Some(entry) = &mut self.entries[index]
                && entry.stage != Stage::Done
                && time::is_due(entry.deadline, now)
            {
                Self::fail(entry, MonitorCommandError::Deadline);
            }
        }
        Ok(())
    }
    pub fn next_dispatch(&mut self, work: usize) -> Option<MonitorCommandDispatch> {
        if self.error.is_some() || self.occupied == 0 {
            return None;
        }
        for _ in 0..work.min(self.entries.len()) {
            let index = self.dispatch_cursor;
            self.dispatch_cursor = (self.dispatch_cursor + 1) % self.entries.len();
            let Some(entry) = &mut self.entries[index] else {
                continue;
            };
            if entry.stage != Stage::Queued {
                continue;
            }
            if time::is_due(entry.deadline, self.now) {
                Self::fail(entry, MonitorCommandError::Deadline);
                continue;
            }
            entry.stage = Stage::Dispatching;
            entry.possibly_sent = true;
            return Some(MonitorCommandDispatch {
                token: entry.token,
                commands: entry.request.commands.clone(),
                input: std::mem::take(&mut entry.request.input),
            });
        }
        None
    }
    pub fn mark_dispatched(
        &mut self,
        token: MonitorCommandToken,
        tid: u64,
    ) -> Result<(), MonitorCommandError> {
        // Reject foreign/stale before considering a supplied transport correlation.
        if self.entry(token)?.stage != Stage::Dispatching {
            return Err(MonitorCommandError::Protocol);
        }
        if tid == 0 || self.owns_tid(tid) {
            return Err(MonitorCommandError::Protocol);
        }
        self.entry(token)?.stage = Stage::InFlight(tid);
        self.retire_handoff_input(token)
    }
    fn retire_handoff_input(
        &mut self,
        token: MonitorCommandToken,
    ) -> Result<(), MonitorCommandError> {
        let released = if let Some(profile) = self.compatible {
            let entry = self.entry(token)?;
            let retained = profile
                .request_charge(&entry.request, size_of::<Entry>())
                .expect("validated retained request");
            let released = entry.charge - retained;
            entry.charge = retained;
            released
        } else {
            0
        };
        self.charged -= released;
        Ok(())
    }
    pub fn handoff_failed(
        &mut self,
        token: MonitorCommandToken,
        error: MonitorCommandError,
        possibly_sent: bool,
    ) -> Result<(), MonitorCommandError> {
        let entry = self.entry(token)?;
        if entry.stage != Stage::Dispatching {
            return Err(MonitorCommandError::Protocol);
        }
        entry.possibly_sent = possibly_sent;
        Self::fail(entry, error);
        self.retire_handoff_input(token)
    }
    pub fn owns_tid(&self, tid: u64) -> bool {
        tid != 0
            && self
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.stage == Stage::InFlight(tid))
    }
    pub fn on_reply(
        &mut self,
        tid: u64,
        commands: Vec<String>,
        mut reply: MonitorCommandReply,
    ) -> Result<(), MonitorCommandError> {
        let cap = self.limits.map_or(0, |limits| limits.reply_bytes as usize);
        let now = self.now;
        let entry = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.stage == Stage::InFlight(tid))
            .ok_or(MonitorCommandError::Stale)?;
        // MonClient already consumed correlation. Never retain an orphan cancellation.
        entry.stage = Stage::Dispatching;
        let error = if time::is_due(entry.deadline, now) {
            Some(MonitorCommandError::Deadline)
        } else if commands != entry.request.commands {
            Some(MonitorCommandError::Protocol)
        } else if self.compatible.is_some_and(|p| {
            p.check_monitor_reply(&commands, &reply.status, reply.data.len())
                .is_err()
        }) || self.compatible.is_none()
            && reply
                .data
                .capacity()
                .checked_add(reply.status.capacity())
                .is_none_or(|n| n > cap)
        {
            Some(MonitorCommandError::ReplyTooLarge)
        } else {
            None
        };
        if let Some(error) = error {
            Self::fail(entry, error);
            return Err(error);
        }
        if let Some(profile) = self.compatible {
            let extra = match profile.normalize_reply(&mut reply.status, &mut reply.data) {
                Ok(extra) => extra,
                Err(error) => {
                    Self::fail(entry, error);
                    return Err(error);
                }
            };
            // Constructor proves slots * maximal representation fits u64. Reply
            // arrival does not compete with already accepted replies for target credit.
            entry.charge = entry
                .charge
                .checked_add(extra)
                .expect("validated command bound");
            self.charged = self
                .charged
                .checked_add(extra)
                .expect("validated command bound");
        }
        entry.stage = Stage::Done;
        entry.outcome = Some(MonitorCommandOutcome::Reply(reply));
        Ok(())
    }
    pub fn on_lost(&mut self, tid: u64) -> Result<(), MonitorCommandError> {
        let entry = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.stage == Stage::InFlight(tid))
            .ok_or(MonitorCommandError::Stale)?;
        entry.stage = Stage::Dispatching;
        Self::fail(entry, MonitorCommandError::MonitorLost);
        Ok(())
    }
    pub fn cancel(&mut self, token: MonitorCommandToken) -> Result<(), MonitorCommandError> {
        let entry = self.entry(token)?;
        if entry.stage == Stage::Done {
            return Err(MonitorCommandError::AlreadyComplete);
        }
        Self::fail(entry, MonitorCommandError::Cancelled);
        Ok(())
    }
    pub fn fail_pending(&mut self, error: MonitorCommandError) {
        for entry in self.entries.iter_mut().flatten() {
            Self::fail(entry, error);
        }
    }
    pub fn stop(&mut self, error: MonitorCommandError) {
        self.error.get_or_insert(error);
        self.fail_pending(error);
    }
    pub fn take_abandoned_tid(&mut self) -> Option<u64> {
        if self.occupied == 0 {
            return None;
        }
        self.entries
            .iter_mut()
            .flatten()
            .find_map(|entry| entry.abandoned.take())
    }
    pub fn poll_into(&mut self, out: &mut [Option<MonitorCommandCompletion>]) -> usize {
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
                .is_some_and(|entry| entry.stage == Stage::Done && entry.abandoned.is_none())
            {
                let mut entry = slot.take().unwrap();
                self.occupied -= 1;
                self.charged -= entry.charge;
                out[count] = Some(MonitorCommandCompletion {
                    token: entry.token,
                    outcome: entry.outcome.take().unwrap(),
                });
                count += 1;
            }
        }
        count
    }
    pub fn next_deadline_us(&self) -> Option<u64> {
        if self.occupied == 0 {
            return None;
        }
        self.entries
            .iter()
            .flatten()
            .filter(|entry| entry.stage != Stage::Done)
            .filter_map(|entry| time::timer(entry.deadline))
            .min()
    }
    pub fn can_wait(&self) -> bool {
        if self.occupied == 0 {
            return true;
        }
        self.entries
            .iter()
            .flatten()
            .all(|entry| matches!(entry.stage, Stage::InFlight(_)) && entry.deadline > self.now)
    }
    pub fn charged_bytes(&self) -> u64 {
        self.charged
    }
    pub fn outstanding(&self) -> usize {
        self.occupied
    }
    pub fn error(&self) -> Option<MonitorCommandError> {
        self.error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wide_command_budget_and_unlimited_timer_are_independent() {
        let mut q = MonitorCommandQueue::new_compatible(
            crate::CommandCompatibleProfile::new(2, 4096).unwrap(),
        )
        .unwrap();
        let request = || MonitorCommandRequest {
            commands: vec!["status".into()],
            input: vec![],
        };
        let end = time::deadline_after(5, 1u64 << 32).unwrap();
        let finite = q.submit(request(), end).unwrap();
        let unlimited = q.submit(request(), time::NO_DEADLINE).unwrap();
        q.progress(end - 1, 2).unwrap();
        assert_eq!(q.next_deadline_us(), Some(end));
        assert_eq!(q.poll_into(&mut [None]), 0);
        q.progress(end, 2).unwrap();
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        let done = out[0].take().unwrap();
        assert_eq!(done.token, finite);
        assert!(matches!(
            done.outcome,
            MonitorCommandOutcome::Failed {
                error: MonitorCommandError::Deadline,
                ..
            }
        ));
        assert_eq!(q.next_deadline_us(), None);
        q.progress(MAX_TIME, 2).unwrap();
        assert_eq!(q.poll_into(&mut out), 0);
        assert_eq!(q.next_dispatch(2).unwrap().token, unlimited);
        q.mark_dispatched(unlimited, 1).unwrap();
        assert!(q.can_wait());
        assert_eq!(q.next_deadline_us(), None);
        assert_eq!(
            q.submit(request(), MAX_TIME + 1).unwrap_err().reason,
            MonitorCommandError::Overflow
        );
    }
    #[test]
    fn compatible_completed_replies_overrun_target_without_losing_either_result() {
        let profile = crate::CommandCompatibleProfile::new(2, 2048).unwrap();
        let mut queue = MonitorCommandQueue::new_compatible(profile).unwrap();
        let mut tokens = Vec::new();
        for _ in 0..2 {
            tokens.push(
                queue
                    .submit(
                        MonitorCommandRequest {
                            commands: vec!["status".into()],
                            input: vec![],
                        },
                        100,
                    )
                    .unwrap(),
            );
        }
        let mut sends = Vec::new();
        for tid in 1..=2 {
            let dispatch = queue.next_dispatch(2).unwrap();
            queue.mark_dispatched(dispatch.token, tid).unwrap();
            sends.push((tid, dispatch.commands));
        }
        for (tid, commands) in sends.into_iter().rev() {
            queue
                .on_reply(
                    tid,
                    commands,
                    MonitorCommandReply {
                        version: tid,
                        result: -13,
                        status: "remote\0status".into(),
                        data: vec![tid as u8; 4096],
                    },
                )
                .unwrap();
        }
        assert!(queue.charged_bytes() > 2048);
        let rejected = queue
            .submit(
                MonitorCommandRequest {
                    commands: vec![],
                    input: vec![],
                },
                100,
            )
            .unwrap_err();
        assert_eq!(rejected.reason, MonitorCommandError::NoCredit);
        let held = queue.charged_bytes();
        assert_eq!(queue.poll_into(&mut []), 0);
        assert_eq!(queue.charged_bytes(), held);
        let mut out = [None, None];
        assert_eq!(queue.poll_into(&mut out), 2);
        assert_eq!(queue.charged_bytes(), 0);
        for completion in out.into_iter().flatten() {
            assert!(tokens.contains(&completion.token));
            match completion.outcome {
                MonitorCommandOutcome::Reply(reply) => {
                    assert_eq!(reply.result, -13);
                    assert_eq!(reply.status.as_bytes(), b"remote\0status");
                    assert_eq!(reply.data, vec![reply.version as u8; 4096]);
                }
                _ => panic!("validated reply lost"),
            }
        }
    }
    #[test]
    fn compatible_real_former_ceiling_request_and_reply_are_not_reserved_upfront() {
        let mut queue = MonitorCommandQueue::new_compatible(
            crate::CommandCompatibleProfile::new(1, 1).unwrap(),
        )
        .unwrap();
        let token = queue
            .submit(
                MonitorCommandRequest {
                    commands: vec!["read-only-own-fixture".into()],
                    input: vec![7; 32 << 20],
                },
                100,
            )
            .unwrap();
        assert!(queue.charged_bytes() < (33 << 20));
        let dispatch = queue.next_dispatch(1).unwrap();
        queue.mark_dispatched(token, 1).unwrap();
        queue
            .on_reply(
                1,
                dispatch.commands,
                MonitorCommandReply {
                    version: 1,
                    result: 0,
                    status: String::new(),
                    data: dispatch.input,
                },
            )
            .unwrap();
        let mut out = [None];
        assert_eq!(queue.poll_into(&mut out), 1);
        match out[0].take().unwrap().outcome {
            MonitorCommandOutcome::Reply(reply) => {
                assert!(reply.data.len() == 32 << 20 && reply.data.iter().all(|b| *b == 7))
            }
            _ => panic!("former ceiling reply rejected"),
        }
    }
    #[test]
    fn compatible_successful_handoff_retires_input_credit_but_keeps_echo() {
        let mut queue = MonitorCommandQueue::new_compatible(
            crate::CommandCompatibleProfile::new(2, 4096).unwrap(),
        )
        .unwrap();
        let token = queue
            .submit(
                MonitorCommandRequest {
                    commands: vec!["echo".into()],
                    input: vec![7; 3000],
                },
                100,
            )
            .unwrap();
        let charged = queue.charged_bytes();
        let dispatch = queue.next_dispatch(2).unwrap();
        assert_eq!(queue.charged_bytes(), charged); // not accepted yet
        let reject = queue
            .submit(
                MonitorCommandRequest {
                    commands: vec![],
                    input: vec![9; 3000],
                },
                100,
            )
            .unwrap_err();
        assert_eq!(reject.reason, MonitorCommandError::NoCredit);
        queue.mark_dispatched(token, 1).unwrap();
        assert_eq!(
            queue.charged_bytes(),
            charged - dispatch.input.capacity() as u64
        );
        queue.submit(reject.request, 100).unwrap();
        assert_eq!(
            queue.on_reply(
                1,
                vec!["wrong".into()],
                MonitorCommandReply {
                    version: 0,
                    result: 0,
                    status: String::new(),
                    data: vec![]
                }
            ),
            Err(MonitorCommandError::Protocol)
        );
        let dispatch = queue.next_dispatch(2).unwrap();
        let held = queue.charged_bytes();
        let input_capacity = dispatch.input.capacity();
        drop(dispatch.input);
        queue
            .handoff_failed(dispatch.token, MonitorCommandError::Transport, true)
            .unwrap();
        assert_eq!(queue.charged_bytes(), held - input_capacity as u64);
    }
    fn request() -> MonitorCommandRequest {
        MonitorCommandRequest {
            commands: vec!["secret-command".into(), "".into(), "second".into()],
            input: vec![0, 255, 1],
        }
    }
    fn queue() -> MonitorCommandQueue {
        MonitorCommandQueue::new(MonitorCommandLimits {
            slots: 2,
            bytes: 2048,
            request_bytes: 512,
            reply_bytes: 128,
        })
        .unwrap()
    }
    fn reply() -> MonitorCommandReply {
        MonitorCommandReply {
            version: 42,
            result: -13,
            status: "secret-status".into(),
            data: vec![0, 255],
        }
    }
    fn take(q: &mut MonitorCommandQueue) -> MonitorCommandCompletion {
        let mut out = [None];
        assert_eq!(q.poll_into(&mut out), 1);
        out[0].take().unwrap()
    }
    #[test]
    fn empty_fast_paths_preserve_clock_and_held_completion_credit() {
        let mut q = queue();
        assert_eq!(q.outstanding(), 0);
        q.progress(50, 2).unwrap();
        assert_eq!(q.progress(49, 2), Err(MonitorCommandError::Clock));
        assert_eq!(q.next_deadline_us(), None);
        assert!(q.can_wait());
        assert!(q.next_dispatch(2).is_none());
        let a = q.submit(request(), 100).unwrap();
        let b = q.submit(request(), 100).unwrap();
        assert_eq!(q.outstanding(), 2);
        q.cancel(a).unwrap();
        q.cancel(b).unwrap();
        assert_eq!(q.outstanding(), 2); // terminal entries still own credit
        assert!(!q.can_wait());
        let mut held = [None];
        assert_eq!(q.poll_into(&mut held), 1);
        assert_eq!(q.poll_into(&mut held), 0);
        assert_eq!(q.outstanding(), 1);
        take(&mut q);
        assert_eq!(q.outstanding(), 0);
        assert_eq!(q.poll_into(&mut [None]), 0);
        assert!(q.can_wait());
        q.progress(90, 2).unwrap();
        assert_eq!(
            q.submit(request(), 89).unwrap_err().reason,
            MonitorCommandError::Deadline
        );
        q.submit(request(), 100).unwrap();
        assert_eq!(q.outstanding(), 1);
    }
    fn failed(done: MonitorCommandCompletion, error: MonitorCommandError, possibly_sent: bool) {
        assert!(
            matches!(done.outcome, MonitorCommandOutcome::Failed { error: e, possibly_sent: p } if e==error && p==possibly_sent)
        );
    }
    #[test]
    fn exact_vector_raw_reply_ownership_redaction_and_credit_release() {
        let mut q = queue();
        let token = q.submit(request(), 100).unwrap();
        let charge = q.charged_bytes();
        assert!(charge > 128);
        assert!(!q.can_wait());
        assert_eq!(q.next_deadline_us(), Some(100));
        let dispatch = q.next_dispatch(2).unwrap();
        assert_eq!(dispatch.commands, ["secret-command", "", "second"]);
        assert_eq!(dispatch.input, [0, 255, 1]);
        for text in [
            format!("{:?}", request()),
            format!("{dispatch:?}"),
            format!("{:?}", reply()),
            format!("{q:?}"),
        ] {
            assert!(!text.contains("secret-"));
        }
        q.mark_dispatched(token, 9).unwrap();
        assert!(q.can_wait());
        assert_eq!(
            q.on_reply(8, dispatch.commands.clone(), reply()),
            Err(MonitorCommandError::Stale)
        );
        assert_eq!(q.charged_bytes(), charge);
        q.on_reply(9, dispatch.commands, reply()).unwrap();
        assert!(!q.can_wait());
        let done = take(&mut q);
        assert_eq!(done.token, token);
        let MonitorCommandOutcome::Reply(reply) = done.outcome else {
            panic!()
        };
        assert_eq!((reply.version, reply.result), (42, -13));
        assert_eq!(reply.status, "secret-status");
        assert_eq!(reply.data, [0, 255]);
        assert_eq!(q.charged_bytes(), 0);
        assert_eq!(q.outstanding(), 0);
        assert!(q.can_wait());
        assert_eq!(q.cancel(token), Err(MonitorCommandError::Stale));
        let fresh = q.submit(request(), 100).unwrap();
        assert_ne!(fresh, token);
        assert_eq!(q.cancel(token), Err(MonitorCommandError::Stale));
        let foreign = queue().submit(request(), 100).unwrap();
        assert_eq!(q.cancel(foreign), Err(MonitorCommandError::Stale));
    }
    #[test]
    fn rejected_requests_keep_ownership_and_memory_credit() {
        let mut q = queue();
        q.submit(request(), 100).unwrap();
        q.submit(request(), 100).unwrap();
        let charge = q.charged_bytes();
        let rejected = q.submit(request(), 100).unwrap_err();
        assert_eq!(rejected.reason, MonitorCommandError::NoCredit);
        assert_eq!(rejected.request.input, [0, 255, 1]);
        assert_eq!(q.charged_bytes(), charge);
        let mut large = request();
        large.input = vec![1; 513];
        assert_eq!(
            q.submit(large, 100).unwrap_err().reason,
            MonitorCommandError::RequestTooLarge
        );
        let mut limits = q.limits.unwrap();
        limits.bytes = 200;
        let mut q = MonitorCommandQueue::new(limits).unwrap();
        assert_eq!(
            q.submit(request(), 100).unwrap_err().reason,
            MonitorCommandError::NoCredit
        );
        assert_eq!(q.charged_bytes(), 0);
    }
    #[test]
    fn occupied_completion_outputs_are_preserved_without_consuming_queue_credit() {
        let mut q = queue();
        let a = q.submit(request(), 100).unwrap();
        q.cancel(a).unwrap();
        let previous = take(&mut q);
        let b = q.submit(request(), 100).unwrap();
        q.cancel(b).unwrap();
        let credit = q.charged_bytes();
        let mut out = [Some(previous), None];
        assert_eq!(q.poll_into(&mut out), 0);
        assert_eq!(out[0].as_ref().unwrap().token, a);
        assert!(out[1].is_none());
        assert_eq!(q.charged_bytes(), credit);
        out[0] = None;
        assert_eq!(q.poll_into(&mut out), 1);
        assert_eq!(out[0].as_ref().unwrap().token, b);
        assert_eq!(q.charged_bytes(), 0);
    }
    #[test]
    fn spare_capacities_are_charged_and_oversize_retained_replies_rejected() {
        for kind in 0..3 {
            let mut q = queue();
            let mut r = request();
            match kind {
                0 => r.input.reserve(4096),
                1 => r.commands.reserve(4096),
                _ => r.commands[0].reserve(4096),
            }
            let rejected = q.submit(r, 100).unwrap_err();
            assert_eq!(rejected.reason, MonitorCommandError::NoCredit);
            assert_eq!(q.outstanding(), 0);
            assert_eq!(q.charged_bytes(), 0);
            assert!(MonitorCommandQueue::retained_size(&rejected.request).unwrap() > 2048);
        }
        for kind in 0..2 {
            let mut q = queue();
            let token = q.submit(request(), 100).unwrap();
            let d = q.next_dispatch(2).unwrap();
            q.mark_dispatched(token, 1).unwrap();
            let mut r = reply();
            if kind == 0 {
                r.data.reserve(4096);
            } else {
                r.status.reserve(4096);
            }
            assert_eq!(
                q.on_reply(1, d.commands, r),
                Err(MonitorCommandError::ReplyTooLarge)
            );
            failed(take(&mut q), MonitorCommandError::ReplyTooLarge, true);
        }
    }
    #[test]
    fn abandoned_tids_hold_slots_until_detached_and_are_bounded_under_reuse() {
        let mut q = queue();
        for tid in 1..100 {
            let token = q.submit(request(), 100).unwrap();
            q.next_dispatch(2).unwrap();
            q.mark_dispatched(token, tid).unwrap();
            q.cancel(token).unwrap();
            assert_eq!(q.cancel(token), Err(MonitorCommandError::AlreadyComplete));
            assert_eq!(q.poll_into(&mut [None]), 0);
            assert_eq!(q.take_abandoned_tid(), Some(tid));
            assert_eq!(q.take_abandoned_tid(), None);
            failed(take(&mut q), MonitorCommandError::Cancelled, true);
            assert_eq!(q.charged_bytes(), 0);
        }
    }
    #[test]
    fn deadlines_clock_validation_and_handoff_uncertainty() {
        let mut q = queue();
        q.submit(request(), 10).unwrap();
        q.progress(10, 2).unwrap();
        failed(take(&mut q), MonitorCommandError::Deadline, false);
        assert_eq!(
            q.submit(request(), 10).unwrap_err().reason,
            MonitorCommandError::Deadline
        );
        let token = q.submit(request(), 20).unwrap();
        let d = q.next_dispatch(2).unwrap();
        q.mark_dispatched(token, 3).unwrap();
        assert_eq!(q.progress(9, 2), Err(MonitorCommandError::Clock));
        assert_eq!(q.progress(MAX_TIME + 1, 2), Err(MonitorCommandError::Clock));
        assert!(q.owns_tid(3));
        assert_eq!(q.next_deadline_us(), Some(20));
        q.progress(20, 0).unwrap();
        assert_eq!(
            q.on_reply(3, d.commands, reply()),
            Err(MonitorCommandError::Deadline)
        );
        assert_eq!(q.take_abandoned_tid(), None);
        failed(take(&mut q), MonitorCommandError::Deadline, true);
        let token = q.submit(request(), 100).unwrap();
        q.next_dispatch(2).unwrap();
        q.handoff_failed(token, MonitorCommandError::NotReady, false)
            .unwrap();
        failed(take(&mut q), MonitorCommandError::NotReady, false);
    }
    #[test]
    fn echo_caps_duplicate_tids_and_loss_never_publish_unverified_results() {
        for mode in 0..3 {
            let mut q = queue();
            let token = q.submit(request(), 100).unwrap();
            let d = q.next_dispatch(2).unwrap();
            q.mark_dispatched(token, 1).unwrap();
            let (error, result) = match mode {
                0 => (
                    MonitorCommandError::Protocol,
                    q.on_reply(1, vec!["wrong".into()], reply()),
                ),
                1 => {
                    let mut r = reply();
                    r.data = vec![0; 129];
                    (
                        MonitorCommandError::ReplyTooLarge,
                        q.on_reply(1, d.commands, r),
                    )
                }
                _ => (MonitorCommandError::MonitorLost, q.on_lost(1)),
            };
            if mode < 2 {
                assert_eq!(result, Err(error));
            } else {
                result.unwrap();
            }
            assert_eq!(q.take_abandoned_tid(), None);
            failed(take(&mut q), error, true);
        }
        let mut q = queue();
        let a = q.submit(request(), 100).unwrap();
        let b = q.submit(request(), 100).unwrap();
        q.next_dispatch(2).unwrap();
        q.mark_dispatched(a, 7).unwrap();
        q.next_dispatch(2).unwrap();
        assert_eq!(q.mark_dispatched(b, 7), Err(MonitorCommandError::Protocol));
        assert_eq!(q.mark_dispatched(b, 0), Err(MonitorCommandError::Protocol));
        q.handoff_failed(b, MonitorCommandError::Protocol, true)
            .unwrap();
        failed(take(&mut q), MonitorCommandError::Protocol, true);
    }
    #[test]
    fn monitor_loss_is_current_only_close_sticky_and_done_results_preserved() {
        let mut q = queue();
        let token = q.submit(request(), 100).unwrap();
        let d = q.next_dispatch(2).unwrap();
        q.mark_dispatched(token, 1).unwrap();
        q.on_reply(1, d.commands, reply()).unwrap();
        q.submit(request(), 100).unwrap();
        q.fail_pending(MonitorCommandError::MonitorLost);
        assert!(matches!(
            take(&mut q).outcome,
            MonitorCommandOutcome::Reply(_)
        ));
        failed(take(&mut q), MonitorCommandError::MonitorLost, false);
        q.submit(request(), 100).unwrap();
        q.stop(MonitorCommandError::Closed);
        failed(take(&mut q), MonitorCommandError::Closed, false);
        assert_eq!(
            q.submit(request(), 100).unwrap_err().reason,
            MonitorCommandError::Closed
        );
        assert!(q.next_dispatch(2).is_none());
    }
}
