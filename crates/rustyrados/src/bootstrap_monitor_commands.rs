// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::{Bootstrap, BootstrapState};
use crate::{
    MonitorCommandCompletion, MonitorCommandError, MonitorCommandLimits, MonitorCommandQueue,
    MonitorCommandReply, MonitorCommandRequest, MonitorCommandToken, RejectedMonitorCommand,
};
use monc::MonSendError;
pub(super) struct MonitorCommandControl {
    pub(super) queue: MonitorCommandQueue,
    pub(super) work: usize,
}
impl Bootstrap {
    pub fn enable_compatible_monitor_commands(
        &mut self,
        profile: crate::CommandCompatibleProfile,
        work: usize,
    ) -> Result<(), MonitorCommandError> {
        if self.commands.is_some() {
            return Err(MonitorCommandError::AlreadyEnabled);
        }
        if !(1..=4096).contains(&work) {
            return Err(MonitorCommandError::Limits);
        }
        if self.state != BootstrapState::Ready {
            return Err(MonitorCommandError::NotReady);
        }
        let mut queue = MonitorCommandQueue::new_compatible(profile)?;
        queue.progress(self.control_now(), 0)?;
        self.commands = Some(MonitorCommandControl { queue, work });
        Ok(())
    }
    pub fn enable_monitor_commands(
        &mut self,
        limits: MonitorCommandLimits,
        work: usize,
    ) -> Result<(), MonitorCommandError> {
        if self.commands.is_some() {
            return Err(MonitorCommandError::AlreadyEnabled);
        }
        if !(1..=4096).contains(&work) {
            return Err(MonitorCommandError::Limits);
        }
        if self.state != BootstrapState::Ready {
            return Err(MonitorCommandError::NotReady);
        }
        let mut queue = MonitorCommandQueue::new(limits)?;
        queue.progress(self.control_now(), 0)?;
        self.commands = Some(MonitorCommandControl { queue, work });
        Ok(())
    }
    pub fn submit_monitor_command(
        &mut self,
        request: MonitorCommandRequest,
        deadline: u64,
    ) -> Result<MonitorCommandToken, RejectedMonitorCommand> {
        if self.commands.is_none() {
            return Err(RejectedMonitorCommand {
                reason: MonitorCommandError::Disabled,
                request,
            });
        }
        if self.state != BootstrapState::Ready {
            return Err(RejectedMonitorCommand {
                reason: MonitorCommandError::NotReady,
                request,
            });
        }
        let now = self.control_now();
        let queue = &mut self.commands.as_mut().unwrap().queue;
        if let Err(reason) = queue.progress(now, 0) {
            return Err(RejectedMonitorCommand { reason, request });
        }
        queue.submit(request, deadline)
    }
    pub fn cancel_monitor_command(
        &mut self,
        token: MonitorCommandToken,
    ) -> Result<(), MonitorCommandError> {
        self.commands
            .as_mut()
            .ok_or(MonitorCommandError::Disabled)?
            .queue
            .cancel(token)?;
        self.monitor_commands_detach(usize::MAX);
        Ok(())
    }
    pub fn poll_monitor_commands_into(
        &mut self,
        out: &mut [Option<MonitorCommandCompletion>],
    ) -> usize {
        self.commands
            .as_mut()
            .map_or(0, |control| control.queue.poll_into(out))
    }
    pub fn monitor_command_error(&self) -> Option<MonitorCommandError> {
        self.commands
            .as_ref()
            .and_then(|control| control.queue.error())
    }
    fn monitor_commands_detach(&mut self, work: usize) {
        let Some(control) = &mut self.commands else {
            return;
        };
        for _ in 0..work.min(control.queue.outstanding()) {
            let Some(tid) = control.queue.take_abandoned_tid() else {
                break;
            };
            if let Some(mon) = &mut self.monitor {
                mon.cancel_command_once(tid);
            }
        }
    }
    pub(super) fn monitor_commands_progress(&mut self, work: usize) {
        let now = self.control_now();
        if let Some(control) = &mut self.commands
            && let Err(error) = control.queue.progress(now, work)
        {
            control.queue.stop(error);
        }
        self.monitor_commands_detach(work);
    }
    pub(super) fn monitor_commands_dispatch(&mut self, work: usize) {
        self.monitor_commands_detach(work);
        if self.state != BootstrapState::Ready {
            return;
        }
        let Some(dispatch) = self
            .commands
            .as_mut()
            .and_then(|control| control.queue.next_dispatch(work))
        else {
            return;
        };
        let sent = match &mut self.monitor {
            Some(mon) => mon.try_send_commands_once(dispatch.commands, dispatch.input),
            None => Err(MonSendError::NoSession),
        };
        let queue = &mut self.commands.as_mut().unwrap().queue;
        match sent {
            Ok(tid) => {
                if queue.mark_dispatched(dispatch.token, tid).is_err() {
                    if let Some(mon) = &mut self.monitor {
                        mon.cancel_command_once(tid);
                    }
                    queue.stop(MonitorCommandError::Protocol);
                }
            }
            Err(error) => {
                let reason = match error {
                    MonSendError::NoSession => MonitorCommandError::NotReady,
                    MonSendError::IdentityExhausted => MonitorCommandError::Identity,
                    MonSendError::Rejected => MonitorCommandError::Transport,
                };
                let _ =
                    queue.handoff_failed(dispatch.token, reason, error != MonSendError::NoSession);
            }
        }
        self.monitor_commands_detach(work);
        self.drain_monitor_events();
    }
    pub(super) fn monitor_command_reply(
        &mut self,
        tid: u64,
        commands: Vec<String>,
        reply: MonitorCommandReply,
    ) -> bool {
        if !self
            .commands
            .as_ref()
            .is_some_and(|control| control.queue.owns_tid(tid))
        {
            return false;
        }
        self.monitor_commands_progress(0);
        let _ = self
            .commands
            .as_mut()
            .unwrap()
            .queue
            .on_reply(tid, commands, reply);
        true
    }
    pub(super) fn monitor_command_lost(&mut self, tid: u64) -> bool {
        let Some(control) = &mut self.commands else {
            return false;
        };
        if !control.queue.owns_tid(tid) {
            return false;
        }
        let _ = control.queue.on_lost(tid);
        true
    }
    pub(super) fn monitor_commands_lost(&mut self) {
        if let Some(control) = &mut self.commands {
            control.queue.fail_pending(MonitorCommandError::MonitorLost);
        }
        self.monitor_commands_detach(usize::MAX);
    }
    pub(super) fn monitor_commands_stop(&mut self, error: MonitorCommandError) {
        if let Some(control) = &mut self.commands {
            control.queue.stop(error);
        }
        self.monitor_commands_detach(usize::MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BootstrapConfig, MessengerMode, MonitorCommandOutcome};
    use std::time::Duration;
    fn fixture() -> Bootstrap {
        let mut b = Bootstrap::new(BootstrapConfig {
            entity: "client.command".into(),
            key: cephx::CryptoKey::new(
                cephx::key::KeyType::Aes,
                Default::default(),
                b"1234567890abcdef",
            ),
            monitors: monc::parse_mon_host("v2:127.0.0.1:3300").unwrap(),
            expected_fsid: None,
            mode: MessengerMode::Crc,
            startup_timeout: Duration::from_secs(10),
            wall_origin_unix: 100,
        })
        .unwrap();
        // Composition fixture only; no authentication claim.
        b.state = BootstrapState::Ready;
        b
    }
    fn limits() -> MonitorCommandLimits {
        MonitorCommandLimits {
            slots: 4,
            bytes: 4096,
            request_bytes: 512,
            reply_bytes: 128,
        }
    }
    fn request() -> MonitorCommandRequest {
        MonitorCommandRequest {
            commands: vec!["{}".into()],
            input: vec![],
        }
    }
    fn take(b: &mut Bootstrap) -> crate::MonitorCommandCompletion {
        let mut out = [None];
        assert_eq!(b.poll_monitor_commands_into(&mut out), 1);
        out[0].take().unwrap()
    }
    fn flight(b: &mut Bootstrap, tid: u64) -> MonitorCommandToken {
        let token = b.submit_monitor_command(request(), 100).unwrap();
        let q = &mut b.commands.as_mut().unwrap().queue;
        q.next_dispatch(4).unwrap();
        q.mark_dispatched(token, tid).unwrap();
        token
    }
    #[test]
    fn opt_in_readiness_timer_idle_and_no_session_handoff() {
        let mut b = fixture();
        assert_eq!(
            b.submit_monitor_command(request(), 100).unwrap_err().reason,
            MonitorCommandError::Disabled
        );
        b.state = BootstrapState::Hunting;
        assert_eq!(
            b.enable_monitor_commands(limits(), 4),
            Err(MonitorCommandError::NotReady)
        );
        b.state = BootstrapState::Ready;
        b.enable_monitor_commands(limits(), 4).unwrap();
        assert!(b.can_sleep());
        assert_eq!(
            b.enable_monitor_commands(limits(), 4),
            Err(MonitorCommandError::AlreadyEnabled)
        );
        b.submit_monitor_command(request(), 100).unwrap();
        assert!(!b.can_sleep());
        assert_eq!(b.next_timer(), Some(Duration::from_micros(100)));
        b.monitor_commands_dispatch(4);
        assert!(matches!(
            take(&mut b).outcome,
            MonitorCommandOutcome::Failed {
                error: MonitorCommandError::NotReady,
                possibly_sent: false
            }
        ));
        assert!(b.can_sleep());
    }
    #[test]
    fn daemon_command_routing_keeps_internal_command_replies_and_losses() {
        use monc::MonEvent;
        let mut b = fixture();
        b.enable_monitor_commands(limits(), 4).unwrap();
        b.daemon_monitor = true;
        let token = flight(&mut b, 8);
        let reply = |tid| MonEvent::CommandOnceReply {
            tid,
            version: 4,
            r: 0,
            rs: "finished".into(),
            cmd: vec!["{}".into()],
            data: vec![],
        };
        assert!(matches!(
            b.monitor_event(reply(7)),
            Some(MonEvent::CommandOnceReply { tid: 7, .. })
        ));
        assert!(b.monitor_event(reply(8)).is_none());
        assert_eq!(take(&mut b).token, token);
        let token = flight(&mut b, 9);
        assert!(
            b.monitor_event(MonEvent::CommandOnceLost { tid: 9 })
                .is_none()
        );
        assert_eq!(take(&mut b).token, token);
        assert!(matches!(
            b.monitor_event(MonEvent::CommandOnceLost { tid: 10 }),
            Some(MonEvent::CommandOnceLost { tid: 10 })
        ));
    }
    #[test]
    fn exact_family_reply_and_deadline_and_cancel_routing() {
        let mut b = fixture();
        b.enable_monitor_commands(limits(), 4).unwrap();
        let token = flight(&mut b, 8);
        assert!(b.can_sleep());
        let event = |tid| monc::MonEvent::CommandOnceReply {
            tid,
            version: 4,
            r: -13,
            rs: "denied".into(),
            cmd: vec!["{}".into()],
            data: vec![0, 255],
        };
        b.monitor_event(event(7));
        assert_eq!(b.poll_monitor_commands_into(&mut [None]), 0);
        b.monitor_event(event(8));
        let done = take(&mut b);
        assert_eq!(done.token, token);
        assert!(matches!(
            done.outcome,
            MonitorCommandOutcome::Reply(MonitorCommandReply {
                result: -13,
                version: 4,
                ..
            })
        ));
        let token = flight(&mut b, 9);
        b.cancel_monitor_command(token).unwrap();
        b.monitor_event(event(9));
        assert!(matches!(
            take(&mut b).outcome,
            MonitorCommandOutcome::Failed {
                error: MonitorCommandError::Cancelled,
                ..
            }
        ));
        flight(&mut b, 10);
        b.last_now = Duration::from_micros(100);
        b.monitor_event(event(10));
        assert!(matches!(
            take(&mut b).outcome,
            MonitorCommandOutcome::Failed {
                error: MonitorCommandError::Deadline,
                ..
            }
        ));
    }
    #[test]
    fn loss_detaches_current_requests_and_close_terminalizes_once() {
        let mut b = fixture();
        b.enable_monitor_commands(limits(), 4).unwrap();
        flight(&mut b, 1);
        b.monitor_commands_lost();
        assert!(matches!(
            take(&mut b).outcome,
            MonitorCommandOutcome::Failed {
                error: MonitorCommandError::MonitorLost,
                possibly_sent: true
            }
        ));
        let token = b.submit_monitor_command(request(), 100).unwrap();
        b.close();
        let done = take(&mut b);
        assert_eq!(done.token, token);
        assert!(matches!(
            done.outcome,
            MonitorCommandOutcome::Failed {
                error: MonitorCommandError::Closed,
                possibly_sent: false
            }
        ));
        assert_eq!(b.poll_monitor_commands_into(&mut [None]), 0);
        assert_eq!(b.monitor_command_error(), Some(MonitorCommandError::Closed));
    }
}
