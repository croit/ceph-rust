// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Explicit command ownership policy; strict constructors remain independent.
use crate::{ByteAdmission, MonitorCommandError, MonitorCommandRequest};

#[derive(Clone, Copy, Debug)]
pub struct CommandCompatibleProfile {
    slots: usize,
    target: u64,
}

impl CommandCompatibleProfile {
    pub fn new(slots: usize, retained_bytes: u64) -> Result<Self, MonitorCommandError> {
        if !(1..=4096).contains(&slots) || retained_bytes == 0 {
            return Err(MonitorCommandError::Limits);
        }
        let this = Self {
            slots,
            target: retained_bytes,
        };
        this.check_counter_bound(0)?;
        Ok(this)
    }
    pub fn slots(self) -> usize {
        self.slots
    }
    pub fn hard_limits(self) -> msgr2::Limits {
        msgr2::Limits::wire_shape()
    }
    pub fn admission(self) -> ByteAdmission {
        ByteAdmission::compatible(self.target)
    }
    /// Metadata plus maximal canonical wire request/reply storage, never allocated here.
    /// Retained local target names use independent checked per-admission arithmetic.
    pub fn check_counter_bound(self, entry_bytes: usize) -> Result<(), MonitorCommandError> {
        let hard = self.hard_limits();
        let per_entry = u64::from(hard.max_segment / 4)
            .checked_mul(size_of::<String>() as u64)
            .and_then(|n| n.checked_add(hard.max_frame.checked_mul(2)?))
            .and_then(|n| n.checked_add(entry_bytes as u64))
            .and_then(|n| n.checked_add(size_of::<MonitorCommandRequest>() as u64))
            .ok_or(MonitorCommandError::Limits)?;
        per_entry
            .checked_mul(self.slots as u64)
            .ok_or(MonitorCommandError::Limits)?;
        Ok(())
    }
    pub fn check_segments(
        self,
        front: usize,
        middle: usize,
        data: usize,
    ) -> Result<(), MonitorCommandError> {
        let hard = self.hard_limits();
        if [front, middle, data, msgr2::payload::HEADER2_LEN]
            .into_iter()
            .any(|n| u32::try_from(n).is_err())
            || front
                .checked_add(middle)
                .and_then(|n| n.checked_add(data))
                .and_then(|n| n.checked_add(msgr2::payload::HEADER2_LEN))
                .and_then(|n| u64::try_from(n).ok())
                .is_none_or(|n| n > hard.max_frame)
        {
            return Err(MonitorCommandError::RequestTooLarge);
        }
        Ok(())
    }
    fn vector_front(commands: &[String]) -> Result<usize, MonitorCommandError> {
        if commands.len() > u32::MAX as usize {
            return Err(MonitorCommandError::RequestTooLarge);
        }
        commands
            .iter()
            .try_fold(4usize, |n, text| {
                if text.len() > u32::MAX as usize {
                    return None;
                }
                n.checked_add(4)?.checked_add(text.len())
            })
            .ok_or(MonitorCommandError::RequestTooLarge)
    }
    /// MMonCommand has PSM18 + FSID16; daemon MCommand has FSID16.
    pub fn check_request(
        self,
        request: &MonitorCommandRequest,
        monitor: bool,
    ) -> Result<(), MonitorCommandError> {
        self.request_wire_charge(request, monitor).map(|_| ())
    }
    pub fn request_wire_charge(
        self,
        request: &MonitorCommandRequest,
        monitor: bool,
    ) -> Result<usize, MonitorCommandError> {
        let front = Self::vector_front(&request.commands)?
            .checked_add(if monitor { 34 } else { 16 })
            .ok_or(MonitorCommandError::RequestTooLarge)?;
        self.check_segments(front, 0, request.input.len())?;
        front
            .checked_add(request.input.len())
            .ok_or(MonitorCommandError::RequestTooLarge)
    }
    pub fn check_monitor_reply(
        self,
        commands: &[String],
        status: &str,
        data: usize,
    ) -> Result<(), MonitorCommandError> {
        let front = Self::vector_front(commands)?
            .checked_add(18 + 4 + 4)
            .and_then(|n| n.checked_add(status.len()))
            .ok_or(MonitorCommandError::ReplyTooLarge)?;
        self.check_segments(front, 0, data)
            .map_err(|_| MonitorCommandError::ReplyTooLarge)
    }
    /// Predict exact post-normalization charge without mutating a rejected request.
    pub fn request_charge(self, request: &MonitorCommandRequest, metadata: usize) -> Option<u64> {
        let hard = self.hard_limits();
        let max_count = hard.max_segment as usize / 4;
        let vector_capacity = if request.commands.capacity() > max_count {
            request.commands.len()
        } else {
            request.commands.capacity()
        };
        let string_capacity = request
            .commands
            .iter()
            .try_fold(0usize, |n, s| n.checked_add(s.capacity()))?;
        let string_capacity = if string_capacity > hard.max_segment as usize {
            request
                .commands
                .iter()
                .try_fold(0usize, |n, s| n.checked_add(s.len()))?
        } else {
            string_capacity
        };
        let input_capacity = if request.input.capacity() > hard.max_segment as usize {
            request.input.len()
        } else {
            request.input.capacity()
        };
        (metadata as u64)
            .checked_add((vector_capacity as u64).checked_mul(size_of::<String>() as u64)?)?
            .checked_add(string_capacity as u64)?
            .checked_add(input_capacity as u64)
    }
    /// Called only after all admission checks; exact boxes trim excessive slack.
    pub fn normalize_request(self, request: &mut MonitorCommandRequest) {
        let hard = self.hard_limits();
        if request.input.capacity() > hard.max_segment as usize {
            request.input = std::mem::take(&mut request.input)
                .into_boxed_slice()
                .into_vec();
        }
        if request
            .commands
            .iter()
            .try_fold(0u64, |n, s| n.checked_add(s.capacity() as u64))
            .is_none_or(|n| n > u64::from(hard.max_segment))
        {
            for text in &mut request.commands {
                *text = std::mem::take(text).into_boxed_str().into_string();
            }
        }
        if request.commands.capacity() > hard.max_segment as usize / 4 {
            request.commands = std::mem::take(&mut request.commands)
                .into_boxed_slice()
                .into_vec();
        }
    }
    /// A valid encoded reply may arrive above the aggregate admission target.
    pub fn normalize_reply(
        self,
        status: &mut String,
        data: &mut Vec<u8>,
    ) -> Result<u64, MonitorCommandError> {
        Self::normalize_reply_storage(status, data, self.hard_limits().max_frame)
    }
    fn normalize_reply_storage(
        status: &mut String,
        data: &mut Vec<u8>,
        hard: u64,
    ) -> Result<u64, MonitorCommandError> {
        if (status.capacity() as u64)
            .checked_add(data.capacity() as u64)
            .is_none_or(|n| n > hard)
        {
            *status = std::mem::take(status).into_boxed_str().into_string();
            *data = std::mem::take(data).into_boxed_slice().into_vec();
        }
        (status.capacity() as u64)
            .checked_add(data.capacity() as u64)
            .filter(|n| *n <= hard)
            .ok_or(MonitorCommandError::ReplyTooLarge)
    }
    pub fn normalize_reply_bytes(
        self,
        status: &mut Vec<u8>,
        data: &mut Vec<u8>,
    ) -> Result<u64, MonitorCommandError> {
        Self::normalize_reply_byte_storage(status, data, self.hard_limits().max_frame)
    }
    fn normalize_reply_byte_storage(
        status: &mut Vec<u8>,
        data: &mut Vec<u8>,
        hard: u64,
    ) -> Result<u64, MonitorCommandError> {
        if (status.capacity() as u64)
            .checked_add(data.capacity() as u64)
            .is_none_or(|n| n > hard)
        {
            *status = std::mem::take(status).into_boxed_slice().into_vec();
            *data = std::mem::take(data).into_boxed_slice().into_vec();
        }
        (status.capacity() as u64)
            .checked_add(data.capacity() as u64)
            .filter(|n| *n <= hard)
            .ok_or(MonitorCommandError::ReplyTooLarge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use messages::Message;
    #[test]
    fn wire_shape_metadata_and_soft_charge_are_independent() {
        let profile = CommandCompatibleProfile::new(2, 1).unwrap();
        assert_eq!(profile.hard_limits(), msgr2::Limits::wire_shape());
        for (front, middle, data) in [(0, 0, (256 << 20) + 1), (256 << 20, 0, 256 << 20)] {
            profile.check_segments(front, middle, data).unwrap();
            let charge = u64::try_from(front + middle + data).unwrap();
            assert_eq!(profile.admission().admit(0, 0, charge), Ok(charge));
            assert!(profile.admission().admit(charge, 1, charge).is_err());
        }
        #[cfg(target_pointer_width = "64")]
        {
            let max = u32::MAX as usize;
            profile.check_segments(max, max, max).unwrap();
            assert!(profile.check_segments(max + 1, 0, 0).is_err());
        }
        assert!(profile.check_segments(usize::MAX, 1, 1).is_err());
    }

    #[test]
    fn canonical_profile_validates_exact_own_message_shapes() {
        assert!(CommandCompatibleProfile::new(0, 1).is_err());
        assert!(CommandCompatibleProfile::new(1, 0).is_err());
        let profile = CommandCompatibleProfile::new(2, 1).unwrap();
        let commands = vec!["".into(), "binary\0text".into()];
        let body = vec![0, 255, 42];
        let mon = messages::MMonCommand {
            cmd: commands.clone(),
            data: body.clone(),
            ..Default::default()
        };
        let daemon = messages::MCommand {
            cmd: commands.clone(),
            data: body.clone(),
            ..Default::default()
        };
        let mon_wire = mon.encode(0).unwrap();
        let daemon_wire = daemon.encode(0).unwrap();
        assert_eq!(
            mon_wire.front.len(),
            CommandCompatibleProfile::vector_front(&commands).unwrap() + 34
        );
        assert_eq!(
            daemon_wire.front.len(),
            CommandCompatibleProfile::vector_front(&commands).unwrap() + 16
        );
        profile
            .check_request(
                &MonitorCommandRequest {
                    commands,
                    input: body,
                },
                true,
            )
            .unwrap();
        let hard = profile.hard_limits();
        assert!(
            profile
                .check_segments(hard.max_segment as usize, 0, 0)
                .is_ok()
        );
        assert!(
            profile
                .check_segments(hard.max_segment as usize + 1, 0, 0)
                .is_err()
        );
        #[cfg(target_pointer_width = "64")]
        assert!(
            profile
                .check_segments(hard.max_segment as usize, 0, hard.max_segment as usize)
                .is_ok()
        );
        assert!(profile.check_segments(usize::MAX, 0, 0).is_err());
        assert!(profile.check_counter_bound(usize::MAX).is_err());
        let echo = vec!["echo".to_string()];
        let reply = messages::MMonCommandAck {
            cmd: echo.clone(),
            rs: "status".into(),
            data: vec![7, 0],
            ..Default::default()
        }
        .encode(0)
        .unwrap();
        assert_eq!(
            reply.front.len(),
            CommandCompatibleProfile::vector_front(&echo).unwrap() + 26 + "status".len()
        );
        profile
            .check_monitor_reply(&echo, "status", reply.data.len())
            .unwrap();
        assert!(
            profile
                .check_monitor_reply(
                    &echo,
                    "status",
                    profile.hard_limits().max_segment as usize + 1
                )
                .is_err()
        );
    }
    #[test]
    fn excess_reply_capacity_is_trimmed_without_changing_binary_bytes() {
        let mut status = String::with_capacity(64);
        status.push_str("a\0b");
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&[0, 255, 7]);
        assert_eq!(
            CommandCompatibleProfile::normalize_reply_storage(&mut status, &mut data, 16).unwrap(),
            6
        );
        assert_eq!(status.as_bytes(), b"a\0b");
        assert_eq!(data, [0, 255, 7]);
        let (s, d) = (status.as_ptr(), data.as_ptr());
        assert_eq!(
            CommandCompatibleProfile::normalize_reply_storage(&mut status, &mut data, 16).unwrap(),
            6
        );
        assert_eq!((s, d), (status.as_ptr(), data.as_ptr()));
        let mut binary_status = Vec::with_capacity(64);
        binary_status.extend_from_slice(&[255, 0]);
        assert_eq!(
            CommandCompatibleProfile::normalize_reply_byte_storage(
                &mut binary_status,
                &mut data,
                16
            )
            .unwrap(),
            5
        );
        assert_eq!(binary_status, [255, 0]);
    }
}
