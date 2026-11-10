// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Native owned host read destinations. The implemented delivery is verified staging; direct placement is separate.
use crate::{AdmissionError, ReadOutcome, ReadRequest};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadIntoPolicy {
    /// Permit verified staging when direct placement is unavailable; the result reports the path used.
    AllowStaging,
    /// Reject before dispatch unless direct placement can be guaranteed. Not implemented by the staged path.
    DirectOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadDeliveryPath {
    Staged,
}

/// Transfers exclusive ownership of an initialized host allocation to the client. This API never accepts GPU memory.
#[derive(Debug)]
pub struct ReadIntoRequest {
    pub read: ReadRequest,
    pub buffer: Vec<u8>,
    pub buffer_offset: usize,
    pub policy: ReadIntoPolicy,
}

#[derive(Debug)]
pub struct RejectedReadInto {
    pub reason: AdmissionError,
    pub request: ReadIntoRequest,
}

/// The exact submitted allocation, returned once with a terminal result. Bytes outside `data()` retain their initial
/// contents on the staged path. `ReadOutcome` retains the server/local status; its data is empty for read-into results.
#[derive(Debug, PartialEq, Eq)]
pub struct ReadIntoResult {
    buffer: Vec<u8>,
    offset: usize,
    initialized: usize,
    delivery: Option<ReadDeliveryPath>,
}

impl ReadIntoResult {
    pub fn data(&self) -> &[u8] {
        &self.buffer[self.offset..self.offset + self.initialized]
    }

    /// Full caller-initialized allocation, including unchanged prefix/suffix bytes.
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub fn buffer_offset(&self) -> usize {
        self.offset
    }

    pub fn initialized(&self) -> usize {
        self.initialized
    }

    /// Some on a successful read, including EOF; None if no payload was delivered.
    pub fn delivery(&self) -> Option<ReadDeliveryPath> {
        self.delivery
    }

    /// Recover the original allocation for reuse without allocating or copying.
    pub fn into_buffer(self) -> Vec<u8> {
        self.buffer
    }
}

#[derive(Debug)]
pub(crate) struct ReadIntoPending {
    pub buffer: Vec<u8>,
    pub offset: usize,
}

impl ReadIntoPending {
    /// Called only after ordinary reply identity/shape and frame integrity validation, or a local terminal outcome.
    /// Admission proved offset + requested length <= allocation length; reply validation bounds returned data by it.
    pub fn complete(self, mut outcome: ReadOutcome) -> (ReadOutcome, Option<ReadIntoResult>) {
        let mut result = ReadIntoResult {
            buffer: self.buffer,
            offset: self.offset,
            initialized: 0,
            delivery: None,
        };
        if let ReadOutcome::Remote {
            result: status,
            op_result,
            data,
            ..
        } = &mut outcome
            && *status >= 0
            && *op_result >= 0
        {
            result.buffer[self.offset..self.offset + data.len()].copy_from_slice(data);
            result.initialized = data.len();
            result.delivery = Some(ReadDeliveryPath::Staged);
            *data = bytes::Bytes::new();
        }
        (outcome, Some(result))
    }
}
