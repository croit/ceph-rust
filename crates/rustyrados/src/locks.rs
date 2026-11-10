// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Advisory object locks. Server time and authenticated identity are authoritative.
//!
//! The wire codec is the shared [`cls_lock`] crate; this module owns the
//! native typed operations, the input budget and the reply limits.
use crate::{Access, CompoundRequest, RequestContext, Target};
use bytes::Bytes;
use cls_lock::{DecodeError, Method, Request};
use denc::types::EntityName;
use opwire::{Cls, OsdOp, op};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LockKind {
    Exclusive = 1,
    Shared = 2,
    ExclusiveEphemeral = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LockRenew {
    New = 0,
    May = 1,
    Must = 2,
}

/// Owned binary fields; `build` borrows this value, including on rejection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockOperation {
    Acquire {
        name: Vec<u8>,
        kind: LockKind,
        cookie: Vec<u8>,
        tag: Vec<u8>,
        description: Vec<u8>,
        duration: Duration,
        renew: LockRenew,
    },
    Unlock {
        name: Vec<u8>,
        cookie: Vec<u8>,
    },
    Break {
        name: Vec<u8>,
        locker: EntityName,
        cookie: Vec<u8>,
    },
    GetInfo {
        name: Vec<u8>,
    },
    List,
    Assert {
        name: Vec<u8>,
        kind: LockKind,
        cookie: Vec<u8>,
        tag: Vec<u8>,
    },
    SetCookie {
        name: Vec<u8>,
        kind: LockKind,
        cookie: Vec<u8>,
        tag: Vec<u8>,
        new_cookie: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockReplyKind {
    Empty,
    Info,
    Names,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockBuildError {
    EmptyName,
    DurationOverflow,
    LengthOverflow,
    InputLimit,
}

/// Public C/C++ wire inputs, separate from strict native acquisition validation.
/// Duration words are independent, unnormalized unsigned32 values. Flags are
/// passed verbatim; the server owns their interpretation and name validation.
/// Fields default to owned vectors; adapters may borrow slices until `build`
/// validates the full envelope and encodes an independently owned request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompatibleLockOperation<B = Vec<u8>> {
    Acquire {
        name: B,
        kind: LockKind,
        cookie: B,
        tag: B,
        description: B,
        seconds: u32,
        nanoseconds: u32,
        flags: u8,
    },
    Unlock {
        name: B,
        cookie: B,
    },
    Break {
        name: B,
        locker: EntityName,
        cookie: B,
    },
    GetInfo {
        name: B,
    },
}

/// Validated native inputs or actual compatible inputs, borrowed until encoded.
#[derive(Clone, Copy)]
enum LockWireInput<'a> {
    Acquire {
        name: &'a [u8],
        kind: LockKind,
        cookie: &'a [u8],
        tag: &'a [u8],
        description: &'a [u8],
        seconds: u32,
        nanoseconds: u32,
        flags: u8,
    },
    Unlock {
        name: &'a [u8],
        cookie: &'a [u8],
    },
    Break {
        name: &'a [u8],
        locker: EntityName,
        cookie: &'a [u8],
    },
    GetInfo {
        name: &'a [u8],
    },
    List,
    Assert {
        name: &'a [u8],
        kind: LockKind,
        cookie: &'a [u8],
        tag: &'a [u8],
    },
    SetCookie {
        name: &'a [u8],
        kind: LockKind,
        cookie: &'a [u8],
        tag: &'a [u8],
        new_cookie: &'a [u8],
    },
}

impl<B: AsRef<[u8]>> CompatibleLockOperation<B> {
    /// Consumes the input representation, not borrowed backing storage.
    /// All limits and wire widths are checked before allocating encoded bytes;
    /// the returned call owns its bytes independently of the input container.
    pub fn build(self, max_input_bytes: usize) -> Result<LockCall, LockBuildError> {
        let wire = match &self {
            Self::Acquire {
                name,
                kind,
                cookie,
                tag,
                description,
                seconds,
                nanoseconds,
                flags,
            } => LockWireInput::Acquire {
                name: name.as_ref(),
                kind: *kind,
                cookie: cookie.as_ref(),
                tag: tag.as_ref(),
                description: description.as_ref(),
                seconds: *seconds,
                nanoseconds: *nanoseconds,
                flags: *flags,
            },
            Self::Unlock { name, cookie } => LockWireInput::Unlock {
                name: name.as_ref(),
                cookie: cookie.as_ref(),
            },
            Self::Break {
                name,
                locker,
                cookie,
            } => LockWireInput::Break {
                name: name.as_ref(),
                locker: *locker,
                cookie: cookie.as_ref(),
            },
            Self::GetInfo { name } => LockWireInput::GetInfo {
                name: name.as_ref(),
            },
        };
        wire.build(max_input_bytes)
    }
}

/// The full CALL input length: class name, method name and payload, checked
/// against the wire width and the caller's input budget.
fn call_len(
    method_len: usize,
    payload_len: usize,
    max_input_bytes: usize,
) -> Result<usize, LockBuildError> {
    let total = 4usize
        .checked_add(method_len)
        .and_then(|total| total.checked_add(payload_len))
        .ok_or(LockBuildError::LengthOverflow)?;
    if total > u32::MAX as usize {
        return Err(LockBuildError::LengthOverflow);
    }
    if total > max_input_bytes {
        return Err(LockBuildError::InputLimit);
    }
    Ok(total)
}

#[derive(Debug)]
pub struct LockCall {
    operation: OsdOp,
    access: Access,
    reply: LockReplyKind,
}
impl LockCall {
    pub fn required_access(&self) -> Access {
        self.access
    }
    pub fn reply_kind(&self) -> LockReplyKind {
        self.reply
    }
    pub fn into_op(self) -> OsdOp {
        self.operation
    }
    /// Default HEAD context. Use `into_op` to compose an atomic assertion/write vector.
    pub fn into_compound(self, target: Target, max_output_bytes: u32) -> CompoundRequest {
        CompoundRequest {
            target,
            access: self.access,
            context: RequestContext::default(),
            operations: vec![self.operation],
            max_output_bytes,
        }
    }
}

impl LockOperation {
    /// Cap includes class and method names. All widths and cap checked before allocation.
    pub fn build(&self, max_input_bytes: usize) -> Result<LockCall, LockBuildError> {
        let wire = match self {
            Self::Acquire {
                name,
                kind,
                cookie,
                tag,
                description,
                duration,
                renew,
            } => {
                if name.is_empty() {
                    return Err(LockBuildError::EmptyName);
                }
                if duration.as_secs() > u64::from(u32::MAX) {
                    return Err(LockBuildError::DurationOverflow);
                }
                LockWireInput::Acquire {
                    name,
                    kind: *kind,
                    cookie,
                    tag,
                    description,
                    seconds: duration.as_secs() as u32,
                    nanoseconds: duration.subsec_nanos(),
                    flags: *renew as u8,
                }
            }
            Self::Unlock { name, cookie } => LockWireInput::Unlock { name, cookie },
            Self::Break {
                name,
                locker,
                cookie,
            } => LockWireInput::Break {
                name,
                locker: *locker,
                cookie,
            },
            Self::GetInfo { name } => LockWireInput::GetInfo { name },
            Self::List => LockWireInput::List,
            Self::Assert {
                name,
                kind,
                cookie,
                tag,
            } => {
                if name.is_empty() {
                    return Err(LockBuildError::EmptyName);
                }
                LockWireInput::Assert {
                    name,
                    kind: *kind,
                    cookie,
                    tag,
                }
            }
            Self::SetCookie {
                name,
                kind,
                cookie,
                tag,
                new_cookie,
            } => {
                if name.is_empty() {
                    return Err(LockBuildError::EmptyName);
                }
                LockWireInput::SetCookie {
                    name,
                    kind: *kind,
                    cookie,
                    tag,
                    new_cookie,
                }
            }
        };
        wire.build(max_input_bytes)
    }
}

impl LockWireInput<'_> {
    fn build(self, max_input_bytes: usize) -> Result<LockCall, LockBuildError> {
        use LockWireInput::*;
        let (method, request, access, reply): (Method, Request<'_>, _, _) = match self {
            Acquire {
                name,
                kind,
                cookie,
                tag,
                description,
                seconds,
                nanoseconds,
                flags,
            } => (
                Method::Lock,
                Request::Lock {
                    name,
                    kind: kind as u8,
                    cookie,
                    tag,
                    description,
                    duration_sec: seconds,
                    duration_nsec: nanoseconds,
                    flags,
                },
                Access::ReadWrite,
                LockReplyKind::Empty,
            ),
            Unlock { name, cookie } => (
                Method::Unlock,
                Request::Unlock { name, cookie },
                Access::ReadWrite,
                LockReplyKind::Empty,
            ),
            Break {
                name,
                locker,
                cookie,
            } => (
                Method::Break,
                Request::Break {
                    name,
                    locker,
                    cookie,
                },
                Access::ReadWrite,
                LockReplyKind::Empty,
            ),
            GetInfo { name } => (
                Method::GetInfo,
                Request::GetInfo { name },
                Access::Read,
                LockReplyKind::Info,
            ),
            List => (
                Method::ListLocks,
                Request::List,
                Access::Read,
                LockReplyKind::Names,
            ),
            Assert {
                name,
                kind,
                cookie,
                tag,
            } => (
                Method::AssertLocked,
                Request::Assert {
                    name,
                    kind: kind as u8,
                    cookie,
                    tag,
                },
                Access::Read,
                LockReplyKind::Empty,
            ),
            SetCookie {
                name,
                kind,
                cookie,
                tag,
                new_cookie,
            } => (
                Method::SetCookie,
                Request::SetCookie {
                    name,
                    kind: kind as u8,
                    cookie,
                    tag,
                    new_cookie,
                },
                Access::ReadWrite,
                LockReplyKind::Empty,
            ),
        };
        let payload_len = request
            .payload_len()
            .map_err(|_| LockBuildError::LengthOverflow)?;
        let total = call_len(method.name().len(), payload_len, max_input_bytes)?;
        let payload = request
            .encode()
            .map_err(|_| LockBuildError::LengthOverflow)?;
        debug_assert_eq!(payload.len(), payload_len);
        let mut indata = Vec::with_capacity(total);
        indata.extend_from_slice(cls_lock::CLASS);
        indata.extend_from_slice(method.name());
        indata.extend_from_slice(&payload);
        let mut operation = OsdOp::new(op::CALL);
        operation.set_cls(Cls {
            class_len: cls_lock::CLASS.len() as u8,
            method_len: method.name().len() as u8,
            argc: 0,
            indata_len: payload_len as u32,
        });
        operation.indata = indata.into();
        Ok(LockCall {
            operation,
            access,
            reply,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockDecodeLimits {
    pub bytes: usize,
    pub entries: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockDecodeError {
    ByteLimit,
    EntryLimit,
    PositiveResult,
    Malformed(denc::Error),
}
#[derive(Debug)]
pub struct RejectedLockData {
    pub reason: LockDecodeError,
    pub data: Bytes,
}
#[derive(Debug)]
pub enum LockReply {
    Empty,
    Info(LockInfo),
    Names(LockNames),
    Remote {
        result: i32,
        op_result: i32,
        data: Bytes,
    },
}

/// The decoded holders, in `std::map` key order (the shared decoder's rule).
#[derive(Debug)]
pub struct LockInfo {
    lockers: Vec<cls_lock::Locker>,
    kind: u8,
    tag: Bytes,
}
impl LockInfo {
    /// Raw stored type; an empty holder map can retain its previous type and tag.
    pub fn stored_kind(&self) -> u8 {
        self.kind
    }
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }
    pub fn entries(&self) -> Lockers<'_> {
        Lockers {
            inner: self.lockers.iter(),
        }
    }
}

/// The decoded lock names, in reply order.
#[derive(Debug)]
pub struct LockNames {
    names: Vec<Bytes>,
}
impl LockNames {
    pub fn entries(&self) -> LockNameIter<'_> {
        LockNameIter {
            inner: self.names.iter(),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Locker<'a> {
    pub locker: EntityName,
    pub cookie: &'a [u8],
    pub expiration: denc::types::UTime,
    pub address: denc::types::EntityAddr,
    pub description: &'a [u8],
}
#[derive(Debug)]
pub struct Lockers<'a> {
    inner: std::slice::Iter<'a, cls_lock::Locker>,
}
impl<'a> Iterator for Lockers<'a> {
    type Item = Locker<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|locker| Locker {
            locker: locker.locker,
            cookie: &locker.cookie,
            expiration: locker.expiration,
            address: locker.address,
            description: &locker.description,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}
impl ExactSizeIterator for Lockers<'_> {}
impl std::iter::FusedIterator for Lockers<'_> {}
#[derive(Debug)]
pub struct LockNameIter<'a> {
    inner: std::slice::Iter<'a, Bytes>,
}
impl<'a> Iterator for LockNameIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|name| &name[..])
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}
impl ExactSizeIterator for LockNameIter<'_> {}
impl std::iter::FusedIterator for LockNameIter<'_> {}

impl LockReply {
    /// Supply the actual compound and indexed operation results. Errors retain input ownership.
    pub fn decode(
        kind: LockReplyKind,
        result: i32,
        op_result: i32,
        data: Bytes,
        limits: LockDecodeLimits,
    ) -> Result<Self, RejectedLockData> {
        let decoded = if data.len() > limits.bytes {
            Err(LockDecodeError::ByteLimit)
        } else if result < 0 || op_result < 0 {
            return Ok(Self::Remote {
                result,
                op_result,
                data,
            });
        } else if result != 0 || op_result != 0 {
            Err(LockDecodeError::PositiveResult)
        } else {
            Self::decode_success(kind, &data, limits.entries)
        };
        decoded.map_err(|reason| RejectedLockData { reason, data })
    }
    fn decode_success(
        kind: LockReplyKind,
        data: &Bytes,
        limit: u32,
    ) -> Result<Self, LockDecodeError> {
        match kind {
            LockReplyKind::Empty => {
                if data.is_empty() {
                    Ok(Self::Empty)
                } else {
                    Err(LockDecodeError::Malformed(denc::Error::TrailingBytes(
                        data.len(),
                    )))
                }
            }
            LockReplyKind::Info => {
                let info = cls_lock::decode_info(data, limit).map_err(decode_error)?;
                Ok(Self::Info(LockInfo {
                    lockers: info.lockers,
                    kind: info.kind,
                    tag: info.tag,
                }))
            }
            LockReplyKind::Names => {
                let names = cls_lock::decode_names(data, limit).map_err(decode_error)?;
                Ok(Self::Names(LockNames { names: names.names }))
            }
        }
    }
}

fn decode_error(error: DecodeError) -> LockDecodeError {
    match error {
        DecodeError::EntryLimit => LockDecodeError::EntryLimit,
        DecodeError::Malformed(error) => LockDecodeError::Malformed(error),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod compatible_width_tests {
    use super::*;

    #[test]
    fn each_call_checks_total_width_using_metadata_only() {
        let max = u32::MAX as usize;
        for method_len in [4, 6, 10, 8] {
            let payload = max - 4 - method_len;
            assert_eq!(call_len(method_len, payload, max), Ok(max));
            assert_eq!(
                call_len(method_len, payload + 1, usize::MAX),
                Err(LockBuildError::LengthOverflow)
            );
        }
    }

    #[test]
    fn synthetic_lengths_check_widths_before_any_payload_allocation() {
        let max = u32::MAX as usize;
        assert_eq!(call_len(4, max - 8, max), Ok(max));
        assert_eq!(
            call_len(4, max - 7, usize::MAX),
            Err(LockBuildError::LengthOverflow)
        );
        assert_eq!(call_len(4, 31, 38), Err(LockBuildError::InputLimit));
        assert_eq!(call_len(4, 31, 39), Ok(39));
        if let Some(over) = max.checked_add(1) {
            assert_eq!(
                call_len(4, over, usize::MAX),
                Err(LockBuildError::LengthOverflow)
            );
        }
    }
}
