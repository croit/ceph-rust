// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Target and completion checks shared by RBD metadata class queries.

use crate::{HeaderDecodeError, LayoutError};
use opwire::{OsdOp, op};
use rustyrados::{
    LocalRequestError, ReadCompletion, ReadOutcome, ReadPublication, RequestToken, Target,
};

pub(crate) const MAX_OBJECT_NAME_BYTES: usize = 2048;
pub(crate) const HEADER_PREFIX: &[u8] = b"rbd_header.";
pub(crate) const MAX_NAMESPACE_BYTES: usize = 256;

pub(crate) fn class_target(
    pool: i64,
    namespace: Vec<u8>,
    prefix: &[u8],
    name: &[u8],
) -> Result<Target, QueryError> {
    if pool < 0 || name.is_empty() {
        return Err(QueryError::InvalidTarget);
    }
    let object_len = prefix
        .len()
        .checked_add(name.len())
        .ok_or(QueryError::InvalidTarget)?;
    let mut object = Vec::with_capacity(object_len);
    object.extend_from_slice(prefix);
    object.extend_from_slice(name);
    Ok(Target {
        pool,
        object,
        namespace,
        locator: Vec::new(),
    })
}

pub(crate) fn header_target(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
) -> Result<Target, QueryError> {
    if image_id.contains(&0) {
        return Err(QueryError::InvalidImageId);
    }
    class_target(pool, namespace, HEADER_PREFIX, image_id)
}

/// A metadata query cannot publish a value from an invalid target or reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryError {
    /// The pool, namespace, object name or lock holder is invalid for the
    /// pinned OSD.
    InvalidTarget,
    /// The caller's reply allowance cannot hold even the smallest valid result.
    InvalidOutputLimit,
    /// The server reported this signed errno.
    Remote(i32),
    /// The reply shape or operation identity is inconsistent with the query.
    InvalidReply,
    /// The completion belongs to another request or queue.
    WrongCompletion,
    /// The output did not come from a normal server reply.
    InvalidPublication,
    /// The request was rejected locally before a usable server reply.
    Local {
        /// The local limit or routing failure.
        error: LocalRequestError,
        /// Whether the transport may already have sent the request.
        possibly_sent: bool,
    },
    /// The request was canceled before it was sent.
    CanceledUnsent,
    /// The transport cannot establish whether the server saw the request.
    PossiblySent,
    /// The deadline expired; `possibly_sent` preserves transport uncertainty.
    Deadline { possibly_sent: bool },
    /// A structurally valid reply exceeded the output allowance.
    ReplyTooLarge,
    /// One of the image-header class outputs is malformed.
    Header(HeaderDecodeError),
    /// The captured image header cannot form an unstriped object layout.
    Layout(LayoutError),
    /// An image ID is missing, malformed or unusable in a request key.
    InvalidImageId,
    /// An image name holds a NUL byte and cannot name an image.
    InvalidImageName,
    /// The stripe unit, count or object order cannot describe a usable layout.
    InvalidStripeGeometry,
    /// A parent specification or overlap is malformed or inconsistent.
    InvalidParent,
    /// Snapshot selector or SnapshotInfo reply is unusable.
    InvalidSnapshot,
    /// A raw head write is empty, outside the captured image, or has no head context.
    InvalidWriteRange,
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTarget => f.write_str("invalid RBD metadata target"),
            Self::InvalidOutputLimit => f.write_str("RBD metadata output limit is too small"),
            Self::Remote(errno) => write!(f, "RBD class call failed: {errno}"),
            Self::InvalidReply => f.write_str("invalid RBD class reply"),
            Self::WrongCompletion => f.write_str("RBD completion token mismatch"),
            Self::InvalidPublication => f.write_str("RBD reply has invalid provenance"),
            Self::Local {
                error,
                possibly_sent,
            } => write!(
                f,
                "RBD request rejected locally: {error:?} (possibly sent: {possibly_sent})"
            ),
            Self::CanceledUnsent => f.write_str("RBD request canceled before send"),
            Self::PossiblySent => f.write_str("RBD request transport state uncertain"),
            Self::Deadline { possibly_sent } => {
                write!(
                    f,
                    "RBD request deadline expired (possibly sent: {possibly_sent})"
                )
            }
            Self::ReplyTooLarge => f.write_str("RBD reply exceeded output allowance"),
            Self::Header(error) => std::fmt::Display::fmt(error, f),
            Self::Layout(error) => std::fmt::Display::fmt(error, f),
            Self::InvalidImageId => f.write_str("invalid RBD image ID"),
            Self::InvalidImageName => f.write_str("invalid RBD image name"),
            Self::InvalidStripeGeometry => f.write_str("invalid RBD stripe geometry"),
            Self::InvalidParent => f.write_str("invalid RBD parent metadata"),
            Self::InvalidSnapshot => f.write_str("invalid RBD snapshot metadata"),
            Self::InvalidWriteRange => f.write_str("invalid RBD raw head write range"),
        }
    }
}

impl std::error::Error for QueryError {}

/// Match request identity and reply provenance before a class or data decoder
/// sees outputs. Retain local transport uncertainty instead of collapsing it
/// into a server errno.
pub(crate) fn compound_reply(
    expected: RequestToken,
    completion: ReadCompletion,
) -> Result<(i32, u64, Vec<OsdOp>), QueryError> {
    if completion.token != expected {
        return Err(QueryError::WrongCompletion);
    }
    match completion.outcome {
        ReadOutcome::RemoteCompound {
            publication: ReadPublication::Reply,
            result,
            user_version,
            operations,
            ..
        } => Ok((result, user_version, operations)),
        ReadOutcome::RemoteCompound { .. } => Err(QueryError::InvalidPublication),
        ReadOutcome::LocalRejected {
            error,
            possibly_sent,
        } => Err(QueryError::Local {
            error,
            possibly_sent,
        }),
        ReadOutcome::CanceledUnsent => Err(QueryError::CanceledUnsent),
        ReadOutcome::PossiblySent => Err(QueryError::PossiblySent),
        ReadOutcome::Deadline { possibly_sent } => Err(QueryError::Deadline { possibly_sent }),
        ReadOutcome::ReplyTooLarge { .. } => Err(QueryError::ReplyTooLarge),
        _ => Err(QueryError::InvalidReply),
    }
}

/// Validate the one-operation form used by independent metadata getters.
/// A server errno takes precedence over absent per-operation output.
pub(crate) fn single_class_reply(
    overall_result: i32,
    operations: Vec<OsdOp>,
) -> Result<OsdOp, QueryError> {
    if overall_result < 0 {
        return Err(QueryError::Remote(overall_result));
    }
    if overall_result != 0 || operations.len() != 1 {
        return Err(QueryError::InvalidReply);
    }
    let mut operation = operations
        .into_iter()
        .next()
        .ok_or(QueryError::InvalidReply)?;
    if operation.op != op::CALL {
        return Err(QueryError::InvalidReply);
    }
    if operation.rval < 0 {
        return Err(QueryError::Remote(operation.rval));
    }
    if operation.rval != 0 {
        return Err(QueryError::InvalidReply);
    }
    operation.flatten_outdata();
    Ok(operation)
}
