// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Bounded image-header timestamp observation.

use crate::{
    QueryError, Versioned,
    metadata_query::{compound_reply, header_target},
};
use opwire::{OsdOp, op};
use rustyrados::{Access, CompoundRequest, ReadCompletion, RequestContext, RequestToken};

/// Ceph's raw `utime_t` header value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageTimestamp {
    /// Whole seconds since the Unix epoch.
    pub seconds: u32,
    /// Fractional nanoseconds below one second.
    pub nanoseconds: u32,
}

/// Three timestamps captured from one header class batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageTimestamps {
    /// Image creation time.
    pub create: ImageTimestamp,
    /// Image access time.
    pub access: ImageTimestamp,
    /// Image modification time.
    pub modify: ImageTimestamp,
}

/// Exact output capacities for the three timestamp class calls.
pub const IMAGE_TIMESTAMP_REPLY_CAPACITIES: [usize; 3] = [8; 3];

/// Read all three header timestamps in one ordinary class batch.
pub fn image_timestamps_query(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
) -> Result<CompoundRequest, QueryError> {
    Ok(CompoundRequest {
        target: header_target(pool, namespace, image_id)?,
        access: Access::Read,
        context: RequestContext::default(),
        operations: [
            b"get_create_timestamp".as_slice(),
            b"get_access_timestamp",
            b"get_modify_timestamp",
        ]
        .into_iter()
        .map(|method| OsdOp::call(b"rbd", method, &[]))
        .collect(),
        max_output_bytes: 24,
    })
}

/// Decode only a normal server reply for the expected request token.
pub fn decode_image_timestamps_completion(
    expected: RequestToken,
    completion: ReadCompletion,
) -> Result<Versioned<ImageTimestamps>, QueryError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    Ok(Versioned {
        value: decode_image_timestamps_query(result, operations)?,
        user_version,
    })
}

/// Decode exactly three raw little-endian `utime_t` outputs.
pub fn decode_image_timestamps_query(
    overall_result: i32,
    operations: Vec<OsdOp>,
) -> Result<ImageTimestamps, QueryError> {
    if overall_result < 0 {
        return Err(QueryError::Remote(overall_result));
    }
    if overall_result != 0 || operations.len() != 3 {
        return Err(QueryError::InvalidReply);
    }
    let mut values = Vec::with_capacity(3);
    for mut operation in operations {
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
        let bytes: [u8; 8] = operation
            .outdata
            .as_ref()
            .try_into()
            .map_err(|_| QueryError::InvalidReply)?;
        let seconds = u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| QueryError::InvalidReply)?,
        );
        let nanoseconds = u32::from_le_bytes(
            bytes[4..]
                .try_into()
                .map_err(|_| QueryError::InvalidReply)?,
        );
        if nanoseconds >= 1_000_000_000 {
            return Err(QueryError::InvalidReply);
        }
        values.push(ImageTimestamp {
            seconds,
            nanoseconds,
        });
    }
    Ok(ImageTimestamps {
        create: values[0],
        access: values[1],
        modify: values[2],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply() -> Vec<OsdOp> {
        let query = image_timestamps_query(7, b"ns".to_vec(), b"image1").unwrap();
        let mut operations: Vec<_> = query.operations.iter().map(OsdOp::echo).collect();
        for (operation, second) in operations.iter_mut().zip([11u32, 12, 13]) {
            let mut bytes = second.to_le_bytes().to_vec();
            bytes.extend_from_slice(&345u32.to_le_bytes());
            operation.outdata = bytes.into();
        }
        operations
    }

    #[test]
    fn query_reads_exact_three_header_keys() {
        let query = image_timestamps_query(7, b"ns".to_vec(), b"image1").unwrap();
        assert_eq!(query.target.object, b"rbd_header.image1");
        assert_eq!(query.access, Access::Read);
        let methods: Vec<_> = query
            .operations
            .iter()
            .map(|op| op.cls_call().unwrap().method.to_vec())
            .collect();
        assert_eq!(
            methods,
            [
                b"get_create_timestamp".as_slice(),
                b"get_access_timestamp",
                b"get_modify_timestamp"
            ]
        );
        assert!(
            query
                .operations
                .iter()
                .all(|op| op.cls_call().unwrap().input.is_empty())
        );
        assert!(query.preflight(1 << 20).is_ok());
    }

    #[test]
    fn decode_requires_exact_raw_utimes() {
        let times = decode_image_timestamps_query(0, reply()).unwrap();
        assert_eq!(
            times.create,
            ImageTimestamp {
                seconds: 11,
                nanoseconds: 345
            }
        );
        assert_eq!(times.access.seconds, 12);
        assert_eq!(times.modify.seconds, 13);
        let mut invalid = reply();
        invalid[1].outdata = 1_000_000_000u32.to_le_bytes().repeat(2).into();
        assert_eq!(
            decode_image_timestamps_query(0, invalid),
            Err(QueryError::InvalidReply)
        );
        let mut failed = reply();
        failed[2].rval = -5;
        assert_eq!(
            decode_image_timestamps_query(0, failed),
            Err(QueryError::Remote(-5))
        );
        assert_eq!(
            decode_image_timestamps_query(-2, reply()),
            Err(QueryError::Remote(-2))
        );
    }
}
