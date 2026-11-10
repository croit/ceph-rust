// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Exact class calls needed for the first image-header observation.

use crate::{
    HeaderReplies, ImageHeader, QueryError, Versioned,
    metadata_query::{compound_reply, header_target},
};
use opwire::{OsdOp, op};
use rustyrados::{Access, CompoundRequest, ReadCompletion, RequestContext, RequestToken};

const MAX_DATA_PREFIX_BYTES: usize = crate::metadata_query::MAX_OBJECT_NAME_BYTES - 17;
/// Exact upper bounds for the four pinned header getter outputs, in request order.
pub const HEADER_REPLY_CAPACITIES: [usize; 4] = [9, 16, 4 + MAX_DATA_PREFIX_BYTES, 8];
const MAX_REPLY_BYTES: u32 = (9 + 16 + 4 + MAX_DATA_PREFIX_BYTES + 8) as u32;

/// Build one read-only RADOS compound for `get_size`, `get_features`,
/// `get_object_prefix` and `get_data_pool` on a known image ID. The output allowance derives from
/// the 2048-byte OSD object-name limit, not a soft application byte target.
/// The caller retains request identity, deadline and transport ownership.
pub fn header_query(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
    read_only: bool,
) -> Result<CompoundRequest, QueryError> {
    let target = header_target(pool, namespace, image_id)?;
    let snap = opwire::NOSNAP.to_le_bytes();
    let mut feature_input = Vec::from(snap);
    if read_only {
        feature_input.push(1);
    }
    Ok(CompoundRequest {
        target,
        access: Access::Read,
        context: RequestContext::default(),
        operations: vec![
            OsdOp::call(b"rbd", b"get_size", &snap),
            OsdOp::call(b"rbd", b"get_features", &feature_input),
            OsdOp::call(b"rbd", b"get_object_prefix", &[]),
            OsdOp::call(b"rbd", b"get_data_pool", &[]),
        ],
        max_output_bytes: MAX_REPLY_BYTES,
    })
}

/// Decode a completion only when it belongs to the submitted query and came
/// from a normal server reply. No header is published from transport or local
/// failures, even if a scalar server status is available.
pub fn decode_header_completion(
    expected: RequestToken,
    completion: ReadCompletion,
) -> Result<Versioned<ImageHeader>, QueryError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    Ok(Versioned {
        value: decode_header_query(result, operations)?,
        user_version,
    })
}

/// Decode a verified `RemoteCompound` result. A failed class call
/// preserves the server's signed errno; successful outputs must match the
/// expected four-operation shape before any header is published.
pub fn decode_header_query(
    overall_result: i32,
    operations: Vec<OsdOp>,
) -> Result<ImageHeader, QueryError> {
    if overall_result < 0 {
        return Err(QueryError::Remote(overall_result));
    }
    if overall_result != 0 || operations.len() != 4 {
        return Err(QueryError::InvalidReply);
    }
    let mut outputs = Vec::with_capacity(4);
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
        outputs.push(operation.outdata.to_vec());
    }
    let mut outputs = outputs.into_iter();
    let replies = HeaderReplies {
        size: outputs.next().ok_or(QueryError::InvalidReply)?,
        features: outputs.next().ok_or(QueryError::InvalidReply)?,
        object_prefix: outputs.next().ok_or(QueryError::InvalidReply)?,
        data_pool: outputs.next().ok_or(QueryError::InvalidReply)?,
    };
    ImageHeader::decode(replies).map_err(QueryError::Header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyrados::{LocalRequestError, ReadOutcome, ReadPublication};

    fn reply() -> Vec<OsdOp> {
        let request = header_query(7, b"ns".to_vec(), b"image1", false).unwrap();
        let mut operations: Vec<_> = request.operations.iter().map(OsdOp::echo).collect();
        let mut size = vec![22];
        size.extend_from_slice(&123_456u64.to_le_bytes());
        operations[0].outdata = size.into();
        let mut features = Vec::new();
        features.extend_from_slice(&0x3du64.to_le_bytes());
        features.extend_from_slice(&0x3du64.to_le_bytes());
        operations[1].outdata = features.into();
        let mut prefix = 9u32.to_le_bytes().to_vec();
        prefix.extend_from_slice(b"rbd_data.");
        operations[2].outdata = prefix.into();
        operations[3].outdata = (-1i64).to_le_bytes().to_vec().into();
        operations
    }

    #[test]
    fn header_request_is_read_only_and_exact() {
        let query = header_query(7, b"ns".to_vec(), b"image1", true).unwrap();
        assert_eq!(query.target.object, b"rbd_header.image1");
        assert_eq!(query.target.namespace, b"ns");
        assert_eq!(query.access, Access::Read);
        assert_eq!(query.context.snapid, opwire::NOSNAP);
        assert_eq!(query.operations.len(), 4);
        assert_eq!(query.operations[0].cls_call().unwrap().method, b"get_size");
        assert_eq!(
            query.operations[1].cls_call().unwrap().method,
            b"get_features"
        );
        assert_eq!(
            query.operations[2].cls_call().unwrap().method,
            b"get_object_prefix"
        );
        assert_eq!(
            query.operations[3].cls_call().unwrap().method,
            b"get_data_pool"
        );
        assert!(query.operations[1].indata.ends_with(&[1]));
        assert!(query.preflight(1 << 20).is_ok());
    }

    #[test]
    fn query_decodes_exact_reply_and_rejects_failed_or_changed_operations() {
        let header = decode_header_query(0, reply()).unwrap();
        assert_eq!(header.size, 123_456);
        assert_eq!(header.object_prefix, b"rbd_data.");
        assert_eq!(header.data_pool_id, -1);
        assert_eq!(
            decode_header_query(-2, reply()),
            Err(QueryError::Remote(-2))
        );
        let mut failed = reply();
        failed[1].rval = -5;
        assert_eq!(decode_header_query(0, failed), Err(QueryError::Remote(-5)));
        let mut changed = reply();
        changed[2].op = op::READ;
        assert_eq!(
            decode_header_query(0, changed),
            Err(QueryError::InvalidReply)
        );
        assert_eq!(
            decode_header_query(0, reply()[..2].to_vec()),
            Err(QueryError::InvalidReply)
        );
    }

    #[test]
    fn invalid_target_never_builds_an_outbound_request() {
        assert!(matches!(
            header_query(-1, vec![], b"id", false),
            Err(QueryError::InvalidTarget)
        ));
        assert!(matches!(
            header_query(1, vec![], b"", false),
            Err(QueryError::InvalidTarget)
        ));
        let long_namespace = vec![b'x'; 257];
        assert_eq!(
            header_query(1, long_namespace.clone(), b"id", false)
                .unwrap()
                .target
                .namespace,
            long_namespace
        );
        assert_eq!(
            header_query(
                1,
                vec![],
                &vec![b'x'; crate::metadata_query::MAX_OBJECT_NAME_BYTES],
                false
            )
            .unwrap()
            .target
            .object
            .len(),
            crate::metadata_query::MAX_OBJECT_NAME_BYTES + b"rbd_header.".len()
        );
        for id in [b"missing-member".as_slice(), b"bad/id", b"!not-hex!"] {
            let query = header_query(1, vec![], id, false).unwrap();
            assert_eq!(
                query.target.object,
                [b"rbd_header.".as_slice(), id].concat()
            );
        }
        assert!(matches!(
            header_query(1, vec![], b"image\0id", false),
            Err(QueryError::InvalidImageId)
        ));
    }

    #[test]
    fn completion_requires_matching_token_and_server_reply() {
        let mut queue = rustyrados::ObjectQueue::new(2, 1 << 20, 1).unwrap();
        let expected = queue
            .submit_compound(header_query(7, vec![], b"image1", false).unwrap())
            .unwrap();
        let other = queue
            .submit_compound(header_query(7, vec![], b"image2", false).unwrap())
            .unwrap();
        let server = |token, publication| {
            ReadCompletion::new(
                token,
                ReadOutcome::RemoteCompound {
                    publication,
                    result: 0,
                    user_version: 1,
                    replay_version: Default::default(),
                    operations: reply(),
                },
            )
        };
        assert_eq!(
            decode_header_completion(expected, server(other, ReadPublication::Reply)),
            Err(QueryError::WrongCompletion)
        );
        assert_eq!(
            decode_header_completion(expected, server(expected, ReadPublication::OutputLimit)),
            Err(QueryError::InvalidPublication)
        );
        assert_eq!(
            decode_header_completion(
                expected,
                ReadCompletion::new(
                    expected,
                    ReadOutcome::Deadline {
                        possibly_sent: true,
                    },
                ),
            ),
            Err(QueryError::Deadline {
                possibly_sent: true,
            })
        );
        assert_eq!(
            decode_header_completion(
                expected,
                ReadCompletion::new(
                    expected,
                    ReadOutcome::LocalRejected {
                        error: LocalRequestError::OutputLimit,
                        possibly_sent: true,
                    },
                ),
            ),
            Err(QueryError::Local {
                error: LocalRequestError::OutputLimit,
                possibly_sent: true,
            })
        );
        let observed =
            decode_header_completion(expected, server(expected, ReadPublication::Reply)).unwrap();
        assert_eq!(observed.user_version, 1);
        assert_eq!(observed.value.size, 123_456);
    }
}
