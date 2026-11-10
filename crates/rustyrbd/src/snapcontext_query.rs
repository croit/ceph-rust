// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Exact snapshot-context observation before image writes.

use crate::{
    QueryError, Versioned,
    metadata_query::{compound_reply, header_target, single_class_reply},
};
use opwire::OsdOp;
use rustyrados::{Access, CompoundRequest, ReadCompletion, RequestContext, RequestToken};

/// Minimum encoded `get_snapcontext` reply: the sequence and an empty ID vector.
pub(crate) const MIN_SNAPCONTEXT_REPLY_BYTES: u32 = 12;

/// One atomically observed image write-snapshot context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageSnapContext {
    /// Highest allocated snapshot ID in the image header.
    pub sequence: u64,
    /// Snapshot IDs in strictly descending order, including trashed snapshots.
    pub ids: Vec<u64>,
}

/// Build the read-only class query. `max_output_bytes` is the caller's session
/// allowance; an empty vector still requires 12 reply bytes. A limit failure
/// never publishes a partial context.
pub fn snapcontext_query(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
    max_output_bytes: u32,
) -> Result<CompoundRequest, QueryError> {
    if max_output_bytes < MIN_SNAPCONTEXT_REPLY_BYTES {
        return Err(QueryError::InvalidOutputLimit);
    }
    let target = header_target(pool, namespace, image_id)?;
    Ok(CompoundRequest {
        target,
        access: Access::Read,
        context: RequestContext::default(),
        operations: vec![OsdOp::call(b"rbd", b"get_snapcontext", &[])],
        max_output_bytes,
    })
}

/// Decode only the matching ordinary server reply.
pub fn decode_snapcontext_completion(
    expected: RequestToken,
    completion: ReadCompletion,
) -> Result<Versioned<ImageSnapContext>, QueryError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    Ok(Versioned {
        value: decode_snapcontext_query(result, operations)?,
        user_version,
    })
}

/// Decode the exact sequence and descending ID vector from a verified reply.
pub fn decode_snapcontext_query(
    overall_result: i32,
    operations: Vec<OsdOp>,
) -> Result<ImageSnapContext, QueryError> {
    let operation = single_class_reply(overall_result, operations)?;
    let output = operation.outdata.as_ref();
    let head: [u8; 12] = output
        .get(..12)
        .ok_or(QueryError::InvalidReply)?
        .try_into()
        .map_err(|_| QueryError::InvalidReply)?;
    let sequence = u64::from_le_bytes(head[..8].try_into().expect("fixed-size slice"));
    let count = u32::from_le_bytes(head[8..].try_into().expect("fixed-size slice")) as usize;
    let expected_bytes = count
        .checked_mul(8)
        .and_then(|bytes| bytes.checked_add(12))
        .ok_or(QueryError::InvalidReply)?;
    if output.len() != expected_bytes || sequence >= opwire::NOSNAP {
        return Err(QueryError::InvalidReply);
    }
    let mut ids = Vec::with_capacity(count);
    for bytes in output[12..].as_chunks::<8>().0 {
        let id = u64::from_le_bytes(*bytes);
        if id > sequence || ids.last().is_some_and(|previous| *previous <= id) {
            return Err(QueryError::InvalidReply);
        }
        ids.push(id);
    }
    Ok(ImageSnapContext { sequence, ids })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyrados::{ObjectQueue, ReadOutcome, ReadPublication};

    fn reply(sequence: u64, ids: &[u64]) -> Vec<OsdOp> {
        let query = snapcontext_query(7, vec![], b"image1", 4096).unwrap();
        let mut operation = OsdOp::echo(&query.operations[0]);
        let mut output = sequence.to_le_bytes().to_vec();
        output.extend_from_slice(&(ids.len() as u32).to_le_bytes());
        for id in ids {
            output.extend_from_slice(&id.to_le_bytes());
        }
        operation.outdata = output.into();
        vec![operation]
    }

    #[test]
    fn snapcontext_query_is_bounded_and_read_only() {
        let query = snapcontext_query(7, b"ns".to_vec(), b"image1", 4096).unwrap();
        assert_eq!(query.target.object, b"rbd_header.image1");
        assert_eq!(query.access, Access::Read);
        assert_eq!(query.max_output_bytes, 4096);
        assert_eq!(
            query.operations[0].cls_call().unwrap().method,
            b"get_snapcontext"
        );
        assert!(query.preflight(1 << 20).is_ok());
        assert!(matches!(
            snapcontext_query(7, vec![], b"image1", 11),
            Err(QueryError::InvalidOutputLimit)
        ));
    }

    #[test]
    fn snapcontext_reply_is_exact_and_descending() {
        assert_eq!(
            decode_snapcontext_query(0, reply(9, &[9, 5, 2])),
            Ok(ImageSnapContext {
                sequence: 9,
                ids: vec![9, 5, 2]
            })
        );
        assert_eq!(
            decode_snapcontext_query(0, reply(0, &[])),
            Ok(ImageSnapContext {
                sequence: 0,
                ids: vec![]
            })
        );
        for (sequence, ids) in [(9, vec![10]), (9, vec![5, 5]), (9, vec![2, 5])] {
            assert_eq!(
                decode_snapcontext_query(0, reply(sequence, &ids)),
                Err(QueryError::InvalidReply)
            );
        }
        assert_eq!(
            decode_snapcontext_query(0, reply(opwire::NOSNAP, &[])),
            Err(QueryError::InvalidReply)
        );
        let mut truncated = reply(9, &[9, 5]);
        truncated[0].outdata = truncated[0].outdata.slice(..20);
        assert_eq!(
            decode_snapcontext_query(0, truncated),
            Err(QueryError::InvalidReply)
        );
        let mut forged_count = reply(9, &[]);
        forged_count[0].outdata = [
            9u64.to_le_bytes().as_slice(),
            u32::MAX.to_le_bytes().as_slice(),
        ]
        .concat()
        .into();
        assert_eq!(
            decode_snapcontext_query(0, forged_count),
            Err(QueryError::InvalidReply)
        );
        assert_eq!(
            decode_snapcontext_query(-2, reply(9, &[])),
            Err(QueryError::Remote(-2))
        );
    }

    #[test]
    fn snapcontext_completion_requires_matching_token_and_provenance() {
        let mut queue = ObjectQueue::new(2, 1 << 20, 1).unwrap();
        let expected = queue
            .submit_compound(snapcontext_query(7, vec![], b"image1", 4096).unwrap())
            .unwrap();
        let other = queue
            .submit_compound(snapcontext_query(7, vec![], b"image2", 4096).unwrap())
            .unwrap();
        let completion = |token, publication| {
            ReadCompletion::new(
                token,
                ReadOutcome::RemoteCompound {
                    publication,
                    result: 0,
                    user_version: 1,
                    replay_version: Default::default(),
                    operations: reply(9, &[9, 5]),
                },
            )
        };
        assert_eq!(
            decode_snapcontext_completion(expected, completion(other, ReadPublication::Reply)),
            Err(QueryError::WrongCompletion)
        );
        assert_eq!(
            decode_snapcontext_completion(
                expected,
                completion(expected, ReadPublication::OutputLimit)
            ),
            Err(QueryError::InvalidPublication)
        );
        assert_eq!(
            decode_snapcontext_completion(expected, completion(expected, ReadPublication::Reply)),
            Ok(Versioned {
                value: ImageSnapContext {
                    sequence: 9,
                    ids: vec![9, 5]
                },
                user_version: 1,
            })
        );
    }
}
