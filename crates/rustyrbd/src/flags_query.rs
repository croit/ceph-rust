// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Flags observation for image head or one snapshot.

use crate::{
    QueryError, Versioned,
    metadata_query::{compound_reply, header_target, single_class_reply},
};
use opwire::OsdOp;
use rustyrados::{Access, CompoundRequest, ReadCompletion, RequestContext, RequestToken};

/// Class query for head (`NOSNAP`) or a specific snapshot. A returned zero
/// does not prove that the header object exists.
pub fn flags_query(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
    snapshot_id: u64,
) -> Result<CompoundRequest, QueryError> {
    let target = header_target(pool, namespace, image_id)?;
    Ok(CompoundRequest {
        target,
        access: Access::Read,
        context: RequestContext::default(),
        operations: vec![OsdOp::call(
            b"rbd",
            b"get_flags",
            &snapshot_id.to_le_bytes(),
        )],
        max_output_bytes: 8,
    })
}

/// Query operation features when the header has FEATURE_OPERATIONS. A zero
/// result can also come from an absent key and does not prove header existence.
pub fn op_features_query(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
) -> Result<CompoundRequest, QueryError> {
    let target = header_target(pool, namespace, image_id)?;
    Ok(CompoundRequest {
        target,
        access: Access::Read,
        context: RequestContext::default(),
        operations: vec![OsdOp::call(b"rbd", b"op_features_get", &[])],
        max_output_bytes: 8,
    })
}

/// Decode the exact u64 result of a verified operation-features query.
pub fn decode_op_features_completion(
    expected: RequestToken,
    completion: ReadCompletion,
) -> Result<Versioned<u64>, QueryError> {
    decode_flags_completion(expected, completion)
}

/// Decode only the completion for the submitted flags query.
pub fn decode_flags_completion(
    expected: RequestToken,
    completion: ReadCompletion,
) -> Result<Versioned<u64>, QueryError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    Ok(Versioned {
        value: decode_flags_query(result, operations)?,
        user_version,
    })
}

/// Decode one verified ordinary server reply as an exact u64 flag word.
pub fn decode_flags_query(overall_result: i32, operations: Vec<OsdOp>) -> Result<u64, QueryError> {
    let operation = single_class_reply(overall_result, operations)?;
    let flags: [u8; 8] = operation
        .outdata
        .as_ref()
        .try_into()
        .map_err(|_| QueryError::InvalidReply)?;
    Ok(u64::from_le_bytes(flags))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyrados::{ObjectQueue, ReadOutcome, ReadPublication};

    fn reply(flags: u64) -> Vec<OsdOp> {
        let query = flags_query(7, vec![], b"image1", opwire::NOSNAP).unwrap();
        let mut operation = OsdOp::echo(&query.operations[0]);
        operation.outdata = flags.to_le_bytes().to_vec().into();
        vec![operation]
    }

    #[test]
    fn flags_query_preserves_head_or_snapshot_selector() {
        for snapid in [opwire::NOSNAP, 17] {
            let query = flags_query(7, b"ns".to_vec(), b"image1", snapid).unwrap();
            assert_eq!(query.target.object, b"rbd_header.image1");
            assert_eq!(query.access, Access::Read);
            assert_eq!(query.operations[0].cls_call().unwrap().method, b"get_flags");
            assert_eq!(
                query.operations[0].cls_call().unwrap().input,
                &snapid.to_le_bytes()
            );
            assert!(query.preflight(1 << 20).is_ok());
        }
    }

    #[test]
    fn operation_features_query_is_conditional_header_getter() {
        let query = op_features_query(7, b"ns".to_vec(), b"image1").unwrap();
        assert_eq!(query.target.object, b"rbd_header.image1");
        assert_eq!(query.target.namespace, b"ns");
        assert_eq!(query.access, Access::Read);
        assert_eq!(query.operations.len(), 1);
        assert_eq!(
            query.operations[0].cls_call().unwrap().method,
            b"op_features_get"
        );
        assert!(query.operations[0].cls_call().unwrap().input.is_empty());
        assert_eq!(query.max_output_bytes, 8);
        assert!(query.preflight(1 << 20).is_ok());
    }

    #[test]
    fn flags_reply_retains_remote_error_and_rejects_wrong_shape() {
        assert_eq!(decode_flags_query(0, reply(3)), Ok(3));
        assert_eq!(
            decode_flags_query(-2, reply(0)),
            Err(QueryError::Remote(-2))
        );
        let mut truncated = reply(3);
        truncated[0].outdata = vec![0; 7].into();
        assert_eq!(
            decode_flags_query(0, truncated),
            Err(QueryError::InvalidReply)
        );
    }

    #[test]
    fn flags_completion_requires_matching_token_and_provenance() {
        let mut queue = ObjectQueue::new(2, 1 << 20, 1).unwrap();
        let expected = queue
            .submit_compound(flags_query(7, vec![], b"image1", opwire::NOSNAP).unwrap())
            .unwrap();
        let other = queue
            .submit_compound(flags_query(7, vec![], b"image2", opwire::NOSNAP).unwrap())
            .unwrap();
        let completion = |token, publication| {
            ReadCompletion::new(
                token,
                ReadOutcome::RemoteCompound {
                    publication,
                    result: 0,
                    user_version: 1,
                    replay_version: Default::default(),
                    operations: reply(3),
                },
            )
        };
        assert_eq!(
            decode_flags_completion(expected, completion(other, ReadPublication::Reply)),
            Err(QueryError::WrongCompletion)
        );
        assert_eq!(
            decode_flags_completion(expected, completion(expected, ReadPublication::OutputLimit)),
            Err(QueryError::InvalidPublication)
        );
        assert_eq!(
            decode_flags_completion(expected, completion(expected, ReadPublication::Reply)),
            Ok(Versioned {
                value: 3,
                user_version: 1
            })
        );
    }
}
