// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Name and ID lookup for v2 image opens.

use crate::{
    QueryError, Versioned,
    metadata_query::{
        HEADER_PREFIX, MAX_OBJECT_NAME_BYTES, class_target, compound_reply, single_class_reply,
    },
};
use opwire::OsdOp;
use rustyrados::{Access, CompoundRequest, ReadCompletion, RequestContext, RequestToken, Target};

const ID_PREFIX: &[u8] = b"rbd_id.";
const DIRECTORY_OBJECT: &[u8] = b"rbd_directory";
const MAX_ID_BYTES: usize = MAX_OBJECT_NAME_BYTES - HEADER_PREFIX.len();
const MAX_NAME_BYTES: usize = MAX_OBJECT_NAME_BYTES - ID_PREFIX.len();
const MAX_REPLY_BYTES: u32 = (4 + MAX_ID_BYTES) as u32;
/// Maximum encoded name-to-ID class reply for the pinned OSD object-name limit.
pub const IMAGE_ID_REPLY_CAPACITY: usize = MAX_REPLY_BYTES as usize;
/// Maximum encoded directory name accepted by this metadata read boundary.
pub const IMAGE_NAME_REPLY_CAPACITY: usize = MAX_NAME_BYTES + 4;

fn image_id_target(pool: i64, namespace: Vec<u8>, image_name: &[u8]) -> Result<Target, QueryError> {
    // The name becomes the `rbd_id.` object suffix; the directory key is a
    // length-aware byte string, but a NUL can never name an image over the C
    // API and would alias the name in every NUL-terminated consumer.
    if image_name.contains(&0) {
        return Err(QueryError::InvalidImageName);
    }
    let object_len = ID_PREFIX
        .len()
        .checked_add(image_name.len())
        .ok_or(QueryError::InvalidTarget)?;
    if pool < 0 {
        return Err(QueryError::InvalidTarget);
    }
    let mut object = Vec::with_capacity(object_len);
    object.extend_from_slice(ID_PREFIX);
    object.extend_from_slice(image_name);
    Ok(Target {
        pool,
        object,
        namespace,
        locator: Vec::new(),
    })
}

/// Resolve an image ID to its current directory name.
pub fn image_name_query(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
) -> Result<CompoundRequest, QueryError> {
    if image_id.is_empty() || image_id.contains(&0) {
        return Err(QueryError::InvalidImageId);
    }
    let target = class_target(pool, namespace, b"", DIRECTORY_OBJECT)?;
    let length = u32::try_from(image_id.len()).map_err(|_| QueryError::InvalidImageId)?;
    let mut input = Vec::with_capacity(4 + image_id.len());
    input.extend_from_slice(&length.to_le_bytes());
    input.extend_from_slice(image_id);
    Ok(CompoundRequest {
        target,
        access: Access::Read,
        context: RequestContext::default(),
        operations: vec![OsdOp::call(b"rbd", b"dir_get_name", &input)],
        max_output_bytes: IMAGE_NAME_REPLY_CAPACITY as u32,
    })
}

/// Decode an exact, nonempty directory name from a class reply.
pub fn decode_image_name_query(
    overall_result: i32,
    operations: Vec<OsdOp>,
) -> Result<Vec<u8>, QueryError> {
    let operation = single_class_reply(overall_result, operations)?;
    let output = operation.outdata.as_ref();
    let length = output
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(QueryError::InvalidReply)? as usize;
    let name = &output[4..];
    if length == 0 || length > MAX_NAME_BYTES || name.len() != length || name.contains(&0) {
        return Err(QueryError::InvalidReply);
    }
    Ok(name.to_vec())
}

/// Query the image ID for a name in the metadata pool and namespace. An ID
/// reply does not establish that the header exists or that the image can open.
pub fn image_id_query(
    pool: i64,
    namespace: Vec<u8>,
    image_name: &[u8],
) -> Result<CompoundRequest, QueryError> {
    // `rbd_id.` is the pinned empty-name detection object. Other class target
    // builders reject an empty suffix, but this object name remains nonempty.
    let target = image_id_target(pool, namespace, image_name)?;
    Ok(CompoundRequest {
        target,
        access: Access::Read,
        context: RequestContext::default(),
        operations: vec![OsdOp::call(b"rbd", b"get_id", &[])],
        max_output_bytes: MAX_REPLY_BYTES,
    })
}

/// Decode only the completion for this query, preserving transport certainty.
pub fn decode_image_id_completion(
    expected: RequestToken,
    completion: ReadCompletion,
) -> Result<Versioned<Vec<u8>>, QueryError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    Ok(Versioned {
        value: decode_image_id_query(result, operations)?,
        user_version,
    })
}

/// Decode a previously verified ordinary server reply. The class output is
/// one exact length-prefixed ASCII-alphanumeric ID, usable as a header suffix.
pub fn decode_image_id_query(
    overall_result: i32,
    operations: Vec<OsdOp>,
) -> Result<Vec<u8>, QueryError> {
    let operation = single_class_reply(overall_result, operations)?;
    let output = operation.outdata.as_ref();
    let length: [u8; 4] = output
        .get(..4)
        .ok_or(QueryError::InvalidImageId)?
        .try_into()
        .map_err(|_| QueryError::InvalidImageId)?;
    let length = u32::from_le_bytes(length) as usize;
    let id = &output[4..];
    if length == 0
        || length > MAX_ID_BYTES
        || id.len() != length
        || !id.iter().all(u8::is_ascii_alphanumeric)
    {
        return Err(QueryError::InvalidImageId);
    }
    Ok(id.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opwire::op;
    use rustyrados::{ObjectQueue, ReadOutcome, ReadPublication};

    fn reply(id: &[u8]) -> Vec<OsdOp> {
        let query = image_id_query(7, b"ns".to_vec(), b"disk").unwrap();
        let mut operation = OsdOp::echo(&query.operations[0]);
        let mut bytes = (id.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(id);
        operation.outdata = bytes.into();
        vec![operation]
    }

    #[test]
    fn name_query_targets_id_object_and_preserves_read_only_access() {
        let query = image_id_query(7, b"ns".to_vec(), b"disk").unwrap();
        assert_eq!(query.target.object, b"rbd_id.disk");
        assert_eq!(query.target.namespace, b"ns");
        assert_eq!(query.access, Access::Read);
        assert_eq!(query.operations[0].cls_call().unwrap().method, b"get_id");
        assert!(query.preflight(1 << 20).is_ok());
        assert_eq!(
            image_id_query(7, vec![], b"").unwrap().target.object,
            b"rbd_id."
        );
        assert_eq!(
            image_id_query(
                7,
                vec![],
                &vec![b'x'; MAX_OBJECT_NAME_BYTES - ID_PREFIX.len()]
            )
            .unwrap()
            .target
            .object
            .len(),
            MAX_OBJECT_NAME_BYTES
        );
        assert_eq!(
            image_id_query(
                7,
                vec![],
                &vec![b'x'; MAX_OBJECT_NAME_BYTES - ID_PREFIX.len() + 1]
            )
            .unwrap()
            .target
            .object
            .len(),
            MAX_OBJECT_NAME_BYTES + 1
        );
        let long_namespace = vec![b'n'; 257];
        assert_eq!(
            image_id_query(7, long_namespace.clone(), b"disk")
                .unwrap()
                .target
                .namespace,
            long_namespace
        );
    }

    #[test]
    fn image_name_with_a_nul_is_rejected_like_the_id_path() {
        assert!(matches!(
            image_id_query(7, vec![], b"bad\0id"),
            Err(QueryError::InvalidImageName)
        ));
    }

    #[test]
    fn id_query_targets_directory_with_exact_encoded_id() {
        let query = image_name_query(7, b"ns".to_vec(), b"a09Z").unwrap();
        assert_eq!(query.target.object, b"rbd_directory");
        assert_eq!(query.target.namespace, b"ns");
        assert_eq!(query.access, Access::Read);
        let call = query.operations[0].cls_call().unwrap();
        assert_eq!(call.method, b"dir_get_name");
        assert_eq!(call.input, b"\x04\x00\x00\x00a09Z");
        for id in [b"missing-member".as_slice(), b"bad/id", b"!not-hex!"] {
            let query = image_name_query(7, vec![], id).unwrap();
            let call = query.operations[0].cls_call().unwrap();
            assert_eq!(&call.input[4..], id);
        }
        let long_id = vec![b'x'; MAX_ID_BYTES + 1];
        let query = image_name_query(7, vec![], &long_id).unwrap();
        assert_eq!(query.target.object, b"rbd_directory");
        assert_eq!(&query.operations[0].cls_call().unwrap().input[4..], long_id);
        assert!(matches!(
            image_name_query(7, vec![], b"bad\0id"),
            Err(QueryError::InvalidImageId)
        ));
    }

    #[test]
    fn directory_name_reply_requires_one_exact_string() {
        let query = image_name_query(7, vec![], b"a09Z").unwrap();
        let mut operation = OsdOp::echo(&query.operations[0]);
        operation.outdata = b"\x04\x00\x00\x00disk".to_vec().into();
        assert_eq!(
            decode_image_name_query(0, vec![operation.clone()]),
            Ok(b"disk".to_vec())
        );
        assert_eq!(
            decode_image_name_query(-2, vec![operation.clone()]),
            Err(QueryError::Remote(-2))
        );
        for invalid in [
            b"\x00\x00\x00\x00".as_slice(),
            b"\x04\x00\x00\x00dis".as_slice(),
            b"\x04\x00\x00\x00disk!".as_slice(),
            b"\x03\x00\x00\x00d\0k".as_slice(),
        ] {
            operation.outdata = invalid.to_vec().into();
            assert_eq!(
                decode_image_name_query(0, vec![operation.clone()]),
                Err(QueryError::InvalidReply)
            );
        }
    }

    #[test]
    fn image_id_must_be_exact_and_usable_as_header_suffix() {
        assert_eq!(
            decode_image_id_query(0, reply(b"a09Z")),
            Ok(b"a09Z".to_vec())
        );
        assert_eq!(
            decode_image_id_query(-2, reply(b"a09Z")),
            Err(QueryError::Remote(-2))
        );
        for id in [&b""[..], &b"a-b"[..], &b"ab\0"[..]] {
            assert_eq!(
                decode_image_id_query(0, reply(id)),
                Err(QueryError::InvalidImageId)
            );
        }
        assert_eq!(
            decode_image_id_query(0, reply(&vec![b'a'; MAX_ID_BYTES + 1])),
            Err(QueryError::InvalidImageId)
        );
        let mut trailing = reply(b"ab");
        trailing[0].outdata = b"\x02\x00\x00\x00ab!".to_vec().into();
        assert_eq!(
            decode_image_id_query(0, trailing),
            Err(QueryError::InvalidImageId)
        );
        let mut bad_op = reply(b"ab");
        bad_op[0].op = op::READ;
        assert_eq!(
            decode_image_id_query(0, bad_op),
            Err(QueryError::InvalidReply)
        );
        let mut failed = reply(b"ab");
        failed[0].rval = -5;
        assert_eq!(
            decode_image_id_query(0, failed),
            Err(QueryError::Remote(-5))
        );
    }

    #[test]
    fn image_id_completion_rejects_other_token_and_provenance() {
        let mut queue = ObjectQueue::new(2, 1 << 20, 1).unwrap();
        let expected = queue
            .submit_compound(image_id_query(7, vec![], b"disk").unwrap())
            .unwrap();
        let other = queue
            .submit_compound(image_id_query(7, vec![], b"other").unwrap())
            .unwrap();
        let completion = |token, publication| {
            ReadCompletion::new(
                token,
                ReadOutcome::RemoteCompound {
                    publication,
                    result: 0,
                    user_version: 1,
                    replay_version: Default::default(),
                    operations: reply(b"a09Z"),
                },
            )
        };
        assert_eq!(
            decode_image_id_completion(expected, completion(other, ReadPublication::Reply)),
            Err(QueryError::WrongCompletion)
        );
        assert_eq!(
            decode_image_id_completion(
                expected,
                completion(expected, ReadPublication::OutputLimit)
            ),
            Err(QueryError::InvalidPublication)
        );
        assert_eq!(
            decode_image_id_completion(expected, completion(expected, ReadPublication::Reply)),
            Ok(Versioned {
                value: b"a09Z".to_vec(),
                user_version: 1
            })
        );
    }
}
