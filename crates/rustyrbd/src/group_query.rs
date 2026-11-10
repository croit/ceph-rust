// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Image group reference observed during image open.

use crate::{
    QueryError, Versioned,
    metadata_query::{compound_reply, header_target, single_class_reply},
};
use denc::Decoder;
use opwire::OsdOp;
use rustyrados::{Access, CompoundRequest, ReadCompletion, RequestContext, RequestToken};

/// Minimum encoded `image_group_get` reply: the pool ID and an empty group ID.
pub(crate) const MIN_GROUP_REPLY_BYTES: u32 = 18;

/// The group associated with an image, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageGroupSpec {
    pub pool: i64,
    pub group_id: Vec<u8>,
}

/// Query the group reference on the image header. A default result alone does
/// not prove that the header exists.
pub fn image_group_query(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
    max_output_bytes: u32,
) -> Result<CompoundRequest, QueryError> {
    if max_output_bytes < MIN_GROUP_REPLY_BYTES {
        return Err(QueryError::InvalidOutputLimit);
    }
    let target = header_target(pool, namespace, image_id)?;
    Ok(CompoundRequest {
        target,
        access: Access::Read,
        context: RequestContext::default(),
        operations: vec![OsdOp::call(b"rbd", b"image_group_get", &[])],
        max_output_bytes,
    })
}

/// Decode a group reference only from the matching ordinary server reply.
pub fn decode_image_group_completion(
    expected: RequestToken,
    completion: ReadCompletion,
) -> Result<Versioned<Option<ImageGroupSpec>>, QueryError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    Ok(Versioned {
        value: decode_image_group_query(result, operations)?,
        user_version,
    })
}

/// Decode one bounded GroupSpec, accepting compatible versions and tails.
/// The default sentinel means no group; a partial or contradictory spec
/// cannot be used as an address.
pub fn decode_image_group_query(
    overall_result: i32,
    operations: Vec<OsdOp>,
) -> Result<Option<ImageGroupSpec>, QueryError> {
    let operation = single_class_reply(overall_result, operations)?;
    let mut decoder = Decoder::new(&operation.outdata);
    let spec = decoder
        .versioned(1, |body, _| {
            let pool = body.i64()?;
            let group_id = body.bytes()?.to_vec();
            Ok(ImageGroupSpec { pool, group_id })
        })
        .map_err(|_| QueryError::InvalidReply)?;
    if spec.pool == -1 && spec.group_id.is_empty() {
        return Ok(None);
    }
    if spec.pool < 0 || spec.group_id.is_empty() {
        return Err(QueryError::InvalidReply);
    }
    Ok(Some(spec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyrados::{ObjectQueue, ReadOutcome, ReadPublication};

    fn reply(pool: i64, id: &[u8]) -> Vec<OsdOp> {
        let request = image_group_query(7, vec![], b"image1", 4096).unwrap();
        let mut operation = OsdOp::echo(&request.operations[0]);
        let body_len = 8 + 4 + id.len();
        let mut data = vec![1, 1];
        data.extend_from_slice(&(body_len as u32).to_le_bytes());
        data.extend_from_slice(&pool.to_le_bytes());
        data.extend_from_slice(&(id.len() as u32).to_le_bytes());
        data.extend_from_slice(id);
        operation.outdata = data.into();
        vec![operation]
    }

    #[test]
    fn query_and_exact_group_reference() {
        let query = image_group_query(7, b"ns".to_vec(), b"image1", 4096).unwrap();
        assert_eq!(query.target.object, b"rbd_header.image1");
        assert_eq!(query.target.namespace, b"ns");
        assert_eq!(
            query.operations[0].cls_call().unwrap().method,
            b"image_group_get"
        );
        assert!(query.preflight(1 << 20).is_ok());
        assert_eq!(decode_image_group_query(0, reply(-1, b"")), Ok(None));
        assert_eq!(
            decode_image_group_query(0, reply(11, b"group1")),
            Ok(Some(ImageGroupSpec {
                pool: 11,
                group_id: b"group1".to_vec()
            }))
        );
        assert_eq!(
            decode_image_group_query(-2, vec![]),
            Err(QueryError::Remote(-2))
        );
        assert_eq!(
            decode_image_group_query(0, reply(-1, b"group1")),
            Err(QueryError::InvalidReply)
        );
    }

    #[test]
    fn group_frames_accept_compatible_versions_and_tails_without_losing_address_guards() {
        for (pool, group) in [
            (-1, &b""[..]),
            (11, &b"group1"[..]),
            (-1, &b"group1"[..]),
            (11, &b""[..]),
        ] {
            let original = reply(pool, group)[0].outdata.to_vec();
            let decode = |bytes: &[u8]| {
                let mut operations = reply(pool, group);
                operations[0].outdata = bytes.to_vec().into();
                decode_image_group_query(0, operations)
            };
            let expected = decode(&original);
            for version in [0, 1, 255] {
                for compat in [0, 1] {
                    let mut bytes = original.clone();
                    bytes[0] = version;
                    bytes[1] = compat;
                    let length = u32::from_le_bytes(bytes[2..6].try_into().unwrap()) + 2;
                    bytes.extend([0xab, 0xcd]);
                    bytes[2..6].copy_from_slice(&length.to_le_bytes());
                    bytes.extend([0xef]);
                    assert_eq!(decode(&bytes), expected);
                }
            }
            for end in 0..original.len() {
                assert_eq!(decode(&original[..end]), Err(QueryError::InvalidReply));
            }
            let mut short = original.clone();
            let length = u32::from_le_bytes(short[2..6].try_into().unwrap()) - 1;
            short[2..6].copy_from_slice(&length.to_le_bytes());
            assert_eq!(decode(&short), Err(QueryError::InvalidReply));
            let mut incompatible = original;
            incompatible[1] = 2;
            assert_eq!(decode(&incompatible), Err(QueryError::InvalidReply));
        }
    }

    #[test]
    fn completion_requires_matching_token_and_reply() {
        let mut queue = ObjectQueue::new(2, 1 << 20, 1).unwrap();
        let expected = queue
            .submit_compound(image_group_query(7, vec![], b"image1", 4096).unwrap())
            .unwrap();
        let other = queue
            .submit_compound(image_group_query(7, vec![], b"image2", 4096).unwrap())
            .unwrap();
        let completion = |token, publication| {
            ReadCompletion::new(
                token,
                ReadOutcome::RemoteCompound {
                    publication,
                    result: 0,
                    user_version: 29,
                    replay_version: Default::default(),
                    operations: reply(-1, b""),
                },
            )
        };
        assert_eq!(
            decode_image_group_completion(expected, completion(other, ReadPublication::Reply)),
            Err(QueryError::WrongCompletion)
        );
        assert_eq!(
            decode_image_group_completion(
                expected,
                completion(expected, ReadPublication::OutputLimit)
            ),
            Err(QueryError::InvalidPublication)
        );
        assert_eq!(
            decode_image_group_completion(expected, completion(expected, ReadPublication::Reply)),
            Ok(Versioned {
                value: None,
                user_version: 29
            })
        );
    }
}
