// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Parent identity and snapshot-specific overlap observations.

use crate::{
    QueryError, Versioned,
    metadata_query::{
        HEADER_PREFIX, MAX_NAMESPACE_BYTES, MAX_OBJECT_NAME_BYTES, compound_reply, header_target,
        single_class_reply,
    },
};
use denc::{Decoder, Encoder};
use opwire::OsdOp;
use rustyrados::{Access, CompoundRequest, ReadCompletion, RequestContext, RequestToken};

const MAX_PARENT_ID_BYTES: usize = MAX_OBJECT_NAME_BYTES - HEADER_PREFIX.len();
pub(crate) const MAX_PARENT_REPLY_BYTES: u32 =
    (6 + 8 + 4 + MAX_NAMESPACE_BYTES + 4 + MAX_PARENT_ID_BYTES + 8) as u32;

/// The parent image and snapshot to consult inside the overlap range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentSpec {
    pub pool: i64,
    pub namespace: Vec<u8>,
    pub image_id: Vec<u8>,
    pub snapshot_id: u64,
}

/// Encode `parent_attach`: versioned parent identity, overlap, reattach flag.
pub fn parent_attach_input(
    spec: &ParentSpec,
    overlap: u64,
    reattach: bool,
) -> denc::Result<Vec<u8>> {
    let mut encoder = Encoder::with_capacity(64);
    encoder.versioned(1, 1, |body| {
        body.i64(spec.pool)?;
        body.bytes(&spec.namespace)?;
        body.bytes(&spec.image_id)?;
        body.u64(spec.snapshot_id)
    })?;
    encoder.u64(overlap)?;
    encoder.bool(reattach)?;
    Ok(encoder.into_vec())
}

/// Query the namespace-aware parent identity from the child header.
pub fn parent_query(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
) -> Result<CompoundRequest, QueryError> {
    let target = header_target(pool, namespace, image_id)?;
    Ok(CompoundRequest {
        target,
        access: Access::Read,
        context: RequestContext::default(),
        operations: vec![OsdOp::call(b"rbd", b"parent_get", &[])],
        max_output_bytes: MAX_PARENT_REPLY_BYTES,
    })
}

/// Query the parent overlap for head or one snapshot. The result is only an
/// observation and does not prove that the child header exists.
pub fn parent_overlap_query(
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
            b"parent_overlap_get",
            &snapshot_id.to_le_bytes(),
        )],
        max_output_bytes: 9,
    })
}

/// Decode only the matching ordinary server reply for parent identity.
pub fn decode_parent_completion(
    expected: RequestToken,
    completion: ReadCompletion,
) -> Result<Versioned<Option<ParentSpec>>, QueryError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    Ok(Versioned {
        value: decode_parent_query(result, operations)?,
        user_version,
    })
}

/// Decode only the matching ordinary server reply for parent overlap.
pub fn decode_parent_overlap_completion(
    expected: RequestToken,
    completion: ReadCompletion,
) -> Result<Versioned<Option<u64>>, QueryError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    Ok(Versioned {
        value: decode_parent_overlap_query(result, operations)?,
        user_version,
    })
}

/// Decode a verified `parent_get` reply. An exact default spec means no parent.
pub fn decode_parent_query(
    overall_result: i32,
    operations: Vec<OsdOp>,
) -> Result<Option<ParentSpec>, QueryError> {
    let operation = single_class_reply(overall_result, operations)?;
    let mut decoder = Decoder::new(&operation.outdata);
    let spec = decoder
        .versioned(1, |body, _| {
            let pool = body.i64()?;
            let namespace = body.bytes()?.to_vec();
            let image_id = body.bytes()?.to_vec();
            let snapshot_id = body.u64()?;
            Ok(ParentSpec {
                pool,
                namespace,
                image_id,
                snapshot_id,
            })
        })
        .map_err(|_| QueryError::InvalidParent)?;
    if spec.pool == -1
        && spec.namespace.is_empty()
        && spec.image_id.is_empty()
        && spec.snapshot_id == opwire::NOSNAP
    {
        return Ok(None);
    }
    if spec.pool < 0
        || spec.namespace.len() > MAX_NAMESPACE_BYTES
        || spec.image_id.is_empty()
        || spec.image_id.len() > MAX_PARENT_ID_BYTES
        || !spec.image_id.iter().all(u8::is_ascii_alphanumeric)
        || spec.snapshot_id >= opwire::NOSNAP
    {
        return Err(QueryError::InvalidParent);
    }
    Ok(Some(spec))
}

/// Decode a verified `parent_overlap_get` reply as an exact optional u64.
pub fn decode_parent_overlap_query(
    overall_result: i32,
    operations: Vec<OsdOp>,
) -> Result<Option<u64>, QueryError> {
    let operation = single_class_reply(overall_result, operations)?;
    match operation.outdata.as_ref() {
        [0] => Ok(None),
        [1, bytes @ ..] if bytes.len() == 8 => {
            let overlap: [u8; 8] = bytes.try_into().map_err(|_| QueryError::InvalidParent)?;
            Ok(Some(u64::from_le_bytes(overlap)))
        }
        _ => Err(QueryError::InvalidParent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyrados::{ObjectQueue, ReadOutcome, ReadPublication};

    fn parent_reply(bytes: &[u8]) -> Vec<OsdOp> {
        let request = parent_query(7, vec![], b"child1").unwrap();
        let mut operation = OsdOp::echo(&request.operations[0]);
        operation.outdata = bytes.to_vec().into();
        vec![operation]
    }

    fn encoded_parent(pool: i64, namespace: &[u8], image_id: &[u8], snapid: u64) -> Vec<u8> {
        let body_length = 8 + 4 + namespace.len() + 4 + image_id.len() + 8;
        let mut output = vec![1, 1];
        output.extend_from_slice(&(body_length as u32).to_le_bytes());
        output.extend_from_slice(&pool.to_le_bytes());
        output.extend_from_slice(&(namespace.len() as u32).to_le_bytes());
        output.extend_from_slice(namespace);
        output.extend_from_slice(&(image_id.len() as u32).to_le_bytes());
        output.extend_from_slice(image_id);
        output.extend_from_slice(&snapid.to_le_bytes());
        output
    }

    #[test]
    fn attach_preserves_the_versioned_parent_identity() {
        let spec = ParentSpec {
            pool: 23,
            namespace: b"ns".to_vec(),
            image_id: b"parent1".to_vec(),
            snapshot_id: 9,
        };
        let encoded = parent_attach_input(&spec, 4096, false).unwrap();
        let body = encoded_parent(23, b"ns", b"parent1", 9);
        assert_eq!(&encoded[..body.len()], body.as_slice());
        assert_eq!(
            decode_parent_query(0, parent_reply(&encoded[..body.len()])),
            Ok(Some(spec))
        );
        assert_eq!(&encoded[body.len()..], &[0, 16, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn parent_queries_target_header_with_exact_inputs() {
        let parent = parent_query(7, b"ns".to_vec(), b"child1").unwrap();
        assert_eq!(parent.target.object, b"rbd_header.child1");
        assert_eq!(
            parent.operations[0].cls_call().unwrap().method,
            b"parent_get"
        );
        assert!(parent.preflight(1 << 20).is_ok());
        let overlap = parent_overlap_query(7, b"ns".to_vec(), b"child1", 19).unwrap();
        let call = overlap.operations[0].cls_call().unwrap();
        assert_eq!(call.method, b"parent_overlap_get");
        assert_eq!(call.input, &19u64.to_le_bytes());
        assert!(overlap.preflight(1 << 20).is_ok());
    }

    #[test]
    fn parent_identity_decodes_default_present_and_malformed_values() {
        assert_eq!(
            decode_parent_query(
                0,
                parent_reply(&encoded_parent(-1, b"", b"", opwire::NOSNAP))
            ),
            Ok(None)
        );
        let present =
            decode_parent_query(0, parent_reply(&encoded_parent(23, b"ns", b"parent1", 9)))
                .unwrap()
                .unwrap();
        assert_eq!(present.pool, 23);
        assert_eq!(present.namespace, b"ns");
        assert_eq!(present.image_id, b"parent1");
        assert_eq!(present.snapshot_id, 9);
        assert_eq!(decode_parent_query(-2, vec![]), Err(QueryError::Remote(-2)));
        for bytes in [
            encoded_parent(23, b"ns", b"parent-1", 9),
            encoded_parent(-1, b"ns", b"", opwire::NOSNAP),
            encoded_parent(23, b"ns", b"parent1", opwire::SNAPDIR),
        ] {
            assert_eq!(
                decode_parent_query(0, parent_reply(&bytes)),
                Err(QueryError::InvalidParent)
            );
        }
    }

    #[test]
    fn parent_frames_accept_compatible_versions_and_tails_without_losing_address_guards() {
        for (pool, namespace, image, snapshot) in [
            (-1, &b""[..], &b""[..], opwire::NOSNAP),
            (23, &b"ns"[..], &b"parent1"[..], 9),
            (23, &b"ns"[..], &b"parent-1"[..], 9),
        ] {
            let original = encoded_parent(pool, namespace, image, snapshot);
            let expected = decode_parent_query(0, parent_reply(&original));
            for version in [0, 1, 255] {
                for compat in [0, 1] {
                    let mut bytes = original.clone();
                    bytes[0] = version;
                    bytes[1] = compat;
                    let length = u32::from_le_bytes(bytes[2..6].try_into().unwrap()) + 2;
                    bytes.extend([0xab, 0xcd]);
                    bytes[2..6].copy_from_slice(&length.to_le_bytes());
                    bytes.extend([0xef]);
                    assert_eq!(decode_parent_query(0, parent_reply(&bytes)), expected);
                }
            }
            for end in 0..original.len() {
                assert_eq!(
                    decode_parent_query(0, parent_reply(&original[..end])),
                    Err(QueryError::InvalidParent)
                );
            }
            let mut short = original.clone();
            let length = u32::from_le_bytes(short[2..6].try_into().unwrap()) - 1;
            short[2..6].copy_from_slice(&length.to_le_bytes());
            assert_eq!(
                decode_parent_query(0, parent_reply(&short)),
                Err(QueryError::InvalidParent)
            );
            let mut incompatible = original;
            incompatible[1] = 2;
            assert_eq!(
                decode_parent_query(0, parent_reply(&incompatible)),
                Err(QueryError::InvalidParent)
            );
        }
    }

    #[test]
    fn overlap_reply_is_exact_optional_and_keeps_remote_errors() {
        let query = parent_overlap_query(7, vec![], b"child1", opwire::NOSNAP).unwrap();
        let mut op = OsdOp::echo(&query.operations[0]);
        op.outdata = vec![0].into();
        assert_eq!(decode_parent_overlap_query(0, vec![op.clone()]), Ok(None));
        let mut present = vec![1];
        present.extend_from_slice(&4096u64.to_le_bytes());
        op.outdata = present.into();
        assert_eq!(
            decode_parent_overlap_query(0, vec![op.clone()]),
            Ok(Some(4096))
        );
        assert_eq!(
            decode_parent_overlap_query(-2, vec![]),
            Err(QueryError::Remote(-2))
        );
        op.outdata = vec![2].into();
        assert_eq!(
            decode_parent_overlap_query(0, vec![op]),
            Err(QueryError::InvalidParent)
        );
    }

    #[test]
    fn parent_completion_requires_matching_token_and_provenance() {
        let mut queue = ObjectQueue::new(2, 1 << 20, 1).unwrap();
        let expected = queue
            .submit_compound(parent_query(7, vec![], b"child1").unwrap())
            .unwrap();
        let other = queue
            .submit_compound(parent_query(7, vec![], b"child2").unwrap())
            .unwrap();
        let completion = |token, publication| {
            ReadCompletion::new(
                token,
                ReadOutcome::RemoteCompound {
                    publication,
                    result: 0,
                    user_version: 1,
                    replay_version: Default::default(),
                    operations: parent_reply(&encoded_parent(23, b"ns", b"parent1", 9)),
                },
            )
        };
        assert_eq!(
            decode_parent_completion(expected, completion(other, ReadPublication::Reply)),
            Err(QueryError::WrongCompletion)
        );
        assert_eq!(
            decode_parent_completion(expected, completion(expected, ReadPublication::OutputLimit)),
            Err(QueryError::InvalidPublication)
        );
        assert!(
            decode_parent_completion(expected, completion(expected, ReadPublication::Reply))
                .unwrap()
                .value
                .is_some()
        );
    }
}
