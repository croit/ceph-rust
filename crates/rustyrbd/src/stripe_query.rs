// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Conditional geometry query for images with STRIPINGV2.

use crate::{
    QueryError, Versioned,
    metadata_query::{compound_reply, header_target, single_class_reply},
};
use opwire::OsdOp;
use rustyrados::{Access, CompoundRequest, ReadCompletion, RequestContext, RequestToken};

/// Geometry returned by `rbd.get_stripe_unit_count` for one captured header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StripeGeometry {
    /// Contiguous bytes placed in one data object before moving to the next.
    pub unit: u64,
    /// Number of data objects in one stripe set.
    pub count: u64,
}

/// Build the conditional read-only class query for a header with STRIPINGV2.
/// The image owner decides whether the feature is present before submission.
pub fn stripe_query(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
) -> Result<CompoundRequest, QueryError> {
    let target = header_target(pool, namespace, image_id)?;
    Ok(CompoundRequest {
        target,
        access: Access::Read,
        context: RequestContext::default(),
        operations: vec![OsdOp::call(b"rbd", b"get_stripe_unit_count", &[])],
        max_output_bytes: 16,
    })
}

/// Decode only a reply for the submitted query and validate geometry against
/// the captured object order. This does not produce a striped byte mapping.
pub fn decode_stripe_completion(
    expected: RequestToken,
    completion: ReadCompletion,
    order: u8,
) -> Result<Versioned<StripeGeometry>, QueryError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    Ok(Versioned {
        value: decode_stripe_query(result, operations, order)?,
        user_version,
    })
}

/// Decode one verified ordinary server reply for `get_stripe_unit_count`.
pub fn decode_stripe_query(
    overall_result: i32,
    operations: Vec<OsdOp>,
    order: u8,
) -> Result<StripeGeometry, QueryError> {
    let operation = single_class_reply(overall_result, operations)?;
    let output: [u8; 16] = operation
        .outdata
        .as_ref()
        .try_into()
        .map_err(|_| QueryError::InvalidReply)?;
    let object_size = 1u64
        .checked_shl(u32::from(order))
        .ok_or(QueryError::InvalidStripeGeometry)?;
    let geometry = StripeGeometry {
        unit: u64::from_le_bytes(output[..8].try_into().expect("fixed-size slice")),
        count: u64::from_le_bytes(output[8..].try_into().expect("fixed-size slice")),
    };
    if geometry.unit == 0
        || geometry.count == 0
        || geometry.unit > object_size
        || object_size % geometry.unit != 0
    {
        return Err(QueryError::InvalidStripeGeometry);
    }
    Ok(geometry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyrados::{ObjectQueue, ReadOutcome, ReadPublication};

    fn reply(unit: u64, count: u64) -> Vec<OsdOp> {
        let query = stripe_query(7, vec![], b"image1").unwrap();
        let mut operation = OsdOp::echo(&query.operations[0]);
        let mut output = unit.to_le_bytes().to_vec();
        output.extend_from_slice(&count.to_le_bytes());
        operation.outdata = output.into();
        vec![operation]
    }

    #[test]
    fn stripe_query_is_one_read_only_header_call() {
        let query = stripe_query(7, b"ns".to_vec(), b"image1").unwrap();
        assert_eq!(query.target.object, b"rbd_header.image1");
        assert_eq!(query.target.namespace, b"ns");
        assert_eq!(query.access, Access::Read);
        assert_eq!(
            query.operations[0].cls_call().unwrap().method,
            b"get_stripe_unit_count"
        );
        assert!(query.preflight(1 << 20).is_ok());
        let query = stripe_query(7, vec![], b"image-1/path").unwrap();
        assert_eq!(query.target.object, b"rbd_header.image-1/path");
        assert!(matches!(
            stripe_query(7, vec![], b"image\0id"),
            Err(QueryError::InvalidImageId)
        ));
    }

    #[test]
    fn stripe_reply_requires_exact_and_usable_geometry() {
        assert_eq!(
            decode_stripe_query(0, reply(1 << 20, 4), 22),
            Ok(StripeGeometry {
                unit: 1 << 20,
                count: 4
            })
        );
        assert_eq!(
            decode_stripe_query(-8, reply(1 << 20, 4), 22),
            Err(QueryError::Remote(-8))
        );
        for (unit, count) in [(0, 4), (1 << 20, 0), (3, 4), (1 << 23, 1)] {
            assert_eq!(
                decode_stripe_query(0, reply(unit, count), 22),
                Err(QueryError::InvalidStripeGeometry)
            );
        }
        assert_eq!(
            decode_stripe_query(0, reply(1, 1), 64),
            Err(QueryError::InvalidStripeGeometry)
        );
        let mut trailing = reply(1 << 20, 4);
        trailing[0].outdata = vec![0; 17].into();
        assert_eq!(
            decode_stripe_query(0, trailing, 22),
            Err(QueryError::InvalidReply)
        );
    }

    #[test]
    fn stripe_completion_requires_matching_token_and_provenance() {
        let mut queue = ObjectQueue::new(2, 1 << 20, 1).unwrap();
        let expected = queue
            .submit_compound(stripe_query(7, vec![], b"image1").unwrap())
            .unwrap();
        let other = queue
            .submit_compound(stripe_query(7, vec![], b"image2").unwrap())
            .unwrap();
        let completion = |token, publication| {
            ReadCompletion::new(
                token,
                ReadOutcome::RemoteCompound {
                    publication,
                    result: 0,
                    user_version: 1,
                    replay_version: Default::default(),
                    operations: reply(1 << 20, 4),
                },
            )
        };
        assert_eq!(
            decode_stripe_completion(expected, completion(other, ReadPublication::Reply), 22),
            Err(QueryError::WrongCompletion)
        );
        assert_eq!(
            decode_stripe_completion(
                expected,
                completion(expected, ReadPublication::OutputLimit),
                22
            ),
            Err(QueryError::InvalidPublication)
        );
        assert_eq!(
            decode_stripe_completion(expected, completion(expected, ReadPublication::Reply), 22),
            Ok(Versioned {
                value: StripeGeometry {
                    unit: 1 << 20,
                    count: 4
                },
                user_version: 1,
            })
        );
    }
}
