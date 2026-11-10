// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! One batched, version-matched image-head refresh observation.

use crate::{
    FEATURE_OPERATIONS, FEATURE_STRIPING_V2, HeadInputs, HeadObservation, HeadObservationError,
    ImageHeader, QueryError, Versioned, decode_flags_query, decode_image_group_query,
    decode_parent_overlap_query, decode_parent_query, decode_snapcontext_query,
    decode_stripe_query,
    group_query::MIN_GROUP_REPLY_BYTES,
    metadata_query::{compound_reply, header_target},
    parent_query::MAX_PARENT_REPLY_BYTES,
    snapcontext_query::MIN_SNAPCONTEXT_REPLY_BYTES,
};
use opwire::OsdOp;
use rustyrados::{Access, CompoundRequest, ReadCompletion, RequestContext, RequestToken};

/// Data retained while the compound is in flight. The submitted request
/// and this receipt must be kept together by the image-open coordinator.
#[derive(Debug)]
pub struct HeadRefreshReceipt {
    header: Versioned<ImageHeader>,
    stripe: bool,
    op_features: bool,
    bounded_limits: Option<(u32, u32)>,
}

impl HeadRefreshReceipt {
    /// Per-class output caps in the same order as the refresh compound.
    /// Their sum equals the request's maximum output allowance.
    pub fn reply_capacities(&self) -> Option<Vec<usize>> {
        let (max_snapcontext_bytes, max_group_bytes) = self.bounded_limits?;
        let mut capacities = vec![
            8,
            max_snapcontext_bytes as usize,
            MAX_PARENT_REPLY_BYTES as usize,
            9,
            max_group_bytes as usize,
        ];
        if self.stripe {
            capacities.push(16);
        }
        if self.op_features {
            capacities.push(8);
        }
        Some(capacities)
    }
}

/// A reply may fail as a RADOS query or contradict the prior header version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadRefreshError {
    Query(QueryError),
    Observation(HeadObservationError),
}

impl std::fmt::Display for HeadRefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Query(error) => std::fmt::Display::fmt(error, f),
            Self::Observation(error) => std::fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for HeadRefreshError {}

impl From<QueryError> for HeadRefreshError {
    fn from(error: QueryError) -> Self {
        Self::Query(error)
    }
}

impl From<HeadObservationError> for HeadRefreshError {
    fn from(error: HeadObservationError) -> Self {
        Self::Observation(error)
    }
}

/// Build the second, conditional stage of image-head observation. The two
/// variable output limits are caller-selected; fixed outputs have exact caps.
pub fn head_refresh_query(
    header: Versioned<ImageHeader>,
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
    max_snapcontext_bytes: u32,
    max_group_bytes: u32,
) -> Result<(CompoundRequest, HeadRefreshReceipt), QueryError> {
    if max_snapcontext_bytes < MIN_SNAPCONTEXT_REPLY_BYTES
        || max_group_bytes < MIN_GROUP_REPLY_BYTES
    {
        return Err(QueryError::InvalidOutputLimit);
    }
    let target = header_target(pool, namespace, image_id)?;
    let stripe = header.value.features & FEATURE_STRIPING_V2 != 0;
    let op_features = header.value.features & FEATURE_OPERATIONS != 0;
    let mut max_output_bytes = 8u32
        .checked_add(max_snapcontext_bytes)
        .and_then(|n| n.checked_add(MAX_PARENT_REPLY_BYTES))
        .and_then(|n| n.checked_add(9))
        .and_then(|n| n.checked_add(max_group_bytes))
        .ok_or(QueryError::InvalidOutputLimit)?;
    if stripe {
        max_output_bytes = max_output_bytes
            .checked_add(16)
            .ok_or(QueryError::InvalidOutputLimit)?;
    }
    if op_features {
        max_output_bytes = max_output_bytes
            .checked_add(8)
            .ok_or(QueryError::InvalidOutputLimit)?;
    }
    let snap = opwire::NOSNAP.to_le_bytes();
    let mut operations = vec![
        OsdOp::call(b"rbd", b"get_flags", &snap),
        OsdOp::call(b"rbd", b"get_snapcontext", &[]),
        OsdOp::call(b"rbd", b"parent_get", &[]),
        OsdOp::call(b"rbd", b"parent_overlap_get", &snap),
        OsdOp::call(b"rbd", b"image_group_get", &[]),
    ];
    if stripe {
        operations.push(OsdOp::call(b"rbd", b"get_stripe_unit_count", &[]));
    }
    if op_features {
        operations.push(OsdOp::call(b"rbd", b"op_features_get", &[]));
    }
    let request = CompoundRequest {
        target,
        access: Access::Read,
        context: RequestContext::default(),
        operations,
        max_output_bytes,
    };
    Ok((
        request,
        HeadRefreshReceipt {
            header,
            stripe,
            op_features,
            bounded_limits: Some((max_snapcontext_bytes, max_group_bytes)),
        },
    ))
}

/// Build the same class batch for a C provider that allocates each reply.
/// No output buffer is reserved; the total wire reply must fit in `u32`.
pub fn head_refresh_query_allocated(
    header: Versioned<ImageHeader>,
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
) -> Result<(CompoundRequest, HeadRefreshReceipt), QueryError> {
    let (mut request, mut receipt) = head_refresh_query(
        header,
        pool,
        namespace,
        image_id,
        MIN_SNAPCONTEXT_REPLY_BYTES,
        MIN_GROUP_REPLY_BYTES,
    )?;
    request.max_output_bytes = u32::MAX;
    receipt.bounded_limits = None;
    Ok((request, receipt))
}

/// Decode the exact compound reply and join it to the preceding header query.
/// A version change publishes nothing, including fields already decoded.
pub fn decode_head_refresh_completion(
    receipt: HeadRefreshReceipt,
    expected: RequestToken,
    completion: ReadCompletion,
) -> Result<HeadObservation, HeadRefreshError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    decode_head_refresh_query(receipt, result, user_version, operations)
}

/// Decode an already verified same-object class batch. C ABI adapters must
/// independently establish the reply's ordinary provenance and version.
pub fn decode_head_refresh_query(
    receipt: HeadRefreshReceipt,
    result: i32,
    user_version: u64,
    operations: Vec<OsdOp>,
) -> Result<HeadObservation, HeadRefreshError> {
    if result < 0 {
        return Err(QueryError::Remote(result).into());
    }
    if result != 0
        || operations.len() != 5 + usize::from(receipt.stripe) + usize::from(receipt.op_features)
    {
        return Err(QueryError::InvalidReply.into());
    }
    if user_version != receipt.header.user_version {
        return Err(HeadObservationError::VersionChanged {
            field: "refresh reply",
            expected: receipt.header.user_version,
            observed: user_version,
        }
        .into());
    }
    let mut operations = operations.into_iter();
    let mut one = || {
        operations
            .next()
            .map(|operation| vec![operation])
            .ok_or(QueryError::InvalidReply)
    };
    let flags = decode_flags_query(0, one()?)?;
    let snap_context = decode_snapcontext_query(0, one()?)?;
    let parent = decode_parent_query(0, one()?)?;
    let parent_overlap = decode_parent_overlap_query(0, one()?)?;
    let group = decode_image_group_query(0, one()?)?;
    let stripe = if receipt.stripe {
        Some(Versioned {
            value: decode_stripe_query(0, one()?, receipt.header.value.order)?,
            user_version,
        })
    } else {
        None
    };
    let op_features = if receipt.op_features {
        Some(Versioned {
            value: decode_flags_query(0, one()?)?,
            user_version,
        })
    } else {
        None
    };
    Ok(HeadObservation::assemble(HeadInputs {
        header: receipt.header,
        snap_context: Versioned {
            value: snap_context,
            user_version,
        },
        flags: Versioned {
            value: flags,
            user_version,
        },
        parent: Versioned {
            value: parent,
            user_version,
        },
        parent_overlap: Versioned {
            value: parent_overlap,
            user_version,
        },
        group: Versioned {
            value: group,
            user_version,
        },
        stripe,
        op_features,
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyrados::{ObjectQueue, ReadOutcome, ReadPublication};

    fn header(features: u64) -> Versioned<ImageHeader> {
        Versioned {
            value: ImageHeader {
                order: 22,
                size: 8192,
                features,
                incompatible_features: 0,
                object_prefix: b"rbd_data.image1".to_vec(),
                data_pool_id: -1,
            },
            user_version: 37,
        }
    }

    fn envelope(body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![1, 1];
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    fn reply(request: &CompoundRequest) -> Vec<OsdOp> {
        let mut operations: Vec<_> = request.operations.iter().map(OsdOp::echo).collect();
        operations[0].outdata = 3u64.to_le_bytes().to_vec().into();
        let mut snapcontext = 9u64.to_le_bytes().to_vec();
        snapcontext.extend_from_slice(&1u32.to_le_bytes());
        snapcontext.extend_from_slice(&9u64.to_le_bytes());
        operations[1].outdata = snapcontext.into();
        let mut parent = (-1i64).to_le_bytes().to_vec();
        parent.extend_from_slice(&0u32.to_le_bytes());
        parent.extend_from_slice(&0u32.to_le_bytes());
        parent.extend_from_slice(&opwire::NOSNAP.to_le_bytes());
        operations[2].outdata = envelope(&parent).into();
        operations[3].outdata = vec![0].into();
        let mut group = (-1i64).to_le_bytes().to_vec();
        group.extend_from_slice(&0u32.to_le_bytes());
        operations[4].outdata = envelope(&group).into();
        let mut next = 5;
        if request.operations.iter().any(|op| {
            op.cls_call()
                .is_ok_and(|call| call.method == b"get_stripe_unit_count")
        }) {
            let mut stripe = (1u64 << 20).to_le_bytes().to_vec();
            stripe.extend_from_slice(&4u64.to_le_bytes());
            operations[next].outdata = stripe.into();
            next += 1;
        }
        if request.operations.iter().any(|op| {
            op.cls_call()
                .is_ok_and(|call| call.method == b"op_features_get")
        }) {
            operations[next].outdata = 2u64.to_le_bytes().to_vec().into();
        }
        operations
    }

    #[test]
    fn batch_builds_exact_conditional_calls_and_coherent_head() {
        let features = 1 | FEATURE_STRIPING_V2 | FEATURE_OPERATIONS;
        let (request, receipt) =
            head_refresh_query(header(features), 7, b"ns".to_vec(), b"image1", 4096, 1024).unwrap();
        assert_eq!(request.target.object, b"rbd_header.image1");
        assert_eq!(request.target.namespace, b"ns");
        assert_eq!(request.access, Access::Read);
        assert_eq!(
            receipt.reply_capacities().unwrap().iter().sum::<usize>(),
            request.max_output_bytes as usize
        );
        let methods: Vec<_> = request
            .operations
            .iter()
            .map(|op| op.cls_call().unwrap().method.to_vec())
            .collect();
        let expected: [&[u8]; 7] = [
            b"get_flags",
            b"get_snapcontext",
            b"parent_get",
            b"parent_overlap_get",
            b"image_group_get",
            b"get_stripe_unit_count",
            b"op_features_get",
        ];
        assert_eq!(
            methods,
            expected
                .iter()
                .map(|name| name.to_vec())
                .collect::<Vec<_>>()
        );
        assert!(request.preflight(1 << 20).is_ok());
        let operations = reply(&request);
        let mut queue = ObjectQueue::new(1, 1 << 20, 1).unwrap();
        let expected = queue.submit_compound(request).unwrap();
        let completion = ReadCompletion::new(
            expected,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: 0,
                user_version: 37,
                replay_version: Default::default(),
                operations,
            },
        );
        let observed = decode_head_refresh_completion(receipt, expected, completion).unwrap();
        assert_eq!(observed.user_version(), 37);
        assert_eq!(observed.flags(), 3);
        assert_eq!(observed.snap_context().ids, [9]);
        assert_eq!(observed.stripe().unwrap().count, 4);
        assert_eq!(observed.op_features(), Some(2));
    }

    #[test]
    fn default_object_map_feature_does_not_request_operation_features() {
        let (request, receipt) =
            head_refresh_query(header(61), 7, b"ns".to_vec(), b"image1", 4096, 1024).unwrap();
        assert!(!receipt.op_features);
        assert!(request.operations.iter().all(|op| {
            op.cls_call()
                .is_ok_and(|call| call.method != b"op_features_get")
        }));
    }

    #[test]
    fn changed_header_version_or_wrong_token_publishes_nothing() {
        let (request, receipt) =
            head_refresh_query(header(1), 7, vec![], b"image1", 4096, 1024).unwrap();
        let operations = reply(&request);
        let mut queue = ObjectQueue::new(2, 1 << 20, 1).unwrap();
        let expected = queue.submit_compound(request).unwrap();
        let completion = ReadCompletion::new(
            expected,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: 0,
                user_version: 38,
                replay_version: Default::default(),
                operations,
            },
        );
        assert_eq!(
            decode_head_refresh_completion(receipt, expected, completion),
            Err(HeadRefreshError::Observation(
                HeadObservationError::VersionChanged {
                    field: "refresh reply",
                    expected: 37,
                    observed: 38
                }
            ))
        );
        let (request, receipt) =
            head_refresh_query(header(1), 7, vec![], b"image1", 4096, 1024).unwrap();
        let operations = reply(&request);
        let other = queue.submit_compound(request).unwrap();
        let completion = ReadCompletion::new(
            other,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: 0,
                user_version: 37,
                replay_version: Default::default(),
                operations,
            },
        );
        assert_eq!(
            decode_head_refresh_completion(receipt, expected, completion),
            Err(HeadRefreshError::Query(QueryError::WrongCompletion))
        );
    }

    #[test]
    fn rejects_too_small_or_overflowing_output_allowances() {
        assert!(matches!(
            head_refresh_query(header(1), 7, vec![], b"image1", 11, 18),
            Err(QueryError::InvalidOutputLimit)
        ));
        assert!(matches!(
            head_refresh_query(header(1), 7, vec![], b"image1", 12, 17),
            Err(QueryError::InvalidOutputLimit)
        ));
        assert!(matches!(
            head_refresh_query(header(1), 7, vec![], b"image1", u32::MAX, 18),
            Err(QueryError::InvalidOutputLimit)
        ));
    }
}
