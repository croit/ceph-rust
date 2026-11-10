// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Batched per-snapshot observation on one image header version.

use crate::{
    HeadObservation, QueryError, SnapshotInputs, SnapshotObservation, SnapshotObservationError,
    Versioned, decode_flags_query, decode_parent_overlap_query, decode_snapshot_protection_query,
    decode_snapshot_query,
    metadata_query::{compound_reply, header_target},
    snapshot_query::MIN_SNAPSHOT_REPLY_BYTES,
};
use opwire::OsdOp;
use rustyrados::{Access, CompoundRequest, ReadCompletion, RequestContext, RequestToken};

/// Identity retained while the per-snapshot compound is in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotRefreshReceipt {
    snapshot_id: u64,
    header_version: u64,
    max_snapshot_info_bytes: Option<u32>,
}

impl SnapshotRefreshReceipt {
    /// Exact per-class output caps in snapshot refresh order.
    pub fn reply_capacities(&self) -> Option<[usize; 4]> {
        Some([self.max_snapshot_info_bytes? as usize, 8, 9, 1])
    }
}

/// A per-snapshot getter failed, or its version cannot join the head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotRefreshError {
    Query(QueryError),
    Observation(SnapshotObservationError),
}

impl std::fmt::Display for SnapshotRefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Query(error) => std::fmt::Display::fmt(error, f),
            Self::Observation(error) => std::fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for SnapshotRefreshError {}

impl From<QueryError> for SnapshotRefreshError {
    fn from(error: QueryError) -> Self {
        Self::Query(error)
    }
}

impl From<SnapshotObservationError> for SnapshotRefreshError {
    fn from(error: SnapshotObservationError) -> Self {
        Self::Observation(error)
    }
}

/// Query all mutable snapshot metadata in one RADOS operation after the ID
/// has been observed in the head's SnapContext.
pub fn snapshot_refresh_query(
    head: &HeadObservation,
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
    snapshot_id: u64,
    max_snapshot_info_bytes: u32,
) -> Result<(CompoundRequest, SnapshotRefreshReceipt), QueryError> {
    if snapshot_id >= opwire::NOSNAP
        || head
            .snap_context()
            .ids
            .binary_search_by(|probe| snapshot_id.cmp(probe))
            .is_err()
    {
        return Err(QueryError::InvalidSnapshot);
    }
    if max_snapshot_info_bytes < MIN_SNAPSHOT_REPLY_BYTES {
        return Err(QueryError::InvalidOutputLimit);
    }
    let max_output_bytes = max_snapshot_info_bytes
        .checked_add(8 + 9 + 1)
        .ok_or(QueryError::InvalidOutputLimit)?;
    let target = header_target(pool, namespace, image_id)?;
    let snap = snapshot_id.to_le_bytes();
    let request = CompoundRequest {
        target,
        access: Access::Read,
        context: RequestContext::default(),
        operations: vec![
            OsdOp::call(b"rbd", b"snapshot_get", &snap),
            OsdOp::call(b"rbd", b"get_flags", &snap),
            OsdOp::call(b"rbd", b"parent_overlap_get", &snap),
            OsdOp::call(b"rbd", b"get_protection_status", &snap),
        ],
        max_output_bytes,
    };
    Ok((
        request,
        SnapshotRefreshReceipt {
            snapshot_id,
            header_version: head.user_version(),
            max_snapshot_info_bytes: Some(max_snapshot_info_bytes),
        },
    ))
}

/// Build the same snapshot batch for librados-allocated C outputs.
/// No reply buffer is reserved; the total reply must fit in `u32`.
pub fn snapshot_refresh_query_allocated(
    head: &HeadObservation,
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
    snapshot_id: u64,
) -> Result<(CompoundRequest, SnapshotRefreshReceipt), QueryError> {
    let (mut request, mut receipt) = snapshot_refresh_query(
        head,
        pool,
        namespace,
        image_id,
        snapshot_id,
        MIN_SNAPSHOT_REPLY_BYTES,
    )?;
    request.max_output_bytes = u32::MAX;
    receipt.max_snapshot_info_bytes = None;
    Ok((request, receipt))
}

/// Decode one exact batch and join it to the captured head version.
pub fn decode_snapshot_refresh_completion(
    head: &HeadObservation,
    receipt: SnapshotRefreshReceipt,
    expected: RequestToken,
    completion: ReadCompletion,
) -> Result<SnapshotObservation, SnapshotRefreshError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    decode_snapshot_refresh_query(head, receipt, result, user_version, operations)
}

/// Decode a verified same-header batch without relying on a transport token.
/// A C ABI caller must establish reply provenance and version separately.
pub fn decode_snapshot_refresh_query(
    head: &HeadObservation,
    receipt: SnapshotRefreshReceipt,
    result: i32,
    user_version: u64,
    operations: Vec<OsdOp>,
) -> Result<SnapshotObservation, SnapshotRefreshError> {
    if head.user_version() != receipt.header_version {
        return Err(SnapshotObservationError::VersionChanged {
            field: "head receipt",
            expected: receipt.header_version,
            observed: head.user_version(),
        }
        .into());
    }
    if result < 0 {
        return Err(QueryError::Remote(result).into());
    }
    if result != 0 || operations.len() != 4 {
        return Err(QueryError::InvalidReply.into());
    }
    if user_version != receipt.header_version {
        return Err(SnapshotObservationError::VersionChanged {
            field: "refresh reply",
            expected: receipt.header_version,
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
    let info = decode_snapshot_query(0, one()?, receipt.snapshot_id)?;
    let flags = decode_flags_query(0, one()?)?;
    let parent_overlap = decode_parent_overlap_query(0, one()?)?;
    let protection = decode_snapshot_protection_query(0, one()?)?;
    Ok(SnapshotObservation::assemble(
        head,
        SnapshotInputs {
            info: Versioned {
                value: info,
                user_version,
            },
            flags: Versioned {
                value: flags,
                user_version,
            },
            parent_overlap: Versioned {
                value: parent_overlap,
                user_version,
            },
            protection: Versioned {
                value: protection,
                user_version,
            },
        },
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeadInputs, ImageHeader, ImageSnapContext};
    use rustyrados::{ObjectQueue, ReadOutcome, ReadPublication};

    fn head() -> HeadObservation {
        HeadObservation::assemble(HeadInputs {
            header: Versioned {
                value: ImageHeader {
                    order: 22,
                    size: 8192,
                    features: 0,
                    incompatible_features: 0,
                    object_prefix: b"rbd_data.image1".to_vec(),
                    data_pool_id: -1,
                },
                user_version: 37,
            },
            snap_context: Versioned {
                value: ImageSnapContext {
                    sequence: 1,
                    ids: vec![1],
                },
                user_version: 37,
            },
            flags: Versioned {
                value: 0,
                user_version: 37,
            },
            parent: Versioned {
                value: None,
                user_version: 37,
            },
            parent_overlap: Versioned {
                value: None,
                user_version: 37,
            },
            group: Versioned {
                value: None,
                user_version: 37,
            },
            stripe: None,
            op_features: None,
        })
        .unwrap()
    }

    fn reply(request: &CompoundRequest) -> Vec<OsdOp> {
        let mut operations: Vec<_> = request.operations.iter().map(OsdOp::echo).collect();
        operations[0].outdata = include_bytes!("../../../testdata/cls/dencoder/SnapshotInfo/1.bin")
            .to_vec()
            .into();
        operations[1].outdata = 3u64.to_le_bytes().to_vec().into();
        operations[2].outdata = vec![0].into();
        operations[3].outdata = vec![2].into();
        operations
    }

    #[test]
    fn builds_exact_snapshot_batch_and_joins_same_version() {
        let head = head();
        let (request, receipt) =
            snapshot_refresh_query(&head, 7, b"ns".to_vec(), b"image1", 1, 4096).unwrap();
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
            .map(|operation| operation.cls_call().unwrap().method.to_vec())
            .collect();
        let expected: [&[u8]; 4] = [
            b"snapshot_get",
            b"get_flags",
            b"parent_overlap_get",
            b"get_protection_status",
        ];
        assert_eq!(
            methods,
            expected
                .iter()
                .map(|name| name.to_vec())
                .collect::<Vec<_>>()
        );
        for operation in &request.operations {
            assert_eq!(operation.cls_call().unwrap().input, &1u64.to_le_bytes());
        }
        assert!(request.preflight(1 << 20).is_ok());
        let operations = reply(&request);
        let mut queue = ObjectQueue::new(1, 1 << 20, 1).unwrap();
        let token = queue.submit_compound(request).unwrap();
        let completion = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: 0,
                user_version: 37,
                replay_version: Default::default(),
                operations,
            },
        );
        let observed =
            decode_snapshot_refresh_completion(&head, receipt, token, completion).unwrap();
        assert_eq!(observed.info().id, 1);
        assert_eq!(observed.info().name, b"snap1");
        assert_eq!(observed.flags(), 3);
        assert_eq!(observed.protection(), 2);
        assert_eq!(observed.user_version(), 37);
    }

    #[test]
    fn rejects_absent_id_or_changed_header_version() {
        let head = head();
        assert!(matches!(
            snapshot_refresh_query(&head, 7, vec![], b"image1", 2, 4096),
            Err(QueryError::InvalidSnapshot)
        ));
        assert!(matches!(
            snapshot_refresh_query(&head, 7, vec![], b"image1", 1, 47),
            Err(QueryError::InvalidOutputLimit)
        ));
        let (request, receipt) =
            snapshot_refresh_query(&head, 7, vec![], b"image1", 1, 4096).unwrap();
        let operations = reply(&request);
        let mut queue = ObjectQueue::new(1, 1 << 20, 1).unwrap();
        let token = queue.submit_compound(request).unwrap();
        let completion = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: 0,
                user_version: 38,
                replay_version: Default::default(),
                operations,
            },
        );
        assert_eq!(
            decode_snapshot_refresh_completion(&head, receipt, token, completion),
            Err(SnapshotRefreshError::Observation(
                SnapshotObservationError::VersionChanged {
                    field: "refresh reply",
                    expected: 37,
                    observed: 38
                }
            ))
        );
    }
}
