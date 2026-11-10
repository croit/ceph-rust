// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Raw sparse data-object replies with owned, uncoalesced packed data.

use crate::{
    ParentSpec, PlannedRead, QueryError, RawReadResult, ReadResolution, Versioned,
    data_read::data_compound_reply, resolve_raw_read,
};
use opwire::{CrcHint, SparseReadView, op};
use rustyrados::{FrozenPayload, ReadCompletion, RequestToken};

/// One occupied range in the data object. The packed byte offset refers to
/// the payload's encoded owner, not a freshly copied dense buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SparseExtent {
    pub object_offset: u64,
    pub length: u64,
    data_offset: usize,
}

/// Shared reply owner plus validated sparse extents. Every gap in the
/// submitted object-local range represents zeros.
#[derive(Debug)]
pub struct SparseReadPayload {
    encoded: FrozenPayload,
    encoded_crc: CrcHint,
    extents: Vec<SparseExtent>,
    data_start: usize,
    request_offset: u64,
    request_length: u32,
}

impl SparseReadPayload {
    /// Packed bytes only, without extent-map framing. Borrows the same owner.
    pub fn packed_data(&self) -> &[u8] {
        &self.encoded[self.data_start..]
    }

    /// Object-local occupied extents paired with their borrowed packed bytes.
    pub fn extents(&self) -> impl ExactSizeIterator<Item = (u64, &[u8])> {
        self.extents.iter().map(|extent| {
            let start = extent.data_offset;
            let end = start + extent.length as usize;
            (extent.object_offset, &self.encoded[start..end])
        })
    }

    /// Fill one caller-provided segment with sparse bytes and zeros. Occupied
    /// ranges are copied once; only gaps are explicitly zeroed.
    pub fn fill_into(&self, destination: &mut [u8]) -> Result<(), QueryError> {
        if destination.len() != self.request_length as usize {
            return Err(QueryError::InvalidOutputLimit);
        }
        let mut cursor = 0usize;
        for (at, data) in self.extents() {
            let start =
                usize::try_from(at - self.request_offset).map_err(|_| QueryError::InvalidReply)?;
            destination[cursor..start].fill(0);
            let end = start + data.len();
            destination[start..end].copy_from_slice(data);
            cursor = end;
        }
        destination[cursor..].fill(0);
        Ok(())
    }

    /// Move the encoded buffer owner and its checksum hint to the caller.
    /// The extent offsets remain relative to that whole encoded owner.
    pub fn into_encoded(self) -> (FrozenPayload, CrcHint, Vec<SparseExtent>) {
        (self.encoded, self.encoded_crc, self.extents)
    }
}

/// A sparse object can be present (including an all-hole object) or absent.
#[derive(Debug)]
pub enum RawSparseResult {
    Data(SparseReadPayload),
    Missing,
}

/// Decode a bounded SPARSE_READ completion. The expected offset and length
/// are retained from the submitted plan; they constrain all reported extents.
pub fn decode_sparse_read_completion(
    expected: RequestToken,
    expected_object_offset: u64,
    expected_length: u32,
    completion: ReadCompletion,
) -> Result<Versioned<RawSparseResult>, QueryError> {
    let (result, user_version, operations) =
        data_compound_reply(expected, op::SPARSE_READ, completion)?;
    if result == -opwire::errno::ENOENT {
        return Ok(Versioned {
            value: RawSparseResult::Missing,
            user_version,
        });
    }
    if result < 0 {
        return Err(QueryError::Remote(result));
    }
    if result != 0 || operations.len() != 1 || expected_length == 0 {
        return Err(QueryError::InvalidReply);
    }
    let mut operation = operations
        .into_iter()
        .next()
        .ok_or(QueryError::InvalidReply)?;
    if operation.op != op::SPARSE_READ {
        return Err(QueryError::InvalidReply);
    }
    if operation.rval == -opwire::errno::ENOENT {
        return Ok(Versioned {
            value: RawSparseResult::Missing,
            user_version,
        });
    }
    if operation.rval < 0 {
        return Err(QueryError::Remote(operation.rval));
    }
    if operation.rval != 0 || operation.extent().offset != expected_object_offset {
        return Err(QueryError::InvalidReply);
    }
    operation.flatten_outdata();
    let (extents, data_start) = {
        let view = denc::from_slice::<SparseReadView<'_>>(&operation.outdata)
            .map_err(|_| QueryError::InvalidReply)?;
        view.validate_range(expected_object_offset, u64::from(expected_length))
            .map_err(|_| QueryError::InvalidReply)?;
        let packed_length = view.data().len() as u64;
        // The pinned reference reports the packed data length in the reply
        // extent of a replicated sparse read. A direct erasure-coded read
        // keeps the requested length in the reply extent instead, because
        // the shards are read by the client. Both shapes describe the same
        // reply; the extent map and the packed data are validated above.
        if operation.extent().length != packed_length
            && operation.extent().length != u64::from(expected_length)
        {
            return Err(QueryError::InvalidReply);
        }
        let data_start = operation.outdata.len() - view.data().len();
        let mut data_offset = data_start;
        let mut extents = Vec::with_capacity(view.extents().len());
        for (object_offset, length) in view.extents() {
            extents.push(SparseExtent {
                object_offset,
                length,
                data_offset,
            });
            data_offset += length as usize;
        }
        (extents, data_start)
    };
    // See `decode_data_read_completion`: a placement read's store-verified
    // block CRCs have no consumer in the image path.
    let (encoded, encoded_crc, more, _block_crcs) = operation.take_outdata();
    debug_assert!(more.is_empty());
    Ok(Versioned {
        value: RawSparseResult::Data(SparseReadPayload {
            encoded,
            encoded_crc,
            extents,
            data_start,
            request_offset: expected_object_offset,
            request_length: expected_length,
        }),
        user_version,
    })
}

/// Resolve a sparse object result using the same missing-object parent rule
/// as a plain READ. Occupied extents and all-hole gaps remain separate.
///
/// The plan carries the parent overlap of the view it was planned for.
pub fn resolve_sparse_read<'a>(
    plan: &PlannedRead,
    result: RawSparseResult,
    parent: Option<&'a ParentSpec>,
) -> Result<ReadResolution<'a>, QueryError> {
    match result {
        RawSparseResult::Data(payload) => Ok(ReadResolution::SparseData { payload }),
        RawSparseResult::Missing => resolve_raw_read(plan, RawReadResult::Missing, parent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DataLocator, ImageHeader};
    use opwire::{Extent, OsdOp};
    use rustyrados::{ObjectQueue, ReadOutcome, ReadPublication};

    fn header() -> ImageHeader {
        ImageHeader {
            order: 22,
            size: 8192,
            features: 0,
            incompatible_features: 0,
            object_prefix: b"rbd_data.image1".to_vec(),
            data_pool_id: -1,
        }
    }

    fn encoded_sparse() -> Vec<u8> {
        let mut data = 2u32.to_le_bytes().to_vec();
        for (at, len) in [(100u64, 3u64), (110, 2)] {
            data.extend_from_slice(&at.to_le_bytes());
            data.extend_from_slice(&len.to_le_bytes());
        }
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(b"abcde");
        data
    }

    #[test]
    fn plan_and_decode_sparse_data_without_copying_owner() {
        let locator = DataLocator::from_header(&header(), 7, vec![]).unwrap();
        let plan = locator
            .plan_sparse_read(100, 100, 100, 4096, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        assert_eq!(plan.request.operations[0].op, op::SPARSE_READ);
        assert_eq!(plan.request.max_output_bytes, 4096);
        assert!(plan.request.preflight(1 << 20).is_ok());
        let mut queue = ObjectQueue::new(1, 1 << 20, 1).unwrap();
        let token = queue.submit_compound(plan.request).unwrap();
        let mut operation = OsdOp::sparse_read(100, 100).echo();
        operation.outdata = FrozenPayload::from(encoded_sparse());
        let original_owner = operation.outdata.as_ptr();
        operation.set_extent(Extent {
            offset: 100,
            length: 5,
            ..Default::default()
        });
        let completion = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: 0,
                user_version: 11,
                replay_version: Default::default(),
                operations: vec![operation],
            },
        );
        let observed = decode_sparse_read_completion(token, 100, 100, completion).unwrap();
        assert_eq!(observed.user_version, 11);
        let RawSparseResult::Data(payload) = observed.value else {
            panic!("expected sparse data")
        };
        assert_eq!(payload.packed_data(), b"abcde");
        assert_eq!(
            payload.extents().collect::<Vec<_>>(),
            vec![(100, b"abc".as_slice()), (110, b"de".as_slice())]
        );
        let mut dense = vec![0xff; 100];
        payload.fill_into(&mut dense).unwrap();
        assert_eq!(&dense[..3], b"abc");
        assert!(dense[3..10].iter().all(|byte| *byte == 0));
        assert_eq!(&dense[10..12], b"de");
        assert!(dense[12..].iter().all(|byte| *byte == 0));
        assert_eq!(
            payload.fill_into(&mut dense[..99]),
            Err(QueryError::InvalidOutputLimit)
        );
        let (encoded, _, extents) = payload.into_encoded();
        assert_eq!(encoded.as_ptr(), original_owner);
        assert_eq!(extents.len(), 2);
    }

    #[test]
    fn sparse_read_accepts_verified_ec_split_without_partial_failure_data() {
        let locator = DataLocator::from_header(&header(), 7, vec![]).unwrap();
        let plan = locator
            .plan_sparse_read(100, 100, 100, 4096, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        let mut queue = ObjectQueue::new(1, 1 << 20, 1).unwrap();
        let token = queue.submit_compound(plan.request).unwrap();
        let mut operation = OsdOp::sparse_read(100, 100).echo();
        operation.outdata = FrozenPayload::from(encoded_sparse());
        operation.set_extent(Extent {
            offset: 100,
            length: 100,
            ..Default::default()
        });

        let success = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: rustyrados::ReadPublication::EcSplit,
                result: 0,
                user_version: 11,
                replay_version: Default::default(),
                operations: vec![operation.clone()],
            },
        );
        let observed = decode_sparse_read_completion(token, 100, 100, success).unwrap();
        let RawSparseResult::Data(payload) = observed.value else {
            panic!("expected sparse split data")
        };
        assert_eq!(payload.packed_data(), b"abcde");

        let partial_failure = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: rustyrados::ReadPublication::EcSplit,
                result: -opwire::errno::EIO,
                user_version: 11,
                replay_version: Default::default(),
                operations: vec![operation],
            },
        );
        assert!(matches!(
            decode_sparse_read_completion(token, 100, 100, partial_failure),
            Err(QueryError::InvalidReply)
        ));
    }

    #[test]
    fn rejects_sparse_extents_outside_request_and_wrong_provenance() {
        let locator = DataLocator::from_header(&header(), 7, vec![]).unwrap();
        let plan = locator
            .plan_sparse_read(100, 100, 100, 4096, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        let mut queue = ObjectQueue::new(2, 1 << 20, 1).unwrap();
        let expected = queue.submit_compound(plan.request).unwrap();
        let other = queue
            .submit_compound(
                locator
                    .plan_sparse_read(200, 100, 100, 4096, opwire::NOSNAP)
                    .unwrap()
                    .unwrap()
                    .request,
            )
            .unwrap();
        let mut operation = OsdOp::sparse_read(100, 100).echo();
        operation.outdata = FrozenPayload::from(encoded_sparse());
        operation.set_extent(Extent {
            offset: 100,
            length: 5,
            ..Default::default()
        });
        let completion = |token, publication, operation: OsdOp| {
            ReadCompletion::new(
                token,
                ReadOutcome::RemoteCompound {
                    publication,
                    result: 0,
                    user_version: 11,
                    replay_version: Default::default(),
                    operations: vec![operation],
                },
            )
        };
        assert!(matches!(
            decode_sparse_read_completion(
                expected,
                100,
                100,
                completion(other, ReadPublication::Reply, operation.clone())
            ),
            Err(QueryError::WrongCompletion)
        ));
        assert!(matches!(
            decode_sparse_read_completion(
                expected,
                100,
                100,
                completion(expected, ReadPublication::OutputLimit, operation.clone())
            ),
            Err(QueryError::InvalidPublication)
        ));
        let mut outside = operation;
        let mut encoded = encoded_sparse();
        encoded[4..12].copy_from_slice(&99u64.to_le_bytes());
        outside.outdata = FrozenPayload::from(encoded);
        assert!(matches!(
            decode_sparse_read_completion(
                expected,
                100,
                100,
                completion(expected, ReadPublication::Reply, outside)
            ),
            Err(QueryError::InvalidReply)
        ));
    }

    #[test]
    fn accepts_the_requested_length_reply_extent_of_a_direct_erasure_read() {
        let locator = DataLocator::from_header(&header(), 7, vec![]).unwrap();
        let plan = locator
            .plan_sparse_read(100, 100, 100, 4096, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        let mut queue = ObjectQueue::new(1, 1 << 20, 1).unwrap();
        let token = queue.submit_compound(plan.request).unwrap();
        let mut operation = OsdOp::sparse_read(100, 100).echo();
        operation.outdata = FrozenPayload::from(encoded_sparse());
        // A direct erasure-coded read keeps the requested length in the reply
        // extent, while a replicated sparse read reports the packed length.
        operation.set_extent(Extent {
            offset: 100,
            length: 100,
            ..Default::default()
        });
        let completion = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: 0,
                user_version: 11,
                replay_version: Default::default(),
                operations: vec![operation],
            },
        );
        let observed = decode_sparse_read_completion(token, 100, 100, completion).unwrap();
        let RawSparseResult::Data(payload) = observed.value else {
            panic!("expected sparse data")
        };
        assert_eq!(payload.packed_data(), b"abcde");
    }

    #[test]
    fn rejects_a_sparse_reply_extent_that_is_neither_packed_nor_requested() {
        let locator = DataLocator::from_header(&header(), 7, vec![]).unwrap();
        let plan = locator
            .plan_sparse_read(100, 100, 100, 4096, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        let mut queue = ObjectQueue::new(1, 1 << 20, 1).unwrap();
        let token = queue.submit_compound(plan.request).unwrap();
        let mut operation = OsdOp::sparse_read(100, 100).echo();
        operation.outdata = FrozenPayload::from(encoded_sparse());
        operation.set_extent(Extent {
            offset: 100,
            length: 7,
            ..Default::default()
        });
        let completion = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: 0,
                user_version: 11,
                replay_version: Default::default(),
                operations: vec![operation],
            },
        );
        assert!(matches!(
            decode_sparse_read_completion(token, 100, 100, completion),
            Err(QueryError::InvalidReply)
        ));
    }
}
