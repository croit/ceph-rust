// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Raw data-object READ segments, before image-level fallback.

use crate::{
    HeadObservation, ImageHeader, ImageLayout, ImageSnapContext, ObjectExtent, ParentSpec,
    QueryError, SnapshotObservation, StripeGeometry, Versioned,
    metadata_query::MAX_NAMESPACE_BYTES,
};
use opwire::{CrcHint, OsdOp, Pieces, op};
use rustyrados::{
    Access, CompoundRequest, FrozenPayload, ReadCompletion, ReadOutcome, ReadPublication,
    RequestContext, RequestToken, Target,
};

/// Immutable routing and geometry captured from one validated image header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataLocator {
    pub(crate) layout: ImageLayout,
    pub(crate) pool: i64,
    pub(crate) namespace: Vec<u8>,
    pub(crate) required_snapshot_id: Option<u64>,
    pub(crate) head_snap_context: Option<ImageSnapContext>,
    /// Parent overlap of the captured head or snapshot. `None` means no bytes
    /// of this view come from a parent.
    pub(crate) parent_overlap: Option<u64>,
}

/// The next bounded raw READ or SPARSE_READ and its logical span.
#[derive(Debug)]
pub struct PlannedRead {
    /// Logical offset in the image at the captured header size.
    pub logical_offset: u64,
    /// Object-local placement and maximum successful output length.
    pub extent: ObjectExtent,
    /// Request to submit through the RADOS runtime.
    pub request: CompoundRequest,
    /// Parent overlap of the view this read was planned for. The head and a
    /// snapshot have different overlaps, so the plan carries its own.
    pub parent_overlap: Option<u64>,
}

/// Owned READ bytes remain in the transport's shared buffers. A short result
/// is not padded; the image owner must resolve parent data or zero fill.
#[derive(Debug)]
pub struct ReadPayload {
    first: FrozenPayload,
    first_crc: CrcHint,
    more: Pieces,
    length: usize,
}

impl ReadPayload {
    /// Actual returned data length, which may be shorter than the request.
    pub fn len(&self) -> usize {
        self.length
    }

    /// Whether the object returned no data bytes.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Borrow all returned pieces in byte order without coalescing them.
    pub fn parts(&self) -> impl Iterator<Item = &[u8]> {
        std::iter::once(self.first.as_ref())
            .chain(self.more.iter().map(|(bytes, _)| bytes.as_ref()))
            .filter(|bytes| !bytes.is_empty())
    }

    /// Move the buffer owners and verified checksum hints to the image owner.
    pub fn into_parts(self) -> (FrozenPayload, CrcHint, Pieces) {
        (self.first, self.first_crc, self.more)
    }
}

/// A raw object can be present or absent. Missing is not zero-filled here:
/// layered images may need bytes from a parent.
#[derive(Debug)]
pub enum RawReadResult {
    Data(ReadPayload),
    Missing,
}

/// Resolution of one raw child-object segment at a captured image metadata
/// version. A parent segment must still be read through the parent's own
/// image path; this is not user-visible image data.
#[derive(Debug)]
pub enum ReadResolution<'a> {
    /// Existing object bytes followed by zeros if its READ was short. An
    /// existing child object never falls back to the parent for its tail.
    Data {
        payload: ReadPayload,
        zero_tail: u64,
    },
    /// Existing sparse object: returned extents are data and all gaps are
    /// zeros, including any tail before the requested range ends.
    SparseData { payload: crate::SparseReadPayload },
    /// Missing child object: read the overlap span from the parent snapshot,
    /// then produce zeros after the overlap boundary.
    Parent {
        parent: &'a ParentSpec,
        logical_offset: u64,
        length: u64,
        zero_tail: u64,
    },
    /// Missing object wholly outside parent overlap, or no parent at all.
    Zero { length: u64 },
}

/// Resolve a verified raw object result against the captured parent range.
///
/// `parent` must come from the same coherent head or snapshot observation as
/// the plan. The plan carries the parent overlap of its own view, so the head
/// overlap can never be applied to a snapshot read. A missing parent identity
/// with positive overlap is an error rather than a silent zero read.
pub fn resolve_raw_read<'a>(
    plan: &PlannedRead,
    result: RawReadResult,
    parent: Option<&'a ParentSpec>,
) -> Result<ReadResolution<'a>, QueryError> {
    let length = plan.extent.length;
    if length == 0 || plan.logical_offset.checked_add(length).is_none() {
        return Err(QueryError::InvalidReply);
    }
    match result {
        RawReadResult::Data(payload) => {
            if payload.len() as u64 > length {
                return Err(QueryError::InvalidReply);
            }
            Ok(ReadResolution::Data {
                zero_tail: length - payload.len() as u64,
                payload,
            })
        }
        RawReadResult::Missing => {
            let parent_length = plan
                .parent_overlap
                .unwrap_or(0)
                .saturating_sub(plan.logical_offset)
                .min(length);
            if parent_length == 0 {
                return Ok(ReadResolution::Zero { length });
            }
            let parent = parent.ok_or(QueryError::InvalidParent)?;
            Ok(ReadResolution::Parent {
                parent,
                logical_offset: plan.logical_offset,
                length: parent_length,
                zero_tail: length - parent_length,
            })
        }
    }
}

impl DataLocator {
    /// Geometry captured for this head or selected snapshot.
    pub fn layout(&self) -> &ImageLayout {
        &self.layout
    }

    /// Capture data-pool and default geometry from one header observation.
    pub fn from_header(
        header: &ImageHeader,
        metadata_pool: i64,
        namespace: Vec<u8>,
    ) -> Result<Self, QueryError> {
        Self::from_header_with_stripe(header, None, metadata_pool, namespace)
    }

    /// Capture the complete geometry of a coherent head observation.
    pub fn from_head(
        head: &HeadObservation,
        metadata_pool: i64,
        namespace: Vec<u8>,
    ) -> Result<Self, QueryError> {
        let mut locator =
            Self::from_header_with_stripe(head.header(), head.stripe(), metadata_pool, namespace)?;
        locator.required_snapshot_id = Some(opwire::NOSNAP);
        locator.head_snap_context = Some(head.snap_context().clone());
        locator.parent_overlap = head.parent_overlap();
        Ok(locator)
    }

    /// Capture a snapshot's size and selector from observations of the same
    /// header version. A snapshot may be larger or smaller than current head.
    pub fn from_snapshot(
        head: &HeadObservation,
        snapshot: &SnapshotObservation,
        metadata_pool: i64,
        namespace: Vec<u8>,
    ) -> Result<Self, QueryError> {
        if head.user_version() != snapshot.user_version() {
            return Err(QueryError::InvalidSnapshot);
        }
        let mut locator = Self::from_head(head, metadata_pool, namespace)?;
        locator.layout = locator.layout.with_image_size(snapshot.info().image_size);
        locator.required_snapshot_id = Some(snapshot.info().id);
        locator.head_snap_context = None;
        // A snapshot has its own parent overlap, which can differ from the
        // head's. The plan must carry the overlap of the view it reads.
        locator.parent_overlap = snapshot.parent_overlap();
        Ok(locator)
    }

    /// Capture data-pool and geometry, including conditional STRIPINGV2.
    pub fn from_header_with_stripe(
        header: &ImageHeader,
        stripe: Option<StripeGeometry>,
        metadata_pool: i64,
        namespace: Vec<u8>,
    ) -> Result<Self, QueryError> {
        if namespace.len() > MAX_NAMESPACE_BYTES {
            return Err(QueryError::InvalidTarget);
        }
        let pool = header
            .data_pool(metadata_pool)
            .map_err(QueryError::Header)?;
        let layout =
            ImageLayout::from_header_with_stripe(header, stripe).map_err(QueryError::Layout)?;
        Ok(Self {
            layout,
            pool,
            namespace,
            required_snapshot_id: None,
            head_snap_context: None,
            parent_overlap: None,
        })
    }

    /// Plan one raw READ segment, clipped at image EOF, object boundary and
    /// caller's positive maximum payload. `None` means no logical bytes remain.
    /// The snapshot selector belongs to the request context, not the target.
    pub fn plan_read(
        &self,
        logical_offset: u64,
        requested_length: u64,
        max_read_bytes: u32,
        snapshot_id: u64,
    ) -> Result<Option<PlannedRead>, QueryError> {
        self.plan_object_read(
            logical_offset,
            requested_length,
            max_read_bytes,
            0,
            snapshot_id,
            false,
        )
    }

    /// Plan one SPARSE_READ segment. `max_output_bytes` bounds the encoded
    /// extent map and packed data; it is independent of the logical span cap.
    pub fn plan_sparse_read(
        &self,
        logical_offset: u64,
        requested_length: u64,
        max_read_bytes: u32,
        max_output_bytes: u32,
        snapshot_id: u64,
    ) -> Result<Option<PlannedRead>, QueryError> {
        if max_output_bytes < 8 {
            return Err(QueryError::InvalidOutputLimit);
        }
        self.plan_object_read(
            logical_offset,
            requested_length,
            max_read_bytes,
            max_output_bytes,
            snapshot_id,
            true,
        )
    }

    fn plan_object_read(
        &self,
        logical_offset: u64,
        requested_length: u64,
        max_read_bytes: u32,
        max_output_bytes: u32,
        snapshot_id: u64,
        sparse: bool,
    ) -> Result<Option<PlannedRead>, QueryError> {
        if max_read_bytes == 0 {
            return Err(QueryError::InvalidOutputLimit);
        }
        if self
            .required_snapshot_id
            .is_some_and(|required| required != snapshot_id)
        {
            return Err(QueryError::InvalidSnapshot);
        }
        let Some(extent) = self.layout.first_extent(
            logical_offset,
            requested_length.min(u64::from(max_read_bytes)),
        ) else {
            return Ok(None);
        };
        let mut object = Vec::new();
        self.layout
            .write_object_name(extent.object_number, &mut object);
        let context = RequestContext {
            snapid: snapshot_id,
            ..Default::default()
        };
        let request = CompoundRequest {
            target: Target {
                pool: self.pool,
                object,
                namespace: self.namespace.clone(),
                locator: Vec::new(),
            },
            access: Access::Read,
            context,
            operations: vec![if sparse {
                OsdOp::sparse_read(extent.object_offset, extent.length)
            } else {
                OsdOp::read(extent.object_offset, extent.length)
            }],
            max_output_bytes: if sparse {
                max_output_bytes
            } else {
                extent.length as u32
            },
        };
        Ok(Some(PlannedRead {
            logical_offset,
            extent,
            request,
            parent_overlap: self.parent_overlap,
        }))
    }
}

/// Match a compound data-read completion and validate its publication.
///
/// Ordinary OSD replies retain per-operation status publication. A verified
/// EC split is also valid for a one-operation READ or SPARSE_READ compound:
/// success contains exactly the aggregate data operation, while failure
/// contains no operation outputs. A failed split that carries data is never
/// published as a partial read.
pub(crate) fn data_compound_reply(
    expected: RequestToken,
    expected_op: u16,
    completion: ReadCompletion,
) -> Result<(i32, u64, Vec<OsdOp>), QueryError> {
    if completion.token != expected {
        return Err(QueryError::WrongCompletion);
    }
    match completion.outcome {
        ReadOutcome::RemoteCompound {
            publication: ReadPublication::Reply,
            result,
            user_version,
            operations,
            ..
        } => Ok((result, user_version, operations)),
        ReadOutcome::RemoteCompound {
            publication: ReadPublication::EcSplit,
            result,
            user_version,
            operations,
            ..
        } => {
            if result < 0 {
                if operations.is_empty() {
                    Ok((result, user_version, operations))
                } else {
                    Err(QueryError::InvalidReply)
                }
            } else if operations.len() == 1
                && operations[0].op == expected_op
                && operations[0].rval == 0
            {
                Ok((result, user_version, operations))
            } else {
                Err(QueryError::InvalidReply)
            }
        }
        ReadOutcome::RemoteCompound { .. } => Err(QueryError::InvalidPublication),
        ReadOutcome::LocalRejected {
            error,
            possibly_sent,
        } => Err(QueryError::Local {
            error,
            possibly_sent,
        }),
        ReadOutcome::CanceledUnsent => Err(QueryError::CanceledUnsent),
        ReadOutcome::PossiblySent => Err(QueryError::PossiblySent),
        ReadOutcome::Deadline { possibly_sent } => Err(QueryError::Deadline { possibly_sent }),
        ReadOutcome::ReplyTooLarge { .. } => Err(QueryError::ReplyTooLarge),
        _ => Err(QueryError::InvalidReply),
    }
}

/// Decode a raw READ completion without copying its payload. The caller must
/// retain the expected segment length and token when submitting the request.
pub fn decode_data_read_completion(
    expected: RequestToken,
    expected_length: u32,
    completion: ReadCompletion,
) -> Result<Versioned<RawReadResult>, QueryError> {
    let (result, user_version, operations) = data_compound_reply(expected, op::READ, completion)?;
    if result == -opwire::errno::ENOENT {
        return Ok(Versioned {
            value: RawReadResult::Missing,
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
    if operation.op != op::READ {
        return Err(QueryError::InvalidReply);
    }
    if operation.rval == -opwire::errno::ENOENT {
        return Ok(Versioned {
            value: RawReadResult::Missing,
            user_version,
        });
    }
    if operation.rval < 0 {
        return Err(QueryError::Remote(operation.rval));
    }
    let length = operation.outdata_len();
    if operation.rval != 0
        || length > expected_length as usize
        || operation.extent().length != length as u64
    {
        return Err(QueryError::InvalidReply);
    }
    // A placement read carries the source OSD's store-verified per-4096-byte
    // block CRCs. The image path copies the bytes into the caller's buffer and
    // verifies no checksum, so the block CRCs have no consumer here; the
    // message CRC already covers the wire between the OSDs.
    let (first, first_crc, more, _block_crcs) = operation.take_outdata();
    Ok(Versioned {
        value: RawReadResult::Data(ReadPayload {
            first,
            first_crc,
            more,
            length,
        }),
        user_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyrados::{ObjectQueue, ReadOutcome, ReadPublication};

    fn header(size: u64, data_pool_id: i64) -> ImageHeader {
        ImageHeader {
            order: 22,
            size,
            features: 0,
            incompatible_features: 0,
            object_prefix: b"rbd_data.native".to_vec(),
            data_pool_id,
        }
    }

    #[test]
    fn plans_bounded_snapshot_read_in_selected_data_pool() {
        let locator = DataLocator::from_header(&header(5_000_000, 23), 7, b"ns".to_vec()).unwrap();
        let first = locator
            .plan_read(4_194_300, 1_000_000, 4096, 17)
            .unwrap()
            .unwrap();
        assert_eq!(first.logical_offset, 4_194_300);
        assert_eq!(first.extent.length, 4);
        assert_eq!(first.request.target.pool, 23);
        assert_eq!(
            first.request.target.object,
            b"rbd_data.native.0000000000000000"
        );
        assert_eq!(first.request.target.namespace, b"ns");
        assert_eq!(first.request.context.snapid, 17);
        assert_eq!(first.request.operations[0].op, op::READ);
        assert_eq!(first.request.operations[0].extent().offset, 4_194_300);
        assert_eq!(first.request.operations[0].extent().length, 4);
        assert_eq!(first.request.max_output_bytes, 4);
        assert!(first.request.preflight(1 << 20).is_ok());

        let second = locator
            .plan_read(4_194_304, 1_000_000, 4096, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        assert_eq!(second.extent.object_number, 1);
        assert_eq!(second.extent.length, 4096);
        assert_eq!(
            second.request.target.object,
            b"rbd_data.native.0000000000000001"
        );
        assert_eq!(second.request.context.snapid, opwire::NOSNAP);
        assert!(
            locator
                .plan_read(5_000_000, 1, 4096, opwire::NOSNAP)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn locator_rejects_unusable_context_and_uses_metadata_pool_by_default() {
        let locator = DataLocator::from_header(&header(4096, -1), 7, vec![]).unwrap();
        assert_eq!(
            locator
                .plan_read(0, 16, 16, opwire::NOSNAP)
                .unwrap()
                .unwrap()
                .request
                .target
                .pool,
            7
        );
        assert!(matches!(
            locator.plan_read(0, 1, 0, opwire::NOSNAP),
            Err(QueryError::InvalidOutputLimit)
        ));
        assert!(matches!(
            DataLocator::from_header(&header(4096, -1), 7, vec![0; 257]),
            Err(QueryError::InvalidTarget)
        ));
        let mut striped = header(4096, -1);
        striped.features = 1 << 1;
        assert!(matches!(
            DataLocator::from_header(&striped, 7, vec![]),
            Err(QueryError::Layout(_))
        ));
    }

    #[test]
    fn striped_locator_splits_at_stripe_unit_boundary() {
        let mut image = header(13_000, -1);
        image.order = 12;
        image.features = 1 << 1;
        let locator = DataLocator::from_header_with_stripe(
            &image,
            Some(StripeGeometry {
                unit: 1024,
                count: 3,
            }),
            7,
            vec![],
        )
        .unwrap();
        let segment = locator
            .plan_read(1024, 4096, 4096, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        assert_eq!(
            segment.extent,
            ObjectExtent {
                object_number: 1,
                object_offset: 0,
                length: 1024,
            }
        );
        assert_eq!(
            segment.request.target.object,
            b"rbd_data.native.0000000000000001"
        );
        assert_eq!(segment.request.operations[0].extent().length, 1024);
        assert!(segment.request.preflight(1 << 20).is_ok());
    }

    #[test]
    fn raw_read_preserves_shared_bytes_and_missing_object() {
        let locator = DataLocator::from_header(&header(4096, -1), 7, vec![]).unwrap();
        let plan = locator
            .plan_read(0, 16, 16, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        let mut queue = ObjectQueue::new(1, 1 << 20, 1).unwrap();
        let token = queue.submit_compound(plan.request).unwrap();
        let mut operation = OsdOp::read(0, 16).echo();
        operation.outdata = FrozenPayload::from_static(b"data");
        let source_ptr = operation.outdata.as_ptr();
        operation.set_extent(opwire::Extent {
            offset: 0,
            length: 4,
            ..Default::default()
        });
        let completion = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: 0,
                user_version: 1,
                replay_version: Default::default(),
                operations: vec![operation],
            },
        );
        let observed = decode_data_read_completion(token, 16, completion).unwrap();
        assert_eq!(observed.user_version, 1);
        let RawReadResult::Data(payload) = observed.value else {
            panic!("expected raw data")
        };
        assert_eq!(payload.len(), 4);
        assert_eq!(
            payload.parts().collect::<Vec<_>>(),
            vec![b"data".as_slice()]
        );
        let (owned, _, more) = payload.into_parts();
        assert_eq!(&owned[..], b"data");
        assert_eq!(owned.as_ptr(), source_ptr);
        assert!(more.is_empty());

        let missing = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: -opwire::errno::ENOENT,
                user_version: 0,
                replay_version: Default::default(),
                operations: vec![],
            },
        );
        assert!(matches!(
            decode_data_read_completion(token, 16, missing),
            Ok(Versioned {
                value: RawReadResult::Missing,
                user_version: 0
            })
        ));
    }

    #[test]
    fn raw_read_accepts_verified_ec_split_without_publishing_partial_failures() {
        let locator = DataLocator::from_header(&header(4096, -1), 7, vec![]).unwrap();
        let plan = locator
            .plan_read(0, 16, 16, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        let mut queue = ObjectQueue::new(1, 1 << 20, 1).unwrap();
        let token = queue.submit_compound(plan.request).unwrap();
        let mut operation = OsdOp::read(0, 16).echo();
        operation.outdata = FrozenPayload::from_static(b"data");
        operation.set_extent(opwire::Extent {
            offset: 0,
            length: 4,
            ..Default::default()
        });

        let success = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::EcSplit,
                result: 0,
                user_version: 1,
                replay_version: Default::default(),
                operations: vec![operation.clone()],
            },
        );
        let observed = decode_data_read_completion(token, 16, success).unwrap();
        let RawReadResult::Data(payload) = observed.value else {
            panic!("expected split data")
        };
        assert_eq!(
            payload.parts().collect::<Vec<_>>(),
            vec![b"data".as_slice()]
        );

        let partial_failure = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::EcSplit,
                result: -opwire::errno::EIO,
                user_version: 1,
                replay_version: Default::default(),
                operations: vec![operation],
            },
        );
        assert!(matches!(
            decode_data_read_completion(token, 16, partial_failure),
            Err(QueryError::InvalidReply)
        ));
    }

    #[test]
    fn raw_read_rejects_wrong_shape_before_publishing_bytes() {
        let locator = DataLocator::from_header(&header(4096, -1), 7, vec![]).unwrap();
        let plan = locator
            .plan_read(0, 16, 16, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        let mut queue = ObjectQueue::new(2, 1 << 20, 1).unwrap();
        let expected = queue.submit_compound(plan.request).unwrap();
        let other = queue
            .submit_compound(
                locator
                    .plan_read(16, 16, 16, opwire::NOSNAP)
                    .unwrap()
                    .unwrap()
                    .request,
            )
            .unwrap();
        let mut operation = OsdOp::read(0, 16).echo();
        operation.outdata = FrozenPayload::from_static(b"data");
        operation.set_extent(opwire::Extent {
            offset: 0,
            length: 4,
            ..Default::default()
        });
        let completion = |token, publication, operation: OsdOp| {
            ReadCompletion::new(
                token,
                ReadOutcome::RemoteCompound {
                    publication,
                    result: 0,
                    user_version: 1,
                    replay_version: Default::default(),
                    operations: vec![operation],
                },
            )
        };
        assert!(matches!(
            decode_data_read_completion(
                expected,
                16,
                completion(other, ReadPublication::Reply, operation.clone())
            ),
            Err(QueryError::WrongCompletion)
        ));
        assert!(matches!(
            decode_data_read_completion(
                expected,
                16,
                completion(expected, ReadPublication::OutputLimit, operation.clone())
            ),
            Err(QueryError::InvalidPublication)
        ));
        operation.set_extent(opwire::Extent {
            offset: 0,
            length: 5,
            ..Default::default()
        });
        assert!(matches!(
            decode_data_read_completion(
                expected,
                16,
                completion(expected, ReadPublication::Reply, operation)
            ),
            Err(QueryError::InvalidReply)
        ));
    }

    #[test]
    fn missing_child_uses_parent_only_inside_overlap() {
        let mut locator = DataLocator::from_header(&header(8192, -1), 7, vec![]).unwrap();
        locator.parent_overlap = Some(4096);
        let plan = locator
            .plan_read(3500, 1000, 1000, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        let parent = ParentSpec {
            pool: 9,
            namespace: vec![],
            image_id: b"parent1".to_vec(),
            snapshot_id: 5,
        };
        let resolved = resolve_raw_read(&plan, RawReadResult::Missing, Some(&parent)).unwrap();
        let ReadResolution::Parent {
            parent: observed,
            logical_offset,
            length,
            zero_tail,
        } = resolved
        else {
            panic!("expected parent span");
        };
        assert!(std::ptr::eq(observed, &parent));
        assert_eq!((logical_offset, length, zero_tail), (3500, 596, 404));
        let outside = locator
            .plan_read(4500, 1000, 1000, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        assert!(matches!(
            resolve_raw_read(&outside, RawReadResult::Missing, Some(&parent)),
            Ok(ReadResolution::Zero { length: 1000 })
        ));
        assert!(matches!(
            resolve_raw_read(&plan, RawReadResult::Missing, None),
            Err(QueryError::InvalidParent)
        ));
    }

    #[test]
    fn a_plan_carries_the_overlap_of_its_own_view() {
        // The head and a snapshot have different parent overlaps. A plan must
        // never take the overlap of another view.
        let mut head = DataLocator::from_header(&header(8192, -1), 7, vec![]).unwrap();
        head.parent_overlap = Some(4096);
        let plan = head
            .plan_read(3500, 1000, 1000, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        assert_eq!(plan.parent_overlap, Some(4096));

        let mut snapshot = head.clone();
        snapshot.parent_overlap = Some(1024);
        let plan = snapshot.plan_read(3500, 1000, 1000, 5).unwrap().unwrap();
        assert_eq!(plan.parent_overlap, Some(1024));
        // With the snapshot's smaller overlap the read is outside it, so the
        // bytes are zeros instead of parent data.
        let parent = ParentSpec {
            pool: 9,
            namespace: vec![],
            image_id: b"parent1".to_vec(),
            snapshot_id: 5,
        };
        assert!(matches!(
            resolve_raw_read(&plan, RawReadResult::Missing, Some(&parent)),
            Ok(ReadResolution::Zero { length: 1000 })
        ));
    }

    #[test]
    fn existing_short_child_zero_fills_even_inside_parent_overlap() {
        let locator = DataLocator::from_header(&header(8192, -1), 7, vec![]).unwrap();
        let plan = locator
            .plan_read(3500, 1000, 1000, opwire::NOSNAP)
            .unwrap()
            .unwrap();
        let parent = ParentSpec {
            pool: 9,
            namespace: vec![],
            image_id: b"parent1".to_vec(),
            snapshot_id: 5,
        };
        let payload = ReadPayload {
            first: FrozenPayload::from_static(b"data"),
            first_crc: CrcHint::default(),
            more: Pieces::new(),
            length: 4,
        };
        let resolved =
            resolve_raw_read(&plan, RawReadResult::Data(payload), Some(&parent)).unwrap();
        let ReadResolution::Data { payload, zero_tail } = resolved else {
            panic!("expected child data");
        };
        assert_eq!(
            payload.parts().collect::<Vec<_>>(),
            vec![b"data".as_slice()]
        );
        assert_eq!(zero_tail, 996);
    }
}
