// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Raw head data-object WRITE segments, before image writer policy.

use crate::{DataLocator, ObjectExtent, QueryError, Versioned, metadata_query::compound_reply};
use opwire::{OsdOp, op};
use rustyrados::{
    Access, CompoundRequest, FrozenPayload, ReadCompletion, RequestContext, RequestToken, Target,
};

/// One object-local portion of a caller write. The image owner must first
/// establish watch, refresh, lock, copy-up, and object-map policy.
#[derive(Debug)]
pub struct PlannedWrite {
    pub logical_offset: u64,
    pub extent: ObjectExtent,
    pub request: CompoundRequest,
}

/// Several adjacent vector fragments routed to one object and submitted in
/// one compound request, with one immutable input owner per WRITE operation.
#[derive(Debug)]
pub struct PlannedWriteGroup {
    pub logical_offset: u64,
    pub extents: Vec<ObjectExtent>,
    pub request: CompoundRequest,
}

/// A validated raw head range, advanced one object-local WRITE at a time.
/// Each segment retains a shared slice of the original immutable payload.
/// This cursor does not grant image-level write access or submit requests.
#[derive(Debug)]
pub struct RawWriteSegments<'a> {
    locator: &'a DataLocator,
    logical_offset: u64,
    remaining: FrozenPayload,
    max_write_bytes: u32,
}

/// A validated vector of immutable raw head WRITE buffers. A segment never
/// spans two source buffers, so the current single-buffer wire encoder can
/// retain each payload without flattening it.
#[derive(Debug)]
pub struct RawWriteVectorSegments<'a> {
    locator: &'a DataLocator,
    logical_offset: u64,
    remaining: Vec<FrozenPayload>,
    index: usize,
    pending: Option<PlannedWrite>,
    max_write_bytes: u32,
}

impl RawWriteVectorSegments<'_> {
    /// Plan the next nonempty source span. The cursor advances only after a
    /// complete segment has been planned; each result owns its source slice.
    pub fn next_segment(&mut self) -> Result<Option<PlannedWrite>, QueryError> {
        if let Some(plan) = self.pending.take() {
            return Ok(Some(plan));
        }
        while self
            .remaining
            .get(self.index)
            .is_some_and(FrozenPayload::is_empty)
        {
            self.index += 1;
        }
        let Some(source) = self.remaining.get(self.index) else {
            return Ok(None);
        };
        let plan = self.locator.plan_raw_write(
            self.logical_offset,
            source.clone(),
            self.max_write_bytes,
        )?;
        let length = plan.extent.length as usize;
        self.logical_offset += plan.extent.length;
        let tail = source.slice(length..);
        self.remaining[self.index] = tail;
        Ok(Some(plan))
    }

    /// Group consecutive fragments of the same object into one request up
    /// to the configured payload cap and the wire operation-count limit.
    /// Each operation keeps its own source slice; the compound encoder sends
    /// these as separate shared data pieces in the same data segment.
    pub fn next_group(&mut self) -> Result<Option<PlannedWriteGroup>, QueryError> {
        let Some(first) = self.next_segment()? else {
            return Ok(None);
        };
        let object_number = first.extent.object_number;
        let logical_offset = first.logical_offset;
        let mut length = first.extent.length;
        let mut extents = vec![first.extent];
        let mut request = first.request;
        while length < u64::from(self.max_write_bytes)
            && request.operations.len() < u16::MAX as usize
        {
            let Some(next) = self.next_segment()? else {
                break;
            };
            if next.extent.object_number != object_number
                || next.extent.length > u64::from(self.max_write_bytes) - length
            {
                self.pending = Some(next);
                break;
            }
            length += next.extent.length;
            extents.push(next.extent);
            request.operations.extend(next.request.operations);
        }
        Ok(Some(PlannedWriteGroup {
            logical_offset,
            extents,
            request,
        }))
    }
}

impl RawWriteSegments<'_> {
    /// Plan the next segment. `None` means the complete caller range was
    /// planned. An error leaves the cursor at the same logical offset.
    pub fn next_segment(&mut self) -> Result<Option<PlannedWrite>, QueryError> {
        if self.remaining.is_empty() {
            return Ok(None);
        }
        let plan = self.locator.plan_raw_write(
            self.logical_offset,
            self.remaining.clone(),
            self.max_write_bytes,
        )?;
        let length = plan.extent.length as usize;
        self.logical_offset += plan.extent.length;
        self.remaining = self.remaining.slice(length..);
        Ok(Some(plan))
    }
}

impl DataLocator {
    fn validate_raw_write_range(
        &self,
        logical_offset: u64,
        length: usize,
        max_write_bytes: u32,
    ) -> Result<u64, QueryError> {
        let length = u64::try_from(length).map_err(|_| QueryError::InvalidWriteRange)?;
        if max_write_bytes == 0
            || length == 0
            || self.required_snapshot_id != Some(opwire::NOSNAP)
            || self.head_snap_context.is_none()
            || logical_offset
                .checked_add(length)
                .is_none_or(|end| end > self.layout.image_size())
        {
            return Err(QueryError::InvalidWriteRange);
        }
        Ok(length)
    }

    /// Validate the entire range before returning the first raw WRITE plan.
    /// The cursor splits at stripe/object and positive payload-cap boundaries.
    /// The image owner remains responsible for copy-up, writer fencing,
    /// submission, completion, and a cross-queue flush fence.
    pub fn plan_raw_write_segments(
        &self,
        logical_offset: u64,
        data: FrozenPayload,
        max_write_bytes: u32,
    ) -> Result<RawWriteSegments<'_>, QueryError> {
        self.validate_raw_write_range(logical_offset, data.len(), max_write_bytes)?;
        Ok(RawWriteSegments {
            locator: self,
            logical_offset,
            remaining: data,
            max_write_bytes,
        })
    }

    /// Validate an entire immutable buffer vector before producing any raw
    /// WRITE request. Empty entries are skipped. Each emitted request retains
    /// one shared input slice; no vector payload is flattened or copied.
    /// The image owner still provides write admission and completion policy.
    pub fn plan_raw_writev_segments(
        &self,
        logical_offset: u64,
        data: Vec<FrozenPayload>,
        max_write_bytes: u32,
    ) -> Result<RawWriteVectorSegments<'_>, QueryError> {
        let length = data.iter().try_fold(0usize, |total, part| {
            total
                .checked_add(part.len())
                .ok_or(QueryError::InvalidWriteRange)
        })?;
        self.validate_raw_write_range(logical_offset, length, max_write_bytes)?;
        Ok(RawWriteVectorSegments {
            locator: self,
            logical_offset,
            remaining: data,
            index: 0,
            pending: None,
            max_write_bytes,
        })
    }

    /// Plan the first bounded raw WRITE from a coherent head locator. The
    /// complete caller buffer must fit the captured image size; a snapshot or
    /// geometry-only locator cannot write. The returned request retains a
    /// slice of `data` without copying its bytes.
    pub fn plan_raw_write(
        &self,
        logical_offset: u64,
        data: FrozenPayload,
        max_write_bytes: u32,
    ) -> Result<PlannedWrite, QueryError> {
        let length = self.validate_raw_write_range(logical_offset, data.len(), max_write_bytes)?;
        let extent = self
            .layout
            .first_extent(logical_offset, length.min(u64::from(max_write_bytes)))
            .ok_or(QueryError::InvalidWriteRange)?;
        let mut object = Vec::new();
        self.layout
            .write_object_name(extent.object_number, &mut object);
        let snap_context = self
            .head_snap_context
            .as_ref()
            .ok_or(QueryError::InvalidWriteRange)?;
        let request = CompoundRequest {
            target: Target {
                pool: self.pool,
                object,
                namespace: self.namespace.clone(),
                locator: Vec::new(),
            },
            access: Access::Write,
            context: RequestContext {
                snap_sequence: snap_context.sequence,
                snapshots: snap_context.ids.clone(),
                ..Default::default()
            },
            operations: vec![OsdOp::write_bytes(
                extent.object_offset,
                data.slice(..extent.length as usize),
            )],
            max_output_bytes: 0,
        };
        Ok(PlannedWrite {
            logical_offset,
            extent,
            request,
        })
    }
}

/// Accept only a matching ordinary server reply for one raw WRITE. A remote
/// errno or an uncertain transport result never becomes a successful write.
/// The image owner must still provide cross-queue flush and writer fencing.
pub fn decode_data_write_completion(
    expected: RequestToken,
    expected_extent: ObjectExtent,
    completion: ReadCompletion,
) -> Result<Versioned<()>, QueryError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    if result < 0 {
        return Err(QueryError::Remote(result));
    }
    if result != 0 || operations.len() != 1 {
        return Err(QueryError::InvalidReply);
    }
    let operation = operations.first().ok_or(QueryError::InvalidReply)?;
    check_write_operation(expected_extent, operation)?;
    Ok(Versioned {
        value: (),
        user_version,
    })
}

/// Accept a compound WRITE result only when every operation matches the
/// planned object-local extent and has a successful durable server result.
pub fn decode_data_write_group_completion(
    expected: RequestToken,
    expected_extents: &[ObjectExtent],
    completion: ReadCompletion,
) -> Result<Versioned<()>, QueryError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    if result < 0 {
        return Err(QueryError::Remote(result));
    }
    if result != 0 || expected_extents.is_empty() || operations.len() != expected_extents.len() {
        return Err(QueryError::InvalidReply);
    }
    for (&extent, operation) in expected_extents.iter().zip(&operations) {
        check_write_operation(extent, operation)?;
    }
    Ok(Versioned {
        value: (),
        user_version,
    })
}

fn check_write_operation(
    expected_extent: ObjectExtent,
    operation: &OsdOp,
) -> Result<(), QueryError> {
    if operation.rval < 0 {
        return Err(QueryError::Remote(operation.rval));
    }
    // The pinned reference trims a stale write that arrives after a
    // truncate to the object's current size and reports the trimmed length
    // in the reply extent. The write was applied up to that size, so a
    // shorter reply length is a valid answer; a longer one is not.
    if operation.op != op::WRITE
        || operation.rval != 0
        || operation.extent().offset != expected_extent.object_offset
        || operation.extent().length > expected_extent.length
        || operation.outdata_len() != 0
    {
        return Err(QueryError::InvalidReply);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        HeadInputs, HeadObservation, ImageHeader, ImageSnapContext, SnapshotInfo, SnapshotInputs,
        SnapshotNamespace, SnapshotObservation, StripeGeometry,
    };
    use rustyrados::{ObjectQueue, ReadOutcome, ReadPublication};

    fn head_inputs() -> HeadInputs {
        HeadInputs {
            header: Versioned {
                value: ImageHeader {
                    order: 22,
                    size: 8_388_608,
                    features: 0,
                    incompatible_features: 0,
                    object_prefix: b"rbd_data.image1".to_vec(),
                    data_pool_id: 11,
                },
                user_version: 37,
            },
            snap_context: Versioned {
                value: ImageSnapContext {
                    sequence: 9,
                    ids: vec![9, 5],
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
        }
    }

    fn head() -> HeadObservation {
        HeadObservation::assemble(head_inputs()).unwrap()
    }

    #[test]
    fn whole_range_segments_keep_payload_and_snapshot_context_across_stripes() {
        let mut inputs = head_inputs();
        inputs.header.value.features = 1 << 1;
        inputs.header.value.order = 12;
        inputs.header.value.size = 16_384;
        inputs.stripe = Some(Versioned {
            value: StripeGeometry {
                unit: 1024,
                count: 2,
            },
            user_version: 37,
        });
        let head = HeadObservation::assemble(inputs).unwrap();
        let locator = DataLocator::from_head(&head, 7, b"ns".to_vec()).unwrap();
        let data = FrozenPayload::from(vec![0x5a; 2600]);
        let mut segments = locator
            .plan_raw_write_segments(1020, data.clone(), 700)
            .unwrap();
        let mut lengths = Vec::new();
        let mut object_numbers = Vec::new();
        let mut consumed = 0usize;
        while let Some(plan) = segments.next_segment().unwrap() {
            let payload = &plan.request.operations[0].indata;
            assert_eq!(payload.as_ptr(), data.as_ptr().wrapping_add(consumed));
            assert_eq!(payload.len(), plan.extent.length as usize);
            assert_eq!(plan.logical_offset, 1020 + consumed as u64);
            assert_eq!(plan.request.context.snap_sequence, 9);
            assert_eq!(plan.request.context.snapshots, [9, 5]);
            assert_eq!(plan.request.target.pool, 11);
            assert_eq!(plan.request.target.namespace, b"ns");
            lengths.push(plan.extent.length);
            object_numbers.push(plan.extent.object_number);
            consumed += payload.len();
        }
        assert_eq!(consumed, data.len());
        assert_eq!(lengths, [4, 700, 324, 700, 324, 548]);
        assert_eq!(object_numbers, [0, 1, 1, 0, 0, 1]);
        assert!(segments.next_segment().unwrap().is_none());
        assert!(matches!(
            locator.plan_raw_write_segments(16_383, data, 700),
            Err(QueryError::InvalidWriteRange)
        ));
    }

    #[test]
    fn vector_segments_preserve_each_source_and_reject_aggregate_overflow_of_image() {
        let locator = DataLocator::from_head(&head(), 7, vec![]).unwrap();
        let first = FrozenPayload::from_static(b"abcde");
        let second = FrozenPayload::from_static(b"1234567");
        let offset = 4_194_304 - 3;
        let mut segments = locator
            .plan_raw_writev_segments(
                offset,
                vec![
                    FrozenPayload::new(),
                    first.clone(),
                    FrozenPayload::new(),
                    second.clone(),
                ],
                4,
            )
            .unwrap();
        for (logical, object, pointer, length) in [
            (offset, 0, first.as_ptr(), 3),
            (offset + 3, 1, first.as_ptr().wrapping_add(3), 2),
            (offset + 5, 1, second.as_ptr(), 4),
            (offset + 9, 1, second.as_ptr().wrapping_add(4), 3),
        ] {
            let plan = segments.next_segment().unwrap().unwrap();
            let payload = &plan.request.operations[0].indata;
            assert_eq!(plan.logical_offset, logical);
            assert_eq!(plan.extent.object_number, object);
            assert_eq!(plan.extent.length, length);
            assert_eq!(payload.as_ptr(), pointer);
            assert_eq!(payload.len(), length as usize);
            assert_eq!(plan.request.context.snap_sequence, 9);
            assert_eq!(plan.request.context.snapshots, [9, 5]);
        }
        assert!(segments.next_segment().unwrap().is_none());
        assert!(matches!(
            locator.plan_raw_writev_segments(8_388_607, vec![first, second], 4),
            Err(QueryError::InvalidWriteRange)
        ));
        assert!(matches!(
            locator.plan_raw_writev_segments(0, vec![FrozenPayload::new()], 4),
            Err(QueryError::InvalidWriteRange)
        ));
    }

    #[test]
    fn vector_group_preserves_two_owners_in_one_durable_object_request() {
        let locator = DataLocator::from_head(&head(), 7, vec![]).unwrap();
        let first = FrozenPayload::from_static(b"abcde");
        let second = FrozenPayload::from_static(b"1234567");
        let mut cursor = locator
            .plan_raw_writev_segments(4_194_304 - 3, vec![first.clone(), second.clone()], 12)
            .unwrap();
        let before_boundary = cursor.next_group().unwrap().unwrap();
        assert_eq!(before_boundary.logical_offset, 4_194_301);
        assert_eq!(before_boundary.extents.len(), 1);
        assert_eq!(before_boundary.request.operations.len(), 1);
        let grouped = cursor.next_group().unwrap().unwrap();
        assert_eq!(grouped.logical_offset, 4_194_304);
        assert_eq!(grouped.extents.len(), 2);
        assert_eq!(grouped.request.operations.len(), 2);
        assert_eq!(
            grouped.request.operations[0].indata.as_ptr(),
            first.as_ptr().wrapping_add(3)
        );
        assert_eq!(
            grouped.request.operations[1].indata.as_ptr(),
            second.as_ptr()
        );
        assert_eq!(grouped.request.context.snapshots, [9, 5]);
        assert!(grouped.request.preflight(1 << 20).is_ok());
        assert!(cursor.next_group().unwrap().is_none());

        let expected_extents = grouped.extents;
        let echoes = grouped.request.operations.iter().map(OsdOp::echo).collect();
        let mut queue = ObjectQueue::new(1, 1 << 20, 1).unwrap();
        let token = queue.submit_compound(grouped.request).unwrap();
        let reply = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: 0,
                user_version: 12,
                replay_version: Default::default(),
                operations: echoes,
            },
        );
        assert_eq!(
            decode_data_write_group_completion(token, &expected_extents, reply),
            Ok(Versioned {
                value: (),
                user_version: 12,
            })
        );
    }

    #[test]
    fn bounded_head_write_retains_payload_owner_and_snapshot_context() {
        let locator = DataLocator::from_head(&head(), 7, b"ns".to_vec()).unwrap();
        let data = FrozenPayload::from(vec![0x5a; 64]);
        let plan = locator.plan_raw_write(4_194_300, data.clone(), 64).unwrap();
        assert_eq!(plan.extent.object_offset, 4_194_300);
        assert_eq!(plan.extent.length, 4);
        assert_eq!(plan.request.target.pool, 11);
        assert_eq!(plan.request.target.namespace, b"ns");
        assert_eq!(
            plan.request.target.object,
            b"rbd_data.image1.0000000000000000"
        );
        assert_eq!(plan.request.context.snapid, opwire::NOSNAP);
        assert_eq!(plan.request.context.snap_sequence, 9);
        assert_eq!(plan.request.context.snapshots, vec![9, 5]);
        assert_eq!(plan.request.access, Access::Write);
        assert_eq!(plan.request.operations[0].indata.as_ptr(), data.as_ptr());
        assert_eq!(plan.request.operations[0].indata.len(), 4);
        assert!(plan.request.preflight(1 << 20).is_ok());
    }

    #[test]
    fn rejects_unbound_or_out_of_range_write() {
        let head = head();
        let locator = DataLocator::from_head(&head, 7, vec![]).unwrap();
        assert!(matches!(
            locator.plan_raw_write(8_388_607, FrozenPayload::from_static(b"ab"), 32),
            Err(QueryError::InvalidWriteRange)
        ));
        assert!(matches!(
            locator.plan_raw_write(0, FrozenPayload::new(), 32),
            Err(QueryError::InvalidWriteRange)
        ));
        assert!(matches!(
            locator.plan_raw_write(0, FrozenPayload::from_static(b"a"), 0),
            Err(QueryError::InvalidWriteRange)
        ));
        let unbound = DataLocator::from_header(head.header(), 7, vec![]).unwrap();
        assert!(matches!(
            unbound.plan_raw_write(0, FrozenPayload::from_static(b"a"), 32),
            Err(QueryError::InvalidWriteRange)
        ));
        let snapshot = SnapshotObservation::assemble(
            &head,
            SnapshotInputs {
                info: Versioned {
                    value: SnapshotInfo {
                        id: 9,
                        namespace: SnapshotNamespace::User,
                        name: b"s".to_vec(),
                        image_size: 4096,
                        timestamp_seconds: 0,
                        timestamp_nanoseconds: 0,
                        child_count: 0,
                    },
                    user_version: 37,
                },
                flags: Versioned {
                    value: 0,
                    user_version: 37,
                },
                parent_overlap: Versioned {
                    value: None,
                    user_version: 37,
                },
                protection: Versioned {
                    value: 0,
                    user_version: 37,
                },
            },
        )
        .unwrap();
        let snapshot_locator = DataLocator::from_snapshot(&head, &snapshot, 7, vec![]).unwrap();
        assert!(matches!(
            snapshot_locator.plan_raw_write(0, FrozenPayload::from_static(b"a"), 32),
            Err(QueryError::InvalidWriteRange)
        ));
    }

    #[test]
    fn durable_reply_is_exact_and_uncertainty_is_retained() {
        let locator = DataLocator::from_head(&head(), 7, vec![]).unwrap();
        let plan = locator
            .plan_raw_write(0, FrozenPayload::from_static(b"abc"), 32)
            .unwrap();
        let echo = plan.request.operations[0].echo();
        let mut queue = ObjectQueue::new(1, 1 << 20, 1).unwrap();
        let token = queue.submit_compound(plan.request).unwrap();
        let reply = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: 0,
                user_version: 12,
                replay_version: Default::default(),
                operations: vec![echo],
            },
        );
        assert_eq!(
            decode_data_write_completion(token, plan.extent, reply),
            Ok(Versioned {
                value: (),
                user_version: 12
            })
        );
        assert_eq!(
            decode_data_write_completion(
                token,
                plan.extent,
                ReadCompletion::new(token, ReadOutcome::PossiblySent)
            ),
            Err(QueryError::PossiblySent)
        );
        assert_eq!(
            decode_data_write_completion(
                token,
                plan.extent,
                ReadCompletion::new(
                    token,
                    ReadOutcome::Deadline {
                        possibly_sent: true
                    }
                )
            ),
            Err(QueryError::Deadline {
                possibly_sent: true
            })
        );
    }

    #[test]
    fn a_trimmed_write_reply_is_accepted_and_a_longer_one_is_not() {
        let locator = DataLocator::from_head(&head(), 7, vec![]).unwrap();
        let plan = locator
            .plan_raw_write(0, FrozenPayload::from_static(b"abcdef"), 32)
            .unwrap();
        let mut queue = ObjectQueue::new(1, 1 << 20, 1).unwrap();
        let echo = plan.request.operations[0].echo();
        let token = queue.submit_compound(plan.request).unwrap();
        // The pinned reference trims a stale write that arrives after a
        // truncate down to the object's current size and reports the trimmed
        // length in the reply extent.
        let mut trimmed = echo.clone();
        trimmed.set_extent(opwire::Extent {
            offset: plan.extent.object_offset,
            length: plan.extent.length - 2,
            ..Default::default()
        });
        let reply = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: 0,
                user_version: 12,
                replay_version: Default::default(),
                operations: vec![trimmed],
            },
        );
        assert_eq!(
            decode_data_write_completion(token, plan.extent, reply),
            Ok(Versioned {
                value: (),
                user_version: 12
            })
        );
        // A reply that claims more bytes than the planned write is not a
        // reply to this write.
        let mut longer = echo.clone();
        longer.set_extent(opwire::Extent {
            offset: plan.extent.object_offset,
            length: plan.extent.length + 1,
            ..Default::default()
        });
        let reply = ReadCompletion::new(
            token,
            ReadOutcome::RemoteCompound {
                publication: ReadPublication::Reply,
                result: 0,
                user_version: 12,
                replay_version: Default::default(),
                operations: vec![longer],
            },
        );
        assert_eq!(
            decode_data_write_completion(token, plan.extent, reply),
            Err(QueryError::InvalidReply)
        );
    }
}
